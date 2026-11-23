package main

// Що DocScan знайшов у документі: блок docscan запису виявлення (знахідки з поясненнями, докази — віддалений шаблон,
// DDE, підозрілі місця VBA, ціль ярлика, документи в архіві; правила YARA з описами і місцем спрацювання), код
// макросів зі сховища watcher-а (<DataDir>\macros\<sha256 документа>.vba.txt) з підсвіченими підозрілими рядками.
// Лише читання.

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

func (p paths) macroDir() string { return filepath.Join(p.data, "macros") }

var shaRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// docFull — запис виявлення з блоком docscan повністю.
type docFull struct {
	Docscan *struct {
		Ftype           string            `json:"ftype"`
		Verdict         string            `json:"verdict"`
		Findings        []string          `json:"findings"`
		FindingsText    []string          `json:"findings_text"`
		Evidence        map[string]string `json:"evidence"`
		YaraMatches     []string          `json:"yara_matches"`
		YaraFileMatches []string          `json:"yara_file_matches"`
		YaraDocMatches  []string          `json:"yara_doc_matches"`
		YaraInfoMatches []string          `json:"yara_info_matches"`
		YaraPartMatches []struct {
			Part  string   `json:"part"`
			Rules []string `json:"rules"`
		} `json:"yara_part_matches"`
		YaraDescriptions []struct {
			Rule        string `json:"rule"`
			Description string `json:"description"`
		} `json:"yara_descriptions"`
		Details []struct {
			Rule     string `json:"rule"`
			Finding  string `json:"finding"`
			Severity string `json:"severity"`
			Disarm   string `json:"disarm"`
			Mitre    string `json:"mitre"`
		} `json:"details"`
	} `json:"docscan"`
	YaraFileMatches []string `json:"yara_file_matches"`
	Macro           *struct {
		File     string `json:"file"`
		Size     int64  `json:"size"`
		Uploaded bool   `json:"uploaded"`
	} `json:"macro"`
	Critical *struct {
		Queued    bool     `json:"queued"`
		Fragments int      `json:"fragments"`
		Rules     []string `json:"rules"`
	} `json:"critical"`
	DocFile struct {
		Sha256 string `json:"sha256"`
	} `json:"docfile"`
}

type finding struct{ Name, Severity, Text, Disarm, Mitre string }
type evidence struct{ Label, Value string }
type ruleHit struct{ Rule, Where, Desc string }

// docView — для сторінки запису.
type docView struct {
	Ftype     string
	Findings  []finding
	Evidence  []evidence
	Rules     []ruleHit
	MacroSHA  string // є код макросів у сховищі
	MacroSize int64
	Critical  string
}

var evidenceLabel = map[string]string{
	"template_url": "віддалений шаблон (завантажується при відкритті)",
	"dde_command":  "DDE-команда (запуск програми з документа)",
	"vba_evidence": "підозрілі місця в коді макросів",
	"lnk_target":   "ярлик веде на",
	"lnk_args":     "аргументи ярлика",
	"archive_docs": "документи в архіві",
}

func (s *server) docView(line []byte) *docView {
	var x docFull
	if json.Unmarshal(bytes.TrimSpace(line), &x) != nil {
		return nil
	}
	v := &docView{}
	if d := x.Docscan; d != nil {
		v.Ftype = d.Ftype
		texts := map[string]string{}
		for i, f := range d.Findings {
			if i < len(d.FindingsText) {
				texts[f] = d.FindingsText[i]
			}
		}
		seen := map[string]bool{}
		for _, dt := range d.Details {
			f := finding{Name: dt.Finding, Severity: dt.Severity, Disarm: dt.Disarm, Mitre: dt.Mitre, Text: texts[dt.Finding]}
			if f.Name == "" {
				f.Name = dt.Rule
			}
			if !seen[f.Name] {
				seen[f.Name] = true
				v.Findings = append(v.Findings, f)
			}
		}
		for _, f := range d.Findings { // знахідки без details (старі записи)
			if !seen[f] {
				seen[f] = true
				v.Findings = append(v.Findings, finding{Name: f, Text: texts[f]})
			}
		}
		keys := make([]string, 0, len(d.Evidence))
		for k := range d.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if val := strings.TrimSpace(d.Evidence[k]); val != "" {
				l := evidenceLabel[k]
				if l == "" {
					l = k
				}
				v.Evidence = append(v.Evidence, evidence{l, val})
			}
		}
		desc := map[string]string{}
		for _, yd := range d.YaraDescriptions {
			desc[yd.Rule] = yd.Description
		}
		add := func(rule, where string) {
			v.Rules = append(v.Rules, ruleHit{rule, where, desc[rule]})
		}
		for _, r := range d.YaraFileMatches {
			add(r, "файл")
		}
		for _, r := range d.YaraDocMatches {
			add(r, "текст документа")
		}
		for _, r := range d.YaraMatches {
			add(r, "код макросів")
		}
		for _, pm := range d.YaraPartMatches {
			for _, r := range pm.Rules {
				add(r, "частина: "+pm.Part)
			}
		}
		for _, r := range d.YaraInfoMatches {
			add(r, "інформаційне")
		}
	} else {
		for _, r := range x.YaraFileMatches {
			v.Rules = append(v.Rules, ruleHit{r, "файл", ""})
		}
	}
	sha := strings.ToLower(x.DocFile.Sha256)
	if shaRe.MatchString(sha) {
		if st, err := os.Stat(filepath.Join(s.p.macroDir(), sha+".vba.txt")); err == nil {
			v.MacroSHA, v.MacroSize = sha, st.Size()
		}
	}
	if c := x.Critical; c != nil && c.Queued {
		v.Critical = strings.Join(c.Rules, ", ")
		if v.Critical == "" {
			v.Critical = "так"
		}
	}
	if v.Ftype == "" && len(v.Findings) == 0 && len(v.Evidence) == 0 && len(v.Rules) == 0 && v.MacroSHA == "" && v.Critical == "" {
		return nil
	}
	return v
}

// ---------------------------------------------------------------- код макросів

// suspicious — що підсвічувати в коді VBA (автозапуск, запуск програм, мережа, файли, обфускація, WinAPI).
var suspicious = regexp.MustCompile(`(?i)\b(auto_?open|auto_?close|autoexec|document_open|document_close|workbook_open|workbook_activate|` +
	`shell(execute)?|wscript|cscript|createobject|getobject|callbyname|application\.run|executeexcel4macro|` +
	`urldownloadtofile|xmlhttp|serverxmlhttp|winhttp|adodb\.stream|savetofile|responsebody|` +
	`powershell|cmd(\.exe)?|mshta|rundll32|regsvr32|certutil|bitsadmin|` +
	`environ|kill|filecopy|createtextfile|open\s+.+\s+for\s+(output|binary|append)|` +
	`chrw?b?\s*\(|strreverse|base64|frombase64string|` +
	`declare\s+(ptrsafe\s+)?(function|sub)|lib\s+"|virtualalloc|rtlmovememory|createthread)\b`)

type codeLine struct {
	N    int
	Text string
	Hit  bool
}

type macroData struct {
	SHA      string
	Size     int64
	Time     time.Time
	Lines    []codeLine
	Hits     int
	Words    []kv
	Truncate bool
	Recs     []rec
}

func (s *server) macro(q *req) {
	sha := strings.ToLower(strings.TrimSpace(q.r.FormValue("sha")))
	if !shaRe.MatchString(sha) {
		s.render(q, "macro", "Макроси", errText("give the sha256 of the document"))
		return
	}
	f := filepath.Join(s.p.macroDir(), sha+".vba.txt")
	st, err := os.Stat(f)
	if err != nil {
		s.render(q, "macro", "Макроси", errText("no macro code of this document in "+s.p.macroDir()+" (kept 90 days / 500 MB)"))
		return
	}
	b, err := os.ReadFile(f)
	if err != nil {
		s.render(q, "macro", "Макроси", err)
		return
	}
	d := macroData{SHA: sha, Size: st.Size(), Time: st.ModTime()}
	const max = 2 << 20
	if len(b) > max {
		b, d.Truncate = b[:max], true
	}
	text := strings.ReplaceAll(strings.TrimPrefix(string(b), "\ufeff"), "\r\n", "\n")
	words := map[string]int{}
	for i, l := range strings.Split(text, "\n") {
		cl := codeLine{N: i + 1, Text: l}
		if m := suspicious.FindAllString(l, -1); m != nil {
			cl.Hit = true
			d.Hits++
			for _, w := range m {
				words[strings.ToLower(strings.Fields(w)[0])]++
			}
		}
		d.Lines = append(d.Lines, cl)
	}
	for k, n := range words {
		d.Words = append(d.Words, kv{k, n})
	}
	sort.Slice(d.Words, func(i, j int) bool {
		return d.Words[i].N > d.Words[j].N || d.Words[i].N == d.Words[j].N && d.Words[i].K < d.Words[j].K
	})
	d.Recs, _ = s.readRecords(filter{verdict: "all", text: sha}, 0, 20)
	s.render(q, "macro", "Код макросів", d)
}

type macroItem struct {
	SHA  string
	Size int64
	Time time.Time
	Rec  *rec
}

func (s *server) macros(q *req) {
	ents, _ := os.ReadDir(s.p.macroDir())
	recs, _ := s.readRecords(filter{verdict: "all"}, 0, maxScan)
	bySHA := map[string]*rec{}
	for i := range recs {
		k := strings.ToLower(recs[i].SHA)
		if _, ok := bySHA[k]; !ok && k != "" {
			bySHA[k] = &recs[i]
		}
	}
	var items []macroItem
	for _, e := range ents {
		n := e.Name()
		sha := strings.TrimSuffix(n, ".vba.txt")
		if e.IsDir() || !strings.HasSuffix(n, ".vba.txt") || !shaRe.MatchString(sha) {
			continue
		}
		st, err := e.Info()
		if err != nil {
			continue
		}
		items = append(items, macroItem{SHA: sha, Size: st.Size(), Time: st.ModTime(), Rec: bySHA[sha]})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Time.After(items[j].Time) })
	s.render(q, "macros", "Макроси", struct {
		Items []macroItem
		Dir   string
	}{items, s.p.macroDir()})
}

type errText string

func (e errText) Error() string { return string(e) }
