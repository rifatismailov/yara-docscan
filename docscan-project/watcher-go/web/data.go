package main

// Що показує веб: стан DocScan (версії, служби, списки, оновлення), виявлення з docscan-results.json (і ротованих
// .1 .. .N — watcher ротує файл за розміром), журнали. Лише читання файлів, які пишуть watcher і updater.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"docscan/watcher/orglists"
)

// ---------------------------------------------------------------- журнал служби і запис у файли

type logger struct {
	mu   sync.Mutex
	file string
}

func newLogger(file string) *logger {
	os.MkdirAll(filepath.Dir(file), 0o755)
	return &logger{file: file}
}

// Log — "<yyyy-MM-dd HH:mm:ss> [LEVEL] message" (як watcher.log).
func (l *logger) Log(level, format string, args ...any) {
	line := fmt.Sprintf("%s [%s] %s", time.Now().Format("2006-01-02 15:04:05"), level, fmt.Sprintf(format, args...))
	fmt.Println(line)
	l.mu.Lock()
	defer l.mu.Unlock()
	rotateIfBig(l.file, 5<<20, 3)
	appendLine(l.file, []byte(line+"\r\n"))
}

func rotateIfBig(file string, maxBytes int64, keep int) {
	st, err := os.Stat(file)
	if err != nil || st.Size() < maxBytes {
		return
	}
	for k := keep - 1; k >= 1; k-- {
		os.Rename(fmt.Sprintf("%s.%d", file, k), fmt.Sprintf("%s.%d", file, k+1))
	}
	os.Rename(file, file+".1")
}

// appendLine — один запис у кінець файлу (O_APPEND: рядок не перемішується з рядками watcher-а).
func appendLine(file string, b []byte) error {
	f, err := os.OpenFile(file, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func firstLine(file string) string {
	f, err := os.Open(file)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	if sc.Scan() {
		return strings.TrimSpace(strings.TrimPrefix(sc.Text(), "\ufeff"))
	}
	return ""
}

// tailLines — останні n рядків файлу (читає не більше 8 МБ з кінця).
func tailLines(file string, n int) []string {
	f, err := os.Open(file)
	if err != nil {
		return nil
	}
	defer f.Close()
	st, _ := f.Stat()
	const max = 8 << 20
	off := int64(0)
	if st.Size() > max {
		off = st.Size() - max
	}
	f.Seek(off, io.SeekStart)
	b, _ := io.ReadAll(f)
	if off > 0 {
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			b = b[i+1:]
		}
	}
	lines := strings.Split(strings.TrimRight(strings.ReplaceAll(string(b), "\r\n", "\n"), "\n"), "\n")
	if len(lines) == 1 && lines[0] == "" {
		return nil
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines
}

// ---------------------------------------------------------------- стан

type listState struct {
	Kind, File, Error string
	Present           bool
	Serial            int64
	Entries           int
	Prev              bool
}

type svcState struct{ Name, Display, State, Start string }

type updRec struct {
	Time                                         time.Time
	Status, Component, From, To, Source, Message string
}

type statusData struct {
	Program, Rules string
	CriticalFiles  int
	Lists          []listState
	Services       []svcState
	DetectOnly     bool
	WatchPath      []string
	ModeSource     string
	UpdMode        string
	UpdMirror      string
	RulesMirror    string
	ListsURL       string
	Updates        []updRec
	Counts         map[string]int // за 24 год: HIGH / MEDIUM / LOW / INFO / SKIPPED
	CertUntil      time.Time
	InitialPw      bool
	Pause          pauseState
	SettingsErr    string
}

func (s *server) status(q *req) {
	d := statusData{Counts: map[string]int{}}
	d.Program = firstLine(filepath.Join(s.p.install, "VERSION.txt"))
	d.Rules = firstLine(filepath.Join(s.p.install, "rules", "VERSION.txt"))
	if m, _ := filepath.Glob(filepath.Join(s.p.install, "rules", "critical", "*.yar")); m != nil {
		d.CriticalFiles = len(m)
	}
	for _, k := range []struct{ kind, file string }{{"white", "whitelist.json"}, {"black", "blacklist.json"}} {
		f := filepath.Join(s.p.data, "lists", k.file)
		ls := listState{Kind: k.kind, File: f, Prev: fileExists(f + ".prev")}
		if b, err := os.ReadFile(f); err == nil {
			ls.Present = true
			if l, err := orglists.Parse(b, k.kind); err == nil {
				ls.Serial, ls.Entries = l.Serial, len(l.Entries)
			} else {
				ls.Error = err.Error()
			}
		}
		d.Lists = append(d.Lists, ls)
	}
	d.Services = services()
	// режим watcher: settings.json (веб), інакше параметр служби (-NoDisarm) / install.json
	set, serr := readSettings(s.p)
	if serr != nil {
		d.SettingsErr = serr.Error()
	}
	d.DetectOnly, d.ModeSource = s.effectiveDetectOnly(set)
	if ip := install(s.p); ip != nil {
		d.WatchPath = ip.Params.WatchPath
	}
	if len(set.WatchPath) > 0 {
		d.WatchPath = set.WatchPath
	}
	d.Pause = pauseOf(set, time.Now())
	var u struct {
		Mode   string `json:"mode"`
		Mirror struct {
			URL string `json:"url"`
		} `json:"mirror"`
		Rules struct {
			Mirror struct {
				URL string `json:"url"`
			} `json:"mirror"`
		} `json:"rules"`
		Lists struct {
			URL string `json:"url"`
		} `json:"lists"`
	}
	if b, err := os.ReadFile(filepath.Join(s.p.data, "update", "updater.json")); err == nil {
		json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &u)
	}
	d.UpdMode, d.UpdMirror, d.RulesMirror, d.ListsURL = u.Mode, u.Mirror.URL, u.Rules.Mirror.URL, u.Lists.URL
	for _, l := range tailLines(filepath.Join(s.p.results(), "docscan-updates.json"), 12) {
		var r struct {
			Timestamp string `json:"timestamp"`
			Update    struct {
				Status, Component, From, To, Source, Message string
			} `json:"update"`
		}
		if json.Unmarshal([]byte(l), &r) == nil {
			t, _ := time.Parse("2006-01-02T15:04:05.000-07:00", r.Timestamp)
			d.Updates = append([]updRec{{t, r.Update.Status, r.Update.Component, r.Update.From, r.Update.To, r.Update.Source, r.Update.Message}}, d.Updates...)
		}
	}
	since := time.Now().Add(-24 * time.Hour)
	recs, _ := s.readRecords(filter{since: since, admin: false, all: true}, 0, 1<<30)
	for _, r := range recs {
		d.Counts[r.Verdict]++
	}
	if b, err := os.ReadFile(s.p.certPEM()); err == nil {
		d.CertUntil = certNotAfter(b)
	}
	d.InitialPw = fileExists(s.p.initialPw())
	s.render(q, "status", "Стан", d)
}

type installJSON struct {
	Installed string `json:"installed"`
	Params    struct {
		DetectOnly bool     `json:"DetectOnly"`
		WatchPath  []string `json:"WatchPath"`
	} `json:"params"`
}

func install(p paths) *installJSON {
	b, err := os.ReadFile(filepath.Join(p.data, "install.json"))
	if err != nil {
		return nil
	}
	var j installJSON
	if json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &j) != nil {
		return nil
	}
	return &j
}

// ---------------------------------------------------------------- виявлення

// rec — запис docscan-results.json для списку; ID — файл (0 = поточний, 1 = .1 ...) і зсув рядка.
type rec struct {
	File                                               int
	Off                                                int64
	Time                                               time.Time
	Event, Verdict, Category, Path, Name, SHA, Summary string
	Disarm, List, ListComment, AdminUser, AdminAction  string
	Scan                                               string // id скану (scan.go)
	Rules                                              []string
}

type rawRec struct {
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`
	Category  string `json:"category"`
	Verdict   string `json:"verdict"`
	Summary   string `json:"summary"`
	Disarm    string `json:"disarm"`
	Scan      string `json:"scan"`
	DocFile   struct {
		Path   string `json:"path"`
		Name   string `json:"name"`
		Sha256 string `json:"sha256"`
	} `json:"docfile"`
	List *struct {
		List    string `json:"list"`
		Source  string `json:"source"`
		By      string `json:"by"`
		Comment string `json:"comment"`
	} `json:"list"`
	YaraFileMatches []string `json:"yara_file_matches"`
	Docscan         *struct {
		Findings        []string `json:"findings"`
		YaraMatches     []string `json:"yara_matches"`
		YaraDocMatches  []string `json:"yara_doc_matches"`
		YaraPartMatches []struct {
			Rules []string `json:"rules"`
		} `json:"yara_part_matches"`
	} `json:"docscan"`
	Admin *struct {
		User   string `json:"user"`
		Action string `json:"action"`
		Detail string `json:"detail"`
	} `json:"admin"`
}

func (x *rawRec) toRec(file int, off int64) rec {
	t, _ := time.Parse("2006-01-02T15:04:05.000-07:00", x.Timestamp)
	r := rec{File: file, Off: off, Time: t, Event: x.Event, Verdict: x.Verdict, Category: x.Category, Path: x.DocFile.Path,
		Name: x.DocFile.Name, SHA: x.DocFile.Sha256, Summary: x.Summary, Disarm: x.Disarm}
	r.Scan = x.Scan
	if x.List != nil {
		r.List, r.ListComment = x.List.List+" / "+x.List.By, x.List.Comment
		if x.List.Source != "" {
			r.List += " (" + x.List.Source + ")"
		}
	}
	if x.Admin != nil {
		r.AdminUser, r.AdminAction, r.Summary = x.Admin.User, x.Admin.Action, x.Admin.Detail
	}
	seen := map[string]bool{}
	addR := func(n string) {
		if n != "" && !seen[n] {
			seen[n] = true
			r.Rules = append(r.Rules, n)
		}
	}
	if x.Docscan != nil {
		for _, f := range x.Docscan.Findings {
			addR(f)
		}
		for _, n := range x.Docscan.YaraMatches {
			addR(n)
		}
		for _, n := range x.Docscan.YaraDocMatches {
			addR(n)
		}
		for _, pm := range x.Docscan.YaraPartMatches {
			for _, n := range pm.Rules {
				addR(n)
			}
		}
	}
	for _, n := range x.YaraFileMatches {
		addR(n)
	}
	return r
}

type filter struct {
	verdict string // "" — виявлення (усе, крім INFO); "all"; HIGH / MEDIUM / LOW / INFO / SKIPPED
	text    string // підрядок у шляху / summary
	rule    string // правило / finding
	since   time.Time
	admin   bool // лише дії у веб
	all     bool // усі рівні (для лічильників)
}

func (f filter) match(r *rec) bool {
	if !f.since.IsZero() && r.Time.Before(f.since) {
		return false
	}
	if f.admin != (r.Event == "Admin") {
		return false
	}
	if !f.admin && !f.all {
		switch f.verdict {
		case "":
			if r.Verdict == "INFO" || r.Verdict == "" {
				return false
			}
		case "all":
		default:
			if r.Verdict != f.verdict {
				return false
			}
		}
	}
	if f.text != "" {
		t := strings.ToLower(f.text)
		if !strings.Contains(strings.ToLower(r.Path+" "+r.Summary+" "+r.SHA+" "+r.ListComment+" "+r.Scan), t) {
			return false
		}
	}
	if f.rule != "" {
		ok := false
		for _, n := range r.Rules {
			if strings.EqualFold(n, f.rule) {
				ok = true
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// resultFiles — docscan-results.json, .1, .2 ... (найновіший перший).
func (s *server) resultFiles() []string {
	fs := []string{s.p.resultsLog()}
	for i := 1; i <= 50; i++ {
		f := fmt.Sprintf("%s.%d", s.p.resultsLog(), i)
		if !fileExists(f) {
			break
		}
		fs = append(fs, f)
	}
	return fs
}

const maxScan = 200_000 // записів за один перегляд (кілька ротованих файлів)

// readRecords — записи, що підходять, від найновіших: пропустити skip, повернути не більше limit; і скільки всього.
func (s *server) readRecords(f filter, skip, limit int) ([]rec, int) {
	var out []rec
	total, scanned := 0, 0
	for i, file := range s.resultFiles() {
		b, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		// рядки з кінця
		end := len(b)
		for end > 0 && scanned < maxScan {
			start := bytes.LastIndexByte(b[:end], '\n')
			line := b[start+1 : end]
			end = start
			if start < 0 {
				end = 0
			}
			line = bytes.TrimSpace(line)
			if len(line) == 0 || line[0] != '{' {
				continue
			}
			scanned++
			var x rawRec
			if json.Unmarshal(line, &x) != nil {
				continue
			}
			r := x.toRec(i, int64(start+1))
			if !f.match(&r) {
				continue
			}
			if !f.since.IsZero() && r.Time.Before(f.since) {
				continue
			}
			total++
			if total > skip && len(out) < limit {
				out = append(out, r)
			}
		}
	}
	return out, total
}

type detData struct {
	Verdict, Text, Rule, Days string
	Admin                     bool
	Recs                      []rec
	Total, Page, Pages        int
	TopRules                  []kv
}

type kv struct {
	K string
	N int
}

const perPage = 100

func (s *server) detections(q *req) {
	r := q.r
	d := detData{Verdict: r.FormValue("verdict"), Text: strings.TrimSpace(r.FormValue("q")), Rule: strings.TrimSpace(r.FormValue("rule")),
		Days: r.FormValue("days"), Admin: r.FormValue("admin") == "1"}
	d.Page, _ = strconv.Atoi(r.FormValue("page"))
	if d.Page < 0 {
		d.Page = 0
	}
	f := filter{verdict: d.Verdict, text: d.Text, rule: d.Rule, admin: d.Admin}
	switch d.Days {
	case "1", "7", "30":
		n, _ := strconv.Atoi(d.Days)
		f.since = time.Now().Add(-time.Duration(n) * 24 * time.Hour)
	}
	d.Recs, d.Total = s.readRecords(f, d.Page*perPage, perPage)
	d.Pages = (d.Total + perPage - 1) / perPage
	// найчастіші правила серед того, що на сторінці (швидкий фільтр «усе за правилом»)
	cnt := map[string]int{}
	for _, x := range d.Recs {
		for _, n := range x.Rules {
			cnt[n]++
		}
	}
	for k, n := range cnt {
		d.TopRules = append(d.TopRules, kv{k, n})
	}
	sort.Slice(d.TopRules, func(i, j int) bool {
		if d.TopRules[i].N != d.TopRules[j].N {
			return d.TopRules[i].N > d.TopRules[j].N
		}
		return d.TopRules[i].K < d.TopRules[j].K
	})
	if len(d.TopRules) > 20 {
		d.TopRules = d.TopRules[:20]
	}
	s.render(q, "detections", "Виявлення", d)
}

type recordData struct {
	Rec  rec
	JSON string
	Doc  *docView
}

// record — один запис повністю (файл і зсув — з посилання; після ротації посилання застаріває).
func (s *server) record(q *req) {
	fi, _ := strconv.Atoi(q.r.FormValue("f"))
	off, _ := strconv.ParseInt(q.r.FormValue("o"), 10, 64)
	files := s.resultFiles()
	if fi < 0 || fi >= len(files) || off < 0 {
		s.render(q, "record", "Запис", fmt.Errorf("no such record (the results file may have been rotated - open the list again)"))
		return
	}
	f, err := os.Open(files[fi])
	if err != nil {
		s.render(q, "record", "Запис", err)
		return
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		s.render(q, "record", "Запис", err)
		return
	}
	br := bufio.NewReaderSize(f, 1<<20)
	line, err := br.ReadBytes('\n')
	if err != nil && err != io.EOF {
		s.render(q, "record", "Запис", err)
		return
	}
	var x rawRec
	var pretty bytes.Buffer
	if json.Unmarshal(bytes.TrimSpace(line), &x) != nil || json.Indent(&pretty, bytes.TrimSpace(line), "", "  ") != nil {
		s.render(q, "record", "Запис", fmt.Errorf("no record at this place (the results file may have been rotated - open the list again)"))
		return
	}
	s.render(q, "record", "Запис", recordData{Rec: x.toRec(fi, off), JSON: pretty.String(), Doc: s.docView(line)})
}

// ---------------------------------------------------------------- журнали

type logsData struct {
	Which, Text string
	Files       []string
	Lines       []string
}

func (s *server) logs(q *req) {
	which := q.r.FormValue("which")
	files := map[string]string{"watcher": "watcher.log", "updater": "updater.log", "web": "web.log"}
	if files[which] == "" {
		which = "watcher"
	}
	d := logsData{Which: which, Text: strings.TrimSpace(q.r.FormValue("q")), Files: []string{"watcher", "updater", "web"}}
	lines := tailLines(filepath.Join(s.p.results(), files[which]), 5000)
	for i := len(lines) - 1; i >= 0 && len(d.Lines) < 500; i-- {
		if d.Text == "" || strings.Contains(strings.ToLower(lines[i]), strings.ToLower(d.Text)) {
			d.Lines = append(d.Lines, lines[i])
		}
	}
	s.render(q, "logs", "Журнали", d)
}
