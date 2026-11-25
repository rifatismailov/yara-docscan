package main

// Записи docscan-results.json (і ротованих .1 .. .N — watcher ротує файл за розміром): читання з кінця, фільтр,
// запис за посиланням (номер файлу + зсув рядка). Лише читання. Опис: docscan-project/DOCSCAN.md#web.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// rec — запис для сторінок; File (0 = поточний файл, 1 = .1 ...) і Off — посилання на рядок.
type rec struct {
	File                                              int
	Off                                               int64
	Time                                              time.Time
	Event, Verdict, Path, Name, SHA, Summary, Disarm  string
	List, ListComment, AdminUser, AdminAction, ScanID string
	Rules                                             []string // знахідки і правила YARA, без повторів
}

type rawRec struct {
	Timestamp string `json:"timestamp"`
	Event     string `json:"event"`
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

const recTime = "2006-01-02T15:04:05.000-07:00"

func (x *rawRec) toRec(file int, off int64) rec {
	t, _ := time.Parse(recTime, x.Timestamp)
	r := rec{File: file, Off: off, Time: t, Event: x.Event, Verdict: x.Verdict, Path: x.DocFile.Path, Name: x.DocFile.Name,
		SHA: x.DocFile.Sha256, Summary: x.Summary, Disarm: x.Disarm, ScanID: x.Scan}
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
	add := func(names ...string) {
		for _, n := range names {
			if n != "" && !seen[n] {
				seen[n] = true
				r.Rules = append(r.Rules, n)
			}
		}
	}
	if d := x.Docscan; d != nil {
		add(d.Findings...)
		add(d.YaraMatches...)
		add(d.YaraDocMatches...)
		for _, pm := range d.YaraPartMatches {
			add(pm.Rules...)
		}
	}
	add(x.YaraFileMatches...)
	return r
}

type filter struct {
	verdict string // "" — виявлення (усе, крім INFO); "all"; HIGH / MEDIUM / LOW / INFO / SKIPPED
	text    string // підрядок у шляху / описі / sha256 / коментарі списку / id скану
	rule    string // правило / знахідка
	since   time.Time
	admin   bool // лише дії у вебі
}

func (f filter) match(r *rec) bool {
	if !f.since.IsZero() && r.Time.Before(f.since) || f.admin != (r.Event == "Admin") {
		return false
	}
	if !f.admin {
		switch f.verdict {
		case "all":
		case "":
			if r.Verdict == "INFO" || r.Verdict == "" {
				return false
			}
		default:
			if r.Verdict != f.verdict {
				return false
			}
		}
	}
	if f.text != "" && !strings.Contains(strings.ToLower(r.Path+" "+r.Summary+" "+r.SHA+" "+r.ListComment+" "+r.ScanID), strings.ToLower(f.text)) {
		return false
	}
	if f.rule != "" {
		for _, n := range r.Rules {
			if strings.EqualFold(n, f.rule) {
				return true
			}
		}
		return false
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
		for end := len(b); end > 0 && scanned < maxScan; { // рядки з кінця
			start := bytes.LastIndexByte(b[:end], '\n')
			line := bytes.TrimSpace(b[start+1 : end])
			end = max(start, 0)
			if len(line) == 0 || line[0] != '{' {
				continue
			}
			scanned++
			var x rawRec
			if json.Unmarshal(line, &x) != nil {
				continue
			}
			if r := x.toRec(i, int64(start+1)); f.match(&r) {
				total++
				if total > skip && len(out) < limit {
					out = append(out, r)
				}
			}
		}
	}
	return out, total
}

var errRotated = errors.New("запису вже немає на цьому місці (файл результатів ротовано) — відкрийте список ще раз")

// recordLine — рядок запису за посиланням (fs — номер файлу, os_ — зсув): сам рядок і розібраний запис.
func (s *server) recordLine(fs, os_ string) ([]byte, *rawRec, error) {
	fi, err1 := strconv.Atoi(fs)
	off, err2 := strconv.ParseInt(os_, 10, 64)
	files := s.resultFiles()
	if err1 != nil || err2 != nil || fi < 0 || fi >= len(files) || off < 0 {
		return nil, nil, errRotated
	}
	f, err := os.Open(files[fi])
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, nil, err
	}
	b := make([]byte, 1<<20)
	n, _ := io.ReadFull(f, b)
	b = b[:n]
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	b = bytes.TrimSpace(b)
	var x rawRec
	if json.Unmarshal(b, &x) != nil {
		return nil, nil, errRotated
	}
	return b, &x, nil
}

// kv — назва і кількість (теги «найчастіші правила», слова в коді макросів).
type kv struct {
	K string
	N int
}
