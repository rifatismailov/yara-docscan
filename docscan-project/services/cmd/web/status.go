package main

// Сторінка «Стан»: версії програми й правил, режим, служби, списки організації, оновлення, лічильники за добу.
// Лише читання файлів, які пишуть watcher, updater та інсталятор. Опис: docscan-project/DOCSCAN.md#web.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"docscan/services/pkg/orglists"
)

type listState struct {
	Kind, File, Error string
	Present, Prev     bool
	Serial            int64
	Entries           int
}

type svcState struct{ Name, Display, State, Start string }

type updRec struct {
	Time                                 time.Time
	Status, Component, From, To, Message string
}

type statusData struct {
	Program, Rules string
	CriticalFiles  int
	DetectOnly     bool
	ModeSource     string
	WatchPath      []string
	Pause          pauseState
	SettingsErr    string
	Services       []svcState
	Lists          []listState
	UpdMode        string
	UpdMirror      string
	RulesMirror    string
	ListsURL       string
	Updates        []updRec
	Counts         map[string]int // за 24 год: HIGH / MEDIUM / LOW / INFO / SKIPPED
	CertUntil      time.Time
	InitialPw      bool
}

// installJSON — параметри встановлення (install.ps1 пише, -Reuse читає).
type installJSON struct {
	Params struct {
		DetectOnly bool     `json:"DetectOnly"`
		WatchPath  []string `json:"WatchPath"`
	} `json:"params"`
}

func install(p paths) *installJSON {
	var j installJSON
	if !readJSON(p.installJSON(), &j) {
		return nil
	}
	return &j
}

func (s *server) status(q *req) {
	d := statusData{Counts: map[string]int{}, Services: services(), InitialPw: fileExists(s.p.initialPw())}
	d.Program = firstLine(s.p.programVersion())
	d.Rules = firstLine(filepath.Join(s.p.rulesDir(), "VERSION.txt"))
	crit, _ := filepath.Glob(filepath.Join(s.p.rulesDir(), "critical", "*.yar"))
	d.CriticalFiles = len(crit)

	set, err := readSettings(s.p)
	if err != nil {
		d.SettingsErr = err.Error()
	}
	d.DetectOnly, d.ModeSource = s.effectiveDetectOnly(set)
	d.Pause = pauseOf(set, time.Now())
	d.WatchPath = set.WatchPath
	if ip := install(s.p); ip != nil && len(d.WatchPath) == 0 {
		d.WatchPath = ip.Params.WatchPath
	}

	for _, kind := range []string{"white", "black"} {
		f := s.p.listFile(kind, false)
		ls := listState{Kind: kind, File: f, Prev: fileExists(f + ".prev")}
		if b, err := os.ReadFile(f); err == nil {
			ls.Present = true
			if l, err := orglists.Parse(b, kind); err == nil {
				ls.Serial, ls.Entries = l.Serial, len(l.Entries)
			} else {
				ls.Error = err.Error()
			}
		}
		d.Lists = append(d.Lists, ls)
	}

	var u struct {
		Mode   string `json:"mode"`
		Mirror urlRef `json:"mirror"`
		Rules  struct {
			Mirror urlRef `json:"mirror"`
		} `json:"rules"`
		Lists urlRef `json:"lists"`
	}
	readJSON(s.p.updaterJSON(), &u)
	d.UpdMode, d.UpdMirror, d.RulesMirror, d.ListsURL = u.Mode, u.Mirror.URL, u.Rules.Mirror.URL, u.Lists.URL
	for _, l := range tailLines(s.p.updatesLog(), 12) {
		var r struct {
			Timestamp string `json:"timestamp"`
			Update    struct {
				Status, Component, From, To, Message string
			} `json:"update"`
		}
		if json.Unmarshal([]byte(l), &r) == nil {
			t, _ := time.Parse(recTime, r.Timestamp)
			u := r.Update
			d.Updates = append([]updRec{{t, u.Status, u.Component, u.From, u.To, u.Message}}, d.Updates...)
		}
	}

	recs, _ := s.readRecords(filter{verdict: "all", since: time.Now().Add(-24 * time.Hour)}, 0, 1<<30)
	for _, r := range recs {
		d.Counts[r.Verdict]++
	}
	if b, err := os.ReadFile(s.p.certPEM()); err == nil {
		d.CertUntil = certNotAfter(b)
	}
	s.render(q, "status", "Стан", d)
}
