package main

// Сторінки «Виявлення» (список із фільтрами, дії у вебі), «Запис» (один запис повністю) і «Журнали».
// Опис: docscan-project/DOCSCAN.md#web.

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type detData struct {
	Verdict, Text, Rule, Days string
	Admin                     bool
	Recs                      []rec
	Total, Page, Pages        int
	TopRules                  []kv
}

const perPage = 100

func (s *server) detections(q *req) {
	f := q.r.FormValue
	d := detData{Verdict: f("verdict"), Text: strings.TrimSpace(f("q")), Rule: strings.TrimSpace(f("rule")), Days: f("days"), Admin: f("admin") == "1"}
	d.Page, _ = strconv.Atoi(f("page"))
	d.Page = max(d.Page, 0)
	flt := filter{verdict: d.Verdict, text: d.Text, rule: d.Rule, admin: d.Admin}
	switch d.Days {
	case "1", "7", "30":
		n, _ := strconv.Atoi(d.Days)
		flt.since = time.Now().Add(-time.Duration(n) * 24 * time.Hour)
	}
	d.Recs, d.Total = s.readRecords(flt, d.Page*perPage, perPage)
	d.Pages = (d.Total + perPage - 1) / perPage
	// найчастіші правила на сторінці (швидкий фільтр «усе за правилом»)
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
		a, b := d.TopRules[i], d.TopRules[j]
		return a.N > b.N || a.N == b.N && a.K < b.K
	})
	d.TopRules = d.TopRules[:min(len(d.TopRules), 20)]
	s.render(q, "detections", "Виявлення", d)
}

type recordData struct {
	Rec  rec
	JSON string
	Doc  *docView
}

// record — один запис повністю (посилання: номер файлу і зсув; після ротації посилання застаріває).
func (s *server) record(q *req) {
	line, x, err := s.recordLine(q.r.FormValue("f"), q.r.FormValue("o"))
	if err != nil {
		s.render(q, "record", "Запис", err)
		return
	}
	fi, _ := strconv.Atoi(q.r.FormValue("f"))
	off, _ := strconv.ParseInt(q.r.FormValue("o"), 10, 64)
	var pretty bytes.Buffer
	json.Indent(&pretty, line, "", "  ")
	s.render(q, "record", "Запис", recordData{Rec: x.toRec(fi, off), JSON: pretty.String(), Doc: s.docView(line)})
}

type logsData struct {
	Which, Text string
	Files       []string
	Lines       []string
}

// logs — останні 500 рядків журналу служби (з фільтром), найновіші зверху.
func (s *server) logs(q *req) {
	files := []string{"watcher", "updater", "web"}
	d := logsData{Which: q.r.FormValue("which"), Text: strings.TrimSpace(q.r.FormValue("q")), Files: files}
	if d.Which != "updater" && d.Which != "web" {
		d.Which = "watcher"
	}
	lines := tailLines(filepath.Join(s.p.results(), d.Which+".log"), 5000)
	for i := len(lines) - 1; i >= 0 && len(d.Lines) < 500; i-- {
		if d.Text == "" || strings.Contains(strings.ToLower(lines[i]), strings.ToLower(d.Text)) {
			d.Lines = append(d.Lines, lines[i])
		}
	}
	s.render(q, "logs", "Журнали", d)
}
