package main

// Сторінка «Дозволені й заблоковані»: білий і чорний списки. Записи організації (lists\whitelist.json /
// blacklist.json, з дзеркала) — лише перегляд; записи цього ПК (whitelist.local.json / blacklist.local.json) watcher
// застосовує разом зі списками організації, дзеркало їх не перезаписує. Типовий випадок: свою програму забрано в
// карантин -> на записі виявлення «Дозволити і повернути файл»: path + sha256 у дозволені, файл — назад на місце.
// Маршрут лишився /exceptions (посилання з записів). Опис: docscan-project/DOCSCAN.md#lists.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"docscan/services/pkg/orglists"
)

const listsTitle = "Дозволені й заблоковані"

// listsReload — watcher перечитує списки не частіше разу на 2 с: файл, повернутий раніше, знову пішов би в карантин.
const listsReload = 3 * time.Second

func readList(file, kind string) (*orglists.List, error) {
	b, err := os.ReadFile(file)
	if os.IsNotExist(err) {
		return &orglists.List{Schema: orglists.Schema}, nil
	}
	if err != nil {
		return nil, err
	}
	return orglists.Parse(b, kind)
}

// writeLocalList — перевірка тим самим кодом, що watcher (orglists.Parse), потім запис.
func writeLocalList(p paths, kind string, l *orglists.List) error {
	l.Schema, l.Serial = orglists.Schema, time.Now().Unix()
	if l.Description == "" {
		l.Description = "Local " + kind + " list of this PC (DocScan web interface)"
	}
	if l.Entries == nil {
		l.Entries = []orglists.Entry{}
	}
	b, _ := json.MarshalIndent(l, "", "  ")
	if _, err := orglists.Parse(b, kind); err != nil {
		return err
	}
	os.MkdirAll(p.listsDir(), 0o755)
	err := writeFileAtomic(p.listFile(kind, true), append(b, '\n'), 0o644)
	markWeb(p.listFile(kind, true))
	return err
}

func entryText(e orglists.Entry) string {
	return fmt.Sprintf("path=%q lnk_target=%q sha256=%q comment=%q", e.Path, e.LnkTarget, e.SHA256, e.Comment)
}

// addLocal — запис у локальний список цього ПК і аудит.
func (s *server) addLocal(q *req, kind string, e orglists.Entry) error {
	l, err := readList(s.p.listFile(kind, true), kind)
	if err != nil {
		return fmt.Errorf("локальний список зламаний: %v", err)
	}
	l.Entries = append(l.Entries, e)
	if err := writeLocalList(s.p, kind, l); err != nil {
		return fmt.Errorf("не збережено: %v", err)
	}
	s.audit(q.r, AdminUser, "local-"+kind+"-added", entryText(e))
	return nil
}

// putBack — копія з карантину src на місце dst (replace — замінити файл, що вже там є: знешкоджену копію
// документа), після чого копія з карантину зникає.
func putBack(src, dst string, replace bool) error {
	if replace {
		tmp := dst + ".docscan-restore"
		os.Remove(tmp)
		if err := copyFile(src, tmp); err != nil {
			return err
		}
		if err := os.Rename(tmp, dst); err != nil { // Windows: замінює (MoveFileEx REPLACE_EXISTING)
			os.Remove(tmp)
			return fmt.Errorf("файл відкритий? %v", err)
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		if err := copyFile(src, dst); err != nil {
			return err
		}
	}
	return os.Remove(src)
}

// ---------------------------------------------------------------- сторінка

type listView struct {
	Kind, File, Error string
	Entries           []orglists.Entry
}

type exData struct {
	LocalWhite, LocalBlack, MirrorWhite, MirrorBlack listView
	Pause                                            pauseState // розділ «Заблоковані»: чи діє блокування
	DetectOnly                                       bool
	// форма «Додати запис» (з посилання на запис виявлення — шлях, sha256, чи файл у карантині)
	Kind, Path, Lnk, SHA, Comment string
	F, O                          string
	Quarantined                   bool
}

func (s *server) view(kind string, local bool) listView {
	v := listView{Kind: kind, File: s.p.listFile(kind, local)}
	if l, err := readList(v.File, kind); err != nil {
		v.Error = err.Error()
	} else {
		v.Entries = l.Entries
	}
	return v
}

func (s *server) exData() exData {
	d := exData{LocalWhite: s.view("white", true), LocalBlack: s.view("black", true),
		MirrorWhite: s.view("white", false), MirrorBlack: s.view("black", false), Kind: "white"}
	if set, err := readSettings(s.p); err == nil {
		d.Pause = pauseOf(set, time.Now())
		d.DetectOnly, _ = s.effectiveDetectOnly(set)
	}
	return d
}

func (s *server) exceptions(q *req) {
	f := q.r.FormValue
	d := s.exData()
	if f("kind") == "black" {
		d.Kind = "black"
	}
	d.Path, d.SHA, d.Lnk = f("path"), f("sha"), f("lnk")
	if f("f") != "" {
		if _, x, err := s.recordLine(f("f"), f("o")); err == nil {
			d.F, d.O = f("f"), f("o")
			d.Path, d.SHA = x.DocFile.Path, x.DocFile.Sha256
			d.Quarantined = x.Disarm == "quarantined"
			d.Comment = "allowed after a block: " + x.DocFile.Name
		}
	}
	s.render(q, "exceptions", listsTitle, d)
}

func (s *server) exceptionAdd(q *req) {
	if q.r.Method != "POST" {
		s.back(q, "/exceptions", "")
		return
	}
	f := q.r.FormValue
	kind := f("kind")
	if kind != "black" {
		kind = "white"
	}
	e := orglists.Entry{Path: strings.TrimSpace(f("path")), LnkTarget: strings.TrimSpace(f("lnk")),
		SHA256: strings.ToLower(strings.TrimSpace(f("sha"))), Comment: strings.TrimSpace(f("comment")),
		Added: time.Now().Format("2006-01-02"), By: AdminUser}
	if f("scope") == "path" { // будь-яка версія за цим шляхом
		e.SHA256 = ""
	}
	if err := s.addLocal(q, kind, e); err != nil {
		d := s.exData()
		d.Kind, d.Path, d.Lnk, d.SHA, d.Comment, d.F, d.O = kind, e.Path, e.LnkTarget, f("sha"), e.Comment, f("f"), f("o")
		d.Quarantined = f("restore") == "on"
		s.renderErr(q, "exceptions", listsTitle, d, err)
		return
	}
	msg := map[string]string{"white": "додано в дозволені: файл не перевірятиметься і не блокуватиметься (watcher застосує за кілька секунд)",
		"black": "додано в заблоковані: файл забиратиметься в карантин на цьому ПК (watcher застосує за кілька секунд)"}[kind]
	if kind == "white" && f("restore") == "on" && f("f") != "" {
		time.Sleep(listsReload)
		where, err := s.restore(f("f"), f("o"))
		if err != nil {
			s.audit(q.r, AdminUser, "restore-failed", err.Error())
			s.back(q, "/exceptions", msg+"; файл НЕ повернуто: "+err.Error())
			return
		}
		s.audit(q.r, AdminUser, "restored", where)
		msg += "; файл повернуто з карантину: " + where
	}
	s.back(q, "/exceptions", msg)
}

func (s *server) exceptionRemove(q *req) {
	if q.r.Method != "POST" {
		s.back(q, "/exceptions", "")
		return
	}
	kind := q.r.FormValue("kind")
	i, err := strconv.Atoi(q.r.FormValue("i"))
	l, lerr := readList(s.p.listFile(kind, true), kind)
	if (kind != "white" && kind != "black") || err != nil || lerr != nil || i < 0 || i >= len(l.Entries) {
		s.back(q, "/exceptions", "запис не знайдено (сторінку оновлено)")
		return
	}
	e := l.Entries[i]
	l.Entries = append(l.Entries[:i], l.Entries[i+1:]...)
	if err := writeLocalList(s.p, kind, l); err != nil {
		s.render(q, "exceptions", listsTitle, err)
		return
	}
	s.audit(q.r, AdminUser, "local-"+kind+"-removed", entryText(e))
	s.back(q, "/exceptions", "запис прибрано")
}

// restore — файл запису виявлення з карантину на місце: копія <ім'я>.<N>.docscan-bak з тим самим sha256.
// Місце вже зайняте — не перезаписує.
func (s *server) restore(fs, os_ string) (string, error) {
	_, x, err := s.recordLine(fs, os_)
	if err != nil {
		return "", err
	}
	dst, sha := x.DocFile.Path, strings.ToLower(x.DocFile.Sha256)
	if x.Disarm != "quarantined" || dst == "" || sha == "" {
		return "", errors.New("у цього запису немає файлу в карантині")
	}
	if _, err := os.Lstat(dst); err == nil {
		return "", fmt.Errorf("%s уже існує — не перезаписано", dst)
	}
	base := baseOf(dst)
	cands, _ := filepath.Glob(filepath.Join(s.p.quarantine(), globEscape(base)+".*.docscan-bak"))
	for _, c := range cands {
		if h, err := fileSHA(c); err == nil && h == sha {
			return dst, putBack(c, dst, false)
		}
	}
	return "", fmt.Errorf("у карантині немає копії %s з sha256 %s (вже повернуто або видалено?)", base, sha)
}
