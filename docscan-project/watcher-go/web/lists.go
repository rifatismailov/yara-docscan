package main

// Етап 3 (WEB-DESIGN.md): «Виключення» — локальні списки цього ПК (lists\whitelist.local.json /
// blacklist.local.json). Watcher застосовує їх разом зі списками з дзеркала організації (Pollen), дзеркало їх не
// перезаписує. Типовий випадок: своя програма заблокована на робочому столі -> на записі виявлення «додати у
// виключення і повернути»: запис path + sha256 у локальний білий список, файл — назад з карантину.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"docscan/watcher/orglists"
)

func (p paths) listsDir() string   { return filepath.Join(p.data, "lists") }
func (p paths) quarantine() string { return filepath.Join(p.data, "quarantine") }

// listFile — файл списку: kind white | black, local — цього ПК (інакше — з дзеркала).
func (p paths) listFile(kind string, local bool) string {
	n := kind + "list"
	if local {
		n += ".local"
	}
	return filepath.Join(p.listsDir(), n+".json")
}

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
	l.Schema = orglists.Schema
	l.Serial = time.Now().Unix()
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
	return writeFileAtomic(p.listFile(kind, true), append(b, '\n'), 0o644)
}

type listView struct {
	Kind, File, Error string
	Entries           []orglists.Entry
}

type exData struct {
	LocalWhite, LocalBlack, MirrorWhite, MirrorBlack listView
	// форма (з посилання на запис виявлення)
	Kind, Path, Lnk, SHA, Comment string
	F, O                          string // запис виявлення (для «повернути з карантину»)
	Quarantined                   bool
}

func (s *server) view(kind string, local bool) listView {
	f := s.p.listFile(kind, local)
	v := listView{Kind: kind, File: f}
	l, err := readList(f, kind)
	if err != nil {
		v.Error = err.Error()
	} else {
		v.Entries = l.Entries
	}
	return v
}

func (s *server) exData() exData {
	return exData{LocalWhite: s.view("white", true), LocalBlack: s.view("black", true),
		MirrorWhite: s.view("white", false), MirrorBlack: s.view("black", false), Kind: "white"}
}

func (s *server) exceptions(q *req) {
	d := s.exData()
	f := q.r.FormValue
	if f("kind") == "black" {
		d.Kind = "black"
	}
	d.Path, d.SHA, d.Lnk = f("path"), f("sha"), f("lnk")
	// з запису виявлення: шлях, sha256, у карантині чи ні
	if f("f") != "" {
		if x, err := s.recordAt(f("f"), f("o")); err == nil {
			d.F, d.O = f("f"), f("o")
			d.Path, d.SHA = x.DocFile.Path, x.DocFile.Sha256
			d.Quarantined = x.Disarm == "quarantined"
			d.Comment = "allowed after a block: " + x.DocFile.Name
		}
	}
	s.render(q, "exceptions", "Виключення", d)
}

func (s *server) exceptionAdd(q *req) {
	if q.r.Method != "POST" {
		s.back(q, "/exceptions", "")
		return
	}
	f := q.r.FormValue
	kind := f("kind")
	if kind != "white" && kind != "black" {
		kind = "white"
	}
	e := orglists.Entry{Path: strings.TrimSpace(f("path")), LnkTarget: strings.TrimSpace(f("lnk")),
		SHA256: strings.ToLower(strings.TrimSpace(f("sha"))), Comment: strings.TrimSpace(f("comment")),
		Added: time.Now().Format("2006-01-02"), By: AdminUser}
	if f("scope") == "path" { // будь-яка версія за цим шляхом
		e.SHA256 = ""
	}
	fail := func(err error) {
		d := s.exData()
		d.Kind, d.Path, d.Lnk, d.SHA, d.Comment, d.F, d.O = kind, e.Path, e.LnkTarget, f("sha"), e.Comment, f("f"), f("o")
		d.Quarantined = f("restore") == "on"
		s.renderErr(q, "exceptions", "Виключення", d, err)
	}
	l, err := readList(s.p.listFile(kind, true), kind)
	if err != nil {
		fail(fmt.Errorf("local %s list is broken: %v", kind, err))
		return
	}
	l.Entries = append(l.Entries, e)
	if err := writeLocalList(s.p, kind, l); err != nil {
		fail(fmt.Errorf("not saved: %v", err))
		return
	}
	what := fmt.Sprintf("path=%q lnk_target=%q sha256=%q comment=%q", e.Path, e.LnkTarget, e.SHA256, e.Comment)
	s.audit(q.r, AdminUser, "local-"+kind+"-added", what)
	msg := map[string]string{"white": "виключення додано: файл не перевірятиметься і не блокуватиметься (watcher застосує за кілька секунд)",
		"black": "запис локального чорного списку додано"}[kind]
	if kind == "white" && f("restore") == "on" && f("f") != "" {
		time.Sleep(3 * time.Second) // watcher перечитує списки не частіше разу на 2 с: файл не має повернутися в карантин
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
	if kind != "white" && kind != "black" {
		s.back(q, "/exceptions", "")
		return
	}
	i, err := strconv.Atoi(q.r.FormValue("i"))
	l, lerr := readList(s.p.listFile(kind, true), kind)
	if err != nil || lerr != nil || i < 0 || i >= len(l.Entries) {
		s.back(q, "/exceptions", "запис не знайдено (сторінку оновлено)")
		return
	}
	e := l.Entries[i]
	l.Entries = append(l.Entries[:i], l.Entries[i+1:]...)
	if err := writeLocalList(s.p, kind, l); err != nil {
		s.render(q, "exceptions", "Виключення", err)
		return
	}
	s.audit(q.r, AdminUser, "local-"+kind+"-removed", fmt.Sprintf("path=%q lnk_target=%q sha256=%q comment=%q", e.Path, e.LnkTarget, e.SHA256, e.Comment))
	s.back(q, "/exceptions", "запис прибрано")
}

// recordAt — запис docscan-results.json за посиланням (f — номер файлу, o — зсув).
func (s *server) recordAt(fs, os_ string) (*rawRec, error) {
	fi, _ := strconv.Atoi(fs)
	off, err := strconv.ParseInt(os_, 10, 64)
	files := s.resultFiles()
	if err != nil || fi < 0 || fi >= len(files) || off < 0 {
		return nil, fmt.Errorf("no such record (the results file may have been rotated)")
	}
	f, err := os.Open(files[fi])
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, err
	}
	b := make([]byte, 1<<20)
	n, _ := io.ReadFull(f, b)
	b = b[:n]
	if i := bytes.IndexByte(b, '\n'); i >= 0 {
		b = b[:i]
	}
	var x rawRec
	if err := json.Unmarshal(bytes.TrimSpace(b), &x); err != nil {
		return nil, fmt.Errorf("no record at this place (the results file may have been rotated)")
	}
	return &x, nil
}

// restore — файл запису виявлення з карантину на місце: копія <ім'я>.<N>.docscan-bak з тим самим sha256.
// Місце вже зайняте — не перезаписує.
func (s *server) restore(fs, os_ string) (string, error) {
	x, err := s.recordAt(fs, os_)
	if err != nil {
		return "", err
	}
	if x.Disarm != "quarantined" || x.DocFile.Path == "" || x.DocFile.Sha256 == "" {
		return "", fmt.Errorf("this record has no file in the quarantine")
	}
	dst := x.DocFile.Path
	if _, err := os.Lstat(dst); err == nil {
		return "", fmt.Errorf("%s already exists - not overwritten", dst)
	}
	base := dst[strings.LastIndexAny(dst, `\/`)+1:]
	cands, _ := filepath.Glob(filepath.Join(s.p.quarantine(), globEscape(base)+".*.docscan-bak"))
	for _, c := range cands {
		if h, err := fileSHA(c); err != nil || h != strings.ToLower(x.DocFile.Sha256) {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return "", err
		}
		if err := copyFile(c, dst); err != nil {
			return "", err
		}
		os.Remove(c)
		return dst, nil
	}
	return "", fmt.Errorf("no copy of %s with sha256 %s in %s (already restored or removed?)", base, x.DocFile.Sha256, s.p.quarantine())
}

func globEscape(s string) string {
	r := strings.NewReplacer("[", "[[]", "*", "[*]", "?", "[?]")
	return r.Replace(s)
}

func fileSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(dst)
		return err
	}
	return out.Close()
}
