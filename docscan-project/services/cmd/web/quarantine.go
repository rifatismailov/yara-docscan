package main

// Опис: docscan-project/DOCSCAN.md#web. «Карантин» — файли <DataDir>\quarantine\<ім'я>.<N>.docscan-bak. Їх кладе watcher (чорний
// список, -QuarantineGeneral) або модуль docscan (LNK, небезпечні PDF / старі документи — файл прибрано; документ,
// що лікується, — тут оригінал до знешкодження). Звідки і чому — із запису виявлення з тим самим sha256 (запис
// рахує sha256 файлу ДО знешкодження = sha256 копії).
//
// Повернути: спершу виключення (локальний білий список: шлях + sha256 — інакше watcher одразу забере файл знову),
// потім файл на місце. Знешкоджений документ замінюється оригіналом лише за явним підтвердженням. Видалити — копія
// зникає назавжди. Усе — записи аудиту для Wazuh.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"docscan/services/pkg/orglists"
)

type qItem struct {
	Name, Orig, SHA, Err string
	Size                 int64
	Time                 time.Time
	Rec                  *rec // запис виявлення з тим самим sha256 (nil — не знайдено)
}

// shaCache — sha256 файлів карантину (ім'я + час + розмір -> хеш), щоб не хешувати все щоразу.
var shaCache = struct {
	sync.Mutex
	m map[string]string
}{m: map[string]string{}}

func cachedSHA(p string, st os.FileInfo) (string, error) {
	k := fmt.Sprintf("%s|%d|%d", p, st.ModTime().UnixNano(), st.Size())
	shaCache.Lock()
	h, ok := shaCache.m[k]
	shaCache.Unlock()
	if ok {
		return h, nil
	}
	h, err := fileSHA(p)
	if err == nil {
		shaCache.Lock()
		if len(shaCache.m) > 20000 {
			shaCache.m = map[string]string{}
		}
		shaCache.m[k] = h
		shaCache.Unlock()
	}
	return h, err
}

// origName — AnyDesk.exe.3.docscan-bak -> AnyDesk.exe
func origName(n string) string {
	s := strings.TrimSuffix(n, ".docscan-bak")
	if i := strings.LastIndexByte(s, '.'); i > 0 {
		if _, err := fmt.Sscanf(s[i+1:], "%d", new(int)); err == nil {
			return s[:i]
		}
	}
	return s
}

// qItems — файли карантину (найновіші першими) з записами виявлення.
func (s *server) qItems() ([]qItem, error) {
	ents, err := os.ReadDir(s.p.quarantine())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	// sha256 -> найновіший запис з дією над файлом (не detect-only / paused / порожньо)
	bySHA := map[string]*rec{}
	recs, _ := s.readRecords(filter{verdict: "all"}, 0, maxScan)
	for i := range recs {
		r := &recs[i]
		if r.SHA == "" || r.Disarm == "" || r.Disarm == "detect-only" || r.Disarm == "paused" || strings.HasPrefix(r.Disarm, "failed:") {
			continue
		}
		if _, ok := bySHA[strings.ToLower(r.SHA)]; !ok {
			bySHA[strings.ToLower(r.SHA)] = r
		}
	}
	var out []qItem
	for _, e := range ents {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".docscan-bak") {
			continue
		}
		st, err := e.Info()
		if err != nil {
			continue
		}
		it := qItem{Name: e.Name(), Orig: origName(e.Name()), Size: st.Size(), Time: st.ModTime()}
		if it.SHA, err = cachedSHA(filepath.Join(s.p.quarantine(), e.Name()), st); err != nil {
			it.Err = err.Error()
		} else if r := bySHA[it.SHA]; r != nil && strings.EqualFold(baseOf(r.Path), it.Orig) {
			it.Rec = r
		}
		out = append(out, it)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out, nil
}

func baseOf(p string) string { return p[strings.LastIndexAny(p, `\/`)+1:] }

type qData struct {
	Items []qItem
	Bytes int64
	Dir   string
}

func (s *server) quarantinePage(q *req) {
	items, err := s.qItems()
	if err != nil {
		s.render(q, "quarantine", "Карантин", err)
		return
	}
	d := qData{Items: items, Dir: s.p.quarantine()}
	for _, it := range items {
		d.Bytes += it.Size
	}
	s.render(q, "quarantine", "Карантин", d)
}

// qFile — файл карантину за ім'ям (лише ім'я в теці карантину, без шляхів).
func (s *server) qFile(name string) (string, error) {
	if name == "" || name != filepath.Base(name) || strings.ContainsAny(name, `\/`) || !strings.HasSuffix(name, ".docscan-bak") {
		return "", fmt.Errorf("bad quarantine file name")
	}
	p := filepath.Join(s.p.quarantine(), name)
	if !fileExists(p) {
		return "", fmt.Errorf("%s is no longer in the quarantine", name)
	}
	return p, nil
}

// quarantineDelete — POST name, confirm=on.
func (s *server) quarantineDelete(q *req) {
	if q.r.Method != "POST" {
		s.back(q, "/quarantine", "")
		return
	}
	p, err := s.qFile(q.r.FormValue("name"))
	if err != nil {
		s.back(q, "/quarantine", err.Error())
		return
	}
	if q.r.FormValue("confirm") != "on" {
		s.back(q, "/quarantine", "не видалено: позначте «так, видалити назавжди»")
		return
	}
	h, _ := fileSHA(p)
	if err := os.Remove(p); err != nil {
		s.back(q, "/quarantine", "не видалено: "+err.Error())
		return
	}
	s.audit(q.r, AdminUser, "quarantine-deleted", fmt.Sprintf("%s sha256=%s", filepath.Base(p), h))
	s.back(q, "/quarantine", "видалено назавжди: "+filepath.Base(p))
}

// quarantineRestore — POST name, mode=exact|path, replace=on (документ, який знешкоджено: замінити оригіналом).
func (s *server) quarantineRestore(q *req) {
	if q.r.Method != "POST" {
		s.back(q, "/quarantine", "")
		return
	}
	name := q.r.FormValue("name")
	p, err := s.qFile(name)
	if err != nil {
		s.back(q, "/quarantine", err.Error())
		return
	}
	items, _ := s.qItems()
	var it *qItem
	for i := range items {
		if items[i].Name == name {
			it = &items[i]
		}
	}
	if it == nil || it.Rec == nil || it.Rec.Path == "" {
		s.back(q, "/quarantine", "не повернуто: невідомо, звідки файл (немає запису виявлення з цим sha256)")
		return
	}
	dst := it.Rec.Path
	replace := false
	if st, err := os.Lstat(dst); err == nil {
		if !st.Mode().IsRegular() {
			s.back(q, "/quarantine", "не повернуто: "+dst+" — не файл")
			return
		}
		if h, _ := fileSHA(dst); h == it.SHA {
			s.back(q, "/quarantine", "не повернуто: на місці вже той самий файл")
			return
		}
		if q.r.FormValue("replace") != "on" {
			s.back(q, "/quarantine", "не повернуто: "+dst+" існує (знешкоджена копія?) — позначте «замінити оригіналом»")
			return
		}
		replace = true
	}
	// 1) виключення: шлях + sha256 (або лише шлях)
	e := orglists.Entry{Path: dst, SHA256: it.SHA, Comment: "restored from the quarantine: " + it.Orig, Added: time.Now().Format("2006-01-02"), By: AdminUser}
	if q.r.FormValue("mode") == "path" {
		e.SHA256 = ""
	}
	l, err := readList(s.p.listFile("white", true), "white")
	if err != nil {
		s.back(q, "/quarantine", "не повернуто: локальний білий список зламаний: "+err.Error())
		return
	}
	l.Entries = append(l.Entries, e)
	if err := writeLocalList(s.p, "white", l); err != nil {
		s.back(q, "/quarantine", "не повернуто: "+err.Error())
		return
	}
	s.audit(q.r, AdminUser, "local-white-added", fmt.Sprintf("path=%q sha256=%q comment=%q", e.Path, e.SHA256, e.Comment))
	time.Sleep(3 * time.Second) // watcher перечитує списки не частіше разу на 2 с
	// 2) файл на місце
	if replace {
		tmp := dst + ".docscan-restore"
		os.Remove(tmp)
		if err := copyFile(p, tmp); err != nil {
			s.back(q, "/quarantine", "не повернуто: "+err.Error())
			return
		}
		if err := os.Rename(tmp, dst); err != nil { // Windows: замінює (MoveFileEx REPLACE_EXISTING)
			os.Remove(tmp)
			s.back(q, "/quarantine", "не повернуто (файл відкритий?): "+err.Error())
			return
		}
	} else {
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			s.back(q, "/quarantine", "не повернуто: "+err.Error())
			return
		}
		if err := copyFile(p, dst); err != nil {
			s.back(q, "/quarantine", "не повернуто: "+err.Error())
			return
		}
	}
	os.Remove(p)
	s.audit(q.r, AdminUser, "restored", fmt.Sprintf("%s -> %s%s", it.Name, dst, map[bool]string{true: " (replaced the disarmed copy)", false: ""}[replace]))
	s.back(q, "/quarantine", "повернуто: "+dst+" (і додано у виключення)")
}
