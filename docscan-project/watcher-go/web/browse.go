package main

// Провідник для скану (/scan/browse?p=<тека>): адмін не мусить знати шлях напам'ять — диски, далі теки й файли;
// позначив потрібне галочками, вибрав дію — запит на скан шляху (scan.go scanStart, kind=path, поля pick).
// Лише перегляд імен: файли не відкриваються і не читаються. Цілий системний диск вибрати не можна (лише
// «Скан документів»); теки програм (drives.Protected) позначені — скан там лише повідомляє.

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"docscan/watcher/drives"
)

const browseMax = 1000 // елементів на сторінку теки

type browseItem struct {
	Name, Path string
	Dir        bool
	Size       int64
	Mod        time.Time
	Protected  bool
}

type crumb struct{ Name, Path string }

type browseData struct {
	Path      string // "" — список дисків
	Up        string // батьківська тека; "" з кореня диска — до списку дисків
	Crumbs    []crumb
	Drives    []drives.Drive
	Items     []browseItem
	More      int  // не показано (понад browseMax)
	CanPick   bool // цю теку можна вибрати цілою
	Protected bool
	Err       string
}

func (s *server) browse(q *req) {
	p := strings.TrimSpace(q.r.FormValue("p"))
	d := browseData{}
	if p == "" {
		d.Drives = drives.List()
		s.render(q, "browse", "Сканування — вибір", d)
		return
	}
	if len(p) == 2 && p[1] == ':' {
		p += `\`
	}
	if !absPath.MatchString(p) && !filepath.IsAbs(p) {
		s.back(q, "/scan/browse", "")
		return
	}
	p = filepath.Clean(p)
	if len(p) == 2 && p[1] == ':' { // Clean("C:\") лишає "C:\", але про всяк випадок
		p += `\`
	}
	d.Path, d.Protected = p, drives.Protected(p)
	d.CanPick = !isSystemRoot(p)
	if parent := filepath.Dir(p); parent != p {
		d.Up = parent
	}
	// хлібні крихти: C:\ > Users > anna
	for cur := p; ; {
		parent := filepath.Dir(cur)
		name := filepath.Base(cur)
		if parent == cur {
			name = cur
		}
		d.Crumbs = append([]crumb{{name, cur}}, d.Crumbs...)
		if parent == cur {
			break
		}
		cur = parent
	}
	ents, err := os.ReadDir(p)
	if err != nil {
		d.Err = err.Error()
	}
	sort.Slice(ents, func(i, j int) bool {
		if ents[i].IsDir() != ents[j].IsDir() {
			return ents[i].IsDir()
		}
		return strings.ToLower(ents[i].Name()) < strings.ToLower(ents[j].Name())
	})
	for _, e := range ents {
		if len(d.Items) >= browseMax {
			d.More++
			continue
		}
		it := browseItem{Name: e.Name(), Path: filepath.Join(p, e.Name()), Dir: e.IsDir()}
		if e.Type()&(os.ModeSymlink|os.ModeIrregular) != 0 {
			continue // посилання / точки з'єднання (Documents and Settings) — не ходимо
		}
		if fi, err := e.Info(); err == nil {
			it.Size, it.Mod = fi.Size(), fi.ModTime()
		}
		it.Protected = drives.Protected(it.Path)
		d.Items = append(d.Items, it)
	}
	s.render(q, "browse", "Сканування — вибір", d)
}
