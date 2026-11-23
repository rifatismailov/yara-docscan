package main

// Білий і чорний списки організації (whitelist.json / blacklist.json, формат — watcher-go/orglists). Watcher
// застосовує їх ДО сканування (scan.go, applyLists):
//
//	1) чорний за sha256      -> HIGH, карантин (відомий шкідливий файл — завжди)
//	2) білий                 -> файл не сканується (INFO "дозволено білим списком")
//	3) чорний за шляхом / ціллю ярлика -> HIGH, карантин
//	4) інакше                -> звичайне сканування yara64
//
// Ціль ярлика (lnk_target) знає лише модуль docscan: якщо в списках є такі записи, ярлик спершу сканується БЕЗ
// лікування, ціль береться зі звіту (evidence.lnk_target). Файли списків перечитуються, щойно змінились (перезапуск
// не потрібен); зламаний файл не застосовується — лишається попередня справна версія, у watcher.log — ERROR.
// Після кожної зміни списків і при старті — прохід по файлах, що ВЖЕ лежать під масками чорного списку (sweep.go).

import (
	"os"
	"strings"
	"sync"
	"time"

	"docscan/watcher/orglists"
)

type listFile struct {
	kind, path string
	mod        time.Time
	size       int64
	known      bool
	ok         *orglists.List // остання справна версія
}

// Lists — обидва списки; nil — списків немає (watcher без -Whitelist / -Blacklist). Поруч зі списками з дзеркала
// організації — ЛОКАЛЬНІ списки цього ПК (whitelist.local.json / blacklist.local.json; веде веб-інтерфейс, напр.
// «виключення» для своєї програми): застосовуються разом, дзеркало їх не перезаписує.
type Lists struct {
	mu             sync.Mutex
	white, black   listFile
	lwhite, lblack listFile // локальні
	mw, mb         *orglists.List
	nw, nb         int // скільки записів з дзеркала на початку mw / mb (решта — локальні)
	log            *Logger
	checked        time.Time
	gen            int // +1 за кожну зміну списків: після неї — прохід по наявних файлах (sweep.go)
}

// localPath — whitelist.json -> whitelist.local.json (та сама тека).
func localPath(p string) string {
	if p == "" {
		return ""
	}
	return strings.TrimSuffix(p, ".json") + ".local.json"
}

// merge — записи дзеркала, потім локальні (nil, якщо обох немає).
func merge(m, loc *orglists.List) (*orglists.List, int) {
	if loc == nil || len(loc.Entries) == 0 {
		if m == nil {
			return nil, 0
		}
		return m, len(m.Entries)
	}
	out := &orglists.List{Schema: orglists.Schema}
	n := 0
	if m != nil {
		out.Serial, out.Entries, n = m.Serial, append(out.Entries, m.Entries...), len(m.Entries)
	}
	out.Entries = append(out.Entries, loc.Entries...)
	return out, n
}

// source — запис списку list ("white" / "black") з номером i у злитому списку: "mirror" або "local"; і його номер
// у своєму файлі.
func (l *Lists) source(list string, i int) (string, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	n := l.nw
	if list == "black" {
		n = l.nb
	}
	if i < n {
		return "mirror", i
	}
	return "local", i - n
}

// bump — новий прохід по наявних файлах (режим чи пауза чорного списку змінились: settings.go).
func (l *Lists) bump() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gen++
}

// generation — поточні списки і номер їхньої версії.
func (l *Lists) generation() (white, black *orglists.List, gen int) {
	white, black = l.get()
	l.mu.Lock()
	defer l.mu.Unlock()
	return white, black, l.gen
}

func newLists(white, black string, log *Logger) *Lists {
	if white == "" && black == "" {
		return nil
	}
	l := &Lists{white: listFile{kind: "white", path: white}, black: listFile{kind: "black", path: black},
		lwhite: listFile{kind: "white", path: localPath(white)}, lblack: listFile{kind: "black", path: localPath(black)}, log: log}
	l.get()
	return l
}

// get — поточні списки (перечитує змінені файли, не частіше разу на 2 с).
func (l *Lists) get() (white, black *orglists.List) {
	if l == nil {
		return nil, nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.checked) >= 2*time.Second {
		l.checked = time.Now()
		g := l.gen
		for _, f := range []*listFile{&l.white, &l.black, &l.lwhite, &l.lblack} {
			l.reload(f)
		}
		if g != l.gen || l.mw == nil && l.mb == nil {
			l.mw, l.nw = merge(l.white.ok, l.lwhite.ok)
			l.mb, l.nb = merge(l.black.ok, l.lblack.ok)
		}
	}
	return l.mw, l.mb
}

func (l *Lists) reload(f *listFile) {
	if f.path == "" {
		return
	}
	st, err := os.Stat(f.path)
	if err != nil || !st.Mode().IsRegular() {
		if f.known { // список прибрали (install.ps1 -NoWhitelist / -NoBlacklist)
			f.known, f.ok = false, nil
			l.gen++
			l.log.Log("INFO", "lists: %s removed", f.path)
		}
		return
	}
	if f.known && st.ModTime().Equal(f.mod) && st.Size() == f.size {
		return
	}
	f.known, f.mod, f.size = true, st.ModTime(), st.Size()
	b, err := os.ReadFile(f.path)
	if err == nil {
		var lst *orglists.List
		if lst, err = orglists.Parse(b, f.kind); err == nil {
			f.ok = lst
			l.gen++
			l.log.Log("INFO", "lists: %s - %d entries (serial %d)", f.path, len(lst.Entries), lst.Serial)
			return
		}
	}
	if f.ok != nil {
		l.log.Log("ERROR", "lists: %s is broken, the previous version stays in force: %v", f.path, err)
	} else {
		l.log.Log("ERROR", "lists: %s is broken and not used: %v", f.path, err)
	}
}

// ListHit — запис списку, що вирішив долю файлу (у записі для Wazuh: "list").
type ListHit struct {
	List      string `json:"list"`             // white | black
	Source    string `json:"source,omitempty"` // mirror (список організації) | local (цього ПК, веб-інтерфейс)
	Entry     int    `json:"entry"`            // номер запису (з 0) у своєму файлі
	By        string `json:"by"`               // які поля збіглися: path, lnk_target, sha256
	Comment   string `json:"comment,omitempty"`
	LnkTarget string `json:"lnk_target,omitempty"` // ціль ярлика, якщо її перевіряли
	Paused    string `json:"paused,omitempty"`     // чорний список на паузі до (settings.json)
}

// applyLists — списки ДО сканування. true — файл вирішено списком (сканування не потрібне).
func (w *Watcher) applyLists(r *Record, path, sha string, wk *worker) bool {
	white, black := w.lists.get()
	if white == nil && black == nil {
		return false
	}
	f := orglists.File{Path: path, SHA256: sha}
	if f.IsLnk() && orglists.NeedsTarget(white, black) {
		f.Target = func() string { // ціль ярлика знає модуль docscan: скан БЕЗ лікування
			so := w.invokeScan(path, false, false, false, wk.macroTmp, wk.critTmp)
			if so.ds != nil {
				return so.ds.Evidence.LnkTarget
			}
			return ""
		}
	}
	d := orglists.Decide(white, black, f)
	if d.Action == "" {
		return false
	}
	var by []string
	if d.Entry.Path != "" {
		by = append(by, "path")
	}
	if d.Entry.LnkTarget != "" {
		by = append(by, "lnk_target")
	}
	if d.Entry.SHA256 != "" {
		by = append(by, "sha256")
	}
	src, idx := w.lists.source(d.List, d.Index)
	r.List = &ListHit{List: d.List, Source: src, Entry: idx, By: strings.Join(by, "+"), Comment: d.Entry.Comment, LnkTarget: d.Target}
	if d.Action == "allow" {
		r.Verdict = "INFO"
		return true
	}
	r.Verdict = "HIGH"
	paused, until := w.blackPaused(time.Now())
	switch {
	case w.noDisarmFor(r):
		r.Disarm = "detect-only"
	case paused: // settings.json: the black list is paused (web interface) - reported, not quarantined
		r.Disarm = "paused"
		r.List.Paused = until
	default:
		if err := quarantine(path, w.c.BackupDir); err != nil {
			r.Errors = append(r.Errors, "quarantine failed: "+err.Error())
			r.Disarm = "failed:quarantine"
		} else {
			r.Disarm = "quarantined"
		}
	}
	return true
}
