// Package orglists — білий і чорний списки організації (whitelist.json / blacklist.json): формат, сувора перевірка
// і зіставлення файлу з записами. Спільний для docscan-watcher (застосовує списки) і docscan-updater (перевіряє й
// ставить списки з дзеркала організації) — щоб обидва вирішували однаково.
//
//	{
//	  "schema": 1,
//	  "serial": 20261121120000,          // номер версії (ставить docscan-updater -SignList; для ручних списків — не обов'язково)
//	  "description": "...",
//	  "entries": [
//	    {"path": "C:\\Users\\*\\Desktop\\App*.lnk", "lnk_target": "\\\\fileserver\\BIN\\", "comment": "App"},
//	    {"sha256": "<64 hex>", "comment": "наша внутрішня програма"}
//	  ]
//	}
//
// Поля запису (потрібне хоча б одне; якщо кілька — файл має збігтися з УСІМА):
//
//	path        де лежить файл: повний шлях з маскою; * — будь-що в межах однієї теки, ** — будь-яка глибина, ? — один символ
//	lnk_target  куди веде ярлик (.lnk): мережева тека \\сервер\шара\ (у чорному списку можна й увесь сервер \\сервер\)
//	sha256      вміст файлу (хеш)
//
// comment / added / by — для людей (навіщо, коли, хто). Регістр літер не важливий.
package orglists

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
)

// Schema — версія формату.
const Schema = 1

// List — whitelist.json або blacklist.json.
type List struct {
	Schema      int     `json:"schema"`
	Serial      int64   `json:"serial,omitempty"`
	Description string  `json:"description,omitempty"`
	Entries     []Entry `json:"entries"`
}

// Entry — один запис списку.
type Entry struct {
	Path      string `json:"path,omitempty"`
	LnkTarget string `json:"lnk_target,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
	Comment   string `json:"comment,omitempty"`
	Added     string `json:"added,omitempty"`
	By        string `json:"by,omitempty"`
}

var (
	shaRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	absRe   = regexp.MustCompile(`^(?:[a-z]:\\|\\[^\\])`) // C:\... або (macOS / Linux, після заміни / на \) \tmp\...
	globMu  sync.Mutex
	globMap = map[string]*regexp.Regexp{}
)

// Parse — суворе читання: невідоме поле, інша схема, неправильний запис — помилка з номером запису.
// kind — "white" або "black" (у білому списку обмеження суворіші: не цілий сервер, не «всі файли теки»).
func Parse(b []byte, kind string) (*List, error) {
	d := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))))
	d.DisallowUnknownFields()
	var l List
	if err := d.Decode(&l); err != nil {
		return nil, fmt.Errorf("not valid JSON of this format: %w", err)
	}
	if d.More() {
		return nil, fmt.Errorf("extra data after the JSON object")
	}
	if l.Schema != Schema {
		return nil, fmt.Errorf(`"schema" must be %d (got %d)`, Schema, l.Schema)
	}
	if l.Serial < 0 {
		return nil, fmt.Errorf(`"serial" must not be negative`)
	}
	for i := range l.Entries {
		if err := checkEntry(&l.Entries[i], kind); err != nil {
			return nil, fmt.Errorf("entries[%d]: %w", i, err)
		}
	}
	return &l, nil
}

func checkEntry(e *Entry, kind string) error {
	if e.Path == "" && e.LnkTarget == "" && e.SHA256 == "" {
		return fmt.Errorf(`give "path", "lnk_target" and/or "sha256"`)
	}
	if e.SHA256 != "" {
		e.SHA256 = strings.ToLower(strings.TrimSpace(e.SHA256))
		if !shaRe.MatchString(e.SHA256) {
			return fmt.Errorf("sha256 %q: expected 64 hex characters (Get-FileHash <file>)", e.SHA256)
		}
	}
	if e.Path != "" {
		p := norm(e.Path)
		if !absRe.MatchString(p) {
			return fmt.Errorf(`path %q: expected a full path like C:\Users\*\Desktop\App*.lnk`, e.Path)
		}
		for _, s := range strings.Split(p, `\`) {
			if s == "." || s == ".." {
				return fmt.Errorf(`path %q: no "." or ".." parts`, e.Path)
			}
		}
		if kind == "white" {
			name := p[strings.LastIndex(p, `\`)+1:]
			if strings.Trim(name, "*?.") == "" {
				return fmt.Errorf("path %q: the white list cannot allow every file of a folder - name the files (App*.lnk, setup.exe)", e.Path)
			}
		}
		e.Path = strings.TrimSpace(e.Path)
	}
	if e.LnkTarget != "" {
		t := norm(e.LnkTarget)
		if !strings.HasPrefix(t, `\\`) {
			return fmt.Errorf(`lnk_target %q: expected a network folder \\server\share\`, e.LnkTarget)
		}
		if strings.ContainsAny(t, `:*?"<>|`) {
			return fmt.Errorf(`lnk_target %q: no : * ? " < > | (no masks here)`, e.LnkTarget)
		}
		parts := strings.Split(strings.TrimSuffix(t[2:], `\`), `\`)
		for _, s := range parts {
			if s == "" || s == "." || s == ".." {
				return fmt.Errorf(`lnk_target %q: empty, "." or ".." part`, e.LnkTarget)
			}
		}
		if kind == "white" && len(parts) < 2 {
			return fmt.Errorf(`lnk_target %q: the white list needs a share (\\server\share\), not a whole server`, e.LnkTarget)
		}
		e.LnkTarget = `\\` + strings.Join(parts, `\`) + `\`
	}
	return nil
}

// norm — для порівняння: "/" -> "\", нижній регістр, без пробілів по краях.
func norm(s string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), "/", `\`))
}

// MatchPath — шлях файлу p підходить під маску pattern (* — у межах теки, ** — будь-яка глибина, ? — один символ).
func MatchPath(pattern, p string) bool {
	return glob(norm(pattern)).MatchString(norm(p))
}

func glob(pat string) *regexp.Regexp {
	globMu.Lock()
	defer globMu.Unlock()
	if re, ok := globMap[pat]; ok {
		return re
	}
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pat); i++ {
		switch c := pat[i]; c {
		case '*':
			if i+1 < len(pat) && pat[i+1] == '*' {
				b.WriteString(`.*`)
				i++
			} else {
				b.WriteString(`[^\\]*`)
			}
		case '?':
			b.WriteString(`[^\\]`)
		default:
			b.WriteString(regexp.QuoteMeta(string(c)))
		}
	}
	b.WriteString("$")
	re := regexp.MustCompile(b.String())
	globMap[pat] = re
	return re
}

// MatchTarget — ціль ярлика target лежить у мережевій теці prefix (нормалізований запис lnk_target, з "\" у кінці).
// Ціль з "." / ".." частинами не підходить ні до чого: ними можна вийти з теки.
func MatchTarget(prefix, target string) bool {
	t := norm(target)
	if !strings.HasPrefix(t, `\\`) {
		return false
	}
	for _, s := range strings.Split(t[2:], `\`) {
		if s == "." || s == ".." {
			return false
		}
	}
	return strings.HasPrefix(t, norm(prefix))
}

// File — файл, який перевіряється: шлях, хеш і (лише для ярликів, за потреби) його ціль.
type File struct {
	Path   string
	SHA256 string
	Target func() string // ціль ярлика; викликається лише коли запис має lnk_target (нею треба просканувати ярлик)
}

// IsLnk — файл — ярлик.
func (f File) IsLnk() bool { return strings.HasSuffix(strings.ToLower(f.Path), ".lnk") }

// Match — файл збігається з УСІМА полями запису.
func (e *Entry) Match(f File, target *string) bool {
	if e.SHA256 != "" && !strings.EqualFold(e.SHA256, f.SHA256) {
		return false
	}
	if e.Path != "" && !MatchPath(e.Path, f.Path) {
		return false
	}
	if e.LnkTarget != "" {
		if !f.IsLnk() || f.Target == nil {
			return false
		}
		if *target == "\x00" { // ще не дізнавались
			*target = f.Target()
		}
		if !MatchTarget(e.LnkTarget, *target) {
			return false
		}
	}
	return true
}

// Decision — що робити з файлом за списками.
type Decision struct {
	Action string // "block" | "allow" | "" (списки до файлу не стосуються — звичайне сканування)
	List   string // "black" | "white"
	Index  int    // номер запису
	Entry  Entry
	Target string // ціль ярлика, якщо її дізнавались
}

// Decide — порядок: 1) чорний за sha256 (відомий шкідливий файл — завжди); 2) білий (файл без сканування);
// 3) чорний за шляхом / ціллю ярлика; 4) нічого. Так своя програма з sha256 у білому проходить навіть з теки, де
// *.exe заборонені, а відомий шкідливий файл — ніколи.
func Decide(white, black *List, f File) Decision {
	target := "\x00"
	res := func(a, l string, i int, e Entry) Decision {
		d := Decision{Action: a, List: l, Index: i, Entry: e}
		if target != "\x00" {
			d.Target = target
		}
		return d
	}
	if black != nil {
		for i := range black.Entries {
			if e := &black.Entries[i]; e.SHA256 != "" && e.Match(f, &target) {
				return res("block", "black", i, *e)
			}
		}
	}
	if white != nil {
		for i := range white.Entries {
			if e := &white.Entries[i]; e.Match(f, &target) {
				return res("allow", "white", i, *e)
			}
		}
	}
	if black != nil {
		for i := range black.Entries {
			if e := &black.Entries[i]; e.SHA256 == "" && e.Match(f, &target) {
				return res("block", "black", i, *e)
			}
		}
	}
	d := res("", "", -1, Entry{})
	return d
}

// NeedsTarget — у списках є записи з lnk_target (тоді ярлик треба спершу просканувати без лікування, щоб узнати ціль).
func NeedsTarget(lists ...*List) bool {
	for _, l := range lists {
		if l == nil {
			continue
		}
		for _, e := range l.Entries {
			if e.LnkTarget != "" {
				return true
			}
		}
	}
	return false
}
