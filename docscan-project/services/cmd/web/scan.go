package main

// Сторінка «Сканування»: скан документів на локальних дисках, скан тек / файлів (провідник — browse.go) або цілого
// знімного / не системного диска, авто-скан знімних носіїв. Повного скану всіх файлів немає навмисно (він ламав би
// встановлені програми). Сам скан робить служба DocScanWatcher (services/cmd/watcher/scanjob.go): веб лише кладе
// запит <DataDir>\scan\request-<id>.json або cancel-<id>, а показує scan\status.json (що йде зараз) і
// scan\history.json (останні 50). Режим для нових флешок — settings.json usb_scan. Кожна дія — у аудит.
// Дія скану: detect (лише повідомити) | cure (знешкодити документ, інше — у карантин) | delete (HIGH-файли видалити
// без копії — лише після сторінки підтвердження). Опис: docscan-project/DOCSCAN.md#web.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"docscan/services/pkg/drives"
)

// той самий формат, що services/cmd/watcher/scanjob.go
type wScanReq struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	Paths  []string `json:"paths"`
	By     string   `json:"by"`
	Detect bool     `json:"detect,omitempty"`
	Delete bool     `json:"delete,omitempty"`
}

type wScanRun struct {
	ID       string   `json:"id"`
	Kind     string   `json:"kind"`
	Paths    []string `json:"paths"`
	By       string   `json:"by"`
	Detect   bool     `json:"detect"`
	Delete   bool     `json:"delete"`
	Deleted  int      `json:"deleted"`
	Note     string   `json:"note"`
	State    string   `json:"state"`
	Started  string   `json:"started"`
	Finished string   `json:"finished"`
	Seconds  int      `json:"seconds"`
	Found    int64    `json:"found"`
	Scanned  int      `json:"scanned"`
	Cached   int      `json:"cached"`
	Hits     int      `json:"hits"`
	Errors   int      `json:"errors"`
	Skipped  int      `json:"skipped"`
	Walking  bool     `json:"walking"`
	Current  string   `json:"current"`
	HitFiles []string `json:"hit_files"`
}

// Done — оброблено файлів (для смужки ходу).
func (r wScanRun) Done() int64 { return int64(r.Scanned + r.Cached + r.Errors + r.Skipped) }

// Pct — відсоток (поки обхід триває — від уже знайденого).
func (r wScanRun) Pct() int {
	if r.Found == 0 {
		return 0
	}
	p := int(r.Done() * 100 / r.Found)
	if p > 100 {
		p = 100
	}
	return p
}

func (r wScanRun) StartedAt() time.Time { t, _ := time.Parse(time.RFC3339, r.Started); return t }

func (r wScanRun) Took() string {
	d := time.Duration(r.Seconds) * time.Second
	if d < time.Minute {
		return fmt.Sprintf("%d с", r.Seconds)
	}
	if d < time.Hour {
		return fmt.Sprintf("%d хв %d с", int(d.Minutes()), r.Seconds%60)
	}
	return fmt.Sprintf("%d год %d хв", int(d.Hours()), int(d.Minutes())%60)
}

func (r wScanRun) KindName() string {
	return map[string]string{"docs": "документи", "full": "повний (старий)", "path": "шлях", "usb": "носій"}[r.Kind]
}

type wScanStatus struct {
	Updated string     `json:"updated"`
	USBMode string     `json:"usb_mode"`
	Active  []wScanRun `json:"active"`
	Queue   int        `json:"queue"`
}

type scanData struct {
	Drives   []drives.Drive
	Active   []wScanRun
	History  []wScanRun
	Pending  []pendingReq // запити, яких служба ще не взяла
	NotTaken int          // найстаріший запит чекає стільки секунд (> pendingWarn — служба не працює?)
	USBSet   string       // settings.json usb_scan
	USBNow   string       // що діє (status.json від служби)
	Stale    bool         // служба давно не оновлювала стан
	Updated  time.Time
}

func (d scanData) refresh() int {
	if len(d.Active) > 0 || len(d.Pending) > 0 {
		return 5
	}
	return 0
}

const pendingWarn = 15 // с: служба бере запити раз на 2 с

// pendingReq — запит у черзі (request-<id>.json), служба його ще не взяла.
type pendingReq struct {
	wScanReq
	Age int // с
}

func (r pendingReq) KindName() string { return wScanRun{Kind: r.Kind}.KindName() }

func (r pendingReq) Action() string { return actionName(r.wScanReq) }

func (s *server) pending() []pendingReq {
	m, _ := filepath.Glob(filepath.Join(s.p.scanDir(), "request-*.json"))
	var out []pendingReq
	for _, f := range m {
		var r pendingReq
		fi, err := os.Stat(f)
		if err != nil || !readJSON(f, &r.wScanReq) {
			continue
		}
		r.Age = int(time.Since(fi.ModTime()).Seconds())
		out = append(out, r)
	}
	return out
}

func (s *server) scanData() scanData {
	d := scanData{Drives: drives.List()}
	var st wScanStatus
	if readJSON(filepath.Join(s.p.scanDir(), "status.json"), &st) {
		d.Active, d.USBNow = st.Active, st.USBMode
		d.Updated, _ = time.Parse(time.RFC3339, st.Updated)
		d.Stale = len(st.Active) > 0 && time.Since(d.Updated) > 30*time.Second
	}
	readJSON(filepath.Join(s.p.scanDir(), "history.json"), &d.History)
	d.Pending = s.pending()
	for _, r := range d.Pending {
		if r.Age > d.NotTaken {
			d.NotTaken = r.Age
		}
	}
	if set, err := readSettings(s.p); err == nil {
		d.USBSet = set.USBScan
	}
	return d
}

func (s *server) scanPage(q *req) {
	s.render(q, "scan", "Сканування", s.scanData())
}

var absPath = regexp.MustCompile(`^([A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+)`)

// scanConfirm — сторінка підтвердження видалення: ті самі поля форми ще раз, з confirm=on.
type scanConfirm struct {
	What   string
	Fields [][2]string
}

func isSystemRoot(p string) bool {
	return drives.IsRoot(p, drives.List(), func(d drives.Drive) bool { return d.System })
}

// actionName — для аудиту, повідомлень і сторінки підтвердження.
func actionName(sq wScanReq) string {
	switch {
	case sq.Detect:
		return "лише повідомити"
	case sq.Delete:
		return "ВИДАЛИТИ загрози без копії"
	}
	return "лікувати / карантин"
}

func (s *server) scanStart(q *req) {
	if q.r.Method != "POST" {
		s.back(q, "/scan", "")
		return
	}
	fail := func(e error) { s.renderErr(q, "scan", "Сканування", s.scanData(), e) }
	kind := q.r.FormValue("kind")
	sq := wScanReq{By: AdminUser}
	switch q.r.FormValue("action") {
	case "detect":
		sq.Detect = true
	case "delete":
		sq.Delete = true
	}
	switch kind {
	case "docs": // документи на вибраних локальних дисках
		sq.Kind = "docs"
		pick := map[string]bool{}
		for _, r := range q.r.Form["docs_root"] {
			pick[r] = true
		}
		for _, d := range drives.List() {
			if d.Kind == "fixed" && pick[d.Root] {
				sq.Paths = append(sq.Paths, d.Root)
			}
		}
		if len(sq.Paths) == 0 {
			fail(errors.New("виберіть хоча б один локальний диск"))
			return
		}
	case "drive": // знімний — увесь носій; не системний локальний (D:\) — усі файли; системний — ні
		root := q.r.FormValue("root")
		for _, d := range drives.List() {
			if d.Root != root {
				continue
			}
			switch {
			case d.Removable():
				sq.Kind = "usb"
			case d.Kind == "fixed" && !d.System:
				sq.Kind = "path"
			}
		}
		if sq.Kind == "" {
			fail(fmt.Errorf("диск %s: не підключений знімний і не локальний несистемний (системний — «Скан документів» або теки)", root))
			return
		}
		sq.Paths = []string{root}
	case "path": // провідник: позначені теки / файли; нічого не позначено — уся відкрита тека (cur)
		sq.Kind = "path"
		picks := q.r.Form["pick"]
		if len(picks) == 0 && q.r.FormValue("cur") != "" {
			picks = []string{q.r.FormValue("cur")}
		}
		for _, l := range picks {
			l = strings.TrimSpace(l)
			if len(l) == 2 && l[1] == ':' {
				l += `\`
			}
			if !absPath.MatchString(l) && !filepath.IsAbs(l) {
				fail(fmt.Errorf("%s: потрібен повний шлях", l))
				return
			}
			if _, err := os.Stat(l); err != nil {
				fail(fmt.Errorf("%s: не знайдено", l))
				return
			}
			if isSystemRoot(l) {
				fail(fmt.Errorf("%s: цілий системний диск не сканується — «Скан документів» або окремі теки", l))
				return
			}
			sq.Paths = append(sq.Paths, l)
		}
		if len(sq.Paths) == 0 {
			fail(errors.New("нічого не вибрано: позначте галочками теки або файли"))
			return
		}
	default:
		s.back(q, "/scan", "")
		return
	}
	what := sq.Kind + " " + strings.Join(sq.Paths, ", ") + " (" + actionName(sq) + ")"
	for _, r := range s.pending() { // подвійне натискання — той самий запит ще в черзі
		if r.Kind == sq.Kind && strings.Join(r.Paths, "|") == strings.Join(sq.Paths, "|") {
			s.back(q, "/scan", "такий скан уже в черзі ("+r.ID+") — чекає на службу DocScanWatcher")
			return
		}
	}
	if sq.Delete && q.r.FormValue("confirm") != "on" {
		c := scanConfirm{What: what}
		for k, vs := range q.r.PostForm {
			if k == "csrf" || k == "confirm" {
				continue
			}
			for _, v := range vs {
				c.Fields = append(c.Fields, [2]string{k, v})
			}
		}
		s.render(q, "scan_confirm", "Сканування", c)
		return
	}
	sq.ID = time.Now().Format("20060102-150405.000") + "-" + sq.Kind
	if err := os.MkdirAll(s.p.scanDir(), 0o755); err != nil {
		fail(err)
		return
	}
	b, _ := json.MarshalIndent(sq, "", "  ")
	if err := writeFileAtomic(filepath.Join(s.p.scanDir(), "request-"+sq.ID+".json"), b, 0o644); err != nil {
		fail(err)
		return
	}
	s.audit(q.r, AdminUser, "scan-start", sq.ID+": "+what)
	s.back(q, "/scan", "скан поставлено в чергу: "+what+" — служба почне за кілька секунд")
}

var scanIDRe = regexp.MustCompile(`^[0-9A-Za-z.\-]{1,64}$`)

func (s *server) scanStop(q *req) {
	if q.r.Method != "POST" {
		s.back(q, "/scan", "")
		return
	}
	id := q.r.FormValue("id")
	name := "cancel-" + id
	if id == "all" {
		name = "cancel-all"
	} else if !scanIDRe.MatchString(id) {
		s.back(q, "/scan", "")
		return
	}
	if id == "all" { // запити, яких служба ще не взяла, — просто прибрати
		for _, r := range s.pending() {
			os.Remove(filepath.Join(s.p.scanDir(), "request-"+r.ID+".json"))
		}
	} else if os.Remove(filepath.Join(s.p.scanDir(), "request-"+id+".json")) == nil {
		s.audit(q.r, AdminUser, "scan-stop", id+" (from the queue)")
		s.back(q, "/scan", "запит прибрано з черги: "+id)
		return
	}
	if err := os.WriteFile(filepath.Join(s.p.scanDir(), name), []byte(time.Now().Format(time.RFC3339)), 0o644); err != nil {
		s.renderErr(q, "scan", "Сканування", s.scanData(), err)
		return
	}
	s.audit(q.r, AdminUser, "scan-stop", id)
	s.back(q, "/scan", "зупинка: "+id)
}

func (s *server) scanUSB(q *req) {
	if q.r.Method != "POST" {
		s.back(q, "/scan", "")
		return
	}
	m := q.r.FormValue("usb")
	switch m {
	case "", "off", "detect", "full":
	default:
		s.back(q, "/scan", "")
		return
	}
	set, err := readSettings(s.p)
	if err != nil {
		s.renderErr(q, "scan", "Сканування", s.scanData(), err)
		return
	}
	was := set.USBScan
	set.USBScan = m
	if err := writeSettings(s.p, set); err != nil {
		s.renderErr(q, "scan", "Сканування", s.scanData(), err)
		return
	}
	s.audit(q.r, AdminUser, "usb-scan", usbName(was)+" -> "+usbName(m))
	s.back(q, "/scan", "знімні носії: "+usbName(m)+" — діє за кілька секунд")
}

func usbName(m string) string {
	return map[string]string{"": "як режим DocScan", "off": "не сканувати", "detect": "лише повідомлення", "full": "повний (знешкодження і карантин)"}[m]
}
