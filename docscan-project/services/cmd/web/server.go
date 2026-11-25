package main

// HTTP: заголовки безпеки, перевірка Host (лише 127.0.0.1:<порт> / localhost:<порт> — від DNS rebinding), сесія
// (cookie Secure; HttpOnly; SameSite=Strict), CSRF-токен у кожній формі POST, дії по одній (м'ютекс), маршрути і
// вивід сторінок. Опис: docscan-project/DOCSCAN.md#web.

import (
	"crypto/subtle"
	"embed"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html static/*
var assets embed.FS

type server struct {
	p      paths
	listen string
	port   string
	host   string
	log    *logger
	tpl    *template.Template
	ss     *sessions
	lim    *limiter
	mu     sync.Mutex // дії (POST) по одній
	// checkCfg — перевірка updater.json (за замовчуванням docscan-updater -CheckConfig; тести підміняють)
	checkCfg func(file string) error
}

func newServer(p paths, listen string, lg *logger) (*server, error) {
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, err
	}
	if _, err := readAuth(p); err != nil {
		return nil, fmt.Errorf("no admin password: %v (install.ps1 creates it: docscan-web.exe -InitAuth)", err)
	}
	host, _ := os.Hostname()
	s := &server{p: p, listen: listen, port: port, host: host, log: lg, ss: &sessions{m: map[string]*session{}}, lim: &limiter{}}
	s.tpl, err = template.New("").Funcs(funcs).ParseFS(assets, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return s, nil
}

var funcs = template.FuncMap{
	"q":    url.QueryEscape,
	"join": strings.Join,
	"short": func(s string, n int) string {
		if r := []rune(s); len(r) > n {
			return string(r[:n]) + "…"
		}
		return s
	},
	"ts": func(t time.Time) string {
		if t.IsZero() {
			return "—"
		}
		return t.Local().Format("2006-01-02 15:04:05")
	},
	"add":       func(a, b int) int { return a + b },
	"hasPrefix": strings.HasPrefix,
	"mb": func(b int64) string {
		if b < 1<<20 {
			return fmt.Sprintf("%.0f КБ", float64(b)/1024)
		}
		return fmt.Sprintf("%.1f МБ", float64(b)/(1<<20))
	},
	"pair": func(a, b any) []any { return []any{a, b} }, // два аргументи у вкладений шаблон (сторінка + дані)
}

// routes — сторінки й дії після входу.
var routes = map[string]func(*server, *req){
	"/":                   (*server).status,
	"/detections":         (*server).detections,
	"/record":             (*server).record,
	"/logs":               (*server).logs,
	"/macros":             (*server).macros,
	"/macro":              (*server).macro,
	"/scan":               (*server).scanPage,
	"/scan/start":         (*server).scanStart,
	"/scan/stop":          (*server).scanStop,
	"/scan/usb":           (*server).scanUSB,
	"/scan/browse":        (*server).browse,
	"/mode":               (*server).mode,
	"/pause":              (*server).pause,
	"/exceptions":         (*server).exceptions,
	"/exceptions/add":     (*server).exceptionAdd,
	"/exceptions/remove":  (*server).exceptionRemove,
	"/quarantine":         (*server).quarantinePage,
	"/quarantine/restore": (*server).quarantineRestore,
	"/quarantine/delete":  (*server).quarantineDelete,
	"/updates":            (*server).updates,
	"/updates/check":      (*server).updatesCheck,
	"/password":           (*server).password,
	"/logout":             (*server).logout,
}

// hostOK — Host запиту: лише наша адреса (сторінка з іншого «домену», що вказує на 127.0.0.1, не пройде).
func (s *server) hostOK(h string) bool {
	for _, ok := range []string{"127.0.0.1:" + s.port, "localhost:" + s.port, "[::1]:" + s.port} {
		if strings.EqualFold(h, ok) {
			return true
		}
	}
	return false
}

func (s *server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Strict-Transport-Security", "max-age=31536000")
	if !s.hostOK(r.Host) {
		http.Error(w, "use https://127.0.0.1:"+s.port+"/", http.StatusMisdirectedRequest)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/static/") {
		w.Header().Set("Cache-Control", "max-age=3600")
		http.FileServer(http.FS(assets)).ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/login" {
		s.login(w, r)
		return
	}
	var tok string
	var ss *session
	if c, err := r.Cookie(sessionCookie); err == nil {
		tok, ss = c.Value, s.ss.get(c.Value, time.Now())
	}
	if ss == nil {
		if r.Method == http.MethodPost {
			http.Error(w, "сесію завершено — увійдіть знову", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
		return
	}
	if r.Method == http.MethodPost {
		r.Body = http.MaxBytesReader(w, r.Body, 4<<20)
		if err := r.ParseForm(); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(ss.csrf)) != 1 {
			http.Error(w, "форма застаріла — оновіть сторінку", http.StatusForbidden)
			return
		}
		s.mu.Lock()
		defer s.mu.Unlock()
	}
	// тимчасовий пароль: спершу новий
	if ss.mustChange && r.URL.Path != "/password" && r.URL.Path != "/logout" {
		http.Redirect(w, r, "/password", http.StatusSeeOther)
		return
	}
	h := routes[r.URL.Path]
	if h == nil {
		http.NotFound(w, r)
		return
	}
	h(s, &req{w: w, r: r, tok: tok, ss: ss})
}

type req struct {
	w   http.ResponseWriter
	r   *http.Request
	tok string
	ss  *session
}

// page — спільні дані сторінки.
type page struct {
	Title, Path, CSRF, Flash, Error, Host string
	MustChange                            bool
	Refresh                               int // с: сторінка оновлюється сама (іде скан)
	Now                                   time.Time
	Data                                  any
}

// render — сторінка; data, що є помилкою, — сторінка з повідомленням про помилку.
func (s *server) render(q *req, name, title string, data any) {
	if e, ok := data.(error); ok {
		s.renderErr(q, name, title, nil, e)
		return
	}
	s.renderErr(q, name, title, data, nil)
}

// renderErr — сторінка з даними і помилкою (дані форми не губляться).
func (s *server) renderErr(q *req, name, title string, data any, e error) {
	p := page{Title: title, Path: q.r.URL.Path, Flash: q.r.FormValue("flash"), Host: s.host, Now: time.Now(), Data: data}
	if e != nil {
		p.Error = e.Error()
	}
	if q.ss != nil {
		p.CSRF, p.MustChange = q.ss.csrf, q.ss.mustChange
	}
	if rf, ok := data.(interface{ refresh() int }); ok {
		p.Refresh = rf.refresh()
	}
	q.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(q.w, name, p); err != nil {
		s.log.Log("ERROR", "template %s: %v", name, err)
	}
}

// back — після дії: назад на сторінку з повідомленням (redirect, щоб оновлення сторінки не повторило дію).
func (s *server) back(q *req, to, flash string) {
	if flash != "" {
		sep := "?"
		if strings.Contains(to, "?") {
			sep = "&"
		}
		to += sep + "flash=" + url.QueryEscape(flash)
	}
	http.Redirect(q.w, q.r, to, http.StatusSeeOther)
}
