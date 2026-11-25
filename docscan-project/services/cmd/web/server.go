package main

// Опис: docscan-project/DOCSCAN.md#web — маршрути, вхід, аудит.

// HTTP: заголовки безпеки, перевірка Host (лише 127.0.0.1:<порт> / localhost:<порт> — від DNS rebinding), вхід,
// сесія (cookie Secure; HttpOnly; SameSite=Strict), CSRF-токен у кожній формі POST, дії по одній (м'ютекс).

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

//go:embed templates/*.html static/*
var assets embed.FS

const (
	sessionCookie = "docscan_session"
	preCookie     = "docscan_login"
)

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
	"lower": strings.ToLower,
	"q":     url.QueryEscape,
	"join":  strings.Join,
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
	"list2": func(a, b listView) []listView { return []listView{a, b} },
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
			http.Error(w, "the session has ended - sign in again", http.StatusUnauthorized)
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
			http.Error(w, "bad form token (reload the page)", http.StatusForbidden)
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
	rq := &req{w: w, r: r, tok: tok, ss: ss}
	switch r.URL.Path {
	case "/":
		s.status(rq)
	case "/detections":
		s.detections(rq)
	case "/record":
		s.record(rq)
	case "/logs":
		s.logs(rq)
	case "/mode":
		s.mode(rq)
	case "/pause":
		s.pause(rq)
	case "/updates":
		s.updates(rq)
	case "/updates/check":
		s.updatesCheck(rq)
	case "/exceptions":
		s.exceptions(rq)
	case "/exceptions/add":
		s.exceptionAdd(rq)
	case "/exceptions/remove":
		s.exceptionRemove(rq)
	case "/macro":
		s.macro(rq)
	case "/macros":
		s.macros(rq)
	case "/quarantine":
		s.quarantinePage(rq)
	case "/quarantine/restore":
		s.quarantineRestore(rq)
	case "/quarantine/delete":
		s.quarantineDelete(rq)
	case "/scan":
		s.scanPage(rq)
	case "/scan/start":
		s.scanStart(rq)
	case "/scan/stop":
		s.scanStop(rq)
	case "/scan/usb":
		s.scanUSB(rq)
	case "/scan/browse":
		s.browse(rq)
	case "/password":
		s.password(rq)
	case "/logout":
		s.logout(rq)
	default:
		http.NotFound(w, r)
	}
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

func (s *server) render(q *req, name, title string, data any) {
	p := page{Title: title, Path: q.r.URL.Path, Flash: q.r.FormValue("flash"), Host: s.host, Now: time.Now(), Data: data}
	if q.ss != nil {
		p.CSRF, p.MustChange = q.ss.csrf, q.ss.mustChange
	}
	if e, ok := data.(error); ok {
		p.Error, p.Data = e.Error(), nil
	}
	if rf, ok := data.(interface{ refresh() int }); ok {
		p.Refresh = rf.refresh()
	}
	q.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(q.w, name, p); err != nil {
		s.log.Log("ERROR", "template %s: %v", name, err)
	}
}

// renderErr — сторінка з даними форми і помилкою (введене не губиться).
func (s *server) renderErr(q *req, name, title string, data any, e error) {
	p := page{Title: title, Path: q.r.URL.Path, Host: s.host, Now: time.Now(), Data: data, Error: e.Error()}
	if q.ss != nil {
		p.CSRF, p.MustChange = q.ss.csrf, q.ss.mustChange
	}
	q.w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tpl.ExecuteTemplate(q.w, name, p); err != nil {
		s.log.Log("ERROR", "template %s: %v", name, err)
	}
}

func (s *server) back(q *req, to, flash string) {
	u := to
	if flash != "" {
		sep := "?"
		if strings.Contains(to, "?") {
			sep = "&"
		}
		u += sep + "flash=" + url.QueryEscape(flash)
	}
	http.Redirect(q.w, q.r, u, http.StatusSeeOther)
}

// ---------------------------------------------------------------- вхід / вихід / пароль

type loginData struct {
	Next, Pre, Err string
	FirstRun       bool
}

func (s *server) login(w http.ResponseWriter, r *http.Request) {
	next := r.FormValue("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") {
		next = "/"
	}
	q := &req{w: w, r: r}
	show := func(d loginData, code int) {
		if c, err := r.Cookie(preCookie); d.Pre == "" && err == nil && len(c.Value) >= 32 {
			d.Pre = c.Value
		}
		if d.Pre == "" { // токен форми до входу — у cookie (подвійна відправка)
			d.Pre = randomToken()
			http.SetCookie(w, &http.Cookie{Name: preCookie, Value: d.Pre, Path: "/login", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: 900})
		}
		d.FirstRun = fileExists(s.p.initialPw())
		if code != 0 {
			w.WriteHeader(code)
		}
		s.render(q, "login", "Вхід", d)
	}
	if r.Method != http.MethodPost {
		show(loginData{Next: next}, 0)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
	r.ParseForm()
	c, err := r.Cookie(preCookie)
	if err != nil || c.Value == "" || subtle.ConstantTimeCompare([]byte(c.Value), []byte(r.FormValue("pre"))) != 1 {
		show(loginData{Next: next, Err: "the form expired - try again"}, http.StatusUnauthorized)
		return
	}
	now := time.Now()
	if err := s.lim.check(now); err != nil {
		show(loginData{Next: next, Err: err.Error()}, http.StatusTooManyRequests)
		return
	}
	a, err := readAuth(s.p)
	user := strings.TrimSpace(r.FormValue("name"))
	if err != nil || !strings.EqualFold(user, a.User) || !verifyPassword(r.FormValue("password"), a.Hash) {
		locked := s.lim.fail(now)
		s.audit(r, user, "login-failed", "")
		if locked > 0 {
			s.audit(r, user, "login-locked", fmt.Sprintf("%d failed sign-ins in a row - sign-in locked for %s", s.lim.failures(), locked))
		}
		show(loginData{Next: next, Err: "wrong user or password"}, http.StatusUnauthorized)
		return
	}
	if a.tempExpired(now) { // тимчасовий пароль прострочено: не діє, файл з ним — геть
		os.Remove(s.p.initialPw())
		s.audit(r, a.User, "login-refused", "the temporary password expired "+a.Expires)
		show(loginData{Next: next, Err: "the temporary password expired - make a new one: docscan-web.exe -ResetPassword (PowerShell as administrator)"}, http.StatusUnauthorized)
		return
	}
	s.lim.ok()
	tok := s.ss.add(a.MustChange, now)
	http.SetCookie(w, &http.Cookie{Name: preCookie, Value: "", Path: "/login", MaxAge: -1})
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: tok, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode})
	s.audit(r, a.User, "login", "")
	if a.MustChange {
		next = "/password"
	}
	http.Redirect(w, r, next, http.StatusSeeOther)
}

func (s *server) logout(q *req) {
	if q.r.Method == http.MethodPost {
		s.ss.end(q.tok)
		s.audit(q.r, AdminUser, "logout", "")
	}
	http.SetCookie(q.w, &http.Cookie{Name: sessionCookie, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(q.w, q.r, "/login", http.StatusSeeOther)
}

func (s *server) password(q *req) {
	if q.r.Method != http.MethodPost {
		s.render(q, "password", "Пароль", nil)
		return
	}
	a, err := readAuth(s.p)
	if err != nil {
		s.render(q, "password", "Пароль", err)
		return
	}
	if !verifyPassword(q.r.FormValue("old"), a.Hash) {
		s.render(q, "password", "Пароль", fmt.Errorf("the current password is wrong"))
		return
	}
	nw := q.r.FormValue("new")
	if err := checkNewPassword(nw); err != nil {
		s.render(q, "password", "Пароль", err)
		return
	}
	if nw != q.r.FormValue("new2") {
		s.render(q, "password", "Пароль", fmt.Errorf("the new passwords differ"))
		return
	}
	if nw == q.r.FormValue("old") {
		s.render(q, "password", "Пароль", fmt.Errorf("the new password is the same as the current one"))
		return
	}
	h, err := hashPassword(nw)
	if err != nil {
		s.render(q, "password", "Пароль", err)
		return
	}
	if err := writeAuth(s.p, &authFile{User: a.User, Hash: h, Changed: time.Now().Format(time.RFC3339)}); err != nil {
		s.render(q, "password", "Пароль", err)
		return
	}
	os.Remove(s.p.initialPw())
	q.ss.mustChange = false
	s.ss.endAll(q.tok)
	s.audit(q.r, a.User, "password-changed", "")
	s.back(q, "/", "пароль змінено")
}

// ---------------------------------------------------------------- аудит

// audit — дія у веб: рядок у web.log і запис event "Admin" у docscan-results.json (його читає агент Wazuh).
func (s *server) audit(r *http.Request, user, action, detail string) {
	wu := ""
	if r != nil {
		port, _ := strconv.Atoi(s.port)
		wu = winUser(r.RemoteAddr, port) // хто з користувачів Windows (термінальний сервер: веб бачать усі)
	}
	s.log.Log("AUDIT", "%s%s %s %s", user, map[bool]string{true: " (" + wu + ")", false: ""}[wu != ""], action, detail)
	if err := writeAdminRecord(s.p, s.host, user, action, detail, "web", wu); err != nil {
		s.log.Log("ERROR", "audit record: %v", err)
	}
}

// writeAdminRecord — запис аудиту (event "Admin") у docscan-results.json -> Wazuh. via: web | cli;
// windows_user — обліковий запис Windows, що зробив дію (браузер / командний рядок), якщо відомий.
func writeAdminRecord(p paths, host, user, action, detail, via, wu string) error {
	a := map[string]string{"user": user, "action": action, "detail": detail, "via": via}
	if wu != "" {
		a["windows_user"] = wu
	}
	rec := map[string]any{"timestamp": time.Now().Format("2006-01-02T15:04:05.000-07:00"), "source": "docscan", "host": host,
		"event": "Admin", "admin": a}
	b, _ := json.Marshal(rec)
	return appendLine(p.resultsLog(), append(b, '\n'))
}
