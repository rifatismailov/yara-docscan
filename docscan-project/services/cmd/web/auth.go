package main

// Вхід: один обліковий запис admin. Пароль генерує install.ps1 (docscan-web.exe -InitAuth): у web\auth.json лише
// хеш (PBKDF2-SHA256), сам пароль — у web\initial-password.txt (ACL: SYSTEM, Адміністратори) до першого входу,
// після якого DocScan вимагає змінити пароль і видаляє файл. Тимчасовий пароль діє tempPasswordTTL (24 год): потім
// він не приймається, а файл видаляється (служба перевіряє раз на годину) — пароль, який ніхто не забрав, не лежить
// на ПК роками; новий — docscan-web.exe -ResetPassword. Сесії — у пам'яті служби (перезапуск = вийти).
// Опис: docscan-project/DOCSCAN.md#web.

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AdminUser — ім'я облікового запису.
const AdminUser = "admin"

const (
	sessionCookie = "docscan_session"
	preCookie     = "docscan_login" // токен форми входу (подвійна відправка: cookie + поле форми)
)

const (
	pbkdfIter   = 600_000
	minPassword = 12
	sessionIdle = 30 * time.Minute
	maxSessions = 32
	// tempPasswordTTL — скільки діє тимчасовий пароль (після встановлення / -ResetPassword)
	tempPasswordTTL = 24 * time.Hour
)

type authFile struct {
	User       string `json:"user"`
	Hash       string `json:"hash"`        // pbkdf2-sha256$<iter>$<salt>$<hash>
	MustChange bool   `json:"must_change"` // тимчасовий пароль (після встановлення / -ResetPassword)
	Changed    string `json:"changed"`
	Expires    string `json:"expires,omitempty"` // тимчасовий пароль діє до (RFC 3339); старі auth.json без поля — без строку
}

// tempExpired — тимчасовий пароль, строк якого минув.
func (a *authFile) tempExpired(now time.Time) bool {
	if a == nil || !a.MustChange || a.Expires == "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, a.Expires)
	return err == nil && now.After(t)
}

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	h, err := pbkdf2.Key(sha256.New, pw, salt, pbkdfIter, 32)
	if err != nil {
		return "", err
	}
	e := base64.RawStdEncoding
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", pbkdfIter, e.EncodeToString(salt), e.EncodeToString(h)), nil
}

func verifyPassword(pw, enc string) bool {
	f := strings.Split(enc, "$")
	if len(f) != 4 || f[0] != "pbkdf2-sha256" {
		return false
	}
	iter, err := strconv.Atoi(f[1])
	if err != nil || iter < 1 {
		return false
	}
	e := base64.RawStdEncoding
	salt, err1 := e.DecodeString(f[2])
	want, err2 := e.DecodeString(f[3])
	if err1 != nil || err2 != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, iter, len(want))
	return err == nil && subtle.ConstantTimeCompare(got, want) == 1
}

// randomPassword — 20 символів без схожих (0/O, 1/l/I).
func randomPassword() string {
	const abc = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, 20)
	rand.Read(b)
	for i := range b {
		b[i] = abc[int(b[i])%len(abc)]
	}
	return string(b)
}

func randomToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func checkNewPassword(pw string) error {
	if len([]rune(pw)) < minPassword {
		return fmt.Errorf("пароль — не менше %d символів", minPassword)
	}
	return nil
}

func readAuth(p paths) (*authFile, error) {
	b, err := os.ReadFile(p.authFile())
	if err != nil {
		return nil, err
	}
	var a authFile
	if err := json.Unmarshal(b, &a); err != nil || a.Hash == "" {
		return nil, fmt.Errorf("%s зламаний (новий пароль: docscan-web -ResetPassword)", p.authFile())
	}
	return &a, nil
}

func writeAuth(p paths, a *authFile) error {
	b, _ := json.MarshalIndent(a, "", "  ")
	return writeFileAtomic(p.authFile(), b, 0o600)
}

// newInitialPassword — тимчасовий пароль: хеш у auth.json, сам пароль — у initial-password.txt.
func newInitialPassword(p paths, listen string) (string, error) {
	pw := randomPassword()
	h, err := hashPassword(pw)
	if err != nil {
		return "", err
	}
	now := time.Now()
	exp := now.Add(tempPasswordTTL)
	if err := writeAuth(p, &authFile{User: AdminUser, Hash: h, MustChange: true, Changed: now.Format(time.RFC3339), Expires: exp.Format(time.RFC3339)}); err != nil {
		return "", err
	}
	txt := fmt.Sprintf("DocScan web interface: https://%s/\r\n"+
		"user:     %s\r\npassword: %s\r\n\r\nTemporary: valid until %s. DocScan asks for a new password at the first sign-in and then deletes this file.\r\n"+
		"Expired or lost: \"C:\\Program Files\\DocScan\\web\\docscan-web.exe\" -ResetPassword (PowerShell as administrator).\r\n",
		listen, AdminUser, pw, exp.Format("2006-01-02 15:04"))
	if err := writeFileAtomic(p.initialPw(), []byte(txt), 0o600); err != nil {
		return "", err
	}
	return pw, nil
}

// ---------------------------------------------------------------- сесії і спроби входу

type session struct {
	csrf       string
	seen       time.Time
	mustChange bool
}

type sessions struct {
	mu sync.Mutex
	m  map[string]*session
}

func (s *sessions) add(mustChange bool, now time.Time) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if now.Sub(v.seen) > sessionIdle {
			delete(s.m, k)
		}
	}
	if len(s.m) >= maxSessions { // найстаріша сесія виходить
		var old string
		for k, v := range s.m {
			if old == "" || v.seen.Before(s.m[old].seen) {
				old = k
			}
		}
		delete(s.m, old)
	}
	tok := randomToken()
	s.m[tok] = &session{csrf: randomToken(), seen: now, mustChange: mustChange}
	return tok
}

func (s *sessions) get(tok string, now time.Time) *session {
	s.mu.Lock()
	defer s.mu.Unlock()
	v := s.m[tok]
	if v == nil {
		return nil
	}
	if now.Sub(v.seen) > sessionIdle {
		delete(s.m, tok)
		return nil
	}
	v.seen = now
	return v
}

func (s *sessions) end(tok string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.m, tok)
}

// endAll — після зміни пароля всі інші сесії виходять.
func (s *sessions) endAll(except string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k := range s.m {
		if k != except {
			delete(s.m, k)
		}
	}
}

// limiter — невдалі входи (усі з 127.0.0.1, тому лічильник один): після 3 невдалих кожна наступна спроба
// чекає 2^(n-3) с, до 15 хв; вдалий вхід скидає.
type limiter struct {
	mu    sync.Mutex
	fails int
	until time.Time
}

// wait — скільки ще чекати до наступної спроби (0 — можна).
func (l *limiter) wait(now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Before(l.until) {
		return l.until.Sub(now)
	}
	return 0
}

// fail — невдала спроба; повертає, на скільки вхід тепер заблоковано (0 — ще ні).
func (l *limiter) fail(now time.Time) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails++
	if l.fails >= 3 {
		d := time.Second << min(l.fails-3, 10)
		if d > 15*time.Minute {
			d = 15 * time.Minute
		}
		l.until = now.Add(d)
		return d
	}
	return 0
}

func (l *limiter) failures() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fails
}

func (l *limiter) ok() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fails, l.until = 0, time.Time{}
}

// purgeTempPassword — строк тимчасового пароля минув: файл з ним видалити (запис аудиту — раз).
func (s *server) purgeTempPassword(now time.Time) {
	a, err := readAuth(s.p)
	if err != nil || !a.tempExpired(now) || !fileExists(s.p.initialPw()) {
		return
	}
	if err := os.Remove(s.p.initialPw()); err == nil {
		s.audit(nil, AdminUser, "temp-password-expired", "nobody signed in with the temporary password until "+a.Expires+" - "+s.p.initialPw()+" deleted")
	}
}

// ---------------------------------------------------------------- сторінки: вхід, вихід, пароль

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
		if d.Pre == "" {
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
		show(loginData{Next: next, Err: "форма застаріла — спробуйте ще раз"}, http.StatusUnauthorized)
		return
	}
	now := time.Now()
	if wait := s.lim.wait(now); wait > 0 {
		show(loginData{Next: next, Err: fmt.Sprintf("забагато невдалих спроб — зачекайте %s", wait.Round(time.Second))}, http.StatusTooManyRequests)
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
		show(loginData{Next: next, Err: "неправильний користувач або пароль"}, http.StatusUnauthorized)
		return
	}
	if a.tempExpired(now) { // тимчасовий пароль прострочено: не діє, файл з ним — геть
		os.Remove(s.p.initialPw())
		s.audit(r, a.User, "login-refused", "the temporary password expired "+a.Expires)
		show(loginData{Next: next, Err: "строк тимчасового пароля минув — новий: docscan-web -ResetPassword (PowerShell від адміністратора)"}, http.StatusUnauthorized)
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
	f := q.r.FormValue
	fail := func(e error) { s.render(q, "password", "Пароль", e) }
	a, err := readAuth(s.p)
	switch nw := f("new"); {
	case err != nil:
		fail(err)
	case !verifyPassword(f("old"), a.Hash):
		fail(errors.New("поточний пароль неправильний"))
	case checkNewPassword(nw) != nil:
		fail(checkNewPassword(nw))
	case nw != f("new2"):
		fail(errors.New("нові паролі не збігаються"))
	case nw == f("old"):
		fail(errors.New("новий пароль такий самий, як поточний"))
	default:
		h, err := hashPassword(nw)
		if err == nil {
			err = writeAuth(s.p, &authFile{User: a.User, Hash: h, Changed: time.Now().Format(time.RFC3339)})
		}
		if err != nil {
			fail(err)
			return
		}
		os.Remove(s.p.initialPw())
		q.ss.mustChange = false
		s.ss.endAll(q.tok)
		s.audit(q.r, a.User, "password-changed", "")
		s.back(q, "/", "пароль змінено")
	}
}
