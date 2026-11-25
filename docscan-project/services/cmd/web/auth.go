package main

// Опис: docscan-project/DOCSCAN.md#web — пароль, тимчасовий пароль, сесії, обмеження спроб.

// Вхід: один обліковий запис admin. Пароль генерує install.ps1 (docscan-web.exe -InitAuth): у web\auth.json лише
// хеш (PBKDF2-SHA256), сам пароль — у web\initial-password.txt (ACL: SYSTEM, Адміністратори) до першого входу,
// після якого DocScan вимагає змінити пароль і видаляє файл. Тимчасовий пароль діє tempPasswordTTL (24 год): потім
// він не приймається, а файл видаляється (служба перевіряє раз на годину) — пароль, який ніхто не забрав, не лежить
// на ПК роками; новий — docscan-web.exe -ResetPassword. Сесії — у пам'яті служби (перезапуск = вийти).

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// AdminUser — ім'я облікового запису.
const AdminUser = "admin"

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
		return fmt.Errorf("the password needs at least %d characters", minPassword)
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
		return nil, fmt.Errorf("%s is broken (docscan-web.exe -ResetPassword makes a new password)", p.authFile())
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

var errWait = errors.New("too many failed sign-ins")

func (l *limiter) check(now time.Time) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Before(l.until) {
		return fmt.Errorf("%w - wait %s", errWait, l.until.Sub(now).Round(time.Second))
	}
	return nil
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
