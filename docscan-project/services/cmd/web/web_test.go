package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func testPaths(t *testing.T) paths {
	d := t.TempDir()
	p := paths{data: filepath.Join(d, "data"), install: filepath.Join(d, "prog")}
	for _, x := range []string{p.web(), p.results(), filepath.Join(p.install, "rules")} {
		os.MkdirAll(x, 0o755)
	}
	os.WriteFile(filepath.Join(p.install, "VERSION.txt"), []byte("DocScan v1.0.8 (build test)\r\n"), 0o644)
	os.WriteFile(filepath.Join(p.install, "rules", "VERSION.txt"), []byte("DocScan rules v1.0.5 (commit x)\r\n"), 0o644)
	return p
}

func TestCert(t *testing.T) {
	p := testPaths(t)
	th, made, err := ensureCert(p, time.Now())
	if err != nil || !made || len(th) != 40 {
		t.Fatalf("ensureCert: %v %v %q", err, made, th)
	}
	b, _ := os.ReadFile(p.certPEM())
	blk, _ := pem.Decode(b)
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if c.IsCA || c.Subject.CommonName != CertCN || len(c.IPAddresses) != 2 || c.IPAddresses[0].String() != "127.0.0.1" {
		t.Fatalf("certificate: CA %v, CN %q, IPs %v", c.IsCA, c.Subject.CommonName, c.IPAddresses)
	}
	if err := c.VerifyHostname("127.0.0.1"); err != nil {
		t.Fatal(err)
	}
	if c.VerifyHostname("example.org") == nil {
		t.Fatal("the certificate must not be valid for other names")
	}
	th2, made2, _ := ensureCert(p, time.Now())
	if made2 || th2 != th {
		t.Fatal("a valid certificate must be kept")
	}
	// close to the end -> a new one
	if _, made3, _ := ensureCert(p, time.Now().Add(certLife-30*24*time.Hour)); !made3 {
		t.Fatal("an expiring certificate must be replaced")
	}
}

func TestPasswordHash(t *testing.T) {
	h, err := hashPassword("correct horse battery")
	if err != nil || !verifyPassword("correct horse battery", h) || verifyPassword("wrong", h) || verifyPassword("x", "garbage") {
		t.Fatal("hash / verify")
	}
}

// the whole sign-in flow: Host check, redirect, temporary password -> forced change, CSRF, status page
func TestSignInFlow(t *testing.T) {
	p := testPaths(t)
	pw, err := newInitialPassword(p, "127.0.0.1:8741")
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(p.initialPw()); !strings.Contains(string(b), pw) {
		t.Fatal("initial-password.txt has no password")
	}
	s, err := newServer(p, "127.0.0.1:8741", newLogger(p.webLog()))
	if err != nil {
		t.Fatal(err)
	}
	do := func(method, path string, form url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
		var r *http.Request
		if form != nil {
			r = httptest.NewRequest(method, "https://127.0.0.1:8741"+path, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			r = httptest.NewRequest(method, "https://127.0.0.1:8741"+path, nil)
		}
		for _, c := range cookies {
			r.AddCookie(c)
		}
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	cookie := func(w *httptest.ResponseRecorder, name string) *http.Cookie {
		for _, c := range w.Result().Cookies() {
			if c.Name == name {
				return c
			}
		}
		return nil
	}
	// another Host (DNS rebinding) -> refused
	r := httptest.NewRequest("GET", "https://evil.example:8741/", nil)
	w := httptest.NewRecorder()
	s.ServeHTTP(w, r)
	if w.Code != http.StatusMisdirectedRequest {
		t.Fatalf("foreign Host: %d", w.Code)
	}
	// no session -> login
	if w := do("GET", "/", nil); w.Code != http.StatusSeeOther || !strings.HasPrefix(w.Header().Get("Location"), "/login") {
		t.Fatalf("no session: %d %s", w.Code, w.Header().Get("Location"))
	}
	lg := do("GET", "/login", nil)
	pre := cookie(lg, preCookie)
	if pre == nil || !strings.Contains(lg.Body.String(), "initial-password.txt") {
		t.Fatal("login page: no form cookie / first-run hint")
	}
	// wrong password
	if w := do("POST", "/login", url.Values{"pre": {pre.Value}, "name": {"admin"}, "password": {"nope"}}, pre); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong password: %d", w.Code)
	}
	s.lim.ok()
	w = do("POST", "/login", url.Values{"pre": {pre.Value}, "name": {"admin"}, "password": {pw}}, pre)
	sc := cookie(w, sessionCookie)
	if w.Code != http.StatusSeeOther || sc == nil || w.Header().Get("Location") != "/password" || !sc.Secure || !sc.HttpOnly || sc.SameSite != http.SameSiteStrictMode {
		t.Fatalf("login: %d %s %+v", w.Code, w.Header().Get("Location"), sc)
	}
	// temporary password: every page leads to /password
	if w := do("GET", "/detections", nil, sc); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/password" {
		t.Fatalf("must change: %d %s", w.Code, w.Header().Get("Location"))
	}
	page := do("GET", "/password", nil, sc).Body.String()
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page)
	if m == nil {
		t.Fatal("no CSRF token in the form")
	}
	nw := "a new long password 1"
	if w := do("POST", "/password", url.Values{"csrf": {"bad"}, "old": {pw}, "new": {nw}, "new2": {nw}}, sc); w.Code != http.StatusForbidden {
		t.Fatalf("bad CSRF: %d", w.Code)
	}
	if w := do("POST", "/password", url.Values{"csrf": {m[1]}, "old": {pw}, "new": {"short"}, "new2": {"short"}}, sc); !strings.Contains(w.Body.String(), "at least") {
		t.Fatal("short password accepted")
	}
	if w := do("POST", "/password", url.Values{"csrf": {m[1]}, "old": {pw}, "new": {nw}, "new2": {nw}}, sc); w.Code != http.StatusSeeOther {
		t.Fatalf("change: %d %s", w.Code, w.Body.String())
	}
	if fileExists(p.initialPw()) {
		t.Fatal("initial-password.txt must be deleted after the change")
	}
	a, _ := readAuth(p)
	if a.MustChange || !verifyPassword(nw, a.Hash) {
		t.Fatal("auth.json not updated")
	}
	if w := do("GET", "/", nil, sc); w.Code != 200 || !strings.Contains(w.Body.String(), "DocScan v1.0.8") {
		t.Fatalf("status: %d", w.Code)
	}
	// every page renders (a template error would only reach web.log)
	appendLine(p.resultsLog(), []byte(`{"timestamp":"`+time.Now().Format("2006-01-02T15:04:05.000-07:00")+`","event":"Created","verdict":"HIGH","disarm":"quarantined","docfile":{"path":"C:\\Users\\a\\Downloads\\AnyDesk.exe","name":"AnyDesk.exe"},"list":{"list":"black","by":"path","comment":"banned"}}`+"\n"))
	os.WriteFile(filepath.Join(p.results(), "watcher.log"), []byte("2026-11-23 10:00:00 [INFO] start: watching C:\\Users\r\n"), 0o644)
	det := do("GET", "/detections", nil, sc).Body.String()
	if !strings.Contains(det, "AnyDesk.exe") || !regexp.MustCompile(`/record\?f=0&(amp;)?o=`).MatchString(det) {
		t.Fatalf("detections page:\n%s", det)
	}
	off := regexp.MustCompile(`/record\?f=0&(?:amp;)?o=(\d+)`).FindStringSubmatch(det)[1]
	if w := do("GET", "/record?f=0&o="+off, nil, sc); !strings.Contains(w.Body.String(), "banned") || !strings.Contains(w.Body.String(), "&#34;disarm&#34;: &#34;quarantined&#34;") {
		t.Fatalf("record page:\n%s", w.Body.String())
	}
	if w := do("GET", "/detections?admin=1", nil, sc); !strings.Contains(w.Body.String(), "password-changed") {
		t.Fatal("admin actions page")
	}
	if w := do("GET", "/logs?which=watcher", nil, sc); !strings.Contains(w.Body.String(), "start: watching") {
		t.Fatal("logs page")
	}
	if l, _ := os.ReadFile(p.webLog()); strings.Contains(string(l), "template") {
		t.Fatalf("template error: %s", l)
	}
	// audit records for Wazuh
	b, _ := os.ReadFile(p.resultsLog())
	for _, a := range []string{`"action":"login-failed"`, `"action":"login"`, `"action":"password-changed"`} {
		if !strings.Contains(string(b), a) {
			t.Errorf("no audit record %s", a)
		}
	}
}

func TestLimiter(t *testing.T) {
	l := &limiter{}
	now := time.Now()
	for i := 0; i < 3; i++ {
		if l.check(now) != nil {
			t.Fatal("blocked too early")
		}
		l.fail(now)
	}
	if l.check(now) == nil {
		t.Fatal("not blocked after 3 failures")
	}
	if l.check(now.Add(2*time.Second)) != nil {
		t.Fatal("still blocked after the wait")
	}
	for i := 0; i < 30; i++ {
		l.fail(now)
	}
	if l.check(now.Add(15*time.Minute+time.Second)) != nil {
		t.Fatal("the wait must not exceed 15 min")
	}
	l.ok()
	if l.check(now) != nil {
		t.Fatal("success must reset")
	}
}

// records from the current and the rotated results file, newest first, filters, the record page
func TestRecords(t *testing.T) {
	p := testPaths(t)
	now := time.Now()
	stamp := func(d time.Duration) string { return now.Add(-d).Format("2006-01-02T15:04:05.000-07:00") }
	old := `{"timestamp":"` + stamp(48*time.Hour) + `","event":"Created","verdict":"MEDIUM","docfile":{"path":"C:\\Users\\a\\x.xlsm"},"docscan":{"findings":["MACRO_COM"]}}` + "\n"
	cur := `{"timestamp":"` + stamp(2*time.Hour) + `","event":"Created","verdict":"INFO","docfile":{"path":"C:\\Users\\a\\ok.docx"}}` + "\n" +
		`{"timestamp":"` + stamp(time.Hour) + `","event":"ListSweep","verdict":"HIGH","disarm":"quarantined","docfile":{"path":"C:\\Users\\a\\Downloads\\AnyDesk.exe"},"list":{"list":"black","by":"path","comment":"banned"}}` + "\n" +
		`{"timestamp":"` + stamp(30*time.Minute) + `","event":"Admin","admin":{"user":"admin","action":"login"}}` + "\n"
	os.WriteFile(p.resultsLog()+".1", []byte(old), 0o644)
	os.WriteFile(p.resultsLog(), []byte(cur), 0o644)
	s := &server{p: p}
	recs, n := s.readRecords(filter{}, 0, 10)
	if n != 2 || recs[0].Verdict != "HIGH" || recs[1].Rules[0] != "MACRO_COM" || recs[1].File != 1 {
		t.Fatalf("detections: %d %+v", n, recs)
	}
	if _, n := s.readRecords(filter{verdict: "all"}, 0, 10); n != 3 {
		t.Fatalf("all: %d", n)
	}
	if _, n := s.readRecords(filter{since: now.Add(-24 * time.Hour)}, 0, 10); n != 1 {
		t.Fatalf("24h: %d", n)
	}
	if r, n := s.readRecords(filter{rule: "macro_com", verdict: "all"}, 0, 10); n != 1 || r[0].Path != `C:\Users\a\x.xlsm` {
		t.Fatalf("rule: %d", n)
	}
	if r, n := s.readRecords(filter{admin: true}, 0, 10); n != 1 || r[0].AdminAction != "login" {
		t.Fatalf("admin: %d", n)
	}
	if _, n := s.readRecords(filter{text: "anydesk"}, 0, 10); n != 1 {
		t.Fatalf("text: %d", n)
	}
}

// temporary password: expires after tempPasswordTTL (sign-in refused, file deleted, audited); lockout and
// -ResetPassword are audited
func TestTempPasswordAndAudit(t *testing.T) {
	p := testPaths(t)
	pw, err := newInitialPassword(p, "127.0.0.1:8741")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := readAuth(p)
	if a.Expires == "" || a.tempExpired(time.Now()) || !a.tempExpired(time.Now().Add(tempPasswordTTL+time.Minute)) {
		t.Fatalf("expiry %+v", a)
	}
	if b, _ := os.ReadFile(p.initialPw()); !strings.Contains(string(b), "valid until") {
		t.Fatal("no expiry in initial-password.txt")
	}
	s, err := newServer(p, "127.0.0.1:8741", newLogger(p.webLog()))
	if err != nil {
		t.Fatal(err)
	}
	login := func(pass string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "https://127.0.0.1:8741/login", nil)
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		var pre *http.Cookie
		for _, c := range w.Result().Cookies() {
			if c.Name == preCookie {
				pre = c
			}
		}
		r = httptest.NewRequest("POST", "https://127.0.0.1:8741/login", strings.NewReader(url.Values{"pre": {pre.Value}, "name": {"admin"}, "password": {pass}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(pre)
		w = httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
	// 3 wrong passwords -> locked, audited
	for i := 0; i < 3; i++ {
		login("wrong-" + fmt.Sprint(i))
	}
	if l := auditHas(t, p, "login-locked"); !strings.Contains(l, "3 failed sign-ins") {
		t.Fatalf("lockout record: %s", l)
	}
	s.lim.ok()
	// expired: the right password is refused, the file goes, audited
	a.Expires = time.Now().Add(-time.Minute).Format(time.RFC3339)
	writeAuth(p, a)
	if w := login(pw); w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "ResetPassword") {
		t.Fatalf("expired password accepted: %d", w.Code)
	}
	if fileExists(p.initialPw()) {
		t.Fatal("expired initial-password.txt kept")
	}
	auditHas(t, p, "login-refused")
	// the hourly purge removes an expired file nobody used
	newInitialPassword(p, "127.0.0.1:8741")
	a, _ = readAuth(p)
	s.purgeTempPassword(time.Now())
	if !fileExists(p.initialPw()) {
		t.Fatal("a valid temporary password purged")
	}
	s.purgeTempPassword(time.Now().Add(tempPasswordTTL + time.Minute))
	if fileExists(p.initialPw()) {
		t.Fatal("expired file not purged")
	}
	auditHas(t, p, "temp-password-expired")
	// -ResetPassword from the command line: audited, via cli
	if cmdInitAuth(p, true, "127.0.0.1:8741") != 0 {
		t.Fatal("reset failed")
	}
	if l := auditHas(t, p, "password-reset"); !strings.Contains(l, `"via":"cli"`) {
		t.Fatalf("reset record: %s", l)
	}
}
