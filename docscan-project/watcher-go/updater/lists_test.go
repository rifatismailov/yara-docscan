package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"docscan/watcher/manifest"
)

// orgServer — сервер організації: файли за назвою (немає — 404)
type orgServer struct {
	mu    sync.Mutex
	files map[string][]byte
}

func (o *orgServer) put(name string, b []byte) { o.mu.Lock(); o.files[name] = b; o.mu.Unlock() }
func (o *orgServer) del(name string)           { o.mu.Lock(); delete(o.files, name); o.mu.Unlock() }
func (o *orgServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	b, ok := o.files[strings.TrimPrefix(r.URL.Path, "/docscan/")]
	o.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Write(b)
}

func signed(t *testing.T, seed, body string) ([]byte, []byte) {
	sig, err := manifest.Sign([]byte(body), seed)
	if err != nil {
		t.Fatal(err)
	}
	return []byte(body), []byte(sig)
}

func TestListsUpdate(t *testing.T) {
	e, _ := newEnv(t, "https://unused.invalid/", "v1.0.0")
	orgSeed, orgPub, _ := manifest.NewSeed()
	otherSeed, _, _ := manifest.NewSeed()
	srv := &orgServer{files: map[string][]byte{}}
	hs := httptest.NewServer(srv)
	defer hs.Close()
	e.u.cfg.Lists = Lists{URL: hs.URL + "/docscan/", CheckEveryHours: 24, PublicKeys: []string{orgPub}}
	white := filepath.Join(e.u.dataDir, "lists", "whitelist.json")
	now := time.Now()

	// nothing published: nothing done, no error
	if e.u.checkLists(now) {
		t.Fatal("no lists on the server must not be an error")
	}
	// v1: signed by the organisation -> installed
	w1 := `{"schema": 1, "serial": 100, "entries": [{"path": "C:\\Users\\*\\Desktop\\App*.lnk", "lnk_target": "\\\\srv\\BIN\\"}, {"sha256": "` + strings.Repeat("a", 64) + `"}]}`
	d, s := signed(t, orgSeed, w1)
	srv.put("whitelist.json", d)
	srv.put("whitelist.json.sig", s)
	if e.u.checkLists(now) {
		t.Fatalf("signed list rejected: %+v", e.records(t))
	}
	if b, _ := os.ReadFile(white); string(b) != w1 {
		t.Fatalf("whitelist.json not installed: %q", b)
	}
	rs := e.records(t)
	if last := rs[len(rs)-1]; last.Component != "lists" || last.Status != "success" || last.To != "100" {
		t.Fatalf("record: %+v", last)
	}
	// the same again: up to date, no new record
	n := len(e.records(t))
	if e.u.checkLists(now) || len(e.records(t)) != n {
		t.Fatalf("same serial must be 'up to date' without a record")
	}

	reject := func(name, body string, sig []byte) {
		t.Helper()
		srv.put("whitelist.json", []byte(body))
		srv.put("whitelist.json.sig", sig)
		e.u.lastErr = map[string]time.Time{}
		if !e.u.checkLists(now) {
			t.Errorf("%s: accepted", name)
		}
		if b, _ := os.ReadFile(white); string(b) != w1 {
			t.Errorf("%s: the installed list was replaced", name)
		}
		rs := e.records(t)
		if last := rs[len(rs)-1]; last.Status != "error" || last.Component != "lists" {
			t.Errorf("%s: no error record: %+v", name, last)
		}
	}
	w2 := strings.Replace(w1, `"serial": 100`, `"serial": 200`, 1)
	_, s2 := signed(t, orgSeed, w2)
	reject("tampered after signing", strings.Replace(w2, `srv`, `evil`, 1), s2)
	_, so := signed(t, otherSeed, w2)
	reject("signed by another key", w2, so)
	reject("no signature", w2, []byte("ed25519 00000000 AAAA"))
	old := strings.Replace(w1, `"serial": 100`, `"serial": 50`, 1)
	_, sOld := signed(t, orgSeed, old)
	reject("older serial (replay)", old, sOld)
	noSerial := `{"schema": 1, "entries": [{"sha256": "` + strings.Repeat("c", 64) + `"}]}`
	_, sNo := signed(t, orgSeed, noSerial)
	reject("signed without serial", noSerial, sNo)
	bad := `{"schema": 1, "serial": 300, "entries": [{"path": "C:\\Users\\*\\Downloads\\*.*"}]}`
	_, sBad := signed(t, orgSeed, bad)
	reject("valid signature, invalid list (white list allowing every file of a folder)", bad, sBad)
	srv.del("whitelist.json.sig")
	srv.put("whitelist.json", []byte(w2))
	e.u.lastErr = map[string]time.Time{}
	if !e.u.checkLists(now) {
		t.Errorf("list without .sig accepted")
	}

	// newer + black list: both installed
	d2, s2b := signed(t, orgSeed, w2)
	srv.put("whitelist.json", d2)
	srv.put("whitelist.json.sig", s2b)
	b1 := `{"schema": 1, "serial": 7, "entries": [{"path": "C:\\Users\\*\\Downloads\\*.exe"}]}`
	db, sb := signed(t, orgSeed, b1)
	srv.put("blacklist.json", db)
	srv.put("blacklist.json.sig", sb)
	e.u.lastErr = map[string]time.Time{}
	if e.u.checkLists(now) {
		t.Fatalf("newer lists rejected: %+v", e.records(t)[len(e.records(t))-1])
	}
	if b, _ := os.ReadFile(white); string(b) != w2 {
		t.Errorf("newer whitelist not installed")
	}
	if b, _ := os.ReadFile(white + ".prev"); string(b) != w1 {
		t.Errorf("previous whitelist not kept as .prev")
	}
	if b, _ := os.ReadFile(filepath.Join(e.u.dataDir, "lists", "blacklist.json")); string(b) != b1 {
		t.Errorf("blacklist not installed")
	}

	// schedule: next check after check_every_hours; an error -> in an hour
	e.u.listsNext = time.Time{}
	if w := e.u.listsTick(now); w != 24*time.Hour {
		t.Errorf("next check in %s, want 24h", w)
	}
	if w := e.u.listsTick(now.Add(time.Hour)); w != 23*time.Hour {
		t.Errorf("before the time: %s left, want 23h", w)
	}
	srv.put("whitelist.json.sig", []byte("broken"))
	e.u.listsNext = time.Time{}
	if w := e.u.listsTick(now); w != time.Hour {
		t.Errorf("after an error the next check in %s, want 1h", w)
	}
}

func TestListsToken(t *testing.T) {
	e, _ := newEnv(t, "https://unused.invalid/", "v1.0.0")
	orgSeed, orgPub, _ := manifest.NewSeed()
	srv := &orgServer{files: map[string][]byte{}}
	fake := strings.Repeat("x", 16) // a made-up value for the test server, not a real secret
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "token "+fake {
			http.Redirect(w, r, "/user/login", http.StatusSeeOther) // like Forgejo with sign-in required
			return
		}
		srv.ServeHTTP(w, r)
	}))
	defer auth.Close()
	d, s := signed(t, orgSeed, `{"schema": 1, "serial": 5, "entries": [{"sha256": "`+strings.Repeat("d", 64)+`"}]}`)
	srv.put("whitelist.json", d)
	srv.put("whitelist.json.sig", s)
	e.u.cfg.Lists = Lists{URL: auth.URL + "/docscan/", CheckEveryHours: 24, PublicKeys: []string{orgPub}}
	if !e.u.checkLists(time.Now()) {
		t.Fatal("without the token the closed mirror must fail")
	}
	e.u.cfg.Lists.Token = fake
	e.u.lastErr = map[string]time.Time{}
	if e.u.checkLists(time.Now()) {
		t.Fatalf("with the token the list must install: %+v", e.records(t))
	}
}

func TestListsConfig(t *testing.T) {
	dir := t.TempDir()
	cfgp := filepath.Join(dir, "updater.json")
	os.WriteFile(cfgp, []byte(`{"mode": "off", "lists": {"url": "https://lists.org.local/docscan/"}}`), 0o644)
	if _, err := loadConfig(cfgp, dir); err == nil || !strings.Contains(err.Error(), "public_keys") {
		t.Errorf("lists.url without public_keys must be refused: %v", err)
	}
	_, pub, _ := manifest.NewSeed()
	os.WriteFile(cfgp, []byte(`{"mode": "off", "lists": {"url": "https://lists.org.local/docscan/", "public_keys": ["`+pub+`"]}}`), 0o644)
	c, err := loadConfig(cfgp, dir)
	if err != nil || c.Lists.CheckEveryHours != 24 {
		t.Errorf("config: %v %+v", err, c)
	}
	os.WriteFile(cfgp, []byte(`{"mode": "off", "lists": {"url": "ftp://x/", "public_keys": ["`+pub+`"]}}`), 0o644)
	if _, err := loadConfig(cfgp, dir); err == nil {
		t.Errorf("ftp lists.url accepted")
	}
}
