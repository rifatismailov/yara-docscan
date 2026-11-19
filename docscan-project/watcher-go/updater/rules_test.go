package main

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"docscan/watcher/manifest"
)

// rulesRelease — підписаний реліз правил: пакет, маніфест, підпис, пакет для ручного встановлення.
type rulesRelease struct {
	pkg, data, sig, bundle []byte
}

func makeRules(t *testing.T, seed, version, extra string) *rulesRelease {
	files := map[string][]byte{
		"docscan-index.yar": []byte("include \"general/a.yar\"\n" + extra),
		"VERSION.txt":       []byte("DocScan rules " + version + " (commit abc)\r\n"),
		"general/a.yar":     []byte("rule a { condition: true }\n"),
	}
	r := &rulesRelease{pkg: zipOf(files)}
	m := manifest.Manifest{Schema: manifest.Schema, Product: manifest.ProductRules, Version: version, Build: "b", Commit: "c",
		Created: "2026-11-19T10:00:00Z", Files: map[string]string{}}
	for n, b := range files {
		h := sha256.Sum256(b)
		m.Files[n] = hex.EncodeToString(h[:])
	}
	h := sha256.Sum256(r.pkg)
	m.Package = manifest.File{Name: "DocScan-rules.zip", Size: int64(len(r.pkg)), SHA256: hex.EncodeToString(h[:])}
	r.data, _ = json.MarshalIndent(m, "", "  ")
	s, err := manifest.Sign(r.data, seed)
	if err != nil {
		t.Fatal(err)
	}
	r.sig = []byte(s)
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for n, c := range map[string][]byte{"rules-manifest.json": r.data, "rules-manifest.sig": r.sig, "DocScan-rules.zip": r.pkg} {
		o, _ := w.Create(n)
		o.Write(c)
	}
	w.Close()
	r.bundle = b.Bytes()
	return r
}

func serveRules(r *rulesRelease) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		switch filepath.Base(q.URL.Path) {
		case "rules-manifest.json":
			w.Write(r.data)
		case "rules-manifest.sig":
			w.Write(r.sig)
		case "DocScan-rules.zip":
			w.Write(r.pkg)
		default:
			http.NotFound(w, q)
		}
	})
}

// fakeSvc: Start пише в watcher.log "start: watching", а якщо в правилах є BROKEN — рядок помилки (watcher не стартував).
type fakeSvc struct {
	u      *Updater
	starts int
}

func (f *fakeSvc) Stop(string) error { return nil }
func (f *fakeSvc) Start(string) error {
	f.starts++
	idx, _ := os.ReadFile(filepath.Join(f.u.rulesDir(), "docscan-index.yar"))
	line := "2026-11-19 12:00:00 [INFO] start: watching C:\\Users\r\n"
	if strings.Contains(string(idx), "BROKEN") {
		line = "2026-11-19 12:00:00 [ERROR] the rules do not compile\r\n"
	}
	p := filepath.Join(f.u.dataDir, "results", "watcher.log")
	os.MkdirAll(filepath.Dir(p), 0o755)
	fh, _ := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	fh.WriteString(line)
	fh.Close()
	return nil
}

func rulesEnv(t *testing.T) (*env, string, *fakeSvc, *httptest.Server) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	e, seed := newEnv(t, srv.URL, "v1.0.4")
	f := &fakeSvc{u: e.u}
	e.u.svc, e.u.poll = f, 10*time.Millisecond
	e.u.compiler = func(dir string) error {
		if b, _ := os.ReadFile(filepath.Join(dir, "docscan-index.yar")); strings.Contains(string(b), "NOCOMPILE") {
			return os.ErrInvalid
		}
		return nil
	}
	e.u.cfg.Rules.GitHub.Repo = DefaultRulesRepo
	// правила з пакета програми (до окремих правил): без VERSION.txt
	os.MkdirAll(e.u.rulesDir(), 0o755)
	os.WriteFile(filepath.Join(e.u.rulesDir(), "docscan-index.yar"), []byte("old"), 0o644)
	return e, seed, f, srv
}

func TestRulesUpdateAndRollback(t *testing.T) {
	e, seed, f, srv := rulesEnv(t)
	srv.Config.Handler = serveRules(makeRules(t, seed, "v1.0.1", ""))
	if o := e.u.checkRules(&Request{Component: "rules"}, false, time.Now()); o.Status != "done" {
		t.Fatalf("check: %+v", o)
	}
	if e.u.installedRules() != "v1.0.1" || !exists(e.u.rulesDir()+".prev") || f.starts != 1 {
		t.Fatalf("installed %q prev %v starts %d", e.u.installedRules(), exists(e.u.rulesDir()+".prev"), f.starts)
	}
	r := e.records(t)
	if len(r) != 1 || r[0].Status != "success" || r[0].Component != "rules" || r[0].To != "v1.0.1" {
		t.Fatalf("records: %+v", r)
	}
	// ті самі — нічого
	if o := e.u.checkRules(&Request{Component: "rules"}, false, time.Now()); o.Status != "current" {
		t.Fatalf("again: %+v", o)
	}
	// компілюються, але watcher з ними не стартує -> відкат на v1.0.1
	srv.Config.Handler = serveRules(makeRules(t, seed, "v1.0.2", "BROKEN"))
	e.u.checkRules(&Request{Component: "rules"}, false, time.Now())
	if e.u.installedRules() != "v1.0.1" {
		t.Fatalf("after rollback installed %q", e.u.installedRules())
	}
	if r = e.records(t); r[len(r)-1].Status != "rollback" {
		t.Fatalf("records: %+v", r)
	}
	// не компілюються -> не ставляться взагалі (watcher не зупиняється)
	starts := f.starts
	srv.Config.Handler = serveRules(makeRules(t, seed, "v1.0.3", "NOCOMPILE"))
	e.u.checkRules(&Request{Component: "rules"}, false, time.Now())
	if e.u.installedRules() != "v1.0.1" || f.starts != starts {
		t.Fatalf("no-compile: installed %q starts %d->%d", e.u.installedRules(), starts, f.starts)
	}
	if r = e.records(t); r[len(r)-1].Status != "failed" {
		t.Fatalf("records: %+v", r)
	}
	// невдалі версії періодична перевірка не повторює
	srv.Config.Handler = serveRules(makeRules(t, seed, "v1.0.2", "BROKEN"))
	if o := e.u.checkRules(&Request{Component: "rules"}, false, time.Now()); o.Status != "current" {
		t.Fatalf("failed version retried: %+v", o)
	}
}

func TestInstallRulesFile(t *testing.T) {
	e, seed, f, _ := rulesEnv(t)
	dir := t.TempDir()
	good := filepath.Join(dir, "DocScan-rules-bundle.zip")
	os.WriteFile(good, makeRules(t, seed, "v1.0.5", "").bundle, 0o644)
	msg, err := e.u.installRulesFile(good)
	if err != nil || e.u.installedRules() != "v1.0.5" || f.starts != 0 {
		t.Fatalf("install: %q %v installed %q starts %d", msg, err, e.u.installedRules(), f.starts)
	}
	// чужий ключ
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	bad := filepath.Join(dir, "bad.zip")
	os.WriteFile(bad, makeRules(t, base64.StdEncoding.EncodeToString(other.Seed()), "v1.0.6", "").bundle, 0o644)
	if _, err := e.u.installRulesFile(bad); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("foreign key: %v", err)
	}
	// старіші — ні
	old := filepath.Join(dir, "old.zip")
	os.WriteFile(old, makeRules(t, seed, "v1.0.4", "").bundle, 0o644)
	if _, err := e.u.installRulesFile(old); err == nil {
		t.Fatal("older rules installed")
	}
	// не пакет правил (просто zip)
	plain := filepath.Join(dir, "plain.zip")
	os.WriteFile(plain, zipOf(map[string][]byte{"x.yar": []byte("rule x { condition: true }")}), 0o644)
	if _, err := e.u.installRulesFile(plain); err == nil {
		t.Fatal("a plain zip accepted")
	}
	if e.u.installedRules() != "v1.0.5" {
		t.Fatalf("installed changed to %q", e.u.installedRules())
	}
}
