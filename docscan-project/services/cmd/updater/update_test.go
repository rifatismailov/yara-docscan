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

	"docscan/services/pkg/manifest"
)

// release — підписаний реліз у пам'яті: файли пакета, zip, manifest.json, manifest.sig.
type release struct {
	files       map[string][]byte
	data, sig   []byte
	pkg         []byte
	tamperAfter bool // віддати пакет з підміненим файлом
}

func makeRelease(t *testing.T, seed, version string) *release {
	r := &release{files: map[string][]byte{
		"install.ps1":    []byte("# installer " + version),
		"VERSION.txt":    []byte("DocScan " + version + " (build 20261119-abcdef12)\r\nyara64 4.6.0\r\n"),
		"bin/yara64.exe": []byte("exe " + version),
	}}
	r.pkg = zipOf(r.files)
	m := manifest.Manifest{Schema: manifest.Schema, Product: manifest.Product, Version: version, Build: "b", Commit: "c",
		Created: "2026-11-19T10:00:00Z", Files: map[string]string{}}
	for n, b := range r.files {
		h := sha256.Sum256(b)
		m.Files[n] = hex.EncodeToString(h[:])
	}
	h := sha256.Sum256(r.pkg)
	m.Package = manifest.File{Name: "DocScan-windows-x64.zip", Size: int64(len(r.pkg)), SHA256: hex.EncodeToString(h[:])}
	r.data, _ = json.MarshalIndent(m, "", "  ")
	s, err := manifest.Sign(r.data, seed)
	if err != nil {
		t.Fatal(err)
	}
	r.sig = []byte(s)
	return r
}

func zipOf(files map[string][]byte) []byte {
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for n, c := range files {
		o, _ := w.Create(n)
		o.Write(c)
	}
	w.Close()
	return b.Bytes()
}

func serve(r *release) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, q *http.Request) {
		switch filepath.Base(q.URL.Path) {
		case "manifest.json":
			w.Write(r.data)
		case "manifest.sig":
			w.Write(r.sig)
		case "DocScan-windows-x64.zip":
			if r.tamperAfter {
				f := map[string][]byte{}
				for k, v := range r.files {
					f[k] = v
				}
				f["bin/yara64.exe"] = []byte("evil")
				w.Write(zipOf(f))
				return
			}
			w.Write(r.pkg)
		default:
			http.NotFound(w, q)
		}
	}))
}

type env struct {
	u        *Updater
	launched []string
	// що «інсталятор» зробить: ok — VERSION.txt з теки пакета в InstallDir і ok:true
	installOK map[string]bool
}

func newEnv(t *testing.T, mirror string, installed string) (*env, string) {
	p, priv, _ := ed25519.GenerateKey(rand.Reader)
	seed := base64.StdEncoding.EncodeToString(priv.Seed())
	dir := t.TempDir()
	e := &env{installOK: map[string]bool{}}
	inst := filepath.Join(dir, "Program Files", "DocScan")
	os.MkdirAll(inst, 0o755)
	if installed != "" {
		os.WriteFile(filepath.Join(inst, "VERSION.txt"), []byte("DocScan "+installed+" (build x)\r\n"), 0o644)
	}
	cfg := &Config{Mode: "mirror", CheckEveryHours: 6, GitHub: GitHub{Repo: DefaultRepo}, Mirror: Mirror{URL: mirror},
		Marker: Marker{File: filepath.Join(dir, "data", "update", "update.json")}}
	e.u = &Updater{cfg: cfg, dataDir: filepath.Join(dir, "data"), installDir: inst,
		keys: []string{"ed25519:" + base64.StdEncoding.EncodeToString(p)}, log: &logger{file: filepath.Join(dir, "data", "results", "updater.log")},
		host: "PC", http: http.DefaultClient, lastErr: map[string]time.Time{}}
	e.u.launch = func(pkgDir, resultFile, logFile string) error {
		v := filepath.Base(pkgDir)
		e.launched = append(e.launched, v)
		res := InstallResult{OK: e.installOK[v], Version: v}
		if res.OK {
			b, _ := os.ReadFile(filepath.Join(pkgDir, "VERSION.txt"))
			os.WriteFile(filepath.Join(inst, "VERSION.txt"), b, 0o644)
		} else {
			res.Error = "the watcher did not start"
		}
		b, _ := json.Marshal(res)
		return os.WriteFile(resultFile, b, 0o644)
	}
	return e, seed
}

func (e *env) records(t *testing.T) []RecordUpdate {
	b, _ := os.ReadFile(filepath.Join(e.u.dataDir, "results", "docscan-updates.json"))
	var out []RecordUpdate
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		if l == "" {
			continue
		}
		var r Record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatal(err)
		}
		out = append(out, r.Update)
	}
	return out
}

func TestUpdateSuccess(t *testing.T) {
	srv := serve(nil)
	defer srv.Close()
	e, seed := newEnv(t, srv.URL, "v1.0.3")
	rel := makeRelease(t, seed, "v1.0.4")
	srv.Config.Handler = serve(rel).Config.Handler
	e.installOK["v1.0.4"] = true

	o := e.u.check(&Request{}, false, time.Now())
	if o.Status != "started" || o.To != "v1.0.4" {
		t.Fatalf("check: %+v", o)
	}
	if !exists(filepath.Join(e.u.pkgDir("v1.0.4"), "bin", "yara64.exe")) {
		t.Fatal("package not unpacked")
	}
	e.u.handleState(time.Now())
	if e.u.installed() != "v1.0.4" || e.u.busy() {
		t.Fatalf("installed %s busy %v", e.u.installed(), e.u.busy())
	}
	r := e.records(t)
	if len(r) != 1 || r[0].Status != "success" || r[0].From != "v1.0.3" || r[0].To != "v1.0.4" {
		t.Fatalf("records: %+v", r)
	}
	// той самий реліз ще раз — нічого не робити
	if o := e.u.check(&Request{}, false, time.Now()); o.Status != "current" {
		t.Fatalf("second check: %+v", o)
	}
}

func TestUpdateRollback(t *testing.T) {
	srv := serve(nil)
	defer srv.Close()
	e, seed := newEnv(t, srv.URL, "v1.0.3")
	srv.Config.Handler = serve(makeRelease(t, seed, "v1.0.4")).Config.Handler
	// попередній пакет є (його лишило попереднє оновлення / інсталятор)
	prev := e.u.pkgDir("v1.0.3")
	os.MkdirAll(prev, 0o755)
	os.WriteFile(filepath.Join(prev, "install.ps1"), []byte("#"), 0o644)
	os.WriteFile(filepath.Join(prev, "VERSION.txt"), []byte("DocScan v1.0.3 (build x)\r\n"), 0o644)
	e.installOK["v1.0.3"] = true // v1.0.4 — не встановлюється

	if o := e.u.check(&Request{}, false, time.Now()); o.Status != "started" {
		t.Fatalf("check: %+v", o)
	}
	e.u.handleState(time.Now()) // install failed -> rollback started
	e.u.handleState(time.Now()) // rollback result
	if strings.Join(e.launched, ",") != "v1.0.4,v1.0.3" {
		t.Fatalf("launched: %v", e.launched)
	}
	r := e.records(t)
	if len(r) != 1 || r[0].Status != "rollback" || !strings.Contains(r[0].Message, "did not start") {
		t.Fatalf("records: %+v", r)
	}
	// невдала версія не повторюється періодичною перевіркою...
	if o := e.u.check(&Request{}, false, time.Now()); o.Status != "current" || !strings.Contains(o.Message, "failed") {
		t.Fatalf("retry: %+v", o)
	}
	// ...а маркер — повторює
	if o := e.u.check(&Request{Version: "v1.0.4"}, true, time.Now()); o.Status != "started" {
		t.Fatalf("marker retry: %+v", o)
	}
}

func TestUpdateRejects(t *testing.T) {
	srv := serve(nil)
	defer srv.Close()
	e, seed := newEnv(t, srv.URL, "v1.0.3")

	// чужий ключ
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	srv.Config.Handler = serve(makeRelease(t, base64.StdEncoding.EncodeToString(other.Seed()), "v1.0.4")).Config.Handler
	if o := e.u.check(&Request{}, false, time.Now()); o.Status != "error" || !strings.Contains(o.Message, "signature") {
		t.Fatalf("foreign key: %+v", o)
	}
	// підмінений файл у пакеті (пакет не збігається з маніфестом)
	rel := makeRelease(t, seed, "v1.0.4")
	rel.tamperAfter = true
	srv.Config.Handler = serve(rel).Config.Handler
	if o := e.u.check(&Request{}, false, time.Now()); o.Status != "error" || e.u.busy() || exists(e.u.pkgDir("v1.0.4")) {
		t.Fatalf("tampered: %+v", o)
	}
	// старіша версія — ніколи
	srv.Config.Handler = serve(makeRelease(t, seed, "v1.0.2")).Config.Handler
	if o := e.u.check(&Request{}, false, time.Now()); o.Status != "current" || len(e.launched) != 0 {
		t.Fatalf("downgrade: %+v", o)
	}
	// маркер просить іншу версію / інший маніфест
	srv.Config.Handler = serve(makeRelease(t, seed, "v1.0.5")).Config.Handler
	if o := e.u.check(&Request{Version: "v1.0.6"}, true, time.Now()); o.Status != "error" {
		t.Fatalf("version mismatch: %+v", o)
	}
	if o := e.u.check(&Request{SHA256: strings.Repeat("0", 64)}, true, time.Now()); o.Status != "error" {
		t.Fatalf("sha mismatch: %+v", o)
	}
	// поза вікном періодична перевірка лише чекає
	e.u.cfg.Window = "02:00-03:00"
	noon := time.Date(2026, 11, 19, 12, 0, 0, 0, time.Local)
	if o := e.u.check(&Request{}, false, noon); o.Status != "waiting" {
		t.Fatalf("window: %+v", o)
	}
}

func TestMarkerAndConfig(t *testing.T) {
	ok := []string{`{}`, `{"version":"v1.2.3","source":"https://u.local/ds","sha256":"` + strings.Repeat("a", 64) + `","request_id":"wazuh-42"}`,
		`{"source":"\\\\srv\\share\\docscan"}`, `{"source":"mirror"}`, "\xef\xbb\xbf{\"version\":\"v1.0.0\"}"}
	for _, s := range ok {
		if _, err := parseMarker([]byte(s)); err != nil {
			t.Fatalf("%s: %v", s, err)
		}
	}
	bad := []string{`{"version":"1.2"}`, `{"source":"ftp://x"}`, `{"sha256":"xyz"}`, `{"request_id":"a b"}`, `not json`}
	for _, s := range bad {
		if _, err := parseMarker([]byte(s)); err == nil {
			t.Fatalf("%s accepted", s)
		}
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "updater.json")
	os.WriteFile(p, []byte(`{"mode":"mirror"}`), 0o644)
	if _, err := loadConfig(p, dir); err == nil {
		t.Fatal("mirror without url accepted")
	}
	os.WriteFile(p, []byte("\xef\xbb\xbf"+`{"mode":"marker","window":"22:00-06:00"}`), 0o644) // з BOM, як пише PowerShell
	c, err := loadConfig(p, dir)
	if err != nil || c.GitHub.Repo != DefaultRepo || c.CheckEveryHours != 6 {
		t.Fatalf("defaults: %+v %v", c, err)
	}
	if !c.inWindow(time.Date(2026, 1, 1, 23, 0, 0, 0, time.Local)) || c.inWindow(time.Date(2026, 1, 1, 12, 0, 0, 0, time.Local)) {
		t.Fatal("window over midnight")
	}
}

// -CheckConfig (the web interface checks updater.json with it before replacing the file)
func TestCheckConfigFile(t *testing.T) {
	dir := t.TempDir()
	key := "ed25519:2vfxMxxGiMm8CVAnXqC173tSP3FKFOS2tMIn8YBTM5k="
	for name, c := range map[string]struct {
		json string
		ok   bool
	}{
		"good":          {`{"mode":"mirror","mirror":{"url":"https://example.org/r"},"lists":{"url":"https://example.org/l","public_keys":["` + key + `"]},"extra_public_keys":["` + key + `"]}`, true},
		"bom":           {"\ufeff" + `{"mode":"github"}`, true},
		"unknown field": {`{"mode":"github","mirorr":{"url":"x"}}`, false},
		"bad mode":      {`{"mode":"sometimes"}`, false},
		"mirror no url": {`{"mode":"mirror"}`, false},
		"lists no key":  {`{"mode":"off","lists":{"url":"https://example.org/l"}}`, false},
		"bad key":       {`{"mode":"off","extra_public_keys":["ed25519:abc"]}`, false},
		"bad window":    {`{"mode":"github","window":"night"}`, false},
		"not json":      {`mode = github`, false},
	} {
		p := filepath.Join(dir, "u.json")
		os.WriteFile(p, []byte(c.json), 0o644)
		if err := checkConfigFile(p, dir); (err == nil) != c.ok {
			t.Errorf("%s: ok=%v, err=%v", name, c.ok, err)
		}
	}
	if checkConfigFile(filepath.Join(dir, "missing.json"), dir) == nil {
		t.Error("a missing file must be an error")
	}
}
