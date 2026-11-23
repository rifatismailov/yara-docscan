package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// a signed-in session (password already changed) for the page tests
func signedIn(t *testing.T) (*server, paths, func(method, path string, form url.Values) *httptest.ResponseRecorder) {
	p := testPaths(t)
	os.MkdirAll(filepath.Join(p.data, "update"), 0o755)
	h, _ := hashPassword("a long test password")
	writeAuth(p, &authFile{User: AdminUser, Hash: h})
	s, err := newServer(p, "127.0.0.1:8741", newLogger(p.webLog()))
	if err != nil {
		t.Fatal(err)
	}
	tok := s.ss.add(false, time.Now())
	csrf := s.ss.get(tok, time.Now()).csrf
	return s, p, func(method, path string, form url.Values) *httptest.ResponseRecorder {
		var r *http.Request
		if form != nil {
			form.Set("csrf", csrf)
			r = httptest.NewRequest(method, "https://127.0.0.1:8741"+path, strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		} else {
			r = httptest.NewRequest(method, "https://127.0.0.1:8741"+path, nil)
		}
		r.AddCookie(&http.Cookie{Name: sessionCookie, Value: tok})
		w := httptest.NewRecorder()
		s.ServeHTTP(w, r)
		return w
	}
}

// fakeLists — не справжній токен списків: перевіряється, що веб ніде його не показує
const fakeLists = "TEST-ONLY-NOT-REAL"

func auditHas(t *testing.T, p paths, action string) string {
	b, _ := os.ReadFile(p.resultsLog())
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, `"action":"`+action+`"`) {
			return l
		}
	}
	t.Errorf("no audit record %s", action)
	return ""
}

func TestModeAndPause(t *testing.T) {
	_, p, do := signedIn(t)
	os.WriteFile(filepath.Join(p.data, "install.json"), []byte(`{"installed":"DocScan v1.0.8","params":{"DetectOnly":false,"WatchPath":["C:\\Users"],"Workers":0,"OssecDir":"x"}}`), 0o644)
	if w := do("GET", "/mode", nil); w.Code != 200 || !strings.Contains(w.Body.String(), `value="detect"`) {
		t.Fatalf("mode page %d", w.Code)
	}
	// detect-only; a relative folder is refused
	if w := do("POST", "/mode", url.Values{"mode": {"detect"}, "watch": {"Users"}, "workers": {"0"}}); !strings.Contains(w.Body.String(), "full path") {
		t.Fatal("relative folder accepted")
	}
	if w := do("POST", "/mode", url.Values{"mode": {"detect"}, "watch": {"C:\\Users\r\nD:\\Share"}, "workers": {"4"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("save mode: %d %s", w.Code, w.Body.String())
	}
	set, err := readSettings(p)
	if err != nil || set.DetectOnly == nil || !*set.DetectOnly || len(set.WatchPath) != 2 || *set.Workers != 4 {
		t.Fatalf("settings.json: %+v %v", set, err)
	}
	var ij map[string]map[string]any
	b, _ := os.ReadFile(filepath.Join(p.data, "install.json"))
	json.Unmarshal(b, &ij)
	if ij["params"]["DetectOnly"] != true || ij["params"]["OssecDir"] != "x" {
		t.Fatalf("install.json not synced (or other params lost): %v", ij["params"])
	}
	auditHas(t, p, "watcher-settings")
	// pause 1 h, then resume
	if w := do("POST", "/pause", url.Values{"for": {"1h"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("pause %d", w.Code)
	}
	set, _ = readSettings(p)
	if ps := pauseOf(set, time.Now()); !ps.On || ps.Manual || time.Until(ps.Until) < 50*time.Minute {
		t.Fatalf("pause: %+v", ps)
	}
	if !*set.DetectOnly || len(set.WatchPath) != 2 {
		t.Fatal("the pause must keep the other settings")
	}
	if w := do("GET", "/", nil); !strings.Contains(w.Body.String(), "ПАУЗІ") {
		t.Fatal("status page: no pause banner")
	}
	auditHas(t, p, "blacklist-paused")
	do("POST", "/pause", url.Values{"for": {"manual"}})
	set, _ = readSettings(p)
	if set.BlacklistPausedUntil != "manual" {
		t.Fatal("manual pause")
	}
	do("POST", "/pause", url.Values{"for": {"off"}})
	set, _ = readSettings(p)
	if set.BlacklistPausedUntil != "" || pauseOf(set, time.Now()).On {
		t.Fatal("resume")
	}
	auditHas(t, p, "blacklist-resumed")
}

func TestUpdates(t *testing.T) {
	s, p, do := signedIn(t)
	key := "ed25519:2vfxMxxGiMm8CVAnXqC173tSP3FKFOS2tMIn8YBTM5k="
	os.WriteFile(p.updaterJSON(), []byte(`{"mode":"github","check_every_hours":6,"github":{"repo":"rifatismailov/yara-docscan"},"marker":{"file":"C:\\x\\update.json"},"lists":{"url":"","token":`+strconv.Quote(fakeLists)+`}}`), 0o600)
	var checked string
	s.checkCfg = func(f string) error {
		b, _ := os.ReadFile(f)
		checked = string(b)
		if strings.Contains(checked, `"mode": "sometimes"`) {
			return errors.New(`mode "sometimes" (github | mirror | marker | off)`)
		}
		return nil
	}
	page := do("GET", "/updates", nil).Body.String()
	if strings.Contains(page, fakeLists) {
		t.Fatal("the token must never reach the page")
	}
	form := url.Values{"mode": {"mirror"}, "mirror": {"https://example.org/docscan"}, "every": {"6"}, "repo": {"rifatismailov/yara-docscan"},
		"rules_mirror": {"https://example.org/rules"}, "extra_keys": {key}, "lists_url": {"https://example.org/lists"}, "lists_keys": {key}, "lists_every": {"24"}}
	if w := do("POST", "/updates", form); w.Code != http.StatusSeeOther {
		t.Fatalf("save: %d %s", w.Code, w.Body.String())
	}
	var c updConfig
	b, _ := os.ReadFile(p.updaterJSON())
	json.Unmarshal(b, &c)
	if c.Mode != "mirror" || c.Rules.Mirror.URL != "https://example.org/rules" || c.Lists.Token != fakeLists || c.Marker.File != `C:\x\update.json` || len(c.ExtraPublicKeys) != 1 {
		t.Fatalf("updater.json: %+v", c)
	}
	if !fileExists(p.updaterJSON() + ".bak") {
		t.Fatal("no updater.json.bak")
	}
	a := auditHas(t, p, "updater-config")
	if !strings.Contains(a, "mode:") || strings.Contains(a, fakeLists) {
		t.Fatalf("audit: %s", a)
	}
	// refused by the updater -> nothing written, the form keeps what was typed
	form.Set("mode", "sometimes")
	w := do("POST", "/updates", form)
	if !strings.Contains(w.Body.String(), "refuses") || !strings.Contains(w.Body.String(), "https://example.org/rules") {
		t.Fatalf("refused config: %s", w.Body.String())
	}
	b2, _ := os.ReadFile(p.updaterJSON())
	if string(b2) != string(b) {
		t.Fatal("a refused config was written")
	}
	// token: cleared only on purpose
	form.Set("mode", "mirror")
	form.Set("lists_token_clear", "on")
	do("POST", "/updates", form)
	b, _ = os.ReadFile(p.updaterJSON())
	if strings.Contains(string(b), fakeLists) {
		t.Fatal("token not cleared")
	}
	// check now
	if w := do("POST", "/updates/check", url.Values{}); w.Code != http.StatusSeeOther || !fileExists(filepath.Join(p.data, "update", "check-now")) {
		t.Fatalf("check now: %d", w.Code)
	}
	auditHas(t, p, "update-check-now")
	if l, _ := os.ReadFile(p.webLog()); regexp.MustCompile(`template`).Match(l) {
		t.Fatalf("template error: %s", l)
	}
}
