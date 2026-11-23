package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseSettings(t *testing.T) {
	if _, err := parseSettings([]byte(`{"detect_only":true,"blacklist_paused_until":"manual","watch_path":["C:\\Users"],"workers":4}`)); err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string]string{
		"unknown field": `{"detect_olny":true}`,
		"bad time":      `{"blacklist_paused_until":"tomorrow"}`,
		"workers":       `{"workers":500}`,
		"not json":      `detect_only=1`,
	} {
		if _, err := parseSettings([]byte(b)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	now := time.Now()
	s := Settings{BlacklistPausedUntil: now.Add(time.Hour).Format(time.RFC3339)}
	if !s.Paused(now) || s.Paused(now.Add(2*time.Hour)) {
		t.Fatal("pause until a time")
	}
	if !(&Settings{BlacklistPausedUntil: "manual"}).Paused(now.Add(1000 * time.Hour)) {
		t.Fatal("manual pause")
	}
}

// mode and pause change at once; a black list hit during the pause is reported ("paused"), not quarantined;
// the end of the pause starts a new sweep
func TestSettingsLive(t *testing.T) {
	dir := t.TempDir()
	set := filepath.Join(dir, "settings.json")
	black := filepath.Join(dir, "blacklist.json")
	inbox := filepath.Join(dir, "in")
	os.MkdirAll(inbox, 0o755)
	os.MkdirAll(filepath.Join(dir, "q"), 0o755)
	os.WriteFile(black, []byte(`{"schema":1,"entries":[{"path":"`+strings.ReplaceAll(inbox, `/`, `\\`)+`\\*.exe"}]}`), 0o644)
	lg := &Logger{a: &appender{file: filepath.Join(dir, "watcher.log"), maxBytes: 1 << 20, keep: 1}}
	w := &Watcher{c: &Config{Settings: set, OutDir: dir, BackupDir: filepath.Join(dir, "q")}, log: lg}
	w.lists = newLists("", black, lg)
	w.loadSettings()
	if w.noDisarm() {
		t.Fatal("no settings, no -NoDisarm: full mode")
	}
	_, _, g0 := w.lists.generation()

	// detect-only at once
	os.WriteFile(set, []byte(`{"detect_only":true}`), 0o644)
	w.reloadSettings(time.Now())
	if !w.noDisarm() {
		t.Fatal("detect_only not applied")
	}
	// full mode + pause for 1 s
	until := time.Now().Add(1500 * time.Millisecond).Truncate(time.Second).Add(time.Second)
	os.WriteFile(set, []byte(`{"detect_only":false,"blacklist_paused_until":"`+until.Format(time.RFC3339)+`","blacklist_paused_by":"admin"}`), 0o644)
	w.reloadSettings(time.Now())
	exe := filepath.Join(inbox, "AnyDesk.exe")
	os.WriteFile(exe, []byte("x"), 0o644)
	r := &Record{}
	if !w.applyLists(r, exe, "", &worker{}) || r.Verdict != "HIGH" || r.Disarm != "paused" || r.List.Paused == "" {
		t.Fatalf("paused hit: %+v %+v", r, r.List)
	}
	if _, err := os.Stat(exe); err != nil {
		t.Fatal("paused: the file must stay")
	}
	_, _, g1 := w.lists.generation()
	// the pause is over -> quarantine again and a new sweep
	w.reloadSettings(until.Add(time.Second))
	_, _, g2 := w.lists.generation()
	if !(g1 > g0 && g2 > g1) {
		t.Fatalf("generations %d %d %d: a change and the end of the pause must start a sweep", g0, g1, g2)
	}
	time.Sleep(time.Until(until.Add(100 * time.Millisecond)))
	r = &Record{}
	w.applyLists(r, exe, "", &worker{})
	if r.Disarm != "quarantined" {
		t.Fatalf("after the pause: %q %v", r.Disarm, r.Errors)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "watcher.log"))
	for _, s := range []string{"settings: mode detect-only", "black list PAUSED", "black list pause over"} {
		if !strings.Contains(string(b), s) {
			t.Errorf("watcher.log: no %q", s)
		}
	}
	// a broken file: the previous values stay
	os.WriteFile(set, []byte(`{"detect_only":`), 0o644)
	w.reloadSettings(time.Now())
	if w.noDisarm() {
		t.Fatal("a broken settings.json changed the mode")
	}
}
