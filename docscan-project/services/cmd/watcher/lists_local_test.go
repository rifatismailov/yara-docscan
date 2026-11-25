package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// the organisation bans exe on the desktop (mirror black list); a local exception (whitelist.local.json, the web
// interface) lets our own program run there; the record says where the entry came from
func TestLocalException(t *testing.T) {
	dir := t.TempDir()
	desk := filepath.Join(dir, "Desktop")
	os.MkdirAll(desk, 0o755)
	os.MkdirAll(filepath.Join(dir, "q"), 0o755)
	d := strings.ReplaceAll(desk, `/`, `\\`)
	black := filepath.Join(dir, "blacklist.json")
	white := filepath.Join(dir, "whitelist.json")
	os.WriteFile(black, []byte(`{"schema":1,"entries":[{"path":"`+d+`\\**.exe","comment":"no programs on the desktop"}]}`), 0o644)
	lg := &Logger{a: &appender{file: filepath.Join(dir, "watcher.log"), maxBytes: 1 << 20, keep: 1}}
	w := &Watcher{c: &Config{BackupDir: filepath.Join(dir, "q"), OutDir: dir}, log: lg}
	w.lists = newLists(white, black, lg)
	app := filepath.Join(desk, "OurApp.exe")
	other := filepath.Join(desk, "game.exe")
	os.WriteFile(app, []byte("ours"), 0o644)
	os.WriteFile(other, []byte("game"), 0o644)
	_, _, g0 := w.lists.generation()

	os.WriteFile(localPath(white), []byte(`{"schema":1,"entries":[{"path":"`+d+`\\OurApp.exe","comment":"own program","by":"admin"}]}`), 0o644)
	w.lists.mu.Lock()
	w.lists.checked = time.Time{} // re-read now (normally every 2 s)
	w.lists.mu.Unlock()
	r := &Record{}
	if !w.applyLists(r, app, "", &worker{}) || r.List.List != "white" || r.List.Source != "local" || r.Verdict != "INFO" {
		t.Fatalf("own program: %+v %+v", r, r.List)
	}
	r = &Record{}
	if !w.applyLists(r, other, "", &worker{}) || r.List.List != "black" || r.List.Source != "mirror" || r.Disarm != "quarantined" {
		t.Fatalf("other program: %+v %+v", r, r.List)
	}
	if _, err := os.Stat(app); err != nil {
		t.Fatal("the excepted program must stay")
	}
	if _, _, g1 := w.lists.generation(); g1 == g0 {
		t.Fatal("a local list change must start a sweep")
	}
}
