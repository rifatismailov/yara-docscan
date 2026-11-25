package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"docscan/services/pkg/orglists"
)

// the sweep walks only the folders under the black list masks and queues the files that match them
func TestSweepQueuesExistingBlacklistedFiles(t *testing.T) {
	root := t.TempDir()
	users := filepath.Join(root, "Users")
	files := []string{
		`anna/Downloads/AnyDesk.exe`, // top level of Downloads ("**\" = zero folders)
		`anna/Downloads/x/tool.ps1`,
		`anna/Downloads/report.docx`, // a document: no mask
		`anna/Desktop/pike.exe`,      // white list
		`anna/Desktop/game.exe`,
		`anna/AppData/Local/app.exe`, // not under a mask: the folder is not even walked
		`bob/Documents/setup.msi`,
	}
	for _, f := range files {
		p := filepath.Join(users, filepath.FromSlash(f))
		os.MkdirAll(filepath.Dir(p), 0o755)
		os.WriteFile(p, []byte("x"), 0o644)
	}
	u := strings.ReplaceAll(users, `/`, `\`)
	black := &orglists.List{Entries: []orglists.Entry{
		{Path: u + `\*\Downloads\**\*.exe`}, {Path: u + `\*\Downloads\**\*.ps1`},
		{Path: u + `\*\Desktop\**\*.exe`}, {Path: u + `\*\Documents\**\*.msi`},
	}}
	white := &orglists.List{Entries: []orglists.Entry{{Path: u + `\**\pike.exe`}}}
	out := t.TempDir()
	w := &Watcher{c: &Config{WatchPath: []string{users}, OutDir: out, BackupDir: out, MacroDir: out, CriticalOut: filepath.Join(out, "c", "q.json")},
		docSet: map[string]bool{".docx": true}, genSet: map[string]bool{".exe": true, ".ps1": true, ".msi": true}}
	co := &coordinator{w: w, rescanCh: make(chan fsEvent, 100), sweepN: make(chan int, 1)}
	co.sweep(white, black)
	n := <-co.sweepN
	close(co.rescanCh)
	var got []string
	for e := range co.rescanCh {
		if e.evt != "ListSweep" {
			t.Errorf("event %q", e.evt)
		}
		r, _ := filepath.Rel(users, e.path)
		got = append(got, filepath.ToSlash(r))
	}
	sort.Strings(got)
	want := []string{`anna/Desktop/game.exe`, `anna/Downloads/AnyDesk.exe`, `anna/Downloads/x/tool.ps1`, `bob/Documents/setup.msi`}
	if strings.Join(got, ",") != strings.Join(want, ",") || n != len(want) {
		t.Fatalf("queued %d %v, want %v", n, got, want)
	}
}
