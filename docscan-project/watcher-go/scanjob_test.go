//go:build !windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"docscan/watcher/drives"
)

// fake yara64: "EVIL" in the file -> a vendor rule matches (general file -> HIGH), otherwise clean
const fakeYara = `#!/bin/sh
for f; do :; done
echo "$f" >> "$(dirname "$0")/scanned.txt"
grep -q SLOW "$f" 2>/dev/null && sleep 0.2
if grep -q EVIL "$f" 2>/dev/null; then
  echo '{"ftype":"pe","verdict":"INFO","findings":[],"yara_file_matches":["Test_Evil"]}'
else
  echo '{"ftype":"pe","verdict":"INFO","findings":[]}'
fi
`

type scanEnv struct {
	t     *testing.T
	root  string
	out   string
	scan  string
	stop  chan os.Signal
	done  chan int
	yaraN func() int
}

func newScanEnv(t *testing.T) *scanEnv {
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	os.MkdirAll(bin, 0o755)
	yara := filepath.Join(bin, "yara64")
	os.WriteFile(yara, []byte(fakeYara), 0o755)
	rules := filepath.Join(root, "rules.yar")
	os.WriteFile(rules, []byte("rule x { condition: false }"), 0o644)
	users := filepath.Join(root, "Users")
	os.MkdirAll(users, 0o755)
	out := filepath.Join(root, "data", "results")
	drivePollEvery = 200 * time.Millisecond
	drives.SetFake([]drives.Drive{{Root: "/", Kind: "fixed"}})
	t.Cleanup(func() { drives.SetFake(nil) })
	c, err := parseConfig([]string{"-WatchPath", users, "-Yara", yara, "-Yarac", filepath.Join(bin, "none"), "-Rules", rules,
		"-OutDir", out, "-Workers", "2", "-SettleSeconds", "0"})
	if err != nil {
		t.Fatal(err)
	}
	e := &scanEnv{t: t, root: root, out: out, scan: filepath.Join(root, "data", "scan"), stop: make(chan os.Signal, 1), done: make(chan int, 1)}
	e.yaraN = func() int {
		b, _ := os.ReadFile(filepath.Join(bin, "scanned.txt"))
		return strings.Count(string(b), "\n")
	}
	go func() { e.done <- start(c, e.stop) }()
	t.Cleanup(func() {
		e.stop <- syscall.SIGTERM
		select {
		case <-e.done:
		case <-time.After(10 * time.Second):
			t.Error("watcher did not stop")
		}
	})
	e.waitFor("watcher started", func() bool { return exists(filepath.Join(e.scan, "status.json")) })
	return e
}

func (e *scanEnv) waitFor(what string, ok func() bool) {
	e.t.Helper()
	for end := time.Now().Add(30 * time.Second); time.Now().Before(end); time.Sleep(100 * time.Millisecond) {
		if ok() {
			return
		}
	}
	b, _ := os.ReadFile(filepath.Join(e.out, "watcher.log"))
	e.t.Fatalf("timeout: %s\nwatcher.log:\n%s", what, b)
}

func (e *scanEnv) history(id string) *scanRun {
	for _, h := range readScanHistory(e.scan) {
		if h.ID == id {
			return &h
		}
	}
	return nil
}

func (e *scanEnv) run(q scanReq) scanRun {
	e.t.Helper()
	id, err := WriteScanRequest(e.scan, q)
	if err != nil {
		e.t.Fatal(err)
	}
	var h *scanRun
	e.waitFor("scan "+id+" in history", func() bool { h = e.history(id); return h != nil })
	return *h
}

func (e *scanEnv) records() []Record {
	b, _ := os.ReadFile(filepath.Join(e.out, "docscan-results.json"))
	var rs []Record
	for _, l := range bytes.Split(b, []byte("\n")) {
		var r Record
		if json.Unmarshal(l, &r) == nil {
			rs = append(rs, r)
		}
	}
	return rs
}

func mkFiles(t *testing.T, base string, files map[string]string) {
	for f, body := range files {
		p := filepath.Join(base, filepath.FromSlash(f))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// scan of a path: only scannable extensions, clean files only counted, threats written (PathScan + id);
// a second scan of the same files takes the clean ones from the cache
func TestScanPathAndCache(t *testing.T) {
	e := newScanEnv(t)
	dir := filepath.Join(e.root, "stick")
	mkFiles(t, dir, map[string]string{
		"a.exe": "clean a", "b.exe": "EVIL b", "report.docx": "clean doc", "notes.txt": "EVIL (not a scanned type)",
		"sub/deep/c.ps1": "EVIL c",
	})
	r := e.run(scanReq{Kind: "path", Paths: []string{dir}, By: "test"})
	if r.State != "done" || r.Found != 4 || r.Scanned != 4 || r.Hits != 2 || r.Cached != 0 || r.Errors != 0 {
		t.Fatalf("first scan: %+v", r)
	}
	var hits []string
	for _, rec := range e.records() {
		if rec.Scan == r.ID {
			if rec.Event != "PathScan" || rec.Verdict != "HIGH" {
				t.Errorf("record %+v", rec)
			}
			hits = append(hits, rec.DocFile.Name)
		}
	}
	if len(hits) != 2 {
		t.Fatalf("records for Wazuh: %v (want only the 2 threats)", hits)
	}
	n := e.yaraN()
	r2 := e.run(scanReq{Kind: "path", Paths: []string{dir}, By: "test"})
	if r2.Cached != 2 || r2.Hits != 2 || r2.Scanned != 2 {
		t.Fatalf("second scan: %+v", r2)
	}
	if got := e.yaraN() - n; got != 2 {
		t.Fatalf("second scan ran yara %d times, want 2 (clean files from the cache)", got)
	}
	// one file of any extension
	r3 := e.run(scanReq{Kind: "path", Paths: []string{filepath.Join(dir, "notes.txt")}, By: "test"})
	if r3.Found != 1 || r3.Hits != 1 {
		t.Fatalf("single file: %+v", r3)
	}
	// a path that does not exist
	r4 := e.run(scanReq{Kind: "path", Paths: []string{filepath.Join(dir, "nope")}, By: "test"})
	if r4.State != "failed" || !strings.Contains(r4.Note, "немає доступу") {
		t.Fatalf("missing path: %+v", r4)
	}
}

// a new removable medium is scanned on its own (usb, by auto); with usb_scan off it is not
func TestUSBAutoScan(t *testing.T) {
	e := newScanEnv(t)
	stick := filepath.Join(e.root, "usb1")
	mkFiles(t, stick, map[string]string{"setup.exe": "EVIL", "doc.docx": "clean"})
	time.Sleep(600 * time.Millisecond) // first poll: the media already present are not scanned
	drives.SetFake([]drives.Drive{{Root: "/", Kind: "fixed"}, {Root: stick, Kind: "usb", Label: "STICK", Serial: 7}})
	var h scanRun
	e.waitFor("usb scan", func() bool {
		for _, x := range readScanHistory(e.scan) {
			if x.Kind == "usb" {
				h = x
				return true
			}
		}
		return false
	})
	if h.By != "auto" || h.Found != 2 || h.Hits != 1 || h.Detect {
		t.Fatalf("usb scan: %+v", h)
	}
	ok := false
	for _, rec := range e.records() {
		if rec.Event == "USBScan" && rec.DocFile.Name == "setup.exe" {
			ok = true
		}
	}
	if !ok {
		t.Fatal("no USBScan record for setup.exe")
	}

	// usb_scan off -> another stick is only logged
	os.WriteFile(filepath.Join(e.root, "data", "settings.json"), []byte(`{"usb_scan": "off"}`), 0o644)
	e.waitFor("status usb_mode off", func() bool { st := readScanStatus(e.scan); return st != nil && st.USBMode == "off" })
	stick2 := filepath.Join(e.root, "usb2")
	mkFiles(t, stick2, map[string]string{"x.exe": "EVIL"})
	drives.SetFake([]drives.Drive{{Root: "/", Kind: "fixed"}, {Root: stick2, Kind: "usb", Serial: 8}})
	e.waitFor("log: scan off", func() bool {
		b, _ := os.ReadFile(filepath.Join(e.out, "watcher.log"))
		return bytes.Contains(b, []byte("automatic scan is off"))
	})
	for _, x := range readScanHistory(e.scan) {
		if x.Kind == "usb" && x.Paths[0] == stick2 {
			t.Fatalf("usb_scan off, but scanned: %+v", x)
		}
	}

	// usb_scan detect -> report only
	os.WriteFile(filepath.Join(e.root, "data", "settings.json"), []byte(`{"usb_scan": "detect"}`), 0o644)
	e.waitFor("status usb_mode detect", func() bool { st := readScanStatus(e.scan); return st != nil && st.USBMode == "detect" })
	stick3 := filepath.Join(e.root, "usb3")
	mkFiles(t, stick3, map[string]string{"y.exe": "EVIL"})
	drives.SetFake([]drives.Drive{{Root: "/", Kind: "fixed"}, {Root: stick3, Kind: "usb", Serial: 9}})
	e.waitFor("detect usb scan", func() bool {
		for _, x := range readScanHistory(e.scan) {
			if x.Kind == "usb" && x.Paths[0] == stick3 {
				h = x
				return true
			}
		}
		return false
	})
	if !h.Detect || h.Hits != 1 {
		t.Fatalf("detect usb scan: %+v", h)
	}
}

// stop: the queued files of the scan are dropped, the scan goes to history as cancelled
func TestScanCancel(t *testing.T) {
	e := newScanEnv(t)
	dir := filepath.Join(e.root, "big")
	files := map[string]string{}
	for i := 0; i < 60; i++ {
		files[filepath.Join("d", strings.Repeat("x", i%7+1), time.Duration(i).String()+".exe")] = "SLOW " + time.Duration(i).String()
	}
	mkFiles(t, dir, files)
	id, _ := WriteScanRequest(e.scan, scanReq{Kind: "path", Paths: []string{dir}, By: "test"})
	e.waitFor("running", func() bool {
		st := readScanStatus(e.scan)
		return st != nil && len(st.Active) == 1 && st.Active[0].Scanned >= 1
	})
	os.WriteFile(filepath.Join(e.scan, "cancel-"+id), nil, 0o644)
	var h *scanRun
	e.waitFor("cancelled", func() bool { h = e.history(id); return h != nil })
	if h.State != "cancelled" || h.Scanned >= 60 {
		t.Fatalf("cancel: %+v", h)
	}
}

func TestScanClientRequestAndStatus(t *testing.T) {
	out := filepath.Join(t.TempDir(), "results")
	c, err := parseConfig([]string{"-OutDir", out, "-ScanPath", "/tmp/a,/tmp/b", "-ScanDetect"})
	if err != nil || !c.ScanClient() {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if code := scanClient(c, &b); code != 0 {
		t.Fatalf("code %d: %s", code, b.String())
	}
	ents, _ := filepath.Glob(filepath.Join(filepath.Dir(out), "scan", "request-*.json"))
	if len(ents) != 1 {
		t.Fatalf("requests: %v", ents)
	}
	var q scanReq
	raw, _ := os.ReadFile(ents[0])
	json.Unmarshal(raw, &q)
	if q.Kind != "path" || len(q.Paths) != 2 || !q.Detect || !strings.HasPrefix(q.By, "cli") {
		t.Fatalf("request %+v", q)
	}
	c2, _ := parseConfig([]string{"-OutDir", out, "-ScanCancel", "../evil"})
	if scanClient(c2, &b) != 2 {
		t.Fatal("bad id accepted")
	}
	c3, _ := parseConfig([]string{"-OutDir", out, "-ScanStatus"})
	b.Reset()
	scanClient(c3, &b)
	if !strings.Contains(b.String(), "no status yet") {
		t.Fatal(b.String())
	}
}

// a file that cannot be opened: ERROR at once (no 60 s wait), counted, not written for Wazuh
func TestScanUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	e := newScanEnv(t)
	dir := filepath.Join(e.root, "locked")
	mkFiles(t, dir, map[string]string{"held.exe": "x", "ok.exe": "fine"})
	os.Chmod(filepath.Join(dir, "held.exe"), 0)
	start := time.Now()
	r := e.run(scanReq{Kind: "path", Paths: []string{dir}, By: "test"})
	if r.Errors != 1 || r.Scanned != 1 || time.Since(start) > 15*time.Second {
		t.Fatalf("unreadable: %+v in %s", r, time.Since(start))
	}
	for _, rec := range e.records() {
		if rec.Scan == r.ID {
			t.Fatalf("written for Wazuh: %+v", rec)
		}
	}
}

// scan of documents on the local disks: only documents, system / program folders not walked; no scan of a whole
// local disk as a path; a file in a program folder (path scan) is only reported - never quarantined
func TestScanDocsAndProgramFolders(t *testing.T) {
	e := newScanEnv(t)
	disk := filepath.Join(e.root, "disk")
	mkFiles(t, disk, map[string]string{
		"home/a.docx": "EVIL a", "home/b.docx": "clean b", "home/prog.exe": "EVIL exe (not a document)",
		"Library/t.docx": "EVIL lib", "Tool.app/Contents/t.docx": "EVIL app", "Tool.app/Contents/tool.exe": "EVIL tool",
	})
	drives.SetFake([]drives.Drive{{Root: disk + "/", Kind: "fixed", System: true}})
	r := e.run(scanReq{Kind: "docs", By: "test"})
	if r.State != "done" || r.Found != 2 || r.Hits != 1 {
		t.Fatalf("docs scan: %+v", r)
	}
	// chosen disks: a folder is not a disk - skipped
	if r := e.run(scanReq{Kind: "docs", Paths: []string{filepath.Join(disk, "home")}, By: "test"}); r.State != "failed" || !strings.Contains(r.Note, "не локальний диск") {
		t.Fatalf("docs scan of a folder: %+v", r)
	}
	for _, rec := range e.records() {
		if rec.Scan == r.ID && (rec.Event != "DocsScan" || rec.DocFile.Name != "a.docx") {
			t.Errorf("record %+v", rec)
		}
	}
	// a whole local disk as a path: refused
	if r := e.run(scanReq{Kind: "path", Paths: []string{disk}, By: "test"}); r.State != "failed" || !strings.Contains(r.Note, "цілий системний диск") {
		t.Fatalf("whole disk as a path: %+v", r)
	}
	// a program folder asked by hand: scanned, but only reported
	tool := filepath.Join(disk, "Tool.app", "Contents")
	r = e.run(scanReq{Kind: "path", Paths: []string{tool}, By: "test"})
	if r.Hits != 2 || !strings.Contains(r.Note, "лише повідомлення") {
		t.Fatalf("program folder: %+v", r)
	}
	for _, f := range []string{"t.docx", "tool.exe"} {
		if !exists(filepath.Join(tool, f)) {
			t.Errorf("%s removed from a program folder", f)
		}
	}
	for _, rec := range e.records() {
		if rec.Scan == r.ID && rec.Disarm != "" {
			t.Errorf("program folder file changed: %s %s", rec.DocFile.Name, rec.Disarm)
		}
	}
}

// delete mode: HIGH files are deleted (no copy in the quarantine), clean ones stay; in a program folder - report only
func TestScanDelete(t *testing.T) {
	e := newScanEnv(t)
	dir := filepath.Join(e.root, "stick")
	mkFiles(t, dir, map[string]string{"evil.exe": "EVIL del", "ok.exe": "clean del", "Tool.app/x.exe": "EVIL in app"})
	r := e.run(scanReq{Kind: "path", Paths: []string{dir}, By: "test", Delete: true})
	if r.State != "done" || !r.Delete || r.Deleted != 1 || r.Hits != 2 {
		t.Fatalf("delete scan: %+v", r)
	}
	if exists(filepath.Join(dir, "evil.exe")) || !exists(filepath.Join(dir, "ok.exe")) || !exists(filepath.Join(dir, "Tool.app", "x.exe")) {
		t.Fatal("wrong files deleted")
	}
	if m, _ := filepath.Glob(filepath.Join(e.root, "data", "quarantine", "evil.exe*")); len(m) != 0 {
		t.Fatalf("a copy kept in the quarantine: %v", m)
	}
	got := map[string]string{}
	for _, rec := range e.records() {
		if rec.Scan == r.ID {
			got[rec.DocFile.Name] = rec.Disarm
		}
	}
	if got["evil.exe"] != "deleted" || got["x.exe"] != "" {
		t.Fatalf("records: %v", got)
	}
	// detect wins over delete
	mkFiles(t, dir, map[string]string{"evil2.exe": "EVIL del 2"})
	if r := e.run(scanReq{Kind: "path", Paths: []string{dir}, By: "test", Delete: true, Detect: true}); r.Delete || r.Deleted != 0 || !exists(filepath.Join(dir, "evil2.exe")) {
		t.Fatalf("detect+delete: %+v", r)
	}
}

// two scans of the same files at once: the second waits for the first one's results and counts them (not skipped);
// a stopped scan hands its queued files over to the one waiting for them
func TestScanOverlap(t *testing.T) {
	e := newScanEnv(t)
	dir := filepath.Join(e.root, "stick")
	files := map[string]string{"evil.exe": "EVIL SLOW overlap"}
	for i := 0; i < 6; i++ {
		files[fmt.Sprintf("f%d.exe", i)] = fmt.Sprintf("SLOW overlap %d", i)
	}
	mkFiles(t, dir, files)
	id1, _ := WriteScanRequest(e.scan, scanReq{Kind: "path", Paths: []string{dir}, By: "a", Detect: true})
	id2, _ := WriteScanRequest(e.scan, scanReq{Kind: "usb", Paths: []string{dir}, By: "b", Detect: true})
	var h1, h2 *scanRun
	e.waitFor("both scans done", func() bool { h1, h2 = e.history(id1), e.history(id2); return h1 != nil && h2 != nil })
	for _, h := range []*scanRun{h1, h2} {
		if h.State != "done" || h.Found != 7 || h.Scanned != 7 || h.Hits != 1 || h.Skipped != 0 {
			t.Errorf("scan %s: %+v", h.ID, *h)
		}
	}
	if n := e.yaraN(); n > 8 { // each clean file once (the cache); the threat may run twice (it is not cached)
		t.Errorf("yara ran %d times, want 7..8", n)
	}
	// stop the first: the second still gets every file
	mkFiles(t, dir, map[string]string{"g.exe": "SLOW overlap g", "h.exe": "SLOW overlap h"})
	id3, _ := WriteScanRequest(e.scan, scanReq{Kind: "path", Paths: []string{dir}, By: "a", Detect: true})
	id4, _ := WriteScanRequest(e.scan, scanReq{Kind: "usb", Paths: []string{dir}, By: "b", Detect: true})
	e.waitFor("scan 3 running", func() bool { st := readScanStatus(e.scan); return st != nil && len(st.Active) == 2 })
	os.WriteFile(filepath.Join(e.scan, "cancel-"+id3), nil, 0o644)
	var h4 *scanRun
	e.waitFor("scan 4 done", func() bool { h4 = e.history(id4); return h4 != nil })
	if h4.State != "done" || h4.Found != 9 || h4.Scanned+h4.Cached != 9 || h4.Skipped != 0 {
		t.Errorf("scan 4 after scan 3 stopped: %+v", *h4)
	}
}
