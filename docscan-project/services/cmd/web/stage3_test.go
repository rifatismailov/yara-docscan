package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// an own program blocked on the desktop: "add an exception and restore" -> local white list + the file is back
func TestExceptionAndRestore(t *testing.T) {
	_, p, do := signedIn(t)
	desk := filepath.Join(p.data, "Users", "anna", "Desktop")
	os.MkdirAll(desk, 0o755)
	os.MkdirAll(p.quarantine(), 0o755)
	app := filepath.Join(desk, "OurApp.exe")
	body := []byte("our own program")
	h := sha256.Sum256(body)
	sha := hex.EncodeToString(h[:])
	os.WriteFile(filepath.Join(p.quarantine(), "OurApp.exe.0.docscan-bak"), body, 0o600)
	os.WriteFile(filepath.Join(p.quarantine(), "OurApp.exe.1.docscan-bak"), []byte("another file with this name"), 0o600)
	rec := `{"timestamp":"` + time.Now().Format("2006-01-02T15:04:05.000-07:00") + `","event":"ListSweep","verdict":"HIGH","disarm":"quarantined","docfile":{"path":` + jsonStr(app) + `,"name":"OurApp.exe","sha256":"` + sha + `"},"list":{"list":"black","source":"mirror","by":"path","comment":"no programs on the desktop"}}` + "\n"
	appendLine(p.resultsLog(), []byte(rec))

	det := do("GET", "/detections", nil).Body.String()
	m := regexp.MustCompile(`/record\?f=(\d+)&(?:amp;)?o=(\d+)`).FindStringSubmatch(det)
	if m == nil {
		t.Fatal("no record link")
	}
	if !strings.Contains(det, "black / path (mirror)") {
		t.Fatal("the list source is not shown")
	}
	page := do("GET", "/record?f="+m[1]+"&o="+m[2], nil).Body.String()
	if !strings.Contains(page, "Дозволити і повернути файл") {
		t.Fatal("record page: no exception button")
	}
	form := do("GET", "/exceptions?f="+m[1]+"&o="+m[2], nil).Body.String()
	if !strings.Contains(form, sha) || !strings.Contains(form, `name="restore" checked`) {
		t.Fatal("exception form not prefilled from the record")
	}
	// a relative path is refused by the same check as the watcher's: nothing written
	if w := do("POST", "/exceptions/add", url.Values{"kind": {"white"}, "path": {`Desktop\OurApp.exe`}, "comment": {"x"}}); !strings.Contains(w.Body.String(), "не збережено") {
		t.Fatalf("bad entry: %s", w.Body.String())
	}
	if fileExists(p.listFile("white", true)) {
		t.Fatal("a refused entry was written")
	}
	w := do("POST", "/exceptions/add", url.Values{"kind": {"white"}, "path": {app}, "sha": {sha}, "scope": {"exact"},
		"comment": {"own program"}, "restore": {"on"}, "f": {m[1]}, "o": {m[2]}})
	if w.Code != http.StatusSeeOther || !strings.Contains(w.Header().Get("Location"), url.QueryEscape("повернуто")) {
		t.Fatalf("add + restore: %d %s", w.Code, w.Header().Get("Location"))
	}
	if b, err := os.ReadFile(app); err != nil || string(b) != string(body) {
		t.Fatal("the file is not back")
	}
	if fileExists(filepath.Join(p.quarantine(), "OurApp.exe.0.docscan-bak")) || !fileExists(filepath.Join(p.quarantine(), "OurApp.exe.1.docscan-bak")) {
		t.Fatal("only the copy with the same sha256 must leave the quarantine")
	}
	l, err := readList(p.listFile("white", true), "white")
	if err != nil || len(l.Entries) != 1 || l.Entries[0].SHA256 != sha || l.Entries[0].By != "admin" {
		t.Fatalf("local white list: %+v %v", l, err)
	}
	auditHas(t, p, "local-white-added")
	auditHas(t, p, "restored")
	// restoring again: the place is taken -> refused, nothing overwritten
	if _, err := (&server{p: p}).restore(m[1], m[2]); err == nil {
		t.Fatal("restore over an existing file")
	}
	// remove the entry
	if w := do("POST", "/exceptions/remove", url.Values{"kind": {"white"}, "i": {"0"}}); w.Code != http.StatusSeeOther {
		t.Fatalf("remove: %d", w.Code)
	}
	l, _ = readList(p.listFile("white", true), "white")
	if len(l.Entries) != 0 {
		t.Fatal("entry not removed")
	}
	auditHas(t, p, "local-white-removed")
	if lg, _ := os.ReadFile(p.webLog()); strings.Contains(string(lg), "template") {
		t.Fatalf("template error: %s", lg)
	}
}

func jsonStr(s string) string {
	return `"` + strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `"`, `\"`) + `"`
}
