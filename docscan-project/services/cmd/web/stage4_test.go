package main

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestQuarantinePage(t *testing.T) {
	_, p, do := signedIn(t)
	os.MkdirAll(p.quarantine(), 0o755)
	dir := filepath.Join(p.data, "Users", "anna", "Desktop")
	os.MkdirAll(dir, 0o755)
	put := func(qname, path, disarm string, body []byte) string {
		h := sha256.Sum256(body)
		sha := hex.EncodeToString(h[:])
		os.WriteFile(filepath.Join(p.quarantine(), qname), body, 0o600)
		if path != "" {
			appendLine(p.resultsLog(), []byte(`{"timestamp":"`+time.Now().Format("2006-01-02T15:04:05.000-07:00")+`","event":"Created","verdict":"HIGH","disarm":"`+disarm+`","docfile":{"path":`+jsonStr(path)+`,"name":"`+filepath.Base(path)+`","sha256":"`+sha+`"},"docscan":{"findings":["X"]}}`+"\n"))
		}
		return sha
	}
	tool := filepath.Join(dir, "tool.exe")
	doc := filepath.Join(dir, "report.docm")
	put("tool.exe.0.docscan-bak", tool, "quarantined", []byte("tool"))
	put("report.docm.0.docscan-bak", doc, "removed:macros", []byte("original with macros"))
	os.WriteFile(doc, []byte("disarmed copy"), 0o644) // the cured document stays in place
	put("old.lnk.0.docscan-bak", "", "", []byte("no record"))

	page := do("GET", "/quarantine", nil).Body.String()
	for _, s := range []string{"tool.exe", "report.docm", "old.lnk", "запис виявлення не знайдено", "замінити знешкоджену копію"} {
		if !strings.Contains(page, s) {
			t.Fatalf("quarantine page: no %q", s)
		}
	}
	// a path instead of a name is refused
	if w := do("POST", "/quarantine/delete", url.Values{"name": {`..\auth.json`}, "confirm": {"on"}}); !strings.Contains(w.Header().Get("Location"), url.QueryEscape("bad quarantine file name")) {
		t.Fatalf("path traversal: %s", w.Header().Get("Location"))
	}
	// restore a removed file
	if w := do("POST", "/quarantine/restore", url.Values{"name": {"tool.exe.0.docscan-bak"}, "mode": {"exact"}}); w.Code != http.StatusSeeOther || !fileExists(tool) {
		t.Fatalf("restore: %s", w.Header().Get("Location"))
	}
	if fileExists(filepath.Join(p.quarantine(), "tool.exe.0.docscan-bak")) {
		t.Fatal("the restored copy must leave the quarantine")
	}
	l, _ := readList(p.listFile("white", true), "white")
	if len(l.Entries) != 1 || l.Entries[0].Path != tool || l.Entries[0].SHA256 == "" {
		t.Fatalf("exception: %+v", l.Entries)
	}
	// a disarmed document: only with "replace"
	do("POST", "/quarantine/restore", url.Values{"name": {"report.docm.0.docscan-bak"}, "mode": {"path"}})
	if b, _ := os.ReadFile(doc); string(b) != "disarmed copy" {
		t.Fatal("replaced the disarmed copy without confirmation")
	}
	do("POST", "/quarantine/restore", url.Values{"name": {"report.docm.0.docscan-bak"}, "mode": {"path"}, "replace": {"on"}})
	if b, _ := os.ReadFile(doc); string(b) != "original with macros" {
		t.Fatal("the original did not replace the disarmed copy")
	}
	l, _ = readList(p.listFile("white", true), "white")
	if len(l.Entries) != 2 || l.Entries[1].SHA256 != "" {
		t.Fatalf("path-only exception: %+v", l.Entries)
	}
	// delete: only with the confirmation
	do("POST", "/quarantine/delete", url.Values{"name": {"old.lnk.0.docscan-bak"}})
	if !fileExists(filepath.Join(p.quarantine(), "old.lnk.0.docscan-bak")) {
		t.Fatal("deleted without confirmation")
	}
	do("POST", "/quarantine/delete", url.Values{"name": {"old.lnk.0.docscan-bak"}, "confirm": {"on"}})
	if fileExists(filepath.Join(p.quarantine(), "old.lnk.0.docscan-bak")) {
		t.Fatal("not deleted")
	}
	for _, a := range []string{"restored", "quarantine-deleted", "local-white-added"} {
		auditHas(t, p, a)
	}
	if origName("AnyDesk.exe.12.docscan-bak") != "AnyDesk.exe" || origName("a.b.docscan-bak") != "a.b" {
		t.Fatal("origName")
	}
}
