package deploy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// CheckCritical with the yara built in the repository root (make): names, compile, tests/match and tests/no-match
func TestCheckCritical(t *testing.T) {
	yara, _ := filepath.Abs("../../../../yara")
	if st, err := os.Stat(yara); err != nil || !st.Mode().IsRegular() {
		t.Skip("no ./yara in the repository root")
	}
	repo := t.TempDir()
	w := func(p, s string) {
		os.MkdirAll(filepath.Dir(filepath.Join(repo, p)), 0o755)
		os.WriteFile(filepath.Join(repo, p), []byte(s), 0o644)
	}
	index := filepath.Join(repo, "index.yar")
	os.WriteFile(index, []byte("rule nothing { condition: false }\n"), 0o644)
	w("critical/a.yar", `rule A { strings: $x = "secret project falcon" condition: $x }`)
	w("critical/b.yar", `rule B { strings: $x = "access code" condition: $x }`)
	w("tests/match/one.txt", "Report: Secret  Project\r\nFalcon starts monday")
	w("tests/match/sub/two.txt", "the access code is in the safe")
	w("tests/no-match/three.txt", "a public press release")
	r, err := CheckCritical(repo, yara, index, t.TempDir())
	if err != nil || r.Match != 2 || r.NoMatch != 1 || len(r.Files) != 2 {
		t.Fatalf("good set: %v %+v", err, r)
	}
	// a document that should match but does not, and a false alarm
	w("tests/match/four.txt", "nothing relevant here")
	w("tests/no-match/five.txt", "please keep the access code")
	r, err = CheckCritical(repo, yara, index, t.TempDir())
	if err == nil || len(r.Missed) != 1 || !strings.HasSuffix(r.Missed[0], "four.txt") || len(r.Unwanted) != 1 || !strings.HasSuffix(r.Unwanted[0], "five.txt") {
		t.Fatalf("missed / false alarm: %v %+v", err, r)
	}
	// a broken file -> its name in the error
	w("critical/c.yar", `rule C { condition: nonsense }`)
	if _, err = CheckCritical(repo, yara, index, t.TempDir()); err == nil || !strings.Contains(err.Error(), "c.yar") {
		t.Fatalf("broken file: %v", err)
	}
	os.Remove(filepath.Join(repo, "critical/c.yar"))
	// a non-rules file / a subfolder in critical/
	w("critical/notes.docx", "x")
	if _, err = CheckCritical(repo, yara, index, t.TempDir()); err == nil || !strings.Contains(err.Error(), "notes.docx") {
		t.Fatalf("other file: %v", err)
	}
}
