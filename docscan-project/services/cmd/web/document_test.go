package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestDocumentView(t *testing.T) {
	_, p, do := signedIn(t)
	sha := strings.Repeat("ab", 32)
	os.MkdirAll(p.macroDir(), 0o755)
	vba := "Attribute VB_Name = \"Module1\"\r\nSub AutoOpen()\r\n  x = 1\r\n  Shell \"cmd.exe /c calc\"\r\n  y = \"<script>alert(1)</script>\"\r\nEnd Sub\r\n"
	os.WriteFile(filepath.Join(p.macroDir(), sha+".vba.txt"), []byte(vba), 0o644)
	rec := `{"timestamp":"` + time.Now().Format("2006-01-02T15:04:05.000-07:00") + `","event":"Created","category":"document","verdict":"HIGH","disarm":"removed:macros",` +
		`"docfile":{"path":"C:\\Users\\a\\report.docm","name":"report.docm","sha256":"` + sha + `"},` +
		`"docscan":{"ftype":"ooxml","findings":["MACRO_SUSPICIOUS","REMOTE_TEMPLATE"],"findings_text":["Макрос запускає програми","Віддалений шаблон"],` +
		`"evidence":{"template_url":"http://evil.example/t.dotm","vba_evidence":"Shell | AutoOpen","dde_command":""},` +
		`"yara_matches":["SUSP_VBA_Shell"],"yara_part_matches":[{"part":"word/vbaProject.bin","rules":["Office_AutoOpen"]}],` +
		`"yara_descriptions":[{"rule":"SUSP_VBA_Shell","description":"VBA runs a shell"}],` +
		`"details":[{"rule":"DS_MACRO_SUSPICIOUS","finding":"MACRO_SUSPICIOUS","severity":"HIGH","disarm":"macros","mitre":"T1204.002"}]},` +
		`"macro":{"file":"` + sha + `.vba.txt","size":120}}` + "\n"
	appendLine(p.resultsLog(), []byte(rec))
	det := do("GET", "/detections", nil).Body.String()
	m := regexp.MustCompile(`/record\?f=(\d+)&(?:amp;)?o=(\d+)`).FindStringSubmatch(det)
	page := do("GET", "/record?f="+m[1]+"&o="+m[2], nil).Body.String()
	for _, s := range []string{"Документ · ooxml", "Макрос запускає програми", "T1204.002", "віддалений шаблон", "http://evil.example/t.dotm",
		"VBA runs a shell", "код макросів", "частина: word/vbaProject.bin", "/macro?sha=" + sha} {
		if !strings.Contains(page, s) {
			t.Errorf("record page: no %q", s)
		}
	}
	if strings.Contains(page, "DDE-команда") {
		t.Error("an empty evidence field must not be shown")
	}
	code := do("GET", "/macro?sha="+sha, nil).Body.String()
	if !strings.Contains(code, `class="ln hit"><i>2</i>Sub AutoOpen()`) || !strings.Contains(code, `<i>4</i>  Shell`) {
		t.Fatalf("macro page: no highlighted lines\n%s", code)
	}
	if strings.Contains(code, "<script>alert(1)</script>") || !strings.Contains(code, "&lt;script&gt;") {
		t.Fatal("VBA code must be escaped")
	}
	if !strings.Contains(code, "report.docm") {
		t.Fatal("macro page: no link to the document record")
	}
	if w := do("GET", "/macro?sha=../../web/auth", nil); !strings.Contains(w.Body.String(), "give the sha256") {
		t.Fatal("bad sha accepted")
	}
	if l := do("GET", "/macros", nil).Body.String(); !strings.Contains(l, "report.docm") || !strings.Contains(l, "v-HIGH") {
		t.Fatal("macros list")
	}
	if lg, _ := os.ReadFile(p.webLog()); strings.Contains(string(lg), "template") {
		t.Fatalf("template error: %s", lg)
	}
}
