package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The PowerShell watcher stays in the package as a fallback (install.ps1 -WatcherEngine ps): both must watch the
// same extensions, otherwise switching the engine silently changes what is scanned.
func TestExtensionListsMatchPowerShellWatcher(t *testing.T) {
	b, err := os.ReadFile("../../../watcher/docscan-watcher.ps1")
	if err != nil {
		t.Skip("docscan-watcher.ps1 not found:", err)
	}
	ps := map[string][]string{}
	cur := ""
	start := regexp.MustCompile(`\$(DocExt|GenExt|CriticalExt)\s*=\s*@\(`)
	ext := regexp.MustCompile(`"(\.[A-Za-z0-9]+)"`)
	for _, line := range strings.Split(string(b), "\n") {
		code, _, _ := strings.Cut(line, "#")
		if m := start.FindStringSubmatchIndex(code); m != nil {
			cur = code[m[2]:m[3]]
			code = code[m[1]:]
		}
		if cur == "" {
			continue
		}
		for _, m := range ext.FindAllStringSubmatch(code, -1) {
			ps[cur] = append(ps[cur], strings.ToLower(m[1]))
		}
		if strings.Contains(code, ")") {
			cur = ""
		}
	}
	norm := func(v []string) string {
		c := append([]string(nil), v...)
		sort.Strings(c)
		return strings.Join(c, " ")
	}
	for name, goList := range map[string][]string{"DocExt": defDocExt, "GenExt": defGenExt, "CriticalExt": defCriticalExt} {
		if len(ps[name]) == 0 {
			t.Fatalf("%s not found in docscan-watcher.ps1", name)
		}
		if norm(ps[name]) != norm(goList) {
			t.Errorf("%s differs:\n  ps1: %s\n  go:  %s", name, norm(ps[name]), norm(goList))
		}
	}
}
