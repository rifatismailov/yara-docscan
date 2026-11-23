package main

import (
	"errors"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPolicyPage(t *testing.T) {
	s, p, do := signedIn(t)
	pkg := "rule A { condition: true }\r\nrule B { condition: false }\r\n"
	os.WriteFile(p.policyCur(), []byte(pkg), 0o644)
	s.checkPolicy = func(text string) error {
		if strings.Contains(text, "broken") {
			return errors.New("line 1: syntax error")
		}
		return nil
	}
	if w := do("GET", "/policy", nil); !strings.Contains(w.Body.String(), "пакетна") {
		t.Fatal("policy page")
	}
	local := "rule A { condition: true }\r\nrule B { condition: true }\r\n"
	// broken -> nothing applied, the text stays in the form
	w := do("POST", "/policy", url.Values{"act": {"apply"}, "text": {"broken"}})
	if !strings.Contains(w.Body.String(), "does not compile") || fileExists(p.policyLocal()) {
		t.Fatal("a broken policy was applied")
	}
	// check only
	if w := do("POST", "/policy", url.Values{"act": {"check"}, "text": {local}}); !strings.Contains(w.Body.String(), "компілюється") || fileExists(p.policyLocal()) {
		t.Fatal("check must not apply")
	}
	if w := do("POST", "/policy", url.Values{"act": {"apply"}, "text": {local}}); w.Code != http.StatusSeeOther {
		t.Fatalf("apply: %d %s", w.Code, w.Body.String())
	}
	if c, _ := readText(p.policyCur()); c != local {
		t.Fatal("the local policy is not in rules\\")
	}
	if c, _ := readText(p.policyPkg()); c != pkg {
		t.Fatal("the package policy is not kept next to it")
	}
	page := do("GET", "/policy", nil).Body.String()
	if !strings.Contains(page, "ЛОКАЛЬНА") || !strings.Contains(page, "+1 / −1") {
		t.Fatalf("state after apply:\n%s", page)
	}
	auditHas(t, p, "policy-local-applied")
	// revert
	do("POST", "/policy", url.Values{"act": {"revert"}, "text": {local}})
	if c, _ := readText(p.policyCur()); c != pkg || fileExists(p.policyPkg()) || fileExists(p.policyLocal()) {
		t.Fatal("revert")
	}
	auditHas(t, p, "policy-local-removed")
}

func TestLineDiff(t *testing.T) {
	d, a, r := lineDiff("a\nb\nc\n", "a\nB\nc\nd\n", 1)
	if a != 2 || r != 1 || len(d) == 0 {
		t.Fatalf("%v %d %d", d, a, r)
	}
}

// the real compile check with the DocScan yara and the real rules (when they are on this machine)
func TestCompilePolicyReal(t *testing.T) {
	home, _ := os.UserHomeDir()
	yara := filepath.Join(home, "yara", "yara")
	rules := filepath.Join(home, "yara-docscan-rules")
	if !fileExists(yara) || !fileExists(filepath.Join(rules, "file-index.yar")) {
		t.Skip("no DocScan yara / yara-docscan-rules here")
	}
	d := t.TempDir()
	p := paths{data: filepath.Join(d, "data"), install: filepath.Join(d, "prog")}
	os.MkdirAll(filepath.Join(p.install, "bin"), 0o755)
	os.Symlink(yara, p.yaraExe())
	os.Symlink(rules, p.rulesDir())
	s := &server{p: p}
	pol, _ := readText(filepath.Join(rules, "docscan-policy.yar"))
	if err := s.compilePolicy(pol); err != nil {
		t.Fatalf("the package policy must compile: %v", err)
	}
	if err := s.compilePolicy(pol + "\nrule broken { condition: nope }\n"); err == nil {
		t.Fatal("a broken policy compiled")
	} else if !strings.Contains(err.Error(), "nope") && !strings.Contains(err.Error(), "error") {
		t.Fatal(err)
	}
}
