package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func write(t *testing.T, body string) string {
	p := filepath.Join(t.TempDir(), "c.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExampleConfigLoads(t *testing.T) {
	c, err := Load("../../config.example.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(c.Enabled(), ","); got != "macos,windows" {
		t.Fatalf("enabled %q", got)
	}
	w := c.Platforms["windows"].Machines()
	if len(w) != 2 || w[0].Connection.Port != 5985 || w[0].Connection.Auth != "ntlm" {
		t.Fatalf("windows candidates/defaults: %+v", w)
	}
	if c.Forgejo.Mode != "mirror" || c.Forgejo.Check.Timeout.Seconds() != 5 {
		t.Fatalf("forgejo defaults: %+v", c.Forgejo)
	}
}

func TestUnknownFieldIsAnError(t *testing.T) {
	_, err := Load(write(t, "version: 1\nplatfroms: {}\n"))
	if err == nil || !strings.Contains(err.Error(), "platfroms") {
		t.Fatalf("expected an error about the typo, got %v", err)
	}
}

func TestRequiresCycle(t *testing.T) {
	_, err := Load(write(t, `
platforms:
  windows: {enabled: true, connection: {type: local}, requires: [linux]}
  linux:   {enabled: true, connection: {type: local}, requires: [windows]}
`))
	if err == nil || !strings.Contains(err.Error(), "cycle") {
		t.Fatalf("expected a cycle error, got %v", err)
	}
}

func TestSecretRefs(t *testing.T) {
	os.Setenv("CIRUN_TEST_SECRET", "s3")
	hosts := filepath.Join(t.TempDir(), "hosts.json")
	os.WriteFile(hosts, []byte(`{"216":{"user":"u","password":"p"}}`), 0o600)
	r := NewResolver(Secrets{HostsFile: hosts})
	for ref, want := range map[string]string{"env:CIRUN_TEST_SECRET": "s3", "hosts:216": "p", "hosts:216.user": "u", "": ""} {
		if got, err := r.Get(ref); err != nil || got != want {
			t.Fatalf("%s: %q %v", ref, got, err)
		}
	}
	if _, err := r.Get("plain-password"); err == nil {
		t.Fatal("a value without a known prefix must be rejected")
	}
}
