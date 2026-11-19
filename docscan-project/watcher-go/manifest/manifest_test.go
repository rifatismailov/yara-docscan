package manifest

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func testKey(t *testing.T) (seed, pub string) {
	p, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv.Seed()), "ed25519:" + base64.StdEncoding.EncodeToString(p)
}

func sample() []byte {
	m := Manifest{Schema: Schema, Product: Product, Version: "v1.2.3", Build: "20261119-abcdef12", Commit: "abc",
		Created: "2026-11-19T10:00:00Z", Package: File{Name: "DocScan-windows-x64.zip", Size: 10, SHA256: strings.Repeat("a", 64)},
		Files: map[string]string{"bin/yara64.exe": strings.Repeat("b", 64)}}
	b, _ := json.MarshalIndent(m, "", "  ")
	return b
}

func TestSignVerify(t *testing.T) {
	seed, pub := testKey(t)
	data := sample()
	sig, err := Sign(data, seed)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := PublicKeyOf(seed); got != pub {
		t.Fatalf("PublicKeyOf %s != %s", got, pub)
	}
	m, id, err := Verify(data, sig, []string{pub})
	if err != nil || m.Version != "v1.2.3" || id == "" {
		t.Fatalf("verify: %v %v %s", err, m, id)
	}
	// чужий ключ, змінені дані, змінений підпис — відмова
	_, other := testKey(t)
	if _, _, err := Verify(data, sig, []string{other}); err == nil {
		t.Fatal("verified with a foreign key")
	}
	bad := append([]byte{}, data...)
	bad[len(bad)-3] ^= 1
	if _, _, err := Verify(bad, sig, []string{pub}); err == nil {
		t.Fatal("verified modified data")
	}
	if _, _, err := Verify(data, strings.Replace(sig, "ed25519 ", "rsa ", 1), []string{pub}); err == nil {
		t.Fatal("verified a bad sig line")
	}
}

func TestOfficialKeys(t *testing.T) {
	for _, k := range OfficialKeys {
		if _, err := ParseKey(k); err != nil {
			t.Fatal(err)
		}
	}
}

func TestCheckRejects(t *testing.T) {
	for _, p := range []string{"../x", "/abs", `a\b`, "C:/x", "a//b", "a/./b", ""} {
		if SafePath(p) {
			t.Fatalf("SafePath(%q) = true", p)
		}
	}
	if !SafePath("watcher/docscan-watcher.exe") {
		t.Fatal("SafePath rejects a normal path")
	}
	var m Manifest
	json.Unmarshal(sample(), &m)
	m.Product = "other"
	if m.Check() == nil {
		t.Fatal("other product accepted")
	}
}

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{{"v1.0.3", "v1.0.10", -1}, {"v1.1.0", "v1.0.9", 1}, {"v2.0.0", "v2.0.0", 0}, {"", "v0.0.1", -1}, {"20261116-abc", "v1.0.0", -1}}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Fatalf("Compare(%q, %q) = %d", c.a, c.b, got)
		}
	}
	if VersionFromTitle("DocScan v1.0.3 (build 20261119-7182ee86)\r") != "v1.0.3" {
		t.Fatal("VersionFromTitle")
	}
}
