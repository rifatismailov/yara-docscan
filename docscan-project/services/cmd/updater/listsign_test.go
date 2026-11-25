package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"docscan/services/pkg/manifest"
	"docscan/services/pkg/orglists"
)

func TestSignList(t *testing.T) {
	dir := t.TempDir()
	key := filepath.Join(dir, "org-lists.key")
	if newListKeyCmd([]string{"-NewListKey", "-Out", key}) != 0 {
		t.Fatal("NewListKey failed")
	}
	if newListKeyCmd([]string{"-NewListKey", "-Out", key}) == 0 {
		t.Fatal("NewListKey overwrote an existing key")
	}
	if st, _ := os.Stat(key); st.Mode().Perm()&0o077 != 0 {
		t.Errorf("key file readable by others: %v", st.Mode())
	}
	seedB, _ := os.ReadFile(key)
	pub, err := manifest.PublicKeyOf(strings.TrimSpace(string(seedB)))
	if err != nil {
		t.Fatal(err)
	}
	bl := filepath.Join(dir, "blacklist.json")
	os.WriteFile(bl, []byte(`{"schema": 1, "entries": [{"path": "C:\\Users\\*\\Downloads\\*.exe"}, {"lnk_target": "\\\\evil-srv\\"}]}`), 0o644)
	if signListCmd([]string{"-SignList", bl, "-Kind", "black", "-Key", key}) != 0 {
		t.Fatal("SignList failed")
	}
	verify := func() *orglists.List {
		t.Helper()
		data, _ := os.ReadFile(bl)
		sig, _ := os.ReadFile(bl + ".sig")
		if _, err := manifest.VerifySig(data, string(sig), []string{pub}); err != nil {
			t.Fatalf("signature does not verify: %v", err)
		}
		l, err := orglists.Parse(data, "black")
		if err != nil {
			t.Fatal(err)
		}
		return l
	}
	l1 := verify()
	if l1.Serial < 20260101000000 || len(l1.Entries) != 2 {
		t.Fatalf("serial / content: %+v", l1)
	}
	// re-sign: serial grows even within the same second
	if signListCmd([]string{"-SignList", bl, "-Kind", "black", "-Key", key}) != 0 {
		t.Fatal("second SignList failed")
	}
	if l2 := verify(); l2.Serial <= l1.Serial {
		t.Fatalf("serial did not grow: %d -> %d", l1.Serial, l2.Serial)
	}
	// wrong kind / broken list / no key: refused, nothing signed
	if signListCmd([]string{"-SignList", bl, "-Kind", "white", "-Key", key}) == 0 {
		t.Error("a whole server (black-list only) signed as a white list")
	}
	t.Setenv("DOCSCAN_LISTS_KEY", "")
	if signListCmd([]string{"-SignList", bl, "-Kind", "black"}) == 0 {
		t.Error("signed without a key")
	}
	t.Setenv("DOCSCAN_LISTS_KEY", strings.TrimSpace(string(seedB)))
	if signListCmd([]string{"-SignList", bl, "-Kind", "black"}) != 0 {
		t.Error("key from DOCSCAN_LISTS_KEY not used")
	}
	verify()
}
