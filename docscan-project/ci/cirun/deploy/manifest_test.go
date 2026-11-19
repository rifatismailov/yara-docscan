package deploy

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"

	"docscan/watcher/manifest"
)

// Sign: manifest.json з хешами файлів пакета, підпис перевіряється кодом updater-а; чужий ключ — відмова.
func TestSignManifest(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	seed := base64.StdEncoding.EncodeToString(priv.Seed())
	old := trustedKeys
	trustedKeys = []string{"ed25519:" + base64.StdEncoding.EncodeToString(pub)}
	defer func() { trustedKeys = old }()

	dir := t.TempDir()
	pkg := filepath.Join(dir, PkgAsset)
	f, _ := os.Create(pkg)
	w := zip.NewWriter(f)
	for n, c := range map[string]string{"bin/yara64.exe": "exe", "VERSION.txt": "DocScan v1.2.3\r\n"} {
		o, _ := w.Create(n)
		o.Write([]byte(c))
	}
	w.Close()
	f.Close()
	sha, _ := fileSHA(pkg)
	r := &Release{Tag: "v1.2.3", Version: "v1.2.3", Build: "20261119-abcdef12", Dir: dir, PkgSHA: sha}
	if err := r.Sign("abcdef1234", seed); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(dir, ManifestAsset))
	sig, _ := os.ReadFile(filepath.Join(dir, SigAsset))
	m, _, err := manifest.Verify(data, string(sig), trustedKeys)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != "v1.2.3" || m.Package.SHA256 != sha || len(m.Files) != 2 || m.Files["bin/yara64.exe"] == "" {
		t.Fatalf("manifest: %+v", m)
	}
	if len(r.Assets) != 2 {
		t.Fatalf("assets: %v", r.Assets)
	}
	// ключ не з довірених — реліз не підписується
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	if err := r.Sign("x", base64.StdEncoding.EncodeToString(other.Seed())); err == nil {
		t.Fatal("signed with an untrusted key")
	}
}
