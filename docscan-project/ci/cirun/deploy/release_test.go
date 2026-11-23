package deploy

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// repack: the first line of VERSION.txt becomes the release title and SHA256SUMS.txt still matches every file
// (install.ps1 refuses a package whose files do not match).
func TestRepackVersionAndSums(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		`bin\yara64.exe`: "exe", "install.ps1": "ps", `watcher\docscan-watcher.exe`: "go", `watcher\docscan-watcher.ps1`: "ps1", `updater\docscan-updater.exe`: "upd", `web\docscan-web.exe`: "web",
		"VERSION.txt": "DocScan 20261118-abcdef12\r\nyara64 4.6.0\r\nbuilt 2026-11-18T10:00:00 on VM\r\n",
	}
	sums := ""
	for n, c := range files {
		h := sha256.Sum256([]byte(c))
		sums += hex.EncodeToString(h[:]) + "  " + n + "\r\n"
	}
	files["SHA256SUMS.txt"] = sums
	src := filepath.Join(dir, "src.zip")
	f, _ := os.Create(src)
	w := zip.NewWriter(f)
	for n, c := range files {
		o, _ := w.Create(n)
		o.Write([]byte(c))
	}
	w.Close()
	f.Close()

	dst := filepath.Join(dir, "dst.zip")
	if err := repack(src, dst, "DocScan v1.0.0 (build 20261118-abcdef12)"); err != nil {
		t.Fatal(err)
	}
	zr, err := zip.OpenReader(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	got := map[string]string{}
	for _, e := range zr.File {
		r, _ := e.Open()
		b, _ := io.ReadAll(r)
		r.Close()
		got[e.Name] = string(b)
	}
	if !strings.HasPrefix(got["VERSION.txt"], "DocScan v1.0.0 (build 20261118-abcdef12)\r\nyara64 4.6.0\r\n") {
		t.Errorf("VERSION.txt = %q", got["VERSION.txt"])
	}
	for _, l := range strings.Split(strings.TrimSpace(got["SHA256SUMS.txt"]), "\r\n") {
		p := strings.SplitN(l, "  ", 2)
		h := sha256.Sum256([]byte(got[strings.ReplaceAll(p[1], `\`, "/")]))
		if hex.EncodeToString(h[:]) != p[0] {
			t.Errorf("SHA256SUMS mismatch for %s", p[1])
		}
	}
}
