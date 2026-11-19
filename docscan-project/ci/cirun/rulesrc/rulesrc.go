// Package rulesrc — правила для прогону CI з релізів github.com/rifatismailov/yara-docscan-rules (у git проєкту
// правил більше немає). Реліз завантажується, перевіряється так само, як на ПК (підпис CI, sha256 пакета і кожного
// файлу), і розкладається в docscan-project/rules робочої теки — тести бачать правила там, де й раніше; стенди
// отримують DocScan-rules.zip (розкласти в ту саму теку) і DocScan-rules-bundle.zip (install.ps1 -Rules).
package rulesrc

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"docscan/watcher/manifest"
)

// Repo — репозиторій релізів правил.
const Repo = "rifatismailov/yara-docscan-rules"

// Тека правил у робочій теці репозиторію проєкту (у .gitignore).
const TreeDir = "docscan-project/rules"

const (
	PkgName      = "DocScan-rules.zip"
	ManifestName = "rules-manifest.json"
	SigName      = "rules-manifest.sig"
	BundleName   = "DocScan-rules-bundle.zip"
)

// Rules — перевірений реліз правил у кеші.
type Rules struct {
	Version string
	Dir     string // <кеш>/<версія>: усі чотири файли
	Zip     string // DocScan-rules.zip
	Bundle  string // DocScan-rules-bundle.zip
	m       *manifest.Manifest
}

var client = &http.Client{Timeout: 10 * time.Minute}

func base(version string) string {
	if version == "" || version == "latest" {
		return "https://github.com/" + Repo + "/releases/latest/download/"
	}
	return "https://github.com/" + Repo + "/releases/download/" + version + "/"
}

func get(url string, limit int64) ([]byte, error) {
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", url, limit)
	}
	return b, err
}

// Fetch: реліз version ("" / latest — найновіший) -> перевірка -> кеш cacheDir/<версія> (повторно не качається).
func Fetch(version, cacheDir string) (*Rules, error) {
	if version != "" && version != "latest" {
		if r, err := load(filepath.Join(cacheDir, version)); err == nil {
			return r, nil
		}
	}
	b := base(version)
	data, err := get(b+ManifestName, 4<<20)
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	sig, err := get(b+SigName, 4096)
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	m, _, err := manifest.VerifyProduct(data, string(sig), manifest.OfficialKeys, manifest.ProductRules)
	if err != nil {
		return nil, fmt.Errorf("rules release %s: %w", orLatest(version), err)
	}
	dir := filepath.Join(cacheDir, m.Version)
	if r, err := load(dir); err == nil {
		return r, nil
	}
	pkg, err := get(b+m.Package.Name, m.Package.Size)
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if h := sha256.Sum256(pkg); int64(len(pkg)) != m.Package.Size || hex.EncodeToString(h[:]) != m.Package.SHA256 {
		return nil, fmt.Errorf("rules %s: %s differs from the signed manifest", m.Version, m.Package.Name)
	}
	bundle, err := get(b+BundleName, 512<<20)
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	tmp := dir + ".tmp"
	os.RemoveAll(tmp)
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		return nil, err
	}
	for n, c := range map[string][]byte{ManifestName: data, SigName: sig, PkgName: pkg, BundleName: bundle} {
		if err := os.WriteFile(filepath.Join(tmp, n), c, 0o644); err != nil {
			return nil, err
		}
	}
	os.RemoveAll(dir)
	if err := os.Rename(tmp, dir); err != nil {
		return nil, err
	}
	return load(dir)
}

// load — кешований реліз: підпис і пакет перевіряються щоразу (кеш на диску — не довіра).
func load(dir string) (*Rules, error) {
	data, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, err
	}
	sig, err := os.ReadFile(filepath.Join(dir, SigName))
	if err != nil {
		return nil, err
	}
	m, _, err := manifest.VerifyProduct(data, string(sig), manifest.OfficialKeys, manifest.ProductRules)
	if err != nil {
		return nil, err
	}
	pkg, err := os.ReadFile(filepath.Join(dir, PkgName))
	if err != nil {
		return nil, err
	}
	if h := sha256.Sum256(pkg); hex.EncodeToString(h[:]) != m.Package.SHA256 {
		return nil, fmt.Errorf("%s: cached package differs from the manifest", dir)
	}
	if _, err := os.Stat(filepath.Join(dir, BundleName)); err != nil {
		return nil, err
	}
	return &Rules{Version: m.Version, Dir: dir, Zip: filepath.Join(dir, PkgName), Bundle: filepath.Join(dir, BundleName), m: m}, nil
}

// Materialize розкладає правила в dst (спершу очищає): лише файли маніфесту, кожен — з його sha256.
func (r *Rules) Materialize(dst string) error {
	pkg, err := os.ReadFile(r.Zip)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		return err
	}
	if err := os.RemoveAll(dst); err != nil {
		return err
	}
	n := 0
	for _, e := range zr.File {
		if e.FileInfo().IsDir() {
			continue
		}
		want, ok := r.m.Files[e.Name]
		if !ok || !manifest.SafePath(e.Name) {
			return fmt.Errorf("rules %s: unexpected file %q", r.Version, e.Name)
		}
		rc, err := e.Open()
		if err != nil {
			return err
		}
		b, err := io.ReadAll(io.LimitReader(rc, 256<<20))
		rc.Close()
		if err != nil {
			return err
		}
		if h := sha256.Sum256(b); hex.EncodeToString(h[:]) != want {
			return fmt.Errorf("rules %s: %s differs from the signed manifest", r.Version, e.Name)
		}
		p := filepath.Join(dst, filepath.FromSlash(e.Name))
		os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, b, 0o644); err != nil {
			return err
		}
		n++
	}
	if n != len(r.m.Files) {
		return fmt.Errorf("rules %s: %d of %d files", r.Version, n, len(r.m.Files))
	}
	return nil
}

func orLatest(v string) string {
	if strings.TrimSpace(v) == "" {
		return "latest"
	}
	return v
}
