package deploy

// Підписаний маніфест релізу (формат — docscan/watcher/manifest): manifest.json + manifest.sig поруч із пакетом.
// docscan-updater на ПК бере оновлення лише з дійсним підписом, хоч із GitHub, хоч із дзеркала організації.

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"time"

	"docscan/watcher/manifest"
)

// Імена файлів маніфесту серед активів релізу (однакові в усіх релізах: releases/latest/download/<ім'я>).
const (
	ManifestAsset = "manifest.json"
	SigAsset      = "manifest.sig"
)

// trustedKeys — ключі, яким довіряють ПК (тест підставляє свій).
var trustedKeys = manifest.OfficialKeys

// Sign складає manifest.json (версія, збірка, коміт, пакет і sha256 кожного файлу в ньому), підписує його
// ключем seedB64 і додає обидва файли до активів. Ключ має бути одним з manifest.OfficialKeys — інакше ПК
// відкинуть реліз, тож краще не випускати його взагалі.
func (r *Release) Sign(commit, seedB64 string) error {
	pub, err := manifest.PublicKeyOf(seedB64)
	if err != nil {
		return err
	}
	if !slices.Contains(trustedKeys, pub) {
		return fmt.Errorf("the signing key %s is not in manifest.OfficialKeys (watcher-go/manifest) - PCs would reject the release", pub)
	}
	pkg := filepath.Join(r.Dir, PkgAsset)
	st, err := os.Stat(pkg)
	if err != nil {
		return err
	}
	files, err := zipHashes(pkg)
	if err != nil {
		return err
	}
	m := manifest.Manifest{Schema: manifest.Schema, Product: manifest.Product, Version: r.Version, Build: r.Build,
		Commit: commit, Created: time.Now().UTC().Format(time.RFC3339),
		Package: manifest.File{Name: PkgAsset, Size: st.Size(), SHA256: r.PkgSHA}, Files: files}
	if err := m.Check(); err != nil {
		return fmt.Errorf("manifest: %w", err)
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	sig, err := manifest.Sign(data, seedB64)
	if err != nil {
		return err
	}
	// перевірка тим самим кодом, що й на ПК
	if _, _, err := manifest.Verify(data, sig, trustedKeys); err != nil {
		return fmt.Errorf("manifest self-check: %w", err)
	}
	mp, sp := filepath.Join(r.Dir, ManifestAsset), filepath.Join(r.Dir, SigAsset)
	if err := os.WriteFile(mp, data, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(sp, []byte(sig), 0o644); err != nil {
		return err
	}
	r.Assets = append(r.Assets, mp, sp)
	return nil
}

// zipHashes — sha256 кожного файлу в zip (імена з "/").
func zipHashes(p string) (map[string]string, error) {
	zr, err := zip.OpenReader(p)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	out := map[string]string{}
	for _, e := range zr.File {
		if e.FileInfo().IsDir() {
			continue
		}
		if !manifest.SafePath(e.Name) {
			return nil, fmt.Errorf("%s: unsafe path in the package: %q", p, e.Name)
		}
		rc, err := e.Open()
		if err != nil {
			return nil, err
		}
		h := sha256.New()
		_, err = io.Copy(h, rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		out[e.Name] = hex.EncodeToString(h.Sum(nil))
	}
	return out, nil
}
