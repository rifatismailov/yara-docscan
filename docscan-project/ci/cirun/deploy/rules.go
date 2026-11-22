package deploy

// Реліз правил (репозиторій yara-docscan-rules): cirun rules-release --dir <його checkout>.
//
//	DocScan-rules.zip         правила (усе з репозиторію, крім tools/, README.md, .git) + critical/ (правила критичної
//	                          інформації з окремого репозиторію, critical.go) + VERSION.txt
//	rules-manifest.json/.sig  підписаний маніфест (продукт docscan-rules) — для DocScanUpdater
//	DocScan-rules-bundle.zip  ці три файли одним архівом — для ручного встановлення (install.ps1 -Rules)
//
// Номер — vX.Y.Z окремо від програми (найбільший v-тег репозиторію правил + bump). Перед пакуванням правила
// компілюються нашим yarac так само, як на ПК (зовнішні змінні DocScan): не компілюються — релізу немає.

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"docscan/watcher/manifest"
)

const (
	RulesPkgAsset      = "DocScan-rules.zip"
	RulesManifestAsset = "rules-manifest.json"
	RulesSigAsset      = "rules-manifest.sig"
	RulesBundleAsset   = "DocScan-rules-bundle.zip"
)

// RulesRelease — реліз правил: тег, коміт, тека з активами.
type RulesRelease struct {
	Repo, Tag, Commit, Dir, PkgSHA string
	Assets                         []string
}

// skipRules — що з репозиторію правил не йде на ПК.
func skipRules(rel string) bool {
	first := strings.SplitN(rel, "/", 2)[0]
	return first == ".git" || first == "tools" || rel == "README.md" || strings.HasPrefix(filepath.Base(rel), ".")
}

// PrepareRules: компіляція (yarac — наш, з модулем docscan), пакет з VERSION.txt, підписаний маніфест, пакет для
// ручного встановлення — у outDir.
// critical — checkout репозиторію критичних правил ("" — пакет без critical/); critCommit — його коміт (для VERSION.txt).
func PrepareRules(rulesDir, repo, tag, commit, yarac, seedB64, outDir, critical, critCommit string) (*RulesRelease, error) {
	idx := filepath.Join(rulesDir, "docscan-index.yar")
	if _, err := os.Stat(idx); err != nil {
		return nil, fmt.Errorf("%s: no docscan-index.yar - not a DocScan rules repository", rulesDir)
	}
	yarc := filepath.Join(outDir, "check.yarc")
	os.MkdirAll(outDir, 0o755)
	out, err := exec.Command(yarac, "-w", "-d", "filename=", "-d", "filepath=", "-d", "extension=", "-d", "filetype=", "-d", "owner=", idx, yarc).CombinedOutput()
	os.Remove(yarc)
	if err != nil {
		return nil, fmt.Errorf("the rules do not compile (%s): %s", yarac, strings.TrimSpace(string(out)))
	}
	r := &RulesRelease{Repo: repo, Tag: tag, Commit: commit, Dir: outDir}
	extra := map[string]string{}
	crit := ""
	if critical != "" {
		if _, err := os.Stat(filepath.Join(rulesDir, "critical")); err == nil {
			return nil, fmt.Errorf("%s has its own critical/ - the critical rules come only from %s", rulesDir, critical)
		}
		names, err := CriticalFiles(filepath.Join(critical, "critical"))
		if err != nil {
			return nil, err
		}
		for _, n := range names {
			extra["critical/"+n] = filepath.Join(critical, "critical", n)
		}
		crit = fmt.Sprintf(", critical %s: %d files", short(critCommit), len(names))
	}
	pkg := filepath.Join(outDir, RulesPkgAsset)
	if err := zipRules(rulesDir, pkg, fmt.Sprintf("DocScan rules %s (commit %s%s, %s)\r\n", tag, short(commit), crit, time.Now().UTC().Format("2006-01-02")), extra); err != nil {
		return nil, err
	}
	if r.PkgSHA, err = fileSHA(pkg); err != nil {
		return nil, err
	}
	data, sig, err := signPackage(manifest.ProductRules, tag, short(commit), commit, pkg, r.PkgSHA, seedB64)
	if err != nil {
		return nil, err
	}
	mp, sp := filepath.Join(outDir, RulesManifestAsset), filepath.Join(outDir, RulesSigAsset)
	if err := os.WriteFile(mp, data, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(sp, sig, 0o644); err != nil {
		return nil, err
	}
	bundle := filepath.Join(outDir, RulesBundleAsset)
	if err := zipFiles(bundle, mp, sp, pkg); err != nil {
		return nil, err
	}
	r.Assets = []string{pkg, mp, sp, bundle}
	return r, nil
}

func short(c string) string {
	if len(c) > 8 {
		return c[:8]
	}
	return c
}

// zipRules — усі файли правил (імена з "/") + extra (ім'я в пакеті -> файл) + VERSION.txt.
func zipRules(dir, dst, version string, extra map[string]string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	w := zip.NewWriter(f)
	err = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		if skipRules(rel) {
			if fi.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if fi.IsDir() || rel == "VERSION.txt" {
			return nil
		}
		return addFile(w, rel, p)
	})
	if err != nil {
		return err
	}
	var names []string
	for n := range extra {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := addFile(w, n, extra[n]); err != nil {
			return err
		}
	}
	o, err := w.CreateHeader(&zip.FileHeader{Name: "VERSION.txt", Method: zip.Deflate, Modified: time.Now()})
	if err != nil {
		return err
	}
	if _, err := o.Write([]byte(version)); err != nil {
		return err
	}
	return w.Close()
}

func zipFiles(dst string, files ...string) error {
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	w := zip.NewWriter(f)
	for _, p := range files {
		if err := addFile(w, filepath.Base(p), p); err != nil {
			return err
		}
	}
	return w.Close()
}

func addFile(w *zip.Writer, name, path string) error {
	in, err := os.Open(path)
	if err != nil {
		return err
	}
	defer in.Close()
	st, _ := in.Stat()
	o, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: st.ModTime()})
	if err != nil {
		return err
	}
	_, err = io.Copy(o, in)
	return err
}

// Publish: gh release create на репозиторії правил; наявний тег не перезаписується. Потім пакет качається за
// публічною адресою і звіряється sha256.
func (r *RulesRelease) Publish(say func(string, ...any)) error {
	if out, err := exec.Command("gh", "release", "view", r.Tag, "--repo", r.Repo).CombinedOutput(); err == nil {
		return fmt.Errorf("release %s already exists on %s - not overwritten", r.Tag, r.Repo)
	} else if !strings.Contains(string(out), "not found") {
		return fmt.Errorf("gh release view: %s", strings.TrimSpace(string(out)))
	}
	notes := fmt.Sprintf("DocScan rules %s (commit %s).\n\n"+
		"- `%s` — the rules bundle for a manual install: `DocScan-Install.ps1 -Rules <file or URL>`\n"+
		"- `%s` + `%s` + `%s` — for the DocScanUpdater service (rule-only updates)\n\n"+
		"Signed by the DocScan CI (ed25519); DocScan installs only signed rules. Compiled with DocScan's yarac before publishing.",
		r.Tag, short(r.Commit), RulesBundleAsset, RulesPkgAsset, RulesManifestAsset, RulesSigAsset)
	args := append([]string{"release", "create", r.Tag}, r.Assets...)
	args = append(args, "--repo", r.Repo, "--target", r.Commit, "--title", "DocScan rules "+r.Tag, "--notes", notes)
	if out, err := exec.Command("gh", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("gh release create: %s", strings.TrimSpace(string(out)))
	}
	url := DownloadURL(r.Repo, r.Tag, RulesPkgAsset)
	if err := AssetOK(url, r.PkgSHA); err != nil {
		return fmt.Errorf("release created, but the rules package does not download correctly: %w", err)
	}
	say("    %s\n    sha256 %s   OK", url, r.PkgSHA)
	say("    manual install:  DocScan-Install.ps1 -Rules https://github.com/%s/releases/latest/download/%s", r.Repo, RulesBundleAsset)
	return nil
}
