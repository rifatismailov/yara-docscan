// Package deploy — реліз DocScan на GitHub (cirun --release / --release-run). Файлових серверів для
// розгортання немає: ПК бере ВСЕ з релізу GitHub цього репозиторію.
//
// Активи релізу vX.Y.Z (тег на протестований і запушений коміт, номер — version.go):
//
//	DocScan-windows-x64.zip (+ .sha256)  повний пакет: bin\ (yara64, yarac64, рантайм VC++), rules\,
//	                                     watcher\, updater\, install.ps1, uninstall.ps1, SHA256SUMS.txt, VERSION.txt
//	manifest.json + manifest.sig         підписаний маніфест (manifest.go): docscan-updater на ПК ставить лише його
//	                                     (перший рядок: "DocScan vX.Y.Z (build <дата>-<коміт>)")
//	DocScan-Install.ps1                  єдиний скрипт для ПК: качає пакет з релізу, звіряє SHA256,
//	                                     запускає install.ps1 з пакета
//
// Імена активів однакові в усіх релізах, тож .../releases/latest/download/<ім'я> - завжди найновіший
// (без GitHub API і його ліміту 60 запитів на годину з однієї адреси). Правила E5Search (critical) у
// реліз НЕ потрапляють: їх дають інсталятору окремо (-Critical <файл або URL>).
package deploy

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// PkgAsset — ім'я пакета серед активів релізу (однакове в усіх релізах).
const PkgAsset = "DocScan-windows-x64.zip"

// Release — реліз: репозиторій, тег, версія, теки з активами, sha256 пакета.
type Release struct {
	Repo, Tag, Version, Dir, PkgSHA string // Version = Tag (vX.Y.Z)
	Build                           string // збірка пакета: <дата>-<коміт>
	Extra                           string // додатково в опис релізу (таблиця «Verified on» конвеєра)
	Rules                           string // реліз правил yara-docscan-rules, з яким тестували
	Assets                          []string
}

var sumLineRe = regexp.MustCompile(`(?m)^[0-9a-f]{64}  VERSION\.txt`)

var verRe = regexp.MustCompile(`^DocScan-(\d{8}-[0-9a-f]+)\.zip$`)

// FullPackage — найновіший пакет прогону: <runDir>/<платформа>/DocScan-<версія>.zip.
func FullPackage(runDir string) (path, version string, err error) {
	zips, _ := filepath.Glob(filepath.Join(runDir, "*", "DocScan-*.zip"))
	var full []string
	for _, z := range zips {
		if filepath.Base(filepath.Dir(z)) != "release" && verRe.MatchString(filepath.Base(z)) {
			full = append(full, z)
		}
	}
	if len(full) == 0 {
		return "", "", fmt.Errorf("no Windows package DocScan-<version>.zip in %s", runDir)
	}
	sort.Strings(full)
	path = full[len(full)-1]
	return path, verRe.FindStringSubmatch(filepath.Base(path))[1], nil
}

// DownloadURL — адреса активу релізу.
func DownloadURL(repo, tag, asset string) string {
	return fmt.Sprintf("https://github.com/%s/releases/download/%s/%s", repo, tag, asset)
}

// Prepare складає активи в <runDir>/release: пакет (імена в zip - з прямими скісними: Compress-Archive
// пише "\"), його .sha256, DocScan-Install.ps1.
func Prepare(runDir, repo, tag string) (*Release, error) {
	full, ver, err := FullPackage(runDir)
	if err != nil {
		return nil, err
	}
	r := &Release{Repo: repo, Tag: tag, Version: tag, Build: ver, Dir: filepath.Join(runDir, "release")}
	os.RemoveAll(r.Dir)
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		return nil, err
	}
	pkg := filepath.Join(r.Dir, PkgAsset)
	if err := repack(full, pkg, "DocScan "+tag+" (build "+ver+")"); err != nil {
		return nil, err
	}
	if r.PkgSHA, err = fileSHA(pkg); err != nil {
		return nil, err
	}
	if err := os.WriteFile(pkg+".sha256", []byte(r.PkgSHA+"  "+PkgAsset+"\n"), 0o644); err != nil {
		return nil, err
	}
	inst, err := os.ReadFile(filepath.Join("docscan-project", "deploy", "DocScan-Install.ps1"))
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(r.Dir, "DocScan-Install.ps1"), inst, 0o644); err != nil {
		return nil, err
	}
	r.Assets = []string{pkg, pkg + ".sha256", filepath.Join(r.Dir, "DocScan-Install.ps1")}
	return r, nil
}

// repack переписує zip з прямими скісними в іменах; перевіряє, що це пакет DocScan. Перший рядок VERSION.txt
// замінюється на title (номер релізу + збірка), рядок VERSION.txt у SHA256SUMS.txt — на новий sha256
// (install.ps1 звіряє кожен файл).
func repack(src, dst, title string) error {
	zr, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer zr.Close()
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer f.Close()
	w := zip.NewWriter(f)
	need := map[string]bool{"bin/yara64.exe": false, "install.ps1": false, "SHA256SUMS.txt": false, "VERSION.txt": false,
		"watcher/docscan-watcher.exe": false, "watcher/docscan-watcher.ps1": false, "updater/docscan-updater.exe": false}
	read := func(e *zip.File) ([]byte, error) {
		r, err := e.Open()
		if err != nil {
			return nil, err
		}
		defer r.Close()
		return io.ReadAll(r)
	}
	// VERSION.txt: новий перший рядок; його sha256 - для SHA256SUMS.txt
	var version []byte
	for _, e := range zr.File {
		if strings.ReplaceAll(e.Name, `\`, "/") == "VERSION.txt" {
			b, err := read(e)
			if err != nil {
				return err
			}
			lines := strings.SplitN(string(b), "\n", 2)
			lines[0] = title + "\r"
			version = []byte(strings.Join(lines, "\n"))
		}
	}
	vsum := sha256.Sum256(version)
	for _, e := range zr.File {
		name := strings.ReplaceAll(e.Name, `\`, "/")
		if strings.HasSuffix(name, "/") {
			continue
		}
		if _, ok := need[name]; ok {
			need[name] = true
		}
		b, err := read(e)
		if err != nil {
			return err
		}
		switch name {
		case "VERSION.txt":
			b = version
		case "SHA256SUMS.txt":
			b = sumLineRe.ReplaceAll(b, []byte(hex.EncodeToString(vsum[:])+"  VERSION.txt"))
		}
		out, err := w.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Deflate, Modified: e.Modified})
		if err == nil {
			_, err = out.Write(b)
		}
		if err != nil {
			return err
		}
	}
	for n, ok := range need {
		if !ok {
			return fmt.Errorf("%s: no %s - not a DocScan package", src, n)
		}
	}
	return w.Close()
}

// Publish: gh release create vX.Y.Z з усіма активами (наявний реліз не перезаписується: якщо його
// пакет - саме ця збірка, це не помилка). Потім пакет качається за публічною адресою і звіряється sha256.
func (r *Release) Publish(sha string, say func(string, ...any)) error {
	url := DownloadURL(r.Repo, r.Tag, PkgAsset)
	if out, err := exec.Command("gh", "release", "view", r.Tag, "--repo", r.Repo).CombinedOutput(); err == nil {
		if err := AssetOK(url, r.PkgSHA); err != nil {
			return fmt.Errorf("release %s already exists on %s with a different package - not overwritten: %w", r.Tag, r.Repo, err)
		}
		say("\nGitHub release %s already exists, its package is this build\n    %s", r.Tag, url)
		return nil
	} else if !strings.Contains(string(out), "not found") {
		return fmt.Errorf("gh release view: %s (is gh installed and logged in?)", strings.TrimSpace(string(out)))
	}
	base := "https://github.com/" + r.Repo + "/releases/latest/download"
	notes := fmt.Sprintf("DocScan %s for Windows 10/11 x64 (build %s) - built and tested by cirun at commit %s.\n\n"+
		"The rules are NOT in this package: download the rules bundle first (a release of "+
		"https://github.com/rifatismailov/yara-docscan-rules) and give it to the installer.\n\n"+
		"Install or update (PowerShell as Administrator):\n\n"+
		"    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12\n"+
		"    $f = \"$env:TEMP\\DocScan-Install.ps1\"\n"+
		"    irm %s/DocScan-Install.ps1 -OutFile $f\n"+
		"    $r = \"<path or URL of DocScan-rules-bundle.zip>\"   # e.g. https://github.com/rifatismailov/yara-docscan-rules/releases/latest/download/DocScan-rules-bundle.zip\n"+
		"    powershell -ExecutionPolicy Bypass -File $f -Rules $r                 # standard PC\n"+
		"    powershell -ExecutionPolicy Bypass -File $f -Rules $r -DetectOnly     # pilot: detection and alerts only\n"+
		"    powershell -ExecutionPolicy Bypass -File $f -Rules $r -Critical <file or URL of critical-rules.yar>\n\n"+
		"An update of an installed PC needs no -Rules (the installed rules stay; the DocScanUpdater service updates them). "+
		"Do not run it with irm | iex: the script ends with exit and would close the window.\n\n"+
		"%s: yara64.exe, yarac64.exe, VC++ runtime, watcher, updater, install.ps1 / uninstall.ps1. "+
		"The critical-information rules (E5Search) are not part of the release.", r.Version, r.Build, sha, base, PkgAsset)
	if r.Rules != "" {
		notes += "\n\nTested with the rules " + r.Rules + " of yara-docscan-rules."
	}
	if r.Extra != "" {
		notes += "\n\n## Verified on\n\n" + r.Extra
	}
	say("\nGitHub release %s on %s", r.Tag, r.Repo)
	args := append([]string{"release", "create", r.Tag}, r.Assets...)
	args = append(args, "--repo", r.Repo, "--target", sha, "--title", "DocScan "+r.Version, "--notes", notes)
	if out, err := exec.Command("gh", args...).CombinedOutput(); err != nil {
		return fmt.Errorf("gh release create: %s", strings.TrimSpace(string(out)))
	}
	if err := AssetOK(url, r.PkgSHA); err != nil {
		return fmt.Errorf("release created, but the package does not download correctly: %w", err)
	}
	say("    %s\n    sha256 %s   OK", url, r.PkgSHA)
	say("    install on a PC:  irm %s/DocScan-Install.ps1 -OutFile $f; powershell -ExecutionPolicy Bypass -File $f", base)
	return nil
}

// AssetOK — актив доступний за адресою і має очікуваний sha256.
func AssetOK(url, want string) error {
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return err
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != want {
		return fmt.Errorf("%s: sha256 %s, expected %s", url, got, want)
	}
	return nil
}

func fileSHA(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// RepoFromRemote — "owner/repo" з адреси git remote GitHub (https://github.com/o/r.git, git@github.com:o/r.git).
func RepoFromRemote(url string) string {
	m := regexp.MustCompile(`github\.com[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$`).FindStringSubmatch(strings.TrimSpace(url))
	if m == nil {
		return ""
	}
	return m[1] + "/" + m[2]
}
