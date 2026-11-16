package deploy

// Реліз на GitHub (cirun --release): програма (bin\ - yara64.exe, yarac64.exe, рантайм VC++) лежить
// ЛИШЕ в релізах GitHub, з версією; внутрішній сервер тримає решту пакета (правила, watcher, скрипти)
// без bin\. Пакет з Windows (DocScan-<версія>.zip, повний - ним користуються тести) ділиться на два:
//
//   DocScan-bin-<версія>.zip   bin\* - актив релізу docscan-<версія> на GitHub (+ .sha256);
//   DocScan-<версія>.zip       усе, крім bin\, + BIN-URL.txt (адреса активу) - внутрішній сервер.
//
// SHA256SUMS.txt лишається повним: у ньому і хеші bin\*. DocScan-Install.ps1 качає bin з GitHub, а
// install.ps1 звіряє ВСІ файли з SHA256SUMS.txt внутрішнього пакета - підмінений на GitHub exe не
// встановиться (довіра - внутрішньому серверу, GitHub - лише сховище).

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

// Release — актив релізу: тег, локальний файл, його sha256 і адреса завантаження.
type Release struct {
	Repo, Tag, BinZip, BinSHA, URL string
}

var verRe = regexp.MustCompile(`^DocScan-(\d{8}-[0-9a-f]+)\.zip$`)

// FullPackage — найновіший повний пакет прогону: <runDir>/<платформа>/DocScan-<версія>.zip.
func FullPackage(runDir string) (path, version string, err error) {
	zips, _ := filepath.Glob(filepath.Join(runDir, "*", "DocScan-*.zip"))
	var full []string
	for _, z := range zips {
		d := filepath.Base(filepath.Dir(z))
		if d != "deploy" && d != "release" && verRe.MatchString(filepath.Base(z)) {
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

// AssetURL — адреса активу релізу на GitHub.
func AssetURL(repo, version string) string {
	return fmt.Sprintf("https://github.com/%s/releases/download/docscan-%s/DocScan-bin-%s.zip", repo, version, version)
}

// Split ділить повний пакет: DocScan-bin-<v>.zip (лише bin/) і DocScan-<v>.zip (без bin/, + BIN-URL.txt)
// у теці dir. Імена в zip - з прямими скісними (Compress-Archive пише "\"). Повертає шляхи обох.
func Split(full, version, binURL, dir string) (binZip, pkgZip string, err error) {
	zr, err := zip.OpenReader(full)
	if err != nil {
		return "", "", err
	}
	defer zr.Close()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	binZip = filepath.Join(dir, "DocScan-bin-"+version+".zip")
	pkgZip = filepath.Join(dir, "DocScan-"+version+".zip")
	bf, err := os.Create(binZip)
	if err != nil {
		return "", "", err
	}
	defer bf.Close()
	pf, err := os.Create(pkgZip)
	if err != nil {
		return "", "", err
	}
	defer pf.Close()
	bw, pw := zip.NewWriter(bf), zip.NewWriter(pf)
	nbin, hasSums := 0, false
	for _, f := range zr.File {
		name := strings.ReplaceAll(f.Name, `\`, "/")
		if strings.HasSuffix(name, "/") {
			continue
		}
		w := pw
		if strings.HasPrefix(strings.ToLower(name), "bin/") {
			w = bw
			nbin++
		}
		if name == "SHA256SUMS.txt" {
			hasSums = true
		}
		if err := copyEntry(w, f, name); err != nil {
			return "", "", err
		}
	}
	if nbin == 0 || !hasSums {
		return "", "", fmt.Errorf("%s: no bin/ or no SHA256SUMS.txt - not a DocScan package", full)
	}
	hw, err := pw.CreateHeader(&zip.FileHeader{Name: "BIN-URL.txt", Method: zip.Deflate, Modified: time.Now()})
	if err != nil {
		return "", "", err
	}
	io.WriteString(hw, binURL+"\r\n")
	if err := bw.Close(); err != nil {
		return "", "", err
	}
	if err := pw.Close(); err != nil {
		return "", "", err
	}
	for _, z := range []string{binZip, pkgZip} {
		s, err := fileSHA(z)
		if err != nil {
			return "", "", err
		}
		os.WriteFile(z+".sha256", []byte(s+"  "+filepath.Base(z)+"\n"), 0o644)
	}
	return binZip, pkgZip, nil
}

func copyEntry(w *zip.Writer, f *zip.File, name string) error {
	r, err := f.Open()
	if err != nil {
		return err
	}
	defer r.Close()
	h := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: f.Modified}
	out, err := w.CreateHeader(h)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, r)
	return err
}

// Publish на GitHub: gh release create docscan-<v> (тег на протестований і запушений коміт) з активом
// DocScan-bin-<v>.zip і .sha256; наявний реліз не перезаписується. Потім актив качається за публічною
// адресою і звіряється sha256 - так його отримає ПК.
func (r *Release) Publish(sha string, say func(string, ...any)) error {
	if out, err := exec.Command("gh", "release", "view", r.Tag, "--repo", r.Repo).CombinedOutput(); err == nil {
		return fmt.Errorf("release %s already exists on %s - not overwritten", r.Tag, r.Repo)
	} else if !strings.Contains(string(out), "not found") {
		return fmt.Errorf("gh release view: %s (is gh installed and logged in?)", strings.TrimSpace(string(out)))
	}
	notes := fmt.Sprintf("DocScan %s - yara64.exe / yarac64.exe (Windows x64) built and tested by cirun at commit %s.\n\n"+
		"Installed by DocScan-Install.ps1 from the internal deployment server: the files are verified against the "+
		"SHA256SUMS.txt of the internal package, not only against the .sha256 here.", strings.TrimPrefix(r.Tag, "docscan-"), sha)
	say("\nGitHub release %s on %s", r.Tag, r.Repo)
	c := exec.Command("gh", "release", "create", r.Tag, r.BinZip, r.BinZip+".sha256", "--repo", r.Repo,
		"--target", sha, "--title", "DocScan "+strings.TrimPrefix(r.Tag, "docscan-"), "--notes", notes)
	if out, err := c.CombinedOutput(); err != nil {
		return fmt.Errorf("gh release create: %s", strings.TrimSpace(string(out)))
	}
	got, err := urlSHA(r.URL)
	if err != nil {
		return fmt.Errorf("release created, but the asset does not download: %w", err)
	}
	if got != r.BinSHA {
		return fmt.Errorf("release asset sha256 %s, expected %s", got, r.BinSHA)
	}
	say("    %s\n    sha256 %s   OK", r.URL, got)
	return nil
}

// AssetOK — актив релізу доступний і має очікуваний sha256 (перед викладанням на внутрішній сервер).
func AssetOK(url, want string) error {
	got, err := urlSHA(url)
	if err != nil {
		return err
	}
	if got != want {
		return fmt.Errorf("%s: sha256 %s, expected %s", url, got, want)
	}
	return nil
}

func urlSHA(u string) (string, error) {
	resp, err := (&http.Client{Timeout: 5 * time.Minute}).Get(u)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: %s", u, resp.Status)
	}
	h := sha256.New()
	if _, err := io.Copy(h, resp.Body); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
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

// Prepare ділить пакет прогону в <runDir>/release і повертає опис релізу (ще не опублікованого).
func Prepare(runDir, repo string) (*Release, string, error) {
	full, ver, err := FullPackage(runDir)
	if err != nil {
		return nil, "", err
	}
	url := AssetURL(repo, ver)
	binZip, pkgZip, err := Split(full, ver, url, filepath.Join(runDir, "release"))
	if err != nil {
		return nil, "", err
	}
	s, err := fileSHA(binZip)
	if err != nil {
		return nil, "", err
	}
	return &Release{Repo: repo, Tag: "docscan-" + ver, BinZip: binZip, BinSHA: s, URL: url}, pkgZip, nil
}

// RepoFromRemote — "owner/repo" з адреси git remote GitHub (https://github.com/o/r.git, git@github.com:o/r.git).
func RepoFromRemote(url string) string {
	m := regexp.MustCompile(`github\.com[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?/?$`).FindStringSubmatch(strings.TrimSpace(url))
	if m == nil {
		return ""
	}
	return m[1] + "/" + m[2]
}
