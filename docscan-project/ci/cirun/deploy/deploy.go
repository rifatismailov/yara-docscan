// Package deploy — набір для розгортання (пакет Windows + інсталятори з адресою сервера) і його
// публікація на сервер розгортання: scp, перевірка sha256 на сервері, лише потім DocScan-latest.txt.
package deploy

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"docscan/cirun/config"
)

// Set — готовий набір у теці Dir; Pkg — ім'я пакета (DocScan-<дата>-<коміт>.zip).
type Set struct {
	Dir, Pkg string
}

// Base — HTTP-адреса теки розгортання: deploy.url, інакше http://<host>:8080/docscan.
func Base(d config.Deploy) string {
	if d.URL != "" {
		return strings.TrimRight(d.URL, "/")
	}
	h := d.Host
	if h == "" {
		h = "<server>"
	}
	return "http://" + h + ":8080/docscan"
}

// Build складає набір у <runDir>/deploy з найновішого <runDir>/*/DocScan-*.zip (nil — пакета немає):
// пакет + .sha256, DocScan-latest.txt, DocScan-Install.ps1, три завантажувачі DocScan-Setup*.ps1 з
// адресою сервера (шаблон — лише ASCII, бо його виконує «irm | iex»; рядки — CRLF), critical-rules.yar.
func Build(runDir string, d config.Deploy, say func(string, ...any)) (*Set, error) {
	zips, _ := filepath.Glob(filepath.Join(runDir, "*", "DocScan-*.zip"))
	if len(zips) == 0 {
		say("\n(no Windows package in this run - no deployment set)")
		return nil, nil
	}
	sort.Strings(zips)
	zipPath := zips[len(zips)-1]
	base := Base(d)
	dir := filepath.Join(runDir, "deploy")
	os.RemoveAll(dir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	pkg := filepath.Base(zipPath)
	for _, cp := range [][2]string{{zipPath, pkg}, {zipPath + ".sha256", pkg + ".sha256"},
		{filepath.Join("docscan-project", "deploy", "DocScan-Install.ps1"), "DocScan-Install.ps1"}} {
		if err := copyFile(cp[0], filepath.Join(dir, cp[1])); err != nil {
			return nil, err
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "DocScan-latest.txt"), []byte(pkg+"\n"), 0o644); err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(filepath.Join("docscan-project", "deploy", "DocScan-Setup.ps1"))
	if err != nil {
		return nil, err
	}
	for _, b := range raw {
		if b > 127 {
			return nil, fmt.Errorf("DocScan-Setup.ps1 must be ASCII only (it is run by irm | iex)")
		}
	}
	tpl := strings.ReplaceAll(string(raw), "\r\n", "\n")
	tpl = strings.ReplaceAll(tpl, "'http://<server>:8080/docscan'", "'"+base+"'")
	tpl = strings.ReplaceAll(tpl, "http://<server>:8080/docscan", base)
	for _, v := range [][2]string{{"DocScan-Setup.ps1", ""}, {"DocScan-Setup-Pilot.ps1", "'-DetectOnly'"}, {"DocScan-Setup-Critical.ps1", "'-Critical'"}} {
		t := tpl
		if v[1] != "" {
			t = strings.Replace(tpl, "$InstallArg = @()", "$InstallArg = @("+v[1]+")", 1)
		}
		if err := os.WriteFile(filepath.Join(dir, v[0]), []byte(strings.ReplaceAll(t, "\n", "\r\n")), 0o644); err != nil {
			return nil, err
		}
	}
	crit := os.Getenv("DOCSCAN_CRITICAL_RULES")
	if crit == "" {
		crit = d.CriticalRules
	}
	if crit = config.ExpandHome(crit); crit != "" {
		if st, err := os.Stat(crit); err == nil && st.Mode().IsRegular() {
			copyFile(crit, filepath.Join(dir, "critical-rules.yar"))
		}
	}
	abs, _ := filepath.Abs(dir)
	say("\ndeployment set: %s", abs)
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if st, err := e.Info(); err == nil {
			say("    %-34s %8d bytes", e.Name(), st.Size())
		}
	}
	return &Set{Dir: dir, Pkg: pkg}, nil
}

// Publish викладає набір: ssh mkdir -> scp усіх файлів, КРІМ DocScan-latest.txt -> sha256sum -c на
// сервері -> лише тоді scp DocScan-latest.txt (жоден ПК не отримає недокачаний пакет) -> перевірка HTTP.
// Пароль — через змінну SSHPASS для sshpass -e, не в командному рядку.
func Publish(s *Set, d config.Deploy, sec *config.Resolver, say func(string, ...any)) error {
	user := d.User
	if user == "" {
		u, err := sec.Get(d.UserRef)
		if err != nil {
			return err
		}
		user = u
	}
	pass, err := sec.Get(d.PasswordRef)
	if err != nil {
		return err
	}
	if d.Host == "" || user == "" || pass == "" {
		return fmt.Errorf("deploy: host, user and password_ref are required")
	}
	target := user + "@" + d.Host
	env := append(os.Environ(), "SSHPASS="+pass)
	var files []string
	entries, _ := os.ReadDir(s.Dir)
	for _, e := range entries {
		if e.Name() != "DocScan-latest.txt" {
			files = append(files, filepath.Join(s.Dir, e.Name()))
		}
	}
	say("\npublish to %s:%s", target, d.Dir)
	ssh := []string{"-e", "ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10", target}
	runC := func(args ...string) error {
		c := exec.Command("sshpass", args...)
		c.Env, c.Stdout, c.Stderr = env, os.Stdout, os.Stderr
		return c.Run()
	}
	scp := func(src ...string) error {
		return runC(append(append([]string{"-e", "scp", "-q"}, src...), target+":"+d.Dir+"/")...)
	}
	if err := runC(append(ssh, "mkdir -p '"+d.Dir+"'")...); err != nil {
		return fmt.Errorf("ssh mkdir: %w (is sshpass installed?)", err)
	}
	if err := scp(files...); err != nil {
		return fmt.Errorf("scp: %w", err)
	}
	c := exec.Command("sshpass", append(ssh, "cd '"+d.Dir+"' && sha256sum -c '"+s.Pkg+".sha256'")...)
	c.Env = env
	chk, err := c.CombinedOutput()
	say("    %s", strings.TrimSpace(string(chk)))
	if err != nil {
		return fmt.Errorf("the package on the server does not match its sha256 - DocScan-latest.txt NOT switched")
	}
	if err := scp(filepath.Join(s.Dir, "DocScan-latest.txt")); err != nil {
		return fmt.Errorf("scp DocScan-latest.txt: %w", err)
	}
	base := Base(d)
	latest, err1 := httpGet(base + "/DocScan-latest.txt")
	setup, err2 := httpGet(base + "/DocScan-Setup.ps1")
	if err1 != nil || err2 != nil {
		return fmt.Errorf("HTTP check failed: %v %v", err1, err2)
	}
	if strings.TrimSpace(latest) != s.Pkg || !strings.Contains(setup, base) {
		return fmt.Errorf("HTTP check: %s/DocScan-latest.txt -> %s (expected %s)", base, strings.TrimSpace(latest), s.Pkg)
	}
	say("    %s/DocScan-latest.txt -> %s   OK", base, s.Pkg)
	say("    install on a PC:  irm %s/DocScan-Setup.ps1 | iex", base)
	return nil
}

// ExistingSet — набір з готової теки (--publish-dir): найновіший DocScan-*.zip у ній.
func ExistingSet(dir string) (*Set, error) {
	dir, _ = filepath.Abs(dir)
	zips, _ := filepath.Glob(filepath.Join(dir, "DocScan-*.zip"))
	if len(zips) == 0 {
		return nil, fmt.Errorf("no DocScan-*.zip in %s", dir)
	}
	sort.Strings(zips)
	return &Set{Dir: dir, Pkg: filepath.Base(zips[len(zips)-1])}, nil
}

func httpGet(u string) (string, error) {
	r, err := (&http.Client{Timeout: 15 * time.Second}).Get(u)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", fmt.Errorf("%s: %s", u, r.Status)
	}
	b, err := io.ReadAll(r.Body)
	return string(b), err
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
