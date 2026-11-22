package main

// Правила окремо від програми (репозиторій yara-docscan-rules). Реліз правил vX.Y.Z:
//
//	DocScan-rules.zip         самі правила (docscan-index.yar, docscan-policy.yar, file-index.yar, general\, maldoc\, VERSION.txt)
//	                          і critical\*.yar — правила критичної інформації (третій прохід; watcher -CriticalRules)
//	rules-manifest.json/.sig  підписаний маніфест (продукт docscan-rules): розмір і sha256 пакета, sha256 кожного файлу
//	DocScan-rules-bundle.zip  ті самі три файли одним архівом — для ручного встановлення (install.ps1 -Rules <файл>)
//
// Встановлення (обидва шляхи — той самий код): підпис -> пакет -> кожен файл -> пробна компіляція yarac64 -> заміна
// <InstallDir>\rules (попередні — rules.prev). Updater (служба) ще зупиняє watcher перед заміною, запускає після і
// чекає "start: watching"; не стартував — повертає rules.prev і запускає знову (відкат).

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"docscan/watcher/manifest"
)

const (
	rulesManifestName = "rules-manifest.json"
	rulesSigName      = "rules-manifest.sig"
	rulesStartWait    = 3 * time.Minute
	watcherService    = "DocScanWatcher"
)

// DefaultRulesRepo — офіційний репозиторій правил.
const DefaultRulesRepo = "rifatismailov/yara-docscan-rules"

func (u *Updater) rulesDir() string { return filepath.Join(u.installDir, "rules") }

// installedRules — версія з <InstallDir>\rules\VERSION.txt ("DocScan rules v1.0.2 (…)"); правила з пакета
// програми (до окремих правил) VERSION.txt не мають — "", тобто будь-який реліз правил новіший.
func (u *Updater) installedRules() string {
	b, err := os.ReadFile(filepath.Join(u.rulesDir(), "VERSION.txt"))
	if err != nil {
		return ""
	}
	return manifest.VersionFromTitle(strings.SplitN(strings.TrimPrefix(string(b), "\ufeff"), "\n", 2)[0])
}

// rulesBase — тека з файлами релізу правил: github (найновіший / версія), дзеркало, адреса з маркера.
func (u *Updater) rulesBase(r *Request) (string, string) {
	src := r.Source
	if src == "" {
		src = u.cfg.Mode
		if src == "marker" || src == "off" {
			src = "github"
		}
	}
	switch src {
	case "github":
		if r.Version != "" {
			return "github", fmt.Sprintf("https://github.com/%s/releases/download/%s", u.cfg.Rules.GitHub.Repo, r.Version)
		}
		return "github", fmt.Sprintf("https://github.com/%s/releases/latest/download", u.cfg.Rules.GitHub.Repo)
	case "mirror":
		if u.cfg.Rules.Mirror.URL != "" {
			return "mirror", u.cfg.Rules.Mirror.URL
		}
		return "mirror", u.cfg.Mirror.URL
	}
	return "url", src
}

// checkRules — перевірка / встановлення найновіших правил (служба). Як check для програми, але ставить сам.
func (u *Updater) checkRules(r *Request, marker bool, now time.Time) Outcome {
	from := u.installedRules()
	kind, base := u.rulesBase(r)
	o := Outcome{From: from}
	fail := func(f string, a ...any) Outcome { o.Status, o.Message = "error", fmt.Sprintf(f, a...); return o }
	data, err := u.fetch(base, rulesManifestName, maxManifest)
	if err != nil {
		return fail("rules manifest: %v", err)
	}
	sig, err := u.fetch(base, rulesSigName, 4096)
	if err != nil {
		return fail("rules manifest signature: %v", err)
	}
	if r.SHA256 != "" {
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != r.SHA256 {
			return fail("rules manifest sha256 differs from the one in the marker")
		}
	}
	m, keyID, err := manifest.VerifyProduct(data, string(sig), u.keys, manifest.ProductRules)
	if err != nil {
		return fail("rules: %v", err)
	}
	o.To = m.Version
	if r.Version != "" && m.Version != r.Version {
		return fail("the source has rules %s, the marker asks for %s", m.Version, r.Version)
	}
	if c := manifest.Compare(m.Version, from); c <= 0 {
		o.Status, o.Message = "current", "rules: "+map[bool]string{true: "already installed", false: "the source has older rules " + m.Version + " - no downgrade"}[c == 0]
		return o
	}
	if !marker {
		if t, ok := u.failed()["rules:"+m.Version]; ok {
			o.Status, o.Message = "current", fmt.Sprintf("rules %s failed at %s - waiting for newer rules or a marker", m.Version, t)
			return o
		}
		if !u.cfg.inWindow(now) {
			o.Status, o.Message = "waiting", fmt.Sprintf("rules %s are available, waiting for the window %s", m.Version, u.cfg.Window)
			return o
		}
	}
	u.log.Log("INFO", "rules %s -> %s from %s (%s), signed by key %s", orNone(from), m.Version, base, kind, keyID)
	pkg, err := u.fetch(base, m.Package.Name, m.Package.Size)
	if err != nil {
		return fail("rules package: %v", err)
	}
	dir := filepath.Join(u.work(), "rules-packages", m.Version)
	if err := stageRules(m, pkg, dir); err != nil {
		return fail("rules package: %v", err)
	}
	if err := u.compileRules(dir); err != nil {
		u.markFailed("rules:"+m.Version, now)
		u.writeRecord(RecordUpdate{Status: "failed", Component: "rules", From: from, To: m.Version, Mode: u.cfg.Mode, Source: kind,
			RequestID: r.RequestID, Message: "rules " + m.Version + " do not compile, not installed: " + err.Error()})
		o.Status = "done"
		return o
	}
	status, msg := u.swapRules(dir, true)
	if status != "success" {
		u.markFailed("rules:"+m.Version, now)
	}
	u.writeRecord(RecordUpdate{Status: status, Component: "rules", From: from, To: m.Version, Mode: u.cfg.Mode, Source: kind, RequestID: r.RequestID, Message: msg})
	u.pruneRules(m.Version)
	o.Status = "done"
	return o
}

// stageRules: пакет — розмір і sha256 з маніфесту, розпакувати з перевіркою кожного файлу в dir.
func stageRules(m *manifest.Manifest, pkg []byte, dir string) error {
	h := sha256.Sum256(pkg)
	if int64(len(pkg)) != m.Package.Size || hex.EncodeToString(h[:]) != m.Package.SHA256 {
		return fmt.Errorf("%s: size / sha256 differ from the signed manifest", m.Package.Name)
	}
	if err := unpackVerified(pkg, m, dir); err != nil {
		return err
	}
	if !exists(filepath.Join(dir, "docscan-index.yar")) {
		os.RemoveAll(dir)
		return fmt.Errorf("the rules package has no docscan-index.yar")
	}
	return nil
}

// compileRules — пробна компіляція так само, як її робить watcher (yarac64 + зовнішні змінні DocScan).
func (u *Updater) compileRules(dir string) error {
	yarac := filepath.Join(u.installDir, "bin", "yarac64.exe")
	if u.compiler != nil {
		return u.compiler(dir)
	}
	if !exists(yarac) {
		return fmt.Errorf("%s is missing", yarac)
	}
	out := filepath.Join(u.work(), "rules-test.yarc")
	defer os.Remove(out)
	cmd := exec.Command(yarac, "-w", "-d", "filename=", "-d", "filepath=", "-d", "extension=", "-d", "filetype=", "-d", "owner=",
		filepath.Join(dir, "docscan-index.yar"), out)
	cmd.Dir = dir
	b, err := cmd.CombinedOutput()
	if err != nil || !exists(out) {
		return fmt.Errorf("yarac64: %v %s", err, strings.TrimSpace(string(b)))
	}
	return u.compileCritical(filepath.Join(dir, "critical"))
}

// compileCritical — critical\*.yar пакета (якщо є) компілюються разом так, як їх компілює yara64 на скануванні
// (--critical-rules=<тека>): основні правила — одне порожнє правило, файл — пробний.
func (u *Updater) compileCritical(dir string) error {
	ents, _ := os.ReadDir(dir)
	n := 0
	for _, e := range ents {
		if !e.IsDir() && strings.EqualFold(filepath.Ext(e.Name()), ".yar") {
			n++
		}
	}
	if n == 0 {
		return nil
	}
	yara := filepath.Join(u.installDir, "bin", "yara64.exe")
	if !exists(yara) {
		return fmt.Errorf("%s is missing (needed to check the critical rules)", yara)
	}
	tmp, err := os.MkdirTemp(u.work(), "critical-test-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	empty, probe := filepath.Join(tmp, "empty.yar"), filepath.Join(tmp, "probe.txt")
	os.WriteFile(empty, []byte("rule docscan_critical_probe { condition: false }\n"), 0o644)
	os.WriteFile(probe, []byte("probe\r\n"), 0o644)
	b, _ := exec.Command(yara, "-w", "--critical-rules="+dir, "--critical-out="+filepath.Join(tmp, "q.json"), empty, probe).CombinedOutput()
	var errs []string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(strings.ToLower(l), "error") {
			errs = append(errs, strings.TrimSpace(l))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("critical rules: %s", strings.Join(errs, "; "))
	}
	return nil
}

// swapRules: <InstallDir>\rules -> rules.prev, нові — на місце. restart: служба — зупинити watcher до і запустити
// після, дочекатися "start: watching"; інакше — rules.prev назад (відкат). Повертає статус запису і пояснення.
func (u *Updater) swapRules(staged string, restart bool) (string, string) {
	cur, prev := u.rulesDir(), u.rulesDir()+".prev"
	from, to := u.installedRules(), versionOfDir(staged)
	if restart {
		if err := u.svc.Stop(watcherService); err != nil {
			return "failed", "stop " + watcherService + ": " + err.Error()
		}
	}
	os.RemoveAll(prev)
	if exists(cur) {
		if err := os.Rename(cur, prev); err != nil {
			if restart {
				u.svc.Start(watcherService)
			}
			return "failed", "move the current rules aside: " + err.Error()
		}
	}
	if err := copyTree(staged, cur); err != nil {
		os.RemoveAll(cur)
		os.Rename(prev, cur)
		if restart {
			u.svc.Start(watcherService)
		}
		return "failed", "copy the new rules: " + err.Error()
	}
	if !restart {
		return "success", fmt.Sprintf("rules %s installed", to)
	}
	if err := u.startAndWait(); err == nil {
		return "success", fmt.Sprintf("rules updated %s -> %s", orNone(from), to)
	} else {
		u.log.Log("WARN", "the watcher did not start with rules %s (%v) - rolling back to %s", to, err, orNone(from))
		u.svc.Stop(watcherService)
		os.RemoveAll(cur)
		if exists(prev) {
			os.Rename(prev, cur)
		}
		if err2 := u.startAndWait(); err2 != nil {
			return "failed", fmt.Sprintf("rules %s: the watcher did not start (%v); the rollback to %s did not help either: %v", to, err, orNone(from), err2)
		}
		return "rollback", fmt.Sprintf("rules %s: the watcher did not start (%v); rolled back to %s", to, err, orNone(from))
	}
}

// startAndWait — запустити watcher і дочекатися його рядка "start: watching" (записаного після запуску).
func (u *Updater) startAndWait() error {
	log := filepath.Join(u.dataDir, "results", "watcher.log")
	var mark int64
	if st, err := os.Stat(log); err == nil {
		mark = st.Size()
	}
	if err := u.svc.Start(watcherService); err != nil {
		return err
	}
	deadline := time.Now().Add(rulesStartWait)
	for time.Now().Before(deadline) {
		time.Sleep(u.poll)
		if tail := readFrom(log, mark); tail != "" {
			if strings.Contains(tail, "start: watching") {
				return nil
			}
			if i := strings.Index(tail, "[ERROR]"); i >= 0 {
				line := tail[i:]
				if j := strings.IndexAny(line, "\r\n"); j > 0 {
					line = line[:j]
				}
				return fmt.Errorf("watcher: %s", line)
			}
		}
	}
	return fmt.Errorf("no \"start: watching\" in watcher.log within %s", rulesStartWait)
}

func readFrom(p string, off int64) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	if st, _ := f.Stat(); st != nil && st.Size() < off {
		off = 0 // журнал перейшов на новий файл
	}
	f.Seek(off, io.SeekStart)
	b, _ := io.ReadAll(io.LimitReader(f, 1<<20))
	return string(b)
}

func versionOfDir(dir string) string {
	b, _ := os.ReadFile(filepath.Join(dir, "VERSION.txt"))
	return orNone(manifest.VersionFromTitle(strings.SplitN(strings.TrimPrefix(string(b), "\ufeff"), "\n", 2)[0]))
}

func copyTree(src, dst string) error {
	return filepath.Walk(src, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		t := filepath.Join(dst, rel)
		if fi.IsDir() {
			return os.MkdirAll(t, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(t, b, 0o644)
	})
}

// pruneRules — у rules-packages лишається лише остання версія.
func (u *Updater) pruneRules(keep string) {
	ents, _ := os.ReadDir(filepath.Join(u.work(), "rules-packages"))
	for _, e := range ents {
		if e.Name() != keep {
			os.RemoveAll(filepath.Join(u.work(), "rules-packages", e.Name()))
		}
	}
}

// installRulesFile — install.ps1 -Rules: пакет для ручного встановлення (DocScan-rules-bundle.zip або тека з
// rules-manifest.json, rules-manifest.sig і пакетом) -> ті самі перевірки -> <InstallDir>\rules. Watcher тут
// не чіпається: його запускає інсталятор.
func (u *Updater) installRulesFile(src string) (string, error) {
	files := map[string][]byte{}
	if st, err := os.Stat(src); err == nil && st.IsDir() {
		ents, _ := os.ReadDir(src)
		for _, e := range ents {
			if !e.IsDir() {
				if b, err := os.ReadFile(filepath.Join(src, e.Name())); err == nil {
					files[e.Name()] = b
				}
			}
		}
	} else {
		b, err := os.ReadFile(src)
		if err != nil {
			return "", err
		}
		zr, err := zip.NewReader(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			return "", fmt.Errorf("%s: not a zip: %w", src, err)
		}
		for _, e := range zr.File {
			if e.FileInfo().IsDir() || strings.ContainsAny(e.Name, `/\`) || e.UncompressedSize64 > 512<<20 {
				continue // лише файли верхнього рівня пакета
			}
			rc, err := e.Open()
			if err != nil {
				return "", err
			}
			files[e.Name], err = io.ReadAll(io.LimitReader(rc, 512<<20))
			rc.Close()
			if err != nil {
				return "", err
			}
		}
	}
	data, sig := files[rulesManifestName], files[rulesSigName]
	if data == nil || sig == nil {
		return "", fmt.Errorf("%s: no %s / %s - expected DocScan-rules-bundle.zip from a yara-docscan-rules release", src, rulesManifestName, rulesSigName)
	}
	m, keyID, err := manifest.VerifyProduct(data, string(sig), u.keys, manifest.ProductRules)
	if err != nil {
		return "", err
	}
	pkg := files[m.Package.Name]
	if pkg == nil {
		return "", fmt.Errorf("%s: no %s", src, m.Package.Name)
	}
	if c := manifest.Compare(m.Version, u.installedRules()); c < 0 {
		return "", fmt.Errorf("rules %s are older than the installed %s - no downgrade", m.Version, u.installedRules())
	}
	dir := filepath.Join(u.work(), "rules-packages", m.Version)
	if err := stageRules(m, pkg, dir); err != nil {
		return "", err
	}
	if err := u.compileRules(dir); err != nil {
		return "", fmt.Errorf("rules %s do not compile: %w", m.Version, err)
	}
	if st, msg := u.swapRules(dir, false); st != "success" {
		return "", fmt.Errorf("%s", msg)
	}
	u.pruneRules(m.Version)
	return fmt.Sprintf("rules %s (signed by key %s, %d files)", m.Version, keyID, len(m.Files)), nil
}
