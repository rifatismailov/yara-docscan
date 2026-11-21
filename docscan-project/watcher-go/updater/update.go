package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"docscan/watcher/manifest"
)

// Оновлення (порядок дій):
//
//	1. маніфест + підпис з джерела -> підпис одного з довірених ключів, продукт, версія новіша за встановлену
//	   (на старішу — ніколи), для маркера — ще його version / sha256;
//	2. пакет -> розмір і sha256 з маніфесту -> розпакувати в <DataDir>\update\packages\<версія> (zip-slip, ліміт
//	   розміру) -> sha256 КОЖНОГО файлу з маніфестом, зайвих файлів немає;
//	3. state.json (що, звідки, на що) -> install.ps1 з цього пакета: -Reuse (ті самі параметри, що на ПК зараз:
//	   install.json) -ResultFile. Інсталятор зупиняє watcher і updater, замінює файли, перевіряє правила, запускає
//	   службу і чекає "start: watching"; результат — у install-result.json;
//	4. updater (новий, після перезапуску інсталятором) читає state.json + результат: успіх — запис "success";
//	   невдача — install.ps1 попереднього пакета (packages\<стара версія>) так само -Reuse = відкат, запис "rollback".
//
// Записи для агента — <DataDir>\results\docscan-updates.json (рядок JSON на подію), журнал — updater.log.

// Імена файлів релізу (як у cirun deploy: однакові в усіх релізах).
const (
	manifestName = "manifest.json"
	sigName      = "manifest.sig"
	maxManifest  = 4 << 20
	maxUnpacked  = 4 << 30
	installWait  = 25 * time.Minute
)

// Launcher запускає install.ps1 з теки пакета (від'єднано: інсталятор зупинить і цю службу).
type Launcher func(pkgDir, resultFile, logFile string) error

type Updater struct {
	cfg        *Config
	dataDir    string
	installDir string
	keys       []string
	log        *logger
	launch     Launcher
	host       string
	http       *http.Client
	lastErr    map[string]time.Time
	svc        services               // зупинка / запуск watcher-а (заміна правил)
	compiler   func(dir string) error // тест: замість yarac64
	poll       time.Duration          // як часто дивитися watcher.log після запуску
	listsNext  time.Time              // наступна перевірка списків організації (lists.go)
}

// services — служби Windows (svc_windows.go); тест підставляє свої.
type services interface {
	Stop(name string) error
	Start(name string) error
}

func (u *Updater) work() string           { return filepath.Join(u.dataDir, "update") }
func (u *Updater) pkgDir(v string) string { return filepath.Join(u.work(), "packages", v) }
func (u *Updater) stateFile() string      { return filepath.Join(u.work(), "state.json") }
func (u *Updater) resultFile() string     { return filepath.Join(u.work(), "install-result.json") }
func (u *Updater) failedFile() string     { return filepath.Join(u.work(), "failed.json") }

// installed — версія з <InstallDir>\VERSION.txt ("DocScan v1.0.3 (build …)"); старі збірки без vX.Y.Z — "".
func (u *Updater) installed() string {
	b, err := os.ReadFile(filepath.Join(u.installDir, "VERSION.txt"))
	if err != nil {
		return ""
	}
	return manifest.VersionFromTitle(strings.SplitN(strings.TrimPrefix(string(b), "\ufeff"), "\n", 2)[0])
}

// base — тека з файлами релізу для запиту: github (найновіший або конкретна версія), дзеркало, адреса з маркера.
func (u *Updater) base(r *Request) (string, string) {
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
			return "github", fmt.Sprintf("https://github.com/%s/releases/download/%s", u.cfg.GitHub.Repo, r.Version)
		}
		return "github", fmt.Sprintf("https://github.com/%s/releases/latest/download", u.cfg.GitHub.Repo)
	case "mirror":
		return "mirror", u.cfg.Mirror.URL
	}
	return "url", src
}

// fetch — файл name з теки base (http(s) або шлях / UNC) у пам'ять, не більше limit байт.
func (u *Updater) fetch(base, name string, limit int64) ([]byte, error) {
	var rc io.ReadCloser
	if strings.HasPrefix(base, "http://") || strings.HasPrefix(base, "https://") {
		resp, err := u.http.Get(strings.TrimRight(base, "/") + "/" + name)
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != 200 {
			resp.Body.Close()
			return nil, fmt.Errorf("%s/%s: %s", strings.TrimRight(base, "/"), name, resp.Status)
		}
		rc = resp.Body
	} else {
		f, err := os.Open(filepath.Join(base, name))
		if err != nil {
			return nil, err
		}
		rc = f
	}
	defer rc.Close()
	b, err := io.ReadAll(io.LimitReader(rc, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, limit)
	}
	return b, nil
}

// Outcome — результат перевірки.
type Outcome struct {
	Status  string // current | waiting | started | error
	From    string
	To      string
	Message string
}

// check — одна перевірка: періодична (marker=false) або за маркером агента. Ставить оновлення, якщо воно є.
func (u *Updater) check(r *Request, marker bool, now time.Time) Outcome {
	from := u.installed()
	srcKind, base := u.base(r)
	o := Outcome{From: from}
	fail := func(f string, a ...any) Outcome { o.Status, o.Message = "error", fmt.Sprintf(f, a...); return o }

	data, err := u.fetch(base, manifestName, maxManifest)
	if err != nil {
		return fail("manifest: %v", err)
	}
	sig, err := u.fetch(base, sigName, 4096)
	if err != nil {
		return fail("manifest signature: %v", err)
	}
	if r.SHA256 != "" {
		h := sha256.Sum256(data)
		if hex.EncodeToString(h[:]) != r.SHA256 {
			return fail("manifest sha256 differs from the one in the marker")
		}
	}
	m, keyID, err := manifest.VerifyProduct(data, string(sig), u.keys, manifest.Product)
	if err != nil {
		return fail("%v", err)
	}
	o.To = m.Version
	if r.Version != "" && m.Version != r.Version {
		return fail("the source has %s, the marker asks for %s", m.Version, r.Version)
	}
	switch c := manifest.Compare(m.Version, from); {
	case c == 0:
		o.Status, o.Message = "current", "already installed"
		return o
	case c < 0:
		o.Status, o.Message = "current", fmt.Sprintf("the source has an older version %s - no downgrade", m.Version)
		return o
	}
	if !marker {
		if t, ok := u.failed()[m.Version]; ok {
			o.Status, o.Message = "current", fmt.Sprintf("%s failed to install at %s - waiting for a newer release or a marker", m.Version, t)
			return o
		}
		if !u.cfg.inWindow(now) {
			o.Status, o.Message = "waiting", fmt.Sprintf("%s is available, waiting for the window %s", m.Version, u.cfg.Window)
			return o
		}
	}
	u.log.Log("INFO", "update %s -> %s from %s (%s), signed by key %s", orNone(from), m.Version, base, srcKind, keyID)

	pkg, err := u.fetch(base, m.Package.Name, m.Package.Size)
	if err != nil {
		return fail("package: %v", err)
	}
	h := sha256.Sum256(pkg)
	if int64(len(pkg)) != m.Package.Size || hex.EncodeToString(h[:]) != m.Package.SHA256 {
		return fail("package %s: size / sha256 differ from the signed manifest", m.Package.Name)
	}
	dir := u.pkgDir(m.Version)
	if err := unpackVerified(pkg, m, dir); err != nil {
		return fail("package: %v", err)
	}
	os.WriteFile(filepath.Join(dir, manifestName), data, 0o644)
	os.WriteFile(filepath.Join(dir, sigName), sig, 0o644)

	st := &State{Phase: "install", RequestID: r.RequestID, From: from, To: m.Version, Source: srcKind, Started: now}
	if err := u.saveState(st); err != nil {
		return fail("state: %v", err)
	}
	os.Remove(u.resultFile())
	if err := u.launch(dir, u.resultFile(), filepath.Join(u.work(), "install-"+m.Version+".log")); err != nil {
		os.Remove(u.stateFile())
		return fail("start install.ps1: %v", err)
	}
	o.Status, o.Message = "started", "install.ps1 started"
	u.log.Log("INFO", "install.ps1 of %s started (the installer restarts the services)", m.Version)
	return o
}

// unpackVerified розпаковує пакет у dir: лише файли з маніфесту, кожен — з його sha256; інакше теки немає.
func unpackVerified(pkg []byte, m *manifest.Manifest, dir string) error {
	zr, err := zip.NewReader(bytes.NewReader(pkg), int64(len(pkg)))
	if err != nil {
		return err
	}
	tmp := dir + ".tmp"
	os.RemoveAll(tmp)
	ok := false
	defer func() {
		if !ok {
			os.RemoveAll(tmp)
		}
	}()
	seen := map[string]bool{}
	var total int64
	for _, e := range zr.File {
		if e.FileInfo().IsDir() {
			continue
		}
		want, listed := m.Files[e.Name]
		if !listed || !manifest.SafePath(e.Name) {
			return fmt.Errorf("unexpected file in the package: %q", e.Name)
		}
		if seen[e.Name] {
			return fmt.Errorf("file twice in the package: %q", e.Name)
		}
		seen[e.Name] = true
		dst := filepath.Join(tmp, filepath.FromSlash(e.Name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return err
		}
		rc, err := e.Open()
		if err != nil {
			return err
		}
		f, err := os.Create(dst)
		if err != nil {
			rc.Close()
			return err
		}
		h := sha256.New()
		n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(rc, maxUnpacked-total+1))
		rc.Close()
		f.Close()
		if err != nil {
			return err
		}
		if total += n; total > maxUnpacked {
			return fmt.Errorf("the package unpacks to more than %d bytes", int64(maxUnpacked))
		}
		if hex.EncodeToString(h.Sum(nil)) != want {
			return fmt.Errorf("%s: sha256 differs from the signed manifest", e.Name)
		}
	}
	if len(seen) != len(m.Files) {
		return fmt.Errorf("the package has %d of %d files of the manifest", len(seen), len(m.Files))
	}
	os.RemoveAll(dir)
	if err := os.Rename(tmp, dir); err != nil {
		return err
	}
	ok = true
	return nil
}

// State — оновлення, що триває (переживає перезапуск updater-а інсталятором).
type State struct {
	Phase     string    `json:"phase"` // install | rollback
	RequestID string    `json:"request_id,omitempty"`
	From      string    `json:"from"`
	To        string    `json:"to"`
	Source    string    `json:"source"`
	Started   time.Time `json:"started"`
	Error     string    `json:"error,omitempty"` // чому не вдалося встановити To (для запису після відкату)
}

// InstallResult — що пише install.ps1 -ResultFile.
type InstallResult struct {
	OK      bool   `json:"ok"`
	Version string `json:"version"`
	Error   string `json:"error"`
}

func (u *Updater) saveState(s *State) error {
	os.MkdirAll(u.work(), 0o755)
	b, _ := json.MarshalIndent(s, "", "  ")
	return os.WriteFile(u.stateFile(), b, 0o644)
}

func (u *Updater) loadState() *State {
	b, err := os.ReadFile(u.stateFile())
	if err != nil {
		return nil
	}
	var s State
	if json.Unmarshal(b, &s) != nil || (s.Phase != "install" && s.Phase != "rollback") {
		os.Remove(u.stateFile())
		return nil
	}
	return &s
}

// busy — оновлення вже триває.
func (u *Updater) busy() bool { return u.loadState() != nil }

// handleState — завершує оновлення, що триває: успіх, відкат або остаточна помилка.
func (u *Updater) handleState(now time.Time) {
	s := u.loadState()
	if s == nil {
		return
	}
	var res *InstallResult
	if b, err := os.ReadFile(u.resultFile()); err == nil {
		var r InstallResult
		if json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &r) == nil {
			res = &r
		}
	}
	if res == nil {
		if now.Sub(s.Started) < installWait {
			return // інсталятор ще працює
		}
		res = &InstallResult{Error: fmt.Sprintf("install.ps1 gave no result in %s", installWait)}
	}
	os.Remove(u.resultFile())
	cur := u.installed()
	switch s.Phase {
	case "install":
		if res.OK && cur == s.To {
			os.Remove(u.stateFile())
			u.record("success", s, fmt.Sprintf("updated %s -> %s", orNone(s.From), s.To))
			u.prune(s.To, s.From)
			return
		}
		msg := res.Error
		if msg == "" {
			msg = fmt.Sprintf("installed version is %s, expected %s", orNone(cur), s.To)
		}
		u.markFailed(s.To, now)
		prev := u.pkgDir(s.From)
		if s.From == "" || !exists(filepath.Join(prev, "install.ps1")) {
			os.Remove(u.stateFile())
			u.record("failed", s, "update to "+s.To+" failed: "+msg+"; no previous package to roll back to")
			return
		}
		u.log.Log("WARN", "update to %s failed (%s) - rolling back to %s", s.To, msg, s.From)
		s.Phase, s.Started, s.Error = "rollback", now, msg
		u.saveState(s)
		if err := u.launch(prev, u.resultFile(), filepath.Join(u.work(), "install-"+s.From+"-rollback.log")); err != nil {
			os.Remove(u.stateFile())
			u.record("failed", s, "update to "+s.To+" failed: "+msg+"; rollback could not start: "+err.Error())
		}
	case "rollback":
		os.Remove(u.stateFile())
		if res.OK && cur == s.From {
			u.record("rollback", s, "update to "+s.To+" failed: "+s.Error+"; rolled back to "+s.From)
		} else {
			u.record("failed", s, "update to "+s.To+" failed: "+s.Error+"; the rollback to "+s.From+" failed too: "+res.Error)
		}
	}
}

// failed — версії, що не встановились (періодична перевірка їх не повторює; маркер — повторює).
func (u *Updater) failed() map[string]string {
	m := map[string]string{}
	if b, err := os.ReadFile(u.failedFile()); err == nil {
		json.Unmarshal(b, &m)
	}
	return m
}

func (u *Updater) markFailed(v string, now time.Time) {
	m := u.failed()
	m[v] = now.Format(time.RFC3339)
	b, _ := json.MarshalIndent(m, "", "  ")
	os.WriteFile(u.failedFile(), b, 0o644)
}

// prune — у packages лишаються лише поточна і попередня версії (для відкату).
func (u *Updater) prune(keep ...string) {
	ents, _ := os.ReadDir(filepath.Join(u.work(), "packages"))
	for _, e := range ents {
		k := false
		for _, v := range keep {
			if v != "" && e.Name() == v {
				k = true
			}
		}
		if !k {
			os.RemoveAll(filepath.Join(u.work(), "packages", e.Name()))
		}
	}
}

// Record — рядок docscan-updates.json для агента (Wazuh чи іншого).
type Record struct {
	Timestamp string       `json:"timestamp"`
	Source    string       `json:"source"`
	Host      string       `json:"host"`
	Event     string       `json:"event"`
	Update    RecordUpdate `json:"update"`
}

type RecordUpdate struct {
	Status    string `json:"status"`    // success | rollback | failed | current | error
	Component string `json:"component"` // program | rules | lists
	From      string `json:"from"`
	To        string `json:"to,omitempty"`
	Mode      string `json:"mode"`
	Source    string `json:"source,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Message   string `json:"message"`
}

func (u *Updater) record(status string, s *State, msg string) {
	u.writeRecord(RecordUpdate{Status: status, Component: "program", From: s.From, To: s.To, Mode: u.cfg.Mode, Source: s.Source, RequestID: s.RequestID, Message: msg})
}

func (u *Updater) writeRecord(ru RecordUpdate) {
	if ru.Component == "" {
		ru.Component = "program"
	}
	lvl := map[string]string{"success": "INFO", "current": "INFO", "rollback": "WARN"}[ru.Status]
	if lvl == "" {
		lvl = "ERROR"
	}
	u.log.Log(lvl, "%s: %s", ru.Status, ru.Message)
	rec := Record{Timestamp: time.Now().Format("2006-01-02T15:04:05.000-07:00"), Source: "docscan", Host: u.host, Event: "Update", Update: ru}
	b, _ := json.Marshal(rec)
	p := filepath.Join(u.dataDir, "results", "docscan-updates.json")
	os.MkdirAll(filepath.Dir(p), 0o755)
	if st, err := os.Stat(p); err == nil && st.Size() > 10<<20 {
		os.Rename(p, p+".1")
	}
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		u.log.Log("ERROR", "%s: %v", p, err)
		return
	}
	f.Write(append(b, '\n'))
	f.Close()
}

// reportError — помилка перевірки: запис для агента, але та сама помилка не частіше разу на добу.
func (u *Updater) reportError(o Outcome, r *Request, src string, now time.Time) {
	if t, ok := u.lastErr[o.Message]; ok && now.Sub(t) < 24*time.Hour && r.RequestID == "" {
		u.log.Log("WARN", "error (repeated): %s", o.Message)
		return
	}
	u.lastErr[o.Message] = now
	u.writeRecord(RecordUpdate{Status: "error", Component: r.component(), From: o.From, To: o.To, Mode: u.cfg.Mode, Source: src, RequestID: r.RequestID, Message: o.Message})
}

func orNone(v string) string {
	if v == "" {
		return "(unknown)"
	}
	return v
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
