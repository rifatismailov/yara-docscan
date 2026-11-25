package main

// Опис: docscan-project/DOCSCAN.md#web. сторінки «Оновлення» (updater.json) і «Режим і чорний список» (settings.json).
//
//	updater.json  форма -> тимчасовий файл -> docscan-updater -CheckConfig (той самий код, що читає служба) ->
//	              копія старого (updater.json.bak) -> заміна. Служба DocScanUpdater перечитує файл сама; «перевірити
//	              зараз» — файл update\check-now (служба бачить його за 30 с).
//	settings.json режим і пауза чорного списку — watcher застосовує одразу (за 5 с); теки й кількість сканувань — після
//	              перезапуску служби DocScanWatcher (веб перезапускає її сам). install.json синхронізується, щоб
//	              переустановлення (install.ps1 -Reuse) не повернуло старі значення.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ---------------------------------------------------------------- settings.json (той самий формат, що services/cmd/watcher/settings.go)

type wSettings struct {
	DetectOnly           *bool    `json:"detect_only,omitempty"`
	WatchPath            []string `json:"watch_path,omitempty"`
	Workers              *int     `json:"workers,omitempty"`
	BlacklistPausedUntil string   `json:"blacklist_paused_until,omitempty"`
	BlacklistPausedBy    string   `json:"blacklist_paused_by,omitempty"`
	USBScan              string   `json:"usb_scan,omitempty"` // off | detect | full; "" — як режим (scan.go)
}

func (p paths) settingsFile() string { return filepath.Join(p.data, "settings.json") }
func (p paths) updaterJSON() string  { return filepath.Join(p.data, "update", "updater.json") }
func (p paths) updaterExe() string   { return filepath.Join(p.install, "updater", "docscan-updater.exe") }

func readSettings(p paths) (wSettings, error) {
	var s wSettings
	b, err := os.ReadFile(p.settingsFile())
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	d := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))))
	d.DisallowUnknownFields()
	if err := d.Decode(&s); err != nil {
		return s, fmt.Errorf("%s: %w", p.settingsFile(), err)
	}
	return s, nil
}

func writeSettings(p paths, s wSettings) error {
	b, _ := json.MarshalIndent(s, "", "  ")
	err := writeFileAtomic(p.settingsFile(), append(b, '\n'), 0o644)
	markWeb(p.settingsFile())
	return err
}

// pauseState — пауза чорного списку для сторінок.
type pauseState struct {
	On     bool
	Manual bool
	Until  time.Time
	By     string
}

func pauseOf(s wSettings, now time.Time) pauseState {
	switch v := strings.TrimSpace(s.BlacklistPausedUntil); v {
	case "":
	case "manual":
		return pauseState{On: true, Manual: true, By: s.BlacklistPausedBy}
	default:
		if t, err := time.Parse(time.RFC3339, v); err == nil && now.Before(t) {
			return pauseState{On: true, Until: t, By: s.BlacklistPausedBy}
		}
	}
	return pauseState{}
}

// effectiveDetectOnly — режим, у якому зараз працює watcher: settings.json, інакше параметр служби / install.json.
func (s *server) effectiveDetectOnly(set wSettings) (bool, string) {
	if set.DetectOnly != nil {
		return *set.DetectOnly, "settings.json"
	}
	if cmd := serviceCommand("DocScanWatcher"); cmd != "" {
		return strings.Contains(strings.ToLower(cmd), "-nodisarm"), "service DocScanWatcher"
	}
	if ip := install(s.p); ip != nil {
		return ip.Params.DetectOnly, "install.json"
	}
	return false, "default"
}

// syncInstallJSON — ті самі значення в install.json (params), щоб install.ps1 -Reuse їх зберіг.
func syncInstallJSON(p paths, detect bool, watch []string, workers int) error {
	f := filepath.Join(p.data, "install.json")
	b, err := os.ReadFile(f)
	if err != nil {
		return nil // DocScan поставлено не цим інсталятором — нічого синхронізувати
	}
	var m map[string]any
	if err := json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &m); err != nil {
		return fmt.Errorf("install.json: %w", err)
	}
	par, _ := m["params"].(map[string]any)
	if par == nil {
		par = map[string]any{}
	}
	par["DetectOnly"], par["Workers"] = detect, workers
	if len(watch) > 0 {
		par["WatchPath"] = watch
	}
	m["params"] = par
	out, _ := json.MarshalIndent(m, "", "    ")
	return writeFileAtomic(f, out, 0o644)
}

// ---------------------------------------------------------------- «Режим і чорний список»

type modeData struct {
	DetectOnly bool
	Source     string
	WatchPath  string
	Workers    int
	Pause      pauseState
	Today      string
}

func (s *server) mode(q *req) {
	set, err := readSettings(s.p)
	if err != nil {
		s.render(q, "mode", "Режим", err)
		return
	}
	d := modeData{Pause: pauseOf(set, time.Now()), Today: endOfDay(time.Now()).Format("15:04")}
	d.DetectOnly, d.Source = s.effectiveDetectOnly(set)
	watch := set.WatchPath
	if len(watch) == 0 {
		if ip := install(s.p); ip != nil {
			watch = ip.Params.WatchPath
		}
	}
	d.WatchPath = strings.Join(watch, "\r\n")
	if set.Workers != nil {
		d.Workers = *set.Workers
	}
	if q.r.Method != "POST" {
		s.render(q, "mode", "Режим", d)
		return
	}
	// POST: режим, теки, кількість сканувань
	detect := q.r.FormValue("mode") == "detect"
	var paths []string
	for _, l := range strings.Split(q.r.FormValue("watch"), "\n") {
		if l = strings.TrimSpace(l); l != "" {
			if !filepath.IsAbs(l) && !strings.HasPrefix(l, `\\`) && !(len(l) >= 3 && l[1] == ':' && (l[2] == '\\' || l[2] == '/')) {
				s.render(q, "mode", "Режим", fmt.Errorf("folder %q: a full path like C:\\Users", l))
				return
			}
			paths = append(paths, l)
		}
	}
	if len(paths) == 0 {
		s.render(q, "mode", "Режим", fmt.Errorf("give at least one folder to watch"))
		return
	}
	workers, err := strconv.Atoi(strings.TrimSpace(q.r.FormValue("workers")))
	if err != nil || workers < 0 || workers > 64 {
		s.render(q, "mode", "Режим", fmt.Errorf("parallel scans: 0 (automatic) .. 64"))
		return
	}
	restart := strings.Join(paths, "|") != strings.Join(watch, "|") || workers != d.Workers
	was := fmt.Sprintf("mode %s, folders %s, workers %d", modeName(d.DetectOnly), strings.Join(watch, ";"), d.Workers)
	set.DetectOnly, set.WatchPath, set.Workers = &detect, paths, &workers
	if err := writeSettings(s.p, set); err != nil {
		s.render(q, "mode", "Режим", err)
		return
	}
	if err := syncInstallJSON(s.p, detect, paths, workers); err != nil {
		s.log.Log("ERROR", "%v", err)
	}
	now := fmt.Sprintf("mode %s, folders %s, workers %d", modeName(detect), strings.Join(paths, ";"), workers)
	s.audit(q.r, AdminUser, "watcher-settings", was+" -> "+now)
	msg := "збережено: режим діє за кілька секунд"
	if restart {
		if err := restartService("DocScanWatcher"); err != nil {
			msg += "; теки / кількість сканувань — після перезапуску служби DocScanWatcher (" + err.Error() + ")"
		} else {
			msg += "; службу DocScanWatcher перезапущено (нові теки / кількість сканувань)"
		}
	}
	s.back(q, "/mode", msg)
}

func modeName(detect bool) string {
	if detect {
		return "detect-only"
	}
	return "full"
}

func endOfDay(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 23, 59, 59, 0, t.Location())
}

// pause — POST: for = 1h | 4h | today | manual | off.
func (s *server) pause(q *req) {
	if q.r.Method != "POST" {
		s.back(q, "/mode", "")
		return
	}
	set, err := readSettings(s.p)
	if err != nil {
		s.render(q, "mode", "Режим", err)
		return
	}
	now := time.Now()
	var until, msg, action string
	switch q.r.FormValue("for") {
	case "1h":
		until = now.Add(time.Hour).Format(time.RFC3339)
	case "4h":
		until = now.Add(4 * time.Hour).Format(time.RFC3339)
	case "today":
		until = endOfDay(now).Format(time.RFC3339)
	case "manual":
		until = "manual"
	case "off":
	default:
		s.back(q, "/mode", "")
		return
	}
	if until == "" {
		set.BlacklistPausedUntil, set.BlacklistPausedBy = "", ""
		action, msg = "blacklist-resumed", "чорний список знову блокує; наявні файли перевіряються ще раз"
	} else {
		set.BlacklistPausedUntil, set.BlacklistPausedBy = until, AdminUser
		action, msg = "blacklist-paused", "чорний список на паузі до "+until+": збіги — лише повідомлення, без карантину"
	}
	if err := writeSettings(s.p, set); err != nil {
		s.render(q, "mode", "Режим", err)
		return
	}
	s.audit(q.r, AdminUser, action, until)
	s.back(q, "/mode", msg)
}

// ---------------------------------------------------------------- «Оновлення»

type updConfig struct {
	Mode            string   `json:"mode"`
	CheckEveryHours float64  `json:"check_every_hours"`
	GitHub          repoRef  `json:"github"`
	Mirror          urlRef   `json:"mirror"`
	Marker          fileRef  `json:"marker"`
	Rules           updRules `json:"rules"`
	Lists           updLists `json:"lists"`
	Window          string   `json:"window"`
	ExtraPublicKeys []string `json:"extra_public_keys"`
}
type repoRef struct {
	Repo string `json:"repo"`
}
type urlRef struct {
	URL string `json:"url"`
}
type fileRef struct {
	File string `json:"file"`
}
type updRules struct {
	Off    bool    `json:"off"`
	GitHub repoRef `json:"github"`
	Mirror urlRef  `json:"mirror"`
}
type updLists struct {
	URL             string   `json:"url"`
	CheckEveryHours float64  `json:"check_every_hours"`
	PublicKeys      []string `json:"public_keys"`
	Token           string   `json:"token,omitempty"`
}

func readUpdater(p paths) (updConfig, error) {
	var c updConfig
	b, err := os.ReadFile(p.updaterJSON())
	if os.IsNotExist(err) {
		return updConfig{Mode: "github", CheckEveryHours: 6, GitHub: repoRef{"rifatismailov/yara-docscan"}}, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), &c); err != nil {
		return c, fmt.Errorf("%s: %w", p.updaterJSON(), err)
	}
	return c, nil
}

// flat — поля конфігу рядками (для запису «було -> стало» в аудиті; токен — лише «задано / ні»).
func (c updConfig) flat() map[string]string {
	tok := ""
	if c.Lists.Token != "" {
		tok = "(set)"
	}
	return map[string]string{
		"mode": c.Mode, "check_every_hours": fmtF(c.CheckEveryHours), "window": c.Window, "github.repo": c.GitHub.Repo,
		"mirror.url": c.Mirror.URL, "marker.file": c.Marker.File, "rules.off": strconv.FormatBool(c.Rules.Off),
		"rules.github.repo": c.Rules.GitHub.Repo, "rules.mirror.url": c.Rules.Mirror.URL,
		"extra_public_keys": strings.Join(c.ExtraPublicKeys, ","), "lists.url": c.Lists.URL,
		"lists.check_every_hours": fmtF(c.Lists.CheckEveryHours), "lists.public_keys": strings.Join(c.Lists.PublicKeys, ","), "lists.token": tok,
	}
}

func fmtF(f float64) string { return strconv.FormatFloat(f, 'f', -1, 64) }

func diff(a, b map[string]string) string {
	var ks []string
	for k := range b {
		if a[k] != b[k] {
			ks = append(ks, k)
		}
	}
	sort.Strings(ks)
	var out []string
	for _, k := range ks {
		out = append(out, fmt.Sprintf("%s: %q -> %q", k, a[k], b[k]))
	}
	return strings.Join(out, "; ")
}

type updData struct {
	C        updConfig
	Extra    string // ключі — по одному в рядку
	ListKeys string
	HasToken bool
	Checked  string
}

func lines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return out
}

func (s *server) updates(q *req) {
	c, err := readUpdater(s.p)
	if err != nil {
		s.render(q, "updates", "Оновлення", err)
		return
	}
	show := func(c updConfig, e error) {
		d := updData{C: c, Extra: strings.Join(c.ExtraPublicKeys, "\r\n"), ListKeys: strings.Join(c.Lists.PublicKeys, "\r\n"), HasToken: c.Lists.Token != ""}
		d.C.Lists.Token = "" // токен у форму не віддається
		if e != nil {
			s.renderErr(q, "updates", "Оновлення", d, e)
			return
		}
		s.render(q, "updates", "Оновлення", d)
	}
	if q.r.Method != "POST" {
		show(c, nil)
		return
	}
	f := q.r.FormValue
	n := c // невідомі формі поля (marker.file) лишаються
	n.Mode = f("mode")
	n.CheckEveryHours, _ = strconv.ParseFloat(strings.TrimSpace(f("every")), 64)
	n.Window = strings.TrimSpace(f("window"))
	n.GitHub.Repo = strings.TrimSpace(f("repo"))
	n.Mirror.URL = strings.TrimSpace(f("mirror"))
	n.Rules.Off = f("rules_off") == "on"
	n.Rules.GitHub.Repo = strings.TrimSpace(f("rules_repo"))
	n.Rules.Mirror.URL = strings.TrimSpace(f("rules_mirror"))
	n.ExtraPublicKeys = lines(f("extra_keys"))
	n.Lists.URL = strings.TrimSpace(f("lists_url"))
	n.Lists.CheckEveryHours, _ = strconv.ParseFloat(strings.TrimSpace(f("lists_every")), 64)
	n.Lists.PublicKeys = lines(f("lists_keys"))
	if t := strings.TrimSpace(f("lists_token")); t != "" {
		n.Lists.Token = t
	}
	if f("lists_token_clear") == "on" {
		n.Lists.Token = ""
	}
	if n.ExtraPublicKeys == nil {
		n.ExtraPublicKeys = []string{}
	}
	if n.Lists.PublicKeys == nil {
		n.Lists.PublicKeys = []string{}
	}
	b, _ := json.MarshalIndent(n, "", "  ")
	tmp := s.p.updaterJSON() + ".web-new"
	os.MkdirAll(filepath.Dir(tmp), 0o755)
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		show(n, err)
		return
	}
	defer os.Remove(tmp)
	if err := s.checkUpdaterConfig(tmp); err != nil {
		show(n, fmt.Errorf("not saved - the updater refuses this configuration: %v", err))
		return
	}
	ch := diff(c.flat(), n.flat())
	if ch == "" {
		s.back(q, "/updates", "без змін")
		return
	}
	if old, err := os.ReadFile(s.p.updaterJSON()); err == nil {
		os.WriteFile(s.p.updaterJSON()+".bak", old, 0o600)
	}
	if err := os.Rename(tmp, s.p.updaterJSON()); err != nil {
		show(n, err)
		return
	}
	markWeb(s.p.updaterJSON())
	s.audit(q.r, AdminUser, "updater-config", ch)
	s.back(q, "/updates", "збережено (попередній файл — updater.json.bak); служба DocScanUpdater застосує його за пів хвилини")
}

// updatesCheck — POST: «перевірити зараз» (файл check-now для служби).
func (s *server) updatesCheck(q *req) {
	if q.r.Method != "POST" {
		s.back(q, "/updates", "")
		return
	}
	f := filepath.Join(s.p.data, "update", "check-now")
	if err := os.WriteFile(f, []byte(time.Now().Format(time.RFC3339)), 0o644); err != nil {
		s.render(q, "updates", "Оновлення", err)
		return
	}
	s.audit(q.r, AdminUser, "update-check-now", "")
	s.back(q, "/", "служба DocScanUpdater перевірить програму, правила і списки протягом пів хвилини — результат у таблиці «Оновлення» нижче")
}

// checkUpdaterConfig — docscan-updater -CheckConfig (тести підміняють s.checkCfg).
func (s *server) checkUpdaterConfig(file string) error {
	if s.checkCfg != nil {
		return s.checkCfg(file)
	}
	out, err := exec.Command(s.p.updaterExe(), "-CheckConfig", file, "-DataDir", s.p.data).CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(string(out)), "ERROR:"))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("%s", msg)
	}
	return nil
}
