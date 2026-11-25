package main

// Сторінка «Режим»: повний / detect only і пауза блокування заблокованих файлів (settings.json). Watcher застосовує
// зміни сам, за 5 с, без перезапуску; install.json синхронізується, щоб install.ps1 -Reuse не повернув старий режим.
// Теки під наглядом і кількість сканувань у вебі не змінюються — їх задає інсталятор (-WatchPath, -Workers).
// Опис: docscan-project/DOCSCAN.md#web.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// settings.json — той самий формат, що services/cmd/watcher/settings.go

type wSettings struct {
	DetectOnly           *bool    `json:"detect_only,omitempty"`
	WatchPath            []string `json:"watch_path,omitempty"`
	Workers              *int     `json:"workers,omitempty"`
	BlacklistPausedUntil string   `json:"blacklist_paused_until,omitempty"`
	BlacklistPausedBy    string   `json:"blacklist_paused_by,omitempty"`
	USBScan              string   `json:"usb_scan,omitempty"` // off | detect | full; "" — як режим (scan.go)
}

func readSettings(p paths) (wSettings, error) {
	var s wSettings
	b, err := os.ReadFile(p.settingsFile())
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	d := json.NewDecoder(bytes.NewReader(noBOM(b)))
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

// syncInstallJSON — той самий режим у install.json (params.DetectOnly), щоб install.ps1 -Reuse його зберіг.
func syncInstallJSON(p paths, detect bool) error {
	f := p.installJSON()
	b, err := os.ReadFile(f)
	if err != nil {
		return nil // DocScan поставлено не цим інсталятором — нічого синхронізувати
	}
	var m map[string]any
	if err := json.Unmarshal(noBOM(b), &m); err != nil {
		return fmt.Errorf("install.json: %w", err)
	}
	par, _ := m["params"].(map[string]any)
	if par == nil {
		par = map[string]any{}
	}
	par["DetectOnly"] = detect
	m["params"] = par
	out, _ := json.MarshalIndent(m, "", "    ")
	return writeFileAtomic(f, out, 0o644)
}

// ---------------------------------------------------------------- сторінка

type modeData struct {
	DetectOnly bool
	Source     string
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
	if q.r.Method != "POST" {
		s.render(q, "mode", "Режим", d)
		return
	}
	detect := q.r.FormValue("mode") == "detect"
	if detect == d.DetectOnly && set.DetectOnly != nil {
		s.back(q, "/mode", "режим не змінився")
		return
	}
	was := "mode " + modeName(d.DetectOnly)
	set.DetectOnly = &detect
	if err := writeSettings(s.p, set); err != nil {
		s.render(q, "mode", "Режим", err)
		return
	}
	if err := syncInstallJSON(s.p, detect); err != nil {
		s.log.Log("ERROR", "%v", err)
	}
	s.audit(q.r, AdminUser, "watcher-settings", was+" -> mode "+modeName(detect))
	s.back(q, "/mode", "збережено: режим діє за кілька секунд")
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

// pause — POST: for = 1h | 4h | today | manual | off. Пауза блокування (чорного списку), кнопки — на сторінці «Режим».
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
		action, msg = "blacklist-resumed", "блокування знову діє; наявні файли перевіряються ще раз"
	} else {
		set.BlacklistPausedUntil, set.BlacklistPausedBy = until, AdminUser
		action, msg = "blacklist-paused", "блокування на паузі до "+until+": збіги із заблокованими — лише повідомлення, без карантину"
	}
	if err := writeSettings(s.p, set); err != nil {
		s.render(q, "mode", "Режим", err)
		return
	}
	s.audit(q.r, AdminUser, action, until)
	s.back(q, "/mode", msg)
}
