package main

// settings.json (<DataDir>\settings.json, -Settings): налаштування поверх параметрів служби. Пишуть веб-інтерфейс
// (docscan-web.exe) і install.ps1. Перечитується, щойно змінився (раз на 5 с):
//
//	detect_only             режим: true — лише повідомлення (як -NoDisarm), false — знешкодження і карантин; одразу
//	blacklist_paused_until  пауза чорного списку: час RFC 3339 або "manual" (до ручного ввімкнення); одразу. Під час
//	                        паузи збіг з чорним списком — HIGH з disarm "paused" (повідомлення є, карантину немає);
//	                        після паузи — прохід по наявних файлах (sweep.go)
//	usb_scan                новий знімний носій (флешка, USB-диск, SD): off — не сканувати, detect — лише повідомлення,
//	                        full — як увесь DocScan (знешкодження і карантин); без поля — як режим (scanjob.go); одразу
//	watch_path, workers     теки і кількість сканувань — під час старту служби (веб перезапускає службу)
//
// Зламаний файл не застосовується: лишаються попередні значення, у watcher.log — ERROR.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"
)

// Settings — settings.json.
type Settings struct {
	DetectOnly           *bool    `json:"detect_only,omitempty"`
	WatchPath            []string `json:"watch_path,omitempty"`
	Workers              *int     `json:"workers,omitempty"` // 0 — автоматично
	BlacklistPausedUntil string   `json:"blacklist_paused_until,omitempty"`
	BlacklistPausedBy    string   `json:"blacklist_paused_by,omitempty"`
	USBScan              string   `json:"usb_scan,omitempty"` // off | detect | full; "" — як режим
}

// PausedUntil — пауза чорного списку: (час кінця, вручну, є пауза).
func (s *Settings) PausedUntil() (time.Time, bool, bool) {
	switch v := strings.TrimSpace(s.BlacklistPausedUntil); v {
	case "":
		return time.Time{}, false, false
	case "manual":
		return time.Time{}, true, true
	default:
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return time.Time{}, false, false
		}
		return t, false, true
	}
}

// Paused — чорний список на паузі зараз.
func (s *Settings) Paused(now time.Time) bool {
	t, manual, ok := s.PausedUntil()
	return ok && (manual || now.Before(t))
}

func parseSettings(b []byte) (*Settings, error) {
	d := json.NewDecoder(bytes.NewReader(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))))
	d.DisallowUnknownFields()
	var s Settings
	if err := d.Decode(&s); err != nil {
		return nil, err
	}
	if v := strings.TrimSpace(s.BlacklistPausedUntil); v != "" && v != "manual" {
		if _, err := time.Parse(time.RFC3339, v); err != nil {
			return nil, fmt.Errorf("blacklist_paused_until %q: a time (RFC 3339) or \"manual\"", v)
		}
	}
	switch s.USBScan {
	case "", "off", "detect", "full":
	default:
		return nil, fmt.Errorf("usb_scan %q: off, detect or full", s.USBScan)
	}
	if s.Workers != nil && (*s.Workers < 0 || *s.Workers > 64) {
		return nil, fmt.Errorf("workers %d: 0 (automatic) .. 64", *s.Workers)
	}
	return &s, nil
}

// settingsState — поточні налаштування watcher-а (file — settings.json; "" — немає).
type settingsState struct {
	mu        sync.Mutex
	file      string
	mod       time.Time
	size      int64
	known     bool
	cur       Settings
	flagNoDis bool // -NoDisarm з параметрів служби (коли в settings.json немає detect_only)
	paused    bool // стан паузи на останній перевірці (щоб побачити її кінець)
}

// noDisarm — зараз лише повідомлення (DetectOnly).
func (w *Watcher) noDisarm() bool {
	if w.set == nil {
		return w.c.NoDisarm
	}
	w.set.mu.Lock()
	defer w.set.mu.Unlock()
	if w.set.cur.DetectOnly != nil {
		return *w.set.cur.DetectOnly
	}
	return w.set.flagNoDis
}

// blackPaused — чорний список на паузі: (так, до чого — для запису).
func (w *Watcher) blackPaused(now time.Time) (bool, string) {
	if w.set == nil {
		return false, ""
	}
	w.set.mu.Lock()
	defer w.set.mu.Unlock()
	if !w.set.cur.Paused(now) {
		return false, ""
	}
	return true, w.set.cur.BlacklistPausedUntil
}

// loadSettings — під час старту: прочитати і застосувати теки / кількість сканувань.
func (w *Watcher) loadSettings() {
	w.set = &settingsState{file: w.c.Settings, flagNoDis: w.c.NoDisarm}
	if w.c.Settings == "" {
		return
	}
	w.reloadSettings(time.Now())
	w.set.mu.Lock()
	s := w.set.cur
	w.set.mu.Unlock()
	if len(s.WatchPath) > 0 {
		w.c.WatchPath = s.WatchPath
	}
	if s.Workers != nil {
		if *s.Workers > 0 {
			w.c.MinWorkers, w.c.MaxWorkers = *s.Workers, *s.Workers
		}
	}
}

// reloadSettings — файл змінився: нові значення (режим, пауза — одразу). Кінець паузи чи зміна списків -> прохід.
func (w *Watcher) reloadSettings(now time.Time) {
	st := w.set
	if st == nil || st.file == "" {
		return
	}
	st.mu.Lock()
	changed := false
	fi, err := os.Stat(st.file)
	switch {
	case err != nil || !fi.Mode().IsRegular():
		if st.known {
			st.known, st.cur, changed = false, Settings{}, true
			w.log.Log("INFO", "settings: %s removed - the service parameters apply", st.file)
		}
	case !st.known || !fi.ModTime().Equal(st.mod) || fi.Size() != st.size:
		first := !st.known
		st.known, st.mod, st.size = true, fi.ModTime(), fi.Size()
		b, err := os.ReadFile(st.file)
		var s *Settings
		if err == nil {
			s, err = parseSettings(b)
		}
		if err != nil {
			w.log.Log("ERROR", "settings: %s is broken, the previous values stay: %v", st.file, err)
		} else {
			old := st.cur
			st.cur, changed = *s, true
			mode := func(x Settings) string {
				if x.DetectOnly == nil {
					return map[bool]string{true: "detect-only (service parameter)", false: "full (service parameter)"}[st.flagNoDis]
				}
				return map[bool]string{true: "detect-only", false: "full"}[*x.DetectOnly]
			}
			if first || mode(old) != mode(*s) {
				w.log.Log("INFO", "settings: mode %s", mode(*s))
			}
			if !first && s.USBScan != old.USBScan {
				w.log.Log("INFO", "settings: automatic scan of removable media %s", map[string]string{"": "as the mode", "off": "off", "detect": "detect-only", "full": "full"}[s.USBScan])
			}
			if s.BlacklistPausedUntil != old.BlacklistPausedUntil && s.Paused(now) {
				w.log.Log("WARN", "settings: black list PAUSED until %s (by %s) - matches are reported, nothing is quarantined", s.BlacklistPausedUntil, orDash(s.BlacklistPausedBy))
			}
		}
	}
	paused := st.cur.Paused(now)
	ended := st.paused && !paused
	st.paused = paused
	st.mu.Unlock()
	if ended {
		w.log.Log("INFO", "settings: black list pause over - existing files are checked again")
	}
	if (ended || changed) && w.lists != nil {
		w.lists.bump() // прохід по наявних файлах (sweep.go): режим чи пауза змінились
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
