package main

// Опис: docscan-project/DOCSCAN.md#watcher — аудит поза вебом: старт / зупинка служби, зміни в обхід вебу.

// Аудит того, що відбувається з DocScan поза вебом (записи event "Admin" у docscan-results.json -> Wazuh, як і
// дії у вебі):
//
//   - служба watcher-а стартувала / зупинилась і чому (команда служби — services.msc, sc stop, Stop-Service;
//     вимкнення Windows; Ctrl+C у консолі);
//   - файл налаштувань змінили В ОБХІД вебу: settings.json, локальні білий / чорний списки, локальна політика,
//     updater.json. Веб, записавши такий файл, кладе поруч <файл>.websha (sha256 вмісту) — його зміна вже має
//     запис аудиту вебу. Зміна, якої немає в .websha (руками, скриптом, чужою програмою), — запис
//     "config-changed-outside-web" зі старим і новим sha256; видалення — "config-deleted-outside-web".
//     Перевірка раз на 30 с; на старті служби — лише запам'ятати стан (без записів), окрім файлів, що вже на старті
//     не збігаються з .websha (змінили, поки служба не працювала).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"time"

	"docscan/services/pkg/winsvc"
)

// adminRecord — запис аудиту watcher-а (via: service | file).
func (w *Watcher) adminRecord(action, detail, via string) {
	host, _ := os.Hostname()
	rec := map[string]any{"timestamp": time.Now().Format("2006-01-02T15:04:05.000-07:00"), "source": "docscan", "host": host,
		"event": "Admin", "admin": map[string]string{"user": "-", "action": action, "detail": detail, "via": via}}
	b, _ := json.Marshal(rec)
	if err := w.results.append(append(b, '\n')); err != nil {
		w.log.Log("ERROR", "audit record: %v", err)
	}
	w.log.Log("AUDIT", "%s %s (%s)", action, detail, via)
}

func (w *Watcher) auditStart() {
	w.adminRecord("watcher-started", "DocScanWatcher started: watching "+strings.Join(w.c.WatchPath, ", "), "service")
}

func (w *Watcher) auditStop() {
	why := map[string]string{
		"stop":     "stopped by a service command (services.msc / sc stop / Stop-Service / the installer)",
		"shutdown": "Windows is shutting down",
	}[winsvc.StopReason]
	if why == "" {
		why = "stopped (console)"
	}
	w.adminRecord("watcher-stopped", why, "service")
}

var confCheckEvery = 30 * time.Second // тести — коротше

// configFiles — файли, які змінює веб (і більше ніхто з DocScan); шляхи від <DataDir>.
var configFiles = []string{"settings.json", "lists/whitelist.local.json", "lists/blacklist.local.json",
	"policy/docscan-policy.yar", "update/updater.json"}

type confWatch struct {
	dir  string
	last map[string]string // відносний шлях -> sha256 ("" — файла немає)
	next time.Time
}

func fileSum(p string) string {
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func webSum(p string) string {
	b, _ := os.ReadFile(p + ".websha")
	return strings.TrimSpace(string(b))
}

// newConfWatch — стан на старті служби; файли, що вже не збігаються з .websha, — записи одразу.
func (w *Watcher) newConfWatch() *confWatch {
	cw := &confWatch{dir: filepath.Dir(w.c.OutDir), last: map[string]string{}}
	for _, rel := range configFiles {
		p := filepath.Join(cw.dir, filepath.FromSlash(rel))
		s := fileSum(p)
		cw.last[rel] = s
		if ws := webSum(p); s != "" && ws != "" && ws != s {
			w.adminRecord("config-changed-outside-web", p+" was changed while DocScanWatcher was not running (sha256 "+short(s)+", the web wrote "+short(ws)+")", "file")
		}
	}
	return cw
}

func short(s string) string {
	if len(s) > 16 {
		return s[:16]
	}
	return s
}

// check — раз на 30 с: що змінилось з минулого разу і чи це зробив веб.
func (w *Watcher) checkConfig(cw *confWatch, now time.Time) {
	if cw == nil || now.Before(cw.next) {
		return
	}
	cw.next = now.Add(confCheckEvery)
	for _, rel := range configFiles {
		p := filepath.Join(cw.dir, filepath.FromSlash(rel))
		s := fileSum(p)
		was := cw.last[rel]
		if s == was {
			continue
		}
		cw.last[rel] = s
		switch {
		case s == "" && webSum(p) == "-":
			// видалив веб (напр. «повернути пакетну політику») — його запис аудиту вже є
		case s == "":
			w.adminRecord("config-deleted-outside-web", p+" deleted (sha256 was "+short(was)+")", "file")
		case webSum(p) == s:
			// записав веб — його запис аудиту вже є
		default:
			w.adminRecord("config-changed-outside-web", p+" changed not through the web interface (sha256 "+short(was)+" -> "+short(s)+")", "file")
		}
	}
}
