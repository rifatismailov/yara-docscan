package main

// Списки організації з її сервера (updater.json "lists"): раз на check_every_hours (24) — whitelist.json і
// blacklist.json з lists.url (https:// або \\server\share\тека) разом з <файл>.sig. Ставиться лише список, що:
//   - підписаний ключем з lists.public_keys (ключ організації, окремий від ключа релізів);
//   - проходить ту саму перевірку, що й у watcher (orglists.Parse);
//   - має serial, БІЛЬШИЙ за встановлений (старий підписаний список повторно не підсунути).
// Інакше лишається поточний список, у docscan-updates.json — "error" (component "lists"). Файлу на сервері немає
// (і підпису теж) — цей список не публікується, нічого не робиться. Попередня версія — <файл>.prev (бекап).
// Watcher підхоплює новий файл сам.

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"docscan/watcher/manifest"
	"docscan/watcher/orglists"
)

var listNames = []struct{ file, kind string }{{"whitelist.json", "white"}, {"blacklist.json", "black"}}

func (u *Updater) listsDir() string { return filepath.Join(u.dataDir, "lists") }

var errNotFound = errors.New("not found")

// fetchOpt — як fetch, але "немає файлу" (404 / нема на шарі) — errNotFound.
func (u *Updater) fetchOpt(base, name string, limit int64) ([]byte, error) {
	if strings.HasPrefix(base, "http://") || strings.HasPrefix(base, "https://") {
		req, err := http.NewRequest("GET", strings.TrimRight(base, "/")+"/"+name, nil)
		if err != nil {
			return nil, err
		}
		if u.cfg.Lists.Token != "" { // закрите дзеркало (Forgejo з входом, приватний репозиторій)
			req.Header.Set("Authorization", "token "+u.cfg.Lists.Token)
		}
		resp, err := u.http.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == 404 {
			return nil, errNotFound
		}
		if resp.StatusCode != 200 {
			return nil, fmt.Errorf("%s/%s: %s", strings.TrimRight(base, "/"), name, resp.Status)
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(b)) > limit {
			return nil, fmt.Errorf("%s: larger than %d bytes", name, limit)
		}
		return b, nil
	}
	b, err := u.fetch(base, name, limit)
	if err != nil && os.IsNotExist(err) {
		return nil, errNotFound
	}
	return b, err
}

// installedSerial — serial встановленого списку (0 — немає / без serial / не читається).
func (u *Updater) installedSerial(file, kind string) int64 {
	b, err := os.ReadFile(filepath.Join(u.listsDir(), file))
	if err != nil {
		return 0
	}
	l, err := orglists.Parse(b, kind)
	if err != nil {
		return 0
	}
	return l.Serial
}

// checkLists — одна перевірка обох списків; повертає, чи була помилка.
func (u *Updater) checkLists(now time.Time) bool {
	failed := false
	for _, ln := range listNames {
		r := &Request{Component: "lists"}
		from := u.installedSerial(ln.file, ln.kind)
		o, ok := u.checkList(ln.file, ln.kind, from)
		switch {
		case !ok:
			failed = true
			u.reportError(Outcome{Status: "error", From: strconv.FormatInt(from, 10), Message: ln.file + ": " + o}, r, u.cfg.Lists.URL, now)
		case o != "":
			u.log.Log("INFO", "lists: %s", o)
		}
	}
	return failed
}

// checkList -> (повідомлення, гаразд). Поставлений список записується як success.
func (u *Updater) checkList(file, kind string, from int64) (string, bool) {
	base := u.cfg.Lists.URL
	data, err := u.fetchOpt(base, file, 8<<20)
	sig, serr := u.fetchOpt(base, file+".sig", 4096)
	if errors.Is(err, errNotFound) && errors.Is(serr, errNotFound) {
		return "", true // цей список організація не публікує
	}
	if err != nil {
		return fmt.Sprintf("cannot download: %v", err), false
	}
	if serr != nil {
		return fmt.Sprintf("no signature %s.sig (%v) - not installed", file, serr), false
	}
	kid, err := manifest.VerifySig(data, string(sig), u.cfg.Lists.PublicKeys)
	if err != nil {
		return fmt.Sprintf("%v - not installed", err), false
	}
	l, err := orglists.Parse(data, kind)
	if err != nil {
		return fmt.Sprintf("signed, but not a valid list: %v - not installed", err), false
	}
	if l.Serial <= 0 {
		return `signed, but without "serial" - not installed (sign it with docscan-updater -SignList)`, false
	}
	if l.Serial == from {
		return fmt.Sprintf("%s serial %d - up to date", file, from), true
	}
	if l.Serial < from {
		return fmt.Sprintf("serial %d is older than the installed %d - not installed (an old list again?)", l.Serial, from), false
	}
	dir := u.listsDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err.Error(), false
	}
	dst := filepath.Join(dir, file)
	if old, err := os.ReadFile(dst); err == nil { // бекап попередньої версії (повернути вручну: перейменувати .prev)
		if err := writeReplace(dst+".prev", old); err != nil {
			return "backup " + file + ".prev: " + err.Error(), false
		}
	}
	if err := writeReplace(dst+".sig", sig); err != nil {
		return err.Error(), false
	}
	if err := writeReplace(dst, data); err != nil {
		return err.Error(), false
	}
	msg := fmt.Sprintf("%s serial %d (key %s): %d entries", file, l.Serial, kid, len(l.Entries))
	u.writeRecord(RecordUpdate{Status: "success", Component: "lists", From: strconv.FormatInt(from, 10),
		To: strconv.FormatInt(l.Serial, 10), Mode: "lists", Source: base, Message: msg})
	return "", true
}

// writeReplace — через тимчасовий файл; на Windows файл може саме читати watcher — кілька спроб.
func writeReplace(p string, b []byte) error {
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	var err error
	for i := 0; i < 10; i++ {
		if err = os.Rename(tmp, p); err == nil {
			return nil
		}
		time.Sleep(300 * time.Millisecond)
	}
	os.Remove(tmp)
	return err
}

// listsTick — перевірка списків за власним розкладом; повертає, через скільки наступна.
func (u *Updater) listsTick(now time.Time) time.Duration {
	if u.cfg.Lists.URL == "" {
		return 0
	}
	if !u.listsNext.IsZero() && now.Before(u.listsNext) {
		return u.listsNext.Sub(now)
	}
	every := time.Duration(u.cfg.Lists.CheckEveryHours * float64(time.Hour))
	if u.checkLists(now) {
		every = time.Hour // сервер недоступний / список відхилено — спробувати знову за годину
	}
	u.listsNext = now.Add(every)
	return every
}
