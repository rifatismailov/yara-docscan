package main

// Сторінка «Оновлення»: updater.json. Форма -> тимчасовий файл -> docscan-updater -CheckConfig (той самий код, що
// читає служба) -> копія старого (updater.json.bak) -> заміна. Служба DocScanUpdater перечитує файл сама;
// «Перевірити зараз» — файл update\check-now (служба бачить його за 30 с). Опис: docscan-project/DOCSCAN.md#web.

import (
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
	if err := json.Unmarshal(noBOM(b), &c); err != nil {
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
		show(n, fmt.Errorf("не збережено — служба оновлень відхиляє цей конфіг: %v", err))
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
	if err := os.WriteFile(s.p.checkNow(), []byte(time.Now().Format(time.RFC3339)), 0o644); err != nil {
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
