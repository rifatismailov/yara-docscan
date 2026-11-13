// Package config — налаштування cirun з YAML (docscan-project/ci/config.yaml).
//
// У конфігу немає паролів: лише посилання на них (*_ref), які розгортає Resolver (secrets.go) —
// з бази KeePassXC, з ~/.docscan/hosts.json або зі змінної середовища. config.yaml з внутрішніми
// адресами не йде в git (.gitignore); у репозиторії лежить config.example.yaml із заглушками.
package config

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// PlatformOrder — відомі платформи в порядку виводу і запуску в межах однієї хвилі.
var PlatformOrder = []string{"macos", "windows", "linux"}

// Connection — як дістатися до машини.
type Connection struct {
	Type        string `yaml:"type"`         // local | ssh | winrm
	Host        string `yaml:"host"`         // адреса машини (ssh, winrm)
	Port        int    `yaml:"port"`         // 22 для ssh, 5985 для winrm, якщо не задано
	User        string `yaml:"user"`         // ім'я користувача прямо в конфігу...
	UserRef     string `yaml:"user_ref"`     // ...або посилання на нього (keepassxc:…#UserName)
	PasswordRef string `yaml:"password_ref"` // посилання на пароль; самого пароля в конфігу немає
	KeyFile     string `yaml:"key_file"`     // ssh: приватний ключ (замість або разом з паролем)
	KnownHosts  string `yaml:"known_hosts"`  // ssh: файл відомих ключів хостів (обов'язково перевіряється)
	Auth        string `yaml:"auth"`         // winrm: ntlm (за замовчуванням)
}

// Candidate — одна з машин, що можуть виконати платформу (перша доступна виграє).
type Candidate struct {
	Name       string     `yaml:"name"`
	Connection Connection `yaml:"connection"`
}

// Platform — налаштування однієї ОС.
type Platform struct {
	Enabled    bool              `yaml:"enabled"`
	Connection *Connection       `yaml:"connection"` // одна машина...
	Candidates []Candidate       `yaml:"candidates"` // ...або кілька за порядком переваги
	Requires   []string          `yaml:"requires"`   // платформи, що мають бути увімкнені й зелені раніше
	Workdir    string            `yaml:"workdir"`    // робоча тека на машині ("." для local = сам репозиторій)
	Script     string            `yaml:"script"`     // скрипт збірки/тестів для macOS/Linux
	Source     string            `yaml:"source"`     // Windows: auto | git | zip
	Seeds      string            `yaml:"seeds"`      // тека корпусу для тесту «ворожі файли» на тій машині
	Env        map[string]string `yaml:"env"`        // додаткові змінні середовища для скрипта
}

// Machines — кандидати платформи: candidates або одна connection як кандидат з її типом в імені.
func (p *Platform) Machines() []Candidate {
	if len(p.Candidates) > 0 {
		return p.Candidates
	}
	if p.Connection != nil {
		return []Candidate{{Name: p.Connection.Type, Connection: *p.Connection}}
	}
	return nil
}

// KeePassXC — де лежить база паролів і як її відкрити.
type KeePassXC struct {
	Database     string `yaml:"database"`      // файл .kdbx
	Unlock       string `yaml:"unlock"`        // keychain | prompt | key_file
	KeychainItem string `yaml:"keychain_item"` // ім'я запису в Связці ключів macOS (unlock: keychain)
	KeyFile      string `yaml:"key_file"`      // файл-ключ (unlock: key_file)
	CLI          string `yaml:"cli"`           // шлях до keepassxc-cli; порожньо — знайти самому
}

// Secrets — джерела секретів для посилань *_ref.
type Secrets struct {
	HostsFile string    `yaml:"hosts_file"` // старі посилання hosts:<профіль>[.<поле>]
	KeePassXC KeePassXC `yaml:"keepassxc"`  // посилання keepassxc:<група/запис>[#атрибут]
}

// Push — головна публікація: git push коміту на GitHub після зеленого прогону. Від Forgejo не
// залежить: слухач на іншому сервері сам стежить за GitHub і запускає свої тести.
type Push struct {
	Enabled bool   `yaml:"enabled"`
	Remote  string `yaml:"remote"` // git remote GitHub (за замовчуванням docscan)
	Tag     string `yaml:"tag"`    // тег на протестований коміт, напр. "ci/passed/{short}"; порожньо — без тегу
}

// Forgejo — НЕобов'язково (enabled: false за замовчуванням). Якщо увімкнено і доступний — після push
// на GitHub підсмикнути дзеркало (mode: mirror) або запушити в Forgejo (mode: push) і поставити статуси
// коміту. Недоступний Forgejo ні на що не впливає.
type Forgejo struct {
	Enabled          bool   `yaml:"enabled"`
	URL              string `yaml:"url"`                // http://<сервер>:3000
	Repo             string `yaml:"repo"`               // власник/репозиторій
	TokenRef         string `yaml:"token_ref"`          // API-токен (статуси, mirror-sync, перевірка)
	CheckoutTokenRef string `yaml:"checkout_token_ref"` // токен лише на читання: Windows бере ним код через git
	Mode             string `yaml:"mode"`               // mirror — після push на GitHub викликати mirror-sync; push — ще й git push у Forgejo
	Remote           string `yaml:"remote"`             // git remote Forgejo (mode: push, check.method: ls-remote)
	Check            struct {
		Method  string        `yaml:"method"`  // api | ls-remote
		Timeout time.Duration `yaml:"timeout"` // напр. 5s
	} `yaml:"check"`
	Report struct {
		CommitStatus bool `yaml:"commit_status"` // статус коміту на кожну платформу (cirun/<платформа>)
	} `yaml:"report"`
}

// Deploy — набір для розгортання і сервер, куди його викладати.
type Deploy struct {
	Publish       bool   `yaml:"publish"`        // викладати після зеленого прогону
	Host          string `yaml:"host"`           // сервер розгортання (ssh)
	User          string `yaml:"user"`           // користувач ssh
	UserRef       string `yaml:"user_ref"`       // або посилання на нього
	PasswordRef   string `yaml:"password_ref"`   // посилання на пароль ssh
	Dir           string `yaml:"dir"`            // тека на сервері (відносно домашньої)
	URL           string `yaml:"url"`            // HTTP-адреса цієї теки
	CriticalRules string `yaml:"critical_rules"` // локальний файл правил E5Search (у набір), порожньо — без нього
}

// Config — увесь конфіг.
type Config struct {
	Version     int    `yaml:"version"`
	OutDir      string `yaml:"out_dir"`      // куди складати результати прогонів (ci-out)
	FuzzSeconds int    `yaml:"fuzz_seconds"` // секунди фазингу на ОС (прапорець --fuzz перекриває)
	Repo        struct {
		Commit  string `yaml:"commit"`  // auto — комітити зміни (з перевіркою безпеки); off — збирати HEAD
		Message string `yaml:"message"` // порожньо — "ci: <файли>"
	} `yaml:"repo"`
	Secrets   Secrets              `yaml:"secrets"`
	Platforms map[string]*Platform `yaml:"platforms"`
	Push      Push                 `yaml:"push"`
	Forgejo   Forgejo              `yaml:"forgejo"`
	Deploy    Deploy               `yaml:"deploy"`

	Path string `yaml:"-"` // звідки завантажено
}

// Load читає YAML, підставляє значення за замовчуванням і перевіряє конфіг. Невідомі поля — помилка
// (одруківка в назві поля інакше мовчки вимкнула б налаштування).
func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c := &Config{Path: path}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	c.defaults()
	if err := c.validate(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

func (c *Config) defaults() {
	if c.OutDir == "" {
		c.OutDir = "ci-out"
	}
	if c.Repo.Commit == "" {
		c.Repo.Commit = "auto"
	}
	if c.Secrets.HostsFile == "" {
		c.Secrets.HostsFile = "~/.docscan/hosts.json"
	}
	if c.Secrets.KeePassXC.Unlock == "" {
		c.Secrets.KeePassXC.Unlock = "keychain"
	}
	if c.Secrets.KeePassXC.KeychainItem == "" {
		c.Secrets.KeePassXC.KeychainItem = "docscan-kdbx"
	}
	for name, p := range c.Platforms {
		if p == nil {
			p = &Platform{}
			c.Platforms[name] = p
		}
		if p.Script == "" && name != "windows" {
			p.Script = "docscan-project/ci/build-test-unix.sh"
		}
		if p.Source == "" {
			p.Source = "auto"
		}
		fix := func(cn *Connection) {
			if cn.Port == 0 {
				cn.Port = map[string]int{"ssh": 22, "winrm": 5985}[cn.Type]
			}
			if cn.Type == "winrm" && cn.Auth == "" {
				cn.Auth = "ntlm"
			}
			if cn.Type == "ssh" && cn.KnownHosts == "" {
				cn.KnownHosts = "~/.ssh/known_hosts"
			}
		}
		if p.Connection != nil {
			fix(p.Connection)
		}
		for i := range p.Candidates {
			fix(&p.Candidates[i].Connection)
		}
	}
	if c.Push.Remote == "" {
		c.Push.Remote = "docscan"
	}
	if c.Forgejo.Mode == "" {
		c.Forgejo.Mode = "mirror"
	}
	if c.Forgejo.Remote == "" {
		c.Forgejo.Remote = "forgejo"
	}
	if c.Forgejo.Check.Method == "" {
		c.Forgejo.Check.Method = "api"
	}
	if c.Forgejo.Check.Timeout == 0 {
		c.Forgejo.Check.Timeout = 5 * time.Second
	}
	if c.Deploy.Dir == "" {
		c.Deploy.Dir = "scripts/docscan"
	}
}

func (c *Config) validate() error {
	known := map[string]bool{}
	for _, n := range PlatformOrder {
		known[n] = true
	}
	for name, p := range c.Platforms {
		if !known[name] {
			return fmt.Errorf("platforms.%s: unknown platform (known: %s)", name, strings.Join(PlatformOrder, ", "))
		}
		if !p.Enabled {
			continue
		}
		if len(p.Machines()) == 0 {
			return fmt.Errorf("platforms.%s: no connection or candidates", name)
		}
		for _, m := range p.Machines() {
			switch m.Connection.Type {
			case "local":
			case "ssh", "winrm":
				if m.Connection.Host == "" {
					return fmt.Errorf("platforms.%s (%s): host is empty", name, m.Name)
				}
			default:
				return fmt.Errorf("platforms.%s (%s): connection type %q (local | ssh | winrm)", name, m.Name, m.Connection.Type)
			}
		}
		for _, r := range p.Requires {
			if !known[r] || r == name {
				return fmt.Errorf("platforms.%s.requires: %q is not another platform", name, r)
			}
		}
	}
	// цикли в requires (a -> b -> a) не дали б жодній платформі стартувати
	state := map[string]int{}
	var visit func(string) error
	visit = func(n string) error {
		switch state[n] {
		case 1:
			return fmt.Errorf("platforms: requires cycle through %s", n)
		case 2:
			return nil
		}
		state[n] = 1
		if p := c.Platforms[n]; p != nil {
			for _, r := range p.Requires {
				if err := visit(r); err != nil {
					return err
				}
			}
		}
		state[n] = 2
		return nil
	}
	for n := range c.Platforms {
		if err := visit(n); err != nil {
			return err
		}
	}
	switch c.Forgejo.Mode {
	case "mirror", "push":
	default:
		return fmt.Errorf("forgejo.mode %q (mirror | push)", c.Forgejo.Mode)
	}
	switch c.Forgejo.Check.Method {
	case "api", "ls-remote":
	default:
		return fmt.Errorf("forgejo.check.method %q (api | ls-remote)", c.Forgejo.Check.Method)
	}
	return nil
}

// Enabled — увімкнені платформи в порядку PlatformOrder.
func (c *Config) Enabled() []string {
	var out []string
	for _, n := range PlatformOrder {
		if p := c.Platforms[n]; p != nil && p.Enabled {
			out = append(out, n)
		}
	}
	return out
}

// ExpandHome розгортає «~/…» у повний шлях від домашньої теки.
func ExpandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		h, _ := os.UserHomeDir()
		return filepath.Join(h, p[2:])
	}
	return p
}
