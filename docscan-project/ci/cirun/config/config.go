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
	// FullTests — чи проганяти на цій машині ВСІ тести (третій прохід, ворожі файли, фазинг, корпуси,
	// шкідливе ПЗ). false — лише збірка і 35 зразків (напр. робоча станція, де не можна тримати
	// корпуси й шкідливе ПЗ). Не задано — true.
	FullTests *bool `yaml:"full_tests"`
}

// Full — FullTests зі значенням за замовчуванням (true).
func (c Candidate) Full() bool { return c.FullTests == nil || *c.FullTests }

// Tests — тести на файлах поза git: корпуси (документи з корпусів фазингу), корпус для ворожих файлів,
// справжнє шкідливе ПЗ. Мак збирає з них архіви (package assets) і викладає в приватний сховок пакетів
// Forgejo; віддалені машини завантажують їх перед тестами і видаляють після.
type Tests struct {
	Enabled    bool     `yaml:"enabled"`
	CorpusDirs []string `yaml:"corpus_dirs"` // теки корпусів (з них беруться лише документи)
	Seeds      string   `yaml:"seeds"`       // корпус для тесту «ворожі файли»
	Malware    string   `yaml:"malware"`     // зразки шкідливого ПЗ + expected.txt; порожньо — без цього тесту
	LocalDir   string   `yaml:"local_dir"`   // Мак: архіви і розпакована копія (поза репозиторієм)
	Store      struct {
		URL      string `yaml:"url"`       // Forgejo, напр. http://<сервер>:3000
		Owner    string `yaml:"owner"`     // власник пакета
		Package  string `yaml:"package"`   // ім'я generic-пакета
		TokenRef string `yaml:"token_ref"` // токен лише на пакети
	} `yaml:"store"`
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

// Release — реліз програми на GitHub (cirun --release; gh має бути встановлений і авторизований).
type Release struct {
	Repo string `yaml:"repo"` // "owner/repo"; порожньо — з адреси push.remote
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

// Stand — тестовий стенд конвеєра Forgejo (cirun probe / stand / report). Стенди перевіряються на
// доступність перед прогоном: недоступний — SKIPPED (прогін не падає), помилка на доступному — ERROR (push на
// GitHub блокується).
type Stand struct {
	Name  string `yaml:"name"`  // коротке ім'я: win11, srv2019, win10, ubuntu (ім'я завдання у workflow)
	Title string `yaml:"title"` // для звіту: "Windows 11", "Windows Server 2019"
	OS    string `yaml:"os"`    // windows | linux
	Role  string `yaml:"role"`  // build — збирає (Windows: MSBuild + пакет) і віддає збірку іншим;
	// test — тестує збірку стенда From; self — збирає і тестує сам (Linux)
	From  string `yaml:"from"`  // role: test — ім'я стенда, чию збірку тестувати
	Suite string `yaml:"suite"` // smoke — збірка, 42 зразки, пісочниця, установка + watcher;
	// full — ще третій прохід, ворожі файли, корпус, шкідливе ПЗ (+ фазинг на Linux)
	Connection Connection `yaml:"connection"`
	Workdir    string     `yaml:"workdir"` // C:\ci (Windows), ~/docscan-ci (Linux)
	Load       *LoadTest  `yaml:"load"`    // навантажувальний тест термінального сервера після набору (лише Windows)
}

// LoadTest — навантажувальний тест на стенді-термінальному сервері (ci/loadtest): пакет цього коміту ставиться
// як на сервер (-DetectOnly, стежить за C:\Users), Users користувачів працюють з файлами у своїх профілях
// (rds_load.ps1), loadtest_report.py звіряє кожну дію з записами watcher-а: пропущений файл — FAIL.
// Сервер готується один раз вручну: rds_setup.ps1 (користувачі), rds_docs.ps1 (тестові набори в <root>\docs).
type LoadTest struct {
	Users        int    `yaml:"users"`         // 25
	Minutes      int    `yaml:"minutes"`       // тривалість навантаження, 20
	IntervalSec  int    `yaml:"interval_sec"`  // середній інтервал між діями одного користувача, 20
	Burst        int    `yaml:"burst"`         // на старті кожен користувач кладе стільки файлів одразу, 10
	ProbeUsers   int    `yaml:"probe_users"`   // + поодинокі файли під час напливу (затримка для людини), 5
	DrainMinutes int    `yaml:"drain_minutes"` // скільки чекати, поки watcher дочитає, 30
	Root         string `yaml:"root"`          // тека тесту на сервері: docs\, runs\, critical-rules.yar; C:\loadtest
	Critical     string `yaml:"critical"`      // правила критичної інформації на сервері (не в git); "" — <root>\critical-rules.yar, якщо є
}

// Pipeline — конвеєр Forgejo Actions: куди після зеленого прогону пушити і де випускати реліз.
type Pipeline struct {
	GitHubRepo     string `yaml:"github_repo"`      // owner/repo
	GitHubTokenRef string `yaml:"github_token_ref"` // fine-grained токен: Contents + Releases (push і реліз)
	Branch         string `yaml:"branch"`           // гілка, яку пушити (за замовчуванням — та, що в прогоні)
	// Mode: local — ▷ збирає і тестує все сам (platforms:), як раніше; forgejo — ▷ проганяє лише macOS, пушить
	// коміт у Forgejo (forgejo.url / repo / token_ref) і запускає там Workflow на стендах (stands:)
	Mode     string `yaml:"mode"`
	Workflow string `yaml:"workflow"` // файл workflow у .forgejo/workflows (за замовчуванням pipeline.yml)
}

// Config — увесь конфіг.
// FileServer — файловий сервер тестової платформи (SMB): звідти бойовий тест (--combat) бере тестові файли,
// шкідливе ПЗ і реальні зразки (лише запаролені zip).
type FileServer struct {
	UNC         string `yaml:"unc"`          // \\<сервер>\<шара>
	User        string `yaml:"user"`         // користувач SMB...
	UserRef     string `yaml:"user_ref"`     // ...або посилання на нього
	PasswordRef string `yaml:"password_ref"` // посилання на пароль
}

type Config struct {
	Version     int    `yaml:"version"`
	OutDir      string `yaml:"out_dir"`      // куди складати результати прогонів (ci-out)
	FuzzSeconds int    `yaml:"fuzz_seconds"` // секунди фазингу на ОС (прапорець --fuzz перекриває)
	Repo        struct {
		Commit  string `yaml:"commit"`  // auto — комітити зміни (з перевіркою безпеки); off — збирати HEAD
		Message string `yaml:"message"` // порожньо — "ci: <файли>"
	} `yaml:"repo"`
	Secrets    Secrets              `yaml:"secrets"`
	Platforms  map[string]*Platform `yaml:"platforms"`
	Tests      Tests                `yaml:"tests"`
	Push       Push                 `yaml:"push"`
	Forgejo    Forgejo              `yaml:"forgejo"`
	FileServer FileServer           `yaml:"fileserver"`
	Release    Release              `yaml:"release"`
	Stands     []Stand              `yaml:"stands"`
	Pipeline   Pipeline             `yaml:"pipeline"`

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
	if c.Pipeline.Mode == "" {
		c.Pipeline.Mode = "local"
	}
	if c.Pipeline.Workflow == "" {
		c.Pipeline.Workflow = "pipeline.yml"
	}
	for i := range c.Stands {
		st := &c.Stands[i]
		if st.Connection.Port == 0 {
			st.Connection.Port = map[string]int{"ssh": 22, "winrm": 5985}[st.Connection.Type]
		}
		if st.Connection.Type == "winrm" && st.Connection.Auth == "" {
			st.Connection.Auth = "ntlm"
		}
		if st.Connection.Type == "ssh" && st.Connection.KnownHosts == "" {
			st.Connection.KnownHosts = "~/.ssh/known_hosts"
		}
		if st.Workdir == "" {
			st.Workdir = map[string]string{"windows": `C:\ci`, "linux": "docscan-ci"}[st.OS]
		}
		if st.Title == "" {
			st.Title = st.Name
		}
		if st.Suite == "" {
			st.Suite = "full"
		}
		if l := st.Load; l != nil {
			def := func(v *int, d int) {
				if *v <= 0 {
					*v = d
				}
			}
			def(&l.Users, 25)
			def(&l.Minutes, 20)
			def(&l.IntervalSec, 20)
			def(&l.DrainMinutes, 30)
			if l.Burst < 0 {
				l.Burst = 0
			}
			if l.ProbeUsers < 0 {
				l.ProbeUsers = 0
			}
			if l.Root == "" {
				l.Root = `C:\loadtest`
			}
		}
	}
	if c.Tests.LocalDir == "" {
		c.Tests.LocalDir = "~/docscan-ci/assets"
	}
	if c.Tests.Store.Package == "" {
		c.Tests.Store.Package = "docscan-tests"
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
	if c.Pipeline.Mode != "local" && c.Pipeline.Mode != "forgejo" {
		return fmt.Errorf("pipeline.mode %q (local | forgejo)", c.Pipeline.Mode)
	}
	if c.Pipeline.Mode == "forgejo" && (c.Forgejo.URL == "" || c.Forgejo.Repo == "" || c.Forgejo.TokenRef == "") {
		return fmt.Errorf("pipeline.mode forgejo needs forgejo.url, forgejo.repo and forgejo.token_ref")
	}
	names := map[string]*Stand{}
	for i := range c.Stands {
		st := &c.Stands[i]
		if st.Name == "" || names[st.Name] != nil {
			return fmt.Errorf("stands[%d]: empty or repeated name %q", i, st.Name)
		}
		names[st.Name] = st
		switch {
		case st.OS != "windows" && st.OS != "linux":
			return fmt.Errorf("stands.%s.os %q (windows | linux)", st.Name, st.OS)
		case st.Suite != "smoke" && st.Suite != "full":
			return fmt.Errorf("stands.%s.suite %q (smoke | full)", st.Name, st.Suite)
		case st.Connection.Host == "":
			return fmt.Errorf("stands.%s: connection.host is empty", st.Name)
		case st.OS == "windows" && st.Connection.Type != "winrm", st.OS == "linux" && st.Connection.Type != "ssh":
			return fmt.Errorf("stands.%s: %s goes over %s", st.Name, st.OS, map[string]string{"windows": "winrm", "linux": "ssh"}[st.OS])
		}
		switch st.Role {
		case "build", "self":
		case "test":
			if st.OS != "windows" {
				return fmt.Errorf("stands.%s: role test is for Windows stands (Linux builds itself: role self)", st.Name)
			}
		default:
			return fmt.Errorf("stands.%s.role %q (build | test | self)", st.Name, st.Role)
		}
		if st.Load != nil && st.OS != "windows" {
			return fmt.Errorf("stands.%s.load: the load test is for a Windows terminal server", st.Name)
		}
	}
	for _, st := range c.Stands {
		if st.Role == "test" {
			if b := names[st.From]; b == nil || b.Role != "build" || b.OS != st.OS {
				return fmt.Errorf("stands.%s.from %q: not a %s stand with role build", st.Name, st.From, st.OS)
			}
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

// Stand — стенд за іменем (nil — немає такого).
func (c *Config) Stand(name string) *Stand {
	for i := range c.Stands {
		if c.Stands[i].Name == name {
			return &c.Stands[i]
		}
	}
	return nil
}

// ExpandHome розгортає «~/…» у повний шлях від домашньої теки.
func ExpandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		h, _ := os.UserHomeDir()
		return filepath.Join(h, p[2:])
	}
	return p
}
