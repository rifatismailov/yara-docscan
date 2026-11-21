package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"docscan/watcher/manifest"
)

// Config — updater.json (<DataDir>\update\updater.json; пише install.ps1 з параметрів -Update*, далі його можна
// правити; доступ — лише SYSTEM і адміністратори, як і до всього <DataDir>).
type Config struct {
	// Mode — звідки дізнаватися про нову версію:
	//   github  раз на check_every_hours — останній реліз на GitHub (releases/latest/download/…);
	//   mirror  те саме з дзеркала організації (тека з файлами релізу: http(s) або шлях / UNC);
	//   marker  чекати, поки агент (Wazuh чи будь-який інший) запише маркер marker.file з тим, що ставити;
	//   off     не оновлювати.
	Mode            string   `json:"mode"`
	CheckEveryHours float64  `json:"check_every_hours"`
	GitHub          GitHub   `json:"github"`
	Mirror          Mirror   `json:"mirror"`
	Marker          Marker   `json:"marker"`
	Rules           Rules    `json:"rules"`
	Lists           Lists    `json:"lists"`
	Window          string   `json:"window"`            // "22:00-06:00" — ставити лише в цей час (порожньо — будь-коли)
	ExtraPublicKeys []string `json:"extra_public_keys"` // ключі організації, що підписує свої збірки (ed25519:<base64>)
}

type GitHub struct {
	Repo string `json:"repo"` // owner/repo
}

// Rules — оновлення правил (пакети релізів yara-docscan-rules) у тому ж режимі, що й програма.
type Rules struct {
	Off    bool   `json:"off"`    // true — правила не оновлювати (лишаються ті, що поставив інсталятор)
	GitHub GitHub `json:"github"` // репозиторій релізів правил
	Mirror Mirror `json:"mirror"` // режим mirror: окрема тека з релізом правил; порожньо — та сама, що й для програми
}

// Lists — білий / чорний списки організації з ЇЇ дзеркала (lists.go): whitelist.json / blacklist.json + .sig,
// підписані ключем організації (public_keys — окремо від extra_public_keys: цей ключ не підпише програму).
type Lists struct {
	URL             string   `json:"url"`               // https://lists.org.local/docscan/ або \\server\share\docscan; "" — лише вручну
	CheckEveryHours float64  `json:"check_every_hours"` // за замовчуванням 24
	PublicKeys      []string `json:"public_keys"`       // ed25519:<base64> (docscan-updater -NewListKey)
	Token           string   `json:"token,omitempty"`   // закрите дзеркало: "Authorization: token <це>" (Forgejo / Gitea / GitHub; лише читання)
}

type Mirror struct {
	URL string `json:"url"` // https://update.org.local/docscan/ або \\server\share\docscan
}

type Marker struct {
	File string `json:"file"`
}

// DefaultRepo — офіційний репозиторій релізів.
const DefaultRepo = "rifatismailov/yara-docscan"

var repoRe = regexp.MustCompile(`^[\w.-]+/[\w.-]+$`)
var windowRe = regexp.MustCompile(`^(\d\d):(\d\d)-(\d\d):(\d\d)$`)

// loadConfig читає updater.json; немає файлу — значення за замовчуванням (github, кожні 6 год).
func loadConfig(path, dataDir string) (*Config, error) {
	c := &Config{}
	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil {
		// PowerShell 5.1 (Set-Content -Encoding UTF8, Out-File) пише з BOM — правлений вручну файл теж має читатися
		if err := json.Unmarshal(bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")), c); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	if c.Mode == "" {
		c.Mode = "github"
	}
	if c.CheckEveryHours <= 0 {
		c.CheckEveryHours = 6
	}
	if c.GitHub.Repo == "" {
		c.GitHub.Repo = DefaultRepo
	}
	if c.Rules.GitHub.Repo == "" {
		c.Rules.GitHub.Repo = DefaultRulesRepo
	}
	if c.Lists.CheckEveryHours <= 0 {
		c.Lists.CheckEveryHours = 24
	}
	if c.Marker.File == "" {
		c.Marker.File = dataDir + `\update\update.json`
	}
	return c, c.check()
}

func (c *Config) check() error {
	switch c.Mode {
	case "github", "marker", "off":
	case "mirror":
		if c.Mirror.URL == "" {
			return fmt.Errorf("mode mirror: mirror.url is empty")
		}
		if err := checkSource(c.Mirror.URL); err != nil {
			return fmt.Errorf("mirror.url: %w", err)
		}
	default:
		return fmt.Errorf("mode %q (github | mirror | marker | off)", c.Mode)
	}
	if !repoRe.MatchString(c.GitHub.Repo) {
		return fmt.Errorf("github.repo %q: expected owner/repo", c.GitHub.Repo)
	}
	if !repoRe.MatchString(c.Rules.GitHub.Repo) {
		return fmt.Errorf("rules.github.repo %q: expected owner/repo", c.Rules.GitHub.Repo)
	}
	if c.Window != "" {
		if _, _, err := parseWindow(c.Window); err != nil {
			return err
		}
	}
	if c.Rules.Mirror.URL != "" {
		if err := checkSource(c.Rules.Mirror.URL); err != nil {
			return fmt.Errorf("rules.mirror.url: %w", err)
		}
	}
	if c.Lists.URL != "" {
		if err := checkSource(c.Lists.URL); err != nil {
			return fmt.Errorf("lists.url: %w", err)
		}
		if len(c.Lists.PublicKeys) == 0 {
			return fmt.Errorf("lists.url is set but lists.public_keys is empty - the lists must be signed by the organisation")
		}
	}
	for _, k := range c.Lists.PublicKeys {
		if _, err := manifest.ParseKey(k); err != nil {
			return fmt.Errorf("lists.public_keys: %w", err)
		}
	}
	for _, k := range c.ExtraPublicKeys {
		if _, err := manifest.ParseKey(k); err != nil {
			return fmt.Errorf("extra_public_keys: %w", err)
		}
	}
	return nil
}

// checkSource — http(s) URL або локальний шлях / UNC (тека з файлами релізу).
func checkSource(s string) error {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") {
		u, err := url.Parse(s)
		if err != nil || u.Host == "" {
			return fmt.Errorf("%q is not a valid URL", s)
		}
		return nil
	}
	if strings.HasPrefix(s, `\\`) || (len(s) > 2 && s[1] == ':' && (s[2] == '\\' || s[2] == '/')) || strings.HasPrefix(s, "/") {
		return nil
	}
	return fmt.Errorf("%q: expected http(s)://..., a UNC path or a local folder", s)
}

// parseWindow — "22:00-06:00" -> хвилини від півночі.
func parseWindow(w string) (from, to int, err error) {
	m := windowRe.FindStringSubmatch(strings.ReplaceAll(w, " ", ""))
	if m == nil {
		return 0, 0, fmt.Errorf("window %q: expected HH:MM-HH:MM", w)
	}
	n := func(s string) int { v := 0; fmt.Sscan(s, &v); return v }
	h1, m1, h2, m2 := n(m[1]), n(m[2]), n(m[3]), n(m[4])
	if h1 > 23 || h2 > 23 || m1 > 59 || m2 > 59 {
		return 0, 0, fmt.Errorf("window %q: bad time", w)
	}
	return h1*60 + m1, h2*60 + m2, nil
}

// inWindow — зараз можна ставити (вікна немає — завжди можна; вікно може переходити через північ).
func (c *Config) inWindow(t time.Time) bool {
	if c.Window == "" {
		return true
	}
	from, to, err := parseWindow(c.Window)
	if err != nil {
		return true
	}
	m := t.Hour()*60 + t.Minute()
	if from <= to {
		return m >= from && m < to
	}
	return m >= from || m < to
}

// Request — що ставити: періодична перевірка (усе порожнє — найновіше з джерела режиму) або маркер агента.
type Request struct {
	Component string `json:"component"`  // program (за замовчуванням) | rules
	Version   string `json:"version"`    // vX.Y.Z; порожньо — найновіше
	Source    string `json:"source"`     // "" | "github" | "mirror" | http(s) URL / UNC теки з файлами релізу
	SHA256    string `json:"sha256"`     // sha256 manifest.json, якщо агент хоче закріпити саме цей реліз
	RequestID string `json:"request_id"` // повертається в записі результату
}

var reqIDRe = regexp.MustCompile(`^[\w.:-]{0,64}$`)
var hex64Re = regexp.MustCompile(`^[0-9a-f]{64}$`)

// parseMarker — маркер агента: суворі формати полів (адреса і хеш не довіряються — довіряється лише підпис
// маніфесту, але сміття в маркері — привід відмовити одразу).
func parseMarker(b []byte) (*Request, error) {
	var r Request
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf")) // маркер, записаний PowerShell-ом, — з BOM
	if err := json.Unmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("marker: %w", err)
	}
	r.SHA256 = strings.ToLower(strings.TrimSpace(r.SHA256))
	switch {
	case r.Version != "" && !manifest.ValidVersion(r.Version):
		return nil, fmt.Errorf("marker: version %q is not vX.Y.Z", r.Version)
	case r.SHA256 != "" && !hex64Re.MatchString(r.SHA256):
		return nil, fmt.Errorf("marker: sha256 is not 64 hex characters")
	case !reqIDRe.MatchString(r.RequestID):
		return nil, fmt.Errorf("marker: request_id: up to 64 characters [A-Za-z0-9_.:-]")
	}
	switch r.Component {
	case "", "program", "rules":
	default:
		return nil, fmt.Errorf("marker: component %q (program | rules)", r.Component)
	}
	switch r.Source {
	case "", "github", "mirror":
	default:
		if err := checkSource(r.Source); err != nil {
			return nil, fmt.Errorf("marker: source: %w", err)
		}
	}
	return &r, nil
}

// component — що оновлювати за цим запитом.
func (r *Request) component() string {
	if r.Component == "rules" || r.Component == "lists" {
		return r.Component
	}
	return "program"
}
