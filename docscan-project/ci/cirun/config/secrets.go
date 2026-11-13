package config

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strings"
	"sync"

	"golang.org/x/term"
)

// Resolver розгортає посилання на секрети:
//
//	keepassxc:<група/запис>[#атрибут]  — з бази KeePassXC; атрибути: Password (за замовчуванням),
//	                                     UserName, URL, Notes
//	hosts:<профіль>[.<поле>]           — зі старого ~/.docscan/hosts.json; поле за замовчуванням password
//	env:<ЗМІННА>                       — зі змінної середовища
//
// Секрети живуть лише в пам'яті; Resolver нічого не друкує і не пише на диск.
type Resolver struct {
	cfg Secrets

	mu       sync.Mutex
	kxLoaded bool
	kxErr    error
	kx       map[string]map[string]string // "CI/Windows/pc-216" -> {"Password": .., "UserName": ..}
	hosts    map[string]map[string]any
}

// NewResolver створює Resolver; база KeePassXC відкривається лише при першому keepassxc:-посиланні.
func NewResolver(s Secrets) *Resolver { return &Resolver{cfg: s} }

// Get повертає значення за посиланням; порожнє посилання — порожній рядок без помилки.
func (r *Resolver) Get(ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	switch {
	case ref == "":
		return "", nil
	case strings.HasPrefix(ref, "keepassxc:"):
		path, attr, _ := strings.Cut(strings.TrimPrefix(ref, "keepassxc:"), "#")
		if attr == "" {
			attr = "Password"
		}
		if err := r.loadKeePassXC(); err != nil {
			return "", err
		}
		e, ok := r.kx[strings.Trim(path, "/")]
		if !ok {
			return "", fmt.Errorf("%s: no such entry in %s", ref, r.cfg.KeePassXC.Database)
		}
		v, ok := e[attr]
		if !ok {
			return "", fmt.Errorf("%s: attribute %q (Password, UserName, URL, Notes)", ref, attr)
		}
		return v, nil
	case strings.HasPrefix(ref, "hosts:"):
		prof, field, _ := strings.Cut(strings.TrimPrefix(ref, "hosts:"), ".")
		if field == "" {
			field = "password"
		}
		if err := r.loadHosts(); err != nil {
			return "", err
		}
		v, ok := r.hosts[prof][field].(string)
		if !ok {
			return "", fmt.Errorf("%s: not found in %s", ref, r.cfg.HostsFile)
		}
		return v, nil
	case strings.HasPrefix(ref, "env:"):
		name := strings.TrimPrefix(ref, "env:")
		v, ok := os.LookupEnv(name)
		if !ok {
			return "", fmt.Errorf("%s: environment variable is not set", ref)
		}
		return v, nil
	}
	return "", fmt.Errorf("%q: unknown secret reference (keepassxc:, hosts:, env:)", ref)
}

// User — ім'я користувача підключення: user з конфігу або значення user_ref.
func (r *Resolver) User(c Connection) (string, error) {
	if c.User != "" {
		return c.User, nil
	}
	return r.Get(c.UserRef)
}

func (r *Resolver) loadHosts() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.hosts != nil {
		return nil
	}
	b, err := os.ReadFile(ExpandHome(r.cfg.HostsFile))
	if err != nil {
		return err
	}
	h := map[string]map[string]any{}
	if err := json.Unmarshal(b, &h); err != nil {
		return fmt.Errorf("%s: %w", r.cfg.HostsFile, err)
	}
	r.hosts = h
	return nil
}

// keepassxcCLI — шлях до keepassxc-cli: з конфігу, з PATH або з програми KeePassXC на macOS.
func (r *Resolver) keepassxcCLI() (string, error) {
	if c := r.cfg.KeePassXC.CLI; c != "" {
		return ExpandHome(c), nil
	}
	if p, err := exec.LookPath("keepassxc-cli"); err == nil {
		return p, nil
	}
	mac := "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli"
	if _, err := os.Stat(mac); err == nil {
		return mac, nil
	}
	return "", fmt.Errorf("keepassxc-cli not found (install KeePassXC or set secrets.keepassxc.cli)")
}

// masterPassword — майстер-пароль бази за режимом unlock.
func (r *Resolver) masterPassword() (string, error) {
	k := r.cfg.KeePassXC
	switch k.Unlock {
	case "keychain":
		// macOS: пароль лежить у Связці ключів; macOS сама питає дозволу при першому зверненні
		args := []string{"find-generic-password", "-s", k.KeychainItem, "-w"}
		if u, err := user.Current(); err == nil {
			args = append(args, "-a", u.Username)
		}
		out, err := exec.Command("security", args...).Output()
		if err != nil {
			return "", fmt.Errorf("keychain item %q not readable (create it: security add-generic-password -s %s -a $USER -w)", k.KeychainItem, k.KeychainItem)
		}
		return strings.TrimRight(string(out), "\r\n"), nil
	case "prompt":
		// питаємо в терміналі один раз за запуск, без відображення символів
		tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return "", fmt.Errorf("unlock: prompt needs a terminal: %w", err)
		}
		defer tty.Close()
		fmt.Fprintf(tty, "KeePassXC master password for %s: ", k.Database)
		pw, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(tty)
		return string(pw), err
	case "key_file":
		return "", nil // база відкривається лише файлом-ключем
	}
	return "", fmt.Errorf("secrets.keepassxc.unlock %q (keychain | prompt | key_file)", k.Unlock)
}

// loadKeePassXC відкриває базу ОДИН раз за запуск: keepassxc-cli export -f csv (майстер-пароль — через
// stdin, не аргументом), CSV розбирається лише в пам'яті. Інакше кожне посилання знову розшифровувало б
// базу (Argon2, ~1 с на кожне).
func (r *Resolver) loadKeePassXC() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.kxLoaded {
		return r.kxErr
	}
	r.kxLoaded = true
	r.kxErr = func() error {
		k := r.cfg.KeePassXC
		if k.Database == "" {
			return fmt.Errorf("secrets.keepassxc.database is not set")
		}
		cli, err := r.keepassxcCLI()
		if err != nil {
			return err
		}
		pw, err := r.masterPassword()
		if err != nil {
			return err
		}
		args := []string{"export", "-q", "-f", "csv"}
		if k.Unlock == "key_file" {
			args = append(args, "--no-password", "-k", ExpandHome(k.KeyFile))
		}
		args = append(args, ExpandHome(k.Database))
		cmd := exec.Command(cli, args...)
		if k.Unlock != "key_file" {
			cmd.Stdin = strings.NewReader(pw + "\n")
		}
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("KeePassXC database %s not opened: %s", k.Database, strings.TrimSpace(stderr.String()))
		}
		rows, err := csv.NewReader(bytes.NewReader(out)).ReadAll()
		if err != nil || len(rows) == 0 {
			return fmt.Errorf("KeePassXC export: unexpected format")
		}
		col := map[string]int{}
		for i, h := range rows[0] {
			col[h] = i
		}
		get := func(row []string, name string) string {
			if i, ok := col[name]; ok && i < len(row) {
				return row[i]
			}
			return ""
		}
		r.kx = map[string]map[string]string{}
		for _, row := range rows[1:] {
			// Group = "Root/CI/Windows": перший рівень — сама база, його відкидаємо
			group := get(row, "Group")
			if _, rest, ok := strings.Cut(group, "/"); ok {
				group = rest
			} else {
				group = ""
			}
			path := strings.Trim(group+"/"+get(row, "Title"), "/")
			r.kx[path] = map[string]string{
				"Password": get(row, "Password"),
				"UserName": get(row, "Username"),
				"URL":      get(row, "URL"),
				"Notes":    get(row, "Notes"),
			}
		}
		return nil
	}()
	return r.kxErr
}
