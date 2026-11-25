package main

// Опис: docscan-project/DOCSCAN.md#web. «Політика» — docscan-policy.yar (що є виявленням, рівні, що знешкоджувати). Пакетна
// приходить з правилами; локальна правка ПК — <DataDir>\policy\docscan-policy.yar. Застосувати: перевірка компіляції
// разом з усіма правилами ПК (yara64, як watcher), потім вона стає <InstallDir>\rules\docscan-policy.yar, пакетна —
// поруч (docscan-policy.package.yar), watcher перезапускається. DocScanUpdater після кожного оновлення правил ставить
// локальну знову (updater/policy.go). Повернути пакетну — локальна зникає.

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

func (p paths) rulesDir() string    { return filepath.Join(p.install, "rules") }
func (p paths) policyCur() string   { return filepath.Join(p.rulesDir(), "docscan-policy.yar") }
func (p paths) policyPkg() string   { return filepath.Join(p.rulesDir(), "docscan-policy.package.yar") }
func (p paths) policyLocal() string { return filepath.Join(p.data, "policy", "docscan-policy.yar") }
func (p paths) yaraExe() string     { return filepath.Join(p.install, "bin", "yara64.exe") }
func (p paths) fileIndex() string   { return filepath.Join(p.rulesDir(), "file-index.yar") }
func readText(f string) (string, bool) {
	b, err := os.ReadFile(f)
	return string(b), err == nil
}

type policyData struct {
	LocalOn, LocalExists, LocalBroken bool
	Text                              string // у формі
	Package                           string
	Diff                              []diffLine
	Added, Removed                    int
	Rules                             string // версія правил
}

type diffLine struct {
	Op   string // "+" "-" " "
	Text string
}

// packagePolicy — текст пакетної політики (копія поруч, коли діє локальна).
func (s *server) packagePolicy() string {
	if t, ok := readText(s.p.policyPkg()); ok {
		return t
	}
	t, _ := readText(s.p.policyCur())
	return t
}

func (s *server) policyState() policyData {
	d := policyData{Package: s.packagePolicy(), Rules: firstLine(filepath.Join(s.p.rulesDir(), "VERSION.txt"))}
	local, ok := readText(s.p.policyLocal())
	cur, _ := readText(s.p.policyCur())
	d.LocalExists = ok
	d.LocalOn = ok && local == cur && fileExists(s.p.policyPkg())
	d.LocalBroken = ok && !d.LocalOn // локальна є, але діє пакетна (не компілювалась з новими правилами)
	d.Text = d.Package
	if ok {
		d.Text = local
	}
	return d
}

func (s *server) policy(q *req) {
	d := s.policyState()
	if q.r.Method != "POST" {
		d.Diff, d.Added, d.Removed = lineDiff(d.Package, d.Text, 3)
		s.render(q, "policy", "Політика", d)
		return
	}
	text := strings.ReplaceAll(q.r.FormValue("text"), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\n", "\r\n")
	act := q.r.FormValue("act")
	show := func(e error, flash string) {
		d.Text = text
		d.Diff, d.Added, d.Removed = lineDiff(d.Package, text, 3)
		if e != nil {
			s.renderErr(q, "policy", "Політика", d, e)
			return
		}
		s.back(q, "/policy", flash)
	}
	switch act {
	case "check", "apply":
		if strings.TrimSpace(text) == "" {
			show(fmt.Errorf("the policy is empty"), "")
			return
		}
		if err := s.compilePolicy(text); err != nil {
			show(fmt.Errorf("does not compile with the rules of this PC - not applied: %v", err), "")
			return
		}
		if act == "check" {
			d.Text = text
			d.Diff, d.Added, d.Removed = lineDiff(d.Package, text, 3)
			q.r.Form.Set("flash", "компілюється разом з усіма правилами ПК (не застосовано)")
			s.render(q, "policy", "Політика", d)
			return
		}
		if text == strings.ReplaceAll(strings.ReplaceAll(d.Package, "\r\n", "\n"), "\n", "\r\n") {
			show(fmt.Errorf("the text is the same as the package policy - use «повернути пакетну»"), "")
			return
		}
		_, add, rem := lineDiff(d.Package, text, 0)
		os.MkdirAll(filepath.Dir(s.p.policyLocal()), 0o755)
		if !fileExists(s.p.policyPkg()) { // пакетна — поруч, поки діє локальна
			if err := copyFile(s.p.policyCur(), s.p.policyPkg()); err != nil {
				show(err, "")
				return
			}
		}
		err := writeFileAtomic(s.p.policyLocal(), []byte(text), 0o644)
		markWeb(s.p.policyLocal())
		if err != nil {
			show(err, "")
			return
		}
		if err := writeFileAtomic(s.p.policyCur(), []byte(text), 0o644); err != nil {
			show(err, "")
			return
		}
		s.audit(q.r, AdminUser, "policy-local-applied", fmt.Sprintf("+%d -%d lines vs the package policy (%s)", add, rem, d.Rules))
		msg := "локальну політику застосовано"
		if err := restartService("DocScanWatcher"); err != nil {
			msg += "; перезапустіть службу DocScanWatcher (" + err.Error() + ")"
		} else {
			msg += "; DocScanWatcher перезапущено"
		}
		show(nil, msg)
	case "revert":
		if !fileExists(s.p.policyPkg()) && !d.LocalExists {
			show(nil, "діє пакетна політика")
			return
		}
		if fileExists(s.p.policyPkg()) {
			if err := writeFileAtomic(s.p.policyCur(), []byte(d.Package), 0o644); err != nil {
				show(err, "")
				return
			}
			os.Remove(s.p.policyPkg())
		}
		os.Remove(s.p.policyLocal())
		markWeb(s.p.policyLocal())
		s.audit(q.r, AdminUser, "policy-local-removed", d.Rules)
		msg := "повернуто пакетну політику"
		if err := restartService("DocScanWatcher"); err != nil {
			msg += "; перезапустіть службу DocScanWatcher (" + err.Error() + ")"
		} else {
			msg += "; DocScanWatcher перезапущено"
		}
		show(nil, msg)
	default:
		show(nil, "")
	}
}

// compilePolicy — політика разом з file-index.yar ПК (усі правила), як компілює watcher (yara64 --file-vars).
func (s *server) compilePolicy(text string) error {
	if s.checkPolicy != nil {
		return s.checkPolicy(text)
	}
	tmp, err := os.MkdirTemp(filepath.Join(s.p.data, "policy"), "check-")
	if err != nil {
		if err := os.MkdirAll(filepath.Join(s.p.data, "policy"), 0o755); err != nil {
			return err
		}
		if tmp, err = os.MkdirTemp(filepath.Join(s.p.data, "policy"), "check-"); err != nil {
			return err
		}
	}
	defer os.RemoveAll(tmp)
	cand := filepath.Join(tmp, "docscan-policy.yar")
	if err := os.WriteFile(cand, []byte(text), 0o644); err != nil {
		return err
	}
	esc := func(p string) string { return strings.ReplaceAll(p, `\`, `\\`) }
	idx := filepath.Join(tmp, "index.yar")
	os.WriteFile(idx, []byte(fmt.Sprintf("include \"%s\"\r\ninclude \"%s\"\r\n", esc(cand), esc(s.p.fileIndex()))), 0o644)
	probe := filepath.Join(tmp, "probe.txt")
	os.WriteFile(probe, []byte("probe\r\n"), 0o644)
	out, _ := exec.Command(s.p.yaraExe(), "-w", "--file-vars", idx, probe).CombinedOutput()
	var errs []string
	for _, l := range strings.Split(string(out), "\n") {
		if strings.Contains(strings.ToLower(l), "error") {
			errs = append(errs, strings.ReplaceAll(strings.TrimSpace(l), tmp+string(filepath.Separator), ""))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}
	return nil
}

// lineDiff — різниця рядків (LCS), ctx рядків контексту навколо змін; і кількість доданих / прибраних.
func lineDiff(a, b string, ctx int) ([]diffLine, int, int) {
	norm := func(s string) []string {
		s = strings.TrimRight(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
		if s == "" {
			return nil
		}
		return strings.Split(s, "\n")
	}
	x, y := norm(a), norm(b)
	if len(x)*len(y) > 4_000_000 { // занадто великі — лише лічильники
		return nil, len(y), len(x)
	}
	n, m := len(x), len(y)
	L := make([][]int32, n+1)
	for i := range L {
		L[i] = make([]int32, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				L[i][j] = L[i+1][j+1] + 1
			} else if L[i+1][j] >= L[i][j+1] {
				L[i][j] = L[i+1][j]
			} else {
				L[i][j] = L[i][j+1]
			}
		}
	}
	var all []diffLine
	add, rem := 0, 0
	i, j := 0, 0
	for i < n || j < m {
		switch {
		case i < n && j < m && x[i] == y[j]:
			all = append(all, diffLine{" ", x[i]})
			i, j = i+1, j+1
		case j < m && (i == n || L[i][j+1] >= L[i+1][j]):
			all = append(all, diffLine{"+", y[j]})
			add, j = add+1, j+1
		default:
			all = append(all, diffLine{"-", x[i]})
			rem, i = rem+1, i+1
		}
	}
	if ctx <= 0 {
		return nil, add, rem
	}
	// лише зміни з контекстом
	keep := make([]bool, len(all))
	for k, d := range all {
		if d.Op != " " {
			for t := k - ctx; t <= k+ctx; t++ {
				if t >= 0 && t < len(all) {
					keep[t] = true
				}
			}
		}
	}
	var out []diffLine
	gap := false
	for k, d := range all {
		if keep[k] {
			out = append(out, d)
			gap = false
		} else if !gap && len(out) > 0 {
			out = append(out, diffLine{"…", ""})
			gap = true
		}
	}
	return out, add, rem
}
