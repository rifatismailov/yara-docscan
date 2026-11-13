// Package gitops — робота з git: автокоміт з перевіркою безпеки для публічного репозиторію, push,
// git archive точного коміту.
package gitops

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// Git виконує git з аргументами і повертає вивід без кінцевого переводу рядка.
func Git(args ...string) (string, error) {
	b, err := exec.Command("git", args...).Output()
	if err != nil {
		if e, ok := err.(*exec.ExitError); ok && len(e.Stderr) > 0 {
			return "", fmt.Errorf("git %s: %s", strings.Join(args, " "), strings.TrimSpace(string(e.Stderr)))
		}
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// MustGit — Git, але помилка зупиняє програму.
func MustGit(args ...string) string {
	out, err := Git(args...)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	return out
}

// run — git з виводом у термінал (для push / commit), повертає код виходу.
func run(args ...string) int {
	c := exec.Command("git", args...)
	c.Stdout, c.Stderr = os.Stdout, os.Stderr
	if err := c.Run(); err != nil {
		if e, ok := err.(*exec.ExitError); ok {
			return e.ExitCode()
		}
		return 127
	}
	return 0
}

// ------------------------------------------------------------- перевірка безпеки --

// forbidden — що не можна пускати в публічний репозиторій; перевіряються лише ДОДАНІ рядки.
// Внутрішні імена розбиті на шматки ("ab" + "cd"), щоб цей публічний файл сам їх не містив.
var forbidden = []struct {
	rx   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`\b(192\.168\.(1|17|88|129)|10\.10\.67|172\.118\.18)\.\d{1,3}\b`), "internal IP address"},
	{regexp.MustCompile(`(?i)(` + "fort" + "una" + `|` + "odessa" + `\.ua)`), "internal host / user name"},
	{regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token)['"]?\s*[:=]\s*['"][^'"\s]{6,}['"]`), "password / token value"},
	{regexp.MustCompile(`\b[0-9a-f]{40}\b`), "40-hex token (Forgejo/GitHub)"},
}

// surname — прізвище (розбите на шматки); дозволене лише як частина публічного імені облікового запису.
var surname = regexp.MustCompile(`(?i)` + "isma" + "ilov")

// MaxFile — найбільший дозволений файл у коміті (5 МБ): більші — найчастіше випадкові бінарники.
const MaxFile = 5 * 1024 * 1024

func internalSurname(line string) bool {
	for _, m := range surname.FindAllStringIndex(line, -1) {
		if m[0] < 5 || !strings.EqualFold(line[m[0]-5:m[0]], "rifat") {
			return true
		}
	}
	return false
}

// SafetyCheck перевіряє те, що вже в індексі (git add): розміри файлів і кожен доданий рядок.
func SafetyCheck() []string {
	var problems []string
	for _, f := range strings.Split(MustGit("diff", "--cached", "--name-only", "-z"), "\x00") {
		if st, err := os.Stat(f); f != "" && err == nil && st.Mode().IsRegular() && st.Size() > MaxFile {
			problems = append(problems, f+": file larger than 5 MB")
		}
	}
	cur := "?"
	for _, line := range strings.Split(MustGit("diff", "--cached", "-U0", "--no-color"), "\n") {
		switch {
		case strings.HasPrefix(line, "+++ "):
			cur = strings.TrimPrefix(strings.TrimPrefix(line, "+++ "), "b/")
		case strings.HasPrefix(line, "+"):
			text := strings.TrimSpace(line[1:])
			if len(text) > 100 {
				text = text[:100]
			}
			for _, f := range forbidden {
				if f.rx.MatchString(line) {
					problems = append(problems, fmt.Sprintf("%s: %s:  %s", cur, f.what, text))
				}
			}
			if internalSurname(line) {
				problems = append(problems, fmt.Sprintf("%s: internal host / user name:  %s", cur, text))
			}
		}
	}
	return problems
}

// CommitIfNeeded: є незакомічені зміни — git add -A, перевірка безпеки, один коміт. Повертає хеш HEAD.
// Знахідки перевірки — помилка (зміни лишаються у файлах, лише знімаються з індексу).
func CommitIfNeeded(message string, say func(string, ...any)) (string, error) {
	changes, err := Git("status", "--porcelain")
	if err != nil {
		return "", err
	}
	if changes != "" {
		say("commit local changes:")
		for i, l := range strings.Split(changes, "\n") {
			if i == 30 {
				break
			}
			say("    %s", l)
		}
		if run("add", "-A") != 0 {
			return "", fmt.Errorf("git add failed")
		}
		if problems := SafetyCheck(); len(problems) > 0 {
			run("reset", "-q")
			say("\n! NOT committed - the public repository must not get:")
			for i, p := range problems {
				if i == 20 {
					break
				}
				say("    %s", p)
			}
			return "", fmt.Errorf("fix these changes (or commit by hand with --no-commit) and press Run again")
		}
		files := strings.Split(MustGit("diff", "--cached", "--name-only"), "\n")
		msg := message
		if msg == "" {
			var names []string
			for i, f := range files {
				if i == 6 {
					break
				}
				names = append(names, filepath.Base(f))
			}
			msg = "ci: " + strings.Join(names, ", ")
			if len(files) > 6 {
				msg += " ..."
			}
		}
		if run("commit", "-q", "-m", msg) != 0 {
			return "", fmt.Errorf("git commit failed")
		}
		say("    committed: %s  (%s)", MustGit("rev-parse", "--short", "HEAD"), msg)
	}
	return Git("rev-parse", "HEAD")
}

// Dirty — чи є незакомічені зміни (для попередження при --no-commit).
func Dirty() bool {
	s, _ := Git("status", "--porcelain")
	return s != ""
}

// Push — git push <remote> <refs...> з виводом у термінал.
func Push(remote string, refs ...string) error {
	if run(append([]string{"push", remote}, refs...)...) != 0 {
		return fmt.Errorf("git push %s %s failed", remote, strings.Join(refs, " "))
	}
	return nil
}

// Tag ставить легкий тег name на коміт sha (перезаписує, якщо вже є).
func Tag(name, sha string) error {
	if run("tag", "-f", name, sha) != 0 {
		return fmt.Errorf("git tag %s failed", name)
	}
	return nil
}

// Archive — точний коміт архівом (zip для Windows, tar.gz для macOS/Linux); лише файли, що в git.
func Archive(sha, format string) ([]byte, error) {
	return exec.Command("git", "archive", "--format="+format, sha).Output()
}
