// Package platform — цільові ОС: macOS, Linux (unix.go) і Windows (windows.go). Кожна працює через
// transport.Transport, тож де саме вона виконується (локально, SSH, WinRM), вирішує лише конфіг.
package platform

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// Source — що збирати: точний коміт і способи доставити його на машину.
type Source struct {
	SHA      string
	Archive  func(format string) ([]byte, error) // git archive --format=<zip|tar.gz> <SHA>
	GitURL   string                              // звідки машина може взяти код сама (якщо бачить Forgejo)
	GitToken string                              // токен лише на читання для GitURL
}

// StepResult — результат одного кроку (build, documents, critical, hostile, fuzz, package …).
type StepResult struct {
	Name     string
	Status   string // PASS | FAIL | SKIP
	Duration time.Duration
	Log      string // вивід кроку (для логів у артефактах)
}

// Failed — чи є серед кроків FAIL.
func Failed(steps []StepResult) bool {
	for _, s := range steps {
		if s.Status == "FAIL" {
			return true
		}
	}
	return false
}

// Event — що платформа повідомляє під час роботи (для ходу в терміналі).
type Event struct {
	Platform string
	Kind     string      // machine — вибрано машину; start — почався крок; done — крок завершено
	Where    string      // "10.0.0.5 (pc-216)" — для machine
	Step     string      // ім'я кроку — для start/done
	Result   *StepResult // для done
}

// Reporter отримує події; викликається з горутини платформи (має бути потокобезпечним).
type Reporter func(Event)

// Platform — одна цільова ОС. Порядок викликів:
// Prepare -> SyncSource -> Build -> Test -> FetchArtifacts -> Close (Close — завжди).
type Platform interface {
	Name() string
	Prepare(ctx context.Context) error                                // підключитися (перша доступна машина), перевірити інструменти
	SyncSource(ctx context.Context, src Source) error                 // покласти точний коміт у робочу теку машини
	Build(ctx context.Context) (StepResult, error)                    // повна збірка під цю ОС
	Test(ctx context.Context) ([]StepResult, error)                   // усі тести на цій машині
	FetchArtifacts(ctx context.Context, dst string) ([]string, error) // забрати бінарники / пакет і логи в dst
	Close() error
}

// summaryRx — рядок підсумку кроку в виводі скриптів: «build          PASS  (57s)».
var summaryRx = regexp.MustCompile(`^(\S+)\s+(PASS|FAIL|SKIP)\b\s*\(?(\d+)?s?\)?`)

// stepTracker розбирає вивід скрипта на кроки: «::group::<крок>» — початок, рядок підсумку — кінець.
type stepTracker struct {
	platform string
	report   Reporter
	known    map[string]bool // кроки, які ми рахуємо (інші рядки «X PASS» ігноруються)
	started  map[string]time.Time
	logs     map[string]*strings.Builder
	cur      string
	steps    []StepResult
}

func newTracker(platform string, report Reporter, known ...string) *stepTracker {
	k := map[string]bool{}
	for _, n := range known {
		k[n] = true
	}
	return &stepTracker{platform: platform, report: report, known: k,
		started: map[string]time.Time{}, logs: map[string]*strings.Builder{}}
}

// line — обробити один рядок виводу.
func (t *stepTracker) line(l string) {
	if strings.HasPrefix(l, "::group::") {
		name := strings.TrimPrefix(l, "::group::")
		if t.known[name] {
			t.cur = name
			t.started[name] = time.Now()
			t.logs[name] = &strings.Builder{}
			t.report(Event{Platform: t.platform, Kind: "start", Step: name})
		}
		return
	}
	if l == "::endgroup::" {
		return
	}
	if m := summaryRx.FindStringSubmatch(l); m != nil && t.known[m[1]] {
		for _, s := range t.steps { // підсумок наприкінці повторюється — кожен крок один раз
			if s.Name == m[1] {
				return
			}
		}
		r := StepResult{Name: m[1], Status: m[2]}
		if st, ok := t.started[m[1]]; ok {
			r.Duration = time.Since(st)
		}
		if b := t.logs[m[1]]; b != nil {
			r.Log = b.String()
		}
		t.steps = append(t.steps, r)
		if t.cur == m[1] {
			t.cur = ""
		}
		t.report(Event{Platform: t.platform, Kind: "done", Step: r.Name, Result: &r})
		return
	}
	if b := t.logs[t.cur]; b != nil {
		b.WriteString(l)
		b.WriteByte('\n')
	}
}
