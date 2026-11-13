// Package orchestrator — один прогін: збірка й тести на кожній увімкненій платформі (хвилями з
// урахуванням requires), зведення, а після ЗЕЛЕНОГО прогону — push коміту на GitHub (+ Forgejo, якщо увімкнено).
package orchestrator

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"docscan/cirun/config"
	"docscan/cirun/forgejo"
	"docscan/cirun/gitops"
	"docscan/cirun/platform"
)

// ErrNotGreen — прогін не зелений (main перетворює на код виходу).
var ErrNotGreen = errors.New("the run is not green")

// Outcome — підсумок однієї платформи.
type Outcome struct {
	Platform  string
	Status    string // success | failure | skipped
	Reason    string // чому failure / skipped
	Where     string // машина
	Steps     []platform.StepResult
	Artifacts []string
	Took      time.Duration
}

// Options — що робити в цьому прогоні.
type Options struct {
	Only   []string // лише ці платформи (порожньо — усі увімкнені)
	Push   bool     // push коміту на GitHub після зеленого прогону
	Branch string   // гілка для push
	Fuzz   int      // секунди фазингу
}

// Orchestrator — один прогін.
type Orchestrator struct {
	Cfg     *config.Config
	Sec     *config.Resolver
	Opt     Options
	RunDir  string          // ci-out/<прогін>
	Forgejo *forgejo.Client // nil — Forgejo не налаштований
	Results map[string]*Outcome
	// Factory, якщо задано, створює платформи замість справжніх (для тестів оркестратора).
	Factory func(name string, rep platform.Reporter) platform.Platform

	mu      sync.Mutex
	started time.Time
	prog    *progress
}

// Say друкує рядок (потокобезпечно: платформи пишуть з різних горутин).
func (o *Orchestrator) Say(format string, a ...any) {
	o.mu.Lock()
	defer o.mu.Unlock()
	fmt.Printf(format+"\n", a...)
}

// newPlatform створює платформу за іменем.
func (o *Orchestrator) newPlatform(name string, rep platform.Reporter) platform.Platform {
	if o.Factory != nil {
		return o.Factory(name, rep)
	}
	p := o.Cfg.Platforms[name]
	switch name {
	case "macos":
		return platform.NewMacOS(p, o.Sec, o.Opt.Fuzz, o.RunDir, rep)
	case "linux":
		return platform.NewLinux(p, o.Sec, o.Opt.Fuzz, o.RunDir, rep)
	case "windows":
		return platform.NewWindows(p, o.Sec, rep)
	}
	return nil
}

// planned — платформи цього прогону: увімкнені в конфігу (і з --only, якщо задано).
func (o *Orchestrator) planned() []string {
	var out []string
	for _, n := range o.Cfg.Enabled() {
		if len(o.Opt.Only) == 0 || contains(o.Opt.Only, n) {
			out = append(out, n)
		}
	}
	return out
}

// Plan — платформи, які цей прогін збиратиме.
func (o *Orchestrator) Plan() []string { return o.planned() }

// canRun — умова запуску з requires: кожна потрібна платформа має бути в цьому прогоні й зеленою.
func (o *Orchestrator) canRun(name string, planned []string) (bool, string) {
	for _, req := range o.Cfg.Platforms[name].Requires {
		if !contains(planned, req) {
			return false, req + " is not enabled in this run"
		}
		if r := o.Results[req]; r == nil || r.Status != "success" {
			return false, req + " did not pass"
		}
	}
	return true, ""
}

// Build — збірка й тести: хвилі з урахуванням requires, у межах хвилі — паралельно.
// Повертає true, якщо всі заплановані платформи зелені.
func (o *Orchestrator) Build(ctx context.Context, src platform.Source) bool {
	o.started = time.Now()
	o.Results = map[string]*Outcome{}
	planned := o.planned()
	if len(planned) == 0 {
		o.Say("no platform is enabled (config: platforms.*.enabled)")
		return false
	}
	o.prog = newProgress(o, planned)
	o.prog.start()
	defer o.prog.stop()

	pending := append([]string(nil), planned...)
	for len(pending) > 0 {
		var wave, rest []string
		for _, n := range pending {
			done := true
			for _, req := range o.Cfg.Platforms[n].Requires {
				if contains(planned, req) && o.Results[req] == nil {
					done = false
				}
			}
			if done {
				wave = append(wave, n)
			} else {
				rest = append(rest, n)
			}
		}
		if len(wave) == 0 { // config.validate не пропускає цикли; це лише запобіжник
			for _, n := range rest {
				o.Results[n] = &Outcome{Platform: n, Status: "skipped", Reason: "requires cycle"}
			}
			break
		}
		var wg sync.WaitGroup
		for _, n := range wave {
			if ok, why := o.canRun(n, planned); !ok {
				o.Results[n] = &Outcome{Platform: n, Status: "skipped", Reason: why}
				o.Say("    [%s] skipped: %s", n, why)
				o.prog.finish(n)
				continue
			}
			wg.Add(1)
			go func(n string) {
				defer wg.Done()
				out := o.runPlatform(ctx, n, src)
				o.mu.Lock()
				o.Results[n] = out
				o.mu.Unlock()
				o.prog.finish(n)
				o.Say("    %-8s %-8s %4ds   %d%%   %s", n, out.Status, int(out.Took.Seconds()), o.prog.percent(), out.Reason)
			}(n)
		}
		wg.Wait()
		pending = rest
	}
	green := true
	for _, n := range planned {
		if o.Results[n].Status != "success" {
			green = false
		}
	}
	return green
}

// runPlatform проводить одну платформу через усі етапи; при провалі збирає логи.
func (o *Orchestrator) runPlatform(ctx context.Context, name string, src platform.Source) (out *Outcome) {
	t := time.Now()
	out = &Outcome{Platform: name, Status: "failure"}
	p := o.newPlatform(name, func(ev platform.Event) { o.onEvent(out, ev) })
	dst := filepath.Join(o.RunDir, name)
	defer func() {
		if out.Status != "success" {
			if c, ok := p.(interface{ CollectLogs(context.Context, string) }); ok {
				c.CollectLogs(ctx, dst)
			}
		}
		p.Close()
		out.Took = time.Since(t)
	}()
	if err := p.Prepare(ctx); err != nil {
		out.Reason = "prepare: " + err.Error()
		return out
	}
	if err := p.SyncSource(ctx, src); err != nil {
		out.Reason = "source: " + err.Error()
		return out
	}
	b, err := p.Build(ctx)
	out.Steps = append(out.Steps, b)
	if err != nil || b.Status != "PASS" {
		out.Reason = "build failed"
		if err != nil {
			out.Reason += ": " + err.Error()
		}
		return out
	}
	tests, err := p.Test(ctx)
	out.Steps = append(out.Steps, tests...)
	if err != nil || platform.Failed(tests) {
		out.Reason = "tests failed"
		if err != nil {
			out.Reason += ": " + err.Error()
		}
		return out
	}
	files, err := p.FetchArtifacts(ctx, dst)
	out.Artifacts = files
	if err != nil {
		out.Reason = "artifacts: " + err.Error()
		return out
	}
	out.Status = "success"
	return out
}

// onEvent — подія платформи: машина, початок/кінець кроку (друкується одразу, з відсотком).
func (o *Orchestrator) onEvent(out *Outcome, ev platform.Event) {
	switch ev.Kind {
	case "machine":
		out.Where = ev.Where
		o.Say("    [%s] machine: %s", ev.Platform, ev.Where)
	case "start":
		o.prog.stepStart(ev.Platform, ev.Step)
	case "done":
		o.prog.stepDone(ev.Platform, ev.Step)
		o.Say("    [%s %s] %-10s %s (%ds)   %d%%", ev.Platform, out.Where, ev.Step, ev.Result.Status,
			int(ev.Result.Duration.Seconds()), o.prog.percent())
	}
}

// Summary друкує підсумок по платформах і пише його в <RunDir>/summary.txt.
func (o *Orchestrator) Summary() {
	var b strings.Builder
	for _, n := range config.PlatformOrder {
		r := o.Results[n]
		if r == nil {
			continue
		}
		fmt.Fprintf(&b, "%-8s %-8s %s %s\n", n, r.Status, r.Where, r.Reason)
		for _, s := range r.Steps {
			fmt.Fprintf(&b, "    %-12s %s  (%ds)\n", s.Name, s.Status, int(s.Duration.Seconds()))
		}
	}
	os.WriteFile(filepath.Join(o.RunDir, "summary.txt"), []byte(b.String()), 0o644)
	o.Say("\n----- summary\n%s", strings.TrimRight(b.String(), "\n"))
}

// Statuses — стани платформ для статусів коміту у Forgejo.
func (o *Orchestrator) Statuses() []forgejo.Status {
	var st []forgejo.Status
	for _, n := range config.PlatformOrder {
		if r := o.Results[n]; r != nil {
			d := r.Status
			if r.Reason != "" {
				d += ": " + r.Reason
			}
			if r.Where != "" {
				d += " on " + r.Where
			}
			st = append(st, forgejo.Status{Platform: n, State: r.Status, Description: d})
		}
	}
	return st
}

// PublishCommit — після зеленого прогону: git push на GitHub (push.remote) — завжди, від Forgejo не
// залежить: слухач на іншому сервері сам стежить за GitHub. Далі тег (push.tag, якщо задано). Якщо Forgejo
// увімкнено: доступний — Sync (дзеркало / push) і статуси коміту; недоступний — лише повідомлення.
func (o *Orchestrator) PublishCommit(ctx context.Context, sha string) error {
	remote := o.Cfg.Push.Remote
	o.Say("\ngit push %s %s (%s)", remote, o.Opt.Branch, sha[:8])
	if err := gitops.Push(remote, o.Opt.Branch); err != nil {
		return err
	}
	if t := o.Cfg.Push.Tag; t != "" {
		name := strings.ReplaceAll(t, "{short}", sha[:8])
		if err := gitops.Tag(name, sha); err == nil {
			if err := gitops.Push(remote, "refs/tags/"+name); err != nil {
				o.Say("    ! tag %s: %v", name, err)
			} else {
				o.Say("    tag %s -> %s", name, sha[:8])
			}
		}
	}
	if o.Forgejo != nil {
		if err := o.Forgejo.Reachable(ctx); err != nil {
			o.Say("    Forgejo not reachable (%v) - skipped (the mirror syncs on its own schedule)", err)
			return nil
		}
		if err := o.Forgejo.Sync(ctx, o.Opt.Branch, sha); err != nil {
			o.Say("    ! Forgejo: %v", err)
		}
		o.Forgejo.ReportStatuses(ctx, sha, o.Statuses())
	}
	return nil
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// ------------------------------------------------------------------ хід і відсоток --

// weights — звичайна тривалість кроків (секунди): відсоток рахується за ними, бо фазинг займає
// більшу частину часу і простий підрахунок кроків вводив би в оману.
func weights(name string, fuzz int) map[string]float64 {
	fz := 1.0
	if fuzz > 0 {
		fz = float64(fuzz)/2 + 40 // два фазери паралельно по fuzz/2 с + їх збірка
	}
	switch name {
	case "windows":
		return map[string]float64{"checkout": 15, "build": 70, "documents": 90, "critical": 10, "package": 40}
	case "linux":
		return map[string]float64{"build": 180, "documents": 20, "critical": 5, "hostile": 20, "fuzz": fz}
	}
	return map[string]float64{"build": 90, "documents": 20, "critical": 5, "hostile": 20, "fuzz": fz}
}

type track struct {
	w        map[string]float64
	done     map[string]bool
	cur      string
	curStart time.Time
	finished bool
}

type progress struct {
	o      *Orchestrator
	order  []string
	tracks map[string]*track
	quit   chan struct{}
	wg     sync.WaitGroup
	mu     sync.Mutex
}

func newProgress(o *Orchestrator, planned []string) *progress {
	p := &progress{o: o, order: planned, tracks: map[string]*track{}, quit: make(chan struct{})}
	for _, n := range planned {
		p.tracks[n] = &track{w: weights(n, o.Opt.Fuzz), done: map[string]bool{}}
	}
	return p
}

func (p *progress) stepStart(pl, step string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t := p.tracks[pl]; t != nil {
		t.cur, t.curStart = step, time.Now()
	}
}

func (p *progress) stepDone(pl, step string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t := p.tracks[pl]; t != nil {
		t.done[step] = true
		if t.cur == step {
			t.cur = ""
		}
	}
}

func (p *progress) finish(pl string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if t := p.tracks[pl]; t != nil {
		t.finished = true
	}
}

// percent — загальний відсоток: зроблені кроки повною вагою, поточний — за часом (не більше 95 %).
func (p *progress) percent() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	var have, total float64
	for _, t := range p.tracks {
		for s, w := range t.w {
			total += w
			switch {
			case t.finished || t.done[s]:
				have += w
			case s == t.cur:
				have += min(time.Since(t.curStart).Seconds(), 0.95*w)
			}
		}
	}
	if total == 0 {
		return 0
	}
	return int(100 * have / total)
}

// start — рядок стану раз на 30 с: що кожна платформа робить зараз.
func (p *progress) start() {
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		tick := time.NewTicker(30 * time.Second)
		defer tick.Stop()
		for {
			select {
			case <-p.quit:
				return
			case <-tick.C:
				p.mu.Lock()
				var parts []string
				for _, n := range p.order {
					t := p.tracks[n]
					switch {
					case t.finished:
						parts = append(parts, n+": finished")
					case t.cur == "fuzz":
						parts = append(parts, fmt.Sprintf("%s: fuzz %ds/%ds", n, int(time.Since(t.curStart).Seconds()), int(t.w["fuzz"])))
					case t.cur != "":
						parts = append(parts, n+": "+t.cur+" "+strconv.Itoa(int(time.Since(t.curStart).Seconds()))+"s")
					default:
						parts = append(parts, n+": waiting")
					}
				}
				p.mu.Unlock()
				p.o.Say("    ... %s   ~%d%%   (%s)", strings.Join(parts, " | "), p.percent(), time.Since(p.o.started).Round(time.Second))
			}
		}
	}()
}

func (p *progress) stop() {
	close(p.quit)
	p.wg.Wait()
}
