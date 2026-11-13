// cirun — «кнопка Запуск» проєкту DocScan (VS Code ▷ / задача «DocScan CI»).
//
// Один запуск:
//
//	коміт локальних змін (з перевіркою безпеки, без push) -> збірка і всі тести на кожній увімкненій
//	платформі (macOS, Windows, Linux — з config.yaml) -> якщо все зелене: git push на GitHub (завжди; слухач
//	на іншому сервері сам бачить новий коміт; Forgejo — лише необов'язкове доповнення) -> набір на сервер.
//
// Запуск (з кореня репозиторію або будь-де в ньому):
//
//	go run -C docscan-project/ci/cirun . [--config FILE] [--only macos,windows] [--fuzz SECONDS]
//	        [-m "повідомлення"] [--no-commit] [--no-push] [--no-publish] [--plan] [--push-only]
//	        [--publish-dir DIR]
//	go run -C docscan-project/ci/cirun . windows      (лише Windows за змінними середовища — для ci.yml)
//
// Налаштування — docscan-project/ci/config.yaml (не в git; зразок — config.example.yaml). Паролів у
// конфігу немає: посилання keepassxc:/hosts:/env: розгортає config.Resolver.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"docscan/cirun/assets"
	"docscan/cirun/config"
	"docscan/cirun/deploy"
	"docscan/cirun/forgejo"
	"docscan/cirun/gitops"
	"docscan/cirun/orchestrator"
	"docscan/cirun/platform"
	"docscan/cirun/transport"
)

func say(format string, a ...any) { fmt.Printf(format+"\n", a...) }

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func main() {
	// "go run -C docscan-project/ci/cirun ." стартує в теці модуля: працюємо з кореня репозиторію
	if err := os.Chdir(gitops.MustGit("rev-parse", "--show-toplevel")); err != nil {
		die("%v", err)
	}
	if len(os.Args) > 1 && os.Args[1] == "windows" {
		os.Exit(legacyWindows())
	}

	cfgPath := flag.String("config", "docscan-project/ci/config.yaml", "configuration file")
	only := flag.String("only", "", "only these platforms, comma-separated (macos,windows,linux)")
	fuzz := flag.Int("fuzz", -1, "fuzzing seconds per OS (default: fuzz_seconds from the config; 0 = none)")
	msg := flag.String("m", "", "commit message for the auto-commit")
	flag.StringVar(msg, "message", "", "same as -m")
	noCommit := flag.Bool("no-commit", false, "do not commit local changes (the last commit is built)")
	noPush := flag.Bool("no-push", false, "do not git push the commit to GitHub after a green run")
	noPublish := flag.Bool("no-publish", false, "do not upload the deployment set to the server")
	plan := flag.Bool("plan", false, "check config, secrets and machines; build nothing")
	pushOnly := flag.Bool("push-only", false, "only git push HEAD to GitHub (after an earlier green run)")
	publishDir := flag.String("publish-dir", "", "only publish an existing deployment set (ci-out/<run>/deploy)")
	flag.Parse()

	cfg, err := config.Load(*cfgPath)
	if err != nil {
		die("%v\n(create it from docscan-project/ci/config.example.yaml)", err)
	}
	sec := config.NewResolver(cfg.Secrets)
	if *fuzz < 0 {
		*fuzz = cfg.FuzzSeconds
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	if *publishDir != "" {
		s, err := deploy.ExistingSet(*publishDir)
		if err == nil {
			err = deploy.Publish(s, cfg.Deploy, sec, say)
		}
		result(err == nil, map[bool]string{true: "PUBLISHED", false: fmt.Sprint("NOT published: ", err)}[err == nil])
		return
	}
	if *plan {
		os.Exit(showPlan(ctx, cfg, sec, splitList(*only)))
	}

	started := time.Now()
	branch := gitops.MustGit("rev-parse", "--abbrev-ref", "HEAD")

	// Forgejo — необов'язковий: лише якщо увімкнений у конфігу (дзеркало, статуси коміту)
	var fj *forgejo.Client
	if cfg.Forgejo.Enabled {
		if fj, err = forgejo.New(cfg.Forgejo, sec, say); err != nil {
			say("! Forgejo: %v - skipped", err)
			fj = nil
		}
	}

	// ---- коміт (без push: push на GitHub — лише після зеленого прогону)
	var sha string
	if *noCommit || cfg.Repo.Commit == "off" {
		if gitops.Dirty() {
			say("! uncommitted changes (--no-commit): remote machines build the last commit %s; a local platform"+
				" with workdir \".\" builds the working tree as it is", gitops.MustGit("rev-parse", "--short", "HEAD"))
		}
		sha = gitops.MustGit("rev-parse", "HEAD")
	} else {
		message := *msg
		if message == "" {
			message = cfg.Repo.Message
		}
		if sha, err = gitops.CommitIfNeeded(message, say); err != nil {
			die("%v", err)
		}
	}

	o := &orchestrator.Orchestrator{Cfg: cfg, Sec: sec, Forgejo: fj,
		Opt: orchestrator.Options{Only: splitList(*only), Push: !*noPush, Branch: branch, Fuzz: *fuzz}}

	if *pushOnly {
		err := o.PublishCommit(ctx, sha)
		result(err == nil, map[bool]string{true: "PUSHED " + sha[:8], false: fmt.Sprint("NOT pushed: ", err)}[err == nil])
		return
	}

	// ---- збірка і тести
	o.RunDir = filepath.Join(cfg.OutDir, "run-"+time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(o.RunDir, 0o755); err != nil {
		die("%v", err)
	}
	src := platform.Source{SHA: sha, Archive: func(f string) ([]byte, error) { return gitops.Archive(sha, f) }}
	if cfg.Forgejo.Enabled && cfg.Forgejo.URL != "" { // інакше Windows отримує zip точного коміту
		src.GitURL = strings.TrimRight(cfg.Forgejo.URL, "/") + "/" + cfg.Forgejo.Repo + ".git"
		src.GitToken, _ = sec.Get(cfg.Forgejo.CheckoutTokenRef)
	}
	// тестові файли поза git (корпуси, шкідливе ПЗ): Мак — локальна копія, віддалені машини — зі сховку
	if cfg.Tests.Enabled {
		as, err := assets.Prepare(cfg.Tests, sec, say)
		if err != nil {
			say("! test assets: %v - remote machines skip the corpus / malware steps", err)
		}
		o.Assets = as
		if as != nil {
			say("test assets %s: corpus %s", as.Version, map[bool]string{true: "local + store", false: "local only"}[as.CorpusURL != ""])
		}
	}
	say("build %s (%s) on: %s   fuzzing %ds", sha[:8], branch, strings.Join(o.Plan(), ", "), *fuzz)
	green := o.Build(ctx, src)
	o.Summary()
	if !o.Consistency() { // однакові файли мають дати однакові рішення на всіх ОС
		green = false
	}

	tail := []string{}
	// ---- push коміту на GitHub (лише зелений прогін; від Forgejo не залежить)
	pushNote := ""
	if green && !*noPush && cfg.Push.Enabled {
		if err := o.PublishCommit(ctx, sha); err != nil {
			say("! git push: %v", err)
			pushNote = "  (push failed: run later with --push-only)"
			tail = append(tail, "NOT pushed")
		} else {
			tail = append(tail, "PUSHED")
		}
	} else if !green {
		say("\n! the run is not green - nothing is pushed or published")
	}

	// ---- набір для розгортання
	if green && cfg.Deploy.Publish && !*noPublish {
		s, err := deploy.Build(o.RunDir, cfg.Deploy, say)
		switch {
		case err != nil:
			say("! deployment set: %v", err)
			tail = append(tail, "NOT published")
		case s != nil:
			if err := deploy.Publish(s, cfg.Deploy, sec, say); err != nil {
				say("! publish: %v", err)
				tail = append(tail, "NOT published")
			} else {
				tail = append(tail, "PUBLISHED")
			}
		}
	}

	abs, _ := filepath.Abs(o.RunDir)
	say("\nRESULT: %s   (%d min)   artifacts: %s   %s%s", map[bool]string{true: "SUCCESS", false: "FAILURE"}[green],
		int(time.Since(started).Minutes()), abs, strings.Join(tail, "  "), pushNote)
	if !green || contains(tail, "NOT published") {
		os.Exit(1)
	}
	if contains(tail, "NOT pushed") {
		os.Exit(2) // зібрано й перевірено, але push на GitHub не вдався
	}
}

// result друкує RESULT для коротких режимів і виходить з кодом 0/1.
func result(ok bool, text string) {
	say("\nRESULT: %s", text)
	if !ok {
		os.Exit(1)
	}
}

// showPlan — --plan: конфіг, посилання на секрети (без значень), доступність машин і Forgejo.
func showPlan(ctx context.Context, cfg *config.Config, sec *config.Resolver, only []string) int {
	bad := 0
	check := func(what, ref string) {
		if ref == "" {
			return
		}
		if _, err := sec.Get(ref); err != nil {
			say("      %-9s %-40s ERROR %v", what, ref, err)
			bad++
		} else {
			say("      %-9s %-40s ok", what, ref)
		}
	}
	say("config: %s", cfg.Path)
	for _, n := range cfg.Enabled() {
		if len(only) > 0 && !contains(only, n) {
			continue
		}
		p := cfg.Platforms[n]
		req := ""
		if len(p.Requires) > 0 {
			req = "   requires: " + strings.Join(p.Requires, ", ")
		}
		say("  %s%s", n, req)
		for _, m := range p.Machines() {
			state := "reachable"
			if !transport.Reachable(m.Connection) {
				state = "NOT reachable"
			}
			say("    %-10s %-6s %-18s %s", m.Name, m.Connection.Type, m.Connection.Host, state)
			check("user", m.Connection.UserRef)
			check("password", m.Connection.PasswordRef)
		}
	}
	if cfg.Tests.Enabled {
		t := cfg.Tests
		for _, d := range append(append([]string{}, t.CorpusDirs...), t.Seeds, t.Malware) {
			if d == "" {
				continue
			}
			state := "ok"
			if _, err := os.Stat(config.ExpandHome(d)); err != nil {
				state = "MISSING"
				bad++
			}
			say("  tests    %-40s %s", d, state)
		}
		if t.Store.URL != "" {
			say("  store    %s/%s (generic package %s)", t.Store.URL, t.Store.Owner, t.Store.Package)
			check("token", t.Store.TokenRef)
		}
	}
	if cfg.Push.Enabled {
		url, _ := gitops.Git("remote", "get-url", cfg.Push.Remote)
		state := "reachable"
		cctx, cancel := context.WithTimeout(ctx, 15*time.Second)
		cmd := exec.CommandContext(cctx, "git", "ls-remote", "--heads", cfg.Push.Remote)
		cmd.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
		if err := cmd.Run(); err != nil {
			state = "NOT reachable (" + err.Error() + ")"
			bad++
		}
		cancel()
		say("  push     %s (%s)  %s", cfg.Push.Remote, url, state)
	} else {
		say("  push     disabled (push.enabled: false)")
	}
	if cfg.Forgejo.Enabled {
		say("  forgejo  %s  mode: %s  check: %s", cfg.Forgejo.URL, cfg.Forgejo.Mode, cfg.Forgejo.Check.Method)
		check("token", cfg.Forgejo.TokenRef)
		check("checkout", cfg.Forgejo.CheckoutTokenRef)
		if fj, err := forgejo.New(cfg.Forgejo, sec, say); err == nil {
			if err := fj.Reachable(ctx); err != nil {
				say("      Forgejo NOT reachable: %v", err)
			} else {
				say("      Forgejo reachable")
			}
		}
	}
	if cfg.Deploy.Publish {
		say("  deploy   %s:%s  %s", cfg.Deploy.Host, cfg.Deploy.Dir, deploy.Base(cfg.Deploy))
		check("user", cfg.Deploy.UserRef)
		check("password", cfg.Deploy.PasswordRef)
	}
	if bad > 0 {
		say("\n%d problem(s) found", bad)
		return 1
	}
	return 0
}

// legacyWindows — «cirun windows»: лише Windows за змінними середовища (WIN11_*/WIN216_* HOST/USER/PASS,
// GIT_URL, GIT_TOKEN, SHA, CI_OUT) — так його викликає завдання windows у .forgejo/workflows/ci.yml.
// Артефакти — у $CI_OUT/artifacts (+ summary.txt), як і раніше.
func legacyWindows() int {
	sha := os.Getenv("SHA")
	if sha == "" {
		fmt.Println("SHA is not set")
		return 1
	}
	p := &config.Platform{Enabled: true, Source: "auto", Workdir: os.Getenv("WIN_DIR")}
	for _, pre := range [][2]string{{"WIN11", "vm-win11"}, {"WIN216", "pc-216"}} {
		if h := strings.TrimSpace(os.Getenv(pre[0] + "_HOST")); h != "" {
			p.Candidates = append(p.Candidates, config.Candidate{Name: pre[1], Connection: config.Connection{
				Type: "winrm", Host: h, Port: 5985, Auth: "ntlm", User: os.Getenv(pre[0] + "_USER"), PasswordRef: "env:" + pre[0] + "_PASS"}})
		}
	}
	out := os.Getenv("CI_OUT")
	if out == "" {
		out = "ci-out"
	}
	art := filepath.Join(out, "artifacts")
	sec := config.NewResolver(config.Secrets{})
	var summary []string
	rep := func(ev platform.Event) {
		switch ev.Kind {
		case "machine":
			fmt.Println("Windows build machine: " + ev.Where)
			summary = append(summary, "machine        "+ev.Where)
		case "done":
			line := fmt.Sprintf("%-14s %s  (%ds)", ev.Step, ev.Result.Status, int(ev.Result.Duration.Seconds()))
			fmt.Println(line)
			summary = append(summary, line)
		}
	}
	w := platform.NewWindows(p, sec, 0, nil, rep)
	defer w.Close()
	ctx := context.Background()
	src := platform.Source{SHA: sha, GitURL: os.Getenv("GIT_URL"), GitToken: os.Getenv("GIT_TOKEN"),
		Archive: func(f string) ([]byte, error) { return gitops.Archive(sha, f) }}
	ok := false
	if err := w.Prepare(ctx); err != nil {
		fmt.Println(err)
	} else if err := w.SyncSource(ctx, src); err != nil {
		fmt.Println(err)
	} else if b, _ := w.Build(ctx); b.Status == "PASS" {
		tests, _ := w.Test(ctx)
		if _, err := w.FetchArtifacts(ctx, art); err != nil {
			fmt.Println(err)
		} else {
			ok = !platform.Failed(tests)
		}
	}
	w.SaveLogs(art)
	os.MkdirAll(art, 0o755)
	os.WriteFile(filepath.Join(art, "summary.txt"), []byte(strings.Join(summary, "\n")+"\n"), 0o644)
	fmt.Println("\n===== Windows summary\n" + strings.Join(summary, "\n"))
	if ok {
		return 0
	}
	return 1
}

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
