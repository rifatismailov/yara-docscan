package main

// Конвеєр Forgejo Actions (.forgejo/workflows/pipeline.yml) — підкоманди для завдань workflow:
//
//	cirun probe  --art DIR [--output FILE]          які стенди доступні: <ім'я>=online|offline у FILE ($GITHUB_OUTPUT);
//	                                                недоступний стенд одразу отримує статус SKIPPED (host offline)
//	cirun stand  --name N --sha SHA --art DIR       один стенд: збірка / тести за його role і suite, статус і артефакти
//	             [--fuzz S] [--assets VER] [--malware]   у DIR/<N>/ (status.json, логи кроків, пакет / tar.gz)
//	cirun report --art DIR [--mac "OK|деталі"] [--md FILE]   зведення у форматі [CI/CD] ..., таблиця «Verified on»
//	                                                для релізу; код 1 — є ERROR (або жоден стенд не пройшов)
//	cirun publish --art DIR --sha SHA [--release] [--bump patch|minor|major] [--notes FILE]
//	                                                перевірка безпеки комітів, що йдуть на GitHub -> git push -> реліз
//
// Статуси коміту у Forgejo (якщо задано CIRUN_FORGEJO_URL / _REPO / _TOKEN): cirun/<стенд> з описом
// "<назва>|<OK|ERROR|SKIPPED>|<деталі>", cirun/result, cirun/publish — їх читає ▷ на Маку.
//
// DIR — спільна тека прогону на хості раннера (усі завдання одного прогону бачать її): так збірка стенда role
// build дістається стендам role test без сторонніх сховищ.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"docscan/cirun/assets"
	"docscan/cirun/config"
	"docscan/cirun/deploy"
	"docscan/cirun/forgejo"
	"docscan/cirun/gitops"
	"docscan/cirun/platform"
	"docscan/cirun/rulesrc"
	"docscan/cirun/transport"
)

// StandStatus — підсумок одного стенда (DIR/<ім'я>/status.json).
type StandStatus struct {
	Name      string       `json:"name"`
	Title     string       `json:"title"`
	OS        string       `json:"os"`
	Role      string       `json:"role"`
	Suite     string       `json:"suite"`
	Status    string       `json:"status"` // OK | ERROR | SKIPPED
	Detail    string       `json:"detail"`
	Where     string       `json:"where"`
	Seconds   int          `json:"seconds"`
	Steps     []StepStatus `json:"steps"`
	Artifacts []string     `json:"artifacts"` // імена файлів у DIR/<ім'я>/
}

// StepStatus — один крок стенда.
type StepStatus struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Seconds int    `json:"seconds"`
}

func pipelineCommand(args []string) int {
	switch args[0] {
	case "publish":
		return cmdPublish(args[1:])
	case "probe":
		return cmdProbe(args[1:])
	case "prepare":
		return cmdPrepare(args[1:])
	case "rules-release":
		return cmdRulesRelease(args[1:])
	case "stand":
		return cmdStand(args[1:])
	case "report":
		return cmdReport(args[1:])
	}
	return -1
}

func loadPipelineConfig(path string) (*config.Config, *config.Resolver) {
	cfg, err := config.Load(path)
	if err != nil {
		die("%v", err)
	}
	if len(cfg.Stands) == 0 {
		die("%s: no stands (section stands:)", path)
	}
	return cfg, config.NewResolver(cfg.Secrets)
}

func writeStatus(dir string, st *StandStatus) error {
	d := filepath.Join(dir, st.Name)
	if err := os.MkdirAll(d, 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(filepath.Join(d, "status.json"), b, 0o644)
}

func readStatus(dir, name string) *StandStatus {
	b, err := os.ReadFile(filepath.Join(dir, name, "status.json"))
	if err != nil {
		return nil
	}
	var st StandStatus
	if json.Unmarshal(b, &st) != nil {
		return nil
	}
	return &st
}

// postStatus — статус коміту у Forgejo для ▷ (тихо нічого, якщо змінних середовища немає).
func postStatus(sha, name, title, state, detail string) {
	u, repo, tok := os.Getenv("CIRUN_FORGEJO_URL"), os.Getenv("CIRUN_FORGEJO_REPO"), os.Getenv("CIRUN_FORGEJO_TOKEN")
	if u == "" || repo == "" || tok == "" || sha == "" {
		return
	}
	st := map[string]string{"OK": "success", "ERROR": "failure", "SKIPPED": "warning", "RUNNING": "pending"}[state]
	if st == "" {
		st = "error"
	}
	c := forgejo.NewClient(u, repo, tok)
	if err := c.SetStatus(context.Background(), sha, "cirun/"+name, st, title+"|"+state+"|"+detail, os.Getenv("CIRUN_RUN_URL")); err != nil {
		fmt.Printf("! commit status cirun/%s: %v\n", name, err)
	}
}

func standStatus(s *config.Stand) *StandStatus {
	return &StandStatus{Name: s.Name, Title: s.Title, OS: s.OS, Role: s.Role, Suite: s.Suite,
		Where: fmt.Sprintf("%s (%s)", s.Connection.Host, s.Name)}
}

// ---------------------------------------------------------------- probe --

func cmdProbe(args []string) int {
	fs := flag.NewFlagSet("probe", flag.ExitOnError)
	cfgPath := fs.String("config", "docscan-project/ci/config.yaml", "configuration file")
	art := fs.String("art", "", "run folder shared by the jobs of this run")
	output := fs.String("output", os.Getenv("GITHUB_OUTPUT"), "file for <stand>=online|offline lines (job outputs)")
	sha := fs.String("sha", "", "commit (for the Forgejo commit statuses)")
	fs.Parse(args)
	cfg, _ := loadPipelineConfig(*cfgPath)
	if *art == "" {
		die("probe: --art is required")
	}
	var lines []string
	for i := range cfg.Stands {
		s := &cfg.Stands[i]
		state := "offline"
		if transport.Reachable(s.Connection) {
			state = "online"
		} else {
			st := standStatus(s)
			st.Status, st.Detail = "SKIPPED", "host offline"
			if err := writeStatus(*art, st); err != nil {
				die("%v", err)
			}
			postStatus(*sha, s.Name, s.Title, st.Status, st.Detail)
		}
		fmt.Printf("[probe] %-28s %-20s %s\n", s.Title, s.Connection.Host, state)
		lines = append(lines, s.Name+"="+state)
	}
	if *output != "" {
		f, err := os.OpenFile(*output, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			die("%v", err)
		}
		fmt.Fprintln(f, strings.Join(lines, "\n"))
		f.Close()
	}
	return 0
}

// ---------------------------------------------------------------- stand --

func cmdStand(args []string) int {
	fs := flag.NewFlagSet("stand", flag.ExitOnError)
	cfgPath := fs.String("config", "docscan-project/ci/config.yaml", "configuration file")
	name := fs.String("name", "", "stand name (stands[].name)")
	sha := fs.String("sha", "", "commit to build and test (must be in this checkout)")
	art := fs.String("art", "", "run folder shared by the jobs of this run")
	fuzz := fs.Int("fuzz", 0, "fuzzing seconds (Linux stands)")
	assetsVer := fs.String("assets", "", "version of the test files in the Forgejo store (from ▷ on the Mac); empty - no corpus / malware")
	malware := fs.Bool("malware", true, "the assets version has malware.zip")
	rulesVer := fs.String("rules", "latest", "rules release of yara-docscan-rules (the version ▷ tested on macOS)")
	combat := fs.Bool("combat", false, "stage 3 (release only): the combat test on this stand after a green stage 2 - Windows: the installed watcher on the build stand's package with ~5 500 test files; Linux: the full suite again with long fuzzing (--fuzz)")
	fs.Parse(args)
	if *name == "" || *sha == "" || *art == "" {
		die("stand: --name, --sha and --art are required")
	}
	cfg, sec := loadPipelineConfig(*cfgPath)
	s := cfg.Stand(*name)
	if s == nil {
		die("stand %q is not in the config", *name)
	}
	full, err := gitops.Git("rev-parse", "--verify", *sha+"^{commit}")
	if err != nil {
		die("commit %s is not in this checkout", *sha)
	}
	st := standStatus(s)
	if *combat { // свій статус (<стенд>-combat): результат етапу 2 цього стенда лишається
		st.Name, st.Title = s.Name+"-combat", s.Title+" combat"
	}
	if prev := readStatus(*art, s.Name); prev != nil && prev.Status == "SKIPPED" {
		if *combat { // реліз без бойового тесту неможливий: недоступний стенд — ERROR, не пропуск
			st.Status, st.Detail = "ERROR", "the stand is offline: "+prev.Detail
			writeStatus(*art, st)
			fmt.Printf("[%s] %s: %s\n", st.Name, st.Title, st.Detail)
			return 1
		}
		fmt.Printf("[%s] %s: %s - skipped\n", s.Name, s.Title, prev.Detail)
		return 0
	}
	t0 := time.Now()
	postStatus(full, st.Name, st.Title, "RUNNING", s.Suite+" suite on "+s.Connection.Host)
	finish := func() int {
		st.Seconds = int(time.Since(t0).Seconds())
		if st.Status == "OK" {
			var names []string
			for _, x := range st.Steps {
				if x.Status == "PASS" {
					names = append(names, x.Name)
				}
			}
			st.Detail = fmt.Sprintf("%s suite: %s, %s", s.Suite, strings.Join(names, ", "), (time.Duration(st.Seconds) * time.Second).String())
		}
		if err := writeStatus(*art, st); err != nil {
			fmt.Println("! status:", err)
		}
		postStatus(full, st.Name, st.Title, st.Status, st.Detail)
		fmt.Printf("[%s] %s -> %s (%s)\n", s.Name, s.Title, st.Status, st.Detail)
		if st.Status == "ERROR" {
			return 1
		}
		return 0
	}

	// етап 3: бойовий тест лише після зеленого етапу 2 (жоден стенд не ERROR / без результату)
	if *combat {
		var bad []string
		for i := range cfg.Stands {
			o := readStatus(*art, cfg.Stands[i].Name)
			if o == nil || o.Status == "ERROR" {
				bad = append(bad, cfg.Stands[i].Name)
			}
		}
		if len(bad) > 0 {
			st.Status, st.Detail = "SKIPPED", "stage 2 is not green ("+strings.Join(bad, ", ")+") - no combat test, no release"
			return finish()
		}
	}

	// збірка стенда-збирача для role test
	prebuilt := ""
	if s.Role == "test" {
		b := readStatus(*art, s.From)
		if b == nil || b.Status != "OK" {
			why := "not run"
			if b != nil {
				why = b.Status + ": " + b.Detail
			}
			st.Status, st.Detail = "SKIPPED", "no build from "+s.From+" ("+why+")"
			return finish()
		}
		zips, _ := filepath.Glob(filepath.Join(*art, s.From, "DocScan-*.zip"))
		if len(zips) == 0 {
			st.Status, st.Detail = "ERROR", "no package from "+s.From
			return finish()
		}
		prebuilt = zips[0]
	}

	var as *assets.Assets
	if s.Suite == "full" && *assetsVer != "" {
		if as, err = assets.Remote(cfg.Tests, sec, *assetsVer, *malware); err != nil {
			fmt.Printf("[%s] ! test assets: %v - corpus / malware steps are skipped\n", s.Name, err)
			as = nil
		}
	}
	dst := filepath.Join(*art, s.Name)
	os.MkdirAll(dst, 0o755)
	falseV := false
	cand := config.Candidate{Name: s.Name, Connection: s.Connection}
	if s.Suite == "smoke" {
		cand.FullTests = &falseV
	}
	pc := &config.Platform{Enabled: true, Candidates: []config.Candidate{cand}, Workdir: s.Workdir, Source: "zip"}
	rep := func(ev platform.Event) {
		switch ev.Kind {
		case "machine":
			st.Where = ev.Where
			fmt.Printf("[%s] machine: %s\n", s.Name, ev.Where)
		case "note":
			fmt.Printf("[%s] ! %s\n", s.Name, ev.Step)
		case "start":
			fmt.Printf("[%s] %s ...\n", s.Name, ev.Step)
		case "done":
			fmt.Printf("[%s] %-10s %s (%ds)\n", s.Name, ev.Step, ev.Result.Status, int(ev.Result.Duration.Seconds()))
		}
	}
	var p platform.Platform
	switch s.OS {
	case "windows":
		pc.Script = ""
		w := platform.NewWindows(pc, sec, 0, as, rep)
		w.SetStand(s.Role, s.Suite, prebuilt)
		w.SetLoad(s.Load)
		if *combat {
			if s.Role != "test" || prebuilt == "" {
				st.Status, st.Detail = "ERROR", "combat test: a role test stand with the build stand's package is needed"
				return finish()
			}
			fsrv, err := combatFileServer(cfg)
			if err != nil {
				st.Status, st.Detail = "ERROR", "combat test: "+err.Error()
				return finish()
			}
			w.SetStand("test", "combat", prebuilt) // лише бойовий тест: повний набір цей пакет уже пройшов на етапі 2
			w.SetLoad(nil)
			w.EnableCombat(fsrv)
		}
		p = w
	case "linux":
		pc.Script = "docscan-project/ci/build-test-unix.sh"
		abs, _ := filepath.Abs(dst)
		p = platform.NewLinux(pc, sec, *fuzz, abs, as, rep)
	}
	// SIGTERM: Forgejo скасовує завдання — кроки прибирання (тестові файли, навантажувальний тест) ще встигають
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	defer p.Close()
	st.Status = "ERROR"
	add := func(rs ...platform.StepResult) {
		for _, r := range rs {
			st.Steps = append(st.Steps, StepStatus{r.Name, r.Status, int(r.Duration.Seconds())})
		}
	}
	collect := func() {
		if c, ok := p.(interface{ CollectLogs(context.Context, string) }); ok {
			c.CollectLogs(ctx, dst)
		}
	}
	if err := p.Prepare(ctx); err != nil {
		st.Detail = "prepare: " + err.Error()
		return finish()
	}
	src := platform.Source{SHA: full, Archive: func(f string) ([]byte, error) { return gitops.Archive(full, f) }}
	// правила цього прогону: підписаний реліз yara-docscan-rules (кеш у теці прогону — спільний для завдань)
	rules, err := rulesrc.Fetch(*rulesVer, filepath.Join(*art, "rules"))
	if err != nil {
		st.Detail = "rules: " + err.Error()
		return finish()
	}
	src.RulesZip, src.RulesBundle, src.RulesVersion = rules.Zip, rules.Bundle, rules.Version
	fmt.Printf("[%s] rules %s\n", s.Name, rules.Version)
	if err := p.SyncSource(ctx, src); err != nil {
		st.Detail = "source: " + err.Error()
		collect()
		return finish()
	}
	b, err := p.Build(ctx)
	add(b)
	if err != nil || b.Status != "PASS" {
		st.Detail = "FAIL: build"
		collect()
		return finish()
	}
	tests, err := p.Test(ctx)
	add(tests...)
	if err != nil || platform.Failed(tests) {
		var bad []string
		for _, r := range tests {
			if r.Status == "FAIL" {
				bad = append(bad, r.Name)
			}
		}
		st.Detail = "FAIL: " + strings.Join(bad, ", ")
		if err != nil {
			st.Detail += " (" + err.Error() + ")"
		}
		collect()
		return finish()
	}
	files, err := p.FetchArtifacts(ctx, dst)
	if err != nil {
		st.Detail = "artifacts: " + err.Error()
		return finish()
	}
	for _, f := range files {
		st.Artifacts = append(st.Artifacts, filepath.Base(f))
	}
	// етап 1: пакет стенда-збирача — у сховок Forgejo (docscan-builds/<коміт>): його видно в Packages, з нього
	// тестують інші стенди, бойовий тест і реліз (той самий файл)
	if s.Role == "build" && !*combat {
		if zips, _ := filepath.Glob(filepath.Join(dst, "DocScan-*.zip")); len(zips) > 0 {
			if err := putBuild(cfg, sec, full, filepath.Base(zips[0]), zips[0]); err != nil {
				fmt.Printf("[%s] ! package to the Forgejo store: %v\n", s.Name, err)
			} else {
				fmt.Printf("[%s] package %s -> Forgejo store (%s/%s)\n", s.Name, filepath.Base(zips[0]), BuildsPackage, full[:12])
			}
		}
	}
	st.Status = "OK"
	return finish()
}

// combatFileServer — звідки бойовий тест бере тестові файли: fileserver з конфігу, а на раннері, де його в
// CIRUN_CONFIG немає, — із секретів Forgejo CI_FS_UNC, CI_FS_USER, CI_FS_PASS (адреса не в публічному workflow).
func combatFileServer(cfg *config.Config) (config.FileServer, error) {
	if cfg.FileServer.UNC != "" {
		return cfg.FileServer, nil
	}
	f := config.FileServer{UNC: os.Getenv("CI_FS_UNC"), User: os.Getenv("CI_FS_USER"), PasswordRef: "env:CI_FS_PASS"}
	if f.UNC == "" || f.User == "" || os.Getenv("CI_FS_PASS") == "" {
		return f, fmt.Errorf("no file server: fileserver in the config or the secrets CI_FS_UNC / CI_FS_USER / CI_FS_PASS")
	}
	return f, nil
}

// ---------------------------------------------------------------- report --

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	cfgPath := fs.String("config", "docscan-project/ci/config.yaml", "configuration file")
	art := fs.String("art", "", "run folder shared by the jobs of this run")
	mac := fs.String("mac", "", `result of the local Mac check from ▷: "OK|<details>" (empty - not reported)`)
	md := fs.String("md", "", "write the Verified-on table (Markdown) here, for the release notes")
	sha := fs.String("sha", "", "commit (for the Forgejo commit statuses)")
	combat := fs.String("combat", "", "stage 3 (a release run): stands whose combat test must be OK, comma-separated (win10,ubuntu); a missing or skipped one is an ERROR - no push, no release")
	fs.Parse(args)
	cfg, _ := loadPipelineConfig(*cfgPath)
	var all []*StandStatus
	if *mac != "" {
		state, detail, _ := strings.Cut(*mac, "|")
		all = append(all, &StandStatus{Name: "macos", Title: "macOS", Where: "local", Status: state, Detail: detail})
	}
	for i := range cfg.Stands {
		s := &cfg.Stands[i]
		st := readStatus(*art, s.Name)
		if st == nil {
			st = standStatus(s)
			st.Status, st.Detail = "ERROR", "no result (the job did not finish)"
		}
		all = append(all, st)
	}
	for _, n := range splitList(*combat) { // реліз — лише після зеленого бойового тесту (правило проєкту)
		st := readStatus(*art, n+"-combat")
		switch {
		case st == nil:
			st = &StandStatus{Name: n + "-combat", Title: n + " combat", Status: "ERROR", Detail: "no result (the combat job did not run or finish)"}
		case st.Status == "SKIPPED":
			st.Status = "ERROR" // без бойового тесту релізу немає
		}
		all = append(all, st)
	}
	var ok, bad []string
	for _, st := range all {
		label := st.Title
		if st.Name != "macos" {
			label += " (" + st.Name + ")"
		} else {
			label += " (local)"
		}
		fmt.Printf("[CI/CD] %-34s -> %-8s (%s)\n", label, st.Status, st.Detail)
		switch st.Status {
		case "OK":
			ok = append(ok, st.Title)
		case "SKIPPED":
		default:
			bad = append(bad, st.Title)
		}
	}
	fmt.Println(strings.Repeat("-", 80))
	green := len(bad) == 0 && len(ok) > 0
	if green {
		fmt.Printf("[RESULT] Verified on: %s.\n", strings.Join(ok, ", "))
	} else if len(bad) > 0 {
		fmt.Printf("[RESULT] ERROR on: %s - no push to GitHub.\n", strings.Join(bad, ", "))
	} else {
		fmt.Println("[RESULT] no stand passed (all skipped) - no push to GitHub.")
	}
	if *md != "" {
		var b strings.Builder
		b.WriteString("| Platform | Result | Details |\n|---|---|---|\n")
		for _, st := range all {
			fmt.Fprintf(&b, "| %s | %s | %s |\n", st.Title, st.Status, strings.ReplaceAll(st.Detail, "|", "/"))
		}
		if len(ok) > 0 {
			fmt.Fprintf(&b, "\nVerified on: %s.\n", strings.Join(ok, ", "))
		}
		os.WriteFile(*md, []byte(b.String()), 0o644)
	}
	switch {
	case green:
		postStatus(*sha, "result", "Result", "OK", "Verified on: "+strings.Join(ok, ", "))
	case len(bad) > 0:
		postStatus(*sha, "result", "Result", "ERROR", "ERROR on: "+strings.Join(bad, ", "))
	default:
		postStatus(*sha, "result", "Result", "ERROR", "no stand passed (all skipped)")
	}
	if !green {
		return 1
	}
	return 0
}

// ---------------------------------------------------------------- publish --

// cmdPublish — після зеленого звіту: перевірка безпеки того, що додадуть коміти до публічної гілки GitHub
// (внутрішні адреси, паролі / токени, test-samples/provided, файли > 5 МБ) -> git push <sha>:<гілка> (лише
// fast-forward) -> з --release реліз vX.Y.Z з пакетом Windows, tar.gz Linux / macOS і таблицею «Verified on».
// Токен GitHub — у змінних середовища процесів git / gh, не в командному рядку.
func cmdPublish(args []string) int {
	fs := flag.NewFlagSet("publish", flag.ExitOnError)
	rulesVer := fs.String("rules", "", "rules release the run was tested with (for the release notes)")
	cfgPath := fs.String("config", "docscan-project/ci/config.yaml", "configuration file")
	art := fs.String("art", "", "run folder shared by the jobs of this run")
	sha := fs.String("sha", "", "the tested commit")
	branch := fs.String("branch", "", "GitHub branch (default: pipeline.branch)")
	release := fs.Bool("release", false, "also make the GitHub release vX.Y.Z")
	bump := fs.String("bump", "patch", "release number part: patch | minor | major")
	notes := fs.String("notes", "", "Markdown file appended to the release notes (the Verified-on table of cirun report)")
	macAsset := fs.String("mac-asset", "", "macOS tar.gz; empty - taken from the package store (docscan-builds/<commit>), where ▷ put it")
	fs.Parse(args)
	cfg, sec := loadPipelineConfig(*cfgPath)
	full, err := gitops.Git("rev-parse", "--verify", *sha+"^{commit}")
	if err != nil || *art == "" {
		die("publish: --sha (in this checkout) and --art are required")
	}
	repo, br := cfg.Pipeline.GitHubRepo, *branch
	if br == "" {
		br = cfg.Pipeline.Branch
	}
	if repo == "" || br == "" {
		die("publish: pipeline.github_repo and pipeline.branch (or --branch) are required")
	}
	tok, err := sec.Get(cfg.Pipeline.GitHubTokenRef)
	if err != nil || tok == "" {
		die("publish: GitHub token (pipeline.github_token_ref): %v", err)
	}
	fail := func(f string, a ...any) int {
		msg := fmt.Sprintf(f, a...)
		fmt.Println("[GIT]    NOT pushed: " + msg)
		postStatus(full, "publish", "GitHub", "ERROR", msg)
		return 1
	}
	ghURL := "https://github.com/" + repo + ".git"
	// git з токеном лише через змінні середовища (http.extraHeader), без токена в URL / аргументах
	env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=http.https://github.com/.extraheader",
		"GIT_CONFIG_VALUE_0=AUTHORIZATION: basic "+base64.StdEncoding.EncodeToString([]byte("x-access-token:"+tok)))
	git := func(a ...string) (string, error) {
		c := exec.Command("git", a...)
		c.Env = env
		out, err := c.CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}

	// 1. що вже на GitHub: базовий коміт (і його історія тут — для diff)
	base := ""
	if out, err := git("ls-remote", ghURL, "refs/heads/"+br); err == nil && out != "" {
		base = strings.Fields(out)[0]
		if _, err := gitops.Git("cat-file", "-e", base+"^{commit}"); err != nil {
			if out, err := git("fetch", "--quiet", ghURL, br); err != nil {
				return fail("fetch %s from GitHub: %s", br, out)
			}
		}
		if base == full {
			fmt.Printf("[GIT]    %s is already on GitHub (%s)\n", full[:8], br)
		} else if _, err := gitops.Git("merge-base", "--is-ancestor", base, full); err != nil {
			return fail("GitHub %s (%s) is not an ancestor of %s - no force push", br, base[:8], full[:8])
		}
	}
	// 2. перевірка безпеки
	if problems := gitops.SafetyCheckRange(base, full); len(problems) > 0 {
		fmt.Println("[GATE]   the public repository must not get:")
		for _, p := range problems {
			fmt.Println("    " + p)
		}
		return fail("security gate: %d finding(s)", len(problems))
	}
	fmt.Println("[GATE]   OK: no internal addresses, credentials, customer samples, large files")
	// 3. push
	if base != full {
		if out, err := git("push", ghURL, full+":refs/heads/"+br); err != nil {
			return fail("git push: %s", out)
		}
		fmt.Printf("[GIT]    Pushed to GitHub (%s -> %s) %s\n", repo, br, full[:8])
	}
	done := "pushed " + full[:8] + " to " + br
	// 4. реліз
	if *release {
		os.Setenv("GH_TOKEN", tok)
		tag, existing, err := deploy.ReleaseTag(repo, full, *bump)
		if err != nil {
			return fail("release: %v", err)
		}
		if existing {
			fmt.Printf("[REL]    commit %s is already released as %s\n", full[:8], tag)
		}
		r, err := deploy.Prepare(*art, repo, tag)
		if err != nil {
			return fail("release: %v", err)
		}
		// підписаний маніфест: без нього updater на ПК реліз не прийме, тож без ключа — без релізу
		seed, err := sec.Get(cfg.Release.SigningKeyRef)
		if err != nil {
			return fail("release signing key: %v", err)
		}
		if err := r.Sign(full, seed); err != nil {
			return fail("release manifest: %v", err)
		}
		// tar.gz Linux / macOS під сталими іменами (releases/latest/download/<ім'я>)
		extra := map[string]string{}
		if l, _ := filepath.Glob(filepath.Join(*art, "*", "yara-linux-*.tar.gz")); len(l) > 0 {
			extra["yara-docscan-linux-x64.tar.gz"] = l[0]
		}
		if *macAsset == "" {
			*macAsset = fetchMacAsset(cfg, sec, full, *art)
		}
		if *macAsset != "" {
			extra["yara-docscan-macos-arm64.tar.gz"] = *macAsset
		}
		for n, src := range extra {
			if err := copyFile(src, filepath.Join(r.Dir, n)); err != nil {
				return fail("release asset %s: %v", n, err)
			}
			r.Assets = append(r.Assets, filepath.Join(r.Dir, n))
		}
		if *notes != "" {
			b, _ := os.ReadFile(*notes)
			r.Extra = string(b)
		}
		if *rulesVer != "" {
			r.Rules = *rulesVer
		}
		if err := r.Publish(full, func(f string, a ...any) { fmt.Printf("[REL]   "+f+"\n", a...) }); err != nil {
			return fail("release: %v", err)
		}
		done += ", released " + tag
	}
	postStatus(full, "publish", "GitHub", "OK", done)
	return 0
}

func copyFile(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, b, 0o644)
}

// BuildsPackage — generic-пакет сховку Forgejo, куди ▷ кладе macOS tar.gz коміту (версія = 12 символів хешу).
const BuildsPackage = "docscan-builds"

// MacAsset — ім'я macOS tar.gz у сховку.
const MacAsset = "yara-darwin-arm64.tar.gz"

// buildsURL — адреса файлу name збірки коміту sha у сховку (tests.store).
func buildsURL(cfg *config.Config, sha, name string) string {
	return fmt.Sprintf("%s/api/packages/%s/generic/%s/%s/%s", strings.TrimRight(cfg.Tests.Store.URL, "/"),
		cfg.Tests.Store.Owner, BuildsPackage, sha[:12], name)
}

// fetchMacAsset — macOS tar.gz коміту зі сховку в <art>/macos.tar.gz; "" — немає (реліз без macOS).
func fetchMacAsset(cfg *config.Config, sec *config.Resolver, sha, art string) string {
	if cfg.Tests.Store.URL == "" {
		return ""
	}
	tok, _ := sec.Get(cfg.Tests.Store.TokenRef)
	req, _ := http.NewRequest("GET", buildsURL(cfg, sha, MacAsset), nil)
	req.Header.Set("Authorization", "token "+tok)
	r, err := (&http.Client{Timeout: 5 * time.Minute}).Do(req)
	if err != nil || r.StatusCode != 200 {
		fmt.Println("[REL]    no macOS tar.gz from ▷ in the store - the release has no macOS asset")
		if r != nil {
			r.Body.Close()
		}
		return ""
	}
	defer r.Body.Close()
	dst := filepath.Join(art, "macos.tar.gz")
	f, err := os.Create(dst)
	if err == nil {
		_, err = io.Copy(f, r.Body)
		f.Close()
	}
	if err != nil {
		return ""
	}
	return dst
}
