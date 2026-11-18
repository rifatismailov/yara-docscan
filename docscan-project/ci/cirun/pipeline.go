package main

// Конвеєр Forgejo Actions (.forgejo/workflows/pipeline.yml) — підкоманди для завдань workflow:
//
//	cirun probe  --art DIR [--output FILE]          які стенди доступні: <ім'я>=online|offline у FILE ($GITHUB_OUTPUT);
//	                                                недоступний стенд одразу отримує статус SKIPPED (host offline)
//	cirun stand  --name N --sha SHA --art DIR       один стенд: збірка / тести за його role і suite, статус і артефакти
//	             [--fuzz S] [--assets VER] [--malware]   у DIR/<N>/ (status.json, логи кроків, пакет / tar.gz)
//	cirun report --art DIR [--mac "OK|деталі"] [--md FILE]   зведення у форматі [CI/CD] ..., таблиця «Verified on»
//	                                                для релізу; код 1 — є ERROR (або жоден стенд не пройшов)
//
// DIR — спільна тека прогону на хості раннера (усі завдання одного прогону бачать її): так збірка стенда role
// build дістається стендам role test без сторонніх сховищ.

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"docscan/cirun/assets"
	"docscan/cirun/config"
	"docscan/cirun/gitops"
	"docscan/cirun/platform"
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
	case "probe":
		return cmdProbe(args[1:])
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
	if prev := readStatus(*art, s.Name); prev != nil && prev.Status == "SKIPPED" {
		fmt.Printf("[%s] %s: %s - skipped\n", s.Name, s.Title, prev.Detail)
		return 0
	}
	st := standStatus(s)
	t0 := time.Now()
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
		fmt.Printf("[%s] %s -> %s (%s)\n", s.Name, s.Title, st.Status, st.Detail)
		if st.Status == "ERROR" {
			return 1
		}
		return 0
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
		p = w
	case "linux":
		pc.Script = "docscan-project/ci/build-test-unix.sh"
		abs, _ := filepath.Abs(dst)
		p = platform.NewLinux(pc, sec, *fuzz, abs, as, rep)
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
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
	st.Status = "OK"
	return finish()
}

// ---------------------------------------------------------------- report --

func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	cfgPath := fs.String("config", "docscan-project/ci/config.yaml", "configuration file")
	art := fs.String("art", "", "run folder shared by the jobs of this run")
	mac := fs.String("mac", "", `result of the local Mac check from ▷: "OK|<details>" (empty - not reported)`)
	md := fs.String("md", "", "write the Verified-on table (Markdown) here, for the release notes")
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
	if !green {
		return 1
	}
	return 0
}
