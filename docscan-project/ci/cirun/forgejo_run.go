package main

// ▷ у режимі конвеєра Forgejo (pipeline.mode: forgejo):
//
//	1. macOS — локальна збірка й тести на цьому Маку (як і раніше); не зелено — далі не йдемо;
//	2. macOS tar.gz -> сховок Forgejo (docscan-builds/<коміт>) — для релізу;
//	3. git push коміту в Forgejo (гілка прогону; токен — через змінні середовища git);
//	4. запуск workflow pipeline.yml (sha, release, bump, версія тестових файлів, результат macOS, фазинг);
//	5. стеження: зміни стану завдань і статуси коміту cirun/<стенд> одразу в термінал; у кінці — зведення
//	   [CI/CD] ... / [RESULT] ... / [GIT] ... і код виходу (0 — зелено й запушено, 1 — ні).

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"docscan/cirun/config"
	"docscan/cirun/forgejo"
	"docscan/cirun/orchestrator"
	"docscan/cirun/platform"
)

func runForgejo(ctx context.Context, cfg *config.Config, sec *config.Resolver, o *orchestrator.Orchestrator,
	src platform.Source, sha, branch string, release bool, bump string, fuzz int, started time.Time) int {
	finish := func(ok bool, text string) int {
		abs, _ := filepath.Abs(o.RunDir)
		say("\nRESULT: %s   (%d min)   artifacts: %s   %s", map[bool]string{true: "SUCCESS", false: "FAILURE"}[ok],
			int(time.Since(started).Minutes()), abs, text)
		if ok {
			return 0
		}
		return 1
	}

	// 1. macOS локально
	o.Opt.Only, o.Opt.Push = []string{"macos"}, false
	say("[CI/CD] macOS (local): build %s (%s), fuzzing %ds", sha[:8], branch, fuzz)
	t0 := time.Now()
	green := o.Build(ctx, src)
	o.Summary()
	macDetail := fmt.Sprintf("build + tests, %s", time.Since(t0).Round(time.Second))
	if !green {
		say("[CI/CD] macOS (local)                    -> ERROR    (%s)", macDetail)
		return finish(false, "macOS failed - nothing is pushed")
	}
	say("[CI/CD] macOS (local)                    -> OK       (%s)", macDetail)

	tok, err := sec.Get(cfg.Forgejo.TokenRef)
	if err != nil {
		return finish(false, "Forgejo token: "+err.Error())
	}
	fj := forgejo.NewClient(cfg.Forgejo.URL, cfg.Forgejo.Repo, tok)

	// 2. macOS tar.gz -> сховок (лише для релізу; помилка — реліз без macOS)
	if release {
		if err := uploadMacAsset(cfg, sec, sha, o.RunDir); err != nil {
			say("! macOS tar.gz to the store: %v - the release will have no macOS asset", err)
		}
	}

	// 3. push у Forgejo
	url := strings.TrimRight(cfg.Forgejo.URL, "/") + "/" + cfg.Forgejo.Repo + ".git"
	push := exec.Command("git", "push", "--quiet", url, sha+":refs/heads/"+branch)
	push.Env = append(os.Environ(), "GIT_TERMINAL_PROMPT=0", "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader",
		"GIT_CONFIG_VALUE_0=Authorization: basic "+base64.StdEncoding.EncodeToString([]byte("ci:"+tok)))
	if out, err := push.CombinedOutput(); err != nil {
		return finish(false, "git push to Forgejo: "+strings.TrimSpace(string(out)))
	}
	say("[GIT]    pushed %s to Forgejo (%s)", sha[:8], branch)

	// 4. workflow
	inputs := map[string]string{"sha": sha, "release": fmt.Sprint(release), "bump": bump,
		"mac": "OK|" + macDetail, "fuzz": fmt.Sprint(fuzz)}
	if o.Assets != nil && o.Assets.CorpusURL != "" {
		inputs["assets"] = o.Assets.Version
	}
	run, err := fj.Dispatch(ctx, cfg.Pipeline.Workflow, branch, inputs)
	if err != nil {
		return finish(false, "start the Forgejo workflow: "+err.Error())
	}
	say("[CI/CD] Forgejo run: %s   jobs: %s", fj.RunURL(run), strings.Join(run.Jobs, ", "))

	// 5. стеження
	lastJob := map[string]string{}
	lastSt := map[string]string{}
	status := ""
	for status == "" {
		select {
		case <-ctx.Done():
			return finish(false, "interrupted (the Forgejo run goes on: "+fj.RunURL(run)+")")
		case <-time.After(15 * time.Second):
		}
		st, jobs, err := fj.RunState(ctx, run.ID)
		if err != nil {
			say("    (Forgejo: %v)", err)
			continue
		}
		for _, j := range jobs {
			if lastJob[j.Name] != j.Status {
				lastJob[j.Name] = j.Status
				say("    job %-8s %-10s %s", j.Name, j.Status, time.Since(started).Round(time.Second))
			}
		}
		if cs, err := fj.Statuses(ctx, sha); err == nil {
			for _, c := range cs {
				if strings.HasPrefix(c.Context, "cirun/") && lastSt[c.Context] != c.Description {
					lastSt[c.Context] = c.Description
					say("%s", statusLine(c))
				}
			}
		}
		switch st {
		case "success", "failure", "cancelled", "skipped":
			status = st
		}
	}

	// зведення
	cs, _ := fj.Statuses(ctx, sha)
	say("\n%s", strings.Repeat("-", 80))
	say("[CI/CD] macOS (local)                    -> OK       (%s)", macDetail)
	var result, pub *forgejo.CommitStatus
	for i := range cs {
		c := &cs[i]
		switch c.Context {
		case "cirun/result":
			result = c
		case "cirun/publish":
			pub = c
		default:
			if strings.HasPrefix(c.Context, "cirun/") {
				say("%s", statusLine(*c))
			}
		}
	}
	say("%s", strings.Repeat("-", 80))
	if result != nil {
		_, st, detail := splitStatus(result.Description)
		say("[RESULT] %s (%s)", detail, st)
	}
	ok := status == "success"
	tail := "run " + status + ": " + fj.RunURL(run)
	if pub != nil {
		_, st, detail := splitStatus(pub.Description)
		say("[GIT]    %s: %s", st, detail)
		if st == "OK" {
			tail = "PUSHED  " + strings.ToUpper(strings.ReplaceAll(detail, "pushed ", ""))
		}
	} else {
		say("[GIT]    not pushed to GitHub")
	}
	return finish(ok, tail)
}

// statusLine — статус стенда у форматі [CI/CD] <назва> (<ім'я>) -> STATUS (деталі).
func statusLine(c forgejo.CommitStatus) string {
	title, st, detail := splitStatus(c.Description)
	name := strings.TrimPrefix(c.Context, "cirun/")
	if name == "result" || name == "publish" {
		return fmt.Sprintf("[%s] %s: %s", strings.ToUpper(name), st, detail)
	}
	return fmt.Sprintf("[CI/CD] %-34s -> %-8s (%s)", title+" ("+name+")", st, detail)
}

func splitStatus(d string) (title, state, detail string) {
	p := strings.SplitN(d, "|", 3)
	for len(p) < 3 {
		p = append(p, "")
	}
	return p[0], p[1], p[2]
}

// uploadMacAsset кладе ci-out/<прогін>/macos/yara-darwin-arm64.tar.gz у сховок (docscan-builds/<коміт>).
func uploadMacAsset(cfg *config.Config, sec *config.Resolver, sha, runDir string) error {
	if cfg.Tests.Store.URL == "" {
		return fmt.Errorf("no tests.store")
	}
	data, err := os.ReadFile(filepath.Join(runDir, "macos", MacAsset))
	if err != nil {
		return err
	}
	tok, err := sec.Get(cfg.Tests.Store.TokenRef)
	if err != nil {
		return err
	}
	u := buildsURL(cfg, sha, MacAsset)
	del, _ := http.NewRequest("DELETE", u, nil) // повторний прогін того самого коміту — замінити
	del.Header.Set("Authorization", "token "+tok)
	if r, err := http.DefaultClient.Do(del); err == nil {
		r.Body.Close()
	}
	req, _ := http.NewRequest("PUT", u, strings.NewReader(string(data)))
	req.Header.Set("Authorization", "token "+tok)
	r, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return err
	}
	r.Body.Close()
	if r.StatusCode >= 300 {
		return fmt.Errorf("PUT %s: %s", u, r.Status)
	}
	return nil
}
