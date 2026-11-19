package main

// cirun rules-release --dir <checkout yara-docscan-rules> [--repo owner/repo] [--bump patch|minor|major] [--dry-run]
//
// Підписаний реліз правил для DocScanUpdater і ручного встановлення (deploy/rules.go). Коміт має бути чистим і
// вже на GitHub (тег ставиться на нього). Ключ підпису — release.signing_key_ref конфігу (KeePassXC).

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"docscan/cirun/config"
	"docscan/cirun/deploy"
)

func cmdRulesRelease(args []string) int {
	fs := flag.NewFlagSet("rules-release", flag.ExitOnError)
	cfgPath := fs.String("config", "docscan-project/ci/config.yaml", "configuration file (release.signing_key_ref)")
	dir := fs.String("dir", "", "checkout of the rules repository")
	repo := fs.String("repo", "rifatismailov/yara-docscan-rules", "GitHub repository of the rules")
	bump := fs.String("bump", "patch", "release number part to increase: patch | minor | major")
	yarac := fs.String("yarac", "./yarac", "DocScan's yarac (with the docscan module) for the compile check")
	dry := fs.Bool("dry-run", false, "build and sign the assets, do not publish")
	fs.Parse(args)
	if *dir == "" {
		die("rules-release: --dir is required")
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		die("%v", err)
	}
	sec := config.NewResolver(cfg.Secrets)
	git := func(a ...string) (string, error) {
		out, err := exec.Command("git", append([]string{"-C", *dir}, a...)...).CombinedOutput()
		return strings.TrimSpace(string(out)), err
	}
	if st, err := git("status", "--porcelain"); err != nil || st != "" {
		die("rules-release: %s is not a clean git checkout:\n%s", *dir, st)
	}
	sha, err := git("rev-parse", "HEAD")
	if err != nil {
		die("rules-release: %v", err)
	}
	if out, err := exec.Command("gh", "api", "repos/"+*repo+"/commits/"+sha, "-q", ".sha").CombinedOutput(); err != nil || !strings.HasPrefix(string(out), sha) {
		die("rules-release: commit %s is not on github.com/%s yet - push it first", sha[:8], *repo)
	}
	tag, existing, err := deploy.ReleaseTag(*repo, sha, *bump)
	if err != nil {
		die("rules-release: %v", err)
	}
	if existing {
		fmt.Printf("[RULES] commit %s is already released as %s\n", sha[:8], tag)
		return 0
	}
	seed, err := sec.Get(cfg.Release.SigningKeyRef)
	if err != nil {
		die("rules-release: signing key: %v", err)
	}
	out, _ := filepath.Abs(filepath.Join(cfg.OutDir, "rules-release-"+tag))
	os.RemoveAll(out)
	r, err := deploy.PrepareRules(*dir, *repo, tag, sha, *yarac, seed, out)
	if err != nil {
		die("rules-release: %v", err)
	}
	fmt.Printf("[RULES] %s of %s (commit %s): compiled, signed\n", tag, *repo, sha[:8])
	for _, a := range r.Assets {
		st, _ := os.Stat(a)
		fmt.Printf("        %-26s %10d\n", filepath.Base(a), st.Size())
	}
	if *dry {
		fmt.Printf("[RULES] dry run - not published (%s)\n", out)
		return 0
	}
	if err := r.Publish(func(f string, a ...any) { fmt.Printf("[RULES]"+f+"\n", a...) }); err != nil {
		die("rules-release: %v", err)
	}
	fmt.Printf("[RULES] released %s\n", tag)
	return 0
}
