// ci-run: the "Run" button (VS Code ▷ / task "DocScan CI"): commit -> push -> build + tests on every
// system -> deployment set -> publish to the deployment server.
//
//	go run -C docscan-project/ci/cirun . [--fuzz SECONDS] [-m "message"] [--no-commit] [--no-push]
//	                                     [--local] [--no-publish] [--publish-dir DIR]
//	go run -C docscan-project/ci/cirun . windows      (the Windows job alone, see windows.go)
//
// Two modes, chosen automatically:
//   - Forgejo reachable  -> the "build-test" workflow runs there (runners: this Mac, Windows over WinRM,
//     Ubuntu when it exists); ci-run follows it and downloads the artifacts.
//   - Forgejo NOT reachable (or --local) -> the same steps run from this Mac directly: build-test-unix.sh
//     here and the Windows job over WinRM to the first reachable Windows build machine (the Proxmox VM,
//     else the fallback PC "216").
//
// After a green run the deployment set is put together in ci-out/<run>/deploy/: the Windows package
// DocScan-<date>-<commit>.zip + .sha256, DocScan-latest.txt, DocScan-Install.ps1 and the bootstraps
// DocScan-Setup.ps1 / -Pilot / -Critical with the server address filled in (+ critical-rules.yar).
// Then it is uploaded to the deployment server (default; --no-publish to skip) and DocScan-latest.txt is
// switched to the new package: "irm http://<server>:8080/docscan/DocScan-Setup.ps1 | iex" installs it.
//
// Auto-commit: every change git does not ignore (git add -A) goes into one commit, unless the safety
// check finds something that must not reach the public repository (internal addresses, host/user
// names, passwords, tokens, files > 5 MB) - then nothing is committed and ci-run stops.
//
// Settings: ~/.docscan/hosts.json - profile "forgejo" (url, token, ci_checkout_token), "vm" and "216"
// (host, user, password: the Windows build machines, local mode), "fs" (host, user, password,
// deploy_dir, deploy_url, critical_rules: the deployment server). Repository on Forgejo: FORGEJO_REPO
// (default rifat/yara-docscan).
package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

type options struct {
	fuzz, message, remote, publishDir  string
	noPush, noCommit, local, noPublish bool
}

var (
	opt     options
	hosts   map[string]profile
	started = time.Now()
)

func main() {
	// "go run -C docscan-project/ci/cirun ." starts in the module folder: work from the repository root
	root := strings.TrimSpace(mustGit("rev-parse", "--show-toplevel"))
	if err := os.Chdir(root); err != nil {
		die(err.Error())
	}
	if len(os.Args) > 1 && os.Args[1] == "windows" {
		os.Exit(runWindows())
	}
	flag.StringVar(&opt.fuzz, "fuzz", "300", "fuzzing seconds per OS (0 = none)")
	flag.BoolVar(&opt.noPush, "no-push", false, "do not git push")
	flag.BoolVar(&opt.noCommit, "no-commit", false, "do not commit local changes (CI builds the last commit)")
	flag.StringVar(&opt.message, "m", "", "commit message for the auto-commit")
	flag.StringVar(&opt.message, "message", "", "same as -m")
	flag.StringVar(&opt.remote, "remote", "docscan", "git remote of GitHub")
	flag.BoolVar(&opt.local, "local", false, "do not use Forgejo: build and test from this Mac")
	flag.BoolVar(&opt.noPublish, "no-publish", false, "do not upload the deployment set to the server")
	flag.Bool("publish", false, "the default now; kept for old tasks")
	flag.StringVar(&opt.publishDir, "publish-dir", "", "only publish an existing deployment set (ci-out/<run>/deploy), no build")
	flag.Parse()

	hosts = loadHosts()
	fj := hosts["forgejo"]
	forgejoURL := strings.TrimRight(envOr("FORGEJO_URL", fj.s("url")), "/")
	forgejoToken := envOr("FORGEJO_TOKEN", fj.s("token"))
	repo := envOr("FORGEJO_REPO", "rifat/yara-docscan")

	if opt.publishDir != "" {
		publishOnly(opt.publishDir)
		return
	}

	// ---- commit and push
	branch := mustGit("rev-parse", "--abbrev-ref", "HEAD")
	changes := mustGit("status", "--porcelain")
	if changes != "" && !opt.noCommit {
		commit(changes)
	} else if changes != "" {
		say("! uncommitted changes (--no-commit) - the last COMMIT %s is built", mustGit("rev-parse", "--short", "HEAD"))
	}
	sha := mustGit("rev-parse", "HEAD")
	if !opt.noPush {
		say("git push %s %s", opt.remote, branch)
		if runCmd(nil, "git", "push", opt.remote, branch) != 0 {
			say("! git push failed - continuing with the local commit")
		}
	}

	// ---- build and tests
	var out string
	var green bool
	useForgejo := !opt.local && forgejoURL != "" && forgejoToken != "" && reachable(forgejoURL)
	if useForgejo {
		f := &forgejo{url: forgejoURL, token: forgejoToken, repo: repo}
		out, green = f.run(branch, sha)
	} else {
		if !opt.local {
			say("Forgejo (%s) is not reachable - local mode", orStr(forgejoURL, "not configured"))
		}
		gitURL := "http://localhost/"
		if forgejoURL != "" {
			gitURL = forgejoURL + "/" + repo + ".git"
		}
		out, green = runLocal(sha, gitURL, fj.s("ci_checkout_token"))
	}

	entries, _ := os.ReadDir(out)
	for _, e := range entries {
		if b, err := os.ReadFile(filepath.Join(out, e.Name(), "summary.txt")); err == nil {
			say("\n----- %s\n%s", e.Name(), strings.TrimRight(string(b), "\n"))
		}
	}

	// ---- deployment set and publishing
	var dep *deployment
	if green {
		dep = deploySet(out)
	}
	published := "" // "" = not asked, "yes", "no"
	if !opt.noPublish {
		published = "no"
		if !green {
			say("\n! publishing skipped: the run is not green")
		} else if dep != nil && publish(dep) {
			published = "yes"
		}
	}
	tail := map[string]string{"": "", "yes": "   PUBLISHED", "no": "   NOT published"}[published]
	abs, _ := filepath.Abs(out)
	say("\nRESULT: %s   (%d min)   artifacts: %s%s", map[bool]string{true: "SUCCESS", false: "FAILURE"}[green],
		int(time.Since(started).Minutes()), abs, tail)
	if !green || published == "no" {
		os.Exit(1)
	}
}

// ------------------------------------------------------------------ commit --

// The internal names are split so that this public file does not contain them.
var forbidden = []struct {
	rx   *regexp.Regexp
	what string
}{
	{regexp.MustCompile(`\b(192\.168\.(1|17|88|129)|10\.10\.67|172\.118\.18)\.\d{1,3}\b`), "internal IP address"},
	{regexp.MustCompile(`(?i)(` + "fort" + "una" + `|` + "odessa" + `\.ua)`), "internal host / user name"},
	{regexp.MustCompile(`(?i)(password|passwd|pwd|secret|token)['"]?\s*[:=]\s*['"][^'"\s]{6,}['"]`), "password / token value"},
	{regexp.MustCompile(`\b[0-9a-f]{40}\b`), "40-hex token (Forgejo/GitHub)"},
}
var surname = regexp.MustCompile(`(?i)` + "isma" + "ilov")

const maxFile = 5 * 1024 * 1024

// internalSurname: the surname is allowed only as part of the public GitHub account name.
func internalSurname(line string) bool {
	for _, m := range surname.FindAllStringIndex(line, -1) {
		if m[0] < 5 || !strings.EqualFold(line[m[0]-5:m[0]], "rifat") {
			return true
		}
	}
	return false
}

func safetyCheck() []string {
	var problems []string
	for _, f := range strings.Split(mustGit("diff", "--cached", "--name-only", "-z"), "\x00") {
		if st, err := os.Stat(f); f != "" && err == nil && st.Mode().IsRegular() && st.Size() > maxFile {
			problems = append(problems, f+": file larger than 5 MB")
		}
	}
	cur := "?"
	for _, line := range strings.Split(mustGit("diff", "--cached", "-U0", "--no-color"), "\n") {
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

func commit(changes string) {
	say("commit local changes:")
	for i, l := range strings.Split(changes, "\n") {
		if i == 30 {
			break
		}
		say("    %s", l)
	}
	mustRun("git", "add", "-A")
	if problems := safetyCheck(); len(problems) > 0 {
		mustRun("git", "reset", "-q")
		say("\n! NOT committed - the public repository must not get:")
		for i, p := range problems {
			if i == 20 {
				break
			}
			say("    %s", p)
		}
		die("fix these changes (or commit by hand with --no-commit) and press Run again")
	}
	files := strings.Split(mustGit("diff", "--cached", "--name-only"), "\n")
	msg := opt.message
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
	mustRun("git", "commit", "-q", "-m", msg)
	say("    committed: %s  (%s)", mustGit("rev-parse", "--short", "HEAD"), msg)
}

// ------------------------------------------------------------- local mode --

func runLocal(sha, gitURL, gitToken string) (string, bool) {
	out := filepath.Join("ci-out", "local-"+time.Now().Format("20060102-150405"))
	if err := os.MkdirAll(out, 0o755); err != nil {
		die(err.Error())
	}
	absOut, _ := filepath.Abs(out)
	seeds := filepath.Join(home(), "docscan-ci", "seeds")
	if !isDir(seeds) {
		seeds = ""
	}
	self, err := os.Executable()
	if err != nil {
		die(err.Error())
	}
	winEnv := append(os.Environ(), "SHA="+sha, "CI_OUT="+filepath.Join(absOut, "windows-work"),
		"GIT_URL="+gitURL, "GIT_TOKEN="+gitToken)
	for _, m := range [][2]string{{"WIN11", "vm"}, {"WIN216", "216"}} {
		if p := hosts[m[1]]; p.s("host") != "" {
			winEnv = append(winEnv, m[0]+"_HOST="+p.s("host"), m[0]+"_USER="+p.s("user"), m[0]+"_PASS="+p.s("password"))
		}
	}
	jobs := []struct {
		name string
		cmd  []string
		env  []string
	}{
		{"macos", []string{"sh", "docscan-project/ci/build-test-unix.sh"},
			append(os.Environ(), "CI_OUT="+filepath.Join(absOut, "macos-work"), "FUZZ_SECONDS="+opt.fuzz, "CI_SEEDS="+seeds)},
		{"windows", []string{self, "windows"}, winEnv},
	}

	say("local mode: macOS here + Windows over WinRM (fuzzing %ss)", opt.fuzz)
	var wg sync.WaitGroup
	var mu sync.Mutex
	allOK := true
	mac := &tracker{job: "macos", where: thisMac(), log: filepath.Join(out, "macos.log"), steps: macSteps(opt.fuzz), done: map[string]bool{}}
	win := &tracker{job: "windows", where: "?", log: filepath.Join(out, "windows.log"), steps: winSteps(), done: map[string]bool{}}
	say("    [macos] this Mac: %s", mac.where)
	say("    [windows] picking the build machine (VM, else the fallback PC) ...")
	prog := newProgress(&mu, mac, win)
	prog.start()
	for _, j := range jobs {
		wg.Add(1)
		go func(name string, cmd, env []string) {
			defer wg.Done()
			t := time.Now()
			work := filepath.Join(out, name+"-work")
			os.MkdirAll(work, 0o755)
			logPath := filepath.Join(out, name+".log")
			rc := 1
			if log, err := os.Create(logPath); err == nil {
				c := exec.Command(cmd[0], cmd[1:]...)
				c.Env, c.Stdout, c.Stderr = env, log, log
				rc = exitCode(c.Run())
				log.Close()
			}
			if isDir(filepath.Join(work, "artifacts")) {
				copyDir(filepath.Join(work, "artifacts"), filepath.Join(out, name))
			}
			mu.Lock()
			prog.finish(name)
			allOK = allOK && rc == 0
			say("    %-10s %-8s %4ds   %d%%   (log: %s)", name, map[bool]string{true: "success", false: "failure"}[rc == 0],
				int(time.Since(t).Seconds()), prog.percent(), logPath)
			mu.Unlock()
		}(j.name, j.cmd, j.env)
	}
	wg.Wait()
	prog.stop()
	for _, j := range jobs { // the artifacts are copied out; the work folders (fuzz build tree etc.) go
		os.RemoveAll(filepath.Join(out, j.name+"-work"))
	}
	return out, allOK
}

// --------------------------------------------------------- deployment set --

type deployment struct {
	dir, pkg, base string
	fs             profile
}

func deployBase(fs profile) string {
	if u := fs.s("deploy_url"); u != "" {
		return strings.TrimRight(u, "/")
	}
	return "http://" + orStr(fs.s("host"), "<server>") + ":8080/docscan"
}

func deploySet(out string) *deployment {
	zips, _ := filepath.Glob(filepath.Join(out, "*", "DocScan-*.zip"))
	if len(zips) == 0 {
		say("\n(no Windows package in this run - no deployment set)")
		return nil
	}
	sort.Strings(zips)
	zipPath := zips[len(zips)-1]
	fs := hosts["fs"]
	base := deployBase(fs)
	d := filepath.Join(out, "deploy")
	os.RemoveAll(d)
	if err := os.MkdirAll(d, 0o755); err != nil {
		die(err.Error())
	}
	pkg := filepath.Base(zipPath)
	mustCopy(zipPath, filepath.Join(d, pkg))
	mustCopy(zipPath+".sha256", filepath.Join(d, pkg+".sha256"))
	mustWrite(filepath.Join(d, "DocScan-latest.txt"), pkg+"\n")
	deploy := filepath.Join("docscan-project", "deploy")
	mustCopy(filepath.Join(deploy, "DocScan-Install.ps1"), filepath.Join(d, "DocScan-Install.ps1"))

	raw, err := os.ReadFile(filepath.Join(deploy, "DocScan-Setup.ps1"))
	if err != nil {
		die(err.Error())
	}
	for _, b := range raw {
		if b > 127 {
			die("DocScan-Setup.ps1 must be ASCII only (it is run by irm | iex)")
		}
	}
	tpl := strings.ReplaceAll(string(raw), "\r\n", "\n")
	tpl = strings.ReplaceAll(tpl, "'http://<server>:8080/docscan'", "'"+base+"'")
	tpl = strings.ReplaceAll(tpl, "http://<server>:8080/docscan", base)
	for _, v := range [][2]string{{"DocScan-Setup.ps1", ""}, {"DocScan-Setup-Pilot.ps1", "'-DetectOnly'"}, {"DocScan-Setup-Critical.ps1", "'-Critical'"}} {
		t := tpl
		if v[1] != "" {
			t = strings.Replace(tpl, "$InstallArg = @()", "$InstallArg = @("+v[1]+")", 1)
		}
		mustWrite(filepath.Join(d, v[0]), strings.ReplaceAll(t, "\n", "\r\n"))
	}
	crit := envOr("DOCSCAN_CRITICAL_RULES", fs.s("critical_rules"))
	if crit != "" {
		crit = expandHome(crit)
		if st, err := os.Stat(crit); err == nil && st.Mode().IsRegular() {
			mustCopy(crit, filepath.Join(d, "critical-rules.yar"))
		}
	}
	abs, _ := filepath.Abs(d)
	say("\ndeployment set: %s", abs)
	entries, _ := os.ReadDir(d)
	for _, e := range entries {
		if st, err := e.Info(); err == nil {
			say("    %-34s %8d bytes", e.Name(), st.Size())
		}
	}
	return &deployment{dir: d, pkg: pkg, base: base, fs: fs}
}

func publishOnly(dir string) {
	dir, _ = filepath.Abs(dir)
	zips, _ := filepath.Glob(filepath.Join(dir, "DocScan-*.zip"))
	if len(zips) == 0 {
		die("no DocScan-*.zip in " + dir)
	}
	sort.Strings(zips)
	fs := hosts["fs"]
	ok := publish(&deployment{dir: dir, pkg: filepath.Base(zips[len(zips)-1]), base: deployBase(fs), fs: fs})
	say("\nRESULT: %s", map[bool]string{true: "PUBLISHED", false: "NOT published"}[ok])
	if !ok {
		os.Exit(1)
	}
}

// publish uploads the set with scp (password from hosts.json via sshpass), checks the package sha256 on
// the server and only then switches DocScan-latest.txt; finally checks it over HTTP.
func publish(d *deployment) bool {
	host, user, pass := d.fs.s("host"), d.fs.s("user"), d.fs.s("password")
	if host == "" || user == "" || pass == "" {
		say("! publishing: no server in ~/.docscan/hosts.json profile 'fs' (host, user, password)")
		return false
	}
	rdir := orStr(d.fs.s("deploy_dir"), "scripts/docscan")
	target := user + "@" + host
	env := append(os.Environ(), "SSHPASS="+pass)
	var files []string
	entries, _ := os.ReadDir(d.dir)
	for _, e := range entries {
		if e.Name() != "DocScan-latest.txt" {
			files = append(files, filepath.Join(d.dir, e.Name()))
		}
	}
	say("\npublish to %s:%s", target, rdir)
	ssh := []string{"sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10", target}
	scp := func(src ...string) bool {
		args := append([]string{"-e", "scp", "-q"}, src...)
		return runCmd(env, "sshpass", append(args, target+":"+rdir+"/")...) == 0
	}
	if runCmd(env, ssh[0], append(ssh[1:], "mkdir -p '"+rdir+"'")...) != 0 || !scp(files...) {
		say("! publish failed (ssh/scp; is sshpass installed?)")
		return false
	}
	c := exec.Command(ssh[0], append(ssh[1:], "cd '"+rdir+"' && sha256sum -c '"+d.pkg+".sha256'")...)
	c.Env = env
	chk, err := c.CombinedOutput()
	say("    %s", strings.TrimSpace(string(chk)))
	if err != nil {
		say("! the package on the server does not match its sha256 - DocScan-latest.txt NOT switched")
		return false
	}
	if !scp(filepath.Join(d.dir, "DocScan-latest.txt")) {
		say("! publish failed: DocScan-latest.txt")
		return false
	}
	latest, err1 := httpGet(d.base + "/DocScan-latest.txt")
	setup, err2 := httpGet(d.base + "/DocScan-Setup.ps1")
	if err1 != nil || err2 != nil {
		say("    HTTP check failed: %v %v", err1, err2)
		return false
	}
	ok := strings.TrimSpace(latest) == d.pkg && strings.Contains(setup, d.base)
	say("    %s/DocScan-latest.txt -> %s   %s", d.base, strings.TrimSpace(latest), map[bool]string{true: "OK", false: "MISMATCH"}[ok])
	say("    install on a PC:  irm %s/DocScan-Setup.ps1 | iex", d.base)
	return ok
}

// ---------------------------------------------------------------- helpers --

func say(format string, a ...any) { fmt.Printf(format+"\n", a...) }

func die(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

func orStr(s, def string) string {
	if s != "" {
		return s
	}
	return def
}

func home() string {
	h, _ := os.UserHomeDir()
	return h
}

func expandHome(p string) string {
	if strings.HasPrefix(p, "~/") {
		return filepath.Join(home(), p[2:])
	}
	return p
}

func isDir(p string) bool {
	st, err := os.Stat(p)
	return err == nil && st.IsDir()
}

// mustGit runs git and returns its output without the trailing newline; stops on an error.
func mustGit(args ...string) string {
	b, err := exec.Command("git", args...).Output()
	if err != nil {
		die("git " + strings.Join(args, " ") + ": " + err.Error())
	}
	return strings.TrimRight(string(b), "\r\n")
}

func mustRun(name string, args ...string) {
	if runCmd(nil, name, args...) != 0 {
		die(name + " " + strings.Join(args, " ") + " failed")
	}
}

// runCmd runs a command with the output on this terminal and returns its exit code.
func runCmd(env []string, name string, args ...string) int {
	c := exec.Command(name, args...)
	c.Env, c.Stdout, c.Stderr = env, os.Stdout, os.Stderr
	return exitCode(c.Run())
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if e, ok := err.(*exec.ExitError); ok {
		return e.ExitCode()
	}
	return 127
}

func reachable(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Hostname() == "" {
		return false
	}
	port := u.Port()
	if port == "" {
		port = map[bool]string{true: "443", false: "80"}[u.Scheme == "https"]
	}
	return tcpOpen(net.JoinHostPort(u.Hostname(), port))
}

func tcpOpen(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 4*time.Second)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func httpGet(u string) (string, error) {
	c := http.Client{Timeout: 15 * time.Second}
	r, err := c.Get(u)
	if err != nil {
		return "", err
	}
	defer r.Body.Close()
	if r.StatusCode != 200 {
		return "", fmt.Errorf("%s: %s", u, r.Status)
	}
	b, err := io.ReadAll(r.Body)
	return string(b), err
}

func mustWrite(path, text string) {
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		die(err.Error())
	}
}

func mustCopy(src, dst string) {
	if err := copyFile(src, dst); err != nil {
		die(err.Error())
	}
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}

func copyDir(src, dst string) error {
	return filepath.WalkDir(src, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		target := filepath.Join(dst, rel)
		if e.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		return copyFile(p, target)
	})
}
