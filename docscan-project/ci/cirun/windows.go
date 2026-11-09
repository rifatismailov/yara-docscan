package main

// "ci-run windows": DocScan CI for Windows, driven over WinRM from this Mac / a Unix runner (no runner
// on Windows). Picks the first reachable Windows build machine (the Proxmox VM first, then the fallback
// PC), puts the exact commit on it (git fetch from Forgejo, or - when the machine does not see Forgejo -
// a git-archive zip sent over WinRM), builds with MSBuild, runs the document regression
// (check_verdicts.ps1 - no Python needed) and, if Python is there, the third-pass tests, builds the
// package (build_package.ps1) and copies the zip back into the artifacts.
//
// Environment (Forgejo secrets / variables, or ci-run in local mode; never in the repository):
//
//	WIN11_HOST, WIN11_USER, WIN11_PASS      first choice (VM)
//	WIN216_HOST, WIN216_USER, WIN216_PASS   fallback (a workstation)
//	GIT_URL, GIT_TOKEN                      Forgejo clone URL + read token (used when the machine sees Forgejo)
//	SHA                                     the commit to build (must exist in the local repository)
//	CI_OUT                                  local output folder (default ci-out)
//	WIN_DIR                                 work folder on Windows (default C:\ci)
//
// Windows needs VS Build Tools 2022; Git and Python are optional.

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/masterzen/winrm"
)

type winJob struct {
	client  *winrm.Client
	ctx     context.Context
	wdir    string
	out     string
	summary []string
	failed  bool
}

func runWindows() int {
	sha := os.Getenv("SHA")
	if sha == "" {
		fmt.Println("SHA is not set")
		return 1
	}
	w := &winJob{ctx: context.Background(), wdir: envOr("WIN_DIR", `C:\ci`), out: envOr("CI_OUT", "ci-out")}
	repo := w.wdir + `\yara`
	os.MkdirAll(filepath.Join(w.out, "artifacts"), 0o755)

	// ---- the build machine: the VM if it answers, else the fallback PC
	type target struct{ label, host, user, pass string }
	var targets []target
	for _, t := range [][2]string{{"WIN11", "VM Windows 11"}, {"WIN216", "fallback PC"}} {
		if h := strings.TrimSpace(os.Getenv(t[0] + "_HOST")); h != "" {
			targets = append(targets, target{t[1], h, os.Getenv(t[0] + "_USER"), os.Getenv(t[0] + "_PASS")})
		}
	}
	var tg *target
	for i := range targets {
		if tcpOpen(targets[i].host + ":5985") {
			tg = &targets[i]
			break
		}
	}
	if tg == nil {
		var names []string
		for _, t := range targets {
			names = append(names, t.label+" ("+t.host+")")
		}
		fmt.Println("no Windows build machine is reachable: " + strings.Join(names, ", "))
		os.WriteFile(filepath.Join(w.out, "artifacts", "summary.txt"), []byte("machine        FAIL  (none reachable)\n"), 0o644)
		return 1
	}
	fmt.Printf("Windows build machine: %s %s\n", tg.label, tg.host)
	w.summary = append(w.summary, fmt.Sprintf("machine        %s %s", tg.label, tg.host))
	params := *winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	client, err := winrm.NewClientWithParameters(winrm.NewEndpoint(tg.host, 5985, false, false, nil, nil, nil, 2*time.Hour),
		tg.user, tg.pass, &params)
	if err != nil {
		fmt.Println("WinRM: " + err.Error())
		return 1
	}
	w.client = client

	// {{W}}, {{REPO}} ... in the scripts below are filled in by fill()
	common := `
$w = '{{W}}'; $repo = '{{REPO}}'
New-Item -ItemType Directory -Force $w | Out-Null
# the test samples look malicious on purpose (inert): Defender must not take them from the CI folder
if (Get-Command Add-MpPreference -EA 0) {
  try { if (@((Get-MpPreference).ExclusionPath) -notcontains $w) { Add-MpPreference -ExclusionPath $w -EA Stop } } catch { }
}
`
	gitURL := envOr("GIT_URL", "http://localhost/")
	version := time.Now().Format("20060102") + "-" + sha[:8]
	y := repo + `\windows\vs2019\Release\yara64.exe`
	fill := strings.NewReplacer("{{W}}", w.wdir, "{{REPO}}", repo, "{{URL}}", gitURL, "{{SHA}}", sha, "{{Y}}", y,
		"{{V}}", version, "{{HDR}}", "Authorization: token "+os.Getenv("GIT_TOKEN")).Replace

	// ---- 1. the exact commit: git from Forgejo when the machine sees it, otherwise a zip from here
	_, probe := w.ps(fill(common + `
try { $r = Invoke-WebRequest -UseBasicParsing '{{URL}}' -Method Head -TimeoutSec 6; 'forgejo: yes' } catch { 'forgejo: no' }
if (Get-Command git -EA 0) { 'git: yes' } else { 'git: no' }
`))
	ok := false
	if strings.Contains(probe, "forgejo: yes") && strings.Contains(probe, "git: yes") {
		ok = w.step("checkout", fill(common+`
if (Test-Path "$repo" -PathType Container) { if (-not (Test-Path "$repo\.git")) { Remove-Item $repo -Recurse -Force } }
if (-not (Test-Path "$repo\.git")) { git -c "http.extraHeader={{HDR}}" clone --no-checkout '{{URL}}' $repo 2>&1 | % { "$_" } }
Set-Location $repo
git -c "http.extraHeader={{HDR}}" fetch --force origin {{SHA}} 2>&1 | % { "$_" }
git checkout --force {{SHA}} 2>&1 | % { "$_" }
git clean -xfdq -e windows/vs2019/packages 2>&1 | % { "$_" }
"commit: " + (git rev-parse HEAD) + " (git)"
if ((git rev-parse HEAD) -ne '{{SHA}}') { exit 1 }
`), -1)
	} else {
		data, err := exec.Command("git", "archive", "--format=zip", sha).Output()
		if err == nil {
			err = w.put(data, w.wdir+`\src.zip`)
		}
		if err != nil {
			fmt.Println("source upload failed: " + err.Error())
			w.summary = append(w.summary, "checkout       FAIL  (upload: "+cut(err.Error(), 80)+")")
			w.failed = true
		} else {
			ok = w.step("checkout", fill(common+`
$keep = "$w\packages-cache"
if (Test-Path "$repo\windows\vs2019\packages") { Remove-Item $keep -Recurse -Force -EA 0; Move-Item "$repo\windows\vs2019\packages" $keep }
Remove-Item $repo -Recurse -Force -EA 0
Expand-Archive "$w\src.zip" $repo -Force
Remove-Item "$w\src.zip"
if (Test-Path $keep) { Move-Item $keep "$repo\windows\vs2019\packages" }
"commit: {{SHA}} (zip from the runner, `+fmt.Sprint(len(data))+` bytes)"
`), -1)
		}
	}

	// ---- 2. build
	if ok {
		ok = w.step("build", fill(common+`
Set-Location $repo
$pk = "windows\vs2019\packages"
if (Get-Command nuget -EA 0) { nuget restore windows\vs2019\yara.sln 2>&1 | Select-Object -Last 2 }
elseif (-not (Test-Path $pk)) {
  # no NuGet on this machine: take the restored packages from an earlier build tree, else get nuget.exe
  $cache = @("C:\docscan-build\yara\windows\vs2019\packages") | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($cache) { Copy-Item $cache $pk -Recurse; "packages: copied from $cache" }
  else {
    New-Item -ItemType Directory -Force "$w\tools" | Out-Null
    if (-not (Test-Path "$w\tools\nuget.exe")) { Invoke-WebRequest -UseBasicParsing https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -OutFile "$w\tools\nuget.exe" }
    & "$w\tools\nuget.exe" restore windows\vs2019\yara.sln 2>&1 | Select-Object -Last 2
  }
}
$mb = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\MSBuild\Current\Bin\MSBuild.exe" -EA 0 | Select -First 1 -Expand FullName
& $mb windows\vs2019\yara.sln "/t:yara;yarac" /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /m /v:m /nologo 2>&1 |
  ForEach-Object { "$_" } | Where-Object { $_ -match "error|warning C|->" }
$rc = $LASTEXITCODE
& .\windows\vs2019\Release\yara64.exe --version
exit $rc
`), -1)
	}

	// ---- 3. tests and the package
	if ok {
		w.step("documents", fill(common+`
Set-Location $repo
powershell -NoProfile -ExecutionPolicy Bypass -File docscan-project\ci\check_verdicts.ps1 -Yara '{{Y}}' -Rules docscan-project\rules\docscan-index.yar -Samples docscan-project\test-samples\generated -Expected docscan-project\ci\expected-verdicts.tsv -WorkDir "$w\tmp"
exit $LASTEXITCODE
`), -1)
		w.step("critical", fill(common+`
Set-Location $repo; $env:PYTHONIOENCODING = 'utf-8'
$py = @("python", "python3", "py") | ForEach-Object { Get-Command $_ -EA 0 } | Where-Object { $_.Source -notlike "*WindowsApps*" } | Select-Object -First 1
if (-not $py) { "no Python on this machine - the third-pass tests run on macOS / Linux"; exit 3 }
& $py.Source docscan-project\test-critical\run_tests.py --yara '{{Y}}'
exit $LASTEXITCODE
`), 3)
		if w.step("package", fill(common+`
Set-Location $repo
Remove-Item "$w\dist" -Recurse -Force -EA 0
powershell -ExecutionPolicy Bypass -File docscan-project\deploy\build_package.ps1 -Repo $repo -Out "$w\dist" -Version {{V}} 2>&1 | % { "$_" }
if (-not (Test-Path "$w\dist\DocScan-{{V}}.zip")) { exit 1 }
(Get-FileHash "$w\dist\DocScan-{{V}}.zip").Hash.ToLower() + "  DocScan-{{V}}.zip"
`), -1) {
			if err := w.fetchPackage(version); err != nil {
				fmt.Println("package download failed: " + err.Error())
				w.summary = append(w.summary, "download       FAIL  ("+cut(err.Error(), 80)+")")
				w.failed = true
			}
		}
	}

	// ---- summary and logs into the artifacts
	os.WriteFile(filepath.Join(w.out, "summary.txt"), []byte(strings.Join(w.summary, "\n")+"\n"), 0o644)
	entries, _ := os.ReadDir(w.out)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".log") || e.Name() == "summary.txt" {
			copyFile(filepath.Join(w.out, e.Name()), filepath.Join(w.out, "artifacts", e.Name()))
		}
	}
	fmt.Println("\n===== Windows summary\n" + strings.Join(w.summary, "\n"))
	if w.failed || !ok {
		return 1
	}
	return 0
}

// fetchPackage copies DocScan-<version>.zip back (base64 over WinRM) and writes its .sha256.
func (w *winJob) fetchPackage(version string) error {
	zp := w.wdir + `\dist\DocScan-` + version + `.zip`
	stdout, stderr, rc, err := w.client.RunPSWithContext(w.ctx, "[Convert]::ToBase64String([IO.File]::ReadAllBytes('"+zp+"'))")
	if err == nil && rc != 0 {
		err = fmt.Errorf("%s", cut(stderr, 200))
	}
	if err != nil {
		return err
	}
	data, err := base64.StdEncoding.DecodeString(strings.NewReplacer("\r", "", "\n", "").Replace(stdout))
	if err != nil {
		return err
	}
	name := "DocScan-" + version + ".zip"
	dst := filepath.Join(w.out, "artifacts", name)
	if err := os.WriteFile(dst, data, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	h := hex.EncodeToString(sum[:])
	fmt.Printf("package: %s (%d bytes, sha256 %s)\n", dst, len(data), h)
	return os.WriteFile(dst+".sha256", []byte(h+"  "+name+"\n"), 0o644)
}

// put sends bytes to a Windows file: base64 parts appended with "echo" over one shell (WinRM limits the
// size of one command), then PowerShell decodes them.
func (w *winJob) put(data []byte, remote string) error {
	b64 := base64.StdEncoding.EncodeToString(data)
	shell, err := w.client.CreateShell()
	if err != nil {
		return err
	}
	cmd := func(c string) error {
		co, err := shell.ExecuteWithContext(w.ctx, c)
		if err != nil {
			return err
		}
		var errOut strings.Builder
		var wg sync.WaitGroup
		wg.Add(2)
		go func() { defer wg.Done(); io.Copy(io.Discard, co.Stdout) }()
		go func() { defer wg.Done(); io.Copy(&errOut, co.Stderr) }()
		co.Wait()
		wg.Wait()
		co.Close()
		if co.ExitCode() != 0 {
			return fmt.Errorf("%s", cut(errOut.String(), 200))
		}
		return nil
	}
	err = cmd(fmt.Sprintf(`if not exist "%s" mkdir "%s"`, w.wdir, w.wdir))
	if err == nil {
		err = cmd(fmt.Sprintf(`del /q "%s.b64" 2>nul & ver >nul`, remote))
	}
	for i := 0; err == nil && i < len(b64); i += 7000 {
		err = cmd(fmt.Sprintf(`echo %s>>"%s.b64"`, b64[i:min(i+7000, len(b64))], remote))
	}
	shell.Close()
	if err != nil {
		return err
	}
	_, stderr, rc, err := w.client.RunPSWithContext(w.ctx, fmt.Sprintf(
		"$b=(Get-Content '%[1]s.b64') -join ''; [IO.File]::WriteAllBytes('%[1]s',[Convert]::FromBase64String($b)); Remove-Item '%[1]s.b64'", remote))
	if err == nil && rc != 0 {
		err = fmt.Errorf("%s", cut(stderr, 200))
	}
	return err
}

// ps runs a PowerShell script on the machine (as a .ps1 file: no command-length limit) and returns the
// exit code and the output.
func (w *winJob) ps(script string) (int, string) {
	path := fmt.Sprintf(`%s\step-%d.ps1`, w.wdir, time.Now().UnixMilli())
	body := "\ufeff$ErrorActionPreference='Continue'\n$ProgressPreference='SilentlyContinue'\n" + script
	if err := w.put([]byte(body), path); err != nil {
		return 1, "upload of the step script failed: " + err.Error()
	}
	stdout, stderr, rc, err := w.client.RunPSWithContext(w.ctx, fmt.Sprintf(
		"& powershell -NoProfile -ExecutionPolicy Bypass -File '%[1]s'; $c=$LASTEXITCODE; Remove-Item '%[1]s' -EA 0; exit $c", path))
	if err != nil {
		return 1, stdout + stderr + "\nWinRM: " + err.Error()
	}
	var keep []string
	for _, l := range strings.Split(strings.ReplaceAll(stdout+stderr, "\r\n", "\n"), "\n") {
		if !strings.HasPrefix(l, "#< CLIXML") && !strings.HasPrefix(l, "<Objs ") {
			keep = append(keep, l)
		}
	}
	return rc, strings.Join(keep, "\n")
}

// step runs one named step: log file windows-<name>.log, the last 30 lines on screen, a summary line.
// skipRC: the exit code that means "skipped" (-1 = none).
func (w *winJob) step(name, script string, skipRC int) bool {
	fmt.Println("::group::windows " + name)
	t := time.Now()
	rc, out := w.ps(script)
	os.WriteFile(filepath.Join(w.out, "windows-"+name+".log"), []byte(out), 0o644)
	lines := strings.Split(out, "\n")
	if len(lines) > 30 {
		lines = lines[len(lines)-30:]
	}
	fmt.Println(strings.Join(lines, "\n"))
	fmt.Println("::endgroup::")
	res := "FAIL"
	switch {
	case skipRC >= 0 && rc == skipRC:
		res = "SKIP"
	case rc == 0:
		res = "PASS"
	}
	w.failed = w.failed || res == "FAIL"
	line := fmt.Sprintf("%-14s %s  (%ds)", name, res, int(time.Since(t).Seconds()))
	w.summary = append(w.summary, line)
	fmt.Println(line)
	return res != "FAIL"
}

func cut(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
