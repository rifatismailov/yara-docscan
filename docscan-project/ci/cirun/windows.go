package main

// «ci-run windows» — CI для Windows, яким керують по WinRM з цього Мака / Unix-runner-а
// (на самій Windows runner не потрібен).
//
// Що робить: вибирає першу доступну Windows-машину для збірки (спершу ВМ на Proxmox, потім запасний ПК),
// кладе на неї точний коміт (git fetch з Forgejo, а якщо машина Forgejo не бачить — zip з git archive,
// переданий по WinRM), збирає MSBuild-ом, проганяє перевірку документів (check_verdicts.ps1 — Python не
// потрібен) і, якщо там є Python, тести третього проходу, збирає пакет (build_package.ps1) і забирає zip
// назад в артефакти.
//
// Змінні середовища (секрети/змінні Forgejo або ci-run у локальному режимі; ніколи не в репозиторії):
//
//	WIN11_HOST, WIN11_USER, WIN11_PASS      перший вибір (ВМ)
//	WIN216_HOST, WIN216_USER, WIN216_PASS   запасний варіант (робоча станція)
//	GIT_URL, GIT_TOKEN                      адреса клонування у Forgejo + токен лише на читання
//	                                        (використовуються, якщо машина бачить Forgejo)
//	SHA                                     коміт, який збирати (має бути в локальному репозиторії)
//	CI_OUT                                  локальна тека виводу (за замовчуванням ci-out)
//	WIN_DIR                                 робоча тека на Windows (за замовчуванням C:\ci)
//
// На Windows потрібні VS Build Tools 2022; Git і Python — необов'язково.

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

// winJob — стан однієї задачі Windows: з'єднання з машиною і результати кроків.
type winJob struct {
	client  *winrm.Client   // клієнт WinRM (HTTP 5985, автентифікація NTLM) до вибраної машини
	ctx     context.Context // контекст для команд WinRM (зараз без скасування — context.Background)
	wdir    string          // робоча тека на Windows (WIN_DIR, за замовчуванням C:\ci)
	out     string          // локальна тека виводу (CI_OUT): логи кроків, summary.txt, artifacts/
	summary []string        // рядки підсумку: «machine ...», «build PASS (57s)» — потім у summary.txt
	failed  bool            // true, якщо хоч один крок завершився FAIL
}

// runWindows — уся задача Windows; повертає код виходу процесу (0 — усе пройшло, 1 — ні).
// Кроки: вибір машини -> checkout (git або zip) -> build (MSBuild) -> documents -> critical ->
// package -> забрати zip -> summary.txt і логи в artifacts/. Якщо checkout чи build не вдалися,
// наступні кроки не виконуються.
func runWindows() int {
	sha := os.Getenv("SHA")
	if sha == "" {
		fmt.Println("SHA is not set")
		return 1
	}
	w := &winJob{ctx: context.Background(), wdir: envOr("WIN_DIR", `C:\ci`), out: envOr("CI_OUT", "ci-out")}
	repo := w.wdir + `\yara` // тека з кодом на Windows
	os.MkdirAll(filepath.Join(w.out, "artifacts"), 0o755)

	// ---- машина для збірки: ВМ, якщо відповідає, інакше запасний ПК
	// target — один кандидат: опис для повідомлень, адреса і обліковий запис.
	type target struct {
		label string // «VM Windows 11» або «fallback PC»
		host  string // адреса машини
		user  string // користувач WinRM
		pass  string // пароль WinRM
	}
	var targets []target // кандидати в порядку переваги (задані в середовищі)
	for _, t := range [][2]string{{"WIN11", "VM Windows 11"}, {"WIN216", "fallback PC"}} {
		if h := strings.TrimSpace(os.Getenv(t[0] + "_HOST")); h != "" {
			targets = append(targets, target{t[1], h, os.Getenv(t[0] + "_USER"), os.Getenv(t[0] + "_PASS")})
		}
	}
	var tg *target // перший кандидат, у якого відкритий порт WinRM 5985
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
	// Цей рядок також читає progress.go, щоб показати IP машини в терміналі.
	fmt.Printf("Windows build machine: %s %s\n", tg.label, tg.host)
	w.summary = append(w.summary, fmt.Sprintf("machine        %s %s", tg.label, tg.host))
	// params — налаштування WinRM: копія типових, але з транспортом NTLM (вхід локальним
	// обліковим записом Windows без домену і без HTTPS).
	params := *winrm.DefaultParameters
	params.TransportDecorator = func() winrm.Transporter { return &winrm.ClientNTLM{} }
	// Тайм-аут HTTP 2 години: збірка і тести йдуть однією командою.
	client, err := winrm.NewClientWithParameters(winrm.NewEndpoint(tg.host, 5985, false, false, nil, nil, nil, 2*time.Hour),
		tg.user, tg.pass, &params)
	if err != nil {
		fmt.Println("WinRM: " + err.Error())
		return 1
	}
	w.client = client

	// common — початок кожного PowerShell-скрипта кроку: змінні $w (робоча тека) і $repo (код),
	// створення робочої теки і виняток Microsoft Defender для неї. {{W}}, {{REPO}} ... у скриптах
	// нижче заповнює fill().
	common := `
$w = '{{W}}'; $repo = '{{REPO}}'
New-Item -ItemType Directory -Force $w | Out-Null
# the test samples look malicious on purpose (inert): Defender must not take them from the CI folder
if (Get-Command Add-MpPreference -EA 0) {
  try { if (@((Get-MpPreference).ExclusionPath) -notcontains $w) { Add-MpPreference -ExclusionPath $w -EA Stop } } catch { }
}
`
	gitURL := envOr("GIT_URL", "http://localhost/")
	version := time.Now().Format("20060102") + "-" + sha[:8] // версія пакета: <дата>-<коміт>
	y := repo + `\windows\vs2019\Release\yara64.exe`         // зібраний yara64.exe
	// fill підставляє значення замість {{...}} у текст скрипта. Заглушки замість fmt.Sprintf —
	// бо в PowerShell багато символів «%», які fmt сприйняв би як свої.
	fill := strings.NewReplacer("{{W}}", w.wdir, "{{REPO}}", repo, "{{URL}}", gitURL, "{{SHA}}", sha, "{{Y}}", y,
		"{{V}}", version, "{{HDR}}", "Authorization: token "+os.Getenv("GIT_TOKEN")).Replace

	// ---- 1. точний коміт: git з Forgejo, якщо машина його бачить і має git, інакше zip звідси
	// probe — вивід перевірки: чи бачить машина Forgejo і чи є на ній git.
	_, probe := w.ps(fill(common + `
try { $r = Invoke-WebRequest -UseBasicParsing '{{URL}}' -Method Head -TimeoutSec 6; 'forgejo: yes' } catch { 'forgejo: no' }
if (Get-Command git -EA 0) { 'git: yes' } else { 'git: no' }
`))
	ok := false // чи можна йти до наступного кроку
	if strings.Contains(probe, "forgejo: yes") && strings.Contains(probe, "git: yes") {
		// git: клон (якщо ще немає), fetch саме цього коміту, checkout, очистка — кеш пакетів NuGet лишається.
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
		// zip: git archive точного коміту тут -> передати по WinRM -> розпакувати замість старого коду
		// (теку пакетів NuGet переносимо вбік і назад, щоб не завантажувати знову).
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

	// ---- 2. збірка: пакети NuGet (nuget, або кеш з попередньої збірки, або завантажити nuget.exe),
	// потім MSBuild (Release x64, toolset v143) лише проєктів yara і yarac; у лог — лише помилки,
	// попередження компілятора і рядки «->» (що зібрано).
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

	// ---- 3. тести і пакет
	if ok {
		// documents: 30 зразків (з них 6 — макроси VBA проти хибних тривог) — вердикт, лікування, повторний скан, оригінали не змінені (check_verdicts.ps1)
		w.step("documents", fill(common+`
Set-Location $repo
powershell -NoProfile -ExecutionPolicy Bypass -File docscan-project\ci\check_verdicts.ps1 -Yara '{{Y}}' -Rules docscan-project\rules\docscan-index.yar -Samples docscan-project\test-samples\generated -Expected docscan-project\ci\expected-verdicts.tsv -WorkDir "$w\tmp"
exit $LASTEXITCODE
`), -1)
		// critical: тести третього проходу — лише якщо на машині є справжній Python (не заглушка
		// з WindowsApps); немає — код 3, що означає SKIP (ці тести однаково йдуть на macOS/Linux).
		w.step("critical", fill(common+`
Set-Location $repo; $env:PYTHONIOENCODING = 'utf-8'
$py = @("python", "python3", "py") | ForEach-Object { Get-Command $_ -EA 0 } | Where-Object { $_.Source -notlike "*WindowsApps*" } | Select-Object -First 1
if (-not $py) { "no Python on this machine - the third-pass tests run on macOS / Linux"; exit 3 }
& $py.Source docscan-project\test-critical\run_tests.py --yara '{{Y}}'
exit $LASTEXITCODE
`), 3)
		// package: build_package.ps1 збирає DocScan-<версія>.zip у C:\ci\dist; потім zip забираємо сюди.
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

	// ---- підсумок і логи в артефакти
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

// fetchPackage забирає з Windows готовий пакет DocScan-<version>.zip і кладе його в artifacts/ разом
// з файлом .sha256 («<хеш>  <ім'я>»). Як: PowerShell на машині читає zip і видає його base64-текстом
// у stdout (WinRM передає лише текст), тут base64 декодується назад у байти.
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

// put передає байти data у файл remote на Windows. WinRM не має «копіювання файлу» і обмежує довжину
// однієї команди, тому: дані кодуються в base64, ріжуться на шматки по 7000 символів, і кожен шматок
// дописується в remote.b64 командою cmd «echo ...>>» — усе в ОДНІЙ оболонці WinRM (так набагато
// швидше, ніж нова оболонка на кожен шматок). Наприкінці PowerShell декодує remote.b64 у remote і
// видаляє .b64. Повертає помилку, якщо хоч одна команда завершилась не з 0.
func (w *winJob) put(data []byte, remote string) error {
	b64 := base64.StdEncoding.EncodeToString(data)
	shell, err := w.client.CreateShell()
	if err != nil {
		return err
	}
	// cmd виконує одну команду cmd.exe в цій оболонці: читає stdout (відкидаємо) і stderr (для помилки)
	// паралельно — інакше команда може зависнути на повному буфері — і перевіряє код виходу.
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
		// видалити залишок попередньої спроби; «ver >nul» — щоб код виходу був 0, навіть якщо файлу не було
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

// ps виконує PowerShell-скрипт на машині і повертає код виходу та вивід (stdout + stderr). Як: скрипт
// передається файлом step-<мс>.ps1 у робочу теку (через put — так немає обмеження на довжину
// команди), з BOM UTF-8 (щоб PowerShell 5.1 правильно прочитав не-ASCII) і заголовком
// «помилки не зупиняють, без смуги прогресу»; запускається окремим powershell, файл видаляється.
// Службові рядки PowerShell про прогрес («#< CLIXML», «<Objs ...») з виводу прибираються.
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
	var keep []string // рядки виводу без службових
	for _, l := range strings.Split(strings.ReplaceAll(stdout+stderr, "\r\n", "\n"), "\n") {
		if !strings.HasPrefix(l, "#< CLIXML") && !strings.HasPrefix(l, "<Objs ") {
			keep = append(keep, l)
		}
	}
	return rc, strings.Join(keep, "\n")
}

// step виконує один названий крок: увесь вивід — у windows-<name>.log, останні 30 рядків — на екран
// (між «::group::» і «::endgroup::», які Forgejo згортає в лозі), рядок підсумку «<name> PASS (Ns)»
// — на екран і в summary. skipRC — код виходу, що означає «пропущено» (SKIP), -1 — такого немає.
// Повертає false лише для FAIL (SKIP — не помилка, можна йти далі).
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

// cut прибирає пробіли по краях і обрізає рядок до n байтів — для коротких повідомлень про помилки.
func cut(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}
