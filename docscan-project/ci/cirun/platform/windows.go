package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"docscan/cirun/assets"
	"docscan/cirun/config"
	"docscan/cirun/transport"
)

// Windows — збірка MSBuild-ом на Windows-машині (зараз через WinRM; кандидати — ВМ, потім запасний ПК).
type Windows struct {
	cfg    *config.Platform
	sec    *config.Resolver
	report Reporter
	fuzz   int               // секунди фазингу
	assets *assets.Assets    // тестові файли поза git (nil — немає)
	full   bool              // вибрана машина проганяє всі тести (Candidate.full_tests)
	extra  map[string][]byte // corpus-verdicts.tsv, malware-verdicts.tsv — у артефакти

	t    transport.Transport
	wdir string // робоча тека на Windows (C:\ci)
	repo string // код: <wdir>\yara
	sha  string // коміт, що збирається (для версії пакета)
	logs map[string]string
	fill func(string) string // підставляє {{W}}, {{REPO}}, {{Y}}, {{V}}, … у скрипти
}

// NewWindows створює платформу Windows за розділом конфігу.
func NewWindows(cfg *config.Platform, sec *config.Resolver, fuzz int, as *assets.Assets, report Reporter) *Windows {
	w := cfg.Workdir
	if w == "" {
		w = `C:\ci`
	}
	return &Windows{cfg: cfg, sec: sec, report: report, fuzz: fuzz, assets: as, wdir: w, repo: w + `\yara`,
		logs: map[string]string{}, extra: map[string][]byte{}}
}

func (w *Windows) Name() string { return "windows" }

// Prepare: перший кандидат з відкритим портом; WinRM-транспорт з робочою текою w.wdir.
func (w *Windows) Prepare(ctx context.Context) error {
	var tried []string
	for _, m := range w.cfg.Machines() {
		if m.Connection.Type != "winrm" {
			return fmt.Errorf("%s: Windows over %q is not supported yet (winrm only)", m.Name, m.Connection.Type)
		}
		if !transport.Reachable(m.Connection) {
			tried = append(tried, m.Name+" ("+m.Connection.Host+")")
			continue
		}
		t, err := transport.New(ctx, m.Connection, w.sec)
		if err != nil {
			return fmt.Errorf("%s: %w", m.Name, err)
		}
		if wr, ok := t.(*transport.WinRM); ok {
			wr.SetWorkdir(w.wdir)
		}
		w.t = t
		w.full = m.Full()
		// залишки обірваного прогону (напр. машину вимкнули посеред тесту): скрипти кроків (у одному з них
		// токен до сховку), розпаковані тестові файли і шкідливе ПЗ — геть, перш ніж робити щось інше
		t.Run(ctx, fmt.Sprintf(`Remove-Item '%[1]s\step-*.ps1','%[1]s\*.b64' -Force -EA 0; Remove-Item '%[1]s\tests' -Recurse -Force -EA 0`, w.wdir), nil)
		// цей рядок читає й старий розбір логів; формат лишається тим самим
		w.report(Event{Platform: "windows", Kind: "machine", Where: t.Where() + " (" + m.Name + ")"})
		return nil
	}
	return fmt.Errorf("no Windows build machine is reachable: %s", strings.Join(tried, ", "))
}

// common — початок кожного скрипта: $w, $repo, робоча тека і виняток Defender для неї (тестові зразки
// навмисно схожі на шкідливі, Defender не повинен їх забирати).
const winCommon = `
$w = '{{W}}'; $repo = '{{REPO}}'
New-Item -ItemType Directory -Force $w | Out-Null
if (Get-Command Add-MpPreference -EA 0) {
  try { if (@((Get-MpPreference).ExclusionPath) -notcontains $w) { Add-MpPreference -ExclusionPath $w -EA Stop } } catch { }
}
`

// step виконує один PowerShell-крок: подія start, вивід у logs, подія done з PASS / FAIL / SKIP.
// skipRC — код виходу, що означає «пропущено» (-1 — такого немає).
func (w *Windows) step(ctx context.Context, name, script string, skipRC int) StepResult {
	w.report(Event{Platform: "windows", Kind: "start", Step: name})
	t := time.Now()
	r, err := w.t.Run(ctx, w.fill(winCommon+script), nil)
	res := StepResult{Name: name, Status: "FAIL", Duration: time.Since(t), Log: r.Output}
	switch {
	case err != nil:
		res.Log += "\nWinRM: " + err.Error()
	case skipRC >= 0 && r.ExitCode == skipRC:
		res.Status = "SKIP"
	case r.ExitCode == 0:
		res.Status = "PASS"
	}
	w.logs[name] = res.Log
	w.report(Event{Platform: "windows", Kind: "done", Step: name, Result: &res})
	return res
}

// SyncSource: git з Forgejo, якщо машина його бачить і має git (source: auto | git), інакше zip
// точного коміту, переданий транспортом (source: auto | zip). Кеш пакетів NuGet зберігається.
func (w *Windows) SyncSource(ctx context.Context, src Source) error {
	w.sha = src.SHA
	version := time.Now().Format("20060102") + "-" + src.SHA[:8]
	w.fill = strings.NewReplacer("{{W}}", w.wdir, "{{REPO}}", w.repo, "{{URL}}", src.GitURL, "{{SHA}}", src.SHA,
		"{{Y}}", w.repo+`\windows\vs2019\Release\yara64.exe`, "{{YC}}", w.repo+`\windows\vs2019\Release\yarac64.exe`, "{{V}}", version,
		"{{HDR}}", "Authorization: token "+src.GitToken).Replace

	useGit := false
	if w.cfg.Source != "zip" && src.GitURL != "" {
		r, _ := w.t.Run(ctx, w.fill(`
try { $r = Invoke-WebRequest -UseBasicParsing '{{URL}}' -Method Head -TimeoutSec 6; 'forgejo: yes' } catch { 'forgejo: no' }
if (Get-Command git -EA 0) { 'git: yes' } else { 'git: no' }
`), nil)
		useGit = strings.Contains(r.Output, "forgejo: yes") && strings.Contains(r.Output, "git: yes")
	}
	if w.cfg.Source == "git" && !useGit {
		return fmt.Errorf("source: git, but the machine does not see Forgejo or has no git")
	}
	var res StepResult
	if useGit {
		res = w.step(ctx, "checkout", `
if (Test-Path "$repo" -PathType Container) { if (-not (Test-Path "$repo\.git")) { Remove-Item $repo -Recurse -Force } }
if (-not (Test-Path "$repo\.git")) { git -c "http.extraHeader={{HDR}}" clone --no-checkout '{{URL}}' $repo 2>&1 | % { "$_" } }
Set-Location $repo
git -c "http.extraHeader={{HDR}}" fetch --force origin {{SHA}} 2>&1 | % { "$_" }
git checkout --force {{SHA}} 2>&1 | % { "$_" }
git clean -xfdq -e windows/vs2019/packages 2>&1 | % { "$_" }
"commit: " + (git rev-parse HEAD) + " (git)"
if ((git rev-parse HEAD) -ne '{{SHA}}') { exit 1 }
`, -1)
	} else {
		data, err := src.Archive("zip")
		if err != nil {
			return err
		}
		if err := w.t.Upload(ctx, data, w.wdir+`\src.zip`); err != nil {
			return fmt.Errorf("source upload: %w", err)
		}
		res = w.step(ctx, "checkout", `
$keep = "$w\packages-cache"
if (Test-Path "$repo\windows\vs2019\packages") { Remove-Item $keep -Recurse -Force -EA 0; Move-Item "$repo\windows\vs2019\packages" $keep }
Remove-Item $repo -Recurse -Force -EA 0
Expand-Archive "$w\src.zip" $repo -Force
Remove-Item "$w\src.zip"
if (Test-Path $keep) { Move-Item $keep "$repo\windows\vs2019\packages" }
"commit: {{SHA}} (zip, `+fmt.Sprint(len(data))+` bytes)"
`, -1)
	}
	if res.Status != "PASS" {
		return fmt.Errorf("checkout failed")
	}
	return nil
}

// Build: пакети NuGet (nuget, кеш з попередньої збірки або завантажений nuget.exe), потім MSBuild
// Release x64 (v143) проєктів yara і yarac; у лог — помилки, попередження компілятора і «->».
func (w *Windows) Build(ctx context.Context) (StepResult, error) {
	return w.step(ctx, "build", `
Set-Location $repo
$pk = "windows\vs2019\packages"
if (Get-Command nuget -EA 0) { nuget restore windows\vs2019\yara.sln 2>&1 | Select-Object -Last 2 }
elseif (-not (Test-Path $pk)) {
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
`, -1), nil
}

// Test: перевірка документів (check_verdicts.ps1, Python не потрібен) — на будь-якій машині. На машині з
// full_tests: третій прохід, тестові файли поза git (завантажити зі сховку в C:\ci\tests — виняток
// Defender), ворожі файли, корпус, шкідливе ПЗ (лише сканування), фазинг (якщо є clang-cl). Після тестів
// C:\ci\tests видаляється ЗАВЖДИ — корпуси і шкідливе ПЗ на машині не лишаються.
func (w *Windows) Test(ctx context.Context) ([]StepResult, error) {
	steps := []StepResult{w.step(ctx, "documents", `
Set-Location $repo
powershell -NoProfile -ExecutionPolicy Bypass -File docscan-project\ci\check_verdicts.ps1 -Yara '{{Y}}' -Rules docscan-project\rules\docscan-index.yar -Samples docscan-project\test-samples\generated -Expected docscan-project\ci\expected-verdicts.tsv -WorkDir "$w\tmp"
exit $LASTEXITCODE
`, -1)}
	// confine: пісочниця DocScan (cli/docscan_sandbox.c) — yara64 розбирає файл у процесі-воркері з
	// lockdown-токеном; воркер пробує читати/писати файли, реєстр, запустити cmd.exe — усе має бути
	// заблоковано; брокер — job object і без привілеїв. RESULT: CONFINED → код 0
	// Не CONFINED → діагностика: які DLL вантажаться на старті (а які — відкладено) і хто з них тягне
	// user32/gdi32 (lockdown-процес без доступу до window station падає з 0xC0000142).
	steps = append(steps, w.step(ctx, "confine", `
& '{{Y}}' --docscan-confine-check x 2>&1 | % { "$_" }
$rc = $LASTEXITCODE
if ($rc -ne 0) {
  $db = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx64\x64\dumpbin.exe" -EA 0 | Select-Object -First 1 -ExpandProperty FullName
  function deps($file) {
    $r = @{ start = @(); delay = @() }; $sec = ''
    foreach ($l in (& $db /nologo /dependents $file)) {
      if ($l -match 'delay load dependencies') { $sec = 'delay' } elseif ($l -match 'following dependencies') { $sec = 'start' }
      elseif ($sec -and $l -match '^\s+(\S+\.dll)\s*$') { $r[$sec] += $Matches[1] }
    }
    $r
  }
  if ($db) {
    "--- diagnostics (dumpbin)"
    $y = deps '{{Y}}'
    "yara64.exe loads at start: " + ($y.start -join ', ')
    "yara64.exe delay-loads:    " + ($y.delay -join ', ')
    foreach ($d in $y.start) {
      $p = Join-Path $env:WINDIR "System32\$d"
      if (Test-Path $p) { $s = (deps $p).start | Where-Object { $_ -match '(?i)^(user32|gdi32|win32u)\.dll$' }; if ($s) { "  $d loads at start: " + ($s -join ', ') } }
    }
  } else { "--- diagnostics: dumpbin not found" }
}
exit $rc
`, -1))
	if !w.full {
		// машина лише для збірки і 35 зразків (напр. робоча станція): прогін на Windows НЕПОВНИЙ
		w.report(Event{Platform: "windows", Kind: "note", Step: "partial: full_tests is off on this machine - no critical, hostile, corpus, malware, fuzz"})
		return steps, nil
	}
	// $py — справжній Python (не заглушка з WindowsApps); немає — код 3 = SKIP
	const py = `
$py = @("python", "python3", "py") | ForEach-Object { Get-Command $_ -EA 0 } | Where-Object { $_.Source -notlike "*WindowsApps*" } | Select-Object -First 1
if (-not $py) { "no Python on this machine"; exit 3 }
$py = $py.Source; $env:PYTHONIOENCODING = 'utf-8'
`
	steps = append(steps, w.step(ctx, "critical", py+`
Set-Location $repo
& $py docscan-project\test-critical\run_tests.py --yara '{{Y}}'
exit $LASTEXITCODE
`, 3))

	if w.assets != nil && w.assets.CorpusURL != "" {
		defer w.t.Run(context.Background(), w.fill(`Remove-Item "{{W}}\tests" -Recurse -Force -EA 0`), nil)
		get := w.step(ctx, "assets", py+`
$t = "$w\tests"; Remove-Item $t -Recurse -Force -EA 0; New-Item -ItemType Directory -Force $t | Out-Null
# без смуги прогресу: у Windows PowerShell 5.1 вона сповільнює завантаження великих файлів у рази
$ProgressPreference = 'SilentlyContinue'
$sw = [Diagnostics.Stopwatch]::StartNew()
function lap($what) { "{0,-22} {1,6:N0} s" -f $what, $sw.Elapsed.TotalSeconds; $sw.Restart() }
$h = @{ Authorization = 'token `+w.assets.Token+`' }
Invoke-WebRequest -UseBasicParsing -Uri '`+w.assets.CorpusURL+`' -Headers $h -OutFile "$t\corpus.tar.gz"
lap "corpus download"
tar.exe -xzf "$t\corpus.tar.gz" -C $t; if ($LASTEXITCODE) { "tar failed"; exit 1 }
Remove-Item "$t\corpus.tar.gz"
lap "corpus unpack"
$mal = '`+w.assets.MalwareURL+`'
if ($mal) {
  Invoke-WebRequest -UseBasicParsing -Uri $mal -Headers $h -OutFile "$t\malware.zip"
  lap "malware download"
  # tar.exe (bsdtar / libarchive) читає запаролений zip сам і швидко; Python zipfile розшифровує ZipCrypto
  # на чистому Python (дуже повільно на 1 ГБ) — лише запасний шлях, якщо tar.exe не впорався
  New-Item -ItemType Directory -Force "$t\malware" | Out-Null
  tar.exe -xf "$t\malware.zip" --passphrase '`+assets.MalwareZipKey+`' -C "$t\malware" 2>&1 | Select-Object -Last 3
  if ($LASTEXITCODE) {
    "tar.exe could not unpack malware.zip - falling back to Python"
    Remove-Item "$t\malware" -Recurse -Force -EA 0
    & $py -c "import zipfile,sys; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2], pwd=b'`+assets.MalwareZipKey+`')" "$t\malware.zip" "$t\malware"
    if ($LASTEXITCODE) { "unzip failed"; exit 1 }
  }
  Remove-Item "$t\malware.zip"
  lap "malware unpack"
}
"corpus: " + (Get-ChildItem "$t\corpus" -Recurse -File).Count + " files, seeds: " + (Get-ChildItem "$t\seeds" -File -EA 0).Count + ", malware: " + (Get-ChildItem "$t\malware" -Recurse -File -EA 0).Count
`, 3)
		steps = append(steps, get)
		if get.Status == "PASS" {
			steps = append(steps, w.step(ctx, "hostile", py+`
Set-Location $repo; $t = "$w\tests"
& $py docscan-project\test-critical\hostile.py "$t\seeds" "$t\hostile"
if ($LASTEXITCODE) { exit 1 }
& $py docscan-project\test-critical\hostile_run.py '{{Y}}' docscan-project\rules\docscan-index.yar docscan-project\test-critical\crit-test.yar "$t\hostile" 120
exit $LASTEXITCODE
`, 3))
			steps = append(steps, w.step(ctx, "corpus", py+`
Set-Location $repo
& $py docscan-project\ci\check_corpus.py --yara '{{Y}}' --yarac '{{YC}}' --rules docscan-project\rules\docscan-index.yar --dir "$w\tests\corpus" --out "$w\corpus-verdicts.tsv"
exit $LASTEXITCODE
`, 3))
			w.keep(ctx, "corpus-verdicts.tsv")
			if w.assets.MalwareURL != "" {
				steps = append(steps, w.step(ctx, "malware", py+`
Set-Location $repo
& $py docscan-project\ci\check_corpus.py --yara '{{Y}}' --yarac '{{YC}}' --rules docscan-project\rules\docscan-index.yar --dir "$w\tests\malware" --out "$w\malware-verdicts.tsv" --expect "$w\tests\malware\expected.txt"
exit $LASTEXITCODE
`, 3))
				w.keep(ctx, "malware-verdicts.tsv")
			}
		}
	}

	if w.fuzz > 0 {
		// фазер розбору (clang-cl + libFuzzer + ASan): усі парсери DocScan і лікування (фазер усього модуля
		// потребує libyara, зібраної clang, — лише на Маці/Linux). Немає LLVM — SKIP (на ВМ: choco install llvm).
		//   1. регресії: кожен fuzz\regressions\parsers-* окремо — падіння = FAIL;
		//   2. фазинг з базою з УСІХ тестових файлів: корпуси (POI, pdf.js, LibreOffice RTF, LNK, Tika, oletools,
		//      plaso), 42 згенеровані зразки, документи-зразки seeds (шкідливе ПЗ — ні);
		//   3. знайдені падіння -> fuzz-crashes.zip в артефакти прогону.
		steps = append(steps, w.step(ctx, "fuzz", `
Set-Location $repo
if (-not (Test-Path "C:\Program Files\LLVM\bin\clang-cl.exe")) { "no LLVM (clang-cl) on this machine: choco install llvm"; exit 3 }
$f = "$w\fuzz"; Remove-Item $f -Recurse -Force -EA 0
Remove-Item "$w\fuzz-crashes.zip" -Force -EA 0
powershell -NoProfile -ExecutionPolicy Bypass -File docscan-project\fuzz\build_windows.ps1 -Repo $repo -Out $f
if (-not (Test-Path "$f\docscan_parsers_fuzzer.exe")) { exit 1 }
New-Item -ItemType Directory -Force "$f\corpus", "$f\crashes" | Out-Null
$fz = "$f\docscan_parsers_fuzzer.exe"
$bad = 0; $nr = 0
foreach ($r in (Get-ChildItem "$repo\docscan-project\fuzz\regressions" -Filter "parsers-*" -File)) {
  $nr++
  & $fz -timeout=10 -rss_limit_mb=2048 $r.FullName *> $null
  if ($LASTEXITCODE -ne 0) { "regression FAIL: " + $r.Name; $bad++ }
}
"regressions: $nr, failed: $bad"
$seeds = @("$w\tests\corpus", "$w\tests\seeds", "$repo\docscan-project\test-samples\generated") | Where-Object { Test-Path $_ }
"seed folders: " + ($seeds -join ', ')
& $fz "-dict=$repo\docscan-project\fuzz\docscan.dict" -max_len=262144 -max_total_time=`+fmt.Sprint(w.fuzz)+` -timeout=20 -rss_limit_mb=2048 "-artifact_prefix=$f\crashes\" "$f\corpus" @seeds 2>&1 | Select-String -Pattern "^#|Done|ERROR|crash|INITED" | Select-Object -Last 15 | % { $_.Line }
$rc = $LASTEXITCODE
# failures: crash-* / timeout-* / oom-* / leak-*; slow-unit-* (one run took > 10 s, e.g. the VM was busy) is
# only reported and kept in the artifacts
$all = @(Get-ChildItem "$f\crashes" -File)
$n = @($all | Where-Object { $_.Name -match '^(crash|timeout|oom|leak)-' }).Count
$slow = @($all | Where-Object { $_.Name -like 'slow-unit-*' })
"crash/timeout inputs: $n"
foreach ($s in $slow) { "slow input (not a failure): " + $s.Name + " (" + $s.Length + " bytes)" }
if ($all.Count -gt 0) { Compress-Archive -Path "$f\crashes\*" -DestinationPath "$w\fuzz-crashes.zip" -Force }
if ($bad -gt 0 -or $rc -ne 0 -or $n -gt 0) { exit 1 }
`, 3))
		w.keep(ctx, "fuzz-crashes.zip")
	}
	return steps, nil
}

// keep забирає файл результату з робочої теки машини (для артефактів і звірки між платформами).
func (w *Windows) keep(ctx context.Context, name string) {
	if b, err := w.t.Download(ctx, w.wdir+`\`+name); err == nil {
		w.extra[name] = b
	}
}

// FetchArtifacts: build_package.ps1 -> C:\ci\dist\DocScan-<версія>.zip -> сюди (+ .sha256), логи кроків, summary.txt.
func (w *Windows) FetchArtifacts(ctx context.Context, dst string) ([]string, error) {
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return nil, err
	}
	var files []string
	defer w.SaveLogs(dst) // логи кроків — навіть якщо пакет не вийшов
	pkg := w.step(ctx, "package", `
Set-Location $repo
Remove-Item "$w\dist" -Recurse -Force -EA 0
powershell -ExecutionPolicy Bypass -File docscan-project\deploy\build_package.ps1 -Repo $repo -Out "$w\dist" -Version {{V}} 2>&1 | % { "$_" }
if (-not (Test-Path "$w\dist\DocScan-{{V}}.zip")) { exit 1 }
(Get-FileHash "$w\dist\DocScan-{{V}}.zip").Hash.ToLower() + "  DocScan-{{V}}.zip"
`, -1)
	if pkg.Status != "PASS" {
		return files, fmt.Errorf("package step failed")
	}
	version := w.fill("{{V}}")
	name := "DocScan-" + version + ".zip"
	data, err := w.t.Download(ctx, w.wdir+`\dist\`+name)
	if err != nil {
		return files, fmt.Errorf("package download: %w", err)
	}
	p := filepath.Join(dst, name)
	if err := os.WriteFile(p, data, 0o644); err != nil {
		return files, err
	}
	sum := sha256.Sum256(data)
	if err := os.WriteFile(p+".sha256", []byte(hex.EncodeToString(sum[:])+"  "+name+"\n"), 0o644); err != nil {
		return files, err
	}
	return append(files, p, p+".sha256"), nil
}

// CollectLogs — після провалу: логи виконаних кроків у dst.
func (w *Windows) CollectLogs(ctx context.Context, dst string) { w.SaveLogs(dst) }

// SaveLogs пише вивід кожного виконаного кроку у <dst>/windows-<крок>.log.
func (w *Windows) SaveLogs(dst string) {
	os.MkdirAll(dst, 0o755)
	for n, b := range w.extra {
		os.WriteFile(filepath.Join(dst, n), b, 0o644)
	}
	for n, l := range w.logs {
		os.WriteFile(filepath.Join(dst, "windows-"+n+".log"), []byte(l), 0o644)
	}
}

func (w *Windows) Close() error {
	if w.t != nil {
		return w.t.Close()
	}
	return nil
}
