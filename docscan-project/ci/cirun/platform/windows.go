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
	fuzz   int                // секунди фазингу
	assets *assets.Assets     // тестові файли поза git (nil — немає)
	full   bool               // вибрана машина проганяє всі тести (Candidate.full_tests)
	extra  map[string][]byte  // corpus-verdicts.tsv, malware-verdicts.tsv — у артефакти
	combat *config.FileServer // бойовий тест (--combat): звідки брати тестові файли; nil — вимкнено
	// стенд конвеєра Forgejo (cirun stand): role build — MSBuild + пакет; test — готовий пакет prebuilt замість
	// збірки; suite smoke | full. role "" — звичайний прогін cirun (усе як раніше).
	role, suite, prebuilt string
	load                  *config.LoadTest // навантажувальний тест після повного набору (стенд-термінальний сервер); nil — ні

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

// SetStand робить з платформи стенд конвеєра: role build | test, suite smoke | full, prebuilt — пакет
// DocScan-<версія>.zip стенда-збирача (для role test).
func (w *Windows) SetStand(role, suite, prebuilt string) {
	w.role, w.suite, w.prebuilt = role, suite, prebuilt
}

// SetLoad вмикає навантажувальний тест на стенді конвеєра (після повного набору).
func (w *Windows) SetLoad(l *config.LoadTest) { w.load = l }

// pkgPath — пакет цього коміту на машині: role build — щойно зібраний, інакше — пакет стенда-збирача.
func (w *Windows) pkgPath() string {
	if w.role == "build" {
		return w.wdir + `\dist\DocScan-` + w.fill("{{V}}") + ".zip"
	}
	return w.wdir + `\build.zip`
}

// EnableCombat вмикає бойовий тест (--combat) з тестовими файлами з файлового сервера fs.
func (w *Windows) EnableCombat(fs config.FileServer) { w.combat = &fs }

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
		if w.role != "" {
			w.full = w.suite == "full"
		}
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
try { Expand-Archive "$w\src.zip" $repo -Force -ErrorAction Stop } catch { "ERROR: source not unpacked: $_"; exit 1 }
Remove-Item "$w\src.zip"
if (-not (Test-Path "$repo\windows\vs2019\yara.sln")) { "ERROR: source incomplete (no windows\vs2019\yara.sln)"; exit 1 }
if (Test-Path $keep) { Move-Item $keep "$repo\windows\vs2019\packages" }
"commit: {{SHA}} (zip, `+fmt.Sprint(len(data))+` bytes)"
`, -1)
	}
	if res.Status != "PASS" {
		return fmt.Errorf("checkout failed")
	}
	return w.provideRules(ctx, src)
}

// provideRules — правила цього прогону: <repo>\docscan-project\rules (тести) і <wdir>\DocScan-rules-bundle.zip
// (install.ps1 -Rules у smoke, навантажувальному і бойовому тестах). Звідки — rulesrc (підписаний реліз).
func (w *Windows) provideRules(ctx context.Context, src Source) error {
	if src.RulesZip == "" {
		return nil
	}
	for local, remote := range map[string]string{src.RulesZip: w.wdir + `\rules.zip`, src.RulesBundle: w.wdir + `\DocScan-rules-bundle.zip`} {
		b, err := os.ReadFile(local)
		if err != nil {
			return err
		}
		if err := w.t.Upload(ctx, b, remote); err != nil {
			return fmt.Errorf("rules upload: %w", err)
		}
	}
	res := w.step(ctx, "rules", `
$d = "$repo\docscan-project\rules"
Remove-Item $d -Recurse -Force -EA 0
try { Expand-Archive "$w\rules.zip" $d -Force -ErrorAction Stop } catch { "ERROR: rules not unpacked: $_"; exit 1 }
Remove-Item "$w\rules.zip"
if (-not (Test-Path "$d\docscan-index.yar")) { "ERROR: no docscan-index.yar"; exit 1 }
"rules: " + (Get-Content "$d\VERSION.txt" -TotalCount 1) + " (" + @(Get-ChildItem $d -Recurse -File).Count + " files)"
`, -1)
	if res.Status != "PASS" {
		return fmt.Errorf("rules not unpacked")
	}
	return nil
}

// Build: Go-watcher (docscan-watcher.exe, крос-збірка на Маку з цього коміту -> у репозиторій на машині, звідти
// його бере build_package.ps1), пакети NuGet (nuget, кеш з попередньої збірки або завантажений nuget.exe), потім
// MSBuild Release x64 (v143) проєктів yara і yarac; у лог — помилки, попередження компілятора і «->».
func (w *Windows) Build(ctx context.Context) (StepResult, error) {
	if w.role == "test" {
		return w.deployPrebuilt(ctx), nil
	}
	exes, glog, err := buildGoWatcher(ctx, w.sha)
	sizes := ""
	for rel, b := range exes {
		if err != nil {
			break
		}
		err = w.t.Upload(ctx, b, w.repo+`\docscan-project\services\`+strings.ReplaceAll(rel, "/", `\`))
		sizes += fmt.Sprintf(" %s %d bytes;", rel, len(b))
	}
	if err != nil {
		res := StepResult{Name: "build", Status: "FAIL", Log: "Go watcher: " + err.Error() + "\n" + glog}
		w.logs["build"] = res.Log
		w.report(Event{Platform: "windows", Kind: "start", Step: "build"})
		w.report(Event{Platform: "windows", Kind: "done", Step: "build", Result: &res})
		return res, nil
	}
	res := w.step(ctx, "build", fmt.Sprintf("\n\"Go watcher + updater:%s cross-built, go vet + go test passed\"", sizes)+`
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
`, -1)
	return res, nil
}

// deployPrebuilt — стенд role test: замість збірки — бінарники з пакета стенда-збирача (bin\ пакета: yara64,
// yarac64, рантайм VC++) у ту саму теку, де їх шукають тести (windows\vs2019\Release); сам пакет лишається
// в <wdir>\build.zip для кроку install.
func (w *Windows) deployPrebuilt(ctx context.Context) StepResult {
	fail := func(msg string) StepResult {
		res := StepResult{Name: "build", Status: "FAIL", Log: msg}
		w.logs["build"] = msg
		w.report(Event{Platform: "windows", Kind: "start", Step: "build"})
		w.report(Event{Platform: "windows", Kind: "done", Step: "build", Result: &res})
		return res
	}
	data, err := os.ReadFile(w.prebuilt)
	if err != nil {
		return fail("prebuilt package: " + err.Error())
	}
	if err := w.t.Upload(ctx, data, w.wdir+`\build.zip`); err != nil {
		return fail("prebuilt package upload: " + err.Error())
	}
	return w.step(ctx, "build", fmt.Sprintf("\n\"prebuilt package %s (%d bytes) - no compiler on this stand\"", filepath.Base(w.prebuilt), len(data))+`
$x = "$w\build-x"; Remove-Item $x -Recurse -Force -EA 0
Expand-Archive "$w\build.zip" $x -Force
$rel = "$repo\windows\vs2019\Release"; New-Item -ItemType Directory -Force $rel | Out-Null
Copy-Item "$x\bin\*" $rel -Force
Get-Content "$x\VERSION.txt" -TotalCount 1
Remove-Item $x -Recurse -Force
& '{{Y}}' --version
exit $LASTEXITCODE
`, -1)
}

// install — стенд конвеєра: пакет цього коміту встановлюється як на ПК (install_smoke.ps1: install.ps1, Go-watcher
// від SYSTEM, 4 зразки -> записи з очікуваним вердиктом, uninstall -Purge). Пакет: role build — щойно зібраний
// (крок package), role test — пакет стенда-збирача.
func (w *Windows) install(ctx context.Context) []StepResult {
	var steps []StepResult
	if w.role == "build" {
		p := w.packageStep(ctx)
		steps = append(steps, p)
		if p.Status != "PASS" {
			return steps
		}
	}
	pkg := w.pkgPath()
	return append(steps, w.step(ctx, "install", `
Set-Location $repo
powershell -NoProfile -ExecutionPolicy Bypass -File docscan-project\ci\install_smoke.ps1 -Package '`+pkg+`' -Repo $repo -Work "$w\smoke" -Rules "$w\DocScan-rules-bundle.zip"
exit $LASTEXITCODE
`, -1))
}

// packageStep — build_package.ps1 -> <wdir>\dist\DocScan-<версія>.zip (якщо його ще немає в цьому прогоні).
func (w *Windows) packageStep(ctx context.Context) StepResult {
	return w.step(ctx, "package", `
Set-Location $repo
if (-not (Test-Path "$w\dist\DocScan-{{V}}.zip")) {
  Remove-Item "$w\dist" -Recurse -Force -EA 0
  powershell -ExecutionPolicy Bypass -File docscan-project\deploy\build_package.ps1 -Repo $repo -Out "$w\dist" -Version {{V}} 2>&1 | % { "$_" }
}
if (-not (Test-Path "$w\dist\DocScan-{{V}}.zip")) { exit 1 }
(Get-FileHash "$w\dist\DocScan-{{V}}.zip").Hash.ToLower() + "  DocScan-{{V}}.zip"
`, -1)
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
	if w.role != "" {
		steps = append(steps, w.install(ctx)...)
	}
	if w.suite == "combat" { // лише бойовий тест (cirun --release-run): повний набір цього коміту вже пройшов у конвеєрі
		if w.combat == nil {
			return steps, fmt.Errorf("suite combat without the combat test (no fileserver)")
		}
		return append(steps, w.runCombat(ctx, pyFind)...), nil
	}
	if !w.full {
		if w.role != "" { // стенд з набором smoke: так і задумано, не «неповний прогін»
			return steps, nil
		}
		// машина лише для збірки і 35 зразків (напр. робоча станція): прогін на Windows НЕПОВНИЙ
		w.report(Event{Platform: "windows", Kind: "note", Step: "partial: full_tests is off on this machine - no critical, hostile, corpus, malware, fuzz"})
		return steps, nil
	}
	const py = pyFind
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
	if w.combat != nil {
		steps = append(steps, w.runCombat(ctx, py)...)
	}
	if w.load != nil && w.role != "" {
		steps = append(steps, w.runLoad(ctx, py)...)
	}
	return steps, nil
}

// runLoad — навантажувальний тест термінального сервера (ci/loadtest) з пакетом цього коміту:
//
//	load-setup    rds_reset.ps1 -Package: DocScan з нуля (-DetectOnly, стежить за C:\Users) + завдання SYSTEM з
//	              rds_load.ps1 (Users користувачів працюють з файлами у профілях; з WinRM-сеансу не можна —
//	              WinRM вбиває дочірні процеси, коли сеанс закривається);
//	load-run      опитування раз на 30 с, поки rds_load.ps1 не запише done.txt (навантаження + дочитування);
//	load          loadtest_report.py: кожна дія користувача має запис watcher-а; пропущений файл — FAIL;
//	load-cleanup  завдання, генератори, DocScan і файли тесту в профілях — геть (завжди).
func (w *Windows) runLoad(ctx context.Context, py string) (steps []StepResult) {
	l := w.load
	q := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	name := "ci-" + time.Now().Format("20060102-150405") + "-" + w.sha[:8]
	root := strings.TrimRight(l.Root, `\`)
	run := root + `\runs\` + name
	tlog := root + `\runs\` + name + "-task.log"
	const task = "DocScan CI load"
	head := `
$root = '` + q(root) + `'; $run = '` + q(run) + `'; $tlog = '` + q(tlog) + `'; $lt = "$repo\docscan-project\ci\loadtest"
`
	defer func() {
		steps = append(steps, w.step(context.Background(), "load-cleanup", head+`
Stop-ScheduledTask -TaskName '`+task+`' -EA 0; Unregister-ScheduledTask -TaskName '`+task+`' -Confirm:$false -EA 0
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | ? { $_.CommandLine -match 'loadgen\.ps1|rds_load\.ps1' } | % { Stop-Process -Id $_.ProcessId -Force -EA 0 }
& powershell -NoProfile -ExecutionPolicy Bypass -File "$lt\rds_reset.ps1" -RemoveOnly 2>&1 | % { "$_" }
# прогони CI: лишаються 5 останніх (кожен — копія результатів і журналу watcher-а)
Get-ChildItem "$root\runs" -Directory -Filter 'ci-*' -EA 0 | Sort-Object Name -Descending | Select-Object -Skip 5 | % { Remove-Item $_.FullName -Recurse -Force -EA 0; Remove-Item ($_.FullName + '-task.log') -Force -EA 0 }
exit 0
`, -1))
	}()

	crit := ""
	if l.Critical != "" {
		crit = `$crit = '` + q(l.Critical) + `'`
	} else {
		crit = `$crit = "$root\critical-rules.yar"; if (-not (Test-Path $crit)) { $crit = "" }`
	}
	args := fmt.Sprintf(`-Users %d -Minutes %d -IntervalSec %d -Burst %d -ProbeUsers %d -ProbeMinutes %d -DrainMinutes %d -Name %s -Root "%s"`,
		l.Users, l.Minutes, l.IntervalSec, l.Burst, l.ProbeUsers, l.Minutes, l.DrainMinutes, name, root)
	setup := w.step(ctx, "load-setup", head+crit+`
if (-not (Test-Path "$root\docs")) { "no test documents in $root\docs (once: rds_docs.ps1)"; exit 1 }
$users = @(Get-ChildItem C:\Users -Directory | ? Name -match '^lt\d\d$').Count
if ($users -lt `+fmt.Sprint(l.Users)+`) { "only $users load-test user profiles, `+fmt.Sprint(l.Users)+` needed (once: rds_setup.ps1 + one logon each)"; exit 1 }
"users: $users, sessions: " + @(quser 2>$null | Select -Skip 1).Count + ", critical rules: " + $(if ($crit) { 'yes' } else { 'no' })
$a = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", "$lt\rds_reset.ps1", "-Package", '`+q(w.pkgPath())+`', "-Rules", "$w\DocScan-rules-bundle.zip", "-DetectOnly")
if ($crit) { $a += @("-Critical", $crit) }
& powershell @a 2>&1 | % { "$_" }
if ($LASTEXITCODE) { "rds_reset.ps1 failed: exit $LASTEXITCODE"; exit 1 }
New-Item -ItemType Directory -Force "$root\runs" | Out-Null
Unregister-ScheduledTask -TaskName '`+task+`' -Confirm:$false -EA 0
$act = New-ScheduledTaskAction -Execute cmd.exe -Argument ('/c powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + "$lt\rds_load.ps1" + '" `+strings.ReplaceAll(args, "'", "''")+` > "' + $tlog + '" 2>&1')
$pr = New-ScheduledTaskPrincipal -UserId S-1-5-18 -LogonType ServiceAccount -RunLevel Highest
$st = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries
Register-ScheduledTask -TaskName '`+task+`' -Action $act -Principal $pr -Settings $st -Force | Out-Null
Start-ScheduledTask -TaskName '`+task+`'
"started: $run"
`, -1)
	steps = append(steps, setup)
	if setup.Status != "PASS" {
		return steps
	}

	// load-run: rds_load.ps1 працює завданням SYSTEM; тут — опитування раз на 30 с
	w.report(Event{Platform: "windows", Kind: "start", Step: "load-run"})
	t0 := time.Now()
	limit := time.Duration(l.Minutes+l.DrainMinutes+45) * time.Minute
	runSt := StepResult{Name: "load-run", Status: "FAIL"}
	var lines []string
	for time.Since(t0) < limit {
		r, err := w.t.Run(ctx, `$run = '`+q(run)+`'
if (Test-Path "$run\done.txt") { "done" }
"task: " + (Get-ScheduledTask -TaskName '`+task+`' -EA 0).State
Get-Content "$run\drain.log" -Tail 1 -EA 0`, nil)
		if ctx.Err() != nil {
			break
		}
		done, state, last := false, "", ""
		for _, ln := range strings.Split(r.Output, "\n") {
			ln = strings.TrimSpace(ln)
			switch {
			case ln == "done":
				done = true
			case strings.HasPrefix(ln, "task: "):
				state = strings.TrimPrefix(ln, "task: ")
			case ln != "":
				last = ln
			}
		}
		if last != "" && (len(lines) == 0 || lines[len(lines)-1] != last) {
			lines = append(lines, last)
		}
		if done {
			runSt.Status = "PASS"
			break
		}
		if err == nil && state != "Running" && state != "Queued" && time.Since(t0) > 2*time.Minute {
			lines = append(lines, "rds_load.ps1 is not running any more (task state: "+state+") and wrote no done.txt")
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
		}
	}
	if runSt.Status != "PASS" && time.Since(t0) >= limit {
		lines = append(lines, fmt.Sprintf("no done.txt after %s", limit))
	}
	runSt.Duration = time.Since(t0)
	runSt.Log = strings.Join(lines, "\n")
	w.logs["load-run"] = runSt.Log
	w.report(Event{Platform: "windows", Kind: "done", Step: "load-run", Result: &runSt})
	steps = append(steps, runSt)

	// load: звіт по тому, що є (навіть якщо прогін не дійшов до кінця)
	steps = append(steps, w.step(ctx, "load", py+head+`
Copy-Item $tlog "$w\load-task.log" -Force -EA 0
if (-not (Test-Path "$run\meta.json")) { "no run folder $run"; exit 1 }
if (-not (Test-Path "$run\done.txt")) {  # не дочекалися: копії результатів, як rds_fetch
  foreach ($f in @("docscan-results.json", "watcher.log") | % { $b = "$env:ProgramData\DocScan\results\$_"; $b; 1..5 | % { "$b.$_" } }) { if (Test-Path $f) { Copy-Item $f $run -Force } }
}
$out = & $py "$lt\loadtest_report.py" $run 2>&1 | % { "$_" }
$rc = $LASTEXITCODE
$out | Set-Content "$w\load-report.txt" -Encoding UTF8
$out
if (-not (Test-Path "$run\done.txt")) { exit 1 }
exit $rc
`, 3))
	w.keep(context.Background(), "load-report.txt")
	w.keep(context.Background(), "load-task.log")
	return steps
}

// runCombat — бойовий тест: пакет цього коміту встановлюється install.ps1 як на робочій станції, і
// установлений watcher (SYSTEM) обробляє КОЖЕН тестовий файл, що з'являється в теці (42 зразки, реальні зразки
// замовника, шкідливе ПЗ, корпуси, seeds — з файлового сервера). Кроки:
//
//	combat-setup    combat_setup.ps1: пакет, install.ps1, файли з сервера, знімок стану, подавач (завдання SYSTEM);
//	combat-feed     подавач кладе файли партіями й чекає, поки watcher упорається; тут — лише опитування стану;
//	combat          check_watcher.py: запис на кожен файл, вердикти проти еталонів, звіт;
//	combat-cleanup  combat_cleanup.ps1: тестові файли, шкідливе ПЗ, їхні бекапи — геть (завжди).
func (w *Windows) runCombat(ctx context.Context, py string) (steps []StepResult) {
	work, inbox := w.wdir+`\combat`, w.wdir+`\inbox`
	fail := func(name, msg string) []StepResult {
		w.report(Event{Platform: "windows", Kind: "start", Step: name})
		r := StepResult{Name: name, Status: "FAIL", Log: msg}
		w.logs[name] = msg
		w.report(Event{Platform: "windows", Kind: "done", Step: name, Result: &r})
		return append(steps, r)
	}
	fs := w.combat
	if fs.UNC == "" {
		return fail("combat-setup", "no fileserver section in the config: the combat test takes its files from the file server")
	}
	user := fs.User
	if user == "" && fs.UserRef != "" {
		u, err := w.sec.Get(fs.UserRef)
		if err != nil {
			return fail("combat-setup", "fileserver user: "+err.Error())
		}
		user = u
	}
	pass, err := w.sec.Get(fs.PasswordRef)
	if err != nil {
		return fail("combat-setup", "fileserver password: "+err.Error())
	}
	q := func(s string) string { return strings.ReplaceAll(s, "'", "''") }
	defer func() {
		steps = append(steps, w.step(context.Background(), "combat-cleanup", `
& powershell -NoProfile -ExecutionPolicy Bypass -File "$repo\docscan-project\ci\combat_cleanup.ps1" -Work '`+work+`' -Inbox '`+inbox+`'
exit 0
`, -1))
	}()
	pkgArg := "" // стенд без компілятора (Win10): готовий пакет стенда-збирача замість збірки на місці
	if w.prebuilt != "" {
		pkgArg = ` -Package "$w\build.zip"`
	}
	setup := w.step(ctx, "combat-setup", `
$env:DOCSCAN_SHARE_PASS = '`+q(pass)+`'
Set-Location $repo
& powershell -NoProfile -ExecutionPolicy Bypass -File docscan-project\ci\combat_setup.ps1 -Repo $repo -Work '`+work+`' -Inbox '`+inbox+`' -Version {{V}} -Share '`+q(fs.UNC)+`' -ShareUser '`+q(user)+`' -Rules "$w\DocScan-rules-bundle.zip"`+pkgArg+`
exit $LASTEXITCODE
`, -1)
	steps = append(steps, setup)
	if setup.Status != "PASS" {
		return steps
	}

	// combat-feed: подавач працює завданням SYSTEM на машині; тут — опитування раз на 30 с
	w.report(Event{Platform: "windows", Kind: "start", Step: "combat-feed"})
	t0 := time.Now()
	feed := StepResult{Name: "combat-feed", Status: "FAIL"}
	var lines []string
	lastNote := time.Time{}
	for time.Since(t0) < 8*time.Hour {
		r, err := w.t.Run(ctx, w.fill(`Get-Content '`+work+`\feed-status.txt' -EA 0; "task: " + (Get-ScheduledTask -TaskName "DocScan combat feed" -EA 0).State`), nil)
		if ctx.Err() != nil {
			break
		}
		st, task := "", ""
		for _, l := range strings.Split(r.Output, "\n") {
			l = strings.TrimSpace(l)
			switch {
			case strings.HasPrefix(l, "task: "):
				task = strings.TrimPrefix(l, "task: ")
			case l != "":
				st = l
			}
		}
		if err == nil && st != "" && (len(lines) == 0 || lines[len(lines)-1] != st) {
			lines = append(lines, time.Now().Format("15:04:05")+" "+st)
			if time.Since(lastNote) > 10*time.Minute || strings.HasPrefix(st, "done") {
				w.report(Event{Platform: "windows", Kind: "note", Step: "combat: " + st})
				lastNote = time.Now()
			}
		}
		if strings.HasPrefix(st, "done") {
			feed.Status = "PASS"
			break
		}
		if err == nil && task != "Running" && task != "Queued" && time.Since(t0) > 2*time.Minute {
			lines = append(lines, "the feeder task is not running any more (state: "+task+")")
			break
		}
		select {
		case <-ctx.Done():
		case <-time.After(30 * time.Second):
		}
	}
	feed.Duration = time.Since(t0)
	feed.Log = strings.Join(lines, "\n")
	w.logs["combat-feed"] = feed.Log
	w.report(Event{Platform: "windows", Kind: "done", Step: "combat-feed", Result: &feed})
	steps = append(steps, feed)

	// combat: що watcher записав на кожен файл (навіть якщо подавач не дійшов до кінця — звіт по тому, що є)
	steps = append(steps, w.step(ctx, "combat", py+`
Set-Location $repo
$snap = Get-Content '`+work+`\snap.json' -Raw | ConvertFrom-Json
$res = "$env:ProgramData\DocScan\results"
$cv = @(); if (Test-Path "$w\corpus-verdicts.tsv") { $cv = @("--corpus-verdicts", "$w\corpus-verdicts.tsv") }
$co = @(); if ($snap.critical_on) { $co = @("--critical-on") }
& $py docscan-project\ci\check_watcher.py --results "$res\docscan-results.json" --results-offset $snap.results --log "$res\watcher.log" --log-offset $snap.log --inbox '`+inbox+`' --src '`+work+`\src' --watcher docscan-project\services\cmd\watcher\config.go --expected docscan-project\ci\expected-verdicts.tsv @cv @co --records "$w\combat-records.json" --report "$w\combat-report.txt"
$rc = $LASTEXITCODE
# the watcher log of the test (from the snapshot on)
$in = [IO.File]::Open("$res\watcher.log", 'Open', 'Read', 'ReadWrite'); $o = [long]$snap.log; if ($o -gt $in.Length) { $o = 0 }
[void]$in.Seek($o, 'Begin'); $out = [IO.File]::Create("$w\combat-watcher.log"); $in.CopyTo($out); $out.Close(); $in.Close()
exit $rc
`, 3))
	for _, f := range []string{"combat-report.txt", "combat-records.json", "combat-watcher.log"} {
		w.keep(context.Background(), f)
	}
	return steps
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
	if w.role == "test" { // пакет зібрав стенд-збирач
		return files, nil
	}
	if w.role == "" { // звичайний прогін: пакет завжди свіжий
		w.t.Run(ctx, w.fill(`Remove-Item '{{W}}\dist' -Recurse -Force -EA 0`), nil)
	}
	pkg := w.packageStep(ctx)
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

// pyFind — $py: справжній Python (не заглушка з WindowsApps); немає — код 3 = SKIP
const pyFind = `
$py = @("python", "python3", "py") | ForEach-Object { Get-Command $_ -EA 0 } | Where-Object { $_.Source -notlike "*WindowsApps*" } | Select-Object -First 1
if (-not $py) { "no Python on this machine"; exit 3 }
$py = $py.Source; $env:PYTHONIOENCODING = 'utf-8'
`
