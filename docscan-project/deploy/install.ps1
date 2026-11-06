# DocScan — встановлення / оновлення на Windows.
#
# Запуск (PowerShell ВІД АДМІНІСТРАТОРА, з розпакованої теки пакета):
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -WatchPath 'C:\Users','D:\Shares'
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -DetectOnly       # пілот: лише алерти, файли не змінюються
#   ... -NoAvExclusion   — не додавати винятки Microsoft Defender (за замовчуванням додаються)
#
# Що робить:
#   1) перевіряє SHA256SUMS.txt пакета;
#   1b) винятки Microsoft Defender для -InstallDir і -DataDir (-NoAvExclusion — пропустити); ESET — лише попередження;
#   2) копіює bin\, rules\, watcher\ у -InstallDir (за замовч. C:\Program Files\DocScan);
#   3) створює -DataDir (C:\ProgramData\DocScan): results\ і quarantine\ — доступ лише SYSTEM + Administrators;
#   4) самоперевірка: yara64 запускається, правила компілюються, тестовий скан дає JSON;
#   5) ПОВНІСТЮ прибирає старий DocScan (Wazuh active-response): doc-scan.ps1, doc-scan.cmd,
#      <ossec-agent>\tmp\docscan; старий карантин <ossec-agent>\quarantine переноситься в
#      <DataDir>\quarantine\legacy\ (докази не губляться); і старий YARA для active-response
#      (active-response\bin\yara, yara-scan.*) — його замінює yara64 DocScan. На менеджері Wazuh
#      приберіть <command>/<active-response> для doc-scan і yara-scan;
#   6) агент Wazuh: ossec.conf (бекап) — прибирає <command>/<active-response> doc-scan/yara-scan,
#      додає <localfile> (json) на results\docscan-results.json; перезапускає WazuhSvc, при помилці
#      конфігурації повертає старий ossec.conf;
#   7) реєструє завдання планувальника "DocScan Watcher": при старті Windows, від SYSTEM,
#      перезапуск при збої; і запускає його.
# Повторний запуск = оновлення (попередні правила зберігаються в rules.prev\).

param(
  [string]  $InstallDir = "$env:ProgramFiles\DocScan",
  [string]  $DataDir    = "$env:ProgramData\DocScan",
  [string[]]$WatchPath  = @("C:\Users"),
  [switch]  $QuarantineGeneral,   # exe/скрипти/архіви зі збігом vendor-правил -> карантин
  [switch]  $NoAvExclusion,       # НЕ додавати винятки Defender (якщо їх задає центральна політика)
  [switch]  $DetectOnly,          # лише детект і алерти: файли НЕ лікуються й не переносяться в карантин (пілот)
  [switch]  $NoStart,             # зареєструвати, але не запускати зараз
  [string]  $OssecDir = "${env:ProgramFiles(x86)}\ossec-agent",
  [switch]  $KeepLegacy,          # не прибирати старий DocScan (active-response)
  [switch]  $KeepLegacyYara,      # НЕ видаляти старий YARA active-response (yara-scan + yara\)
  [switch]  $NoWazuhConfig        # не чіпати ossec.conf агента і не перезапускати WazuhSvc
)

$ErrorActionPreference = "Stop"
$TaskName = "DocScan Watcher"
$Pkg = $PSScriptRoot

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "ПОМИЛКА: $m" -ForegroundColor Red; exit 1 }

# ---- ossec.conf агента (текстові правки: файл має кілька <ossec_config>, це не один XML) ----
$DsBegin = "<!-- DocScan: managed by DocScan install.ps1 -->"
$DsEnd   = "<!-- /DocScan -->"
function Remove-DocScanBlock([string]$c) {
  return [regex]::Replace($c, "(?s)[ \t]*" + [regex]::Escape($DsBegin) + ".*?" + [regex]::Escape($DsEnd) + "\r?\n?", "")
}
function Remove-LegacyArBlocks([string]$c) {
  # лише блоки старого DocScan/YARA; загальний <active-response><disabled>..</active-response> лишається
  # спершу <active-response> (усередині є вкладений <command>ім'я</command>), потім визначення <command> з <name>
  $c = [regex]::Replace($c, "(?s)[ \t]*<active-response>(?:(?!</active-response>).)*?(doc-scan|yara-scan)(?:(?!</active-response>).)*?</active-response>\r?\n?", "")
  $c = [regex]::Replace($c, "(?s)[ \t]*<command>(?:(?!</command>).)*?<name>\s*(doc-scan|yara-scan)\s*</name>(?:(?!</command>).)*?</command>\r?\n?", "")
  return $c
}
function Read-Text([string]$p) { return [IO.File]::ReadAllText($p, (New-Object Text.UTF8Encoding($false))) }
function Write-Text([string]$p, [string]$t) { [IO.File]::WriteAllText($p, $t, (New-Object Text.UTF8Encoding($false))) }


# --- 0. права адміністратора ---
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Fail "запустіть PowerShell від імені адміністратора" }

# --- 1. цілісність пакета ---
Step "перевірка цілісності пакета"
$sums = Join-Path $Pkg "SHA256SUMS.txt"
if (-not (Test-Path $sums)) { Fail "немає SHA256SUMS.txt — пакет неповний" }
$bad = @()
foreach ($l in Get-Content $sums) {
  if ($l -notmatch '^([0-9a-f]{64})\s+(.+)$') { continue }
  $f = Join-Path $Pkg $Matches[2]
  if (-not (Test-Path -LiteralPath $f)) { $bad += "немає: $($Matches[2])"; continue }
  if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower() -ne $Matches[1]) { $bad += "змінено: $($Matches[2])" }
}
if ($bad.Count) { $bad | % { Write-Host "  $_" -ForegroundColor Red }; Fail "пакет пошкоджений або змінений" }
Write-Host "  ok ($((Get-Content $sums).Count) файлів)"

# --- 2. зупинити попередню версію ---
$old = Get-ScheduledTask -TaskName $TaskName -EA SilentlyContinue
if ($old) {
  Step "зупинка попередньої версії"
  Stop-ScheduledTask -TaskName $TaskName -EA SilentlyContinue
  Start-Sleep 2
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    ? { $_.CommandLine -like "*docscan-watcher.ps1*" } | % { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
}

# --- 2b. антивірус: винятки (ДО копіювання — файли правил містять рядки зі шкідливих зразків) ---
# Defender: Add-MpPreference -ExclusionPath. Ризик винятку малий: $DataDir закрито для всіх, крім SYSTEM і
# Administrators (крок 4), $InstallDir — звичайні права Program Files. ESET з локального скрипта не
# налаштовується (налаштування під паролем / ESET PROTECT) — лише попередження.
if (-not $NoAvExclusion) {
  Step "антивірус: винятки для $InstallDir і $DataDir"
  if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
    try {
      Add-MpPreference -ExclusionPath $InstallDir, $DataDir -ErrorAction Stop
      $ex = @((Get-MpPreference -ErrorAction Stop).ExclusionPath)
      if ($ex -contains $InstallDir -and $ex -contains $DataDir) { Write-Host "  Microsoft Defender: винятки додано" }
      else { Write-Host "  Microsoft Defender: винятків не видно — ймовірно, ними керує політика (GPO/Intune); додайте там" -ForegroundColor Yellow }
    } catch {
      Write-Host "  Microsoft Defender: не вдалося додати винятки ($($_.Exception.Message)) — додайте політикою" -ForegroundColor Yellow
    }
  } else {
    Write-Host "  Microsoft Defender недоступний на цій машині — пропускаю" -ForegroundColor Yellow
  }
  if (Get-Service -Name ekrn -ErrorAction SilentlyContinue) {
    Write-Host "  ESET виявлено: винятки для $InstallDir і $DataDir додайте політикою в ESET PROTECT" -ForegroundColor Yellow
  }
}

# --- 3. файли програми ---
Step "копіювання в $InstallDir"
New-Item -ItemType Directory -Force $InstallDir | Out-Null
if (Test-Path "$InstallDir\rules") {
  Remove-Item "$InstallDir\rules.prev" -Recurse -Force -EA SilentlyContinue
  Copy-Item "$InstallDir\rules" "$InstallDir\rules.prev" -Recurse
}
foreach ($d in "bin", "rules", "watcher") {
  Remove-Item "$InstallDir\$d" -Recurse -Force -EA SilentlyContinue
  Copy-Item (Join-Path $Pkg $d) "$InstallDir\$d" -Recurse
}
Copy-Item (Join-Path $Pkg "uninstall.ps1") $InstallDir -Force
Copy-Item (Join-Path $Pkg "VERSION.txt") $InstallDir -Force -EA SilentlyContinue

# --- 4. дані: результати й карантин (лише SYSTEM + Administrators) ---
Step "теки даних у $DataDir"
foreach ($d in $DataDir, "$DataDir\results", "$DataDir\quarantine") { New-Item -ItemType Directory -Force $d | Out-Null }
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)   # без успадкування від ProgramData (там є Users:Read)
foreach ($sid in "S-1-5-18", "S-1-5-32-544") {  # SYSTEM, Administrators
  $id = (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount])
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id, "FullControl",
    "ContainerInherit,ObjectInherit", "None", "Allow")))
}
Set-Acl -Path $DataDir -AclObject $acl   # results\ і quarantine\ успадковують ці права

# --- 4b. старий DocScan (Wazuh active-response) -> повне видалення ---
$legacyRemoved = @()
if ((Test-Path $OssecDir) -and -not $KeepLegacy) {
  $arBin = Join-Path $OssecDir "active-response\bin"
  Step "прибираю старий DocScan (Wazuh active-response) з $OssecDir"
  foreach ($n in "doc-scan.ps1", "doc-scan.cmd") {
    $f = Join-Path $arBin $n
    if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force; $legacyRemoved += $f }
  }
  $work = Join-Path $OssecDir "tmp\docscan"
  if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force; $legacyRemoved += $work }
  # старий карантин: оригінали заражених файлів — переносимо, не стираємо
  $oldQ = Join-Path $OssecDir "quarantine"
  if (Test-Path -LiteralPath $oldQ) {
    $items = @(Get-ChildItem -LiteralPath $oldQ -Force)
    if ($items.Count) {
      $dst = "$DataDir\quarantine\legacy"
      New-Item -ItemType Directory -Force $dst | Out-Null
      foreach ($i in $items) { Move-Item -LiteralPath $i.FullName (Join-Path $dst $i.Name) -Force }
      Write-Host ("  старий карантин ({0} об'єктів) -> {1}" -f $items.Count, $dst)
    }
    Remove-Item -LiteralPath $oldQ -Recurse -Force -EA SilentlyContinue
    $legacyRemoved += $oldQ
  }
  if (-not $KeepLegacyYara) {
    foreach ($n in "yara-scan.ps1", "yara-scan.cmd", "yara") {
      $f = Join-Path $arBin $n
      if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Recurse -Force; $legacyRemoved += $f }
    }
  }
  if ($legacyRemoved.Count) {
    $legacyRemoved | % { Write-Host "  видалено: $_" }
    Write-Host "  На менеджері Wazuh приберіть <command>/<active-response> для doc-scan і yara-scan." -ForegroundColor Yellow
  } else {
    Write-Host "  (слідів старого DocScan немає)"
  }
}

# --- 4c. агент Wazuh: ossec.conf + перезапуск ---
$wazuhDone = $false
$ossecConf = Join-Path $OssecDir "ossec.conf"
if ((Test-Path $ossecConf) -and -not $NoWazuhConfig) {
  Step "агент Wazuh: $ossecConf"
  New-Item -ItemType Directory -Force "$DataDir\legacy" | Out-Null
  $bak = "$DataDir\legacy\ossec.conf.{0}.bak" -f (Get-Date -Format "yyyyMMdd-HHmmss")
  Copy-Item -LiteralPath $ossecConf $bak
  $orig = Read-Text $ossecConf
  $new = Remove-LegacyArBlocks (Remove-DocScanBlock $orig)
  $results = "$DataDir\results\docscan-results.json"
  # створити заздалегідь: інакше після рестарту агент пише ERROR (1103) "could not open file"
  if (-not (Test-Path -LiteralPath $results)) { [IO.File]::WriteAllText($results, "") }
  $block = "  $DsBegin`r`n  <localfile>`r`n    <log_format>json</log_format>`r`n    <location>$results</location>`r`n  </localfile>`r`n  $DsEnd`r`n"
  $i = $new.LastIndexOf("</ossec_config>")
  if ($i -lt 0) { Fail "ossec.conf без </ossec_config> — не чіпаю (бекап: $bak)" }
  $new = $new.Substring(0, $i) + $block + $new.Substring($i)
  Write-Text $ossecConf $new
  Write-Host "  бекап: $bak"
  Write-Host "  <localfile> json -> $results"

  $svc = Get-Service WazuhSvc -EA SilentlyContinue
  if ($svc) {
    $log = Join-Path $OssecDir "ossec.log"
    $mark = if (Test-Path $log) { (Get-Item $log).Length } else { 0 }
    Restart-Service WazuhSvc -Force
    Start-Sleep 10
    $errs = @()
    if (Test-Path $log) {
      $fs = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite'); [void]$fs.Seek($mark, 'Begin')
      $tail = (New-Object IO.StreamReader($fs)).ReadToEnd(); $fs.Close()
      $errs = @($tail -split "`n" | ? { $_ -match "(ERROR|CRITICAL).*(config|xml|localfile|ossec\.conf)" })
    }
    if ((Get-Service WazuhSvc).Status -ne "Running" -or $errs.Count) {
      Write-Host "  агент не прийняв конфігурацію — повертаю старий ossec.conf" -ForegroundColor Yellow
      $errs | % { Write-Host "    $_" }
      Copy-Item -LiteralPath $bak $ossecConf -Force
      Restart-Service WazuhSvc -Force
      Fail "ossec.conf відкочено (агент працює на старій конфігурації)"
    }
    Write-Host "  WazuhSvc перезапущено, конфігурацію прийнято"
  } else {
    Write-Host "  (службу WazuhSvc не знайдено — перезапустіть агент вручну)"
  }
  $wazuhDone = $true
}

# --- 5. самоперевірка ---
Step "самоперевірка"
$yara  = "$InstallDir\bin\yara64.exe"
$rules = "$InstallDir\rules\docscan-index.yar"
$ver = & $yara --version 2>&1
if ($LASTEXITCODE -ne 0) { Fail "yara64.exe не запускається: $ver (бракує vcruntime140.dll?)" }
$probe = Join-Path $env:TEMP "docscan-probe.txt"; "probe" | Set-Content $probe
$out = & $yara -w --docscan-json $rules $probe 2>&1 | % { "$_" }
Remove-Item $probe -EA SilentlyContinue
$json = $out | ? { $_ -like '{*' } | Select -First 1
if (-not $json) { Fail "правила не компілюються або немає JSON:`n$($out -join "`n")" }
$j = $json | ConvertFrom-Json
Write-Host "  yara64 $ver; правила компілюються; тестовий скан: verdict=$($j.verdict)"

# --- 6. завдання планувальника ---
Step "реєстрація завдання '$TaskName' (старт при завантаженні Windows, SYSTEM)"
$wp = ($WatchPath | % { "'" + ($_ -replace "'", "''") + "'" }) -join ","
$taskArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"& '$InstallDir\watcher\docscan-watcher.ps1'" +
        " -WatchPath $wp -Yara '$yara' -Rules '$rules' -OutDir '$DataDir\results' -BackupDir '$DataDir\quarantine'" +
        ($(if ($QuarantineGeneral) { " -QuarantineGeneral" } else { "" })) +
        ($(if ($DetectOnly) { " -NoDisarm" } else { "" })) + "`""
$action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArgs
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable `
               -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew `
               -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
  -Settings $settings -Description "DocScan: авто-скан і лікування нових документів (yara64 + docscan)" -Force | Out-Null

if (-not $NoStart) {
  Start-ScheduledTask -TaskName $TaskName
  Start-Sleep 8
  $state = (Get-ScheduledTask -TaskName $TaskName).State
  $log = "$DataDir\results\watcher.log"
  $started = (Test-Path $log) -and (Select-String -Path $log -Pattern "disarm=True" -Quiet -Encoding UTF8)
  if ($state -ne "Running" -or -not $started) { Fail "watcher не стартував (стан: $state). Див. $log" }
  Write-Host "  watcher працює"
}

Write-Host ""
Write-Host "DocScan встановлено." -ForegroundColor Green
Write-Host "  програма:   $InstallDir"
Write-Host ("  стежить за: $($WatchPath -join ', ')   " + $(if ($DetectOnly) { "(ЛИШЕ ДЕТЕКТ: файли не змінюються)" } else { "(лікування увімкнене)" }))
Write-Host "  результати: $DataDir\results\docscan-results.json  (лог: watcher.log)"
Write-Host "  карантин:   $DataDir\quarantine"
if ($legacyRemoved.Count) { Write-Host "  старий DocScan (Wazuh active-response) прибрано повністю" }
if ($wazuhDone) { Write-Host "  Wazuh:      агент читає results\docscan-results.json (json); на менеджері — deploy\manager\cleanup_manager.sh" }
Write-Host "  політика:   $InstallDir\rules\docscan-policy.yar  (після зміни: Restart-ScheduledTask '$TaskName')"
Write-Host "  видалення:  powershell -ExecutionPolicy Bypass -File '$InstallDir\uninstall.ps1'"
