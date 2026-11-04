# DocScan — встановлення / оновлення на Windows.
#
# Запуск (PowerShell ВІД АДМІНІСТРАТОРА, з розпакованої теки пакета):
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -WatchPath 'C:\Users','D:\Shares'
#
# Що робить:
#   1) перевіряє SHA256SUMS.txt пакета;
#   2) копіює bin\, rules\, watcher\ у -InstallDir (за замовч. C:\Program Files\DocScan);
#   3) створює -DataDir (C:\ProgramData\DocScan): results\ і quarantine\ — доступ лише SYSTEM + Administrators;
#   4) самоперевірка: yara64 запускається, правила компілюються, тестовий скан дає JSON;
#   5) реєструє завдання планувальника "DocScan Watcher": при старті Windows, від SYSTEM,
#      перезапуск при збої; і запускає його.
# Повторний запуск = оновлення (попередні правила зберігаються в rules.prev\).

param(
  [string]  $InstallDir = "$env:ProgramFiles\DocScan",
  [string]  $DataDir    = "$env:ProgramData\DocScan",
  [string[]]$WatchPath  = @("C:\Users"),
  [switch]  $QuarantineGeneral,   # exe/скрипти/архіви зі збігом vendor-правил -> карантин
  [switch]  $NoStart              # зареєструвати, але не запускати зараз
)

$ErrorActionPreference = "Stop"
$TaskName = "DocScan Watcher"
$Pkg = $PSScriptRoot

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "ПОМИЛКА: $m" -ForegroundColor Red; exit 1 }

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
        ($(if ($QuarantineGeneral) { " -QuarantineGeneral" } else { "" })) + "`""
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
Write-Host "  стежить за: $($WatchPath -join ', ')   (лікування увімкнене)"
Write-Host "  результати: $DataDir\results\docscan-results.json  (лог: watcher.log)"
Write-Host "  карантин:   $DataDir\quarantine"
Write-Host "  політика:   $InstallDir\rules\docscan-policy.yar  (після зміни: Restart-ScheduledTask '$TaskName')"
Write-Host "  видалення:  powershell -ExecutionPolicy Bypass -File '$InstallDir\uninstall.ps1'"
