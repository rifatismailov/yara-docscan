# DocScan — встановлення з HTTP-сервера одним скриптом.
#
# На робочій машині, PowerShell ВІД АДМІНІСТРАТОРА:
#   powershell -ExecutionPolicy Bypass -File .\DocScan-Setup.ps1 -DetectOnly        # пілот: лише алерти
#   powershell -ExecutionPolicy Bypass -File .\DocScan-Setup.ps1                    # повний режим (з лікуванням)
# або без збереження файлу:
#   powershell -ExecutionPolicy Bypass -Command "iwr -UseBasicParsing <BaseUrl>/DocScan-Setup.ps1 -OutFile $env:TEMP\ds.ps1; & $env:TEMP\ds.ps1 -DetectOnly"
#
# Що робить:
#   1) бере ім'я поточного пакета з <BaseUrl>/DocScan-latest.txt (або -Version);
#   2) завантажує DocScan-<версія>.zip і .sha256, звіряє SHA256 (не збігся — зупиняється);
#   3) розпаковує в тимчасову теку і запускає install.ps1 з переданими параметрами
#      (install.ps1 ще раз перевіряє кожен файл за SHA256SUMS.txt усередині пакета);
#   4) прибирає тимчасові файли.
# Оновлення: на сервер — новий zip + .sha256, у DocScan-latest.txt — його ім'я; цей скрипт не міняється.

param(
  [string]  $BaseUrl = "",          # напр. http://<сервер>:8080 (тека, де лежать пакет і DocScan-latest.txt)
  [string]  $Version = "",          # напр. 20261106-f1d0b6a7; порожньо — з DocScan-latest.txt
  [switch]  $DetectOnly,            # -> install.ps1 -DetectOnly
  [switch]  $NoAvExclusion,         # -> install.ps1 -NoAvExclusion
  [switch]  $QuarantineGeneral,     # -> install.ps1 -QuarantineGeneral
  [string[]]$WatchPath              # -> install.ps1 -WatchPath
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # без цього Invoke-WebRequest у PS 5.1 дуже повільний

function Fail($m) { Write-Host "ПОМИЛКА: $m" -ForegroundColor Red; exit 1 }

# Текстовий файл із сервера. Через файл, а не .Content: невідомий тип (напр. .sha256 як
# application/octet-stream) PowerShell 5.1 повертає масивом байтів, а не рядком.
function Get-RemoteText([string]$url) {
  $tmp = [IO.Path]::GetTempFileName()
  try { Invoke-WebRequest -UseBasicParsing $url -OutFile $tmp; return [IO.File]::ReadAllText($tmp) }
  finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Fail "запустіть PowerShell від імені адміністратора" }
if (-not $BaseUrl) { Fail "не задано -BaseUrl (адреса сервера з пакетом)" }
$BaseUrl = $BaseUrl.TrimEnd('/')

# 1) версія
if (-not $Version) {
  try { $latest = Get-RemoteText "$BaseUrl/DocScan-latest.txt" }
  catch { Fail "не вдалося прочитати $BaseUrl/DocScan-latest.txt — $($_.Exception.Message)" }
  $pkg = ($latest -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1).Trim()
} else {
  $pkg = "DocScan-$Version.zip"
}
if ($pkg -notmatch '^DocScan-[\w.-]+\.zip$') { Fail "дивне ім'я пакета: '$pkg'" }
Write-Host "==> пакет: $pkg  ($BaseUrl)" -ForegroundColor Cyan

# 2) завантаження і перевірка
$work = Join-Path $env:TEMP ("DocScan-setup-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force $work | Out-Null
try {
  $zip = Join-Path $work $pkg
  try {
    Invoke-WebRequest -UseBasicParsing "$BaseUrl/$pkg" -OutFile $zip
    $sumLine = Get-RemoteText "$BaseUrl/$pkg.sha256"
  } catch { Fail "завантаження не вдалося — $($_.Exception.Message)" }
  $expected = (($sumLine.Trim() -split '\s+')[0]).ToLower()
  $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($expected -notmatch '^[0-9a-f]{64}$') { Fail "у $pkg.sha256 немає контрольної суми" }
  if ($actual -ne $expected) { Fail "SHA256 не збігається (очікувано $expected, отримано $actual) — пакет пошкоджено або підмінено" }
  Write-Host "==> SHA256 збігається, розпаковую" -ForegroundColor Cyan

  # 3) розпаковка і встановлення
  $dir = Join-Path $work "pkg"
  Expand-Archive $zip $dir -Force
  $inst = Join-Path $dir "install.ps1"
  if (-not (Test-Path $inst)) { Fail "у пакеті немає install.ps1" }

  # у тому ж процесі зі splatting: -File не передає масиви (-WatchPath 'C:\Users','D:\Shares')
  $p = @{}
  if ($DetectOnly)        { $p.DetectOnly = $true }
  if ($NoAvExclusion)     { $p.NoAvExclusion = $true }
  if ($QuarantineGeneral) { $p.QuarantineGeneral = $true }
  if ($WatchPath)         { $p.WatchPath = $WatchPath }
  Write-Host ("==> install.ps1 " + (($p.Keys | ForEach-Object { "-$_" }) -join " ")) -ForegroundColor Cyan
  $global:LASTEXITCODE = 0
  & $inst @p
  $rc = $LASTEXITCODE
} finally {
  # 4) прибирання
  Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
if ($rc -ne 0) { Fail "install.ps1 завершився з кодом $rc" }
Write-Host "Готово." -ForegroundColor Green
