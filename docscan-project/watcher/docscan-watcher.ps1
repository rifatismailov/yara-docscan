# DocScan watcher — стежить за новими файлами (FileSystemWatcher) і сканує їх yara64.exe.
#
# Два типи файлів:
#   document — Office / RTF / PDF / LNK:
#       прохід A: yara64 --docscan-json docscan-index.yar   (наш модуль: вектори, докази, Шар 2 по VBA)
#       прохід B: yara64 file-index.yar                     (vendor-правила по сирих байтах файлу)
#   general  — exe/dll/скрипти/hta/архіви/образи:
#       тільки прохід B
#
# Результат: один JSON на рядок у $OutDir\docscan-results.json (у майбутньому забиратиме Wazuh:
# <localfile><log_format>json</log_format>). Діагностика роботи — $OutDir\watcher.log.
#
# Запуск (PowerShell від адміністратора, щоб бачити файли всіх користувачів):
#   powershell -ExecutionPolicy Bypass -File docscan-watcher.ps1
#   powershell -ExecutionPolicy Bypass -File docscan-watcher.ps1 -WatchPath C:\docscan-build\inbox -Disarm
# Зупинка: Ctrl+C.

param(
  [string[]]$WatchPath = @("C:\Users"),
  [string]$Base        = "C:\docscan-build",
  [string]$Yara        = "",
  [string]$DocRules    = "",
  [string]$FileRules   = "",
  [string]$OutDir      = "",
  [switch]$Disarm,                 # лікувати документи з verdict HIGH (оригінал -> <file>.docscan-bak)
  [int]$MaxSizeMB      = 100,      # більші файли пропускаємо (запис у лог)
  [int]$SettleSeconds  = 2,        # скільки чекати тиші після останньої події по файлу
  [int]$ReadyTimeout   = 60,       # скільки чекати, поки файл перестане записуватись
  [string[]]$DocExt = @(
    ".doc",".dot",".docx",".docm",".dotx",".dotm",
    ".xls",".xlt",".xlsx",".xlsm",".xltx",".xltm",".xlsb",
    ".ppt",".pps",".pot",".pptx",".pptm",".potx",".potm",".ppsx",".ppsm",
    ".rtf",".pdf",".lnk"),
  [string[]]$GenExt = @(
    ".exe",".dll",".sys",".scr",".cpl",".ocx",".com",".msi",
    ".ps1",".psm1",".vbs",".vbe",".js",".jse",".wsf",".wsh",".hta",".bat",".cmd",".jar",
    ".zip",".rar",".7z",".iso",".img",".vhd",".vhdx"),
  # шляхи (regex), які не скануємо: кеші браузерів, Recent (там .lnk на кожне відкриття файлу) тощо
  [string[]]$ExcludePattern = @(
    '\\\$Recycle\.Bin\\',
    '\\AppData\\Local\\(Temp\\chocolatey|Packages|Microsoft\\(Edge|OneDrive|Windows\\(WebCache|Explorer|Notifications|INetCache\\IE))|Google\\Chrome|Mozilla|D3DSCache)\\',
    '\\AppData\\Roaming\\(Code|Mozilla|Microsoft\\(Windows\\Recent|Office\\Recent))\\',
    '\.docscan-bak$',
    '\\~\$[^\\]*$')
)

if (-not $Yara)      { $Yara      = "$Base\yara\windows\vs2019\Release\yara64.exe" }
if (-not $DocRules)  { $DocRules  = "$Base\yara\docscan-project\rules\docscan-index.yar" }
if (-not $FileRules) { $FileRules = "$Base\yara\docscan-project\rules\file-index.yar" }
if (-not $OutDir)    { $OutDir    = "$Base\results" }

[Console]::OutputEncoding = [Text.Encoding]::UTF8   # вивід yara64 (шляхи, докази) — UTF-8
$utf8   = New-Object Text.UTF8Encoding($false)
$Result = Join-Path $OutDir "docscan-results.json"
$LogF   = Join-Path $OutDir "watcher.log"
$DocSet = @{}; $DocExt | % { $DocSet[$_.ToLower()] = 1 }
$GenSet = @{}; $GenExt | % { $GenSet[$_.ToLower()] = 1 }

function Log([string]$msg, [string]$level = "INFO") {
  $line = "{0} [{1}] {2}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $level, $msg
  Write-Host $line -ForegroundColor @{INFO="Gray";WARN="Yellow";ERROR="Red";HIT="Magenta";OK="Green"}[$level]
  [IO.File]::AppendAllText($LogF, $line + "`r`n", $utf8)
}

function Get-Category([string]$path) {
  $ext = [IO.Path]::GetExtension($path).ToLower()
  if ($DocSet.ContainsKey($ext)) { return "document" }
  if ($GenSet.ContainsKey($ext)) { return "general" }
  return $null
}

function Test-Excluded([string]$path) {
  if ($path.StartsWith($OutDir, [StringComparison]::OrdinalIgnoreCase)) { return $true }
  foreach ($p in $ExcludePattern) { if ($path -match $p) { return $true } }
  return $false
}

# Файл готовий, коли його можна відкрити на читання і розмір не змінюється.
function Wait-FileReady([string]$path) {
  $deadline = (Get-Date).AddSeconds($ReadyTimeout)
  $last = -1
  while ((Get-Date) -lt $deadline) {
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { return "gone" }
    try {
      $fs = [IO.File]::Open($path, 'Open', 'Read', 'ReadWrite')
      $len = $fs.Length; $fs.Close()
      if ($len -eq $last) { return "ready" }
      $last = $len
    } catch { }
    Start-Sleep -Milliseconds 500
  }
  return "timeout"
}

# Прохід B: звичайний yara-скан, повертає імена правил, що спрацювали.
function Invoke-FileScan([string]$path) {
  $out = & $Yara -w $FileRules $path 2>&1
  $rules = @(); $errs = @()
  foreach ($l in $out) {
    if ($l -is [Management.Automation.ErrorRecord]) { $errs += "$l"; continue }
    $s = "$l"
    if ($s -match '^error') { $errs += $s; continue }
    if ($s.Trim()) { $rules += ($s -split ' ', 2)[0] }
  }
  return @{ rules = @($rules | Select-Object -Unique); errors = $errs }
}

# Прохід A: наш модуль. Повертає розібраний JSON docscan (+ дію лікування).
function Invoke-DocScan([string]$path) {
  $yargs = @("--docscan-json")
  if ($Disarm) { $yargs += "--docscan-disarm" }
  $out = & $Yara @yargs $DocRules $path 2>&1 | ForEach-Object { "$_" }
  $json = $out | Where-Object { $_ -like '{*' } | Select-Object -First 1
  $act  = $out | Where-Object { $_ -like 'docscan-disarm:*' } | Select-Object -First 1
  $errs = @($out | Where-Object { $_ -match '^error' })
  $obj  = $null
  if ($json) { try { $obj = $json | ConvertFrom-Json } catch { $errs += "bad docscan json: $json" } }
  if ($act) { $act = $act -replace '^docscan-disarm: .* -> ', '' }
  return @{ docscan = $obj; disarm = $act; errors = $errs }
}

$Rank = @{ INFO = 0; MEDIUM = 1; HIGH = 2 }
function Max-Verdict($a, $b) { if ($Rank[$b] -gt $Rank[$a]) { $b } else { $a } }

function Scan-File([string]$path, [string]$evt) {
  $cat = Get-Category $path
  $state = Wait-FileReady $path
  if ($state -eq "gone") { Log "зник до скану: $path" "WARN"; return }

  $rec = [ordered]@{
    timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")
    source    = "docscan"
    host      = $env:COMPUTERNAME
    event     = $evt
    category  = $cat
    file      = [ordered]@{ path = $path; name = [IO.Path]::GetFileName($path);
                            ext = [IO.Path]::GetExtension($path).ToLower(); size = $null; sha256 = $null }
    verdict   = "INFO"
    docscan   = $null
    yara_file_matches = @()
    disarm    = $null
    errors    = @()
  }
  if ($state -eq "timeout") { $rec.errors += "file still being written after ${ReadyTimeout}s" }

  try {
    $fi = Get-Item -LiteralPath $path
    $rec.file.size = $fi.Length
    if ($fi.Length -gt $MaxSizeMB * 1MB) {
      $rec.verdict = "SKIPPED"; $rec.errors += "size > ${MaxSizeMB}MB"
    } else {
      $rec.file.sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()

      # прохід B до лікування: бачимо оригінальні байти
      $fs = Invoke-FileScan $path
      $rec.yara_file_matches = $fs.rules
      $rec.errors += $fs.errors

      if ($cat -eq "document") {
        $ds = Invoke-DocScan $path
        $rec.docscan = $ds.docscan
        $rec.disarm  = $ds.disarm
        $rec.errors += $ds.errors
        if ($ds.docscan) { $rec.verdict = $ds.docscan.verdict }
        # vendor-правило на самому документі підіймає щонайменше до MEDIUM
        if ($fs.rules.Count) { $rec.verdict = Max-Verdict $rec.verdict "MEDIUM" }
      } elseif ($fs.rules.Count) {
        $rec.verdict = "HIGH"   # file-index = strict-набір + maldoc
      }
    }
  } catch {
    $rec.errors += "$_"
  }
  if ($rec.errors.Count -and -not $rec.docscan -and -not $rec.yara_file_matches.Count -and $rec.verdict -eq "INFO") {
    $rec.verdict = "ERROR"
  }

  $json = $rec | ConvertTo-Json -Depth 8 -Compress
  [IO.File]::AppendAllText($Result, $json + "`n", $utf8)

  $what = @()
  if ($rec.docscan) { $what += ($rec.docscan.findings -join ",") }
  if ($rec.yara_file_matches.Count) { $what += "yara:" + ($rec.yara_file_matches -join ",") }
  if ($rec.disarm) { $what += "disarm:" + $rec.disarm }
  $lvl = switch ($rec.verdict) { "HIGH" { "HIT" } "MEDIUM" { "HIT" } "ERROR" { "ERROR" } "SKIPPED" { "WARN" } default { "OK" } }
  Log ("{0,-7} {1,-8} {2}  {3}" -f $rec.verdict, $cat, $path, ($what -join " | ")) $lvl
}

# ---------- старт ----------
New-Item -ItemType Directory -Force $OutDir | Out-Null
foreach ($p in $Yara, $DocRules, $FileRules) {
  if (-not (Test-Path $p)) { Write-Host "НЕ ЗНАЙДЕНО: $p" -ForegroundColor Red; exit 1 }
}
# перевірка, що обидва набори правил компілюються (інакше кожен скан мовчки падатиме)
$probe = Join-Path $OutDir "probe.txt"; "probe" | Set-Content $probe
foreach ($r in $DocRules, $FileRules) {
  $e = & $Yara -w $r $probe 2>&1 | Where-Object { "$_" -match 'error' }
  if ($e) { Write-Host "Правила не компілюються: $r`n$e" -ForegroundColor Red; exit 1 }
}
Remove-Item $probe

$watchers = @()
foreach ($wp in $WatchPath) {
  if (-not (Test-Path $wp)) { Log "немає теки для спостереження: $wp" "WARN"; continue }
  $w = New-Object IO.FileSystemWatcher $wp, "*"
  $w.IncludeSubdirectories = $true
  $w.NotifyFilter = [IO.NotifyFilters]'FileName, LastWrite, Size'
  $w.InternalBufferSize = 65536
  $i = $watchers.Count
  foreach ($ev in "Created", "Changed", "Renamed") {
    Register-ObjectEvent $w $ev -SourceIdentifier "docscan.$i.$ev" | Out-Null
  }
  Register-ObjectEvent $w Error -SourceIdentifier "docscan.$i.Error" | Out-Null
  $w.EnableRaisingEvents = $true
  $watchers += $w
}
if (-not $watchers.Count) { Log "жодної теки для спостереження" "ERROR"; exit 1 }

Log ("старт: стежу за {0} | disarm={1} | результат: {2}" -f ($WatchPath -join ", "), [bool]$Disarm, $Result)

$pending = @{}   # path -> @{ t = час останньої події; evt = тип першої події }
$recent  = @{}   # path -> sha256 останнього скану (щоб не дублювати Changed після того ж вмісту)

try {
  while ($true) {
    $e = Wait-Event -Timeout 1
    while ($e) {
      $sid = $e.SourceIdentifier
      if ($sid -like "*.Error") {
        Log ("FileSystemWatcher error (можливо переповнення буфера, частина подій втрачена): " + $e.SourceEventArgs.GetException().Message) "ERROR"
      } else {
        $path = $e.SourceEventArgs.FullPath
        $type = "$($e.SourceEventArgs.ChangeType)"
        if ((Get-Category $path) -and -not (Test-Excluded $path)) {
          if ($pending.ContainsKey($path)) { $pending[$path].t = Get-Date }
          else { $pending[$path] = @{ t = Get-Date; evt = $type } }
        }
      }
      Remove-Event -EventIdentifier $e.EventIdentifier
      $e = Get-Event | Select-Object -First 1
    }

    $now = Get-Date
    foreach ($path in @($pending.Keys)) {
      if (($now - $pending[$path].t).TotalSeconds -lt $SettleSeconds) { continue }
      $evt = $pending[$path].evt
      $pending.Remove($path)
      if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
      # той самий вміст уже скановано — пропускаємо (Word/провідник шлють кілька Changed поспіль)
      try { $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -EA Stop).Hash } catch { $h = $null }
      if ($h -and $recent[$path] -eq $h) { continue }
      Scan-File $path $evt
      try { $recent[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -EA Stop).Hash } catch { $recent.Remove($path) }
    }
    if ($recent.Count -gt 5000) { $recent.Clear() }
  }
} finally {
  Get-EventSubscriber | Where-Object SourceIdentifier -like "docscan.*" | Unregister-Event
  $watchers | ForEach-Object { $_.EnableRaisingEvents = $false; $_.Dispose() }
  Log "зупинено"
}
