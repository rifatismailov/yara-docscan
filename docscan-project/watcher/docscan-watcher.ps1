# DocScan watcher — стежить за новими файлами (FileSystemWatcher) і сканує їх yara64.exe.
#
# Один запуск на файл:  yara64 -w --docscan-json [--docscan-disarm] -C rules.yarc <file>
#   (rules.yarc компілюється з docscan-index.yar один раз на старті)
#   docscan-index.yar = docscan-policy.yar (що вважати HIGH/MEDIUM, що лікувати)
#                     + file-index.yar     (vendor-правила: по файлу і по розпакованому VBA)
#
# Категорії файлів:
#   document — Office (і надбудови) / RTF / PDF / LNK / OneNote / IQY / SLK: модуль + політика
#              + vendor, зокрема документні правила (yara_doc_matches); ЛІКУВАННЯ ЗА ПОЛІТИКОЮ (за замовч.)
#   general  — exe/dll/xll/скрипти/hta/msc/url/HTML/SVG/архіви/образи: vendor-правила; документні
#              правила тут лише індикатори (шаблони шелкоду — звичайний код у будь-якому бінарнику)
#
# Результат: один JSON на рядок у $OutDir\docscan-results.json (у майбутньому забиратиме Wazuh:
# <localfile><log_format>json</log_format>). Діагностика роботи — $OutDir\watcher.log.
#
# Запуск (PowerShell від адміністратора, щоб бачити файли всіх користувачів):
#   powershell -ExecutionPolicy Bypass -File docscan-watcher.ps1
#   powershell -ExecutionPolicy Bypass -File docscan-watcher.ps1 -WatchPath C:\docscan-build\inbox -NoDisarm   (тільки детект)
# Зупинка: Ctrl+C.

param(
  [string[]]$WatchPath = @("C:\Users"),
  [string]$Base        = "C:\docscan-build",
  [string]$Yara        = "",
  [string]$Yarac       = "",       # за замовч. yarac64.exe поруч із yara64.exe; ним правила компілюються раз на старті
  [string]$Rules       = "",       # за замовчуванням <Base>\yara\docscan-project\rules\docscan-index.yar
  [string]$OutDir      = "",
  [switch]$NoDisarm,               # НЕ лікувати (діагностика). За замовчуванням документи лікуються за meta.disarm
  [string]$BackupDir   = "",       # бекапи й карантин (за замовч. <Base>\quarantine); watcher її не сканує
  [switch]$QuarantineGeneral,      # general-файли (exe/скрипти/архіви) зі збігом vendor-правил -> у карантин
  [int]$MaxLogMB       = 50,       # ротація docscan-results.json і watcher.log
  [int]$KeepLogs       = 5,
  [int]$MaxSizeMB      = 100,      # більші файли пропускаємо (запис у лог)
  [int]$SettleSeconds  = 2,        # скільки чекати тиші після останньої події по файлу
  [int]$ReadyTimeout   = 60,       # скільки чекати, поки файл перестане записуватись
  [string[]]$DocExt = @(
    ".doc",".dot",".docx",".docm",".dotx",".dotm",
    ".xls",".xlt",".xlsx",".xlsm",".xltx",".xltm",".xlsb",
    ".ppt",".pps",".pot",".pptx",".pptm",".potx",".potm",".ppsx",".ppsm",
    ".xla",".xlam",".ppa",".ppam",                 # надбудови Excel / PowerPoint (макроси при відкритті)
    ".rtf",".pdf",".lnk",
    ".one",                                         # OneNote: вкладені скрипти/exe
    ".iqy",".slk"),                                 # Excel Web Query / SYLK: тягнуть дані, виконують DDE
  [string[]]$GenExt = @(
    ".exe",".dll",".sys",".scr",".cpl",".ocx",".com",".msi",
    ".ps1",".psm1",".vbs",".vbe",".js",".jse",".wsf",".wsh",".hta",".bat",".cmd",".jar",
    ".xll",                                         # надбудова Excel = DLL
    ".msc",                                         # консоль MMC (GrimResource)
    ".url",                                         # Internet Shortcut
    ".svg",".htm",".html",                          # HTML smuggling
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
if (-not $Yarac)     { $Yarac     = Join-Path (Split-Path $Yara) "yarac64.exe" }
if (-not $Rules)     { $Rules     = "$Base\yara\docscan-project\rules\docscan-index.yar" }
if (-not $OutDir)    { $OutDir    = "$Base\results" }
if (-not $BackupDir) { $BackupDir = "$Base\quarantine" }

[Console]::OutputEncoding = [Text.Encoding]::UTF8   # вивід yara64 (шляхи, докази) — UTF-8
$utf8   = New-Object Text.UTF8Encoding($false)
$Result = Join-Path $OutDir "docscan-results.json"
$LogF   = Join-Path $OutDir "watcher.log"
$DocSet = @{}; $DocExt | % { $DocSet[$_.ToLower()] = 1 }
$GenSet = @{}; $GenExt | % { $GenSet[$_.ToLower()] = 1 }

# Ротація: file -> file.1 -> ... -> file.$KeepLogs (найстаріший видаляється).
function Rotate-IfBig([string]$file) {
  if (-not (Test-Path -LiteralPath $file)) { return }
  if ((Get-Item -LiteralPath $file).Length -lt $MaxLogMB * 1MB) { return }
  for ($k = $KeepLogs - 1; $k -ge 1; $k--) {
    if (Test-Path -LiteralPath "$file.$k") { Move-Item -LiteralPath "$file.$k" "$file.$($k + 1)" -Force }
  }
  Move-Item -LiteralPath $file "$file.1" -Force
}

function Log([string]$msg, [string]$level = "INFO") {
  Rotate-IfBig $LogF
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
  if ($path.StartsWith($BackupDir, [StringComparison]::OrdinalIgnoreCase)) { return $true }
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

# Один запуск yara64: JSON (політика + vendor) і, для документів, дія лікування.
function Invoke-Scan([string]$path, [bool]$cure) {
  $yargs = @("-w", "--docscan-json")
  if ($cure) { $yargs += @("--docscan-disarm", "--docscan-backup-dir=$BackupDir") }
  $out = & $Yara @yargs @RuleArgs $path 2>&1 | ForEach-Object { "$_" }
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
    # НЕ 'file': у індексах Wazuh data.file — keyword, об'єкт там індексатор відкидає (mapper_parsing_exception)
    docfile   = [ordered]@{ path = $path; name = [IO.Path]::GetFileName($path);
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
    $rec.docfile.size = $fi.Length
    if ($fi.Length -gt $MaxSizeMB * 1MB) {
      $rec.verdict = "SKIPPED"; $rec.errors += "size > ${MaxSizeMB}MB"
    } else {
      $rec.docfile.sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLower()

      # vendor-правила бачать байти ДО лікування: yara збирає збіги до --docscan-disarm
      $ds = Invoke-Scan $path ((-not $NoDisarm) -and $cat -eq "document")
      $rec.errors += $ds.errors
      if ($ds.docscan) {
        $rec.docscan = $ds.docscan
        $rec.disarm  = $ds.disarm
        $rec.yara_file_matches = @($ds.docscan.yara_file_matches)
        # документні правила (тег docscan_doc) — детект лише для документів
        if ($cat -eq "document") { $rec.yara_file_matches += @($ds.docscan.yara_doc_matches | ? { $_ }) }
        $rec.verdict = $ds.docscan.verdict
      }
      # vendor-правило на самому файлі: документ — щонайменше MEDIUM, general — HIGH
      if ($rec.yara_file_matches.Count) {
        if ($cat -eq "document") { $rec.verdict = Max-Verdict $rec.verdict "MEDIUM" }
        else { $rec.verdict = "HIGH" }
      }
      # general-файл зі збігом vendor-правил: опційний карантин (копія -> BackupDir, оригінал видаляється)
      if ($QuarantineGeneral -and -not $NoDisarm -and $cat -eq "general" -and $rec.yara_file_matches.Count) {
        $i = 0
        do { $dst = Join-Path $BackupDir ("{0}.{1}.docscan-bak" -f [IO.Path]::GetFileName($path), $i++) } while (Test-Path -LiteralPath $dst)
        try { Copy-Item -LiteralPath $path $dst -ErrorAction Stop; Remove-Item -LiteralPath $path -Force -ErrorAction Stop; $rec.disarm = "quarantined" }
        catch { $rec.errors += "quarantine failed: $_"; $rec.disarm = "failed:quarantine" }
      }
    }
  } catch {
    $rec.errors += "$_"
  }
  if ($rec.errors.Count -and -not $rec.docscan -and -not $rec.yara_file_matches.Count -and $rec.verdict -eq "INFO") {
    $rec.verdict = "ERROR"
  }

  $json = $rec | ConvertTo-Json -Depth 8 -Compress
  Rotate-IfBig $Result
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
New-Item -ItemType Directory -Force $BackupDir | Out-Null
foreach ($p in $Yara, $Rules) {
  if (-not (Test-Path $p)) { Write-Host "НЕ ЗНАЙДЕНО: $p" -ForegroundColor Red; exit 1 }
}
# перевірка, що правила компілюються (інакше кожен скан мовчки падатиме)
$probe = Join-Path $OutDir "probe.txt"; "probe" | Set-Content $probe
$e = & $Yara -w --file-vars $Rules $probe 2>&1 | Where-Object { "$_" -match 'error' }
Remove-Item $probe
if ($e) { Write-Host "Правила не компілюються: $Rules`n$e" -ForegroundColor Red; exit 1 }

# Правила компілюються ОДИН раз (yarac64 -> rules.yarc), далі кожен скан іде з -C. Тисячі вендорних
# правил компілюються ~0.5 с і довше — робити це на кожен файл означало б секунди на скан.
# Змінні filename/filepath/extension/filetype/owner оголошуються тут, значення yara64 ставить на кожен файл.
$RuleArgs = @($Rules)
$Compiled = Join-Path $OutDir "rules.yarc"
if (Test-Path $Yarac) {
  Remove-Item $Compiled -ErrorAction SilentlyContinue
  $ce = & $Yarac -w -d filename= -d filepath= -d extension= -d filetype= -d owner= $Rules $Compiled 2>&1 | ForEach-Object { "$_" }
  if ($LASTEXITCODE -eq 0 -and (Test-Path $Compiled)) { $RuleArgs = @("-C", $Compiled) }
  else { Log ("yarac64 не скомпілював правила, скануємо з вихідних .yar (повільніше): " + ($ce -join " ")) "WARN" }
} else {
  Log "немає $Yarac — скануємо з вихідних .yar (кожен скан компілює правила заново)" "WARN"
}

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

Log ("старт: стежу за {0} | disarm={1} | карантин: {2} | результат: {3}" -f ($WatchPath -join ", "), (-not $NoDisarm), $BackupDir, $Result)

$pending = @{}   # path -> @{ t = час останньої події; evt = тип першої події }
$rescanAt = $null   # після переповнення буфера: коли доскановувати
$rescanFrom = $null # ... файли, змінені з цього моменту
$recent  = @{}   # path -> sha256 останнього скану (щоб не дублювати Changed після того ж вмісту)

try {
  while ($true) {
    $e = Wait-Event -Timeout 1
    while ($e) {
      $sid = $e.SourceIdentifier
      if ($sid -like "*.Error") {
        Log ("FileSystemWatcher error (можливо переповнення буфера, частина подій втрачена): " + $e.SourceEventArgs.GetException().Message) "ERROR"
        # події втрачено -> через хвилину пройдемося по теках і візьмемо файли, змінені з цього часу
        if (-not $rescanFrom) { $rescanFrom = (Get-Date).AddMinutes(-1) }
        $rescanAt = (Get-Date).AddSeconds(60)
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
    if ($rescanAt -and $now -ge $rescanAt) {
      $n = 0
      foreach ($wp in $WatchPath) {
        Get-ChildItem -LiteralPath $wp -Recurse -File -Force -ErrorAction SilentlyContinue |
          Where-Object { $_.LastWriteTime -ge $rescanFrom -and (Get-Category $_.FullName) -and -not (Test-Excluded $_.FullName) } |
          ForEach-Object { if (-not $pending.ContainsKey($_.FullName)) { $pending[$_.FullName] = @{ t = $now.AddSeconds(-$SettleSeconds); evt = "Rescan" }; $n++ } }
      }
      Log ("доскановування після переповнення: файлів змінених з {0:HH:mm:ss} — {1}" -f $rescanFrom, $n) "WARN"
      $rescanAt = $null; $rescanFrom = $null
    }
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
