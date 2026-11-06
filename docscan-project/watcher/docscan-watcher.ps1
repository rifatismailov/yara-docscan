# DocScan watcher - watches for new files (FileSystemWatcher) and scans them with yara64.exe.
#
# One run per file:  yara64 -w --docscan-json [--docscan-disarm] -C rules.yarc <file>
#   (rules.yarc is compiled from docscan-index.yar once at start)
#   docscan-index.yar = docscan-policy.yar (what counts as HIGH/MEDIUM, what to disarm)
#                     + file-index.yar     (vendor rules: on the file and on the extracted VBA)
#
# File categories:
#   document - Office (and add-ins) / RTF / PDF / LNK / OneNote / IQY / SLK: module + policy
#              + vendor, including the document rules (yara_doc_matches); DISARM BY POLICY (default)
#   general  - exe/dll/xll/scripts/hta/msc/url/HTML/SVG/archives/images: vendor rules; the document
#              rules are only indicators here (shellcode patterns are ordinary code in any binary)
#
# Output: one JSON per line in $OutDir\docscan-results.json (read by the Wazuh agent:
# <localfile><log_format>json</log_format>). Operational log - $OutDir\watcher.log.
#
# Run (PowerShell as Administrator, to see the files of all users):
#   powershell -ExecutionPolicy Bypass -File docscan-watcher.ps1
#   powershell -ExecutionPolicy Bypass -File docscan-watcher.ps1 -WatchPath C:\docscan-build\inbox -NoDisarm   (detect only)
# Stop: Ctrl+C.

param(
  [string[]]$WatchPath = @("C:\Users"),
  [string]$Base        = "C:\docscan-build",
  [string]$Yara        = "",
  [string]$Yarac       = "",       # default: yarac64.exe next to yara64.exe; compiles the rules once at start
  [string]$Rules       = "",       # default <Base>\yara\docscan-project\rules\docscan-index.yar
  [string]$OutDir      = "",
  [switch]$NoDisarm,               # do NOT disarm (diagnostics). By default documents are disarmed per meta.disarm
  [string]$BackupDir   = "",       # backups and quarantine (default <Base>\quarantine); the watcher does not scan it
  [switch]$QuarantineGeneral,      # general files (exe/scripts/archives) matching vendor rules -> quarantine
  [int]$MaxLogMB       = 50,       # rotation of docscan-results.json and watcher.log
  [int]$KeepLogs       = 5,
  [int]$MaxSizeMB      = 100,      # larger files are skipped (logged)
  [int]$SettleSeconds  = 2,        # quiet time to wait after the last event for a file
  [int]$ReadyTimeout   = 60,       # how long to wait for a file to stop being written
  [int]$RescanCooldown = 60,       # the same file again - at most once per N s (Word/OneDrive autosave)
  [int]$DisarmRetryMinutes = 60,   # file open (locked): retry every 30 s for the first N min, then every 5 min (no end)
  [double]$DisarmNoticeHours = 24,   # file open this long - a separate Wazuh record (DisarmPending), retries go on
  [string]$MacroDir    = "",       # extracted VBA code of documents with macros (default <OutDir>\..\macros)
  [string]$MacroUpload = "",       # also upload it: POST to this collector URL (e.g. http://<server>:8080)
  [int]$MacroKeepDays  = 90,       # local retention of the macro store: older files are deleted ...
  [int]$MacroMaxMB     = 500,      # ... and the oldest go first when the store is bigger than this
  [string[]]$DocExt = @(
    ".doc",".dot",".docx",".docm",".dotx",".dotm",
    ".xls",".xlt",".xlsx",".xlsm",".xltx",".xltm",".xlsb",
    ".ppt",".pps",".pot",".pptx",".pptm",".potx",".potm",".ppsx",".ppsm",
    ".xla",".xlam",".ppa",".ppam",                 # Excel / PowerPoint add-ins (macros on open)
    ".rtf",".pdf",".lnk",
    ".one",                                         # OneNote: embedded scripts/exe
    ".iqy",".slk"),                                 # Excel Web Query / SYLK: pull data, run DDE
  [string[]]$GenExt = @(
    ".exe",".dll",".sys",".scr",".cpl",".ocx",".com",".msi",
    ".ps1",".psm1",".vbs",".vbe",".js",".jse",".wsf",".wsh",".hta",".bat",".cmd",".jar",
    ".xll",                                         # Excel add-in = DLL
    ".msc",                                         # MMC console (GrimResource)
    ".url",                                         # Internet Shortcut
    ".svg",".htm",".html",                          # HTML smuggling
    ".zip",".rar",".7z",".iso",".img",".vhd",".vhdx"),
  # paths (regex) that are not scanned: browser caches, Recent (a .lnk for every opened file), etc.
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
if (-not $MacroDir)  { $MacroDir  = Join-Path (Split-Path $OutDir) "macros" }
$MacroUpload = $MacroUpload.TrimEnd('/')

[Console]::OutputEncoding = [Text.Encoding]::UTF8   # yara64 output (paths, evidence) is UTF-8
$utf8   = New-Object Text.UTF8Encoding($false)
$Result = Join-Path $OutDir "docscan-results.json"
$LogF   = Join-Path $OutDir "watcher.log"
$DocSet = @{}; $DocExt | % { $DocSet[$_.ToLower()] = 1 }
$GenSet = @{}; $GenExt | % { $GenSet[$_.ToLower()] = 1 }

# Rotation: file -> file.1 -> ... -> file.$KeepLogs (the oldest is deleted).
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
  if ($path.StartsWith($MacroDir, [StringComparison]::OrdinalIgnoreCase)) { return $true }
  foreach ($p in $ExcludePattern) { if ($path -match $p) { return $true } }
  return $false
}

# A file is ready when it can be opened for reading and its size does not change.
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

# One yara64 run: JSON (policy + vendor) and, for documents, the disarm action.
# For a document the decompressed VBA is written to $MacroTmp (yara writes it only when there are macros,
# and before any disarm, so the original code is kept).
function Invoke-Scan([string]$path, [bool]$cure, [bool]$extract) {
  $yargs = @("-w", "--docscan-json")
  if ($cure) { $yargs += @("--docscan-disarm", "--docscan-backup-dir=$BackupDir") }
  if ($extract) { Remove-Item -LiteralPath $MacroTmp -Force -EA SilentlyContinue; $yargs += "--docscan-extract=$MacroTmp" }
  $out = & $Yara @yargs @RuleArgs $path 2>&1 | ForEach-Object { "$_" }
  $json = $out | Where-Object { $_ -like '{*' } | Select-Object -First 1
  $act  = $out | Where-Object { $_ -like 'docscan-disarm:*' } | Select-Object -First 1
  $errs = @($out | Where-Object { $_ -match '^error' })
  $obj  = $null
  if ($json) { try { $obj = $json | ConvertFrom-Json } catch { $errs += "bad docscan json: $json" } }
  if ($act) { $act = $act -replace '^docscan-disarm: .* -> ', '' }
  return @{ docscan = $obj; disarm = $act; errors = $errs }
}

# ---- macro store: <MacroDir>\<document sha256>.vba.txt (one file per document content) ----
# The file starts with a short header (VBA comment lines, UTF-8): host, document path, sha256, findings,
# time - so a copy on the collector is self-describing. Then the VBA code as yara extracted it (the
# project's code page, usually 1251). Sent files are listed in <MacroDir>\sent.txt (one sha256 per line);
# the rest is retried hourly by Sync-Macros. (Not the Archive attribute: re-applying the folder ACL on a
# reinstall sets it again, and every macro would be sent again.)
function Save-Macro([string]$docSha, $rec, $ds) {
  if (-not (Test-Path -LiteralPath $MacroTmp)) { return $null }
  $len = (Get-Item -LiteralPath $MacroTmp).Length
  $dst = Join-Path $MacroDir "$docSha.vba.txt"
  if ($len -eq 0 -or (Test-Path -LiteralPath $dst)) {
    Remove-Item -LiteralPath $MacroTmp -Force -EA SilentlyContinue
    if ($len -eq 0) { return $null }
  } else {
    $hdr = "' DocScan macro`r`n' host: $env:COMPUTERNAME`r`n' file: $($rec.docfile.path)`r`n' sha256: $docSha`r`n" +
           "' findings: $(@($ds.findings) -join ', ')`r`n' saved: $((Get-Date).ToString('yyyy-MM-ddTHH:mm:sszzz'))`r`n'`r`n"
    $bytes = [byte[]]($utf8.GetBytes($hdr) + [IO.File]::ReadAllBytes($MacroTmp))
    [IO.File]::WriteAllBytes($dst, $bytes)
    Remove-Item -LiteralPath $MacroTmp -Force -EA SilentlyContinue
  }
  return [ordered]@{ file = $dst; size = $len; uploaded = $false }
}

# POST the stored file (header + code) to the collector, e.g. http://<server>:8080/
function Send-Macro([string]$file) {
  if (-not $MacroUpload) { return $false }
  $fi = Get-Item -LiteralPath $file -EA SilentlyContinue
  if (-not $fi) { return $false }
  $sha = $fi.Name -replace '\.vba\.txt$', ''
  if ($MacroSentSet.ContainsKey($sha)) { return $true }   # already sent
  try {
    $null = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$MacroUpload/" -Body ([IO.File]::ReadAllBytes($file)) `
              -ContentType "application/octet-stream" -TimeoutSec 15 -ErrorAction Stop
    $MacroSentSet[$sha] = 1
    [IO.File]::AppendAllText($MacroSent, "$sha`r`n", $utf8)
    return $true
  } catch {
    Log "macro upload failed (will retry): $($fi.Name) - $($_.Exception.Message)" "WARN"
    return $false
  }
}

# Retention + upload retry. Runs at start and then once an hour.
function Sync-Macros {
  $files = @(Get-ChildItem -LiteralPath $MacroDir -Filter *.vba.txt -File -EA SilentlyContinue | Sort-Object LastWriteTime)
  $limit = (Get-Date).AddDays(-$MacroKeepDays)
  $total = ($files | Measure-Object Length -Sum).Sum
  $kept = @()
  foreach ($f in $files) {
    if ($f.LastWriteTime -lt $limit -or $total -gt $MacroMaxMB * 1MB) {
      $total -= $f.Length; Remove-Item -LiteralPath $f.FullName -Force -EA SilentlyContinue
    } else { $kept += $f }
  }
  # sent.txt keeps only the files that are still in the store
  $keep = @{}; foreach ($f in $kept) { $keep[($f.Name -replace '\.vba\.txt$', '')] = 1 }
  $stale = @($MacroSentSet.Keys | Where-Object { -not $keep.ContainsKey($_) })
  if ($stale.Count) {
    foreach ($k in $stale) { $MacroSentSet.Remove($k) }
    [IO.File]::WriteAllText($MacroSent, (($MacroSentSet.Keys | ForEach-Object { "$_`r`n" }) -join ""), $utf8)
  }
  if ($MacroUpload) {
    # one per second at most: the collector names files <ip>_<yyyyMMdd_HHmmss>.txt
    foreach ($f in $kept) {
      if ($MacroSentSet.ContainsKey(($f.Name -replace '\.vba\.txt$', ''))) { continue }
      if (-not (Send-Macro $f.FullName)) { break }
      Start-Sleep -Milliseconds 1100
    }
  }
}

# Human-readable description: policy rule texts (meta.text), vendor rule descriptions (meta.description),
# rules on the VBA code, the disarm action. Capped at 600 characters (Wazuh alert description).
function Get-Summary($rec) {
  $p = @()
  $ds = $rec.docscan
  if ($rec.event -eq "DisarmPending") { $p += "Disarm not done in $DisarmNoticeHours h: the file is still open in another program - manual check needed" }
  if ($ds -and $ds.findings_text) { $p += @($ds.findings_text) }
  # where it was found: a document part (second pass) or the macro code
  $where = @{}
  if ($ds) {
    foreach ($pm in @($ds.yara_part_matches)) { if ($pm) { foreach ($r in @($pm.rules)) { if (-not $where[$r]) { $where[$r] = $pm.part } } } }
    foreach ($r in @($ds.yara_matches)) { if ($r -and -not $where[$r]) { $where[$r] = "macro code" } }
  }
  foreach ($m in $rec.yara_file_matches) {
    $d = $null
    if ($ds -and $ds.yara_descriptions) { $d = (@($ds.yara_descriptions) | Where-Object { $_.rule -eq $m } | Select-Object -First 1).description }
    $t = "YARA $m"
    if ($where[$m]) { $t += " (in " + $where[$m] + ")" }
    if ($d) { $t += " - $d" }
    $p += $t
  }
  if ($rec.disarm) { $p += "action: " + $rec.disarm }
  if ($rec.verdict -eq "SKIPPED" -or $rec.verdict -eq "ERROR") { $p += ($rec.errors -join "; ") }
  $t = ($p -join " | ")
  if ($t.Length -gt 600) { $t = $t.Substring(0, 597) + "..." }
  return $t
}

$Rank = @{ INFO = 0; MEDIUM = 1; HIGH = 2 }
function Max-Verdict($a, $b) { if ($Rank[$b] -gt $Rank[$a]) { $b } else { $a } }

function Scan-File([string]$path, [string]$evt) {
  $cat = Get-Category $path
  $state = Wait-FileReady $path
  if ($state -eq "gone") { Log "gone before scan: $path" "WARN"; return $null }

  $rec = [ordered]@{
    timestamp = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")
    source    = "docscan"
    host      = $env:COMPUTERNAME
    event     = $evt
    category  = $cat
    # NOT 'file': in the Wazuh indices data.file is a keyword, the indexer rejects an object there (mapper_parsing_exception)
    docfile   = [ordered]@{ path = $path; name = [IO.Path]::GetFileName($path);
                            ext = [IO.Path]::GetExtension($path).ToLower(); size = $null; sha256 = $null }
    verdict   = "INFO"
    docscan   = $null
    yara_file_matches = @()
    disarm    = $null
    macro     = $null  # saved VBA code: @{ file; size; uploaded } (documents with macros)
    summary   = ""     # human-readable: what was found and what was done (for the Wazuh alert description)
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

      # vendor rules see the bytes BEFORE disarm: yara collects the matches before --docscan-disarm
      $ds = Invoke-Scan $path ((-not $NoDisarm) -and $cat -eq "document") ($cat -eq "document")
      $rec.errors += $ds.errors
      if ($cat -eq "document") {
        $mc = Save-Macro $rec.docfile.sha256 $rec $ds.docscan
        if ($mc) { $mc.uploaded = Send-Macro $mc.file; $rec.macro = $mc }
      }
      if ($ds.docscan) {
        $rec.docscan = $ds.docscan
        $rec.disarm  = $ds.disarm
        $rec.yara_file_matches = @($ds.docscan.yara_file_matches)
        # document rules (tag docscan_doc) - detection only for documents; the same for the second
        # pass: matches in the extracted document parts and in the macro code
        if ($cat -eq "document") {
          $rec.yara_file_matches += @($ds.docscan.yara_doc_matches | ? { $_ })
          foreach ($pm in @($ds.docscan.yara_part_matches)) { if ($pm) { $rec.yara_file_matches += @($pm.rules) } }
          $rec.yara_file_matches += @($ds.docscan.yara_matches | ? { $_ })
          $rec.yara_file_matches = @($rec.yara_file_matches | Select-Object -Unique)
        }
        $rec.verdict = $ds.docscan.verdict
      }
      # vendor rule on the file itself: document - at least MEDIUM, general - HIGH
      if ($rec.yara_file_matches.Count) {
        if ($cat -eq "document") { $rec.verdict = Max-Verdict $rec.verdict "MEDIUM" }
        else { $rec.verdict = "HIGH" }
      }
      # general file matching vendor rules: optional quarantine (copy -> BackupDir, the original is deleted)
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
  $rec.summary = Get-Summary $rec

  # The same result as last time for this path (the user saves the document, the content changed,
  # but the verdict and findings did not) - not written for Wazuh, only to the local log. HIGH is always written.
  $key = "$($rec.verdict)|$($rec.summary)"
  $repeat = ($rec.verdict -ne "HIGH" -and $LastKey[$path] -eq $key)
  if (-not $repeat) {
    $json = $rec | ConvertTo-Json -Depth 8 -Compress
    Rotate-IfBig $Result
    [IO.File]::AppendAllText($Result, $json + "`n", $utf8)
    $LastKey[$path] = $key
  }

  $what = @()
  if ($rec.docscan) { $what += ($rec.docscan.findings -join ",") }
  if ($rec.yara_file_matches.Count) { $what += "yara:" + ($rec.yara_file_matches -join ",") }
  if ($rec.disarm) { $what += "disarm:" + $rec.disarm }
  $lvl = switch ($rec.verdict) { "HIGH" { "HIT" } "MEDIUM" { "HIT" } "ERROR" { "ERROR" } "SKIPPED" { "WARN" } default { "OK" } }
  if ($repeat) { $what += "(unchanged - not written for Wazuh)" }
  Log ("{0,-7} {1,-8} {2}  {3}" -f $rec.verdict, $cat, $path, ($what -join " | ")) $lvl
  return $rec
}

# The file is open in another process without shared write (Word holds the document) - disarm is not possible now.
function Test-FileLocked([string]$path) {
  try { $fs = [IO.File]::Open($path, 'Open', 'ReadWrite', 'None'); $fs.Close(); return $false }
  catch { return (Test-Path -LiteralPath $path -PathType Leaf) }
}

# ---------- start ----------
New-Item -ItemType Directory -Force $OutDir | Out-Null
New-Item -ItemType Directory -Force $BackupDir | Out-Null
New-Item -ItemType Directory -Force $MacroDir | Out-Null
$MacroTmp = Join-Path $MacroDir "extract.tmp"
$MacroSent = Join-Path $MacroDir "sent.txt"
$MacroSentSet = @{}
if (Test-Path -LiteralPath $MacroSent) {
  foreach ($l in [IO.File]::ReadAllLines($MacroSent, $utf8)) { if ($l -match '^[0-9a-f]{64}$') { $MacroSentSet[$l] = 1 } }
} elseif (Test-Path -LiteralPath $MacroDir) {
  # first start of this version: files the previous version already sent (Archive cleared) count as sent
  foreach ($f in Get-ChildItem -LiteralPath $MacroDir -Filter *.vba.txt -File -EA SilentlyContinue) {
    if (-not ($f.Attributes -band [IO.FileAttributes]::Archive)) { $MacroSentSet[($f.Name -replace '\.vba\.txt$', '')] = 1 }
  }
  [IO.File]::WriteAllText($MacroSent, (($MacroSentSet.Keys | ForEach-Object { "$_`r`n" }) -join ""), $utf8)
}
foreach ($p in $Yara, $Rules) {
  if (-not (Test-Path $p)) { Write-Host "NOT FOUND: $p" -ForegroundColor Red; exit 1 }
}
# check that the rules compile (otherwise every scan would fail silently)
$probe = Join-Path $OutDir "probe.txt"; "probe" | Set-Content $probe
$e = & $Yara -w --file-vars $Rules $probe 2>&1 | Where-Object { "$_" -match 'error' }
Remove-Item $probe
if ($e) { Write-Host "The rules do not compile: $Rules`n$e" -ForegroundColor Red; exit 1 }

# The rules are compiled ONCE (yarac64 -> rules.yarc), then every scan runs with -C. Thousands of vendor
# rules take ~0.5 s or more to compile - doing it for every file would mean seconds per scan.
# The variables filename/filepath/extension/filetype/owner are declared here, yara64 sets the values per file.
$RuleArgs = @($Rules)
$Compiled = Join-Path $OutDir "rules.yarc"
if (Test-Path $Yarac) {
  Remove-Item $Compiled -ErrorAction SilentlyContinue
  $ce = & $Yarac -w -d filename= -d filepath= -d extension= -d filetype= -d owner= $Rules $Compiled 2>&1 | ForEach-Object { "$_" }
  if ($LASTEXITCODE -eq 0 -and (Test-Path $Compiled)) { $RuleArgs = @("-C", $Compiled) }
  else { Log ("yarac64 did not compile the rules, scanning from the source .yar (slower): " + ($ce -join " ")) "WARN" }
} else {
  Log "$Yarac is missing - scanning from the source .yar (every scan recompiles the rules)" "WARN"
}

$watchers = @()
foreach ($wp in $WatchPath) {
  if (-not (Test-Path $wp)) { Log "watch folder does not exist: $wp" "WARN"; continue }
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
if (-not $watchers.Count) { Log "no folder to watch" "ERROR"; exit 1 }

Log ("start: watching {0} | disarm={1} | quarantine: {2} | results: {3}" -f ($WatchPath -join ", "), (-not $NoDisarm), $BackupDir, $Result)
Log ("macros: {0} (keep {1} days / {2} MB) | upload: {3}" -f $MacroDir, $MacroKeepDays, $MacroMaxMB, $(if ($MacroUpload) { $MacroUpload } else { "off" }))
Sync-Macros
$nextMacroSync = (Get-Date).AddHours(1)

$pending = @{}   # path -> @{ t = time of the last event; evt = type of the first event }
$rescanAt = $null   # after a buffer overflow: when to rescan
$rescanFrom = $null # ... the files changed since this moment
$recent  = @{}   # path -> sha256 of the last scan (no duplicate scans for Changed with the same content)
$LastScan = @{}  # path -> time of the last scan (-RescanCooldown pause for repeated changes)
$LastKey  = @{}  # path -> "verdict|summary" of the last Wazuh record (identical repeats are not written)
$Retry    = @{}  # path -> @{ next; since; noticed } - disarm of a locked file is retried later
$RetryFile = Join-Path $OutDir "retry.json"   # the same list on disk: survives a restart and a reboot

function Save-Retry {
  $items = @($Retry.Keys | ForEach-Object { [ordered]@{ path = $_; since = $Retry[$_].since.ToString("o"); noticed = [bool]$Retry[$_].noticed } })
  $tmp = "$RetryFile.tmp"
  [IO.File]::WriteAllText($tmp, (ConvertTo-Json -InputObject $items -Depth 3 -Compress), $utf8)
  Move-Item -LiteralPath $tmp $RetryFile -Force
}
function Add-Retry([string]$path) {
  if (-not $Retry.ContainsKey($path)) {
    $Retry[$path] = @{ next = (Get-Date).AddSeconds(30); since = (Get-Date); noticed = $false }
    Log "file is open in another program - disarm will be retried as soon as it is closed: $path" "WARN"
  } else { $Retry[$path].next = (Get-Date).AddSeconds(30) }
  Save-Retry
}
function Remove-Retry([string]$path) {
  if ($Retry.ContainsKey($path)) { $Retry.Remove($path); Save-Retry }
}
# unfinished disarms from the previous run (after a reboot Word no longer holds the file)
if (Test-Path -LiteralPath $RetryFile) {
  try {
    foreach ($it in @(Get-Content -LiteralPath $RetryFile -Raw -Encoding utf8 | ConvertFrom-Json)) {
      if ($it.path -and (Test-Path -LiteralPath $it.path -PathType Leaf)) {
        $Retry[$it.path] = @{ next = Get-Date; since = [datetime]$it.since; noticed = [bool]$it.noticed }
      }
    }
    if ($Retry.Count) { Log ("unfinished disarm from the previous run: {0} file(s)" -f $Retry.Count) "WARN" }
    Save-Retry
  } catch { Log "could not read ${RetryFile}: $_" "ERROR" }
}

try {
  while ($true) {
    $e = Wait-Event -Timeout 1
    while ($e) {
      $sid = $e.SourceIdentifier
      if ($sid -like "*.Error") {
        Log ("FileSystemWatcher error (buffer overflow likely, some events lost): " + $e.SourceEventArgs.GetException().Message) "ERROR"
        # events were lost -> in a minute walk the folders and take the files changed since then
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
      Log ("rescan after overflow: files changed since {0:HH:mm:ss} - {1}" -f $rescanFrom, $n) "WARN"
      $rescanAt = $null; $rescanFrom = $null
    }
    foreach ($path in @($pending.Keys)) {
      if (($now - $pending[$path].t).TotalSeconds -lt $SettleSeconds) { continue }
      # this file was scanned recently (editing with autosave) - wait for the pause, then one scan of the
      # latest version. A new file (not scanned yet) - right away.
      if ($LastScan.ContainsKey($path) -and ($now - $LastScan[$path]).TotalSeconds -lt $RescanCooldown) { continue }
      $evt = $pending[$path].evt
      $pending.Remove($path)
      if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { continue }
      # the same content was already scanned - skip (Word/Explorer send several Changed in a row)
      try { $h = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -EA Stop).Hash } catch { $h = $null }
      if ($h -and $recent[$path] -eq $h) { continue }
      $r = Scan-File $path $evt
      $LastScan[$path] = Get-Date
      try { $recent[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -EA Stop).Hash } catch { $recent.Remove($path) }
      # disarm failed because the file is open (Word) - retry when it is released;
      # a new scan without a failed disarm removes the file from the retry list
      if ($r -and "$($r.disarm)" -like 'failed:*' -and (Test-FileLocked $path)) { Add-Retry $path }
      elseif ($r) { Remove-Retry $path }
    }

    # disarm retry for locked files
    # No end date: every 30 s for the first -DisarmRetryMinutes, then every 5 min. After
    # -DisarmNoticeHours - one Wazuh record (DisarmPending): the SOC has to handle it manually.
    foreach ($path in @($Retry.Keys)) {
      $rt = $Retry[$path]
      if ($now -lt $rt.next) { continue }
      if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { Remove-Retry $path; continue }
      $age = ($now - $rt.since)
      $step = $(if ($age.TotalMinutes -lt $DisarmRetryMinutes) { 30 } else { 300 })
      if (Test-FileLocked $path) {
        $rt.next = $now.AddSeconds($step)
        if (-not $rt.noticed -and $age.TotalHours -ge $DisarmNoticeHours) {
          $rt.noticed = $true; Save-Retry
          Log "disarm not done in $DisarmNoticeHours h - the file is still open: $path" "ERROR"
          $null = Scan-File $path "DisarmPending"   # HIGH + failed:replace -> a separate Wazuh record
          $LastScan[$path] = Get-Date
        }
        continue
      }
      $r = Scan-File $path "DisarmRetry"
      $LastScan[$path] = Get-Date
      try { $recent[$path] = (Get-FileHash -LiteralPath $path -Algorithm SHA256 -EA Stop).Hash } catch { $recent.Remove($path) }
      if ($r -and "$($r.disarm)" -like 'failed:*' -and (Test-FileLocked $path)) { $rt.next = (Get-Date).AddSeconds($step) }
      else {
        if ($r -and "$($r.disarm)" -like 'failed:*') { Log "disarm failed (file not locked): $path - $($r.disarm)" "ERROR" }
        Remove-Retry $path
      }
    }

    if ($now -ge $nextMacroSync) { Sync-Macros; $nextMacroSync = (Get-Date).AddHours(1) }

    if ($recent.Count -gt 5000) { $recent.Clear(); $LastScan.Clear(); $LastKey.Clear() }
  }
} finally {
  Get-EventSubscriber | Where-Object SourceIdentifier -like "docscan.*" | Unregister-Event
  $watchers | ForEach-Object { $_.EnableRaisingEvents = $false; $_.Dispose() }
  Log "stopped"
}
