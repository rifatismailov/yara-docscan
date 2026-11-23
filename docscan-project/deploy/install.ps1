# DocScan - install / update on Windows.
#
# Run (PowerShell AS ADMINISTRATOR, from the unpacked package folder):
#   powershell -ExecutionPolicy Bypass -File .\install.ps1
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -WatchPath 'C:\Users','D:\Shares'
#   powershell -ExecutionPolicy Bypass -File .\install.ps1 -DetectOnly       # pilot: alerts only, files are not changed
#   ... -NoAvExclusion   - do not add Microsoft Defender exclusions (added by default)
#
# What it does:
#   1) verifies the package SHA256SUMS.txt;
#   1b) Microsoft Defender exclusions for -InstallDir and -DataDir (-NoAvExclusion skips); ESET - warning only;
#   2) copies bin\, watcher\, updater\ to -InstallDir (default C:\Program Files\DocScan); the rules come from
#      -Rules (a yara-docscan-rules bundle, with critical\*.yar) or stay as installed;
#   3) creates -DataDir (C:\ProgramData\DocScan): results\, quarantine\, macros\ - access for SYSTEM + Administrators only;
#      macros\ = the VBA code of every document with macros (-MacroUpload: also POSTed to a collector);
#      critical\ = the E5Search queue (critical.json: full text of documents matching the critical rules - critical\*.yar of
#      the rules package, on every PC unless -NoCritical);
#   4) self-test: yara64 starts, the rules compile, a test scan returns JSON;
#   5) FULLY removes the old DocScan (Wazuh active-response): doc-scan.ps1, doc-scan.cmd,
#      <ossec-agent>\tmp\docscan; the old quarantine <ossec-agent>\quarantine is moved to
#      <DataDir>\quarantine\legacy\ (evidence is kept); and the old YARA for active-response
#      (active-response\bin\yara, yara-scan.*) - DocScan's yara64 replaces it. On the Wazuh manager
#      remove <command>/<active-response> for doc-scan and yara-scan;
#   6) Wazuh agent: ossec.conf (backup) - removes <command>/<active-response> doc-scan/yara-scan,
#      adds <localfile> (json) for results\docscan-results.json; restarts WazuhSvc, restores the old
#      ossec.conf on a configuration error;
#   7) registers the Windows service "DocScan Watcher" (DocScanWatcher): automatic start with Windows, as SYSTEM,
#      restarted by Windows after every failure; and starts it. The service is watcher\docscan-watcher.exe (Go:
#      parallel scans, the pool grows with the load - see watcher-go\README.md); -Workers N = a fixed number of
#      parallel scans. -WatcherEngine ps = the old PowerShell script, run by the scheduled task "DocScan Watcher"
#      (a script cannot be a service). A task left by an older version is removed.
#   3b) rules: -Rules <bundle> (signed rules release of yara-docscan-rules, verified by docscan-updater.exe); without
#      -Rules the rules a PC already has from a bundle (rules\VERSION.txt) stay - a program update never replaces
#      them; otherwise the rules of this package (old packages only - packages come without rules); no rules - not installed;
#   8) the update service "DocScan Updater" (DocScanUpdater, updater\docscan-updater.exe): how it updates is in
#      <DataDir>\update\updater.json, written from -UpdateMode (github | mirror | marker | off), -UpdateMirror,
#      -ListsUrl / -ListsKey / -ListsEveryHours (the organisation's signed white / black lists),
#      -UpdateMarker, -UpdateEveryHours, -UpdateWindow (only when given, or on the first install: github); or the whole
#      file at once: -UpdateConfig <updater.json: file, UNC or URL> (the organisation's mirror, keys, lists), checked by
#      docscan-updater -CheckConfig; -Update* / -Lists* given next to it change it. It installs
#      only releases signed by the DocScan CI, never an older version, and rolls back when the new one does not start.
#   9) the web interface "DocScan Web" (DocScanWeb, web\docscan-web.exe): https://127.0.0.1:<-WebPort 8741>/, HTTPS with
#      a certificate made here and trusted by Windows (only 127.0.0.1 / localhost, not a CA), user admin with a
#      generated password (shown once, also in <DataDir>\web\initial-password.txt until the first sign-in). -NoWeb - none.
# Running it again = update (the previous rules are kept in rules.prev\). The parameters of every install are kept in
# <DataDir>\install.json: -Reuse repeats them (the updater runs install.ps1 -Reuse -ResultFile <json>, so the PC keeps
# its mode: -DetectOnly, -WatchPath, -Workers, ...). The installed package stays in <DataDir>\update\packages\<version>
# (current + previous) - the updater rolls back with it.

param(
  # ProgramW6432 = the 64-bit Program Files even when this runs in a 32-bit PowerShell (from a 32-bit cmd / SysWOW64)
  [string]  $InstallDir = "$(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles })\DocScan",
  [string]  $DataDir    = "$env:ProgramData\DocScan",
  [string[]]$WatchPath  = @("C:\Users"),
  [switch]  $QuarantineGeneral,   # exe/scripts/archives matching vendor rules -> quarantine
  [switch]  $NoAvExclusion,       # do NOT add Defender exclusions (if a central policy sets them)
  [switch]  $DetectOnly,          # detection and alerts only: files are NOT disarmed or quarantined (pilot)
  [string]  $MacroUpload = "",    # collector URL for the extracted macro code (POST), e.g. http://<server>:8080; empty - local only
  [switch]  $NoCritical,          # turn the critical-information check off on this PC (the critical rules come with the rules
                                  # package: rules\critical\*.yar; without this switch the check runs on every PC)
  [string]  $Whitelist = "",      # white list of the organisation (whitelist.json) -> <DataDir>\lists\; empty - keep the installed one
  [string]  $Blacklist = "",      # black list of the organisation (blacklist.json) -> <DataDir>\lists\; empty - keep the installed one
  [switch]  $NoWhitelist,         # remove the white list
  [switch]  $NoBlacklist,         # remove the black list
  [switch]  $NoStart,             # register, but do not start now
  [ValidateSet("go", "ps")]
  [string]  $WatcherEngine = "go", # go = docscan-watcher.exe (parallel scans); ps = the old PowerShell script (fallback)
  [int]     $Workers = 0,         # Go watcher: FIXED number of parallel scans; 0 = automatic (2 .. number of CPUs)
  [string]  $OssecDir = "${env:ProgramFiles(x86)}\ossec-agent",
  [switch]  $KeepLegacy,          # do not remove the old DocScan (active-response)
  [switch]  $KeepLegacyYara,      # do NOT remove the old active-response YARA (yara-scan + yara\)
  [switch]  $NoWazuhConfig,       # do not touch the agent's ossec.conf and do not restart WazuhSvc
  [ValidateSet("", "github", "mirror", "marker", "off")]
  [string]  $UpdateMode = "",     # updates: github (default on a new install) | mirror | marker | off; empty - keep updater.json
  [string]  $UpdateConfig = "",   # a ready updater.json (file, UNC or URL): replaces the PC's one; -Update* / -Lists* change it
  [string]  $UpdateMirror = "",   # mode mirror: folder with the release files (https://... or \\server\share\docscan)
  [string]  $UpdateMarker = "",   # mode marker: the file an agent writes (default <DataDir>\update\update.json)
  [double]  $UpdateEveryHours = 0, # github / mirror: how often to check (default 6)
  [string]  $UpdateWindow = "",   # install updates only at this time, e.g. 22:00-06:00
  [string]  $ListsUrl = "",       # the organisation's mirror with signed whitelist.json / blacklist.json (+ .sig): https://... or
                                  # \\server\share\docscan; DocScanUpdater checks it daily. Empty - lists only by hand
  [string[]]$ListsKey = @(),      # public key(s) the organisation signs its lists with (ed25519:..., docscan-updater -NewListKey)
  [double]  $ListsEveryHours = 0, # how often to check the lists (default 24)
  [string]  $ListsToken = "",     # a closed mirror (Forgejo with sign-in, a private repository): read-only token -> lists.token
  [string]  $Rules = "",          # rules bundle from a yara-docscan-rules release (DocScan-rules-bundle.zip: file, UNC or URL; or a
                                  # folder with rules-manifest.json/.sig + DocScan-rules.zip) - verified (CI signature) and installed
  [switch]  $NoWeb,               # no web interface (service DocScanWeb); an installed one is removed
  [int]     $WebPort = 8741,      # web interface: https://127.0.0.1:<port>/ (8740 is Anthophila_Hive's)
  [switch]  $Reuse,               # take the parameters of the previous install (<DataDir>\install.json) - used by the updater
  [string]  $ResultFile = ""      # write {"ok":..,"version":..,"error":..} here at the end (the updater reads it)
)

$ErrorActionPreference = "Stop"
$TaskName = "DocScan Watcher"     # scheduled task: only -WatcherEngine ps (and older versions)
$SvcName  = "DocScanWatcher"      # Windows service: the Go watcher (display name "DocScan Watcher")
$Pkg = $PSScriptRoot

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Write-Result([bool]$ok, [string]$err) {
  if (-not $ResultFile) { return }
  $v = ""
  if (Test-Path "$InstallDir\VERSION.txt") { $v = ([string](Get-Content "$InstallDir\VERSION.txt" -TotalCount 1)) -replace '^.*?(v\d+\.\d+\.\d+).*$', '$1' }
  try { (@{ ok = $ok; version = $v; error = $err } | ConvertTo-Json -Compress) | Set-Content -LiteralPath $ResultFile -Encoding ASCII } catch { }
}
$script:updStopped = $false
function Fail($m) {
  Write-Host "ERROR: $m" -ForegroundColor Red
  Write-Result $false $m
  # the update service was stopped for this install: it must run again - it is the one that rolls back
  if ($script:updStopped -and (Get-Service -Name "DocScanUpdater" -EA SilentlyContinue)) {
    Set-Service -Name "DocScanUpdater" -StartupType Automatic -EA SilentlyContinue
    Start-Service -Name "DocScanUpdater" -EA SilentlyContinue
  }
  exit 1
}
# any other terminating error (a cmdlet under -ErrorAction Stop, a native tool's stderr in PowerShell 5.1) -> Fail,
# so the result file is written and the updater service comes back
trap { Fail "unexpected error: $($_.Exception.Message)" }

# -Reuse: the parameters of the previous install, except the ones given now
$InstallJson = Join-Path $DataDir "install.json"
$prevInstall = $null
if (Test-Path -LiteralPath $InstallJson) { try { $prevInstall = Get-Content -LiteralPath $InstallJson -Raw | ConvertFrom-Json } catch { } }
if ($Reuse) {
  if (-not $prevInstall) { Fail "-Reuse: no $InstallJson (DocScan was not installed by this version of install.ps1)" }
  $p = $prevInstall.params
  foreach ($n in "WatchPath", "MacroUpload", "WatcherEngine", "Workers", "OssecDir", "WebPort") {
    if (-not $PSBoundParameters.ContainsKey($n) -and $null -ne $p.$n -and "$($p.$n)" -ne "") { Set-Variable -Name $n -Value $p.$n }
  }
  foreach ($n in "QuarantineGeneral", "NoAvExclusion", "DetectOnly", "NoWazuhConfig", "KeepLegacy", "KeepLegacyYara", "NoCritical", "NoWeb") {
    if (-not $PSBoundParameters.ContainsKey($n) -and $p.$n) { Set-Variable -Name $n -Value ([switch]$true) }
  }
  $WatchPath = @($WatchPath)
  Write-Host "==> -Reuse: parameters of the install of $($prevInstall.installed)" -ForegroundColor Cyan
}

# -UpdateConfig: read and check it BEFORE anything changes on the PC (step 8 writes it); the package's updater checks
# it the same way the service will (unknown or misspelled keys, bad mode, bad keys)
$UpdCfgObj = $null
if ($UpdateConfig) {
  try {
    $raw = if ($UpdateConfig -match '^https?://') { (Invoke-WebRequest -UseBasicParsing $UpdateConfig -TimeoutSec 60).Content } else { Get-Content -LiteralPath $UpdateConfig -Raw }
    $UpdCfgObj = $raw | ConvertFrom-Json
  } catch { Fail "-UpdateConfig ${UpdateConfig}: cannot read it as JSON - $($_.Exception.Message)" }
  $pkgUpd = Join-Path $Pkg "updater\docscan-updater.exe"
  if (Test-Path -LiteralPath $pkgUpd) {
    $chk = Join-Path $env:TEMP ("docscan-updater-check-" + [guid]::NewGuid() + ".json")
    [IO.File]::WriteAllText($chk, $raw, (New-Object Text.UTF8Encoding($false)))
    $eap = $ErrorActionPreference; $ErrorActionPreference = "Continue"   # the updater's stderr is its answer, not an exception
    $co = @(& $pkgUpd -CheckConfig $chk 2>&1 | % { "$_" }); $rc = $LASTEXITCODE
    $ErrorActionPreference = $eap
    Remove-Item -LiteralPath $chk -Force -EA SilentlyContinue
    if ($rc) { Fail "-UpdateConfig ${UpdateConfig}: docscan-updater -CheckConfig - $($co -join ' ')" }
  }
}

# ---- agent ossec.conf (text edits: the file has several <ossec_config> blocks, it is not one XML document) ----
$DsBegin = "<!-- DocScan: managed by DocScan install.ps1 -->"
$DsEnd   = "<!-- /DocScan -->"
function Remove-DocScanBlock([string]$c) {
  return [regex]::Replace($c, "(?s)[ \t]*" + [regex]::Escape($DsBegin) + ".*?" + [regex]::Escape($DsEnd) + "\r?\n?", "")
}
function Remove-LegacyArBlocks([string]$c) {
  # only the old DocScan/YARA blocks; a generic <active-response><disabled>..</active-response> stays
  # <active-response> first (it contains a nested <command>name</command>), then the <command> definitions with <name>
  $c = [regex]::Replace($c, "(?s)[ \t]*<active-response>(?:(?!</active-response>).)*?(doc-scan|yara-scan)(?:(?!</active-response>).)*?</active-response>\r?\n?", "")
  $c = [regex]::Replace($c, "(?s)[ \t]*<command>(?:(?!</command>).)*?<name>\s*(doc-scan|yara-scan)\s*</name>(?:(?!</command>).)*?</command>\r?\n?", "")
  return $c
}
function Read-Text([string]$p) { return [IO.File]::ReadAllText($p, (New-Object Text.UTF8Encoding($false))) }
function Write-Text([string]$p, [string]$t) { [IO.File]::WriteAllText($p, $t, (New-Object Text.UTF8Encoding($false))) }


# --- 0. administrator rights ---
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Fail "run PowerShell as Administrator" }

# --- 1. package integrity ---
Step "checking package integrity"
$sums = Join-Path $Pkg "SHA256SUMS.txt"
if (-not (Test-Path $sums)) { Fail "SHA256SUMS.txt is missing - the package is incomplete" }
$bad = @()
foreach ($l in Get-Content $sums) {
  if ($l -notmatch '^([0-9a-f]{64})\s+(.+)$') { continue }
  $f = Join-Path $Pkg $Matches[2]
  if (-not (Test-Path -LiteralPath $f)) { $bad += "missing: $($Matches[2])"; continue }
  if ((Get-FileHash -LiteralPath $f -Algorithm SHA256).Hash.ToLower() -ne $Matches[1]) { $bad += "modified: $($Matches[2])" }
}
if ($bad.Count) { $bad | % { Write-Host "  $_" -ForegroundColor Red }; Fail "the package is damaged or modified" }
Write-Host "  ok ($((Get-Content $sums).Count) files)"
if ($WatcherEngine -eq "go" -and -not (Test-Path (Join-Path $Pkg "watcher\docscan-watcher.exe"))) {
  Fail "this package has no watcher\docscan-watcher.exe (older package) - use -WatcherEngine ps or a newer package"
}

# --- 2. stop the previous version ---
# "DocScan Watcher Go" = the load-test task of ci\loadtest\rds_watcher_swap.ps1 - replaced by the normal task now
$oldTasks = @($TaskName, "DocScan Watcher Go") | ? { Get-ScheduledTask -TaskName $_ -EA SilentlyContinue }
$oldSvc = Get-Service -Name $SvcName -EA SilentlyContinue
$UpdSvc = "DocScanUpdater"
# the updater: stopped for the update (it may be the one running this installer - the installer lives on)
if ((Get-Service -Name $UpdSvc -EA SilentlyContinue) -and (Get-Service -Name $UpdSvc).Status -ne 'Stopped') {
  Set-Service -Name $UpdSvc -StartupType Disabled -EA SilentlyContinue
  Stop-Service -Name $UpdSvc -Force -EA SilentlyContinue
  $script:updStopped = $true
}
# the web interface: its exe is replaced too (step 9 starts it again)
$WebSvc = "DocScanWeb"
if ((Get-Service -Name $WebSvc -EA SilentlyContinue) -and (Get-Service -Name $WebSvc).Status -ne 'Stopped') {
  Stop-Service -Name $WebSvc -Force -EA SilentlyContinue
}
Get-Process docscan-web -EA SilentlyContinue | ? { $_.Path -like "$InstallDir\*" } | Stop-Process -Force -EA SilentlyContinue
$oldProcs = @(Get-CimInstance Win32_Process | ? { $_.Name -eq 'docscan-watcher.exe' -or ($_.Name -eq 'powershell.exe' -and $_.CommandLine -like "*docscan-watcher.ps1*") })
if ($oldTasks.Count -or $oldSvc -or $oldProcs.Count) {
  Step "stopping the previous version"
  # the service first; Disabled for the time of the update: its recovery actions must not start the watcher again
  # if it has to be killed below (step 6 sets Automatic again)
  if ($oldSvc -and $oldSvc.Status -ne 'Stopped') {
    Set-Service -Name $SvcName -StartupType Disabled -EA SilentlyContinue
    Stop-Service -Name $SvcName -Force -EA SilentlyContinue
    try { $oldSvc.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } catch { }
  }
  foreach ($t in $oldTasks) { Stop-ScheduledTask -TaskName $t -EA SilentlyContinue }
  Start-Sleep 2
  # by process name (the Go exe) / the script path (PowerShell) - the exe must be gone before it is overwritten
  Get-CimInstance Win32_Process | ? { $_.Name -eq 'docscan-watcher.exe' -or ($_.Name -eq 'powershell.exe' -and $_.CommandLine -like "*docscan-watcher.ps1*") } |
    % { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
  Get-Process docscan-updater -EA SilentlyContinue | ? { $_.Path -like "$InstallDir\*" } | Stop-Process -Force -EA SilentlyContinue
  # scans still running (up to -ScanTimeout) would keep bin\yara64.exe locked
  Get-CimInstance Win32_Process -Filter "Name='yara64.exe'" | ? { $_.ExecutablePath -like "$InstallDir\bin\*" } |
    % { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
  if ($oldTasks -contains "DocScan Watcher Go") { Unregister-ScheduledTask -TaskName "DocScan Watcher Go" -Confirm:$false -EA SilentlyContinue }
  Start-Sleep 1
}

# --- 2b. antivirus exclusions (BEFORE copying - the rule files contain strings from malicious samples) ---
# Defender: Add-MpPreference -ExclusionPath. The risk is small: $DataDir is closed to everyone except SYSTEM and
# Administrators (step 4), $InstallDir has the normal Program Files permissions. ESET cannot be configured from a
# local script (settings are password-protected / ESET PROTECT) - warning only.
if (-not $NoAvExclusion) {
  Step "antivirus: exclusions for $InstallDir and $DataDir"
  if (Get-Command Add-MpPreference -ErrorAction SilentlyContinue) {
    try {
      Add-MpPreference -ExclusionPath $InstallDir, $DataDir -ErrorAction Stop
      $ex = @((Get-MpPreference -ErrorAction Stop).ExclusionPath)
      if ($ex -contains $InstallDir -and $ex -contains $DataDir) { Write-Host "  Microsoft Defender: exclusions added" }
      else { Write-Host "  Microsoft Defender: exclusions not visible - probably managed by a policy (GPO/Intune); add them there" -ForegroundColor Yellow }
    } catch {
      Write-Host "  Microsoft Defender: could not add exclusions ($($_.Exception.Message)) - add them by policy" -ForegroundColor Yellow
    }
  } else {
    Write-Host "  Microsoft Defender is not available on this machine - skipped" -ForegroundColor Yellow
  }
  if (Get-Service -Name ekrn -ErrorAction SilentlyContinue) {
    Write-Host "  ESET detected: add exclusions for $InstallDir and $DataDir with an ESET PROTECT policy" -ForegroundColor Yellow
  }
}

# --- 3. program files ---
Step "copying to $InstallDir"
New-Item -ItemType Directory -Force $InstallDir | Out-Null
if ((Test-Path "$InstallDir\rules") -and -not $Rules -and -not (Test-Path "$InstallDir\rules\VERSION.txt") -and (Test-Path (Join-Path $Pkg "rules"))) {
  Remove-Item "$InstallDir\rules.prev" -Recurse -Force -EA SilentlyContinue
  Copy-Item "$InstallDir\rules" "$InstallDir\rules.prev" -Recurse
}
# rules: from a bundle (-Rules, installed below by docscan-updater) / kept (the PC has bundle rules: rules\VERSION.txt)
# / from this package (old packages only: packages come without rules since v1.0.6)
$bundleRules = Test-Path "$InstallDir\rules\VERSION.txt"
$pkgRules = Test-Path (Join-Path $Pkg "rules\docscan-index.yar")
$rulesFrom = if ($Rules) { "bundle" } elseif ($bundleRules) { "kept" } elseif ($pkgRules) { "package" } else { "" }
if (-not $rulesFrom) { Fail "no rules: this package has none and none are installed - give the rules bundle: -Rules <DocScan-rules-bundle.zip | URL> (a yara-docscan-rules release)" }
foreach ($d in "bin", "rules", "watcher", "updater", "web") {
  if (-not (Test-Path (Join-Path $Pkg $d))) { continue }   # updater\: packages from v1.0.x on; web\: with the web interface
  if ($d -eq "rules" -and $rulesFrom -ne "package") { continue }
  Remove-Item "$InstallDir\$d" -Recurse -Force -EA SilentlyContinue
  Copy-Item (Join-Path $Pkg $d) "$InstallDir\$d" -Recurse
}
Copy-Item (Join-Path $Pkg "uninstall.ps1") $InstallDir -Force
Copy-Item (Join-Path $Pkg "VERSION.txt") $InstallDir -Force -EA SilentlyContinue
# critical-information rules: part of the rules package (rules\critical\*.yar, any number of files - CRITICAL-RULES.md);
# the separate <InstallDir>\critical\critical-rules.yar of older versions is not used any more
$critRules = "$InstallDir\rules\critical"
if (Test-Path -LiteralPath "$InstallDir\critical") {
  Remove-Item "$InstallDir\critical" -Recurse -Force -EA SilentlyContinue
  Write-Host "  removed $InstallDir\critical (the critical rules now come with the rules package)"
}

# a stray copy from an earlier run in a 32-bit PowerShell (installed to Program Files (x86)) - remove it
$x86Dir = "${env:ProgramFiles(x86)}\DocScan"
if (${env:ProgramFiles(x86)} -and $x86Dir -ne $InstallDir -and (Test-Path -LiteralPath "$x86Dir\watcher\docscan-watcher.ps1")) {
  Remove-Item -LiteralPath $x86Dir -Recurse -Force -EA SilentlyContinue
  if (Get-Command Remove-MpPreference -ErrorAction SilentlyContinue) { Remove-MpPreference -ExclusionPath $x86Dir -EA SilentlyContinue }
  Write-Host "  removed the old copy in $x86Dir"
}

# --- 4. data: results and quarantine (SYSTEM + Administrators only) ---
Step "data folders in $DataDir"
foreach ($d in $DataDir, "$DataDir\results", "$DataDir\quarantine") { New-Item -ItemType Directory -Force $d | Out-Null }
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetAccessRuleProtection($true, $false)   # no inheritance from ProgramData (it has Users:Read)
foreach ($sid in "S-1-5-18", "S-1-5-32-544") {  # SYSTEM, Administrators
  $id = (New-Object Security.Principal.SecurityIdentifier $sid).Translate([Security.Principal.NTAccount])
  $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($id, "FullControl",
    "ContainerInherit,ObjectInherit", "None", "Allow")))
}
Set-Acl -Path $DataDir -AclObject $acl   # results\ and quarantine\ inherit these permissions

# white / black lists of the organisation (deploy\README.txt, "White and black lists"): the watcher applies them before
# the scan and re-reads them when they change. Not part of the package; an update keeps them. Only SYSTEM /
# Administrators can change them (DataDir ACL). Checked with docscan-updater -CheckList - the code the watcher uses.
$listsDir = "$DataDir\lists"
$whiteFile = "$listsDir\whitelist.json"
$blackFile = "$listsDir\blacklist.json"
New-Item -ItemType Directory -Force $listsDir | Out-Null
foreach ($l in @(@{ Src = $Whitelist; No = $NoWhitelist; Dst = $whiteFile; Name = "white list"; Kind = "white" },
                 @{ Src = $Blacklist; No = $NoBlacklist; Dst = $blackFile; Name = "black list"; Kind = "black" })) {
  if ($l.No) { Remove-Item -LiteralPath $l.Dst -Force -EA SilentlyContinue; continue }
  if (-not $l.Src) { continue }
  if (-not (Test-Path -LiteralPath $l.Src -PathType Leaf)) { Fail "$($l.Name) not found: $($l.Src)" }
  $chk = & "$InstallDir\updater\docscan-updater.exe" -CheckList $l.Kind $l.Src 2>&1 | % { "$_" }
  if ($LASTEXITCODE -ne 0) { Fail "$($l.Name): $($chk -join ' ')" }
  if (Test-Path -LiteralPath $l.Dst) { Copy-Item -LiteralPath $l.Dst "$($l.Dst).prev" -Force }   # backup
  Copy-Item -LiteralPath $l.Src $l.Dst -Force
  Write-Host "  $($l.Name): $($chk -join ' ') -> $($l.Dst)"
}

# --- 4b. old DocScan (Wazuh active-response) -> full removal ---
$legacyRemoved = @()
if ((Test-Path $OssecDir) -and -not $KeepLegacy) {
  $arBin = Join-Path $OssecDir "active-response\bin"
  Step "removing the old DocScan (Wazuh active-response) from $OssecDir"
  foreach ($n in "doc-scan.ps1", "doc-scan.cmd") {
    $f = Join-Path $arBin $n
    if (Test-Path -LiteralPath $f) { Remove-Item -LiteralPath $f -Force; $legacyRemoved += $f }
  }
  $work = Join-Path $OssecDir "tmp\docscan"
  if (Test-Path -LiteralPath $work) { Remove-Item -LiteralPath $work -Recurse -Force; $legacyRemoved += $work }
  # old quarantine: originals of infected files - move them, do not delete
  $oldQ = Join-Path $OssecDir "quarantine"
  if (Test-Path -LiteralPath $oldQ) {
    $items = @(Get-ChildItem -LiteralPath $oldQ -Force)
    if ($items.Count) {
      $dst = "$DataDir\quarantine\legacy"
      New-Item -ItemType Directory -Force $dst | Out-Null
      foreach ($i in $items) { Move-Item -LiteralPath $i.FullName (Join-Path $dst $i.Name) -Force }
      Write-Host ("  old quarantine ({0} items) -> {1}" -f $items.Count, $dst)
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
    $legacyRemoved | % { Write-Host "  removed: $_" }
    Write-Host "  On the Wazuh manager remove <command>/<active-response> for doc-scan and yara-scan." -ForegroundColor Yellow
  } else {
    Write-Host "  (no traces of the old DocScan)"
  }
}

# --- 4c. Wazuh agent: ossec.conf + restart ---
$wazuhDone = $false
$ossecConf = Join-Path $OssecDir "ossec.conf"
if ((Test-Path $ossecConf) -and -not $NoWazuhConfig) {
  Step "Wazuh agent: $ossecConf"
  New-Item -ItemType Directory -Force "$DataDir\legacy" | Out-Null
  $bak = "$DataDir\legacy\ossec.conf.{0}.bak" -f (Get-Date -Format "yyyyMMdd-HHmmss")
  Copy-Item -LiteralPath $ossecConf $bak
  $orig = Read-Text $ossecConf
  $new = Remove-LegacyArBlocks (Remove-DocScanBlock $orig)
  $results = "$DataDir\results\docscan-results.json"
  # create it beforehand: otherwise the agent logs ERROR (1103) "could not open file" after the restart
  if (-not (Test-Path -LiteralPath $results)) { [IO.File]::WriteAllText($results, "") }
  $updates = "$DataDir\results\docscan-updates.json"   # records of the updater (event "Update")
  if (-not (Test-Path -LiteralPath $updates)) { [IO.File]::WriteAllText($updates, "") }
  $block = "  $DsBegin`r`n"
  foreach ($loc in $results, $updates) { $block += "  <localfile>`r`n    <log_format>json</log_format>`r`n    <location>$loc</location>`r`n  </localfile>`r`n" }
  $block += "  $DsEnd`r`n"
  $i = $new.LastIndexOf("</ossec_config>")
  if ($i -lt 0) { Fail "ossec.conf has no </ossec_config> - not touching it (backup: $bak)" }
  $new = $new.Substring(0, $i) + $block + $new.Substring($i)
  $unchanged = ($new -eq $orig)
  if (-not $unchanged) { Write-Text $ossecConf $new }
  Write-Host "  backup: $bak"
  Write-Host ("  <localfile> json -> $results, $updates" + $(if ($unchanged) { " (already there - no agent restart)" } else { "" }))

  # Restart-Service sometimes fails with "Cannot stop WazuhSvc" (the agent hangs while stopping):
  # wait for it, then end the agent process and start the service again
  function Restart-Wazuh {
    try { Restart-Service WazuhSvc -Force -ErrorAction Stop; return } catch { Write-Host "  Restart-Service: $($_.Exception.Message) - waiting / ending the agent process" -ForegroundColor Yellow }
    for ($k = 0; $k -lt 10 -and (Get-Service WazuhSvc).Status -ne "Stopped"; $k++) { Start-Sleep 3 }
    if ((Get-Service WazuhSvc).Status -ne "Stopped") {
      Get-Process wazuh-agent, ossec-agent -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
      Start-Sleep 3
    }
    try { Start-Service WazuhSvc -ErrorAction Stop } catch { Write-Host "  Start-Service: $($_.Exception.Message)" -ForegroundColor Yellow }
  }
  $svc = Get-Service WazuhSvc -EA SilentlyContinue
  if ($unchanged) {
    # an update with the same ossec.conf block: the agent keeps running
  } elseif ($svc) {
    $log = Join-Path $OssecDir "ossec.log"
    $mark = if (Test-Path $log) { (Get-Item $log).Length } else { 0 }
    Restart-Wazuh
    Start-Sleep 10
    $errs = @()
    if (Test-Path $log) {
      $fs = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite'); [void]$fs.Seek($mark, 'Begin')
      $tail = (New-Object IO.StreamReader($fs)).ReadToEnd(); $fs.Close()
      $errs = @($tail -split "`n" | ? { $_ -match "(ERROR|CRITICAL).*(config|xml|localfile|ossec\.conf)" })
    }
    if ((Get-Service WazuhSvc).Status -ne "Running" -or $errs.Count) {
      Write-Host "  the agent rejected the configuration - restoring the old ossec.conf" -ForegroundColor Yellow
      $errs | % { Write-Host "    $_" }
      Copy-Item -LiteralPath $bak $ossecConf -Force
      Restart-Wazuh
      Fail "ossec.conf rolled back (the agent runs on the old configuration)"
    }
    Write-Host "  WazuhSvc restarted, configuration accepted"
  } else {
    Write-Host "  (WazuhSvc service not found - restart the agent manually)"
  }
  $wazuhDone = $true
}

# --- 4d. rules bundle (-Rules): docscan-updater checks the CI signature, every file, compiles them, installs ---
if ($Rules) {
  Step "rules bundle: $Rules"
  $rb = $Rules
  if ($Rules -match '^https?://') {
    $rb = Join-Path $env:TEMP "DocScan-rules-bundle.zip"
    $ProgressPreference = "SilentlyContinue"
    try { Invoke-WebRequest -UseBasicParsing $Rules -OutFile $rb } catch { Fail "-Rules: could not download $Rules - $($_.Exception.Message)" }
  } elseif (-not (Test-Path -LiteralPath $Rules)) { Fail "-Rules: not found: $Rules" }
  $upd = "$InstallDir\updater\docscan-updater.exe"
  if (-not (Test-Path $upd)) { Fail "-Rules needs updater\docscan-updater.exe (a newer package)" }
  $eap = $ErrorActionPreference; $ErrorActionPreference = "Continue"
  $o = & $upd -InstallRules $rb -DataDir $DataDir -InstallDir $InstallDir 2>&1 | % { "$_" }
  $rc = $LASTEXITCODE; $ErrorActionPreference = $eap
  if ($Rules -match '^https?://') { Remove-Item $rb -EA SilentlyContinue }
  if ($rc -ne 0) { Fail "the rules bundle was not installed: $($o -join ' ')" }
  Write-Host "  $($o -join ' ')"
} elseif ($rulesFrom -eq "kept") {
  Write-Host ("==> rules: kept " + [string](Get-Content "$InstallDir\rules\VERSION.txt" -TotalCount 1) + " (updated separately)") -ForegroundColor Cyan
}

# --- 5. self-test ---
Step "self-test"
$yara  = "$InstallDir\bin\yara64.exe"
$rules = "$InstallDir\rules\docscan-index.yar"
$eap = $ErrorActionPreference; $ErrorActionPreference = "Continue"   # yara64 writes errors to stderr: read them, do not stop
$ver = & $yara --version 2>&1
if ($LASTEXITCODE -ne 0) { Fail "yara64.exe does not start: $ver (vcruntime140.dll missing?)" }
$probe = Join-Path $env:TEMP "docscan-probe.txt"; "probe" | Set-Content $probe
$out = & $yara -w --docscan-json $rules $probe 2>&1 | % { "$_" }
$critOn = (-not $NoCritical) -and @(Get-ChildItem -LiteralPath $critRules -File -Filter *.yar -EA SilentlyContinue | ? { $_.Extension -eq ".yar" }).Count -gt 0
if ($critOn) {
  $q = Join-Path $env:TEMP "docscan-probe-critical.json"
  # --file-vars: the main rules use the filename/filepath externals
  $co = & $yara -w --file-vars "--critical-rules=$critRules" "--critical-out=$q" $rules $probe 2>&1 | % { "$_" }
  Remove-Item $q -EA SilentlyContinue
  if ($LASTEXITCODE -ne 0) { Remove-Item $probe -EA SilentlyContinue; Fail "the critical rules do not compile:`n$($co -join "`n")" }
}
Remove-Item $probe -EA SilentlyContinue
$ErrorActionPreference = $eap
$json = $out | ? { $_ -like '{*' } | Select -First 1
if (-not $json) { Fail "the rules do not compile or there is no JSON:`n$($out -join "`n")" }
$j = $json | ConvertFrom-Json
Write-Host "  yara64 $ver; rules compile; test scan: verdict=$($j.verdict)"

# --- 6. Windows service (Go watcher) / scheduled task (-WatcherEngine ps) ---
if ($WatcherEngine -eq "go") {
  Step "registering service '$SvcName' (DocScan Watcher: starts with Windows, SYSTEM, restarted after a failure)"
  # docscan-watcher.exe: same option names as the script. One -WatchPath per folder (its list option splits on
  # commas). Quoting for the C runtime command-line parser: a trailing backslash before the closing quote is
  # doubled ("D:\\" -> D:\), otherwise it would escape the quote.
  function Q([string]$s) { '"' + ($s -replace '(\\+)$', '$1$1') + '"' }
  $goArgs = @()
  foreach ($p in $WatchPath) { $goArgs += "-WatchPath", (Q $p) }
  $goArgs += "-Yara", (Q $yara), "-Rules", (Q $rules), "-OutDir", (Q "$DataDir\results"), "-BackupDir", (Q "$DataDir\quarantine")
  if ($QuarantineGeneral) { $goArgs += "-QuarantineGeneral" }
  if ($DetectOnly) { $goArgs += "-NoDisarm" }
  if ($MacroUpload) { $goArgs += "-MacroUpload", (Q $MacroUpload) }
  $goArgs += "-Whitelist", (Q $whiteFile), "-Blacklist", (Q $blackFile)   # re-read when changed; a missing file = no list
  if (-not $NoCritical) { $goArgs += "-CriticalRules", (Q $critRules), "-CriticalOut", (Q "$DataDir\critical\critical.json") }
  if ($Workers -gt 0) { $goArgs += "-Workers", $Workers }
  $bin = (Q "$InstallDir\watcher\docscan-watcher.exe") + " " + ($goArgs -join " ")
  # the older scheduled task (before the service) - the service replaces it
  foreach ($t in @($TaskName, "DocScan Watcher Go")) { Unregister-ScheduledTask -TaskName $t -Confirm:$false -EA SilentlyContinue }
  $desc = "DocScan: auto-scan and disarm of new documents (yara64 + docscan)"
  if (Get-Service -Name $SvcName -EA SilentlyContinue) {
    # update: the parameters of this install (ImagePath = exe + arguments); New-Service cannot change an existing one
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$SvcName" -Name ImagePath -Value $bin
    Set-Service -Name $SvcName -StartupType Automatic -DisplayName "DocScan Watcher" -Description $desc
  } else {
    New-Service -Name $SvcName -BinaryPathName $bin -DisplayName "DocScan Watcher" -Description $desc -StartupType Automatic | Out-Null
  }
  # LocalSystem; recovery: restart 10 s / 10 s / 60 s after each failure (the count resets after a day without one),
  # also when the watcher exits with an error code (failureflag), not only on a crash
  sc.exe config $SvcName obj= LocalSystem | Out-Null
  sc.exe failure $SvcName reset= 86400 actions= restart/10000/restart/10000/restart/60000 | Out-Null
  sc.exe failureflag $SvcName 1 | Out-Null
} else {
  Step "registering task '$TaskName' (starts at Windows boot, SYSTEM)"
  if (Get-Service -Name $SvcName -EA SilentlyContinue) { sc.exe delete $SvcName | Out-Null }   # the Go service of a newer install
  $wp = ($WatchPath | % { "'" + ($_ -replace "'", "''") + "'" }) -join ","
  $taskArgs = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command `"& '$InstallDir\watcher\docscan-watcher.ps1'" +
          " -WatchPath $wp -Yara '$yara' -Rules '$rules' -OutDir '$DataDir\results' -BackupDir '$DataDir\quarantine'" +
          ($(if ($QuarantineGeneral) { " -QuarantineGeneral" } else { "" })) +
          ($(if ($DetectOnly) { " -NoDisarm" } else { "" })) +
          ($(if ($MacroUpload) { " -MacroUpload '" + ($MacroUpload -replace "'", "''") + "'" } else { "" })) +
          ($(if (-not $NoCritical) { " -CriticalRules '$critRules' -CriticalOut '$DataDir\critical\critical.json'" } else { "" })) + "`""
  $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $taskArgs
  $trigger   = New-ScheduledTaskTrigger -AtStartup
  $principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
  $settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable `
                 -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew `
                 -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description "DocScan: auto-scan and disarm of new documents (yara64 + docscan)" -Force | Out-Null
}

if (-not $NoStart) {
  # On start the watcher compiles thousands of rules - on a slow PC that takes a minute or more.
  # Wait for ITS OWN "start: watching" line (only text written after this point), up to 180 s.
  $log = "$DataDir\results\watcher.log"
  $mark = if (Test-Path $log) { (Get-Item $log).Length } else { 0 }
  if ($WatcherEngine -eq "go") { Start-Service -Name $SvcName } else { Start-ScheduledTask -TaskName $TaskName }
  Write-Host "  waiting for the watcher to compile the rules (up to 3 min)..."
  $started = $false; $state = ""
  for ($t = 0; $t -lt 180 -and -not $started; $t += 3) {
    Start-Sleep 3
    $state = if ($WatcherEngine -eq "go") { "$((Get-Service -Name $SvcName).Status)" } else { "$((Get-ScheduledTask -TaskName $TaskName).State)" }
    if ($state -ne "Running") { break }
    if (Test-Path $log) {
      $fs = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite'); [void]$fs.Seek($mark, 'Begin')
      $tail = (New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)).ReadToEnd(); $fs.Close()
      $started = $tail -match "start: watching"
    }
  }
  if (-not $started) {
    # why: the task's exit code (0x1 = the script exited with an error, 0x41303 = never ran) and the log tail
    if ($WatcherEngine -eq "go") {
      $sv = Get-CimInstance Win32_Service -Filter "Name='$SvcName'" -EA SilentlyContinue
      if ($sv) { Write-Host ("  service: {0}, exit code {1} (service-specific {2})" -f $sv.State, $sv.ExitCode, $sv.ServiceSpecificExitCode) }
    } else {
      $ti = Get-ScheduledTaskInfo -TaskName $TaskName -EA SilentlyContinue
      if ($ti) { Write-Host ("  task: last run {0}, result 0x{1:X}" -f $ti.LastRunTime, $ti.LastTaskResult) }
    }
    if (Test-Path $log) { Get-Content $log -Tail 15 | % { Write-Host "  | $_" } } else { Write-Host "  (no $log - the script did not get to logging: execution policy / antivirus?)" }
    Fail "the watcher did not start (state: $state). See $log"
  }
  Write-Host "  watcher is running"
}

# --- 7. what was installed and how: install.json (-Reuse), the package for a rollback ---
$verTitle = if (Test-Path "$InstallDir\VERSION.txt") { [string](Get-Content "$InstallDir\VERSION.txt" -TotalCount 1) } else { "" }
$relVer = if ($verTitle -match '\b(v\d+\.\d+\.\d+)\b') { $Matches[1] } else { "" }
$hist = @()
if ($prevInstall -and $prevInstall.history) { $hist = @($prevInstall.history | ? { $_ -and $_ -ne $relVer }) }
if ($relVer) { $hist += $relVer }
$hist = @($hist | Select-Object -Last 2)
$keepParams = [ordered]@{
  WatchPath = @($WatchPath); MacroUpload = $MacroUpload; WatcherEngine = $WatcherEngine; Workers = $Workers; OssecDir = $OssecDir
  QuarantineGeneral = [bool]$QuarantineGeneral; NoAvExclusion = [bool]$NoAvExclusion; DetectOnly = [bool]$DetectOnly
  NoWazuhConfig = [bool]$NoWazuhConfig; KeepLegacy = [bool]$KeepLegacy; KeepLegacyYara = [bool]$KeepLegacyYara
  NoCritical = [bool]$NoCritical; NoWeb = [bool]$NoWeb; WebPort = $WebPort
}
# UTF-8 without BOM (Write-Text): docscan-updater (Go) reads these files
Write-Text $InstallJson ([ordered]@{ installed = $verTitle; version = $relVer; time = (Get-Date).ToString("s"); history = $hist; params = $keepParams } | ConvertTo-Json -Depth 4)
# settings.json (read by the watcher over its service parameters; the web interface edits it): the mode, folders and
# workers of THIS install, so a value set earlier in the web interface does not override the installer. The black
# list pause (blacklist_paused_*) set in the web interface stays.
$setFile = Join-Path $DataDir "settings.json"
$set = [ordered]@{}
if (Test-Path -LiteralPath $setFile) {
  try { $o = Get-Content -LiteralPath $setFile -Raw | ConvertFrom-Json; foreach ($k in "blacklist_paused_until", "blacklist_paused_by") { if ($o.$k) { $set[$k] = [string]$o.$k } } } catch { }
}
$set.detect_only = [bool]$DetectOnly; $set.watch_path = @($WatchPath); $set.workers = [int]$Workers
Write-Text $setFile ($set | ConvertTo-Json -Depth 3)
# the package itself (current + previous release): the updater reinstalls the previous one when an update fails
$pkgRoot = "$DataDir\update\packages"
if ($relVer) {
  $keepPkg = "$pkgRoot\$relVer"
  if ((Resolve-Path $Pkg).Path.TrimEnd('\') -ne $keepPkg) {
    Remove-Item $keepPkg -Recurse -Force -EA SilentlyContinue
    New-Item -ItemType Directory -Force $keepPkg | Out-Null
    Copy-Item "$Pkg\*" $keepPkg -Recurse -Force
  }
  Get-ChildItem $pkgRoot -Directory -EA SilentlyContinue | ? { $hist -notcontains $_.Name -and $_.Name -notlike "*.tmp" } |
    % { Remove-Item $_.FullName -Recurse -Force -EA SilentlyContinue }
}

# --- 8. update service (DocScanUpdater) ---
$updExe = "$InstallDir\updater\docscan-updater.exe"
$updDir = "$DataDir\update"
$updCfg = "$updDir\updater.json"
New-Item -ItemType Directory -Force $updDir | Out-Null
$cfgGiven = $UpdateConfig -or $UpdateMode -or $UpdateMirror -or $UpdateMarker -or $UpdateEveryHours -gt 0 -or $UpdateWindow -or $ListsUrl -or $ListsKey.Count -or $ListsEveryHours -gt 0 -or $ListsToken
if ($cfgGiven -or -not (Test-Path -LiteralPath $updCfg)) {
  $c = [ordered]@{ mode = "github"; check_every_hours = 6; github = @{ repo = "rifatismailov/yara-docscan" }; mirror = @{ url = "" }
                   marker = @{ file = "$updDir\update.json" }; window = ""; extra_public_keys = @()
                   rules = @{ off = $false; github = @{ repo = "rifatismailov/yara-docscan-rules" }; mirror = @{ url = "" } }
                   lists = @{ url = ""; check_every_hours = 24; public_keys = @() } }
  if ($UpdCfgObj) {   # the organisation's ready updater.json (read and checked at the start) replaces the PC's one
    foreach ($pr in $UpdCfgObj.PSObject.Properties) { $c[$pr.Name] = $pr.Value }
  } elseif (Test-Path -LiteralPath $updCfg) {   # given parameters change the existing config, the rest stays
    try { $o = Get-Content -LiteralPath $updCfg -Raw | ConvertFrom-Json; foreach ($k in @($c.Keys)) { if ($null -ne $o.$k) { $c[$k] = $o.$k } } } catch { }
  }
  if ($UpdateMode) { $c.mode = $UpdateMode }
  if ($UpdateMirror) { $c.mirror = @{ url = $UpdateMirror } }
  if ($UpdateMarker) { $c.marker = @{ file = $UpdateMarker } }
  if ($UpdateEveryHours -gt 0) { $c.check_every_hours = $UpdateEveryHours }
  if ($UpdateWindow) { $c.window = $UpdateWindow }
  # the organisation's lists: signed by ITS key (lists.public_keys - separate from extra_public_keys)
  if ($ListsUrl -or $ListsKey.Count -or $ListsEveryHours -gt 0 -or $ListsToken) {
    $l = [ordered]@{ url = [string]$c.lists.url; check_every_hours = $(if ($c.lists.check_every_hours) { $c.lists.check_every_hours } else { 24 }); public_keys = @($c.lists.public_keys | ? { $_ }); token = [string]$c.lists.token }
    if ($ListsToken) { $l.token = $ListsToken }
    if ($ListsUrl) { $l.url = $ListsUrl }
    if ($ListsKey.Count) {
      foreach ($k in $ListsKey) { if ($k -notmatch '^ed25519:[A-Za-z0-9+/]{43}=$') { Fail "-ListsKey '$k': expected ed25519:<base64> (docscan-updater -NewListKey prints it)" } }
      $l.public_keys = @($ListsKey)
    }
    if ($ListsEveryHours -gt 0) { $l.check_every_hours = $ListsEveryHours }
    if ($l.url -and -not $l.public_keys.Count) { Fail "-ListsUrl needs -ListsKey: lists from a mirror must be signed by the organisation" }
    $c.lists = $l
  }
  if ($c.mode -eq "mirror" -and -not $c.mirror.url) { Fail "-UpdateMode mirror needs -UpdateMirror <folder with the release files>" }
  if ($UpdCfgObj -and (Test-Path -LiteralPath $updExe)) {   # the result too (with -Update* / -Lists* given next to it)
    $chk = "$updCfg.check"
    Write-Text $chk ($c | ConvertTo-Json -Depth 6)
    $eap = $ErrorActionPreference; $ErrorActionPreference = "Continue"
    $co = @(& $updExe -CheckConfig $chk 2>&1 | % { "$_" }); $rc = $LASTEXITCODE
    $ErrorActionPreference = $eap
    Remove-Item -LiteralPath $chk -Force -EA SilentlyContinue
    if ($rc) { Fail "-UpdateConfig ${UpdateConfig}: docscan-updater -CheckConfig - $($co -join ' ')" }
  }
  Write-Text $updCfg ($c | ConvertTo-Json -Depth 6)
}
$updMode = try { (Get-Content -LiteralPath $updCfg -Raw | ConvertFrom-Json).mode } catch { "github" }
$listsUrlNow = try { [string](Get-Content -LiteralPath $updCfg -Raw | ConvertFrom-Json).lists.url } catch { "" }
# the service runs when it has something to do: program / rule updates, or the organisation's lists
if ((Test-Path -LiteralPath $updExe) -and ($updMode -ne "off" -or $listsUrlNow)) {
  Step "update service '$UpdSvc' (DocScan Updater: mode $updMode$(if ($listsUrlNow) { ", lists $listsUrlNow" }), $updCfg)"
  $ubin = '"' + $updExe + '" -DataDir "' + $DataDir.TrimEnd('\') + '" -InstallDir "' + $InstallDir.TrimEnd('\') + '"'
  $udesc = "DocScan: installs signed DocScan updates (see $updCfg)"
  if (Get-Service -Name $UpdSvc -EA SilentlyContinue) {
    Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$UpdSvc" -Name ImagePath -Value $ubin
    Set-Service -Name $UpdSvc -StartupType Automatic -DisplayName "DocScan Updater" -Description $udesc
  } else {
    New-Service -Name $UpdSvc -BinaryPathName $ubin -DisplayName "DocScan Updater" -Description $udesc -StartupType Automatic | Out-Null
  }
  sc.exe config $UpdSvc obj= LocalSystem | Out-Null
  sc.exe failure $UpdSvc reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
  sc.exe failureflag $UpdSvc 1 | Out-Null
  if (-not $NoStart) { Start-Service -Name $UpdSvc; Write-Host "  running" }
} elseif (Get-Service -Name $UpdSvc -EA SilentlyContinue) {
  Write-Host "  updates off (mode off / no updater in the package): service $UpdSvc removed"
  Stop-Service -Name $UpdSvc -Force -EA SilentlyContinue; sc.exe delete $UpdSvc | Out-Null
}

# --- 9. web interface (DocScanWeb): https://127.0.0.1:<WebPort>/, HTTPS + admin password ---
$webExe = "$InstallDir\web\docscan-web.exe"
$webDir = "$DataDir\web"
$webUrl = "https://127.0.0.1:$WebPort/"
$webPw = ""
$webOn = $false
if (-not $NoWeb -and (Test-Path -LiteralPath $webExe)) {
  # a broken web interface must not fail the install (the updater would roll back the protection): warning only
  try {
    Step "web interface '$WebSvc' ($webUrl)"
    if ($WebPort -lt 1 -or $WebPort -gt 65535) { throw "-WebPort ${WebPort}: expected 1..65535" }
    New-Item -ItemType Directory -Force $webDir | Out-Null
    # the key and the password hash: SYSTEM and Administrators only (no inheritance from ProgramData: Users can read there)
    icacls $webDir /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
    if ($LASTEXITCODE) { throw "icacls $webDir failed" }
    $o = @(& $webExe -InitTLS -DataDir $DataDir 2>&1 | % { "$_" })
    if ($LASTEXITCODE -or ($o[-1] -notmatch '^cert (.+) ([0-9A-F]{40}) (new|kept)$')) { throw "certificate: $($o -join ' ')" }
    $thumb = $Matches[2]
    # the certificate becomes trusted (no browser warning); only for 127.0.0.1 / localhost and not a CA.
    # Older copies of OUR certificate (same CN) are removed from Root
    Get-ChildItem Cert:\LocalMachine\Root | ? { $_.Subject -like "CN=DocScan Web 127.0.0.1*" -and $_.Thumbprint -ne $thumb } | Remove-Item -EA SilentlyContinue
    if (-not (Test-Path "Cert:\LocalMachine\Root\$thumb")) {
      Import-Certificate -FilePath "$webDir\cert.cer" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    }
    Write-Host "  certificate $thumb ($($Matches[3])), trusted for https://127.0.0.1"
    $o = @(& $webExe -InitAuth -DataDir $DataDir -Listen "127.0.0.1:$WebPort" 2>&1 | % { "$_" })
    if ($LASTEXITCODE) { throw "password: $($o -join ' ')" }
    if ($o[-1] -match '^password (\S+)$') { $webPw = $Matches[1] }
    $wbin = '"' + $webExe + '" -DataDir "' + $DataDir.TrimEnd('\') + '" -InstallDir "' + $InstallDir.TrimEnd('\') + '" -Listen 127.0.0.1:' + $WebPort
    $wdesc = "DocScan: web interface of this PC ($webUrl)"
    if (Get-Service -Name $WebSvc -EA SilentlyContinue) {
      Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$WebSvc" -Name ImagePath -Value $wbin
      Set-Service -Name $WebSvc -StartupType Automatic -DisplayName "DocScan Web" -Description $wdesc
    } else {
      New-Service -Name $WebSvc -BinaryPathName $wbin -DisplayName "DocScan Web" -Description $wdesc -StartupType Automatic | Out-Null
    }
    sc.exe config $WebSvc obj= LocalSystem | Out-Null
    sc.exe failure $WebSvc reset= 86400 actions= restart/60000/restart/60000/restart/300000 | Out-Null
    if (-not $NoStart) {
      Start-Service -Name $WebSvc
      [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
      $ok = $false
      for ($i = 0; $i -lt 20 -and -not $ok; $i++) {
        Start-Sleep -Milliseconds 500
        try { $r = Invoke-WebRequest -UseBasicParsing "$($webUrl)login" -TimeoutSec 5; $ok = $r.StatusCode -eq 200 } catch { }
      }
      if ($ok) { Write-Host "  running: $webUrl answers over trusted HTTPS" } else { Write-Host "  started, but $webUrl does not answer yet - see $DataDir\results\web.log" -ForegroundColor Yellow }
    }
    $webOn = $true
  } catch {
    Write-Host "  web interface NOT set up: $($_.Exception.Message)" -ForegroundColor Yellow
    $webOn = $false
  }
} elseif (Get-Service -Name $WebSvc -EA SilentlyContinue) {
  Step "web interface off$(if ($NoWeb) { ' (-NoWeb)' } else { ' (not in this package)' }): service $WebSvc removed"
  Stop-Service -Name $WebSvc -Force -EA SilentlyContinue; sc.exe delete $WebSvc | Out-Null
  Get-ChildItem Cert:\LocalMachine\Root | ? { $_.Subject -like "CN=DocScan Web 127.0.0.1*" } | Remove-Item -EA SilentlyContinue
}

Write-Result $true ""
Write-Host ""
Write-Host "DocScan installed." -ForegroundColor Green
Write-Host "  program:    $InstallDir"
Write-Host ("  watcher:    " + $(if ($WatcherEngine -eq "go") { "service $SvcName - docscan-watcher.exe (Go), " + $(if ($Workers -gt 0) { "$Workers parallel scans" } else { "parallel scans: automatic" }) } else { "task '$TaskName' - docscan-watcher.ps1 (PowerShell, one scan at a time)" }))
Write-Host ("  watching:   $($WatchPath -join ', ')   " + $(if ($DetectOnly) { "(DETECT ONLY: files are not changed)" } else { "(disarm enabled)" }))
Write-Host "  results:    $DataDir\results\docscan-results.json  (log: watcher.log)"
Write-Host "  quarantine: $DataDir\quarantine"
Write-Host ("  macros:     $DataDir\macros  (90 days / 500 MB)" + $(if ($MacroUpload) { "; copy -> $MacroUpload" } else { "" }))
Write-Host ("  critical:   " + $(if ($critOn) { "$critRules ($(@(Get-ChildItem -LiteralPath $critRules -File -Filter *.yar).Count) files, from the rules package) -> queue $DataDir\critical\critical.json" } elseif ($NoCritical) { "off (-NoCritical)" } else { "off (the rules package has no critical rules yet)" }))
if ($legacyRemoved.Count) { Write-Host "  old DocScan (Wazuh active-response) fully removed" }
if ($wazuhDone) { Write-Host "  Wazuh:      the agent reads results\docscan-results.json (json); on the manager - deploy\manager\cleanup_manager.sh" }
elseif ($NoWazuhConfig) { Write-Host "  Wazuh:      not configured (-NoWazuhConfig)" }
else { Write-Host "  Wazuh:      NO AGENT ($ossecConf not found) - results stay on this PC only; run the installer again after installing the agent" -ForegroundColor Yellow }
Write-Host ("  policy:     $InstallDir\rules\docscan-policy.yar  (after a change: " + $(if ($WatcherEngine -eq "go") { "Restart-Service $SvcName" } else { "Restart-ScheduledTask '$TaskName'" }) + ")")
$rv = if (Test-Path "$InstallDir\rules\VERSION.txt") { [string](Get-Content "$InstallDir\rules\VERSION.txt" -TotalCount 1) } else { "from the program package" }
Write-Host "  rules:      $InstallDir\rules ($rv)"
Write-Host ("  lists:      white " + $(if (Test-Path -LiteralPath $whiteFile) { $whiteFile } else { "-" }) + ", black " + $(if (Test-Path -LiteralPath $blackFile) { $blackFile } else { "-" }) + $(if ($listsUrlNow) { "; updated daily from $listsUrlNow" } else { "" }))
Write-Host ("  updates:    " + $(if ((Test-Path -LiteralPath $updExe) -and ($updMode -ne "off" -or $listsUrlNow)) { "service $UpdSvc, mode $updMode ($updCfg); records: $DataDir\results\docscan-updates.json" } else { "off" }))
if ($webOn) {
  Write-Host "  web:        $webUrl  (user admin)"
  if ($webPw) {
    Write-Host "              password: $webPw" -ForegroundColor Yellow
    Write-Host "              temporary: change it at the first sign-in; until then it is also in $webDir\initial-password.txt (Administrators only)"
  } else { Write-Host "              password unchanged (forgot it: '$webExe' -ResetPassword)" }
} else { Write-Host "  web:        off$(if ($NoWeb) { ' (-NoWeb)' })" }
Write-Host "  uninstall:  powershell -ExecutionPolicy Bypass -File '$InstallDir\uninstall.ps1'"
