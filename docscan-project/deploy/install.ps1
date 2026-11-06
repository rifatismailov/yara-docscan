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
#   2) copies bin\, rules\, watcher\ to -InstallDir (default C:\Program Files\DocScan);
#   3) creates -DataDir (C:\ProgramData\DocScan): results\ and quarantine\ - access for SYSTEM + Administrators only;
#   4) self-test: yara64 starts, the rules compile, a test scan returns JSON;
#   5) FULLY removes the old DocScan (Wazuh active-response): doc-scan.ps1, doc-scan.cmd,
#      <ossec-agent>\tmp\docscan; the old quarantine <ossec-agent>\quarantine is moved to
#      <DataDir>\quarantine\legacy\ (evidence is kept); and the old YARA for active-response
#      (active-response\bin\yara, yara-scan.*) - DocScan's yara64 replaces it. On the Wazuh manager
#      remove <command>/<active-response> for doc-scan and yara-scan;
#   6) Wazuh agent: ossec.conf (backup) - removes <command>/<active-response> doc-scan/yara-scan,
#      adds <localfile> (json) for results\docscan-results.json; restarts WazuhSvc, restores the old
#      ossec.conf on a configuration error;
#   7) registers the scheduled task "DocScan Watcher": at Windows startup, as SYSTEM,
#      restart on failure; and starts it.
# Running it again = update (the previous rules are kept in rules.prev\).

param(
  # ProgramW6432 = the 64-bit Program Files even when this runs in a 32-bit PowerShell (from a 32-bit cmd / SysWOW64)
  [string]  $InstallDir = "$(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles })\DocScan",
  [string]  $DataDir    = "$env:ProgramData\DocScan",
  [string[]]$WatchPath  = @("C:\Users"),
  [switch]  $QuarantineGeneral,   # exe/scripts/archives matching vendor rules -> quarantine
  [switch]  $NoAvExclusion,       # do NOT add Defender exclusions (if a central policy sets them)
  [switch]  $DetectOnly,          # detection and alerts only: files are NOT disarmed or quarantined (pilot)
  [switch]  $NoStart,             # register, but do not start now
  [string]  $OssecDir = "${env:ProgramFiles(x86)}\ossec-agent",
  [switch]  $KeepLegacy,          # do not remove the old DocScan (active-response)
  [switch]  $KeepLegacyYara,      # do NOT remove the old active-response YARA (yara-scan + yara\)
  [switch]  $NoWazuhConfig        # do not touch the agent's ossec.conf and do not restart WazuhSvc
)

$ErrorActionPreference = "Stop"
$TaskName = "DocScan Watcher"
$Pkg = $PSScriptRoot

function Step($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Fail($m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

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

# --- 2. stop the previous version ---
$old = Get-ScheduledTask -TaskName $TaskName -EA SilentlyContinue
if ($old) {
  Step "stopping the previous version"
  Stop-ScheduledTask -TaskName $TaskName -EA SilentlyContinue
  Start-Sleep 2
  Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
    ? { $_.CommandLine -like "*docscan-watcher.ps1*" } | % { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
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
  $block = "  $DsBegin`r`n  <localfile>`r`n    <log_format>json</log_format>`r`n    <location>$results</location>`r`n  </localfile>`r`n  $DsEnd`r`n"
  $i = $new.LastIndexOf("</ossec_config>")
  if ($i -lt 0) { Fail "ossec.conf has no </ossec_config> - not touching it (backup: $bak)" }
  $new = $new.Substring(0, $i) + $block + $new.Substring($i)
  Write-Text $ossecConf $new
  Write-Host "  backup: $bak"
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
      Write-Host "  the agent rejected the configuration - restoring the old ossec.conf" -ForegroundColor Yellow
      $errs | % { Write-Host "    $_" }
      Copy-Item -LiteralPath $bak $ossecConf -Force
      Restart-Service WazuhSvc -Force
      Fail "ossec.conf rolled back (the agent runs on the old configuration)"
    }
    Write-Host "  WazuhSvc restarted, configuration accepted"
  } else {
    Write-Host "  (WazuhSvc service not found - restart the agent manually)"
  }
  $wazuhDone = $true
}

# --- 5. self-test ---
Step "self-test"
$yara  = "$InstallDir\bin\yara64.exe"
$rules = "$InstallDir\rules\docscan-index.yar"
$ver = & $yara --version 2>&1
if ($LASTEXITCODE -ne 0) { Fail "yara64.exe does not start: $ver (vcruntime140.dll missing?)" }
$probe = Join-Path $env:TEMP "docscan-probe.txt"; "probe" | Set-Content $probe
$out = & $yara -w --docscan-json $rules $probe 2>&1 | % { "$_" }
Remove-Item $probe -EA SilentlyContinue
$json = $out | ? { $_ -like '{*' } | Select -First 1
if (-not $json) { Fail "the rules do not compile or there is no JSON:`n$($out -join "`n")" }
$j = $json | ConvertFrom-Json
Write-Host "  yara64 $ver; rules compile; test scan: verdict=$($j.verdict)"

# --- 6. scheduled task ---
Step "registering task '$TaskName' (starts at Windows boot, SYSTEM)"
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
  -Settings $settings -Description "DocScan: auto-scan and disarm of new documents (yara64 + docscan)" -Force | Out-Null

if (-not $NoStart) {
  # On start the watcher compiles thousands of rules - on a slow PC that takes a minute or more.
  # Wait for ITS OWN "start: watching" line (only text written after this point), up to 180 s.
  $log = "$DataDir\results\watcher.log"
  $mark = if (Test-Path $log) { (Get-Item $log).Length } else { 0 }
  Start-ScheduledTask -TaskName $TaskName
  Write-Host "  waiting for the watcher to compile the rules (up to 3 min)..."
  $started = $false; $state = ""
  for ($t = 0; $t -lt 180 -and -not $started; $t += 3) {
    Start-Sleep 3
    $state = "$((Get-ScheduledTask -TaskName $TaskName).State)"
    if ($state -ne "Running") { break }
    if (Test-Path $log) {
      $fs = [IO.File]::Open($log, 'Open', 'Read', 'ReadWrite'); [void]$fs.Seek($mark, 'Begin')
      $tail = (New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)).ReadToEnd(); $fs.Close()
      $started = $tail -match "start: watching"
    }
  }
  if (-not $started) { Fail "the watcher did not start (state: $state). See $log" }
  Write-Host "  watcher is running"
}

Write-Host ""
Write-Host "DocScan installed." -ForegroundColor Green
Write-Host "  program:    $InstallDir"
Write-Host ("  watching:   $($WatchPath -join ', ')   " + $(if ($DetectOnly) { "(DETECT ONLY: files are not changed)" } else { "(disarm enabled)" }))
Write-Host "  results:    $DataDir\results\docscan-results.json  (log: watcher.log)"
Write-Host "  quarantine: $DataDir\quarantine"
if ($legacyRemoved.Count) { Write-Host "  old DocScan (Wazuh active-response) fully removed" }
if ($wazuhDone) { Write-Host "  Wazuh:      the agent reads results\docscan-results.json (json); on the manager - deploy\manager\cleanup_manager.sh" }
Write-Host "  policy:     $InstallDir\rules\docscan-policy.yar  (after a change: Restart-ScheduledTask '$TaskName')"
Write-Host "  uninstall:  powershell -ExecutionPolicy Bypass -File '$InstallDir\uninstall.ps1'"
