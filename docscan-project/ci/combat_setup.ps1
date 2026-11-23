# DocScan combat test - setup (cirun --combat, Windows; run as Administrator over WinRM).
#
# The test runs DocScan exactly as on a workstation: the package built from this commit is installed with
# install.ps1 (an update if DocScan is already there: C:\Program Files\DocScan, C:\ProgramData\DocScan, the
# Windows service DocScanWatcher as SYSTEM), the watcher watches C:\Users as usual plus the test inbox, and
# every test file is dropped into that inbox (combat_feed.ps1). check_watcher.py then reads what the watcher
# wrote to docscan-results.json. combat_cleanup.ps1 removes the test files, the malware and their backups.
#
#   1. package: build_package.ps1 -> <Work>\pkg, unpacked;
#   2. test files from the file server (UNC -Share, password in $env:DOCSCAN_SHARE_PASS): yara\corpus,
#      yara\seeds, yara\malware\malware.zip and provided.zip (password "infected", unpacked here only) and
#      the 42 generated samples from the repository -> <Work>\src\<set>;
#   3. snapshot (<Work>\snap.json): sizes of the results / log / critical queue, files in quarantine and macros;
#   4. install.ps1 -WatchPath 'C:\Users','<Inbox>' -NoWazuhConfig;
#   5. the feeder as a one-shot SYSTEM task (a process started over WinRM dies with the WinRM shell).
# The files are only copied and scanned, never opened or run.

param(
  [Parameter(Mandatory)][string]$Repo,
  [Parameter(Mandatory)][string]$Work,
  [Parameter(Mandatory)][string]$Inbox,
  [Parameter(Mandatory)][string]$Version,
  [Parameter(Mandatory)][string]$Share,       # \\<file server>\share
  [Parameter(Mandatory)][string]$ShareUser,
  [string]$DataDir = "$env:ProgramData\DocScan",
  [string]$InstallDir = "$env:ProgramW6432\DocScan",
  [string]$Rules = "",        # rules bundle of the run -> install.ps1 -Rules
  [string]$Package = ""       # a ready package (the build stand's DocScan-<version>.zip): no build here - a stand without
                              # a compiler (Win10) runs the combat on the Win11 package
)

$ErrorActionPreference = "Continue"
$Feed = "DocScan combat feed"
$sw = [Diagnostics.Stopwatch]::StartNew()
function lap($what) { "{0,-28} {1,6:N0} s" -f $what, $sw.Elapsed.TotalSeconds; $sw.Restart() }
function Fail($m) { "ERROR: $m"; exit 1 }

# leftovers of an earlier (broken) run
if (Get-ScheduledTask -TaskName $Feed -EA 0) { Stop-ScheduledTask -TaskName $Feed -EA 0; Unregister-ScheduledTask -TaskName $Feed -Confirm:$false }
Remove-Item $Work -Recurse -Force -EA 0
New-Item -ItemType Directory -Force $Work, "$Work\src", $Inbox | Out-Null
Get-ChildItem -LiteralPath $Inbox -Force | Remove-Item -Recurse -Force -EA 0

# --- 1. package: the ready one of the build stand, or built here
if ($Package) {
  if (-not (Test-Path -LiteralPath $Package)) { Fail "no package $Package" }
  New-Item -ItemType Directory -Force "$Work\pkg" | Out-Null
  $zip = "$Work\pkg\DocScan-$Version.zip"
  Copy-Item -LiteralPath $Package $zip -Force
  "  ready package: $Package"
} else {
  & powershell -NoProfile -ExecutionPolicy Bypass -File "$Repo\docscan-project\deploy\build_package.ps1" -Repo $Repo -Out "$Work\pkg" -Version $Version 2>&1 | Select-Object -Last 2 | % { "  $_" }
  $zip = "$Work\pkg\DocScan-$Version.zip"
}
if (-not (Test-Path $zip)) { Fail "package not built" }
Expand-Archive $zip "$Work\pkg\x" -Force
lap "package"

# --- 2. test files
$pw = $env:DOCSCAN_SHARE_PASS
if (-not $pw) { Fail "no file server password (DOCSCAN_SHARE_PASS)" }
net use $Share /delete /y 2>$null | Out-Null
net use $Share $pw /user:$ShareUser 2>&1 | Out-Null
if (-not (Test-Path "$Share\yara")) { Fail "file server not reachable: $Share" }
foreach ($d in "corpus", "seeds") {
  robocopy "$Share\yara\$d" "$Work\src\$d" /E /MT:16 /R:2 /W:2 /NFL /NDL /NJH /NJS /NP | Out-Null
  if ($LASTEXITCODE -ge 8) { Fail "copy of $d failed (robocopy $LASTEXITCODE)" }
}
Copy-Item "$Share\yara\malware\malware.zip", "$Share\yara\malware\provided.zip" $Work
net use $Share /delete /y 2>$null | Out-Null
lap "copy from the file server"
New-Item -ItemType Directory -Force "$Work\src\malware" | Out-Null
tar.exe -xf "$Work\malware.zip" --passphrase infected -C "$Work\src\malware" 2>&1 | Select-Object -Last 3
if ($LASTEXITCODE) { Fail "malware.zip not unpacked" }
tar.exe -xf "$Work\provided.zip" --passphrase infected -C "$Work\src" 2>&1 | Select-Object -Last 3
if ($LASTEXITCODE) { Fail "provided.zip not unpacked" }
Remove-Item "$Work\malware.zip", "$Work\provided.zip"
Copy-Item "$Repo\docscan-project\test-samples\generated" "$Work\src\generated" -Recurse
lap "unpack"
foreach ($s in "generated", "provided", "malware", "corpus", "seeds") {
  "  {0,-10} {1,5} files" -f $s, @(Get-ChildItem "$Work\src\$s" -Recurse -File -EA 0 | ? { $_.Name -ne "expected.txt" }).Count
}

# --- 3. snapshot: what is there BEFORE the test (cleanup removes only what the test added)
function Size($p) { if (Test-Path -LiteralPath $p) { (Get-Item -LiteralPath $p).Length } else { 0 } }
$snap = [ordered]@{
  results    = Size "$DataDir\results\docscan-results.json"
  log        = Size "$DataDir\results\watcher.log"
  critical   = Size "$DataDir\critical\critical.json"
  quarantine = @(Get-ChildItem "$DataDir\quarantine" -Recurse -File -EA 0 | % { $_.FullName })
  macros     = @(Get-ChildItem "$DataDir\macros" -File -EA 0 | % { $_.FullName })
  started    = (Get-Date).ToString("o")
}

# --- 4. install / update DocScan as on a workstation (the Wazuh agent is not needed here)
$wp = "'C:\Users','" + $Inbox + "'"
& powershell -NoProfile -ExecutionPolicy Bypass -Command "& '$Work\pkg\x\install.ps1' -WatchPath $wp -NoWazuhConfig -UpdateMode off$(if ($Rules) { " -Rules '$Rules'" })" 2>&1 | % { "  $_" }
if ($LASTEXITCODE) { Fail "install.ps1 failed" }
$snap.critical_on = @(Get-ChildItem "$InstallDir\rules\critical\*.yar" -EA SilentlyContinue).Count -gt 0   # critical\*.yar of the rules package
$snap | ConvertTo-Json -Depth 3 | Set-Content "$Work\snap.json" -Encoding UTF8
"  version: " + ((Get-Content "$InstallDir\VERSION.txt" -TotalCount 1) -join "")
"  third pass (critical rules): " + $snap.critical_on
lap "install"

# --- 5. feeder: one-shot task as SYSTEM
$arg = "-NoProfile -ExecutionPolicy Bypass -File `"$Repo\docscan-project\ci\combat_feed.ps1`" -Work `"$Work`" -Inbox `"$Inbox`""
$a = New-ScheduledTaskAction -Execute powershell.exe -Argument $arg
$p = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
$s = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 8) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $Feed -Action $a -Principal $p -Settings $s -Force | Out-Null
Start-ScheduledTask -TaskName $Feed
Start-Sleep 5
"  feeder: " + (Get-ScheduledTask -TaskName $Feed).State
exit 0
