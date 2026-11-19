# DocScan load test: start from zero on the test terminal server - uninstall DocScan with its data, remove the
# load-test files from the users' profiles and install the latest GitHub release again (its install.ps1 runs the
# Go watcher). Run as SYSTEM or Administrator outside WinRM (rds_load.ps1 explains why).
#   rds_reset.ps1 -Critical C:\loadtest\critical-rules.yar [-Workers 8] [-Prefix lt] [-DetectOnly] [-DefenderOff]
#                 [-GoExe C:\loadtest\docscan-watcher.exe]   # only to test an exe that is not released yet
# -DefenderOff: Microsoft Defender off first (rds_defender.ps1 -Off) - otherwise a signature update makes it block
# and delete samples of the test set, and it slows every scan.
# CI (cirun, stand with "load:"):
#   rds_reset.ps1 -Package C:\ci\build.zip -DetectOnly [-Critical ...]   # the package of the tested commit, not the release
#   rds_reset.ps1 -RemoveOnly                                           # after the test: uninstall + profiles, no install
# Both run fine from a WinRM shell (only rds_load.ps1 needs a scheduled task).

param(
  [string]$Critical = "",
  [string]$GoExe = "",
  [int]$Workers = 0,
  [string]$Prefix = "lt",
  [string]$Package = "",    # DocScan-<version>.zip to install instead of the latest GitHub release
  [switch]$RemoveOnly,      # stop + uninstall + remove the load-test files, install nothing
  [switch]$DetectOnly,
  [switch]$DefenderOff
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
function Step($m) { Write-Host ("{0:HH:mm:ss} == {1}" -f (Get-Date), $m) }
$inst = "$env:ProgramW6432\DocScan"

if ($DefenderOff) {
  Step "Microsoft Defender off"
  & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "rds_defender.ps1") -Off | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "rds_defender.ps1 -Off failed" }
}

Step "stop watchers"
# the service (Go watcher, install.ps1): Disabled first - otherwise its recovery actions start a killed watcher again
foreach ($s in "DocScanUpdater", "DocScanWatcher") {   # the updater too: no update in the middle of a test
  if (Get-Service $s -EA SilentlyContinue) {
    Set-Service $s -StartupType Disabled -EA SilentlyContinue
    Stop-Service $s -Force -EA SilentlyContinue
  }
}
foreach ($t in "DocScan Watcher Go", "DocScan Watcher") {
  if (Get-ScheduledTask $t -EA SilentlyContinue) { Stop-ScheduledTask $t -EA SilentlyContinue }
}
if (Get-ScheduledTask "DocScan Watcher Go" -EA SilentlyContinue) { Unregister-ScheduledTask "DocScan Watcher Go" -Confirm:$false }
Get-CimInstance Win32_Process | ? { $_.Name -eq 'docscan-watcher.exe' -or ($_.Name -eq 'powershell.exe' -and $_.CommandLine -match "docscan-watcher\.ps1'") } |
  % { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
Get-Process yara64 -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue

Step "uninstall DocScan (-Purge: results, quarantine, macros, queue)"
if (Test-Path "$inst\uninstall.ps1") { & powershell -NoProfile -ExecutionPolicy Bypass -File "$inst\uninstall.ps1" -Purge | Out-Host }
Remove-Item "$env:ProgramData\DocScan" -Recurse -Force -EA SilentlyContinue
Remove-Item $inst -Recurse -Force -EA SilentlyContinue

Step "remove load-test files from the profiles"
$n = 0
foreach ($p in Get-ChildItem "C:\Users" -Directory -EA SilentlyContinue | ? { $_.Name -match "^$Prefix\d\d$" }) {
  foreach ($d in "Desktop\lt-all", "Desktop\lt", "Documents\lt", "Downloads\lt", "Downloads\probe") {
    $x = Join-Path $p.FullName $d
    if (Test-Path -LiteralPath $x) { cmd /c rd /s /q "`"$x`"" 2>&1 | Out-Null; $n++ }
  }
}
"  folders removed: $n"
if ($RemoveOnly) { Step "done (remove only)"; exit 0 }

if ($Package) {
  Step "install the package $Package"
  $pk = Join-Path $env:TEMP "docscan-load-pkg"
  Remove-Item $pk -Recurse -Force -EA SilentlyContinue
  Expand-Archive -LiteralPath $Package -DestinationPath $pk -Force
  # -UpdateMode off: the update service must not replace the tested build with a release during the test
  $a = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $pk "install.ps1"), "-NoWazuhConfig", "-UpdateMode", "off")
  if ($Critical) { $a += @("-CriticalRules", $Critical) }
  if ($DetectOnly) { $a += "-DetectOnly" }
  if ($Workers -gt 0 -and -not $GoExe) { $a += @("-Workers", $Workers) }
  & powershell @a | Out-Host
  $rc = $LASTEXITCODE
  Remove-Item $pk -Recurse -Force -EA SilentlyContinue
  if ($rc -ne 0) { throw "install.ps1 failed: exit $rc" }
} else {
  Step "install the latest release"
  $f = "$env:TEMP\DocScan-Install.ps1"
  Invoke-WebRequest -UseBasicParsing https://github.com/rifatismailov/yara-docscan/releases/latest/download/DocScan-Install.ps1 -OutFile $f
  $a = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $f)
  if ($Critical) { $a += @("-Critical", $Critical) }
  if ($DetectOnly) { $a += "-DetectOnly" }
  if ($Workers -gt 0 -and -not $GoExe) { $a += @("-Workers", $Workers) }
  & powershell @a | Out-Host
  if ($LASTEXITCODE -ne 0) { throw "DocScan-Install.ps1 failed: exit $LASTEXITCODE" }
}
Get-Content "$inst\VERSION.txt" -TotalCount 1

if ($GoExe) {
  Step "switch to the Go watcher"
  $sw = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $PSScriptRoot "rds_watcher_swap.ps1"), "-Exe", $GoExe)
  if ($Workers -gt 0) { $sw += @("-Workers", $Workers) }
  & powershell @sw | Out-Host
  Start-Sleep 5
  Get-Content "$env:ProgramData\DocScan\results\watcher.log" -Tail 6
}
Step "done"
