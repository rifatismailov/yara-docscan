# DocScan CI - make a test stand clean of DocScan (before every install and after the combat test).
# A stand must never keep a DocScan between runs: a leftover install - with its own updater, rules or lists - changes
# what the next run tests (2026-11-24: an updater left on Win10 pulled newer rules, the next install refused the run's
# older rules as a downgrade). Removes: the services (DocScanWatcher, DocScanUpdater, DocScanWeb) and the old
# scheduled task, C:\Program Files\DocScan, C:\ProgramData\DocScan, the Defender exclusions, the web certificate.
# Uses the installed uninstall.ps1 -Purge when there is one, then removes whatever is still there.

param(
  [string]$InstallDir = "$env:ProgramW6432\DocScan",
  [string]$DataDir = "$env:ProgramData\DocScan"
)

$ErrorActionPreference = "Continue"
$u = Join-Path $InstallDir "uninstall.ps1"
if (Test-Path -LiteralPath $u) {
  "clean: DocScan found - uninstall.ps1 -Purge"
  & powershell -NoProfile -ExecutionPolicy Bypass -File $u -Purge 2>&1 | % { "  $_" }
}
# leftovers (an install broken half-way, an older version without uninstall.ps1)
foreach ($s in "DocScanUpdater", "DocScanWatcher", "DocScanWeb") {
  if (Get-Service -Name $s -EA SilentlyContinue) {
    Set-Service -Name $s -StartupType Disabled -EA SilentlyContinue
    Stop-Service -Name $s -Force -EA SilentlyContinue
    sc.exe delete $s | Out-Null
    "clean: service $s removed"
  }
}
if (Get-ScheduledTask -TaskName "DocScan Watcher" -EA SilentlyContinue) { Unregister-ScheduledTask -TaskName "DocScan Watcher" -Confirm:$false }
Get-Process -EA SilentlyContinue | ? { $_.Path -and ($_.Path -like "$InstallDir\*") } | Stop-Process -Force -EA SilentlyContinue
Get-ChildItem Cert:\LocalMachine\Root -EA SilentlyContinue | ? { $_.Subject -like "CN=DocScan Web 127.0.0.1*" } | Remove-Item -EA SilentlyContinue
foreach ($d in $InstallDir, $DataDir) {
  if (Test-Path -LiteralPath $d) {
    Remove-Item -LiteralPath $d -Recurse -Force -EA SilentlyContinue
    if (Test-Path -LiteralPath $d) {   # files of another owner / ACL left by an interrupted install
      takeown /F $d /R /D Y 2>&1 | Out-Null; icacls $d /reset /T /C /Q 2>&1 | Out-Null
      Remove-Item -LiteralPath $d -Recurse -Force -EA SilentlyContinue
    }
    if (Test-Path -LiteralPath $d) { "clean: WARNING - $d is still there (a file is held open)" } else { "clean: $d removed" }
  }
}
try { Remove-MpPreference -ExclusionPath $InstallDir, $DataDir -EA SilentlyContinue } catch { }
$mp = [Environment]::GetEnvironmentVariable("Path", "Machine")
$keep = @($mp -split ";" | ? { $_ -and -not $_.StartsWith($InstallDir + "\", [StringComparison]::OrdinalIgnoreCase) })
if ($keep.Count -ne @($mp -split ";" | ? { $_ }).Count) { [Environment]::SetEnvironmentVariable("Path", ($keep -join ";"), "Machine"); "clean: DocScan folders removed from PATH" }
"clean: no DocScan on this machine"
exit 0
