# DocScan - uninstall.
#   powershell -ExecutionPolicy Bypass -File "C:\Program Files\DocScan\uninstall.ps1"           # data is kept
#   powershell -ExecutionPolicy Bypass -File "C:\Program Files\DocScan\uninstall.ps1" -Purge    # + results and quarantine
param(
  [string]$InstallDir = "$(if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles })\DocScan",
  [string]$DataDir    = "$env:ProgramData\DocScan",
  [switch]$Purge
)
$TaskName = "DocScan Watcher"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host "Run as Administrator" -ForegroundColor Red; exit 1 }

$SvcName = "DocScanWatcher"
# the services (Go watcher, updater): Disabled first, so their recovery actions do not start them again, then stop
# (the updater first: it must not start an update while DocScan is being removed)
foreach ($s in "DocScanUpdater", $SvcName, "DocScanWeb") {
  if (Get-Service -Name $s -EA SilentlyContinue) {
    Set-Service -Name $s -StartupType Disabled -EA SilentlyContinue
    Stop-Service -Name $s -Force -EA SilentlyContinue
    try { (Get-Service -Name $s).WaitForStatus('Stopped', [TimeSpan]::FromSeconds(30)) } catch { }
  }
}
Get-Process docscan-updater, docscan-web -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
# "DocScan Watcher Go" = the load-test task of ci\loadtest\rds_watcher_swap.ps1 (before install.ps1 ran the Go watcher)
foreach ($t in $TaskName, "DocScan Watcher Go") { Stop-ScheduledTask -TaskName $t -EA SilentlyContinue }
# the watcher processes: the Go build or the PowerShell script (matched by process name, not by any command line)
Get-CimInstance Win32_Process | ? { $_.Name -eq 'docscan-watcher.exe' -or ($_.Name -eq 'powershell.exe' -and $_.CommandLine -like "*docscan-watcher.ps1*") } |
  % { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
foreach ($t in $TaskName, "DocScan Watcher Go") { Unregister-ScheduledTask -TaskName $t -Confirm:$false -EA SilentlyContinue }
foreach ($s in $SvcName, "DocScanUpdater", "DocScanWeb") {
  if (Get-Service -Name $s -EA SilentlyContinue) { sc.exe delete $s | Out-Null; Write-Host "service '$s' removed" }
}
Write-Host "task '$TaskName' removed"

# the web interface certificate install.ps1 made trusted (only ours: CN "DocScan Web 127.0.0.1")
$wc = @(Get-ChildItem Cert:\LocalMachine\Root | ? { $_.Subject -like "CN=DocScan Web 127.0.0.1*" })
if ($wc.Count) { $wc | Remove-Item -EA SilentlyContinue; Write-Host "web certificate removed from the trusted root certificates" }

# remove our <localfile> from the agent's ossec.conf
$ossecConf = "${env:ProgramFiles(x86)}\ossec-agent\ossec.conf"
if (Test-Path $ossecConf) {
  $enc = New-Object Text.UTF8Encoding($false)
  $c = [IO.File]::ReadAllText($ossecConf, $enc)
  $n = [regex]::Replace($c, "(?s)[ \t]*<!-- DocScan: managed by DocScan install.ps1 -->.*?<!-- /DocScan -->\r?\n?", "")
  if ($n -ne $c) {
    [IO.File]::WriteAllText($ossecConf, $n, $enc)
    Restart-Service WazuhSvc -Force -EA SilentlyContinue
    Write-Host "ossec.conf: DocScan <localfile> block removed, WazuhSvc restarted"
  }
}

# uninstall.ps1 lives in $InstallDir: delete everything except itself, and itself later
Get-ChildItem $InstallDir -Force -EA SilentlyContinue | ? { $_.FullName -ne $PSCommandPath } |
  Remove-Item -Recurse -Force -EA SilentlyContinue
Start-Process cmd.exe -ArgumentList "/c timeout /t 2 >nul & rmdir /s /q `"$InstallDir`"" -WindowStyle Hidden
Write-Host "program removed: $InstallDir"

if ($Purge) {
  Remove-Item $DataDir -Recurse -Force -EA SilentlyContinue
  Write-Host "data removed: $DataDir"
} else {
  Write-Host "data kept: $DataDir (results, quarantine). To remove: -Purge"
}

# Microsoft Defender exclusions added by install.ps1: the program one always; the data one only with -Purge
# (without -Purge the quarantine still holds originals of malicious documents - Defender must not clean them)
if (Get-Command Remove-MpPreference -ErrorAction SilentlyContinue) {
  $paths = @($InstallDir) + $(if ($Purge) { @($DataDir) } else { @() })
  try { Remove-MpPreference -ExclusionPath $paths -ErrorAction Stop; Write-Host ("Defender: exclusions removed: " + ($paths -join ", ")) }
  catch { Write-Host "Defender: could not remove exclusions ($($_.Exception.Message))" -ForegroundColor Yellow }
}
