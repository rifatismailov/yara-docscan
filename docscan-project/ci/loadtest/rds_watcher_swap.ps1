# DocScan load test: switch the installed watcher between the PowerShell script and the Go build (test servers
# only, until install.ps1 installs the Go watcher itself). The Go watcher gets the same options as the task
# "DocScan Watcher" that install.ps1 registered; it runs as its own task "DocScan Watcher Go" (SYSTEM, at startup,
# restart on failure), the PowerShell task is disabled meanwhile.
#   rds_watcher_swap.ps1 -Exe C:\loadtest\docscan-watcher.exe [-Workers 8]     # -> Go
#   rds_watcher_swap.ps1 -Restore                                             # -> PowerShell again

param(
  [string]$Exe = "",
  [int]$Workers = 0,
  [switch]$Restore
)
$ErrorActionPreference = "Stop"
$ps = "DocScan Watcher"; $go = "DocScan Watcher Go"
$dst = "$env:ProgramW6432\DocScan\watcher\docscan-watcher.exe"

function Stop-Watchers {
  foreach ($t in $ps, $go) { if (Get-ScheduledTask $t -EA SilentlyContinue) { Stop-ScheduledTask $t -EA SilentlyContinue } }
  # the watcher processes themselves (not every command line that mentions the exe, like the caller's -Exe)
  Get-CimInstance Win32_Process | ? { $_.Name -eq 'docscan-watcher.exe' -or ($_.Name -eq 'powershell.exe' -and $_.CommandLine -match "docscan-watcher\.ps1'") } |
    % { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
  Get-Process yara64 -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue
  Start-Sleep 2
}

if ($Restore) {
  Stop-Watchers
  if (Get-ScheduledTask $go -EA SilentlyContinue) { Unregister-ScheduledTask $go -Confirm:$false }
  Enable-ScheduledTask $ps | Out-Null
  Start-ScheduledTask $ps
  "PowerShell watcher back: " + (Get-ScheduledTask $ps).State
  exit 0
}
if (-not (Test-Path -LiteralPath $Exe)) { throw "-Exe not found: $Exe" }

# install.ps1 already runs the Go watcher (current packages): only replace the exe and restart the task
if ((Get-ScheduledTask $ps).Actions[0].Execute -like "*docscan-watcher.exe") {
  if ($Workers -gt 0) { Write-Host "-Workers ignored: reinstall with DocScan-Install.ps1 -Workers $Workers" }
  Stop-Watchers
  Copy-Item -LiteralPath $Exe $dst -Force
  Start-ScheduledTask $ps
  Start-Sleep 5
  "Go watcher replaced: " + (Get-FileHash $dst).Hash.ToLower() + ", task " + (Get-ScheduledTask $ps).State
  exit 0
}

# the options of the installed PowerShell task: -Name 'value' pairs and switches after the script path
$a = (Get-ScheduledTask $ps).Actions[0].Arguments
if ($a -notmatch "docscan-watcher\.ps1'\s+(.*)`"\s*$") { throw "unexpected arguments of '$ps': $a" }
$opts = $Matches[1]
$args2 = @()
foreach ($m in [regex]::Matches($opts, "-(\w+)(?:\s+'((?:[^']|'')*)')?")) {
  $args2 += "-" + $m.Groups[1].Value
  if ($m.Groups[2].Success) { $args2 += '"' + ($m.Groups[2].Value -replace "''", "'") + '"' }
}
if ($Workers -gt 0) { $args2 += "-Workers", $Workers }

Stop-Watchers
Disable-ScheduledTask $ps | Out-Null
Copy-Item -LiteralPath $Exe $dst -Force
$action    = New-ScheduledTaskAction -Execute $dst -Argument ($args2 -join " ")
$trigger   = New-ScheduledTaskTrigger -AtStartup
$principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
$settings  = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable `
               -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew `
               -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName $go -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
  -Description "DocScan: Go watcher (load test)" -Force | Out-Null
Start-ScheduledTask $go
Start-Sleep 5
"Go watcher: " + (Get-ScheduledTask $go).State
"  $dst $($args2 -join ' ')"
