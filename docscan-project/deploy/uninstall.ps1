# DocScan - uninstall.
#   powershell -ExecutionPolicy Bypass -File "C:\Program Files\DocScan\uninstall.ps1"           # data is kept
#   powershell -ExecutionPolicy Bypass -File "C:\Program Files\DocScan\uninstall.ps1" -Purge    # + results and quarantine
param(
  [string]$InstallDir = "$env:ProgramFiles\DocScan",
  [string]$DataDir    = "$env:ProgramData\DocScan",
  [switch]$Purge
)
$TaskName = "DocScan Watcher"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host "Run as Administrator" -ForegroundColor Red; exit 1 }

Stop-ScheduledTask -TaskName $TaskName -EA SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
  ? { $_.CommandLine -like "*docscan-watcher.ps1*" } | % { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -EA SilentlyContinue
Write-Host "task '$TaskName' removed"

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
