# DocScan — видалення.
#   powershell -ExecutionPolicy Bypass -File "C:\Program Files\DocScan\uninstall.ps1"           # дані лишаються
#   powershell -ExecutionPolicy Bypass -File "C:\Program Files\DocScan\uninstall.ps1" -Purge    # + results і карантин
param(
  [string]$InstallDir = "$env:ProgramFiles\DocScan",
  [string]$DataDir    = "$env:ProgramData\DocScan",
  [switch]$Purge
)
$TaskName = "DocScan Watcher"
$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Write-Host "Запустіть від імені адміністратора" -ForegroundColor Red; exit 1 }

Stop-ScheduledTask -TaskName $TaskName -EA SilentlyContinue
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" |
  ? { $_.CommandLine -like "*docscan-watcher.ps1*" } | % { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue }
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -EA SilentlyContinue
Write-Host "завдання '$TaskName' видалено"

# uninstall.ps1 лежить у $InstallDir: видаляємо все, крім себе, а себе — відкладено
Get-ChildItem $InstallDir -Force -EA SilentlyContinue | ? { $_.FullName -ne $PSCommandPath } |
  Remove-Item -Recurse -Force -EA SilentlyContinue
Start-Process cmd.exe -ArgumentList "/c timeout /t 2 >nul & rmdir /s /q `"$InstallDir`"" -WindowStyle Hidden
Write-Host "програму видалено: $InstallDir"

if ($Purge) {
  Remove-Item $DataDir -Recurse -Force -EA SilentlyContinue
  Write-Host "дані видалено: $DataDir"
} else {
  Write-Host "дані збережено: $DataDir (results, quarantine). Видалити: -Purge"
}
