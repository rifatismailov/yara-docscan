# DocScan combat test - cleanup (always, also after a failure or an interrupted run).
# Removes everything the test brought to the machine: the feeder task, the test files in the inbox, the
# unpacked malware and samples (<Work>), the backups / quarantined copies and the macro files the test
# created (compared with <Work>\snap.json), and the lines the test added to the E5Search queue.
# Then DocScan itself is removed (clean_docscan.ps1): a stand never keeps DocScan between runs.

param(
  [Parameter(Mandatory)][string]$Work,
  [Parameter(Mandatory)][string]$Inbox,
  [string]$DataDir = "$env:ProgramData\DocScan"
)

$ErrorActionPreference = "Continue"
$Feed = "DocScan combat feed"
if (Get-ScheduledTask -TaskName $Feed -EA 0) { Stop-ScheduledTask -TaskName $Feed -EA 0; Unregister-ScheduledTask -TaskName $Feed -Confirm:$false }

$snapF = Join-Path $Work "snap.json"
if (Test-Path $snapF) {
  $snap = Get-Content $snapF -Raw | ConvertFrom-Json
  $keepQ = @{}; foreach ($f in @($snap.quarantine)) { if ($f) { $keepQ[$f] = 1 } }
  $keepM = @{}; foreach ($f in @($snap.macros)) { if ($f) { $keepM[$f] = 1 } }
  $nq = 0; $nm = 0
  foreach ($f in Get-ChildItem "$DataDir\quarantine" -Recurse -File -EA 0) {
    if (-not $keepQ.ContainsKey($f.FullName)) { Remove-Item -LiteralPath $f.FullName -Force -EA 0; $nq++ }
  }
  foreach ($f in Get-ChildItem "$DataDir\macros" -File -EA 0) {
    if ($f.Name -eq "sent.txt") { continue }
    if (-not $keepM.ContainsKey($f.FullName)) { Remove-Item -LiteralPath $f.FullName -Force -EA 0; $nm++ }
  }
  # the E5Search queue: back to its size before the test (only test documents were added meanwhile)
  $q = "$DataDir\critical\critical.json"
  if ((Test-Path $q) -and (Get-Item $q).Length -gt [long]$snap.critical) {
    $fs = [IO.File]::Open($q, 'Open', 'ReadWrite', 'ReadWrite'); $fs.SetLength([long]$snap.critical); $fs.Close()
  }
  "removed: $nq file(s) from quarantine, $nm macro file(s); critical queue restored"
}
Get-ChildItem -LiteralPath $Inbox -Force -EA 0 | Remove-Item -Recurse -Force -EA 0
Remove-Item $Work -Recurse -Force -EA 0
"inbox empty: " + (-not (Get-ChildItem -LiteralPath $Inbox -Force -EA 0)) + "; work folder removed: " + (-not (Test-Path $Work))
# DocScan itself goes too: the stand is clean for the next run
& powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "clean_docscan.ps1") -DataDir $DataDir 2>&1 | % { "  $_" }
