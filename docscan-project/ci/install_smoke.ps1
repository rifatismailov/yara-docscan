# DocScan CI - install smoke test on a test stand (cirun stand, step "install"): the package of this commit is
# installed the way a PC gets it (install.ps1, Windows service DocScanWatcher as SYSTEM, the Go watcher), a few samples are
# dropped into a test inbox, the watcher must write a record with the expected verdict for each of them, then
# DocScan is removed again (uninstall.ps1 -Purge). Detect-only: the samples are not changed.
#   install_smoke.ps1 -Package C:\ci\dist\DocScan-<version>.zip -Repo C:\ci\yara [-Work C:\ci\smoke]
# Exit code 0 = every sample has its record and verdict; the report is printed.

param(
  [Parameter(Mandatory = $true)][string]$Package,
  [Parameter(Mandatory = $true)][string]$Repo,
  [string]$Work = "C:\ci\smoke",
  [string]$Rules = "",            # rules bundle of the run (DocScan-rules-bundle.zip) -> install.ps1 -Rules, as on a PC
  [int]$TimeoutSec = 240
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
function Fail($m) { Write-Host "FAIL: $m"; $script:failed = $true }
$failed = $false
$inbox = "$Work\inbox"
$samples = @("macro_suspicious.docm", "altchunk.docx", "archive_clean.zip", "lnk_remote_exec.lnk")
$results = "$env:ProgramData\DocScan\results\docscan-results.json"

# expected verdicts (column 2 of expected-verdicts.tsv)
$expected = @{}
foreach ($l in Get-Content "$Repo\docscan-project\ci\expected-verdicts.tsv") {
  if ($l -match '^#') { continue }
  $f = $l -split "`t"
  if ($f.Count -ge 2) { $expected[$f[0]] = $f[1] }
}

Remove-Item $Work -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory -Force "$Work\pkg", $inbox | Out-Null
Expand-Archive $Package "$Work\pkg" -Force
"package: " + (Get-Content "$Work\pkg\VERSION.txt" -TotalCount 1)

# install: an update if DocScan is already there; watch only the test inbox. Updates: mode marker - the update
# service runs (checked below) but does nothing without a marker; github would "update" this CI build (no vX.Y.Z)
# to the latest release in the middle of the test
& powershell -NoProfile -ExecutionPolicy Bypass -Command "& '$Work\pkg\install.ps1' -WatchPath '$inbox' -NoWazuhConfig -DetectOnly -UpdateMode marker$(if ($Rules) { " -Rules '$Rules'" })" 2>&1 | % { "  $_" }
if ($LASTEXITCODE) { "FAIL: install.ps1 exit $LASTEXITCODE"; exit 1 }
# the watcher is the Windows service DocScanWatcher: automatic, LocalSystem, restart after a failure, the Go exe
$sv = Get-CimInstance Win32_Service -Filter "Name='DocScanWatcher'"
if (-not $sv) { Fail "no service DocScanWatcher" }
"service: " + $sv.State + ", start " + $sv.StartMode + ", account " + $sv.StartName + ", runs " + $sv.PathName.Substring(0, [Math]::Min(80, $sv.PathName.Length))
if ($sv.PathName -notlike '"*docscan-watcher.exe"*') { Fail "the service does not run the Go watcher" }
if ($sv.StartMode -ne "Auto" -or $sv.StartName -ne "LocalSystem") { Fail "the service must start automatically as LocalSystem" }
$fa = (sc.exe qfailure DocScanWatcher) -join " "
if ($fa -notmatch "RESTART") { Fail "no restart-on-failure actions: $fa" }
if (Get-ScheduledTask "DocScan Watcher" -EA SilentlyContinue) { Fail "the old scheduled task 'DocScan Watcher' is still there" }
# the update service: running, its config, install.json for -Reuse, the package kept for a rollback (release builds)
$us = Get-CimInstance Win32_Service -Filter "Name='DocScanUpdater'"
if (-not $us) { Fail "no service DocScanUpdater" }
else {
  "updater: " + $us.State + ", start " + $us.StartMode + ", account " + $us.StartName
  if ($us.State -ne "Running" -or $us.StartMode -ne "Auto" -or $us.StartName -ne "LocalSystem") { Fail "DocScanUpdater must run automatically as LocalSystem" }
}
$uc = "$env:ProgramData\DocScan\update\updater.json"
if (-not (Test-Path $uc)) { Fail "no $uc" } else { "updater.json: mode " + (Get-Content $uc -Raw | ConvertFrom-Json).mode }
$ij = "$env:ProgramData\DocScan\install.json"
if (-not (Test-Path $ij)) { Fail "no $ij" } else { $j = Get-Content $ij -Raw | ConvertFrom-Json; "install.json: " + $j.installed + ", DetectOnly " + $j.params.DetectOnly + ", WatchPath " + ($j.params.WatchPath -join ";") }
Start-Sleep 3
$ul = "$env:ProgramData\DocScan\results\updater.log"
if (Test-Path $ul) { "updater.log: " + (Get-Content $ul -Tail 1) } else { Fail "no $ul - the updater did not start" }

$mark = if (Test-Path $results) { (Get-Item $results).Length } else { 0 }
foreach ($s in $samples) { Copy-Item "$Repo\docscan-project\test-samples\generated\$s" $inbox }
"dropped: " + ($samples -join ", ")

# wait for one record per sample (records written after $mark)
$got = @{}
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline -and $got.Count -lt $samples.Count) {
  Start-Sleep 3
  if (-not (Test-Path $results)) { continue }
  $fs = [IO.File]::Open($results, 'Open', 'Read', 'ReadWrite'); [void]$fs.Seek([Math]::Min($mark, $fs.Length), 'Begin')
  $tail = (New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)).ReadToEnd(); $fs.Close()
  foreach ($l in ($tail -split "`n")) {
    if ($l -notlike '{*') { continue }
    try { $r = $l | ConvertFrom-Json } catch { continue }
    if ($r.docfile.path -like "$inbox\*") { $got[$r.docfile.name] = $r }
  }
}
foreach ($s in $samples) {
  $r = $got[$s]
  if (-not $r) { Fail "$s - no record within $TimeoutSec s"; continue }
  $ok = $r.verdict -eq $expected[$s] -and -not $r.errors
  "{0,-6} {1,-24} verdict {2,-6} expected {3,-6} {4}" -f $(if ($ok) { "ok" } else { "FAIL" }), $s, $r.verdict, $expected[$s], ($r.errors -join "; ")
  if (-not $ok) { $failed = $true }
}
# recovery: the watcher process is killed (a crash) -> Windows starts the service again (sc failure: after 10 s)
$p0 = (Get-CimInstance Win32_Service -Filter "Name='DocScanWatcher'").ProcessId
if ($p0) {
  Stop-Process -Id $p0 -Force
  $p1 = 0
  for ($t = 0; $t -lt 60 -and -not $p1; $t += 3) {
    Start-Sleep 3
    $sv = Get-CimInstance Win32_Service -Filter "Name='DocScanWatcher'"
    if ($sv.State -eq "Running" -and $sv.ProcessId -and $sv.ProcessId -ne $p0) { $p1 = $sv.ProcessId }
  }
  if ($p1) { "recovery: watcher killed (pid $p0) -> service running again (pid $p1) after ~$t s" }
  else { Fail "recovery: the service did not come back within 60 s after the watcher was killed" }
} else { Fail "the service has no process" }
$log = "$env:ProgramData\DocScan\results\watcher.log"
if (Test-Path $log) { "--- watcher.log (tail)"; Get-Content $log -Tail 6 | % { "  $_" } }

# remove DocScan again: the stand stays clean for the next run
& powershell -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramW6432\DocScan\uninstall.ps1" -Purge 2>&1 | % { "  $_" }
Remove-Item $Work -Recurse -Force -EA SilentlyContinue
if ($failed) { "RESULT: FAIL"; exit 1 }
"RESULT: OK ($($samples.Count) samples, Go watcher as a service, restart after a crash)"
exit 0
