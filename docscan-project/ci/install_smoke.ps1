# DocScan CI - install smoke test on a test stand (cirun stand, step "install"): the package of this commit is
# installed the way a PC gets it (install.ps1, task "DocScan Watcher" as SYSTEM, the Go watcher), a few samples are
# dropped into a test inbox, the watcher must write a record with the expected verdict for each of them, then
# DocScan is removed again (uninstall.ps1 -Purge). Detect-only: the samples are not changed.
#   install_smoke.ps1 -Package C:\ci\dist\DocScan-<version>.zip -Repo C:\ci\yara [-Work C:\ci\smoke]
# Exit code 0 = every sample has its record and verdict; the report is printed.

param(
  [Parameter(Mandatory = $true)][string]$Package,
  [Parameter(Mandatory = $true)][string]$Repo,
  [string]$Work = "C:\ci\smoke",
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

# install: an update if DocScan is already there; watch only the test inbox
& powershell -NoProfile -ExecutionPolicy Bypass -Command "& '$Work\pkg\install.ps1' -WatchPath '$inbox' -NoWazuhConfig -DetectOnly" 2>&1 | % { "  $_" }
if ($LASTEXITCODE) { "FAIL: install.ps1 exit $LASTEXITCODE"; exit 1 }
$task = Get-ScheduledTask "DocScan Watcher"
"task: " + $task.State + ", runs " + $task.Actions[0].Execute
if ($task.Actions[0].Execute -notlike "*docscan-watcher.exe") { Fail "the task does not run the Go watcher" }

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
$log = "$env:ProgramData\DocScan\results\watcher.log"
if (Test-Path $log) { "--- watcher.log (tail)"; Get-Content $log -Tail 6 | % { "  $_" } }

# remove DocScan again: the stand stays clean for the next run
& powershell -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramW6432\DocScan\uninstall.ps1" -Purge 2>&1 | % { "  $_" }
Remove-Item $Work -Recurse -Force -EA SilentlyContinue
if ($failed) { "RESULT: FAIL"; exit 1 }
"RESULT: OK ($($samples.Count) samples, Go watcher)"
exit 0
