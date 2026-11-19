# DocScan combat test - feeder (runs as SYSTEM from a one-shot scheduled task, started by combat_setup.ps1).
#
# Copies the test files from <Work>\src\<set>\... into the watched inbox <Inbox>\<set>\... the way files
# arrive on a workstation: in small batches (a mass copy of thousands of files at once would overflow the
# FileSystemWatcher buffer - the watcher survives that, but this test is about every single file). After each
# batch it waits until the watcher has gone quiet, then the next batch. Nothing here scans anything: the
# installed DocScan watcher (Windows service DocScanWatcher, SYSTEM) does all the work.
#
# Progress: <Work>\feed-status.txt (one line, rewritten); the end: a line starting with "done".
# The files are only copied, never opened or run.

param(
  [Parameter(Mandatory)][string]$Work,       # C:\ci\combat
  [Parameter(Mandatory)][string]$Inbox,      # C:\ci\inbox (watched by the installed watcher)
  [string]$DataDir = "$env:ProgramData\DocScan",
  [int]$Batch = 50,                          # files per batch
  [int]$QuietSeconds = 10,                   # the watcher log unchanged this long = the batch is done
  [int]$BatchTimeout = 900,                  # at most this long per batch
  [int]$FinalQuiet = 120                     # at the end: rescans after disarm come after -RescanCooldown (60 s)
)

$ErrorActionPreference = "Continue"
$src = Join-Path $Work "src"
$status = Join-Path $Work "feed-status.txt"
$log = Join-Path $DataDir "results\watcher.log"
$res = Join-Path $DataDir "results\docscan-results.json"
$sets = @("generated", "provided", "malware", "corpus", "seeds")
$t0 = Get-Date

function Size($p) { if (Test-Path -LiteralPath $p) { (Get-Item -LiteralPath $p).Length } else { 0 } }
function Say($m) { [IO.File]::WriteAllText($status, $m) }

# the watcher is busy while its log or the results file grows
function Wait-Quiet([int]$quiet, [int]$timeout) {
  $end = (Get-Date).AddSeconds($timeout)
  $last = "{0}/{1}" -f (Size $log), (Size $res); $since = Get-Date
  while ((Get-Date) -lt $end) {
    Start-Sleep 2
    $now = "{0}/{1}" -f (Size $log), (Size $res)
    if ($now -ne $last) { $last = $now; $since = Get-Date }
    elseif (((Get-Date) - $since).TotalSeconds -ge $quiet) { return $true }
  }
  return $false
}

$all = @()
foreach ($s in $sets) {
  $d = Join-Path $src $s
  if (-not (Test-Path $d)) { continue }
  foreach ($f in Get-ChildItem -LiteralPath $d -Recurse -File) {
    if ($f.Name -eq "expected.txt") { continue }
    $all += [pscustomobject]@{ set = $s; full = $f.FullName; rel = $f.FullName.Substring($d.Length + 1) }
  }
}
$total = $all.Count
$fed = 0; $slow = 0
for ($i = 0; $i -lt $total; $i += $Batch) {
  foreach ($x in $all[$i..([Math]::Min($i + $Batch, $total) - 1)]) {
    $dst = Join-Path (Join-Path $Inbox $x.set) $x.rel
    $dir = Split-Path $dst
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force $dir | Out-Null }
    try { Copy-Item -LiteralPath $x.full $dst -Force -ErrorAction Stop } catch { }
    $fed++
  }
  $cur = $all[[Math]::Min($i + $Batch, $total) - 1].set
  $min = [int]((Get-Date) - $t0).TotalMinutes
  Say ("feeding: {0} / {1} files (set {2}), {3} min" -f $fed, $total, $cur, $min)
  if (-not (Wait-Quiet $QuietSeconds $BatchTimeout)) { $slow++ }
}
Say ("waiting for the last scans and rescans after disarm: {0} / {1} files fed, {2} min" -f $fed, $total, [int]((Get-Date) - $t0).TotalMinutes)
Wait-Quiet $FinalQuiet 1800 | Out-Null
Say ("done: {0} files fed in {1} min, batches over {2} s: {3}" -f $fed, [int]((Get-Date) - $t0).TotalMinutes, $BatchTimeout, $slow)
