# DocScan load test: one run on the test terminal server - N loadgen.ps1 processes + resource sampling.
#
# Run as SYSTEM or Administrator, NOT inside a WinRM shell (WinRM kills child processes when the shell closes):
# through a one-shot scheduled task (rds_run.py does that).
#   rds_load.ps1 [-Users 25] [-Prefix lt] [-Minutes 20] [-IntervalSec 20] [-Burst 0] [-Name <run name>]
#                [-DrainMinutes 30] [-All]
# Writes C:\loadtest\runs\<Name>\:
#   meta.json        parameters, start / end, DocScan version, server CPU / RAM
#   gen-<user>.csv   actions of every user (loadgen.ps1); probe-<user>.csv - the single files of -ProbeUsers
#   perf.csv         every 5 s: CPU %, free RAM, watcher CPU % / memory, yara64 processes, disk queue,
#                    size of docscan-results.json, live loadgen processes
#   docscan-results.json[.N], watcher.log[.N]   copies after the run, rotated ones included (the report keeps
#                    records from the run time)
#   done.txt         written last
# After the loadgen processes end the run waits for the watcher to catch up: until every created file has a scan
# line in watcher.log (progress in drain.log), or no new scan for 15 min (stalled), at most -DrainMinutes.

param(
  [int]$Users = 25,
  [string]$Prefix = "lt",
  [int]$Minutes = 20,
  [int]$IntervalSec = 20,
  [int]$Burst = 0,
  [switch]$All,             # stress: every user copies the whole test set to the desktop at once (loadgen.ps1 -All)
  [int]$ProbeUsers = 0,     # + this many users also drop one single file every 30 s into Downloads (loadgen -Probe)
  [int]$ProbeMinutes = 30,
  [string]$Name = "",
  [int]$DrainMinutes = 30,
  [string]$Root = "C:\loadtest",
  [string]$Data = "C:\ProgramData\DocScan"
)
$ErrorActionPreference = "Stop"
if (-not $Name) { $Name = Get-Date -Format "yyyyMMdd-HHmmss" }
$run = Join-Path $Root "runs\$Name"
New-Item -ItemType Directory -Force $run | Out-Null
$res = Join-Path $Data "results\docscan-results.json"
$wlog = Join-Path $Data "results\watcher.log"
$cores = (Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors

$start = Get-Date
$meta = [ordered]@{
  name = $Name; start = $start.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz"); end = $null
  users = $Users; minutes = $Minutes; interval_sec = $IntervalSec; burst = $Burst; all = [bool]$All
  probe_users = $ProbeUsers; probe_minutes = $ProbeMinutes
  docscan = [string](Get-Content "$env:ProgramFiles\DocScan\VERSION.txt" -TotalCount 1 -EA SilentlyContinue)
  cpu = $cores; ram_gb = [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory / 1GB, 1)
  sessions = @(quser 2>$null | Select -Skip 1).Count
}
$meta | ConvertTo-Json | Set-Content (Join-Path $run "meta.json") -Encoding UTF8

$procs = for ($i = 1; $i -le $Users; $i++) {
  $u = "{0}{1:D2}" -f $Prefix, $i
  $a = "-NoProfile -ExecutionPolicy Bypass -File `"$PSScriptRoot\loadgen.ps1`" -User $u -Log `"$run\gen-$u.csv`" -Docs `"$Root\docs`"" +
       " -Minutes $Minutes -IntervalSec $IntervalSec -Burst $Burst -Seed $i" + $(if ($All) { " -All" } else { "" })
  Start-Process powershell.exe -ArgumentList $a -WindowStyle Hidden -PassThru
}

# paths with a scan line in watcher.log (and its rotated copy) since the start of the run
$scanRe = [regex]'^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \[(?:OK|HIT|WARN|ERROR)\] \S+\s+(?:document|general)\s+(.*)$'
function Get-Scanned {
  $set = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
  $from = $start.ToString("yyyy-MM-dd HH:mm:ss")
  foreach ($f in "$wlog.1", $wlog) {
    if (-not (Test-Path $f)) { continue }
    $fs = [IO.File]::Open($f, 'Open', 'Read', 'ReadWrite'); $sr = New-Object IO.StreamReader($fs)
    while ($null -ne ($l = $sr.ReadLine())) {
      $m = $scanRe.Match($l)
      if (-not $m.Success -or $m.Groups[1].Value -lt $from) { continue }
      # "<path>  <what>": a path may itself hold two spaces - every cut at "  " is a candidate
      $rest = $m.Groups[2].Value.TrimEnd(); $i = $rest.IndexOf("  ")
      while ($i -ge 0) { [void]$set.Add($rest.Substring(0, $i)); $i = $rest.IndexOf("  ", $i + 1) }
      [void]$set.Add($rest)
    }
    $sr.Close()
  }
  return ,$set
}

$procs = @($procs) + @(for ($i = 1; $i -le $ProbeUsers; $i++) {
  $u = "{0}{1:D2}" -f $Prefix, $i
  $a = "-NoProfile -ExecutionPolicy Bypass -File `"$PSScriptRoot\loadgen.ps1`" -User $u -Log `"$run\probe-$u.csv`" -Docs `"$Root\docs`"" +
       " -Minutes $ProbeMinutes -IntervalSec 30 -Seed $(100 + $i) -Probe"
  Start-Process powershell.exe -ArgumentList $a -WindowStyle Hidden -PassThru
})

$perf = New-Object IO.StreamWriter((Join-Path $run "perf.csv"), $false, (New-Object Text.UTF8Encoding($false)))
$perf.AutoFlush = $true
$perf.WriteLine("time,cpu_pct,free_ram_mb,watcher_cpu_pct,watcher_ws_mb,yara64,disk_queue,results_bytes,loadgen_alive")
$prevCpu = $null; $prevT = $null
$genDone = $null
while ($true) {
  $now = Get-Date
  $cpu = (Get-CimInstance Win32_PerfFormattedData_PerfOS_Processor -Filter "Name='_Total'").PercentProcessorTime
  $free = [int]((Get-CimInstance Win32_OperatingSystem).FreePhysicalMemory / 1KB)
  $wp = Get-CimInstance Win32_Process | ? { $_.Name -eq 'docscan-watcher.exe' -or ($_.Name -eq 'powershell.exe' -and $_.CommandLine -match "docscan-watcher\.ps1'") } | Select -First 1
  $wcpu = ""; $wws = ""
  if ($wp) {
    $p = Get-Process -Id $wp.ProcessId -EA SilentlyContinue
    if ($p) {
      $t = $p.TotalProcessorTime.TotalSeconds
      if ($prevCpu -ne $null) { $wcpu = [math]::Round(100 * ($t - $prevCpu) / ($now - $prevT).TotalSeconds / $cores, 1) }
      $prevCpu = $t; $prevT = $now; $wws = [int]($p.WorkingSet64 / 1MB)
    }
  }
  $yc = @(Get-Process yara64 -EA SilentlyContinue).Count
  $dq = (Get-CimInstance Win32_PerfFormattedData_PerfDisk_PhysicalDisk -Filter "Name='_Total'").CurrentDiskQueueLength
  $size = if (Test-Path $res) { (Get-Item $res).Length } else { 0 }
  $alive = @($procs | ? { -not $_.HasExited }).Count
  $perf.WriteLine(($now.ToString("yyyy-MM-ddTHH:mm:ss.fffzzz"), $cpu, $free, $wcpu, $wws, $yc, $dq, $size, $alive) -join ",")

  # Done when every file the users created / renamed (and that is still there) has a scan line in watcher.log.
  # A quiet watcher is NOT done: the old one sat silent for hours on its event queue. Stalled = no new scan for
  # 15 min; at most -DrainMinutes after the users finished.
  if ($alive -eq 0) {
    if (-not $genDone) {
      $genDone = $now
      $targets = New-Object 'Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
      foreach ($g in Get-ChildItem "$run\gen-*.csv", "$run\probe-*.csv") {
        foreach ($r in (Import-Csv $g.FullName)) { if (-not $r.error -and ($r.action -in "new", "rename", "edit", "probe")) { [void]$targets.Add($r.path) } }
      }
      $lastScans = -1; $lastProgress = $now; $nextCheck = $now
    }
    if ($now -ge $nextCheck) {
      $nextCheck = $now.AddSeconds(60)
      $scanned = Get-Scanned
      $left = 0
      foreach ($t in $targets) { if (-not $scanned.Contains($t) -and (Test-Path -LiteralPath $t)) { $left++ } }
      if ($scanned.Count -ne $lastScans) { $lastScans = $scanned.Count; $lastProgress = $now }
      Add-Content (Join-Path $run "drain.log") ("{0:HH:mm:ss} scanned paths {1}, left {2}" -f $now, $scanned.Count, $left)
      if ($left -eq 0) { break }
      if (($now - $lastProgress).TotalMinutes -ge 15) { Add-Content (Join-Path $run "drain.log") "stalled: no new scan for 15 min"; break }
      if (($now - $genDone).TotalMinutes -ge $DrainMinutes) { Add-Content (Join-Path $run "drain.log") "-DrainMinutes reached"; break }
    }
  }
  Start-Sleep -Seconds 5
}
$perf.Close()

# with the rotated copies (.1 .. .5): a long run can fill more than one 50 MB file
foreach ($f in @($res, $wlog) + (1..5 | % { "$res.$_"; "$wlog.$_" })) {
  if ((Test-Path $f) -and (Get-Item $f).LastWriteTime -ge $start) { Copy-Item $f $run -Force }
}
$meta.end = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")
$meta | ConvertTo-Json | Set-Content (Join-Path $run "meta.json") -Encoding UTF8
Set-Content (Join-Path $run "done.txt") $meta.end
