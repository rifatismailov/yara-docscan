# DocScan load test: file activity of ONE user in their profile (run by rds_load.ps1, one process per user).
#
#   loadgen.ps1 -User lt01 -Log <csv> [-Docs C:\loadtest\docs] [-Minutes 20] [-IntervalSec 20] [-Burst 0] [-Seed 1]
# Works in C:\Users\<User>\{Desktop,Documents,Downloads}\lt (the watcher watches C:\Users). Actions:
#   -All       stress: copy the WHOLE set to Desktop\lt-all (folder structure kept) as fast as possible, then stop;
#   -Probe     one single file every IntervalSec into Downloads\probe for Minutes (action "probe"): what a user
#              downloads while a burst is being scanned - its latency is what the user feels;
#   -Burst N   first N new files at once (a folder copied / an archive unpacked);
#   then every IntervalSec * 0.5..1.5 s one action: 60% new (copy of a random test document), 25% edit (the
#   same file overwritten with another document of the same type = a saved change), 10% rename, 5% delete.
# Only the extensions the watcher scans are used (its default lists + the critical-check text formats).
# Every action goes to the CSV log (time with ms and offset, action, path, source, error) - loadtest_report.py
# matches it with the watcher's records.

param(
  [Parameter(Mandatory = $true)][string]$User,
  [Parameter(Mandatory = $true)][string]$Log,
  [string]$Docs = "C:\loadtest\docs",
  [int]$Minutes = 20,
  [int]$IntervalSec = 20,
  [int]$Burst = 0,
  [int]$Seed = 0,
  [switch]$All,
  [switch]$Probe
)
$ErrorActionPreference = "Stop"

$ext = @(
  ".doc", ".dot", ".docx", ".docm", ".dotx", ".dotm", ".xls", ".xlt", ".xlsx", ".xlsm", ".xltx", ".xltm", ".xlsb",
  ".ppt", ".pps", ".pot", ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm", ".xla", ".xlam", ".ppa", ".ppam",
  ".rtf", ".pdf", ".lnk", ".one", ".iqy", ".slk",
  ".exe", ".dll", ".sys", ".scr", ".cpl", ".ocx", ".com", ".msi", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse",
  ".wsf", ".wsh", ".hta", ".bat", ".cmd", ".jar", ".xll", ".msc", ".url", ".svg", ".htm", ".html",
  ".zip", ".rar", ".7z", ".iso", ".img", ".vhd", ".vhdx",
  ".odt", ".ods", ".odp", ".txt", ".csv")
$pool = @(Get-ChildItem -LiteralPath $Docs -Recurse -File | ? { $ext -contains $_.Extension.ToLower() -and $_.Length -le 100MB })
if (-not $pool.Count) { throw "no test documents in $Docs" }
$byExt = @{}
foreach ($f in $pool) { $e = $f.Extension.ToLower(); if (-not $byExt[$e]) { $byExt[$e] = New-Object Collections.ArrayList }; [void]$byExt[$e].Add($f) }

$dirs = foreach ($d in "Desktop", "Documents", "Downloads") {
  $p = "C:\Users\$User\$d\lt"
  New-Item -ItemType Directory -Force $p | Out-Null
  $p
}
$rnd = if ($Seed) { New-Object Random $Seed } else { New-Object Random }
$mine = New-Object Collections.Generic.List[string]
$script:n = 0

$utf8 = New-Object Text.UTF8Encoding($false)
$w = New-Object IO.StreamWriter($Log, $true, $utf8)
$w.AutoFlush = $true
$w.WriteLine("time,user,action,path,src,error")
function Q([string]$s) { '"' + ($s -replace '"', '""') + '"' }
function W($action, $path, $src, $err) {
  $t = (Get-Date).ToString("yyyy-MM-ddTHH:mm:ss.fffzzz")
  $w.WriteLine(($t, $User, $action, (Q $path), (Q $src), (Q $err)) -join ",")
}
function New-Name($src, $dir) {
  $script:n++
  $b = [IO.Path]::GetFileNameWithoutExtension($src)
  if ($b.Length -gt 40) { $b = $b.Substring(0, 40) }
  Join-Path $dir ("{0}_{1}_{2:D5}{3}" -f $User, $b, $script:n, [IO.Path]::GetExtension($src).ToLower())
}
function Pick-Mine {
  while ($mine.Count) {
    $i = $rnd.Next($mine.Count); $p = $mine[$i]
    if (Test-Path -LiteralPath $p) { return $p }
    $mine.RemoveAt($i)   # moved to quarantine by the watcher, or gone
  }
  return $null
}
function Act-New {
  $src = $pool[$rnd.Next($pool.Count)]
  $dst = New-Name $src.Name $dirs[$rnd.Next($dirs.Count)]
  try { Copy-Item -LiteralPath $src.FullName $dst; $mine.Add($dst); W "new" $dst $src.FullName "" }
  catch { W "new" $dst $src.FullName $_.Exception.Message }
}
function Act-Edit {
  $p = Pick-Mine; if (-not $p) { Act-New; return }
  $c = $byExt[[IO.Path]::GetExtension($p).ToLower()]
  $src = $c[$rnd.Next($c.Count)]
  try { Copy-Item -LiteralPath $src.FullName $p -Force; W "edit" $p $src.FullName "" }
  catch { W "edit" $p $src.FullName $_.Exception.Message }
}
function Act-Rename {
  $p = Pick-Mine; if (-not $p) { Act-New; return }
  $new = New-Name $p (Split-Path $p)
  try { Rename-Item -LiteralPath $p ([IO.Path]::GetFileName($new)); $mine.Remove($p) | Out-Null; $mine.Add($new); W "rename" $new $p "" }
  catch { W "rename" $new $p $_.Exception.Message }
}
function Act-Delete {
  $p = Pick-Mine; if (-not $p) { Act-New; return }
  try { Remove-Item -LiteralPath $p -Force; $mine.Remove($p) | Out-Null; W "delete" $p "" "" }
  catch { W "delete" $p "" $_.Exception.Message }
}

try {
  if ($All) {
    $root = (Resolve-Path -LiteralPath $Docs).Path.TrimEnd('\')
    $to = "C:\Users\$User\Desktop\lt-all"
    foreach ($src in $pool) {
      $dst = Join-Path $to $src.FullName.Substring($root.Length + 1)
      try {
        $d = Split-Path $dst
        if (-not (Test-Path -LiteralPath $d)) { New-Item -ItemType Directory -Force $d | Out-Null }
        Copy-Item -LiteralPath $src.FullName $dst -Force
        W "new" $dst $src.FullName ""
      } catch { W "new" $dst $src.FullName $_.Exception.Message }
    }
    return
  }
  if ($Probe) {
    $pd = "C:\Users\$User\Downloads\probe"
    New-Item -ItemType Directory -Force $pd | Out-Null
    $end = (Get-Date).AddMinutes($Minutes)
    while ((Get-Date) -lt $end) {
      $src = $pool[$rnd.Next($pool.Count)]
      $dst = New-Name $src.Name $pd
      try { Copy-Item -LiteralPath $src.FullName $dst; W "probe" $dst $src.FullName "" }
      catch { W "probe" $dst $src.FullName $_.Exception.Message }
      Start-Sleep -Seconds $IntervalSec
    }
    return
  }
  for ($i = 0; $i -lt $Burst; $i++) { Act-New }
  $end = (Get-Date).AddMinutes($Minutes)
  while ((Get-Date) -lt $end) {
    Start-Sleep -Milliseconds ([int](1000 * $IntervalSec * (0.5 + $rnd.NextDouble())))
    $r = $rnd.NextDouble()
    if ($r -lt 0.60) { Act-New } elseif ($r -lt 0.85) { Act-Edit } elseif ($r -lt 0.95) { Act-Rename } else { Act-Delete }
  }
} finally { $w.Close() }
