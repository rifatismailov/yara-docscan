# Document regression for Windows without Python - the same check as check_verdicts.py.
# For every sample: copy -> yara64 --docscan-json --docscan-disarm (verdict, disarm action)
# -> rescan the cured copy (verdict after, or DELETED); compare with expected-verdicts.tsv;
# the originals must not change. Exit 0 = PASS.
#
#   powershell -ExecutionPolicy Bypass -File check_verdicts.ps1 -Yara yara64.exe -Rules docscan-index.yar `
#     -Samples test-samples\generated -Expected expected-verdicts.tsv [-WorkDir C:\ci\tmp]
param(
  [Parameter(Mandatory)][string]$Yara,
  [Parameter(Mandatory)][string]$Rules,
  [Parameter(Mandatory)][string]$Samples,
  [Parameter(Mandatory)][string]$Expected,
  [string]$WorkDir = $env:TEMP
)

function Scan([string]$path, [bool]$disarm, [string]$bak) {
  $a = @("-w", "--docscan-json")
  if ($disarm) { $a += @("--docscan-disarm", "--docscan-backup-dir=$bak") }
  $out = & $Yara @a $Rules $path 2>&1 | ForEach-Object { "$_" }
  $verdict = "ERROR"; $action = "-"
  foreach ($l in $out) {
    if ($l -like '{*') { try { $verdict = ($l | ConvertFrom-Json).verdict } catch { } }
    elseif ($l -like 'docscan-disarm:*') { $action = ($l -split ' -> ')[-1].Trim() }
  }
  return @($verdict, $action)
}

function Remove-Retry([string]$p) {
  for ($i = 1; $i -le 20; $i++) {
    if (-not (Test-Path -LiteralPath $p)) { return }
    try { Remove-Item -LiteralPath $p -Force -ErrorAction Stop; return } catch { Start-Sleep -Milliseconds (250 * $i) }
  }
}

$tmp = Join-Path $WorkDir ("cv-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
$bak = Join-Path $tmp "backup"
New-Item -ItemType Directory -Force $bak | Out-Null
$files = @(Get-ChildItem -LiteralPath $Samples -File | Sort-Object Name)
$before = @{}; foreach ($f in $files) { $before[$f.Name] = (Get-FileHash -LiteralPath $f.FullName).Hash }

$exp = @{}
foreach ($l in Get-Content -LiteralPath $Expected -Encoding UTF8) {
  if (-not $l.Trim() -or $l.StartsWith("#")) { continue }
  $p = $l -split "`t"; $exp[$p[0]] = ($p[1..3] -join "`t")
}

$fails = 0
"{0,-30} {1,-8} {2,-12} {3,-8}" -f "file", "verdict", "disarm", "after"
foreach ($f in $files) {
  $work = Join-Path $tmp ("work" + $f.Extension)
  Copy-Item -LiteralPath $f.FullName $work -Force
  $r = Scan $work $true $bak
  $after = if (Test-Path -LiteralPath $work) { (Scan $work $false $bak)[0] } else { "DELETED" }
  $kind = ($r[1] -split '[:,]')[0]
  $got = "$($r[0])`t$kind`t$after"
  $ok = $exp[$f.Name] -eq $got
  if (-not $ok) { $fails++ }
  "{0,-30} {1,-8} {2,-12} {3,-8} {4}" -f $f.Name, $r[0], $kind, $after, $(if ($ok) { "ok" } else { "FAIL (expected $($exp[$f.Name] -replace "`t", ' / '))" })
  Remove-Retry $work
}
$missing = @($exp.Keys | Where-Object { -not (Test-Path -LiteralPath (Join-Path $Samples $_)) })
foreach ($m in $missing) { "{0,-30} missing sample (antivirus?)" -f $m }
$changed = @($files | Where-Object { (Get-FileHash -LiteralPath $_.FullName).Hash -ne $before[$_.Name] })
if ($changed.Count) { "ORIGINALS CHANGED: " + ($changed.Name -join ", ") } else { "originals unchanged" }
Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
$total = $fails + $missing.Count + $changed.Count
"RESULT: {0} ({1} problem(s))" -f $(if ($total -eq 0) { "PASS" } else { "FAIL" }), $total
exit $(if ($total -eq 0) { 0 } else { 1 })
