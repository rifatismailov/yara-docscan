# DocScan - regression test on Windows.
#
# For every file in test-samples (the originals are NOT touched):
#   1) copy -> C:\docscan-build\work.<ext>
#   2) run 1: yara64.exe --docscan-json --docscan-disarm   (detection + disarm)
#   3) run 2: yara64.exe --docscan-json                    (rescan of the disarmed copy)
#   4) the copy and the backup are deleted
# At the end - SHA256 check: the originals did not change.
#
# Run:
#   powershell -ExecutionPolicy Bypass -File C:\docscan-build\run_tests.ps1
#   (parameters can be overridden: -Samples D:\x -Rules D:\rules\docscan-index.yar)

param(
  [string]$Yara    = "C:\docscan-build\yara\windows\vs2019\Release\yara64.exe",
  # default - rules and samples from this repo (full set: policy + vendor)
  [string]$Rules   = (Join-Path $PSScriptRoot "..\rules\docscan-index.yar"),
  [string]$Samples = (Join-Path $PSScriptRoot "..\test-samples"),
  [string]$WorkDir = "C:\docscan-build"
)

foreach ($p in $Yara, $Rules, $Samples) {
  if (-not (Test-Path $p)) { Write-Host "NOT FOUND: $p" -ForegroundColor Red; exit 1 }
}

$files = Get-ChildItem $Samples -Recurse -File | Sort-Object FullName
$hashBefore = @{}
foreach ($f in $files) { $hashBefore[$f.FullName] = (Get-FileHash $f.FullName).Hash }

Write-Host "yara64: $(& $Yara --version)   rules: $Rules   files: $($files.Count)`n"

$results = foreach ($f in $files) {
  $work = Join-Path $WorkDir "work$($f.Extension)"
  Remove-Item $work, "$work.docscan-bak" -Force -ErrorAction SilentlyContinue
  Copy-Item $f.FullName $work -Force

  # run 1: detection + disarm
  $out    = & $Yara --docscan-json --docscan-disarm $Rules $work 2>&1 | ForEach-Object { "$_" }
  $json   = $out | Where-Object { $_ -like '{*' } | Select-Object -First 1
  $action = ($out | Where-Object { $_ -like 'docscan-disarm:*' }) -replace '^docscan-disarm: .* -> ', ''
  if (-not $action) { $action = "-" }
  $scan = if ($json) { $json | ConvertFrom-Json } else { $null }

  # run 2: rescan after disarm
  if (Test-Path $work) {
    $j2 = & $Yara --docscan-json $Rules $work 2>&1 | Where-Object { "$_" -like '{*' } | Select-Object -First 1
    $after = if ($j2) { ("$j2" | ConvertFrom-Json).verdict } else { "?" }
  } else {
    $after = "DELETED"
  }
  $backup = Test-Path "$work.docscan-bak"
  Remove-Item $work, "$work.docscan-bak" -Force -ErrorAction SilentlyContinue

  [pscustomobject]@{
    File     = $f.FullName.Substring($Samples.Length).TrimStart('\')
    Verdict  = if ($scan) { $scan.verdict } else { "ERROR" }
    Findings = if ($scan) { $scan.findings -join ',' } else { ($out -join ' ') }
    Disarm   = $action
    After    = $after
    Backup   = $backup
    Json     = $json
  }
}

$results | Format-Table File, Verdict, Findings, Disarm, After, Backup -AutoSize -Wrap | Out-String -Width 250 | Write-Host

Write-Host "--- JSON (run 1) ---"
foreach ($r in $results) { Write-Host "$($r.File)`n  $($r.Json)" }

# summary
$errors  = @($results | Where-Object { $_.Verdict -eq 'ERROR' })
$changed = @($files | Where-Object { (Get-FileHash $_.FullName).Hash -ne $hashBefore[$_.FullName] })
Write-Host "`n=== SUMMARY ==="
Write-Host ("Verdicts:      " + (($results | Group-Object Verdict | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  '))
Write-Host ("After disarm:  " + (($results | Group-Object After   | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  '))
if ($errors.Count) { Write-Host "Scan errors: $($errors.Count) -> $($errors.File -join ', ')" -ForegroundColor Red }
if ($changed.Count -eq 0) {
  Write-Host "Originals unchanged ($($files.Count) files, SHA256 matches)" -ForegroundColor Green
} else {
  Write-Host "WARNING: originals changed: $($changed.FullName -join ', ')" -ForegroundColor Red
}
