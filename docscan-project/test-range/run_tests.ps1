# DocScan — регресійний тест на Windows (216).
#
# Для кожного файлу з test-samples (оригінали НЕ чіпаються):
#   1) копія -> C:\docscan-build\work.<ext>
#   2) прогін 1: yara64.exe --docscan-json --docscan-disarm   (детект + лікування)
#   3) прогін 2: yara64.exe --docscan-json                    (повторний скан вилікуваної копії)
#   4) копія і бекап видаляються
# Наприкінці — перевірка SHA256: оригінали не змінились.
#
# Запуск:
#   powershell -ExecutionPolicy Bypass -File C:\docscan-build\run_tests.ps1
#   (параметри можна перевизначити: -Samples D:\x -Rules C:\docscan-build\docscan.yar)

param(
  [string]$Yara    = "C:\docscan-build\yara\windows\vs2019\Release\yara64.exe",
  [string]$Rules   = "C:\docscan-build\docscan.yar",
  [string]$Samples = "C:\docscan-build\test-samples",
  [string]$WorkDir = "C:\docscan-build"
)

foreach ($p in $Yara, $Rules, $Samples) {
  if (-not (Test-Path $p)) { Write-Host "НЕ ЗНАЙДЕНО: $p" -ForegroundColor Red; exit 1 }
}

$files = Get-ChildItem $Samples -Recurse -File | Sort-Object FullName
$hashBefore = @{}
foreach ($f in $files) { $hashBefore[$f.FullName] = (Get-FileHash $f.FullName).Hash }

Write-Host "yara64: $(& $Yara --version)   правила: $Rules   файлів: $($files.Count)`n"

$results = foreach ($f in $files) {
  $work = Join-Path $WorkDir "work$($f.Extension)"
  Remove-Item $work, "$work.docscan-bak" -Force -ErrorAction SilentlyContinue
  Copy-Item $f.FullName $work -Force

  # прогін 1: детект + лікування
  $out    = & $Yara --docscan-json --docscan-disarm $Rules $work 2>&1 | ForEach-Object { "$_" }
  $json   = $out | Where-Object { $_ -like '{*' } | Select-Object -First 1
  $action = ($out | Where-Object { $_ -like 'docscan-disarm:*' }) -replace '^docscan-disarm: .* -> ', ''
  if (-not $action) { $action = "-" }
  $scan = if ($json) { $json | ConvertFrom-Json } else { $null }

  # прогін 2: повторний скан після лікування
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

Write-Host "--- JSON (прогін 1) ---"
foreach ($r in $results) { Write-Host "$($r.File)`n  $($r.Json)" }

# підсумок
$errors  = @($results | Where-Object { $_.Verdict -eq 'ERROR' })
$changed = @($files | Where-Object { (Get-FileHash $_.FullName).Hash -ne $hashBefore[$_.FullName] })
Write-Host "`n=== ПІДСУМОК ==="
Write-Host ("Вердикти:    " + (($results | Group-Object Verdict | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  '))
Write-Host ("Після лікув.: " + (($results | Group-Object After   | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join '  '))
if ($errors.Count) { Write-Host "Помилки скану: $($errors.Count) -> $($errors.File -join ', ')" -ForegroundColor Red }
if ($changed.Count -eq 0) {
  Write-Host "Оригінали не змінені ($($files.Count) файлів, SHA256 збігається)" -ForegroundColor Green
} else {
  Write-Host "УВАГА: змінено оригінали: $($changed.FullName -join ', ')" -ForegroundColor Red
}
