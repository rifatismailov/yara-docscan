# DocScan — перевірка вендорних правил-кандидатів на хибні спрацювання (FP) на чистій Windows.
#
#   powershell -ExecutionPolicy Bypass -File fp_scan.ps1 -Rules C:\docscan-build\s2\cand.yarc
#
# -Rules: скомпільований набір (yarac з -d filename= -d filepath= -d extension= -d filetype= -d owner=,
#         кожен файл-кандидат у своєму namespace — тоді в результаті видно, з якого файлу правило).
# Сканує чисті системні теки (за замовч. Windows, Program Files, ProgramData) з --file-vars, тож
# THOR-правила зі змінними filename/extension оцінюються як у вотчері.
# Результат у -Out: hits.txt (namespace:rule шлях), summary.txt (скільки файлів спрацювало на правило).
# Правило з будь-яким збігом на чистій системі в набір не йде.

param(
  [Parameter(Mandatory)][string]$Rules,
  [string]  $Yara  = "C:\docscan-build\yara\windows\vs2019\Release\yara64.exe",
  [string]  $Out   = "C:\docscan-build\s2\fp",
  [string[]]$Paths = @("C:\Windows", "C:\Program Files", "C:\Program Files (x86)", "C:\ProgramData"),
  [int]     $MaxSizeMB = 100,
  [int]     $Threads = 4
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force $Out | Out-Null
$hits = Join-Path $Out "hits.txt"; $err = Join-Path $Out "errors.txt"
Remove-Item $hits, $err -ErrorAction SilentlyContinue
$t0 = Get-Date
foreach ($p in $Paths) {
  if (-not (Test-Path $p)) { continue }
  "{0:HH:mm:ss} scan $p" -f (Get-Date) | Tee-Object -Append (Join-Path $Out "progress.txt")
  # -e: namespace у виводі; -z: пропускати великі файли, як вотчер; помилки доступу -> errors.txt.
  # Через cmd: у PowerShell 5.1 stderr нативної програми з ErrorActionPreference=Stop обриває скрипт.
  cmd /c "`"$Yara`" -w -e --file-vars -C -r -p $Threads -z $($MaxSizeMB * 1MB) `"$Rules`" `"$p`" >> `"$hits`" 2>> `"$err`""
}
$lines = if (Test-Path $hits) { Get-Content $hits -Encoding utf8 } else { @() }
$lines | ForEach-Object { ($_ -split ' ', 2)[0] } | Group-Object | Sort-Object Count -Descending |
  ForEach-Object { "{0,6}  {1}" -f $_.Count, $_.Name } | Out-File -Encoding utf8 (Join-Path $Out "summary.txt")
"done in {0:N0} min; hits {1}; rules with FP {2}" -f ((Get-Date) - $t0).TotalMinutes, $lines.Count,
  (Get-Content (Join-Path $Out "summary.txt")).Count | Tee-Object -Append (Join-Path $Out "progress.txt")
