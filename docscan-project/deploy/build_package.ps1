# DocScan — збірка пакета розгортання (на машині, де зібрано yara64.exe).
#
#   powershell -ExecutionPolicy Bypass -File build_package.ps1 [-Repo C:\docscan-build\yara] [-Out C:\docscan-build\dist]
#
# Результат: <Out>\DocScan-<версія>.zip — розпакувати на цільовій машині й запустити install.ps1.
param(
  [string]$Repo = "C:\docscan-build\yara",
  [string]$Out  = "C:\docscan-build\dist",
  [string]$Version = ""          # за замовч. <дата>-<git-коміт> або <дата>-local
)
$ErrorActionPreference = "Stop"
$exe = "$Repo\windows\vs2019\Release\yara64.exe"
if (-not (Test-Path $exe)) { throw "немає $exe — спершу зберіть yara64.exe (MSBuild)" }

$ver = $Version
if (-not $ver) {
  $commit = $null
  try { $commit = (& git -C $Repo rev-parse --short HEAD 2>$null) } catch { }
  if (-not $commit) { $commit = "local" }
  $ver = "{0}-{1}" -f (Get-Date -Format "yyyyMMdd"), $commit
}
$stage = Join-Path $Out "DocScan-$ver"
Remove-Item $stage -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory -Force "$stage\bin", "$stage\watcher" | Out-Null

# yara64.exe + VC++ runtime (yara64 is built with /MD and needs VCRUNTIME140.dll;
# the CRT itself is the Universal CRT that ships with Windows 10/11)
Copy-Item $exe "$stage\bin\"
# yarac64.exe: вотчер компілює ним правила раз на старті (без нього скан кожного файлу компілює їх заново)
$yarac = Join-Path (Split-Path $exe) "yarac64.exe"
if (-not (Test-Path $yarac)) { throw "немає $yarac — зберіть і його (MSBuild /t:yara;yarac)" }
Copy-Item $yarac "$stage\bin\"
$crt = Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Redist\MSVC" -Recurse -Filter vcruntime140.dll |
       ? { $_.FullName -match '\\x64\\Microsoft\.VC\d+\.CRT\\' -and $_.FullName -notmatch 'onecore|debug' } | Select -First 1
if (-not $crt) { throw "не знайдено vcruntime140.dll у VC\Redist" }
Copy-Item $crt.FullName, (Join-Path $crt.DirectoryName "vcruntime140_1.dll") "$stage\bin\"

# rules: policy + indexes + vendor subsets
Copy-Item "$Repo\docscan-project\rules" "$stage\rules" -Recurse
Copy-Item "$Repo\docscan-project\watcher\docscan-watcher.ps1" "$stage\watcher\"
foreach ($f in "install.ps1", "uninstall.ps1", "README.txt") { Copy-Item "$Repo\docscan-project\deploy\$f" $stage }
# для адміністратора Wazuh: скрипт прибирання менеджера + блок правил (на робочих машинах не використовуються)
Copy-Item "$Repo\docscan-project\deploy\manager" "$stage\manager" -Recurse
"DocScan $ver`r`nyara64 $(& $exe --version)`r`nbuilt $(Get-Date -Format s) on $env:COMPUTERNAME" | Set-Content "$stage\VERSION.txt"

# checksums of every file (install.ps1 verifies them)
$lines = Get-ChildItem $stage -Recurse -File | ? { $_.Name -ne "SHA256SUMS.txt" } | % {
  "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $_.FullName.Substring($stage.Length + 1)
}
$lines | Set-Content "$stage\SHA256SUMS.txt" -Encoding ASCII

$zip = "$stage.zip"
Remove-Item $zip -EA SilentlyContinue
Compress-Archive -Path "$stage\*" -DestinationPath $zip
Write-Host ("Пакет: {0}  ({1:N1} MB, {2} файлів)" -f $zip, ((Get-Item $zip).Length / 1MB), $lines.Count)
