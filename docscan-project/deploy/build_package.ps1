# DocScan - build the deployment package (on the machine where yara64.exe was built).
#
#   powershell -ExecutionPolicy Bypass -File build_package.ps1 [-Repo C:\docscan-build\yara] [-Out C:\docscan-build\dist]
#
# Result: <Out>\DocScan-<version>.zip - unpack it on the target machine and run install.ps1.
param(
  [string]$Repo = "C:\docscan-build\yara",
  [string]$Out  = "C:\docscan-build\dist",
  [string]$Version = ""          # default <date>-<git commit> or <date>-local
)
$ErrorActionPreference = "Stop"
$exe = "$Repo\windows\vs2019\Release\yara64.exe"
if (-not (Test-Path $exe)) { throw "$exe is missing - build yara64.exe first (MSBuild)" }

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
# yarac64.exe: the watcher compiles the rules with it once at start (without it every file scan recompiles them)
$yarac = Join-Path (Split-Path $exe) "yarac64.exe"
if (-not (Test-Path $yarac)) { throw "$yarac is missing - build it too (MSBuild /t:yara;yarac)" }
Copy-Item $yarac "$stage\bin\"
$crt = Get-ChildItem "${env:ProgramFiles(x86)}\Microsoft Visual Studio\2022\BuildTools\VC\Redist\MSVC" -Recurse -Filter vcruntime140.dll |
       ? { $_.FullName -match '\\x64\\Microsoft\.VC\d+\.CRT\\' -and $_.FullName -notmatch 'onecore|debug' } | Select -First 1
if (-not $crt) { throw "vcruntime140.dll not found in VC\Redist" }
Copy-Item $crt.FullName, (Join-Path $crt.DirectoryName "vcruntime140_1.dll") "$stage\bin\"

# rules: policy + indexes + vendor subsets
Copy-Item "$Repo\docscan-project\rules" "$stage\rules" -Recurse
Copy-Item "$Repo\docscan-project\watcher\docscan-watcher.ps1" "$stage\watcher\"
foreach ($f in "install.ps1", "uninstall.ps1", "README.txt") { Copy-Item "$Repo\docscan-project\deploy\$f" $stage }
# for the Wazuh administrator: manager cleanup script + rule block (not used on workstations)
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
Write-Host ("Package: {0}  ({1:N1} MB, {2} files)" -f $zip, ((Get-Item $zip).Length / 1MB), $lines.Count)
