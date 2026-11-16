# DocScan - install from an HTTP server (main script).
#
# Normally started by the bootstrap DocScan-Setup.ps1 (irm <BaseUrl>/DocScan-Setup.ps1 | iex).
# Directly, PowerShell AS ADMINISTRATOR:
#   powershell -ExecutionPolicy Bypass -File .\DocScan-Install.ps1 -BaseUrl http://<server>:8080 [-DetectOnly]
#
# What it does:
#   1) reads the current package name from <BaseUrl>/DocScan-latest.txt (or -Version);
#   2) downloads DocScan-<version>.zip and .sha256, checks the SHA256 (stops on mismatch);
#   3) unpacks it into a temp folder and runs install.ps1 with the given parameters
#      (the program - bin\ - is a GitHub release asset: downloaded from the address in BIN-URL.txt;
#      a package that still contains bin\ is installed as it is)
#      (install.ps1 checks every file again against SHA256SUMS.txt inside the package);
#   4) removes the temp files.
# Update: put the new zip + .sha256 on the server and its name into DocScan-latest.txt; this script stays the same.

param(
  [string]  $BaseUrl = "",          # e.g. http://<server>:8080 (folder with the package and DocScan-latest.txt)
  [string]  $Version = "",          # e.g. 20261106-f1d0b6a7; empty - from DocScan-latest.txt
  [switch]  $DetectOnly,            # -> install.ps1 -DetectOnly
  [switch]  $NoAvExclusion,         # -> install.ps1 -NoAvExclusion
  [switch]  $QuarantineGeneral,     # -> install.ps1 -QuarantineGeneral
  [string[]]$WatchPath,             # -> install.ps1 -WatchPath
  [switch]  $NoMacroUpload,         # do not send macro code to <BaseUrl> (keep it on the PC only)
  [switch]  $Critical,              # this PC gets the critical-information check: <BaseUrl>/critical-rules.yar (E5Search)
  [switch]  $NoCritical             # -> install.ps1 -NoCritical (turn the check off, remove the rules)
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # without it Invoke-WebRequest in PS 5.1 is very slow

function Fail($m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

# A text file from the server. Via a file, not .Content: for an unknown type (e.g. .sha256 as
# application/octet-stream) PowerShell 5.1 returns a byte array, not a string.
function Get-RemoteText([string]$url) {
  $tmp = [IO.Path]::GetTempFileName()
  try { Invoke-WebRequest -UseBasicParsing $url -OutFile $tmp; return [IO.File]::ReadAllText($tmp) }
  finally { Remove-Item $tmp -Force -ErrorAction SilentlyContinue }
}

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Fail "run PowerShell as Administrator" }
if (-not $BaseUrl) { Fail "-BaseUrl is not set (address of the server with the package)" }
$BaseUrl = $BaseUrl.TrimEnd('/')

# 1) version
if (-not $Version) {
  try { $latest = Get-RemoteText "$BaseUrl/DocScan-latest.txt" }
  catch { Fail "could not read $BaseUrl/DocScan-latest.txt - $($_.Exception.Message)" }
  $pkg = ($latest -split "`r?`n" | Where-Object { $_.Trim() } | Select-Object -First 1).Trim()
} else {
  $pkg = "DocScan-$Version.zip"
}
if ($pkg -notmatch '^DocScan-[\w.-]+\.zip$') { Fail "unexpected package name: '$pkg'" }
Write-Host "==> package: $pkg  ($BaseUrl)" -ForegroundColor Cyan

# 2) download and verify
$work = Join-Path $env:TEMP ("DocScan-setup-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force $work | Out-Null
try {
  $zip = Join-Path $work $pkg
  try {
    Invoke-WebRequest -UseBasicParsing "$BaseUrl/$pkg" -OutFile $zip
    $sumLine = Get-RemoteText "$BaseUrl/$pkg.sha256"
  } catch { Fail "download failed - $($_.Exception.Message)" }
  $expected = (($sumLine.Trim() -split '\s+')[0]).ToLower()
  $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($expected -notmatch '^[0-9a-f]{64}$') { Fail "$pkg.sha256 has no checksum" }
  if ($actual -ne $expected) { Fail "SHA256 mismatch (expected $expected, got $actual) - the package is damaged or replaced" }
  Write-Host "==> SHA256 matches, unpacking" -ForegroundColor Cyan

  # 3) unpack and install
  $dir = Join-Path $work "pkg"
  Expand-Archive $zip $dir -Force
  $inst = Join-Path $dir "install.ps1"
  if (-not (Test-Path $inst)) { Fail "install.ps1 is missing from the package" }

  # 3a) the program (bin\: yara64.exe, yarac64.exe, VC++ runtime) is not on this server: it is a GitHub
  # release asset, its address is in BIN-URL.txt. Trust comes from THIS server: install.ps1 checks the
  # downloaded files against SHA256SUMS.txt of the package, so a replaced file on GitHub is refused.
  $binUrlF = Join-Path $dir "BIN-URL.txt"
  if (-not (Test-Path (Join-Path $dir "bin\yara64.exe")) -and (Test-Path $binUrlF)) {
    $binUrl = ((Get-Content $binUrlF -TotalCount 1) -join "").Trim()
    if ($binUrl -notmatch '^https://github\.com/[\w.-]+/[\w.-]+/releases/download/[\w.-]+/DocScan-bin-[\w.-]+\.zip$') {
      Fail "unexpected program address in BIN-URL.txt: '$binUrl'"
    }
    Write-Host "==> program: $binUrl" -ForegroundColor Cyan
    # GitHub accepts TLS 1.2+ only; Windows PowerShell 5.1 may offer older versions by default
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    $binZip = Join-Path $work "bin.zip"
    try { Invoke-WebRequest -UseBasicParsing $binUrl -OutFile $binZip }
    catch { Fail "could not download the program from GitHub - $($_.Exception.Message)" }
    Expand-Archive $binZip $dir -Force
    if (-not (Test-Path (Join-Path $dir "bin\yara64.exe"))) { Fail "the GitHub release asset has no bin\yara64.exe" }
  }

  # same process with splatting: -File cannot pass arrays (-WatchPath 'C:\Users','D:\Shares')
  $p = @{}
  if ($DetectOnly)        { $p.DetectOnly = $true }
  if ($NoAvExclusion)     { $p.NoAvExclusion = $true }
  if ($QuarantineGeneral) { $p.QuarantineGeneral = $true }
  if ($WatchPath)         { $p.WatchPath = $WatchPath }
  if (-not $NoMacroUpload) { $p.MacroUpload = $BaseUrl }   # macro code copies go to the same server
  # critical-information check (E5Search): only on the PCs it is asked for (lawyer, accountant, HR);
  # without -Critical the rules a PC already has stay as they are
  if ($Critical -and $NoCritical) { Fail "-Critical and -NoCritical together" }
  if ($NoCritical) { $p.NoCritical = $true }
  if ($Critical) {
    $crit = Join-Path $work "critical-rules.yar"
    try { Invoke-WebRequest -UseBasicParsing "$BaseUrl/critical-rules.yar" -OutFile $crit -ErrorAction Stop }
    catch { Fail "-Critical: could not download $BaseUrl/critical-rules.yar - $($_.Exception.Message)" }
    $p.CriticalRules = $crit
  }
  Write-Host ("==> install.ps1 " + (($p.Keys | ForEach-Object { "-$_" }) -join " ")) -ForegroundColor Cyan
  $global:LASTEXITCODE = 0
  & $inst @p
  $rc = $LASTEXITCODE
} finally {
  # 4) cleanup
  Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
if ($rc -ne 0) { Fail "install.ps1 exited with code $rc" }
Write-Host "Done." -ForegroundColor Green
