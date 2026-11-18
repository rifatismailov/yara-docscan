# DocScan - install or update from the GitHub release (the only script to run on a PC).
#
# PowerShell AS ADMINISTRATOR:
#   [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12   # GitHub needs TLS 1.2
#   $f = "$env:TEMP\DocScan-Install.ps1"
#   irm https://github.com/rifatismailov/yara-docscan/releases/latest/download/DocScan-Install.ps1 -OutFile $f
#   powershell -ExecutionPolicy Bypass -File $f                                  # standard PC
#   powershell -ExecutionPolicy Bypass -File $f -DetectOnly                      # pilot: detection and alerts only
#   powershell -ExecutionPolicy Bypass -File $f -Critical C:\path\critical-rules.yar     # + critical-information
#   powershell -ExecutionPolicy Bypass -File $f -Critical https://.../critical-rules.yar #   check (E5Search)
#
# What it does:
#   1) downloads DocScan-windows-x64.zip and its .sha256 from the GitHub release (the latest one, or
#      the one tagged -Version, e.g. v1.0.0) and checks the SHA256 (stops on mismatch);
#   2) the package holds everything: bin\ (yara64.exe, yarac64.exe, VC++ runtime), rules\, watcher\,
#      install.ps1, uninstall.ps1; it is unpacked into a temp folder;
#   3) -Critical: the E5Search rules are NOT in the release (sensitive) - they come from the given local
#      file / UNC path or URL (a private URL: -CriticalToken or $env:DOCSCAN_CRITICAL_TOKEN);
#   4) runs install.ps1 from the package (it checks every file against SHA256SUMS.txt, installs to
#      C:\Program Files\DocScan, registers the "DocScan Watcher" task) and removes the temp files.
# Update: the same command; a new release on GitHub = a new version for every PC that runs it.

param(
  [string]  $Version = "",          # e.g. v1.0.0 (or an old release 20261116-7b6f6764); empty - the latest release
  [string]  $Repo = "rifatismailov/yara-docscan",   # GitHub owner/repo with the releases
  [switch]  $DetectOnly,            # -> install.ps1 -DetectOnly (no disarm, alerts only)
  [string]  $Critical = "",         # critical-rules.yar: local / UNC path or http(s) URL -> install.ps1 -CriticalRules
  [string]  $CriticalToken = "",    # bearer token for a private -Critical URL (or $env:DOCSCAN_CRITICAL_TOKEN)
  [switch]  $NoCritical,            # -> install.ps1 -NoCritical (turn the check off, remove the rules)
  [string[]]$WatchPath,             # -> install.ps1 -WatchPath
  [switch]  $NoAvExclusion,         # -> install.ps1 -NoAvExclusion
  [switch]  $QuarantineGeneral,     # -> install.ps1 -QuarantineGeneral
  [string]  $MacroUpload = "",      # -> install.ps1 -MacroUpload (collector URL); empty - macro code stays on the PC
  [ValidateSet("", "go", "ps")]
  [string]  $WatcherEngine = "",    # -> install.ps1 -WatcherEngine (default there: go; ps = the old PowerShell watcher)
  [int]     $Workers = 0            # -> install.ps1 -Workers (fixed number of parallel scans; 0 = automatic)
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"   # without it Invoke-WebRequest in PS 5.1 is very slow
# GitHub accepts TLS 1.2+ only; Windows PowerShell 5.1 may offer older versions by default
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12

function Fail($m) { Write-Host "ERROR: $m" -ForegroundColor Red; exit 1 }

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $admin) { Fail "run PowerShell as Administrator" }
if ($Repo -notmatch '^[\w.-]+/[\w.-]+$') { Fail "-Repo must be owner/repo" }
if ($Version -and $Version -notmatch '^(v\d+\.\d+\.\d+|\d{8}-[0-9a-f]+)$') { Fail "-Version must look like v1.0.0 (or 20261116-7b6f6764 for an old release)" }
# release tags: vX.Y.Z; the releases before v1.0.0 were tagged docscan-<date>-<commit>
$tag = if ($Version -match '^v') { $Version } else { "docscan-$Version" }
if ($Critical -and $NoCritical) { Fail "-Critical and -NoCritical together" }

$asset = "DocScan-windows-x64.zip"
$base = if ($Version) { "https://github.com/$Repo/releases/download/$tag" } else { "https://github.com/$Repo/releases/latest/download" }
Write-Host "==> release: $(if ($Version) { $tag } else { 'latest' })  (github.com/$Repo)" -ForegroundColor Cyan

$work = Join-Path $env:TEMP ("DocScan-setup-" + [guid]::NewGuid().ToString("N").Substring(0, 8))
New-Item -ItemType Directory -Force $work | Out-Null
$rc = 1
try {
  # 1) package + checksum
  $zip = Join-Path $work $asset
  $sumF = "$zip.sha256"
  try {
    Invoke-WebRequest -UseBasicParsing "$base/$asset" -OutFile $zip
    Invoke-WebRequest -UseBasicParsing "$base/$asset.sha256" -OutFile $sumF
  } catch { Fail "download from GitHub failed - $($_.Exception.Message)" }
  $expected = (([IO.File]::ReadAllText($sumF).Trim() -split '\s+')[0]).ToLower()
  $actual = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLower()
  if ($expected -notmatch '^[0-9a-f]{64}$') { Fail "$asset.sha256 has no checksum" }
  if ($actual -ne $expected) { Fail "SHA256 mismatch (expected $expected, got $actual) - the package is damaged or replaced" }
  Write-Host "==> SHA256 matches, unpacking" -ForegroundColor Cyan

  # 2) unpack
  $dir = Join-Path $work "pkg"
  Expand-Archive $zip $dir -Force
  $inst = Join-Path $dir "install.ps1"
  if (-not (Test-Path $inst)) { Fail "install.ps1 is missing from the package" }
  $ver = (Get-Content (Join-Path $dir "VERSION.txt") -TotalCount 1 -EA SilentlyContinue) -join ""
  if ($ver) { Write-Host "==> $ver" -ForegroundColor Cyan }

  # 3) parameters for install.ps1 (same process with splatting: -File cannot pass arrays)
  $p = @{}
  if ($DetectOnly)        { $p.DetectOnly = $true }
  if ($NoAvExclusion)     { $p.NoAvExclusion = $true }
  if ($QuarantineGeneral) { $p.QuarantineGeneral = $true }
  if ($WatchPath)         { $p.WatchPath = $WatchPath }
  if ($MacroUpload)       { $p.MacroUpload = $MacroUpload }
  if ($NoCritical)        { $p.NoCritical = $true }
  if ($WatcherEngine)     { $p.WatcherEngine = $WatcherEngine }
  if ($Workers -gt 0)     { $p.Workers = $Workers }
  # without -Critical / -NoCritical the rules a PC already has stay as they are
  if ($Critical) {
    $crit = Join-Path $work "critical-rules.yar"
    if ($Critical -match '^https?://') {
      $tok = if ($CriticalToken) { $CriticalToken } else { $env:DOCSCAN_CRITICAL_TOKEN }
      $h = @{}
      if ($tok) { $h.Authorization = "Bearer $tok" }
      try { Invoke-WebRequest -UseBasicParsing $Critical -Headers $h -OutFile $crit }
      catch { Fail "-Critical: could not download $Critical - $($_.Exception.Message)" }
    } else {
      if (-not (Test-Path -LiteralPath $Critical -PathType Leaf)) { Fail "-Critical: file not found: $Critical" }
      Copy-Item -LiteralPath $Critical $crit
    }
    if ((Get-Item $crit).Length -eq 0) { Fail "-Critical: the rules file is empty" }
    $p.CriticalRules = $crit
  }

  # 4) install
  Write-Host ("==> install.ps1 " + (($p.Keys | ForEach-Object { "-$_" }) -join " ")) -ForegroundColor Cyan
  $global:LASTEXITCODE = 0
  & $inst @p
  $rc = $LASTEXITCODE
} finally {
  Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
}
if ($rc -ne 0) { Fail "install.ps1 exited with code $rc" }
Write-Host "Done." -ForegroundColor Green
