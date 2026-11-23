# DocScan - install or update from the GitHub release (the only script to run on a PC).
#
# PowerShell AS ADMINISTRATOR:
#   [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12   # GitHub needs TLS 1.2
#   $f = "$env:TEMP\DocScan-Install.ps1"
#   irm https://github.com/rifatismailov/yara-docscan/releases/latest/download/DocScan-Install.ps1 -OutFile $f
#   powershell -ExecutionPolicy Bypass -File $f                                  # standard PC
#   powershell -ExecutionPolicy Bypass -File $f -DetectOnly                      # pilot: detection and alerts only
#
# What it does:
#   1) downloads DocScan-windows-x64.zip and its .sha256 from the GitHub release (the latest one, or
#      the one tagged -Version, e.g. v1.0.0) and checks the SHA256 (stops on mismatch);
#   2) the package holds the program: bin\ (yara64.exe, yarac64.exe, VC++ runtime), watcher\, updater\,
#      install.ps1, uninstall.ps1 - no rules: a new PC needs -Rules (the yara-docscan-rules bundle, with the
#      critical rules in critical\); it is unpacked into a temp folder;
#   3) runs install.ps1 from the package (it checks every file against SHA256SUMS.txt, installs to
#      C:\Program Files\DocScan, registers the Windows service "DocScan Watcher") and removes the temp files.
# Update: the same command; a new release on GitHub = a new version for every PC that runs it.

param(
  [string]  $Version = "",          # e.g. v1.0.0 (or an old release 20261116-7b6f6764); empty - the latest release
  [string]  $Repo = "rifatismailov/yara-docscan",   # GitHub owner/repo with the releases
  [switch]  $DetectOnly,            # -> install.ps1 -DetectOnly (no disarm, alerts only)
  [switch]  $NoCritical,            # -> install.ps1 -NoCritical (no critical-information check on this PC; the critical
                                    #    rules come with the rules package)
  [string]  $Whitelist = "",        # whitelist.json: local / UNC path or http(s) URL -> install.ps1 -Whitelist
  [string]  $Blacklist = "",        # blacklist.json: local / UNC path or http(s) URL -> install.ps1 -Blacklist
  [string]  $ListsToken = "",       # token for private -Whitelist / -Blacklist URLs and a closed -ListsUrl mirror (or $env:DOCSCAN_LISTS_TOKEN)
  [switch]  $NoWhitelist,           # -> install.ps1 -NoWhitelist
  [switch]  $NoBlacklist,           # -> install.ps1 -NoBlacklist
  [string[]]$WatchPath,             # -> install.ps1 -WatchPath
  [switch]  $NoAvExclusion,         # -> install.ps1 -NoAvExclusion
  [switch]  $QuarantineGeneral,     # -> install.ps1 -QuarantineGeneral
  [string]  $MacroUpload = "",      # -> install.ps1 -MacroUpload (collector URL); empty - macro code stays on the PC
  [ValidateSet("", "go", "ps")]
  [string]  $WatcherEngine = "",    # -> install.ps1 -WatcherEngine (default there: go; ps = the old PowerShell watcher)
  [int]     $Workers = 0,           # -> install.ps1 -Workers (fixed number of parallel scans; 0 = automatic)
  # updates (service DocScanUpdater, see install.ps1): -> install.ps1 -UpdateMode / -UpdateMirror / ...
  [string]  $UpdateMode = "",       # github (default) | mirror | marker | off
  [string]  $UpdateConfig = "",     # a ready updater.json of the organisation (file, UNC or URL) -> install.ps1 -UpdateConfig
  [string]  $UpdateMirror = "",     # mode mirror: folder with the release files (https://... or \\server\share)
  [string]  $UpdateMarker = "",     # mode marker: the file an agent writes
  [double]  $UpdateEveryHours = 0,  # github / mirror: check interval (default 6)
  [string]  $UpdateWindow = "",     # e.g. 22:00-06:00
  [string]  $ListsUrl = "",         # -> install.ps1 -ListsUrl: the organisation's mirror with signed lists (checked daily)
  [string[]]$ListsKey = @(),        # -> install.ps1 -ListsKey: the organisation's public key(s) for the lists
  [double]  $ListsEveryHours = 0,   # -> install.ps1 -ListsEveryHours (default 24)
  [switch]  $NoWeb,                 # -> install.ps1 -NoWeb (no web interface)
  [int]     $WebPort = 0,           # -> install.ps1 -WebPort (default there: 8741)
  [string]  $Rules = ""             # rules bundle (DocScan-rules-bundle.zip of a yara-docscan-rules release): file, UNC or URL -> install.ps1 -Rules
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
if ($Whitelist -and $NoWhitelist) { Fail "-Whitelist and -NoWhitelist together" }
if ($Blacklist -and $NoBlacklist) { Fail "-Blacklist and -NoBlacklist together" }

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
  if ($NoWhitelist)       { $p.NoWhitelist = $true }
  if ($NoBlacklist)       { $p.NoBlacklist = $true }
  if ($WatcherEngine)     { $p.WatcherEngine = $WatcherEngine }
  if ($Workers -gt 0)     { $p.Workers = $Workers }
  if ($UpdateMode)        { $p.UpdateMode = $UpdateMode }
  if ($UpdateConfig)      { $p.UpdateConfig = $(if ($UpdateConfig -match '^https?://') { $UpdateConfig } else { (Resolve-Path -LiteralPath $UpdateConfig).Path }) }
  if ($UpdateMirror)      { $p.UpdateMirror = $UpdateMirror }
  if ($UpdateMarker)      { $p.UpdateMarker = $UpdateMarker }
  if ($UpdateEveryHours -gt 0) { $p.UpdateEveryHours = $UpdateEveryHours }
  if ($UpdateWindow)      { $p.UpdateWindow = $UpdateWindow }
  if ($ListsUrl)          { $p.ListsUrl = $ListsUrl }
  if ($ListsKey.Count)    { $p.ListsKey = $ListsKey }
  if ($ListsEveryHours -gt 0) { $p.ListsEveryHours = $ListsEveryHours }
  if ($ListsUrl -and ($ListsToken -or $env:DOCSCAN_LISTS_TOKEN)) { $p.ListsToken = $(if ($ListsToken) { $ListsToken } else { $env:DOCSCAN_LISTS_TOKEN }) }   # closed mirror
  if ($NoWeb)             { $p.NoWeb = $true }
  if ($WebPort -gt 0)     { $p.WebPort = $WebPort }
  if ($Rules)             { $p.Rules = $Rules }

  # white / black lists: without -Whitelist / -Blacklist the lists a PC already has stay (install.ps1 checks the format)
  foreach ($l in @(@{ Src = $Whitelist; Key = "Whitelist"; File = "whitelist.json" }, @{ Src = $Blacklist; Key = "Blacklist"; File = "blacklist.json" })) {
    if (-not $l.Src) { continue }
    $dst = Join-Path $work $l.File
    if ($l.Src -match '^https?://') {
      $tok = if ($ListsToken) { $ListsToken } else { $env:DOCSCAN_LISTS_TOKEN }
      $h = @{}
      if ($tok) { $h.Authorization = "Bearer $tok" }
      try { Invoke-WebRequest -UseBasicParsing $l.Src -Headers $h -OutFile $dst }
      catch { Fail "-$($l.Key): could not download $($l.Src) - $($_.Exception.Message)" }
    } else {
      if (-not (Test-Path -LiteralPath $l.Src -PathType Leaf)) { Fail "-$($l.Key): file not found: $($l.Src)" }
      Copy-Item -LiteralPath $l.Src $dst
    }
    $p[$l.Key] = $dst
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
