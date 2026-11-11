# Build the files served to Windows agents: CommandRunner.zip (+ .sha256) and Install-CommandRunner.ps1,
# with the real file-server address in place of <server> (the sources in git keep the placeholder).
# Usage: .\New-CommandRunnerPackage.ps1 -Server 10.0.0.5 [-OutDir C:\webroot\active-response]
# Then copy the OutDir files to <web root>/active-response/ on the file server.
param(
  [Parameter(Mandatory)][string]$Server,
  [string]$OutDir = (Join-Path $PSScriptRoot 'dist')
)

$ErrorActionPreference = 'Stop'
if ($Server -notmatch '^[A-Za-z0-9.-]+$') { throw "Server must be a host name or IP address: $Server" }

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null
$stage = Join-Path $OutDir 'stage'
Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $stage -Force | Out-Null

# fill in the address; the output must not keep the placeholder
function Fill([string]$src, [string]$dst) {
  if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { throw "Required file is missing: $src" }
  $text = [IO.File]::ReadAllText($src).Replace('<server>', $Server)
  [IO.File]::WriteAllText($dst, $text, (New-Object Text.UTF8Encoding($false)))
}
Fill (Join-Path $PSScriptRoot 'commanda-runer.ps1') (Join-Path $stage 'commanda-runer.ps1')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'commanda-runer.cmd') -Destination $stage
Fill (Join-Path $PSScriptRoot 'Install-CommandRunner.ps1') (Join-Path $OutDir 'Install-CommandRunner.ps1')

$zip = Join-Path $OutDir 'CommandRunner.zip'
Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
Compress-Archive -LiteralPath (Join-Path $stage 'commanda-runer.cmd'), (Join-Path $stage 'commanda-runer.ps1') -DestinationPath $zip
Remove-Item -LiteralPath $stage -Recurse -Force
$hash = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
"$hash  CommandRunner.zip" | Set-Content -LiteralPath (Join-Path $OutDir 'CommandRunner.zip.sha256') -Encoding ASCII
Write-Host "Created in ${OutDir}: CommandRunner.zip ($($hash.Substring(0,12))), CommandRunner.zip.sha256, Install-CommandRunner.ps1"
