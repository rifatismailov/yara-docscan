# Install-CommandRunner.ps1 - put the Wazuh Active Response command runner on this PC.
#
# Run as administrator, e.g.:
#   irm http://<server>:8080/active-response/Install-CommandRunner.ps1 | iex
#
# It downloads and verifies CommandRunner.zip, removes any old runner files, installs the new ones,
# and restarts the Wazuh agent service.

$ErrorActionPreference = 'Stop'

$BaseUrl = 'http://<server>:8080/active-response'

function Die([string]$m) {
  Write-Host ("CommandRunner: " + $m) -ForegroundColor Red
  throw ("CommandRunner: " + $m)
}

# admin?
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
  Die "run this in an elevated PowerShell (Run as administrator)."
}

# find the Wazuh agent
$agent = @("${env:ProgramFiles(x86)}\ossec-agent", "$env:ProgramFiles\ossec-agent") |
         Where-Object { Test-Path (Join-Path $_ 'active-response') } | Select-Object -First 1
if (-not $agent) { Die "Wazuh agent not found (no ossec-agent\active-response folder)." }
$bin = Join-Path $agent 'active-response\bin'
New-Item -ItemType Directory -Force $bin | Out-Null
Write-Host ("CommandRunner: Wazuh agent at " + $agent)

# download the archive + hash
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$tmp = Join-Path $env:TEMP ("cmdrunner-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force $tmp | Out-Null
$zip = Join-Path $tmp 'CommandRunner.zip'
$hashFile = Join-Path $tmp 'CommandRunner.zip.sha256'
try {
  Invoke-WebRequest -UseBasicParsing -Uri ($BaseUrl.TrimEnd('/') + '/CommandRunner.zip') -OutFile $zip -TimeoutSec 60
  Invoke-WebRequest -UseBasicParsing -Uri ($BaseUrl.TrimEnd('/') + '/CommandRunner.zip.sha256') -OutFile $hashFile -TimeoutSec 30
} catch { Remove-Item $tmp -Recurse -Force -EA 0; Die ("download failed: " + $_.Exception.Message) }

$wantText = [IO.File]::ReadAllText($hashFile, [Text.Encoding]::ASCII)
$want = ([regex]::Match($wantText, '[0-9A-Fa-f]{64}')).Value.ToLowerInvariant()
$have = (Get-FileHash -LiteralPath $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if (-not $want -or $have -ne $want) {
  Remove-Item $tmp -Recurse -Force -EA 0
  Die ("CommandRunner.zip SHA256 mismatch - have " + $have + ", expected " + $want + "; not installed.")
}
Write-Host ("CommandRunner: archive verified sha256=" + $have.Substring(0,12))

# extract and verify the package contents before stopping the agent
$ext = Join-Path $tmp 'x'
Expand-Archive -LiteralPath $zip -DestinationPath $ext -Force
$files = Get-ChildItem -LiteralPath $ext -Recurse -File -Include 'commanda-runer.cmd','commanda-runer.ps1'
if ($files.Count -lt 2) { Remove-Item $tmp -Recurse -Force -EA 0; Die "the archive does not contain both commanda-runer.cmd and commanda-runer.ps1." }

# stop agent, remove old copies, install the verified files, then start it again
try {
  $service = Get-Service -Name 'WazuhSvc' -ErrorAction Stop
  if ($service.Status -ne [System.ServiceProcess.ServiceControllerStatus]::Stopped) {
    Stop-Service -Name $service.Name -Force -ErrorAction Stop
    $service.WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
  }
  Write-Host "CommandRunner: Wazuh agent service stopped."

  foreach ($name in @('commanda-runer.cmd','commanda-runer.ps1')) {
    $old = Join-Path $bin $name
    if (Test-Path -LiteralPath $old) {
      Remove-Item -LiteralPath $old -Force -ErrorAction Stop
      Write-Host ("CommandRunner: removed old " + $name)
    }
  }

  foreach ($f in $files) {
    Copy-Item -LiteralPath $f.FullName -Destination (Join-Path $bin $f.Name) -Force -ErrorAction Stop
    Write-Host ("CommandRunner: installed " + $f.Name)
  }
} catch {
  try {
    Start-Service -Name 'WazuhSvc' -ErrorAction Stop
    (Get-Service -Name 'WazuhSvc').WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
  } catch { }
  Remove-Item $tmp -Recurse -Force -EA 0
  Die ("could not replace runner files: " + $_.Exception.Message)
}

try {
  Start-Service -Name 'WazuhSvc' -ErrorAction Stop
  (Get-Service -Name 'WazuhSvc').WaitForStatus([System.ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
  Write-Host "CommandRunner: Wazuh agent service restarted."
} catch {
  Remove-Item $tmp -Recurse -Force -EA 0
  Die ("runner files installed, but could not restart WazuhSvc: " + $_.Exception.Message)
}
Remove-Item $tmp -Recurse -Force -EA 0

Write-Host ""
Write-Host ("CommandRunner: done -> " + $bin) -ForegroundColor Green
Write-Host "Next: define the command on the Wazuh MANAGER (see README.txt), then run it from the API:"
Write-Host "  PUT /active-response  {""command"":""!commanda-runer.cmd"",""arguments"":[""<script>.ps1""]}"
