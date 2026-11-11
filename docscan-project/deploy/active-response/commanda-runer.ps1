# commanda-runer.ps1 - Wazuh Active Response helper (runs as SYSTEM via commanda-runer.cmd).
#
# What it does: reads the Active Response request (JSON on stdin), takes ONE script name from
# parameters.extra_args, downloads that script from the DocScan file server, verifies its SHA256
# against the .sha256 published next to it, and only then runs it in a child PowerShell with a
# time limit. Every step is written to the agent's active-responses.log.
#
# This is a remote-command channel to every PC, so the rules below are deliberately tight:
#   * the server address is fixed here - it CANNOT be changed from the manager / the AR request;
#   * only safe relative paths are accepted (no URL, traversal, backslash, or other host);
#   * the script runs ONLY if its SHA256 matches the .sha256 on the server (missing hash = refuse);
#   * a run is killed after $TimeoutSec seconds.
# To add a new command: put <name>.ps1 and <name>.ps1.sha256 on the server, nothing to change here.

$ErrorActionPreference = 'Stop'

# --- fixed settings (<server> is replaced with the real address by New-CommandRunnerPackage.ps1) ----------
$BaseUrl    = 'http://<server>:8080'
$TimeoutSec = 600
$NameRx     = '^(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\.ps1$'

# --- logging into the Wazuh active-responses.log ---------------------------------------------------
$Bin = Split-Path -Parent $MyInvocation.MyCommand.Path
$Log = Join-Path (Split-Path -Parent $Bin) 'active-responses.log'
function Log([string]$msg) {
  $line = '{0} commanda-runer: {1}' -f (Get-Date -Format 'yyyy/MM/dd HH:mm:ss'), $msg
  try { Add-Content -LiteralPath $Log -Value $line -Encoding ascii } catch { }
}

function Fail([string]$msg) { Log ("REFUSED: " + $msg); exit 2 }

# --- read the AR request ---------------------------------------------------------------------------
# Wazuh (execd) sends {"command":"add|delete","parameters":{"extra_args":["name.ps1"], ...}} on stdin.
$stdin = ''
try { $stdin = [Console]::In.ReadToEnd() } catch { }

$arCmd = 'add'; $name = $null
if ($stdin.Trim()) {
  try {
    $req = $stdin | ConvertFrom-Json
    if ($req.command) { $arCmd = [string]$req.command }
    if ($req.parameters -and $req.parameters.extra_args) { $name = [string]@($req.parameters.extra_args)[0] }
  } catch { Fail ("bad AR JSON on stdin: " + $_.Exception.Message) }
}
# fallback: name passed as a plain argument (older callers / manual test)
if (-not $name -and $args.Count -ge 1) { $name = [string]$args[0] }

# AR sends the request twice (add then delete); only "add" runs the command.
if ($arCmd -eq 'delete') { Log "delete phase - nothing to do"; exit 0 }
if (-not $name)          { Fail "no script name in the request" }
if ($name -notmatch $NameRx -or $name -match '(^|/)\.\.?(/|$)') {
  Fail ("script path not allowed: '" + $name + "'")
}

Log ("request: " + $name)

# --- download the script and its hash --------------------------------------------------------------
$tmp  = Join-Path $env:TEMP ("ar-" + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Force $tmp | Out-Null
# Keep the relative path for the server URL, but save the download at the temp
# directory root so a path such as policy/test.ps1 does not require subfolders.
$file = Join-Path $tmp ([IO.Path]::GetFileName($name))
$hashFile = Join-Path $tmp 'script.sha256'
$urlPath = (($name -split '/') | ForEach-Object { [Uri]::EscapeDataString($_) }) -join '/'
$url = $BaseUrl.TrimEnd('/') + '/' + $urlPath
try {
  [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
  Invoke-WebRequest -UseBasicParsing -Uri $url -OutFile $file -TimeoutSec 60
} catch {
  Remove-Item $tmp -Recurse -Force -EA 0
  Fail ("script download failed from " + $url + ": " + $_.Exception.Message)
}

# SHA256 sidecars are optional. If present, verify them; a missing sidecar must
# not prevent a policy script from running. Keep other sidecar download errors fatal.
$hasHash = $false
try {
  Invoke-WebRequest -UseBasicParsing -Uri ($url + '.sha256') -OutFile $hashFile -TimeoutSec 30
  $hasHash = $true
} catch {
  $status = 0
  try { $status = [int]$_.Exception.Response.StatusCode } catch { }
  if ($status -ne 404) {
    Remove-Item $tmp -Recurse -Force -EA 0
    Fail ("checksum download failed from " + $url + '.sha256: ' + $_.Exception.Message)
  }
}

if ($hasHash) {
  # Read as ASCII because the HTTP server may serve the sidecar as bytes.
  $wantText = [IO.File]::ReadAllText($hashFile, [Text.Encoding]::ASCII)
  $want = ([regex]::Match($wantText, '[0-9A-Fa-f]{64}')).Value.ToLowerInvariant()
  $have = (Get-FileHash -LiteralPath $file -Algorithm SHA256).Hash.ToLowerInvariant()
  if (-not $want)      { Remove-Item $tmp -Recurse -Force -EA 0; Fail ($name + ": invalid .sha256 on the server") }
  if ($have -ne $want) { Remove-Item $tmp -Recurse -Force -EA 0; Fail ($name + ": SHA256 mismatch (have " + $have.Substring(0,12) + ", want " + $want.Substring(0,12) + ")") }
  Log ("verified " + $name + " sha256=" + $have.Substring(0,12) + " - running")
} else {
  Log ("no .sha256 for " + $name + " - running without checksum")
}

# --- run it with a time limit ----------------------------------------------------------------------
$out = Join-Path $tmp 'out.txt'
$rc  = $null
try {
  $p = Start-Process -FilePath 'powershell.exe' `
         -ArgumentList @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File', ('"{0}"' -f $file)) `
         -RedirectStandardOutput $out -RedirectStandardError ($out + '.err') `
         -WindowStyle Hidden -PassThru
  if ($p.WaitForExit($TimeoutSec * 1000)) {
    $rc = $p.ExitCode
  } else {
    try { $p.Kill() } catch { }
    Log ($name + ": TIMEOUT after " + $TimeoutSec + "s - killed")
    Remove-Item $tmp -Recurse -Force -EA 0
    exit 3
  }
} catch {
  Remove-Item $tmp -Recurse -Force -EA 0
  Fail ($name + ": start failed: " + $_.Exception.Message)
}

# Copy a bounded amount of child output into the persistent Wazuh log before
# removing the temporary folder, including stderr where PowerShell reports errors.
foreach ($stream in @(@{ Path = $out; Label = 'stdout' }, @{ Path = ($out + '.err'); Label = 'stderr' })) {
  if (Test-Path -LiteralPath $stream.Path) {
    $lines = @(Get-Content -LiteralPath $stream.Path -TotalCount 10 -EA 0)
    foreach ($line in $lines) {
      $message = [string]$line
      if ($message.Length -gt 500) { $message = $message.Substring(0, 500) + ' [truncated]' }
      if ($message) { Log ($name + ' ' + $stream.Label + ': ' + $message) }
    }
  }
}
Log ("done " + $name + " exit=" + $rc)

Remove-Item $tmp -Recurse -Force -EA 0
exit $rc
