# DocScan load test: open N RDP sessions at once to the test terminal server from a Windows client.
#
# Runs in the client's INTERACTIVE desktop session (mstsc needs one): directly, or over WinRM through a scheduled
# task "interactive, only when the user is logged on" (see rds_run.py). A disconnected session works as well.
#   rds_connect.ps1 -Server <ip> -Password <pw> [-Count 25] [-Prefix lt] [-Domain <server name>] [-DelaySec 5]
#   rds_connect.ps1 -Close            # close every mstsc window opened by this script
# mstsc keeps one saved password per target name, and all N users go to the same server, so every user gets its own
# alias: hosts file "<ip> <Prefix>rds01" ... and cmdkey TERMSRV/<Prefix>rdsNN = that user. The server certificate
# warning is switched off for the client user (AuthenticationLevelOverride = 0) - a test client only.
# Small windows (800x600) keep the client's memory low.

param(
  [string]$Server = "",
  [string]$Password = "",
  [int]$Count = 25,
  [string]$Prefix = "lt",
  [string]$Domain = "",     # the server's computer name (local accounts); empty = ".\"
  [int]$DelaySec = 5,
  [switch]$Close
)
$ErrorActionPreference = "Stop"
$hosts = "$env:SystemRoot\System32\drivers\etc\hosts"
$tag = "# docscan-loadtest"

if ($Close) {
  $n = 0
  Get-CimInstance Win32_Process -Filter "Name='mstsc.exe'" | ? { $_.CommandLine -match "${Prefix}rds\d\d" } |
    % { Stop-Process -Id $_.ProcessId -Force -EA SilentlyContinue; $n++ }
  1..$Count | % { cmdkey /delete:("TERMSRV/{0}rds{1:D2}" -f $Prefix, $_) | Out-Null }
  "closed mstsc: $n"
  exit 0
}
if (-not $Server -or -not $Password) { throw "-Server and -Password are required" }

# hosts aliases (rewritten every run)
$old = @([IO.File]::ReadAllLines($hosts))
$keep = @($old | ? { $_ -notmatch [regex]::Escape($tag) })
$add = @(1..$Count | % { "{0} {1}rds{2:D2} {3}" -f $Server, $Prefix, $_, $tag })
$new = $keep + $add
if (($old -join "`n") -ne ($new -join "`n")) {
  # Defender / the DNS client hold the file for a moment now and then: retry
  for ($t = 1; ; $t++) {
    try { [IO.File]::WriteAllLines($hosts, [string[]]$new, [Text.Encoding]::ASCII); break }
    catch { if ($t -ge 10) { throw }; Start-Sleep -Milliseconds 500 }
  }
  ipconfig /flushdns | Out-Null
}

# no certificate prompt, no "remember me" dialogs
$tsc = "HKCU:\Software\Microsoft\Terminal Server Client"
New-Item $tsc -Force | Out-Null
Set-ItemProperty $tsc AuthenticationLevelOverride 0 -Type DWord

$dom = if ($Domain) { $Domain } else { "." }
for ($i = 1; $i -le $Count; $i++) {
  $alias = "{0}rds{1:D2}" -f $Prefix, $i
  $user = "{0}\{1}{2:D2}" -f $dom, $Prefix, $i
  cmdkey /generic:"TERMSRV/$alias" /user:$user /pass:$Password | Out-Null
  # no .rdp file: Windows 11 shows a blocking "unknown publisher" dialog for unsigned .rdp files;
  # mstsc /v takes the saved credential of TERMSRV/<alias> and the defaults of Default.rdp
  Start-Process mstsc.exe -ArgumentList "/v:$alias /w:800 /h:600"
  "{0:HH:mm:ss} started {1} as {2}" -f (Get-Date), $alias, $user
  if ($i -lt $Count) { Start-Sleep -Seconds $DelaySec }
}
"started: $Count"
