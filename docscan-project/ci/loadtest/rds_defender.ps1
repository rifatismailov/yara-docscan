# DocScan load test: Microsoft Defender on the TEST server - off (it blocks / deletes known samples of the test
# set after a signature update, and its scans of every yara64 start and every file skew the timings) or back on.
# Test machines only. Run as SYSTEM (WinRM gets "Access is denied" for Set-MpPreference) - e.g. through the
# one-shot scheduled task the load-test runner uses.
#   rds_defender.ps1 -Off      # real-time / behaviour / download / script scanning off, also as policy
#                              # (survives reboots and signature updates); C:\loadtest excluded
#   rds_defender.ps1 -On       # policy keys removed, protection on again (the C:\loadtest exclusion stays)

param(
  [switch]$Off,
  [switch]$On,
  [string]$Root = "C:\loadtest"
)
$ErrorActionPreference = "Stop"
if ($Off -eq $On) { throw "give -Off or -On" }
$pol = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection"
$names = "DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection", "DisableScriptScanning", "DisableOnAccessProtection"

$top = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"
$spy = "$top\Spynet"
if ($Off) {
  # the test set is never deleted, even with protection on (+ the CI work folders of the test stands)
  Add-MpPreference -ExclusionPath (@($Root, "C:\ci", "C:\docscan-build") | ? { $_ })
  New-Item $pol -Force | Out-Null
  foreach ($n in $names) { Set-ItemProperty $pol $n 1 -Type DWord }
  # whole engine off by policy (honoured on Server / LTSC / older builds; ignored elsewhere - the keys above do the job)
  Set-ItemProperty $top DisableAntiSpyware 1 -Type DWord
  # no cloud lookups / sample uploads of the test files to Microsoft
  New-Item $spy -Force | Out-Null
  Set-ItemProperty $spy SpynetReporting 0 -Type DWord
  Set-ItemProperty $spy SubmitSamplesConsent 2 -Type DWord
  Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true `
    -DisableScriptScanning $true -MAPSReporting Disabled -SubmitSamplesConsent NeverSend -PUAProtection Disabled `
    -DisableBlockAtFirstSeen $true -EA Continue
} else {
  if (Test-Path $pol) { foreach ($n in $names) { Remove-ItemProperty $pol $n -EA SilentlyContinue } }
  Remove-ItemProperty $top DisableAntiSpyware -EA SilentlyContinue
  Remove-Item $spy -Recurse -EA SilentlyContinue
  Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false `
    -DisableScriptScanning $false -MAPSReporting Advanced -SubmitSamplesConsent SendSafeSamples -DisableBlockAtFirstSeen $false
}
Start-Sleep 2
$s = Get-MpComputerStatus
"Defender: real-time {0}, behaviour {1}, downloads {2}; exclusions: {3}" -f $s.RealTimeProtectionEnabled,
  $s.BehaviorMonitorEnabled, $s.IoavProtectionEnabled, ((Get-MpPreference).ExclusionPath -join "; ")
if ($Off -and $s.RealTimeProtectionEnabled) { throw "real-time protection is still on (Tamper Protection?)" }
