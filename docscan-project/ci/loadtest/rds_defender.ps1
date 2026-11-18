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

if ($Off) {
  # the test set is never deleted, even with protection on
  Add-MpPreference -ExclusionPath $Root
  New-Item $pol -Force | Out-Null
  foreach ($n in $names) { Set-ItemProperty $pol $n 1 -Type DWord }
  Set-MpPreference -DisableRealtimeMonitoring $true -DisableBehaviorMonitoring $true -DisableIOAVProtection $true `
    -DisableScriptScanning $true
} else {
  if (Test-Path $pol) { foreach ($n in $names) { Remove-ItemProperty $pol $n -EA SilentlyContinue } }
  Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false `
    -DisableScriptScanning $false
}
Start-Sleep 2
$s = Get-MpComputerStatus
"Defender: real-time {0}, behaviour {1}, downloads {2}; exclusions: {3}" -f $s.RealTimeProtectionEnabled,
  $s.BehaviorMonitorEnabled, $s.IoavProtectionEnabled, ((Get-MpPreference).ExclusionPath -join "; ")
if ($Off -and $s.RealTimeProtectionEnabled) { throw "real-time protection is still on (Tamper Protection?)" }
