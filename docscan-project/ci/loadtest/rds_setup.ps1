# DocScan load test: prepare a Windows Server as a test terminal server (RD Session Host) with N local users.
#
# Run as Administrator on the server (locally or over WinRM). Idempotent: a second run updates passwords and settings.
#   rds_setup.ps1 -Password <users' password> [-Count 25] [-Prefix lt] [-TimeZone "FLE Standard Time"]
# Stage "users" (this script):
#   - time zone (logs line up with Wazuh);
#   - role RD Session Host (RDS-RD-Server): without it Windows Server allows only 2 admin sessions. No RDS CALs are
#     needed for the test: the 120-day grace period has no session limit. Needs a reboot -> "REBOOT NEEDED" at the end;
#   - RDP on (+ firewall group "Remote Desktop"), NLA kept;
#   - users <Prefix>01..<Prefix>NN: password never expires, members of "Remote Desktop Users";
#   - no first-logon animation (25 first logons at once are slow enough without it).
# The password comes as a parameter only: it is not stored in this script or in the repository.

param(
  [Parameter(Mandatory = $true)][string]$Password,
  [int]$Count = 25,
  [string]$Prefix = "lt",
  [string]$TimeZone = "FLE Standard Time"
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Step($m) { Write-Host "== $m" }

Step "time zone: $TimeZone"
Set-TimeZone -Id $TimeZone

Step "role RD Session Host"
$f = Get-WindowsFeature RDS-RD-Server
$reboot = $false
if (-not $f.Installed) {
  $r = Install-WindowsFeature RDS-RD-Server -IncludeManagementTools
  if (-not $r.Success) { throw "RDS-RD-Server install failed: $($r.ExitCode)" }
  $reboot = ($r.RestartNeeded -eq "Yes")
  Write-Host "  installed (restart needed: $($r.RestartNeeded))"
} elseif ($f.InstallState -eq "InstallPending") {
  $reboot = $true; Write-Host "  install pending - reboot"
} else { Write-Host "  already installed" }

Step "RDP on"
Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" fDenyTSConnections 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"
# no single-session restriction needed: every test user has its own account

Step "no first-logon animation"
Set-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" EnableFirstLogonAnimation 0 -Type DWord

Step "users ${Prefix}01..$('{0}{1:D2}' -f $Prefix, $Count)"
$sec = ConvertTo-SecureString $Password -AsPlainText -Force
$rdu = (New-Object Security.Principal.SecurityIdentifier "S-1-5-32-555").Translate([Security.Principal.NTAccount]).Value.Split('\')[-1]
$made = 0; $updated = 0
for ($i = 1; $i -le $Count; $i++) {
  $u = "{0}{1:D2}" -f $Prefix, $i
  if (Get-LocalUser $u -EA SilentlyContinue) {
    Set-LocalUser $u -Password $sec -PasswordNeverExpires $true
    Enable-LocalUser $u
    $updated++
  } else {
    New-LocalUser $u -Password $sec -PasswordNeverExpires -UserMayNotChangePassword `
      -FullName "DocScan load test $i" -Description "DocScan load test user" | Out-Null
    $made++
  }
  if (-not (Get-LocalGroupMember $rdu -Member $u -EA SilentlyContinue)) { Add-LocalGroupMember $rdu -Member $u }
}
Write-Host "  created $made, updated $updated; group '$rdu' members: $((Get-LocalGroupMember $rdu).Count)"

if ($reboot) { Write-Host "REBOOT NEEDED" } else { Write-Host "OK" }
