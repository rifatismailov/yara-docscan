# DocScan CI - install smoke test on a test stand (cirun stand, step "install"): the package of this commit is
# installed the way a PC gets it (install.ps1, Windows service DocScanWatcher as SYSTEM, the Go watcher), a few samples are
# dropped into a test inbox, the watcher must write a record with the expected verdict for each of them, then
# DocScan is removed again (uninstall.ps1 -Purge). Detect-only: the samples are not changed.
#   install_smoke.ps1 -Package C:\ci\dist\DocScan-<version>.zip -Repo C:\ci\yara [-Work C:\ci\smoke]
# Exit code 0 = every sample has its record and verdict; the report is printed.

param(
  [Parameter(Mandatory = $true)][string]$Package,
  [Parameter(Mandatory = $true)][string]$Repo,
  [string]$Work = "C:\ci\smoke",
  [string]$Rules = "",            # rules bundle of the run (DocScan-rules-bundle.zip) -> install.ps1 -Rules, as on a PC
  [int]$TimeoutSec = 240
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
function Fail($m) { Write-Host "FAIL: $m"; $script:failed = $true }
$failed = $false
$inbox = "$Work\inbox"
$samples = @("macro_suspicious.docm", "altchunk.docx", "archive_clean.zip", "lnk_remote_exec.lnk")
$results = "$env:ProgramData\DocScan\results\docscan-results.json"

# expected verdicts (column 2 of expected-verdicts.tsv)
$expected = @{}
foreach ($l in Get-Content "$Repo\docscan-project\ci\expected-verdicts.tsv") {
  if ($l -match '^#') { continue }
  $f = $l -split "`t"
  if ($f.Count -ge 2) { $expected[$f[0]] = $f[1] }
}

Remove-Item $Work -Recurse -Force -EA SilentlyContinue
New-Item -ItemType Directory -Force "$Work\pkg", $inbox | Out-Null
Expand-Archive $Package "$Work\pkg" -Force
"package: " + (Get-Content "$Work\pkg\VERSION.txt" -TotalCount 1)

# white / black lists of the organisation: a folder in the inbox where .exe is banned (black: path), a known bad file
# (black: sha256), our own program allowed there (white: sha256); detect-only here -> HIGH without quarantine
$lst = "$inbox\lists"; New-Item -ItemType Directory -Force $lst | Out-Null
$ownApp = "$Work\own-app.exe"; [IO.File]::WriteAllText($ownApp, "our own program " + [guid]::NewGuid())
$badFile = "$Work\bad.dll"; [IO.File]::WriteAllText($badFile, "known bad " + [guid]::NewGuid())
$hOwn = (Get-FileHash $ownApp).Hash.ToLower(); $hBad = (Get-FileHash $badFile).Hash.ToLower()
$wl = "$Work\whitelist.json"; $bl = "$Work\blacklist.json"
[IO.File]::WriteAllText($wl, (@{ schema = 1; entries = @(@{ sha256 = $hOwn; comment = "smoke: own app" }) } | ConvertTo-Json -Depth 5))
[IO.File]::WriteAllText($bl, (@{ schema = 1; entries = @(@{ path = "$lst\*.exe"; comment = "smoke: no exe here" }, @{ sha256 = $hBad; comment = "smoke: known bad" }) } | ConvertTo-Json -Depth 5))
$badList = "$Work\bad-list.json"; [IO.File]::WriteAllText($badList, '{"schema": 1, "entries": [{"path": "%USERPROFILE%\\Downloads\\*.exe"}]}')
# the organisation's list mirror (a local folder here): a new org key, the white list signed with it
$du = "$Work\pkg\updater\docscan-updater.exe"
$orgDir = "$Work\orglists"; New-Item -ItemType Directory -Force $orgDir | Out-Null
$keyOut = & $du -NewListKey -Out "$Work\org-lists.key" 2>&1 | % { "$_" }
$orgPub = @($keyOut | ? { $_ -match '^ed25519:' })[0]
if (-not $orgPub) { Fail "-NewListKey printed no public key: $keyOut" }
Copy-Item $wl "$orgDir\whitelist.json"
$signOut = & $du -SignList "$orgDir\whitelist.json" -Kind white -Key "$Work\org-lists.key" 2>&1 | % { "$_" }
if ($LASTEXITCODE) { Fail "-SignList: $signOut" } else { "org lists: $signOut" }

# a clean stand: any DocScan left on it (an interrupted run, a manual install with its own updater, rules, lists) is
# removed first - the run tests a fresh install of ITS package, nothing else
& powershell -NoProfile -ExecutionPolicy Bypass -File "$Repo\docscan-project\ci\clean_docscan.ps1" 2>&1 | % { "  $_" }
# install on the clean machine; watch only the test inbox. Updates: mode marker - the update
# service runs (checked below) but does nothing without a marker; github would "update" this CI build (no vX.Y.Z)
# to the latest release in the middle of the test
# the update config comes as one ready updater.json (-UpdateConfig, the way an organisation sets its mirror and keys)
$ucfg = "$Work\updater-org.json"
[IO.File]::WriteAllText($ucfg, (@{ mode = "marker"; lists = @{ url = $orgDir; public_keys = @($orgPub) } } | ConvertTo-Json -Depth 4))
& powershell -NoProfile -ExecutionPolicy Bypass -Command "& '$Work\pkg\install.ps1' -WatchPath '$inbox' -NoWazuhConfig -DetectOnly -UpdateConfig '$ucfg' -Whitelist '$wl' -Blacklist '$bl'$(if ($Rules) { " -Rules '$Rules'" })" 2>&1 | % { "  $_" }
if ($LASTEXITCODE) { "FAIL: install.ps1 exit $LASTEXITCODE"; exit 1 }
# the watcher is the Windows service DocScanWatcher: automatic, LocalSystem, restart after a failure, the Go exe
$sv = Get-CimInstance Win32_Service -Filter "Name='DocScanWatcher'"
if (-not $sv) { Fail "no service DocScanWatcher" }
"service: " + $sv.State + ", start " + $sv.StartMode + ", account " + $sv.StartName + ", runs " + $sv.PathName.Substring(0, [Math]::Min(80, $sv.PathName.Length))
if ($sv.PathName -notlike '"*docscan-watcher.exe"*') { Fail "the service does not run the Go watcher" }
if ($sv.StartMode -ne "Auto" -or $sv.StartName -ne "LocalSystem") { Fail "the service must start automatically as LocalSystem" }
$fa = (sc.exe qfailure DocScanWatcher) -join " "
if ($fa -notmatch "RESTART") { Fail "no restart-on-failure actions: $fa" }
if (Get-ScheduledTask "DocScan Watcher" -EA SilentlyContinue) { Fail "the old scheduled task 'DocScan Watcher' is still there" }
# the update service: running, its config, install.json for -Reuse, the package kept for a rollback (release builds)
$us = Get-CimInstance Win32_Service -Filter "Name='DocScanUpdater'"
if (-not $us) { Fail "no service DocScanUpdater" }
else {
  "updater: " + $us.State + ", start " + $us.StartMode + ", account " + $us.StartName
  if ($us.State -ne "Running" -or $us.StartMode -ne "Auto" -or $us.StartName -ne "LocalSystem") { Fail "DocScanUpdater must run automatically as LocalSystem" }
}
$uc = "$env:ProgramData\DocScan\update\updater.json"
if (-not (Test-Path $uc)) { Fail "no $uc" } else {
  $uo = Get-Content $uc -Raw | ConvertFrom-Json
  "updater.json: mode " + $uo.mode + ", lists " + $uo.lists.url
  if ($uo.mode -ne "marker" -or $uo.lists.url -ne $orgDir -or @($uo.lists.public_keys)[0] -ne $orgPub) { Fail "updater.json is not the one given with -UpdateConfig" }
}
# a broken -UpdateConfig (unknown key) is refused at the start, before anything changes (docscan-updater -CheckConfig);
# the services keep running
$badCfg = "$Work\updater-bad.json"; [IO.File]::WriteAllText($badCfg, '{"mode": "marker", "lists_url": "typo"}')
$bo = & powershell -NoProfile -ExecutionPolicy Bypass -Command "& '$Work\pkg\install.ps1' -Reuse -UpdateConfig '$badCfg' -NoStart" 2>&1 | % { "$_" }
if (-not $LASTEXITCODE) { Fail "install.ps1 accepted an updater.json with an unknown key" }
elseif (-not ($bo -match 'CheckConfig.*lists_url')) { Fail "bad -UpdateConfig refused, but not by the config check: $(($bo | Select -Last 3) -join ' | ')" }
else { "bad -UpdateConfig refused: " + (@($bo -match 'CheckConfig')[0]).Trim() }
if ((Get-Service DocScanWatcher).Status -ne "Running") { Fail "a refused -UpdateConfig stopped DocScanWatcher" }
if ((Get-Content $uc -Raw | ConvertFrom-Json).mode -ne "marker") { Fail "a refused -UpdateConfig changed updater.json" }
$ij = "$env:ProgramData\DocScan\install.json"
if (-not (Test-Path $ij)) { Fail "no $ij" } else { $j = Get-Content $ij -Raw | ConvertFrom-Json; "install.json: " + $j.installed + ", DetectOnly " + $j.params.DetectOnly + ", WatchPath " + ($j.params.WatchPath -join ";") }
# audit outside the web: the installer's record (who installed, how) and the service start, in docscan-results.json
$resf = "$env:ProgramData\DocScan\results\docscan-results.json"
$aud = @(Get-Content $resf -Encoding UTF8 -EA SilentlyContinue | ? { $_ -match '"event":"Admin"' })
foreach ($a in "docscan-installed|docscan-updated", "watcher-started") {
  if (-not ($aud -match ('"action":"(' + $a + ')"'))) { Fail "no audit record $a in docscan-results.json" }
}
# the commands in the machine PATH: docscan-web / docscan-watcher / docscan-updater from a new console
$mpath = @([Environment]::GetEnvironmentVariable("Path", "Machine") -split ";")
foreach ($d in "watcher", "web", "updater") {
  if ($mpath -notcontains "$env:ProgramW6432\DocScan\$d") { Fail "PATH: no $env:ProgramW6432\DocScan\$d" }
}
$env:Path = ($mpath -join ";")
$wc = Get-Command docscan-web -EA SilentlyContinue
if (-not $wc) { Fail "docscan-web is not found through PATH" } else { "PATH: docscan-watcher, docscan-web, docscan-updater - ok" }
"audit: installer and service records - ok (" + (@($aud | % { ([regex]'"action":"([^"]+)"').Match($_).Groups[1].Value }) -join ", ") + ")"
# the web interface: service DocScanWeb, a trusted certificate for 127.0.0.1 (no -SkipCertificateCheck: Windows must
# trust it), the temporary password for Administrators only, sign-in -> forced password change, the audit record
$wsv = Get-CimInstance Win32_Service -Filter "Name='DocScanWeb'"
$webDir = "$env:ProgramData\DocScan\web"
if (-not $wsv) { Fail "no service DocScanWeb" }
else {
  "web: " + $wsv.State + ", start " + $wsv.StartMode + ", account " + $wsv.StartName
  if ($wsv.State -ne "Running" -or $wsv.StartMode -ne "Auto" -or $wsv.StartName -ne "LocalSystem") { Fail "DocScanWeb must run automatically as LocalSystem" }
  $wc = @(Get-ChildItem Cert:\LocalMachine\Root | ? { $_.Subject -like "CN=DocScan Web 127.0.0.1*" })
  if ($wc.Count -ne 1) { Fail "web: $($wc.Count) DocScan certificates in the trusted root store (expected 1)" }
  # by SID (group names depend on the Windows language): only SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544)
  $sids = @((Get-Acl $webDir).Access | % { try { $_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value } catch { "$($_.IdentityReference)" } } | Sort-Object -Unique)
  $other = @($sids | ? { $_ -ne "S-1-5-18" -and $_ -ne "S-1-5-32-544" })
  if ($other.Count) { Fail "web: $webDir is open to $($other -join ', ') (only SYSTEM and Administrators)" }
  $pwLine = @(Get-Content "$webDir\initial-password.txt" -EA SilentlyContinue | ? { $_ -match '^password:\s+(\S+)' })
  if (-not $pwLine) { Fail "web: no initial-password.txt with a password" }
  else {
    $pw0 = ($pwLine[0] -replace '^password:\s+', '').Trim()
    [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
    try {
      $u = "https://127.0.0.1:8741"
      $r = Invoke-WebRequest -UseBasicParsing "$u/login" -SessionVariable ws -TimeoutSec 15
      $pre = [regex]::Match($r.Content, 'name="pre" value="([^"]+)"').Groups[1].Value
      $r = Invoke-WebRequest -UseBasicParsing "$u/login" -WebSession $ws -Method Post -Body @{ pre = $pre; next = "/"; name = "admin"; password = $pw0 } -TimeoutSec 15
      $csrf = [regex]::Match($r.Content, 'name="csrf" value="([^"]+)"').Groups[1].Value
      if (-not $csrf -or $r.Content -notmatch 'name="new2"') { Fail "web: after the sign-in with the temporary password the password form did not come" }
      $nw = "smoke-" + [guid]::NewGuid().ToString("N")
      $r = Invoke-WebRequest -UseBasicParsing "$u/password" -WebSession $ws -Method Post -Body @{ csrf = $csrf; old = $pw0; new = $nw; new2 = $nw } -TimeoutSec 15
      if ($r.Content -notmatch 'href="/detections"') { Fail "web: no status page after the password change" }
      if (Test-Path "$webDir\initial-password.txt") { Fail "web: initial-password.txt still there after the password change" }
      if (-not (Select-String -Path $results -Pattern '"action":"password-changed"' -Quiet)) { Fail "web: no audit record for Wazuh" }
      "web: https://127.0.0.1:8741 trusted HTTPS, sign-in, forced password change, audit record - ok"
    } catch { Fail "web: $($_.Exception.Message)" }
  }
}

Start-Sleep 3
# critical rules come with the rules package (rules\critical\*.yar): when the package has them, the watcher runs the check
$critN = @(Get-ChildItem "$env:ProgramW6432\DocScan\rules\critical\*.yar" -EA SilentlyContinue).Count
$wl0 = "$env:ProgramData\DocScan\results\watcher.log"
$critLine = ""
for ($t = 0; $t -lt 90 -and -not $critLine; $t += 3) {   # the line comes after the rules are compiled at start
  if (Test-Path $wl0) { $critLine = [string](Get-Content $wl0 -Encoding UTF8 | Select-String "critical: (rules|off)" | Select -Last 1) }
  if (-not $critLine) { Start-Sleep 3 }
}
if ($critN -and $critLine -notmatch 'critical: rules') { Fail "the rules package has $critN critical .yar, but the watcher says: $critLine" }
else { "critical: $critN file(s) in the rules package - $($critLine -replace '^.*?(critical: )', '$1')" }
$ul = "$env:ProgramData\DocScan\results\updater.log"
if (Test-Path $ul) { "updater.log: " + (Get-Content $ul -Tail 1) } else { Fail "no $ul - the updater did not start" }

# lists installed; a broken list is refused by the same check the watcher uses
foreach ($f in "whitelist.json", "blacklist.json") { if (-not (Test-Path "$env:ProgramData\DocScan\lists\$f")) { Fail "no lists\$f" } }
$chk = & "$env:ProgramW6432\DocScan\updater\docscan-updater.exe" -CheckList black $badList 2>&1 | % { "$_" }
if ($LASTEXITCODE -ne 1) { Fail "-CheckList accepted a broken list: $chk" } else { "lists: installed; broken list refused - $chk" }
# signed list from the organisation's mirror: DocScanUpdater -Once installs it, refuses a forged one
$upd = "$env:ProgramW6432\DocScan\updater\docscan-updater.exe"
& $upd -Once 2>&1 | Out-Null
$inst = Get-Content "$env:ProgramData\DocScan\lists\whitelist.json" -Raw | ConvertFrom-Json
$served = Get-Content "$orgDir\whitelist.json" -Raw | ConvertFrom-Json
if ($inst.serial -ne $served.serial) { Fail "signed org list not installed by DocScanUpdater (installed serial $($inst.serial), served $($served.serial))" }
elseif (-not (Test-Path "$env:ProgramData\DocScan\lists\whitelist.json.prev")) { Fail "no backup whitelist.json.prev" }
else { "org lists: whitelist.json serial $($inst.serial) installed by DocScanUpdater, previous kept as .prev" }
$forged = (Get-Content "$orgDir\whitelist.json" -Raw) -replace '"serial":\s*\d+', ('"serial": ' + ([int64]$served.serial + 1)) -replace 'own app', 'evil app'
[IO.File]::WriteAllText("$orgDir\whitelist.json", $forged)
& $upd -Once 2>&1 | Out-Null
$inst2 = Get-Content "$env:ProgramData\DocScan\lists\whitelist.json" -Raw | ConvertFrom-Json
$ur = Get-Content "$env:ProgramData\DocScan\results\docscan-updates.json" -Tail 1 | ConvertFrom-Json
if ($inst2.serial -ne $served.serial -or $ur.update.component -ne "lists" -or $ur.update.status -ne "error") { Fail "a forged org list was not refused (installed serial $($inst2.serial), last record $($ur.update.component) $($ur.update.status))" }
else { "org lists: forged list refused - $($ur.update.message)" }

$mark = if (Test-Path $results) { (Get-Item $results).Length } else { 0 }
foreach ($s in $samples) { Copy-Item "$Repo\docscan-project\test-samples\generated\$s" $inbox }
"dropped: " + ($samples -join ", ")

# wait for one record per sample (records written after $mark)
$got = @{}
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline -and $got.Count -lt $samples.Count) {
  Start-Sleep 3
  if (-not (Test-Path $results)) { continue }
  $fs = [IO.File]::Open($results, 'Open', 'Read', 'ReadWrite'); [void]$fs.Seek([Math]::Min($mark, $fs.Length), 'Begin')
  $tail = (New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)).ReadToEnd(); $fs.Close()
  foreach ($l in ($tail -split "`n")) {
    if ($l -notlike '{*') { continue }
    try { $r = $l | ConvertFrom-Json } catch { continue }
    if ($r.docfile.path -like "$inbox\*") { $got[$r.docfile.name] = $r }
  }
}
foreach ($s in $samples) {
  $r = $got[$s]
  if (-not $r) { Fail "$s - no record within $TimeoutSec s"; continue }
  $ok = $r.verdict -eq $expected[$s] -and -not $r.errors
  "{0,-6} {1,-24} verdict {2,-6} expected {3,-6} {4}" -f $(if ($ok) { "ok" } else { "FAIL" }), $s, $r.verdict, $expected[$s], ($r.errors -join "; ")
  if (-not $ok) { $failed = $true }
}
# lists decide before the scan: .exe in the banned folder -> HIGH; our own app there -> allowed; a known bad file -> HIGH
$mark2 = (Get-Item $results).Length
[IO.File]::WriteAllText("$lst\setup.exe", "unknown installer " + [guid]::NewGuid())
Copy-Item $ownApp "$lst\own-app.exe"
Copy-Item $badFile "$lst\bad.dll"
$hits = @{}
$deadline = (Get-Date).AddSeconds($TimeoutSec)
while ((Get-Date) -lt $deadline -and $hits.Count -lt 3) {
  Start-Sleep 3
  $fs = [IO.File]::Open($results, 'Open', 'Read', 'ReadWrite'); [void]$fs.Seek([Math]::Min($mark2, $fs.Length), 'Begin')
  $tail = (New-Object IO.StreamReader($fs, [Text.Encoding]::UTF8)).ReadToEnd(); $fs.Close()
  foreach ($l in ($tail -split "`n")) {
    if ($l -notlike '{*') { continue }
    try { $r = $l | ConvertFrom-Json } catch { continue }
    if ($r.docfile.path -like "$lst\*" -and $r.list) { $hits[$r.docfile.name] = $r }
  }
}
foreach ($c in @(@("setup.exe", "black", "HIGH", "path"), @("own-app.exe", "white", "INFO", "sha256"), @("bad.dll", "black", "HIGH", "sha256"))) {
  $r = $hits[$c[0]]
  if (-not $r -or $r.list.list -ne $c[1] -or $r.verdict -ne $c[2] -or $r.list.by -ne $c[3]) { Fail "lists: $($c[0]) must be $($c[1]) / $($c[2]) by $($c[3]), got $($r.list.list) / $($r.verdict) by $($r.list.by)" }
  else { "lists: $($c[0]) -> $($r.verdict) | $($r.summary)" }
}

# recovery: the watcher process is killed (a crash) -> Windows starts the service again (sc failure: after 10 s)
$p0 = (Get-CimInstance Win32_Service -Filter "Name='DocScanWatcher'").ProcessId
if ($p0) {
  Stop-Process -Id $p0 -Force
  $p1 = 0
  for ($t = 0; $t -lt 60 -and -not $p1; $t += 3) {
    Start-Sleep 3
    $sv = Get-CimInstance Win32_Service -Filter "Name='DocScanWatcher'"
    if ($sv.State -eq "Running" -and $sv.ProcessId -and $sv.ProcessId -ne $p0) { $p1 = $sv.ProcessId }
  }
  if ($p1) { "recovery: watcher killed (pid $p0) -> service running again (pid $p1) after ~$t s" }
  else { Fail "recovery: the service did not come back within 60 s after the watcher was killed" }
} else { Fail "the service has no process" }
$log = "$env:ProgramData\DocScan\results\watcher.log"
if (Test-Path $log) { "--- watcher.log (tail)"; Get-Content $log -Tail 6 | % { "  $_" } }

# remove DocScan again: the stand stays clean for the next run
& powershell -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramW6432\DocScan\uninstall.ps1" -Purge 2>&1 | % { "  $_" }
if (@([Environment]::GetEnvironmentVariable("Path", "Machine") -split ";") -match [regex]::Escape("$env:ProgramW6432\DocScan\")) { Fail "uninstall left DocScan folders in the machine PATH" }
if (@(Get-ChildItem Cert:\LocalMachine\Root | ? { $_.Subject -like "CN=DocScan Web 127.0.0.1*" }).Count) { Fail "uninstall left the web certificate in the trusted root store" }
Remove-Item $Work -Recurse -Force -EA SilentlyContinue
if ($failed) { "RESULT: FAIL"; exit 1 }
"RESULT: OK ($($samples.Count) samples, Go watcher as a service, restart after a crash, web interface)"
exit 0
