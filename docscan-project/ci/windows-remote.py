#!/usr/bin/env python3
"""DocScan CI for Windows, driven over WinRM from a Unix runner (no runner on Windows).

Picks the first reachable Windows build machine (the Proxmox VM first, then the fallback PC),
puts the exact commit on it (git fetch from Forgejo, or - when the machine does not see Forgejo -
a git-archive zip sent over WinRM), builds with MSBuild, runs the document regression
(check_verdicts.ps1 - no Python needed) and, if Python is there, the third-pass tests, builds the
package (build_package.ps1) and copies the zip back into the artifacts.

Environment (Forgejo secrets / variables; never in the repository):
  WIN11_HOST, WIN11_USER, WIN11_PASS      first choice (VM)
  WIN216_HOST, WIN216_USER, WIN216_PASS   fallback (a workstation)
  GIT_URL, GIT_TOKEN                      Forgejo clone URL + read token (used when the machine sees Forgejo)
  SHA                                     the commit to build (must be checked out in the runner's workspace)
  CI_OUT                                  local output folder (default ci-out)
  WIN_DIR                                 work folder on Windows (default C:\\ci)
Needs pywinrm on the runner; Git (optional), VS Build Tools 2022 on Windows.
"""
import base64
import hashlib
import os
import socket
import subprocess
import sys
import time

import winrm

SHA = os.environ["SHA"]
OUT = os.environ.get("CI_OUT", "ci-out")
WDIR = os.environ.get("WIN_DIR", r"C:\ci")
REPO = WDIR + r"\yara"
os.makedirs(os.path.join(OUT, "artifacts"), exist_ok=True)
summary = []
failed = False


def reachable(host, port=5985, timeout=4):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


targets = []
for pfx, label in (("WIN11", "VM Windows 11"), ("WIN216", "fallback PC")):
    h = os.environ.get(pfx + "_HOST", "").strip()
    if h:
        targets.append((label, h, os.environ.get(pfx + "_USER", ""), os.environ.get(pfx + "_PASS", "")))
target = next((t for t in targets if reachable(t[1])), None)
if target is None:
    print("no Windows build machine is reachable: " + ", ".join("%s (%s)" % (t[0], t[1]) for t in targets))
    open(os.path.join(OUT, "artifacts", "summary.txt"), "w").write("machine        FAIL  (none reachable)\n")
    sys.exit(1)
label, HOST, USER, PASS = target
print("Windows build machine: %s %s" % (label, HOST), flush=True)
summary.append("machine        %s %s" % (label, HOST))
session = winrm.Session("http://%s:5985/wsman" % HOST, auth=(USER, PASS), transport="ntlm",
                        read_timeout_sec=7300, operation_timeout_sec=7200)


def put(data, remote):
    """Send bytes to a Windows file in base64 parts over one shell (WinRM limits a command's size)."""
    b64 = base64.b64encode(data).decode()
    p = session.protocol
    shell = p.open_shell()
    try:
        def cmd(c):
            cid = p.run_command(shell, c)
            out, err, rc = p.get_command_output(shell, cid)
            p.cleanup_command(shell, cid)
            if rc != 0:
                raise RuntimeError(err.decode(errors="replace"))
        cmd('if not exist "%s" mkdir "%s"' % (WDIR, WDIR))
        cmd('del /q "%s.b64" 2>nul & ver >nul' % remote)
        for i in range(0, len(b64), 7000):
            cmd('echo %s>>"%s.b64"' % (b64[i:i + 7000], remote))
    finally:
        p.close_shell(shell)
    r = session.run_ps("$b=(Get-Content '{0}.b64') -join ''; [IO.File]::WriteAllBytes('{0}',[Convert]::FromBase64String($b));"
                       " Remove-Item '{0}.b64'; (Get-Item '{0}').Length".format(remote))
    if r.status_code != 0:
        raise RuntimeError(r.std_err.decode(errors="replace"))


def ps(script):
    path = WDIR + r"\step-%d.ps1" % int(time.time() * 1000)
    put(("$ErrorActionPreference='Continue'\n$ProgressPreference='SilentlyContinue'\n" + script).encode("utf-8-sig"), path)
    r = session.run_ps("& powershell -NoProfile -ExecutionPolicy Bypass -File '{0}'; $c=$LASTEXITCODE; Remove-Item '{0}' -EA 0; exit $c".format(path))
    out = r.std_out.decode("utf-8", "replace") + r.std_err.decode("utf-8", "replace")
    return r.status_code, "\n".join(l for l in out.splitlines() if not l.startswith(("#< CLIXML", "<Objs ")))


def step(name, script, skip_rc=None):
    global failed
    print("::group::windows " + name, flush=True)
    t = time.time()
    rc, out = ps(script)
    open(os.path.join(OUT, "windows-%s.log" % name), "w", encoding="utf-8").write(out)
    print("\n".join(out.splitlines()[-30:]))
    print("::endgroup::")
    res = "SKIP" if (skip_rc is not None and rc == skip_rc) else ("PASS" if rc == 0 else "FAIL")
    failed |= res == "FAIL"
    line = "%-14s %s  (%ds)" % (name, res, time.time() - t)
    summary.append(line)
    print(line, flush=True)
    return res != "FAIL"


COMMON = r"""
$w = '%(w)s'; $repo = '%(repo)s'
New-Item -ItemType Directory -Force $w | Out-Null
# the test samples look malicious on purpose (inert): Defender must not take them from the CI folder
if (Get-Command Add-MpPreference -EA 0) {
  try { if (@((Get-MpPreference).ExclusionPath) -notcontains $w) { Add-MpPreference -ExclusionPath $w -EA Stop } } catch { }
}
""" % {"w": WDIR, "repo": REPO}

# 1. the exact commit: git from Forgejo when the machine sees it, otherwise a zip from the runner
rc, out = ps(COMMON + r"""
try { $r = Invoke-WebRequest -UseBasicParsing '%(url)s' -Method Head -TimeoutSec 6; 'forgejo: yes' } catch { 'forgejo: no' }
if (Get-Command git -EA 0) { 'git: yes' } else { 'git: no' }
""" % {"url": os.environ.get("GIT_URL", "http://localhost/")})
use_git = "forgejo: yes" in out and "git: yes" in out
if use_git:
    hdr = "Authorization: token " + os.environ.get("GIT_TOKEN", "")
    ok = step("checkout", COMMON + r"""
if (Test-Path "$repo" -PathType Container) { if (-not (Test-Path "$repo\.git")) { Remove-Item $repo -Recurse -Force } }
if (-not (Test-Path "$repo\.git")) { git -c "http.extraHeader=%(hdr)s" clone --no-checkout '%(url)s' $repo 2>&1 | %% { "$_" } }
Set-Location $repo
git -c "http.extraHeader=%(hdr)s" fetch --force origin %(sha)s 2>&1 | %% { "$_" }
git checkout --force %(sha)s 2>&1 | %% { "$_" }
git clean -xfdq -e windows/vs2019/packages 2>&1 | %% { "$_" }
"commit: " + (git rev-parse HEAD) + " (git)"
if ((git rev-parse HEAD) -ne '%(sha)s') { exit 1 }
""" % {"url": os.environ["GIT_URL"], "hdr": hdr, "sha": SHA})
else:
    t = time.time()
    try:
        data = subprocess.run(["git", "archive", "--format=zip", SHA], capture_output=True, check=True).stdout
        put(data, WDIR + r"\src.zip")
        ok = step("checkout", COMMON + r"""
$keep = "$w\packages-cache"
if (Test-Path "$repo\windows\vs2019\packages") { Remove-Item $keep -Recurse -Force -EA 0; Move-Item "$repo\windows\vs2019\packages" $keep }
Remove-Item $repo -Recurse -Force -EA 0
Expand-Archive "$w\src.zip" $repo -Force
Remove-Item "$w\src.zip"
if (Test-Path $keep) { Move-Item $keep "$repo\windows\vs2019\packages" }
"commit: %(sha)s (zip from the runner, %(n)d bytes)"
""" % {"sha": SHA, "n": len(data)})
    except Exception as e:  # noqa: BLE001
        print("source upload failed: %s" % e)
        summary.append("checkout       FAIL  (upload: %s)" % str(e)[:80])
        failed, ok = True, False

if ok:
    ok = step("build", COMMON + r"""
Set-Location $repo
$pk = "windows\vs2019\packages"
if (Get-Command nuget -EA 0) { nuget restore windows\vs2019\yara.sln 2>&1 | Select-Object -Last 2 }
elseif (-not (Test-Path $pk)) {
  # no NuGet on this machine: take the restored packages from an earlier build tree, else get nuget.exe
  $cache = @("C:\docscan-build\yara\windows\vs2019\packages") | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($cache) { Copy-Item $cache $pk -Recurse; "packages: copied from $cache" }
  else {
    New-Item -ItemType Directory -Force "$w\tools" | Out-Null
    if (-not (Test-Path "$w\tools\nuget.exe")) { Invoke-WebRequest -UseBasicParsing https://dist.nuget.org/win-x86-commandline/latest/nuget.exe -OutFile "$w\tools\nuget.exe" }
    & "$w\tools\nuget.exe" restore windows\vs2019\yara.sln 2>&1 | Select-Object -Last 2
  }
}
$mb = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\MSBuild\Current\Bin\MSBuild.exe" -EA 0 | Select -First 1 -Expand FullName
& $mb windows\vs2019\yara.sln "/t:yara;yarac" /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /m /v:m /nologo 2>&1 |
  ForEach-Object { "$_" } | Where-Object { $_ -match "error|warning C|->" }
$rc = $LASTEXITCODE
& .\windows\vs2019\Release\yara64.exe --version
exit $rc
""")

if ok:
    y = REPO + r"\windows\vs2019\Release\yara64.exe"
    step("documents", COMMON + r"""
Set-Location $repo
powershell -NoProfile -ExecutionPolicy Bypass -File docscan-project\ci\check_verdicts.ps1 -Yara '%(y)s' `
  -Rules docscan-project\rules\docscan-index.yar -Samples docscan-project\test-samples\generated `
  -Expected docscan-project\ci\expected-verdicts.tsv -WorkDir "$w\tmp"
exit $LASTEXITCODE
""" % {"y": y})
    step("critical", COMMON + r"""
Set-Location $repo; $env:PYTHONIOENCODING = 'utf-8'
$py = @("python", "python3", "py") | ForEach-Object { Get-Command $_ -EA 0 } | Where-Object { $_.Source -notlike "*WindowsApps*" } | Select-Object -First 1
if (-not $py) { "no Python on this machine - the third-pass tests run on macOS / Linux"; exit 3 }
& $py.Source docscan-project\test-critical\run_tests.py --yara '%(y)s'
exit $LASTEXITCODE
""" % {"y": y}, skip_rc=3)
    version = time.strftime("%Y%m%d") + "-" + SHA[:8]
    if step("package", COMMON + r"""
Set-Location $repo
Remove-Item "$w\dist" -Recurse -Force -EA 0
powershell -ExecutionPolicy Bypass -File docscan-project\deploy\build_package.ps1 -Repo $repo -Out "$w\dist" -Version %(v)s 2>&1 | %% { "$_" }
if (-not (Test-Path "$w\dist\DocScan-%(v)s.zip")) { exit 1 }
(Get-FileHash "$w\dist\DocScan-%(v)s.zip").Hash.ToLower() + "  DocScan-%(v)s.zip"
""" % {"v": version}):
        zp = WDIR + r"\dist\DocScan-%s.zip" % version
        r = session.run_ps("[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'))" % zp)
        data = base64.b64decode(r.std_out.decode().replace("\r", "").replace("\n", ""))
        dst = os.path.join(OUT, "artifacts", "DocScan-%s.zip" % version)
        open(dst, "wb").write(data)
        h = hashlib.sha256(data).hexdigest()
        open(dst + ".sha256", "w").write("%s  DocScan-%s.zip\n" % (h, version))
        print("package: %s (%d bytes, sha256 %s)" % (dst, len(data), h))

open(os.path.join(OUT, "summary.txt"), "w").write("\n".join(summary) + "\n")
for f in os.listdir(OUT):
    if f.endswith(".log") or f == "summary.txt":
        open(os.path.join(OUT, "artifacts", f), "wb").write(open(os.path.join(OUT, f), "rb").read())
print("\n===== Windows summary\n" + "\n".join(summary))
sys.exit(1 if failed or not ok else 0)
