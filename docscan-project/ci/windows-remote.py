#!/usr/bin/env python3
"""DocScan CI for Windows, driven over WinRM from a Unix runner (no runner on Windows).

On the Windows machine: fetch the exact commit from Forgejo -> MSBuild (yara, yarac)
-> document regression (check_verdicts.py) -> third-pass tests (run_tests.py)
-> package (build_package.ps1) -> the zip is copied back into the artifacts.

Environment (from Forgejo secrets/variables, never in the repository):
  WIN_HOST, WIN_USER, WIN_PASS   WinRM (HTTP 5985, NTLM) of the Windows build machine
  GIT_URL                        clone URL of the repository on Forgejo (http://.../owner/repo.git)
  GIT_TOKEN                      read token for that repository (sent as an HTTP header, not stored)
  SHA                            the commit to build
  CI_OUT                         local output folder (default ci-out)
  WIN_DIR                        work folder on Windows (default C:\\ci)
Needs: pip package pywinrm on the runner; Git, Python 3, NuGet, VS Build Tools 2022 on Windows.
"""
import base64
import os
import sys
import time

import winrm

HOST = os.environ["WIN_HOST"]
SHA = os.environ["SHA"]
OUT = os.environ.get("CI_OUT", "ci-out")
WDIR = os.environ.get("WIN_DIR", r"C:\ci")
REPO = WDIR + r"\yara"
os.makedirs(os.path.join(OUT, "artifacts"), exist_ok=True)

session = winrm.Session("http://%s:5985/wsman" % HOST, auth=(os.environ["WIN_USER"], os.environ["WIN_PASS"]),
                        transport="ntlm", read_timeout_sec=7300, operation_timeout_sec=7200)
summary = []
failed = False


def ps(script):
    """Run PowerShell on the Windows machine (the script is sent in parts: WinRM limits a command's size)."""
    path = WDIR + r"\step-%d.ps1" % int(time.time() * 1000)
    data = base64.b64encode(("$ErrorActionPreference='Continue'\n$ProgressPreference='SilentlyContinue'\n" + script)
                            .encode("utf-8-sig")).decode()
    session.run_ps("New-Item -ItemType Directory -Force '%s' | Out-Null; Remove-Item '%s.b64' -EA 0" % (WDIR, path))
    for i in range(0, len(data), 1800):
        session.run_cmd("cmd", ["/c", "echo %s>>%s.b64" % (data[i:i + 1800], path)])
    r = session.run_ps("$b=(Get-Content '{0}.b64') -join ''; [IO.File]::WriteAllBytes('{0}',[Convert]::FromBase64String($b));"
                       " Remove-Item '{0}.b64'; & powershell -NoProfile -ExecutionPolicy Bypass -File '{0}'; $c=$LASTEXITCODE;"
                       " Remove-Item '{0}' -EA 0; exit $c".format(path))
    return r.status_code, r.std_out.decode("utf-8", "replace") + r.std_err.decode("utf-8", "replace")


def step(name, script):
    global failed
    print("::group::windows " + name, flush=True)
    t = time.time()
    rc, out = ps(script)
    open(os.path.join(OUT, "windows-%s.log" % name), "w", encoding="utf-8").write(out)
    print("\n".join(out.splitlines()[-30:]))
    print("::endgroup::")
    res = "PASS" if rc == 0 else "FAIL"
    failed |= rc != 0
    line = "%-14s %s  (%ds)" % (name, res, time.time() - t)
    summary.append(line)
    print(line, flush=True)
    return rc == 0


# 1. the exact commit (token as a header: it is not written into .git/config)
hdr = "Authorization: token " + os.environ["GIT_TOKEN"]
ok = step("checkout", r"""
$url = '%(url)s'; $repo = '%(repo)s'
# the test samples look malicious on purpose (inert): Defender must not take them from the CI folder
if (Get-Command Add-MpPreference -EA 0) {
  if (@((Get-MpPreference).ExclusionPath) -notcontains '%(wdir)s') { Add-MpPreference -ExclusionPath '%(wdir)s' }
  "defender exclusion: " + (@((Get-MpPreference).ExclusionPath) -contains '%(wdir)s')
}
if (-not (Test-Path "$repo\.git")) { git -c "http.extraHeader=%(hdr)s" clone --no-checkout $url $repo 2>&1 | %% { "$_" } }
Set-Location $repo
git -c "http.extraHeader=%(hdr)s" fetch --force origin %(sha)s 2>&1 | %% { "$_" }
git checkout --force %(sha)s 2>&1 | %% { "$_" }
git clean -xfdq -e windows/vs2019/packages 2>&1 | %% { "$_" }
"commit: " + (git rev-parse HEAD)
if ((git rev-parse HEAD) -ne '%(sha)s') { exit 1 }
""" % {"url": os.environ["GIT_URL"], "repo": REPO, "hdr": hdr, "sha": SHA, "wdir": WDIR})

if ok:
    ok = step("build", r"""
Set-Location '%(repo)s'
nuget restore windows\vs2019\yara.sln 2>&1 | Select-Object -Last 3
$mb = Get-ChildItem "C:\Program Files*\Microsoft Visual Studio\*\*\MSBuild\Current\Bin\MSBuild.exe" -EA 0 | Select -First 1 -Expand FullName
& $mb windows\vs2019\yara.sln "/t:yara;yarac" /p:Configuration=Release /p:Platform=x64 /p:PlatformToolset=v143 /m /v:m /nologo 2>&1 |
  ForEach-Object { "$_" } | Where-Object { $_ -match "error|warning C|->" }
$rc = $LASTEXITCODE
& .\windows\vs2019\Release\yara64.exe --version
exit $rc
""" % {"repo": REPO})

if ok:
    y = REPO + r"\windows\vs2019\Release\yara64.exe"
    step("documents", r"""
Set-Location '%(repo)s'; $env:PYTHONIOENCODING = 'utf-8'
python docscan-project\ci\check_verdicts.py --yara '%(y)s' --rules docscan-project\rules\docscan-index.yar --samples docscan-project\test-samples\generated --expected docscan-project\ci\expected-verdicts.tsv --workdir '%(w)s\tmp'
exit $LASTEXITCODE
""" % {"repo": REPO, "y": y, "w": WDIR})
    step("critical", r"""
Set-Location '%(repo)s'; $env:PYTHONIOENCODING = 'utf-8'
python docscan-project\test-critical\run_tests.py --yara '%(y)s'
exit $LASTEXITCODE
""" % {"repo": REPO, "y": y})
    version = time.strftime("%Y%m%d") + "-" + SHA[:8]
    if step("package", r"""
Set-Location '%(repo)s'
Remove-Item '%(w)s\dist' -Recurse -Force -EA 0
powershell -ExecutionPolicy Bypass -File docscan-project\deploy\build_package.ps1 -Repo '%(repo)s' -Out '%(w)s\dist' -Version %(v)s 2>&1 | %% { "$_" }
if (-not (Test-Path '%(w)s\dist\DocScan-%(v)s.zip')) { exit 1 }
(Get-FileHash '%(w)s\dist\DocScan-%(v)s.zip').Hash.ToLower() + "  DocScan-%(v)s.zip"
""" % {"repo": REPO, "w": WDIR, "v": version}):
        zp = WDIR + r"\dist\DocScan-%s.zip" % version
        r = session.run_ps("[Convert]::ToBase64String([IO.File]::ReadAllBytes('%s'))" % zp)
        data = base64.b64decode(r.std_out.decode().replace("\r", "").replace("\n", ""))
        dst = os.path.join(OUT, "artifacts", "DocScan-%s.zip" % version)
        open(dst, "wb").write(data)
        import hashlib
        h = hashlib.sha256(data).hexdigest()
        open(dst + ".sha256", "w").write("%s  DocScan-%s.zip\n" % (h, version))
        print("package: %s (%d bytes, sha256 %s)" % (dst, len(data), h))

open(os.path.join(OUT, "summary.txt"), "w").write("\n".join(summary) + "\n")
for f in os.listdir(OUT):
    if f.endswith(".log") or f == "summary.txt":
        open(os.path.join(OUT, "artifacts", f), "wb").write(open(os.path.join(OUT, f), "rb").read())
print("\n===== Windows summary\n" + "\n".join(summary))
sys.exit(1 if failed or not ok else 0)
