#!/usr/bin/env python3
"""The "Run" button (VS Code ▷ / task "DocScan CI"): commit -> push -> build + tests on every system
-> deployment set -> (optionally) publish to the deployment server.

  python3 docscan-project/ci/ci-run.py [--fuzz SECONDS] [-m "message"] [--no-commit] [--no-push]
                                       [--local] [--publish]

Two modes, chosen automatically:
  * Forgejo reachable  -> the "build-test" workflow runs there (runners: this Mac, Windows over WinRM,
                          Ubuntu when it exists); the script follows it and downloads the artifacts.
  * Forgejo NOT reachable (or --local) -> the same steps run from this Mac directly: build-test-unix.sh
                          here, windows-remote.py over WinRM to the first reachable Windows build machine
                          (the Proxmox VM, else the fallback PC "216").
After a green run the deployment set is put together in ci-out/<run>/deploy/: the Windows package
DocScan-<date>-<commit>.zip + .sha256, DocScan-latest.txt, DocScan-Install.ps1 and the bootstraps
DocScan-Setup.ps1 / -Pilot / -Critical with the server address filled in (+ critical-rules.yar).
--publish uploads it to the deployment server and switches DocScan-latest.txt to the new package.

Auto-commit: every change git does not ignore (git add -A) goes into one commit, unless the safety
check finds something that must not reach the public repository (internal addresses, host/user
names, passwords, tokens, files > 5 MB) - then nothing is committed and the script stops.

Settings: ~/.docscan/hosts.json - profile "forgejo" (url, token), "vm" and "216" (host, user, password:
the Windows build machines, local mode), "fs" (host, user, password, deploy_dir, deploy_url,
critical_rules: the deployment server). Repository on Forgejo: FORGEJO_REPO (default rifat/yara-docscan).
"""
import argparse
import glob
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ap = argparse.ArgumentParser()
ap.add_argument("--fuzz", default="300", help="fuzzing seconds per OS (0 = none)")
ap.add_argument("--no-push", action="store_true", help="do not git push")
ap.add_argument("--no-commit", action="store_true", help="do not commit local changes (CI builds the last commit)")
ap.add_argument("-m", "--message", default="", help="commit message for the auto-commit")
ap.add_argument("--remote", default="docscan", help="git remote of GitHub (default: docscan)")
ap.add_argument("--local", action="store_true", help="do not use Forgejo: build and test from this Mac")
ap.add_argument("--publish", action="store_true", help="after a green run, upload the deployment set to the server")
a = ap.parse_args()

REPO_ROOT = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True, check=True).stdout.strip()
os.chdir(REPO_ROOT)
try:
    HOSTS = json.load(open(os.path.expanduser("~/.docscan/hosts.json")))
except (OSError, ValueError):
    HOSTS = {}
FJ = HOSTS.get("forgejo", {})
URL = os.environ.get("FORGEJO_URL", FJ.get("url", "")).rstrip("/")
TOKEN = os.environ.get("FORGEJO_TOKEN", FJ.get("token", ""))
REPO = os.environ.get("FORGEJO_REPO", "rifat/yara-docscan")
started = time.time()


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout.strip()


def say(msg):
    print(msg, flush=True)


# ------------------------------------------------------------------ commit --

_INTERNAL_NAMES = "|".join(["fort" + "una", "(?<!rifat)" + "isma" + "ilov", "odessa" + r"\.ua"])  # split: this file is public too
FORBIDDEN = [
    (re.compile(r"\b(192\.168\.(1|17|88|129)|10\.10\.67|172\.118\.18)\.\d{1,3}\b"), "internal IP address"),
    (re.compile(_INTERNAL_NAMES, re.I), "internal host / user name"),
    (re.compile(r"(password|passwd|pwd|secret|token)['\"]?\s*[:=]\s*['\"][^'\"\s]{6,}['\"]", re.I), "password / token value"),
    (re.compile(r"\b[0-9a-f]{40}\b"), "40-hex token (Forgejo/GitHub)"),
]
MAX_FILE = 5 * 1024 * 1024


def safety_check():
    problems = []
    for f in git("diff", "--cached", "--name-only", "-z").split("\0"):
        if f and os.path.isfile(f) and os.path.getsize(f) > MAX_FILE:
            problems.append("%s: file larger than 5 MB" % f)
    diff = subprocess.run(["git", "diff", "--cached", "-U0", "--no-color"], capture_output=True,
                          text=True, encoding="utf-8", errors="replace").stdout
    cur = "?"
    for line in diff.splitlines():
        if line.startswith("+++ "):
            cur = line[6:] if line.startswith("+++ b/") else line[4:]
        elif line.startswith("+") and not line.startswith("+++"):
            for rx, what in FORBIDDEN:
                if rx.search(line):
                    problems.append("%s: %s:  %s" % (cur, what, line[1:].strip()[:100]))
    return problems


branch = git("rev-parse", "--abbrev-ref", "HEAD")
changes = git("status", "--porcelain")
if changes and not a.no_commit:
    say("commit local changes:")
    say("\n".join("    " + l for l in changes.splitlines()[:30]))
    subprocess.run(["git", "add", "-A"], check=True)
    problems = safety_check()
    if problems:
        subprocess.run(["git", "reset", "-q"], check=True)
        say("\n! NOT committed - the public repository must not get:")
        say("\n".join("    " + p for p in problems[:20]))
        sys.exit("fix these changes (or commit by hand with --no-commit) and press Run again")
    files = git("diff", "--cached", "--name-only").splitlines()
    msg = a.message or ("ci: " + (", ".join(os.path.basename(f) for f in files[:6]) + (" ..." if len(files) > 6 else "")))
    subprocess.run(["git", "commit", "-q", "-m", msg], check=True)
    say("    committed: %s  (%s)" % (git("rev-parse", "--short", "HEAD"), msg))
elif changes:
    say("! uncommitted changes (--no-commit) - the last COMMIT %s is built" % git("rev-parse", "--short", "HEAD"))
sha = git("rev-parse", "HEAD")

if not a.no_push:
    say("git push %s %s" % (a.remote, branch))
    if subprocess.run(["git", "push", a.remote, branch]).returncode != 0:
        say("! git push failed - continuing with the local commit")


def reachable(url, timeout=4):
    try:
        u = urllib.parse.urlparse(url)
        with socket.create_connection((u.hostname, u.port or 80), timeout=timeout):
            return True
    except (OSError, ValueError, TypeError):
        return False


# ------------------------------------------------------------ remote mode --

def api(method, path, body=None, raw=False):
    req = urllib.request.Request(URL + "/api/v1" + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "token " + TOKEN, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
        return data if raw else (json.loads(data) if data else None)


def run_forgejo():
    say("Forgejo: sync the mirror")
    api("POST", "/repos/%s/mirror-sync" % REPO)
    for _ in range(60):
        head = api("GET", "/repos/%s/branches/%s" % (REPO, urllib.parse.quote(branch, safe="")))["commit"]["id"]
        if head == sha:
            break
        time.sleep(3)
    else:
        sys.exit("the mirror did not get %s in 3 minutes (is it pushed to GitHub?)" % sha[:8])
    say("Forgejo: start the workflow build-test (fuzzing %ss per OS)" % a.fuzz)
    info = api("POST", "/repos/%s/actions/workflows/ci.yml/dispatches" % REPO,
               {"ref": branch, "inputs": {"fuzz_seconds": str(a.fuzz)}, "return_run_info": True})
    rid = info["id"]
    say("    run #%s: %s/%s/actions/runs/%s   jobs: %s" % (info.get("run_number", rid), URL, REPO, rid, ", ".join(info.get("jobs", []))))
    last = {}
    while True:
        jobs = api("GET", "/repos/%s/actions/runs/%s/jobs" % (REPO, rid))
        if isinstance(jobs, dict):
            jobs = jobs.get("jobs", [])
        for j in jobs:
            if last.get(j["name"]) != j.get("status"):
                last[j["name"]] = j.get("status")
                say("    %-10s %-12s %4ds" % (j["name"], j.get("status"), time.time() - started))
        r = api("GET", "/repos/%s/actions/runs/%s" % (REPO, rid))
        if r.get("status") in ("success", "failure", "cancelled", "skipped"):
            break
        time.sleep(15)
    out = os.path.join("ci-out", "run-%s" % rid)
    os.makedirs(out, exist_ok=True)
    arts = api("GET", "/repos/%s/actions/runs/%s/artifacts" % (REPO, rid))
    for art in (arts.get("artifacts", []) if isinstance(arts, dict) else arts):
        try:
            zipfile.ZipFile(io.BytesIO(api("GET", "/repos/%s/actions/artifacts/%s/zip" % (REPO, art["id"]), raw=True))) \
                .extractall(os.path.join(out, art["name"]))
        except (urllib.error.HTTPError, zipfile.BadZipFile) as e:
            say("    artifact %s: %s" % (art["name"], e))
    return out, r.get("status") == "success"


# ------------------------------------------------------------- local mode --

def run_local():
    out = os.path.join("ci-out", "local-" + time.strftime("%Y%m%d-%H%M%S"))
    os.makedirs(out)
    jobs = {}
    seeds = os.path.expanduser("~/docscan-ci/seeds")
    env_mac = dict(os.environ, CI_OUT=os.path.abspath(os.path.join(out, "macos-work")), FUZZ_SECONDS=str(a.fuzz),
                   CI_SEEDS=seeds if os.path.isdir(seeds) else "")
    jobs["macos"] = (["sh", "docscan-project/ci/build-test-unix.sh"], env_mac, os.path.join(out, "macos-work"), os.path.join(out, "macos"))
    env_win = dict(os.environ, SHA=sha, CI_OUT=os.path.abspath(os.path.join(out, "windows-work")),
                   GIT_URL="%s/%s.git" % (URL, REPO) if URL else "http://localhost/", GIT_TOKEN=FJ.get("ci_checkout_token", ""))
    for pfx, prof in (("WIN11", "vm"), ("WIN216", "216")):
        p = HOSTS.get(prof, {})
        if p.get("host"):
            env_win.update({pfx + "_HOST": p["host"], pfx + "_USER": p.get("user", ""), pfx + "_PASS": p.get("password", "")})
    jobs["windows"] = ([sys.executable, "docscan-project/ci/windows-remote.py"], env_win, os.path.join(out, "windows-work"), os.path.join(out, "windows"))

    results = {}

    def run(name, cmd, env, work, dst):
        t = time.time()
        os.makedirs(work, exist_ok=True)
        with open(os.path.join(out, name + ".log"), "w") as log:
            rc = subprocess.run(cmd, env=env, stdout=log, stderr=subprocess.STDOUT).returncode
        if os.path.isdir(os.path.join(work, "artifacts")):
            shutil.copytree(os.path.join(work, "artifacts"), dst, dirs_exist_ok=True)
        results[name] = rc
        say("    %-10s %-8s %4ds   (log: %s)" % (name, "success" if rc == 0 else "failure", time.time() - t, os.path.join(out, name + ".log")))

    say("local mode: macOS here + Windows over WinRM (fuzzing %ss)" % a.fuzz)
    threads = [threading.Thread(target=run, args=(n,) + v) for n, v in jobs.items()]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    for n in jobs:
        shutil.rmtree(os.path.join(out, n + "-work", "fuzz"), ignore_errors=True)
    return out, all(rc == 0 for rc in results.values())


# --------------------------------------------------------- deployment set --

def deploy_set(out_dir):
    zips = sorted(glob.glob(os.path.join(out_dir, "*", "DocScan-*.zip")))
    if not zips:
        say("\n(no Windows package in this run - no deployment set)")
        return None
    fs = HOSTS.get("fs", {})
    base = fs.get("deploy_url") or ("http://%s:8080/docscan" % fs["host"] if fs.get("host") else "http://<server>:8080/docscan")
    d = os.path.join(out_dir, "deploy")
    shutil.rmtree(d, ignore_errors=True)
    os.makedirs(d)
    pkg = os.path.basename(zips[-1])
    shutil.copy(zips[-1], d)
    shutil.copy(zips[-1] + ".sha256", d)
    open(os.path.join(d, "DocScan-latest.txt"), "w", newline="\n").write(pkg + "\n")
    shutil.copy(os.path.join("docscan-project", "deploy", "DocScan-Install.ps1"), d)
    tpl = open(os.path.join("docscan-project", "deploy", "DocScan-Setup.ps1"), "rb").read().decode("ascii").replace("\r\n", "\n")
    tpl = tpl.replace("'http://<server>:8080/docscan'", "'%s'" % base).replace("http://<server>:8080/docscan", base)
    for name, arg in (("DocScan-Setup.ps1", None), ("DocScan-Setup-Pilot.ps1", "'-DetectOnly'"), ("DocScan-Setup-Critical.ps1", "'-Critical'")):
        t = tpl if arg is None else re.sub(r"\$InstallArg = @\(\)", "$InstallArg = @(%s)" % arg, tpl, count=1)
        open(os.path.join(d, name), "wb").write(t.replace("\n", "\r\n").encode("ascii"))
    crit = os.environ.get("DOCSCAN_CRITICAL_RULES") or fs.get("critical_rules", "")
    if crit and os.path.isfile(os.path.expanduser(crit)):
        shutil.copy(os.path.expanduser(crit), os.path.join(d, "critical-rules.yar"))
    say("\ndeployment set: %s" % os.path.abspath(d))
    for f in sorted(os.listdir(d)):
        say("    %-34s %8d bytes" % (f, os.path.getsize(os.path.join(d, f))))
    return d, pkg, fs, base


def publish(d, pkg, fs, base):
    if not (fs.get("host") and fs.get("user") and fs.get("password")):
        say("! --publish: no server in ~/.docscan/hosts.json profile 'fs' (host, user, password)")
        return False
    rdir = fs.get("deploy_dir", "scripts/docscan")
    env = dict(os.environ, SSHPASS=fs["password"])
    target = "%s@%s" % (fs["user"], fs["host"])
    files = [f for f in sorted(os.listdir(d)) if f != "DocScan-latest.txt"]
    say("\npublish to %s:%s" % (target, rdir))
    ssh = ["sshpass", "-e", "ssh", "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=10", target]
    try:
        subprocess.run(ssh + ["mkdir -p '%s'" % rdir], env=env, check=True)
        subprocess.run(["sshpass", "-e", "scp", "-q"] + [os.path.join(d, f) for f in files] + ["%s:%s/" % (target, rdir)], env=env, check=True)
        chk = subprocess.run(ssh + ["cd '%s' && sha256sum -c '%s.sha256'" % (rdir, pkg)], env=env, capture_output=True, text=True)
        say("    " + (chk.stdout.strip() or chk.stderr.strip()))
        if chk.returncode != 0:
            say("! the package on the server does not match its sha256 - DocScan-latest.txt NOT switched")
            return False
        subprocess.run(["sshpass", "-e", "scp", "-q", os.path.join(d, "DocScan-latest.txt"), "%s:%s/" % (target, rdir)], env=env, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        say("! publish failed: %s" % e)
        return False
    try:
        latest = urllib.request.urlopen(base + "/DocScan-latest.txt", timeout=15).read().decode().strip()
        setup = urllib.request.urlopen(base + "/DocScan-Setup.ps1", timeout=15).read().decode("ascii", "replace")
        ok = latest == pkg and base in setup
        say("    %s/DocScan-latest.txt -> %s   %s" % (base, latest, "OK" if ok else "MISMATCH"))
        say("    install on a PC:  irm %s/DocScan-Setup.ps1 | iex" % base)
        return ok
    except OSError as e:
        say("    HTTP check failed: %s" % e)
        return False


# ------------------------------------------------------------------- main --

use_forgejo = not a.local and URL and TOKEN and reachable(URL)
if not use_forgejo and not a.local:
    say("Forgejo (%s) is not reachable - local mode" % (URL or "not configured"))
out, green = run_forgejo() if use_forgejo else run_local()

for name in sorted(os.listdir(out)):
    s = os.path.join(out, name, "summary.txt")
    if os.path.exists(s):
        say("\n----- %s\n%s" % (name, open(s).read().rstrip()))

dep = deploy_set(out) if green else None
published = None
if a.publish:
    if not green:
        say("\n! --publish skipped: the run is not green")
        published = False
    elif not dep:
        published = False
    else:
        published = publish(*dep)
say("\nRESULT: %s   (%d min)   artifacts: %s%s" % ("SUCCESS" if green else "FAILURE", (time.time() - started) / 60,
    os.path.abspath(out), "" if published is None else ("   PUBLISHED" if published else "   NOT published")))
sys.exit(0 if green and published is not False else 1)
