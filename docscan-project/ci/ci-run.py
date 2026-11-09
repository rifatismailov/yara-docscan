#!/usr/bin/env python3
"""The "Run" button: commit (if there are changes) -> push -> Forgejo mirror sync -> start the
build-test workflow -> follow it -> download the artifacts. Used by the VS Code ▷ / task "DocScan CI".

  python3 docscan-project/ci/ci-run.py [--fuzz SECONDS] [-m "message"] [--no-commit] [--no-push]

Auto-commit: every change git does not ignore (git add -A) goes into one commit, unless the
safety check finds something that must not reach the public repository (internal addresses,
host/user names, passwords, tokens, files > 5 MB) - then nothing is committed and the script stops.

Forgejo address and API token: ~/.docscan/hosts.json, profile "forgejo" ({"url", "token"}), or the
environment FORGEJO_URL / FORGEJO_TOKEN. Repository: FORGEJO_REPO (default rifat/yara-docscan).
"""
import argparse, json, os, subprocess, sys, time, urllib.request, urllib.error, zipfile, io

ap = argparse.ArgumentParser()
ap.add_argument("--fuzz", default="300", help="fuzzing seconds per OS (0 = none)")
ap.add_argument("--no-push", action="store_true", help="do not git push (the commit is already on GitHub)")
ap.add_argument("--no-commit", action="store_true", help="do not commit local changes (CI builds the last commit)")
ap.add_argument("-m", "--message", default="", help="commit message for the auto-commit")
ap.add_argument("--remote", default="docscan", help="git remote of GitHub (default: docscan)")
a = ap.parse_args()

cfg = {}
try:
    cfg = json.load(open(os.path.expanduser("~/.docscan/hosts.json")))["forgejo"]
except (OSError, KeyError, ValueError):
    pass
URL = os.environ.get("FORGEJO_URL", cfg.get("url", "")).rstrip("/")
TOKEN = os.environ.get("FORGEJO_TOKEN", cfg.get("token", ""))
REPO = os.environ.get("FORGEJO_REPO", "rifat/yara-docscan")
if not URL or not TOKEN:
    sys.exit("Forgejo URL/token not set (~/.docscan/hosts.json profile 'forgejo' or FORGEJO_URL/FORGEJO_TOKEN)")


def api(method, path, body=None, raw=False):
    req = urllib.request.Request(URL + "/api/v1" + path, method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Authorization": "token " + TOKEN, "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read()
        return data if raw else (json.loads(data) if data else None)


def git(*args):
    return subprocess.run(["git", *args], capture_output=True, text=True, check=True).stdout.strip()


# what must never reach the public repository (same check as before every manual push)
import re
_INTERNAL_NAMES = "|".join(["fort" + "una", "(?<!rifat)" + "isma" + "ilov", "odessa" + r"\.ua"])  # split: this file is public too
FORBIDDEN = [
    (re.compile(r"\b(192\.168\.(1|17|88|129)|10\.10\.67|172\.118\.18)\.\d{1,3}\b"), "internal IP address"),
    (re.compile(_INTERNAL_NAMES, re.I), "internal host / user name"),
    (re.compile(r"(password|passwd|pwd|secret|token)['\"]?\s*[:=]\s*['\"][^'\"\s]{6,}['\"]", re.I), "password / token value"),
    (re.compile(r"\b[0-9a-f]{40}\b"), "40-hex token (Forgejo/GitHub)"),
]
MAX_FILE = 5 * 1024 * 1024


def safety_check():
    """Check the staged changes; returns a list of problems."""
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
    print("0/4 commit local changes:", flush=True)
    print("\n".join("    " + l for l in changes.splitlines()[:30]))
    subprocess.run(["git", "add", "-A"], check=True)
    problems = safety_check()
    if problems:
        subprocess.run(["git", "reset", "-q"], check=True)   # unstage, files stay as they are
        print("\n! NOT committed - the public repository must not get:")
        print("\n".join("    " + p for p in problems[:20]))
        sys.exit("fix these changes (or commit by hand with --no-commit) and press Run again")
    files = git("diff", "--cached", "--name-only").splitlines()
    msg = a.message or ("ci: " + (", ".join(os.path.basename(f) for f in files[:6]) + (" ..." if len(files) > 6 else "")))
    subprocess.run(["git", "commit", "-q", "-m", msg], check=True)
    print("    committed: %s  (%s)" % (git("rev-parse", "--short", "HEAD"), msg), flush=True)
elif changes:
    print("! uncommitted changes (--no-commit) - CI builds the last COMMIT %s" % git("rev-parse", "--short", "HEAD"))
sha = git("rev-parse", "HEAD")

if not a.no_push:
    print("1/4 git push %s %s" % (a.remote, branch), flush=True)
    subprocess.run(["git", "push", a.remote, branch], check=True)

print("2/4 Forgejo: sync the mirror", flush=True)
api("POST", "/repos/%s/mirror-sync" % REPO)
for _ in range(60):
    head = api("GET", "/repos/%s/branches/%s" % (REPO, urllib.request.quote(branch, safe="")))["commit"]["id"]
    if head == sha:
        break
    time.sleep(3)
else:
    sys.exit("the mirror did not get %s in 3 minutes (is it pushed to GitHub?)" % sha[:8])

print("3/4 start the workflow build-test (fuzzing %ss per OS)" % a.fuzz, flush=True)
started = time.time()
info = api("POST", "/repos/%s/actions/workflows/ci.yml/dispatches" % REPO,
           {"ref": branch, "inputs": {"fuzz_seconds": str(a.fuzz)}, "return_run_info": True})
rid = info["id"]
print("    run #%s: %s/%s/actions/runs/%s   jobs: %s" % (info.get("run_number", rid), URL, REPO, rid,
                                                       ", ".join(info.get("jobs", []))), flush=True)

print("4/4 follow the run (Ctrl+C stops following, not the run)", flush=True)
last = {}
while True:
    jobs = api("GET", "/repos/%s/actions/runs/%s/jobs" % (REPO, rid))
    if isinstance(jobs, dict):
        jobs = jobs.get("jobs", [])
    for j in jobs:
        st = j.get("status")
        if last.get(j["name"]) != st:
            last[j["name"]] = st
            print("    %-10s %-22s %4ds" % (j["name"], st, time.time() - started), flush=True)
    r = api("GET", "/repos/%s/actions/runs/%s" % (REPO, rid))
    if r.get("status") in ("success", "failure", "cancelled", "skipped"):
        break
    time.sleep(15)

concl = r.get("status")
out = os.path.join("ci-out", "run-%s" % rid)
os.makedirs(out, exist_ok=True)
arts = api("GET", "/repos/%s/actions/runs/%s/artifacts" % (REPO, rid))
for art in (arts.get("artifacts", []) if isinstance(arts, dict) else arts):
    try:
        zipfile.ZipFile(io.BytesIO(api("GET", "/repos/%s/actions/artifacts/%s/zip" % (REPO, art["id"]), raw=True))) \
            .extractall(os.path.join(out, art["name"]))
    except (urllib.error.HTTPError, zipfile.BadZipFile) as e:
        print("    artifact %s: %s" % (art["name"], e))
for name in sorted(os.listdir(out)):
    s = os.path.join(out, name, "summary.txt")
    if os.path.exists(s):
        print("\n----- %s\n%s" % (name, open(s).read().rstrip()))
print("\nRESULT: %s   (%d min)   artifacts: %s" % (str(concl).upper(), (time.time() - started) / 60, os.path.abspath(out)))
sys.exit(0 if str(concl) in ("success",) else 1)
