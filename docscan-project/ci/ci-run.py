#!/usr/bin/env python3
"""The "Run" button: push -> Forgejo mirror sync -> start the build-test workflow -> follow it
-> download the artifacts. Used by the VS Code task "DocScan CI".

  python3 docscan-project/ci/ci-run.py [--fuzz SECONDS] [--no-push]

Forgejo address and API token: ~/.docscan/hosts.json, profile "forgejo" ({"url", "token"}), or the
environment FORGEJO_URL / FORGEJO_TOKEN. Repository: FORGEJO_REPO (default rifat/yara-docscan).
"""
import argparse, json, os, subprocess, sys, time, urllib.request, urllib.error, zipfile, io

ap = argparse.ArgumentParser()
ap.add_argument("--fuzz", default="300", help="fuzzing seconds per OS (0 = none)")
ap.add_argument("--no-push", action="store_true", help="do not git push (the commit is already on GitHub)")
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


branch = git("rev-parse", "--abbrev-ref", "HEAD")
sha = git("rev-parse", "HEAD")
if git("status", "--porcelain", "--untracked-files=no"):
    print("! there are uncommitted changes - CI builds the last COMMIT %s, not the working tree" % sha[:8])

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
api("POST", "/repos/%s/actions/workflows/ci.yml/dispatches" % REPO, {"ref": branch, "inputs": {"fuzz_seconds": str(a.fuzz)}})
run = None
for _ in range(40):
    runs = api("GET", "/repos/%s/actions/runs?limit=10" % REPO).get("workflow_runs", [])
    for r in runs:
        if r.get("head_sha") == sha and r.get("event") == "workflow_dispatch":
            run = r
            break
    if run:
        break
    time.sleep(3)
if not run:
    sys.exit("the run did not appear - check Forgejo -> Дії")
rid = run["id"]
print("    run #%s: %s" % (run.get("run_number", rid), run.get("html_url", URL + "/" + REPO + "/actions")), flush=True)

print("4/4 follow the run (Ctrl+C stops following, not the run)", flush=True)
last = {}
while True:
    jobs = api("GET", "/repos/%s/actions/runs/%s/jobs" % (REPO, rid)).get("jobs", [])
    for j in jobs:
        st = "%s/%s" % (j.get("status"), j.get("conclusion") or "-")
        if last.get(j["name"]) != st:
            last[j["name"]] = st
            print("    %-10s %-22s %4ds" % (j["name"], st, time.time() - started), flush=True)
    r = api("GET", "/repos/%s/actions/runs/%s" % (REPO, rid))
    if r.get("status") in ("completed", "success", "failure", "cancelled", "skipped") or r.get("conclusion"):
        break
    time.sleep(15)

concl = r.get("conclusion") or r.get("status")
out = os.path.join("ci-out", "run-%s" % rid)
os.makedirs(out, exist_ok=True)
for art in api("GET", "/repos/%s/actions/runs/%s/artifacts" % (REPO, rid)).get("artifacts", []):
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
