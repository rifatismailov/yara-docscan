#!/usr/bin/env python3
"""Document regression for CI (macOS, Linux, Windows): the same check as
test-range/run_tests.ps1, in Python so that every OS runs it.

For every sample: copy -> yara --docscan-json --docscan-disarm (verdict,
disarm action) -> rescan the cured copy (verdict after, or DELETED). The
result must match expected-verdicts.tsv; the originals must not change.

usage: check_verdicts.py --yara Y --rules R --samples DIR --expected TSV [--write]
"""
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time


def remove(path, tries=20):
    """Delete a file; on Windows an antivirus may hold it for a moment after it was written."""
    for i in range(tries):
        try:
            if os.path.exists(path):
                os.remove(path)
            return
        except PermissionError:
            time.sleep(0.25 * (i + 1))
    os.remove(path)


def scan(yara, rules, path, disarm, backup_dir):
    cmd = [yara, "-w", "--docscan-json"]
    if disarm:
        cmd += ["--docscan-disarm", "--docscan-backup-dir=" + backup_dir]
    p = subprocess.run(cmd + [rules, path], capture_output=True, text=True, encoding="utf-8", errors="replace")
    verdict, action = "ERROR", "-"
    for line in p.stdout.splitlines():
        if line.startswith("{"):
            try:
                verdict = json.loads(line).get("verdict", "ERROR")
            except ValueError:
                pass
        elif line.startswith("docscan-disarm:"):
            action = line.rsplit(" -> ", 1)[-1].strip()
    return verdict, action


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--yara", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--samples", required=True)
    ap.add_argument("--expected", required=True)
    ap.add_argument("--write", action="store_true", help="write the current results as the expectation")
    ap.add_argument("--workdir", default=None, help="folder for the working copies (default: system temp)."
                    " On Windows use a folder excluded from the antivirus")
    a = ap.parse_args()

    files = sorted(f for f in os.listdir(a.samples) if os.path.isfile(os.path.join(a.samples, f)))
    before = {f: hashlib.sha256(open(os.path.join(a.samples, f), "rb").read()).hexdigest() for f in files}
    rows = []
    if a.workdir:
        os.makedirs(a.workdir, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=a.workdir, ignore_cleanup_errors=True) as tmp:
        bak = os.path.join(tmp, "backup")
        os.makedirs(bak)
        for f in files:
            work = os.path.join(tmp, "work" + os.path.splitext(f)[1])
            shutil.copyfile(os.path.join(a.samples, f), work)
            verdict, action = scan(a.yara, a.rules, work, True, bak)
            after = scan(a.yara, a.rules, work, False, bak)[0] if os.path.exists(work) else "DELETED"
            action_kind = action.split(":")[0].split(",")[0]
            rows.append((f, verdict, action_kind, after))
            remove(work)

    if a.write:
        with open(a.expected, "w", encoding="utf-8", newline="\n") as out:
            out.write("# file\tverdict\tdisarm\tafter   (written by check_verdicts.py --write)\n")
            for r in rows:
                out.write("\t".join(r) + "\n")
        print("expectation written: %d files -> %s" % (len(rows), a.expected))
        return 0

    exp = {}
    for line in open(a.expected, encoding="utf-8"):
        if line.strip() and not line.startswith("#"):
            p = line.rstrip("\n").split("\t")
            exp[p[0]] = tuple(p[1:4])
    fails = 0
    print("%-30s %-8s %-12s %-8s" % ("file", "verdict", "disarm", "after"))
    for f, v, d, af in rows:
        e = exp.get(f)
        ok = e == (v, d, af)
        fails += not ok
        print("%-30s %-8s %-12s %-8s %s" % (f, v, d, af, "ok" if ok else "FAIL (expected %s)" % (e,)))
    missing = sorted(set(exp) - set(files))
    for m in missing:
        print("%-30s missing sample" % m)
    changed = [f for f in files if hashlib.sha256(open(os.path.join(a.samples, f), "rb").read()).hexdigest() != before[f]]
    print("\nverdicts: " + "  ".join("%s=%d" % (k, sum(1 for r in rows if r[1] == k)) for k in ("HIGH", "MEDIUM", "INFO", "ERROR")))
    print("after disarm: " + "  ".join("%s=%d" % (k, sum(1 for r in rows if r[3] == k)) for k in ("HIGH", "MEDIUM", "INFO", "DELETED")))
    print("originals unchanged" if not changed else "ORIGINALS CHANGED: %s" % changed)
    total = fails + len(missing) + len(changed)
    print("RESULT: %s (%d problem(s))" % ("PASS" if total == 0 else "FAIL", total))
    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
