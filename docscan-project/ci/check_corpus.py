#!/usr/bin/env python3
"""Corpus and malware checks for CI - the same on macOS, Linux and Windows.

Corpus mode: every file under --dir is scanned with the DocScan rule set; the verdicts go to --out (TSV:
relative path, verdict, findings, vendor matches). The run fails only if yara crashes, hangs or prints no
result for a file - a verdict itself is not judged here: cirun compares the TSVs of all platforms, and any
difference between macOS / Windows / Linux on the same files is a failure there.

Malware mode (--expect FILE): FILE lists relative paths (one per line, # comments) that MUST be detected -
a vendor rule match or a MEDIUM / HIGH verdict of the policy; a regression test on real samples. The samples are
only read, never executed. clean.txt next to FILE (if present) lists the opposite: real clean documents that once
gave a false alarm - each must stay INFO with no vendor match (a false-positive regression test).

The rules are compiled once (yarac, the file externals declared empty), then every file is scanned with
-C in parallel (one yara process per file, --jobs at a time).

usage: check_corpus.py --yara Y --yarac YC --rules R --dir D --out TSV [--expect FILE] [--timeout S] [--jobs N]
"""
import argparse
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile


def scan(yara, compiled, path, timeout):
    """-> (verdict, findings, vendor matches); verdict CRASH / TIMEOUT / NORESULT when yara failed."""
    try:
        p = subprocess.run([yara, "-w", "--docscan-json", "-C", compiled, path],
                           capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return "TIMEOUT", "", ""
    for line in p.stdout.decode("utf-8", "replace").splitlines():
        if line.startswith("{"):
            try:
                j = json.loads(line)
            except ValueError:
                continue
            d = j.get("docscan") if isinstance(j.get("docscan"), dict) else j
            verdict = d.get("verdict") or j.get("verdict") or "NORESULT"
            findings = ",".join(sorted(d.get("findings") or j.get("findings") or []))
            rules = set(d.get("yara_file_matches") or j.get("yara_file_matches") or [])
            # second pass: parts of the file (document pieces, files inside an archive)
            for pm in (d.get("yara_part_matches") or j.get("yara_part_matches") or []):
                if isinstance(pm, dict):
                    rules.update(pm.get("rules") or [])
            vendor = ",".join(sorted(rules))
            return verdict, findings, vendor
    return ("CRASH" if p.returncode not in (0, 1) else "NORESULT"), "", ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--yara", required=True)
    ap.add_argument("--yarac", required=True)
    ap.add_argument("--rules", required=True)
    ap.add_argument("--dir", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--expect", default="", help="malware mode: paths that must get a vendor match")
    ap.add_argument("--timeout", type=int, default=120, help="seconds per file")
    ap.add_argument("--jobs", type=int, default=os.cpu_count() or 2)
    a = ap.parse_args()

    files = []
    for root, _, names in os.walk(a.dir):
        for n in names:
            if n in ("expected.txt", "clean.txt", ".DS_Store"):
                continue
            files.append(os.path.join(root, n))
    files.sort()
    if not files:
        print("no files in %s" % a.dir)
        return 1

    with tempfile.TemporaryDirectory() as tmp:
        compiled = os.path.join(tmp, "rules.yarc")
        c = subprocess.run([a.yarac, "-w", "-d", "filename=", "-d", "filepath=", "-d", "extension=",
                            "-d", "filetype=", "-d", "owner=", a.rules, compiled], capture_output=True)
        if c.returncode != 0 or not os.path.exists(compiled):
            print("rules do not compile:\n" + c.stderr.decode("utf-8", "replace")[-2000:])
            return 1
        with concurrent.futures.ThreadPoolExecutor(max_workers=a.jobs) as pool:
            results = list(pool.map(lambda f: scan(a.yara, compiled, f, a.timeout), files))

    rel = [os.path.relpath(f, a.dir).replace(os.sep, "/") for f in files]
    with open(a.out, "w", encoding="utf-8", newline="\n") as out:
        for r, (v, fd, vm) in sorted(zip(rel, results)):
            out.write("%s\t%s\t%s\t%s\n" % (r, v, fd, vm))

    counts = {}
    for v, _, _ in results:
        counts[v] = counts.get(v, 0) + 1
    print("files: %d   %s" % (len(files), "  ".join("%s=%d" % kv for kv in sorted(counts.items()))))
    bad = [r for r, (v, _, _) in zip(rel, results) if v in ("CRASH", "TIMEOUT", "NORESULT")]
    for r in bad[:20]:
        print("  FAILED TO SCAN: " + r)

    missed = []
    if a.expect:
        want = [l.strip() for l in open(a.expect, encoding="utf-8") if l.strip() and not l.startswith("#")]
        got = dict(zip(rel, results))
        for w in want:
            v = got.get(w)
            # detected = a vendor rule matched OR the policy gave MEDIUM / HIGH (documents are often caught
            # by the policy itself: macro that runs programs, DDE, Equation Editor...)
            if v is None or not (v[2] or v[0] in ("MEDIUM", "HIGH")):
                missed.append(w)
        for w in missed:
            print("  MISSED: %s" % w)
        print("expected detections: %d/%d" % (len(want) - len(missed), len(want)))

    falsepos = []
    cf = os.path.join(os.path.dirname(a.expect), "clean.txt") if a.expect else ""
    if cf and os.path.exists(cf):
        clean = [l.strip() for l in open(cf, encoding="utf-8") if l.strip() and not l.startswith("#")]
        got = dict(zip(rel, results))
        for c in clean:
            v = got.get(c)
            if v is None:
                falsepos.append("%s (not in the set)" % c)
            elif v[0] in ("MEDIUM", "HIGH") or v[2]:
                falsepos.append("%s: %s %s %s" % (c, v[0], v[1], v[2]))
        for f in falsepos:
            print("  FALSE POSITIVE: %s" % f)
        print("clean documents without alarm: %d/%d" % (len(clean) - len(falsepos), len(clean)))

    ok = not bad and not missed and not falsepos
    print("RESULT: %s" % ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
