#!/usr/bin/env python3
"""Run yara64 (--docscan-json + --critical-rules) over hostile.py files.
A crash (exit code is an NTSTATUS / signal) or a hang (> timeout) is a failure;
otherwise the result must fit the expectation in hostile.json.
usage: hostile_run.py <yara64> <index.yar> <critical.yar> <dir> [timeout_s]
"""
import json, os, subprocess, sys, time
yara, index, crit, d = sys.argv[1:5]
tmo = int(sys.argv[5]) if len(sys.argv) > 5 else 120
exp = json.load(open(os.path.join(d, "hostile.json"), encoding="utf-8"))
q = os.path.join(d, "..", "hostile_q.json")
fails = 0
for fn, e in exp.items():
    if os.path.exists(q):
        os.remove(q)
    t = time.time()
    try:
        p = subprocess.run([yara, "-w", "--docscan-json", "--critical-rules=" + crit, "--critical-out=" + q, index, os.path.join(d, fn)],
                           capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=tmo)
        rc, err, out = p.returncode, p.stderr, p.stdout
    except subprocess.TimeoutExpired:
        rc, err, out = "HANG", "", ""
    dt = time.time() - t
    queued = os.path.exists(q) and os.path.getsize(q) > 0
    reason = next((l.split("(", 1)[1].rstrip(")") for l in err.splitlines() if "docscan-critical: skipped" in l), "")
    crash = rc == "HANG" or (isinstance(rc, int) and (rc < 0 or rc > 255))
    has_json = any(l.startswith("{") for l in out.splitlines())
    x = e["expect"]
    ok = not crash and has_json and (
        x == "any" or (x == "queue" and queued) or (x == "noqueue" and not queued) or
        (x == "skip" and not queued and reason) or (x == "skip:password" and "password" in reason) or
        (x == "skip:empty" and "no text" in reason))
    if queued:
        o = json.loads(open(q, encoding="utf-8").readline())
        info = "queued %d fragments, %d chars, %.1f MB JSON" % (o["text_info"]["fragment_count"], o["text_info"]["total_chars"], os.path.getsize(q) / 1e6)
    else:
        info = reason or "not queued"
    fails += not ok
    print("%-4s %-24s rc=%-5s %6.1fs  %s   [%s]" % ("ok" if ok else "FAIL", fn, rc, dt, info, e["note"]))
print("FAILURES: %d of %d" % (fails, len(exp)))
