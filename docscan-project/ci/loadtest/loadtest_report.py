#!/usr/bin/env python3
"""DocScan load test report: match the users' file actions (gen-*.csv) with the watcher's records.

usage: loadtest_report.py <run dir>      (a copy of C:\\loadtest\\runs\\<name> from the test server)

For every successful new / edit / rename action the watcher must write a record for that path at or after the
action time (an edit within the watcher's 60 s cooldown is covered by the scan of the later version):
  covered     - a record exists; latency = record time - action time;
  superseded  - no record, but the file was renamed / deleted later (nothing left to scan);
  unchanged   - an edit that wrote the same test document again (older loadgen.ps1): same content, the watcher
                rightly skips an unchanged file - not a miss;
  MISSED      - no record and the file is still there.
Also: verdicts, records with errors, watcher WARN / ERROR lines (buffer overflow, rescans), resources (perf.csv),
and a per-minute timeline (actions, records, latency) to see whether the watcher keeps up.
Exit code 1 when anything is MISSED.
"""
import csv, glob, json, os, sys
from collections import Counter, defaultdict
from datetime import datetime

if len(sys.argv) != 2:
    sys.exit(__doc__)
run = sys.argv[1]


def ts(s):
    return datetime.fromisoformat(s.strip())


def pct(v, p):
    if not v:
        return float("nan")
    v = sorted(v)
    return v[min(len(v) - 1, int(round(p / 100.0 * (len(v) - 1))))]


meta = json.load(open(os.path.join(run, "meta.json"), encoding="utf-8-sig"))
if isinstance(meta.get("docscan"), dict):  # older runs: Get-Content's string with its PS properties
    meta["docscan"] = meta["docscan"].get("value")
t0 = ts(meta["start"])

# --- actions
acts = []
for f in sorted(glob.glob(os.path.join(run, "gen-*.csv")) + glob.glob(os.path.join(run, "probe-*.csv"))):
    with open(f, encoding="utf-8") as fh:
        for r in csv.DictReader(fh):
            r["t"] = ts(r["time"])
            acts.append(r)
acts.sort(key=lambda r: r["t"])

# --- watcher records of this run
recs = defaultdict(list)
allrecs = []
ROT = ["%s.%d" % ("{}", k) for k in range(5, 0, -1)] + ["{}"]  # oldest first
for f in [x.format("docscan-results.json") for x in ROT]:
    p = os.path.join(run, f)
    if not os.path.exists(p):
        continue
    with open(p, encoding="utf-8-sig", errors="replace") as fh:
        for line in fh:
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                r = json.loads(line)
            except ValueError:
                continue
            t = ts(r["timestamp"])
            if t < t0:
                continue
            r["t"] = t
            allrecs.append(r)
            recs[r["docfile"]["path"].lower()].append(r)
# every scan is also a watcher.log line "<time> [OK|HIT|WARN|ERROR] <verdict> <category> <path>  <what>"; a rescan
# with an unchanged result is ONLY there (the watcher does not repeat it for Wazuh): it counts as coverage as well
import re
scan_re = re.compile(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) \[(?:OK|HIT|WARN|ERROR)\] (\S+)\s+(?:document|general)\s+(.*)$")
scans = defaultdict(list)  # path -> scan end times (log lines, 1 s resolution)
nscan = 0
for f in [x.format("watcher.log") for x in ROT]:
    p = os.path.join(run, f)
    if not os.path.exists(p):
        continue
    for line in open(p, encoding="utf-8-sig", errors="replace"):
        m = scan_re.match(line)
        if not m:
            continue
        t = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=t0.tzinfo)
        if t < t0.replace(microsecond=0):
            continue
        nscan += 1
        # "<path>  <what>": a path may itself hold two spaces ("WinHex  18.5.lnk") - every cut is a candidate
        rest = m.group(3).rstrip()
        cuts = [i for i in range(len(rest)) if rest.startswith("  ", i)] + [len(rest)]
        for i in cuts:
            scans[rest[:i].lower()].append(t)
for p_, r_ in recs.items():
    scans[p_].extend(r["t"] for r in r_)
for v in scans.values():
    v.sort()
for v in recs.values():
    v.sort(key=lambda r: r["t"])

# --- match
later = defaultdict(list)  # path -> times it stopped existing under that name (rename-from / delete)
for a in acts:
    if a["error"]:
        continue
    if a["action"] == "rename":
        later[a["src"].lower()].append(a["t"])
    elif a["action"] == "delete":
        later[a["path"].lower()].append(a["t"])

# the test document each file holds, in action order: an edit with the same source leaves the content unchanged
holds = {}
same_content = set()
for a in sorted(acts, key=lambda a: a["t"]):
    if a["error"]:
        continue
    p = a["path"].lower()
    if a["action"] in ("new", "probe"):
        holds[p] = a["src"]
    elif a["action"] == "edit":
        if holds.get(p) == a["src"]:
            same_content.add(id(a))
        holds[p] = a["src"]
    elif a["action"] == "rename":
        holds[p] = holds.pop(a["src"].lower(), None)

stat = Counter()
lat = []
missed = []
first_rec = {}
for a in acts:
    if a["action"] not in ("new", "edit", "rename", "probe"):
        continue
    if a["error"]:
        stat["action_error"] += 1
        continue
    p = a["path"].lower()
    hit = next((t for t in scans.get(p, []) if (t - a["t"]).total_seconds() >= -1), None)
    if hit:
        stat["covered"] += 1
        d = max(0.0, (hit - a["t"]).total_seconds())
        lat.append(d)
        a["lat"] = d
    elif any(t >= a["t"] for t in later.get(p, [])):
        stat["superseded"] += 1
    elif id(a) in same_content:
        stat["unchanged"] += 1
    else:
        stat["MISSED"] += 1
        missed.append(a)

# --- output
# a run still going (fetched mid-way): up to the last perf sample
_end = meta.get("end")
if not _end and os.path.exists(os.path.join(run, "perf.csv")):
    _l = open(os.path.join(run, "perf.csv"), encoding="utf-8").read().strip().splitlines()
    _end = _l[-1].split(",")[0] if len(_l) > 1 else None
dur = (ts(_end) - t0).total_seconds() / 60 if _end else float("nan")
print(("RUNNING - " if not meta.get("end") else "") + "run %s: %s users, %s min, interval %s s, burst %s; DocScan %s; server %s CPU / %s GB; sessions %s; took %.1f min"
      % (meta["name"], meta["users"], meta["minutes"], meta["interval_sec"], meta["burst"], meta.get("docscan"),
         meta["cpu"], meta["ram_gb"], meta.get("sessions"), dur))
ac = Counter(a["action"] for a in acts)
print("\nactions: %d  (%s)  with errors: %d" % (len(acts), ", ".join("%s %d" % kv for kv in sorted(ac.items())),
                                               sum(1 for a in acts if a["error"])))
errs = Counter(a["error"].split(".")[0][:80] for a in acts if a["error"])
for e, n in errs.most_common(5):
    print("  %4d x %s" % (n, e))
print("watcher scans: %d (%.1f / min); records for Wazuh: %d (unchanged rescans are not repeated there)"
      % (nscan, nscan / dur if dur == dur and dur else 0, len(allrecs)))
print("  verdicts: " + ", ".join("%s %d" % kv for kv in Counter(r["verdict"] for r in allrecs).most_common()))
print("  disarmed: %d, critical queued: %d, records with errors: %d"
      % (sum(1 for r in allrecs if r.get("disarm") and not str(r["disarm"]).startswith("failed")),
         sum(1 for r in allrecs if r.get("critical")), sum(1 for r in allrecs if r.get("errors"))))
re_ = Counter("; ".join(r["errors"])[:90] for r in allrecs if r.get("errors"))
for e, n in re_.most_common(5):
    print("  %4d x %s" % (n, e))

print("\ncoverage: covered %d, superseded %d, unchanged %d, MISSED %d, action errors %d"
      % (stat["covered"], stat["superseded"], stat["unchanged"], stat["MISSED"], stat["action_error"]))
for kind in ("probe", "new", "rename", "edit"):
    l = [a["lat"] for a in acts if a["action"] == kind and "lat" in a]
    if l:
        print("latency %-6s -> scan, s: p50 %5.1f  p90 %5.1f  p99 %5.1f  max %5.1f  (%d)%s"
              % (kind, pct(l, 50), pct(l, 90), pct(l, 99), max(l), len(l),
                 "   <- a rescan waits out the watcher's 60 s cooldown" if kind == "edit" else
                 "   <- single files dropped during the burst (what a user feels)" if kind == "probe" else ""))
for a in missed[:15]:
    print("  MISSED %s %s %s" % (a["time"], a["action"], a["path"]))
if len(missed) > 15:
    print("  ... %d more" % (len(missed) - 15))

# watcher log
wl = Counter()
wlines = []
for f in [x.format("watcher.log") for x in ROT]:
    p = os.path.join(run, f)
    if not os.path.exists(p):
        continue
    for line in open(p, encoding="utf-8-sig", errors="replace"):
        try:
            t = datetime.strptime(line[:19], "%Y-%m-%d %H:%M:%S")
        except ValueError:
            continue
        if t < t0.replace(tzinfo=None):
            continue
        for k in ("[WARN]", "[ERROR]"):
            if k in line:
                wl[k] += 1
                wlines.append(line.rstrip())
        if "buffer overflow" in line:
            wl["overflow"] += 1
        if "rescan after overflow" in line:
            wl["rescan"] += 1
print("\nwatcher.log: WARN %d, ERROR %d, buffer overflow %d, rescans %d"
      % (wl["[WARN]"], wl["[ERROR]"], wl["overflow"], wl["rescan"]))
for l in Counter(l[20:120] for l in wlines).most_common(6):
    print("  %4d x %s" % (l[1], l[0]))

# resources
pp = os.path.join(run, "perf.csv")
if os.path.exists(pp):
    rows = list(csv.DictReader(open(pp, encoding="utf-8")))

    def col(k):
        return [float(r[k]) for r in rows if r.get(k) not in ("", None)]
    cpu, free, wc, ws, yc, dq = (col(k) for k in ("cpu_pct", "free_ram_mb", "watcher_cpu_pct", "watcher_ws_mb",
                                                  "yara64", "disk_queue"))
    print("\nresources (%d samples): CPU avg %.0f%% max %.0f%%; free RAM min %.0f MB; watcher CPU avg %.1f%% max %.1f%%"
          " (of all cores; 1 core = %.1f%%), memory max %.0f MB; yara64 at once max %.0f; disk queue max %.0f"
          % (len(rows), sum(cpu) / len(cpu), max(cpu), min(free), sum(wc) / max(1, len(wc)), max(wc or [0]),
             100.0 / meta["cpu"], max(ws or [0]), max(yc or [0]), max(dq or [0])))

# timeline
print("\nminute  actions  records  latency p50 / max, s")
bm = defaultdict(lambda: [0, 0, []])
for a in acts:
    m = int((a["t"] - t0).total_seconds() // 60)
    bm[m][0] += 1
    if "lat" in a:
        bm[m][2].append(a["lat"])
for r in allrecs:
    bm[int((r["t"] - t0).total_seconds() // 60)][1] += 1
for m in sorted(bm):
    a, r, l = bm[m]
    print("%5d  %7d  %7d   %s" % (m, a, r, ("%.1f / %.1f" % (pct(l, 50), max(l))) if l else "-"))

sys.exit(1 if stat["MISSED"] else 0)
