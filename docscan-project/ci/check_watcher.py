#!/usr/bin/env python3
"""DocScan combat test - what the installed watcher did with every test file (cirun --combat, Windows).

Reads the lines the watcher appended to docscan-results.json during the test (from --results-offset on,
only files under --inbox) and checks them against the test files in --src/<set>/... :

  every file the watcher is meant to scan (its extension is in the watcher's -DocExt / -GenExt lists, and
  -CriticalExt with the third pass on) has a record and no ERROR;
  generated - verdict, disarm action and the verdict after disarm as in expected-verdicts.tsv;
  provided  - the customer's real samples: HIGH;
  malware   - every path of malware/expected.txt the watcher scans is detected (MEDIUM / HIGH or a vendor
              rule); paths it does not scan because of the extension are listed, not failed;
  corpus    - the policy verdict equals the one of the direct scan (--corpus-verdicts, the corpus step).

Prints a report (also written to --report) and writes the records of the test to --records.
usage: check_watcher.py --results F --results-offset N --log F --log-offset N --inbox DIR --src DIR
                        --watcher PS1 --expected TSV [--corpus-verdicts TSV] [--critical-on]
                        --records OUT --report OUT
"""
import argparse
import collections
import datetime
import json
import os
import re
import sys

SETS = ["generated", "provided", "malware", "corpus", "seeds"]


def watched_extensions(ps1, critical_on):
    """The default -DocExt / -GenExt / -CriticalExt of docscan-watcher.ps1 (comments may contain brackets)."""
    lists = {}
    cur = None
    for line in open(ps1, encoding="utf-8-sig"):
        code = line.split("#", 1)[0]
        m = re.search(r"\$(DocExt|GenExt|CriticalExt)\s*=\s*@\(", code)
        if m:
            cur = m.group(1)
            lists[cur] = []
            code = code[m.end():]
        if cur:
            lists[cur] += [e.lower() for e in re.findall(r'"(\.[A-Za-z0-9]+)"', code)]
            if ")" in code:
                cur = None
    ext = set(lists.get("DocExt", [])) | set(lists.get("GenExt", []))
    if critical_on:
        ext |= set(lists.get("CriticalExt", []))
    return ext


def read_from(path, offset):
    data = open(path, "rb").read()
    if offset > len(data):  # rotated meanwhile
        offset = 0
    return data[offset:].decode("utf-8", "replace")


def main():
    ap = argparse.ArgumentParser()
    for a in ("--results", "--log", "--inbox", "--src", "--watcher", "--expected", "--records", "--report"):
        ap.add_argument(a, required=True)
    ap.add_argument("--results-offset", type=int, default=0)
    ap.add_argument("--log-offset", type=int, default=0)
    ap.add_argument("--corpus-verdicts", default="")
    ap.add_argument("--critical-on", action="store_true")
    ap.add_argument("--max-size-mb", type=int, default=100)
    a = ap.parse_args()

    out = []
    fails = []

    def say(s=""):
        out.append(s)

    inbox = os.path.normcase(os.path.abspath(a.inbox)).rstrip("\\/") + os.sep
    recs = collections.defaultdict(list)  # (set, rel) -> records in order
    kept = []
    for line in read_from(a.results, a.results_offset).splitlines():
        if not line.startswith("{"):
            continue
        try:
            r = json.loads(line)
        except ValueError:
            continue
        p = os.path.normcase((r.get("docfile") or {}).get("path") or "")
        if not p.startswith(inbox):
            continue
        kept.append(line)
        parts = p[len(inbox):].replace("\\", "/").split("/", 1)
        if len(parts) == 2:
            recs[(parts[0], parts[1])].append(r)
    with open(a.records, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(kept) + ("\n" if kept else ""))
    log = read_from(a.log, a.log_offset)

    ext = watched_extensions(a.watcher, a.critical_on)
    files = {}  # (set, rel) -> (size, watched)
    for s in SETS:
        root = os.path.join(a.src, s)
        for dp, _, names in os.walk(root):
            for n in names:
                if n == "expected.txt" and s == "malware":
                    continue
                full = os.path.join(dp, n)
                rel = os.path.normcase(os.path.relpath(full, root)).replace("\\", "/")
                files[(s, rel)] = (os.path.getsize(full), os.path.splitext(n)[1].lower() in ext)

    def dv(r):  # verdict of the policy (yara64 --docscan-json)
        return (r.get("docscan") or {}).get("verdict") or "NONE"

    def kind(r):
        d = r.get("disarm") or "-"
        return d.split(":")[0].split(",")[0]

    stamps = []
    for rs in recs.values():
        for r in rs:
            try:
                stamps.append(datetime.datetime.fromisoformat(r["timestamp"]))
            except (KeyError, ValueError):
                pass
    nrec = sum(len(v) for v in recs.values())
    say("DocScan combat test: the installed watcher (SYSTEM), every file dropped into the inbox")
    if stamps:
        mins = (max(stamps) - min(stamps)).total_seconds() / 60
        say("records: %d   first %s   last %s   (%.0f min, %.1f files/min)" % (
            nrec, min(stamps).strftime("%H:%M:%S"), max(stamps).strftime("%H:%M:%S"), mins,
            len(recs) / mins if mins > 0 else 0))
    ov = len(re.findall(r"FileSystemWatcher error", log))
    gone = len(re.findall(r"gone before scan", log))
    say("watcher log: buffer overflows %d, 'gone before scan' %d" % (ov, gone))
    say()

    # ---- per set
    say("%-10s %6s %8s %8s %7s %6s %6s %6s %6s %6s %7s %7s" % (
        "set", "files", "watched", "scanned", "missing", "HIGH", "MEDIUM", "INFO", "SKIP", "ERROR", "disarm", "macros"))
    for s in SETS:
        keys = [k for k in files if k[0] == s]
        if not keys:
            continue
        w = [k for k in keys if files[k][1]]
        got = [k for k in w if recs.get(k)]
        miss = [k for k in w if not recs.get(k)]
        cnt = collections.Counter(recs[k][0].get("verdict") for k in got)
        dis = sum(1 for k in got if any(kind(r) not in ("-", "detect-only") for r in recs[k]))
        mac = sum(1 for k in got if any(r.get("macro") for r in recs[k]))
        say("%-10s %6d %8d %8d %7d %6d %6d %6d %6d %6d %7d %7d" % (
            s, len(keys), len(w), len(got), len(miss), cnt["HIGH"], cnt["MEDIUM"], cnt["INFO"], cnt["SKIPPED"],
            cnt["ERROR"], dis, mac))
        for k in miss:
            fails.append("%s/%s: watched extension, but no record" % k)
        for k in got:
            for r in recs[k]:
                if r.get("verdict") == "ERROR":
                    fails.append("%s/%s: ERROR %s" % (k[0], k[1], "; ".join(r.get("errors") or [])))
    crit = sum(1 for rs in recs.values() if any(r.get("critical") for r in rs))
    say("third pass: %s, documents queued for E5Search: %d" % ("on" if a.critical_on else "off", crit))
    acts = collections.Counter(kind(r) for rs in recs.values() for r in rs[:1])
    say("disarm actions (first scan): " + "  ".join("%s=%d" % kv for kv in sorted(acts.items())))
    say()

    # ---- generated: the reference of the document test
    exp = {}
    for line in open(a.expected, encoding="utf-8"):
        if line.strip() and not line.startswith("#"):
            p = line.rstrip("\n").split("\t")
            exp[os.path.normcase(p[0])] = tuple(p[1:4])
    say("generated samples against expected-verdicts.tsv (policy verdict / disarm / after):")
    bad = checked = 0
    for f, e in sorted(exp.items()):
        rs = recs.get(("generated", f))
        if not rs:
            continue  # already counted as missing
        checked += 1
        first = rs[0]
        v, d = dv(first), kind(first)
        if d in ("deleted", "quarantined"):
            after = "DELETED" if not os.path.exists(os.path.join(a.inbox, "generated", f)) else "NOT-DELETED"
        elif len(rs) > 1:
            after = dv(rs[-1])
        else:
            after = v if d in ("-", "detect-only") else "(no rescan)"
        ok = (v, d) == e[:2] and (after == e[2] or after == "(no rescan)")
        if not ok:
            bad += 1
            fails.append("generated/%s: got %s / %s / %s, expected %s / %s / %s" % ((f, v, d, after) + e))
        elif after == "(no rescan)":
            say("  %-28s %s / %s - no record of the rescan after disarm (expected after: %s)" % (f, v, d, e[2]))
    say("  %d/%d as expected (%d in the reference)" % (checked - bad, checked, len(exp)))
    say()

    # ---- provided: the customer's real samples
    prov = [k for k in files if k[0] == "provided"]
    if prov:
        say("customer's real samples (must be HIGH):")
        for k in sorted(prov):
            rs = recs.get(k)
            v = dv(rs[0]) if rs else "no record"
            say("  %-36s %-6s %s" % (k[1], v, (rs[0].get("disarm") or "") if rs else ""))
            if rs and v != "HIGH":
                fails.append("provided/%s: %s, expected HIGH" % (k[1], v))
        say()

    # ---- malware: expected detections
    ef = os.path.join(a.src, "malware", "expected.txt")
    if os.path.exists(ef):
        want = [os.path.normcase(l.strip()).replace("\\", "/") for l in open(ef, encoding="utf-8")
                if l.strip() and not l.startswith("#")]
        det, missed, notw, big = 0, [], [], []
        for p in want:
            fi = files.get(("malware", p))
            if fi is None:
                missed.append(p + " (not in the archive)")
            elif not fi[1]:
                notw.append(p)
            elif fi[0] > a.max_size_mb * 1024 * 1024:
                big.append(p)
            else:
                rs = recs.get(("malware", p)) or []
                # as check_corpus.py: a vendor rule on the file or on a part of it (a file inside an archive)
                if any(r.get("verdict") in ("MEDIUM", "HIGH") or r.get("yara_file_matches")
                       or (r.get("docscan") or {}).get("yara_file_matches")
                       or any(pm.get("rules") for pm in (r.get("docscan") or {}).get("yara_part_matches") or []
                              if isinstance(pm, dict))
                       for r in rs):
                    det += 1
                else:
                    missed.append(p)
        say("malware: %d expected detections - detected by the watcher %d, MISSED %d, not scanned by the watcher "
            "(extension not in its lists) %d, larger than %d MB %d" % (len(want), det, len(missed), len(notw),
                                                                     a.max_size_mb, len(big)))
        for p in missed:
            fails.append("malware/%s: MISSED by the watcher" % p)
        exts = collections.Counter(os.path.splitext(p)[1] or "(none)" for p in notw)
        if exts:
            say("  not scanned, by extension: " + "  ".join("%s=%d" % kv for kv in exts.most_common(15)))
        say()

    # ---- corpus: the same policy verdict as the direct scan
    if a.corpus_verdicts and os.path.exists(a.corpus_verdicts):
        direct = {}
        for line in open(a.corpus_verdicts, encoding="utf-8"):
            p = line.rstrip("\n").split("\t")
            if len(p) >= 2:
                rel = p[0][len("external/"):] if p[0].startswith("external/") else p[0]
                direct[os.path.normcase(rel).replace("\\", "/")] = p[1]
        same, diff = 0, []
        for k, rs in recs.items():
            if k[0] == "corpus" and k[1] in direct:
                if dv(rs[0]) == direct[k[1]]:
                    same += 1
                else:
                    diff.append("%s: watcher %s, direct scan %s" % (k[1], dv(rs[0]), direct[k[1]]))
        say("corpus: policy verdict = direct scan for %d files, different %d" % (same, len(diff)))
        for d in diff:
            fails.append("corpus/" + d)
        say()

    say("problems: %d" % len(fails))
    for f in fails[:200]:
        say("  " + f)
    if len(fails) > 200:
        say("  ... %d more" % (len(fails) - 200))
    say("RESULT: %s" % ("PASS" if not fails else "FAIL"))
    text = "\n".join(out) + "\n"
    open(a.report, "w", encoding="utf-8", newline="\n").write(text)
    sys.stdout.write(text)
    return 0 if not fails else 1


if __name__ == "__main__":
    sys.exit(main())
