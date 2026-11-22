#!/usr/bin/env python3
"""Quality of critical-information rules (pass 3) on a labelled set and on a clean corpus.

  eval_sensitive.py --yara ./yara --rules docscan-project/rules/docscan-index.yar \\
      --critical <rules.yar> --dataset ~/docscan-test-dataset-v2 [--corpus <clean documents folder>] [--out report.txt]

Every document is scanned by yara64 with --critical-rules, as on a PC. A rule's category is taken from its name:
ORG_<CATEGORY>_... (BANK PERS CRED KEYS TOK INFRA CLASS ORG -> bank personal credentials keys tokens infra classified
org), or from the meta "category" line of the rule. The dataset (gen_sensitive_dataset.py) has expected.tsv: every
category present in each document, or "none".

Per category: found / missed (recall) and false alarms (precision); lists of misses and false alarms. With --corpus:
documents of a clean corpus on which any rule matched (each is a false alarm, unless the corpus really holds such data).
"""
import argparse
import csv
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict

CODES = {"BANK": "bank", "PERS": "personal", "CRED": "credentials", "KEYS": "keys", "TOK": "tokens",
         "INFRA": "infra", "CLASS": "classified", "ORG": "org"}
DOC_EXT = {".docx", ".docm", ".xlsx", ".xlsm", ".pptx", ".odt", ".ods", ".odp", ".doc", ".xls", ".ppt", ".rtf", ".txt", ".csv"}


def rule_categories(path):
    """rule name -> category (meta "category" wins over the name). path: a .yar or a folder of .yar (as on a PC)."""
    if os.path.isdir(path):
        cats = {}
        for f in sorted(os.listdir(path)):
            if f.endswith(".yar") and not f.startswith("."):
                cats.update(rule_categories(os.path.join(path, f)))
        return cats
    cats, cur = {}, None
    for line in open(path, encoding="utf-8"):
        m = re.match(r'\s*(?:private\s+|global\s+)*rule\s+(\w+)', line)
        if m:
            cur = m.group(1)
            p = cur.split("_")
            if len(p) > 2 and p[1] in CODES:
                cats[cur] = CODES[p[1]]
            continue
        m = re.match(r'\s*category\s*=\s*"([^"]+)"', line)
        if m and cur:
            cats[cur] = m.group(1).strip()
    return cats


def scan(yara, rules, critical, path, queue):
    p = subprocess.run([yara, "-w", "--file-vars", "--critical-rules=" + critical, "--critical-out=" + queue, rules, path],
                       capture_output=True, text=True, timeout=120)
    out = p.stdout + p.stderr
    if "do not compile" in out or out.startswith("error"):
        sys.exit("the critical rules do not compile:\n" + out)
    m = re.search(r'docscan-critical: queued .*?rules=(\S*)', out)
    return set(m.group(1).split(",")) - {""} if m else set()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--yara", required=True)
    ap.add_argument("--rules", required=True, help="DocScan rules (docscan-index.yar)")
    ap.add_argument("--critical", required=True, help="critical-information rules to evaluate: a .yar or a folder of .yar")
    ap.add_argument("--dataset", required=True, help="folder with expected.tsv (gen_sensitive_dataset.py)")
    ap.add_argument("--corpus", help="clean documents (any rule match there = a false alarm)")
    ap.add_argument("--out", help="write the report here too")
    a = ap.parse_args()
    cats = rule_categories(a.critical)
    queue = os.path.join(tempfile.mkdtemp(prefix="docscan-crit-"), "queue.json")
    rep = []

    def say(s=""):
        print(s)
        rep.append(s)

    exp = list(csv.DictReader(open(os.path.join(a.dataset, "expected.tsv"), encoding="utf-8"), delimiter="\t"))
    allcats = sorted(set(CODES.values()))
    tp, fn, fp = defaultdict(int), defaultdict(list), defaultdict(list)
    for r in exp:
        path = os.path.join(a.dataset, r["folder"], r["file"]) if r.get("folder") else None
        if not path or not os.path.exists(path):
            for root, _, files in os.walk(a.dataset):
                if r["file"] in files:
                    path = os.path.join(root, r["file"])
        hit = scan(a.yara, a.rules, a.critical, path, queue)
        got = {cats.get(x, "?") for x in hit}
        want = set(r["expected"].split(",")) - {"none", ""}
        for c in allcats:
            if c in want and c in got:
                tp[c] += 1
            elif c in want:
                fn[c].append(r["file"])
            elif c in got:
                fp[c].append("%s (%s)" % (r["file"], ",".join(sorted(x for x in hit if cats.get(x) == c))))
    say("Dataset: %s (%d documents), rules: %s (%d rules)" % (a.dataset, len(exp), a.critical, len(cats)))
    say("%-12s %6s %7s %7s %8s %9s" % ("category", "found", "missed", "false", "recall", "precision"))
    T = F = M = 0
    for c in allcats:
        t, m, f = tp[c], len(fn[c]), len(fp[c])
        T, M, F = T + t, M + m, F + f
        say("%-12s %6d %7d %7d %7.0f%% %8.0f%%" % (c, t, m, f, 100.0 * t / max(1, t + m), 100.0 * t / max(1, t + f)))
    say("%-12s %6d %7d %7d %7.0f%% %8.0f%%" % ("TOTAL", T, M, F, 100.0 * T / max(1, T + M), 100.0 * T / max(1, T + F)))
    for c in allcats:
        if fn[c]:
            say("missed %-11s %s" % (c + ":", ", ".join(fn[c])))
    for c in allcats:
        if fp[c]:
            say("false  %-11s %s" % (c + ":", ", ".join(fp[c])))
    if a.corpus:
        files = [os.path.join(r, f) for r, _, fs in os.walk(a.corpus) for f in fs if os.path.splitext(f)[1].lower() in DOC_EXT]
        hits = []
        for p in sorted(files):
            h = scan(a.yara, a.rules, a.critical, p, queue)
            if h:
                hits.append((os.path.relpath(p, a.corpus), sorted(h)))
        say()
        say("Clean corpus: %s - %d documents, alarms on %d (%.1f%%)" % (a.corpus, len(files), len(hits), 100.0 * len(hits) / max(1, len(files))))
        by = defaultdict(int)
        for _, h in hits:
            for x in h:
                by[x] += 1
        for x, n in sorted(by.items(), key=lambda kv: -kv[1]):
            say("  %-24s %d" % (x, n))
        for p, h in hits[:40]:
            say("  %s  %s" % (p, ",".join(h)))
    if a.out:
        open(a.out, "w", encoding="utf-8").write("\n".join(rep) + "\n")


if __name__ == "__main__":
    main()
