#!/usr/bin/env python3
"""Check the mixed set (mix_corpus.py) - the scan verdict AND the critical queue.

Mode "cli": runs yara64 itself (--docscan-json + --critical-rules, no disarm).
Mode "watcher": reads the watcher results (docscan-results.json) and the queue.
Expectations: verdict >= expected.json; the vendor rule found in a part when
part_rule; queued exactly when the base document was queued in the clean run
(reference queue file); the queued text == the clean text (dde_split adds
"TEST").

usage: eval_mix.py cli <yara64> <index.yar> <critical.yar> <mix_dir> <reference_queue>
       eval_mix.py watcher <docscan-results.json> <queue> <mix_dir> <reference_queue>
"""
import json, os, subprocess, sys, collections
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_tests import split_chars, reconstruct

RANK = {"INFO": 0, "MEDIUM": 1, "HIGH": 2}
mode = sys.argv[1]
if mode == "cli":
    yara, index, crit, mix, ref = sys.argv[2:7]
else:
    results, queue, mix, ref = sys.argv[2:6]
exp = json.load(open(os.path.join(mix, "expected.json"), encoding="utf-8"))

def text_of(o):
    return reconstruct(o["fragments"])

clean = {}
for l in open(ref, encoding="utf-8"):
    if l.strip():
        o = json.loads(l)
        st, ex = os.path.splitext(o["document"]["name"])
        clean[(st, ex[1:])] = text_of(o)

got = {}      # file -> (verdict, findings, part_rules, vba_rules, disarm)
queued = {}   # file -> json
if mode == "cli":
    q = os.path.join(os.path.dirname(os.path.abspath(ref)), "mix_q.json")
    for fn in sorted(exp):
        if os.path.exists(q):
            os.remove(q)
        p = subprocess.run([yara, "-w", "--docscan-json", "--critical-rules=" + crit, "--critical-out=" + q,
                            index, os.path.join(mix, fn)], capture_output=True, text=True, encoding="utf-8", errors="replace")
        j = json.loads([l for l in p.stdout.split("\n") if l.startswith("{")][0])
        got[fn] = (j["verdict"], j["findings"], sorted({r for x in j.get("yara_part_matches", []) for r in x["rules"]}),
                   j.get("yara_matches", []), None)
        if os.path.exists(q):
            queued[fn] = json.loads(open(q, encoding="utf-8").readline())
else:
    for l in open(results, encoding="utf-8"):
        if not l.strip():
            continue
        r = json.loads(l)
        fn = r["docfile"]["name"]
        if fn in exp:
            d = r.get("docscan") or {}
            got[fn] = (r["verdict"], d.get("findings", []), sorted({x for y in d.get("yara_part_matches", []) or [] for x in y["rules"]}),
                       d.get("yara_matches", []) or [], r.get("disarm"))
    for l in open(queue, encoding="utf-8"):
        if l.strip():
            o = json.loads(l)
            queued[o["document"]["name"]] = o

fails = []
by_vec = collections.defaultdict(lambda: [0, 0])
for fn, e in sorted(exp.items()):
    v = got.get(fn)
    if v is None:
        fails.append((fn, "no scan record")); continue
    ok = RANK[v[0]] >= RANK[e["verdict"]]
    if e["part_rule"] and "gen_macro_ShellExecute_action" not in v[2] + v[3]:
        ok = False; fails.append((fn, "second pass: vendor rule not found", v[2], v[3]))
    if not RANK[v[0]] >= RANK[e["verdict"]]:
        fails.append((fn, "verdict %s < %s" % (v[0], e["verdict"]), v[1]))
    # the clean document of the same format (docm/xlsm/pptm came from docx/xlsx/pptx)
    fmt = {"docm": "docx", "xlsm": "xlsx", "pptm": "pptx"}.get(fn.rsplit(".", 1)[1], fn.rsplit(".", 1)[1])
    key = (e["base"], fmt)
    want_q = key in clean
    is_q = fn in queued
    if want_q != is_q:
        ok = False; fails.append((fn, "queued=%s, expected %s" % (is_q, want_q)))
    elif is_q:
        o = queued[fn]; t = text_of(o)
        ref_t = clean[key]
        # the DDE field result "TEST" (dde_split) and the empty DDEAUTO paragraph are real text
        same = t == ref_t or ("dde_split" in e["vectors"] and t.replace("TEST\n", "", 1).lstrip("\n") == ref_t)
        valid = t is not None and [(f["start"], f["end"], f["text"]) for f in split_chars(t)] == [(f["start"], f["end"], f["text"]) for f in o["fragments"]]
        if not same:
            ok = False; fails.append((fn, "queued text differs from the clean document", len(t or ""), len(ref_t)))
        if not valid:
            ok = False; fails.append((fn, "fragments != reference"))
    for vec in e["vectors"]:
        by_vec[vec][0] += ok; by_vec[vec][1] += 1

print("documents: %d, scanned: %d, queued: %d" % (len(exp), len(got), len(queued)))
print("verdicts:", dict(collections.Counter(g[0] for g in got.values())))
if mode == "watcher":
    print("disarm:", dict(collections.Counter((g[4] or "-").split(":")[0] for g in got.values())))
print("ok per vector:", {k: "%d/%d" % tuple(v) for k, v in sorted(by_vec.items())})
print("FAILURES: %d" % len(fails))
for f in fails[:40]:
    print("  ", f)
