#!/usr/bin/env python3
"""Run yara64 --critical-rules over the converted E5Search test corpus.

For every document: queued or not (vs the label from the file name:
tp_*/tph_*/tp_gen_* = positive, fp_*/fph_* = negative), the matched rules, and
for every queued JSON: sha256/size, JSON invariants, fragments == the reference
algorithm. usage: eval_corpus.py <yara64> <rules> <docs_dir> <work_dir>
"""
import collections
import hashlib
import json
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from run_tests import split_chars, reconstruct  # the reference copy

yara, rules, docs, work = sys.argv[1:5]
os.makedirs(work, exist_ok=True)
main = os.path.join(work, "never.yar")
open(main, "w").write("rule never { condition: false }\n")


def label(fn):
    if fn.startswith("tp_gen"):
        return "TP-gen"
    if fn.startswith("tph"):
        return "TP-hard"
    if fn.startswith("tp"):
        return "TP"
    if fn.startswith("fph"):
        return "FP-hard"
    return "FP"


stats = collections.defaultdict(lambda: [0, 0])      # (class, ext) -> [queued, total]
rulehits = collections.Counter()
bad, skipped, missed, fps = [], [], [], []
texts = collections.defaultdict(dict)                # stem -> ext -> total_chars
for fn in sorted(os.listdir(docs)):
    path = os.path.join(docs, fn)
    stem, ext = os.path.splitext(fn)
    ext = ext[1:]
    q = os.path.join(work, "q.json")
    if os.path.exists(q):
        os.remove(q)
    p = subprocess.run([yara, "--critical-rules=" + rules, "--critical-out=" + q, main, path],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    if "skipped" in p.stderr:
        skipped.append((fn, p.stderr.strip()))
    lines = open(q, encoding="utf-8").read().split("\n") if os.path.exists(q) else [""]
    objs = [json.loads(l) for l in lines if l]
    c = label(stem)
    st = stats[(c, ext)]
    st[1] += 1
    if not objs:
        if c.startswith("TP"):
            missed.append(fn)
        continue
    st[0] += 1
    o = objs[0]
    if c.startswith("FP"):
        fps.append((fn, o["metadata"]["yara_matches"]))
    for r in o["metadata"]["yara_matches"]:
        rulehits[r] += 1
    raw = open(path, "rb").read()
    fr = o["fragments"]
    errs = []
    if o["document"]["sha256"] != hashlib.sha256(raw).hexdigest():
        errs.append("sha256")
    if o["document"]["size_bytes"] != len(raw) or o["document"]["format"] != ext:
        errs.append("size/format")
    if fr[0]["start"] != 0 or fr[-1]["end"] != o["text_info"]["total_chars"] or o["text_info"]["fragment_count"] != len(fr):
        errs.append("text_info")
    if any(f["index"] != i or f["end"] - f["start"] != len(f["text"]) or not f["text"].strip() for i, f in enumerate(fr)):
        errs.append("fragment fields")
    t = reconstruct(fr)
    if t is None:
        errs.append("inconsistent slices")
    elif [(f["start"], f["end"], f["text"]) for f in split_chars(t)] != [(f["start"], f["end"], f["text"]) for f in fr]:
        errs.append("!= reference")
    if errs:
        bad.append((fn, errs))
    texts[stem][ext] = o["text_info"]["total_chars"]

classes = ["TP", "TP-hard", "TP-gen", "FP", "FP-hard"]
exts = sorted({e for _, e in stats})
print("queued / documents (rows: class, columns: format)")
print("%-8s" % "" + "".join("%9s" % e for e in exts) + "%10s" % "total")
for c in classes:
    row, qs, ts = "", 0, 0
    for e in exts:
        q, t = stats.get((c, e), [0, 0])
        qs += q
        ts += t
        row += "%9s" % ("%d/%d" % (q, t) if t else "-")
    print("%-8s" % c + row + "%10s" % ("%d/%d" % (qs, ts)))
pos = sum(v[0] for k, v in stats.items() if k[0].startswith("TP")), sum(v[1] for k, v in stats.items() if k[0].startswith("TP"))
neg = sum(v[0] for k, v in stats.items() if k[0].startswith("FP")), sum(v[1] for k, v in stats.items() if k[0].startswith("FP"))
print("\npositives queued (recall of the pre-filter): %d/%d = %.0f%%" % (pos[0], pos[1], 100.0 * pos[0] / pos[1]))
print("negatives queued (sent to E5Search anyway):  %d/%d = %.0f%%" % (neg[0], neg[1], 100.0 * neg[0] / neg[1]))
print("rule hits:", dict(rulehits))
print("JSON/fragment errors: %d %s" % (len(bad), bad[:10]))
print("skipped by yara: %d %s" % (len(skipped), skipped[:5]))
missed_stems = sorted({os.path.splitext(f)[0] for f in missed})
print("positives NOT queued (%d files, %d documents): %s" % (len(missed), len(missed_stems), missed_stems))
fp_stems = collections.Counter(os.path.splitext(f)[0] for f, _ in fps)
print("negatives queued (documents): %s" % dict(fp_stems))
# same document, different formats: text length spread
spread = {s: v for s, v in texts.items() if len(v) > 1 and max(v.values()) - min(v.values()) > 0.05 * max(v.values())}
print("documents whose text length differs >5%% between formats: %d %s" % (len(spread), list(spread.items())[:3]))
