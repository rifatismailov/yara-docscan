#!/usr/bin/env python3
"""Step-2 candidates for the vendor set: every signature-base yara/*.yar not in vendor-selection.txt
and every Elastic Windows_/Multi_ file, platform-filtered per rule like build_vendor_rules.py; each
file compiled alone with the THOR externals. Writes <dir>/cand/<ns>.yar, <dir>/cand.list
(ns, source, path, rules) and <dir>/bad.list. Also compiles all of them, one namespace per file,
into <dir>/cand.yarc for fp_scan.ps1 on a clean Windows.

  python3 make_candidates.py [DIR]
"""
import sys, re, subprocess, os
from pathlib import Path
T = Path(__file__).resolve().parent; sys.path.insert(0, str(T))
import build_vendor_rules as B
V = B.DEFAULT_VENDOR
OUT = Path(sys.argv[1] if len(sys.argv) > 1 else "candidates").resolve() / "cand"; OUT.mkdir(parents=True, exist_ok=True)
YARAC = str(T.parents[2] / "yarac")
EXT = sum((["-d", f"{v}="] for v in ("filename","filepath","extension","filetype","owner")), [])
sel = {(l.split()[1], l.split()[2]) for l in (T/"vendor-selection.txt").read_text().splitlines() if l.strip() and not l.startswith('#')}
cands = []
for f in sorted((V/"signature-base/yara").glob("*.yar")):
    rel = "yara/" + f.name
    if ("signature-base", rel) not in sel: cands.append(("signature-base", rel))
for f in sorted((V/"protections-artifacts/yara/rules").glob("*.yar")):
    if f.name.startswith(("Windows_", "Multi_")):
        cands.append(("protections-artifacts", "yara/rules/" + f.name))
good, bad = [], []
for i, (src, rel) in enumerate(cands):
    text = (V/src/rel).read_text(encoding="utf-8", errors="replace")
    pre, rules, tail = B.split_rules(text)
    keep = []; nk = 0
    kept_conds = " ".join(r['cond'] for r in rules if r['private'] or not B.platform_reason(rel, r))
    for r in rules:
        why = None if r['private'] else B.platform_reason(rel, r)
        if why and re.search(r'\b%s\b' % r['name'], kept_conds): why = None
        if why: continue
        keep.append(r['text']); nk += 0 if r['private'] else 1
    if not nk: continue
    ns = "c%04d" % i
    p = OUT / f"{ns}.yar"; p.write_text(pre + "".join(keep) + tail, encoding="utf-8")
    r = subprocess.run([YARAC, "-w", *EXT, str(p), os.devnull], capture_output=True, text=True)
    if r.returncode: bad.append(f"{src}\t{rel}\t{(r.stderr or r.stdout).strip().splitlines()[0][:200]}"); p.unlink(); continue
    good.append(f"{ns}\t{src}\t{rel}\t{nk}")
(OUT.parent/"cand.list").write_text("\n".join(good)+"\n"); (OUT.parent/"bad.list").write_text("\n".join(bad)+"\n")
print("candidates", len(cands), "good files", len(good), "rules", sum(int(g.split('\t')[3]) for g in good), "bad", len(bad))
args = [f"{g.split(chr(9))[0]}:{OUT}/{g.split(chr(9))[0]}.yar" for g in good]
r = subprocess.run([YARAC, "-w", *EXT, *args, str(OUT.parent / "cand.yarc")], capture_output=True, text=True)
print("cand.yarc:", "ok" if r.returncode == 0 else (r.stderr or r.stdout)[:500])
