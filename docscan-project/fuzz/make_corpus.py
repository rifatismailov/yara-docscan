#!/usr/bin/env python3
"""Build seed corpora for the docscan fuzzers from the test samples.

  corpus/module/   whole files                      -> docscan_fuzzer
  corpus/parsers/  <selector byte> + payload        -> docscan_parsers_fuzzer
                   (selectors as in docscan_parsers_fuzzer.cc)

Usage: make_corpus.py <test-samples dir> <out dir>
"""
import hashlib, os, sys, zipfile
from pathlib import Path

SEL = dict(ole=0, lnk=1, rtf=2, pdf=3, ooxml=4, msovba=5, rels=6, disarm=7)


def put(dirpath, data):
    dirpath.mkdir(parents=True, exist_ok=True)
    (dirpath / hashlib.sha1(data).hexdigest()).write_bytes(data)


def msovba_containers(cfb):
    """Rough MS-OVBA container starts: 0x01 + chunk header with signature 3."""
    out = []
    for i in range(len(cfb) - 3):
        if cfb[i] == 1 and ((cfb[i + 1] | cfb[i + 2] << 8) & 0x7000) >> 12 == 3:
            out.append(cfb[i:i + 4096])
    return out[:20]


def main(src, dst):
    mod, par = Path(dst) / "module", Path(dst) / "parsers"
    for f in sorted(Path(src).rglob("*")):
        if not f.is_file():
            continue
        data = f.read_bytes()
        put(mod, data)
        head = data[:4]
        if head[:2] == b"PK":
            put(par, bytes([SEL["ooxml"]]) + data)
            put(par, bytes([SEL["disarm"]]) + data)
            try:
                z = zipfile.ZipFile(f)
                for name in z.namelist():
                    part = z.read(name)
                    if name.endswith(".rels"):
                        put(par, bytes([SEL["rels"]]) + part)
                    elif name.endswith("vbaProject.bin"):
                        put(par, bytes([SEL["ole"]]) + part)
                        put(mod, part)
                        for c in msovba_containers(part):
                            put(par, bytes([SEL["msovba"]]) + c)
                    elif "embeddings/oleObject" in name:
                        put(par, bytes([SEL["ole"]]) + part)
            except zipfile.BadZipFile:
                pass
        elif head == b"\xd0\xcf\x11\xe0":
            put(par, bytes([SEL["ole"]]) + data)
        elif head == b"{\\rt":
            put(par, bytes([SEL["rtf"]]) + data)
            put(par, bytes([SEL["disarm"]]) + data)
        elif head == b"%PDF":
            put(par, bytes([SEL["pdf"]]) + data)
        elif head == b"L\x00\x00\x00":
            put(par, bytes([SEL["lnk"]]) + data)
    for d in (mod, par):
        print(f"{d}: {len(list(d.iterdir()))} seeds")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
