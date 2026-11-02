#!/usr/bin/env python3
"""Build seed corpora for the docscan fuzzers from the test samples.

  corpus/module/   whole files                      -> docscan_fuzzer
  corpus/parsers/  <selector byte> + payload        -> docscan_parsers_fuzzer
                   (selectors as in docscan_parsers_fuzzer.cc)

Usage: make_corpus.py <out dir> <source dir> [<source dir> ...]
Type is detected by magic bytes (test-data folders often use odd extensions).
Files larger than MAX_SEED are skipped: libFuzzer truncates inputs to -max_len.
"""
import hashlib, os, sys, zipfile
from pathlib import Path

MAX_SEED = 256 * 1024
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


def main(dst, srcs):
    mod, par = Path(dst) / "module", Path(dst) / "parsers"
    files = (f for src in srcs for f in sorted(Path(src).rglob("*"))
             if f.is_file() and ".git" not in f.parts)
    for f in files:
        try:
            if f.stat().st_size > MAX_SEED:
                continue
            data = f.read_bytes()
        except OSError:
            continue
        if data[:4] not in (b"PK\x03\x04", b"\xd0\xcf\x11\xe0", b"{\\rt", b"%PDF", b"L\x00\x00\x00"):
            continue
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
            except Exception:  # broken zips are welcome as raw seeds
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
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2:])
