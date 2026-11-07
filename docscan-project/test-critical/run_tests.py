#!/usr/bin/env python3
"""Tests for the critical-information mode (yara --critical-rules).

Builds test documents in a temp folder, runs the yara CLI on each and checks:
  1. fragments == the reference algorithm (yara_sender_ref.py of E5Search,
     copied below verbatim) on the same text: start, end, text;
  2. JSON invariants of the sender spec (schema 2.0);
  3. the phrase is found in the normalised text (case, line breaks), a
     document without the phrase is not queued;
  4. text formats: txt, csv, docx, xlsx, pptx, odt, rtf (+ doc/xls/ppt files
     given with --legacy DIR); unsupported formats are skipped;
  5. chunk parameters: rule meta > --critical-chunk > 700/120, invalid values
     are rejected;
  6. without --critical-rules the CLI output is unchanged.

Usage:  python3 run_tests.py [--yara PATH] [--legacy DIR]
"""

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile


# ---- reference algorithm (E5Search yara_sender_ref.py), do not change ----
def split_chars(text, size=700, overlap=120):
    fragments = []
    start = 0
    n = len(text)                      # n = number of Unicode code points
    while start < n:
        end = min(n, start + size)
        if end < n:
            half = start + size // 2
            cut = max(text.rfind("\n", half, end), text.rfind(" ", half, end))
            if cut > start:
                end = cut
        if text[start:end].strip():
            fragments.append({"index": len(fragments), "start": start, "end": end, "text": text[start:end]})
        if end >= n:
            break
        start = max(start + 1, end - overlap)
    return fragments
# ---------------------------------------------------------------------------

RULES = r'''
rule crit_test_marking
{
    meta:
        description = "test: grif"
    strings:
        $m1 = /службов[^ ]{0,12} користуванн[^ ]{0,8}/
    condition:
        any of them
}

rule crit_test_all
{
    meta:
        description = "test: every document with the marker word"
    strings:
        $a = "zzmarker"
    condition:
        $a
}
'''

RULES_META = r'''
rule crit_meta_chunk
{
    meta:
        e5_chunk_size = 400
        e5_chunk_overlap = 50
    strings:
        $a = "zzmarker"
    condition:
        $a
}
'''

RULES_BAD_META = r'''
rule crit_bad_chunk
{
    meta:
        e5_chunk_size = 100
    strings:
        $a = "zzmarker"
    condition:
        $a
}
'''

MAIN_RULES = 'rule dummy_never { condition: false }\n'

FAILS = []


def check(cond, what):
    if cond:
        print("  ok   " + what)
    else:
        print("  FAIL " + what)
        FAILS.append(what)


# ------------------------------------------------------------- documents --

def w_docx(path, paragraphs):
    body = "".join(
        "<w:p>" + "".join('<w:r><w:t xml:space="preserve">%s</w:t></w:r>' % esc(run) for run in p) + "</w:p>"
        for p in paragraphs)
    doc = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
           '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:body>%s<w:p><w:pPr><w:tabs><w:tab w:val="left" w:pos="720"/></w:tabs></w:pPr></w:p></w:body></w:document>' % body)
    core = ('<?xml version="1.0" encoding="UTF-8"?><cp:coreProperties '
            'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/">'
            '<dc:title>Наказ</dc:title><dc:creator>Іваненко І. І.</dc:creator>'
            '<cp:lastModifiedBy>Петренко П. П.</cp:lastModifiedBy>'
            '<dcterms:created>2026-10-12T08:30:00Z</dcterms:created>'
            '<dcterms:modified>2026-10-13T14:05:00Z</dcterms:modified></cp:coreProperties>')
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("word/document.xml", doc)
        z.writestr("docProps/core.xml", core)


def w_xlsx(path, strings):
    sst = ('<?xml version="1.0" encoding="UTF-8"?><sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
           + "".join("<si><t>%s</t><rPh><t>skip-phonetic</t></rPh></si>" % esc(s) for s in strings) + "</sst>")
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("xl/workbook.xml", "<workbook/>")
        z.writestr("xl/sharedStrings.xml", sst)
        z.writestr("xl/worksheets/sheet1.xml",
                   '<worksheet><sheetData><row><c t="inlineStr"><is><t>inline cell text</t></is></c>'
                   '<c><v>12345</v></c></row></sheetData></worksheet>')


def w_pptx(path, slides):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", "<Types/>")
        z.writestr("ppt/presentation.xml", "<p:presentation/>")
        for i, s in enumerate(slides, 1):
            z.writestr("ppt/slides/slide%d.xml" % i,
                       '<p:sld xmlns:a="a" xmlns:p="p"><p:txBody><a:p><a:r><a:t>%s</a:t></a:r></a:p></p:txBody></p:sld>' % esc(s))


def w_odt(path, paragraphs):
    content = ('<?xml version="1.0" encoding="UTF-8"?><office:document-content xmlns:office="o" xmlns:text="t">'
               '<office:body><office:text>' +
               "".join("<text:p>%s</text:p>" % p for p in paragraphs) +
               '</office:text></office:body></office:document-content>')
    meta = ('<?xml version="1.0"?><office:document-meta xmlns:office="o" xmlns:meta="m" xmlns:dc="d">'
            '<office:meta><meta:initial-creator>Автор ODT</meta:initial-creator>'
            '<meta:creation-date>2026-09-01T10:00:00.123</meta:creation-date></office:meta></office:document-meta>')
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("mimetype", "application/vnd.oasis.opendocument.text")
        z.writestr("content.xml", content)
        z.writestr("meta.xml", meta)


def rtf_u(s):
    out = []
    for ch in s:
        o = ord(ch)
        if ch == "\n":
            out.append("\\par\n")
        elif o < 128:
            out.append("\\" + ch if ch in "\\{}" else ch)
        else:
            out.append("\\u%d?" % (o if o < 32768 else o - 65536))
    return "".join(out)


def w_rtf(path, text):
    data = ("{\\rtf1\\ansi\\ansicpg1251\\deff0{\\fonttbl{\\f0\\fcharset204 Times New Roman;}}"
            "{\\info{\\author " + rtf_u("Автор RTF") + "}{\\title " + rtf_u("Заголовок") + "}}"
            "{\\*\\generator Test;}\\f0 " + rtf_u(text) + "\\par "
            "\\'c4\\'f1\\'ea \\'ef\\'f0\\'ee\\'e1\\'e0}")
    with open(path, "w", encoding="ascii") as f:
        f.write(data)


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ------------------------------------------------------------------ run --

def run_yara(yara, rules_text, doc, tmp, extra=()):
    rules = os.path.join(tmp, "crit.yar")
    main = os.path.join(tmp, "main.yar")
    queue = os.path.join(tmp, "critical.json")
    with open(rules, "w", encoding="utf-8") as f:
        f.write(rules_text)
    with open(main, "w") as f:
        f.write(MAIN_RULES)
    if os.path.exists(queue):
        os.remove(queue)
    p = subprocess.run([yara, "--critical-rules=" + rules, "--critical-out=" + queue, *extra, main, doc],
                       capture_output=True, text=True, encoding="utf-8", errors="replace")
    objs = []
    if os.path.exists(queue):
        with open(queue, encoding="utf-8") as f:
            lines = f.read().split("\n")
        check(lines[-1] == "", "queue file ends with a newline")
        objs = [json.loads(l) for l in lines if l]
    return p, objs


def reconstruct(frags):
    text = frags[0]["text"]
    for prev, f in zip(frags, frags[1:]):
        ov = prev["end"] - f["start"]
        if ov > 0:
            if text[f["start"]:prev["end"]] != f["text"][:ov]:
                return None
            text = text[:f["start"]] + f["text"]
        else:
            return None if f["start"] != prev["end"] else text + f["text"]
    return text


def validate(obj, doc, name, expect_text=None, size=700, overlap=120):
    d = obj["document"]
    raw = open(doc, "rb").read()
    check(obj.get("schema_version") == "2.0", name + ": schema_version 2.0")
    check(d.get("format") == os.path.splitext(doc)[1][1:].lower(), name + ": format = extension")
    check(d.get("sha256") == hashlib.sha256(raw).hexdigest(), name + ": sha256 of the original file")
    check(d.get("size_bytes") == len(raw), name + ": size_bytes")
    check(d.get("name") == os.path.basename(doc), name + ": name")
    m = obj["metadata"]
    check(m.get("source") == "yara" and m.get("received_at", "").endswith("Z"), name + ": source / received_at")
    check(isinstance(m.get("yara_matches"), list) and m["yara_matches"], name + ": yara_matches (rule names)")
    fr = obj["fragments"]
    ti = obj["text_info"]
    check(fr and fr[0]["start"] == 0, name + ": first start = 0")
    check(fr[-1]["end"] == ti["total_chars"], name + ": last end = total_chars")
    check(ti["fragment_count"] == len(fr), name + ": fragment_count")
    check(ti["chunking"] == {"unit": "chars", "size": size, "overlap": overlap}, name + ": chunking %d/%d" % (size, overlap))
    okidx = all(f["index"] == i for i, f in enumerate(fr))
    oklen = all(f["end"] - f["start"] == len(f["text"]) and f["text"].strip() for f in fr)
    nogap = all(fr[i]["start"] <= fr[i - 1]["end"] for i in range(1, len(fr)))
    check(okidx, name + ": indexes 0,1,2...")
    check(oklen, name + ": end-start = code points, no empty fragment")
    check(nogap, name + ": no gaps")
    text = reconstruct(fr)
    check(text is not None, name + ": fragments are consistent slices of one text")
    if text is not None:
        if expect_text is not None:
            check(text == expect_text, name + ": text as expected")
        ref = split_chars(text, size, overlap)
        check([(f["start"], f["end"], f["text"]) for f in ref] ==
              [(f["start"], f["end"], f["text"]) for f in fr], name + ": fragments == reference algorithm")
    return text


def main():
    ap = argparse.ArgumentParser()
    here = os.path.dirname(os.path.abspath(__file__))
    ap.add_argument("--yara", default=os.path.join(here, "..", "..", "yara"))
    ap.add_argument("--legacy", help="folder with .doc/.xls/.ppt files that contain the word zzmarker")
    a = ap.parse_args()
    yara = os.path.abspath(a.yara)

    with tempfile.TemporaryDirectory() as tmp:
        # --- 1. chunking on plain text: the 6 texts of the prompt
        cases = {
            "short": "zzmarker короткий текст.",
            "exact700": ("zzmarker " + "а" * 691),
            "nospaces2000": "zzmarker" + "б" * 1992,
            "cyrillic": "zzmarker " + " ".join(["Відомості про організацію, засоби і методи розвідувальної діяльності"] * 40),
            "emoji": "zzmarker " + ("слово 😀 " * 150) + "😀" * 300,
            "newlines": "zzmarker\n" + "\n".join("рядок номер %d з текстом" % i for i in range(120)),
        }
        print("== chunking (txt)")
        for name, text in cases.items():
            doc = os.path.join(tmp, name + ".txt")
            with open(doc, "w", encoding="utf-8", newline="") as f:
                f.write(text)
            p, objs = run_yara(yara, RULES, doc, tmp)
            check(len(objs) == 1, name + ": one document queued")
            if objs:
                validate(objs[0], doc, name, expect_text=text.strip())
            check(text[20:60] not in p.stdout + p.stderr, name + ": document text is not printed")

        # --- 3. search: phrase split by a line break, capitalised; and no phrase
        print("== search")
        doc = os.path.join(tmp, "grif.docx")
        w_docx(doc, [["ДЛЯ СЛУЖБОВОГО"], ["КОРИСТУВАННЯ"], ["Прим. № 2"], ["Текст наказу."]])
        p, objs = run_yara(yara, RULES, doc, tmp)
        check(len(objs) == 1 and objs[0]["metadata"]["yara_matches"] == ["crit_test_marking"],
              "phrase across a paragraph break, upper case -> queued by crit_test_marking")
        if objs:
            t = validate(objs[0], doc, "grif.docx")
            check(t == "ДЛЯ СЛУЖБОВОГО\nКОРИСТУВАННЯ\nПрим. № 2\nТекст наказу.", "docx text, paragraphs by \\n, tab stops ignored")
            md = objs[0]["metadata"]
            check(md.get("author") == "Іваненко І. І." and md.get("last_modified_by") == "Петренко П. П." and
                  md.get("title") == "Наказ" and md.get("created_at") == "2026-10-12T08:30:00Z" and
                  md.get("modified_at") == "2026-10-13T14:05:00Z", "docx metadata from docProps/core.xml")
            check("docscan-critical: queued fragments=1 rules=crit_test_marking" in p.stdout, "stdout line 'queued'")
        doc = os.path.join(tmp, "plain.docx")
        w_docx(doc, [["Звичайний лист без грифа."]])
        p, objs = run_yara(yara, RULES, doc, tmp)
        check(objs == [] and "queued" not in p.stdout, "document without the phrase is not queued")

        # --- 4. formats
        print("== formats")
        doc = os.path.join(tmp, "t.xlsx")
        w_xlsx(doc, ["zzmarker перший рядок", "Для службового користування"])
        p, objs = run_yara(yara, RULES, doc, tmp)
        check(len(objs) == 1, "xlsx queued")
        if objs:
            t = validate(objs[0], doc, "xlsx")
            check("inline cell text" in t and "skip-phonetic" not in t and "12345" not in t,
                  "xlsx: shared + inline strings, no phonetic runs, no numbers")
        doc = os.path.join(tmp, "t.pptx")
        w_pptx(doc, ["zzmarker слайд один", "слайд два"])
        p, objs = run_yara(yara, RULES, doc, tmp)
        check(len(objs) == 1 and objs and validate(objs[0], doc, "pptx") == "zzmarker слайд один\nслайд два", "pptx text in slide order")
        doc = os.path.join(tmp, "t.odt")
        w_odt(doc, ["zzmarker абзац<text:s text:c=\"3\"/>один", "абзац <text:span>два</text:span>"])
        p, objs = run_yara(yara, RULES, doc, tmp)
        if objs:
            t = validate(objs[0], doc, "odt")
            check(t == "zzmarker абзац   один\nабзац два", "odt text (text:s, spans)")
            check(objs[0]["metadata"].get("author") == "Автор ODT" and
                  objs[0]["metadata"].get("created_at") == "2026-09-01T10:00:00Z", "odt metadata from meta.xml")
        else:
            check(False, "odt queued")
        doc = os.path.join(tmp, "t.rtf")
        w_rtf(doc, "zzmarker Відомості ДЛЯ службового\nкористування")
        p, objs = run_yara(yara, RULES, doc, tmp)
        check(len(objs) == 1, "rtf queued")
        if objs:
            t = validate(objs[0], doc, "rtf")
            check(t == "zzmarker Відомості ДЛЯ службового\nкористування\nДск проба", "rtf text (\\u, \\'hh in 1251)")
            check(objs[0]["metadata"].get("author") == "Автор RTF" and objs[0]["metadata"].get("title") == "Заголовок",
                  "rtf metadata from \\info")
            check(sorted(objs[0]["metadata"]["yara_matches"]) == ["crit_test_all", "crit_test_marking"], "both rules listed")
        doc = os.path.join(tmp, "t.csv")
        with open(doc, "wb") as f:
            f.write("zzmarker;Для службового користування\r\nрядок;два\r\n".encode("cp1251"))
        p, objs = run_yara(yara, RULES, doc, tmp)
        check(len(objs) == 1 and objs and validate(objs[0], doc, "csv-1251") == "zzmarker;Для службового користування\nрядок;два",
              "csv in Windows-1251, \\r\\n -> \\n")
        doc = os.path.join(tmp, "t16.txt")
        with open(doc, "wb") as f:
            f.write(b"\xff\xfe" + "zzmarker UTF-16 текст".encode("utf-16-le"))
        p, objs = run_yara(yara, RULES, doc, tmp)
        check(len(objs) == 1 and objs and validate(objs[0], doc, "txt-utf16") == "zzmarker UTF-16 текст", "txt UTF-16LE with BOM")
        doc = os.path.join(tmp, "t.pdf")
        with open(doc, "wb") as f:
            f.write(b"%PDF-1.4\nzzmarker\n%%EOF\n")
        p, objs = run_yara(yara, RULES, doc, tmp)
        check(objs == [] and "skipped (format without text support)" in p.stderr, "pdf: skipped, message on stderr")
        doc = os.path.join(tmp, "empty.txt")
        with open(doc, "w") as f:
            f.write("   \n\t ")
        p, objs = run_yara(yara, RULES, doc, tmp)
        check(objs == [] and "skipped (no text in the document)" in p.stderr, "empty text: skipped, message on stderr")
        doc = os.path.join(tmp, "x.bin")
        with open(doc, "wb") as f:
            f.write(b"zzmarker binary")
        p, objs = run_yara(yara, RULES, doc, tmp)
        check(objs == [], "unknown extension: not queued")

        if a.legacy:
            print("== legacy Office (%s)" % a.legacy)
            for fn in sorted(os.listdir(a.legacy)):
                doc = os.path.join(a.legacy, fn)
                p, objs = run_yara(yara, RULES, doc, tmp)
                check(len(objs) == 1, fn + ": queued")
                if objs:
                    t = validate(objs[0], doc, fn)
                    print("       text: %r" % (t[:80] if t else t))
                    print("       meta: %s" % {k: v for k, v in objs[0]["metadata"].items() if k not in ("yara_matches",)})

        # --- 5. chunk parameters
        print("== chunk parameters")
        long_doc = os.path.join(tmp, "long.txt")
        with open(long_doc, "w", encoding="utf-8") as f:
            f.write(cases["cyrillic"])
        p, objs = run_yara(yara, RULES_META, long_doc, tmp, ["--critical-chunk=500,100"])
        check(len(objs) == 1 and objs and objs[0]["text_info"]["chunking"]["size"] == 400, "rule meta wins over --critical-chunk")
        if objs:
            validate(objs[0], long_doc, "meta 400/50", size=400, overlap=50)
        p, objs = run_yara(yara, RULES, long_doc, tmp, ["--critical-chunk=500,100"])
        check(len(objs) == 1 and objs and objs[0]["text_info"]["chunking"]["size"] == 500, "--critical-chunk over the default")
        if objs:
            validate(objs[0], long_doc, "cli 500/100", size=500, overlap=100)
        p, objs = run_yara(yara, RULES, long_doc, tmp, ["--critical-chunk=100,10"])
        check(p.returncode != 0 and "critical-chunk" in p.stderr and objs == [], "--critical-chunk=100,10 rejected")
        p, objs = run_yara(yara, RULES, long_doc, tmp, ["--critical-chunk=700,400"])
        check(p.returncode != 0 and objs == [], "--critical-chunk=700,400 rejected (overlap > size/2)")
        p, objs = run_yara(yara, RULES_BAD_META, long_doc, tmp)
        check(objs == [] and "invalid chunk size/overlap" in p.stderr, "rule meta e5_chunk_size=100 rejected, not queued")

        # --- 6. without --critical-rules nothing changes
        print("== without --critical-rules")
        main_rules = os.path.join(tmp, "m2.yar")
        with open(main_rules, "w") as f:
            f.write('rule has_marker { strings: $a = "zzmarker" condition: $a }\n')
        p = subprocess.run([yara, main_rules, long_doc], capture_output=True, text=True)
        check(p.stdout.strip() == "has_marker " + long_doc and p.stderr == "", "plain yara output unchanged")
        check(not os.path.exists(os.path.join(tmp, "critical.json.unused")), "no queue file without the option")

    print("\n%s: %d failure(s)" % ("FAILED" if FAILS else "PASSED", len(FAILS)))
    for f in FAILS:
        print("  - " + f)
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
