#!/usr/bin/env python3
"""Mixed test set ("compote"): E5Search corpus documents + inert attack vectors.

Takes the converted corpus (docx / xlsx / pptx / rtf made by md2office.py and
LibreOffice) and injects the BENIGN vectors of test-range/gen_test_range.py:
first-pass vectors (macro, DDE, remote template, ms-msdt, ActiveX, Equation
Editor, embedded PE, altChunk, RTF objupdate, Excel DDE, XLM sheet) and
second-pass vectors (VBA code / OLE Package payload with the strings of the
vendor rule gen_macro_ShellExecute_action). Nothing has a working payload.
Some documents get all docx vectors at once.

Writes <out>/<stem>__<vector>.<ext> and <out>/expected.json:
  {file: {"base": stem, "vectors": [...], "verdict": "HIGH"|"MEDIUM", "part_rule": bool}}

usage: mix_corpus.py <corpus_docs_dir> <out_dir>
"""
import json
import os
import re
import sys
import zipfile

SRC, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)
here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(here, "..", "test-range"))
_argv = sys.argv
sys.argv = [_argv[0], os.path.join(OUT, ".range-unused")]
import gen_test_range as G  # noqa: E402  (its OUT is not used here)
sys.argv = _argv

URL = G.TEST_URL
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

MACRO_SUSP = ('Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\n    Dim s As String\r\n'
              '    s = "powershell"\r\n    s = "DownloadFile"\r\n    s = "CreateObject"\r\n'
              "    ' inert test - no execution\r\nEnd Sub\r\n")
MACRO_VENDOR = ('Attribute VB_Name = "Module1"\r\nSub AutoOpen()\r\n    Dim t As String\r\n'
                '    t = "ShellExecute"\r\n    t = "GetObject"\r\n    t = "00A0C91F3880"\r\n'
                "    t = \"C08AFD90\"\r\n    ' inert test - no execution\r\nEnd Sub\r\n")
# the vendor rule wants data that starts like a VBA module ("Attribute ...")
VBS_VENDOR = MACRO_VENDOR.encode("latin-1")


def add_rel(parts, rels_path, typ, target, mode=None):
    xml = parts.get(rels_path)
    if xml is None:
        xml = b'<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"></Relationships>'
    m = ' TargetMode="%s"' % mode if mode else ""
    n = len(re.findall(rb"<Relationship ", xml)) + 1
    rel = ('<Relationship Id="rIdMix%d" Type="%s/%s" Target="%s"%s/>' % (n, REL, typ, target, m)).encode()
    parts[rels_path] = xml.replace(b"</Relationships>", rel + b"</Relationships>")


def body_insert(parts, xml):
    d = parts["word/document.xml"]
    i = d.find(b"<w:body>")
    parts["word/document.xml"] = d[:i + 8] + xml.encode() + d[i + 8:]


# --- docx vectors: (name, verdict, part_rule, function(parts), new extension or None)
def v_macro(p):
    p["word/vbaProject.bin"] = G.vba_project(MACRO_SUSP)


def v_macro_vendor(p):
    p["word/vbaProject.bin"] = G.vba_project(MACRO_VENDOR)


def v_dde(p):
    body_insert(p, '<w:p><w:fldSimple w:instr=" DDEAUTO c:\\\\Windows\\\\System32\\\\notepad.exe TEST "/></w:p>')


def v_dde_split(p):
    body_insert(p, '<w:p><w:r><w:fldChar w:fldCharType="begin"/></w:r>'
                   '<w:r><w:instrText xml:space="preserve"> DDE</w:instrText></w:r>'
                   '<w:r><w:instrText xml:space="preserve">AUTO c:\\Windows\\System32\\cmd.exe "/c notepad.exe" </w:instrText></w:r>'
                   '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>TEST</w:t></w:r>'
                   '<w:r><w:fldChar w:fldCharType="end"/></w:r></w:p>')


def v_template(p):
    add_rel(p, "word/_rels/settings.xml.rels", "attachedTemplate", URL + "/t.dotx", "External")


def v_msdt(p):
    add_rel(p, "word/_rels/document.xml.rels", "oleObject", "ms-msdt:/id PCWDiagnostic /skip force /param TEST", "External")


def v_ext_ole(p):
    add_rel(p, "word/_rels/document.xml.rels", "oleObject", URL + "/o.bin", "External")


def v_pe(p):
    import struct
    mz = bytearray(0x100)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, 0x80)
    mz[0x80:0x84] = b"PE\x00\x00"
    p["word/embeddings/oleObject1.bin"] = bytes(mz)


def v_package(p):
    pkg = G.ole10native("invoice.vbs", r"C:\Temp\invoice.vbs", VBS_VENDOR)
    p["word/embeddings/oleObject2.bin"] = G.build_cfb(pkg, "\x01Ole10Native")


def v_activex(p):
    p["word/activeX/activeX1.xml"] = (
        b'<?xml version="1.0"?><ax:ocx ax:classid="{8856F961-340A-11D0-A96B-00C04FD705A2}" '
        b'ax:persistence="persistPropertyBag" xmlns:ax="http://schemas.microsoft.com/office/2006/activeX"/>')


def v_altchunk(p):
    add_rel(p, "word/_rels/document.xml.rels", "aFChunk", "afchunk.rtf")
    p["word/afchunk.rtf"] = b"{\\rtf1 DocScan altChunk test}"


def v_equation(p):
    p["word/embeddings/oleObject3.bin"] = G.build_cfb(b"\x1c\x00" + bytes(30), "Equation Native")


DOCX_VECTORS = [
    ("macro", "HIGH", False, v_macro, "docm"),
    ("macro_vendor", "MEDIUM", True, v_macro_vendor, "docm"),
    ("ddeauto", "HIGH", False, v_dde, None),
    ("dde_split", "HIGH", False, v_dde_split, None),
    ("remote_template", "HIGH", False, v_template, None),
    ("msdt", "HIGH", False, v_msdt, None),
    ("external_ole", "MEDIUM", False, v_ext_ole, None),
    ("embedded_pe", "HIGH", False, v_pe, None),
    ("package_vbs", "HIGH", True, v_package, None),
    ("activex", "HIGH", False, v_activex, None),
    ("altchunk", "MEDIUM", False, v_altchunk, None),
    ("equation", "HIGH", False, v_equation, None),
]

RTF_VECTORS = [
    ("rtf_objupdate", "HIGH", False, r"{\object\objupdate\objemb {\*\objdata 0105}}"),
    ("rtf_equation", "HIGH", False,
     "{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata " + G.ole1_object("Equation.3", bytes(32)) + "}}"),
    ("rtf_package", "HIGH", True,
     "{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata "
     + G.ole1_object("Package", G.ole10native("invoice.vbs", r"C:\Temp\invoice.vbs", VBS_VENDOR)[4:]) + "}}"),
]


def read_zip(path):
    with zipfile.ZipFile(path) as z:
        return {n: z.read(n) for n in z.namelist()}


def write_zip(path, parts):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for n, d in parts.items():
            z.writestr(n, d)


expected = {}


def put(name, base, vectors, verdict, part_rule):
    expected[name] = {"base": base, "vectors": vectors, "verdict": verdict, "part_rule": part_rule}


files = sorted(os.listdir(SRC))
docx = [f for f in files if f.endswith(".docx")]
for i, fn in enumerate(docx):
    stem = fn[:-5]
    vname, verdict, part, fun, ext = DOCX_VECTORS[i % len(DOCX_VECTORS)]
    parts = read_zip(os.path.join(SRC, fn))
    fun(parts)
    out = "%s__%s.%s" % (stem, vname, ext or "docx")
    write_zip(os.path.join(OUT, out), parts)
    put(out, stem, [vname], verdict, part)
    if i % 12 == 5:  # the full compote: every docx vector in one document
        parts = read_zip(os.path.join(SRC, fn))
        for v in DOCX_VECTORS:
            v[3](parts)
        out = "%s__all.docm" % stem
        write_zip(os.path.join(OUT, out), parts)
        put(out, stem, [v[0] for v in DOCX_VECTORS], "HIGH", True)

for i, fn in enumerate(f for f in files if f.endswith(".rtf")):
    stem = fn[:-4]
    vname, verdict, part, obj = RTF_VECTORS[i % len(RTF_VECTORS)]
    data = open(os.path.join(SRC, fn), "rb").read().rstrip()
    assert data.endswith(b"}")
    data = data[:-1] + obj.encode("ascii") + b"}"
    out = "%s__%s.rtf" % (stem, vname)
    open(os.path.join(OUT, out), "wb").write(data)
    put(out, stem, [vname], verdict, part)

for i, fn in enumerate(f for f in files if f.endswith(".xlsx")):
    stem = fn[:-5]
    parts = read_zip(os.path.join(SRC, fn))
    if i % 2 == 0:
        s = parts["xl/worksheets/sheet1.xml"]
        cell = b'<row r="9999"><c r="A9999"><f>cmd|\' /C notepad.exe\'!A0</f><v>0</v></c></row>'
        parts["xl/worksheets/sheet1.xml"] = s.replace(b"</sheetData>", cell + b"</sheetData>")
        out, v, verdict = "%s__excel_dde.xlsx" % stem, "excel_dde", "HIGH"
    else:
        parts["xl/macrosheets/sheet1.xml"] = (
            b'<?xml version="1.0"?><xm:macrosheet xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main"/>')
        out, v, verdict = "%s__xlm_sheet.xlsm" % stem, "xlm_sheet", "MEDIUM"
    write_zip(os.path.join(OUT, out), parts)
    put(out, stem, [v], verdict, False)

for i, fn in enumerate(f for f in files if f.endswith(".pptx")):
    if i % 2:
        continue
    stem = fn[:-5]
    parts = read_zip(os.path.join(SRC, fn))
    parts["ppt/vbaProject.bin"] = G.vba_project(MACRO_SUSP)
    out = "%s__macro.pptm" % stem
    write_zip(os.path.join(OUT, out), parts)
    put(out, stem, ["macro"], "HIGH", False)

json.dump(expected, open(os.path.join(OUT, "expected.json"), "w"), ensure_ascii=False, indent=1)
print("%d mixed documents" % len(expected))
