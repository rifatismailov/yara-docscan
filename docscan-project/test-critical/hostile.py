#!/usr/bin/env python3
"""Hostile / broken inputs for the critical-mode text extraction.

Each file must be handled without a crash or a hang; the expectation column
says what the CLI should do with it. Built from the converted corpus (legacy
seeds) plus synthetic structures. Writes <out>/hostile.json.

usage: hostile.py <seeds_dir> <out_dir>
"""
import json, os, random, struct, sys, zipfile

SRC, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)
random.seed(7)
PHRASE = "Для службового користування"
exp = {}


def put(name, data, expect, note):
    open(os.path.join(OUT, name), "wb").write(data)
    exp[name] = {"expect": expect, "note": note}


def zbytes(parts, comp=zipfile.ZIP_DEFLATED):
    import io
    b = io.BytesIO()
    with zipfile.ZipFile(b, "w", comp) as z:
        for n, d in parts.items():
            z.writestr(n, d)
    return b.getvalue()


W = '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body>%s</w:body></w:document>'

# --- zip / OOXML
put("zipbomb.docx", zbytes({"word/document.xml": b"<w:t>" + b" " * (200 * 1024 * 1024)}),
    "skip", "document.xml 200 MB unpacked (> 64 MB entry cap)")
big = (W % ("<w:p><w:r><w:t>%s слово слово слово слово слово слово</w:t></w:r></w:p>" % PHRASE * 280000)).encode()
put("text_over_cap.docx", zbytes({"word/document.xml": big}), "queue", "%d MB of XML text: cut at the 16 MB text cap" % (len(big) >> 20))
put("deep_xml.docx", zbytes({"word/document.xml": (W % ("<w:p>" * 300000 + "<w:r><w:t>%s</w:t></w:r>" % PHRASE + "</w:p>" * 300000)).encode()}),
    "queue", "300 000 nested paragraphs")
put("unclosed_xml.docx", zbytes({"word/document.xml": ('<w:document><w:body><w:p><w:r><w:t>%s <w:t "x' % PHRASE).encode()}),
    "any", "XML cut in the middle of a tag")
put("garbage_xml.docx", zbytes({"word/document.xml": bytes(random.randrange(256) for _ in range(200000))}), "any", "document.xml is random bytes")
many = {"word/document.xml": (W % "<w:p><w:r><w:t>%s</w:t></w:r></w:p>" % PHRASE).encode()}
for i in range(20000):
    many["word/header%d.xml" % i] = b"<w:hdr><w:p><w:r><w:t>h</w:t></w:r></w:p></w:hdr>"
put("many_parts.docx", zbytes(many), "queue", "20 000 header parts (list cap 2048)")
put("entities.docx", zbytes({"word/document.xml": (W % ("<w:p><w:r><w:t>%s &#0; &#xD800; &#1114112; &amp;&lt;&bogus; &#x;</w:t></w:r></w:p>" % PHRASE)).encode()}),
    "queue", "NUL / surrogate / out-of-range / unknown entities")
bad = (W % ("<w:p><w:r><w:t>%s X</w:t></w:r></w:p>" % PHRASE)).encode().replace(b" X<", b" \xff\xfe\xc0\xaf\xed\xa0\x80<")
put("bad_utf8.docx", zbytes({"word/document.xml": bad}), "queue", "invalid UTF-8 inside text -> U+FFFD")
put("odt_odd_mimetype.odt", zbytes({"mimetype": b"application/vnd.oasis.opendocument.graphics", "content.xml": b"<office:document-content/>"}),
    "skip", "ODF drawing (not supported)")
put("zip_not_office.docx", zbytes({"readme.txt": PHRASE.encode()}), "skip", "a plain zip renamed to .docx")
seed_docx = open(os.path.join(SRC, "tp_07.docx"), "rb").read()
put("truncated.docx", seed_docx[: len(seed_docx) // 2], "any", "half of a real docx")

# --- RTF
put("deep_rtf.rtf", b"{\\rtf1 " + b"{" * 1000000 + PHRASE.encode("cp1251").hex().encode() + b"}" * 10, "any", "1 000 000 nested groups")
put("rtf_bin.rtf", b"{\\rtf1 \\bin999999999999 " + b"x" * 100 + b"}", "any", "\\bin with an absurd length")
put("rtf_uc.rtf", b"{\\rtf1\\uc99999 \\u-99999? \\u1044?\\u1083?\\u1103? \\'zz \\'4 \\u55357\\u56832 }", "any", "bad \\uc / \\u / \\' values")
put("rtf_words.rtf", b"{\\rtf1 \\" + b"a" * 100000 + b"12345678901234567890 text}", "any", "a 100 000-letter control word")

# --- legacy Office, corrupted from real files
doc = bytearray(open(os.path.join(SRC, "tp_07.doc"), "rb").read())
cfb = doc[:]


def corrupt(data, find, mutate, name, note):
    d = bytearray(data)
    mutate(d)
    put(name, bytes(d), "any", note)


def stream_offsets(d):
    # locate the WordDocument stream start by its FIB magic (0xA5EC) - good enough for a test
    i = d.find(b"\xec\xa5")
    return i


w = stream_offsets(doc)
if w > 0:
    corrupt(doc, None, lambda d: struct.pack_into("<I", d, w + 0x1A2, 0x7FFFFFF0), "doc_bad_fcclx.doc", "fcClx far outside the table stream")
    corrupt(doc, None, lambda d: struct.pack_into("<I", d, w + 0x1A6, 0xFFFFFFFF), "doc_bad_lcbclx.doc", "lcbClx = 4 GB")
    corrupt(doc, None, lambda d: struct.pack_into("<H", d, w + 0x0A, struct.unpack_from("<H", d, w + 0x0A)[0] | 0x0100), "doc_encrypted_flag.doc", "fEncrypted set")
    corrupt(doc, None, lambda d: struct.pack_into("<H", d, w + 2, 0x0065), "doc_word6.doc", "nFib of Word 6")
put("doc_random_body.doc", bytes(doc[:512]) + bytes(random.randrange(256) for _ in range(len(doc) - 512)), "any", "real CFB header, random rest")
put("doc_header_only.doc", bytes(doc[:512]), "any", "only the CFB header")
xls = bytearray(open(os.path.join(SRC, "tp_05.xls"), "rb").read())
i = xls.find(b"\xfc\x00")
while i > 0 and i < len(xls) - 12:
    ln = struct.unpack_from("<H", xls, i + 2)[0]
    if 8 < ln < 8300:
        break
    i = xls.find(b"\xfc\x00", i + 1)
if i > 0:
    d = bytearray(xls); struct.pack_into("<I", d, i + 8, 0xFFFFFFFF); put("xls_sst_count.xls", bytes(d), "any", "SST unique count = 4 G")
    d = bytearray(xls); struct.pack_into("<H", d, i + 12, 0xFFFF); put("xls_sst_cch.xls", bytes(d), "any", "first SST string 65535 chars")
    d = bytearray(xls); struct.pack_into("<H", d, i + 2, 0xFFFF); put("xls_sst_len.xls", bytes(d), "any", "SST record length 65535")
j = xls.find(b"\x2f\x00")
put("xls_random_body.xls", bytes(xls[:512]) + bytes(random.randrange(256) for _ in range(len(xls) - 512)), "any", "real CFB header, random rest")
ppt = bytearray(open(os.path.join(SRC, "tp_02.ppt"), "rb").read())
k = ppt.find(b"\xa0\x0f")
if k > 2:
    d = bytearray(ppt); struct.pack_into("<I", d, k + 2, 0xFFFFFFF0); put("ppt_atom_len.ppt", bytes(d), "any", "TextCharsAtom length 4 GB")
put("ppt_random_body.ppt", bytes(ppt[:512]) + bytes(random.randrange(256) for _ in range(len(ppt) - 512)), "any", "real CFB header, random rest")
# encrypted docx = CFB with an EncryptedPackage stream
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "test-range"))
_argv = sys.argv; sys.argv = [_argv[0], os.path.join(OUT, ".unused")]
import gen_test_range as G  # noqa: E402
sys.argv = _argv
put("encrypted.docx", G.build_cfb(b"\x00" * 5000, "EncryptedPackage"), "skip:password", "password-protected docx")

# --- plain text
put("utf16_odd.txt", b"\xff\xfe" + PHRASE.encode("utf-16-le") + b"\x41", "queue", "UTF-16LE with an odd byte at the end")
put("nul_bytes.txt", (PHRASE + "\x00\x00 текст\x00").encode("utf-8"), "queue", "NUL characters")
put("mixed.csv", PHRASE.encode("utf-8") + b";\xcf\xf0\xe8\xe2\xb3\xf2", "noqueue", "UTF-8 + 1251 in one file: read as 1251 (no guessing) - the UTF-8 phrase is lost")
put("phrase_after_cap.txt", ("слово " * 3000000 + PHRASE).encode("utf-8"), "noqueue", "the phrase after the 16 MB text cap")
put("phrase_before_cap.txt", (PHRASE + " " + "слово " * 3000000).encode("utf-8"), "queue", "the phrase at the start of 17 MB of text")
put("only_spaces.txt", b" \t\r\n" * 1000, "skip:empty", "whitespace only")
put("empty.docx", b"", "any", "empty file")

json.dump(exp, open(os.path.join(OUT, "hostile.json"), "w"), ensure_ascii=False, indent=1)
print(len(exp), "hostile files")
