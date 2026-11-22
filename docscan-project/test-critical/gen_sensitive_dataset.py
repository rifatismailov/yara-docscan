#!/usr/bin/env python3
"""Synthetic test set for the critical-information search (pass 3): Ukrainian business documents with sensitive
data, hard negatives, mixed and clean documents, plus expected.tsv.

  gen_sensitive_dataset.py [OUT_DIR] [--seed N]        (default ~/docscan-test-dataset-v2, seed 2026)

Everything is invented, but in the REAL format: card numbers pass the Luhn check, IBANs the mod-97 check, RNOKPP the
control digit (and encode the birth date), keys and tokens have the real prefixes, alphabets and lengths. None of it
opens anything: card numbers use test BINs or random digits, keys are random bytes, tokens random characters.
No "TEST" markers and no category names in the documents - a rule must find the data, not a label.

Categories (expected.tsv "expected", comma separated, or "none"):
  bank, personal, credentials, keys, tokens, infra, classified, org
Layout: <category>/positive, <category>/negative, mixed/, clean/; file names <category>_<pos|neg>_NN.<ext>.
Formats: docx (body, table, header / footer), xlsx (tables of tens of rows), pptx (slides + notes), odt, rtf, txt, csv.
No PDF: pass 3 does not read PDF. Only the Python standard library.
"""
import argparse
import base64
import csv
import datetime
import io
import json
import os
import random
import shutil
import string
import zipfile
from xml.sax.saxutils import escape

R = random.Random()

# ------------------------------------------------------------------ fake data in real formats

FIRST_M = ["Петро", "Олександр", "Андрій", "Іван", "Сергій", "Микола", "Дмитро", "Василь", "Юрій", "Тарас", "Богдан", "Остап"]
FIRST_F = ["Олена", "Марія", "Наталія", "Ірина", "Оксана", "Тетяна", "Галина", "Світлана", "Юлія", "Анна", "Леся", "Христина"]
LAST = ["Іваненко", "Петренко", "Коваленко", "Бондаренко", "Ткаченко", "Шевчук", "Мельник", "Кравчук", "Олійник",
        "Савченко", "Руденко", "Мороз", "Гнатюк", "Литвиненко", "Захарченко", "Даниленко", "Остапчук", "Яковенко"]
PATR_M = ["Петрович", "Олександрович", "Андрійович", "Іванович", "Сергійович", "Миколайович", "Васильович"]
PATR_F = ["Петрівна", "Олександрівна", "Андріївна", "Іванівна", "Сергіївна", "Миколаївна", "Василівна"]
CITIES = ["м. Київ", "м. Львів", "м. Одеса", "м. Дніпро", "м. Харків", "м. Вінниця", "м. Полтава", "м. Житомир"]
STREETS = ["вул. Садова", "вул. Лісова", "просп. Миру", "вул. Шкільна", "вул. Зелена", "вул. Польова", "бульв. Незалежності"]
COMPANIES = ["ТОВ «Ромашка-Трейд»", "ТОВ «Вектор Плюс»", "ПП «Світанок»", "ТОВ «Дніпро Логістик»", "ТОВ «Еко Сервіс»"]
BANKS = ["АТ «Перший Умовний Банк»", "АТ «Банк Східний Тест»", "АТ «Кредит Простір»"]
BIP39 = ("abandon ability able about above absent absorb abstract absurd abuse access accident account accuse achieve "
         "acid acoustic acquire across act action actor actress actual adapt add addict address adjust admit adult "
         "advance advice aerobic affair afford afraid again age agent agree ahead aim air airport aisle alarm album "
         "alcohol alert alien all alley allow almost alone alpha already also alter always amateur amazing among").split()


def rs(alphabet, n):
    return "".join(R.choice(alphabet) for _ in range(n))


AZ09 = string.ascii_uppercase + string.digits
az09 = string.ascii_lowercase + string.digits
Aa09 = string.ascii_letters + string.digits
B64 = Aa09 + "+/"
B64URL = Aa09 + "-_"


def luhn_complete(prefix, length):
    digits = [int(c) for c in prefix] + [R.randint(0, 9) for _ in range(length - len(prefix) - 1)]
    total = 0
    for i, d in enumerate(reversed(digits)):
        d = d * 2 if i % 2 == 0 else d
        total += d - 9 if d > 9 else d
    return "".join(map(str, digits)) + str((10 - total % 10) % 10)


def card():
    kind = R.choice(["visa", "visa", "mc", "mc2", "amex", "prostir"])
    if kind == "visa":
        return "Visa", luhn_complete("4", 16)
    if kind == "mc":
        return "Mastercard", luhn_complete(str(R.randint(51, 55)), 16)
    if kind == "mc2":
        return "Mastercard", luhn_complete(str(R.randint(2221, 2720)), 16)
    if kind == "amex":
        return "American Express", luhn_complete(R.choice(["34", "37"]), 15)
    return "ПРОСТІР", luhn_complete("9804", 16)


def fmt_card(n):
    style = R.choice(["groups", "groups", "dash", "plain"])
    if len(n) == 15:
        g = [n[:4], n[4:10], n[10:]]
    else:
        g = [n[i:i + 4] for i in range(0, 16, 4)]
    return {"groups": " ".join(g), "dash": "-".join(g), "plain": n}[style]


def iban_ua():
    mfo = "%06d" % R.randint(300000, 399999)
    acc = "".join(str(R.randint(0, 9)) for _ in range(19))
    bban = mfo + acc
    num = int(bban + "3010" + "00")  # U=30 A=10
    check = 98 - num % 97
    return "UA%02d%s" % (check, bban), mfo


def fmt_iban(i):
    return " ".join(i[k:k + 4] for k in range(0, len(i), 4)) if R.random() < 0.5 else i


def edrpou():
    return "%08d" % R.randint(10000000, 45999999)


def birth():
    return datetime.date(1960, 1, 1) + datetime.timedelta(days=R.randint(0, 365 * 40))


def rnokpp(b, female):
    days = (b - datetime.date(1899, 12, 31)).days
    mid = R.randint(0, 99) * 10 + R.choice([0, 2, 4, 6, 8] if female else [1, 3, 5, 7, 9])
    d = "%05d%04d" % (days, mid)
    w = [-1, 5, 7, 9, 4, 6, 10, 5, 7]
    return d + str(sum(int(a) * b for a, b in zip(d, w)) % 11 % 10)


def person():
    female = R.random() < 0.5
    b = birth()
    name = "%s %s %s" % (R.choice(LAST), R.choice(FIRST_F if female else FIRST_M), R.choice(PATR_F if female else PATR_M))
    return {"name": name, "birth": b, "rnokpp": rnokpp(b, female),
            "phone": "+380 %s %03d %02d %02d" % (R.choice(["50", "63", "66", "67", "68", "73", "93", "95", "96", "97", "98", "99"]),
                                               R.randint(100, 999), R.randint(10, 99), R.randint(10, 99)),
            "address": "%s, %s, %d, кв. %d" % (R.choice(CITIES), R.choice(STREETS), R.randint(1, 120), R.randint(1, 300)),
            "passport": "%s %06d" % (rs("АВЕКМНОРСТХ", 2), R.randint(100000, 999999)),
            "idcard": "%09d" % R.randint(0, 999999999),
            "unzr": "%s-%05d" % (b.strftime("%Y%m%d"), R.randint(0, 99999))}


def password():
    return rs(Aa09, R.randint(4, 6)) + R.choice("!#$%&*@") + rs(Aa09, R.randint(4, 7))


def pem(kind="RSA PRIVATE KEY", lines=None):
    body = base64.b64encode(bytes(R.getrandbits(8) for _ in range(48 * (lines or R.randint(12, 25))))).decode()
    return "-----BEGIN %s-----\n%s\n-----END %s-----" % (kind, "\n".join(body[i:i + 64] for i in range(0, len(body), 64)), kind)


def openssh_key():
    body = "b3BlbnNzaC1rZXktdjEAAAAA" + base64.b64encode(bytes(R.getrandbits(8) for _ in range(700))).decode()
    return "-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----" % "\n".join(body[i:i + 70] for i in range(0, len(body), 70))


def putty_key():
    priv = base64.b64encode(bytes(R.getrandbits(8) for _ in range(256))).decode()
    pub = base64.b64encode(bytes(R.getrandbits(8) for _ in range(280))).decode()
    return ("PuTTY-User-Key-File-3: ssh-rsa\nEncryption: none\nComment: rsa-key-20260114\nPublic-Lines: 5\n%s\n"
            "Private-Lines: 4\n%s\nPrivate-MAC: %s" % ("\n".join(pub[i:i + 64] for i in range(0, len(pub), 64)),
                                                       "\n".join(priv[i:i + 64] for i in range(0, len(priv), 64)), rs("0123456789abcdef", 64)))


def jwt():
    h = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
    p = base64.urlsafe_b64encode(('{"sub":"%d","name":"%s","iat":%d}' % (R.randint(1000, 9999), R.choice(["svc-crm", "ivan.p", "api-gw"]),
                                                                        1760000000 + R.randint(0, 9999999))).encode()).decode().rstrip("=")
    return "%s.%s.%s" % (h, p, rs(B64URL, 43))


TOKENS = {
    "aws": lambda: "aws_access_key_id = AKIA%s\naws_secret_access_key = %s" % (rs(AZ09, 16), rs(B64, 40)),
    "google": lambda: "AIza" + rs(B64URL, 35),
    "github": lambda: "ghp_" + rs(Aa09, 36),
    "github_pat": lambda: "github_pat_" + rs(Aa09, 22) + "_" + rs(Aa09, 59),
    "gitlab": lambda: "glpat-" + rs(B64URL, 20),
    "slack": lambda: "xoxb-%d-%d-%s" % (R.randint(10 ** 10, 10 ** 11), R.randint(10 ** 12, 10 ** 13), rs(Aa09, 24)),
    "slack_hook": lambda: "https://hooks.slack.com/services/T%s/B%s/%s" % (rs(AZ09, 10), rs(AZ09, 10), rs(Aa09, 24)),
    "telegram": lambda: "%d:AA%s" % (R.randint(10 ** 8, 10 ** 10 - 1), rs(B64URL, 33)),
    "azure": lambda: "DefaultEndpointsProtocol=https;AccountName=%sstore;AccountKey=%s==;EndpointSuffix=core.windows.net" % (rs(az09, 8), rs(B64, 86)),
    "stripe": lambda: "sk_live_" + rs(Aa09, 24),
    "openai": lambda: "sk-proj-" + rs(B64URL, 48),
    "jwt": jwt,
    "bearer": lambda: "Authorization: Bearer " + rs(B64URL, 40),
}


def bcrypt():
    return "$2b$12$" + rs("./" + Aa09, 53)


# ------------------------------------------------------------------ document writers (stdlib only)

def x(s):
    return escape(s)


CT_HEAD = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/>'
REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def core_xml(title):
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
            'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
            '<dc:title>%s</dc:title><dc:creator>%s</dc:creator></cp:coreProperties>' % (x(title), x(R.choice(LAST))))


def wpara(t):
    runs = []
    for i, part in enumerate(t.split("\n")):
        if i:
            runs.append("<w:r><w:br/></w:r>")
        runs.append('<w:r><w:t xml:space="preserve">%s</w:t></w:r>' % x(part))
    return "<w:p>%s</w:p>" % "".join(runs)


def write_docx(path, doc):
    body = [wpara(p) for p in doc.get("paras", [])]
    if doc.get("table"):
        rows = "".join("<w:tr>%s</w:tr>" % "".join("<w:tc><w:p><w:r><w:t xml:space=\"preserve\">%s</w:t></w:r></w:p></w:tc>" % x(str(c)) for c in r)
                       for r in doc["table"])
        body.append("<w:tbl><w:tblPr><w:tblStyle w:val=\"TableGrid\"/></w:tblPr>%s</w:tbl>" % rows)
    body += [wpara(p) for p in doc.get("after", [])]
    rels, sect, ct = [], [], ""
    for kind, key in (("header", "header"), ("footer", "footer")):
        if doc.get(key):
            rid = "rId%d" % (len(rels) + 1)
            rels.append('<Relationship Id="%s" Type="%s/%s" Target="%s1.xml"/>' % (rid, REL, kind, kind))
            sect.append('<w:%sReference w:type="default" r:id="%s"/>' % (kind, rid))
            ct += '<Override PartName="/word/%s1.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.%s+xml"/>' % (kind, kind)
    document = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?><w:document xmlns:w="%s" xmlns:r="%s"><w:body>%s<w:sectPr>%s</w:sectPr></w:body></w:document>'
                % (W, REL, "".join(body), "".join(sect)))
    parts = {
        "[Content_Types].xml": CT_HEAD + '<Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>' + ct + "</Types>",
        "_rels/.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="%s/officeDocument" Target="word/document.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>' % REL,
        "word/_rels/document.xml.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">%s</Relationships>' % "".join(rels),
        "word/document.xml": document,
        "docProps/core.xml": core_xml(doc.get("title", "")),
    }
    for kind, tag in (("header", "hdr"), ("footer", "ftr")):
        if doc.get(kind):
            parts["word/%s1.xml" % kind] = '<?xml version="1.0"?><w:%s xmlns:w="%s">%s</w:%s>' % (tag, W, wpara(doc[kind]), tag)
    zwrite(path, parts)


def col(n):
    s = ""
    n += 1
    while n:
        n, r = divmod(n - 1, 26)
        s = chr(65 + r) + s
    return s


def write_xlsx(path, doc):
    SS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    rows = doc.get("table") or [[p] for p in doc.get("paras", [])]
    strings, idx = [], {}

    def si(v):
        v = str(v)
        if v not in idx:
            idx[v] = len(strings)
            strings.append(v)
        return idx[v]
    xml_rows = []
    for r, row in enumerate(rows):
        cells = "".join('<c r="%s%d" t="s"><v>%d</v></c>' % (col(c), r + 1, si(v)) for c, v in enumerate(row))
        xml_rows.append('<row r="%d">%s</row>' % (r + 1, cells))
    parts = {
        "[Content_Types].xml": CT_HEAD + '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/></Types>',
        "_rels/.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="%s/officeDocument" Target="xl/workbook.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>' % REL,
        "xl/workbook.xml": '<?xml version="1.0"?><workbook xmlns="%s" xmlns:r="%s"><sheets><sheet name="%s" sheetId="1" r:id="rId1"/></sheets></workbook>' % (SS, REL, x(doc.get("sheet", "Аркуш1"))),
        "xl/_rels/workbook.xml.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="%s/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="%s/sharedStrings" Target="sharedStrings.xml"/></Relationships>' % (REL, REL),
        "xl/worksheets/sheet1.xml": '<?xml version="1.0"?><worksheet xmlns="%s"><sheetData>%s</sheetData></worksheet>' % (SS, "".join(xml_rows)),
        "xl/sharedStrings.xml": '<?xml version="1.0"?><sst xmlns="%s" count="%d" uniqueCount="%d">%s</sst>' % (SS, len(strings), len(strings), "".join('<si><t xml:space="preserve">%s</t></si>' % x(s) for s in strings)),
        "docProps/core.xml": core_xml(doc.get("title", "")),
    }
    zwrite(path, parts)


def write_pptx(path, doc):
    P = "http://schemas.openxmlformats.org/presentationml/2006/main"
    A = "http://schemas.openxmlformats.org/drawingml/2006/main"
    slides = doc.get("slides") or [(doc.get("title", ""), doc.get("paras", []))]
    notes = doc.get("notes", [])
    ct, prels, ids, parts = "", [], [], {}

    def sp(texts):
        ps = "".join('<a:p><a:r><a:rPr lang="uk-UA"/><a:t>%s</a:t></a:r></a:p>' % x(t) for t in texts)
        return ('<p:sp><p:nvSpPr><p:cNvPr id="2" name="Text"/><p:cNvSpPr/><p:nvPr/></p:nvSpPr><p:spPr/>'
                '<p:txBody><a:bodyPr/><a:lstStyle/>%s</p:txBody></p:sp>' % ps)
    for i, (title, lines) in enumerate(slides, 1):
        lines_all = [title] + [l for t in lines for l in t.split("\n")]
        parts["ppt/slides/slide%d.xml" % i] = ('<?xml version="1.0"?><p:sld xmlns:p="%s" xmlns:a="%s"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>%s</p:spTree></p:cSld></p:sld>'
                                               % (P, A, sp(lines_all)))
        ct += '<Override PartName="/ppt/slides/slide%d.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.slide+xml"/>' % i
        prels.append('<Relationship Id="rId%d" Type="%s/slide" Target="slides/slide%d.xml"/>' % (i, REL, i))
        ids.append('<p:sldId id="%d" r:id="rId%d"/>' % (255 + i, i))
        if i <= len(notes) and notes[i - 1]:
            parts["ppt/notesSlides/notesSlide%d.xml" % i] = ('<?xml version="1.0"?><p:notes xmlns:p="%s" xmlns:a="%s"><p:cSld><p:spTree><p:nvGrpSpPr><p:cNvPr id="1" name=""/><p:cNvGrpSpPr/><p:nvPr/></p:nvGrpSpPr><p:grpSpPr/>%s</p:spTree></p:cSld></p:notes>'
                                                             % (P, A, sp(notes[i - 1].split("\n"))))
            parts["ppt/slides/_rels/slide%d.xml.rels" % i] = '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="%s/notesSlide" Target="../notesSlides/notesSlide%d.xml"/></Relationships>' % (REL, i)
            ct += '<Override PartName="/ppt/notesSlides/notesSlide%d.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.notesSlide+xml"/>' % i
    parts.update({
        "[Content_Types].xml": CT_HEAD + '<Override PartName="/ppt/presentation.xml" ContentType="application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml"/><Override PartName="/docProps/core.xml" ContentType="application/vnd.openxmlformats-package.core-properties+xml"/>' + ct + "</Types>",
        "_rels/.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="%s/officeDocument" Target="ppt/presentation.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/></Relationships>' % REL,
        "ppt/presentation.xml": '<?xml version="1.0"?><p:presentation xmlns:p="%s" xmlns:r="%s"><p:sldIdLst>%s</p:sldIdLst><p:sldSz cx="12192000" cy="6858000"/><p:notesSz cx="6858000" cy="9144000"/></p:presentation>' % (P, REL, "".join(ids)),
        "ppt/_rels/presentation.xml.rels": '<?xml version="1.0"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">%s</Relationships>' % "".join(prels),
        "docProps/core.xml": core_xml(doc.get("title", "")),
    })
    zwrite(path, parts)


def write_odt(path, doc):
    paras = []
    if doc.get("header"):
        paras.append(doc["header"])
    paras += doc.get("paras", [])
    if doc.get("table"):
        paras += [" | ".join(map(str, r)) for r in doc["table"]]
    paras += doc.get("after", [])
    body = "".join("<text:p>%s</text:p>" % "<text:line-break/>".join(x(l) for l in p.split("\n")) for p in paras)
    content = ('<?xml version="1.0" encoding="UTF-8"?><office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0" '
               'xmlns:text="urn:oasis:names:tc:opendocument:xmlns:text:1.0" office:version="1.2"><office:body><office:text>%s</office:text></office:body></office:document-content>' % body)
    manifest = ('<?xml version="1.0" encoding="UTF-8"?><manifest:manifest xmlns:manifest="urn:oasis:names:tc:opendocument:xmlns:manifest:1.0" manifest:version="1.2">'
                '<manifest:file-entry manifest:full-path="/" manifest:media-type="application/vnd.oasis.opendocument.text"/>'
                '<manifest:file-entry manifest:full-path="content.xml" manifest:media-type="text/xml"/></manifest:manifest>')
    with zipfile.ZipFile(path, "w") as z:
        z.writestr(zipfile.ZipInfo("mimetype"), "application/vnd.oasis.opendocument.text", compress_type=zipfile.ZIP_STORED)
        z.writestr("content.xml", content, compress_type=zipfile.ZIP_DEFLATED)
        z.writestr("META-INF/manifest.xml", manifest, compress_type=zipfile.ZIP_DEFLATED)


def rtf_text(s):
    out = []
    for ch in s:
        o = ord(ch)
        if ch in "\\{}":
            out.append("\\" + ch)
        elif ch == "\n":
            out.append("\\line ")
        elif o < 128:
            out.append(ch)
        else:
            out.append("\\u%d?" % (o if o < 32768 else o - 65536))
    return "".join(out)


def lines_of(doc):
    out = []
    if doc.get("header"):
        out.append(doc["header"])
    if doc.get("title"):
        out.append(doc["title"])
    out += doc.get("paras", [])
    if doc.get("table"):
        out += ["\t".join(map(str, r)) for r in doc["table"]]
    out += doc.get("after", [])
    if doc.get("footer"):
        out.append(doc["footer"])
    return out


def write_rtf(path, doc):
    body = "".join("\\pard %s\\par\n" % rtf_text(l) for l in lines_of(doc))
    open(path, "w", encoding="ascii").write("{\\rtf1\\ansi\\ansicpg1251\\deff0{\\fonttbl{\\f0 Times New Roman;}}\n%s}" % body)


def write_txt(path, doc):
    open(path, "w", encoding="utf-8").write("\n".join(lines_of(doc)) + "\n")


def write_csv(path, doc):
    rows = doc.get("table") or [["текст"]] + [[l] for l in lines_of(doc)]
    with open(path, "w", encoding="utf-8", newline="") as f:
        csv.writer(f).writerows(rows)


def zwrite(path, parts):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in parts.items():
            z.writestr(k, v)


WRITERS = {"docx": write_docx, "xlsx": write_xlsx, "pptx": write_pptx, "odt": write_odt, "rtf": write_rtf, "txt": write_txt, "csv": write_csv}

# ------------------------------------------------------------------ document builders: return (doc, formats, extra categories, where)


def sign():
    return "З повагою,\n%s\n%s" % (person()["name"], R.choice(COMPANIES))


def date():
    return (datetime.date(2026, 1, 10) + datetime.timedelta(days=R.randint(0, 300))).strftime("%d.%m.%Y")


# --- bank
def bank_pos(i):
    k = i % 6
    if k == 0:
        rows = [["№", "ПІБ", "Номер картки", "Термін дії", "CVV", "Банк"]]
        for n in range(R.randint(20, 40)):
            p = person(); b, c = card()
            rows.append([n + 1, p["name"], fmt_card(c), "%02d/%02d" % (R.randint(1, 12), R.randint(27, 31)), "%03d" % R.randint(0, 999), R.choice(BANKS)])
        return {"title": "Реєстр карток для зарахування заробітної плати", "table": rows, "sheet": "Картки"}, ["xlsx", "csv"], [], "таблиця, стовпці «Номер картки», «CVV»"
    if k == 1:
        p = person(); b, c = card()
        return {"title": "Заява на виплату", "paras": [
            "Прошу перерахувати компенсацію за відрядження на мою картку %s." % b,
            "Номер картки: %s, діє до %02d/%02d, код на звороті %03d." % (fmt_card(c), R.randint(1, 12), R.randint(27, 30), R.randint(0, 999)),
            "Власник картки: %s." % p["name"], date(), p["name"]]}, ["docx", "odt", "rtf"], [], "текст заяви"
    if k == 2:
        ib, mfo = iban_ua(); co = R.choice(COMPANIES)
        return {"title": "Реквізити для оплати", "paras": [
            "Отримувач: %s" % co, "Код ЄДРПОУ: %s" % edrpou(), "IBAN: %s" % fmt_iban(ib), "Банк: %s, МФО %s" % (R.choice(BANKS), mfo),
            "Призначення платежу: оплата за рахунком № %d від %s, без ПДВ." % (R.randint(100, 999), date()), sign()]}, ["docx", "txt", "pptx"], [], "реквізити, рядок IBAN"
    if k == 3:
        p = person(); b, c = card()
        return {"title": "Листування з бухгалтерією", "paras": [
            "Добрий день! Скидаю дані корпоративної картки для оплати підписки:",
            "card number %s\nexp %02d/%02d\nCVC %03d" % (fmt_card(c), R.randint(1, 12), R.randint(27, 30), R.randint(0, 999)),
            "ПІН-код %04d, тримайте його в сейфі." % R.randint(0, 9999), sign()]}, ["txt", "docx"], [], "лист, номер картки, CVC, ПІН"
    if k == 4:
        ib, mfo = iban_ua()
        return {"title": "International payment details", "paras": [
            "Beneficiary: %s" % R.choice(COMPANIES), "IBAN: %s" % ib, "SWIFT/BIC: %sUA%s" % (rs(string.ascii_uppercase, 4), rs(AZ09, 2)),
            "Bank: %s" % R.choice(BANKS), "Payment reference: invoice %d" % R.randint(1000, 9999)]}, ["docx", "pptx"], [], "реквізити, IBAN і SWIFT"
    p = person()
    return {"title": "Доступ до клієнт-банку", "paras": [
        "Для оплати рахунків під час моєї відпустки:", "Клієнт-банк %s\nлогін: %s\nпароль: %s" % (R.choice(BANKS), "buh" + rs(az09, 4), password()),
        "Ключ ЕЦП лежить у папці «Бухгалтерія».", p["name"]]}, ["txt", "rtf"], ["credentials"], "лист, логін і пароль клієнт-банку"


def bank_neg(i):
    k = i % 6
    if k == 0:
        rows = [["№ замовлення", "Дата", "Сума, грн", "ТТН"]] + [["%016d" % R.randint(10 ** 15, 10 ** 16 - 1), date(), "%d,00" % R.randint(100, 9000), "2045%010d" % R.randint(0, 10 ** 10)] for _ in range(25)]
        return {"title": "Реєстр замовлень", "table": rows}, ["xlsx", "csv"], "16-значні номери замовлень і ТТН, не картки"
    if k == 1:
        return {"title": "Чек", "paras": ["Оплачено карткою **** **** **** %04d." % R.randint(0, 9999), "Сума: %d,00 грн. Дякуємо за покупку!" % R.randint(50, 900)]}, ["txt", "docx"], "маска картки"
    if k == 2:
        return {"title": "Рахунок-фактура № %d" % R.randint(100, 999), "paras": ["Постачальник: %s" % R.choice(COMPANIES), "Сума до сплати: %d,00 грн." % R.randint(1000, 90000), "Реквізити надамо окремим листом."]}, ["docx", "odt"], "рахунок без реквізитів"
    if k == 3:
        return {"title": "Нові картки для клієнтів", "paras": ["Відкрийте картку Visa або Mastercard у нашому банку онлайн за 5 хвилин.", "Обслуговування 0 грн, кешбек до 5%. Телефон гарячої лінії 0 800 000 000."]}, ["pptx", "txt"], "реклама карток без номерів"
    if k == 4:
        return {"title": "Звіт про продажі", "paras": ["Виручка: 1 234 567,89 грн за %s." % date(), "Номер звіту 2026-0001-2345-6789, телефон відділу +380 44 000 00 00."]}, ["docx", "rtf"], "числа й телефони в одному рядку"
    return {"title": "Шаблон заяви", "paras": ["Номер картки: ________________", "IBAN: UA__ ______ _________________", "Підпис: ______"]}, ["docx", "odt"], "порожній шаблон"


# --- personal
def personal_pos(i):
    k = i % 6
    if k == 0:
        rows = [["ПІБ", "Дата народження", "РНОКПП", "Телефон", "Адреса"]]
        for _ in range(R.randint(25, 50)):
            p = person(); rows.append([p["name"], p["birth"].strftime("%d.%m.%Y"), p["rnokpp"], p["phone"], p["address"]])
        return {"title": "Список працівників", "table": rows, "sheet": "Персонал"}, ["xlsx", "csv"], [], "таблиця працівників з РНОКПП"
    if k == 1:
        p = person()
        return {"title": "Особова картка працівника", "paras": [
            "ПІБ: %s" % p["name"], "Дата народження: %s" % p["birth"].strftime("%d.%m.%Y"), "РНОКПП: %s" % p["rnokpp"],
            "Паспорт серії %s, виданий %s РВ ГУ ДМС у %s" % (p["passport"], date(), R.choice(CITIES)),
            "Адреса реєстрації: %s" % p["address"], "Телефон: %s" % p["phone"]]}, ["docx", "odt", "rtf"], [], "особова картка"
    if k == 2:
        p = person()
        return {"title": "Дані для оформлення відрядження", "paras": [
            "%s, ID-картка № %s, запис ЄДДР %s." % (p["name"], p["idcard"], p["unzr"]),
            "Закордонний паспорт %s%06d, дійсний до 2031 року." % (rs("ABCEFKMNPT", 2), R.randint(100000, 999999)),
            "Посвідчення водія %s %06d." % (rs("АВЕКМНОРСТХ", 3), R.randint(100000, 999999))]}, ["docx", "txt", "pptx"], [], "документи працівника"
    if k == 3:
        rows = [["Клієнт", "Телефон"]] + [[person()["name"], person()["phone"]] for _ in range(R.randint(15, 30))]
        return {"title": "Контакти клієнтів для обдзвону", "table": rows}, ["xlsx", "csv", "docx"], [], "список 15+ телефонів з ПІБ"
    if k == 4:
        p = person()
        return {"title": "Анкета клієнта", "slides": [("Анкета клієнта", ["%s" % p["name"], "д.н. %s, ІПН %s" % (p["birth"].strftime("%d.%m.%Y"), p["rnokpp"]), p["address"]])],
                "notes": ["Перевірити паспорт %s перед підписанням договору." % p["passport"]]}, ["pptx"], [], "слайд і нотатки"
    p = person()
    return {"title": "Довідка", "paras": ["Видана %s, ідентифікаційний код %s, у тому, що він (вона) працює в %s." % (p["name"], p["rnokpp"], R.choice(COMPANIES))]}, ["rtf", "odt", "txt"], [], "довідка з ідентифікаційним кодом"


def personal_neg(i):
    k = i % 5
    if k == 0:
        return {"title": "Договір № %010d" % R.randint(10 ** 9, 10 ** 10 - 1), "paras": ["Артикул товару 4820001234567, кількість 10 шт.", "Сторони: %s та %s." % (R.choice(COMPANIES), R.choice(COMPANIES))]}, ["docx", "rtf"], "10-значні номери договору й артикулу"
    if k == 1:
        return {"title": "Лист", "paras": ["Шановні партнери, нагадуємо про семінар %s." % date(), sign(), "тел. +380 44 000 12 34"]}, ["docx", "txt"], "один телефон у підписі"
    if k == 2:
        return {"title": "Наказ про відпустку", "paras": ["Надати щорічну відпустку %s з %s на 14 календарних днів." % (person()["name"], date())]}, ["docx", "odt", "pptx"], "ПІБ без ідентифікаторів"
    if k == 3:
        return {"title": R.choice(COMPANIES), "paras": ["Код ЄДРПОУ %s, юридична адреса: %s, %s." % (edrpou(), R.choice(CITIES), R.choice(STREETS)), "Комерційна пропозиція на постачання канцтоварів."]}, ["docx", "rtf"], "ЄДРПОУ компанії в шапці"
    return {"title": "Анкета (бланк)", "paras": ["ПІБ: ____________", "РНОКПП: __________", "Паспорт: серія ___ № ______"]}, ["docx", "csv"], "порожня анкета"


# --- credentials
def cred_pos(i):
    k = i % 7
    if k == 0:
        u = person()["name"].split()[1].lower()
        return {"title": "Ваш обліковий запис", "paras": ["Вітаємо! Для вас створено пошту.", "Логін: %s@romashka.ua\nТимчасовий пароль: %s" % (rs(az09, 6), password()), "Змініть пароль після першого входу.", "Служба ІТ"]}, ["docx", "txt", "rtf"], [], "лист ІТ з паролем"
    if k == 1:
        rows = [["Сервіс", "Адреса", "Логін", "Пароль"]] + [[s, "https://%s.local" % s.lower(), R.choice(["admin", "root", "operator", "buh"]), password()]
                                                           for s in ["CRM", "1C", "Router", "NAS", "Camera", "Mail", "Wiki", "Jira"]]
        return {"title": "Облікові записи", "table": rows}, ["xlsx", "csv", "docx"], [], "таблиця логінів і паролів"
    if k == 2:
        return {"title": "Налаштування підключення", "paras": ["Рядок підключення для звітів:", "Server=db01;Database=crm;User Id=sa;Password=%s;TrustServerCertificate=True" % password()]}, ["txt", "docx"], [], "рядок підключення до БД"
    if k == 3:
        return {"title": "Доступ до файлів", "paras": ["Архів лежить тут: ftp://upload:%s@files.romashka.local/2026/" % password(), "Резервна БД: postgres://app:%s@db02:5432/main" % password()]}, ["txt", "odt"], ["org"], "URL з паролем (і внутрішній домен romashka.local)"
    if k == 4:
        return {"title": "Wi-Fi для гостей", "paras": ["Мережа: Romashka-Guest", "Пароль від Wi-Fi: %s" % password(), "Діє до кінця місяця."]}, ["pptx", "docx", "txt"], [], "пароль Wi-Fi"
    if k == 5:
        return {"title": "Підключення до сервера", "paras": ["full address:s:srv-term-01\nusername:s:ROMASHKA\\admin\npassword 51:b:01000000D08C9DDF0115D1118C7A00C04FC297EB0100%s" % rs("0123456789ABCDEF", 120)]}, ["txt", "rtf"], [], "фрагмент .rdp з паролем"
    rows = [["login", "password_hash"]] + [[rs(az09, 7), bcrypt() if R.random() < 0.6 else rs("0123456789abcdef", 32)] for _ in range(20)]
    return {"title": "Вивантаження користувачів", "table": rows}, ["csv", "xlsx"], [], "хеші паролів (bcrypt, NTLM)"


def cred_neg(i):
    k = i % 5
    if k == 0:
        return {"title": "Повідомлення", "paras": ["Пароль змінено успішно.", "Забули пароль? Натисніть «Відновити»."]}, ["docx", "txt"], "повідомлення без пароля"
    if k == 1:
        return {"title": "Інструкція", "paras": ["Вкажіть у файлі налаштувань: password=<ваш_пароль>", "Password=********", "пароль: [вкажіть]"]}, ["odt", "docx"], "заглушки замість пароля"
    if k == 2:
        return {"title": "Політика паролів", "paras": ["Пароль має містити щонайменше 12 символів, великі й малі літери, цифри.", "Пароль змінюється кожні 90 днів."]}, ["docx", "pptx"], "політика без паролів"
    if k == 3:
        return {"title": "Оповідання", "paras": ["«Пароль?» — спитав вартовий. «Сонях», — відповів мандрівник, і ворота відчинилися."]}, ["rtf", "odt"], "слово «пароль» у художньому тексті"
    return {"title": "Облікові записи (шаблон)", "table": [["Сервіс", "Логін", "Пароль"], ["CRM", "", ""], ["Mail", "", ""]]}, ["xlsx", "csv"], "порожня таблиця"


# --- keys
def keys_pos(i):
    k = i % 6
    if k == 0:
        return {"title": "Ключ для сервера", "paras": ["Тримай ключ для доступу до srv-web-01, поклади в ~/.ssh/id_rsa:", pem("RSA PRIVATE KEY")]}, ["txt", "docx", "odt"], [], "PEM RSA у листі"
    if k == 1:
        return {"title": "Налаштування деплою", "paras": ["Приватний ключ бота деплою:", openssh_key()]}, ["txt", "docx"], [], "OpenSSH private key"
    if k == 2:
        return {"title": "Сертифікат сайту", "paras": ["Сертифікат і ключ для nginx:", pem("PRIVATE KEY"), "Пароль не потрібен."]}, ["docx", "pptx", "rtf"], [], "PRIVATE KEY (PKCS#8)"
    if k == 3:
        return {"title": "Ключ PuTTY", "paras": ["Файл ключа для підключення до маршрутизатора:", putty_key()]}, ["txt", "odt"], [], "ключ PuTTY"
    if k == 4:
        return {"title": "Ключ КЕП директора", "paras": ["Надсилаю ключ КЕП (файл Key-6.dat) для підписання звітності.", "Пароль до ключа: %s" % password(), "Не передавайте нікому."]}, ["docx", "rtf", "txt"], ["credentials"], "КЕП і пароль до ключа"
    words = " ".join(R.choice(BIP39) for _ in range(R.choice([12, 24])))
    return {"title": "Гаманець компанії", "paras": ["Мнемонічна фраза (seed phrase) гаманця для оплати хостингу:", words]}, ["txt", "pptx", "xlsx"], [], "сід-фраза"


def keys_neg(i):
    k = i % 5
    if k == 0:
        return {"title": "Сертифікат", "paras": ["Публічний сертифікат сервера:", pem("CERTIFICATE")]}, ["txt", "docx"], "публічний сертифікат"
    if k == 1:
        return {"title": "Ключ для доступу", "paras": ["Додайте мій публічний ключ у authorized_keys:", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI%s ivan@laptop" % rs(B64, 43)]}, ["txt", "odt"], "публічний ключ SSH"
    if k == 2:
        return {"title": "Що таке КЕП", "paras": ["Кваліфікований електронний підпис можна отримати в банку чи у Дії.", "Ключ зберігайте на захищеному носії."]}, ["docx", "pptx"], "довідка про КЕП"
    if k == 3:
        return {"title": "Інструкція", "paras": ["Вставте сюди ваш ключ:", "-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----"]}, ["docx", "rtf"], "заглушка ключа без тіла"
    return {"title": "Контрольні суми", "paras": ["SHA-256: %s" % rs("0123456789abcdef", 64), "Розмір: 1 048 576 байт"]}, ["txt", "csv"], "хеш файлу"


# --- tokens
def tokens_pos(i):
    names = list(TOKENS)
    t = names[i % len(names)]
    val = TOKENS[t]()
    ctx = R.choice([
        ("Конфіг сервісу", ["# налаштування інтеграції", "%s" % val if "\n" in val or "=" in val or t in ("bearer",) else "API_KEY=%s" % val]),
        ("Тікет розробника", ["Не працює вивантаження, ось ключ, з яким тестував:", val]),
        ("Нотатки", ["токен для бота / інтеграції:", val, "потім перевипустити"]),
    ])
    return {"title": ctx[0], "paras": ctx[1]}, ["txt", "docx", "odt", "pptx", "csv", "rtf"], [], "токен " + t


def tokens_neg(i):
    k = i % 5
    if k == 0:
        return {"title": "Приклад з документації", "paras": ["aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"]}, ["txt", "docx"], "офіційні приклади AWS"
    if k == 1:
        return {"title": "Налаштування", "paras": ["GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx", "STRIPE_KEY=sk_test_YOUR_KEY_HERE", "API_KEY=YOUR_API_KEY"]}, ["txt", "odt"], "заглушки токенів"
    if k == 2:
        return {"title": "Як отримати токен", "paras": ["Відкрийте Settings → Developer settings → Tokens і створіть новий токен з правами read.", "Скопіюйте його в менеджер паролів."]}, ["docx", "pptx"], "інструкція без токена"
    if k == 3:
        return {"title": "Вкладення", "paras": ["Логотип (base64): iVBORw0KGgo" + rs(B64, 120)]}, ["txt", "rtf"], "base64 зображення"
    return {"title": "Реліз", "paras": ["Збірка 4.6.0, SHA-256: %s" % rs("0123456789abcdef", 64), "commit %s" % rs("0123456789abcdef", 40)]}, ["txt", "csv"], "хеші збірки"


# --- infra
def infra_pos(i):
    k = i % 5
    if k == 0:
        return {"title": "VPN для віддаленої роботи", "paras": ["client\ndev tun\nremote vpn.romashka.ua 1194\n<ca>\n%s\n</ca>\n<key>\n%s\n</key>\n<tls-auth>\n%s\n</tls-auth>" % (pem("CERTIFICATE", 8), pem("PRIVATE KEY", 10), rs("0123456789abcdef", 64))]}, ["txt", "docx"], ["keys"], "профіль OpenVPN з ключем"
    if k == 1:
        return {"title": "WireGuard", "paras": ["[Interface]\nPrivateKey = %s=\nAddress = 10.8.0.%d/24\n[Peer]\nPublicKey = %s=\nEndpoint = vpn.romashka.ua:51820" % (rs(B64, 43), R.randint(2, 200), rs(B64, 43))]}, ["txt", "odt", "pptx"], [], "конфіг WireGuard"
    if k == 2:
        return {"title": "Доступ до кластера", "paras": ["apiVersion: v1\nkind: Config\nusers:\n- name: deploy\n  user:\n    client-certificate-data: %s\n    client-key-data: %s" % (rs(B64, 80), rs(B64, 120))]}, ["txt", "docx"], [], "kubeconfig"
    if k == 3:
        return {"title": ".env для продакшну", "paras": ["APP_ENV=production\nDB_HOST=db01\nDB_PASSWORD=%s\nSECRET_KEY=%s\nAPI_TOKEN=%s" % (password(), rs(Aa09, 40), rs(Aa09, 32))]}, ["txt", "xlsx", "csv"], ["credentials"], ".env із паролем і ключами"
    rows = "\n".join("INSERT INTO users (login, email, password_hash) VALUES ('%s', '%s@romashka.ua', '%s');" % (rs(az09, 6), rs(az09, 6), bcrypt()) for _ in range(12))
    return {"title": "Дамп таблиці користувачів", "paras": [rows]}, ["txt", "docx"], ["credentials"], "SQL-дамп з хешами паролів"


def infra_neg(i):
    k = i % 4
    if k == 0:
        return {"title": "Мережа офісу", "paras": ["remote vpn.romashka.ua 1194, протокол udp, підмережа 10.8.0.0/24.", "DNS: 10.0.0.2"]}, ["docx", "pptx"], "конфіг без секретів"
    if k == 1:
        return {"title": ".env.example", "paras": ["DB_HOST=\nDB_PASSWORD=\nSECRET_KEY="]}, ["txt", "csv"], "порожній шаблон .env"
    if k == 2:
        return {"title": "Запит до бази", "paras": ["SELECT login, last_seen FROM users WHERE active = 1 ORDER BY last_seen DESC;"]}, ["docx", "txt"], "SELECT без даних"
    return {"title": "Порти сервісів", "table": [["Сервіс", "Порт"], ["HTTP", "80"], ["HTTPS", "443"], ["VPN", "1194"]]}, ["xlsx", "pptx"], "таблиця портів"


# --- classified
GRIFS = ["Для службового користування", "ДСК", "Таємно", "Цілком таємно", "Комерційна таємниця", "Конфіденційно",
         "CONFIDENTIAL", "Internal use only", "STRICTLY CONFIDENTIAL"]


def classified_pos(i):
    g = GRIFS[i % len(GRIFS)]
    body = ["Звіт про результати переговорів з постачальником за %s." % date(), "Пропонуємо погодити знижку 7%% та відтермінування оплати на 60 днів."]
    if i % 3 == 0:
        return {"title": "Звіт", "header": "%s. Прим. № %d" % (g, R.randint(1, 5)), "paras": body}, ["docx"], [], "гриф у верхньому колонтитулі"
    if i % 3 == 1:
        return {"title": "", "paras": [g.upper() if R.random() < 0.5 else g, "Не підлягає розголошенню."] + body}, ["docx", "odt", "rtf", "txt", "pptx"], [], "гриф першим рядком"
    return {"title": "Протокол наради", "paras": body, "footer": "%s — копіювання заборонено" % g}, ["docx"], [], "гриф у нижньому колонтитулі"


def classified_neg(i):
    k = i % 4
    if k == 0:
        return {"title": "Політика конфіденційності", "paras": ["Ми не передаємо ваші персональні дані третім особам.", "Детальніше — на сайті компанії."]}, ["docx", "txt"], "політика конфіденційності сайту"
    if k == 1:
        return {"title": "Новини законодавства", "paras": ["Верховна Рада розглянула зміни до закону «Про державну таємницю»."]}, ["docx", "odt"], "стаття про закон"
    if k == 2:
        return {"title": "Казка", "paras": ["Стара таємниця лісу відкрилася лише найсміливішому."]}, ["rtf", "pptx"], "«таємниця» в художньому тексті"
    return {"title": "Прайс", "paras": ["Вудскрин для терас — 1250 грн/м²", "Дошка ДСКП 18 мм — 890 грн"]}, ["xlsx", "csv"], "«дск» всередині слів"


# --- org
def org_pos(i):
    k = i % 4
    if k == 0:
        return {"title": "Проєкт «Сокіл»", "paras": ["Статус Project Falcon на %s: завершено етап 2." % date(), "Бюджет етапу 3 — 1,2 млн грн."]}, ["docx", "pptx", "odt"], [], "кодова назва проєкту"
    if k == 1:
        return {"title": "Договори", "table": [["Номер", "Контрагент", "Сума"]] + [["№ РТ-%04d/26" % R.randint(1, 999), R.choice(COMPANIES), "%d 000" % R.randint(10, 900)] for _ in range(12)]}, ["xlsx", "csv"], [], "внутрішні номери договорів"
    if k == 2:
        return {"title": "Інфраструктура", "paras": ["Файли бухгалтерії — \\\\srv-buh-01\\buh, домен romashka.local.", "Резервні копії — srv-backup-02.romashka.local."]}, ["txt", "docx", "rtf"], [], "внутрішній домен і сервери"
    return {"title": "ОПЕРАЦІЯ ГРІМ", "paras": ["План запуску нової лінійки продукції, розсилка лише учасникам."]}, ["docx", "pptx"], [], "кодова назва"


def org_neg(i):
    k = i % 3
    if k == 0:
        return {"title": "Птахи України", "paras": ["Сокіл-сапсан — найшвидший птах планети."]}, ["docx", "rtf"], "«сокіл» як птах"
    if k == 1:
        return {"title": "Техніка", "paras": ["Falcon 9 вивела на орбіту ще 20 супутників."]}, ["txt", "pptx"], "falcon в іншому значенні"
    return {"title": "Договір № 45-П/2026", "paras": ["Договір постачання між %s та %s." % (R.choice(COMPANIES), R.choice(COMPANIES))]}, ["docx", "xlsx"], "договір іншого формату"


CATS = {"bank": (bank_pos, bank_neg), "personal": (personal_pos, personal_neg), "credentials": (cred_pos, cred_neg),
        "keys": (keys_pos, keys_neg), "tokens": (tokens_pos, tokens_neg), "infra": (infra_pos, infra_neg),
        "classified": (classified_pos, classified_neg), "org": (org_pos, org_neg)}


def mixed(i):
    p = person(); b, c = card(); ib, mfo = iban_ua()
    k = i % 5
    if k == 0:
        return {"title": "Виплата матеріальної допомоги", "paras": ["Прошу виплатити %s (РНОКПП %s) матеріальну допомогу." % (p["name"], p["rnokpp"]), "IBAN: %s" % fmt_iban(ib), "або на картку %s" % fmt_card(c)]}, ["docx", "xlsx"], ["personal", "bank"], "лист бухгалтерії"
    if k == 1:
        return {"title": "Пам'ятка новому працівнику", "paras": ["Пошта: %s@romashka.ua, пароль: %s" % (rs(az09, 6), password()), "Wi-Fi Romashka-Office, пароль від Wi-Fi: %s" % password(),
                                                            "VPN:\n[Interface]\nPrivateKey = %s=" % rs(B64, 43)]}, ["docx", "pptx", "txt"], ["credentials", "infra"], "пароль, Wi-Fi, VPN"
    if k == 2:
        return {"title": "Тікет INC-%d" % R.randint(1000, 9999), "header": "Конфіденційно", "paras": ["Падає синхронізація, рядок підключення: Server=db01;User Id=sa;Password=%s;" % password(), "Токен: %s" % TOKENS["github"]()]}, ["docx"], ["classified", "credentials", "tokens"], "тікет з грифом у колонтитулі"
    if k == 3:
        rows = [["Клієнт", "Телефон", "Картка"]] + [[person()["name"], person()["phone"], fmt_card(card()[1])] for _ in range(15)]
        return {"title": "Проєкт «Сокіл» — клієнти пілоту", "slides": [("Проєкт «Сокіл»", ["Клієнти пілоту:"] + ["%s, %s, %s" % tuple(r) for r in rows[1:]])]}, ["pptx", "xlsx"], ["org", "personal", "bank"], "презентація з таблицею клієнтів"
    return {"title": "Доступи для підрядника", "paras": ["ДСК", "Ключ для сервера:", pem("RSA PRIVATE KEY", 10), "Токен Slack: %s" % TOKENS["slack"]()]}, ["txt", "docx"], ["classified", "keys", "tokens"], "ключ і токен"


def clean(i):
    docs = [
        ("Наказ про відпустку", ["Надати відпустку працівникам відділу продажів згідно з графіком."]),
        ("Протокол наради", ["Присутні: 7 осіб. Вирішили: оновити прайс до кінця місяця.", "Відповідальний — відділ маркетингу."]),
        ("Комерційна пропозиція", ["Пропонуємо постачання офісного паперу за ціною 210 грн за пачку.", "Доставка безкоштовна від 20 пачок."]),
        ("Прайс-лист", ["Папір А4 — 210 грн", "Ручка — 15 грн", "Степлер — 120 грн"]),
        ("Новини компанії", ["Ми відкрили новий склад у Житомирі площею 1 200 м²."]),
        ("Інструкція з охорони праці", ["Перед початком роботи перевірте справність обладнання.", "Про несправності повідомляйте керівника."]),
        ("Меню корпоративу", ["Салат, суп дня, печеня, узвар.", "Початок о 18:00."]),
        ("Графік чергувань", ["Понеділок — Іваненко, вівторок — Петренко, середа — Коваленко."]),
        ("Оголошення", ["У п'ятницю офіс працює до 16:00."]),
        ("План навчання", ["Курс Excel для бухгалтерії: 3 заняття по 2 години."]),
    ]
    t, ps = docs[i % len(docs)]
    return {"title": t, "paras": ps + [sign()] if i % 2 else ps}, ["docx", "odt", "rtf", "txt", "xlsx", "pptx", "csv"], [], ""


# ------------------------------------------------------------------ main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("out", nargs="?", default=os.path.expanduser("~/docscan-test-dataset-v2"))
    ap.add_argument("--seed", type=int, default=2026)
    ap.add_argument("--pos", type=int, default=12, help="positive documents per category")
    ap.add_argument("--neg", type=int, default=6, help="hard negatives per category")
    a = ap.parse_args()
    R.seed(a.seed)
    if os.path.exists(a.out):
        shutil.rmtree(a.out)
    rows = []

    def emit(folder, name, fmts, doc, expected, where, note):
        fmt = fmts[len(rows) % len(fmts)] if len(fmts) > 1 else fmts[0]
        if fmt != "pptx" and doc.get("slides"):  # a "presentation" in another format: slides and notes as text
            doc = dict(doc)
            doc["paras"] = [l for t, ls in doc.pop("slides") for l in [t] + list(ls)] + list(doc.pop("notes", []))
        os.makedirs(os.path.join(a.out, folder), exist_ok=True)
        fn = "%s.%s" % (name, fmt)
        WRITERS[fmt](os.path.join(a.out, folder, fn), doc)
        rows.append({"file": fn, "folder": folder, "format": fmt, "expected": ",".join(sorted(set(expected))) or "none", "where": where, "notes": note})

    for cat, (pos, neg) in CATS.items():
        for i in range(a.pos):
            doc, fmts, extra, where = pos(i)
            emit(cat + "/positive", "%s_pos_%02d" % (cat, i + 1), fmts, doc, [cat] + extra, where, "positive")
        for i in range(a.neg):
            doc, fmts, note = neg(i)
            emit(cat + "/negative", "%s_neg_%02d" % (cat, i + 1), fmts, doc, [], "", "hard negative: " + note)
    for i in range(15):
        doc, fmts, cats, where = mixed(i)
        emit("mixed", "mix_%02d" % (i + 1), fmts, doc, cats, where, "mixed")
    for i in range(20):
        doc, fmts, _, _ = clean(i)
        emit("clean", "clean_%02d" % (i + 1), fmts, doc, [], "", "clean")

    with open(os.path.join(a.out, "expected.tsv"), "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f, delimiter="\t", lineterminator="\n")
        w.writerow(["file", "folder", "format", "expected", "where", "notes"])
        for r in rows:
            w.writerow([r["file"], r["folder"], r["format"], r["expected"], r["where"], r["notes"]])
    summary = {"seed": a.seed, "documents": len(rows),
               "by_kind": {k: sum(1 for r in rows if k in r["notes"]) for k in ("positive", "hard negative", "mixed", "clean")},
               "by_format": {f: sum(1 for r in rows if r["format"] == f) for f in WRITERS},
               "by_category": {c: sum(1 for r in rows if c in r["expected"].split(",")) for c in CATS}}
    json.dump(summary, open(os.path.join(a.out, "summary.json"), "w", encoding="utf-8"), ensure_ascii=False, indent=2)
    open(os.path.join(a.out, "README.md"), "w", encoding="utf-8").write(
        "# Synthetic sensitive-data test set for DocScan (pass 3)\n\nGenerated by `docscan-project/test-critical/gen_sensitive_dataset.py --seed %d`.\n"
        "All data is invented but in the real format (Luhn, IBAN mod-97, RNOKPP control digit, real token prefixes and lengths); "
        "none of it opens anything. `expected.tsv` lists every category present in each document (or `none`).\n" % a.seed)
    print("%s: %d documents  %s" % (a.out, len(rows), json.dumps(summary["by_kind"], ensure_ascii=False)))


if __name__ == "__main__":
    main()
