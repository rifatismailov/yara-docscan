#!/usr/bin/env python3
"""Markdown test corpus (E5Search crit/tests) -> real Office documents.

docx for every .md (headings, bold/italic runs, line breaks, lists, tables as
Word tables, font from the YAML front matter); the front matter itself is NOT
copied (it is ground truth for evaluation only). xlsx for documents with
tables, pptx for a share of the documents. doc/odt/rtf/xls/ppt are made later
with LibreOffice on the Windows VM.

usage: md2office.py <tests_dir> <out_dir>
"""
import os
import re
import sys

from docx import Document
from docx.shared import Pt
from openpyxl import Workbook
from pptx import Presentation
from pptx.util import Pt as PPt

SRC, OUT = sys.argv[1], sys.argv[2]
os.makedirs(OUT, exist_ok=True)

INLINE = re.compile(r"(\*\*[^*]+\*\*|\*[^*]+\*)")


def front_matter(lines):
    meta = {}
    if lines and lines[0].strip() == "---":
        for i in range(1, len(lines)):
            if lines[i].strip() == "---":
                for l in lines[1:i]:
                    if ":" in l:
                        k, v = l.split(":", 1)
                        meta[k.strip()] = v.strip()
                return meta, lines[i + 1:]
    return meta, lines


def plain(s):
    return re.sub(r"\*\*([^*]+)\*\*|\*([^*]+)\*", lambda m: m.group(1) or m.group(2), s).replace("\\", "")


def add_runs(par, text):
    for part in INLINE.split(text):
        if not part:
            continue
        if part.startswith("**") and part.endswith("**"):
            par.add_run(part[2:-2]).bold = True
        elif part.startswith("*") and part.endswith("*") and len(part) > 2:
            par.add_run(part[1:-1]).italic = True
        else:
            par.add_run(part.replace("\\", ""))


def blocks(lines):
    """-> list of ("h", level, text) | ("p", [line, ...]) | ("li", text) | ("table", rows)"""
    out, para, i = [], [], 0

    def flush():
        if para:
            out.append(("p", list(para)))
            para.clear()

    while i < len(lines):
        l = lines[i].rstrip("\r\n")
        s = l.strip()
        if not s:
            flush()
        elif s.startswith("#"):
            flush()
            lvl = len(s) - len(s.lstrip("#"))
            out.append(("h", lvl, s[lvl:].strip()))
        elif s.startswith("|"):
            flush()
            rows = []
            while i < len(lines) and lines[i].strip().startswith("|"):
                cells = [c.strip() for c in lines[i].strip().strip("|").split("|")]
                if not all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
                    rows.append(cells)
                i += 1
            out.append(("table", rows))
            continue
        elif re.match(r"^([-*+]|\d+[.)])\s+", s):
            flush()
            out.append(("li", re.sub(r"^[-*+]\s+", "", s)))
        elif re.fullmatch(r"-{3,}|\*{3,}", s):
            flush()
        else:
            para.append(l[1:].strip() if s.startswith(">") else l)
        i += 1
    flush()
    return out


def to_docx(bl, meta, path):
    d = Document()
    st = d.styles["Normal"]
    st.font.name = meta.get("font", "Times New Roman")
    try:
        st.font.size = Pt(float(meta.get("font_size", 14)))
    except ValueError:
        pass
    for b in bl:
        if b[0] == "h":
            add_runs(d.add_heading(level=min(b[1], 4)), b[2])
        elif b[0] == "li":
            add_runs(d.add_paragraph(style="List Bullet"), b[1])
        elif b[0] == "table":
            rows = b[1]
            if not rows:
                continue
            w = max(len(r) for r in rows)
            t = d.add_table(rows=len(rows), cols=w)
            t.style = "Table Grid"
            for r, row in enumerate(rows):
                for c, cell in enumerate(row):
                    add_runs(t.cell(r, c).paragraphs[0], cell)
        else:
            p = d.add_paragraph()
            for k, line in enumerate(b[1]):
                hard = line.endswith("  ") or line.endswith("\\")
                add_runs(p, line.rstrip(" \\"))
                if k < len(b[1]) - 1:
                    # each source line on its own line, as in the real document
                    # (the grif and "Прим. №" are separate lines)
                    p.add_run().add_break()
    d.core_properties.author = "Тестовий автор"
    d.core_properties.title = next((plain(b[2]) for b in bl if b[0] == "h"), "")
    d.save(path)


def to_xlsx(bl, path):
    wb = Workbook()
    ws = wb.active
    ws.title = "Документ"
    r = 1
    for b in bl:
        if b[0] == "table":
            for row in b[1]:
                for c, cell in enumerate(row, 1):
                    ws.cell(row=r, column=c, value=plain(cell))
                r += 1
        else:
            txt = plain(b[2] if b[0] == "h" else (b[1] if b[0] == "li" else " ".join(x.strip() for x in b[1])))
            ws.cell(row=r, column=1, value=txt)
            r += 1
    wb.save(path)


def to_pptx(bl, path):
    prs = Presentation()
    slide, body = None, None
    for b in bl:
        if b[0] == "h" or slide is None:
            slide = prs.slides.add_slide(prs.slide_layouts[1])
            slide.shapes.title.text = plain(b[2]) if b[0] == "h" else ""
            body = slide.placeholders[1].text_frame
            body.text = ""
            if b[0] == "h":
                continue
        if b[0] == "table":
            for row in b[1]:
                body.add_paragraph().text = " | ".join(plain(c) for c in row)
        else:
            txt = plain(b[1] if b[0] == "li" else " ".join(x.strip() for x in b[1]))
            p = body.add_paragraph()
            p.text = txt
            p.font.size = PPt(14)
    prs.save(path)


n = {"docx": 0, "xlsx": 0, "pptx": 0}
for sub in ("base", "hard", "generated"):
    d = os.path.join(SRC, "corpus", sub)
    for i, fn in enumerate(sorted(os.listdir(d))):
        if not fn.endswith(".md"):
            continue
        meta, lines = front_matter(open(os.path.join(d, fn), encoding="utf-8").read().replace("\r\n", "\n").split("\n"))
        bl = blocks(lines)
        stem = fn[:-3]
        to_docx(bl, meta, os.path.join(OUT, stem + ".docx"))
        n["docx"] += 1
        if any(b[0] == "table" for b in bl) and i % 2 == 0:
            to_xlsx(bl, os.path.join(OUT, stem + ".xlsx"))
            n["xlsx"] += 1
        if i % 3 == 0:
            to_pptx(bl, os.path.join(OUT, stem + ".pptx"))
            n["pptx"] += 1
print(n)
