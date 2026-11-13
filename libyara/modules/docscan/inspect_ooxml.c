/* DocScan: OOXML inspector. Mirrors Inspect-Ooxml from the retired PowerShell implementation (doc-scan.ps1).

   OOXML (docx/xlsx/pptx) is a ZIP. We iterate its entries and, by path:
     *.rels                         -> external relationships (rels.c)
     word/vbaProject.bin            -> macro present
     word/document.xml, headers...  -> DDEAUTO
     word/embeddings/oleObject*.bin -> embedded LNK / PE, OLE Package, Equation (oleobj.c)
     <part>/activeX/activeXN.xml    -> ActiveX control CLSID
     *.rels aFChunk relationship     -> altChunk (embedded RTF/HTML/MHT document)
     xl/macrosheets/<sheet>          -> Excel 4.0 (XLM) macro sheets
*/

#include "inspect.h"
#include "magic.h"
#include "zip.h"
#include "rels.h"
#include "vba.h"
#include "search.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static int strncasecmp_portable(const char* a, const char* b, size_t n)
{
  for (size_t i = 0; i < n; i++)
  {
    int ca = tolower((unsigned char) a[i]), cb = tolower((unsigned char) b[i]);
    if (ca != cb || ca == 0)
      return ca - cb;
  }
  return 0;
}

static int ends_with(const char* s, const char* suffix)
{
  size_t ls = strlen(s), lx = strlen(suffix);
  return ls >= lx && strcmp(s + ls - lx, suffix) == 0;
}

// word/document.xml, word/headerN.xml, word/footerN.xml, xl/worksheets/sheetN.xml, xl/workbook.xml
static int is_body_xml(const char* name)
{
  if (strstr(name, "word/document.xml"))
    return 1;
  if ((strstr(name, "word/header") || strstr(name, "word/footer")) &&
      ends_with(name, ".xml"))
    return 1;
  if (strstr(name, "xl/worksheets/sheet") && ends_with(name, ".xml"))
    return 1;
  if (ends_with(name, "xl/workbook.xml"))
    return 1;
  return 0;
}

// Parts an altChunk usually points to (word/afchunk.mht, word/afchunk1.rtf ...).
static int is_altchunk_part(const char* name)
{
  if (strncmp(name, "word/", 5) != 0 || strchr(name + 5, '/') != NULL)
    return 0;
  return strstr(name, "afchunk") != NULL || strstr(name, "aFChunk") != NULL ||
         ends_with(name, ".rtf") || ends_with(name, ".mht") ||
         ends_with(name, ".mhtml") || ends_with(name, ".htm") ||
         ends_with(name, ".html");
}

static int is_embedded_ole(const char* name)
{
  return strstr(name, "embeddings/oleObject") != NULL && ends_with(name, ".bin");
}

static int lower(uint8_t c)
{
  return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

// Raw fact: every "DDE..." field instruction (DDEAUTO or "DDE "), so rules can
// decide which commands are dangerous. The end depends on where it sits:
//   <w:fldSimple w:instr=" DDE ... "/>   attribute -> ends at '"'
//   <w:instrText> DDE "a" "b" </w:instrText>  text -> ends at '<' (quotes allowed)
static void record_dde(const uint8_t* xml, size_t n, docscan_result_t* r)
{
  for (size_t i = 0; i + 4 <= n && r->n_dde < DOCSCAN_MAX_DDE; i++)
  {
    if (lower(xml[i]) != 'd' || lower(xml[i + 1]) != 'd' ||
        lower(xml[i + 2]) != 'e' ||
        (lower(xml[i + 3]) != 'a' && xml[i + 3] != ' '))
      continue;

    size_t p = i;
    while (p > 0 && xml[p - 1] == ' ')
      p--;
    int in_attr = (p > 0 && xml[p - 1] == '"');

    char* out = r->dde[r->n_dde++];
    size_t k = 0;
    while (i < n && xml[i] != '<' && !(in_attr && xml[i] == '"') && k + 1 < 512)
      out[k++] = (char) xml[i++];
    out[k] = '\0';

    // evidence: the first DDE instruction of any kind (DDEAUTO or plain DDE)
    if (r->dde_command[0] == '\0')
      snprintf(r->dde_command, sizeof(r->dde_command), "%s", out);
  }
}

// Add an instruction to dde[] (trimmed, deduplicated).
static void add_dde(docscan_result_t* r, const char* s)
{
  while (*s == ' ')
    s++;
  if (*s == '\0' || r->n_dde >= DOCSCAN_MAX_DDE)
    return;
  for (int i = 0; i < r->n_dde; i++)
    if (strcmp(r->dde[i], s) == 0)
      return;
  snprintf(r->dde[r->n_dde++], sizeof(r->dde[0]), "%s", s);
  if (r->dde_command[0] == '\0')
    snprintf(r->dde_command, sizeof(r->dde_command), "%s", s);
}

// Word complex fields: the instruction may be split over several
// <w:instrText> runs ("DDE" + "AUTO c:\..."), a known way to dodge a plain
// string search. Join the runs of each field (fldChar begin .. separate/end).
static void record_complex_fields(const uint8_t* xml, size_t n, docscan_result_t* r)
{
  char instr[512];
  size_t il = 0;
  int open = 0;

  for (size_t i = 0; i < n; i++)
  {
    if (xml[i] != '<')
      continue;

    if (n - i > 10 && memcmp(xml + i, "<w:fldChar", 10) == 0)
    {
      const uint8_t* gt = docscan_memmem(xml + i, n - i, ">", 1);
      size_t tag = gt ? (size_t) (gt - (xml + i)) : n - i;
      int begin = docscan_contains(xml + i, tag, "\"begin\"");
      if (begin)
      {
        open = 1;
        il = 0;
      }
      else if (open && (docscan_contains(xml + i, tag, "\"separate\"") ||
                        docscan_contains(xml + i, tag, "\"end\"")))
      {
        instr[il] = '\0';
        const char* t = instr;
        while (*t == ' ')
          t++;
        if (lower((uint8_t) t[0]) == 'd' && lower((uint8_t) t[1]) == 'd' &&
            lower((uint8_t) t[2]) == 'e')
          add_dde(r, t);
        open = 0;
      }
    }
    else if (open && n - i > 12 && memcmp(xml + i, "<w:instrText", 12) == 0)
    {
      const uint8_t* gt = docscan_memmem(xml + i, n - i, ">", 1);
      if (gt == NULL)
        break;
      size_t c = (size_t) (gt - xml) + 1;
      while (c < n && xml[c] != '<' && il + 1 < sizeof(instr))
        instr[il++] = (char) xml[c++];
      i = c - 1;
    }
  }
}

// Excel DDE formula: service|'topic'!item  e.g.  cmd|' /c calc'!A0
static int is_dde_formula(const uint8_t* f, size_t len)
{
  for (size_t p = 1; p < len; p++)
  {
    if (f[p] != '|')
      continue;
    size_t k = p;
    while (k > 0 && (isalnum(f[k - 1]) || f[k - 1] == '_' || f[k - 1] == '.'))
      k--;
    if (k < p && docscan_memmem(f + p, len - p, "!", 1) != NULL)
      return 1;
  }
  return 0;
}

// xl/worksheets/sheetN.xml: every <f>..</f> holding a DDE formula -> dde[].
static void record_excel_formulas(const uint8_t* xml, size_t n, docscan_result_t* r)
{
  for (size_t i = 0; i + 3 < n && r->n_dde < DOCSCAN_MAX_DDE; i++)
  {
    if (xml[i] != '<' || xml[i + 1] != 'f' || (xml[i + 2] != '>' && xml[i + 2] != ' '))
      continue;
    const uint8_t* gt = docscan_memmem(xml + i, n - i, ">", 1);
    if (gt == NULL || gt[-1] == '/')
      continue;
    size_t c0 = (size_t) (gt - xml) + 1;
    const uint8_t* end = docscan_memmem(xml + c0, n - c0, "</f>", 4);
    if (end == NULL)
      break;
    size_t flen = (size_t) (end - (xml + c0));
    if (is_dde_formula(xml + c0, flen))
    {
      char buf[512];
      size_t k = (size_t) snprintf(buf, sizeof(buf), "DDE ");
      for (size_t j = 0; j < flen && k + 1 < sizeof(buf); j++)
        buf[k++] = (char) xml[c0 + j];
      buf[k] = '\0';
      add_dde(r, buf);
    }
    i = (size_t) (end - xml);
  }
}

// xl/externalLinks/externalLinkN.xml: <ddeLink ddeService=".." ddeTopic="..">
static void record_excel_ddelink(const uint8_t* xml, size_t n, docscan_result_t* r)
{
  const uint8_t* at = docscan_memmem(xml, n, "<ddeLink", 8);
  if (at == NULL)
    return;
  const uint8_t* gt = docscan_memmem(at, n - (size_t) (at - xml), ">", 1);
  size_t tl = gt ? (size_t) (gt - at) : n - (size_t) (at - xml);
  char svc[200] = "", topic[300] = "";
  const char* names[2] = {"ddeService=\"", "ddeTopic=\""};
  char* outs[2] = {svc, topic};
  size_t szs[2] = {sizeof(svc), sizeof(topic)};
  for (int a = 0; a < 2; a++)
  {
    const uint8_t* v = docscan_memmem(at, tl, names[a], strlen(names[a]));
    if (v == NULL)
      continue;
    v += strlen(names[a]);
    size_t k = 0;
    while (v < at + tl && *v != '"' && k + 1 < szs[a])
      outs[a][k++] = (char) *v++;
    outs[a][k] = '\0';
  }
  char buf[512];
  snprintf(buf, sizeof(buf), "DDE %s %s", svc, topic);
  add_dde(r, buf);
}

// DDE detection inside a decompressed body xml part.
static void scan_dde(const uint8_t* xml, size_t n, docscan_result_t* r)
{
  record_dde(xml, n, r);
  record_complex_fields(xml, n, r);

  if (docscan_contains_ci(xml, n, "DDEAUTO"))
  {
    r->dde_auto = 1;

    // Capture a short evidence snippet starting at DDEAUTO (stop at '<').
    if (r->dde_command[0] == '\0')
    {
      const uint8_t* at = docscan_memmem(xml, n, "DDEAUTO", 7);
      if (at != NULL)
      {
        size_t avail = n - (size_t) (at - xml);
        size_t i = 0;
        while (i < avail && at[i] != '<' && i + 1 < sizeof(r->dde_command))
        {
          r->dde_command[i] = (char) at[i];
          i++;
        }
        r->dde_command[i] = '\0';
      }
    }
  }
  else if (
      docscan_contains_ci(xml, n, "DDE ") &&   // "DDE " command, not "hi(dde)n"
      (docscan_contains_ci(xml, n, "cmd") ||
       docscan_contains_ci(xml, n, "powershell") ||
       docscan_contains_ci(xml, n, "mshta") ||
       docscan_contains_ci(xml, n, "rundll32")))
  {
    r->dde_link = 1;
  }
}

// <Relationship ... Type=".../aFChunk" Target="afchunk.rtf"/> -> altchunks[]
static void record_altchunks(const uint8_t* xml, size_t n, docscan_result_t* r)
{
  size_t i = 0;
  while (i < n && r->n_altchunks < DOCSCAN_MAX_ALTCHUNK)
  {
    const uint8_t* at = docscan_memmem(xml + i, n - i, "<Relationship ", 14);
    if (at == NULL)
      break;
    size_t s0 = (size_t) (at - xml);
    const uint8_t* gt = docscan_memmem(at, n - s0, ">", 1);
    size_t tl = gt ? (size_t) (gt - at) : n - s0;
    if (docscan_contains(at, tl, "/aFChunk\""))
    {
      char tgt[256] = "";
      const uint8_t* v = docscan_memmem(at, tl, "Target=\"", 8);
      if (v != NULL)
      {
        v += 8;
        size_t k = 0;
        while (v < at + tl && *v != '"' && k + 1 < sizeof(tgt))
          tgt[k++] = (char) *v++;
        tgt[k] = '\0';
      }
      snprintf(r->altchunks[r->n_altchunks++], sizeof(r->altchunks[0]), "%s", tgt);
    }
    i = s0 + tl + 1;
  }
}

// word/activeX/activeX1.xml: <ax:ocx ax:classid="{8856F961-...}" ...> -> activex[]
static void record_activex_xml(const uint8_t* xml, size_t n, docscan_result_t* r)
{
  const uint8_t* v = docscan_memmem(xml, n, "classid=\"", 9);
  char id[64] = "ocx";
  if (v != NULL)
  {
    v += 9;
    size_t k = 0;
    while (v < xml + n && *v != '"' && k + 1 < sizeof(id))
      id[k++] = (char) *v++;
    id[k] = '\0';
  }
  docscan_add_activex(r, id);
}

// Look for an embedded LNK signature or an embedded PE (MZ..PE).
// Sets the per-object facts in *e and the legacy flags in *r.
static void scan_embedded_ole(
    const uint8_t* d,
    size_t n,
    docscan_embedded_t* e,
    docscan_result_t* r)
{
  static const uint8_t lnk_sig[20] = {
      0x4C, 0x00, 0x00, 0x00, 0x01, 0x14, 0x02, 0x00, 0x00, 0x00,
      0x00, 0x00, 0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46};

  const uint8_t* lp = docscan_memmem(d, n, lnk_sig, sizeof(lnk_sig));
  if (lp != NULL)
  {
    r->embedded_lnk = 1;
    e->is_lnk = 1;
    docscan_inspect_lnk(lp, (size_t) (d + n - lp), r);  // parse for target/args
  }

  // MZ ... e_lfanew -> "PE\0\0"
  for (size_t i = 0; i + 0x40 < n; i++)
  {
    if (d[i] == 0x4D && d[i + 1] == 0x5A)  // "MZ"
    {
      uint32_t off = (uint32_t) d[i + 0x3C] | ((uint32_t) d[i + 0x3D] << 8) |
                     ((uint32_t) d[i + 0x3E] << 16) |
                     ((uint32_t) d[i + 0x3F] << 24);
      size_t p = i + off;
      if (off > 0 && off < 0x1000 && p + 4 < n && d[p] == 'P' &&
          d[p + 1] == 'E' && d[p + 2] == 0 && d[p + 3] == 0)
      {
        r->embedded_pe = 1;
        e->is_pe = 1;
        break;
      }
    }
  }
}

// Extensions of files inside an archive that are inspected as documents (by their magic bytes, not only
// the name: a renamed file is still inspected by what it really is).
static int archive_doc_name(const char* name)
{
  static const char* ext[] = {".doc", ".dot", ".docx", ".docm", ".dotx", ".dotm", ".xls", ".xlt", ".xlsx",
                              ".xlsm", ".xltx", ".xltm", ".xlsb", ".xla", ".xlam", ".ppt", ".pps", ".pot",
                              ".pptx", ".pptm", ".potx", ".potm", ".ppsx", ".ppsm", ".ppa", ".ppam", ".rtf",
                              ".pdf", ".lnk", NULL};
  size_t ln = strlen(name);
  for (int k = 0; ext[k] != NULL; k++)
  {
    size_t le = strlen(ext[k]);
    if (ln > le && strncasecmp_portable(name + ln - le, ext[k], le) == 0)
      return 1;
  }
  return 0;
}

// A plain ZIP archive (not Office / OpenDocument): list the first-level entries as facts and inspect
// the documents inside with the same inspectors as a file of their own. No recursion (an archive inside
// is not opened), bounded: DOCSCAN_MAX_ARCHIVE_DOCS documents, each <= DOCSCAN_ZIP_MAX_ENTRY, all
// <= DOCSCAN_ARCHIVE_BUDGET bytes — a zip bomb cannot make the scan expensive.
static void inspect_archive(docscan_zip* z, int count, docscan_result_t* r)
{
  r->is_archive = 1;
  for (int i = 0; i < count; i++)
  {
    char name[256];
    if (docscan_zip_entry_name(z, i, name, sizeof(name)) != 0)
      continue;
    int enc = docscan_zip_entry_encrypted(z, i);
    r->archive_encrypted += enc;
    if (r->n_archive_entries < DOCSCAN_MAX_ARCHIVE)
    {
      docscan_archive_entry_t* e = &r->archive_entries[r->n_archive_entries++];
      snprintf(e->name, sizeof(e->name), "%s", name);
      e->size = docscan_zip_entry_size(z, i);
      e->encrypted = enc;
    }
    else
    {
      r->archive_truncated = 1;
    }
  }

  size_t budget = DOCSCAN_ARCHIVE_BUDGET;
  r->archive_depth = 1;
  for (int i = 0; i < count && r->n_archive_docs < DOCSCAN_MAX_ARCHIVE_DOCS; i++)
  {
    char name[256];
    if (docscan_zip_entry_name(z, i, name, sizeof(name)) != 0 || !archive_doc_name(name) ||
        docscan_zip_entry_encrypted(z, i))
      continue;
    uint64_t sz = docscan_zip_entry_size(z, i);
    if (sz == 0 || sz > DOCSCAN_ZIP_MAX_ENTRY || sz > budget)
      continue;
    size_t n = 0;
    uint8_t* d = docscan_zip_extract(z, i, &n);
    if (d == NULL)
      continue;
    budget -= n;
    int inspected = 1;
    switch (docscan_detect_magic(d, n))
    {
    case DOCSCAN_TYPE_OOXML:
      docscan_inspect_ooxml(d, n, r);  // archive_depth = 1: inspected as Office, not as an archive
      break;
    case DOCSCAN_TYPE_OLE:
      docscan_inspect_ole(d, n, r);
      break;
    case DOCSCAN_TYPE_RTF:
      docscan_inspect_rtf(d, n, r);
      break;
    case DOCSCAN_TYPE_PDF:
      docscan_inspect_pdf(d, n, r);
      break;
    case DOCSCAN_TYPE_LNK:
      docscan_inspect_lnk(d, n, r);
      break;
    default:
      inspected = 0;
    }
    docscan_zip_free(d);
    if (inspected)
      snprintf(r->archive_docs[r->n_archive_docs++], sizeof(r->archive_docs[0]), "%s", name);
  }
  r->archive_depth = 0;

  // Every other file inside (exe, dll, scripts, anything that is not a document): handed to the second
  // scan as a part, so the vendor rules see its real (uncompressed) bytes - e.g. a miner or EICAR packed
  // into a zip. Bounded by docscan_add_part (DOCSCAN_PART_MAX per file, DOCSCAN_PARTS_BUDGET in all).
  for (int i = 0; i < count && r->parts_bytes < DOCSCAN_PARTS_BUDGET && budget > 0; i++)
  {
    char name[256];
    if (docscan_zip_entry_name(z, i, name, sizeof(name)) != 0 || archive_doc_name(name) ||
        docscan_zip_entry_encrypted(z, i))
      continue;
    uint64_t sz = docscan_zip_entry_size(z, i);
    if (sz == 0 || sz > DOCSCAN_ZIP_MAX_ENTRY || sz > budget || name[strlen(name) - 1] == '/')
      continue;
    size_t n = 0;
    uint8_t* d = docscan_zip_extract(z, i, &n);
    if (d == NULL)
      continue;
    budget -= n;
    char part[300];
    snprintf(part, sizeof(part), "archive:%s", name);
    docscan_add_part(r, part, d, n);
    docscan_zip_free(d);
  }
}

// docscan_zip_central_names callback: names of an unreadable ZIP go to archive_entries.
static void central_name(const char* name, int encrypted, uint64_t size, void* ud)
{
  docscan_result_t* r = (docscan_result_t*) ud;
  r->archive_encrypted += encrypted;
  if (strcmp(name, "[Content_Types].xml") == 0 || strcmp(name, "mimetype") == 0)
    r->archive_truncated |= 2;  // marks an Office / OpenDocument package (see below)
  if (r->n_archive_entries < DOCSCAN_MAX_ARCHIVE)
  {
    docscan_archive_entry_t* e = &r->archive_entries[r->n_archive_entries++];
    snprintf(e->name, sizeof(e->name), "%s", name);
    e->size = size;
    e->encrypted = encrypted;
  }
  else
  {
    r->archive_truncated |= 1;
  }
}

void docscan_inspect_ooxml(const uint8_t* data, size_t size, docscan_result_t* r)
{
  docscan_zip* z = docscan_zip_open(data, size);

  if (z == NULL)
  {
    // A "PK" file that miniz refuses (malformed — sometimes on purpose, to get past scanners while
    // Windows still lists it). The content is not inspected; the names are read straight from the
    // central directory, so the name rules (shortcut / script inside) still work.
    if (r->archive_depth == 0)
    {
      r->zip_unreadable = 1;
      if (docscan_zip_central_names(data, size, central_name, r) > 0)
      {
        int office = (r->archive_truncated & 2) != 0;
        r->archive_truncated &= 1;
        if (office)  // a damaged Office / OpenDocument file, not an archive: keep the names out
          r->n_archive_entries = 0, r->archive_encrypted = 0;
        else
          r->is_archive = 1;
      }
    }
    return;
  }

  int count = docscan_zip_count(z);

  // Office ([Content_Types].xml) or OpenDocument (mimetype) — a document; anything else at the top
  // level — a plain archive
  if (r->archive_depth == 0)
  {
    int office = 0;
    for (int i = 0; i < count && !office; i++)
    {
      char name[256];
      if (docscan_zip_entry_name(z, i, name, sizeof(name)) == 0 &&
          (strcmp(name, "[Content_Types].xml") == 0 || strcmp(name, "mimetype") == 0))
        office = 1;
    }
    if (!office)
    {
      inspect_archive(z, count, r);
      docscan_zip_close(z);
      return;
    }
  }

  for (int i = 0; i < count; i++)
  {
    char name[512];

    if (docscan_zip_entry_name(z, i, name, sizeof(name)) != 0)
      continue;

    // Raw fact: every part of the package.
    if (r->n_entries < DOCSCAN_MAX_ENTRIES)
    {
      docscan_entry_t* en = &r->entries[r->n_entries++];
      snprintf(en->name, sizeof(en->name), "%s", name);
      en->size = docscan_zip_entry_size(z, i);
    }
    else
    {
      r->entries_truncated = 1;
    }

    if (ends_with(name, ".rels"))
    {
      size_t sz;
      uint8_t* c = docscan_zip_extract(z, i, &sz);
      if (c != NULL)
      {
        docscan_scan_rels(c, sz, name, r);
        record_altchunks(c, sz, r);
        docscan_add_part(r, name, c, sz);
        docscan_zip_free(c);
      }
    }
    else if (ends_with(name, "vbaProject.bin"))
    {
      r->macro_present = 1;
      size_t sz;
      uint8_t* c = docscan_zip_extract(z, i, &sz);
      if (c != NULL)
      {
        docscan_scan_vba_container(c, sz, r);  // decompress VBA -> suspicious?
        docscan_zip_free(c);
      }
    }
    else if (is_body_xml(name))
    {
      size_t sz;
      uint8_t* c = docscan_zip_extract(z, i, &sz);
      if (c != NULL)
      {
        scan_dde(c, sz, r);
        if (strstr(name, "xl/worksheets/"))
          record_excel_formulas(c, sz, r);
        // the body text is NOT handed to the second scan: script rules fire on
        // documents that merely describe attacks (DDE in the text is parsed above)
        docscan_zip_free(c);
      }
    }
    else if (strstr(name, "xl/externalLinks/externalLink") && ends_with(name, ".xml"))
    {
      size_t sz;
      uint8_t* c = docscan_zip_extract(z, i, &sz);
      if (c != NULL)
      {
        record_excel_ddelink(c, sz, r);
        docscan_add_part(r, name, c, sz);
        docscan_zip_free(c);
      }
    }
    else if (is_embedded_ole(name))
    {
      size_t sz;
      uint8_t* c = docscan_zip_extract(z, i, &sz);
      docscan_embedded_t tmp;
      docscan_embedded_t* e = r->n_embedded < DOCSCAN_MAX_EMBEDDED
                                  ? &r->embedded[r->n_embedded++]
                                  : &tmp;
      memset(e, 0, sizeof(*e));
      snprintf(e->name, sizeof(e->name), "%s", name);
      e->size = docscan_zip_entry_size(z, i);
      if (c != NULL)
      {
        scan_embedded_ole(c, sz, e, r);
        docscan_scan_ole_objects(c, sz, name, r);  // Package / Equation / OCX
        docscan_add_part(r, name, c, sz);
        docscan_zip_free(c);
      }
    }
    else if (strstr(name, "/activeX/activeX"))
    {
      size_t sz;
      uint8_t* c = docscan_zip_extract(z, i, &sz);
      if (c != NULL)
      {
        if (ends_with(name, ".xml"))
          record_activex_xml(c, sz, r);
        docscan_add_part(r, name, c, sz);
        docscan_zip_free(c);
      }
    }
    else if (strstr(name, "xl/macrosheets/") && !strstr(name, "/_rels/") &&
             (ends_with(name, ".xml") || ends_with(name, ".bin")))
    {
      r->xlm_macrosheets++;
      size_t sz;
      uint8_t* c = docscan_zip_extract(z, i, &sz);
      if (c != NULL)
      {
        docscan_add_part(r, name, c, sz);
        docscan_zip_free(c);
      }
    }
    else if (strstr(name, "/embeddings/") || is_altchunk_part(name))
    {
      // any other embedded file (docx/xlsx/pdf/bin inside the package) and the
      // documents imported by altChunk (afchunk.rtf / .mht / .htm)
      size_t sz;
      uint8_t* c = docscan_zip_extract(z, i, &sz);
      if (c != NULL)
      {
        docscan_add_part(r, name, c, sz);
        docscan_zip_free(c);
      }
    }
  }

  docscan_zip_close(z);
}
