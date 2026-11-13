/* DocScan remediation. See yara/docscan_disarm.h.
   Cures a document in place (backup first). Uses miniz to rebuild OOXML zips. */

#include <yara/docscan_disarm.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miniz.h"
#include "search.h"  // docscan_rtf_control_word_at
#include "zip.h"     // DOCSCAN_ZIP_MAX_ENTRY

// ---- small helpers ----
// All paths are UTF-8. On Windows they go through the wide-char CRT so names
// with Cyrillic (or any non-ANSI) characters work; plain fopen() would read
// the UTF-8 bytes as the ANSI code page.
#if defined(_WIN32)
#include <io.h>     // _wrename (MSVC accepted it implicitly; clang does not)
#include <wchar.h>  // _wfopen, _wremove
#include <windows.h>

static int to_wide(const char* s, wchar_t* w, int wn)
{
  return MultiByteToWideChar(CP_UTF8, 0, s, -1, w, wn) > 0;
}

static FILE* ds_fopen(const char* path, const char* mode)
{
  wchar_t wp[4096], wm[8];
  if (!to_wide(path, wp, 4096) || !to_wide(mode, wm, 8))
    return NULL;
  return _wfopen(wp, wm);
}

static int ds_remove(const char* path)
{
  wchar_t wp[4096];
  return to_wide(path, wp, 4096) ? _wremove(wp) : -1;
}

static int ds_rename(const char* from, const char* to)
{
  wchar_t wf[4096], wt[4096];
  if (!to_wide(from, wf, 4096) || !to_wide(to, wt, 4096))
    return -1;
  return _wrename(wf, wt);
}
#else
#define ds_fopen fopen
#define ds_remove remove
#define ds_rename rename
#endif

static int read_file(const char* path, unsigned char** out, size_t* out_len)
{
  FILE* f = ds_fopen(path, "rb");
  if (!f)
    return -1;
  fseek(f, 0, SEEK_END);
  long n = ftell(f);
  fseek(f, 0, SEEK_SET);
  if (n < 0) { fclose(f); return -1; }
  unsigned char* b = (unsigned char*) malloc((size_t) n + 1);
  if (!b) { fclose(f); return -1; }
  size_t rd = fread(b, 1, (size_t) n, f);
  fclose(f);
  b[rd] = 0;
  *out = b;
  *out_len = rd;
  return 0;
}

static int write_file(const char* path, const void* buf, size_t len)
{
  FILE* f = ds_fopen(path, "wb");
  if (!f)
    return -1;
  size_t wr = fwrite(buf, 1, len, f);
  int rc = fclose(f);
  return (wr == len && rc == 0) ? 0 : -1;
}

static int file_exists(const char* path)
{
  FILE* f = ds_fopen(path, "rb");
  if (f)
    fclose(f);
  return f != NULL;
}

static const char* base_name(const char* path)
{
  const char* b = path;
  for (const char* p = path; *p; p++)
    if (*p == '/' || *p == '\\')
      b = p + 1;
  return b;
}

// Copy the original before touching it. With a backup_dir the copy gets a
// unique name there (<name>.<n>.docscan-bak), so repeated hits never overwrite
// an earlier backup. Returns 0 only if the copy is fully written.
static int backup(const char* path, const char* backup_dir)
{
  char bak[4096];
  if (backup_dir != NULL && backup_dir[0] != '\0')
  {
    size_t l = strlen(backup_dir);
    const char* sep = (backup_dir[l - 1] == '/' || backup_dir[l - 1] == '\\') ? "" :
#if defined(_WIN32)
                                                                                "\\";
#else
                                                                                "/";
#endif
    int i = 0;
    do
    {
      snprintf(bak, sizeof(bak), "%s%s%s.%d.docscan-bak", backup_dir, sep, base_name(path), i++);
    } while (file_exists(bak) && i < 100000);
  }
  else
  {
    snprintf(bak, sizeof(bak), "%s.docscan-bak", path);
  }

  unsigned char* b;
  size_t n;
  if (read_file(path, &b, &n) != 0)
  {
    fprintf(stderr, "docscan-disarm: cannot read %s for backup (errno %d)\n", path, errno);
    return -1;
  }
  int rc = write_file(bak, b, n);
  if (rc != 0)
    fprintf(stderr, "docscan-disarm: cannot write backup %s (errno %d)\n", bak, errno);
  free(b);
  return rc;
}

static void append(char* dst, size_t sz, const char* s)
{
  size_t l = strlen(dst);
  if (l + 1 < sz)
    snprintf(dst + l, sz - l, "%s%s", l ? "," : "", s);
}

// ---- RTF: break the \objupdate control word ----
static int cure_rtf(const char* path, char* action, size_t asz)
{
  unsigned char* b;
  size_t n;
  if (read_file(path, &b, &n) != 0)
    return -1;
  int changed = 0;
  for (size_t i = 0; i + 10 <= n; i++)
  {
    // only the real control word (the same test as detection): escaped text "\\objupdate" in a
    // document is left untouched
    if (b[i] == '\\' && docscan_rtf_control_word_at(b, n, i, "objupdate"))
    {
      b[i + 9] = 'X';  // \objupdate -> \objupdatX (control word broken)
      changed = 1;
    }
  }
  int rc = 0;
  if (changed)
  {
    rc = write_file(path, b, n);
    append(action, asz, rc == 0 ? "stripped:objupdate" : "failed:write");
  }
  free(b);
  return rc;
}

// ---- OOXML string edits ----
static int lower_c(unsigned char c)
{
  return (c >= 'A' && c <= 'Z') ? c + 32 : c;
}

// Neutralise DDE field instructions in place (same length, XML stays valid):
//   DDEAUTO ... -> REMOVED ...      DDE ... -> REM ...
// Case-insensitive, like detection, and only at the start of a field
// instruction (after '>' or '"' plus spaces), so ordinary text that merely
// contains the letters "DDE" is left alone.
static void strip_dde(unsigned char* buf, size_t len)
{
  for (size_t i = 0; i + 4 <= len; i++)
  {
    if (lower_c(buf[i]) != 'd' || lower_c(buf[i + 1]) != 'd' ||
        lower_c(buf[i + 2]) != 'e')
      continue;

    size_t k = i;
    while (k > 0 && buf[k - 1] == ' ')
      k--;
    if (k == 0 || (buf[k - 1] != '>' && buf[k - 1] != '"'))
      continue;

    if (i + 7 <= len && lower_c(buf[i + 3]) == 'a' && lower_c(buf[i + 4]) == 'u' &&
        lower_c(buf[i + 5]) == 't' && lower_c(buf[i + 6]) == 'o')
      memcpy(buf + i, "REMOVED", 7);
    else if (buf[i + 3] == ' ')
      memcpy(buf + i, "REM", 3);
  }
}

// Word complex fields whose joined instruction starts with DDE (possibly
// split over several <w:instrText> runs): blank every run of that field with
// spaces (same length, XML stays valid, the field instruction becomes empty).
static void blank_dde_fields(unsigned char* buf, size_t len)
{
  size_t runs[64][2];  // [start, end) of each instrText content in the field
  int nr = 0, open = 0;
  char head[16];
  size_t hl = 0;

  for (size_t i = 0; i < len; i++)
  {
    if (buf[i] != '<')
      continue;
    if (len - i > 10 && memcmp(buf + i, "<w:fldChar", 10) == 0)
    {
      size_t g = i;
      while (g < len && buf[g] != '>')
        g++;
      size_t tl = g - i;
      int is = 0, ie = 0;
      for (size_t k = i; k + 7 <= i + tl; k++)
      {
        if (memcmp(buf + k, "\"begin\"", 7) == 0) is = 1;
        if (k + 10 <= i + tl && memcmp(buf + k, "\"separate\"", 10) == 0) ie = 1;
        if (k + 5 <= i + tl && memcmp(buf + k, "\"end\"", 5) == 0) ie = 1;
      }
      if (is)
      {
        open = 1; nr = 0; hl = 0;
      }
      else if (open && ie)
      {
        size_t h = 0;
        while (h < hl && head[h] == ' ')
          h++;
        if (hl - h >= 3 && lower_c(head[h]) == 'd' && lower_c(head[h + 1]) == 'd' &&
            lower_c(head[h + 2]) == 'e')
          for (int r = 0; r < nr; r++)
            memset(buf + runs[r][0], ' ', runs[r][1] - runs[r][0]);
        open = 0;
      }
    }
    else if (open && len - i > 12 && memcmp(buf + i, "<w:instrText", 12) == 0)
    {
      size_t c = i;
      while (c < len && buf[c] != '>')
        c++;
      if (c >= len)
        break;
      size_t s0 = ++c;
      while (c < len && buf[c] != '<')
      {
        if (hl < sizeof(head))
          head[hl++] = (char) buf[c];
        c++;
      }
      if (nr < 64)
      {
        runs[nr][0] = s0;
        runs[nr][1] = c;
        nr++;
      }
      i = c - 1;
    }
  }
}

// Excel: service|'topic'!item inside <f>..</f> is a DDE formula.
static int is_dde_formula(const unsigned char* f, size_t len)
{
  for (size_t p = 1; p < len; p++)
  {
    if (f[p] != '|')
      continue;
    size_t k = p;
    while (k > 0 && ((f[k - 1] >= 'a' && f[k - 1] <= 'z') || (f[k - 1] >= 'A' && f[k - 1] <= 'Z') ||
                     (f[k - 1] >= '0' && f[k - 1] <= '9') || f[k - 1] == '_' || f[k - 1] == '.'))
      k--;
    if (k < p && memchr(f + p, '!', len - p) != NULL)
      return 1;
  }
  return 0;
}

// Drop every <f ...>..</f> holding a DDE formula; the cached <v> value stays,
// leaving a plain value cell. Returns a new malloc'd buffer.
static unsigned char* remove_dde_formulas(const unsigned char* in, size_t len, size_t* out_len)
{
  unsigned char* out = (unsigned char*) malloc(len + 1);
  if (!out)
    return NULL;
  size_t o = 0, i = 0;
  while (i < len)
  {
    if (in[i] == '<' && i + 2 < len && in[i + 1] == 'f' && (in[i + 2] == '>' || in[i + 2] == ' '))
    {
      size_t g = i;
      while (g < len && in[g] != '>')
        g++;
      if (g < len && in[g - 1] != '/')
      {
        size_t c0 = g + 1, e = c0;
        while (e + 4 <= len && memcmp(in + e, "</f>", 4) != 0)
          e++;
        if (e + 4 <= len && is_dde_formula(in + c0, e - c0))
        {
          i = e + 4;  // skip the whole element
          continue;
        }
      }
    }
    out[o++] = in[i++];
  }
  *out_len = o;
  return out;
}

// <ddeLink ddeService=".." ddeTopic=".."> : blank both values (same length).
static void blank_ddelink(unsigned char* buf, size_t len)
{
  const char* names[2] = {"ddeService=\"", "ddeTopic=\""};
  for (int a = 0; a < 2; a++)
  {
    size_t nl = strlen(names[a]);
    for (size_t i = 0; i + nl <= len; i++)
    {
      if (memcmp(buf + i, names[a], nl) != 0)
        continue;
      for (size_t k = i + nl; k < len && buf[k] != '"'; k++)
        buf[k] = ' ';
    }
  }
}

// Remove every <Relationship ...> / <Override ...> element whose text contains
// any of the given markers. Returns a new malloc'd buffer (len in *out_len).
static unsigned char* remove_elements(
    const unsigned char* in,
    size_t in_len,
    const char* const* markers,
    int nmarkers,
    size_t* out_len)
{
  unsigned char* out = (unsigned char*) malloc(in_len + 1);
  if (!out)
    return NULL;
  size_t o = 0, i = 0;
  while (i < in_len)
  {
    // Length-checked compare: the extracted part is not NUL-terminated, and a
    // '<' in its last bytes made strncmp read past the end (found by libFuzzer).
    if (in[i] == '<' &&
        ((in_len - i >= 13 && memcmp(in + i, "<Relationship", 13) == 0) ||
         (in_len - i >= 9 && memcmp(in + i, "<Override", 9) == 0)))
    {
      // find element end ">"
      size_t j = i;
      while (j < in_len && in[j] != '>')
        j++;
      if (j < in_len)
        j++;  // include '>'
      size_t elen = j - i;
      int drop = 0;
      for (int m = 0; m < nmarkers && !drop; m++)
      {
        const char* mk = markers[m];
        size_t mlen = strlen(mk);
        for (size_t k = i; k + mlen <= j; k++)
          if (memcmp(in + k, mk, mlen) == 0) { drop = 1; break; }
      }
      if (!drop)
      {
        memcpy(out + o, in + i, elen);
        o += elen;
      }
      i = j;
    }
    else
    {
      out[o++] = in[i++];
    }
  }
  *out_len = o;
  return out;
}

static int name_is(const char* name, const char* suffix)
{
  size_t ln = strlen(name), ls = strlen(suffix);
  return ln >= ls && strcmp(name + ln - ls, suffix) == 0;
}

static int cure_ooxml(const char* path, const docscan_disarm_info* info,
                      char* action, size_t asz)
{
  unsigned char* buf;
  size_t size;
  if (read_file(path, &buf, &size) != 0)
    return -1;

  mz_zip_archive zin;
  memset(&zin, 0, sizeof(zin));
  if (!mz_zip_reader_init_mem(&zin, buf, size, 0))
  {
    free(buf);
    return -1;
  }

  char tmp[4096];
  snprintf(tmp, sizeof(tmp), "%s.docscan-tmp", path);
  // Build the cured zip in memory and write it with write_file(): miniz's own
  // file API uses ANSI fopen() and fails on non-ANSI paths on Windows.
  mz_zip_archive zout;
  memset(&zout, 0, sizeof(zout));
  if (!mz_zip_writer_init_heap(&zout, 0, 0))
  {
    mz_zip_reader_end(&zin);
    free(buf);
    return -1;
  }

  // markers for relationship/override removal
  static const char* handlers[] = {
      "ms-msdt:", "search-ms:", "search:", "ms-officecmd:", "mhtml:",
      "ms-word:", "ms-excel:", "ms-powerpoint:", "!x-usc:", NULL};
  const char* markers[16];
  int nm = 0;
  if (info->macro) markers[nm++] = "vbaProject";
  if (info->embedded) markers[nm++] = "oleObject";
  if (info->remote_template) markers[nm++] = "attachedTemplate";
  if (info->protocol_handler)
    for (int h = 0; handlers[h] != NULL; h++)
      markers[nm++] = handlers[h];

  int failed = 0;
  int n = (int) mz_zip_reader_get_num_files(&zin);
  for (int i = 0; i < n && !failed; i++)
  {
    mz_zip_archive_file_stat st;
    if (!mz_zip_reader_file_stat(&zin, (mz_uint) i, &st))
    {
      failed = 1;
      break;
    }
    const char* name = st.m_filename;

    // skip (drop) malicious binary parts
    if (info->macro && (name_is(name, "vbaProject.bin") ||
                        name_is(name, "vbaData.xml")))
      continue;
    if (info->embedded && strstr(name, "embeddings/oleObject") &&
        name_is(name, ".bin"))
      continue;

    // A part we can't (or won't: zip-bomb size) read must not be silently
    // dropped from the cured document — give up and leave the file as is.
    void* data = NULL;
    size_t dsize = 0;
    if (st.m_uncomp_size <= DOCSCAN_ZIP_MAX_ENTRY)
      data = mz_zip_reader_extract_to_heap(&zin, (mz_uint) i, &dsize, 0);
    if (!data)
    {
      failed = 1;
      break;
    }

    void* edited = NULL;
    size_t esize = dsize;
    const void* payload = data;

    if (name_is(name, ".rels") && nm > 0)
    {
      edited = remove_elements(data, dsize, markers, nm, &esize);
      if (edited) payload = edited;
    }
    else if (info->macro && name_is(name, "[Content_Types].xml"))
    {
      const char* mk[1] = {"vbaProject"};
      edited = remove_elements(data, dsize, mk, 1, &esize);
      if (edited) payload = edited;
    }
    else if (info->dde_auto &&
             (strstr(name, "word/document.xml") || strstr(name, "word/header") ||
              strstr(name, "word/footer")))
    {
      strip_dde((unsigned char*) data, dsize);         // in-place, same length
      blank_dde_fields((unsigned char*) data, dsize);  // split DDE fields
    }
    else if (info->dde_auto && strstr(name, "xl/worksheets/") && name_is(name, ".xml"))
    {
      edited = remove_dde_formulas(data, dsize, &esize);
      if (edited) payload = edited;
    }
    else if (info->dde_auto && strstr(name, "xl/externalLinks/") && name_is(name, ".xml"))
    {
      blank_ddelink((unsigned char*) data, dsize);
    }

    mz_zip_writer_add_mem(&zout, name, payload, esize, MZ_DEFAULT_COMPRESSION);
    if (edited) free(edited);
    mz_free(data);
  }

  void* zbuf = NULL;
  size_t zsize = 0;
  if (!failed)
    failed = !mz_zip_writer_finalize_heap_archive(&zout, &zbuf, &zsize);
  int write_failed = 0;
  if (!failed)
    failed = write_failed = write_file(tmp, zbuf, zsize) != 0;
  if (zbuf)
    mz_free(zbuf);
  mz_zip_writer_end(&zout);
  mz_zip_reader_end(&zin);
  free(buf);

  if (failed)
  {
    ds_remove(tmp);
    append(action, asz, write_failed ? "failed:write" : "failed:unreadable-part");
    return -1;
  }

  // replace original with cured temp. If the original cannot be removed (open
  // in another program, e.g. Word holds it) leave it untouched and report it,
  // so the caller can retry later; the backup already exists.
  if (ds_remove(path) != 0)
  {
    ds_remove(tmp);  // original still in place
    append(action, asz, "failed:replace");
    return -1;
  }
  if (ds_rename(tmp, path) != 0)
  {
    // original gone, rename failed: keep the cured copy as <file>.docscan-tmp
    append(action, asz, "failed:replace");
    return -1;
  }

  if (info->macro) append(action, asz, "removed:vbaProject.bin");
  if (info->embedded) append(action, asz, "removed:embeddings");
  if (info->remote_template) append(action, asz, "removed:remote-template");
  if (info->protocol_handler) append(action, asz, "removed:protocol-rel");
  if (info->dde_auto) append(action, asz, "stripped:dde");
  return 0;
}

int docscan_disarm(const char* path, const docscan_disarm_info* info,
                   char* out_action, size_t out_action_sz)
{
  if (out_action && out_action_sz)
    out_action[0] = 0;
  if (!info || !info->present)
    return 0;

  int any = info->macro || info->remote_template || info->protocol_handler ||
            info->dde_auto || info->embedded || info->rtf_objupdate ||
            info->lnk_bad || info->quarantine;

  // HIGH verdict but the policy asked for no action: report it.
  if (!any)
  {
    append(out_action, out_action_sz, "detect-only");
    return 0;
  }

  // Legacy OLE (.doc/.xls) cannot be cured in place reliably -> quarantine.
  // RTF: \objupdate can be stripped, an embedded object (Equation, Package)
  // cannot be cut out reliably -> quarantine.
  // A plain ZIP archive: the dangerous file is INSIDE it -> the whole archive goes to quarantine.
  int quarantine = info->quarantine || (info->type == 2) || (info->type == 6) ||
                   (info->type == 3 && info->embedded);

  // PDF: only quarantine is possible.
  if (info->type == 4 && !quarantine)
  {
    append(out_action, out_action_sz, "detect-only");
    return 0;
  }

  // Never modify or delete a file whose backup could not be written.
  if (backup(path, info->backup_dir) != 0)
  {
    append(out_action, out_action_sz, "failed:backup");
    return -1;
  }

  // Quarantine / LNK: the file itself goes away (the backup keeps it).
  if (quarantine || (info->type == 5 && info->lnk_bad))
  {
    if (ds_remove(path) != 0)
    {
      append(out_action, out_action_sz, "failed:delete");
      return -1;
    }
    append(out_action, out_action_sz,
           info->type == 5 && !quarantine ? "deleted:lnk" : "quarantined");
    return 0;
  }

  if (info->type == 3 && info->rtf_objupdate)
    return cure_rtf(path, out_action, out_action_sz);

  if (info->type == 1)
    return cure_ooxml(path, info, out_action, out_action_sz);

  append(out_action, out_action_sz, "detect-only");
  return 0;
}
