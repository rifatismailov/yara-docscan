/* DocScan remediation. See yara/docscan_disarm.h.
   Cures a document in place (backup first). Uses miniz to rebuild OOXML zips. */

#include <yara/docscan_disarm.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "miniz.h"
#include "zip.h"  // DOCSCAN_ZIP_MAX_ENTRY

// ---- small helpers ----
static int read_file(const char* path, unsigned char** out, size_t* out_len)
{
  FILE* f = fopen(path, "rb");
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
  FILE* f = fopen(path, "wb");
  if (!f)
    return -1;
  size_t wr = fwrite(buf, 1, len, f);
  fclose(f);
  return wr == len ? 0 : -1;
}

static int backup(const char* path)
{
  char bak[4096];
  snprintf(bak, sizeof(bak), "%s.docscan-bak", path);
  unsigned char* b;
  size_t n;
  if (read_file(path, &b, &n) != 0)
    return -1;
  int rc = write_file(bak, b, n);
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
    if (memcmp(b + i, "\\objupdate", 10) == 0)
    {
      b[i + 9] = 'X';  // \objupdate -> \objupdatX (control word broken)
      changed = 1;
    }
  }
  int rc = 0;
  if (changed)
  {
    rc = write_file(path, b, n);
    append(action, asz, "stripped:objupdate");
  }
  free(b);
  return rc;
}

// ---- OOXML string edits ----
// Replace every case-sensitive "DDEAUTO" with "DDE_OFF" (same length) in place.
static void strip_dde(unsigned char* buf, size_t len)
{
  // Replace with a 7-char token that contains no "DDE" (else DDE_LINK lingers).
  for (size_t i = 0; i + 7 <= len; i++)
    if (memcmp(buf + i, "DDEAUTO", 7) == 0)
      memcpy(buf + i, "REMOVED", 7);
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
  mz_zip_archive zout;
  memset(&zout, 0, sizeof(zout));
  if (!mz_zip_writer_init_file(&zout, tmp, 0))
  {
    mz_zip_reader_end(&zin);
    free(buf);
    return -1;
  }

  // markers for relationship/override removal
  const char* markers[6];
  int nm = 0;
  if (info->macro) markers[nm++] = "vbaProject";
  if (info->embedded) markers[nm++] = "oleObject";
  if (info->remote_template) markers[nm++] = "attachedTemplate";
  if (info->protocol_handler) { markers[nm++] = "ms-msdt"; markers[nm++] = "search-ms"; }

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
      strip_dde((unsigned char*) data, dsize);  // in-place, same length
    }

    mz_zip_writer_add_mem(&zout, name, payload, esize, MZ_DEFAULT_COMPRESSION);
    if (edited) free(edited);
    mz_free(data);
  }

  if (!failed)
    failed = !mz_zip_writer_finalize_archive(&zout);
  mz_zip_writer_end(&zout);
  mz_zip_reader_end(&zin);
  free(buf);

  if (failed)
  {
    remove(tmp);
    append(action, asz, "failed:unreadable-part");
    return -1;
  }

  // replace original with cured temp
  remove(path);
  if (rename(tmp, path) != 0)
    return -1;

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

  // LNK: the file itself is the vector -> back up and delete.
  if (info->type == 5)
  {
    if (info->lnk_bad)
    {
      backup(path);
      remove(path);
      append(out_action, out_action_sz, "deleted:lnk");
    }
    return 0;
  }

  // RTF
  if (info->type == 3)
  {
    if (info->rtf_objupdate)
    {
      backup(path);
      return cure_rtf(path, out_action, out_action_sz);
    }
    return 0;
  }

  // OOXML
  if (info->type == 1)
  {
    if (info->macro || info->embedded || info->remote_template ||
        info->protocol_handler || info->dde_auto)
    {
      backup(path);
      return cure_ooxml(path, info, out_action, out_action_sz);
    }
    return 0;
  }

  // OLE / PDF: not cured in place yet (quarantine handled by orchestrator).
  append(out_action, out_action_sz, "detect-only");
  return 0;
}
