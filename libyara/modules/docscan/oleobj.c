/* DocScan: facts about objects inside a CFB (OLE compound file):
   an OOXML embedding (oleObject*.bin) or a whole legacy Office file.
     "\x01Ole10Native"  -> OLE Package: the carried file name
     "Equation Native"  -> Equation Editor 3.0 object (CVE-2017-11882 family)
     "\x03OCXNAME"      -> ActiveX control
     "Workbook"/"Book"  -> BIFF8 BOUNDSHEET records of type "macro sheet" (XLM)
   Facts only; docscan-policy.yar decides what they mean. Bounds-checked. */

#include "inspect.h"
#include "cfb.h"

#include <stdio.h>
#include <string.h>

typedef struct
{
  const char* source;
  docscan_result_t* r;
} ole_ctx;

static void add_activex(docscan_result_t* r, const char* id)
{
  for (int i = 0; i < r->n_activex; i++)
    if (strcmp(r->activex[i], id) == 0)
      return;
  if (r->n_activex < DOCSCAN_MAX_ACTIVEX)
    snprintf(r->activex[r->n_activex++], sizeof(r->activex[0]), "%s", id);
}

// Copy a NUL-terminated ANSI string from d[*p..n) (at most out_sz-1 chars).
static int take_cstr(const uint8_t* d, size_t n, size_t* p, char* out, size_t out_sz)
{
  size_t k = 0;
  while (*p < n && d[*p] != 0)
  {
    if (k + 1 < out_sz)
      out[k++] = (d[*p] >= 0x20 && d[*p] < 0x7F) ? (char) d[*p] : '?';
    (*p)++;
  }
  out[k] = '\0';
  if (*p >= n)
    return -1;
  (*p)++;  // skip NUL
  return 0;
}

void docscan_record_package(
    const uint8_t* d,
    size_t n,
    int has_size_prefix,
    const char* source,
    docscan_result_t* r)
{
  size_t p = has_size_prefix ? 4 : 0;
  char label[256], path[256];
  if (p + 2 > n)
    return;
  p += 2;  // flags
  if (take_cstr(d, n, &p, label, sizeof(label)) != 0)
    return;
  if (take_cstr(d, n, &p, path, sizeof(path)) != 0)
    path[0] = '\0';
  const char* name = label;
  if (name[0] == '\0')
  {
    // no label: use the base name of the original path
    name = path;
    for (const char* c = path; *c; c++)
      if (*c == '\\' || *c == '/')
        name = c + 1;
  }
  if (r->n_packages < DOCSCAN_MAX_PACKAGES)
  {
    docscan_package_t* pk = &r->packages[r->n_packages++];
    snprintf(pk->name, sizeof(pk->name), "%s", name);
    snprintf(pk->source, sizeof(pk->source), "%s", source ? source : "");
  }
}

// BIFF8 workbook globals: BOUNDSHEET (0x0085) = u32 pos, u8 state, u8 type;
// type 0x01 = Excel 4.0 macro sheet. Globals end at the first EOF (0x000A).
static void scan_biff(const uint8_t* d, size_t n, docscan_result_t* r)
{
  size_t p = 0;
  int records = 0;
  while (p + 4 <= n && records++ < 100000)
  {
    uint16_t type = (uint16_t) (d[p] | (d[p + 1] << 8));
    uint16_t len = (uint16_t) (d[p + 2] | (d[p + 3] << 8));
    size_t body = p + 4;
    if (body + len > n)
      break;
    if (type == 0x000A && records > 1)
      break;
    if (type == 0x0085 && len >= 6 && d[body + 5] == 0x01)
      r->xlm_macrosheets++;
    p = body + len;
  }
}

static int on_stream(const char* name, const uint8_t* data, size_t size, void* ud)
{
  ole_ctx* c = (ole_ctx*) ud;
  if (strcmp(name, "\x01Ole10Native") == 0)
    docscan_record_package(data, size, 1, c->source, c->r);
  else if (strcmp(name, "Equation Native") == 0)
    c->r->equation_objects++;
  else if (strcmp(name, "\x03OCXNAME") == 0)
    add_activex(c->r, "ocx");
  else if (strcmp(name, "Workbook") == 0 || strcmp(name, "Book") == 0)
    scan_biff(data, size, c->r);
  return 0;
}

void docscan_scan_ole_objects(
    const uint8_t* data,
    size_t size,
    const char* source,
    docscan_result_t* r)
{
  ole_ctx c = {source, r};
  docscan_cfb_foreach_named_stream(data, size, on_stream, &c);
}

void docscan_add_activex(docscan_result_t* r, const char* id)
{
  add_activex(r, id);
}
