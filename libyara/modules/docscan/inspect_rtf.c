/* DocScan: RTF inspector. Mirrors Inspect-Rtf from the retired PowerShell implementation (doc-scan.ps1).
   Facts: \objupdate, embedded objects, Equation Editor objects, OLE Package payloads
   (\objdata is hex: an OLE1 object header + native data). */

#include "inspect.h"
#include "search.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RTF_MAX_OBJ (8u * 1024 * 1024)

static int hexval(uint8_t c)
{
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

static uint32_t le32(const uint8_t* d, size_t n, size_t o)
{
  return o + 4 <= n ? (uint32_t) d[o] | ((uint32_t) d[o + 1] << 8) |
                          ((uint32_t) d[o + 2] << 16) | ((uint32_t) d[o + 3] << 24)
                    : 0;
}

// OLE1 object (decoded \objdata): OLEVersion u32, FormatID u32, ClassName
// (u32 len + chars), TopicName, ItemName (u32 len + chars), NativeDataSize u32,
// native data. Class "Package" -> native data is the package (flags, label, path).
static void parse_ole1(const uint8_t* b, size_t n, docscan_result_t* r)
{
  size_t p = 8;
  uint32_t cl = le32(b, n, p);
  if (cl == 0 || cl > 256 || p + 4 + cl > n)
    return;
  const uint8_t* cls = b + p + 4;
  p += 4 + cl;
  int is_package = cl >= 7 && memcmp(cls, "Package", 7) == 0;
  if (cl >= 8 && memcmp(cls, "Equation", 8) == 0)
    r->equation_objects++;
  if (!is_package)
    return;
  for (int k = 0; k < 2; k++)  // TopicName, ItemName
  {
    uint32_t l = le32(b, n, p);
    if (l > n || p + 4 + l > n)
      return;
    p += 4 + l;
  }
  uint32_t ns = le32(b, n, p);
  p += 4;
  if (p >= n)
    return;
  if (ns > n - p)
    ns = (uint32_t) (n - p);
  docscan_record_package(b + p, ns, 0, "rtf", r);
}

// Decode the hex run after every \objdata and parse it as an OLE1 object.
static void scan_objdata(const uint8_t* d, size_t n, docscan_result_t* r)
{
  size_t i = 0;
  int objects = 0;
  while (i < n && objects++ < 64)
  {
    const uint8_t* at = docscan_memmem(d + i, n - i, "\\objdata", 8);
    if (at == NULL)
      break;
    size_t p = (size_t) (at - d) + 8;
    uint8_t* buf = (uint8_t*) malloc(RTF_MAX_OBJ);
    if (buf == NULL)
      return;
    size_t bl = 0;
    int hi = -1;
    for (; p < n && bl < RTF_MAX_OBJ; p++)
    {
      uint8_t c = d[p];
      if (c == ' ' || c == '\r' || c == '\n' || c == '\t')
        continue;
      if (c == '}' || c == '{' || c == '\\')
        break;
      int v = hexval(c);
      if (v < 0)
        break;
      if (hi < 0)
        hi = v;
      else
      {
        buf[bl++] = (uint8_t) (hi << 4 | v);
        hi = -1;
      }
    }
    if (bl > 16)
    {
      char pn[64];
      snprintf(pn, sizeof(pn), "rtf:objdata[%d]", objects - 1);
      docscan_add_part(r, pn, buf, bl);  // decoded object -> second scan
      parse_ole1(buf, bl, r);
    }
    free(buf);
    i = p;
  }
}

void docscan_inspect_rtf(const uint8_t* data, size_t size, docscan_result_t* r)
{
  // \objupdate — forces the embedded OLE object to update (fetch/run) on open.
  // Classic RTF weaponisation (T1203). HIGH.
  if (docscan_contains_ci(data, size, "\\objupdate"))
    r->rtf_objupdate = 1;

  // Presence of an embedded object — context only (common & often benign).
  if (docscan_contains_ci(data, size, "\\objdata") ||
      docscan_contains_ci(data, size, "\\objlink") ||
      docscan_contains_ci(data, size, "\\objhtml"))
    r->rtf_embedded_object = 1;

  // Equation Editor 3.0 object: declared class, or the class name hex-encoded
  // in \objdata ("Equation" = 4571756174696f6e) when \objclass is left out.
  int eq_before = r->equation_objects;
  scan_objdata(data, size, r);
  if (r->equation_objects == eq_before &&
      (docscan_contains_ci(data, size, "\\objclass Equation") ||
       docscan_contains_ci(data, size, "4571756174696f6e")))
    r->equation_objects++;
}
