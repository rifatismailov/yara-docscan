/* DocScan: LNK (Windows shortcut) inspector. Parses the binary MS-SHLLINK
   format to recover target + arguments (replaces the WScript.Shell COM used by
   Inspect-Lnk in doc-scan.ps1), then flags LOLBin / URL-in-args / obfuscation. */

#include "inspect.h"
#include "search.h"

#include <stdio.h>
#include <string.h>

static uint16_t rd16(const uint8_t* d, size_t n, size_t o)
{
  return (o + 2 <= n) ? (uint16_t) (d[o] | (d[o + 1] << 8)) : 0;
}

static uint32_t rd32(const uint8_t* d, size_t n, size_t o)
{
  if (o + 4 > n)
    return 0;
  return (uint32_t) d[o] | ((uint32_t) d[o + 1] << 8) |
         ((uint32_t) d[o + 2] << 16) | ((uint32_t) d[o + 3] << 24);
}

// Portable case-insensitive full-string compare (MSVC has no strcasecmp).
static int ci_streq(const char* a, const char* b)
{
  while (*a && *b)
  {
    char x = *a++, y = *b++;
    if (x >= 'A' && x <= 'Z')
      x += 32;
    if (y >= 'A' && y <= 'Z')
      y += 32;
    if (x != y)
      return 0;
  }
  return *a == 0 && *b == 0;
}

// Copy an ANSI NUL-terminated string at off into out.
static void cpy_ansi(
    const uint8_t* d,
    size_t n,
    size_t off,
    char* out,
    size_t out_sz)
{
  size_t i = 0;
  while (off + i < n && d[off + i] != 0 && i + 1 < out_sz)
  {
    out[i] = (char) d[off + i];
    i++;
  }
  out[i] = '\0';
}

// Copy a StringData entry (2-byte char count + chars) at off into out as ASCII
// (for UTF-16 we take the low byte — fine for paths/args). Returns bytes used.
static size_t cpy_stringdata(
    const uint8_t* d,
    size_t n,
    size_t off,
    int unicode,
    char* out,
    size_t out_sz)
{
  uint16_t count = rd16(d, n, off);
  size_t charsz = unicode ? 2 : 1;
  size_t base = off + 2;

  if (out != NULL)
  {
    size_t i = 0, j = 0;
    while (i < count && base + i * charsz < n && j + 1 < out_sz)
    {
      out[j++] = (char) d[base + i * charsz];
      i++;
    }
    out[j] = '\0';
  }

  return 2 + (size_t) count * charsz;
}

void docscan_inspect_lnk(const uint8_t* d, size_t n, docscan_result_t* r)
{
  if (n < 76 || rd32(d, n, 0) != 0x4C)  // HeaderSize must be 0x4C
    return;

  uint32_t flags = rd32(d, n, 0x14);
  int hasIDList = flags & 0x01;
  int hasLinkInfo = flags & 0x02;
  int hasName = flags & 0x04;
  int hasRelPath = flags & 0x08;
  int hasWorkDir = flags & 0x10;
  int hasArgs = flags & 0x20;
  int isUnicode = (flags & 0x80) ? 1 : 0;

  size_t pos = 76;

  if (hasIDList)
    pos += 2 + rd16(d, n, pos);  // IDListSize + the IDList

  char target[512] = "";
  if (hasLinkInfo && pos + 20 <= n)
  {
    uint32_t liSize = rd32(d, n, pos);
    uint32_t lbpOff = rd32(d, n, pos + 16);  // LocalBasePathOffset
    if (lbpOff != 0)
      cpy_ansi(d, n, pos + lbpOff, target, sizeof(target));
    pos += liSize;
  }

  char args[512] = "";
  if (hasName)
    pos += cpy_stringdata(d, n, pos, isUnicode, NULL, 0);
  if (hasRelPath)
    pos += cpy_stringdata(d, n, pos, isUnicode, NULL, 0);
  if (hasWorkDir)
    pos += cpy_stringdata(d, n, pos, isUnicode, NULL, 0);
  if (hasArgs)
    pos += cpy_stringdata(d, n, pos, isUnicode, args, sizeof(args));

  snprintf(r->lnk_target, sizeof(r->lnk_target), "%s", target);
  snprintf(r->lnk_args, sizeof(r->lnk_args), "%s", args);

  // LOLBin: the leaf name of the target path.
  const char* leaf = target;
  for (const char* p = target; *p; p++)
    if (*p == '\\' || *p == '/')
      leaf = p + 1;

  static const char* lolbins[] = {
      "cmd.exe",      "powershell.exe", "pwsh.exe",    "mshta.exe",
      "rundll32.exe", "wscript.exe",    "cscript.exe", "regsvr32.exe",
      "certutil.exe", "bitsadmin.exe",  "msiexec.exe", "forfiles.exe",
      "conhost.exe",  NULL};
  for (int i = 0; lolbins[i] != NULL; i++)
  {
    if (ci_streq(leaf, lolbins[i]))
    {
      r->lnk_lolbin = 1;
      break;
    }
  }

  // URL / UNC in arguments.
  const uint8_t* a = (const uint8_t*) args;
  size_t al = strlen(args);
  if (docscan_contains_ci(a, al, "http://") ||
      docscan_contains_ci(a, al, "https://") ||
      docscan_contains_ci(a, al, "ftp://") || docscan_contains_ci(a, al, "\\\\") ||
      docscan_contains_ci(a, al, "www."))
    r->lnk_url_args = 1;

  // Obfuscated / download cradle markers.
  static const char* obf[] = {
      "-enc",          "-encodedcommand",    "frombase64string",
      "-w hidden",     "-windowstyle hidden", "iex",
      "invoke-expression", "downloadstring",  NULL};
  for (int i = 0; obf[i] != NULL; i++)
  {
    if (docscan_contains_ci(a, al, obf[i]))
    {
      r->lnk_obfuscated = 1;
      break;
    }
  }
}
