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

static size_t put_utf8(char* out, size_t j, size_t out_sz, uint32_t cp);

// Copy an ANSI NUL-terminated string at off into out. The code page is not
// known (CP1252, CP1251...), so bytes >= 0x80 map to U+0080..U+00FF: the output
// is always valid UTF-8 (JSON consumers reject raw ANSI bytes).
static void cpy_ansi(
    const uint8_t* d,
    size_t n,
    size_t off,
    char* out,
    size_t out_sz)
{
  size_t j = 0;
  for (size_t i = 0; off + i < n && d[off + i] != 0; i++)
    j = put_utf8(out, j, out_sz, d[off + i]);
  out[j] = '\0';
}

// Append code point cp to out as UTF-8 (bounded). Returns new length.
static size_t put_utf8(char* out, size_t j, size_t out_sz, uint32_t cp)
{
  uint8_t b[4];
  size_t k;
  if (cp < 0x80) { b[0] = (uint8_t) cp; k = 1; }
  else if (cp < 0x800) { b[0] = 0xC0 | (cp >> 6); b[1] = 0x80 | (cp & 0x3F); k = 2; }
  else if (cp < 0x10000) { b[0] = 0xE0 | (cp >> 12); b[1] = 0x80 | ((cp >> 6) & 0x3F); b[2] = 0x80 | (cp & 0x3F); k = 3; }
  else { b[0] = 0xF0 | (cp >> 18); b[1] = 0x80 | ((cp >> 12) & 0x3F); b[2] = 0x80 | ((cp >> 6) & 0x3F); b[3] = 0x80 | (cp & 0x3F); k = 4; }
  if (j + k + 1 > out_sz)
    return j;
  for (size_t i = 0; i < k; i++)
    out[j++] = (char) b[i];
  return j;
}

// Decode `count` UTF-16LE units at off (or up to a NUL if count == SIZE_MAX)
// into UTF-8, so Cyrillic paths/arguments survive. Surrogate pairs handled.
static void cpy_utf16(
    const uint8_t* d,
    size_t n,
    size_t off,
    size_t count,
    char* out,
    size_t out_sz)
{
  size_t j = 0;
  for (size_t i = 0; i < count && off + 2 * i + 1 < n; i++)
  {
    uint32_t u = rd16(d, n, off + 2 * i);
    if (count == (size_t) -1 && u == 0)
      break;
    if (u >= 0xD800 && u <= 0xDBFF && i + 1 < count)
    {
      uint32_t lo = rd16(d, n, off + 2 * (i + 1));
      if (lo >= 0xDC00 && lo <= 0xDFFF)
      {
        u = 0x10000 + ((u - 0xD800) << 10) + (lo - 0xDC00);
        i++;
      }
    }
    if (u >= 0xD800 && u <= 0xDFFF)
      u = 0xFFFD;  // lone surrogate: not encodable as valid UTF-8
    j = put_utf8(out, j, out_sz, u);
  }
  out[j] = '\0';
}

// Copy a StringData entry (2-byte char count + chars) at off into out
// (UTF-16 decoded to UTF-8, ANSI copied as is). Returns bytes used.
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

  if (out != NULL && unicode)
  {
    cpy_utf16(d, n, base, count, out, out_sz);
  }
  else if (out != NULL)
  {
    size_t j = 0;
    for (size_t i = 0; i < count && base + i < n; i++)
      j = put_utf8(out, j, out_sz, d[base + i]);
    out[j] = '\0';
  }

  return 2 + (size_t) count * charsz;
}

// Long name inside a 0xBEEF0004 extension block (ext = start of the block).
// Its offset depends on the block version: v9 0x2E, v8 0x2A, v7 0x26, v3 0x14.
static void beef0004_name(
    const uint8_t* d,
    size_t ext,
    size_t to,
    char* out,
    size_t out_sz)
{
  out[0] = '\0';
  uint16_t ver = rd16(d, to, ext + 2);
  size_t off = ver >= 9 ? 0x2E : ver >= 8 ? 0x2A : ver >= 7 ? 0x26 : ver >= 3 ? 0x14 : 0;
  if (off == 0 || ext + off + 2 > to)
    return;
  cpy_utf16(d, to, ext + off, (size_t) -1, out, out_sz);
}

// Shell-item names must be printable; anything else means we misparsed.
static int printable(const char* s)
{
  for (const unsigned char* p = (const unsigned char*) s; *p; p++)
    if (*p < 0x20)
      return 0;
  return s[0] != '\0';
}

// Rebuild a path from the LinkTargetIDList: volume item ("C:\") + file-entry
// items (long name from the 0xBEEF0004 extension, else the 8.3 primary name).
// Used when the LNK carries neither LinkInfo nor RelativePath.
static void idlist_path(
    const uint8_t* d,
    size_t start,
    size_t end,
    char* out,
    size_t out_sz)
{
  static const uint8_t ext_sig[4] = {0x04, 0x00, 0xEF, 0xBE};
  size_t j = 0;
  out[0] = '\0';

  for (int items = 0; start + 2 <= end && items < 64; items++)
  {
    size_t isz = rd16(d, end, start);
    if (isz < 3 || start + isz > end)
      break;
    uint8_t type = d[start + 2];
    char name[256] = "";

    if ((type & 0x70) == 0x20 && isz >= 6 && d[start + 4] == ':' &&
        ((d[start + 3] | 0x20) >= 'a' && (d[start + 3] | 0x20) <= 'z'))  // volume: "C:\"
    {
      cpy_ansi(d, start + isz, start + 3, name, sizeof(name));
      j = 0;
      out[0] = '\0';
    }
    else if ((type & 0x70) == 0x30 && isz > 14)  // file entry (dir / file)
    {
      const uint8_t* sig = docscan_memmem(d + start + 14, isz - 14, ext_sig, 4);
      if (sig != NULL && (size_t) (sig - d) >= start + 4)
        beef0004_name(d, (size_t) (sig - d) - 4, start + isz, name, sizeof(name));
      if (!printable(name))
      {
        if (type & 0x04)
          cpy_utf16(d, start + isz, start + 14, (size_t) -1, name, sizeof(name));
        else
          cpy_ansi(d, start + isz, start + 14, name, sizeof(name));
      }
      if (!printable(name))
        name[0] = '\0';
    }

    if (name[0] != '\0')
    {
      if (j > 0 && out[j - 1] != '\\' && j + 1 < out_sz)
        out[j++] = '\\';
      for (const char* c = name; *c && j + 1 < out_sz; c++)
        out[j++] = *c;
      out[j] = '\0';
    }
    start += isz;
  }
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

  size_t idStart = 0, idEnd = 0;
  if (hasIDList)
  {
    idStart = pos + 2;
    idEnd = idStart + rd16(d, n, pos);  // IDListSize
    if (idEnd > n)
      idEnd = n;
    pos = idStart + rd16(d, n, pos);
  }

  char target[512] = "";
  if (hasLinkInfo && pos + 28 <= n)
  {
    uint32_t liSize = rd32(d, n, pos);
    uint32_t liHdr = rd32(d, n, pos + 4);     // LinkInfoHeaderSize
    uint32_t lbpOff = rd32(d, n, pos + 16);   // LocalBasePathOffset
    uint32_t cnrlOff = rd32(d, n, pos + 20);  // CommonNetworkRelativeLinkOffset
    uint32_t sufOff = rd32(d, n, pos + 24);   // CommonPathSuffixOffset

    // Unicode local path (header >= 0x24) keeps Cyrillic; else the ANSI one.
    if (liHdr >= 0x24 && pos + 32 <= n && rd32(d, n, pos + 28) != 0)
      cpy_utf16(d, n, pos + rd32(d, n, pos + 28), (size_t) -1, target, sizeof(target));
    if (target[0] == '\0' && lbpOff != 0)
      cpy_ansi(d, n, pos + lbpOff, target, sizeof(target));

    // Target on a network share: \\host\share + CommonPathSuffix.
    if (target[0] == '\0' && cnrlOff != 0 && pos + cnrlOff + 12 <= n)
    {
      size_t cnrl = pos + cnrlOff;
      char net[256] = "", suf[256] = "";
      uint32_t netNameOff = rd32(d, n, cnrl + 8);
      if (netNameOff != 0)
        cpy_ansi(d, n, cnrl + netNameOff, net, sizeof(net));
      if (sufOff != 0)
        cpy_ansi(d, n, pos + sufOff, suf, sizeof(suf));
      snprintf(target, sizeof(target), "%s%s%s", net,
               (suf[0] && net[0] && net[strlen(net) - 1] != '\\') ? "\\" : "", suf);
    }
    pos += liSize;
  }

  char args[512] = "";
  if (hasName)
    pos += cpy_stringdata(d, n, pos, isUnicode, NULL, 0);
  char relpath[512] = "";
  if (hasRelPath)
    pos += cpy_stringdata(d, n, pos, isUnicode, relpath, sizeof(relpath));
  if (hasWorkDir)
    pos += cpy_stringdata(d, n, pos, isUnicode, NULL, 0);
  if (hasArgs)
    pos += cpy_stringdata(d, n, pos, isUnicode, args, sizeof(args));

  // No LinkInfo path (crafted LNKs often carry only a RelativePath).
  if (target[0] == '\0')
    snprintf(target, sizeof(target), "%s", relpath);
  if (target[0] == '\0' && idEnd > idStart)
    idlist_path(d, idStart, idEnd, target, sizeof(target));

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
