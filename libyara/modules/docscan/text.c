/* DocScan: full-text extraction for the critical-information mode.
   See <yara/docscan_critical.h>.

   docx/xlsx/pptx and odt/ods/odp: zip (miniz via zip.c) + a small XML text
   walker; doc/xls/ppt: CFB streams (cfb.c) - Word piece table, Excel SST,
   PowerPoint text atoms; rtf: control-word parser; txt/csv: BOM / UTF-8 /
   Windows-1251. Document properties: docProps/core.xml, ODF meta.xml, OLE
   SummaryInformation.

   Every input byte is untrusted: all reads are bounds-checked, loops are
   capped, the output is capped at DOCSCAN_TEXT_MAX. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yara/docscan_critical.h>

#include "cfb.h"
#include "dynbuf.h"
#include "magic.h"
#include "zip.h"

#define MAX_STREAM (64u * 1024 * 1024)

// ---------------------------------------------------------------- output --

typedef struct
{
  docscan_buf b;
  int full;  // reached DOCSCAN_TEXT_MAX: ignore the rest
  int oom;
} tout;

static void put_bytes(tout* o, const char* s, size_t n)
{
  if (o->full || o->oom)
    return;
  if (o->b.len + n > DOCSCAN_TEXT_MAX)
  {
    o->full = 1;
    return;
  }
  if (docscan_buf_push(&o->b, (const uint8_t*) s, n))
    o->oom = 1;
}

static void put_cp(tout* o, uint32_t c)
{
  char u[4];
  if (c == 0)
    return;
  if (c > 0x10FFFF || (c >= 0xD800 && c <= 0xDFFF))
    c = 0xFFFD;
  if (c < 0x80)
  {
    u[0] = (char) c;
    put_bytes(o, u, 1);
  }
  else if (c < 0x800)
  {
    u[0] = (char) (0xC0 | (c >> 6));
    u[1] = (char) (0x80 | (c & 0x3F));
    put_bytes(o, u, 2);
  }
  else if (c < 0x10000)
  {
    u[0] = (char) (0xE0 | (c >> 12));
    u[1] = (char) (0x80 | ((c >> 6) & 0x3F));
    u[2] = (char) (0x80 | (c & 0x3F));
    put_bytes(o, u, 3);
  }
  else
  {
    u[0] = (char) (0xF0 | (c >> 18));
    u[1] = (char) (0x80 | ((c >> 12) & 0x3F));
    u[2] = (char) (0x80 | ((c >> 6) & 0x3F));
    u[3] = (char) (0x80 | (c & 0x3F));
    put_bytes(o, u, 4);
  }
}

static void put_nl(tout* o)
{
  put_bytes(o, "\n", 1);
}

// UTF-16LE code units -> output (surrogate pairs joined). `filter` maps the
// legacy Office control characters (Word / PowerPoint) when not NULL.
typedef int (*cp_filter)(uint32_t c, void* st, tout* o);

static void put_utf16le(
    tout* o,
    const uint8_t* p,
    size_t nunits,
    cp_filter f,
    void* st)
{
  for (size_t i = 0; i < nunits && !o->full; i++)
  {
    uint32_t c = (uint32_t) p[2 * i] | ((uint32_t) p[2 * i + 1] << 8);
    if (c >= 0xD800 && c <= 0xDBFF && i + 1 < nunits)
    {
      uint32_t d = (uint32_t) p[2 * i + 2] | ((uint32_t) p[2 * i + 3] << 8);
      if (d >= 0xDC00 && d <= 0xDFFF)
      {
        c = 0x10000 + ((c - 0xD800) << 10) + (d - 0xDC00);
        i++;
      }
    }
    if (f == NULL || f(c, st, o))
      put_cp(o, c);
  }
}

// ------------------------------------------------------------ code pages --

static const uint16_t cp1251_hi[128] = {
    0x0402, 0x0403, 0x201A, 0x0453, 0x201E, 0x2026, 0x2020, 0x2021, 0x20AC,
    0x2030, 0x0409, 0x2039, 0x040A, 0x040C, 0x040B, 0x040F, 0x0452, 0x2018,
    0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014, 0xFFFD, 0x2122, 0x0459,
    0x203A, 0x045A, 0x045C, 0x045B, 0x045F, 0x00A0, 0x040E, 0x045E, 0x0408,
    0x00A4, 0x0490, 0x00A6, 0x00A7, 0x0401, 0x00A9, 0x0404, 0x00AB, 0x00AC,
    0x00AD, 0x00AE, 0x0407, 0x00B0, 0x00B1, 0x0406, 0x0456, 0x0491, 0x00B5,
    0x00B6, 0x00B7, 0x0451, 0x2116, 0x0454, 0x00BB, 0x0458, 0x0405, 0x0455,
    0x0457, 0x0410, 0x0411, 0x0412, 0x0413, 0x0414, 0x0415, 0x0416, 0x0417,
    0x0418, 0x0419, 0x041A, 0x041B, 0x041C, 0x041D, 0x041E, 0x041F, 0x0420,
    0x0421, 0x0422, 0x0423, 0x0424, 0x0425, 0x0426, 0x0427, 0x0428, 0x0429,
    0x042A, 0x042B, 0x042C, 0x042D, 0x042E, 0x042F, 0x0430, 0x0431, 0x0432,
    0x0433, 0x0434, 0x0435, 0x0436, 0x0437, 0x0438, 0x0439, 0x043A, 0x043B,
    0x043C, 0x043D, 0x043E, 0x043F, 0x0440, 0x0441, 0x0442, 0x0443, 0x0444,
    0x0445, 0x0446, 0x0447, 0x0448, 0x0449, 0x044A, 0x044B, 0x044C, 0x044D,
    0x044E, 0x044F};

static const uint16_t cp1252_80[32] = {
    0x20AC, 0xFFFD, 0x201A, 0x0192, 0x201E, 0x2026, 0x2020, 0x2021,
    0x02C6, 0x2030, 0x0160, 0x2039, 0x0152, 0xFFFD, 0x017D, 0xFFFD,
    0xFFFD, 0x2018, 0x2019, 0x201C, 0x201D, 0x2022, 0x2013, 0x2014,
    0x02DC, 0x2122, 0x0161, 0x203A, 0x0153, 0xFFFD, 0x017E, 0x0178};

// Single byte -> code point in Windows-1251 (cp=1251) or Windows-1252.
static uint32_t cp_byte(uint8_t b, int cp)
{
  if (b < 0x80)
    return b;
  if (cp == 1251)
    return cp1251_hi[b - 0x80];
  if (b < 0xA0)
    return cp1252_80[b - 0x80];
  return b;  // Latin-1 range
}

// ----------------------------------------------------------- UTF-8 check --

// Length of a valid UTF-8 sequence at p (1..4), or 0 if invalid.
static int utf8_seq(const uint8_t* p, size_t n, uint32_t* cp)
{
  uint8_t c = p[0];
  if (c < 0x80)
  {
    *cp = c;
    return 1;
  }
  int len;
  uint32_t v, min;
  if ((c & 0xE0) == 0xC0)
  {
    len = 2;
    v = c & 0x1F;
    min = 0x80;
  }
  else if ((c & 0xF0) == 0xE0)
  {
    len = 3;
    v = c & 0x0F;
    min = 0x800;
  }
  else if ((c & 0xF8) == 0xF0)
  {
    len = 4;
    v = c & 0x07;
    min = 0x10000;
  }
  else
    return 0;
  if ((size_t) len > n)
    return 0;
  for (int i = 1; i < len; i++)
  {
    if ((p[i] & 0xC0) != 0x80)
      return 0;
    v = (v << 6) | (p[i] & 0x3F);
  }
  if (v < min || v > 0x10FFFF || (v >= 0xD800 && v <= 0xDFFF))
    return 0;
  *cp = v;
  return len;
}

static int is_valid_utf8(const uint8_t* p, size_t n)
{
  size_t i = 0;
  uint32_t c;
  while (i < n)
  {
    int l = utf8_seq(p + i, n - i, &c);
    if (l == 0)
      return 0;
    i += (size_t) l;
  }
  return 1;
}

// Python str.isspace() for the code points we care about.
static int py_space(uint32_t c)
{
  return (c >= 0x09 && c <= 0x0D) || (c >= 0x1C && c <= 0x20) || c == 0x85 ||
         c == 0xA0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200A) ||
         c == 0x2028 || c == 0x2029 || c == 0x202F || c == 0x205F ||
         c == 0x3000;
}

// The single form of the text: valid UTF-8 (bad bytes -> U+FFFD), no NUL,
// \r\n and \r -> \n, stripped (Python strip()). In place in t->text.
static int finalize(docscan_text_t* t, docscan_buf* raw)
{
  tout o = {{0}, 0, 0};
  const uint8_t* p = raw->p;
  size_t n = raw->len, i = 0;
  while (i < n)
  {
    uint32_t c;
    int l = utf8_seq(p + i, n - i, &c);
    if (l == 0)
    {
      put_cp(&o, 0xFFFD);
      i++;
      continue;
    }
    i += (size_t) l;
    if (c == '\r')
    {
      if (i < n && p[i] == '\n')
        continue;  // \r\n -> the \n follows
      c = '\n';
    }
    put_cp(&o, c);  // drops NUL
  }
  if (o.oom)
  {
    docscan_buf_free(&o.b);
    return DOCSCAN_TEXT_NOMEM;
  }

  // strip: leading / trailing Python whitespace
  size_t s = 0, e = o.b.len;
  while (s < e)
  {
    uint32_t c;
    int l = utf8_seq(o.b.p + s, e - s, &c);
    if (l == 0 || !py_space(c))
      break;
    s += (size_t) l;
  }
  while (e > s)
  {
    size_t k = e - 1;
    while (k > s && (o.b.p[k] & 0xC0) == 0x80) k--;
    uint32_t c;
    int l = utf8_seq(o.b.p + k, e - k, &c);
    if (l == 0 || !py_space(c))
      break;
    e = k;
  }
  if (e == s)
  {
    docscan_buf_free(&o.b);
    return DOCSCAN_TEXT_EMPTY;
  }
  t->text = (char*) malloc(e - s + 1);
  if (t->text == NULL)
  {
    docscan_buf_free(&o.b);
    return DOCSCAN_TEXT_NOMEM;
  }
  memcpy(t->text, o.b.p + s, e - s);
  t->text[e - s] = '\0';
  t->len = e - s;
  docscan_buf_free(&o.b);
  return DOCSCAN_TEXT_OK;
}

// --------------------------------------------------------------- helpers --

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

static void copy_meta(char* dst, size_t dsz, const char* src, size_t n)
{
  // trim spaces, keep at most dsz-1 bytes, never cut a UTF-8 sequence
  while (n && (*src == ' ' || *src == '\t' || *src == '\n' || *src == '\r'))
  {
    src++;
    n--;
  }
  while (n && (src[n - 1] == ' ' || src[n - 1] == '\t' || src[n - 1] == '\n' ||
               src[n - 1] == '\r'))
    n--;
  if (n >= dsz)
  {
    n = dsz - 1;
    while (n && ((uint8_t) src[n] & 0xC0) == 0x80) n--;
  }
  for (size_t i = 0; i < n; i++)
    dst[i] = (src[i] == '\0' || src[i] == '\n' || src[i] == '\r' || src[i] == '\t') ? ' ' : src[i];
  dst[n] = '\0';
}

// days since 1970-01-01 -> civil date (Howard Hinnant's algorithm)
static void civil(int64_t z, int* y, int* m, int* d)
{
  z += 719468;
  int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  int64_t doe = z - era * 146097;
  int64_t yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  int64_t yy = yoe + era * 400;
  int64_t doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  int64_t mp = (5 * doy + 2) / 153;
  *d = (int) (doy - (153 * mp + 2) / 5 + 1);
  *m = (int) (mp < 10 ? mp + 3 : mp - 9);
  *y = (int) (yy + (*m <= 2));
}

// Windows FILETIME (100 ns since 1601) -> "YYYY-MM-DDTHH:MM:SSZ"
static void filetime_iso(uint64_t ft, char* out, size_t osz)
{
  out[0] = '\0';
  if (ft == 0)
    return;
  int64_t secs = (int64_t) (ft / 10000000ULL) - 11644473600LL;
  if (secs < 0 || secs > 32503680000LL)  // before 1970 / after 3000: junk
    return;
  int y, m, d;
  civil(secs / 86400, &y, &m, &d);
  int64_t r = secs % 86400;
  snprintf(out, osz, "%04d-%02d-%02dT%02d:%02d:%02dZ", y, m, d, (int) (r / 3600),
           (int) (r / 60 % 60), (int) (r % 60));
}

// ------------------------------------------------------------ XML walker --

// What to take from one XML part. Tag names are compared WITHOUT the
// namespace prefix (w:t, a:t and t are all "t").
typedef struct
{
  const char* const* text;   // collect character data inside these; NULL = inside `para`
  const char* const* para;   // '\n' after the element
  const char* const* tab;    // '\t'
  const char* const* br;     // '\n'
  const char* const* skip;   // ignore everything inside
  int odf_space;             // ODF <text:s text:c="N"/> -> N spaces
  int collapse;              // ODF: runs of XML whitespace in text -> one space
} xml_profile;

static int name_in(const char* name, size_t nl, const char* const* list)
{
  if (list == NULL)
    return 0;
  for (; *list; list++)
    if (strlen(*list) == nl && memcmp(*list, name, nl) == 0)
      return 1;
  return 0;
}

// &lt; &gt; &amp; &quot; &apos; &#N; &#xH; -> code point; returns bytes used
static size_t xml_entity(const uint8_t* p, size_t n, uint32_t* cp)
{
  size_t e = 1;
  while (e < n && e < 12 && p[e] != ';') e++;
  if (e >= n || p[e] != ';')
    return 0;
  const char* s = (const char*) p + 1;
  size_t l = e - 1;
  if (l == 2 && memcmp(s, "lt", 2) == 0)
    *cp = '<';
  else if (l == 2 && memcmp(s, "gt", 2) == 0)
    *cp = '>';
  else if (l == 3 && memcmp(s, "amp", 3) == 0)
    *cp = '&';
  else if (l == 4 && memcmp(s, "quot", 4) == 0)
    *cp = '"';
  else if (l == 4 && memcmp(s, "apos", 4) == 0)
    *cp = '\'';
  else if (l >= 2 && s[0] == '#')
  {
    uint32_t v = 0;
    size_t k = 1;
    int hex = (s[1] == 'x' || s[1] == 'X');
    if (hex)
      k = 2;
    if (k >= l)
      return 0;
    for (; k < l; k++)
    {
      char ch = s[k];
      int dgt;
      if (ch >= '0' && ch <= '9')
        dgt = ch - '0';
      else if (hex && ch >= 'a' && ch <= 'f')
        dgt = ch - 'a' + 10;
      else if (hex && ch >= 'A' && ch <= 'F')
        dgt = ch - 'A' + 10;
      else
        return 0;
      v = v * (hex ? 16 : 10) + (uint32_t) dgt;
      if (v > 0x10FFFF)
        return 0;
    }
    *cp = v;
  }
  else
    return 0;
  return e + 1;
}

static void xml_chars(tout* o, const uint8_t* p, size_t n, int collapse, int* last_space)
{
  size_t i = 0;
  while (i < n && !o->full)
  {
    uint32_t c;
    size_t used = 1;
    if (p[i] == '&' && (used = xml_entity(p + i, n - i, &c)) != 0)
    {
    }
    else
    {
      int l = utf8_seq(p + i, n - i, &c);
      if (l == 0)
      {
        c = 0xFFFD;
        l = 1;
      }
      used = (size_t) l;
    }
    i += used;
    if (collapse && (c == ' ' || c == '\t' || c == '\n' || c == '\r'))
    {
      if (!*last_space)
        put_cp(o, ' ');
      *last_space = 1;
      continue;
    }
    *last_space = 0;
    put_cp(o, c);
  }
}

// ODF text:c="N" attribute of <text:s>
static int odf_count(const uint8_t* a, size_t n)
{
  for (size_t i = 0; i + 3 < n; i++)
  {
    if ((i == 0 || a[i - 1] == ' ' || a[i - 1] == ':') && a[i] == 'c' &&
        a[i + 1] == '=' && (a[i + 2] == '"' || a[i + 2] == '\''))
    {
      int v = 0;
      for (size_t k = i + 3; k < n && a[k] >= '0' && a[k] <= '9'; k++)
      {
        v = v * 10 + (a[k] - '0');
        if (v > 1000)
          return 1000;
      }
      return v > 0 ? v : 1;
    }
  }
  return 1;
}

static void xml_text(tout* o, const uint8_t* x, size_t n, const xml_profile* pr)
{
  size_t i = 0;
  int text_depth = 0, para_depth = 0, skip_depth = 0, last_space = 0;

  while (i < n && !o->full)
  {
    if (x[i] != '<')
    {
      size_t j = i;
      while (j < n && x[j] != '<') j++;
      int collect = skip_depth == 0 &&
                    (pr->text ? text_depth > 0 : para_depth > 0);
      if (collect)
        xml_chars(o, x + i, j - i, pr->collapse, &last_space);
      i = j;
      continue;
    }
    // markup
    if (i + 4 <= n && memcmp(x + i, "<!--", 4) == 0)
    {
      const uint8_t* e = NULL;
      for (size_t k = i + 4; k + 3 <= n; k++)
        if (x[k] == '-' && x[k + 1] == '-' && x[k + 2] == '>')
        {
          e = x + k;
          break;
        }
      i = e ? (size_t) (e - x) + 3 : n;
      continue;
    }
    if (i + 9 <= n && memcmp(x + i, "<![CDATA[", 9) == 0)
    {
      size_t k = i + 9, end = n;
      for (; k + 3 <= n; k++)
        if (x[k] == ']' && x[k + 1] == ']' && x[k + 2] == '>')
        {
          end = k;
          break;
        }
      int collect = skip_depth == 0 &&
                    (pr->text ? text_depth > 0 : para_depth > 0);
      if (collect)
      {
        // CDATA is literal: no entities
        for (size_t q = i + 9; q < end && !o->full;)
        {
          uint32_t c;
          int l = utf8_seq(x + q, end - q, &c);
          if (l == 0)
          {
            c = 0xFFFD;
            l = 1;
          }
          put_cp(o, c);
          q += (size_t) l;
        }
      }
      i = end + 3;
      continue;
    }
    // find the end of the tag, honouring quoted attribute values
    size_t k = i + 1;
    uint8_t q = 0;
    for (; k < n; k++)
    {
      if (q)
      {
        if (x[k] == q)
          q = 0;
      }
      else if (x[k] == '"' || x[k] == '\'')
        q = x[k];
      else if (x[k] == '>')
        break;
    }
    if (k >= n)
      break;
    size_t tag_end = k;  // index of '>'
    if (x[i + 1] == '?' || x[i + 1] == '!')
    {
      i = tag_end + 1;
      continue;
    }
    int closing = x[i + 1] == '/';
    size_t ns = i + 1 + (closing ? 1 : 0), ne = ns;
    while (ne < tag_end && x[ne] != ' ' && x[ne] != '\t' && x[ne] != '\n' &&
           x[ne] != '\r' && x[ne] != '/' && x[ne] != '>')
      ne++;
    int selfclose = !closing && tag_end > i && x[tag_end - 1] == '/';
    // local name (after the prefix)
    const char* name = (const char*) x + ns;
    size_t nl = ne - ns;
    for (size_t c = ns; c < ne; c++)
      if (x[c] == ':')
      {
        name = (const char*) x + c + 1;
        nl = ne - c - 1;
      }

    if (name_in(name, nl, pr->skip))
    {
      if (closing)
      {
        if (skip_depth > 0)
          skip_depth--;
      }
      else if (!selfclose)
        skip_depth++;
    }
    else if (skip_depth == 0)
    {
      if (!closing)
      {
        if (pr->text && name_in(name, nl, pr->text) && !selfclose)
          text_depth++;
        if (name_in(name, nl, pr->para))
        {
          if (selfclose)
            put_nl(o);
          else
            para_depth++;
          last_space = 0;
        }
        if (name_in(name, nl, pr->tab))
          put_bytes(o, "\t", 1);
        if (name_in(name, nl, pr->br))
          put_nl(o);
        if (pr->odf_space && nl == 1 && name[0] == 's')
        {
          int cnt = odf_count(x + ne, tag_end - ne);
          for (int s = 0; s < cnt; s++) put_bytes(o, " ", 1);
        }
      }
      else
      {
        if (pr->text && name_in(name, nl, pr->text) && text_depth > 0)
          text_depth--;
        if (name_in(name, nl, pr->para))
        {
          if (para_depth > 0)
            para_depth--;
          put_nl(o);
          last_space = 0;
        }
      }
    }
    i = tag_end + 1;
  }
}

// text of the first element with this local name (for docProps/core.xml, meta.xml)
static void xml_first(const uint8_t* x, size_t n, const char* local, char* out, size_t osz)
{
  size_t ll = strlen(local);
  out[0] = '\0';
  for (size_t i = 0; i + 1 < n; i++)
  {
    if (x[i] != '<' || x[i + 1] == '/' || x[i + 1] == '?' || x[i + 1] == '!')
      continue;
    size_t ns = i + 1, ne = ns;
    while (ne < n && x[ne] != ' ' && x[ne] != '>' && x[ne] != '/' && x[ne] != '\t' &&
           x[ne] != '\n' && x[ne] != '\r')
      ne++;
    const char* name = (const char*) x + ns;
    size_t nl = ne - ns;
    for (size_t c = ns; c < ne; c++)
      if (x[c] == ':')
      {
        name = (const char*) x + c + 1;
        nl = ne - c - 1;
      }
    if (nl != ll || memcmp(name, local, ll) != 0)
      continue;
    size_t gt = ne;
    while (gt < n && x[gt] != '>') gt++;
    if (gt >= n || x[gt - 1] == '/')
      return;
    size_t s = gt + 1, e = s;
    while (e < n && x[e] != '<') e++;
    tout o = {{0}, 0, 0};
    int ls = 0;
    xml_chars(&o, x + s, e - s, 0, &ls);
    if (o.b.p != NULL)
      copy_meta(out, osz, (const char*) o.b.p, o.b.len);
    docscan_buf_free(&o.b);
    return;
  }
}

// ISO date from XML: keep "YYYY-MM-DDTHH:MM:SS", drop fractions, end with Z
static void iso_date(const char* in, char* out, size_t osz)
{
  out[0] = '\0';
  size_t l = strlen(in);
  if (l < 10 || in[4] != '-' || in[7] != '-')
    return;
  char tmp[32];
  size_t k = 0;
  for (size_t i = 0; i < l && k < 19; i++)
  {
    if (in[i] == '.' || in[i] == 'Z' || in[i] == '+' ||
        (in[i] == '-' && i > 10))
      break;
    tmp[k++] = in[i];
  }
  tmp[k] = '\0';
  if (k == 10)
    snprintf(out, osz, "%sT00:00:00Z", tmp);
  else if (k >= 16)
    snprintf(out, osz, "%s%sZ", tmp, k == 16 ? ":00" : "");
}

// ------------------------------------------------------------------- zip --

typedef struct
{
  int idx;
  long num;
  char name[128];
} zent;

static int zent_cmp(const void* a, const void* b)
{
  const zent* x = (const zent*) a;
  const zent* y = (const zent*) b;
  if (x->num != y->num)
    return x->num < y->num ? -1 : 1;
  return strcmp(x->name, y->name);
}

// entries named <prefix><digits?><suffix>, sorted by the number
static int zip_list(docscan_zip* z, const char* prefix, const char* suffix, zent* out, int max)
{
  int cnt = 0, total = docscan_zip_count(z);
  size_t pl = strlen(prefix), sl = strlen(suffix);
  for (int i = 0; i < total && cnt < max; i++)
  {
    char nm[256];
    if (docscan_zip_entry_name(z, i, nm, sizeof(nm)))
      continue;
    size_t l = strlen(nm);
    if (l < pl + sl || strncmp(nm, prefix, pl) != 0 || strcmp(nm + l - sl, suffix) != 0)
      continue;
    long num = 0;
    size_t k = pl;
    for (; k < l - sl; k++)
    {
      if (nm[k] < '0' || nm[k] > '9')
        break;
      if (num < 100000000)
        num = num * 10 + (nm[k] - '0');
    }
    if (k != l - sl)
      continue;  // something else between the prefix and the suffix
    out[cnt].idx = i;
    out[cnt].num = num;
    snprintf(out[cnt].name, sizeof(out[cnt].name), "%s", nm);
    cnt++;
  }
  qsort(out, (size_t) cnt, sizeof(zent), zent_cmp);
  return cnt;
}

static int zip_find(docscan_zip* z, const char* name)
{
  int total = docscan_zip_count(z);
  for (int i = 0; i < total; i++)
  {
    char nm[256];
    if (docscan_zip_entry_name(z, i, nm, sizeof(nm)) == 0 && strcmp(nm, name) == 0)
      return i;
  }
  return -1;
}

static void zip_part(tout* o, docscan_zip* z, int idx, const xml_profile* pr)
{
  size_t n = 0;
  uint8_t* x = idx >= 0 ? docscan_zip_extract(z, idx, &n) : NULL;
  if (x == NULL)
    return;
  xml_text(o, x, n, pr);
  if (o->b.len && o->b.p[o->b.len - 1] != '\n')
    put_nl(o);  // parts are separated, without an empty line
  docscan_zip_free(x);
}

static void zip_parts(tout* o, docscan_zip* z, const char* prefix, const char* suffix, const xml_profile* pr)
{
  zent* e = (zent*) malloc(sizeof(zent) * 2048);
  if (e == NULL)
  {
    o->oom = 1;
    return;
  }
  int cnt = zip_list(z, prefix, suffix, e, 2048);
  for (int i = 0; i < cnt && !o->full; i++) zip_part(o, z, e[i].idx, pr);
  free(e);
}

static const char* const T_TEXT[] = {"t", NULL};
static const char* const T_PARA_W[] = {"p", NULL};
static const char* const T_TAB[] = {"tab", NULL};
static const char* const T_BR_W[] = {"br", "cr", NULL};
// mc:Fallback repeats the text of mc:Choice; w:tabs holds tab-stop <w:tab/>
// definitions; w:delText / instrText are not "t" anyway.
static const char* const T_SKIP_W[] = {"Fallback", "tabs", NULL};
static const char* const T_PARA_X[] = {"si", "is", NULL};
static const char* const T_SKIP_X[] = {"rPh", NULL};
static const char* const T_PARA_O[] = {"p", "h", NULL};
static const char* const T_TAB_O[] = {"tab", NULL};
static const char* const T_BR_O[] = {"line-break", NULL};
static const char* const T_SKIP_O[] = {"tracked-changes", NULL};

static const xml_profile P_WORD = {T_TEXT, T_PARA_W, T_TAB, T_BR_W, T_SKIP_W, 0, 0};
static const xml_profile P_XLSX = {T_TEXT, T_PARA_X, NULL, NULL, T_SKIP_X, 0, 0};
static const xml_profile P_PPTX = {T_TEXT, T_PARA_W, T_TAB, T_BR_W, T_SKIP_W, 0, 0};
static const xml_profile P_ODF = {NULL, T_PARA_O, T_TAB_O, T_BR_O, T_SKIP_O, 1, 1};

static void ooxml_core(docscan_zip* z, docscan_text_t* t)
{
  int i = zip_find(z, "docProps/core.xml");
  size_t n = 0;
  uint8_t* x = i >= 0 ? docscan_zip_extract(z, i, &n) : NULL;
  if (x == NULL)
    return;
  char tmp[64];
  xml_first(x, n, "creator", t->author, sizeof(t->author));
  xml_first(x, n, "lastModifiedBy", t->last_modified_by, sizeof(t->last_modified_by));
  xml_first(x, n, "title", t->title, sizeof(t->title));
  xml_first(x, n, "created", tmp, sizeof(tmp));
  iso_date(tmp, t->created_at, sizeof(t->created_at));
  xml_first(x, n, "modified", tmp, sizeof(tmp));
  iso_date(tmp, t->modified_at, sizeof(t->modified_at));
  docscan_zip_free(x);
}

static void odf_meta(docscan_zip* z, docscan_text_t* t)
{
  int i = zip_find(z, "meta.xml");
  size_t n = 0;
  uint8_t* x = i >= 0 ? docscan_zip_extract(z, i, &n) : NULL;
  if (x == NULL)
    return;
  char tmp[64];
  xml_first(x, n, "initial-creator", t->author, sizeof(t->author));
  xml_first(x, n, "creator", t->last_modified_by, sizeof(t->last_modified_by));
  xml_first(x, n, "title", t->title, sizeof(t->title));
  xml_first(x, n, "creation-date", tmp, sizeof(tmp));
  iso_date(tmp, t->created_at, sizeof(t->created_at));
  xml_first(x, n, "date", tmp, sizeof(tmp));
  iso_date(tmp, t->modified_at, sizeof(t->modified_at));
  docscan_zip_free(x);
}

static int extract_zip(const uint8_t* data, size_t size, docscan_text_t* t, tout* o)
{
  docscan_zip* z = docscan_zip_open(data, size);
  if (z == NULL)
    return DOCSCAN_TEXT_BROKEN;
  int rc = DOCSCAN_TEXT_OK;

  if (zip_find(z, "word/document.xml") >= 0)
  {
    snprintf(t->kind, sizeof(t->kind), "docx");
    zip_parts(o, z, "word/header", ".xml", &P_WORD);
    zip_part(o, z, zip_find(z, "word/document.xml"), &P_WORD);
    zip_part(o, z, zip_find(z, "word/footnotes.xml"), &P_WORD);
    zip_part(o, z, zip_find(z, "word/endnotes.xml"), &P_WORD);
    zip_parts(o, z, "word/footer", ".xml", &P_WORD);
    zip_part(o, z, zip_find(z, "word/comments.xml"), &P_WORD);
    ooxml_core(z, t);
  }
  else if (zip_find(z, "xl/workbook.xml") >= 0)
  {
    snprintf(t->kind, sizeof(t->kind), "xlsx");
    zip_part(o, z, zip_find(z, "xl/sharedStrings.xml"), &P_XLSX);
    zip_parts(o, z, "xl/worksheets/sheet", ".xml", &P_XLSX);  // inline strings
    ooxml_core(z, t);
  }
  else if (zip_find(z, "ppt/presentation.xml") >= 0)
  {
    snprintf(t->kind, sizeof(t->kind), "pptx");
    zip_parts(o, z, "ppt/slides/slide", ".xml", &P_PPTX);
    zip_parts(o, z, "ppt/notesSlides/notesSlide", ".xml", &P_PPTX);
    ooxml_core(z, t);
  }
  else if (zip_find(z, "content.xml") >= 0)
  {
    // OpenDocument: the type is in the "mimetype" entry
    const char* k = "odt";
    int mi = zip_find(z, "mimetype");
    size_t mn = 0;
    uint8_t* m = mi >= 0 ? docscan_zip_extract(z, mi, &mn) : NULL;
    if (m != NULL)
    {
      if (mn >= 11 && memcmp(m + mn - 11, "spreadsheet", 11) == 0)
        k = "ods";
      else if (mn >= 12 && memcmp(m + mn - 12, "presentation", 12) == 0)
        k = "odp";
      else if (!(mn >= 4 && memcmp(m + mn - 4, "text", 4) == 0))
        k = NULL;
      docscan_zip_free(m);
    }
    if (k == NULL)
      rc = DOCSCAN_TEXT_UNSUPPORTED;  // other ODF (drawing, formula, ...)
    else
    {
      snprintf(t->kind, sizeof(t->kind), "%s", k);
      zip_part(o, z, zip_find(z, "content.xml"), &P_ODF);
      odf_meta(z, t);
    }
  }
  else
    rc = DOCSCAN_TEXT_UNSUPPORTED;  // plain zip, xlsb, ...

  docscan_zip_close(z);
  return rc;
}

// ------------------------------------------------------------------- RTF --

static const char* const RTF_SKIP[] = {
    "fonttbl", "colortbl", "stylesheet", "info", "pict", "object", "objdata",
    "themedata", "colorschememapping", "latentstyles", "datastore", "xmlnstbl",
    "rsidtbl", "generator", "listtable", "listoverridetable", "revtbl",
    "filetbl", "mmathPr", "shppict", "nonshppict", "blipuid", "fldinst",
    "datafield", "docvar", "userprops", "protusertbl", "bkmkstart", "bkmkend",
    "pgdsctbl", "fchars", "lchars", "aftnsep", "ftnsep", "ftnsepc", "aftnsepc",
    "listtext", "pntext", "pntxta", "pntxtb", "wgrffmtfilter", "sp", "sv",
    "atnid", "atnauthor", "xe", "tc", "template", "passwordhash", NULL};

typedef struct
{
  uint8_t skip;
  uint8_t cap;  // 1 author, 2 operator, 3 title
  int uc;
} rtf_grp;

static int extract_rtf(const uint8_t* d, size_t n, docscan_text_t* t, tout* o)
{
  rtf_grp st[256];
  int sp = 0;
  st[0].skip = 0;
  st[0].cap = 0;
  st[0].uc = 1;
  int cp = 0, saw204 = 0, pending = 0;
  uint32_t hi = 0;  // first half of a surrogate pair from \u
  tout capb[4] = {{{0}, 0, 0}, {{0}, 0, 0}, {{0}, 0, 0}, {{0}, 0, 0}};
  size_t i = 0;
  snprintf(t->kind, sizeof(t->kind), "rtf");

#define RTF_EMIT(c)                                     \
  do                                                    \
  {                                                     \
    if (st[sp].cap)                                     \
      put_cp(&capb[st[sp].cap], (c));                   \
    else if (!st[sp].skip)                              \
      put_cp(o, (c));                                   \
  } while (0)

  while (i < n && !o->full)
  {
    uint8_t c = d[i];
    if (c == '{')
    {
      if (sp < 255)
      {
        st[sp + 1] = st[sp];
        sp++;
      }
      else
        st[sp].skip = 1;  // absurd nesting: drop the rest of it
      i++;
      continue;
    }
    if (c == '}')
    {
      if (sp > 0)
        sp--;
      pending = 0;
      i++;
      continue;
    }
    if (c == '\r' || c == '\n')
    {
      i++;
      continue;
    }
    if (c != '\\')
    {
      i++;
      if (pending > 0)
      {
        pending--;
        continue;
      }
      RTF_EMIT(cp_byte(c, (cp == 1251 || (cp == 0 && saw204)) ? 1251 : 1252));
      continue;
    }
    // control
    if (i + 1 >= n)
      break;
    uint8_t c1 = d[i + 1];
    if (c1 == '\\' || c1 == '{' || c1 == '}')
    {
      i += 2;
      if (pending > 0)
      {
        pending--;
        continue;
      }
      RTF_EMIT(c1);
      continue;
    }
    if (c1 == '\'')
    {
      uint32_t v = 0;
      int ok = i + 3 < n;
      for (int k = 2; ok && k < 4; k++)
      {
        uint8_t h = d[i + k];
        v <<= 4;
        if (h >= '0' && h <= '9')
          v |= h - '0';
        else if (h >= 'a' && h <= 'f')
          v |= h - 'a' + 10;
        else if (h >= 'A' && h <= 'F')
          v |= h - 'A' + 10;
        else
          ok = 0;
      }
      i += ok ? 4 : 2;
      if (!ok)
        continue;
      if (pending > 0)
      {
        pending--;
        continue;
      }
      RTF_EMIT(cp_byte((uint8_t) v, (cp == 1251 || (cp == 0 && saw204)) ? 1251 : 1252));
      continue;
    }
    if (c1 == '*')
    {
      st[sp].skip = 1;  // ignorable destination
      i += 2;
      continue;
    }
    if (c1 == '~')
    {
      i += 2;
      RTF_EMIT(0xA0);
      continue;
    }
    if (c1 == '_')
    {
      i += 2;
      RTF_EMIT('-');
      continue;
    }
    if (c1 == '-' || c1 == ':' || c1 == '|')
    {
      i += 2;
      continue;
    }
    if (c1 == '\r' || c1 == '\n')
    {
      i += 2;
      RTF_EMIT('\n');
      continue;
    }
    if (!((c1 >= 'a' && c1 <= 'z') || (c1 >= 'A' && c1 <= 'Z')))
    {
      i += 2;
      continue;
    }
    // control word
    size_t ws = i + 1, we = ws;
    while (we < n && we - ws < 32 &&
           ((d[we] >= 'a' && d[we] <= 'z') || (d[we] >= 'A' && d[we] <= 'Z')))
      we++;
    char word[33];
    size_t wl = we - ws;
    memcpy(word, d + ws, wl);
    word[wl] = '\0';
    long param = 0;
    int has_param = 0, neg = 0;
    size_t k = we;
    if (k < n && d[k] == '-')
    {
      neg = 1;
      k++;
    }
    while (k < n && d[k] >= '0' && d[k] <= '9' && k - we < 11)
    {
      param = param * 10 + (d[k] - '0');
      has_param = 1;
      k++;
    }
    if (neg)
      param = -param;
    if (!has_param && neg)
      k--;  // a lone '-' is not part of the word
    if (k < n && d[k] == ' ')
      k++;  // the delimiter space belongs to the control word
    i = k;

    if (strcmp(word, "bin") == 0)
    {
      if (has_param && param > 0)
        i = ((size_t) param > n - i) ? n : i + (size_t) param;
      continue;
    }
    if (strcmp(word, "ansicpg") == 0)
    {
      cp = (int) param;
      continue;
    }
    if (strcmp(word, "fcharset") == 0)
    {
      if (param == 204)
        saw204 = 1;
      continue;
    }
    if (strcmp(word, "uc") == 0)
    {
      st[sp].uc = (int) (param < 0 ? 0 : (param > 10 ? 10 : param));
      continue;
    }
    if (strcmp(word, "u") == 0)
    {
      long v = param < 0 ? param + 65536 : param;
      pending = st[sp].uc;
      // a surrogate pair comes as two \u words: join them
      if (v >= 0xD800 && v <= 0xDBFF)
      {
        hi = (uint32_t) v;
        continue;
      }
      if (v >= 0xDC00 && v <= 0xDFFF && hi)
      {
        RTF_EMIT(0x10000 + ((hi - 0xD800) << 10) + ((uint32_t) v - 0xDC00));
        hi = 0;
        continue;
      }
      hi = 0;
      RTF_EMIT((uint32_t) v);
      continue;
    }
    if (strcmp(word, "author") == 0)
    {
      st[sp].cap = 1;
      continue;
    }
    if (strcmp(word, "operator") == 0)
    {
      st[sp].cap = 2;
      continue;
    }
    if (strcmp(word, "title") == 0)
    {
      st[sp].cap = 3;
      continue;
    }
    if (name_in(word, wl, RTF_SKIP))
    {
      st[sp].skip = 1;
      continue;
    }
    if (st[sp].skip && !st[sp].cap)
      continue;
    if (!strcmp(word, "par") || !strcmp(word, "line") || !strcmp(word, "sect") ||
        !strcmp(word, "page") || !strcmp(word, "row"))
      RTF_EMIT('\n');
    else if (!strcmp(word, "cell") || !strcmp(word, "tab"))
      RTF_EMIT('\t');
    else if (!strcmp(word, "emdash"))
      RTF_EMIT(0x2014);
    else if (!strcmp(word, "endash"))
      RTF_EMIT(0x2013);
    else if (!strcmp(word, "lquote"))
      RTF_EMIT(0x2018);
    else if (!strcmp(word, "rquote"))
      RTF_EMIT(0x2019);
    else if (!strcmp(word, "ldblquote"))
      RTF_EMIT(0x201C);
    else if (!strcmp(word, "rdblquote"))
      RTF_EMIT(0x201D);
    else if (!strcmp(word, "bullet"))
      RTF_EMIT(0x2022);
  }
#undef RTF_EMIT

  if (capb[1].b.p)
    copy_meta(t->author, sizeof(t->author), (const char*) capb[1].b.p, capb[1].b.len);
  if (capb[2].b.p)
    copy_meta(t->last_modified_by, sizeof(t->last_modified_by), (const char*) capb[2].b.p, capb[2].b.len);
  if (capb[3].b.p)
    copy_meta(t->title, sizeof(t->title), (const char*) capb[3].b.p, capb[3].b.len);
  for (int q = 0; q < 4; q++) docscan_buf_free(&capb[q].b);
  return DOCSCAN_TEXT_OK;
}

// ------------------------------------------------ OLE SummaryInformation --

static void ole_string(const uint8_t* s, size_t n, size_t o, int cp, char* out, size_t osz)
{
  // VT_LPSTR: u32 byte count (incl. NUL) + bytes in the property-set code page
  uint32_t cnt = rd32(s, n, o);
  if (cnt == 0 || cnt > 4096 || o + 4 + cnt > n)
    return;
  tout b = {{0}, 0, 0};
  const uint8_t* p = s + o + 4;
  if (cp == 1200)
    put_utf16le(&b, p, cnt / 2, NULL, NULL);
  else if (cp == 65001)
    put_bytes(&b, (const char*) p, cnt);
  else
    for (uint32_t i = 0; i < cnt; i++) put_cp(&b, cp_byte(p[i], cp == 1251 ? 1251 : 1252));
  if (b.b.p)
  {
    size_t l = strnlen((const char*) b.b.p, b.b.len);
    copy_meta(out, osz, (const char*) b.b.p, l);
  }
  docscan_buf_free(&b.b);
}

static void ole_summary(const uint8_t* data, size_t size, docscan_text_t* t)
{
  size_t n = 0;
  uint8_t* s = docscan_cfb_get_stream(data, size, "\x05SummaryInformation", 1u << 20, &n);
  if (s == NULL)
    return;
  // header: byte order (2), version (2), OS (4), CLSID (16), sets (4), FMTID (16), offset (4)
  uint32_t off = rd32(s, n, 44);
  if (rd16(s, n, 0) != 0xFFFE || off < 48 || off + 8 > n)
  {
    free(s);
    return;
  }
  uint32_t cnt = rd32(s, n, off + 4);
  if (cnt > 256)
    cnt = 256;
  int cp = 1252;
  // pass 1: the code page (PID 1, VT_I2)
  for (uint32_t i = 0; i < cnt; i++)
  {
    uint32_t pid = rd32(s, n, off + 8 + i * 8);
    uint32_t po = off + rd32(s, n, off + 12 + i * 8);
    if (pid == 1 && rd16(s, n, po) == 2)
      cp = rd16(s, n, po + 4);
  }
  for (uint32_t i = 0; i < cnt; i++)
  {
    uint32_t pid = rd32(s, n, off + 8 + i * 8);
    size_t po = (size_t) off + rd32(s, n, off + 12 + i * 8);
    uint16_t vt = rd16(s, n, po);
    if (vt == 0x1E)  // VT_LPSTR
    {
      if (pid == 2)
        ole_string(s, n, po + 4, cp, t->title, sizeof(t->title));
      else if (pid == 4)
        ole_string(s, n, po + 4, cp, t->author, sizeof(t->author));
      else if (pid == 8)
        ole_string(s, n, po + 4, cp, t->last_modified_by, sizeof(t->last_modified_by));
    }
    else if (vt == 0x40 && po + 12 <= n)  // VT_FILETIME
    {
      uint64_t ft = (uint64_t) rd32(s, n, po + 4) | ((uint64_t) rd32(s, n, po + 8) << 32);
      if (pid == 12)
        filetime_iso(ft, t->created_at, sizeof(t->created_at));
      else if (pid == 13)
        filetime_iso(ft, t->modified_at, sizeof(t->modified_at));
    }
  }
  free(s);
}

// ------------------------------------------------------------- Word .doc --

typedef struct
{
  int field_depth;
  int in_instr[16];  // per field level: 1 while inside the instruction part
} word_state;

// Word special characters; returns 1 to output c as is.
static int word_filter(uint32_t c, void* stp, tout* o)
{
  word_state* st = (word_state*) stp;
  if (c == 0x13)  // field begin: instruction follows
  {
    if (st->field_depth < 15)
      st->field_depth++;
    st->in_instr[st->field_depth] = 1;
    return 0;
  }
  if (c == 0x14)  // field separator: result follows
  {
    st->in_instr[st->field_depth] = 0;
    return 0;
  }
  if (c == 0x15)  // field end
  {
    if (st->field_depth > 0)
      st->field_depth--;
    return 0;
  }
  for (int k = 1; k <= st->field_depth; k++)
    if (st->in_instr[k])
      return 0;
  if (c == 0x0D || c == 0x0B || c == 0x0C)
  {
    put_nl(o);
    return 0;
  }
  if (c == 0x07)
  {
    put_bytes(o, "\t", 1);
    return 0;
  }
  if (c == 0x1E)
  {
    put_bytes(o, "-", 1);
    return 0;
  }
  if (c < 0x20 && c != 0x09)
    return 0;  // pictures, footnote marks, optional hyphen (0x1F), ...
  return 1;
}

static int extract_doc(const uint8_t* data, size_t size, docscan_text_t* t, tout* o)
{
  size_t wn = 0, tn = 0;
  uint8_t* w = docscan_cfb_get_stream(data, size, "WordDocument", MAX_STREAM, &wn);
  if (w == NULL)
    return DOCSCAN_TEXT_BROKEN;
  snprintf(t->kind, sizeof(t->kind), "doc");
  int rc = DOCSCAN_TEXT_OK;
  uint16_t flags = rd16(w, wn, 0x0A);
  if (rd16(w, wn, 0) != 0xA5EC || wn < 0x1AA)
    rc = DOCSCAN_TEXT_BROKEN;
  else if (rd16(w, wn, 2) < 0xC1)
    rc = DOCSCAN_TEXT_UNSUPPORTED;  // Word 6/95 and older: no piece table here
  else if (flags & 0x0100)
    rc = DOCSCAN_TEXT_ENCRYPTED;
  if (rc != DOCSCAN_TEXT_OK)
  {
    free(w);
    return rc;
  }
  uint8_t* tb = docscan_cfb_get_stream(
      data, size, (flags & 0x0200) ? "1Table" : "0Table", MAX_STREAM, &tn);
  uint32_t fcClx = rd32(w, wn, 0x01A2), lcbClx = rd32(w, wn, 0x01A6);
  if (tb == NULL || (uint64_t) fcClx + lcbClx > tn || lcbClx < 5)
  {
    free(w);
    free(tb);
    return DOCSCAN_TEXT_BROKEN;
  }
  // CLX: Prc* (0x01, cb u16, grpprl) then Pcdt (0x02, lcb u32, PlcPcd)
  size_t p = fcClx, end = (size_t) fcClx + lcbClx;
  while (p < end && tb[p] == 0x01)
    p += 3 + rd16(tb, tn, p + 1);
  if (p + 5 > end || tb[p] != 0x02)
  {
    free(w);
    free(tb);
    return DOCSCAN_TEXT_BROKEN;
  }
  uint32_t lcb = rd32(tb, tn, p + 1);
  size_t plc = p + 5;
  if (lcb < 16 || plc + lcb > end)
  {
    free(w);
    free(tb);
    return DOCSCAN_TEXT_BROKEN;
  }
  // PlcPcd: (n+1) CPs (4 bytes) + n PCDs (8 bytes)  =>  lcb = 4 + 12n
  size_t npc = (lcb - 4) / 12;
  word_state ws;
  memset(&ws, 0, sizeof(ws));
  for (size_t k = 0; k < npc && !o->full; k++)
  {
    uint32_t cp0 = rd32(tb, tn, plc + k * 4), cp1 = rd32(tb, tn, plc + (k + 1) * 4);
    if (cp1 <= cp0)
      continue;
    size_t nch = cp1 - cp0;
    uint32_t fc = rd32(tb, tn, plc + (npc + 1) * 4 + k * 8 + 2);
    if (fc & 0x40000000)
    {
      // "compressed": one byte per char (Windows-1252) at fc/2
      size_t at = (fc & 0x3FFFFFFF) / 2;
      if (at >= wn)
        continue;
      if (nch > wn - at)
        nch = wn - at;
      for (size_t q = 0; q < nch && !o->full; q++)
      {
        uint32_t c = cp_byte(w[at + q], 1252);
        if (word_filter(c, &ws, o))
          put_cp(o, c);
      }
    }
    else
    {
      size_t at = fc;
      if (at >= wn)
        continue;
      if (nch > (wn - at) / 2)
        nch = (wn - at) / 2;
      put_utf16le(o, w + at, nch, word_filter, &ws);
    }
  }
  free(w);
  free(tb);
  ole_summary(data, size, t);
  return DOCSCAN_TEXT_OK;
}

// ----------------------------------------------------------- Excel .xls --

// Reads the SST string table across CONTINUE records.
typedef struct
{
  const uint8_t* s;  // Workbook stream
  size_t n;
  size_t rec;        // offset of the current record header
  size_t pos;        // read position inside the stream
  size_t rec_end;    // end of the current record data
  int ok;
} biff_rd;

// Move to the next CONTINUE record; 1 on success.
static int biff_next(biff_rd* r)
{
  size_t h = r->rec_end;
  if (h + 4 > r->n || rd16(r->s, r->n, h) != 0x003C)
  {
    r->ok = 0;
    return 0;
  }
  r->rec = h;
  r->pos = h + 4;
  r->rec_end = r->pos + rd16(r->s, r->n, h + 2);
  if (r->rec_end > r->n)
    r->rec_end = r->n;
  return 1;
}

static int biff_avail(biff_rd* r, size_t want)
{
  while (r->ok && r->pos + want > r->rec_end)
  {
    if (r->pos < r->rec_end)
      return 0;  // a field split across records: not expected for fixed fields
    if (!biff_next(r))
      return 0;
  }
  return r->ok;
}

static void biff_skip(biff_rd* r, size_t n)
{
  while (r->ok && n > 0)
  {
    size_t a = r->rec_end - r->pos;
    if (a == 0)
    {
      if (!biff_next(r))
        return;
      continue;
    }
    size_t k = a < n ? a : n;
    r->pos += k;
    n -= k;
  }
}

static int extract_xls(const uint8_t* data, size_t size, docscan_text_t* t, tout* o)
{
  size_t n = 0;
  uint8_t* s = docscan_cfb_get_stream(data, size, "Workbook", MAX_STREAM, &n);
  if (s == NULL)
  {
    s = docscan_cfb_get_stream(data, size, "Book", MAX_STREAM, &n);
    free(s);
    return s ? DOCSCAN_TEXT_UNSUPPORTED : DOCSCAN_TEXT_BROKEN;  // BIFF5: Excel 95
  }
  snprintf(t->kind, sizeof(t->kind), "xls");
  int rc = DOCSCAN_TEXT_EMPTY, guard = 0;
  size_t h = 0;
  while (h + 4 <= n && guard++ < 10000000)
  {
    uint16_t type = rd16(s, n, h), len = rd16(s, n, h + 2);
    if (type == 0x002F)  // FILEPASS
    {
      rc = DOCSCAN_TEXT_ENCRYPTED;
      break;
    }
    if (type == 0x00FC)  // SST
    {
      biff_rd r = {s, n, h, h + 4, h + 4 + len, 1};
      if (r.rec_end > n)
        r.rec_end = n;
      if (!biff_avail(&r, 8))
        break;
      uint32_t uniq = rd32(s, n, r.pos + 4);
      r.pos += 8;
      rc = DOCSCAN_TEXT_OK;
      for (uint32_t k = 0; k < uniq && r.ok && !o->full; k++)
      {
        if (!biff_avail(&r, 3))
          break;
        uint16_t cch = rd16(s, n, r.pos);
        uint8_t fl = s[r.pos + 2];
        r.pos += 3;
        uint16_t runs = 0;
        uint32_t ext = 0;
        if (fl & 0x08)
        {
          if (!biff_avail(&r, 2))
            break;
          runs = rd16(s, n, r.pos);
          r.pos += 2;
        }
        if (fl & 0x04)
        {
          if (!biff_avail(&r, 4))
            break;
          ext = rd32(s, n, r.pos);
          r.pos += 4;
        }
        int wide = fl & 0x01;
        size_t left = cch;
        while (left > 0 && r.ok && !o->full)
        {
          if (r.pos >= r.rec_end)
          {
            // the characters continue in the next record, which starts
            // with its own "high byte" flag
            if (!biff_next(&r) || r.pos >= r.rec_end)
              break;
            wide = s[r.pos] & 0x01;
            r.pos++;
          }
          size_t avail = (r.rec_end - r.pos) / (wide ? 2 : 1);
          size_t k2 = avail < left ? avail : left;
          if (k2 == 0)
          {
            r.pos = r.rec_end;
            continue;
          }
          if (wide)
            put_utf16le(o, s + r.pos, k2, NULL, NULL);
          else
            for (size_t q = 0; q < k2; q++) put_cp(o, s[r.pos + q]);  // Latin-1
          r.pos += k2 * (wide ? 2 : 1);
          left -= k2;
        }
        put_nl(o);
        biff_skip(&r, (size_t) runs * 4);
        biff_skip(&r, ext);
      }
      break;
    }
    h += 4 + (size_t) len;
  }
  free(s);
  if (rc == DOCSCAN_TEXT_OK || rc == DOCSCAN_TEXT_EMPTY)
    ole_summary(data, size, t);
  return rc == DOCSCAN_TEXT_EMPTY ? DOCSCAN_TEXT_OK : rc;  // finalize decides "empty"
}

// ------------------------------------------------------ PowerPoint .ppt --

static int ppt_filter(uint32_t c, void* st, tout* o)
{
  (void) st;
  if (c == 0x0D || c == 0x0B)
  {
    put_nl(o);
    return 0;
  }
  return c >= 0x20 || c == 0x09;
}

static void ppt_records(const uint8_t* s, size_t from, size_t to, tout* o, int depth, int* guard)
{
  size_t p = from;
  while (p + 8 <= to && !o->full && (*guard)++ < 5000000)
  {
    uint16_t verinst = rd16(s, to, p);
    uint16_t type = rd16(s, to, p + 2);
    uint32_t len = rd32(s, to, p + 4);
    size_t body = p + 8;
    if ((uint64_t) body + len > to)
      len = (uint32_t) (to - body);
    if ((verinst & 0x0F) == 0x0F && depth < 32)
      ppt_records(s, body, body + len, o, depth + 1, guard);
    else if (type == 0x0FA0)  // TextCharsAtom: UTF-16LE
    {
      put_utf16le(o, s + body, len / 2, ppt_filter, NULL);
      put_nl(o);
    }
    else if (type == 0x0FA8)  // TextBytesAtom: low bytes of UTF-16
    {
      for (uint32_t q = 0; q < len; q++)
        if (ppt_filter(s[body + q], NULL, o))
          put_cp(o, s[body + q]);
      put_nl(o);
    }
    p = body + len;
  }
}

static int extract_ppt(const uint8_t* data, size_t size, docscan_text_t* t, tout* o)
{
  size_t n = 0;
  uint8_t* s = docscan_cfb_get_stream(data, size, "PowerPoint Document", MAX_STREAM, &n);
  if (s == NULL)
    return DOCSCAN_TEXT_BROKEN;
  snprintf(t->kind, sizeof(t->kind), "ppt");
  int guard = 0;
  ppt_records(s, 0, n, o, 0, &guard);
  free(s);
  ole_summary(data, size, t);
  return DOCSCAN_TEXT_OK;
}

// ------------------------------------------------------------ plain text --

static int extract_plain(const uint8_t* d, size_t n, docscan_text_t* t, tout* o, const char* ext)
{
  snprintf(t->kind, sizeof(t->kind), "%s", ext);
  if (n >= 3 && d[0] == 0xEF && d[1] == 0xBB && d[2] == 0xBF)
    put_bytes(o, (const char*) d + 3, n - 3);
  else if (n >= 2 && d[0] == 0xFF && d[1] == 0xFE)
    put_utf16le(o, d + 2, (n - 2) / 2, NULL, NULL);
  else if (n >= 2 && d[0] == 0xFE && d[1] == 0xFF)
  {
    // UTF-16BE: swap into a temporary LE copy
    size_t m = (n - 2) / 2;
    uint8_t* le = (uint8_t*) malloc(m * 2 + 1);
    if (le == NULL)
      return DOCSCAN_TEXT_NOMEM;
    for (size_t i = 0; i < m; i++)
    {
      le[2 * i] = d[2 + 2 * i + 1];
      le[2 * i + 1] = d[2 + 2 * i];
    }
    put_utf16le(o, le, m, NULL, NULL);
    free(le);
  }
  else if (is_valid_utf8(d, n))
    put_bytes(o, (const char*) d, n);
  else
    for (size_t i = 0; i < n && !o->full; i++) put_cp(o, cp_byte(d[i], 1251));
  return DOCSCAN_TEXT_OK;
}

// ------------------------------------------------------------------ API --

int docscan_text_extract(
    const uint8_t* data,
    size_t size,
    const char* ext,
    docscan_text_t* out)
{
  memset(out, 0, sizeof(*out));
  if (ext == NULL)
    ext = "";
  if (data == NULL || size == 0)
    return DOCSCAN_TEXT_EMPTY;

  tout o = {{0}, 0, 0};
  int rc;
  switch (docscan_detect_magic(data, size))
  {
  case DOCSCAN_TYPE_OOXML:
    rc = extract_zip(data, size, out, &o);
    break;
  case DOCSCAN_TYPE_OLE:
    // by the main stream, not by the extension
    if (docscan_cfb_has_stream(data, size, "EncryptedPackage"))
      rc = DOCSCAN_TEXT_ENCRYPTED;  // password-protected docx/xlsx/pptx
    else if (docscan_cfb_has_stream(data, size, "WordDocument"))
      rc = extract_doc(data, size, out, &o);
    else if (docscan_cfb_has_stream(data, size, "Workbook") ||
             docscan_cfb_has_stream(data, size, "Book"))
      rc = extract_xls(data, size, out, &o);
    else if (docscan_cfb_has_stream(data, size, "PowerPoint Document"))
      rc = extract_ppt(data, size, out, &o);
    else
      rc = DOCSCAN_TEXT_UNSUPPORTED;  // msg, vbaProject.bin, ...
    break;
  case DOCSCAN_TYPE_RTF:
    rc = extract_rtf(data, size, out, &o);
    break;
  case DOCSCAN_TYPE_UNKNOWN:
    if (strcmp(ext, "txt") == 0 || strcmp(ext, "csv") == 0)
      rc = extract_plain(data, size, out, &o, ext);
    else
      rc = DOCSCAN_TEXT_UNSUPPORTED;
    break;
  default:  // pdf, lnk: no text support (yet)
    rc = DOCSCAN_TEXT_UNSUPPORTED;
  }

  if (o.oom)
    rc = DOCSCAN_TEXT_NOMEM;
  if (rc == DOCSCAN_TEXT_OK)
    rc = finalize(out, &o.b);
  docscan_buf_free(&o.b);
  if (rc != DOCSCAN_TEXT_OK)
  {
    free(out->text);
    out->text = NULL;
    out->len = 0;
  }
  return rc;
}

void docscan_text_free(docscan_text_t* t)
{
  if (t == NULL)
    return;
  free(t->text);
  t->text = NULL;
  t->len = 0;
}

const char* docscan_text_strerror(int code)
{
  switch (code)
  {
  case DOCSCAN_TEXT_OK:
    return "ok";
  case DOCSCAN_TEXT_UNSUPPORTED:
    return "format without text support";
  case DOCSCAN_TEXT_EMPTY:
    return "no text in the document";
  case DOCSCAN_TEXT_ENCRYPTED:
    return "password-protected document";
  case DOCSCAN_TEXT_BROKEN:
    return "damaged document";
  case DOCSCAN_TEXT_NOMEM:
    return "out of memory";
  }
  return "unknown";
}
