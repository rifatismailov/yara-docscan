/* DocScan critical-information mode: search copy, SHA-256, fragments, JSON.
   See <yara/docscan_critical.h>. Plain C, no YARA dependency. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yara/docscan_critical.h>

#include "dynbuf.h"

// ------------------------------------------------------------- UTF-8 io --

// Decode one code point of VALID UTF-8 (the extracted text is validated).
static uint32_t dec(const uint8_t* p, size_t n, size_t* i)
{
  uint8_t c = p[*i];
  uint32_t v;
  int len;
  if (c < 0x80)
  {
    (*i)++;
    return c;
  }
  if ((c & 0xE0) == 0xC0)
  {
    len = 2;
    v = c & 0x1F;
  }
  else if ((c & 0xF0) == 0xE0)
  {
    len = 3;
    v = c & 0x0F;
  }
  else
  {
    len = 4;
    v = c & 0x07;
  }
  size_t k = 1;
  for (; k < (size_t) len && *i + k < n; k++) v = (v << 6) | (p[*i + k] & 0x3F);
  *i += k;
  return v;
}

static int enc(uint32_t c, char* u)
{
  if (c < 0x80)
  {
    u[0] = (char) c;
    return 1;
  }
  if (c < 0x800)
  {
    u[0] = (char) (0xC0 | (c >> 6));
    u[1] = (char) (0x80 | (c & 0x3F));
    return 2;
  }
  if (c < 0x10000)
  {
    u[0] = (char) (0xE0 | (c >> 12));
    u[1] = (char) (0x80 | ((c >> 6) & 0x3F));
    u[2] = (char) (0x80 | (c & 0x3F));
    return 3;
  }
  u[0] = (char) (0xF0 | (c >> 18));
  u[1] = (char) (0x80 | ((c >> 12) & 0x3F));
  u[2] = (char) (0x80 | ((c >> 6) & 0x3F));
  u[3] = (char) (0x80 | (c & 0x3F));
  return 4;
}

// Python str.isspace()
static int py_space(uint32_t c)
{
  return (c >= 0x09 && c <= 0x0D) || (c >= 0x1C && c <= 0x20) || c == 0x85 ||
         c == 0xA0 || c == 0x1680 || (c >= 0x2000 && c <= 0x200A) ||
         c == 0x2028 || c == 0x2029 || c == 0x202F || c == 0x205F ||
         c == 0x3000;
}

// ------------------------------------------------------------ search copy --

static uint32_t lower(uint32_t c)
{
  if (c >= 'A' && c <= 'Z')
    return c + 32;
  if (c < 0xC0)
    return c;
  if (c <= 0xDE && c != 0xD7)  // Latin-1
    return c + 32;
  if (c >= 0x0100 && c <= 0x017F)  // Latin Extended-A (pairs)
  {
    if ((c >= 0x0139 && c <= 0x0148) || (c >= 0x0179 && c <= 0x017E))
      return (c & 1) ? c + 1 : c;
    if (c == 0x0130 || c == 0x0131 || c == 0x0138 || c == 0x0149 || c == 0x017F)
      return c == 0x0130 ? 'i' : c;
    return (c & 1) ? c : c + 1;
  }
  if (c >= 0x0400 && c <= 0x040F)  // Ѐ..Џ (Є І Ї Ў ...)
    return c + 0x50;
  if (c >= 0x0410 && c <= 0x042F)  // А..Я
    return c + 0x20;
  if ((c >= 0x0460 && c <= 0x0481) || (c >= 0x048A && c <= 0x04BF) ||
      (c >= 0x04D0 && c <= 0x052F))  // pairs, incl. Ґ (0490)
    return (c & 1) ? c : c + 1;
  if (c == 0x04C0)
    return 0x04CF;
  if (c >= 0x04C1 && c <= 0x04CE)
    return (c & 1) ? c + 1 : c;
  return c;
}

char* docscan_text_normalize(const char* text, size_t len, size_t* out_len)
{
  // never longer than the input (+1 for the NUL; lowercase is the same
  // UTF-8 length for every mapping above except U+0130 -> 'i', shorter)
  char* out = (char*) malloc(len + 1);
  if (out == NULL)
    return NULL;
  const uint8_t* p = (const uint8_t*) text;
  size_t i = 0, o = 0;
  int space = 0;
  while (i < len)
  {
    uint32_t c = dec(p, len, &i);
    if (py_space(c) || c == 0x200B || c == 0xFEFF)
    {
      space = 1;
      continue;
    }
    if (c == 0x00AD)  // soft hyphen: invisible, splits words
      continue;
    if (c == 0x2019 || c == 0x02BC || c == 0x2018 || c == 0x0060 || c == 0x00B4)
      c = '\'';
    if (space && o > 0)
      out[o++] = ' ';
    space = 0;
    c = lower(c);
    char u[4];
    int l = enc(c, u);
    if (o + (size_t) l > len)  // cannot happen; keep the bound obvious
      break;
    memcpy(out + o, u, (size_t) l);
    o += (size_t) l;
  }
  out[o] = '\0';
  if (out_len)
    *out_len = o;
  return out;
}

// ---------------------------------------------------------------- SHA-256 --

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

#define ROR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))

static void sha_block(uint32_t h[8], const uint8_t* b)
{
  uint32_t w[64];
  for (int i = 0; i < 16; i++)
    w[i] = ((uint32_t) b[4 * i] << 24) | ((uint32_t) b[4 * i + 1] << 16) |
           ((uint32_t) b[4 * i + 2] << 8) | b[4 * i + 3];
  for (int i = 16; i < 64; i++)
  {
    uint32_t s0 = ROR(w[i - 15], 7) ^ ROR(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = ROR(w[i - 2], 17) ^ ROR(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }
  uint32_t a = h[0], bb = h[1], c = h[2], d = h[3], e = h[4], f = h[5], g = h[6], hh = h[7];
  for (int i = 0; i < 64; i++)
  {
    uint32_t S1 = ROR(e, 6) ^ ROR(e, 11) ^ ROR(e, 25);
    uint32_t ch = (e & f) ^ (~e & g);
    uint32_t t1 = hh + S1 + ch + K256[i] + w[i];
    uint32_t S0 = ROR(a, 2) ^ ROR(a, 13) ^ ROR(a, 22);
    uint32_t mj = (a & bb) ^ (a & c) ^ (bb & c);
    uint32_t t2 = S0 + mj;
    hh = g;
    g = f;
    f = e;
    e = d + t1;
    d = c;
    c = bb;
    bb = a;
    a = t1 + t2;
  }
  h[0] += a;
  h[1] += bb;
  h[2] += c;
  h[3] += d;
  h[4] += e;
  h[5] += f;
  h[6] += g;
  h[7] += hh;
}

void docscan_sha256_hex(const uint8_t* data, size_t size, char hex[65])
{
  uint32_t h[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                   0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
  size_t i = 0;
  for (; i + 64 <= size; i += 64) sha_block(h, data + i);
  uint8_t last[128];
  size_t rem = size - i;
  memset(last, 0, sizeof(last));
  if (rem)
    memcpy(last, data + i, rem);
  last[rem] = 0x80;
  size_t tot = (rem + 9 <= 64) ? 64 : 128;
  uint64_t bits = (uint64_t) size * 8;
  for (int k = 0; k < 8; k++) last[tot - 1 - k] = (uint8_t) (bits >> (8 * k));
  sha_block(h, last);
  if (tot == 128)
    sha_block(h, last + 64);
  static const char* hx = "0123456789abcdef";
  for (int k = 0; k < 8; k++)
    for (int j = 0; j < 4; j++)
    {
      uint8_t v = (uint8_t) (h[k] >> (24 - 8 * j));
      hex[k * 8 + j * 2] = hx[v >> 4];
      hex[k * 8 + j * 2 + 1] = hx[v & 15];
    }
  hex[64] = '\0';
}

// -------------------------------------------------------------- fragments --

// Byte offset of every code point (+ the end). n code points -> n+1 offsets.
static uint32_t* cp_offsets(const char* text, size_t len, size_t* ncp)
{
  size_t n = 0;
  for (size_t i = 0; i < len; i++)
    if (((uint8_t) text[i] & 0xC0) != 0x80)
      n++;
  uint32_t* off = (uint32_t*) malloc((n + 1) * sizeof(uint32_t));
  if (off == NULL)
    return NULL;
  size_t k = 0;
  for (size_t i = 0; i < len; i++)
    if (((uint8_t) text[i] & 0xC0) != 0x80)
      off[k++] = (uint32_t) i;
  off[n] = (uint32_t) len;
  *ncp = n;
  return off;
}

long docscan_text_split(
    const char* text,
    size_t len,
    int size,
    int overlap,
    docscan_fragment** out)
{
  *out = NULL;
  if (size < 1 || overlap < 0 || len > 0xFFFFFFF0u)
    return -1;
  size_t n = 0;
  uint32_t* off = cp_offsets(text, len, &n);
  if (off == NULL)
    return -1;
  size_t cap = 16, cnt = 0;
  docscan_fragment* f = (docscan_fragment*) malloc(cap * sizeof(docscan_fragment));
  if (f == NULL)
  {
    free(off);
    return -1;
  }
  const uint8_t* p = (const uint8_t*) text;
  size_t start = 0;
  while (start < n)
  {
    size_t end = start + (size_t) size < n ? start + (size_t) size : n;
    if (end < n)
    {
      size_t half = start + (size_t) size / 2;
      // max(rfind("\n", half, end), rfind(" ", half, end)): the last of either
      long cut = -1;
      for (size_t i = end; i > half; i--)
      {
        uint8_t b = p[off[i - 1]];
        if (b == '\n' || b == ' ')
        {
          cut = (long) (i - 1);
          break;
        }
      }
      if (cut > (long) start)
        end = (size_t) cut;
    }
    // text[start:end].strip() is not empty?
    int nonblank = 0;
    for (size_t i = start; i < end && !nonblank; i++)
    {
      size_t bi = off[i];
      uint32_t c = dec(p, len, &bi);
      if (!py_space(c))
        nonblank = 1;
    }
    if (nonblank)
    {
      if (cnt == cap)
      {
        cap *= 2;
        docscan_fragment* nf = (docscan_fragment*) realloc(f, cap * sizeof(docscan_fragment));
        if (nf == NULL)
        {
          free(f);
          free(off);
          return -1;
        }
        f = nf;
      }
      f[cnt].start = start;
      f[cnt].end = end;
      cnt++;
    }
    if (end >= n)
      break;
    size_t next = end > (size_t) overlap ? end - (size_t) overlap : 0;
    start = next > start + 1 ? next : start + 1;
  }
  free(off);
  *out = f;
  return (long) cnt;
}

// ------------------------------------------------------------------- JSON --

typedef struct
{
  docscan_buf b;
  int oom;
} jbuf;

static void jraw(jbuf* j, const char* s, size_t n)
{
  if (!j->oom && docscan_buf_push(&j->b, (const uint8_t*) s, n))
    j->oom = 1;
}

static void jlit(jbuf* j, const char* s)
{
  jraw(j, s, strlen(s));
}

static void jstr(jbuf* j, const char* s, size_t n)
{
  static const char* hx = "0123456789abcdef";
  jraw(j, "\"", 1);
  size_t run = 0;
  for (size_t i = 0; i < n; i++)
  {
    uint8_t c = (uint8_t) s[i];
    const char* esc = NULL;
    char u[7];
    if (c == '"')
      esc = "\\\"";
    else if (c == '\\')
      esc = "\\\\";
    else if (c == '\n')
      esc = "\\n";
    else if (c == '\r')
      esc = "\\r";
    else if (c == '\t')
      esc = "\\t";
    else if (c == '\b')
      esc = "\\b";
    else if (c == '\f')
      esc = "\\f";
    else if (c < 0x20)
    {
      u[0] = '\\';
      u[1] = 'u';
      u[2] = '0';
      u[3] = '0';
      u[4] = hx[c >> 4];
      u[5] = hx[c & 15];
      u[6] = '\0';
      esc = u;
    }
    if (esc)
    {
      jraw(j, s + i - run, run);
      run = 0;
      jlit(j, esc);
    }
    else
      run++;
  }
  jraw(j, s + n - run, run);
  jraw(j, "\"", 1);
}

static void jfield(jbuf* j, int* first, const char* key, const char* val)
{
  if (val == NULL || val[0] == '\0')
    return;
  if (!*first)
    jraw(j, ",", 1);
  *first = 0;
  jstr(j, key, strlen(key));
  jraw(j, ":", 1);
  jstr(j, val, strlen(val));
}

char* docscan_critical_json(
    const char* text,
    size_t len,
    const docscan_critical_doc* d,
    size_t* out_len,
    int* out_fragments)
{
  if (d->chunk_size < 200 || d->chunk_size > 1500 || d->chunk_overlap < 0 ||
      d->chunk_overlap > d->chunk_size / 2)
    return NULL;
  docscan_fragment* fr = NULL;
  long nf = docscan_text_split(text, len, d->chunk_size, d->chunk_overlap, &fr);
  if (nf <= 0)
  {
    free(fr);
    return NULL;
  }
  size_t ncp = 0;
  uint32_t* off = cp_offsets(text, len, &ncp);
  if (off == NULL)
  {
    free(fr);
    return NULL;
  }

  jbuf j = {{0}, 0};
  char num[64];
  int first;
  jlit(&j, "{\"schema_version\":\"2.0\",\"document\":{");
  first = 1;
  jfield(&j, &first, "name", d->name);
  jfield(&j, &first, "format", d->format);
  if (!first)
    jraw(&j, ",", 1);
  snprintf(num, sizeof(num), "\"size_bytes\":%llu", (unsigned long long) d->size_bytes);
  jlit(&j, num);
  first = 0;
  jfield(&j, &first, "sha256", d->sha256);
  jfield(&j, &first, "path", d->path);

  jlit(&j, "},\"metadata\":{");
  first = 1;
  jfield(&j, &first, "author", d->author);
  jfield(&j, &first, "last_modified_by", d->last_modified_by);
  jfield(&j, &first, "created_at", d->created_at);
  jfield(&j, &first, "modified_at", d->modified_at);
  jfield(&j, &first, "title", d->title);
  jfield(&j, &first, "source", "yara");
  jfield(&j, &first, "received_at", d->received_at);
  jlit(&j, ",\"yara_matches\":[");
  for (int i = 0; i < d->n_matches; i++)
  {
    if (i)
      jraw(&j, ",", 1);
    jstr(&j, d->matches[i], strlen(d->matches[i]));
  }
  jlit(&j, "]}");

  size_t total = fr[nf - 1].end;
  snprintf(num, sizeof(num), ",\"text_info\":{\"total_chars\":%llu,", (unsigned long long) total);
  jlit(&j, num);
  snprintf(num, sizeof(num), "\"fragment_count\":%ld,", nf);
  jlit(&j, num);
  snprintf(num, sizeof(num), "\"chunking\":{\"unit\":\"chars\",\"size\":%d,\"overlap\":%d}},",
           d->chunk_size, d->chunk_overlap);
  jlit(&j, num);

  jlit(&j, "\"fragments\":[");
  for (long i = 0; i < nf; i++)
  {
    snprintf(num, sizeof(num), "%s{\"index\":%ld,\"start\":%llu,\"end\":%llu,\"text\":",
             i ? "," : "", i, (unsigned long long) fr[i].start, (unsigned long long) fr[i].end);
    jlit(&j, num);
    jstr(&j, text + off[fr[i].start], off[fr[i].end] - off[fr[i].start]);
    jraw(&j, "}", 1);
  }
  jlit(&j, "]}\n");
  free(off);
  free(fr);

  if (j.oom)
  {
    docscan_buf_free(&j.b);
    return NULL;
  }
  jraw(&j, "", 0);
  char* res = (char*) realloc(j.b.p, j.b.len + 1);
  if (res == NULL)
  {
    docscan_buf_free(&j.b);
    return NULL;
  }
  res[j.b.len] = '\0';
  if (out_len)
    *out_len = j.b.len;
  if (out_fragments)
    *out_fragments = (int) nf;
  return res;
}
