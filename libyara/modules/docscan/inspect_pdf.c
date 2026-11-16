/* DocScan: PDF inspector. Mirrors Inspect-Pdf from the retired PowerShell implementation (doc-scan.ps1).

   The keys (/JS, /JavaScript, /OpenAction, /AA, /Launch, /EmbeddedFile) are looked up as real PDF names,
   not as plain substrings: a plain search finds "/JS" or "/AA" by chance inside compressed stream data
   (images, fonts) and inside longer names (/JSomething), which gave PDF_JS / PDF_OPENACTION false
   positives on ordinary PDFs. The lexer below:
     - reads a name token up to a PDF delimiter and decodes #xx escapes (/J#53 is /JS);
     - skips the data of "stream ... endstream" (only when "stream" follows a dictionary ">>");
     - skips comments (% ... end of line) and literal strings ( ... ), so text that only looks like a
       stream start cannot hide the names after it.
   A stream / string without its end is not skipped (a damaged or crafted file is read on as plain bytes). */

#include <string.h>

#include "inspect.h"
#include "search.h"

// Dangerous JS = exploit/exec APIs or shellcode markers. Benign viewer JS
// (this.print, app.alert, zoom) is deliberately NOT listed, so ordinary
// scanner/printer PDFs stay MEDIUM instead of HIGH.
static int pdf_has_dangerous_js(const uint8_t* d, size_t n)
{
  static const char* sus[] = {
      "app.launchURL", "exportDataObject", "importDataObject", "getAnnots",
      "submitForm",    "Collab.",          "util.printf",      "getIcon",
      "media.newPlayer", "eval(",          "unescape(",        "String.fromCharCode",
      ".exe",          "powershell",       "cmd.exe",          "rundll32",
      "mshta",         "certutil",         "Net.HTTP",         "SOAP.",
      "heapLib",       "shellcode",        NULL};

  for (int i = 0; sus[i] != NULL; i++)
  {
    if (docscan_contains(d, n, sus[i]))
      return 1;
  }
  return 0;
}

#define PDF_N_JS         0x01
#define PDF_N_JAVASCRIPT 0x02
#define PDF_N_OPENACTION 0x04
#define PDF_N_AA         0x08
#define PDF_N_LAUNCH     0x10
#define PDF_N_EMBEDDED   0x20

#define PDF_MAX_STRING (1u << 20)  // a literal string longer than this is not skipped

static int pdf_is_space(uint8_t c)
{
  return c == 0 || c == 9 || c == 10 || c == 12 || c == 13 || c == 32;
}

static int pdf_is_delim(uint8_t c)
{
  return pdf_is_space(c) || c == '(' || c == ')' || c == '<' || c == '>' || c == '[' ||
         c == ']' || c == '{' || c == '}' || c == '/' || c == '%';
}

static int hexval(uint8_t c)
{
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return -1;
}

// "stream" at i is a stream start whose data can be skipped: preceded by ">>" (spaces allowed), followed
// by CR / LF, and not an object stream: /Type /ObjStm holds ordinary objects (dictionaries with /JS ...),
// and an uncompressed one must be read like the rest of the file
static int pdf_stream_at(const uint8_t* d, size_t n, size_t i)
{
  if (i + 7 > n || memcmp(d + i, "stream", 6) != 0 || (d[i + 6] != '\r' && d[i + 6] != '\n'))
    return 0;
  size_t k = i;
  while (k > 0 && pdf_is_space(d[k - 1]))
    k--;
  if (k < 2 || d[k - 1] != '>' || d[k - 2] != '>')
    return 0;
  // the stream dictionary: back to the "obj" keyword of this object (at most 4 KB)
  size_t from = (k > 4096) ? k - 4096 : 0;
  size_t s = from;
  for (size_t j = k; j >= from + 3; j--)
    if (memcmp(d + j - 3, "obj", 3) == 0)
    {
      s = j;
      break;
    }
  // a compressed object stream (/Filter) is binary like any other: skipped
  return docscan_memmem(d + s, k - s, "/ObjStm", 7) == NULL ||
         docscan_memmem(d + s, k - s, "/Filter", 7) != NULL;
}

// end of a literal string starting at d[i] == '(' (index after ')'), or 0 when it does not end soon or
// holds control bytes: then the '(' is a byte of binary data (a stream not recognised), not a string
static size_t pdf_string_end(const uint8_t* d, size_t n, size_t i)
{
  size_t lim = (n - i > PDF_MAX_STRING) ? i + PDF_MAX_STRING : n;
  int depth = 0;
  for (size_t j = i; j < lim; j++)
  {
    if (d[j] < 0x20 && d[j] != '\t' && d[j] != '\n' && d[j] != '\r' && d[j] != '\f' && d[j] != 0)
      return 0;
    if (d[j] == '\\')
      j++;
    else if (d[j] == '(')
      depth++;
    else if (d[j] == ')' && --depth == 0)
      return j + 1;
  }
  return 0;
}

static int pdf_names(const uint8_t* d, size_t n)
{
  static const struct
  {
    const char* name;
    int flag;
  } keys[] = {
      {"JS", PDF_N_JS},
      {"JavaScript", PDF_N_JAVASCRIPT},
      {"OpenAction", PDF_N_OPENACTION},
      {"AA", PDF_N_AA},
      {"Launch", PDF_N_LAUNCH},
      {"EmbeddedFile", PDF_N_EMBEDDED},
      {"EmbeddedFiles", PDF_N_EMBEDDED},
      {NULL, 0}};

  int found = 0;
  size_t i = 0;
  while (i < n)
  {
    uint8_t c = d[i];

    if (c == 's' && pdf_stream_at(d, n, i))
    {
      const uint8_t* e = docscan_memmem(d + i + 6, n - i - 6, "endstream", 9);
      if (e != NULL)
      {
        i = (size_t) (e - d) + 9;
        continue;
      }
    }
    else if (c == '%')
    {
      while (i < n && d[i] != '\r' && d[i] != '\n') i++;
      continue;
    }
    else if (c == '(')
    {
      size_t e = pdf_string_end(d, n, i);
      if (e != 0)
      {
        i = e;
        continue;
      }
    }
    else if (c == '/')
    {
      char name[16];
      size_t k = 0;
      int too_long = 0;
      size_t j = i + 1;
      while (j < n && !pdf_is_delim(d[j]))
      {
        int ch = d[j];
        if (ch == '#' && j + 2 < n && hexval(d[j + 1]) >= 0 && hexval(d[j + 2]) >= 0)
        {
          ch = hexval(d[j + 1]) * 16 + hexval(d[j + 2]);
          j += 3;
        }
        else
          j++;
        if (k < sizeof(name) - 1)
          name[k++] = (char) ch;
        else
          too_long = 1;
      }
      if (!too_long)
      {
        name[k] = '\0';
        for (int t = 0; keys[t].name != NULL; t++)
          if (strcmp(name, keys[t].name) == 0)
            found |= keys[t].flag;
      }
      i = (j > i + 1) ? j : i + 1;
      continue;
    }
    i++;
  }
  return found;
}

void docscan_inspect_pdf(const uint8_t* data, size_t size, docscan_result_t* r)
{
  int names = pdf_names(data, size);
  int js = (names & (PDF_N_JS | PDF_N_JAVASCRIPT)) != 0;
  int autoact = (names & (PDF_N_OPENACTION | PDF_N_AA)) != 0;
  int launch = (names & PDF_N_LAUNCH) != 0;
  int embed = (names & PDF_N_EMBEDDED) != 0;

  if (launch)
    r->pdf_launch = 1;  // runs an external program — HIGH

  if (js && pdf_has_dangerous_js(data, size))
    r->pdf_js_auto = 1;  // exploit/exec JS — HIGH
  else if (js)
    r->pdf_js = 1;  // JS present but not obviously malicious — MEDIUM

  if (autoact && !js)
    r->pdf_openaction = 1;  // auto-action without JS — MEDIUM

  if (embed)
    r->pdf_embedded = 1;  // MEDIUM
}
