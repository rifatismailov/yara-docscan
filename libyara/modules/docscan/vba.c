/* DocScan: VBA source inspection. See vba.h. */

#include "vba.h"
#include "cfb.h"
#include "msovba.h"
#include "search.h"

#include <stdlib.h>
#include <string.h>

// Suspicious VBA constructs (same intent as the $sus regex in doc-scan.ps1).
// We scan only decompressed VBA source, so these are strong malware signals.
static const char* SUS[] = {
    "powershell",   "cmd.exe",       "mshta",        "rundll32",
    "regsvr32",     "certutil",      "bitsadmin",    "WScript.Shell",
    "CreateObject", "Shell",         ".Run",         ".Exec",
    "DownloadString", "DownloadFile", "URLDownloadToFile", "XmlHttp",
    "WinHttp",      "FromBase64",    "StrReverse",   "Environ",
    "AutoOpen",     "Auto_Open",     "Document_Open", "Workbook_Open",
    "Auto_Exec",    NULL};

// Append a keyword to the evidence string, "a | b | c" style, bounded.
static void add_evidence(docscan_result_t* r, const char* kw)
{
  size_t used = strlen(r->vba_evidence);
  size_t cap = sizeof(r->vba_evidence);
  size_t need = strlen(kw) + (used ? 3 : 0);

  if (used + need + 1 >= cap)
    return;

  if (used)
  {
    memcpy(r->vba_evidence + used, " | ", 3);
    used += 3;
  }
  memcpy(r->vba_evidence + used, kw, strlen(kw));
  r->vba_evidence[used + strlen(kw)] = '\0';
}

static int vba_stream_cb(const uint8_t* data, size_t size, void* ud)
{
  docscan_result_t* r = (docscan_result_t*) ud;

  // Find an MS-OVBA container: a 0x01 byte followed by a chunk header (sig==3).
  for (size_t i = 0; i + 3 < size; i++)
  {
    if (data[i] != 0x01)
      continue;

    uint16_t hdr = (uint16_t) (data[i + 1] | (data[i + 2] << 8));
    if (((hdr & 0x7000) >> 12) != 3)
      continue;

    // Cheap preview first: p-code holds many false 0x01 candidates, and a
    // crafted stream can hold thousands; full decompression only when the
    // preview starts like VBA source.
    size_t plen = 0;
    uint8_t* preview = docscan_msovba_decompress(data, size, i, 64, &plen);
    int looks_vba = preview != NULL && plen >= 8 &&
                    docscan_contains_ci(preview, plen < 48 ? plen : 48, "Attribut");
    free(preview);
    if (!looks_vba)
      continue;

    size_t dlen = 0;
    uint8_t* dec =
        docscan_msovba_decompress(data, size, i, 4u * 1024 * 1024, &dlen);
    if (dec == NULL)
      continue;

    // Real VBA module source begins with "Attribute VB_...".
    size_t head = dlen < 48 ? dlen : 48;
    if (dlen >= 8 && docscan_contains_ci(dec, head, "Attribut"))
    {
      r->macro_present = 1;

      // The module stream is [compiled p-code][compressed source]; the source
      // container starts at i, so i = p-code size. Compiled code in a module
      // whose source defines no procedure = the source was erased (stomping).
      if (docscan_vba_count_procedures((const char*) dec, dlen) == 0 &&
          i > (size_t) r->vba_pcode_nosrc && i < (size_t) 0x7fffffff)
        r->vba_pcode_nosrc = (int) i;

      for (int k = 0; SUS[k] != NULL; k++)
      {
        if (docscan_contains_ci(dec, dlen, SUS[k]))
        {
          r->macro_suspicious = 1;
          add_evidence(r, SUS[k]);
        }
      }

      // Accumulate the full VBA source (capped) for optional Layer-2 rescanning.
      if (r->vba_code_len < 2u * 1024 * 1024)
      {
        char* nb = (char*) realloc(r->vba_code, r->vba_code_len + dlen + 2);
        if (nb != NULL)
        {
          r->vba_code = nb;
          memcpy(r->vba_code + r->vba_code_len, dec, dlen);
          r->vba_code_len += dlen;
          r->vba_code[r->vba_code_len++] = '\n';  // separate modules
          r->vba_code[r->vba_code_len] = '\0';
        }
      }

      free(dec);
      break;  // one VBA module per stream is enough
    }

    free(dec);
  }

  return 0;  // keep scanning other streams
}

// Auto-run procedure names: the same list as DS_MACRO_AUTOEXEC in docscan-policy.yar.
static const char* AUTOEXEC[] = {
    "AutoOpen",      "Auto_Open",      "AutoExec",      "Auto_Exec",
    "AutoClose",     "Auto_Close",     "Document_Open", "Document_Close",
    "Workbook_Open", "Workbook_BeforeClose", NULL};

void docscan_scan_vba_container(const uint8_t* cfb, size_t size, docscan_result_t* r)
{
  docscan_cfb_foreach_stream(cfb, size, vba_stream_cb, r);

  // The whole raw container, not only the decompressed source: the p-code
  // identifier table (_VBA_PROJECT) keeps procedure names even when the source
  // was erased ("VBA stomping"), so an empty source + an auto-run name here is
  // a reason to stay careful (DS_MACRO_STOMPED in the policy).
  for (int k = 0; AUTOEXEC[k] != NULL; k++)
  {
    if (docscan_contains_ci(cfb, size, AUTOEXEC[k]))
    {
      r->vba_autoexec_names = 1;
      break;
    }
  }
}

static int is_blank(char c)
{
  return c == ' ' || c == '\t' || c == '\r';
}

// p..end starts with the word w (ASCII, any case) followed by a space or tab.
static int starts_word(const char* p, const char* end, const char* w)
{
  size_t n = strlen(w);

  if ((size_t) (end - p) <= n)
    return 0;

  for (size_t i = 0; i < n; i++)
  {
    char a = p[i], b = w[i];
    if (a >= 'A' && a <= 'Z')
      a = (char) (a + 32);
    if (b >= 'A' && b <= 'Z')
      b = (char) (b + 32);
    if (a != b)
      return 0;
  }
  return p[n] == ' ' || p[n] == '\t';
}

int docscan_vba_count_procedures(const char* code, size_t len)
{
  static const char* MODS[] = {"Public", "Private", "Friend", "Static", NULL};
  static const char* KINDS[] = {"Sub", "Function", "Property", NULL};
  const char* p = code;
  const char* end = code + len;
  int count = 0;

  if (code == NULL)
    return 0;

  while (p < end)
  {
    const char* eol = (const char*) memchr(p, '\n', (size_t) (end - p));
    if (eol == NULL)
      eol = end;

    const char* q = p;
    while (q < eol && is_blank(*q)) q++;

    // optional access / storage modifiers: "Private Sub", "Public Static Function"
    for (int again = 1; again;)
    {
      again = 0;
      for (int k = 0; MODS[k] != NULL; k++)
      {
        if (starts_word(q, eol, MODS[k]))
        {
          q += strlen(MODS[k]);
          while (q < eol && is_blank(*q)) q++;
          again = 1;
          break;
        }
      }
    }

    // "Sub Name", "Function Name", "Property Get Name"; the name may be non-ASCII
    for (int k = 0; KINDS[k] != NULL; k++)
    {
      if (starts_word(q, eol, KINDS[k]))
      {
        const char* n = q + strlen(KINDS[k]);
        while (n < eol && is_blank(*n)) n++;
        unsigned char c = n < eol ? (unsigned char) *n : 0;
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c == '_' || c >= 0x80)
          count++;
        break;
      }
    }

    p = eol + 1;
  }
  return count;
}
