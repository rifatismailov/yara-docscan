/* DocScan: PDF inspector. Mirrors Inspect-Pdf from the retired PowerShell implementation (doc-scan.ps1). */

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

void docscan_inspect_pdf(const uint8_t* data, size_t size, docscan_result_t* r)
{
  int js = docscan_contains(data, size, "/JavaScript") ||
           docscan_contains(data, size, "/JS");
  int autoact = docscan_contains(data, size, "/OpenAction") ||
                docscan_contains(data, size, "/AA");
  int launch = docscan_contains(data, size, "/Launch");
  int embed = docscan_contains(data, size, "/EmbeddedFile");

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
