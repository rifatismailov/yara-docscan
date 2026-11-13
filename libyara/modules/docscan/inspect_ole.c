/* DocScan: OLE (.doc/.xls) inspector. Mirrors Inspect-Ole from doc-scan.ps1.
   A legacy Office file IS a CFB, so we decompress its VBA directly. */

#include "inspect.h"
#include "cfb.h"
#include "search.h"
#include "vba.h"

#include <stdlib.h>

// Password encryption of an Office file. Encrypted content cannot be checked, and Excel opens files
// encrypted with its default password ("VelvetSweatshop") WITHOUT asking — a known way to hide macros.
static int ole_encrypted(const uint8_t* data, size_t size)
{
  // OOXML (docx/xlsx/pptx...) with a password is a CFB holding EncryptionInfo + EncryptedPackage;
  // PowerPoint 97-2003 keeps an EncryptedSummary stream
  if (docscan_cfb_has_stream(data, size, "EncryptedPackage") ||
      docscan_cfb_has_stream(data, size, "EncryptedSummary"))
    return 1;

  size_t n = 0;
  int enc = 0;
  // Word 97-2003: FIB at the start of WordDocument, wIdent 0xA5EC, flags at 0x0A: fEncrypted = 0x0100
  uint8_t* w = docscan_cfb_get_stream(data, size, "WordDocument", 64u * 1024 * 1024, &n);
  if (w != NULL)
  {
    enc = n >= 12 && w[0] == 0xEC && w[1] == 0xA5 && (w[0x0B] & 0x01);
    free(w);
    if (enc)
      return 1;
  }

  // Excel 97-2003: a FILEPASS record (0x002F) in the workbook globals, before their EOF (0x000A)
  uint8_t* b = docscan_cfb_get_stream(data, size, "Workbook", 64u * 1024 * 1024, &n);
  if (b == NULL)
    b = docscan_cfb_get_stream(data, size, "Book", 64u * 1024 * 1024, &n);  // Excel 5/95
  if (b != NULL)
  {
    for (size_t p = 0; p + 4 <= n && p < 1024u * 1024;)
    {
      uint16_t type = (uint16_t) (b[p] | (b[p + 1] << 8));
      uint16_t len = (uint16_t) (b[p + 2] | (b[p + 3] << 8));
      if (type == 0x002F)
      {
        enc = 1;
        break;
      }
      if (type == 0x000A)
        break;
      p += 4 + (size_t) len;
    }
    free(b);
  }
  return enc;
}

void docscan_inspect_ole(const uint8_t* data, size_t size, docscan_result_t* r)
{
  r->encrypted = ole_encrypted(data, size);

  // Cheap marker (ASCII). The VBA scan below is authoritative anyway.
  if (docscan_contains(data, size, "_VBA_PROJECT"))
    r->macro_present = 1;

  // The whole file is a CFB — decompress VBA and check for suspicious constructs.
  docscan_scan_vba_container(data, size, r);

  // Package / Equation / ActiveX objects and XLM macro sheets in the file itself.
  docscan_scan_ole_objects(data, size, "ole", r);
}
