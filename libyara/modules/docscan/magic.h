/* DocScan: file-type detection by magic bytes (plain C, no YARA dependency).
   Mirrors Get-Magic from the retired PowerShell implementation (doc-scan.ps1). */

#ifndef DOCSCAN_MAGIC_H
#define DOCSCAN_MAGIC_H

#include <stddef.h>
#include <stdint.h>

// A type is one file FORMAT (by internal structure), not one extension.
// One format covers many extensions — we group by magic, not by name,
// because an attacker can rename a weaponised .docx to "invoice.pdf".
typedef enum
{
  DOCSCAN_TYPE_UNKNOWN = 0,

  // "PK" (ZIP container) — all modern Office:
  //   .docx .docm .dotx .dotm   (Word)
  //   .xlsx .xlsm .xlsb .xltx .xltm .xlam  (Excel)
  //   .pptx .pptm .potx .potm .ppsx .ppsm .ppam  (PowerPoint)
  //   .odt .ods .odp  (OpenDocument are ZIP too)
  DOCSCAN_TYPE_OOXML,

  // D0 CF 11 E0 (OLE Compound File) — legacy Office 97-2003:
  //   .doc .dot  (Word)   .xls .xlt .xla  (Excel)   .ppt .pot .pps  (PowerPoint)
  //   also the vbaProject.bin stream itself is an OLE/CFB file.
  DOCSCAN_TYPE_OLE,

  // "{\rt" — Rich Text Format:  .rtf
  DOCSCAN_TYPE_RTF,

  // 4C 00 00 00 (ShellLinkHeader size = 0x4C) — Windows shortcut:  .lnk
  DOCSCAN_TYPE_LNK,

  // "%PDF" — Portable Document Format:  .pdf
  DOCSCAN_TYPE_PDF,
} docscan_type_t;

// Returns the detected type, or DOCSCAN_TYPE_UNKNOWN. Safe on short/NULL buffers.
docscan_type_t docscan_detect_magic(const uint8_t* data, size_t size);

#endif
