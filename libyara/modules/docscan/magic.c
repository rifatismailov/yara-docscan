/* DocScan: file-type detection by magic bytes. See magic.h. */

#include "magic.h"

docscan_type_t docscan_detect_magic(const uint8_t* data, size_t size)
{
  if (data == NULL || size < 4)
    return DOCSCAN_TYPE_UNKNOWN;

  // "PK" — ZIP container, i.e. OOXML (docx/xlsx/pptx)
  if (data[0] == 0x50 && data[1] == 0x4B)
    return DOCSCAN_TYPE_OOXML;

  // D0 CF 11 E0 — OLE Compound File (legacy .doc/.xls, and vbaProject.bin)
  if (data[0] == 0xD0 && data[1] == 0xCF && data[2] == 0x11 && data[3] == 0xE0)
    return DOCSCAN_TYPE_OLE;

  // "{\rt" — RTF
  if (data[0] == 0x7B && data[1] == 0x5C && data[2] == 0x72 && data[3] == 0x74)
    return DOCSCAN_TYPE_RTF;

  // 4C 00 00 00 — LNK ShellLinkHeader (HeaderSize = 0x4C)
  if (data[0] == 0x4C && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x00)
    return DOCSCAN_TYPE_LNK;

  // "%PDF"
  if (data[0] == 0x25 && data[1] == 0x50 && data[2] == 0x44 && data[3] == 0x46)
    return DOCSCAN_TYPE_PDF;

  return DOCSCAN_TYPE_UNKNOWN;
}
