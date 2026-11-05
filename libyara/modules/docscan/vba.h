/* DocScan: find & inspect VBA macro source inside a CFB container
   (vbaProject.bin, or a legacy .doc/.xls which is itself a CFB).
   Mirrors Expand-VbaSource + Inspect-VbaSource from the retired PowerShell implementation (doc-scan.ps1). */

#ifndef DOCSCAN_VBA_H
#define DOCSCAN_VBA_H

#include <stddef.h>
#include <stdint.h>

#include "inspect.h"

// Iterates CFB streams, decompresses VBA module source (MS-OVBA), and sets
// macro_present / macro_suspicious (+ vba_evidence) on *r.
void docscan_scan_vba_container(const uint8_t* cfb, size_t size, docscan_result_t* r);

#endif
