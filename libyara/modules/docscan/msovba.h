/* DocScan: MS-OVBA decompression (the compression used for VBA source inside
   CFB streams). Mirrors Expand-MsOvba from the retired PowerShell implementation (doc-scan.ps1). */

#ifndef DOCSCAN_MSOVBA_H
#define DOCSCAN_MSOVBA_H

#include <stddef.h>
#include <stdint.h>

// Decompress an MS-OVBA CompressedContainer beginning at `start` (must be 0x01).
// Returns a newly allocated buffer (sets *out_size) or NULL. Caller frees().
uint8_t* docscan_msovba_decompress(
    const uint8_t* buf,
    size_t len,
    size_t start,
    size_t max_out,
    size_t* out_size);

#endif
