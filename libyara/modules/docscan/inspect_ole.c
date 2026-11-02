/* DocScan: OLE (.doc/.xls) inspector. Mirrors Inspect-Ole from doc-scan.ps1.
   A legacy Office file IS a CFB, so we decompress its VBA directly. */

#include "inspect.h"
#include "vba.h"
#include "search.h"

void docscan_inspect_ole(const uint8_t* data, size_t size, docscan_result_t* r)
{
  // Cheap marker (ASCII). The VBA scan below is authoritative anyway.
  if (docscan_contains(data, size, "_VBA_PROJECT"))
    r->macro_present = 1;

  // The whole file is a CFB — decompress VBA and check for suspicious constructs.
  docscan_scan_vba_container(data, size, r);
}
