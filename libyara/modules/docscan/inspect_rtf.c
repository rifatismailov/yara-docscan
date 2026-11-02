/* DocScan: RTF inspector. Mirrors Inspect-Rtf from reference/doc-scan.ps1. */

#include "inspect.h"
#include "search.h"

void docscan_inspect_rtf(const uint8_t* data, size_t size, docscan_result_t* r)
{
  // \objupdate — forces the embedded OLE object to update (fetch/run) on open.
  // Classic RTF weaponisation (T1203). HIGH.
  if (docscan_contains_ci(data, size, "\\objupdate"))
    r->rtf_objupdate = 1;

  // Presence of an embedded object — context only (common & often benign).
  if (docscan_contains_ci(data, size, "\\objdata") ||
      docscan_contains_ci(data, size, "\\objlink") ||
      docscan_contains_ci(data, size, "\\objhtml"))
    r->rtf_embedded_object = 1;
}
