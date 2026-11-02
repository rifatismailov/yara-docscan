/* DocScan: lightweight scan of OOXML .rels XML for malicious external
   relationships (no full XML parser; mirrors the checks in Inspect-Ooxml). */

#ifndef DOCSCAN_RELS_H
#define DOCSCAN_RELS_H

#include <stddef.h>
#include <stdint.h>

#include "inspect.h"

// Scans a decompressed *.rels document and updates *r:
//   remote_template / protocol_handler / external_ole / external_frame
// and captures the offending target into r->template_url.
void docscan_scan_rels(const uint8_t* xml, size_t size, docscan_result_t* r);

#endif
