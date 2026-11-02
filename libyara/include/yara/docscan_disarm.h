/* DocScan remediation ("cure"): neutralise the attack vector in a document,
   in place, keeping the document. Lives in the CLI path (NOT the read-only
   scan module). Backs up the original before any change. */

#ifndef YR_DOCSCAN_DISARM_H
#define YR_DOCSCAN_DISARM_H

#include <stddef.h>

// What the scan found, captured so disarm knows what to remove.
typedef struct
{
  int present;           // docscan module ran on this file
  int type;              // 1=ooxml 2=ole 3=rtf 4=pdf 5=lnk
  int high;              // any HIGH finding -> worth curing

  // OOXML / OLE vectors
  int macro;             // remove vbaProject.bin (+ macro rels/content-type)
  int remote_template;   // drop external attachedTemplate relationship
  int protocol_handler;  // drop external protocol-handler relationship
  int dde_auto;          // break DDEAUTO in document xml
  int embedded;          // remove embeddings/oleObject*.bin

  // RTF
  int rtf_objupdate;

  // LNK (file itself is the vector)
  int lnk_bad;
} docscan_disarm_info;

// Cure `path` in place. Backs the original up to "<path>.docscan-bak" first.
// Writes a short action summary into out_action. Returns 0 on success/no-op.
int docscan_disarm(
    const char* path,
    const docscan_disarm_info* info,
    char* out_action,
    size_t out_action_sz);

#endif
