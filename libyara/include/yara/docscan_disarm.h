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
  int type;              // 1=ooxml 2=ole 3=rtf 4=pdf 5=lnk 6=zip archive (quarantine only)
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

  // Any type: back the file up and delete it (used when a type cannot be
  // cured in place, e.g. legacy OLE macros or a dangerous PDF).
  int quarantine;

  // Where backups / quarantined files go (UTF-8). NULL = "<file>.docscan-bak"
  // next to the original.
  const char* backup_dir;
} docscan_disarm_info;

// Cure `path` (UTF-8) in place. Backs the original up first (backup_dir or
// "<path>.docscan-bak"); if the backup fails nothing is changed.
// Writes a short action summary into out_action. Returns 0 on success/no-op.
// = docscan_disarm_plan() on the file's bytes + docscan_disarm_apply().
int docscan_disarm(
    const char* path,
    const docscan_disarm_info* info,
    char* out_action,
    size_t out_action_sz);

// The two halves of docscan_disarm, for the Windows sandbox: the PLAN parses the (hostile) document and
// cures it in memory - it runs in the locked-down worker and touches no file; the APPLY only does file
// operations (backup, delete, replace with the cured bytes) - it runs in the broker and parses nothing.
#define DOCSCAN_DISARM_NONE    0  // nothing to do (detect-only, nothing changed); action says why
#define DOCSCAN_DISARM_DELETE  1  // back up, then delete the file (quarantine, bad LNK)
#define DOCSCAN_DISARM_REPLACE 2  // back up, then replace the file with *cured
#define DOCSCAN_DISARM_FAILED  3  // the document could not be cured; action says why (may be empty)

// Decide and cure in memory. On DOCSCAN_DISARM_REPLACE *cured / *cured_len hold the new file
// (free with docscan_disarm_free). action: what was / will be done ("removed:vbaProject.bin", ...).
int docscan_disarm_plan(
    const unsigned char* data,
    size_t len,
    const docscan_disarm_info* info,
    unsigned char** cured,
    size_t* cured_len,
    char* action,
    size_t action_sz);

// Carry out a plan on `path` (UTF-8): backup (backup_dir or "<path>.docscan-bak"), then delete or
// replace. plan_action is the action of the plan; out_action gets the final result (the plan's action,
// or "failed:backup" / "failed:delete" / "failed:write" / "failed:replace"). Returns 0 on success.
int docscan_disarm_apply(
    const char* path,
    const char* backup_dir,
    int kind,
    const unsigned char* cured,
    size_t cured_len,
    const char* plan_action,
    char* out_action,
    size_t out_action_sz);

void docscan_disarm_free(unsigned char* p);

#endif
