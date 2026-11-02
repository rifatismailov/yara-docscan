/* DocScan: structural inspectors + the result they fill.
   Plain C, no YARA dependency (take a buffer + size, fill docscan_result_t). */

#ifndef DOCSCAN_INSPECT_H
#define DOCSCAN_INSPECT_H

#include <stddef.h>
#include <stdint.h>

#include "magic.h"

// All detection results for one document. Grows milestone by milestone.
// docscan.c maps these fields onto the module's YARA-visible fields.
typedef struct
{
  docscan_type_t type;

  // --- RTF ---
  int rtf_objupdate;        // \objupdate — auto-updating OLE object     (HIGH)
  int rtf_embedded_object;  // \objdata/\objlink/\objhtml                (context)

  // --- PDF ---
  int pdf_launch;           // /Launch — runs external program           (HIGH)
  int pdf_js_auto;          // JS present + dangerous API                (HIGH)
  int pdf_js;               // JS present, not obviously dangerous       (MEDIUM)
  int pdf_openaction;       // auto-action without JS                    (MEDIUM)
  int pdf_embedded;         // /EmbeddedFile                            (MEDIUM)

  // --- OOXML ---
  int remote_template;      // external attachedTemplate -> remote URL   (HIGH)
  int protocol_handler;     // external rel ms-msdt:/search-ms: (Follina)(HIGH)
  int dde_auto;             // DDEAUTO in document xml                    (HIGH)
  int embedded_lnk;         // LNK signature in embedded oleObject        (HIGH)
  int embedded_pe;          // MZ..PE in embedded oleObject               (HIGH)
  int macro_present;        // vbaProject.bin / VBA stream present         (MEDIUM)
  int macro_suspicious;     // VBA source has exec/download constructs     (HIGH)
  int external_ole;         // external oleObject relationship            (MEDIUM)
  int external_frame;       // external frame relationship                (MEDIUM)
  int dde_link;             // DDE + exec keyword (not AUTO)              (context)

  // --- LNK ---
  int lnk_lolbin;           // target is a LOLBin (cmd/powershell/...)    (MEDIUM)
  int lnk_url_args;         // URL in arguments                           (HIGH)
  int lnk_obfuscated;       // obfuscated powershell args (-enc/iex/...)  (HIGH)

  // --- evidence (fixed buffers, no malloc) ---
  char template_url[512];   // remote-template / protocol-handler target
  char dde_command[512];    // DDE field instruction snippet
  char vba_evidence[512];   // suspicious VBA constructs found
  char lnk_target[512];     // LNK target path
  char lnk_args[512];       // LNK command-line arguments

  // Full decompressed VBA source (malloc'd; the module sets the field and frees
  // it). Exposed so the orchestrator can rescan it with vendor YARA rules.
  char* vba_code;
  size_t vba_code_len;
} docscan_result_t;

// Each inspector reads the raw bytes and sets the relevant fields in *r.
void docscan_inspect_rtf(const uint8_t* data, size_t size, docscan_result_t* r);
void docscan_inspect_pdf(const uint8_t* data, size_t size, docscan_result_t* r);
void docscan_inspect_ooxml(const uint8_t* data, size_t size, docscan_result_t* r);
void docscan_inspect_ole(const uint8_t* data, size_t size, docscan_result_t* r);
void docscan_inspect_lnk(const uint8_t* data, size_t size, docscan_result_t* r);

#endif
