/* DocScan: structural inspectors + the result they fill.
   Plain C, no YARA dependency (take a buffer + size, fill docscan_result_t). */

#ifndef DOCSCAN_INSPECT_H
#define DOCSCAN_INSPECT_H

#include <stddef.h>
#include <stdint.h>

#include "magic.h"

// Raw facts exposed to rules (the policy file decides what they mean).
// Arrays are capped; *_truncated tells a rule that more existed (padding a
// document with junk entries must not hide the interesting ones silently).
#define DOCSCAN_MAX_RELS     256
#define DOCSCAN_MAX_ENTRIES  512
#define DOCSCAN_MAX_EMBEDDED 64
#define DOCSCAN_MAX_DDE      32
#define DOCSCAN_MAX_PACKAGES 32
#define DOCSCAN_MAX_ACTIVEX  32
#define DOCSCAN_MAX_ALTCHUNK 16
#define DOCSCAN_MAX_PARTS    64                   // parts handed to the 2nd (vendor) scan
#define DOCSCAN_PART_MAX     (8u * 1024 * 1024)   // per part
#define DOCSCAN_PARTS_BUDGET (32u * 1024 * 1024)  // all parts of one document

typedef struct
{
  char part[192];    // the .rels file it came from, e.g. word/_rels/settings.xml.rels
  char type[192];    // relationship Type URI
  char target[512];  // Target as written in the file
} docscan_rel_t;

typedef struct
{
  char name[256];
  uint64_t size;  // uncompressed size from the ZIP header
} docscan_entry_t;

typedef struct
{
  char name[256];
  uint64_t size;
  int is_pe;
  int is_lnk;
} docscan_embedded_t;

typedef struct
{
  char name[256];    // file name carried by the OLE Package (label, else path)
  char source[192];  // where it was found: embedding part, "ole", "rtf"
} docscan_package_t;

// A decompressed / decoded piece of the document for the second scan with the
// vendor rules (raw scans cannot see inside ZIP parts or RTF hex).
typedef struct
{
  char name[256];  // e.g. "word/document.xml", "word/embeddings/oleObject1.bin!invoice.vbs"
  uint8_t* data;   // malloc'd copy (docscan.c frees it)
  size_t len;
} docscan_part_t;

// All detection results for one document.
// docscan.c maps these fields onto the module's YARA-visible fields.
// Large (~250 KB): always heap-allocate it.
typedef struct
{
  docscan_type_t type;

  // --- raw facts for policy rules ---
  docscan_rel_t external_rels[DOCSCAN_MAX_RELS];  // TargetMode="External" only
  int n_external_rels;
  int external_rels_truncated;

  docscan_entry_t entries[DOCSCAN_MAX_ENTRIES];   // every ZIP part
  int n_entries;
  int entries_truncated;

  docscan_embedded_t embedded[DOCSCAN_MAX_EMBEDDED];  // embeddings/oleObject*.bin
  int n_embedded;

  char dde[DOCSCAN_MAX_DDE][512];  // every DDE / DDEAUTO field instruction
  int n_dde;

  // --- embedded objects (OOXML embeddings, legacy OLE, RTF \objdata) ---
  docscan_package_t packages[DOCSCAN_MAX_PACKAGES];  // OLE Package (Ole10Native) payloads
  int n_packages;
  int equation_objects;     // Equation Editor 3.0 objects ("Equation Native" / Equation.3)
  char activex[DOCSCAN_MAX_ACTIVEX][64];  // ActiveX controls: CLSID ("{...}") or "ocx"
  int n_activex;
  char altchunks[DOCSCAN_MAX_ALTCHUNK][256];  // altChunk (aFChunk) relationship targets
  int n_altchunks;
  int xlm_macrosheets;      // Excel 4.0 (XLM) macro sheets

  // --- parts for the second scan (see docscan_part_t) ---
  docscan_part_t parts[DOCSCAN_MAX_PARTS];
  int n_parts;
  size_t parts_bytes;
  int parts_truncated;      // more parts / bytes existed than the caps allow

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

// oleobj.c: facts from a CFB (an embedded oleObject*.bin or a whole legacy
// Office file): OLE Package payloads, Equation Editor objects, ActiveX
// controls, XLM macro sheets in a BIFF8 workbook.
void docscan_scan_ole_objects(
    const uint8_t* data,
    size_t size,
    const char* source,
    docscan_result_t* r);

// Copy a piece of the document into r->parts (capped; empty data ignored).
void docscan_add_part(docscan_result_t* r, const char* name, const uint8_t* d, size_t n);

// Record an ActiveX control id (CLSID "{...}" or "ocx"), deduplicated.
void docscan_add_activex(docscan_result_t* r, const char* id);

// Parse an OLE Package native stream (Ole10Native layout:
// [size u32] flags u16, label\0, path\0, ...) and record its file name.
void docscan_record_package(
    const uint8_t* d,
    size_t n,
    int has_size_prefix,
    const char* source,
    docscan_result_t* r);

#endif
