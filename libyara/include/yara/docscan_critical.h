/* DocScan critical-information mode (--critical-rules): the CLI side helpers.

   YARA here is only a quick pre-filter. When a phrase from the critical rules
   is found in the document TEXT, the full text is split into fragments and one
   JSON object (schema 2.0 of the E5Search sender spec) is appended as one line
   to a queue file; another program sends it to E5Search. No verdict here.

   Plain C, no YARA objects: text extraction reuses the docscan parsers
   (zip/OOXML, ODF, CFB/OLE, RTF). */

#ifndef YR_DOCSCAN_CRITICAL_H
#define YR_DOCSCAN_CRITICAL_H

#include <stddef.h>
#include <stdint.h>

#define DOCSCAN_TEXT_OK          0
#define DOCSCAN_TEXT_UNSUPPORTED 1  // format without text support (pdf, images, exe, ...)
#define DOCSCAN_TEXT_EMPTY       2  // supported, but no text in it
#define DOCSCAN_TEXT_ENCRYPTED   3  // password-protected document
#define DOCSCAN_TEXT_BROKEN      4  // supported format, but the file is damaged
#define DOCSCAN_TEXT_NOMEM       5

// Largest text we keep (bytes of UTF-8); the rest of a huge document is cut.
#define DOCSCAN_TEXT_MAX (16u * 1024 * 1024)

typedef struct
{
  char* text;      // UTF-8, valid, no NUL chars, \r\n -> \n, stripped; malloc'ed
  size_t len;      // bytes
  char kind[8];    // what the content is: docx xlsx pptx odt ods odp doc xls ppt rtf txt
  // From the document properties when the format has them ("" = unknown).
  char author[256];
  char last_modified_by[256];
  char title[512];
  char created_at[32];   // ISO-8601 UTC, e.g. 2026-10-12T08:30:00Z
  char modified_at[32];
} docscan_text_t;

// Extract the full text of a document held in memory. `ext` is the file
// extension, lowercase, without the dot ("" if none): the format is detected
// by content; the extension only matters for plain text (txt, csv).
// Returns DOCSCAN_TEXT_*; on DOCSCAN_TEXT_OK free the result with
// docscan_text_free().
int docscan_text_extract(
    const uint8_t* data,
    size_t size,
    const char* ext,
    docscan_text_t* out);

void docscan_text_free(docscan_text_t* t);

// Short English reason for a DOCSCAN_TEXT_* code.
const char* docscan_text_strerror(int code);

// The copy that the critical rules scan: Unicode lowercase (Latin, Cyrillic),
// every run of whitespace -> one space, soft hyphens dropped, apostrophe
// variants -> '. Returns a malloc'ed UTF-8 buffer (NULL on allocation failure).
char* docscan_text_normalize(const char* text, size_t len, size_t* out_len);

// SHA-256 of a buffer as 64 lowercase hex chars + NUL.
void docscan_sha256_hex(const uint8_t* data, size_t size, char hex[65]);

// Everything the JSON needs besides the text. NULL / "" fields are omitted.
typedef struct
{
  const char* name;               // file name (UTF-8)
  const char* path;               // full path (UTF-8)
  const char* format;             // extension without the dot, lowercase
  uint64_t size_bytes;
  const char* sha256;             // 64 hex
  const char* author;
  const char* last_modified_by;
  const char* title;
  const char* created_at;
  const char* modified_at;
  const char* received_at;        // when the scan of this file started (UTC)
  const char* const* matches;     // names of the matched critical rules
  int n_matches;
  int chunk_size;                 // 200..1500
  int chunk_overlap;              // 0..chunk_size/2
} docscan_critical_doc;

// Split `text` (the exact algorithm of yara_sender_ref.py, code points) and
// build ONE line of JSON (schema 2.0) ending with '\n'. Returns a malloc'ed
// buffer, or NULL on allocation failure / bad chunk parameters / no fragments.
char* docscan_critical_json(
    const char* text,
    size_t len,
    const docscan_critical_doc* doc,
    size_t* out_len,
    int* out_fragments);

// Fragments only (for tests): code-point start/end of each fragment.
typedef struct
{
  size_t start;
  size_t end;
} docscan_fragment;

// Returns the number of fragments (array in *out, free() it), or -1.
long docscan_text_split(
    const char* text,
    size_t len,
    int size,
    int overlap,
    docscan_fragment** out);

#endif
