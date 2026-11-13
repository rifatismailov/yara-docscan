/* DocScan: thin wrapper over miniz for reading ZIP (OOXML) from memory.
   Keeps miniz's complexity isolated from the inspectors. */

#ifndef DOCSCAN_ZIP_H
#define DOCSCAN_ZIP_H

#include <stddef.h>
#include <stdint.h>

typedef struct docscan_zip docscan_zip;  // opaque handle

// Open a ZIP held in memory. Returns NULL if the buffer is not a valid ZIP.
docscan_zip* docscan_zip_open(const uint8_t* data, size_t size);
void docscan_zip_close(docscan_zip* z);

// Number of entries in the archive.
int docscan_zip_count(docscan_zip* z);

// Copy entry i's name into buf (NUL-terminated, truncated). Returns 0 on success.
int docscan_zip_entry_name(docscan_zip* z, int i, char* buf, size_t buf_size);

// Uncompressed size of entry i as declared in the ZIP header (0 on error).
uint64_t docscan_zip_entry_size(docscan_zip* z, int i);

// 1 if entry i is encrypted (password-protected ZIP entry): its content cannot be read.
int docscan_zip_entry_encrypted(docscan_zip* z, int i);

// For a ZIP that miniz refuses (malformed, possibly on purpose to get past scanners): read the names
// straight from the central directory (found from the end-of-central-directory record). cb gets every
// entry name, its "encrypted" flag and its uncompressed size; returns the number of entries read.
typedef void (*docscan_zip_name_cb)(const char* name, int encrypted, uint64_t size, void* ud);
int docscan_zip_central_names(const uint8_t* data, size_t size, docscan_zip_name_cb cb, void* ud);

// Largest entry we decompress. The size comes from the (untrusted) ZIP header;
// a 1 KB zip bomb can claim gigabytes. Real OOXML parts are far smaller.
#define DOCSCAN_ZIP_MAX_ENTRY (64u * 1024 * 1024)

// Decompress entry i into a newly allocated buffer (sets *out_size).
// Returns NULL on failure or if the entry is larger than DOCSCAN_ZIP_MAX_ENTRY.
// Caller must release it with docscan_zip_free().
uint8_t* docscan_zip_extract(docscan_zip* z, int i, size_t* out_size);
void docscan_zip_free(void* p);

#endif
