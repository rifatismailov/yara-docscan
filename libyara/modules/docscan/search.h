/* DocScan: portable byte search (plain C, no YARA dependency).
   MSVC has no memmem(), so we provide our own — keeps the module portable. */

#ifndef DOCSCAN_SEARCH_H
#define DOCSCAN_SEARCH_H

#include <stddef.h>
#include <stdint.h>

// Case-sensitive byte search. Returns pointer to first match, or NULL.
const uint8_t* docscan_memmem(
    const uint8_t* hay,
    size_t hay_len,
    const void* needle,
    size_t needle_len);

// Case-sensitive: 1 if the NUL-terminated token occurs in [hay, hay+hay_len).
int docscan_contains(const uint8_t* hay, size_t hay_len, const char* token);

// Case-insensitive (ASCII): 1 if the NUL-terminated token occurs.
int docscan_contains_ci(const uint8_t* hay, size_t hay_len, const char* token);

#endif
