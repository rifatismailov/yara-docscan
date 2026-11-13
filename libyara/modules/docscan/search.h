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

// RTF: 1 if at position i there is the control word \<word> (ASCII, any case) — a real one: the
// backslash is preceded by an EVEN number of backslashes ("\\" is an escaped backslash, so text
// such as "\\objupdate" in a document about RTF is not a control word) and the word is not the
// start of a longer control word (the next byte is not a letter).
int docscan_rtf_control_word_at(const uint8_t* b, size_t n, size_t i, const char* word);

// RTF: 1 if the real control word \<word> occurs anywhere (see docscan_rtf_control_word_at).
int docscan_rtf_has_control_word(const uint8_t* b, size_t n, const char* word);

#endif
