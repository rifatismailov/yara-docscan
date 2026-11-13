/* DocScan: portable byte search. See search.h. */

#include "search.h"

#include <string.h>

const uint8_t* docscan_memmem(
    const uint8_t* hay,
    size_t hay_len,
    const void* needle_,
    size_t needle_len)
{
  const uint8_t* needle = (const uint8_t*) needle_;

  if (needle_len == 0)
    return hay;
  if (hay == NULL || needle == NULL || hay_len < needle_len)
    return NULL;

  const uint8_t first = needle[0];
  size_t last = hay_len - needle_len;

  for (size_t i = 0; i <= last; i++)
  {
    if (hay[i] == first && memcmp(hay + i, needle, needle_len) == 0)
      return hay + i;
  }

  return NULL;
}

int docscan_contains(const uint8_t* hay, size_t hay_len, const char* token)
{
  return docscan_memmem(hay, hay_len, token, strlen(token)) != NULL;
}

static uint8_t to_lower(uint8_t c)
{
  return (c >= 'A' && c <= 'Z') ? (uint8_t) (c + 32) : c;
}

int docscan_contains_ci(const uint8_t* hay, size_t hay_len, const char* token)
{
  size_t tlen = strlen(token);

  if (tlen == 0)
    return 1;
  if (hay == NULL || hay_len < tlen)
    return 0;

  size_t last = hay_len - tlen;

  for (size_t i = 0; i <= last; i++)
  {
    size_t j = 0;
    for (; j < tlen; j++)
    {
      if (to_lower(hay[i + j]) != to_lower((uint8_t) token[j]))
        break;
    }
    if (j == tlen)
      return 1;
  }

  return 0;
}

int docscan_rtf_control_word_at(const uint8_t* b, size_t n, size_t i, const char* word)
{
  size_t wl = strlen(word);

  if (b == NULL || i >= n || b[i] != '\\' || n - i - 1 < wl)
    return 0;

  for (size_t j = 0; j < wl; j++)
  {
    if (to_lower(b[i + 1 + j]) != to_lower((uint8_t) word[j]))
      return 0;
  }

  // \objupdatex is another control word, not \objupdate
  size_t end = i + 1 + wl;
  if (end < n && ((b[end] >= 'a' && b[end] <= 'z') || (b[end] >= 'A' && b[end] <= 'Z')))
    return 0;

  // count the backslashes right before position i: odd = this one is escaped ("\\word" is text)
  size_t k = i, slashes = 0;
  while (k > 0 && b[k - 1] == '\\')
  {
    slashes++;
    k--;
  }
  return slashes % 2 == 0;
}

int docscan_rtf_has_control_word(const uint8_t* b, size_t n, const char* word)
{
  for (size_t i = 0; b != NULL && i < n; i++)
  {
    if (b[i] == '\\' && docscan_rtf_control_word_at(b, n, i, word))
      return 1;
  }
  return 0;
}
