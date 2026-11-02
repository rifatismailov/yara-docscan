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
