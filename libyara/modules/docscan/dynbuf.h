/* DocScan: tiny growable byte buffer (header-only, used by cfb/msovba). */

#ifndef DOCSCAN_DYNBUF_H
#define DOCSCAN_DYNBUF_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct
{
  uint8_t* p;
  size_t len;
  size_t cap;
} docscan_buf;

// Appends n bytes. Returns 0 on success, -1 on allocation failure.
static inline int docscan_buf_push(docscan_buf* b, const uint8_t* src, size_t n)
{
  if (n == 0)
    return 0;

  if (b->len + n > b->cap)
  {
    size_t nc = b->cap ? b->cap : 4096;
    while (nc < b->len + n)
      nc *= 2;
    uint8_t* np = (uint8_t*) realloc(b->p, nc);
    if (np == NULL)
      return -1;
    b->p = np;
    b->cap = nc;
  }

  memcpy(b->p + b->len, src, n);
  b->len += n;
  return 0;
}

static inline void docscan_buf_free(docscan_buf* b)
{
  free(b->p);
  b->p = NULL;
  b->len = 0;
  b->cap = 0;
}

#endif
