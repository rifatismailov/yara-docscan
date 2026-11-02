/* DocScan: minimal CFB reader. See cfb.h. Ported from Read-CfbStreams.
   Sector n starts at (n + 1) * sectorSize: v3 (512-byte sectors) and v4
   (4096-byte sectors, the header padded to a full sector) alike.
   and vbaProject.bin. All reads are bounds-checked (untrusted input). */

#include "cfb.h"
#include "dynbuf.h"

#include <stdlib.h>
#include <string.h>

#define CFB_MAX_ITER   1000000
#define CFB_MAX_STREAM (4u * 1024 * 1024)
#define CFB_MAX_BUILD  (64u * 1024 * 1024)

static uint16_t u16(const uint8_t* d, size_t n, size_t o)
{
  return (o + 2 <= n) ? (uint16_t) (d[o] | ((uint16_t) d[o + 1] << 8)) : 0;
}

static int32_t i32(const uint8_t* d, size_t n, size_t o)
{
  if (o + 4 > n)
    return -1;
  return (int32_t) ((uint32_t) d[o] | ((uint32_t) d[o + 1] << 8) |
                    ((uint32_t) d[o + 2] << 16) | ((uint32_t) d[o + 3] << 24));
}

static uint32_t u32(const uint8_t* d, size_t n, size_t o)
{
  if (o + 4 > n)
    return 0;
  return (uint32_t) d[o] | ((uint32_t) d[o + 1] << 8) |
         ((uint32_t) d[o + 2] << 16) | ((uint32_t) d[o + 3] << 24);
}

// Growable int32 array (for FAT / miniFAT / FAT-sector lists).
typedef struct
{
  int32_t* p;
  size_t len;
  size_t cap;
} i32buf;

static int i32_push(i32buf* b, int32_t v)
{
  if (b->len >= b->cap)
  {
    size_t nc = b->cap ? b->cap * 2 : 256;
    int32_t* np = (int32_t*) realloc(b->p, nc * sizeof(int32_t));
    if (np == NULL)
      return -1;
    b->p = np;
    b->cap = nc;
  }
  b->p[b->len++] = v;
  return 0;
}

// Follow a FAT chain over the main file, concatenating sectors into out.
static void read_chain(
    const uint8_t* data,
    size_t size,
    uint32_t sectorSize,
    const i32buf* fat,
    int32_t start,
    docscan_buf* out)
{
  // A chain can't be longer than the number of sectors in the file; anything
  // longer is a cycle (crafted FAT), so stop there.
  size_t nSec = size / sectorSize;  // sectors after the header (+1 slack)
  int32_t sid = start;
  size_t g = 0;
  while (sid >= 0 && (size_t) sid < fat->len && g < nSec && g < CFB_MAX_ITER)
  {
    size_t o = ((size_t) sid + 1) * sectorSize;
    if (o >= size)
      break;
    size_t end = o + sectorSize;
    if (end > size)
      end = size;
    if (docscan_buf_push(out, data + o, end - o))
      break;
    if (out->len > CFB_MAX_BUILD)
      break;
    sid = fat->p[sid];
    g++;
  }
}

int docscan_cfb_foreach_stream(
    const uint8_t* data,
    size_t size,
    docscan_cfb_stream_cb cb,
    void* ud)
{
  if (size < 512 || data[0] != 0xD0 || data[1] != 0xCF || data[2] != 0x11 ||
      data[3] != 0xE0)
    return -1;

  // Validate the shift exponents before shifting: they come from the file,
  // and shifting by >= 32 is undefined behaviour.
  uint16_t sectorShift = u16(data, size, 30);
  uint16_t miniShift = u16(data, size, 32);

  if (sectorShift < 7 || sectorShift > 16 || miniShift < 2 ||
      miniShift > sectorShift)
    return -1;

  uint32_t sectorSize = 1u << sectorShift;
  uint32_t miniSize = 1u << miniShift;

  int32_t firstDir = i32(data, size, 48);
  uint32_t miniCutoff = u32(data, size, 56);
  int32_t firstMiniFat = i32(data, size, 60);
  int32_t firstDifat = i32(data, size, 68);

  // Every count below is bounded by the sectors that physically exist in the
  // file: a crafted DIFAT/FAT/miniFAT can loop, and without these bounds a
  // 1 KB file made the FAT grow to billions of entries (found by libFuzzer).
  size_t nSec = size / sectorSize;  // sectors after the header (+1 slack)
  size_t budget = CFB_MAX_BUILD;  // total stream bytes handed to cb

  int rc = 0;
  i32buf fatSecs = {0}, fat = {0}, mfat = {0};
  docscan_buf dir = {0}, mini = {0};

  // 1) FAT sector numbers: 109 entries in header DIFAT, then the DIFAT chain.
  for (int i = 0; i < 109; i++)
  {
    int32_t s = i32(data, size, 76 + (size_t) i * 4);
    if (s >= 0)
      i32_push(&fatSecs, s);
  }
  {
    int32_t d = firstDifat;
    size_t g = 0;
    while (d >= 0 && g < nSec && fatSecs.len < nSec)
    {
      size_t o = ((size_t) d + 1) * sectorSize;
      if (o + sectorSize > size)
        break;
      for (uint32_t i = 0; i + 1 < sectorSize / 4; i++)
      {
        int32_t s = i32(data, size, o + (size_t) i * 4);
        if (s >= 0)
          i32_push(&fatSecs, s);
      }
      d = i32(data, size, o + sectorSize - 4);
      g++;
    }
  }

  // 2) Build the FAT array from those sectors.
  // FAT entries past the last real sector address nothing, so stop at nSec.
  for (size_t k = 0; k < fatSecs.len && fat.len < nSec; k++)
  {
    size_t o = ((size_t) fatSecs.p[k] + 1) * sectorSize;
    if (o + sectorSize > size)
      continue;
    for (uint32_t i = 0; i < sectorSize / 4; i++)
      i32_push(&fat, i32(data, size, o + (size_t) i * 4));
  }

  // 3) Directory stream.
  read_chain(data, size, sectorSize, &fat, firstDir, &dir);
  if (dir.len < 128)
    goto done;
  size_t nEnt = dir.len / 128;

  // 4) Mini stream (root entry's start sector is at dir+116).
  {
    int32_t rootStart = i32(dir.p, dir.len, 116);
    read_chain(data, size, sectorSize, &fat, rootStart, &mini);
  }

  // 5) Mini FAT.
  {
    int32_t mf = firstMiniFat;
    size_t g = 0;
    while (mf >= 0 && (size_t) mf < fat.len && g < nSec)
    {
      size_t o = ((size_t) mf + 1) * sectorSize;
      if (o + sectorSize > size)
        break;
      for (uint32_t i = 0; i < sectorSize / 4; i++)
        i32_push(&mfat, i32(data, size, o + (size_t) i * 4));
      mf = fat.p[mf];
      g++;
    }
  }

  // 6) Each stream entry (type 2 = stream).
  for (size_t e = 0; e < nEnt; e++)
  {
    size_t base = e * 128;
    if (dir.p[base + 66] != 2)
      continue;

    int32_t start = i32(dir.p, dir.len, base + 116);
    int32_t ssize = i32(dir.p, dir.len, base + 120);
    if (ssize <= 0 || (uint32_t) ssize > CFB_MAX_STREAM)
      continue;

    docscan_buf sb = {0};

    if ((uint32_t) ssize < miniCutoff)
    {
      // small stream: via mini FAT over the mini stream
      int32_t sid = start;
      size_t g = 0, nMini = mini.len / miniSize + 1;
      while (sid >= 0 && (size_t) sid < mfat.len && g < nMini)
      {
        size_t o = (size_t) sid * miniSize;
        if (o >= mini.len)
          break;
        size_t end = o + miniSize;
        if (end > mini.len)
          end = mini.len;
        if (docscan_buf_push(&sb, mini.p + o, end - o))
          break;
        if (sb.len > CFB_MAX_STREAM)
          break;
        sid = mfat.p[sid];
        g++;
      }
    }
    else
    {
      read_chain(data, size, sectorSize, &fat, start, &sb);
    }

    size_t used = (sb.len < (size_t) ssize) ? sb.len : (size_t) ssize;
    int stop = 0;
    if (used > budget)
      used = budget;
    if (sb.p != NULL && used > 0)
    {
      stop = cb(sb.p, used, ud);
      budget -= used;
    }
    docscan_buf_free(&sb);
    if (stop || budget == 0)
      break;
  }

done:
  free(fatSecs.p);
  free(fat.p);
  free(mfat.p);
  docscan_buf_free(&dir);
  docscan_buf_free(&mini);
  return rc;
}
