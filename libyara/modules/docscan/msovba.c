/* DocScan: MS-OVBA decompression. See msovba.h. */

#include "msovba.h"
#include "dynbuf.h"

uint8_t* docscan_msovba_decompress(
    const uint8_t* buf,
    size_t len,
    size_t start,
    size_t max_out,
    size_t* out_size)
{
  if (out_size)
    *out_size = 0;
  if (start >= len || buf[start] != 0x01)
    return NULL;

  docscan_buf out = {0};
  size_t pos = start + 1;

  while (pos + 1 < len)
  {
    uint16_t header = (uint16_t) (buf[pos] | (buf[pos + 1] << 8));
    pos += 2;

    uint32_t chunkSz = (header & 0x0FFF) + 3;
    uint32_t sig = (header & 0x7000) >> 12;
    int compressed = (header & 0x8000) != 0;

    if (sig != 3)
      break;

    size_t chunkEnd = pos + (chunkSz - 2);
    if (chunkEnd > len)
      chunkEnd = len;

    if (!compressed)
    {
      if (pos < chunkEnd && docscan_buf_push(&out, buf + pos, chunkEnd - pos))
        goto fail;
      pos = chunkEnd;
    }
    else
    {
      size_t chunkStartOut = out.len;

      while (pos < chunkEnd)
      {
        uint8_t flags = buf[pos];
        pos++;

        for (int b = 0; b < 8 && pos < chunkEnd; b++)
        {
          if (((flags >> b) & 1) == 0)
          {
            // literal byte
            if (docscan_buf_push(&out, &buf[pos], 1))
              goto fail;
            pos++;
          }
          else
          {
            // back-reference (copy from already-decompressed output)
            if (pos + 1 >= chunkEnd)
            {
              pos = chunkEnd;
              break;
            }
            uint16_t token = (uint16_t) (buf[pos] | (buf[pos + 1] << 8));
            pos += 2;

            size_t diff = out.len - chunkStartOut;
            int bitCount = 4;
            while ((size_t) (1u << bitCount) < diff)
              bitCount++;
            if (bitCount > 12)
              bitCount = 12;

            uint16_t lenMask = (uint16_t) (0xFFFF >> bitCount);
            uint32_t copyLen = (token & lenMask) + 3;
            uint32_t copyOff = (token >> (16 - bitCount)) + 1;

            if (copyOff > out.len)
              goto fail;
            size_t src = out.len - copyOff;

            for (uint32_t k = 0; k < copyLen; k++)
            {
              uint8_t byte = out.p[src + k];  // read before push (realloc-safe)
              if (docscan_buf_push(&out, &byte, 1))
                goto fail;
            }
          }

          if (out.len > max_out)
          {
            if (out_size)
              *out_size = out.len;
            return out.p;
          }
        }
      }
    }

    if (out.len > max_out)
      break;
  }

  if (out.len == 0)
  {
    docscan_buf_free(&out);
    return NULL;
  }

  if (out_size)
    *out_size = out.len;
  return out.p;

fail:
  docscan_buf_free(&out);
  return NULL;
}
