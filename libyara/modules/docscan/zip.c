/* DocScan: thin wrapper over miniz. See zip.h. */

#include "zip.h"

#include <stdlib.h>
#include <string.h>

#include "miniz.h"

struct docscan_zip
{
  mz_zip_archive ar;
};

docscan_zip* docscan_zip_open(const uint8_t* data, size_t size)
{
  docscan_zip* z = (docscan_zip*) calloc(1, sizeof(docscan_zip));

  if (z == NULL)
    return NULL;

  if (!mz_zip_reader_init_mem(&z->ar, data, size, 0))
  {
    free(z);
    return NULL;
  }

  return z;
}

void docscan_zip_close(docscan_zip* z)
{
  if (z == NULL)
    return;

  mz_zip_reader_end(&z->ar);
  free(z);
}

int docscan_zip_count(docscan_zip* z)
{
  return (int) mz_zip_reader_get_num_files(&z->ar);
}

int docscan_zip_entry_name(docscan_zip* z, int i, char* buf, size_t buf_size)
{
  mz_zip_archive_file_stat st;

  if (buf == NULL || buf_size == 0)
    return -1;

  if (!mz_zip_reader_file_stat(&z->ar, (mz_uint) i, &st))
    return -1;

  size_t n = strlen(st.m_filename);

  if (n >= buf_size)
    n = buf_size - 1;

  memcpy(buf, st.m_filename, n);
  buf[n] = '\0';

  return 0;
}

uint64_t docscan_zip_entry_size(docscan_zip* z, int i)
{
  mz_zip_archive_file_stat st;

  if (!mz_zip_reader_file_stat(&z->ar, (mz_uint) i, &st))
    return 0;

  return (uint64_t) st.m_uncomp_size;
}

uint8_t* docscan_zip_extract(docscan_zip* z, int i, size_t* out_size)
{
  mz_zip_archive_file_stat st;

  if (!mz_zip_reader_file_stat(&z->ar, (mz_uint) i, &st) ||
      st.m_uncomp_size > DOCSCAN_ZIP_MAX_ENTRY)
    return NULL;

  return (uint8_t*) mz_zip_reader_extract_to_heap(
      &z->ar, (mz_uint) i, out_size, 0);
}

void docscan_zip_free(void* p)
{
  mz_free(p);
}

int docscan_zip_entry_encrypted(docscan_zip* z, int i)
{
  if (z == NULL || i < 0)
    return 0;
  return mz_zip_reader_is_file_encrypted(&z->ar, (mz_uint) i) ? 1 : 0;
}

static uint32_t rd16(const uint8_t* p) { return (uint32_t) p[0] | ((uint32_t) p[1] << 8); }
static uint32_t rd32(const uint8_t* p) { return rd16(p) | (rd16(p + 2) << 16); }

int docscan_zip_central_names(const uint8_t* data, size_t size, docscan_zip_name_cb cb, void* ud)
{
  if (data == NULL || size < 22)
    return 0;
  // end-of-central-directory record: in the last 22 + 65535 (max comment) bytes
  size_t lo = size > 22 + 65535 ? size - 22 - 65535 : 0;
  size_t e = size - 22;
  for (;; e--)
  {
    if (data[e] == 'P' && data[e + 1] == 'K' && data[e + 2] == 5 && data[e + 3] == 6)
      break;
    if (e == lo)
      return 0;
  }
  uint32_t total = rd16(data + e + 10), cd_size = rd32(data + e + 12), cd_off = rd32(data + e + 16);
  // the central directory ends where the EOCD starts: trust that over a (possibly wrong) stored offset
  size_t start = cd_size <= e ? e - cd_size : cd_off;
  if (start + 4 > e || data[start] != 'P' || data[start + 1] != 'K' || data[start + 2] != 1)
    start = cd_off;
  int n = 0;
  size_t p = start;
  while (n < (int) total && n < 65535 && p + 46 <= e && data[p] == 'P' && data[p + 1] == 'K' &&
         data[p + 2] == 1 && data[p + 3] == 2)
  {
    uint32_t flags = rd16(data + p + 8);
    uint32_t usize = rd32(data + p + 24);
    uint32_t nl = rd16(data + p + 28), xl = rd16(data + p + 30), cl = rd16(data + p + 32);
    if (p + 46 + nl > e)
      break;
    char name[256];
    size_t l = nl < sizeof(name) - 1 ? nl : sizeof(name) - 1;
    memcpy(name, data + p + 46, l);
    name[l] = '\0';
    for (size_t k = 0; k < l; k++)
      if (name[k] == '\0')
        name[k] = '?';  // a NUL inside a name would cut it short
    cb(name, (int) (flags & 1), usize, ud);
    n++;
    p += 46 + (size_t) nl + xl + cl;
  }
  return n;
}
