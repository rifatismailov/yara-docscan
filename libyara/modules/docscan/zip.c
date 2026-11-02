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

uint8_t* docscan_zip_extract(docscan_zip* z, int i, size_t* out_size)
{
  return (uint8_t*) mz_zip_reader_extract_to_heap(
      &z->ar, (mz_uint) i, out_size, 0);
}

void docscan_zip_free(void* p)
{
  mz_free(p);
}
