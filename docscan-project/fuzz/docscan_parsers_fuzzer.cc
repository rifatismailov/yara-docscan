// libFuzzer target: docscan parsers called directly, bypassing magic dispatch.
//
// The first input byte selects the target, the rest is the payload:
//   0 CFB/OLE + VBA   1 LNK    2 RTF    3 PDF    4 OOXML (zip)
//   5 MS-OVBA decompress        6 .rels parser   7 disarm (cure a temp file)
//
// Reaching CFB / MS-OVBA through the module needs a valid deflated ZIP, which
// random mutation almost never keeps intact — hence direct entry points.

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern "C" {
#include <yara/docscan_disarm.h>
#include "inspect.h"
#include "msovba.h"
#include "rels.h"
}

static char tmp_path[256];

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  snprintf(tmp_path, sizeof(tmp_path), "/tmp/docscan-fuzz-%d.bin", (int) getpid());
  return 0;
}

static void fuzz_disarm(const uint8_t* d, size_t n)
{
  FILE* f = fopen(tmp_path, "wb");
  if (f == NULL)
    return;
  fwrite(d, 1, n, f);
  fclose(f);

  docscan_disarm_info info;
  memset(&info, 0, sizeof(info));
  info.present = 1;
  info.high = 1;
  info.type = (n >= 2 && d[0] == 'P' && d[1] == 'K') ? 1 : 3;  // ooxml : rtf
  info.macro = info.remote_template = info.protocol_handler = 1;
  info.dde_auto = info.embedded = info.rtf_objupdate = 1;

  char action[256];
  docscan_disarm(tmp_path, &info, action, sizeof(action));

  char bak[300];
  snprintf(bak, sizeof(bak), "%s.docscan-bak", tmp_path);
  remove(bak);
  remove(tmp_path);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (size < 1)
    return 0;

  uint8_t sel = data[0] % 8;
  const uint8_t* d = data + 1;
  size_t n = size - 1;

  docscan_result_t r;
  memset(&r, 0, sizeof(r));

  switch (sel)
  {
  case 0: docscan_inspect_ole(d, n, &r); break;
  case 1: docscan_inspect_lnk(d, n, &r); break;
  case 2: docscan_inspect_rtf(d, n, &r); break;
  case 3: docscan_inspect_pdf(d, n, &r); break;
  case 4: docscan_inspect_ooxml(d, n, &r); break;
  case 5:
  {
    size_t out = 0;
    uint8_t* p = docscan_msovba_decompress(d, n, 0, 4u * 1024 * 1024, &out);
    free(p);
    break;
  }
  case 6: docscan_scan_rels(d, n, &r); break;
  case 7: fuzz_disarm(d, n); break;
  }

  free(r.vba_code);
  return 0;
}
