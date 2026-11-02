// libFuzzer target: the whole docscan module, exactly as a real scan runs it.
// Mirrors tests/oss-fuzz/pe_fuzzer.cc: compile a rule that imports docscan
// and touches its fields, then scan each fuzz input from memory.

#include <stddef.h>
#include <stdint.h>
#include <yara.h>

const char* RULES =
    "import \"docscan\" "
    "rule test { condition: "
    "  docscan.is_ooxml or docscan.is_ole or docscan.is_rtf or "
    "  docscan.is_pdf or docscan.is_lnk or docscan.macro_suspicious or "
    "  docscan.remote_template or docscan.dde_auto or "
    "  docscan.vba_code contains \"Shell\" or "
    "  docscan.lnk_args contains \"http\" or "
    "  for any rel in docscan.external_rels : (rel.target matches /^https?:/i) or "
    "  for any d in docscan.dde : (d matches /^ddeauto/i) or "
    "  for any e in docscan.embedded : (e.is_pe == 1) or "
    "  for any x in docscan.entries : (x.name iendswith \"vbaProject.bin\") "
    "}";

YR_RULES* rules = NULL;

extern "C" int LLVMFuzzerInitialize(int* argc, char*** argv)
{
  YR_COMPILER* compiler;

  if (yr_initialize() != ERROR_SUCCESS)
    return 0;

  if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
    return 0;

  if (yr_compiler_add_string(compiler, RULES, NULL) == 0)
    yr_compiler_get_rules(compiler, &rules);

  yr_compiler_destroy(compiler);

  return 0;
}

static int callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  return CALLBACK_CONTINUE;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
  if (rules == NULL)
    return 0;

  yr_rules_scan_mem(
      rules, data, size, SCAN_FLAGS_NO_TRYCATCH, callback, NULL, 0);

  return 0;
}
