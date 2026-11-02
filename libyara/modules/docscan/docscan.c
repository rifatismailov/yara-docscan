/*
DocScan YARA module — detection of weaponised documents.

Detects the file type by magic bytes and runs the matching inspector
(OOXML, OLE, RTF, PDF, LNK; VBA is decompressed for OOXML/OLE).

This module is READ-ONLY. It never modifies the scanned file; remediation
("cure") is done by cli/yara.c (--docscan-disarm -> disarm.c) after the scan.
See docscan-project/SCAN-FLOW.md.
*/

#include <stdlib.h>
#include <string.h>

#include <yara/modules.h>

#include "inspect.h"
#include "magic.h"

#define MODULE_NAME docscan

begin_declarations
  // --- File type, detected by magic bytes (not extension) ---
  declare_integer("is_ooxml");  // ZIP Office: docx docm dotx dotm xlsx xlsm xlsb
                                //   xltx xltm xlam pptx pptm potx potm ppsx ppsm
                                //   ppam (+ odt ods odp)
  declare_integer("is_ole");    // legacy Office 97-2003: doc dot xls xlt xla ppt
                                //   pot pps
  declare_integer("is_rtf");    // rtf
  declare_integer("is_pdf");    // pdf
  declare_integer("is_lnk");    // lnk (Windows shortcut)

  // --- RTF findings ---
  declare_integer("rtf_objupdate");        // HIGH
  declare_integer("rtf_embedded_object");  // context

  // --- PDF findings ---
  declare_integer("pdf_launch");           // HIGH
  declare_integer("pdf_js_auto");          // HIGH
  declare_integer("pdf_js");               // MEDIUM
  declare_integer("pdf_openaction");       // MEDIUM
  declare_integer("pdf_embedded");         // MEDIUM

  // --- OOXML findings ---
  declare_integer("remote_template");      // HIGH
  declare_integer("protocol_handler");     // HIGH (Follina)
  declare_integer("dde_auto");             // HIGH
  declare_integer("embedded_lnk");         // HIGH
  declare_integer("embedded_pe");          // HIGH
  declare_integer("macro_present");        // MEDIUM
  declare_integer("macro_suspicious");     // HIGH
  declare_integer("external_ole");         // MEDIUM
  declare_integer("external_frame");       // MEDIUM
  declare_integer("dde_link");             // context

  // --- LNK findings ---
  declare_integer("lnk_lolbin");           // MEDIUM
  declare_integer("lnk_url_args");         // HIGH
  declare_integer("lnk_obfuscated");       // HIGH

  // --- evidence strings ---
  declare_string("template_url");
  declare_string("dde_command");
  declare_string("vba_evidence");
  declare_string("lnk_target");
  declare_string("lnk_args");
  declare_string("vba_code");  // full decompressed VBA (for Layer-2 rescan)
end_declarations

int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  docscan_result_t r;

  memset(&r, 0, sizeof(r));

  // Default type flags to 0 so rules can test them reliably.
  yr_set_integer(0, module_object, "is_ooxml");
  yr_set_integer(0, module_object, "is_ole");
  yr_set_integer(0, module_object, "is_rtf");
  yr_set_integer(0, module_object, "is_pdf");
  yr_set_integer(0, module_object, "is_lnk");

  foreach_memory_block(context->iterator, block)
  {
    const uint8_t* data = yr_fetch_block_data(block);

    if (data == NULL)
      continue;

    r.type = docscan_detect_magic(data, block->size);

    switch (r.type)
    {
    case DOCSCAN_TYPE_OOXML:
      yr_set_integer(1, module_object, "is_ooxml");
      docscan_inspect_ooxml(data, block->size, &r);
      break;
    case DOCSCAN_TYPE_OLE:
      yr_set_integer(1, module_object, "is_ole");
      docscan_inspect_ole(data, block->size, &r);
      break;
    case DOCSCAN_TYPE_RTF:
      yr_set_integer(1, module_object, "is_rtf");
      docscan_inspect_rtf(data, block->size, &r);
      break;
    case DOCSCAN_TYPE_PDF:
      yr_set_integer(1, module_object, "is_pdf");
      docscan_inspect_pdf(data, block->size, &r);
      break;
    case DOCSCAN_TYPE_LNK:
      yr_set_integer(1, module_object, "is_lnk");
      docscan_inspect_lnk(data, block->size, &r);
      break;
    default:
      break;
    }

    // A document scan delivers the whole file in the first block.
    break;
  }

  // Map the collected results onto the module's fields (0/"" if not set).
  yr_set_integer(r.rtf_objupdate, module_object, "rtf_objupdate");
  yr_set_integer(r.rtf_embedded_object, module_object, "rtf_embedded_object");
  yr_set_integer(r.pdf_launch, module_object, "pdf_launch");
  yr_set_integer(r.pdf_js_auto, module_object, "pdf_js_auto");
  yr_set_integer(r.pdf_js, module_object, "pdf_js");
  yr_set_integer(r.pdf_openaction, module_object, "pdf_openaction");
  yr_set_integer(r.pdf_embedded, module_object, "pdf_embedded");

  yr_set_integer(r.remote_template, module_object, "remote_template");
  yr_set_integer(r.protocol_handler, module_object, "protocol_handler");
  yr_set_integer(r.dde_auto, module_object, "dde_auto");
  yr_set_integer(r.embedded_lnk, module_object, "embedded_lnk");
  yr_set_integer(r.embedded_pe, module_object, "embedded_pe");
  yr_set_integer(r.macro_present, module_object, "macro_present");
  yr_set_integer(r.macro_suspicious, module_object, "macro_suspicious");
  yr_set_integer(r.external_ole, module_object, "external_ole");
  yr_set_integer(r.external_frame, module_object, "external_frame");
  yr_set_integer(r.dde_link, module_object, "dde_link");

  yr_set_integer(r.lnk_lolbin, module_object, "lnk_lolbin");
  yr_set_integer(r.lnk_url_args, module_object, "lnk_url_args");
  yr_set_integer(r.lnk_obfuscated, module_object, "lnk_obfuscated");

  yr_set_string(r.template_url, module_object, "template_url");
  yr_set_string(r.dde_command, module_object, "dde_command");
  yr_set_string(r.vba_evidence, module_object, "vba_evidence");
  yr_set_string(r.lnk_target, module_object, "lnk_target");
  yr_set_string(r.lnk_args, module_object, "lnk_args");

  if (r.vba_code != NULL)
  {
    yr_set_sized_string(
        r.vba_code, r.vba_code_len, module_object, "vba_code");
    free(r.vba_code);
  }
  else
  {
    yr_set_string("", module_object, "vba_code");
  }

  return ERROR_SUCCESS;
}

int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}
