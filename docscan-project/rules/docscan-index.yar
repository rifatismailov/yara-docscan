// DocScan index for the ONE-COMMAND auto-rescan flow:
//
//   yara64.exe --docscan-json docscan-index.yar <document>
//
// 1) import "docscan" loads our module -> structural detection + VBA extraction.
// 2) Every rule included below is auto-applied by yara64.exe to the DECOMPRESSED
//    VBA (Layer 2) -> matches appear in the JSON as "yara_matches":[...].
//
// Add vendor / critical-info rules with more `include` lines. Paths are relative
// to THIS file. Keep only rules that compile standalone (no missing modules/vars).

import "docscan"

include "maldoc/signature-base/gen_macro_ShellExecute_action.yar"
// include "maldoc/signature-base/gen_maldoc.yar"
// include "maldoc/signature-base/general_officemacros.yar"
// include "../reference/vendor-rules-full-later/..."   // full corpus (adjust path)
// include "crit/critinfo.yar"                           // Function 3 (critical info)
