// Full DocScan index — one command does everything:
//
//   yara64.exe --docscan-json [--docscan-disarm] docscan-index.yar <file>
//
// 1) docscan-policy.yar: import "docscan" + policy rules (meta.severity) ->
//    "findings", "verdict", "details" and what --docscan-disarm removes.
// 2) file-index.yar: vendor rules (no meta.severity). Each one is applied to
//    the raw file -> "yara_file_matches", and to the decompressed VBA (Layer 2)
//    -> "yara_matches".
//
// Paths are relative to this file. Add your own rules with more include lines.
include "docscan-policy.yar"
include "file-index.yar"
