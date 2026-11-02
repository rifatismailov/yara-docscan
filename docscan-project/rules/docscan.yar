// Our detection only: the docscan module + the default policy (no vendor rules).
//
//   yara64.exe --docscan-json docscan.yar <file>
//
// Severity, finding names and disarm actions live in docscan-policy.yar.
include "docscan-policy.yar"
