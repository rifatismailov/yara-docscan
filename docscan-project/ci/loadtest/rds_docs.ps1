# DocScan load test: copy the test document sets from the file share to the test terminal server (once).
#   rds_docs.ps1 -Share \\<fileserver>\share [-User <share user> -Password <pw>] [-Dest C:\loadtest\docs]
# Sets (folders under <Share>\yara): test-samples (42 inert attack vectors), seeds (tp / fp / tph / fph documents in
# 8 formats, critical-information positives among them), corpus (public test corpora). Malware is NOT copied.
# C:\loadtest is outside C:\Users, so the watcher does not scan the source copies.

param(
  [Parameter(Mandatory = $true)][string]$Share,
  [string]$User = "",
  [string]$Password = "",
  [string]$Dest = "C:\loadtest\docs",
  [string[]]$Sets = @("test-samples", "seeds", "corpus")
)
$ErrorActionPreference = "Stop"
if ($User) { net use $Share /user:$User $Password | Out-Null }
try {
  foreach ($s in $Sets) {
    $src = Join-Path $Share "yara\$s"
    if (-not (Test-Path -LiteralPath $src)) { throw "not found: $src" }
    $rl = Join-Path $env:TEMP "rds_docs-$s.log"
    robocopy $src (Join-Path $Dest $s) /MIR /R:1 /W:1 /NP /NDL /NJH /XF .DS_Store "/LOG:$rl" | Out-Null
    $rc = $LASTEXITCODE
    $n = (Get-ChildItem (Join-Path $Dest $s) -Recurse -File).Count
    "{0,-14} {1} files (robocopy exit {2})" -f $s, $n, $rc
    # exit >= 8: some files were not copied - usually the local antivirus blocks an attack-vector sample
    if ($rc -ge 8) { Select-String -Path $rl -Pattern "ERROR \d+ \(0x" | Select -First 10 | % { "  " + $_.Line.Trim() } }
  }
} finally {
  if ($User) { net use $Share /delete /y | Out-Null }
}
