# Safe smoke test for the Wazuh CommandRunner.
# Runs as the Wazuh agent account (normally LocalSystem) and creates a marker
# in that account's TEMP directory (usually C:\Windows\Temp).

$ErrorActionPreference = 'Stop'

try {
  $tempDir = $env:TEMP
  if (-not $tempDir) { throw 'TEMP is not set for the Wazuh agent process.' }
  if (-not (Test-Path -LiteralPath $tempDir -PathType Container)) {
    New-Item -ItemType Directory -Path $tempDir -Force | Out-Null
  }

  $marker = Join-Path $tempDir 'Wazuh.txt'
  Set-Content -LiteralPath $marker -Value 'Wazuh installed' -Encoding ASCII
  Write-Output ("Created " + $marker)
} catch {
  Write-Output ("Wazuh runner test failed: " + $_.Exception.Message)
  exit 1
}
