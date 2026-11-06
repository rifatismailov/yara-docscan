# DocScan setup bootstrap. Run in PowerShell as Administrator:
#   irm http://<server>:8080/docscan/DocScan-Setup.ps1 | iex          # full mode (detection + disarm)
#   irm http://<server>:8080/docscan/DocScan-Setup-Pilot.ps1 | iex    # pilot: detection and alerts only
#
# ASCII only, no BOM: "irm | iex" decodes the text without a charset. Everything runs inside one
# script block, so nothing leaks into the calling session. It downloads DocScan-Install.ps1 (the
# real, UTF-8 installer script) and runs it in a separate powershell.exe: errors never close this
# window, and the output is readable.
& {
  $BaseUrl    = 'http://<server>:8080/docscan'   # where DocScan-Install.ps1, DocScan-latest.txt and the package are
  $InstallArg = @()                      # pilot copy: @('-DetectOnly')
  $ProgressPreference = 'SilentlyContinue'
  $f = Join-Path $env:TEMP ('DocScan-Install-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.ps1')
  try {
    Invoke-WebRequest -UseBasicParsing "$BaseUrl/DocScan-Install.ps1" -OutFile $f
    # 64-bit PowerShell even when started from a 32-bit console (sysnative exists only for 32-bit processes)
    $ps = Join-Path $env:windir 'sysnative\WindowsPowerShell\v1.0\powershell.exe'
    if (-not (Test-Path $ps)) { $ps = 'powershell.exe' }
    & $ps -NoProfile -ExecutionPolicy Bypass -File $f -BaseUrl $BaseUrl @InstallArg
    if ($LASTEXITCODE -ne 0) { Write-Host "DocScan setup failed (exit code $LASTEXITCODE)" -ForegroundColor Red }
  } catch {
    Write-Host ('DocScan setup: ' + $_.Exception.Message) -ForegroundColor Red
  } finally {
    Remove-Item $f -Force -ErrorAction SilentlyContinue
  }
}
