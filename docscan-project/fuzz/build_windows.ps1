# Build the docscan parser fuzzer on Windows (clang-cl + libFuzzer + ASan).
#
#   powershell -ExecutionPolicy Bypass -File build_windows.ps1 [-Repo C:\docscan-build\yara] [-Out C:\docscan-build\fuzz]
#
# Needs LLVM for Windows (choco install llvm) and VS Build Tools (linker, SDK).
# Only the parser fuzzer: it covers every docscan parser and the disarm code,
# including the Windows-only wide-char file paths. The whole-module fuzzer
# needs libyara built with clang and stays on macOS/Linux (fuzz/build.sh).
param(
  [string]$Repo = "C:\docscan-build\yara",
  [string]$Out  = "C:\docscan-build\fuzz",
  [string]$Llvm = "C:\Program Files\LLVM"
)
$ErrorActionPreference = "Stop"
New-Item -ItemType Directory -Force $Out | Out-Null
$vs = & "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -products * -latest -property installationPath
$vcvars = Join-Path $vs "VC\Auxiliary\Build\vcvars64.bat"
$m = "$Repo\libyara\modules\docscan"
$src = "inspect_ooxml inspect_ole inspect_rtf inspect_pdf lnk rels zip miniz cfb oleobj msovba vba search magic disarm text critical" -split " " |
       % { "`"$m\$_.c`"" }
# /MT: libFuzzer for Windows links the static CRT; /MD objects would not resolve.
$cmd = "`"$Llvm\bin\clang-cl.exe`" /nologo /O1 /Zi /MT -fsanitize=address,fuzzer " +
       "/I`"$Repo\libyara\include`" /I`"$m`" /D_CRT_SECURE_NO_WARNINGS " +
       "`"$Repo\docscan-project\fuzz\docscan_parsers_fuzzer.cc`" $($src -join ' ') " +
       "/Fe`"$Out\docscan_parsers_fuzzer.exe`" /Fo`"$Out\\`" /link /INCREMENTAL:NO"
$log = cmd /c "call `"$vcvars`" >nul && $cmd 2>&1"
$log | Select-String -Pattern "error" | % { $_.Line }
if (-not (Test-Path "$Out\docscan_parsers_fuzzer.exe")) { Write-Host "BUILD FAILED"; exit 1 }
# ASan on Windows always uses the dynamic runtime (even with /MT): ship it next to the exe.
Get-ChildItem "$Llvm\lib\clang" -Recurse -Filter "clang_rt.asan_dynamic-x86_64.dll" | Select -First 1 |
  % { Copy-Item $_.FullName $Out -Force }
Write-Host "Built: $Out\docscan_parsers_fuzzer.exe"
