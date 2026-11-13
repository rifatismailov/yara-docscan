#!/usr/bin/env bash
# Fetch extra, openly licensed seed files for the docscan fuzzers.
#
#   docscan-project/fuzz/fetch_corpus.sh [DEST]   (default: docscan-project/fuzz/external)
#
# Only the needed test-data folders are downloaded (sparse checkout, no history).
# DEST is git-ignored: third-party files are never committed.
#
#   poi       Apache POI test-data       Apache-2.0  doc/docx/xls/xlsx/ppt/pptx, CFB edge cases, macros
#   pdfjs     Mozilla pdf.js test/pdfs   Apache-2.0  PDFs incl. broken ones
#   plaso     plaso test_data            Apache-2.0  LNK, OLE, Office files from forensics tests
#   lo-rtf    LibreOffice RTF import QA  MPL-2.0     RTF edge cases
#   lnk       EricZimmerman/Lnk tests    MIT         ~550 LNK from many Windows versions, incl. Bad/
#   pylnk     strayge/pylnk examples     LGPL-3.0    a few more LNK variants
#   tika      Apache Tika test-documents Apache-2.0  OneNote .one, dotm/xlam/pptm/ppsm/potm/xlsb, encrypted
#                                                    Office files, PDFs with JS / attachments
#   oletools  decalage2/oletools tests   BSD-2       DDE, OLE Package exe/lnk, Excel 4.0 macros (xls/xlsb/
#                                                    xltm/slk), external links, encrypted docs (incl. the
#                                                    default "VelvetSweatshop" password that opens silently)
#
# Not here (never in the repository): the EICAR test file and real malware samples - they live in
# ~/docscan-ci/malware (see docscan-project/ci/README.md, "Malware detection test").
set -euo pipefail

DEST=${1:-$(cd "$(dirname "$0")" && pwd)/external}
mkdir -p "$DEST"
cd "$DEST"

fetch() {  # fetch <name> <url> <dir>...
  local name=$1 url=$2; shift 2
  if [ ! -d "$name/.git" ]; then
    git clone -q --depth 1 --filter=blob:none --sparse "$url" "$name"
  fi
  local dirs=()
  for d in "$@"; do dirs+=("/$d/"); done
  git -C "$name" sparse-checkout set --no-cone "${dirs[@]}"
  printf '%-8s %6s files  %s\n' "$name" \
    "$(find "$name" -type f -not -path '*/.git/*' | wc -l | tr -d ' ')" \
    "$(du -sh "$name" | cut -f1)"
}

fetch poi    https://github.com/apache/poi.git \
  test-data/document test-data/spreadsheet test-data/slideshow test-data/poifs test-data/openxml4j
fetch pdfjs  https://github.com/mozilla/pdf.js.git test/pdfs
fetch plaso  https://github.com/log2timeline/plaso.git test_data
fetch lo-rtf https://github.com/LibreOffice/core.git \
  sw/qa/extras/rtfimport/data sw/qa/extras/rtfexport/data writerfilter/qa/cppunittests/rtftok/data
fetch lnk    https://github.com/EricZimmerman/Lnk.git Lnk.Test/TestFiles
fetch pylnk  https://github.com/strayge/pylnk.git tests/examples
TIKA=tika-parsers/tika-parsers-standard/tika-parsers-standard-modules
fetch tika   https://github.com/apache/tika.git \
  $TIKA/tika-parser-microsoft-module/src/test/resources/test-documents \
  $TIKA/tika-parser-pdf-module/src/test/resources/test-documents \
  $TIKA/tika-parser-miscoffice-module/src/test/resources/test-documents
fetch oletools https://github.com/decalage2/oletools.git tests/test-data
