#!/bin/sh
# Build the docscan libFuzzer targets with ASan + UBSan.
#
#   docscan-project/fuzz/build.sh [BUILD_DIR]      (default: /tmp/docscan-fuzz)
#
# Needs a clang with libFuzzer: on macOS `brew install llvm` (Apple clang has
# no libFuzzer runtime); on Linux the distro clang is fine. Set LLVM=... to
# override the toolchain prefix.
set -eu

REPO=$(cd "$(dirname "$0")/../.." && pwd)
FUZZ="$REPO/docscan-project/fuzz"
BUILD=${1:-/tmp/docscan-fuzz}
LLVM=${LLVM:-$( [ -d /opt/homebrew/opt/llvm ] && echo /opt/homebrew/opt/llvm || echo /usr )}
CC="$LLVM/bin/clang"
CXX="$LLVM/bin/clang++"
# -fno-sanitize=function: upstream libyara calls destructors through a generic
# pointer type (hash.c:218), which aborts every run before docscan is reached.
SAN="-fsanitize=address,undefined -fno-sanitize=function -fno-sanitize-recover=undefined"

# Separate tree: the in-tree (non-fuzz) build must not be disturbed.
mkdir -p "$BUILD"
rsync -a --delete \
  --exclude .git --exclude docscan-project --exclude attack-vectors \
  --exclude '*.o' --exclude '*.lo' --exclude '*.la' --exclude .libs --exclude .deps \
  --exclude Makefile --exclude config.status --exclude config.log --exclude libtool \
  --exclude /yara --exclude /yarac --exclude stamp-h1 --exclude libyara/config.h \
  "$REPO/" "$BUILD/src/"

cd "$BUILD/src"
CC="$CC" CFLAGS="-g -O1 -fno-omit-frame-pointer -fsanitize=fuzzer-no-link $SAN" \
  ./configure --disable-shared --enable-static --without-crypto >"$BUILD/configure.log" 2>&1
make clean >/dev/null 2>&1 || true    # CFLAGS changes do not trigger a rebuild
make -j8 libyara.la >"$BUILD/make.log" 2>&1

INC="-I$BUILD/src/libyara/include -I$BUILD/src/libyara/modules/docscan"
LIB="$BUILD/src/.libs/libyara.a"
for t in docscan_fuzzer docscan_parsers_fuzzer; do
  "$CXX" -g -O1 -fsanitize=fuzzer $SAN $INC "$FUZZ/$t.cc" "$LIB" -lm -lpthread -o "$BUILD/$t"
done

# Every input that ever crashed/hung a fuzzer must stay fixed.
# regressions/module-*  -> docscan_fuzzer, regressions/parsers-* -> docscan_parsers_fuzzer
fail=0
for f in "$FUZZ"/regressions/*; do
  case "$(basename "$f")" in
    module-*) t=docscan_fuzzer ;;
    *)        t=docscan_parsers_fuzzer ;;
  esac
  if "$BUILD/$t" -timeout=10 -rss_limit_mb=2048 "$f" >"$BUILD/regression.log" 2>&1; then
    echo "ok    $(basename "$f")"
  else
    echo "FAIL  $(basename "$f")  (see $BUILD/regression.log)"
    fail=1
  fi
done
[ "$fail" -eq 0 ] || { echo "Regression inputs fail — fix before fuzzing further."; exit 1; }

EXTRA=""; [ -d "$FUZZ/external" ] && EXTRA="$FUZZ/external"    # fetch_corpus.sh
python3 "$FUZZ/make_corpus.py" "$BUILD/corpus" "$REPO/docscan-project/test-samples" $EXTRA

cat <<EOF

Built: $BUILD/docscan_fuzzer  $BUILD/docscan_parsers_fuzzer
Run (Ctrl+C to stop; crashes are saved as crash-* in the current dir):
  cd $BUILD
  ./docscan_fuzzer         -dict=$FUZZ/docscan.dict -max_len=262144 corpus/module
  ./docscan_parsers_fuzzer -dict=$FUZZ/docscan.dict -max_len=262144 corpus/parsers
Reproduce a crash:  ./docscan_parsers_fuzzer crash-<sha1>
After fixing it, copy the input to $FUZZ/regressions/ with a descriptive name.
EOF
