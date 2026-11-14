#!/bin/sh
# DocScan CI for macOS and Linux: build -> document regression -> third-pass tests
# -> hostile files (if a seed corpus is given) -> fuzzing -> artifacts.
#
#   sh docscan-project/ci/build-test-unix.sh [all|build|test]
#     all   (default) build, then every test
#     build only the build (cirun: Platform.Build)
#     test  only the tests on an existing build (cirun: Platform.Test); appends to summary.txt
# Environment:
#   CI_OUT        output folder (default: <repo>/ci-out)
#   FUZZ_SECONDS  fuzzing time in seconds, split between the two fuzzers (default 300, 0 = skip)
#   CI_SEEDS      folder with converted corpus documents (tp_07.docx, tp_07.doc, tp_05.xls, tp_02.ppt ...)
#                 for hostile.py; empty = skip that step
# Exit code != 0 if any step fails; a summary is in $CI_OUT/summary.txt.
set -u
STAGE=${1:-all}
case "$STAGE" in all|build|test) ;; *) echo "usage: $0 [all|build|test]"; exit 2 ;; esac
REPO=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${CI_OUT:-$REPO/ci-out}
case "$OUT" in /*) ;; *) OUT="$REPO/$OUT" ;; esac
FUZZ_SECONDS=${FUZZ_SECONDS:-300}
OS=$(uname -s)
mkdir -p "$OUT/artifacts"
SUMMARY="$OUT/summary.txt"
[ "$STAGE" = test ] || : > "$SUMMARY"
FAILED=0

step() {  # step <name> <command...>: run, log, record the result
  name=$1; shift
  echo "::group::$name"
  start=$(date +%s)
  if "$@" > "$OUT/$name.log" 2>&1; then res=PASS; else res=FAIL; FAILED=1; fi
  tail -25 "$OUT/$name.log"
  echo "::endgroup::"
  printf '%-14s %s  (%ss)\n' "$name" "$res" "$(( $(date +%s) - start ))" | tee -a "$SUMMARY"
}

cd "$REPO" || exit 1
if [ "$OS" = Darwin ]; then
  export LIBTOOLIZE=glibtoolize PATH="/opt/homebrew/bin:$PATH"
  JOBS=$(sysctl -n hw.ncpu)
else
  JOBS=$(nproc)
fi

build() {
  [ -f Makefile ] || { ./bootstrap.sh && ./configure; } || return 1
  make -j"$JOBS" && ./yara --version
}
[ "$STAGE" = test ] || step build build
[ -x ./yara ] || { echo "no yara binary - stop"; cat "$SUMMARY"; exit 1; }
if [ "$STAGE" = build ]; then
  cp "$OUT"/*.log "$SUMMARY" "$OUT/artifacts/" 2>/dev/null
  echo; echo "===== $OS build"; cat "$SUMMARY"; exit $FAILED
fi

step documents python3 docscan-project/ci/check_verdicts.py --yara ./yara \
  --rules docscan-project/rules/docscan-index.yar \
  --samples docscan-project/test-samples/generated \
  --expected docscan-project/ci/expected-verdicts.tsv

step critical python3 docscan-project/test-critical/run_tests.py --yara ./yara

if [ -n "${CI_SEEDS:-}" ] && [ -d "${CI_SEEDS:-}" ]; then
  hostile() {
    rm -rf "$OUT/hostile" && python3 docscan-project/test-critical/hostile.py "$CI_SEEDS" "$OUT/hostile" &&
    python3 docscan-project/test-critical/hostile_run.py ./yara docscan-project/rules/docscan-index.yar \
      docscan-project/test-critical/crit-test.yar "$OUT/hostile" 120
  }
  step hostile hostile
  rm -rf "$OUT/hostile"
else
  echo "hostile        SKIP  (no CI_SEEDS)" | tee -a "$SUMMARY"
fi

# corpus: documents from public test corpora (cirun test assets); verdicts -> corpus-verdicts.tsv, which
# cirun compares between the platforms
if [ -n "${CI_CORPUS:-}" ] && [ -d "${CI_CORPUS:-}" ]; then
  corpus() {
    python3 docscan-project/ci/check_corpus.py --yara ./yara --yarac ./yarac \
      --rules docscan-project/rules/docscan-index.yar --dir "$CI_CORPUS" --out "$OUT/corpus-verdicts.tsv" &&
    cp "$OUT/corpus-verdicts.tsv" "$OUT/artifacts/"
  }
  step corpus corpus
else
  echo "corpus         SKIP  (no CI_CORPUS)" | tee -a "$SUMMARY"
fi

# malware: real samples, ONLY scanned (never executed); files in expected.txt must get a vendor match
if [ -n "${CI_MALWARE:-}" ] && [ -d "${CI_MALWARE:-}" ]; then
  malware() {
    python3 docscan-project/ci/check_corpus.py --yara ./yara --yarac ./yarac \
      --rules docscan-project/rules/docscan-index.yar --dir "$CI_MALWARE" --out "$OUT/malware-verdicts.tsv" \
      --expect "$CI_MALWARE/expected.txt" &&
    cp "$OUT/malware-verdicts.tsv" "$OUT/artifacts/"
  }
  step malware malware
else
  echo "malware        SKIP  (no CI_MALWARE)" | tee -a "$SUMMARY"
fi

if [ "$FUZZ_SECONDS" -gt 0 ]; then
  fuzz() {
    B="$OUT/fuzz"
    sh docscan-project/fuzz/build.sh "$B" || return 1
    half=$(( FUZZ_SECONDS / 2 )); [ "$half" -lt 10 ] && half=10
    mkdir -p "$B/crashes"
    ( cd "$B" && ./docscan_parsers_fuzzer -dict="$REPO/docscan-project/fuzz/docscan.dict" -max_len=262144 \
        -max_total_time=$half -timeout=20 -rss_limit_mb=2048 -artifact_prefix=crashes/ corpus/parsers ) > "$B/parsers.log" 2>&1 &
    p1=$!
    ( cd "$B" && ./docscan_fuzzer -dict="$REPO/docscan-project/fuzz/docscan.dict" -max_len=262144 \
        -max_total_time=$half -timeout=20 -rss_limit_mb=2048 -artifact_prefix=crashes/ corpus/module ) > "$B/module.log" 2>&1 &
    p2=$!
    wait $p1; r1=$?; wait $p2; r2=$?
    grep -h "^Done" "$B/parsers.log" "$B/module.log"
    # failures: crash-* / timeout-* / oom-* / leak-*; slow-unit-* (one run took > 10 s) is only reported
    n=$(ls "$B/crashes" | grep -cE '^(crash|timeout|oom|leak)-' || true)
    echo "crash/timeout inputs: $n"
    for s in "$B"/crashes/slow-unit-*; do [ -e "$s" ] && echo "slow input (not a failure): $(basename "$s")"; done
    if [ -n "$(ls "$B/crashes")" ]; then cp -r "$B/crashes" "$OUT/artifacts/fuzz-crashes"; fi
    [ "$r1" -eq 0 ] && [ "$r2" -eq 0 ] && [ "$n" -eq 0 ]
  }
  step fuzz fuzz
else
  echo "fuzz           SKIP  (FUZZ_SECONDS=0)" | tee -a "$SUMMARY"
fi

# artifacts: the binaries + logs
tar -czf "$OUT/artifacts/yara-$(echo "$OS" | tr 'A-Z' 'a-z')-$(uname -m).tar.gz" yara yarac 2>/dev/null
cp "$OUT"/*.log "$SUMMARY" "$OUT/artifacts/" 2>/dev/null
echo; echo "===== $OS summary"; cat "$SUMMARY"
exit $FAILED
