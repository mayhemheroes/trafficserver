#!/usr/bin/env bash
#
# mayhem/test.sh — RUN the http_kat_test binary mayhem/build.sh already built (never compiles here).
#
# http_kat_test (mayhem/harnesses/http_kat_test.cc) is a mayhemheroes-added functional oracle for
# the REAL production HTTP/1.x request parser (proxy/hdrs/HTTP.cc's HTTPHdr::parse_req(), via
# HTTPParser/HdrHeap) — the exact code tests/fuzzing/fuzz_http.cc fuzzes. Upstream ships no
# assertion-based unit test for this path (only the libFuzzer harness, which never asserts
# anything), so this closes that gap: it feeds two FIXED, well-formed HTTP/1.1 requests through the
# unmodified production parser and asserts the parsed method / URL path / Host header against
# exact, independently known values (see the harness for the derivation — they're not invented here,
# they're the real behavior: query strings stripped, leading '/' stripped by URL::path_get()).
#
# A no-op/`exit(0)` neuter of the binary produces NO markers at all, so this script fails as soon as
# it can't find the expected "match=1" / "SUMMARY failures=0" lines — not just "did it exit 0".
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

KAT_BIN="/mayhem/http_kat_test"
if [ ! -x "$KAT_BIN" ]; then
  echo "MISSING http_kat_test: $KAT_BIN (mayhem/build.sh should have built it)" >&2
  emit_ctrf "trafficserver-http-kat" 0 1
  exit 1
fi

out="$("$KAT_BIN" 2>&1)"; rc=$?
echo "=== http_kat_test ===" >&2
echo "$out" >&2

# Each case asserts 4 fields (parse_result, method, path, host); we ship 2 cases = 8 checks.
match_count="$(printf '%s\n' "$out" | grep -c 'match=1' || true)"
summary_line="$(printf '%s\n' "$out" | grep -E '^HTTP_KAT SUMMARY failures=' | tail -1 || true)"

passed=0
failed=0
if [ "$rc" -eq 0 ] && [ "$summary_line" = "HTTP_KAT SUMMARY failures=0" ] && [ "${match_count:-0}" -eq 8 ]; then
  passed=8
else
  echo "http_kat_test did not produce the expected passing markers (rc=$rc, matches=${match_count:-0}, summary='${summary_line}')" >&2
  failed=8
fi

emit_ctrf "trafficserver-http-kat" "$passed" "$failed"
