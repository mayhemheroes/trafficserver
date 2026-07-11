#!/usr/bin/env bash
#
# mayhem/build.sh — build SIX of Apache Traffic Server's OSS-Fuzz libFuzzer harnesses
# (tests/fuzzing/*.cc, unmodified) as sanitized fuzz binaries (+ standalone reproducers), plus a
# functional KAT test binary for mayhem/test.sh.
#
# Targets built (from tests/fuzzing/CMakeLists.txt):
#   fuzz_hpack           — proxy/http2 HPACK header-block decoder (hpack_decode_header_block)
#   fuzz_http            — proxy/hdrs + proxy/http HTTP/1.x request & response line/header parser
#   fuzz_json            — lib/swoc + yaml-cpp + mgmt/rpc JSONRPC message parsing
#   fuzz_proxy_protocol  — iocore/net PROXY protocol v1/v2 header parser
#   fuzz_rec_http        — records (records.yaml) + tscore/libswoc parsing surface
#   fuzz_yamlcpp         — lib/yamlcpp YAML parser (upstream vendored yaml-cpp)
#
# fuzz_hpack / fuzz_http are NOT shipped from upstream's own tests/fuzzing/fuzz_hpack.cc /
# fuzz_http.cc object code: those two harnesses call HTTPHdr::create() (-> new_HdrHeap() ->
# this_ethread()) with no ATS EThread ever registered on libFuzzer's driver thread, so
# this_ethread() is null and every parse short-circuits before reaching the instrumented
# HPACK/HTTP decode code — 0 edges, even though the binaries ARE instrumented (coverage counters
# load fine). Section 2 below instead compiles our OWN copies, mayhem/harnesses/fuzz_hpack.cc and
# fuzz_http.cc, which bring up a real EThread first (mirroring mayhem/harnesses/http_kat_test.cc's
# proven bring-up) and then run the exact same parse logic as upstream's harnesses. Upstream's
# tests/fuzzing/fuzz_hpack.cc / fuzz_http.cc are left completely untouched (still built by cmake
# below as an unused byproduct, so their transitive library objects — proxy/hdrs, proxy/http2,
# etc. — get compiled and are available to relink against).
#
# NOT built: fuzz_http3frame (proxy/http3 QUIC frame parser). Its CMake target links `ts::quic`,
# which upstream's OWN tests/fuzzing/oss-fuzz.sh only satisfies by building a full BoringSSL +
# quiche + Rust-nightly HTTP/3 stack from source (tools/build_h3_tools.sh) — and worse, once that's
# turned on (-DENABLE_QUICHE=ON), `inknet` itself (a dependency of fuzz_hpack/fuzz_proxy_protocol)
# gains extra QUICNet*.cc translation units that call real quiche APIs, so it isn't a narrow,
# containable dependency. That closure is out of scope for this pass (heavy, hard to air-gap — see
# mayhem/cmake/mayhem-quic-stub.cmake for the full explanation and the workaround that lets the
# other six targets configure/build without it).
#
# Build contract (base image ENV) — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF < 4; Mayhem's triage can't read DWARF >= 4)
#   SRC                 /mayhem
#   STANDALONE_FUZZ_MAIN  /opt/mayhem/StandaloneFuzzTargetMain.c
set -euo pipefail

[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
export SANITIZER_FLAGS DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

cd "$SRC"

# ALL_TARGETS: everything cmake builds (need fuzz_hpack/fuzz_http's own compile+link so their
# transitive deps — proxy/hdrs, proxy/http2, tscore, iocore/eventsystem, records, … — are
# available to link our EThread-aware replacements against; see WRAPPER_TARGETS below).
# GENERIC_TARGETS: shipped AS-IS from upstream's own tests/fuzzing/*.cc (unmodified, already get
# edges — no EThread problem).
# WRAPPER_TARGETS: shipped from OUR mayhem/harnesses/*.cc copies instead (section 2 below).
ALL_TARGETS=(fuzz_hpack fuzz_http fuzz_json fuzz_proxy_protocol fuzz_rec_http fuzz_yamlcpp)
GENERIC_TARGETS=(fuzz_json fuzz_proxy_protocol fuzz_rec_http fuzz_yamlcpp)
WRAPPER_TARGETS=(fuzz_hpack fuzz_http)

# ── 1) SANITIZED fuzz build: ATS's OWN cmake fuzz targets (tests/fuzzing/, wired in via the
#      project's native -DENABLE_FUZZING=ON path), built with $SANITIZER_FLAGS + $DEBUG_FLAGS +
#      -fsanitize=fuzzer-no-link. That last flag is the one that actually matters for Mayhem: ATS's
#      own tests/fuzzing/CMakeLists.txt only adds $LIB_FUZZING_ENGINE (-fsanitize=fuzzer) via
#      CMAKE_EXE_LINKER_FLAGS at the FINAL link step of each fuzz_* binary — it never lands on the
#      compile line for any of the fuzzed library code (proxy/hdrs, proxy/http2, records,
#      iocore/net, lib/swoc, lib/yamlcpp, …) or even the harness .cc itself. Without
#      -fsanitize=fuzzer-no-link on CMAKE_C_FLAGS/CMAKE_CXX_FLAGS, NONE of that code carries
#      SanitizerCoverage instrumentation, so libFuzzer/Mayhem observe a flat 0-edge coverage map
#      (clean smoke run, no crashes, just no signal). Adding fuzzer-no-link here is the standard
#      OSS-Fuzz split: compile everything with the no-link coverage flag, link only the final
#      fuzz_* binary against the real libFuzzer runtime via $LIB_FUZZING_ENGINE (already wired
#      above via CMAKE_EXE_LINKER_FLAGS) — the two are compatible (fuzzer-no-link is a strict
#      subset of fuzzer's instrumentation).
#      -DCMAKE_PROJECT_INCLUDE injects mayhem/cmake/mayhem-quic-stub.cmake so configure succeeds
#      without fuzz_http3frame's ts::quic dependency (see that file for why). ENABLE_QUICHE is left
#      at its default OFF, so this is a plain, real-OpenSSL build — no quiche/BoringSSL anywhere.
#      -DCMAKE_CXX_SCAN_FOR_MODULES=OFF avoids needing clang-scan-deps (C++20 P1689 dep-scanning),
#      which the base image doesn't ship and which this project doesn't need.
#      Building just these 6 named targets (not `all`) compiles only what they transitively depend
#      on (proxy/hdrs, proxy/http2, records, iocore/eventsystem, iocore/net, lib/swoc, lib/yamlcpp,
#      mgmt/rpc/jsonrpc_protocol, …) — not traffic_server/traffic_ctl/the cache/the plugin API.
COVERAGE_FLAGS="-fsanitize=fuzzer-no-link"
BUILD_FUZZ="$SRC/mayhem-build-fuzz"
rm -rf "$BUILD_FUZZ"
cmake -S "$SRC" -B "$BUILD_FUZZ" -G Ninja \
  -DCMAKE_C_COMPILER="$CC" -DCMAKE_CXX_COMPILER="$CXX" \
  -DCMAKE_CXX_SCAN_FOR_MODULES=OFF \
  -DENABLE_FUZZING=ON -DENABLE_POSIX_CAP=OFF -DYAML_BUILD_SHARED_LIBS=OFF \
  -DENABLE_HWLOC=OFF -DENABLE_JEMALLOC=OFF -DENABLE_LUAJIT=OFF \
  -DCMAKE_PROJECT_INCLUDE="$SRC/mayhem/cmake/mayhem-quic-stub.cmake" \
  -DCMAKE_C_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $COVERAGE_FLAGS" \
  -DCMAKE_CXX_FLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS $COVERAGE_FLAGS" \
  -DCMAKE_EXE_LINKER_FLAGS="$SANITIZER_FLAGS" -DCMAKE_BUILD_TYPE=
cmake --build "$BUILD_FUZZ" -j"$MAYHEM_JOBS" --target "${ALL_TARGETS[@]}"

# All 6 targets dynamically link libswoc.so.1 at runtime. tests/fuzzing/CMakeLists.txt bakes
# RUNPATH=$ORIGIN/lib into every binary in that directory and (only for fuzz_http) copies libswoc
# into a lib/ dir next to the *build-tree* binary — but $ORIGIN/lib is NOT a safe place for us to
# drop a file once these binaries are copied to $OUT=/mayhem: /mayhem/lib is upstream's OWN vendored
# third-party source directory (lib/yamlcpp, lib/swoc, lib/fastlz, …), not build output, and must
# stay untouched. Instead, `patchelf --set-rpath` every shipped binary (fuzz targets, standalone
# reproducers, the KAT test) to a dedicated, collision-free runtime-lib directory we own.
RTLIB_DIR="/mayhem/mayhem-rt-lib"
mkdir -p "$RTLIB_DIR"
libswoc_real="$(find "$BUILD_FUZZ/lib/swoc" -name 'libswoc.so.*.*.*' -type f | head -1)"
cp "$libswoc_real" "$RTLIB_DIR/libswoc.so.1"

# Standalone driver object (no libFuzzer runtime; StandaloneFuzzTargetMain.c is C, so it's compiled
# once here and re-linked into each C++ harness below — clang++ would otherwise mangle its
# LLVMFuzzerTestOneInput reference).
STANDALONE_OBJ="$BUILD_FUZZ/standalone_main.o"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$STANDALONE_FUZZ_MAIN" -o "$STANDALONE_OBJ"

for t in "${GENERIC_TARGETS[@]}"; do
  cp "$BUILD_FUZZ/tests/fuzzing/$t" "/mayhem/$t"
  patchelf --set-rpath "$RTLIB_DIR" "/mayhem/$t"

  # Standalone reproducer: re-link the SAME compiled objects (ninja's own recorded link command for
  # this target), swapping $LIB_FUZZING_ENGINE (-fsanitize=fuzzer) for the standalone driver object
  # and retargeting the output path — same technique used by every other mayhemheroes C/C++ port.
  # NOTE: the substitution must anchor on a trailing space/EOL (ERE `(-no-link)?` won't do — we
  # want the opposite: NOT matching), because $LIB_FUZZING_ENGINE (-fsanitize=fuzzer) is now a
  # literal PREFIX of $COVERAGE_FLAGS (-fsanitize=fuzzer-no-link), which also appears on this same
  # link line via CMAKE_CXX_FLAGS (clang++ passes CXX_FLAGS at link time too). An unanchored sed
  # would mangle "-fsanitize=fuzzer-no-link" into "$STANDALONE_OBJ-no-link" (bogus, no such file).
  link_cmd="$(ninja -C "$BUILD_FUZZ" -t commands "$t" | tail -1)"
  standalone_cmd="$(printf '%s' "$link_cmd" | sed -E \
    -e "s#$LIB_FUZZING_ENGINE(\$| )#$STANDALONE_OBJ\1#" \
    -e "s#-o tests/fuzzing/$t#-o /mayhem/$t-standalone#")"
  ( cd "$BUILD_FUZZ" && eval "$standalone_cmd" )
  patchelf --set-rpath "$RTLIB_DIR" "/mayhem/$t-standalone"
  echo "built $t (+ standalone)"
done

# ── 2) EThread-aware wrapper harnesses: fuzz_hpack / fuzz_http, built from OUR
#      mayhem/harnesses/{fuzz_hpack,fuzz_http}.cc instead of upstream's tests/fuzzing/ copies (see
#      the top-of-file comment and the two harness files themselves for the full why). Each
#      wrapper is compiled+linked by taking cmake/ninja's OWN recorded compile+link recipe for the
#      matching upstream target (same include paths, same library set, same sanitizer/coverage
#      flags — nothing hand-guessed) and substituting just the one source file / object path, the
#      same technique mayhem/harnesses/http_kat_test.cc already uses below. This still links
#      against the SAME production objects (proxy/hdrs, proxy/http2, tscore, iocore/eventsystem,
#      records, libswoc, yaml-cpp, ls-hpack) that upstream's own fuzz_hpack/fuzz_http compiled in
#      step 1 above — only the harness .cc (and its .o) differs.
for t in "${WRAPPER_TARGETS[@]}"; do
  WRAPPER_SRC="$SRC/mayhem/harnesses/$t.cc"
  WRAPPER_OBJ="$BUILD_FUZZ/mayhem-wrapper-$t.o"

  compile_cmd="$(ninja -C "$BUILD_FUZZ" -t commands "$t" | grep -- "-c .*/$t\.cc\$")"
  wrapper_compile_cmd="$(printf '%s' "$compile_cmd" | sed \
    -e "s#/mayhem/tests/fuzzing/$t\.cc#$WRAPPER_SRC#" \
    -e "s#tests/fuzzing/CMakeFiles/$t.dir/$t.cc.o#$WRAPPER_OBJ#g")"
  ( cd "$BUILD_FUZZ" && eval "$wrapper_compile_cmd" )

  # Same anchoring caveat as the standalone-reproducer sed above ($LIB_FUZZING_ENGINE is a literal
  # prefix of $COVERAGE_FLAGS on this same link line) — here we're not touching the fuzzer-engine
  # flag at all, just retargeting the one object file, so no anchoring is needed for that part.
  link_cmd="$(ninja -C "$BUILD_FUZZ" -t commands "$t" | tail -1)"
  link_cmd="${link_cmd%% && cd *}"   # drop any POST_BUILD lib/ copy_if_different steps (fuzz_http)
  wrapper_link_cmd="$(printf '%s' "$link_cmd" | sed \
    -e "s#tests/fuzzing/CMakeFiles/$t.dir/$t.cc.o#$WRAPPER_OBJ#g")"
  ( cd "$BUILD_FUZZ" && eval "$wrapper_link_cmd" )

  cp "$BUILD_FUZZ/tests/fuzzing/$t" "/mayhem/$t"
  patchelf --set-rpath "$RTLIB_DIR" "/mayhem/$t"

  # Standalone reproducer, built from the SAME wrapper link command (so it matches the fuzz binary
  # actually shipped, not upstream's original object) — same fuzzer-engine anchoring as the
  # GENERIC_TARGETS loop above.
  standalone_cmd="$(printf '%s' "$wrapper_link_cmd" | sed -E \
    -e "s#$LIB_FUZZING_ENGINE(\$| )#$STANDALONE_OBJ\1#" \
    -e "s#-o tests/fuzzing/$t#-o /mayhem/$t-standalone#")"
  ( cd "$BUILD_FUZZ" && eval "$standalone_cmd" )
  patchelf --set-rpath "$RTLIB_DIR" "/mayhem/$t-standalone"
  echo "built $t (mayhem EThread-aware wrapper, + standalone)"
done

# ── 3) http_kat_test: a mayhemheroes-added functional KAT for mayhem/test.sh (upstream ships no
#      assertion-based unit test for proxy/hdrs' HTTP/1.x parser — only the libFuzzer harness,
#      which never asserts anything). Compiles mayhem/harnesses/http_kat_test.cc against the SAME
#      production objects fuzz_http already links (proxy/hdrs, tscore, iocore/eventsystem, records,
#      tsutil, libswoc, yaml-cpp, ls-hpack), reusing fuzz_http's own CMake-generated compile+link
#      recipe (so include paths / library set never drift from what fuzz_http actually needs) minus
#      the libFuzzer engine (this is a plain `main()` binary, not a fuzz target). ──────────────────
KAT_SRC="$SRC/mayhem/harnesses/http_kat_test.cc"
KAT_OBJ="$BUILD_FUZZ/http_kat_test.o"
KAT_BIN="/mayhem/http_kat_test"

compile_cmd="$(ninja -C "$BUILD_FUZZ" -t commands fuzz_http | grep -- '-c .*fuzz_http\.cc$')"
kat_compile_cmd="$(printf '%s' "$compile_cmd" | sed \
  -e "s#/mayhem/tests/fuzzing/fuzz_http\.cc#$KAT_SRC#" \
  -e "s#tests/fuzzing/CMakeFiles/fuzz_http.dir/fuzz_http.cc.o#$KAT_OBJ#g")"
( cd "$BUILD_FUZZ" && eval "$kat_compile_cmd" )

link_cmd="$(ninja -C "$BUILD_FUZZ" -t commands fuzz_http | tail -1)"
link_cmd="${link_cmd%% && cd *}"   # drop fuzz_http's own POST_BUILD lib/ copy_if_different steps
# Same anchoring caveat as the standalone-reproducer sed above: $LIB_FUZZING_ENGINE
# (-fsanitize=fuzzer) is now a literal prefix of $COVERAGE_FLAGS (-fsanitize=fuzzer-no-link), which
# is ALSO on this link line (via CXX_FLAGS) and must be left alone — anchor on a following
# space/EOL so only the standalone -fsanitize=fuzzer link flag is dropped.
kat_link_cmd="$(printf '%s' "$link_cmd" | sed -E \
  -e "s# $LIB_FUZZING_ENGINE(\$| )#\1#" \
  -e "s#tests/fuzzing/CMakeFiles/fuzz_http.dir/fuzz_http.cc.o#$KAT_OBJ#g" \
  -e "s#-o tests/fuzzing/fuzz_http#-o $KAT_BIN#")"
( cd "$BUILD_FUZZ" && eval "$kat_link_cmd" )
patchelf --set-rpath "$RTLIB_DIR" "$KAT_BIN"

echo "build.sh complete:"
ls -la /mayhem/fuzz_hpack /mayhem/fuzz_http /mayhem/fuzz_json /mayhem/fuzz_proxy_protocol \
       /mayhem/fuzz_rec_http /mayhem/fuzz_yamlcpp \
       /mayhem/fuzz_hpack-standalone /mayhem/fuzz_http-standalone /mayhem/fuzz_json-standalone \
       /mayhem/fuzz_proxy_protocol-standalone /mayhem/fuzz_rec_http-standalone /mayhem/fuzz_yamlcpp-standalone \
       /mayhem/http_kat_test "$RTLIB_DIR/libswoc.so.1" 2>&1
