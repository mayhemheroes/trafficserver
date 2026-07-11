# Injected via CMAKE_PROJECT_INCLUDE by mayhem/build.sh — this is a mayhemheroes-added file, not
# an upstream one.
#
# ATS's tests/fuzzing/CMakeLists.txt (upstream, unmodified) unconditionally references the
# `ts::quic` target for the fuzz_http3frame executable:
#
#     target_link_libraries(fuzz_http3frame PRIVATE ts::tscore ts::quic)
#
# `ts::quic` (src/iocore/net/quic/) is only DEFINED when TS_USE_QUIC is true, which requires
# -DENABLE_QUICHE=ON, which in turn requires a REAL BoringSSL/quictls + quiche(+Rust nightly)
# toolchain (see upstream tools/build_h3_tools.sh / tests/fuzzing/oss-fuzz.sh) — AND, worse, once
# TS_USE_QUIC is true, `inknet` itself (a dependency of fuzz_hpack/fuzz_proxy_protocol) gains extra
# QUICNet*.cc sources that call real quiche APIs (src/iocore/net/CMakeLists.txt, `if(TS_USE_QUIC)`
# block) — so ENABLE_QUICHE=ON is not a narrow, containable knob; it drags a full HTTP/3 stack into
# the whole build, not just the one HTTP/3 harness.
#
# mayhem/build.sh deliberately does NOT build fuzz_http3frame (out of scope for this pass — see the
# comment in mayhem/build.sh). We only need `ts::quic` to EXIST as a valid CMake target so the
# *configure/generate* step succeeds; its real sources are never compiled because nothing in our
# requested --target list depends on it (TS_USE_QUIC / ENABLE_QUICHE are left at their default OFF,
# so `inknet` never gains the QUIC sources either — a plain, real-OpenSSL build). This dummy
# INTERFACE target satisfies the reference without needing quiche/BoringSSL/Rust at all.
if(NOT TARGET ts::quic)
  add_library(mayhem_quic_stub INTERFACE)
  add_library(ts::quic ALIAS mayhem_quic_stub)
endif()
