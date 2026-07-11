/** @file

  mayhem/harnesses/fuzz_hpack.cc — EThread-aware wrapper around ATS's OWN OSS-Fuzz HPACK harness
  (tests/fuzzing/fuzz_hpack.cc, upstream, unmodified — LLVMFuzzerTestOneInput below replicates its
  body byte-for-byte).

  Upstream's fuzz_hpack.cc calls HTTPHdr::create() straight from LLVMFuzzerTestOneInput, with no ATS
  runtime bring-up at all. HTTPHdr::create() allocates via new_HdrHeap(), which sizes/tags its
  per-thread free-list (ProxyAllocator) off this_ethread() — and libFuzzer's driver thread is never
  registered as a real ATS EThread, so this_ethread() returns nullptr and the parse hits a null
  Thread pointer before hpack_decode_header_block() ever runs. The binary still loads all 85148
  SanitizerCoverage counters (it IS instrumented) but records ~0 edges, because execution never
  gets far enough into proxy/http2/HPACK.cc to trip any of them.

  Fix: bring up a minimal ATS event system and register the calling thread as a real EThread
  ONCE, in LLVMFuzzerInitialize (not per-input — eventProcessor.start()/EThread registration is
  one-time process setup, and libFuzzer already owns the per-input loop). This mirrors
  mayhem/harnesses/http_kat_test.cc's proven bring-up (itself modeled on
  src/proxy/http/unit_tests/main.cc's EventProcessorListener setup), which already parses ATS
  headers correctly under the exact same production code fuzz_hpack targets.

  LLVMFuzzerTestOneInput is otherwise IDENTICAL to tests/fuzzing/fuzz_hpack.cc: same input-length
  bounds, same HpackIndexingTable/HTTPHdr/hpack_decode_header_block call, same table-size
  constants. Only the missing thread context is added — the HPACK decoder under test is untouched.

  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
  agreements. See the NOTICE file distributed with this work for additional information regarding
  copyright ownership. The ASF licenses this file to you under the Apache License, Version 2.0.
*/

#include "proxy/http2/HTTP2.h"
#include "proxy/hdrs/HuffmanCodec.h"
#include "tscore/Diags.h"
#include "tscore/Layout.h"
#include "iocore/eventsystem/EventSystem.h"
#include "records/RecordsConfig.h"

#include <memory>

#define kMinInputLength 8
#define kMaxInputLength 128

#define INITIAL_TABLE_SIZE      4096
#define MAX_REQUEST_HEADER_SIZE 131072
#define MAX_TABLE_SIZE          4096

extern int cmd_disable_pfreelist;

extern "C" int
LLVMFuzzerInitialize(int *, char ***)
{
  // Same ATS runtime bring-up as mayhem/harnesses/http_kat_test.cc: register this (libFuzzer
  // driver) thread as a real EThread so this_ethread()-keyed allocation (new_HdrHeap and friends)
  // has a valid Thread to work with. Done ONCE here, before the fuzzing loop starts.
  Layout::create();
  DiagsPtr::set(new Diags("fuzz_hpack", "", "", nullptr));
  RecProcessInit();
  LibRecordsConfigInit();
  ink_event_system_init(EVENT_SYSTEM_MODULE_PUBLIC_VERSION);
  eventProcessor.start(1);
  EThread *main_thread = new EThread;
  main_thread->set_specific();

  cmd_disable_pfreelist = true;

  return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *input_data, size_t size_data)
{
  if (size_data < kMinInputLength || size_data > kMaxInputLength) {
    return 0;
  }

  HpackIndexingTable       indexing_table(INITIAL_TABLE_SIZE);
  std::unique_ptr<HTTPHdr> headers(new HTTPHdr);
  headers->create(HTTPType::REQUEST);

  hpack_decode_header_block(indexing_table, headers.get(), input_data, size_data, MAX_REQUEST_HEADER_SIZE, MAX_TABLE_SIZE);

  headers->destroy();

  return 0;
}
