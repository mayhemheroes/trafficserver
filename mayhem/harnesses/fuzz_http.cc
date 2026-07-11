/** @file

  mayhem/harnesses/fuzz_http.cc — EThread-aware wrapper around ATS's OWN OSS-Fuzz HTTP/1.x harness
  (tests/fuzzing/fuzz_http.cc, upstream, unmodified — LLVMFuzzerTestOneInput below replicates its
  body byte-for-byte).

  Upstream's fuzz_http.cc calls http_init() and HTTPHdr::create() straight from
  LLVMFuzzerTestOneInput, with no ATS runtime bring-up. Exactly like fuzz_hpack (see
  mayhem/harnesses/fuzz_hpack.cc for the full explanation), HTTPHdr::create()'s new_HdrHeap()
  allocation is keyed off this_ethread() — and libFuzzer's driver thread was never registered as a
  real ATS EThread, so this_ethread() is nullptr and every parse_req/parse_resp call short-circuits
  before proxy/hdrs' HTTP.cc parser logic runs. The binary IS instrumented (coverage counters load
  fine) but records ~0 edges because execution never reaches them.

  Fix: bring up a minimal ATS event system and register the calling thread as a real EThread ONCE,
  in LLVMFuzzerInitialize (mirrors mayhem/harnesses/http_kat_test.cc's proven bring-up, which
  already parses ATS headers correctly using this exact production parser). http_init() itself is
  also one-time global setup, so it moves into LLVMFuzzerInitialize alongside the EThread bring-up
  rather than running on every input as upstream does.

  LLVMFuzzerTestOneInput is otherwise IDENTICAL to tests/fuzzing/fuzz_http.cc: same input-length
  bounds, same six HTTPHdr request/response (HTTP/1.1, /2, /3) parse calls in the same order. Only
  the missing thread context (and the one-time-vs-per-input init calls) changed — the HTTP header
  parser under test is untouched.

  Licensed to the Apache Software Foundation (ASF) under one or more contributor license
  agreements. See the NOTICE file distributed with this work for additional information regarding
  copyright ownership. The ASF licenses this file to you under the Apache License, Version 2.0.
*/

#include "proxy/hdrs/HTTP.h"
#include "proxy/hdrs/HttpCompat.h"
#include "tscore/Diags.h"
#include "tscore/Layout.h"
#include "iocore/eventsystem/EventSystem.h"
#include "records/RecordsConfig.h"

#include <cstring>
#include <string>

#define kMinInputLength 10
#define kMaxInputLength 1024

extern int cmd_disable_pfreelist;

extern "C" int
LLVMFuzzerInitialize(int *, char ***)
{
  // Same ATS runtime bring-up as mayhem/harnesses/http_kat_test.cc / fuzz_hpack.cc: register this
  // (libFuzzer driver) thread as a real EThread so this_ethread()-keyed allocation has a valid
  // Thread to work with. http_init() is one-time global module init, so it also belongs here
  // rather than on every LLVMFuzzerTestOneInput call (upstream re-runs it, and re-sets a fresh
  // Diags, on every single input — harmless upstream since it never reaches this code with a live
  // thread anyway, but wasteful/wrong once the parser is actually reachable).
  Layout::create();
  DiagsPtr::set(new Diags("fuzz_http", "", "", nullptr));
  RecProcessInit();
  LibRecordsConfigInit();
  ink_event_system_init(EVENT_SYSTEM_MODULE_PUBLIC_VERSION);
  eventProcessor.start(1);
  EThread *main_thread = new EThread;
  main_thread->set_specific();

  cmd_disable_pfreelist = true;
  http_init();

  return 0;
}

extern "C" int
LLVMFuzzerTestOneInput(const uint8_t *input_data, size_t size_data)
{
  if (size_data < kMinInputLength || size_data > kMaxInputLength) {
    return 0;
  }

  std::string input(reinterpret_cast<const char *>(input_data), size_data);
  char const *start = input.c_str();
  char const *end   = input.c_str() + input.size();

  HTTPParser parser;
  HTTPHdr    req_hdr, rsp_hdr, req_hdr_2, rsp_hdr_2, req_hdr_3, rsp_hdr_3;

  req_hdr.create(HTTPType::REQUEST);
  rsp_hdr.create(HTTPType::RESPONSE);
  req_hdr_2.create(HTTPType::REQUEST, HTTP_2_0);
  rsp_hdr_2.create(HTTPType::RESPONSE, HTTP_2_0);
  req_hdr_3.create(HTTPType::REQUEST, HTTP_3_0);
  rsp_hdr_3.create(HTTPType::RESPONSE, HTTP_3_0);

  {
    http_parser_init(&parser);
    ParseResult result = req_hdr.parse_req(&parser, &start, end, true);
    http_parser_clear(&parser);
    (void)result;
  }
  {
    http_parser_init(&parser);
    ParseResult result = rsp_hdr.parse_resp(&parser, &start, end, true);
    http_parser_clear(&parser);
    (void)result;
  }
  {
    http_parser_init(&parser);
    ParseResult result = req_hdr_2.parse_req(&parser, &start, end, true);
    http_parser_clear(&parser);
    (void)result;
  }
  {
    http_parser_init(&parser);
    ParseResult result = rsp_hdr_2.parse_resp(&parser, &start, end, true);
    http_parser_clear(&parser);
    (void)result;
  }
  {
    http_parser_init(&parser);
    ParseResult result = req_hdr_3.parse_req(&parser, &start, end, true);
    http_parser_clear(&parser);
    (void)result;
  }
  {
    http_parser_init(&parser);
    ParseResult result = rsp_hdr_3.parse_resp(&parser, &start, end, true);
    http_parser_clear(&parser);
    (void)result;
  }

  req_hdr.destroy();
  rsp_hdr.destroy();
  req_hdr_2.destroy();
  rsp_hdr_2.destroy();
  req_hdr_3.destroy();
  rsp_hdr_3.destroy();

  return 0;
}
