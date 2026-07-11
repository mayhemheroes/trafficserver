/** @file

  mayhem/harnesses/http_kat_test.cc — standalone known-answer test for the REAL production HTTP/1.x
  request-line + header parser (proxy/hdrs/HTTP.cc's HTTPHdr::parse_req(), via HTTPParser /
  HdrHeap) — the exact code tests/fuzzing/fuzz_http.cc fuzzes. Upstream ships no assertion-based
  unit test for this path (only the libFuzzer harness, which never asserts anything), so this is a
  mayhemheroes-added functional oracle for mayhem/test.sh.

  Feeds a FIXED, well-formed HTTP/1.1 request into the unmodified production parser and asserts
  three independently COMPUTED fields end up with the exact expected values: the parsed method,
  the parsed URL path (query string stripped, leading '/' stripped — that's HdrHeap/URL's own
  behavior, not something this test invents), and the Host header. A second case with a different
  method/path/host proves it isn't an echo of the input.

  This is NOT the fuzz binary itself — it links the SAME production objects (proxy/hdrs, tscore,
  iocore/eventsystem, records, tsutil, libswoc, yaml-cpp, ls-hpack) that mayhem/build.sh already
  compiled for fuzz_http, via the exact link recipe CMake generated for that target (see
  mayhem/build.sh). A PATCH that neuters the parser (e.g. makes it a no-op / always "succeeds"
  without actually parsing) will not reproduce these exact values, so this MUST fail under the
  sabotage/anti-reward-hack check (SPEC.md #6.3).

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

#include <cstdio>
#include <cstring>
#include <string_view>

namespace
{
int g_failures = 0;

bool
check_eq(const char *case_name, const char *field, std::string_view got, std::string_view want)
{
  bool ok = (got == want);
  std::printf("HTTP_KAT case=%s field=%s got=[%.*s] want=[%.*s] match=%d\n", case_name, field, (int)got.size(),
              got.data(), (int)want.size(), want.data(), ok ? 1 : 0);
  if (!ok) {
    g_failures++;
  }
  return ok;
}

// Parse `raw` as an HTTP/1.x REQUEST and assert method/path/host against the expected values.
void
run_case(const char *case_name, std::string_view raw, std::string_view want_method, std::string_view want_path,
         std::string_view want_host)
{
  const char *start = raw.data();
  const char *end   = raw.data() + raw.size();

  HTTPParser parser;
  http_parser_init(&parser);
  HTTPHdr req_hdr;
  req_hdr.create(HTTPType::REQUEST);

  ParseResult result = req_hdr.parse_req(&parser, &start, end, true);
  http_parser_clear(&parser);

  bool parsed_ok = (result == ParseResult::DONE);
  std::printf("HTTP_KAT case=%s field=parse_result got=%d want=%d match=%d\n", case_name, (int)result,
              (int)ParseResult::DONE, parsed_ok ? 1 : 0);
  if (!parsed_ok) {
    g_failures++;
  }

  check_eq(case_name, "method", req_hdr.method_get(), want_method);
  URL *url = req_hdr.url_get();
  check_eq(case_name, "path", url->path_get(), want_path);
  check_eq(case_name, "host", req_hdr.host_get(), want_host);

  req_hdr.destroy();
}

} // namespace

int
main()
{
  // Minimal ATS runtime bring-up: the production HdrHeap allocator (new_HdrHeap -> this_ethread())
  // needs the calling thread registered as a real EThread, or every HTTPHdr::create() hits a
  // null-Thread UB path under UBSan. This mirrors src/proxy/http/unit_tests/main.cc's own
  // EventProcessorListener setup (upstream's established pattern for standalone hdrs testing).
  Layout::create();
  DiagsPtr::set(new Diags("http_kat_test", "", "", nullptr));
  RecProcessInit();
  LibRecordsConfigInit();
  ink_event_system_init(EVENT_SYSTEM_MODULE_PUBLIC_VERSION);
  eventProcessor.start(1);
  EThread *main_thread = new EThread;
  main_thread->set_specific();

  http_init();

  run_case("get-query", "GET /foo/bar?x=1 HTTP/1.1\r\n"
                         "Host: example.com\r\n"
                         "X-Test: hello\r\n"
                         "\r\n",
           "GET", "foo/bar", "example.com");

  run_case("post-deep-path", "POST /a/b/c/upload HTTP/1.1\r\n"
                              "Host: mayhem.example.org\r\n"
                              "Content-Length: 0\r\n"
                              "\r\n",
           "POST", "a/b/c/upload", "mayhem.example.org");

  std::printf("HTTP_KAT SUMMARY failures=%d\n", g_failures);
  return g_failures == 0 ? 0 : 1;
}
