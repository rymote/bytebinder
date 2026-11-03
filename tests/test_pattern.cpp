#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

TEST_CASE("pattern::scan_all reports every match in a buffer", "[pattern][scan_all]") {
    static unsigned char haystack[1024];
    std::memset(haystack, 0, sizeof(haystack));
    const unsigned char needle[] = {0xDE, 0xAD, 0xBE, 0xEF};
    std::memcpy(haystack + 64,  needle, sizeof(needle));
    std::memcpy(haystack + 256, needle, sizeof(needle));
    std::memcpy(haystack + 700, needle, sizeof(needle));

    bb::pattern parsed = bb::parse_ida_pattern("DE AD BE EF");
    std::vector<uintptr_t> hits;
    parsed.scan_all(bb::local_accessor::instance(),
                     reinterpret_cast<uintptr_t>(haystack),
                     sizeof(haystack), 0,
                     [&](uintptr_t address) {
                         hits.push_back(address);
                         return true;
                     });
    REQUIRE(hits.size() == 3);
    REQUIRE(hits[0] == reinterpret_cast<uintptr_t>(haystack + 64));
    REQUIRE(hits[1] == reinterpret_cast<uintptr_t>(haystack + 256));
    REQUIRE(hits[2] == reinterpret_cast<uintptr_t>(haystack + 700));
}

TEST_CASE("pattern::scan_all honors max_results", "[pattern][scan_all]") {
    static unsigned char haystack[256];
    std::memset(haystack, 0, sizeof(haystack));
    for (int index = 0; index < 200; index += 8) haystack[index] = 0xAA;

    bb::pattern parsed = bb::parse_ida_pattern("AA");
    std::vector<uintptr_t> hits;
    parsed.scan_all(bb::local_accessor::instance(),
                     reinterpret_cast<uintptr_t>(haystack),
                     sizeof(haystack), 5,
                     [&](uintptr_t address) {
                         hits.push_back(address);
                         return true;
                     });
    REQUIRE(hits.size() == 5);
    REQUIRE(hits[0] == reinterpret_cast<uintptr_t>(haystack + 0));
    REQUIRE(hits[1] == reinterpret_cast<uintptr_t>(haystack + 8));
    REQUIRE(hits[2] == reinterpret_cast<uintptr_t>(haystack + 16));
    REQUIRE(hits[3] == reinterpret_cast<uintptr_t>(haystack + 24));
    REQUIRE(hits[4] == reinterpret_cast<uintptr_t>(haystack + 32));
}

TEST_CASE("pattern::scan_all stops early when callback returns false", "[pattern][scan_all]") {
    static unsigned char haystack[256];
    std::memset(haystack, 0, sizeof(haystack));
    haystack[10] = 0xAA;
    haystack[50] = 0xAA;
    haystack[100] = 0xAA;

    bb::pattern parsed = bb::parse_ida_pattern("AA");
    size_t hit_count = 0;
    uintptr_t first_address = 0;
    const size_t reported = parsed.scan_all(
        bb::local_accessor::instance(),
        reinterpret_cast<uintptr_t>(haystack),
        sizeof(haystack), 0,
        [&](uintptr_t address) {
            ++hit_count;
            first_address = address;
            return false;
        });
    REQUIRE(hit_count == 1);
    REQUIRE(reported == 1);
    REQUIRE(first_address == reinterpret_cast<uintptr_t>(haystack + 10));
}

TEST_CASE("pattern::scan_all does not double-count matches at window boundary",
          "[pattern][scan_all]") {
    // The scan window is 64 KiB. A match at exactly offset 64 KiB used to be
    // reported twice: once at the tail of window N and once at the head of
    // window N+1. This test pins the fix.
    constexpr size_t window_step = 64 * 1024;
    constexpr size_t buffer_size = window_step + 32;
    static std::unique_ptr<unsigned char[]> haystack{new unsigned char[buffer_size]};
    std::memset(haystack.get(), 0, buffer_size);
    const unsigned char needle[] = {0x55, 0xAA, 0x42, 0x42};
    std::memcpy(haystack.get() + window_step, needle, sizeof(needle));

    bb::pattern parsed = bb::parse_ida_pattern("55 AA 42 42");
    std::vector<uintptr_t> hits;
    parsed.scan_all(bb::local_accessor::instance(),
                     reinterpret_cast<uintptr_t>(haystack.get()),
                     buffer_size, 0,
                     [&](uintptr_t address) {
                         hits.push_back(address);
                         return true;
                     });
    REQUIRE(hits.size() == 1);
    REQUIRE(hits[0] == reinterpret_cast<uintptr_t>(haystack.get() + window_step));
}

TEST_CASE("pattern::scan_all honors cancel flag", "[pattern][cancel]") {
    static unsigned char haystack[1024 * 256]; // 256 KiB
    std::memset(haystack, 0, sizeof(haystack));
    std::atomic<bool> cancel_flag{true}; // cancelled before first iteration

    bb::pattern parsed = bb::parse_ida_pattern("AA BB");
    size_t matches = parsed.scan_all(
        bb::local_accessor::instance(),
        reinterpret_cast<uintptr_t>(haystack),
        sizeof(haystack), 0,
        [](uintptr_t) { return true; },
        &cancel_flag, nullptr);
    REQUIRE(matches == 0);
}

TEST_CASE("pattern::scan_all reports progress", "[pattern][progress]") {
    static unsigned char haystack[1024 * 200];
    std::memset(haystack, 0, sizeof(haystack));
    bb::pattern parsed = bb::parse_ida_pattern("AA BB");
    size_t progress_calls = 0;
    parsed.scan_all(
        bb::local_accessor::instance(),
        reinterpret_cast<uintptr_t>(haystack),
        sizeof(haystack), 0,
        [](uintptr_t) { return true; },
        nullptr,
        [&](const bb::pattern::scan_progress& progress) {
            REQUIRE(progress.bytes_total == sizeof(haystack));
            REQUIRE(progress.bytes_scanned <= sizeof(haystack));
            ++progress_calls;
        });
    REQUIRE(progress_calls > 0);
}
