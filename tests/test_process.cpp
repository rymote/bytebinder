#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

TEST_CASE("process::current() returns a usable local handle", "[process][local]") {
    auto current_process = bb::process::current();
    REQUIRE(current_process.is_local());
    REQUIRE(current_process.id().has_value());
    const auto loaded_modules = current_process.modules();
    REQUIRE_FALSE(loaded_modules.empty());
}

namespace {
    // Placed in a globally-addressable buffer so a regions-intersected scan
    // across the test binary's mapped image deterministically locates it.
    // The byte sequence is unusual enough that we don't expect false positives
    // anywhere else in the process.
    alignas(16) volatile unsigned char bytebinder_scan_marker_buffer[64] = {
        0x55, 0xAA, 0x42, 0x42, 0x4D, 0x4B, 0x52, 0x01,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    };
}

// AddressSanitizer adds redzones around every global, so a 64 KiB chunked read
// over a real module's data section necessarily touches them and triggers a
// global-buffer-overflow report. The whole-module scan path is exercised in
// non-sanitizer builds; the boundary and buffer-level scan paths are exercised
// by the dedicated `pattern::scan_all` tests, which use heap-allocated buffers
// that ASan does not redzone-overflow on.
#if !BYTEBINDER_HAS_ASAN
TEST_CASE("process::scan finds a marker after partial-read fix", "[process][scan]") {
    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());
    bb::mem hit = current_process.scan(
        "55 AA 42 42 4D 4B 52 01 DE AD BE EF CA FE BA BE",
        self_modules.front().name);
    REQUIRE(hit.address != std::numeric_limits<uintptr_t>::max());
    REQUIRE(hit.address ==
            reinterpret_cast<uintptr_t>(&bytebinder_scan_marker_buffer[0]));
}
#endif

TEST_CASE("process::alive() returns true for current process", "[process][lifecycle]") {
    REQUIRE(bb::process::current().alive());
}

TEST_CASE("process::regions(required, forbidden) filters correctly", "[process][regions]") {
    auto current_process = bb::process::current();
    const auto code_only = current_process.regions(bb::protection::execute);
    const auto data_only = current_process.regions(bb::protection::read,
                                                    bb::protection::execute);
    REQUIRE_FALSE(code_only.empty());
    REQUIRE_FALSE(data_only.empty());
    for (const auto& region : code_only) {
        REQUIRE((region.protection & bb::protection::execute) != 0);
    }
    for (const auto& region : data_only) {
        REQUIRE((region.protection & bb::protection::read)    != 0);
        REQUIRE((region.protection & bb::protection::execute) == 0);
    }
}

TEST_CASE("process::is_readable on stack and bogus addresses", "[process][predicates]") {
    auto current_process = bb::process::current();
    int local_value = 0;
    REQUIRE(current_process.is_readable(reinterpret_cast<uintptr_t>(&local_value),
                                         sizeof(local_value)));
    REQUIRE_FALSE(current_process.is_readable(0x1, 1));
    REQUIRE_FALSE(current_process.is_readable(
        std::numeric_limits<uintptr_t>::max() - 16, 8));
}

TEST_CASE("process::is_writable rejects code regions", "[process][predicates]") {
    auto current_process = bb::process::current();
    int local_value = 0;
    REQUIRE(current_process.is_writable(reinterpret_cast<uintptr_t>(&local_value),
                                         sizeof(local_value)));
    auto function_pointer =
        reinterpret_cast<uintptr_t>(&bytebinder_test_marker_function);
    REQUIRE_FALSE(current_process.is_writable(function_pointer, 1));
}

TEST_CASE("process::module_sections returns at least one allocatable section",
          "[process][sections]") {
    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());
    bool found_any = false;
    for (const auto& candidate : self_modules) {
        const auto sections = current_process.module_sections(candidate.name);
        if (!sections.empty()) {
            found_any = true;
            for (const auto& section : sections) {
                REQUIRE(section.size > 0);
                REQUIRE(section.base >= candidate.base);
            }
            break;
        }
    }
    REQUIRE(found_any);
}
