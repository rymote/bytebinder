#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"
#include "vtable_probe.h"

// Heuristic + dump tests also crash under ASan: find_vtables and
// find_string_tables read whole regions in one go, dump_memory copies in 1 MiB
// chunks. All cross global redzones in the test binary's data segments.
#if !BYTEBINDER_HAS_ASAN

TEST_CASE("process::find_vtables runs across every readable region", "[process][find_vtables]") {
    auto current_process = bb::process::current();
    auto candidates = current_process.find_vtables(std::nullopt, 3, 100);
    for (const auto& candidate : candidates) {
        REQUIRE(candidate.entries.size() >= 3);
    }
}

TEST_CASE("process::find_vtables finds a known vtable in the test binary", "[process][find_vtables]") {
    vtable_probe probe;
    REQUIRE(probe.first(1) == 2);
    const uintptr_t probe_vtable = bb::vmt(reinterpret_cast<uintptr_t>(&probe)).vtable_address();

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());
    auto candidates = current_process.find_vtables(self_modules.front().name, 4, 0);

    // Adjacent vtables can merge into one run, so accept the probe's vtable
    // anywhere inside a candidate rather than only at its start.
    bool found_probe_vtable = false;
    for (const auto& candidate : candidates) {
        const uintptr_t candidate_end = candidate.address + candidate.entries.size() * sizeof(uintptr_t);
        if (probe_vtable >= candidate.address && probe_vtable < candidate_end) {
            found_probe_vtable = true;
            break;
        }
    }
    REQUIRE(found_probe_vtable);
}

namespace {
    volatile char bytebinder_string_table_synthetic[] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAA\0BBBBBBBBBBBBBBBBBBBBBBBBBB\0CCCCCCCCCCCCCCCCCCCCCCCCCC\0";
}

TEST_CASE("process::find_string_tables locates a synthetic string run",
          "[process][find_string_tables]") {
    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());

    auto runs = current_process.find_string_tables(
        self_modules.front().name, 16, 10000);
    bool found_run = false;
    for (const auto& run : runs) {
        if (run.base == reinterpret_cast<uintptr_t>(
                const_cast<const char*>(bytebinder_string_table_synthetic))) {
            REQUIRE(run.string_count >= 3);
            found_run = true;
            break;
        }
    }
    REQUIRE(found_run);
}

#endif // !BYTEBINDER_HAS_ASAN
