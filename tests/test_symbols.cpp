#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

#if !defined(_WIN32)
TEST_CASE("process::resolve_symbol finds a libc dynamic symbol", "[process][symbols]") {
    auto current_process = bb::process::current();
    const auto resolved = current_process.resolve_symbol("memcpy");
    REQUIRE(resolved.has_value());
    REQUIRE(resolved->address != 0);
    REQUIRE_FALSE(resolved->module_name.empty());
}

TEST_CASE("process::symbolize round-trips an address back to its name", "[process][symbols]") {
    auto current_process = bb::process::current();
    const auto resolved_memcpy = current_process.resolve_symbol("memcpy");
    REQUIRE(resolved_memcpy.has_value());
    const auto symbolized = current_process.symbolize(resolved_memcpy->address);
    REQUIRE(symbolized.has_value());
#if defined(__APPLE__)
    // libSystem exports memcpy as an alias that shares its address with
    // memmove and _platform_memmove, so any of those names is a valid answer.
    REQUIRE(symbolized->symbol.address == resolved_memcpy->address);
#else
    REQUIRE(symbolized->symbol.name == "memcpy");
#endif
}
#endif

TEST_CASE("process::symbolize returns offset from symbol start", "[symbols]") {
    auto current_process = bb::process::current();
    auto resolved = current_process.resolve_symbol("memcpy");
    if (!resolved.has_value()) {
        SUCCEED("memcpy unresolved on this platform/build; offset semantics untestable here");
        return;
    }
    const uintptr_t query_address = resolved->address + 7;
    auto symbolized = current_process.symbolize(query_address);
    REQUIRE(symbolized.has_value());
    REQUIRE(symbolized->symbol.address + symbolized->offset_from_start == query_address);
}

TEST_CASE("process::resolve_symbols batches lookups", "[symbols]") {
    auto current_process = bb::process::current();
    std::array<std::string_view, 3> names{"memcpy", "memmove", "memset"};
    auto results = current_process.resolve_symbols(names);
    REQUIRE(results.size() == names.size());
    for (size_t index = 0; index < names.size(); ++index) {
        if (results[index].has_value()) {
            REQUIRE_FALSE(results[index]->name.empty());
        }
    }
}
