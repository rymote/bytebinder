#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

#if defined(__GNUC__) && !defined(__clang__)
__attribute__((noinline, noipa, optimize("O0")))
#elif defined(__clang__)
__attribute__((noinline, optnone))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
void bytebinder_test_call_marker_helper() {
    // The marker function has an observable volatile side effect, AND we do
    // additional volatile work AFTER the call to defeat MSVC's tail-call /
    // tail-merge optimization (which would emit `jmp` instead of `call` and
    // make find_xrefs miss the call kind).
    bytebinder_test_marker_function();
    bytebinder_test_marker_observable += 1;
}

TEST_CASE("process::find_xrefs locates a call to a known function", "[process][find_xrefs]") {
    bytebinder_test_call_marker_helper();

    auto current_process = bb::process::current();
    auto xrefs = current_process.find_xrefs(
        reinterpret_cast<uintptr_t>(&bytebinder_test_marker_function),
        std::nullopt, 0);

    bool found_call = false;
    for (const auto& entry : xrefs) {
        if (entry.kind == bb::xref_kind::call) {
            found_call = true;
            break;
        }
    }
    REQUIRE(found_call);
}

TEST_CASE("process::find_prologues returns at least one prologue in the test binary",
          "[process][find_prologues]") {
    auto current_process = bb::process::current();
    const auto modules = current_process.modules();
    REQUIRE_FALSE(modules.empty());
    auto prologues = current_process.find_prologues(modules.front().name, 100);
    REQUIRE_FALSE(prologues.empty());
}

TEST_CASE("process::find_instruction_pattern matches a simple template",
          "[process][find_instruction_pattern]") {
    auto current_process = bb::process::current();
    std::vector<bb::instruction_pattern_element> pattern;
    pattern.push_back({"push", std::nullopt});
    pattern.push_back({"mov", 2});
    pattern.push_back({"", std::nullopt});
    auto matches = current_process.find_instruction_pattern(
        std::span<const bb::instruction_pattern_element>{pattern}, std::nullopt, 100);
    REQUIRE_FALSE(matches.empty());
}
