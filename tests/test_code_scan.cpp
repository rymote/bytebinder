#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "code_image_accessor.h"
#include "test_support.h"

#include <algorithm>
#include <memory>

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

namespace {
    constexpr uintptr_t image_base = 0x140000000;
    constexpr size_t image_size = 0x4000;

    constexpr size_t caller_offset = 0x1000;
    constexpr size_t caller_size = 0x20;
    constexpr size_t second_function_offset = 0x1040;
    constexpr size_t leaf_offset = 0x1080;
    constexpr size_t fragment_offset = 0x10C0;
    constexpr size_t thunk_offset = 0x1100;
    constexpr size_t import_stub_offset = 0x1140;
    constexpr size_t table_offset = 0x3000;
    constexpr size_t plain_unwind_offset = 0x2000;
    constexpr size_t chained_unwind_offset = 0x2010;

    std::shared_ptr<code_image_accessor> make_image_with_table() {
        auto accessor = std::make_shared<code_image_accessor>(image_base, image_size);
        accessor->poke_pe_headers(table_offset, 3 * 12);
        accessor->poke_bytes(plain_unwind_offset, {0x01});
        accessor->poke_bytes(chained_unwind_offset, {0x21});

        // push rdi; sub rsp, 0x20; call leaf; call thunk; add rsp, 0x20; pop rdi; ret
        accessor->poke_bytes(caller_offset, {0x57, 0x48, 0x83, 0xEC, 0x20, 0xE8, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0x48, 0x83, 0xC4, 0x20, 0x5F, 0xC3});
        accessor->poke_relative(caller_offset + 5, leaf_offset);
        accessor->poke_relative(caller_offset + 10, thunk_offset);
        // An unusual start no prologue pattern would ever recognize: mov eax, ecx; ret
        accessor->poke_bytes(second_function_offset, {0x89, 0xC8, 0xC3});
        // Leaf function outside the table: mov eax, 1; ret
        accessor->poke_bytes(leaf_offset, {0xB8, 0x01, 0, 0, 0, 0xC3});
        accessor->poke_bytes(fragment_offset, {0x48, 0x83, 0xEC, 0x20, 0xC3});
        // Thunk: jmp second function
        accessor->poke_bytes(thunk_offset, {0xE9, 0, 0, 0, 0});
        accessor->poke_relative(thunk_offset, second_function_offset);
        // jmp [rip+0], the shape of an import stub, leads out of the module
        accessor->poke_bytes(import_stub_offset, {0xFF, 0x25, 0, 0, 0, 0});

        accessor->poke_table_entry(table_offset, 0, caller_offset, caller_offset + caller_size, plain_unwind_offset);
        accessor->poke_table_entry(table_offset, 1, second_function_offset, second_function_offset + 3, plain_unwind_offset);
        accessor->poke_table_entry(table_offset, 2, fragment_offset, fragment_offset + 5, chained_unwind_offset);
        return accessor;
    }

    bool contains_address(const std::vector<uintptr_t>& addresses, uintptr_t address) {
        return std::find(addresses.begin(), addresses.end(), address) != addresses.end();
    }
}

TEST_CASE("process::find_functions reads the unwind table and adds leaf call targets",
          "[process][find_functions]") {
    const bb::process target(make_image_with_table());
    const auto functions = target.find_functions("image.exe");

    REQUIRE(functions.size() == 3);

    REQUIRE(functions[0].address == image_base + caller_offset);
    REQUIRE(functions[0].size == caller_size);
    REQUIRE(functions[0].source == bb::function_source::unwind_table);

    REQUIRE(functions[1].address == image_base + second_function_offset);
    REQUIRE(functions[1].source == bb::function_source::unwind_table);

    REQUIRE(functions[2].address == image_base + leaf_offset);
    REQUIRE(functions[2].size == 0);
    REQUIRE(functions[2].source == bb::function_source::call_target);
}

TEST_CASE("process::find_functions leaves out chained fragments and jump thunks",
          "[process][find_functions]") {
    const bb::process target(make_image_with_table());
    const auto functions = target.find_functions("image.exe");

    const auto reported = [&functions](size_t offset) {
        return std::any_of(functions.begin(), functions.end(), [offset](const bb::function_entry& entry) {
            return entry.address == image_base + offset;
        });
    };
    REQUIRE_FALSE(reported(fragment_offset));
    REQUIRE_FALSE(reported(thunk_offset));
}

TEST_CASE("process::find_functions finds leaf functions behind thunks and tail jumps",
          "[process][find_functions]") {
    constexpr size_t tail_function_offset = 0x1200;
    constexpr size_t tail_target_offset = 0x1240;
    constexpr size_t thunked_caller_offset = 0x1280;
    constexpr size_t leaf_thunk_offset = 0x12C0;
    constexpr size_t thunked_leaf_offset = 0x1300;

    auto accessor = make_image_with_table();
    accessor->poke_pe_headers(table_offset, 2 * 12);

    // jmp tail target, as an optimized tail call
    accessor->poke_bytes(tail_function_offset, {0xE9, 0, 0, 0, 0});
    accessor->poke_relative(tail_function_offset, tail_target_offset);
    accessor->poke_bytes(tail_target_offset, {0x31, 0xC0, 0xC3});
    // call stub; call thunk to leaf; ret
    accessor->poke_bytes(thunked_caller_offset, {0xE8, 0, 0, 0, 0, 0xE8, 0, 0, 0, 0, 0xC3});
    accessor->poke_relative(thunked_caller_offset, import_stub_offset);
    accessor->poke_relative(thunked_caller_offset + 5, leaf_thunk_offset);
    accessor->poke_bytes(leaf_thunk_offset, {0xE9, 0, 0, 0, 0});
    accessor->poke_relative(leaf_thunk_offset, thunked_leaf_offset);
    accessor->poke_bytes(thunked_leaf_offset, {0xB8, 0x02, 0, 0, 0, 0xC3});

    accessor->poke_table_entry(table_offset, 0, tail_function_offset, tail_function_offset + 5, plain_unwind_offset);
    accessor->poke_table_entry(table_offset, 1, thunked_caller_offset, thunked_caller_offset + 11, plain_unwind_offset);

    const bb::process target(accessor);
    const auto functions = target.find_functions("image.exe");
    const auto source_of = [&functions](size_t offset) -> std::optional<bb::function_source> {
        for (const auto& entry : functions) {
            if (entry.address == image_base + offset) {
                return entry.source;
            }
        }
        return std::nullopt;
    };
    REQUIRE(source_of(tail_target_offset) == bb::function_source::call_target);
    REQUIRE(source_of(thunked_leaf_offset) == bb::function_source::call_target);
    REQUIRE_FALSE(source_of(leaf_thunk_offset).has_value());
    REQUIRE_FALSE(source_of(import_stub_offset).has_value());
    REQUIRE(functions.size() == 4);
}

TEST_CASE("process::find_functions honors max_results and reports unknown modules",
          "[process][find_functions]") {
    const bb::process target(make_image_with_table());
    REQUIRE(target.find_functions("image.exe", 2).size() == 2);
    REQUIRE(target.find_functions("image.exe", 0).size() == 3);
    REQUIRE(target.find_functions("missing.exe").empty());
}

TEST_CASE("process::find_functions falls back to prologues without a usable table",
          "[process][find_functions]") {
    constexpr size_t function_offset = 0x1000;

    SECTION("no PE headers at all") {
        auto accessor = std::make_shared<code_image_accessor>(image_base, image_size);
        accessor->poke_bytes(function_offset, {0x57, 0x48, 0x83, 0xEC, 0x20, 0xC3});
        const auto functions = bb::process(accessor).find_functions("image.exe");
        REQUIRE(functions.size() == 1);
        REQUIRE(functions[0].address == image_base + function_offset);
        REQUIRE(functions[0].source == bb::function_source::prologue);
    }

    SECTION("a table that points outside the module") {
        auto accessor = std::make_shared<code_image_accessor>(image_base, image_size);
        accessor->poke_pe_headers(static_cast<uint32_t>(image_size - 4), 0x1000);
        accessor->poke_bytes(function_offset, {0x57, 0x48, 0x83, 0xEC, 0x20, 0xC3});
        const auto functions = bb::process(accessor).find_functions("image.exe");
        REQUIRE(functions.size() == 1);
        REQUIRE(functions[0].source == bb::function_source::prologue);
    }

    SECTION("a table for another architecture") {
        auto accessor = std::make_shared<code_image_accessor>(image_base, image_size);
        accessor->poke_pe_headers(table_offset, 12, 0xAA64);
        accessor->poke_table_entry(table_offset, 0, 0x1800, 0x1810, plain_unwind_offset);
        const auto functions = bb::process(accessor).find_functions("image.exe");
        REQUIRE(functions.empty());
    }
}

TEST_CASE("process::find_prologues recognizes common function starts",
          "[process][find_prologues]") {
    auto accessor = std::make_shared<code_image_accessor>(image_base, image_size);
    size_t offset = 0x1000;
    std::vector<uintptr_t> expected;
    const auto add = [&](std::initializer_list<uint8_t> bytes) {
        accessor->poke_bytes(offset, bytes);
        expected.push_back(image_base + offset);
        offset += 0x20;
    };
    add({0xF3, 0x0F, 0x1E, 0xFA, 0x90});                         // endbr64
    add({0x55, 0x48, 0x89, 0xE5, 0xC3});                         // push rbp; mov rbp, rsp
    add({0x48, 0x83, 0xEC, 0x28, 0xC3});                         // sub rsp, 0x28
    add({0x57, 0x48, 0x83, 0xEC, 0x30, 0xC3});                   // push rdi; sub rsp, 0x30
    add({0x53, 0x57, 0xC3});                                     // push rbx; push rdi
    add({0x41, 0x54, 0x41, 0x55, 0xC3});                         // push r12; push r13
    add({0x48, 0x89, 0x5C, 0x24, 0x08, 0x57, 0xC3});             // mov [rsp+8], rbx; push rdi
    add({0x48, 0x89, 0x4C, 0x24, 0x10, 0x48, 0x83, 0xEC, 0x20}); // mov [rsp+0x10], rcx; sub rsp, 0x20
    add({0x48, 0x8B, 0xC4, 0x48, 0x89, 0x58, 0x08, 0xC3});       // mov rax, rsp; mov [rax+8], rbx

    const bb::process target(accessor);
    const auto found = target.find_prologues("image.exe", 0);
    for (const uintptr_t address : expected) {
        REQUIRE(contains_address(found, address));
    }
    REQUIRE(found.size() == expected.size());
}

TEST_CASE("process::find_prologues rejects code that only resembles a start",
          "[process][find_prologues]") {
    auto accessor = std::make_shared<code_image_accessor>(image_base, image_size);
    size_t offset = 0x1000;
    const auto add = [&](std::initializer_list<uint8_t> bytes) {
        accessor->poke_bytes(offset, bytes);
        offset += 0x20;
    };
    add({0x29, 0xC8, 0xC3});                         // sub eax, ecx on a boundary
    add({0x48, 0x83, 0xE8, 0x20, 0xC3});             // sub rax, 0x20
    add({0x50, 0x48, 0x89, 0xE5, 0xC3});             // push rax; mov rbp, rsp
    add({0x53, 0xC3});                               // push rbx; ret
    add({0x48, 0x89, 0x5C, 0x24, 0x48, 0x57, 0xC3}); // mov [rsp+0x48], rbx is a local, not home space
    add({0x48, 0x8B, 0xC4, 0xC3});                   // mov rax, rsp; ret

    // A real prologue inside a function body, not on any boundary.
    accessor->poke_bytes(offset, {0x90, 0x90, 0x90, 0x48, 0x83, 0xEC, 0x20, 0xC3});

    const bb::process target(accessor);
    REQUIRE(target.find_prologues("image.exe", 0).empty());
}

TEST_CASE("process::find_functions lists a real function in this binary",
          "[process][find_functions]") {
    auto current_process = bb::process::current();
    const auto modules = current_process.modules();
    REQUIRE_FALSE(modules.empty());
    const auto functions = current_process.find_functions(modules.front().name, 0);
    REQUIRE_FALSE(functions.empty());
    REQUIRE(std::is_sorted(functions.begin(), functions.end(), [](const bb::function_entry& left, const bb::function_entry& right) {
        return left.address < right.address;
    }));
#if defined(_WIN32) && defined(_M_X64)
    REQUIRE(functions.front().source == bb::function_source::unwind_table);

    // A debug build reaches this through a jump thunk, so the pointer is followed first.
    auto* start = reinterpret_cast<const uint8_t*>(&bytebinder_test_call_marker_helper);
    if (start[0] == 0xE9) {
        int32_t relative = 0;
        std::memcpy(&relative, start + 1, sizeof(relative));
        start += 5 + relative;
    }
    const auto address = reinterpret_cast<uintptr_t>(start);
    REQUIRE(std::any_of(functions.begin(), functions.end(), [address](const bb::function_entry& entry) {
        return entry.address == address;
    }));
#endif
}
