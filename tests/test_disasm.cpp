#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

TEST_CASE("mem::disasm decodes a known x64 sequence", "[mem][disasm]") {
    if constexpr (sizeof(void*) == 8) {
        memset(buffer, 0, sizeof(buffer));
        // x64: push rbp; mov rbp, rsp; nop; ret
        buffer[0] = 0x55;
        buffer[1] = 0x48; buffer[2] = 0x89; buffer[3] = 0xE5;
        buffer[4] = 0x90;
        buffer[5] = 0xC3;

        bb::mem code(reinterpret_cast<void*>(buffer));

        SECTION("disasm_one returns the first instruction") {
            const auto first_instruction = code.disasm_one();
            REQUIRE(first_instruction.has_value());
            REQUIRE(first_instruction->length == 1);
            REQUIRE(first_instruction->mnemonic == "push");
        }

        SECTION("disasm walks instructions in order") {
            const auto decoded = code.disasm(4, 8);
            REQUIRE(decoded.size() == 4);
            REQUIRE(decoded[0].mnemonic == "push");
            REQUIRE(decoded[1].mnemonic == "mov");
            REQUIRE(decoded[2].mnemonic == "nop");
            REQUIRE(decoded[3].mnemonic == "ret");
            REQUIRE(decoded[0].length == 1);
            REQUIRE(decoded[1].length == 3);
            REQUIRE(decoded[2].length == 1);
            REQUIRE(decoded[3].length == 1);
            REQUIRE(decoded[1].address == decoded[0].address + 1);
        }
    }
}

TEST_CASE("mem::disasm works through a remote-style accessor", "[mem][disasm][remote]") {
    // Self-attach: same address space, but the bound accessor is the remote
    // accessor (Read/WriteProcessMemory or process_vm_readv path), exercising
    // the same code path ryclass-mcp will use.
    const auto current_pid = bb::process::current().id();
    REQUIRE(current_pid.has_value());
    auto self_via_remote = bb::process::attach(*current_pid);

    auto code_at_test_function = self_via_remote.at(
        reinterpret_cast<uintptr_t>(&bytebinder_test_marker_function));
    auto decoded = code_at_test_function.disasm(/*max_instructions=*/1);
    REQUIRE_FALSE(decoded.empty());
    REQUIRE(decoded.front().length > 0);
}

TEST_CASE("resolve_rip_relative returns expected address", "[disasm]") {
    REQUIRE(bb::resolve_rip_relative(0x100, 7, 0x10) == 0x117);
    REQUIRE(bb::resolve_rip_relative(0x1000, 5, -16) == 0xFF5);
}
