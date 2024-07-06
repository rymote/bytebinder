#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"

uint8_t buffer[1024];

TEST_CASE("Initialization and address calculation", "[mem]") {
    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));
    bb::mem memory(reinterpret_cast<void*>(buffer));

    SECTION("init function sets base correctly") {
        REQUIRE(bb::mem::storage.base == reinterpret_cast<uintptr_t>(buffer));
        REQUIRE(bb::mem::storage.size == sizeof(buffer));
    }

    uint32_t expectedValue = 123456789;
    *reinterpret_cast<uint32_t*>(buffer + 100) = expectedValue;

    SECTION("add method calculates new address correctly") {
        auto offsettedMemory = memory.add(100);
        auto retrievedValue = *offsettedMemory.get<uint32_t*>();
        REQUIRE(retrievedValue == expectedValue);
    }
}

TEST_CASE("RIP-relative address calculation", "[mem]") {
    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));
    bb::mem memory(reinterpret_cast<void*>(buffer + 100));

    int32_t relativeOffset = 50;
    *reinterpret_cast<int32_t*>(buffer + 100 + 3) = relativeOffset;

    uint32_t knownValue = 123456789;
    auto targetAddress = reinterpret_cast<uintptr_t>(buffer + 100 + 3 + 4 + relativeOffset);
    *reinterpret_cast<uint32_t*>(targetAddress) = knownValue;

    bb::mem calculatedAddress = memory.rip(3);

    SECTION("Calculates correct RIP-relative address and retrieves correct value") {
        uint32_t retrievedValue = *calculatedAddress.get<uintptr_t*>();
        REQUIRE(retrievedValue == knownValue);
    }
}

TEST_CASE("Memory operations using mem.get and mem.set", "[mem]") {
    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));
    bb::mem memory(reinterpret_cast<void*>(buffer));

    memset(buffer, 0, sizeof(buffer));

    SECTION("Set and Get integer values") {
        uint32_t setValue = 0x87654321;

        auto mem1 = memory.add(30);
        mem1.set(setValue);

        auto mem2 = memory.add(30);
        auto getValue = *mem2.get<uint32_t*>();

        REQUIRE(getValue == setValue);
    }

    SECTION("Set and Get byte values") {
        uint8_t byteValue = 0xAB;
        memory.add(15).set(byteValue);
        auto readByte = *memory.add(15).get<uint8_t*>();
        REQUIRE(readByte == byteValue);
    }

    SECTION("Set and Get for multiple data types and sizes") {
        uint64_t largeValue = 0xCAFEBABEDEADBEEF;
        memory.add(40).set(largeValue);
        REQUIRE(*memory.add(40).get<uint64_t*>() == largeValue);
    }

    SECTION("Set and Get across various offsets") {
        for (int offset = 0; offset < 100; offset += 4) {
            uint32_t value = static_cast<uint32_t>(offset) * 5;
            memory.add(offset).set(value);
            REQUIRE(*memory.add(offset).get<uint32_t*>() == value);
        }
    }
}


TEST_CASE("NOP operation", "[mem]") {
    memset(buffer, 0, sizeof(buffer));
    bb::mem memory(reinterpret_cast<void*>(buffer + 50));
    memory.nop(10);

    SECTION("Buffer contains NOPs at correct position") {
        for (int i = 0; i < 10; i++) {
            REQUIRE(buffer[50 + i] == 0x90);
        }
    }
}

TEST_CASE("RET operation sets correct opcode", "[mem]") {
    bb::mem memory(reinterpret_cast<void*>(buffer));
    memory.ret();

    REQUIRE(buffer[0] == 0xC3);
}

TEST_CASE("JMP and CALL operations", "[mem]") {
    bb::mem memory(reinterpret_cast<void*>(buffer));
    uintptr_t fake_function = reinterpret_cast<uintptr_t>(buffer) + 200;

    SECTION("JMP writes correct opcode and address") {
        memory.jmp(fake_function);
        REQUIRE(buffer[0] == 0x48);
        REQUIRE(buffer[1] == 0xB8);
        REQUIRE(*reinterpret_cast<uintptr_t*>(buffer + 2) == fake_function);
        REQUIRE(buffer[10] == 0xFF);
        REQUIRE(buffer[11] == 0xE0);
    }

    SECTION("CALL writes correct opcode and relative address") {
        memory.call(fake_function);
        REQUIRE(buffer[0] == 0xE8);
        int32_t rel_address = *reinterpret_cast<int32_t*>(buffer + 1);
        REQUIRE(reinterpret_cast<uintptr_t>(buffer + 5 + rel_address) == fake_function);
    }
}
TEST_CASE("Search for pattern in memory and returns correct position", "[mem]") {
    memset(buffer, 0, sizeof(buffer));
    uint8_t knownPattern[] = { 0xF2, 0xAF, 0xDF, 0x1F, 0x9F, 0xFB, 0x12 };
    size_t patternStartOffset = 6;
    std::memcpy(&buffer[patternStartOffset], knownPattern, sizeof(knownPattern));

    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));

    auto result = bb::mem::scan("AF ? 1F 9F FB");

    uint8_t expectedByte = buffer[patternStartOffset + 1];
    REQUIRE(*result.get<uint8_t*>() == expectedByte);

    SECTION("Pattern scanning correctly identifies memory locations") {
        REQUIRE(*result.get<uint8_t*>() == 0xAF);
    }
}

void (*OrigFunction)(int) = nullptr;
void HookFunction(int value){
    OrigFunction(5);
}

int testValue = 0;
NOINLINE void TestHookFunction(int value) {
    testValue = value;
}

TEST_CASE("Function hooking and behavior validation") {
    SECTION("Original function should modify global state correctly") {
        TestHookFunction(2);
        REQUIRE(testValue == 2);
    }

    if (!OrigFunction) {
        bb::mem(reinterpret_cast<void*>(&TestHookFunction)).hook(HookFunction, &OrigFunction);
    }

    SECTION("Original function pointer should call hooked function") {
        OrigFunction(10);
        REQUIRE(testValue == 10);
    }

    SECTION("Original function should be called with altered argument after hooking") {
        TestHookFunction(10);
        REQUIRE(testValue == 5);
    }
}

TEST_CASE("Memory comparison validation", "[mem]") {
    memset(buffer, 0, sizeof(buffer));
    const char pattern[] = "HelloWorld";
    std::memcpy(buffer + 100, pattern, strlen(pattern));
    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));
    bb::mem memory(reinterpret_cast<void*>(buffer + 100));

    SECTION("Correctly compares identical memory content") {
        REQUIRE(memory.compare(pattern, strlen(pattern)) == true);
    }

    SECTION("Correctly identifies non-identical memory content") {
        const char wrongPattern[] = "Goodbye";
        REQUIRE(memory.compare(wrongPattern, strlen(wrongPattern)) == false);
    }

    SECTION("Correctly compares partial memory content") {
        REQUIRE(memory.compare("Hello", 5) == true);
    }
}