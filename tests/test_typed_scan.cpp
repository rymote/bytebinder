#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

namespace {
    alignas(16) volatile unsigned char find_bytes_haystack[1024] = {};
    alignas(16) volatile unsigned char find_bytes_all_haystack[1024] = {};

    void write_haystack_bytes(volatile unsigned char* destination,
                                const unsigned char* source,
                                size_t length) {
        for (size_t index = 0; index < length; ++index) {
            destination[index] = source[index];
        }
    }
}

// Scan-family tests crash under AddressSanitizer because the chunked memcpy
// inside pattern::scan / typed_scan reads in 64 KiB strides, which crosses
// ASan's per-global redzones in the test binary's .data/.rdata. The non-ASan
// build covers correctness; under ASan we skip these to avoid false positives.
#if !BYTEBINDER_HAS_ASAN
TEST_CASE("process::find_bytes locates exact byte sequence", "[process][find_bytes]") {
    volatile unsigned char xor_key = 0x5A;
    unsigned char needle[12];
    const unsigned char obfuscated[12] = {
        static_cast<unsigned char>(0x13 ^ 0x5A), static_cast<unsigned char>(0x37 ^ 0x5A),
        static_cast<unsigned char>(0xC0 ^ 0x5A), static_cast<unsigned char>(0xDE ^ 0x5A),
        static_cast<unsigned char>(0xBA ^ 0x5A), static_cast<unsigned char>(0xBE ^ 0x5A),
        static_cast<unsigned char>(0xFA ^ 0x5A), static_cast<unsigned char>(0xCE ^ 0x5A),
        static_cast<unsigned char>(0x71 ^ 0x5A), static_cast<unsigned char>(0xA5 ^ 0x5A),
        static_cast<unsigned char>(0x6D ^ 0x5A), static_cast<unsigned char>(0xE3 ^ 0x5A),
    };
    for (size_t index = 0; index < sizeof(needle); ++index) {
        needle[index] = static_cast<unsigned char>(obfuscated[index] ^ xor_key);
    }
    write_haystack_bytes(find_bytes_haystack + 200, needle, sizeof(needle));

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());
    bb::mem hit = current_process.find_bytes({needle, sizeof(needle)},
                                              self_modules.front().name);
    REQUIRE(hit.address == reinterpret_cast<uintptr_t>(&find_bytes_haystack[200]));
}

TEST_CASE("process::find_bytes_all returns every occurrence", "[process][find_bytes]") {
    volatile unsigned char xor_key = 0xA5;
    unsigned char needle[12];
    const unsigned char obfuscated[12] = {
        static_cast<unsigned char>(0xAB ^ 0xA5), static_cast<unsigned char>(0xCD ^ 0xA5),
        static_cast<unsigned char>(0xEF ^ 0xA5), static_cast<unsigned char>(0x01 ^ 0xA5),
        static_cast<unsigned char>(0x23 ^ 0xA5), static_cast<unsigned char>(0x45 ^ 0xA5),
        static_cast<unsigned char>(0x67 ^ 0xA5), static_cast<unsigned char>(0x89 ^ 0xA5),
        static_cast<unsigned char>(0x4F ^ 0xA5), static_cast<unsigned char>(0x12 ^ 0xA5),
        static_cast<unsigned char>(0x9C ^ 0xA5), static_cast<unsigned char>(0x3B ^ 0xA5),
    };
    for (size_t index = 0; index < sizeof(needle); ++index) {
        needle[index] = static_cast<unsigned char>(obfuscated[index] ^ xor_key);
    }
    write_haystack_bytes(find_bytes_all_haystack + 100, needle, sizeof(needle));
    write_haystack_bytes(find_bytes_all_haystack + 500, needle, sizeof(needle));
    write_haystack_bytes(find_bytes_all_haystack + 900, needle, sizeof(needle));

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());
    auto result = current_process.find_bytes_all({needle, sizeof(needle)},
                                                   self_modules.front().name);
    REQUIRE(result.matches.size() >= 3);
}

namespace {
    volatile int32_t bytebinder_scan_value_buffer[1024] = {};
    volatile unsigned char bytebinder_scan_alignment_buffer[1024] = {};
}

TEST_CASE("process::scan_value finds an exact int32_t", "[process][scan_value]") {
    bytebinder_scan_value_buffer[300] = 0xDEADBEEF;

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());

    auto result = current_process.scan_value<int32_t>(
        static_cast<int32_t>(0xDEADBEEF),
        self_modules.front().name);

    bool found_at_buffer = false;
    for (uintptr_t address : result.matches) {
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_value_buffer[300])) {
            found_at_buffer = true;
            break;
        }
    }
    REQUIRE(found_at_buffer);
}

TEST_CASE("process::scan_value honors alignment", "[process][scan_value]") {
    // Place the int32 value 0xCAFEBABE at offset 5 (deliberately misaligned).
    int32_t marker = static_cast<int32_t>(0xCAFEBABE);
    for (size_t byte_index = 0; byte_index < sizeof(marker); ++byte_index) {
        const_cast<volatile unsigned char*>(bytebinder_scan_alignment_buffer)[5 + byte_index] =
            reinterpret_cast<const unsigned char*>(&marker)[byte_index];
    }

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());

    // Default alignment (4 for int32) should NOT find it at offset 5.
    auto aligned = current_process.scan_value<int32_t>(
        static_cast<int32_t>(0xCAFEBABE),
        self_modules.front().name);
    bool found_aligned = false;
    for (uintptr_t address : aligned.matches) {
        if (address == reinterpret_cast<uintptr_t>(
                &bytebinder_scan_alignment_buffer[5])) {
            found_aligned = true;
            break;
        }
    }
    REQUIRE_FALSE(found_aligned);

    // Alignment 1 should find it.
    auto unaligned = current_process.scan_value<int32_t>(
        static_cast<int32_t>(0xCAFEBABE),
        self_modules.front().name, 1);
    bool found_unaligned = false;
    for (uintptr_t address : unaligned.matches) {
        if (address == reinterpret_cast<uintptr_t>(
                &bytebinder_scan_alignment_buffer[5])) {
            found_unaligned = true;
            break;
        }
    }
    REQUIRE(found_unaligned);
}

namespace {
    volatile float bytebinder_scan_range_buffer[1024] = {};
}

TEST_CASE("process::scan_value_in_range finds float within epsilon", "[process][scan_value]") {
    bytebinder_scan_range_buffer[42] = 1.5f;
    bytebinder_scan_range_buffer[200] = 1.500001f;
    bytebinder_scan_range_buffer[800] = 2.0f;

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());

    auto result = current_process.scan_value_in_range<float>(
        1.49f, 1.51f, self_modules.front().name);

    bool found_42 = false, found_200 = false, found_800 = false;
    for (uintptr_t address : result.matches) {
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_range_buffer[42])) found_42 = true;
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_range_buffer[200])) found_200 = true;
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_range_buffer[800])) found_800 = true;
    }
    REQUIRE(found_42);
    REQUIRE(found_200);
    REQUIRE_FALSE(found_800);
}

namespace {
    volatile uint32_t bytebinder_scan_mask_buffer[1024] = {};
}

TEST_CASE("process::scan_value_with_mask matches low byte only", "[process][scan_value]") {
    bytebinder_scan_mask_buffer[10] = 0xAABBCC42;
    bytebinder_scan_mask_buffer[20] = 0x11223342;
    bytebinder_scan_mask_buffer[30] = 0xAABBCC43;

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());

    auto result = current_process.scan_value_with_mask<uint32_t>(
        0x42u, 0xFFu, self_modules.front().name);

    bool found_10 = false, found_20 = false, found_30 = false;
    for (uintptr_t address : result.matches) {
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_mask_buffer[10])) found_10 = true;
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_mask_buffer[20])) found_20 = true;
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_mask_buffer[30])) found_30 = true;
    }
    REQUIRE(found_10);
    REQUIRE(found_20);
    REQUIRE_FALSE(found_30);
}
#endif // !__SANITIZE_ADDRESS__ (scan-family tests)
