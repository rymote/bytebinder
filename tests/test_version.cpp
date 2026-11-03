#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

#include <string_view>

TEST_CASE("bytebinder_version matches the CMake project version", "[meta]") {
    const char* version = bytebinder_version();
    REQUIRE(version != nullptr);
    REQUIRE(std::string_view(version) == BYTEBINDER_EXPECTED_VERSION);
}

TEST_CASE("bytebinder_abi_revision matches the expected revision", "[meta]") {
    // Bump together with kAbiRevision in src/bb_version.cpp.
    REQUIRE(bytebinder_abi_revision() == 2u);
}
