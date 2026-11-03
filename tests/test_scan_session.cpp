#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"
#include "scan_test_accessor.h"

#include <algorithm>
#include <memory>

namespace {
    bool contains_address(const std::vector<bb::scan_match>& matches, uintptr_t address) {
        return std::any_of(matches.begin(), matches.end(),
                           [address](const bb::scan_match& match) { return match.address == address; });
    }
}

TEST_CASE("scan_session narrows an exact int32 value across scans", "[scan_session]") {
    const uintptr_t base = 0x40000000;
    auto accessor = std::make_shared<scan_test_accessor>(base, 4096);

    // One cell holds the tracked value; fill the rest with a different value
    // so the first scan does not match everywhere.
    const size_t tracked_offset = 512;
    for (size_t offset = 0; offset + 4 <= accessor->storage.size(); offset += 4) {
        accessor->poke<int32_t>(offset, 7);
    }
    accessor->poke<int32_t>(tracked_offset, 100);

    bb::process target(accessor);
    bb::scan_session session(target, bb::scan_value_type::int32);

    const size_t first_count = session.first_scan(bb::scan_constraint::equals(100));
    REQUIRE(first_count == 1);
    REQUIRE(contains_address(session.results(), base + tracked_offset));

    // Value drops; decreased() then an exact match should keep the same cell.
    accessor->poke<int32_t>(tracked_offset, 80);
    REQUIRE(session.next_scan(bb::scan_constraint::decreased()) == 1);
    REQUIRE(session.next_scan(bb::scan_constraint::equals(80)) == 1);
    REQUIRE(session.results().front().address == base + tracked_offset);
}

TEST_CASE("scan_session unknown-initial-value then changed/unchanged", "[scan_session]") {
    const uintptr_t base = 0x50000000;
    auto accessor = std::make_shared<scan_test_accessor>(base, 256);
    for (size_t offset = 0; offset + 4 <= accessor->storage.size(); offset += 4) {
        accessor->poke<int32_t>(offset, static_cast<int32_t>(offset));
    }

    bb::process target(accessor);
    bb::scan_session session(target, bb::scan_value_type::int32);

    const size_t total = session.first_scan_unknown();
    REQUIRE(total == 256 / 4);

    // Change exactly one cell, then unchanged() must drop it and changed()
    // must keep only it.
    accessor->poke<int32_t>(64, 999999);

    bb::scan_session changed_session = session; // copy the recorded set
    REQUIRE(session.next_scan(bb::scan_constraint::unchanged()) == total - 1);
    REQUIRE_FALSE(contains_address(session.results(), base + 64));

    REQUIRE(changed_session.next_scan(bb::scan_constraint::changed()) == 1);
    REQUIRE(changed_session.results().front().address == base + 64);
}

TEST_CASE("scan_session undo restores the previous result set", "[scan_session]") {
    const uintptr_t base = 0x60000000;
    auto accessor = std::make_shared<scan_test_accessor>(base, 64);
    for (size_t offset = 0; offset + 4 <= accessor->storage.size(); offset += 4) {
        accessor->poke<int32_t>(offset, 5);
    }

    bb::process target(accessor);
    bb::scan_session session(target, bb::scan_value_type::int32);

    REQUIRE(session.first_scan(bb::scan_constraint::equals(5)) == 16);
    REQUIRE(session.next_scan(bb::scan_constraint::greater_than(1000)) == 0);
    session.undo();
    REQUIRE(session.result_count() == 16);
}

TEST_CASE("scan_session range and float scans", "[scan_session]") {
    const uintptr_t base = 0x70000000;
    auto accessor = std::make_shared<scan_test_accessor>(base, 64);
    accessor->poke<float>(0, 1.5f);
    accessor->poke<float>(4, 2.5f);
    accessor->poke<float>(8, 100.0f);

    bb::process target(accessor);
    bb::scan_session session(target, bb::scan_value_type::float32);

    REQUIRE(session.first_scan(bb::scan_constraint::between(1.0f, 3.0f)) >= 2);
    REQUIRE(contains_address(session.results(), base + 0));
    REQUIRE(contains_address(session.results(), base + 4));
    REQUIRE_FALSE(contains_address(session.results(), base + 8));
}

TEST_CASE("scan_session rejects previous-relative first scans and late type change", "[scan_session]") {
    const uintptr_t base = 0x80000000;
    auto accessor = std::make_shared<scan_test_accessor>(base, 64);
    bb::process target(accessor);
    bb::scan_session session(target, bb::scan_value_type::int32);

    REQUIRE_THROWS_AS(session.first_scan(bb::scan_constraint::increased()),
                      bb::memory_operation_exception);
    REQUIRE_THROWS_AS(session.next_scan(bb::scan_constraint::equals(0)),
                      bb::memory_operation_exception);

    session.first_scan(bb::scan_constraint::equals(0));
    REQUIRE_THROWS_AS(session.set_value_type(bb::scan_value_type::int16),
                      bb::memory_operation_exception);
}
