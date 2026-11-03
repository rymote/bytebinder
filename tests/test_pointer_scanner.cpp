#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"
#include "scan_test_accessor.h"

#include <algorithm>
#include <memory>

TEST_CASE("pointer_scanner finds a static multi-level path to a target", "[pointer_scanner]") {
    const uintptr_t base = 0x40000000;
    auto accessor = std::make_shared<scan_test_accessor>(base, 0x400);

    // The first 0x100 bytes stand in for a module's static data.
    accessor->set_module("target.exe", 0, 0x100);

    // Build a two-dereference chain:
    //   static slot (base+0x10) -> base+0x200
    //   slot (base+0x208)       -> base+0x300
    //   target field            == base+0x304
    accessor->poke<uintptr_t>(0x10, base + 0x200);
    accessor->poke<uintptr_t>(0x208, base + 0x300);

    const uintptr_t target_address = base + 0x304;

    bb::process target(accessor);
    bb::pointer_scanner scanner(target);

    bb::pointer_scan_options options;
    options.max_depth = 4;
    options.max_offset = 0x1000;

    const auto paths = scanner.find_paths(target_address, options);
    REQUIRE(scanner.index_size() >= 2);
    REQUIRE_FALSE(paths.empty());

    // Every reported path must actually resolve to the target.
    for (const auto& path : paths) {
        const auto resolution = target.resolve_chain(path.base, path.to_chain_steps());
        REQUIRE(resolution.address.has_value());
        REQUIRE(*resolution.address == target_address);
        REQUIRE(scanner.target_process().accessor().is_local() == false);
    }

    // At least one path must start from the static base slot.
    const bool from_static_base = std::any_of(paths.begin(), paths.end(),
                                              [base](const bb::pointer_path& path) {
                                                  return path.base == base + 0x10;
                                              });
    REQUIRE(from_static_base);
}

TEST_CASE("pointer_scanner returns no path when none is static", "[pointer_scanner]") {
    const uintptr_t base = 0x90000000;
    auto accessor = std::make_shared<scan_test_accessor>(base, 0x400);
    // No module set, so no slot can be a static base.
    accessor->poke<uintptr_t>(0x10, base + 0x200);
    accessor->poke<uintptr_t>(0x208, base + 0x300);

    bb::process target(accessor);
    bb::pointer_scanner scanner(target);
    const auto paths = scanner.find_paths(base + 0x304);
    REQUIRE(paths.empty());
}
