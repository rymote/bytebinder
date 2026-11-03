#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"
#include "chain_test_layout.h"
#include "chain_test_leaf.h"
#include "chain_test_node.h"

namespace {
    volatile chain_test_layout chain_test_root{};
    volatile chain_test_node   chain_test_node_a{};
    volatile chain_test_leaf   chain_test_leaf_value{};

    void initialize_chain_test_buffers(uint32_t leaf_value) {
        chain_test_leaf_value.value = leaf_value;
        const_cast<chain_test_node&>(chain_test_node_a).pointer_to_node_b =
            reinterpret_cast<uintptr_t>(&chain_test_leaf_value);
        const_cast<chain_test_layout&>(chain_test_root).pointer_to_node_a =
            reinterpret_cast<uintptr_t>(&chain_test_node_a);
    }
}

TEST_CASE("resolve_chain walks dereferenced steps to the leaf", "[process][chain]") {
    initialize_chain_test_buffers(0xC0FFEE42);
    auto current_process = bb::process::current();
    std::array<bb::chain_step, 3> steps{{
        {0,  true},
        {0,  true},
        {0,  false},
    }};
    auto resolution = current_process.resolve_chain(
        reinterpret_cast<uintptr_t>(&chain_test_root), steps);
    REQUIRE(resolution.address.has_value());
    REQUIRE(*resolution.address ==
            reinterpret_cast<uintptr_t>(&chain_test_leaf_value));
}

TEST_CASE("resolve_chain populates diagnostics on failure", "[process][chain]") {
    auto current_process = bb::process::current();
    std::array<bb::chain_step, 2> steps{{
        {0, true},
        {0, true},
    }};
    auto resolution = current_process.resolve_chain(0x1, steps);
    REQUIRE_FALSE(resolution.address.has_value());
    REQUIRE(resolution.failed_at_step == 0);
    REQUIRE(resolution.failure == bb::memory_error_code::READ_FAILED);
    REQUIRE(resolution.partial_walk_addr == 0x1);
}

TEST_CASE("resolve_chain leaf step without dereference returns base+sum(offsets)",
          "[process][chain]") {
    auto current_process = bb::process::current();
    std::array<bb::chain_step, 2> steps{{
        {0x10, false},
        {0x20, false},
    }};
    auto resolution = current_process.resolve_chain(0x1000, steps);
    REQUIRE(resolution.address.has_value());
    REQUIRE(*resolution.address == 0x1030);
}

TEST_CASE("resolve_chain with empty steps returns base unchanged", "[process][chain]") {
    auto current_process = bb::process::current();
    auto resolution = current_process.resolve_chain(0xDEADBEEF, {});
    REQUIRE(resolution.address.has_value());
    REQUIRE(*resolution.address == 0xDEADBEEF);
}

TEST_CASE("read_chain returns the typed value at the chain leaf", "[process][chain]") {
    initialize_chain_test_buffers(0xCAFEBABE);
    auto current_process = bb::process::current();
    std::array<bb::chain_step, 3> steps{{
        {0, true},
        {0, true},
        {offsetof(chain_test_leaf, value), false},
    }};
    auto value = current_process.read_chain<uint32_t>(
        reinterpret_cast<uintptr_t>(&chain_test_root), steps);
    REQUIRE(value.has_value());
    REQUIRE(*value == 0xCAFEBABE);
}

TEST_CASE("read_chain returns nullopt when the chain is broken", "[process][chain]") {
    auto current_process = bb::process::current();
    std::array<bb::chain_step, 1> steps{{ {0, true} }};
    auto value = current_process.read_chain<uint32_t>(0x1, steps);
    REQUIRE_FALSE(value.has_value());
}

#if !BYTEBINDER_HAS_ASAN
namespace {
    volatile uintptr_t bytebinder_chain_pointer_holder = 0;
    volatile uint8_t   bytebinder_chain_target_buffer[64] = {};
}

TEST_CASE("find_pointers_to locates a synthetic pointer in writable data",
          "[process][find_pointers_to]") {
    bytebinder_chain_pointer_holder =
        reinterpret_cast<uintptr_t>(&bytebinder_chain_target_buffer[0]);

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());

    auto matches = current_process.find_pointers_to(
        bytebinder_chain_pointer_holder,
        self_modules.front().name);
    bool found_holder = false;
    for (uintptr_t address : matches) {
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_chain_pointer_holder)) {
            found_holder = true;
            break;
        }
    }
    REQUIRE(found_holder);
}
#endif // !BYTEBINDER_HAS_ASAN

TEST_CASE("watch_chain fires on initial resolution", "[process][watch_chain]") {
    initialize_chain_test_buffers(0x11111111);

    auto current_process = bb::process::current();
    std::array<bb::chain_step, 3> steps{{
        {0, true},
        {0, true},
        {0, false},
    }};

    std::atomic<int> fire_count{0};
    std::atomic<uintptr_t> seen_address{0};

    auto handle = current_process.watch_chain(
        reinterpret_cast<uintptr_t>(&chain_test_root),
        steps,
        [&](uintptr_t address) {
            seen_address.store(address);
            fire_count.fetch_add(1);
        },
        std::chrono::milliseconds{20});

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    while (std::chrono::steady_clock::now() < deadline && fire_count.load() == 0) {
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }

    handle.stop();
    REQUIRE(fire_count.load() >= 1);
    REQUIRE(seen_address.load() ==
            reinterpret_cast<uintptr_t>(&chain_test_leaf_value));
}

TEST_CASE("watch_chain re-resolves when intermediate pointer flips",
          "[process][watch_chain]") {
    static volatile chain_test_leaf bytebinder_alt_leaf{};
    initialize_chain_test_buffers(0x22222222);
    bytebinder_alt_leaf.value = 0x33333333;

    auto current_process = bb::process::current();
    std::array<bb::chain_step, 3> steps{{
        {0, true},
        {0, true},
        {0, false},
    }};

    std::atomic<uintptr_t> latest{0};
    auto handle = current_process.watch_chain(
        reinterpret_cast<uintptr_t>(&chain_test_root),
        steps,
        [&](uintptr_t address) { latest.store(address); },
        std::chrono::milliseconds{20});

    const uintptr_t first_target = reinterpret_cast<uintptr_t>(&chain_test_leaf_value);
    const auto deadline_one = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    while (std::chrono::steady_clock::now() < deadline_one
           && latest.load() != first_target) {
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }
    REQUIRE(latest.load() == first_target);

    // Flip the intermediate pointer (chain_test_node_a.pointer_to_node_b)
    // to point at the alt leaf.
    const_cast<chain_test_node&>(chain_test_node_a).pointer_to_node_b =
        reinterpret_cast<uintptr_t>(&bytebinder_alt_leaf);

    const uintptr_t second_target = reinterpret_cast<uintptr_t>(&bytebinder_alt_leaf);
    const auto deadline_two = std::chrono::steady_clock::now() + std::chrono::seconds{1};
    while (std::chrono::steady_clock::now() < deadline_two
           && latest.load() != second_target) {
        std::this_thread::sleep_for(std::chrono::milliseconds{10});
    }

    handle.stop();
    REQUIRE(latest.load() == second_target);
}
