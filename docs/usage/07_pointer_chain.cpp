// docs/usage/07_pointer_chain.cpp
//
// Builds a small three-level object graph in this process (a global root slot
// pointing at a "player" block, whose slot 2 points at a "stats" block holding
// a health value at +0x10), then walks it the way you would walk a chain
// found with a memory scanner:
//
//   1. resolve_chain   - get the leaf address, with diagnostics on failure
//   2. read_chain<T>   - resolve and read the typed leaf value in one call
//   3. find_pointers_to - discover which slots hold a pointer to a block
//   4. watch_chain     - get a callback when the chain re-resolves elsewhere
//
// The same calls work against another process: swap `bb::process::current()`
// for `bb::process::attach(pid)`.

#include <bytebinder.h>

#include <array>
#include <chrono>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <memory>
#include <thread>

namespace {
    uintptr_t root_slot = 0;
}

int main() {
    auto stats_block = std::make_unique<uint8_t[]>(0x40);
    auto player_block = std::make_unique<uintptr_t[]>(8);
    const uint32_t initial_health = 100;
    std::memcpy(stats_block.get() + 0x10, &initial_health, sizeof(initial_health));
    player_block[2] = reinterpret_cast<uintptr_t>(stats_block.get());
    root_slot = reinterpret_cast<uintptr_t>(player_block.get());

    auto current = bb::process::current();
    const uintptr_t base = reinterpret_cast<uintptr_t>(&root_slot);

    // [base] -> player, [player + 0x10] -> stats, stats + 0x10 is the leaf.
    const std::array<bb::chain_step, 3> steps{{
        {0x00, true},
        {0x10, true},
        {0x10, false},
    }};

    const auto resolution = current.resolve_chain(base, steps);
    if (resolution.address.has_value()) {
        std::printf("health lives at 0x%" PRIxPTR "\n", *resolution.address);
    }

    if (const auto health = current.read_chain<uint32_t>(base, steps)) {
        std::printf("health = %u\n", *health);
    }

    // Null the root so the second hop dereferences 0x10, then inspect the
    // diagnostics. A null stats pointer alone would not fail the walk: the
    // last step only adds its offset.
    root_slot = 0;
    const auto broken = current.resolve_chain(base, steps);
    if (!broken.address.has_value()) {
        std::printf("chain broke at step %zu while dereferencing 0x%" PRIxPTR "\n",
                    broken.failed_at_step, broken.partial_walk_addr);
    }
    root_slot = reinterpret_cast<uintptr_t>(player_block.get());

    // root_slot is a writable global, so it shows up as a holder of the
    // player pointer. Heap holders appear too when you drop the module filter.
    const auto holders = current.find_pointers_to(root_slot);
    std::printf("%zu slot(s) point at the player block\n", holders.size());

    // Watch the chain, then "reallocate" the stats block the way a game would
    // on respawn. The callback fires once for the initial resolution and once
    // after the move.
    auto watcher = current.watch_chain(
        base, steps,
        [](uintptr_t resolved) {
            std::printf("chain resolves to 0x%" PRIxPTR "\n", resolved);
        },
        std::chrono::milliseconds{20});

    std::this_thread::sleep_for(std::chrono::milliseconds{100});
    auto respawned_stats = std::make_unique<uint8_t[]>(0x40);
    std::memcpy(respawned_stats.get() + 0x10, &initial_health, sizeof(initial_health));
    player_block[2] = reinterpret_cast<uintptr_t>(respawned_stats.get());
    std::this_thread::sleep_for(std::chrono::milliseconds{100});

    watcher.stop();
    return 0;
}
