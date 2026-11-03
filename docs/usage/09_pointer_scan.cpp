// docs/usage/09_pointer_scan.cpp
//
// Reverse pointer scanning: given a volatile leaf address (the kind a value
// scan leaves you with), find static-based pointer paths that resolve back to
// it. Each path starts inside a loaded module, so it survives a restart of the
// target once rebased. Here the graph is built in-process; against a remote
// target, swap bb::process::current() for bb::process::attach(pid).

#include <bytebinder.h>

#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <memory>

int main() {
    auto current = bb::process::current();
    bb::pointer_scanner scanner(current);

    // The address we want to reach again after a restart.
    auto leaf = std::make_unique<uint8_t[]>(0x40);
    const uintptr_t leaf_address = reinterpret_cast<uintptr_t>(leaf.get());

    bb::pointer_scan_options options;
    options.max_depth = 4;
    options.max_offset = 0x400;
    options.max_results = 20;

    const auto paths = scanner.find_paths(leaf_address, options);
    std::printf("indexed %zu pointer slot(s); found %zu path(s)\n",
                scanner.index_size(), paths.size());

    for (const auto& path : paths) {
        std::printf("  base 0x%" PRIxPTR " depth %zu\n", path.base, path.depth());

        // Every emitted path re-resolves to the target through resolve_chain.
        const auto resolution = current.resolve_chain(path.base, path.to_chain_steps());
        if (resolution.address == leaf_address) {
            std::printf("    verified: resolves back to the leaf\n");
        }
    }

    return 0;
}
