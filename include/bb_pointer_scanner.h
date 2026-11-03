/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

/**
 * @file
 * @brief Reverse pointer scanning: given a target address, find static-based
 *        pointer paths that resolve to it. This is the discovery step behind a
 *        stable cheat: process::find_pointers_to locates a single pointer to an
 *        address, while a pointer scan chains several dereferences from a module
 *        base down to the target, so the result keeps working after a restart
 *        once rebased. The resulting paths feed straight into
 *        process::resolve_chain and watch_chain via pointer_path::to_chain_steps.
 *
 * Example:
 * @code
 * bb::pointer_scanner scanner(bb::process::attach(pid));
 * auto paths = scanner.find_paths(health_address);
 * for (const auto& path : paths) {
 *     auto resolution = target.resolve_chain(path.base, path.to_chain_steps());
 *     // resolution.address == health_address
 * }
 * @endcode
 */

#include "bb_api.h"
#include "bb_pointer_path.h"
#include "bb_pointer_scan_options.h"
#include "bb_process.h"

#include <cstdint>
#include <vector>

namespace bytebinder {
    /**
     * @brief Builds a reverse index of pointer slots in a process and searches
     *        it for multi-level paths to a target. Not thread safe: the index is
     *        mutable state; use one scanner per thread.
     */
    class BYTEBINDER_API pointer_scanner {
    public:
        /// @brief Binds a scanner to @p target. The index is built lazily on the
        ///        first find_paths, or eagerly via build_index.
        explicit pointer_scanner(process target);

        /**
         * @brief Scans the indexed regions for pointer-aligned slots whose stored
         *        value points into any readable region, and records them for
         *        reverse search. Replaces any existing index. Honors the index
         *        filters and slot cap in @p options.
         */
        void build_index(const pointer_scan_options& options = {});

        /// @brief Number of pointer slots currently indexed.
        [[nodiscard]] size_t index_size() const noexcept { return pointer_slots.size(); }

        /// @brief True once an index has been built.
        [[nodiscard]] bool has_index() const noexcept { return index_built; }

        /**
         * @brief Finds static-based pointer paths that resolve to @p target,
         *        bounded by @p options. Builds the index first if none exists.
         *        Returned paths are ordered shallowest first.
         */
        [[nodiscard]] std::vector<pointer_path> find_paths(
            uintptr_t target,
            const pointer_scan_options& options = {});

        /// @brief The bound process.
        [[nodiscard]] const process& target_process() const noexcept { return target; }

    private:
        struct pointer_slot {
            uintptr_t value = 0;   // pointer stored at this slot
            uintptr_t address = 0; // where the pointer is stored
        };

        struct module_range {
            uintptr_t begin = 0;
            uintptr_t end = 0;
        };

        process target;
        std::vector<pointer_slot> pointer_slots; // sorted by value
        std::vector<module_range> module_ranges; // sorted by begin
        bool index_built = false;

        [[nodiscard]] bool address_is_static(uintptr_t address) const;

        void search_upward(uintptr_t need,
                           size_t derefs_used,
                           const pointer_scan_options& options,
                           std::vector<ptrdiff_t>& offsets_leafward,
                           std::vector<pointer_path>& out_paths,
                           size_t& visited_nodes) const;
    };
}
