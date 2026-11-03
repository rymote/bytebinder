/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"
#include "bb_memory_accessor.h"

#include <cstddef>
#include <cstdint>

namespace bytebinder {
    /**
     * @brief Tuning for a pointer scan. The defaults keep the search bounded:
     *        up to four dereferences, offsets within 4 KiB (one struct's worth),
     *        and a capped result count, which is what keeps a reverse scan from
     *        exploding on a large process.
     */
    struct BYTEBINDER_API pointer_scan_options {
        /// @brief Maximum number of dereferences in a path.
        size_t max_depth = 4;

        /// @brief Maximum per-level offset added before each dereference.
        uintptr_t max_offset = 0x1000;

        /// @brief Maximum number of paths to return. 0 means unlimited.
        size_t max_results = 1000;

        /// @brief Upper bound on reverse-search nodes visited, a hard stop
        ///        against pathological blow-up. 0 means unlimited.
        size_t max_visited_nodes = 2'000'000;

        /// @brief Protection required of a region to be indexed as a source of
        ///        pointer slots. Pointers to chase live in writable data.
        int index_required_protection = protection::read | protection::write;

        /// @brief Protection forbidden of an indexed region.
        int index_forbidden_protection = protection::execute;

        /// @brief Cap on indexed pointer slots. 0 means unlimited.
        size_t max_index_slots = 0;
    };
}
