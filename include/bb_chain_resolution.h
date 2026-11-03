/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"
#include "bb_memory_error_code.h"

#include <cstddef>
#include <cstdint>
#include <optional>

namespace bytebinder {
    /**
     * @brief Outcome of resolve_chain.
     *
     * On success `address` holds the final VA. On failure all the diagnostic
     * fields describe where and why:
     * - failed_at_step: zero-based index into the steps span.
     * - failure: typed code (READ_FAILED on bad deref, etc).
     * - partial_walk_addr: the running address at the moment of failure,
     *   post-offset and pre-deref.
     */
    struct BYTEBINDER_API chain_resolution {
        std::optional<uintptr_t> address;
        size_t failed_at_step = 0;
        memory_error_code failure = memory_error_code::READ_FAILED;
        uintptr_t partial_walk_addr = 0;
    };
}
