/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_watchpoint_condition.h"

#include <cstddef>
#include <cstdint>

namespace bytebinder {
    /**
     * @brief A request to trap access to a small span of memory using one of the
     *        CPU's hardware debug slots. This is the primitive a "find what
     *        accesses this address" workflow installs on each thread it watches.
     *
     * @note size must be 1, 2, 4, or 8 bytes for a data condition (write or
     *       read_write), and the hardware requires address be aligned to size.
     *       For the execute condition the length is fixed at one byte and size is
     *       ignored. A single thread has only four debug slots, so at most four
     *       watchpoints can be active on it at once.
     */
    struct watchpoint {
        uintptr_t address = 0;
        size_t size = 0;
        watchpoint_condition condition = watchpoint_condition::write;
    };
}
