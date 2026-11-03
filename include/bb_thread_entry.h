/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <cstdint>

namespace bytebinder {
    /// @brief One thread of a process, identified by its OS thread id. On macOS
    ///        the id is the thread's Mach port value, which is stable only for
    ///        the lifetime of the enumerating task's reference.
    struct BYTEBINDER_API thread_entry {
        uint64_t thread_id = 0;
    };
}
