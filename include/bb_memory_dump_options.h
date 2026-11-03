/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <cstddef>

namespace bytebinder {
    /// @brief Inclusion filters and per-region size bounds for dump_memory.
    struct BYTEBINDER_API memory_dump_options {
        bool include_executable = true;
        bool include_writable_data = true;
        bool include_readonly_data = true;
        bool include_anonymous_mappings = false;
        bool include_special_mappings = false;

        size_t min_region_size = 0;
        size_t max_region_size = 0;
    };
}
