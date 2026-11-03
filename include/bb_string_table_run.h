/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <cstddef>
#include <cstdint>

namespace bytebinder {
    /// @brief A contiguous block of adjacent NUL-terminated printable-ASCII
    ///        strings (e.g. a localization table).
    struct BYTEBINDER_API string_table_run {
        uintptr_t base = 0;
        size_t size_bytes = 0;
        size_t string_count = 0;
    };
}
