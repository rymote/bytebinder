/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"
#include "bb_function_source.h"

#include <cstddef>
#include <cstdint>

namespace bytebinder {
    /// @brief One function reported by find_functions. @c size is only known for
    ///        functions from the unwind table, and is zero otherwise.
    struct BYTEBINDER_API function_entry {
        uintptr_t address = 0;
        size_t size = 0;
        function_source source = function_source::prologue;
    };
}
