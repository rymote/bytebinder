/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <cstdint>
#include <vector>

namespace bytebinder {
    /// @brief A pointer-aligned run treated as a candidate vtable: the run's
    ///        start address plus the resolved entries.
    struct BYTEBINDER_API vtable_candidate {
        uintptr_t address = 0;
        std::vector<uintptr_t> entries;
    };
}
