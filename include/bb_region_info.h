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
#include <string>

namespace bytebinder {
    /// @brief One mapped region: address range, protection bits, and the backing
    ///        file path (empty for anonymous mappings).
    struct BYTEBINDER_API region_info {
        uintptr_t base = 0;
        size_t size = 0;
        int protection = 0;
        std::string mapped_path;
    };
}
