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
    /// @brief One loaded module: short name, full path, load base, and size.
    struct BYTEBINDER_API module_info {
        std::string name;
        std::string path;
        uintptr_t base = 0;
        size_t size = 0;
    };
}
