/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <cstdint>
#include <string>

namespace bytebinder {
    /// @brief One running process: its id, short image name, and full image
    ///        path when it can be read (empty otherwise).
    struct BYTEBINDER_API process_entry {
        uint32_t process_id = 0;
        std::string name;
        std::string path;
    };
}
