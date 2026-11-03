/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <cstddef>
#include <filesystem>

namespace bytebinder {
    /// @brief Aggregate result of a dump pass: counts plus the path to the
    ///        manifest file (which is written last).
    struct BYTEBINDER_API memory_dump_result {
        size_t regions_dumped = 0;
        size_t regions_skipped = 0;
        size_t total_bytes_written = 0;
        std::filesystem::path manifest_path;
    };
}
