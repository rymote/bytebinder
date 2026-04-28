/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

/**
 * @file
 * @brief Memory snapshot dumper. Writes one binary file per region plus a
 *        JSON manifest. The manifest is written LAST so partial dumps
 *        leave a recoverable state. Does not compress; pipe through
 *        `xz` / `zstd` externally if needed.
 *
 * Example:
 * @code
 * bb::memory_dump_options options;
 * options.include_anonymous_mappings = true;
 * auto result = bb::process::current().dump_memory("./snapshot", options);
 * std::printf("manifest: %s\n", result.manifest_path.string().c_str());
 * @endcode
 */

#include "bb_api.h"

#include <cstddef>
#include <filesystem>

namespace bytebinder {

    class process;

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

    /// @brief Aggregate result of a dump pass: counts plus the path to the
    ///        manifest file (which is written last).
    struct BYTEBINDER_API memory_dump_result {
        size_t regions_dumped = 0;
        size_t regions_skipped = 0;
        size_t total_bytes_written = 0;
        std::filesystem::path manifest_path;
    };

    /// @brief Free-function backend for process::dump_memory.
    BYTEBINDER_API memory_dump_result dump_memory_for_process(
        const process& target_process,
        std::filesystem::path output_directory,
        const memory_dump_options& options);
}
