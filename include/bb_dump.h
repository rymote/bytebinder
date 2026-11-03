/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
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
#include "bb_memory_dump_options.h"
#include "bb_memory_dump_result.h"

#include <cstddef>
#include <filesystem>

namespace bytebinder {

    class process;

    /// @brief Free-function backend for process::dump_memory.
    BYTEBINDER_API memory_dump_result dump_memory_for_process(
        const process& target_process,
        std::filesystem::path output_directory,
        const memory_dump_options& options);
}
