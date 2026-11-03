/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

/**
 * @file
 * @brief Enumerating the running processes, so a front-end can present a target
 *        picker before calling process::attach. These are plain snapshots taken
 *        at call time; a returned pid may already have exited by the time it is
 *        used, which process::attach and process::alive detect.
 */

#include "bb_api.h"
#include "bb_process_entry.h"

#include <optional>
#include <string_view>
#include <vector>

namespace bytebinder {
    /**
     * @brief Returns every process the caller can see, newest listing each
     *        call. On Windows this uses the toolhelp snapshot; on Linux it reads
     *        /proc; on macOS it uses the sysctl process table. Entries whose
     *        name or path cannot be read still appear with the fields left empty.
     */
    [[nodiscard]] BYTEBINDER_API std::vector<process_entry> list_processes();

    /**
     * @brief Returns the processes whose short image name equals @p name,
     *        compared case-insensitively. Useful for attaching to a target
     *        known only by its executable name.
     */
    [[nodiscard]] BYTEBINDER_API std::vector<process_entry> find_processes_by_name(
        std::string_view name);
}
