/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

/**
 * @file
 * @brief Enumerating a process's threads. This is the read-only half of the
 *        debugger surface: a front-end lists threads before suspending them or
 *        reading their registers, and a remote operation that must stop the
 *        target first needs the thread set to act on.
 */

#include "bb_api.h"
#include "bb_thread_entry.h"

#include <cstdint>
#include <vector>

namespace bytebinder {
    /**
     * @brief Returns the thread ids of @p process_id. On Windows this filters
     *        the toolhelp thread snapshot by owning process; on Linux it reads
     *        /proc/<pid>/task; on macOS it uses task_threads on the task port,
     *        which requires the privileges task_for_pid needs for a foreign pid.
     *        Returns an empty vector if the process cannot be inspected.
     */
    [[nodiscard]] BYTEBINDER_API std::vector<thread_entry> list_threads(uint32_t process_id);

    /// @brief Convenience wrapper that enumerates the calling process's threads.
    [[nodiscard]] BYTEBINDER_API std::vector<thread_entry> list_current_process_threads();
}
