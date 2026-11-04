/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

namespace bytebinder {
    /// @brief How find_functions learned about a function.
    enum class function_source {
        unwind_table, ///< Listed in the module's x64 exception directory. Exact.
        call_target,  ///< Target of a direct call from a listed function. Finds leaf functions.
        prologue,     ///< Matched the prologue heuristic. The module had no usable table.
    };
}
