/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

namespace bytebinder {
    /// @brief Severity of a log message routed through the installed sink.
    enum class log_level {
        debug,
        info,
        warn,
        error
    };
}
