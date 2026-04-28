/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "bb_api.h"

#include <functional>
#include <string_view>

/**
 * @file
 * @brief Process-wide diagnostic-log sink. Defaults to no-op; install a
 *        callback via `set_log_sink`. Sink invocations may happen on
 *        arbitrary library threads.
 */
namespace bytebinder {
    /// @brief Severity of a log message routed through the installed sink.
    enum class log_level {
        debug,
        info,
        warn,
        error
    };

    /**
     * @brief Sink callback signature. The library guarantees the
     *        std::string_view is valid only for the duration of the call.
     *        Sinks must not throw; exceptions are swallowed.
     */
    using log_sink = std::function<void(log_level, std::string_view)>;

    /**
     * @brief Installs (or clears, when @p sink is empty) a process-wide log
     *        sink. Default is no sink — log calls are no-ops. Thread-safe to
     *        install; sink invocations happen from arbitrary library threads.
     */
    BYTEBINDER_API void set_log_sink(log_sink sink);

    /// Internal: emit a log message. Public-but-undocumented; meant to be
    /// called from bytebinder internals, not user code.
    BYTEBINDER_API void log(log_level level, std::string_view message);
}
