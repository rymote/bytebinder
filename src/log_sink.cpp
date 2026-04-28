/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "log_sink.h"

#include <mutex>

namespace bytebinder {
    namespace {
        std::mutex sink_mutex;
        log_sink current_sink;
    }

    void set_log_sink(log_sink sink) {
        std::lock_guard<std::mutex> guard(sink_mutex);
        current_sink = std::move(sink);
    }

    void log(log_level level, std::string_view message) {
        log_sink local_copy;
        {
            std::lock_guard<std::mutex> guard(sink_mutex);
            local_copy = current_sink;
        }
        if (!local_copy) return;
        try {
            local_copy(level, message);
        } catch (...) {
            // Swallow — sink failures must not propagate into bytebinder.
        }
    }
}
