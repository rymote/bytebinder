/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_init_func.h"
#include "bb_init_registry.h"
#include "bb_mem_holder.h"
#include "bb_static_func.h"
#include "bb_static_hook.h"
#include "bb_static_mem.h"

namespace bytebinder {
    /// @brief Resolves every pending mem initializer and runs every queued
    ///        init_func / static_hook. Call once after process startup.
    inline void run_init_funcs() {
        for (auto& [holder, initializer] : mem_initializers()) {
            holder->set_target(initializer());
        }
        for (auto& initializer : function_initializers()) {
            initializer();
        }
    }
}
