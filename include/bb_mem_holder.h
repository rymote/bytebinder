/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_mem.h"

namespace bytebinder {
    /// @brief Common base for objects that own a deferred-resolved `mem`
    ///        target. Populated by run_init_funcs.
    class mem_holder {
    public:
        mem_holder() : target() {}

        /// @brief Stores the resolved `mem` for later access.
        void set_target(const mem& new_target) { target = new_target; }
        /// @brief Returns the previously stored target (default-constructed
        ///        until run_init_funcs has fired).
        mem get_target() const { return target; }

    protected:
        mem target;
    };
}
