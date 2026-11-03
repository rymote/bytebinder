/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_init_registry.h"

namespace bytebinder {
    /// @brief Registers a free initializer to run when run_init_funcs() is called.
    class init_func {
    public:
        explicit init_func(const function_initializer_t& initializer) {
            function_initializers().push_back(initializer);
        }
    };
}
