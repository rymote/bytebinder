/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_pch.h"
#include "bb_mem.h"

namespace bytebinder {
    class mem_holder;

    /// @brief Lazy producer of a `mem` value used by the static_mem/static_func
    ///        initialization queue.
    using mem_initializer_t = std::function<mem()>;
    /// @brief Lazy void-returning callback used by init_func and static_hook.
    using function_initializer_t = std::function<void()>;

    inline std::unordered_map<mem_holder*, mem_initializer_t>& mem_initializers() {
        static std::unordered_map<mem_holder*, mem_initializer_t> instance;
        return instance;
    }

    inline std::vector<function_initializer_t>& function_initializers() {
        static std::vector<function_initializer_t> instance;
        return instance;
    }
}
