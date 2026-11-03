/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_init_registry.h"
#include "bb_mem_holder.h"

namespace bytebinder {
    /**
     * @brief Lazily-resolved function pointer that can be called as if it
     *        were a regular function once run_init_funcs() has fired.
     */
    template<typename FunctionPointer>
    class static_func : public mem_holder {
    public:
        explicit static_func(const mem_initializer_t& initializer) : mem_holder() {
            mem_initializers()[this] = initializer;
        }

        template<typename... Args>
        auto operator()(Args... args) -> decltype(target.get<FunctionPointer>()(args...)) {
            return target.get<FunctionPointer>()(args...);
        }
    };
}
