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
     * @brief Lazily-resolved typed pointer. Construction registers an
     *        initializer; run_init_funcs() resolves it; subsequent operator->
     *        calls dereference the resolved address.
     */
    template<typename PointerType>
    class static_mem : public mem_holder {
    public:
        explicit static_mem(const mem_initializer_t& initializer) : mem_holder() {
            mem_initializers()[this] = initializer;
        }

        PointerType operator->() {
            return target.get<PointerType>();
        }
    };
}
