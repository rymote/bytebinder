/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "pch.h"

namespace bytebinder {
    /**
     * @brief A resolved symbol — function or data — with its name, runtime
     *        address, byte size (0 if unknown), and the owning module's
     *        basename.
     */
    struct BYTEBINDER_API symbol_info {
        std::string name;
        std::string module_name;
        uintptr_t address = 0;
        size_t size = 0;

        [[nodiscard]] bool valid() const noexcept { return address != 0; }
    };
}
