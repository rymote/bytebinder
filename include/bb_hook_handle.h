/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <polyhook2/Detour/ADetour.hpp>

namespace bytebinder {
    class mem;

    /**
     * @brief Reversible handle to an installed function detour.
     *        Returned by mem::hook; unhook() reverts the patch.
     */
    class BYTEBINDER_API hook_handle {
    public:
        hook_handle() = default;
        /// @brief Returns true if the handle owns a live detour.
        [[nodiscard]] bool installed() const noexcept { return detour_pointer != nullptr; }
        /// @brief Reverts the detour and clears the handle.
        bool unhook();

    private:
        explicit hook_handle(PLH::Detour* detour) : detour_pointer(detour) {}
        PLH::Detour* detour_pointer = nullptr;
        friend class mem;
    };
}
