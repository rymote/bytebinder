/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"
#include "bb_memory_accessor.h"

#include <cstdint>

namespace bytebinder {
    class vmt;

    /**
     * @brief Tracks an installed vtable patch so it can be reverted.
     */
    class BYTEBINDER_API vmt_handle {
    public:
        vmt_handle() = default;

        /// @brief Returns true while the patch is in effect.
        [[nodiscard]] bool installed() const noexcept { return entry_address != 0; }
        /// @brief Returns the function pointer that was originally stored at
        ///        the patched vtable slot.
        [[nodiscard]] uintptr_t original_function() const noexcept { return original_pointer; }
        /// @brief Returns the address of the patched vtable entry.
        [[nodiscard]] uintptr_t entry() const noexcept { return entry_address; }

        /// @brief Restores the original vtable entry and clears the handle.
        bool unhook();

    private:
        vmt_handle(uintptr_t entry_address,
                   uintptr_t original_pointer,
                   memory_accessor* accessor)
            : entry_address(entry_address),
              original_pointer(original_pointer),
              accessor(accessor) {}

        uintptr_t entry_address = 0;
        uintptr_t original_pointer = 0;
        memory_accessor* accessor = nullptr;

        friend class vmt;
    };
}
