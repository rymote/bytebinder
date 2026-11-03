/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_memory_accessor.h"
#include "bb_local_accessor.h"
#include "bb_vmt_handle.h"

namespace bytebinder {
    class vmt;

    /**
     * @brief Reads an object's vtable pointer and patches individual entries.
     *
     * Usage:
     * @code
     *   bb::vmt v(reinterpret_cast<uintptr_t>(some_object));
     *   auto handle = v.hook(3, reinterpret_cast<void*>(&my_detour));
     *   // ... later ...
     *   handle.unhook();
     * @endcode
     *
     * The patch is process-wide: every instance sharing the vtable observes the
     * detour. To isolate one instance, copy the vtable first and rebind the
     * object's vtable pointer (not provided here — it is application-specific).
     */
    class BYTEBINDER_API vmt {
    public:
        /// @brief Reads the vtable pointer at @p object_address through @p accessor.
        explicit vmt(uintptr_t object_address,
                     memory_accessor* accessor = &local_accessor::instance());

        /// @brief Returns the address of the vtable owned by the bound object.
        [[nodiscard]] uintptr_t vtable_address() const noexcept { return vtable_pointer; }
        /// @brief Returns the accessor used to read/write vtable slots.
        [[nodiscard]] memory_accessor* backing_accessor() const noexcept { return accessor; }

        /// Returns the function pointer stored at @p index in the vtable.
        [[nodiscard]] uintptr_t function_at(size_t index) const;

        /// Replaces the entry at @p index with @p detour and returns a handle
        /// that can revert the change.
        vmt_handle hook(size_t index, void* detour);

    private:
        uintptr_t vtable_pointer = 0;
        memory_accessor* accessor = nullptr;
    };
}
