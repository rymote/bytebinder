/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "memory_accessor.h"
#include "local_accessor.h"

namespace bytebinder {
    class vmt;

    /**
     * @brief Tracks an installed vtable patch so it can be reverted.
     */
    class BYTEBINDER_API vmt_handle {
    public:
        vmt_handle() = default;

        [[nodiscard]] bool installed() const noexcept { return entry_address != 0; }
        [[nodiscard]] uintptr_t original_function() const noexcept { return original_pointer; }
        [[nodiscard]] uintptr_t entry() const noexcept { return entry_address; }

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
        explicit vmt(uintptr_t object_address,
                     memory_accessor* accessor = &local_accessor::instance());

        [[nodiscard]] uintptr_t vtable_address() const noexcept { return vtable_pointer; }
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
