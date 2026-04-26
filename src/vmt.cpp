/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "vmt.h"
#include "memory_exceptions.h"

namespace bytebinder {
    vmt::vmt(uintptr_t object_address, memory_accessor* backing)
        : accessor(backing) {
        if (accessor == nullptr) {
            throw memory_operation_exception("vmt requires a non-null accessor.",
                                              memory_error_code::INVALID_OPERATION);
        }
        if (accessor->read(object_address, &vtable_pointer, sizeof(vtable_pointer))
            != sizeof(vtable_pointer)) {
            throw memory_operation_exception("Failed to read vtable pointer from object.",
                                              memory_error_code::READ_FAILED);
        }
        if (vtable_pointer == 0) {
            throw memory_operation_exception("Object has a null vtable pointer.",
                                              memory_error_code::INVALID_OPERATION);
        }
    }

    uintptr_t vmt::function_at(size_t index) const {
        const uintptr_t entry_address = vtable_pointer + index * sizeof(uintptr_t);
        uintptr_t function_pointer = 0;
        if (accessor->read(entry_address, &function_pointer, sizeof(function_pointer))
            != sizeof(function_pointer)) {
            throw memory_operation_exception("Failed to read vtable entry.",
                                              memory_error_code::READ_FAILED);
        }
        return function_pointer;
    }

    vmt_handle vmt::hook(size_t index, void* detour) {
        const uintptr_t entry_address = vtable_pointer + index * sizeof(uintptr_t);
        const uintptr_t original_pointer = function_at(index);
        const uintptr_t detour_pointer = reinterpret_cast<uintptr_t>(detour);

        if (accessor->write(entry_address, &detour_pointer, sizeof(detour_pointer))
            != sizeof(detour_pointer)) {
            throw memory_operation_exception("Failed to overwrite vtable entry.",
                                              memory_error_code::WRITE_FAILED);
        }
        return vmt_handle(entry_address, original_pointer, accessor);
    }

    bool vmt_handle::unhook() {
        if (!installed() || accessor == nullptr) {
            return false;
        }
        const bool restored = accessor->write(entry_address,
                                               &original_pointer,
                                               sizeof(original_pointer))
                              == sizeof(original_pointer);
        entry_address = 0;
        accessor = nullptr;
        return restored;
    }
}
