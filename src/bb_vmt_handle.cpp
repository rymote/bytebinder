/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#include "bb_vmt_handle.h"

namespace bytebinder {
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
