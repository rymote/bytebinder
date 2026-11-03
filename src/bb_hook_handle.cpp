/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#include "bb_hook_handle.h"
#include "bb_mem.h"

namespace bytebinder {
    bool hook_handle::unhook() {
        return detour_pointer != nullptr && mem::unhook(*this);
    }
}
