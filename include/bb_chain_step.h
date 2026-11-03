/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <cstddef>

namespace bytebinder {
    /**
     * @brief One hop in a pointer chain.
     *
     * `offset` is added to the running address; `dereference == true` means
     * after adding the offset, read 8 bytes at the resulting address and
     * treat them as the next address. The final step in a typical chain
     * has `dereference == false`: its offset is the field-within-struct
     * location whose value the caller will read separately via read_chain<T>.
     */
    struct BYTEBINDER_API chain_step {
        ptrdiff_t offset = 0;
        bool dereference = true;
    };
}
