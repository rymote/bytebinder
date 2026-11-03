/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"
#include "bb_xref_kind.h"

#include <cstddef>
#include <cstdint>

namespace bytebinder {
    /// @brief One disassembled instruction whose computed target equals the
    ///        queried address, plus its kind and decoded length.
    struct BYTEBINDER_API xref {
        uintptr_t instruction_address = 0;
        xref_kind kind = xref_kind::call;
        size_t instruction_length = 0;
    };
}
