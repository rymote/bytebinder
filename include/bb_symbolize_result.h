/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"
#include "bb_symbol_info.h"

#include <cstddef>

namespace bytebinder {
    /**
     * @brief Result of process::symbolize: the containing symbol plus the
     *        byte offset from the symbol's start to the queried address.
     */
    struct BYTEBINDER_API symbolize_result {
        symbol_info symbol;
        size_t offset_from_start = 0;
    };
}
