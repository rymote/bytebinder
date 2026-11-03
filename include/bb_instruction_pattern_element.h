/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <cstddef>
#include <optional>
#include <string>

namespace bytebinder {
    /// @brief One element of an instruction-template pattern: mnemonic
    ///        (case-insensitive; empty = wildcard) and optional operand-count
    ///        constraint.
    struct BYTEBINDER_API instruction_pattern_element {
        std::string mnemonic;
        std::optional<size_t> operand_count;
    };
}
