/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <array>
#include <cstdint>

namespace bytebinder {
    /**
     * @brief A portable view of a thread's integer register state. The three
     *        named fields are meaningful on every supported architecture; the
     *        instruction pointer is what identifies the instruction that hit a
     *        breakpoint, which is the register a "what accesses this address"
     *        workflow reads.
     *
     * @note general_registers holds the architecture's general-purpose integer
     *       registers in encoding order, which differs per architecture:
     *       - x86_64: RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8..R15.
     *       - aarch64: X0..X15 (the first sixteen of X0..X30).
     *       - arm (32-bit): R0..R15, zero-extended.
     *       Fields past the architecture's register count are left zero.
     */
    struct BYTEBINDER_API cpu_registers {
        uint64_t instruction_pointer = 0;
        uint64_t stack_pointer = 0;
        uint64_t frame_pointer = 0;
        std::array<uint64_t, 16> general_registers{};
    };
}
