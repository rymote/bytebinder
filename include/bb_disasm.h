/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "bb_pch.h"

namespace bytebinder {
    /**
     * @brief A single decoded instruction.
     *
     * `text` is the formatted Intel-syntax string (e.g. "mov rax, qword ptr [rdi+0x10]"),
     * `mnemonic` is just the opcode name ("mov"), `bytes` is the raw machine code,
     * and `length` is the instruction's byte length.
     */
    struct BYTEBINDER_API instruction {
        uintptr_t address = 0;
        size_t length = 0;
        std::string mnemonic;
        std::string text;
        std::vector<uint8_t> bytes;

        /// @brief Returns true if this instruction was successfully decoded.
        [[nodiscard]] bool valid() const noexcept { return length > 0; }
    };

    /**
     * @brief Resolves an x86-64 RIP-relative address: returns
     *        instruction_address + instruction_length + signed_displacement.
     *        Used by mem::rip and the xref scanner.
     */
    [[nodiscard]] BYTEBINDER_API uintptr_t resolve_rip_relative(
        uintptr_t instruction_address,
        size_t instruction_length,
        int32_t signed_displacement);
}
