/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "pch.h"

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

        [[nodiscard]] bool valid() const noexcept { return length > 0; }
    };
}
