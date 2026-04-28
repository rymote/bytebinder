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
     * @brief A resolved symbol — function or data — with its name, runtime
     *        address, byte size (0 if unknown), and the owning module's
     *        basename.
     *
     * @note On Windows, symbol resolution requires DbgHelp + PDBs for
     *       non-exported symbols. Linux parses ELF .dynsym/.symtab directly,
     *       so stripped binaries only expose dynamic symbols.
     */
    struct BYTEBINDER_API symbol_info {
        std::string name;
        std::string module_name;
        uintptr_t address = 0;
        size_t size = 0;

        /// @brief Returns true if `address` is non-zero.
        [[nodiscard]] bool valid() const noexcept { return address != 0; }
    };

    /**
     * @brief Result of process::symbolize: the containing symbol plus the
     *        byte offset from the symbol's start to the queried address.
     */
    struct BYTEBINDER_API symbolize_result {
        symbol_info symbol;
        size_t offset_from_start = 0;
    };
}
