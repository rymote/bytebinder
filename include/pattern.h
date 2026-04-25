/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 *
 * This file is part of bytebinder, a powerful tool for reading, writing, hooking, and manipulating memory addresses.
 *
 * Repository: https://github.com/rymote/bytebinder
 *
 * For issues, suggestions, or contributions, please visit the repository or contact the authors.
 *
 * This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties
 * of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders
 * be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out
 * of, or in connection with the software or the use or other dealings in the software.
 */

#pragma once

#include "pch.h"
#include "memory_exceptions.h"

namespace bytebinder {
    class memory_accessor;

    class BYTEBINDER_API pattern {
    public:
        std::string signature; ///< The binary pattern as a string of length size().
        std::string mask;      ///< Same length as signature; 'x' = match byte, '?' = wildcard.

        pattern(std::string signature_bytes, std::string match_mask);

        [[nodiscard]] size_t size() const noexcept { return signature.size(); }

        /// Scans the local process's mem::storage range. Back-compat entry point.
        [[nodiscard]] uintptr_t scan() const;

        /// Scans @p total_size bytes starting at @p base via @p accessor in 64 KiB
        /// chunks with overlap. Returns the first match address or
        /// numeric_limits<uintptr_t>::max() if not found.
        [[nodiscard]] uintptr_t scan(memory_accessor& accessor,
                                       uintptr_t base, size_t total_size) const;

    private:
        [[nodiscard]] bool match_local(uintptr_t haystack_address) const noexcept;
        [[nodiscard]] bool match_buffer(const uint8_t* buffer) const noexcept;
    };

    BYTEBINDER_API pattern parse_ida_pattern(std::string_view ida_pattern);
}