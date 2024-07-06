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
#include "mem.h"

namespace bytebinder {
    /**
     * @brief Represents a memory pattern, often used for pattern scanning within binary data.
     *
     * This class encapsulates the signature and mask of the pattern, along with its size, to facilitate memory scanning based on this pattern.
     */
    class pattern {
    public:
        std::string signature; ///< The binary pattern as a string.
        std::string mask; ///< The mask where 'x' indicates a byte to match and '?' indicates a wildcard byte.
        size_t size; ///< The size of the pattern.

        /**
         * @brief Constructs a pattern object with the specified signature, mask, and size.
         *
         * @param signature The pattern's byte signature represented as a string.
         * @param mask The pattern's mask where each 'x' represents a byte that must match and each '?' represents any byte.
         * @param size The length of the pattern and mask.
         */
        pattern(char *signature, char *mask, size_t size);

        /**
         * @brief Scans memory for the pattern starting from the base address provided by `mem::storage()` up to the end of its reported size.
         *
         * This method iterates over memory, applying the `match` function to find the pattern.
         *
         * @throws memory_operation_exception if the pattern cannot be found within the memory range.
         * @return The address where the pattern is found, or `std::numeric_limits<uintptr_t>::max()` if the pattern is not found.
         */
        [[nodiscard]] uintptr_t scan() const;

    private:
        /**
         * @brief Checks if the memory at a given address matches the specified pattern and mask.
         *
         * This static function compares bytes one by one, respecting the mask ('x' must match, '?' can be any byte).
         *
         * @param address The starting address to check for a match.
         * @param pattern The byte pattern as a C-style string.
         * @param mask The mask for the pattern as a C-style string.
         * @return True if the pattern matches the memory at the address, false otherwise.
         */
        static bool match(uintptr_t address, const char *pattern, const char *mask);
    };
}