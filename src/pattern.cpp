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

#include "pattern.h"

namespace bytebinder {
    pattern::pattern(char *signature_, char *mask_, size_t size_) : signature(signature_, size_), mask(mask_, size_), size(size_) {}

    uintptr_t pattern::scan() const {
        size_t l = size;

        for (size_t n = 0; n < (mem::storage.size - l); ++n) {
            if (match(mem::storage.base + n, signature.c_str(), mask.c_str())) {
                return mem::storage.base + n;
            }
        }

        return std::numeric_limits<uintptr_t>::max();
    }

    bool pattern::match(uintptr_t address, const char *pattern, const char *mask) {
        size_t n = 0;

        while (reinterpret_cast<const char *>(address)[n] == pattern[n] || mask[n] == (char)'?') {
            if (!mask[++n]) {
                return true;
            }
        }

        return false;
    }
}