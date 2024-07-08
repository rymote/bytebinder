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

#include "memory_exceptions.h"

namespace bytebinder {
    memory_operation_exception::memory_operation_exception(const std::string &message, memory_error_code errorCode)
            : message(message), errorCode(errorCode) {}

    const char *memory_operation_exception::what() const noexcept {
        return message.c_str();
    }

    memory_error_code memory_operation_exception::get_error_code() const noexcept {
        return errorCode;
    }
}