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
#include "mem.h"

namespace bytebinder {
    /**
     * @brief A template class that creates a trampoline for function hooking.
     *
     * This class facilitates function interception by creating a trampoline that hooks a specified function
     * and provides access to both the original and detour functions. It is typically used in situations where
     * function behavior needs to be modified or extended, such as in software testing or reverse engineering.
     *
     * @tparam ReturnType The return type of the function being hooked.
     * @tparam Args The argument types of the function being hooked.
     */
    template<typename ReturnType, typename... Args>
    class trampoline {
        using FunctionType = ReturnType(*)(Args...); ///< Function pointer type for the target function.

        FunctionType detourFunction = nullptr; ///< Pointer to the detour function which will replace the original function.
        FunctionType originalFunction = nullptr; ///< Pointer to the original function that is being hooked.
        mem memory; ///< Memory object representing the location of the target function.

    public:
        /**
         * @brief Constructs a trampoline object using a specific IDA-style memory pattern to locate and hook a function.
         *
         * The constructor scans for the function's memory address using the provided IDA-style pattern, then sets up a hook
         * that redirects calls to the original function to the detour function, while preserving a pointer to the original.
         * An IDA-style pattern is a string that represents binary data with hexadecimal bytes and wildcards ('?') where bytes are unknown.
         *
         * @throws memory_operation_exception if the pattern cannot be found or hooking fails.
         * @param ida_pattern The IDA-style memory pattern used to locate the target function in memory. This pattern should be a sequence of hexadecimal bytes separated by spaces, where '?' represents any byte.
         */
        template<size_t Size>
        constexpr explicit
        trampoline(const char(&ida_pattern)[Size]) : pattern(ida_pattern), memory(mem::scan(ida_pattern)) {
            memory.hook(detourFunction, &originalFunction);
        }

        /**
         * @brief Returns the detour function pointer.
         *
         * This function can be used to call the detour function directly, allowing manual control over when
         * the modified behavior is executed.
         *
         * @return Function pointer to the detour function.
         */
        FunctionType get_main_function() const {
            return detourFunction;
        }

        /**
         * @brief Returns the original function pointer.
         *
         * This function allows the original behavior of the hooked function to be called, useful for conditions
         * where the original functionality needs to be preserved or executed alongside new behavior.
         *
         * @return Function pointer to the original function.
         */
        FunctionType get_original_function() const {
            return originalFunction;
        }

        /**
         * @brief Function call operator that executes the original function.
         *
         * This operator allows the trampoline object to be used like a function call, directly invoking
         * the original function with the specified arguments.
         *
         * @param args Arguments to pass to the original function.
         * @return The result of the original function call.
         */
        ReturnType operator()(Args...args) {
            return originalFunction(args...);
        }
    };
}