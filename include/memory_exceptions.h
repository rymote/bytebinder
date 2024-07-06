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

namespace bytebinder {
    /**
     * @brief Enumeration of error codes for memory operation exceptions.
     */
    enum class memory_error_code {
        // Initialization Errors
        INITIALIZATION_FAILED = 101,
        MODULE_INFO_RETRIEVAL_FAILED = 102,
        BASE_ADDRESS_CALCULATION_ERROR = 103,

        // Memory Allocation Errors
        ALLOCATION_FAILED = 201,
        DEALLOCATION_FAILED = 202,
        HEAP_INITIALIZATION_FAILED = 203,

        // Memory Operation Errors
        PROTECTION_CHANGE_FAILED = 301,
        READ_FAILED = 302,
        WRITE_FAILED = 303,
        PATTERN_MATCH_FAILED = 304,

        // Hooking Errors
        HOOK_INSTALLATION_FAILED = 401,
        HOOK_REMOVAL_FAILED = 402,
        TRAMPOLINE_SETUP_FAILED = 403,

        // Aseembly Errors
        ASSEMBLY_FAILED = 501,

        // Miscellaneous Errors
        UNKNOWN_ERROR = 601,
        INVALID_OPERATION = 602
    };

    /**
     * @brief Exception class for memory manipulation errors.
     *
     * This class encapsulates errors that occur during memory operations, providing detailed error messages
     * and potentially additional context or error codes.
     */
    class memory_operation_exception : public std::exception {
    private:
        std::string message; ///< Detailed error message.
        memory_error_code errorCode; ///< Error code enum.

    public:
        /**
         * @brief Constructor for the exception with a message and an optional error code.
         *
         * @param message The error message describing what went wrong.
         * @param errorCode The error code enum for additional context.
         */
        memory_operation_exception(const std::string &message,
                                   memory_error_code errorCode = memory_error_code::UNKNOWN_ERROR);

        /**
         * @brief Returns the error message associated with the exception.
         *
         * @return The error message.
         */
        virtual const char *what() const noexcept override;

        /**
         * @brief Retrieves the error code associated with the exception.
         *
         * @return The error code enum value.
         */
        memory_error_code get_error_code() const noexcept;
    };
}