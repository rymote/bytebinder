/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

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
}
