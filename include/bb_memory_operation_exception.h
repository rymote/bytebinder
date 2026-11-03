/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_pch.h"
#include "bb_memory_error_code.h"

namespace bytebinder {
    /**
     * @brief Exception class for memory manipulation errors.
     *
     * This class encapsulates errors that occur during memory operations, providing detailed error messages
     * and potentially additional context or error codes.
     */
    class BYTEBINDER_API memory_operation_exception : public std::exception {
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
