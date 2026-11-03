/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <cstddef>

namespace bytebinder {
    /**
     * @brief Value type selected at runtime for a scan session. The templated
     *        scans on `bb::process` fix the type at compile time; a scan session
     *        instead picks the type from this enum, which is what a value editor
     *        front-end needs when the user chooses a type from a control.
     */
    enum class scan_value_type {
        int8,
        uint8,
        int16,
        uint16,
        int32,
        uint32,
        int64,
        uint64,
        float32,
        float64
    };

    /// @brief Width in bytes of a scan value of @p type.
    [[nodiscard]] BYTEBINDER_API size_t scan_value_type_width(scan_value_type type) noexcept;

    /// @brief True if @p type is a floating-point type (float32 or float64).
    [[nodiscard]] BYTEBINDER_API bool scan_value_type_is_float(scan_value_type type) noexcept;

    /// @brief True if @p type is a signed integer type.
    [[nodiscard]] BYTEBINDER_API bool scan_value_type_is_signed(scan_value_type type) noexcept;
}
