/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#include "bb_scan_value_type.h"

namespace bytebinder {
    size_t scan_value_type_width(scan_value_type type) noexcept {
        switch (type) {
            case scan_value_type::int8:
            case scan_value_type::uint8:    return 1;
            case scan_value_type::int16:
            case scan_value_type::uint16:   return 2;
            case scan_value_type::int32:
            case scan_value_type::uint32:
            case scan_value_type::float32:  return 4;
            case scan_value_type::int64:
            case scan_value_type::uint64:
            case scan_value_type::float64:  return 8;
        }
        return 0;
    }

    bool scan_value_type_is_float(scan_value_type type) noexcept {
        return type == scan_value_type::float32 || type == scan_value_type::float64;
    }

    bool scan_value_type_is_signed(scan_value_type type) noexcept {
        switch (type) {
            case scan_value_type::int8:
            case scan_value_type::int16:
            case scan_value_type::int32:
            case scan_value_type::int64:
            case scan_value_type::float32:
            case scan_value_type::float64:  return true;
            default:                        return false;
        }
    }
}
