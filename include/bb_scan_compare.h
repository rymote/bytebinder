/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

namespace bytebinder {
    /**
     * @brief Comparison applied by a scan. The first group compares each read
     *        value against a caller-supplied operand; the second group compares
     *        it against the value recorded for that address on the previous
     *        scan, which is only meaningful on a next_scan over an existing
     *        result set.
     */
    enum class scan_compare {
        equal,              ///< value == operand
        not_equal,          ///< value != operand
        greater,            ///< value >  operand
        less,               ///< value <  operand
        greater_or_equal,   ///< value >= operand
        less_or_equal,      ///< value <= operand
        between,            ///< operand <= value <= operand_high

        changed,            ///< value != previous
        unchanged,          ///< value == previous
        increased,          ///< value >  previous
        decreased,          ///< value <  previous
        increased_by,       ///< value == previous + operand
        decreased_by        ///< value == previous - operand
    };

    /// @brief True if @p compare is evaluated against the previous recorded
    ///        value rather than a caller-supplied operand.
    [[nodiscard]] constexpr bool scan_compare_uses_previous(scan_compare compare) noexcept {
        switch (compare) {
            case scan_compare::changed:
            case scan_compare::unchanged:
            case scan_compare::increased:
            case scan_compare::decreased:
            case scan_compare::increased_by:
            case scan_compare::decreased_by:
                return true;
            default:
                return false;
        }
    }
}
