/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"
#include "bb_scan_compare.h"

#include <cstdint>
#include <type_traits>

namespace bytebinder {
    /**
     * @brief A comparison plus its operands, independent of the scanned value
     *        type. Integer and floating-point operands are stored in separate
     *        fields; the scan session reads whichever matches its value type,
     *        so one constraint drives a scan of any type.
     *
     * Build constraints with the static helpers rather than by hand:
     * @code
     * auto c = bb::scan_constraint::equals(100);
     * auto r = bb::scan_constraint::between(0.0f, 1.0f);
     * auto d = bb::scan_constraint::decreased();
     * @endcode
     */
    struct BYTEBINDER_API scan_constraint {
        scan_compare compare = scan_compare::equal;
        int64_t integer_operand = 0;
        int64_t integer_operand_high = 0;
        double float_operand = 0.0;
        double float_operand_high = 0.0;

        template<typename ValueType>
        static scan_constraint with_operand(scan_compare compare, ValueType operand) {
            scan_constraint result;
            result.compare = compare;
            if constexpr (std::is_floating_point_v<ValueType>) {
                result.float_operand = static_cast<double>(operand);
                result.integer_operand = static_cast<int64_t>(operand);
            } else {
                result.integer_operand = static_cast<int64_t>(operand);
                result.float_operand = static_cast<double>(operand);
            }
            return result;
        }

        template<typename ValueType>
        static scan_constraint equals(ValueType operand) {
            return with_operand(scan_compare::equal, operand);
        }

        template<typename ValueType>
        static scan_constraint not_equals(ValueType operand) {
            return with_operand(scan_compare::not_equal, operand);
        }

        template<typename ValueType>
        static scan_constraint greater_than(ValueType operand) {
            return with_operand(scan_compare::greater, operand);
        }

        template<typename ValueType>
        static scan_constraint less_than(ValueType operand) {
            return with_operand(scan_compare::less, operand);
        }

        template<typename ValueType>
        static scan_constraint between(ValueType inclusive_low, ValueType inclusive_high) {
            scan_constraint result;
            result.compare = scan_compare::between;
            if constexpr (std::is_floating_point_v<ValueType>) {
                result.float_operand = static_cast<double>(inclusive_low);
                result.float_operand_high = static_cast<double>(inclusive_high);
            } else {
                result.integer_operand = static_cast<int64_t>(inclusive_low);
                result.integer_operand_high = static_cast<int64_t>(inclusive_high);
            }
            return result;
        }

        static scan_constraint changed()   { scan_constraint c; c.compare = scan_compare::changed;   return c; }
        static scan_constraint unchanged() { scan_constraint c; c.compare = scan_compare::unchanged; return c; }
        static scan_constraint increased() { scan_constraint c; c.compare = scan_compare::increased; return c; }
        static scan_constraint decreased() { scan_constraint c; c.compare = scan_compare::decreased; return c; }

        template<typename ValueType>
        static scan_constraint increased_by(ValueType delta) {
            return with_operand(scan_compare::increased_by, delta);
        }

        template<typename ValueType>
        static scan_constraint decreased_by(ValueType delta) {
            return with_operand(scan_compare::decreased_by, delta);
        }
    };
}
