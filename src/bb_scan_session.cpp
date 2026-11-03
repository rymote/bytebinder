/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#include "bb_scan_session.h"
#include "bb_memory_exceptions.h"

#include <cstring>
#include <type_traits>

namespace bytebinder {
    namespace {
        template<typename ValueType>
        bool compare_typed(const uint8_t* current_bytes,
                           const uint8_t* previous_bytes,
                           bool have_previous,
                           const scan_constraint& constraint) {
            ValueType value;
            std::memcpy(&value, current_bytes, sizeof(ValueType));

            const auto operand = [&]() -> ValueType {
                if constexpr (std::is_floating_point_v<ValueType>) {
                    return static_cast<ValueType>(constraint.float_operand);
                } else {
                    return static_cast<ValueType>(constraint.integer_operand);
                }
            };
            const auto operand_high = [&]() -> ValueType {
                if constexpr (std::is_floating_point_v<ValueType>) {
                    return static_cast<ValueType>(constraint.float_operand_high);
                } else {
                    return static_cast<ValueType>(constraint.integer_operand_high);
                }
            };

            switch (constraint.compare) {
                case scan_compare::equal:            return value == operand();
                case scan_compare::not_equal:        return value != operand();
                case scan_compare::greater:          return value >  operand();
                case scan_compare::less:             return value <  operand();
                case scan_compare::greater_or_equal: return value >= operand();
                case scan_compare::less_or_equal:    return value <= operand();
                case scan_compare::between:          return value >= operand() && value <= operand_high();
                default:                             break;
            }

            if (!have_previous) return false;
            ValueType previous;
            std::memcpy(&previous, previous_bytes, sizeof(ValueType));
            switch (constraint.compare) {
                case scan_compare::changed:      return value != previous;
                case scan_compare::unchanged:    return value == previous;
                case scan_compare::increased:    return value >  previous;
                case scan_compare::decreased:    return value <  previous;
                case scan_compare::increased_by: return value == static_cast<ValueType>(previous + operand());
                case scan_compare::decreased_by: return value == static_cast<ValueType>(previous - operand());
                default:                         return false;
            }
        }

        bool evaluate_constraint(scan_value_type type,
                                 const uint8_t* current_bytes,
                                 const uint8_t* previous_bytes,
                                 bool have_previous,
                                 const scan_constraint& constraint) {
            switch (type) {
                case scan_value_type::int8:    return compare_typed<int8_t>(current_bytes, previous_bytes, have_previous, constraint);
                case scan_value_type::uint8:   return compare_typed<uint8_t>(current_bytes, previous_bytes, have_previous, constraint);
                case scan_value_type::int16:   return compare_typed<int16_t>(current_bytes, previous_bytes, have_previous, constraint);
                case scan_value_type::uint16:  return compare_typed<uint16_t>(current_bytes, previous_bytes, have_previous, constraint);
                case scan_value_type::int32:   return compare_typed<int32_t>(current_bytes, previous_bytes, have_previous, constraint);
                case scan_value_type::uint32:  return compare_typed<uint32_t>(current_bytes, previous_bytes, have_previous, constraint);
                case scan_value_type::int64:   return compare_typed<int64_t>(current_bytes, previous_bytes, have_previous, constraint);
                case scan_value_type::uint64:  return compare_typed<uint64_t>(current_bytes, previous_bytes, have_previous, constraint);
                case scan_value_type::float32: return compare_typed<float>(current_bytes, previous_bytes, have_previous, constraint);
                case scan_value_type::float64: return compare_typed<double>(current_bytes, previous_bytes, have_previous, constraint);
            }
            return false;
        }

        // Caches a sliding 64 KiB window so a sorted sweep of nearby addresses
        // reads the target once per window instead of once per address.
        class window_reader {
        public:
            explicit window_reader(memory_accessor& accessor) : accessor(accessor) {}

            const uint8_t* value_at(uintptr_t address, size_t width) {
                if (address >= window_start
                    && address + width <= window_start + window_valid) {
                    return buffer.data() + (address - window_start);
                }
                if (buffer.size() < window_size) buffer.resize(window_size);
                window_start = address;
                window_valid = accessor.read(address, buffer.data(), window_size);
                if (address + width <= window_start + window_valid) {
                    return buffer.data();
                }
                return nullptr;
            }

        private:
            static constexpr size_t window_size = 64 * 1024;
            memory_accessor& accessor;
            std::vector<uint8_t> buffer;
            uintptr_t window_start = 0;
            size_t window_valid = 0;
        };
    }

    scan_session::scan_session(process target, scan_value_type type)
        : target(std::move(target)), type(type) {}

    void scan_session::set_value_type(scan_value_type new_type) {
        if (scanned) {
            throw memory_operation_exception(
                "Cannot change a scan session's value type after a scan; call reset() first.",
                memory_error_code::INVALID_OPERATION);
        }
        type = new_type;
    }

    void scan_session::set_module(std::optional<std::string_view> module_name) {
        if (module_name.has_value()) {
            module_restriction = std::string(*module_name);
        } else {
            module_restriction.reset();
        }
    }

    size_t scan_session::first_scan(const scan_constraint& constraint) {
        if (scan_compare_uses_previous(constraint.compare)) {
            throw memory_operation_exception(
                "first_scan requires an operand comparison; previous-relative "
                "comparisons are only valid on next_scan.",
                memory_error_code::INVALID_OPERATION);
        }
        return run_first_scan(&constraint);
    }

    size_t scan_session::first_scan_unknown() {
        return run_first_scan(nullptr);
    }

    size_t scan_session::run_first_scan(const scan_constraint* constraint) {
        const size_t width = scan_value_type_width(type);
        size_t stride = alignment == 0 ? width : alignment;
        if (stride == 0) stride = 1;

        matches.clear();
        previous_matches.clear();
        have_undo = false;

        std::optional<module_info> restricted_module;
        if (module_restriction.has_value()) {
            restricted_module = target.find_module(*module_restriction);
            if (!restricted_module.has_value()) {
                throw memory_operation_exception(
                    "Scan module not found: " + *module_restriction,
                    memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
            }
        }

        const auto regions = target.regions(required_region_protection,
                                            forbidden_region_protection);

        size_t bytes_total = 0;
        for (const auto& region : regions) bytes_total += region.size;
        size_t bytes_scanned = 0;
        size_t bytes_since_progress = 0;

        memory_accessor& accessor = target.accessor();
        constexpr size_t window_step = 64 * 1024;
        const size_t window_capacity = window_step + width;
        std::vector<uint8_t> window_buffer(window_capacity);

        for (const auto& region : regions) {
            uintptr_t region_begin = region.base;
            uintptr_t region_end = region.base + region.size;
            if (restricted_module.has_value()) {
                const uintptr_t module_begin = restricted_module->base;
                const uintptr_t module_end = restricted_module->base + restricted_module->size;
                region_begin = std::max(region_begin, module_begin);
                region_end = std::min(region_end, module_end);
                if (region_begin >= region_end) continue;
            }

            uintptr_t window_start = region_begin;
            while (window_start + width <= region_end) {
                if (cancel_flag != nullptr
                    && cancel_flag->load(std::memory_order_relaxed)) {
                    scanned = true;
                    return matches.size();
                }

                const size_t want_bytes = std::min<size_t>(window_capacity,
                                                           region_end - window_start);
                const size_t got_bytes = accessor.read(window_start,
                                                       window_buffer.data(),
                                                       want_bytes);
                if (got_bytes >= width) {
                    const size_t inclusive_last = got_bytes - width;
                    const bool is_final_window = want_bytes < window_capacity;
                    const size_t exclusive_upper = is_final_window
                        ? inclusive_last + 1
                        : std::min<size_t>(inclusive_last + 1, window_step);

                    const size_t alignment_remainder = window_start % stride;
                    size_t offset = alignment_remainder == 0
                        ? 0
                        : stride - alignment_remainder;

                    for (; offset < exclusive_upper; offset += stride) {
                        const uint8_t* current = window_buffer.data() + offset;
                        if (constraint == nullptr
                            || evaluate_constraint(type, current, nullptr, false, *constraint)) {
                            scan_match match;
                            match.address = window_start + offset;
                            std::memcpy(match.previous_value.data(), current, width);
                            matches.push_back(match);
                        }
                    }
                }

                window_start += window_step;
                bytes_scanned += window_step;
                bytes_since_progress += window_step;
                if (progress_callback && bytes_since_progress >= (4 * 1024 * 1024)) {
                    progress_callback({bytes_scanned, bytes_total, matches.size()});
                    bytes_since_progress = 0;
                }
            }
        }

        if (progress_callback) {
            progress_callback({bytes_total, bytes_total, matches.size()});
        }
        scanned = true;
        return matches.size();
    }

    size_t scan_session::next_scan(const scan_constraint& constraint) {
        if (!scanned) {
            throw memory_operation_exception(
                "next_scan requires a prior first_scan or first_scan_unknown.",
                memory_error_code::INVALID_OPERATION);
        }

        const size_t width = scan_value_type_width(type);
        previous_matches = matches;
        have_undo = true;

        std::vector<scan_match> survivors;
        survivors.reserve(matches.size());

        window_reader reader(target.accessor());
        const size_t total = matches.size();
        size_t processed = 0;

        for (const auto& match : matches) {
            if (cancel_flag != nullptr
                && cancel_flag->load(std::memory_order_relaxed)) {
                break;
            }

            const uint8_t* current = reader.value_at(match.address, width);
            if (current != nullptr
                && evaluate_constraint(type, current, match.previous_value.data(),
                                       true, constraint)) {
                scan_match updated;
                updated.address = match.address;
                std::memcpy(updated.previous_value.data(), current, width);
                survivors.push_back(updated);
            }

            ++processed;
            if (progress_callback && (processed % (256 * 1024)) == 0) {
                progress_callback({processed, total, survivors.size()});
            }
        }

        matches = std::move(survivors);
        if (progress_callback) {
            progress_callback({total, total, matches.size()});
        }
        return matches.size();
    }

    void scan_session::undo() {
        if (!have_undo) return;
        matches = std::move(previous_matches);
        previous_matches.clear();
        have_undo = false;
    }

    void scan_session::reset() {
        matches.clear();
        previous_matches.clear();
        have_undo = false;
        scanned = false;
    }
}
