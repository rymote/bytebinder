/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

/**
 * @file
 * @brief Templated typed-value scans on `bb::process`. Definitions live in
 *        this header (rather than a .cpp) so the templates instantiate per
 *        translation unit. Reuses `bb::process::accessor()` and
 *        `bb::region_info`.
 *
 * Example:
 * @code
 * auto target = bb::process::current();
 * auto fives = target.scan_value_in_range<float>(4.99f, 5.01f);
 * for (uintptr_t address : fives.matches) {
 *     // ...
 * }
 * @endcode
 */

#include "bb_process.h"
#include "bb_memory_accessor.h"
#include "bb_memory_exceptions.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <type_traits>

namespace bytebinder {

    namespace detail {
        /**
         * @brief Core templated scanner. Iterates @p target_accessor at
         *        @p alignment-byte stride between @p base and @p base+size,
         *        reads sizeof(ValueType) bytes at each address, calls
         *        @p predicate with the read value. Pushes matching addresses
         *        into @p out_matches up to @p max_results.
         *        Returns bytes scanned.
         */
        template<typename ValueType, typename Predicate>
        size_t template_scan_value(memory_accessor& target_accessor,
                                     uintptr_t base, size_t size,
                                     size_t alignment,
                                     size_t max_results,
                                     std::vector<uintptr_t>& out_matches,
                                     Predicate predicate) {
            static_assert(std::is_trivially_copyable_v<ValueType>,
                           "scan_value requires a trivially-copyable type");
            if (alignment == 0) alignment = 1;
            if (size < sizeof(ValueType)) return 0;

            constexpr size_t window_step = 64 * 1024;
            const size_t window_capacity = window_step + sizeof(ValueType);
            std::vector<uint8_t> window_buffer(window_capacity);

            uintptr_t window_start = base;
            const uintptr_t scan_end = base + size;
            const size_t initial_match_count = out_matches.size();

            while (window_start + sizeof(ValueType) <= scan_end) {
                const size_t want_bytes = std::min<size_t>(window_capacity,
                                                            scan_end - window_start);
                const size_t got_bytes = target_accessor.read(window_start,
                                                                window_buffer.data(),
                                                                want_bytes);
                if (got_bytes >= sizeof(ValueType)) {
                    const size_t inclusive_last = got_bytes - sizeof(ValueType);
                    const bool is_final_window = want_bytes < window_capacity;
                    const size_t exclusive_upper = is_final_window
                        ? inclusive_last + 1
                        : std::min<size_t>(inclusive_last + 1, window_step);

                    // Align starting offset to caller-requested alignment.
                    const size_t window_offset_alignment_remainder =
                        window_start % alignment;
                    size_t offset = (window_offset_alignment_remainder == 0)
                        ? 0
                        : alignment - window_offset_alignment_remainder;

                    for (; offset < exclusive_upper; offset += alignment) {
                        ValueType candidate;
                        std::memcpy(&candidate, window_buffer.data() + offset, sizeof(ValueType));
                        if (predicate(candidate)) {
                            out_matches.push_back(window_start + offset);
                            if (max_results != 0
                                && (out_matches.size() - initial_match_count) >= max_results) {
                                return window_start - base;
                            }
                        }
                    }
                }
                window_start += window_step;
            }
            return scan_end - base;
        }
    }

    template<typename ValueType>
    process::scan_result process::scan_value(
        ValueType expected,
        std::optional<std::string_view> module_name,
        size_t alignment,
        size_t max_results) const {
        scan_result aggregate;
        if (!accessor_impl) return aggregate;

        uintptr_t scan_base = 0;
        size_t scan_size = std::numeric_limits<size_t>::max();
        if (module_name.has_value()) {
            const auto resolved_module = accessor_impl->find_module(*module_name);
            if (!resolved_module.has_value()) {
                throw memory_operation_exception(
                    std::string("Module not found: ") + std::string(*module_name),
                    memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
            }
            scan_base = resolved_module->base;
            scan_size = resolved_module->size;
        }

        std::vector<region_info> candidate_regions;
        const uintptr_t requested_end =
            (scan_size > std::numeric_limits<uintptr_t>::max() - scan_base)
            ? std::numeric_limits<uintptr_t>::max()
            : scan_base + scan_size;
        for (const auto& candidate : accessor_impl->regions()) {
            if ((candidate.protection & protection::read) == 0) continue;
            const uintptr_t candidate_end = candidate.base + candidate.size;
            const uintptr_t overlap_start = std::max(candidate.base, scan_base);
            const uintptr_t overlap_end   = std::min(candidate_end, requested_end);
            if (overlap_start >= overlap_end) continue;
            region_info clipped = candidate;
            clipped.base = overlap_start;
            clipped.size = overlap_end - overlap_start;
            candidate_regions.push_back(std::move(clipped));
        }

        for (const auto& current_region : candidate_regions) {
            ++aggregate.regions_scanned;
            aggregate.bytes_scanned += current_region.size;
            const size_t remaining =
                max_results == 0 ? 0
                                 : (max_results - aggregate.matches.size());
            if (max_results != 0 && remaining == 0) break;
            detail::template_scan_value<ValueType>(
                *accessor_impl,
                current_region.base, current_region.size,
                alignment, remaining,
                aggregate.matches,
                [expected](const ValueType& observed) {
                    return std::memcmp(&observed, &expected, sizeof(ValueType)) == 0;
                });
        }
        return aggregate;
    }

    template<typename ValueType>
    process::scan_result process::scan_value_in_range(
        ValueType inclusive_low,
        ValueType inclusive_high,
        std::optional<std::string_view> module_name,
        size_t alignment,
        size_t max_results) const {
        scan_result aggregate;
        if (!accessor_impl) return aggregate;

        uintptr_t scan_base = 0;
        size_t scan_size = std::numeric_limits<size_t>::max();
        if (module_name.has_value()) {
            const auto resolved_module = accessor_impl->find_module(*module_name);
            if (!resolved_module.has_value()) {
                throw memory_operation_exception(
                    std::string("Module not found: ") + std::string(*module_name),
                    memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
            }
            scan_base = resolved_module->base;
            scan_size = resolved_module->size;
        }

        std::vector<region_info> candidate_regions;
        const uintptr_t requested_end =
            (scan_size > std::numeric_limits<uintptr_t>::max() - scan_base)
            ? std::numeric_limits<uintptr_t>::max()
            : scan_base + scan_size;
        for (const auto& candidate : accessor_impl->regions()) {
            if ((candidate.protection & protection::read) == 0) continue;
            const uintptr_t candidate_end = candidate.base + candidate.size;
            const uintptr_t overlap_start = std::max(candidate.base, scan_base);
            const uintptr_t overlap_end   = std::min(candidate_end, requested_end);
            if (overlap_start >= overlap_end) continue;
            region_info clipped = candidate;
            clipped.base = overlap_start;
            clipped.size = overlap_end - overlap_start;
            candidate_regions.push_back(std::move(clipped));
        }

        for (const auto& current_region : candidate_regions) {
            ++aggregate.regions_scanned;
            aggregate.bytes_scanned += current_region.size;
            const size_t remaining =
                max_results == 0 ? 0
                                 : (max_results - aggregate.matches.size());
            if (max_results != 0 && remaining == 0) break;
            detail::template_scan_value<ValueType>(
                *accessor_impl,
                current_region.base, current_region.size,
                alignment, remaining,
                aggregate.matches,
                [inclusive_low, inclusive_high](const ValueType& observed) {
                    return inclusive_low <= observed && observed <= inclusive_high;
                });
        }
        return aggregate;
    }

    template<typename ValueType>
    process::scan_result process::scan_value_with_mask(
        ValueType expected,
        ValueType mask,
        std::optional<std::string_view> module_name,
        size_t alignment,
        size_t max_results) const {
        scan_result aggregate;
        if (!accessor_impl) return aggregate;

        uintptr_t scan_base = 0;
        size_t scan_size = std::numeric_limits<size_t>::max();
        if (module_name.has_value()) {
            const auto resolved_module = accessor_impl->find_module(*module_name);
            if (!resolved_module.has_value()) {
                throw memory_operation_exception(
                    std::string("Module not found: ") + std::string(*module_name),
                    memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
            }
            scan_base = resolved_module->base;
            scan_size = resolved_module->size;
        }

        std::vector<region_info> candidate_regions;
        const uintptr_t requested_end =
            (scan_size > std::numeric_limits<uintptr_t>::max() - scan_base)
            ? std::numeric_limits<uintptr_t>::max()
            : scan_base + scan_size;
        for (const auto& candidate : accessor_impl->regions()) {
            if ((candidate.protection & protection::read) == 0) continue;
            const uintptr_t candidate_end = candidate.base + candidate.size;
            const uintptr_t overlap_start = std::max(candidate.base, scan_base);
            const uintptr_t overlap_end   = std::min(candidate_end, requested_end);
            if (overlap_start >= overlap_end) continue;
            region_info clipped = candidate;
            clipped.base = overlap_start;
            clipped.size = overlap_end - overlap_start;
            candidate_regions.push_back(std::move(clipped));
        }

        for (const auto& current_region : candidate_regions) {
            ++aggregate.regions_scanned;
            aggregate.bytes_scanned += current_region.size;
            const size_t remaining =
                max_results == 0 ? 0
                                 : (max_results - aggregate.matches.size());
            if (max_results != 0 && remaining == 0) break;
            detail::template_scan_value<ValueType>(
                *accessor_impl,
                current_region.base, current_region.size,
                alignment, remaining,
                aggregate.matches,
                [expected, mask](const ValueType& observed) {
                    return static_cast<ValueType>(observed & mask)
                        == static_cast<ValueType>(expected & mask);
                });
        }
        return aggregate;
    }
}
