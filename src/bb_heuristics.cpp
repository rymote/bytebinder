/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "bb_heuristics.h"
#include "bb_process.h"
#include "bb_memory_accessor.h"
#include "bb_log_sink.h"

#include <algorithm>
#include <cstring>
#include <vector>

namespace bytebinder {
    namespace {
        bool address_is_in_executable_region(uintptr_t address,
                                                const std::vector<region_info>& executable_regions) {
            for (const auto& region : executable_regions) {
                if (address >= region.base && address < region.base + region.size) return true;
            }
            return false;
        }
    }

    std::vector<vtable_candidate> find_vtables_in_process(
        const process& target_process,
        std::optional<std::string_view> module_name,
        size_t min_entries,
        size_t max_results) {
        std::vector<vtable_candidate> matches;
        memory_accessor& bound_accessor = target_process.accessor();

        std::vector<region_info> executable_regions;
        for (const auto& region : bound_accessor.regions()) {
            if ((region.protection & protection::execute) != 0) {
                executable_regions.push_back(region);
            }
        }
        if (executable_regions.empty()) return matches;

        std::vector<region_info> data_regions;
        if (module_name.has_value()) {
            const auto resolved = bound_accessor.find_module(*module_name);
            if (!resolved.has_value()) return matches;
            const uintptr_t module_end = resolved->base + resolved->size;
            for (const auto& region : bound_accessor.regions()) {
                if ((region.protection & protection::read) == 0) continue;
                if ((region.protection & protection::execute) != 0) continue;
                const uintptr_t region_end = region.base + region.size;
                const uintptr_t overlap_start = std::max(region.base, resolved->base);
                const uintptr_t overlap_end   = std::min(region_end, module_end);
                if (overlap_start >= overlap_end) continue;
                region_info clipped = region;
                clipped.base = overlap_start;
                clipped.size = overlap_end - overlap_start;
                data_regions.push_back(std::move(clipped));
            }
        } else {
            for (const auto& region : bound_accessor.regions()) {
                if ((region.protection & protection::read) == 0) continue;
                if ((region.protection & protection::execute) != 0) continue;
                data_regions.push_back(region);
            }
        }

        constexpr size_t pointer_size = sizeof(void*);
        std::vector<uint8_t> region_buffer;

        for (const auto& region : data_regions) {
            region_buffer.resize(region.size);
            const size_t bytes_read = bound_accessor.read(region.base,
                                                            region_buffer.data(),
                                                            region.size);
            if (bytes_read < pointer_size * min_entries) continue;

            const size_t aligned_bytes = bytes_read - (bytes_read % pointer_size);
            size_t cursor = 0;
            while (cursor + pointer_size * min_entries <= aligned_bytes) {
                vtable_candidate candidate;
                candidate.address = region.base + cursor;
                size_t probe_cursor = cursor;
                while (probe_cursor + pointer_size <= aligned_bytes) {
                    uintptr_t value;
                    std::memcpy(&value, region_buffer.data() + probe_cursor, pointer_size);
                    if (!address_is_in_executable_region(value, executable_regions)) break;
                    candidate.entries.push_back(value);
                    probe_cursor += pointer_size;
                }
                if (candidate.entries.size() >= min_entries) {
                    matches.push_back(std::move(candidate));
                    if (max_results != 0 && matches.size() >= max_results) {
                        return matches;
                    }
                    cursor = probe_cursor;
                } else {
                    cursor += pointer_size;
                }
            }
        }
        return matches;
    }

    std::vector<string_table_run> find_string_tables_in_process(
        const process& target_process,
        std::optional<std::string_view> module_name,
        size_t min_string_length,
        size_t max_results) {
        std::vector<string_table_run> matches;
        memory_accessor& bound_accessor = target_process.accessor();

        std::vector<region_info> data_regions;
        if (module_name.has_value()) {
            const auto resolved = bound_accessor.find_module(*module_name);
            if (!resolved.has_value()) return matches;
            const uintptr_t module_end = resolved->base + resolved->size;
            for (const auto& region : bound_accessor.regions()) {
                if ((region.protection & protection::read) == 0) continue;
                const uintptr_t region_end = region.base + region.size;
                const uintptr_t overlap_start = std::max(region.base, resolved->base);
                const uintptr_t overlap_end   = std::min(region_end, module_end);
                if (overlap_start >= overlap_end) continue;
                region_info clipped = region;
                clipped.base = overlap_start;
                clipped.size = overlap_end - overlap_start;
                data_regions.push_back(std::move(clipped));
            }
        } else {
            for (const auto& region : bound_accessor.regions()) {
                if ((region.protection & protection::read) == 0) continue;
                data_regions.push_back(region);
            }
        }

        std::vector<uint8_t> region_buffer;

        for (const auto& region : data_regions) {
            region_buffer.resize(region.size);
            const size_t bytes_read = bound_accessor.read(region.base,
                                                            region_buffer.data(),
                                                            region.size);
            if (bytes_read == 0) continue;

            size_t cursor = 0;
            while (cursor < bytes_read) {
                size_t string_start = cursor;
                while (cursor < bytes_read) {
                    const unsigned char byte = region_buffer[cursor];
                    if (byte == 0 || byte < 0x20 || byte > 0x7E) break;
                    ++cursor;
                }
                if (cursor < bytes_read && region_buffer[cursor] == 0
                    && (cursor - string_start) >= min_string_length) {
                    string_table_run run;
                    run.base = region.base + string_start;
                    run.string_count = 1;
                    size_t run_cursor = cursor + 1;
                    while (run_cursor < bytes_read) {
                        const size_t next_string_start = run_cursor;
                        while (run_cursor < bytes_read) {
                            const unsigned char b = region_buffer[run_cursor];
                            if (b == 0 || b < 0x20 || b > 0x7E) break;
                            ++run_cursor;
                        }
                        if (run_cursor < bytes_read
                            && region_buffer[run_cursor] == 0
                            && (run_cursor - next_string_start) >= min_string_length) {
                            ++run.string_count;
                            ++run_cursor;
                            continue;
                        }
                        break;
                    }
                    if (run.string_count >= 2) {
                        run.size_bytes = run_cursor - string_start;
                        matches.push_back(std::move(run));
                        if (max_results != 0 && matches.size() >= max_results) {
                            return matches;
                        }
                        cursor = run_cursor;
                        continue;
                    }
                }
                ++cursor;
            }
        }
        return matches;
    }
}
