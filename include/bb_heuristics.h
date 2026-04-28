/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

/**
 * @file
 * @brief Heuristic structural scans. find_vtables locates aligned arrays
 *        of pointers where every entry resolves to an executable region.
 *        find_string_tables locates contiguous runs of NUL-terminated
 *        printable-ASCII strings. Both run over readable regions.
 *
 * Example:
 * @code
 * auto target = bb::process::current();
 * auto vtables = target.find_vtables(std::nullopt, 4, 100);
 * for (const auto& candidate : vtables) {
 *     std::printf("vtable @ 0x%lx with %zu entries\n",
 *                 candidate.address, candidate.entries.size());
 * }
 * @endcode
 */

#include "bb_api.h"

#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace bytebinder {

    class process;

    /// @brief A pointer-aligned run treated as a candidate vtable: the run's
    ///        start address plus the resolved entries.
    struct BYTEBINDER_API vtable_candidate {
        uintptr_t address = 0;
        std::vector<uintptr_t> entries;
    };

    /// @brief A contiguous block of adjacent NUL-terminated printable-ASCII
    ///        strings (e.g. a localization table).
    struct BYTEBINDER_API string_table_run {
        uintptr_t base = 0;
        size_t size_bytes = 0;
        size_t string_count = 0;
    };

    /// @brief Free-function backend for process::find_vtables.
    BYTEBINDER_API std::vector<vtable_candidate> find_vtables_in_process(
        const process& target_process,
        std::optional<std::string_view> module_name,
        size_t min_entries,
        size_t max_results);

    /// @brief Free-function backend for process::find_string_tables.
    BYTEBINDER_API std::vector<string_table_run> find_string_tables_in_process(
        const process& target_process,
        std::optional<std::string_view> module_name,
        size_t min_string_length,
        size_t max_results);
}
