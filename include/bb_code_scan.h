/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

/**
 * @file
 * @brief Disassembly-driven scans: cross-references, function-entry-point
 *        heuristics, and structural instruction-pattern matching. Backed
 *        by Zydis. Operates only on regions with both `protection::read`
 *        and `protection::execute` set.
 *
 * Example:
 * @code
 * auto target = bb::process::current();
 * auto xrefs = target.find_xrefs(reinterpret_cast<uintptr_t>(&hot_function));
 * for (const auto& reference : xrefs) {
 *     std::printf("0x%lx (kind=%d)\n",
 *                 reference.instruction_address,
 *                 static_cast<int>(reference.kind));
 * }
 * @endcode
 */

#include "bb_api.h"
#include "bb_function_entry.h"
#include "bb_function_source.h"
#include "bb_instruction_pattern_element.h"
#include "bb_xref.h"
#include "bb_xref_kind.h"

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bytebinder {

    class process;

    /// @brief Free-function backend for process::find_xrefs.
    BYTEBINDER_API std::vector<xref> find_xrefs_in_process(
        const process& target_process,
        uintptr_t target_address,
        std::optional<std::string_view> module_name,
        size_t max_results);

    /// @brief Free-function backend for process::find_prologues.
    BYTEBINDER_API std::vector<uintptr_t> find_prologues_in_process(
        const process& target_process,
        std::string_view module_name,
        size_t max_results);

    /// @brief Free-function backend for process::find_functions.
    BYTEBINDER_API std::vector<function_entry> find_functions_in_process(
        const process& target_process,
        std::string_view module_name,
        size_t max_results);

    /// @brief Free-function backend for process::find_instruction_pattern.
    BYTEBINDER_API std::vector<uintptr_t> find_instruction_pattern_in_process(
        const process& target_process,
        std::span<const instruction_pattern_element> pattern,
        std::optional<std::string_view> module_name,
        size_t max_results);
}
