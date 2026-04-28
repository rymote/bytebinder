/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
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

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace bytebinder {

    class process;

    /// @brief Category of cross-reference reported by find_xrefs.
    enum class xref_kind {
        call,
        jmp_uncond,
        jmp_cond,
        lea_rip,
        mov_rip_load,
        mov_rip_store,
    };

    /// @brief One disassembled instruction whose computed target equals the
    ///        queried address, plus its kind and decoded length.
    struct BYTEBINDER_API xref {
        uintptr_t instruction_address = 0;
        xref_kind kind = xref_kind::call;
        size_t instruction_length = 0;
    };

    /// @brief One element of an instruction-template pattern: mnemonic
    ///        (case-insensitive; empty = wildcard) and optional operand-count
    ///        constraint.
    struct BYTEBINDER_API instruction_pattern_element {
        std::string mnemonic;
        std::optional<size_t> operand_count;
    };

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

    /// @brief Free-function backend for process::find_instruction_pattern.
    BYTEBINDER_API std::vector<uintptr_t> find_instruction_pattern_in_process(
        const process& target_process,
        std::span<const instruction_pattern_element> pattern,
        std::optional<std::string_view> module_name,
        size_t max_results);
}
