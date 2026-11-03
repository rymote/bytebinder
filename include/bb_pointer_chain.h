/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"
#include "bb_memory_exceptions.h"
#include "bb_chain_resolution.h"
#include "bb_chain_step.h"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace bytebinder {

    class process;
    class watch_handle;

    /**
     * @brief Stateless pointer-chain walker bound to @p target_process.
     *
     * Implemented in bb_pointer_chain.cpp. See process::resolve_chain for
     * step semantics and the chain_resolution diagnostic fields.
     */
    BYTEBINDER_API chain_resolution resolve_chain_for_process(
        const process& target_process,
        uintptr_t base,
        std::span<const chain_step> steps);

    /**
     * @brief Locate pointer-aligned slots whose stored 8 bytes equal @p target.
     *
     * Discovery helper. Scans readable regions of @p target_process matching
     * the protection mask. Implemented in bb_pointer_chain.cpp.
     */
    BYTEBINDER_API std::vector<uintptr_t> find_pointers_to_in_process(
        const process& target_process,
        uintptr_t target,
        std::optional<std::string_view> module_name,
        int required_protection,
        int forbidden_protection,
        size_t max_results);

    /**
     * @brief Worker-thread chain re-walker for @p target_process.
     *
     * Re-walks the chain every @p interval and invokes @p on_resolve when the
     * resolved final address changes. Implemented in bb_pointer_chain.cpp.
     */
    BYTEBINDER_API watch_handle watch_chain_for_process(
        const process& target_process,
        uintptr_t base,
        std::span<const chain_step> steps,
        std::function<void(uintptr_t)> on_resolve,
        std::chrono::milliseconds interval);
}
