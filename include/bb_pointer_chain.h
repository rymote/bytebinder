/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "bb_api.h"
#include "bb_memory_exceptions.h"

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
     * @brief One hop in a pointer chain.
     *
     * `offset` is added to the running address; `dereference == true` means
     * after adding the offset, read 8 bytes at the resulting address and
     * treat them as the next address. The final step in a typical chain
     * has `dereference == false` — its offset is the field-within-struct
     * location whose value the caller will read separately via read_chain<T>.
     */
    struct BYTEBINDER_API chain_step {
        ptrdiff_t offset = 0;
        bool dereference = true;
    };

    /**
     * @brief Outcome of resolve_chain.
     *
     * On success `address` holds the final VA. On failure all the diagnostic
     * fields describe where and why:
     * - failed_at_step: zero-based index into the steps span.
     * - failure: typed code (READ_FAILED on bad deref, etc).
     * - partial_walk_addr: the running address at the moment of failure,
     *   post-offset and pre-deref.
     */
    struct BYTEBINDER_API chain_resolution {
        std::optional<uintptr_t> address;
        size_t failed_at_step = 0;
        memory_error_code failure = memory_error_code::READ_FAILED;
        uintptr_t partial_walk_addr = 0;
    };

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
