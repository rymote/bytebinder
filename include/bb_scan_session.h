/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

/**
 * @file
 * @brief Stateful value-scan loop: first scan, then successive next scans that
 *        narrow the surviving addresses. This is the scan model a value editor
 *        drives, where the user picks a runtime type and repeatedly filters by
 *        exact value, range, or change relative to the previous scan. The
 *        templated scans on `bb::process` remain the right tool for one-shot
 *        typed scans; a scan session adds the result set, the next-scan filters,
 *        and single-level undo on top of them.
 *
 * Example:
 * @code
 * bb::scan_session session(bb::process::current(), bb::scan_value_type::int32);
 * session.first_scan(bb::scan_constraint::equals(100));
 * // player takes damage ...
 * session.next_scan(bb::scan_constraint::decreased());
 * session.next_scan(bb::scan_constraint::equals(80));
 * for (const auto& match : session.results()) {
 *     // match.address now holds the health value
 * }
 * @endcode
 */

#include "bb_api.h"
#include "bb_process.h"
#include "bb_scan_constraint.h"
#include "bb_scan_match.h"
#include "bb_scan_value_type.h"

#include <atomic>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bytebinder {
    /**
     * @brief Progress report emitted during a scan, for driving a progress bar.
     */
    struct BYTEBINDER_API scan_session_progress {
        size_t bytes_scanned = 0;
        size_t bytes_total = 0;
        size_t matches_so_far = 0;
    };

    /**
     * @brief A running value-scan over one process. Not thread safe: a session
     *        owns a mutable result set, so serialize calls on a single session.
     *        Distinct sessions over the same process are independent and may run
     *        concurrently, since the underlying accessor reads are thread safe.
     */
    class BYTEBINDER_API scan_session {
    public:
        /// @brief Binds a session to @p target scanning values of @p type.
        scan_session(process target, scan_value_type type);

        /// @brief The value type this session scans.
        [[nodiscard]] scan_value_type value_type() const noexcept { return type; }

        /**
         * @brief Changes the scanned value type. Only valid before the first
         *        scan or after reset(); throws memory_operation_exception with
         *        INVALID_OPERATION once a scan has produced results, because the
         *        recorded value widths would no longer match.
         */
        void set_value_type(scan_value_type new_type);

        /**
         * @brief Sets the scan stride in bytes. 0 restores natural alignment
         *        (the value width). Applies to the next first_scan only.
         */
        void set_alignment(size_t new_alignment) noexcept { alignment = new_alignment; }

        /**
         * @brief Restricts first_scan to regions where every required bit is set
         *        and no forbidden bit is set. The default keeps writable,
         *        non-executable memory, which is where mutable game state lives.
         */
        void set_region_filter(int required_protection, int forbidden_protection) noexcept {
            required_region_protection = required_protection;
            forbidden_region_protection = forbidden_protection;
        }

        /**
         * @brief Restricts first_scan to a single module's address range, or
         *        clears the restriction when nullopt.
         */
        void set_module(std::optional<std::string_view> module_name);

        /// @brief Optional cooperative cancellation flag, polled between windows.
        void set_cancel_flag(const std::atomic<bool>* cancel) noexcept { cancel_flag = cancel; }

        /// @brief Optional progress callback, invoked periodically during scans.
        void set_progress_callback(std::function<void(const scan_session_progress&)> callback) {
            progress_callback = std::move(callback);
        }

        /**
         * @brief First scan with a known constraint. Walks the filtered regions
         *        and keeps every aligned address whose value satisfies
         *        @p constraint. The constraint must not be a previous-relative
         *        comparison (changed, increased, ...), since there is no prior
         *        value yet. Returns the number of matches.
         */
        size_t first_scan(const scan_constraint& constraint);

        /**
         * @brief Unknown-initial-value first scan. Records every aligned address
         *        in the filtered regions together with its current value, with
         *        no filtering, so later next_scan calls can compare against it.
         *        This can record a very large result set. Returns the count.
         */
        size_t first_scan_unknown();

        /**
         * @brief Narrows the current result set, re-reading each surviving
         *        address and keeping those that satisfy @p constraint. Both
         *        operand comparisons and previous-relative comparisons are
         *        valid here. Records the single previous result set for undo().
         *        Throws INVALID_OPERATION if no scan has run yet. Returns the
         *        surviving count.
         */
        size_t next_scan(const scan_constraint& constraint);

        /// @brief Restores the result set from before the last next_scan. A
        ///        single level of history is kept; a second undo is a no-op.
        void undo();

        /// @brief Clears all results and history, returning to the pre-scan state.
        void reset();

        /// @brief True once a first scan has run and not been reset.
        [[nodiscard]] bool has_scanned() const noexcept { return scanned; }

        /// @brief The surviving matches.
        [[nodiscard]] const std::vector<scan_match>& results() const noexcept { return matches; }

        /// @brief The number of surviving matches.
        [[nodiscard]] size_t result_count() const noexcept { return matches.size(); }

        /// @brief The bound process.
        [[nodiscard]] const process& target_process() const noexcept { return target; }

    private:
        process target;
        scan_value_type type;
        size_t alignment = 0;
        int required_region_protection = protection::read | protection::write;
        int forbidden_region_protection = protection::execute;
        std::optional<std::string> module_restriction;
        const std::atomic<bool>* cancel_flag = nullptr;
        std::function<void(const scan_session_progress&)> progress_callback;

        bool scanned = false;
        std::vector<scan_match> matches;
        std::vector<scan_match> previous_matches;
        bool have_undo = false;

        size_t run_first_scan(const scan_constraint* constraint);
    };
}
