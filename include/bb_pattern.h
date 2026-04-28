/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 *
 * This file is part of bytebinder, a powerful tool for reading, writing, hooking, and manipulating memory addresses.
 *
 * Repository: https://github.com/rymote/bytebinder
 *
 * For issues, suggestions, or contributions, please visit the repository or contact the authors.
 *
 * This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties
 * of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders
 * be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out
 * of, or in connection with the software or the use or other dealings in the software.
 */

#pragma once

#include "bb_pch.h"
#include "bb_memory_exceptions.h"

namespace bytebinder {
    class memory_accessor;

    /**
     * @brief IDA-style binary pattern with wildcards, plus chunked scanners
     *        that stream through any memory_accessor in 64 KiB windows with
     *        overlap so matches that straddle window boundaries are still found.
     *
     * Example:
     * @code
     * bb::pattern parsed = bb::parse_ida_pattern("48 89 5C 24 ? 48 89 74 24 ?");
     * auto first = parsed.scan(accessor, base, size);
     * std::vector<uintptr_t> all;
     * parsed.scan_all(accessor, base, size, 0,
     *                  [&](uintptr_t hit){ all.push_back(hit); return true; });
     * @endcode
     */
    class BYTEBINDER_API pattern {
    public:
        std::string signature; ///< The binary pattern as a string of length size().
        std::string mask;      ///< Same length as signature; 'x' = match byte, '?' = wildcard.

        /// @brief Constructs a pattern from raw signature bytes and a match mask.
        pattern(std::string signature_bytes, std::string match_mask);

        /// @brief Returns the pattern length in bytes.
        [[nodiscard]] size_t size() const noexcept { return signature.size(); }

        /// Scans the local process's mem::storage range. Back-compat entry point.
        [[nodiscard]] uintptr_t scan() const;

        /// Scans @p total_size bytes starting at @p base via @p accessor in 64 KiB
        /// chunks with overlap. Returns the first match address or
        /// numeric_limits<uintptr_t>::max() if not found.
        [[nodiscard]] uintptr_t scan(memory_accessor& accessor,
                                       uintptr_t base, size_t total_size) const;

        /// Streaming variant: invokes @p on_match for each match found in
        /// `[base, base+total_size)`. Returns the number of matches reported.
        /// @p on_match returning false stops the scan early.
        /// @p max_results = 0 means unlimited.
        size_t scan_all(memory_accessor& accessor,
                        uintptr_t base, size_t total_size,
                        size_t max_results,
                        const std::function<bool(uintptr_t)>& on_match) const;

        /// @brief Snapshot of in-flight scan progress, used by the cancel/progress
        ///        scan_all overload.
        struct BYTEBINDER_API scan_progress {
            uintptr_t bytes_scanned = 0;
            uintptr_t bytes_total   = 0;
            size_t    matches_so_far = 0;
        };

        /**
         * @brief Variant of scan_all with an external cancel flag and an
         *        optional progress callback. @p cancel may be nullptr.
         *        @p on_progress may be nullptr; if set, it is called at most
         *        once per 64 KiB window.
         */
        size_t scan_all(memory_accessor& accessor,
                        uintptr_t base, size_t total_size,
                        size_t max_results,
                        const std::function<bool(uintptr_t)>& on_match,
                        const std::atomic<bool>* cancel,
                        const std::function<void(const scan_progress&)>& on_progress) const;

    private:
        [[nodiscard]] bool match_local(uintptr_t haystack_address) const noexcept;
        [[nodiscard]] bool match_buffer(const uint8_t* buffer) const noexcept;
    };

    /// @brief Parses an IDA-style hex pattern with `?` wildcards into a
    ///        `pattern` object. Spaces and tabs are ignored.
    BYTEBINDER_API pattern parse_ida_pattern(std::string_view ida_pattern);
}