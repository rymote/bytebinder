/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "memory_accessor.h"
#include "pattern.h"
#include "symbols.h"

#include <atomic>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

namespace bytebinder {
    class mem;

    /**
     * @brief High-level handle to either the current process (in-process mode)
     *        or a remote PID (out-of-process mode). Owns the memory_accessor
     *        used by every mem instance derived from it.
     *
     * Thread safety:
     *  - All const methods (regions, modules, find_module, scan, scan_all,
     *    resolve_symbol, resolve_symbols, symbolize, is_readable,
     *    is_writable, alive) are safe to call concurrently from multiple
     *    threads on the same process instance. They go through the bound
     *    accessor's read-side surface, which is thread-safe.
     *  - The non-const at(address) returns a fresh mem; concurrent calls are
     *    safe.
     *  - process is copyable and the copies share the same memory_accessor;
     *    concurrent use across copies is equivalent to concurrent use on one
     *    instance.
     */
    class BYTEBINDER_API process {
    public:
        static process current();
        static process attach(uint32_t target_process_id);

        process() = default;
        explicit process(std::shared_ptr<memory_accessor> accessor);

        [[nodiscard]] memory_accessor& accessor() const noexcept { return *accessor_impl; }
        [[nodiscard]] std::shared_ptr<memory_accessor> accessor_shared() const noexcept { return accessor_impl; }
        [[nodiscard]] bool is_local() const noexcept;
        [[nodiscard]] std::optional<uint32_t> id() const noexcept;

        /**
         * @brief Returns true if the bound process is still running. For local
         *        processes this is always true. For remote processes, checks
         *        existence via `kill(pid, 0)` (Linux) or
         *        `WaitForSingleObject(handle, 0)` (Windows). Distinguishes
         *        "address unmapped" from "process exited" in callers that
         *        otherwise see all reads return 0 bytes.
         */
        [[nodiscard]] bool alive() const noexcept;

        [[nodiscard]] mem at(uintptr_t address) const;
        [[nodiscard]] std::vector<region_info> regions() const;

        /**
         * @brief Filtered enumeration: returns only regions where every bit of
         *        @p required_protection is set AND no bit of @p forbidden_protection is set.
         *        Examples:
         *          regions(protection::execute)                  → code regions.
         *          regions(protection::read, protection::execute) → readable data (no .text).
         *          regions(protection::write)                    → writable regions.
         */
        [[nodiscard]] std::vector<region_info> regions(int required_protection,
                                                        int forbidden_protection = 0) const;

        /**
         * @brief Returns true iff every byte in [address, address+length) lives
         *        in a region whose protection includes @p protection::read.
         *        Length 0 is treated as "address is in any mapped region".
         */
        [[nodiscard]] bool is_readable(uintptr_t address, size_t length = 0) const;

        /// Same as is_readable but checks protection::write.
        [[nodiscard]] bool is_writable(uintptr_t address, size_t length = 0) const;

        [[nodiscard]] std::vector<module_info> modules() const;
        [[nodiscard]] std::optional<module_info> find_module(std::string_view name) const;

        struct BYTEBINDER_API module_section {
            std::string name;       // ".text", ".rdata", ".data", etc
            uintptr_t base = 0;     // VA in the target process
            size_t size = 0;
            int protection = 0;     // posix bits derived from section flags
        };

        /**
         * @brief Parses the module's section table. Linux: reads ELF section
         *        headers from disk via the module's path. Windows: walks the
         *        in-memory PE header (DOS -> NT -> section table) via the bound
         *        accessor. Cached per module path.
         */
        [[nodiscard]] std::vector<module_section> module_sections(std::string_view module_name) const;

        /**
         * @brief Scans the entire process for an IDA-style pattern. If
         *        @p module_name is provided, only that module's range is
         *        scanned; otherwise every readable region is searched.
         *
         * @return mem bound to this process at the match address, or an invalid
         *         mem (`valid() == false`) if no match was found.
         */
        [[nodiscard]] mem scan(std::string_view ida_pattern,
                                std::optional<std::string_view> module_name = std::nullopt) const;

        struct BYTEBINDER_API scan_result {
            std::vector<uintptr_t> matches;
            size_t regions_scanned = 0;
            size_t regions_skipped = 0; // unreadable / protection mismatch
            size_t bytes_scanned   = 0;
        };

        /**
         * @brief Multi-match scan. Returns up to @p max_results match addresses
         *        across all readable regions (or only @p module_name if given).
         *        @p max_results = 0 means unlimited.
         */
        [[nodiscard]] scan_result scan_all(std::string_view ida_pattern,
                                            std::optional<std::string_view> module_name = std::nullopt,
                                            size_t max_results = 10000) const;

        [[nodiscard]] scan_result scan_all(std::string_view ida_pattern,
                                            std::optional<std::string_view> module_name,
                                            size_t max_results,
                                            const std::atomic<bool>* cancel,
                                            const std::function<void(const pattern::scan_progress&)>& on_progress) const;

        /**
         * @brief Resolves a named symbol (function or data) to its runtime
         *        address. Walks every loaded module unless @p module_name
         *        restricts the search.
         *
         * On Linux, parses .dynsym and .symtab from each ELF file on disk;
         * stripped binaries only expose dynamic symbols. On Windows, uses
         * DbgHelp (requires PDB availability for non-exported symbols).
         */
        [[nodiscard]] std::optional<symbol_info> resolve_symbol(
            std::string_view symbol_name,
            std::optional<std::string_view> module_name = std::nullopt) const;

        /**
         * @brief Batch resolution. Parses each module's symbol table once and
         *        returns one entry per input name (nullopt for misses).
         */
        [[nodiscard]] std::vector<std::optional<symbol_info>> resolve_symbols(
            std::span<const std::string_view> symbol_names,
            std::optional<std::string_view> module_name = std::nullopt) const;

        /**
         * @brief Reverse lookup: returns the symbol whose [address, address+size)
         *        contains @p address, or nullopt if none found.
         */
        [[nodiscard]] std::optional<symbolize_result> symbolize(uintptr_t address) const;

    private:
        std::shared_ptr<memory_accessor> accessor_impl;
    };
}
