/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "bb_code_scan.h"
#include "bb_dump.h"
#include "bb_heuristics.h"
#include "bb_memory_accessor.h"
#include "bb_pattern.h"
#include "bb_pointer_chain.h"
#include "bb_symbols.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <span>
#include <string_view>
#include <type_traits>
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
     *
     * Example:
     * @code
     * auto target = bb::process::attach(pid);
     * uint8_t needle[] = {0x48, 0x89, 0x5C, 0x24};
     * if (auto hit = target.find_bytes({needle, sizeof(needle)}); hit.valid()) {
     *     auto value = hit.read<uint32_t>();
     * }
     * @endcode
     *
     * @note On Windows, symbol resolution and remote-process protection changes
     *       depend on DbgHelp + PDBs and admin privileges respectively. On
     *       Linux, remote protection changes require ptrace.
     */
    class BYTEBINDER_API process {
    public:
        /// @brief Returns a process bound to the calling (in-process) program.
        static process current();
        /// @brief Returns a process bound to a remote PID via the platform's
        ///        out-of-process accessor.
        static process attach(uint32_t target_process_id);

        /// @brief Default-constructs a detached process with no backing accessor.
        process() = default;
        /// @brief Constructs a process around an explicit accessor (e.g. a custom
        ///        subclass for tests or sandboxes).
        explicit process(std::shared_ptr<memory_accessor> accessor);

        /// @brief Returns a reference to the bound memory_accessor.
        [[nodiscard]] memory_accessor& accessor() const noexcept { return *accessor_impl; }
        /// @brief Returns a shared_ptr to the bound memory_accessor for ownership-sharing.
        [[nodiscard]] std::shared_ptr<memory_accessor> accessor_shared() const noexcept { return accessor_impl; }
        /// @brief Returns true if the bound accessor is the in-process accessor.
        [[nodiscard]] bool is_local() const noexcept;
        /// @brief Returns the bound process id, or nullopt for in-process targets.
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

        /// @brief Returns a mem handle bound to this process at @p address.
        [[nodiscard]] mem at(uintptr_t address) const;
        /// @brief Enumerates every mapped region in the bound process.
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

        /// @brief Enumerates every loaded module in the bound process.
        [[nodiscard]] std::vector<module_info> modules() const;
        /// @brief Returns the module whose basename matches @p name, or nullopt.
        [[nodiscard]] std::optional<module_info> find_module(std::string_view name) const;

        /// @brief One section of a loaded module (".text", ".rdata", etc).
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

        /// @brief Aggregate result of a multi-match scan: hit addresses plus
        ///        per-call statistics for diagnostics.
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

        /**
         * @brief Variant of scan_all with cooperative cancellation and a
         *        progress callback.
         * @param cancel Optional flag polled between regions; nullable.
         * @param on_progress Optional progress callback invoked per 64 KiB
         *                    window; nullable.
         */
        [[nodiscard]] scan_result scan_all(std::string_view ida_pattern,
                                            std::optional<std::string_view> module_name,
                                            size_t max_results,
                                            const std::atomic<bool>* cancel,
                                            const std::function<void(const pattern::scan_progress&)>& on_progress) const;

        /**
         * @brief Convenience scan for an exact byte sequence (no wildcards).
         *        Internally constructs an IDA pattern with all match-bytes
         *        and defers to scan().
         */
        [[nodiscard]] mem find_bytes(std::span<const uint8_t> needle,
                                       std::optional<std::string_view> module_name = std::nullopt) const;

        /**
         * @brief Multi-match variant of find_bytes.
         */
        [[nodiscard]] scan_result find_bytes_all(std::span<const uint8_t> needle,
                                                   std::optional<std::string_view> module_name = std::nullopt,
                                                   size_t max_results = 10000) const;

        /**
         * @brief Iterates every executable region (or only @p module_name if
         *        provided), decodes instructions with Zydis, and returns each
         *        instruction whose computed target equals @p target_address.
         *        Recognized kinds: direct CALL/JMP/Jcc, RIP-relative LEA, and
         *        RIP-relative MOV (load vs store inferred from operand 0).
         *        @p max_results = 0 means unlimited.
         */
        [[nodiscard]] std::vector<xref> find_xrefs(
            uintptr_t target_address,
            std::optional<std::string_view> module_name = std::nullopt,
            size_t max_results = 10000) const;

        /**
         * @brief Heuristic function-prologue scanner. Returns addresses where
         *        @p module_name's executable regions begin a recognized x86_64
         *        prologue: `endbr64`, `push rbp; mov rbp, rsp`, or
         *        `sub rsp, imm` (frame-pointer-omitted leaves).
         *        @p max_results = 0 means unlimited.
         */
        [[nodiscard]] std::vector<uintptr_t> find_prologues(
            std::string_view module_name,
            size_t max_results = 100000) const;

        /**
         * @brief Sliding-window instruction-template scanner. Each element of
         *        @p pattern matches an instruction whose mnemonic equals
         *        @c mnemonic (case-insensitive; empty string is a wildcard) and
         *        whose visible operand count equals @c operand_count when set.
         *        Returns addresses of the first instruction in each successful
         *        match. @p max_results = 0 means unlimited.
         */
        [[nodiscard]] std::vector<uintptr_t> find_instruction_pattern(
            std::span<const instruction_pattern_element> pattern,
            std::optional<std::string_view> module_name = std::nullopt,
            size_t max_results = 10000) const;

        /**
         * @brief Heuristic vtable scanner. Walks every readable, non-executable
         *        region (or the intersection with @p module_name's range), and
         *        reports any pointer-aligned run of @p min_entries or more
         *        consecutive pointers that all resolve into an executable
         *        region. @p max_results = 0 means unlimited.
         */
        [[nodiscard]] std::vector<vtable_candidate> find_vtables(
            std::optional<std::string_view> module_name = std::nullopt,
            size_t min_entries = 3,
            size_t max_results = 10000) const;

        /**
         * @brief Heuristic string-table scanner. Returns runs of two or more
         *        adjacent NUL-terminated printable-ASCII strings, where each
         *        string is at least @p min_string_length bytes long. Useful
         *        for locating localization or message tables.
         *        @p max_results = 0 means unlimited.
         */
        [[nodiscard]] std::vector<string_table_run> find_string_tables(
            std::optional<std::string_view> module_name = std::nullopt,
            size_t min_string_length = 16,
            size_t max_results = 10000) const;

        /**
         * @brief Snapshots every readable region matching @p options to disk:
         *        one binary file per region plus a JSON manifest. The manifest
         *        is written LAST, so partial dumps still leave recoverable
         *        per-region files. Non-readable regions (e.g. `[vsyscall]`) are
         *        always skipped.
         */
        [[nodiscard]] memory_dump_result dump_memory(
            std::filesystem::path output_directory,
            const memory_dump_options& options = {}) const;

        /**
         * @brief Walk a pointer chain. Each step's offset is added to the
         *        running address; if the step's `dereference` flag is set,
         *        the walker reads 8 bytes there and treats them as the next
         *        address. Empty `steps` returns success with `address = base`.
         *        On any read failure the returned `chain_resolution` carries
         *        `failed_at_step`, `failure`, and `partial_walk_addr` for
         *        diagnostics.
         *
         * Example:
         * @code
         * std::array<bb::chain_step, 3> steps{{ {0,true}, {0x10,true}, {0x4,false} }};
         * auto r = process.resolve_chain(base, steps);
         * if (r.address) std::printf("0x%lx\n", *r.address);
         * @endcode
         */
        [[nodiscard]] chain_resolution resolve_chain(
            uintptr_t base,
            std::span<const chain_step> steps) const;

        /**
         * @brief Resolve the chain and read a typed value at the final
         *        address. Returns nullopt on chain-walk failure OR if the
         *        final read short-reads. Caller can re-run resolve_chain
         *        for diagnostics.
         */
        template<typename ValueType>
        [[nodiscard]] std::optional<ValueType> read_chain(
            uintptr_t base,
            std::span<const chain_step> steps) const;

        /**
         * @brief Locate every pointer-aligned address in the readable regions
         *        matching the protection mask whose 8 stored bytes equal
         *        @p target. Defaults to writable, non-executable data, which
         *        is where chain intermediate pointers live.
         */
        [[nodiscard]] std::vector<uintptr_t> find_pointers_to(
            uintptr_t target,
            std::optional<std::string_view> module_name = std::nullopt,
            int required_protection = protection::read | protection::write,
            int forbidden_protection = protection::execute,
            size_t max_results = 10000) const;

        /**
         * @brief Watch a pointer chain. The worker thread re-walks the chain
         *        every @p interval and invokes @p on_resolve(final_address)
         *        whenever resolution succeeds and yields an address different
         *        from the previous tick. The returned watch_handle stops the
         *        worker on destruction (RAII).
         */
        [[nodiscard]] watch_handle watch_chain(
            uintptr_t base,
            std::span<const chain_step> steps,
            std::function<void(uintptr_t)> on_resolve,
            std::chrono::milliseconds interval = std::chrono::milliseconds{1000}) const;

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

        /**
         * @brief Scans for an exact value of type T at @p alignment-byte stride.
         *        Default alignment is sizeof(T) (natural alignment).
         *        Bitwise comparison: scan_value<float>(NaN) matches nothing.
         */
        template<typename ValueType>
        [[nodiscard]] scan_result scan_value(
            ValueType expected,
            std::optional<std::string_view> module_name = std::nullopt,
            size_t alignment = sizeof(ValueType),
            size_t max_results = 10000) const;

        /**
         * @brief Scans for values in [inclusive_low, inclusive_high] using
         *        operator<= comparisons. For floats this covers epsilon
         *        matching: scan_value_in_range(1.49f, 1.51f). Requires
         *        ValueType to support operator<=.
         */
        template<typename ValueType>
        [[nodiscard]] scan_result scan_value_in_range(
            ValueType inclusive_low,
            ValueType inclusive_high,
            std::optional<std::string_view> module_name = std::nullopt,
            size_t alignment = sizeof(ValueType),
            size_t max_results = 10000) const;

        /**
         * @brief Bitmask scan: address matches iff
         *        (read_value & mask) == (expected & mask).
         *        ValueType must support operator& and operator==.
         */
        template<typename ValueType>
        [[nodiscard]] scan_result scan_value_with_mask(
            ValueType expected,
            ValueType mask,
            std::optional<std::string_view> module_name = std::nullopt,
            size_t alignment = sizeof(ValueType),
            size_t max_results = 10000) const;

    private:
        std::shared_ptr<memory_accessor> accessor_impl;
    };

    template<typename ValueType>
    std::optional<ValueType> process::read_chain(
        uintptr_t base,
        std::span<const chain_step> steps) const {
        static_assert(std::is_trivially_copyable_v<ValueType>,
                       "read_chain requires a trivially-copyable type");
        const auto resolution = resolve_chain(base, steps);
        if (!resolution.address.has_value()) return std::nullopt;
        ValueType value{};
        const size_t got = accessor_impl->read(*resolution.address,
                                                  &value, sizeof(ValueType));
        if (got != sizeof(ValueType)) return std::nullopt;
        return value;
    }
}
