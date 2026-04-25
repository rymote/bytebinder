/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "memory_accessor.h"

namespace bytebinder {
    class mem;

    /**
     * @brief High-level handle to either the current process (in-process mode)
     *        or a remote PID (out-of-process mode). Owns the memory_accessor
     *        used by every mem instance derived from it.
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

        [[nodiscard]] mem at(uintptr_t address) const;
        [[nodiscard]] std::vector<region_info> regions() const;
        [[nodiscard]] std::vector<module_info> modules() const;
        [[nodiscard]] std::optional<module_info> find_module(std::string_view name) const;

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

    private:
        std::shared_ptr<memory_accessor> accessor_impl;
    };
}
