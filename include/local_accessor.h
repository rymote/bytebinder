/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "memory_accessor.h"

namespace bytebinder {
    /**
     * @brief In-process memory accessor: direct dereference for read/write,
     *        VirtualProtect/mprotect for protection changes, GetModuleHandle/
     *        dl_iterate_phdr for module enumeration. Process-wide singleton.
     */
    class BYTEBINDER_API local_accessor : public memory_accessor {
    public:
        static local_accessor& instance();

        local_accessor(const local_accessor&) = delete;
        local_accessor& operator=(const local_accessor&) = delete;

        [[nodiscard]] bool is_local() const noexcept override { return true; }
        [[nodiscard]] std::optional<uint32_t> process_id() const noexcept override;

        size_t read(uintptr_t address, void* destination, size_t size) override;
        size_t write(uintptr_t address, const void* source, size_t size) override;

        [[nodiscard]] int read_protection(uintptr_t address) override;
        int set_protection(uintptr_t address, size_t size, int new_protection) override;

        [[nodiscard]] std::vector<region_info> regions() override;
        [[nodiscard]] std::vector<module_info> modules() override;

    private:
        local_accessor() = default;
    };
}
