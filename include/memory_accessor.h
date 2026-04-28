/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "pch.h"

#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bytebinder {
    /**
     * @brief POSIX-style protection bits used as a portable currency between
     *        Windows and Unix accessors. Translation to/from PAGE_* / PROT_*
     *        happens inside each accessor implementation.
     */
    namespace protection {
        constexpr int none      = 0;
        constexpr int read      = 1;
        constexpr int write     = 2;
        constexpr int execute   = 4;
    }

    struct BYTEBINDER_API region_info {
        uintptr_t base = 0;
        size_t size = 0;
        int protection = 0;
        std::string mapped_path;
    };

    struct BYTEBINDER_API module_info {
        std::string name;
        std::string path;
        uintptr_t base = 0;
        size_t size = 0;
    };

    /**
     * @brief Abstract memory access strategy. Implementations:
     *        - local_accessor   — in-process direct dereference (the default).
     *        - remote_accessor  — out-of-process via ReadProcessMemory or
     *                             process_vm_readv/writev; protection changes
     *                             require platform privileges.
     *
     * Thread safety:
     *  - read(): safe to call concurrently from multiple threads on the same
     *    accessor for both local_accessor and remote_accessor. The OS
     *    primitives (memcpy, process_vm_readv, ReadProcessMemory) are
     *    thread-safe per their documentation.
     *  - write(): safe to call concurrently from multiple threads, but the
     *    local_accessor write path may temporarily flip page protection;
     *    overlapping writes to the same page across threads can race on the
     *    protection flip. Serialize same-page writes externally.
     *  - regions(), modules(), read_protection(): safe to call concurrently;
     *    each call reads the OS state independently.
     *  - set_protection(): not safe to call concurrently with itself or with
     *    overlapping write() calls. Serialize externally.
     */
    class BYTEBINDER_API memory_accessor {
    public:
        virtual ~memory_accessor() = default;

        [[nodiscard]] virtual bool is_local() const noexcept = 0;
        [[nodiscard]] virtual std::optional<uint32_t> process_id() const noexcept = 0;

        virtual size_t read(uintptr_t address, void* destination, size_t size) = 0;
        virtual size_t write(uintptr_t address, const void* source, size_t size) = 0;

        [[nodiscard]] virtual int read_protection(uintptr_t address) = 0;
        virtual int set_protection(uintptr_t address, size_t size, int new_protection) = 0;

        [[nodiscard]] virtual std::vector<region_info> regions() = 0;
        [[nodiscard]] virtual std::vector<module_info> modules() = 0;

        [[nodiscard]] std::optional<module_info> find_module(std::string_view name);
    };
}
