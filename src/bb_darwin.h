/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

/**
 * @file
 * @brief Internal macOS helpers shared by local_accessor, remote_accessor,
 *        symbol resolution, and section parsing. Everything goes through a
 *        Mach task port plus a memory_accessor, so the same code serves the
 *        calling process (mach_task_self) and a task_for_pid target.
 *        Not installed; only compiled on Apple platforms.
 */

#if defined(__APPLE__)

#include "bb_memory_accessor.h"
#include "bb_process.h"

#include <mach/mach.h>

#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace bytebinder::darwin {
    /// @brief Converts VM_PROT_* bits to bytebinder protection bits.
    int to_posix_protection(vm_prot_t native_protection);

    /// @brief Converts bytebinder protection bits to VM_PROT_* bits.
    vm_prot_t to_native_protection(int posix_protection);

    /// @brief Protection of the page holding @p address in @p task, or
    ///        nullopt when the address is unmapped.
    std::optional<int> query_protection(mach_port_t task, uintptr_t address);

    /**
     * @brief Applies @p new_protection to the pages covering
     *        [address, address+size) in @p task and returns the previous
     *        protection of the first page. Adds VM_PROT_COPY when write
     *        access is requested so copy-on-write mappings whose maximum
     *        protection lacks write (such as __TEXT) can still be patched.
     * @throws memory_operation_exception on failure.
     */
    int change_protection(mach_port_t task, uintptr_t address, size_t size, int new_protection);

    /// @brief Every mapped region of @p task, descending into submaps (the
    ///        dyld shared cache) so protections are reported per mapping.
    std::vector<region_info> enumerate_regions(mach_port_t task, int process_id);

    /// @brief Every image dyld has loaded into @p task, main executable first.
    std::vector<module_info> enumerate_modules(memory_accessor& target_accessor, mach_port_t task);

    /**
     * @brief Load base and byte span of the Mach-O image whose header lives at
     *        @p header_address. Images inside the dyld shared cache only
     *        report their __TEXT span, because their other segments sit in
     *        separate cache mappings interleaved with every other image.
     */
    std::optional<module_info> describe_image(memory_accessor& target_accessor,
                                              uintptr_t header_address,
                                              std::string path);

    /// @brief Sections of the Mach-O image at @p header_address, named
    ///        "segment,section" (for example "__TEXT,__text").
    std::vector<process::module_section> parse_sections(memory_accessor& target_accessor,
                                                        uintptr_t header_address);

    /**
     * @brief Calls @p on_symbol(name, runtime_address) for every defined,
     *        non-debug symbol in the image's LC_SYMTAB. The leading
     *        underscore that Mach-O adds to C symbols is stripped.
     */
    void for_each_symbol(memory_accessor& target_accessor,
                         uintptr_t header_address,
                         const std::function<void(std::string_view, uintptr_t)>& on_symbol);
}

#endif
