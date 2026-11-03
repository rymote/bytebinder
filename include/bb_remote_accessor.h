/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_memory_accessor.h"

namespace bytebinder {
    /**
     * @brief Out-of-process memory accessor. Read/write goes through
     *        Read/WriteProcessMemory (Windows), process_vm_readv/writev (Linux),
     *        or mach_vm_read_overwrite/mach_vm_write on a task_for_pid port
     *        (macOS). Protection changes require platform privileges
     *        (admin / ptrace / root or the debugger entitlement).
     */
    class BYTEBINDER_API remote_accessor : public memory_accessor {
    public:
        explicit remote_accessor(uint32_t target_process_id);
        ~remote_accessor() override;

        remote_accessor(const remote_accessor&) = delete;
        remote_accessor& operator=(const remote_accessor&) = delete;

        [[nodiscard]] bool is_local() const noexcept override { return false; }
        [[nodiscard]] std::optional<uint32_t> process_id() const noexcept override { return target_pid; }

        size_t read(uintptr_t address, void* destination, size_t size) override;
        size_t write(uintptr_t address, const void* source, size_t size) override;

        [[nodiscard]] int read_protection(uintptr_t address) override;
        int set_protection(uintptr_t address, size_t size, int new_protection) override;

        [[nodiscard]] std::vector<region_info> regions() override;
        [[nodiscard]] std::vector<module_info> modules() override;

    private:
        uint32_t target_pid = 0;
#if defined(_WIN32)
        void* process_handle = nullptr;
#elif defined(__APPLE__)
        unsigned int task_port = 0; ///< mach_port_t; MACH_PORT_NULL when task_for_pid was refused.
#endif
    };
}
