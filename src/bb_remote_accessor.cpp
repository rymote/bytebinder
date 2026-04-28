/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "bb_remote_accessor.h"
#include "bb_log_sink.h"
#include "bb_memory_exceptions.h"

#include <string>

#include <cstring>
#include <cstdio>
#include <cstdlib>

#if defined(_WIN32)
    #include <windows.h>
    #include <psapi.h>
#else
    #include <sys/uio.h>
    #include <sys/types.h>
    #include <sys/wait.h>
    #include <sys/ptrace.h>
    #include <sys/user.h>
    #include <sys/syscall.h>
    #include <signal.h>
    #include <errno.h>
    #include <unistd.h>
    #include <dirent.h>
    #include <elf.h>
    #if defined(__aarch64__) || defined(__arm__)
        #include <linux/ptrace.h>
    #endif
#endif

namespace bytebinder {
    namespace {
#if defined(_WIN32)
        DWORD posix_to_page_protection(int posix_flags) {
            const bool readable   = (posix_flags & protection::read)    != 0;
            const bool writable   = (posix_flags & protection::write)   != 0;
            const bool executable = (posix_flags & protection::execute) != 0;
            if (executable && writable) return PAGE_EXECUTE_READWRITE;
            if (executable && readable) return PAGE_EXECUTE_READ;
            if (executable)             return PAGE_EXECUTE;
            if (writable)               return PAGE_READWRITE;
            if (readable)               return PAGE_READONLY;
            return PAGE_NOACCESS;
        }

        int page_to_posix_protection(DWORD page_flags) {
            switch (page_flags & 0xFF) {
                case PAGE_NOACCESS:               return 0;
                case PAGE_READONLY:               return protection::read;
                case PAGE_READWRITE:              return protection::read | protection::write;
                case PAGE_WRITECOPY:              return protection::read | protection::write;
                case PAGE_EXECUTE:                return protection::execute;
                case PAGE_EXECUTE_READ:           return protection::read | protection::execute;
                case PAGE_EXECUTE_READWRITE:      return protection::read | protection::write | protection::execute;
                case PAGE_EXECUTE_WRITECOPY:      return protection::read | protection::write | protection::execute;
                default:                          return 0;
            }
        }
#else
        int parse_proc_protection(const char* permission_string) {
            int parsed = 0;
            if (permission_string[0] == 'r') parsed |= protection::read;
            if (permission_string[1] == 'w') parsed |= protection::write;
            if (permission_string[2] == 'x') parsed |= protection::execute;
            return parsed;
        }
#endif
    }

#if defined(_WIN32)
    remote_accessor::remote_accessor(uint32_t target_process_id) : target_pid(target_process_id) {
        process_handle = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION
                                      | PROCESS_QUERY_INFORMATION,
                                      FALSE, target_process_id);
        if (process_handle == nullptr) {
            throw memory_operation_exception("OpenProcess failed.",
                                              memory_error_code::INITIALIZATION_FAILED);
        }
    }

    remote_accessor::~remote_accessor() {
        if (process_handle != nullptr) {
            CloseHandle(process_handle);
        }
    }

    size_t remote_accessor::read(uintptr_t address, void* destination, size_t size) {
        SIZE_T bytes_read = 0;
        if (!ReadProcessMemory(process_handle, reinterpret_cast<LPCVOID>(address),
                               destination, size, &bytes_read)) {
            return 0;
        }
        return static_cast<size_t>(bytes_read);
    }

    size_t remote_accessor::write(uintptr_t address, const void* source, size_t size) {
        SIZE_T bytes_written = 0;
        if (!WriteProcessMemory(process_handle, reinterpret_cast<LPVOID>(address),
                                source, size, &bytes_written)) {
            return 0;
        }
        return static_cast<size_t>(bytes_written);
    }

    int remote_accessor::read_protection(uintptr_t address) {
        MEMORY_BASIC_INFORMATION region_info_local;
        if (!VirtualQueryEx(process_handle, reinterpret_cast<LPCVOID>(address),
                            &region_info_local, sizeof(region_info_local))) {
            return 0;
        }
        return page_to_posix_protection(region_info_local.Protect);
    }

    int remote_accessor::set_protection(uintptr_t address, size_t size, int new_protection) {
        DWORD previous = 0;
        if (!VirtualProtectEx(process_handle, reinterpret_cast<LPVOID>(address), size,
                              posix_to_page_protection(new_protection), &previous)) {
            throw memory_operation_exception("VirtualProtectEx failed.",
                                              memory_error_code::PROTECTION_CHANGE_FAILED);
        }
        return page_to_posix_protection(previous);
    }

    std::vector<region_info> remote_accessor::regions() {
        std::vector<region_info> out;
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        const uintptr_t max_address = reinterpret_cast<uintptr_t>(sysinfo.lpMaximumApplicationAddress);
        uintptr_t cursor = 0;
        while (cursor < max_address) {
            MEMORY_BASIC_INFORMATION info;
            if (!VirtualQueryEx(process_handle, reinterpret_cast<LPCVOID>(cursor),
                                &info, sizeof(info))) {
                break;
            }
            if (info.State == MEM_COMMIT) {
                region_info entry;
                entry.base = reinterpret_cast<uintptr_t>(info.BaseAddress);
                entry.size = info.RegionSize;
                entry.protection = page_to_posix_protection(info.Protect);
                out.push_back(std::move(entry));
            }
            cursor = reinterpret_cast<uintptr_t>(info.BaseAddress) + info.RegionSize;
        }
        return out;
    }

    std::vector<module_info> remote_accessor::modules() {
        std::vector<module_info> out;
        HMODULE module_handles[1024];
        DWORD bytes_needed = 0;
        if (!EnumProcessModulesEx(process_handle, module_handles,
                                  sizeof(module_handles), &bytes_needed,
                                  LIST_MODULES_ALL)) {
            return out;
        }
        const size_t module_count = bytes_needed / sizeof(HMODULE);
        for (size_t module_index = 0; module_index < module_count; ++module_index) {
            char path_buffer[MAX_PATH] = {0};
            GetModuleFileNameExA(process_handle, module_handles[module_index],
                                 path_buffer, sizeof(path_buffer));
            MODULEINFO information = {nullptr};
            if (!GetModuleInformation(process_handle, module_handles[module_index],
                                      &information, sizeof(information))) {
                continue;
            }
            module_info entry;
            entry.path = path_buffer;
            const char* basename = std::strrchr(path_buffer, '\\');
            entry.name = basename ? basename + 1 : path_buffer;
            entry.base = reinterpret_cast<uintptr_t>(information.lpBaseOfDll);
            entry.size = information.SizeOfImage;
            out.push_back(std::move(entry));
        }
        return out;
    }
#else
    remote_accessor::remote_accessor(uint32_t target_process_id) : target_pid(target_process_id) {
        if (kill(static_cast<pid_t>(target_process_id), 0) != 0 && errno == ESRCH) {
            throw memory_operation_exception("Target process does not exist.",
                                              memory_error_code::INITIALIZATION_FAILED);
        }
    }

    remote_accessor::~remote_accessor() = default;

    size_t remote_accessor::read(uintptr_t address, void* destination, size_t size) {
        iovec local_io{destination, size};
        iovec remote_io{reinterpret_cast<void*>(address), size};
        const ssize_t bytes_read = process_vm_readv(static_cast<pid_t>(target_pid),
                                                     &local_io, 1, &remote_io, 1, 0);
        if (bytes_read < 0 || static_cast<size_t>(bytes_read) < size) {
            log(log_level::warn,
                "remote_accessor::read: short read at " + std::to_string(address));
        }
        return bytes_read < 0 ? 0 : static_cast<size_t>(bytes_read);
    }

    size_t remote_accessor::write(uintptr_t address, const void* source, size_t size) {
        iovec local_io{const_cast<void*>(source), size};
        iovec remote_io{reinterpret_cast<void*>(address), size};
        const ssize_t bytes_written = process_vm_writev(static_cast<pid_t>(target_pid),
                                                         &local_io, 1, &remote_io, 1, 0);
        return bytes_written < 0 ? 0 : static_cast<size_t>(bytes_written);
    }

    int remote_accessor::read_protection(uintptr_t address) {
        char path_buffer[64];
        std::snprintf(path_buffer, sizeof(path_buffer),
                      "/proc/%u/maps", static_cast<unsigned>(target_pid));
        FILE* maps_file = std::fopen(path_buffer, "r");
        if (!maps_file) return 0;

        char line_buffer[1024];
        int discovered = -1;
        while (std::fgets(line_buffer, sizeof(line_buffer), maps_file)) {
            uintptr_t segment_start = 0;
            uintptr_t segment_end = 0;
            char permission_string[5] = {0};
            if (std::sscanf(line_buffer, "%lx-%lx %4s",
                            &segment_start, &segment_end, permission_string) != 3) {
                continue;
            }
            if (address < segment_start || address >= segment_end) continue;
            discovered = parse_proc_protection(permission_string);
            break;
        }
        std::fclose(maps_file);
        return discovered < 0 ? 0 : discovered;
    }

#if !defined(_WIN32) && (defined(__x86_64__) || defined(__aarch64__) || defined(__arm__))
#define BYTEBINDER_PTRACE_AVAILABLE 1
#endif

#if defined(BYTEBINDER_PTRACE_AVAILABLE)
    namespace {
        // glibc declares `ptrace` as taking `enum __ptrace_request`; the PTRACE_* macros
        // expand to integer literals, which gcc 14+ rejects without an explicit cast.
        template<typename... Args>
        long ptrace_request_call(int request_code, Args... arguments) {
            return ptrace(static_cast<__ptrace_request>(request_code), arguments...);
        }

        int posix_to_linux_protection(int posix_flags) {
            int linux_flags = 0;
            if (posix_flags & protection::read)    linux_flags |= PROT_READ;
            if (posix_flags & protection::write)   linux_flags |= PROT_WRITE;
            if (posix_flags & protection::execute) linux_flags |= PROT_EXEC;
            return linux_flags == 0 ? PROT_NONE : linux_flags;
        }

        std::vector<pid_t> enumerate_thread_ids(pid_t leader_pid) {
            std::vector<pid_t> thread_ids;
            char task_directory_path[64];
            std::snprintf(task_directory_path, sizeof(task_directory_path),
                          "/proc/%d/task", static_cast<int>(leader_pid));
            DIR* directory_handle = opendir(task_directory_path);
            if (!directory_handle) return thread_ids;
            struct dirent* entry;
            while ((entry = readdir(directory_handle)) != nullptr) {
                if (entry->d_name[0] == '.') continue;
                const long parsed_tid = std::strtol(entry->d_name, nullptr, 10);
                if (parsed_tid > 0) {
                    thread_ids.push_back(static_cast<pid_t>(parsed_tid));
                }
            }
            closedir(directory_handle);
            return thread_ids;
        }

#if defined(__x86_64__)
        using gpr_set = user_regs_struct;

        void capture_registers(pid_t thread_id, gpr_set& destination) {
            if (ptrace_request_call(PTRACE_GETREGS, thread_id, nullptr, &destination) < 0) {
                throw memory_operation_exception(
                    std::string("PTRACE_GETREGS failed: ") + std::strerror(errno),
                    memory_error_code::PROTECTION_CHANGE_FAILED);
            }
        }
        void apply_registers(pid_t thread_id, const gpr_set& source) {
            if (ptrace_request_call(PTRACE_SETREGS, thread_id, nullptr,
                       const_cast<gpr_set*>(&source)) < 0) {
                throw memory_operation_exception(
                    std::string("PTRACE_SETREGS failed: ") + std::strerror(errno),
                    memory_error_code::PROTECTION_CHANGE_FAILED);
            }
        }
        unsigned long program_counter(const gpr_set& regs) { return regs.rip; }
        long syscall_return_value(const gpr_set& regs) {
            return static_cast<long>(regs.rax);
        }
        void prepare_syscall_registers(gpr_set& regs, long syscall_number,
                                        unsigned long arg1, unsigned long arg2,
                                        unsigned long arg3) {
            regs.rax = static_cast<unsigned long long>(syscall_number);
            regs.rdi = arg1;
            regs.rsi = arg2;
            regs.rdx = arg3;
        }
        long compose_syscall_overlay(long original_word, const gpr_set& /*regs*/) {
            return (original_word & ~static_cast<long>(0xFFFF)) | 0x050FL;
        }

#elif defined(__aarch64__)
        using gpr_set = user_pt_regs;

        void capture_registers(pid_t thread_id, gpr_set& destination) {
            struct iovec io_vector { &destination, sizeof(destination) };
            if (ptrace_request_call(PTRACE_GETREGSET, thread_id, NT_PRSTATUS, &io_vector) < 0) {
                throw memory_operation_exception(
                    std::string("PTRACE_GETREGSET(NT_PRSTATUS) failed: ")
                        + std::strerror(errno),
                    memory_error_code::PROTECTION_CHANGE_FAILED);
            }
        }
        void apply_registers(pid_t thread_id, const gpr_set& source) {
            struct iovec io_vector { const_cast<gpr_set*>(&source), sizeof(source) };
            if (ptrace_request_call(PTRACE_SETREGSET, thread_id, NT_PRSTATUS, &io_vector) < 0) {
                throw memory_operation_exception(
                    std::string("PTRACE_SETREGSET(NT_PRSTATUS) failed: ")
                        + std::strerror(errno),
                    memory_error_code::PROTECTION_CHANGE_FAILED);
            }
        }
        unsigned long program_counter(const gpr_set& regs) { return regs.pc; }
        long syscall_return_value(const gpr_set& regs) {
            return static_cast<long>(regs.regs[0]);
        }
        void prepare_syscall_registers(gpr_set& regs, long syscall_number,
                                        unsigned long arg1, unsigned long arg2,
                                        unsigned long arg3) {
            regs.regs[8] = static_cast<unsigned long long>(syscall_number);
            regs.regs[0] = arg1;
            regs.regs[1] = arg2;
            regs.regs[2] = arg3;
        }
        long compose_syscall_overlay(long original_word, const gpr_set& /*regs*/) {
            // svc #0 = D4 00 00 01 in big-endian opcode form;
            // little-endian memory representation = 0x01 0x00 0x00 0xD4 = 0xD4000001 raw.
            return (original_word & ~static_cast<long>(0xFFFFFFFFL))
                 | static_cast<long>(0xD4000001UL);
        }

#elif defined(__arm__)
        // 32-bit ARM: PTRACE_GETREGSET with NT_PRSTATUS yields 18 unsigned longs:
        //   r0..r12 (uregs[0..12]), sp=uregs[13], lr=uregs[14], pc=uregs[15], cpsr=uregs[16].
        struct gpr_set {
            unsigned long uregs[18];
        };

        void capture_registers(pid_t thread_id, gpr_set& destination) {
            struct iovec io_vector { &destination, sizeof(destination) };
            if (ptrace_request_call(PTRACE_GETREGSET, thread_id, NT_PRSTATUS, &io_vector) < 0) {
                throw memory_operation_exception(
                    std::string("PTRACE_GETREGSET(NT_PRSTATUS) failed: ")
                        + std::strerror(errno),
                    memory_error_code::PROTECTION_CHANGE_FAILED);
            }
        }
        void apply_registers(pid_t thread_id, const gpr_set& source) {
            struct iovec io_vector { const_cast<gpr_set*>(&source), sizeof(source) };
            if (ptrace_request_call(PTRACE_SETREGSET, thread_id, NT_PRSTATUS, &io_vector) < 0) {
                throw memory_operation_exception(
                    std::string("PTRACE_SETREGSET(NT_PRSTATUS) failed: ")
                        + std::strerror(errno),
                    memory_error_code::PROTECTION_CHANGE_FAILED);
            }
        }
        unsigned long program_counter(const gpr_set& regs) { return regs.uregs[15]; }
        long syscall_return_value(const gpr_set& regs) {
            return static_cast<long>(regs.uregs[0]);
        }
        void prepare_syscall_registers(gpr_set& regs, long syscall_number,
                                        unsigned long arg1, unsigned long arg2,
                                        unsigned long arg3) {
            regs.uregs[7] = static_cast<unsigned long>(syscall_number);
            regs.uregs[0] = arg1;
            regs.uregs[1] = arg2;
            regs.uregs[2] = arg3;
        }
        long compose_syscall_overlay(long original_word, const gpr_set& regs) {
            const bool thumb_mode = (regs.uregs[16] & 0x20UL) != 0;
            if (thumb_mode) {
                return (original_word & ~static_cast<long>(0xFFFF))
                     | static_cast<long>(0xDF00L);
            }
            return (original_word & ~static_cast<long>(0xFFFFFFFFL))
                 | static_cast<long>(0xEF000000UL);
        }
#endif

        struct ptrace_freeze_guard {
            pid_t leader_pid;
            std::vector<pid_t> attached_thread_ids;
            pid_t injection_thread_id = 0;

            explicit ptrace_freeze_guard(pid_t pid) : leader_pid(pid) {}

            ptrace_freeze_guard(const ptrace_freeze_guard&) = delete;
            ptrace_freeze_guard& operator=(const ptrace_freeze_guard&) = delete;

            void freeze_all_threads() {
                for (int retry_round = 0; retry_round < 8; ++retry_round) {
                    const auto current_tids = enumerate_thread_ids(leader_pid);
                    bool found_unattached = false;
                    for (pid_t candidate_tid : current_tids) {
                        if (std::find(attached_thread_ids.begin(),
                                       attached_thread_ids.end(),
                                       candidate_tid)
                            != attached_thread_ids.end()) {
                            continue;
                        }
                        if (ptrace_request_call(PTRACE_ATTACH, candidate_tid, nullptr, nullptr) < 0) {
                            if (errno == ESRCH) continue;
                            throw memory_operation_exception(
                                std::string("PTRACE_ATTACH ")
                                    + std::to_string(candidate_tid) + " failed: "
                                    + std::strerror(errno),
                                memory_error_code::PROTECTION_CHANGE_FAILED);
                        }
                        int wait_status = 0;
                        if (waitpid(candidate_tid, &wait_status, __WALL) < 0) {
                            ptrace_request_call(PTRACE_DETACH, candidate_tid, nullptr, nullptr);
                            throw memory_operation_exception(
                                std::string("waitpid after PTRACE_ATTACH failed: ")
                                    + std::strerror(errno),
                                memory_error_code::PROTECTION_CHANGE_FAILED);
                        }
                        attached_thread_ids.push_back(candidate_tid);
                        found_unattached = true;
                    }
                    if (!found_unattached) break;
                }

                if (attached_thread_ids.empty()) {
                    throw memory_operation_exception(
                        "Failed to attach to any thread of the target process.",
                        memory_error_code::PROTECTION_CHANGE_FAILED);
                }

                injection_thread_id = attached_thread_ids.front();
                for (pid_t tid : attached_thread_ids) {
                    if (tid == leader_pid) {
                        injection_thread_id = tid;
                        break;
                    }
                }
            }

            ~ptrace_freeze_guard() {
                for (pid_t tid : attached_thread_ids) {
                    ptrace_request_call(PTRACE_DETACH, tid, nullptr, nullptr);
                }
            }
        };

        long inject_remote_syscall(pid_t thread_id, long syscall_number,
                                    unsigned long arg1, unsigned long arg2,
                                    unsigned long arg3) {
            gpr_set saved_registers{};
            capture_registers(thread_id, saved_registers);

            const unsigned long pc_value = program_counter(saved_registers);

            errno = 0;
            const long original_word_at_pc = ptrace_request_call(PTRACE_PEEKTEXT, thread_id,
                                                     pc_value, nullptr);
            if (errno != 0) {
                throw memory_operation_exception(
                    std::string("PTRACE_PEEKTEXT failed: ") + std::strerror(errno),
                    memory_error_code::PROTECTION_CHANGE_FAILED);
            }

            const long overlay_word = compose_syscall_overlay(original_word_at_pc,
                                                                saved_registers);
            if (ptrace_request_call(PTRACE_POKETEXT, thread_id, pc_value, overlay_word) < 0) {
                throw memory_operation_exception(
                    std::string("PTRACE_POKETEXT (overlay) failed: ")
                        + std::strerror(errno),
                    memory_error_code::PROTECTION_CHANGE_FAILED);
            }

            gpr_set syscall_registers = saved_registers;
            prepare_syscall_registers(syscall_registers, syscall_number,
                                       arg1, arg2, arg3);

            auto restore_target_state = [&]() noexcept {
                ptrace_request_call(PTRACE_POKETEXT, thread_id, pc_value, original_word_at_pc);
                struct iovec io_vector { &saved_registers, sizeof(saved_registers) };
                (void)io_vector;
                try { apply_registers(thread_id, saved_registers); }
                catch (...) {}
            };

            try {
                apply_registers(thread_id, syscall_registers);
            } catch (...) { restore_target_state(); throw; }

            if (ptrace_request_call(PTRACE_SINGLESTEP, thread_id, nullptr, nullptr) < 0) {
                const std::string message =
                    std::string("PTRACE_SINGLESTEP failed: ") + std::strerror(errno);
                restore_target_state();
                throw memory_operation_exception(message,
                    memory_error_code::PROTECTION_CHANGE_FAILED);
            }
            int wait_status = 0;
            if (waitpid(thread_id, &wait_status, __WALL) < 0) {
                const std::string message =
                    std::string("waitpid after PTRACE_SINGLESTEP failed: ")
                        + std::strerror(errno);
                restore_target_state();
                throw memory_operation_exception(message,
                    memory_error_code::PROTECTION_CHANGE_FAILED);
            }
            if (!WIFSTOPPED(wait_status)) {
                restore_target_state();
                throw memory_operation_exception(
                    "Remote thread did not return to a stopped state after singlestep.",
                    memory_error_code::PROTECTION_CHANGE_FAILED);
            }

            gpr_set post_syscall_registers{};
            try { capture_registers(thread_id, post_syscall_registers); }
            catch (...) { restore_target_state(); throw; }

            const long return_value = syscall_return_value(post_syscall_registers);
            restore_target_state();
            return return_value;
        }
    }
#endif

    int remote_accessor::set_protection(uintptr_t address, size_t size, int new_protection) {
#if defined(BYTEBINDER_PTRACE_AVAILABLE)
        const long page_size_signed = sysconf(_SC_PAGESIZE);
        const uintptr_t page_size = static_cast<uintptr_t>(page_size_signed);
        const uintptr_t aligned_start = address & ~(page_size - 1);
        const uintptr_t aligned_end =
            (address + size + page_size - 1) & ~(page_size - 1);
        const size_t aligned_size = aligned_end - aligned_start;

        const int previous_protection = read_protection(address);

        ptrace_freeze_guard freeze_guard(static_cast<pid_t>(target_pid));
        freeze_guard.freeze_all_threads();

        const long syscall_return = inject_remote_syscall(
            freeze_guard.injection_thread_id,
            static_cast<long>(SYS_mprotect),
            static_cast<unsigned long>(aligned_start),
            static_cast<unsigned long>(aligned_size),
            static_cast<unsigned long>(posix_to_linux_protection(new_protection)));

        if (syscall_return < 0) {
            throw memory_operation_exception(
                std::string("Remote mprotect failed (errno=")
                    + std::to_string(-syscall_return) + "): "
                    + std::strerror(static_cast<int>(-syscall_return)),
                memory_error_code::PROTECTION_CHANGE_FAILED);
        }

        return previous_protection;
#elif !defined(_WIN32)
        (void)address; (void)size; (void)new_protection;
        throw memory_operation_exception(
            "Remote set_protection is unavailable on this Linux architecture.",
            memory_error_code::INVALID_OPERATION);
#endif
    }

    std::vector<region_info> remote_accessor::regions() {
        std::vector<region_info> out;
        char path_buffer[64];
        std::snprintf(path_buffer, sizeof(path_buffer),
                      "/proc/%u/maps", static_cast<unsigned>(target_pid));
        FILE* maps_file = std::fopen(path_buffer, "r");
        if (!maps_file) return out;

        char line_buffer[2048];
        while (std::fgets(line_buffer, sizeof(line_buffer), maps_file)) {
            uintptr_t segment_start = 0;
            uintptr_t segment_end = 0;
            char permission_string[5] = {0};
            char file_path_buffer[1024] = {0};
            const int matched = std::sscanf(line_buffer, "%lx-%lx %4s %*s %*s %*s %1023[^\n]",
                                             &segment_start, &segment_end,
                                             permission_string, file_path_buffer);
            if (matched < 3) continue;
            region_info entry;
            entry.base = segment_start;
            entry.size = segment_end - segment_start;
            entry.protection = parse_proc_protection(permission_string);
            if (matched == 4) {
                const char* trimmed = file_path_buffer;
                while (*trimmed == ' ' || *trimmed == '\t') ++trimmed;
                entry.mapped_path = trimmed;
            }
            out.push_back(std::move(entry));
        }
        std::fclose(maps_file);
        return out;
    }

    std::vector<module_info> remote_accessor::modules() {
        std::vector<module_info> out;
        const auto all_regions = regions();

        std::string current_path;
        uintptr_t current_low = 0;
        uintptr_t current_high = 0;

        auto flush_current = [&]() {
            if (current_path.empty()) {
                return;
            }
            const auto last_slash_position = current_path.find_last_of('/');
            const std::string current_basename = last_slash_position == std::string::npos
                ? current_path
                : current_path.substr(last_slash_position + 1);

            auto existing = std::find_if(out.begin(), out.end(),
                [&](const module_info& candidate) { return candidate.path == current_path; });
            if (existing != out.end()) {
                if (current_low < existing->base) existing->base = current_low;
                if (current_high > existing->base + existing->size) {
                    existing->size = current_high - existing->base;
                }
            } else {
                module_info entry;
                entry.path = current_path;
                entry.name = current_basename;
                entry.base = current_low;
                entry.size = current_high - current_low;
                out.push_back(std::move(entry));
            }
            current_path.clear();
            current_low = 0;
            current_high = 0;
        };

        for (const auto& region : all_regions) {
            const bool is_file_backed = !region.mapped_path.empty()
                && region.mapped_path[0] == '/';
            const bool is_anonymous = region.mapped_path.empty();
            const uintptr_t region_end = region.base + region.size;

            if (is_file_backed) {
                if (region.mapped_path == current_path && region.base == current_high) {
                    current_high = region_end;
                } else {
                    flush_current();
                    current_path = region.mapped_path;
                    current_low = region.base;
                    current_high = region_end;
                }
            } else if (is_anonymous && !current_path.empty() && region.base == current_high) {
                current_high = region_end;
            } else {
                flush_current();
            }
        }
        flush_current();
        return out;
    }
#endif
}
