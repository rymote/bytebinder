/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "local_accessor.h"
#include "memory_exceptions.h"

#include <cstring>
#include <cstdio>

#if defined(_WIN32)
    #include <windows.h>
    #include <psapi.h>
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
        int posix_to_native_protection(int posix_flags) {
            int native = 0;
            if (posix_flags & protection::read)    native |= PROT_READ;
            if (posix_flags & protection::write)   native |= PROT_WRITE;
            if (posix_flags & protection::execute) native |= PROT_EXEC;
            return native == 0 ? PROT_NONE : native;
        }

        int parse_proc_protection(const char* permission_string) {
            int parsed = 0;
            if (permission_string[0] == 'r') parsed |= protection::read;
            if (permission_string[1] == 'w') parsed |= protection::write;
            if (permission_string[2] == 'x') parsed |= protection::execute;
            return parsed;
        }
#endif
    }

    local_accessor& local_accessor::instance() {
        static local_accessor singleton;
        return singleton;
    }

    std::optional<uint32_t> local_accessor::process_id() const noexcept {
#if defined(_WIN32)
        return static_cast<uint32_t>(GetCurrentProcessId());
#else
        return static_cast<uint32_t>(getpid());
#endif
    }

    size_t local_accessor::read(uintptr_t address, void* destination, size_t size) {
        if (address == 0 || destination == nullptr || size == 0) {
            return 0;
        }
        std::memcpy(destination, reinterpret_cast<const void*>(address), size);
        return size;
    }

    size_t local_accessor::write(uintptr_t address, const void* source, size_t size) {
        if (address == 0 || source == nullptr || size == 0) {
            return 0;
        }
        const int original = read_protection(address);
        const int needed = original | protection::read | protection::write;
        if ((original & protection::write) == 0) {
            set_protection(address, size, needed);
        }
        std::memcpy(reinterpret_cast<void*>(address), source, size);
        if ((original & protection::write) == 0) {
            set_protection(address, size, original);
        }
        return size;
    }

    int local_accessor::read_protection(uintptr_t address) {
#if defined(_WIN32)
        MEMORY_BASIC_INFORMATION region_info_local;
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(address),
                          &region_info_local, sizeof(region_info_local))) {
            return 0;
        }
        return page_to_posix_protection(region_info_local.Protect);
#else
        FILE* maps_file = std::fopen("/proc/self/maps", "r");
        if (!maps_file) {
            return protection::read | protection::write | protection::execute;
        }
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
        return discovered < 0 ? (protection::read | protection::write | protection::execute)
                              : discovered;
#endif
    }

    int local_accessor::set_protection(uintptr_t address, size_t size, int new_protection) {
        const int previous = read_protection(address);
#if defined(_WIN32)
        DWORD ignored = 0;
        if (!VirtualProtect(reinterpret_cast<LPVOID>(address), size,
                            posix_to_page_protection(new_protection), &ignored)) {
            throw memory_operation_exception("VirtualProtect failed.",
                                              memory_error_code::PROTECTION_CHANGE_FAILED);
        }
#else
        const long page_size = sysconf(_SC_PAGESIZE);
        const uintptr_t aligned_start = address & ~(static_cast<uintptr_t>(page_size) - 1);
        const uintptr_t aligned_end =
            (address + size + page_size - 1) & ~(static_cast<uintptr_t>(page_size) - 1);
        if (mprotect(reinterpret_cast<void*>(aligned_start),
                     aligned_end - aligned_start,
                     posix_to_native_protection(new_protection)) != 0) {
            throw memory_operation_exception("mprotect failed.",
                                              memory_error_code::PROTECTION_CHANGE_FAILED);
        }
#endif
        return previous;
    }

    std::vector<region_info> local_accessor::regions() {
        std::vector<region_info> out;
#if defined(_WIN32)
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        const uintptr_t max_address = reinterpret_cast<uintptr_t>(sysinfo.lpMaximumApplicationAddress);
        uintptr_t cursor = 0;
        while (cursor < max_address) {
            MEMORY_BASIC_INFORMATION info;
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor), &info, sizeof(info))) {
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
#else
        FILE* maps_file = std::fopen("/proc/self/maps", "r");
        if (!maps_file) return out;
        char line_buffer[2048];
        while (std::fgets(line_buffer, sizeof(line_buffer), maps_file)) {
            uintptr_t segment_start = 0;
            uintptr_t segment_end = 0;
            char permission_string[5] = {0};
            char path_buffer[1024] = {0};
            const int matched = std::sscanf(line_buffer, "%lx-%lx %4s %*s %*s %*s %1023[^\n]",
                                             &segment_start, &segment_end,
                                             permission_string, path_buffer);
            if (matched < 3) continue;
            region_info entry;
            entry.base = segment_start;
            entry.size = segment_end - segment_start;
            entry.protection = parse_proc_protection(permission_string);
            if (matched == 4) {
                const char* trimmed = path_buffer;
                while (*trimmed == ' ' || *trimmed == '\t') ++trimmed;
                entry.mapped_path = trimmed;
            }
            out.push_back(std::move(entry));
        }
        std::fclose(maps_file);
#endif
        return out;
    }

    std::vector<module_info> local_accessor::modules() {
        std::vector<module_info> out;
#if defined(_WIN32)
        HMODULE module_handles[1024];
        DWORD bytes_needed = 0;
        if (!EnumProcessModulesEx(GetCurrentProcess(), module_handles,
                                  sizeof(module_handles), &bytes_needed,
                                  LIST_MODULES_ALL)) {
            return out;
        }
        const size_t module_count = bytes_needed / sizeof(HMODULE);
        for (size_t module_index = 0; module_index < module_count; ++module_index) {
            char path_buffer[MAX_PATH] = {0};
            GetModuleFileNameExA(GetCurrentProcess(), module_handles[module_index],
                                 path_buffer, sizeof(path_buffer));
            MODULEINFO information = {nullptr};
            if (!GetModuleInformation(GetCurrentProcess(), module_handles[module_index],
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
#else
        struct iteration_state {
            std::vector<module_info>* destination;
        } state{&out};

        dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* user_data) -> int {
            auto* iter_state = static_cast<iteration_state*>(user_data);
            const char* current_module_path = info->dlpi_name;
            if (current_module_path == nullptr) return 0;

            uintptr_t lowest_segment = std::numeric_limits<uintptr_t>::max();
            uintptr_t highest_segment = 0;
            for (int segment_index = 0; segment_index < info->dlpi_phnum; ++segment_index) {
                const ElfW(Phdr)& program_header = info->dlpi_phdr[segment_index];
                if (program_header.p_type != PT_LOAD) continue;
                const uintptr_t segment_start = info->dlpi_addr + program_header.p_vaddr;
                const uintptr_t segment_end = segment_start + program_header.p_memsz;
                if (segment_start < lowest_segment) lowest_segment = segment_start;
                if (segment_end > highest_segment) highest_segment = segment_end;
            }

            module_info entry;
            entry.path = current_module_path;
            const char* basename = std::strrchr(current_module_path, '/');
            entry.name = basename ? basename + 1 : current_module_path;
            if (lowest_segment == std::numeric_limits<uintptr_t>::max()) {
                entry.base = info->dlpi_addr;
                entry.size = 0;
            } else {
                entry.base = lowest_segment;
                entry.size = highest_segment - lowest_segment;
            }
            iter_state->destination->push_back(std::move(entry));
            return 0;
        }, &state);
#endif
        return out;
    }

    std::optional<module_info> memory_accessor::find_module(std::string_view name) {
        const auto loaded_modules = modules();
        for (const auto& candidate : loaded_modules) {
            if (candidate.name == name || candidate.path == name) {
                return candidate;
            }
        }
        return std::nullopt;
    }
}
