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

#include "mem.h"
#include <polyhook2/ErrorLog.hpp>

namespace bytebinder {
    namespace {
        class stderr_polyhook_logger : public PLH::Logger {
        public:
            void log(const std::string& message, PLH::ErrorLevel level) override {
                if (level == PLH::ErrorLevel::INFO) {
                    return;
                }
                const char* level_name = (level == PLH::ErrorLevel::SEV) ? "SEV" : "WARN";
                std::cerr << "[bytebinder/polyhook][" << level_name << "] "
                          << message << std::endl;
            }
        };
    }

    mem::mem(uintptr_t address)
        : address(address), accessor(&local_accessor::instance()) {}
    mem::mem(void* address)
        : address(reinterpret_cast<uintptr_t>(address)),
          accessor(&local_accessor::instance()) {}
    mem::mem()
        : address(std::numeric_limits<uintptr_t>::max()),
          accessor(&local_accessor::instance()) {}

    std::atomic_bool mem::dry_run_mode{false};
    std::vector<std::unique_ptr<PLH::Detour>> mem::detours;
    std::mutex mem::global_mutex;
    mem::_storage mem::storage;
    mem::_heap mem::heap;

    namespace {
        struct polyhook_logger_installer {
            polyhook_logger_installer() {
                PLH::Log::registerLogger(std::make_shared<stderr_polyhook_logger>());
            }
        };
        const polyhook_logger_installer polyhook_logger_installer_instance;
    }

    void mem::init(const char* module, uintptr_t requested_base, size_t requested_size) {
        std::lock_guard<std::mutex> guard(global_mutex);
        if (requested_base != 0) {
            mem::storage.base = requested_base;
            mem::storage.size = requested_size;
        } else {
        #if defined(_WIN32)
            auto module_handle = reinterpret_cast<uintptr_t>(GetModuleHandleA(module));
            if (!module_handle) {
                throw memory_operation_exception("Failed to retrieve module handle.",
                                                  memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
            }

            MODULEINFO module_info = {nullptr};
            if (!GetModuleInformation(GetCurrentProcess(),
                                      reinterpret_cast<HMODULE>(module_handle),
                                      &module_info, sizeof(MODULEINFO))) {
                throw memory_operation_exception("Couldn't get ModuleInformation",
                                                  memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
            }

            mem::storage.base = module_handle;
            mem::storage.size = module_info.SizeOfImage;
        #else
            struct iteration_state {
                const char* requested_module_name;
                uintptr_t resolved_base;
                size_t resolved_size;
                bool found;
            } state{module, 0, 0, false};

            dl_iterate_phdr([](struct dl_phdr_info* info, size_t, void* user_data) -> int {
                auto* iter_state = static_cast<iteration_state*>(user_data);
                const char* current_module_name = info->dlpi_name;

                bool matches;
                if (iter_state->requested_module_name == nullptr) {
                    matches = (current_module_name == nullptr || current_module_name[0] == '\0');
                } else {
                    if (!current_module_name) {
                        return 0;
                    }
                    const char* current_basename = strrchr(current_module_name, '/');
                    current_basename = current_basename ? current_basename + 1 : current_module_name;
                    matches = strcmp(current_module_name, iter_state->requested_module_name) == 0
                           || strcmp(current_basename, iter_state->requested_module_name) == 0;
                }
                if (!matches) {
                    return 0;
                }

                uintptr_t lowest_segment = std::numeric_limits<uintptr_t>::max();
                uintptr_t highest_segment = 0;
                for (int segment_index = 0; segment_index < info->dlpi_phnum; ++segment_index) {
                    const ElfW(Phdr)& program_header = info->dlpi_phdr[segment_index];
                    if (program_header.p_type != PT_LOAD) {
                        continue;
                    }
                    const uintptr_t segment_start = info->dlpi_addr + program_header.p_vaddr;
                    const uintptr_t segment_end = segment_start + program_header.p_memsz;
                    if (segment_start < lowest_segment) lowest_segment = segment_start;
                    if (segment_end > highest_segment) highest_segment = segment_end;
                }

                if (lowest_segment == std::numeric_limits<uintptr_t>::max()) {
                    iter_state->resolved_base = info->dlpi_addr;
                    iter_state->resolved_size = 0;
                } else {
                    iter_state->resolved_base = lowest_segment;
                    iter_state->resolved_size = highest_segment - lowest_segment;
                }
                iter_state->found = true;
                return 1;
            }, &state);

            if (!state.found) {
                throw memory_operation_exception(
                    std::string("Failed to find module: ") + (module ? module : "(main executable)"),
                    memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
            }
            mem::storage.base = state.resolved_base;
            mem::storage.size = state.resolved_size;
        #endif
        }

        try {
            init_heap();
        } catch (const memory_operation_exception& exception) {
            std::cerr << "Heap initialization failed: " << exception.what() << std::endl;
            throw;
        }
    }

    void mem::init_heap() {
        mem::heap.size = 1024 * 1024;
        mem::heap.allocated = 0;
        #if defined(_WIN32)
            mem::heap.data = reinterpret_cast<uintptr_t>(
                VirtualAlloc(nullptr, mem::heap.size,
                              MEM_COMMIT | MEM_RESERVE,
                              PAGE_EXECUTE_READWRITE));
            if (mem::heap.data == 0) {
                throw memory_operation_exception("Failed to allocate heap memory.",
                                                  memory_error_code::ALLOCATION_FAILED);
            }
        #else
            mem::heap.data = reinterpret_cast<uintptr_t>(
                mmap(nullptr, mem::heap.size,
                     PROT_READ | PROT_WRITE | PROT_EXEC,
                     MAP_PRIVATE | MAP_ANON, -1, 0));
            if (mem::heap.data == reinterpret_cast<uintptr_t>(MAP_FAILED)) {
                throw memory_operation_exception("Failed to allocate heap memory.",
                                                  memory_error_code::ALLOCATION_FAILED);
            }
        #endif
    }

    void mem::make_executable(mem region, size_t size) {
        #if defined(_WIN32)
            DWORD previous_protection = 0;
            if (!VirtualProtect(reinterpret_cast<LPVOID>(region.address), size,
                                PAGE_EXECUTE_READ, &previous_protection)) {
                throw memory_operation_exception("Failed to set executable protection.",
                                                  memory_error_code::PROTECTION_CHANGE_FAILED);
            }
        #else
            const long page_size_signed = sysconf(_SC_PAGESIZE);
            const uintptr_t page_size = static_cast<uintptr_t>(page_size_signed);
            const uintptr_t aligned_start = region.address & ~(page_size - 1);
            const uintptr_t aligned_end =
                (region.address + size + page_size - 1) & ~(page_size - 1);

            if (mprotect(reinterpret_cast<void*>(aligned_start),
                         aligned_end - aligned_start,
                         PROT_READ | PROT_EXEC) != 0) {
                throw memory_operation_exception("Failed to set executable protection.",
                                                  memory_error_code::PROTECTION_CHANGE_FAILED);
            }
        #endif
    }

    void mem::set_dry_run(bool state) {
        dry_run_mode.store(state, std::memory_order_release);
    }

    bool mem::is_dry_run() {
        return dry_run_mode.load(std::memory_order_acquire);
    }

    bool hook_handle::unhook() {
        return detour_pointer != nullptr && mem::unhook(*this);
    }

    bool mem::unhook(hook_handle& handle) {
        if (!handle.installed()) {
            return false;
        }
        std::lock_guard<std::mutex> guard(global_mutex);
        for (auto detour_iter = detours.begin(); detour_iter != detours.end(); ++detour_iter) {
            if (detour_iter->get() != handle.detour_pointer) {
                continue;
            }
            const bool unhooked = (*detour_iter)->unHook();
            detours.erase(detour_iter);
            handle.detour_pointer = nullptr;
            return unhooked;
        }
        handle.detour_pointer = nullptr;
        return false;
    }

    void mem::unhook_all() {
        std::lock_guard<std::mutex> guard(global_mutex);
        for (auto& detour : detours) {
            detour->unHook();
        }
        detours.clear();
    }

    bool mem::valid() const {
        return address != std::numeric_limits<uintptr_t>::max();
    }

    mem mem::add(int offset) const {
        return mem(address + offset, accessor);
    }

    mem mem::rip(int offset) const {
        int32_t relative_displacement = 0;
        if (accessor->read(address + offset, &relative_displacement,
                           sizeof(relative_displacement))
            != sizeof(relative_displacement)) {
            throw memory_operation_exception("Failed to read RIP-relative displacement.",
                                              memory_error_code::READ_FAILED);
        }
        const uintptr_t effective_address =
            address + offset + 4 + static_cast<intptr_t>(relative_displacement);
        return mem(effective_address, accessor);
    }

    void mem::nop(size_t size) const {
        if (is_dry_run()) {
            return;
        }
        std::vector<uint8_t> nop_buffer(size, 0x90);
        if (accessor->write(address, nop_buffer.data(), size) != size) {
            throw memory_operation_exception("Failed to write NOP sequence.",
                                              memory_error_code::WRITE_FAILED);
        }
    }

    void mem::ret() {
        if (!is_dry_run()) {
            set<uint8_t>(0xC3);
        }
    }

    mem mem::jmp(uintptr_t function) {
        if (is_dry_run()) {
            return *this;
        }

        if constexpr (sizeof(void*) == 8) {
            uint8_t encoded_jump[12] = {
                0x48, 0xB8,
                0, 0, 0, 0, 0, 0, 0, 0,
                0xFF, 0xE0
            };
            std::memcpy(encoded_jump + 2, &function, sizeof(uintptr_t));
            if (accessor->write(address, encoded_jump, sizeof(encoded_jump))
                != sizeof(encoded_jump)) {
                throw memory_operation_exception("Failed to write absolute jump.",
                                                  memory_error_code::WRITE_FAILED);
            }
        } else {
            uint8_t encoded_jump[7] = { 0xB8, 0, 0, 0, 0, 0xFF, 0xE0 };
            const uint32_t target = static_cast<uint32_t>(function);
            std::memcpy(encoded_jump + 1, &target, sizeof(target));
            if (accessor->write(address, encoded_jump, sizeof(encoded_jump))
                != sizeof(encoded_jump)) {
                throw memory_operation_exception("Failed to write absolute jump.",
                                                  memory_error_code::WRITE_FAILED);
            }
        }

        return *this;
    }

    void mem::call(uintptr_t function) {
        if (is_dry_run()) {
            return;
        }
        uint8_t encoded_call[5] = { 0xE8, 0, 0, 0, 0 };
        const int32_t relative = static_cast<int32_t>(function - address - 5);
        std::memcpy(encoded_call + 1, &relative, sizeof(relative));
        if (accessor->write(address, encoded_call, sizeof(encoded_call))
            != sizeof(encoded_call)) {
            throw memory_operation_exception("Failed to write relative call.",
                                              memory_error_code::WRITE_FAILED);
        }
    }

    void mem::set_call(void* target) {
        if (is_dry_run()) {
            return;
        }
        if (!is_local()) {
            throw memory_operation_exception(
                "set_call requires a local accessor; remote trampoline allocation "
                "is not supported.",
                memory_error_code::INVALID_OPERATION);
        }
        constexpr size_t trampoline_size = sizeof(void*) == 8 ? 12 : 7;
        mem trampoline = alloc_near(address, trampoline_size);
        trampoline.jmp(reinterpret_cast<uintptr_t>(target));
        call(trampoline.address);
    }

    bool mem::compare(const void* buffer, size_t size) const {
        if (size == 0) return true;
        std::vector<uint8_t> staging(size);
        if (accessor->read(address, staging.data(), size) != size) {
            return false;
        }
        return std::memcmp(staging.data(), buffer, size) == 0;
    }

    mem mem::find(const void* buffer, size_t size) const {
        if (!valid() || size == 0 || size > mem::storage.size) {
            return mem();
        }

        const uintptr_t haystack_end = mem::storage.base + mem::storage.size;
        if (address < mem::storage.base || address + size > haystack_end) {
            return mem();
        }

        const size_t haystack_size = haystack_end - address;
        std::vector<uint8_t> haystack(haystack_size);
        const size_t bytes_read = accessor->read(address, haystack.data(), haystack_size);
        if (bytes_read < size) {
            return mem();
        }

        for (size_t cursor_offset = 0; cursor_offset + size <= bytes_read; ++cursor_offset) {
            if (std::memcmp(haystack.data() + cursor_offset, buffer, size) == 0) {
                return mem(address + cursor_offset, accessor);
            }
        }
        return mem();
    }

    namespace {
        constexpr int64_t REL32_RANGE_LIMIT = 0x7FFF0000LL;

#if !defined(_WIN32)
        std::vector<std::pair<uintptr_t, uintptr_t>> read_process_mappings() {
            std::vector<std::pair<uintptr_t, uintptr_t>> mappings;
            FILE* maps_file = std::fopen("/proc/self/maps", "r");
            if (!maps_file) {
                return mappings;
            }
            char line_buffer[1024];
            while (std::fgets(line_buffer, sizeof(line_buffer), maps_file)) {
                uintptr_t segment_start = 0;
                uintptr_t segment_end = 0;
                if (std::sscanf(line_buffer, "%lx-%lx", &segment_start, &segment_end) == 2) {
                    mappings.emplace_back(segment_start, segment_end);
                }
            }
            std::fclose(maps_file);
            return mappings;
        }
#endif
    }

    mem mem::alloc_near(uintptr_t target_address, size_t size) {
#if defined(_WIN32)
        SYSTEM_INFO system_info;
        GetSystemInfo(&system_info);
        const uintptr_t allocation_granularity = system_info.dwAllocationGranularity;
        const size_t aligned_size =
            (size + allocation_granularity - 1) & ~(allocation_granularity - 1);

        const uintptr_t lower_bound = (target_address > REL32_RANGE_LIMIT)
            ? target_address - REL32_RANGE_LIMIT : 0;
        const uintptr_t upper_bound = target_address + REL32_RANGE_LIMIT;

        auto try_reserve_at = [&](uintptr_t candidate_address) -> uintptr_t {
            void* allocated = VirtualAlloc(reinterpret_cast<LPVOID>(candidate_address),
                                            aligned_size,
                                            MEM_COMMIT | MEM_RESERVE,
                                            PAGE_EXECUTE_READWRITE);
            return reinterpret_cast<uintptr_t>(allocated);
        };

        uintptr_t cursor =
            (target_address + allocation_granularity - 1) & ~(allocation_granularity - 1);
        while (cursor < upper_bound) {
            MEMORY_BASIC_INFORMATION region_info;
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor),
                              &region_info, sizeof(region_info))) {
                break;
            }
            if (region_info.State == MEM_FREE && region_info.RegionSize >= aligned_size) {
                if (uintptr_t allocated_at = try_reserve_at(cursor)) {
                    return mem(allocated_at);
                }
            }
            cursor = reinterpret_cast<uintptr_t>(region_info.BaseAddress)
                   + region_info.RegionSize;
        }

        cursor = target_address & ~(allocation_granularity - 1);
        while (cursor > lower_bound) {
            MEMORY_BASIC_INFORMATION region_info;
            if (!VirtualQuery(reinterpret_cast<LPCVOID>(cursor),
                              &region_info, sizeof(region_info))) {
                break;
            }
            if (region_info.State == MEM_FREE && region_info.RegionSize >= aligned_size) {
                const uintptr_t candidate = (reinterpret_cast<uintptr_t>(region_info.BaseAddress)
                                             + region_info.RegionSize - aligned_size)
                                            & ~(allocation_granularity - 1);
                if (candidate >= lower_bound) {
                    if (uintptr_t allocated_at = try_reserve_at(candidate)) {
                        return mem(allocated_at);
                    }
                }
            }
            const uintptr_t base_addr = reinterpret_cast<uintptr_t>(region_info.BaseAddress);
            if (base_addr <= allocation_granularity) break;
            cursor = base_addr - allocation_granularity;
        }

        throw memory_operation_exception("No nearby free region found within rel32 range.",
                                          memory_error_code::ALLOCATION_FAILED);
#else
        const long page_size_signed = sysconf(_SC_PAGESIZE);
        const uintptr_t page_size = static_cast<uintptr_t>(page_size_signed);
        const size_t aligned_size = (size + page_size - 1) & ~(page_size - 1);

        const uintptr_t lower_bound = (target_address > REL32_RANGE_LIMIT)
            ? target_address - REL32_RANGE_LIMIT : page_size;
        const uintptr_t upper_bound = target_address + REL32_RANGE_LIMIT;

        auto mappings = read_process_mappings();
        std::sort(mappings.begin(), mappings.end());

        auto try_mmap_at = [&](uintptr_t candidate_address) -> uintptr_t {
            void* allocated = mmap(reinterpret_cast<void*>(candidate_address),
                                    aligned_size,
                                    PROT_READ | PROT_WRITE | PROT_EXEC,
                                    MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE,
                                    -1, 0);
            if (allocated == MAP_FAILED) {
                return 0;
            }
            if (reinterpret_cast<uintptr_t>(allocated) != candidate_address) {
                munmap(allocated, aligned_size);
                return 0;
            }
            return reinterpret_cast<uintptr_t>(allocated);
        };

        for (size_t mapping_index = 0; mapping_index < mappings.size(); ++mapping_index) {
            const uintptr_t hole_start = mappings[mapping_index].second;
            const uintptr_t hole_end = (mapping_index + 1 < mappings.size())
                                       ? mappings[mapping_index + 1].first
                                       : std::numeric_limits<uintptr_t>::max();
            if (hole_end - hole_start < aligned_size) {
                continue;
            }

            const uintptr_t aligned_hole_start = (hole_start + page_size - 1) & ~(page_size - 1);
            if (aligned_hole_start + aligned_size > hole_end) {
                continue;
            }

            uintptr_t candidate;
            if (aligned_hole_start >= target_address) {
                if (aligned_hole_start > upper_bound) continue;
                candidate = aligned_hole_start;
            } else {
                const uintptr_t aligned_hole_top = (hole_end - aligned_size) & ~(page_size - 1);
                if (aligned_hole_top < lower_bound) continue;
                candidate = aligned_hole_top < target_address ? aligned_hole_top
                                                              : aligned_hole_start;
            }

            if (candidate < lower_bound || candidate > upper_bound) {
                continue;
            }

            if (uintptr_t allocated_at = try_mmap_at(candidate)) {
                return mem(allocated_at);
            }
        }

        throw memory_operation_exception("No nearby free region found within rel32 range.",
                                          memory_error_code::ALLOCATION_FAILED);
#endif
    }

    mem mem::alloc(size_t size) {
        std::lock_guard<std::mutex> guard(global_mutex);
        const size_t aligned_size = (size + 15) & ~static_cast<size_t>(15);

        if (mem::heap.data == 0) {
            throw memory_operation_exception("Heap not initialized; call mem::init first.",
                                              memory_error_code::ALLOCATION_FAILED);
        }
        if (mem::heap.allocated + aligned_size > mem::heap.size) {
            throw memory_operation_exception("Out of heap space",
                                              memory_error_code::ALLOCATION_FAILED);
        }

        const uintptr_t allocation_address = mem::heap.data + mem::heap.allocated;
        mem::heap.allocated += aligned_size;
        return mem(allocation_address);
    }

    mem mem::assemble(const std::function<void(Assembler&)>& asm_function) {
        static asmjit::JitRuntime runtime;

        asmjit::CodeHolder code;
        code.init(runtime.environment());

        Assembler a(&code);

        try {
            asm_function(a);
        } catch (const asmjit::Error& err) {
            throw memory_operation_exception("Assembly failed: Error code " + std::to_string(err), memory_error_code::ASSEMBLY_FAILED);
        } catch (const std::exception& e) {
            throw memory_operation_exception("Assembly failed: " + std::string(e.what()), memory_error_code::ASSEMBLY_FAILED);
        }

        void* result = nullptr;
        asmjit::Error asmErr = runtime.add(&result, &code);
        if (asmErr != asmjit::kErrorOk || result == nullptr) {
            throw memory_operation_exception("Failed to allocate memory for assembled code.", memory_error_code::ALLOCATION_FAILED);
        }

        return mem(result);
    }

    void mem::dump(std::ostream& output_stream, size_t size) const {
        if (!valid()) {
            throw memory_operation_exception("Invalid or inaccessible memory address.",
                                              memory_error_code::READ_FAILED);
        }

        std::vector<uint8_t> bytes(size);
        const size_t bytes_read = accessor->read(address, bytes.data(), size);
        if (bytes_read != size) {
            throw memory_operation_exception("Short read in dump.",
                                              memory_error_code::READ_FAILED);
        }
        try {
            output_stream << std::hex << std::setfill('0');
            for (size_t byte_index = 0; byte_index < size; ++byte_index) {
                if ((byte_index % 16 == 0) && byte_index != 0) output_stream << "\n";
                output_stream << std::setw(2) << static_cast<int>(bytes[byte_index]) << " ";
            }
            output_stream << std::dec << std::endl;
        } catch (std::ios_base::failure& exception) {
            throw memory_operation_exception(
                "Failed to write memory content to stream: " + std::string(exception.what()),
                memory_error_code::WRITE_FAILED);
        } catch (...) {
            throw memory_operation_exception("An unknown error occurred while dumping memory.",
                                              memory_error_code::UNKNOWN_ERROR);
        }
    }

    watch_handle mem::watch(size_t size,
                             std::function<void()> callback,
                             std::chrono::milliseconds interval) const {
        if (!valid()) {
            throw memory_operation_exception("Invalid or inaccessible memory address.",
                                              memory_error_code::READ_FAILED);
        }

        auto stop_flag = std::make_shared<std::atomic_bool>(false);
        const uintptr_t watched_address = address;
        const std::chrono::milliseconds poll_interval = interval;
        memory_accessor* watch_accessor = accessor;

        std::thread worker_thread([watched_address, size,
                                   user_callback = std::move(callback),
                                   poll_interval, stop_flag, watch_accessor]() {
            try {
                std::vector<uint8_t> snapshot(size);
                std::vector<uint8_t> current(size);
                watch_accessor->read(watched_address, snapshot.data(), size);

                while (!stop_flag->load(std::memory_order_acquire)) {
                    std::this_thread::sleep_for(poll_interval);
                    if (stop_flag->load(std::memory_order_acquire)) {
                        break;
                    }
                    if (watch_accessor->read(watched_address, current.data(), size) != size) {
                        continue;
                    }
                    if (std::memcmp(snapshot.data(), current.data(), size) != 0) {
                        user_callback();
                        snapshot.swap(current);
                    }
                }
            } catch (const std::exception& exception) {
                std::cerr << "Exception in memory watch thread: "
                          << exception.what() << std::endl;
            }
        });

        return watch_handle(std::move(stop_flag), std::move(worker_thread));
    }
}