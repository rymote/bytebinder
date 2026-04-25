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

#include "scoped_unlock.h"

#if !defined(_WIN32)
    #include <cstdio>
#endif

namespace bytebinder {
#if !defined(_WIN32)
    namespace {
        int read_original_protection(uintptr_t query_address) {
            FILE* maps_file = std::fopen("/proc/self/maps", "r");
            if (!maps_file) {
                return PROT_READ | PROT_WRITE | PROT_EXEC;
            }

            char line_buffer[1024];
            int discovered_protection = -1;
            while (std::fgets(line_buffer, sizeof(line_buffer), maps_file)) {
                uintptr_t segment_start = 0;
                uintptr_t segment_end = 0;
                char permission_string[5] = {0};
                if (std::sscanf(line_buffer, "%lx-%lx %4s",
                                &segment_start, &segment_end, permission_string) != 3) {
                    continue;
                }
                if (query_address < segment_start || query_address >= segment_end) {
                    continue;
                }

                int parsed_protection = 0;
                if (permission_string[0] == 'r') parsed_protection |= PROT_READ;
                if (permission_string[1] == 'w') parsed_protection |= PROT_WRITE;
                if (permission_string[2] == 'x') parsed_protection |= PROT_EXEC;
                discovered_protection = parsed_protection;
                break;
            }
            std::fclose(maps_file);

            if (discovered_protection < 0) {
                return PROT_READ | PROT_WRITE | PROT_EXEC;
            }
            return discovered_protection;
        }
    }
#endif

    #if defined(_WIN32)
        scoped_unlock::scoped_unlock(uint64_t target_address, size_t target_length)
            : original_protection(0),
              length(target_length),
              address(reinterpret_cast<void*>(target_address)) {
            if (!VirtualProtect(reinterpret_cast<LPVOID>(address), length,
                                PAGE_EXECUTE_READWRITE, &original_protection)) {
                throw memory_operation_exception("Failed to change memory protection.",
                                                  memory_error_code::PROTECTION_CHANGE_FAILED);
            }
        }

        scoped_unlock::~scoped_unlock() {
            DWORD discarded = 0;
            if (!VirtualProtect(address, length, original_protection, &discarded)) {
                std::cerr << "Failed to restore original memory protection." << std::endl;
            }
        }
    #else
        scoped_unlock::scoped_unlock(uint64_t target_address, size_t target_length) {
            const long page_size = sysconf(_SC_PAGESIZE);
            const uintptr_t page_mask = ~(static_cast<uintptr_t>(page_size) - 1);

            const uintptr_t aligned_start = target_address & page_mask;
            const uintptr_t aligned_end =
                (target_address + target_length + (page_size - 1)) & page_mask;

            address = reinterpret_cast<void*>(aligned_start);
            length = aligned_end - aligned_start;
            original_protection = read_original_protection(target_address);

            if (mprotect(address, length, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                throw memory_operation_exception("Failed to change memory protection.",
                                                  memory_error_code::PROTECTION_CHANGE_FAILED);
            }
        }

        scoped_unlock::~scoped_unlock() {
            if (mprotect(address, length, original_protection) != 0) {
                std::cerr << "Failed to restore original memory protection." << std::endl;
            }
        }
    #endif
}
