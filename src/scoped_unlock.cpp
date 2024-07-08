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

namespace bytebinder {
    #if defined(_WIN32)
        scoped_unlock::scoped_unlock(uint64_t address, size_t length) : address(reinterpret_cast<void *>(address)), length(length), rights(0) {
    #else
        scoped_unlock::scoped_unlock(uint64_t address, size_t length) : address(reinterpret_cast<void *>(address)), length(length) {
    #endif

        #if defined(_WIN32)
            if (!VirtualProtect(reinterpret_cast<LPVOID>(address), length, PAGE_EXECUTE_READWRITE, &rights)) {
                throw memory_operation_exception("Failed to change memory protection.", memory_error_code::PROTECTION_CHANGE_FAILED);
            }
        #else
            long pagesize = sysconf(_SC_PAGESIZE);
            auto start = reinterpret_cast<uintptr_t>(this->address);
            uintptr_t end = start + this->length;

            start &= ~(pagesize - 1);
            this->length = end - start;

            if (mprotect(reinterpret_cast<void*>(start), this->length, PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
                throw memory_operation_exception("Failed to change memory protection.", memory_error_code::PROTECTION_CHANGE_FAILED);
            }
        #endif
    }

    scoped_unlock::~scoped_unlock() {
        #if defined(_WIN32)
            DWORD temp;
            if (!VirtualProtect(address, length, rights, &temp)) {
                std::cerr << "Failed to restore original memory protection." << std::endl;
            }
        #else
            if (mprotect(address, length, PROT_READ) != 0) {
                std::cerr << "Failed to restore original memory protection." << std::endl;
            }
        #endif
    }
}