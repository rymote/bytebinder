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

#pragma once

#include "pch.h"
#include "memory_exceptions.h"

namespace bytebinder {
    /**
     * @brief Class to temporarily change memory protection of a region, ensuring it's writable and executable.
     *
     * This class is a RAII (Resource Acquisition Is Initialization) style guard that changes the memory
     * protection rights of a specified memory region upon construction, and restores them upon destruction.
     */
    class scoped_unlock {
    public:
        /**
         * @brief Constructs the scoped_unlock object and changes the memory protection rights of a region.
         *
         * The constructor changes the memory protection rights of the specified memory address
         * to PAGE_EXECUTE_READWRITE, allowing modification, execution, and reading of that memory region.
         *
         * @param address The memory address for which the protection rights are to be changed.
         * @param length The length of the memory region whose rights are to be changed.
         * @throws memory_operation_exception if the memory protection change fails.
         */
        scoped_unlock(uint64_t address, size_t length);

        /**
         * @brief Destroys the scoped_unlock object and restores the original memory protection rights.
         *
         * The destructor restores the original memory protection rights to the memory region specified
         * at the construction of the object. This ensures that the changes are only temporary and the
         * integrity of the memory protection is maintained.
         */
        ~scoped_unlock();

    private:
#if defined(_WIN32)
        DWORD rights; ///< Stores the original memory protection rights to be restored.
#endif
        size_t length; ///< Length of the memory region.
        void *address; ///< Memory address of the region.
    };
}