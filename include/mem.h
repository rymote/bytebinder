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
#include "scoped_unlock.h"
#include "pattern.h"

#include <asmjit/core/jitruntime.h>
#include <asmjit/x86/x86assembler.h>
#include <polyhook2/Detour/ADetour.hpp>
#include <polyhook2/Detour/x86Detour.hpp>
#include <polyhook2/Detour/x64Detour.hpp>

using namespace asmjit::x86;

namespace bytebinder {
    /**
     * @brief Class that facilitates direct memory manipulation and management.
     *
     * This class is designed to handle various memory manipulation tasks such as reading, writing,
     * hooking, and pattern scanning in a target process's memory space. It provides utilities
     * to modify memory safely with features like locking mechanisms and direct memory access.
     */
    class mem {
        friend class pattern; // Allows the pattern class to access private and protected members of mem.

    public:
        uintptr_t address; ///< Holds the memory address that this object represents.

        /**
         * @brief Constructs an instance representing the memory at a specific address.
         *
         * @param address Memory address as a uintptr_t.
         */
        //explicit mem(uintptr_t address);
        constexpr mem(uintptr_t address): address(address) {}

        /**
         * @brief Constructs an instance from a void pointer by converting it to an uintptr_t address.
         *
         * @param address Memory address as a void pointer.
         */
        explicit mem(void *address);

        /**
         * @brief Default constructor initializing the memory address to zero.
         */
        explicit mem();

        /**
         * @brief Initializes the memory manipulation environment, including hooking and base address determination.
         * This function should be called before any other memory manipulation methods are used.
         * It retrieves the module base address, and initializes the heap.
         *
         * This function should be called before any other memory manipulation methods are used.
         *
         * @param module Optional module name from which to retrieve the base address. If not provided, the base of the current process is used.
         * @throws memory_operation_exception if initialization fails at any step.
         */
        static void init(const char *module = nullptr, uintptr_t base = 0, size_t size = 0);

        /**
         * @brief Initializes the heap for memory allocations.
         *
         * This method sets up a custom heap for dynamic memory operations. It allocates a fixed size of memory
         * which can then be used for operations such as hook installation, code injection, etc. The method will
         * throw an exception if the memory cannot be allocated, ensuring that failure to initialize the heap
         * is handled gracefully.
         *
         * @throws memory_operation_exception if the heap memory cannot be allocated.
         */
        static void init_heap();

        static void debug() {} // TODO

        /**
         * @brief Checks if the current memory address is valid (i.e., not the maximum possible value for uintptr_t).
         *
         * @return True if the address is valid, otherwise false.
         */
        [[nodiscard]] bool valid() const;

        /**
         * @brief Adds an offset to the current memory address and returns a new mem object with the resulting address.
         *
         * @param offset The offset to add to the current address.
         * @return A new mem object representing the address at the current address plus offset.
         */
        [[nodiscard]] mem add(int offset) const;

        /**
         * @brief Calculates a RIP-relative address based on the current address plus an offset, typically used for x86-64 RIP-relative addressing.
         *
         * @param offset The offset from the current address to start calculating (default is 3 bytes).
         * @return A new mem object representing the computed RIP-relative address.
         */
        [[nodiscard]] mem rip(int offset = 3) const;

        /**
         * @brief Retrieves the value at the current memory address plus an optional offset.
         *
         * @param offset The offset to add to the current address for retrieving the value (default is 0).
         * @return The value of type T at the specified address.
         */
        template<class T = void *>
        T get(int offset = 0) {
            uintptr_t offsetted_address = address + offset;
            return (T)(offsetted_address);
        }

        /**
         * @brief Sets a value at the current memory address.
         *
         * @param value The value to set at the current memory address.
         */
        template<typename T>
        void set(const T &value) {
            scoped_unlock lock(address, sizeof(T));
            memcpy(reinterpret_cast<void*>(address), &value, sizeof(T));
        }

        /**
         * @brief Replaces a specified number of bytes at the current memory address with NOP (no operation) instructions, effectively "nopping out" those bytes.
         *
         * @param size The number of bytes to replace with NOP instructions.
         */
        void nop(size_t size) const;

        /**
         * @brief Sets a return (RET) instruction at the current memory address.
         */
        void ret();

        /**
         * @brief Writes a jump instruction at the current memory address to a specified function.
         *
         * @param function The address of the function to jump to.
         * @return A mem object representing the current address after setting the jump.
         */
        mem jmp(uintptr_t function);

        /**
         * @brief Writes a call instruction at the current memory address to a specified function.
         *
         * @param function The address of the function to call.
         */
        void call(uintptr_t function);

        /**
         * @brief Sets up a call instruction to a function and ensures the function is called via a JMP hook.
         *
         * @param target Pointer to the function that will be called.
         */
        void set_call(void *target);

        /**
         * @brief Hooks a function at the current memory address to a detour function and optionally provides a pointer to the original function.
         *
         * @param detourFunction The function to detour to.
         * @param originalFunction Optional pointer to store the original function address.
         * @throws memory_operation_exception If the hook could not be enabled.
         */
        template<typename T>
        void hook(T *detourFunction, T **originalFunction = nullptr) {
            if (get<uint8_t>() == 0xE8) {
                if (originalFunction) {
                    *originalFunction = reinterpret_cast<T*>(rip(1).address);
                }

                set_call(detourFunction);
                return;
            }

            try {
                PLH::Detour* detour = nullptr;

                if constexpr (sizeof(void*) == 4) {
                    detour = new PLH::x86Detour(
                        address,
                        reinterpret_cast<uintptr_t>(detourFunction),
                        reinterpret_cast<uintptr_t*>(originalFunction)
                    );
                } else {
                    detour = new PLH::x64Detour(
                        address,
                        reinterpret_cast<uintptr_t>(detourFunction),
                        reinterpret_cast<uintptr_t*>(originalFunction)
                    );
                }

                mem::detours.push_back(detour);

                if (!detour->hook()) {
                    throw memory_operation_exception("Unable to hook the function.", memory_error_code::HOOK_INSTALLATION_FAILED);
                }
            } catch (const std::exception& e) {
                throw memory_operation_exception("Unable to hook the function: " + std::string(e.what()), memory_error_code::HOOK_INSTALLATION_FAILED);
            }
        }

        /**
         * @brief Compares the memory block at the current address with the given buffer.
         *
         * This method performs a byte-by-byte comparison between the memory at the object's address
         * and the buffer provided by the caller.
         *
         * @param buffer Pointer to the buffer to compare against the memory.
         * @param size Size of the buffer and the number of bytes to compare.
         * @return True if the memory content matches the buffer, otherwise false.
         */
        bool compare(const void *buffer, size_t size) const;

        /**
         * @brief Finds the first occurrence of the specified buffer within a block of memory starting from the current address.
         *
         * This method scans a block of memory for the first match of the specified buffer by iterating over
         * each byte and using the compare method to check for a match.
         *
         * @param buffer Pointer to the buffer to find in memory.
         * @param size Size of the buffer.
         * @return A mem object representing the address where the buffer starts if found; otherwise, returns an invalid mem object.
         */
        mem find(const void *buffer, size_t size) const;

        /**
         * @brief Scans memory for a given pattern and returns the address where the pattern starts.
         *
         * An IDA-style pattern is a string that represents binary data with hexadecimal bytes and wildcards ('?') where bytes are unknown.
         *
         * @param ida_pattern The pattern to scan for, specified in IDA-style format.
         * @return A mem object representing the address where the pattern is found.
         */
        template<size_t Size>
        static mem scan(const char(&ida_pattern)[Size])  {
            char signature[128];
            char mask[128];
            size_t size = 0;

            try {
                for (size_t i = 0; i < Size; ++i, ++size) {
                    char currentChar = ida_pattern[i];

                    if ((currentChar >= 'a' && currentChar <= 'f') || (currentChar >= 'A' && currentChar <= 'F') || (currentChar >= '0' && currentChar <= '9')) {
                        if (i + 1 >= Size || ida_pattern[i + 1] == '\0') {
                            throw std::invalid_argument("Incomplete byte in pattern");
                        }

                        signature[size] = (char_from_hex(currentChar) << 4) + char_from_hex(ida_pattern[i + 1]);
                        mask[size] = 'x';
                        i += 2;
                    } else if (currentChar == '?') {
                        signature[size] = '\x00';
                        mask[size] = '?';
                        ++i;
                    } else {
                        --size;
                    }
                }
            } catch (const std::invalid_argument& e) {
                throw memory_operation_exception(std::string("Error parsing pattern: ") + e.what(), memory_error_code::PATTERN_MATCH_FAILED);
            }

            signature[size] = 0;
            mask[size] = 0;

            mem found(pattern(signature, mask, size).scan());
            if (found.address == std::numeric_limits<uintptr_t>::max()) {
                throw memory_operation_exception("Pattern not found in memory.", memory_error_code::PATTERN_MATCH_FAILED);
            }

            return found;
        }

        /**
         * @brief Allocates a block of memory of the specified size on the custom heap.
         *
         * @param size The size of the memory block to allocate.
         * @return A mem object representing the address of the allocated memory.
         * @throws memory_operation_exception If there is insufficient space in the heap or the allocation fails.
         */
        static mem alloc(size_t size);

        /**
         * @brief Assembles machine code using a provided assembly function and returns the address where the code is located.
         *
         * @param asm_function A function that takes an Assembler reference and specifies the assembly instructions.
         * @return A mem object representing the address of the assembled machine code.
         * @throws memory_operation_exception if the assembly fails or if memory for the code cannot be allocated.
         */
        static mem assemble(const std::function<void(Assembler & )> &asm_function);

        /**
         * @brief Dumps the memory content from the current address to a specified output stream.
         *
         * This method is useful for debugging or logging memory contents. It formats the output as hexadecimal values.
         *
         * @param output_stream Output stream to write the memory dump.
         * @param size Number of bytes to dump.
         * @throws memory_operation_exception if the memory address is invalid or inaccessible.
         */
        void dump(std::ostream &output_stream, size_t size) const;

        /**
         * @brief Starts watching a memory region for changes and calls a callback function when changes are detected.
         * This method uses a separate thread to periodically check the memory at the current address against a snapshot.
         * If any difference is detected between the snapshot and the current memory state, the callback is invoked.
         *
         * @param size The number of bytes to watch.
         * @param callback The function to call when a change is detected.
         * @param interval The time interval in milliseconds between checks. Default is 1000 milliseconds.
         * @throws memory_operation_exception if the initial memory read fails or if the address is invalid.
         */
        void watch(size_t size, const std::function<void()> &callback, unsigned interval = 1000);

        /**
         * @struct storage
         * @brief Holds information about the memory region of interest.
         *
         * This structure contains data about the base address and size of a module or a memory region
         * that is of interest for operations such as pattern scanning.
         */
        struct _storage {
            size_t size{};
            uintptr_t base{};
        };
        static _storage storage;

        /**
         * @struct heap
         * @brief Manages a block of memory allocated for temporary storage or operations.
         *
         * This structure helps manage a heap-like block of memory used for dynamic memory operations,
         * such as allocating space for hooks, trampolines, or other temporary modifications.
         */
        struct _heap {
            uintptr_t data = 0;
            size_t size = 0;
            size_t allocated = 0;
        };
        static _heap heap;

    private:
        /**
         * @brief Internal utility function to convert a hexadecimal character to its corresponding numerical value.
         *
         * @param character The hexadecimal character.
         * @return The numerical value corresponding to the hexadecimal character.
         */
        constexpr static unsigned char char_from_hex(char character) {
            if (character >= 'a' && character <= 'f')
                return character - 'a' + 10;
            if (character >= 'A' && character <= 'F')
                return character - 'A' + 10;
            if (character >= '0' && character <= '9')
                return character - '0';

            return 0;
        }

        static std::vector<PLH::Detour*> detours;
    };
}