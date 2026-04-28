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

#include "bb_pch.h"
#include "bb_macros.h"
#include "bb_memory_exceptions.h"
#include "bb_scoped_unlock.h"
#include "bb_pattern.h"
#include "bb_local_accessor.h"
#include "bb_disasm.h"

#include <array>

#include <asmjit/core/jitruntime.h>
#include <asmjit/x86/x86assembler.h>
#include <polyhook2/Detour/ADetour.hpp>
#include <polyhook2/Detour/x86Detour.hpp>
#include <polyhook2/Detour/x64Detour.hpp>

using namespace asmjit::x86;

namespace bytebinder {
    class mem;

    /**
     * @brief Reversible handle to an installed function detour.
     *        Returned by mem::hook; unhook() reverts the patch.
     */
    class BYTEBINDER_API hook_handle {
    public:
        hook_handle() = default;
        /// @brief Returns true if the handle owns a live detour.
        [[nodiscard]] bool installed() const noexcept { return detour_pointer != nullptr; }
        /// @brief Reverts the detour and clears the handle.
        bool unhook();

    private:
        explicit hook_handle(PLH::Detour* detour) : detour_pointer(detour) {}
        PLH::Detour* detour_pointer = nullptr;
        friend class mem;
    };

    /**
     * @brief Owning handle for a memory-watch worker thread spawned by
     *        mem::watch. Stops and joins the worker on destruction.
     */
    class BYTEBINDER_API watch_handle {
    public:
        watch_handle() = default;
        watch_handle(std::shared_ptr<std::atomic_bool> stop_flag,
                     std::thread worker_thread)
            : stop_flag(std::move(stop_flag)),
              worker_thread(std::move(worker_thread)) {}

        watch_handle(const watch_handle&) = delete;
        watch_handle& operator=(const watch_handle&) = delete;

        watch_handle(watch_handle&& other) noexcept
            : stop_flag(std::move(other.stop_flag)),
              worker_thread(std::move(other.worker_thread)) {}

        watch_handle& operator=(watch_handle&& other) noexcept {
            if (this != &other) {
                stop();
                stop_flag = std::move(other.stop_flag);
                worker_thread = std::move(other.worker_thread);
            }
            return *this;
        }

        ~watch_handle() { stop(); }

        void stop() noexcept {
            if (stop_flag) {
                stop_flag->store(true);
            }
            if (worker_thread.joinable()) {
                worker_thread.join();
            }
        }

        [[nodiscard]] bool active() const noexcept {
            return stop_flag && !stop_flag->load();
        }

    private:
        std::shared_ptr<std::atomic_bool> stop_flag;
        std::thread worker_thread;
    };

    /**
     * @brief Class that facilitates direct memory manipulation and management.
     *
     * This class is designed to handle various memory manipulation tasks such as reading, writing,
     * hooking, and pattern scanning in a target process's memory space. It provides utilities
     * to modify memory safely with features like locking mechanisms and direct memory access.
     *
     * Example:
     * @code
     * bb::mem address(reinterpret_cast<void*>(0x1234));
     * uint32_t value = address.read<uint32_t>();
     * address.write<uint32_t>(value + 1);
     * auto disasm = address.disasm(4);
     * @endcode
     *
     * @note Hooking is local-only. A remote process's mem::hook throws
     *       memory_operation_exception with INVALID_OPERATION.
     */
    class BYTEBINDER_API mem {
        friend class pattern; // Allows the pattern class to access private and protected members of mem.

    public:
        uintptr_t address; ///< Holds the memory address this object represents.
        memory_accessor* accessor; ///< Backing memory access strategy; never null.

        constexpr mem(uintptr_t address, memory_accessor* accessor)
            : address(address), accessor(accessor) {}

        mem(uintptr_t address);
        explicit mem(void* address);
        explicit mem();

        [[nodiscard]] bool is_local() const noexcept { return accessor && accessor->is_local(); }

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

        /**
         * @brief Toggles dry-run mode. When enabled, write-style methods (nop, ret, jmp,
         *        call, set_call) become no-ops while still validating their arguments.
         *        Useful for unit-testing call sites without actually mutating memory.
         */
        static void set_dry_run(bool state);

        /**
         * @brief Returns the current dry-run mode state.
         */
        [[nodiscard]] static bool is_dry_run();

        [[deprecated("Use set_dry_run; the old name is misleading.")]]
        static void set_debug(bool state) { set_dry_run(state); }

        [[deprecated("Use is_dry_run; the old name is misleading.")]]
        [[nodiscard]] static bool is_debug() { return is_dry_run(); }

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
         * @brief Returns a typed pointer from a base address with an optional offset.
         *
         * @tparam T The type of pointer to return, defaults to `void*`.
         * @param offset Byte offset to add to the base address, defaults to 0.
         * @return Pointer of type T to the address calculated as `address + offset`.
         */
        /**
         * @brief Returns a typed pointer at address+offset. **Local accessor only**;
         *        a remote accessor's bytes do not live in this process and the
         *        returned pointer would be unsafe to dereference.
         */
        template<class T = void *>
        T get(int offset = 0) {
            if (!is_local()) {
                throw memory_operation_exception(
                    "mem::get<T> requires a local accessor; use mem::read<T> for remote.",
                    memory_error_code::INVALID_OPERATION);
            }
            uintptr_t offsetted_address = address + offset;
            return (T)(offsetted_address);
        }

        /**
         * @brief Reads a T-sized value at address+offset via the bound accessor.
         *        Works for both local and remote.
         */
        template<typename T>
        [[nodiscard]] T read(int offset = 0) const {
            T value{};
            if (accessor->read(address + offset, &value, sizeof(T)) != sizeof(T)) {
                throw memory_operation_exception("Read failed.",
                                                  memory_error_code::READ_FAILED);
            }
            return value;
        }

        /**
         * @brief Reads @p size bytes starting at address+offset into a vector
         *        via the bound accessor.
         */
        [[nodiscard]] std::vector<uint8_t> read_bytes(size_t size, int offset = 0) const {
            std::vector<uint8_t> buffer(size);
            const size_t bytes_read = accessor->read(address + offset, buffer.data(), size);
            buffer.resize(bytes_read);
            return buffer;
        }

        /**
         * @brief Reads a NUL-terminated C string at this address via the bound
         *        accessor. Reads in 256-byte chunks; stops at the first NUL or
         *        at @p max_length. Returns std::nullopt if the first chunk is
         *        unreadable; returns the partial string if a later chunk fails.
         */
        [[nodiscard]] std::optional<std::string> read_cstring(size_t max_length = 4096) const;

        /**
         * @brief Reads a NUL-terminated UTF-16 string (Windows wide string).
         *        Same semantics as read_cstring but units are 16 bits.
         */
        [[nodiscard]] std::optional<std::u16string> read_wstring(size_t max_length = 4096) const;

        /**
         * @brief Writes @p value (sizeof(T) bytes) to address+offset via the bound
         *        accessor.
         */
        template<typename T>
        void set(const T& value) {
            if (accessor->write(address, &value, sizeof(T)) != sizeof(T)) {
                throw memory_operation_exception("Write failed.",
                                                  memory_error_code::WRITE_FAILED);
            }
        }

        /**
         * @brief Writes a typed value at address+offset via the bound accessor.
         */
        template<typename T>
        void write(const T& value, int offset = 0) {
            if (accessor->write(address + offset, &value, sizeof(T)) != sizeof(T)) {
                throw memory_operation_exception("Write failed.",
                                                  memory_error_code::WRITE_FAILED);
            }
        }

        /**
         * @brief Writes raw bytes at address+offset via the bound accessor.
         */
        void write_bytes(std::span<const uint8_t> bytes, int offset = 0) {
            if (accessor->write(address + offset, bytes.data(), bytes.size())
                != bytes.size()) {
                throw memory_operation_exception("Write failed.",
                                                  memory_error_code::WRITE_FAILED);
            }
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
        hook_handle hook(T *detour_function, T **original_function = nullptr) {
            if (!is_local()) {
                throw memory_operation_exception(
                    "hook requires a local accessor; remote process hooking is not supported.",
                    memory_error_code::INVALID_OPERATION);
            }
            if (get<uint8_t>() == 0xE8) {
                if (original_function) {
                    *original_function = reinterpret_cast<T*>(rip(1).address);
                }
                set_call(reinterpret_cast<void *>(detour_function));
                return hook_handle();
            }

            try {
                std::unique_ptr<PLH::Detour> detour;

                if constexpr (sizeof(void*) == 4) {
                    detour = std::make_unique<PLH::x86Detour>(
                        address,
                        reinterpret_cast<uintptr_t>(detour_function),
                        reinterpret_cast<uintptr_t*>(original_function));
                } else {
                    detour = std::make_unique<PLH::x64Detour>(
                        address,
                        reinterpret_cast<uintptr_t>(detour_function),
                        reinterpret_cast<uintptr_t*>(original_function));
                }

                if (!detour->hook()) {
                    throw memory_operation_exception("Unable to hook the function.",
                                                      memory_error_code::HOOK_INSTALLATION_FAILED);
                }

                PLH::Detour* raw_detour_pointer = detour.get();
                {
                    std::lock_guard<std::mutex> guard(mem::global_mutex);
                    mem::detours.push_back(std::move(detour));
                }
                return hook_handle(raw_detour_pointer);
            } catch (const memory_operation_exception&) {
                throw;
            } catch (const std::exception& exception) {
                throw memory_operation_exception(
                    "Unable to hook the function: " + std::string(exception.what()),
                    memory_error_code::HOOK_INSTALLATION_FAILED);
            }
        }

        static bool unhook(hook_handle& handle);
        static void unhook_all();

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
        static mem scan(const char(&ida_pattern)[Size]) {
            std::string signature_bytes;
            std::string match_mask;
            signature_bytes.reserve(Size / 2);
            match_mask.reserve(Size / 2);

            auto is_hex_digit = [](char character) {
                return (character >= '0' && character <= '9')
                    || (character >= 'a' && character <= 'f')
                    || (character >= 'A' && character <= 'F');
            };

            try {
                for (size_t cursor = 0; cursor < Size; ) {
                    const char current_character = ida_pattern[cursor];
                    if (current_character == '\0') {
                        break;
                    }
                    if (current_character == ' ' || current_character == '\t') {
                        ++cursor;
                        continue;
                    }
                    if (current_character == '?') {
                        signature_bytes.push_back('\x00');
                        match_mask.push_back('?');
                        ++cursor;
                        if (cursor < Size && ida_pattern[cursor] == '?') {
                            ++cursor;
                        }
                        continue;
                    }
                    if (is_hex_digit(current_character)) {
                        if (cursor + 1 >= Size || ida_pattern[cursor + 1] == '\0') {
                            throw std::invalid_argument("Incomplete byte in pattern");
                        }
                        const char second_character = ida_pattern[cursor + 1];
                        if (!is_hex_digit(second_character)) {
                            throw std::invalid_argument("Invalid hex digit in pattern");
                        }
                        signature_bytes.push_back(
                            static_cast<char>((char_from_hex(current_character) << 4)
                                              | char_from_hex(second_character)));
                        match_mask.push_back('x');
                        cursor += 2;
                        continue;
                    }
                    throw std::invalid_argument("Unexpected character in pattern");
                }
            } catch (const std::invalid_argument& exception) {
                if (is_dry_run()) {
                    std::cerr << "[bytebinder] Corrupt pattern: " << ida_pattern << std::endl;
                    return mem();
                }
                throw memory_operation_exception(
                    std::string("Error parsing pattern: ") + exception.what(),
                    memory_error_code::PATTERN_MATCH_FAILED);
            }

            if (signature_bytes.empty()) {
                if (is_dry_run()) {
                    std::cerr << "[bytebinder] Empty pattern" << std::endl;
                    return mem();
                }
                throw memory_operation_exception("Pattern is empty.",
                                                  memory_error_code::PATTERN_MATCH_FAILED);
            }

            mem found(pattern(std::move(signature_bytes), std::move(match_mask)).scan());
            if (!found.valid()) {
                if (is_dry_run()) {
                    std::cerr << "[bytebinder] Memory pattern not found: " << ida_pattern << std::endl;
                    return mem();
                }
                throw memory_operation_exception("Pattern not found in memory.",
                                                  memory_error_code::PATTERN_MATCH_FAILED);
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
         * @brief Allocates @p size bytes of executable memory within ±2 GiB of @p target_address.
         *        Used for trampolines that need to be reachable by a 32-bit relative call/jump.
         *
         * @throws memory_operation_exception if no suitable region is available.
         */
        static mem alloc_near(uintptr_t target_address, size_t size);

        /**
         * @brief Removes write permission and adds execute permission on @p size bytes
         *        starting at @p region. Use after writing generated code to a buffer
         *        previously allocated as read-write to enforce W^X discipline.
         *
         * @throws memory_operation_exception if the protection change fails.
         */
        static void make_executable(mem region, size_t size);

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
        [[nodiscard]] watch_handle watch(size_t size,
                                          std::function<void()> callback,
                                          std::chrono::milliseconds interval = std::chrono::milliseconds{1000}) const;

        /**
         * @brief Decodes up to @p max_instructions starting at this address using
         *        Zydis. Reads up to @p max_bytes through the bound accessor first,
         *        so this works for both local and remote mems. The decoder uses
         *        x86_64 mode on 64-bit hosts and x86 mode on 32-bit hosts.
         */
        [[nodiscard]] std::vector<instruction> disasm(size_t max_instructions,
                                                       size_t max_bytes = 1024) const;

        /**
         * @brief Decodes a single instruction at this address.
         */
        [[nodiscard]] std::optional<instruction> disasm_one() const;

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

        static std::atomic_bool dry_run_mode;
        static std::vector<std::unique_ptr<PLH::Detour>> detours;
        static std::mutex global_mutex;
    };
}