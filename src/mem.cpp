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

namespace bytebinder {
    mem::mem(void* address) : address(reinterpret_cast<uintptr_t>(address)) {}
    mem::mem() : address(0) {}

    std::vector<PLH::Detour*> mem::detours;
    mem::_storage mem::storage;
    mem::_heap mem::heap;

    void mem::init(const char* module, uintptr_t _base, size_t _size) {
    #if defined(_WIN32)
        auto base = reinterpret_cast<uintptr_t>(GetModuleHandleA(module));
        if (!base) {
            throw memory_operation_exception("Failed to retrieve module handle.", memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
        }

        MODULEINFO info = {nullptr};
        if (!GetModuleInformation(GetCurrentProcess(), reinterpret_cast<HMODULE>(base), &info, sizeof(MODULEINFO))) {
            throw memory_operation_exception("Couldn't get ModuleInformation", memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
        }

        mem::storage.base = _base ? _base : base;
        mem::storage.size = _size ? _size : info.SizeOfImage;
    #else
        Dl_info dl_info;
        void* handle = dlopen(module, RTLD_LAZY);
        if (!handle) {
            throw memory_operation_exception("Failed to open module.", memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
        }

        if (!dladdr(reinterpret_cast<void*>(init), &dl_info)) {
            dlclose(handle);
            throw memory_operation_exception("Failed to retrieve module address.", memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
        }

        mem::storage.base = reinterpret_cast<uintptr_t>(dl_info.dli_fbase);
        mem::storage.size = 0;
        dlclose(handle);
    #endif

        try {
            init_heap();
        } catch (const memory_operation_exception& e) {
            std::cerr << "Heap initialization failed: " << e.what() << std::endl;
            throw;
        }
    }

    void mem::init_heap() {
        mem::heap.size = 1024 * 1024;
    #if defined(_WIN32)
        mem::heap.data = reinterpret_cast<uintptr_t>(VirtualAlloc(nullptr, mem::heap.size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (mem::heap.data == 0) {
            throw memory_operation_exception("Failed to allocate heap memory.", memory_error_code::ALLOCATION_FAILED);
        }
    #else
        mem::heap.data = reinterpret_cast<uintptr_t>(mmap(nullptr, mem::heap.size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANON, -1, 0));
            if (mem::heap.data == reinterpret_cast<uintptr_t>(MAP_FAILED)) {
                throw memory_operation_exception("Failed to allocate heap memory.", memory_error_code::ALLOCATION_FAILED);
            }
    #endif
    }

    bool mem::valid() const {
        return address != std::numeric_limits<uintptr_t>::max();
    }

    mem mem::add(int offset) const {
        return {address + offset};
    }

    mem mem::rip(int offset) const {
        auto* relativeOffset = reinterpret_cast<int32_t*>(address + offset);
        uintptr_t effectiveAddress = address + offset + 4 + *relativeOffset;
        return mem(reinterpret_cast<void*>(effectiveAddress));
    }

    void mem::nop(size_t size) const {
        scoped_unlock lock(address, size);
        memset(reinterpret_cast<void*>(address), 0x90, size);
    }

    void mem::ret() {
        set<uint8_t>(0xC3);
    }

    mem mem::jmp(uintptr_t function) {
        set<uint8_t>(0x48);
        add(1).set<uint8_t>(0xB8);
        add(2).set<uintptr_t>(function);
        add(10).set<uint8_t>(0xFF);
        add(11).set<uint8_t>(0xE0);
        return (*this);
    }

    void mem::call(uintptr_t function) {
        set<uint8_t>(0xE8);
        add(1).set(int32_t(function - address - 5));
    }

    void mem::set_call(void* target) {
        call(alloc(12).jmp(reinterpret_cast<uintptr_t>(target)).get<uintptr_t>());
    }

    bool mem::compare(const void* buffer, size_t size) const {
        return memcmp(reinterpret_cast<void*>(address), buffer, size) == 0;
    }

    mem mem::find(const void* buffer, size_t size) const {
        size_t range = mem::storage.size - size;
        for (size_t i = 0; i < range; ++i) {
            if (compare(reinterpret_cast<const char*>(buffer), size)) {
                return {address + i};
            }
        }

        return mem();
    }

    mem mem::alloc(size_t size) {
        size_t min = (size + 15) & ~15;

        mem::heap.allocated += min;
        if (mem::heap.allocated > mem::heap.size) {
            throw memory_operation_exception("Out of heap space", memory_error_code::ALLOCATION_FAILED);
        }

        mem::heap.data = mem::heap.data + min;
        return {mem::heap.data};
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

    void mem::dump(std::ostream& os, size_t size) const {
        if (!valid()) {
            throw memory_operation_exception("Invalid or inaccessible memory address.", memory_error_code::READ_FAILED);
        }

        const auto* data = reinterpret_cast<const unsigned char*>(address);
        try {
            os << std::hex << std::setfill('0');
            for (size_t i = 0; i < size; ++i) {
                if ((i % 16 == 0) && i != 0) os << "\n";
                os << std::setw(2) << static_cast<int>(data[i]) << " ";
            }

            os << std::dec << std::endl;
        } catch (std::ios_base::failure& e) {
            throw memory_operation_exception("Failed to write memory content to stream: " + std::string(e.what()), memory_error_code::WRITE_FAILED);
        } catch (...) {
            throw memory_operation_exception("An unknown error occurred while dumping memory.", memory_error_code::UNKNOWN_ERROR);
        }
    }

    void mem::watch(size_t size, const std::function<void()>& callback, unsigned interval) {
        if (!valid()) {
            throw memory_operation_exception("Invalid or inaccessible memory address.", memory_error_code::READ_FAILED);
        }

        std::thread([this, size, callback, interval]() {
            try {
                std::vector<uint8_t> snapshot(size);
                std::vector<uint8_t> current(size);

                memcpy(snapshot.data(), reinterpret_cast<void*>(address), size);

                while (true) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(interval));
                    memcpy(current.data(), reinterpret_cast<void*>(address), size);
                    if (memcmp(snapshot.data(), current.data(), size) != 0) {
                        callback();
                        snapshot = std::move(current);
                    }
                }
            } catch (const std::exception& e) {
                std::cerr << "Exception in memory watch thread: " << e.what() << std::endl;
            }
        }).detach();
    }
}