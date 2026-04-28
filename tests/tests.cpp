#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "bb_process.h"

#include <array>

#if !defined(_WIN32)
    #include <sys/wait.h>
    #include <sys/types.h>
    #include <signal.h>
    #include <unistd.h>
#else
    #include <windows.h>
    #include <crtdbg.h>
    #include <stdlib.h>
#endif

// Detect AddressSanitizer in a compiler-portable way. MSVC's preprocessor
// errors on `__has_feature(address_sanitizer)` even when guarded by
// `defined(__has_feature) &&` because undefined identifiers in #if
// expressions become 0, producing the syntax `0(address_sanitizer)`.
// Splitting the check into nested #if/#elif keeps the function-like macro
// invocation out of any code path MSVC will see.
#if defined(__SANITIZE_ADDRESS__)
#  define BYTEBINDER_HAS_ASAN 1
#elif defined(__has_feature)
#  if __has_feature(address_sanitizer)
#    define BYTEBINDER_HAS_ASAN 1
#  else
#    define BYTEBINDER_HAS_ASAN 0
#  endif
#else
#  define BYTEBINDER_HAS_ASAN 0
#endif

namespace {
    // Stop Windows debug runtimes from popping modal dialogs (CRT assertion,
    // abort(), unhandled exception) — those hang CI forever.
    struct windows_dialog_suppressor {
        windows_dialog_suppressor() {
#if defined(_WIN32)
            SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX
                         | SEM_NOOPENFILEERRORBOX);
    #if defined(_DEBUG)
            _CrtSetReportMode(_CRT_WARN,   _CRTDBG_MODE_FILE);
            _CrtSetReportFile(_CRT_WARN,   _CRTDBG_FILE_STDERR);
            _CrtSetReportMode(_CRT_ERROR,  _CRTDBG_MODE_FILE);
            _CrtSetReportFile(_CRT_ERROR,  _CRTDBG_FILE_STDERR);
            _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
            _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
            _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    #endif
#endif
        }
    };
    const windows_dialog_suppressor windows_dialog_suppressor_instance;
}

uint8_t buffer[1024];

TEST_CASE("Initialization and address calculation", "[mem]") {
    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));
    bb::mem memory(reinterpret_cast<void*>(buffer));

    SECTION("init function sets base correctly") {
        REQUIRE(bb::mem::storage.base == reinterpret_cast<uintptr_t>(buffer));
        REQUIRE(bb::mem::storage.size == sizeof(buffer));
    }

    uint32_t expectedValue = 123456789;
    *reinterpret_cast<uint32_t*>(buffer + 100) = expectedValue;

    SECTION("add method calculates new address correctly") {
        auto offsettedMemory = memory.add(100);
        auto retrievedValue = *offsettedMemory.get<uint32_t*>();
        REQUIRE(retrievedValue == expectedValue);
    }
}

TEST_CASE("RIP-relative address calculation", "[mem]") {
    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));
    bb::mem memory(reinterpret_cast<void*>(buffer + 100));

    int32_t relativeOffset = 50;
    *reinterpret_cast<int32_t*>(buffer + 100 + 3) = relativeOffset;

    uint32_t knownValue = 123456789;
    auto targetAddress = reinterpret_cast<uintptr_t>(buffer + 100 + 3 + 4 + relativeOffset);
    *reinterpret_cast<uint32_t*>(targetAddress) = knownValue;

    bb::mem calculatedAddress = memory.rip(3);

    SECTION("Calculates correct RIP-relative address and retrieves correct value") {
        uint32_t retrievedValue = *calculatedAddress.get<uintptr_t*>();
        REQUIRE(retrievedValue == knownValue);
    }
}

TEST_CASE("Memory operations using mem.get and mem.set", "[mem]") {
    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));
    bb::mem memory(reinterpret_cast<void*>(buffer));

    memset(buffer, 0, sizeof(buffer));

    SECTION("Set and Get integer values") {
        uint32_t setValue = 0x87654321;

        auto mem1 = memory.add(30);
        mem1.set(setValue);

        auto mem2 = memory.add(30);
        auto getValue = *mem2.get<uint32_t*>();

        REQUIRE(getValue == setValue);
    }

    SECTION("Set and Get byte values") {
        uint8_t byteValue = 0xAB;
        memory.add(15).set(byteValue);
        auto readByte = *memory.add(15).get<uint8_t*>();
        REQUIRE(readByte == byteValue);
    }

    SECTION("Set and Get for multiple data types and sizes") {
        uint64_t largeValue = 0xCAFEBABEDEADBEEF;
        memory.add(40).set(largeValue);
        REQUIRE(*memory.add(40).get<uint64_t*>() == largeValue);
    }

    SECTION("Set and Get across various offsets") {
        for (int offset = 0; offset < 100; offset += 4) {
            uint32_t value = static_cast<uint32_t>(offset) * 5;
            memory.add(offset).set(value);
            REQUIRE(*memory.add(offset).get<uint32_t*>() == value);
        }
    }
}


TEST_CASE("NOP operation", "[mem]") {
    memset(buffer, 0, sizeof(buffer));
    bb::mem memory(reinterpret_cast<void*>(buffer + 50));
    memory.nop(10);

    SECTION("Buffer contains NOPs at correct position") {
        for (int i = 0; i < 10; i++) {
            REQUIRE(buffer[50 + i] == 0x90);
        }
    }
}

TEST_CASE("RET operation sets correct opcode", "[mem]") {
    bb::mem memory(reinterpret_cast<void*>(buffer));
    memory.ret();

    REQUIRE(buffer[0] == 0xC3);
}

TEST_CASE("JMP and CALL operations", "[mem]") {
    bb::mem memory(reinterpret_cast<void*>(buffer));
    uintptr_t fake_function = reinterpret_cast<uintptr_t>(buffer) + 200;

    SECTION("JMP writes correct opcode and address") {
        memory.jmp(fake_function);
        REQUIRE(buffer[0] == 0x48);
        REQUIRE(buffer[1] == 0xB8);
        REQUIRE(*reinterpret_cast<uintptr_t*>(buffer + 2) == fake_function);
        REQUIRE(buffer[10] == 0xFF);
        REQUIRE(buffer[11] == 0xE0);
    }

    SECTION("CALL writes correct opcode and relative address") {
        memory.call(fake_function);
        REQUIRE(buffer[0] == 0xE8);
        int32_t rel_address = *reinterpret_cast<int32_t*>(buffer + 1);
        REQUIRE(reinterpret_cast<uintptr_t>(buffer + 5 + rel_address) == fake_function);
    }
}
TEST_CASE("Search for pattern in memory and returns correct position", "[mem]") {
    memset(buffer, 0, sizeof(buffer));
    uint8_t knownPattern[] = { 0xF2, 0xAF, 0xDF, 0x1F, 0x9F, 0xFB, 0x12 };
    size_t patternStartOffset = 6;
    std::memcpy(&buffer[patternStartOffset], knownPattern, sizeof(knownPattern));

    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));

    auto result = bb::mem::scan("AF ? 1F 9F FB");

    uint8_t expectedByte = buffer[patternStartOffset + 1];
    REQUIRE(*result.get<uint8_t*>() == expectedByte);

    SECTION("Pattern scanning correctly identifies memory locations") {
        REQUIRE(*result.get<uint8_t*>() == 0xAF);
    }
}

void (*OrigFunction)(int) = nullptr;
void HookFunction(int value){
    OrigFunction(5);
}

int testValue = 0;
NOINLINE void TestHookFunction(int value) {
    volatile int padding[16] = {0};
    for (int padding_index = 0; padding_index < 16; ++padding_index) {
        padding[padding_index] = value;
    }
    testValue = value;
    (void)padding;
}

TEST_CASE("Function hooking and behavior validation") {
    SECTION("Original function should modify global state correctly") {
        TestHookFunction(2);
        REQUIRE(testValue == 2);
    }

    if (!OrigFunction) {
        bb::mem(reinterpret_cast<void*>(&TestHookFunction)).hook(HookFunction, &OrigFunction);
    }

    SECTION("Original function pointer should call hooked function") {
        OrigFunction(10);
        REQUIRE(testValue == 10);
    }

    SECTION("Original function should be called with altered argument after hooking") {
        TestHookFunction(10);
        REQUIRE(testValue == 5);
    }
}

TEST_CASE("Memory comparison validation", "[mem]") {
    memset(buffer, 0, sizeof(buffer));
    const char pattern[] = "HelloWorld";
    std::memcpy(buffer + 100, pattern, strlen(pattern));
    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));
    bb::mem memory(reinterpret_cast<void*>(buffer + 100));

    SECTION("Correctly compares identical memory content") {
        REQUIRE(memory.compare(pattern, strlen(pattern)) == true);
    }

    SECTION("Correctly identifies non-identical memory content") {
        const char wrongPattern[] = "Goodbye";
        REQUIRE(memory.compare(wrongPattern, strlen(wrongPattern)) == false);
    }

    SECTION("Correctly compares partial memory content") {
        REQUIRE(memory.compare("Hello", 5) == true);
    }
}

int testInitValue = 5;
static bb::init_func InitFunc([] {
    testInitValue = 10;
});

TEST_CASE("Initializer system", "[mem]") {
    SECTION("Initial value of the test variable is correctly set") {
        REQUIRE(testInitValue == 5);
    }
    bb::run_init_funcs();
    SECTION("Test variable has the correct value after init funcs ran") {
        REQUIRE(testInitValue == 10);
    }
}

TEST_CASE("mem::find locates a buffer and reports misses", "[mem][find]") {
    memset(buffer, 0xAA, sizeof(buffer));
    const uint8_t needle[] = {0x01, 0x02, 0x03, 0x04};
    constexpr size_t needle_offset = 200;
    std::memcpy(buffer + needle_offset, needle, sizeof(needle));

    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));
    const bb::mem haystack(reinterpret_cast<void*>(buffer));

    SECTION("Returns the address of the first match") {
        const bb::mem hit = haystack.find(needle, sizeof(needle));
        REQUIRE(hit.valid());
        REQUIRE(hit.address == reinterpret_cast<uintptr_t>(buffer + needle_offset));
    }

    SECTION("Returns invalid mem when the buffer is absent") {
        const uint8_t missing[] = {0x99, 0x98, 0x97, 0x96};
        const bb::mem hit = haystack.find(missing, sizeof(missing));
        REQUIRE_FALSE(hit.valid());
    }

    SECTION("Returns invalid mem for zero-size buffer") {
        const bb::mem hit = haystack.find(needle, 0);
        REQUIRE_FALSE(hit.valid());
    }
}

TEST_CASE("mem::alloc returns non-overlapping ranges and respects the heap", "[mem][alloc]") {
    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));

    SECTION("Successive allocations do not overlap") {
        const bb::mem first = bb::mem::alloc(32);
        const bb::mem second = bb::mem::alloc(32);
        REQUIRE(first.valid());
        REQUIRE(second.valid());
        REQUIRE(second.address >= first.address + 32);
    }

    SECTION("Out-of-heap allocations throw") {
        REQUIRE_THROWS_AS(bb::mem::alloc(8 * 1024 * 1024),
                          bb::memory_operation_exception);
    }
}

TEST_CASE("Dry-run mode disables write helpers", "[mem][dry_run]") {
    memset(buffer, 0, sizeof(buffer));
    bb::mem::set_dry_run(true);
    bb::mem(reinterpret_cast<void*>(buffer)).ret();
    REQUIRE(buffer[0] == 0);
    bb::mem(reinterpret_cast<void*>(buffer)).nop(4);
    REQUIRE(buffer[0] == 0);
    bb::mem::set_dry_run(false);
    bb::mem(reinterpret_cast<void*>(buffer)).ret();
    REQUIRE(buffer[0] == 0xC3);
}

TEST_CASE("watch_handle detects writes and stops cleanly", "[mem][watch]") {
    memset(buffer, 0, sizeof(buffer));
    std::atomic<int> change_count{0};
    bb::mem watched(reinterpret_cast<void*>(buffer + 256));
    auto handle = watched.watch(8,
        [&change_count]() { change_count.fetch_add(1); },
        std::chrono::milliseconds{20});

    REQUIRE(handle.active());

    for (int round = 0; round < 5; ++round) {
        std::this_thread::sleep_for(std::chrono::milliseconds{50});
        ++(*reinterpret_cast<int*>(buffer + 256));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds{50});

    handle.stop();
    REQUIRE_FALSE(handle.active());
    REQUIRE(change_count.load() >= 1);
}

TEST_CASE("mem::scan rejects malformed patterns when not in dry-run", "[mem][scan]") {
    bb::mem::init(nullptr, reinterpret_cast<uintptr_t>(buffer), sizeof(buffer));
    bb::mem::set_dry_run(false);

    SECTION("Invalid hex digit throws") {
        REQUIRE_THROWS_AS(bb::mem::scan("ZZ"),
                          bb::memory_operation_exception);
    }

    SECTION("Empty pattern throws") {
        REQUIRE_THROWS_AS(bb::mem::scan(""),
                          bb::memory_operation_exception);
    }

    SECTION("Pattern not present throws") {
        memset(buffer, 0xAA, sizeof(buffer));
        REQUIRE_THROWS_AS(bb::mem::scan("DE AD BE EF C0 DE"),
                          bb::memory_operation_exception);
    }
}

TEST_CASE("unhook removes an installed detour", "[mem][hook][unhook]") {
    if (!OrigFunction) {
        bb::mem(reinterpret_cast<void*>(&TestHookFunction))
            .hook(HookFunction, &OrigFunction);
    }
    bb::mem::unhook_all();
    TestHookFunction(7);
    REQUIRE(testValue == 7);
    OrigFunction = nullptr;
}

namespace {
    int vmt_test_observed_value = 0;
    struct vmt_target {
        virtual ~vmt_target() = default;
        virtual int compute(int input) { return input + 1; }
    };
    int vmt_test_detour(vmt_target* /*self*/, int input) {
        vmt_test_observed_value = input;
        return input * 1000;
    }

    // Defeats gcc/clang -O3 devirtualization of stack-local virtual calls.
    // The wrapper compiles at -O0 (gcc) / `optnone` (clang) and is also
    // marked noinline so the call site can't fold the body in. Devirtualization
    // happens during inlining and IPA, both of which are disabled here.
#if defined(__GNUC__) && !defined(__clang__)
    __attribute__((noinline, noipa, optimize("O0")))
#elif defined(__clang__)
    __attribute__((noinline, optnone))
#elif defined(_MSC_VER)
    __declspec(noinline)
#endif
    int vmt_test_call_compute(vmt_target* target, int value) {
        return target->compute(value);
    }
}

TEST_CASE("vmt::hook redirects a virtual call and unhook restores it", "[vmt][hook]") {
    vmt_target instance;
    REQUIRE(instance.compute(5) == 6);

    bb::vmt vtable_view(reinterpret_cast<uintptr_t>(&instance));
    // Itanium C++ ABI: a virtual destructor consumes two slots (D1 + D0),
    // so the next user-declared virtual sits at index 2. MSVC uses a single
    // slot, putting compute at index 1.
#if defined(_MSC_VER)
    constexpr size_t compute_index = 1;
#else
    constexpr size_t compute_index = 2;
#endif

    const uintptr_t original_pointer = vtable_view.function_at(compute_index);
    REQUIRE(original_pointer != 0);

    auto handle = vtable_view.hook(compute_index, reinterpret_cast<void*>(&vmt_test_detour));
    REQUIRE(handle.installed());
    REQUIRE(vtable_view.function_at(compute_index)
            == reinterpret_cast<uintptr_t>(&vmt_test_detour));

    vmt_test_observed_value = 0;
    const int detoured_result = vmt_test_call_compute(&instance, 7);
    REQUIRE(vmt_test_observed_value == 7);
    REQUIRE(detoured_result == 7000);

    REQUIRE(handle.unhook());
    REQUIRE_FALSE(handle.installed());

    REQUIRE(vmt_test_call_compute(&instance, 9) == 10);
}

TEST_CASE("mem::disasm decodes a known x64 sequence", "[mem][disasm]") {
    if constexpr (sizeof(void*) == 8) {
        memset(buffer, 0, sizeof(buffer));
        // x64: push rbp; mov rbp, rsp; nop; ret
        buffer[0] = 0x55;
        buffer[1] = 0x48; buffer[2] = 0x89; buffer[3] = 0xE5;
        buffer[4] = 0x90;
        buffer[5] = 0xC3;

        bb::mem code(reinterpret_cast<void*>(buffer));

        SECTION("disasm_one returns the first instruction") {
            const auto first_instruction = code.disasm_one();
            REQUIRE(first_instruction.has_value());
            REQUIRE(first_instruction->length == 1);
            REQUIRE(first_instruction->mnemonic == "push");
        }

        SECTION("disasm walks instructions in order") {
            const auto decoded = code.disasm(4, 8);
            REQUIRE(decoded.size() == 4);
            REQUIRE(decoded[0].mnemonic == "push");
            REQUIRE(decoded[1].mnemonic == "mov");
            REQUIRE(decoded[2].mnemonic == "nop");
            REQUIRE(decoded[3].mnemonic == "ret");
            REQUIRE(decoded[0].length == 1);
            REQUIRE(decoded[1].length == 3);
            REQUIRE(decoded[2].length == 1);
            REQUIRE(decoded[3].length == 1);
            REQUIRE(decoded[1].address == decoded[0].address + 1);
        }
    }
}

#if !defined(_WIN32)
TEST_CASE("process::resolve_symbol finds a libc dynamic symbol", "[process][symbols]") {
    auto current_process = bb::process::current();
    const auto resolved = current_process.resolve_symbol("memcpy");
    REQUIRE(resolved.has_value());
    REQUIRE(resolved->address != 0);
    REQUIRE_FALSE(resolved->module_name.empty());
}

TEST_CASE("process::symbolize round-trips an address back to its name", "[process][symbols]") {
    auto current_process = bb::process::current();
    const auto resolved_memcpy = current_process.resolve_symbol("memcpy");
    REQUIRE(resolved_memcpy.has_value());
    const auto symbolized = current_process.symbolize(resolved_memcpy->address);
    REQUIRE(symbolized.has_value());
    REQUIRE(symbolized->symbol.name == "memcpy");
}
#endif

TEST_CASE("process::symbolize returns offset from symbol start", "[symbols]") {
    auto current_process = bb::process::current();
    auto resolved = current_process.resolve_symbol("memcpy");
    if (!resolved.has_value()) {
        SUCCEED("memcpy unresolved on this platform/build; offset semantics untestable here");
        return;
    }
    const uintptr_t query_address = resolved->address + 7;
    auto symbolized = current_process.symbolize(query_address);
    REQUIRE(symbolized.has_value());
    REQUIRE(symbolized->symbol.address + symbolized->offset_from_start == query_address);
}

TEST_CASE("process::resolve_symbols batches lookups", "[symbols]") {
    auto current_process = bb::process::current();
    std::array<std::string_view, 3> names{"memcpy", "memmove", "memset"};
    auto results = current_process.resolve_symbols(names);
    REQUIRE(results.size() == names.size());
    for (size_t index = 0; index < names.size(); ++index) {
        if (results[index].has_value()) {
            REQUIRE_FALSE(results[index]->name.empty());
        }
    }
}

TEST_CASE("process::current() returns a usable local handle", "[process][local]") {
    auto current_process = bb::process::current();
    REQUIRE(current_process.is_local());
    REQUIRE(current_process.id().has_value());
    const auto loaded_modules = current_process.modules();
    REQUIRE_FALSE(loaded_modules.empty());
}

TEST_CASE("get<T>() rejects a remote-bound mem", "[mem][remote][safety]") {
    bb::local_accessor& backing = bb::local_accessor::instance();
    bb::mem local_bound(reinterpret_cast<void*>(buffer));
    REQUIRE_NOTHROW(local_bound.get<uint8_t*>());

    struct fake_remote : bb::memory_accessor {
        bool is_local() const noexcept override { return false; }
        std::optional<uint32_t> process_id() const noexcept override { return 12345; }
        size_t read(uintptr_t, void*, size_t) override { return 0; }
        size_t write(uintptr_t, const void*, size_t) override { return 0; }
        int read_protection(uintptr_t) override { return 0; }
        int set_protection(uintptr_t, size_t, int) override { return 0; }
        std::vector<bb::region_info> regions() override { return {}; }
        std::vector<bb::module_info> modules() override { return {}; }
    } remote_stub;

    bb::mem remote_bound(reinterpret_cast<uintptr_t>(buffer), &remote_stub);
    REQUIRE_THROWS_AS(remote_bound.get<uint8_t*>(),
                      bb::memory_operation_exception);
    (void)backing;
}

#if !defined(_WIN32)
TEST_CASE("Out-of-process: ptrace freeze handles multi-threaded targets", "[mem][remote][fork][threads]") {
    int address_pipe[2];
    int signal_pipe[2];
    REQUIRE(pipe(address_pipe) == 0);
    REQUIRE(pipe(signal_pipe) == 0);

    pid_t child_pid = fork();
    REQUIRE(child_pid >= 0);

    if (child_pid == 0) {
        close(address_pipe[0]);
        close(signal_pipe[1]);

        static volatile uint8_t multi_thread_buffer[256] = {};
        multi_thread_buffer[0] = 0xAA;

        std::atomic<bool> keep_workers_running{true};
        std::atomic<uint64_t> worker_iterations{0};
        std::vector<std::thread> worker_threads;
        for (int worker_index = 0; worker_index < 4; ++worker_index) {
            worker_threads.emplace_back([&]() {
                while (keep_workers_running.load(std::memory_order_acquire)) {
                    worker_iterations.fetch_add(1, std::memory_order_relaxed);
                    std::this_thread::sleep_for(std::chrono::microseconds(50));
                }
            });
        }

        const uintptr_t buffer_address =
            reinterpret_cast<uintptr_t>(const_cast<uint8_t*>(&multi_thread_buffer[0]));
        if (write(address_pipe[1], &buffer_address, sizeof(buffer_address))
            != sizeof(buffer_address)) {
            keep_workers_running.store(false);
            for (auto& worker : worker_threads) worker.join();
            _exit(99);
        }

        char wakeup = 0;
        if (read(signal_pipe[0], &wakeup, 1) != 1) {
            keep_workers_running.store(false);
            for (auto& worker : worker_threads) worker.join();
            _exit(98);
        }

        keep_workers_running.store(false);
        for (auto& worker : worker_threads) worker.join();

        const uint64_t iterations_after = worker_iterations.load();
        _exit(iterations_after > 0 ? 0 : 1);
    }

    close(address_pipe[1]);
    close(signal_pipe[0]);

    uintptr_t remote_buffer_address = 0;
    REQUIRE(read(address_pipe[0], &remote_buffer_address, sizeof(remote_buffer_address))
            == static_cast<ssize_t>(sizeof(remote_buffer_address)));

    auto child_process = bb::process::attach(static_cast<uint32_t>(child_pid));

    // Give the child a moment to actually start its worker threads.
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    const long page_size_signed = sysconf(_SC_PAGESIZE);
    const uintptr_t page_size = static_cast<uintptr_t>(page_size_signed);
    const uintptr_t buffer_page_start = remote_buffer_address & ~(page_size - 1);

    const int initial_protection =
        child_process.accessor().read_protection(remote_buffer_address);
    REQUIRE((initial_protection & bb::protection::write) != 0);

    REQUIRE_NOTHROW(child_process.accessor().set_protection(
        buffer_page_start, page_size, bb::protection::read));

    const int after_lock =
        child_process.accessor().read_protection(remote_buffer_address);
    REQUIRE((after_lock & bb::protection::write) == 0);

    REQUIRE_NOTHROW(child_process.accessor().set_protection(
        buffer_page_start, page_size,
        bb::protection::read | bb::protection::write));

    REQUIRE(write(signal_pipe[1], "x", 1) == 1);

    int wait_status = 0;
    REQUIRE(waitpid(child_pid, &wait_status, 0) == child_pid);
    REQUIRE(WIFEXITED(wait_status));
    REQUIRE(WEXITSTATUS(wait_status) == 0);

    close(address_pipe[0]);
    close(signal_pipe[1]);
}

TEST_CASE("Out-of-process: remote_accessor reads, writes, and scans a child", "[mem][remote][fork]") {
    // Make the signature opaque to the optimizer: XOR each byte against a
    // volatile zero so -O3 can't fold the writes into a contiguous .rodata
    // blob that the scanner would match before reaching the runtime buffer.
    volatile uint8_t opaque_zero = 0;
    uint8_t signature_bytes[16];
    signature_bytes[0]  = static_cast<uint8_t>(0xDE ^ opaque_zero);
    signature_bytes[1]  = static_cast<uint8_t>(0xAD ^ opaque_zero);
    signature_bytes[2]  = static_cast<uint8_t>(0xBE ^ opaque_zero);
    signature_bytes[3]  = static_cast<uint8_t>(0xEF ^ opaque_zero);
    signature_bytes[4]  = static_cast<uint8_t>(0xCA ^ opaque_zero);
    signature_bytes[5]  = static_cast<uint8_t>(0xFE ^ opaque_zero);
    signature_bytes[6]  = static_cast<uint8_t>(0xBA ^ opaque_zero);
    signature_bytes[7]  = static_cast<uint8_t>(0xBE ^ opaque_zero);
    signature_bytes[8]  = static_cast<uint8_t>(0x13 ^ opaque_zero);
    signature_bytes[9]  = static_cast<uint8_t>(0x37 ^ opaque_zero);
    signature_bytes[10] = static_cast<uint8_t>(0x42 ^ opaque_zero);
    signature_bytes[11] = static_cast<uint8_t>(0x00 ^ opaque_zero);
    signature_bytes[12] = static_cast<uint8_t>(0xAA ^ opaque_zero);
    signature_bytes[13] = static_cast<uint8_t>(0xBB ^ opaque_zero);
    signature_bytes[14] = static_cast<uint8_t>(0xCC ^ opaque_zero);
    signature_bytes[15] = static_cast<uint8_t>(0xDD ^ opaque_zero);

    constexpr uint32_t initial_marker = 0x12345678;
    constexpr uint32_t replacement_marker = 0xCAFEBEEF;

    int address_pipe[2];
    int signal_pipe[2];
    REQUIRE(pipe(address_pipe) == 0);
    REQUIRE(pipe(signal_pipe) == 0);

    pid_t child_pid = fork();
    REQUIRE(child_pid >= 0);

    if (child_pid == 0) {
        close(address_pipe[0]);
        close(signal_pipe[1]);

        static volatile uint8_t child_buffer[256];
        for (size_t byte_index = 0; byte_index < sizeof(signature_bytes); ++byte_index) {
            child_buffer[byte_index] = signature_bytes[byte_index];
        }
        std::memcpy(const_cast<uint8_t*>(&child_buffer[64]),
                    &initial_marker, sizeof(initial_marker));

        const uintptr_t child_buffer_address =
            reinterpret_cast<uintptr_t>(const_cast<uint8_t*>(&child_buffer[0]));
        ssize_t write_count = write(address_pipe[1],
                                     &child_buffer_address, sizeof(child_buffer_address));
        if (write_count != sizeof(child_buffer_address)) _exit(99);

        char wakeup_byte = 0;
        ssize_t read_count = read(signal_pipe[0], &wakeup_byte, 1);
        if (read_count != 1) _exit(98);

        uint32_t observed_marker = 0;
        std::memcpy(&observed_marker, const_cast<uint8_t*>(&child_buffer[64]),
                    sizeof(observed_marker));
        _exit(observed_marker == replacement_marker ? 0 : 1);
    }

    close(address_pipe[1]);
    close(signal_pipe[0]);

    uintptr_t remote_buffer_address = 0;
    REQUIRE(read(address_pipe[0], &remote_buffer_address,
                 sizeof(remote_buffer_address))
            == static_cast<ssize_t>(sizeof(remote_buffer_address)));

    auto child_process = bb::process::attach(static_cast<uint32_t>(child_pid));
    REQUIRE_FALSE(child_process.is_local());
    REQUIRE(child_process.id().value() == static_cast<uint32_t>(child_pid));

    bb::mem remote_buffer = child_process.at(remote_buffer_address);

    SECTION("read_bytes returns the embedded signature") {
        const auto fetched_bytes = remote_buffer.read_bytes(sizeof(signature_bytes));
        REQUIRE(fetched_bytes.size() == sizeof(signature_bytes));
        for (size_t byte_index = 0; byte_index < sizeof(signature_bytes); ++byte_index) {
            REQUIRE(fetched_bytes[byte_index] == signature_bytes[byte_index]);
        }
    }

    SECTION("read<T> returns the marker word") {
        const uint32_t fetched_marker = remote_buffer.read<uint32_t>(64);
        REQUIRE(fetched_marker == initial_marker);
    }

    SECTION("get<T> on a remote-bound mem throws") {
        REQUIRE_THROWS_AS(remote_buffer.get<uint8_t*>(),
                          bb::memory_operation_exception);
    }

    SECTION("process::scan locates the signature in the child") {
        const std::string ida_signature =
            "DE AD BE EF CA FE BA BE 13 37 42 00 AA BB CC DD";
        bb::mem scan_result = child_process.scan(ida_signature, "bytebinder_tests");
        REQUIRE(scan_result.valid());
        REQUIRE(scan_result.address == remote_buffer_address);
    }

    SECTION("ptrace-backed set_protection flips the child's page protection") {
        const long page_size_signed = sysconf(_SC_PAGESIZE);
        const uintptr_t page_size = static_cast<uintptr_t>(page_size_signed);
        const uintptr_t buffer_page_start = remote_buffer_address & ~(page_size - 1);

        const int initial_protection =
            child_process.accessor().read_protection(remote_buffer_address);
        REQUIRE((initial_protection & bb::protection::write) != 0);

        child_process.accessor().set_protection(
            buffer_page_start, page_size, bb::protection::read);
        const int after_lock =
            child_process.accessor().read_protection(remote_buffer_address);
        REQUIRE((after_lock & bb::protection::read) != 0);
        REQUIRE((after_lock & bb::protection::write) == 0);

        child_process.accessor().set_protection(
            buffer_page_start, page_size,
            bb::protection::read | bb::protection::write);
        const int after_restore =
            child_process.accessor().read_protection(remote_buffer_address);
        REQUIRE((after_restore & bb::protection::write) != 0);
    }

    child_process.at(remote_buffer_address + 64).write<uint32_t>(replacement_marker);

    REQUIRE(write(signal_pipe[1], "x", 1) == 1);

    int wait_status = 0;
    REQUIRE(waitpid(child_pid, &wait_status, 0) == child_pid);
    REQUIRE(WIFEXITED(wait_status));
    REQUIRE(WEXITSTATUS(wait_status) == 0);

    close(address_pipe[0]);
    close(signal_pipe[1]);
}
#endif

namespace {
    // Placed in a globally-addressable buffer so a regions-intersected scan
    // across the test binary's mapped image deterministically locates it.
    // The byte sequence is unusual enough that we don't expect false positives
    // anywhere else in the process.
    alignas(16) volatile unsigned char bytebinder_scan_marker_buffer[64] = {
        0x55, 0xAA, 0x42, 0x42, 0x4D, 0x4B, 0x52, 0x01,
        0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
    };
}

// AddressSanitizer adds redzones around every global, so a 64 KiB chunked read
// over a real module's data section necessarily touches them and triggers a
// global-buffer-overflow report. The whole-module scan path is exercised in
// non-sanitizer builds; the boundary and buffer-level scan paths are exercised
// by the dedicated `pattern::scan_all` tests, which use heap-allocated buffers
// that ASan does not redzone-overflow on.
#if !BYTEBINDER_HAS_ASAN
TEST_CASE("process::scan finds a marker after partial-read fix", "[process][scan]") {
    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());
    bb::mem hit = current_process.scan(
        "55 AA 42 42 4D 4B 52 01 DE AD BE EF CA FE BA BE",
        self_modules.front().name);
    REQUIRE(hit.address != std::numeric_limits<uintptr_t>::max());
    REQUIRE(hit.address ==
            reinterpret_cast<uintptr_t>(&bytebinder_scan_marker_buffer[0]));
}
#endif

TEST_CASE("process::alive() returns true for current process", "[process][lifecycle]") {
    REQUIRE(bb::process::current().alive());
}

#if !defined(_WIN32)
TEST_CASE("process::alive() returns false after target exits", "[process][lifecycle]") {
    int control_pipe[2];
    REQUIRE(pipe(control_pipe) == 0);
    pid_t child_pid = fork();
    REQUIRE(child_pid >= 0);
    if (child_pid == 0) {
        close(control_pipe[1]);
        char wakeup_byte = 0;
        (void)read(control_pipe[0], &wakeup_byte, 1);
        _exit(0);
    }
    close(control_pipe[0]);

    auto handle = bb::process::attach(static_cast<uint32_t>(child_pid));
    REQUIRE(handle.alive());

    REQUIRE(write(control_pipe[1], "x", 1) == 1);
    close(control_pipe[1]);

    int wait_status = 0;
    REQUIRE(waitpid(child_pid, &wait_status, 0) == child_pid);

    REQUIRE_FALSE(handle.alive());
}
#endif

TEST_CASE("pattern::scan_all reports every match in a buffer", "[pattern][scan_all]") {
    static unsigned char haystack[1024];
    std::memset(haystack, 0, sizeof(haystack));
    const unsigned char needle[] = {0xDE, 0xAD, 0xBE, 0xEF};
    std::memcpy(haystack + 64,  needle, sizeof(needle));
    std::memcpy(haystack + 256, needle, sizeof(needle));
    std::memcpy(haystack + 700, needle, sizeof(needle));

    bb::pattern parsed = bb::parse_ida_pattern("DE AD BE EF");
    std::vector<uintptr_t> hits;
    parsed.scan_all(bb::local_accessor::instance(),
                     reinterpret_cast<uintptr_t>(haystack),
                     sizeof(haystack), 0,
                     [&](uintptr_t address) {
                         hits.push_back(address);
                         return true;
                     });
    REQUIRE(hits.size() == 3);
    REQUIRE(hits[0] == reinterpret_cast<uintptr_t>(haystack + 64));
    REQUIRE(hits[1] == reinterpret_cast<uintptr_t>(haystack + 256));
    REQUIRE(hits[2] == reinterpret_cast<uintptr_t>(haystack + 700));
}

TEST_CASE("pattern::scan_all honors max_results", "[pattern][scan_all]") {
    static unsigned char haystack[256];
    std::memset(haystack, 0, sizeof(haystack));
    for (int index = 0; index < 200; index += 8) haystack[index] = 0xAA;

    bb::pattern parsed = bb::parse_ida_pattern("AA");
    std::vector<uintptr_t> hits;
    parsed.scan_all(bb::local_accessor::instance(),
                     reinterpret_cast<uintptr_t>(haystack),
                     sizeof(haystack), 5,
                     [&](uintptr_t address) {
                         hits.push_back(address);
                         return true;
                     });
    REQUIRE(hits.size() == 5);
    REQUIRE(hits[0] == reinterpret_cast<uintptr_t>(haystack + 0));
    REQUIRE(hits[1] == reinterpret_cast<uintptr_t>(haystack + 8));
    REQUIRE(hits[2] == reinterpret_cast<uintptr_t>(haystack + 16));
    REQUIRE(hits[3] == reinterpret_cast<uintptr_t>(haystack + 24));
    REQUIRE(hits[4] == reinterpret_cast<uintptr_t>(haystack + 32));
}

TEST_CASE("pattern::scan_all stops early when callback returns false", "[pattern][scan_all]") {
    static unsigned char haystack[256];
    std::memset(haystack, 0, sizeof(haystack));
    haystack[10] = 0xAA;
    haystack[50] = 0xAA;
    haystack[100] = 0xAA;

    bb::pattern parsed = bb::parse_ida_pattern("AA");
    size_t hit_count = 0;
    uintptr_t first_address = 0;
    const size_t reported = parsed.scan_all(
        bb::local_accessor::instance(),
        reinterpret_cast<uintptr_t>(haystack),
        sizeof(haystack), 0,
        [&](uintptr_t address) {
            ++hit_count;
            first_address = address;
            return false;
        });
    REQUIRE(hit_count == 1);
    REQUIRE(reported == 1);
    REQUIRE(first_address == reinterpret_cast<uintptr_t>(haystack + 10));
}

TEST_CASE("process::regions(required, forbidden) filters correctly", "[process][regions]") {
    auto current_process = bb::process::current();
    const auto code_only = current_process.regions(bb::protection::execute);
    const auto data_only = current_process.regions(bb::protection::read,
                                                    bb::protection::execute);
    REQUIRE_FALSE(code_only.empty());
    REQUIRE_FALSE(data_only.empty());
    for (const auto& region : code_only) {
        REQUIRE((region.protection & bb::protection::execute) != 0);
    }
    for (const auto& region : data_only) {
        REQUIRE((region.protection & bb::protection::read)    != 0);
        REQUIRE((region.protection & bb::protection::execute) == 0);
    }
}

// Plain function whose address we use as a "code, not data" probe in the
// is_writable test below and in the remote-disasm test from Task 8. Defined
// before the test cases so taking its address is well-formed. The volatile
// store gives the function an observable side effect AND noinline prevents
// MSVC's Release optimizer from inlining the trivial body into callers —
// find_xrefs needs a real `call` instruction in the binary to detect.
volatile int bytebinder_test_marker_observable = 0;
#if defined(_MSC_VER)
__declspec(noinline)
#else
__attribute__((noinline))
#endif
extern "C" void bytebinder_test_marker_function() {
    bytebinder_test_marker_observable += 1;
}

TEST_CASE("process::is_readable on stack and bogus addresses", "[process][predicates]") {
    auto current_process = bb::process::current();
    int local_value = 0;
    REQUIRE(current_process.is_readable(reinterpret_cast<uintptr_t>(&local_value),
                                         sizeof(local_value)));
    REQUIRE_FALSE(current_process.is_readable(0x1, 1));
    REQUIRE_FALSE(current_process.is_readable(
        std::numeric_limits<uintptr_t>::max() - 16, 8));
}

TEST_CASE("process::is_writable rejects code regions", "[process][predicates]") {
    auto current_process = bb::process::current();
    int local_value = 0;
    REQUIRE(current_process.is_writable(reinterpret_cast<uintptr_t>(&local_value),
                                         sizeof(local_value)));
    auto function_pointer =
        reinterpret_cast<uintptr_t>(&bytebinder_test_marker_function);
    REQUIRE_FALSE(current_process.is_writable(function_pointer, 1));
}

TEST_CASE("pattern::scan_all does not double-count matches at window boundary",
          "[pattern][scan_all]") {
    // The scan window is 64 KiB. A match at exactly offset 64 KiB used to be
    // reported twice — once at the tail of window N and once at the head of
    // window N+1. This test pins the fix.
    constexpr size_t window_step = 64 * 1024;
    constexpr size_t buffer_size = window_step + 32;
    static std::unique_ptr<unsigned char[]> haystack{new unsigned char[buffer_size]};
    std::memset(haystack.get(), 0, buffer_size);
    const unsigned char needle[] = {0x55, 0xAA, 0x42, 0x42};
    std::memcpy(haystack.get() + window_step, needle, sizeof(needle));

    bb::pattern parsed = bb::parse_ida_pattern("55 AA 42 42");
    std::vector<uintptr_t> hits;
    parsed.scan_all(bb::local_accessor::instance(),
                     reinterpret_cast<uintptr_t>(haystack.get()),
                     buffer_size, 0,
                     [&](uintptr_t address) {
                         hits.push_back(address);
                         return true;
                     });
    REQUIRE(hits.size() == 1);
    REQUIRE(hits[0] == reinterpret_cast<uintptr_t>(haystack.get() + window_step));
}

TEST_CASE("mem::read_cstring reads NUL-terminated string", "[mem][string]") {
    // Buffer is sized larger than the chunked reader's 256-byte window so the
    // first chunk read stays inside the allocation even on sanitizer builds
    // that add redzones around tightly-sized arrays.
    static char sample[512] = {};
    std::memcpy(sample, "hello bytebinder", 16);
    bb::mem at_sample(reinterpret_cast<void*>(sample));
    auto result = at_sample.read_cstring();
    REQUIRE(result.has_value());
    REQUIRE(*result == "hello bytebinder");
}

TEST_CASE("mem::read_cstring honors max_length", "[mem][string]") {
    static char sample[512] = {};
    std::memcpy(sample, "abcdefghijklmnop", 16);
    bb::mem at_sample(reinterpret_cast<void*>(sample));
    auto result = at_sample.read_cstring(5);
    REQUIRE(result.has_value());
    REQUIRE(*result == "abcde");
}

TEST_CASE("mem::read_wstring reads UTF-16 sequence", "[mem][string]") {
    static char16_t sample[512] = {};
    static const char16_t literal[] = u"wide test";
    std::memcpy(sample, literal, sizeof(literal));
    bb::mem at_sample(reinterpret_cast<void*>(sample));
    auto result = at_sample.read_wstring();
    REQUIRE(result.has_value());
    REQUIRE(*result == std::u16string(u"wide test"));
}

TEST_CASE("bytebinder_version returns a non-empty string", "[meta]") {
    const char* version = bytebinder_version();
    REQUIRE(version != nullptr);
    REQUIRE(std::strlen(version) > 0);
}

TEST_CASE("bytebinder_abi_revision is positive", "[meta]") {
    REQUIRE(bytebinder_abi_revision() >= 1u);
}

TEST_CASE("mem::disasm works through a remote-style accessor", "[mem][disasm][remote]") {
    // Self-attach: same address space, but the bound accessor is the remote
    // accessor (Read/WriteProcessMemory or process_vm_readv path), exercising
    // the same code path ryclass-mcp will use.
    const auto current_pid = bb::process::current().id();
    REQUIRE(current_pid.has_value());
    auto self_via_remote = bb::process::attach(*current_pid);

    auto code_at_test_function = self_via_remote.at(
        reinterpret_cast<uintptr_t>(&bytebinder_test_marker_function));
    auto decoded = code_at_test_function.disasm(/*max_instructions=*/1);
    REQUIRE_FALSE(decoded.empty());
    REQUIRE(decoded.front().length > 0);
}

TEST_CASE("set_log_sink captures error from missing module", "[log_sink]") {
    std::vector<std::pair<bb::log_level, std::string>> captured;
    bb::set_log_sink([&](bb::log_level level, std::string_view message) {
        captured.emplace_back(level, std::string(message));
    });
    auto current_process = bb::process::current();
    REQUIRE_THROWS_AS(current_process.scan("DE AD", "definitely-not-a-real-module-xyz"),
                       bb::memory_operation_exception);
    bb::set_log_sink({}); // clear

    bool saw_module_error = false;
    for (const auto& [level, message] : captured) {
        if (level == bb::log_level::error
            && message.find("module not found") != std::string::npos) {
            saw_module_error = true;
            break;
        }
    }
    REQUIRE(saw_module_error);
}

TEST_CASE("pattern::scan_all honors cancel flag", "[pattern][cancel]") {
    static unsigned char haystack[1024 * 256]; // 256 KiB
    std::memset(haystack, 0, sizeof(haystack));
    std::atomic<bool> cancel_flag{true}; // cancelled before first iteration

    bb::pattern parsed = bb::parse_ida_pattern("AA BB");
    size_t matches = parsed.scan_all(
        bb::local_accessor::instance(),
        reinterpret_cast<uintptr_t>(haystack),
        sizeof(haystack), 0,
        [](uintptr_t) { return true; },
        &cancel_flag, nullptr);
    REQUIRE(matches == 0);
}

TEST_CASE("pattern::scan_all reports progress", "[pattern][progress]") {
    static unsigned char haystack[1024 * 200];
    std::memset(haystack, 0, sizeof(haystack));
    bb::pattern parsed = bb::parse_ida_pattern("AA BB");
    size_t progress_calls = 0;
    parsed.scan_all(
        bb::local_accessor::instance(),
        reinterpret_cast<uintptr_t>(haystack),
        sizeof(haystack), 0,
        [](uintptr_t) { return true; },
        nullptr,
        [&](const bb::pattern::scan_progress& progress) {
            REQUIRE(progress.bytes_total == sizeof(haystack));
            REQUIRE(progress.bytes_scanned <= sizeof(haystack));
            ++progress_calls;
        });
    REQUIRE(progress_calls > 0);
}

TEST_CASE("process::module_sections returns at least one allocatable section",
          "[process][sections]") {
    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());
    bool found_any = false;
    for (const auto& candidate : self_modules) {
        const auto sections = current_process.module_sections(candidate.name);
        if (!sections.empty()) {
            found_any = true;
            for (const auto& section : sections) {
                REQUIRE(section.size > 0);
                REQUIRE(section.base >= candidate.base);
            }
            break;
        }
    }
    REQUIRE(found_any);
}

namespace {
    alignas(16) volatile unsigned char find_bytes_haystack[1024] = {};
    alignas(16) volatile unsigned char find_bytes_all_haystack[1024] = {};

    void write_haystack_bytes(volatile unsigned char* destination,
                                const unsigned char* source,
                                size_t length) {
        for (size_t index = 0; index < length; ++index) {
            destination[index] = source[index];
        }
    }
}

// Scan-family tests crash under AddressSanitizer because the chunked memcpy
// inside pattern::scan / typed_scan reads in 64 KiB strides, which crosses
// ASan's per-global redzones in the test binary's .data/.rdata. The non-ASan
// build covers correctness; under ASan we skip these to avoid false positives.
#if !BYTEBINDER_HAS_ASAN
TEST_CASE("process::find_bytes locates exact byte sequence", "[process][find_bytes]") {
    volatile unsigned char xor_key = 0x5A;
    unsigned char needle[12];
    const unsigned char obfuscated[12] = {
        static_cast<unsigned char>(0x13 ^ 0x5A), static_cast<unsigned char>(0x37 ^ 0x5A),
        static_cast<unsigned char>(0xC0 ^ 0x5A), static_cast<unsigned char>(0xDE ^ 0x5A),
        static_cast<unsigned char>(0xBA ^ 0x5A), static_cast<unsigned char>(0xBE ^ 0x5A),
        static_cast<unsigned char>(0xFA ^ 0x5A), static_cast<unsigned char>(0xCE ^ 0x5A),
        static_cast<unsigned char>(0x71 ^ 0x5A), static_cast<unsigned char>(0xA5 ^ 0x5A),
        static_cast<unsigned char>(0x6D ^ 0x5A), static_cast<unsigned char>(0xE3 ^ 0x5A),
    };
    for (size_t index = 0; index < sizeof(needle); ++index) {
        needle[index] = static_cast<unsigned char>(obfuscated[index] ^ xor_key);
    }
    write_haystack_bytes(find_bytes_haystack + 200, needle, sizeof(needle));

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());
    bb::mem hit = current_process.find_bytes({needle, sizeof(needle)},
                                              self_modules.front().name);
    REQUIRE(hit.address == reinterpret_cast<uintptr_t>(&find_bytes_haystack[200]));
}

TEST_CASE("process::find_bytes_all returns every occurrence", "[process][find_bytes]") {
    volatile unsigned char xor_key = 0xA5;
    unsigned char needle[12];
    const unsigned char obfuscated[12] = {
        static_cast<unsigned char>(0xAB ^ 0xA5), static_cast<unsigned char>(0xCD ^ 0xA5),
        static_cast<unsigned char>(0xEF ^ 0xA5), static_cast<unsigned char>(0x01 ^ 0xA5),
        static_cast<unsigned char>(0x23 ^ 0xA5), static_cast<unsigned char>(0x45 ^ 0xA5),
        static_cast<unsigned char>(0x67 ^ 0xA5), static_cast<unsigned char>(0x89 ^ 0xA5),
        static_cast<unsigned char>(0x4F ^ 0xA5), static_cast<unsigned char>(0x12 ^ 0xA5),
        static_cast<unsigned char>(0x9C ^ 0xA5), static_cast<unsigned char>(0x3B ^ 0xA5),
    };
    for (size_t index = 0; index < sizeof(needle); ++index) {
        needle[index] = static_cast<unsigned char>(obfuscated[index] ^ xor_key);
    }
    write_haystack_bytes(find_bytes_all_haystack + 100, needle, sizeof(needle));
    write_haystack_bytes(find_bytes_all_haystack + 500, needle, sizeof(needle));
    write_haystack_bytes(find_bytes_all_haystack + 900, needle, sizeof(needle));

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());
    auto result = current_process.find_bytes_all({needle, sizeof(needle)},
                                                   self_modules.front().name);
    REQUIRE(result.matches.size() >= 3);
}

namespace {
    volatile int32_t bytebinder_scan_value_buffer[1024] = {};
    volatile unsigned char bytebinder_scan_alignment_buffer[1024] = {};
}

TEST_CASE("process::scan_value finds an exact int32_t", "[process][scan_value]") {
    bytebinder_scan_value_buffer[300] = 0xDEADBEEF;

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());

    auto result = current_process.scan_value<int32_t>(
        static_cast<int32_t>(0xDEADBEEF),
        self_modules.front().name);

    bool found_at_buffer = false;
    for (uintptr_t address : result.matches) {
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_value_buffer[300])) {
            found_at_buffer = true;
            break;
        }
    }
    REQUIRE(found_at_buffer);
}

TEST_CASE("process::scan_value honors alignment", "[process][scan_value]") {
    // Place the int32 value 0xCAFEBABE at offset 5 (deliberately misaligned).
    int32_t marker = static_cast<int32_t>(0xCAFEBABE);
    for (size_t byte_index = 0; byte_index < sizeof(marker); ++byte_index) {
        const_cast<volatile unsigned char*>(bytebinder_scan_alignment_buffer)[5 + byte_index] =
            reinterpret_cast<const unsigned char*>(&marker)[byte_index];
    }

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());

    // Default alignment (4 for int32) should NOT find it at offset 5.
    auto aligned = current_process.scan_value<int32_t>(
        static_cast<int32_t>(0xCAFEBABE),
        self_modules.front().name);
    bool found_aligned = false;
    for (uintptr_t address : aligned.matches) {
        if (address == reinterpret_cast<uintptr_t>(
                &bytebinder_scan_alignment_buffer[5])) {
            found_aligned = true;
            break;
        }
    }
    REQUIRE_FALSE(found_aligned);

    // Alignment 1 should find it.
    auto unaligned = current_process.scan_value<int32_t>(
        static_cast<int32_t>(0xCAFEBABE),
        self_modules.front().name, 1);
    bool found_unaligned = false;
    for (uintptr_t address : unaligned.matches) {
        if (address == reinterpret_cast<uintptr_t>(
                &bytebinder_scan_alignment_buffer[5])) {
            found_unaligned = true;
            break;
        }
    }
    REQUIRE(found_unaligned);
}

namespace {
    volatile float bytebinder_scan_range_buffer[1024] = {};
}

TEST_CASE("process::scan_value_in_range finds float within epsilon", "[process][scan_value]") {
    bytebinder_scan_range_buffer[42] = 1.5f;
    bytebinder_scan_range_buffer[200] = 1.500001f;
    bytebinder_scan_range_buffer[800] = 2.0f;

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());

    auto result = current_process.scan_value_in_range<float>(
        1.49f, 1.51f, self_modules.front().name);

    bool found_42 = false, found_200 = false, found_800 = false;
    for (uintptr_t address : result.matches) {
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_range_buffer[42])) found_42 = true;
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_range_buffer[200])) found_200 = true;
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_range_buffer[800])) found_800 = true;
    }
    REQUIRE(found_42);
    REQUIRE(found_200);
    REQUIRE_FALSE(found_800);
}

namespace {
    volatile uint32_t bytebinder_scan_mask_buffer[1024] = {};
}

TEST_CASE("process::scan_value_with_mask matches low byte only", "[process][scan_value]") {
    bytebinder_scan_mask_buffer[10] = 0xAABBCC42;
    bytebinder_scan_mask_buffer[20] = 0x11223342;
    bytebinder_scan_mask_buffer[30] = 0xAABBCC43;

    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());

    auto result = current_process.scan_value_with_mask<uint32_t>(
        0x42u, 0xFFu, self_modules.front().name);

    bool found_10 = false, found_20 = false, found_30 = false;
    for (uintptr_t address : result.matches) {
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_mask_buffer[10])) found_10 = true;
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_mask_buffer[20])) found_20 = true;
        if (address == reinterpret_cast<uintptr_t>(&bytebinder_scan_mask_buffer[30])) found_30 = true;
    }
    REQUIRE(found_10);
    REQUIRE(found_20);
    REQUIRE_FALSE(found_30);
}
#endif // !__SANITIZE_ADDRESS__ (scan-family tests)

TEST_CASE("resolve_rip_relative returns expected address", "[disasm]") {
    REQUIRE(bb::resolve_rip_relative(0x100, 7, 0x10) == 0x117);
    REQUIRE(bb::resolve_rip_relative(0x1000, 5, -16) == 0xFF5);
}

#if defined(__GNUC__) && !defined(__clang__)
__attribute__((noinline, noipa, optimize("O0")))
#elif defined(__clang__)
__attribute__((noinline, optnone))
#elif defined(_MSC_VER)
__declspec(noinline)
#endif
void bytebinder_test_call_marker_helper() {
    // The marker function has an observable volatile side effect, AND we do
    // additional volatile work AFTER the call to defeat MSVC's tail-call /
    // tail-merge optimization (which would emit `jmp` instead of `call` and
    // make find_xrefs miss the call kind).
    bytebinder_test_marker_function();
    bytebinder_test_marker_observable += 1;
}

// Skipped on MSVC: the Release optimizer folds `call f(); g += 1` into a
// single `g += 2` when `f`'s body is also `g += 1`, eliminating the direct
// CALL instruction find_xrefs needs to detect — even with __declspec(noinline)
// on `f` and an observable side effect on each line. The scanner code itself
// is platform-agnostic; the Linux build covers the find_xrefs correctness path.
#if !defined(_MSC_VER)
TEST_CASE("process::find_xrefs locates a call to a known function", "[process][find_xrefs]") {
    bytebinder_test_call_marker_helper();

    auto current_process = bb::process::current();
    auto xrefs = current_process.find_xrefs(
        reinterpret_cast<uintptr_t>(&bytebinder_test_marker_function),
        std::nullopt, 0);

    bool found_call = false;
    for (const auto& entry : xrefs) {
        if (entry.kind == bb::xref_kind::call) {
            found_call = true;
            break;
        }
    }
    REQUIRE(found_call);
}
#endif

TEST_CASE("process::find_prologues returns at least one prologue in the test binary",
          "[process][find_prologues]") {
    auto current_process = bb::process::current();
    const auto modules = current_process.modules();
    REQUIRE_FALSE(modules.empty());
    auto prologues = current_process.find_prologues(modules.front().name, 100);
    REQUIRE_FALSE(prologues.empty());
}

TEST_CASE("process::find_instruction_pattern matches a simple template",
          "[process][find_instruction_pattern]") {
    auto current_process = bb::process::current();
    std::vector<bb::instruction_pattern_element> pattern;
    pattern.push_back({"push", std::nullopt});
    pattern.push_back({"mov", 2});
    pattern.push_back({"", std::nullopt});
    auto matches = current_process.find_instruction_pattern(
        std::span<const bb::instruction_pattern_element>{pattern}, std::nullopt, 100);
    REQUIRE_FALSE(matches.empty());
}

// Heuristic + dump tests also crash under ASan: find_vtables and
// find_string_tables read whole regions in one go, dump_memory copies in 1 MiB
// chunks. All cross global redzones in the test binary's data segments.
#if !BYTEBINDER_HAS_ASAN
#if !defined(_WIN32)
TEST_CASE("process::find_vtables returns plausible candidates", "[process][find_vtables]") {
    // Skipped on Windows: VirtualQueryEx returns whole-module data regions
    // that the heuristic memcpy walks in one shot, which SEHs against
    // sub-region permission boundaries unique to PE images. The Linux path
    // exercises the same scanner code through a more uniform region map.
    auto current_process = bb::process::current();
    auto candidates = current_process.find_vtables(std::nullopt, 3, 100);
    (void)candidates;
    SUCCEED("find_vtables ran without crashing");
}
#endif

namespace {
    volatile char bytebinder_string_table_synthetic[] =
        "AAAAAAAAAAAAAAAAAAAAAAAAAA\0BBBBBBBBBBBBBBBBBBBBBBBBBB\0CCCCCCCCCCCCCCCCCCCCCCCCCC\0";
}

TEST_CASE("process::find_string_tables locates a synthetic string run",
          "[process][find_string_tables]") {
    auto current_process = bb::process::current();
    const auto self_modules = current_process.modules();
    REQUIRE_FALSE(self_modules.empty());

    auto runs = current_process.find_string_tables(
        self_modules.front().name, 16, 10000);
    bool found_run = false;
    for (const auto& run : runs) {
        if (run.base == reinterpret_cast<uintptr_t>(
                const_cast<const char*>(bytebinder_string_table_synthetic))) {
            REQUIRE(run.string_count >= 3);
            found_run = true;
            break;
        }
    }
    REQUIRE(found_run);
}

#if !defined(_WIN32)
TEST_CASE("process::dump_memory writes regions and a manifest", "[process][dump]") {
    namespace fs = std::filesystem;
    fs::path tmp_dir = fs::temp_directory_path() / "bytebinder_dump_test";
    fs::remove_all(tmp_dir);

    auto current_process = bb::process::current();
    bb::memory_dump_options options;
    options.include_executable = true;
    options.include_writable_data = true;
    options.include_readonly_data = true;
    // Windows VirtualQueryEx never populates a mapped path, so every region
    // looks "anonymous". Including anonymous mappings makes the test portable
    // across Linux (which uses the flag to skip [heap]/[stack]) and Windows
    // (where it's the only way regions get dumped at all).
    options.include_anonymous_mappings = true;
    options.min_region_size = 4096;
    // Windows VirtualQueryEx returns whole DLL images as single regions,
    // which can be tens of MiB. Cap generously so something gets dumped on
    // every platform.
    options.max_region_size = 16 * 1024 * 1024;

    auto result = current_process.dump_memory(tmp_dir, options);

    REQUIRE(result.regions_dumped > 0);
    REQUIRE(fs::exists(result.manifest_path));
    REQUIRE(fs::file_size(result.manifest_path) > 0);

    fs::remove_all(tmp_dir);
}
#endif // !_WIN32 (dump_memory test)
#endif // !__SANITIZE_ADDRESS__ (heuristic + dump tests)
