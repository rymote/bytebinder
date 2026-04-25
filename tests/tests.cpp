#define CATCH_CONFIG_MAIN
#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "process.h"

#if !defined(_WIN32)
    #include <sys/wait.h>
    #include <sys/types.h>
    #include <signal.h>
    #include <unistd.h>
#endif

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