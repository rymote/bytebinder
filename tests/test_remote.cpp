#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

// Both child-process tests rely on ptrace and process_vm_readv; on macOS,
// task_for_pid on a child needs root or the debugger entitlement.
#if defined(__linux__)
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
