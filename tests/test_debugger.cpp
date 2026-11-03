#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

#if defined(_WIN32)
namespace {
    // When this test binary is launched with BYTEBINDER_WP_CHILD set, it becomes
    // a watchpoint target instead of a test run: it prints the address to watch
    // and then writes to it forever. This runs during static init, before Catch2's
    // main, so the spawned child never enters the test runner.
    struct watchpoint_child_runner {
        watchpoint_child_runner() {
            char marker[8] = {0};
            if (GetEnvironmentVariableA("BYTEBINDER_WP_CHILD", marker, sizeof(marker)) > 0) {
                static volatile uint64_t child_target = 0;
                std::printf("0x%llx\n",
                    static_cast<unsigned long long>(reinterpret_cast<uintptr_t>(
                        const_cast<uint64_t*>(&child_target))));
                std::fflush(stdout);
                for (;;) {
                    child_target = child_target + 1;
                    Sleep(1);
                }
            }
        }
    };
    const watchpoint_child_runner g_watchpoint_child_runner;
}

TEST_CASE("debugger suspends, reads registers, and resumes a thread", "[debugger]") {
    std::atomic<uint64_t> counter{0};
    std::atomic<bool> keep_running{true};
    std::thread worker([&]() {
        while (keep_running.load(std::memory_order_acquire)) {
            counter.fetch_add(1, std::memory_order_relaxed);
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
    });

    const DWORD worker_tid = GetThreadId(static_cast<HANDLE>(worker.native_handle()));
    REQUIRE(worker_tid != 0);

    bb::debugger debug_session(static_cast<uint32_t>(GetCurrentProcessId()));

    // Suspend must actually stop the counter from advancing.
    REQUIRE(debug_session.suspend_thread(worker_tid));
    const uint64_t after_suspend = counter.load();
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    REQUIRE(counter.load() == after_suspend);

    // Registers of the suspended thread must be readable and sane.
    const auto registers = debug_session.read_registers(worker_tid);
    REQUIRE(registers.has_value());
    REQUIRE(registers->instruction_pointer != 0);
    REQUIRE(registers->stack_pointer != 0);

    // Writing the same values back must succeed (round-trip, no behavior change).
    REQUIRE(debug_session.write_registers(worker_tid, *registers));

    // Resume must let it advance again.
    REQUIRE(debug_session.resume_thread(worker_tid));
    std::this_thread::sleep_for(std::chrono::milliseconds(30));
    REQUIRE(counter.load() > after_suspend);

    keep_running.store(false, std::memory_order_release);
    worker.join();
}

TEST_CASE("debugger enumerates the current process threads", "[debugger]") {
    bb::debugger debug_session(static_cast<uint32_t>(GetCurrentProcessId()));
    REQUIRE_FALSE(debug_session.threads().empty());
}

namespace {
    volatile uint64_t g_watchpoint_target = 0;
    std::atomic<int> g_watchpoint_hits{0};
    std::atomic<uint64_t> g_watchpoint_hit_address{0};

    LONG CALLBACK watchpoint_exception_handler(PEXCEPTION_POINTERS exception_pointers) {
        if (exception_pointers->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP) {
            g_watchpoint_hit_address.store(exception_pointers->ContextRecord->Rip);
            g_watchpoint_hits.fetch_add(1);
            // Disarm every slot in the faulting thread's context so the write
            // that resumes below does not retrigger the trap.
            exception_pointers->ContextRecord->Dr7 = 0;
            return EXCEPTION_CONTINUE_EXECUTION;
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // Removes the vectored handler on scope exit so a throwing REQUIRE between
    // registration and the hit assertions cannot leak a handler into later tests.
    struct scoped_vectored_handler {
        PVOID handle = AddVectoredExceptionHandler(1, watchpoint_exception_handler);
        ~scoped_vectored_handler() {
            if (handle != nullptr) RemoveVectoredExceptionHandler(handle);
        }
    };
}

TEST_CASE("debugger hardware write watchpoint traps a write", "[debugger][watchpoint]") {
    g_watchpoint_hits.store(0);
    g_watchpoint_hit_address.store(0);
    g_watchpoint_target = 0;

    scoped_vectored_handler handler;
    REQUIRE(handler.handle != nullptr);

    std::atomic<bool> worker_spinning{false};
    std::atomic<bool> start_writing{false};
    std::thread worker([&]() {
        worker_spinning.store(true, std::memory_order_release);
        while (!start_writing.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        g_watchpoint_target = 0x1234;
    });

    const DWORD worker_tid = GetThreadId(static_cast<HANDLE>(worker.native_handle()));
    REQUIRE(worker_tid != 0);
    while (!worker_spinning.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    bb::debugger debug_session(static_cast<uint32_t>(GetCurrentProcessId()));
    const bb::watchpoint point{
        reinterpret_cast<uintptr_t>(const_cast<uint64_t*>(&g_watchpoint_target)),
        8,
        bb::watchpoint_condition::write
    };
    REQUIRE(debug_session.set_watchpoint(worker_tid, 0, point));

    start_writing.store(true, std::memory_order_release);
    worker.join();

    CHECK(g_watchpoint_target == 0x1234);
    CHECK(g_watchpoint_hits.load() >= 1);
    CHECK(g_watchpoint_hit_address.load() != 0);
}

TEST_CASE("debugger clears a hardware watchpoint so a write no longer traps", "[debugger][watchpoint]") {
    g_watchpoint_hits.store(0);
    g_watchpoint_hit_address.store(0);
    g_watchpoint_target = 0;

    scoped_vectored_handler handler;
    REQUIRE(handler.handle != nullptr);

    std::atomic<bool> worker_spinning{false};
    std::atomic<bool> start_writing{false};
    std::thread worker([&]() {
        worker_spinning.store(true, std::memory_order_release);
        while (!start_writing.load(std::memory_order_acquire)) {
            std::this_thread::yield();
        }
        g_watchpoint_target = 0x5678;
    });

    const DWORD worker_tid = GetThreadId(static_cast<HANDLE>(worker.native_handle()));
    REQUIRE(worker_tid != 0);
    while (!worker_spinning.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    bb::debugger debug_session(static_cast<uint32_t>(GetCurrentProcessId()));
    const bb::watchpoint point{
        reinterpret_cast<uintptr_t>(const_cast<uint64_t*>(&g_watchpoint_target)),
        8,
        bb::watchpoint_condition::write
    };
    REQUIRE(debug_session.set_watchpoint(worker_tid, 0, point));
    REQUIRE(debug_session.clear_watchpoint(worker_tid, 0));

    start_writing.store(true, std::memory_order_release);
    worker.join();

    CHECK(g_watchpoint_target == 0x5678);
    CHECK(g_watchpoint_hits.load() == 0);
}

TEST_CASE("debugger event loop catches a watchpoint in a child process", "[debugger][watchpoint][eventloop]") {
    SECURITY_ATTRIBUTES pipe_security{sizeof(SECURITY_ATTRIBUTES), nullptr, TRUE};
    HANDLE read_pipe = nullptr;
    HANDLE write_pipe = nullptr;
    REQUIRE(CreatePipe(&read_pipe, &write_pipe, &pipe_security, 0));
    REQUIRE(SetHandleInformation(read_pipe, HANDLE_FLAG_INHERIT, 0));

    wchar_t executable_path[MAX_PATH];
    REQUIRE(GetModuleFileNameW(nullptr, executable_path, MAX_PATH) > 0);

    SetEnvironmentVariableA("BYTEBINDER_WP_CHILD", "1");

    STARTUPINFOW startup{};
    startup.cb = sizeof(startup);
    startup.dwFlags = STARTF_USESTDHANDLES;
    startup.hStdOutput = write_pipe;
    startup.hStdError = write_pipe;
    startup.hStdInput = nullptr;

    PROCESS_INFORMATION process_info{};
    const BOOL created = CreateProcessW(executable_path, nullptr, nullptr, nullptr, TRUE,
                                        0, nullptr, nullptr, &startup, &process_info);
    SetEnvironmentVariableA("BYTEBINDER_WP_CHILD", nullptr);
    CloseHandle(write_pipe);
    REQUIRE(created);

    // Read the child's reported target address (one "0x...\n" line).
    char address_text[64] = {0};
    DWORD text_length = 0;
    while (text_length < sizeof(address_text) - 1) {
        char character = 0;
        DWORD read_count = 0;
        if (!ReadFile(read_pipe, &character, 1, &read_count, nullptr) || read_count == 0) break;
        if (character == '\n') break;
        address_text[text_length++] = character;
    }
    CloseHandle(read_pipe);
    const uintptr_t target_address = static_cast<uintptr_t>(std::strtoull(address_text, nullptr, 16));

    bool caught = false;
    int hit_slot = -1;
    uint64_t hit_instruction_pointer = 0;

    if (target_address != 0) {
        bb::debugger debug_session(static_cast<uint32_t>(process_info.dwProcessId));
        const bool attached = debug_session.attach();
        CHECK(attached);

        if (attached) {
            bool armed = false;
            for (int iteration = 0; iteration < 200 && !caught; ++iteration) {
                const auto event = debug_session.wait_for_event(3000);
                if (!event.has_value()) break;

                if (!armed && (event->kind == bb::debug_event_kind::process_created
                               || event->kind == bb::debug_event_kind::thread_created)) {
                    const bb::watchpoint point{target_address, 8, bb::watchpoint_condition::write};
                    for (const auto& thread : debug_session.threads()) {
                        debug_session.set_watchpoint(thread.thread_id, 0, point);
                    }
                    armed = true;
                }

                if (event->kind == bb::debug_event_kind::watchpoint_hit) {
                    caught = true;
                    hit_slot = event->watchpoint_slot;
                    hit_instruction_pointer = event->registers.instruction_pointer;
                    break;
                }

                if (event->kind == bb::debug_event_kind::process_exited) break;
                debug_session.continue_event(*event, true);
            }
            debug_session.detach();
        }
    }

    TerminateProcess(process_info.hProcess, 0);
    WaitForSingleObject(process_info.hProcess, 2000);
    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);

    CHECK(target_address != 0);
    CHECK(caught);
    CHECK(hit_slot == 0);
    CHECK(hit_instruction_pointer != 0);
}
#endif

#if defined(__linux__)
TEST_CASE("debugger attaches to a child and reads its registers", "[debugger][fork]") {
    pid_t child_pid = fork();
    REQUIRE(child_pid >= 0);

    if (child_pid == 0) {
        volatile uint64_t spin = 0;
        for (;;) {
            spin = spin + 1;
            struct timespec nap{0, 1000000};
            nanosleep(&nap, nullptr);
        }
        _exit(0);
    }

    bb::debugger debug_session(static_cast<uint32_t>(child_pid));

    REQUIRE(debug_session.suspend_thread(static_cast<uint64_t>(child_pid)));
    const auto registers = debug_session.read_registers(static_cast<uint64_t>(child_pid));
    REQUIRE(registers.has_value());
    REQUIRE(registers->instruction_pointer != 0);
    REQUIRE(registers->stack_pointer != 0);
    REQUIRE(debug_session.resume_thread(static_cast<uint64_t>(child_pid)));

    kill(child_pid, SIGKILL);
    int wait_status = 0;
    waitpid(child_pid, &wait_status, 0);
}

TEST_CASE("debugger arms and clears a hardware watchpoint on a child", "[debugger][watchpoint][fork]") {
    static volatile uint64_t watched_value = 0;

    pid_t child_pid = fork();
    REQUIRE(child_pid >= 0);

    if (child_pid == 0) {
        for (;;) {
            watched_value = watched_value + 1;
            struct timespec nap{0, 1000000};
            nanosleep(&nap, nullptr);
        }
        _exit(0);
    }

    bb::debugger debug_session(static_cast<uint32_t>(child_pid));
    REQUIRE(debug_session.suspend_thread(static_cast<uint64_t>(child_pid)));

    const bb::watchpoint point{
        reinterpret_cast<uintptr_t>(const_cast<uint64_t*>(&watched_value)),
        8,
        bb::watchpoint_condition::write
    };
    REQUIRE(debug_session.set_watchpoint(static_cast<uint64_t>(child_pid), 0, point));
    REQUIRE(debug_session.clear_watchpoint(static_cast<uint64_t>(child_pid), 0));
    REQUIRE(debug_session.resume_thread(static_cast<uint64_t>(child_pid)));

    kill(child_pid, SIGKILL);
    int wait_status = 0;
    waitpid(child_pid, &wait_status, 0);
}

TEST_CASE("debugger event loop catches a hardware watchpoint hit", "[debugger][watchpoint][eventloop][fork]") {
    static volatile uint64_t watched_value = 0;

    pid_t child_pid = fork();
    REQUIRE(child_pid >= 0);

    if (child_pid == 0) {
        for (;;) {
            watched_value = watched_value + 1;
            struct timespec nap{0, 1000000};
            nanosleep(&nap, nullptr);
        }
        _exit(0);
    }

    bb::debugger debug_session(static_cast<uint32_t>(child_pid));
    REQUIRE(debug_session.attach());

    const bb::watchpoint point{
        reinterpret_cast<uintptr_t>(const_cast<uint64_t*>(&watched_value)),
        8,
        bb::watchpoint_condition::write
    };
    REQUIRE(debug_session.set_watchpoint(static_cast<uint64_t>(child_pid), 0, point));

    // Drive the loop from the attach stop: continue, then wait for the trap.
    bb::debug_event current;
    current.kind = bb::debug_event_kind::breakpoint_hit;
    current.thread_id = static_cast<uint64_t>(child_pid);

    bool caught = false;
    int hit_slot = -1;
    uint64_t hit_instruction_pointer = 0;
    for (int iteration = 0; iteration < 50 && !caught; ++iteration) {
        REQUIRE(debug_session.continue_event(current, true));
        const auto event = debug_session.wait_for_event(2000);
        if (!event.has_value()) break;
        if (event->kind == bb::debug_event_kind::watchpoint_hit) {
            caught = true;
            hit_slot = event->watchpoint_slot;
            hit_instruction_pointer = event->registers.instruction_pointer;
            break;
        }
        if (event->kind == bb::debug_event_kind::process_exited) break;
        current = *event;
    }

    debug_session.detach();
    kill(child_pid, SIGKILL);
    int wait_status = 0;
    waitpid(child_pid, &wait_status, 0);

    CHECK(caught);
    CHECK(hit_slot == 0);
    CHECK(hit_instruction_pointer != 0);
}
#endif
