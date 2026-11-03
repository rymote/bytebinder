/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

/**
 * @file
 * @brief Thread-level debugging primitives: suspend and resume a thread, read or
 *        write its integer registers, arm or clear the CPU's hardware watchpoints
 *        on it, and run the debug event loop that catches a watchpoint trap and
 *        reports the faulting instruction. Together these are "find what accesses
 *        this address": arm a watchpoint, then wait for the hit.
 *
 * Platform model:
 *  - Windows: a thread is opened by its id; suspend and register access need no
 *    separate debug attach. The event loop uses DebugActiveProcess and
 *    WaitForDebugEvent, so it controls the whole process.
 *  - Linux: suspend_thread ptrace-attaches and stops the thread, resume_thread
 *    detaches it, and register access requires the thread be suspended first.
 *    The event loop attaches to the process and drives it with ptrace cont/wait.
 *    The caller must be permitted to trace the target (same user and a
 *    permissive ptrace_scope, or root).
 *  - macOS: a thread is addressed by its Mach port; suspend, register access, and
 *    watchpoint arming need the task port that task_for_pid returns, which
 *    requires root or the debugger entitlement for a foreign process. The event
 *    loop, which rides on Mach exception ports, is not yet implemented there.
 */

#include "bb_api.h"
#include "bb_cpu_registers.h"
#include "bb_debug_event.h"
#include "bb_thread_entry.h"
#include "bb_watchpoint.h"

#include <cstdint>
#include <optional>
#include <vector>

namespace bytebinder {
    /**
     * @brief Debug control bound to one process. Not thread safe: a debugger
     *        holds per-thread OS state (handles, ptrace attachment), so drive one
     *        debugger from a single thread.
     */
    class BYTEBINDER_API debugger {
    public:
        /// @brief Binds a debugger to @p process_id. Binding performs no global
        ///        attach; per-thread state is acquired on first use and released
        ///        in the destructor.
        explicit debugger(uint32_t process_id);
        ~debugger();

        debugger(const debugger&) = delete;
        debugger& operator=(const debugger&) = delete;

        /// @brief The bound process id.
        [[nodiscard]] uint32_t process_id() const noexcept { return bound_process_id; }

        /// @brief Enumerates the bound process's threads.
        [[nodiscard]] std::vector<thread_entry> threads() const;

        /**
         * @brief Suspends @p thread_id. On Windows this increments the thread's
         *        suspend count; on Linux it attaches and stops the thread; on
         *        macOS it increments the Mach suspend count. Returns false if the
         *        thread cannot be controlled. Nested suspends must be matched by
         *        the same number of resume_thread calls.
         */
        bool suspend_thread(uint64_t thread_id);

        /// @brief Reverses a suspend_thread on @p thread_id.
        bool resume_thread(uint64_t thread_id);

        /**
         * @brief Reads @p thread_id's integer registers. On Linux the thread must
         *        be suspended first. Returns nullopt on failure.
         */
        [[nodiscard]] std::optional<cpu_registers> read_registers(uint64_t thread_id);

        /**
         * @brief Writes @p thread_id's integer registers from @p registers. On
         *        Linux the thread must be suspended first. Returns false on
         *        failure.
         */
        bool write_registers(uint64_t thread_id, const cpu_registers& registers);

        /// @brief The number of hardware watchpoint slots a thread has (four on
        ///        x86 and x86_64).
        [[nodiscard]] static constexpr int watchpoint_slot_count() noexcept { return 4; }

        /**
         * @brief Arms hardware watchpoint @p slot (0..3) on @p thread_id to trap
         *        @p point. Replaces whatever that slot held. On Linux the thread
         *        must be suspended first. Returns false if the slot is out of
         *        range, the watchpoint is malformed, the architecture has no
         *        hardware watchpoints (only x86 and x86_64 are supported), or the
         *        thread cannot be controlled.
         *
         * @note The hardware delivers the trap as a debug exception to the
         *       process that owns the thread; catching that exception and
         *       reporting the faulting instruction is the exception-wait loop,
         *       which is a separate step from arming the slot here.
         */
        bool set_watchpoint(uint64_t thread_id, int slot, const watchpoint& point);

        /// @brief Disables hardware watchpoint @p slot on @p thread_id. On Linux
        ///        the thread must be suspended first. Returns false if the slot is
        ///        out of range or the thread cannot be controlled.
        bool clear_watchpoint(uint64_t thread_id, int slot);

        /**
         * @brief Becomes the controlling debugger of the bound process so its
         *        exceptions, including hardware watchpoint traps, are delivered to
         *        wait_for_event. On Windows this calls DebugActiveProcess and
         *        arranges for the target to keep running when the debugger
         *        detaches; on Linux it ptrace-attaches to the process and leaves
         *        it stopped so watchpoints can be armed before the first continue.
         *        Returns false on failure or if already attached. Not implemented
         *        on macOS.
         */
        bool attach();

        /// @brief Stops debugging and leaves the target process running. Safe to
        ///        call when not attached. Returns false only if a live detach
        ///        failed.
        bool detach();

        /**
         * @brief Blocks until the next debug event, or until
         *        @p timeout_milliseconds elapses (pass a negative value to wait
         *        without a timeout). Returns nullopt on timeout or error. The
         *        target is left stopped on a returned event and must be released
         *        with continue_event (except process_exited, after which the
         *        target is gone).
         */
        [[nodiscard]] std::optional<debug_event> wait_for_event(int timeout_milliseconds);

        /**
         * @brief Resumes the target after wait_for_event. When @p handled is true
         *        the stopping exception is swallowed (the choice for the
         *        debugger's own watchpoint trap); when false it is passed on to
         *        the target's own handlers. A no-op for process_exited. Returns
         *        false on failure.
         */
        bool continue_event(const debug_event& event, bool handled);

    private:
        uint32_t bound_process_id = 0;
        bool debugging_active = false;

#if defined(__APPLE__)
        unsigned int task_port = 0;
        bool owns_task_port = false;
        unsigned int exception_port = 0;
        bool reply_pending = false;
        unsigned int pending_remote_port = 0;
        unsigned int pending_bits = 0;
        int pending_id = 0;
#endif
    };
}
