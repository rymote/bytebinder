/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_cpu_registers.h"
#include "bb_debug_event_kind.h"

#include <cstdint>

namespace bytebinder {
    /**
     * @brief One event delivered by the debugger's wait loop. For a trap or
     *        exception the thread is stopped and registers holds its state;
     *        watchpoint_slot names the hardware slot that fired (0..3), or -1 when
     *        the stop was not a hardware watchpoint. exit_code is meaningful for
     *        process_exited, and native_exception_code carries the raw OS code
     *        (a Windows exception status or a POSIX signal number) for diagnosis.
     */
    struct debug_event {
        debug_event_kind kind = debug_event_kind::unknown;
        uint64_t thread_id = 0;
        cpu_registers registers{};
        int watchpoint_slot = -1;
        uint64_t exception_address = 0;
        uint32_t exit_code = 0;
        uint32_t native_exception_code = 0;
    };
}
