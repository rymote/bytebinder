/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

namespace bytebinder {
    /**
     * @brief What a debug event reports. watchpoint_hit is the one a "find what
     *        accesses this address" workflow waits for: it carries the slot that
     *        fired and the faulting thread's registers. The remaining kinds let a
     *        caller drive the event loop (continue past the initial attach
     *        breakpoint, notice new threads, and detect the target exiting).
     */
    enum class debug_event_kind {
        unknown,
        watchpoint_hit,
        breakpoint_hit,
        single_step,
        exception,
        thread_created,
        thread_exited,
        process_created,
        process_exited
    };
}
