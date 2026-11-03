/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

namespace bytebinder {
    /**
     * @brief The kind of access a hardware watchpoint traps. These map directly
     *        onto the x86 debug-register read/write field: execute traps when the
     *        watched address is fetched as an instruction, write traps on a store,
     *        and read_write traps on either a load or a store.
     *
     * @note x86 hardware has no read-only data watchpoint; read_write is the
     *       narrowest condition that catches reads.
     */
    enum class watchpoint_condition {
        execute,
        write,
        read_write
    };
}
