/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

namespace bytebinder {
    /// @brief Category of cross-reference reported by find_xrefs.
    enum class xref_kind {
        call,
        jmp_uncond,
        jmp_cond,
        lea_rip,
        mov_rip_load,
        mov_rip_store,
    };
}
