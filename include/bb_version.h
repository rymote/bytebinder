/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

/// @brief Semantic version string of the linked bytebinder build, e.g. "0.3.0".
BYTEBINDER_API const char* bytebinder_version(void);

/// @brief Monotonically increasing ABI revision. Bump this in src/bb_version.cpp
///        every time the layout of any exported struct, vtable, or class
///        changes. Wrappers that dynamically load bytebinder must compare this
///        against the value they were built against and refuse mismatched
///        binaries.
BYTEBINDER_API uint32_t bytebinder_abi_revision(void);

#ifdef __cplusplus
}
#endif
