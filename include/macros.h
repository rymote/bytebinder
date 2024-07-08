#pragma once

#include "mem.h"

/**
 * @brief Macro to execute code only when the mem class is in debug mode.
 *
 * @param code Code block to be executed when debug mode is enabled.
 */
#define MEM_DEBUG_EXEC(code) \
    if (bytebinder::mem::is_debug()) { \
        code; \
    }

/**
 * @brief Macro to execute code only when the mem class is not in debug mode.
 *
 * @param code Code block to be executed when debug mode is disabled.
 */
#define MEM_NON_DEBUG_EXEC(code) \
    if (!bytebinder::mem::is_debug()) { \
        code; \
    }