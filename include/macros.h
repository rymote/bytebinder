#pragma once

#include "mem.h"

#define MEM_DRY_RUN_EXEC(code) \
    if (bytebinder::mem::is_dry_run()) { \
        code; \
    }

#define MEM_NON_DRY_RUN_EXEC(code) \
    if (!bytebinder::mem::is_dry_run()) { \
        code; \
    }

#define MEM_DEBUG_EXEC(code) MEM_DRY_RUN_EXEC(code)
#define MEM_NON_DEBUG_EXEC(code) MEM_NON_DRY_RUN_EXEC(code)
