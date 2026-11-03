/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_hook_handle.h"
#include "bb_init_registry.h"
#include "bb_mem.h"
#include "bb_static_mem.h"

#include <cstddef>

namespace bytebinder {
    /**
     * @brief Pattern-or-target backed function hook installed lazily by
     *        run_init_funcs. Calling the instance forwards to the original
     *        (non-detoured) function.
     */
    template<typename ReturnType, typename... Args>
    class static_hook {
    public:
        using function_t = ReturnType(*)(Args...);

        template<std::size_t PatternSize>
        static_hook(const char(&ida_pattern)[PatternSize], function_t detour)
            : detour_function(detour) {
            function_initializers().push_back([this, ida_pattern]() {
                this->handle = mem::scan(ida_pattern)
                    .template get<function_t>()
                    .hook(detour_function, &original_function);
            });
        }

        static_hook(static_mem<function_t>& target_mem, function_t detour)
            : detour_function(detour) {
            function_initializers().push_back([this, &target_mem]() {
                this->handle = target_mem.get_target()
                    .hook(detour_function, &original_function);
            });
        }

        [[nodiscard]] function_t detour() const noexcept { return detour_function; }
        [[nodiscard]] function_t original() const noexcept { return original_function; }
        [[nodiscard]] hook_handle& handle_ref() noexcept { return handle; }

        ReturnType operator()(Args... args) const {
            return original_function(args...);
        }

    private:
        function_t detour_function = nullptr;
        function_t original_function = nullptr;
        hook_handle handle;
    };
}
