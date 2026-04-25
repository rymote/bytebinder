/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "pch.h"
#include "mem.h"

namespace bytebinder {
    class mem_holder;

    using mem_initializer_t = std::function<mem()>;
    using function_initializer_t = std::function<void()>;

    inline std::unordered_map<mem_holder*, mem_initializer_t>& mem_initializers() {
        static std::unordered_map<mem_holder*, mem_initializer_t> instance;
        return instance;
    }

    inline std::vector<function_initializer_t>& function_initializers() {
        static std::vector<function_initializer_t> instance;
        return instance;
    }

    class mem_holder {
    public:
        mem_holder() : target() {}

        void set_target(const mem& new_target) { target = new_target; }
        mem get_target() const { return target; }

    protected:
        mem target;
    };

    template<typename PointerType>
    class static_mem : public mem_holder {
    public:
        explicit static_mem(const mem_initializer_t& initializer) : mem_holder() {
            mem_initializers()[this] = initializer;
        }

        PointerType operator->() {
            return target.get<PointerType>();
        }
    };

    template<typename FunctionPointer>
    class static_func : public mem_holder {
    public:
        explicit static_func(const mem_initializer_t& initializer) : mem_holder() {
            mem_initializers()[this] = initializer;
        }

        template<typename... Args>
        auto operator()(Args... args) -> decltype(target.get<FunctionPointer>()(args...)) {
            return target.get<FunctionPointer>()(args...);
        }
    };

    class init_func {
    public:
        explicit init_func(const function_initializer_t& initializer) {
            function_initializers().push_back(initializer);
        }
    };

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

    inline void run_init_funcs() {
        for (auto& [holder, initializer] : mem_initializers()) {
            holder->set_target(initializer());
        }
        for (auto& initializer : function_initializers()) {
            initializer();
        }
    }
}
