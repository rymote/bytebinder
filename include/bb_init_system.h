/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#pragma once

#include "bb_pch.h"
#include "bb_mem.h"

namespace bytebinder {
    class mem_holder;

    /// @brief Lazy producer of a `mem` value used by the static_mem/static_func
    ///        initialization queue.
    using mem_initializer_t = std::function<mem()>;
    /// @brief Lazy void-returning callback used by init_func and static_hook.
    using function_initializer_t = std::function<void()>;

    inline std::unordered_map<mem_holder*, mem_initializer_t>& mem_initializers() {
        static std::unordered_map<mem_holder*, mem_initializer_t> instance;
        return instance;
    }

    inline std::vector<function_initializer_t>& function_initializers() {
        static std::vector<function_initializer_t> instance;
        return instance;
    }

    /// @brief Common base for objects that own a deferred-resolved `mem`
    ///        target. Populated by run_init_funcs.
    class mem_holder {
    public:
        mem_holder() : target() {}

        /// @brief Stores the resolved `mem` for later access.
        void set_target(const mem& new_target) { target = new_target; }
        /// @brief Returns the previously stored target (default-constructed
        ///        until run_init_funcs has fired).
        mem get_target() const { return target; }

    protected:
        mem target;
    };

    /**
     * @brief Lazily-resolved typed pointer. Construction registers an
     *        initializer; run_init_funcs() resolves it; subsequent operator->
     *        calls dereference the resolved address.
     */
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

    /**
     * @brief Lazily-resolved function pointer that can be called as if it
     *        were a regular function once run_init_funcs() has fired.
     */
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

    /// @brief Registers a free initializer to run when run_init_funcs() is called.
    class init_func {
    public:
        explicit init_func(const function_initializer_t& initializer) {
            function_initializers().push_back(initializer);
        }
    };

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

    /// @brief Resolves every pending mem initializer and runs every queued
    ///        init_func / static_hook. Call once after process startup.
    inline void run_init_funcs() {
        for (auto& [holder, initializer] : mem_initializers()) {
            holder->set_target(initializer());
        }
        for (auto& initializer : function_initializers()) {
            initializer();
        }
    }
}
