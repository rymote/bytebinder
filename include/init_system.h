/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 *
 * This file is part of bytebinder, a powerful tool for reading, writing, hooking, and manipulating memory addresses.
 *
 * Repository: https://github.com/rymote/bytebinder
 *
 * For issues, suggestions, or contributions, please visit the repository or contact the authors.
 *
 * This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties
 * of merchantability, fitness for a particular purpose, and noninfringement. In no event shall the authors or copyright holders
 * be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out
 * of, or in connection with the software or the use or other dealings in the software.
 */

#pragma once

#include "pch.h"
#include "mem.h"

namespace bytebinder {
    class mem_holder;

    using mem_initializer_t = std::function<mem()>;
    using function_initializer_t = std::function<void()>;
    inline std::unordered_map<mem_holder*, mem_initializer_t> mem_initializers;
    inline std::vector<function_initializer_t> function_initializers;

    class mem_holder {
    public:
        mem_holder() : target(nullptr) {}

        void set_target(const mem& _target) {
            target = _target;
        }

        mem get_target() {
            return target;
        }

    protected:
        mem target;
    };

    template<typename T>
    class static_mem : public mem_holder {
    public:
        static_mem(const mem_initializer_t& function) : mem_holder() {
            mem_initializers[this] = function;
        }

        T operator->() {
            return target.get<T>();
        }
    };

    template<typename R, typename... Args>
    class static_func : public mem_holder {
    public:
        static_func(const mem_initializer_t& function) : mem_holder() {
            mem_initializers[this] = function;
        }

        R operator()(Args... args) {
            return target.get<R(*)(Args...)>()(args...);
        }
    };

    class init_func {
    public:
        init_func(const function_initializer_t& function) {
            function_initializers.push_back(function);
        }
    };

    template<typename R, typename... Args>
    class static_hook {
        using function_t = R(__fastcall*)(Args...);
        function_t hook_function;
        function_t original_function;

    public:
        template<std::size_t S>
        constexpr static_hook(const char(&ida_pattern)[S]) {
            static init_func _([this, ida_pattern]() {
                mem::scan(ida_pattern).get<function_t>().hook(hook_function, &original_function);
            });
        }

        static_hook(const static_mem<function_t>& target) {
            static init_func _([this, target] {
                target.get_target().hook(hook_function, &original_function);
            });
        }

        function_t get_hook() {
            return hook_function;
        }

        function_t get_orig() {
            return original_function;
        }

        R operator()(Args...args) const {
            return original_function(args...);
        }
    };

    inline void run_init_funcs() {
        for (auto& [holder, fn] : mem_initializers) {
            holder->set_target(fn());
        }

        for (auto& init : function_initializers) {
            init();
        }
    }
}