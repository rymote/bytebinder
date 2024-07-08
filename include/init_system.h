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
    using fn_initializer_t = std::function<void()>;
    inline std::unordered_map<mem_holder*, mem_initializer_t> mem_initializers;
    inline std::vector<fn_initializer_t> fn_initializers;

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
        static_mem(const mem_initializer_t& fn) : mem_holder() {
            mem_initializers[this] = fn;
        }

        T operator->() {
            return target.get<T>();
        }
    };

    template<typename R, typename... Args>
    class static_func : public mem_holder {
    public:
        static_func(const mem_initializer_t& fn) : mem_holder() {
            mem_initializers[this] = fn;
        }

        R operator()(Args... args) {
            return target.get<R(*)(Args...)>()(args...);
        }
    };

    class init_func {
    public:
        init_func(const fn_initializer_t& fn) {
            fn_initializers.push_back(fn);
        }
    };

    template<typename R, typename... Args>
    class static_hook {
        using fn_t = R(__fastcall*)(Args...);
        fn_t hook_func;
        fn_t orig_func;

    public:
        template<std::size_t S>
        constexpr static_hook(const char(&ida_pattern)[S]) {
            static init_func _([this, ida_pattern]() {
                mem::scan(ida_pattern).get<fn_t>().hook(hook_func, &orig_func);
            });
        }

        static_hook(const static_mem<fn_t>& target) {
            static init_func _([this, target] {
                target.get_target().hook(hook_func, &orig_func);
            });
        }

        fn_t get_hook() {
            return hook_func;
        }

        fn_t get_orig() {
            return hook_func;
        }

        R operator()(Args...args) const {
            return orig_func(args...);
        }
    };

    inline void run_init_funcs() {
        for (auto& [holder, fn] : mem_initializers) {
            holder->set_target(fn());
        }

        for (auto& init : fn_initializers) {
            init();
        }
    }
}