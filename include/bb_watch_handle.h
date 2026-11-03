/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#pragma once

#include "bb_api.h"

#include <atomic>
#include <memory>
#include <thread>
#include <utility>

namespace bytebinder {
    /**
     * @brief Owning handle for a memory-watch worker thread spawned by
     *        mem::watch. Stops and joins the worker on destruction.
     */
    class BYTEBINDER_API watch_handle {
    public:
        watch_handle() = default;
        watch_handle(std::shared_ptr<std::atomic_bool> stop_flag,
                     std::thread worker_thread)
            : stop_flag(std::move(stop_flag)),
              worker_thread(std::move(worker_thread)) {}

        watch_handle(const watch_handle&) = delete;
        watch_handle& operator=(const watch_handle&) = delete;

        watch_handle(watch_handle&& other) noexcept
            : stop_flag(std::move(other.stop_flag)),
              worker_thread(std::move(other.worker_thread)) {}

        watch_handle& operator=(watch_handle&& other) noexcept {
            if (this != &other) {
                stop();
                stop_flag = std::move(other.stop_flag);
                worker_thread = std::move(other.worker_thread);
            }
            return *this;
        }

        ~watch_handle() { stop(); }

        void stop() noexcept {
            if (stop_flag) {
                stop_flag->store(true);
            }
            if (worker_thread.joinable()) {
                worker_thread.join();
            }
        }

        [[nodiscard]] bool active() const noexcept {
            return stop_flag && !stop_flag->load();
        }

    private:
        std::shared_ptr<std::atomic_bool> stop_flag;
        std::thread worker_thread;
    };
}
