#include <catch2/catch_test_macros.hpp>
#include "bytebinder.h"
#include "test_support.h"

#include <atomic>
#include <thread>

TEST_CASE("list_current_process_threads sees spawned threads", "[thread][enumeration]") {
    const size_t baseline = bb::list_current_process_threads().size();
    REQUIRE(baseline >= 1);

    std::atomic<bool> keep_running{true};
    std::atomic<bool> worker_started{false};
    std::thread worker([&]() {
        worker_started.store(true);
        while (keep_running.load(std::memory_order_acquire)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
    });

    while (!worker_started.load(std::memory_order_acquire)) {
        std::this_thread::yield();
    }

    const size_t with_worker = bb::list_current_process_threads().size();
    REQUIRE(with_worker > baseline);

    keep_running.store(false, std::memory_order_release);
    worker.join();
}
