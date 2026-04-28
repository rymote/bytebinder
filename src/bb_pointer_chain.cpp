/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "bb_pointer_chain.h"
#include "bb_process.h"
#include "bb_memory_accessor.h"
#include "bb_mem.h"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

namespace bytebinder {

    chain_resolution resolve_chain_for_process(
        const process& target_process,
        uintptr_t base,
        std::span<const chain_step> steps) {
        chain_resolution result;
        if (steps.empty()) {
            result.address = base;
            return result;
        }
        memory_accessor& bound_accessor = target_process.accessor();

        uintptr_t running = base;
        for (size_t step_index = 0; step_index < steps.size(); ++step_index) {
            const chain_step& step = steps[step_index];
            running = static_cast<uintptr_t>(
                static_cast<intptr_t>(running) + step.offset);
            if (step.dereference) {
                if (!target_process.is_readable(running, sizeof(uint64_t))) {
                    result.failed_at_step = step_index;
                    result.failure = memory_error_code::READ_FAILED;
                    result.partial_walk_addr = running;
                    return result;
                }
                uint64_t next = 0;
                const size_t got = bound_accessor.read(running, &next, sizeof(next));
                if (got != sizeof(next)) {
                    result.failed_at_step = step_index;
                    result.failure = memory_error_code::READ_FAILED;
                    result.partial_walk_addr = running;
                    return result;
                }
                running = static_cast<uintptr_t>(next);
            }
        }
        result.address = running;
        return result;
    }

    std::vector<uintptr_t> find_pointers_to_in_process(
        const process& target_process,
        uintptr_t target,
        std::optional<std::string_view> module_name,
        int required_protection,
        int forbidden_protection,
        size_t max_results) {
        memory_accessor& bound_accessor = target_process.accessor();
        std::vector<uintptr_t> matches;

        std::vector<region_info> candidate_regions;
        if (module_name.has_value()) {
            const auto resolved = bound_accessor.find_module(*module_name);
            if (!resolved.has_value()) return matches;
            const uintptr_t module_end = resolved->base + resolved->size;
            for (const auto& region : bound_accessor.regions()) {
                if ((region.protection & required_protection) != required_protection) continue;
                if ((region.protection & forbidden_protection) != 0) continue;
                const uintptr_t region_end = region.base + region.size;
                const uintptr_t overlap_start = std::max(region.base, resolved->base);
                const uintptr_t overlap_end   = std::min(region_end, module_end);
                if (overlap_start >= overlap_end) continue;
                region_info clipped = region;
                clipped.base = overlap_start;
                clipped.size = overlap_end - overlap_start;
                candidate_regions.push_back(std::move(clipped));
            }
        } else {
            for (auto& region : bound_accessor.regions()) {
                if ((region.protection & required_protection) != required_protection) continue;
                if ((region.protection & forbidden_protection) != 0) continue;
                candidate_regions.push_back(std::move(region));
            }
        }

        constexpr size_t pointer_size = sizeof(void*);
        std::vector<uint8_t> region_buffer;

        for (const auto& region : candidate_regions) {
            region_buffer.resize(region.size);
            const size_t bytes_read = bound_accessor.read(region.base,
                                                            region_buffer.data(),
                                                            region.size);
            if (bytes_read < pointer_size) continue;

            const size_t aligned_end = bytes_read - (bytes_read % pointer_size);
            for (size_t cursor = 0; cursor + pointer_size <= aligned_end;
                 cursor += pointer_size) {
                uintptr_t value;
                std::memcpy(&value, region_buffer.data() + cursor, pointer_size);
                if (value == target) {
                    matches.push_back(region.base + cursor);
                    if (max_results != 0 && matches.size() >= max_results) {
                        return matches;
                    }
                }
            }
        }
        return matches;
    }

    namespace {
        // Per-watch state carrying the intermediate-pointer cache.
        // cached_slot[i] = address read FROM at deref step i (post-offset).
        // cached_value[i] = pointer value previously observed at that slot.
        struct chain_watch_state {
            std::vector<chain_step> steps;
            std::vector<uintptr_t> cached_slot;
            std::vector<uintptr_t> cached_value;
            std::optional<uintptr_t> last_final;
        };
    }

    watch_handle watch_chain_for_process(
        const process& target_process,
        uintptr_t base,
        std::span<const chain_step> steps,
        std::function<void(uintptr_t)> on_resolve,
        std::chrono::milliseconds interval) {
        auto stop_flag = std::make_shared<std::atomic_bool>(false);
        auto state = std::make_shared<chain_watch_state>();
        state->steps.assign(steps.begin(), steps.end());
        auto accessor_shared = target_process.accessor_shared();

        std::thread worker([stop_flag, state, accessor_shared,
                            base, on_resolve = std::move(on_resolve),
                            interval]() {
            const std::vector<chain_step>& steps_vec = state->steps;
            while (!stop_flag->load(std::memory_order_relaxed)) {
                uintptr_t running = base;
                size_t deref_index = 0;
                bool walk_succeeded = true;

                for (size_t step_index = 0; step_index < steps_vec.size(); ++step_index) {
                    const chain_step& step = steps_vec[step_index];
                    running = static_cast<uintptr_t>(
                        static_cast<intptr_t>(running) + step.offset);
                    if (step.dereference) {
                        uint64_t observed = 0;
                        const size_t got = accessor_shared->read(running, &observed, sizeof(observed));
                        if (got != sizeof(observed)) {
                            walk_succeeded = false;
                            break;
                        }
                        // Update cache; truncate stale tail entries when an
                        // earlier slot's value changed.
                        if (deref_index < state->cached_slot.size()
                            && state->cached_slot[deref_index] == running
                            && state->cached_value[deref_index] == observed) {
                            // cache hit — same slot, same pointer.
                        } else {
                            if (deref_index >= state->cached_slot.size()) {
                                state->cached_slot.push_back(running);
                                state->cached_value.push_back(observed);
                            } else {
                                state->cached_slot[deref_index] = running;
                                state->cached_value[deref_index] = observed;
                            }
                            if (state->cached_slot.size() > deref_index + 1) {
                                state->cached_slot.resize(deref_index + 1);
                                state->cached_value.resize(deref_index + 1);
                            }
                        }
                        running = static_cast<uintptr_t>(observed);
                        ++deref_index;
                    }
                }

                if (!walk_succeeded) {
                    state->last_final.reset();
                } else if (!state->last_final.has_value() || *state->last_final != running) {
                    state->last_final = running;
                    try {
                        on_resolve(running);
                    } catch (...) {
                        // Swallow per the same contract as set_log_sink.
                    }
                }

                // Cooperative cancellable sleep.
                const auto deadline = std::chrono::steady_clock::now() + interval;
                while (std::chrono::steady_clock::now() < deadline
                       && !stop_flag->load(std::memory_order_relaxed)) {
                    std::this_thread::sleep_for(std::chrono::milliseconds{10});
                }
            }
        });

        return watch_handle(stop_flag, std::move(worker));
    }
}
