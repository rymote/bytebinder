/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#include "bb_pointer_scanner.h"

#include <algorithm>
#include <cstring>

namespace bytebinder {
    namespace {
        struct address_range {
            uintptr_t begin = 0;
            uintptr_t end = 0;
        };

        bool range_contains(const std::vector<address_range>& sorted_ranges, uintptr_t address) {
            auto upper = std::upper_bound(sorted_ranges.begin(), sorted_ranges.end(), address,
                                          [](uintptr_t value, const address_range& range) {
                                              return value < range.begin;
                                          });
            if (upper == sorted_ranges.begin()) return false;
            --upper;
            return address >= upper->begin && address < upper->end;
        }
    }

    pointer_scanner::pointer_scanner(process target) : target(std::move(target)) {}

    bool pointer_scanner::address_is_static(uintptr_t address) const {
        auto upper = std::upper_bound(module_ranges.begin(), module_ranges.end(), address,
                                      [](uintptr_t value, const module_range& range) {
                                          return value < range.begin;
                                      });
        if (upper == module_ranges.begin()) return false;
        --upper;
        return address >= upper->begin && address < upper->end;
    }

    void pointer_scanner::build_index(const pointer_scan_options& options) {
        pointer_slots.clear();
        module_ranges.clear();

        for (const auto& module : target.modules()) {
            module_ranges.push_back({module.base, module.base + module.size});
        }
        std::sort(module_ranges.begin(), module_ranges.end(),
                  [](const module_range& left, const module_range& right) {
                      return left.begin < right.begin;
                  });

        // A stored value is treated as a pointer only if it lands inside some
        // readable region of the target.
        std::vector<address_range> readable_ranges;
        for (const auto& region : target.regions(protection::read, 0)) {
            readable_ranges.push_back({region.base, region.base + region.size});
        }
        std::sort(readable_ranges.begin(), readable_ranges.end(),
                  [](const address_range& left, const address_range& right) {
                      return left.begin < right.begin;
                  });

        const auto index_regions = target.regions(options.index_required_protection,
                                                  options.index_forbidden_protection);
        memory_accessor& accessor = target.accessor();

        constexpr size_t pointer_size = sizeof(uintptr_t);
        constexpr size_t window_step = 64 * 1024;
        const size_t window_capacity = window_step + pointer_size;
        std::vector<uint8_t> window_buffer(window_capacity);

        for (const auto& region : index_regions) {
            uintptr_t window_start = region.base;
            const uintptr_t region_end = region.base + region.size;
            while (window_start + pointer_size <= region_end) {
                const size_t want_bytes = std::min<size_t>(window_capacity,
                                                           region_end - window_start);
                const size_t got_bytes = accessor.read(window_start,
                                                       window_buffer.data(),
                                                       want_bytes);
                if (got_bytes >= pointer_size) {
                    const size_t inclusive_last = got_bytes - pointer_size;
                    const bool is_final_window = want_bytes < window_capacity;
                    const size_t exclusive_upper = is_final_window
                        ? inclusive_last + 1
                        : std::min<size_t>(inclusive_last + 1, window_step);

                    const uintptr_t alignment_remainder = window_start % pointer_size;
                    size_t offset = alignment_remainder == 0
                        ? 0
                        : pointer_size - alignment_remainder;

                    for (; offset < exclusive_upper; offset += pointer_size) {
                        uintptr_t stored_value = 0;
                        std::memcpy(&stored_value, window_buffer.data() + offset, pointer_size);
                        if (stored_value == 0) continue;
                        if (!range_contains(readable_ranges, stored_value)) continue;

                        pointer_slot slot;
                        slot.value = stored_value;
                        slot.address = window_start + offset;
                        pointer_slots.push_back(slot);

                        if (options.max_index_slots != 0
                            && pointer_slots.size() >= options.max_index_slots) {
                            goto index_complete;
                        }
                    }
                }
                window_start += window_step;
            }
        }

    index_complete:
        std::sort(pointer_slots.begin(), pointer_slots.end(),
                  [](const pointer_slot& left, const pointer_slot& right) {
                      return left.value < right.value;
                  });
        index_built = true;
    }

    void pointer_scanner::search_upward(uintptr_t need,
                                        size_t derefs_used,
                                        const pointer_scan_options& options,
                                        std::vector<ptrdiff_t>& offsets_leafward,
                                        std::vector<pointer_path>& out_paths,
                                        size_t& visited_nodes) const {
        if (options.max_results != 0 && out_paths.size() >= options.max_results) return;

        const uintptr_t low_value = need > options.max_offset ? need - options.max_offset : 0;

        auto lower = std::lower_bound(pointer_slots.begin(), pointer_slots.end(), low_value,
                                      [](const pointer_slot& slot, uintptr_t value) {
                                          return slot.value < value;
                                      });
        auto upper = std::upper_bound(pointer_slots.begin(), pointer_slots.end(), need,
                                      [](uintptr_t value, const pointer_slot& slot) {
                                          return value < slot.value;
                                      });

        for (auto iterator = lower; iterator != upper; ++iterator) {
            if (options.max_visited_nodes != 0 && visited_nodes >= options.max_visited_nodes) return;
            ++visited_nodes;
            if (options.max_results != 0 && out_paths.size() >= options.max_results) return;

            const ptrdiff_t offset = static_cast<ptrdiff_t>(need - iterator->value);

            std::vector<ptrdiff_t> offsets_from_here;
            offsets_from_here.reserve(offsets_leafward.size() + 1);
            offsets_from_here.push_back(offset);
            offsets_from_here.insert(offsets_from_here.end(),
                                     offsets_leafward.begin(), offsets_leafward.end());

            if (address_is_static(iterator->address)) {
                pointer_path path;
                path.base = iterator->address;
                path.offsets.reserve(offsets_from_here.size() + 1);
                path.offsets.push_back(0);
                path.offsets.insert(path.offsets.end(),
                                    offsets_from_here.begin(), offsets_from_here.end());
                out_paths.push_back(std::move(path));
            }

            if (derefs_used + 1 < options.max_depth) {
                search_upward(iterator->address, derefs_used + 1, options,
                              offsets_from_here, out_paths, visited_nodes);
            }
        }
    }

    std::vector<pointer_path> pointer_scanner::find_paths(uintptr_t target_address,
                                                          const pointer_scan_options& options) {
        if (!index_built) build_index(options);

        std::vector<pointer_path> paths;
        std::vector<ptrdiff_t> offsets_leafward;
        size_t visited_nodes = 0;
        search_upward(target_address, 0, options, offsets_leafward, paths, visited_nodes);

        std::stable_sort(paths.begin(), paths.end(),
                         [](const pointer_path& left, const pointer_path& right) {
                             return left.offsets.size() < right.offsets.size();
                         });
        return paths;
    }
}
