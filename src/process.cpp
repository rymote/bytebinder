/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "bb_process.h"
#include "local_accessor.h"
#include "remote_accessor.h"
#include "mem.h"
#include "pattern.h"

namespace bytebinder {
    process::process(std::shared_ptr<memory_accessor> accessor)
        : accessor_impl(std::move(accessor)) {}

    process process::current() {
        return process(std::shared_ptr<memory_accessor>(&local_accessor::instance(),
                                                         [](memory_accessor*){}));
    }

    process process::attach(uint32_t target_process_id) {
        return process(std::make_shared<remote_accessor>(target_process_id));
    }

    bool process::is_local() const noexcept {
        return accessor_impl && accessor_impl->is_local();
    }

    std::optional<uint32_t> process::id() const noexcept {
        return accessor_impl ? accessor_impl->process_id() : std::nullopt;
    }

    mem process::at(uintptr_t address) const {
        return mem(address, accessor_impl.get());
    }

    std::vector<region_info> process::regions() const {
        return accessor_impl ? accessor_impl->regions() : std::vector<region_info>{};
    }

    std::vector<module_info> process::modules() const {
        return accessor_impl ? accessor_impl->modules() : std::vector<module_info>{};
    }

    std::optional<module_info> process::find_module(std::string_view name) const {
        return accessor_impl ? accessor_impl->find_module(name) : std::nullopt;
    }

    mem process::scan(std::string_view ida_pattern,
                       std::optional<std::string_view> module_name) const {
        if (!accessor_impl) {
            return mem();
        }
        const pattern parsed_pattern = parse_ida_pattern(ida_pattern);

        if (module_name.has_value()) {
            const auto resolved_module = accessor_impl->find_module(*module_name);
            if (!resolved_module.has_value()) {
                throw memory_operation_exception(
                    std::string("Module not found: ") + std::string(*module_name),
                    memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
            }
            const uintptr_t hit = parsed_pattern.scan(*accessor_impl,
                                                       resolved_module->base,
                                                       resolved_module->size);
            return hit == std::numeric_limits<uintptr_t>::max()
                   ? mem(std::numeric_limits<uintptr_t>::max(), accessor_impl.get())
                   : mem(hit, accessor_impl.get());
        }

        const auto all_regions = accessor_impl->regions();
        for (const auto& region : all_regions) {
            if ((region.protection & protection::read) == 0) continue;
            const uintptr_t hit = parsed_pattern.scan(*accessor_impl,
                                                       region.base, region.size);
            if (hit != std::numeric_limits<uintptr_t>::max()) {
                return mem(hit, accessor_impl.get());
            }
        }
        return mem(std::numeric_limits<uintptr_t>::max(), accessor_impl.get());
    }
}
