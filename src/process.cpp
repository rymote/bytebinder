/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "bb_process.h"
#include "local_accessor.h"
#include "log_sink.h"
#include "remote_accessor.h"
#include "mem.h"
#include "pattern.h"

#include <fstream>
#include <unordered_map>
#include <mutex>
#include <cstring>
#if !defined(_WIN32)
#include <elf.h>
#endif

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

    bool process::alive() const noexcept {
        if (!accessor_impl) return false;
        if (accessor_impl->is_local()) return true;
        const auto target_process_id = accessor_impl->process_id();
        if (!target_process_id.has_value()) return false;
#if defined(_WIN32)
        HANDLE process_handle = OpenProcess(SYNCHRONIZE, FALSE, *target_process_id);
        if (!process_handle) return false;
        const DWORD wait_result = WaitForSingleObject(process_handle, 0);
        CloseHandle(process_handle);
        return wait_result == WAIT_TIMEOUT;
#else
        return ::kill(static_cast<pid_t>(*target_process_id), 0) == 0
            || errno != ESRCH;
#endif
    }

    mem process::at(uintptr_t address) const {
        return mem(address, accessor_impl.get());
    }

    std::vector<region_info> process::regions() const {
        return accessor_impl ? accessor_impl->regions() : std::vector<region_info>{};
    }

    std::vector<region_info> process::regions(int required_protection,
                                                int forbidden_protection) const {
        std::vector<region_info> filtered;
        if (!accessor_impl) return filtered;
        for (auto& candidate : accessor_impl->regions()) {
            if ((candidate.protection & required_protection) != required_protection) continue;
            if ((candidate.protection & forbidden_protection) != 0) continue;
            filtered.push_back(std::move(candidate));
        }
        return filtered;
    }

    std::vector<module_info> process::modules() const {
        return accessor_impl ? accessor_impl->modules() : std::vector<module_info>{};
    }

    std::optional<module_info> process::find_module(std::string_view name) const {
        return accessor_impl ? accessor_impl->find_module(name) : std::nullopt;
    }

    namespace {
        std::vector<region_info> regions_intersected_with(
            memory_accessor& target_accessor,
            uintptr_t requested_base,
            size_t requested_size,
            int required_protection = protection::read,
            int forbidden_protection = 0) {
            std::vector<region_info> intersected;
            const uintptr_t requested_end =
                (requested_size > std::numeric_limits<uintptr_t>::max() - requested_base)
                ? std::numeric_limits<uintptr_t>::max()
                : requested_base + requested_size;
            for (const auto& candidate_region : target_accessor.regions()) {
                if ((candidate_region.protection & required_protection) != required_protection) continue;
                if ((candidate_region.protection & forbidden_protection) != 0) continue;
                const uintptr_t candidate_end = candidate_region.base + candidate_region.size;
                const uintptr_t overlap_start = std::max(candidate_region.base, requested_base);
                const uintptr_t overlap_end = std::min(candidate_end, requested_end);
                if (overlap_start >= overlap_end) continue;
                region_info clipped = candidate_region;
                clipped.base = overlap_start;
                clipped.size = overlap_end - overlap_start;
                intersected.push_back(std::move(clipped));
            }
            return intersected;
        }

        std::mutex section_cache_mutex;
        std::unordered_map<std::string, std::vector<process::module_section>> section_cache;

        std::vector<process::module_section> parse_elf_sections(const std::string& module_path,
                                                                  uintptr_t module_base) {
            std::vector<process::module_section> parsed_sections;
#if !defined(_WIN32)
            std::ifstream file_stream(module_path, std::ios::binary);
            if (!file_stream) return parsed_sections;
            ElfW(Ehdr) elf_header{};
            file_stream.read(reinterpret_cast<char*>(&elf_header), sizeof(elf_header));
            if (!file_stream) return parsed_sections;
            if (std::memcmp(elf_header.e_ident, ELFMAG, SELFMAG) != 0) return parsed_sections;

            std::vector<ElfW(Shdr)> section_headers(elf_header.e_shnum);
            file_stream.seekg(elf_header.e_shoff);
            file_stream.read(reinterpret_cast<char*>(section_headers.data()),
                              static_cast<std::streamsize>(sizeof(ElfW(Shdr)) * elf_header.e_shnum));
            if (!file_stream) return parsed_sections;

            const ElfW(Shdr)& strtab_header = section_headers[elf_header.e_shstrndx];
            std::vector<char> string_table(strtab_header.sh_size);
            file_stream.seekg(strtab_header.sh_offset);
            file_stream.read(string_table.data(),
                              static_cast<std::streamsize>(strtab_header.sh_size));
            if (!file_stream) return parsed_sections;

            for (const auto& section_header : section_headers) {
                if ((section_header.sh_flags & SHF_ALLOC) == 0) continue;
                process::module_section entry;
                entry.name = std::string(string_table.data() + section_header.sh_name);
                entry.base = module_base + section_header.sh_addr;
                entry.size = section_header.sh_size;
                entry.protection = protection::read;
                if (section_header.sh_flags & SHF_WRITE)     entry.protection |= protection::write;
                if (section_header.sh_flags & SHF_EXECINSTR) entry.protection |= protection::execute;
                parsed_sections.push_back(std::move(entry));
            }
#endif
            (void)module_path;
            (void)module_base;
            return parsed_sections;
        }

        std::vector<process::module_section> parse_pe_sections(memory_accessor& target_accessor,
                                                                 uintptr_t module_base) {
            std::vector<process::module_section> parsed_sections;
#if defined(_WIN32)
            IMAGE_DOS_HEADER dos_header{};
            if (target_accessor.read(module_base, &dos_header, sizeof(dos_header)) != sizeof(dos_header)) return parsed_sections;
            if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) return parsed_sections;

            IMAGE_NT_HEADERS nt_headers{};
            if (target_accessor.read(module_base + dos_header.e_lfanew, &nt_headers, sizeof(nt_headers))
                != sizeof(nt_headers)) return parsed_sections;
            if (nt_headers.Signature != IMAGE_NT_SIGNATURE) return parsed_sections;

            const uintptr_t section_table_address = module_base + dos_header.e_lfanew
                + offsetof(IMAGE_NT_HEADERS, OptionalHeader)
                + nt_headers.FileHeader.SizeOfOptionalHeader;
            const uint16_t number_of_sections = nt_headers.FileHeader.NumberOfSections;

            std::vector<IMAGE_SECTION_HEADER> section_headers(number_of_sections);
            const size_t section_table_byte_size = sizeof(IMAGE_SECTION_HEADER) * number_of_sections;
            if (target_accessor.read(section_table_address, section_headers.data(),
                                       section_table_byte_size) != section_table_byte_size) return parsed_sections;

            for (const auto& section_header : section_headers) {
                process::module_section entry;
                const size_t name_length = ::strnlen(reinterpret_cast<const char*>(section_header.Name),
                                                       IMAGE_SIZEOF_SHORT_NAME);
                entry.name.assign(reinterpret_cast<const char*>(section_header.Name), name_length);
                entry.base = module_base + section_header.VirtualAddress;
                entry.size = section_header.Misc.VirtualSize;
                entry.protection = 0;
                if (section_header.Characteristics & IMAGE_SCN_MEM_READ)    entry.protection |= protection::read;
                if (section_header.Characteristics & IMAGE_SCN_MEM_WRITE)   entry.protection |= protection::write;
                if (section_header.Characteristics & IMAGE_SCN_MEM_EXECUTE) entry.protection |= protection::execute;
                parsed_sections.push_back(std::move(entry));
            }
#endif
            (void)target_accessor;
            (void)module_base;
            return parsed_sections;
        }

        bool covers_range_with_protection(memory_accessor& target_accessor,
                                            uintptr_t address, size_t length,
                                            int required_protection) {
            const size_t effective_length = length == 0 ? 1 : length;
            const auto covering = regions_intersected_with(
                target_accessor, address, effective_length,
                required_protection, 0);
            if (covering.empty()) return false;
            uintptr_t covered_through = address;
            const uintptr_t target_end = address + effective_length;
            for (const auto& slice : covering) {
                if (slice.base > covered_through) return false; // gap
                const uintptr_t slice_end = slice.base + slice.size;
                if (slice_end > covered_through) covered_through = slice_end;
                if (covered_through >= target_end) return true;
            }
            return covered_through >= target_end;
        }
    }

    bool process::is_readable(uintptr_t address, size_t length) const {
        if (!accessor_impl) return false;
        return covers_range_with_protection(*accessor_impl, address, length,
                                              protection::read);
    }

    bool process::is_writable(uintptr_t address, size_t length) const {
        if (!accessor_impl) return false;
        return covers_range_with_protection(*accessor_impl, address, length,
                                              protection::write);
    }

    std::vector<process::module_section> process::module_sections(std::string_view module_name) const {
        if (!accessor_impl) return {};
        const auto resolved_module = accessor_impl->find_module(module_name);
        if (!resolved_module.has_value()) return {};

        const std::string cache_key = resolved_module->path.empty()
            ? std::string(module_name) : resolved_module->path;
        {
            std::lock_guard<std::mutex> guard(section_cache_mutex);
            const auto cached = section_cache.find(cache_key);
            if (cached != section_cache.end()) return cached->second;
        }

#if defined(_WIN32)
        auto parsed = parse_pe_sections(*accessor_impl, resolved_module->base);
#else
        auto parsed = parse_elf_sections(resolved_module->path, resolved_module->base);
#endif

        {
            std::lock_guard<std::mutex> guard(section_cache_mutex);
            section_cache[cache_key] = parsed;
        }
        return parsed;
    }

    mem process::scan(std::string_view ida_pattern,
                       std::optional<std::string_view> module_name) const {
        if (!accessor_impl) {
            return mem();
        }
        const pattern parsed_pattern = parse_ida_pattern(ida_pattern);

        uintptr_t scan_base = 0;
        size_t scan_size = std::numeric_limits<size_t>::max();
        if (module_name.has_value()) {
            const auto resolved_module = accessor_impl->find_module(*module_name);
            if (!resolved_module.has_value()) {
                log(log_level::error,
                    std::string("process::scan: module not found: ") + std::string(*module_name));
                throw memory_operation_exception(
                    std::string("Module not found: ") + std::string(*module_name),
                    memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
            }
            scan_base = resolved_module->base;
            scan_size = resolved_module->size;
        }

        const auto candidate_regions =
            regions_intersected_with(*accessor_impl, scan_base, scan_size);

        for (const auto& current_region : candidate_regions) {
            const uintptr_t hit = parsed_pattern.scan(*accessor_impl,
                                                       current_region.base,
                                                       current_region.size);
            if (hit != std::numeric_limits<uintptr_t>::max()) {
                return mem(hit, accessor_impl.get());
            }
        }
        return mem(std::numeric_limits<uintptr_t>::max(), accessor_impl.get());
    }

    process::scan_result process::scan_all(std::string_view ida_pattern,
                                            std::optional<std::string_view> module_name,
                                            size_t max_results) const {
        scan_result aggregate;
        if (!accessor_impl) return aggregate;
        const pattern parsed_pattern = parse_ida_pattern(ida_pattern);

        uintptr_t scan_base = 0;
        size_t scan_size = std::numeric_limits<size_t>::max();
        if (module_name.has_value()) {
            const auto resolved_module = accessor_impl->find_module(*module_name);
            if (!resolved_module.has_value()) {
                log(log_level::error,
                    std::string("process::scan_all: module not found: ") + std::string(*module_name));
                throw memory_operation_exception(
                    std::string("Module not found: ") + std::string(*module_name),
                    memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
            }
            scan_base = resolved_module->base;
            scan_size = resolved_module->size;
        }

        const auto candidate_regions =
            regions_intersected_with(*accessor_impl, scan_base, scan_size);

        // regions_skipped stays 0 here — regions_intersected_with already
        // filters out non-readable regions. The field is reserved for future
        // accessors that surface skip reasons separately.
        for (const auto& current_region : candidate_regions) {
            ++aggregate.regions_scanned;
            aggregate.bytes_scanned += current_region.size;
            // remaining=0 has two meanings: "budget exhausted" (caught by the
            // break below) or "max_results==0, unlimited" (passed verbatim to
            // pattern::scan_all, which interprets 0 as unlimited). The
            // [&aggregate, max_results] lambda below handles both.
            const size_t remaining =
                max_results == 0 ? 0
                                 : (max_results - aggregate.matches.size());
            if (max_results != 0 && remaining == 0) break;
            parsed_pattern.scan_all(*accessor_impl,
                                     current_region.base, current_region.size,
                                     remaining,
                                     [&aggregate, max_results](uintptr_t hit_address) {
                                         aggregate.matches.push_back(hit_address);
                                         if (max_results != 0
                                             && aggregate.matches.size() >= max_results) {
                                             return false;
                                         }
                                         return true;
                                     });
        }
        return aggregate;
    }

    process::scan_result process::scan_all(
        std::string_view ida_pattern,
        std::optional<std::string_view> module_name,
        size_t max_results,
        const std::atomic<bool>* cancel,
        const std::function<void(const pattern::scan_progress&)>& on_progress) const {
        scan_result aggregate;
        if (!accessor_impl) return aggregate;
        const pattern parsed_pattern = parse_ida_pattern(ida_pattern);

        uintptr_t scan_base = 0;
        size_t scan_size = std::numeric_limits<size_t>::max();
        if (module_name.has_value()) {
            const auto resolved_module = accessor_impl->find_module(*module_name);
            if (!resolved_module.has_value()) {
                log(log_level::error,
                    std::string("process::scan_all: module not found: ") + std::string(*module_name));
                throw memory_operation_exception(
                    std::string("Module not found: ") + std::string(*module_name),
                    memory_error_code::MODULE_INFO_RETRIEVAL_FAILED);
            }
            scan_base = resolved_module->base;
            scan_size = resolved_module->size;
        }

        const auto candidate_regions =
            regions_intersected_with(*accessor_impl, scan_base, scan_size);

        for (const auto& current_region : candidate_regions) {
            if (cancel && cancel->load(std::memory_order_relaxed)) break;
            ++aggregate.regions_scanned;
            aggregate.bytes_scanned += current_region.size;
            const size_t remaining =
                max_results == 0 ? 0
                                 : (max_results - aggregate.matches.size());
            if (max_results != 0 && remaining == 0) break;
            parsed_pattern.scan_all(*accessor_impl,
                                     current_region.base, current_region.size,
                                     remaining,
                                     [&aggregate, max_results](uintptr_t hit_address) {
                                         aggregate.matches.push_back(hit_address);
                                         if (max_results != 0
                                             && aggregate.matches.size() >= max_results) {
                                             return false;
                                         }
                                         return true;
                                     },
                                     cancel, on_progress);
        }
        return aggregate;
    }
}
