/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#include "bb_darwin.h"

#if defined(__APPLE__)

#include "bb_log_sink.h"
#include "bb_memory_exceptions.h"

#include <libproc.h>
#include <mach/mach_error.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstring>
#include <limits>
#include <thread>

namespace bytebinder::darwin {
    namespace {
        // MH_DYLIB_IN_CACHE is missing from older SDK headers.
        constexpr uint32_t dylib_in_cache_flag = 0x80000000u;
        constexpr uint32_t maximum_load_command_bytes = 16u * 1024u * 1024u;
        constexpr uint32_t maximum_symbol_count = 8u * 1024u * 1024u;

        bool segment_name_equals(const char (&segment_name)[16], const char* expected) {
            return std::strncmp(segment_name, expected, sizeof(segment_name)) == 0;
        }

        std::string fixed_name(const char (&name)[16]) {
            return std::string(name, ::strnlen(name, sizeof(name)));
        }

        std::string basename_of(const std::string& path) {
            const auto last_slash = path.find_last_of('/');
            return last_slash == std::string::npos ? path : path.substr(last_slash + 1);
        }

        std::string read_c_string(memory_accessor& target_accessor, uintptr_t address) {
            constexpr size_t chunk_size = 256;
            constexpr size_t maximum_length = 4096;
            std::string result;
            char chunk[chunk_size];
            while (result.size() < maximum_length) {
                const size_t got = target_accessor.read(address + result.size(), chunk, chunk_size);
                if (got == 0) break;
                const void* terminator = std::memchr(chunk, '\0', got);
                if (terminator != nullptr) {
                    result.append(chunk, static_cast<const char*>(terminator) - chunk);
                    return result;
                }
                result.append(chunk, got);
                if (got < chunk_size) break;
            }
            return result;
        }

        bool read_load_commands(memory_accessor& target_accessor,
                                uintptr_t header_address,
                                mach_header_64& header,
                                std::vector<uint8_t>& commands) {
            if (target_accessor.read(header_address, &header, sizeof(header)) != sizeof(header)) {
                return false;
            }
            if (header.magic != MH_MAGIC_64) return false;
            if (header.sizeofcmds == 0 || header.sizeofcmds > maximum_load_command_bytes) return false;
            commands.resize(header.sizeofcmds);
            return target_accessor.read(header_address + sizeof(header), commands.data(), commands.size())
                   == commands.size();
        }

        template<typename Visitor>
        void for_each_load_command(const mach_header_64& header,
                                   const std::vector<uint8_t>& commands,
                                   Visitor visitor) {
            size_t offset = 0;
            for (uint32_t command_index = 0; command_index < header.ncmds; ++command_index) {
                if (offset + sizeof(load_command) > commands.size()) return;
                load_command command;
                std::memcpy(&command, commands.data() + offset, sizeof(command));
                if (command.cmdsize < sizeof(load_command) || offset + command.cmdsize > commands.size()) {
                    return;
                }
                visitor(command, commands.data() + offset);
                offset += command.cmdsize;
            }
        }

        std::vector<segment_command_64> collect_segments(const mach_header_64& header,
                                                         const std::vector<uint8_t>& commands) {
            std::vector<segment_command_64> segments;
            for_each_load_command(header, commands, [&](const load_command& command, const uint8_t* bytes) {
                if (command.cmd != LC_SEGMENT_64 || command.cmdsize < sizeof(segment_command_64)) return;
                segment_command_64 segment;
                std::memcpy(&segment, bytes, sizeof(segment));
                segments.push_back(segment);
            });
            return segments;
        }

        std::optional<uintptr_t> compute_slide(uintptr_t header_address,
                                               const std::vector<segment_command_64>& segments) {
            for (const auto& segment : segments) {
                if (segment_name_equals(segment.segname, "__TEXT")) {
                    return header_address - static_cast<uintptr_t>(segment.vmaddr);
                }
            }
            return std::nullopt;
        }
    }

    int to_posix_protection(vm_prot_t native_protection) {
        int posix_protection = protection::none;
        if (native_protection & VM_PROT_READ)    posix_protection |= protection::read;
        if (native_protection & VM_PROT_WRITE)   posix_protection |= protection::write;
        if (native_protection & VM_PROT_EXECUTE) posix_protection |= protection::execute;
        return posix_protection;
    }

    vm_prot_t to_native_protection(int posix_protection) {
        vm_prot_t native_protection = VM_PROT_NONE;
        if (posix_protection & protection::read)    native_protection |= VM_PROT_READ;
        if (posix_protection & protection::write)   native_protection |= VM_PROT_WRITE;
        if (posix_protection & protection::execute) native_protection |= VM_PROT_EXECUTE;
        return native_protection;
    }

    std::optional<int> query_protection(mach_port_t task, uintptr_t address) {
        if (task == MACH_PORT_NULL) return std::nullopt;
        natural_t depth = 0;
        while (true) {
            mach_vm_address_t region_address = address;
            mach_vm_size_t region_size = 0;
            vm_region_submap_info_data_64_t information;
            mach_msg_type_number_t information_count = VM_REGION_SUBMAP_INFO_COUNT_64;
            const kern_return_t result = mach_vm_region_recurse(
                task, &region_address, &region_size, &depth,
                reinterpret_cast<vm_region_recurse_info_t>(&information), &information_count);
            if (result != KERN_SUCCESS) return std::nullopt;
            if (region_address > address) return std::nullopt;
            if (information.is_submap) {
                ++depth;
                continue;
            }
            return to_posix_protection(information.protection);
        }
    }

    int change_protection(mach_port_t task, uintptr_t address, size_t size, int new_protection) {
        if (task == MACH_PORT_NULL) {
            throw memory_operation_exception("No task port for the target process.",
                                             memory_error_code::PROTECTION_CHANGE_FAILED);
        }
        const uintptr_t page_size = static_cast<uintptr_t>(vm_page_size);
        const uintptr_t aligned_start = address & ~(page_size - 1);
        const uintptr_t aligned_end = (address + size + page_size - 1) & ~(page_size - 1);
        const mach_vm_size_t aligned_size = aligned_end - aligned_start;
        const int previous_protection = query_protection(task, address).value_or(protection::none);

        const vm_prot_t native_protection = to_native_protection(new_protection);
        kern_return_t result = KERN_FAILURE;
        if (new_protection & protection::write) {
            result = mach_vm_protect(task, aligned_start, aligned_size, FALSE,
                                     native_protection | VM_PROT_COPY);
        }
        if (result != KERN_SUCCESS) {
            result = mach_vm_protect(task, aligned_start, aligned_size, FALSE, native_protection);
        }
        if (result != KERN_SUCCESS) {
            log(log_level::error,
                std::string("darwin::change_protection: mach_vm_protect failed: ")
                    + mach_error_string(result));
            throw memory_operation_exception(
                std::string("mach_vm_protect failed: ") + mach_error_string(result),
                memory_error_code::PROTECTION_CHANGE_FAILED);
        }
        return previous_protection;
    }

    std::vector<region_info> enumerate_regions(mach_port_t task, int process_id) {
        std::vector<region_info> regions;
        if (task == MACH_PORT_NULL) return regions;

        mach_vm_address_t cursor = 0;
        natural_t depth = 0;
        while (true) {
            mach_vm_size_t region_size = 0;
            vm_region_submap_info_data_64_t information;
            mach_msg_type_number_t information_count = VM_REGION_SUBMAP_INFO_COUNT_64;
            const kern_return_t result = mach_vm_region_recurse(
                task, &cursor, &region_size, &depth,
                reinterpret_cast<vm_region_recurse_info_t>(&information), &information_count);
            if (result != KERN_SUCCESS) break;
            if (information.is_submap) {
                ++depth;
                continue;
            }

            region_info entry;
            entry.base = static_cast<uintptr_t>(cursor);
            entry.size = static_cast<size_t>(region_size);
            entry.protection = to_posix_protection(information.protection);
            char path_buffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
            if (proc_regionfilename(process_id, cursor, path_buffer, sizeof(path_buffer)) > 0) {
                entry.mapped_path = path_buffer;
            }
            regions.push_back(std::move(entry));

            if (cursor + region_size < cursor) break;
            cursor += region_size;
        }
        return regions;
    }

    std::optional<module_info> describe_image(memory_accessor& target_accessor,
                                              uintptr_t header_address,
                                              std::string path) {
        mach_header_64 header{};
        std::vector<uint8_t> commands;
        if (!read_load_commands(target_accessor, header_address, header, commands)) return std::nullopt;

        const auto segments = collect_segments(header, commands);
        const auto slide = compute_slide(header_address, segments);
        if (!slide.has_value()) return std::nullopt;

        const bool is_in_shared_cache = (header.flags & dylib_in_cache_flag) != 0;
        uintptr_t lowest_address = std::numeric_limits<uintptr_t>::max();
        uintptr_t highest_address = 0;
        for (const auto& segment : segments) {
            if (segment_name_equals(segment.segname, "__PAGEZERO")) continue;
            if (segment_name_equals(segment.segname, "__LINKEDIT")) continue;
            if (is_in_shared_cache && !segment_name_equals(segment.segname, "__TEXT")) continue;
            const uintptr_t segment_start = static_cast<uintptr_t>(segment.vmaddr) + *slide;
            const uintptr_t segment_end = segment_start + static_cast<uintptr_t>(segment.vmsize);
            lowest_address = std::min(lowest_address, segment_start);
            highest_address = std::max(highest_address, segment_end);
        }
        if (lowest_address == std::numeric_limits<uintptr_t>::max()) return std::nullopt;

        module_info entry;
        entry.name = basename_of(path);
        entry.path = std::move(path);
        entry.base = lowest_address;
        entry.size = highest_address - lowest_address;
        return entry;
    }

    std::vector<module_info> enumerate_modules(memory_accessor& target_accessor, mach_port_t task) {
        std::vector<module_info> modules;
        if (task == MACH_PORT_NULL) return modules;

        task_dyld_info_data_t dyld_information;
        mach_msg_type_number_t information_count = TASK_DYLD_INFO_COUNT;
        if (task_info(task, TASK_DYLD_INFO, reinterpret_cast<task_info_t>(&dyld_information),
                      &information_count) != KERN_SUCCESS) {
            return modules;
        }

        // dyld briefly nulls infoArray while it edits the list; retry a few times.
        dyld_all_image_infos all_image_infos{};
        const size_t header_bytes = std::min<size_t>(sizeof(all_image_infos),
                                                     dyld_information.all_image_info_size);
        for (int attempt = 0; attempt < 10; ++attempt) {
            std::memset(&all_image_infos, 0, sizeof(all_image_infos));
            if (target_accessor.read(dyld_information.all_image_info_addr, &all_image_infos, header_bytes)
                != header_bytes) {
                return modules;
            }
            if (all_image_infos.infoArray != nullptr) break;
            std::this_thread::sleep_for(std::chrono::milliseconds{1});
        }
        if (all_image_infos.infoArray == nullptr || all_image_infos.infoArrayCount == 0) return modules;

        std::vector<dyld_image_info> image_infos(all_image_infos.infoArrayCount);
        const size_t info_bytes = image_infos.size() * sizeof(dyld_image_info);
        if (target_accessor.read(reinterpret_cast<uintptr_t>(all_image_infos.infoArray),
                                 image_infos.data(), info_bytes) != info_bytes) {
            return modules;
        }

        std::optional<size_t> main_executable_index;
        for (const auto& image : image_infos) {
            const uintptr_t header_address = reinterpret_cast<uintptr_t>(image.imageLoadAddress);
            if (header_address == 0) continue;
            std::string path = image.imageFilePath != nullptr
                ? read_c_string(target_accessor, reinterpret_cast<uintptr_t>(image.imageFilePath))
                : std::string();
            auto described = describe_image(target_accessor, header_address, std::move(path));
            if (!described.has_value()) continue;

            uint32_t file_type = 0;
            if (target_accessor.read(header_address + offsetof(mach_header_64, filetype),
                                     &file_type, sizeof(file_type)) == sizeof(file_type)
                && file_type == MH_EXECUTE && !main_executable_index.has_value()) {
                main_executable_index = modules.size();
            }
            modules.push_back(std::move(*described));
        }

        if (all_image_infos.dyldImageLoadAddress != nullptr) {
            auto dyld_image = describe_image(target_accessor,
                                             reinterpret_cast<uintptr_t>(all_image_infos.dyldImageLoadAddress),
                                             "/usr/lib/dyld");
            if (dyld_image.has_value()) modules.push_back(std::move(*dyld_image));
        }

        if (main_executable_index.has_value() && *main_executable_index != 0) {
            std::rotate(modules.begin(),
                        modules.begin() + static_cast<std::ptrdiff_t>(*main_executable_index),
                        modules.begin() + static_cast<std::ptrdiff_t>(*main_executable_index) + 1);
        }
        return modules;
    }

    std::vector<process::module_section> parse_sections(memory_accessor& target_accessor,
                                                        uintptr_t header_address) {
        std::vector<process::module_section> sections;
        mach_header_64 header{};
        std::vector<uint8_t> commands;
        if (!read_load_commands(target_accessor, header_address, header, commands)) return sections;
        const auto slide = compute_slide(header_address, collect_segments(header, commands));
        if (!slide.has_value()) return sections;

        for_each_load_command(header, commands, [&](const load_command& command, const uint8_t* bytes) {
            if (command.cmd != LC_SEGMENT_64 || command.cmdsize < sizeof(segment_command_64)) return;
            segment_command_64 segment;
            std::memcpy(&segment, bytes, sizeof(segment));
            const size_t available_sections =
                (command.cmdsize - sizeof(segment_command_64)) / sizeof(section_64);
            const size_t section_count = std::min<size_t>(segment.nsects, available_sections);
            for (size_t section_index = 0; section_index < section_count; ++section_index) {
                section_64 raw_section;
                std::memcpy(&raw_section,
                            bytes + sizeof(segment_command_64) + section_index * sizeof(section_64),
                            sizeof(raw_section));
                if (raw_section.size == 0) continue;
                process::module_section entry;
                entry.name = fixed_name(raw_section.segname) + "," + fixed_name(raw_section.sectname);
                entry.base = static_cast<uintptr_t>(raw_section.addr) + *slide;
                entry.size = static_cast<size_t>(raw_section.size);
                entry.protection = to_posix_protection(segment.initprot);
                sections.push_back(std::move(entry));
            }
        });
        return sections;
    }

    void for_each_symbol(memory_accessor& target_accessor,
                         uintptr_t header_address,
                         const std::function<void(std::string_view, uintptr_t)>& on_symbol) {
        mach_header_64 header{};
        std::vector<uint8_t> commands;
        if (!read_load_commands(target_accessor, header_address, header, commands)) return;

        const auto segments = collect_segments(header, commands);
        const auto slide = compute_slide(header_address, segments);
        if (!slide.has_value()) return;

        std::optional<segment_command_64> linkedit_segment;
        for (const auto& segment : segments) {
            if (segment_name_equals(segment.segname, "__LINKEDIT")) linkedit_segment = segment;
        }
        std::optional<symtab_command> symbol_table_command;
        for_each_load_command(header, commands, [&](const load_command& command, const uint8_t* bytes) {
            if (command.cmd != LC_SYMTAB || command.cmdsize < sizeof(symtab_command)) return;
            symtab_command parsed;
            std::memcpy(&parsed, bytes, sizeof(parsed));
            symbol_table_command = parsed;
        });
        if (!linkedit_segment.has_value() || !symbol_table_command.has_value()) return;
        if (symbol_table_command->nsyms == 0 || symbol_table_command->nsyms > maximum_symbol_count) return;

        // Same formula dyld and fishhook use; it also holds for shared-cache
        // images, whose symbol tables live in the cache's shared __LINKEDIT.
        const uintptr_t linkedit_base = *slide + static_cast<uintptr_t>(linkedit_segment->vmaddr)
                                      - static_cast<uintptr_t>(linkedit_segment->fileoff);

        std::vector<nlist_64> symbols(symbol_table_command->nsyms);
        const size_t symbol_bytes = symbols.size() * sizeof(nlist_64);
        if (target_accessor.read(linkedit_base + symbol_table_command->symoff, symbols.data(), symbol_bytes)
            != symbol_bytes) {
            return;
        }

        auto is_defined_symbol = [](const nlist_64& symbol) {
            return (symbol.n_type & N_STAB) == 0
                && (symbol.n_type & N_TYPE) == N_SECT
                && symbol.n_value != 0;
        };

        // Shared-cache images point into one large string pool, so read only
        // the slice this image's symbols reference.
        uint32_t lowest_string_offset = std::numeric_limits<uint32_t>::max();
        uint32_t highest_string_offset = 0;
        for (const auto& symbol : symbols) {
            if (!is_defined_symbol(symbol)) continue;
            lowest_string_offset = std::min(lowest_string_offset, symbol.n_un.n_strx);
            highest_string_offset = std::max(highest_string_offset, symbol.n_un.n_strx);
        }
        if (lowest_string_offset > highest_string_offset) return;
        if (lowest_string_offset >= symbol_table_command->strsize) return;

        constexpr uint32_t maximum_name_length = 1024;
        const uint32_t slice_end = std::min<uint32_t>(
            symbol_table_command->strsize,
            highest_string_offset + std::min<uint32_t>(maximum_name_length,
                                                       symbol_table_command->strsize - highest_string_offset));
        std::vector<char> strings(slice_end - lowest_string_offset);
        const size_t string_bytes = target_accessor.read(
            linkedit_base + symbol_table_command->stroff + lowest_string_offset,
            strings.data(), strings.size());
        if (string_bytes == 0) return;
        strings.resize(string_bytes);

        for (const auto& symbol : symbols) {
            if (!is_defined_symbol(symbol)) continue;
            const uint32_t relative_offset = symbol.n_un.n_strx - lowest_string_offset;
            if (relative_offset >= strings.size()) continue;
            const char* name_start = strings.data() + relative_offset;
            const size_t remaining = strings.size() - relative_offset;
            const void* terminator = std::memchr(name_start, '\0', remaining);
            if (terminator == nullptr) continue;
            std::string_view name(name_start, static_cast<const char*>(terminator) - name_start);
            if (!name.empty() && name.front() == '_') name.remove_prefix(1);
            if (name.empty()) continue;
            on_symbol(name, static_cast<uintptr_t>(symbol.n_value) + *slide);
        }
    }
}

#endif
