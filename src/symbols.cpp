/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
 */

#include "bb_process.h"
#include "memory_exceptions.h"

#include <algorithm>
#include <cstring>
#include <fstream>
#include <mutex>
#include <unordered_map>

#if defined(_WIN32)
    #include <windows.h>
    #include <dbghelp.h>
#else
    #include <elf.h>
#endif

namespace bytebinder {
    namespace {
#if defined(_WIN32)
        std::once_flag dbghelp_initialization_flag;
        bool dbghelp_initialized = false;

        void initialize_dbghelp_once() {
            std::call_once(dbghelp_initialization_flag, []() {
                SymSetOptions(SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES | SYMOPT_UNDNAME);
                if (SymInitialize(GetCurrentProcess(), nullptr, TRUE)) {
                    dbghelp_initialized = true;
                }
            });
        }

        std::string lookup_module_basename(uintptr_t address) {
            IMAGEHLP_MODULE64 module_info_local;
            std::memset(&module_info_local, 0, sizeof(module_info_local));
            module_info_local.SizeOfStruct = sizeof(module_info_local);
            if (SymGetModuleInfo64(GetCurrentProcess(),
                                   static_cast<DWORD64>(address),
                                   &module_info_local)) {
                return module_info_local.ModuleName;
            }
            return {};
        }
#else
        struct module_symbol_table {
            std::vector<symbol_info> entries_sorted_by_address;
            std::unordered_map<std::string, size_t> by_name;
        };

        std::mutex symbol_cache_mutex;
        std::unordered_map<std::string, module_symbol_table> symbol_cache;

        template<typename ElfHeader, typename SectionHeader, typename SymbolEntry,
                 unsigned ElfClassValue>
        bool parse_elf_for(std::ifstream& file_stream,
                            const std::string& module_basename,
                            uintptr_t module_runtime_base,
                            module_symbol_table& destination) {
            file_stream.seekg(0);
            ElfHeader elf_header{};
            file_stream.read(reinterpret_cast<char*>(&elf_header), sizeof(elf_header));
            if (file_stream.gcount() != static_cast<std::streamsize>(sizeof(elf_header))) {
                return false;
            }
            if (std::memcmp(elf_header.e_ident, "\x7f""ELF", 4) != 0) {
                return false;
            }
            if (elf_header.e_ident[EI_CLASS] != ElfClassValue) {
                return false;
            }

            const size_t section_count = elf_header.e_shnum;
            std::vector<SectionHeader> sections(section_count);
            file_stream.seekg(elf_header.e_shoff);
            file_stream.read(reinterpret_cast<char*>(sections.data()),
                             section_count * sizeof(SectionHeader));
            if (file_stream.gcount() !=
                static_cast<std::streamsize>(section_count * sizeof(SectionHeader))) {
                return false;
            }

            const bool is_position_independent = (elf_header.e_type == ET_DYN);

            auto load_one_table = [&](size_t symbol_section_index) {
                if (symbol_section_index >= section_count) {
                    return;
                }
                const SectionHeader& symbol_section = sections[symbol_section_index];
                const size_t string_section_index = symbol_section.sh_link;
                if (string_section_index >= section_count) {
                    return;
                }
                const SectionHeader& string_section = sections[string_section_index];

                std::vector<char> string_table(string_section.sh_size);
                file_stream.seekg(string_section.sh_offset);
                file_stream.read(string_table.data(), string_section.sh_size);
                if (file_stream.gcount() !=
                    static_cast<std::streamsize>(string_section.sh_size)) {
                    return;
                }

                const size_t symbol_count = symbol_section.sh_size / sizeof(SymbolEntry);
                std::vector<SymbolEntry> raw_symbols(symbol_count);
                file_stream.seekg(symbol_section.sh_offset);
                file_stream.read(reinterpret_cast<char*>(raw_symbols.data()),
                                 symbol_count * sizeof(SymbolEntry));
                if (file_stream.gcount() !=
                    static_cast<std::streamsize>(symbol_count * sizeof(SymbolEntry))) {
                    return;
                }

                for (const SymbolEntry& current_symbol : raw_symbols) {
                    const unsigned char symbol_type = current_symbol.st_info & 0x0F;
                    if (symbol_type != STT_FUNC && symbol_type != STT_OBJECT) {
                        continue;
                    }
                    if (current_symbol.st_value == 0) {
                        continue;
                    }
                    if (current_symbol.st_name >= string_table.size()) {
                        continue;
                    }
                    const char* name_start = string_table.data() + current_symbol.st_name;
                    if (*name_start == '\0') {
                        continue;
                    }

                    symbol_info entry;
                    entry.name = name_start;
                    entry.module_name = module_basename;
                    entry.address = is_position_independent
                        ? module_runtime_base + current_symbol.st_value
                        : current_symbol.st_value;
                    entry.size = current_symbol.st_size;

                    if (destination.by_name.find(entry.name) != destination.by_name.end()) {
                        continue;
                    }
                    destination.by_name.emplace(entry.name,
                                                 destination.entries_sorted_by_address.size());
                    destination.entries_sorted_by_address.push_back(std::move(entry));
                }
            };

            for (size_t section_index = 0; section_index < section_count; ++section_index) {
                const auto& current_section = sections[section_index];
                if (current_section.sh_type == SHT_DYNSYM) {
                    load_one_table(section_index);
                }
            }
            for (size_t section_index = 0; section_index < section_count; ++section_index) {
                const auto& current_section = sections[section_index];
                if (current_section.sh_type == SHT_SYMTAB) {
                    load_one_table(section_index);
                }
            }
            return true;
        }

        const module_symbol_table* load_or_get_cached(const module_info& info) {
            std::lock_guard<std::mutex> guard(symbol_cache_mutex);
            const auto cached = symbol_cache.find(info.path);
            if (cached != symbol_cache.end()) {
                return &cached->second;
            }

            std::ifstream elf_stream(info.path, std::ios::binary);
            if (!elf_stream) {
                return nullptr;
            }

            unsigned char ident[EI_NIDENT] = {0};
            elf_stream.read(reinterpret_cast<char*>(ident), EI_NIDENT);
            if (elf_stream.gcount() != EI_NIDENT) {
                return nullptr;
            }
            if (std::memcmp(ident, "\x7f""ELF", 4) != 0) {
                return nullptr;
            }

            module_symbol_table fresh_table;
            bool parsed = false;
            if (ident[EI_CLASS] == ELFCLASS64) {
                parsed = parse_elf_for<Elf64_Ehdr, Elf64_Shdr, Elf64_Sym, ELFCLASS64>(
                    elf_stream, info.name, info.base, fresh_table);
            } else if (ident[EI_CLASS] == ELFCLASS32) {
                parsed = parse_elf_for<Elf32_Ehdr, Elf32_Shdr, Elf32_Sym, ELFCLASS32>(
                    elf_stream, info.name, info.base, fresh_table);
            }
            if (!parsed) {
                return nullptr;
            }

            std::sort(fresh_table.entries_sorted_by_address.begin(),
                       fresh_table.entries_sorted_by_address.end(),
                       [](const symbol_info& left, const symbol_info& right) {
                           return left.address < right.address;
                       });
            // Rebuild by_name index after sort.
            fresh_table.by_name.clear();
            for (size_t entry_index = 0;
                 entry_index < fresh_table.entries_sorted_by_address.size();
                 ++entry_index) {
                fresh_table.by_name.emplace(
                    fresh_table.entries_sorted_by_address[entry_index].name,
                    entry_index);
            }

            const auto inserted = symbol_cache.emplace(info.path, std::move(fresh_table));
            return &inserted.first->second;
        }
#endif
    }

    std::optional<symbol_info> process::resolve_symbol(
        std::string_view symbol_name,
        std::optional<std::string_view> module_name) const {
        if (!accessor_impl) {
            return std::nullopt;
        }
#if defined(_WIN32)
        if (!is_local()) {
            return std::nullopt;
        }
        initialize_dbghelp_once();
        if (!dbghelp_initialized) {
            return std::nullopt;
        }

        alignas(SYMBOL_INFO) char symbol_buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
        SYMBOL_INFO* symbol_struct = reinterpret_cast<SYMBOL_INFO*>(symbol_buffer);
        std::memset(symbol_struct, 0, sizeof(*symbol_struct));
        symbol_struct->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol_struct->MaxNameLen = MAX_SYM_NAME;

        const std::string null_terminated_name(symbol_name);
        if (!SymFromName(GetCurrentProcess(), null_terminated_name.c_str(), symbol_struct)) {
            return std::nullopt;
        }

        if (module_name.has_value()) {
            const std::string discovered_module =
                lookup_module_basename(static_cast<uintptr_t>(symbol_struct->Address));
            if (discovered_module != *module_name) {
                return std::nullopt;
            }
        }

        symbol_info result;
        result.name = null_terminated_name;
        result.address = static_cast<uintptr_t>(symbol_struct->Address);
        result.size = symbol_struct->Size;
        result.module_name =
            lookup_module_basename(static_cast<uintptr_t>(symbol_struct->Address));
        return result;
#else
        const auto loaded_modules = accessor_impl->modules();
        for (const auto& current_module : loaded_modules) {
            if (module_name.has_value()
                && current_module.name != *module_name
                && current_module.path != *module_name) {
                continue;
            }
            if (current_module.path.empty() || current_module.path[0] != '/') {
                continue;
            }
            const auto* table = load_or_get_cached(current_module);
            if (!table) {
                continue;
            }
            const std::string lookup_key(symbol_name);
            const auto found = table->by_name.find(lookup_key);
            if (found != table->by_name.end()) {
                return table->entries_sorted_by_address[found->second];
            }
        }
        return std::nullopt;
#endif
    }

    std::optional<symbol_info> process::symbolize(uintptr_t address) const {
        if (!accessor_impl) {
            return std::nullopt;
        }
#if defined(_WIN32)
        if (!is_local()) {
            return std::nullopt;
        }
        initialize_dbghelp_once();
        if (!dbghelp_initialized) {
            return std::nullopt;
        }

        alignas(SYMBOL_INFO) char symbol_buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME];
        SYMBOL_INFO* symbol_struct = reinterpret_cast<SYMBOL_INFO*>(symbol_buffer);
        std::memset(symbol_struct, 0, sizeof(*symbol_struct));
        symbol_struct->SizeOfStruct = sizeof(SYMBOL_INFO);
        symbol_struct->MaxNameLen = MAX_SYM_NAME;

        DWORD64 displacement_from_symbol = 0;
        if (!SymFromAddr(GetCurrentProcess(),
                         static_cast<DWORD64>(address),
                         &displacement_from_symbol, symbol_struct)) {
            return std::nullopt;
        }

        symbol_info result;
        result.name.assign(symbol_struct->Name, symbol_struct->NameLen);
        result.address = static_cast<uintptr_t>(symbol_struct->Address);
        result.size = symbol_struct->Size;
        result.module_name = lookup_module_basename(result.address);
        return result;
#else
        const auto loaded_modules = accessor_impl->modules();
        for (const auto& current_module : loaded_modules) {
            if (address < current_module.base
                || address >= current_module.base + current_module.size) {
                continue;
            }
            if (current_module.path.empty() || current_module.path[0] != '/') {
                continue;
            }
            const auto* table = load_or_get_cached(current_module);
            if (!table || table->entries_sorted_by_address.empty()) {
                continue;
            }
            // Binary search for the largest entry whose address <= query.
            auto upper_iter = std::upper_bound(
                table->entries_sorted_by_address.begin(),
                table->entries_sorted_by_address.end(),
                address,
                [](uintptr_t query, const symbol_info& candidate) {
                    return query < candidate.address;
                });
            if (upper_iter == table->entries_sorted_by_address.begin()) {
                continue;
            }
            const auto& candidate = *std::prev(upper_iter);
            const uintptr_t candidate_end =
                candidate.address + (candidate.size > 0 ? candidate.size : 1);
            if (address >= candidate.address && address < candidate_end) {
                return candidate;
            }
        }
        return std::nullopt;
#endif
    }
}
