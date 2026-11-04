/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#include "bb_code_scan.h"
#include "bb_process.h"
#include "bb_memory_accessor.h"
#include "bb_disasm.h"
#include "bb_log_sink.h"

#include <Zydis/Zydis.h>

#include <algorithm>
#include <cctype>
#include <vector>

namespace bytebinder {
    namespace {
        ZydisDecoder& shared_decoder() {
            static ZydisDecoder instance = []() {
                ZydisDecoder decoder;
#if defined(__x86_64__) || defined(_M_X64)
                ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
#else
                ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LEGACY_32, ZYDIS_STACK_WIDTH_32);
#endif
                return decoder;
            }();
            return instance;
        }

        std::optional<xref_kind> classify_for_xref(const ZydisDecodedInstruction& decoded) {
            switch (decoded.mnemonic) {
                case ZYDIS_MNEMONIC_CALL:  return xref_kind::call;
                case ZYDIS_MNEMONIC_JMP:   return xref_kind::jmp_uncond;
                case ZYDIS_MNEMONIC_JZ: case ZYDIS_MNEMONIC_JNZ:
                case ZYDIS_MNEMONIC_JL: case ZYDIS_MNEMONIC_JLE:
                case ZYDIS_MNEMONIC_JB: case ZYDIS_MNEMONIC_JBE:
                case ZYDIS_MNEMONIC_JS: case ZYDIS_MNEMONIC_JNS:
                case ZYDIS_MNEMONIC_JO: case ZYDIS_MNEMONIC_JNO:
                case ZYDIS_MNEMONIC_JP: case ZYDIS_MNEMONIC_JNP:
                case ZYDIS_MNEMONIC_JCXZ: case ZYDIS_MNEMONIC_JECXZ: case ZYDIS_MNEMONIC_JRCXZ:
                    return xref_kind::jmp_cond;
                case ZYDIS_MNEMONIC_LEA:   return xref_kind::lea_rip;
                case ZYDIS_MNEMONIC_MOV:   return xref_kind::mov_rip_load;
                default:                   return std::nullopt;
            }
        }

        std::vector<region_info> executable_regions_of(memory_accessor& accessor, const module_info& module) {
            const uintptr_t module_end = module.base + module.size;
            std::vector<region_info> executable_regions;
            for (const auto& region : accessor.regions()) {
                if ((region.protection & protection::execute) == 0) continue;
                if ((region.protection & protection::read) == 0) continue; // skip [vsyscall]
                const uintptr_t region_end = region.base + region.size;
                const uintptr_t overlap_start = std::max(region.base, module.base);
                const uintptr_t overlap_end   = std::min(region_end, module_end);
                if (overlap_start >= overlap_end) continue;
                region_info clipped = region;
                clipped.base = overlap_start;
                clipped.size = overlap_end - overlap_start;
                executable_regions.push_back(std::move(clipped));
            }
            return executable_regions;
        }

        std::optional<uintptr_t> instruction_target(uintptr_t address,
                                                     const ZydisDecodedInstruction& decoded,
                                                     const ZydisDecodedOperand* operands) {
            for (size_t operand_index = 0; operand_index < decoded.operand_count; ++operand_index) {
                const auto& operand = operands[operand_index];
                if (operand.type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                    && operand.imm.is_relative) {
                    return resolve_rip_relative(address,
                                                  decoded.length,
                                                  static_cast<int32_t>(operand.imm.value.s));
                }
                if (operand.type == ZYDIS_OPERAND_TYPE_MEMORY
                    && operand.mem.base == ZYDIS_REGISTER_RIP
                    && operand.mem.disp.has_displacement) {
                    return resolve_rip_relative(address,
                                                  decoded.length,
                                                  static_cast<int32_t>(operand.mem.disp.value));
                }
            }
            return std::nullopt;
        }
    }

    std::vector<xref> find_xrefs_in_process(const process& target_process,
                                              uintptr_t target_address,
                                              std::optional<std::string_view> module_name,
                                              size_t max_results) {
        std::vector<xref> matches;
        memory_accessor& bound_accessor = target_process.accessor();

        std::vector<region_info> executable_regions;
        if (module_name.has_value()) {
            const auto resolved = bound_accessor.find_module(*module_name);
            if (!resolved.has_value()) {
                bytebinder::log(log_level::error,
                                  std::string("find_xrefs: module not found: ") + std::string(*module_name));
                return matches;
            }
            executable_regions = executable_regions_of(bound_accessor, *resolved);
        } else {
            for (auto& region : bound_accessor.regions()) {
                if ((region.protection & protection::execute) == 0) continue;
                if ((region.protection & protection::read) == 0) continue;
                executable_regions.push_back(std::move(region));
            }
        }

        std::vector<uint8_t> region_buffer;
        ZydisDecoder& decoder = shared_decoder();
        ZydisDecodedInstruction decoded;
        ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];

        for (const auto& region : executable_regions) {
            region_buffer.resize(region.size);
            const size_t bytes_read = bound_accessor.read(region.base,
                                                            region_buffer.data(),
                                                            region.size);
            if (bytes_read == 0) continue;

            size_t cursor = 0;
            while (cursor < bytes_read) {
                const ZyanStatus status = ZydisDecoderDecodeFull(
                    &decoder,
                    region_buffer.data() + cursor,
                    bytes_read - cursor,
                    &decoded,
                    operands);
                if (!ZYAN_SUCCESS(status)) {
                    cursor += 1;
                    continue;
                }
                const uintptr_t instruction_address = region.base + cursor;
                const auto kind_opt = classify_for_xref(decoded);
                if (kind_opt.has_value()) {
                    const auto target_opt = instruction_target(instruction_address, decoded, operands);
                    if (target_opt.has_value() && *target_opt == target_address) {
                        xref entry;
                        entry.instruction_address = instruction_address;
                        entry.kind = *kind_opt;
                        entry.instruction_length = decoded.length;
                        if (entry.kind == xref_kind::mov_rip_load
                            && decoded.operand_count >= 2
                            && operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY) {
                            entry.kind = xref_kind::mov_rip_store;
                        }
                        matches.push_back(entry);
                        if (max_results != 0 && matches.size() >= max_results) {
                            return matches;
                        }
                    }
                }
                cursor += decoded.length;
            }
        }
        return matches;
    }

    namespace {
        constexpr uint8_t padding_byte = 0xCC;
        constexpr uint8_t return_byte = 0xC3;
        constexpr uintptr_t function_alignment = 16;

        bool is_stack_pointer(ZydisRegister reg) {
            return reg == ZYDIS_REGISTER_RSP || reg == ZYDIS_REGISTER_ESP;
        }

        bool is_frame_pointer(ZydisRegister reg) {
            return reg == ZYDIS_REGISTER_RBP || reg == ZYDIS_REGISTER_EBP;
        }

        bool is_callee_saved(ZydisRegister reg) {
            switch (reg) {
                case ZYDIS_REGISTER_RBX: case ZYDIS_REGISTER_RBP:
                case ZYDIS_REGISTER_RSI: case ZYDIS_REGISTER_RDI:
                case ZYDIS_REGISTER_R12: case ZYDIS_REGISTER_R13:
                case ZYDIS_REGISTER_R14: case ZYDIS_REGISTER_R15:
                case ZYDIS_REGISTER_EBX: case ZYDIS_REGISTER_EBP:
                case ZYDIS_REGISTER_ESI: case ZYDIS_REGISTER_EDI:
                    return true;
                default:
                    return false;
            }
        }

        bool pushes_callee_saved(const ZydisDecodedInstruction& decoded, const ZydisDecodedOperand* operands) {
            return decoded.mnemonic == ZYDIS_MNEMONIC_PUSH
                && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
                && is_callee_saved(operands[0].reg.value);
        }

        bool reserves_stack_frame(const ZydisDecodedInstruction& decoded, const ZydisDecodedOperand* operands) {
            return decoded.mnemonic == ZYDIS_MNEMONIC_SUB
                && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
                && is_stack_pointer(operands[0].reg.value)
                && operands[1].type == ZYDIS_OPERAND_TYPE_IMMEDIATE;
        }

        bool sets_up_frame_pointer(const ZydisDecodedInstruction& decoded, const ZydisDecodedOperand* operands) {
            if (operands[0].type != ZYDIS_OPERAND_TYPE_REGISTER || !is_frame_pointer(operands[0].reg.value)) {
                return false;
            }
            if (decoded.mnemonic == ZYDIS_MNEMONIC_MOV) {
                return operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER && is_stack_pointer(operands[1].reg.value);
            }
            return decoded.mnemonic == ZYDIS_MNEMONIC_LEA
                && operands[1].type == ZYDIS_OPERAND_TYPE_MEMORY
                && is_stack_pointer(operands[1].mem.base);
        }

        // MSVC stores incoming registers in the caller's shadow space, such as mov [rsp+8], rbx.
        bool spills_to_home_space(const ZydisDecodedInstruction& decoded, const ZydisDecodedOperand* operands) {
            if (decoded.mnemonic != ZYDIS_MNEMONIC_MOV
                || operands[0].type != ZYDIS_OPERAND_TYPE_MEMORY
                || !is_stack_pointer(operands[0].mem.base)
                || operands[0].mem.index != ZYDIS_REGISTER_NONE
                || operands[1].type != ZYDIS_OPERAND_TYPE_REGISTER) {
                return false;
            }
            const int64_t displacement = operands[0].mem.disp.value;
            return displacement == 0x8 || displacement == 0x10 || displacement == 0x18 || displacement == 0x20;
        }

        // MSVC opens larger functions with mov rax, rsp, then spills through rax.
        bool captures_stack_pointer(const ZydisDecodedInstruction& decoded, const ZydisDecodedOperand* operands) {
            return decoded.mnemonic == ZYDIS_MNEMONIC_MOV
                && operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
                && operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                && is_stack_pointer(operands[1].reg.value)
                && !is_frame_pointer(operands[0].reg.value);
        }

        bool decoded_is_prologue_anchor(const ZydisDecodedInstruction& first,
                                          const ZydisDecodedOperand* first_operands,
                                          const ZydisDecodedInstruction& second,
                                          const ZydisDecodedOperand* second_operands) {
            if (first.mnemonic == ZYDIS_MNEMONIC_ENDBR64 || first.mnemonic == ZYDIS_MNEMONIC_ENDBR32) {
                return true;
            }
            if (reserves_stack_frame(first, first_operands)) {
                return true;
            }
            if (pushes_callee_saved(first, first_operands)) {
                return pushes_callee_saved(second, second_operands)
                    || reserves_stack_frame(second, second_operands)
                    || sets_up_frame_pointer(second, second_operands);
            }
            if (spills_to_home_space(first, first_operands)) {
                return spills_to_home_space(second, second_operands)
                    || pushes_callee_saved(second, second_operands)
                    || reserves_stack_frame(second, second_operands);
            }
            if (captures_stack_pointer(first, first_operands)) {
                return second.mnemonic == ZYDIS_MNEMONIC_MOV
                    && second_operands[0].type == ZYDIS_OPERAND_TYPE_MEMORY
                    && second_operands[0].mem.base == first_operands[0].reg.value;
            }
            return false;
        }

        // Without this the scan decodes from the middle of real instructions, and most
        // of what it reports is not a function start at all.
        bool sits_on_function_boundary(const std::vector<uint8_t>& buffer, size_t cursor, uintptr_t address) {
            if (cursor == 0 || address % function_alignment == 0) {
                return true;
            }
            const uint8_t previous = buffer[cursor - 1];
            return previous == padding_byte || previous == return_byte;
        }
    }

    std::vector<uintptr_t> find_prologues_in_process(const process& target_process,
                                                        std::string_view module_name,
                                                        size_t max_results) {
        std::vector<uintptr_t> matches;
        memory_accessor& bound_accessor = target_process.accessor();
        const auto resolved = bound_accessor.find_module(module_name);
        if (!resolved.has_value()) {
            bytebinder::log(log_level::error,
                              std::string("find_prologues: module not found: ") + std::string(module_name));
            return matches;
        }

        const std::vector<region_info> executable_regions = executable_regions_of(bound_accessor, *resolved);

        std::vector<uint8_t> region_buffer;
        ZydisDecoder& decoder = shared_decoder();
        ZydisDecodedInstruction first_decoded;
        ZydisDecodedOperand first_operands[ZYDIS_MAX_OPERAND_COUNT];
        ZydisDecodedInstruction second_decoded;
        ZydisDecodedOperand second_operands[ZYDIS_MAX_OPERAND_COUNT];

        for (const auto& region : executable_regions) {
            region_buffer.resize(region.size);
            const size_t bytes_read = bound_accessor.read(region.base,
                                                            region_buffer.data(),
                                                            region.size);
            if (bytes_read == 0) continue;

            for (size_t cursor = 0; cursor + 8 <= bytes_read; ++cursor) {
                const uintptr_t candidate = region.base + cursor;
                if (!sits_on_function_boundary(region_buffer, cursor, candidate)) {
                    continue;
                }
                const ZyanStatus first_status = ZydisDecoderDecodeFull(
                    &decoder,
                    region_buffer.data() + cursor,
                    bytes_read - cursor,
                    &first_decoded, first_operands);
                if (!ZYAN_SUCCESS(first_status) || cursor + first_decoded.length + 1 > bytes_read) {
                    continue;
                }
                const ZyanStatus second_status = ZydisDecoderDecodeFull(
                    &decoder,
                    region_buffer.data() + cursor + first_decoded.length,
                    bytes_read - cursor - first_decoded.length,
                    &second_decoded, second_operands);
                if (ZYAN_SUCCESS(second_status)
                    && decoded_is_prologue_anchor(first_decoded, first_operands, second_decoded, second_operands)) {
                    matches.push_back(candidate);
                    if (max_results != 0 && matches.size() >= max_results) {
                        return matches;
                    }
                }
            }
        }
        return matches;
    }

    namespace {
        constexpr uint16_t dos_magic = 0x5A4D;
        constexpr uint32_t pe_signature = 0x00004550;
        constexpr uint16_t machine_amd64 = 0x8664;
        constexpr uint16_t pe32_plus_magic = 0x20B;
        constexpr size_t optional_header_offset = 24;
        constexpr size_t rva_count_offset = 108;
        constexpr size_t data_directories_offset = 112;
        constexpr size_t exception_directory_index = 3;
        constexpr size_t data_directory_size = 8;
        constexpr size_t runtime_function_size = 12;
        constexpr uint8_t unwind_flag_chain_info = 0x4;
        constexpr uintptr_t unwind_is_chain_reference = 0x1;

        template<typename ValueType>
        bool read_value(memory_accessor& accessor, uintptr_t address, ValueType& value) {
            return accessor.read(address, &value, sizeof(ValueType)) == sizeof(ValueType);
        }

        // Fills functions with the table's real entries and fragments with the chained
        // pieces of them, which are code but not function starts. Leaves both empty when
        // the module has no table this can read.
        void read_unwind_table(memory_accessor& accessor,
                                 const module_info& module,
                                 std::vector<function_entry>& functions,
                                 std::vector<function_entry>& fragments) {
            uint16_t magic = 0;
            uint32_t pe_offset = 0;
            uint32_t signature = 0;
            uint16_t machine = 0;
            if (!read_value(accessor, module.base, magic) || magic != dos_magic
                || !read_value(accessor, module.base + 0x3C, pe_offset) || pe_offset >= module.size
                || !read_value(accessor, module.base + pe_offset, signature) || signature != pe_signature
                || !read_value(accessor, module.base + pe_offset + 4, machine) || machine != machine_amd64) {
                return;
            }

            const uintptr_t optional_header = module.base + pe_offset + optional_header_offset;
            const uintptr_t exception_directory = optional_header + data_directories_offset
                + exception_directory_index * data_directory_size;
            uint16_t optional_magic = 0;
            uint32_t rva_count = 0;
            uint32_t table_rva = 0;
            uint32_t table_size = 0;
            if (!read_value(accessor, optional_header, optional_magic) || optional_magic != pe32_plus_magic
                || !read_value(accessor, optional_header + rva_count_offset, rva_count) || rva_count <= exception_directory_index
                || !read_value(accessor, exception_directory, table_rva)
                || !read_value(accessor, exception_directory + 4, table_size)
                || table_size == 0
                || static_cast<uint64_t>(table_rva) + table_size > module.size) {
                return;
            }

            std::vector<uint32_t> table(table_size / sizeof(uint32_t));
            const size_t bytes_read = accessor.read(module.base + table_rva, table.data(), table.size() * sizeof(uint32_t));
            const size_t entry_count = bytes_read / runtime_function_size;

            for (size_t entry_index = 0; entry_index < entry_count; ++entry_index) {
                const uint32_t begin = table[entry_index * 3];
                const uint32_t end = table[entry_index * 3 + 1];
                const uint32_t unwind = table[entry_index * 3 + 2];
                if (begin >= end || end > module.size) {
                    continue;
                }
                function_entry entry;
                entry.address = module.base + begin;
                entry.size = end - begin;
                entry.source = function_source::unwind_table;

                bool is_fragment = (unwind & unwind_is_chain_reference) != 0;
                uint8_t version_and_flags = 0;
                if (!is_fragment && read_value(accessor, module.base + unwind, version_and_flags)) {
                    is_fragment = ((version_and_flags >> 3) & unwind_flag_chain_info) != 0;
                }
                (is_fragment ? fragments : functions).push_back(entry);
            }
        }

        bool lies_inside_any(const std::vector<function_entry>& sorted_ranges, uintptr_t address) {
            auto next = std::upper_bound(sorted_ranges.begin(), sorted_ranges.end(), address,
                [](uintptr_t value, const function_entry& entry) { return value < entry.address; });
            if (next == sorted_ranges.begin()) {
                return false;
            }
            --next;
            return address < next->address + next->size;
        }

        constexpr int maximum_thunk_hops = 4;

        // A call often lands on a jump thunk, which is not a function but leads to one.
        // Returns nothing for a thunk that leaves the module, such as an import stub.
        std::optional<uintptr_t> follow_jump_thunks(memory_accessor& accessor, uintptr_t address) {
            ZydisDecoder& decoder = shared_decoder();
            ZydisDecodedInstruction decoded;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
            uint8_t first_bytes[ZYDIS_MAX_INSTRUCTION_LENGTH];
            for (int hop = 0; hop < maximum_thunk_hops; ++hop) {
                const size_t bytes_read = accessor.read(address, first_bytes, sizeof(first_bytes));
                if (bytes_read == 0
                    || !ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, first_bytes, bytes_read, &decoded, operands))) {
                    return std::nullopt;
                }
                if (decoded.mnemonic != ZYDIS_MNEMONIC_JMP) {
                    return address;
                }
                if (operands[0].type != ZYDIS_OPERAND_TYPE_IMMEDIATE || !operands[0].imm.is_relative) {
                    return std::nullopt;
                }
                address = resolve_rip_relative(address, decoded.length, static_cast<int32_t>(operands[0].imm.value.s));
            }
            return std::nullopt;
        }

        // Decoding is only trustworthy from a known function start, so this walks the
        // listed functions rather than sweeping the whole code section.
        std::vector<function_entry> find_call_targets(memory_accessor& accessor,
                                                         const module_info& module,
                                                         const std::vector<function_entry>& functions,
                                                         const std::vector<function_entry>& known_ranges) {
            ZydisDecoder& decoder = shared_decoder();
            ZydisDecodedInstruction decoded;
            ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
            std::vector<uintptr_t> targets;
            std::vector<uint8_t> code;

            const std::vector<region_info> regions = executable_regions_of(accessor, module);
            const auto is_executable = [&regions](uintptr_t address) {
                return std::any_of(regions.begin(), regions.end(), [address](const region_info& region) {
                    return address >= region.base && address < region.base + region.size;
                });
            };

            for (const auto& function : functions) {
                code.resize(function.size);
                const size_t bytes_read = accessor.read(function.address, code.data(), code.size());
                size_t cursor = 0;
                while (cursor < bytes_read) {
                    if (!ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, code.data() + cursor, bytes_read - cursor, &decoded, operands))) {
                        break;
                    }
                    if ((decoded.mnemonic == ZYDIS_MNEMONIC_CALL || decoded.mnemonic == ZYDIS_MNEMONIC_JMP)
                        && operands[0].type == ZYDIS_OPERAND_TYPE_IMMEDIATE
                        && operands[0].imm.is_relative) {
                        const uintptr_t target = resolve_rip_relative(function.address + cursor,
                                                                         decoded.length,
                                                                         static_cast<int32_t>(operands[0].imm.value.s));
                        const bool leaves_function = target < function.address || target >= function.address + function.size;
                        if (leaves_function && is_executable(target)) {
                            targets.push_back(target);
                        }
                    }
                    cursor += decoded.length;
                }
            }

            std::vector<uintptr_t> destinations;
            for (const uintptr_t target : targets) {
                const auto destination = follow_jump_thunks(accessor, target);
                if (destination.has_value() && is_executable(*destination) && !lies_inside_any(known_ranges, *destination)) {
                    destinations.push_back(*destination);
                }
            }
            std::sort(destinations.begin(), destinations.end());
            destinations.erase(std::unique(destinations.begin(), destinations.end()), destinations.end());

            std::vector<function_entry> found;
            for (const uintptr_t destination : destinations) {
                function_entry entry;
                entry.address = destination;
                entry.source = function_source::call_target;
                found.push_back(entry);
            }
            return found;
        }
    }

    std::vector<function_entry> find_functions_in_process(const process& target_process,
                                                             std::string_view module_name,
                                                             size_t max_results) {
        std::vector<function_entry> functions;
        memory_accessor& bound_accessor = target_process.accessor();
        const auto resolved = bound_accessor.find_module(module_name);
        if (!resolved.has_value()) {
            bytebinder::log(log_level::error,
                              std::string("find_functions: module not found: ") + std::string(module_name));
            return functions;
        }

        std::vector<function_entry> fragments;
        read_unwind_table(bound_accessor, *resolved, functions, fragments);

        const auto by_address = [](const function_entry& left, const function_entry& right) {
            return left.address < right.address;
        };
        if (functions.empty()) {
            for (const uintptr_t address : find_prologues_in_process(target_process, module_name, max_results)) {
                function_entry entry;
                entry.address = address;
                entry.source = function_source::prologue;
                functions.push_back(entry);
            }
            return functions;
        }

        std::vector<function_entry> known_ranges = functions;
        known_ranges.insert(known_ranges.end(), fragments.begin(), fragments.end());
        std::sort(known_ranges.begin(), known_ranges.end(), by_address);

        const std::vector<function_entry> call_targets = find_call_targets(bound_accessor, *resolved, functions, known_ranges);
        functions.insert(functions.end(), call_targets.begin(), call_targets.end());
        std::sort(functions.begin(), functions.end(), by_address);
        functions.erase(std::unique(functions.begin(), functions.end(),
            [](const function_entry& left, const function_entry& right) { return left.address == right.address; }),
            functions.end());

        if (max_results != 0 && functions.size() > max_results) {
            functions.resize(max_results);
        }
        return functions;
    }

    namespace {
        bool instruction_matches_template(const ZydisDecodedInstruction& decoded,
                                            const instruction_pattern_element& tpl) {
            if (!tpl.mnemonic.empty()) {
                const char* observed = ZydisMnemonicGetString(decoded.mnemonic);
                if (!observed) return false;
                std::string observed_lower(observed);
                std::transform(observed_lower.begin(), observed_lower.end(),
                                observed_lower.begin(),
                                [](unsigned char c){ return std::tolower(c); });
                std::string template_lower = tpl.mnemonic;
                std::transform(template_lower.begin(), template_lower.end(),
                                template_lower.begin(),
                                [](unsigned char c){ return std::tolower(c); });
                if (observed_lower != template_lower) return false;
            }
            if (tpl.operand_count.has_value()
                && decoded.operand_count_visible != *tpl.operand_count) {
                return false;
            }
            return true;
        }
    }

    std::vector<uintptr_t> find_instruction_pattern_in_process(
        const process& target_process,
        std::span<const instruction_pattern_element> pattern,
        std::optional<std::string_view> module_name,
        size_t max_results) {
        std::vector<uintptr_t> matches;
        if (pattern.empty()) return matches;
        memory_accessor& bound_accessor = target_process.accessor();

        std::vector<region_info> executable_regions;
        if (module_name.has_value()) {
            const auto resolved = bound_accessor.find_module(*module_name);
            if (!resolved.has_value()) return matches;
            const uintptr_t scan_end = resolved->base + resolved->size;
            for (const auto& region : bound_accessor.regions()) {
                if ((region.protection & protection::execute) == 0) continue;
                if ((region.protection & protection::read) == 0) continue;
                const uintptr_t region_end = region.base + region.size;
                const uintptr_t overlap_start = std::max(region.base, resolved->base);
                const uintptr_t overlap_end   = std::min(region_end, scan_end);
                if (overlap_start >= overlap_end) continue;
                region_info clipped = region;
                clipped.base = overlap_start;
                clipped.size = overlap_end - overlap_start;
                executable_regions.push_back(std::move(clipped));
            }
        } else {
            for (auto& region : bound_accessor.regions()) {
                if ((region.protection & protection::execute) == 0) continue;
                if ((region.protection & protection::read) == 0) continue;
                executable_regions.push_back(std::move(region));
            }
        }

        std::vector<uint8_t> region_buffer;
        ZydisDecoder& decoder = shared_decoder();

        for (const auto& region : executable_regions) {
            region_buffer.resize(region.size);
            const size_t bytes_read = bound_accessor.read(region.base,
                                                            region_buffer.data(),
                                                            region.size);
            if (bytes_read == 0) continue;

            for (size_t cursor = 0; cursor < bytes_read;) {
                size_t window_cursor = cursor;
                bool full_match = true;
                size_t first_instruction_length = 0;
                ZydisDecodedInstruction probe;
                ZydisDecodedOperand probe_operands[ZYDIS_MAX_OPERAND_COUNT];

                for (size_t element_index = 0; element_index < pattern.size(); ++element_index) {
                    if (window_cursor >= bytes_read) { full_match = false; break; }
                    const ZyanStatus status = ZydisDecoderDecodeFull(
                        &decoder,
                        region_buffer.data() + window_cursor,
                        bytes_read - window_cursor,
                        &probe, probe_operands);
                    if (!ZYAN_SUCCESS(status)) { full_match = false; break; }
                    if (!instruction_matches_template(probe, pattern[element_index])) {
                        full_match = false; break;
                    }
                    if (element_index == 0) first_instruction_length = probe.length;
                    window_cursor += probe.length;
                }

                if (full_match) {
                    matches.push_back(region.base + cursor);
                    if (max_results != 0 && matches.size() >= max_results) {
                        return matches;
                    }
                    cursor += first_instruction_length > 0 ? first_instruction_length : 1;
                } else {
                    cursor += 1;
                }
            }
        }
        return matches;
    }
}
