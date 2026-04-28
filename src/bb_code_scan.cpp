/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: MIT
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
        bool decoded_is_prologue_anchor(const ZydisDecodedInstruction& first,
                                          const ZydisDecodedInstruction& second,
                                          const ZydisDecodedOperand* second_operands) {
            // Pattern A: push rbp; mov rbp, rsp
            if (first.mnemonic == ZYDIS_MNEMONIC_PUSH
                && second.mnemonic == ZYDIS_MNEMONIC_MOV
                && second.operand_count >= 2
                && second_operands[0].type == ZYDIS_OPERAND_TYPE_REGISTER
                && second_operands[1].type == ZYDIS_OPERAND_TYPE_REGISTER
                && second_operands[0].reg.value == ZYDIS_REGISTER_RBP
                && second_operands[1].reg.value == ZYDIS_REGISTER_RSP) {
                return true;
            }
            // Pattern B: endbr64 (CET indirect-branch tracking)
            if (first.mnemonic == ZYDIS_MNEMONIC_ENDBR64) return true;
            // Pattern C: sub rsp, N (no-frame-ptr leaf functions)
            if (first.mnemonic == ZYDIS_MNEMONIC_SUB && first.operand_count >= 2) {
                return true;
            }
            return false;
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

        const uintptr_t module_end = resolved->base + resolved->size;
        std::vector<region_info> executable_regions;
        for (const auto& region : bound_accessor.regions()) {
            if ((region.protection & protection::execute) == 0) continue;
            if ((region.protection & protection::read) == 0) continue; // skip [vsyscall]
            const uintptr_t region_end = region.base + region.size;
            const uintptr_t overlap_start = std::max(region.base, resolved->base);
            const uintptr_t overlap_end   = std::min(region_end, module_end);
            if (overlap_start >= overlap_end) continue;
            region_info clipped = region;
            clipped.base = overlap_start;
            clipped.size = overlap_end - overlap_start;
            executable_regions.push_back(std::move(clipped));
        }

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

            for (size_t cursor = 0; cursor + 8 <= bytes_read;) {
                const ZyanStatus first_status = ZydisDecoderDecodeFull(
                    &decoder,
                    region_buffer.data() + cursor,
                    bytes_read - cursor,
                    &first_decoded, first_operands);
                if (!ZYAN_SUCCESS(first_status)) {
                    ++cursor;
                    continue;
                }
                bool matched = false;
                if (cursor + first_decoded.length + 1 <= bytes_read) {
                    const ZyanStatus second_status = ZydisDecoderDecodeFull(
                        &decoder,
                        region_buffer.data() + cursor + first_decoded.length,
                        bytes_read - cursor - first_decoded.length,
                        &second_decoded, second_operands);
                    if (ZYAN_SUCCESS(second_status)
                        && decoded_is_prologue_anchor(first_decoded, second_decoded, second_operands)) {
                        matches.push_back(region.base + cursor);
                        matched = true;
                        if (max_results != 0 && matches.size() >= max_results) {
                            return matches;
                        }
                    }
                }
                cursor += matched ? first_decoded.length : 1;
            }
        }
        return matches;
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
