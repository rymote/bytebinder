/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#include "bb_process_enumeration.h"

#include <algorithm>
#include <cctype>

#if defined(_WIN32)
    #include <windows.h>
    #include <tlhelp32.h>
#elif defined(__APPLE__)
    #include <libproc.h>
    #include <sys/sysctl.h>
    #include <vector>
#else
    #include <cstdio>
    #include <cstring>
    #include <dirent.h>
    #include <unistd.h>
#endif

namespace bytebinder {
    namespace {
        std::string to_lower_ascii(std::string_view text) {
            std::string lowered(text);
            std::transform(lowered.begin(), lowered.end(), lowered.begin(),
                           [](unsigned char character) {
                               return static_cast<char>(std::tolower(character));
                           });
            return lowered;
        }

#if defined(_WIN32)
        std::string wide_to_utf8(const wchar_t* wide_text) {
            if (wide_text == nullptr || wide_text[0] == L'\0') return {};
            const int required = WideCharToMultiByte(CP_UTF8, 0, wide_text, -1,
                                                     nullptr, 0, nullptr, nullptr);
            if (required <= 0) return {};
            std::string result(static_cast<size_t>(required - 1), '\0');
            WideCharToMultiByte(CP_UTF8, 0, wide_text, -1,
                                result.data(), required, nullptr, nullptr);
            return result;
        }

        std::string query_image_path(DWORD process_id) {
            HANDLE handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id);
            if (handle == nullptr) return {};
            wchar_t path_buffer[MAX_PATH];
            DWORD length = MAX_PATH;
            std::string result;
            if (QueryFullProcessImageNameW(handle, 0, path_buffer, &length)) {
                result = wide_to_utf8(path_buffer);
            }
            CloseHandle(handle);
            return result;
        }
#endif
    }

    std::vector<process_entry> list_processes() {
        std::vector<process_entry> entries;

#if defined(_WIN32)
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return entries;

        PROCESSENTRY32W process_record;
        process_record.dwSize = sizeof(process_record);
        if (Process32FirstW(snapshot, &process_record)) {
            do {
                process_entry entry;
                entry.process_id = process_record.th32ProcessID;
                entry.name = wide_to_utf8(process_record.szExeFile);
                entry.path = query_image_path(process_record.th32ProcessID);
                entries.push_back(std::move(entry));
            } while (Process32NextW(snapshot, &process_record));
        }
        CloseHandle(snapshot);

#elif defined(__APPLE__)
        int management_info_base[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};
        size_t required_bytes = 0;
        if (sysctl(management_info_base, 4, nullptr, &required_bytes, nullptr, 0) != 0) {
            return entries;
        }
        std::vector<char> buffer(required_bytes);
        if (sysctl(management_info_base, 4, buffer.data(), &required_bytes, nullptr, 0) != 0) {
            return entries;
        }
        const size_t record_count = required_bytes / sizeof(struct kinfo_proc);
        const auto* records = reinterpret_cast<const struct kinfo_proc*>(buffer.data());
        for (size_t record_index = 0; record_index < record_count; ++record_index) {
            const int pid = records[record_index].kp_proc.p_pid;
            if (pid <= 0) continue;
            process_entry entry;
            entry.process_id = static_cast<uint32_t>(pid);
            entry.name = records[record_index].kp_proc.p_comm;
            char path_buffer[PROC_PIDPATHINFO_MAXSIZE] = {0};
            if (proc_pidpath(pid, path_buffer, sizeof(path_buffer)) > 0) {
                entry.path = path_buffer;
            }
            entries.push_back(std::move(entry));
        }

#else
        DIR* proc_directory = opendir("/proc");
        if (proc_directory == nullptr) return entries;
        struct dirent* directory_entry;
        while ((directory_entry = readdir(proc_directory)) != nullptr) {
            char* parse_end = nullptr;
            const long parsed_pid = std::strtol(directory_entry->d_name, &parse_end, 10);
            if (parse_end == directory_entry->d_name || *parse_end != '\0' || parsed_pid <= 0) {
                continue;
            }

            process_entry entry;
            entry.process_id = static_cast<uint32_t>(parsed_pid);

            char comm_path[64];
            std::snprintf(comm_path, sizeof(comm_path), "/proc/%ld/comm", parsed_pid);
            if (FILE* comm_file = std::fopen(comm_path, "r")) {
                char name_buffer[256];
                if (std::fgets(name_buffer, sizeof(name_buffer), comm_file) != nullptr) {
                    std::string name(name_buffer);
                    if (!name.empty() && name.back() == '\n') name.pop_back();
                    entry.name = std::move(name);
                }
                std::fclose(comm_file);
            }

            char exe_path[64];
            std::snprintf(exe_path, sizeof(exe_path), "/proc/%ld/exe", parsed_pid);
            char link_target[4096];
            const ssize_t link_length = readlink(exe_path, link_target, sizeof(link_target) - 1);
            if (link_length > 0) {
                link_target[link_length] = '\0';
                entry.path = link_target;
            }

            entries.push_back(std::move(entry));
        }
        closedir(proc_directory);
#endif

        return entries;
    }

    std::vector<process_entry> find_processes_by_name(std::string_view name) {
        const std::string wanted = to_lower_ascii(name);
        std::vector<process_entry> matches;
        for (auto& entry : list_processes()) {
            if (to_lower_ascii(entry.name) == wanted) {
                matches.push_back(std::move(entry));
            }
        }
        return matches;
    }
}
