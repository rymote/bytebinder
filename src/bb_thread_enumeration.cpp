/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#include "bb_thread_enumeration.h"

#if defined(_WIN32)
    #include <windows.h>
    #include <tlhelp32.h>
#elif defined(__APPLE__)
    #include <mach/mach.h>
    #include <unistd.h>
#else
    #include <cstdlib>
    #include <dirent.h>
    #include <cstdio>
    #include <unistd.h>
#endif

namespace bytebinder {
    std::vector<thread_entry> list_threads(uint32_t process_id) {
        std::vector<thread_entry> threads;

#if defined(_WIN32)
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return threads;

        THREADENTRY32 thread_record;
        thread_record.dwSize = sizeof(thread_record);
        if (Thread32First(snapshot, &thread_record)) {
            do {
                const bool owns_size_field =
                    thread_record.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID)
                        + sizeof(thread_record.th32OwnerProcessID);
                if (owns_size_field && thread_record.th32OwnerProcessID == process_id) {
                    threads.push_back({static_cast<uint64_t>(thread_record.th32ThreadID)});
                }
                thread_record.dwSize = sizeof(thread_record);
            } while (Thread32Next(snapshot, &thread_record));
        }
        CloseHandle(snapshot);

#elif defined(__APPLE__)
        task_t task = MACH_PORT_NULL;
        if (static_cast<int>(process_id) == getpid()) {
            task = mach_task_self();
        } else if (task_for_pid(mach_task_self(), static_cast<int>(process_id), &task) != KERN_SUCCESS) {
            return threads;
        }

        thread_act_array_t thread_list = nullptr;
        mach_msg_type_number_t thread_count = 0;
        if (task_threads(task, &thread_list, &thread_count) == KERN_SUCCESS) {
            for (mach_msg_type_number_t thread_index = 0; thread_index < thread_count; ++thread_index) {
                threads.push_back({static_cast<uint64_t>(thread_list[thread_index])});
            }
            vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(thread_list),
                          thread_count * sizeof(thread_act_t));
        }
        if (task != mach_task_self() && task != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), task);
        }

#else
        char task_directory_path[64];
        std::snprintf(task_directory_path, sizeof(task_directory_path),
                      "/proc/%u/task", static_cast<unsigned>(process_id));
        DIR* task_directory = opendir(task_directory_path);
        if (task_directory == nullptr) return threads;
        struct dirent* directory_entry;
        while ((directory_entry = readdir(task_directory)) != nullptr) {
            char* parse_end = nullptr;
            const long parsed_tid = std::strtol(directory_entry->d_name, &parse_end, 10);
            if (parse_end == directory_entry->d_name || *parse_end != '\0' || parsed_tid <= 0) {
                continue;
            }
            threads.push_back({static_cast<uint64_t>(parsed_tid)});
        }
        closedir(task_directory);
#endif

        return threads;
    }

    std::vector<thread_entry> list_current_process_threads() {
#if defined(_WIN32)
        return list_threads(static_cast<uint32_t>(GetCurrentProcessId()));
#else
        return list_threads(static_cast<uint32_t>(getpid()));
#endif
    }
}
