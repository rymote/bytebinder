/*
 * bytebinder - A C++ Library for Low-Level Memory Manipulation
 *
 * Authors: Péter Marton, Jovan Ivanovic
 * License: BSD 3-Clause
 */

#include "bb_debugger.h"
#include "bb_debug_register_encoding.h"
#include "bb_thread_enumeration.h"

#if defined(_WIN32)
    #include <windows.h>
#elif defined(__APPLE__)
    #include <mach/mach.h>
    #include <mach/mach_port.h>
    #include <mach/message.h>
    #include <mach/task.h>
    #include <mach/exception_types.h>
    #include <mach/thread_status.h>
    #include <mach/thread_act.h>
    #include <unistd.h>
#else
    #include <cerrno>
    #include <csignal>
    #include <cstddef>
    #include <cstring>
    #include <ctime>
    #include <sys/ptrace.h>
    #include <sys/types.h>
    #include <sys/user.h>
    #include <sys/wait.h>
    #include <unistd.h>
    #if defined(__aarch64__) || defined(__arm__)
        #include <elf.h>
        #include <sys/uio.h>
        #include <linux/ptrace.h>
    #endif
#endif

namespace bytebinder {
#if defined(_WIN32)
    namespace {
        HANDLE open_thread(uint64_t thread_id, DWORD access) {
            return OpenThread(access, FALSE, static_cast<DWORD>(thread_id));
        }
    }

    debugger::debugger(uint32_t process_id) : bound_process_id(process_id) {}
    debugger::~debugger() { detach(); }

    bool debugger::suspend_thread(uint64_t thread_id) {
        HANDLE handle = open_thread(thread_id, THREAD_SUSPEND_RESUME);
        if (handle == nullptr) return false;
        const DWORD previous = SuspendThread(handle);
        CloseHandle(handle);
        return previous != static_cast<DWORD>(-1);
    }

    bool debugger::resume_thread(uint64_t thread_id) {
        HANDLE handle = open_thread(thread_id, THREAD_SUSPEND_RESUME);
        if (handle == nullptr) return false;
        const DWORD previous = ResumeThread(handle);
        CloseHandle(handle);
        return previous != static_cast<DWORD>(-1);
    }

    std::optional<cpu_registers> debugger::read_registers(uint64_t thread_id) {
        HANDLE handle = open_thread(thread_id, THREAD_GET_CONTEXT);
        if (handle == nullptr) return std::nullopt;

        CONTEXT context;
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        const BOOL ok = GetThreadContext(handle, &context);
        CloseHandle(handle);
        if (!ok) return std::nullopt;

        cpu_registers registers;
        registers.instruction_pointer = context.Rip;
        registers.stack_pointer = context.Rsp;
        registers.frame_pointer = context.Rbp;
        registers.general_registers = {
            context.Rax, context.Rcx, context.Rdx, context.Rbx,
            context.Rsp, context.Rbp, context.Rsi, context.Rdi,
            context.R8,  context.R9,  context.R10, context.R11,
            context.R12, context.R13, context.R14, context.R15
        };
        return registers;
    }

    bool debugger::write_registers(uint64_t thread_id, const cpu_registers& registers) {
        HANDLE handle = open_thread(thread_id, THREAD_GET_CONTEXT | THREAD_SET_CONTEXT);
        if (handle == nullptr) return false;

        CONTEXT context;
        context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
        if (!GetThreadContext(handle, &context)) {
            CloseHandle(handle);
            return false;
        }

        context.Rip = registers.instruction_pointer;
        context.Rsp = registers.stack_pointer;
        context.Rbp = registers.frame_pointer;
        context.Rax = registers.general_registers[0];
        context.Rcx = registers.general_registers[1];
        context.Rdx = registers.general_registers[2];
        context.Rbx = registers.general_registers[3];
        context.Rsi = registers.general_registers[6];
        context.Rdi = registers.general_registers[7];
        context.R8  = registers.general_registers[8];
        context.R9  = registers.general_registers[9];
        context.R10 = registers.general_registers[10];
        context.R11 = registers.general_registers[11];
        context.R12 = registers.general_registers[12];
        context.R13 = registers.general_registers[13];
        context.R14 = registers.general_registers[14];
        context.R15 = registers.general_registers[15];

        const BOOL ok = SetThreadContext(handle, &context);
        CloseHandle(handle);
        return ok != 0;
    }

    bool debugger::set_watchpoint(uint64_t thread_id, int slot, const watchpoint& point) {
        if (!debug_register_encoding::is_valid_slot(slot)) return false;

        HANDLE handle = open_thread(thread_id, THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME);
        if (handle == nullptr) return false;
        if (SuspendThread(handle) == static_cast<DWORD>(-1)) {
            CloseHandle(handle);
            return false;
        }

        CONTEXT context;
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        bool ok = GetThreadContext(handle, &context) != 0;
        if (ok) {
            const std::optional<uint64_t> control =
                debug_register_encoding::apply_to_control(context.Dr7, slot, point);
            if (!control.has_value()) {
                ok = false;
            } else {
                switch (slot) {
                    case 0: context.Dr0 = point.address; break;
                    case 1: context.Dr1 = point.address; break;
                    case 2: context.Dr2 = point.address; break;
                    case 3: context.Dr3 = point.address; break;
                }
                context.Dr7 = *control;
                context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                ok = SetThreadContext(handle, &context) != 0;
            }
        }

        ResumeThread(handle);
        CloseHandle(handle);
        return ok;
    }

    bool debugger::clear_watchpoint(uint64_t thread_id, int slot) {
        if (!debug_register_encoding::is_valid_slot(slot)) return false;

        HANDLE handle = open_thread(thread_id, THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME);
        if (handle == nullptr) return false;
        if (SuspendThread(handle) == static_cast<DWORD>(-1)) {
            CloseHandle(handle);
            return false;
        }

        CONTEXT context;
        context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        bool ok = GetThreadContext(handle, &context) != 0;
        if (ok) {
            context.Dr7 = debug_register_encoding::clear_in_control(context.Dr7, slot);
            context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
            ok = SetThreadContext(handle, &context) != 0;
        }

        ResumeThread(handle);
        CloseHandle(handle);
        return ok;
    }

    bool debugger::attach() {
        if (debugging_active) return false;
        if (!DebugActiveProcess(static_cast<DWORD>(bound_process_id))) return false;
        DebugSetProcessKillOnExit(FALSE);
        debugging_active = true;
        return true;
    }

    bool debugger::detach() {
        if (!debugging_active) return true;
        const BOOL ok = DebugActiveProcessStop(static_cast<DWORD>(bound_process_id));
        debugging_active = false;
        return ok != 0;
    }

    std::optional<debug_event> debugger::wait_for_event(int timeout_milliseconds) {
        if (!debugging_active) return std::nullopt;

        DEBUG_EVENT native_event;
        const DWORD timeout = timeout_milliseconds < 0 ? INFINITE : static_cast<DWORD>(timeout_milliseconds);
        if (!WaitForDebugEvent(&native_event, timeout)) return std::nullopt;

        debug_event event;
        event.thread_id = native_event.dwThreadId;

        switch (native_event.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT: {
                const EXCEPTION_RECORD& record = native_event.u.Exception.ExceptionRecord;
                event.native_exception_code = record.ExceptionCode;
                event.exception_address = reinterpret_cast<uintptr_t>(record.ExceptionAddress);

                uint64_t debug_status = 0;
                HANDLE thread_handle = open_thread(native_event.dwThreadId, THREAD_GET_CONTEXT);
                if (thread_handle != nullptr) {
                    CONTEXT context;
                    context.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_DEBUG_REGISTERS;
                    if (GetThreadContext(thread_handle, &context)) {
                        event.registers.instruction_pointer = context.Rip;
                        event.registers.stack_pointer = context.Rsp;
                        event.registers.frame_pointer = context.Rbp;
                        event.registers.general_registers = {
                            context.Rax, context.Rcx, context.Rdx, context.Rbx,
                            context.Rsp, context.Rbp, context.Rsi, context.Rdi,
                            context.R8,  context.R9,  context.R10, context.R11,
                            context.R12, context.R13, context.R14, context.R15
                        };
                        debug_status = context.Dr6;
                    }
                    CloseHandle(thread_handle);
                }

                if (record.ExceptionCode == static_cast<DWORD>(EXCEPTION_SINGLE_STEP)) {
                    const int slot = debug_register_encoding::triggered_slot(debug_status);
                    if (slot >= 0) {
                        event.kind = debug_event_kind::watchpoint_hit;
                        event.watchpoint_slot = slot;
                    } else {
                        event.kind = debug_event_kind::single_step;
                    }
                } else if (record.ExceptionCode == static_cast<DWORD>(EXCEPTION_BREAKPOINT)) {
                    event.kind = debug_event_kind::breakpoint_hit;
                } else {
                    event.kind = debug_event_kind::exception;
                }
                break;
            }
            case CREATE_PROCESS_DEBUG_EVENT:
                if (native_event.u.CreateProcessInfo.hFile != nullptr) {
                    CloseHandle(native_event.u.CreateProcessInfo.hFile);
                }
                event.kind = debug_event_kind::process_created;
                break;
            case CREATE_THREAD_DEBUG_EVENT:
                event.kind = debug_event_kind::thread_created;
                break;
            case EXIT_THREAD_DEBUG_EVENT:
                event.kind = debug_event_kind::thread_exited;
                event.exit_code = native_event.u.ExitThread.dwExitCode;
                break;
            case EXIT_PROCESS_DEBUG_EVENT:
                event.kind = debug_event_kind::process_exited;
                event.exit_code = native_event.u.ExitProcess.dwExitCode;
                break;
            case LOAD_DLL_DEBUG_EVENT:
                if (native_event.u.LoadDll.hFile != nullptr) {
                    CloseHandle(native_event.u.LoadDll.hFile);
                }
                event.kind = debug_event_kind::unknown;
                break;
            default:
                event.kind = debug_event_kind::unknown;
                break;
        }

        return event;
    }

    bool debugger::continue_event(const debug_event& event, bool handled) {
        if (!debugging_active) return false;
        const DWORD status = handled ? DBG_CONTINUE : DBG_EXCEPTION_NOT_HANDLED;
        return ContinueDebugEvent(static_cast<DWORD>(bound_process_id),
                                  static_cast<DWORD>(event.thread_id), status) != 0;
    }

#elif defined(__APPLE__)
    debugger::debugger(uint32_t process_id) : bound_process_id(process_id) {
        if (static_cast<int>(process_id) == getpid()) {
            task_port = mach_task_self();
            owns_task_port = false;
        } else {
            mach_port_t acquired = MACH_PORT_NULL;
            if (task_for_pid(mach_task_self(), static_cast<int>(process_id), &acquired) == KERN_SUCCESS) {
                task_port = acquired;
                owns_task_port = true;
            }
        }
    }

    debugger::~debugger() {
        detach();
        if (owns_task_port && task_port != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), task_port);
        }
    }

    bool debugger::suspend_thread(uint64_t thread_id) {
        return thread_suspend(static_cast<thread_act_t>(thread_id)) == KERN_SUCCESS;
    }

    bool debugger::resume_thread(uint64_t thread_id) {
        return thread_resume(static_cast<thread_act_t>(thread_id)) == KERN_SUCCESS;
    }

    std::optional<cpu_registers> debugger::read_registers(uint64_t thread_id) {
    #if defined(__x86_64__)
        x86_thread_state64_t state{};
        mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
        if (thread_get_state(static_cast<thread_act_t>(thread_id), x86_THREAD_STATE64,
                             reinterpret_cast<thread_state_t>(&state), &state_count) != KERN_SUCCESS) {
            return std::nullopt;
        }
        cpu_registers registers;
        registers.instruction_pointer = state.__rip;
        registers.stack_pointer = state.__rsp;
        registers.frame_pointer = state.__rbp;
        registers.general_registers = {
            state.__rax, state.__rcx, state.__rdx, state.__rbx,
            state.__rsp, state.__rbp, state.__rsi, state.__rdi,
            state.__r8,  state.__r9,  state.__r10, state.__r11,
            state.__r12, state.__r13, state.__r14, state.__r15
        };
        return registers;
    #else
        (void)thread_id;
        return std::nullopt;
    #endif
    }

    bool debugger::write_registers(uint64_t thread_id, const cpu_registers& registers) {
    #if defined(__x86_64__)
        x86_thread_state64_t state{};
        mach_msg_type_number_t state_count = x86_THREAD_STATE64_COUNT;
        if (thread_get_state(static_cast<thread_act_t>(thread_id), x86_THREAD_STATE64,
                             reinterpret_cast<thread_state_t>(&state), &state_count) != KERN_SUCCESS) {
            return false;
        }
        state.__rip = registers.instruction_pointer;
        state.__rsp = registers.stack_pointer;
        state.__rbp = registers.frame_pointer;
        state.__rax = registers.general_registers[0];
        state.__rcx = registers.general_registers[1];
        state.__rdx = registers.general_registers[2];
        state.__rbx = registers.general_registers[3];
        state.__rsi = registers.general_registers[6];
        state.__rdi = registers.general_registers[7];
        state.__r8  = registers.general_registers[8];
        state.__r9  = registers.general_registers[9];
        state.__r10 = registers.general_registers[10];
        state.__r11 = registers.general_registers[11];
        state.__r12 = registers.general_registers[12];
        state.__r13 = registers.general_registers[13];
        state.__r14 = registers.general_registers[14];
        state.__r15 = registers.general_registers[15];
        return thread_set_state(static_cast<thread_act_t>(thread_id), x86_THREAD_STATE64,
                                reinterpret_cast<thread_state_t>(&state), x86_THREAD_STATE64_COUNT) == KERN_SUCCESS;
    #else
        (void)thread_id;
        (void)registers;
        return false;
    #endif
    }

    bool debugger::set_watchpoint(uint64_t thread_id, int slot, const watchpoint& point) {
    #if defined(__x86_64__)
        if (!debug_register_encoding::is_valid_slot(slot)) return false;

        x86_debug_state64_t state{};
        mach_msg_type_number_t state_count = x86_DEBUG_STATE64_COUNT;
        if (thread_get_state(static_cast<thread_act_t>(thread_id), x86_DEBUG_STATE64,
                             reinterpret_cast<thread_state_t>(&state), &state_count) != KERN_SUCCESS) {
            return false;
        }

        const std::optional<uint64_t> control =
            debug_register_encoding::apply_to_control(state.__dr7, slot, point);
        if (!control.has_value()) return false;

        switch (slot) {
            case 0: state.__dr0 = point.address; break;
            case 1: state.__dr1 = point.address; break;
            case 2: state.__dr2 = point.address; break;
            case 3: state.__dr3 = point.address; break;
        }
        state.__dr7 = *control;
        return thread_set_state(static_cast<thread_act_t>(thread_id), x86_DEBUG_STATE64,
                                reinterpret_cast<thread_state_t>(&state), x86_DEBUG_STATE64_COUNT) == KERN_SUCCESS;
    #else
        (void)thread_id;
        (void)slot;
        (void)point;
        return false;
    #endif
    }

    bool debugger::clear_watchpoint(uint64_t thread_id, int slot) {
    #if defined(__x86_64__)
        if (!debug_register_encoding::is_valid_slot(slot)) return false;

        x86_debug_state64_t state{};
        mach_msg_type_number_t state_count = x86_DEBUG_STATE64_COUNT;
        if (thread_get_state(static_cast<thread_act_t>(thread_id), x86_DEBUG_STATE64,
                             reinterpret_cast<thread_state_t>(&state), &state_count) != KERN_SUCCESS) {
            return false;
        }

        state.__dr7 = debug_register_encoding::clear_in_control(state.__dr7, slot);
        return thread_set_state(static_cast<thread_act_t>(thread_id), x86_DEBUG_STATE64,
                                reinterpret_cast<thread_state_t>(&state), x86_DEBUG_STATE64_COUNT) == KERN_SUCCESS;
    #else
        (void)thread_id;
        (void)slot;
        return false;
    #endif
    }

    namespace {
        // The exception request and reply laid out as the kernel's MIG stubs send
        // them for EXCEPTION_DEFAULT with MACH_EXCEPTION_CODES (64-bit codes).
        struct exception_request_message {
            mach_msg_header_t header;
            mach_msg_body_t body;
            mach_msg_port_descriptor_t thread;
            mach_msg_port_descriptor_t task;
            NDR_record_t ndr;
            exception_type_t exception;
            mach_msg_type_number_t code_count;
            int64_t code[2];
            char trailer[64];
        };

        struct exception_reply_message {
            mach_msg_header_t header;
            NDR_record_t ndr;
            kern_return_t return_code;
        };
    }

    bool debugger::attach() {
        if (debugging_active) return false;
        if (task_port == MACH_PORT_NULL) return false;

        mach_port_name_t port = MACH_PORT_NULL;
        if (mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port) != KERN_SUCCESS) {
            return false;
        }
        if (mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND) != KERN_SUCCESS) {
            mach_port_deallocate(mach_task_self(), port);
            return false;
        }
        if (task_set_exception_ports(task_port, EXC_MASK_BREAKPOINT, port,
                                     EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, THREAD_STATE_NONE) != KERN_SUCCESS) {
            mach_port_deallocate(mach_task_self(), port);
            return false;
        }

        exception_port = port;
        debugging_active = true;
        return true;
    }

    bool debugger::detach() {
        if (!debugging_active) return true;
        task_set_exception_ports(task_port, EXC_MASK_BREAKPOINT, MACH_PORT_NULL,
                                 EXCEPTION_DEFAULT | MACH_EXCEPTION_CODES, THREAD_STATE_NONE);
        if (exception_port != MACH_PORT_NULL) {
            mach_port_deallocate(mach_task_self(), exception_port);
            exception_port = MACH_PORT_NULL;
        }
        reply_pending = false;
        debugging_active = false;
        return true;
    }

    std::optional<debug_event> debugger::wait_for_event(int timeout_milliseconds) {
    #if defined(__x86_64__)
        if (!debugging_active) return std::nullopt;

        exception_request_message request{};
        mach_msg_option_t options = MACH_RCV_MSG;
        mach_msg_timeout_t timeout = MACH_MSG_TIMEOUT_NONE;
        if (timeout_milliseconds >= 0) {
            options |= MACH_RCV_TIMEOUT;
            timeout = static_cast<mach_msg_timeout_t>(timeout_milliseconds);
        }

        const mach_msg_return_t received = mach_msg(&request.header, options, 0,
                                                    sizeof(request), exception_port,
                                                    timeout, MACH_PORT_NULL);
        if (received != MACH_MSG_SUCCESS) return std::nullopt;

        // Remember what continue_event must send back (MIG reply id = request + 100).
        pending_remote_port = request.header.msgh_remote_port;
        pending_bits = request.header.msgh_bits;
        pending_id = request.header.msgh_id + 100;
        reply_pending = true;

        const thread_act_t faulting_thread = static_cast<thread_act_t>(request.thread.name);

        debug_event event;
        event.thread_id = static_cast<uint64_t>(request.thread.name);
        event.native_exception_code = static_cast<uint32_t>(request.exception);

        x86_thread_state64_t thread_state{};
        mach_msg_type_number_t thread_state_count = x86_THREAD_STATE64_COUNT;
        if (thread_get_state(faulting_thread, x86_THREAD_STATE64,
                             reinterpret_cast<thread_state_t>(&thread_state), &thread_state_count) == KERN_SUCCESS) {
            event.registers.instruction_pointer = thread_state.__rip;
            event.registers.stack_pointer = thread_state.__rsp;
            event.registers.frame_pointer = thread_state.__rbp;
            event.registers.general_registers = {
                thread_state.__rax, thread_state.__rcx, thread_state.__rdx, thread_state.__rbx,
                thread_state.__rsp, thread_state.__rbp, thread_state.__rsi, thread_state.__rdi,
                thread_state.__r8,  thread_state.__r9,  thread_state.__r10, thread_state.__r11,
                thread_state.__r12, thread_state.__r13, thread_state.__r14, thread_state.__r15
            };
            event.exception_address = thread_state.__rip;
        }

        x86_debug_state64_t debug_state{};
        mach_msg_type_number_t debug_state_count = x86_DEBUG_STATE64_COUNT;
        int slot = -1;
        if (thread_get_state(faulting_thread, x86_DEBUG_STATE64,
                             reinterpret_cast<thread_state_t>(&debug_state), &debug_state_count) == KERN_SUCCESS) {
            slot = debug_register_encoding::triggered_slot(debug_state.__dr6);
        }

        if (slot >= 0) {
            event.kind = debug_event_kind::watchpoint_hit;
            event.watchpoint_slot = slot;
        } else {
            event.kind = debug_event_kind::breakpoint_hit;
        }
        return event;
    #else
        (void)timeout_milliseconds;
        return std::nullopt;
    #endif
    }

    bool debugger::continue_event(const debug_event& event, bool handled) {
        (void)event;
        if (!debugging_active || !reply_pending) return false;

        exception_reply_message reply{};
        reply.header.msgh_bits = MACH_MSGH_BITS(MACH_MSGH_BITS_REMOTE(pending_bits), 0);
        reply.header.msgh_size = sizeof(reply);
        reply.header.msgh_remote_port = pending_remote_port;
        reply.header.msgh_local_port = MACH_PORT_NULL;
        reply.header.msgh_id = pending_id;
        reply.ndr = NDR_record;
        reply.return_code = handled ? KERN_SUCCESS : KERN_FAILURE;

        reply_pending = false;
        return mach_msg(&reply.header, MACH_SEND_MSG, sizeof(reply), 0,
                        MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL) == MACH_MSG_SUCCESS;
    }

#else
    namespace {
        template<typename... Args>
        long ptrace_call(int request_code, Args... arguments) {
            return ptrace(static_cast<__ptrace_request>(request_code), arguments...);
        }
    }

    debugger::debugger(uint32_t process_id) : bound_process_id(process_id) {}
    debugger::~debugger() { detach(); }

    bool debugger::suspend_thread(uint64_t thread_id) {
        if (ptrace_call(PTRACE_ATTACH, static_cast<pid_t>(thread_id), nullptr, nullptr) < 0) {
            return false;
        }
        int wait_status = 0;
        if (waitpid(static_cast<pid_t>(thread_id), &wait_status, __WALL) < 0) {
            ptrace_call(PTRACE_DETACH, static_cast<pid_t>(thread_id), nullptr, nullptr);
            return false;
        }
        return true;
    }

    bool debugger::resume_thread(uint64_t thread_id) {
        return ptrace_call(PTRACE_DETACH, static_cast<pid_t>(thread_id), nullptr, nullptr) >= 0;
    }

    std::optional<cpu_registers> debugger::read_registers(uint64_t thread_id) {
        cpu_registers registers;
    #if defined(__x86_64__)
        user_regs_struct raw{};
        if (ptrace_call(PTRACE_GETREGS, static_cast<pid_t>(thread_id), nullptr, &raw) < 0) {
            return std::nullopt;
        }
        registers.instruction_pointer = raw.rip;
        registers.stack_pointer = raw.rsp;
        registers.frame_pointer = raw.rbp;
        registers.general_registers = {
            raw.rax, raw.rcx, raw.rdx, raw.rbx,
            raw.rsp, raw.rbp, raw.rsi, raw.rdi,
            raw.r8,  raw.r9,  raw.r10, raw.r11,
            raw.r12, raw.r13, raw.r14, raw.r15
        };
        return registers;
    #elif defined(__aarch64__)
        user_pt_regs raw{};
        struct iovec io_vector { &raw, sizeof(raw) };
        if (ptrace_call(PTRACE_GETREGSET, static_cast<pid_t>(thread_id), NT_PRSTATUS, &io_vector) < 0) {
            return std::nullopt;
        }
        registers.instruction_pointer = raw.pc;
        registers.stack_pointer = raw.sp;
        registers.frame_pointer = raw.regs[29];
        for (size_t register_index = 0; register_index < registers.general_registers.size(); ++register_index) {
            registers.general_registers[register_index] = raw.regs[register_index];
        }
        return registers;
    #elif defined(__arm__)
        struct arm_regs { unsigned long uregs[18]; } raw{};
        struct iovec io_vector { &raw, sizeof(raw) };
        if (ptrace_call(PTRACE_GETREGSET, static_cast<pid_t>(thread_id), NT_PRSTATUS, &io_vector) < 0) {
            return std::nullopt;
        }
        registers.instruction_pointer = raw.uregs[15];
        registers.stack_pointer = raw.uregs[13];
        registers.frame_pointer = raw.uregs[11];
        for (size_t register_index = 0; register_index < registers.general_registers.size(); ++register_index) {
            registers.general_registers[register_index] = raw.uregs[register_index];
        }
        return registers;
    #else
        (void)thread_id;
        return std::nullopt;
    #endif
    }

    bool debugger::write_registers(uint64_t thread_id, const cpu_registers& registers) {
    #if defined(__x86_64__)
        user_regs_struct raw{};
        if (ptrace_call(PTRACE_GETREGS, static_cast<pid_t>(thread_id), nullptr, &raw) < 0) {
            return false;
        }
        raw.rip = registers.instruction_pointer;
        raw.rsp = registers.stack_pointer;
        raw.rbp = registers.frame_pointer;
        raw.rax = registers.general_registers[0];
        raw.rcx = registers.general_registers[1];
        raw.rdx = registers.general_registers[2];
        raw.rbx = registers.general_registers[3];
        raw.rsi = registers.general_registers[6];
        raw.rdi = registers.general_registers[7];
        raw.r8  = registers.general_registers[8];
        raw.r9  = registers.general_registers[9];
        raw.r10 = registers.general_registers[10];
        raw.r11 = registers.general_registers[11];
        raw.r12 = registers.general_registers[12];
        raw.r13 = registers.general_registers[13];
        raw.r14 = registers.general_registers[14];
        raw.r15 = registers.general_registers[15];
        return ptrace_call(PTRACE_SETREGS, static_cast<pid_t>(thread_id), nullptr, &raw) >= 0;
    #else
        (void)thread_id;
        (void)registers;
        return false;
    #endif
    }

    bool debugger::set_watchpoint(uint64_t thread_id, int slot, const watchpoint& point) {
    #if defined(__x86_64__)
        if (!debug_register_encoding::is_valid_slot(slot)) return false;

        const pid_t pid = static_cast<pid_t>(thread_id);
        const unsigned long debug_register_base = offsetof(struct user, u_debugreg);
        const unsigned long address_offset = debug_register_base + static_cast<unsigned long>(slot) * sizeof(unsigned long);
        const unsigned long control_offset = debug_register_base + 7 * sizeof(unsigned long);

        errno = 0;
        const long current_control = ptrace_call(PTRACE_PEEKUSER, pid,
                                                 reinterpret_cast<void*>(control_offset), nullptr);
        if (current_control == -1 && errno != 0) return false;

        const std::optional<uint64_t> control =
            debug_register_encoding::apply_to_control(static_cast<uint64_t>(current_control), slot, point);
        if (!control.has_value()) return false;

        if (ptrace_call(PTRACE_POKEUSER, pid, reinterpret_cast<void*>(address_offset),
                        reinterpret_cast<void*>(static_cast<uintptr_t>(point.address))) < 0) {
            return false;
        }
        if (ptrace_call(PTRACE_POKEUSER, pid, reinterpret_cast<void*>(control_offset),
                        reinterpret_cast<void*>(static_cast<uintptr_t>(*control))) < 0) {
            return false;
        }
        return true;
    #else
        (void)thread_id;
        (void)slot;
        (void)point;
        return false;
    #endif
    }

    bool debugger::clear_watchpoint(uint64_t thread_id, int slot) {
    #if defined(__x86_64__)
        if (!debug_register_encoding::is_valid_slot(slot)) return false;

        const pid_t pid = static_cast<pid_t>(thread_id);
        const unsigned long debug_register_base = offsetof(struct user, u_debugreg);
        const unsigned long control_offset = debug_register_base + 7 * sizeof(unsigned long);

        errno = 0;
        const long current_control = ptrace_call(PTRACE_PEEKUSER, pid,
                                                 reinterpret_cast<void*>(control_offset), nullptr);
        if (current_control == -1 && errno != 0) return false;

        const uint64_t control = debug_register_encoding::clear_in_control(
            static_cast<uint64_t>(current_control), slot);
        return ptrace_call(PTRACE_POKEUSER, pid, reinterpret_cast<void*>(control_offset),
                           reinterpret_cast<void*>(static_cast<uintptr_t>(control))) >= 0;
    #else
        (void)thread_id;
        (void)slot;
        return false;
    #endif
    }

    bool debugger::attach() {
        if (debugging_active) return false;
        const pid_t pid = static_cast<pid_t>(bound_process_id);
        if (ptrace_call(PTRACE_ATTACH, pid, nullptr, nullptr) < 0) return false;
        int wait_status = 0;
        if (waitpid(pid, &wait_status, __WALL) < 0) {
            ptrace_call(PTRACE_DETACH, pid, nullptr, nullptr);
            return false;
        }
        debugging_active = true;
        return true;
    }

    bool debugger::detach() {
        if (!debugging_active) return true;
        const bool ok = ptrace_call(PTRACE_DETACH, static_cast<pid_t>(bound_process_id),
                                    nullptr, nullptr) >= 0;
        debugging_active = false;
        return ok;
    }

    std::optional<debug_event> debugger::wait_for_event(int timeout_milliseconds) {
        if (!debugging_active) return std::nullopt;

        const pid_t pid = static_cast<pid_t>(bound_process_id);
        int wait_status = 0;
        pid_t result = 0;
        if (timeout_milliseconds < 0) {
            result = waitpid(pid, &wait_status, __WALL);
        } else {
            for (int waited_milliseconds = 0; ; ++waited_milliseconds) {
                result = waitpid(pid, &wait_status, __WALL | WNOHANG);
                if (result != 0) break;
                if (waited_milliseconds >= timeout_milliseconds) break;
                struct timespec nap{0, 1000000};
                nanosleep(&nap, nullptr);
            }
        }
        if (result <= 0) return std::nullopt;

        debug_event event;
        event.thread_id = static_cast<uint64_t>(result);

        if (WIFEXITED(wait_status)) {
            event.kind = debug_event_kind::process_exited;
            event.exit_code = static_cast<uint32_t>(WEXITSTATUS(wait_status));
            debugging_active = false;
            return event;
        }
        if (WIFSIGNALED(wait_status)) {
            event.kind = debug_event_kind::process_exited;
            event.exit_code = static_cast<uint32_t>(WTERMSIG(wait_status));
            debugging_active = false;
            return event;
        }
        if (WIFSTOPPED(wait_status)) {
            const int signal_number = WSTOPSIG(wait_status);
            event.native_exception_code = static_cast<uint32_t>(signal_number);
        #if defined(__x86_64__)
            const std::optional<cpu_registers> registers = read_registers(static_cast<uint64_t>(result));
            if (registers.has_value()) event.registers = *registers;

            const unsigned long debug_register_base = offsetof(struct user, u_debugreg);
            const unsigned long status_offset = debug_register_base + 6 * sizeof(unsigned long);
            errno = 0;
            const long debug_status = ptrace_call(PTRACE_PEEKUSER, pid,
                                                 reinterpret_cast<void*>(status_offset), nullptr);
            int slot = -1;
            if (!(debug_status == -1 && errno != 0)) {
                slot = debug_register_encoding::triggered_slot(static_cast<uint64_t>(debug_status));
            }

            if (signal_number == SIGTRAP && slot >= 0) {
                event.kind = debug_event_kind::watchpoint_hit;
                event.watchpoint_slot = slot;
                event.exception_address = event.registers.instruction_pointer;
            } else if (signal_number == SIGTRAP) {
                event.kind = debug_event_kind::breakpoint_hit;
                event.exception_address = event.registers.instruction_pointer;
            } else {
                event.kind = debug_event_kind::exception;
            }
        #else
            event.kind = debug_event_kind::exception;
        #endif
            return event;
        }

        event.kind = debug_event_kind::unknown;
        return event;
    }

    bool debugger::continue_event(const debug_event& event, bool handled) {
        if (!debugging_active) return false;
        if (event.kind == debug_event_kind::process_exited) return true;

        const pid_t target = static_cast<pid_t>(event.thread_id);
    #if defined(__x86_64__)
        const unsigned long debug_register_base = offsetof(struct user, u_debugreg);
        const unsigned long status_offset = debug_register_base + 6 * sizeof(unsigned long);
        ptrace_call(PTRACE_POKEUSER, target, reinterpret_cast<void*>(status_offset),
                    reinterpret_cast<void*>(static_cast<uintptr_t>(0)));
    #endif
        const int signal_number = handled ? 0 : static_cast<int>(event.native_exception_code);
        return ptrace_call(PTRACE_CONT, target, nullptr,
                           reinterpret_cast<void*>(static_cast<intptr_t>(signal_number))) >= 0;
    }
#endif

    std::vector<thread_entry> debugger::threads() const {
        return list_threads(bound_process_id);
    }
}
