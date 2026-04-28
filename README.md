<div align="center">
    <a href="https://github.com/rymote/bytebinder"><img src="https://github.com/rymote/bytebinder/blob/master/.github/rymote-bytebinder-cover.png" alt="rymote/bytebinder" /></a>
</div>
<br />

<div align="center">
  bytebinder - Low-level memory manipulation and management library
</div>

<div align="center">
  <sub>
    Brought to you by 
    <a href="https://github.com/martonp96">@martonp96</a>,
    <a href="https://github.com/jovanivanovic">@jovanivanovic</a>,
    <a href="https://github.com/rymote">@rymote</a>
  </sub>
</div>

> [!CAUTION]
> ## Disclaimer
> 
> **Important Notice:**
> 
> **bytebinder** is provided as a tool for legitimate security research and educational purposes only. The authors of this library do not condone or support any use of this library for malicious or illegal activities. Users of **bytebinder** are solely responsible for compliance with all applicable laws and regulations.
> 
> ### Responsibility and Liability
> 
> - The authors and contributors of **bytebinder** are not responsible for any damages, data loss, or legal issues that may arise from the use or misuse of this library.
> - This software is provided "as is," without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement.
> - In no event shall the authors or copyright holders be liable for any claim, damages, or other liability, whether in an action of contract, tort, or otherwise, arising from, out of, or in connection with the software or the use or other dealings in the software.
> 
> ### Intended Use
> 
> **bytebinder** is intended for:
> 
> - Security researchers conducting vulnerability assessments.
> - Educators teaching low-level programming and security concepts.
> - Developers creating debugging and testing tools.
> 
> ### Prohibited Use
> 
> **bytebinder** must not be used for:
> 
> - Unauthorized access to computer systems or networks.
> - Distribution of malware or malicious payloads.
> - Any other activities that violate applicable laws or regulations.
> 
> **By using bytebinder, you agree to this disclaimer and affirm that you understand the potential risks and legal implications associated with its use.**

## Features

- **In-process and out-of-process**: same `bb::mem` API drives the calling process or a remote PID via `bb::process::attach(pid)`.
- **Memory address handling**: fluent offset math, RIP-relative arithmetic, typed accessor-aware reads and writes (`read<T>`, `write<T>`, `read_bytes`, `write_bytes`).
- **Hooking and patching**: PolyHook 2.0-backed function detours, `nop`/`ret`/`jmp`/`call` primitives, declarative `bb::static_hook` registrations, `bb::vmt` vtable patching.
- **Disassembly**: `mem.disasm(n)` returns Zydis-decoded `bb::instruction`s — works on local and remote memory.
- **Symbol resolution**: `process.resolve_symbol(name)` and `process.symbolize(addr)` — Linux ELF `.dynsym`/`.symtab` parser, Windows DbgHelp.
- **Memory scanning and pattern matching**: IDA-style signatures with chunked-read scanning for remote targets.
- **Memory watching**: cancellable polling with RAII handles.
- **Foreign protection changes**: `ptrace`-injected `mprotect` on Linux x86_64, aarch64, and 32-bit ARM (with multi-thread freeze).
- **Robust error handling**: typed exceptions with `memory_error_code`.

### Platform support

| Platform | Status |
|---|---|
| Windows (MSVC, x64) | supported, exercised in CI |
| Linux (x86_64) | supported, exercised in CI (Debug + Release, ASan + UBSan) |
| Linux (aarch64, 32-bit ARM) | code paths cross-compile-checked in CI; runtime tested on real hardware/QEMU only |
| macOS | not yet — Mach VM / dyld backed accessors are tracked separately |

## Installation

> **Note**: Function detours rely on PolyHook 2.0 and require a function with
> enough bytes to safely overwrite the prologue (typically ≥ 14 bytes on x64).
> Hooking very small leaf functions may fail with `Function too small to hook`.

### Prerequisites

- CMake **3.28+**
- A C++20-capable compiler (MSVC 19.30+, GCC 12+, Clang 15+)
- Git (the build pulls in PolyHook 2.0 as a submodule)

### Build from source

```sh
git clone --recurse-submodules https://github.com/rymote/bytebinder.git
cd bytebinder
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The build produces `bytebinder` static + shared libraries under `build/lib/`.
The Catch2 test runner builds as `bytebinder_tests`; run with
`ctest --test-dir build`.

### Build options

| Option | Default | Description |
|---|---|---|
| `BYTEBINDER_BUILD_STATIC` | `ON` | Build the static archive target. |
| `BYTEBINDER_BUILD_SHARED` | `ON` | Build the shared library target. |
| `BYTEBINDER_BUILD_TESTS` | `ON` (top-level) | Build the Catch2 test runner. |
| `BYTEBINDER_ENABLE_SANITIZERS` | `OFF` | Compile with AddressSanitizer + UBSan in Debug. |

### Consume from another CMake project

```cmake
find_package(bytebinder CONFIG REQUIRED)
target_link_libraries(my_target PRIVATE bytebinder::shared)  # or bytebinder::static
```

## Usage

```cpp
#include <bytebinder/bytebinder.h>

int main() {
    // Bind to the current process's main module. On Windows this calls
    // GetModuleHandleA(nullptr); on Linux it walks dl_iterate_phdr.
    bb::mem::init();

    // Find a function by signature (IDA-style; '?' is a wildcard nibble).
    bb::mem target = bb::mem::scan("48 89 5C 24 ? 48 89 74 24 ? 57 48 83 EC 20");

    using fn_t = int(*)(int);
    fn_t original = nullptr;
    auto handle = target.hook<fn_t>([](int value) {
        return original(value) + 1;
    }, &original);

    // ... do work ...

    handle.unhook();        // remove this hook
    bb::mem::unhook_all();  // or remove every hook installed via bytebinder
}
```

### Watching for memory changes

```cpp
auto watch = bb::mem(some_address).watch(
    sizeof(int),
    []{ std::cout << "value changed!\n"; },
    std::chrono::milliseconds{50});

// keep `watch` alive for as long as you want callbacks; its destructor stops
// the worker thread cleanly. Call `watch.stop()` to cancel earlier.
```

### Out-of-process: attach to another PID

```cpp
#include <bytebinder/bytebinder.h>

int main(int argc, char** argv) {
    auto target = bb::process::attach(std::stoul(argv[1]));

    for (auto& loaded : target.modules()) {
        std::printf("%-40s 0x%lx (%zu bytes)\n",
                    loaded.name.c_str(), loaded.base, loaded.size);
    }

    bb::mem hit = target.scan("DE AD BE EF ?? ?? CA FE", "libgame.so");
    if (hit.valid()) {
        const auto first_eight = hit.read_bytes(8);
        const uint32_t marker  = hit.read<uint32_t>(/*offset=*/16);
        // mutate it
        target.at(hit.address + 16).write<uint32_t>(0xCAFEBEEF);
    }
}
```

Backed by `Read/WriteProcessMemory` + `VirtualQueryEx` on Windows and
`process_vm_readv/writev` + `/proc/<pid>/maps` on Linux.

**What's local-only**: `mem::hook<T>`, `mem::set_call`, `mem::assemble`,
`mem::alloc`, and `mem::alloc_near` operate on the calling process and throw
`memory_operation_exception(INVALID_OPERATION)` if invoked through a
remote-bound `mem`. Use `mem::read<T>` / `mem::read_bytes` /
`mem::write<T>` / `mem::write_bytes` for cross-process I/O — they go through
the bound accessor and work for both local and remote.

**Linux note**: `remote_accessor::set_protection` is implemented via
`ptrace` + an injected `mprotect` syscall on **x86_64**, **aarch64**, and
**32-bit ARM** (both ARM and Thumb modes). The flow:

1. Walk `/proc/<pid>/task/` and `PTRACE_ATTACH` every thread, retrying until
   no new TIDs appear (handles thread creation racing the freeze).
2. On the leader thread: save the GPR set + 8 bytes at the program counter,
   overlay the architecture's syscall instruction (`0F 05` x86_64,
   `D4 00 00 01` aarch64, `EF 00 00 00` ARM, `DF 00` Thumb), set the syscall
   args (`rax/rdi/rsi/rdx`, `x8/x0/x1/x2`, or `r7/r0/r1/r2`),
   `PTRACE_SINGLESTEP`, read the result.
3. Restore bytes + registers and `PTRACE_DETACH` every thread.

The target must be `ptrace`-attachable: a parent always qualifies; otherwise
`yama.ptrace_scope` and `CAP_SYS_PTRACE` apply. The x86_64 + multi-thread
path is exercised end-to-end in CI; aarch64 and arm paths are
syntax-checked under cross-compilers (`crossbuild-essential-arm64`,
`crossbuild-essential-armhf`) and need real hardware or a QEMU runner for
live verification. Reads, writes, region enumeration, and scanning never
need ptrace.

### Disassembly

```cpp
bb::mem entry_point = bb::mem(reinterpret_cast<void*>(&some_function));
for (const auto& decoded : entry_point.disasm(/*max_instructions=*/8)) {
    std::printf("0x%lx  %-40s  ; %zu bytes\n",
                decoded.address, decoded.text.c_str(), decoded.length);
}
```

Backed by Zydis. Decoder mode is x86_64 on 64-bit hosts, x86 on 32-bit hosts.
Reads the bytes through the bound accessor, so it works equally for an
in-process pointer or a `bb::process::attach(pid).at(addr)` remote view.

### vtable hooking

```cpp
bb::vmt vtable_view(reinterpret_cast<uintptr_t>(my_object));
auto handle = vtable_view.hook(/*index=*/3, reinterpret_cast<void*>(&my_detour));

// ... later ...
handle.unhook();   // restores the original entry
```

The patch is process-wide: every instance sharing the vtable observes the
detour. To isolate one instance, copy the vtable first and rebind the
object's vtable pointer (application-specific, not provided here).

### Symbol resolution

```cpp
auto current_process = bb::process::current();

if (auto resolved = current_process.resolve_symbol("memcpy")) {
    std::printf("memcpy lives at 0x%lx (in %s)\n",
                resolved->address, resolved->module_name.c_str());
}

if (auto symbolized = current_process.symbolize(some_address)) {
    std::printf("0x%lx → %s+%lu\n",
                some_address, symbolized->name.c_str(),
                some_address - symbolized->address);
}
```

On **Linux**, parses each loaded module's ELF `.dynsym` and `.symtab`
directly from disk (no `libelf` dependency). Stripped binaries only expose
dynamic symbols. Tables are cached per module path.

On **Windows**, uses DbgHelp's `SymFromName` / `SymFromAddr`. Non-exported
symbols require PDB availability for the loaded module. Currently
local-only (remote-process Windows symbols would need to share the
`OpenProcess` HANDLE with DbgHelp; tracked separately).

### Declarative pattern-bound hooks

```cpp
static int my_detour(int value);
static bb::static_hook<int, int> patched_func("E8 ? ? ? ? 8B C8", my_detour);

int main() {
    bb::mem::init();
    bb::run_init_funcs();   // resolves and installs every static_* registration
    return patched_func(42);
}
```

## API reference

The full surface is documented inline in `include/`. The summary below is a navigation aid.

### Headers at a glance

| Header | Public surface |
|---|---|
| `bb_process.h` | `process`, `process::module_section`, `process::scan_result` |
| `mem.h` | `mem`, `hook_handle`, `watch_handle` |
| `memory_accessor.h` | `memory_accessor`, `protection` namespace, `region_info`, `module_info` |
| `local_accessor.h`, `remote_accessor.h` | concrete accessors |
| `pattern.h` | `pattern`, `parse_ida_pattern`, `pattern::scan_progress` |
| `symbols.h` | `symbol_info`, `symbolize_result` |
| `disasm.h` | `instruction` |
| `vmt.h` | `vmt`, `vmt_handle` |
| `scoped_unlock.h` | `scoped_unlock` |
| `log_sink.h` | `log_level`, `log_sink`, `set_log_sink` |
| `bytebinder_version.h` | `bytebinder_version()`, `bytebinder_abi_revision()` |
| `init_system.h` | `static_mem`, `static_func`, `static_hook`, `init_func`, `run_init_funcs` |
| `memory_exceptions.h` | `memory_operation_exception`, `memory_error_code` |

### `bb::process`

Handle to the current process or a remote PID. Owns a `memory_accessor`.

| Method | Returns | Local? | Notes |
|---|---|---|---|
| `process::current()` | `process` | local | Binds to the calling process. |
| `process::attach(pid)` | `process` | remote | Opens the target via OS primitives. |
| `id()` | `optional<uint32_t>` | both | Process ID, if any. |
| `alive()` | `bool` | both | False once a remote target exits. |
| `at(address)` | `mem` | both | Bind a `mem` to this process at `address`. |
| `regions()` | `vector<region_info>` | both | All committed regions. |
| `regions(req, forbidden=0)` | `vector<region_info>` | both | Filtered by protection bits. |
| `modules()` | `vector<module_info>` | both | Loaded modules with base + size. |
| `find_module(name)` | `optional<module_info>` | both | Match by basename or full path. |
| `module_sections(module)` | `vector<module_section>` | both | Parses PE/ELF section table. Cached per module path. |
| `is_readable(addr, len=0)` | `bool` | both | Range fully covered by readable regions. |
| `is_writable(addr, len=0)` | `bool` | both | Range fully covered by writable regions. |
| `scan(pattern, module={})` | `mem` | both | First-match. Throws if module not found. |
| `scan_all(pattern, module={}, max=10000)` | `scan_result` | both | All matches up to `max` (0 = unlimited). |
| `scan_all(pattern, module, max, cancel*, on_progress)` | `scan_result` | both | Cancellable + progress callback per 64 KiB window. |
| `resolve_symbol(name, module={})` | `optional<symbol_info>` | Linux: both, Windows: local | DbgHelp on Windows; ELF .dynsym/.symtab on Linux. |
| `resolve_symbols(span<name>, module={})` | `vector<optional<symbol_info>>` | same | Single table parse per module. |
| `symbolize(address)` | `optional<symbolize_result>` | same | Symbol + offset_from_start. |

Thread safety: all const methods are safe to call concurrently from multiple threads on the same `process` instance.

### `bb::mem`

Fluent wrapper over a `(uintptr_t address, memory_accessor*)` pair.

| Method | Returns | Local? | Notes |
|---|---|---|---|
| `add(offset)` | `mem` | both | Pure arithmetic. |
| `rip(offset=3)` | `mem` | both | Resolves x86-64 RIP-relative displacement via the bound accessor. |
| `get<T>(offset=0)` | `T` (pointer-shaped) | local-only | Returns a typed pointer; throws `INVALID_OPERATION` for remote. |
| `read<T>(offset=0)` | `T` | both | Typed read via accessor. |
| `read_bytes(size, offset=0)` | `vector<uint8_t>` | both | Resizes to actual bytes read. |
| `read_cstring(max=4096)` | `optional<string>` | both | Stops at NUL. |
| `read_wstring(max=4096)` | `optional<u16string>` | both | UTF-16, stops at NUL. |
| `set<T>(value)` / `write<T>(value, offset=0)` | `void` | both | Typed write via accessor. |
| `write_bytes(span, offset=0)` | `void` | both | |
| `nop(size)` | `void` | local-only | Replaces bytes with `0x90`. Honors dry-run. |
| `ret()` | `void` | local-only | Writes a single `0xC3`. Honors dry-run. |
| `jmp(function)` | `mem` | local-only | E9-relative. |
| `call(function)` | `void` | local-only | E8-relative. |
| `set_call(target)` | `void` | local-only | Patches an existing E8 to point at `target`. |
| `hook<T>(detour, original_out=nullptr)` | `hook_handle` | local-only | PolyHook 2.0 detour, or E8 patch if the byte at this address is 0xE8. |
| `compare(buffer, size)` | `bool` | both | |
| `find(buffer, size)` | `mem` | both | First occurrence within `mem::storage`. |
| `dump(out, size)` | `void` | both | Hex dump for debugging. |
| `watch(size, cb, interval=1s)` | `watch_handle` | local-only | RAII polling. |
| `disasm(max_instr, max_bytes=1024)` | `vector<instruction>` | both | Zydis-decoded; reads via accessor. |
| `disasm_one()` | `optional<instruction>` | both | |
| `mem::scan(pattern)` (static) | `mem` | local-only | Scans `mem::storage`. Use `process::scan` for remote. |
| `mem::alloc(size)` (static) | `mem` | local-only | Bump-allocates from the bytebinder heap. |
| `mem::alloc_near(target, size)` (static) | `mem` | local-only | Within ±2 GiB of `target`. |
| `mem::make_executable(region, size)` (static) | `void` | local-only | W^X flip. |
| `mem::assemble(asm_function)` (static) | `mem` | local-only | AsmJit-backed code generation. |

### `bb::memory_accessor`

Abstract base. Implementations: `bb::local_accessor`, `bb::remote_accessor`.

| Method | Returns | Notes |
|---|---|---|
| `is_local()` | `bool` | |
| `process_id()` | `optional<uint32_t>` | |
| `read(addr, dst, n)` | `size_t` | Returns bytes actually read; partial on permission gap. |
| `write(addr, src, n)` | `size_t` | Local accessor temporarily flips page protection. |
| `read_protection(addr)` | `int` (posix bits) | |
| `set_protection(addr, n, new)` | `int` (previous) | Linux remote uses ptrace + injected `mprotect`. |
| `regions()` | `vector<region_info>` | |
| `modules()` | `vector<module_info>` | |
| `find_module(name)` | `optional<module_info>` | Helper on the base class. |

Thread safety: `read`, `regions`, `modules`, `read_protection` are safe to call concurrently. `write` and `set_protection` need external serialization on overlapping pages.

### `bb::pattern`

IDA-style signature matcher.

| Method | Returns | Notes |
|---|---|---|
| `parse_ida_pattern(text)` (free) | `pattern` | `?` and `??` are wildcard nibbles. |
| `scan()` | `uintptr_t` | Scans `mem::storage`. |
| `scan(accessor, base, size)` | `uintptr_t` | First match in a range. |
| `scan_all(accessor, base, size, max, on_match)` | `size_t` (matches reported) | `on_match` returning false stops early. `max=0` is unlimited. |
| `scan_all(accessor, base, size, max, on_match, cancel*, on_progress)` | `size_t` | Cancellable + progress callback per 64 KiB. |

### `bb::vmt` / `bb::vmt_handle`

Read and patch vtable entries on objects with a reversible handle.

| Method | Returns | Notes |
|---|---|---|
| `vmt(object_address)` | `vmt` | Reads `*object_address` to get the vtable. |
| `hook(index, target)` | `vmt_handle` | Patches `vtable[index]`. |
| `vmt_handle::unhook()` | `bool` | Restores the original entry. |

### Free functions and helper types

| Symbol | Purpose |
|---|---|
| `bb::parse_ida_pattern(text)` | Build a `pattern` from an IDA-style hex string. |
| `bb::set_log_sink(sink)` | Install (or clear with `{}`) a process-wide log callback. |
| `bb::log_level` | `debug` / `info` / `warn` / `error`. |
| `bb::run_init_funcs()` | Resolve and install every `static_*` registration. |
| `bytebinder_version()` | Semantic version string of the linked build. |
| `bytebinder_abi_revision()` | Monotonic ABI revision; check at dlopen time. |
| `bb::region_info` | `{base, size, protection, mapped_path}`. |
| `bb::module_info` | `{name, path, base, size}`. |
| `bb::process::module_section` | `{name, base, size, protection}` from PE/ELF section table. |
| `bb::symbol_info` | `{name, module_name, address, size}`. |
| `bb::symbolize_result` | `{symbol, offset_from_start}`. |
| `bb::process::scan_result` | `{matches, regions_scanned, regions_skipped, bytes_scanned}`. |
| `bb::pattern::scan_progress` | `{bytes_scanned, bytes_total, matches_so_far}`. |
| `bb::instruction` | `{address, length, mnemonic, text, bytes}` decoded by Zydis. |
| `bb::scoped_unlock` | RAII page-protection flip. |
| `bb::hook_handle`, `bb::watch_handle` | RAII cancellation handles. |

### Errors

`bb::memory_operation_exception` is thrown by every primitive on failure and carries a `bb::memory_error_code` enum value (`READ_FAILED`, `WRITE_FAILED`, `PROTECTION_CHANGE_FAILED`, `HOOK_INSTALLATION_FAILED`, `PATTERN_MATCH_FAILED`, `MODULE_INFO_RETRIEVAL_FAILED`, `INVALID_OPERATION`). For diagnostic breadcrumbs at OS-error sites, install a `bb::log_sink`.

### Dry-run mode

`bb::mem::set_dry_run(true)` causes the patch primitives (`nop`, `ret`, `jmp`,
`call`, `set_call`) to skip their writes. Useful for unit-testing call sites
without mutating real code. (The legacy aliases `set_debug` / `is_debug` are
deprecated.)
