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

- **Memory Address Handling**: Easily manage and manipulate memory addresses with simple and intuitive methods.
- **Cross-Platform Support**: Compatible with both Windows and Unix-like systems for maximum flexibility.
- **Memory Initialization**: Initialize memory addresses and heap allocations efficiently.
- **Hooking and Patching**: Install hooks and patches on functions with ease.
- **Memory Scanning and Pattern Matching**: Search for patterns in memory to locate specific data.
- **Memory Watching**: Monitor changes in memory and trigger callbacks on modifications.
- **Error Handling**: Robust error handling with detailed exception messages.

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

## Reference

The full API is documented inline in `include/`. Briefly:

- `bb::process` — handle to the current process or a remote PID
  (`process::current()`, `process::attach(pid)`). Owns a `memory_accessor`,
  enumerates modules and regions, and exposes `at(address)` plus a
  process-aware `scan(pattern, optional<module>)`.
- `bb::memory_accessor` — abstract read/write/protection/region/module
  surface. Implementations: `bb::local_accessor` (in-process direct
  dereference) and `bb::remote_accessor` (`Read/WriteProcessMemory` or
  `process_vm_readv/writev`).
- `bb::mem` — fluent wrapper over a `uintptr_t` and a bound accessor.
  Offset math (`add`, `rip`); typed accessor-aware I/O (`read<T>`, `write<T>`,
  `read_bytes`, `write_bytes`); local-only pointer view (`get<T>`); patch
  primitives (`nop`, `ret`, `jmp`, `call`, `set_call`, `hook<T>` — all
  local-only); search (`compare`, `find`); allocation (`alloc`, `alloc_near`,
  `make_executable` — local-only); code generation (`assemble` — local-only);
  observability (`dump`, `watch`).
- `bb::scoped_unlock` — RAII page-protection flip; restores the original
  permissions on destruction.
- `bb::pattern` — IDA-style signature matcher. Used by `mem::scan`.
- `bb::hook_handle` / `bb::watch_handle` — RAII cancellation handles.
- `bb::static_mem<T>`, `bb::static_func<R, Args...>`, `bb::static_hook<R, Args...>`,
  `bb::init_func` — declarative registration; `bb::run_init_funcs()` flushes
  the queue.
- `bb::memory_operation_exception` / `bb::memory_error_code` — thrown by every
  primitive on failure; carries a typed error code.

### Dry-run mode

`bb::mem::set_dry_run(true)` causes the patch primitives (`nop`, `ret`, `jmp`,
`call`, `set_call`) to skip their writes. Useful for unit-testing call sites
without mutating real code. (The legacy aliases `set_debug` / `is_debug` are
deprecated.)
