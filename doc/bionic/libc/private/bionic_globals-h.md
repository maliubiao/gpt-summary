Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The request asks for a comprehensive explanation of the `bionic_globals.h` header file, covering its functionalities, relation to Android, implementation details of libc functions, dynamic linking aspects, potential errors, and how Android frameworks reach this code. It also requests Frida hooking examples.

2. **Initial Analysis of the Header File:** I first scan the header file to identify the key data structures and declarations. I notice:
    * `libc_globals`: This is the central structure holding various global state for the C library.
    * `memtag_dynamic_entries_t`:  Related to Memory Tagging Extension (MTE).
    * `libc_shared_globals`:  Crucially, this structure contains data shared between `libc.so` and the dynamic linker.
    * Function prototypes prefixed with `__libc_init_`:  These indicate initialization routines for different parts of the C library.
    * `WriteProtected`: A template suggesting that certain global variables are protected against accidental modification.
    * Includes:  Standard C headers (`inttypes.h`, `link.h`, etc.) and private Bionic headers (`private/WriteProtected.h`, etc.).

3. **Categorize Functionality:** Based on the identified structures and declarations, I start grouping functionalities:
    * **Core Libc Globals:** The `libc_globals` structure is the core, encompassing things like VDSO access, setjmp cookie, memory tagging flags, and importantly, the malloc dispatch table.
    * **Memory Management:** The presence of `MallocDispatch`, `bionic_allocator.h`, and MTE-related members strongly indicate memory management is a key area.
    * **Dynamic Linking:**  `libc_shared_globals` is a clear indicator of interaction with the dynamic linker. Members like `load_hook`, `unload_hook`, `auxv`, and TLS-related members solidify this.
    * **Security Features:** MTE related variables (`memtag`, `__libc_memtag_stack`, etc.) and mention of GWP-ASan point to security features.
    * **FD Management:** `FdTable` suggests file descriptor management.
    * **VDSO:** `vdso_entry` and `__libc_init_vdso` highlight interaction with the Virtual Dynamically-linked Shared Object.
    * **Initialization:** The `__libc_init_*` functions are responsible for setting up various subsystems.

4. **Detailed Explanation of Each Structure/Functionality:**  I then go through each identified category and elaborate on its purpose and components:
    * **`libc_globals`:** Explain each member: `vdso`, `setjmp_cookie`, memory tagging flags, and the crucial `current_dispatch_table` and its relation to malloc hooks.
    * **`memtag_dynamic_entries_t`:** Focus on its role in MTE configuration.
    * **`libc_shared_globals`:** Detail the interaction between libc and the dynamic linker, explaining each member's role in dynamic loading, TLS, and communication.
    * **`__libc_init_*` functions:** Explain their initialization roles for VDSO, malloc, setjmp cookie, MTE, FDSan, etc.

5. **Connecting to Android:**  For each functionality, I explicitly connect it to how it affects Android. Examples:
    * **Malloc:**  Essential for all Android apps and the framework. Explain its role in memory allocation for Java objects (through ART) and native code.
    * **Dynamic Linking:** Fundamental for how Android loads shared libraries (`.so` files). Explain the linker's role in resolving symbols.
    * **MTE/GWP-ASan:**  Android security features to detect memory corruption bugs.

6. **Implementation Details:**  This is where I explain *how* things might be implemented, even if the header file doesn't contain the full implementation.
    * **Malloc Dispatch:** Explain the concept of function pointers and how swapping the dispatch table allows for different malloc behaviors (debugging, hooks).
    * **Dynamic Linking:** Describe the process of loading shared libraries, relocation, and symbol resolution. I provide a sample `.so` layout and explain the linking process conceptually.
    * **VDSO:** Explain how it provides fast syscalls.

7. **Potential Errors:** I think about common mistakes developers might make related to these functionalities:
    * **Memory Management:** Double frees, use-after-free, memory leaks.
    * **Dynamic Linking:**  Dependency issues, version conflicts.

8. **Android Framework/NDK Path:** I trace a typical path from the Android framework down to these low-level libraries:
    * Java code in the framework calls native methods.
    * ART uses `dlopen` to load native libraries.
    * The dynamic linker (`linker64`) comes into play.
    * Native code uses `malloc` and other libc functions.

9. **Frida Hooking:** I provide practical Frida examples for hooking functions related to malloc, dynamic linking, and even accessing the global variables. This demonstrates how to inspect and modify behavior at this level.

10. **Review and Refine:** I reread my answer to ensure clarity, accuracy, and completeness, addressing all parts of the original request. I make sure the language is clear and avoids overly technical jargon where possible. I double-check that the examples are relevant and easy to understand. For instance, I ensure the `.so` layout example is basic but illustrative.

By following this structured approach, I can dissect the header file, understand its significance within the Android ecosystem, and provide a comprehensive and informative answer covering all aspects of the request. The key is to break down the complex topic into manageable parts and then connect those parts back to the bigger picture of how Android works.
这是一个非常重要的头文件，定义了 `bionic` C 库和动态链接器的全局变量。让我们逐步分解它的功能和相关概念。

**`bionic/libc/private/bionic_globals.h` 的功能**

这个头文件定义了两个主要的全局结构体：

1. **`libc_globals`**: 包含 `libc.so` 库自身的全局状态。
2. **`libc_shared_globals`**: 包含 `libc.so` 和动态链接器 (`linker64` 或 `linker`) 之间共享的全局状态。

此外，它还声明了一些全局变量和初始化函数。

**详细解释 `libc_globals` 的功能：**

* **`vdso_entry vdso[VDSO_END];`**:
    * **功能**: 存储 Virtual DSO (vDSO) 的入口点地址。vDSO 是内核提供的一种机制，允许用户空间程序以非常高效的方式调用某些系统调用，而无需陷入内核。
    * **Android 关系**: Android 使用 vDSO 来优化常见的系统调用，例如 `gettimeofday`。这提高了性能，因为用户空间可以直接跳转到内核映射的内存区域执行代码，避免了完整的上下文切换。
    * **实现**: 内核会在进程启动时将 vDSO 映射到进程的地址空间。`libc` 初始化时，会读取 vDSO 中导出的符号地址并存储在这里。
    * **使用错误**: 用户代码不应直接访问或修改 `vdso` 数组。
* **`long setjmp_cookie;`**:
    * **功能**: 用于防止 `setjmp`/`longjmp` 滥用导致的安全漏洞。它在 `setjmp` 时设置，并在 `longjmp` 时校验，如果被修改，则可能表示栈被破坏。
    * **Android 关系**: 这是一个通用的安全机制，用于增强程序的健壮性。
    * **实现**: `setjmp` 会将当前的栈信息和 `setjmp_cookie` 的值保存起来。`longjmp` 恢复栈信息前会检查当前 `setjmp_cookie` 的值是否与保存的值一致。
    * **使用错误**: 用户不应手动修改 `setjmp_cookie`。
* **`uintptr_t heap_pointer_tag;`**:
    * **功能**: 用于 ARM Memory Tagging Extension (MTE)。它存储分配的堆内存的指针标签。
    * **Android 关系**: MTE 是 Android 中用于检测内存安全漏洞（例如 use-after-free 和 heap-buffer-overflow）的重要安全特性。
    * **实现**: 当启用 MTE 时，内存分配器会在分配的内存地址中设置标签。CPU 会在访问内存时检查标签是否匹配。
    * **假设输入与输出**: 如果分配的地址是 `0x1000`，标签可能是 `0x42`。`heap_pointer_tag` 可能存储的就是这个标签。
* **`_Atomic(bool) decay_time_enabled;`**:
    * **功能**:  控制是否启用与时间衰减相关的特性，具体用途可能与资源管理或统计有关。
    * **Android 关系**: 具体功能需要查看相关的代码实现，可能用于优化后台任务或资源回收。
* **`_Atomic(bool) memtag;`**:
    * **功能**:  一个原子布尔值，指示是否全局启用了内存标签 (MTE)。
    * **Android 关系**:  这是控制整个进程是否使用 MTE 的总开关。
* **`_Atomic(const MallocDispatch*) current_dispatch_table;`**:
    * **功能**:  指向当前生效的内存分配器分发表格 (`MallocDispatch`) 的原子指针。
    * **Android 关系**: 允许动态切换不同的内存分配策略，用于调试 (例如 `asan`, `msan`)、性能分析 (例如 `jemalloc`) 或钩子 (malloc hooks)。
    * **实现**:  `MallocDispatch` 结构体包含一组函数指针，指向实际的内存分配、释放、重新分配等函数。通过原子地切换 `current_dispatch_table`，可以在运行时改变内存分配行为。
    * **用户/编程常见使用错误**:  用户不应直接修改 `current_dispatch_table` 指针。应使用提供的 API (例如通过环境变量或系统属性) 来配置内存分配器。
* **`_Atomic(const MallocDispatch*) default_dispatch_table;`**:
    * **功能**: 指向默认的内存分配器分发表格。
    * **Android 关系**:  当同时启用内存分配限制和其他钩子时使用。
* **`MallocDispatch malloc_dispatch_table;`**:
    * **功能**:  默认的内存分配器分发表格的实例。

**详细解释 `memtag_dynamic_entries_t` 的功能：**

这个结构体用于传递与内存标签相关的动态信息：

* **`void* memtag_globals;`**: 指向内存标签全局变量的指针。
* **`size_t memtag_globalssz;`**: 内存标签全局变量的大小。
* **`bool has_memtag_mode;`**: 指示是否定义了内存标签模式。
* **`unsigned memtag_mode;`**: 内存标签模式。
* **`bool memtag_heap;`**: 指示堆内存是否启用内存标签。
* **`bool memtag_stack;`**: 指示栈内存是否启用内存标签。

**详细解释 `libc_shared_globals` 的功能：**

这个结构体定义了 `libc.so` 和动态链接器共享的状态，是它们之间通信的关键桥梁。

* **`FdTable fd_table;`**:
    * **功能**: 管理进程的文件描述符。
    * **Android 关系**:  所有文件 I/O 操作都依赖于文件描述符。
    * **实现**: `FdTable` 内部可能维护一个数组或链表来跟踪已打开的文件描述符以及相关的状态信息。
* **`int initial_linker_arg_count = 0;`**:
    * **功能**: 记录传递给动态链接器的初始参数数量。
    * **Android 关系**:  通常为 0 或 1。
* **`ElfW(auxv_t)* auxv = nullptr;`**:
    * **功能**: 指向 Auxiliary Vector (auxv) 的指针。auxv 包含关于进程和系统的信息，例如硬件能力、页面大小等。
    * **Android 关系**:  动态链接器和 `libc` 使用 auxv 中的信息来进行初始化和配置。
* **`pthread_mutex_t abort_msg_lock = PTHREAD_MUTEX_INITIALIZER; abort_msg_t* abort_msg = nullptr;`**:
    * **功能**: 用于保护 `abort_msg` 变量，该变量可能存储关于进程中止的信息。
    * **Android 关系**:  用于在程序崩溃时收集和报告错误信息。
* **`StaticTlsLayout static_tls_layout; TlsModules tls_modules; BionicAllocator tls_allocator;`**:
    * **功能**: 管理线程本地存储 (TLS)。TLS 允许每个线程拥有自己的全局变量副本。
    * **Android 关系**:  TLS 用于存储线程特定的数据，例如 errno、pthread 相关的变量等。动态链接器负责分配和管理 TLS 空间。
    * **实现**: `StaticTlsLayout` 描述静态 TLS 的布局，`TlsModules` 跟踪已加载库的 TLS 模块，`tls_allocator` 用于动态分配 TLS 块。
* **`void (*load_hook)(ElfW(Addr) base, const ElfW(Phdr)* phdr, ElfW(Half) phnum) = nullptr;`**:
    * **功能**:  一个函数指针，指向在加载共享库后执行的钩子函数。
    * **Android 关系**:  允许 `libc` 在加载共享库时执行自定义的操作。
    * **动态链接处理过程**: 当动态链接器加载一个新的共享库时，它会调用这个钩子函数。`base` 是共享库加载的基地址，`phdr` 是程序头表的指针，`phnum` 是程序头条目的数量。
* **`void (*unload_hook)(ElfW(Addr) base, const ElfW(Phdr)* phdr, ElfW(Half) phnum) = nullptr;`**:
    * **功能**:  一个函数指针，指向在卸载共享库前执行的钩子函数。
    * **Android 关系**:  允许 `libc` 在卸载共享库时执行清理操作。
    * **动态链接处理过程**: 当动态链接器卸载一个共享库时，它会调用这个钩子函数。
* **`void (*set_target_sdk_version_hook)(int target) = nullptr;`**:
    * **功能**:  一个函数指针，指向在设置目标 SDK 版本时执行的钩子函数。
    * **Android 关系**:  允许 `libc` 根据目标 SDK 版本调整其行为。
* **`const char* init_progname = nullptr; char** init_environ = nullptr;`**:
    * **功能**:  存储程序名和环境变量的指针。
    * **Android 关系**:  由动态链接器传递给 `libc`，用于初始化全局变量，例如 `program_invocation_name` 和 `environ`。
* **`const gwp_asan::AllocatorState* gwp_asan_state = nullptr; const gwp_asan::AllocationMetadata* gwp_asan_metadata = nullptr; bool (*debuggerd_needs_gwp_asan_recovery)(void* fault_addr) = nullptr; void (*debuggerd_gwp_asan_pre_crash_report)(void* fault_addr) = nullptr; void (*debuggerd_gwp_asan_post_crash_report)(void* fault_addr) = nullptr;`**:
    * **功能**:  与 GWP-ASan (Guard Wrapped Pages - AddressSanitizer) 集成相关的指针和函数。GWP-ASan 是一种用于检测内存错误的采样式检测工具。
    * **Android 关系**:  用于在生产环境中检测内存安全问题。
* **`const char* scudo_stack_depot = nullptr; const char* scudo_region_info = nullptr; const char* scudo_ring_buffer = nullptr; size_t scudo_ring_buffer_size = 0; size_t scudo_stack_depot_size = 0;`**:
    * **功能**:  与 Scudo 内存分配器相关的调试信息。Scudo 是 bionic 默认的内存分配器。
    * **Android 关系**:  这些信息可以用于调试内存分配问题。
* **`HeapTaggingLevel initial_heap_tagging_level = M_HEAP_TAGGING_LEVEL_NONE; bool initial_memtag_stack = false; bool initial_memtag_stack_abi = false; int64_t heap_tagging_upgrade_timer_sec = 0;`**:
    * **功能**:  与堆内存标签相关的初始配置信息。
    * **Android 关系**:  用于配置 MTE 的行为。
* **`void (*memtag_stack_dlopen_callback)() = nullptr;`**:
    * **功能**:  一个函数指针，指向在 `dlopen` 调用时执行的与栈内存标签相关的回调函数。
    * **Android 关系**:  用于在加载新的共享库时处理栈内存标签。
* **`pthread_mutex_t crash_detail_page_lock = PTHREAD_MUTEX_INITIALIZER; crash_detail_page_t* crash_detail_page = nullptr;`**:
    * **功能**:  用于保护 `crash_detail_page` 变量，该变量可能存储关于崩溃的详细信息。
    * **Android 关系**:  用于在程序崩溃时收集更详细的调试信息。

**动态链接的处理过程和 SO 布局样本**

当一个可执行文件或者共享库需要加载其他的共享库时，动态链接器会介入。以下是一个简化的处理过程和一个 SO 布局示例：

**SO 布局样本:**

```
.text   (代码段 - 可执行指令)
.rodata (只读数据段 - 常量)
.data   (已初始化数据段 - 全局变量)
.bss    (未初始化数据段 - 全局变量，启动时清零)
.dynamic (动态链接信息)
.plt    (过程链接表 - 用于延迟绑定)
.got    (全局偏移表 - 用于访问全局变量和函数)
...
```

**链接的处理过程：**

1. **加载共享库**: `dlopen` 系统调用（或隐式加载）触发动态链接器加载指定的 SO 文件。
2. **内存映射**: 动态链接器将 SO 文件映射到进程的地址空间中。
3. **符号解析**: 动态链接器遍历 SO 文件的 `.dynamic` 段，查找所需的其他共享库依赖。对于每个依赖，重复步骤 1 和 2。
4. **重定位**: 动态链接器修改 SO 文件中的某些指令和数据，使其指向正确的地址。这涉及到修改 `.got` 表中的条目，以便在运行时可以正确地访问全局变量和函数。
5. **执行初始化代码**: 动态链接器执行 SO 文件中的 `DT_INIT` 和 `DT_INIT_ARRAY` 指向的初始化函数。
6. **调用 `load_hook`**: 如果定义了 `load_hook`，动态链接器会调用它。

**假设输入与输出 (关于 `load_hook`)：**

假设有一个共享库 `libexample.so`，它的程序头表信息如下：

```
程序头[0]: 类型 LOAD   偏移 0x000000 vaddr 0xb7000000 paddr 0xb7000000 文件大小 0x10000 内存大小 0x10000 标志 r-x  对齐 0x1000
程序头[1]: 类型 LOAD   偏移 0x010000 vaddr 0xb7010000 paddr 0xb7010000 文件大小 0x01000 内存大小 0x01800 标志 rw-  对齐 0x1000
```

当 `libexample.so` 被加载时，如果 `libc_shared_globals()->load_hook` 指向一个有效的函数，则该函数会被调用，输入参数如下：

* `base`: `0xb7000000` (第一个 LOAD 段的虚拟地址)
* `phdr`: 指向程序头表起始位置的指针
* `phnum`: `2` (程序头条目的数量)

`load_hook` 函数可能会执行一些与加载的库相关的初始化操作，例如记录日志或设置一些内部状态。

**libc 函数的实现 (举例说明)**

由于这是一个头文件，它只声明了函数，没有包含具体的实现。 `libc` 函数的实现通常在 `.c` 源文件中。这里举例说明一些可能的情况：

* **`malloc`**: 内存分配的核心函数。它的实现会根据配置（例如是否启用了 MTE，是否使用了特定的分配器）调用 `current_dispatch_table` 中相应的分配函数。Scudo 是 bionic 默认的 `malloc` 实现，它使用复杂的算法来管理内存块，跟踪已分配的内存，并尽量减少碎片。
* **`free`**: 释放 `malloc` 分配的内存。它也会通过 `current_dispatch_table` 调用相应的释放函数，Scudo 会将释放的内存块标记为可用，并可能合并相邻的空闲块。
* **`dlopen`**:  动态加载共享库的函数。它的实现会调用底层的系统调用（如 `__dl_dlopen`），然后动态链接器会接管，执行上面描述的链接过程。
* **`pthread_create`**: 创建新线程的函数。它的实现会调用底层的内核 `clone` 系统调用，并设置新的线程栈、TLS 等信息。

**Android Framework 或 NDK 如何到达这里**

1. **Java 代码调用 Native 方法**: Android Framework 中的 Java 代码经常需要调用 Native 代码来执行一些底层操作或利用 C/C++ 库。这通常通过 JNI (Java Native Interface) 实现。
2. **ART (Android Runtime) 加载 Native 库**: 当 Java 代码调用一个 Native 方法时，ART 会使用 `dlopen` 加载包含该方法的 Native 库 (`.so` 文件)。
3. **动态链接器 (`linker64` 或 `linker`) 介入**: `dlopen` 调用会触发动态链接器开始工作，它会解析库的依赖，加载所需的其他共享库，并进行符号重定位。
4. **Native 代码执行，调用 libc 函数**: 加载的 Native 代码可以使用标准 C 库函数，例如 `malloc`, `free`, `pthread_mutex_lock` 等。这些函数最终会链接到 `bionic` 提供的实现。

**Frida Hook 示例**

以下是一些使用 Frida hook 这个头文件中定义的变量或函数的示例：

```javascript
// Hook malloc 函数 (通过 current_dispatch_table)
Interceptor.attach(Module.findExportByName("libc.so", "__malloc_default_dispatch"), {
  onEnter: function(args) {
    console.log("malloc called with size: " + args[0]);
  },
  onLeave: function(retval) {
    console.log("malloc returned: " + retval);
  }
});

// Hook dlopen 函数
Interceptor.attach(Module.findExportByName("linker64", "__dl_dlopen"), {
  onEnter: function(args) {
    console.log("dlopen called with path: " + args[0]);
  },
  onLeave: function(retval) {
    console.log("dlopen returned: " + retval);
  }
});

// 读取 __libc_globals 变量 (需要找到其地址)
var libc_globals_ptr = Module.findSymbolName("__libc_globals");
if (libc_globals_ptr) {
  var libc_globals = ptr(libc_globals_ptr).readPointer(); // 读取 WriteProtected 的指针
  console.log("__libc_globals address: " + libc_globals);

  // 读取 heap_pointer_tag
  var heap_pointer_tag = libc_globals.add(8).readU64(); // 假设偏移量
  console.log("heap_pointer_tag: " + heap_pointer_tag);
}

// Hook load_hook (需要先找到 __libc_shared_globals 的地址)
var libc_shared_globals_ptr = Module.findSymbolName("__libc_shared_globals");
if (libc_shared_globals_ptr) {
  var libc_shared_globals = ptr(libc_shared_globals_ptr).readPointer();
  var load_hook_ptr = libc_shared_globals.add(offsetof(libc_shared_globals, 'load_hook')).readPointer(); // 获取 load_hook 的地址

  if (!load_hook_ptr.isNull()) {
    Interceptor.attach(load_hook_ptr, {
      onEnter: function(args) {
        console.log("load_hook called with base: " + args[0]);
      }
    });
  } else {
    console.log("load_hook is null");
  }
}

function offsetof(struct, member) {
  const struct_layout = Process.findModuleByName("libc.so").enumerateSymbols().find(s => s.name.includes(struct) && s.name.includes(member));
  if (struct_layout) {
    const offsetMatch = struct_layout.name.match(/offset=([0-9]+)/);
    if (offsetMatch) {
      return parseInt(offsetMatch[1]);
    }
  }
  return undefined;
}
```

**用户或编程常见的使用错误**

* **内存管理错误**:
    * **Double free**: 多次释放同一块内存。
    * **Use-after-free**: 访问已经释放的内存。
    * **Memory leak**: 分配的内存没有被释放。
    * **Heap buffer overflow**: 写入超过分配内存大小的数据。
* **动态链接错误**:
    * **找不到共享库**: 依赖的共享库不在指定的路径中。
    * **符号未定义**:  程序尝试调用或访问一个在加载的库中不存在的符号。
    * **版本冲突**:  依赖的共享库版本不兼容。
* **多线程错误**:
    * **竞争条件**: 多个线程以不可预测的顺序访问共享资源，导致错误的结果。
    * **死锁**: 多个线程互相等待对方释放资源。
    * **未正确初始化互斥锁/条件变量**: 导致程序行为异常。

希望这个详细的解释能够帮助你理解 `bionic_globals.h` 的作用和它在 Android 系统中的重要性。这个头文件是理解 Android 底层机制的关键入口点之一。

Prompt: 
```
这是目录为bionic/libc/private/bionic_globals.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。

"""
/*
 * Copyright (C) 2015 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _PRIVATE_BIONIC_GLOBALS_H
#define _PRIVATE_BIONIC_GLOBALS_H

#include <inttypes.h>
#include <link.h>
#include <platform/bionic/malloc.h>
#include <pthread.h>
#include <stdatomic.h>
#include <sys/cdefs.h>

#include "private/WriteProtected.h"
#include "private/bionic_allocator.h"
#include "private/bionic_elf_tls.h"
#include "private/bionic_fdsan.h"
#include "private/bionic_malloc_dispatch.h"
#include "private/bionic_vdso.h"

struct libc_globals {
  vdso_entry vdso[VDSO_END];
  long setjmp_cookie;
  uintptr_t heap_pointer_tag;
  _Atomic(bool) decay_time_enabled;
  _Atomic(bool) memtag;

  // In order to allow a complete switch between dispatch tables without
  // the need for copying each function by function in the structure,
  // use a single atomic pointer to switch.
  // The current_dispatch_table pointer can only ever be set to a complete
  // table. Any dispatch table that is pointed to by current_dispatch_table
  // cannot be modified after that. If the pointer changes in the future,
  // the old pointer must always stay valid.
  // The malloc_dispatch_table is modified by malloc debug, malloc hooks,
  // and heaprofd. Only one of these modes can be active at any given time.
  _Atomic(const MallocDispatch*) current_dispatch_table;
  // This pointer is only used by the allocation limit code when both a
  // limit is enabled and some other hook is enabled at the same time.
  _Atomic(const MallocDispatch*) default_dispatch_table;
  MallocDispatch malloc_dispatch_table;
};

struct memtag_dynamic_entries_t {
  void* memtag_globals;
  size_t memtag_globalssz;
  bool has_memtag_mode;
  unsigned memtag_mode;
  bool memtag_heap;
  bool memtag_stack;
};

__LIBC_HIDDEN__ extern WriteProtected<libc_globals> __libc_globals;
// These cannot be in __libc_globals, because we cannot access the
// WriteProtected in a thread-safe way.
// See b/328256432.
//
// __libc_memtag_stack says whether stack MTE is enabled on the process, i.e.
// whether the stack pages are mapped with PROT_MTE. This is always false if
// MTE is disabled for the process (i.e. libc_globals.memtag is false).
__LIBC_HIDDEN__ extern _Atomic(bool) __libc_memtag_stack;
// __libc_memtag_stack_abi says whether the process contains any code that was
// compiled with memtag-stack. This is true even if the process does not have
// MTE enabled (e.g. because it was overridden using MEMTAG_OPTIONS, or because
// MTE is disabled for the device).
// Code compiled with memtag-stack needs a stack history buffer in
// TLS_SLOT_STACK_MTE, because the codegen will emit an unconditional
// (to keep the code branchless) write to it.
// Protected by g_heap_creation_lock.
__LIBC_HIDDEN__ extern bool __libc_memtag_stack_abi;

struct abort_msg_t;
struct crash_detail_page_t;
namespace gwp_asan {
struct AllocatorState;
struct AllocationMetadata;
};  // namespace gwp_asan

// Globals shared between the dynamic linker and libc.so.
struct libc_shared_globals {
  // Construct the shared globals using a constexpr constructor to ensure that
  // the object doesn't need dynamic initialization. The object is accessed
  // before the dynamic linker has relocated itself.
  constexpr libc_shared_globals() {}

  FdTable fd_table;

  // When the linker is invoked on a binary (e.g. `linker64 /system/bin/date`),
  // record the number of arguments passed to the linker itself rather than to
  // the program it's loading. Typically 0, sometimes 1.
  int initial_linker_arg_count = 0;

  ElfW(auxv_t)* auxv = nullptr;

  pthread_mutex_t abort_msg_lock = PTHREAD_MUTEX_INITIALIZER;
  abort_msg_t* abort_msg = nullptr;

  StaticTlsLayout static_tls_layout;
  TlsModules tls_modules;
  BionicAllocator tls_allocator;

  // Values passed from libc.so to the loader.
  void (*load_hook)(ElfW(Addr) base, const ElfW(Phdr)* phdr, ElfW(Half) phnum) = nullptr;
  void (*unload_hook)(ElfW(Addr) base, const ElfW(Phdr)* phdr, ElfW(Half) phnum) = nullptr;
  void (*set_target_sdk_version_hook)(int target) = nullptr;

  // Values passed from the linker to libc.so.
  const char* init_progname = nullptr;
  char** init_environ = nullptr;

  const gwp_asan::AllocatorState* gwp_asan_state = nullptr;
  const gwp_asan::AllocationMetadata* gwp_asan_metadata = nullptr;
  bool (*debuggerd_needs_gwp_asan_recovery)(void* fault_addr) = nullptr;
  void (*debuggerd_gwp_asan_pre_crash_report)(void* fault_addr) = nullptr;
  void (*debuggerd_gwp_asan_post_crash_report)(void* fault_addr) = nullptr;

  const char* scudo_stack_depot = nullptr;
  const char* scudo_region_info = nullptr;
  const char* scudo_ring_buffer = nullptr;
  size_t scudo_ring_buffer_size = 0;
  size_t scudo_stack_depot_size = 0;

  HeapTaggingLevel initial_heap_tagging_level = M_HEAP_TAGGING_LEVEL_NONE;
  // See comments for __libc_memtag_stack / __libc_memtag_stack_abi above.
  bool initial_memtag_stack = false;
  bool initial_memtag_stack_abi = false;
  int64_t heap_tagging_upgrade_timer_sec = 0;

  void (*memtag_stack_dlopen_callback)() = nullptr;
  pthread_mutex_t crash_detail_page_lock = PTHREAD_MUTEX_INITIALIZER;
  crash_detail_page_t* crash_detail_page = nullptr;
};

__LIBC_HIDDEN__ libc_shared_globals* __libc_shared_globals();
__LIBC_HIDDEN__ bool __libc_mte_enabled();
__LIBC_HIDDEN__ void __libc_init_mte(const memtag_dynamic_entries_t*, const void*, size_t,
                                     uintptr_t);
__LIBC_HIDDEN__ void __libc_init_mte_stack(void*);
__LIBC_HIDDEN__ void __libc_init_fdsan();
__LIBC_HIDDEN__ void __libc_init_fdtrack();
__LIBC_HIDDEN__ void __libc_init_profiling_handlers();

__LIBC_HIDDEN__ void __libc_init_malloc(libc_globals* globals);
__LIBC_HIDDEN__ void __libc_init_setjmp_cookie(libc_globals* globals);
__LIBC_HIDDEN__ void __libc_init_vdso(libc_globals* globals);

#if defined(__i386__)
__LIBC_HIDDEN__ extern void* __libc_sysinfo;
extern "C" __LIBC_HIDDEN__ void __libc_int0x80();
__LIBC_HIDDEN__ void __libc_init_sysinfo();
#endif

#endif

"""

```