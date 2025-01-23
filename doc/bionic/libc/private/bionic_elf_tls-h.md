Response:
Let's break down the thought process for analyzing this C header file (`bionic_elf_tls.handroid`). The goal is to understand its functionality and its place within the Android ecosystem.

**1. Initial Scan and Keyword Identification:**

The first step is a quick skim of the file, looking for recurring keywords and structural elements. Immediately, terms like "TLS," "thread," "dynamic linker," "module," "offset," and "segment" stand out. The presence of `struct`, `typedef`, `extern`, and `#pragma once` confirms it's a C/C++ header file likely defining data structures and function declarations.

**2. Understanding the Core Concept: TLS (Thread-Local Storage):**

The filename itself, `bionic_elf_tls.handroid`, strongly suggests a focus on Thread-Local Storage (TLS) within the Android Bionic library. This becomes the central theme. TLS allows each thread to have its own private copy of global variables. This is crucial for multithreaded applications to avoid data races and maintain thread safety.

**3. Analyzing the Data Structures (structs):**

The next step is to examine the defined structs, as they represent the key building blocks of the TLS implementation.

*   **`TlsAlign`:**  This struct clearly deals with memory alignment, a performance optimization technique. It stores the alignment value and a skew. The `of_type` template suggests it's used to determine the alignment requirement of specific data types.

*   **`TlsAlignedSize`:**  This struct combines the size of a memory block with its alignment requirements. Again, the `of_type` template is present.

*   **`TlsSegment`:**  This represents a contiguous block of memory associated with TLS. It includes the aligned size, a pointer to initialization data, and the size of that initialization data. This hints at how TLS data might be initialized when a thread starts.

*   **`StaticTlsLayout`:** This is more complex. The name suggests it manages the layout of TLS data that is known at compile/link time. The member variables like `offset_bionic_tcb_`, `offset_bionic_tls_`, `offset_exe_`, and the `reserve_*` functions indicate its role in allocating and tracking space for different parts of static TLS. The `TpAllocations` substructure and `reserve_tp_pair` suggest management of the thread pointer.

*   **`TlsModule`:**  This struct describes a single TLS module, which can be either the main executable or a shared library (.so). It stores the segment information, the static offset (if it's a statically linked module), the generation in which it was loaded, and a pointer to the `soinfo` (shared object information) structure used by the dynamic linker.

*   **`TlsModules`:** This struct acts as a container for all TLS modules. It includes a generation counter (important for tracking when modules are loaded/unloaded), a read-write lock for thread safety, an array of `TlsModule` structures, and callbacks for when dynamic TLS is created or destroyed. The presence of thread exit callbacks is also notable.

*   **`TlsDtv`:**  The "Dynamic Thread Vector" is a critical component for dynamic linking and TLS. Each thread gets its own DTV. It contains a count, a pointer to a previous DTV (for cleanup), a generation number, and an array of pointers to the TLS data of each loaded module. The comment about not being part of the public ABI is important.

*   **`TlsIndex`:** This simple struct is used as an argument to the `__tls_get_addr` function. It contains the module ID and the offset within that module's TLS data.

*   **`bionic_tcb`:** While not fully defined here, its mention and use in `__free_dynamic_tls` indicates it's the Thread Control Block, a fundamental data structure for managing threads.

*   **`CallbackHolder`:**  A simple linked list node for managing thread exit callbacks.

**4. Analyzing Function Declarations:**

The function declarations provide insight into the operations performed on the TLS data structures.

*   `__bionic_get_tls_segment`:  Retrieves TLS segment information from the program headers.
*   `__bionic_check_tls_align`: Verifies alignment requirements.
*   `StaticTlsLayout::reserve_*`: Functions for reserving space within the static TLS layout.
*   `__init_static_tls`: Initializes the static TLS region for a thread.
*   `TLS_GET_ADDR` (`__tls_get_addr`): The core function for resolving the address of a thread-local variable given a `TlsIndex`.
*   `__free_dynamic_tls`:  Releases dynamically allocated TLS memory.
*   `__notify_thread_exit_callbacks`: Executes the registered thread exit callbacks.

**5. Identifying Connections to Android and the Dynamic Linker:**

The file explicitly mentions "Bionic" (Android's C library) and "dynamic linker."  The presence of `ElfW(Phdr)`, `load_bias`, and `soinfo_ptr` in the `TlsModule` struct strongly links this code to the ELF format and dynamic linking process. The comments about the DTV being related to `dlopen` further solidify this connection.

**6. Inferring Functionality and Purpose:**

By combining the analysis of data structures and function declarations, we can deduce the following functionalities:

*   **Static TLS Layout Management:** `StaticTlsLayout` manages the allocation and organization of TLS data known at link time.
*   **Dynamic TLS Allocation and Management:** The `TlsModules` and `TlsDtv` structures, along with functions like `__free_dynamic_tls`, handle the creation and management of TLS data for dynamically loaded libraries.
*   **TLS Address Resolution:** The `__tls_get_addr` function is the central mechanism for accessing thread-local variables.
*   **Thread Exit Handling:** The callbacks provide a way to perform cleanup actions when a thread terminates.
*   **Synchronization:** The `pthread_rwlock_t` in `TlsModules` ensures thread-safe access to the TLS module table.

**7. Considering User and Programming Errors:**

Based on the identified functionalities, we can think about potential errors:

*   **Incorrect Alignment:**  Manually allocating TLS data without respecting alignment requirements could lead to crashes.
*   **Accessing Uninitialized TLS:** Trying to access a thread-local variable before it's initialized could lead to undefined behavior.
*   **Race Conditions (less likely here due to internal locking):**  While the code itself uses locks, incorrect usage of thread-local variables in application code could still lead to race conditions.
*   **Memory Leaks (potentially):**  If dynamic TLS memory isn't properly freed.

**8. Tracing the Path from Android Framework/NDK:**

This requires understanding the Android process startup and dynamic linking process.

*   When an Android app starts, the zygote process forks a new process.
*   The dynamic linker (`linker64` or `linker`) is responsible for loading the necessary shared libraries.
*   During library loading, the dynamic linker interacts with the TLS mechanisms defined in this header to allocate and initialize TLS data for each library.
*   When NDK code uses thread-local variables (declared with `__thread` or `thread_local`), the compiler generates code that relies on functions like `__tls_get_addr` to access these variables.

**9. Frida Hooking (Conceptual):**

To debug, one would use Frida to intercept calls to key functions like:

*   `__bionic_get_tls_segment`: To see how TLS segments are identified.
*   `StaticTlsLayout::reserve_*`: To observe the layout process.
*   `__init_static_tls`: To inspect the initial TLS setup.
*   `__tls_get_addr`: To understand how TLS addresses are resolved at runtime.
*   Callbacks in `TlsModules`: To see when dynamic TLS is created/destroyed.

**Self-Correction/Refinement During the Process:**

Initially, one might focus solely on the individual structs and functions. However, realizing the overarching theme of TLS and its connection to the dynamic linker is crucial. Connecting the individual pieces together to form a coherent picture of the TLS management process is a key part of the analysis. For example, noticing how `TlsModule` links the segment information with the `soinfo_ptr` strengthens the understanding of its role in dynamic linking. Similarly, understanding the purpose of the DTV and its connection to dynamic loading is an iterative process.
这个头文件 `bionic/libc/private/bionic_elf_tls.handroid` 定义了 Android Bionic C 库中与 ELF TLS (Thread-Local Storage，线程本地存储) 相关的内部数据结构和函数。它主要负责管理和组织每个线程独有的数据存储空间。由于它位于 `private` 目录下，这意味着这些接口是 Bionic 内部使用的，不属于公共 API，开发者不应该直接依赖它们。

**功能列举:**

1. **定义 TLS 相关的数据结构:**
    *   `TlsAlign`: 描述 TLS 数据的对齐方式。
    *   `TlsAlignedSize`:  表示 TLS 数据的大小和对齐方式。
    *   `TlsSegment`:  代表一个 TLS 段，包含其大小、初始化数据指针和大小。
    *   `StaticTlsLayout`:  用于管理静态 TLS 区域的布局，即在程序加载时就确定的 TLS 数据。
    *   `TlsModule`: 描述一个 TLS 模块，通常对应一个可执行文件或共享库。
    *   `TlsModules`:  管理所有 TLS 模块的表格，包括静态和动态加载的模块。
    *   `TlsDtv`:  Dynamic Thread Vector（动态线程向量），用于在运行时查找 TLS 数据。每个线程都有自己的 DTV。
    *   `TlsIndex`:  用于 `__tls_get_addr` 函数的参数，指定要访问的 TLS 变量所属的模块 ID 和偏移量。
    *   `CallbackHolder`:  用于管理线程退出时需要调用的回调函数链表。

2. **声明和定义用于操作 TLS 的内部函数:**
    *   `__bionic_get_tls_segment`: 从程序头表中获取 TLS 段的信息。
    *   `__bionic_check_tls_align`:  检查给定的对齐值是否有效。
    *   `__init_static_tls`: 初始化线程的静态 TLS 区域。
    *   `TLS_GET_ADDR` (`__tls_get_addr`):  核心函数，用于获取线程局部变量的地址。
    *   `__free_dynamic_tls`:  释放动态分配的 TLS 内存。
    *   `__notify_thread_exit_callbacks`:  通知并执行所有注册的线程退出回调函数。

3. **定义 TLS 相关的常量:**
    *   `kTlsGenerationNone`, `kTlsGenerationFirst`:  用于跟踪 TLS 模块加载和卸载的代数。
    *   `kTlsUninitializedModuleId`:  表示未初始化的模块 ID。

**与 Android 功能的关系及举例说明:**

这个头文件是 Bionic C 库的内部实现，直接支撑着 Android 平台上多线程应用程序对线程局部存储的使用。

*   **多线程支持:** Android 应用经常使用多线程来提高性能和响应速度。TLS 允许每个线程拥有自己的变量副本，避免了线程之间的数据竞争和同步问题。例如，一个网络请求库可能为每个请求线程维护一个独立的连接池。

*   **动态链接器 (linker):** Android 使用动态链接器来加载共享库 (`.so` 文件)。每个共享库可能包含自己的 TLS 数据。这个头文件中定义的 `TlsModule` 和 `TlsModules` 结构体以及相关的函数，就是动态链接器管理和访问这些 TLS 数据的关键。当一个共享库被加载或卸载时，动态链接器会更新 `TlsModules` 表格，并可能导致 `TlsDtv` 的扩展或更新。

*   **NDK 开发:** 使用 Android NDK 进行原生开发的开发者可以使用 `__thread` 关键字（C++11）或特定于编译器的属性来声明线程局部变量。Bionic 内部就使用这里的机制来实现这些线程局部变量的存储和访问。

**libc 函数的功能实现详解:**

这里列出的主要是 Bionic 内部函数，不属于公开的 libc 函数。但它们的功能是支撑 libc 中与线程相关的特性。

*   **`__bionic_get_tls_segment(const ElfW(Phdr)* phdr_table, size_t phdr_count, ElfW(Addr) load_bias, TlsSegment* out)`:**
    *   **功能:**  遍历可执行文件或共享库的程序头表 (`phdr_table`)，查找类型为 `PT_TLS` 的段。如果找到，就将该 TLS 段的大小、初始化数据地址和大小等信息填充到 `out` 指向的 `TlsSegment` 结构体中。`load_bias` 是加载地址的偏移量。
    *   **实现:**  该函数会迭代程序头表中的每个条目，检查 `p_type` 字段是否等于 `PT_TLS`。如果匹配，它会将 `p_memsz` (内存大小) 赋值给 `out->aligned_size.size`，`p_vaddr + load_bias` 赋值给 `out->init_ptr`（这里假设初始化数据的地址等于虚拟地址），`p_filesz` (文件大小) 赋值给 `out->init_size`。

*   **`__bionic_check_tls_align(size_t align)`:**
    *   **功能:**  检查给定的对齐值 `align` 是否是 2 的幂。TLS 数据通常需要满足特定的对齐要求以提高性能。
    *   **实现:**  可以使用位运算来检查，例如 `(align > 0) && ((align & (align - 1)) == 0)`。

*   **`__init_static_tls(void* static_tls)`:**
    *   **功能:**  在线程创建时，为该线程的静态 TLS 区域进行初始化。这个区域的大小和布局在编译链接时就已经确定。
    *   **实现:**  根据 `StaticTlsLayout` 计算出的偏移量，将可执行文件和静态链接的共享库的 TLS 初始化数据复制到 `static_tls` 指向的内存区域。

*   **`TLS_GET_ADDR(const TlsIndex* ti)` 或 `__tls_get_addr(const TlsIndex* ti)`:**
    *   **功能:**  这是访问线程局部变量的核心函数。给定一个 `TlsIndex`，它返回该线程中对应 TLS 变量的地址。
    *   **实现:**
        1. **获取 DTV:**  从当前线程的控制块（`pthread_t` 或 `bionic_tcb`）中获取指向该线程的 DTV 的指针。
        2. **查找模块基址:**  使用 `ti->module_id` 作为索引访问 DTV 中的条目。DTV 的每个条目存储着对应模块的 TLS 数据的起始地址。
        3. **计算最终地址:**  将 DTV 中获取的模块基址加上 `ti->offset`，得到最终的线程局部变量的地址。
        4. **处理动态加载:**  如果模块是动态加载的，DTV 可能需要动态扩展。Bionic 内部会处理这种情况，确保 DTV 有足够的空间来存储新加载模块的 TLS 数据地址。

*   **`__free_dynamic_tls(bionic_tcb* tcb)`:**
    *   **功能:**  在线程退出时，释放该线程动态分配的 TLS 内存。
    *   **实现:**  该函数会获取 `tcb` 中指向该线程的 `TlsDtv` 的指针，并释放 DTV 结构本身以及 DTV 中指向的动态分配的 TLS 数据块。

*   **`__notify_thread_exit_callbacks()`:**
    *   **功能:**  在线程即将退出时，遍历并执行注册到该线程的退出回调函数。
    *   **实现:**  从线程的控制块中获取回调函数链表的头节点，然后依次遍历链表，调用每个 `CallbackHolder` 中存储的回调函数。

**涉及 dynamic linker 的功能，so 布局样本，以及链接的处理过程:**

*   **功能关联:** `TlsModule` 结构体中的 `soinfo_ptr` 字段指向动态链接器维护的 `soinfo` 结构，该结构包含了已加载共享库的各种信息，例如加载地址、依赖关系等。动态链接器在加载共享库时，会解析其程序头表，调用 `__bionic_get_tls_segment` 获取 TLS 段的信息，并将其添加到 `TlsModules` 表格中。同时，也会更新当前线程的 DTV，使其包含新加载的共享库的 TLS 数据地址。

*   **so 布局样本:**

```
LOAD off    0x00000000 vaddr 0xXXXXXXXX paddr 0xXXXXXXXX flags r-x size 0xYYYY
LOAD off    0x000YYYY  vaddr 0xXXXXXXXX+0xYYYY paddr 0xXXXXXXXX+0xYYYY flags r-- size 0xZZZZ
LOAD off    0x000YYYY+0xZZZZ vaddr 0xXXXXXXXX+0xYYYY+0xZZZZ paddr 0xXXXXXXXX+0xYYYY+0xZZZZ flags rw- size 0xAAAA
TLS  off    0xBBBBBBBB vaddr 0xCCCCCCCC paddr 0xDDDDDDDD flags --- size 0xEEEE align 0x8
```

这是一个简化的共享库 ELF 文件布局示例。其中 `TLS` 行表示 TLS 段的信息：

    *   `off`: TLS 段在文件中的偏移量。
    *   `vaddr`: TLS 段的虚拟地址。
    *   `paddr`: TLS 段的物理地址（通常与虚拟地址相同）。
    *   `flags`: TLS 段的权限标志。
    *   `size`: TLS 段的大小。
    *   `align`: TLS 段的对齐要求。

*   **链接的处理过程:**
    1. **链接时:** 静态链接器在链接可执行文件和共享库时，会为每个包含 TLS 数据的模块预留空间，并计算出静态 TLS 区域的布局。`StaticTlsLayout` 结构体及其相关函数就是用于执行此操作的。
    2. **加载时:** 当动态链接器加载一个共享库时，它会读取该库的程序头表，找到 `PT_TLS` 段。
    3. **TLS 模块注册:**  动态链接器会创建一个 `TlsModule` 结构体，并将从程序头表获取的 TLS 段信息（大小、对齐等）存储进去。这个 `TlsModule` 会被添加到全局的 `TlsModules` 表格中。
    4. **DTV 更新:** 对于新加载的共享库，动态链接器需要确保每个线程的 DTV 都有一个条目指向该库的 TLS 数据。如果当前线程的 DTV 不够大，动态链接器会分配一个更大的 DTV，并将旧 DTV 的内容复制过来，然后添加新模块的 TLS 数据地址。
    5. **地址解析:** 当代码访问一个线程局部变量时，编译器会生成访问 `__tls_get_addr` 的代码，并传递一个 `TlsIndex`。`__tls_get_addr` 根据 `TlsIndex` 中的模块 ID 和偏移量，在当前线程的 DTV 中查找对应的 TLS 数据地址。

**逻辑推理，假设输入与输出:**

假设有一个包含 TLS 变量的共享库 `libexample.so` 被加载。

*   **假设输入:**
    *   `libexample.so` 的程序头表中包含一个 `PT_TLS` 段，大小为 64 字节，对齐为 8 字节。
    *   `libexample.so` 被加载到内存地址 `0x7000000000`。
    *   当前线程的 DTV 大小为 N，可以容纳 M 个模块的 TLS 数据地址。

*   **逻辑推理过程:**
    1. 动态链接器解析 `libexample.so` 的程序头表，调用 `__bionic_get_tls_segment` 获取 TLS 段信息。
    2. 创建一个 `TlsModule` 结构体，记录 `libexample.so` 的 TLS 段大小为 64，对齐为 8。
    3. 如果 `libexample.so` 是第一个被加载的共享库，它的模块 ID 将是 1。
    4. 动态链接器需要更新当前线程的 DTV。如果 N 不足以容纳 M+1 个模块，则会分配一个更大的 DTV。
    5. 新 DTV 的索引 0 位置（对应模块 ID 1）将指向为 `libexample.so` 分配的 TLS 存储区域的起始地址。这个地址通常会在线程的 TLS 区域内分配。

*   **假设输出:**
    *   `TlsModules` 表格中添加了一个新的 `TlsModule` 条目，记录了 `libexample.so` 的 TLS 信息。
    *   当前线程的 DTV 被更新，其索引 0 的值指向 `libexample.so` 的 TLS 数据起始地址，例如 `0x7fff55554000`。
    *   当代码尝试访问 `libexample.so` 中的一个偏移为 16 字节的线程局部变量时，`__tls_get_addr` 会使用模块 ID 1 和偏移 16，从 DTV 中获取 `0x7fff55554000`，然后加上偏移 16，得到最终地址 `0x7fff55554010`。

**用户或者编程常见的使用错误:**

1. **不正确的 TLS 变量声明:** 在不支持线程局部存储的环境中使用 `__thread` 或 `thread_local` 关键字，或者在 C 代码中使用不正确的编译器扩展。

2. **在线程创建之前访问 TLS 变量:**  线程局部变量在线程创建时才会被初始化。在线程创建之前尝试访问这些变量会导致未定义的行为，通常是访问到未分配的内存。

3. **混淆静态和动态 TLS:**  理解静态 TLS（在程序加载时分配）和动态 TLS（为动态加载的库分配）的区别很重要。尝试在静态上下文中访问动态 TLS 变量可能会失败。

4. **内存泄漏 (较少见，通常由系统管理):**  虽然 TLS 内存通常由系统管理，但在某些特殊情况下，如果用户自定义了 TLS 的分配和释放机制，可能会导致内存泄漏。

**Android framework 或 ndk 是如何一步步的到达这里:**

1. **NDK 开发 (C/C++):**
    *   开发者在 NDK 代码中使用 `__thread` 关键字声明线程局部变量，例如 `__thread int my_thread_local_var;`。
    *   编译器在编译时，会将对 `my_thread_local_var` 的访问转换为调用 `__tls_get_addr` 函数的代码，并生成相应的 `TlsIndex`。
    *   当程序运行时，如果代码执行到访问 `my_thread_local_var` 的地方，就会调用 `__tls_get_addr`。
    *   `__tls_get_addr` 函数会按照上述的步骤，从当前线程的 DTV 中查找并返回该变量的地址。

2. **Android Framework (Java/Kotlin) and Native Bridge:**
    *   虽然 Java/Kotlin 代码本身不直接使用这里的 TLS 机制，但 Android Framework 的某些底层组件，例如 Binder 驱动、ART 虚拟机等，可能会使用 C/C++ 实现，并利用 TLS 来存储线程特定的数据。
    *   当 Java/Kotlin 代码通过 JNI 调用到 Native 代码时，如果 Native 代码中使用了 TLS 变量，那么访问这些变量的路径与 NDK 开发类似。

**Frida hook 示例调试这些步骤:**

以下是一个使用 Frida hook `__tls_get_addr` 函数的示例：

```javascript
if (Process.arch === 'arm64') {
    const tls_get_addr_ptr = Module.findExportByName(null, "__tls_get_addr");

    if (tls_get_addr_ptr) {
        Interceptor.attach(tls_get_addr_ptr, {
            onEnter: function (args) {
                const ti = ptr(args[0]);
                const module_id = ti.readUSize();
                const offset = ti.add(Process.pointerSize).readUSize();
                console.log("[__tls_get_addr] Called");
                console.log("  Module ID:", module_id);
                console.log("  Offset:", offset);
                // 你可以进一步读取 DTV 的内容来查看地址解析过程
            },
            onLeave: function (retval) {
                console.log("  Return Value (Address):", retval);
            }
        });
    } else {
        console.error("__tls_get_addr not found!");
    }
} else {
    console.log("Frida hook example is for arm64 architecture.");
}
```

**解释:**

1. **`Process.arch === 'arm64'`:**  检查当前进程的架构是否为 arm64，因为 `__tls_get_addr` 的调用约定可能因架构而异。
2. **`Module.findExportByName(null, "__tls_get_addr")`:**  在所有已加载的模块中查找 `__tls_get_addr` 函数的地址。
3. **`Interceptor.attach(...)`:**  使用 Frida 的 `Interceptor` API 拦截对 `__tls_get_addr` 函数的调用。
4. **`onEnter: function (args)`:**  在函数调用前执行。`args` 数组包含了传递给函数的参数。对于 `__tls_get_addr`，第一个参数是指向 `TlsIndex` 结构体的指针。
5. **`const ti = ptr(args[0]);`:** 将参数转换为 Frida 的 `NativePointer` 对象。
6. **`const module_id = ti.readUSize();` 和 `const offset = ti.add(Process.pointerSize).readUSize();`:**  从 `TlsIndex` 结构体中读取模块 ID 和偏移量。
7. **`console.log(...)`:**  打印相关信息，例如函数被调用、模块 ID 和偏移量。
8. **`onLeave: function (retval)`:**  在函数调用返回后执行。`retval` 是函数的返回值，对于 `__tls_get_addr` 来说是线程局部变量的地址。

通过运行这个 Frida 脚本，你可以在 Android 设备上监控 `__tls_get_addr` 的调用，观察哪些模块的 TLS 变量正在被访问，以及访问的偏移量是多少，从而深入理解 TLS 的工作原理。你还可以扩展这个脚本来检查 DTV 的内容，验证地址解析的过程。

### 提示词
```
这是目录为bionic/libc/private/bionic_elf_tls.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
```

### 源代码
```c
/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <link.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <sys/cdefs.h>

#include "bionic_elf_dtv_offset.h"

__LIBC_HIDDEN__ extern _Atomic(size_t) __libc_tls_generation_copy;

struct TlsAlign {
  size_t value = 1;
  size_t skew = 0;  // p_vaddr % p_align

  template <typename T>
  static constexpr TlsAlign of_type() {
    return TlsAlign{.value = alignof(T)};
  }
};

struct TlsAlignedSize {
  size_t size = 0;
  TlsAlign align;

  template <typename T>
  static constexpr TlsAlignedSize of_type() {
    return TlsAlignedSize{.size = sizeof(T), .align = TlsAlign::of_type<T>()};
  }
};

struct TlsSegment {
  TlsAlignedSize aligned_size;
  const void* init_ptr = "";    // Field is non-null even when init_size is 0.
  size_t init_size = 0;
};

__LIBC_HIDDEN__ bool __bionic_get_tls_segment(const ElfW(Phdr)* phdr_table, size_t phdr_count,
                                              ElfW(Addr) load_bias, TlsSegment* out);

__LIBC_HIDDEN__ bool __bionic_check_tls_align(size_t align);

struct StaticTlsLayout {
  constexpr StaticTlsLayout() {}

public:
  size_t offset_bionic_tcb() const { return offset_bionic_tcb_; }
  size_t offset_bionic_tls() const { return offset_bionic_tls_; }
  size_t offset_thread_pointer() const;
  size_t offset_exe() const { return offset_exe_; }

  size_t size() const { return cursor_; }

  size_t reserve_exe_segment_and_tcb(const TlsSegment* exe_segment, const char* progname);
  size_t reserve_bionic_tls();
  size_t reserve_solib_segment(const TlsSegment& segment) { return reserve(segment.aligned_size); }
  void finish_layout();

#if !defined(STATIC_TLS_LAYOUT_TEST)
 private:
#endif
  size_t cursor_ = 0;
  size_t align_ = 1;

  // Offsets to various Bionic TLS structs from the beginning of static TLS.
  size_t offset_bionic_tcb_ = SIZE_MAX;
  size_t offset_bionic_tls_ = SIZE_MAX;

  size_t offset_exe_ = SIZE_MAX;

  struct TpAllocations {
    size_t before;
    size_t tp;
    size_t after;
  };

  size_t align_cursor(TlsAlign align);
  size_t align_cursor_unskewed(size_t align);
  size_t reserve(TlsAlignedSize aligned_size);
  TpAllocations reserve_tp_pair(TlsAlignedSize before, TlsAlignedSize after);

  template <typename T> size_t reserve_type() {
    return reserve(TlsAlignedSize::of_type<T>());
  }
};

static constexpr size_t kTlsGenerationNone = 0;
static constexpr size_t kTlsGenerationFirst = 1;

// The first ELF TLS module has ID 1. Zero is reserved for the first word of
// the DTV, a generation count. Unresolved weak symbols also use module ID 0.
static constexpr size_t kTlsUninitializedModuleId = 0;

static inline size_t __tls_module_id_to_idx(size_t id) { return id - 1; }
static inline size_t __tls_module_idx_to_id(size_t idx) { return idx + 1; }

// A descriptor for a single ELF TLS module.
struct TlsModule {
  TlsSegment segment;

  // Offset into the static TLS block or SIZE_MAX for a dynamic module.
  size_t static_offset = SIZE_MAX;

  // The generation in which this module was loaded. Dynamic TLS lookups use
  // this field to detect when a module has been unloaded.
  size_t first_generation = kTlsGenerationNone;

  // Used by the dynamic linker to track the associated soinfo* object.
  void* soinfo_ptr = nullptr;
};

// Signature of the callbacks that will be called after DTLS creation and
// before DTLS destruction.
typedef void (*dtls_listener_t)(void* dynamic_tls_begin, void* dynamic_tls_end);

// Signature of the thread-exit callbacks.
typedef void (*thread_exit_cb_t)(void);

struct CallbackHolder {
  thread_exit_cb_t cb;
  CallbackHolder* prev;
};

// Table of the ELF TLS modules. Either the dynamic linker or the static
// initialization code prepares this table, and it's then used during thread
// creation and for dynamic TLS lookups.
struct TlsModules {
  constexpr TlsModules() {}

  // A pointer to the TLS generation counter in libc.so. The counter is
  // incremented each time an solib is loaded or unloaded.
  _Atomic(size_t) generation = kTlsGenerationFirst;
  _Atomic(size_t) *generation_libc_so = nullptr;

  // Access to the TlsModule[] table requires taking this lock.
  pthread_rwlock_t rwlock = PTHREAD_RWLOCK_INITIALIZER;

  // Pointer to a block of TlsModule objects. The first module has ID 1 and
  // is stored at index 0 in this table.
  size_t module_count = 0;
  size_t static_module_count = 0;
  TlsModule* module_table = nullptr;

  // Callback to be invoked after a dynamic TLS allocation.
  dtls_listener_t on_creation_cb = nullptr;

  // Callback to be invoked before a dynamic TLS deallocation.
  dtls_listener_t on_destruction_cb = nullptr;

  // The first thread-exit callback; inlined to avoid allocation.
  thread_exit_cb_t first_thread_exit_callback = nullptr;

  // The additional callbacks, if any.
  CallbackHolder* thread_exit_callback_tail_node = nullptr;
};

void __init_static_tls(void* static_tls);

// Dynamic Thread Vector. Each thread has a different DTV. For each module
// (executable or solib), the DTV has a pointer to that module's TLS memory. The
// DTV is initially empty and is allocated on-demand. It grows as more modules
// are dlopen'ed. See https://www.akkadia.org/drepper/tls.pdf.
//
// The layout of the DTV is specified in various documents, but it is not part
// of Bionic's public ABI. A compiler can't generate code to access it directly,
// because it can't access libc's global generation counter.
struct TlsDtv {
  // Number of elements in this object's modules field.
  size_t count;

  // A pointer to an older TlsDtv object that should be freed when the thread
  // exits. The objects aren't immediately freed because a DTV could be
  // reallocated by a signal handler that interrupted __tls_get_addr's fast
  // path.
  TlsDtv* next;

  // The DTV slot points at this field, which allows omitting an add instruction
  // on the fast path for a TLS lookup. The arm64 tlsdesc_resolver.S depends on
  // the layout of fields past this point.
  size_t generation;
  void* modules[];
};

struct TlsIndex {
  size_t module_id;
  size_t offset;
};

#if defined(__i386__)
#define TLS_GET_ADDR_CALLING_CONVENTION __attribute__((regparm(1)))
#define TLS_GET_ADDR ___tls_get_addr
#else
#define TLS_GET_ADDR_CALLING_CONVENTION
#define TLS_GET_ADDR __tls_get_addr
#endif

extern "C" void* TLS_GET_ADDR(const TlsIndex* ti) TLS_GET_ADDR_CALLING_CONVENTION;

struct bionic_tcb;
void __free_dynamic_tls(bionic_tcb* tcb);
void __notify_thread_exit_callbacks();
```