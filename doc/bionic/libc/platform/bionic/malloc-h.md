Response:
My thought process for answering the request goes like this:

1. **Understand the Goal:** The user wants a detailed explanation of the provided C header file (`malloc.handroid`). The key is to dissect its purpose, functionality, connections to Android, implementation details (where possible), dynamic linking aspects, common errors, and how Android frameworks use it. The request also asks for Frida hooking examples.

2. **Identify Key Components:** The header file primarily defines structures and enums related to `android_mallopt`. This function is the central point of investigation. The file also includes standard library headers (`malloc.h`, `stdbool.h`, `stdint.h`).

3. **High-Level Functionality:**  Recognize that `android_mallopt` is an Android-specific extension to the standard `mallopt` function. Its purpose is to provide finer control over memory allocation behavior within the Android environment.

4. **Break Down `android_mallopt` Opcodes:**  Go through each defined `enum` value in the header. For each opcode, identify:
    * **Its purpose:** What does this specific mallopt option do?
    * **Arguments:** What data does it take as input (`arg`, `arg_size`)?
    * **Android Relevance:** How does this relate to Android's operation (Zygote, debugging, memory limits, GWP-ASan, etc.)?

5. **Explain Key Concepts:**  For complex opcodes like `M_INITIALIZE_GWP_ASAN`, elaborate on the underlying technology (GWP-ASan), its different modes, and its role in memory safety. Similarly, for `M_GET_MALLOC_LEAK_INFO`, describe the memory leak detection mechanism.

6. **Address Specific Request Points:**
    * **Function Implementation:**  Acknowledge that the *header* file doesn't contain the actual *implementation*. Explain that the implementation would be in a separate C/C++ file within the Bionic library.
    * **Dynamic Linker:** Explain how `libc.so` (where `android_mallopt` resides) is a shared library and how it's loaded by the dynamic linker. Provide a simplified example of a shared library layout in memory. Describe the symbol resolution process.
    * **Logic Reasoning (Hypothetical Input/Output):**  For opcodes that modify state or retrieve information (e.g., `M_SET_ALLOCATION_LIMIT_BYTES`, `M_GET_PROCESS_PROFILEABLE`), provide simple examples of how calling `android_mallopt` with specific arguments would affect the process.
    * **User Errors:** Think about common mistakes related to memory management (leaks, double frees) and how the debugging features exposed by `android_mallopt` can help.
    * **Android Framework and NDK Usage:**  Trace the path from application code (using standard `malloc`) to how the Android framework or even system services might use `android_mallopt` directly for specialized memory management tasks (e.g., Zygote).

7. **Frida Hooking:**  Provide concrete Frida code snippets to demonstrate how to intercept calls to `android_mallopt` and potentially modify arguments or observe return values. Focus on the core mechanics of hooking.

8. **Structure and Language:** Organize the information clearly using headings and bullet points. Use clear and concise language. Explain technical terms. Since the request is in Chinese, answer in Chinese.

9. **Review and Refine:**  Read through the entire answer to ensure accuracy, completeness, and clarity. Check for any inconsistencies or areas that need further explanation. For example, initially I might have focused too much on the header structure. I would then refine it to emphasize the *functionality* that the header enables. Also, ensure all aspects of the original request are addressed.

**Self-Correction Example during the process:**

Initially, I might just list the opcodes with very brief descriptions. However, the request emphasizes "详细解释每一个libc函数的功能是如何实现的". While I can't show the *actual* C code, I can explain the *mechanism* behind each opcode. For `M_GET_MALLOC_LEAK_INFO`, I'd expand on the idea of tracking allocations and backtraces, even without showing the internal data structures. For dynamic linking, simply saying "libc is linked" isn't enough. I need to explain the *process* of linking and loading.

By following this detailed thought process, addressing each facet of the request, and continually refining the answer, I can generate a comprehensive and helpful response.
这个目录 `bionic/libc/platform/bionic/malloc.handroid` 下的源代码文件 `malloc.handroid` 是 Android Bionic C 库中关于内存分配管理的一个头文件。它主要定义了一些用于扩展标准 `malloc` 功能的 Android 特有接口，特别是 `android_mallopt` 函数及其相关的常量和数据结构。

**功能列举:**

这个文件主要定义了以下功能：

1. **`android_mallopt` 函数:**  这是一个 Android 扩展的 `mallopt` 函数，允许开发者对内存分配器的行为进行更细粒度的控制。与标准 `mallopt` 相比，它提供了一些 Android 独有的选项。
2. **`android_mallopt_leak_info_t` 结构体:** 用于获取内存泄漏信息的结构体，包含了指向泄漏信息缓冲区的指针、缓冲区大小、单个条目大小、总分配内存大小以及回溯栈大小等信息。
3. **`android_mallopt_gwp_asan_options_t` 结构体:** 用于配置 GWP-ASan (Guard Without Panic - AddressSanitizer) 的选项，包括程序名称和 GWP-ASan 的运行模式。
4. **`android_mallopt` 的操作码 (Opcodes):**  定义了一系列常量，用于指定 `android_mallopt` 函数要执行的具体操作。这些操作码涵盖了诸如初始化 Zygote 子进程性能分析、重置 hooks、设置内存分配限制、获取/释放内存泄漏信息、查询进程是否可被分析、初始化 GWP-ASan 以及查询内存标签堆栈是否启用等功能。

**与 Android 功能的关系及举例说明:**

这些功能与 Android 平台的运行和调试密切相关：

* **Zygote 进程管理 (`M_INIT_ZYGOTE_CHILD_PROFILING`, `M_SET_ZYGOTE_CHILD`):**  Zygote 是 Android 系统中所有应用程序进程的父进程。这些操作码允许在 Zygote 进程 fork 出子进程后进行特定的内存管理操作，例如初始化性能分析基础设施，这对于追踪应用程序的内存使用情况至关重要。
    * **举例:** 当 Android 系统启动一个新的应用程序时，Zygote 进程会 fork 出一个新的进程。在 fork 之后，系统可能会调用 `android_mallopt(M_SET_ZYGOTE_CHILD, ...)` 来通知 Bionic 的内存分配器这是一个子进程，以便进行相应的调整。
* **内存泄漏检测 (`M_WRITE_MALLOC_LEAK_INFO_TO_FILE`, `M_GET_MALLOC_LEAK_INFO`, `M_FREE_MALLOC_LEAK_INFO`):**  Android 平台提供了内存泄漏检测机制，这些操作码允许开发者或工具获取当前内存分配的详细信息，包括分配时的回溯栈，以便定位内存泄漏的根源。
    * **举例:**  开发者可以使用 `M_GET_MALLOC_LEAK_INFO` 获取内存泄漏信息，然后将信息写入文件进行分析，或者通过 `M_WRITE_MALLOC_LEAK_INFO_TO_FILE` 直接将信息输出到文件。
* **内存分配限制 (`M_SET_ALLOCATION_LIMIT_BYTES`):**  可以设置进程的总内存分配上限，这有助于防止恶意应用或存在 bug 的应用消耗过多的内存资源，导致系统不稳定。
    * **举例:**  系统服务可能会使用 `M_SET_ALLOCATION_LIMIT_BYTES` 来限制某个应用程序可以分配的最大内存量。
* **GWP-ASan (`M_INITIALIZE_GWP_ASAN`):**  GWP-ASan 是一种轻量级的内存安全工具，用于检测堆内存的 bug，如 use-after-free 和堆溢出。`M_INITIALIZE_GWP_ASAN` 操作码用于初始化和配置 GWP-ASan。
    * **举例:**  Android 系统在应用启动时可能会调用 `android_mallopt(M_INITIALIZE_GWP_ASAN, ...)` 来根据应用的配置 (例如，在 AndroidManifest.xml 中设置 `gwpAsanMode`) 或系统属性来启用或配置 GWP-ASan。
* **进程可分析性查询 (`M_GET_PROCESS_PROFILEABLE`):**  允许查询当前进程是否被 Android 平台认为是可进行性能分析的。
    * **举例:**  性能分析工具可能会先调用 `android_mallopt(M_GET_PROCESS_PROFILEABLE, ...)` 来检查目标进程是否允许进行性能分析。
* **内存标签堆栈查询 (`M_MEMTAG_STACK_IS_ON`):**  用于查询当前进程是否启用了内存标签堆栈，这是一种硬件辅助的内存安全特性。
* **延迟释放内存 (`M_GET_DECAY_TIME_ENABLED`):** 查询当前进程是否启用了延迟释放内存的机制。这可以避免内存频繁释放和分配带来的性能开销。

**libc 函数的功能实现:**

这个头文件本身**不包含** libc 函数的实现代码，它只是声明了 `android_mallopt` 函数及其相关的常量和数据结构。`android_mallopt` 的具体实现代码位于 Bionic 库的其他源文件中。

然而，我们可以推测一下 `android_mallopt` 的各个操作码是如何实现的：

* **`M_INIT_ZYGOTE_CHILD_PROFILING`:**  实现可能涉及到设置一些全局变量或调用特定的函数，以启动内存分配信息的收集和跟踪机制，以便后续进行性能分析。
* **`M_RESET_HOOKS`:** 可能会清除之前设置的用于内存分配的自定义 hooks，恢复到默认的分配行为。
* **`M_SET_ALLOCATION_LIMIT_BYTES`:**  实现可能需要在 Bionic 的内存分配器内部维护一个已分配内存的计数器，并在每次分配时检查是否超过了设定的限制。如果超过限制，`malloc` 等函数可能会返回 `NULL` 或者触发错误。
* **`M_SET_ZYGOTE_CHILD`:**  实现可能只是简单地设置一个标志位，表明当前进程是 Zygote 的子进程。这个标志位可能会影响后续的内存分配策略或统计信息的收集。
* **`M_WRITE_MALLOC_LEAK_INFO_TO_FILE` / `M_GET_MALLOC_LEAK_INFO`:**  实现会遍历当前进程中所有已分配的内存块，记录其分配时的回溯栈信息。这些信息通常存储在 Bionic 内存分配器的元数据中。`M_WRITE_MALLOC_LEAK_INFO_TO_FILE` 将这些信息格式化后写入指定的文件，而 `M_GET_MALLOC_LEAK_INFO` 则将信息填充到用户提供的 `android_mallopt_leak_info_t` 结构体中。
* **`M_FREE_MALLOC_LEAK_INFO`:**  实现会释放由 `M_GET_MALLOC_LEAK_INFO` 分配的用于存储内存泄漏信息的缓冲区。
* **`M_GET_PROCESS_PROFILEABLE`:**  实现可能检查一些系统属性或进程状态来确定当前进程是否被标记为可分析。
* **`M_INITIALIZE_GWP_ASAN`:** 实现会根据提供的 `android_mallopt_gwp_asan_options_t` 结构体中的信息，初始化 GWP-ASan 机制，例如设置 GWP-ASan 的运行模式 (始终启用、永不启用、采样等)。这可能涉及到分配一些用于 GWP-ASan 跟踪的内存。
* **`M_MEMTAG_STACK_IS_ON`:** 实现可能读取内核提供的接口或检查硬件特性来判断内存标签堆栈是否已启用。
* **`M_GET_DECAY_TIME_ENABLED`:** 实现可能检查相关的系统属性或内部状态来确定是否启用了延迟释放内存的机制.

**涉及 dynamic linker 的功能及其处理过程:**

`android_mallopt` 函数本身是 Bionic C 库 (`libc.so`) 的一部分，它通过动态链接器加载到进程的地址空间中。

**so 布局样本:**

一个简化的 `libc.so` 内存布局可能如下所示：

```
地址范围         | 内容
-----------------|------------------------------------
0xXXXXXXXX000    | .text (代码段，包含 android_mallopt 的指令)
0xXXXXXXXXYYYY   | .rodata (只读数据段，包含字符串常量等)
0xXXXXXXXXZZZZ   | .data (已初始化数据段，包含全局变量)
0xXXXXXXXXWWWW   | .bss (未初始化数据段，包含未初始化的全局变量)
...              | 其他段 (例如 .plt, .got 等)
```

**链接的处理过程:**

1. **编译链接时:**  当编译链接一个使用 `android_mallopt` 的程序时，链接器会记录下对 `android_mallopt` 函数的引用，并将其放入可执行文件的动态符号表中。
2. **程序加载时:** 当 Android 系统加载该程序时，动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载程序依赖的共享库，包括 `libc.so`。
3. **符号解析:** 动态链接器会解析可执行文件中的未定义符号，包括 `android_mallopt`。它会在已加载的共享库 (`libc.so`) 的符号表中查找 `android_mallopt` 的地址。
4. **重定位:** 找到 `android_mallopt` 的地址后，动态链接器会更新可执行文件中对 `android_mallopt` 的引用，将其指向 `libc.so` 中 `android_mallopt` 函数的实际地址。
5. **调用:** 当程序执行到调用 `android_mallopt` 的代码时，程序会跳转到 `libc.so` 中 `android_mallopt` 的地址执行。

**假设输入与输出 (逻辑推理):**

* **假设输入:**  调用 `android_mallopt(M_SET_ALLOCATION_LIMIT_BYTES, &limit, sizeof(size_t))`，其中 `limit` 的值为 `1048576` (1MB)。
* **预期输出:** 如果操作成功，`android_mallopt` 返回 `true`。之后，任何尝试分配超过剩余可用额度的内存的操作都可能失败（例如 `malloc` 返回 `NULL`）。

* **假设输入:** 调用 `android_mallopt(M_GET_PROCESS_PROFILEABLE, &is_profileable, sizeof(bool))`，并且当前进程是可被分析的。
* **预期输出:** `android_mallopt` 返回 `true`，并且 `is_profileable` 的值被设置为 `true`。

**用户或编程常见的使用错误:**

* **传递错误的 `opcode`:**  使用未定义的或错误的 `opcode` 值会导致 `android_mallopt` 执行错误的操作或直接失败。
* **传递不正确的参数或 `arg_size`:**  某些 `opcode` 需要特定的参数类型和大小。例如，`M_SET_ALLOCATION_LIMIT_BYTES` 需要一个指向 `size_t` 的指针，并且 `arg_size` 必须是 `sizeof(size_t)`。传递错误的参数会导致内存错误或未定义的行为。
* **在错误的生命周期阶段调用:**  某些 `opcode` 只能在特定的进程生命周期阶段调用。例如，`M_INITIALIZE_GWP_ASAN` 通常需要在进程启动的早期调用。
* **忘记检查返回值:** `android_mallopt` 返回一个布尔值表示操作是否成功。忽略返回值可能导致在操作失败的情况下继续执行，从而引发其他问题。
* **不匹配的 `M_GET_MALLOC_LEAK_INFO` 和 `M_FREE_MALLOC_LEAK_INFO`:**  如果调用 `M_GET_MALLOC_LEAK_INFO` 获取了内存泄漏信息，务必在不再需要时调用 `M_FREE_MALLOC_LEAK_INFO` 释放分配的内存，否则会导致内存泄漏。

**Android framework 或 NDK 如何一步步到达这里:**

1. **NDK 应用调用标准 C 库函数:** NDK 应用通常通过标准的 C 库函数 (如 `malloc`, `free`) 进行内存管理。
2. **Bionic libc 的实现:** 这些标准 C 库函数在 Android 上由 Bionic C 库实现。Bionic 的 `malloc` 实现内部可能会使用到一些更底层的机制。
3. **Framework 或系统服务直接调用 `android_mallopt`:** Android Framework 或系统服务有时会直接调用 `android_mallopt` 来进行更精细的内存管理控制或获取调试信息。
    * **例如:**  Zygote 进程在 fork 子进程后可能会调用 `android_mallopt(M_SET_ZYGOTE_CHILD, ...)`。
    * **例如:**  系统服务可能会调用 `android_mallopt(M_SET_ALLOCATION_LIMIT_BYTES, ...)` 来限制特定进程的内存使用。
    * **例如:**  调试工具或系统服务可能会调用 `android_mallopt(M_GET_MALLOC_LEAK_INFO, ...)` 来获取内存泄漏信息。
4. **间接调用:**  某些 Framework 的功能可能会间接地触发对 `android_mallopt` 的调用。例如，启用某个调试选项可能会导致系统调用 `android_mallopt` 来收集内存分配信息。

**Frida hook 示例调试这些步骤:**

以下是一些使用 Frida hook `android_mallopt` 的示例：

```javascript
// Hook android_mallopt 函数，打印参数和返回值
Interceptor.attach(Module.findExportByName("libc.so", "android_mallopt"), {
  onEnter: function (args) {
    const opcode = args[0].toInt32();
    const arg = args[1];
    const arg_size = args[2].toInt32();

    console.log("android_mallopt called with opcode:", opcode);
    console.log("arg:", arg);
    console.log("arg_size:", arg_size);

    // 可以根据 opcode 和 arg_size 来解析 arg 的内容
    if (opcode === 3) { // M_SET_ALLOCATION_LIMIT_BYTES
      console.log("Allocation limit:", arg.readU64());
    } else if (opcode === 6) { // M_GET_MALLOC_LEAK_INFO
      // 这里需要小心处理 arg 指针，因为它指向一个结构体
      console.log("Getting malloc leak info...");
    }
  },
  onLeave: function (retval) {
    console.log("android_mallopt returned:", retval);
  },
});

// Hook M_SET_ZYGOTE_CHILD 的调用
const M_SET_ZYGOTE_CHILD = 4;
Interceptor.attach(Module.findExportByName("libc.so", "android_mallopt"), {
  onEnter: function (args) {
    if (args[0].toInt32() === M_SET_ZYGOTE_CHILD) {
      console.log("M_SET_ZYGOTE_CHILD called!");
    }
  },
});

// 修改 M_SET_ALLOCATION_LIMIT_BYTES 的参数
const M_SET_ALLOCATION_LIMIT_BYTES = 3;
Interceptor.attach(Module.findExportByName("libc.so", "android_mallopt"), {
  onEnter: function (args) {
    if (args[0].toInt32() === M_SET_ALLOCATION_LIMIT_BYTES) {
      const originalLimit = args[1].readU64();
      console.log("Original allocation limit:", originalLimit);

      // 将分配限制修改为 2MB
      const newLimit = 2 * 1024 * 1024;
      args[1].writeU64(newLimit);
      console.log("New allocation limit set to:", newLimit);
    }
  },
});
```

这些 Frida 脚本可以帮助你观察 `android_mallopt` 的调用时机、参数和返回值，从而理解 Android 系统如何在底层进行内存管理和调试。请注意，修改内存管理相关的参数可能会导致系统不稳定，请谨慎操作。

### 提示词
```
这是目录为bionic/libc/platform/bionic/malloc.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2018 The Android Open Source Project
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

#include <malloc.h>
#include <stdbool.h>
#include <stdint.h>

// Structures for android_mallopt.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnullability-completeness"
typedef struct {
  // Pointer to the buffer allocated by a call to M_GET_MALLOC_LEAK_INFO.
  uint8_t* buffer;
  // The size of the "info" buffer.
  size_t overall_size;
  // The size of a single entry.
  size_t info_size;
  // The sum of all allocations that have been tracked. Does not include
  // any heap overhead.
  size_t total_memory;
  // The maximum number of backtrace entries.
  size_t backtrace_size;
} android_mallopt_leak_info_t;
#pragma clang diagnostic pop
// Opcodes for android_mallopt.

enum {
  // Marks the calling process as a profileable zygote child, possibly
  // initializing profiling infrastructure.
  M_INIT_ZYGOTE_CHILD_PROFILING = 1,
#define M_INIT_ZYGOTE_CHILD_PROFILING M_INIT_ZYGOTE_CHILD_PROFILING
  M_RESET_HOOKS = 2,
#define M_RESET_HOOKS M_RESET_HOOKS
  // Set an upper bound on the total size in bytes of all allocations made
  // using the memory allocation APIs.
  //   arg = size_t*
  //   arg_size = sizeof(size_t)
  M_SET_ALLOCATION_LIMIT_BYTES = 3,
#define M_SET_ALLOCATION_LIMIT_BYTES M_SET_ALLOCATION_LIMIT_BYTES
  // Called after the zygote forks to indicate this is a child.
  M_SET_ZYGOTE_CHILD = 4,
#define M_SET_ZYGOTE_CHILD M_SET_ZYGOTE_CHILD

  // Options to dump backtraces of allocations. These options only
  // work when malloc debug has been enabled.

  // Writes the backtrace information of all current allocations to a file.
  // NOTE: arg_size has to be sizeof(FILE*) because FILE is an opaque type.
  //   arg = FILE*
  //   arg_size = sizeof(FILE*)
  M_WRITE_MALLOC_LEAK_INFO_TO_FILE = 5,
#define M_WRITE_MALLOC_LEAK_INFO_TO_FILE M_WRITE_MALLOC_LEAK_INFO_TO_FILE
  // Get information about the backtraces of all
  //   arg = android_mallopt_leak_info_t*
  //   arg_size = sizeof(android_mallopt_leak_info_t)
  M_GET_MALLOC_LEAK_INFO = 6,
#define M_GET_MALLOC_LEAK_INFO M_GET_MALLOC_LEAK_INFO
  // Free the memory allocated and returned by M_GET_MALLOC_LEAK_INFO.
  //   arg = android_mallopt_leak_info_t*
  //   arg_size = sizeof(android_mallopt_leak_info_t)
  M_FREE_MALLOC_LEAK_INFO = 7,
#define M_FREE_MALLOC_LEAK_INFO M_FREE_MALLOC_LEAK_INFO
  // Query whether the current process is considered to be profileable by the
  // Android platform. Result is assigned to the arg pointer's destination.
  //   arg = bool*
  //   arg_size = sizeof(bool)
  M_GET_PROCESS_PROFILEABLE = 9,
#define M_GET_PROCESS_PROFILEABLE M_GET_PROCESS_PROFILEABLE
  // Maybe enable GWP-ASan. Set *arg to force GWP-ASan to be turned on,
  // otherwise this mallopt() will internally decide whether to sample the
  // process. The program must be single threaded at the point when the
  // android_mallopt function is called.
  //   arg = android_mallopt_gwp_asan_options_t*
  //   arg_size = sizeof(android_mallopt_gwp_asan_options_t)
  M_INITIALIZE_GWP_ASAN = 10,
#define M_INITIALIZE_GWP_ASAN M_INITIALIZE_GWP_ASAN
  // Query whether memtag stack is enabled for this process.
  M_MEMTAG_STACK_IS_ON = 11,
#define M_MEMTAG_STACK_IS_ON M_MEMTAG_STACK_IS_ON
  // Query whether the current process has the decay time enabled so that
  // the memory from allocations are not immediately released to the OS.
  // Result is assigned to the arg pointer's destination.
  //   arg = bool*
  //   arg_size = sizeof(bool)
  M_GET_DECAY_TIME_ENABLED = 12,
#define M_GET_DECAY_TIME_ENABLED M_GET_DECAY_TIME_ENABLED
};

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wnullability-completeness"
typedef struct {
  // The null-terminated name that the zygote is spawning. Because native
  // SpecializeCommon (where the GWP-ASan mallopt() is called from) happens
  // before argv[0] is set, we need the zygote to tell us the new app name.
  const char* program_name = nullptr;

  // An android_mallopt(M_INITIALIZE_GWP_ASAN) is always issued on process
  // startup and app startup, regardless of whether GWP-ASan is desired or not.
  // This allows the process/app's desire to be overwritten by the
  // "libc.debug.gwp_asan.*.app_default" or "libc.debug.gwp_asan.*.<name>"
  // system properties, as well as the "GWP_ASAN_*" environment variables.
  //
  // Worth noting, the "libc.debug.gwp_asan.*.app_default" sysprops *do not*
  // apply to system apps. They use the "libc.debug.gwp_asan.*.system_default"
  // sysprops.
  //
  // In recoverable mode, GWP-ASan will detect heap memory safety bugs, and bug
  // reports will be created by debuggerd, however the process will recover and
  // continue to function as if the memory safety bug wasn't detected. This
  // prevents any user-visible impact as apps and processes don't crash, and
  // probably saves us some CPU time in restarting the process.
  //
  // Process sampling enables GWP-ASan, but only a small percentage of the time
  // (~1%). This helps mitigate any recurring high-frequency problems in certain
  // processes, as it's highly likely the next restart of said process won't
  // have GWP-ASan. In addition, for system processes and system apps, this
  // allows us to mitigate system-wide memory overhead concerns, as each
  // GWP-ASan enabled process uses ~70KiB of extra memory.
  enum Mode {
    // Used by default for apps, or by those that have an explicit
    // `gwpAsanMode=default` in the manifest.
    //
    // Result:
    //  - Android 13 and before: GWP-ASan is not enabled.
    //  - Android 14 and after: Enables GWP-ASan with process sampling in
    //    recoverable mode.
    APP_MANIFEST_DEFAULT = 3,
    // This is used by apps that have `gwpAsanMode=always` in the manifest.
    //
    // Result:
    //  - Android 14 and before: Enables GWP-ASan in non-recoverable mode,
    //    without process sampling.
    //  - Android 15 and after: Enables GWP-ASan in recoverable mode, without
    //    process sampling.
    APP_MANIFEST_ALWAYS = 0,
    // This is used by apps that have `gwpAsanMode=never` in the manifest.
    //
    // Result:
    //  - GWP-ASan is not enabled, unless it's force-enabled by a system
    //    property or environment variable.
    APP_MANIFEST_NEVER = 2,
    // Used by system processes and system apps.
    //
    // Result:
    //  - Android 14 and before: Enables GWP-ASan with process sampling in
    //    non-recoverable mode.
    //  - Android 15 and after: Enables GWP-ASan with process sampling in
    //    recoverable mode.
    SYSTEM_PROCESS_OR_SYSTEM_APP = 1,
    // Next enum value = 4. Numbered non-sequentially above to preserve ABI
    // stability, but now ordered more logically.
  };

  Mode mode = APP_MANIFEST_NEVER;
} android_mallopt_gwp_asan_options_t;
#pragma clang diagnostic pop
// Manipulates bionic-specific handling of memory allocation APIs such as
// malloc. Only for use by the Android platform and APEXes.
//
// On success, returns true. On failure, returns false and sets errno.
extern "C" bool android_mallopt(int opcode, void* _Nullable arg, size_t arg_size);
```