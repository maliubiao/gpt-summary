Response:
Let's break down the thought process for analyzing this C++ source file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of `sys_thread_properties.cpp`. This involves identifying its functionalities, its relationship to Android, explaining the underlying libc functions, detailing dynamic linker interaction, addressing potential errors, and outlining its usage within the Android framework/NDK. A Frida hook example is also required.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly read through the code and identify key data structures, functions, and system calls. Keywords like `tls`, `thread`, `ptrace`, `dtv`, `callback`, and `allocator` immediately stand out. The `#include` directives provide clues about the dependencies.

**3. Function-by-Function Analysis:**

Next, analyze each function individually:

* **`__libc_get_static_tls_bounds`:**  The name suggests retrieving boundaries of static TLS. The code accesses `__libc_shared_globals()->static_tls_layout` and uses `__get_bionic_tcb()`. This points to the management of thread-local storage.

* **`__libc_register_thread_exit_callback`:** This function deals with registering callbacks executed when a thread exits. It manipulates a linked list (`CallbackHolder`) within the global `tls_modules`. The use of `BionicAllocator` suggests custom memory management for these callbacks.

* **`__get_bionic_tcb_for_thread`:** This is the most complex function. It retrieves the Thread Control Block (TCB) for a given thread ID (`tid`). The logic branches based on the architecture (`__aarch64__`, `__arm__`, etc.), employing `ptrace` to access thread-specific registers. The fallback mechanism with `async_safe_write_log` for failure is important. The key insight here is the architecture-specific way to find the thread pointer register.

* **`__libc_iterate_dynamic_tls`:** This function iterates through dynamically allocated thread-local storage blocks. It retrieves the TCB, then the DTV (Dynamic Thread Vector), and uses the `tls_modules` and `tls_allocator` to access the allocated blocks. The callback mechanism `cb` is crucial for user-provided actions on each block.

* **`__libc_register_dynamic_tls_listeners`:** This function registers callbacks triggered when dynamic TLS blocks are created or destroyed. It directly modifies the `tls_modules` structure.

**4. Identifying Core Functionalities:**

Based on the function analysis, the core functionalities are:

* **Managing Static TLS:**  Retrieving boundaries.
* **Managing Thread Exit Callbacks:** Registering and executing callbacks.
* **Accessing Thread Control Block (TCB):**  Retrieving the TCB for a given thread (potentially using `ptrace`).
* **Iterating through Dynamic TLS:**  Providing a way to access dynamically allocated TLS blocks.
* **Managing Dynamic TLS Lifecycle Events:**  Registering callbacks for creation and destruction.

**5. Relating to Android Functionality:**

Consider how these functionalities are used in the broader Android context:

* **Thread Management:**  Fundamental to Android's multi-threaded nature.
* **Native Development:**  NDK relies heavily on threads and thread-local storage.
* **Dynamic Linking:**  Dynamic TLS is essential for shared libraries.
* **Security and Debugging:** `ptrace` usage highlights debugging and potentially security-related operations.

**6. Explaining libc Functions:**

For each libc function, provide a detailed explanation of its implementation:

* **`__get_bionic_tcb`:** Explain how it accesses the TCB for the *current* thread (usually through a dedicated register or special memory location).
* **`ptrace`:** Explain its role in inspecting and controlling other processes, focusing on its use here to access thread registers.
* **`gettid`:** Explain its function of getting the current thread ID.
* **Memory Management (implicit):**  Mention the role of `BionicAllocator` in managing memory for TLS structures and callbacks.

**7. Dynamic Linker Interaction:**

This requires understanding how shared libraries use thread-local storage.

* **SO Layout:**  Describe the typical structure of a shared object, including the `.tbss` and `.tdata` sections for TLS.
* **Linking Process:** Explain how the dynamic linker allocates and initializes TLS blocks for shared libraries when they are loaded. The DTV plays a crucial role here. Focus on the runtime linking aspect.

**8. Logic, Assumptions, and Edge Cases:**

* **Assumptions:** The code assumes the availability of `ptrace` and the correct thread pointer register.
* **Edge Cases:** Consider scenarios where `ptrace` fails (permissions, security restrictions). The code handles this with error logging.
* **Error Handling:** Focus on the `ptrace` error handling and the fallback mechanisms.

**9. Common User Errors:**

Think about how developers might misuse these low-level functions:

* **Incorrect `tid`:** Passing an invalid thread ID to `__get_bionic_tcb_for_thread`.
* **Incorrect Callback Usage:**  Memory management issues within exit callbacks.
* **Security Risks:** Misusing `ptrace` can lead to security vulnerabilities.

**10. Android Framework/NDK Usage:**

Trace the path from higher-level Android APIs to this code:

* **Java `Thread`:**  Leads to native thread creation.
* **NDK Pthreads:** Direct usage of `pthread_create`.
* **Dynamic Library Loading:** `dlopen` triggers dynamic linking, involving TLS setup.

**11. Frida Hook Example:**

Choose a relevant function to hook, like `__libc_get_static_tls_bounds`. The hook should demonstrate intercepting the function call, logging arguments, and potentially modifying the behavior.

**12. Structuring the Response:**

Organize the information logically with clear headings and bullet points. Start with a high-level overview of the file's purpose and then delve into the details of each function and concept. Use code snippets and diagrams where appropriate (although a full diagram wasn't explicitly requested in *this* particular prompt). Maintain a clear and concise writing style.

**Self-Correction/Refinement during the process:**

* **Initially, I might focus too much on the individual system calls.**  It's important to step back and understand the *higher-level purpose* of the code – managing thread-local storage.
* **I might forget to explain the `__libc_shared_globals()` structure.** This is a central point for accessing global state in Bionic and should be mentioned.
* **The dynamic linker section requires careful explanation.**  It's a complex topic, so breaking it down into SO layout and the linking process is crucial.
* **The Frida hook example needs to be practical and demonstrate a useful debugging technique.**  Simply hooking and printing the function name isn't very helpful.

By following this structured approach, I can systematically analyze the source code and generate a comprehensive and informative response.
这个文件 `bionic/libc/bionic/sys_thread_properties.cpp` 是 Android Bionic C 库的一部分，主要负责提供与线程属性相关的底层操作，特别是关于线程本地存储 (Thread-Local Storage, TLS) 的访问和管理。

**主要功能:**

1. **获取静态 TLS 的边界:**  `__libc_get_static_tls_bounds` 函数允许获取当前线程静态 TLS 区域的起始和结束地址。
2. **注册线程退出回调函数:** `__libc_register_thread_exit_callback` 函数允许注册在线程退出时被调用的回调函数。
3. **获取任意线程的 TCB (Thread Control Block):** `__get_bionic_tcb_for_thread` 函数允许获取指定线程的 TCB 指针。为了访问其他线程的 TCB，它使用了 `ptrace` 系统调用。
4. **迭代动态 TLS 块:** `__libc_iterate_dynamic_tls` 函数允许遍历指定线程的动态 TLS 块，并对每个块执行回调函数。
5. **注册动态 TLS 监听器:** `__libc_register_dynamic_tls_listeners` 函数允许注册在动态 TLS 块创建和销毁时被调用的监听器。

**与 Android 功能的关系及举例说明:**

这些功能都与 Android 的多线程机制和动态链接密切相关。

* **线程本地存储 (TLS):**  TLS 允许每个线程拥有自己独立的变量副本。这在多线程编程中非常重要，可以避免竞态条件和提高效率。Android 框架和 NDK 中创建的线程都依赖于 TLS 来存储线程特定的数据。例如，C++ 中的 `thread_local` 变量就是通过 TLS 实现的。
* **动态链接:** 当 Android 应用加载共享库 (so 文件) 时，这些共享库可能包含需要线程本地存储的变量。动态链接器负责在运行时为这些变量分配 TLS 空间。`__libc_iterate_dynamic_tls` 允许访问这些动态分配的 TLS 块。
* **线程退出回调:** Android 系统需要在线程退出时执行一些清理工作，例如释放线程相关的资源。`__libc_register_thread_exit_callback` 提供的机制允许注册这些清理函数。
* **进程间通信和调试:** `ptrace` 系统调用是 Linux 中强大的调试和进程控制工具。在 Android 中，它被用于实现调试器、性能分析工具等。`__get_bionic_tcb_for_thread` 使用 `ptrace` 来访问其他线程的内部状态，这在调试多线程程序时非常有用。

**libc 函数功能实现:**

1. **`__libc_get_static_tls_bounds(void** stls_begin, void** stls_end)`:**
   - 此函数从全局变量 `__libc_shared_globals()` 中获取 `static_tls_layout` 信息，该结构体描述了静态 TLS 的布局。
   - `__get_bionic_tcb()` 函数返回当前线程的 TCB 指针。TCB 是一个存储线程元数据的结构体，其中包含了 TLS 的信息。
   - `layout.offset_bionic_tcb()` 返回 bionic TCB 在静态 TLS 区域内的偏移量。
   - 通过从 TCB 指针减去偏移量，即可得到静态 TLS 区域的起始地址。
   - 结束地址则是起始地址加上静态 TLS 区域的大小 (`layout.size()`)。
   - **实现原理:** 利用了 TLS 在内存中的布局是预先确定的，通过访问线程的 TCB 可以计算出静态 TLS 的边界。

2. **`__libc_register_thread_exit_callback(thread_exit_cb_t cb)`:**
   - 此函数维护一个线程退出回调函数链表。
   - `__libc_shared_globals()->tls_modules` 获取 TLS 模块相关的全局信息。
   - 如果链表为空 (`modules.first_thread_exit_callback == nullptr`)，则将新的回调函数设置为链表的头部。
   - 否则，使用 `BionicAllocator` 分配一个 `CallbackHolder` 结构体来存储新的回调函数。
   - 新的节点插入到链表的尾部，`modules.thread_exit_callback_tail_node` 指向链表的最后一个节点。
   - **实现原理:** 使用链表结构来存储多个需要在线程退出时执行的回调函数。`BionicAllocator` 是 Bionic 库内部的内存分配器。

3. **`static inline __always_inline bionic_tcb* __get_bionic_tcb_for_thread(pid_t tid)`:**
   - **如果 `tid` 等于当前线程 ID (`gettid()`)**: 直接调用 `__get_bionic_tcb()` 获取当前线程的 TCB。
   - **否则 (需要访问其他线程的 TCB)**: 使用 `ptrace` 系统调用。
     - `ptrace(PTRACE_GETREGSET, tid, NT_ARM_TLS, &pt_iov)` (AArch64): 获取指定线程的 TLS 寄存器值。
     - `ptrace(PTRACE_GET_THREAD_AREA, tid, nullptr, &tp_reg)` (ARM): 获取线程局部存储区域的地址。
     - `ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &pt_iov)` 和 `ptrace(PTRACE_GET_THREAD_AREA, tid, u_info.entry_number, &u_info)` (x86): 获取 GDT (Global Descriptor Table) 中与线程相关的条目，从而获取 TLS 基地址。
     - `ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &pt_iov)` (RISC-V): 获取线程指针寄存器 `tp` 的值。
     - `ptrace(PTRACE_PEEKUSER, tid, offsetof(user_regs_struct, fs_base), nullptr)` (x86_64): 获取 `fs_base` 寄存器的值，该寄存器通常用于指向 TLS。
   - 不同的架构使用不同的方法来获取线程指针寄存器或 TLS 基地址。
   - 获取到线程指针后，根据 `MIN_TLS_SLOT` 偏移量计算出 `bionic_tcb` 的地址。
   - 如果 `ptrace` 调用失败，会记录一个 fatal 级别的日志。
   - **实现原理:** 利用了操作系统提供的调试接口 `ptrace` 来访问其他进程的寄存器和内存。不同架构的线程本地存储实现方式不同，因此需要不同的 `ptrace` 参数和处理逻辑。

4. **`void __libc_iterate_dynamic_tls(pid_t tid, void (*cb)(void* __dynamic_tls_begin, void* __dynamic_tls_end, size_t __dso_id, void* __arg), void* arg)`:**
   - 首先调用 `__get_bionic_tcb_for_thread(tid)` 获取指定线程的 TCB。
   - 从 TCB 中获取动态线程向量 (DTV) 的指针 (`__get_tcb_dtv(tcb)`)。DTV 是一个存储动态 TLS 块信息的数组。
   - `__libc_shared_globals()->tls_modules.static_module_count` 表示静态 TLS 模块的数量。动态 TLS 模块的索引从这个值开始。
   - 遍历 DTV 中索引大于等于静态模块数量的条目。
   - 对于每个非空的 DTV 条目 (`dtv->modules[i]`)，将其视为动态 TLS 块的起始地址 (`dtls_begin`)。
   - 使用 `__libc_shared_globals()->tls_allocator.get_chunk_size(dtls_begin)` 获取该 TLS 块的大小，从而计算出结束地址 (`dtls_end`)。
   - `__tls_module_idx_to_id(i)` 将 DTV 索引转换为动态共享对象 (DSO) 的 ID。
   - 调用用户提供的回调函数 `cb`，传递动态 TLS 块的起始地址、结束地址、DSO ID 和用户提供的参数 `arg`。
   - **实现原理:** 通过访问线程的 DTV，可以找到所有已加载的共享库的动态 TLS 块。`BionicAllocator` 用于管理动态 TLS 块的内存。

5. **`void __libc_register_dynamic_tls_listeners(dtls_listener_t on_creation, dtls_listener_t on_destruction)`:**
   - 此函数用于注册在动态 TLS 块创建和销毁时被调用的监听器函数。
   - `__libc_shared_globals()->tls_modules` 获取 TLS 模块相关的全局信息。
   - 将传入的 `on_creation` 和 `on_destruction` 回调函数分别赋值给 `tls_modules.on_creation_cb` 和 `tls_modules.on_destruction_cb`。
   - **实现原理:**  提供了一种机制，允许其他模块在动态 TLS 的生命周期事件发生时执行自定义操作。

**涉及 dynamic linker 的功能及处理过程:**

`__libc_iterate_dynamic_tls` 函数直接涉及 dynamic linker 的功能。

**SO 布局样本:**

```
// 假设有一个名为 libtest.so 的共享库

.tbss          // 存放未初始化的线程局部变量
  .rel.tbss    // .tbss 段的重定位信息

.tdata         // 存放已初始化的线程局部变量
  .rel.tdata   // .tdata 段的重定位信息

.text          // 代码段
.rodata        // 只读数据段
...
```

**链接的处理过程:**

1. **编译时:** 编译器会为共享库中声明的线程局部变量在 `.tbss` 或 `.tdata` 段中分配空间，并生成相应的重定位信息。
2. **加载时 (dlopen 或应用启动):**
   - Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会解析 ELF 文件头，识别需要分配 TLS 空间的共享库。
   - 对于每个需要 TLS 的共享库，链接器会在当前线程的 DTV 中分配一个槽位。
   - 链接器会分配一块内存区域作为该共享库的动态 TLS 块。
   - 根据 `.tdata` 段的内容初始化动态 TLS 块。
   - DTV 中对应的槽位会指向分配的动态 TLS 块的起始地址。
   - `__tls_module_idx_to_id` 函数负责将 DTV 的索引映射到共享库的 ID。

**逻辑推理及假设输入与输出:**

假设有一个线程 ID 为 `12345` 的线程，并且该线程加载了两个共享库，它们的动态 TLS 块分别位于内存地址 `0x7faaaaa000` 和 `0x7fbbbbb000`，大小分别为 `0x100` 和 `0x200` 字节。

调用 `__libc_iterate_dynamic_tls(12345, my_callback, nullptr)`，其中 `my_callback` 是一个自定义的回调函数，定义如下：

```c++
void my_callback(void* begin, void* end, size_t id, void* arg) {
  printf("Dynamic TLS block: begin=%p, end=%p, id=%zu\n", begin, end, id);
}
```

**可能的输出:**

```
Dynamic TLS block: begin=0x7faaaaa000, end=0x7faaaaa100, id=1
Dynamic TLS block: begin=0x7fbbbbb000, end=0x7fbbbbb200, id=2
```

这里假设共享库的 ID 分别为 1 和 2。

**用户或编程常见的使用错误:**

1. **在不合适的时机注册线程退出回调:** 如果在线程已经开始退出流程后才注册回调，回调可能不会被执行。
2. **在线程退出回调中访问无效的内存:** 线程退出时，一些资源可能已经被释放，如果在回调中访问这些资源会导致崩溃。
3. **错误地使用 `ptrace` 访问其他线程:**  `ptrace` 需要足够的权限。如果应用没有 `CAP_SYS_PTRACE` capability 或者 SELinux 策略不允许，`ptrace` 调用会失败。
4. **在回调函数中执行耗时操作:** 线程退出回调应该尽快执行完毕，避免阻塞线程退出流程。
5. **忘记处理 `ptrace` 失败的情况:**  `__get_bionic_tcb_for_thread` 中 `ptrace` 失败会记录日志，但调用者应该意识到这种情况并采取相应的措施。

**Android framework or ndk 如何一步步的到达这里:**

1. **Java `Thread` 创建 (Framework):**
   - 当 Java 代码中创建一个新的 `Thread` 对象并调用 `start()` 方法时，会通过 JNI 调用到 Android Runtime (ART)。
   - ART 会调用 `pthread_create` 创建一个 native 线程。
   - `pthread_create` 的实现位于 Bionic libc 中。
   - 在新线程创建的过程中，Bionic libc 会初始化线程相关的结构，包括 TCB 和 TLS。

2. **NDK `pthread_create` (NDK):**
   - NDK 开发者可以直接使用 `pthread_create` 函数创建线程。
   - 这会直接调用到 Bionic libc 的 `pthread_create` 实现。

3. **动态库加载 (`dlopen`) (Framework/NDK):**
   - 当使用 `System.loadLibrary()` (Java) 或 `dlopen()` (C/C++) 加载共享库时，动态链接器会被调用。
   - 动态链接器会为共享库分配 TLS 空间，并可能注册动态 TLS 的创建和销毁监听器。

4. **访问线程本地变量 (`thread_local`) (NDK):**
   - 当 NDK 代码中使用 `thread_local` 关键字声明线程本地变量时，编译器会将这些变量放置在 TLS 区域。
   - 对这些变量的访问会转换为对 TLS 区域的内存访问。

**Frida hook 示例调试步骤:**

假设我们要 hook `__libc_get_static_tls_bounds` 函数，查看其返回的静态 TLS 边界。

**Frida hook 脚本 (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName('libc.so');
  const get_static_tls_bounds = libc.getExportByName('__libc_get_static_tls_bounds');

  if (get_static_tls_bounds) {
    Interceptor.attach(get_static_tls_bounds, {
      onEnter: function (args) {
        console.log('[*] __libc_get_static_tls_bounds called');
      },
      onLeave: function (retval) {
        const beginPtr = this.context.r0; // 假设 r0 寄存器存放 begin 指针
        const endPtr = this.context.r1;   // 假设 r1 寄存器存放 end 指针
        const begin = Memory.readPointer(ptr(beginPtr));
        const end = Memory.readPointer(ptr(endPtr));
        console.log(`[*] Static TLS bounds: begin=${begin}, end=${end}`);
      }
    });
  } else {
    console.error('[-] __libc_get_static_tls_bounds not found');
  }
} else {
  console.log('[-] This script is for Android only.');
}
```

**调试步骤:**

1. **准备 Frida 环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端。你的电脑上安装了 Frida 客户端。
2. **运行目标应用:** 启动你想要调试的 Android 应用。
3. **执行 Frida hook 脚本:** 使用 Frida 命令行工具连接到目标应用并执行 hook 脚本。例如：
   ```bash
   frida -U -f <package_name> -l your_script.js --no-pause
   ```
   将 `<package_name>` 替换为你的应用包名，`your_script.js` 替换为你的 Frida 脚本文件名。
4. **观察输出:** 当目标应用执行到 `__libc_get_static_tls_bounds` 函数时，Frida 会拦截调用并执行你在脚本中定义的操作，你将在控制台上看到相应的日志输出，包括静态 TLS 的起始和结束地址。

**注意:** 不同架构下，寄存器约定可能不同，你需要根据实际情况调整 `onLeave` 中的寄存器读取。可以使用 Frida 的 `context` 对象访问寄存器值。

通过这种方式，你可以利用 Frida 深入了解 Android 底层线程属性相关的操作，并进行调试和分析。

### 提示词
```
这是目录为bionic/libc/bionic/sys_thread_properties.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <sys/thread_properties.h>

#include <async_safe/CHECK.h>
#include <async_safe/log.h>

#include <elf.h>
#include <pthread.h>
#include <unistd.h>

#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>

#if defined(__i386__)
#include <asm/ldt.h>
#endif

#include "private/ErrnoRestorer.h"
#include "private/bionic_elf_tls.h"
#include "private/bionic_globals.h"
#include "private/bionic_tls.h"
#include "pthread_internal.h"

void __libc_get_static_tls_bounds(void** stls_begin, void** stls_end) {
  const StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
  *stls_begin = reinterpret_cast<char*>(__get_bionic_tcb()) - layout.offset_bionic_tcb();
  *stls_end = reinterpret_cast<char*>(*stls_begin) + layout.size();
}

void __libc_register_thread_exit_callback(thread_exit_cb_t cb) {
  TlsModules& modules = __libc_shared_globals()->tls_modules;

  if (modules.first_thread_exit_callback == nullptr) {
    modules.first_thread_exit_callback = cb;
    return;
  }

  BionicAllocator& allocator = __libc_shared_globals()->tls_allocator;
  CallbackHolder* new_node =
      reinterpret_cast<CallbackHolder*>(allocator.alloc(sizeof(CallbackHolder)));
  new_node->cb = cb;
  new_node->prev = modules.thread_exit_callback_tail_node;
  modules.thread_exit_callback_tail_node = new_node;
}

static inline __always_inline bionic_tcb* __get_bionic_tcb_for_thread(pid_t tid) {
  // If tid is same as self, then we don't need ptrace.
  if (gettid() == tid) return __get_bionic_tcb();

  // Find the thread-pointer register for the given thread.
  void** tp_reg = nullptr;
#if defined(__aarch64__)
  uint64_t reg;
  struct iovec pt_iov { .iov_base = &reg, .iov_len = sizeof(reg) };
  if (ptrace(PTRACE_GETREGSET, tid, NT_ARM_TLS, &pt_iov) == 0) {
    tp_reg = reinterpret_cast<void**>(reg);
  }
#elif defined(__arm__)
  if (ptrace(PTRACE_GET_THREAD_AREA, tid, nullptr, &tp_reg) != 0) {
    // Reset the tp_reg if ptrace was unsuccessful.
    tp_reg = nullptr;
  }
#elif defined(__i386__)
  struct user_regs_struct regs;
  struct iovec pt_iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
  if (ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &pt_iov) == 0) {
    struct user_desc u_info;
    u_info.entry_number = regs.xgs >> 3;
    if (ptrace(PTRACE_GET_THREAD_AREA, tid, u_info.entry_number, &u_info) == 0) {
      tp_reg = reinterpret_cast<void**>(u_info.base_addr);
    }
  }
#elif defined(__riscv)
  struct user_regs_struct regs;
  struct iovec pt_iov = { .iov_base = &regs, .iov_len = sizeof(regs) };
  if (ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &pt_iov) == 0) {
    tp_reg = reinterpret_cast<void**>(regs.tp);
  }
#elif defined(__x86_64__)
  {
    ErrnoRestorer errno_restorer;
    errno = 0;
    uintptr_t fs_base = ptrace(PTRACE_PEEKUSER, tid, offsetof(user_regs_struct, fs_base), nullptr);
    if (errno == 0) {
      tp_reg = reinterpret_cast<void**>(fs_base);
    }
  }
#endif

  if (tp_reg == nullptr) {
    async_safe_write_log(ANDROID_LOG_FATAL, "libc",
                         "__get_bionic_tcb_for_thread failed to read thread register.");
  }

  return reinterpret_cast<bionic_tcb*>(&tp_reg[MIN_TLS_SLOT]);
}

void __libc_iterate_dynamic_tls(pid_t tid,
                                void (*cb)(void* __dynamic_tls_begin, void* __dynamic_tls_end,
                                           size_t __dso_id, void* __arg),
                                void* arg) {
  TlsModules& modules = __libc_shared_globals()->tls_modules;
  bionic_tcb* const tcb = __get_bionic_tcb_for_thread(tid);
  TlsDtv* const dtv = __get_tcb_dtv(tcb);
  BionicAllocator& allocator = __libc_shared_globals()->tls_allocator;

  for (size_t i = modules.static_module_count; i < dtv->count; ++i) {
    void* dtls_begin = dtv->modules[i];
    if (dtls_begin == nullptr) continue;
    void* dtls_end =
        static_cast<void*>(static_cast<char*>(dtls_begin) + allocator.get_chunk_size(dtls_begin));
    size_t dso_id = __tls_module_idx_to_id(i);

    cb(dtls_begin, dtls_end, dso_id, arg);
  }
}

void __libc_register_dynamic_tls_listeners(dtls_listener_t on_creation,
                                           dtls_listener_t on_destruction) {
  TlsModules& tls_modules = __libc_shared_globals()->tls_modules;
  tls_modules.on_creation_cb = on_creation;
  tls_modules.on_destruction_cb = on_destruction;
}
```