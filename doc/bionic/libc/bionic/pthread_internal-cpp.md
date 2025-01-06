Response:
Let's break down the thought process for analyzing the `pthread_internal.cpp` file.

**1. Understanding the Context:**

The first step is recognizing the file's location and description: `bionic/libc/bionic/pthread_internal.cpp`, part of Android's Bionic C library. This immediately signals that the file is crucial for thread management in the Android environment. The "internal" in the name suggests it handles low-level, implementation details not directly exposed to typical users.

**2. Identifying Core Data Structures:**

The global variables `g_thread_list` and `g_thread_list_lock` jump out. The names strongly suggest a linked list of threads and a lock to protect it. The type `pthread_internal_t*` is the key data structure for representing a thread internally. Examining its usage throughout the code will be crucial.

**3. Analyzing Key Functions and Their Purpose (Iterative Approach):**

I'd go through each function, trying to understand its role.

* **`__pthread_internal_add`:** The name and the code clearly indicate adding a `pthread_internal_t` to the global list. The linked list manipulation is straightforward (inserting at the head). The return value, `reinterpret_cast<pthread_t>(thread)`, establishes the connection between the internal representation and the user-facing `pthread_t`.

* **`__pthread_internal_remove`:**  The logic mirrors `add`, performing the opposite operation. It removes a thread from the linked list.

* **`__pthread_internal_free`:** This function deals with memory management, specifically `munmap`. This points to the fact that thread stacks (and potentially the `pthread_internal_t` structure itself) are allocated using `mmap`.

* **`__pthread_internal_remove_and_free`:**  A convenience function combining the previous two operations.

* **`__pthread_internal_gettid`:** This function takes a `pthread_t` and returns a `pid_t`. It needs to find the corresponding internal thread structure. This leads to the next function.

* **`__pthread_internal_find`:**  This is a critical function. It searches the `g_thread_list` for a `pthread_internal_t` matching the provided `pthread_t`. The special handling for the current thread (`__get_thread()`) and the error handling (especially the SDK version check and `async_safe_fatal`) are important details.

* **`__get_main_stack_startstack` and `__find_main_stack_limits`:** These functions delve into how the main thread's stack boundaries are determined by reading `/proc/self/stat` and `/proc/self/maps`. This reveals Android's reliance on procfs for system information.

* **`__allocate_stack_mte_ringbuffer`:** The `mte` in the name and the `stack_mte_ringbuffer_allocate` call strongly suggest Memory Tagging Extension support, a security feature. The naming of the allocated memory using `async_safe_format_buffer` is noteworthy.

* **`__pthread_internal_remap_stack_with_mte`:** This function deals with enabling MTE on thread stacks. The logic of iterating through the thread list and calling `mprotect` is central. The interaction with `__libc_memtag_stack_abi` and `__libc_memtag_stack` indicates process-wide flags related to MTE.

* **`android_run_on_all_threads`:**  This function showcases inter-thread communication using signals. The use of `tgkill` and a semaphore (`g_sem`) for synchronization are the key elements. The handling of potentially terminating threads is important for robustness.

**4. Connecting to Android Functionality:**

After understanding the individual functions, the next step is to relate them to Android's broader functionality.

* **Thread Creation:** The `add` and memory allocation functions are clearly involved in `pthread_create`.
* **Thread Termination:** The `remove` and `free` functions are used during `pthread_exit` and `pthread_join`.
* **Thread Identification:**  `gettid` is fundamental for logging and debugging.
* **Memory Management:** The use of `mmap` and `munmap` highlights how Bionic manages thread stacks.
* **Security:** The MTE-related functions demonstrate Android's efforts to enhance security.
* **Inter-Process Communication (Indirectly):** While not directly IPC, `android_run_on_all_threads` shows how the system can signal all threads within a process.

**5. Explaining LibC Function Implementations:**

For each identified LibC function (or related internal functions like `__pthread_internal_add`), the explanation focuses on how it achieves its task: linked list manipulation, memory management, system calls (`munmap`, `mprotect`, `tgkill`), and file system interaction (`/proc`).

**6. Dynamic Linker Aspects:**

While this specific file doesn't directly implement the dynamic linker, it interacts with it. The `pthread_create` function, which utilizes the functions in this file, is a key point where the dynamic linker's involvement becomes apparent (loading libraries needed by the new thread). The SO layout and linking process explanation comes from understanding how Android loads and manages shared libraries.

**7. Logical Reasoning and Examples:**

For functions like `__pthread_internal_find`, considering invalid inputs (null `pthread_t`) and the resulting behavior helps illustrate the function's error handling. For `android_run_on_all_threads`, demonstrating the execution flow with a simple function helps clarify its operation.

**8. User/Programming Errors:**

Common mistakes like passing an invalid `pthread_t` are directly addressed by the error handling within `__pthread_internal_find`.

**9. Framework/NDK Path and Frida Hooking:**

This requires understanding the call stack involved in thread creation. Starting from the NDK (`pthread_create`), tracing through the Android Framework (e.g., `java.lang.Thread` in Java, then native calls), and eventually landing in Bionic functions is the key. Frida examples demonstrate how to intercept these calls for debugging and analysis.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on thread management.
* **Correction:**  Realize the importance of the memory management aspects (stack allocation).
* **Initial thought:** Briefly mention MTE.
* **Correction:**  Recognize the significance of MTE as a security feature and elaborate on the related functions.
* **Initial thought:**  Focus purely on the code.
* **Correction:**  Connect the code to broader Android concepts and user-level APIs.
* **Initial thought:**  Provide basic explanations.
* **Correction:**  Offer more detailed explanations of the internal mechanisms and interactions.

By following this structured, iterative, and context-aware approach, I can thoroughly analyze the `pthread_internal.cpp` file and provide a comprehensive explanation.
好的，我们来详细分析 `bionic/libc/bionic/pthread_internal.cpp` 这个文件。

**文件功能概述**

`pthread_internal.cpp` 文件是 Android Bionic libc 库中关于 POSIX 线程 (pthread) 的内部实现细节。它主要负责管理和维护进程中所有线程的内部状态信息，并提供了一些底层的操作函数。这些函数不对外暴露，而是被 Bionic libc 中公开的 `pthread_*` 系列函数调用。

**核心功能列表**

1. **线程列表管理:**
   - 维护一个全局链表 (`g_thread_list`)，用于跟踪进程中所有的线程。
   - 提供添加 (`__pthread_internal_add`) 和移除 (`__pthread_internal_remove`) 线程到该列表的功能。
   - 使用读写锁 (`g_thread_list_lock`) 来保证对线程列表的并发访问安全。

2. **线程查找:**
   - 提供根据 `pthread_t` (线程 ID) 查找对应的内部线程结构 (`pthread_internal_t`) 的功能 (`__pthread_internal_find`)。

3. **线程内部结构管理:**
   - 负责分配和释放线程的内部数据结构 (`pthread_internal_t`) 以及线程栈空间。
   - `__pthread_internal_free` 函数负责释放线程相关的内存，包括栈空间。

4. **获取线程 ID (TID):**
   - 提供根据 `pthread_t` 获取 Linux 线程 ID (TID) 的功能 (`__pthread_internal_gettid`)。

5. **主线程栈边界查找:**
   - 提供查找主线程栈的起始和结束地址的功能 (`__get_main_stack_startstack`, `__find_main_stack_limits`)。这通常用于一些需要知道主线程栈范围的操作，例如内存保护设置。

6. **内存标签扩展 (MTE) 支持 (AArch64):**
   - 提供了在支持 MTE 的架构上分配和管理线程栈的 MTE 环形缓冲区的功能 (`__allocate_stack_mte_ringbuffer`)。
   - 提供了重新映射线程栈并启用 MTE 保护的功能 (`__pthread_internal_remap_stack_with_mte`)。这通常在进程启动后，根据系统配置或应用请求启用 MTE。

7. **在所有线程上运行函数:**
   - 提供了一个机制 (`android_run_on_all_threads`)，允许在进程中的所有线程上执行指定的函数。这通过发送特定的信号来实现线程间的同步和协作。

**与 Android 功能的关系及举例说明**

`pthread_internal.cpp` 中的功能是 Android 线程管理的核心组成部分，与 Android 的许多功能紧密相关：

* **应用线程创建:** 当一个 Android 应用（无论是 Java 层还是 Native 层）创建新线程时，最终会调用到 Bionic libc 的 `pthread_create` 函数。`pthread_create` 会调用 `__pthread_internal_add` 将新线程的内部结构添加到全局线程列表中。

   * **例子:** 一个 Java 应用使用 `new Thread(() -> {...}).start()` 创建一个新线程。这个操作最终会通过 JNI 调用到 Native 层的 `pthread_create`。

* **线程同步和互斥:**  虽然这个文件本身不直接实现锁和条件变量等同步原语，但它维护的线程列表和内部结构是实现这些原语的基础。例如，`pthread_mutex_lock` 可能需要访问当前线程的内部状态。

* **线程销毁:** 当线程退出时，`pthread_exit` 会调用 `__pthread_internal_remove_and_free` 将线程从全局列表中移除并释放其占用的资源。

* **获取线程信息:**  Android 系统或应用可以通过 `pthread_self()` 获取当前线程的 `pthread_t`，然后通过 `gettid()` 系统调用（其内部可能会使用 `__pthread_internal_gettid`）获取线程的 Linux TID。这在日志记录、性能分析等场景中非常有用。

   * **例子:** 在 Native 代码中使用 `gettid()` 可以获取当前线程的 TID，用于在 logcat 中区分不同线程的日志输出。

* **内存安全 (MTE):** Android 引入了 MTE 来增强内存安全性。`pthread_internal.cpp` 中关于 MTE 的功能使得 Android 可以在线程栈上启用 MTE 保护，帮助检测和防止内存相关的错误。

**libc 函数的功能实现详解**

由于 `pthread_internal.cpp` 主要包含内部函数，我们来详细解释其中几个关键内部函数的实现：

1. **`__pthread_internal_add(pthread_internal_t* thread)`:**
   - **功能:** 将给定的 `pthread_internal_t` 结构添加到全局线程列表 `g_thread_list` 的头部。
   - **实现:**
     - 获取写锁 `g_thread_list_lock`，以独占访问线程列表。
     - 将新线程的 `next` 指针指向当前的列表头部 (`g_thread_list`)。
     - 将新线程的 `prev` 指针设置为 `nullptr`，因为它将成为新的头部。
     - 如果原来的头部存在（`thread->next != nullptr`），则将其 `prev` 指针指向新线程。
     - 将全局线程列表的头部 `g_thread_list` 更新为新添加的线程。
     - 返回新线程的 `pthread_t`，实际上是将 `pthread_internal_t` 结构的指针进行类型转换。

2. **`__pthread_internal_remove(pthread_internal_t* thread)`:**
   - **功能:** 从全局线程列表 `g_thread_list` 中移除指定的 `pthread_internal_t` 结构。
   - **实现:**
     - 获取写锁 `g_thread_list_lock`。
     - 如果被移除的线程有后继节点 (`thread->next != nullptr`)，则将其后继节点的 `prev` 指针指向被移除线程的前驱节点 (`thread->prev`)。
     - 如果被移除的线程有前驱节点 (`thread->prev != nullptr`)，则将其前驱节点的 `next` 指针指向被移除线程的后继节点 (`thread->next`)。
     - 如果被移除的线程是列表的头部 (`thread->prev == nullptr`)，则更新全局线程列表的头部 `g_thread_list` 为被移除线程的后继节点。

3. **`__pthread_internal_find(pthread_t thread_id, const char* caller)`:**
   - **功能:** 根据给定的 `pthread_t` 查找对应的 `pthread_internal_t` 结构。
   - **实现:**
     - 将 `thread_id` 强制转换为 `pthread_internal_t*`。
     - **快速路径:** 如果要查找的线程是当前线程（通过 `__get_thread()` 获取），则直接返回。
     - 获取读锁 `g_thread_list_lock`，允许多个查找操作并发进行。
     - 遍历全局线程列表 `g_thread_list`，逐个比较列表中的 `pthread_internal_t` 结构指针与要查找的指针是否相等。
     - 如果找到匹配的线程，则返回该 `pthread_internal_t` 指针。
     - 如果遍历完列表没有找到，则进行错误处理：
       - 如果目标 SDK 版本大于等于 26，并且 `thread` 是 `nullptr`，则发出警告日志，因为这是一个常见的错误。
       - 否则，发出严重错误日志并终止程序，因为传入了无效的 `pthread_t`。

4. **`__pthread_internal_gettid(pthread_t thread_id, const char* caller)`:**
   - **功能:** 根据给定的 `pthread_t` 获取对应的 Linux 线程 ID (TID)。
   - **实现:**
     - 调用 `__pthread_internal_find` 函数查找与 `thread_id` 对应的 `pthread_internal_t` 结构。
     - 如果找到，则返回该结构的 `tid` 成员（通常在线程创建时通过 `gettid()` 系统调用获取）。
     - 如果未找到，则返回 -1。

**涉及 dynamic linker 的功能**

虽然 `pthread_internal.cpp` 本身不直接实现 dynamic linker 的功能，但它与 dynamic linker 有着密切的联系，主要体现在线程的创建和初始化过程中。

**SO 布局样本 (简化)**

假设一个简单的 Android 应用加载了一个共享库 `libexample.so`。

```
Memory Map (简化):

[可执行文件内存段]
...
[libexample.so 代码段] <--- 加载到这里
...
[libexample.so 数据段]
...
[libc.so 代码段]
...
[libc.so 数据段]
...
[线程栈 1]
[线程内部结构 1]
[线程栈 2]
[线程内部结构 2]
...
```

**链接的处理过程**

1. **`pthread_create` 调用:** 当应用调用 `pthread_create` 创建新线程时，Bionic libc 的 `pthread_create` 实现会被执行。

2. **栈分配和内部结构创建:** `pthread_create` 会分配新的线程栈空间，并创建一个 `pthread_internal_t` 结构来存储新线程的内部信息。

3. **TLS 初始化:**  dynamic linker 需要为新线程设置线程本地存储 (TLS)。这涉及到在内存中分配 TLS 块，并设置相应的寄存器（例如 ARM64 上的 TPIDR_EL0）。`pthread_internal_t` 结构中会包含指向 TLS 块的指针。

4. **共享库的加载和链接:** 如果新线程需要访问已加载的共享库中的符号，dynamic linker 确保这些符号能够正确解析。在线程创建时，dynamic linker 会维护一个已加载共享库的列表，新线程可以访问这些共享库。

5. **`__pthread_internal_add`:** 新创建的线程的 `pthread_internal_t` 结构会被添加到全局线程列表 `g_thread_list` 中，这使得其他线程可以找到和操作这个新线程。

**逻辑推理，假设输入与输出**

考虑 `__pthread_internal_find` 函数：

* **假设输入:**
    - `thread_id`: 一个有效的 `pthread_t` 值，指向内存中一个已存在的 `pthread_internal_t` 结构。
    - `caller`:  字符串 "pthread_join"。

* **预期输出:** 指向该 `pthread_internal_t` 结构的指针。

* **假设输入:**
    - `thread_id`: `nullptr` (0)。
    - `caller`: 字符串 "pthread_join"。
    - 假设目标 SDK 版本 >= 26。

* **预期输出:**  会输出一个警告日志到 logcat，提示传入了无效的 `pthread_t` (0)，并返回 `nullptr`。

* **假设输入:**
    - `thread_id`: 一个无效的内存地址，不指向任何有效的 `pthread_internal_t` 结构。
    - `caller`: 字符串 "pthread_join"。

* **预期输出:**  如果目标 SDK 版本 >= 26，会输出一个严重错误日志并调用 `async_safe_fatal` 终止程序。否则，返回 `nullptr`。

**用户或编程常见的使用错误**

1. **使用未初始化的 `pthread_t`:**  声明了一个 `pthread_t` 变量，但没有用 `pthread_create` 的返回值初始化它，就尝试将其传递给其他 pthread 函数。

   ```c++
   pthread_t thread;
   // ... 没有调用 pthread_create ...
   pthread_join(thread, nullptr); // 错误：thread 未初始化
   ```

2. **传递已销毁线程的 `pthread_t`:** 在一个线程已经 `pthread_join` 或 detach 后，仍然尝试使用它的 `pthread_t`。

   ```c++
   pthread_t thread;
   pthread_create(&thread, nullptr, thread_func, nullptr);
   pthread_join(thread, nullptr);
   // ... 之后 ...
   pthread_kill(thread, SIGTERM); // 错误：thread 对应的线程已销毁
   ```

3. **在错误的上下文中使用 `pthread_self()` 的返回值:**  虽然 `pthread_self()` 返回当前线程的 `pthread_t`，但在某些特殊情况下（例如在 signal handler 中），其返回值可能需要谨慎使用。

4. **在目标 SDK >= 26 的情况下，错误地将 `nullptr` 作为 `pthread_t` 传递:** 正如代码中所示，新版本的 Android 对此做了更严格的检查，会输出警告或直接 crash。

**Android Framework 或 NDK 如何到达这里**

1. **NDK (Native 开发):**
   - 当 NDK 代码调用 `pthread_create` 时，它会直接链接到 Bionic libc 中的 `pthread_create` 函数。
   - Bionic 的 `pthread_create` 实现会分配必要的资源，创建 `pthread_internal_t` 结构，并调用 `__pthread_internal_add`。

2. **Android Framework (Java 层):**
   - 当 Java 代码创建一个新的 `java.lang.Thread` 对象并调用 `start()` 方法时，最终会通过 JNI 调用到 Native 层的代码。
   - Android Runtime (ART) 会处理线程的创建，最终也会调用到 Bionic libc 的 `pthread_create`。

**Frida Hook 示例调试**

我们可以使用 Frida hook `__pthread_internal_add` 函数，观察新线程的添加过程：

```javascript
if (Process.platform === 'android') {
  const pthread_internal_add = Module.findExportByName('libc.so', '__pthread_internal_add');
  if (pthread_internal_add) {
    Interceptor.attach(pthread_internal_add, {
      onEnter: function (args) {
        const threadInternalPtr = ptr(args[0]);
        console.log('[+] __pthread_internal_add called');
        console.log('    Thread internal struct address:', threadInternalPtr);

        // 可以进一步读取 pthread_internal_t 结构体的成员
        // 例如，假设 pthread_internal_t 的第一个成员是指向栈的指针
        // const stackPtr = threadInternalPtr.readPointer();
        // console.log('    Stack pointer:', stackPtr);
      },
      onLeave: function (retval) {
        console.log('    Returns pthread_t:', retval);
      }
    });
    console.log('[+] Hooked __pthread_internal_add');
  } else {
    console.error('[-] __pthread_internal_add not found in libc.so');
  }
}
```

这个 Frida 脚本会 hook `__pthread_internal_add` 函数，并在每次有新线程添加到全局列表时打印相关信息，例如 `pthread_internal_t` 结构的地址和返回的 `pthread_t` 值。你可以根据 `pthread_internal_t` 的结构定义来读取更多的成员信息。

要 hook `__pthread_internal_find` 并观察查找过程，可以使用类似的 Frida 脚本：

```javascript
if (Process.platform === 'android') {
  const pthread_internal_find = Module.findExportByName('libc.so', '__pthread_internal_find');
  if (pthread_internal_find) {
    Interceptor.attach(pthread_internal_find, {
      onEnter: function (args) {
        const threadId = ptr(args[0]);
        const caller = args[1].readCString();
        console.log('[+] __pthread_internal_find called');
        console.log('    pthread_t:', threadId);
        console.log('    Caller:', caller);
      },
      onLeave: function (retval) {
        console.log('    Returns pthread_internal_t*:', retval);
      }
    });
    console.log('[+] Hooked __pthread_internal_find');
  } else {
    console.error('[-] __pthread_internal_find not found in libc.so');
  }
}
```

通过这些 Frida hook 示例，你可以深入了解 Android 系统中线程管理的内部运作机制。

Prompt: 
```
这是目录为bionic/libc/bionic/pthread_internal.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2008 The Android Open Source Project
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

#include "pthread_internal.h"

#include <errno.h>
#include <semaphore.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/types.h>

#include <async_safe/log.h>
#include <bionic/mte.h>
#include <bionic/reserved_signals.h>
#include <bionic/tls_defines.h>

#include "private/ErrnoRestorer.h"
#include "private/ScopedRWLock.h"
#include "private/bionic_futex.h"
#include "private/bionic_globals.h"
#include "private/bionic_tls.h"

static pthread_internal_t* g_thread_list = nullptr;
static pthread_rwlock_t g_thread_list_lock = PTHREAD_RWLOCK_INITIALIZER;

pthread_t __pthread_internal_add(pthread_internal_t* thread) {
  ScopedWriteLock locker(&g_thread_list_lock);

  // We insert at the head.
  thread->next = g_thread_list;
  thread->prev = nullptr;
  if (thread->next != nullptr) {
    thread->next->prev = thread;
  }
  g_thread_list = thread;
  return reinterpret_cast<pthread_t>(thread);
}

void __pthread_internal_remove(pthread_internal_t* thread) {
  ScopedWriteLock locker(&g_thread_list_lock);

  if (thread->next != nullptr) {
    thread->next->prev = thread->prev;
  }
  if (thread->prev != nullptr) {
    thread->prev->next = thread->next;
  } else {
    g_thread_list = thread->next;
  }
}

static void __pthread_internal_free(pthread_internal_t* thread) {
  if (thread->mmap_size != 0) {
    // Free mapped space, including thread stack and pthread_internal_t.
    munmap(thread->mmap_base, thread->mmap_size);
  }
}

void __pthread_internal_remove_and_free(pthread_internal_t* thread) {
  __pthread_internal_remove(thread);
  __pthread_internal_free(thread);
}

pid_t __pthread_internal_gettid(pthread_t thread_id, const char* caller) {
  pthread_internal_t* thread = __pthread_internal_find(thread_id, caller);
  return thread ? thread->tid : -1;
}

pthread_internal_t* __pthread_internal_find(pthread_t thread_id, const char* caller) {
  pthread_internal_t* thread = reinterpret_cast<pthread_internal_t*>(thread_id);

  // Check if we're looking for ourselves before acquiring the lock.
  if (thread == __get_thread()) return thread;

  {
    // Make sure to release the lock before the abort below. Otherwise,
    // some apps might deadlock in their own crash handlers (see b/6565627).
    ScopedReadLock locker(&g_thread_list_lock);
    for (pthread_internal_t* t = g_thread_list; t != nullptr; t = t->next) {
      if (t == thread) return thread;
    }
  }

  // Historically we'd return null, but from API level 26 we catch this error.
  if (android_get_application_target_sdk_version() >= 26) {
    if (thread == nullptr) {
      // This seems to be a common mistake, and it's relatively harmless because
      // there will never be a valid thread at address 0, whereas other invalid
      // addresses might sometimes contain threads or things that look enough like
      // threads for us to do some real damage by continuing.
      // TODO: try getting rid of this when Treble lets us keep vendor blobs on an old API level.
      async_safe_format_log(ANDROID_LOG_WARN, "libc", "invalid pthread_t (0) passed to %s", caller);
    } else {
      async_safe_fatal("invalid pthread_t %p passed to %s", thread, caller);
    }
  }
  return nullptr;
}

static uintptr_t __get_main_stack_startstack() {
  FILE* fp = fopen("/proc/self/stat", "re");
  if (fp == nullptr) {
    async_safe_fatal("couldn't open /proc/self/stat: %m");
  }

  char line[BUFSIZ];
  if (fgets(line, sizeof(line), fp) == nullptr) {
    async_safe_fatal("couldn't read /proc/self/stat: %m");
  }

  fclose(fp);

  // See man 5 proc. There's no reason comm can't contain ' ' or ')',
  // so we search backwards for the end of it. We're looking for this field:
  //
  //  startstack %lu (28) The address of the start (i.e., bottom) of the stack.
  uintptr_t startstack = 0;
  const char* end_of_comm = strrchr(line, ')');
  if (sscanf(end_of_comm + 1,
             " %*c "
             "%*d %*d %*d %*d %*d "
             "%*u %*u %*u %*u %*u %*u %*u "
             "%*d %*d %*d %*d %*d %*d "
             "%*u %*u %*d %*u %*u %*u %" SCNuPTR,
             &startstack) != 1) {
    async_safe_fatal("couldn't parse /proc/self/stat");
  }

  return startstack;
}

void __find_main_stack_limits(uintptr_t* low, uintptr_t* high) {
  // Ask the kernel where our main thread's stack started.
  uintptr_t startstack = __get_main_stack_startstack();

  // Hunt for the region that contains that address.
  FILE* fp = fopen("/proc/self/maps", "re");
  if (fp == nullptr) {
    async_safe_fatal("couldn't open /proc/self/maps: %m");
  }
  char line[BUFSIZ];
  while (fgets(line, sizeof(line), fp) != nullptr) {
    uintptr_t lo, hi;
    if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR, &lo, &hi) == 2) {
      if (lo <= startstack && startstack <= hi) {
        *low = lo;
        *high = hi;
        fclose(fp);
        return;
      }
    }
  }
  async_safe_fatal("stack not found in /proc/self/maps");
}

#if defined(__aarch64__)
__LIBC_HIDDEN__ void* __allocate_stack_mte_ringbuffer(size_t n, pthread_internal_t* thread) {
  const char* name;
  if (thread == nullptr) {
    name = "stack_mte_ring:main";
  } else {
    // The kernel doesn't copy the name string, but this variable will last at least as long as the
    // mapped area. We unmap the ring buffer before unmapping the rest of the thread storage.
    auto& name_buffer = thread->stack_mte_ringbuffer_vma_name_buffer;
    static_assert(arraysize(name_buffer) >= arraysize("stack_mte_ring:") + 11 + 1);
    async_safe_format_buffer(name_buffer, arraysize(name_buffer), "stack_mte_ring:%d", thread->tid);
    name = name_buffer;
  }
  void* ret = stack_mte_ringbuffer_allocate(n, name);
  if (!ret) async_safe_fatal("error: failed to allocate stack mte ring buffer");
  return ret;
}
#endif

bool __pthread_internal_remap_stack_with_mte() {
#if defined(__aarch64__)
  ScopedWriteLock creation_locker(&g_thread_creation_lock);
  ScopedReadLock list_locker(&g_thread_list_lock);
  // If process already uses memtag-stack ABI, we don't need to do anything.
  if (__libc_memtag_stack_abi) return false;
  __libc_memtag_stack_abi = true;

  for (pthread_internal_t* t = g_thread_list; t != nullptr; t = t->next) {
    // should_allocate_stack_mte_ringbuffer indicates the thread is already
    // aware that this process requires stack MTE, and will allocate the
    // ring buffer in __pthread_start.
    if (t->terminating || t->should_allocate_stack_mte_ringbuffer) continue;
    t->bionic_tcb->tls_slot(TLS_SLOT_STACK_MTE) =
        __allocate_stack_mte_ringbuffer(0, t->is_main() ? nullptr : t);
  }
  if (!atomic_load(&__libc_globals->memtag)) return false;
  if (atomic_exchange(&__libc_memtag_stack, true)) return false;
  uintptr_t lo, hi;
  __find_main_stack_limits(&lo, &hi);

  if (mprotect(reinterpret_cast<void*>(lo), hi - lo,
               PROT_READ | PROT_WRITE | PROT_MTE | PROT_GROWSDOWN)) {
    async_safe_fatal("error: failed to set PROT_MTE on main thread");
  }
  for (pthread_internal_t* t = g_thread_list; t != nullptr; t = t->next) {
    if (t->terminating || t->is_main()) continue;
    if (mprotect(t->mmap_base_unguarded, t->mmap_size_unguarded,
                 PROT_READ | PROT_WRITE | PROT_MTE)) {
      async_safe_fatal("error: failed to set PROT_MTE on thread: %d", t->tid);
    }
  }
  return true;
#else
  return false;
#endif  // defined(__aarch64__)
}

bool android_run_on_all_threads(bool (*func)(void*), void* arg) {
  // Take the locks in this order to avoid inversion (pthread_create ->
  // __pthread_internal_add).
  ScopedWriteLock creation_locker(&g_thread_creation_lock);
  ScopedReadLock list_locker(&g_thread_list_lock);

  // Call the function directly for the current thread so that we don't need to worry about
  // the consequences of synchronizing with ourselves.
  if (!func(arg)) {
    return false;
  }

  static sem_t g_sem;
  if (sem_init(&g_sem, 0, 0) != 0) {
    return false;
  }

  static bool (*g_func)(void*);
  static void *g_arg;
  g_func = func;
  g_arg = arg;

  static _Atomic(bool) g_retval(true);

  auto handler = [](int, siginfo_t*, void*) {
    ErrnoRestorer restorer;
    if (!g_func(g_arg)) {
      atomic_store(&g_retval, false);
    }
    sem_post(&g_sem);
  };

  struct sigaction act = {}, oldact;
  act.sa_flags = SA_SIGINFO;
  act.sa_sigaction = handler;
  sigfillset(&act.sa_mask);
  if (sigaction(BIONIC_SIGNAL_RUN_ON_ALL_THREADS, &act, &oldact) != 0) {
    sem_destroy(&g_sem);
    return false;
  }

  pid_t my_pid = getpid();
  size_t num_tids = 0;
  for (pthread_internal_t* t = g_thread_list; t != nullptr; t = t->next) {
    // The function is called directly for the current thread above, so no need to send a signal to
    // ourselves to call it here.
    if (t == __get_thread()) continue;

    // If a thread is terminating (has blocked signals) or has already terminated, our signal will
    // never be received, so we need to check for that condition and skip the thread if it is the
    // case.
    if (atomic_load(&t->terminating)) continue;

    if (tgkill(my_pid, t->tid, BIONIC_SIGNAL_RUN_ON_ALL_THREADS) == 0) {
      ++num_tids;
    } else {
      atomic_store(&g_retval, false);
    }
  }

  for (size_t i = 0; i != num_tids; ++i) {
    if (TEMP_FAILURE_RETRY(sem_wait(&g_sem)) != 0) {
      atomic_store(&g_retval, false);
      break;
    }
  }

  sigaction(BIONIC_SIGNAL_RUN_ON_ALL_THREADS, &oldact, 0);
  sem_destroy(&g_sem);
  return atomic_load(&g_retval);
}

"""

```