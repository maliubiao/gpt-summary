Response:
Here's a breakdown of the thinking process used to generate the detailed response:

1. **Understand the Goal:** The primary goal is to analyze the provided C header file (`threads_inlines.handroid`) and explain its purpose, functions, relation to Android, and potential usage scenarios, along with debugging techniques.

2. **Initial Overview:**  Start by recognizing that this file is part of Android's Bionic libc and focuses on providing inline implementations for thread-related functionalities. The filename suffix ".handroid" suggests it might contain Android-specific optimizations or modifications. The inclusion of `<threads.h>` strongly indicates it's implementing the C11 threads standard.

3. **Function-by-Function Analysis:**  Go through each function defined in the file sequentially. For each function, consider the following:

    * **Purpose:** What does the function do?  Relate it to standard threading concepts (mutexes, condition variables, thread creation, etc.).
    * **Implementation:** How is it implemented?  Notice the consistent pattern of wrapping `pthread` functions. This is a key observation.
    * **Return Values:** Pay attention to how error codes are mapped between `pthread` and the C11 `thrd_*` family.
    * **Parameters:** Note the types and purpose of each parameter.

4. **Identify Key Patterns and Abstractions:**  Recognize the core design principle: providing a C11-compliant threading interface on top of the POSIX threads (pthreads) implementation available in Android. The `__bionic_thrd_error` function is crucial for this mapping.

5. **Connect to Android:**  Explicitly state the relationship to Android. Highlight that Bionic is the standard C library, meaning this code is fundamental for all Android processes. Think about where these functions are used – any multithreaded Android application.

6. **Illustrate with Examples:** For each category of functions (mutexes, condition variables, threads, thread-local storage, `call_once`), create simple, illustrative code snippets demonstrating their usage. Focus on the basic mechanics.

7. **Address Dynamic Linking:**  The prompt specifically asks about dynamic linking. Since these functions are in `libc.so`, the explanation needs to cover how applications link against `libc.so` and how the dynamic linker resolves these symbols. Create a basic `libc.so` layout example. Describe the linking process at runtime.

8. **Consider Edge Cases and Errors:** Think about common mistakes developers might make when using these threading primitives. Examples include forgetting to initialize or destroy synchronization objects, incorrect locking order leading to deadlocks, and memory management issues with thread arguments.

9. **Explain Android Framework/NDK Integration:** Trace the path from high-level Android concepts to these low-level primitives. Start with Android Framework (Java/Kotlin), move to the NDK (C/C++), and then show how NDK code ultimately uses Bionic's threading functions.

10. **Demonstrate Debugging with Frida:** Provide practical Frida hook examples for a few key functions. Explain *what* the hook does and *why* it's useful for debugging (e.g., observing function calls, inspecting arguments).

11. **Structure and Language:** Organize the information logically. Use clear and concise language. Explain technical terms. Use headings and bullet points to improve readability. Maintain a consistent tone. Ensure the response is in Chinese as requested.

12. **Refine and Review:** After drafting the response, review it for accuracy, completeness, and clarity. Check for any inconsistencies or areas that could be explained better. Ensure all aspects of the prompt are addressed.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe these inline functions are doing something significantly different from pthreads.
* **Correction:**  Realized the primary purpose is to provide the C11 API. The `__bionic_thrd_error` function and the direct calls to `pthread_*` functions confirm this. Focus shifted to explaining the mapping.
* **Initial thought:**  Just list the functions and their direct `pthread` counterparts.
* **Refinement:** Realized the need for more context and explanation. Added sections explaining the purpose of each group of functions, examples, and how they fit into the Android ecosystem.
* **Initial thought:**  Focus only on the C code.
* **Refinement:**  Recognized the importance of explaining the relationship to the Android Framework and NDK to provide a complete picture.
* **Initial thought:** Provide very complex Frida scripts.
* **Refinement:** Simplified the Frida examples to focus on basic function hooking and argument inspection, making them easier to understand.

By following this structured thought process and incorporating self-correction, a comprehensive and informative answer can be generated.
好的，让我们详细分析一下 `bionic/libc/include/bits/threads_inlines.handroid` 这个头文件的内容和功能。

**文件功能概述**

这个头文件定义了一些内联函数，这些函数是对 POSIX 线程 (pthreads) API 的一层封装。它旨在提供 C11 标准中定义的线程相关 API (`<threads.h>`) 的实现。由于 Android 底层使用的是 pthreads，这个文件起到了一个桥梁的作用，使得开发者可以使用标准 C11 的线程接口，而 Bionic libc 负责将其转换为底层的 pthreads 调用。

**功能详细列举及与 Android 功能的关系**

该文件主要提供了以下功能的内联实现：

1. **错误码转换 (`__bionic_thrd_error`)**:
   - **功能:** 将 pthreads 函数返回的错误码转换为 C11 线程 API 定义的错误码（例如 `thrd_nomem`, `thrd_timedout`, `thrd_busy`, `thrd_error`）。
   - **Android 关系:** Android 的 Bionic libc 实现了 pthreads，因此当调用底层的 `pthread_*` 函数时，可能会返回 POSIX 标准的错误码。这个函数确保了返回给使用 C11 线程 API 的代码是标准规定的错误码。
   - **实现:** 通过一个 `switch` 语句将 `pthread` 错误码映射到 `thrd_*` 错误码。
   - **假设输入与输出:**
     - 输入: `ENOMEM` (pthreads 的内存不足错误)
     - 输出: `thrd_nomem` (C11 的内存不足错误)

2. **一次性初始化 (`call_once`)**:
   - **功能:** 确保一个函数只被执行一次，即使在多线程环境下。
   - **Android 关系:** 在 Android 开发中，某些初始化操作只需要执行一次，例如初始化全局资源。`call_once` 可以方便地实现这种需求。
   - **实现:** 直接调用底层的 `pthread_once` 函数。`pthread_once` 使用 `once_flag` 来保证函数只执行一次。
   - **假设输入与输出:**
     - 输入: 一个未初始化的 `once_flag` 和一个初始化函数 `init_func`。
     - 输出: 首次调用 `call_once` 时，`init_func` 会被执行。后续调用 `call_once` 将不会执行 `init_func`。
   - **用户或编程常见错误:**
     - 未正确初始化 `once_flag`。虽然通常情况下未初始化的内存为零，但在某些平台上可能不是。最好使用 `ONCE_FLAG_INIT` 初始化。
     - 传递了错误的函数指针。

3. **条件变量 (`cnd_broadcast`, `cnd_destroy`, `cnd_init`, `cnd_signal`, `cnd_timedwait`, `cnd_wait`)**:
   - **功能:** 提供线程同步机制，允许线程在满足特定条件时挂起，并在条件满足时被唤醒。
   - **Android 关系:** 条件变量在 Android 的多线程编程中被广泛使用，例如生产者-消费者模式，用于协调线程之间的操作。
   - **实现:** 这些函数都直接调用对应的 `pthread_cond_*` 函数，并通过 `__bionic_thrd_error` 处理错误码。
     - `cnd_broadcast`: 唤醒所有等待该条件变量的线程。
     - `cnd_destroy`: 销毁条件变量。
     - `cnd_init`: 初始化条件变量。
     - `cnd_signal`: 唤醒一个等待该条件变量的线程。
     - `cnd_timedwait`: 在指定时间内等待条件变量变为真，需要与互斥锁配合使用。
     - `cnd_wait`: 无限期等待条件变量变为真，需要与互斥锁配合使用。
   - **用户或编程常见错误:**
     - 在操作条件变量之前未锁定相关的互斥锁。
     - 忘记在条件改变后发送信号或广播。
     - 使用 `cnd_wait` 时，忘记在一个循环中检查条件，以防止虚假唤醒。
     - 在条件变量销毁后尝试使用它。
   - **假设输入与输出:**
     - 线程 A 调用 `cnd_wait` 并持有一个互斥锁。线程 B 修改了条件变量相关的状态并调用 `cnd_signal`。
     - 输出: 线程 A 被唤醒，并重新获得互斥锁。

4. **互斥锁 (`mtx_destroy`, `mtx_init`, `mtx_lock`, `mtx_timedlock`, `mtx_trylock`, `mtx_unlock`)**:
   - **功能:** 提供互斥访问共享资源的机制，防止多个线程同时访问造成数据竞争。
   - **Android 关系:** 互斥锁在 Android 中用于保护共享数据结构，例如全局变量、共享内存等。
   - **实现:** 这些函数都直接调用对应的 `pthread_mutex_*` 函数，并通过 `__bionic_thrd_error` 处理错误码。
     - `mtx_destroy`: 销毁互斥锁。
     - `mtx_init`: 初始化互斥锁，可以指定锁的类型（普通锁或递归锁）。
     - `mtx_lock`: 尝试获取互斥锁，如果锁被其他线程持有，则阻塞等待。
     - `mtx_timedlock`: 在指定时间内尝试获取互斥锁，如果超时仍未获取到锁，则返回错误。
     - `mtx_trylock`: 尝试获取互斥锁，如果锁被其他线程持有，则立即返回错误，不会阻塞。
     - `mtx_unlock`: 释放互斥锁。
   - **实现细节 (`mtx_init`):**  `mtx_init` 函数会根据传入的 `__type` 参数设置 `pthread_mutexattr_t` 的类型，以支持递归锁。
   - **用户或编程常见错误:**
     - 死锁：多个线程互相等待对方释放锁。
     - 忘记解锁，导致其他线程永久阻塞。
     - 在未初始化的互斥锁上进行操作。
     - 重复解锁同一个互斥锁。
   - **假设输入与输出:**
     - 线程 A 调用 `mtx_lock` 获取锁。线程 B 尝试调用 `mtx_lock` 获取相同的锁。
     - 输出: 线程 B 会被阻塞，直到线程 A 调用 `mtx_unlock` 释放锁。

5. **线程管理 (`thrd_create`, `thrd_current`, `thrd_detach`, `thrd_equal`, `thrd_exit`, `thrd_join`, `thrd_sleep`, `thrd_yield`)**:
   - **功能:** 提供创建、管理和控制线程的功能。
   - **Android 关系:**  Android 应用程序和服务都是多线程的，这些函数是创建和管理后台任务的基础。
   - **实现:**
     - `thrd_create`: 创建一个新的线程。它使用一个中间函数 `__bionic_thrd_trampoline` 作为线程的入口点。这个中间函数负责调用用户提供的线程函数，并处理参数的传递和内存的释放。
     - `thrd_current`: 获取当前线程的标识符。
     - `thrd_detach`: 将线程设置为 detached 状态，表示该线程结束后资源会自动释放，不需要其他线程 `join`。
     - `thrd_equal`: 比较两个线程的标识符是否相等。
     - `thrd_exit`: 终止当前线程。
     - `thrd_join`: 等待指定的线程结束，并可以获取线程的返回值。
     - `thrd_sleep`: 让当前线程休眠指定的时间。
     - `thrd_yield`: 让当前线程放弃 CPU 时间片，允许其他线程运行。
   - **实现细节 (`thrd_create`):**  `thrd_create` 分配一个 `__bionic_thrd_data` 结构体来存储用户提供的线程函数和参数，然后将其传递给 `pthread_create`。`__bionic_thrd_trampoline` 负责从这个结构体中提取信息并调用用户的函数，并在函数执行完毕后释放分配的内存。
   - **用户或编程常见错误:**
     - 在 `thrd_create` 中传递错误的函数指针或参数。
     - 忘记 `thrd_join` 一个可 join 的线程，导致资源泄漏。
     - 在 detached 线程上调用 `thrd_join`。
     - 在线程函数中访问已释放的局部变量。
   - **假设输入与输出 (`thrd_create`):**
     - 调用 `thrd_create`，传入一个函数 `my_thread_func` 和参数 `my_arg`。
     - 输出: 新的线程被创建并开始执行 `my_thread_func(my_arg)`。

6. **线程本地存储 (`tss_create`, `tss_delete`, `tss_get`, `tss_set`)**:
   - **功能:** 允许每个线程拥有自己的私有数据副本。
   - **Android 关系:** 在 Android 开发中，线程本地存储可以用于存储与特定线程相关的状态信息，避免全局变量带来的线程安全问题。例如，每个线程可以拥有自己的错误码副本。
   - **实现:** 这些函数都直接调用对应的 `pthread_key_*` 和 `pthread_setspecific`/`pthread_getspecific` 函数，并通过 `__bionic_thrd_error` 处理错误码。
     - `tss_create`: 创建一个线程本地存储的键，可以指定析构函数，在线程结束时自动释放存储的数据。
     - `tss_delete`: 删除一个线程本地存储的键。
     - `tss_get`: 获取当前线程与指定键关联的值。
     - `tss_set`: 设置当前线程与指定键关联的值。
   - **用户或编程常见错误:**
     - 忘记调用 `tss_delete` 清理资源。
     - 在一个线程中设置了 TSS，但在另一个线程中尝试获取，可能会得到空指针。
     - 在 TSS 键被删除后尝试使用它。
   - **假设输入与输出:**
     - 线程 A 调用 `tss_set` 为键 `my_tss_key` 设置值 `my_data_ptr`。
     - 输出: 线程 A 后续调用 `tss_get(my_tss_key)` 将返回 `my_data_ptr`。其他线程调用 `tss_get(my_tss_key)` 将返回 `NULL`，除非它们也设置了自己的值。

**Dynamic Linker 的功能及 SO 布局样本和链接处理过程**

这个头文件本身不直接涉及 dynamic linker 的功能，它定义的是一些内联函数，这些函数最终会链接到 `libc.so` 中。Dynamic linker 的作用是在程序启动时加载程序依赖的动态链接库，并解析和绑定符号。

**SO 布局样本 (`libc.so`)**

一个简化的 `libc.so` 布局可能如下所示：

```
libc.so:
  .text:  // 包含可执行代码
    __bionic_thrd_error (代码)
    call_once (代码)
    cnd_broadcast (代码)
    ...
    pthread_once (代码 - 可能来自 libpthread.so)
    pthread_cond_broadcast (代码 - 可能来自 libpthread.so)
    ...
  .data:  // 包含已初始化的全局变量
  .bss:   // 包含未初始化的全局变量
  .dynamic: // 包含动态链接信息
    SONAME: libc.so
    NEEDED: libpthread.so  // 依赖于 libpthread.so
    SYMTAB: ...           // 符号表
    STRTAB: ...           // 字符串表
    ...
```

**链接的处理过程**

1. **编译时:** 当你编译一个使用了 `<threads.h>` 中函数的程序时，编译器会生成对这些函数的未解析引用。
2. **链接时:** 链接器（例如 `ld`）会将你的程序与 Bionic libc (`libc.so`) 链接起来。链接器会查找 `libc.so` 的符号表，找到 `call_once`, `cnd_broadcast` 等函数的定义，并将这些引用解析到 `libc.so` 中对应的代码地址。
3. **运行时:** 当程序启动时，Android 的 dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会负责加载 `libc.so` 到内存中。
4. **符号绑定:** dynamic linker 会遍历程序和其依赖库的重定位表，将程序中对 `call_once`, `cnd_broadcast` 等函数的调用地址更新为 `libc.so` 中这些函数的实际内存地址。
5. **延迟绑定 (Lazy Binding):** 为了优化启动速度，Android 通常使用延迟绑定。这意味着函数符号的解析和绑定可能不会在程序启动时立即完成，而是在第一次调用该函数时才进行。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java/Kotlin):**
   - Android Framework 层的代码通常使用 Java 的 `java.lang.Thread` 类或 Kotlin 的协程来处理并发。
   - 当需要执行 Native 代码时，Framework 会通过 JNI (Java Native Interface) 调用 NDK 提供的 C/C++ 代码。

2. **Android NDK (C/C++):**
   - NDK 开发者可以直接使用 `<threads.h>` 中定义的 C11 线程 API。
   - 当 NDK 代码中调用例如 `thrd_create` 时，实际上会调用 `bionic/libc/include/bits/threads_inlines.handroid` 中定义的内联函数。
   - 这些内联函数会进一步调用 Bionic libc 提供的 `pthread_*` 函数。

**逐步过程示例：**

1. **Java 代码:**
   ```java
   // 在 Android Framework 层
   new Thread(() -> {
       // 执行一些操作，最终可能调用 Native 代码
       MyNativeLib.doSomething();
   }).start();
   ```

2. **NDK 代码 (C++):**
   ```c++
   // 在 NDK 库中 (my_native_lib.cpp)
   #include <thread>

   void doSomething() {
       std::thread myThread([](){
           // 使用 C++ 标准库的线程，底层可能调用 pthreads
           // 或者直接使用 C11 的线程 API
           thrd_t thread_id;
           thrd_create(&thread_id, my_c11_thread_func, nullptr);
           thrd_join(thread_id, nullptr);
       });
       myThread.join();
   }

   int my_c11_thread_func(void* arg) {
       // ... 线程执行的代码
       return 0;
   }
   ```

3. **Bionic libc (`threads_inlines.handroid`):**
   - 当 `thrd_create(&thread_id, my_c11_thread_func, nullptr)` 被调用时，会执行 `threads_inlines.handroid` 中定义的 `thrd_create` 内联函数。
   - `thrd_create` 内联函数会分配内存，并将 `my_c11_thread_func` 和 `nullptr` 包装起来，然后调用 `pthread_create`。

4. **Bionic libc (`libc.so` 的其他部分):**
   - `pthread_create` 的实现位于 Bionic libc 的其他源文件中，它会创建新的内核线程，并执行指定的入口函数 (`__bionic_thrd_trampoline`，然后再调用 `my_c11_thread_func`)。

**Frida Hook 示例**

可以使用 Frida 来 hook 这些函数，观察它们的调用和参数。

```javascript
// Frida 脚本示例

// Hook thrd_create
Interceptor.attach(Module.findExportByName("libc.so", "thrd_create"), {
  onEnter: function(args) {
    console.log("thrd_create called");
    console.log("  thrd*: " + args[0]);
    console.log("  func: " + args[1]);
    console.log("  arg: " + args[2]);
    // 可以进一步读取函数指针指向的内容，如果需要
  },
  onLeave: function(retval) {
    console.log("thrd_create returned: " + retval);
  }
});

// Hook mtx_lock
Interceptor.attach(Module.findExportByName("libc.so", "mtx_lock"), {
  onEnter: function(args) {
    console.log("mtx_lock called");
    console.log("  mtx*: " + args[0]);
  },
  onLeave: function(retval) {
    console.log("mtx_lock returned: " + retval);
  }
});

// Hook cnd_wait
Interceptor.attach(Module.findExportByName("libc.so", "cnd_wait"), {
  onEnter: function(args) {
    console.log("cnd_wait called");
    console.log("  cnd*: " + args[0]);
    console.log("  mtx*: " + args[1]);
  },
  onLeave: function(retval) {
    console.log("cnd_wait returned: " + retval);
  }
});
```

这个 Frida 脚本会拦截 `thrd_create`, `mtx_lock`, 和 `cnd_wait` 函数的调用，并在控制台打印出函数的参数和返回值，帮助你理解多线程代码的执行流程。

希望这个详细的解释能够帮助你理解 `bionic/libc/include/bits/threads_inlines.handroid` 文件的作用以及它在 Android 系统中的地位。

Prompt: 
```
这是目录为bionic/libc/include/bits/threads_inlines.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <sys/cdefs.h>

#include <threads.h>

#include <errno.h>
#include <sched.h>
#include <stdlib.h>

#if defined(__BIONIC_THREADS_INLINE)

__BEGIN_DECLS

static __inline int __bionic_thrd_error(int __pthread_code) {
  switch (__pthread_code) {
    case 0: return 0;
    case ENOMEM: return thrd_nomem;
    case ETIMEDOUT: return thrd_timedout;
    case EBUSY: return thrd_busy;
    default: return thrd_error;
  }
}

__BIONIC_THREADS_INLINE void call_once(once_flag* _Nonnull __flag,
                                       void (* _Nonnull __function)(void)) {
  pthread_once(__flag, __function);
}



__BIONIC_THREADS_INLINE int cnd_broadcast(cnd_t* _Nonnull __cnd) {
  return __bionic_thrd_error(pthread_cond_broadcast(__cnd));
}

__BIONIC_THREADS_INLINE void cnd_destroy(cnd_t* _Nonnull __cnd) {
  pthread_cond_destroy(__cnd);
}

__BIONIC_THREADS_INLINE int cnd_init(cnd_t* _Nonnull __cnd) {
  return __bionic_thrd_error(pthread_cond_init(__cnd, NULL));
}

__BIONIC_THREADS_INLINE int cnd_signal(cnd_t* _Nonnull __cnd) {
  return __bionic_thrd_error(pthread_cond_signal(__cnd));
}

__BIONIC_THREADS_INLINE int cnd_timedwait(cnd_t* _Nonnull __cnd,
                                          mtx_t* _Nonnull __mtx,
                                          const struct timespec* _Nullable __timeout) {
  return __bionic_thrd_error(pthread_cond_timedwait(__cnd, __mtx, __timeout));
}

__BIONIC_THREADS_INLINE int cnd_wait(cnd_t* _Nonnull __cnd, mtx_t* _Nonnull __mtx) {
  return __bionic_thrd_error(pthread_cond_wait(__cnd, __mtx));
}



__BIONIC_THREADS_INLINE void mtx_destroy(mtx_t* _Nonnull __mtx) {
  pthread_mutex_destroy(__mtx);
}

__BIONIC_THREADS_INLINE int mtx_init(mtx_t* _Nonnull __mtx, int __type) {
  int __pthread_type = (__type & mtx_recursive) ? PTHREAD_MUTEX_RECURSIVE
                                                : PTHREAD_MUTEX_NORMAL;
  __type &= ~mtx_recursive;
  if (__type != mtx_plain && __type != mtx_timed) return thrd_error;

  pthread_mutexattr_t __attr;
  pthread_mutexattr_init(&__attr);
  pthread_mutexattr_settype(&__attr, __pthread_type);
  return __bionic_thrd_error(pthread_mutex_init(__mtx, &__attr));
}

__BIONIC_THREADS_INLINE int mtx_lock(mtx_t* _Nonnull __mtx) {
  return __bionic_thrd_error(pthread_mutex_lock(__mtx));
}

__BIONIC_THREADS_INLINE int mtx_timedlock(mtx_t* _Nonnull __mtx,
                                          const struct timespec* _Nullable __timeout) {
  return __bionic_thrd_error(pthread_mutex_timedlock(__mtx, __timeout));
}

__BIONIC_THREADS_INLINE int mtx_trylock(mtx_t* _Nonnull __mtx) {
  return __bionic_thrd_error(pthread_mutex_trylock(__mtx));
}

__BIONIC_THREADS_INLINE int mtx_unlock(mtx_t* _Nonnull __mtx) {
  return __bionic_thrd_error(pthread_mutex_unlock(__mtx));
}

struct __bionic_thrd_data {
  thrd_start_t _Nonnull __func;
  void* _Nullable __arg;
};

static __inline void* _Nonnull __bionic_thrd_trampoline(void* _Nonnull __arg) {
  struct __bionic_thrd_data __data =
      *__BIONIC_CAST(static_cast, struct __bionic_thrd_data*, __arg);
  free(__arg);
  int __result = __data.__func(__data.__arg);
  return __BIONIC_CAST(reinterpret_cast, void*,
                       __BIONIC_CAST(static_cast, uintptr_t, __result));
}

__BIONIC_THREADS_INLINE int thrd_create(thrd_t* _Nonnull __thrd,
                                        thrd_start_t _Nonnull __func,
                                        void* _Nullable __arg) {
  struct __bionic_thrd_data* __pthread_arg =
      __BIONIC_CAST(static_cast, struct __bionic_thrd_data*,
                    malloc(sizeof(struct __bionic_thrd_data)));
  __pthread_arg->__func = __func;
  __pthread_arg->__arg = __arg;
  int __result = __bionic_thrd_error(pthread_create(__thrd, NULL,
                                                    __bionic_thrd_trampoline,
                                                    __pthread_arg));
  if (__result != thrd_success) free(__pthread_arg);
  return __result;
}

__BIONIC_THREADS_INLINE thrd_t thrd_current(void) {
  return pthread_self();
}

__BIONIC_THREADS_INLINE int thrd_detach(thrd_t __thrd) {
  return __bionic_thrd_error(pthread_detach(__thrd));
}

__BIONIC_THREADS_INLINE int thrd_equal(thrd_t __lhs, thrd_t __rhs) {
  return pthread_equal(__lhs, __rhs);
}

__BIONIC_THREADS_INLINE void thrd_exit(int __result) {
  pthread_exit(__BIONIC_CAST(reinterpret_cast, void*,
                             __BIONIC_CAST(static_cast, uintptr_t, __result)));
}

__BIONIC_THREADS_INLINE int thrd_join(thrd_t __thrd, int* _Nullable __result) {
  void* __pthread_result;
  if (pthread_join(__thrd, &__pthread_result) != 0) return thrd_error;
  if (__result) {
    *__result = __BIONIC_CAST(reinterpret_cast, intptr_t, __pthread_result);
  }
  return thrd_success;
}

__BIONIC_THREADS_INLINE int thrd_sleep(const struct timespec* _Nonnull __duration,
                                       struct timespec* _Nullable __remaining) {
  int __rc = nanosleep(__duration, __remaining);
  if (__rc == 0) return 0;
  return (errno == EINTR) ? -1 : -2;
}

__BIONIC_THREADS_INLINE void thrd_yield(void) {
  sched_yield();
}



__BIONIC_THREADS_INLINE int tss_create(tss_t* _Nonnull __key, tss_dtor_t _Nullable __dtor) {
  return __bionic_thrd_error(pthread_key_create(__key, __dtor));
}

__BIONIC_THREADS_INLINE void tss_delete(tss_t __key) {
  pthread_key_delete(__key);
}

__BIONIC_THREADS_INLINE void* _Nullable tss_get(tss_t __key) {
  return pthread_getspecific(__key);
}

__BIONIC_THREADS_INLINE int tss_set(tss_t __key, void* _Nonnull __value) {
  return __bionic_thrd_error(pthread_setspecific(__key, __value));
}

__END_DECLS

#endif  // __BIONIC_THREADS_INLINE

"""

```