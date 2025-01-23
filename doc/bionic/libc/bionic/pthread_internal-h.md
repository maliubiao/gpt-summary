Response:
Let's break down the thought process for analyzing the `pthread_internal.handroid` header file.

**1. Understanding the Goal:**

The primary goal is to understand the *purpose* and *functionality* of this header file within the Android Bionic library. This involves identifying the data structures, macros, and function declarations it contains, and then explaining their roles. Since it's in the `pthread` directory, it's highly likely related to thread management.

**2. Initial Scan and Keyword Identification:**

A quick scan reveals keywords like `pthread`, `tls`, `stack`, `signal`, `dtor`, `dlerror`, `lock`, `mmap`, `vfork`, `join`, `detach`, `sanitizer`, and `mte`. These keywords provide significant clues about the file's content.

**3. Analyzing the `pthread_internal_t` Structure (The Core):**

This structure is the most important part of the file. The thought process here involves going through each member and asking:

* **What is this member?** (e.g., `next`, `prev` suggest a linked list; `tid` is thread ID; `attr` is thread attributes).
* **What is its type and size?** (e.g., pointers, integers, structures).
* **What does its name suggest?** (e.g., `cached_pid`, `join_state`, `cleanup_stack`).
* **Where might this member be used?** (Consider standard `pthread` functions and common thread management needs).
* **Are there any comments providing additional context?** (The comments about `shadow_call_stack_guard_region` are crucial).

For example, upon seeing `join_state`, the immediate thought is: "This must track the state of a thread in relation to `pthread_join` and `pthread_detach`."  The enumeration `ThreadJoinState` confirms this.

**4. Analyzing Macros and Enums:**

Macros like `PTHREAD_ATTR_FLAG_DETACHED` and `PTHREAD_GUARD_SIZE` define constants. The thought is to understand *what* they represent and *why* they are defined. `PTHREAD_ATTR_FLAG_DETACHED` is clearly a flag related to thread attributes. `PTHREAD_GUARD_SIZE` likely defines the size of a memory region used for protection.

The `ThreadJoinState` enum is directly related to the `join_state` member of `pthread_internal_t`.

**5. Analyzing Function Declarations:**

The function declarations (starting with `__LIBC_HIDDEN__`) are internal functions. The naming convention `__pthread_internal_*` strongly suggests they are implementation details of the `pthread` library. The thought process involves:

* **What does the function name suggest?** (e.g., `__pthread_internal_add` probably adds a thread to some internal list; `__allocate_thread_mapping` allocates memory).
* **What are its parameters and return type?** This provides clues about its input and output.
* **Are there any similar standard `pthread` functions?** (e.g., `__pthread_internal_add` relates to thread creation).

**6. Connecting to Android Functionality:**

After understanding the individual components, the next step is to connect them to higher-level Android functionality. This involves thinking about:

* **How are threads used in Android?** (Applications, system services, etc.)
* **How does the NDK expose threading to developers?** (Standard `pthread` API).
* **How does the Android Framework use threads?** (Looper/Handler, AsyncTask, etc.).
* **How does the dynamic linker interact with threads?** (TLS, library loading).
* **How do debugging tools (like Frida) interact with threads?** (Hooking functions, inspecting memory).

**7. Addressing Specific Request Points:**

The prompt had specific requests, which required targeted analysis:

* **Libc function implementation:**  The file itself *declares* functions but doesn't *implement* them. The explanation focuses on the purpose and potential internal workings based on the declarations and surrounding data structures.
* **Dynamic linker:** The presence of `bionic_tls`, `TlsDtv`, and `dlerror` clearly points to dynamic linker interaction. Creating a sample SO layout and explaining the linking process are necessary.
* **User errors:**  Think about common mistakes developers make with threads (deadlocks, race conditions, incorrect attribute settings).
* **Android Framework/NDK path:** Trace back how a framework or NDK call might eventually lead to the functions defined in this header.
* **Frida hook:**  Provide practical examples of how to use Frida to inspect and intercept the functions and data structures.

**8. Structuring the Response:**

A logical structure is crucial for a comprehensive answer. The chosen structure is:

* **Overall Functionality:** A high-level summary.
* **Detailed Explanation of Key Components:**  Focus on `pthread_internal_t`, macros, and enums.
* **Libc Function Implementation (Conceptual):** Explain the purpose of the declared functions.
* **Dynamic Linker Integration:**  Explain TLS and provide an SO layout example.
* **User Errors:**  Illustrate common mistakes.
* **Android Framework/NDK Path:** Explain how the code is reached.
* **Frida Hook Examples:** Provide concrete debugging examples.

**9. Refinement and Clarity:**

Throughout the process, focus on clear and concise explanations. Use analogies where appropriate (like the linked list for threads). Ensure that technical terms are explained or at least contextualized.

**Self-Correction/Refinement Example:**

Initially, I might focus too heavily on the *implementation* of the libc functions. However, looking at the file content, it's clear this is a *header* file, so it mainly *declares* things. The focus should shift to the *purpose* of these declarations and how they contribute to the overall threading model. Similarly,  I might initially forget to explicitly mention the role of TLS in the dynamic linker context, and then add it upon reviewing the members of `pthread_internal_t` and the declared functions.

By following these steps, we can systematically analyze the provided header file and generate a comprehensive and informative response.
这个C头文件 `pthread_internal.handroid` 定义了 Android Bionic C 库中用于管理线程的内部数据结构和函数声明。它并不直接包含可执行代码的实现，而是为 `pthread` 系列函数（如 `pthread_create`, `pthread_join` 等）的底层实现提供了必要的蓝图。

以下是对其功能的详细列举和解释：

**主要功能：定义线程内部状态和管理结构**

该文件的核心在于定义了 `pthread_internal_t` 这个类，它代表了线程在 Bionic 内部的表示。  这个结构体包含了跟踪和管理线程所需的所有关键信息。

**`pthread_internal_t` 结构体的详细功能：**

* **线程链表管理：**
    * `next`, `prev`:  这两个指针用于将所有活跃的线程组织成一个双向链表。这允许 Bionic 快速遍历和管理所有线程。
    * **Android 关系举例:** 当需要向所有线程发送信号时（例如，在 `fork()` 之后），系统可以使用这个链表来迭代所有线程。

* **线程 ID：**
    * `tid`:  这是操作系统分配的线程 ID（内核线程 ID）。
    * `cached_pid_`:  缓存的进程 ID。
    * `vforked_`:  一个布尔标志，指示线程是否是通过 `vfork()` 创建的。`vfork()` 创建的子进程会共享父进程的内存空间，直到子进程调用 `execve()` 或退出。
    * **Android 关系举例:**  Android 的 `ActivityManagerService` 等系统服务需要跟踪进程和线程，以便进行资源管理和监控。

* **线程属性：**
    * `attr`:  一个 `pthread_attr_t` 结构体，包含了线程的各种属性，例如是否可分离、调度策略、栈大小等。
    * `PTHREAD_ATTR_FLAG_DETACHED`, `PTHREAD_ATTR_FLAG_JOINED`, `PTHREAD_ATTR_FLAG_INHERIT`, `PTHREAD_ATTR_FLAG_EXPLICIT`:  这些宏定义了 `attr` 中使用的标志位，用于表示线程的不同状态和属性设置。
    * **Android 关系举例:**  开发者可以使用 `pthread_attr_setdetachstate()` 来设置线程是否可以被 `pthread_join()` 等待。

* **线程加入状态：**
    * `join_state`:  一个原子变量，用于记录线程的加入状态（未加入、已退出但未加入、已加入、已分离）。
    * `ThreadJoinState` 枚举定义了这些状态。
    * **Android 关系举例:**  当一个线程调用 `pthread_join()` 等待另一个线程结束时，`join_state` 用于确保等待的线程能够正确地获得目标线程的返回值并释放其资源。

* **清理处理程序：**
    * `cleanup_stack`:  指向线程清理处理程序栈的指针。这些处理程序是在线程退出时按照注册的顺序执行的，通常用于释放线程局部资源。
    * **Android 关系举例:**  如果一个线程在持有锁的情况下退出，清理处理程序可以负责释放该锁，避免死锁。

* **线程启动信息：**
    * `start_routine`:  指向线程启动函数的指针。
    * `start_routine_arg`:  传递给启动函数的参数。
    * `return_value`:  存储线程的返回值。
    * `start_mask`:  线程启动时的信号掩码。
    * **Android 关系举例:**  当使用 `pthread_create()` 创建新线程时，需要指定启动函数和参数。

* **备用信号栈：**
    * `alternate_signal_stack`:  指向线程备用信号栈的指针。当线程的主栈溢出时，信号处理程序可以在备用栈上安全地执行。
    * **Android 关系举例:**  这有助于在栈溢出等严重错误发生时，仍然能够捕获信号并进行一些清理或调试操作。

* **影子调用栈（Shadow Call Stack）：**
    * `shadow_call_stack_guard_region`:  用于影子调用栈的安全保护区域的起始地址（仅在 arm64/riscv64 架构上使用）。影子调用栈是一种安全机制，用于防止返回地址被覆盖，从而抵御某些类型的攻击。
    * **Android 关系举例:**  这是 Android 为了提高安全性而引入的特性。

* **栈顶指针：**
    * `stack_top`:  指向线程栈顶的指针。这对于某些调试工具和栈分析非常有用。
    * **Android 关系举例:**  `android_unsafe_frame_pointer_chase` 函数可能会使用这个信息来回溯调用栈。

* **终止状态：**
    * `terminating`:  一个原子布尔变量，指示线程是否正在终止或已终止。
    * **Android 关系举例:**  `android_run_on_all_threads()` 函数会使用这个标志来避免向即将终止的线程发送信号。

* **启动握手锁：**
    * `startup_handshake_lock`:  一个锁，用于在线程启动时进行同步。

* **内存映射信息：**
    * `mmap_base`, `mmap_size`:  线程栈和 TLS 内存映射的基地址和大小。
    * `mmap_base_unguarded`, `mmap_size_unguarded`:  不带保护页的内存映射信息。
    * `vma_name_buffer`:  用于存储 VMA 名称的缓冲区。
    * **Android 关系举例:**  Android 使用 `mmap()` 系统调用为线程分配栈空间。

* **线程局部析构函数：**
    * `thread_local_dtors`:  指向线程局部存储析构函数链表的指针。这些析构函数在线程退出时被调用，用于清理线程局部变量。
    * **Android 关系举例:**  当使用 `__thread` 关键字声明线程局部变量时，可以指定析构函数。

* **`dlerror` 相关：**
    * `current_dlerror`:  指向当前线程的 `dlerror()` 错误消息的指针。
    * `dlerror_buffer`:  存储 `dlerror()` 错误消息的缓冲区。
    * **Android 关系举例:**  `dlerror()` 函数用于获取动态链接器在加载或解析共享库时发生的错误信息。

* **Bionic TLS：**
    * `bionic_tls`:  指向线程的 Bionic TLS（线程局部存储）结构的指针。
    * **Android 关系举例:**  TLS 允许每个线程拥有自己的全局变量副本。

* **`errno` 值：**
    * `errno_value`:  存储线程的 `errno` 值。`errno` 用于指示系统调用的错误。
    * **Android 关系举例:**  每个线程都有自己的 `errno`，避免了多线程环境下的竞争条件。

* **Bionic TCB：**
    * `bionic_tcb`:  指向线程的 Bionic TCB（线程控制块）结构的指针。这是更底层的线程信息结构。
    * `stack_mte_ringbuffer_vma_name_buffer`:  用于存储 MTE 环形缓冲区 VMA 名称的缓冲区。
    * `should_allocate_stack_mte_ringbuffer`:  一个布尔标志，指示是否应该为栈分配 MTE 环形缓冲区。
    * **Android 关系举例:**  TCB 包含更底层的线程状态和寄存器信息。MTE (Memory Tagging Extension) 是一种硬件特性，用于帮助检测内存安全错误。

**辅助宏和函数声明的功能：**

* **宏定义：**
    * `PTHREAD_GUARD_SIZE`: 定义了线程栈保护页的大小，用于检测栈溢出。
    * `SIGNAL_STACK_SIZE_WITHOUT_GUARD`, `SIGNAL_STACK_SIZE`: 定义了备用信号栈的大小。
    * `TLS_SLOT_THREAD_ID`, `TLS_SLOT_BIONIC_TLS`, `TLS_SLOT_DTV`, `MIN_TLS_SLOT`: 定义了 TLS 中各个槽位的索引。

* **静态内联函数：**
    * `__get_bionic_tcb()`:  获取当前线程的 `bionic_tcb`。
    * `__get_thread()`: 获取当前线程的 `pthread_internal_t`。
    * `__get_bionic_tls()`: 获取当前线程的 `bionic_tls`。
    * `__get_tcb_dtv()`, `__set_tcb_dtv()`:  用于获取和设置线程控制块中的 DTV（动态线程向量）。DTV 用于快速访问共享库中的全局变量。

* **外部函数声明：**
    * `__init_tcb()`，`__init_tcb_stack_guard()`，`__init_tcb_dtv()`，`__init_bionic_tls_ptrs()`，`__allocate_temp_bionic_tls()`，`__free_temp_bionic_tls()`，`__init_additional_stacks()`，`__init_thread()`，`__allocate_thread_mapping()`，`__set_stack_and_tls_vma_name()`:  这些函数用于初始化线程的各种内部状态和数据结构。
    * `__pthread_internal_add()`，`__pthread_internal_find()`，`__pthread_internal_gettid()`，`__pthread_internal_remove()`，`__pthread_internal_remove_and_free()`:  这些函数用于管理线程链表和查找线程。
    * `__find_main_stack_limits()`:  查找主线程栈的限制。
    * `__allocate_stack_mte_ringbuffer()`:  分配 MTE 环形缓冲区。
    * `__set_tls()`: 设置线程局部存储。
    * `pthread_key_clean_all()`: 清理所有线程特定数据的键。
    * `__bionic_atfork_run_prepare()`，`__bionic_atfork_run_child()`，`__bionic_atfork_run_parent()`:  在 `fork()` 系统调用前后执行的函数，用于维护线程状态。
    * `__pthread_internal_remap_stack_with_mte()`:  使用 MTE 重新映射线程栈。
    * `android_run_on_all_threads()`:  在一个函数中运行所有线程。
    * `g_thread_creation_lock`:  一个读写锁，用于保护线程创建过程。

**与 Android 功能的关系及举例说明：**

* **线程创建 (`pthread_create`)**: 当应用或系统服务调用 `pthread_create()` 创建新线程时，Bionic 会分配 `pthread_internal_t` 结构体，并使用 `__allocate_thread_mapping()` 分配栈空间，然后调用 `__init_thread()` 初始化线程的各种属性，包括设置 `start_routine` 和 `start_routine_arg`。
* **线程同步 (`pthread_mutex_lock`, `pthread_cond_wait` 等)**:  虽然这个头文件不直接定义同步原语，但 `pthread_internal_t` 结构体是线程管理的基础，同步原语的实现需要访问线程的状态信息。例如，当一个线程被阻塞在互斥锁上时，其状态可能会被记录在某个与 `pthread_internal_t` 关联的数据结构中。
* **线程局部存储 (`pthread_key_create`, `pthread_getspecific`, `pthread_setspecific`)**: `bionic_tls` 成员和相关的函数声明支持线程局部存储的实现。每个线程的 `bionic_tls` 结构体都存储了该线程的特定数据。
* **信号处理 (`signal`, `sigaction`)**: `alternate_signal_stack` 允许在主栈溢出时安全地执行信号处理程序。`start_mask` 记录了线程启动时的信号掩码。
* **动态链接器 (`dlopen`, `dlsym`, `dlclose`)**: `dlerror_buffer` 和 `current_dlerror` 用于支持 `dlerror()` 函数，该函数返回与动态链接相关的错误信息。`TlsDtv` 以及相关的 `__get_tcb_dtv()` 和 `__set_tcb_dtv()` 函数支持动态链接器访问线程局部存储。

**libc 函数的实现（概念性）：**

这个头文件本身不包含 libc 函数的实现，而是定义了实现这些函数所需的内部数据结构和辅助函数。例如：

* **`pthread_create()` 的实现**会使用 `__allocate_thread_mapping()` 分配内存，初始化 `pthread_internal_t` 结构体，设置启动函数和参数，并将新的 `pthread_internal_t` 添加到全局线程链表中 (`__pthread_internal_add()`)。然后，它会创建一个新的内核线程，并将该内核线程与 `pthread_internal_t` 关联起来。
* **`pthread_join()` 的实现**会首先检查目标线程的 `join_state`。如果目标线程已经退出但未被加入，则会收集其返回值并释放其资源。否则，调用线程将被阻塞，直到目标线程退出并通过某种机制更新其 `join_state`。`__pthread_internal_find()` 可能被用于查找目标线程的 `pthread_internal_t` 结构体。

**涉及 dynamic linker 的功能：**

* **`bionic_tls`:**  这是每个线程的线程本地存储区域的描述符。动态链接器使用它来定位共享库中的线程本地变量。
* **`TlsDtv` (Thread Local Storage Dynamic Thread Vector):**  这是一个数组，动态链接器用它来解析对共享库中线程本地变量的引用。每个共享库在 DTV 中都有一个条目。

**so 布局样本：**

假设我们有一个名为 `libexample.so` 的共享库，它包含一个线程局部变量：

```c
// libexample.c
#include <pthread.h>

__thread int my_thread_local_var = 10;

int get_thread_local_var() {
  return my_thread_local_var;
}
```

编译成 `libexample.so` 后，其大致布局可能如下：

```
.text      # 代码段
.rodata    # 只读数据段
.data      # 初始化数据段
.bss       # 未初始化数据段
.tbss      # 线程局部存储未初始化段 (用于 my_thread_local_var)
.tdata     # 线程局部存储初始化段
...
```

**链接的处理过程：**

1. **加载时：** 当 `libexample.so` 被加载到进程空间时，动态链接器会为该库分配内存空间，并解析其符号表。
2. **TLS 初始化：** 动态链接器会为 `libexample.so` 的 TLS 段（`.tbss` 和 `.tdata`）在每个线程的 TLS 区域中分配空间。
3. **DTV 条目：** 动态链接器会更新当前线程的 DTV，为 `libexample.so` 添加一个条目，指向该库的 TLS 块。
4. **访问线程局部变量：** 当代码访问 `my_thread_local_var` 时，编译器会生成特殊的代码序列，该序列会：
    * 获取当前线程的 DTV 指针。
    * 使用 `libexample.so` 的 DTV 条目来定位该库的 TLS 块。
    * 计算 `my_thread_local_var` 在该 TLS 块中的偏移量。
    * 最终访问该内存地址。

**假设输入与输出（逻辑推理）：**

假设有一个线程调用 `pthread_join(thread_id, &retval)`，其中 `thread_id` 是另一个已退出的线程的 ID。

* **假设输入：**
    * `thread_id`: 一个有效的已退出线程的 ID。
    * `retval`: 一个指向 `void*` 的指针，用于接收被连接线程的返回值。
* **逻辑推理：**
    1. `pthread_join()` 内部会调用 `__pthread_internal_find(thread_id, ...)` 找到对应的 `pthread_internal_t` 结构体。
    2. 检查 `thread->join_state`，如果为 `THREAD_EXITED_NOT_JOINED`，表示该线程已退出但未被加入。
    3. 将 `thread->return_value` 的值赋给 `*retval`。
    4. 调用 `__pthread_internal_remove_and_free(thread)` 释放该线程的资源。
    5. 将调用线程的 `join_state` 更新为 `THREAD_JOINED`。
* **预期输出：**
    * `pthread_join()` 返回 0（成功）。
    * `retval` 指向的内存地址存储了被连接线程的返回值。
    * 被连接线程的资源被释放。

**用户或编程常见的使用错误：**

* **忘记 `pthread_join()` 或 `pthread_detach()`：**  如果一个线程被创建但既没有被 `pthread_join()` 等待，也没有被 `pthread_detach()` 分离，那么该线程的资源将无法被回收，导致内存泄漏。
* **多次 `pthread_join()` 同一个线程：**  这会导致未定义的行为，可能导致崩溃。
* **在线程退出后访问其局部变量或资源：**  线程退出后，其栈空间和资源可能被回收或重用，访问这些资源会导致未定义的行为。
* **死锁：**  当多个线程互相等待对方释放资源时，就会发生死锁。这通常涉及到不正确的锁使用顺序或条件变量使用方式。
* **竞争条件：**  当多个线程并发访问共享资源，并且最终结果取决于线程执行的顺序时，就会发生竞争条件。这通常需要使用同步原语来保护共享资源。

**Android Framework 或 NDK 如何一步步到达这里：**

1. **Android Framework (Java层)：**  例如，`AsyncTask` 或 `HandlerThread` 等类最终会调用 NDK 中的 `pthread` 相关函数。
2. **NDK (C/C++层)：**  开发者使用 NDK 提供的 `pthread` API（例如 `<pthread.h>`）。
3. **Bionic libc：** NDK 的 `pthread` 函数调用会链接到 Bionic libc 中的实现。例如，`pthread_create()` 的 NDK 调用最终会调用 Bionic libc 中的 `pthread_create()` 实现。
4. **`pthread_internal.handroid`：**  Bionic libc 的 `pthread_create()` 实现会使用 `pthread_internal_t` 结构体来表示新创建的线程，并调用此头文件中声明的内部函数（如 `__allocate_thread_mapping()`, `__init_thread()`, `__pthread_internal_add()`）来管理线程的创建过程。

**Frida Hook 示例调试步骤：**

假设我们要观察 `pthread_create` 的调用以及新创建线程的 `start_routine`。

**Frida Script:**

```javascript
if (Process.arch === 'arm64' || Process.arch === 'arm') {
  const pthread_create = Module.findExportByName("libc.so", "pthread_create");
  if (pthread_create) {
    Interceptor.attach(pthread_create, {
      onEnter: function (args) {
        console.log("[pthread_create] Thread creating...");
        this.threadPtr = args[0];
        this.attr = args[1];
        this.start_routine = args[2];
        this.arg = args[3];
        console.log("\tThread pointer:", this.threadPtr);
        console.log("\tAttributes:", this.attr);
        console.log("\tStart routine:", this.start_routine);
        console.log("\tArgument:", this.arg);
      },
      onLeave: function (retval) {
        console.log("[pthread_create] Thread created with result:", retval);
        if (retval.toInt() === 0 && this.threadPtr.isNull() === false) {
          // Hook the start routine of the newly created thread
          Interceptor.attach(this.start_routine, {
            onEnter: function (args) {
              console.log("[Start Routine] Entered start routine of new thread");
              console.log("\tArgument to start routine:", args[0]);
            },
            onLeave: function (retval) {
              console.log("[Start Routine] Exited start routine of new thread, returned:", retval);
            }
          });
        }
      }
    });
  } else {
    console.error("pthread_create not found!");
  }
} else {
  console.log("This script is designed for ARM/ARM64 architectures.");
}
```

**调试步骤：**

1. **准备环境：** 确保已安装 Frida 和目标 Android 设备或模拟器已安装 Frida Server。
2. **运行目标应用：** 启动你想要调试的 Android 应用。
3. **执行 Frida 命令：**  使用 Frida 连接到目标应用并加载脚本：
   ```bash
   frida -U -f <your_package_name> -l your_frida_script.js --no-pause
   ```
   将 `<your_package_name>` 替换为目标应用的包名，`your_frida_script.js` 替换为你的 Frida 脚本文件名。
4. **观察输出：** 当应用创建新线程时，Frida 脚本会在控制台上打印出 `pthread_create` 的参数（线程指针、属性、启动函数、参数）以及启动函数的调用信息。

这个 Frida 脚本提供了一个基本的例子，你可以根据需要 hook 其他 `pthread` 相关函数或修改脚本以检查 `pthread_internal_t` 结构体的成员。例如，你可以通过计算 `args[0]` 指向的内存地址并读取其中的内容来查看新创建线程的 `pthread_internal_t` 结构体的各个字段的值。

总结来说，`pthread_internal.handroid` 是 Bionic libc 中线程管理的核心头文件，它定义了线程的内部表示和相关的管理函数声明，为 `pthread` 标准 API 的实现提供了基础。理解这个文件的内容对于深入理解 Android 的线程机制至关重要。

### 提示词
```
这是目录为bionic/libc/bionic/pthread_internal.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#pragma once

#include <pthread.h>
#include <stdatomic.h>

#if __has_feature(hwaddress_sanitizer)
#include <sanitizer/hwasan_interface.h>
#else
#define __hwasan_thread_enter()
#define __hwasan_thread_exit()
#endif

#include "platform/bionic/page.h"

#include "private/bionic_elf_tls.h"
#include "private/bionic_lock.h"
#include "private/bionic_tls.h"

// Has the thread been detached by a pthread_join or pthread_detach call?
#define PTHREAD_ATTR_FLAG_DETACHED 0x00000001

// Has the thread been joined by another thread?
#define PTHREAD_ATTR_FLAG_JOINED 0x00000002

// Used for pthread_attr_setinheritsched. We need two flags for this apparent
// boolean because our historical behavior matches neither of the POSIX choices.
#define PTHREAD_ATTR_FLAG_INHERIT 0x00000004
#define PTHREAD_ATTR_FLAG_EXPLICIT 0x00000008

enum ThreadJoinState {
  THREAD_NOT_JOINED,
  THREAD_EXITED_NOT_JOINED,
  THREAD_JOINED,
  THREAD_DETACHED
};

class thread_local_dtor;

class pthread_internal_t {
 public:
  class pthread_internal_t* next;
  class pthread_internal_t* prev;

  pid_t tid;

 private:
  uint32_t cached_pid_ : 31;
  uint32_t vforked_ : 1;

 public:
  bool is_vforked() { return vforked_; }

  pid_t invalidate_cached_pid() {
    pid_t old_value;
    get_cached_pid(&old_value);
    set_cached_pid(0);
    return old_value;
  }

  void set_cached_pid(pid_t value) {
    cached_pid_ = value;
  }

  bool get_cached_pid(pid_t* cached_pid) {
    *cached_pid = cached_pid_;
    return (*cached_pid != 0);
  }

  pthread_attr_t attr;

  _Atomic(ThreadJoinState) join_state;

  __pthread_cleanup_t* cleanup_stack;

  void* (*start_routine)(void*);
  void* start_routine_arg;
  void* return_value;
  sigset64_t start_mask;

  void* alternate_signal_stack;

  // The start address of the shadow call stack's guard region (arm64/riscv64).
  // This region is SCS_GUARD_REGION_SIZE bytes large, but only SCS_SIZE bytes
  // are actually used.
  //
  // This address is only used to deallocate the shadow call stack on thread
  // exit; the address of the stack itself is stored only in the register used
  // as the shadow stack pointer (x18 on arm64, gp on riscv64).
  //
  // Because the protection offered by SCS relies on the secrecy of the stack
  // address, storing the address here weakens the protection, but only
  // slightly, because it is relatively easy for an attacker to discover the
  // address of the guard region anyway (e.g. it can be discovered by reference
  // to other allocations), but not the stack itself, which is <0.1% of the size
  // of the guard region.
  //
  // longjmp()/setjmp() don't store all the bits of the shadow stack pointer,
  // only the bottom bits covered by SCS_MASK. Since longjmp()/setjmp() between
  // different threads is undefined behavior (and unsupported on Android), we
  // can retrieve the high bits of the shadow stack pointer from the current
  // value in the register --- all the jmp_buf needs to store is where exactly
  // the shadow stack pointer is *within* the thread's shadow stack: the bottom
  // bits of the register.
  //
  // There are at least two other options for discovering the start address of
  // the guard region on thread exit, but they are not as simple as storing in
  // TLS.
  //
  // 1) Derive it from the current value of the shadow stack pointer. This is
  //    only possible in processes that do not contain legacy code that might
  //    clobber x18 on arm64, therefore each process must declare early during
  //    process startup whether it might load legacy code.
  //    TODO: riscv64 has no legacy code, so we can actually go this route
  //    there, but hopefully we'll actually get the Zisslpcfi extension instead.
  // 2) Mark the guard region as such using prctl(PR_SET_VMA_ANON_NAME) and
  //    discover its address by reading /proc/self/maps. One issue with this is
  //    that reading /proc/self/maps can race with allocations, so we may need
  //    code to handle retries.
  void* shadow_call_stack_guard_region;

  // A pointer to the top of the stack. This lets android_unsafe_frame_pointer_chase determine the
  // top of the stack quickly, which would otherwise require special logic for the main thread.
  uintptr_t stack_top;

  // Whether the thread is in the process of terminating (has blocked signals), or has already
  // terminated. This is used by android_run_on_all_threads() to avoid sending a signal to a thread
  // that will never receive it.
  _Atomic(bool) terminating;

  Lock startup_handshake_lock;

  void* mmap_base;
  size_t mmap_size;

  // The location of the VMA to label as the thread's stack_and_tls.
  void* mmap_base_unguarded;
  size_t mmap_size_unguarded;
  char vma_name_buffer[32];

  thread_local_dtor* thread_local_dtors;

  /*
   * The dynamic linker implements dlerror(3), which makes it hard for us to implement this
   * per-thread buffer by simply using malloc(3) and free(3).
   */
  char* current_dlerror;
#define __BIONIC_DLERROR_BUFFER_SIZE 512
  char dlerror_buffer[__BIONIC_DLERROR_BUFFER_SIZE];

  bionic_tls* bionic_tls;

  int errno_value;

  bionic_tcb* bionic_tcb;
  char stack_mte_ringbuffer_vma_name_buffer[32];
  bool should_allocate_stack_mte_ringbuffer;

  bool is_main() { return start_routine == nullptr; }
};

struct ThreadMapping {
  char* mmap_base;
  size_t mmap_size;
  char* mmap_base_unguarded;
  size_t mmap_size_unguarded;

  char* static_tls;
  char* stack_base;
  char* stack_top;
};

__LIBC_HIDDEN__ void __init_tcb(bionic_tcb* tcb, pthread_internal_t* thread);
__LIBC_HIDDEN__ void __init_tcb_stack_guard(bionic_tcb* tcb);
__LIBC_HIDDEN__ void __init_tcb_dtv(bionic_tcb* tcb);
__LIBC_HIDDEN__ void __init_bionic_tls_ptrs(bionic_tcb* tcb, bionic_tls* tls);
__LIBC_HIDDEN__ bionic_tls* __allocate_temp_bionic_tls();
__LIBC_HIDDEN__ void __free_temp_bionic_tls(bionic_tls* tls);
__LIBC_HIDDEN__ void __init_additional_stacks(pthread_internal_t*);
__LIBC_HIDDEN__ int __init_thread(pthread_internal_t* thread);
__LIBC_HIDDEN__ ThreadMapping __allocate_thread_mapping(size_t stack_size, size_t stack_guard_size);
__LIBC_HIDDEN__ void __set_stack_and_tls_vma_name(bool is_main_thread);

__LIBC_HIDDEN__ pthread_t __pthread_internal_add(pthread_internal_t* thread);
__LIBC_HIDDEN__ pthread_internal_t* __pthread_internal_find(pthread_t pthread_id, const char* caller);
__LIBC_HIDDEN__ pid_t __pthread_internal_gettid(pthread_t pthread_id, const char* caller);
__LIBC_HIDDEN__ void __pthread_internal_remove(pthread_internal_t* thread);
__LIBC_HIDDEN__ void __pthread_internal_remove_and_free(pthread_internal_t* thread);
__LIBC_HIDDEN__ void __find_main_stack_limits(uintptr_t* low, uintptr_t* high);
#if defined(__aarch64__)
__LIBC_HIDDEN__ void* __allocate_stack_mte_ringbuffer(size_t n, pthread_internal_t* thread);
#endif

static inline __always_inline bionic_tcb* __get_bionic_tcb() {
  return reinterpret_cast<bionic_tcb*>(&__get_tls()[MIN_TLS_SLOT]);
}

// Make __get_thread() inlined for performance reason. See http://b/19825434.
static inline __always_inline pthread_internal_t* __get_thread() {
  return static_cast<pthread_internal_t*>(__get_tls()[TLS_SLOT_THREAD_ID]);
}

static inline __always_inline bionic_tls& __get_bionic_tls() {
  return *static_cast<bionic_tls*>(__get_tls()[TLS_SLOT_BIONIC_TLS]);
}

static inline __always_inline TlsDtv* __get_tcb_dtv(bionic_tcb* tcb) {
  uintptr_t dtv_slot = reinterpret_cast<uintptr_t>(tcb->tls_slot(TLS_SLOT_DTV));
  return reinterpret_cast<TlsDtv*>(dtv_slot - offsetof(TlsDtv, generation));
}

static inline void __set_tcb_dtv(bionic_tcb* tcb, TlsDtv* val) {
  tcb->tls_slot(TLS_SLOT_DTV) = &val->generation;
}

extern "C" __LIBC_HIDDEN__ int __set_tls(void* ptr);

__LIBC_HIDDEN__ void pthread_key_clean_all(void);

// Address space is precious on LP32, so use the minimum unit: one page.
// On LP64, we could use more but there's no obvious advantage to doing
// so, and the various media processes use RLIMIT_AS as a way to limit
// the amount of allocation they'll do.
#define PTHREAD_GUARD_SIZE max_android_page_size()

// SIGSTKSZ (8KiB) is not big enough.
// An snprintf to a stack buffer of size PATH_MAX consumes ~7KiB of stack.
// On 64-bit, logging uses more than 8KiB by itself, ucontext is comically
// large on aarch64, and we have effectively infinite address space, so double
// the signal stack size.
#if defined(__LP64__)
#define SIGNAL_STACK_SIZE_WITHOUT_GUARD (32 * 1024)
#else
#define SIGNAL_STACK_SIZE_WITHOUT_GUARD (16 * 1024)
#endif

// Traditionally we gave threads a 1MiB stack. When we started
// allocating per-thread alternate signal stacks to ease debugging of
// stack overflows, we subtracted the same amount we were using there
// from the default thread stack size. This should keep memory usage
// roughly constant.
#define PTHREAD_STACK_SIZE_DEFAULT ((1 * 1024 * 1024) - SIGNAL_STACK_SIZE_WITHOUT_GUARD)

// Leave room for a guard page in the internally created signal stacks.
#define SIGNAL_STACK_SIZE (SIGNAL_STACK_SIZE_WITHOUT_GUARD + PTHREAD_GUARD_SIZE)

// Needed by fork.
__LIBC_HIDDEN__ extern void __bionic_atfork_run_prepare();
__LIBC_HIDDEN__ extern void __bionic_atfork_run_child();
__LIBC_HIDDEN__ extern void __bionic_atfork_run_parent();

// Re-map all threads and successively launched threads with PROT_MTE. Returns 'true' if remapping
// took place, 'false' on error or if the stacks were already remapped in the past.
__LIBC_HIDDEN__ bool __pthread_internal_remap_stack_with_mte();

extern "C" bool android_run_on_all_threads(bool (*func)(void*), void* arg);

extern pthread_rwlock_t g_thread_creation_lock;
```