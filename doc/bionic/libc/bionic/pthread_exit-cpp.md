Response:
Let's break down the thought process for analyzing the `pthread_exit.cpp` file.

**1. Understanding the Request:**

The request asks for a detailed explanation of the `pthread_exit` function, its role in Android, its interaction with other components (libc, dynamic linker, framework, NDK), and common errors. It also requests a Frida hook example. The core file provided is the source code of `pthread_exit`.

**2. Initial Code Scan and High-Level Understanding:**

First, I'd quickly scan the code to get a general idea of what's happening. Keywords like `cleanup_stack`, `tls`, `sigaltstack`, `munmap`, `atomic_compare_exchange_weak`, `_exit_with_stack_teardown`, and `__exit` jump out. This suggests the function handles thread-local storage, cleanup routines, signal stacks, memory management, and ultimately thread termination.

**3. Functionality Breakdown (Line by Line or Block by Block):**

Next, I'd go through the code more systematically, commenting on the purpose of each significant block of code:

* **Cleanup Handlers:** The `__pthread_cleanup_push` and `__pthread_cleanup_pop` functions clearly manage a stack of cleanup routines. This is a standard pthread mechanism.
* **`pthread_exit` Entry:** The main `pthread_exit` function starts by calling `__cxa_thread_finalize()`, indicating C++ destructor handling.
* **Storing Return Value:** The `return_value` is stored in the thread's internal structure.
* **Executing Cleanup Handlers:** The `while` loop iterates through and executes the cleanup handlers in reverse order of registration.
* **TLS Destructors:** `pthread_key_clean_all()` handles the destruction of thread-local storage variables.
* **Alternate Signal Stack:**  The code checks for and disables/unmaps an alternate signal stack if it exists.
* **Thread Join State:**  The `atomic_compare_exchange_weak` operation manipulates the thread's join state, indicating it's exiting. This is crucial for `pthread_join`.
* **Signal Blocking:**  Signals are blocked to ensure atomicity of certain operations before unmapping memory.
* **Shadow Call Stack (AArch64/RISC-V):**  If applicable, the shadow call stack is unmapped. This is a security feature.
* **Dynamic TLS:** `__free_dynamic_tls` releases dynamically allocated thread-local storage.
* **Detached Thread Handling:**  The code differentiates between detached and joinable threads. For detached threads, memory is freed immediately.
* **Exit Callbacks:** `__notify_thread_exit_callbacks()` allows for post-exit actions.
* **HWASAN:** `__hwasan_thread_exit()` handles Hardware Address Sanitizer cleanup.
* **Stack MTE (AArch64):**  Stack memory tagging is handled.
* **Final Exit:**  Depending on whether the thread was detached, either `_exit_with_stack_teardown` (for detached) or `__exit` (for joinable) is called.

**4. Connecting to Android Features:**

At this stage, I'd think about how these actions relate to Android's functionality:

* **Bionic as the C Library:** Emphasize that this *is* the core implementation of thread management in Android's C library.
* **NDK Usage:**  NDK developers directly use `pthread_exit`.
* **Android Framework:** The Android framework uses threads extensively, and indirectly relies on this implementation. Examples include Binder threads, UI threads, and worker threads.
* **Dynamic Linker:** The dynamic linker is involved in loading libraries and resolving symbols, including thread-local storage. The `__cxa_thread_finalize()` function is related to C++ object destruction during thread exit, which the dynamic linker helps manage.

**5. Explaining Libc Functions:**

For each of the internal libc functions called within `pthread_exit`, I would provide a brief explanation of their purpose:

* `__cxa_thread_finalize()`: C++ thread-local object destructor.
* `__get_thread()`: Accesses the thread-local storage for the current thread's metadata.
* `pthread_key_clean_all()`: Iterates through TLS keys and calls destructor functions.
* `sigaltstack()`: Manages alternate signal stacks.
* `munmap()`: Unmaps memory regions.
* `atomic_compare_exchange_weak()`: Atomically compares and swaps memory.
* `sigprocmask()`:  Manages signal blocking.
* `__free_dynamic_tls()`: Frees dynamic TLS.
* `_exit_with_stack_teardown()`:  Terminates the process and cleans up the stack (used for detached threads).
* `__exit()`:  Low-level system call for process termination.
* `__set_tid_address()`:  Sets the thread ID address (related to `gettid()`).
* `__pthread_internal_remove()`: Removes the thread from the global thread list.
* `__notify_thread_exit_callbacks()`: Invokes registered exit callbacks.
* `__hwasan_thread_exit()`: Handles HWASAN cleanup.
* `stack_mte_free_ringbuffer()`: Frees memory tagging structures.

**6. Dynamic Linker Interaction:**

This requires understanding how shared libraries and thread-local storage are handled.

* **SO Layout Sample:**  Illustrate the basic layout of a shared object with code, data, and `.tbss` (thread-local storage) sections.
* **Linking Process:** Explain how the dynamic linker resolves TLS access by setting up the `TLS` segment and using offsets. Mention the role of `DT_TLS` entries in the ELF.

**7. Logic and Assumptions:**

For logical reasoning, I'd consider scenarios and their expected outcomes:

* **Cleanup Handlers:**  Assume a thread pushes two cleanup handlers. The output should show they are executed in reverse order.
* **Return Value:** Assume `pthread_exit` is called with a specific return value. `pthread_join` should retrieve this value.

**8. Common Usage Errors:**

Think about common mistakes developers make when using threads:

* **Forgetting to Detach or Join:** Leading to resource leaks.
* **Accessing Freed Memory:** If a detached thread's memory is accessed after it exits.
* **Incorrect Cleanup Handler Logic:** If cleanup handlers don't properly release resources.

**9. Android Framework/NDK Path and Frida Hook:**

Trace the execution flow from a high level:

* **Framework:** An activity starts a background thread (e.g., using `AsyncTask` or `Thread`).
* **NDK:** Native code creates a thread using `pthread_create`.
* **`pthread_exit`:** When the thread's function returns (implicitly or explicitly via `pthread_exit`), this function is called.

For the Frida hook, focus on intercepting the `pthread_exit` function and logging arguments or manipulating behavior.

**10. Structuring the Response:**

Finally, organize the information clearly using headings, bullet points, and code examples. Ensure that the language is clear and precise. Use technical terms correctly but also explain them where necessary. The goal is to provide a comprehensive and understandable explanation of the `pthread_exit` function and its role within the Android ecosystem.
好的，让我们详细分析一下 `bionic/libc/bionic/pthread_exit.cpp` 这个文件。

**功能概述:**

`pthread_exit` 函数是 POSIX 线程标准中用于终止当前线程执行的函数。在 Android 的 Bionic 库中，它的实现负责执行一系列清理工作，确保线程安全且资源得到妥善释放。其主要功能包括：

1. **调用 C++ 线程局部对象的析构函数:** 确保线程特定的 C++ 对象的析构函数被正确调用。
2. **存储线程的返回值:** 将传递给 `pthread_exit` 的 `return_value` 存储起来，以便等待该线程结束的 `pthread_join` 函数可以获取它。
3. **执行清理处理程序 (Cleanup Handlers):**  执行通过 `pthread_cleanup_push` 注册的清理函数。这些函数通常用于释放在线程退出前需要释放的资源（例如，解锁互斥锁、关闭文件描述符）。
4. **调用线程局部存储 (TLS) 的析构函数:**  清理线程特定的数据。
5. **禁用并释放备用信号栈 (Alternate Signal Stack):** 如果线程使用了备用信号栈，则禁用并释放它。
6. **更新线程的 Join 状态:**  标记线程已经退出，并更新其状态，以便 `pthread_join` 可以正确处理。
7. **处理 Detached 线程:** 对于设置为 detached 状态的线程，负责释放其占用的内存，包括栈空间和 `pthread_internal_t` 结构。
8. **通知线程退出回调:** 调用注册的线程退出回调函数。
9. **HWASAN (Hardware Address Sanitizer) 清理:** 如果启用了 HWASAN，则进行相关的清理工作。
10. **Stack MTE (Memory Tagging Extension) 清理 (AArch64):** 如果启用了 MTE，则清理相关的环形缓冲区。
11. **最终退出:** 调用底层的 `_exit_with_stack_teardown` 或 `__exit` 函数来真正结束线程的执行。

**与 Android 功能的关系和举例:**

`pthread_exit` 是 Android 线程管理的基础组成部分，几乎所有使用多线程的 Android 功能都间接地依赖于它。

* **Android Framework 的多线程:**  Android Framework 中存在大量的后台线程，例如处理网络请求、执行异步任务、处理 Binder 调用等。当这些线程执行完毕或者需要提前结束时，最终都会调用 `pthread_exit`。例如，一个 `AsyncTask` 完成其后台任务后，其内部的工作线程就会调用 `pthread_exit`。
* **NDK 开发:**  NDK 开发者在编写本地代码时，如果使用了 POSIX 线程 API (`pthread_create`, `pthread_join`, `pthread_exit` 等)，则直接使用 Bionic 库提供的 `pthread_exit` 实现。例如，一个游戏引擎可能会创建多个线程来处理渲染、物理模拟和音频，当这些线程的任务完成时，会调用 `pthread_exit`。
* **Binder 线程:** Android 的进程间通信机制 Binder 也使用了线程。当一个 Binder 线程处理完一个请求后，它可能会调用 `pthread_exit` 来结束自己的生命周期（或者进入等待新的请求的状态）。

**libc 函数的实现细节:**

让我们逐一解释 `pthread_exit` 中调用的其他 libc 函数：

1. **`__cxa_thread_finalize()`:**
   - **功能:**  这个函数负责调用当前线程中注册的 C++ 线程局部存储 (Thread-Local Storage, TLS) 对象的析构函数。
   - **实现:** 它会遍历当前线程的 TLS 数据结构，找到所有已注册的析构函数，并按照注册的顺序逆序调用它们。这确保了在线程退出时，所有线程特定的 C++ 对象都能被正确清理。

2. **`__get_thread()`:**
   - **功能:**  这是一个 Bionic 内部函数，用于获取当前线程的 `pthread_internal_t` 结构体的指针。
   - **实现:**  通常通过访问一个特殊的寄存器或者内存地址来实现，这个地址存储了当前线程的 `pthread_internal_t` 结构体的指针。这个结构体包含了线程的各种内部信息，例如 TLS 数据、清理处理程序栈、返回值等。

3. **`__pthread_cleanup_push(__pthread_cleanup_t* c, __pthread_cleanup_func_t routine, void* arg)` 和 `__pthread_cleanup_pop(__pthread_cleanup_t* c, int execute)`:**
   - **功能:** 这两个函数实现了线程清理处理程序的栈式管理。`__pthread_cleanup_push` 将一个清理处理程序（由 `routine` 函数指针和 `arg` 参数组成）压入当前线程的清理栈中。`__pthread_cleanup_pop` 将栈顶的清理处理程序弹出，如果 `execute` 参数为非零值，则执行该清理处理程序。
   - **实现:**  `__pthread_cleanup_push` 获取当前线程的 `pthread_internal_t` 结构体，将新的清理处理程序信息添加到 `cleanup_stack` 链表的头部。`__pthread_cleanup_pop` 则从链表头部移除一个元素，并根据 `execute` 参数决定是否调用清理函数。

4. **`pthread_key_clean_all()`:**
   - **功能:**  负责调用当前线程所有已注册的线程局部存储 (TLS) 键的析构函数。
   - **实现:** 它会遍历所有已创建的 TLS 键，并检查当前线程是否为该键关联了值。如果关联了值，并且该键注册了析构函数，则调用该析构函数。

5. **`sigaltstack(const stack_t* ss, stack_t* old_ss)`:**
   - **功能:**  用于设置或获取线程的备用信号栈。备用信号栈用于处理某些信号，例如栈溢出信号 (`SIGSEGV`)。
   - **实现:**  这是一个系统调用，直接与内核交互。当 `pthread_exit` 调用 `sigaltstack` 并传入 `SS_DISABLE` 标志时，它告诉内核停止使用该线程的备用信号栈。

6. **`munmap(void* addr, size_t len)`:**
   - **功能:**  用于解除进程地址空间中指定区域的映射。
   - **实现:**  这是一个系统调用，通知内核解除从地址 `addr` 开始，长度为 `len` 的内存映射。在 `pthread_exit` 中，它用于释放备用信号栈占用的内存。

7. **`atomic_compare_exchange_weak(&thread->join_state, &old_state, THREAD_EXITED_NOT_JOINED)`:**
   - **功能:**  这是一个原子操作，用于尝试将 `thread->join_state` 的值从 `old_state` 修改为 `THREAD_EXITED_NOT_JOINED`。如果当前值不是 `old_state`，则操作失败。
   - **实现:**  通常使用 CPU 提供的原子指令来实现，例如 compare-and-swap (CAS)。这确保了在多线程环境下，对 `join_state` 的修改是线程安全的。

8. **`sigfillset64(&set)` 和 `__rt_sigprocmask(SIG_BLOCK, &set, nullptr, sizeof(sigset64_t))`:**
   - **功能:** 用于阻塞所有信号。
   - **实现:** `sigfillset64` 将信号集 `set` 中的所有信号都置为有效状态。`__rt_sigprocmask` 是一个系统调用，用于修改线程的信号屏蔽字。`SIG_BLOCK` 操作表示将指定的信号添加到当前线程的信号屏蔽字中，从而阻塞这些信号的传递。

9. **`__free_dynamic_tls(__get_bionic_tcb())`:**
   - **功能:**  释放动态分配的线程局部存储 (TLS)。
   - **实现:**  Bionic 维护了一个线程控制块 (Thread Control Block, TCB)，`__get_bionic_tcb()` 返回当前线程的 TCB 指针。`__free_dynamic_tls` 函数会检查 TCB 中是否有动态分配的 TLS 区域，如果有，则调用 `munmap` 解除映射并释放。

10. **`_exit_with_stack_teardown(void* mmap_base, size_t mmap_size)`:**
    - **功能:**  这是一个 Bionic 特有的函数，用于在线程是 detached 状态时，安全地终止线程并释放其栈空间。
    - **实现:**  由于 detached 线程不会被 `pthread_join`，因此需要在线程退出时主动释放其占用的内存。这个函数会执行必要的清理操作，并最终调用底层的 `__exit` 系统调用。它特别处理了栈内存的释放。

11. **`__exit(int status)`:**
    - **功能:**  这是一个底层的系统调用，用于终止当前进程。
    - **实现:**  内核会接收到这个系统调用，并执行进程终止的必要步骤，包括关闭所有文件描述符、释放进程占用的资源等。虽然 `pthread_exit` 是终止线程，但对于 detached 线程或主线程的退出，最终可能会涉及到进程的终止。

12. **`__set_tid_address(int*)`:**
    - **功能:**  设置一个用户空间的地址，当线程退出时，内核会将 0 写入该地址。这通常用于在多线程程序中检测线程退出。
    - **实现:**  这是一个系统调用。在 `pthread_exit` 中，当一个 detached 线程即将释放其内存时，会调用 `__set_tid_address(nullptr)`，防止内核尝试写入已释放的内存。

13. **`__pthread_internal_remove(pthread_internal_t* thread)`:**
    - **功能:**  将指定的 `pthread_internal_t` 结构体从全局的线程列表中移除。
    - **实现:**  Bionic 维护着一个全局的线程列表。这个函数会获取一个全局锁，然后从列表中移除指定的线程结构体。

14. **`__notify_thread_exit_callbacks()`:**
    - **功能:**  调用所有已注册的线程退出回调函数。
    - **实现:**  Bionic 允许程序注册一些回调函数，在线程退出时执行一些额外的操作。这个函数会遍历已注册的回调列表并逐个调用它们。

15. **`__hwasan_thread_exit()`:**
    - **功能:**  如果启用了 Hardware Address Sanitizer (HWASAN)，这个函数会执行线程退出时必要的清理工作，例如释放 HWASAN 相关的元数据。
    - **实现:**  这部分代码与 HWASAN 的具体实现有关，可能包括释放内存、更新 HWASAN 的内部状态等。

16. **`stack_mte_free_ringbuffer(reinterpret_cast<uintptr_t>(stack_mte_tls))`:**
    - **功能:**  如果启用了 Memory Tagging Extension (MTE)，这个函数会释放与线程栈相关的 MTE 环形缓冲区。
    - **实现:**  MTE 是一种硬件安全特性，用于检测内存安全错误。这个函数负责清理线程退出时使用的 MTE 相关资源。

**涉及 Dynamic Linker 的功能:**

`pthread_exit` 与 Dynamic Linker 的主要关联在于对 C++ 线程局部对象析构函数的处理，通过 `__cxa_thread_finalize()` 实现。

**SO 布局样本:**

假设我们有一个共享库 `libexample.so`，它定义了一些线程局部变量：

```c++
// libexample.cpp
#include <pthread.h>

thread_local int tls_variable = 10;

void some_function() {
  // 使用 tls_variable
}
```

编译后的 `libexample.so` 的布局可能如下 (简化表示)：

```
ELF Header
Program Headers:
  LOAD ... // 代码段
  LOAD ... // 数据段
  TLS  ... // TLS 段 (.tbss, .tdata)
...
Section Headers:
  .text  // 代码
  .data  // 已初始化的全局数据
  .bss   // 未初始化的全局数据
  .tbss  // 未初始化的线程局部存储
  .tdata // 已初始化的线程局部存储
  .ctors // 全局构造函数表
  .dtors // 全局析构函数表
  .init_array // 初始化函数数组
  .fini_array // 终止函数数组
  ...
Dynamic Section:
  ...
  DT_TLS     ... // 指向 TLS 模板的指针
  DT_TLSSZ   ... // TLS 模板的大小
  DT_PREINIT_ARRAY     ... // 预初始化函数数组
  DT_PREFINI_ARRAY     ... // 预终止函数数组
  ...
```

**链接的处理过程:**

1. **加载时:** 当程序加载 `libexample.so` 时，Dynamic Linker 会解析其 ELF 文件头和 Program Headers，找到 TLS 段的信息 (`TLS` Program Header)。
2. **TLS 初始化:** 对于每个创建的线程，Dynamic Linker 会根据 `libexample.so` 的 TLS 模板 (`.tbss` 和 `.tdata` 段) 分配一块内存，作为该线程的 TLS 存储空间。
3. **TLS 访问:** 当线程访问 `tls_variable` 时，编译器会生成特殊的指令，利用 TLS 寄存器 (例如，在 x86-64 架构上是 `FS` 或 `GS` 寄存器) 和偏移量来访问线程自己的 TLS 存储空间。
4. **线程退出:** 当线程调用 `pthread_exit` 时，`__cxa_thread_finalize()` 会被调用。这个函数会查找该线程加载的所有共享库的 `.fini_array` 或 `.dtors` 段中注册的线程局部对象的析构函数。
5. **调用析构函数:** Dynamic Linker 会确保这些析构函数被正确调用，清理线程局部对象占用的资源。

**逻辑推理、假设输入与输出:**

假设一个线程通过 `pthread_cleanup_push` 注册了两个清理处理程序，分别用于解锁互斥锁 `mutex1` 和 `mutex2`。

**假设输入:**

```c++
pthread_mutex_t mutex1, mutex2;

void cleanup1(void* arg) {
  pthread_mutex_unlock((pthread_mutex_t*)arg);
  printf("Cleanup 1 called\n");
}

void cleanup2(void* arg) {
  pthread_mutex_unlock((pthread_mutex_t*)arg);
  printf("Cleanup 2 called\n");
}

void* thread_func(void*) {
  pthread_mutex_lock(&mutex1);
  pthread_cleanup_push(cleanup1, &mutex1);

  pthread_mutex_lock(&mutex2);
  pthread_cleanup_push(cleanup2, &mutex2);

  printf("Thread doing some work...\n");

  pthread_cleanup_pop(1); // 执行 cleanup2
  pthread_cleanup_pop(1); // 执行 cleanup1

  pthread_exit(nullptr);
  return nullptr;
}
```

**预期输出:**

```
Thread doing some work...
Cleanup 2 called
Cleanup 1 called
```

**解释:**  `pthread_exit` 会按照 LIFO (后进先出) 的顺序执行清理处理程序栈中的函数。因此，`cleanup2` 会先于 `cleanup1` 被调用。

**用户或编程常见的使用错误:**

1. **忘记 `pthread_detach` 或 `pthread_join`:** 如果创建的线程既没有被设置为 detached 状态，也没有被其他线程 `join`，则该线程的资源可能无法被回收，导致资源泄漏。
2. **在 detached 线程退出后访问其内存:**  detached 线程的栈空间和其他资源会在其 `pthread_exit` 调用后被立即释放。如果其他线程仍然持有指向该线程栈的指针并尝试访问，则会导致未定义行为，通常是崩溃。
3. **清理处理程序中的错误:** 清理处理程序如果本身存在错误（例如，尝试解锁一个未锁定的互斥锁），可能会导致程序崩溃或其他不可预测的行为。
4. **与 `return` 语句混淆:**  在线程函数中使用 `return` 语句与调用 `pthread_exit` 效果不同。`return` 会执行局部变量的析构函数，但不会执行通过 `pthread_cleanup_push` 注册的清理处理程序。只有 `pthread_exit` 才会执行完整的线程退出流程。

**Android Framework 或 NDK 如何到达 `pthread_exit`，以及 Frida Hook 示例:**

**路径：**

1. **Android Framework:**
   - `Activity` 或其他组件可能会创建一个 `Thread` 对象或使用 `AsyncTask`。
   - `AsyncTask` 内部会创建一个后台线程来执行 `doInBackground` 方法。
   - 当线程的 `run` 方法执行完毕或 `AsyncTask` 的后台任务完成时，线程会自然退出，或者显式调用 `pthread_exit` (虽然不常见)。

2. **NDK:**
   - NDK 开发者可以使用 `pthread_create` 创建新的线程。
   - 当线程执行完其入口函数或者调用 `pthread_exit` 时，会进入 `pthread_exit` 的 Bionic 实现。

**Frida Hook 示例:**

我们可以使用 Frida Hook `pthread_exit` 函数来观察其调用情况和参数。

```javascript
if (Process.platform === 'android') {
  const pthread_exit = Module.findExportByName(null, 'pthread_exit');
  if (pthread_exit) {
    Interceptor.attach(pthread_exit, {
      onEnter: function (args) {
        console.log('[pthread_exit] Thread exiting with return value:', args[0]);
        // 可以进一步分析线程 ID 等信息
        const threadId = Process.getCurrentThreadId();
        console.log('[pthread_exit] Thread ID:', threadId);
      },
      onLeave: function (retval) {
        console.log('[pthread_exit] Exiting...');
      }
    });
  } else {
    console.error('pthread_exit not found.');
  }
}
```

**使用方法:**

1. 确保你的 Android 设备已 root，并且安装了 Frida Server。
2. 将上述 JavaScript 代码保存为 `hook_pthread_exit.js`。
3. 运行你想要分析的 Android 应用。
4. 使用 Frida 命令行工具连接到目标应用：
   ```bash
   frida -U -f <your_package_name> -l hook_pthread_exit.js --no-pause
   ```
   将 `<your_package_name>` 替换为你的应用包名。

**预期输出:**

当应用中的线程退出时，你会在 Frida 控制台中看到类似以下的输出：

```
[pthread_exit] Thread exiting with return value: 0x0
[pthread_exit] Thread ID: 12345
[pthread_exit] Exiting...
```

这将帮助你理解哪些线程正在退出以及它们的返回值是什么。你还可以根据需要在 `onEnter` 和 `onLeave` 中添加更复杂的逻辑来分析线程退出的上下文。

希望这个详尽的解释能够帮助你理解 `pthread_exit.cpp` 的功能和在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/pthread_exit.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <pthread.h>

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#include "platform/bionic/mte.h"
#include "private/ScopedRWLock.h"
#include "private/ScopedSignalBlocker.h"
#include "private/bionic_constants.h"
#include "private/bionic_defs.h"
#include "pthread_internal.h"

extern "C" __noreturn void _exit_with_stack_teardown(void*, size_t);
extern "C" __noreturn void __exit(int);
extern "C" int __set_tid_address(int*);
extern "C" void __cxa_thread_finalize();

/* CAVEAT: our implementation of pthread_cleanup_push/pop doesn't support C++ exceptions
 *         and thread cancelation
 */

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
void __pthread_cleanup_push(__pthread_cleanup_t* c, __pthread_cleanup_func_t routine, void* arg) {
  pthread_internal_t* thread = __get_thread();
  c->__cleanup_routine = routine;
  c->__cleanup_arg = arg;
  c->__cleanup_prev = thread->cleanup_stack;
  thread->cleanup_stack = c;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
void __pthread_cleanup_pop(__pthread_cleanup_t* c, int execute) {
  pthread_internal_t* thread = __get_thread();
  thread->cleanup_stack = c->__cleanup_prev;
  if (execute) {
    c->__cleanup_routine(c->__cleanup_arg);
  }
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
__attribute__((no_sanitize("memtag"))) void pthread_exit(void* return_value) {
  // Call dtors for thread_local objects first.
  __cxa_thread_finalize();

  pthread_internal_t* thread = __get_thread();
  thread->return_value = return_value;

  // Call the cleanup handlers.
  while (thread->cleanup_stack) {
    __pthread_cleanup_t* c = thread->cleanup_stack;
    thread->cleanup_stack = c->__cleanup_prev;
    c->__cleanup_routine(c->__cleanup_arg);
  }

  // Call the TLS destructors. It is important to do that before removing this
  // thread from the global list. This will ensure that if someone else deletes
  // a TLS key, the corresponding value will be set to NULL in this thread's TLS
  // space (see pthread_key_delete).
  pthread_key_clean_all();

  if (thread->alternate_signal_stack != nullptr) {
    // Tell the kernel to stop using the alternate signal stack.
    stack_t ss;
    memset(&ss, 0, sizeof(ss));
    ss.ss_flags = SS_DISABLE;
    sigaltstack(&ss, nullptr);

    // Free it.
    munmap(thread->alternate_signal_stack, SIGNAL_STACK_SIZE);
    thread->alternate_signal_stack = nullptr;
  }

  ThreadJoinState old_state = THREAD_NOT_JOINED;
  while (old_state == THREAD_NOT_JOINED &&
         !atomic_compare_exchange_weak(&thread->join_state, &old_state, THREAD_EXITED_NOT_JOINED)) {
  }

  // android_run_on_all_threads() needs to see signals blocked atomically with setting the
  // terminating flag, so take the creation lock while doing these operations.
  {
    ScopedReadLock locker(&g_thread_creation_lock);
    atomic_store(&thread->terminating, true);

    // We don't want to take a signal after unmapping the stack, the shadow call stack, or dynamic
    // TLS memory.
    sigset64_t set;
    sigfillset64(&set);
    __rt_sigprocmask(SIG_BLOCK, &set, nullptr, sizeof(sigset64_t));
  }

#if defined(__aarch64__) || defined(__riscv)
  // Free the shadow call stack and guard pages.
  munmap(thread->shadow_call_stack_guard_region, SCS_GUARD_REGION_SIZE);
#endif

  __free_dynamic_tls(__get_bionic_tcb());

  if (old_state == THREAD_DETACHED) {
    // The thread is detached, no one will use pthread_internal_t after pthread_exit.
    // So we can free mapped space, which includes pthread_internal_t and thread stack.
    // First make sure that the kernel does not try to clear the tid field
    // because we'll have freed the memory before the thread actually exits.
    __set_tid_address(nullptr);

    // pthread_internal_t is freed below with stack, not here.
    __pthread_internal_remove(thread);
  }

  __notify_thread_exit_callbacks();
  __hwasan_thread_exit();

#if defined(__aarch64__)
  if (void* stack_mte_tls = thread->bionic_tcb->tls_slot(TLS_SLOT_STACK_MTE)) {
    stack_mte_free_ringbuffer(reinterpret_cast<uintptr_t>(stack_mte_tls));
  }
#endif
  // Everything below this line needs to be no_sanitize("memtag").

  if (old_state == THREAD_DETACHED && thread->mmap_size != 0) {
    // We need to free mapped space for detached threads when they exit.
    // That's not something we can do in C.
    _exit_with_stack_teardown(thread->mmap_base, thread->mmap_size);
  }
  // No need to free mapped space. Either there was no space mapped,
  // or it is left for the pthread_join caller to clean up.
  __exit(0);
}

"""

```