Response:
Let's break down the thought process for answering the request about `pthread_create.cpp`.

**1. Understanding the Core Request:**

The request is to analyze the provided C++ source code of `pthread_create.cpp`, specifically focusing on its functionality, relationship to Android, implementation details, dynamic linking aspects, error handling, usage scenarios, and how Android frameworks interact with it. The request also asks for a Frida hook example.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code for key functions and data structures. Keywords like `pthread_create`, `clone`, `mmap`, `munmap`, `pthread_attr_t`, `bionic_tcb`, `bionic_tls`, `dynamic linker`, `TLS`, `stack`, `signals`, and Android-specific log macros (`async_safe_log`) immediately stand out. These give a high-level overview of the code's purpose.

**3. Dissecting the Functionality:**

The name of the file and the main function `pthread_create` are strong indicators of its primary function: creating new threads. Reading the code confirms this. The code involves:

* **Resource Allocation:**  `__allocate_thread_mapping` (memory for stack and TLS), `mmap` (general memory allocation), `munmap` (freeing memory).
* **Thread Initialization:** `__init_thread` (setting scheduling, detach state), `__init_tcb` (initializing Thread Control Block), `__init_bionic_tls_ptrs` (setting TLS pointers), `__init_additional_stacks` (signal and shadow call stacks).
* **Thread Creation (Kernel Level):** `clone` system call – the core of thread creation.
* **Synchronization:** `pthread_rwlock_t` (for thread creation locking), mutexes within the thread structure (`startup_handshake_lock`).
* **TLS Handling:** Allocation and initialization of Thread Local Storage.
* **Signal Handling:** Setting up alternate signal stacks.
* **Shadow Call Stack:** Allocation and setup for security.
* **Error Handling:** Checking return values of system calls and using `async_safe_log`.

**4. Connecting to Android:**

The file is explicitly located within the "bionic" directory, Android's C library. This immediately establishes a strong connection to Android. Specific examples of the connection include:

* **Bionic-Specific Types:** `bionic_tcb`, `bionic_tls`.
* **Android Logging:** `async_safe_log`.
* **Target SDK Version Check:**  The code checks `android_get_application_target_sdk_version()` before potentially resetting PAC keys, showcasing Android version-specific behavior.
* **Memory Tagging Extension (MTE):** Conditional use of `PROT_MTE` and related checks indicate Android's security features.
* **`/proc/pid/maps` Naming:** The use of `prctl(PR_SET_VMA, ...)` to name memory regions, which is relevant for debugging on Android.

**5. Explaining `libc` Functions:**

For each `libc` function identified (e.g., `mmap`, `munmap`, `clone`, `pthread_attr_init`, `memset`, `prctl`, `sigaltstack`, `sigprocmask`, `sched_setscheduler`, `sched_getscheduler`), a concise explanation of its standard functionality is necessary. Focus on the "what" rather than getting bogged down in low-level kernel implementation details (unless specifically requested).

**6. Dynamic Linker Involvement:**

The code allocates a temporary `bionic_tls` for the dynamic linker. This is a key point connecting to the dynamic linking process. The explanation should cover:

* **Purpose of Temporary TLS:** Why the dynamic linker needs this during initialization.
* **SO Layout Sample:**  A simplified example showing how shared libraries (.so files) are loaded into memory.
* **Linking Process:**  A high-level description of how the dynamic linker resolves symbols and relocates code. Avoid going into excessive detail on relocation types unless asked.

**7. Logic and Assumptions:**

The main logic revolves around allocating resources, initializing thread structures, and then using `clone` to create the actual thread. Assumptions include:

* The caller provides valid attributes or `nullptr`.
* System calls like `mmap` and `clone` succeed (the code includes error handling, but the basic logic assumes success).

A simple input/output scenario would be calling `pthread_create` with a function pointer and arguments, resulting in a new thread executing that function.

**8. Common Usage Errors:**

Think about typical mistakes developers make when working with threads:

* **Incorrect Attribute Initialization:** Not initializing `pthread_attr_t` properly.
* **Stack Overflow:**  Allocating too small a stack.
* **Detached Threads and Joining:** Trying to join a detached thread.
* **Race Conditions (Implicit):** While not directly caused by `pthread_create`, it *enables* multithreading, making race conditions a common consequence.

**9. Android Framework/NDK Interaction:**

Trace the path from high-level Android components down to `pthread_create`:

* **Java Layer:** `java.lang.Thread`.
* **Native Layer (Framework):**  JNI calls to native methods.
* **NDK:**  Direct usage of POSIX threads via the NDK.

**10. Frida Hook Example:**

A basic Frida hook should demonstrate intercepting the `pthread_create` function, printing arguments, and potentially modifying behavior (though a simple log is sufficient for this request). Focus on getting the basic syntax correct.

**11. Structuring the Response:**

Organize the information logically using headings and bullet points. Start with the main functionality, then delve into implementation details, Android connections, dynamic linking, errors, and finally the framework/NDK path and Frida example.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus heavily on the `clone` system call details.
* **Correction:**  While `clone` is crucial, the request emphasizes the *functionality* of `pthread_create`. Provide sufficient detail about `clone` but don't get lost in kernel specifics.
* **Initial thought:**  Provide a highly technical and detailed explanation of TLS.
* **Correction:** Simplify the TLS explanation, focusing on its purpose and how bionic initializes it. Avoid overly technical details about ELF TLS structures unless specifically asked.
* **Initial thought:**  Only mention NDK usage.
* **Correction:**  Include the Android framework path via `java.lang.Thread` and JNI, providing a more complete picture.

By following these steps, iterating through the code and the request requirements, and refining the approach, a comprehensive and accurate answer can be constructed. The key is to break down the complex topic into manageable parts and address each aspect systematically.
好的，我们来详细分析 `bionic/libc/bionic/pthread_create.cpp` 文件的功能和实现。

**功能概述**

`pthread_create.cpp` 文件实现了 POSIX 线程创建的核心功能，即 `pthread_create` 函数。它的主要职责是：

1. **创建并初始化新的线程:**  为新线程分配必要的资源，包括栈空间和线程控制块（TCB）。
2. **设置线程属性:**  应用用户指定的线程属性，如栈大小、调度策略、优先级等。
3. **调用 `clone` 系统调用:**  使用 Linux 的 `clone` 系统调用来创建新的执行上下文，从而产生新的线程。
4. **执行新线程的入口函数:**  在新线程中调用用户提供的 `start_routine` 函数。
5. **处理线程创建过程中的错误:**  在资源分配或系统调用失败时返回相应的错误码。
6. **与动态链接器交互:**  为新线程设置线程本地存储 (TLS)，这涉及到动态链接器的管理。
7. **支持 Android 特有的功能:**  例如设置信号栈、影子调用栈、以及可能的 MTE (Memory Tagging Extension) 相关操作。

**与 Android 功能的关系及举例**

`pthread_create` 是 Android 系统中创建并发执行任务的基础。Android 应用程序和系统服务都广泛使用它来实现多线程。

* **Android Framework 中的应用:**  例如，ActivityManagerService (AMS) 等系统服务会创建线程来处理不同的客户端请求，避免阻塞主线程。在 Java 层，`java.lang.Thread` 最终会通过 JNI 调用到 `pthread_create`。
* **NDK 开发中的应用:**  使用 NDK 进行 C/C++ 开发时，开发者可以直接调用 `pthread_create` 来创建原生线程，执行后台计算、网络操作等任务。
* **AsyncTask 和线程池:**  Android 的 `AsyncTask` 和各种线程池机制的底层实现很可能也依赖于 `pthread_create` 来创建工作线程。

**详细解释每个 `libc` 函数的功能是如何实现的**

让我们逐个分析 `pthread_create.cpp` 中使用的一些关键 `libc` 函数：

1. **`pthread_attr_init(pthread_attr_t *attr)`:**
   - **功能:** 初始化线程属性对象 `attr` 为默认值。
   - **实现:**  通常会将 `attr` 结构体的成员设置为预定义好的默认值，例如默认的栈大小、非分离状态等。在 bionic 中，`pthread_attr_t` 是一个结构体，包含各种线程属性的字段。

2. **`pthread_attr_setstacksize(pthread_attr_t *attr, size_t stacksize)`:**
   - **功能:** 设置线程的栈大小。
   - **实现:** 将 `attr` 结构体中的 `stack_size` 字段设置为 `stacksize`。

3. **`pthread_attr_setguardsize(pthread_attr_t *attr, size_t guardsize)`:**
   - **功能:** 设置线程栈的保护区大小，用于检测栈溢出。
   - **实现:** 将 `attr` 结构体中的 `guard_size` 字段设置为 `guardsize`。

4. **`mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)`:**
   - **功能:**  在进程的地址空间中创建一个新的内存映射。
   - **实现:**  这是一个系统调用，由内核完成。内核会分配指定大小的虚拟内存区域，并根据 `flags` 和 `fd` 参数决定是否将其映射到文件或匿名内存。在 `pthread_create.cpp` 中，`mmap` 用于分配线程的栈空间和 TLS 空间（使用 `MAP_PRIVATE | MAP_ANONYMOUS`）。

5. **`munmap(void *addr, size_t length)`:**
   - **功能:**  解除对指定内存区域的映射。
   - **实现:**  也是一个系统调用，由内核完成。内核会释放与指定地址范围关联的虚拟内存。在 `pthread_create.cpp` 中，`munmap` 用于释放线程创建失败时分配的内存。

6. **`clone(int (*fn)(void *), void *stack, int flags, void *arg, ...)`:**
   - **功能:**  创建一个新的进程或线程。
   - **实现:**  这是一个核心的 Linux 系统调用。它的行为由 `flags` 参数控制。当使用 `CLONE_THREAD` 等标志时，它会创建一个与调用进程共享地址空间的新线程。
     - `fn`: 新线程执行的入口函数。
     - `stack`: 新线程的栈顶指针。
     - `flags`:  控制 `clone` 行为的标志，如 `CLONE_VM` (共享内存空间), `CLONE_FILES` (共享文件描述符), `CLONE_SIGHAND` (共享信号处理程序) 等。
     - `arg`:  传递给 `fn` 函数的参数。
     - 在 `pthread_create.cpp` 中，`clone` 被用来创建新线程的执行上下文，`__pthread_start` 作为新线程的入口函数。

7. **`memset(void *s, int c, size_t n)`:**
   - **功能:** 将指定内存块 `s` 的前 `n` 个字节设置为值 `c`。
   - **实现:**  这是一个标准 C 库函数，通常会使用优化的汇编指令来实现高效的内存填充。在 `pthread_create.cpp` 中，`memset` 用于清零新分配的线程内部结构。

8. **`getpid()`:**
   - **功能:** 获取当前进程的 ID。
   - **实现:**  这是一个系统调用，内核会返回当前进程的 PID。

9. **`sched_setscheduler(pid_t pid, int policy, const struct sched_param *param)`:**
   - **功能:** 设置指定进程或线程的调度策略和优先级。
   - **实现:**  这是一个系统调用，由内核完成。内核会根据指定的策略（如 `SCHED_FIFO`, `SCHED_RR`, `SCHED_NORMAL`）和优先级调整线程的调度行为。

10. **`sched_getscheduler(pid_t pid)`:**
    - **功能:** 获取指定进程或线程的当前调度策略。
    - **实现:** 也是一个系统调用，内核返回当前的调度策略。

11. **`sched_getparam(pid_t pid, struct sched_param *param)`:**
    - **功能:** 获取指定进程或线程的调度参数（如优先级）。
    - **实现:**  一个系统调用，内核将当前的调度参数填充到 `param` 结构体中。

12. **`prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)`:**
    - **功能:**  对进程或线程执行一些控制操作。
    - **实现:**  这是一个功能强大的系统调用，可以执行多种操作，由 `option` 参数指定。在 `pthread_create.cpp` 中，`prctl` 被用于：
        - `PR_SET_VMA`:  为内存映射区域设置名称，方便调试（例如，为线程的栈和 TLS 区域命名）。
        - `PR_PAC_RESET_KEYS` (在 ARM64 上): 重置指针认证密钥，增强安全性。

13. **`sigaltstack(const stack_t *ss, stack_t *oss)`:**
    - **功能:**  设置或获取信号处理程序的备用栈。
    - **实现:**  这是一个系统调用。当发生信号时，如果设置了备用栈，内核会切换到备用栈上执行信号处理程序，防止在栈溢出等情况下导致程序崩溃。

14. **`__rt_sigprocmask(int how, const sigset64_t *set, sigset64_t *oldset, size_t sigsetsize)`:**
    - **功能:**  检查和/或更改线程的信号屏蔽字。
    - **实现:**  这是一个系统调用。信号屏蔽字决定了哪些信号会被阻塞，不会传递给线程。

15. **`getauxval(unsigned long type)`:**
    - **功能:** 获取 auxiliary vector 中的值。
    - **实现:**  这是一个系统调用，用于获取内核在程序加载时传递的各种信息，例如硬件能力 (`AT_HWCAP`)。

16. **`android_get_application_target_sdk_version()`:**
    - **功能:**  获取应用程序的目标 SDK 版本。
    - **实现:**  这是一个 Android 特有的函数，通常通过读取进程的某个属性或文件来获取。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程**

`pthread_create.cpp` 中与动态链接器交互的关键在于线程本地存储 (TLS) 的管理。每个线程都需要有自己独立的 TLS 区域来存储线程特定的数据。

**SO 布局样本 (简化)**

假设我们有以下共享库 (SO)：

```
libmylib.so:
  .text         # 代码段
  .rodata       # 只读数据段
  .data         # 已初始化数据段
  .bss          # 未初始化数据段
  .tbss         # TLS 未初始化数据段
  .tdata        # TLS 已初始化数据段
```

* **`.tbss` (TLS BSS):** 存储未初始化的线程局部变量。
* **`.tdata` (TLS Data):** 存储已初始化的线程局部变量。

**链接处理过程**

1. **加载时 TLS 的分配:** 当动态链接器加载包含 TLS 段的共享库时，它会为每个线程分配足够的空间来容纳该 SO 的 `.tbss` 和 `.tdata` 段。
2. **`bionic_tls` 结构体:**  在 bionic 中，每个线程都有一个 `bionic_tls` 结构体，它包含了指向该线程所有 TLS 数据的指针。
3. **`__init_static_tls(void* static_tls)`:**  这个函数（虽然在提供的代码片段中没有完整展示，但被调用了）负责初始化线程的静态 TLS 区域。它会遍历已加载的共享库，并将它们的 `.tdata` 段的数据复制到线程的 TLS 区域中。对于 `.tbss` 段，则会将其清零。
4. **`tcb->tls_slot(TLS_SLOT_BIONIC_TLS) = tls;`:**  线程控制块 (TCB) 中会保存一个指向 `bionic_tls` 结构体的指针。这样，线程就可以通过 TCB 访问到自己的 TLS 数据。
5. **`clone` 系统调用的 `CLONE_SETTLS` 标志:**  在创建新线程时，`clone` 系统调用的 `CLONE_SETTLS` 标志以及传递的 `tls` 参数（在 x86 上是 `user_desc`）用于设置新线程的 TLS 描述符，告诉内核新线程的 TLS 区域在哪里。

**临时 `bionic_tls`**

代码中 `__allocate_temp_bionic_tls()` 和 `__free_temp_bionic_tls()` 函数用于在动态链接器的**主线程**加载初始的共享库时提供一个临时的 TLS 区域。这是因为在所有共享库加载完成之前，可能无法为动态链接器的主线程分配完整的 TLS 结构。

**逻辑推理，假设输入与输出**

假设我们有以下调用 `pthread_create` 的代码：

```c++
#include <pthread.h>
#include <stdio.h>

void* thread_func(void* arg) {
  int thread_id = *(int*)arg;
  printf("Hello from thread %d\n", thread_id);
  return NULL;
}

int main() {
  pthread_t thread;
  pthread_attr_t attr;
  int thread_id = 123;

  pthread_attr_init(&attr);

  if (pthread_create(&thread, &attr, thread_func, &thread_id) != 0) {
    perror("pthread_create failed");
    return 1;
  }

  pthread_join(thread, NULL); // 等待子线程结束

  pthread_attr_destroy(&attr);
  return 0;
}
```

**假设输入:**

* `start_routine`: `thread_func` 函数的地址。
* `arg`: 指向 `thread_id` 变量的指针 (值为 123)。
* `attr`: 使用默认属性初始化的 `pthread_attr_t` 结构体。

**预期输出 (在子线程中):**

```
Hello from thread 123
```

**`pthread_create` 函数内部的逻辑推理:**

1. **分配资源:**  `__allocate_thread` 函数会分配栈空间和 `pthread_internal_t` 结构体。
2. **初始化:**  `__init_thread` 函数会设置线程状态。
3. **`clone` 调用:** `clone(__pthread_start, child_stack, flags, thread, &(thread->tid), tls, &(thread->tid))` 被调用，创建一个新的线程。
4. **新线程执行 `__pthread_start`:**
   - 等待父线程释放 `startup_handshake_lock`。
   - 调用用户提供的 `start_routine` (`thread_func`)，并将 `arg` (指向 `thread_id`) 传递给它。
   - `thread_func` 执行，打印 "Hello from thread 123"。
   - 调用 `pthread_exit` 退出线程。

**用户或编程常见的使用错误**

1. **未初始化 `pthread_attr_t`:**  直接使用未初始化的 `pthread_attr_t` 结构体，导致属性值不确定。
   ```c++
   pthread_attr_t attr; // 未初始化
   pthread_create(&thread, &attr, ...); // 错误用法
   ```

2. **栈溢出:**  分配的栈空间不足以满足线程的需求，导致栈溢出。可以通过 `pthread_attr_setstacksize` 设置更大的栈空间。

3. **尝试 join 一个 detached 线程:**  如果线程属性被设置为 detached (分离状态)，则不能使用 `pthread_join` 等待其结束。
   ```c++
   pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
   pthread_create(&thread, &attr, ...);
   pthread_join(thread, NULL); // 错误：尝试 join 一个 detached 线程
   ```

4. **传递错误的参数给线程函数:**  例如，传递局部变量的地址，而线程执行时该变量可能已经失效。
   ```c++
   void* thread_func(void* arg) {
       printf("Value: %d\n", * (int*)arg); // 可能访问无效内存
       return NULL;
   }

   int main() {
       pthread_t thread;
       int value = 10;
       pthread_create(&thread, NULL, thread_func, &value); // 错误：main 函数返回后 value 可能失效
       return 0;
   }
   ```
   **应该传递动态分配的内存或者全局/静态变量的地址。**

5. **忘记清理 `pthread_attr_t`:** 使用 `pthread_attr_init` 初始化后，应该使用 `pthread_attr_destroy` 销毁属性对象，释放资源。

**说明 Android framework 或 ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤**

**Android Framework 到 `pthread_create` 的路径:**

1. **Java 层创建线程:**  在 Java 代码中，通常通过创建 `java.lang.Thread` 类的实例或使用 `ExecutorService` 等线程池机制来创建线程。
   ```java
   // Java 代码
   Thread myThread = new Thread(new Runnable() {
       @Override
       public void run() {
           // 线程执行的代码
       }
   });
   myThread.start();
   ```

2. **JNI 调用:**  `java.lang.Thread.start()` 方法最终会调用到 native 方法 `nativeCreate()`。这是一个 JNI (Java Native Interface) 调用。

3. **`Runtime.cc` 或相关 native 代码:**  在 Android Runtime (ART) 或 Dalvik 虚拟机的 native 代码中，`nativeCreate()` 方法的实现会调用到 `pthread_create`。

**NDK 到 `pthread_create` 的路径:**

1. **C/C++ 代码直接调用:**  在 NDK 开发中，可以直接在 C/C++ 代码中包含 `<pthread.h>` 并调用 `pthread_create`。
   ```c++
   // NDK C++ 代码
   #include <pthread.h>

   void* my_ndk_thread(void*) {
       // ...
       return nullptr;
   }

   void create_ndk_thread() {
       pthread_t thread;
       pthread_create(&thread, nullptr, my_ndk_thread, nullptr);
   }
   ```

**Frida Hook 示例**

可以使用 Frida 来 hook `pthread_create` 函数，观察其调用情况和参数。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Payload: {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = device.spawn(["com.example.myapp"]) # 替换为你的应用包名
    session = device.attach(pid)
    script = session.create_script("""
        Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
            onEnter: function(args) {
                console.log("[+] pthread_create called");
                console.log("    Thread pointer: " + args[0]);
                console.log("    Attributes: " + args[1]);
                console.log("    Start routine: " + args[2]);
                console.log("    Argument: " + args[3]);
                // 可以进一步读取参数指向的内存
                if (args[1] != 0) {
                    console.log("    Stack size (from attr): " + Memory.readU32(ptr(args[1]).add(8))); // 假设栈大小是 pthread_attr_t 的第 3 个字段 (偏移 8)
                }
            },
            onLeave: function(retval) {
                console.log("[+] pthread_create returned: " + retval);
            }
        });
    """)
    script.on('message', on_message)
    script.load()
    device.resume(pid)
    sys.stdin.read()
except Exception as e:
    print(e)
```

**Frida Hook 解释:**

1. **`frida.get_usb_device()`:** 获取 USB 连接的设备。
2. **`device.spawn()`:** 启动目标 Android 应用程序。
3. **`device.attach()`:** 将 Frida 连接到目标进程。
4. **`session.create_script()`:** 创建 Frida 脚本。
5. **`Interceptor.attach()`:**  拦截 `libc.so` 中的 `pthread_create` 函数。
6. **`onEnter()`:**  在 `pthread_create` 函数被调用时执行。
   - 打印函数的参数地址。
   - 尝试读取 `pthread_attr_t` 结构体中的栈大小（需要根据实际的结构体定义来确定偏移量）。
7. **`onLeave()`:** 在 `pthread_create` 函数返回时执行，打印返回值。
8. **`script.load()`:** 加载并执行 Frida 脚本。
9. **`device.resume()`:** 恢复目标进程的执行。

通过运行这个 Frida 脚本，当目标应用程序调用 `pthread_create` 时，你将在 Frida 的控制台中看到相关的调用信息，包括参数值，这有助于调试和理解线程创建的过程。

希望以上分析能够帮助你深入理解 `bionic/libc/bionic/pthread_create.cpp` 的功能和实现！

Prompt: 
```
这是目录为bionic/libc/bionic/pthread_create.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <string.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/random.h>
#include <unistd.h>

#include "pthread_internal.h"

#include <async_safe/log.h>

#include "platform/bionic/macros.h"
#include "platform/bionic/mte.h"
#include "platform/bionic/page.h"
#include "private/ErrnoRestorer.h"
#include "private/ScopedRWLock.h"
#include "private/bionic_constants.h"
#include "private/bionic_defs.h"
#include "private/bionic_globals.h"
#include "private/bionic_ssp.h"
#include "private/bionic_systrace.h"
#include "private/bionic_tls.h"

// x86 uses segment descriptors rather than a direct pointer to TLS.
#if defined(__i386__)
#include <asm/ldt.h>
void __init_user_desc(struct user_desc*, bool, void*);
#endif

__attribute__((no_stack_protector))
void __init_tcb_stack_guard(bionic_tcb* tcb) {
  // GCC looks in the TLS for the stack guard on x86, so copy it there from our global.
  tcb->tls_slot(TLS_SLOT_STACK_GUARD) = reinterpret_cast<void*>(__stack_chk_guard);
}

void __init_bionic_tls_ptrs(bionic_tcb* tcb, bionic_tls* tls) {
  tcb->thread()->bionic_tcb = tcb;
  tcb->thread()->bionic_tls = tls;
  tcb->tls_slot(TLS_SLOT_BIONIC_TLS) = tls;
}

// Allocate a temporary bionic_tls that the dynamic linker's main thread can
// use while it's loading the initial set of ELF modules.
bionic_tls* __allocate_temp_bionic_tls() {
  size_t allocation_size = __BIONIC_ALIGN(sizeof(bionic_tls), page_size());
  void* allocation = mmap(nullptr, allocation_size,
                          PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS,
                          -1, 0);
  if (allocation == MAP_FAILED) {
    async_safe_fatal("failed to allocate bionic_tls: %m");
  }
  return static_cast<bionic_tls*>(allocation);
}

void __free_temp_bionic_tls(bionic_tls* tls) {
  munmap(tls, __BIONIC_ALIGN(sizeof(bionic_tls), page_size()));
}

static void __init_alternate_signal_stack(pthread_internal_t* thread) {
  // Create and set an alternate signal stack.
  int prot = PROT_READ | PROT_WRITE;
#ifdef __aarch64__
  if (atomic_load(&__libc_memtag_stack)) {
    prot |= PROT_MTE;
  }
#endif
  void* stack_base = mmap(nullptr, SIGNAL_STACK_SIZE, prot, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (stack_base != MAP_FAILED) {
    // Create a guard to catch stack overflows in signal handlers.
    if (mprotect(stack_base, PTHREAD_GUARD_SIZE, PROT_NONE) == -1) {
      munmap(stack_base, SIGNAL_STACK_SIZE);
      return;
    }
    stack_t ss;
    ss.ss_sp = reinterpret_cast<uint8_t*>(stack_base) + PTHREAD_GUARD_SIZE;
    ss.ss_size = SIGNAL_STACK_SIZE - PTHREAD_GUARD_SIZE;
    ss.ss_flags = 0;
    sigaltstack(&ss, nullptr);
    thread->alternate_signal_stack = stack_base;

    // We can only use const static allocated string for mapped region name, as Android kernel
    // uses the string pointer directly when dumping /proc/pid/maps.
    prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, ss.ss_sp, ss.ss_size, "thread signal stack");
  }
}

static void __init_shadow_call_stack(pthread_internal_t* thread __unused) {
#if defined(__aarch64__) || defined(__riscv)
  // Allocate the shadow call stack and its guard region.
  char* scs_guard_region = reinterpret_cast<char*>(
      mmap(nullptr, SCS_GUARD_REGION_SIZE, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0));
  if (scs_guard_region == MAP_FAILED) {
    async_safe_fatal("failed to allocate shadow stack: %m");
  }
  thread->shadow_call_stack_guard_region = scs_guard_region;

  // Align the address to SCS_SIZE so that we only need to store the lower log2(SCS_SIZE) bits
  // in jmp_buf. See the SCS commentary in pthread_internal.h for more detail.
  char* scs_aligned_guard_region =
      reinterpret_cast<char*>(__builtin_align_up(reinterpret_cast<uintptr_t>(scs_guard_region), SCS_SIZE));

  // We need to ensure that [scs_offset,scs_offset+SCS_SIZE) is in the guard region and that there
  // is at least one unmapped page after the shadow call stack (to catch stack overflows). We can't
  // use arc4random_uniform in init because /dev/urandom might not have been created yet.
  size_t scs_offset =
      (getpid() == 1) ? 0 : (arc4random_uniform(SCS_GUARD_REGION_SIZE / SCS_SIZE - 1) * SCS_SIZE);

  // Make the stack read-write, and store its address in the register we're using as the shadow
  // stack pointer. This is deliberately the only place where the address is stored.
  char* scs = scs_aligned_guard_region + scs_offset;
  if (mprotect(scs, SCS_SIZE, PROT_READ | PROT_WRITE) == -1) {
    async_safe_fatal("shadow stack read-write mprotect(%p, %d) failed: %m", scs, SCS_SIZE);
  }
#if defined(__aarch64__)
  __asm__ __volatile__("mov x18, %0" ::"r"(scs));
#elif defined(__riscv)
  __asm__ __volatile__("mv x3, %0" ::"r"(scs));
#endif
#endif
}

void __init_additional_stacks(pthread_internal_t* thread) {
  __init_alternate_signal_stack(thread);
  __init_shadow_call_stack(thread);
}

int __init_thread(pthread_internal_t* thread) {
  thread->cleanup_stack = nullptr;

  ThreadJoinState state = THREAD_NOT_JOINED;
  if (__predict_false((thread->attr.flags & PTHREAD_ATTR_FLAG_DETACHED) != 0)) {
    state = THREAD_DETACHED;
  }
  atomic_store_explicit(&thread->join_state, state, memory_order_relaxed);

  // Set the scheduling policy/priority of the thread if necessary.
  bool need_set = true;
  int policy;
  sched_param param;
  if ((thread->attr.flags & PTHREAD_ATTR_FLAG_INHERIT) != 0) {
    // Unless the parent has SCHED_RESET_ON_FORK set, we've already inherited from the parent.
    policy = sched_getscheduler(0);
    need_set = ((policy & SCHED_RESET_ON_FORK) != 0);
    if (need_set) {
      if (policy == -1) {
        async_safe_format_log(ANDROID_LOG_WARN, "libc",
                              "pthread_create sched_getscheduler failed: %m");
        return errno;
      }
      if (sched_getparam(0, &param) == -1) {
        async_safe_format_log(ANDROID_LOG_WARN, "libc", "pthread_create sched_getparam failed: %m");
        return errno;
      }
    }
  } else {
    policy = thread->attr.sched_policy;
    param.sched_priority = thread->attr.sched_priority;
  }
  // Backwards compatibility: before P, Android didn't have pthread_attr_setinheritsched,
  // and our behavior was neither of the POSIX behaviors.
  if ((thread->attr.flags & (PTHREAD_ATTR_FLAG_INHERIT|PTHREAD_ATTR_FLAG_EXPLICIT)) == 0) {
    need_set = (thread->attr.sched_policy != SCHED_NORMAL);
  }
  if (need_set) {
    if (sched_setscheduler(thread->tid, policy, &param) == -1) {
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "pthread_create sched_setscheduler(%d, {%d}) call failed: %m", policy,
                            param.sched_priority);
#if defined(__LP64__)
      // For backwards compatibility reasons, we only report failures on 64-bit devices.
      return errno;
#endif
    }
  }

  return 0;
}

// Allocate a thread's primary mapping. This mapping includes static TLS and
// optionally a stack. Static TLS includes ELF TLS segments and the bionic_tls
// struct.
//
// The stack_guard_size must be a multiple of the page_size().
ThreadMapping __allocate_thread_mapping(size_t stack_size, size_t stack_guard_size) {
  const StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;

  // Allocate in order: stack guard, stack, static TLS, guard page.
  size_t mmap_size;
  if (__builtin_add_overflow(stack_size, stack_guard_size, &mmap_size)) return {};
  if (__builtin_add_overflow(mmap_size, layout.size(), &mmap_size)) return {};
  if (__builtin_add_overflow(mmap_size, PTHREAD_GUARD_SIZE, &mmap_size)) return {};

  // Align the result to a page size.
  const size_t unaligned_size = mmap_size;
  mmap_size = __BIONIC_ALIGN(mmap_size, page_size());
  if (mmap_size < unaligned_size) return {};

  // Create a new private anonymous map. Make the entire mapping PROT_NONE, then carve out a
  // read+write area in the middle.
  const int flags = MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE;
  char* const space = static_cast<char*>(mmap(nullptr, mmap_size, PROT_NONE, flags, -1, 0));
  if (space == MAP_FAILED) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc",
                          "pthread_create failed: couldn't allocate %zu-bytes mapped space: %m",
                          mmap_size);
    return {};
  }
  const size_t writable_size = mmap_size - stack_guard_size - PTHREAD_GUARD_SIZE;
  int prot = PROT_READ | PROT_WRITE;
  const char* prot_str = "R+W";
#ifdef __aarch64__
  if (atomic_load(&__libc_memtag_stack)) {
    prot |= PROT_MTE;
    prot_str = "R+W+MTE";
  }
#endif
  if (mprotect(space + stack_guard_size, writable_size, prot) != 0) {
    async_safe_format_log(
        ANDROID_LOG_WARN, "libc",
        "pthread_create failed: couldn't mprotect %s %zu-byte thread mapping region: %m", prot_str,
        writable_size);
    munmap(space, mmap_size);
    return {};
  }

  ThreadMapping result = {};
  result.mmap_base = space;
  result.mmap_size = mmap_size;
  result.mmap_base_unguarded = space + stack_guard_size;
  result.mmap_size_unguarded = mmap_size - stack_guard_size - PTHREAD_GUARD_SIZE;
  result.static_tls = space + mmap_size - PTHREAD_GUARD_SIZE - layout.size();
  result.stack_base = space;
  result.stack_top = result.static_tls;
  return result;
}

static int __allocate_thread(pthread_attr_t* attr, bionic_tcb** tcbp, void** child_stack) {
  ThreadMapping mapping;
  char* stack_top;
  bool stack_clean = false;

  if (attr->stack_base == nullptr) {
    // The caller didn't provide a stack, so allocate one.

    // Make sure the guard size is a multiple of page_size().
    const size_t unaligned_guard_size = attr->guard_size;
    attr->guard_size = __BIONIC_ALIGN(attr->guard_size, page_size());
    if (attr->guard_size < unaligned_guard_size) return EAGAIN;

    mapping = __allocate_thread_mapping(attr->stack_size, attr->guard_size);
    if (mapping.mmap_base == nullptr) return EAGAIN;

    stack_top = mapping.stack_top;
    attr->stack_base = mapping.stack_base;
    stack_clean = true;
  } else {
    mapping = __allocate_thread_mapping(0, PTHREAD_GUARD_SIZE);
    if (mapping.mmap_base == nullptr) return EAGAIN;

    stack_top = static_cast<char*>(attr->stack_base) + attr->stack_size;
  }

  // Carve out space from the stack for the thread's pthread_internal_t. This
  // memory isn't counted in pthread_attr_getstacksize.

  // To safely access the pthread_internal_t and thread stack, we need to find a 16-byte aligned boundary.
  stack_top = __builtin_align_down(stack_top - sizeof(pthread_internal_t), 16);

  pthread_internal_t* thread = reinterpret_cast<pthread_internal_t*>(stack_top);
  if (!stack_clean) {
    // If thread was not allocated by mmap(), it may not have been cleared to zero.
    // So assume the worst and zero it.
    memset(thread, 0, sizeof(pthread_internal_t));
  }

  // Locate static TLS structures within the mapped region.
  const StaticTlsLayout& layout = __libc_shared_globals()->static_tls_layout;
  auto tcb = reinterpret_cast<bionic_tcb*>(mapping.static_tls + layout.offset_bionic_tcb());
  auto tls = reinterpret_cast<bionic_tls*>(mapping.static_tls + layout.offset_bionic_tls());

  // Initialize TLS memory.
  __init_static_tls(mapping.static_tls);
  __init_tcb(tcb, thread);
  __init_tcb_dtv(tcb);
  __init_tcb_stack_guard(tcb);
  __init_bionic_tls_ptrs(tcb, tls);

  attr->stack_size = stack_top - static_cast<char*>(attr->stack_base);
  thread->attr = *attr;
  thread->mmap_base = mapping.mmap_base;
  thread->mmap_size = mapping.mmap_size;
  thread->mmap_base_unguarded = mapping.mmap_base_unguarded;
  thread->mmap_size_unguarded = mapping.mmap_size_unguarded;
  thread->stack_top = reinterpret_cast<uintptr_t>(stack_top);

  *tcbp = tcb;
  *child_stack = stack_top;
  return 0;
}

void __set_stack_and_tls_vma_name(bool is_main_thread) {
  // Name the thread's stack-and-tls area to help with debugging. This mapped area also includes
  // static TLS data, which is typically a few pages (e.g. bionic_tls).
  pthread_internal_t* thread = __get_thread();
  const char* name;
  if (is_main_thread) {
    name = "stack_and_tls:main";
  } else {
    // The kernel doesn't copy the name string, but this variable will last at least as long as the
    // mapped area. The mapped area's VMAs are unmapped with a single call to munmap.
    auto& name_buffer = thread->vma_name_buffer;
    static_assert(arraysize(name_buffer) >= arraysize("stack_and_tls:") + 11 + 1);
    async_safe_format_buffer(name_buffer, arraysize(name_buffer), "stack_and_tls:%d", thread->tid);
    name = name_buffer;
  }
  prctl(PR_SET_VMA, PR_SET_VMA_ANON_NAME, thread->mmap_base_unguarded, thread->mmap_size_unguarded,
        name);
}

extern "C" int __rt_sigprocmask(int, const sigset64_t*, sigset64_t*, size_t);

__attribute__((no_sanitize("hwaddress", "memtag")))
#if defined(__aarch64__)
// This function doesn't return, but it does appear in stack traces. Avoid using return PAC in this
// function because we may end up resetting IA, which may confuse unwinders due to mismatching keys.
__attribute__((target("branch-protection=bti")))
#endif
static int
__pthread_start(void* arg) {
  pthread_internal_t* thread = reinterpret_cast<pthread_internal_t*>(arg);
#if defined(__aarch64__)
  if (thread->should_allocate_stack_mte_ringbuffer) {
    thread->bionic_tcb->tls_slot(TLS_SLOT_STACK_MTE) = __allocate_stack_mte_ringbuffer(0, thread);
  }
#endif
  __hwasan_thread_enter();

  // Wait for our creating thread to release us. This lets it have time to
  // notify gdb about this thread before we start doing anything.
  // This also provides the memory barrier needed to ensure that all memory
  // accesses previously made by the creating thread are visible to us.
  thread->startup_handshake_lock.lock();

  __set_stack_and_tls_vma_name(false);
  __init_additional_stacks(thread);
  __rt_sigprocmask(SIG_SETMASK, &thread->start_mask, nullptr, sizeof(thread->start_mask));
#if defined(__aarch64__)
  // Chrome's sandbox prevents this prctl, so only reset IA if the target SDK level is high enough.
  // Furthermore, processes loaded from vendor partitions may have their own sandboxes that would
  // reject the prctl. Because no devices launched with PAC enabled before API level 31, we can
  // avoid issues on upgrading devices by checking for PAC support before issuing the prctl.
  static const bool pac_supported = getauxval(AT_HWCAP) & HWCAP_PACA;
  if (pac_supported && android_get_application_target_sdk_version() >= 31) {
    prctl(PR_PAC_RESET_KEYS, PR_PAC_APIAKEY, 0, 0, 0);
  }
#endif

  void* result = thread->start_routine(thread->start_routine_arg);
  pthread_exit(result);

  return 0;
}

// A no-op start routine for pthread_create failures where we've created a thread but aren't
// going to run user code on it. We swap out the user's start routine for this and take advantage
// of the regular thread teardown to free up resources.
static void* __do_nothing(void*) {
  return nullptr;
}

pthread_rwlock_t g_thread_creation_lock = PTHREAD_RWLOCK_INITIALIZER;

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int pthread_create(pthread_t* thread_out, pthread_attr_t const* attr,
                   void* (*start_routine)(void*), void* arg) {
  ErrnoRestorer errno_restorer;

  pthread_attr_t thread_attr;
  ScopedTrace trace("pthread_create");
  if (attr == nullptr) {
    pthread_attr_init(&thread_attr);
  } else {
    thread_attr = *attr;
    attr = nullptr; // Prevent misuse below.
  }

  bionic_tcb* tcb = nullptr;
  void* child_stack = nullptr;
  int result = __allocate_thread(&thread_attr, &tcb, &child_stack);
  if (result != 0) {
    return result;
  }

  pthread_internal_t* thread = tcb->thread();

  // Create a lock for the thread to wait on once it starts so we can keep
  // it from doing anything until after we notify the debugger about it
  //
  // This also provides the memory barrier we need to ensure that all
  // memory accesses previously performed by this thread are visible to
  // the new thread.
  thread->startup_handshake_lock.init(false);
  thread->startup_handshake_lock.lock();

  thread->start_routine = start_routine;
  thread->start_routine_arg = arg;

  thread->set_cached_pid(getpid());

  int flags = CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD | CLONE_SYSVSEM |
      CLONE_SETTLS | CLONE_PARENT_SETTID | CLONE_CHILD_CLEARTID;
  void* tls = &tcb->tls_slot(0);
#if defined(__i386__)
  // On x86 (but not x86-64), CLONE_SETTLS takes a pointer to a struct user_desc rather than
  // a pointer to the TLS itself.
  user_desc tls_descriptor;
  __init_user_desc(&tls_descriptor, false, tls);
  tls = &tls_descriptor;
#endif

  ScopedReadLock locker(&g_thread_creation_lock);

// This has to be done under g_thread_creation_lock or g_thread_list_lock to avoid racing with
// __pthread_internal_remap_stack_with_mte.
#ifdef __aarch64__
  thread->should_allocate_stack_mte_ringbuffer = __libc_memtag_stack_abi;
#else
  thread->should_allocate_stack_mte_ringbuffer = false;
#endif

  sigset64_t block_all_mask;
  sigfillset64(&block_all_mask);
  __rt_sigprocmask(SIG_SETMASK, &block_all_mask, &thread->start_mask, sizeof(thread->start_mask));
  int rc = clone(__pthread_start, child_stack, flags, thread, &(thread->tid), tls, &(thread->tid));
  __rt_sigprocmask(SIG_SETMASK, &thread->start_mask, nullptr, sizeof(thread->start_mask));
  if (rc == -1) {
    int clone_errno = errno;
    // We don't have to unlock the mutex at all because clone(2) failed so there's no child waiting to
    // be unblocked, but we're about to unmap the memory the mutex is stored in, so this serves as a
    // reminder that you can't rewrite this function to use a ScopedPthreadMutexLocker.
    thread->startup_handshake_lock.unlock();
    if (thread->mmap_size != 0) {
      munmap(thread->mmap_base, thread->mmap_size);
    }
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "pthread_create failed: clone failed: %m");
    return clone_errno;
  }

  int init_errno = __init_thread(thread);
  if (init_errno != 0) {
    // Mark the thread detached and replace its start_routine with a no-op.
    // Letting the thread run is the easiest way to clean up its resources.
    atomic_store(&thread->join_state, THREAD_DETACHED);
    __pthread_internal_add(thread);
    thread->start_routine = __do_nothing;
    thread->startup_handshake_lock.unlock();
    return init_errno;
  }

  // Publish the pthread_t and unlock the mutex to let the new thread start running.
  *thread_out = __pthread_internal_add(thread);
  thread->startup_handshake_lock.unlock();

  return 0;
}

"""

```