Response:
Let's break down the thought process for analyzing the provided C code snippet.

**1. Understanding the Goal:**

The request is to analyze the `threads_h.c` file in the Android bionic library. The key is to identify its purpose, how it relates to Android, explain the libc function implementations (although this file *doesn't* implement them, but rather *tests* their presence), detail dynamic linker interactions (again, minimal interaction here), discuss potential user errors, and explain how Android frameworks reach this code, including a Frida example.

**2. Initial Code Scan and Interpretation:**

The first step is to read the code and understand its structure.

* **`#if __has_include(<threads.h>)`:** This conditional compilation suggests the code is designed to run only if the `<threads.h>` header file is available. This immediately tells us it's a *test* file verifying the existence and interface of the C11 threads API.
* **`#include <threads.h>`:**  Confirms the file's focus on the `threads.h` standard.
* **`#include "header_checks.h"`:** Indicates the presence of a custom header for testing.
* **`thread_local int t;`:** Demonstrates testing of thread-local storage.
* **`static void threads_h() { ... }`:**  The core of the test. The name `threads_h` reinforces the purpose.
* **`MACRO(...)` and `TYPE(...)`:** These are likely macros defined in `header_checks.h` used to check for the existence of macros and types defined in `threads.h`.
* **`FUNCTION(...)`:** Similarly, these macros are likely used to verify the presence and signature of functions declared in `threads.h`. The function pointer syntax (`void (*f)(...)`) is a dead giveaway.
* **`#define DO_NOT_INCLUDE_TIME_H` and `#include "time_h.c"`:**  This is a bit peculiar. It suggests the test might also be related to time functions, but it's intentionally excluding the standard `<time.h>` and including a local `time_h.c`. This likely means they are testing the interaction of thread functions with time-related structures (like `timespec`).

**3. Identifying the Core Functionality:**

Based on the code structure, the primary function of `threads_h.c` is **to test the presence and basic interface of the C11 threads API (`<threads.h>`) within the Android bionic library.** It's not *implementing* the thread functionality, but rather *verifying* that the necessary declarations and definitions are present.

**4. Relating to Android Functionality:**

The C11 threads API provides a standardized way to manage threads, mutexes, condition variables, and thread-local storage. These are fundamental building blocks for concurrent programming in Android applications and the Android framework itself. Examples include:

* **Java Threads:**  The Java `Thread` class in Android ultimately relies on native threads managed by bionic.
* **AsyncTask:**  A common Android framework class for background tasks, often using thread pools.
* **RenderThread/UI Thread:**  The core threads in an Android application's process.
* **System Services:**  Many Android system services utilize threads for handling requests concurrently.

**5. Explaining libc Function Implementations (Correction and Clarification):**

The crucial realization is that **this file *doesn't* implement the libc functions.** It *tests* for their existence. The request asks for implementation details, which is not present in this file. Therefore, the answer needs to acknowledge this and explain what the test is actually doing (checking for declarations and basic types). A brief explanation of what these functions *generally* do in a threading library is helpful context.

**6. Dynamic Linker Interaction:**

This file has minimal interaction with the dynamic linker. It's a source file that gets compiled into a test executable. The dynamic linker's role is to link the test executable against the bionic libc, ensuring the `threads.h` symbols are resolved. A basic explanation of the linking process and a simplified SO layout demonstrating the presence of threading symbols is necessary.

**7. Logic Reasoning (Simple Verification):**

The logic is straightforward: the test checks if the elements declared in `<threads.h>` are present. The "input" is the successful compilation and execution of the test. The "output" is confirmation (implicit or explicit through test results) that the required symbols exist.

**8. User/Programming Errors:**

This file itself doesn't introduce user errors directly. However, it tests the underlying threading primitives. Therefore, the answer should focus on common errors developers make *when using* these threading functions: deadlocks, race conditions, improper synchronization, and memory management issues with thread-local storage.

**9. Android Framework and NDK Path:**

Tracing how the framework reaches this specific *test* file is less direct. The framework doesn't directly call this code. Instead, it utilizes the *implementation* of the threading functions within bionic. The NDK exposes the `<threads.h>` API to native developers. The path involves:

* **Framework/NDK using threading primitives.**
* **These calls being implemented by bionic's thread library.**
* **This test file being part of bionic's testing suite to ensure correct implementation.**

The Frida example should demonstrate hooking into a commonly used threading function like `pthread_create` (since `thrd_create` might be a wrapper).

**10. Structuring the Answer:**

A clear and structured answer is crucial. Using headings, bullet points, and code examples (even if simplified) helps with readability. It's important to address each part of the original request.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Maybe this file implements the thread functions.
* **Correction:**  No, the `#include <threads.h>` and the `FUNCTION` macros clearly indicate it's *testing* the interface, not implementing it.
* **Initial thought:**  Focus heavily on dynamic linker internals specific to this file.
* **Correction:** The interaction is minimal. Focus on the basic linking concept of resolving symbols.
* **Initial thought:** Provide very complex Frida examples.
* **Correction:**  A simple example demonstrating hooking into a related pthread function is sufficient to illustrate the concept.

By following these steps of understanding the code, identifying its purpose, connecting it to the broader context, and addressing each part of the request systematically, a comprehensive and accurate answer can be constructed. The key is to pay close attention to the details of the code and avoid making assumptions about its functionality.

这是一个位于 Android Bionic 库中 `bionic/tests/headers/posix/threads_h.c` 的源代码文件。从文件名和代码内容来看，它的主要功能是 **测试 `<threads.h>` 头文件的正确性**。这个头文件定义了 C11 标准中关于线程管理的一些基本接口。

具体来说，这个测试文件会检查：

1. **宏定义 (Macros):**  例如 `ONCE_FLAG_INIT` 和 `TSS_DTOR_ITERATIONS` 是否被正确定义。
2. **类型定义 (Types):** 例如 `cnd_t` (条件变量), `thrd_t` (线程标识符), `tss_t` (线程特定存储), `mtx_t` (互斥锁), `tss_dtor_t` (线程特定存储析构函数), `thrd_start_t` (线程启动函数指针类型), `once_flag` (用于 `call_once`) 是否被正确定义。
3. **枚举常量 (Enumeration Constants):** 检查与互斥锁和线程相关的枚举常量的值，例如 `mtx_plain`, `mtx_recursive`, `mtx_timed`, `thrd_timedout`, `thrd_success`, `thrd_busy`, `thrd_error`, `thrd_nomem`。
4. **函数声明 (Function Declarations):** 检查 `<threads.h>` 中声明的各个函数的存在以及它们的函数签名是否正确。这些函数包括：
    * **`call_once`**:  只调用一次的函数。
    * **条件变量相关**: `cnd_broadcast`, `cnd_destroy`, `cnd_init`, `cnd_signal`, `cnd_timedwait`, `cnd_wait`。
    * **互斥锁相关**: `mtx_destroy`, `mtx_init`, `mtx_lock`, `mtx_timedlock`, `mtx_trylock`, `mtx_unlock`。
    * **线程相关**: `thrd_create`, `thrd_current`, `thrd_detach`, `thrd_equal`, `thrd_exit`, `thrd_join`, `thrd_sleep`, `thrd_yield`。
    * **线程特定存储相关**: `tss_create`, `tss_delete`, `tss_get`, `tss_set`。

**与 Android 功能的关系及举例说明:**

Bionic 是 Android 的 C 库，它提供了 Android 系统和应用程序运行所必需的底层 C 接口。`<threads.h>` 中定义的线程管理功能是构建并发程序的基础，在 Android 中被广泛使用：

* **Android 应用程序的线程管理:**  Android 应用程序可以使用 NDK (Native Development Kit) 调用这些 C 线程 API 来创建和管理线程，执行后台任务，提高程序的响应性。例如，一个需要执行耗时网络请求的应用程序可以使用 `thrd_create` 创建一个新线程来执行请求，避免阻塞主线程 (UI 线程)。
* **Android Framework 的实现:** Android Framework 的许多组件和服务都是多线程的，例如处理用户输入、渲染 UI、执行后台同步等。这些组件的底层实现很可能使用了 Bionic 提供的线程管理功能。
* **JNI (Java Native Interface):** 当 Java 代码需要调用本地 (C/C++) 代码时，本地代码可以使用 `<threads.h>` 中的函数来管理自己的线程，或者与 Java 虚拟机管理的线程进行交互。

**libc 函数的功能实现:**

这个 `threads_h.c` 文件本身 **并不实现** `<threads.h>` 中声明的 libc 函数。它的作用是 **检查这些函数是否被正确声明**。这些函数的具体实现位于 Bionic 库的其他源文件中。

以下简要解释一下这些 libc 函数的功能：

* **`call_once`**:  确保一个初始化函数在程序执行过程中只被调用一次，即使在多线程环境下也是如此。通常用于延迟初始化单例对象或执行只需执行一次的设置。
* **`cnd_broadcast`**:  唤醒所有等待指定条件变量的线程。
* **`cnd_destroy`**:  销毁一个条件变量，释放相关资源。
* **`cnd_init`**:  初始化一个条件变量。
* **`cnd_signal`**:  唤醒一个等待指定条件变量的线程。如果有多个线程等待，则只唤醒其中一个。
* **`cnd_timedwait`**:  等待指定的条件变量，如果在指定的时间内没有被唤醒，则超时返回。
* **`cnd_wait`**:  等待指定的条件变量，直到被其他线程通过 `cnd_signal` 或 `cnd_broadcast` 唤醒。在等待期间，通常会释放关联的互斥锁。
* **`mtx_destroy`**:  销毁一个互斥锁，释放相关资源。
* **`mtx_init`**:  初始化一个互斥锁，可以指定互斥锁的类型（例如，普通锁、递归锁、定时锁）。
* **`mtx_lock`**:  尝试获取指定的互斥锁。如果互斥锁已经被其他线程持有，则当前线程会被阻塞，直到互斥锁被释放。
* **`mtx_timedlock`**:  尝试在指定的时间内获取指定的互斥锁。如果超时仍然无法获取，则返回错误。
* **`mtx_trylock`**:  尝试获取指定的互斥锁。如果互斥锁已经被其他线程持有，则立即返回一个错误，而不会阻塞当前线程。
* **`mtx_unlock`**:  释放当前线程持有的互斥锁。
* **`thrd_create`**:  创建一个新的线程，并指定线程的入口函数和传递给入口函数的参数。
* **`thrd_current`**:  返回当前执行线程的线程标识符。
* **`thrd_detach`**:  将指定的线程设置为 detached 状态。detached 线程在其执行完成后会自动回收资源，不需要其他线程调用 `thrd_join` 等待其结束。
* **`thrd_equal`**:  比较两个线程标识符是否相等，判断它们是否代表同一个线程。
* **`thrd_exit`**:  终止当前线程的执行，并返回一个退出码。
* **`thrd_join`**:  阻塞当前线程，直到指定的线程执行结束。可以获取被 join 线程的退出码。
* **`thrd_sleep`**:  使当前线程休眠指定的时间。
* **`thrd_yield`**:  提示操作系统，当前线程愿意放弃剩余的时间片，让其他线程有机会运行。
* **`tss_create`**:  创建一个线程特定存储 (Thread-Specific Storage) 的键，并指定一个可选的析构函数。每个线程都可以拥有与此键关联的独立的值。
* **`tss_delete`**:  删除一个线程特定存储的键。
* **`tss_get`**:  获取与指定线程特定存储键关联的当前线程的值。
* **`tss_set`**:  设置与指定线程特定存储键关联的当前线程的值。

**涉及 dynamic linker 的功能及 SO 布局样本和链接处理过程:**

这个测试文件本身主要关注头文件的声明，与 dynamic linker 的直接交互较少。但是，当包含 `<threads.h>` 的代码被编译并链接成可执行文件或共享库 (SO) 时，dynamic linker 会参与其中。

**SO 布局样本:**

假设有一个名为 `libmylib.so` 的共享库，它使用了 `<threads.h>` 中的函数。其布局可能如下：

```
libmylib.so:
    .text          # 代码段
        my_thread_function:
            ; ... 使用 thrd_create, mtx_lock 等 ...
    .data          # 初始化数据段
    .bss           # 未初始化数据段
    .dynamic       # 动态链接信息
        NEEDED      libc.so  # 依赖于 libc.so
        ...
    .symtab        # 符号表
        thrd_create (GLOBAL, FUNC)
        mtx_lock    (GLOBAL, FUNC)
        ...
    .strtab        # 字符串表
        ...
```

**链接处理过程:**

1. **编译时:** 当 `libmylib.so` 被编译时，编译器会识别出对 `<threads.h>` 中函数的调用，例如 `thrd_create`。
2. **链接时:**  链接器 (ld) 会查看 `libmylib.so` 的依赖关系，发现它依赖于 `libc.so` (Bionic C 库)。
3. **动态链接:** 当 `libmylib.so` 被加载到进程空间时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下操作：
    * **加载依赖:** 加载 `libc.so` 到进程空间。
    * **符号解析 (Symbol Resolution):**  遍历 `libmylib.so` 的 `.dynamic` 段和 `.symtab`，找到所有未定义的符号 (例如 `thrd_create`, `mtx_lock`)。然后在 `libc.so` 的符号表中查找这些符号的定义。
    * **重定位 (Relocation):**  将 `libmylib.so` 中调用 `thrd_create` 和 `mtx_lock` 的地址更新为 `libc.so` 中对应函数的实际地址。

**假设输入与输出 (逻辑推理):**

这个测试文件主要是验证声明，逻辑比较直接。

* **假设输入:**  系统正确安装了 Bionic 库，并且 `<threads.h>` 文件存在且内容符合 C11 标准。
* **预期输出:**  测试程序成功编译和运行，并且 `threads_h()` 函数中的所有断言 (通过 `MACRO`, `TYPE`, `FUNCTION` 等宏进行检查) 都通过，不会产生错误或警告。

**用户或编程常见的使用错误举例说明:**

虽然这个文件本身不涉及用户代码，但它测试的线程管理功能是多线程编程中容易出错的地方：

* **死锁 (Deadlock):** 两个或多个线程互相等待对方释放资源而导致无限期阻塞。
    ```c
    #include <threads.h>
    #include <stdio.h>

    mtx_t mtx1, mtx2;

    int thread1_func(void* arg) {
        mtx_lock(&mtx1);
        printf("Thread 1 acquired mtx1\n");
        thrd_sleep(&(struct timespec){.tv_sec = 1}, NULL); // 模拟持有锁一段时间
        mtx_lock(&mtx2); // 可能在这里死锁
        printf("Thread 1 acquired mtx2\n");
        mtx_unlock(&mtx2);
        mtx_unlock(&mtx1);
        return 0;
    }

    int thread2_func(void* arg) {
        mtx_lock(&mtx2);
        printf("Thread 2 acquired mtx2\n");
        thrd_sleep(&(struct timespec){.tv_sec = 1}, NULL); // 模拟持有锁一段时间
        mtx_lock(&mtx1); // 可能在这里死锁
        printf("Thread 2 acquired mtx1\n");
        mtx_unlock(&mtx1);
        mtx_unlock(&mtx2);
        return 0;
    }

    int main() {
        mtx_init(&mtx1, mtx_plain);
        mtx_init(&mtx2, mtx_plain);

        thrd_t th1, th2;
        thrd_create(&th1, thread1_func, NULL);
        thrd_create(&th2, thread2_func, NULL);

        thrd_join(th1, NULL);
        thrd_join(th2, NULL);

        mtx_destroy(&mtx1);
        mtx_destroy(&mtx2);
        return 0;
    }
    ```
* **竞争条件 (Race Condition):**  程序的输出依赖于多个线程执行的相对顺序，导致结果的不确定性。
    ```c
    #include <threads.h>
    #include <stdio.h>

    int counter = 0;
    mtx_t counter_mtx;

    int incrementer(void* arg) {
        for (int i = 0; i < 100000; ++i) {
            mtx_lock(&counter_mtx);
            counter++;
            mtx_unlock(&counter_mtx);
        }
        return 0;
    }

    int main() {
        mtx_init(&counter_mtx, mtx_plain);
        thrd_t threads[10];
        for (int i = 0; i < 10; ++i) {
            thrd_create(&threads[i], incrementer, NULL);
        }
        for (int i = 0; i < 10; ++i) {
            thrd_join(threads[i], NULL);
        }
        printf("Counter value: %d\n", counter); // 期望输出 1000000，但可能不是
        mtx_destroy(&counter_mtx);
        return 0;
    }
    ```
* **忘记释放锁:**  持有互斥锁后忘记释放，导致其他线程永远无法获取锁。
* **条件变量使用不当:** 例如，在没有持有互斥锁的情况下调用 `cnd_wait`，或者信号和等待的条件不匹配。
* **线程特定存储管理错误:**  忘记在线程退出时清理线程特定存储，可能导致内存泄漏。

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤:**

`bionic/tests/headers/posix/threads_h.c` 是 Bionic 库的测试代码，Android Framework 或 NDK **不会直接执行这个测试文件**。这个测试文件是在 Bionic 库的开发和测试过程中被使用，以确保 `<threads.h>` 的接口正确。

然而，Android Framework 和 NDK 会 **使用** `<threads.h>` 中定义的线程管理功能。

**Android Framework 到 Bionic 的路径：**

1. **Java 代码:** Android Framework 的很多核心功能是用 Java 实现的。例如，`java.lang.Thread` 类用于创建和管理 Java 线程。
2. **Native 方法调用:** `java.lang.Thread` 的底层实现依赖于本地 (native) 方法。这些本地方法通过 JNI (Java Native Interface) 调用到 Android Runtime (ART) 或 Dalvik 虚拟机的本地代码。
3. **ART/Dalvik:** ART 和 Dalvik 虚拟机是用 C++ 实现的，它们会调用 Bionic 库提供的线程管理函数 (通常是 `pthread` 系列函数，但 `<threads.h>` 提供了对 `pthread` 的封装)。Bionic 的 `<threads.h>` 实际上是对 POSIX Threads (pthreads) 的一个封装。

**NDK 到 Bionic 的路径：**

1. **NDK 开发:**  使用 NDK 进行开发的程序员可以直接包含 `<threads.h>` 头文件，并调用其中定义的函数来创建和管理线程。
2. **编译和链接:** NDK 编译工具链会将 NDK 代码编译成机器码，并链接到 Bionic 库。在链接过程中，对 `<threads.h>` 中函数的调用会被解析到 Bionic 库中相应的实现。

**Frida Hook 示例:**

虽然不能直接 hook 到这个测试文件，但可以 hook 到 Bionic 库中 `thrd_create` 函数的实现（它通常会调用底层的 `pthread_create`）。

```python
import frida
import sys

# 连接到 Android 设备或模拟器
device = frida.get_usb_device()
pid = device.spawn(["com.example.myapp"]) # 替换为你的应用包名
process = device.attach(pid)
device.resume(pid)

# Frida 脚本
script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "thrd_create"), {
    onEnter: function(args) {
        console.log("thrd_create called!");
        console.log("  thread: " + args[0]);
        console.log("  func: " + args[1]);
        console.log("  arg: " + args[2]);
        // 可以进一步检查参数，例如函数指针指向的代码
    },
    onLeave: function(retval) {
        console.log("thrd_create returned: " + retval);
    }
});
"""

script = process.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)
```

**解释 Frida Hook 示例:**

1. **连接设备和进程:** 代码首先连接到 Android 设备，然后启动或附加到一个目标应用程序进程。
2. **查找 `thrd_create` 函数:** `Module.findExportByName("libc.so", "thrd_create")` 找到 Bionic 库中 `thrd_create` 函数的地址。
3. **拦截函数调用:** `Interceptor.attach` 用于拦截对 `thrd_create` 函数的调用。
4. **`onEnter` 函数:** 在 `thrd_create` 函数执行之前被调用，可以访问函数的参数。
5. **`onLeave` 函数:** 在 `thrd_create` 函数执行之后被调用，可以访问函数的返回值。
6. **打印信息:**  脚本在控制台上打印出 `thrd_create` 被调用的信息，包括线程 ID 指针、线程函数指针和参数。

通过这个 Frida 脚本，你可以在目标应用程序调用 `thrd_create` 创建新线程时，观察到这个函数的调用，从而了解 Android Framework 或 NDK 如何使用 Bionic 提供的线程管理功能。  需要注意的是，Bionic 的 `thrd_create` 内部可能会调用底层的 `pthread_create`，因此 hook `pthread_create` 也是一个选择。

Prompt: 
```
这是目录为bionic/tests/headers/posix/threads_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#if __has_include(<threads.h>)

#include <threads.h>

#include "header_checks.h"

thread_local int t;

static void threads_h() {
  MACRO(ONCE_FLAG_INIT);
  MACRO(TSS_DTOR_ITERATIONS);

  TYPE(cnd_t);
  TYPE(thrd_t);
  TYPE(tss_t);
  TYPE(mtx_t);

  TYPE(tss_dtor_t);
  TYPE(thrd_start_t);

  TYPE(once_flag);

  int enumeration_constants = mtx_plain | mtx_recursive | mtx_timed |
      thrd_timedout | thrd_success | thrd_busy | thrd_error | thrd_nomem;

  FUNCTION(call_once, void (*f)(once_flag*, void (*)(void)));

  FUNCTION(cnd_broadcast, int (*f)(cnd_t*));
  FUNCTION(cnd_destroy, void (*f)(cnd_t*));
  FUNCTION(cnd_init, int (*f)(cnd_t*));
  FUNCTION(cnd_signal, int (*f)(cnd_t*));
  FUNCTION(cnd_timedwait, int (*f)(cnd_t*, mtx_t*, const struct timespec*));
  FUNCTION(cnd_wait, int (*f)(cnd_t*, mtx_t*));

  FUNCTION(mtx_destroy, void (*f)(mtx_t*));
  FUNCTION(mtx_init, int (*f)(mtx_t*, int));
  FUNCTION(mtx_lock, int (*f)(mtx_t*));
  FUNCTION(mtx_timedlock, int (*f)(mtx_t*, const struct timespec*));
  FUNCTION(mtx_trylock, int (*f)(mtx_t*));
  FUNCTION(mtx_unlock, int (*f)(mtx_t*));

  FUNCTION(thrd_create, int (*f)(thrd_t*, thrd_start_t, void*));
  FUNCTION(thrd_current, thrd_t (*f)(void));
  FUNCTION(thrd_detach, int (*f)(thrd_t));
  FUNCTION(thrd_equal, int (*f)(thrd_t, thrd_t));
  FUNCTION(thrd_exit, void (*f)(int));
  FUNCTION(thrd_join, int (*f)(thrd_t, int*));
  FUNCTION(thrd_sleep, int (*f)(const struct timespec*, struct timespec*));
  FUNCTION(thrd_yield, void (*f)(void));

  FUNCTION(tss_create, int (*f)(tss_t*, tss_dtor_t));
  FUNCTION(tss_delete, void (*f)(tss_t));
  FUNCTION(tss_get, void* (*f)(tss_t));
  FUNCTION(tss_set, int (*f)(tss_t, void*));
}

#define DO_NOT_INCLUDE_TIME_H
#include "time_h.c"

#endif

"""

```