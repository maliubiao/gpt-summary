Response:
Let's break down the thought process for answering the request about `bionic/tests/headers/posix/pthread_h.c`.

**1. Understanding the Core Question:**

The request is about analyzing a *test file* (`pthread_h.c`) within the Android Bionic library. It's not the implementation of `pthread.h` itself, but a file that checks if the `pthread.h` header includes the expected declarations and macros. This is a crucial distinction. The request asks about the *functionality of this test file*, not the functionality of the pthreads library itself.

**2. Initial Analysis of the Code:**

* **Includes:** The file includes `<pthread.h>` and other test-related headers (`header_checks.h`, `sched_h.c`, `time_h.c`). This immediately suggests its purpose is to verify the contents of `pthread.h`.
* **`pthread_h()` function:** This function is the core of the test. It uses `MACRO()` and `FUNCTION()` macros. These strongly indicate a mechanism for checking the *existence* of macros and function declarations.
* **`MACRO()` calls:** These calls list various `PTHREAD_*` macros (e.g., `PTHREAD_CREATE_DETACHED`). This confirms the test is verifying macro definitions.
* **`TYPE()` calls:** These calls list various `pthread_*_t` types (e.g., `pthread_attr_t`). This confirms the test is verifying type definitions.
* **`FUNCTION()` calls:** These calls list numerous `pthread_*` functions along with their function pointer signatures. This confirms the test is verifying function declarations.
* **`#if !defined(__BIONIC__)` blocks:**  These blocks indicate features that are *not* supported by Bionic's pthreads implementation. This is a critical piece of information for relating the test to Android's specifics.
* **`PTHREAD_COND_INITIALIZER`, etc.:** These check the existence of initializer macros.
* **`#error` directives:**  The presence of `#error pthread_cleanup_pop` and `#error pthread_cleanup_push` indicates that these specific macros *must* be defined.
* **Inclusion of `sched_h.c` and `time_h.c`:** This section tests if including `pthread.h` also makes the symbols from `<sched.h>` and `<time.h>` visible, as mandated by POSIX.

**3. Answering the Specific Questions:**

Now, address each part of the request systematically:

* **Functionality:**  Based on the code analysis, the primary function is to verify the presence of POSIX thread-related macros, types, and function declarations within the `pthread.h` header file in Android's Bionic library. It also checks for specific initializers.

* **Relationship to Android:**  The `#if !defined(__BIONIC__)` blocks are key here. They highlight differences between standard POSIX and Bionic's implementation. Examples include the lack of thread cancellation and robust mutexes in Bionic. This directly relates to Android's implementation choices.

* **Detailed Explanation of libc Functions:** This is a tricky part, as the *test file itself doesn't implement these functions*. The correct answer is to state that the file *tests for the presence of declarations*, not the implementation. Briefly mentioning the general purpose of some common functions (like `pthread_create`, `pthread_mutex_lock`) is helpful for context.

* **Dynamic Linker Functionality:**  This test file doesn't directly interact with the dynamic linker. It checks header definitions. Therefore, the correct answer is to state this and explain that dynamic linking happens at a different stage when the actual pthreads library (`libc.so`) is loaded by the linker. A sample `libc.so` layout and the linking process explanation can be provided generally, but it's not specific to *this test file*.

* **Logical Reasoning (Hypothetical Input/Output):**  Since this is a test file, the "input" is the `pthread.h` header. The "output" is either a successful compilation (if all checks pass) or a compilation error (if a check fails, like a missing macro).

* **Common Usage Errors:**  While this test file doesn't directly expose user errors, common pthreads programming errors are relevant. Examples include forgetting to initialize mutexes, deadlocks, race conditions, and improper handling of detached threads.

* **Android Framework/NDK Path and Frida Hooking:** This requires understanding how the Android build system works. Explain that the NDK provides the headers, the framework relies on the underlying Bionic library, and how tests like this are part of the Bionic build process. A Frida hook example should target a *real usage* of a pthreads function (e.g., `pthread_create`) within an Android application. Hooking the *test itself* isn't very practical.

**4. Structuring the Response:**

Organize the answer clearly, using headings and bullet points to address each part of the request. Be precise in the language, especially when distinguishing between testing declarations and implementing functionality.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This file implements pthreads functionality."  **Correction:** Realize it's a *test* file, not the implementation.
* **Initial thought:** "Explain how `pthread_create` works internally." **Correction:**  The test checks for its declaration. Briefly mention its purpose, but don't dive into the Bionic implementation details (which are in `libc.so`).
* **Initial thought:** "Provide a Frida hook for this specific test file." **Correction:**  A more useful Frida example targets a regular Android application using pthreads.

By following this structured approach, carefully analyzing the code, and understanding the context of a *test file*, you can generate a comprehensive and accurate answer to the request.好的，让我们详细分析一下 `bionic/tests/headers/posix/pthread_h.c` 这个文件。

**文件功能:**

这个 `pthread_h.c` 文件是 Android Bionic 库中的一个 **测试文件**。它的主要功能是 **验证 `pthread.h` 头文件是否正确地定义了 POSIX 标准线程相关的宏、类型和函数声明**。 换句话说，它不是 `pthread` 功能的实现，而是用来确保 `pthread.h` 提供了开发者期望的接口。

具体来说，它做了以下检查：

1. **检查宏定义 (`MACRO()`):**  验证了诸如 `PTHREAD_CREATE_DETACHED`、`PTHREAD_MUTEX_NORMAL` 等 pthread 相关的宏是否被定义。其中，它也通过 `#if !defined(__BIONIC__)` 来区分了标准 POSIX 定义和 Bionic 特有的差异，例如 Bionic 不支持线程取消 (thread cancellation) 和 robust mutexes。
2. **检查类型定义 (`TYPE()`):** 验证了 `pthread_attr_t`、`pthread_mutex_t` 等 pthread 相关的类型是否被定义。
3. **检查函数声明 (`FUNCTION()`):** 验证了诸如 `pthread_create`、`pthread_mutex_lock` 等 pthread 相关的函数是否被正确声明，并检查了其函数指针的类型签名是否正确。
4. **检查初始化宏:** 验证了像 `PTHREAD_COND_INITIALIZER` 和 `PTHREAD_MUTEX_INITIALIZER` 这样的用于静态初始化的宏定义。
5. **检查头文件包含:**  通过包含 `sched_h.c` 和 `time_h.c` (并使用 `#define DO_NOT_INCLUDE_*_H`)，验证了包含 `<pthread.h>` 是否会按照 POSIX 标准使 `<sched.h>` 和 `<time.h>` 中定义的符号可见。
6. **检查特定宏的存在:**  通过 `#if !defined(pthread_cleanup_pop)` 和 `#if !defined(pthread_cleanup_push)` 来断言这两个宏必须被定义。

**与 Android 功能的关系及举例:**

这个测试文件直接关系到 Android 系统中多线程编程的基础设施。`pthread.h` 中定义的接口是 Android NDK (Native Development Kit) 中供 C/C++ 开发者使用的标准线程 API。

**举例说明:**

* 当 Android 应用的 Native 层代码需要创建新线程时，会包含 `<pthread.h>` 头文件，然后调用 `pthread_create` 函数。这个测试文件确保了 `pthread_create` 的声明在 Bionic 提供的 `pthread.h` 中是存在的且正确的。
* 当 Native 代码需要使用互斥锁来同步线程时，会使用 `pthread_mutex_t` 类型来声明互斥锁变量，并调用 `pthread_mutex_lock` 和 `pthread_mutex_unlock` 等函数。这个测试文件验证了这些类型和函数的声明是否正确。
*  `#if !defined(__BIONIC__)`  部分体现了 Android Bionic 对 POSIX 标准的裁剪。例如，Android Bionic 不支持线程取消功能，因此 `PTHREAD_CANCEL_ASYNCHRONOUS` 等相关宏在 Android 上不会被定义。开发者在使用 NDK 进行跨平台开发时，需要注意这些差异。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个 **测试文件本身并不实现任何 libc 函数**。它的作用是检查这些函数的声明是否存在。 libc 函数的实际实现位于 Bionic 库的核心部分，例如 `libc.so`。

如果要详细解释 `pthread.h` 中声明的 libc 函数的实现，需要查看 Bionic 的源代码中对应的函数实现。 例如：

* **`pthread_create`:**  在 Bionic 中，`pthread_create` 的实现会调用底层的内核 `clone` 系统调用来创建一个新的进程（或者更准确地说，一个轻量级进程，即线程），并执行指定的线程函数。它还会处理线程属性的设置，例如栈大小、调度策略等。
* **`pthread_mutex_lock`:**  Bionic 中 `pthread_mutex_lock` 的实现通常使用原子操作和 futex (fast userspace mutex) 机制。当互斥锁未被占用时，会使用原子操作快速获取锁。如果锁被占用，线程会进入休眠状态，等待锁被释放时通过 futex 机制唤醒。
* **`pthread_cond_wait`:**  `pthread_cond_wait` 的实现通常需要与互斥锁配合使用。线程在调用 `pthread_cond_wait` 时，会原子地释放传入的互斥锁并进入等待状态，等待条件变量被唤醒。当被唤醒时，会重新尝试获取之前释放的互斥锁。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个 **测试文件本身不直接涉及 dynamic linker 的功能**。它的作用是检查头文件内容。

Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是在程序启动时加载所需的共享库 (`.so` 文件) 并解析符号引用，将程序代码中使用的函数和变量链接到共享库中实际的地址。

**`libc.so` 布局样本 (简化):**

```
libc.so:
  .text:  // 存放代码段
    pthread_create:  // pthread_create 函数的机器码
    pthread_mutex_lock: // pthread_mutex_lock 函数的机器码
    ...

  .data:  // 存放已初始化的全局变量和静态变量
    ...

  .bss:   // 存放未初始化的全局变量和静态变量
    ...

  .dynsym: // 动态符号表，包含导出的符号信息 (例如函数名、地址)
    pthread_create
    pthread_mutex_lock
    ...

  .dynstr: // 动态符号字符串表，存储符号名称
    "pthread_create"
    "pthread_mutex_lock"
    ...

  .plt:    // Procedure Linkage Table，用于延迟绑定
    条目指向 pthread_create 的解析代码
    条目指向 pthread_mutex_lock 的解析代码
    ...

  .got.plt: // Global Offset Table (for PLT)，存储解析后的函数地址 (初始时是 PLT 的地址)
    pthread_create 的地址 (初始是 PLT 中的地址)
    pthread_mutex_lock 的地址 (初始是 PLT 中的地址)
    ...
```

**链接的处理过程 (简化):**

1. **加载共享库:** 当应用启动时，dynamic linker 会根据可执行文件的依赖信息加载 `libc.so` 到内存中。
2. **解析符号:** 当程序执行到调用 `pthread_create` 的代码时，如果使用的是 **延迟绑定** (默认情况)，程序会跳转到 `.plt` 中 `pthread_create` 对应的条目。
3. **PLT 和 GOT 交互:**  PLT 条目会首先查找 `.got.plt` 中 `pthread_create` 的地址。
4. **第一次调用:** 第一次调用时，`.got.plt` 中存储的是 PLT 条目的地址。PLT 条目会调用 dynamic linker 的解析函数。
5. **符号查找:** dynamic linker 会在 `libc.so` 的 `.dynsym` 中查找 `pthread_create` 的符号，并找到其在 `.text` 段中的实际地址。
6. **更新 GOT:** dynamic linker 会将找到的实际地址写入 `.got.plt` 中 `pthread_create` 对应的位置。
7. **跳转执行:**  dynamic linker 将控制权返回给 PLT 条目，PLT 条目现在会从 `.got.plt` 中读取到 `pthread_create` 的真实地址，并跳转到该地址执行。
8. **后续调用:** 后续对 `pthread_create` 的调用会直接跳转到 `.got.plt` 中存储的真实地址，不再需要 dynamic linker 介入。

**如果做了逻辑推理，请给出假设输入与输出:**

这个测试文件主要是静态检查，并没有复杂的运行时逻辑推理。其 "输入" 可以认为是 `pthread.h` 文件的内容，"输出" 是测试程序是否编译通过且所有断言都成立。

**假设输入:**  `pthread.h` 文件中 `pthread_mutex_lock` 函数的声明被错误地写成了 `int pthread_mutex_lock(pthread_mutex_t)` (缺少了指针 `*`)。

**输出:**  测试程序在编译阶段会报错，因为 `FUNCTION(pthread_mutex_lock, int (*f)(pthread_mutex_t*))` 宏会检查函数指针的类型签名，发现与实际声明不符。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

虽然这个测试文件本身不涉及用户代码，但它测试的 `pthread` API 是用户编程中经常使用的，因此可以列举一些常见的使用错误：

1. **忘记初始化互斥锁或条件变量:**
   ```c
   pthread_mutex_t mutex;
   // 忘记调用 pthread_mutex_init(&mutex, NULL);

   pthread_mutex_lock(&mutex); // 可能导致未定义行为
   ```

2. **死锁 (Deadlock):**  多个线程互相等待对方释放资源，导致所有线程都无法继续执行。
   ```c
   pthread_mutex_t mutex1, mutex2;
   pthread_mutex_init(&mutex1, NULL);
   pthread_mutex_init(&mutex2, NULL);

   void* thread1_func(void* arg) {
       pthread_mutex_lock(&mutex1);
       sleep(1);
       pthread_mutex_lock(&mutex2); // 如果线程 2 已经锁定了 mutex2，则会发生死锁
       // ...
       pthread_mutex_unlock(&mutex2);
       pthread_mutex_unlock(&mutex1);
       return NULL;
   }

   void* thread2_func(void* arg) {
       pthread_mutex_lock(&mutex2);
       sleep(1);
       pthread_mutex_lock(&mutex1); // 如果线程 1 已经锁定了 mutex1，则会发生死锁
       // ...
       pthread_mutex_unlock(&mutex1);
       pthread_mutex_unlock(&mutex2);
       return NULL;
   }
   ```

3. **竞争条件 (Race Condition):** 程序的输出依赖于多个线程执行的相对顺序，导致不可预测的结果。
   ```c
   int counter = 0;

   void* increment_counter(void* arg) {
       for (int i = 0; i < 100000; ++i) {
           counter++; // 多个线程同时访问和修改 counter，可能导致竞争条件
       }
       return NULL;
   }
   ```

4. **对未锁定的互斥锁解锁:**
   ```c
   pthread_mutex_t mutex;
   pthread_mutex_init(&mutex, NULL);

   pthread_mutex_unlock(&mutex); // 错误：尝试解锁一个未被锁定的互斥锁
   ```

5. **忘记释放互斥锁:** 导致其他线程一直阻塞等待。

6. **在信号处理程序中使用非异步信号安全的函数:**  `pthread` 函数通常不是异步信号安全的。

7. **错误地使用 `pthread_join`:**  例如，在已经 detached 的线程上调用 `pthread_join` 会导致错误。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **NDK (Native Development Kit):** 当开发者使用 NDK 构建 Native 代码时，NDK 提供的头文件 (`sysroot/usr/include/pthread.h`) 就包含了这个测试文件所验证的内容。编译器在编译 Native 代码时会包含这些头文件。

2. **Android Framework:** Android Framework 本身是用 Java 编写的，但在其底层实现中，很多功能依赖于 Native 代码 (例如，ART 虚拟机、各种系统服务)。这些 Native 代码会使用 Bionic 库提供的 `pthread` API。

3. **Bionic 库构建:**  在 Android 系统编译过程中，Bionic 库会被编译出来，其中包括 `libc.so`，其中包含了 `pthread` 函数的实现。 `bionic/tests/headers/posix/pthread_h.c` 这样的测试文件会在 Bionic 库的测试阶段被编译和执行，以确保 `pthread.h` 的正确性。

**Frida Hook 示例调试步骤:**

假设我们想 hook `pthread_create` 函数，看看在 Android 应用程序中何时以及如何创建线程。

```python
import frida
import sys

package_name = "your.app.package.name" # 替换成你要调试的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Received: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Is the app running?")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
    onEnter: function(args) {
        console.log("[+] pthread_create called");
        console.log("    Thread ID pointer:", args[0]);
        console.log("    Attributes:", args[1]);
        console.log("    Start routine:", args[2]);
        console.log("    Arg:", args[3]);
        // 可以读取 args 指向的内存，例如读取线程属性
        // if (args[1] != 0) {
        //     console.log("    Detachstate:", Memory.readU32(args[1].add(8))); // 假设 detachstate 是偏移 8 的位置
        // }
    },
    onLeave: function(retval) {
        console.log("[+] pthread_create returned:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**步骤说明:**

1. **安装 Frida:** 确保你的电脑上安装了 Frida 和 Frida-server，并且 Frida-server 运行在你的 Android 设备上。
2. **找到目标进程:** 将 `your.app.package.name` 替换成你要调试的 Android 应用程序的包名。
3. **Hook `pthread_create`:**  Frida 脚本使用 `Interceptor.attach` 来 hook `libc.so` 中的 `pthread_create` 函数。
4. **`onEnter`:** 当 `pthread_create` 被调用时，`onEnter` 函数会被执行，我们可以打印出传递给 `pthread_create` 的参数，例如线程 ID 指针、属性、线程函数和参数。
5. **`onLeave`:** 当 `pthread_create` 执行完毕返回时，`onLeave` 函数会被执行，我们可以打印出返回值。
6. **执行脚本:** 运行 Python 脚本，Frida 会连接到目标应用程序，并 hook `pthread_create` 函数。每当应用程序调用 `pthread_create` 时，你就会在控制台上看到相应的输出信息。

通过这种方式，你可以观察 Android 应用程序在运行时如何使用 `pthread` API，例如创建了哪些线程，传递了什么参数，从而深入了解 Android Framework 或 NDK 如何一步步地使用到这些底层的线程功能。

希望这个详细的解释能够帮助你理解 `bionic/tests/headers/posix/pthread_h.c` 文件的作用以及它在 Android 系统中的地位。

### 提示词
```
这是目录为bionic/tests/headers/posix/pthread_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2017 The Android Open Source Project
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

#include "header_checks.h"

static void pthread_h() {
  MACRO(PTHREAD_BARRIER_SERIAL_THREAD);

#if !defined(__BIONIC__) // No thread cancellation on Android.
  MACRO(PTHREAD_CANCEL_ASYNCHRONOUS);
  MACRO(PTHREAD_CANCEL_ENABLE);
  MACRO(PTHREAD_CANCEL_DEFERRED);
  MACRO(PTHREAD_CANCEL_DISABLE);
  MACRO(PTHREAD_CANCELED);
#endif

  MACRO(PTHREAD_CREATE_DETACHED);
  MACRO(PTHREAD_CREATE_JOINABLE);
  MACRO(PTHREAD_EXPLICIT_SCHED);
  MACRO(PTHREAD_INHERIT_SCHED);
  MACRO(PTHREAD_MUTEX_DEFAULT);
  MACRO(PTHREAD_MUTEX_ERRORCHECK);
  MACRO(PTHREAD_MUTEX_NORMAL);
  MACRO(PTHREAD_MUTEX_RECURSIVE);

#if !defined(__BIONIC__) // No robust mutexes on Android.
  MACRO(PTHREAD_MUTEX_ROBUST);
  MACRO(PTHREAD_MUTEX_STALLED);
#endif

  MACRO(PTHREAD_ONCE_INIT);

  MACRO(PTHREAD_PRIO_INHERIT);
  MACRO(PTHREAD_PRIO_NONE);
#if !defined(__BIONIC__)
  MACRO(PTHREAD_PRIO_PROTECT);
#endif

  MACRO(PTHREAD_PROCESS_SHARED);
  MACRO(PTHREAD_PROCESS_PRIVATE);
  MACRO(PTHREAD_SCOPE_PROCESS);
  MACRO(PTHREAD_SCOPE_SYSTEM);

  pthread_cond_t c0 = PTHREAD_COND_INITIALIZER;
  pthread_mutex_t m0 = PTHREAD_MUTEX_INITIALIZER;
  pthread_rwlock_t rw0 = PTHREAD_RWLOCK_INITIALIZER;

  TYPE(pthread_attr_t);
  TYPE(pthread_barrier_t);
  TYPE(pthread_barrierattr_t);
  TYPE(pthread_cond_t);
  TYPE(pthread_condattr_t);
  TYPE(pthread_key_t);
  TYPE(pthread_mutex_t);
  TYPE(pthread_mutexattr_t);
  TYPE(pthread_once_t);
  TYPE(pthread_rwlock_t);
  TYPE(pthread_rwlockattr_t);
  TYPE(pthread_spinlock_t);
  TYPE(pthread_t);

  FUNCTION(pthread_atfork, int (*f)(void (*)(void), void (*)(void), void (*)(void)));
  FUNCTION(pthread_attr_destroy, int (*f)(pthread_attr_t*));
  FUNCTION(pthread_attr_getdetachstate, int (*f)(const pthread_attr_t*, int*));
  FUNCTION(pthread_attr_getguardsize, int (*f)(const pthread_attr_t*, size_t*));
  FUNCTION(pthread_attr_getinheritsched, int (*f)(const pthread_attr_t*, int*));
  FUNCTION(pthread_attr_getschedparam, int (*f)(const pthread_attr_t*, struct sched_param*));
  FUNCTION(pthread_attr_getschedpolicy, int (*f)(const pthread_attr_t*, int*));
  FUNCTION(pthread_attr_getscope, int (*f)(const pthread_attr_t*, int*));
  FUNCTION(pthread_attr_getstack, int (*f)(const pthread_attr_t*, void**, size_t*));
  FUNCTION(pthread_attr_getstacksize, int (*f)(const pthread_attr_t*, size_t*));
  FUNCTION(pthread_attr_init, int (*f)(pthread_attr_t*));
  FUNCTION(pthread_attr_setdetachstate, int (*f)(pthread_attr_t*, int));
  FUNCTION(pthread_attr_setguardsize, int (*f)(pthread_attr_t*, size_t));
  FUNCTION(pthread_attr_setinheritsched, int (*f)(pthread_attr_t*, int));
  FUNCTION(pthread_attr_setschedparam, int (*f)(pthread_attr_t*, const struct sched_param*));
  FUNCTION(pthread_attr_setschedpolicy, int (*f)(pthread_attr_t*, int));
  FUNCTION(pthread_attr_setscope, int (*f)(pthread_attr_t*, int));
  FUNCTION(pthread_attr_setstack, int (*f)(pthread_attr_t*, void*, size_t));
  FUNCTION(pthread_attr_setstacksize, int (*f)(pthread_attr_t*, size_t));
  FUNCTION(pthread_barrier_destroy, int (*f)(pthread_barrier_t*));
  FUNCTION(pthread_barrier_init, int (*f)(pthread_barrier_t*, const pthread_barrierattr_t*, unsigned));
  FUNCTION(pthread_barrier_wait, int (*f)(pthread_barrier_t*));
  FUNCTION(pthread_barrierattr_destroy, int (*f)(pthread_barrierattr_t*));
  FUNCTION(pthread_barrierattr_getpshared, int (*f)(const pthread_barrierattr_t*, int*));
  FUNCTION(pthread_barrierattr_init, int (*f)(pthread_barrierattr_t*));
  FUNCTION(pthread_barrierattr_setpshared, int (*f)(pthread_barrierattr_t*, int));
#if !defined(__BIONIC__) // No thread cancellation on Android.
  FUNCTION(pthread_cancel, int (*f)(pthread_t));
#endif
  FUNCTION(pthread_cond_broadcast, int (*f)(pthread_cond_t*));
  FUNCTION(pthread_cond_destroy, int (*f)(pthread_cond_t*));
  FUNCTION(pthread_cond_init, int (*f)(pthread_cond_t*, const pthread_condattr_t*));
  FUNCTION(pthread_cond_signal, int (*f)(pthread_cond_t*));
  FUNCTION(pthread_cond_timedwait, int (*f)(pthread_cond_t*, pthread_mutex_t*, const struct timespec*));
  FUNCTION(pthread_cond_wait, int (*f)(pthread_cond_t*, pthread_mutex_t*));
  FUNCTION(pthread_condattr_destroy, int (*f)(pthread_condattr_t*));
  FUNCTION(pthread_condattr_getclock, int (*f)(const pthread_condattr_t*, clockid_t*));
  FUNCTION(pthread_condattr_getpshared, int (*f)(const pthread_condattr_t*, int*));
  FUNCTION(pthread_condattr_init, int (*f)(pthread_condattr_t*));
  FUNCTION(pthread_condattr_setclock, int (*f)(pthread_condattr_t*, clockid_t));
  FUNCTION(pthread_condattr_setpshared, int (*f)(pthread_condattr_t*, int));
  FUNCTION(pthread_create, int (*f)(pthread_t*, const pthread_attr_t*, void* (*)(void*), void*));
  FUNCTION(pthread_detach, int (*f)(pthread_t));
  FUNCTION(pthread_equal, int (*f)(pthread_t, pthread_t));
  FUNCTION(pthread_exit, void (*f)(void*));
#if !defined(__BIONIC__) // Marked obsolescent.
  FUNCTION(pthread_getconcurrency, int (*f)(void));
#endif
  FUNCTION(pthread_getcpuclockid, int (*f)(pthread_t, clockid_t*));
  FUNCTION(pthread_getschedparam, int (*f)(pthread_t, int*, struct sched_param*));
  FUNCTION(pthread_getspecific, void* (*f)(pthread_key_t));
  FUNCTION(pthread_join, int (*f)(pthread_t, void**));
  FUNCTION(pthread_key_create, int (*f)(pthread_key_t*, void (*)(void*)));
  FUNCTION(pthread_key_delete, int (*f)(pthread_key_t));
#if !defined(__BIONIC__) // No robust mutexes on Android.
  FUNCTION(pthread_mutex_consistent, int (*f)(pthread_mutex_t*));
#endif
  FUNCTION(pthread_mutex_destroy, int (*f)(pthread_mutex_t*));
#if !defined(__BIONIC__) // No robust mutexes on Android.
  FUNCTION(pthread_mutex_getprioceiling, int (*f)(const pthread_mutex_t*, int*));
#endif
  FUNCTION(pthread_mutex_init, int (*f)(pthread_mutex_t*, const pthread_mutexattr_t*));
  FUNCTION(pthread_mutex_lock, int (*f)(pthread_mutex_t*));
#if !defined(__BIONIC__) // No robust mutexes on Android.
  FUNCTION(pthread_mutex_setprioceiling, int (*f)(pthread_mutex_t*, int, int*));
#endif
  FUNCTION(pthread_mutex_timedlock, int (*f)(pthread_mutex_t*, const struct timespec*));
  FUNCTION(pthread_mutex_trylock, int (*f)(pthread_mutex_t*));
  FUNCTION(pthread_mutex_unlock, int (*f)(pthread_mutex_t*));
  FUNCTION(pthread_mutexattr_destroy, int (*f)(pthread_mutexattr_t*));
#if !defined(__BIONIC__) // No robust mutexes on Android.
  FUNCTION(pthread_mutexattr_getprioceiling, int (*f)(const pthread_mutexattr_t*, int*));
#endif
  FUNCTION(pthread_mutexattr_getprotocol, int (*f)(const pthread_mutexattr_t*, int*));
  FUNCTION(pthread_mutexattr_getpshared, int (*f)(const pthread_mutexattr_t*, int*));
#if !defined(__BIONIC__) // No robust mutexes on Android.
  FUNCTION(pthread_mutexattr_getrobust, int (*f)(const pthread_mutexattr_t*, int*));
#endif
  FUNCTION(pthread_mutexattr_gettype, int (*f)(const pthread_mutexattr_t*, int*));
  FUNCTION(pthread_mutexattr_init, int (*f)(pthread_mutexattr_t*));
#if !defined(__BIONIC__) // No robust mutexes on Android.
  FUNCTION(pthread_mutexattr_setprioceiling, int (*f)(pthread_mutexattr_t*, int));
#endif
  FUNCTION(pthread_mutexattr_setprotocol, int (*f)(pthread_mutexattr_t*, int));
  FUNCTION(pthread_mutexattr_setpshared, int (*f)(pthread_mutexattr_t*, int));
#if !defined(__BIONIC__) // No robust mutexes on Android.
  FUNCTION(pthread_mutexattr_setrobust, int (*f)(pthread_mutexattr_t*, int));
#endif
  FUNCTION(pthread_mutexattr_settype, int (*f)(pthread_mutexattr_t*, int));
  FUNCTION(pthread_once, int (*f)(pthread_once_t*, void (*)(void)));
  FUNCTION(pthread_rwlock_destroy, int (*f)(pthread_rwlock_t*));
  FUNCTION(pthread_rwlock_init, int (*f)(pthread_rwlock_t*, const pthread_rwlockattr_t*));
  FUNCTION(pthread_rwlock_rdlock, int (*f)(pthread_rwlock_t*));
  FUNCTION(pthread_rwlock_timedrdlock, int (*f)(pthread_rwlock_t*, const struct timespec*));
  FUNCTION(pthread_rwlock_timedwrlock, int (*f)(pthread_rwlock_t*, const struct timespec*));
  FUNCTION(pthread_rwlock_tryrdlock, int (*f)(pthread_rwlock_t*));
  FUNCTION(pthread_rwlock_trywrlock, int (*f)(pthread_rwlock_t*));
  FUNCTION(pthread_rwlock_unlock, int (*f)(pthread_rwlock_t*));
  FUNCTION(pthread_rwlock_wrlock, int (*f)(pthread_rwlock_t*));
  FUNCTION(pthread_rwlockattr_destroy, int (*f)(pthread_rwlockattr_t*));
  FUNCTION(pthread_rwlockattr_getpshared, int (*f)(const pthread_rwlockattr_t*, int*));
  FUNCTION(pthread_rwlockattr_init, int (*f)(pthread_rwlockattr_t*));
  FUNCTION(pthread_rwlockattr_setpshared, int (*f)(pthread_rwlockattr_t*, int));
  FUNCTION(pthread_self, pthread_t (*f)(void));
#if !defined(__BIONIC__) // No thread cancellation on Android.
  FUNCTION(pthread_setcancelstate, int (*f)(int, int*));
  FUNCTION(pthread_setcanceltype, int (*f)(int, int*));
#endif
#if !defined(__BIONIC__) // Marked obsolescent.
  FUNCTION(pthread_setconcurrency, int (*f)(int));
#endif
  FUNCTION(pthread_setschedparam, int (*f)(pthread_t, int, const struct sched_param*));
  FUNCTION(pthread_setschedprio, int (*f)(pthread_t, int));
  FUNCTION(pthread_setspecific, int (*f)(pthread_key_t, const void*));
  FUNCTION(pthread_spin_destroy, int (*f)(pthread_spinlock_t*));
  FUNCTION(pthread_spin_init, int (*f)(pthread_spinlock_t*, int));
  FUNCTION(pthread_spin_lock, int (*f)(pthread_spinlock_t*));
  FUNCTION(pthread_spin_trylock, int (*f)(pthread_spinlock_t*));
  FUNCTION(pthread_spin_unlock, int (*f)(pthread_spinlock_t*));
#if !defined(__BIONIC__) // No thread cancellation on Android.
  FUNCTION(pthread_testcancel, void (*f)(void));
#endif

#if !defined(pthread_cleanup_pop)
#error pthread_cleanup_pop
#endif
#if !defined(pthread_cleanup_push)
#error pthread_cleanup_push
#endif
}

// POSIX: "Inclusion of the <pthread.h> header shall make symbols defined in the
// headers <sched.h> and <time.h> visible."

#define DO_NOT_INCLUDE_SCHED_H
#include "sched_h.c"
#define DO_NOT_INCLUDE_TIME_H
#include "time_h.c"
```