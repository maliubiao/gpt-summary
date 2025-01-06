Response:
Let's break down the thought process to answer the request about the `pthread_test.cpp` file.

**1. Understanding the Core Request:**

The primary goal is to analyze a C++ source file (`pthread_test.cpp`) and explain its functionality, its relationship to Android, the implementation details of included libc functions, its interaction with the dynamic linker, potential errors, and how it's reached within the Android framework/NDK. The request specifies a focus on the *first part* of the file.

**2. Initial Analysis of the Code (Skimming and Keyword Spotting):**

* **Includes:**  The included headers are a strong indicator of the file's purpose. I see:
    * `<gtest/gtest.h>`: Immediately tells me this is a test file using Google Test.
    * `<pthread.h>`: Confirms it's testing pthreads functionality.
    * `<errno.h>`, `<limits.h>`, `<stdio.h>`, etc.:  Standard C library headers, hinting at interactions with the underlying operating system.
    * `<sys/mman.h>`, `<sys/prctl.h>`, `<sys/resource.h>`, `<sys/syscall.h>`:  System-level calls, likely related to memory management, process control, and direct system interaction.
    * `<atomic>`, `<future>`, `<vector>`: C++ standard library components.
    * `<android-base/...>`: Android-specific utility headers.
    * `"private/bionic_constants.h"`, `"private/bionic_time_conversions.h"`, `"SignalUtils.h"`, `"utils.h"`:  Internal Bionic headers, indicating deeper integration with Android's libc.
* **`TEST(pthread, ...)`:**  The core structure of Google Test cases. Each `TEST` macro defines an individual test. The first argument (`pthread`) suggests these tests are grouped under the `pthread` suite.
* **Assertions (`ASSERT_EQ`, `ASSERT_NE`, `ASSERT_TRUE`, etc.):** Standard Google Test assertions to verify expected outcomes.
* **Function Names (e.g., `pthread_key_create`, `pthread_setspecific`, `pthread_create`, `pthread_join`):** These are key pthread functions, directly indicating the focus of the tests.

**3. Deconstructing the Request into Key Areas:**

To provide a comprehensive answer, I need to address these specific points:

* **Functionality of the file:** What does it *do* overall?
* **Relationship to Android:** How does it relate to the bigger picture of the Android operating system?
* **libc function implementation:**  How are the specific C library functions used here implemented in Bionic?  This requires understanding the underlying system calls or Bionic's internal logic.
* **Dynamic linker:** How does the dynamic linker come into play with pthreads?  This involves understanding shared libraries and symbol resolution.
* **Logical Reasoning (Assumptions & Outputs):**  For individual tests, what are the likely inputs and expected outputs?
* **Common Usage Errors:** What are some mistakes developers might make when using pthreads?
* **Android Framework/NDK Path:** How does execution flow from the Android framework or NDK down to these pthread functions?
* **Frida Hooks:**  How can Frida be used to observe and debug these functions?
* **Summary of Functionality (for Part 1):**  A concise overview of what the initial portion of the file tests.

**4. Deep Dive into the First Part of the Code:**

I'll go through the initial tests, focusing on the included headers and the specific pthread functions being tested:

* **`pthread_key_create` and related tests:**  These tests are about thread-specific data (TSD). They check the creation, deletion, setting, and getting of thread-local storage. The tests involving `PTHREAD_KEYS_MAX` and `sysconf` relate to the limits on the number of TSD keys.
* **`pthread_key_fork`:** This test explores how TSD is handled after a `fork()`.
* **`pthread_key_dirty` and `pthread_heap_allocated_stack`:**  These delve into stack management and potential issues with thread stacks.
* **`static_pthread_key_used_before_creation`:**  Specifically tests a Bionic-specific behavior regarding static pthread keys.
* **`pthread_create` and related tests:** Focuses on thread creation, joining, detachment, and handling errors like `EAGAIN`.
* **`pthread_join_self`:**  Tests the expected deadlock when a thread tries to join itself.
* **`pthread_bug_37410`:**  A specific test case for a known Android bug.
* **`pthread_sigmask` and `pthread_sigmask64_SIGTRMIN`:**  Tests the blocking and unblocking of signals within threads.
* **`pthread_setname_np` and `pthread_getname_np`:** Tests setting and retrieving thread names.
* **`pthread_kill`:** Tests sending signals to threads.
* **`pthread_detach`:** Tests detaching threads.
* **`pthread_getcpuclockid`:**  Tests getting the CPU-time clock ID for a thread.
* **`pthread_getschedparam` and `pthread_setschedparam`:** Tests getting and setting thread scheduling parameters.
* **`pthread_join` (error cases):** Tests joining non-existent or already joined threads.
* **`pthread_join__multijoin` and `pthread_join__race`:**  Tests more complex scenarios around joining threads.
* **`pthread_attr_setguardsize` and `pthread_attr_setstacksize`:** Tests setting thread attribute parameters related to stack size and guard pages.
* **`pthread_rwlockattr_smoke` and `pthread_rwlock_init_same_as_PTHREAD_RWLOCK_INITIALIZER`:** Tests read-write lock attributes and initialization.
* **`pthread_rwlock_smoke` and `pthread_rwlock_reader_wakeup_writer`:** Tests basic read-write lock functionality, including locking, unlocking, and wake-up scenarios.

**5. Addressing Specific Request Points (Mental Checklist and Note-Taking):**

* **Functionality:**  Primarily tests the correctness and robustness of Bionic's pthreads implementation.
* **Android Relationship:**  Pthreads are fundamental to multithreading in Android. Examples will be based on common Android use cases (e.g., background tasks, UI threads).
* **libc Implementation:** I'll need to provide high-level explanations of how functions like `pthread_create`, `pthread_join`, `pthread_mutex_lock`, etc., are likely implemented (system calls like `clone`, `futex`, etc.). Detailed, low-level implementation might be too much for this overview but hinting at the underlying mechanisms is important.
* **Dynamic Linker:** Pthreads are part of `libc.so`. I'll need to describe how `libc.so` is loaded and linked. A simplified `libc.so` layout example will be helpful.
* **Logical Reasoning:**  For each test, I'll briefly state the assumed setup and the expected outcome (the assertions).
* **Common Errors:** Examples like forgetting to detach, joining detached threads, race conditions, and improper locking.
* **Android Framework/NDK Path:** Start with a high-level view (Java `Thread`, NDK threads) and trace down to the native `pthread` calls.
* **Frida Hooks:** Provide basic Frida JavaScript examples for intercepting key pthread functions.
* **Summary:** Briefly summarize the tested areas in the first part.

**6. Structuring the Output:**

Organize the answer logically, following the order of the request. Use clear headings and bullet points for readability. Provide code snippets where appropriate (e.g., Frida hooks).

**7. Refinement and Review:**

Before finalizing, review the answer for accuracy, completeness, and clarity. Ensure the language is appropriate and explains technical concepts understandably. Check if all parts of the original request have been addressed. For example, make sure the explanations of libc functions are not just repeating the function signature but provide some insight into *how* they work.

This systematic approach, combining code analysis with an understanding of the underlying system and the specific requirements of the request, helps in generating a comprehensive and accurate answer. The iterative process of analysis, deconstruction, and refinement is key to handling complex technical questions.
好的，这是对 `bionic/tests/pthread_test.cpp` 文件第一部分的分析和归纳。

**文件功能归纳 (第一部分):**

`bionic/tests/pthread_test.cpp` 是 Android Bionic 库中用于测试 `pthread` (POSIX 线程) 相关功能的测试文件。  第一部分主要集中在以下几个方面的功能测试：

1. **线程特定数据 (Thread-Specific Data, TSD):**
   - 测试 `pthread_key_create` 和 `pthread_key_delete` 的基本功能，包括创建和删除线程特定数据的键。
   - 验证 `PTHREAD_KEYS_MAX` 和 `_POSIX_THREAD_KEYS_MAX` 的关系，以及 `sysconf(_SC_THREAD_KEYS_MAX)` 是否返回正确的值。
   - 测试创建多个不同的线程特定数据键，并设置和获取其对应的值。
   - 验证无法创建超过 `PTHREAD_KEYS_MAX` 限制的键。
   - 测试删除键后，`pthread_getspecific` 返回 `nullptr`，且无法再使用 `pthread_setspecific` 设置值。
   - 测试 `fork()` 系统调用后，子进程是否继承了父进程的线程特定数据。
   - 测试在子线程中使用已销毁的键的行为。
   - 测试使用堆分配的栈创建线程的功能。
   - 测试在静态线程键创建之前使用它的行为（Bionic 特有）。

2. **线程创建与管理:**
   - 测试 `pthread_create` 的基本功能，包括创建线程并获取返回值。
   - 测试 `pthread_create` 在资源不足时返回 `EAGAIN` 的情况。
   - 测试 `pthread_detach` 的功能，以及分离线程后 `pthread_join` 的行为。
   - 测试在 `pthread_join` 之后调用 `pthread_detach` 的行为。
   - 测试线程尝试 `pthread_join` 自身时会返回 `EDEADLK`。
   - 测试一个线程等待另一个线程结束 (`pthread_join`)，而主线程退出的情况，以验证死锁避免机制。

3. **线程信号处理:**
   - 测试 `pthread_sigmask` 和 `pthread_sigmask64` 的功能，包括阻塞和取消阻塞信号。
   - 验证 `pthread_sigmask` 与 `sigprocmask` 的一致性。
   - 创建一个子线程使用 `sigwait64` 等待信号，并测试通过 `pthread_kill` 向其发送信号。

4. **线程名称管理:**
   - 测试 `pthread_setname_np` 和 `pthread_getname_np` 的功能，包括设置和获取线程名称。
   - 验证线程名称的长度限制。
   - 测试对不存在或空线程调用线程名称管理函数时的错误处理。

5. **线程信号发送:**
   - 测试 `pthread_kill` 的基本功能，包括向自身发送信号 0（用于检查线程是否存在）。
   - 验证向 `pthread_kill` 传递无效信号时的错误处理。
   - 测试在信号处理函数中调用 `pthread_kill` 的情况。
   - 测试向已退出的线程发送信号时的行为。

6. **线程分离:**
   - 测试对不存在或空线程调用 `pthread_detach` 时的错误处理。

7. **线程时钟:**
   - 测试 `pthread_getcpuclockid` 的功能，获取线程的 CPU 时钟 ID，并使用 `clock_gettime` 获取时间。
   - 测试对不存在或空线程调用 `pthread_getcpuclockid` 时的错误处理。

8. **线程调度参数:**
   - 测试对不存在或空线程调用 `pthread_getschedparam` 和 `pthread_setschedparam` 时的错误处理。
   - 测试对不存在或空线程调用 `pthread_setschedprio` 时的错误处理。

9. **线程连接 (Join) 的错误处理:**
   - 测试对不存在或空线程调用 `pthread_join` 时的错误处理。

10. **线程信号发送的错误处理:**
    - 测试对不存在或空线程调用 `pthread_kill` 时的错误处理。

11. **多线程连接 (Multi-join):**
    - 测试多个线程尝试连接同一个线程时的行为。

12. **线程连接竞争 (Join Race):**
    - 通过循环创建和连接线程，并立即释放线程栈内存，来测试 `pthread_join` 的实现中是否存在竞态条件。

13. **线程属性管理:**
    - 测试 `pthread_attr_setguardsize` 和 `pthread_attr_getguardsize`，用于设置和获取线程栈的保护区大小。
    - 测试 `pthread_attr_setstacksize` 和 `pthread_attr_getstacksize`，用于设置和获取线程栈的大小。

14. **读写锁 (Read-Write Locks):**
    - 测试读写锁属性的设置和获取 (`pthread_rwlockattr_init`, `pthread_rwlockattr_setpshared`, `pthread_rwlockattr_getpshared`, `pthread_rwlockattr_setkind_np`, `pthread_rwlockattr_getkind_np`, `pthread_rwlockattr_destroy`).
    - 验证使用 `PTHREAD_RWLOCK_INITIALIZER` 初始化读写锁与使用 `pthread_rwlock_init` 的效果相同。
    - 测试读写锁的基本操作 (`pthread_rwlock_rdlock`, `pthread_rwlock_wrlock`, `pthread_rwlock_tryrdlock`, `pthread_rwlock_trywrlock`, `pthread_rwlock_unlock`, `pthread_rwlock_destroy`)，包括单个读锁、多个读锁、写锁、尝试加锁以及死锁情况。
    - 测试读锁持有者唤醒等待写锁的线程。

**与 Android 功能的关系举例:**

* **线程特定数据 (TSD):**  在 Android Framework 中，例如 `Looper` 类就使用了线程特定数据来存储每个线程的 `MessageQueue`。这样，每个线程都有自己独立的消息队列，避免了多线程访问冲突。
* **线程创建与管理:** Android 应用的后台任务、网络请求、图片加载等操作通常会在独立的线程中进行，以避免阻塞 UI 线程，保证应用的响应性。`pthread_create` 等函数是实现这些功能的基石。
* **线程信号处理:** Android 系统可以使用信号来通知线程发生了某些事件，例如进程终止信号。开发者也可以使用信号机制来实现自定义的线程间通信。
* **线程名称管理:**  在 Android 的调试工具（如 `adb shell ps -t`）中，可以看到每个线程的名称，这通常是通过 `pthread_setname_np` 设置的，方便开发者识别和调试不同的线程。
* **读写锁:** 在 Android Framework 的某些资源管理模块中，读写锁被用于保护共享资源，允许多个线程同时读取资源，但只允许一个线程写入资源，提高并发效率。例如，在访问共享配置信息时可能会使用读写锁。

**libc 函数的功能实现解释 (示例):**

* **`pthread_key_create(pthread_key_t *key, void (*destructor)(void*))`:**
    - **功能:**  创建一个新的线程特定数据键。每个线程都可以为这个键关联一个私有的值。`destructor` 是一个可选的回调函数，当线程退出时，如果该键关联了一个非空值，则会调用该函数来清理该值。
    - **实现:**  Bionic 的实现通常会维护一个全局的键池。当调用 `pthread_key_create` 时，会尝试找到一个空闲的键并分配给调用者。这个键通常是一个小的整数索引。如果提供了 `destructor`，则会保存该函数指针。

* **`pthread_setspecific(pthread_key_t key, const void *value)`:**
    - **功能:** 将给定的 `value` 与当前线程的指定 `key` 关联起来。
    - **实现:**  每个线程都有一个线程局部存储 (Thread-Local Storage, TLS) 区域，通常是一个数组或者哈希表。`pthread_setspecific` 使用 `key` 作为索引，将 `value` 存储到当前线程的 TLS 中。

* **`pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine)(void*), void *arg)`:**
    - **功能:** 创建一个新的线程。新线程从 `start_routine` 函数开始执行，`arg` 是传递给该函数的参数。
    - **实现:** 在 Linux 系统上，`pthread_create` 通常会调用底层的 `clone` 系统调用来创建一个新的进程上下文（轻量级进程），并使其共享调用线程的内存空间。`attr` 参数用于指定新线程的属性，如栈大小、调度策略等。Bionic 会对 `clone` 系统调用进行封装，并进行一些必要的初始化工作。

* **`pthread_join(pthread_t thread, void **retval)`:**
    - **功能:** 调用线程会阻塞，直到指定的 `thread` 终止。如果 `retval` 非空，则会将目标线程的返回值存储到 `*retval` 中。
    - **实现:**  `pthread_join` 的实现通常依赖于底层的线程同步机制，例如 `futex` (fast userspace mutex)。当一个线程调用 `pthread_join` 时，如果目标线程尚未结束，则调用线程会进入休眠状态，并等待目标线程结束时发出信号。

**涉及 dynamic linker 的功能和链接过程:**

`pthread` 相关的函数通常位于 `libc.so` 共享库中。当一个应用程序或者其他共享库（例如 `libandroid_runtime.so`）需要使用 `pthread` 功能时，dynamic linker 负责加载 `libc.so` 并解析这些符号。

**`libc.so` 布局样本 (简化):**

```
地址范围      | 内容
-----------------|------------------------------------
0xb7000000 - 0xb7000fff | ELF Header 和 Program Headers
0xb7001000 - 0xb70fffff | .text (代码段 - 包括 pthread_create 等函数)
0xb7100000 - 0xb710ffff | .rodata (只读数据段 - 例如常量字符串)
0xb7110000 - 0xb711ffff | .data (已初始化数据段 - 例如全局变量)
0xb7120000 - 0xb712ffff | .bss (未初始化数据段)
...             | ...
0xb7xxxxxx - 0xb7xxxxxx | Symbol Table (符号表 - 包含 pthread_create 等符号及其地址)
0xb7yyyyyyyy - 0xb7yyyyyyyy | String Table (字符串表 - 存储符号名称等字符串)
...
```

**链接的处理过程 (简化):**

1. **加载时:** 当 Android 系统启动应用程序或加载共享库时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 会被调用。
2. **依赖解析:** Dynamic linker 会检查应用程序或共享库的依赖项，发现需要加载 `libc.so`。
3. **加载 `libc.so`:** Dynamic linker 会将 `libc.so` 加载到内存中的某个地址空间 (如上面的例子)。
4. **符号查找:** 当应用程序调用 `pthread_create` 时，编译器会生成对该符号的引用。在加载时，dynamic linker 会在 `libc.so` 的符号表中查找 `pthread_create` 符号的地址。
5. **重定位:**  由于共享库被加载到内存的地址可能每次都不同，dynamic linker 需要修改程序中对 `pthread_create` 等符号的引用，将其指向 `libc.so` 中实际的函数地址。这个过程称为重定位。
6. **绑定:**  一旦符号被找到并重定位，应用程序就可以成功调用 `libc.so` 中的 `pthread_create` 函数。

**假设输入与输出 (逻辑推理):**

以 `TEST(pthread, pthread_key_create)` 为例：

* **假设输入:** 调用 `pthread_key_create(&key, nullptr)`。
* **预期输出:**
    * `pthread_key_create` 返回 0 (表示成功)。
    * `key` 指向的 `pthread_key_t` 变量被赋予一个有效的新键值。
    * 后续调用 `pthread_key_delete(key)` 应该返回 0 (表示成功删除)。
    * 再次调用 `pthread_key_delete(key)` 应该返回 `EINVAL` (表示键无效)。

**用户或编程常见的使用错误举例:**

1. **忘记销毁线程特定数据键:**  如果使用 `pthread_key_create` 创建了键，但在不再需要时忘记使用 `pthread_key_delete` 销毁，可能会导致资源泄漏。
2. **在线程退出后访问其线程特定数据:**  当一个线程退出时，与其关联的线程特定数据也会被清理。如果在线程退出后尝试访问这些数据，会导致未定义的行为。
3. **忘记 `pthread_join` 分离的线程:** 如果一个线程被设置为 detached 状态，那么它的资源会在它结束后自动释放。尝试对 detached 线程调用 `pthread_join` 会导致错误。
4. **死锁:**  多个线程因为互相等待对方释放资源而进入无限等待状态。例如，线程 A 持有锁 1 并等待锁 2，而线程 B 持有锁 2 并等待锁 1。
5. **竞态条件:**  程序的行为取决于多个线程执行的相对顺序，导致不可预测的结果。例如，多个线程同时修改同一个共享变量而没有适当的同步机制。

**Android Framework 或 NDK 如何到达这里:**

1. **Java 代码使用 `java.lang.Thread`:**  在 Android 的 Java 代码中，可以通过创建 `java.lang.Thread` 对象或者使用 `Executor` 框架来创建和管理线程。
2. **Native 代码使用 NDK:**  通过 Android NDK，开发者可以使用 C/C++ 编写 native 代码。在 native 代码中，可以直接调用 `pthread` 相关的函数。
3. **JNI 调用:** 当 Java 代码创建 `java.lang.Thread` 对象时，Android Runtime (ART 或 Dalvik) 会在底层创建一个 native 线程。这个过程会涉及到 JNI (Java Native Interface) 调用。
4. **`libandroid_runtime.so`:** Android Runtime 的核心库 `libandroid_runtime.so` 包含了 Java 线程到 native 线程的映射和管理逻辑。它会调用 Bionic 库中的 `pthread_create` 等函数来创建 native 线程。
5. **系统调用:** 最终，Bionic 的 `pthread_create` 函数会调用 Linux 内核的 `clone` 系统调用来创建新的线程。

**Frida Hook 示例调试步骤:**

假设我们想 hook `pthread_create` 函数，查看新创建线程的起始地址：

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName('libc.so');
  const pthread_create = libc.getExportByName('pthread_create');

  Interceptor.attach(pthread_create, {
    onEnter: function (args) {
      const threadPtr = args[0];
      const attrPtr = args[1];
      const startRoutinePtr = args[2];
      const argPtr = args[3];

      console.log('[pthread_create] Thread pointer:', threadPtr);
      console.log('[pthread_create] Attributes pointer:', attrPtr);
      console.log('[pthread_create] Start routine:', startRoutinePtr);
      console.log('[pthread_create] Argument:', argPtr);
      console.log('[pthread_create] Start routine address:', startRoutinePtr);
    },
    onLeave: function (retval) {
      console.log('[pthread_create] Return value:', retval);
    }
  });
}
```

**步骤解释:**

1. **获取 `libc.so` 模块:** 使用 `Process.getModuleByName('libc.so')` 获取 Bionic 的 C 库模块。
2. **获取 `pthread_create` 导出:** 使用 `libc.getExportByName('pthread_create')` 获取 `pthread_create` 函数的地址。
3. **使用 `Interceptor.attach` 进行 hook:**
   - `onEnter`: 在 `pthread_create` 函数被调用之前执行。我们可以访问函数的参数 (`args`)，例如线程指针、属性指针、起始函数地址和参数。
   - `onLeave`: 在 `pthread_create` 函数执行完毕后执行。我们可以访问函数的返回值 (`retval`)。
4. **打印信息:** 在 `onEnter` 中打印出 `pthread_create` 的参数，包括起始函数的地址，这可以帮助我们了解新线程将要执行的代码。

这是一个非常基础的 Frida hook 示例。可以根据需要 hook 其他 `pthread` 函数，例如 `pthread_join`、`pthread_mutex_lock` 等，以观察线程的创建、同步和销毁过程。

希望以上归纳和解释对您有所帮助！

Prompt: 
```
这是目录为bionic/tests/pthread_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
请列举一下它的功能,
如果它与android的功能有关系，请做出对应的举例说明，
详细解释每一个libc函数的功能是如何实现的,
对于涉及dynamic linker的功能，请给对应的so布局样本，以及链接的处理过程，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明android framework or ndk是如何一步步的到达这里，给出frida hook示例调试这些步骤。
用中文回复。
这是第1部分，共4部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2012 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <malloc.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <sys/param.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <unwind.h>

#include <atomic>
#include <future>
#include <vector>

#include <android-base/macros.h>
#include <android-base/parseint.h>
#include <android-base/scopeguard.h>
#include <android-base/silent_death_test.h>
#include <android-base/strings.h>
#include <android-base/test_utils.h>

#include "private/bionic_constants.h"
#include "private/bionic_time_conversions.h"
#include "SignalUtils.h"
#include "utils.h"

using pthread_DeathTest = SilentDeathTest;

TEST(pthread, pthread_key_create) {
  pthread_key_t key;
  ASSERT_EQ(0, pthread_key_create(&key, nullptr));
  ASSERT_EQ(0, pthread_key_delete(key));
  // Can't delete a key that's already been deleted.
  ASSERT_EQ(EINVAL, pthread_key_delete(key));
}

TEST(pthread, pthread_keys_max) {
  // POSIX says PTHREAD_KEYS_MAX should be at least _POSIX_THREAD_KEYS_MAX.
  ASSERT_GE(PTHREAD_KEYS_MAX, _POSIX_THREAD_KEYS_MAX);
}

TEST(pthread, sysconf_SC_THREAD_KEYS_MAX_eq_PTHREAD_KEYS_MAX) {
  int sysconf_max = sysconf(_SC_THREAD_KEYS_MAX);
  ASSERT_EQ(sysconf_max, PTHREAD_KEYS_MAX);
}

TEST(pthread, pthread_key_many_distinct) {
  // As gtest uses pthread keys, we can't allocate exactly PTHREAD_KEYS_MAX
  // pthread keys, but We should be able to allocate at least this many keys.
  int nkeys = PTHREAD_KEYS_MAX / 2;
  std::vector<pthread_key_t> keys;

  auto scope_guard = android::base::make_scope_guard([&keys] {
    for (const auto& key : keys) {
      EXPECT_EQ(0, pthread_key_delete(key));
    }
  });

  for (int i = 0; i < nkeys; ++i) {
    pthread_key_t key;
    // If this fails, it's likely that LIBC_PTHREAD_KEY_RESERVED_COUNT is wrong.
    ASSERT_EQ(0, pthread_key_create(&key, nullptr)) << i << " of " << nkeys;
    keys.push_back(key);
    ASSERT_EQ(0, pthread_setspecific(key, reinterpret_cast<void*>(i)));
  }

  for (int i = keys.size() - 1; i >= 0; --i) {
    ASSERT_EQ(reinterpret_cast<void*>(i), pthread_getspecific(keys.back()));
    pthread_key_t key = keys.back();
    keys.pop_back();
    ASSERT_EQ(0, pthread_key_delete(key));
  }
}

TEST(pthread, pthread_key_not_exceed_PTHREAD_KEYS_MAX) {
  std::vector<pthread_key_t> keys;
  int rv = 0;

  // Pthread keys are used by gtest, so PTHREAD_KEYS_MAX should
  // be more than we are allowed to allocate now.
  for (int i = 0; i < PTHREAD_KEYS_MAX; i++) {
    pthread_key_t key;
    rv = pthread_key_create(&key, nullptr);
    if (rv == EAGAIN) {
      break;
    }
    EXPECT_EQ(0, rv);
    keys.push_back(key);
  }

  // Don't leak keys.
  for (const auto& key : keys) {
    EXPECT_EQ(0, pthread_key_delete(key));
  }
  keys.clear();

  // We should have eventually reached the maximum number of keys and received
  // EAGAIN.
  ASSERT_EQ(EAGAIN, rv);
}

TEST(pthread, pthread_key_delete) {
  void* expected = reinterpret_cast<void*>(1234);
  pthread_key_t key;
  ASSERT_EQ(0, pthread_key_create(&key, nullptr));
  ASSERT_EQ(0, pthread_setspecific(key, expected));
  ASSERT_EQ(expected, pthread_getspecific(key));
  ASSERT_EQ(0, pthread_key_delete(key));
  // After deletion, pthread_getspecific returns nullptr.
  ASSERT_EQ(nullptr, pthread_getspecific(key));
  // And you can't use pthread_setspecific with the deleted key.
  ASSERT_EQ(EINVAL, pthread_setspecific(key, expected));
}

TEST(pthread, pthread_key_fork) {
  void* expected = reinterpret_cast<void*>(1234);
  pthread_key_t key;
  ASSERT_EQ(0, pthread_key_create(&key, nullptr));
  ASSERT_EQ(0, pthread_setspecific(key, expected));
  ASSERT_EQ(expected, pthread_getspecific(key));

  pid_t pid = fork();
  ASSERT_NE(-1, pid) << strerror(errno);

  if (pid == 0) {
    // The surviving thread inherits all the forking thread's TLS values...
    ASSERT_EQ(expected, pthread_getspecific(key));
    _exit(99);
  }

  AssertChildExited(pid, 99);

  ASSERT_EQ(expected, pthread_getspecific(key));
  ASSERT_EQ(0, pthread_key_delete(key));
}

static void* DirtyKeyFn(void* key) {
  return pthread_getspecific(*reinterpret_cast<pthread_key_t*>(key));
}

TEST(pthread, pthread_key_dirty) {
  pthread_key_t key;
  ASSERT_EQ(0, pthread_key_create(&key, nullptr));

  size_t stack_size = 640 * 1024;
  void* stack = mmap(nullptr, stack_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(MAP_FAILED, stack);
  memset(stack, 0xff, stack_size);

  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));
  ASSERT_EQ(0, pthread_attr_setstack(&attr, stack, stack_size));

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, &attr, DirtyKeyFn, &key));

  void* result;
  ASSERT_EQ(0, pthread_join(t, &result));
  ASSERT_EQ(nullptr, result); // Not ~0!

  ASSERT_EQ(0, munmap(stack, stack_size));
  ASSERT_EQ(0, pthread_key_delete(key));
}

static void* FnWithStackFrame(void*) {
  int x;
  *const_cast<volatile int*>(&x) = 1;
  return nullptr;
}

TEST(pthread, pthread_heap_allocated_stack) {
  SKIP_WITH_HWASAN; // TODO(b/148982147): Re-enable when fixed.

  size_t stack_size = 640 * 1024;
  std::unique_ptr<char[]> stack(new (std::align_val_t(getpagesize())) char[stack_size]);
  memset(stack.get(), '\xff', stack_size);

  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_attr_init(&attr));
  ASSERT_EQ(0, pthread_attr_setstack(&attr, stack.get(), stack_size));

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, &attr, FnWithStackFrame, nullptr));

  void* result;
  ASSERT_EQ(0, pthread_join(t, &result));
}

TEST(pthread, static_pthread_key_used_before_creation) {
#if defined(__BIONIC__)
  // See http://b/19625804. The bug is about a static/global pthread key being used before creation.
  // So here tests if the static/global default value 0 can be detected as invalid key.
  static pthread_key_t key;
  ASSERT_EQ(nullptr, pthread_getspecific(key));
  ASSERT_EQ(EINVAL, pthread_setspecific(key, nullptr));
  ASSERT_EQ(EINVAL, pthread_key_delete(key));
#else
  GTEST_SKIP() << "bionic-only test";
#endif
}

static void* IdFn(void* arg) {
  return arg;
}

class SpinFunctionHelper {
 public:
  SpinFunctionHelper() {
    SpinFunctionHelper::spin_flag_ = true;
  }

  ~SpinFunctionHelper() {
    UnSpin();
  }

  auto GetFunction() -> void* (*)(void*) {
    return SpinFunctionHelper::SpinFn;
  }

  void UnSpin() {
    SpinFunctionHelper::spin_flag_ = false;
  }

 private:
  static void* SpinFn(void*) {
    while (spin_flag_) {}
    return nullptr;
  }
  static std::atomic<bool> spin_flag_;
};

// It doesn't matter if spin_flag_ is used in several tests,
// because it is always set to false after each test. Each thread
// loops on spin_flag_ can find it becomes false at some time.
std::atomic<bool> SpinFunctionHelper::spin_flag_;

static void* JoinFn(void* arg) {
  return reinterpret_cast<void*>(pthread_join(reinterpret_cast<pthread_t>(arg), nullptr));
}

static void AssertDetached(pthread_t t, bool is_detached) {
  pthread_attr_t attr;
  ASSERT_EQ(0, pthread_getattr_np(t, &attr));
  int detach_state;
  ASSERT_EQ(0, pthread_attr_getdetachstate(&attr, &detach_state));
  pthread_attr_destroy(&attr);
  ASSERT_EQ(is_detached, (detach_state == PTHREAD_CREATE_DETACHED));
}

static void MakeDeadThread(pthread_t& t) {
  ASSERT_EQ(0, pthread_create(&t, nullptr, IdFn, nullptr));
  ASSERT_EQ(0, pthread_join(t, nullptr));
}

TEST(pthread, pthread_create) {
  void* expected_result = reinterpret_cast<void*>(123);
  // Can we create a thread?
  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, IdFn, expected_result));
  // If we join, do we get the expected value back?
  void* result;
  ASSERT_EQ(0, pthread_join(t, &result));
  ASSERT_EQ(expected_result, result);
}

TEST(pthread, pthread_create_EAGAIN) {
  pthread_attr_t attributes;
  ASSERT_EQ(0, pthread_attr_init(&attributes));
  ASSERT_EQ(0, pthread_attr_setstacksize(&attributes, static_cast<size_t>(-1) & ~(getpagesize() - 1)));

  pthread_t t;
  ASSERT_EQ(EAGAIN, pthread_create(&t, &attributes, IdFn, nullptr));
}

TEST(pthread, pthread_no_join_after_detach) {
  SpinFunctionHelper spin_helper;

  pthread_t t1;
  ASSERT_EQ(0, pthread_create(&t1, nullptr, spin_helper.GetFunction(), nullptr));

  // After a pthread_detach...
  ASSERT_EQ(0, pthread_detach(t1));
  AssertDetached(t1, true);

  // ...pthread_join should fail.
  ASSERT_EQ(EINVAL, pthread_join(t1, nullptr));
}

TEST(pthread, pthread_no_op_detach_after_join) {
  SpinFunctionHelper spin_helper;

  pthread_t t1;
  ASSERT_EQ(0, pthread_create(&t1, nullptr, spin_helper.GetFunction(), nullptr));

  // If thread 2 is already waiting to join thread 1...
  pthread_t t2;
  ASSERT_EQ(0, pthread_create(&t2, nullptr, JoinFn, reinterpret_cast<void*>(t1)));

  sleep(1); // (Give t2 a chance to call pthread_join.)

#if defined(__BIONIC__)
  ASSERT_EQ(EINVAL, pthread_detach(t1));
#else
  ASSERT_EQ(0, pthread_detach(t1));
#endif
  AssertDetached(t1, false);

  spin_helper.UnSpin();

  // ...but t2's join on t1 still goes ahead (which we can tell because our join on t2 finishes).
  void* join_result;
  ASSERT_EQ(0, pthread_join(t2, &join_result));
  ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(join_result));
}

TEST(pthread, pthread_join_self) {
  ASSERT_EQ(EDEADLK, pthread_join(pthread_self(), nullptr));
}

struct TestBug37410 {
  pthread_t main_thread;
  pthread_mutex_t mutex;

  static void main() {
    TestBug37410 data;
    data.main_thread = pthread_self();
    ASSERT_EQ(0, pthread_mutex_init(&data.mutex, nullptr));
    ASSERT_EQ(0, pthread_mutex_lock(&data.mutex));

    pthread_t t;
    ASSERT_EQ(0, pthread_create(&t, nullptr, TestBug37410::thread_fn, reinterpret_cast<void*>(&data)));

    // Wait for the thread to be running...
    ASSERT_EQ(0, pthread_mutex_lock(&data.mutex));
    ASSERT_EQ(0, pthread_mutex_unlock(&data.mutex));

    // ...and exit.
    pthread_exit(nullptr);
  }

 private:
  static void* thread_fn(void* arg) {
    TestBug37410* data = reinterpret_cast<TestBug37410*>(arg);

    // Unlocking data->mutex will cause the main thread to exit, invalidating *data. Save the handle.
    pthread_t main_thread = data->main_thread;

    // Let the main thread know we're running.
    pthread_mutex_unlock(&data->mutex);

    // And wait for the main thread to exit.
    pthread_join(main_thread, nullptr);

    return nullptr;
  }
};

// Even though this isn't really a death test, we have to say "DeathTest" here so gtest knows to
// run this test (which exits normally) in its own process.
TEST_F(pthread_DeathTest, pthread_bug_37410) {
  // http://code.google.com/p/android/issues/detail?id=37410
  ASSERT_EXIT(TestBug37410::main(), ::testing::ExitedWithCode(0), "");
}

static void* SignalHandlerFn(void* arg) {
  sigset64_t wait_set;
  sigfillset64(&wait_set);
  return reinterpret_cast<void*>(sigwait64(&wait_set, reinterpret_cast<int*>(arg)));
}

TEST(pthread, pthread_sigmask) {
  // Check that SIGUSR1 isn't blocked.
  sigset_t original_set;
  sigemptyset(&original_set);
  ASSERT_EQ(0, pthread_sigmask(SIG_BLOCK, nullptr, &original_set));
  ASSERT_FALSE(sigismember(&original_set, SIGUSR1));

  // Block SIGUSR1.
  sigset_t set;
  sigemptyset(&set);
  sigaddset(&set, SIGUSR1);
  ASSERT_EQ(0, pthread_sigmask(SIG_BLOCK, &set, nullptr));

  // Check that SIGUSR1 is blocked.
  sigset_t final_set;
  sigemptyset(&final_set);
  ASSERT_EQ(0, pthread_sigmask(SIG_BLOCK, nullptr, &final_set));
  ASSERT_TRUE(sigismember(&final_set, SIGUSR1));
  // ...and that sigprocmask agrees with pthread_sigmask.
  sigemptyset(&final_set);
  ASSERT_EQ(0, sigprocmask(SIG_BLOCK, nullptr, &final_set));
  ASSERT_TRUE(sigismember(&final_set, SIGUSR1));

  // Spawn a thread that calls sigwait and tells us what it received.
  pthread_t signal_thread;
  int received_signal = -1;
  ASSERT_EQ(0, pthread_create(&signal_thread, nullptr, SignalHandlerFn, &received_signal));

  // Send that thread SIGUSR1.
  pthread_kill(signal_thread, SIGUSR1);

  // See what it got.
  void* join_result;
  ASSERT_EQ(0, pthread_join(signal_thread, &join_result));
  ASSERT_EQ(SIGUSR1, received_signal);
  ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(join_result));

  // Restore the original signal mask.
  ASSERT_EQ(0, pthread_sigmask(SIG_SETMASK, &original_set, nullptr));
}

TEST(pthread, pthread_sigmask64_SIGTRMIN) {
  // Check that SIGRTMIN isn't blocked.
  sigset64_t original_set;
  sigemptyset64(&original_set);
  ASSERT_EQ(0, pthread_sigmask64(SIG_BLOCK, nullptr, &original_set));
  ASSERT_FALSE(sigismember64(&original_set, SIGRTMIN));

  // Block SIGRTMIN.
  sigset64_t set;
  sigemptyset64(&set);
  sigaddset64(&set, SIGRTMIN);
  ASSERT_EQ(0, pthread_sigmask64(SIG_BLOCK, &set, nullptr));

  // Check that SIGRTMIN is blocked.
  sigset64_t final_set;
  sigemptyset64(&final_set);
  ASSERT_EQ(0, pthread_sigmask64(SIG_BLOCK, nullptr, &final_set));
  ASSERT_TRUE(sigismember64(&final_set, SIGRTMIN));
  // ...and that sigprocmask64 agrees with pthread_sigmask64.
  sigemptyset64(&final_set);
  ASSERT_EQ(0, sigprocmask64(SIG_BLOCK, nullptr, &final_set));
  ASSERT_TRUE(sigismember64(&final_set, SIGRTMIN));

  // Spawn a thread that calls sigwait64 and tells us what it received.
  pthread_t signal_thread;
  int received_signal = -1;
  ASSERT_EQ(0, pthread_create(&signal_thread, nullptr, SignalHandlerFn, &received_signal));

  // Send that thread SIGRTMIN.
  pthread_kill(signal_thread, SIGRTMIN);

  // See what it got.
  void* join_result;
  ASSERT_EQ(0, pthread_join(signal_thread, &join_result));
  ASSERT_EQ(SIGRTMIN, received_signal);
  ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(join_result));

  // Restore the original signal mask.
  ASSERT_EQ(0, pthread_sigmask64(SIG_SETMASK, &original_set, nullptr));
}

static void test_pthread_setname_np__pthread_getname_np(pthread_t t) {
  ASSERT_EQ(0, pthread_setname_np(t, "short"));
  char name[32];
  ASSERT_EQ(0, pthread_getname_np(t, name, sizeof(name)));
  ASSERT_STREQ("short", name);

  // The limit is 15 characters --- the kernel's buffer is 16, but includes a NUL.
  ASSERT_EQ(0, pthread_setname_np(t, "123456789012345"));
  ASSERT_EQ(0, pthread_getname_np(t, name, sizeof(name)));
  ASSERT_STREQ("123456789012345", name);

  ASSERT_EQ(ERANGE, pthread_setname_np(t, "1234567890123456"));

  // The passed-in buffer should be at least 16 bytes.
  ASSERT_EQ(0, pthread_getname_np(t, name, 16));
  ASSERT_EQ(ERANGE, pthread_getname_np(t, name, 15));
}

TEST(pthread, pthread_setname_np__pthread_getname_np__self) {
  test_pthread_setname_np__pthread_getname_np(pthread_self());
}

TEST(pthread, pthread_setname_np__pthread_getname_np__other) {
  SpinFunctionHelper spin_helper;

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, spin_helper.GetFunction(), nullptr));
  test_pthread_setname_np__pthread_getname_np(t);
  spin_helper.UnSpin();
  ASSERT_EQ(0, pthread_join(t, nullptr));
}

// http://b/28051133: a kernel misfeature means that you can't change the
// name of another thread if you've set PR_SET_DUMPABLE to 0.
TEST(pthread, pthread_setname_np__pthread_getname_np__other_PR_SET_DUMPABLE) {
  ASSERT_EQ(0, prctl(PR_SET_DUMPABLE, 0)) << strerror(errno);

  SpinFunctionHelper spin_helper;

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, spin_helper.GetFunction(), nullptr));
  test_pthread_setname_np__pthread_getname_np(t);
  spin_helper.UnSpin();
  ASSERT_EQ(0, pthread_join(t, nullptr));
}

TEST_F(pthread_DeathTest, pthread_setname_np__no_such_thread) {
  pthread_t dead_thread;
  MakeDeadThread(dead_thread);

  EXPECT_DEATH(pthread_setname_np(dead_thread, "short 3"),
               "invalid pthread_t (.*) passed to pthread_setname_np");
}

TEST_F(pthread_DeathTest, pthread_setname_np__null_thread) {
  pthread_t null_thread = 0;
  EXPECT_EQ(ENOENT, pthread_setname_np(null_thread, "short 3"));
}

TEST_F(pthread_DeathTest, pthread_getname_np__no_such_thread) {
  pthread_t dead_thread;
  MakeDeadThread(dead_thread);

  char name[64];
  EXPECT_DEATH(pthread_getname_np(dead_thread, name, sizeof(name)),
               "invalid pthread_t (.*) passed to pthread_getname_np");
}

TEST_F(pthread_DeathTest, pthread_getname_np__null_thread) {
  pthread_t null_thread = 0;

  char name[64];
  EXPECT_EQ(ENOENT, pthread_getname_np(null_thread, name, sizeof(name)));
}

TEST(pthread, pthread_kill__0) {
  // Signal 0 just tests that the thread exists, so it's safe to call on ourselves.
  ASSERT_EQ(0, pthread_kill(pthread_self(), 0));
}

TEST(pthread, pthread_kill__invalid_signal) {
  ASSERT_EQ(EINVAL, pthread_kill(pthread_self(), -1));
}

static void pthread_kill__in_signal_handler_helper(int signal_number) {
  static int count = 0;
  ASSERT_EQ(SIGALRM, signal_number);
  if (++count == 1) {
    // Can we call pthread_kill from a signal handler?
    ASSERT_EQ(0, pthread_kill(pthread_self(), SIGALRM));
  }
}

TEST(pthread, pthread_kill__in_signal_handler) {
  ScopedSignalHandler ssh(SIGALRM, pthread_kill__in_signal_handler_helper);
  ASSERT_EQ(0, pthread_kill(pthread_self(), SIGALRM));
}

TEST(pthread, pthread_kill__exited_thread) {
  static std::promise<pid_t> tid_promise;
  pthread_t thread;
  ASSERT_EQ(0, pthread_create(&thread, nullptr,
                              [](void*) -> void* {
                                tid_promise.set_value(gettid());
                                return nullptr;
                              },
                              nullptr));

  pid_t tid = tid_promise.get_future().get();
  while (TEMP_FAILURE_RETRY(syscall(__NR_tgkill, getpid(), tid, 0)) != -1) {
    continue;
  }
  ASSERT_ERRNO(ESRCH);

  ASSERT_EQ(ESRCH, pthread_kill(thread, 0));
}

TEST_F(pthread_DeathTest, pthread_detach__no_such_thread) {
  pthread_t dead_thread;
  MakeDeadThread(dead_thread);

  EXPECT_DEATH(pthread_detach(dead_thread),
               "invalid pthread_t (.*) passed to pthread_detach");
}

TEST_F(pthread_DeathTest, pthread_detach__null_thread) {
  pthread_t null_thread = 0;
  EXPECT_EQ(ESRCH, pthread_detach(null_thread));
}

TEST(pthread, pthread_getcpuclockid__clock_gettime) {
  SpinFunctionHelper spin_helper;

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, spin_helper.GetFunction(), nullptr));

  clockid_t c;
  ASSERT_EQ(0, pthread_getcpuclockid(t, &c));
  timespec ts;
  ASSERT_EQ(0, clock_gettime(c, &ts));
  spin_helper.UnSpin();
  ASSERT_EQ(0, pthread_join(t, nullptr));
}

TEST_F(pthread_DeathTest, pthread_getcpuclockid__no_such_thread) {
  pthread_t dead_thread;
  MakeDeadThread(dead_thread);

  clockid_t c;
  EXPECT_DEATH(pthread_getcpuclockid(dead_thread, &c),
               "invalid pthread_t (.*) passed to pthread_getcpuclockid");
}

TEST_F(pthread_DeathTest, pthread_getcpuclockid__null_thread) {
  pthread_t null_thread = 0;
  clockid_t c;
  EXPECT_EQ(ESRCH, pthread_getcpuclockid(null_thread, &c));
}

TEST_F(pthread_DeathTest, pthread_getschedparam__no_such_thread) {
  pthread_t dead_thread;
  MakeDeadThread(dead_thread);

  int policy;
  sched_param param;
  EXPECT_DEATH(pthread_getschedparam(dead_thread, &policy, &param),
               "invalid pthread_t (.*) passed to pthread_getschedparam");
}

TEST_F(pthread_DeathTest, pthread_getschedparam__null_thread) {
  pthread_t null_thread = 0;
  int policy;
  sched_param param;
  EXPECT_EQ(ESRCH, pthread_getschedparam(null_thread, &policy, &param));
}

TEST_F(pthread_DeathTest, pthread_setschedparam__no_such_thread) {
  pthread_t dead_thread;
  MakeDeadThread(dead_thread);

  int policy = 0;
  sched_param param;
  EXPECT_DEATH(pthread_setschedparam(dead_thread, policy, &param),
               "invalid pthread_t (.*) passed to pthread_setschedparam");
}

TEST_F(pthread_DeathTest, pthread_setschedparam__null_thread) {
  pthread_t null_thread = 0;
  int policy = 0;
  sched_param param;
  EXPECT_EQ(ESRCH, pthread_setschedparam(null_thread, policy, &param));
}

TEST_F(pthread_DeathTest, pthread_setschedprio__no_such_thread) {
  pthread_t dead_thread;
  MakeDeadThread(dead_thread);

  EXPECT_DEATH(pthread_setschedprio(dead_thread, 123),
               "invalid pthread_t (.*) passed to pthread_setschedprio");
}

TEST_F(pthread_DeathTest, pthread_setschedprio__null_thread) {
  pthread_t null_thread = 0;
  EXPECT_EQ(ESRCH, pthread_setschedprio(null_thread, 123));
}

TEST_F(pthread_DeathTest, pthread_join__no_such_thread) {
  pthread_t dead_thread;
  MakeDeadThread(dead_thread);

  EXPECT_DEATH(pthread_join(dead_thread, nullptr),
               "invalid pthread_t (.*) passed to pthread_join");
}

TEST_F(pthread_DeathTest, pthread_join__null_thread) {
  pthread_t null_thread = 0;
  EXPECT_EQ(ESRCH, pthread_join(null_thread, nullptr));
}

TEST_F(pthread_DeathTest, pthread_kill__no_such_thread) {
  pthread_t dead_thread;
  MakeDeadThread(dead_thread);

  EXPECT_DEATH(pthread_kill(dead_thread, 0),
               "invalid pthread_t (.*) passed to pthread_kill");
}

TEST_F(pthread_DeathTest, pthread_kill__null_thread) {
  pthread_t null_thread = 0;
  EXPECT_EQ(ESRCH, pthread_kill(null_thread, 0));
}

TEST(pthread, pthread_join__multijoin) {
  SpinFunctionHelper spin_helper;

  pthread_t t1;
  ASSERT_EQ(0, pthread_create(&t1, nullptr, spin_helper.GetFunction(), nullptr));

  pthread_t t2;
  ASSERT_EQ(0, pthread_create(&t2, nullptr, JoinFn, reinterpret_cast<void*>(t1)));

  sleep(1); // (Give t2 a chance to call pthread_join.)

  // Multiple joins to the same thread should fail.
  ASSERT_EQ(EINVAL, pthread_join(t1, nullptr));

  spin_helper.UnSpin();

  // ...but t2's join on t1 still goes ahead (which we can tell because our join on t2 finishes).
  void* join_result;
  ASSERT_EQ(0, pthread_join(t2, &join_result));
  ASSERT_EQ(0U, reinterpret_cast<uintptr_t>(join_result));
}

TEST(pthread, pthread_join__race) {
  // http://b/11693195 --- pthread_join could return before the thread had actually exited.
  // If the joiner unmapped the thread's stack, that could lead to SIGSEGV in the thread.
  for (size_t i = 0; i < 1024; ++i) {
    size_t stack_size = 640*1024;
    void* stack = mmap(nullptr, stack_size, PROT_READ|PROT_WRITE, MAP_ANON|MAP_PRIVATE, -1, 0);

    pthread_attr_t a;
    pthread_attr_init(&a);
    pthread_attr_setstack(&a, stack, stack_size);

    pthread_t t;
    ASSERT_EQ(0, pthread_create(&t, &a, IdFn, nullptr));
    ASSERT_EQ(0, pthread_join(t, nullptr));
    ASSERT_EQ(0, munmap(stack, stack_size));
  }
}

static void* GetActualGuardSizeFn(void* arg) {
  pthread_attr_t attributes;
  pthread_getattr_np(pthread_self(), &attributes);
  pthread_attr_getguardsize(&attributes, reinterpret_cast<size_t*>(arg));
  return nullptr;
}

static size_t GetActualGuardSize(const pthread_attr_t& attributes) {
  size_t result;
  pthread_t t;
  pthread_create(&t, &attributes, GetActualGuardSizeFn, &result);
  pthread_join(t, nullptr);
  return result;
}

static void* GetActualStackSizeFn(void* arg) {
  pthread_attr_t attributes;
  pthread_getattr_np(pthread_self(), &attributes);
  pthread_attr_getstacksize(&attributes, reinterpret_cast<size_t*>(arg));
  return nullptr;
}

static size_t GetActualStackSize(const pthread_attr_t& attributes) {
  size_t result;
  pthread_t t;
  pthread_create(&t, &attributes, GetActualStackSizeFn, &result);
  pthread_join(t, nullptr);
  return result;
}

TEST(pthread, pthread_attr_setguardsize_tiny) {
  pthread_attr_t attributes;
  ASSERT_EQ(0, pthread_attr_init(&attributes));

  // No such thing as too small: will be rounded up to one page by pthread_create.
  ASSERT_EQ(0, pthread_attr_setguardsize(&attributes, 128));
  size_t guard_size;
  ASSERT_EQ(0, pthread_attr_getguardsize(&attributes, &guard_size));
  ASSERT_EQ(128U, guard_size);
  ASSERT_EQ(static_cast<unsigned long>(getpagesize()), GetActualGuardSize(attributes));
}

TEST(pthread, pthread_attr_setguardsize_reasonable) {
  pthread_attr_t attributes;
  ASSERT_EQ(0, pthread_attr_init(&attributes));

  // Large enough and a multiple of the page size.
  ASSERT_EQ(0, pthread_attr_setguardsize(&attributes, 32*1024));
  size_t guard_size;
  ASSERT_EQ(0, pthread_attr_getguardsize(&attributes, &guard_size));
  ASSERT_EQ(32*1024U, guard_size);
  ASSERT_EQ(32*1024U, GetActualGuardSize(attributes));
}

TEST(pthread, pthread_attr_setguardsize_needs_rounding) {
  pthread_attr_t attributes;
  ASSERT_EQ(0, pthread_attr_init(&attributes));

  // Large enough but not a multiple of the page size.
  ASSERT_EQ(0, pthread_attr_setguardsize(&attributes, 32*1024 + 1));
  size_t guard_size;
  ASSERT_EQ(0, pthread_attr_getguardsize(&attributes, &guard_size));
  ASSERT_EQ(32*1024U + 1, guard_size);
  ASSERT_EQ(roundup(32 * 1024U + 1, getpagesize()), GetActualGuardSize(attributes));
}

TEST(pthread, pthread_attr_setguardsize_enormous) {
  pthread_attr_t attributes;
  ASSERT_EQ(0, pthread_attr_init(&attributes));

  // Larger than the stack itself. (Historically we mistakenly carved
  // the guard out of the stack itself, rather than adding it after the
  // end.)
  ASSERT_EQ(0, pthread_attr_setguardsize(&attributes, 32*1024*1024));
  size_t guard_size;
  ASSERT_EQ(0, pthread_attr_getguardsize(&attributes, &guard_size));
  ASSERT_EQ(32*1024*1024U, guard_size);
  ASSERT_EQ(32*1024*1024U, GetActualGuardSize(attributes));
}

TEST(pthread, pthread_attr_setstacksize) {
  pthread_attr_t attributes;
  ASSERT_EQ(0, pthread_attr_init(&attributes));

  // Get the default stack size.
  size_t default_stack_size;
  ASSERT_EQ(0, pthread_attr_getstacksize(&attributes, &default_stack_size));

  // Too small.
  ASSERT_EQ(EINVAL, pthread_attr_setstacksize(&attributes, 128));
  size_t stack_size;
  ASSERT_EQ(0, pthread_attr_getstacksize(&attributes, &stack_size));
  ASSERT_EQ(default_stack_size, stack_size);
  ASSERT_GE(GetActualStackSize(attributes), default_stack_size);

  // Large enough and a multiple of the page size; may be rounded up by pthread_create.
  ASSERT_EQ(0, pthread_attr_setstacksize(&attributes, 32*1024));
  ASSERT_EQ(0, pthread_attr_getstacksize(&attributes, &stack_size));
  ASSERT_EQ(32*1024U, stack_size);
  ASSERT_GE(GetActualStackSize(attributes), 32*1024U);

  // Large enough but not aligned; will be rounded up by pthread_create.
  ASSERT_EQ(0, pthread_attr_setstacksize(&attributes, 32*1024 + 1));
  ASSERT_EQ(0, pthread_attr_getstacksize(&attributes, &stack_size));
  ASSERT_EQ(32*1024U + 1, stack_size);
#if defined(__BIONIC__)
  ASSERT_GT(GetActualStackSize(attributes), 32*1024U + 1);
#else // __BIONIC__
  // glibc rounds down, in violation of POSIX. They document this in their BUGS section.
  ASSERT_EQ(GetActualStackSize(attributes), 32*1024U);
#endif // __BIONIC__
}

TEST(pthread, pthread_rwlockattr_smoke) {
  pthread_rwlockattr_t attr;
  ASSERT_EQ(0, pthread_rwlockattr_init(&attr));

  int pshared_value_array[] = {PTHREAD_PROCESS_PRIVATE, PTHREAD_PROCESS_SHARED};
  for (size_t i = 0; i < sizeof(pshared_value_array) / sizeof(pshared_value_array[0]); ++i) {
    ASSERT_EQ(0, pthread_rwlockattr_setpshared(&attr, pshared_value_array[i]));
    int pshared;
    ASSERT_EQ(0, pthread_rwlockattr_getpshared(&attr, &pshared));
    ASSERT_EQ(pshared_value_array[i], pshared);
  }

#if !defined(ANDROID_HOST_MUSL)
  // musl doesn't have pthread_rwlockattr_setkind_np
  int kind_array[] = {PTHREAD_RWLOCK_PREFER_READER_NP,
                      PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP};
  for (size_t i = 0; i < sizeof(kind_array) / sizeof(kind_array[0]); ++i) {
    ASSERT_EQ(0, pthread_rwlockattr_setkind_np(&attr, kind_array[i]));
    int kind;
    ASSERT_EQ(0, pthread_rwlockattr_getkind_np(&attr, &kind));
    ASSERT_EQ(kind_array[i], kind);
  }
#endif

  ASSERT_EQ(0, pthread_rwlockattr_destroy(&attr));
}

TEST(pthread, pthread_rwlock_init_same_as_PTHREAD_RWLOCK_INITIALIZER) {
  pthread_rwlock_t lock1 = PTHREAD_RWLOCK_INITIALIZER;
  pthread_rwlock_t lock2;
  ASSERT_EQ(0, pthread_rwlock_init(&lock2, nullptr));
  ASSERT_EQ(0, memcmp(&lock1, &lock2, sizeof(lock1)));
}

TEST(pthread, pthread_rwlock_smoke) {
  pthread_rwlock_t l;
  ASSERT_EQ(0, pthread_rwlock_init(&l, nullptr));

  // Single read lock
  ASSERT_EQ(0, pthread_rwlock_rdlock(&l));
  ASSERT_EQ(0, pthread_rwlock_unlock(&l));

  // Multiple read lock
  ASSERT_EQ(0, pthread_rwlock_rdlock(&l));
  ASSERT_EQ(0, pthread_rwlock_rdlock(&l));
  ASSERT_EQ(0, pthread_rwlock_unlock(&l));
  ASSERT_EQ(0, pthread_rwlock_unlock(&l));

  // Write lock
  ASSERT_EQ(0, pthread_rwlock_wrlock(&l));
  ASSERT_EQ(0, pthread_rwlock_unlock(&l));

  // Try writer lock
  ASSERT_EQ(0, pthread_rwlock_trywrlock(&l));
  ASSERT_EQ(EBUSY, pthread_rwlock_trywrlock(&l));
  ASSERT_EQ(EBUSY, pthread_rwlock_tryrdlock(&l));
  ASSERT_EQ(0, pthread_rwlock_unlock(&l));

  // Try reader lock
  ASSERT_EQ(0, pthread_rwlock_tryrdlock(&l));
  ASSERT_EQ(0, pthread_rwlock_tryrdlock(&l));
  ASSERT_EQ(EBUSY, pthread_rwlock_trywrlock(&l));
  ASSERT_EQ(0, pthread_rwlock_unlock(&l));
  ASSERT_EQ(0, pthread_rwlock_unlock(&l));

  // Try writer lock after unlock
  ASSERT_EQ(0, pthread_rwlock_wrlock(&l));
  ASSERT_EQ(0, pthread_rwlock_unlock(&l));

  // EDEADLK in "read after write"
  ASSERT_EQ(0, pthread_rwlock_wrlock(&l));
  ASSERT_EQ(EDEADLK, pthread_rwlock_rdlock(&l));
  ASSERT_EQ(0, pthread_rwlock_unlock(&l));

  // EDEADLK in "write after write"
  ASSERT_EQ(0, pthread_rwlock_wrlock(&l));
  ASSERT_EQ(EDEADLK, pthread_rwlock_wrlock(&l));
  ASSERT_EQ(0, pthread_rwlock_unlock(&l));

  ASSERT_EQ(0, pthread_rwlock_destroy(&l));
}

struct RwlockWakeupHelperArg {
  pthread_rwlock_t lock;
  enum Progress {
    LOCK_INITIALIZED,
    LOCK_WAITING,
    LOCK_RELEASED,
    LOCK_ACCESSED,
    LOCK_TIMEDOUT,
  };
  std::atomic<Progress> progress;
  std::atomic<pid_t> tid;
  std::function<int (pthread_rwlock_t*)> trylock_function;
  std::function<int (pthread_rwlock_t*)> lock_function;
  std::function<int (pthread_rwlock_t*, const timespec*)> timed_lock_function;
  clockid_t clock;
};

static void pthread_rwlock_wakeup_helper(RwlockWakeupHelperArg* arg) {
  arg->tid = gettid();
  ASSERT_EQ(RwlockWakeupHelperArg::LOCK_INITIALIZED, arg->progress);
  arg->progress = RwlockWakeupHelperArg::LOCK_WAITING;

  ASSERT_EQ(EBUSY, arg->trylock_function(&arg->lock));
  ASSERT_EQ(0, arg->lock_function(&arg->lock));
  ASSERT_EQ(RwlockWakeupHelperArg::LOCK_RELEASED, arg->progress);
  ASSERT_EQ(0, pthread_rwlock_unlock(&arg->lock));

  arg->progress = RwlockWakeupHelperArg::LOCK_ACCESSED;
}

static void test_pthread_rwlock_reader_wakeup_writer(std::function<int (pthread_rwlock_t*)> lock_function) {
  RwlockWakeupHelperArg wakeup_arg;
  ASSERT_EQ(0, pthread_rwlock_init(&wakeup_arg.lock, nullptr));
  ASSERT_EQ(0, pthread_rwlock_rdlock(&wakeup_arg.lock));
  wakeup_arg.progress = RwlockWakeupHelperArg::LOCK_INITIALIZED;
  wakeup_arg.tid = 0;
  wakeup_arg.trylock_function = &pthread_rwlock_trywrlock;
  wakeup_arg.lock_function = lock_function;

  pthread_t thread;
  ASSERT_EQ(0, pthread_create(&thread, nullptr,
    reinterpret_cast<void* (*)(void*)>(pthread_rwlock_wakeup_helper), &wakeup_arg));
  WaitUntilThreadSleep(wakeup_arg.tid);
  ASSERT_EQ(RwlockWakeupHelperArg::LOCK_WAITING, wakeup_arg.progress);

  wakeup_arg.progress = RwlockWakeupHelperArg::LOCK_RELEASED;
  ASSERT_EQ(0, pthread_rwlock_unlock(&wakeup_arg.lock));

  ASSERT_EQ(0, pthread_join(thread, nullptr));
  ASSERT_EQ(RwlockWakeupHelperArg::LOCK_ACCESSED, wakeup_arg.progress);
  ASSERT_EQ(0, pthread_rwlock_destroy(&wakeup_arg.lock));
}

TEST(pthread, pthread_rwlock_reader_wakeup_writer) {
  test_pthread_rwlock_reader_wakeup_writer(pthread_rwlock_wrlock);
}

TEST(pthread, pthread_rwlock_reader_wakeup_writer_timedwait) {
  timespec ts;
  ASSERT_EQ(0, clock_gettime(CLOCK_REALTIME, &ts));
  ts.tv_sec += 1;
  test_pthread_rwlock_reader_wakeup_writer([&](pthread_rwlock_t* lock) {
    return pthread_rwlock_timedwrlock(lock, &ts);
  });
}

TEST(pthread, pthread_rwlock_reader_wakeup_writer_timedwait_monotonic_np) {
#if defined(__BIONIC__)
  timespec ts;
  ASSERT_EQ(0, clock_gettime(CLOCK_MONOTONIC, &ts));
  ts.tv_sec += 1;
  test_pthread_rwlock_reader_wakeup_writer(
      [&](pthread_rwlock_t* lock) { return pthread_rwlock_timedwrlock_monotonic_np(lock, &ts); });
#else   // __BIONIC__
  GTEST_SKIP() << "pthread_
"""


```