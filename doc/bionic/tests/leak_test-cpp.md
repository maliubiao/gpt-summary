Response:
Let's break down the thought process for analyzing the `leak_test.cpp` file.

**1. Understanding the Goal:**

The first and most crucial step is to recognize the file's name and location: `bionic/tests/leak_test.cpp`. This immediately signals that its primary purpose is to test for memory leaks within Android's Bionic library. The inclusion of `<gtest/gtest.h>` further confirms this is a unit test.

**2. High-Level Overview:**

Quickly scan the code for key elements:

* **Includes:**  Note standard C/C++ libraries (`stdio.h`, `unistd.h`, `<vector>`), POSIX threading (`pthread.h`), system calls (`sys/syscall.h`), and Android-specific headers (`android-base/macros.h`, `android-base/threads.h`). The presence of `utils.h` suggests helper functions within the same directory or a nearby location.
* **Test Fixture (Implicit):**  Notice the `LeakChecker` class. This is the core of the leak detection mechanism.
* **Test Cases:**  Spot the `TEST()` macros. The names `pthread_leak.join` and `pthread_leak.detach` give hints about what's being tested.
* **Key Functions:** Identify `GetMappingSize()`, `WaitUntilAllThreadsExited()`, and the usage of `pthread_create`, `pthread_join`, `pthread_detach`, `pthread_barrier_init`, etc.

**3. Deconstructing `LeakChecker`:**

This class is central, so let's dissect it:

* **Purpose:** The comments and logic make it clear: it aims to detect increases in the total memory mapped by the process. The assumption is that if a test allocates memory and doesn't free it, the total mapped size will increase.
* **`previous_size_`:** Stores the initial mapped size.
* **`maps_`:** A vector to hold the parsed memory map information.
* **`Reset()`:** Updates `previous_size_` with the current mapped size. This allows checking for leaks between specific operations.
* **`Check()`:**  Compares the current mapped size with `previous_size_`. If the current size is larger, it signals a potential leak and `FAIL()`s the test.
* **`GetMappingSize()`:** This is the heart of the measurement. It calls `Maps::parse_maps()` (implying a function in `utils.h`) to get the memory map and then iterates through it, summing up the sizes of all mappings.

**4. Analyzing the Test Cases:**

* **`pthread_leak.join`:**
    * The `SKIP_WITH_NATIVE_BRIDGE` macro is interesting. It suggests a known issue when running under the Native Bridge (used for running ARM code on x86). This provides valuable context.
    * The "warm-up" section is a common practice in performance-sensitive tests or those dealing with initial allocations.
    * The core logic repeatedly creates and joins threads. The `LeakChecker` ensures that joining the thread properly releases any associated memory.
* **`pthread_leak.detach`:**
    * Again, `SKIP_WITH_NATIVE_BRIDGE`.
    * It creates multiple detached threads using `pthread_detach`. Detached threads clean up their resources automatically when they exit.
    * The `pthread_barrier` is used to synchronize the main thread and the child threads, ensuring the child threads have started and their TIDs have been recorded before proceeding.
    * `WaitUntilAllThreadsExited()` is crucial for ensuring all detached threads have finished before checking for leaks. This prevents false positives.
    * The conditional `lc.Reset()` suggests the first pass might be influenced by initial thread creation overhead and is used to establish a baseline.

**5. Examining Individual Functions:**

* **`WaitUntilAllThreadsExited()`:** Uses `syscall(__NR_tgkill, getpid(), tids[i], 0)` to check if a thread is still alive *without* sending a signal. The return value and `errno` are used to determine if the thread exists. `sched_yield()` is used to avoid busy-waiting.
* **`GetMappingSize()`:** Relies on `Maps::parse_maps()`. While the implementation isn't shown, the name strongly suggests it reads and parses `/proc/self/maps`.

**6. Connecting to Android:**

* **Bionic's Role:** Emphasize that this test directly targets Bionic, the foundational C library for Android.
* **Thread Management:** The tests specifically focus on `pthread` functions, which are part of Bionic's threading implementation.
* **Memory Management:** The leak checking mechanism is tied to the process's memory map, a core operating system concept managed (in part) by the kernel but with interfaces provided by Bionic.
* **Native Bridge:** Explain its purpose and why it causes issues with these specific tests.

**7. Addressing the Prompt's Specific Questions:**

Go through each point in the request systematically:

* **功能列举:** Summarize the high-level purpose (leak detection for `pthread`).
* **与 Android 功能的关系:** Explain the connection to Bionic's threading and memory management.
* **libc 函数功能实现:** Describe how `pthread_create`, `pthread_join`, `pthread_detach`, `pthread_barrier_init`, `syscall`, `getpid`, `sched_yield` work.
* **Dynamic Linker:**  Realize the code *doesn't directly* interact with the dynamic linker. Acknowledge this and explain *why* this type of test might not need to. Provide a general explanation of SO layout and linking for context.
* **逻辑推理:** The main logic is the memory map size comparison. Create simple "before" and "after" scenarios to illustrate how a leak would be detected.
* **用户/编程常见错误:**  Focus on common `pthread` usage mistakes that lead to leaks (forgetting to `join` or `detach`).
* **Android Framework/NDK to Here:** Explain the path from application code, through the NDK, to the Bionic library. Provide a Frida hook example.

**8. Structuring the Answer:**

Organize the information logically, using headings and bullet points for clarity. Start with a high-level summary and then delve into details. Address each part of the prompt thoroughly.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the test directly allocates memory with `malloc`.
* **Correction:** The test focuses on thread-related leaks, so the memory increase is likely due to internal thread management structures.
* **Initial thought:**  Provide a very detailed explanation of dynamic linking.
* **Refinement:**  Recognize that this specific test doesn't directly involve dynamic linking. Provide a more general explanation instead.
* **Ensuring Clarity:**  Constantly re-read the prompt to make sure all questions are answered directly and clearly. Use examples where appropriate.

By following these steps, you can systematically analyze the code and generate a comprehensive and accurate response to the prompt.
好的，我们来详细分析一下 `bionic/tests/leak_test.cpp` 这个文件。

**文件功能列举：**

该文件的主要功能是测试 Android Bionic 库中与线程相关的操作（主要是 `pthread` 系列函数）是否存在内存泄漏。 具体来说，它测试了以下场景：

1. **`pthread_join` 的泄漏测试:**  测试重复创建并 `join` 线程，确保每次 `join` 操作后，线程相关的资源能够被正确释放，不会导致内存占用持续增长。
2. **`pthread_detach` 的泄漏测试:** 测试创建并 `detach` 的线程，确保即使线程分离后，其资源也能在线程结束后被系统回收，不会造成内存泄漏。

**与 Android 功能的关系及举例说明：**

这个文件直接测试了 Android 系统底层库 Bionic 的功能，而 Bionic 是 Android 系统运行的基础。

* **线程管理:** `pthread_create`, `pthread_join`, `pthread_detach` 是 POSIX 线程标准中的函数，Bionic 提供了这些函数的实现。Android 应用和 Native 代码广泛使用这些函数来创建和管理线程。如果这些函数存在泄漏，会导致整个 Android 系统资源的浪费，甚至导致系统崩溃。
    * **举例:**  一个 Android 应用使用 NDK 创建了一个后台线程来处理网络请求。如果 `pthread_create` 或其内部机制存在泄漏，那么每次启动这个后台线程都会消耗一些内存，久而久之，应用可能会因为内存不足而崩溃。
* **系统调用:**  `syscall(__NR_tgkill, ...)` 用于检查线程是否存在。这是一个直接与 Linux 内核交互的系统调用。Bionic 封装了一些常用的系统调用，并提供更方便的接口，但有时为了更精细的控制，也会直接使用 `syscall`。
    * **举例:**  在 Android 的进程管理中，系统可能需要强制终止某个线程。这可能会用到类似的系统调用。
* **内存映射:** `sys/mman.h` 中包含的 `mmap` 等函数用于内存映射。`LeakChecker` 类通过读取 `/proc/self/maps` 文件来监控进程的内存映射大小。Bionic 的很多功能，例如动态链接器的加载和卸载动态库，都涉及到内存映射。
    * **举例:**  当一个 Android 应用启动时，它的代码和依赖的动态库会被加载到内存中，这涉及到 `mmap` 操作。

**libc 函数的功能实现详解：**

让我们逐个解释文件中使用的 libc 函数的功能和可能的实现方式：

* **`err(int eval, const char *fmt, ...)`:**
    * **功能:** 这是一个用于报告错误的函数。它会输出格式化的错误信息到标准错误流 (stderr)，并以指定的 `eval` 值退出程序。
    * **实现:**  通常 `err` 函数会调用 `fprintf(stderr, ...)` 来格式化输出错误信息，并可能包含当前程序名。最后调用 `exit(eval)` 终止程序。
* **`inttypes.h` 中的类型 (例如 `uintptr_t`)：**
    * **功能:**  定义了各种跨平台的整数类型，例如 `uintptr_t` 用于存储指针的无符号整数。
    * **实现:**  这些类型通常是 `typedef` 到特定平台上的标准整数类型，例如在 64 位系统上 `uintptr_t` 可能 `typedef` 到 `unsigned long int`。
* **`pthread.h` 中的线程相关函数：**
    * **`pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg)`:**
        * **功能:** 创建一个新的线程。
        * **实现:** 这通常涉及到调用底层的系统调用（例如 Linux 上的 `clone` 或 `fork` + `execve` 的变体），为新线程分配栈空间，设置线程的属性（如优先级），并启动执行 `start_routine` 函数。
    * **`pthread_join(pthread_t thread, void **retval)`:**
        * **功能:** 等待指定的线程结束。
        * **实现:**  这通常通过一个同步机制实现，例如互斥锁和条件变量。调用 `pthread_join` 的线程会阻塞，直到目标线程调用 `pthread_exit` 或从其启动函数返回。如果 `retval` 不为 `NULL`，它将指向目标线程的返回值。
    * **`pthread_detach(pthread_t thread)`:**
        * **功能:** 将指定的线程设置为 detached 状态。 detached 线程在结束后会自动释放其资源，不需要其他线程调用 `pthread_join` 来清理。
        * **实现:**  这通常会修改线程的属性，标记其为 detached。当 detached 线程退出时，系统会自动回收其栈空间和其他资源。
    * **`pthread_barrier_init(pthread_barrier_t *barrier, const pthread_barrierattr_t *attr, unsigned count)`:**
        * **功能:** 初始化一个线程屏障。屏障允许一组线程同步执行，所有线程必须都到达屏障后才能继续执行。
        * **实现:**  屏障通常使用互斥锁和条件变量实现。每个到达屏障的线程都会尝试获取锁并检查计数器。当计数器达到指定的值时，所有等待的线程会被唤醒。
    * **`pthread_barrier_wait(pthread_barrier_t *barrier)`:**
        * **功能:**  线程在屏障处等待，直到所有参与的线程都到达。
        * **实现:**  线程会尝试获取屏障的锁，并检查是否所有线程都已到达。如果没有，线程会进入条件变量的等待状态。
    * **`pthread_barrier_destroy(pthread_barrier_t *barrier)`:**
        * **功能:** 销毁一个线程屏障，释放相关的资源。
        * **实现:**  通常会销毁内部使用的互斥锁和条件变量。
* **`sched.h` 中的 `sched_yield(void)`:**
    * **功能:**  主动放弃当前线程的 CPU 时间片，让操作系统调度其他线程执行。
    * **实现:**  这是一个系统调用，通知内核当前线程愿意放弃 CPU，允许其他就绪的线程运行。
* **`stdio.h` 中的 `printf(const char *format, ...)` 和 `fprintf(FILE *stream, const char *format, ...)`:**
    * **功能:**  格式化输出数据到标准输出 (stdout) 或指定的文件流。
    * **实现:**  这些函数会解析格式化字符串，并将提供的参数按照指定格式转换为字符串并输出。
* **`string.h` 中的 `strcmp(const char *s1, const char *s2)`:**
    * **功能:**  比较两个字符串。
    * **实现:**  通常会逐个字符比较两个字符串，直到找到不同的字符或到达字符串末尾。返回值为 0 表示字符串相等，负数表示 `s1` 小于 `s2`，正数表示 `s1` 大于 `s2`。
* **`sys/mman.h` 中的 `mmap(...)` (虽然代码中未使用，但 `GetMappingSize` 间接相关):**
    * **功能:**  将文件或设备映射到内存中。
    * **实现:**  这是一个系统调用，它会在进程的地址空间中创建一个新的虚拟内存区域，并将其映射到指定的文件或设备。
* **`sys/syscall.h` 中的 `syscall(long number, ...)`:**
    * **功能:**  直接执行系统调用。
    * **实现:**  这是一个汇编指令，用于陷入内核模式，执行指定编号的系统调用。
* **`sys/user.h` 中的结构体 (例如 `struct user_regs_struct`)：**
    * **功能:**  定义了用户态寄存器的结构，用于访问和修改用户态进程的寄存器状态（通常用于调试和性能分析）。
    * **实现:**  这些结构体的定义与具体的 CPU 架构相关。
* **`unistd.h` 中的函数：**
    * **`sleep(unsigned int seconds)`:**  使当前线程休眠指定的秒数。
        * **实现:**  调用底层的系统调用，让当前线程进入睡眠状态，直到指定的延迟时间到达或收到信号。
    * **`usleep(useconds_t usec)`:** 使当前线程休眠指定的微秒数。
        * **实现:**  类似于 `sleep`，但精度更高。
    * **`getpid(void)`:** 获取当前进程的进程 ID。
        * **实现:**  这是一个系统调用，内核维护着进程 ID，调用此函数返回当前进程的 ID。
    * **`gettid(void)`:** 获取当前线程的线程 ID。
        * **实现:**  这是一个系统调用，内核维护着线程 ID，调用此函数返回当前线程的 ID。
    * **`sysconf(int name)`:**  获取系统配置信息，例如 CPU 核心数。
        * **实现:**  这是一个系统调用，内核维护着各种系统配置信息。

**涉及 dynamic linker 的功能：**

这个测试文件本身**并没有直接涉及到 dynamic linker 的操作**。它主要关注的是线程创建和销毁过程中可能产生的内存泄漏，而不是动态库的加载和卸载。

**如果这个测试要涉及 dynamic linker，我们来看一个可能的场景和处理过程：**

**假设输入:**

一个动态库 `libtest.so` 被 `dlopen` 加载，然后在某个时刻 `dlclose` 卸载。测试的目的是检查加载和卸载动态库后，进程的内存映射是否恢复到加载前的状态，以排除 dynamic linker 导致的泄漏。

**对应的 so 布局样本 `libtest.so`:**

```
LOAD           0x0000000000000000  0x0000000000000000  0x0000000000000000  0x000000000000051c  R E   1000
LOAD           0x0000000000200000  0x0000000000200000  0x0000000000000520  0x00000000000000ec  RW    1000
```

* **LOAD:** 表示可加载的 segment。
* **第一个地址 (0x000...)**:  segment 在文件中的偏移。
* **第二个地址 (0x000...)**:  segment 加载到内存中的起始地址 (虚拟地址)。
* **第三个地址 (0x000...)**:  segment 的文件大小。
* **第四个地址 (0x000...)**:  segment 在内存中的大小 (可能大于文件大小，因为有 BSS 段)。
* **R E:**  表示该 segment 的权限（Read, Execute）。
* **RW:**  表示该 segment 的权限（Read, Write）。

**链接的处理过程:**

1. **`dlopen("libtest.so", RTLD_NOW)`:**
   - Dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会查找 `libtest.so` 文件。
   - 它会解析 `libtest.so` 的 ELF 头和 Program Header，读取 LOAD segment 的信息。
   - Dynamic linker 会调用 `mmap` 系统调用，根据 LOAD segment 的信息在进程的地址空间中分配内存区域，并将 `libtest.so` 的内容加载到这些内存区域。
   - 如果 `libtest.so` 依赖其他共享库，这个过程会递归进行。
   - Dynamic linker 还会处理符号的重定位，将 `libtest.so` 中引用的外部符号地址链接到实际的地址。
2. **`dlclose(handle)`:**
   - Dynamic linker 接收到卸载请求。
   - 它会递减 `libtest.so` 的引用计数。如果引用计数变为 0，表示没有其他模块在使用这个库。
   - Dynamic linker 会调用 `munmap` 系统调用，释放之前通过 `mmap` 分配的内存区域。
   - 它还会清理与该动态库相关的内部数据结构。

**泄漏测试的逻辑推理:**

* **假设输入:** 在测试开始时记录进程的内存映射大小 `initial_size`。然后 `dlopen("libtest.so")`，再次记录大小 `after_load_size`。接着 `dlclose(handle)`，最后记录大小 `after_unload_size`。
* **预期输出:**  `after_unload_size` 应该与 `initial_size` 相等，或者非常接近（可能存在一些小的、可忽略的差异）。如果 `after_unload_size` 明显大于 `initial_size`，则可能存在 dynamic linker 导致的内存泄漏。

**用户或者编程常见的使用错误举例说明:**

* **忘记 `pthread_join` 或 `pthread_detach`:**  如果创建的线程既没有 `join` 也没有 `detach`，那么线程退出后，其资源可能不会立即释放，导致泄漏。
    ```c++
    void* thread_func(void*) {
        // ...
        return nullptr;
    }

    void test_leak() {
        pthread_t thread;
        pthread_create(&thread, nullptr, thread_func, nullptr);
        // 忘记 pthread_join 或 pthread_detach
    }
    ```
* **在循环中重复创建线程而不 `join` 或 `detach`:** 这会导致大量线程资源被消耗，最终可能耗尽系统资源。
    ```c++
    void test_leak_loop() {
        for (int i = 0; i < 1000; ++i) {
            pthread_t thread;
            pthread_create(&thread, nullptr, thread_func, nullptr);
            pthread_detach(thread); // 即使 detach，如果创建速度过快也可能导致问题
        }
    }
    ```
* **`dlopen` 后忘记 `dlclose`:**  如果动态库被加载后忘记卸载，那么它占用的内存将一直存在，导致泄漏。
    ```c++
    void test_dlopen_leak() {
        void* handle = dlopen("libtest.so", RTLD_NOW);
        if (handle == nullptr) {
            // 处理错误
        }
        // 忘记 dlclose(handle);
    }
    ```
* **多次 `dlclose` 同一个 handle:** 这可能导致 double free 或其他内存错误。

**Android Framework 或 NDK 如何一步步到达这里，给出 Frida hook 示例调试这些步骤。**

1. **Android Framework 调用 (例如，Java 代码创建线程):**
   - Java 代码使用 `java.lang.Thread` 类创建线程。
   - `java.lang.Thread` 的底层实现会通过 JNI (Java Native Interface) 调用到 Native 代码。

2. **NDK 层 (Native 代码使用 `pthread`):**
   - NDK 开发者可以使用 `pthread.h` 中的函数来创建和管理线程。
   - 例如，在 Native 代码中调用 `pthread_create`。

3. **Bionic 库:**
   - NDK 中使用的 `pthread_create` 等函数最终会调用到 Android Bionic 库中对应的实现。

4. **系统调用:**
   - Bionic 的 `pthread_create` 实现会调用底层的 Linux 系统调用（如 `clone`）来创建新的内核线程。

**Frida Hook 示例调试步骤：**

假设我们要 hook `pthread_create` 函数，查看其调用栈和参数。

```python
import frida
import sys

package_name = "your.app.package" # 替换成你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['message']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), {
    onEnter: function(args) {
        var thread = ptr(args[0]);
        var attr = ptr(args[1]);
        var start_routine = ptr(args[2]);
        var arg = ptr(args[3]);

        send({
            tag: "pthread_create",
            message: "pthread_create called\n" +
                     "  Thread pointer: " + thread + "\n" +
                     "  Attributes: " + attr + "\n" +
                     "  Start routine: " + start_routine + "\n" +
                     "  Argument: " + arg + "\\n" +
                     "  Backtrace:\\n" +
                     Thread.backtrace().map(DebugSymbol.fromAddress).join("\\n")
        });
    },
    onLeave: function(retval) {
        send({
            tag: "pthread_create",
            message: "pthread_create returned: " + retval
        });
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida Hook 代码：**

1. **`frida.get_usb_device().attach(package_name)`:** 连接到 USB 连接的 Android 设备，并附加到指定的应用进程。
2. **`Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"), ...)`:**  拦截 `libc.so` 库中的 `pthread_create` 函数。
3. **`onEnter`:**  在 `pthread_create` 函数调用之前执行。
   - `args` 数组包含了 `pthread_create` 的参数。
   - `Thread.backtrace()` 获取当前线程的调用栈。
   - `DebugSymbol.fromAddress` 将地址转换为符号信息。
   - `send()` 函数将信息发送回 Frida 客户端。
4. **`onLeave`:** 在 `pthread_create` 函数调用之后执行。
   - `retval` 包含了 `pthread_create` 的返回值。

**运行 Frida Hook 的步骤：**

1. 确保你的 Android 设备已连接并通过 USB 调试。
2. 确保你的电脑上安装了 Frida 和 Frida 工具。
3. 运行你要调试的 Android 应用。
4. 运行上面的 Python Frida 脚本。
5. 当应用中调用 `pthread_create` 时，Frida 脚本会拦截并打印出相关信息，包括调用栈和参数。

通过 Frida Hook，你可以深入了解 Android Framework 或 NDK 如何一步步调用到 Bionic 库的函数，以及这些函数的参数和执行流程，从而帮助你调试和理解底层机制。

希望以上详细的分析能够帮助你理解 `bionic/tests/leak_test.cpp` 文件的功能和相关概念。

Prompt: 
```
这是目录为bionic/tests/leak_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2017 The Android Open Source Project
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

#include <err.h>
#include <inttypes.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <chrono>
#include <thread>
#include <vector>

#include <android-base/macros.h>
#include <android-base/threads.h>

#include "utils.h"

using namespace std::chrono_literals;

static void WaitUntilAllThreadsExited(pid_t* tids, size_t tid_count) {
  // Wait until all children have exited.
  bool alive = true;
  while (alive) {
    alive = false;
    for (size_t i = 0; i < tid_count; ++i) {
      if (tids[i] != 0) {
        if (syscall(__NR_tgkill, getpid(), tids[i], 0) == 0) {
          alive = true;
        } else {
          EXPECT_ERRNO(ESRCH);
          tids[i] = 0;  // Skip in next loop.
        }
      }
    }
    sched_yield();
  }
}

class LeakChecker {
 public:
  LeakChecker() {
    // Avoid resizing and using memory later.
    // 64Ki is the default limit on VMAs per process.
    maps_.reserve(64*1024);
    Reset();
  }

  ~LeakChecker() {
    Check();
  }

  void Reset() {
    previous_size_ = GetMappingSize();
  }

  void DumpTo(std::ostream& os) const {
    os << previous_size_;
  }

 private:
  size_t previous_size_;
  std::vector<map_record> maps_;

  void Check() {
    auto current_size = GetMappingSize();
    if (current_size > previous_size_) {
      FAIL() << "increase in process map size: " << previous_size_ << " -> " << current_size;
    }
  }

  size_t GetMappingSize() {
    if (!Maps::parse_maps(&maps_)) {
      err(1, "failed to parse maps");
    }

    size_t result = 0;
    for (const map_record& map : maps_) {
      result += map.addr_end - map.addr_start;
    }

    return result;
  }
};

std::ostream& operator<<(std::ostream& os, const LeakChecker& lc) {
  lc.DumpTo(os);
  return os;
}

// http://b/36045112
TEST(pthread_leak, join) {
  SKIP_WITH_NATIVE_BRIDGE;  // http://b/37920774

  // Warm up. HWASan allocates an extra page on the first iteration, but never after.
  pthread_t thread;
  ASSERT_EQ(0, pthread_create(
                   &thread, nullptr, [](void*) -> void* { return nullptr; }, nullptr));
  ASSERT_EQ(0, pthread_join(thread, nullptr));

  LeakChecker lc;

  for (int i = 0; i < 100; ++i) {
    ASSERT_EQ(0, pthread_create(
                     &thread, nullptr, [](void*) -> void* { return nullptr; }, nullptr));
    ASSERT_EQ(0, pthread_join(thread, nullptr));
  }
}

// http://b/36045112
TEST(pthread_leak, detach) {
  SKIP_WITH_NATIVE_BRIDGE;  // http://b/37920774

  LeakChecker lc;

  // Ancient devices with only 2 cores need a lower limit.
  // http://b/129924384 and https://issuetracker.google.com/142210680.
  const int thread_count = (sysconf(_SC_NPROCESSORS_CONF) > 2) ? 100 : 50;

  for (size_t pass = 0; pass < 1; ++pass) {
    struct thread_data { pthread_barrier_t* barrier; pid_t* tid; } threads[thread_count];

    pthread_barrier_t barrier;
    ASSERT_EQ(pthread_barrier_init(&barrier, nullptr, thread_count + 1), 0);

    // Start child threads.
    pid_t tids[thread_count];
    for (int i = 0; i < thread_count; ++i) {
      threads[i] = {&barrier, &tids[i]};
      const auto thread_function = +[](void* ptr) -> void* {
        thread_data* data = static_cast<thread_data*>(ptr);
        *data->tid = gettid();
        pthread_barrier_wait(data->barrier);
        return nullptr;
      };
      pthread_t thread;
      ASSERT_EQ(0, pthread_create(&thread, nullptr, thread_function, &threads[i]));
      ASSERT_EQ(0, pthread_detach(thread));
    }

    pthread_barrier_wait(&barrier);
    ASSERT_EQ(pthread_barrier_destroy(&barrier), 0);

    WaitUntilAllThreadsExited(tids, thread_count);

    // TODO(b/158573595): the test is flaky without the warmup pass.
    if (pass == 0) lc.Reset();
  }
}

"""

```