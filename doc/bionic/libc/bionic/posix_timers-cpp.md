Response:
Let's break down the thought process to generate the detailed explanation of `posix_timers.cpp`.

**1. Understanding the Core Request:**

The request asks for a comprehensive analysis of `posix_timers.cpp`, focusing on its functionality, relation to Android, implementation details, dynamic linking aspects, error scenarios, and how it's used in the Android ecosystem. It also requires Frida hook examples.

**2. Initial High-Level Analysis:**

The filename `posix_timers.cpp` and the include of `<time.h>` immediately suggest this file implements POSIX timers. The comments confirm this, stating it handles `SIGEV_THREAD` timers and relies on kernel support for other types. The imports like `pthread.h` and `stdatomic.h` hint at multithreading and atomic operations, which are crucial for managing asynchronous events. The inclusion of `private/bionic_lock.h` indicates the use of custom locking mechanisms within Bionic.

**3. Deconstructing the Code - Function by Function:**

The next step is to go through each function defined in the file and understand its purpose. This involves:

* **Identifying the POSIX function being implemented:**  The comments like `// https://pubs.opengroup.org/...` clearly link the functions to their POSIX counterparts (e.g., `timer_create`, `timer_delete`, etc.).
* **Analyzing the core logic:**  For each function, determine the primary actions. For example:
    * `timer_create`: Allocate memory, handle `SIGEV_THREAD` differently, create a kernel timer, potentially create a new thread.
    * `timer_delete`: Delete the kernel timer, potentially stop and free the associated thread.
    * `timer_gettime` and `timer_settime`: Directly interact with the kernel timer.
    * `timer_getoverrun`:  Query the kernel for overrun information.
* **Focusing on `SIGEV_THREAD` handling:**  The code explicitly distinguishes between `SIGEV_THREAD` and other notification types. This is a key area to understand, involving thread creation, signal handling, and synchronization.
* **Identifying System Calls:** The `extern "C"` declarations point to direct system calls (prefixed with `__`). Understanding these calls (`__rt_sigprocmask`, `__rt_sigtimedwait`, `__timer_create`, etc.) is crucial for grasping how the library interacts with the kernel.

**4. Connecting to Android:**

The prompt specifically asks about the connection to Android. This requires thinking about how POSIX timers are used in Android development:

* **NDK Usage:** NDK developers can directly use these functions.
* **Android Framework:**  The Android framework itself relies on these lower-level primitives for various timing mechanisms (e.g., `AlarmManager` internally likely uses timers).
* **Java `java.util.Timer`:**  While not directly using these C++ functions, it's conceptually related and offers a higher-level abstraction.

**5. Dynamic Linking Considerations:**

The prompt mentions the dynamic linker. This requires understanding:

* **Shared Objects (.so):**  `libc.so` is the relevant shared object.
* **Symbol Resolution:** When an application uses `timer_create`, the dynamic linker resolves this symbol to the implementation in `libc.so`.
* **SO Layout:**  A basic mental model of the SO structure (code, data, GOT, PLT) is helpful.
* **Linking Process:** Briefly describe how the linker finds and resolves symbols.

**6. Error Scenarios and Common Mistakes:**

Think about how developers might misuse these functions:

* **Incorrect `sigevent` setup:**  Especially for `SIGEV_THREAD`, forgetting to set the callback function or attributes.
* **Memory Leaks:**  Not properly deleting timers.
* **Race Conditions (although the provided code tries to mitigate them):**  Incorrectly interacting with timers from multiple threads without proper synchronization.

**7. Tracing the Execution Flow (Android Framework/NDK to `posix_timers.cpp`):**

This involves outlining a simplified call stack:

* **NDK:**  A direct call from C/C++ code using the NDK.
* **Framework (simplified):** A higher-level Android service (e.g., `AlarmManager`) calling into native code, which eventually uses the POSIX timer functions.

**8. Frida Hooking:**

Consider what aspects of the timer creation and triggering would be useful to observe:

* **`timer_create`:**  Hooking the entry and exit to see the arguments and the created timer ID.
* **The Callback Function:** Hooking the execution of the callback function itself to observe when it's triggered and with what arguments.

**9. Structuring the Answer:**

Organize the information logically:

* **Introduction:** Briefly state the file's purpose.
* **Functionality:** List the core functions and their roles.
* **Android Relationship:** Explain how these timers are used in the Android ecosystem.
* **Function Implementations:** Detail the implementation of each function, paying special attention to `SIGEV_THREAD`.
* **Dynamic Linking:** Explain the role of the dynamic linker.
* **Error Scenarios:** Provide examples of common mistakes.
* **Android Usage Path:**  Illustrate how the framework and NDK lead to this code.
* **Frida Hooking:** Give concrete examples of how to use Frida for debugging.

**10. Refinement and Language:**

* **Use clear and concise language.**
* **Provide specific code examples where appropriate.**
* **Ensure the technical details are accurate.**
* **Translate any technical terms into Chinese accurately.**

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe focus too much on the low-level kernel details. **Correction:**  Balance kernel interaction with the higher-level C library API and its usage in Android.
* **Initial thought:**  Just list the functions. **Correction:** Provide detailed explanations of the internal workings, especially for `SIGEV_THREAD`.
* **Initial thought:**  Assume deep knowledge of dynamic linking. **Correction:** Provide a simplified explanation suitable for a broader audience.
* **Initial thought:**  Overcomplicate the Frida examples. **Correction:** Focus on simple but illustrative hooks.

By following this systematic approach, combining code analysis with an understanding of the broader Android ecosystem and common development practices, we can generate a comprehensive and accurate answer to the prompt.
这是一个关于 Android Bionic 库中 `posix_timers.cpp` 文件的功能详解。这个文件实现了 POSIX 计时器 API，并在 Android 系统中扮演着重要的角色。

**文件功能概要:**

`bionic/libc/bionic/posix_timers.cpp` 实现了以下 POSIX 计时器相关的函数：

* **`timer_create()`:** 创建一个 POSIX 计时器。
* **`timer_delete()`:** 删除一个 POSIX 计时器。
* **`timer_gettime()`:** 获取一个 POSIX 计时器的当前剩余时间和间隔。
* **`timer_settime()`:** 设置或启动一个 POSIX 计时器。
* **`timer_getoverrun()`:** 获取一个到期的 POSIX 计时器的溢出次数。

**与 Android 功能的关系及举例说明:**

POSIX 计时器是操作系统提供的一种机制，允许程序在指定的时间后接收通知。在 Android 中，它们被广泛用于各种需要定时执行任务的场景。

**举例说明:**

1. **`AlarmManager` (Android Framework):** `AlarmManager` 是 Android Framework 中用于安排在未来某个时间执行操作的服务。在底层实现中，`AlarmManager`  会使用 POSIX 计时器来触发预定的事件。例如，当你设置一个闹钟时，`AlarmManager` 可能会使用一个 `CLOCK_REALTIME_ALARM` 类型的计时器，并在指定的时间发送一个 Intent。

2. **`Handler` 和 `Looper` (Android Framework):** 虽然 `Handler` 和 `Looper` 主要用于线程间通信和消息处理，但它们也支持延迟消息的发送。这种延迟发送的实现也可能在底层利用 POSIX 计时器来实现。

3. **NDK 开发中的定时任务:** 使用 NDK 进行原生开发的应用程序可以直接调用 `timer_create` 等 POSIX 计时器函数来实现自己的定时任务，例如周期性地检查网络连接状态或更新 UI。

**详细解释每一个 libc 函数的功能是如何实现的:**

**1. `timer_create(clockid_t clock_id, sigevent* evp, timer_t* timer_id)`:**

* **功能:** 创建一个新的 POSIX 计时器。
* **实现细节:**
    * 分配一个 `PosixTimer` 结构体的内存来存储计时器的状态信息。
    * 初始化 `kernel_timer_id` 为 -1，表示内核计时器尚未创建。
    * 根据 `evp` 参数判断计时器的通知方式 (`sigev_notify`)：
        * **`SIGEV_SIGNAL` (或 `evp` 为 `nullptr`):**  创建一个传统的信号驱动的计时器。这种情况下，`__timer_create` 系统调用会被直接调用，由内核来管理计时器和信号发送。
        * **`SIGEV_THREAD`:** 创建一个线程驱动的计时器。这种情况下，Bionic 会创建一个专门的线程来处理计时器到期事件。
            * 存储回调函数 (`evp->sigev_notify_function`) 和回调参数 (`evp->sigev_value`)。
            * 创建一个新的 detached 线程 (`__timer_thread_start`)。
            * 在新线程中，会通过 `__rt_sigtimedwait` 等待由内核发送的特定信号 (`TIMER_SIGNAL`)。
            * 在父线程中，使用 `__timer_create` 系统调用创建一个内核计时器，并将信号通知目标设置为新创建的线程 ID (`SIGEV_THREAD_ID`) 和 `TIMER_SIGNAL`。
            * 使用互斥锁 (`startup_handshake_lock`) 来同步父子线程，确保内核计时器在子线程开始等待信号之前创建。
    * 将新创建的 `PosixTimer` 结构的地址赋值给 `*timer_id`。

**2. `timer_delete(timer_t id)`:**

* **功能:** 删除一个先前创建的 POSIX 计时器。
* **实现细节:**
    * 调用 `__timer_delete` 系统调用来删除内核中的计时器。
    * 获取 `PosixTimer` 结构体的指针。
    * 如果计时器是 `SIGEV_THREAD` 类型的，则调用 `__timer_thread_stop` 来停止并释放计时器线程。`__timer_thread_stop` 会设置 `deleted` 标志，并向计时器线程发送一个信号 (`TIMER_SIGNAL`)，使其退出并释放 `PosixTimer` 结构体的内存。
    * 如果计时器不是 `SIGEV_THREAD` 类型的，则直接 `free` 掉 `PosixTimer` 结构体的内存。

**3. `timer_gettime(timer_t id, itimerspec* ts)`:**

* **功能:** 获取指定计时器的剩余时间和间隔。
* **实现细节:** 直接调用 `__timer_gettime` 系统调用，由内核返回计时器的信息。

**4. `timer_settime(timer_t id, int flags, const itimerspec* ts, itimerspec* ots)`:**

* **功能:** 设置或启动指定计时器。
* **实现细节:**
    * 获取 `PosixTimer` 结构体的指针。
    * 直接调用 `__timer_settime` 系统调用，将新的时间参数传递给内核。`flags` 参数可以控制计时器是相对时间还是绝对时间，以及是否修改已经启动的计时器。
    * 注释中提到，对于 `SIGEV_THREAD` 类型的计时器，当周期非常小时，即使调用此函数停止计时器，内核可能仍然会发送几次事件到回调线程，这是符合 POSIX 标准的。

**5. `timer_getoverrun(timer_t id)`:**

* **功能:** 获取指定计时器自上次事件以来，错过的计时器到期事件的次数。
* **实现细节:** 直接调用 `__timer_getoverrun` 系统调用，由内核返回溢出次数。

**涉及 dynamic linker 的功能及处理过程:**

此文件中，与 dynamic linker 直接相关的部分是 libc 函数的导出和应用程序的链接过程。

**so 布局样本 (简化):**

```
libc.so:
    .text:
        timer_create:  // timer_create 函数的代码
        timer_delete:  // timer_delete 函数的代码
        ...
    .data:
        ...
    .got:           // Global Offset Table
        __timer_create@LIBC // 指向 __timer_create 系统调用入口的地址
        __timer_delete@LIBC
        ...
    .plt:           // Procedure Linkage Table
        timer_create:
            jmp *__timer_create@GOT
        timer_delete:
            jmp *__timer_delete@GOT
        ...
```

**链接的处理过程:**

1. **编译时:** 当应用程序调用 `timer_create` 等函数时，编译器会在应用程序的目标文件中生成对这些符号的未解析引用。

2. **链接时:**  链接器 (在 Android 中通常是 `lld`) 在链接应用程序时，会查找所需的共享库 (`libc.so`)。

3. **符号解析:** 链接器会遍历 `libc.so` 的符号表，找到 `timer_create` 等符号的定义。

4. **重定位:** 链接器会修改应用程序目标文件中的未解析引用，使其指向 `libc.so` 中对应函数的地址。具体来说，会更新 GOT (Global Offset Table) 中的条目。

5. **运行时:** 当应用程序启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会加载所有需要的共享库到内存中。

6. **延迟绑定 (Lazy Binding):** 默认情况下，为了优化启动时间，符号的解析是延迟的。当应用程序第一次调用 `timer_create` 时，会跳转到 PLT (Procedure Linkage Table) 中的代码。PLT 中的代码会调用 dynamic linker 来解析 `__timer_create` 等系统调用的地址，并将解析后的地址写入 GOT 中。后续对 `timer_create` 的调用将直接通过 GOT 跳转到正确的系统调用入口。

**假设输入与输出 (逻辑推理):**

**`timer_create` 假设:**

* **输入:**
    * `clock_id = CLOCK_REALTIME`
    * `evp`: 指向一个 `sigevent` 结构，其中 `sigev_notify = SIGEV_THREAD`, `sigev_notify_function = my_timer_callback`, `sigev_value.sival_int = 123`
    * `timer_id`: 指向一个 `timer_t` 变量的指针

* **输出:**
    * 如果成功，`*timer_id` 将包含新创建的计时器的 ID (实际上是指向 `PosixTimer` 结构体的指针)，函数返回 0。
    * 如果失败（例如内存分配失败），函数返回 -1，并设置相应的 `errno` (例如 `ENOMEM`)。

**`timer_settime` 假设:**

* **输入:**
    * `id`: 一个有效的计时器 ID
    * `flags = 0` (相对定时)
    * `ts`: 指向一个 `itimerspec` 结构，其中 `it_value.tv_sec = 1`, `it_value.tv_nsec = 0` (1秒后触发一次)
    * `ots`: 指向一个 `itimerspec` 结构的指针，用于接收之前的计时器设置 (可以为 `nullptr`)

* **输出:**
    * 如果成功，计时器将在 1 秒后触发。如果 `ots` 不为 `nullptr`，它将包含计时器之前的设置。函数返回 0。
    * 如果失败（例如 `id` 无效），函数返回 -1，并设置相应的 `errno` (例如 `EINVAL`)。

**用户或编程常见的使用错误举例说明:**

1. **未检查返回值:** 调用 `timer_create` 或 `timer_settime` 后不检查返回值，可能导致在计时器创建或设置失败时程序行为异常。

   ```c
   timer_t timerid;
   struct sigevent sev;
   // ... 初始化 sev ...

   timer_create(CLOCK_REALTIME, &sev, &timerid); // 缺少错误检查
   // 假设创建失败，timerid 的值可能未定义，后续使用会出错
   ```

2. **`SIGEV_THREAD` 计时器回调函数中的错误处理不当:**  `SIGEV_THREAD` 的回调函数运行在单独的线程中。如果在回调函数中发生未捕获的异常或错误，可能会导致程序崩溃或行为不稳定。

3. **忘记删除计时器:**  创建的计时器如果没有被 `timer_delete` 删除，可能会导致资源泄漏。

4. **在多线程环境中不安全地访问计时器:**  如果多个线程同时尝试修改或删除同一个计时器，可能会导致竞争条件。

5. **`sigevent` 结构体初始化不正确:** 特别是对于 `SIGEV_THREAD` 类型的计时器，必须正确设置 `sigev_notify_function`。

   ```c
   timer_t timerid;
   struct sigevent sev = {0};
   sev.sigev_notify = SIGEV_THREAD;
   // 忘记设置 sev.sigev_notify_function

   timer_create(CLOCK_REALTIME, &sev, &timerid); // 可能导致程序崩溃
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `posix_timers.cpp` 的路径 (简化):**

1. **Java 代码调用 `AlarmManager`:** 例如，使用 `AlarmManager.set()` 方法设置一个闹钟。

2. **Framework 层处理:** `AlarmManagerService` (运行在 System Server 进程中) 接收到请求。

3. **Native 代码调用:** `AlarmManagerService` 通过 JNI 调用到 native 代码中，通常会涉及 `android_server_AlarmManagerService.cpp` 等文件。

4. **使用 `setitimer` 或 `timerfd` (可能):**  旧版本的 Android 或某些特定场景可能使用 `setitimer` 或 `timerfd`。

5. **最终调用 `timer_create` 等:** 在某些情况下，Android 的底层实现可能会使用 POSIX 计时器，从而调用到 `bionic/libc/bionic/posix_timers.cpp` 中的函数。例如，某些特定的定时任务或者更底层的定时机制可能会使用 POSIX 计时器。

**NDK 到 `posix_timers.cpp` 的路径:**

1. **NDK 代码直接调用:** 使用 NDK 开发的 C/C++ 代码可以直接包含 `<time.h>` 并调用 `timer_create`, `timer_settime` 等函数。

   ```c++
   #include <time.h>
   #include <stdio.h>

   void my_timer_callback(union sigval sv) {
       printf("Timer expired with value: %d\n", sv.sival_int);
   }

   int main() {
       timer_t timerid;
       struct sigevent sev;
       struct itimerspec its;

       sev.sigev_notify = SIGEV_THREAD;
       sev.sigev_notify_function = my_timer_callback;
       sev.sigev_value.sival_int = 42;

       if (timer_create(CLOCK_REALTIME, &sev, &timerid) == -1) {
           perror("timer_create");
           return 1;
       }

       its.it_value.tv_sec = 1;
       its.it_value.tv_nsec = 0;
       its.it_interval.tv_sec = 1;
       its.it_interval.tv_nsec = 0;

       if (timer_settime(timerid, 0, &its, NULL) == -1) {
           perror("timer_settime");
           return 1;
       }

       // ... 等待一段时间 ...

       return 0;
   }
   ```

**Frida Hook 示例:**

```python
import frida
import sys

# 连接到目标进程
process_name = "目标进程的名称或PID"
try:
    session = frida.attach(process_name)
except frida.ProcessNotFoundError:
    print(f"找不到进程: {process_name}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "timer_create"), {
    onEnter: function(args) {
        console.log("timer_create called!");
        console.log("  clock_id:", ptr(args[0]));
        console.log("  evp:", args[1]);
        if (args[1] != 0) {
            var evp = ptr(args[1]);
            console.log("    sigev_notify:", Memory.readU32(evp));
            // 可以根据 sigev_notify 的值进一步解析 sigevent 结构体
        }
        console.log("  timer_id:", args[2]);
    },
    onLeave: function(retval) {
        console.log("timer_create returned:", retval);
        if (retval == 0) {
            console.log("  timer_id value:", Memory.readPointer(this.context.r2)); // 假设 timer_id 通过寄存器返回
        }
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "timer_settime"), {
    onEnter: function(args) {
        console.log("timer_settime called!");
        console.log("  timer_id:", ptr(args[0]));
        console.log("  flags:", args[1]);
        console.log("  ts:", args[2]);
        if (args[2] != 0) {
            var ts = ptr(args[2]);
            console.log("    it_value.tv_sec:", Memory.readU64(ts));
            console.log("    it_value.tv_nsec:", Memory.readU64(ts.add(8)));
            console.log("    it_interval.tv_sec:", Memory.readU64(ts.add(16)));
            console.log("    it_interval.tv_nsec:", Memory.readU64(ts.add(24)));
        }
        console.log("  ots:", args[3]);
    },
    onLeave: function(retval) {
        console.log("timer_settime returned:", retval);
    }
});

// 可以添加更多 hook，例如 timer_delete，来观察计时器的生命周期
"""

script = session.create_script(script_code)

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    elif message['type'] == 'error':
        print(f"[-] {message}")

script.on('message', on_message)
script.load()

print("[*] Frida script loaded. Waiting for timer_create and timer_settime calls...")
sys.stdin.read()
session.detach()
```

**使用说明:**

1. 将 `目标进程的名称或PID` 替换为你要调试的 Android 进程的名称或进程 ID。
2. 运行 Frida 脚本。
3. 在目标进程中触发涉及 POSIX 计时器的操作（例如，应用程序设置了一个闹钟或使用了 `java.util.Timer`）。
4. Frida 脚本会在控制台上打印出 `timer_create` 和 `timer_settime` 函数被调用时的参数信息，帮助你理解调用流程和参数设置。

这个详细的解释涵盖了 `bionic/libc/bionic/posix_timers.cpp` 文件的功能、与 Android 的关系、实现细节、动态链接、常见错误以及如何使用 Frida 进行调试。 希望能帮助你深入理解 Android 系统中 POSIX 计时器的使用。

Prompt: 
```
这是目录为bionic/libc/bionic/posix_timers.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <malloc.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "private/bionic_lock.h"

// System calls.
extern "C" int __rt_sigprocmask(int, const sigset64_t*, sigset64_t*, size_t);
extern "C" int __rt_sigtimedwait(const sigset64_t*, siginfo_t*, const timespec*, size_t);
extern "C" int __timer_create(clockid_t, sigevent*, __kernel_timer_t*);
extern "C" int __timer_delete(__kernel_timer_t);
extern "C" int __timer_getoverrun(__kernel_timer_t);
extern "C" int __timer_gettime(__kernel_timer_t, itimerspec*);
extern "C" int __timer_settime(__kernel_timer_t, int, const itimerspec*, itimerspec*);

// Most POSIX timers are handled directly by the kernel. We translate SIGEV_THREAD timers
// into SIGEV_THREAD_ID timers so the kernel handles all the time-related stuff and we just
// need to worry about running user code on a thread.

// We can't use SIGALRM because too many other C library functions throw that around, and since
// they don't send to a specific thread, all threads are eligible to handle the signal and we can
// end up with one of our POSIX timer threads handling it (meaning that the intended recipient
// doesn't). glibc uses SIGRTMIN for its POSIX timer implementation, so in the absence of any
// reason to use anything else, we use that too.
static const int TIMER_SIGNAL = (__SIGRTMIN + 0);

struct PosixTimer {
  __kernel_timer_t kernel_timer_id;

  int sigev_notify;

  // The fields below are only needed for a SIGEV_THREAD timer.
  Lock startup_handshake_lock;
  pthread_t callback_thread;
  void (*callback)(sigval_t);
  sigval_t callback_argument;
  atomic_bool deleted;  // Set when the timer is deleted, to prevent further calling of callback.
};

static __kernel_timer_t to_kernel_timer_id(timer_t timer) {
  return reinterpret_cast<PosixTimer*>(timer)->kernel_timer_id;
}

static void* __timer_thread_start(void* arg) {
  PosixTimer* timer = reinterpret_cast<PosixTimer*>(arg);

  // Check that our parent managed to create the kernel timer and bail if not...
  timer->startup_handshake_lock.lock();
  if (timer->kernel_timer_id == -1) {
    free(timer);
    return nullptr;
  }

  // Give ourselves a specific meaningful name now we have a kernel timer.
  char name[16]; // 16 is the kernel-imposed limit.
  snprintf(name, sizeof(name), "POSIX timer %d", to_kernel_timer_id(timer));
  pthread_setname_np(timer->callback_thread, name);

  sigset64_t sigset = {};
  sigaddset64(&sigset, TIMER_SIGNAL);

  while (true) {
    // Wait for a signal...
    siginfo_t si = {};
    if (__rt_sigtimedwait(&sigset, &si, nullptr, sizeof(sigset)) == -1) continue;

    if (si.si_code == SI_TIMER) {
      // This signal was sent because a timer fired, so call the callback.

      // All events to the callback will be ignored when the timer is deleted.
      if (atomic_load(&timer->deleted) == true) {
        continue;
      }
      timer->callback(timer->callback_argument);
    } else if (si.si_code == SI_TKILL) {
      // This signal was sent because someone wants us to exit.
      free(timer);
      return nullptr;
    }
  }
}

static void __timer_thread_stop(PosixTimer* timer) {
  atomic_store(&timer->deleted, true);
  pthread_kill(timer->callback_thread, TIMER_SIGNAL);
}

// https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/timer_create.html
int timer_create(clockid_t clock_id, sigevent* evp, timer_t* timer_id) {
  PosixTimer* timer = reinterpret_cast<PosixTimer*>(malloc(sizeof(PosixTimer)));
  if (timer == nullptr) {
    return -1;
  }

  timer->kernel_timer_id = -1;
  timer->sigev_notify = (evp == nullptr) ? SIGEV_SIGNAL : evp->sigev_notify;

  // If not a SIGEV_THREAD timer, the kernel can handle it without our help.
  if (timer->sigev_notify != SIGEV_THREAD) {
    if (__timer_create(clock_id, evp, &timer->kernel_timer_id) == -1) {
      free(timer);
      return -1;
    }

    *timer_id = timer;
    return 0;
  }

  // Otherwise, this must be SIGEV_THREAD timer...
  timer->callback = evp->sigev_notify_function;
  timer->callback_argument = evp->sigev_value;
  atomic_store_explicit(&timer->deleted, false, memory_order_relaxed);

  // Check arguments that the kernel doesn't care about but we do.
  if (timer->callback == nullptr) {
    free(timer);
    errno = EINVAL;
    return -1;
  }

  // Create this timer's thread.
  pthread_attr_t thread_attributes;
  if (evp->sigev_notify_attributes == nullptr) {
    pthread_attr_init(&thread_attributes);
  } else {
    thread_attributes = *reinterpret_cast<pthread_attr_t*>(evp->sigev_notify_attributes);
  }
  pthread_attr_setdetachstate(&thread_attributes, PTHREAD_CREATE_DETACHED);

  // We start the thread with TIMER_SIGNAL blocked by blocking the signal here and letting it
  // inherit. If it tried to block the signal itself, there would be a race.
  sigset64_t sigset = {};
  sigaddset64(&sigset, TIMER_SIGNAL);
  sigset64_t old_sigset;

  // Prevent the child thread from running until the timer has been created.
  timer->startup_handshake_lock.init(false);
  timer->startup_handshake_lock.lock();

  // Use __rt_sigprocmask instead of sigprocmask64 to avoid filtering out TIMER_SIGNAL.
  __rt_sigprocmask(SIG_BLOCK, &sigset, &old_sigset, sizeof(sigset));

  int rc = pthread_create(&timer->callback_thread, &thread_attributes, __timer_thread_start, timer);

  __rt_sigprocmask(SIG_SETMASK, &old_sigset, nullptr, sizeof(old_sigset));

  if (rc != 0) {
    free(timer);
    errno = rc;
    return -1;
  }

  // Try to create the kernel timer.
  sigevent se = *evp;
  se.sigev_signo = TIMER_SIGNAL;
  se.sigev_notify = SIGEV_THREAD_ID;
  se.sigev_notify_thread_id = pthread_gettid_np(timer->callback_thread);
  rc = __timer_create(clock_id, &se, &timer->kernel_timer_id);

  // Let the child run (whether we created the kernel timer or not).
  timer->startup_handshake_lock.unlock();
  // If __timer_create(2) failed, the child will kill itself and free the
  // timer struct, so we just need to exit.
  if (rc == -1) {
    return -1;
  }

  *timer_id = timer;
  return 0;
}

// https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/timer_delete.html
int timer_delete(timer_t id) {
  int rc = __timer_delete(to_kernel_timer_id(id));
  if (rc == -1) {
    return -1;
  }

  PosixTimer* timer = reinterpret_cast<PosixTimer*>(id);
  if (timer->sigev_notify == SIGEV_THREAD) {
    // Stopping the timer's thread frees the timer data when it's safe.
    __timer_thread_stop(timer);
  } else {
    // For timers without threads, we can just free right away.
    free(timer);
  }

  return 0;
}

// https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/timer_gettime.html
int timer_gettime(timer_t id, itimerspec* ts) {
  return __timer_gettime(to_kernel_timer_id(id), ts);
}

// https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/timer_settime.html
// When using timer_settime to disarm a repeatable SIGEV_THREAD timer with a very small
// period (like below 1ms), the kernel may continue to send events to the callback thread
// for a few extra times. This behavior is fine because in POSIX standard: The effect of
// disarming or resetting a timer with pending expiration notifications is unspecified.
int timer_settime(timer_t id, int flags, const itimerspec* ts, itimerspec* ots) {
  PosixTimer* timer= reinterpret_cast<PosixTimer*>(id);
  return __timer_settime(timer->kernel_timer_id, flags, ts, ots);
}

// https://pubs.opengroup.org/onlinepubs/9799919799.2024edition/functions/timer_getoverrun.html
int timer_getoverrun(timer_t id) {
  return __timer_getoverrun(to_kernel_timer_id(id));
}

"""

```