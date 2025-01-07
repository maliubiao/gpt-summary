Response:
Let's break down the thought process for analyzing this `timerfd.h` header file.

**1. Understanding the Context:**

The first and most crucial step is recognizing the file's location: `bionic/libc/include/sys/timerfd.h`. This immediately tells us a few key things:

* **Bionic:** This is Android's core C library. Any functionality here is a fundamental part of the Android operating system.
* **libc/include:** This signifies header files, defining interfaces for system calls and library functions.
* **sys/timerfd.h:** This points to a specific subsystem related to timers and file descriptors. The `timerfd` name itself hints at a combination of timer mechanisms and file descriptor interactions.
* **.handroid:** This suffix suggests Android-specific additions or modifications to a standard Linux concept (timerfd exists in Linux).

**2. Initial Scan and Identification of Key Components:**

Next, we quickly scan the contents of the header file. We can immediately identify:

* **Copyright Notice:**  Indicates it's an Android Open Source Project component.
* **Includes:** `<sys/cdefs.h>`, `<fcntl.h>`, `<linux/timerfd.h>`, `<time.h>`, `<sys/types.h>`. These inclusions are vital clues about dependencies and underlying mechanisms. `<linux/timerfd.h>` is a strong indicator that this is a wrapper around a Linux kernel feature.
* **Macros:** `TFD_CLOEXEC` and `TFD_NONBLOCK`. These flags are for `timerfd_create` and likely relate to standard file descriptor behavior (close-on-exec and non-blocking I/O).
* **Function Declarations:** `timerfd_create`, `timerfd_settime`, `timerfd_gettime`. These are the core functions this header defines. The documentation snippets referring to `man7.org` are explicit pointers to the standard Linux man pages for these system calls.
* **More Macros:** `TFD_TIMER_ABSTIME` and `TFD_TIMER_CANCEL_ON_SET`. These are specific to `timerfd_settime` and relate to how the timer behaves.
* **`__BEGIN_DECLS` and `__END_DECLS`:** These are common in system headers to handle C++ compatibility (prevent name mangling).

**3. Functionality Deduction (Based on Names, Documentation, and Includes):**

With the identified components, we can start deducing the functionality:

* **`timerfd_create`:** The name strongly suggests creating a file descriptor associated with a timer. The documentation confirms this, pointing to the `timerfd_create(2)` man page. The `clockid_t` argument suggests the timer can be based on different clock sources (realtime, monotonic, etc.). The `flags` argument reinforces the idea of controlling file descriptor behavior.
* **`timerfd_settime`:**  The name suggests setting the parameters of an existing timer file descriptor. The documentation confirms this, pointing to `timerfd_settime(2)`. The `itimerspec` structure (from `<time.h>`) strongly implies setting initial expiration and interval times. The `flags` here are different, indicating timer-specific behavior (absolute time, cancellation).
* **`timerfd_gettime`:** This seems to be for querying the current state of a timer file descriptor. The documentation and the `itimerspec` argument support this.

**4. Connecting to Android and Examples:**

Now, we link the functionality to the Android context:

* **Core System Functionality:** Because it's in `bionic`, this is fundamental to how Android applications can handle time-based events.
* **Examples:**  We brainstorm common Android scenarios where timers are essential:
    * **Alarm/Reminder Apps:**  Scheduling future notifications.
    * **Game Loops:**  Controlling frame rates.
    * **Network Timeouts:**  Setting limits for waiting for network responses.
    * **Background Tasks:**  Performing periodic updates or synchronizations.

**5. Deep Dive into Libc Function Implementation (Conceptual):**

While we don't have the actual C code here, we can reason about the implementation:

* **System Call Wrapper:** The `timerfd_*` functions in `bionic` are almost certainly wrappers around the corresponding Linux system calls. They handle the transition from user space to kernel space.
* **Error Handling:**  The documentation explicitly mentions returning -1 and setting `errno` on failure. This is standard practice for system calls in Unix-like systems.
* **Kernel Interaction:** The actual timer management logic resides in the Linux kernel. The `timerfd` mechanism provides a way for user-space processes to interact with these kernel timers through file descriptors.

**6. Dynamic Linker Aspects (Conceptual):**

Since this is a header file, it doesn't directly involve dynamic linking. However, the *use* of these functions does.

* **SO Layout:**  Imagine an Android application using `timerfd_create`. The necessary `libc.so` library containing the compiled implementation of these functions will be loaded into the application's process space. The header file helps the *compiler* understand the interface, but the dynamic linker is responsible for *locating and loading* the actual code.
* **Linking Process:**  The application binary will have entries in its dynamic linking section indicating its dependency on `libc.so`. The dynamic linker (`/system/bin/linker64` or `/system/bin/linker`) will resolve these dependencies at runtime.

**7. Logical Reasoning (Simple Case):**

The provided code is primarily declarations. A simple logical inference would be: If `timerfd_create` succeeds, it returns a non-negative file descriptor. If it fails, it returns -1.

**8. Common Usage Errors:**

We consider common mistakes developers might make:

* **Incorrect Flags:** Using the wrong flags with `timerfd_create` or `timerfd_settime`.
* **Invalid File Descriptor:**  Passing an invalid file descriptor to `timerfd_settime` or `timerfd_gettime`.
* **Incorrect `itimerspec`:**  Setting up the `itimerspec` structure incorrectly (e.g., negative times).
* **Forgetting to Read:**  Not reading from the timer file descriptor after it expires.

**9. Android Framework and NDK Path & Frida Hooking:**

This requires understanding the Android software stack:

* **NDK:** Native code (C/C++) directly uses these functions.
* **Android Framework:** Java code in the framework can indirectly use timers (e.g., through `AlarmManager`). The framework implementations likely use underlying native mechanisms, possibly including `timerfd`.
* **Path Tracing:** We hypothesize the call flow from Java down to native code.
* **Frida:**  We devise Frida scripts to intercept the `timerfd_create` call, printing arguments and return values, to observe its behavior.

**Self-Correction/Refinement during the Thought Process:**

* **Initial thought:** "Is this just a wrapper around standard Linux `timerfd`?"  **Correction:** The `.handroid` suffix suggests potential Android-specific aspects. Need to be mindful of that.
* **Initial thought:** Focus too much on the header file. **Correction:**  Remember to consider the *implementation* in `libc.so` and the role of the dynamic linker.
* **Missed connection:** Initially overlook the importance of the `itimerspec` structure. **Correction:** Realize this is key to setting timer values.

By following these steps, combining code analysis with knowledge of operating system concepts and the Android architecture, we can arrive at a comprehensive understanding of the `timerfd.h` header file and its role within the Android ecosystem.
这个文件 `bionic/libc/include/sys/timerfd.h` 是 Android Bionic C 库中关于 **定时器文件描述符 (timer file descriptors)** 的头文件。它定义了用于创建、设置和获取基于文件描述符的定时器的接口。这种机制允许程序像处理普通文件一样处理定时器事件，通过 `read()` 系统调用来等待定时器到期。

**功能列举:**

这个头文件主要定义了以下三个函数和相关的宏：

1. **`timerfd_create(clockid_t __clock, int __flags)`**: 创建一个定时器文件描述符。
2. **`timerfd_settime(int __fd, int __flags, const struct itimerspec* _Nonnull __new_value, struct itimerspec* _Nullable __old_value)`**: 启动或停止一个定时器，并设置其超时时间和间隔时间。
3. **`timerfd_gettime(int __fd, struct itimerspec* _Nonnull __current_value)`**: 查询当前定时器的设置。

此外，还定义了一些相关的宏：

*   **`TFD_CLOEXEC`**:  `timerfd_create()` 的标志，用于创建执行时关闭 (close-on-exec) 的文件描述符。
*   **`TFD_NONBLOCK`**: `timerfd_create()` 的标志，用于创建非阻塞的文件描述符。
*   **`TFD_TIMER_ABSTIME`**: `timerfd_settime()` 的标志，指示使用绝对时间而不是相对时间。
*   **`TFD_TIMER_CANCEL_ON_SET`**: `timerfd_settime()` 的标志，指示当实时时钟改变时取消绝对定时器。

**与 Android 功能的关系及举例:**

`timerfd` 机制是 Linux 内核提供的功能，Android Bionic 作为 Android 的 C 库，提供了对这个功能的封装。它在 Android 系统中被广泛使用，例如：

*   **`AlarmManager` 的底层实现**: Android 的 `AlarmManager` 允许应用程序在未来的某个时刻执行操作。虽然 `AlarmManager` 的 API 是 Java 层的，但在底层实现中，系统可能会使用 `timerfd` 或类似的机制来管理这些定时事件。例如，当应用设置一个延迟闹钟时，系统可以使用 `timerfd_create` 创建一个定时器，并使用 `timerfd_settime` 设置闹钟触发的时间。当定时器到期时，可以通过读取该定时器的文件描述符来触发相应的操作。
*   **`Choreographer` 的同步机制**: Android 的 `Choreographer` 负责协调动画、输入和绘制。它使用 VSYNC 信号进行同步。在某些情况下，为了确保某些任务在特定的时间点执行，`Choreographer` 的底层实现可能也会利用 `timerfd` 来创建高精度的定时器。
*   **网络超时**: 应用程序进行网络操作时，常常需要设置超时时间。可以使用 `timerfd` 创建一个定时器，并在进行网络请求的同时等待定时器到期。如果定时器先到期，则可以判断网络请求超时。
*   **后台任务调度**: 一些后台任务可能需要在固定的时间间隔执行。可以使用 `timerfd` 创建一个周期性定时器来实现。

**libc 函数功能实现详解:**

这些函数实际上是对 Linux 内核提供的 `timerfd` 系统调用的封装。Bionic 的实现会调用相应的 `syscall` 指令来进入内核空间，执行内核提供的定时器管理功能。

1. **`timerfd_create(clockid_t __clock, int __flags)`**:
    *   **功能**:  创建一个与特定时钟关联的定时器，并返回一个文件描述符。
    *   **实现**:
        *   将 `__clock` (指定时钟类型，如 `CLOCK_REALTIME` 或 `CLOCK_MONOTONIC`) 和 `__flags` (如 `TFD_CLOEXEC` 或 `TFD_NONBLOCK`) 作为参数传递给内核的 `timerfd_create()` 系统调用。
        *   内核会在内部创建一个新的定时器对象，并将其与一个新分配的文件描述符关联起来。
        *   如果成功，系统调用返回新文件描述符的数值；如果失败，返回 -1 并设置 `errno`。
    *   **假设输入与输出**:
        *   **输入**: `__clock = CLOCK_MONOTONIC`, `__flags = 0`
        *   **输出**: 如果成功，返回一个非负整数，例如 `3`；如果失败，返回 `-1`，并且 `errno` 可能被设置为 `EINVAL` (如果 `__clock` 不合法) 或 `EMFILE` (如果进程打开的文件描述符过多)。

2. **`timerfd_settime(int __fd, int __flags, const struct itimerspec* __new_value, struct itimerspec* __old_value)`**:
    *   **功能**: 启动或停止由 `__fd` 指定的定时器，并设置其超时时间和间隔时间。
    *   **实现**:
        *   将文件描述符 `__fd`、标志 `__flags` (如 `TFD_TIMER_ABSTIME`)、新的超时和间隔时间结构 `__new_value` 以及可选的用于存储旧设置的结构 `__old_value` 传递给内核的 `timerfd_settime()` 系统调用。
        *   内核会根据 `__new_value` 中的 `it_value` 设置定时器的初始超时时间，根据 `it_interval` 设置定时器的间隔时间（如果设置为非零值，则定时器会周期性触发）。
        *   如果 `__old_value` 不是 `NULL`，内核会将定时器之前的设置存储到该结构中。
        *   如果成功，系统调用返回 0；如果失败，返回 -1 并设置 `errno`。
    *   **假设输入与输出**:
        *   **输入**: `__fd = 3`, `__flags = 0`, `__new_value` 设置为 1 秒后超时，无间隔，`__old_value = NULL`
        *   **输出**: 如果成功，返回 `0`；如果失败，返回 `-1`，并且 `errno` 可能被设置为 `EBADF` (如果 `__fd` 无效) 或 `EINVAL` (如果 `__flags` 或 `__new_value` 不合法)。

3. **`timerfd_gettime(int __fd, struct itimerspec* __current_value)`**:
    *   **功能**: 获取由 `__fd` 指定的定时器的当前设置。
    *   **实现**:
        *   将文件描述符 `__fd` 和用于存储当前设置的结构 `__current_value` 传递给内核的 `timerfd_gettime()` 系统调用。
        *   内核会将定时器的当前状态（包括剩余时间和间隔时间）填充到 `__current_value` 结构中。
        *   如果成功，系统调用返回 0；如果失败，返回 -1 并设置 `errno`。
    *   **假设输入与输出**:
        *   **输入**: `__fd = 3`, `__current_value` 是一个已分配的 `struct itimerspec` 指针。
        *   **输出**: 如果成功，返回 `0`，并且 `__current_value` 指向的结构体会被填充为定时器的当前设置；如果失败，返回 `-1`，并且 `errno` 可能被设置为 `EBADF` (如果 `__fd` 无效)。

**涉及 dynamic linker 的功能:**

这个头文件本身不涉及 dynamic linker 的功能。它只是定义了接口。`timerfd_create`、`timerfd_settime` 和 `timerfd_gettime` 的具体实现位于 `libc.so` 中。当应用程序调用这些函数时，dynamic linker 负责将应用程序与 `libc.so` 链接起来，找到这些函数的实现地址并执行。

**so 布局样本和链接处理过程:**

假设一个简单的 Android 应用使用了 `timerfd_create`：

**so 布局样本 (简化):**

```
应用程序可执行文件 (e.g., /system/bin/my_app):
  - .dynamic 段 (包含动态链接信息)
    - NEEDED libc.so  (依赖于 libc.so)
  - .text 段 (应用程序代码)
    - 调用 timerfd_create 的指令

libc.so (e.g., /system/lib64/libc.so):
  - .dynsym 段 (动态符号表)
    - timerfd_create (函数符号及其地址)
    - timerfd_settime
    - timerfd_gettime
  - .text 段 (libc 的代码)
    - timerfd_create 的实现代码
    - timerfd_settime 的实现代码
    - timerfd_gettime 的实现代码
```

**链接处理过程:**

1. **加载时**: 当 Android 启动应用程序时，`linker64` (或 `linker`) 负责加载应用程序及其依赖的共享库。
2. **解析依赖**: `linker64` 读取应用程序可执行文件的 `.dynamic` 段，找到其依赖的共享库，例如 `libc.so`。
3. **加载共享库**: `linker64` 将 `libc.so` 加载到进程的地址空间。
4. **符号解析**: `linker64` 遍历应用程序中的未定义符号（例如 `timerfd_create`），并在已加载的共享库的动态符号表 (`.dynsym` 段) 中查找对应的符号。
5. **重定位**: 找到符号后，`linker64` 会更新应用程序中调用 `timerfd_create` 的指令，将其指向 `libc.so` 中 `timerfd_create` 函数的实际地址。这个过程称为重定位。

**用户或编程常见的使用错误:**

1. **忘记读取文件描述符**: `timerfd` 创建的定时器到期时，需要在文件描述符上执行 `read()` 操作来清空定时器并获取到期次数。如果忘记读取，定时器可能不会再次触发（对于非周期性定时器），或者累积的到期次数会导致后续读取返回一个较大的值。
    ```c
    int fd = timerfd_create(CLOCK_REALTIME, 0);
    // ... 设置定时器 ...

    // 错误示例：忘记读取
    // ... 等待一段时间 ...

    // 正确示例：读取文件描述符
    uint64_t expirations;
    ssize_t s = read(fd, &expirations, sizeof(expirations));
    if (s != sizeof(expirations)) {
        perror("read");
        // 处理错误
    }
    ```

2. **错误的标志使用**:  错误地使用 `TFD_TIMER_ABSTIME` 可能导致定时器在不期望的时间触发。例如，如果当前时间晚于设置的绝对时间，定时器会立即触发。

3. **未处理 `read()` 的返回值**:  `read()` 调用可能会返回错误，需要检查返回值并处理错误情况。

4. **文件描述符泄漏**: 如果 `timerfd_create` 成功创建了文件描述符，但后续忘记使用 `close()` 关闭，会导致文件描述符泄漏。

5. **在多线程环境中的竞争条件**: 如果多个线程同时操作同一个定时器文件描述符，可能会出现竞争条件，需要使用适当的同步机制（如互斥锁）来保护。

**Android framework or ndk 如何一步步的到达这里:**

**Android Framework (Java) -> Native (NDK) 路径示例 (以 `AlarmManager` 为例):**

1. **Java 代码**:  应用程序使用 `AlarmManager` 设置闹钟。
    ```java
    AlarmManager alarmMgr = (AlarmManager) context.getSystemService(Context.ALARM_SERVICE);
    Intent intent = new Intent(context, MyReceiver.class);
    PendingIntent pendingIntent = PendingIntent.getBroadcast(context, 0, intent, PendingIntent.FLAG_IMMUTABLE);
    alarmMgr.set(AlarmManager.RTC_WAKEUP, System.currentTimeMillis() + 10000, pendingIntent); // 设置 10 秒后触发
    ```

2. **Framework 层 (Java)**: `AlarmManager` 的 `set()` 方法会调用到 `AlarmManagerService` (system_server 进程中的一个系统服务)。

3. **System Server (Native)**: `AlarmManagerService` 内部会与底层的 `AlarmManager` Native 代码进行交互，这部分通常是 C++ 实现，并且可能会使用 `timerfd` 或其他内核定时器机制。

4. **Bionic (C 库)**:  在 Native 代码中，可能会直接调用 `timerfd_create` 和 `timerfd_settime` 系统调用包装函数。

5. **Linux Kernel**: 最终，这些调用会进入 Linux 内核，内核负责管理实际的定时器。

**NDK 直接使用示例:**

1. **NDK 代码 (C/C++)**:  直接在 Native 代码中使用 `timerfd` API。
    ```c++
    #include <sys/timerfd.h>
    #include <unistd.h>
    #include <stdint.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <time.h>
    #include <sys/epoll.h>

    int main() {
        int timerfd = timerfd_create(CLOCK_REALTIME, 0);
        if (timerfd == -1) {
            perror("timerfd_create");
            return 1;
        }

        struct itimerspec its;
        its.it_value.tv_sec = 1;  // 1 秒后超时
        its.it_value.tv_nsec = 0;
        its.it_interval.tv_sec = 0;
        its.it_interval.tv_nsec = 0;

        if (timerfd_settime(timerfd, 0, &its, NULL) == -1) {
            perror("timerfd_settime");
            close(timerfd);
            return 1;
        }

        uint64_t expirations;
        ssize_t s = read(timerfd, &expirations, sizeof(expirations));
        if (s == sizeof(expirations)) {
            printf("Timer expired %llu times\n", (unsigned long long)expirations);
        } else {
            perror("read");
        }

        close(timerfd);
        return 0;
    }
    ```

**Frida Hook 示例调试步骤:**

可以使用 Frida hook `timerfd_create` 函数来观察其调用和参数：

```python
import frida
import sys

package_name = "your.package.name"  # 替换为你的应用程序包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['data']))
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Process with package name '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "timerfd_create"), {
    onEnter: function(args) {
        var clockid = args[0].toInt32();
        var flags = args[1].toInt32();
        send({ tag: "timerfd_create", data: "clockid: " + clockid + ", flags: " + flags });
    },
    onLeave: function(retval) {
        send({ tag: "timerfd_create", data: "returned fd: " + retval });
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "timerfd_settime"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var flags = args[1].toInt32();
        var new_value = ptr(args[2]);
        var old_value = ptr(args[3]);

        var itv_sec = new_value.readU64();
        var itv_nsec = new_value.add(8).readU64();
        var val_sec = new_value.add(16).readU64();
        var val_nsec = new_value.add(24).readU64();

        send({ tag: "timerfd_settime", data: "fd: " + fd + ", flags: " + flags +
               ", new_value: { it_interval: " + itv_sec + "." + itv_nsec +
               ", it_value: " + val_sec + "." + val_nsec + " }" });
    },
    onLeave: function(retval) {
        send({ tag: "timerfd_settime", data: "returned: " + retval });
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. 确保你的 Android 设备已 root，并且安装了 Frida 服务端。
2. 安装 Frida Python 库 (`pip install frida`).
3. 将 `your.package.name` 替换为你要调试的应用程序的包名。
4. 运行 Python 脚本。
5. 在你的 Android 设备上运行目标应用程序，并触发可能使用 `timerfd` 的操作（例如，设置闹钟）。
6. Frida 脚本会拦截对 `timerfd_create` 和 `timerfd_settime` 的调用，并打印出参数信息。你可以观察到应用程序在何时以及如何创建和设置定时器。

这个例子展示了如何使用 Frida hook Bionic 库中的 `timerfd` 相关函数，从而了解 Android 应用程序或 framework 如何利用这些底层机制。你可以根据需要扩展这个脚本，hook `timerfd_gettime` 或其他相关函数，以进行更深入的调试和分析。

Prompt: 
```
这是目录为bionic/libc/include/sys/timerfd.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2013 The Android Open Source Project
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

/**
 * @file sys/timerfd.h
 * @brief Timer file descriptors.
 */

#include <sys/cdefs.h>

#include <fcntl.h>
#include <linux/timerfd.h>
#include <time.h>
#include <sys/types.h>

__BEGIN_DECLS

/*! \macro TFD_CLOEXEC
 * The timerfd_create() flag for a close-on-exec file descriptor.
 */
/*! \macro TFD_NONBLOCK
 * The timerfd_create() flag for a non-blocking file descriptor.
 */

/**
 * [timerfd_create(2)](https://man7.org/linux/man-pages/man2/timerfd_create.2.html) creates a
 * timer file descriptor.
 *
 * Returns the new file descriptor on success, and returns -1 and sets `errno` on failure.
 */
int timerfd_create(clockid_t __clock, int __flags);

/** The timerfd_settime() flag to use absolute rather than relative times. */
#define TFD_TIMER_ABSTIME (1 << 0)
/** The timerfd_settime() flag to cancel an absolute timer if the realtime clock changes. */
#define TFD_TIMER_CANCEL_ON_SET (1 << 1)

/**
 * [timerfd_settime(2)](https://man7.org/linux/man-pages/man2/timerfd_settime.2.html) starts or
 * stops a timer.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int timerfd_settime(int __fd, int __flags, const struct itimerspec* _Nonnull __new_value, struct itimerspec* _Nullable __old_value);

/**
 * [timerfd_gettime(2)](https://man7.org/linux/man-pages/man2/timerfd_gettime.2.html) queries the
 * current timer settings.
 *
 * Returns 0 on success, and returns -1 and sets `errno` on failure.
 */
int timerfd_gettime(int __fd, struct itimerspec* _Nonnull __current_value);

__END_DECLS

"""

```