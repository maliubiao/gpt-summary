Response:
Let's break down the thought process to answer the user's request about the `epoll.h` header file in Android's Bionic library.

**1. Understanding the Core Request:**

The user wants to understand the functionality of the provided C header file, specifically in the context of Android. The decomposed requests are:

* List the functions.
* Explain their purpose.
* Relate them to Android features with examples.
* Explain the *implementation* of each function.
* For functions involving the dynamic linker, explain the linking process with examples.
* Provide examples of logical reasoning with input/output.
* Identify common usage errors.
* Explain how Android frameworks/NDK reach this code, with Frida hook examples.

**2. Initial Analysis of the Header File:**

The header file clearly defines functions related to the `epoll` system call family in Linux. Key observations:

* **Function Declarations:** The file primarily contains function *declarations* (prototypes), not the *implementations*. The implementations reside in the Bionic C library (`libc.so`).
* **Linux System Calls:**  The documentation references Linux man pages (e.g., `epoll_create(2)`). This immediately tells me these functions are wrappers around underlying Linux kernel system calls.
* **Bionic Specifics:**  The presence of `#include <sys/cdefs.h>`, `#include <sys/types.h>`, and Android-specific macros like `__BIONIC_AVAILABILITY_GUARD` and `__INTRODUCED_IN` indicates this is part of Bionic, Android's C library.
* **Signal Handling:** The inclusion of `signal.h` and the presence of `epoll_pwait` family of functions suggest these variants handle signal masking.

**3. Addressing Each Part of the User's Request Systematically:**

* **List Functions:**  This is straightforward. Iterate through the declarations and list the function names.

* **Explain Purpose:**  Refer to the comments in the header file itself. They provide concise descriptions. Also, the linked man pages offer detailed explanations of the standard Linux `epoll` functionality. I should summarize these explanations.

* **Relate to Android Features:** This requires connecting the low-level `epoll` concepts to higher-level Android use cases. I know `epoll` is used for efficient I/O event handling. I need to think about where Android applications and the framework might need this:
    * **Network Connections:**  Servers handling multiple client connections.
    * **Input Events:**  Monitoring file descriptors for input.
    * **Android System Services:**  Many system services likely use non-blocking I/O and event loops managed by `epoll`.

* **Explain Implementation:**  This is the trickiest part given the header file doesn't contain implementations. I need to emphasize that these are *wrappers* around Linux system calls. I should briefly explain the general flow: the Bionic functions make a system call to the Linux kernel, which handles the actual `epoll` operations. I *cannot* provide the detailed C code implementation from just the header.

* **Dynamic Linker:**  Here, the analysis is that *these specific `epoll` functions don't directly involve the dynamic linker*. They are part of the core C library. However, *any* application using these functions will be linked against `libc.so`. I need to explain the general linking process for `libc.so`, providing a simplified `so` layout and describing how the dynamic linker resolves symbols. It's crucial to clarify that these *specific* `epoll` functions don't trigger unique dynamic linking mechanisms beyond the standard loading of `libc.so`.

* **Logical Reasoning (Input/Output):**  Since these are system call wrappers, the "logic" resides in the Linux kernel. For a simple example, I can demonstrate `epoll_create` returning a file descriptor. For `epoll_wait`, I can show how it waits for events and returns the number of ready file descriptors. The examples should be basic and illustrate the core function.

* **Common Usage Errors:** I need to recall common mistakes developers make when using `epoll`:
    * Incorrectly setting up the `epoll_event` structure.
    * Forgetting to add file descriptors to the `epoll` set.
    * Ignoring `errno` after function calls.
    * Buffer overflows when receiving events.

* **Android Framework/NDK and Frida Hooks:** This involves tracing how calls might reach these functions.
    * **NDK:**  Directly using the functions from C/C++ code.
    * **Framework:**  Less direct, but potentially through Java NIO (which uses `epoll` under the hood on Linux) or through system services written in C++. I should provide a plausible call chain.
    * **Frida Hooks:**  Demonstrate how to hook these functions using Frida, showing how to intercept calls and inspect arguments and return values.

**4. Structuring the Answer:**

I'll organize the answer following the user's request structure. I'll use clear headings and bullet points for readability. For each function, I'll provide its purpose, connection to Android, and explanation (emphasizing the system call wrapper nature). The dynamic linker section will be separate, and the Frida example will be its own section.

**5. Refining and Adding Detail:**

As I write, I'll refine the explanations. For example, when discussing Android features, I'll try to be more specific (e.g., mentioning `ServerSocketChannel` in the context of Java NIO). For the dynamic linker, I'll ensure I explain the symbol resolution process clearly. For Frida, I'll provide a concrete code example.

**Self-Correction/Refinement during the Process:**

* **Initial thought:**  Maybe I need to delve deep into the kernel implementation. **Correction:**  The request is focused on the header and the Bionic library. The kernel implementation is outside the scope. I should focus on the wrapper aspect.
* **Initial thought:** The dynamic linker is heavily involved. **Correction:**  While all code in Android relies on the dynamic linker, these specific functions are more about system calls. I need to explain the standard linking process of `libc.so` but avoid overstating the direct dynamic linker involvement for *these specific functions*.
* **Clarity:** Ensure the language is precise and avoids jargon where possible. Explain concepts like "file descriptor" briefly.

By following this structured thought process, I can generate a comprehensive and accurate answer that addresses all aspects of the user's request. The key is to understand the context (Android, Bionic), the nature of the code (header file, system call wrappers), and then address each sub-question systematically.
这个目录 `bionic/libc/include/sys/epoll.h` 是 Android Bionic C 库中关于 `epoll` 系统调用的头文件。`epoll` 是 Linux 内核提供的一种 I/O 事件通知机制，用于高效地监控多个文件描述符上的事件，例如读取、写入或错误。

**功能列举：**

该头文件定义了以下与 `epoll` 相关的函数：

1. **`epoll_create(int __size)`:**  创建一个 `epoll` 实例。
2. **`epoll_create1(int __flags)`:**  创建一个 `epoll` 实例，并允许指定一些标志。
3. **`epoll_ctl(int __epoll_fd, int __op, int __fd, struct epoll_event* __event)`:**  向一个 `epoll` 实例添加、修改或删除文件描述符的监听。
4. **`epoll_wait(int __epoll_fd, struct epoll_event* __events, int __event_count, int __timeout_ms)`:**  等待 `epoll` 实例中监听的文件描述符上的事件发生。
5. **`epoll_pwait(int __epoll_fd, struct epoll_event* __events, int __event_count, int __timeout_ms, const sigset_t* __mask)`:** 类似于 `epoll_wait`，但在等待时可以原子地应用一个信号掩码。
6. **`epoll_pwait64(int __epoll_fd, struct epoll_event* __events, int __event_count, int __timeout_ms, const sigset64_t* __mask)`:**  `epoll_pwait` 的变体，使用 64 位的信号掩码，即使在 32 位系统上也是如此 (API level 28+)。
7. **`epoll_pwait2(int __epoll_fd, struct epoll_event* __events, int __event_count, const struct timespec* __timeout, const sigset_t* __mask)`:** 类似于 `epoll_pwait`，但超时时间使用 `struct timespec`，提供纳秒级精度 (API level 35+)。
8. **`epoll_pwait2_64(int __epoll_fd, struct epoll_event* __events, int __event_count, const struct timespec* __timeout, const sigset64_t* __mask)`:**  `epoll_pwait2` 的变体，使用 64 位的信号掩码 (API level 35+)。

**与 Android 功能的关系及举例说明：**

`epoll` 是 Android 系统中处理并发和异步 I/O 的重要机制。它比传统的 `select` 和 `poll` 更高效，尤其是在需要监控大量文件描述符时。

* **网络编程:** Android 应用程序和系统服务经常需要处理网络连接。`epoll` 可以用来高效地监听多个 socket 上的事件，例如新连接的建立、数据的接收或发送。
    * **例子:**  一个网络服务器应用程序可以使用 `epoll` 来同时监听多个客户端连接的 socket，当有新的数据到达时，`epoll_wait` 会返回，服务器可以处理对应的客户端请求。
* **Binder IPC:** Android 的进程间通信机制 Binder 底层也使用了类似 `epoll` 的机制（可能不是直接使用 `epoll` 系统调用，但原理类似）。系统服务需要监听来自不同进程的请求，`epoll` 这样的机制可以高效地完成这个任务。
    * **例子:** `system_server` 是 Android 的核心系统服务进程，它需要处理来自各种应用程序和系统组件的 Binder 请求。它会使用某种事件循环机制来监听这些请求，而 `epoll` 是实现这种机制的有效方式。
* **输入事件处理:**  Android 系统需要监听各种输入事件，例如触摸、按键等。虽然不一定直接使用 `epoll` 监听输入设备的原始文件描述符，但 `epoll` 的思想可以应用于事件循环和异步处理。
* **文件系统事件监控:**  某些 Android 功能可能需要监控文件系统的变化。`inotify` 系统调用可以与 `epoll` 结合使用，以高效地监控文件和目录的变化。

**libc 函数的实现：**

这些在 `epoll.h` 中声明的函数实际上是对 Linux 内核提供的 `epoll` 系统调用的封装。Bionic libc 提供了这些函数的实现，其主要作用是将用户空间的函数调用转换为内核空间的系统调用。

* **`epoll_create` 和 `epoll_create1`:** 这两个函数会通过 `syscall` 指令触发 `SYS_epoll_create` 或 `SYS_epoll_create1` 系统调用。内核会创建一个新的 `epoll` 实例并返回一个文件描述符，该文件描述符用于后续的 `epoll_ctl` 和 `epoll_wait` 操作。内核中会维护一个数据结构来管理这个 `epoll` 实例以及添加到其中的文件描述符。
* **`epoll_ctl`:** 这个函数通过 `syscall` 指令触发 `SYS_epoll_ctl` 系统调用。它接受 `epoll` 文件描述符、操作类型（添加、修改、删除）、要操作的文件描述符以及一个 `epoll_event` 结构体作为参数。内核会根据操作类型修改 `epoll` 实例中维护的数据结构，例如添加新的文件描述符及其感兴趣的事件，或者修改已存在文件描述符的事件。
* **`epoll_wait`，`epoll_pwait`，`epoll_pwait64`，`epoll_pwait2`，`epoll_pwait2_64`:** 这些函数通过 `syscall` 指令触发相应的 `SYS_epoll_wait`，`SYS_epoll_pwait` 等系统调用。当调用这些函数时，进程会进入睡眠状态，直到 `epoll` 实例中监听的某个文件描述符上有事件发生（例如可读、可写）或超时。内核会将发生事件的文件描述符的相关信息填充到用户空间提供的 `epoll_event` 数组中，并返回就绪的文件描述符数量。`pwait` 系列的函数还允许在等待期间原子地修改信号掩码。

**涉及 dynamic linker 的功能：**

这些 `epoll` 函数本身并不直接涉及 dynamic linker 的核心功能。它们是 Bionic libc 的一部分，当应用程序需要使用这些函数时，dynamic linker 会将应用程序链接到 `libc.so` 库。

**so 布局样本 (libc.so 的简化布局):**

```
libc.so:
    .text:  # 代码段
        epoll_create:
            # epoll_create 的实现代码 (实际上是系统调用封装)
            ...
        epoll_create1:
            # epoll_create1 的实现代码
            ...
        epoll_ctl:
            # epoll_ctl 的实现代码
            ...
        epoll_wait:
            # epoll_wait 的实现代码
            ...
        # ... 其他 libc 函数 ...

    .data:  # 数据段
        # 全局变量等

    .dynamic: # 动态链接信息
        SONAME: libc.so
        NEEDED: libm.so  # 可能依赖其他库
        SYMTAB:  # 符号表，包含导出的符号 (如 epoll_create 等)
        STRTAB:  # 字符串表
        ...
```

**链接的处理过程：**

1. **编译时:** 编译器在编译应用程序的代码时，如果遇到了 `epoll_create` 等函数调用，它会生成一个对这些函数的未解析符号引用。
2. **链接时:** 静态链接器（在构建系统中使用）会记录这些未解析的符号引用，并标记该程序需要链接到 `libc.so`。
3. **运行时:** 当 Android 系统启动应用程序时，dynamic linker (`/system/bin/linker` 或 `/system/bin/linker64`) 负责加载程序和其依赖的共享库。
4. **加载 libc.so:** dynamic linker 会根据程序头部的信息加载 `libc.so` 到内存中。
5. **符号解析:** dynamic linker 会遍历应用程序中未解析的符号引用，并在 `libc.so` 的符号表 (`SYMTAB`) 中查找对应的符号定义（例如 `epoll_create` 的地址）。
6. **重定位:** 找到符号定义后，dynamic linker 会修改应用程序代码中的符号引用，将其指向 `libc.so` 中 `epoll_create` 函数的实际内存地址。

**逻辑推理（假设输入与输出）：**

假设我们有以下代码片段：

```c
#include <sys/epoll.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

int main() {
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        exit(EXIT_FAILURE);
    }
    printf("epoll_fd: %d\n", epoll_fd);
    close(epoll_fd);
    return 0;
}
```

**假设输入:** 无特定输入。

**输出:**

如果 `epoll_create1` 成功，输出类似于：

```
epoll_fd: 3
```

（`3` 是一个示例的文件描述符，实际值可能不同）

如果 `epoll_create1` 失败（例如，资源不足），输出类似于：

```
epoll_create1: Too many open files
```

（具体的错误消息可能因系统状态而异）

**对于 `epoll_wait` 的逻辑推理：**

假设我们已经创建了一个 `epoll` 实例，并向其中添加了一个监听读取事件的 socket 文件描述符 `sockfd`。

**假设输入:**  `sockfd` 上有数据到达。

**输出:**  `epoll_wait` 会返回大于 0 的值（表示就绪的文件描述符数量），并且传递给 `epoll_wait` 的 `epoll_event` 数组中会包含关于 `sockfd` 的事件信息，例如 `events` 成员会包含 `EPOLLIN` 标志，表示可以读取数据。

**涉及用户或者编程常见的使用错误：**

1. **忘记检查返回值和 `errno`:**  所有 `epoll` 函数都可能失败，应该检查返回值是否为 -1，并检查 `errno` 来确定错误原因。
    * **例子:**  不检查 `epoll_create` 的返回值，直接使用返回的 `epoll_fd`，如果 `epoll_create` 失败，会导致程序崩溃或出现未定义行为。
2. **错误地设置 `epoll_event` 结构体:**  在调用 `epoll_ctl` 添加或修改文件描述符时，需要正确设置 `epoll_event` 结构体的 `events` 成员，指定要监听的事件类型（例如 `EPOLLIN`，`EPOLLOUT`，`EPOLLERR`，`EPOLLHUP`）。
    * **例子:**  只设置 `EPOLLIN`，但忘记设置 `EPOLLHUP`，可能导致程序无法正确处理 socket 连接断开的情况。
3. **使用未初始化的 `epoll_event` 结构体:**  在调用 `epoll_wait` 之前，需要确保传递给它的 `epoll_event` 数组有足够的空间来存储返回的事件。
    * **例子:**  声明了一个 `struct epoll_event events[10];` 但传递给 `epoll_wait` 的 `event_count` 大于 10，可能导致内存越界。
4. **忘记从 `epoll` 实例中删除不再需要监听的文件描述符:**  如果不及时删除，`epoll_wait` 可能会持续返回已关闭或不再关心的文件描述符的事件。
5. **在多线程环境中使用 `epoll` 但没有正确的同步机制:**  如果多个线程同时操作同一个 `epoll` 实例，可能会导致数据竞争和未定义的行为。需要使用互斥锁或其他同步机制来保护共享的 `epoll` 实例。
6. **`epoll_ctl` 的 `EPOLL_CTL_MOD` 操作使用了错误的事件掩码:** 修改已监听的文件描述符时，需要提供正确的新的事件掩码，否则可能导致监听的事件类型不正确。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `epoll` 的路径 (示例，可能因具体场景而异):**

1. **Java NIO:** Android Framework 中的网络操作通常使用 Java NIO (New I/O) 包。例如，`ServerSocketChannel` 和 `SocketChannel` 等类在底层会使用 `epoll` (或 `poll`，取决于 Android 版本和具体实现) 来处理非阻塞 I/O。
    * 例如，一个 Java 网络服务器可能会使用 `ServerSocketChannel.open()` 创建一个监听 socket，并将其注册到一个 `Selector` 上。
2. **`Selector`:** `Selector` 是 Java NIO 中用于多路复用的核心组件。在 Linux 系统上，`Selector` 的实现通常会使用 `epoll`。
    * 当调用 `Selector.select()` 方法时，底层会调用 Native 代码。
3. **Native 代码 (libjavacrypto.so, libandroid_runtime.so 等):** Java NIO 的底层实现会调用 Android Runtime (ART) 或 Dalvik 虚拟机提供的 Native 方法。这些 Native 方法可能会调用 Bionic libc 提供的 `epoll` 函数。
    * 例如，`libjavacrypto.so` 中处理网络连接的部分可能最终会调用到 `epoll_create`，`epoll_ctl` 和 `epoll_wait`。
4. **Bionic libc (`libc.so`):**  Bionic libc 提供了 `epoll_create`，`epoll_ctl`，`epoll_wait` 等函数的实现，它们是对 Linux 内核 `epoll` 系统调用的封装。
5. **Linux Kernel:** 最终，Bionic libc 中的函数会通过 `syscall` 指令触发 Linux 内核的 `epoll` 系统调用，由内核来完成实际的事件监控和通知。

**NDK 到 `epoll` 的路径:**

1. **NDK C/C++ 代码:** 使用 NDK 开发的应用程序可以直接调用 Bionic libc 提供的 `epoll` 函数。
    * 例如，一个使用 C++ 编写的网络库可能会直接包含 `<sys/epoll.h>` 并调用 `epoll_create` 等函数。
2. **Bionic libc (`libc.so`):**  NDK 代码链接到 Bionic libc，调用 `epoll` 函数时，会执行 `libc.so` 中的实现。
3. **Linux Kernel:**  与 Framework 的路径相同，最终调用到 Linux 内核的 `epoll` 系统调用。

**Frida Hook 示例：**

以下是一个使用 Frida Hook `epoll_wait` 函数的示例：

```javascript
// attach 到目标进程
function attach(processName) {
  const process = Process.getByName(processName);
  return process;
}

function hook_epoll_wait() {
  const epoll_wait_ptr = Module.findExportByName("libc.so", "epoll_wait");
  if (epoll_wait_ptr) {
    Interceptor.attach(epoll_wait_ptr, {
      onEnter: function (args) {
        const epfd = args[0].toInt32();
        const events = args[1];
        const nfds = args[2].toInt32();
        const timeout = args[3].toInt32();
        console.log(`[epoll_wait] epfd: ${epfd}, events: ${events}, nfds: ${nfds}, timeout: ${timeout}`);
      },
      onLeave: function (retval) {
        const num_ready = retval.toInt32();
        console.log(`[epoll_wait] 返回值: ${num_ready}`);
        if (num_ready > 0) {
          const epoll_event_ptr = this.context.r1; // 在 ARM64 上，events 参数在 r1 寄存器
          if (epoll_event_ptr) {
            for (let i = 0; i < num_ready; i++) {
              const event_ptr = epoll_event_ptr.add(i * Process.pointerSize * 2); // sizeof(struct epoll_event)
              const events_field = event_ptr.readU32();
              const data_fd = event_ptr.add(Process.pointerSize).readPointer().toInt32();
              console.log(`  [事件 ${i+1}] events: ${events_field.toString(16)}, data.fd: ${data_fd}`);
            }
          }
        }
      },
    });
    console.log("Hooked epoll_wait");
  } else {
    console.error("Failed to find epoll_wait in libc.so");
  }
}

function main() {
  const processName = "目标进程名称"; // 将 "目标进程名称" 替换为你要调试的进程名
  const process = attach(processName);
  if (process) {
    console.log(`Attached to process: ${process.name} (PID: ${process.pid})`);
    hook_epoll_wait();
  } else {
    console.error(`Process "${processName}" not found.`);
  }
}

setImmediate(main);
```

**使用说明:**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `epoll_hook.js`）。
2. 将 `目标进程名称` 替换为你想要调试的 Android 应用程序或系统服务的进程名称。
3. 使用 Frida 连接到目标进程并执行该脚本：
   ```bash
   frida -U -f <package_name> -l epoll_hook.js --no-pause  # Hook 启动时启动的应用
   frida -U -n <process_name> -l epoll_hook.js            # Hook 已经运行的应用
   ```
   或者，如果使用 `frida-server`：
   ```bash
   frida -H <设备 IP>:27042 -f <package_name> -l epoll_hook.js --no-pause
   frida -H <设备 IP>:27042 -n <process_name> -l epoll_hook.js
   ```

**Frida Hook 代码解释:**

* `Module.findExportByName("libc.so", "epoll_wait")`: 查找 `libc.so` 中 `epoll_wait` 函数的地址。
* `Interceptor.attach()`:  拦截 `epoll_wait` 函数的调用。
* `onEnter`: 在 `epoll_wait` 函数被调用之前执行，打印传入的参数（`epfd`，`events` 指针，`nfds`，`timeout`）。
* `onLeave`: 在 `epoll_wait` 函数返回之后执行，打印返回值（就绪的文件描述符数量）。
* 如果返回值大于 0，表示有事件发生，则遍历 `events` 数组，读取每个事件的信息（`events` 标志和 `data.fd`）。

通过这个 Frida 脚本，你可以观察到目标进程中 `epoll_wait` 函数的调用情况，包括监听的 `epoll` 实例、等待的事件、超时时间以及返回的就绪事件信息，从而帮助你调试与 `epoll` 相关的代码。你可以根据需要修改脚本来 Hook 其他 `epoll` 函数或提取更多有用的信息。

Prompt: 
```
这是目录为bionic/libc/include/sys/epoll.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#pragma once

/**
 * @file sys/epoll.h
 * @brief I/O event file descriptors.
 */

#include <sys/cdefs.h>
#include <sys/types.h>
#include <signal.h> /* For sigset_t. */

#include <linux/eventpoll.h>

__BEGIN_DECLS

/**
 * [epoll_create(2)](https://man7.org/linux/man-pages/man2/epoll_create.2.html)
 * creates a new [epoll](https://man7.org/linux/man-pages/man7/epoll.7.html)
 * file descriptor.
 *
 * Returns a new file descriptor on success and returns -1 and sets `errno` on
 * failure.
 */
int epoll_create(int __size);

/**
 * [epoll_create1(2)](https://man7.org/linux/man-pages/man2/epoll_create1.2.html)
 * creates a new [epoll](https://man7.org/linux/man-pages/man7/epoll.7.html)
 * file descriptor with the given flags.
 *
 * Returns a new file descriptor on success and returns -1 and sets `errno` on
 * failure.
 */
int epoll_create1(int __flags);

/**
 * [epoll_ctl(2)](https://man7.org/linux/man-pages/man2/epoll_ctl.2.html)
 * adds/modifies/removes file descriptors from the given epoll file descriptor.
 *
 * Returns 0 on success and returns -1 and sets `errno` on failure.
 */
int epoll_ctl(int __epoll_fd, int __op, int __fd, struct epoll_event* __BIONIC_COMPLICATED_NULLNESS __event);

/**
 * [epoll_wait(2)](https://man7.org/linux/man-pages/man2/epoll_wait.2.html)
 * waits for an event on the given epoll file descriptor.
 *
 * Returns the number of ready file descriptors on success, 0 on timeout,
 * or -1 and sets `errno` on failure.
 */
int epoll_wait(int __epoll_fd, struct epoll_event* _Nonnull __events, int __event_count, int __timeout_ms);

/**
 * Like epoll_wait() but atomically applying the given signal mask.
 */
int epoll_pwait(int __epoll_fd, struct epoll_event* _Nonnull __events, int __event_count, int __timeout_ms, const sigset_t* _Nullable __mask);

/**
 * Like epoll_pwait() but using a 64-bit signal mask even on 32-bit systems.
 *
 * Available since API level 28.
 */

#if __BIONIC_AVAILABILITY_GUARD(28)
int epoll_pwait64(int __epoll_fd, struct epoll_event* _Nonnull __events, int __event_count, int __timeout_ms, const sigset64_t* _Nullable __mask) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */


/**
 * Like epoll_pwait() but with a `struct timespec` timeout, for nanosecond resolution.
 *
 * Available since API level 35.
 */

#if __BIONIC_AVAILABILITY_GUARD(35)
int epoll_pwait2(int __epoll_fd, struct epoll_event* _Nonnull __events, int __event_count, const struct timespec* _Nullable __timeout, const sigset_t* _Nullable __mask) __INTRODUCED_IN(35);

/**
 * Like epoll_pwait2() but using a 64-bit signal mask even on 32-bit systems.
 *
 * Available since API level 35.
 */
int epoll_pwait2_64(int __epoll_fd, struct epoll_event* _Nonnull __events, int __event_count, const struct timespec* _Nullable __timeout, const sigset64_t* _Nullable __mask) __INTRODUCED_IN(35);
#endif /* __BIONIC_AVAILABILITY_GUARD(35) */


__END_DECLS

"""

```