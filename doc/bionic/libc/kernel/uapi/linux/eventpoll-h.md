Response:
Let's break down the thought process for answering the request about the `eventpoll.h` header file.

**1. Understanding the Core Request:**

The user wants to understand the purpose and functionality of the provided header file (`eventpoll.h`). They also want to know its relevance to Android, details about any libc functions, dynamic linker interactions, potential errors, and how it's reached from Android framework/NDK. Finally, they want Frida hook examples.

**2. Initial Analysis of the Header File:**

* **File Path:** `bionic/libc/kernel/uapi/linux/eventpoll.h`. This tells us it's part of Bionic (Android's libc), within the kernel API (uapi) for Linux. This immediately signals it's related to system calls and low-level I/O handling.
* **`#ifndef _UAPI_LINUX_EVENTPOLL_H`:**  This is a standard include guard, preventing multiple inclusions.
* **`#include <bits/epoll_event.h>` and `#include <linux/fcntl.h>` and `#include <linux/types.h>`:** These include other header files. `epoll_event.h` will likely define the `epoll_event` structure, `fcntl.h` relates to file control (like `O_CLOEXEC`), and `types.h` defines fundamental data types.
* **`#define EPOLL_CLOEXEC O_CLOEXEC`:**  This defines a constant. `O_CLOEXEC` is for setting the close-on-exec flag for file descriptors.
* **`#define EPOLL_CTL_ADD 1`, `#define EPOLL_CTL_DEL 2`, `#define EPOLL_CTL_MOD 3`:** These define constants for controlling the epoll instance (add, delete, modify file descriptors).
* **`#define EPOLLIN ...`, `#define EPOLLPRI ...`, etc.:**  A long list of defines starting with `EPOLL`. These clearly represent different event types that can be monitored (input, priority, output, error, etc.). The `__poll_t` type suggests they are related to polling mechanisms.
* **Architecture-Specific Packing:** The `#ifdef __x86_64__` block with `__attribute__((packed))` is for architecture-specific structure packing, which can be important for interoperability with the kernel.
* **`struct epoll_params`:**  This structure seems to control some performance-related parameters for epoll, like busy polling.
* **`#define EPOLL_IOC_TYPE 0x8A` and `#define EPIOCSPARAMS ...`, `#define EPIOCGPARAMS ...`:** These defines strongly suggest ioctl commands for setting and getting epoll parameters. `_IOW` and `_IOR` are standard macros for defining ioctl commands.

**3. Connecting to Android Functionality:**

Based on the keywords and the file path, it's clear this header defines the interface for the `epoll` system call family. `epoll` is a fundamental mechanism for efficient I/O multiplexing, allowing a single thread to monitor multiple file descriptors for events. This is crucial for network programming, UI event handling, and other asynchronous operations in Android.

**4. Libc Function Explanation (Implicit):**

This header file *doesn't* define libc functions directly. Instead, it defines constants and structures that are used by the *system calls* related to epoll (like `epoll_create`, `epoll_ctl`, `epoll_wait`). The libc wrappers for these system calls would use the definitions in this header. Therefore, the explanation needs to focus on how the *system calls* work conceptually.

**5. Dynamic Linker Aspects (Indirect):**

This header file itself doesn't directly involve the dynamic linker. However, the *libc* implementation of the epoll system call wrappers *will* be part of a shared object (`.so`) and linked dynamically. The explanation needs to touch upon this indirect relationship.

**6. Logical Reasoning and Examples:**

* **Assumptions:**  Assume a scenario where an Android app needs to listen for incoming network connections and handle user input concurrently.
* **Input:**  File descriptors for the network socket and an input device.
* **Output:** Notifications when data is available on the socket or user input occurs.

**7. Common User Errors:**

Common mistakes when using `epoll` include:
    * Forgetting to add file descriptors to the epoll set.
    * Not handling all possible event types.
    * Incorrectly using edge-triggered mode.
    * File descriptor leaks.

**8. Android Framework/NDK Path:**

Trace how an event might propagate from the Android framework down to the `epoll` level:

* **Java Framework:**  UI events, network operations (using `Socket`, `ServerSocket`).
* **Native Code (NDK):** Direct use of `epoll` system calls via libc wrappers.
* **Binder:** Inter-process communication uses file descriptors and can potentially involve `epoll`.
* **Kernel:** The actual `epoll` implementation.

**9. Frida Hook Examples:**

Focus on hooking the libc wrappers for the `epoll` system calls (`epoll_create`, `epoll_ctl`, `epoll_wait`). Show examples of logging arguments and return values.

**10. Structuring the Answer:**

Organize the information logically with clear headings for each part of the request (functionality, Android relationship, libc function explanation, dynamic linker, errors, Android path, Frida hooks). Use clear and concise language.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** "This file defines epoll functions."  **Correction:**  No, it defines *constants and structures* used by the epoll *system calls*. The *libc* provides the functions that use these definitions.
* **Initial thought:** "Explain the implementation of `EPOLLIN`." **Correction:** `EPOLLIN` is a *constant*. The implementation is in the *kernel's epoll system call handler*. Explain what the constant *represents*.
* **Consider the audience:** The request doesn't specify the technical level, so aim for a balance of detail and clarity. Avoid overly technical kernel details unless directly relevant.

By following this structured thought process, anticipating the user's needs, and refining the understanding of the header file's role, a comprehensive and accurate answer can be generated.
好的，我们来详细分析一下 `bionic/libc/kernel/uapi/linux/eventpoll.h` 这个头文件。

**功能列举:**

这个头文件定义了与 Linux `epoll` 机制相关的用户空间 API。 `epoll` 是一种高效的 I/O 事件通知机制，允许程序监视多个文件描述符（如套接字、管道、文件等）上发生的事件，而无需像 `select` 或 `poll` 那样轮询。

主要功能包括：

1. **定义 `epoll_event` 结构体:**  尽管这个头文件本身没有直接定义，但它包含了 `<bits/epoll_event.h>`，这个头文件定义了用于描述被监视文件描述符及其感兴趣事件的结构体 `epoll_event`。

2. **定义 `epoll_ctl` 操作类型:**  定义了用于操作 `epoll` 实例的控制命令：
   - `EPOLL_CTL_ADD`:  将新的文件描述符添加到 `epoll` 实例的监视列表中。
   - `EPOLL_CTL_DEL`:  从 `epoll` 实例的监视列表中移除文件描述符。
   - `EPOLL_CTL_MOD`:  修改 `epoll` 实例中已存在的文件描述符的事件监听设置。

3. **定义事件类型标志:**  定义了可以被 `epoll` 监视的各种事件类型：
   - `EPOLLIN`:  有数据可读。
   - `EPOLLPRI`:  有紧急数据可读。
   - `EPOLLOUT`:  可以写入数据。
   - `EPOLLERR`:  发生错误。
   - `EPOLLHUP`:  挂断 (例如，连接断开)。
   - `EPOLLRDNORM`, `EPOLLRDBAND`, `EPOLLWRNORM`, `EPOLLWRBAND`, `EPOLLMSG`:  与不同的数据读取/写入条件相关，在实际使用中 `EPOLLIN` 和 `EPOLLOUT` 更常见。
   - `EPOLLRDHUP`:  连接的另一端已关闭写连接（仅适用于流式套接字）。
   - `EPOLL_URING_WAKE`:  与 `io_uring` 异步 I/O 框架相关，用于唤醒等待 `io_uring` 事件的 `epoll` 实例。
   - `EPOLLEXCLUSIVE`:  独占唤醒模式，当多个进程或线程监视同一个文件描述符时，只有一个会被唤醒。
   - `EPOLLWAKEUP`:  防止系统进入低功耗模式，直到有事件发生。
   - `EPOLLONESHOT`:  事件发生后，该文件描述符将不再被监视，需要重新添加。
   - `EPOLLET`:  边缘触发模式，只有在文件描述符状态发生变化时才会通知，而不是像水平触发那样，只要条件满足就一直通知。

4. **定义 `EPOLL_CLOEXEC`:**  与 `fcntl` 系统调用中的 `O_CLOEXEC` 标志相同，用于在 `execve` 系统调用后自动关闭该文件描述符。

5. **定义 `epoll_params` 结构体和相关 ioctl 命令:**  定义了 `epoll_params` 结构体，用于设置和获取 `epoll` 实例的特定参数，如忙轮询相关的配置。  `EPIOCSPARAMS` 和 `EPIOCGPARAMS` 是用于 `ioctl` 系统调用的命令，分别用于设置和获取这些参数。

**与 Android 功能的关系及举例说明:**

`epoll` 是 Android 底层 I/O 操作的核心机制之一，许多 Android 的核心功能都依赖于它：

1. **网络编程:**  Android 的网络库，无论是 Java 层的 `java.net` 包还是 Native 层的 socket API，底层都使用 `epoll` 来高效地管理多个网络连接。例如，一个服务器应用需要同时监听多个客户端连接，`epoll` 可以让服务器在一个线程中处理多个连接的事件，提高并发性能。

   **例子:**  一个网络服务器应用使用 `ServerSocket` 监听连接，并将接受的 `Socket` 的文件描述符添加到 `epoll` 实例中，监听 `EPOLLIN` 事件。当有新的数据到达时，`epoll_wait` 会返回，服务器可以处理该连接的数据。

2. **Binder IPC:**  Android 的进程间通信 (IPC) 机制 Binder 也使用 `epoll` 来监听来自其他进程的请求。Binder 驱动程序会创建文件描述符，并通过 `epoll` 通知进程是否有新的 Binder 事务需要处理。

   **例子:**  当一个应用调用另一个应用的 Service 时，底层的 Binder 驱动程序会通过 `epoll` 通知 Service 进程有新的请求到达。

3. **事件循环 (Looper):**  Android 的消息队列和事件循环机制 (Looper/Handler) 在 Native 层通常使用 `epoll` 来监听各种事件，包括文件描述符上的 I/O 事件、管道事件、定时器事件等。

   **例子:**  `Looper` 可能会监听一个管道的文件描述符，当有新的消息需要处理时，其他线程会向该管道写入数据，`epoll` 监听到 `EPOLLIN` 事件后，`Looper` 就会处理消息队列中的消息。

**每一个 libc 函数的功能是如何实现的:**

这个头文件本身 **不定义 libc 函数**，而是定义了与内核 `epoll` 系统调用交互所需的常量和结构体。  真正实现 `epoll` 功能的是内核提供的系统调用，以及 Bionic libc 中对这些系统调用的封装函数。

以下是涉及的 libc 函数及其简要实现方式：

1. **`epoll_create` 或 `epoll_create1`:**
   - **功能:** 创建一个 `epoll` 实例，返回一个与该实例关联的文件描述符。
   - **实现:**  这是一个系统调用，会陷入内核。内核会在内部创建一个 `epoll` 数据结构，用于管理被监视的文件描述符和事件。`epoll_create1` 允许指定额外的标志，如 `EPOLL_CLOEXEC`。

2. **`epoll_ctl`:**
   - **功能:**  控制 `epoll` 实例，添加、删除或修改要监视的文件描述符。
   - **实现:**  也是一个系统调用。内核会根据传入的操作类型 (`EPOLL_CTL_ADD`, `EPOLL_CTL_DEL`, `EPOLL_CTL_MOD`)，以及 `epoll_event` 结构体中的信息，更新 `epoll` 实例内部的数据结构。

3. **`epoll_wait`:**
   - **功能:**  等待 `epoll` 实例中监视的文件描述符上的事件发生。
   - **实现:**  这是一个阻塞的系统调用。内核会检查 `epoll` 实例中是否有事件发生。如果有，内核会将就绪的文件描述符及其发生的事件信息复制到用户空间提供的 `epoll_event` 数组中，并返回就绪的文件描述符的数量。如果没有事件发生，调用线程会被挂起，直到有事件发生或超时。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`eventpoll.h` 本身不直接涉及 dynamic linker 的功能。但是，使用 `epoll` 的代码（无论是 Android Framework、NDK 应用还是 Bionic libc 自身）会链接到包含 `epoll_create`, `epoll_ctl`, `epoll_wait` 等函数实现的共享库，即 Bionic libc (`/system/lib[64]/libc.so` 或 `/system/lib/libc.so`)。

**so 布局样本 (以 64 位为例):**

```
/system/lib64/libc.so:
    ... (其他代码段和数据段) ...

    .text (代码段):
        ...
        [地址 A] <epoll_create的实现代码>
        [地址 B] <epoll_ctl的实现代码>
        [地址 C] <epoll_wait的实现代码>
        ...

    .data (数据段):
        ...
        (可能包含与 epoll 相关的全局变量，但通常较少)
        ...

    .dynsym (动态符号表):
        epoll_create (类型: 函数, 地址: A)
        epoll_ctl    (类型: 函数, 地址: B)
        epoll_wait   (类型: 函数, 地址: C)
        ... (其他动态符号) ...

    .dynstr (动态字符串表):
        epoll_create
        epoll_ctl
        epoll_wait
        ... (其他字符串) ...

    .rel.dyn 或 .rela.dyn (动态重定位表):
        ... (包含需要动态链接器处理的重定位信息) ...
```

**链接的处理过程:**

1. **编译时:** 当编译链接一个使用 `epoll` 的程序时，链接器会查找所需的符号（如 `epoll_create` 等）。由于这些符号在 Bionic libc 中定义，链接器会在生成的可执行文件或共享库的动态符号表和动态重定位表中记录这些依赖关系。

2. **加载时:** 当 Android 系统加载可执行文件或共享库时，动态链接器 (`/system/bin/linker[64]`) 会负责解析这些动态链接依赖。

3. **符号查找:** 动态链接器会查找需要的共享库（通常根据 `DT_NEEDED` 条目）。对于 `epoll` 相关的函数，它会查找 `libc.so`。

4. **重定位:** 动态链接器会根据动态重定位表中的信息，将程序中对 `epoll_create`、`epoll_ctl`、`epoll_wait` 等函数的调用地址，替换为 `libc.so` 中这些函数的实际加载地址（例如，上面布局样本中的地址 A、B、C）。

**假设输入与输出 (逻辑推理):**

假设有以下 C 代码片段：

```c
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    int epoll_fd = epoll_create1(0);
    if (epoll_fd == -1) {
        perror("epoll_create1");
        return 1;
    }

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd == -1) {
        perror("socket");
        return 1;
    }

    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8080);

    if (bind(listen_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        return 1;
    }

    if (listen(listen_fd, 10) == -1) {
        perror("listen");
        return 1;
    }

    struct epoll_event ev;
    ev.events = EPOLLIN;
    ev.data.fd = listen_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev) == -1) {
        perror("epoll_ctl");
        return 1;
    }

    printf("Listening on port 8080...\n");

    struct epoll_event events[10];
    int nfds = epoll_wait(epoll_fd, events, 10, -1); // 阻塞等待事件
    if (nfds == -1) {
        perror("epoll_wait");
        return 1;
    }

    if (nfds > 0) {
        printf("Event on fd: %d\n", events[0].data.fd);
        // 处理连接
    }

    close(listen_fd);
    close(epoll_fd);
    return 0;
}
```

**假设输入:**  有客户端尝试连接到运行此程序的 8080 端口。

**输出:**  `epoll_wait` 会返回大于 0 的值，表示有事件发生。`events[0].data.fd` 的值将是 `listen_fd`（监听套接字的文件描述符），并且会打印 "Event on fd: [listen_fd 的值]"。

**用户或编程常见的使用错误，请举例说明:**

1. **忘记将文件描述符添加到 `epoll` 实例:**  创建了 `epoll` 实例，但是没有使用 `epoll_ctl(EPOLL_CTL_ADD, ...)` 将需要监视的文件描述符加入。这会导致 `epoll_wait` 永远不会返回预期的事件。

   ```c
   int epoll_fd = epoll_create1(0);
   // ... 创建了套接字 listen_fd ...

   // 错误：忘记添加 listen_fd 到 epoll_fd
   // struct epoll_event ev;
   // ev.events = EPOLLIN;
   // ev.data.fd = listen_fd;
   // epoll_ctl(epoll_fd, EPOLL_CTL_ADD, listen_fd, &ev);

   struct epoll_event events[10];
   int nfds = epoll_wait(epoll_fd, events, 10, -1); // 永远阻塞或超时
   ```

2. **没有正确处理边缘触发模式 (EPOLLET):**  在边缘触发模式下，只有当文件描述符的状态发生变化时，`epoll_wait` 才会通知。如果没有完全读取缓冲区中的数据，后续的数据到达可能不会再次触发事件，导致数据丢失或处理不完整。

   ```c
   struct epoll_event ev;
   ev.events = EPOLLIN | EPOLLET; // 使用边缘触发
   ev.data.fd = client_fd;
   epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev);

   // ... 在 epoll_wait 返回后 ...
   char buffer[100];
   ssize_t count = recv(client_fd, buffer, sizeof(buffer), 0);
   // 错误：如果收到的数据大于 100 字节，剩余的数据可能不会再次触发 EPOLLIN 事件
   ```

3. **文件描述符泄漏:**  在 `epoll_wait` 返回后，处理事件时没有正确关闭不再需要的文件描述符。

   ```c
   // ... 在 epoll_wait 返回后处理新连接 ...
   int conn_fd = accept(listen_fd, ...);
   if (conn_fd != -1) {
       // ... 将 conn_fd 添加到 epoll 监听 ...
       // 错误：在某些情况下没有关闭 conn_fd
   }
   ```

4. **错误地修改已监视的文件描述符的事件:**  使用 `EPOLL_CTL_MOD` 修改事件时，`epoll_event` 结构体中的 `data` 字段也应该保持一致，否则可能导致意外行为。

**说明 Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework (Java 层):**
   - 应用程序可能使用 `java.net.Socket` 或 `java.nio` 包进行网络操作。
   - `java.net.Socket` 底层会通过 JNI 调用到 Native 层的 socket 相关函数。
   - `java.nio` 包中的 `Selector` 类是基于 `epoll` 或 `poll` 等机制实现的 I/O 多路复用。

2. **Native 代码 (NDK):**
   - NDK 应用可以直接调用 Bionic libc 提供的 `epoll` 相关函数 (`epoll_create`, `epoll_ctl`, `epoll_wait`)。
   - 例如，一个用 C++ 编写的网络库或游戏引擎可能会直接使用 `epoll` 来管理网络连接或文件 I/O。

3. **Bionic libc:**
   - 当 Native 代码调用 `epoll_create` 等函数时，实际上是调用了 Bionic libc 中对这些系统调用的封装函数。
   - 这些封装函数会将参数传递给内核的 `epoll` 系统调用。

4. **Linux 内核:**
   - 内核接收到 `epoll` 系统调用后，会执行相应的操作，例如创建 `epoll` 实例、添加/删除/修改监视的文件描述符、等待事件发生等。

**Frida Hook 示例:**

我们可以使用 Frida Hook Bionic libc 中的 `epoll` 相关函数来观察其调用过程。

```python
import frida
import sys

package_name = "your.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "epoll_create"), {
    onEnter: function(args) {
        console.log("[epoll_create] flags: " + args[0]);
    },
    onLeave: function(retval) {
        console.log("[epoll_create] 返回值 (fd): " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "epoll_ctl"), {
    onEnter: function(args) {
        const epfd = args[0];
        const op = args[1].toInt();
        const fd = args[2];
        const eventPtr = args[3];
        let event_str = "";
        if (eventPtr != 0) {
            const events = Memory.readU32(eventPtr);
            event_str = "events: " + events.toString(16);
        }
        let op_str = "";
        if (op === 1) op_str = "EPOLL_CTL_ADD";
        else if (op === 2) op_str = "EPOLL_CTL_DEL";
        else if (op === 3) op_str = "EPOLL_CTL_MOD";
        else op_str = "Unknown Op: " + op;

        console.log("[epoll_ctl] epfd: " + epfd + ", op: " + op_str + ", fd: " + fd + ", " + event_str);
    },
    onLeave: function(retval) {
        console.log("[epoll_ctl] 返回值: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "epoll_wait"), {
    onEnter: function(args) {
        const epfd = args[0];
        const eventsPtr = args[1];
        const maxevents = args[2];
        const timeout = args[3];
        console.log("[epoll_wait] epfd: " + epfd + ", maxevents: " + maxevents + ", timeout: " + timeout);
    },
    onLeave: function(retval) {
        console.log("[epoll_wait] 返回就绪的文件描述符数量: " + retval);
        if (retval > 0) {
            const epollEventSize = 12; // sizeof(struct epoll_event)
            for (let i = 0; i < retval.toInt(); i++) {
                const currentEventPtr = this.context.rdi.add(i * epollEventSize); // x86_64, adjust for other architectures
                const events = Memory.readU32(currentEventPtr);
                const dataFd = Memory.readInt(currentEventPtr.add(8)); // 假设 data 是一个 fd
                console.log("[epoll_wait] 事件 " + i + ": events=" + events.toString(16) + ", data.fd=" + dataFd);
            }
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

print("Frida is hooking epoll functions. Interact with the app to see the logs.")
sys.stdin.read()
session.detach()
```

**使用方法:**

1. 将 `your.package.name` 替换为你要调试的 Android 应用的包名。
2. 确保你的 Android 设备或模拟器已连接，并且 Frida 服务正在运行。
3. 运行这个 Python 脚本。
4. 与目标应用进行交互，例如发起网络请求或触发其他 I/O 操作。
5. Frida 会拦截对 `epoll_create`, `epoll_ctl`, `epoll_wait` 的调用，并打印出相关的参数和返回值，帮助你理解 Android Framework 或 NDK 如何使用 `epoll`.

这个详细的分析涵盖了 `bionic/libc/kernel/uapi/linux/eventpoll.h` 的功能、与 Android 的关系、涉及的 libc 函数和 dynamic linker、常见错误以及 Frida Hook 示例，希望能帮助你深入理解 `epoll` 机制在 Android 中的应用。

### 提示词
```
这是目录为bionic/libc/kernel/uapi/linux/eventpoll.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI_LINUX_EVENTPOLL_H
#define _UAPI_LINUX_EVENTPOLL_H
#include <bits/epoll_event.h>
#include <linux/fcntl.h>
#include <linux/types.h>
#define EPOLL_CLOEXEC O_CLOEXEC
#define EPOLL_CTL_ADD 1
#define EPOLL_CTL_DEL 2
#define EPOLL_CTL_MOD 3
#define EPOLLIN ( __poll_t) 0x00000001
#define EPOLLPRI ( __poll_t) 0x00000002
#define EPOLLOUT ( __poll_t) 0x00000004
#define EPOLLERR ( __poll_t) 0x00000008
#define EPOLLHUP ( __poll_t) 0x00000010
#define EPOLLNVAL ( __poll_t) 0x00000020
#define EPOLLRDNORM ( __poll_t) 0x00000040
#define EPOLLRDBAND ( __poll_t) 0x00000080
#define EPOLLWRNORM ( __poll_t) 0x00000100
#define EPOLLWRBAND ( __poll_t) 0x00000200
#define EPOLLMSG ( __poll_t) 0x00000400
#define EPOLLRDHUP ( __poll_t) 0x00002000
#define EPOLL_URING_WAKE (( __poll_t) (1U << 27))
#define EPOLLEXCLUSIVE (( __poll_t) (1U << 28))
#define EPOLLWAKEUP (( __poll_t) (1U << 29))
#define EPOLLONESHOT (( __poll_t) (1U << 30))
#define EPOLLET (( __poll_t) (1U << 31))
#ifdef __x86_64__
#define EPOLL_PACKED __attribute__((packed))
#else
#define EPOLL_PACKED
#endif
struct epoll_params {
  __u32 busy_poll_usecs;
  __u16 busy_poll_budget;
  __u8 prefer_busy_poll;
  __u8 __pad;
};
#define EPOLL_IOC_TYPE 0x8A
#define EPIOCSPARAMS _IOW(EPOLL_IOC_TYPE, 0x01, struct epoll_params)
#define EPIOCGPARAMS _IOR(EPOLL_IOC_TYPE, 0x02, struct epoll_params)
#endif
```