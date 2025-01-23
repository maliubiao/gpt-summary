Response:
Let's break down the thought process for generating the response. The request is quite detailed, asking for several different analyses of the `poll.cpp` file. Here's a possible breakdown:

1. **Understanding the Core Functionality:** The first step is to understand what the code *does*. The filename `poll.cpp` and the included headers (`sys/poll.h`, `sys/select.h`) immediately suggest this file implements the `poll`, `ppoll`, `select`, and `pselect` system call wrappers for Android's C library (bionic). This core understanding is crucial for the rest of the analysis.

2. **Identifying the Public Functions:** The code defines several functions: `poll`, `ppoll`, `ppoll64`, `select`, `pselect`, and `pselect64`. These are the entry points for userspace programs.

3. **Analyzing Each Function Individually:** For each public function, I need to determine its purpose and how it achieves it. This involves looking at the code within each function:

    * **`poll`:**  It takes a timeout in milliseconds and converts it to a `timespec` structure before calling `__ppoll`. This shows it's a simpler wrapper around the more powerful `__ppoll`.
    * **`ppoll` (and `ppoll64`):** These functions handle signals (`sigset_t`). The code distinguishes between LP64 (64-bit) and ILP32 (32-bit) architectures. On LP64, `sigset_t` and `sigset64_t` are the same, so a strong alias is used. On ILP32, a `SigSetConverter` is used to convert between the two types. The core logic involves copying the `timespec` and `sigset_t` to mutable versions and calling the underlying `__ppoll` system call. Crucially, it filters reserved signals.
    * **`select`:** Similar to `poll`, it takes a `timeval` and converts it to `timespec` before calling `__pselect6`. It also handles the reverse conversion after the system call returns.
    * **`pselect` (and `pselect64`):** Mirrors the `ppoll` logic for handling signals and architecture-specific differences. It also needs to package the `sigset64_t` information into a separate structure (`pselect6_extra_data_t`) as the underlying system call has a limited number of arguments.

4. **Identifying Interactions with Android and the Kernel:**  The functions directly interact with the Linux kernel through system calls (`__ppoll`, `__pselect6`). This is a fundamental aspect of a C library. The handling of `sigset_t` and `sigset64_t`, and the filtering of reserved signals are Android-specific customizations.

5. **Explaining Function Implementations:** For each libc function, I need to describe *how* it works. This involves outlining the steps involved, such as converting time formats, handling signal sets, and calling the underlying system calls.

6. **Dynamic Linker Considerations:** The presence of `extern "C"` indicates these functions are meant to be linked against. The different `ppoll` and `ppoll64` implementations, and the use of `__strong_alias`, hint at the dynamic linker's role in resolving these symbols at runtime. I need to provide a simple example of shared library structure and how linking works.

7. **Logic Inference and Examples:** This involves creating simple scenarios to illustrate the behavior of the functions. For `poll`, a basic example of waiting for input on a file descriptor is appropriate.

8. **Common Usage Errors:**  Thinking about how developers typically misuse these functions is important. Incorrect timeout values, using uninitialized `fd_set` structures, and not checking return values are common errors.

9. **Tracing the Execution Path (Android Framework/NDK):** This requires understanding how higher-level Android components ultimately rely on these low-level C library functions. I need to illustrate a path from a Java or native Android API down to `poll.cpp`. A networking example is a good choice.

10. **Frida Hooking:** Demonstrating how to use Frida to intercept these calls provides a practical debugging technique. The example should show how to hook a function, log its arguments, and potentially modify its behavior.

11. **Structuring the Response:** Finally, I need to organize the information logically, using clear headings and bullet points to make it easy to read and understand. The structure of the prompt provides a good guide for this.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe just explain what `poll` and `select` do generally.
* **Correction:** The prompt specifically asks for details about the *implementation* in `poll.cpp`, including the underlying system calls and Android-specific aspects.
* **Initial thought:**  Focus heavily on the signal handling.
* **Correction:** While important, the prompt also asks about time conversions, the difference between `poll` and `ppoll`, and the interaction with the dynamic linker. Balance is needed.
* **Initial thought:** Provide a very complex dynamic linker example.
* **Correction:** A simple example illustrating the basic concepts of symbol resolution is sufficient. Overcomplicating it might obscure the main point.
* **Initial thought:** Only provide basic Frida hooking.
* **Correction:** Explain *why* Frida is useful in this context and provide a concrete example with argument logging.

By following this structured approach and performing self-correction, I can generate a comprehensive and accurate response that addresses all aspects of the prompt. The key is to break down the problem into smaller, manageable parts and then synthesize the information in a clear and organized way.
好的，我们来详细分析一下 `bionic/libc/bionic/poll.cpp` 这个文件。

**文件功能总览**

`poll.cpp` 文件是 Android Bionic libc 库的一部分，它提供了与 I/O 多路复用相关的函数，主要包括 `poll`、`ppoll`、`select` 和 `pselect` 及其变体。这些函数允许程序同时监控多个文件描述符（例如，socket、文件、管道）的状态，等待其中任何一个变得可读、可写或发生错误。

**功能详细列举**

1. **`poll(pollfd* fds, nfds_t fd_count, int ms)`:**
   - 这是 `poll` 系统调用的用户空间封装。
   - 它接收一个 `pollfd` 结构体数组，每个结构体描述了一个需要监控的文件描述符及其感兴趣的事件（例如，可读、可写）。
   - `fd_count` 指定了数组中 `pollfd` 结构体的数量。
   - `ms` 是一个以毫秒为单位的超时时间。如果为正数，函数最多等待 `ms` 毫秒；如果为 0，则立即返回；如果为 -1，则无限期等待。
   - **功能:** 监控指定的文件描述符集合，直到其中一个或多个文件描述符满足指定的条件，或者超时。

2. **`ppoll(pollfd* fds, nfds_t fd_count, const timespec* ts, const sigset_t* ss)` (ILP32架构):**
   - 这是 `poll` 的一个变体，允许在等待期间阻塞特定的信号。
   - `ts` 是一个指向 `timespec` 结构的指针，用于指定超时时间，精度更高（纳秒级）。可以为 `NULL` 表示无限期等待。
   - `ss` 是一个指向信号掩码 `sigset_t` 的指针，指定了在 `ppoll` 等待期间要阻塞的信号。
   - **功能:**  与 `poll` 类似，但增加了对信号阻塞的控制。

3. **`ppoll64(pollfd* fds, nfds_t fd_count, const timespec* ts, const sigset64_t* ss)`:**
   - 这是 `ppoll` 的 64 位版本，使用 `sigset64_t` 来表示信号掩码。
   - 在 LP64 架构（64 位）上，`sigset_t` 和 `sigset64_t` 是相同的。
   - **功能:** 与 `ppoll` 相同，提供信号阻塞功能。

4. **`select(int fd_count, fd_set* read_fds, fd_set* write_fds, fd_set* error_fds, timeval* tv)`:**
   - 这是 `select` 系统调用的用户空间封装。
   - 它使用三个位图 `fd_set` 来指定需要监控的文件描述符，分别用于监控可读、可写和错误事件。
   - `fd_count` 是要检查的文件描述符的最大值加 1。
   - `tv` 是一个指向 `timeval` 结构的指针，用于指定超时时间，精度为秒和微秒。可以为 `NULL` 表示无限期等待。
   - **功能:** 监控指定的文件描述符集合，直到其中一个或多个文件描述符变得可读、可写或发生错误，或者超时。

5. **`pselect(int fd_count, fd_set* read_fds, fd_set* write_fds, fd_set* error_fds, const timespec* ts, const sigset_t* ss)` (ILP32架构):**
   - 这是 `select` 的一个变体，允许在等待期间阻塞特定的信号。
   - `ts` 是一个指向 `timespec` 结构的指针，用于指定超时时间，精度更高（纳秒级）。可以为 `NULL` 表示无限期等待。
   - `ss` 是一个指向信号掩码 `sigset_t` 的指针，指定了在 `pselect` 等待期间要阻塞的信号。
   - **功能:** 与 `select` 类似，但增加了对信号阻塞的控制。

6. **`pselect64(int fd_count, fd_set* read_fds, fd_set* write_fds, fd_set* error_fds, const timespec* ts, const sigset64_t* ss)`:**
   - 这是 `pselect` 的 64 位版本，使用 `sigset64_t` 来表示信号掩码。
   - **功能:** 与 `pselect` 相同，提供信号阻塞功能。

**与 Android 功能的关系及举例说明**

这些函数是构建高性能、非阻塞 I/O 的基石，在 Android 系统中被广泛使用：

* **网络编程:** Android 应用和服务经常需要同时处理多个网络连接。例如，一个 HTTP 服务器需要监听新的连接请求，并同时处理已建立的连接上的数据收发。`poll` 或 `select` 可以有效地管理这些并发连接。
    * **例子:**  一个网络服务器使用 `poll` 监听一个 socket，等待新的连接请求或已连接 socket 上的数据到达。
* **事件处理:** Android 的事件循环机制（例如，Looper）在底层可能会使用 `poll` 或 `select` 来等待消息队列中有新的事件到达。
    * **例子:**  Android 的 `MessageQueue` 内部可能使用 `poll` 来等待新的消息。
* **Binder IPC:**  虽然 Binder IPC 的实现细节比较复杂，但在某些情况下，底层的通信机制可能涉及到等待文件描述符变得可读或可写，这可能涉及到 `poll` 或 `select`。
* **管道和文件操作:** 当应用需要同时监控多个管道或文件的状态时，可以使用这些函数。
    * **例子:**  一个视频解码器可能使用多个管道进行数据传输，并使用 `poll` 来监控这些管道的状态。

**libc 函数的实现细节**

1. **`poll` 的实现:**
   - `poll` 函数首先将以毫秒为单位的超时时间 `ms` 转换为 `timespec` 结构体。如果 `ms` 为负数，则 `ts_ptr` 为 `nullptr`，表示无限期等待。
   - 然后，它直接调用底层的系统调用 `__ppoll`。`__ppoll` 是内核提供的实现，负责实际的 I/O 多路复用操作。
   - 传递给 `__ppoll` 的信号掩码参数为 `nullptr`，表示不阻塞任何信号。

2. **`ppoll` 的实现:**
   - **LP64 架构:** 直接将 `ppoll` 强别名为 `ppoll64`，因为 `sigset_t` 和 `sigset64_t` 相同。
   - **ILP32 架构:**
     - 创建一个 `SigSetConverter` 对象，用于将 `sigset_t` 转换为 `sigset64_t`。
     - 调用 `ppoll64`，将转换后的 `sigset64_t` 指针传递给它。

3. **`ppoll64` 的实现:**
   - 为了避免修改原始的 `timespec` 和 `sigset64_t` 结构体（因为底层的系统调用可能会修改它们），函数会创建这些结构体的可变拷贝 `mutable_ts` 和 `mutable_ss`。
   - 如果传入的 `ts` 不为 `nullptr`，则将 `ts` 的内容复制到 `mutable_ts`。
   - 如果传入的 `ss` 不为 `nullptr`，则将 `ss` 的内容复制到 `mutable_ss`，并使用 `filter_reserved_signals` 函数过滤掉一些保留的信号，这些信号不应该被用户程序阻塞。
   - 最后，调用底层的系统调用 `__ppoll`，并将可变的 `timespec` 和 `sigset64_t` 指针传递给它。

4. **`select` 的实现:**
   - `select` 函数将以 `timeval` 结构体表示的超时时间转换为 `timespec` 结构体。如果转换失败（例如，时间值无效），则设置 `errno` 为 `EINVAL` 并返回 -1。
   - 它调用底层的系统调用 `__pselect6`。
   - 如果 `tv` 不为 `nullptr`，在 `__pselect6` 返回后，将 `timespec` 结构体中的剩余时间转换回 `timeval` 结构体。这是因为某些 `select` 的实现会在返回时修改超时时间，以指示剩余的等待时间。

5. **`pselect` 的实现:**
   - **LP64 架构:** 直接将 `pselect` 强别名为 `pselect64`。
   - **ILP32 架构:**
     - 创建一个 `SigSetConverter` 对象，将 `sigset_t` 转换为 `sigset64_t`。
     - 调用 `pselect64`，传递转换后的 `sigset64_t` 指针。

6. **`pselect64` 的实现:**
   - 类似于 `ppoll64`，它创建 `timespec` 和 `sigset64_t` 的可变拷贝。
   - 关键的区别在于 `pselect64` 如何处理信号掩码。由于 Linux 内核的 `__pselect6` 系统调用只接受 6 个参数，而实际上需要传递 7 个参数（包括信号掩码），因此 Bionic 通过一个额外的结构体 `pselect6_extra_data_t` 来传递信号掩码的信息。
   - `pselect6_extra_data_t` 结构体包含信号掩码的地址 (`ss_addr`) 和长度 (`ss_len`)。
   - `pselect64` 将信号掩码的地址和长度填充到 `extra_data` 结构体中，并将该结构体的地址作为 `__pselect6` 的最后一个参数传递。

**涉及 dynamic linker 的功能**

`poll.cpp` 文件本身并不直接涉及 dynamic linker 的复杂逻辑，但它定义的函数会被动态链接到应用程序中。

* **`extern "C"`:**  这些函数都使用 `extern "C"` 声明，这确保了这些函数在链接时使用 C 语言的命名约定，而不是 C++ 的名字修饰。这使得它们可以被用 C 编写的代码以及 C++ 代码调用。
* **`__strong_alias`:**  `__strong_alias(ppoll, ppoll64);` 和 `__strong_alias(pselect, pselect64);` 这两个宏定义使用了强别名。这意味着在链接时，如果程序中调用了 `ppoll` (在 LP64 架构上)，dynamic linker 会将其解析为 `ppoll64` 的地址。这是一种代码优化和兼容性处理方式。

**so 布局样本和链接处理过程**

假设我们有一个简单的应用程序 `my_app`，它调用了 `poll` 函数。

**so 布局样本:**

```
/system/bin/linker64 (或 /system/bin/linker)  # Dynamic linker
/system/lib64/libc.so (或 /system/lib/libc.so)   # Bionic libc，包含 poll.cpp 编译后的代码
/data/local/tmp/my_app                       # 应用程序可执行文件
```

**链接处理过程:**

1. **编译时链接:** 当 `my_app` 被编译时，编译器会记录它需要 `poll` 函数的符号。链接器在创建可执行文件时，会在其动态符号表中记录对 `libc.so` 中 `poll` 符号的依赖。
2. **运行时加载:** 当 `my_app` 启动时，Android 的 zygote 进程会 fork 出一个新的进程来运行它。
3. **Dynamic Linker 介入:** 操作系统会加载 `my_app`，并注意到它是一个动态链接的可执行文件。然后，它会启动 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`)。
4. **加载依赖库:** Dynamic linker 会读取 `my_app` 的头部信息，找到它依赖的共享库，例如 `libc.so`。
5. **符号解析:** Dynamic linker 会加载 `libc.so` 到内存中。然后，它会遍历 `my_app` 中未解析的符号（例如 `poll`），并在 `libc.so` 的符号表中查找匹配的符号。
6. **重定位:** 找到 `poll` 符号后，dynamic linker 会将 `my_app` 中所有引用 `poll` 的地方更新为 `libc.so` 中 `poll` 函数的实际内存地址。
7. **执行:** 一旦所有依赖的符号都被解析和重定位，应用程序 `my_app` 就可以开始执行了。当它调用 `poll` 函数时，实际上会跳转到 `libc.so` 中 `poll` 函数的实现代码。

**逻辑推理、假设输入与输出**

假设我们调用 `poll` 函数监控一个可读的 socket 文件描述符。

**假设输入:**

```c++
#include <iostream>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/poll.h>
#include <cstring>

int main() {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        perror("socket");
        return 1;
    }

    sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(8080);

    if (bind(sockfd, (struct sockaddr*)&server_addr, sizeof(server_addr)) == -1) {
        perror("bind");
        close(sockfd);
        return 1;
    }

    if (listen(sockfd, 5) == -1) {
        perror("listen");
        close(sockfd);
        return 1;
    }

    pollfd fds[1];
    fds[0].fd = sockfd;
    fds[0].events = POLLIN; // 监听可读事件

    int timeout_ms = 5000; // 等待 5 秒

    std::cout << "开始 poll..." << std::endl;
    int result = poll(fds, 1, timeout_ms);

    if (result > 0) {
        if (fds[0].revents & POLLIN) {
            std::cout << "socket 可读!" << std::endl;
            // 可以调用 accept() 接受连接
        }
    } else if (result == 0) {
        std::cout << "poll 超时." << std::endl;
    } else {
        perror("poll");
    }

    close(sockfd);
    return 0;
}
```

**预期输出 (假设有连接请求):**

```
开始 poll...
socket 可读!
```

**预期输出 (假设超时):**

```
开始 poll...
poll 超时.
```

**常见使用错误**

1. **忘记检查返回值:** `poll` 和 `select` 返回值小于 0 表示出错，需要检查 `errno`。返回值等于 0 表示超时。返回值大于 0 表示有文件描述符就绪，需要检查 `revents` 字段来确定是哪个文件描述符以及什么事件就绪。
   ```c++
   int result = poll(fds, 1, timeout_ms);
   if (result < 0) {
       perror("poll"); // 正确处理错误
   } else if (result == 0) {
       // 处理超时
   } else {
       // 处理就绪的 fd
   }
   ```

2. **`fd_count` 参数错误:** `select` 函数的 `fd_count` 参数需要设置为所有被监控文件描述符的最大值加 1。如果设置不正确，可能会导致监控遗漏或越界访问。
   ```c++
   // 假设要监控 fd 3, 5, 7
   fd_set read_fds;
   FD_ZERO(&read_fds);
   FD_SET(3, &read_fds);
   FD_SET(5, &read_fds);
   FD_SET(7, &read_fds);
   int max_fd = 7;
   int result = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr); // 正确设置 fd_count
   ```

3. **`fd_set` 初始化错误:** 使用 `select` 时，必须在使用 `fd_set` 之前使用 `FD_ZERO` 宏将其清空，然后再使用 `FD_SET` 宏添加需要监控的文件描述符。
   ```c++
   fd_set read_fds;
   // FD_ZERO(&read_fds); // 必须初始化
   FD_SET(sockfd, &read_fds);
   ```

4. **超时时间设置错误:** 理解超时时间的单位和含义非常重要。`poll` 使用毫秒，`select` 使用 `timeval` 结构体（秒和微秒）。设置错误的超时时间可能导致程序行为不符合预期。

5. **信号处理不当:**  如果使用了 `ppoll` 或 `pselect`，需要正确设置信号掩码，避免阻塞掉不应该阻塞的信号，或者忘记处理在等待期间可能收到的信号。

**Android Framework 或 NDK 如何到达这里**

以下是一个从 Android Framework 到 `poll.cpp` 的可能路径示例（以网络操作为例）：

1. **Java 代码 (Android Framework):**
   - 应用程序或 Framework 服务可能使用 `java.net.Socket` 或 `java.nio` 包中的类进行网络操作。
   - 例如，创建一个 `ServerSocket` 监听端口，或者创建一个 `Socket` 连接到远程服务器。

2. **Native 代码 (Android Framework - 例如，netd 守护进程):**
   - Java 网络相关的类最终会调用到 native 代码，这些 native 代码通常位于 Android Framework 的 native 组件中（例如，`libnetd_client.so`）。
   - `netd` 守护进程负责处理底层的网络操作。

3. **系统调用:**
   - `netd` 或 Framework 的其他 native 组件会调用底层的 socket 系统调用，例如 `socket()`, `bind()`, `listen()`, `accept()`, `connect()`, `send()`, `recv()` 等。
   - 当需要进行 I/O 多路复用时，例如，`netd` 需要同时监听多个 socket 连接，它会调用 `poll` 或 `select` 系统调用。

4. **Bionic libc:**
   - 这些系统调用会陷入内核，内核处理完后返回用户空间。
   - 在用户空间，应用程序或 `netd` 实际上调用的是 Bionic libc 提供的 `poll` 或 `select` 函数的封装，也就是 `bionic/libc/bionic/poll.cpp` 中定义的函数。
   - 这些封装函数负责处理参数转换、错误处理等，然后调用底层的 `__ppoll` 或 `__pselect6` 系统调用。

**Frida Hook 示例**

可以使用 Frida hook `poll` 函数来观察其行为：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

device = frida.get_usb_device(timeout=10)
pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
session = device.attach(pid) if pid else device.spawn(['com.example.myapp']) # 替换为你的应用包名
# session = device.attach('com.android.systemui') # Hook 系统进程

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "poll"), {
    onEnter: function(args) {
        var fds = ptr(args[0]);
        var nfds = args[1].toInt();
        var timeout = args[2].toInt();
        console.log("[*] poll called");
        console.log("    fds: " + fds);
        console.log("    nfds: " + nfds);
        console.log("    timeout (ms): " + timeout);

        for (var i = 0; i < nfds; i++) {
            var pollfd = fds.add(i * Process.pageSize); // 假设 pollfd 大小为 pageSize，实际应根据结构体大小计算
            var fd = pollfd.readInt();
            var events = pollfd.add(4).readShort();
            console.log("    fd[" + i + "]: " + fd + ", events: " + events);
        }
    },
    onLeave: function(retval) {
        console.log("[*] poll returned: " + retval);
        if (retval > 0) {
            var fds = ptr(this.context.r0); // 获取返回值对应的 fds 指针 (x86_64)
            var nfds = this.context.r1.toInt();
            for (var i = 0; i < nfds; i++) {
                var pollfd = fds.add(i * Process.pageSize);
                var fd = pollfd.readInt();
                var revents = pollfd.add(6).readShort();
                console.log("    fd[" + i + "]: " + fd + ", revents: " + revents);
            }
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
if not pid:
    device.resume(session.pid)
sys.stdin.read()
"""
```

**使用方法:**

1. 将上述 Python 代码保存为 `hook_poll.py`。
2. 找到你要 hook 的 Android 应用程序的进程 ID (PID)。可以使用 `adb shell ps | grep your_package_name` 命令获取。
3. 运行 Frida 脚本：`frida -UF -l hook_poll.py <PID>` 或 `python hook_poll.py <PID>`
4. 如果要 hook 启动时就调用的 `poll`，可以先 spawn 应用：`python hook_poll.py com.example.myapp`

**Frida Hook 输出示例:**

```
[*] poll called
    fds: NativePointer(address=0x7b40001000)
    nfds: 1
    timeout (ms): 5000
    fd[0]: 3, events: 1
[*] poll returned: 1
    fd[0]: 3, revents: 1
```

这个输出显示了 `poll` 函数被调用时的参数（`fds` 指针、文件描述符数量、超时时间）以及返回值。如果 `poll` 返回值大于 0，还会显示就绪的文件描述符及其 `revents`。

希望这个详细的解释能够帮助你理解 `bionic/libc/bionic/poll.cpp` 文件的功能和在 Android 系统中的作用。

### 提示词
```
这是目录为bionic/libc/bionic/poll.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```cpp
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

#include <errno.h>
#include <sys/poll.h>
#include <sys/select.h>

#include <platform/bionic/reserved_signals.h>

#include "private/bionic_time_conversions.h"
#include "private/SigSetConverter.h"

extern "C" int __ppoll(pollfd*, unsigned int, timespec*, const sigset64_t*, size_t);
extern "C" int __pselect6(int, fd_set*, fd_set*, fd_set*, timespec*, void*);

int poll(pollfd* fds, nfds_t fd_count, int ms) {
  timespec ts;
  timespec* ts_ptr = nullptr;
  if (ms >= 0) {
    timespec_from_ms(ts, ms);
    ts_ptr = &ts;
  }
  return __ppoll(fds, fd_count, ts_ptr, nullptr, 0);
}

// The underlying ppoll(2) system call only takes `sigset64_t`.
#if defined(__LP64__)
// That's fine for LP64 where `sigset_t` and `sigset64_t` are the same.
__strong_alias(ppoll, ppoll64);
#else
// ILP32 needs a shim.
int ppoll(pollfd* fds, nfds_t fd_count, const timespec* ts, const sigset_t* ss) {
  SigSetConverter set{ss};
  return ppoll64(fds, fd_count, ts, set.ptr);
}
#endif

int ppoll64(pollfd* fds, nfds_t fd_count, const timespec* ts, const sigset64_t* ss) {
  // The underlying __ppoll system call modifies its `struct timespec` argument.
  timespec mutable_ts;
  timespec* mutable_ts_ptr = nullptr;
  if (ts != nullptr) {
    mutable_ts = *ts;
    mutable_ts_ptr = &mutable_ts;
  }

  sigset64_t mutable_ss;
  sigset64_t* mutable_ss_ptr = nullptr;
  if (ss != nullptr) {
    mutable_ss = filter_reserved_signals(*ss, SIG_SETMASK);
    mutable_ss_ptr = &mutable_ss;
  }

  return __ppoll(fds, fd_count, mutable_ts_ptr, mutable_ss_ptr, sizeof(*mutable_ss_ptr));
}

int select(int fd_count, fd_set* read_fds, fd_set* write_fds, fd_set* error_fds, timeval* tv) {
  timespec ts;
  timespec* ts_ptr = nullptr;
  if (tv != nullptr) {
    if (!timespec_from_timeval(ts, *tv)) {
      errno = EINVAL;
      return -1;
    }
    ts_ptr = &ts;
  }
  int result = __pselect6(fd_count, read_fds, write_fds, error_fds, ts_ptr, nullptr);
  if (tv != nullptr) {
    timeval_from_timespec(*tv, ts);
  }
  return result;
}

// The underlying pselect6(2) system call only takes `sigset64_t`.
#if defined(__LP64__)
// That's fine for LP64 where `sigset_t` and `sigset64_t` are the same.
__strong_alias(pselect, pselect64);
#else
// ILP32 needs a shim.
int pselect(int fd_count, fd_set* read_fds, fd_set* write_fds, fd_set* error_fds,
            const timespec* ts, const sigset_t* ss) {
  // The underlying `__pselect6` system call only takes `sigset64_t`.
  SigSetConverter set{ss};
  return pselect64(fd_count, read_fds, write_fds, error_fds, ts, set.ptr);
}
#endif

int pselect64(int fd_count, fd_set* read_fds, fd_set* write_fds, fd_set* error_fds,
              const timespec* ts, const sigset64_t* ss) {
  // The underlying __pselect6 system call modifies its `struct timespec` argument.
  timespec mutable_ts;
  timespec* mutable_ts_ptr = nullptr;
  if (ts != nullptr) {
    mutable_ts = *ts;
    mutable_ts_ptr = &mutable_ts;
  }

  sigset64_t mutable_ss;
  sigset64_t* mutable_ss_ptr = nullptr;
  if (ss != nullptr) {
    mutable_ss = filter_reserved_signals(*ss, SIG_SETMASK);
    mutable_ss_ptr = &mutable_ss;
  }

  // The Linux kernel only handles 6 arguments and this system call really needs 7,
  // so the last argument is a void* pointing to:
  struct pselect6_extra_data_t {
    uintptr_t ss_addr;
    size_t ss_len;
  };
  pselect6_extra_data_t extra_data;
  extra_data.ss_addr = reinterpret_cast<uintptr_t>(mutable_ss_ptr);
  extra_data.ss_len = sizeof(*mutable_ss_ptr);

  return __pselect6(fd_count, read_fds, write_fds, error_fds, mutable_ts_ptr, &extra_data);
}
```