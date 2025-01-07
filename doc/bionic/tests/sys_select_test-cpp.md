Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Understanding the Goal:**

The primary goal is to analyze the `sys_select_test.cpp` file, understand its purpose, the functions it tests, how it relates to Android, and potential usage issues. The prompt also asks for specific details about libc functions, dynamic linking, and debugging.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly scan the code for important keywords and structures. This immediately reveals:

* **`#include` directives:**  `gtest/gtest.h`, `errno.h`, `signal.h`, `stdlib.h`, `sys/select.h`, `sys/types.h`, `sys/wait.h`, `utils.h`. These tell us the core functionalities being tested: `select`/`pselect` and related utilities. The presence of `gtest` indicates it's a unit test.
* **`TEST` macros:**  These define the individual test cases: `fd_set_smoke`, `select_smoke`, `pselect_smoke`, `FD_ISSET_const`. This structure helps organize the analysis by focusing on each test individually.
* **`FD_ZERO`, `FD_SET`, `FD_CLR`, `FD_ISSET`:** These are the core macros for manipulating `fd_set` data structures, which are fundamental to `select` and `pselect`.
* **`select`, `pselect`:** The functions under test.
* **`pipe`, `fork`, `usleep`, `write`, `read`, `exit`, `waitpid` (through `AssertChildExited`):**  These are standard POSIX/libc functions used for setting up test scenarios, especially for testing blocking behavior and inter-process communication.
* **`timeval`, `timespec`:** Structures used for timeouts in `select` and `pselect`.
* **`sigset_t`, `sigemptyset`, `sigaddset`:**  Relating to signal handling, specifically used in the `pselect_smoke` test.
* **`ASSERT_EQ`, `ASSERT_NE`, `ASSERT_TRUE`, `ASSERT_FALSE`, `ASSERT_LT`, `ASSERT_STREQ`, `ASSERT_ERRNO`:**  These are `gtest` assertion macros used to check the expected behavior of the functions being tested.

**3. Analyzing Each Test Case:**

Now, examine each `TEST` function in detail:

* **`fd_set_smoke`:**  Focuses on the basic operations of the `fd_set` macros (`FD_ZERO`, `FD_SET`, `FD_CLR`, `FD_ISSET`). It checks if these macros correctly set, clear, and check bits in the `fd_set`. This test is independent of the `select` and `pselect` system calls themselves but verifies the correctness of the underlying data structure manipulation.

* **`select_smoke`:**  Tests the `select` system call. It covers:
    * Basic usage with standard file descriptors (stdin, stdout, stderr).
    * Handling of return values (number of ready file descriptors).
    * Checking which file descriptors are ready using `FD_ISSET`.
    * Testing invalid `maxfd` and `timeout` arguments, ensuring `errno` is set correctly.
    * Testing a valid timeout scenario using `pipe` and `fork` to simulate data becoming available on a file descriptor after a delay.

* **`pselect_smoke`:** Similar to `select_smoke`, but specifically tests the `pselect` system call. It highlights the key difference: the ability to specify a signal mask. The test focuses on similar aspects as `select_smoke` (basic usage, return values, error handling, timeout), but also includes setting up a signal mask (although the signal mask isn't directly tested for its effect on blocking in this particular test). It also verifies that `timespec` is *not* updated on successful return, unlike `timeval` in `select`.

* **`FD_ISSET_const`:**  A simple test to ensure `FD_ISSET` can be used with a `const fd_set`.

**4. Relating to Android:**

Consider how these tests relate to the broader Android system:

* **Bionic as the C Library:**  Recognize that this test file is part of Bionic, Android's C library. This means it's testing the fundamental system call implementations used by all Android applications and system services.
* **`select`/`pselect` Importance:** Understand that `select` and `pselect` are crucial for implementing I/O multiplexing, allowing applications to monitor multiple file descriptors for readiness (read, write, exception) without blocking. This is essential for network servers, UI event loops, and other asynchronous operations.
* **Standard Libc Functions:** The test uses standard libc functions like `pipe`, `fork`, `usleep`, `read`, `write`, which are foundational to any C program and thus critical to Android.

**5. Detailed Explanation of Libc Functions:**

For each libc function used in the tests, provide a brief explanation of its purpose and how it's used in the context of the tests. For example:

* **`select`:**  Monitors file descriptors for readiness. The test uses it to wait for data on a pipe.
* **`pselect`:** Similar to `select` but allows for a signal mask.
* **`pipe`:** Creates a unidirectional communication channel. Used to simulate delayed data availability.
* **`fork`:** Creates a new process. Used to run the delayed write operation in the background.
* **`usleep`:** Pauses execution for a specified number of microseconds. Used to introduce a delay.
* **`read`:** Reads data from a file descriptor. Used to verify the data written to the pipe.
* **`write`:** Writes data to a file descriptor. Used to send the delayed message.
* **`exit`:** Terminates the current process. Used by the child process after writing.
* **`waitpid` (via `AssertChildExited`):** Waits for a child process to terminate. Used to clean up after the forked process.
* **`FD_ZERO`, `FD_SET`, `FD_CLR`, `FD_ISSET`:**  Macros for manipulating `fd_set`.

**6. Dynamic Linker (Not Directly Involved):**

In this *specific* test file, the dynamic linker isn't directly tested. While `select` and related functions are part of libc, which *is* dynamically linked, the test itself doesn't delve into the dynamic linking process. Therefore, while it's good to acknowledge the dynamic linker's role in loading libc, a detailed explanation of its involvement in *this specific code* isn't necessary. It's important to recognize the limitations of the provided snippet.

**7. Logical Reasoning, Assumptions, Inputs, Outputs:**

For the test cases involving timeouts, make explicit the assumptions about the timing and the expected outcomes. For example, in the `select_smoke` test with the timeout:

* **Assumption:** The `usleep(5000)` (5 milliseconds) in the child process is significantly shorter than the 1-second timeout in `select`.
* **Input:** A file descriptor `fd` that will become readable after a short delay.
* **Expected Output:** `select` returns 1 (indicating one file descriptor is ready), and the `timeval` structure is updated to reflect the remaining time.

**8. Common Usage Errors:**

Think about common mistakes developers make when using `select` and related functions:

* **Incorrect `maxfd`:**  Providing a value that's too small or incorrect can lead to unexpected behavior or missed events.
* **Not clearing `fd_set` before use:**  If you reuse an `fd_set` without clearing it, you might have leftover bits set from previous calls.
* **Forgetting to re-add fds after `select` returns:** `select` modifies the `fd_set` to indicate which file descriptors are ready. If you want to monitor the same set of fds again, you need to re-set them.
* **Incorrect timeout handling:**  Misunderstanding how `select` modifies the `timeval` structure (or the lack of modification for `pselect`'s `timespec`).
* **Signal handling issues (for `select`):** `select` can be interrupted by signals. Using `pselect` with a signal mask provides more control.

**9. Android Framework/NDK Path and Frida Hooking:**

Trace the path from an Android application to the `select` call:

* **Java (Android Framework):**  High-level I/O operations in Java (e.g., network sockets, file I/O) often eventually delegate to native code.
* **NDK:**  Native code developed using the NDK can directly call libc functions like `select` or functions that internally use `select`.
* **Bionic:** The NDK links against Bionic, so calls to `select` are resolved to the Bionic implementation.
* **Kernel:** Bionic's `select` implementation makes a system call to the Linux kernel, which performs the actual monitoring of file descriptors.

For Frida hooking, provide examples of how to intercept the `select` and `pselect` calls to inspect arguments and return values.

**10. Structure and Language:**

Finally, organize the information logically and present it clearly in Chinese, as requested by the prompt. Use headings, bullet points, and code formatting to improve readability.

By following these steps, you can comprehensively analyze the provided C++ test file and address all the requirements of the prompt. The key is to systematically break down the code, understand its purpose, and connect it to the broader Android ecosystem.
这个文件 `bionic/tests/sys_select_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用来测试 `select` 和 `pselect` 这两个系统调用以及相关的 `fd_set` 宏。

**它的功能：**

1. **测试 `fd_set` 相关的宏：**  测试 `FD_ZERO`、`FD_SET`、`FD_CLR` 和 `FD_ISSET` 这些宏的正确性，确保它们能够正确地操作文件描述符集合。
2. **测试 `select` 系统调用：**
   - 验证 `select` 在没有文件描述符准备好时的阻塞行为。
   - 验证 `select` 在有文件描述符准备好时的返回行为。
   - 验证 `select` 对超时参数的处理。
   - 测试 `select` 对无效参数的处理（例如，负数的 `maxfd` 或 `timeout`）。
3. **测试 `pselect` 系统调用：**
   - 验证 `pselect` 的基本功能，类似于 `select`。
   - 验证 `pselect` 对信号掩码的处理（虽然在这个特定的测试中没有显式地测试信号掩码的阻塞效果，但它作为参数被传递）。
   - 验证 `pselect` 对超时参数的处理，注意 `pselect` 的超时参数 `timespec` 在成功返回后不会被修改，而 `select` 的 `timeval` 会被修改。

**与 Android 功能的关系及举例说明：**

`select` 和 `pselect` 是多路 I/O 复用技术的核心，在 Android 中被广泛使用，用于高效地监控多个文件描述符的状态，而无需为每个文件描述符创建一个单独的线程。这对于处理并发网络连接、UI 事件循环等场景至关重要。

**举例说明：**

* **网络编程：**  Android 应用需要同时监听多个网络连接的事件（例如，新连接请求、数据到达）。可以使用 `select` 或 `pselect` 来监控多个 socket 文件描述符的可读状态，当某个 socket 有数据到达时，`select` 或 `pselect` 会返回，应用程序可以处理该 socket 的数据。
* **UI 事件循环：** Android 的 UI 线程也需要监听各种事件，例如用户的触摸、按键事件。虽然底层的实现可能更加复杂，但多路 I/O 复用的思想可以用于监控多个事件源的文件描述符。
* **Binder 通信：** Android 的进程间通信机制 Binder 的底层实现也可能涉及到文件描述符的监控，`select` 或 `pselect` 可以用于等待 Binder 事件的发生。

**详细解释每一个 libc 函数的功能是如何实现的：**

1. **`FD_ZERO(fd_set *fds)`:**
   - **功能：** 将 `fd_set` 结构体 `fds` 中的所有位都设置为 0，清空文件描述符集合。
   - **实现：**  通常 `fd_set` 是一个位图（bitmask），`FD_ZERO` 的实现就是将这块内存区域的所有字节都设置为 0。

2. **`FD_SET(int fd, fd_set *fds)`:**
   - **功能：** 将文件描述符 `fd` 添加到 `fd_set` 结构体 `fds` 中。
   - **实现：**  确定 `fd` 在位图中对应的位，然后将该位设置为 1。通常，`fd_set` 的大小足以容纳系统允许的最大文件描述符数量。

3. **`FD_CLR(int fd, fd_set *fds)`:**
   - **功能：** 将文件描述符 `fd` 从 `fd_set` 结构体 `fds` 中移除。
   - **实现：** 确定 `fd` 在位图中对应的位，然后将该位设置为 0。

4. **`FD_ISSET(int fd, const fd_set *fds)`:**
   - **功能：** 检查文件描述符 `fd` 是否在 `fd_set` 结构体 `fds` 中。
   - **实现：** 确定 `fd` 在位图中对应的位，然后检查该位是否为 1。

5. **`pipe(int pipefd[2])`:**
   - **功能：** 创建一个管道，用于进程间通信。返回两个文件描述符，`pipefd[0]` 用于读取，`pipefd[1]` 用于写入。
   - **实现：**  内核会分配一个匿名的、单向的数据通道，并返回两个关联的文件描述符。写入到 `pipefd[1]` 的数据可以从 `pipefd[0]` 读取。

6. **`fork()`:**
   - **功能：** 创建一个新的进程，新进程是当前进程的副本（子进程）。
   - **实现：**  内核会复制当前进程的地址空间、文件描述符等资源。`fork` 函数在父进程中返回子进程的 PID，在子进程中返回 0。

7. **`usleep(useconds_t usec)`:**
   - **功能：** 使当前进程休眠指定的微秒数。
   - **实现：**  内核会将当前进程置于休眠状态，直到指定的时间过去。这是一个忙等待的低精度休眠，不推荐在高精度计时中使用。

8. **`write(int fd, const void *buf, size_t count)`:**
   - **功能：** 将缓冲区 `buf` 中的 `count` 个字节写入到文件描述符 `fd` 中。
   - **实现：**  内核会将缓冲区中的数据复制到与文件描述符关联的目标（例如，管道的缓冲区，socket 的发送缓冲区）。

9. **`read(int fd, void *buf, size_t count)`:**
   - **功能：** 从文件描述符 `fd` 中读取最多 `count` 个字节到缓冲区 `buf` 中。
   - **实现：** 内核会从与文件描述符关联的源（例如，管道的缓冲区，socket 的接收缓冲区）复制数据到缓冲区 `buf` 中。

10. **`exit(int status)`:**
    - **功能：** 终止当前进程，并向父进程返回退出状态 `status`。
    - **实现：**  内核会清理进程占用的资源，并将退出状态通知父进程。

11. **`select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)`:**
    - **功能：** 监控多个文件描述符的读、写或异常状态。
    - **实现：**  内核会检查 `readfds`、`writefds` 和 `exceptfds` 中指定的文件描述符的状态。
        - 如果 `timeout` 为 `NULL`，`select` 会一直阻塞，直到至少有一个文件描述符准备好。
        - 如果 `timeout` 的 `tv_sec` 和 `tv_usec` 都是 0，`select` 会立即返回，检查文件描述符的状态。
        - 如果 `timeout` 的值大于 0，`select` 会阻塞指定的时间，如果在超时时间内没有文件描述符准备好，则返回 0。
        - `select` 会修改 `readfds`、`writefds` 和 `exceptfds`，只保留准备好的文件描述符。
    - **返回值：** 准备好的文件描述符的总数，超时返回 0，错误返回 -1。

12. **`pselect(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, const struct timespec *timeout, const sigset_t *sigmask)`:**
    - **功能：**  类似于 `select`，但增加了信号掩码的功能，允许在等待文件描述符状态时阻塞或解除阻塞某些信号。
    - **实现：**  与 `select` 类似，但增加了对信号的处理。
        - 在调用 `pselect` 时，进程的信号掩码会被 `sigmask` 替换。
        - 当 `pselect` 返回时，进程的信号掩码会被恢复为调用前的状态。
        - `pselect` 的超时参数是 `timespec` 结构体，表示秒和纳秒，精度更高。
        - 与 `select` 不同，`pselect` 的 `timespec` 超时参数在成功返回后不会被修改。
    - **返回值：** 准备好的文件描述符的总数，超时返回 0，错误返回 -1。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

这个测试文件本身并没有直接测试 dynamic linker 的功能。`select` 和 `pselect` 是系统调用，它们的实现位于内核中，Bionic 库只是提供了对这些系统调用的封装。

然而，`select` 和 `pselect` 这些函数本身是属于 Bionic 库 (`libc.so`) 的，这个库是动态链接的。

**`libc.so` 布局样本（简化）：**

```
libc.so:
    .text:  # 代码段，包含 select 和 pselect 的实现（作为对内核系统调用的封装）
        select:
            ; ... 对 __NR_select 系统调用的封装 ...
        pselect:
            ; ... 对 __NR_pselect6 系统调用的封装 ...
        ... 其他 libc 函数 ...
    .data:  # 数据段，包含全局变量
    .bss:   # 未初始化数据段
    .dynsym: # 动态符号表，列出导出的符号（例如 select, pselect）
    .dynstr: # 动态字符串表，存储符号名称
    .plt:    # 过程链接表，用于延迟绑定
    .got:    # 全局偏移表，用于访问全局数据
```

**链接的处理过程：**

1. **编译时：** 当编译包含 `select` 或 `pselect` 调用的代码时，编译器会生成对这些符号的引用。链接器在链接时会查找 `libc.so` 中的这些符号。
2. **加载时：** 当 Android 应用启动时，其链接器（`linker` 或 `linker64`）负责加载应用依赖的动态链接库，包括 `libc.so`。
3. **重定位：** 链接器会根据 `libc.so` 在内存中的加载地址，修正应用中对 `select` 和 `pselect` 等符号的引用。这通常通过修改全局偏移表 (GOT) 中的条目来实现。
4. **延迟绑定 (Lazy Binding)：**  默认情况下，为了提高启动速度，动态链接器会使用延迟绑定。这意味着对 `select` 或 `pselect` 的实际符号解析和重定位会推迟到第一次调用这些函数时。过程链接表 (PLT) 中的代码会负责在首次调用时调用链接器来解析符号并更新 GOT 表项。

**如果做了逻辑推理，请给出假设输入与输出：**

在 `sys_select_test.cpp` 中，存在一些逻辑推理，例如在 `select_smoke` 测试中：

**假设输入：**

- 创建了一个管道，子进程延迟 5000 微秒 (5 毫秒) 后向管道写入数据。
- 父进程使用 `select` 监控管道的读端，超时时间设置为 1 秒。

**预期输出：**

- `select` 调用应该在 5 毫秒后返回，因为子进程写入了数据，管道变为可读。
- `select` 的返回值应该为 1，表示有一个文件描述符准备好（管道的读端）。
- `FD_ISSET(fd, &r)` 应该返回 `true`，表明管道的读端在就绪集合中。
- 超时时间 `tv.tv_sec` 应该变为 0，`tv.tv_usec` 应该是一个小于 1 秒的值（表示剩余的时间）。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **`maxfd` 参数错误：** `select` 的第一个参数 `nfds` 应该设置为待监控的最大文件描述符加 1。如果设置错误，可能会导致某些文件描述符没有被正确监控。
   ```c++
   fd_set read_fds;
   FD_ZERO(&read_fds);
   FD_SET(5, &read_fds);
   FD_SET(10, &read_fds);
   // 错误：maxfd 应该至少为 11
   int ret = select(10, &read_fds, nullptr, nullptr, nullptr);
   ```

2. **忘记在循环中重新设置 `fd_set`：** `select` 会修改传入的 `fd_set`，只保留准备好的文件描述符。如果在循环中使用 `select`，需要每次循环开始前重新设置要监控的文件描述符。
   ```c++
   while (true) {
       fd_set read_fds;
       FD_ZERO(&read_fds);
       FD_SET(socket1, &read_fds);
       FD_SET(socket2, &read_fds);
       select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);
       // ... 处理就绪的文件描述符 ...
       // 如果没有重新设置 read_fds，下一次循环可能监控的是上次 select 后的状态
   }
   ```

3. **不正确地处理 `select` 的返回值：** `select` 返回准备好的文件描述符的数量，超时返回 0，错误返回 -1 并设置 `errno`。需要正确处理这些返回值。
   ```c++
   int ret = select(max_fd + 1, &read_fds, nullptr, nullptr, &timeout);
   if (ret == -1) {
       perror("select"); // 应该检查 errno
   } else if (ret == 0) {
       // 超时处理
   } else {
       // 处理就绪的文件描述符
   }
   ```

4. **混淆 `select` 和 `pselect` 的超时参数：**  `select` 修改 `timeval`，而 `pselect` 不修改 `timespec`。错误地认为 `pselect` 也会修改超时参数可能导致逻辑错误。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework (Java 代码)：**  假设一个 Android 应用需要进行网络操作，它可能会使用 `java.net.Socket` 或 `java.nio.channels.SocketChannel` 等类。

2. **Framework Native 代码：**  Java Framework 的网络相关的类通常会在 native 层调用相关的函数。例如，`java.net.SocketInputStream` 的 `read()` 方法最终会调用 native 方法。

3. **NDK (C/C++ 代码)：** 如果开发者使用 NDK 直接进行网络编程，他们会使用标准的 socket API，例如 `socket()`, `bind()`, `listen()`, `accept()`, `connect()`, `recv()`, `send()`, 以及 `select()` 或 `pselect()`。

4. **Bionic Libc：** NDK 编译的代码链接到 Bionic 库 (`libc.so`)，当调用 `select()` 或 `pselect()` 时，会调用 Bionic 库中对应的封装函数。这些封装函数会将参数转换为系统调用所需的格式，然后发起系统调用。

5. **内核 (Kernel)：**  最终，`select()` 或 `pselect()` 会作为系统调用进入 Linux 内核。内核负责实际的 I/O 多路复用操作，监控指定文件描述符的状态，并在有事件发生或超时后返回。

**Frida Hook 示例：**

可以使用 Frida hook `select` 和 `pselect` 函数来观察其调用过程和参数。

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {0}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except Exception as e:
    print(f"无法附加到进程: {e}")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "select"), {
    onEnter: function(args) {
        console.log("[+] select called");
        console.log("    nfds: " + args[0]);
        console.log("    readfds: " + args[1]);
        console.log("    writefds: " + args[2]);
        console.log("    exceptfds: " + args[3]);
        console.log("    timeout: " + args[4]);
        // 可以进一步解析 fd_set 和 timeout 结构体
    },
    onLeave: function(retval) {
        console.log("[+] select returned: " + retval);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "pselect"), {
    onEnter: function(args) {
        console.log("[+] pselect called");
        console.log("    nfds: " + args[0]);
        console.log("    readfds: " + args[1]);
        console.log("    writefds: " + args[2]);
        console.log("    exceptfds: " + args[3]);
        console.log("    timeout: " + args[4]);
        console.log("    sigmask: " + args[5]);
        // 可以进一步解析 fd_set, timespec 和 sigset_t 结构体
    },
    onLeave: function(retval) {
        console.log("[+] pselect returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
print("[*] 脚本已加载，开始监听...")
sys.stdin.read()
session.detach()
```

**使用方法：**

1. 确保你的 Android 设备已连接并通过 ADB 可访问。
2. 替换 `package_name` 为你要调试的 Android 应用的包名。
3. 运行 Frida 脚本。
4. 在你的 Android 应用中执行会调用 `select` 或 `pselect` 的操作（例如，进行网络请求）。
5. Frida 脚本会在终端输出 `select` 和 `pselect` 的调用信息，包括参数和返回值。

通过 Frida Hook，你可以深入了解 Android Framework 或 NDK 代码如何最终调用到 Bionic 库的 `select` 和 `pselect` 函数，并观察这些系统调用的具体行为。

Prompt: 
```
这是目录为bionic/tests/sys_select_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#include <signal.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "utils.h"

TEST(sys_select, fd_set_smoke) {
  fd_set fds;
  FD_ZERO(&fds);

  for (size_t i = 0; i < 1024; ++i) {
    EXPECT_FALSE(FD_ISSET(i, &fds));
  }

  FD_SET(0, &fds);
  EXPECT_TRUE(FD_ISSET(0, &fds));
  EXPECT_FALSE(FD_ISSET(1, &fds));
  FD_SET(1, &fds);
  EXPECT_TRUE(FD_ISSET(0, &fds));
  EXPECT_TRUE(FD_ISSET(1, &fds));
  FD_CLR(0, &fds);
  EXPECT_FALSE(FD_ISSET(0, &fds));
  EXPECT_TRUE(FD_ISSET(1, &fds));
  FD_CLR(1, &fds);
  EXPECT_FALSE(FD_ISSET(0, &fds));
  EXPECT_FALSE(FD_ISSET(1, &fds));
}

#define DELAY_MSG "1234"

static void DelayedWrite(int* pid, int* fd) {
  int fds[2];
  ASSERT_EQ(0, pipe(fds));

  if ((*pid = fork()) == 0) {
    close(fds[0]);
    usleep(5000);
    EXPECT_EQ(5, write(fds[1], DELAY_MSG, sizeof(DELAY_MSG)));
    close(fds[1]);
    exit(0);
  }
  ASSERT_LT(0, *pid);
  close(fds[1]);

  *fd = fds[0];
}

static void DelayedWriteCleanup(int pid, int fd) {
  char buf[sizeof(DELAY_MSG)];
  ASSERT_EQ(static_cast<ssize_t>(sizeof(DELAY_MSG)), read(fd, buf, sizeof(DELAY_MSG)));
  ASSERT_STREQ(DELAY_MSG, buf);

  AssertChildExited(pid, 0);
}

TEST(sys_select, select_smoke) {
  fd_set r;
  FD_ZERO(&r);
  fd_set w;
  FD_ZERO(&w);
  fd_set e;
  FD_ZERO(&e);

  FD_SET(STDIN_FILENO, &r);
  FD_SET(STDOUT_FILENO, &w);
  FD_SET(STDERR_FILENO, &w);

  int max = STDERR_FILENO + 1;

  // Invalid max fd.
  ASSERT_EQ(-1, select(-1, &r, &w, &e, nullptr));
  ASSERT_ERRNO(EINVAL);

  int num_fds = select(max, &r, &w, &e, nullptr);
  // If there is data to be read on STDIN, then the number of
  // fds ready will be 3 instead of 2. Allow this case, but verify
  // every fd that is set.
  ASSERT_TRUE(num_fds == 2 || num_fds == 3) << "Num fds returned " << num_fds;
  ASSERT_TRUE(FD_ISSET(STDOUT_FILENO, &w));
  ASSERT_TRUE(FD_ISSET(STDERR_FILENO, &w));
  if (num_fds == 3) {
    ASSERT_TRUE(FD_ISSET(STDIN_FILENO, &r));
  }

  // Invalid timeout.
  timeval tv;
  tv.tv_sec = -1;
  tv.tv_usec = 0;
  ASSERT_EQ(-1, select(max, &r, &w, &e, &tv));
  ASSERT_ERRNO(EINVAL);

  // Valid timeout...
  tv.tv_sec = 1;
  int pid, fd;
  DelayedWrite(&pid, &fd);

  FD_ZERO(&r);
  FD_SET(fd, &r);
  ASSERT_EQ(1, select(fd+1, &r, nullptr, nullptr, &tv));
  // Both tv_sec and tv_nsec should have been updated.
  ASSERT_EQ(0, tv.tv_sec);
  ASSERT_NE(0, tv.tv_usec);

  DelayedWriteCleanup(pid, fd);
}

TEST(sys_select, pselect_smoke) {
  sigset_t ss;
  sigemptyset(&ss);
  sigaddset(&ss, SIGPIPE);

  fd_set r;
  FD_ZERO(&r);
  fd_set w;
  FD_ZERO(&w);
  fd_set e;
  FD_ZERO(&e);

  FD_SET(STDIN_FILENO, &r);
  FD_SET(STDOUT_FILENO, &w);
  FD_SET(STDERR_FILENO, &w);

  int max = STDERR_FILENO + 1;

  // Invalid max fd.
  ASSERT_EQ(-1, pselect(-1, &r, &w, &e, nullptr, &ss));
  ASSERT_ERRNO(EINVAL);

  // If there is data to be read on STDIN, then the number of
  // fds ready will be 3 instead of 2. Allow this case, but verify
  // every fd that is set.
  int num_fds = pselect(max, &r, &w, &e, nullptr, &ss);
  ASSERT_TRUE(num_fds == 2 || num_fds == 3) << "Num fds returned " << num_fds;
  ASSERT_TRUE(FD_ISSET(STDOUT_FILENO, &w));
  ASSERT_TRUE(FD_ISSET(STDERR_FILENO, &w));
  if (num_fds == 3) {
    ASSERT_TRUE(FD_ISSET(STDIN_FILENO, &r));
  }

  // Invalid timeout.
  timespec tv;
  tv.tv_sec = -1;
  tv.tv_nsec = 0;
  ASSERT_EQ(-1, pselect(max, &r, &w, &e, &tv, &ss));
  ASSERT_ERRNO(EINVAL);

  // Valid timeout...
  tv.tv_sec = 1;
  int pid, fd;
  DelayedWrite(&pid, &fd);

  FD_ZERO(&r);
  FD_SET(fd, &r);
  ASSERT_EQ(1, pselect(fd+1, &r, nullptr, nullptr, &tv, nullptr));
  // Neither tv_sec nor tv_nsec should have been updated.
  ASSERT_EQ(1, tv.tv_sec);
  ASSERT_EQ(0, tv.tv_nsec);

  DelayedWriteCleanup(pid, fd);
}

TEST(sys_select, FD_ISSET_const) {
  const fd_set none = {};
  ASSERT_FALSE(FD_ISSET(atoi("0"), &none));
}

"""

```