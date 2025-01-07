Response:
Let's break down the thought process for analyzing the provided C++ test file. The goal is to extract information about its functionality, its relationship to Android, low-level details of libc functions, dynamic linking, potential issues, and its place within the Android ecosystem.

**1. Initial Read-through and High-Level Understanding:**

The first step is to read the code and get a general sense of what it's doing. Keywords like `TEST`, `openpty`, `forkpty`, `ioctl`, `pthread`, `sched_setaffinity` immediately jump out. This tells us it's a test file (likely using Google Test) for pty-related functionality. The presence of threading and CPU affinity suggests testing concurrency or specific kernel behaviors. The "bug_28979140" test clearly points to a regression test for a specific kernel issue.

**2. Deconstructing Each Test Case:**

Next, analyze each `TEST` block individually.

* **`TEST(pty, openpty)`:**  This looks like a basic test for the `openpty` function. It checks if the function returns valid file descriptors, if the tty name is correct, and if setting the window size using the `winsize` structure works. The `ioctl` call is important here.

* **`TEST(pty, forkpty)`:** This test verifies `forkpty`. It checks if a child process is created and if the session ID changes in the child. This is a classic use case of ptys for things like pseudo-terminals in SSH or terminal emulators.

* **`TEST(pty, bug_28979140)`:** This test is more complex. The comments strongly suggest a kernel bug related to memory barriers in a lock-free ring buffer used by ptys. The use of `pthread_create` and `sched_setaffinity` to pin threads to different CPUs reinforces this idea of testing concurrency-related issues. The core logic involves one thread writing data to the pty master, and another thread reading from the pty slave, checking if the data arrives in the correct order.

**3. Identifying Key libc Functions and Their Implementation Details:**

As each test is analyzed, identify the relevant libc functions.

* **`openpty`:** This is the central function being tested. Think about what it likely does: allocates a master and slave pty, sets up permissions, and returns file descriptors. Mentioning the underlying kernel driver and device nodes (`/dev/ptmx`, `/dev/pts/*`) is crucial.

* **`forkpty`:**  This combines `fork` with pty setup. Consider its likely implementation: call `fork`, and in the child, call `setsid` to create a new session and process group, then open the pty slave.

* **`ttyname_r`:** This retrieves the name of the tty associated with a file descriptor. Think about how it might access the underlying system information.

* **`ioctl`:** This is a general-purpose system call for device-specific operations. In this context, `TIOCGWINSZ` is used to get the window size. Explain that `ioctl` communicates directly with device drivers.

* **`close`:** A basic function to release file descriptors.

* **`getsid`:** Gets the session ID of a process.

* **`_exit`:**  Exits the child process without running cleanup handlers.

* **`pthread_create` and `pthread_join`:**  Standard POSIX thread functions. Explain their role in creating and waiting for threads.

* **`sched_getaffinity` and `sched_setaffinity`:**  Used for controlling CPU affinity, which is important for testing the specific kernel bug.

* **`tcgetattr`, `cfmakeraw`, `tcsetattr`:** These are terminal control functions used to put the tty into "raw" mode, disabling things like line buffering and signal generation. This is often needed when interacting directly with a pty.

**4. Android Relevance and Examples:**

Consider how these pty functions are used in Android.

* **Terminal Emulators:** The most obvious example. Terminal apps need ptys to simulate a terminal.
* **`adb shell`:**  When you use `adb shell`, it sets up a pty on the device for the shell session.
* **SSH Clients/Servers:** SSH uses ptys to provide interactive shell access.
* **Process Spawning with PTYs:**  Some applications might spawn subprocesses and interact with them through ptys.

**5. Dynamic Linking:**

The prompt asks about dynamic linking. While the provided code doesn't directly *use* dynamic linking in a complex way (it's a test within `bionic`), think about how these libc functions themselves are part of `libc.so`.

* **SO Layout:** Describe a simplified `libc.so` structure with sections like `.text` (code), `.data` (initialized data), `.bss` (uninitialized data), and the dynamic symbol table.

* **Linking Process:** Explain the steps: the linker finds the required symbols in shared libraries, resolves addresses, and creates the necessary data structures in memory so the program can call functions in `libc.so`.

**6. Potential Issues and Errors:**

Think about common mistakes developers might make when working with ptys:

* **Forgetting to close file descriptors:**  Leads to resource leaks.
* **Incorrect terminal settings:**  Can cause unexpected behavior in terminal applications.
* **Race conditions (in more complex pty usage):**  Especially when multiple processes are interacting with the same pty.
* **Permissions issues:** Incorrect permissions on `/dev/ptmx` or `/dev/pts/*`.

**7. Frida Hooking:**

Demonstrate how to use Frida to intercept calls to functions like `openpty`. This involves finding the function address in memory and replacing it with a custom JavaScript function.

**8. Logical Inferences and Assumptions:**

Where reasoning is involved, state the assumptions. For example, when explaining the implementation of `openpty`, it's assumed it interacts with a kernel driver.

**9. Structure and Language:**

Organize the information clearly with headings and bullet points. Use precise technical language but also provide explanations for less technical concepts. Since the request is in Chinese, ensure the entire response is in Chinese.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus too much on the specifics of the "bug_28979140" test.
* **Correction:**  Broaden the analysis to cover all aspects requested, including general pty functionality, libc implementation, and Android context.

* **Initial thought:**  Overcomplicate the dynamic linking explanation for this simple test.
* **Correction:**  Keep the dynamic linking explanation concise and relevant to the fact that the tested functions reside in `libc.so`.

* **Initial thought:**  Not enough focus on user errors.
* **Correction:**  Add a dedicated section on common mistakes when using pty-related functions.

By following this structured thought process, we can systematically analyze the code and generate a comprehensive and informative response to the user's request.
这个文件 `bionic/tests/pty_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用于测试与伪终端 (pseudo-terminal, pty) 相关的 API。Bionic 是 Android 的 C 库，提供了诸如 `openpty`、`forkpty` 等 POSIX 标准的 pty 操作函数。

**它的功能：**

该文件的主要功能是验证 Bionic 库中 pty 相关函数的正确性和稳定性。它包含多个独立的测试用例 (使用 Google Test 框架)，每个测试用例针对 pty 功能的不同方面进行测试：

1. **`TEST(pty, openpty)`:**  测试 `openpty` 函数，该函数用于打开一对主/从伪终端。测试内容包括：
    *   成功打开主/从伪终端，并返回有效的文件描述符。
    *   主/从伪终端的文件描述符不同。
    *   可以通过 `ttyname_r` 获取从伪终端的名称，并且与 `openpty` 返回的名称一致。
    *   可以使用 `ioctl` 和 `TIOCGWINSZ` 获取和设置终端窗口大小。

2. **`TEST(pty, forkpty)`:** 测试 `forkpty` 函数，该函数是 `fork` 和 `openpty` 的组合，用于创建一个新的进程并在新的进程中打开一个伪终端。测试内容包括：
    *   成功创建子进程。
    *   子进程的会话 ID (session ID) 与父进程不同，这符合 `forkpty` 的行为，即子进程会成为一个新的会话的领导者。

3. **`TEST(pty, bug_28979140)`:**  这是一个回归测试，用于验证一个特定的内核 bug 是否已修复。这个 bug 涉及到在多核处理器上，通过原始 pty (raw pty) 传递数据时可能出现的内存屏障问题，导致读取线程可能看不到写入线程写入的数据。测试内容包括：
    *   仅在多核处理器上运行此测试 (通过检查 CPU 核心数)。
    *   创建一个主伪终端和一个从伪终端，并将从伪终端设置为原始模式 (raw mode)。
    *   创建两个线程，分别绑定到不同的 CPU 核心上：一个线程向主伪终端写入连续的数字，另一个线程从从伪终端读取数据并验证数据的连续性。
    *   通过大量的数据传输来增加触发 bug 的概率。

**与 Android 功能的关系及举例：**

pty 功能在 Android 系统中扮演着重要的角色，尤其是在以下方面：

*   **终端模拟器 (Terminal Emulators):**  Android 上的终端模拟器应用 (例如 Termux) 使用 pty 来模拟真实的终端环境。当你在终端模拟器中运行 shell 命令时，终端模拟器会创建一个 pty 对，并将用户的输入发送到主伪终端，shell 的输出则从从伪终端读取并显示给用户。
*   **`adb shell`:**  当你使用 `adb shell` 命令连接到 Android 设备时，`adb` 会在设备上创建一个 pty 对，并将你的 shell 会话连接到该 pty。这使得你可以在你的电脑上像操作本地终端一样操作 Android 设备的 shell。
*   **SSH 服务:**  如果 Android 设备上运行了 SSH 服务，那么当用户通过 SSH 连接到设备时，SSH 服务也会创建一个 pty 对来为用户的 shell 会话提供终端环境。
*   **进程间通信:**  在某些场景下，开发者可能会使用 pty 作为进程间通信的一种方式，特别是在需要模拟终端交互的情况下。

**举例说明：**

假设你正在开发一个 Android 应用，该应用需要执行一个外部命令，并实时获取命令的输出，就像在终端中运行一样。你可以使用 `openpty` 创建一个 pty 对，将子进程的标准输入/输出/错误重定向到 pty 的从端，然后从 pty 的主端读取子进程的输出。

```c++
#include <pty.h>
#include <unistd.h>
#include <sys/wait.h>
#include <iostream>

int main() {
    int master_fd, slave_fd;
    char slave_name[256];

    pid_t pid = forkpty(&master_fd, &slave_fd, slave_name, nullptr, nullptr);
    if (pid == -1) {
        perror("forkpty");
        return 1;
    }

    if (pid == 0) {
        // 子进程
        close(master_fd); // 关闭主端

        // 将标准输入/输出/错误重定向到从伪终端
        dup2(slave_fd, STDIN_FILENO);
        dup2(slave_fd, STDOUT_FILENO);
        dup2(slave_fd, STDERR_FILENO);
        close(slave_fd);

        // 执行外部命令
        execlp("ls", "ls", "-l", nullptr);
        perror("execlp"); // 如果 exec 失败
        _exit(1);
    } else {
        // 父进程
        close(slave_fd); // 关闭从端

        char buffer[1024];
        ssize_t bytes_read;
        while ((bytes_read = read(master_fd, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_read] = '\0';
            std::cout << "子进程输出: " << buffer;
        }

        close(master_fd);
        wait(nullptr); // 等待子进程结束
    }

    return 0;
}
```

**详细解释每一个 libc 函数的功能是如何实现的：**

这些 pty 相关的 libc 函数的实现通常会涉及到与 Linux 内核的交互。

*   **`openpty(int *amaster, int *aslave, char *name, const struct termios *termp, const struct winsize *winp)`:**
    1. 在内部，它会打开 `/dev/ptmx` 设备文件。`/dev/ptmx` 是一个字符设备，用于创建新的主伪终端。
    2. 当打开 `/dev/ptmx` 成功后，内核会创建一个新的主伪终端和一个关联的从伪终端。
    3. 内核会返回主伪终端的文件描述符给 `amaster`。
    4. 使用 `ptsname(3)` 或类似的机制生成从伪终端的名称 (通常在 `/dev/pts/` 目录下)。
    5. 打开生成的从伪终端设备文件，并将文件描述符返回给 `aslave`。
    6. 如果 `name` 不为空，则将从伪终端的名称复制到 `name` 缓冲区。
    7. 如果 `termp` 不为空，则使用 `tcsetattr(3)` 设置从伪终端的终端属性。
    8. 如果 `winp` 不为空，则使用 `ioctl(2)` 和 `TIOCSWINSZ` 设置从伪终端的窗口大小。

*   **`forkpty(int *amaster, char *name, const struct termios *termp, const struct winsize *winp)`:**
    1. 内部首先调用 `openpty(amaster, ...)` 来创建一个新的 pty 对。
    2. 然后调用 `fork(2)` 创建一个子进程。
    3. 在子进程中：
        *   调用 `setsid(2)` 创建一个新的会话，使子进程成为该会话的领导者。这对于 pty 的正确工作至关重要。
        *   如果需要，调用 `ioctl(aslave, TIOCSCTTY, 1)` 将从伪终端设置为子进程的控制终端。
        *   关闭主伪终端的文件描述符。
        *   将从伪终端的文件描述符复制到标准输入、标准输出和标准错误的文件描述符 (通常使用 `dup2(2)`)。
        *   关闭原始的从伪终端的文件描述符。
    4. 在父进程中：
        *   关闭从伪终端的文件描述符。

*   **`ttyname_r(int fd, char *buf, size_t buflen)`:**
    1. 这个函数尝试找到与文件描述符 `fd` 关联的终端设备文件的路径名。
    2. 它通常会检查 `/dev/pts/` 目录下的文件，并根据文件描述符的设备和 inode 号来匹配。
    3. 更底层的实现可能涉及到 `ioctl(fd, TIOCGNAME, buf)`，但这在不同的系统上可能有差异。`ttyname_r` 是线程安全的版本。

*   **`ioctl(int fd, unsigned long request, ...)`:**
    1. `ioctl` 是一个通用的设备控制系统调用。它的具体实现取决于设备驱动程序。
    2. 当 `fd` 指向一个伪终端的从端时，例如 `TIOCGWINSZ` (获取窗口大小) 或 `TIOCSWINSZ` (设置窗口大小) 等请求会被传递给相应的 pty 驱动程序。
    3. pty 驱动程序会维护与终端相关的状态信息，例如窗口大小、终端属性等，并根据 `ioctl` 的请求进行操作。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

虽然 `pty_test.cpp` 本身是一个测试程序，它链接到 Bionic 库 (特别是 `libc.so`) 来使用 pty 相关的函数。

**`libc.so` 布局样本 (简化)：**

```
libc.so:
    .text:  // 包含 openpty, forkpty, ttyname_r, ioctl 等函数的机器码
        _ZN6__NR_openptyEv:  // openpty 的系统调用号
            ...
        _ZN6__NR_forkptyEv:  // forkpty 的系统调用号
            ...
        _ZN6__NR_ioctlEv:    // ioctl 的系统调用号
            ...
        // ... 其他函数代码 ...

    .data:  // 包含已初始化的全局变量
        // ...

    .bss:   // 包含未初始化的全局变量
        // ...

    .dynsym: // 动态符号表，包含导出的符号 (函数名，变量名等) 及其地址
        openpty
        forkpty
        ttyname_r
        ioctl
        // ... 其他符号 ...

    .dynstr: // 动态字符串表，包含符号表中用到的字符串
        openpty
        forkpty
        ttyname_r
        ioctl
        // ... 其他字符串 ...

    .plt:    // 程序链接表，用于延迟绑定
        openpty@plt:
            // 跳转到 .got.plt 中 openpty 的地址

    .got.plt: // 全局偏移量表，存储动态链接器解析后的函数地址
        openpty: 0x... // 动态链接器填充的 openpty 的实际地址
        forkpty: 0x...
        ioctl:   0x...
        // ...
```

**链接的处理过程：**

1. **编译时链接：** 当 `pty_test.cpp` 被编译成可执行文件时，编译器会找到程序中调用的 `openpty`、`forkpty` 等函数。由于这些函数位于 `libc.so` 中，链接器 (例如 `lld`) 会在生成可执行文件时记录这些外部符号的引用。

2. **可执行文件结构：** 生成的可执行文件会包含一个动态链接信息段，指明它依赖于哪些共享库 (例如 `libc.so`) 以及需要解析哪些符号。

3. **运行时链接：** 当可执行文件被加载到内存中执行时，Android 的动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载程序依赖的共享库。
    *   动态链接器会解析可执行文件的动态链接信息，找到需要加载的 `libc.so`。
    *   动态链接器会将 `libc.so` 加载到内存中的某个地址空间。
    *   然后，动态链接器会遍历可执行文件中引用的外部符号 (例如 `openpty`)，并在 `libc.so` 的 `.dynsym` 表中查找这些符号。
    *   一旦找到符号，动态链接器会将该符号在 `libc.so` 中的实际地址填充到可执行文件的 `.got.plt` 表中对应的条目。

4. **延迟绑定 (Lazy Binding)：** 通常，为了提高启动速度，动态链接器会采用延迟绑定技术。这意味着在程序第一次调用一个动态链接的函数时，才会进行符号解析和地址填充。
    *   最初，`.plt` 表中的条目会指向动态链接器的一些代码。
    *   当程序第一次调用 `openpty` 时，会跳转到 `openpty@plt`。
    *   `openpty@plt` 中的代码会调用动态链接器来解析 `openpty` 的地址。
    *   动态链接器找到 `openpty` 的地址后，会更新 `.got.plt` 中 `openpty` 的条目，并跳转到 `openpty` 的实际地址执行。
    *   后续对 `openpty` 的调用会直接通过 `.got.plt` 跳转到其真实地址，避免了重复的解析过程。

**如果做了逻辑推理，请给出假设输入与输出：**

在 `TEST(pty, openpty)` 中，假设输入 `winsize` 结构体的值为 `w = { 123, 456, 9999, 999 }`，则通过 `ioctl(tty, TIOCGWINSZ, &w_actual)` 读取到的 `w_actual` 结构体的值应该与 `w` 相同，即：

```
w_actual.ws_row == 123
w_actual.ws_col == 456
w_actual.ws_xpixel == 9999
w_actual.ws_ypixel == 999
```

在 `TEST(pty, forkpty)` 中，假设父进程的会话 ID 为 `sid_parent`，则子进程调用 `getsid(0)` 返回的会话 ID `sid_child` 应该与 `sid_parent` 不同。

在 `TEST(pty, bug_28979140)` 中，假设没有发生内核 bug，写入线程写入的连续数字序列 (0, 1, 2, ...) 应该能被读取线程完整且按顺序地读取出来，因此 `arg.matched` 应该始终为 `true`。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **忘记关闭文件描述符：** 在使用 `openpty` 或 `forkpty` 后，如果没有正确地关闭主伪终端和从伪终端的文件描述符，会导致资源泄漏。

    ```c++
    int master_fd, slave_fd;
    openpty(&master_fd, &slave_fd, nullptr, nullptr, nullptr);
    // ... 使用 master_fd 和 slave_fd ...
    // 忘记 close(master_fd);
    // 忘记 close(slave_fd);
    ```

2. **在子进程中错误地处理 pty：**  在使用 `forkpty` 后，子进程需要正确地将从伪终端设置为其控制终端，并将标准输入/输出/错误重定向到从伪终端。如果这些步骤处理不当，可能会导致子进程无法正确地与终端交互。

    ```c++
    pid_t pid = forkpty(&master_fd, &slave_fd, nullptr, nullptr, nullptr);
    if (pid == 0) {
        // 子进程
        close(master_fd);
        // 忘记 dup2 或者使用了错误的文件描述符
        execlp("ls", "ls", "-l", nullptr);
        _exit(1);
    }
    ```

3. **竞争条件：**  在多线程或多进程环境下操作同一个 pty 对时，如果没有适当的同步机制，可能会出现竞争条件，导致数据丢失或损坏。

4. **不正确的终端属性设置：**  如果使用 `tcsetattr` 设置终端属性时出现错误，可能会导致终端显示异常或功能不正常。例如，忘记将终端设置为原始模式 (raw mode) 就无法直接读取输入的字符。

5. **缓冲区溢出：**  在使用 `ttyname_r` 时，提供的缓冲区大小不足以容纳终端名称，可能导致缓冲区溢出。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

通常，Android Framework 或 NDK 应用不会直接调用底层的 `openpty` 或 `forkpty`。相反，它们可能会通过以下方式间接使用 pty 功能：

1. **通过 `ProcessBuilder` 或 `Runtime.exec()` 执行 shell 命令：**  当 Java 代码使用 `ProcessBuilder` 或 `Runtime.exec()` 执行 shell 命令时，Android 系统内部会创建一个新的进程，并可能使用 pty 来连接到该进程的标准输入/输出/错误。

2. **使用 `TerminalEmulator` 等组件：**  Android Framework 提供了 `android.widget.TextView` 等用于显示文本的组件，而像 `TerminalEmulator` 这样的应用则会直接使用 pty 来模拟终端。

3. **通过 SSH 或其他远程连接服务：**  当用户通过 SSH 等远程连接方式访问 Android 设备时，系统会创建 pty 对来处理远程会话。

**Frida Hook 示例：**

假设你想 hook `openpty` 函数，查看哪些应用调用了它，以及调用的参数。你可以使用 Frida 的 JavaScript API 来实现：

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libc.so");
  const openptyPtr = libc.getExportByName("openpty");

  if (openptyPtr) {
    Interceptor.attach(openptyPtr, {
      onEnter: function (args) {
        console.log("[+] openpty called");
        console.log("    * masterfd*: " + args[0]);
        console.log("    * slavefd*: " + args[1]);
        console.log("    * name: " + (args[2].isNull() ? "NULL" : Memory.readUtf8String(args[2])));
        // 可以进一步读取 termios 和 winsize 结构体的内容
      },
      onLeave: function (retval) {
        console.log("    * Returned: " + retval);
      }
    });
  } else {
    console.log("[-] openpty not found in libc.so");
  }
} else {
  console.log("[!] This script is for Android only.");
}
```

**调试步骤：**

1. **准备环境：**  确保你的 Android 设备已 root，并且安装了 Frida 服务 (`frida-server`)。
2. **运行 Frida 脚本：**  将上述 JavaScript 代码保存到一个文件中 (例如 `hook_openpty.js`)，然后在你的电脑上使用 Frida 命令行工具运行该脚本，指定要监控的 Android 进程或所有进程：
    ```bash
    frida -U -f <package_name> -l hook_openpty.js  # 监控特定应用
    frida -U --spawn <package_name> -l hook_openpty.js --no-pause # 启动并监控特定应用
    frida -U -n system_server -l hook_openpty.js # 监控 system_server 进程
    ```
3. **触发 `openpty` 调用：**  在被监控的 Android 应用或系统中执行某些操作，这些操作可能会导致调用 `openpty` 函数。例如，打开一个终端模拟器应用，或者通过 `adb shell` 连接到设备。
4. **查看 Frida 输出：**  Frida 会拦截对 `openpty` 的调用，并在你的终端上打印出相关的日志信息，包括调用的参数和返回值。

通过这种方式，你可以追踪 Android Framework 或 NDK 应用如何间接地使用底层的 pty 功能，并了解其调用时机和参数。对于更深入的调试，你可以 hook 相关的 Java 或 Native 函数，逐步追踪调用栈，最终定位到 `openpty` 的调用。

Prompt: 
```
这是目录为bionic/tests/pty_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#include <pty.h>

#include <gtest/gtest.h>

#include <pthread.h>
#include <sys/ioctl.h>

#include <atomic>

#include <android-base/file.h>

#include "utils.h"

TEST(pty, openpty) {
  int pty, tty;
  char name[32];
  struct winsize w = { 123, 456, 9999, 999 };
  ASSERT_EQ(0, openpty(&pty, &tty, name, nullptr, &w));
  ASSERT_NE(-1, pty);
  ASSERT_NE(-1, tty);
  ASSERT_NE(pty, tty);

  char tty_name[32];
  ASSERT_EQ(0, ttyname_r(tty, tty_name, sizeof(tty_name)));
  ASSERT_STREQ(tty_name, name);

  struct winsize w_actual;
  ASSERT_EQ(0, ioctl(tty, TIOCGWINSZ, &w_actual));
  ASSERT_EQ(w_actual.ws_row, w.ws_row);
  ASSERT_EQ(w_actual.ws_col, w.ws_col);
  ASSERT_EQ(w_actual.ws_xpixel, w.ws_xpixel);
  ASSERT_EQ(w_actual.ws_ypixel, w.ws_ypixel);

  close(pty);
  close(tty);
}

TEST(pty, forkpty) {
  pid_t sid = getsid(0);

  int pty;
  pid_t pid = forkpty(&pty, nullptr, nullptr, nullptr);
  ASSERT_NE(-1, pid);

  if (pid == 0) {
    // We're the child.
    ASSERT_NE(sid, getsid(0));
    _exit(0);
  }

  ASSERT_EQ(sid, getsid(0));

  AssertChildExited(pid, 0);

  close(pty);
}

struct PtyReader_28979140_Arg {
  int main_cpu_id;
  int fd;
  uint32_t data_count;
  bool finished;
  std::atomic<bool> matched;
};

static void PtyReader_28979140(PtyReader_28979140_Arg* arg) {
  arg->finished = false;
  cpu_set_t cpus;
  ASSERT_EQ(0, sched_getaffinity(0, sizeof(cpu_set_t), &cpus));
  CPU_CLR(arg->main_cpu_id, &cpus);
  ASSERT_EQ(0, sched_setaffinity(0, sizeof(cpu_set_t), &cpus));

  uint32_t counter = 0;
  while (counter <= arg->data_count) {
    char buf[4096];  // Use big buffer to read to hit the bug more easily.
    size_t to_read = std::min(sizeof(buf), (arg->data_count + 1 - counter) * sizeof(uint32_t));
    ASSERT_TRUE(android::base::ReadFully(arg->fd, buf, to_read));
    size_t num_of_value = to_read / sizeof(uint32_t);
    uint32_t* p = reinterpret_cast<uint32_t*>(buf);
    while (num_of_value-- > 0) {
      if (*p++ != counter++) {
        arg->matched = false;
      }
    }
  }
  close(arg->fd);
  arg->finished = true;
}

TEST(pty, bug_28979140) {
  // This test is to test a kernel bug, which uses a lock free ring-buffer to
  // pass data through a raw pty, but missing necessary memory barriers.
  cpu_set_t cpus;
  ASSERT_EQ(0, sched_getaffinity(0, sizeof(cpu_set_t), &cpus));
  if (CPU_COUNT(&cpus) < 2) {
    GTEST_SKIP() << "This bug only happens on multiprocessors";
  }
  constexpr uint32_t TEST_DATA_COUNT = 2000000;

  // 1. Open raw pty.
  int pty;
  int tty;
  ASSERT_EQ(0, openpty(&pty, &tty, nullptr, nullptr, nullptr));
  termios tattr;
  ASSERT_EQ(0, tcgetattr(tty, &tattr));
  cfmakeraw(&tattr);
  ASSERT_EQ(0, tcsetattr(tty, TCSADRAIN, &tattr));

  // 2. Make two threads running on different cpus:
  // pty thread uses first available cpu, and tty thread uses other cpus.
  PtyReader_28979140_Arg arg;
  arg.main_cpu_id = -1;
  for (int i = 0; i < CPU_SETSIZE; i++) {
    if (CPU_ISSET(i, &cpus)) {
      arg.main_cpu_id = i;
      break;
    }
  }
  ASSERT_GE(arg.main_cpu_id, 0);

  // 3. Create thread for tty reader.
  pthread_t thread;
  arg.fd = tty;
  arg.data_count = TEST_DATA_COUNT;
  arg.matched = true;
  ASSERT_EQ(0, pthread_create(&thread, nullptr,
                              reinterpret_cast<void*(*)(void*)>(PtyReader_28979140),
                              &arg));

  CPU_ZERO(&cpus);
  CPU_SET(arg.main_cpu_id, &cpus);
  ASSERT_EQ(0, sched_setaffinity(0, sizeof(cpu_set_t), &cpus));

  // 4. Send data to tty reader.
  // Send a bunch of data at a time, so it is easier to catch the bug that some data isn't seen
  // by the reader thread on another cpu.
  uint32_t counter_buf[100];
  uint32_t counter = 0;
  while (counter <= TEST_DATA_COUNT) {
    for (size_t i = 0; i < sizeof(counter_buf) / sizeof(counter_buf[0]); ++i) {
      counter_buf[i] = counter++;
    }
    ASSERT_TRUE(android::base::WriteFully(pty, &counter_buf, sizeof(counter_buf)));
    ASSERT_TRUE(arg.matched) << "failed at count = " << counter;
  }
  ASSERT_EQ(0, pthread_join(thread, nullptr));
  ASSERT_TRUE(arg.finished);
  ASSERT_TRUE(arg.matched);
  close(pty);
}

"""

```