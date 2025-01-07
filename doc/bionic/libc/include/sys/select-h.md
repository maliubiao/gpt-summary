Response:
Let's break down the thought process for analyzing this `select.h` header file.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the `select.h` file, including its purpose, relationship to Android, implementation details, dynamic linking aspects, common errors, and how it's used within the Android framework and NDK. The request also specifically asks for Frida hooking examples.

**2. Initial Overview & Core Functionality:**

The first step is to read the header file itself. The comments immediately highlight that this file is related to the `select` and `pselect` system calls. The primary purpose is clearly stated: waiting for events on a set of file descriptors. The comments also strongly recommend using `poll.h` instead for new code due to scalability limitations of `fd_set`. This immediately sets the context and highlights a crucial piece of information.

**3. Deconstructing the Header File (Top-Down):**

* **Copyright and Redistribution:**  Standard boilerplate, less relevant to the functional analysis.
* **File Description (`@file` and `@brief`):**  Reinforces the purpose of the file.
* **Include Directives:** `<sys/cdefs.h>`, `<sys/types.h>`, `<linux/time.h>`, `<signal.h>`  These tell us what other system headers this file depends on. We can infer that it deals with basic system definitions, time management, and signals.
* **`__BEGIN_DECLS` and `__END_DECLS`:**  Standard C idiom for ensuring C linkage when included in C++ code.
* **`typedef unsigned long fd_mask;`:**  This defines the basic unit for representing the file descriptor sets. The name `fd_mask` suggests it's used as a bitmask.
* **`FD_SETSIZE` and `NFDBITS`:** These are *critical*. They define the hard limit of 1024 file descriptors that `fd_set` can handle. The comment emphasizes the limitation and the recommendation to use `poll.h`. `NFDBITS` tells us how many bits are in `fd_mask`.
* **`typedef struct { fd_mask fds_bits[FD_SETSIZE/NFDBITS]; } fd_set;`:** This is the core data structure. It's an array of `fd_mask` values. The size calculation confirms the bitmask approach: each `fd_mask` can hold `NFDBITS`, and there are enough `fd_mask` elements to cover `FD_SETSIZE`.
* **Macros (`__FDELT`, `__FDMASK`, `__FDS_BITS`):**  These are helper macros for manipulating the `fd_set`.
    * `__FDELT(fd)`: Calculates the index into the `fds_bits` array for a given file descriptor `fd`. This is integer division.
    * `__FDMASK(fd)`: Creates a bitmask with the bit corresponding to `fd` set. This uses bit shifting.
    * `__FDS_BITS(type, set)`:  A type-safe cast to access the `fds_bits` member.
* **Checked Functions (`__FD_CLR_chk`, `__FD_SET_chk`, `__FD_ISSET_chk`):**  These likely perform bounds checking to ensure the file descriptor is within the valid range. The `size_t` argument hints at this.
* **Unchecked Macros (`__FD_CLR`, `__FD_SET`, `__FD_ISSET`):**  These are the core bit manipulation operations *without* bounds checking. The comments clearly state they are for users who allocate their own `fd_set`.
* **`FD_ZERO(set)`:** Uses `memset` to clear all bits in the `fd_set`. Again, the comment points out the limitation to 1024 FDs.
* **`FD_CLR`, `FD_SET`, `FD_ISSET`:** These are the user-facing macros that *do* include bounds checking by calling the `_chk` versions. The comments reiterate the 1024 FD limit and the preference for `poll.h`.
* **Function Declarations (`select`, `pselect`, `pselect64`):** These are the actual system call wrappers. The comments for each point to the relevant man pages and *strongly* recommend using `poll` or `ppoll` instead. The `pselect64` has an API level guard.

**4. Answering the Specific Questions:**

Now, armed with a good understanding of the header file, we can address each part of the request:

* **Functionality:** List the defined types, macros, and functions and their basic purpose (manipulating file descriptor sets and waiting for events).
* **Relationship to Android:**  Explain that this is part of Bionic, Android's C library. Give examples of where `select` might be used (network programming, UI event loops, etc.), although these are less common now due to the preference for `poll`.
* **Libc Function Implementation:** Explain how the macros work by manipulating bits in the `fd_set` structure. Focus on the bitwise AND, OR, and NOT operations.
* **Dynamic Linker:** Acknowledge that *this header file itself* doesn't directly involve the dynamic linker. However, the *implementation* of the `select` and `pselect` system calls will involve system calls that the dynamic linker helps resolve. Provide a simple SO layout and explain the linking process at a high level (symbol lookup, relocation).
* **Logical Inference:** Provide a simple example of setting, checking, and clearing a bit in the `fd_set`.
* **Common Errors:** Highlight the 1024 FD limit as the primary source of errors and the risk of using unchecked macros incorrectly.
* **Android Framework/NDK:** Explain the path from Android Framework (e.g., Java `SocketChannel`) to NDK (JNI calls) and finally to the Bionic `select` function. Mention the system call interface.
* **Frida Hook Example:** Provide a basic Frida script to hook the `select` function and log its arguments.

**5. Refinement and Clarity:**

After drafting the initial answers, review them for clarity, accuracy, and completeness. Ensure the language is accessible and that technical terms are explained where necessary. Emphasize the key takeaways, such as the limitations of `select` and the preference for `poll`.

**Self-Correction/Refinement during the process:**

* **Initial thought:** Perhaps focus heavily on the kernel implementation of `select`. **Correction:** The request is about the header file and its associated libc functions. While the kernel is involved, the focus should be on the Bionic aspects.
* **Initial thought:**  Provide a very complex dynamic linking example. **Correction:** Keep the dynamic linking explanation relatively simple, as the header itself doesn't contain dynamic linking logic. Focus on the concept.
* **Initial thought:**  Only mention positive use cases of `select`. **Correction:**  Emphasize the *disadvantages* and why `poll` is preferred, as this is a key message from the header file itself.
* **Initial thought:** Provide very advanced Frida hooking examples. **Correction:** Start with a basic example that demonstrates the core concept of hooking the function and logging arguments.

By following this structured approach and being willing to refine the answers along the way, we can generate a comprehensive and accurate response to the request.
好的，让我们详细分析一下 `bionic/libc/include/sys/select.handroid` 这个头文件。

**功能列举:**

这个头文件定义了与 **`select` 和 `pselect` 系统调用**相关的接口和数据结构。其主要功能是提供一种机制，允许程序**同时监控多个文件描述符 (file descriptor, fd)** 的状态，以便在其中一个或多个文件描述符准备好进行读、写或发生异常时得到通知。

具体来说，它定义了：

1. **数据类型:**
   - `fd_mask`:  一个无符号长整型，用于表示文件描述符集合中的一个位。
   - `fd_set`: 一个结构体，用于表示一组文件描述符。它内部使用一个 `fd_mask` 数组来存储文件描述符的状态。这个结构体的大小是固定的，限制了能监控的文件描述符的最大数量。

2. **常量:**
   - `FD_SETSIZE`:  定义了 `fd_set` 结构体能够表示的最大文件描述符数量，固定为 1024。这是一个重要的限制。
   - `NFDBITS`: 定义了 `fd_mask` 类型包含的位数。

3. **宏:**
   - `__FDELT(fd)`:  计算给定文件描述符 `fd` 在 `fd_set` 结构体的 `fds_bits` 数组中的索引。
   - `__FDMASK(fd)`: 创建一个位掩码，其中与给定文件描述符 `fd` 对应的位被设置为 1。
   - `__FDS_BITS(type, set)`:  提供了一种类型安全的方式来访问 `fd_set` 结构体的 `fds_bits` 成员。
   - `__FD_CLR(fd, set)`: 清除 `fd_set` 中指定文件描述符 `fd` 对应的位（不进行边界检查）。
   - `__FD_SET(fd, set)`: 设置 `fd_set` 中指定文件描述符 `fd` 对应的位（不进行边界检查）。
   - `__FD_ISSET(fd, set)`: 检查 `fd_set` 中指定文件描述符 `fd` 对应的位是否被设置（不进行边界检查）。
   - `FD_ZERO(set)`: 将 `fd_set` 中的所有位清零，相当于初始化一个空的描述符集合。
   - `FD_CLR(fd, set)`: 清除 `fd_set` 中指定文件描述符 `fd` 对应的位（进行边界检查）。
   - `FD_SET(fd, set)`: 设置 `fd_set` 中指定文件描述符 `fd` 对应的位（进行边界检查）。
   - `FD_ISSET(fd, set)`: 检查 `fd_set` 中指定文件描述符 `fd` 对应的位是否被设置（进行边界检查）。

4. **函数声明:**
   - `select()`:  等待一组文件描述符变为可读、可写或发生异常。
   - `pselect()`:  与 `select()` 类似，但允许指定一个信号掩码，以便在等待期间阻塞某些信号。
   - `pselect64()`:  `pselect()` 的 64 位版本，用于处理更大的信号集（在较新的 Android 版本中引入）。

**与 Android 功能的关系及举例说明:**

这个头文件是 Android 底层 Bionic 库的一部分，因此直接关系到 Android 的核心功能。`select` 和 `pselect` 是 POSIX 标准中定义的系统调用，用于实现 I/O 多路复用。这意味着应用程序可以通过它们高效地监控多个文件描述符，而无需为每个文件描述符创建一个单独的线程或使用非阻塞 I/O 并不断轮询。

**举例说明:**

* **网络编程:** Android 应用程序经常需要处理多个网络连接。例如，一个服务器应用程序可能需要同时监听多个客户端的连接请求和数据传输。`select` 或 `pselect` 可以用来监控服务器套接字和已连接的客户端套接字，以便在有新的连接请求或数据到达时得到通知。
* **UI 事件循环:** 虽然现代 Android UI 框架通常使用更高级的机制，但在底层，某些事件循环的实现可能会使用类似 `select` 的机制来等待不同类型的事件发生（例如，用户输入、定时器事件、文件描述符上的 I/O 事件）。
* **NDK 开发:** 使用 Android NDK 开发的 native 代码可以直接调用这些函数来实现 I/O 多路复用。例如，一个用 C++ 编写的网络应用程序可以使用 `select` 或 `pselect` 来管理多个网络连接。

**libc 函数的功能实现:**

让我们详细解释一下这些 libc 函数（实际上主要是宏定义，最终会调用系统调用）的功能是如何实现的：

1. **`fd_set` 结构体的操作 (宏):**
   - **`FD_ZERO(set)`:**  使用 `memset` 将 `fd_set` 结构体占用的内存全部设置为 0。这有效地清除了所有文件描述符的标记。
   - **`FD_SET(fd, set)`:**
     - 首先，`__bos(set)` 会获取 `fd_set` 结构体的大小，用于进行边界检查。
     - `__FD_SET_chk(fd, set, __bos(set))` 会检查 `fd` 是否在有效范围内 (通常小于 `FD_SETSIZE`)。
     - 如果 `fd` 有效，`__FDELT(fd)` 计算出 `fd` 对应的 `fd_mask` 在 `fds_bits` 数组中的索引。
     - `__FDMASK(fd)` 创建一个位掩码，其中只有与 `fd` 对应的位是 1。
     - `__FDS_BITS(fd_set*, set)[__FDELT(fd)] |= __FDMASK(fd)`  使用位或操作将该位掩码设置到 `fds_bits` 数组的对应元素中，从而将 `fd` 添加到集合中。
   - **`FD_CLR(fd, set)`:**
     - 类似 `FD_SET`，会进行边界检查。
     - `__FDELT(fd)` 和 `__FDMASK(fd)` 的计算方式相同。
     - `__FDS_BITS(fd_set*, set)[__FDELT(fd)] &= ~__FDMASK(fd)` 使用位与和位非操作，将 `fds_bits` 数组对应元素中 `fd` 对应的位清零，从而将 `fd` 从集合中移除。
   - **`FD_ISSET(fd, set)`:**
     - 同样进行边界检查。
     - 计算索引和掩码。
     - `(__FDS_BITS(const fd_set*, set)[__FDELT(fd)] & __FDMASK(fd)) != 0` 使用位与操作检查 `fds_bits` 数组对应元素中 `fd` 对应的位是否为 1。如果结果不为 0，则表示 `fd` 在集合中。

2. **`select()` 和 `pselect()` 函数:**
   - 这些函数是 **系统调用** 的 Bionic 库封装。它们的实现最终会调用 Linux 内核提供的 `select` 或 `pselect` 系统调用。
   - **`select(int __max_fd_plus_one, fd_set* __read_fds, fd_set* __write_fds, fd_set* __exception_fds, struct timeval* __timeout)`:**
     - `__max_fd_plus_one`:  被监控的文件描述符的最大值加 1。内核只会检查文件描述符值小于此值的描述符。
     - `__read_fds`, `__write_fds`, `__exception_fds`:  指向 `fd_set` 结构体的指针，分别指定了需要监控可读、可写和异常条件的描述符集合。可以传入 `NULL` 表示不监控相应的条件。
     - `__timeout`:  一个指向 `timeval` 结构体的指针，指定了等待的最长时间。如果设置为 `NULL`，则无限期等待。如果 `tv_sec` 和 `tv_usec` 都为 0，则立即返回（轮询）。
     - **实现过程:**  `select` 系统调用会将调用进程置于睡眠状态，直到以下情况之一发生：
       - 监控的任何一个文件描述符准备好进行相应的操作（可读、可写或发生异常）。
       - 超时时间到达。
       - 被信号中断（如果应用程序没有忽略或屏蔽该信号）。
     - 当 `select` 返回时，它会修改传入的 `fd_set` 结构体，只保留那些准备好的文件描述符。返回值是准备好的文件描述符的总数，超时返回 0，发生错误返回 -1 并设置 `errno`。
   - **`pselect(int __max_fd_plus_one, fd_set* __read_fds, fd_set* __write_fds, fd_set* __exception_fds, const struct timespec* __timeout, const sigset_t* __mask)`:**
     - 与 `select` 类似，但使用 `timespec` 结构体表示更精确的超时时间（纳秒级）。
     - 增加了 `__mask` 参数，它是一个指向信号掩码的指针。`pselect` 允许在调用期间临时替换进程的信号掩码，并在返回时恢复原来的掩码。这可以防止在检查文件描述符状态和进入睡眠状态之间发生信号，导致竞争条件。
   - **`pselect64()`:**  与 `pselect` 功能相同，只是使用 `sigset64_t` 处理更大的信号集。

**涉及 dynamic linker 的功能:**

这个头文件本身主要是定义接口和数据结构，并不直接涉及 dynamic linker 的功能。然而，**`select` 和 `pselect` 函数的实际实现** 涉及到系统调用，而系统调用的执行会与 dynamic linker 产生间接关系。

**SO 布局样本和链接处理过程 (针对 `select` 或 `pselect` 的实现):**

假设我们有一个简单的 C 程序 `my_app`，它调用了 `select` 函数：

```c
// my_app.c
#include <stdio.h>
#include <sys/select.h>
#include <unistd.h>

int main() {
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(STDIN_FILENO, &readfds);

  struct timeval tv;
  tv.tv_sec = 5;
  tv.tv_usec = 0;

  int retval = select(STDIN_FILENO + 1, &readfds, NULL, NULL, &tv);

  if (retval == -1) {
    perror("select()");
  } else if (retval) {
    printf("Data is available now.\n");
  } else {
    printf("No data within five seconds.\n");
  }

  return 0;
}
```

编译命令： `gcc my_app.c -o my_app`

**SO 布局样本:**

运行 `my_app` 时，以下 SO（Shared Object）文件会被加载到进程的内存空间：

1. **`/system/bin/linker64` (或 `/system/bin/linker`)**:  Android 的动态链接器。
2. **`/apex/com.android.runtime/lib64/bionic/libc.so` (或其他 Bionic 库路径)**: 包含 `select` 函数实现的共享库。
3. **其他依赖的 SO 文件**

**链接处理过程:**

1. **加载程序:** 当操作系统启动 `my_app` 时，内核会加载 `my_app` 的可执行文件到内存中。
2. **动态链接器介入:**  内核会检查 `my_app` 的 ELF 头，发现它需要动态链接器。因此，内核会将控制权交给 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`)。
3. **解析依赖:** 动态链接器会解析 `my_app` 的依赖关系，发现它依赖于 `libc.so`。
4. **加载共享库:** 动态链接器会将 `libc.so` 加载到进程的内存空间中。
5. **符号解析和重定位:**
   - 在 `my_app.c` 中调用了 `select` 函数。编译器生成的目标代码中，`select` 函数的地址是一个占位符。
   - 动态链接器会在 `libc.so` 的符号表 (symbol table) 中查找 `select` 函数的符号。
   - 找到符号后，动态链接器会将 `my_app` 中 `select` 函数调用的占位符地址替换为 `libc.so` 中 `select` 函数的实际入口地址。这个过程称为 **重定位 (relocation)**。
6. **执行程序:**  动态链接完成后，内核会将控制权交还给 `my_app` 的 `main` 函数。当程序执行到 `select()` 调用时，实际上会跳转到 `libc.so` 中 `select` 函数的实现代码。
7. **系统调用:** `libc.so` 中的 `select` 函数实现最终会通过系统调用指令（例如 ARM64 上的 `svc`）陷入内核，请求内核执行 `select` 系统调用。内核会根据传入的参数监控文件描述符的状态，并在条件满足时唤醒进程。

**假设输入与输出 (针对 `select` 函数):**

**假设输入:**

* `__max_fd_plus_one`: 2 (监控文件描述符 0)
* `__read_fds`: 一个 `fd_set`，其中文件描述符 0 (标准输入) 被设置。
* `__write_fds`: `NULL`
* `__exception_fds`: `NULL`
* `__timeout`: `tv_sec = 5`, `tv_usec = 0` (等待 5 秒)

**场景 1: 用户在 5 秒内输入了数据并按下了回车键。**

* **输出:** `select` 函数返回 1。
* `__read_fds` 指向的 `fd_set` 中，文件描述符 0 仍然被设置。

**场景 2: 用户在 5 秒内没有输入任何数据。**

* **输出:** `select` 函数返回 0。
* `__read_fds` 指向的 `fd_set` 中，文件描述符 0 被清除（因为超时，没有事件发生）。

**场景 3:  在 `select` 等待期间，进程接收到一个未被屏蔽的信号。**

* **输出:** `select` 函数返回 -1。
* `errno` 被设置为 `EINTR` (Interrupted system call)。

**用户或编程常见的使用错误:**

1. **超过 `FD_SETSIZE` 限制:**  尝试监控文件描述符值大于或等于 `FD_SETSIZE` (1024) 的文件描述符。这会导致未定义的行为，因为 `fd_set` 无法表示这些描述符。**解决方法:** 对于需要监控大量文件描述符的应用，应该使用 `poll` 或 `epoll` 等更高级的 I/O 多路复用机制。
2. **错误计算 `__max_fd_plus_one`:**  `__max_fd_plus_one` 必须设置为被监控的最大文件描述符值加 1。如果设置不正确，`select` 可能不会监控到某些文件描述符上的事件。
3. **忘记初始化 `fd_set`:**  在使用 `FD_SET` 之前，必须使用 `FD_ZERO` 初始化 `fd_set` 结构体。否则，`fd_set` 中的内容是未知的，可能导致错误的结果。
4. **混淆输入和输出 `fd_set`:**  `select` 会修改传入的 `fd_set` 结构体，只保留那些准备好的文件描述符。如果后续代码没有考虑到这一点，可能会导致逻辑错误。
5. **没有处理 `select` 的返回值:**  应该始终检查 `select` 的返回值，以确定是超时、有文件描述符准备好，还是发生了错误（例如被信号中断）。
6. **在多线程环境中使用 `fd_set` 而没有适当的同步:**  多个线程同时访问和修改同一个 `fd_set` 结构体可能导致数据竞争。

**Android Framework 或 NDK 如何到达这里，给出 Frida hook 示例调试这些步骤。**

**Android Framework 到 Bionic 的路径:**

1. **Android Framework (Java 代码):**  Android Framework 中的许多 I/O 操作最终会委托给 native 代码执行。例如，Java 中的 `Socket` 和 `ServerSocket` 类底层的实现会调用 NDK 提供的 socket 相关函数。
2. **NDK (Native 代码):**  使用 NDK 开发的 C/C++ 代码可以直接调用 Bionic 库提供的系统调用封装函数，包括 `select` 和 `pselect`。例如，一个用 C++ 编写的网络库可能会使用 `select` 来管理多个 socket 连接。
3. **JNI (Java Native Interface):**  Java 代码通过 JNI 调用 native 代码。当 Java 代码需要执行底层的 I/O 操作时，会调用相应的 native 方法。
4. **Bionic 库:**  NDK 提供的头文件（例如 `sys/select.h`) 对应于 Bionic 库中的实现。当 native 代码调用 `select` 函数时，实际上会调用 Bionic 库中 `libc.so` 提供的 `select` 函数的实现。
5. **系统调用:**  Bionic 库中的 `select` 函数最终会通过系统调用指令陷入 Linux 内核，请求内核执行实际的 `select` 操作。

**Frida Hook 示例:**

以下是一个使用 Frida hook `select` 函数的示例：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    device = frida.get_usb_device(timeout=10)
    pid = int(sys.argv[1]) if len(sys.argv) > 1 else None
    session = device.attach(pid) if pid else device.attach('com.example.myapp') # 替换为你的应用包名或 PID

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "select"), {
        onEnter: function(args) {
            console.log("[*] select() called");
            console.log("    max_fd_plus_one:", args[0].toInt32());
            console.log("    read_fds:", args[1]);
            console.log("    write_fds:", args[2]);
            console.log("    except_fds:", args[3]);
            console.log("    timeout:", args[4]);

            // 你可以在这里检查 fd_set 的内容，但这需要更复杂的处理
        },
        onLeave: function(retval) {
            console.log("[*] select() returned:", retval.toInt32());
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    sys.stdin.read()

except frida.ProcessNotFoundError:
    print("进程未找到，请提供正确的包名或 PID")
except Exception as e:
    print(e)
```

**使用步骤:**

1. **安装 Frida:** 确保你的电脑上已经安装了 Frida 和 Frida CLI 工具。
2. **启动目标 Android 应用:** 运行你想要 hook 的 Android 应用。
3. **运行 Frida 脚本:**
   - **通过包名:** `python your_frida_script.py com.example.myapp` (将 `com.example.myapp` 替换为你的应用包名)
   - **通过 PID:**
     - 使用 `adb shell ps | grep your_app_process_name` 找到应用的 PID。
     - 运行脚本: `python your_frida_script.py <PID>` (将 `<PID>` 替换为实际的 PID)

**脚本解释:**

* `frida.get_usb_device()`: 连接到 USB 连接的 Android 设备。
* `device.attach(pid)` 或 `device.attach('com.example.myapp')`:  附加到目标进程。
* `Module.findExportByName("libc.so", "select")`:  在 `libc.so` 中查找 `select` 函数的地址。
* `Interceptor.attach(...)`:  拦截 `select` 函数的调用。
* `onEnter`:  在 `select` 函数执行之前调用。`args` 数组包含了传递给 `select` 函数的参数。
* `onLeave`: 在 `select` 函数执行之后调用。`retval` 包含了 `select` 函数的返回值。
* `console.log(...)`:  在 Frida 控制台中打印信息。

当你运行这个 Frida 脚本并操作你的 Android 应用时，如果应用内部调用了 `select` 函数，你将会在 Frida 控制台中看到相关的日志信息，包括传递给 `select` 函数的参数和返回值。你可以根据这些信息来调试 `select` 函数的调用过程。

这个分析应该涵盖了你提出的所有问题，希望对你有所帮助！

Prompt: 
```
这是目录为bionic/libc/include/sys/select.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * @file sys/select.h
 * @brief Wait for events on a set of file descriptors.
 * New code should prefer the different interface specified in <poll.h> instead,
 * because it scales better and easily avoids the limits on `fd_set` size.
 */

#include <sys/cdefs.h>
#include <sys/types.h>

#include <linux/time.h>
#include <signal.h>

__BEGIN_DECLS

typedef unsigned long fd_mask;

/**
 * The limit on the largest fd that can be used with type `fd_set`.
 * You can allocate your own memory,
 * but new code should prefer the different interface specified in <poll.h> instead,
 * because it scales better and easily avoids the limits on `fd_set` size.
 */
#define FD_SETSIZE 1024
#define NFDBITS (8 * sizeof(fd_mask))

/**
 * The type of a file descriptor set. Limited to 1024 fds.
 * The underlying system calls do not have this limit,
 * and callers can allocate their own sets with calloc().
 *
 * New code should prefer the different interface specified in <poll.h> instead,
 * because it scales better and easily avoids the limits on `fd_set` size.
 */
typedef struct {
  fd_mask fds_bits[FD_SETSIZE/NFDBITS];
} fd_set;

#define __FDELT(fd) ((fd) / NFDBITS)
#define __FDMASK(fd) (1UL << ((fd) % NFDBITS))
#define __FDS_BITS(type, set) (__BIONIC_CAST(static_cast, type, set)->fds_bits)

void __FD_CLR_chk(int, fd_set* _Nonnull , size_t);
void __FD_SET_chk(int, fd_set* _Nonnull, size_t);
int __FD_ISSET_chk(int, const fd_set* _Nonnull, size_t);

/**
 * FD_CLR() with no bounds checking for users that allocated their own set.
 * New code should prefer <poll.h> instead.
 */
#define __FD_CLR(fd, set) (__FDS_BITS(fd_set*, set)[__FDELT(fd)] &= ~__FDMASK(fd))

/**
 * FD_SET() with no bounds checking for users that allocated their own set.
 * New code should prefer <poll.h> instead.
 */
#define __FD_SET(fd, set) (__FDS_BITS(fd_set*, set)[__FDELT(fd)] |= __FDMASK(fd))

/**
 * FD_ISSET() with no bounds checking for users that allocated their own set.
 * New code should prefer <poll.h> instead.
 */
#define __FD_ISSET(fd, set) ((__FDS_BITS(const fd_set*, set)[__FDELT(fd)] & __FDMASK(fd)) != 0)

/**
 * Removes all 1024 fds from the given set.
 * Limited to fds under 1024.
 * New code should prefer <poll.h> instead for this reason,
 * rather than using memset() directly.
 */
#define FD_ZERO(set) __builtin_memset(set, 0, sizeof(*__BIONIC_CAST(static_cast, const fd_set*, set)))

/**
 * Removes `fd` from the given set.
 * Limited to fds under 1024.
 * New code should prefer <poll.h> instead for this reason,
 * rather than using __FD_CLR().
 */
#define FD_CLR(fd, set) __FD_CLR_chk(fd, set, __bos(set))

/**
 * Adds `fd` to the given set.
 * Limited to fds under 1024.
 * New code should prefer <poll.h> instead for this reason,
 * rather than using __FD_SET().
 */
#define FD_SET(fd, set) __FD_SET_chk(fd, set, __bos(set))

/**
 * Tests whether `fd` is in the given set.
 * Limited to fds under 1024.
 * New code should prefer <poll.h> instead for this reason,
 * rather than using __FD_ISSET().
 */
#define FD_ISSET(fd, set) __FD_ISSET_chk(fd, set, __bos(set))

/**
 * [select(2)](https://man7.org/linux/man-pages/man2/select.2.html) waits on a
 * set of file descriptors.
 *
 * New code should prefer poll() from <poll.h> instead,
 * because it scales better and easily avoids the limits on `fd_set` size.
 *
 * Returns the number of ready file descriptors on success, 0 for timeout,
 * and returns -1 and sets `errno` on failure.
 */
int select(int __max_fd_plus_one, fd_set* _Nullable __read_fds, fd_set* _Nullable __write_fds, fd_set* _Nullable __exception_fds, struct timeval* _Nullable __timeout);

/**
 * [pselect(2)](https://man7.org/linux/man-pages/man2/select.2.html) waits on a
 * set of file descriptors.
 *
 * New code should prefer ppoll() from <poll.h> instead,
 * because it scales better and easily avoids the limits on `fd_set` size.
 *
 * Returns the number of ready file descriptors on success, 0 for timeout,
 * and returns -1 and sets `errno` on failure.
 */
int pselect(int __max_fd_plus_one, fd_set* _Nullable __read_fds, fd_set* _Nullable __write_fds, fd_set* _Nullable __exception_fds, const struct timespec* _Nullable __timeout, const sigset_t* _Nullable __mask);

/**
 * [pselect64(2)](https://man7.org/linux/man-pages/man2/select.2.html) waits on a
 * set of file descriptors.
 *
 * New code should prefer ppoll64() from <poll.h> instead,
 * because it scales better and easily avoids the limits on `fd_set` size.
 *
 * Returns the number of ready file descriptors on success, 0 for timeout,
 * and returns -1 and sets `errno` on failure.
 *
 * Available since API level 28.
 */
#if __BIONIC_AVAILABILITY_GUARD(28)
int pselect64(int __max_fd_plus_one, fd_set* _Nullable __read_fds, fd_set* _Nullable __write_fds, fd_set* _Nullable __exception_fds, const struct timespec* _Nullable __timeout, const sigset64_t* _Nullable __mask) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

__END_DECLS

"""

```