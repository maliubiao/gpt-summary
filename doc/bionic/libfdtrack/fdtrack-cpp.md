Response:
Let's break down the thought process for answering the request about `bionic/libfdtrack/fdtrack.cpp`.

**1. Understanding the Goal:**

The core request is to analyze the provided C++ code for `fdtrack.cpp` and explain its functionality, its relation to Android, and delve into the technical details of its implementation. The request also asks for examples of usage errors, debugging techniques (Frida), and how Android frameworks might interact with this code.

**2. Initial Code Scan & High-Level Understanding:**

My first step is to quickly skim the code to get a general idea of what it's doing. I notice keywords and structures like:

* `#include` directives indicating dependencies (e.g., `<inttypes.h>`, `<mutex>`, `<vector>`, `<android/fdsan.h>`, `<bionic/fdtrack.h>`, `<unwindstack/...>`). This immediately suggests the code is involved in tracking file descriptors and their associated call stacks.
* `FdEntry` struct holding a mutex and a vector of `unwindstack::FrameData`. This reinforces the idea of tracking file descriptors and their execution context.
* `fdtrack_dump`, `fdtrack_dump_fatal`, `fdtrack_iterate`. These are likely the primary public interfaces of the library.
* `fd_hook`. This looks like a callback function, potentially triggered by file descriptor events.
* `kFdTableSize`, `kStackDepth`. These constants hint at the limitations of the tracking mechanism (number of FDs and stack frame depth).
* `__attribute__((constructor))`, `__attribute__((destructor))`. These indicate functions that run at library load and unload times.
* `android_fdtrack_*` functions. These clearly point to an underlying Android system mechanism for file descriptor tracking.

**3. Identifying Key Functionality:**

Based on the initial scan, I can deduce the core functionalities:

* **Tracking File Descriptor Creation:** The `fd_hook` with `ANDROID_FDTRACK_EVENT_TYPE_CREATE` suggests recording the stack trace when a file descriptor is opened.
* **Tracking File Descriptor Closure:** The `fd_hook` with `ANDROID_FDTRACK_EVENT_TYPE_CLOSE` suggests clearing the stored stack trace when a file descriptor is closed.
* **Dumping Information:** `fdtrack_dump` and `fdtrack_dump_fatal` are clearly responsible for outputting information about tracked file descriptors, with the `_fatal` version also triggering an abort.
* **Iterating Through Tracked FDs:** `fdtrack_iterate` provides a way to process the information associated with each tracked file descriptor.

**4. Analyzing Implementation Details:**

Now, I need to dive deeper into how these functionalities are implemented.

* **`FdEntry` and `stack_traces`:**  The `stack_traces` array acts as a central repository, with each element corresponding to a file descriptor (within the `kFdTableSize` limit). The `FdEntry` struct ensures thread-safe access to the backtrace information.
* **`fd_hook`:** This function is the core of the event-driven tracking. It uses the `unwindstack` library to capture the call stack at FD creation and clears the backtrace at closure.
* **`Unwinder()`:** The use of `unwindstack::AndroidLocalUnwinder` is crucial for obtaining the call stack. The constructor arguments (`{"libfdtrack.so", "libart.so"}`) indicate frames from these libraries are skipped.
* **`fdtrack_iterate`:**  This function iterates through the `stack_traces` array, acquiring a lock for each valid entry before invoking the provided callback. The locking mechanism prevents race conditions when accessing the backtrace.
* **`fdtrack_dump_impl`:** This function orchestrates the dumping process, iterating through the tracked FDs and logging their information, including the backtrace. The `fatal` version attempts to identify the most common stack trace and includes it in the abort message.
* **Constructor and Destructor (`ctor`, `dtor`):**  These handle the initialization and cleanup. The constructor installs the `fd_hook` and sets up a signal handler to trigger the dump functions. The destructor uninstalls the hook.

**5. Connecting to Android Functionality:**

The code clearly interacts with Android's file descriptor management system through the `android/fdtrack.h` header and the `android_fdtrack_*` functions. The `android_fdsan_get_owner_tag` function indicates integration with Android's File Descriptor Sanitizer (fdsan). The signal handler for `BIONIC_SIGNAL_FDTRACK` is another explicit link to the Android environment.

**6. Considering Edge Cases and Potential Errors:**

* **FD Limit:** The `kFdTableSize` limit is a potential source of information loss if more than 4096 FDs are opened.
* **Locking:**  The `try_lock` in `fdtrack_iterate` acknowledges the possibility of contention, logging a warning if a lock cannot be acquired.
* **Unwinding Failures:** The code doesn't explicitly handle failures from the `Unwinder().Unwind()` call, although the backtrace will simply be empty in that case.
* **User Errors:** Incorrectly managing file descriptors (leaks, double closes) are the primary issues this library aims to detect.

**7. Developing Examples:**

Based on the understanding of the code, I can create examples for:

* **SO Layout:** A simple illustration of how `libfdtrack.so` might be positioned in memory along with other libraries.
* **Linking Process:** A high-level overview of how the dynamic linker resolves symbols related to `fdtrack`.
* **Frida Hook:**  Targeting the `fd_hook` function seems like the most direct way to observe the tracking mechanism in action.
* **Common Usage Errors:** Demonstrating scenarios where file descriptor leaks occur.

**8. Structuring the Response:**

Finally, I organize the information into a coherent structure, addressing each part of the original request:

* **Functionality:** Summarize the key tasks the code performs.
* **Relationship to Android:** Explain how the library integrates with the Android system.
* **Libc Function Details:** Explain the purpose of the libc functions used (e.g., mutex, vector, signal handling).
* **Dynamic Linker Aspects:**  Provide the SO layout and linking process explanation.
* **Logical Reasoning (Assumptions/Inputs/Outputs):** While the code itself isn't performing complex logical deductions, I can create examples showing the *effects* of its tracking.
* **Common Usage Errors:** Illustrate potential problems developers might encounter.
* **Android Framework/NDK Integration and Frida Hook:** Explain how the framework could trigger the library and provide a practical Frida example.

**Self-Correction/Refinement During the Process:**

* Initially, I might focus too much on the `unwindstack` library. I need to remember that the *primary* goal of this code is FD tracking, with stack unwinding being a tool for that purpose.
* I need to ensure that the examples are clear and directly related to the code's functionality. For instance, the Frida hook should target a function that directly interacts with the tracking mechanism.
* I should avoid making assumptions about the internal workings of `android_fdtrack_*` functions unless they are directly apparent from the code. Focus on how *this* code uses those functions.

By following this thought process, I can systematically analyze the code, extract relevant information, and present it in a clear and comprehensive manner that addresses all aspects of the initial request.
好的，我们来详细分析一下 `bionic/libfdtrack/fdtrack.cpp` 这个文件。

**功能列举:**

`fdtrack.cpp` 的主要功能是跟踪和记录文件描述符 (file descriptor, fd) 的创建和关闭时的调用栈信息。其主要目的是帮助开发者诊断文件描述符泄漏问题。具体来说，它做了以下几件事：

1. **Hook 文件描述符操作:**  它通过 `android_fdtrack_compare_exchange_hook` 函数注册了一个钩子函数 `fd_hook`，这个钩子函数会在文件描述符被创建 (`ANDROID_FDTRACK_EVENT_TYPE_CREATE`) 和关闭 (`ANDROID_FDTRACK_EVENT_TYPE_CLOSE`) 时被调用。
2. **记录创建时的调用栈:** 当文件描述符被创建时，`fd_hook` 函数会调用 `unwindstack::AndroidLocalUnwinder` 来获取当前线程的调用栈，并将这个调用栈存储在一个全局的数组 `stack_traces` 中，这个数组以文件描述符作为索引。
3. **清除关闭时的调用栈:** 当文件描述符被关闭时，`fd_hook` 函数会清除 `stack_traces` 中对应文件描述符的调用栈信息。
4. **提供迭代访问接口:**  `fdtrack_iterate` 函数允许用户提供一个回调函数，遍历当前所有被跟踪的文件描述符及其创建时的调用栈。
5. **提供转储 (dump) 功能:** `fdtrack_dump` 和 `fdtrack_dump_fatal` 函数用于转储当前所有被跟踪的文件描述符及其创建时的调用栈信息到 logcat。 `fdtrack_dump_fatal` 还会尝试找到最常见的泄漏调用栈，并将其添加到 abort 信息中，然后触发进程终止。
6. **通过信号触发转储:**  它注册了一个信号处理函数来监听 `BIONIC_SIGNAL_FDTRACK` 信号。当收到这个信号时，会调用 `fdtrack_dump` 或 `fdtrack_dump_fatal`。

**与 Android 功能的关系及举例说明:**

`fdtrack` 紧密地与 Android 的底层文件描述符管理和调试机制相关。

* **`android/fdsan.h` (File Descriptor Sanitizer):** `fdtrack` 可以与 fdsan 协同工作。`fdtrack_dump_impl` 函数中会调用 `android_fdsan_get_owner_tag(fd)` 来获取文件描述符的 owner tag (如果设置了的话)，这可以帮助进一步定位文件描述符的来源。例如，fdsan 可以标记特定模块创建的文件描述符，`fdtrack` 可以显示这些被标记的文件描述符的创建栈。
* **Bionic C 库:**  作为 bionic 的一部分，`fdtrack` 利用了 bionic 提供的底层机制，例如信号处理 (`sigaction`) 和可能的内部文件描述符管理接口 (通过 `android_fdtrack_*` 函数)。
* **动态链接器:** `fdtrack` 的初始化和卸载过程 (通过 `__attribute__((constructor))` 和 `__attribute__((destructor))`) 由动态链接器控制。动态链接器负责在库加载和卸载时调用这些函数。
* **`unwindstack` 库:**  `fdtrack` 使用 `unwindstack` 库来获取调用栈信息。`unwindstack` 能够回溯线程的执行过程，找到函数调用链。

**举例说明:**

假设一个 Android 应用中存在一个文件描述符泄漏，某个组件打开了一个文件或 socket，但忘记关闭它。

1. **创建时:** 当泄漏发生时，例如调用 `open()` 或 `socket()`，bionic 的文件描述符管理机制会分配一个新的文件描述符。同时，由于 `fdtrack` 的钩子函数 `fd_hook` 已安装，它会被调用，记录下 `open()` 或 `socket()` 调用的堆栈信息。
2. **持续存在:** 泄漏的文件描述符会一直存在，直到进程结束。
3. **触发转储:**  开发者可以通过发送 `BIONIC_SIGNAL_FDTRACK` 信号给进程，或者在程序中调用 `fdtrack_dump()` 或 `fdtrack_dump_fatal()` 来触发转储。
4. **查看日志:**  在 logcat 中，开发者会看到 `fdtrack` 输出的日志，其中包含了泄漏的文件描述符的 ID 和创建时的调用栈。通过分析这个调用栈，开发者可以找到泄漏发生的具体代码位置。

**详细解释每一个 libc 函数的功能是如何实现的:**

这里列举的是 `fdtrack.cpp` 中使用的部分 libc 或 bionic 提供的函数，以及它们的简要实现原理：

* **`sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)`:**  用于设置指定信号的处理方式。
    * **实现原理:**  内核维护着一个进程的信号处理表。`sigaction` 系统调用会修改这个表中的对应项，指定当接收到 `signum` 信号时，应该执行哪个处理函数 (`act->sa_sigaction`)。`SA_SIGINFO` 标志表示使用扩展的信号处理函数，可以获取更详细的信号信息。`SA_ONSTACK` 标志表示在备选的信号栈上执行信号处理函数。
* **`abort()`:**  立即终止当前进程，产生一个 core dump 文件 (如果配置允许)。
    * **实现原理:**  `abort()` 函数通常会先解除一些资源，刷新缓冲区，然后向进程自身发送 `SIGABRT` 信号。默认情况下，`SIGABRT` 信号的处理方式是终止进程并生成 core dump。
* **`std::mutex` (来自 `<mutex>`):**  提供互斥锁，用于保护共享资源，防止多线程并发访问时出现数据竞争。
    * **实现原理:**  `std::mutex` 通常基于底层的操作系统提供的互斥锁原语 (例如 Linux 的 `pthread_mutex_t`) 实现。当一个线程尝试 `lock()` 一个已经被其他线程锁定的互斥锁时，该线程会被阻塞，直到持有锁的线程调用 `unlock()` 释放锁。
* **`std::vector` (来自 `<vector>`):**  提供动态数组，可以根据需要自动调整大小。
    * **实现原理:**  `std::vector` 内部维护着一片连续的内存空间。当元素数量超过当前分配的内存大小时，`vector` 会分配一块更大的内存，将现有元素拷贝到新的内存空间，并释放旧的内存。
* **`std::thread` (来自 `<thread>`):**  提供创建和管理线程的能力。
    * **实现原理:**  `std::thread` 通常基于操作系统提供的线程 API (例如 Linux 的 `pthread_create`) 实现。它封装了创建新线程并执行指定函数的功能。
* **`async_safe_format_log` (来自 `<async_safe/log.h>`):**  一个线程安全的日志输出函数，用于在信号处理函数等不允许进行复杂操作的环境下安全地输出日志。
    * **实现原理:**  `async_safe_format_log` 通常会避免使用可能导致死锁或重入问题的标准 I/O 函数。它可能会直接写入到 log 设备，或者使用其他更轻量级的同步机制。
* **`android_fdtrack_compare_exchange_hook` (来自 `<android/fdtrack.h>`):**  一个原子操作，用于注册或替换文件描述符跟踪的钩子函数。
    * **实现原理:**  这是一个原子比较并交换操作。它会比较当前注册的钩子函数是否等于 `expected`，如果是，则将其替换为 `new_hook`。原子性保证了在多线程环境下操作的安全性。
* **`android_fdtrack_set_globally_enabled` (来自 `<android/fdtrack.h>`):**  全局地启用或禁用文件描述符跟踪。
    * **实现原理:**  可能设置一个全局的标志位，控制文件描述符操作事件是否触发钩子函数。
* **`android_fdtrack_set_enabled` (来自 `<android/fdtrack.h>`):**  临时启用或禁用文件描述符跟踪。
    * **实现原理:**  类似于 `android_fdtrack_set_globally_enabled`，但可能只在特定的代码段内生效。
* **`android_fdsan_get_owner_tag` (来自 `<android/fdsan.h>`):**  获取与指定文件描述符关联的 owner tag。
    * **实现原理:**  fdsan 在文件描述符创建时可能会为其关联一个 owner tag，用于标识创建该文件描述符的模块或组件。`android_fdsan_get_owner_tag` 函数用于检索这个 tag。
* **`android_set_abort_message` (来自 `<android/set_abort_message.h>`):**  设置进程终止时的 abort 信息，这个信息会出现在 tombstone 文件中。
    * **实现原理:**  当进程调用 `abort()` 或接收到某些导致终止的信号时，系统会生成一个 tombstone 文件，其中包含了进程崩溃时的各种信息。`android_set_abort_message` 允许程序在终止前自定义一部分信息。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

`libfdtrack.so` 是一个动态链接库，它的加载和初始化由 Android 的动态链接器 `linker` 负责。

**SO 布局样本:**

```
LOAD           00000000  1000      r-x p  /system/lib64/bionic/libfdtrack.so
LOAD           00001000  0048      r-- p  /system/lib64/bionic/libfdtrack.so
LOAD           00002000  0008      rw- p  /system/lib64/bionic/libfdtrack.so

```

这个布局表示：

* **LOAD 00000000:**  表示代码段 (text segment)，具有读和执行权限 (`r-x`)。起始地址为 `00000000` (相对于库的基地址)。大小为 `1000` (十六进制)。
* **LOAD 00001000:** 表示只读数据段 (rodata segment)，具有读权限 (`r--`)。
* **LOAD 00002000:** 表示可读写数据段 (data segment) 和未初始化数据段 (bss segment)，具有读写权限 (`rw-`)。

实际的地址会根据 ASLR (Address Space Layout Randomization) 而变化。

**链接的处理过程:**

1. **加载:** 当一个进程需要使用 `libfdtrack.so` 时 (通常是由于其他库或可执行文件的依赖)，动态链接器会找到并加载这个库到进程的地址空间。
2. **符号解析:** 动态链接器会解析 `libfdtrack.so` 的符号依赖，例如它使用了 `liblog.so` (提供 `async_safe_format_log`) 和 `libc.so` (提供 `sigaction`, `mutex` 等)。动态链接器会在这些依赖库中找到对应的符号定义，并将 `libfdtrack.so` 中的符号引用绑定到这些定义的地址。
3. **重定位:** 由于库被加载到内存中的地址可能不是编译时的地址，动态链接器会修改 `libfdtrack.so` 中需要调整的地址，使其指向正确的内存位置。
4. **构造函数执行:**  动态链接器在完成加载和链接后，会执行 `libfdtrack.so` 中标记为构造函数的函数，即 `ctor()` 函数。
   * `ctor()` 函数会初始化 `stack_traces` 数组，设置信号处理函数，并调用 `android_fdtrack_compare_exchange_hook` 注册 `fd_hook`。
5. **析构函数执行:** 当进程退出或库被卸载时，动态链接器会执行标记为析构函数的函数，即 `dtor()` 函数。
   * `dtor()` 函数会尝试卸载 `fd_hook`。

**假设输入与输出 (逻辑推理):**

假设在某个应用中，以下代码导致了文件描述符泄漏：

```c++
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

void leaky_function() {
  int fd = open("/sdcard/test.txt", O_RDONLY);
  if (fd < 0) {
    perror("open");
  }
  // 忘记关闭 fd
}

int main() {
  for (int i = 0; i < 5; ++i) {
    leaky_function();
  }
  sleep(10); // 让程序运行一段时间
  return 0;
}
```

**假设输入:** 运行上述程序一段时间后，发送 `BIONIC_SIGNAL_FDTRACK` 信号给该进程。

**预期输出 (logcat 中 `fdtrack` 的相关日志):**

```
INFO: fdtrack: fdtrack dumping...
INFO: fdtrack: fd 3: (unowned)
INFO: fdtrack:   0: leaky_function+0x...
INFO: fdtrack:   1: main+0x...
INFO: fdtrack: fd 4: (unowned)
INFO: fdtrack:   0: leaky_function+0x...
INFO: fdtrack:   1: main+0x...
INFO: fdtrack: fd 5: (unowned)
INFO: fdtrack:   0: leaky_function+0x...
INFO: fdtrack:   1: main+0x...
INFO: fdtrack: fd 6: (unowned)
INFO: fdtrack:   0: leaky_function+0x...
INFO: fdtrack:   1: main+0x...
INFO: fdtrack: fd 7: (unowned)
INFO: fdtrack:   0: leaky_function+0x...
INFO: fdtrack:   1: main+0x...
```

可以看到，`fdtrack` 记录了多个未关闭的文件描述符 (fd 3, 4, 5, 6, 7)，并且它们的创建调用栈都指向了 `leaky_function` 和 `main` 函数。

**用户或者编程常见的使用错误:**

1. **忘记关闭文件描述符:** 这是最常见的文件描述符泄漏原因。例如，打开文件、创建 socket 后没有调用 `close()`。
   ```c++
   int fd = open("myfile.txt", O_RDONLY);
   // ... 使用 fd，但忘记 close(fd);
   ```
2. **在异常处理中忘记关闭:** 如果在文件描述符打开后发生了异常，并且没有在 catch 块中正确关闭文件描述符，就会导致泄漏。
   ```c++
   int fd = open("myfile.txt", O_RDONLY);
   try {
       // ... 可能抛出异常的代码
   } catch (...) {
       // ... 异常处理，但忘记 close(fd);
   }
   close(fd); // 如果 try 块没有抛出异常，这里会被执行，但如果抛出了就泄漏了
   ```
3. **在循环中不断打开但不关闭:** 在循环中重复打开文件描述符而不关闭，会导致文件描述符数量迅速增加，最终耗尽系统资源。
   ```c++
   for (int i = 0; i < 10000; ++i) {
       int fd = open("temp.txt", O_CREAT | O_WRONLY | O_TRUNC, 0644);
       // ... 使用 fd，但忘记关闭
   }
   ```
4. **错误地使用文件描述符所有权:** 在多线程或多进程环境中，文件描述符的所有权可能不明确，导致某些线程或进程认为应该由自己关闭，而其他线程或进程可能仍在使用，或者反之，导致忘记关闭。

**Android framework or ndk 是如何一步步的到达这里:**

`libfdtrack.so` 通常不会被 Android framework 或 NDK 代码直接显式调用。它的作用更偏向于底层的监控和调试。其加载和激活通常发生在进程启动的早期阶段，由动态链接器负责。

1. **进程启动:** 当一个 Android 应用或服务启动时，系统会创建一个新的进程。
2. **动态链接器加载:** 动态链接器 (`/system/bin/linker64` 或 `/system/bin/linker`) 会根据可执行文件的依赖关系加载所需的共享库。如果某个被加载的库 (例如 `libc.so`) 依赖于 `libfdtrack.so`，那么 `libfdtrack.so` 也会被加载。
3. **构造函数执行:**  一旦 `libfdtrack.so` 被加载到进程地址空间，动态链接器会执行其构造函数 `ctor()`。
4. **钩子安装:** `ctor()` 函数会调用 `android_fdtrack_compare_exchange_hook` 来安装 `fd_hook` 函数。从这时起，所有新的文件描述符创建和关闭事件都会触发 `fd_hook`。
5. **Framework/NDK 代码执行:**  之后，Android framework 或 NDK 编写的代码可能会执行各种文件操作 (例如通过 `open()`, `socket()`, `fopen()` 等)。
6. **`fd_hook` 触发:**  每当 framework 或 NDK 代码创建或关闭文件描述符时，`fd_hook` 函数会被调用，记录或清除相应的调用栈。
7. **触发转储 (可选):**  开发者可以通过发送信号或在代码中显式调用 `fdtrack_dump()` 等函数来查看当前的 `fdtrack` 记录。某些系统级别的工具或调试服务也可能在特定情况下触发转储。

**Frida hook 示例调试这些步骤:**

可以使用 Frida hook `fd_hook` 函数来观察文件描述符的创建和关闭过程，以及它们对应的调用栈。

```python
import frida
import sys

package_name = "your.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found.")
    sys.exit(1)

script_source = """
Interceptor.attach(Module.findExportByName("libfdtrack.so", "_Z7fd_hookP20android_fdtrack_event"), {
    onEnter: function(args) {
        var event = ptr(args[0]);
        var type = event.readU32();
        var fd = event.add(4).readS32();

        if (type == 0) { // ANDROID_FDTRACK_EVENT_TYPE_CREATE
            console.log("[fdtrack] File descriptor created: fd =", fd);
            Thread.backtrace().map(DebugSymbol.fromAddress).forEach(function(sym) {
                console.log("  " + sym.toString());
            });
        } else if (type == 1) { // ANDROID_FDTRACK_EVENT_TYPE_CLOSE
            console.log("[fdtrack] File descriptor closed: fd =", fd);
        }
    }
});
"""

script = session.create_script(script_source)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用方法:**

1. 将 `your.package.name` 替换为你要调试的 Android 应用的包名。
2. 确保你的 Android 设备已连接并通过 USB 调试。
3. 运行 Frida script。
4. 在你的 Android 应用中执行一些会创建和关闭文件描述符的操作。

**预期输出:**

Frida 的控制台会输出 `fd_hook` 被调用时的信息，包括文件描述符的 ID 和创建时的调用栈。

**总结:**

`bionic/libfdtrack/fdtrack.cpp` 是 Android Bionic 库中一个用于跟踪文件描述符创建和关闭的组件，它通过 hook 机制记录调用栈信息，帮助开发者诊断文件描述符泄漏问题。它与 Android 的底层机制紧密结合，并在动态链接器的管理下运行。通过理解其功能和实现，开发者可以更好地调试和优化 Android 应用。

### 提示词
```
这是目录为bionic/libfdtrack/fdtrack.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2019 The Android Open Source Project
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

#include <inttypes.h>
#include <stdint.h>

#include <array>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include <android/fdsan.h>
#include <android/set_abort_message.h>
#include <bionic/fdtrack.h>

#include <android-base/no_destructor.h>
#include <android-base/thread_annotations.h>
#include <async_safe/log.h>
#include <bionic/reserved_signals.h>

#include <unwindstack/AndroidUnwinder.h>

struct FdEntry {
  std::mutex mutex;
  std::vector<unwindstack::FrameData> backtrace GUARDED_BY(mutex);
};

extern "C" void fdtrack_dump();
extern "C" void fdtrack_dump_fatal();

using fdtrack_callback_t = bool (*)(int fd, const char* const* function_names,
                                    const uint64_t* function_offsets, size_t count, void* arg);
extern "C" void fdtrack_iterate(fdtrack_callback_t callback, void* arg);

static void fd_hook(android_fdtrack_event* event);

// Backtraces for the first 4k file descriptors ought to be enough to diagnose an fd leak.
static constexpr size_t kFdTableSize = 4096;

// Only unwind up to 32 frames outside of libfdtrack.so.
static constexpr size_t kStackDepth = 32;

static bool installed = false;
static std::array<FdEntry, kFdTableSize> stack_traces [[clang::no_destroy]];
static unwindstack::AndroidLocalUnwinder& Unwinder() {
  // Skip any initial frames from libfdtrack.so.
  // Also ignore frames from ART (http://b/236197847) because we'd rather spend
  // our precious few frames on the actual Java calling code rather than the
  // implementation of JNI!
  static android::base::NoDestructor<unwindstack::AndroidLocalUnwinder> unwinder(
      std::vector<std::string>{"libfdtrack.so", "libart.so"});
  return *unwinder.get();
}

__attribute__((constructor)) static void ctor() {
  for (auto& entry : stack_traces) {
    entry.backtrace.reserve(kStackDepth);
  }

  struct sigaction sa = {};
  sa.sa_sigaction = [](int, siginfo_t* siginfo, void*) {
    if (siginfo->si_code == SI_QUEUE && siginfo->si_int == 1) {
      fdtrack_dump_fatal();
    } else {
      fdtrack_dump();
    }
  };
  sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
  sigaction(BIONIC_SIGNAL_FDTRACK, &sa, nullptr);

  unwindstack::ErrorData error;
  if (Unwinder().Initialize(error)) {
    android_fdtrack_hook_t expected = nullptr;
    installed = android_fdtrack_compare_exchange_hook(&expected, &fd_hook);
  }

  android_fdtrack_set_globally_enabled(true);
}

__attribute__((destructor)) static void dtor() {
  if (installed) {
    android_fdtrack_hook_t expected = &fd_hook;
    android_fdtrack_compare_exchange_hook(&expected, nullptr);
  }
}

FdEntry* GetFdEntry(int fd) {
  if (fd >= 0 && fd < static_cast<int>(kFdTableSize)) {
    return &stack_traces[fd];
  }
  return nullptr;
}

static void fd_hook(android_fdtrack_event* event) {
  if (event->type == ANDROID_FDTRACK_EVENT_TYPE_CREATE) {
    if (FdEntry* entry = GetFdEntry(event->fd); entry) {
      std::lock_guard<std::mutex> lock(entry->mutex);
      entry->backtrace.clear();

      unwindstack::AndroidUnwinderData data(kStackDepth);
      if (Unwinder().Unwind(data)) {
        entry->backtrace = std::move(data.frames);
      }
    }
  } else if (event->type == ANDROID_FDTRACK_EVENT_TYPE_CLOSE) {
    if (FdEntry* entry = GetFdEntry(event->fd); entry) {
      std::lock_guard<std::mutex> lock(entry->mutex);
      entry->backtrace.clear();
    }
  }
}

void fdtrack_iterate(fdtrack_callback_t callback, void* arg) {
  bool prev = android_fdtrack_set_enabled(false);

  for (int fd = 0; fd < static_cast<int>(stack_traces.size()); ++fd) {
    const char* function_names[kStackDepth];
    uint64_t function_offsets[kStackDepth];
    FdEntry* entry = GetFdEntry(fd);
    if (!entry) {
      continue;
    }

    if (!entry->mutex.try_lock()) {
      async_safe_format_log(ANDROID_LOG_WARN, "fdtrack", "fd %d locked, skipping", fd);
      continue;
    }

    if (entry->backtrace.empty()) {
      entry->mutex.unlock();
      continue;
    } else if (entry->backtrace.size() < 2) {
      async_safe_format_log(ANDROID_LOG_WARN, "fdtrack", "fd %d missing frames: size = %zu", fd,
                            entry->backtrace.size());

      entry->mutex.unlock();
      continue;
    }

    for (size_t i = 0; i < entry->backtrace.size(); ++i) {
      function_names[i] = entry->backtrace[i].function_name.c_str();
      function_offsets[i] = entry->backtrace[i].function_offset;
    }

    bool should_continue =
        callback(fd, function_names, function_offsets, entry->backtrace.size(), arg);

    entry->mutex.unlock();

    if (!should_continue) {
      break;
    }
  }

  android_fdtrack_set_enabled(prev);
}

static size_t hash_stack(const char* const* function_names, const uint64_t* function_offsets,
                         size_t stack_depth) {
  size_t hash = 0;
  for (size_t i = 0; i < stack_depth; ++i) {
    // To future maintainers: if a libc++ update ever makes this invalid, replace this with +.
    hash = std::__hash_combine(hash, std::hash<std::string_view>()(function_names[i]));
    hash = std::__hash_combine(hash, std::hash<uint64_t>()(function_offsets[i]));
  }
  return hash;
}

static void fdtrack_dump_impl(bool fatal) {
  if (!installed) {
    async_safe_format_log(ANDROID_LOG_INFO, "fdtrack", "fdtrack not installed");
  } else {
    async_safe_format_log(ANDROID_LOG_INFO, "fdtrack", "fdtrack dumping...");
  }

  // If we're aborting, identify the most common stack in the hopes that it's the culprit,
  // and emit that in the abort message so crash reporting can separate different fd leaks out.
  // This is horrible and quadratic, but we need to avoid allocation since this can happen in
  // response to a signal generated asynchronously. We're only going to dump 1k fds by default,
  // and we're about to blow up the entire system, so this isn't too expensive.
  struct StackInfo {
    size_t hash = 0;
    size_t count = 0;

    size_t stack_depth = 0;
    const char* function_names[kStackDepth];
    uint64_t function_offsets[kStackDepth];
  };
  struct StackList {
    size_t count = 0;
    std::array<StackInfo, 128> data;
  };
  static StackList stacks;

  fdtrack_iterate(
      [](int fd, const char* const* function_names, const uint64_t* function_offsets,
         size_t stack_depth, void* stacks_ptr) {
        auto stacks = static_cast<StackList*>(stacks_ptr);
        uint64_t fdsan_owner = android_fdsan_get_owner_tag(fd);
        if (fdsan_owner != 0) {
          async_safe_format_log(ANDROID_LOG_INFO, "fdtrack", "fd %d: (owner = 0x%" PRIx64 ")", fd,
                                fdsan_owner);
        } else {
          async_safe_format_log(ANDROID_LOG_INFO, "fdtrack", "fd %d: (unowned)", fd);
        }

        for (size_t i = 0; i < stack_depth; ++i) {
          async_safe_format_log(ANDROID_LOG_INFO, "fdtrack", "  %zu: %s+%" PRIu64, i,
                                function_names[i], function_offsets[i]);
        }

        if (stacks) {
          size_t hash = hash_stack(function_names, function_offsets, stack_depth);
          bool found_stack = false;
          for (size_t i = 0; i < stacks->count; ++i) {
            if (stacks->data[i].hash == hash) {
              ++stacks->data[i].count;
              found_stack = true;
              break;
            }
          }

          if (!found_stack) {
            if (stacks->count < stacks->data.size()) {
              auto& stack = stacks->data[stacks->count++];
              stack.hash = hash;
              stack.count = 1;
              stack.stack_depth = stack_depth;
              for (size_t i = 0; i < stack_depth; ++i) {
                stack.function_names[i] = function_names[i];
                stack.function_offsets[i] = function_offsets[i];
              }
            }
          }
        }

        return true;
      },
      fatal ? &stacks : nullptr);

  if (fatal) {
    // Find the most common stack.
    size_t max = 0;
    size_t total = 0;
    StackInfo* stack = nullptr;
    for (size_t i = 0; i < stacks.count; ++i) {
      total += stacks.data[i].count;
      if (stacks.data[i].count > max) {
        stack = &stacks.data[i];
        max = stack->count;
      }
    }

    static char buf[1024];

    if (!stack) {
      async_safe_format_buffer(buf, sizeof(buf),
                               "aborting due to fd leak: see \"open files\" in the tombstone; "
                               "no stacks?!");
    } else {
      char* p = buf;
      p += async_safe_format_buffer(buf, sizeof(buf),
                                    "aborting due to fd leak: see \"open files\" in the tombstone; "
                                    "most common stack (%zu/%zu) is\n", max, total);

      for (size_t i = 0; i < stack->stack_depth; ++i) {
        ssize_t bytes_left = buf + sizeof(buf) - p;
        if (bytes_left > 0) {
          p += async_safe_format_buffer(p, buf + sizeof(buf) - p, "  %zu: %s+%" PRIu64 "\n", i,
                                        stack->function_names[i], stack->function_offsets[i]);
        }
      }
    }

    android_set_abort_message(buf);

    // Abort on a different thread to avoid ART dumping runtime stacks.
    std::thread([]() { abort(); }).join();
  }
}

void fdtrack_dump() {
  fdtrack_dump_impl(false);
}

void fdtrack_dump_fatal() {
  fdtrack_dump_impl(true);
}
```