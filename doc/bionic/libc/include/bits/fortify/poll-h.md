Response:
Let's break down the thought process for analyzing this `poll.handroid` file.

**1. Understanding the Context:**

The first and most crucial step is understanding where this file comes from and its purpose. The prompt clearly states it's part of Bionic, Android's C library. The path `bionic/libc/include/bits/fortify/poll.handroid` gives further clues. `include` suggests header files, `bits` often indicates architecture-specific or lower-level details, and `fortify` immediately points towards security hardening. The `.handroid` extension might be specific to the Bionic build system or a way to differentiate fortified versions. Knowing this context is essential to interpret the code correctly.

**2. Initial Code Scan and Identification of Key Elements:**

Next, quickly scan the code looking for recognizable patterns and keywords. We see:

* `#ifndef _POLL_H_`: This confirms it's a header file, and the error directive indicates it should *not* be included directly.
* `#if __BIONIC_AVAILABILITY_GUARD(...)`: This suggests conditional compilation based on Android API levels.
* `int __poll_chk(...)`, `int __ppoll_chk(...)`, `int __ppoll64_chk(...)`: These look like function declarations, likely related to `poll`, `ppoll`, and `ppoll64` system calls. The `_chk` suffix strongly hints at "checked" versions, reinforcing the "fortify" context.
* `#if defined(__BIONIC_FORTIFY)`:  This block is clearly related to the fortification mechanism.
* `#define __bos_fd_count_trivially_safe(...)`: This looks like a macro for checking buffer sizes. `bos` likely stands for "buffer object size."
* `__BIONIC_FORTIFY_INLINE int poll(...)`, `__BIONIC_FORTIFY_INLINE int ppoll(...)`, `__BIONIC_FORTIFY_INLINE int ppoll64(...)`: These are inline function definitions, also related to the `poll` family. The `__overloadable` attribute is also noticeable.
* `__clang_error_if(...)`: This indicates compile-time error checking.
* `__bos_unevaluated_lt(__bos(fds), ...)`:  More buffer size checking. `__bos(fds)` likely gets the size of the `fds` array.
* `__call_bypassing_fortify(...)`: This suggests a way to call the original, un-fortified versions of the functions.

**3. Deconstructing the Fortification Logic:**

The core of the file is the fortification logic. Here's the breakdown:

* **Goal:** Prevent buffer overflows in calls to `poll`, `ppoll`, and `ppoll64`. These functions take an array of `pollfd` structures and the number of elements in that array. A common error is passing an incorrect `fd_count` that's larger than the allocated buffer for `fds`.
* **Mechanism:**
    * **Compile-time check:** `__clang_error_if` checks *at compile time* if the provided `fd_count` could potentially lead to a buffer overflow based on the declared size of `fds`. This is a static analysis approach.
    * **Runtime check (conditional):** The `#if __ANDROID_API__ >= 23 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED` block enables runtime checks.
    * **`__bos_fd_count_trivially_safe` macro:** This macro performs a quick check to see if the provided `fd_count` is "trivially safe" – meaning it's definitely within the bounds of the buffer. It checks if `sizeof(*fds) * fd_count` is less than or equal to the actual size of the buffer (`bos_val`). It also checks if `fd_count` doesn't exceed the maximum value for `nfds_t` to prevent integer overflow during the multiplication.
    * **`_chk` functions:** If the trivial check fails, or runtime checks are enabled, the code calls the `__poll_chk`, `__ppoll_chk`, or `__ppoll64_chk` functions. These are likely more sophisticated runtime checks implemented elsewhere in Bionic. They might perform more detailed validation and potentially log errors or terminate the program if an overflow is detected.
    * **`__call_bypassing_fortify`:**  If the checks pass, this macro calls the underlying, un-fortified version of the `poll` function. This avoids double-checking and potential performance overhead in safe cases.

**4. Linking with Android Functionality:**

The `poll` family of functions are fundamental for I/O multiplexing in Linux and Android. They allow a thread to wait for activity on multiple file descriptors. This is crucial for many Android components, including:

* **Networking:**  Handling multiple network connections concurrently.
* **Input Events:**  Waiting for touch events, keyboard input, etc.
* **Inter-Process Communication (IPC):** Monitoring pipes, sockets, and other IPC mechanisms.

**5. Dynamic Linker Considerations:**

The file itself doesn't directly implement dynamic linking, but it uses functions that *will* be linked. The `__call_bypassing_fortify` macro likely resolves to a direct call to the `poll`, `ppoll`, or `ppoll64` symbols in the C library. The dynamic linker will handle resolving these symbols at runtime.

**6. User Errors:**

The most common user error addressed by this fortification is providing an incorrect `fd_count` to `poll`, `ppoll`, or `ppoll64`. This can lead to reading or writing beyond the bounds of the `fds` array, causing crashes or security vulnerabilities.

**7. Frida Hooking:**

Thinking about Frida, we want to intercept the fortified versions of the functions to observe the checks and how they behave. Hooking the `poll`, `ppoll`, and `ppoll64` functions within the target process's memory space would be the goal.

**8. Structuring the Explanation:**

Finally, organize the information logically, starting with a summary of the file's purpose, then detailing each part of the code, explaining its relation to Android, addressing dynamic linking, common errors, and providing a Frida example. Use clear and concise language. The goal is to provide a comprehensive yet understandable explanation.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Maybe the `_chk` functions are the *actual* implementations of `poll`.
* **Correction:**  The `__call_bypassing_fortify` macro indicates that the standard `poll` functions exist, and the `_chk` functions are wrappers for fortification.
* **Initial thought:** Focus only on runtime checks.
* **Correction:** Recognize the importance of the compile-time `__clang_error_if` check.
* **Considering the audience:**  Explain technical terms like "I/O multiplexing" briefly. Provide concrete examples of Android usage.

By following these steps, we can systematically analyze the `poll.handroid` file and generate a comprehensive and accurate explanation.
这个文件 `bionic/libc/include/bits/fortify/poll.handroid` 是 Android Bionic C 库中用于加强 `poll`、`ppoll` 和 `ppoll64` 函数安全性的代码。它属于 Bionic 的 "fortify" 机制的一部分，旨在在编译时和运行时检测潜在的缓冲区溢出错误。由于它位于 `bits/fortify` 目录下，因此明确表明其功能是与安全加固相关的。

**功能列举:**

1. **提供 `poll`、`ppoll` 和 `ppoll64` 函数的安全加强版本:**  定义了带有 `__bos_unevaluated_lt` 检查的内联函数 `poll`、`ppoll` 和 `ppoll64`。这些内联函数在调用实际的系统调用之前，会检查用户提供的 `fds` 数组的大小和 `fd_count` 是否匹配，以防止缓冲区溢出。

2. **定义检查函数:**  声明了 `__poll_chk`、`__ppoll_chk` 和 `__ppoll64_chk` 函数。这些函数是实际执行运行时缓冲区溢出检查的版本。

3. **使用 Bionic 的可用性保护机制:** 通过 `__BIONIC_AVAILABILITY_GUARD` 宏，根据 Android API 级别有条件地启用某些功能。例如，`__ppoll64_chk` 在 API 级别 28 及以上可用。

4. **定义用于缓冲区大小检查的宏:**  定义了 `__bos_fd_count_trivially_safe` 宏，用于快速判断 `fd_count` 是否明显安全，避免在简单情况下执行更复杂的检查。

5. **提供编译时的缓冲区溢出检查:** 使用 `__clang_error_if` 宏在编译时检查 `fd_count` 是否大于 `fds` 数组的实际大小，如果检测到潜在的溢出，则会产生编译错误。

**与 Android 功能的关系及举例说明:**

`poll`、`ppoll` 和 `ppoll64` 是标准的 POSIX 系统调用，用于实现 I/O 多路复用。它们允许一个线程等待多个文件描述符中的任意一个变为就绪状态（可读、可写或发生错误）。这些系统调用在 Android 中被广泛使用，例如：

* **网络编程:**  `Socket` 的非阻塞操作经常与 `poll` 一起使用，以等待多个连接上的数据到达。例如，一个服务器可能使用 `poll` 来同时监听多个客户端连接。
* **事件处理:** Android 的事件循环机制底层可能使用 `epoll` (一种 `poll` 的变体) 或 `poll` 来等待各种事件，如触摸事件、按键事件、传感器数据等。
* **Binder IPC:** 虽然 Binder 主要使用内核驱动，但在某些情况下，例如进程间的 socket 通信，可能会涉及到 `poll`。

**举例说明:**

假设一个 Android 应用需要同时监听多个网络连接。它可能会创建一个 `pollfd` 结构体数组，每个结构体对应一个 socket 文件描述符。然后调用 `poll` 来等待这些 socket 上发生事件。

```c
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_FDS 10

int main() {
    struct pollfd fds[MAX_FDS];
    int nfds = 0;
    int timeout = -1; // 永久等待

    // 创建并监听一些 socket (省略创建 socket 的代码)
    // ... 假设创建了 3 个监听 socket：listen_fd1, listen_fd2, listen_fd3

    fds[nfds].fd = listen_fd1;
    fds[nfds].events = POLLIN;
    nfds++;

    fds[nfds].fd = listen_fd2;
    fds[nfds].events = POLLIN;
    nfds++;

    fds[nfds].fd = listen_fd3;
    fds[nfds].events = POLLIN;
    nfds++;

    printf("开始监听 %d 个文件描述符...\n", nfds);

    int ret = poll(fds, nfds, timeout);
    if (ret > 0) {
        printf("有事件发生！\n");
        for (int i = 0; i < nfds; ++i) {
            if (fds[i].revents & POLLIN) {
                printf("文件描述符 %d 可读\n", fds[i].fd);
                // 处理连接
            }
        }
    } else if (ret == 0) {
        printf("超时\n");
    } else {
        perror("poll");
    }

    return 0;
}
```

在这个例子中，如果开发者错误地将 `nfds` 设置为大于 `MAX_FDS` 的值，`fortify/poll.handroid` 中的代码就会发挥作用，在编译时或运行时检测到潜在的缓冲区溢出。

**libc 函数的功能实现:**

这个文件本身并没有实现 `poll`、`ppoll` 或 `ppoll64` 的核心逻辑。这些核心逻辑通常由内核提供。`fortify/poll.handroid` 提供的功能是 **围绕这些核心系统调用的安全包装器**。

* **`poll`、`ppoll`、`ppoll64` (在 `__BIONIC_FORTIFY` 块中定义):**
    1. **编译时检查:** 使用 `__clang_error_if(__bos_unevaluated_lt(__bos(fds), sizeof(*fds) * fd_count), ...)` 在编译时检查 `fd_count` 是否会导致访问 `fds` 数组越界。`__bos(fds)` 通常会获取 `fds` 数组的编译时大小。
    2. **运行时检查 (条件性):** 如果定义了 `__BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED` 且 Android API 版本足够高，则会进行运行时检查。
    3. **快速安全检查:**  调用 `__bos_fd_count_trivially_safe` 宏进行快速检查。如果 `fd_count` 乘以 `sizeof(struct pollfd)` 明显小于 `fds` 的实际大小，则认为安全，直接调用未加固的版本。
    4. **调用检查函数:** 如果快速检查不通过，则调用 `__poll_chk`、`__ppoll_chk` 或 `__ppoll64_chk`。这些 `_chk` 函数的实现位于 Bionic 的其他源文件中，它们会执行更严格的运行时边界检查。
    5. **调用原始系统调用:** 如果所有检查都通过，则使用 `__call_bypassing_fortify` 宏调用原始的、未加固的 `poll`、`ppoll` 或 `ppoll64` 系统调用。`__call_bypassing_fortify` 通常会将调用重定向到 Bionic 中未加固的函数实现。

* **`__poll_chk`、`__ppoll_chk`、`__ppoll64_chk`:**
    这些函数的具体实现不在当前文件中。它们的主要功能是在运行时检查 `fd_count` 是否超出了 `fds` 数组的实际分配大小。如果超出，则通常会打印错误日志并可能终止程序，以防止潜在的安全漏洞。

* **`__bos_fd_count_trivially_safe` 宏:**
    这个宏执行一个简单的安全检查，确保 `sizeof(*fds) * (fd_count)` 不大于 `bos_val` (`fds` 数组的实际大小)，并且 `fd_count` 不会太大导致乘法溢出。

**涉及 dynamic linker 的功能:**

当前文件主要涉及编译时和运行时的安全检查，与 dynamic linker 的直接交互较少。但是，理解 dynamic linker 的作用有助于理解 `__call_bypassing_fortify` 的工作原理。

当程序调用 `poll` 时，如果启用了 fortification，并且安全检查通过，`__call_bypassing_fortify(poll)(fds, fd_count, timeout)` 会被执行。这里的 `poll` 实际上是一个指向未加固的 `poll` 函数的函数指针。

**so 布局样本:**

假设我们有一个名为 `libmylib.so` 的共享库，它调用了 `poll` 函数。其内存布局可能如下（简化）：

```
Address Range       | Content
--------------------|------------------------------------
...                 | ...
Text Segment        |
  ...               | 其他代码
  Address_of_poll_wrapper: |  加固后的 poll 函数（来自 fortify）
  ...               |
Data Segment        |
  ...               |
Dynamic Linking Section (.dynsym, .plt, .got) |
  .plt entry for poll: |  跳转到 .got 表项
  .got entry for poll: |  初始值为 dynamic linker 的解析器地址
...                 |
```

**链接的处理过程:**

1. **编译时:** 编译器会将 `poll` 函数的调用转换为对 `.plt` (Procedure Linkage Table) 中对应条目的调用。
2. **加载时:** dynamic linker 会加载 `libmylib.so` 以及其依赖的库（包括 `libc.so`）。
3. **首次调用 `poll`:**
   - 程序执行到 `libmylib.so` 中调用 `poll` 的地方。
   - 根据 PLT 的机制，会跳转到 `.plt` 中 `poll` 对应的条目。
   - `.plt` 条目会先跳转到 `.got` (Global Offset Table) 中 `poll` 对应的条目。
   - 首次调用时，`.got` 中 `poll` 的条目通常包含 dynamic linker 的解析器地址。
   - 解析器被调用，负责在 `libc.so` 中找到 `poll` 函数的实际地址（这里指的是 **加固后的 `poll`**，因为 fortify 的版本会覆盖默认的符号）。
   - dynamic linker 将 `poll` 函数的实际地址写入 `.got` 中 `poll` 的条目。
   - 随后，跳回 `libmylib.so` 中 `poll` 的调用点，这次会直接跳转到 `poll` 的实际地址执行。
4. **后续调用 `poll`:**  由于 `.got` 表中已经有了 `poll` 的实际地址，后续的调用会直接跳转到该地址，无需再次通过 dynamic linker 解析。

当启用了 fortification 时，`libc.so` 中提供的 `poll` 符号实际上是 `fortify/poll.handroid` 中定义的加固版本。`__call_bypassing_fortify(poll)` 可能会使用一些技巧（例如，直接调用未加固的内部函数或使用弱符号）来绕过 fortification 层的检查，直接调用原始的 `poll` 系统调用入口点。

**假设输入与输出 (逻辑推理):**

假设我们调用 `poll` 函数，并考虑 fortification 的检查：

**场景 1：`fd_count` 小于实际 `fds` 数组大小**

* **假设输入:**
    * `fds`: 指向一个包含 10 个 `pollfd` 结构体的数组。
    * `fd_count`: 5
    * `timeout`: 100
* **预期输出:**  `poll` 函数正常执行，等待前 5 个文件描述符上的事件。因为 `fd_count` 在安全范围内，fortification 的检查应该会通过。

**场景 2：`fd_count` 大于实际 `fds` 数组大小 (编译时可检测)**

* **假设输入:**
    * `fds`:  一个静态分配的包含 5 个 `pollfd` 结构体的数组。
    * `fd_count`: 10
    * `timeout`: 100
* **预期输出:**  由于 `__clang_error_if` 的存在，编译时会产生错误，阻止程序生成。错误信息会提示 `fd_count` 大于 `fds` 数组的大小。

**场景 3：`fd_count` 大于实际 `fds` 数组大小 (运行时检测)**

* **假设输入:**
    * `fds`:  一个动态分配的包含 5 个 `pollfd` 结构体的数组。
    * `fd_count`: 10
    * `timeout`: 100
* **预期输出:**
    * 如果 `__BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED` 被启用，并且 API 版本足够高，`__poll_chk` 会检测到 `fd_count` 超出范围。
    * 输出错误日志（具体格式取决于 Bionic 的实现）。
    * 程序可能被终止以防止安全风险。
    * `poll` 函数可能会返回一个错误值（例如 -1）并设置 `errno`。

**用户或编程常见的使用错误:**

1. **`fd_count` 超过 `fds` 数组的实际大小:** 这是最常见的错误，也是 fortification 机制主要防止的。
   ```c
   struct pollfd fds[5];
   int ret = poll(fds, 10, -1); // 错误：fd_count 超出范围
   ```

2. **未正确初始化 `pollfd` 结构体:**  `fd` 成员应该被设置为有效的文件描述符，`events` 成员应该被设置为想要监听的事件类型。
   ```c
   struct pollfd fds[1];
   // 忘记设置 fds[0].fd 和 fds[0].events
   int ret = poll(fds, 1, -1); // 可能导致未定义的行为
   ```

3. **忽略 `poll` 的返回值:**  `poll` 的返回值指示了发生事件的文件描述符数量、超时或错误。忽略返回值可能导致程序逻辑错误。
   ```c
   struct pollfd fds[1];
   fds[0].fd = sockfd;
   fds[0].events = POLLIN;
   poll(fds, 1, 1000); // 未检查返回值
   if (fds[0].revents & POLLIN) { // 假设总是可读，可能出错
       // ...
   }
   ```

**Android framework or ndk 如何一步步的到达这里:**

1. **Android Framework/NDK 调用:**  Android Framework 或 NDK 中的代码（例如 Java 网络库、native 代码中的 socket 操作）最终会调用到 Bionic 提供的 C 库函数。

2. **系统调用封装:** 当代码需要进行 I/O 多路复用时，会调用 `poll`、`ppoll` 或 `ppoll64` 函数。这些函数在 Bionic 中被实现为对内核系统调用的封装。

3. **Fortification 层的介入:** 如果启用了 fortification，并且代码在 API 级别 23 或更高版本上运行，那么实际执行的 `poll` 函数是 `fortify/poll.handroid` 中定义的加固版本。

4. **编译时检查 (在编译时):** 当使用 NDK 编译包含 `poll` 调用的代码时，Clang 编译器会根据 `fortify/poll.handroid` 中的 `__clang_error_if` 进行静态分析，检查潜在的缓冲区溢出。

5. **运行时检查 (在运行时):** 当应用在 Android 设备上运行时，调用 `poll` 时，会首先执行 `fortify/poll.handroid` 中定义的内联函数。根据运行时条件，可能会调用 `__poll_chk` 等函数进行更严格的检查。

6. **最终调用系统调用:** 如果所有安全检查都通过，最终会通过 `__call_bypassing_fortify` 调用到内核的 `poll` 系统调用。

**Frida hook 示例调试这些步骤:**

可以使用 Frida hook `poll` 函数来观察 fortification 的行为。以下是一个示例，hook 了 `poll` 函数，并打印了其参数和返回值：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

def main():
    package_name = "your.target.package"  # 替换为目标应用的包名

    try:
        device = frida.get_usb_device()
        session = device.attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"[-] Process '{package_name}' not found. Make sure the app is running.")
        sys.exit(1)

    script_code = """
    Interceptor.attach(Module.findExportByName("libc.so", "poll"), {
        onEnter: function(args) {
            var fds = ptr(args[0]);
            var nfds = args[1].toInt();
            var timeout = args[2].toInt();

            console.log("[*] poll called");
            console.log("    fds: " + fds);
            console.log("    nfds: " + nfds);
            console.log("    timeout: " + timeout);

            // 可以读取 fds 数组的内容进行更详细的检查
            // for (let i = 0; i < nfds; i++) {
            //     console.log("    fds[" + i + "].fd: " + Memory.readS32(fds.add(i * Process.pointerSize * 2)));
            //     console.log("    fds[" + i + "].events: " + Memory.readS16(fds.add(i * Process.pointerSize * 2 + Process.pointerSize)));
            // }
        },
        onLeave: function(retval) {
            console.log("[*] poll returned: " + retval);
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    input("[+] Press Enter to detach from the process...\n")
    session.detach()

if __name__ == '__main__':
    main()
```

**解释 Frida Hook 代码:**

1. **`frida.get_usb_device()` 和 `device.attach(package_name)`:** 连接到 USB 设备上的目标 Android 应用进程。
2. **`Module.findExportByName("libc.so", "poll")`:**  找到 `libc.so` 中导出的 `poll` 函数的地址。默认情况下，这将 hook 到加固后的 `poll` 版本。
3. **`Interceptor.attach(...)`:** 拦截对 `poll` 函数的调用。
4. **`onEnter`:** 在 `poll` 函数执行之前调用。打印了 `fds` 指针、`nfds` 和 `timeout` 参数。可以进一步读取 `fds` 数组的内容。
5. **`onLeave`:** 在 `poll` 函数执行之后调用。打印了返回值。

**要 hook 未加固的 `poll` 版本或检查 `__poll_chk` 的调用:**

可以尝试 hook `__poll_chk` 函数，或者通过一些技巧（例如，找到 `__call_bypassing_fortify` 调用的目标地址）来 hook 到未加固的版本。但直接 hook `poll` 通常已经足够观察到 fortification 的影响，因为加固后的版本是实际被调用的入口点。

通过这种方式，可以观察到在调用 `poll` 时，传递给它的参数，以及它的返回值，从而理解 fortification 机制在运行时是如何工作的。如果 `nfds` 超出范围，你可能会在 Frida 的输出中看到相关的错误信息，或者观察到 `poll` 返回错误。

### 提示词
```
这是目录为bionic/libc/include/bits/fortify/poll.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef _POLL_H_
#error "Never include this file directly; instead, include <poll.h>"
#endif


#if __BIONIC_AVAILABILITY_GUARD(23)
int __poll_chk(struct pollfd* _Nullable, nfds_t, int, size_t) __INTRODUCED_IN(23);
int __ppoll_chk(struct pollfd* _Nullable, nfds_t, const struct timespec* _Nullable, const sigset_t* _Nullable, size_t) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(28)
int __ppoll64_chk(struct pollfd* _Nullable, nfds_t, const struct timespec* _Nullable, const sigset64_t* _Nullable, size_t) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */


#if defined(__BIONIC_FORTIFY)
#define __bos_fd_count_trivially_safe(bos_val, fds, fd_count)              \
  __bos_dynamic_check_impl_and((bos_val), >=, (sizeof(*fds) * (fd_count)), \
                               (fd_count) <= __BIONIC_CAST(static_cast, nfds_t, -1) / sizeof(*fds))

__BIONIC_FORTIFY_INLINE
int poll(struct pollfd* _Nullable const fds __pass_object_size, nfds_t fd_count, int timeout)
    __overloadable
    __clang_error_if(__bos_unevaluated_lt(__bos(fds), sizeof(*fds) * fd_count),
                     "in call to 'poll', fd_count is larger than the given buffer") {
#if __ANDROID_API__ >= 23 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
  size_t bos_fds = __bos(fds);

  if (!__bos_fd_count_trivially_safe(bos_fds, fds, fd_count)) {
    return __poll_chk(fds, fd_count, timeout, bos_fds);
  }
#endif
  return __call_bypassing_fortify(poll)(fds, fd_count, timeout);
}

__BIONIC_FORTIFY_INLINE
int ppoll(struct pollfd* _Nullable const fds __pass_object_size, nfds_t fd_count, const struct timespec* _Nullable timeout, const sigset_t* _Nullable mask)
    __overloadable
    __clang_error_if(__bos_unevaluated_lt(__bos(fds), sizeof(*fds) * fd_count),
                     "in call to 'ppoll', fd_count is larger than the given buffer") {
#if __ANDROID_API__ >= 23 && __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
  size_t bos_fds = __bos(fds);

  if (!__bos_fd_count_trivially_safe(bos_fds, fds, fd_count)) {
    return __ppoll_chk(fds, fd_count, timeout, mask, bos_fds);
  }
#endif
  return __call_bypassing_fortify(ppoll)(fds, fd_count, timeout, mask);
}

#if __ANDROID_API__ >= 28
__BIONIC_FORTIFY_INLINE
int ppoll64(struct pollfd* _Nullable const fds __pass_object_size, nfds_t fd_count, const struct timespec* _Nullable timeout, const sigset64_t* _Nullable mask)
    __overloadable
    __clang_error_if(__bos_unevaluated_lt(__bos(fds), sizeof(*fds) * fd_count),
                     "in call to 'ppoll64', fd_count is larger than the given buffer") {
#if __BIONIC_FORTIFY_RUNTIME_CHECKS_ENABLED
  size_t bos_fds = __bos(fds);

  if (!__bos_fd_count_trivially_safe(bos_fds, fds, fd_count)) {
    return __ppoll64_chk(fds, fd_count, timeout, mask, bos_fds);
  }
#endif
  return __call_bypassing_fortify(ppoll64)(fds, fd_count, timeout, mask);
}
#endif /* __ANDROID_API__ >= 28 */

#undef __bos_fd_count_trivially_safe

#endif /* defined(__BIONIC_FORTIFY) */
```