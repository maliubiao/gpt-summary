Response:
Let's break down the thought process for answering the request about `bionic/tests/sys_signalfd_test.cpp`.

**1. Understanding the Goal:**

The request asks for a comprehensive analysis of the given C++ test file within the Android Bionic library. The key is to identify its purpose, explain the functions it uses, discuss its relation to Android, address dynamic linking, consider usage errors, and explore how to trace its execution.

**2. Initial Code Scan and Purpose Identification:**

The first step is to quickly read the code to get a general idea. I see `#include` directives for standard C/C++ headers like `<errno.h>`, `<signal.h>`, `<sys/signalfd.h>`, `<unistd.h>`, and also `<gtest/gtest.h>` (indicating a unit test). The core functions used are `signalfd`, `signalfd64`, `sigprocmask`, `sigprocmask64`, `raise`, and `read`. The `TEST` macros strongly suggest this file is designed to test the `signalfd` and `signalfd64` system calls.

**3. Function Breakdown (libc and System Calls):**

Now, I'll go through each included header and the functions they provide:

*   **`<errno.h>`:**  Provides `errno` and related error codes. Used here by `strerror` for better error messages.
*   **`<fcntl.h>`:** Provides file control options like `SFD_CLOEXEC`. This flag is used with `signalfd` to ensure the file descriptor is closed on `execve`.
*   **`<signal.h>`:**  Crucial for signal handling. Defines signal numbers (like `SIGALRM`, `SIGRTMIN`), signal sets (`sigset_t`, `sigset64_t`), and functions like `sigaddset`, `sigprocmask`, `sigprocmask64`, and `raise`.
*   **`<sys/signalfd.h>`:** The heart of the test. Declares the `signalfd` and `signalfd64` system calls and the `signalfd_siginfo` structure.
*   **`<unistd.h>`:** Standard POSIX functions like `read` and `close`. `read` is used to read signal information from the file descriptor created by `signalfd`.
*   **`<thread>`:** Used for creating a separate thread, but it's *not* used in the provided code snippet. It was likely intended for testing signal handling across threads but is currently commented out. I need to mention this observation.
*   **`"SignalUtils.h"`:**  This is a Bionic-specific header, likely containing helper classes like `SignalMaskRestorer`. I need to describe its likely purpose (RAII to restore signal masks).

For each function, I'll explain:

*   **What it does:** A concise description of its primary function.
*   **How it's implemented (general idea):**  For system calls like `signalfd`, I'll explain it involves transitioning to the kernel. For libc functions like `sigaddset`, I'll describe how it manipulates the bits in the signal set.

**4. Android Relevance and Examples:**

Now, connect the dots to Android:

*   **Signal Handling in Android:** Explain that signal handling is fundamental for inter-process communication, error handling, and lifecycle management in Android.
*   **`signalfd`'s Usefulness:**  Describe how `signalfd` allows treating signals as file events, making them easier to integrate into event loops like `epoll` or `poll`, which are common in Android's system services.
*   **Example:**  Give a concrete example of how an Android service might use `signalfd` to handle shutdown signals gracefully.

**5. Dynamic Linker Aspects:**

*   **Identify Involvement:**  The code itself doesn't *directly* use dynamic linker functions. However, *any* C++ executable on Android will involve the dynamic linker (`linker64` or `linker`).
*   **SO Layout:**  Provide a basic example of an SO (Shared Object) layout, showing sections like `.text`, `.data`, `.bss`, `.plt`, `.got`.
*   **Linking Process:**  Explain the high-level linking process: resolving symbols, relocation, and the role of the PLT and GOT. Emphasize that in this *test* context, the linking is relatively simple as it mainly links against libc and libm.

**6. Logic and Input/Output:**

*   **Focus on the Tests:**  The core logic is within the `TestSignalFd` function and the two test cases (`signalfd` and `signalfd64`).
*   **Assumption:**  Assume the tests are run in an environment where signals can be sent and handled.
*   **Input/Output for `TestSignalFd`:**
    *   Input: A valid file descriptor (`fd`) from `signalfd` and a signal number (`signal`).
    *   Output:  The function asserts that a signal was raised, that reading from the file descriptor returns the signal information, and that the signal number in the read data matches the raised signal.

**7. Common Usage Errors:**

Think about how developers might misuse `signalfd`:

*   **Forgetting to block signals:**  Crucial to prevent the default signal handlers from running.
*   **Not handling errors from `signalfd` or `read`:**  Important for robust code.
*   **Incorrect signal mask:**  Specifying the wrong set of signals.
*   **Closing the file descriptor prematurely:** Leading to errors when trying to read.

**8. Android Framework/NDK Tracing with Frida:**

*   **Explain the Path:** Describe how a signal might originate from a framework component (e.g., ActivityManager sending a signal to an app process) or from NDK code.
*   **Frida Basics:** Introduce Frida as a dynamic instrumentation tool.
*   **Hooking Points:** Identify key functions to hook:
    *   `signalfd` (to see when it's called and with what arguments).
    *   `raise` (to observe signal generation).
    *   Potentially `sigaction` or `signal` (though `signalfd` often replaces direct signal handlers).
*   **Frida Script Example:** Provide a concrete JavaScript example of how to hook `signalfd` and log its arguments.

**9. Language and Structure:**

*   **Chinese Response:**  Remember the request is for a Chinese response.
*   **Organization:** Structure the answer logically with clear headings for each part of the request.
*   **Clarity and Detail:**  Provide enough detail to be informative but avoid unnecessary jargon. Explain concepts like signal masks and file descriptors clearly.

**Self-Correction/Refinement during the process:**

*   **Initial thought:** Focus heavily on multi-threading signal handling. **Correction:** Notice the `std::thread` code is commented out. While relevant to `signalfd` in general, it's not central to *this specific test*. Adjust the emphasis.
*   **Initial thought:** Dive deep into the kernel implementation of `signalfd`. **Correction:** The request asks for the *function* of the libc functions. Keep the explanation at a high level for system calls – the focus is on how *to use* them.
*   **Initial thought:**  Assume a deep understanding of dynamic linking. **Correction:** Explain the concepts clearly, providing a basic SO layout and a simplified overview of the linking process relevant to the test context.

By following this structured approach and continuously refining the information, I can generate a comprehensive and accurate answer to the user's request.
这个文件 `bionic/tests/sys_signalfd_test.cpp` 是 Android Bionic 库中的一个单元测试文件。它的主要功能是测试 `signalfd` 和 `signalfd64` 这两个系统调用。这两个系统调用允许应用程序创建一个文件描述符，通过读取这个文件描述符可以接收发送给该进程的信号。

下面对文件中的功能进行详细解释：

**1. 功能列举:**

*   **测试 `signalfd` 系统调用:** 验证 `signalfd` 系统调用是否能够正确地创建一个文件描述符，并通过该文件描述符接收预期的信号 (`SIGALRM`)。
*   **测试 `signalfd64` 系统调用:** 验证 `signalfd64` 系统调用是否能够正确地创建一个文件描述符，并通过该文件描述符接收实时信号 (`SIGRTMIN`)。`signalfd64` 是 `signalfd` 的 64 位版本，用于处理更广泛的信号集。
*   **测试 `SFD_CLOEXEC` 标志:** 验证在使用 `signalfd` 和 `signalfd64` 时，指定 `SFD_CLOEXEC` 标志能够确保创建的文件描述符在 `execve` 系统调用后被自动关闭。
*   **使用 `gtest` 框架进行单元测试:** 利用 Google Test 框架来组织和执行测试用例，并进行断言判断。

**2. 与 Android 功能的关系及举例说明:**

`signalfd` 和 `signalfd64` 是 POSIX 标准定义的系统调用，它们在各种 Unix-like 系统中都存在，包括 Android。它们在 Android 中的作用体现在：

*   **系统服务中的信号处理:** Android 系统服务通常需要监听和处理各种信号，例如进程终止信号、用户自定义信号等。`signalfd` 使得服务可以将信号处理集成到其事件循环中（例如使用 `epoll` 或 `poll`），使得信号像其他文件描述符事件一样被处理。
    *   **举例说明:**  假设一个 Android 系统服务需要优雅地处理 `SIGTERM` 信号（终止信号）。它可以创建一个 `signalfd` 监听 `SIGTERM`，并在服务的主循环中通过 `read` 读取该文件描述符。当收到 `SIGTERM` 时，`read` 会返回，服务可以执行清理工作然后退出。
*   **应用程序中的信号处理:** 虽然 Android 应用开发更倾向于使用 Android 提供的组件和机制（如 `BroadcastReceiver`），但在某些底层开发或者需要细粒度控制的场景下，NDK 开发人员可能会使用 `signalfd` 来处理信号。
    *   **举例说明:** 一个使用 NDK 开发的游戏引擎可能需要捕获特定的信号来执行自定义的操作，例如在收到特定信号时保存游戏状态。

**3. libc 函数的功能及实现:**

*   **`signalfd(int fd, const sigset_t *mask, int flags)` 和 `signalfd64(int fd, const sigset64_t *mask, int flags)`:**
    *   **功能:** 创建一个用于接收信号的文件描述符。
    *   **实现:** 这两个是系统调用，会陷入内核。内核创建一个新的文件描述符，并将其关联到调用进程的信号处理机制。`mask` 参数指定了哪些信号将通过这个文件描述符传递。`flags` 可以包含 `SFD_CLOEXEC` 等标志。如果 `fd` 参数为 -1，则内核会分配一个新的文件描述符；如果指定了一个已存在的文件描述符，并且该文件描述符已经被 `signalfd` 使用，则会修改其监听的信号集（这在测试代码中没有体现）。
*   **`sigemptyset(sigset_t *set)` 和 `sigemptyset64(sigset64_t *set)`:**
    *   **功能:** 初始化信号集 `set`，使其不包含任何信号。
    *   **实现:**  将 `sigset_t` 或 `sigset64_t` 结构体中的所有位都设置为 0。
*   **`sigaddset(sigset_t *set, int signum)` 和 `sigaddset64(sigset64_t *set, int signum)`:**
    *   **功能:** 将指定的信号 `signum` 添加到信号集 `set` 中。
    *   **实现:**  在 `sigset_t` 或 `sigset64_t` 结构体中，找到与 `signum` 对应的位，并将其设置为 1。
*   **`sigprocmask(int how, const sigset_t *newmask, sigset_t *oldmask)` 和 `sigprocmask64(int how, const sigset64_t *newmask, sigset64_t *oldmask)`:**
    *   **功能:**  检查或更改进程的信号屏蔽字（哪些信号会被阻塞）。
    *   **实现:** 这是一个系统调用，会陷入内核。内核根据 `how` 参数（例如 `SIG_BLOCK`，`SIG_UNBLOCK`，`SIG_SETMASK`）来修改进程的信号屏蔽字。`newmask` 指定了新的屏蔽字，`oldmask` 如果非空，则用于返回之前的屏蔽字。**重要的是，为了让 `signalfd` 能够接收信号，这些信号必须被阻塞（block）。否则，信号会按照默认或自定义的信号处理函数处理，而不会传递给 `signalfd`。**
*   **`raise(int sig)`:**
    *   **功能:** 向当前进程发送信号 `sig`。
    *   **实现:** 这是一个库函数，它通常会调用底层的 `kill` 系统调用，将信号发送给当前进程。
*   **`read(int fd, void *buf, size_t count)`:**
    *   **功能:** 从文件描述符 `fd` 中读取最多 `count` 字节的数据到缓冲区 `buf` 中。
    *   **实现:** 这是一个系统调用，会陷入内核。当用于 `signalfd` 创建的文件描述符时，如果没有信号到达，`read` 会阻塞。一旦有被监听的信号到达，`read` 会返回，并将一个 `signalfd_siginfo` 结构体的数据写入到 `buf` 中。
*   **`close(int fd)`:**
    *   **功能:** 关闭文件描述符 `fd`。
    *   **实现:** 这是一个系统调用，会陷入内核，释放与该文件描述符相关的内核资源。
*   **`strerror(int errnum)`:**
    *   **功能:**  将错误码 `errnum` 转换为对应的错误信息字符串。
    *   **实现:**  这是一个库函数，通常会查找一个预定义的错误码到错误消息的映射表。

**4. 涉及 dynamic linker 的功能 (虽然此代码本身不直接涉及，但运行依赖于它):**

这个测试程序本身是一个可执行文件，它依赖于动态链接器来加载其依赖的共享库，例如 libc 和 libgtest。

**so 布局样本 (以 libc.so 为例):**

```
libc.so:
    .interp        # 指向动态链接器的路径
    .note.android.ident
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .hash          # 符号哈希表
    .gnu.version   # 版本信息
    .gnu.version_r # 版本重定位信息
    .rel.dyn       # 数据段重定位信息
    .rel.plt       # PLT 重定位信息
    .plt           # 程序链接表 (Procedure Linkage Table)
    .text          # 代码段
    .rodata        # 只读数据段
    .data          # 已初始化数据段
    .bss           # 未初始化数据段
    ...
```

**链接的处理过程:**

1. **加载:** 当操作系统启动这个测试程序时，首先会加载动态链接器（通常是 `/system/bin/linker64` 或 `/system/bin/linker`）。
2. **解析 ELF 头:** 动态链接器读取测试程序 ELF 头的 `.interp` 段，找到需要使用的动态链接器自身。
3. **加载依赖库:** 动态链接器解析测试程序的 ELF 头，找到需要加载的共享库（例如 libc.so, libgtest.so）。它会根据一定的搜索路径找到这些库，并加载到内存中。
4. **符号解析和重定位:**
    *   测试程序中调用了 libc 中的函数（如 `signalfd`, `sigprocmask` 等）以及 libgtest 的函数（如 `ASSERT_EQ`）。这些函数的地址在编译时是未知的，需要动态链接器在运行时进行解析。
    *   **PLT (Procedure Linkage Table):**  当测试程序第一次调用一个外部函数时，会跳转到 PLT 中相应的条目。
    *   **GOT (Global Offset Table):** PLT 条目会跳转到 GOT 中对应的位置。GOT 最初包含的是一个回到 PLT 的地址。
    *   **动态链接器介入:** 动态链接器通过 GOT 中的信息，找到所需函数的实际地址（在 libc.so 中）。
    *   **更新 GOT:** 动态链接器将找到的函数地址写入 GOT 中。
    *   **后续调用:**  后续对同一个外部函数的调用会直接跳转到 GOT 中已更新的地址，避免了重复的解析过程。
5. **执行:** 动态链接过程完成后，操作系统将控制权交给测试程序的入口点开始执行。

**5. 假设输入与输出 (针对 `TestSignalFd` 函数):**

*   **假设输入:**
    *   `fd`: 一个由 `signalfd` 或 `signalfd64` 成功创建的文件描述符。
    *   `signal`: 一个整数，表示要发送的信号，例如 `SIGALRM`。
*   **逻辑推理:**
    1. `ASSERT_NE(-1, fd)`: 断言文件描述符 `fd` 是有效的（创建成功）。
    2. `ASSERT_EQ(0, raise(signal))`: 向当前进程发送信号 `signal`，断言发送成功。
    3. `ASSERT_EQ(static_cast<ssize_t>(sizeof(sfd_si)), read(fd, &sfd_si, sizeof(sfd_si)))`:  从 `fd` 中读取数据到 `sfd_si` 结构体中，断言读取的字节数等于 `signalfd_siginfo` 结构体的大小。这说明有信号到达了 `fd`。
    4. `ASSERT_EQ(signal, static_cast<int>(sfd_si.ssi_signo))`: 断言读取到的信号编号 `sfd_si.ssi_signo` 与发送的信号 `signal` 相等。
    5. `close(fd)`: 关闭文件描述符。
*   **预期输出:** 如果一切正常，所有断言都会通过，测试用例执行成功。

**6. 用户或编程常见的使用错误:**

*   **忘记阻塞信号:**  如果在使用 `signalfd` 之前没有使用 `sigprocmask` 阻塞要监听的信号，那么信号可能会被默认处理程序捕获，而不会传递给 `signalfd`。
    ```c++
    // 错误示例：忘记阻塞信号
    int sfd;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sfd = signalfd(-1, &mask, 0); // 创建 signalfd

    // ... 期待从 sfd 读取 SIGINT，但可能信号已经被默认处理了
    ```
*   **错误处理 `signalfd` 的返回值:**  `signalfd` 调用失败时会返回 -1，并设置 `errno`。必须检查返回值并处理错误。
    ```c++
    int sfd = signalfd(-1, &mask, 0);
    if (sfd == -1) {
        perror("signalfd"); // 输出错误信息
        // 进行错误处理
    }
    ```
*   **`read` 调用错误处理:**  从 `signalfd` 读取数据时，`read` 可能返回 -1 (出错) 或 0 (在某些情况下，例如文件描述符被提前关闭)。需要检查 `read` 的返回值。
*   **信号屏蔽字设置错误:**  设置了错误的信号屏蔽字，导致 `signalfd` 监听了不期望的信号，或者错过了期望的信号。
*   **过早关闭文件描述符:**  在仍然需要接收信号时关闭了 `signalfd` 返回的文件描述符。

**7. Android framework or ndk 如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `signalfd` 的路径 (示例场景：系统服务处理信号):**

1. **系统服务启动:** Android 系统服务（例如 `ActivityManagerService`）通常运行在一个独立的进程中。
2. **信号注册 (可选):**  某些系统服务可能需要处理特定的信号。虽然不常见，但服务可以使用 JNI 调用 NDK 代码，然后在 NDK 代码中使用 `signalfd`。
3. **信号发送:**  Android Framework 的其他组件或内核可能会向该服务进程发送信号。例如，`init` 进程可能会发送信号来管理服务的生命周期。
4. **NDK 代码中的 `signalfd` 处理:** 如果服务使用了 `signalfd`，其 NDK 代码中的事件循环会通过 `read` 系统调用等待 `signalfd` 返回。
5. **信号到达:** 当发送给服务进程的信号与 `signalfd` 监听的信号匹配时，`read` 系统调用会返回，并将信号信息读取到缓冲区。
6. **信号处理:** NDK 代码根据读取到的信号信息执行相应的处理逻辑。

**NDK 代码直接使用 `signalfd`:**

1. **NDK 开发:** 开发者在 NDK 代码中包含 `<sys/signalfd.h>` 头文件。
2. **创建 `signalfd`:**  使用 `signalfd` 或 `signalfd64` 系统调用创建一个用于接收特定信号的文件描述符。
3. **信号屏蔽:** 使用 `sigprocmask` 阻塞需要 `signalfd` 接收的信号。
4. **事件循环:**  在 NDK 代码的事件循环中，使用 `read` 系统调用监听 `signalfd` 文件描述符。
5. **信号发送:**  其他进程或当前进程自身可以使用 `kill` 或 `raise` 发送信号。
6. **信号处理:**  当 `read` 返回时，处理接收到的信号。

**Frida Hook 示例:**

假设我们想观察一个使用了 `signalfd` 的 NDK 应用是如何创建和读取信号的。我们可以使用 Frida hook `signalfd` 和 `read` 系统调用。

```javascript
// Hook signalfd 系统调用
Interceptor.attach(Module.findExportByName(null, "signalfd"), {
  onEnter: function (args) {
    const fd = args[0].toInt32();
    const mask = args[1];
    const flags = args[2].toInt32();
    console.log("signalfd called with fd:", fd, "mask:", mask, "flags:", flags);

    // 可以进一步解析 mask 中的信号
    if (mask.isNull() === false) {
      const sigset = Memory.readByteArray(mask, Process.pageSize); // 假设页大小足够容纳信号集
      console.log("  Signal Mask (raw):", hexdump(sigset));
      // TODO: 解析 sigset 中的具体信号
    }
  },
  onLeave: function (retval) {
    console.log("signalfd returned:", retval);
  },
});

// Hook read 系统调用
Interceptor.attach(Module.findExportByName(null, "read"), {
  onEnter: function (args) {
    const fd = args[0].toInt32();
    const buf = args[1];
    const count = args[2].toInt32();
    this.isSignalfd = false;
    // 判断是否是对 signalfd 文件描述符的读取 (可能需要一些应用特定的逻辑来判断)
    // 这里只是一个简单的假设：如果 fd 大于某个值，可能是 signalfd 创建的
    if (fd > 1000) {
      this.isSignalfd = true;
      console.log("Potentially reading from signalfd:", fd, "count:", count);
    }
  },
  onLeave: function (retval) {
    if (this.isSignalfd && retval.toInt32() > 0) {
      const fd = this.context.r0.toInt32(); // 不同架构寄存器可能不同
      const buf = this.context.r1;
      const readBytes = retval.toInt32();
      const signalInfo = Memory.readByteArray(buf, readBytes);
      console.log("Read from signalfd:", fd, "bytes:", readBytes);
      console.log("  Signal Info (raw):", hexdump(signalInfo));
      // TODO: 解析 signalInfo 结构体 (signalfd_siginfo)
    }
  },
});
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件（例如 `hook_signalfd.js`）。
2. 使用 Frida 连接到目标 Android 进程：
    ```bash
    frida -U -f <your_app_package_name> -l hook_signalfd.js --no-pause
    ```
    或者，如果进程已经在运行：
    ```bash
    frida -U <your_app_package_name> -l hook_signalfd.js
    ```
3. 运行目标应用，Frida 会在 `signalfd` 和 `read` 系统调用被调用时打印相关信息，帮助你观察信号的创建和读取过程。你需要根据 `signalfd_siginfo` 结构体的定义来解析 `read` 返回的数据，以获取具体的信号信息。

这个测试文件是 Bionic 库中用于确保 `signalfd` 和 `signalfd64` 这两个重要系统调用在 Android 环境下正常工作的关键组成部分。理解其功能有助于深入理解 Android 底层的信号处理机制。

Prompt: 
```
这是目录为bionic/tests/sys_signalfd_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2018 The Android Open Source Project
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

#include <gtest/gtest.h>

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/signalfd.h>
#include <unistd.h>

#include <thread>

#include "SignalUtils.h"

static void TestSignalFd(int fd, int signal) {
  ASSERT_NE(-1, fd) << strerror(errno);

  ASSERT_EQ(0, raise(signal));

  signalfd_siginfo sfd_si;
  ASSERT_EQ(static_cast<ssize_t>(sizeof(sfd_si)), read(fd, &sfd_si, sizeof(sfd_si)));

  ASSERT_EQ(signal, static_cast<int>(sfd_si.ssi_signo));

  close(fd);
}

TEST(sys_signalfd, signalfd) {
  SignalMaskRestorer smr;

  sigset_t mask = {};
  sigaddset(&mask, SIGALRM);
  ASSERT_EQ(0, sigprocmask(SIG_SETMASK, &mask, nullptr));

  TestSignalFd(signalfd(-1, &mask, SFD_CLOEXEC), SIGALRM);
}

TEST(sys_signalfd, signalfd64) {
#if defined(__BIONIC__)
  SignalMaskRestorer smr;

  sigset64_t mask = {};
  sigaddset64(&mask, SIGRTMIN);
  ASSERT_EQ(0, sigprocmask64(SIG_SETMASK, &mask, nullptr));

  TestSignalFd(signalfd64(-1, &mask, SFD_CLOEXEC), SIGRTMIN);
#endif
}

"""

```