Response:
Let's break down the thought process for generating the comprehensive answer to the request about `bionic/libc/bionic/dup.cpp`.

**1. Understanding the Core Request:**

The request is about a specific source file in Android's Bionic library. The key is to analyze its functionality, its relation to Android, its implementation details, and how it's used. The request also asks for examples, debugging approaches, and explanations for potential errors.

**2. Initial Code Analysis:**

The first step is to read the provided C++ code carefully. I identify the three exported functions: `dup`, `dup2`, and `dup3`. I also notice the usage of `__dup` and `__dup3`, implying these are the underlying system calls (or close to it). The `FDTRACK_CREATE` macro is also apparent, suggesting a file descriptor tracking mechanism within Bionic.

**3. Functionality Identification:**

Based on the function names and standard C library knowledge, I immediately recognize the purpose of `dup`, `dup2`, and `dup3`: creating duplicate file descriptors.

**4. Relationship to Android:**

Since Bionic is Android's C library, these functions are fundamental for any Android process that interacts with files, sockets, or other file-like objects. This connection is direct and crucial.

**5. Implementation Details - Deconstructing Each Function:**

*   **`dup(int old_fd)`:**  This is the simplest. It calls `__dup(old_fd)` and wraps the result with `FDTRACK_CREATE`. The core functionality relies on the underlying system call.
*   **`dup2(int old_fd, int new_fd)`:**  This function has a special case: if `old_fd == new_fd`, it checks if `old_fd` is valid and returns it directly. Otherwise, it uses `__dup3` with flags set to 0. This addresses a subtle difference in behavior between `dup2` and `dup3`.
*   **`dup3(int old_fd, int new_fd, int flags)`:** This directly calls `__dup3` and wraps the result with `FDTRACK_CREATE`. The `flags` argument allows for more control (specifically `O_CLOEXEC`).

**6. Exploring `__dup` and `__dup3` (Logical Inference):**

Since these functions have the `__` prefix, they are likely internal Bionic functions, closely tied to the system calls. I infer that `__dup` is a thin wrapper around the `dup()` system call, and `__dup3` is a thin wrapper around the `dup3()` system call. This assumption is reasonable given the naming convention and the context.

**7. Dynamic Linker Implications:**

While the `dup.cpp` code itself doesn't directly involve dynamic linking, the *existence* of this code within `libc.so` (Bionic's C library) is a dynamic linking concern. When an application uses `dup`, the dynamic linker must resolve this symbol to the implementation in `libc.so`.

*   **SO Layout:**  I need to imagine a simplified layout of `libc.so`, showing where the `dup` family of functions would reside.
*   **Linking Process:** I need to describe the steps the dynamic linker takes to find and bind the `dup` functions when an application starts or dynamically loads a shared library.

**8. Logical Reasoning - Assumptions and Outputs:**

I need to illustrate the behavior of `dup`, `dup2`, and `dup3` with simple examples. This involves assuming input file descriptors and showing the resulting new file descriptors. It's important to cover successful cases and error cases (like invalid file descriptors).

**9. Common Usage Errors:**

Think about how developers might misuse these functions. Forgetting to close duplicated file descriptors is a classic memory leak (or file descriptor leak in this case). Using incorrect flags with `dup3` is another potential issue.

**10. Android Framework/NDK Path:**

How does a high-level Android application end up calling these low-level functions?  I need to trace the call stack from the Android Framework (Java) or the NDK (C/C++) down to the Bionic library.

*   **Java Framework:**  Operations like `FileInputStream`, `FileOutputStream` eventually delegate to native code.
*   **NDK:** Direct use of C standard library functions.

**11. Frida Hooking:**

Demonstrate how to use Frida to intercept calls to these functions. This involves identifying the function names within `libc.so` and providing a basic JavaScript hook.

**12. Structuring the Answer:**

Organize the information logically, using headings and bullet points for clarity. Start with a summary of the functionality, then delve into details for each aspect: implementation, dynamic linking, examples, errors, and debugging.

**Self-Correction/Refinement during the process:**

*   Initially, I might focus too much on the low-level system calls. I need to ensure I also address the Android-specific context and the role of Bionic.
*   The dynamic linking explanation needs to be clear and concise, without getting bogged down in excessive detail about the linker's internal workings. A high-level overview is sufficient.
*   The Frida example should be basic but functional, showing the core concept of intercepting function calls.
*   Ensure the language is clear and accessible, avoiding overly technical jargon where possible. Explanations should be tailored to a developer who understands basic C/C++ but might not be intimately familiar with Bionic internals.

By following this thought process, breaking down the problem into smaller parts, and considering the different aspects of the request, I can construct a comprehensive and informative answer like the example provided.
好的，让我们详细分析一下 `bionic/libc/bionic/dup.cpp` 这个文件。

**功能列举:**

这个文件主要实现了以下三个与文件描述符复制相关的 C 标准库函数：

1. **`dup(int old_fd)`**:  复制一个现有的文件描述符。它返回一个新的文件描述符，该描述符与 `old_fd` 指向相同的文件、管道或套接字。新文件描述符与原文件描述符共享文件偏移量和文件状态标志。
2. **`dup2(int old_fd, int new_fd)`**:  类似于 `dup`，但允许你指定新文件描述符的数值。如果 `new_fd` 已经打开，它会先被关闭。如果 `old_fd` 是一个有效的文件描述符，并且 `old_fd` 等于 `new_fd`，则 `dup2` 直接返回 `new_fd` 而不关闭它。
3. **`dup3(int old_fd, int new_fd, int flags)`**:  这是 `dup2` 的更通用的版本，允许通过 `flags` 参数传递额外的控制选项。目前在 Bionic 中，唯一支持的 flag 是 `O_CLOEXEC`，它可以设置新文件描述符的 close-on-exec 标志。

**与 Android 功能的关系及举例说明:**

这些函数在 Android 中扮演着至关重要的角色，因为 Android 系统及其上的应用程序广泛地使用文件描述符来管理各种 I/O 操作，包括文件读写、网络通信、进程间通信等。

*   **进程重定向 I/O:**  `dup2` 经常用于重定向标准输入、标准输出和标准错误。例如，一个 shell 命令可以使用 `dup2` 将一个文件的内容定向到另一个进程的标准输入，或者将一个进程的标准输出定向到一个文件。

    ```c++
    // 假设我们想要将程序输出重定向到一个名为 "output.txt" 的文件
    int fd = open("output.txt", O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        perror("open");
        exit(1);
    }

    // 将标准输出 (文件描述符 1) 复制到 fd
    if (dup2(fd, STDOUT_FILENO) == -1) {
        perror("dup2");
        exit(1);
    }

    close(fd); // 关闭原始的文件描述符，因为标准输出现在指向它所指向的文件

    printf("This will be written to output.txt\n");
    ```

*   **管道操作:**  在使用 `pipe()` 创建管道进行进程间通信时，`dup2` 可以用来将管道的读端或写端复制到进程的标准输入或输出，从而实现数据在进程间的流动。

    ```c++
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("pipe");
        exit(1);
    }

    // 创建子进程
    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        exit(1);
    }

    if (pid == 0) { // 子进程 (接收数据)
        close(pipefd[1]); // 关闭写端
        dup2(pipefd[0], STDIN_FILENO); // 将读端复制到标准输入
        close(pipefd[0]);
        // 现在子进程可以从标准输入读取数据 (实际上是从管道读取)
        char buffer[256];
        ssize_t n = read(STDIN_FILENO, buffer, sizeof(buffer) - 1);
        if (n > 0) {
            buffer[n] = '\0';
            printf("Child received: %s\n", buffer);
        }
    } else { // 父进程 (发送数据)
        close(pipefd[0]); // 关闭读端
        dup2(pipefd[1], STDOUT_FILENO); // 将写端复制到标准输出
        close(pipefd[1]);
        // 现在父进程可以向标准输出写入数据 (实际上是写入管道)
        printf("Hello from parent!\n");
    }
    ```

*   **网络编程:**  在网络编程中，当使用 `accept()` 接受一个新的连接时，会返回一个新的文件描述符。可以使用 `dup` 或 `dup2` 来复制这个文件描述符，以便在不同的部分或线程中处理同一个连接。

*   **文件锁定:**  虽然 `dup` 系列函数本身不直接用于文件锁定，但复制文件描述符可能会影响文件锁定的行为，因为多个文件描述符可能指向同一个文件，需要注意锁的范围和共享性。

**libc 函数的实现细节:**

让我们逐个分析 `dup.cpp` 中每个函数的实现：

1. **`dup(int old_fd)`:**
    ```c++
    int dup(int old_fd) {
      return FDTRACK_CREATE(__dup(old_fd));
    }
    ```
    -   `dup` 函数直接调用了 `__dup(old_fd)`。
    -   `__dup`  (在 Bionic 中，以 `__` 开头的函数通常是系统调用的封装)  很可能直接或间接地调用了 Linux 内核的 `dup` 系统调用。
    -   `FDTRACK_CREATE` 是一个 Bionic 内部的宏，用于跟踪文件描述符的创建。这可能涉及到记录文件描述符的来源、生命周期等信息，用于调试和资源管理。

    **内核 `dup` 系统调用的实现 (简化描述):**
    -   检查 `old_fd` 是否是一个有效的文件描述符。
    -   查找当前进程的文件描述符表（每个进程都有一个文件描述符表）。
    -   找到表中第一个可用的空闲条目。
    -   将 `old_fd` 对应的文件表项（包含文件偏移量、访问模式等信息）的引用计数加 1。
    -   在新找到的空闲条目中，指向 `old_fd` 对应的文件表项。
    -   返回新文件描述符的索引。

2. **`dup2(int old_fd, int new_fd)`:**
    ```c++
    int dup2(int old_fd, int new_fd) {
      // If old_fd is equal to new_fd and a valid file descriptor, dup2 returns
      // old_fd without closing it. This is not true of dup3, so we have to
      // handle this case ourselves.
      if (old_fd == new_fd) {
        if (fcntl(old_fd, F_GETFD) == -1) {
          return -1;
        }
        return old_fd;
      }

      return FDTRACK_CREATE(__dup3(old_fd, new_fd, 0));
    }
    ```
    -   首先，它处理一个特殊情况：如果 `old_fd` 等于 `new_fd`。在这种情况下，如果 `old_fd` 是一个有效的文件描述符（通过 `fcntl(old_fd, F_GETFD)` 检查），则直接返回 `old_fd`，而不会关闭它。这是 `dup2` 和 `dup3` 的一个区别。
    -   如果 `old_fd` 不等于 `new_fd`，则调用 `__dup3(old_fd, new_fd, 0)`。
    -   `__dup3` 很可能直接或间接地调用了 Linux 内核的 `dup3` 系统调用，并将 `flags` 设置为 0。

    **内核 `dup2` 系统调用的实现 (简化描述):**
    -   检查 `old_fd` 是否是一个有效的文件描述符。
    -   检查 `new_fd` 是否在有效的文件描述符范围内。
    -   如果 `new_fd` 已经打开，则关闭它（相当于调用 `close(new_fd)`）。
    -   将 `old_fd` 复制到文件描述符表中的 `new_fd` 位置，过程类似于 `dup`。
    -   返回 `new_fd`。

3. **`dup3(int old_fd, int new_fd, int flags)`:**
    ```c++
    int dup3(int old_fd, int new_fd, int flags) {
      return FDTRACK_CREATE(__dup3(old_fd, new_fd, flags));
    }
    ```
    -   `dup3` 函数直接调用了 `__dup3(old_fd, new_fd, flags)`，并将传入的 `flags` 参数传递下去。
    -   `__dup3` 很可能直接或间接地调用了 Linux 内核的 `dup3` 系统调用。

    **内核 `dup3` 系统调用的实现 (简化描述):**
    -   与 `dup2` 类似，但增加了对 `flags` 的处理。
    -   目前 Linux 内核 `dup3` 最常用的 flag 是 `O_CLOEXEC`。如果设置了这个 flag，则新创建的文件描述符的 close-on-exec 标志会被设置。这意味着当进程调用 `execve` 执行新的程序时，这个文件描述符会被自动关闭。这对于防止子进程意外继承不应该继承的文件描述符非常重要。

**涉及 dynamic linker 的功能:**

虽然 `dup.cpp` 的代码本身并不直接涉及 dynamic linker 的具体操作，但作为 `libc.so` 的一部分，它的存在和使用都依赖于 dynamic linker。

**SO 布局样本:**

假设 `libc.so` 的部分布局如下（简化表示）：

```
libc.so:
    .text:
        ...
        dup:  // dup 函数的代码
            ...
        dup2: // dup2 函数的代码
            ...
        dup3: // dup3 函数的代码
            ...
        __dup: // __dup 函数的代码 (可能是系统调用的封装)
            ...
        __dup3: // __dup3 函数的代码 (可能是系统调用的封装)
            ...
        fcntl: // fcntl 函数的代码 (被 dup2 使用)
            ...
        ...
    .data:
        ...
    .bss:
        ...
    .dynsym: // 动态符号表
        dup
        dup2
        dup3
        fcntl
        ...
    .dynstr: // 动态字符串表
        "dup"
        "dup2"
        "dup3"
        "fcntl"
        ...
    .rel.plt: // PLT 重定位表
        ...
```

**链接的处理过程:**

当一个应用程序（例如通过 NDK 编译的 C/C++ 程序）调用 `dup`、`dup2` 或 `dup3` 时，链接过程如下：

1. **编译时:** 编译器会生成对 `dup` 等函数的未解析符号引用。
2. **链接时:** 静态链接器（如果存在）会将应用程序代码与必要的库（包括 `libc.so`）链接起来。如果采用动态链接，则只建立符号引用关系。
3. **运行时:** 当应用程序启动时，Android 的 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 负责加载应用程序依赖的共享库，包括 `libc.so`。
4. **符号解析:** Dynamic linker 会遍历应用程序和其依赖的共享库的动态符号表 (`.dynsym`)，查找未解析的符号。当遇到对 `dup` 的引用时，linker 会在 `libc.so` 的 `.dynsym` 中找到 `dup` 的定义。
5. **重定位:** Linker 会修改应用程序的指令，将对 `dup` 的符号引用替换为 `libc.so` 中 `dup` 函数的实际地址。这通常通过 Procedure Linkage Table (PLT) 和 Global Offset Table (GOT) 来实现。当第一次调用 `dup` 时，会通过 PLT 跳转到 linker 的代码，linker 会解析 `dup` 的地址并更新 GOT 表项，后续的调用可以直接通过 GOT 跳转到 `dup` 的实现。

**假设输入与输出 (逻辑推理):**

*   **`dup(old_fd)`:**
    *   **假设输入:** `old_fd = 3` (假设文件描述符 3 是一个打开的文件)。
    *   **预期输出:** 返回一个新的文件描述符（例如 `new_fd = 4`），该描述符也指向与文件描述符 3 相同的文件。对 `new_fd` 的操作（如修改文件偏移量）也会影响到 `old_fd`，反之亦然。
    *   **假设输入:** `old_fd = -1` (无效的文件描述符)。
    *   **预期输出:** 返回 `-1`，并设置 `errno` 为 `EBADF` (Bad file descriptor)。

*   **`dup2(old_fd, new_fd)`:**
    *   **假设输入:** `old_fd = 3`, `new_fd = 5` (假设文件描述符 5 当前已打开)。
    *   **预期输出:** 如果成功，文件描述符 5 将会被关闭，并成为文件描述符 3 的副本。返回值为 5。
    *   **假设输入:** `old_fd = 3`, `new_fd = 3`.
    *   **预期输出:** 返回 `3`，不会关闭文件描述符 3。
    *   **假设输入:** `old_fd = -1`, `new_fd = 5`.
    *   **预期输出:** 返回 `-1`，并设置 `errno` 为 `EBADF`.

*   **`dup3(old_fd, new_fd, flags)`:**
    *   **假设输入:** `old_fd = 3`, `new_fd = 5`, `flags = 0`.
    *   **预期输出:** 行为与 `dup2(old_fd, new_fd)` 相同。
    *   **假设输入:** `old_fd = 3`, `new_fd = 5`, `flags = O_CLOEXEC`.
    *   **预期输出:** 文件描述符 5 成为文件描述符 3 的副本，并且其 close-on-exec 标志被设置。
    *   **假设输入:** `old_fd = 3`, `new_fd = 5`, `flags = 未定义的标志`.
    *   **预期输出:**  可能会返回 `-1`，并设置 `errno` 为 `EINVAL` (Invalid argument)。

**用户或编程常见的使用错误:**

1. **忘记关闭复制的文件描述符:**  每次调用 `dup`、`dup2` 或 `dup3` 成功后，都会创建一个新的文件描述符。如果不使用了，必须使用 `close()` 函数关闭它，否则会导致文件描述符泄漏，最终可能耗尽进程的文件描述符资源。

    ```c++
    int fd1 = open("myfile.txt", O_RDONLY);
    int fd2 = dup(fd1);
    // ... 使用 fd1 和 fd2 ...
    close(fd1);
    // 容易忘记关闭 fd2
    ```

2. **在多线程环境中使用 `dup2` 时出现竞争条件:**  如果多个线程同时尝试使用 `dup2` 修改同一个文件描述符，可能会导致意想不到的结果。需要使用互斥锁或其他同步机制来保护对 `dup2` 的调用。

3. **错误地假设复制的文件描述符拥有独立的属性:**  复制的文件描述符共享文件偏移量和文件状态标志。例如，如果在一个复制的文件描述符上调用 `lseek` 修改了文件偏移量，那么原始文件描述符的文件偏移量也会受到影响。

4. **不理解 `dup2` 的特殊情况:**  可能会忘记 `dup2(old_fd, old_fd)` 不会关闭 `old_fd`。

5. **在不需要时使用 `dup3` 的 `O_CLOEXEC` 标志:**  虽然设置 `O_CLOEXEC` 是一个好的实践，但在某些情况下可能不需要，增加了一点点开销。

**Android framework 或 NDK 如何到达这里:**

1. **Android Framework (Java 代码):**
    当 Java 代码执行涉及文件 I/O 的操作时，最终会调用底层的 Native 代码。例如：
    -   `FileInputStream`, `FileOutputStream`: 这些类的方法最终会调用 `open()` 系统调用来获取文件描述符。如果需要复制文件描述符，可能会在 Native 层调用 `dup` 或 `dup2`。
    -   `Socket`:  Socket 操作也涉及文件描述符。例如，`java.net.Socket.getInputStream()` 和 `getOutputStream()` 返回的流与底层的 socket 文件描述符关联。在实现细节中，可能需要复制文件描述符。
    -   `ProcessBuilder`:  当使用 `ProcessBuilder` 启动新的进程并重定向其标准输入/输出/错误时，会使用 `pipe()` 创建管道，然后使用 `dup2()` 将管道的读端或写端复制到子进程的相应文件描述符。

    **Frida Hook 示例 (Java 层可能比较复杂，通常在 Native 层更容易 Hook):**

2. **NDK (Native 代码):**
    使用 NDK 开发的 C/C++ 代码可以直接调用 `dup`、`dup2` 和 `dup3` 这些 libc 函数。

    **Frida Hook 示例 (Native 代码):**

    假设你想 hook `dup` 函数：

    ```javascript
    // 连接到目标进程
    var process = Process.getCurrentProcess();
    var module = Process.getModuleByName("libc.so"); // 或者你的应用加载的包含 dup 的库

    // 获取 dup 函数的地址
    var dupAddress = module.getExportByName("dup");

    if (dupAddress) {
        console.log("Found dup at address:", dupAddress);

        // Intercept dup 函数
        Interceptor.attach(dupAddress, {
            onEnter: function (args) {
                console.log("dup called with old_fd:", args[0]);
            },
            onLeave: function (retval) {
                console.log("dup returned new_fd:", retval);
            }
        });
    } else {
        console.log("Could not find dup function.");
    }
    ```

    **更详细的 Frida Hook 示例 (Hook `dup2` 并查看参数):**

    ```javascript
    // 连接到目标进程 (如果尚未连接)
    // ...

    var libc = Process.getModuleByName("libc.so");
    var dup2Ptr = libc.getExportByName("dup2");

    if (dup2Ptr) {
        Interceptor.attach(dup2Ptr, {
            onEnter: function (args) {
                this.old_fd = args[0].toInt32();
                this.new_fd = args[1].toInt32();
                console.log("dup2 called with old_fd:", this.old_fd, ", new_fd:", this.new_fd);
            },
            onLeave: function (retval) {
                console.log("dup2 returned:", retval.toInt32());
            }
        });
        console.log("Successfully hooked dup2");
    } else {
        console.log("Failed to find dup2");
    }
    ```

    **调试步骤 (结合 Frida):**

    1. **确定目标进程:** 运行你想要调试的 Android 应用。
    2. **编写 Frida 脚本:**  如上面的示例，编写 JavaScript 代码来 hook `dup`、`dup2` 或 `dup3`。
    3. **连接 Frida 到目标进程:** 使用 Frida CLI 或 API 将脚本注入到目标进程。例如：
        ```bash
        frida -U -f <包名> -l your_hook_script.js --no-pause
        ```
        或者，如果进程已经在运行：
        ```bash
        frida -U <包名> -l your_hook_script.js
        ```
    4. **触发相关代码:** 在你的 Android 应用中执行会导致调用 `dup` 系列函数的操作（例如，打开文件，创建管道，重定向 I/O 等）。
    5. **查看 Frida 输出:**  Frida 会在控制台输出你脚本中 `console.log` 的信息，显示 `dup` 函数的调用参数和返回值，从而帮助你理解代码的执行流程和参数传递。

希望这个详细的解释能够帮助你理解 `bionic/libc/bionic/dup.cpp` 的功能和在 Android 中的作用。

Prompt: 
```
这是目录为bionic/libc/bionic/dup.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <fcntl.h>
#include <unistd.h>

#include "private/bionic_fdtrack.h"

extern "C" int __dup(int old_fd);
extern "C" int __dup3(int old_fd, int new_fd, int flags);

int dup(int old_fd) {
  return FDTRACK_CREATE(__dup(old_fd));
}

int dup2(int old_fd, int new_fd) {
  // If old_fd is equal to new_fd and a valid file descriptor, dup2 returns
  // old_fd without closing it. This is not true of dup3, so we have to
  // handle this case ourselves.
  if (old_fd == new_fd) {
    if (fcntl(old_fd, F_GETFD) == -1) {
      return -1;
    }
    return old_fd;
  }

  return FDTRACK_CREATE(__dup3(old_fd, new_fd, 0));
}

int dup3(int old_fd, int new_fd, int flags) {
  return FDTRACK_CREATE(__dup3(old_fd, new_fd, flags));
}

"""

```