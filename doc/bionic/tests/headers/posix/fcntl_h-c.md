Response:
Let's break down the thought process to answer the user's request about `bionic/tests/headers/posix/fcntl_h.c`.

**1. Understanding the Core Question:**

The user wants to know the *purpose* of this specific C file and how it relates to Android. The file name itself (`fcntl_h.c`) and its location (`bionic/tests/headers/posix/`) provide crucial hints. It's a test file for the `fcntl.h` header within Bionic.

**2. Identifying the Key Components in the Code:**

Scanning the code reveals a pattern of `MACRO()` and `FUNCTION()`. This immediately suggests the file is designed to check for the *existence* of specific macros, constants, types, and function declarations defined in the `fcntl.h` header file.

**3. Connecting to the Purpose of Header Files:**

Header files in C (like `fcntl.h`) are meant to declare interfaces – the blueprints for how functions and data structures should look. They don't contain the actual *implementation* of those functions.

**4. Inferring the Test's Functionality:**

Given that it's a test file checking for declarations, the primary function is *validation*. It ensures that the `fcntl.h` header provided by Bionic includes all the necessary POSIX-standard elements related to file control.

**5. Relating to Android and Bionic:**

Bionic is Android's C library. `fcntl.h` is a standard POSIX header, and Android aims for a high degree of POSIX compliance. Therefore, this test file ensures that Bionic's implementation of `fcntl.h` meets these standards. This is important for application compatibility – developers expect standard POSIX functions to be available and work as expected on Android.

**6. Addressing Specific Instructions (and Planning the Response Structure):**

Now, let's go through each specific point raised in the user's request:

* **功能 (Functionality):**  This is directly addressed by the analysis above – it's a header test.

* **与 Android 的关系 (Relationship with Android):** Explain the role of Bionic and how ensuring POSIX compliance benefits Android app development. Provide examples of `fcntl` usage in Android (opening files, setting flags, file locking).

* **详细解释 libc 函数的功能是如何实现的 (Detailed explanation of libc function implementations):**  This is a trap!  This test file *doesn't* contain the implementations. It only checks for declarations. It's crucial to explicitly state this and clarify that the *implementations* are in other parts of Bionic's source code (e.g., within syscall wrappers or kernel interactions). Briefly mention the interaction with the Linux kernel.

* **涉及 dynamic linker 的功能 (Dynamic linker functionality):**  `fcntl.h` itself doesn't directly involve the dynamic linker. However, the functions *declared* in it (like `open`, `fcntl`) are part of libc.so, which *is* dynamically linked. Explain this indirect relationship. Provide a basic `libc.so` layout and the linking process (simplified).

* **逻辑推理，给出假设输入与输出 (Logical reasoning with input/output):** Since this is a header test, the "input" is the compilation process itself. The "output" is either successful compilation (if all declarations are present) or a compilation error (if something is missing). This needs to be explained in that context.

* **用户或者编程常见的使用错误 (Common user/programming errors):**  Focus on common mistakes when *using* the `fcntl` family of functions: incorrect flags, forgetting to check return values, race conditions with file locking, etc. Provide code examples.

* **说明 android framework or ndk 是如何一步步的到达这里 (How Android framework/NDK reaches here):**  Start with a high-level overview (app using NDK, NDK using Bionic headers). Trace the path from a Java app to native code and how the NDK provides access to Bionic's headers, including `fcntl.h`.

* **给出 frida hook 示例调试这些步骤 (Frida hook example):** Provide a practical Frida script to intercept calls to functions declared in `fcntl.h` (like `open`). Explain how this helps in debugging.

**7. Structuring the Response:**

Organize the answer clearly, addressing each of the user's points in order. Use headings and bullet points to improve readability. Use clear and concise language.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Could I explain the low-level kernel calls involved in `fcntl`?  **Correction:**  No, the request is about *this specific file*. Focus on the header and its purpose as a test. Mention kernel interaction generally, but don't dive into syscall details for each function implementation.

* **Initial thought:** Should I provide all possible `fcntl` flags and constants? **Correction:** No, the file itself lists them. Focus on the *purpose* of the file checking for their existence. Give a few key examples to illustrate.

* **Realization:** The user asked about dynamic linking *related to this file*. While the *file itself* doesn't directly involve the linker, the *functions it declares* do. Clarify this indirect relationship.

By following this thought process, breaking down the request, and focusing on the specific information contained within the provided source code, the detailed and accurate answer can be constructed.
这个 `bionic/tests/headers/posix/fcntl_h.c` 文件是 Android Bionic 库中的一个测试文件，其主要功能是 **验证 `fcntl.h` 头文件是否正确定义了 POSIX 标准中关于文件控制的各种宏、常量、结构体和函数声明。**

简单来说，它不是一个实际执行文件操作的代码，而是一个用来确保 `fcntl.h` 内容符合预期的检查工具。

**具体功能列表:**

1. **检查宏定义 (MACRO):** 验证 `fcntl.h` 中是否定义了以下宏：
    * 文件描述符操作相关的宏 (例如 `F_DUPFD`, `F_GETFD`, `F_SETFD`)
    * 文件状态标志相关的宏 (例如 `F_GETFL`, `F_SETFL`)
    * 文件锁相关的宏 (例如 `F_GETLK`, `F_SETLK`, `F_SETLKW`, `F_RDLCK`, `F_WRLCK`, `F_UNLCK`)
    * 文件所有者相关的宏 (例如 `F_GETOWN`, `F_SETOWN`)
    * 文件描述符标志相关的宏 (例如 `FD_CLOEXEC`)
    * 文件偏移量相关的宏 (例如 `SEEK_SET`, `SEEK_CUR`, `SEEK_END`)
    * `open` 系统调用的标志位宏 (例如 `O_CREAT`, `O_RDONLY`, `O_WRONLY`, `O_APPEND`, `O_NONBLOCK` 等)
    * 目录操作相关的宏 (例如 `O_DIRECTORY`, `O_NOFOLLOW`)
    * 原子操作相关的宏 (例如 `AT_FDCWD`, `AT_EACCESS`, `AT_SYMLINK_NOFOLLOW`, `AT_REMOVEDIR`)
    * 文件预读相关的宏 (例如 `POSIX_FADV_DONTNEED`, `POSIX_FADV_NOREUSE` 等)

2. **检查结构体定义 (TYPE, STRUCT_MEMBER):** 验证 `fcntl.h` 中是否正确定义了以下结构体及其成员：
    * `struct flock`: 用于文件锁操作的结构体，检查其成员 `l_type`, `l_whence`, `l_start`, `l_len`, `l_pid` 是否存在且类型正确。

3. **检查类型定义 (TYPE):** 验证 `fcntl.h` 中是否定义了以下类型：
    * `mode_t`: 用于表示文件权限的类型。
    * `off_t`: 用于表示文件偏移量的类型。
    * `pid_t`: 用于表示进程 ID 的类型。

4. **检查函数声明 (FUNCTION):** 验证 `fcntl.h` 中是否声明了以下函数，并检查其函数签名是否正确：
    * `creat`: 创建新文件或覆盖已存在的文件。
    * `fcntl`: 执行各种文件控制操作。
    * `open`: 打开文件。
    * `openat`: 相对于目录文件描述符打开文件。
    * `posix_fadvise`: 向系统提供文件访问模式的建议。
    * `posix_fallocate`: 预先分配文件空间。

**与 Android 功能的关系及举例说明:**

`fcntl.h` 中定义的宏、常量、结构体和函数是 Linux/POSIX 标准中进行底层文件操作的基础。Android 作为基于 Linux 内核的操作系统，其 C 库 (Bionic) 必须提供这些标准接口，以便应用程序能够进行文件操作。

* **文件打开和关闭:**  `open` 和 `close` (虽然 `close` 不在此文件中，但与 `open` 息息相关) 是最基本的文件操作。Android 应用程序，无论是 Java 层还是 Native 层，在访问文件系统时都会间接地使用这些函数。例如，Java 中的 `FileInputStream` 或 `FileOutputStream` 底层会调用 `open` 系统调用。NDK 开发中使用 `fopen` 等标准 C 库函数最终也会通过 Bionic 调用底层的 `open`。
* **文件读写:**  `read` 和 `write` (同样不在本文件，但与 `fcntl` 紧密相关) 用于读写文件内容。Android 应用进行数据持久化、网络通信等都离不开文件的读写。
* **文件锁:** `fcntl` 函数配合 `F_GETLK`, `F_SETLK`, `F_SETLKW` 等命令可以实现文件锁，用于在多进程或多线程环境中同步对文件的访问，避免数据竞争。例如，一些数据库或缓存机制可能会使用文件锁来保证数据一致性。
* **文件状态标志:** `fcntl` 函数配合 `F_GETFL` 和 `F_SETFL` 可以获取和设置文件的状态标志，例如是否以非阻塞模式打开 (`O_NONBLOCK`)、是否以追加模式打开 (`O_APPEND`) 等。Android 系统在处理 I/O 操作时会使用这些标志。
* **原子操作:** `openat` 等带 `at` 后缀的函数允许相对于目录文件描述符进行操作，避免了在多线程或多进程环境下因路径名解析导致的 TOCTOU (Time-of-check to time-of-use) 漏洞。Android 系统在进行安全敏感的文件操作时可能会使用这些原子操作。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个测试文件本身并不包含这些 libc 函数的实现，它只是检查声明。这些函数的实际实现位于 Bionic 库的源代码中，通常会涉及到系统调用 (syscall)。

* **`creat(const char *pathname, mode_t mode)`:**  `creat` 函数用于创建一个新的空文件。它的实现通常会调用底层的 `open` 系统调用，并指定 `O_CREAT | O_WRONLY | O_TRUNC` 标志。`mode` 参数指定了新文件的权限。
* **`fcntl(int fd, int cmd, ...)`:** `fcntl` 是一个功能非常强大的函数，用于对已打开的文件描述符执行各种控制操作。它的实现会根据 `cmd` 参数的值调用不同的底层系统调用。例如：
    * `F_DUPFD`: 复制文件描述符，通常调用 `dup` 或 `dup2` 系统调用。
    * `F_GETFL`: 获取文件状态标志，通常调用 `fcntl` 系统调用并传递 `F_GETFL`。
    * `F_SETFL`: 设置文件状态标志，通常调用 `fcntl` 系统调用并传递 `F_SETFL`。
    * `F_GETLK`, `F_SETLK`, `F_SETLKW`: 执行文件锁操作，通常调用 `fcntl` 系统调用并传递相应的命令以及 `struct flock` 结构体。
* **`open(const char *pathname, int flags, ...)`:** `open` 函数用于打开一个文件。它的实现会调用底层的 `open` 系统调用。`flags` 参数指定了打开文件的模式 (只读、只写、读写) 以及其他选项 (例如 `O_CREAT`, `O_TRUNC`, `O_NONBLOCK` 等)。如果指定了 `O_CREAT`，则需要提供 `mode` 参数来设置新文件的权限。
* **`openat(int dirfd, const char *pathname, int flags, ...)`:** `openat` 与 `open` 类似，但它允许相对于一个目录文件描述符 `dirfd` 打开文件。如果 `dirfd` 是 `AT_FDCWD`，则行为与 `open` 相同。它的实现会调用底层的 `openat` 系统调用。
* **`posix_fadvise(int fd, off_t offset, off_t len, int advice)`:** `posix_fadvise` 函数用于向系统提供关于文件访问模式的建议，以帮助系统优化 I/O 操作。例如，可以建议系统预读数据 (`POSIX_FADV_WILLNEED`) 或释放缓存 (`POSIX_FADV_DONTNEED`). 它的实现会调用底层的 `fadvise` 系统调用。
* **`posix_fallocate(int fd, off_t offset, off_t len)`:** `posix_fallocate` 函数用于预先为文件分配空间，这可以避免在后续写入数据时因动态分配空间而产生的性能开销和文件碎片。它的实现会调用底层的 `fallocate` 系统调用。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

`fcntl.h` 本身并不直接涉及 dynamic linker 的功能。它定义的是与文件操作相关的接口。但是，这些接口的实现 (例如 `open`, `fcntl` 等函数) 位于 Bionic 的动态链接库 `libc.so` 中。应用程序需要通过 dynamic linker 加载 `libc.so` 才能使用这些函数。

**`libc.so` 布局样本 (简化):**

```
libc.so:
    .text          (代码段 - 包含 open, fcntl 等函数的机器码)
    .rodata        (只读数据段 - 包含字符串常量等)
    .data          (已初始化数据段 - 包含全局变量等)
    .bss           (未初始化数据段 - 包含全局变量等)
    .dynsym        (动态符号表 - 包含导出的函数和变量的符号信息)
    .dynstr        (动态字符串表 - 包含符号名称的字符串)
    .plt           (Procedure Linkage Table - 用于延迟绑定)
    .got           (Global Offset Table - 用于存储全局变量的地址)
    ...
```

**链接的处理过程 (简化):**

1. **编译时:** 当应用程序的代码中使用了 `open` 或 `fcntl` 等函数时，编译器会生成对这些函数的未解析引用。这些引用会记录在应用程序的可执行文件或共享库的 `.dynsym` 和 `.rel.plt` (或 `.rel.dyn`) 段中。

2. **加载时:** 当 Android 系统加载应用程序时，dynamic linker (通常是 `/system/bin/linker64` 或 `/system/bin/linker`) 负责解析这些动态链接。

3. **查找共享库:** dynamic linker 会根据应用程序的依赖关系查找需要的共享库，例如 `libc.so`。

4. **符号解析:** 对于应用程序中未解析的 `open` 和 `fcntl` 等符号，dynamic linker 会在 `libc.so` 的 `.dynsym` 中查找匹配的符号。

5. **重定位:** 找到匹配的符号后，dynamic linker 会修改应用程序的 `.got` (Global Offset Table) 或 `.plt` (Procedure Linkage Table) 中的条目，使其指向 `libc.so` 中 `open` 和 `fcntl` 函数的实际地址。

6. **延迟绑定 (Lazy Binding):**  为了提高启动速度，通常会使用延迟绑定。这意味着在程序第一次调用 `open` 或 `fcntl` 时，dynamic linker 才会进行符号解析和重定位。PLT (Procedure Linkage Table) 中的代码会负责跳转到 dynamic linker 进行解析，解析完成后再跳转到实际的函数地址。后续的调用将直接跳转到已经解析的地址。

**假设输入与输出 (针对测试文件):**

由于这个文件是测试文件，它的输入是 Bionic 库的源代码，特别是 `fcntl.h` 头文件。

**假设输入:**  Bionic 的 `fcntl.h` 文件内容正确定义了所有 POSIX 标准中关于文件控制的宏、常量、结构体和函数声明。

**预期输出:**  `bionic/tests/headers/posix/fcntl_h.c` 编译和运行成功，没有报错。这表明 `fcntl.h` 的定义是符合预期的。

**假设输入:**  Bionic 的 `fcntl.h` 文件缺少了 `F_DUPFD_CLOEXEC` 宏的定义。

**预期输出:** `bionic/tests/headers/posix/fcntl_h.c` 在编译或运行时会因为找不到 `F_DUPFD_CLOEXEC` 的宏定义而报错。

**用户或者编程常见的使用错误，请举例说明:**

1. **忘记检查 `fcntl` 等函数的返回值:** 这些函数调用失败时通常会返回 -1，并设置 `errno` 来指示错误原因。不检查返回值可能导致程序出现未预期的行为。

   ```c
   int fd = open("myfile.txt", O_RDONLY);
   if (fd == -1) {
       perror("open"); // 打印错误信息
       // 处理错误情况
   }
   ```

2. **文件锁使用不当导致死锁:** 在多进程或多线程环境中使用文件锁时，如果多个进程或线程互相等待对方释放锁，就会发生死锁。

   ```c
   // 进程 1
   struct flock fl;
   fl.l_type = F_WRLCK;
   // ... 设置其他 flock 成员
   fcntl(fd1, F_SETLKW, &fl); // 进程 1 获取 fd1 的写锁

   // ... 一些操作

   // 进程 2
   struct flock fl2;
   fl2.l_type = F_WRLCK;
   // ... 设置其他 flock 成员
   fcntl(fd2, F_SETLKW, &fl2); // 进程 2 获取 fd2 的写锁

   // 如果进程 1 还需要获取 fd2 的锁，而进程 2 需要获取 fd1 的锁，则可能发生死锁。
   ```

3. **使用错误的 `fcntl` 命令:**  对文件描述符使用错误的 `fcntl` 命令会导致操作失败或产生未定义行为。

   ```c
   int flags = fcntl(fd, F_GETFL);
   // 错误地尝试设置一个不应该设置的标志
   fcntl(fd, F_SETFL, flags | O_CREAT); // O_CREAT 通常只在 open 时使用
   ```

4. **在多线程环境中使用非线程安全的操作:**  虽然 `fcntl` 本身是线程安全的，但对其返回的文件描述符进行的操作可能不是线程安全的。需要使用适当的同步机制来保护共享资源。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework (Java 层):**  Android Framework 中的 Java 代码通常不会直接调用 `open` 或 `fcntl` 等 POSIX 函数。相反，它会使用 Java 提供的 I/O 类，例如 `FileInputStream`, `FileOutputStream`, `RandomAccessFile` 等。

2. **Android Framework (Native 层):**  这些 Java I/O 类的底层实现通常会通过 JNI (Java Native Interface) 调用 Android Runtime (ART) 或 Dalvik 虚拟机提供的 Native 方法。

3. **Android Runtime (ART/Dalvik):** ART/Dalvik 的 Native 方法会调用 Bionic 库中提供的标准 C 库函数，例如 `open`, `read`, `write`, `fcntl` 等。

4. **Bionic 库:** Bionic 库是 Android 的 C 库，它实现了 POSIX 标准的 API。`bionic/tests/headers/posix/fcntl_h.c` 就是 Bionic 库的一部分，用于测试 `fcntl.h` 头文件的正确性。`open` 和 `fcntl` 等函数的实现位于 Bionic 库的其他源文件中，最终会通过系统调用与 Linux 内核交互。

5. **Linux Kernel:** Linux 内核负责实际的文件系统操作。系统调用 (例如 `open`, `fcntl`, `read`, `write`) 是用户空间程序与内核空间交互的接口。

**NDK 的路径:**

如果 Android 应用程序使用 NDK 进行 Native 开发，那么 Native 代码可以直接包含 `<fcntl.h>` 头文件，并调用 `open`, `fcntl` 等函数。NDK 工具链会链接到 Bionic 库，因此 Native 代码中调用的这些函数实际上是 Bionic 库中的实现。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `open` 系统调用的示例：

```javascript
if (Process.platform === 'android') {
  const openPtr = Module.findExportByName("libc.so", "open");
  if (openPtr) {
    Interceptor.attach(openPtr, {
      onEnter: function (args) {
        const pathname = Memory.readUtf8String(args[0]);
        const flags = args[1].toInt();
        console.log(`[open] pathname: ${pathname}, flags: ${flags}`);
      },
      onLeave: function (retval) {
        console.log(`[open] returned: ${retval}`);
      }
    });
  } else {
    console.log("Could not find 'open' function in libc.so");
  }
} else {
  console.log("This script is designed for Android.");
}
```

**使用方法:**

1. 将上述代码保存为 `hook_open.js`。
2. 使用 Frida 连接到目标 Android 进程：`frida -U -f <package_name> -l hook_open.js --no-pause`  (将 `<package_name>` 替换为目标应用的包名)。

**调试步骤:**

1. 运行包含文件操作的 Android 应用程序。
2. Frida 脚本会拦截对 `open` 函数的调用，并在控制台输出传递给 `open` 函数的路径名和标志，以及 `open` 函数的返回值 (文件描述符)。

通过修改 Frida 脚本，你可以拦截其他 `fcntl.h` 中声明的函数，例如 `fcntl`, `openat` 等，并查看它们的参数和返回值，从而调试应用程序的文件操作行为，理解 Android Framework 或 NDK 如何最终调用到这些底层函数。

这个测试文件本身并不会被 Frida 直接 hook，因为它只是一个测试工具。你 hook 的是 Bionic 库中实际实现 `open` 和 `fcntl` 等函数的代码。

Prompt: 
```
这是目录为bionic/tests/headers/posix/fcntl_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <fcntl.h>

#include "header_checks.h"

static void fcntl_h() {
  MACRO(F_DUPFD);
  MACRO(F_DUPFD_CLOEXEC);
  MACRO(F_GETFD);
  MACRO(F_SETFD);
  MACRO(F_GETFL);
  MACRO(F_SETFL);
  MACRO(F_GETLK);
  MACRO(F_SETLK);
  MACRO(F_SETLKW);
  MACRO(F_GETOWN);
  MACRO(F_SETOWN);

  MACRO(FD_CLOEXEC);

  MACRO(F_RDLCK);
  MACRO(F_UNLCK);
  MACRO(F_WRLCK);

  MACRO(SEEK_SET);
  MACRO(SEEK_CUR);
  MACRO(SEEK_END);

  MACRO(O_CLOEXEC);
  MACRO(O_CREAT);
  MACRO(O_DIRECTORY);
  MACRO(O_EXCL);
  MACRO(O_NOCTTY);
  MACRO(O_NOFOLLOW);
  MACRO(O_TRUNC);
#if !defined(__linux__)
  MACRO(O_TTY_INIT);
#endif

  MACRO(O_APPEND);
  MACRO(O_DSYNC);
  MACRO(O_NONBLOCK);
  MACRO(O_RSYNC);
  MACRO(O_SYNC);

  MACRO(O_ACCMODE);

#if !defined(__linux__)
  MACRO(O_EXEC);
#endif
  MACRO(O_RDONLY);
  MACRO(O_RDWR);
#if !defined(__linux__)
  MACRO(O_SEARCH);
#endif
  MACRO(O_WRONLY);

  // POSIX: "The <fcntl.h> header shall define the symbolic constants for
  // file modes for use as values of mode_t as described in <sys/stat.h>."
  // Musl only defines the file mode bits (S_IFUSR, etc.) and not the file
  // type bits (S_IFMT, etc.).
#if !defined(ANDROID_HOST_MUSL)
#include "sys_stat_h_mode_constants.h"
#endif

  MACRO(AT_FDCWD);
#if !defined(__BIONIC__) // See comment in "faccessat.cpp".
  MACRO(AT_EACCESS);
#endif
  MACRO(AT_SYMLINK_NOFOLLOW);
  MACRO(AT_REMOVEDIR);

  MACRO(POSIX_FADV_DONTNEED);
  MACRO(POSIX_FADV_NOREUSE);
  MACRO(POSIX_FADV_NORMAL);
  MACRO(POSIX_FADV_RANDOM);
  MACRO(POSIX_FADV_SEQUENTIAL);
  MACRO(POSIX_FADV_WILLNEED);

  TYPE(struct flock);
  STRUCT_MEMBER(struct flock, short, l_type);
  STRUCT_MEMBER(struct flock, short, l_whence);
  STRUCT_MEMBER(struct flock, off_t, l_start);
  STRUCT_MEMBER(struct flock, off_t, l_len);
  STRUCT_MEMBER(struct flock, pid_t, l_pid);

  TYPE(mode_t);
  TYPE(off_t);
  TYPE(pid_t);

  FUNCTION(creat, int (*f)(const char*, mode_t));
  FUNCTION(fcntl, int (*f)(int, int, ...));
  FUNCTION(open, int (*f)(const char*, int, ...));
  FUNCTION(openat, int (*f)(int, const char*, int, ...));
  FUNCTION(posix_fadvise, int (*f)(int, off_t, off_t, int));
  FUNCTION(posix_fallocate, int (*f)(int, off_t, off_t));
}

"""

```