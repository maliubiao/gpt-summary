Response:
Let's break down the thought process for answering the request about `bionic/tests/sys_stat_test.cpp`.

**1. Understanding the Goal:**

The core request is to analyze a C++ test file within Android's Bionic library. This means understanding what the tests are checking, the libc functions involved, and how they relate to Android's functionality, including the dynamic linker. The request also asks for examples of usage errors, tracing with Frida, and explanations of how the framework reaches these functions.

**2. Initial Scan and High-Level Overview:**

The first step is to quickly read through the code to get a general idea of what it does. I see a series of `TEST` macros, which immediately tells me this is a Google Test file. The test names (`futimens`, `mkfifo`, `stat64_lstat64_fstat64`, etc.) hint at the system calls being tested. The `#include` directives confirm the involvement of standard C library headers like `<sys/stat.h>`, `<fcntl.h>`, and `<errno.h>`. The inclusion of `<android-base/file.h>` and `"utils.h"` indicates some Android-specific testing utilities are being used.

**3. Deconstructing Each Test Case:**

Next, I'd go through each `TEST` case individually and analyze its purpose:

* **`futimens`:**  Tests the `futimens` function, which sets file access and modification times using a file descriptor. It verifies the success case.
* **`futimens_EBADF`:** Tests the error handling of `futimens` when given an invalid file descriptor.
* **`mkfifo_failure`:** Tests the failure case of `mkfifo` when attempting to create a FIFO at an invalid path.
* **`mkfifoat_failure`:** Tests the failure case of `mkfifoat` when given an invalid directory file descriptor.
* **`mkfifo`:** Tests the successful creation of a FIFO using `mkfifo`. It includes a check for root privileges due to SELinux restrictions.
* **`stat64_lstat64_fstat64`:** Tests the 64-bit versions of `stat`, `lstat`, and `fstat`.
* **`statx`:** Tests the `statx` function, which provides more detailed file status information. It includes a check for kernel support.
* **`fchmod_EBADF`:** Tests the error handling of `fchmod` with an invalid file descriptor.
* **`fchmodat_*`:** A series of tests for `fchmodat`, covering various error conditions (invalid file pointer, bad flags, non-existent file) and successful modification of file and symbolic link permissions. It also explicitly addresses the behavior differences between Bionic and glibc regarding `AT_SYMLINK_NOFOLLOW`.
* **`faccessat_*`:** Tests for `faccessat`, verifying file accessibility with different flags and handling of symbolic links. Again, differences between Bionic and glibc are noted.
* **`lchmod`:** Tests `lchmod`, which changes the permissions of a symbolic link itself (if the kernel supports it).

**4. Identifying Key libc Functions and Their Functionality:**

As I analyze each test, I list the libc functions being tested and describe their purpose:

* **`futimens(int fd, const struct timespec times[2])`:** Sets the access and modification times of the file referred to by the file descriptor `fd`.
* **`fstat(int fd, struct stat *buf)`:** Gets file status information based on a file descriptor.
* **`mkfifo(const char *pathname, mode_t mode)`:** Creates a FIFO (named pipe) at the given path.
* **`mkfifoat(int dirfd, const char *pathname, mode_t mode)`:** Creates a FIFO relative to a directory file descriptor.
* **`stat64(const char *pathname, struct stat64 *buf)`:** Gets 64-bit file status information for a given path.
* **`lstat64(const char *pathname, struct stat64 *buf)`:** Like `stat64`, but doesn't follow symbolic links.
* **`fstat64(int fd, struct stat64 *buf)`:** Gets 64-bit file status information based on a file descriptor.
* **`statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf)`:**  Provides extended file status information.
* **`fchmod(int fd, mode_t mode)`:** Changes the permissions of the file referred to by the file descriptor.
* **`fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)`:** Changes permissions relative to a directory file descriptor, with optional flags like `AT_SYMLINK_NOFOLLOW`.
* **`faccessat(int dirfd, const char *pathname, int mode, int flags)`:** Checks file accessibility relative to a directory file descriptor, with optional flags.
* **`lchmod(const char *pathname, mode_t mode)`:** Changes the permissions of a symbolic link itself.
* **`open()`, `close()`, `unlink()`, `tmpfile()`, `fileno()`, `symlink()`:** Standard file manipulation functions used within the tests.

**5. Connecting to Android Functionality:**

Now I think about how these functions are used in Android. File access, permissions, and timestamps are fundamental to the operating system. I consider examples:

* **Package installation:** The installer uses `stat`, `chmod`, and potentially `mkfifo` when creating application directories, setting permissions, and potentially creating communication channels.
* **File sharing:** Apps use these functions to manage permissions on shared files.
* **System services:** System daemons rely on file permissions and access control for security.
* **Dynamic linker:**  The dynamic linker uses `stat` and related calls to find and load shared libraries.

**6. Dynamic Linker Aspects:**

The `stat` family of functions is crucial for the dynamic linker. I need to explain:

* **SO Layout:** A typical layout with executables in `/system/bin` or `/vendor/bin`, and shared libraries in `/system/lib`, `/vendor/lib`, or architecture-specific subdirectories (e.g., `/system/lib64`).
* **Linking Process:**  The linker uses search paths to locate the necessary `.so` files, relying on `stat` (or potentially `statx`) to check for their existence and get information. It then maps these libraries into the process's address space.

**7. Common Usage Errors:**

I think about common mistakes developers make:

* **Incorrect permissions:** Setting overly permissive or restrictive permissions.
* **Not checking return values:** Failing to handle errors indicated by `-1` and `errno`.
* **Race conditions:**  Assuming file status remains the same between checks and actions.
* **Incorrect path handling:**  Issues with relative vs. absolute paths, especially with functions like `fchmodat` and `faccessat`.

**8. Frida Hooking:**

I consider how to trace the execution of these functions using Frida:

* **Basic hooking:** Intercepting the function calls, printing arguments, and return values.
* **Advanced hooking:** Modifying arguments or return values to test different scenarios or bypass checks. I'd provide examples targeting `stat`, `chmod`, or `open`.

**9. Android Framework/NDK Path:**

Finally, I trace the path from the application level down to these Bionic functions:

* **Java framework:**  Android framework classes like `java.io.File` use native methods.
* **NDK:** NDK provides C/C++ headers exposing these system calls.
* **System calls:**  The native methods or NDK functions ultimately make system calls.
* **Bionic:** Bionic implements these system calls, often as wrappers around kernel calls.

**10. Structuring the Answer:**

I organize the information logically, addressing each part of the request:

* Functionality of the test file.
* Relationship to Android functionality (with examples).
* Detailed explanations of libc functions.
* Dynamic linker aspects (SO layout, linking process).
* Logical reasoning with input/output examples.
* Common usage errors.
* Android framework/NDK path and Frida hooking.

**Self-Correction/Refinement:**

* **Initial thought:** Focus heavily on the code itself.
* **Correction:** Shift focus to *why* the code exists, its purpose in testing the libc, and its broader relevance to Android.
* **Initial thought:**  Provide very technical, low-level details of system calls.
* **Correction:** Balance technical details with higher-level explanations and practical examples that are easier to understand.
* **Initial thought:**  Treat each test case in isolation.
* **Correction:**  Synthesize the information to highlight common themes and the overall purpose of the test suite. For example, grouping the `fchmodat` tests together makes sense.

By following this structured approach, iteratively analyzing the code, and considering the broader context of Android development, I can generate a comprehensive and informative answer to the user's request.
好的，让我们来详细分析一下 `bionic/tests/sys_stat_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/sys_stat_test.cpp` 是 Android Bionic 库中的一个测试文件，它的主要功能是测试与文件状态相关的系统调用，例如：

* **修改文件时间戳:** `futimens`
* **创建命名管道 (FIFO):** `mkfifo`, `mkfifoat`
* **获取文件状态信息:** `stat64`, `lstat64`, `fstat64`, `statx`
* **修改文件权限:** `fchmod`, `fchmodat`, `lchmod`
* **检查文件访问权限:** `faccessat`

这个文件使用 Google Test 框架来编写测试用例，每个 `TEST` 宏定义一个独立的测试。

**与 Android 功能的关系及举例**

这些系统调用是 Android 系统底层文件操作的基础，与 Android 的许多功能息息相关：

* **应用程序安装和卸载:**  `mkfifo` 可能用于创建进程间通信的管道，`chmod` 用于设置应用程序文件的权限。例如，在安装 APK 时，`installd` 守护进程可能会使用这些系统调用来创建应用程序的目录和文件，并设置相应的权限。
* **文件系统访问:** 应用程序通过 Java Framework 或 NDK 调用这些系统调用来读取、写入、创建和管理文件。例如，一个下载管理器可能使用 `stat` 来检查文件是否存在，使用 `chmod` 来修改下载文件的权限。
* **进程间通信 (IPC):** `mkfifo` 创建的 FIFO 可用于不同进程之间的数据交换。例如，`logd` 系统日志守护进程可能使用 FIFO 来接收来自各个应用程序的日志信息。
* **动态链接器:**  虽然这个测试文件本身没有直接测试动态链接器的功能，但 `stat` 和相关调用是动态链接器在加载共享库时使用的关键函数，用于查找和验证共享库文件。

**libc 函数功能详解**

下面详细解释一下这个测试文件中涉及的 libc 函数的功能及其实现原理：

* **`futimens(int fd, const struct timespec times[2])`:**
    * **功能:** 修改由文件描述符 `fd` 引用的文件的访问时间和修改时间。
    * **实现:**  Bionic 的 `futimens` 通常会调用底层的 Linux 系统调用 `futimesat` (传递 `AT_FDCWD` 作为 `dirfd`)。  系统调用会将 `times` 数组中的时间信息（分别对应访问时间和修改时间）写入到文件系统的 inode 元数据中。
    * **测试用例 `TEST(sys_stat, futimens)`:** 创建一个临时文件，获取其文件描述符，然后使用 `futimens` 设置访问和修改时间，最后通过 `fstat` 检查时间是否设置成功。
    * **测试用例 `TEST(sys_stat, futimens_EBADF)`:** 尝试使用无效的文件描述符调用 `futimens`，预期会返回 -1 并设置 `errno` 为 `EBADF` (Bad file descriptor)。

* **`mkfifo(const char *pathname, mode_t mode)`:**
    * **功能:** 创建一个命名管道（FIFO），路径名为 `pathname`，权限为 `mode`。
    * **实现:** Bionic 的 `mkfifo` 会调用底层的 Linux 系统调用 `mknod`，并指定文件类型为 `S_IFIFO`。系统调用会在文件系统中创建一个特殊的 inode，表示一个 FIFO。
    * **测试用例 `TEST(sys_stat, mkfifo)`:** 如果当前用户是 root，则创建一个临时文件路径，然后使用 `mkfifo` 创建 FIFO，并使用 `stat` 检查文件类型是否为 FIFO。非 root 用户会跳过测试，因为 SELinux 策略阻止非 root 用户创建 FIFO。
    * **测试用例 `TEST(sys_stat, mkfifo_failure)`:** 尝试在根目录 `/` 下创建 FIFO，预期会失败并设置 `errno` 为 `EEXIST` (File exists)。

* **`mkfifoat(int dirfd, const char *pathname, mode_t mode)`:**
    * **功能:**  与 `mkfifo` 类似，但创建的 FIFO 的路径名 `pathname` 是相对于文件描述符 `dirfd` 指向的目录而言的。如果 `dirfd` 为 `AT_FDCWD`，则行为与 `mkfifo` 相同。
    * **实现:** Bionic 的 `mkfifoat` 直接调用底层的 Linux 系统调用 `mkdirat`，并指定文件类型为 `S_IFIFO`。
    * **测试用例 `TEST(sys_stat, mkfifoat_failure)`:** 尝试使用无效的目录文件描述符 `-2` 调用 `mkfifoat`，预期会失败并设置 `errno` 为 `EBADF`。

* **`stat64(const char *pathname, struct stat64 *buf)`，`lstat64(const char *pathname, struct stat64 *buf)`，`fstat64(int fd, struct stat64 *buf)`:**
    * **功能:** 获取文件的状态信息，包括文件大小、权限、所有者、时间戳等，并将信息存储在 `buf` 指向的 `stat64` 结构体中。
        * `stat64`:  如果 `pathname` 是符号链接，则返回链接指向的文件的状态。
        * `lstat64`: 如果 `pathname` 是符号链接，则返回符号链接本身的状态。
        * `fstat64`:  基于文件描述符 `fd` 获取文件状态。
    * **实现:** Bionic 的这些函数分别调用底层的 Linux 系统调用 `stat`, `lstat`, 和 `fstat`。系统调用会从文件系统的 inode 元数据中读取相关信息。
    * **测试用例 `TEST(sys_stat, stat64_lstat64_fstat64)`:**  分别使用这三个函数获取 `/proc/version` 的状态信息，验证它们可以正常工作。

* **`statx(int dirfd, const char *pathname, int flags, unsigned int mask, struct statx *statxbuf)`:**
    * **功能:**  提供更精细的文件状态信息，可以控制要获取的属性，并支持原子性的状态获取。
    * **实现:** Bionic 的 `statx` 直接调用底层的 Linux 系统调用 `statx`。
    * **测试用例 `TEST(sys_stat, statx)`:**  如果系统支持 `statx`，则使用 `statx` 获取 `/proc/version` 的状态信息，并与 `stat64` 的结果进行比较，验证 `st_ino` (inode number) 和 `st_mode` (文件模式) 是否一致。

* **`fchmod(int fd, mode_t mode)`:**
    * **功能:** 修改由文件描述符 `fd` 引用的文件的权限为 `mode`。
    * **实现:** Bionic 的 `fchmod` 会调用底层的 Linux 系统调用 `fchmod`。系统调用会修改文件系统 inode 元数据中的权限信息。
    * **测试用例 `TEST(sys_stat, fchmod_EBADF)`:** 尝试使用无效的文件描述符调用 `fchmod`，预期会返回 -1 并设置 `errno` 为 `EBADF`。

* **`fchmodat(int dirfd, const char *pathname, mode_t mode, int flags)`:**
    * **功能:**  与 `fchmod` 类似，但修改权限的目标文件路径 `pathname` 是相对于文件描述符 `dirfd` 指向的目录而言的。`flags` 参数可以控制如何处理符号链接。
        * `AT_SYMLINK_NOFOLLOW`: 如果 `pathname` 是符号链接，则修改链接本身的权限，而不是链接指向的文件的权限。
    * **实现:** Bionic 的 `fchmodat` 会调用底层的 Linux 系统调用 `fchmodat`。
    * **测试用例 `TEST(sys_stat, fchmodat_*)` 系列:**  涵盖了 `fchmodat` 的各种场景，包括错误处理（无效的文件指针、错误的 flags、文件不存在）以及成功修改文件和符号链接的权限。特别注意了 `AT_SYMLINK_NOFOLLOW` 标志在 Bionic 和 glibc 上的行为差异。

* **`lchmod(const char *pathname, mode_t mode)`:**
    * **功能:** 修改符号链接自身的权限。
    * **实现:** Bionic 的 `lchmod` 会调用底层的 Linux 系统调用 `lchmod`。
    * **测试用例 `TEST(sys_stat, lchmod)`:** 创建一个符号链接，然后尝试使用 `lchmod` 修改链接的权限。由于内核可能不支持对符号链接进行 `chmod` 操作，因此测试用例会检查 `lchmod` 的返回值和 `errno` 来确定是否成功。

* **`faccessat(int dirfd, const char *pathname, int mode, int flags)`:**
    * **功能:** 检查由 `dirfd` 和 `pathname` 指定的文件是否具有指定的访问权限 `mode` (例如 `R_OK` 表示可读，`W_OK` 表示可写，`X_OK` 表示可执行，`F_OK` 表示文件存在)。
    * **实现:** Bionic 的 `faccessat` 会调用底层的 Linux 系统调用 `faccessat`。
    * **测试用例 `TEST(sys_stat, faccessat_*)` 系列:** 测试了 `faccessat` 的各种场景，包括错误的 flags、`AT_SYMLINK_NOFOLLOW` 标志（注意 Bionic 不完全支持）、以及对 `/dev/null` 和不存在的文件进行权限检查。

**动态链接器功能及 SO 布局和链接过程**

虽然这个测试文件没有直接测试动态链接器的代码，但 `stat` 系列函数是动态链接器在加载共享库时必不可少的。

**SO 布局样本:**

一个典型的 Android SO 库布局可能如下所示：

```
/system
├── bin
│   └── app_process64  (应用程序进程)
├── lib64
│   ├── libc.so       (C 库)
│   ├── libm.so       (数学库)
│   ├── libdl.so      (动态链接器自身)
│   └── ... 其他系统库 ...
└── app
    └── ... 应用相关文件 ...

/vendor
├── lib64
│   └── ... 供应商提供的库 ...

/data
├── app
│   └── com.example.myapp
│       ├── lib
│       │   └── arm64-v8a
│       │       └── libnative.so (应用程序的 native 库)
│       └── ...
└── ...
```

**链接的处理过程:**

1. **应用程序启动:** 当 Android 启动一个应用程序时，Zygote 进程会 fork 出一个新的进程。
2. **加载器执行:** 新进程开始执行，首先会加载 `linker64` (动态链接器)。
3. **解析 ELF 头:** 动态链接器解析应用程序可执行文件 (例如 `app_process64`) 的 ELF 头，查找 `PT_INTERP` 段，该段指定了动态链接器的路径。
4. **加载依赖库:** 动态链接器解析可执行文件的 `DT_NEEDED` 段，该段列出了程序依赖的共享库。
5. **查找共享库:**  动态链接器会在预定义的搜索路径中查找这些共享库。这些搜索路径通常包括 `/system/lib64`, `/vendor/lib64`, 以及应用程序私有库路径等。  **在这个过程中，动态链接器会使用 `stat` 或 `stat64` 来检查共享库文件是否存在以及是否可读。**
6. **加载共享库:** 找到共享库后，动态链接器会将其加载到进程的地址空间中。
7. **符号解析和重定位:** 动态链接器解析共享库的符号表，并将程序中对共享库函数的调用地址重定向到共享库中实际的函数地址。
8. **执行应用程序:**  所有依赖库加载和链接完成后，应用程序的主程序开始执行。

**逻辑推理，假设输入与输出**

以 `TEST(sys_stat, futimens)` 为例：

* **假设输入:**
    * 创建了一个临时文件，文件描述符 `fd` 指向该文件。
    * `times[0].tv_sec = 1678886400` (Unix 时间戳)
    * `times[0].tv_nsec = 0`
    * `times[1].tv_sec = 1678886460`
    * `times[1].tv_nsec = 0`
* **预期输出:**
    * `futimens(fd, times)` 返回 0 (成功)。
    * `fstat(fd, &sb)` 返回 0 (成功)。
    * `sb.st_atime` 等于 `1678886400`。
    * `sb.st_mtime` 等于 `1678886460`。

**用户或编程常见的使用错误**

* **权限不足:**  尝试创建文件、修改权限或访问文件时，当前用户可能没有足够的权限。例如，在非 root 进程中尝试使用 `mkfifo` 创建 FIFO 可能会失败。
* **路径错误:**  提供的文件路径不存在或不正确，导致 `stat`, `open`, `chmod` 等函数调用失败。
* **忘记检查返回值:**  系统调用通常会返回 -1 表示失败，并设置全局变量 `errno` 来指示错误类型。程序员必须检查返回值并根据 `errno` 进行错误处理。
* **竞争条件:**  在多线程或多进程环境下，文件状态可能在检查和操作之间发生变化，导致意外的结果。例如，一个线程检查文件存在，另一个线程在检查后删除了文件。
* **对符号链接的处理不当:**  没有理解 `stat` 和 `lstat` 的区别，或者在使用 `chmod` 等函数时没有考虑 `AT_SYMLINK_NOFOLLOW` 标志的影响，可能导致对目标文件或链接本身的操作意图与实际行为不符。

**Android Framework 或 NDK 如何到达这里，Frida Hook 示例**

1. **Android Framework (Java):**
   * 应用程序调用 `java.io.File` 类的方法，例如 `createNewFile()`, `setLastModified()`, `setExecutable()`, `canRead()`, `exists()`.
   * 这些 `java.io.File` 的方法最终会调用对应的 native 方法。

2. **NDK (C/C++):**
   * 开发者在 NDK 代码中直接包含头文件 `<sys/stat.h>`，并调用相应的 C 标准库函数，例如 `stat`, `chmod`, `mkfifo`。

3. **系统调用:**
   * 无论是 Framework 的 native 方法还是 NDK 代码，最终都会通过系统调用接口 (syscall) 进入 Linux 内核。

4. **Bionic libc:**
   * Bionic libc 提供了这些 C 标准库函数的实现，这些实现通常是对 Linux 系统调用的封装。例如，Bionic 的 `stat` 函数会调用内核的 `__NR_stat` 系统调用。

**Frida Hook 示例:**

以下是一个使用 Frida Hook 拦截 `chmod` 系统调用的示例：

```javascript
// attach 到目标进程
function hook_chmod() {
    const addr_chmod = Module.findExportByName("libc.so", "chmod");
    if (addr_chmod) {
        Interceptor.attach(addr_chmod, {
            onEnter: function (args) {
                const pathname = Memory.readUtf8String(ptr(args[0]));
                const mode = args[1].toInt();
                console.log(`[chmod] pathname: ${pathname}, mode: ${mode.toString(8)}`);
            },
            onLeave: function (retval) {
                console.log(`[chmod] return value: ${retval}`);
            }
        });
    } else {
        console.log("[-] Failed to find chmod");
    }
}

setImmediate(hook_chmod);
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `.js` 文件 (例如 `hook_chmod.js`).
2. 使用 Frida 连接到目标 Android 进程 (替换 `<进程ID>`):
   ```bash
   frida -U -f <包名> -l hook_chmod.js --no-pause
   ```
   或者连接到已经运行的进程：
   ```bash
   frida -U <进程ID> -l hook_chmod.js
   ```

**说明:**

* `Module.findExportByName("libc.so", "chmod")` 查找 `libc.so` 中 `chmod` 函数的地址。
* `Interceptor.attach()` 用于拦截函数调用。
* `onEnter` 函数在 `chmod` 函数调用前执行，可以访问函数参数。
* `onLeave` 函数在 `chmod` 函数返回后执行，可以访问返回值。
* `Memory.readUtf8String()` 用于读取字符串参数。
* `args[0]` 和 `args[1]` 分别对应 `chmod` 函数的 `pathname` 和 `mode` 参数。
* `mode.toString(8)` 将权限模式转换为八进制字符串。

你可以通过修改 `Module.findExportByName` 中的函数名来 Hook 其他的 `stat` 相关函数，例如 `stat`, `open`, `mkfifo` 等。

希望这个详细的分析对您有所帮助！

Prompt: 
```
这是目录为bionic/tests/sys_stat_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>

#include <android-base/file.h>
#include <gtest/gtest.h>

#include "utils.h"

#if defined(__BIONIC__)
#define HAVE_STATX
#elif defined(__GLIBC_PREREQ)
#if __GLIBC_PREREQ(2, 28)
#define HAVE_STATX
#endif
#endif

TEST(sys_stat, futimens) {
  FILE* fp = tmpfile();
  ASSERT_TRUE(fp != nullptr);

  int fd = fileno(fp);
  ASSERT_NE(fd, -1);

  timespec times[2];
  times[0].tv_sec = 123;
  times[0].tv_nsec = 0;
  times[1].tv_sec = 456;
  times[1].tv_nsec = 0;
  ASSERT_EQ(0, futimens(fd, times)) << strerror(errno);

  struct stat sb;
  ASSERT_EQ(0, fstat(fd, &sb));
  ASSERT_EQ(times[0].tv_sec, static_cast<long>(sb.st_atime));
  ASSERT_EQ(times[1].tv_sec, static_cast<long>(sb.st_mtime));

  fclose(fp);
}

TEST(sys_stat, futimens_EBADF) {
  timespec times[2];
  times[0].tv_sec = 123;
  times[0].tv_nsec = 0;
  times[1].tv_sec = 456;
  times[1].tv_nsec = 0;
  ASSERT_EQ(-1, futimens(-1, times));
  ASSERT_ERRNO(EBADF);
}

TEST(sys_stat, mkfifo_failure) {
  errno = 0;
  ASSERT_EQ(-1, mkfifo("/", 0666));
  ASSERT_ERRNO(EEXIST);
}

TEST(sys_stat, mkfifoat_failure) {
  errno = 0;
  ASSERT_EQ(-1, mkfifoat(-2, "x", 0666));
  ASSERT_ERRNO(EBADF);
}

TEST(sys_stat, mkfifo) {
  if (getuid() == 0) {
    // Racy but probably sufficient way to get a suitable filename.
    std::string path;
    {
      TemporaryFile tf;
      path = tf.path;
    }

    ASSERT_EQ(0, mkfifo(path.c_str(), 0666));
    struct stat sb;
    ASSERT_EQ(0, stat(path.c_str(), &sb));
    ASSERT_TRUE(S_ISFIFO(sb.st_mode));
    unlink(path.c_str());
  } else {
    // SELinux policy forbids us from creating FIFOs. http://b/17646702.
    GTEST_SKIP() << "SELinux policy forbids non-root from creating FIFOs";
  }
}

TEST(sys_stat, stat64_lstat64_fstat64) {
  struct stat64 sb;
  ASSERT_EQ(0, stat64("/proc/version", &sb));
  ASSERT_EQ(0, lstat64("/proc/version", &sb));
  int fd = open("/proc/version", O_RDONLY);
  ASSERT_EQ(0, fstat64(fd, &sb));
  close(fd);
}

TEST(sys_stat, statx) {
#if defined(HAVE_STATX)
  struct statx sx;
  int rc = statx(AT_FDCWD, "/proc/version", AT_STATX_SYNC_AS_STAT, STATX_ALL, &sx);
  if (rc == -1 && errno == ENOSYS) GTEST_SKIP() << "no statx() in this kernel";
  ASSERT_EQ(0, rc);
  struct stat64 sb;
  ASSERT_EQ(0, stat64("/proc/version", &sb));
  EXPECT_EQ(sb.st_ino, sx.stx_ino);
  EXPECT_EQ(sb.st_mode, sx.stx_mode);
#else
  GTEST_SKIP() << "statx not available";
#endif
}

TEST(sys_stat, fchmod_EBADF) {
  ASSERT_EQ(-1, fchmod(-1, 0751));
  ASSERT_ERRNO(EBADF);
}

TEST(sys_stat, fchmodat_EFAULT_file) {
  ASSERT_EQ(-1, fchmodat(AT_FDCWD, (char *) 0x1, 0751, 0));
  ASSERT_ERRNO(EFAULT);
}

TEST(sys_stat, fchmodat_AT_SYMLINK_NOFOLLOW_EFAULT_file) {
  ASSERT_EQ(-1, fchmodat(AT_FDCWD, (char *) 0x1, 0751, AT_SYMLINK_NOFOLLOW));
#if defined(__BIONIC__)
  ASSERT_ERRNO(EFAULT);
#else
  // glibc 2.19 does not implement AT_SYMLINK_NOFOLLOW and always
  // returns ENOTSUP
  ASSERT_ERRNO(ENOTSUP);
#endif
}

TEST(sys_stat, fchmodat_bad_flags) {
  ASSERT_EQ(-1, fchmodat(AT_FDCWD, "/blah", 0751, ~AT_SYMLINK_NOFOLLOW));
  ASSERT_ERRNO(EINVAL);
}

TEST(sys_stat, fchmodat_bad_flags_ALL) {
  ASSERT_EQ(-1, fchmodat(AT_FDCWD, "/blah", 0751, ~0));
  ASSERT_ERRNO(EINVAL);
}

TEST(sys_stat, fchmodat_nonexistent_file) {
  ASSERT_EQ(-1, fchmodat(AT_FDCWD, "/blah", 0751, 0));
  ASSERT_ERRNO(ENOENT);
}

TEST(sys_stat, fchmodat_AT_SYMLINK_NOFOLLOW_nonexistent_file) {
  ASSERT_EQ(-1, fchmodat(AT_FDCWD, "/blah", 0751, AT_SYMLINK_NOFOLLOW));
#if defined(__BIONIC__)
  ASSERT_ERRNO(ENOENT);
#else
  // glibc 2.19 does not implement AT_SYMLINK_NOFOLLOW and always
  // returns ENOTSUP
  ASSERT_ERRNO(ENOTSUP);
#endif
}

static void AssertFileModeEquals(mode_t expected_mode, const char* filename) {
  struct stat sb;
  ASSERT_EQ(0, stat(filename, &sb));
  mode_t mask = S_IRWXU | S_IRWXG | S_IRWXO;
  ASSERT_EQ(expected_mode & mask, static_cast<mode_t>(sb.st_mode) & mask);
}

TEST(sys_stat, fchmodat_file) {
  TemporaryFile tf;

  ASSERT_EQ(0, fchmodat(AT_FDCWD, tf.path, 0751, 0));
  AssertFileModeEquals(0751, tf.path);
}

TEST(sys_stat, fchmodat_AT_SYMLINK_NOFOLLOW_file) {
  TemporaryFile tf;
  errno = 0;
  int result = fchmodat(AT_FDCWD, tf.path, 0751, AT_SYMLINK_NOFOLLOW);

#if defined(__BIONIC__)
  ASSERT_EQ(0, result);
  ASSERT_ERRNO(0);
  AssertFileModeEquals(0751, tf.path);
#else
  // glibc 2.19 does not implement AT_SYMLINK_NOFOLLOW and always
  // returns ENOTSUP
  ASSERT_EQ(-1, result);
  ASSERT_ERRNO(ENOTSUP);
#endif
}

TEST(sys_stat, fchmodat_symlink) {
  TemporaryFile tf;
  char linkname[255];

  snprintf(linkname, sizeof(linkname), "%s.link", tf.path);

  ASSERT_EQ(0, symlink(tf.path, linkname));
  ASSERT_EQ(0, fchmodat(AT_FDCWD, linkname, 0751, 0));
  AssertFileModeEquals(0751, tf.path);
  unlink(linkname);
}

TEST(sys_stat, fchmodat_dangling_symlink) {
  TemporaryFile tf;
  char linkname[255];
  char target[255];

  snprintf(linkname, sizeof(linkname), "%s.link", tf.path);
  snprintf(target, sizeof(target), "%s.doesnotexist", tf.path);

  ASSERT_EQ(0, symlink(target, linkname));
  ASSERT_EQ(-1, fchmodat(AT_FDCWD, linkname, 0751, 0));
  ASSERT_ERRNO(ENOENT);
  unlink(linkname);
}

static void AssertSymlinkModeEquals(mode_t expected_mode, const char* linkname) {
  struct stat sb;
  ASSERT_EQ(0, fstatat(AT_FDCWD, linkname, &sb, AT_SYMLINK_NOFOLLOW));
  mode_t mask = S_IRWXU | S_IRWXG | S_IRWXO;
  ASSERT_EQ(expected_mode & mask, static_cast<mode_t>(sb.st_mode) & mask);
}

TEST(sys_stat, fchmodat_AT_SYMLINK_NOFOLLOW_with_symlink) {
  TemporaryFile tf;
  struct stat tf_sb;
  ASSERT_EQ(0, stat(tf.path, &tf_sb));

  char linkname[255];
  snprintf(linkname, sizeof(linkname), "%s.link", tf.path);

  ASSERT_EQ(0, symlink(tf.path, linkname));
  int result = fchmodat(AT_FDCWD, linkname, 0751, AT_SYMLINK_NOFOLLOW);
  // It depends on the kernel whether chmod operation on symlink is allowed.
  if (result == 0) {
    AssertSymlinkModeEquals(0751, linkname);
  } else {
    ASSERT_EQ(-1, result);
    ASSERT_ERRNO(ENOTSUP);
  }

  // Target file mode shouldn't be modified.
  AssertFileModeEquals(tf_sb.st_mode, tf.path);
  unlink(linkname);
}

TEST(sys_stat, fchmodat_AT_SYMLINK_NOFOLLOW_with_dangling_symlink) {
  TemporaryFile tf;

  char linkname[255];
  char target[255];
  snprintf(linkname, sizeof(linkname), "%s.link", tf.path);
  snprintf(target, sizeof(target), "%s.doesnotexist", tf.path);

  ASSERT_EQ(0, symlink(target, linkname));
  int result = fchmodat(AT_FDCWD, linkname, 0751, AT_SYMLINK_NOFOLLOW);
  // It depends on the kernel whether chmod operation on symlink is allowed.
  if (result == 0) {
    AssertSymlinkModeEquals(0751, linkname);
  } else {
    ASSERT_EQ(-1, result);
    ASSERT_ERRNO(ENOTSUP);
  }

  unlink(linkname);
}

TEST(sys_stat, faccessat_EINVAL) {
  ASSERT_EQ(-1, faccessat(AT_FDCWD, "/dev/null", F_OK, ~AT_SYMLINK_NOFOLLOW));
  ASSERT_ERRNO(EINVAL);
#if defined(__BIONIC__)
  ASSERT_EQ(-1, faccessat(AT_FDCWD, "/dev/null", ~(R_OK | W_OK | X_OK), 0));
  ASSERT_ERRNO(EINVAL);
#else
  ASSERT_EQ(0, faccessat(AT_FDCWD, "/dev/null", ~(R_OK | W_OK | X_OK), AT_SYMLINK_NOFOLLOW));
  ASSERT_EQ(-1, faccessat(AT_FDCWD, "/dev/null", ~(R_OK | W_OK | X_OK), 0));
  ASSERT_ERRNO(EINVAL);
#endif
}

TEST(sys_stat, faccessat_AT_SYMLINK_NOFOLLOW_EINVAL) {
#if defined(__BIONIC__)
  // Android doesn't support AT_SYMLINK_NOFOLLOW
  ASSERT_EQ(-1, faccessat(AT_FDCWD, "/dev/null", F_OK, AT_SYMLINK_NOFOLLOW));
  ASSERT_ERRNO(EINVAL);
#else
  ASSERT_EQ(0, faccessat(AT_FDCWD, "/dev/null", F_OK, AT_SYMLINK_NOFOLLOW));
#endif
}

TEST(sys_stat, faccessat_dev_null) {
  ASSERT_EQ(0, faccessat(AT_FDCWD, "/dev/null", F_OK, 0));
  ASSERT_EQ(0, faccessat(AT_FDCWD, "/dev/null", R_OK, 0));
  ASSERT_EQ(0, faccessat(AT_FDCWD, "/dev/null", W_OK, 0));
  ASSERT_EQ(0, faccessat(AT_FDCWD, "/dev/null", R_OK|W_OK, 0));
}

TEST(sys_stat, faccessat_nonexistent) {
  ASSERT_EQ(-1, faccessat(AT_FDCWD, "/blah", F_OK, AT_SYMLINK_NOFOLLOW));
#if defined(__BIONIC__)
  // Android doesn't support AT_SYMLINK_NOFOLLOW
  ASSERT_ERRNO(EINVAL);
#else
  ASSERT_ERRNO(ENOENT);
#endif
}

TEST(sys_stat, lchmod) {
  TemporaryFile tf;
  struct stat tf_sb;
  ASSERT_EQ(0, stat(tf.path, &tf_sb));

  char linkname[255];
  snprintf(linkname, sizeof(linkname), "%s.link", tf.path);

  ASSERT_EQ(0, symlink(tf.path, linkname));
  int result = lchmod(linkname, 0751);
  // Whether or not chmod is allowed on a symlink depends on the kernel.
  if (result == 0) {
    AssertSymlinkModeEquals(0751, linkname);
  } else {
    ASSERT_EQ(-1, result);
    ASSERT_ERRNO(ENOTSUP);
  }

  // The target file mode shouldn't be modified.
  AssertFileModeEquals(tf_sb.st_mode, tf.path);
  unlink(linkname);
}

"""

```