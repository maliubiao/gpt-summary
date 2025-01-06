Response:
Let's break down the thought process for analyzing the `fcntl_test.cpp` file.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the provided C++ test file within the Android Bionic library. This involves identifying the tested functions, their purpose, how they relate to Android, potential issues, and how to debug them.

**2. Initial Scan and Keyword Recognition:**

The first step is to quickly scan the code for recognizable keywords and patterns:

* **`#include` directives:** These tell us which header files are being used, providing clues about the functionalities being tested (e.g., `fcntl.h`, `sys/vfs.h`, `linux/falloc.h`). The inclusion of `gtest/gtest.h` immediately signals this is a unit test file.
* **`TEST(...)` macros:** These are Google Test macros, clearly indicating individual test cases for specific functions or scenarios.
* **Function names:**  Looking at the names of the test cases like `fcntl_smoke`, `open_open64`, `posix_fadvise`, `fallocate`, `splice`, `tee`, `sync_file_range`, etc., directly points to the libc functions being tested.
* **Constants and macros:**  `O_RDONLY`, `O_WRONLY`, `O_CREAT`, `FD_CLOEXEC`, `POSIX_FADV_NORMAL`, `FALLOC_FL_PUNCH_HOLE`, `EXT4_SUPER_MAGIC`, `AT_FDCWD`, `SIZE_MAX`. These are flags and constants related to file operations and provide context for the tests.
* **Helper classes/functions:** `TemporaryFile`, `TemporaryDir`, `SilentDeathTest`, `utils.h`. These suggest the test setup and teardown mechanisms. `SilentDeathTest` hints at testing scenarios that might cause the program to exit.
* **Assertions:** `ASSERT_TRUE`, `ASSERT_EQ`, `ASSERT_NE`, `ASSERT_ERRNO`, `EXPECT_EQ`, `ASSERT_STREQ`, `EXPECT_DEATH`. These are Google Test assertions used to verify the expected behavior of the tested functions.

**3. Grouping Tests by Functionality:**

Based on the test case names and the included headers, we can group the tests by the libc function they primarily target:

* **`fcntl()` related:** `fcntl_smoke`, `fcntl_F_SETFD`
* **`open()`, `open64()`, `openat()`, `openat64()` related:** `open_open64`, `openat_openat64`, `open_O_TMPFILE_mode`
* **`creat()`, `creat64()` related:** `creat_creat64`
* **`posix_fadvise()`, `posix_fadvise64()` related:** `posix_fadvise`
* **`fallocate()`, `fallocate64()`, `posix_fallocate()`, `posix_fallocate64()` related:** `fallocate_EINVAL`, `fallocate`, `falloc_punch`
* **File locking (`flock`) related:** `f_getlk`, `f_getlk64`
* **Piping and data transfer (`splice`, `vmsplice`, `tee`) related:** `splice`, `vmsplice`, `tee`
* **Read-ahead and synchronization (`readahead`, `sync_file_range`) related:** `readahead`, `sync_file_range`

**4. Analyzing Individual Test Cases:**

For each group, examine the individual test cases:

* **Purpose:** What specific aspect of the function is being tested? (e.g., setting `FD_CLOEXEC` flag, handling invalid arguments, basic functionality, specific edge cases like punching holes in files).
* **How it's tested:**  What actions are performed? What assertions are made? What are the expected inputs and outputs (even if implicitly defined by the assertions)?
* **Error handling:**  Are there checks for specific error codes (`errno`)?

**5. Connecting to Android Functionality:**

Consider how these libc functions are used within the broader Android system:

* **File access:** `open`, `openat`, `creat` are fundamental for apps and system services to interact with the filesystem.
* **File descriptors and flags:** `fcntl` is used to manipulate file descriptor properties, including `FD_CLOEXEC` for security when forking new processes.
* **Performance optimization:** `posix_fadvise`, `readahead`, `sync_file_range` can be used by apps or system components to improve I/O performance.
* **Disk space management:** `fallocate` can be used to pre-allocate space for files.
* **Inter-process communication:** `pipe`, `splice`, `vmsplice`, `tee` are used for efficient data transfer between processes.

**6. Dynamic Linker Considerations:**

The test file itself doesn't directly test dynamic linker features. However, since it's part of Bionic, the execution of these tests *relies* on the dynamic linker. Therefore, consider:

* **SO layout:**  The test executable links against libc.so. A basic understanding of the SO layout (e.g., .text, .data, .bss sections, GOT, PLT) is relevant.
* **Linking process:** How the dynamic linker resolves symbols like `open`, `fcntl`, etc., at runtime.

**7. Identifying Common Usage Errors:**

Based on the test cases and general knowledge of file I/O, identify common mistakes developers might make:

* Incorrectly using flags with `open` or `fcntl`.
* Forgetting to check return values and `errno`.
* Not understanding the implications of `FD_CLOEXEC`.
* Issues with file locking.
* Misusing the data transfer functions (`splice`, `tee`).

**8. Debugging with Frida:**

Think about how Frida can be used to inspect the execution of these tests:

* Hooking libc functions: Intercept calls to `open`, `fcntl`, etc., to see their arguments and return values.
* Tracing system calls: Observe the underlying system calls made by these functions.
* Inspecting memory: Examine the contents of buffers and data structures.

**9. Structuring the Output:**

Organize the findings logically, addressing each part of the prompt:

* **Functionality:** List the tested libc functions and their general purpose.
* **Android Relevance:** Provide concrete examples of how these functions are used in Android.
* **Libc Implementation:** Briefly explain the core functionality of each libc function (without going into kernel-level details, unless the test directly touches on kernel specifics like `falloc_punch`).
* **Dynamic Linker:** Explain the basic SO layout and linking process.
* **Logic and Assumptions:** For tests with conditional logic (like `falloc_punch`), explain the assumptions and expected outcomes.
* **Common Errors:** List typical developer mistakes.
* **Android Framework/NDK:** Describe the path from a high-level Android component to these low-level libc functions.
* **Frida Hooking:** Provide practical examples of Frida scripts for debugging.

**Self-Correction/Refinement during the Process:**

* **Initial Overwhelm:** The file has many tests. Focus on grouping and understanding the core function being tested in each group rather than getting bogged down in every detail initially.
* **Depth of Explanation:**  Adjust the level of detail based on the prompt's requirements. For example, for libc implementation, a high-level overview is usually sufficient unless the test specifically dives into kernel behavior.
* **Clarity and Conciseness:** Ensure the explanations are clear, concise, and easy to understand. Use bullet points and formatting to improve readability.
* **Addressing All Parts of the Prompt:** Double-check that all aspects of the prompt have been addressed. For example, initially, I might focus heavily on the function analysis but then realize I haven't explicitly addressed the dynamic linker or Frida aspects adequately.

By following this structured thought process, we can effectively analyze the `fcntl_test.cpp` file and provide a comprehensive answer to the prompt.
```chinese
好的，让我们来详细分析一下 `bionic/tests/fcntl_test.cpp` 这个文件。

**文件功能概述**

`bionic/tests/fcntl_test.cpp` 是 Android Bionic 库中用于测试 `fcntl.h` 头文件中声明的各种文件控制相关系统调用和库函数的单元测试文件。它使用 Google Test 框架 (gtest) 来编写和执行测试用例，旨在验证 Bionic 库中 `fcntl` 相关功能的正确性和健壮性。

**与 Android 功能的关系及举例说明**

`fcntl` 及其相关的系统调用是操作系统中非常基础且重要的功能，在 Android 系统中被广泛使用。以下是一些与 Android 功能相关的例子：

1. **文件访问控制：** `open`, `openat`, `creat` 等函数用于打开、创建文件。Android 应用程序和系统服务需要这些函数来访问设备上的文件，例如读取应用配置、存储用户数据、访问设备文件系统等。
    * **例子：** 当一个 Android 应用需要读取 SharedPreferences 时，底层就会使用 `open` 函数打开对应的 XML 文件。
    * **例子：**  安装 APK 时，`installd` 守护进程会使用 `open` 和 `creat` 来创建和写入应用程序的文件。

2. **文件描述符操作：** `fcntl` 函数本身提供了多种操作文件描述符的能力，例如获取和设置文件描述符的标志 (例如 `FD_CLOEXEC`)，获取和设置文件锁等。
    * **例子：**  当 Android 系统启动一个新进程时，通常会使用 `fork` 系统调用。为了防止子进程继承父进程打开的某些文件描述符，可能会在父进程中使用 `fcntl` 设置 `FD_CLOEXEC` 标志，这样在 `execve` 调用后，这些文件描述符会在子进程中被关闭。

3. **性能优化：** `posix_fadvise`, `readahead`, `sync_file_range` 等函数可以向内核提供文件访问模式的建议，帮助内核进行预读、缓存和同步操作，从而提高文件 I/O 的性能。
    * **例子：**  Android 的媒体框架在播放视频时，可能会使用 `posix_fadvise` 来告知内核即将顺序读取大量数据，以便内核进行预读优化。

4. **文件空间管理：** `fallocate` 函数可以预先分配文件空间，避免文件在写入过程中不断扩展导致碎片化。
    * **例子：**  Android 的下载管理器在下载大文件时，可能会使用 `fallocate` 预分配空间。

5. **进程间通信：** `pipe`, `splice`, `vmsplice`, `tee` 等函数用于创建管道和高效地在文件描述符之间传输数据，常用于进程间通信。
    * **例子：** Android 的 `adb` 工具在与设备进行通信时，会使用管道和 `splice` 等技术来传输数据。

**libc 函数功能实现详解**

这个测试文件主要测试了以下 `libc` 函数：

* **`open(const char *pathname, int flags, ... mode_t mode)` 和 `open64(const char *pathname, int flags, ... mode_t mode)`:**
    * **功能：** 打开一个文件或创建一个新文件。`open64` 是用于处理大文件的版本。
    * **实现：**  这两个函数是对 `open` 系统调用的封装。它们将用户空间的路径名、标志位和模式传递给内核。内核根据这些参数查找或创建文件，并返回一个文件描述符，如果出错则返回 -1 并设置 `errno`。
    * **测试用例：** `open_open64` 测试了基本的文件打开功能。

* **`openat(int dirfd, const char *pathname, int flags, ... mode_t mode)` 和 `openat64(int dirfd, const char *pathname, int flags, ... mode_t mode)`:**
    * **功能：** 类似于 `open`，但允许相对于一个目录文件描述符 (`dirfd`) 打开文件。`AT_FDCWD` 特殊值表示相对于当前工作目录。
    * **实现：**  是对 `openat` 系统调用的封装。
    * **测试用例：** `openat_openat64` 测试了相对于当前工作目录打开文件的功能。

* **`creat(const char *pathname, mode_t mode)` 和 `creat64(const char *pathname, mode_t mode)`:**
    * **功能：** 创建一个新文件。等价于 `open(pathname, O_WRONLY | O_CREAT | O_TRUNC, mode)`。`creat64` 是用于处理大文件的版本。
    * **实现：**  是对 `creat` 系统调用的封装。
    * **测试用例：** `creat_creat64` 测试了尝试创建空文件名的情况，预期会返回错误。

* **`fcntl(int fd, int cmd, ...)`:**
    * **功能：** 对已打开的文件描述符执行各种控制操作。常见的 `cmd` 包括 `F_GETFD` (获取文件描述符标志)、`F_SETFD` (设置文件描述符标志)、`F_GETLK` (获取文件锁信息)、`F_SETLK` (设置文件锁) 等。
    * **实现：**  是对 `fcntl` 系统调用的封装。内核根据 `cmd` 的不同执行相应的操作。
    * **测试用例：** `fcntl_smoke` 测试了获取和设置 `FD_CLOEXEC` 标志的功能。`f_getlk` 和 `f_getlk64` 测试了获取文件锁信息的功能。`fcntl_F_SETFD` (死亡测试) 测试了 `F_SETFD` 命令只支持 `FD_CLOEXEC` 标志。

* **`posix_fadvise(int fd, off_t offset, size_t len, int advice)` 和 `posix_fadvise64(int fd, off_t offset, size_t len, int advice)`:**
    * **功能：** 向内核提供关于文件访问模式的建议，例如 `POSIX_FADV_NORMAL` (默认)、`POSIX_FADV_SEQUENTIAL` (顺序访问)、`POSIX_FADV_RANDOM` (随机访问) 等。
    * **实现：**  是对 `fadvise` 系统调用的封装。内核会根据这些建议调整其缓存策略。
    * **测试用例：** `posix_fadvise` 测试了无效的文件描述符和无效的 `advice` 值的情况。

* **`fallocate(int fd, int mode, off_t offset, off_t len)` 和相关函数 (`fallocate64`, `posix_fallocate`, `posix_fallocate64`)：**
    * **功能：**  预先为文件分配磁盘空间。`fallocate` 可以指定 `mode`，例如 `FALLOC_FL_PUNCH_HOLE` 用于打孔（释放文件中的部分空间）。`posix_fallocate` 是 POSIX 标准的版本。
    * **实现：**  是对 `fallocate` 系统调用的封装。内核会在文件系统中预留指定大小的空间。
    * **测试用例：** `fallocate_EINVAL` 测试了无效长度的情况。`fallocate` 测试了基本的空间分配功能。`falloc_punch` 测试了在特定内核版本上打孔操作是否被禁用 (由于安全漏洞)。

* **`splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)`:**
    * **功能：** 在两个文件描述符之间高效地移动数据，而无需将数据复制到用户空间。通常用于管道。
    * **实现：**  是对 `splice` 系统调用的封装。内核直接在内核空间进行数据传输。
    * **测试用例：** `splice` 测试了从文件到管道，再从管道到文件的基本数据传输。

* **`vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags)`:**
    * **功能：** 将用户空间的内存数据 "注入" 到管道。
    * **实现：**  是对 `vmsplice` 系统调用的封装。内核将用户空间的内存页映射到管道缓冲区。
    * **测试用例：** `vmsplice` 测试了将字符串数据注入管道的功能。

* **`tee(int fdin, int fdout, size_t len, unsigned int flags)`:**
    * **功能：**  将数据从一个管道复制到另一个管道，而不消耗掉 `fdin` 中的数据。
    * **实现：**  是对 `tee` 系统调用的封装。
    * **测试用例：** `tee` 测试了将数据从一个管道复制到另一个管道的功能。

* **`readahead(int fd, off64_t offset, size_t count)`:**
    * **功能：**  向内核建议预读指定文件区域的数据到缓存中。
    * **实现：**  是对 `readahead` 系统调用的封装。
    * **测试用例：** `readahead` 只是检查函数是否可用。

* **`sync_file_range(int fd, off64_t offset, off64_t nbytes, unsigned int flags)`:**
    * **功能：**  将文件的一部分或全部数据同步到磁盘。
    * **实现：**  是对 `sync_file_range` 系统调用的封装。
    * **测试用例：** `sync_file_range` 检查函数是否可用，并测试了 `flags` 参数的传递。

**涉及 dynamic linker 的功能**

这个测试文件本身并没有直接测试 dynamic linker 的功能。然而，作为 Bionic 的一部分，这些测试用例的运行依赖于 dynamic linker。

**so 布局样本：**

当运行 `fcntl_test` 可执行文件时，它会链接到 `libc.so`。 `libc.so` 的布局大致如下：

```
libc.so:
    .text          # 可执行代码段
    .rodata        # 只读数据段 (例如字符串常量)
    .data          # 已初始化全局变量和静态变量
    .bss           # 未初始化全局变量和静态变量
    .dynsym        # 动态符号表
    .dynstr        # 动态字符串表
    .plt           # 程序链接表 (Procedure Linkage Table)
    .got.plt       # 全局偏移表 (Global Offset Table) - PLT 部分
    ... 其他段 ...
```

**链接的处理过程：**

1. **编译链接时：** 编译器将 `fcntl_test.cpp` 编译成目标文件，其中对 `open`, `fcntl` 等函数的调用会生成对这些符号的未解析引用。链接器将 `fcntl_test` 目标文件与 `libc.so` 链接在一起。链接器会查找 `libc.so` 的动态符号表 (`.dynsym`)，找到 `open`, `fcntl` 等符号的定义，并在 `fcntl_test` 的代码中生成相应的重定位信息。

2. **运行时：** 当 `fcntl_test` 程序启动时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会负责加载 `libc.so` 到内存中。
    * dynamic linker 会解析 `fcntl_test` 中对 `libc.so` 中函数的引用。
    * **GOT (Global Offset Table):**  对于外部函数调用，编译器会在 GOT 中预留一个条目。在程序启动时，dynamic linker 会将这些外部函数的实际地址填入 GOT 表中。
    * **PLT (Procedure Linkage Table):**  当程序第一次调用一个外部函数时，会跳转到 PLT 中对应的条目。PLT 中的代码会通过 GOT 表间接地调用该函数。如果 GOT 表中尚未填充函数的地址，PLT 代码会调用 dynamic linker 来解析符号并填充 GOT 表，然后再跳转到实际函数。后续的调用将直接通过 GOT 表进行，避免了再次调用 dynamic linker 的开销。

**假设输入与输出 (逻辑推理)**

大多数测试用例都有明确的预期行为，通过 `ASSERT_*` 和 `EXPECT_*` 宏进行断言。 例如：

* **测试 `creat("")`：**
    * **假设输入：** 调用 `creat("")`，尝试创建一个空文件名的文件。
    * **预期输出：** 函数返回 -1，`errno` 设置为 `ENOENT` (No such file or directory)。

* **测试 `fcntl(fd, F_SETFD, O_NONBLOCK)`：**
    * **假设输入：**  对一个文件描述符 `fd` 调用 `fcntl`，尝试设置 `O_NONBLOCK` 标志。
    * **预期输出：**  程序会因为断言失败而终止 (使用 `EXPECT_DEATH`)，因为 `fcntl` 的 `F_SETFD` 命令只支持 `FD_CLOEXEC`。

**用户或编程常见的使用错误举例说明**

1. **忘记检查返回值和 `errno`：** 文件操作很容易出错，例如文件不存在、权限不足等。忘记检查 `open`, `fcntl` 等函数的返回值，并根据 `errno` 处理错误是很常见的错误。
   ```c++
   int fd = open("non_existent_file.txt", O_RDONLY);
   // 缺少错误检查
   read(fd, buffer, size); // 可能会导致程序崩溃
   ```

2. **不理解 `FD_CLOEXEC` 标志：**  在 `fork` 后 `execve` 前没有正确设置 `FD_CLOEXEC` 标志，可能导致子进程意外地继承了父进程的文件描述符，造成安全风险或资源泄漏。

3. **错误地使用文件锁：**  不正确地使用 `F_SETLK` 或 `F_SETLKW` 可能会导致死锁或数据竞争。

4. **滥用 `fallocate`：**  过度使用 `fallocate` 可能会导致磁盘空间浪费。

5. **混淆 `splice`, `tee`, `vmsplice` 的用途：**  这些函数用于不同的场景，错误地使用可能会导致数据传输失败或性能下降。

**Android framework or ndk 是如何一步步的到达这里**

1. **Android Framework (Java 层)：**
   * 当一个 Android 应用需要访问文件时，通常会使用 `java.io.File`, `FileInputStream`, `FileOutputStream` 等 Java 类。
   * 这些 Java 类的底层实现会调用 Android Runtime (ART) 或 Dalvik 虚拟机提供的 JNI (Java Native Interface) 方法。

2. **Android Runtime (ART/Dalvik)：**
   * ART 或 Dalvik 虚拟机中与文件操作相关的 JNI 方法会调用 Bionic 库中相应的 C/C++ 函数。例如，`FileInputStream.open()` 可能会调用 Bionic 的 `open()` 函数。

3. **Bionic 库 (C/C++ 层)：**
   * Bionic 库中的 `open()`, `fcntl()` 等函数是对 Linux 内核提供的系统调用的封装。它们负责将用户空间的请求转换为内核能够理解的操作，并处理系统调用的返回值。

4. **Linux 内核：**
   * Linux 内核接收到来自 Bionic 库的系统调用请求后，会执行相应的内核代码来完成文件操作，例如查找文件、分配内存、读写磁盘等。

**Frida hook 示例调试步骤**

可以使用 Frida hook 这些 libc 函数来观察其行为。以下是一些示例：

```python
import frida
import sys

package_name = "your.app.package.name"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"[-] Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_source = """
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
    onEnter: function(args) {
        var pathname = Memory.readUtf8String(args[0]);
        var flags = args[1].toInt();
        var mode = args[2] ? args[2].toInt() : -1;
        send(`open("${pathname}", flags=${flags}, mode=${mode.toString(8)})`);
    },
    onLeave: function(retval) {
        send(`open returned: ${retval}`);
    }
});

Interceptor.attach(Module.findExportByName("libc.so", "fcntl"), {
    onEnter: function(args) {
        var fd = args[0].toInt();
        var cmd = args[1].toInt();
        send(`fcntl(fd=${fd}, cmd=${cmd})`);
    },
    onLeave: function(retval) {
        send(`fcntl returned: ${retval}`);
    }
});
"""

script = session.create_script(script_source)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤：**

1. **安装 Frida 和 adb。**
2. **确保你的 Android 设备已 root，并安装了 frida-server。**
3. **将上面的 Python 脚本保存到一个文件 (例如 `hook_fcntl.py`)。**
4. **将 `your.app.package.name` 替换为你想要调试的 Android 应用的包名。**
5. **运行 Python 脚本： `python hook_fcntl.py`。**
6. **在你的 Android 设备上操作目标应用，例如打开文件、进行网络请求等。**
7. **Frida 会拦截对 `open` 和 `fcntl` 函数的调用，并在终端输出相关信息，包括函数参数和返回值。**

你可以根据需要扩展这个脚本来 hook 其他 `fcntl` 相关的函数，并观察它们的行为，这对于理解 Android 框架如何使用这些底层系统调用非常有帮助。

希望这个详细的分析能够帮助你理解 `bionic/tests/fcntl_test.cpp` 文件的功能和它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/tests/fcntl_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#include <fcntl.h>
#include <string.h>
#include <sys/utsname.h>
#include <sys/vfs.h>

#include <android-base/file.h>
#include <android-base/silent_death_test.h>
#include <android-base/stringprintf.h>

// Glibc v2.19 doesn't include these in fcntl.h so host builds will fail without.
#if !defined(FALLOC_FL_PUNCH_HOLE) || !defined(FALLOC_FL_KEEP_SIZE)
#include <linux/falloc.h>
#endif
#if !defined(EXT4_SUPER_MAGIC)
#include <linux/magic.h>
#endif

#include "utils.h"

using fcntl_DeathTest = SilentDeathTest;

TEST(fcntl, fcntl_smoke) {
  int fd = open("/proc/version", O_RDONLY);
  ASSERT_TRUE(fd != -1);

  int flags = fcntl(fd, F_GETFD);
  ASSERT_TRUE(flags != -1);
  ASSERT_EQ(0, flags & FD_CLOEXEC);

  int rc = fcntl(fd, F_SETFD, FD_CLOEXEC);
  ASSERT_EQ(0, rc);

  flags = fcntl(fd, F_GETFD);
  ASSERT_TRUE(flags != -1);
  ASSERT_EQ(FD_CLOEXEC, flags & FD_CLOEXEC);

  close(fd);
}

TEST(fcntl, open_open64) {
  int fd;

  fd = open("/proc/version", O_RDONLY);
  ASSERT_TRUE(fd != -1);
  close(fd);

  fd = open64("/proc/version", O_RDONLY);
  ASSERT_TRUE(fd != -1);
  close(fd);
}

TEST(fcntl, openat_openat64) {
  int fd;

  fd = openat(AT_FDCWD, "/proc/version", O_RDONLY);
  ASSERT_TRUE(fd != -1);
  close(fd);

  fd = openat64(AT_FDCWD, "/proc/version", O_RDONLY);
  ASSERT_TRUE(fd != -1);
  close(fd);
}

TEST(fcntl, creat_creat64) {
  ASSERT_EQ(-1, creat("", 0666));
  ASSERT_ERRNO(ENOENT);
  ASSERT_EQ(-1, creat64("", 0666));
  ASSERT_ERRNO(ENOENT);
}

TEST(fcntl, posix_fadvise) {
  TemporaryFile tf;
  errno = 0;

  EXPECT_EQ(EBADF, posix_fadvise(-1, 0, 0, POSIX_FADV_NORMAL));
  EXPECT_ERRNO(0);

  EXPECT_EQ(EBADF, posix_fadvise64(-1, 0, 0, POSIX_FADV_NORMAL));
  EXPECT_ERRNO(0);

  EXPECT_EQ(EINVAL, posix_fadvise(tf.fd, 0, 0, -1));
  EXPECT_ERRNO(0);

  EXPECT_EQ(EINVAL, posix_fadvise64(tf.fd, 0, 0, -1));
  EXPECT_ERRNO(0);

  EXPECT_EQ(0, posix_fadvise(tf.fd, 0, 0, POSIX_FADV_NORMAL));
  EXPECT_EQ(0, posix_fadvise64(tf.fd, 0, 0, POSIX_FADV_NORMAL));
}

TEST(fcntl, fallocate_EINVAL) {
  TemporaryFile tf;

  // fallocate/fallocate64 set errno.
  // posix_fallocate/posix_fallocate64 return an errno value.

  errno = 0;
  ASSERT_EQ(-1, fallocate(tf.fd, 0, 0, -1));
  ASSERT_ERRNO(EINVAL);

  errno = 0;
  ASSERT_EQ(-1, fallocate64(tf.fd, 0, 0, -1));
  ASSERT_ERRNO(EINVAL);

  errno = 0;
  ASSERT_EQ(EINVAL, posix_fallocate(tf.fd, 0, -1));
  ASSERT_ERRNO(0);

  errno = 0;
  ASSERT_EQ(EINVAL, posix_fallocate64(tf.fd, 0, -1));
  ASSERT_ERRNO(0);
}

TEST(fcntl, fallocate) {
  TemporaryFile tf;
  struct stat sb;
  ASSERT_EQ(0, fstat(tf.fd, &sb));
  ASSERT_EQ(0, sb.st_size);

#if defined(__BIONIC__)
  ASSERT_EQ(0, fallocate(tf.fd, 0, 0, 1));
  ASSERT_EQ(0, fstat(tf.fd, &sb));
  ASSERT_EQ(1, sb.st_size);

  ASSERT_EQ(0, fallocate64(tf.fd, 0, 0, 2));
  ASSERT_EQ(0, fstat(tf.fd, &sb));
  ASSERT_EQ(2, sb.st_size);
#endif

  ASSERT_EQ(0, posix_fallocate(tf.fd, 0, 3));
  ASSERT_EQ(0, fstat(tf.fd, &sb));
  ASSERT_EQ(3, sb.st_size);

  ASSERT_EQ(0, posix_fallocate64(tf.fd, 0, 4));
  ASSERT_EQ(0, fstat(tf.fd, &sb));
  ASSERT_EQ(4, sb.st_size);
}

TEST(fcntl, f_getlk) {
  int fd = open("/proc/version", O_RDONLY);
  ASSERT_TRUE(fd != -1);

  struct flock check_lock;
  check_lock.l_type = F_WRLCK;
  check_lock.l_start = 0;
  check_lock.l_whence = SEEK_SET;
  check_lock.l_len = 0;

  ASSERT_EQ(0, fcntl(fd, F_GETLK, &check_lock));
  close(fd);
}

TEST(fcntl, f_getlk64) {
  int fd = open64("/proc/version", O_RDONLY);
  ASSERT_TRUE(fd != -1);

  struct flock64 check_lock;
  check_lock.l_type = F_WRLCK;
  check_lock.l_start = 0;
  check_lock.l_whence = SEEK_SET;
  check_lock.l_len = 0;

  ASSERT_EQ(0, fcntl(fd, F_GETLK64, &check_lock));
  close(fd);
}

TEST(fcntl, splice) {
  int pipe_fds[2];
  ASSERT_EQ(0, pipe(pipe_fds));

  int in = open("/proc/cpuinfo", O_RDONLY);
  ASSERT_NE(in, -1);

  TemporaryFile tf;

  ssize_t bytes_read = splice(in, nullptr, pipe_fds[1], nullptr, 8*1024, SPLICE_F_MORE | SPLICE_F_MOVE);
  ASSERT_NE(bytes_read, -1);

  ssize_t bytes_written = splice(pipe_fds[0], nullptr, tf.fd, nullptr, bytes_read, SPLICE_F_MORE | SPLICE_F_MOVE);
  ASSERT_EQ(bytes_read, bytes_written);

  close(pipe_fds[0]);
  close(pipe_fds[1]);
  close(in);
}

TEST(fcntl, vmsplice) {
  int pipe_fds[2];
  ASSERT_EQ(0, pipe(pipe_fds));

  iovec v[2];
  v[0].iov_base = const_cast<char*>("hello ");
  v[0].iov_len = 6;
  v[1].iov_base = const_cast<char*>("world\n");
  v[1].iov_len = 6;
  ssize_t bytes_written = vmsplice(pipe_fds[1], v, sizeof(v)/sizeof(iovec), 0);
  ASSERT_EQ(v[0].iov_len + v[1].iov_len, static_cast<size_t>(bytes_written));
  close(pipe_fds[1]);

  char buf[BUFSIZ];
  FILE* fp = fdopen(pipe_fds[0], "r");
  ASSERT_TRUE(fp != nullptr);
  ASSERT_TRUE(fgets(buf, sizeof(buf), fp) != nullptr);
  fclose(fp);
  ASSERT_STREQ("hello world\n", buf);
}

TEST(fcntl, tee) {
  char expected[BUFSIZ];
  FILE* expected_fp = fopen("/proc/version", "r");
  ASSERT_TRUE(expected_fp != nullptr);
  ASSERT_TRUE(fgets(expected, sizeof(expected), expected_fp) != nullptr);
  fclose(expected_fp);

  int pipe1[2];
  ASSERT_EQ(0, pipe(pipe1));

  int pipe2[2];
  ASSERT_EQ(0, pipe(pipe2));

  int in = open("/proc/version", O_RDONLY);
  ASSERT_NE(in, -1);

  // Write /proc/version into pipe1.
  ssize_t bytes_read = splice(in, nullptr, pipe1[1], nullptr, 8*1024, SPLICE_F_MORE | SPLICE_F_MOVE);
  ASSERT_NE(bytes_read, -1);
  close(pipe1[1]);

  // Tee /proc/version from pipe1 into pipe2.
  ssize_t bytes_teed = tee(pipe1[0], pipe2[1], SIZE_MAX, 0);
  ASSERT_EQ(bytes_read, bytes_teed);
  close(pipe2[1]);

  // The out fds of both pipe1 and pipe2 should now contain /proc/version.
  char buf1[BUFSIZ];
  FILE* fp1 = fdopen(pipe1[0], "r");
  ASSERT_TRUE(fp1 != nullptr);
  ASSERT_TRUE(fgets(buf1, sizeof(buf1), fp1) != nullptr);
  fclose(fp1);

  char buf2[BUFSIZ];
  FILE* fp2 = fdopen(pipe2[0], "r");
  ASSERT_TRUE(fp2 != nullptr);
  ASSERT_TRUE(fgets(buf2, sizeof(buf2), fp2) != nullptr);
  fclose(fp2);

  ASSERT_STREQ(expected, buf1);
  ASSERT_STREQ(expected, buf2);
}

TEST(fcntl, readahead) {
  // Just check that the function is available.
  errno = 0;
  ASSERT_EQ(-1, readahead(-1, 0, 123));
  ASSERT_ERRNO(EBADF);
}

TEST(fcntl, sync_file_range) {
  // Just check that the function is available.
  errno = 0;
  ASSERT_EQ(-1, sync_file_range(-1, 0, 0, 0));
  ASSERT_ERRNO(EBADF);

  TemporaryFile tf;
  ASSERT_EQ(0, sync_file_range(tf.fd, 0, 0, 0));

  // The arguments to the underlying system call are in a different order on 32-bit ARM.
  // Check that the `flags` argument gets passed to the kernel correctly.
  errno = 0;
  ASSERT_EQ(-1, sync_file_range(tf.fd, 0, 0, ~0));
  ASSERT_ERRNO(EINVAL);
}

static bool parse_kernel_release(long* const major, long* const minor) {
  struct utsname buf;
  if (uname(&buf) == -1) {
    return false;
  }
  return sscanf(buf.release, "%ld.%ld", major, minor) == 2;
}

/*
 * b/28760453:
 * Kernels older than 4.1 should have ext4 FALLOC_FL_PUNCH_HOLE disabled due to CVE-2015-8839.
 * Devices that fail this test should cherry-pick the following commit:
 * https://android.googlesource.com/kernel/msm/+/bdba352e898cbf57c8620ad68c8abf749c784d1f
 */
TEST(fcntl, falloc_punch) {
  long major = 0, minor = 0;
  ASSERT_TRUE(parse_kernel_release(&major, &minor));

  if (major < 4 || (major == 4 && minor < 1)) {
    TemporaryFile tf;
    struct statfs sfs;
    ASSERT_EQ(0, fstatfs(tf.fd, &sfs));
    if (sfs.f_type == EXT4_SUPER_MAGIC) {
      ASSERT_EQ(-1, fallocate(tf.fd, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, 1));
      ASSERT_ERRNO(EOPNOTSUPP);
    }
  }
}

TEST(fcntl, open_O_TMPFILE_mode) {
  TemporaryDir dir;
  // Without O_EXCL, we're allowed to give this a name later.
  // (This is unrelated to the O_CREAT interaction with O_EXCL.)
  const mode_t perms = S_IRUSR | S_IWUSR;
  int fd = open(dir.path, O_TMPFILE | O_RDWR, perms);

  // Ignore kernels without O_TMPFILE support (< 3.11).
  if (fd == -1 && (errno == EISDIR || errno == EINVAL || errno == EOPNOTSUPP)) return;

  ASSERT_TRUE(fd != -1) << strerror(errno);

  // Does the fd claim to have the mode we set?
  struct stat sb = {};
  ASSERT_EQ(0, fstat(fd, &sb));
  ASSERT_EQ(perms, (sb.st_mode & ~S_IFMT));

  // On Android if we're not root, we won't be able to create links anyway...
  if (getuid() != 0) return;

  std::string final_path = android::base::StringPrintf("%s/named_now", dir.path);
  ASSERT_EQ(0, linkat(AT_FDCWD, android::base::StringPrintf("/proc/self/fd/%d", fd).c_str(),
                      AT_FDCWD, final_path.c_str(),
                      AT_SYMLINK_FOLLOW));
  ASSERT_EQ(0, close(fd));

  // Does the resulting file claim to have the mode we set?
  ASSERT_EQ(0, stat(final_path.c_str(), &sb));
  ASSERT_EQ(perms, (sb.st_mode & ~S_IFMT));

  // With O_EXCL, you're not allowed to add a name later.
  fd = open(dir.path, O_TMPFILE | O_RDWR | O_EXCL, S_IRUSR | S_IWUSR);
  ASSERT_TRUE(fd != -1) << strerror(errno);
  errno = 0;
  ASSERT_EQ(-1, linkat(AT_FDCWD, android::base::StringPrintf("/proc/self/fd/%d", fd).c_str(),
                       AT_FDCWD, android::base::StringPrintf("%s/no_chance", dir.path).c_str(),
                       AT_SYMLINK_FOLLOW));
  ASSERT_ERRNO(ENOENT);
  ASSERT_EQ(0, close(fd));
}

TEST_F(fcntl_DeathTest, fcntl_F_SETFD) {
  EXPECT_DEATH(fcntl(0, F_SETFD, O_NONBLOCK), "only supports FD_CLOEXEC");
}

"""

```