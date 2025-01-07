Response:
Let's break down the thought process for analyzing the provided C++ test file.

**1. Initial Understanding of the Context:**

The prompt clearly states this is a test file (`.cpp`) located within the `bionic/tests` directory of Android. It mentions `bionic` is Android's C library, math library, and dynamic linker. This immediately signals that the code likely tests core system functionality related to these areas. The filename `bug_26110743_test.cpp` suggests it's a specific test case designed to verify a fix for a known bug.

**2. High-Level Code Scan and Structure Identification:**

I quickly scanned the code, noticing the following key elements:

* **Includes:**  `<gtest/gtest.h>`, `<pthread.h>`, `<fcntl.h>`, `<unistd.h>`, `<sys/types.h>`, `<sys/stat.h>`, `<sys/prctl.h>`, `<string>`, `<android-base/scopeguard.h>`. These headers indicate the code interacts with threading, file operations, system calls, and string manipulation. The `gtest` inclusion signifies this is a unit test using the Google Test framework.
* **`extern "C" pid_t gettid();`:** This declares an external C function `gettid()`, which is crucial for thread identification. Since it's `extern "C"`, it reinforces the connection to the C library.
* **`static void ProcSelfReadlinkBody()` and `static void* ProcSelfReadlink(void*)`:**  These function pairs suggest a test related to reading symbolic links under `/proc/self`. The `Body` variant likely contains the core logic, while the other is a wrapper for use with `pthread_create`.
* **`TEST(bug_26110743, ProcSelfReadlink)` and `TEST(bug_26110743, ProcSelfReadlink_NotDumpable)`:**  These are Google Test test cases, clearly named to relate to the bug number and the specific scenario (dumpable/not dumpable).
* **Similar pattern for `ProcTaskFdReadlinkBody()` and `ProcTaskFdReadlink()`:**  This strongly indicates another test, likely focused on `/proc/<pid>/task/<tid>/fd`.
* **Use of `ASSERT_*` macros:** These are Google Test assertions, used to verify expected outcomes during the test execution.
* **`android::base::make_scope_guard`:** This is a RAII (Resource Acquisition Is Initialization) pattern, ensuring that the `prctl` state is restored, even if an assertion fails.

**3. Deep Dive into Key Functionality and System Calls:**

* **`readlink(buf, buf2, sizeof(buf2))`:**  This is the central system call being tested. I know `readlink` is used to read the target of a symbolic link. The test constructs paths like `/proc/self/fd/<fd>` and `/proc/<pid>/task/<tid>/fd/<fd>`, which are special files in the Linux process information pseudo-filesystem (`/proc`). These files are symbolic links pointing to the actual files or devices associated with the file descriptor.
* **`/proc/self/fd/`:** This directory contains symbolic links representing the file descriptors open in the current process.
* **`/proc/<pid>/task/<tid>/fd/`:** This directory, specific to threads within a process, contains symbolic links to file descriptors open by that specific thread.
* **`open("/dev/null", O_RDWR | O_CLOEXEC)`:** This opens the special device `/dev/null`, which discards any data written to it and returns end-of-file on reading. The `O_CLOEXEC` flag ensures the file descriptor is closed in child processes after an `execve`.
* **`getpid()` and `gettid()`:**  These system calls return the process ID and thread ID, respectively. The test explicitly asserts that `mypid != mytid`, confirming that it's running in a multithreaded environment (or at least the test setup creates a separate thread).
* **`pthread_create()` and `pthread_join()`:** These functions are used to create and wait for the termination of a new thread. The tests use threads to explore scenarios where different threads are accessing `/proc`.
* **`prctl(PR_GET_DUMPABLE, ...)` and `prctl(PR_SET_DUMPABLE, ...)`:** The `prctl` system call with `PR_GET_DUMPABLE` and `PR_SET_DUMPABLE` is used to query and set the dumpable attribute of a process. A non-dumpable process (dumpable=0) has restrictions on debugging and core dumping. The tests explicitly check behavior when the process is not dumpable.
* **`snprintf()`:**  This is used to format strings, specifically to construct the paths to the symbolic links in `/proc`.
* **`ASSERT_NE(-1, fd)`:** This checks if the `open()` call was successful.
* **`ASSERT_LT(0, length)`:** This checks if `readlink()` successfully read the link.
* **`ASSERT_EQ("/dev/null", std::string(buf2, length))`:** This verifies that the content of the symbolic link points to `/dev/null`.

**4. Relating to Android Functionality:**

The tests are directly relevant to Android's core functionality. The `/proc` filesystem is a fundamental part of the Linux kernel, upon which Android is built. Accessing and interpreting information within `/proc` is common for various Android system services and applications for monitoring, debugging, and introspection. The tests specifically address potential kernel-level issues related to how `/proc/self/fd` and `/proc/<pid>/task/<tid>/fd` behave, especially in multithreaded scenarios and with the `dumpable` attribute.

**5. Dynamic Linker Considerations (Limited in this case):**

While the prompt mentions the dynamic linker, this particular test file doesn't directly exercise its functionality. The focus is on file system access and threading. However, I would still consider how the dynamic linker might be *indirectly* involved. For example, the `libc.so` where `readlink`, `open`, `pthread_create`, etc., reside, would have been loaded by the dynamic linker.

**6. Logic Inference and Assumptions:**

The tests are designed to verify that `readlink` on the specific `/proc` paths correctly returns the target of the symbolic link, even in a multithreaded context and when the process is not dumpable. The error messages within the tests indicate that specific kernel patches are required for this functionality to work correctly. The tests implicitly assume a Linux kernel environment with the `/proc` filesystem.

**7. Common User Errors:**

A common mistake would be directly manipulating file descriptors obtained from `/proc` without fully understanding their nature. For instance, attempting to `write()` to a file descriptor obtained from `/proc/self/fd` might not always work as expected, as these are symbolic links to underlying files. Another error could be relying on the behavior of `/proc` without checking for necessary kernel features or permissions.

**8. Android Framework/NDK Path (Hypothetical):**

While this test is low-level, a hypothetical path from the Android Framework could involve a system service needing to inspect the file descriptors of another process for debugging or resource monitoring. This could involve the service using APIs (potentially through the NDK) that eventually lead to system calls like `readlink` on `/proc`.

**9. Frida Hooking (Conceptual):**

To debug, I'd use Frida to hook the `readlink` system call and observe the arguments (the path being read) and the return value. This would help confirm whether the correct `/proc` paths are being accessed and what the `readlink` call is returning. I'd also consider hooking `open` to see which file descriptors are being created.

**Self-Correction/Refinement during the process:**

Initially, I might have focused too much on the threading aspect. However, realizing the core of the test is `readlink` on `/proc` paths shifted the focus to understanding the significance of these special files and the kernel patches mentioned in the error messages. I also initially overlooked the `O_CLOEXEC` flag, but recognizing its role in preventing file descriptor leaks in forked processes added another layer of understanding. Finally, while the dynamic linker isn't explicitly tested here, acknowledging its role in loading the necessary libraries provides a more complete picture.
这个C++文件 `bionic/tests/bug_26110743_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用于验证修复了 bug 26110743 的代码是否正确工作。 从代码内容来看，它的主要功能是 **测试 `readlink` 系统调用在读取 `/proc` 文件系统中的特定路径时的行为，尤其是在多线程环境下以及进程不可 dump 的情况下**。

下面详细解释其功能和与 Android 的关系：

**1. 功能列举:**

* **测试 `readlink` 在 `/proc/self/fd/` 下的行为:**  测试在多线程环境下，读取指向已打开文件描述符的符号链接（例如 `/proc/self/fd/<fd>`）是否能正确返回目标路径。
* **测试 `readlink` 在 `/proc/<pid>/task/<tid>/fd/` 下的行为:** 测试在多线程环境下，读取特定线程拥有的文件描述符的符号链接（例如 `/proc/123/task/456/fd/789`）是否能正确返回目标路径。
* **测试在进程不可 dump 时的 `readlink` 行为:**  测试当进程被设置为不可 dump（dumpable 属性为 0）时，上述的 `readlink` 操作是否仍然能正常工作。
* **使用 Google Test 框架:**  利用 Google Test 框架编写单元测试，通过 `ASSERT_*` 宏来断言测试结果是否符合预期。
* **使用 `pthread` 创建和管理线程:**  模拟多线程环境，以验证在并发访问 `/proc` 文件系统时 `readlink` 的行为。
* **使用 `prctl` 系统调用:**  设置和获取进程的 dumpable 属性，用于测试在不同 dumpable 状态下的行为。
* **使用 scope guard 管理资源:**  使用 `android::base::make_scope_guard` 确保在测试结束后恢复进程的 dumpable 属性，即使测试失败也能保证状态恢复。

**2. 与 Android 功能的关系及举例说明:**

这个测试文件直接关系到 Android 系统的核心功能，因为它测试了与进程管理、文件系统访问以及调试相关的基本系统调用。

* **进程和线程管理:** Android 系统大量使用进程和线程。测试 `readlink` 在 `/proc/<pid>/task/<tid>/fd/` 下的行为，确保了系统能够正确跟踪和访问特定线程的文件描述符信息。例如，Android 的 `am` (Activity Manager) 命令可能需要查看进程的状态，这可能涉及到读取 `/proc` 文件系统的信息。
* **文件系统访问:**  `readlink` 是一个基本的文件系统操作。很多 Android 系统服务和应用程序需要读取符号链接的目标路径。例如，`ls -l` 命令在 Android shell 中会使用 `readlink` 来显示符号链接指向的目标。
* **调试和诊断:**  `/proc` 文件系统是 Android 系统进行调试和诊断的重要工具。开发者可以使用 `adb shell` 来查看 `/proc` 下的信息，例如进程的内存映射、打开的文件等。如果 `readlink` 在 `/proc` 下的行为不正确，可能会导致调试工具无法正常工作。例如，在调试一个崩溃的进程时，调试器可能需要读取 `/proc/<pid>/fd/` 下的符号链接来了解进程打开了哪些文件。
* **安全性和权限管理:**  进程的 dumpable 属性会影响调试器的行为。测试在不可 dump 状态下的 `readlink` 行为，确保了在这种安全限制下，基本的系统调用仍然能提供必要的信息。

**3. 详细解释 libc 函数的功能是如何实现的:**

这里涉及到的 libc 函数主要是 `open`, `readlink`, `close`, `snprintf`, `pthread_create`, `pthread_join`, `getpid`, `gettid`, 和 `prctl`。

* **`open(const char *pathname, int flags, ...)`:**
    * **功能:**  打开一个文件，返回一个文件描述符。
    * **实现:**  这是一个系统调用，最终会陷入内核。内核会根据 `pathname` 查找对应的文件或设备，并根据 `flags` 设置打开模式（读、写、追加等）。如果成功，内核会返回一个未被占用的文件描述符；如果失败，返回 -1 并设置 `errno`。在 Android 中，Bionic 库会提供一个封装好的 `open` 函数，它会调用底层的 Linux 系统调用。
* **`readlink(const char *pathname, char *buf, size_t bufsiz)`:**
    * **功能:**  读取符号链接指向的目标路径。
    * **实现:**  这也是一个系统调用。内核会检查 `pathname` 是否是一个符号链接。如果是，内核会将符号链接指向的目标路径复制到 `buf` 中，最多复制 `bufsiz` 个字节，并返回复制的字节数。如果 `pathname` 不是符号链接或者发生错误，返回 -1 并设置 `errno`。Bionic 库提供的 `readlink` 函数会封装底层的系统调用。
* **`close(int fd)`:**
    * **功能:**  关闭一个打开的文件描述符。
    * **实现:**  这是一个系统调用。内核会将 `fd` 对应的文件表项标记为可回收，并释放相关的资源。Bionic 库的 `close` 函数是对系统调用的简单封装。
* **`snprintf(char *str, size_t size, const char *format, ...)`:**
    * **功能:**  格式化字符串并写入到缓冲区，类似于 `sprintf`，但可以防止缓冲区溢出。
    * **实现:**  这是一个 libc 函数，在用户空间实现。它会解析 `format` 字符串，并将后面的参数按照格式进行转换，然后写入到 `str` 指向的缓冲区中，最多写入 `size - 1` 个字符，并在末尾添加 null 终止符。
* **`pthread_create(pthread_t *thread, const pthread_attr_t *attr, void *(*start_routine) (void *), void *arg)`:**
    * **功能:**  创建一个新的线程。
    * **实现:**  这是一个 POSIX 线程库函数。在 Android 中，Bionic 库提供了 `pthread` 的实现。它会调用底层的系统调用（例如 `clone` 或 `fork` 加 `execve` 的组合，取决于具体的实现和平台），创建一个新的执行上下文（线程），并让其从 `start_routine` 函数开始执行。
* **`pthread_join(pthread_t thread, void **retval)`:**
    * **功能:**  等待指定的线程结束。
    * **实现:**  这是一个 POSIX 线程库函数。Bionic 库的实现会调用底层的系统调用（例如 `waitpid` 或者特定的线程等待机制），阻塞当前线程，直到目标线程结束。如果 `retval` 不为空，则会将目标线程的返回值写入到 `*retval` 中。
* **`getpid(void)`:**
    * **功能:**  获取当前进程的 ID。
    * **实现:**  这是一个系统调用。内核会返回当前进程的 PID。Bionic 库的 `getpid` 函数是对系统调用的简单封装。
* **`gettid(void)`:**
    * **功能:**  获取当前线程的 ID。
    * **实现:**  这是一个 Linux 特有的系统调用（并非所有的 POSIX 系统都有）。内核会返回当前线程的 TID。Bionic 库的 `gettid` 函数是对系统调用的简单封装。
* **`prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)`:**
    * **功能:**  对进程或线程的行为进行控制。
    * **实现:**  这是一个系统调用。内核会根据 `option` 的值执行不同的操作。例如，当 `option` 为 `PR_SET_DUMPABLE` 时，内核会设置进程的 dumpable 属性。Bionic 库的 `prctl` 函数是对系统调用的简单封装。

**4. 涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

虽然这个测试文件本身并没有直接测试 dynamic linker 的功能，但它依赖于 libc.so，而 libc.so 是由 dynamic linker 加载的。

**so 布局样本 (libc.so):**

一个简化的 `libc.so` 布局可能如下所示：

```
LOAD ADDR:     0xb7000000  (假设的加载地址)

.dynamic:      ... (包含动态链接信息的段)
.hash / .gnu.hash: ... (符号哈希表)
.dynsym:       ... (动态符号表，包含导出的函数和变量)
.dynstr:       ... (动态字符串表，存储符号名称)
.rel.dyn / .rela.dyn: ... (动态重定位表，用于链接时修改代码或数据)
.rel.plt / .rela.plt: ... (PLT (Procedure Linkage Table) 重定位表)
.text:         ... (代码段，包含 open, readlink 等函数的机器码)
.rodata:       ... (只读数据段，包含字符串常量等)
.data:         ... (已初始化的全局变量和静态变量)
.bss:          ... (未初始化的全局变量和静态变量)
...
```

**链接的处理过程:**

1. **加载:** 当测试程序（例如 `bug_26110743_test`）启动时，内核会将程序加载到内存中。如果程序依赖于动态链接库（例如 libc.so），内核会将加载的责任交给 dynamic linker（通常是 `/system/bin/linker` 或 `/system/bin/linker64`）。
2. **查找依赖:** dynamic linker 会读取测试程序 ELF 头的 `.dynamic` 段，找到其依赖的共享库列表（例如 `libc.so`）。
3. **加载共享库:** dynamic linker 会在预定义的路径（例如 `/system/lib`, `/system/lib64`, vendor 路径等）中查找并加载 `libc.so` 到内存中。
4. **符号解析:** dynamic linker 会解析测试程序和 `libc.so` 的符号表。当测试程序调用 `open`, `readlink` 等函数时，这些符号在编译时是未解析的。dynamic linker 会在 `libc.so` 的 `.dynsym` 中查找这些符号的地址。
5. **重定位:**  由于 `libc.so` 被加载到内存的地址可能不是编译时预期的地址，dynamic linker 需要修改测试程序和 `libc.so` 中与地址相关的指令和数据。这通过读取 `.rel.dyn` 和 `.rel.plt` 等重定位表来完成。例如，当调用 `open` 函数时，实际执行的跳转指令需要指向 `libc.so` 中 `open` 函数的实际加载地址。PLT (Procedure Linkage Table) 和 GOT (Global Offset Table) 机制被广泛用于延迟绑定，即第一次调用共享库函数时才进行解析和重定位。

**假设输入与输出 (针对 `ProcSelfReadlinkBody` 函数):**

* **假设输入:**
    * 当前进程打开了一个文件描述符，例如 `fd = 3` 指向 `/dev/null`。
* **逻辑推理:**
    * `snprintf(buf, sizeof(buf), "/proc/self/fd/%d", fd);` 会生成字符串 `/proc/self/fd/3`。
    * `readlink("/proc/self/fd/3", buf2, sizeof(buf2))` 会读取符号链接 `/proc/self/fd/3` 的目标路径。
* **预期输出:**
    * `readlink` 返回的值大于 0。
    * `buf2` 的内容为 `"/dev/null"`。

**用户或编程常见的使用错误:**

* **不检查 `readlink` 的返回值:**  `readlink` 可能会失败，例如当路径不存在或者不是符号链接时。如果忽略返回值并直接使用 `buf2`，可能会导致未定义行为。
    ```c++
    char buf2[1024];
    ssize_t length = readlink("/nonexistent_path", buf2, sizeof(buf2));
    // 错误：没有检查 length 的值
    printf("Link target: %s\n", buf2); // 可能打印乱码或导致崩溃
    ```
* **缓冲区溢出:**  提供的缓冲区 `buf2` 可能小于符号链接的目标路径长度。`readlink` 只会复制 `bufsiz - 1` 个字节，并且不会添加 null 终止符。因此，需要确保缓冲区足够大，或者手动添加 null 终止符。
    ```c++
    char buf2[5]; // 缓冲区太小
    ssize_t length = readlink("/proc/self/exe", buf2, sizeof(buf2));
    if (length > 0) {
        buf2[sizeof(buf2) - 1] = '\0'; // 确保 null 终止
        printf("Link target: %s\n", buf2); // 可能被截断
    }
    ```
* **在多线程环境下使用静态缓冲区:**  在多线程环境下，如果多个线程同时调用使用了静态缓冲区的函数（虽然这个例子中没有直接体现，但需要注意），可能会导致数据竞争。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

虽然这个测试是 Bionic 内部的，但可以通过一个假设的场景来说明 Android Framework 或 NDK 如何间接到达这里：

假设一个 Android 应用需要获取当前进程打开的文件的路径。

1. **Android Framework:** 应用可能调用 Android Framework 提供的 API，例如 `android.os.Process.myPid()` 获取进程 ID。
2. **NDK:**  应用开发者可以使用 NDK 调用底层的 C/C++ 函数。他们可能会使用 `opendir`, `readdir` 和 `readlink` 等 libc 函数来遍历 `/proc/self/fd/` 目录并读取符号链接的目标。
3. **Bionic libc:** NDK 最终会调用 Bionic libc 提供的 `readlink` 函数。
4. **Kernel:** Bionic libc 的 `readlink` 函数会发起 `readlink` 系统调用，最终由 Linux 内核处理。

**Frida Hook 示例:**

可以使用 Frida hook `readlink` 系统调用来观察其行为。

```javascript
// Frida 脚本
if (Process.platform === 'linux') {
  const readlinkPtr = Module.findExportByName(null, 'readlink');
  if (readlinkPtr) {
    Interceptor.attach(readlinkPtr, {
      onEnter: function (args) {
        const pathname = Memory.readUtf8String(args[0]);
        const buf = args[1];
        const bufsiz = args[2].toInt();
        console.log(`readlink("${pathname}", ${buf}, ${bufsiz})`);
        this.buf = buf;
        this.bufsiz = bufsiz;
      },
      onLeave: function (retval) {
        const length = retval.toInt();
        if (length > 0) {
          const target = Memory.readUtf8String(this.buf, Math.min(length, this.bufsiz));
          console.log(` => 返回 ${length}, target: "${target}"`);
        } else {
          console.log(` => 返回 ${length}`);
        }
      }
    });
  } else {
    console.log("未找到 readlink 函数");
  }
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存为 `readlink_hook.js`。
2. 使用 Frida 连接到目标 Android 进程：`frida -U -f <package_name> -l readlink_hook.js --no-pause`  或者先启动应用，然后使用 `frida -U <process_name_or_pid> -l readlink_hook.js`.
3. 当应用执行到调用 `readlink` 的代码路径时，Frida 会打印出 `readlink` 的参数和返回值，包括读取的路径和目标路径。

通过 Frida Hook，你可以观察到应用在哪些场景下调用了 `readlink`，读取了哪些 `/proc` 下的符号链接，以及 `readlink` 的返回结果，从而帮助你理解 Android Framework 或 NDK 是如何一步步到达这个底层的 libc 函数的。

Prompt: 
```
这是目录为bionic/tests/bug_26110743_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2015 The Android Open Source Project
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
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/prctl.h>

#include <string>

#include <android-base/scopeguard.h>

extern "C" pid_t gettid();

static void ProcSelfReadlinkBody() {
  char buf[100];
  char buf2[1024];
  int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
  ASSERT_NE(-1, fd);
  snprintf(buf, sizeof(buf), "/proc/self/fd/%d", fd);
  const char* ERRORMSG = "Please apply the following two kernel patches:\n"
    "* https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=73af963f9f3036dffed55c3a2898598186db1045\n"
    "* https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=96d0df79f2644fc823f26c06491e182d87a90c2a\n";
  ssize_t length = readlink(buf, buf2, sizeof(buf2));
  ASSERT_LT(0, length) << ERRORMSG;
  ASSERT_EQ("/dev/null", std::string(buf2, length));
  close(fd);
}

static void* ProcSelfReadlink(void*) {
  ProcSelfReadlinkBody();
  return nullptr;
}

TEST(bug_26110743, ProcSelfReadlink) {
  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, ProcSelfReadlink, nullptr));
  void* result;
  ASSERT_EQ(0, pthread_join(t, &result));
  ASSERT_EQ(nullptr, result);
}

TEST(bug_26110743, ProcSelfReadlink_NotDumpable) {
  int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
  prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  auto guard = android::base::make_scope_guard([&]() {
    // restore dumpable
    prctl(PR_SET_DUMPABLE, dumpable, 0, 0, 0);
  });

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, ProcSelfReadlink, nullptr));
  void* result;
  ASSERT_EQ(0, pthread_join(t, &result));
  ASSERT_EQ(nullptr, result);
}

static void ProcTaskFdReadlinkBody() {
  char buf[200];
  char buf2[1024];
  int fd = open("/dev/null", O_RDWR | O_CLOEXEC);
  ASSERT_NE(-1, fd);
  pid_t mypid = getpid();
  pid_t mytid = gettid();
  ASSERT_NE(mypid, mytid);
  snprintf(buf, sizeof(buf), "/proc/%d/task/%d/fd/%d", mypid, mytid, fd);
  const char* ERRORMSG = "Please apply the following kernel patch:\n"
    "* https://git.kernel.org/cgit/linux/kernel/git/torvalds/linux.git/commit/?id=54708d2858e79a2bdda10bf8a20c80eb96c20613\n";
  ssize_t length = readlink(buf, buf2, sizeof(buf2));
  ASSERT_LT(0, length) << ERRORMSG;
  ASSERT_EQ("/dev/null", std::string(buf2, length));
  close(fd);
}

static void* ProcTaskFdReadlink(void*) {
  ProcTaskFdReadlinkBody();
  return nullptr;
}

TEST(bug_26110743, ProcTaskFdReadlink) {
  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, ProcTaskFdReadlink, nullptr));
  void* result;
  ASSERT_EQ(0, pthread_join(t, &result));
  ASSERT_EQ(nullptr, result);
}

TEST(bug_26110743, ProcTaskFdReadlink_NotDumpable) {
  int dumpable = prctl(PR_GET_DUMPABLE, 0, 0, 0, 0);
  prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
  auto guard = android::base::make_scope_guard([&]() {
    // restore dumpable
    prctl(PR_SET_DUMPABLE, dumpable, 0, 0, 0);
  });

  pthread_t t;
  ASSERT_EQ(0, pthread_create(&t, nullptr, ProcTaskFdReadlink, nullptr));
  void* result;
  ASSERT_EQ(0, pthread_join(t, &result));
  ASSERT_EQ(nullptr, result);
}

"""

```