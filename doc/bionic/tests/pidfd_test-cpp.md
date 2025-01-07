Response:
Let's break down the thought process for analyzing the `pidfd_test.cpp` file.

**1. Understanding the Core Task:**

The request asks for a comprehensive analysis of a specific C++ test file in the Android bionic library. This includes identifying its functionality, its relation to Android, explaining the libc function implementations (where applicable and relevant within the test context), discussing dynamic linking aspects, providing examples (including error cases and usage), and outlining how Android frameworks/NDK might lead to its execution, culminating in Frida hook examples.

**2. Initial Reading and Overview:**

The first step is to quickly read through the code to get a high-level understanding. Key observations are:

* **Test File:** The filename `pidfd_test.cpp` and the use of `gtest` strongly indicate this is a unit test file.
* **Feature Focus:** The repeated use of `pidfd_open`, `pidfd_getfd`, and `pidfd_send_signal` (and the conditional compilation with `#if defined(__BIONIC__)`) clearly shows the tests are about the `pidfd` family of system calls.
* **Bionic Specific:** The `__BIONIC__` macro signifies that these tests are specifically for the Android C library implementation of these functions.
* **Basic Test Structure:** Each `TEST` or `TEST_F` block represents a separate test case.
* **Use of `unique_fd`:**  This suggests resource management and automatic closing of file descriptors.
* **Error Handling:**  The tests use `ASSERT_NE(-1, ...)` and checks for `errno == ENOSYS` to handle cases where the kernel doesn't support `pidfd`.

**3. Deconstructing Each Test Case:**

Now, analyze each `TEST` function individually:

* **`TEST(pidfd, pidfd_open)`:**
    * **Purpose:**  Tests the basic functionality of `pidfd_open`.
    * **Steps:** Forks a child process, opens a pidfd for the child, waits for the child's exit using `waitid` with `P_PIDFD`.
    * **Key Functions:** `fork`, `_exit`, `pidfd_open`, `waitid`.

* **`TEST(pidfd, pidfd_getfd)`:**
    * **Purpose:** Tests `pidfd_getfd`, which duplicates a file descriptor from another process.
    * **Steps:** Creates a pipe, opens a pidfd for the current process, uses `pidfd_getfd` to duplicate the read end of the pipe into the current process using the pidfd, and then verifies data transfer.
    * **Key Functions:** `pipe`, `pidfd_open`, `pidfd_getfd`, `write`, `read`, `memcmp`.

* **`TEST_F(pidfd_DeathTest, pidfd_send_signal)`:**
    * **Purpose:** Tests sending signals to a process using `pidfd_send_signal`.
    * **Steps:** Opens a pidfd for the current process, sends a null signal (signal 0) to check if the process exists, and then uses `ASSERT_EXIT` to check if sending `SIGINT` terminates a child process.
    * **Key Functions:** `pidfd_open`, `pidfd_send_signal`, `fork` (implicitly through `ASSERT_EXIT`).

**4. Connecting to Android Functionality:**

At this stage, consider how `pidfd` relates to Android:

* **Process Management:** `pidfd` provides a more robust and less race-prone way to refer to processes compared to just using PIDs. This is crucial in a complex system like Android where processes are frequently created and destroyed.
* **Security:** `pidfd` helps in securely managing file descriptors across process boundaries, which is important for application sandboxing in Android.

**5. Explaining `libc` Functions:**

For each `libc` function used in the tests, provide a concise explanation of its purpose. The level of detail depends on the scope of the test. For instance, explaining the low-level kernel implementation of `fork` is probably overkill, but describing its basic function (creating a new process) is relevant. Focus on what the function *does* within the context of the test.

**6. Dynamic Linker Aspects:**

While the test file itself doesn't directly *call* the dynamic linker (`linker64` or `linker`), it depends on it. The `libc.so` library, where these `pidfd_*` functions are implemented, is loaded by the dynamic linker.

* **SO Layout Sample:**  Describe the basic structure of a shared object (`.so`) file.
* **Linking Process:** Explain the high-level linking process: how the dynamic linker resolves symbols when a program starts. In the context of this test, the `pidfd_*` functions are symbols provided by `libc.so`.

**7. Examples and Error Handling:**

* **Assumptions and Outputs:**  For each test, consider the expected outcome under normal conditions.
* **Common Errors:**  Think about what could go wrong when using these functions. `ENOSYS` (if the kernel doesn't support `pidfd`) is already handled in the tests. Other potential errors include invalid PIDs, incorrect signal numbers, or permission issues (although these specific tests don't directly demonstrate permission errors).

**8. Android Framework/NDK Path:**

* **Framework:**  How would Android system services or applications end up using these `pidfd` functions?  Consider scenarios like process monitoring, inter-process communication, and resource management.
* **NDK:** How would an NDK developer access these functions? Through the standard C library headers (`<sys/pidfd.h>`).

**9. Frida Hooking:**

Provide practical Frida examples for hooking the key functions being tested (`pidfd_open`, `pidfd_getfd`, `pidfd_send_signal`). Show how to intercept the calls, print arguments, and potentially modify behavior.

**10. Language and Formatting:**

Finally, ensure the response is in Chinese as requested and well-organized with clear headings and formatting to make it easy to read and understand.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "I need to explain the deep kernel implementation of `pidfd`."  **Correction:**  Focus on the `libc` wrapper functions and their behavior as tested, not the underlying kernel implementation details.
* **Initial thought:** "The dynamic linker isn't directly involved in this test." **Correction:** While not directly *called*, the test relies on `libc.so`, which is loaded by the dynamic linker. Therefore, explain the basics of dynamic linking in this context.
* **Making sure the examples are relevant and easy to understand.**  Focus on simple, illustrative examples rather than overly complex scenarios.

By following this structured approach, considering the nuances of the request, and refining the analysis along the way, a comprehensive and accurate explanation of the `pidfd_test.cpp` file can be generated.
好的，让我们详细分析一下 `bionic/tests/pidfd_test.cpp` 这个文件。

**文件功能概览**

`bionic/tests/pidfd_test.cpp` 是 Android Bionic 库中的一个测试文件，其主要功能是测试与 `pidfd` 相关的系统调用。 `pidfd` (Process File Descriptor) 是一组 Linux 内核提供的系统调用，允许以更安全可靠的方式引用进程。

具体来说，这个测试文件测试了以下三个核心的 `pidfd` 系统调用：

1. **`pidfd_open(pid_t pid, unsigned int flags)`**: 用于打开一个指向指定 PID 进程的文件描述符。
2. **`pidfd_getfd(int pidfd, int fd, unsigned int flags)`**: 用于在由 `pidfd` 引用的进程中复制一个现有的文件描述符。
3. **`pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)`**: 用于向由 `pidfd` 引用的进程发送信号。

**与 Android 功能的关系及举例说明**

`pidfd` 提供的机制在 Android 系统中具有重要的意义，因为它允许进程以更安全和可靠的方式管理和交互其他进程。  传统的通过 PID 进行进程操作的方式存在一些竞态条件，而 `pidfd` 可以有效地解决这些问题。

**举例说明：**

* **进程监控与管理:** Android 系统服务（如 `init` 进程）可能需要监控和管理其他应用程序进程的生命周期。 使用 `pidfd_open` 可以获得一个指向目标进程的稳定句柄，即使目标进程的 PID 在短时间内发生变化（虽然不常见，但理论上存在）。这可以避免在 PID 重用时误操作新的进程。

* **安全的文件描述符传递:** 在 Android 中，进程间通信 (IPC) 是常见的需求。  使用 `pidfd_getfd` 可以安全地将一个文件描述符从一个进程传递到另一个进程，而无需担心目标进程在传递过程中退出或被新的进程取代。 例如，一个应用可能需要将一个打开的 socket 的文件描述符传递给另一个服务进程进行处理。

* **可靠的信号发送:**  发送信号是进程间通信的另一种方式。  使用 `pidfd_send_signal` 可以确保信号被发送到 *正确的* 进程，即使在目标进程 PID 被回收并分配给新进程的情况下。这对于需要精确控制目标进程行为的系统服务非常重要。

**libc 函数的实现解释**

这些 `pidfd_*` 函数实际上是系统调用的 C 库包装器。  它们的实现通常非常简单，主要是将参数传递给内核，并处理内核返回的错误代码。

1. **`pidfd_open(pid_t pid, unsigned int flags)`**:
   - **功能:**  打开一个指向进程 ID 为 `pid` 的进程的文件描述符。`flags` 参数目前保留，应设置为 0。
   - **实现:**  `pidfd_open` 函数会调用底层的 `syscall` 指令，将系统调用号（对应于 `pidfd_open`）和参数（`pid` 和 `flags`）传递给 Linux 内核。内核会创建一个新的文件描述符，该文件描述符指向目标进程。如果指定的进程不存在或发生其他错误，内核会返回一个错误码，C 库函数会将其转换为负返回值并设置 `errno`。

2. **`pidfd_getfd(int pidfd, int fd, unsigned int flags)`**:
   - **功能:**  复制由 `pidfd` 引用的进程中的文件描述符 `fd` 到当前进程。`flags` 参数目前保留，应设置为 0。
   - **实现:**  类似于 `pidfd_open`，`pidfd_getfd` 也是通过 `syscall` 将参数传递给内核。内核会检查 `pidfd` 是否有效，并尝试在目标进程中找到文件描述符 `fd`。如果找到，内核会在当前进程中创建一个新的文件描述符，该文件描述符引用与目标进程中 `fd` 相同的文件描述符表项。

3. **`pidfd_send_signal(int pidfd, int sig, siginfo_t *info, unsigned int flags)`**:
   - **功能:**  向由 `pidfd` 引用的进程发送信号 `sig`。`info` 可以提供关于信号的额外信息，可以为 `NULL`。 `flags` 可以控制信号发送的行为，目前通常设置为 0。
   - **实现:**  `pidfd_send_signal` 通过 `syscall` 将参数传递给内核。内核会验证 `pidfd` 的有效性，并向目标进程发送指定的信号。相比于传统的 `kill` 系统调用使用 PID，`pidfd_send_signal` 使用文件描述符，可以避免 PID 重用带来的问题。

**涉及 dynamic linker 的功能**

虽然这个测试文件本身没有直接涉及到 dynamic linker 的调用，但它依赖于由 dynamic linker 加载的共享库 `libc.so`。  `pidfd_open`、`pidfd_getfd` 和 `pidfd_send_signal` 这些函数的实现都位于 `libc.so` 中。

**so 布局样本:**

```
libc.so:
    .text          # 包含可执行代码
        ...
        pidfd_open:  # pidfd_open 函数的实现代码
            ...
        pidfd_getfd: # pidfd_getfd 函数的实现代码
            ...
        pidfd_send_signal: # pidfd_send_signal 函数的实现代码
            ...
        ...
    .rodata        # 包含只读数据
        ...
    .data          # 包含已初始化的全局变量和静态变量
        ...
    .bss           # 包含未初始化的全局变量和静态变量
        ...
    .dynamic       # 包含动态链接信息，例如依赖的 so 列表，符号表等
        ...
    .symtab        # 符号表，包含导出的和导入的符号
        ...
        pidfd_open  # pidfd_open 符号
        pidfd_getfd # pidfd_getfd 符号
        pidfd_send_signal # pidfd_send_signal 符号
        ...
    .strtab        # 字符串表，包含符号名称等字符串
        ...
```

**链接的处理过程:**

1. **编译阶段:**  当编译器编译 `pidfd_test.cpp` 时，它会识别出对 `pidfd_open` 等函数的调用。 由于这些函数声明在标准头文件（如 `<sys/pidfd.h>`），编译器知道这些是外部符号。
2. **链接阶段:**  链接器将 `pidfd_test.o` (编译后的目标文件) 与所需的库链接。 在这个例子中，它需要链接 `libc.so`。 链接器会查找 `libc.so` 的符号表，找到 `pidfd_open` 等符号的地址，并在 `pidfd_test.o` 中记录下这些符号需要从 `libc.so` 中加载。
3. **加载阶段 (dynamic linker 的工作):** 当 `pidfd_test` 程序运行时，操作系统会加载程序的可执行文件。 程序头中的信息指示这是一个动态链接的程序，操作系统会启动 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`)。
4. **符号解析:** dynamic linker 会读取程序头中的动态链接信息，找到程序依赖的共享库（例如 `libc.so`）。 它会将这些共享库加载到内存中，并解析未定义的符号。  当遇到对 `pidfd_open` 的调用时，dynamic linker 会在 `libc.so` 的符号表中查找 `pidfd_open` 的地址，并将程序中对 `pidfd_open` 的调用重定向到 `libc.so` 中 `pidfd_open` 的实际地址。

**逻辑推理、假设输入与输出**

让我们针对每个测试用例进行逻辑推理：

**`TEST(pidfd, pidfd_open)`**

* **假设输入:**  当前系统支持 `pidfd_open` 系统调用。
* **逻辑推理:**
    1. `fork()` 创建一个子进程。
    2. 在父进程中，`pidfd_open(child, 0)` 尝试打开一个指向子进程的文件描述符。
    3. 如果 `pidfd_open` 成功，`pidfd.get()` 应该返回一个非负的文件描述符。
    4. `waitid(P_PIDFD, pidfd.get(), &siginfo, WEXITED)` 等待与 `pidfd` 关联的进程退出。
    5. `siginfo.si_pid` 应该等于子进程的 PID。
* **预期输出:** 测试成功，断言不失败。

**`TEST(pidfd, pidfd_getfd)`**

* **假设输入:** 当前系统支持 `pidfd_open` 和 `pidfd_getfd` 系统调用。
* **逻辑推理:**
    1. `pipe(&r, &w)` 创建一个管道，`r` 是读端，`w` 是写端。
    2. `pidfd_open(getpid(), 0)` 打开一个指向当前进程的文件描述符。
    3. `pidfd_getfd(self.get(), r.get(), 0)` 尝试在当前进程中复制管道的读端文件描述符。新的文件描述符 `dup` 应该指向与 `r` 相同的文件描述符表项。
    4. 向管道的写端写入数据。
    5. 从复制的文件描述符 `dup` 中读取数据，应该能读取到写入的数据。
* **预期输出:** 测试成功，断言不失败。

**`TEST_F(pidfd_DeathTest, pidfd_send_signal)`**

* **假设输入:** 当前系统支持 `pidfd_open` 和 `pidfd_send_signal` 系统调用。
* **逻辑推理 (第一个 `pidfd_send_signal`):**
    1. `pidfd_open(getpid(), 0)` 打开一个指向当前进程的文件描述符。
    2. `pidfd_send_signal(self.get(), 0, nullptr, 0)` 发送信号 0 到当前进程。信号 0 不会终止进程，但可以用于检查进程是否存在。如果调用成功，返回 0。
* **预期输出:** 第一个 `pidfd_send_signal` 调用返回 0。

* **逻辑推理 (第二个 `pidfd_send_signal` 在 `ASSERT_EXIT` 中):**
    1. `ASSERT_EXIT` 会 fork 一个子进程。
    2. 在子进程中，`pidfd_open(getpid(), 0)` 会打开一个指向 *子进程* 的文件描述符。
    3. `pidfd_send_signal(child.get(), SIGINT, nullptr, 0)` 会向子进程自身发送 `SIGINT` 信号。
    4. `SIGINT` 的默认行为是终止进程。
* **预期输出:**  子进程会因收到 `SIGINT` 信号而终止，`ASSERT_EXIT` 断言成功。

**用户或编程常见的使用错误**

1. **在不支持 `pidfd` 的内核上使用:**  如果代码没有检查 `pidfd_open` 等函数的返回值并处理 `ENOSYS` 错误，在旧内核上运行时会崩溃或出现意外行为。
   ```c++
   #include <sys/pidfd.h>
   #include <stdio.h>
   #include <errno.h>

   int main() {
       int pidfd = pidfd_open(12345, 0); // 假设进程 12345 存在
       if (pidfd == -1) {
           perror("pidfd_open failed");
           return 1;
       }
       // ... 使用 pidfd ...
       return 0;
   }
   ```
   如果内核不支持 `pidfd_open`，`perror` 会输出类似 "Function not implemented" 的错误信息。

2. **使用无效的 PID:**  向 `pidfd_open` 传递一个不存在的 PID 会导致调用失败，`errno` 会被设置为 `ESRCH` (No such process)。
   ```c++
   int pidfd = pidfd_open(-1, 0);
   if (pidfd == -1 && errno == ESRCH) {
       printf("进程不存在\n");
   }
   ```

3. **使用无效的文件描述符进行 `pidfd_getfd`:**  如果传递给 `pidfd_getfd` 的 `fd` 参数在目标进程中不是一个有效的文件描述符，调用会失败，`errno` 会被设置为 `EBADF` (Bad file descriptor)。

4. **对 `pidfd` 进行错误的操作:**  `pidfd` 本身是一个文件描述符，可以进行一些文件描述符的操作，但不应该对其进行所有类型的操作。 例如，尝试对 `pidfd` 进行 `read` 或 `write` 操作通常不会有预期的效果，或者会失败。

5. **忘记检查 `waitid` 的返回值:** 在使用 `P_PIDFD` 调用 `waitid` 时，如果内核不支持 `P_PIDFD`，`waitid` 会返回 -1，并且 `errno` 会被设置为 `EINVAL`。  测试代码中正确地处理了这种情况。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java 层):**
   - Android Framework 中的一些核心服务，例如 `ActivityManagerService` (AMS) 或 `Process` 类，在进行进程管理操作时，可能会通过 JNI 调用到 Native 层。
   - 在 Native 层，这些服务可能会使用 Bionic 库提供的函数，包括与 `pidfd` 相关的函数。 例如，AMS 可能需要监控应用进程的状态，可能会使用 `pidfd_open` 来获取进程的句柄。

2. **Android NDK (Native 开发):**
   - NDK 开发者可以直接使用 Bionic 提供的 `pidfd_*` 函数。只需要包含 `<sys/pidfd.h>` 头文件。
   - 例如，一个 NDK 开发的应用可能需要安全地向另一个进程发送信号，可以使用 `pidfd_open` 获取目标进程的 `pidfd`，然后使用 `pidfd_send_signal` 发送信号。

**Frida Hook 示例调试步骤**

假设我们要 hook `pidfd_open` 函数：

**Frida Script (JavaScript):**

```javascript
if (Process.platform === 'linux') {
  const pidfd_openPtr = Module.findExportByName('libc.so', 'pidfd_open');
  if (pidfd_openPtr) {
    Interceptor.attach(pidfd_openPtr, {
      onEnter: function (args) {
        const pid = args[0].toInt32();
        const flags = args[1].toInt32();
        console.log(`[pidfd_open] PID: ${pid}, Flags: ${flags}`);
      },
      onLeave: function (retval) {
        const fd = retval.toInt32();
        console.log(`[pidfd_open] Returned FD: ${fd}`);
      },
    });
    console.log('Successfully hooked pidfd_open');
  } else {
    console.log('Failed to find pidfd_open in libc.so');
  }
} else {
  console.log('pidfd_open is only available on Linux');
}
```

**调试步骤:**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida Server。
2. **找到目标进程:** 确定你想监控的进程的 PID。 例如，可以使用 `adb shell ps | grep <process_name>` 命令。
3. **运行 Frida 命令:** 使用 Frida 连接到目标进程并加载脚本。
   ```bash
   frida -U -f <package_name> -l hook_pidfd_open.js --no-pause
   # 或者，如果进程已经在运行：
   frida -U <process_name_or_pid> -l hook_pidfd_open.js
   ```
   将 `<package_name>` 替换为目标应用的包名，或者使用 `-p <pid>` 指定进程 PID。
4. **观察输出:** 当目标进程调用 `pidfd_open` 时，Frida 脚本会拦截调用，并在控制台上打印出 `pid` 和 `flags` 参数以及返回值 (文件描述符)。

**Hook 其他 `pidfd` 函数的示例:**

你可以类似地 hook `pidfd_getfd` 和 `pidfd_send_signal`。  例如，hook `pidfd_send_signal`:

```javascript
if (Process.platform === 'linux') {
  const pidfd_send_signalPtr = Module.findExportByName('libc.so', 'pidfd_send_signal');
  if (pidfd_send_signalPtr) {
    Interceptor.attach(pidfd_send_signalPtr, {
      onEnter: function (args) {
        const pidfd = args[0].toInt32();
        const sig = args[1].toInt32();
        console.log(`[pidfd_send_signal] pidfd: ${pidfd}, sig: ${sig}`);
      },
      onLeave: function (retval) {
        const result = retval.toInt32();
        console.log(`[pidfd_send_signal] Returned: ${result}`);
      },
    });
    console.log('Successfully hooked pidfd_send_signal');
  } else {
    console.log('Failed to find pidfd_send_signal in libc.so');
  }
}
```

通过 Frida Hook，你可以动态地观察和分析 Android 系统和应用如何使用这些底层的 `pidfd` 系统调用。这对于理解系统行为、调试问题以及进行安全研究非常有帮助。

Prompt: 
```
这是目录为bionic/tests/pidfd_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2021 The Android Open Source Project
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
#include <signal.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__BIONIC__)
#include <sys/pidfd.h>
#endif

#include <android-base/silent_death_test.h>
#include <android-base/unique_fd.h>

#include "utils.h"

using android::base::unique_fd;
using namespace std::chrono_literals;

using pidfd_DeathTest = SilentDeathTest;

TEST(pidfd, pidfd_open) {
#if defined(__BIONIC__)
  pid_t child = fork();
  ASSERT_NE(-1, child);
  if (child == 0) {
    _exit(42);
  }

  unique_fd pidfd(pidfd_open(child, 0));
  if (pidfd.get() == -1 && errno == ENOSYS) GTEST_SKIP() << "no pidfd_open() in this kernel";
  ASSERT_NE(-1, pidfd.get()) << strerror(errno);

  siginfo_t siginfo;
  int rc = waitid(P_PIDFD, pidfd.get(), &siginfo, WEXITED);
  if (rc == -1) {
    ASSERT_ERRNO(EINVAL);
    GTEST_SKIP() << "P_PIDFD not available";
  }

  ASSERT_EQ(child, siginfo.si_pid);
#endif
}

TEST(pidfd, pidfd_getfd) {
#if defined(__BIONIC__)
  unique_fd r, w;
  ASSERT_TRUE(android::base::Pipe(&r, &w));
  unique_fd self(pidfd_open(getpid(), 0));
  if (self.get() == -1 && errno == ENOSYS) GTEST_SKIP() << "no pidfd_open() in this kernel";
  ASSERT_NE(-1, self.get()) << strerror(errno);

  unique_fd dup(pidfd_getfd(self.get(), r.get(), 0));
  if (dup.get() == -1 && errno == ENOSYS) GTEST_SKIP() << "no pidfd_getfd() in this kernel";
  ASSERT_NE(-1, dup.get()) << strerror(errno);

  ASSERT_NE(r.get(), dup.get());
  ASSERT_EQ(3, write(w.get(), "foo", 3));
  char buf[4];
  ASSERT_EQ(3, read(dup.get(), buf, sizeof(buf)));
  ASSERT_EQ(0, memcmp(buf, "foo", 3));
#endif
}

TEST_F(pidfd_DeathTest, pidfd_send_signal) {
#if defined(__BIONIC__)
  unique_fd self(pidfd_open(getpid(), 0));
  if (self.get() == -1 && errno == ENOSYS) GTEST_SKIP() << "no pidfd_open() in this kernel";
  ASSERT_NE(-1, self.get()) << strerror(errno);

  int rc = pidfd_send_signal(self.get(), 0, nullptr, 0);
  if (rc == -1 && errno == ENOSYS) GTEST_SKIP() << "no pidfd_send_signal() in this kernel";
  ASSERT_EQ(0, rc) << strerror(errno);

  ASSERT_EXIT(({
                // gtest will fork a child off for ASSERT_EXIT: `self` refers to the parent.
                unique_fd child(pidfd_open(getpid(), 0));
                pidfd_send_signal(child.get(), SIGINT, nullptr, 0);
              }),
              testing::KilledBySignal(SIGINT), "");

#endif
}

"""

```