Response:
Let's break down the thought process for answering this request. The request is quite comprehensive, asking for analysis of a C++ test file within Android's Bionic library. Here's a potential thought process:

1. **Understand the Context:** The first step is recognizing that this is a *test file*. Its primary purpose isn't to provide functionality directly to users but to *verify* the behavior of other functions. The file path `bionic/tests/sys_time_test.cpp` immediately tells us it's testing time-related system calls within the Bionic library.

2. **Identify the Core Functionality Being Tested:**  Scanning the test names (`utimes_nullptr`, `utimes_EINVAL`, `futimes_nullptr`, etc.) reveals the core functions under scrutiny: `utimes`, `futimes`, `futimesat`, `lutimes`, and `gettimeofday`. The `_nullptr` and `_EINVAL` suffixes hint at the specific scenarios being tested: handling null pointers and invalid arguments, respectively.

3. **Analyze Each Test Case:**  Go through each `TEST` block and deduce its purpose:
    * **`*_nullptr` tests:** These check the behavior when a null pointer is passed for the `times` argument. The expectation is likely that the function should handle this gracefully (often by returning 0, as observed).
    * **`*_EINVAL` tests:** These specifically test error handling when invalid `tv_usec` values (out of range) are provided. The expectation is the function returns -1 and sets `errno` to `EINVAL`.
    * **`gettimeofday` test:** This test compares the result of the standard `gettimeofday` with the direct system call version (`syscall(__NR_gettimeofday, ...)`). It aims to ensure the VDSO optimization is working correctly and that the system call returns reasonably consistent results.

4. **Connect to Android Functionality:** Consider how these functions are used within the Android ecosystem.
    * **`utimes`, `futimes`, `futimesat`, `lutimes`:** These are related to file system operations. Think about when an app or the system might need to modify file timestamps: downloading files, creating files, archiving, build processes, etc. Mention concrete examples like file managers or backup apps.
    * **`gettimeofday`:** This is a fundamental timekeeping function used everywhere: logging, scheduling tasks, network protocols, UI updates, etc. It's crucial for almost any Android application.

5. **Explain `libc` Function Implementations (Conceptual):**  Since the request asks for *how* these functions are implemented, even without seeing the actual `bionic` source, we can provide a general explanation. These are system calls, so they ultimately interact with the kernel. Emphasize the transition from user space to kernel space, system call numbers, and the kernel's role in managing time and file system metadata. For `gettimeofday`, mention the VDSO optimization.

6. **Address Dynamic Linking (for `gettimeofday`):** The `gettimeofday` test hints at dynamic linking. Explain the concept of shared libraries (`.so`), the role of the dynamic linker (`linker64` or `linker`), and how the VDSO is a special case. Provide a simplified `.so` layout example. Describe the linking process: finding the library, resolving symbols, and mapping it into memory.

7. **Provide Example Input and Output (for `EINVAL` tests):**  For the `*_EINVAL` tests, clearly show the invalid `timeval` structure as the *input* and the expected *output* (-1 return value and `errno` set to `EINVAL`).

8. **Illustrate Common Usage Errors:** For each function, think about typical mistakes developers might make. Examples include:
    * Passing `NULL` when it's not allowed.
    * Providing invalid time values.
    * Incorrect file paths or file descriptors.

9. **Trace the Path from Framework/NDK:**  Describe the layers involved in reaching these `libc` functions from an Android app:
    * Java SDK (e.g., `java.io.File.setLastModified`) using JNI.
    * NDK C/C++ code directly calling `utimes`.
    * System services potentially using these functions.

10. **Provide Frida Hook Examples:**  This requires showing how to intercept the calls using Frida. For each function, show a basic hook that logs the arguments. This demonstrates how to observe the behavior at runtime.

11. **Structure and Language:** Organize the information logically with clear headings and bullet points. Use clear and concise Chinese. Explain technical terms where necessary. Maintain a helpful and informative tone.

**Self-Correction/Refinement During Thought Process:**

* **Initial thought:** Focus heavily on the specific test cases.
* **Correction:** Realize the need to generalize and explain the underlying functions and their broader usage in Android.
* **Initial thought:**  Simply state the functions are system calls.
* **Refinement:** Explain the user-space/kernel-space transition and the role of the kernel.
* **Initial thought:**  Provide very technical details about dynamic linking.
* **Refinement:** Simplify the explanation to focus on the core concepts relevant to the test case.
* **Initial thought:**  Only provide one Frida hook example.
* **Refinement:** Provide examples for multiple tested functions to illustrate the general approach.

By following this structured approach and iteratively refining the details, a comprehensive and accurate answer can be generated, addressing all aspects of the prompt.
这个文件 `bionic/tests/sys_time_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用来测试与系统时间相关的 C 标准库函数。它的主要功能是：

**功能列表:**

1. **测试 `utimes()` 函数:**
   - 验证当 `times` 参数为 `nullptr` 时，`utimes()` 是否按预期工作 (应成功返回 0)。
   - 验证当 `timeval` 结构体中的 `tv_usec` 成员超出有效范围（负数或大于等于 1000000）时，`utimes()` 是否正确返回 -1 并设置 `errno` 为 `EINVAL`。

2. **测试 `futimes()` 函数:**
   - 验证当 `times` 参数为 `nullptr` 时，`futimes()` 是否按预期工作 (应成功返回 0)。
   - 验证当 `timeval` 结构体中的 `tv_usec` 成员超出有效范围时，`futimes()` 是否正确返回 -1 并设置 `errno` 为 `EINVAL`。

3. **测试 `futimesat()` 函数:**
   - 验证当 `times` 参数为 `nullptr` 时，`futimesat()` 是否按预期工作 (应成功返回 0)。
   - 验证当 `timeval` 结构体中的 `tv_usec` 成员超出有效范围时，`futimesat()` 是否正确返回 -1 并设置 `errno` 为 `EINVAL`。

4. **测试 `lutimes()` 函数:**
   - 验证当 `times` 参数为 `nullptr` 时，`lutimes()` 是否按预期工作 (应成功返回 0)。
   - 验证当 `timeval` 结构体中的 `tv_usec` 成员超出有效范围时，`lutimes()` 是否正确返回 -1 并设置 `errno` 为 `EINVAL`。

5. **测试 `gettimeofday()` 函数:**
   - 验证 `gettimeofday()` 函数的基本功能是否正常，特别是验证了通过 VDSO (Virtual Dynamically Shared Object) 提供的 `gettimeofday` 版本是否正常工作。
   - 通过与直接使用系统调用 `__NR_gettimeofday` 获取的时间进行比较，来检查 VDSO 提供的优化的有效性。

**与 Android 功能的关系及举例说明:**

这些被测试的函数都是与文件系统时间戳和系统时间获取密切相关的系统调用。在 Android 中，这些功能被广泛使用：

* **文件管理器:**  当用户修改文件或文件夹时，文件管理器会调用 `utimes()`、`futimes()` 或 `futimesat()` 来更新文件的访问时间和修改时间戳。
* **下载管理器:** 下载完成后，下载管理器可能会使用这些函数来设置下载文件的原始时间戳。
* **备份和恢复应用:** 这些应用会使用这些函数来保持备份文件的时间戳与原始文件一致。
* **构建系统 (如 Make, Ninja):** 构建系统会依赖文件的时间戳来判断哪些文件需要重新编译。
* **系统服务:** Android 的各种系统服务可能需要获取当前时间 (`gettimeofday()`) 用于日志记录、任务调度等。

**详细解释每一个 libc 函数的功能是如何实现的:**

这些函数都是 C 标准库提供的接口，它们最终会调用底层的 Linux 内核提供的系统调用。

1. **`utimes(const char *pathname, const struct timeval times[2]);`**
   - **功能:** 修改由 `pathname` 指定的文件的访问时间和修改时间。
   - **实现:**
     - 用户空间程序调用 `utimes()` 函数。
     - Bionic 的 `utimes()` 实现会将参数传递给相应的系统调用（例如，在 Linux 上是 `utimensat` 系统调用，当 `times` 为 NULL 时，行为类似于 `touch` 命令）。
     - 内核接收到系统调用请求后，会根据 `pathname` 查找对应的 inode (索引节点)。
     - 如果 `times` 不为 `NULL`，内核会根据 `times[0]` 设置访问时间，`times[1]` 设置修改时间。`tv_sec` 是秒数，`tv_usec` 是微秒数。
     - 如果 `times` 为 `NULL`，内核会将访问时间和修改时间设置为当前时间。
     - 内核执行完成后，将结果返回给用户空间。

2. **`futimes(int fd, const struct timeval times[2]);`**
   - **功能:**  类似于 `utimes()`，但操作对象是通过文件描述符 `fd` 指定的文件。
   - **实现:**
     - 用户空间程序调用 `futimes()` 函数。
     - Bionic 的 `futimes()` 实现会将参数传递给相应的系统调用（通常是 `futimes` 或 `utimensat`，使用 `AT_FDCWD` 作为目录文件描述符）。
     - 内核接收到系统调用请求后，会通过文件描述符 `fd` 找到对应的 inode。
     - 时间戳的设置过程与 `utimes()` 类似。

3. **`futimesat(int dirfd, const char *pathname, const struct timeval times[2], int flags);`**
   - **功能:**  类似于 `utimes()`，但可以指定相对路径，并且可以操作符号链接。
   - **实现:**
     - 用户空间程序调用 `futimesat()` 函数。
     - Bionic 的 `futimesat()` 实现会将参数传递给内核的 `utimensat` 系统调用。
     - `dirfd` 参数指定了起始目录的文件描述符，`AT_FDCWD` 表示当前工作目录。
     - `flags` 参数可以控制是否跟随符号链接 (例如，`AT_SYMLINK_NOFOLLOW`)。
     - 内核根据 `dirfd` 和 `pathname` 找到目标文件，并设置时间戳。

4. **`lutimes(const char *pathname, const struct timeval times[2]);`**
   - **功能:**  类似于 `utimes()`，但如果 `pathname` 是一个符号链接，则修改符号链接本身的时间戳，而不是它指向的目标文件的时间戳。
   - **实现:**
     - 用户空间程序调用 `lutimes()` 函数。
     - Bionic 的 `lutimes()` 实现会将参数传递给内核的 `utimensat` 系统调用，并使用 `AT_SYMLINK_NOFOLLOW` 标志，确保不跟随符号链接。
     - 内核找到符号链接的 inode，并设置其时间戳。

5. **`gettimeofday(struct timeval *tv, struct timezone *tz);`**
   - **功能:** 获取当前时间和时区信息。
   - **实现:**
     - **VDSO 优化:** 为了提高性能，Android 和其他 Linux 系统通常使用 VDSO (Virtual Dynamically Shared Object)。VDSO 是内核映射到用户进程地址空间的一小段代码，允许某些系统调用（如 `gettimeofday`）在用户空间直接执行，避免了陷入内核的开销。
     - 当程序调用 `gettimeofday()` 时，链接器会优先链接到 VDSO 提供的版本。
     - VDSO 中的 `gettimeofday` 代码会直接读取内核维护的当前时间信息，并填充到 `tv` 结构体中。
     - 如果由于某种原因 VDSO 不可用，或者需要更精确的时间信息，`gettimeofday()` 的实现可能会退回到传统的系统调用方式 (`__NR_gettimeofday`)，这会涉及用户空间到内核空间的切换。
     - `tv` 结构体包含当前的秒数 (`tv_sec`) 和微秒数 (`tv_usec`)。
     - `tz` 参数在现代系统上通常被忽略，应该传入 `NULL`。

**涉及 dynamic linker 的功能，对应的 so 布局样本，以及链接的处理过程:**

此测试文件中直接涉及 dynamic linker 的主要是 `gettimeofday()` 的测试。

**so 布局样本 (简化):**

```
# 假设这是 libc.so 的一部分

.text:0000000000100000 <gettimeofday@plt>:  ; Procedure Linkage Table entry
.text:0000000000100000    jmp     qword ptr [rip+offset_to_GOT_entry]

.got:0000000000201000 offset_to_GOT_entry: dq offset_to_actual_function ; Global Offset Table entry

# 如果使用了 VDSO，实际函数地址可能指向 VDSO 中的代码
# 否则指向 libc.so 中实现的 gettimeofday
```

**链接的处理过程:**

1. **编译时:**  当编译链接包含 `gettimeofday()` 调用的程序时，链接器会找到 `libc.so` (或其他包含 `gettimeofday()` 的共享库)。在可执行文件的 `.plt` (Procedure Linkage Table) 节中创建一个条目 `gettimeofday@plt`，并在 `.got` (Global Offset Table) 节中创建一个对应的条目。`.got` 中的初始值通常指向 `.plt` 中的下一条指令。

2. **运行时 (首次调用 `gettimeofday()`):**
   - 程序执行到 `gettimeofday@plt` 时，会跳转到 `.got` 表中存储的地址。
   - 第一次调用时，`.got` 表中的地址指向 `.plt` 中的一段代码，这段代码会调用 dynamic linker。
   - Dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 负责解析符号，找到 `gettimeofday()` 的实际地址。
   - **VDSO 的特殊处理:**  Dynamic linker 会检查是否存在 VDSO，如果存在，并且 VDSO 提供了 `gettimeofday()` 的实现，那么 dynamic linker 会将 `.got` 表中 `gettimeofday` 对应的条目更新为指向 VDSO 中 `gettimeofday` 函数的地址。
   - 如果没有 VDSO 或 VDSO 没有提供，dynamic linker 会查找 `libc.so` 中 `gettimeofday()` 的实现，并将地址更新到 `.got` 表中。

3. **运行时 (后续调用 `gettimeofday()`):**
   - 程序再次调用 `gettimeofday@plt` 时，会跳转到 `.got` 表中已更新的地址，直接执行 `gettimeofday()` 的实际代码，无需再次调用 dynamic linker。

**假设输入与输出 (针对 `utimes_EINVAL` 测试):**

**假设输入:**

* `pathname`:  假设存在一个文件名为 "test_file.txt"
* `times`: 一个 `timeval` 数组，其中：
    * `times[0].tv_sec = 1678886400`
    * `times[0].tv_usec = -123`  (无效的微秒值)
    * `times[1].tv_sec = 1678886400`
    * `times[1].tv_usec = 0`

**预期输出:**

* `utimes()` 函数返回值为 `-1`。
* `errno` 的值为 `EINVAL` (表示参数无效)。

**用户或编程常见的使用错误:**

1. **传递 `NULL` 指针给 `times` 但期望修改为特定时间:** 开发者可能会错误地认为传递 `NULL` 可以设置特定的时间戳，实际上 `NULL` 表示设置为当前时间。

   ```c
   // 错误示例：期望将文件时间戳设置为特定值，但传递了 NULL
   struct timeval tv[2];
   tv[0].tv_sec = ...;
   tv[0].tv_usec = ...;
   tv[1].tv_sec = ...;
   tv[1].tv_usec = ...;
   utimes("my_file.txt", NULL); // 错误！这将设置为当前时间
   ```

2. **`timeval` 结构体中 `tv_usec` 超出范围:**  `tv_usec` 应该在 0 到 999999 之间。

   ```c
   struct timeval tv[2];
   tv[0].tv_sec = 1678886400;
   tv[0].tv_usec = 1234567; // 错误！超出范围
   utimes("my_file.txt", tv); // 将导致 EINVAL 错误
   ```

3. **对符号链接的理解错误:**  不清楚 `utimes()` 和 `lutimes()` 的区别，错误地使用了其中一个函数，导致修改了错误的文件的时间戳。

4. **文件或目录不存在:**  尝试修改不存在的文件或目录的时间戳会导致错误（例如 `ENOENT`）。

5. **权限不足:**  尝试修改没有写权限的文件或目录的时间戳会导致错误（例如 `EACCES`）。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**从 Android Framework 到 Bionic 的路径:**

1. **Java Framework (Android SDK):**  应用程序通常从 Java 代码开始。例如，`java.io.File` 类提供了操作文件时间戳的方法，如 `setLastModified()`。

   ```java
   File file = new File("/sdcard/mydocument.txt");
   long newTime = System.currentTimeMillis();
   file.setLastModified(newTime);
   ```

2. **Native Interface (JNI):**  `java.io.File.setLastModified()` 方法最终会通过 JNI (Java Native Interface) 调用底层的 Native 代码。

3. **NDK (Native Development Kit):**  如果你直接使用 NDK 进行开发，你可以在 C/C++ 代码中直接调用 Bionic 提供的函数。

   ```c++
   #include <sys/time.h>
   #include <sys/stat.h>
   #include <unistd.h>

   void setFileTimes(const char* path, long atime_sec, long mtime_sec) {
       struct timeval times[2];
       times[0].tv_sec = atime_sec;
       times[0].tv_usec = 0;
       times[1].tv_sec = mtime_sec;
       times[1].tv_usec = 0;
       utimes(path, times);
   }
   ```

4. **Bionic libc:**  无论是通过 JNI 还是 NDK，最终都会调用到 Bionic 提供的 C 标准库函数，例如 `utimes()`。

5. **Kernel System Calls:** Bionic 的 `utimes()` 实现会调用 Linux 内核提供的系统调用，如 `utimensat`。

**Frida Hook 示例:**

以下是一些使用 Frida Hook 来调试这些步骤的示例：

**Hook `utimes()`:**

```javascript
if (Process.platform === 'android') {
  const utimesPtr = Module.findExportByName("libc.so", "utimes");
  if (utimesPtr) {
    Interceptor.attach(utimesPtr, {
      onEnter: function(args) {
        const pathname = Memory.readUtf8String(args[0]);
        const timesPtr = args[1];
        let accessTime = null;
        let modificationTime = null;

        if (!timesPtr.isNull()) {
          accessTime = {
            tv_sec: ptr(timesPtr).readLong(),
            tv_usec: ptr(timesPtr).add(8).readLong()
          };
          modificationTime = {
            tv_sec: ptr(timesPtr).add(16).readLong(),
            tv_usec: ptr(timesPtr).add(24).readLong()
          };
        }

        console.log(`utimes called`);
        console.log(`  pathname: ${pathname}`);
        console.log(`  access time: ${JSON.stringify(accessTime)}`);
        console.log(`  modification time: ${JSON.stringify(modificationTime)}`);
      },
      onLeave: function(retval) {
        console.log(`utimes returned: ${retval}`);
      }
    });
  } else {
    console.log("utimes not found in libc.so");
  }
}
```

**Hook `gettimeofday()`:**

```javascript
if (Process.platform === 'android') {
  const gettimeofdayPtr = Module.findExportByName("libc.so", "gettimeofday");
  if (gettimeofdayPtr) {
    Interceptor.attach(gettimeofdayPtr, {
      onEnter: function(args) {
        console.log(`gettimeofday called`);
      },
      onLeave: function(retval) {
        const tvPtr = this.context.r0; // 或 args[0]，取决于架构
        const tzPtr = this.context.r1; // 或 args[1]

        if (!tvPtr.isNull()) {
          const tv_sec = ptr(tvPtr).readLong();
          const tv_usec = ptr(tvPtr).add(8).readLong();
          console.log(`  tv_sec: ${tv_sec}`);
          console.log(`  tv_usec: ${tv_usec}`);
        }

        console.log(`gettimeofday returned: ${retval}`);
      }
    });
  } else {
    console.log("gettimeofday not found in libc.so");
  }
}
```

**调试步骤:**

1. **准备环境:**  确保你的 Android 设备或模拟器上安装了 Frida 服务。
2. **编写 Frida 脚本:**  根据你需要调试的函数编写相应的 Frida Hook 脚本。
3. **运行 Frida:**  使用 Frida 命令将脚本注入到目标 Android 应用程序的进程中。例如：
   ```bash
   frida -U -f com.example.myapp -l your_script.js --no-pause
   ```
   将 `com.example.myapp` 替换为你的应用程序的包名，`your_script.js` 替换为你的 Frida 脚本文件名。
4. **执行操作:** 在你的 Android 应用程序中执行触发相关系统调用的操作（例如，修改文件时间戳，获取当前时间）。
5. **查看输出:**  Frida 会在终端输出 Hook 到的函数调用信息，包括参数和返回值，帮助你理解代码的执行流程和参数传递。

通过这些步骤，你可以观察到 Android Framework 或 NDK 是如何一步步调用到 Bionic 的时间相关函数的，并可以检查参数是否正确，返回值是否符合预期。

### 提示词
```
这是目录为bionic/tests/sys_time_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#include <sys/syscall.h>
#include <sys/time.h>

#include <android-base/file.h>

#include "private/bionic_time_conversions.h"
#include "utils.h"

// http://b/11383777
TEST(sys_time, utimes_nullptr) {
  TemporaryFile tf;
  ASSERT_EQ(0, utimes(tf.path, nullptr));
}

TEST(sys_time, utimes_EINVAL) {
  TemporaryFile tf;

  timeval tv[2] = {};

  tv[0].tv_usec = -123;
  ASSERT_EQ(-1, utimes(tf.path, tv));
  ASSERT_ERRNO(EINVAL);
  tv[0].tv_usec = 1234567;
  ASSERT_EQ(-1, utimes(tf.path, tv));
  ASSERT_ERRNO(EINVAL);

  tv[0].tv_usec = 0;

  tv[1].tv_usec = -123;
  ASSERT_EQ(-1, utimes(tf.path, tv));
  ASSERT_ERRNO(EINVAL);
  tv[1].tv_usec = 1234567;
  ASSERT_EQ(-1, utimes(tf.path, tv));
  ASSERT_ERRNO(EINVAL);
}

TEST(sys_time, futimes_nullptr) {
  TemporaryFile tf;
  ASSERT_EQ(0, futimes(tf.fd, nullptr));
}

TEST(sys_time, futimes_EINVAL) {
  TemporaryFile tf;

  timeval tv[2] = {};

  tv[0].tv_usec = -123;
  ASSERT_EQ(-1, futimes(tf.fd, tv));
  ASSERT_ERRNO(EINVAL);
  tv[0].tv_usec = 1234567;
  ASSERT_EQ(-1, futimes(tf.fd, tv));
  ASSERT_ERRNO(EINVAL);

  tv[0].tv_usec = 0;

  tv[1].tv_usec = -123;
  ASSERT_EQ(-1, futimes(tf.fd, tv));
  ASSERT_ERRNO(EINVAL);
  tv[1].tv_usec = 1234567;
  ASSERT_EQ(-1, futimes(tf.fd, tv));
  ASSERT_ERRNO(EINVAL);
}

TEST(sys_time, futimesat_nullptr) {
  TemporaryFile tf;
  ASSERT_EQ(0, futimesat(AT_FDCWD, tf.path, nullptr));
}

TEST(sys_time, futimesat_EINVAL) {
  TemporaryFile tf;

  timeval tv[2] = {};

  tv[0].tv_usec = -123;
  ASSERT_EQ(-1, futimesat(AT_FDCWD, tf.path, tv));
  ASSERT_ERRNO(EINVAL);
  tv[0].tv_usec = 1234567;
  ASSERT_EQ(-1, futimesat(AT_FDCWD, tf.path, tv));
  ASSERT_ERRNO(EINVAL);

  tv[0].tv_usec = 0;

  tv[1].tv_usec = -123;
  ASSERT_EQ(-1, futimesat(AT_FDCWD, tf.path, tv));
  ASSERT_ERRNO(EINVAL);
  tv[1].tv_usec = 1234567;
  ASSERT_EQ(-1, futimesat(AT_FDCWD, tf.path, tv));
  ASSERT_ERRNO(EINVAL);
}

TEST(sys_time, lutimes_nullptr) {
  TemporaryFile tf;
  ASSERT_EQ(0, lutimes(tf.path, nullptr));
}

TEST(sys_time, lutimes_EINVAL) {
  TemporaryFile tf;

  timeval tv[2] = {};

  tv[0].tv_usec = -123;
  ASSERT_EQ(-1, lutimes(tf.path, tv));
  ASSERT_ERRNO(EINVAL);
  tv[0].tv_usec = 1234567;
  ASSERT_EQ(-1, lutimes(tf.path, tv));
  ASSERT_ERRNO(EINVAL);

  tv[0].tv_usec = 0;

  tv[1].tv_usec = -123;
  ASSERT_EQ(-1, lutimes(tf.path, tv));
  ASSERT_ERRNO(EINVAL);
  tv[1].tv_usec = 1234567;
  ASSERT_EQ(-1, lutimes(tf.path, tv));
  ASSERT_ERRNO(EINVAL);
}

// Musl doesn't define __NR_gettimeofday on 32-bit architectures.
#if !defined(__NR_gettimeofday)
#define __NR_gettimeofday __NR_gettimeofday_time32
#endif

TEST(sys_time, gettimeofday) {
  // Try to ensure that our vdso gettimeofday is working.
  timeval tv1;
  ASSERT_EQ(0, gettimeofday(&tv1, nullptr));
  timeval tv2;
  ASSERT_EQ(0, syscall(__NR_gettimeofday, &tv2, nullptr));

  // What's the difference between the two?
  // To try to avoid flakiness we'll accept answers within 10,000us (0.01s).
  ASSERT_LT(to_us(tv2) - to_us(tv1), 10'000);
}
```