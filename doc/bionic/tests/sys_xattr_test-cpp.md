Response:
Let's break down the thought process for generating the response.

1. **Understanding the Request:** The request asks for an analysis of a C++ test file (`sys_xattr_test.cpp`) within the Android Bionic library. The core focus is on the functionality being tested (extended attributes - xattrs), how it relates to Android, implementation details of the libc functions used, dynamic linker aspects (if any), common errors, and how Android frameworks might reach this code. Frida hooking is also requested.

2. **Initial Code Examination (Skimming):**  The first step is to quickly read through the code to get a general understanding. Key observations:
    * The file uses Google Test (`TEST`).
    * The tests revolve around `setxattr`, `fsetxattr`, `getxattr`, `lgetxattr`, and `flistxattr`.
    * It uses `TemporaryFile` for creating test files.
    * There are checks using `ASSERT_EQ`, `ASSERT_STREQ`, `ASSERT_ERRNO`.
    * The `#if defined(__BIONIC__)` suggests platform-specific behavior.

3. **Identifying Core Functionality:** The primary purpose of this test file is to verify the correct implementation of the system calls for manipulating extended attributes (xattrs). This immediately tells me the main subject of the explanation.

4. **Explaining Individual Tests (and thus Functionality):** I go through each `TEST` case and summarize what it's testing:
    * `setxattr`: Setting xattrs by path.
    * `fsetxattr`: Setting xattrs by file descriptor.
    * `fsetxattr_zerobuf`: Setting an xattr with an empty value.
    * `fsetxattr_toosmallbuf`: Handling insufficient buffer size when getting xattrs.
    * `fsetxattr_invalid_fd`: Handling invalid file descriptors.
    * `fsetxattr_with_opath`:  Testing xattrs with file descriptors opened with `O_PATH`. The `#if defined(__BIONIC__)` is crucial here.
    * `flistattr`: Listing xattrs.
    * `flistattr_opath`: Listing xattrs with `O_PATH` file descriptors.
    * `flistattr_invalid_fd`: Handling invalid file descriptors for listing.

5. **Relating to Android Functionality:**  I consider where xattrs might be used in Android. Key areas come to mind:
    * **Security:** SELinux uses xattrs for security context. This is a *very* important point.
    * **Package Management:**  Tracking installation details or permissions.
    * **File Systems:** Some file systems natively support xattrs.
    * **Backup/Restore:** Storing metadata.

6. **Explaining `libc` Functions:** For each of the xattr-related functions (`setxattr`, `fsetxattr`, `getxattr`, `lgetxattr`, `flistxattr`), I provide a detailed explanation:
    * **Purpose:** What the function does.
    * **How it Works (Simplified):**  Internally, it involves system calls to the kernel. I avoid going into kernel-level details unless strictly necessary.
    * **Key Differences:**  Highlighting the distinction between path-based (`setxattr`) and file descriptor-based (`fsetxattr`) versions, and the `l` prefix for handling symbolic links (`lgetxattr`).

7. **Dynamic Linker Aspects:**  I analyze the code for any explicit dynamic linking. In this particular file, there are *no* direct dynamic linking calls. The system calls are handled by the kernel after being invoked through the `libc`. Therefore, the "dynamic linker" section will explain *why* it's not directly relevant *here*, but still provides general context about shared libraries in Android. I create a simplified example of an `so` layout.

8. **Logic and Assumptions:**  For each test case, I implicitly consider the "happy path" (successful execution) and the error conditions being tested. For example, in `fsetxattr_toosmallbuf`, the assumption is that `fgetxattr` will return an error because the buffer is too small. I state these assumptions as input/output expectations.

9. **Common Errors:**  I think about common mistakes developers might make when using xattr functions:
    * Incorrect buffer sizes (too small, or forgetting null termination if using the result as a string).
    * Invalid file descriptors.
    * Permission issues.
    * Incorrect namespace for the attribute name.

10. **Android Framework and NDK Path:** This requires a bit of knowledge about the Android architecture. I trace a possible path:
    * **Framework:**  A high-level framework service (like `PackageManagerService`) might need to interact with file metadata.
    * **System Server:**  The service runs in the system server process.
    * **JNI:**  The Java code uses JNI to call native code.
    * **NDK:** The NDK provides access to native APIs.
    * **Bionic:** The NDK functions eventually call into Bionic's `libc`, including the xattr functions.

11. **Frida Hooking:** I provide concrete Frida examples for hooking `setxattr` and `fsetxattr`. The key is to understand how to intercept function calls at the native level and print arguments.

12. **Language and Structure:**  The request specifies Chinese. I ensure the entire response is in clear and understandable Chinese. I organize the information logically with clear headings and bullet points.

13. **Review and Refinement:** After drafting the initial response, I review it for clarity, accuracy, and completeness. I make sure all parts of the request have been addressed. For instance, I double-check the explanations of libc functions and the relevance (or irrelevance) of the dynamic linker. I ensure the Frida examples are practical.

This structured approach allows me to dissect the request, analyze the code, and generate a comprehensive and informative response. The key is to move from the specific code to the broader context of Android and system programming.
## 分析 bionic/tests/sys_xattr_test.cpp

这个文件 `bionic/tests/sys_xattr_test.cpp` 是 Android Bionic 库中的一个测试文件，专门用来测试与扩展属性 (Extended Attributes, xattr) 相关的系统调用。

**它的主要功能是：**

1. **测试 `setxattr` 系统调用:**  验证通过文件路径设置扩展属性的功能是否正常。
2. **测试 `fsetxattr` 系统调用:** 验证通过文件描述符设置扩展属性的功能是否正常。
3. **测试设置空值的扩展属性:** 验证能否设置一个内容为空的扩展属性。
4. **测试获取扩展属性时缓冲区过小的情况:** 验证在获取扩展属性时，如果提供的缓冲区太小，是否会返回错误。
5. **测试无效的文件描述符:** 验证当使用无效的文件描述符时，相关系统调用是否会返回错误。
6. **测试使用 `O_PATH` 打开的文件描述符:** 验证使用 `O_PATH` 打开的文件描述符是否能进行扩展属性操作 (不同平台行为可能不同)。
7. **测试 `flistxattr` 系统调用:** 验证列出文件扩展属性的功能是否正常。

**与 Android 功能的关系及举例说明：**

扩展属性是一种在文件系统中存储额外元数据的方法，它允许将任意键值对与文件和目录关联起来。在 Android 中，扩展属性被用于多种目的，包括：

* **SELinux (安全增强型 Linux):**  Android 使用 SELinux 来实现强制访问控制。SELinux 使用扩展属性来标记文件的安全上下文 (security context)，例如 `security.selinux`。这些上下文决定了进程对文件的访问权限。
    * **例子:** 当一个应用被安装到 Android 设备上时，`installd` 守护进程可能会使用 `setxattr` 来设置应用安装目录下所有文件的 `security.selinux` 属性，以确保应用只能在其被允许的上下文中运行。

* **备份和恢复:** 某些备份工具可能会使用扩展属性来存储文件的额外信息，以便在恢复时能够完整还原文件的状态。

* **文件管理和标签:** 一些文件管理器或文件同步工具可能会使用扩展属性来存储用户定义的标签或元数据。

**详细解释每一个 libc 函数的功能是如何实现的：**

这些测试文件主要测试的是以下几个 Bionic libc 提供的函数，它们是对底层 Linux 系统调用的封装：

1. **`setxattr(const char *path, const char *name, const void *value, size_t size, int flags)`:**
   * **功能:**  设置由 `path` 指定的文件或目录的名为 `name` 的扩展属性，其值为 `value`，大小为 `size`。`flags` 参数控制操作的行为，例如是否创建或替换属性。
   * **实现:**  在 Bionic 中，`setxattr` 函数最终会调用 Linux 内核的 `setxattr` 系统调用。
      * 它会进行参数校验，例如检查 `path` 是否有效，`name` 和 `value` 指针是否为空，`size` 是否合法等。
      * 然后，它会使用 `syscall(__NR_setxattr, path, name, value, size, flags)` 来发起系统调用。
      * 内核接收到系统调用后，会根据文件系统类型进行相应的操作，将扩展属性存储在文件的 inode 或其他相关数据结构中。
   * **假设输入与输出:**
      * **输入:** `path = "/sdcard/test.txt"`, `name = "user.comment"`, `value = "This is a test"`, `size = 14`, `flags = 0`
      * **输出:** 如果操作成功，返回 `0`。如果失败（例如权限不足、文件不存在等），返回 `-1` 并设置 `errno`。

2. **`fsetxattr(int fd, const char *name, const void *value, size_t size, int flags)`:**
   * **功能:**  与 `setxattr` 类似，但操作对象是由文件描述符 `fd` 指定的文件或目录。
   * **实现:**  与 `setxattr` 类似，最终调用内核的 `fsetxattr` 系统调用 (`syscall(__NR_fsetxattr, fd, name, value, size, flags)`)。使用文件描述符避免了路径查找，效率更高，并且在文件路径发生变化时依然有效。
   * **假设输入与输出:**
      * **输入:** `fd` 是一个已打开文件的文件描述符, `name = "user.priority"`, `value = "high"`, `size = 4`, `flags = 0`
      * **输出:** 如果操作成功，返回 `0`。如果失败（例如 `fd` 无效），返回 `-1` 并设置 `errno`。

3. **`getxattr(const char *path, const char *name, void *value, size_t size)`:**
   * **功能:** 获取由 `path` 指定的文件或目录的名为 `name` 的扩展属性的值，并将结果存储到 `value` 指向的缓冲区中，最多读取 `size` 字节。
   * **实现:**  Bionic 中的 `getxattr` 函数会调用 Linux 内核的 `getxattr` 系统调用 (`syscall(__NR_getxattr, path, name, value, size)`)。
      * 内核会查找文件的扩展属性，并将找到的值复制到用户提供的缓冲区。
      * 如果提供的缓冲区太小，内核会返回属性值的实际大小，而不是返回错误（某些情况下）。
   * **假设输入与输出:**
      * **输入:** `path = "/sdcard/test.txt"`, `name = "user.comment"`, `value` 是一个大小为 100 字节的缓冲区,  假设之前已设置 "user.comment" 为 "This is a test"。
      * **输出:** 如果操作成功，返回实际读取的字节数（例如 14），`value` 缓冲区中包含 "This is a test"。如果属性不存在，返回 `-1` 并设置 `errno` 为 `ENODATA`。如果缓冲区太小，返回属性的实际大小。

4. **`lgetxattr(const char *path, const char *name, void *value, size_t size)`:**
   * **功能:**  与 `getxattr` 类似，但如果 `path` 指向一个符号链接，则获取的是符号链接自身的扩展属性，而不是它指向的目标文件的扩展属性。
   * **实现:**  Bionic 中的 `lgetxattr` 函数会调用 Linux 内核的 `lgetxattr` 系统调用 (`syscall(__NR_lgetxattr, path, name, value, size)`)。
   * **假设输入与输出:**  假设 `/sdcard/link_to_test.txt` 是指向 `/sdcard/test.txt` 的符号链接。如果符号链接本身有扩展属性，`lgetxattr` 会获取这些属性。

5. **`fgetxattr(int fd, const char *name, void *value, size_t size)`:**
   * **功能:**  与 `getxattr` 类似，但操作对象是由文件描述符 `fd` 指定的文件或目录。
   * **实现:**  Bionic 中的 `fgetxattr` 函数会调用 Linux 内核的 `fgetxattr` 系统调用 (`syscall(__NR_fgetxattr, fd, name, value, size)`)。
   * **假设输入与输出:**  与 `getxattr` 类似，但使用文件描述符。

6. **`flistxattr(int fd, char *list, size_t size)`:**
   * **功能:**  获取由文件描述符 `fd` 指定的文件或目录的所有扩展属性的名称列表，并将结果存储到 `list` 指向的缓冲区中，最多存储 `size` 字节。属性名称之间用空字符分隔。
   * **实现:**  Bionic 中的 `flistxattr` 函数会调用 Linux 内核的 `flistxattr` 系统调用 (`syscall(__NR_flistxattr, fd, list, size)`)。
      * 内核会遍历文件的扩展属性，并将它们的名称复制到用户提供的缓冲区中。
      * 返回值是存储的字节数，如果提供的缓冲区太小，返回值会大于 `size`，指示所需的缓冲区大小。
   * **假设输入与输出:**
      * **输入:** `fd` 是一个已打开文件的文件描述符，该文件具有 "user.comment" 和 "user.priority" 两个扩展属性，`list` 是一个大小为 100 字节的缓冲区。
      * **输出:** 如果操作成功，返回存储的字节数（例如，如果 "user.comment" 和 "user.priority" 加上分隔符占 26 字节，则返回 26），`list` 缓冲区中包含类似 "user.comment\0user.priority\0" 的字符串。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

在这个特定的测试文件中，**没有直接涉及 dynamic linker 的功能**。这些系统调用是由内核提供的，Bionic libc 只是对这些系统调用进行了封装。dynamic linker (如 `linker64` 或 `linker`) 负责加载和链接共享库，解析符号引用。

虽然这个测试本身不涉及 dynamic linker，但如果 `setxattr` 等函数位于一个共享库中（实际上它们属于 `libc.so`），那么 dynamic linker 会在程序启动时负责加载 `libc.so`，并将程序中对 `setxattr` 等符号的引用链接到 `libc.so` 中对应的实现。

**一个简化的 `libc.so` 布局样本：**

```
libc.so:
  .dynsym (动态符号表):
    setxattr  (地址: 0x... , 类型: 函数)
    fsetxattr (地址: 0x... , 类型: 函数)
    getxattr  (地址: 0x... , 类型: 函数)
    ... 其他 libc 函数 ...

  .text (代码段):
    ... setxattr 的实现代码 ...
    ... fsetxattr 的实现代码 ...
    ... getxattr 的实现代码 ...
    ... 其他 libc 函数的实现代码 ...
```

**链接的处理过程：**

1. **程序加载:** 当一个程序需要使用 `setxattr` 时，操作系统会加载程序的可执行文件。
2. **依赖分析:**  加载器会检查可执行文件的动态链接信息，发现它依赖于 `libc.so`。
3. **加载共享库:** dynamic linker 会找到并加载 `libc.so` 到内存中的某个地址。
4. **符号解析:** dynamic linker 会遍历程序中对外部符号的引用，例如对 `setxattr` 的调用。它会在 `libc.so` 的 `.dynsym` 符号表中查找 `setxattr` 的地址。
5. **重定位:**  找到 `setxattr` 的地址后，dynamic linker 会更新程序中调用 `setxattr` 的指令，将占位符地址替换为 `libc.so` 中 `setxattr` 的实际地址。
6. **执行:** 当程序执行到调用 `setxattr` 的地方时，它会跳转到 `libc.so` 中 `setxattr` 的实现代码。

**如果做了逻辑推理，请给出假设输入与输出：**

在测试代码中，已经包含了逻辑推理和假设的输入输出。例如在 `TEST(sys_xattr, setxattr)` 中：

* **假设输入:** 创建一个临时文件，然后尝试设置名为 "user.foo"，值为 "bar" 的扩展属性。
* **预期输出:** `setxattr` 返回 0 (成功)，`getxattr` 和 `lgetxattr` 能够成功读取到 "bar"。

在 `TEST(sys_xattr, fsetxattr_toosmallbuf)` 中：

* **假设输入:** 设置一个较长的扩展属性值 "01234567890123456789"，然后尝试用一个较小的缓冲区去获取。
* **预期输出:** `fgetxattr` 返回 -1，并且 `errno` 被设置为 `ERANGE` (结果太大)。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

1. **缓冲区大小不足:** 在使用 `getxattr` 或 `flistxattr` 时，提供的缓冲区 `size` 小于实际属性值或属性列表的大小。这会导致数据被截断或返回错误。
   ```c++
   char buf[5];
   ssize_t size = getxattr("/path/to/file", "user.data", buf, sizeof(buf));
   if (size >= sizeof(buf)) {
       // 错误：缓冲区太小，数据被截断
   }
   ```

2. **无效的文件描述符或路径:**  向 `setxattr` 或 `fsetxattr` 传递无效的文件描述符或不存在的路径会导致错误。
   ```c++
   int fd = open("/non/existent/file", O_RDONLY);
   if (fd == -1) {
       // 处理打开文件失败的情况
   }
   if (fsetxattr(fd, "user.info", "value", 5, 0) == -1) {
       // 错误：fd 无效
   }
   close(fd);
   ```

3. **权限不足:**  用户可能没有足够的权限来设置或获取某些扩展属性。例如，只有 root 用户才能设置 `security.*` 命名空间的属性。
   ```c++
   if (setxattr("/path/to/file", "security.capability", ..., ...) == -1 && errno == EPERM) {
       // 错误：权限不足
   }
   ```

4. **错误的属性名称:**  使用了不存在的属性名称，或者拼写错误的属性名称。这会导致 `getxattr` 返回 `ENODATA` 错误。
   ```c++
   char buf[100];
   if (getxattr("/path/to/file", "user.typo", buf, sizeof(buf)) == -1 && errno == ENODATA) {
       // 错误：属性不存在
   }
   ```

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 调用:**
   * 某些 Android Framework 服务，例如 `PackageManagerService` (负责应用安装和管理) 或 `MediaProvider` (负责媒体文件管理)，可能需要在文件上存储额外的元数据。
   * 这些服务通常是用 Java 编写的，它们会调用 Android SDK 提供的 Java API。

2. **JNI 调用到 NDK:**
   * Android SDK 的某些类可能会通过 JNI (Java Native Interface) 调用到 Native 代码。
   * 例如，`java.io.File` 类的一些方法在底层可能会调用 Native 函数来执行文件操作。

3. **NDK 接口:**
   * Android NDK 提供了访问底层系统功能的接口。开发者可以使用 NDK 编写 C/C++ 代码，并通过 JNI 与 Java 代码交互。
   * NDK 提供了与文件系统交互的函数，这些函数最终会调用 Bionic libc 提供的系统调用封装。

4. **Bionic libc 系统调用封装:**
   * 当 NDK 代码调用例如 `setxattr` 函数时，实际上会调用 Bionic libc 中对应的封装函数。
   * 这些封装函数会进行必要的参数处理，然后通过 `syscall` 指令发起实际的 Linux 系统调用。

**Frida Hook 示例调试步骤：**

假设我们想 hook `setxattr` 函数，查看哪些 Android 进程在设置扩展属性以及设置了哪些属性。

**Frida Hook Script (JavaScript):**

```javascript
if (Process.platform === 'android') {
  const setxattrPtr = Module.findExportByName("libc.so", "setxattr");

  if (setxattrPtr) {
    Interceptor.attach(setxattrPtr, {
      onEnter: function (args) {
        const path = Memory.readUtf8String(args[0]);
        const name = Memory.readUtf8String(args[1]);
        const valuePtr = args[2];
        const size = args[3].toInt();

        let value = "";
        if (valuePtr && size > 0) {
          value = Memory.readUtf8String(valuePtr, size);
        }

        console.log(`[setxattr Hook]`);
        console.log(`  PID: ${Process.id}`);
        console.log(`  Path: ${path}`);
        console.log(`  Name: ${name}`);
        console.log(`  Value: ${value}`);
        console.log(`  Size: ${size}`);
      },
      onLeave: function (retval) {
        console.log(`  Return Value: ${retval}`);
      }
    });
    console.log("setxattr hooked!");
  } else {
    console.log("setxattr not found in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**使用 Frida 调试：**

1. **准备环境:** 确保你的 Android 设备已 root，并且安装了 Frida 服务端。在 PC 上安装了 Frida 客户端。
2. **运行目标应用或进程:**  运行你想要监控的 Android 应用或进程。
3. **运行 Frida 脚本:**  在 PC 上使用 Frida 客户端连接到目标进程，并执行上面的 JavaScript 脚本。例如：
   ```bash
   frida -U -n com.example.myapp -l hook_setxattr.js
   ```
   或者 hook 系统级别的进程：
   ```bash
   frida -U -f system_server -l hook_setxattr.js
   ```
4. **观察输出:** 当目标应用或进程调用 `setxattr` 时，Frida 会拦截该调用，并打印出相关的参数信息，例如进程 ID、文件路径、属性名称、属性值和大小。

通过这种方式，你可以观察 Android Framework 或 NDK 的哪些部分最终调用了底层的 `setxattr` 等函数，从而理解其调用链。你可以根据需要 hook 其他相关的函数，例如 `fsetxattr`，`getxattr` 等，来进行更深入的调试和分析。

Prompt: 
```
这是目录为bionic/tests/sys_xattr_test.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <fcntl.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include <android-base/file.h>
#include <gtest/gtest.h>

#include "utils.h"

TEST(sys_xattr, setxattr) {
  TemporaryFile tf;
  char buf[10];
  ASSERT_EQ(0, setxattr(tf.path, "user.foo", "bar", 4, 0));
  ASSERT_EQ(4, getxattr(tf.path, "user.foo", buf, sizeof(buf)));
  ASSERT_STREQ("bar", buf);
  buf[0] = '\0';
  ASSERT_EQ(4, lgetxattr(tf.path, "user.foo", buf, sizeof(buf)));
  ASSERT_STREQ("bar", buf);
}

TEST(sys_xattr, fsetxattr) {
  TemporaryFile tf;
  char buf[10];
  ASSERT_EQ(0, fsetxattr(tf.fd, "user.foo", "bar", 4, 0));
  ASSERT_EQ(4, fgetxattr(tf.fd, "user.foo", buf, sizeof(buf)));
  ASSERT_STREQ("bar", buf);
}

TEST(sys_xattr, fsetxattr_zerobuf) {
  TemporaryFile tf;
  char buf[10];
  ASSERT_EQ(0, fsetxattr(tf.fd, "user.foo", "", 0, 0));
  ASSERT_EQ(0, fgetxattr(tf.fd, "user.foo", buf, sizeof(buf)));
}

TEST(sys_xattr, fsetxattr_toosmallbuf) {
  TemporaryFile tf;
  char buf[10];
  ASSERT_EQ(0, fsetxattr(tf.fd, "user.foo", "01234567890123456789", 21, 0));
  ASSERT_EQ(-1, fgetxattr(tf.fd, "user.foo", buf, sizeof(buf)));
  ASSERT_ERRNO(ERANGE);
}

TEST(sys_xattr, fsetxattr_invalid_fd) {
  char buf[10];
  errno = 0;
  ASSERT_EQ(-1, fsetxattr(-1, "user.foo", "0123", 5, 0));
  ASSERT_ERRNO(EBADF);
  errno = 0;
  ASSERT_EQ(-1, fgetxattr(-1, "user.foo", buf, sizeof(buf)));
  ASSERT_ERRNO(EBADF);
}

TEST(sys_xattr, fsetxattr_with_opath) {
  TemporaryFile tf;
  int fd = open(tf.path, O_PATH);
  ASSERT_NE(-1, fd);

  int res = fsetxattr(fd, "user.foo", "bar", 4, 0);
#if defined(__BIONIC__)
  char buf[10];
  ASSERT_EQ(0, res);
  ASSERT_EQ(4, fgetxattr(fd, "user.foo", buf, sizeof(buf)));
  ASSERT_STREQ("bar", buf);
#else
  ASSERT_EQ(-1, res);
  ASSERT_ERRNO(EBADF);
#endif
  close(fd);
}

TEST(sys_xattr, fsetxattr_with_opath_toosmall) {
  TemporaryFile tf;
  int fd = open(tf.path, O_PATH);
  ASSERT_NE(-1, fd);

  int res = fsetxattr(fd, "user.foo", "01234567890123456789", 21, 0);
#if defined(__BIONIC__)
  char buf[10];
  ASSERT_EQ(0, res);
  ASSERT_EQ(-1, fgetxattr(fd, "user.foo", buf, sizeof(buf)));
  ASSERT_ERRNO(ERANGE);
#else
  ASSERT_EQ(-1, res);
  ASSERT_ERRNO(EBADF);
#endif
  close(fd);
}

TEST(sys_xattr, flistattr) {
  TemporaryFile tf;
  char buf[65536];  // 64kB is max possible xattr list size. See "man 7 xattr".
  ASSERT_EQ(0, fsetxattr(tf.fd, "user.foo", "bar", 4, 0));
  ssize_t result = flistxattr(tf.fd, buf, sizeof(buf));
  ASSERT_TRUE(result >= 9);
  ASSERT_TRUE(memmem(buf, sizeof(buf), "user.foo", 9) != nullptr);
}

TEST(sys_xattr, flistattr_opath) {
  TemporaryFile tf;
  char buf[65536];  // 64kB is max possible xattr list size. See "man 7 xattr".
  ASSERT_EQ(0, fsetxattr(tf.fd, "user.foo", "bar", 4, 0));
  int fd = open(tf.path, O_PATH);
  ASSERT_NE(-1, fd);
  ssize_t res = flistxattr(fd, buf, sizeof(buf));
#if defined(__BIONIC__)
  ASSERT_TRUE(res >= 9);
  ASSERT_TRUE(static_cast<size_t>(res) <= sizeof(buf));
  ASSERT_TRUE(memmem(buf, res, "user.foo", 9) != nullptr);
#else
  ASSERT_EQ(-1, res);
  ASSERT_ERRNO(EBADF);
#endif
  close(fd);
}

TEST(sys_xattr, flistattr_invalid_fd) {
  char buf[65536];  // 64kB is max possible xattr list size. See "man 7 xattr".
  errno = 0;
  ASSERT_EQ(-1, flistxattr(-1, buf, sizeof(buf)));
  ASSERT_ERRNO(EBADF);
}

"""

```