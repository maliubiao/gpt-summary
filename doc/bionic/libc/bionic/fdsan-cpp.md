Response:
Let's break down the thought process for analyzing the `fdsan.cpp` file.

**1. Understanding the Request:**

The request asks for a comprehensive analysis of `fdsan.cpp`. Keywords like "功能" (functions/features), "android的功能" (relation to Android), "libc函数的功能是如何实现的" (how libc functions are implemented), "dynamic linker的功能" (dynamic linker aspects), "so布局样本" (SO layout example), "链接的处理过程" (linking process), "逻辑推理" (logical inference), "用户或者编程常见的使用错误" (common user errors), "android framework or ndk是如何一步步的到达这里" (how Android Framework/NDK reaches this code), and "frida hook示例调试这些步骤" (Frida hook example) guide the analysis.

**2. Initial Skim and High-Level Understanding:**

First, I'd quickly read through the code to get a general sense of its purpose. The filename `fdsan.cpp` and the included header `<android/fdsan.h>` strongly suggest it's related to file descriptor (fd) sanitization. The copyright notice confirms it's an Android project.

**3. Identifying Core Functionality:**

I'd then look for the main classes and functions, focusing on the public API defined in `<android/fdsan.h>`. Key functions like `android_fdsan_close_with_tag`, `android_fdsan_get_owner_tag`, `android_fdsan_exchange_owner_tag`, and functions for setting/getting error levels stand out. This suggests the core functionality revolves around tracking and validating file descriptor ownership during close operations.

**4. Analyzing Data Structures:**

The `FdTableImpl` template and `FdEntry` struct are crucial. The template parameter `inline_fds` and the logic around `overflow` suggest an optimization for common cases, with a fallback to a dynamically allocated table for a large number of FDs. The `close_tag` within `FdEntry` is the key piece of data for tracking ownership.

**5. Deconstructing Key Functions (libc functions):**

For each libc-related function used (like `__close`, `getrlimit`, `mmap`, `munmap`, `atomic_load`, `atomic_compare_exchange_strong`, `atomic_exchange`, `__system_property_find`, `__system_property_read_callback`), I'd analyze *how* it's used in the context of `fdsan.cpp`. For example:

* `__close(fd)`:  This is the actual system call to close the FD. `fdsan` wraps it to perform its checks *before* actually closing.
* `getrlimit(RLIMIT_NOFILE, ...)`: Used to determine the maximum number of open file descriptors allowed, and thus the size of the overflow table.
* `mmap(...)`: Used to allocate the overflow table.
* `atomic_*`:  Crucial for thread safety when multiple threads might be closing or modifying FD ownership.

**6. Understanding the Error Handling Mechanism:**

The `fdsan_error` function is the central point for reporting issues. It uses `async_safe_fatal`, `async_safe_format_log`, and `inline_raise` (with `BIONIC_SIGNAL_DEBUGGER` and `SIGABRT`). The different error levels (`FATAL`, `WARN_ALWAYS`, `WARN_ONCE`, `DISABLED`) dictate the severity and behavior upon detecting an error. The use of system properties (`debug.fdsan`) for configuration is also important.

**7. Identifying Android-Specific Aspects:**

The inclusion of `<android/fdsan.h>` and the prefix `android_fdsan_` for public functions immediately mark this as Android-specific. The owner tags and their predefined types (like `FILE*`, `FileInputStream`, `ParcelFileDescriptor`) show integration with higher-level Android concepts. The use of system properties for configuration is a common Android pattern.

**8. Considering Dynamic Linking (although limited in this file):**

While this specific file doesn't directly implement dynamic linking, its integration with the broader Android system requires understanding how it would be linked. I'd consider:

* **SO Location:**  Likely part of `libc.so`.
* **Linking:** Other Android components (framework, NDK libraries) would link against `libc.so` and thus implicitly gain access to the `fdsan` functionality. The `extern "C"` declarations are important for C ABI compatibility.

**9. Thinking About User Errors:**

Based on the functionality, potential user errors include:

* **Double Closing:** Closing an already closed FD.
* **Mismatched Ownership:**  Closing an FD with the wrong expected tag, indicating a logical error in resource management.
* **Ignoring Warnings:** Disabling `fdsan` entirely and missing potential issues.

**10. Tracing Execution Flow (Framework/NDK):**

To understand how the code is reached, I'd consider scenarios like:

* **Java `FileInputStream`/`FileOutputStream`:** These classes internally use native file descriptors. Closing them in Java would eventually lead to a `close()` call in the native code, which `fdsan` intercepts.
* **NDK File Operations:**  Direct use of `open()`, `close()`, etc., in NDK code would also trigger `fdsan`.

**11. Frida Hooking:**

Based on the functions, I'd identify key points for hooking:

* `android_fdsan_close_with_tag`: To observe the tag being passed during closure.
* `android_fdsan_get_owner_tag`: To inspect the current owner of an FD.
* `fdsan_error`: To see when errors are reported and the associated messages.
* `close`: To see all close operations.

**12. Structuring the Output:**

Finally, I'd organize the information logically, covering each point of the request. Using headings and bullet points helps with readability. Providing code examples (even short snippets) and hypothetical scenarios makes the explanation clearer. The SO layout and linking explanation would be more conceptual here, as this specific file isn't the dynamic linker itself.

**Self-Correction/Refinement:**

During the process, I might realize I've missed something or misinterpreted a detail. For example, initially, I might overemphasize the dynamic linker aspects based on the description of bionic, but then realize this specific file focuses on FD management within the C library itself. I would then adjust the emphasis in the output accordingly. Similarly, I'd double-check the interpretation of atomic operations and the error level logic to ensure accuracy.
好的，让我们详细分析一下 `bionic/libc/bionic/fdsan.cpp` 这个文件。

**功能概览:**

`fdsan.cpp` (File Descriptor Sanitizer) 是 Android Bionic C 库中的一个组件，其主要功能是**检测和报告与文件描述符 (file descriptor, fd) 使用相关的错误**，尤其是在 fd 的所有权和生命周期管理方面。  它旨在帮助开发者尽早发现潜在的 bug，例如：

* **Double-close:**  多次关闭同一个文件描述符。
* **Use-after-close:** 在文件描述符被关闭后仍然尝试使用它。
* **Ownership mismatches:**  试图用错误的“所有者”标签关闭文件描述符。

**与 Android 功能的关系及举例说明:**

`fdsan` 是 Android 安全性和稳定性保障的重要组成部分。它通过在 libc 层拦截和检查文件描述符的操作，为开发者提供了一种在运行时检测资源管理错误的方法。

**举例说明:**

* **Android Framework 中的文件操作:**  当 Java 层通过 `FileInputStream`, `FileOutputStream`, `ParcelFileDescriptor` 等类操作文件时，最终会调用底层的 native 函数，这些 native 函数会使用文件描述符。`fdsan` 可以在这些文件描述符被错误关闭或重复关闭时发出警告或终止程序。
* **NDK 开发中的文件操作:**  使用 NDK 进行 native 开发的开发者可以直接使用 `open()`, `close()` 等 POSIX 标准的系统调用来操作文件描述符。`fdsan` 同样可以监控这些操作。
* **Binder 机制中的文件描述符传递:** Android 的 Binder 机制允许在不同进程间传递文件描述符。`fdsan` 可以帮助跟踪这些传递的 fd 的生命周期，防止在错误的进程中关闭 fd。

**详细解释每一个 libc 函数的功能是如何实现的:**

以下列举了 `fdsan.cpp` 中使用的一些关键 libc 函数，并解释了它们的功能和实现方式：

* **`__close(int fd)`:**  这是实际执行关闭文件描述符的系统调用。`fdsan` 的 `close()` 函数会先进行一些检查，然后调用 `__close()` 来真正关闭 fd。这个函数的实现位于内核中。
* **`getrlimit(int resource, struct rlimit *rlim)`:**  用于获取或设置进程资源限制。在 `fdsan.cpp` 中，它被用来获取 `RLIMIT_NOFILE` (进程可以打开的最大文件描述符数) 的上限，以便动态分配 `FdTableOverflow` 结构体来存储更多的 fd 信息。其实现最终会通过系统调用进入内核。
* **`mmap(void *addr, size_t len, int prot, int flags, int fd, off_t offset)`:**  用于在进程的地址空间中创建新的映射。在 `fdsan.cpp` 中，当内联的 `FdTable` 空间不足时，`mmap` 被用来分配额外的内存来存储 `FdEntry` 结构体，形成溢出表 (`FdTableOverflow`)。这是一个系统调用，由内核完成内存映射。
* **`munmap(void *addr, size_t len)`:**  用于解除先前通过 `mmap` 创建的映射。在 `fdsan.cpp` 中，如果分配溢出表时发生竞争，当前线程分配的内存可能会被释放。这也是一个系统调用，由内核完成。
* **`atomic_load(volatile A *ptr)` / `atomic_compare_exchange_strong(volatile A *ptr, T *expected, T desired)` / `atomic_exchange(volatile A *ptr, T desired)`:**  这些是 C11 引入的原子操作，用于在多线程环境下安全地访问和修改共享变量。在 `fdsan.cpp` 中，它们被用来操作 `FdTable` 和 `FdEntry` 中的成员，例如 `overflow` 指针和 `close_tag`，以避免数据竞争。这些操作通常由编译器内建函数或汇编指令实现，保证操作的原子性。
* **`__system_property_find(const char *name)` / `__system_property_read_callback(const prop_info *pi, void (*callback)(void *arg, const char *name, const char *value, uint32_t serial), void *arg)`:**  用于访问 Android 系统属性。`fdsan.cpp` 使用这些函数来读取 `debug.fdsan` 属性的值，从而动态配置 `fdsan` 的错误报告级别。这些函数的实现通常涉及与 `property_service` 进程的通信。
* **`async_safe_fatal(const char* fmt, ...)` / `async_safe_format_log_va_list(int priority, const char* tag, const char* fmt, va_list ap)` / `async_safe_format_buffer_va_list(char* buffer, size_t size, const char* fmt, va_list ap)`:**  这些是 Bionic 提供的异步安全版本的日志和错误报告函数。它们被设计为在信号处理程序等异步上下文中安全调用。
* **`inline_raise(int sig)`:**  用于发送信号。`fdsan.cpp` 使用它在检测到错误时根据配置的错误级别发送 `SIGABRT` (用于致命错误) 或 `BIONIC_SIGNAL_DEBUGGER` (自定义的调试器信号)。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然 `fdsan.cpp` 本身不是 dynamic linker 的一部分，但它是 Bionic libc 的一部分，因此会被动态链接到其他 Android 进程和库中。

**SO 布局样本 (libbase.so 的简化示例，包含 libc.so 的依赖):**

```
libbase.so:
  ...
  NEEDED               libc.so
  ...
  SYMTAB
  ...
  00001000 g    DO .data          _ZN3base7g_valueE  // libbase 的全局变量
  ...
  DYNSYM
  ...
  00002000 g    F  libc.so        close              // 从 libc.so 导入的 close 函数
  00002010 g    F  libc.so        android_fdsan_close_with_tag // 从 libc.so 导入的 fdsan 函数
  ...
```

**链接的处理过程:**

1. **编译时链接:** 当 `libbase.so` 被编译时，链接器会记录它依赖于 `libc.so`，并将需要从 `libc.so` 导入的符号 (例如 `close`, `android_fdsan_close_with_tag`) 记录在 `libbase.so` 的动态符号表中。
2. **加载时链接:** 当 Android 系统加载 `libbase.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会执行以下步骤：
   * **加载依赖:**  dynamic linker 会加载 `libbase.so` 声明的依赖项，包括 `libc.so`。
   * **符号解析 (Symbol Resolution):**  dynamic linker 会遍历 `libbase.so` 的动态符号表，对于每一个未定义的符号，它会在已经加载的共享库 (例如 `libc.so`) 中查找对应的符号定义。
   * **重定位 (Relocation):**  一旦找到符号定义，dynamic linker 会更新 `libbase.so` 中使用这些符号的地址，将其指向 `libc.so` 中实际的函数或变量地址。例如，`libbase.so` 中调用 `close()` 的指令会被修改为跳转到 `libc.so` 中 `close()` 函数的地址。

在这种情况下，`libbase.so` 中对 `close()` 的调用实际上会被链接到 `bionic/libc/bionic/close.cpp` 中 `fdsan` 版本的 `close()` 函数 (它会调用 `android_fdsan_close_with_tag`)，而 `android_fdsan_close_with_tag` 的实现就在 `fdsan.cpp` 中。

**如果做了逻辑推理，请给出假设输入与输出:**

假设我们有以下代码片段，并且 `debug.fdsan` 系统属性设置为 `fatal`:

```c++
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>

int main() {
  int fd = open("/tmp/test.txt", O_RDWR | O_CREAT, 0666);
  if (fd < 0) {
    perror("open");
    return 1;
  }

  close(fd);
  close(fd); // 尝试 double-close
  return 0;
}
```

**假设输入:**

* 运行上述代码的 Android 设备，`debug.fdsan` 系统属性设置为 `fatal`。
* `/tmp/test.txt` 文件不存在 (或存在都没关系，重点是 double-close)。

**预期输出:**

由于 `debug.fdsan` 被设置为 `fatal`，当 `fdsan` 检测到 double-close 时，会调用 `fdsan_error`，最终导致 `inline_raise(SIGABRT)` 和 `abort()` 被调用。程序会崩溃，并可能在 logcat 中看到类似以下的错误信息：

```
A/libc: fdsan: double-close of file descriptor <fd_value> detected
A/libc: Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid <thread_id>, pid <process_id>
```

其中 `<fd_value>` 是实际的文件描述符数值，`<thread_id>` 和 `<process_id>` 是线程和进程 ID。

如果 `debug.fdsan` 设置为 `warn` 或 `warn_once`，则程序不会崩溃，但会在 logcat 中打印警告信息，并可能触发调试器信号 (如果连接了调试器)。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **忘记关闭文件描述符 (Resource Leak):**

   ```c++
   int fd = open("/tmp/leak.txt", O_RDONLY);
   // ... 一些操作，但是忘记调用 close(fd);
   ```

   虽然 `fdsan` 主要关注错误关闭，但资源泄漏也是文件描述符管理的常见问题。虽然 `fdsan` 本身不直接检测泄漏，但它可以帮助发现由于错误的关闭逻辑而导致的泄漏。

2. **在多线程环境下不正确地共享和关闭文件描述符:**

   ```c++
   // 线程 1 打开文件
   int fd = open("/tmp/shared.txt", O_RDWR);
   // 将 fd 传递给线程 2

   // 线程 1 稍后关闭文件
   close(fd);

   // 线程 2 仍然尝试使用已经关闭的 fd
   read(fd, buffer, size); // Use-after-close
   ```

   `fdsan` 可以检测到线程 2 的 use-after-close 错误。

3. **在传递文件描述符所有权时出现逻辑错误:**

   ```c++
   int fd = open("/tmp/transfer.txt", O_RDWR);
   uint64_t tag = android_fdsan_create_owner_tag(ANDROID_FDSAN_OWNER_TYPE_FILE, 123);
   android_fdsan_exchange_owner_tag(fd, 0, tag); // 标记 fd 的所有者

   // ... 将 fd 传递给另一个模块，期望另一个模块用相同的 tag 关闭

   close(fd); // 当前模块尝试关闭，但没有使用正确的 tag
   ```

   如果另一个模块期望使用 `android_fdsan_close_with_tag(fd, tag)` 关闭，而当前模块直接使用 `close(fd)`，`fdsan` 会发出警告，因为所有权不匹配。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤:**

**Android Framework 到 fdsan 的路径 (以 Java 文件操作为例):**

1. **Java 代码:**  Android Framework 的 Java 代码 (例如 `java.io.FileInputStream`) 调用 Java Native Interface (JNI) 方法。
2. **JNI 调用:**  JNI 方法映射到 Framework 层的 C++ 代码 (例如 AOSP 中的 `FileInputStream.cpp`)。
3. **Native 文件操作:** Framework 层的 C++ 代码最终会调用 Bionic libc 提供的文件操作函数，如 `open()`, `close()`, `read()`, `write()` 等。
4. **fdsan 拦截:** 当调用 `close()` 时，Bionic libc 中的 `close()` 函数 (在 `bionic/libc/bionic/close.cpp` 中) 会调用 `android_fdsan_close_with_tag()` 来进行 `fdsan` 的检查。

**NDK 到 fdsan 的路径:**

1. **NDK 代码:** NDK 开发者直接调用 Bionic libc 提供的标准 C 库函数，如 `open()`, `close()` 等。
2. **fdsan 拦截:**  与 Framework 类似，当 NDK 代码调用 `close()` 时，Bionic libc 的 `close()` 函数会触发 `fdsan` 的检查。

**Frida Hook 示例:**

假设我们想 hook `android_fdsan_close_with_tag` 函数，查看关闭文件描述符时传递的 fd 和 tag 信息：

```python
import frida
import sys

package_name = "your.app.package" # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] Message: {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"Error: Process '{package_name}' not found. Please make sure the app is running.")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "android_fdsan_close_with_tag"), {
    onEnter: function(args) {
        var fd = args[0].toInt32();
        var tag_low = args[1].low;
        var tag_high = args[1].high;
        var tag = (tag_high * 0x100000000) + tag_low;
        send({
            type: "fdsan_close",
            fd: fd,
            tag: tag
        });
        console.log("android_fdsan_close_with_tag called with fd: " + fd + ", tag: " + tag);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**Frida Hook 解释:**

1. **导入 frida 库:** 导入必要的 Frida 库。
2. **连接目标进程:** 使用 `frida.get_usb_device().attach(package_name)` 连接到目标 Android 应用的进程。
3. **定义消息处理函数:**  `on_message` 函数用于处理从 Frida 脚本发送回来的消息。
4. **Frida 脚本代码:**
   * `Interceptor.attach(...)`:  使用 Frida 的 `Interceptor` API 来 hook `libc.so` 中的 `android_fdsan_close_with_tag` 函数。
   * `Module.findExportByName(...)`:  查找 `libc.so` 中名为 `android_fdsan_close_with_tag` 的导出函数。
   * `onEnter: function(args)`:  当目标函数被调用时，`onEnter` 函数会被执行。`args` 数组包含了传递给目标函数的参数。
   * `args[0]` 和 `args[1]`:  分别对应 `android_fdsan_close_with_tag` 的 `fd` 和 `expected_tag` 参数。注意 `expected_tag` 是一个 64 位整数，在 JavaScript 中需要处理高低位。
   * `send(...)`:  使用 Frida 的 `send` 函数将数据发送回 Python 脚本。
   * `console.log(...)`:  在目标进程的控制台输出日志信息。
5. **创建和加载脚本:**  创建 Frida 脚本并加载到目标进程中。
6. **保持脚本运行:** `sys.stdin.read()` 用于阻塞 Python 脚本，保持 hook 状态。

**运行此 Frida 脚本后，当目标应用关闭文件描述符时，你将在 Python 终端看到类似以下的输出：**

```
[*] Message: {'type': 'fdsan_close', 'fd': 3, 'tag': 0}
android_fdsan_close_with_tag called with fd: 3, tag: 0
[*] Message: {'type': 'fdsan_close', 'fd': 7, 'tag': 72057594037927936}
android_fdsan_close_with_tag called with fd: 7, tag: 72057594037927936
...
```

这将帮助你观察文件描述符的关闭操作以及相关的 tag 信息，从而调试 `fdsan` 的行为和理解文件描述符的管理流程。

希望这个详细的分析能够帮助你理解 `bionic/libc/bionic/fdsan.cpp` 的功能和工作原理。

Prompt: 
```
这是目录为bionic/libc/bionic/fdsan.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <android/fdsan.h>

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/cdefs.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <async_safe/log.h>
#include <platform/bionic/page.h>
#include <platform/bionic/reserved_signals.h>
#include <sys/system_properties.h>

#include "private/bionic_fdtrack.h"
#include "private/bionic_globals.h"
#include "private/bionic_inline_raise.h"
#include "pthread_internal.h"

extern "C" int __close(int fd);
pid_t __get_cached_pid();

static constexpr const char* kFdsanPropertyName = "debug.fdsan";

template<size_t inline_fds>
FdEntry* FdTableImpl<inline_fds>::at(size_t idx) {
  if (idx < inline_fds) {
    return &entries[idx];
  }

  // Try to create the overflow table ourselves.
  FdTableOverflow* local_overflow = atomic_load(&overflow);
  if (__predict_false(!local_overflow)) {
    struct rlimit rlim = { .rlim_max = 32768 };
    getrlimit(RLIMIT_NOFILE, &rlim);
    rlim_t max = rlim.rlim_max;

    if (max == RLIM_INFINITY) {
      // This isn't actually possible (the kernel has a hard limit), but just
      // in case...
      max = 32768;
    }

    if (idx > max) {
      // This can happen if an fd is created and then the rlimit is lowered.
      // In this case, just return nullptr and ignore the fd.
      return nullptr;
    }

    size_t required_count = max - inline_fds;
    size_t required_size = sizeof(FdTableOverflow) + required_count * sizeof(FdEntry);
    size_t aligned_size = __BIONIC_ALIGN(required_size, page_size());
    size_t aligned_count = (aligned_size - sizeof(FdTableOverflow)) / sizeof(FdEntry);

    void* allocation =
        mmap(nullptr, aligned_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (allocation == MAP_FAILED) {
      async_safe_fatal("fdsan: mmap failed: %m");
    }

    FdTableOverflow* new_overflow = reinterpret_cast<FdTableOverflow*>(allocation);
    new_overflow->len = aligned_count;

    if (atomic_compare_exchange_strong(&overflow, &local_overflow, new_overflow)) {
      local_overflow = new_overflow;
    } else {
      // Someone beat us to it. Deallocate and use theirs.
      munmap(allocation, aligned_size);
    }
  }

  size_t offset = idx - inline_fds;
  if (local_overflow->len <= offset) {
    return nullptr;
  }
  return &local_overflow->entries[offset];
}

void __libc_init_fdsan() {
  constexpr auto default_level = ANDROID_FDSAN_ERROR_LEVEL_FATAL;
  android_fdsan_set_error_level_from_property(default_level);
}

static FdTable& GetFdTable() {
  return __libc_shared_globals()->fd_table;
}

// Exposed to the platform to allow crash_dump to print out the fd table.
extern "C" void* android_fdsan_get_fd_table() {
  return &GetFdTable();
}

static FdEntry* GetFdEntry(int fd) {
  if (fd < 0) {
    return nullptr;
  }

  return GetFdTable().at(fd);
}

__printflike(1, 0) static void fdsan_error(const char* fmt, ...) {
  auto& fd_table = GetFdTable();

  auto error_level = atomic_load(&fd_table.error_level);
  if (error_level == ANDROID_FDSAN_ERROR_LEVEL_DISABLED) {
    return;
  }

  struct {
    size_t size;
    char buf[512];
  } abort_message;

  va_list va;
  va_start(va, fmt);
  if (error_level == ANDROID_FDSAN_ERROR_LEVEL_FATAL) {
    async_safe_fatal_va_list("fdsan", fmt, va);
  } else {
    async_safe_format_log_va_list(ANDROID_LOG_ERROR, "fdsan", fmt, va);
    va_end(va);
    va_start(va, fmt);
    size_t len =
        async_safe_format_buffer_va_list(abort_message.buf, sizeof(abort_message.buf), fmt, va);
    abort_message.size = len + sizeof(size_t);
  }
  va_end(va);

  switch (error_level) {
    case ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE:
      atomic_compare_exchange_strong(&fd_table.error_level, &error_level,
                                     ANDROID_FDSAN_ERROR_LEVEL_DISABLED);
      __BIONIC_FALLTHROUGH;
    case ANDROID_FDSAN_ERROR_LEVEL_WARN_ALWAYS:
      inline_raise(BIONIC_SIGNAL_DEBUGGER, &abort_message);
      break;

    case ANDROID_FDSAN_ERROR_LEVEL_FATAL:
      inline_raise(SIGABRT);
      abort();

    case ANDROID_FDSAN_ERROR_LEVEL_DISABLED:
      break;
  }
}

uint64_t android_fdsan_create_owner_tag(android_fdsan_owner_type type, uint64_t tag) {
  if (tag == 0) {
    return 0;
  }

  if (__predict_false((type & 0xff) != type)) {
    async_safe_fatal("invalid android_fdsan_owner_type value: %x", type);
  }

  uint64_t result = static_cast<uint64_t>(type) << 56;
  uint64_t mask = (static_cast<uint64_t>(1) << 56) - 1;
  result |= tag & mask;
  return result;
}

const char* android_fdsan_get_tag_type(uint64_t tag) {
  uint64_t type = tag >> 56;
  switch (type) {
    case ANDROID_FDSAN_OWNER_TYPE_FILE:
      return "FILE*";
    case ANDROID_FDSAN_OWNER_TYPE_DIR:
      return "DIR*";
    case ANDROID_FDSAN_OWNER_TYPE_UNIQUE_FD:
      return "unique_fd";
    case ANDROID_FDSAN_OWNER_TYPE_FILEINPUTSTREAM:
      return "FileInputStream";
    case ANDROID_FDSAN_OWNER_TYPE_FILEOUTPUTSTREAM:
      return "FileOutputStream";
    case ANDROID_FDSAN_OWNER_TYPE_RANDOMACCESSFILE:
      return "RandomAccessFile";
    case ANDROID_FDSAN_OWNER_TYPE_PARCELFILEDESCRIPTOR:
      return "ParcelFileDescriptor";
    case ANDROID_FDSAN_OWNER_TYPE_SQLITE:
      return "sqlite";
    case ANDROID_FDSAN_OWNER_TYPE_ART_FDFILE:
      return "ART FdFile";
    case ANDROID_FDSAN_OWNER_TYPE_DATAGRAMSOCKETIMPL:
      return "DatagramSocketImpl";
    case ANDROID_FDSAN_OWNER_TYPE_SOCKETIMPL:
      return "SocketImpl";
    case ANDROID_FDSAN_OWNER_TYPE_ZIPARCHIVE:
      return "ZipArchive";
    case ANDROID_FDSAN_OWNER_TYPE_NATIVE_HANDLE:
      return "native_handle_t";
    case ANDROID_FDSAN_OWNER_TYPE_PARCEL:
      return "Parcel";

    case ANDROID_FDSAN_OWNER_TYPE_GENERIC_00:
    default:
      return "native object of unknown type";

    case ANDROID_FDSAN_OWNER_TYPE_GENERIC_FF:
      // If bits 48 to 56 are set, this is a sign-extended generic native pointer
      uint64_t high_bits = tag >> 48;
      if (high_bits == (1 << 16) - 1) {
        return "native object of unknown type";
      }

      return "Java object of unknown type";
  }
}

uint64_t android_fdsan_get_tag_value(uint64_t tag) {
  // Lop off the most significant byte and sign extend.
  return static_cast<uint64_t>(static_cast<int64_t>(tag << 8) >> 8);
}

int android_fdsan_close_with_tag(int fd, uint64_t expected_tag) {
  if (__get_thread()->is_vforked()) {
    return __close(fd);
  }

  FDTRACK_CLOSE(fd);
  FdEntry* fde = GetFdEntry(fd);
  if (!fde) {
    return __close(fd);
  }

  uint64_t tag = expected_tag;
  if (!atomic_compare_exchange_strong(&fde->close_tag, &tag, 0)) {
    const char* expected_type = android_fdsan_get_tag_type(expected_tag);
    uint64_t expected_owner = android_fdsan_get_tag_value(expected_tag);
    const char* actual_type = android_fdsan_get_tag_type(tag);
    uint64_t actual_owner = android_fdsan_get_tag_value(tag);
    if (expected_tag && tag) {
      fdsan_error(
          "attempted to close file descriptor %d, "
          "expected to be owned by %s 0x%" PRIx64 ", actually owned by %s 0x%" PRIx64,
          fd, expected_type, expected_owner, actual_type, actual_owner);
    } else if (expected_tag && !tag) {
      fdsan_error(
          "attempted to close file descriptor %d, "
          "expected to be owned by %s 0x%" PRIx64 ", actually unowned",
          fd, expected_type, expected_owner);
    } else if (!expected_tag && tag) {
      fdsan_error(
          "attempted to close file descriptor %d, "
          "expected to be unowned, actually owned by %s 0x%" PRIx64,
          fd, actual_type, actual_owner);
    } else if (!expected_tag && !tag) {
      // This should never happen: our CAS failed, but expected == actual?
      async_safe_fatal("fdsan atomic_compare_exchange_strong failed unexpectedly while closing");
    }
  }

  int rc = __close(fd);
  // If we were expecting to close with a tag, abort on EBADF.
  if (expected_tag && rc == -1 && errno == EBADF) {
    fdsan_error("double-close of file descriptor %d detected", fd);
  }
  return rc;
}

uint64_t android_fdsan_get_owner_tag(int fd) {
  FdEntry* fde = GetFdEntry(fd);
  if (!fde) {
    return 0;
  }
  return fde->close_tag;
}

void android_fdsan_exchange_owner_tag(int fd, uint64_t expected_tag, uint64_t new_tag) {
  if (__get_thread()->is_vforked()) {
    return;
  }

  FdEntry* fde = GetFdEntry(fd);
  if (!fde) {
    return;
  }

  uint64_t tag = expected_tag;
  if (!atomic_compare_exchange_strong(&fde->close_tag, &tag, new_tag)) {
    if (expected_tag && tag) {
      fdsan_error(
          "failed to exchange ownership of file descriptor: fd %d is "
          "owned by %s 0x%" PRIx64 ", was expected to be owned by %s 0x%" PRIx64,
          fd, android_fdsan_get_tag_type(tag), android_fdsan_get_tag_value(tag),
          android_fdsan_get_tag_type(expected_tag), android_fdsan_get_tag_value(expected_tag));
    } else if (expected_tag && !tag) {
      fdsan_error(
          "failed to exchange ownership of file descriptor: fd %d is "
          "unowned, was expected to be owned by %s 0x%" PRIx64,
          fd, android_fdsan_get_tag_type(expected_tag), android_fdsan_get_tag_value(expected_tag));
    } else if (!expected_tag && tag) {
      fdsan_error(
          "failed to exchange ownership of file descriptor: fd %d is "
          "owned by %s 0x%" PRIx64 ", was expected to be unowned",
          fd, android_fdsan_get_tag_type(tag), android_fdsan_get_tag_value(tag));
    } else if (!expected_tag && !tag) {
      // This should never happen: our CAS failed, but expected == actual?
      async_safe_fatal(
          "fdsan atomic_compare_exchange_strong failed unexpectedly while exchanging owner tag");
    }
  }
}

android_fdsan_error_level android_fdsan_get_error_level() {
  return GetFdTable().error_level;
}

android_fdsan_error_level android_fdsan_set_error_level(android_fdsan_error_level new_level) {
  if (__get_thread()->is_vforked()) {
    return android_fdsan_get_error_level();
  }

  return atomic_exchange(&GetFdTable().error_level, new_level);
}

android_fdsan_error_level android_fdsan_set_error_level_from_property(
    android_fdsan_error_level default_level) {
  const prop_info* pi = __system_property_find(kFdsanPropertyName);
  if (!pi) {
    return android_fdsan_set_error_level(default_level);
  }

  struct callback_data {
    android_fdsan_error_level default_value;
    android_fdsan_error_level result;
  };

  callback_data data;
  data.default_value = default_level;

  __system_property_read_callback(
      pi,
      [](void* arg, const char*, const char* value, uint32_t) {
        callback_data* data = static_cast<callback_data*>(arg);

        if (strcasecmp(value, "1") == 0 || strcasecmp(value, "fatal") == 0) {
          data->result = android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_FATAL);
        } else if (strcasecmp(value, "warn") == 0) {
          data->result = android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_WARN_ALWAYS);
        } else if (strcasecmp(value, "warn_once") == 0) {
          data->result = android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_WARN_ONCE);
        } else {
          if (strlen(value) != 0 && strcasecmp(value, "0") != 0) {
            async_safe_format_log(ANDROID_LOG_ERROR, "libc",
                                  "debug.fdsan set to unknown value '%s', disabling", value);
          }
          data->result = android_fdsan_set_error_level(data->default_value);
        }
      },
      &data);

  return data.result;
}

int close(int fd) {
  int rc = android_fdsan_close_with_tag(fd, 0);
  if (rc == -1 && errno == EINTR) {
    return 0;
  }
  return rc;
}

"""

```