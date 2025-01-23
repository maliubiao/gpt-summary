Response:
Let's break down the thought process for analyzing this C++ code snippet and generating the detailed explanation.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `pthread_setname_np.cpp` within the Android Bionic library. This involves:

* **Function Identification:**  Identifying the core functions implemented in the file.
* **Function Purpose:** Explaining what each function does.
* **Android Relevance:**  Connecting the functions to how they are used within the Android ecosystem.
* **Implementation Details:**  Delving into the code to explain *how* each function achieves its purpose, especially the use of system calls and file operations.
* **Dynamic Linker Aspects:** Examining any interactions with the dynamic linker (in this case, the `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` macro).
* **Error Handling:** Identifying potential errors and common usage mistakes.
* **Usage in Android:** Tracing how the function might be called from higher layers of Android (Framework/NDK).
* **Debugging:** Providing practical debugging techniques using Frida.

**2. Initial Code Scan and Keyword Recognition:**

The first step is a quick scan of the code to identify key elements:

* **Function Names:** `pthread_setname_np`, `pthread_getname_np`, `__open_task_comm_fd`. The `_np` suffix often indicates a non-POSIX or platform-specific function.
* **Includes:**  `<pthread.h>`, `<fcntl.h>`, `<stdio.h>`, `<string.h>`, `<sys/prctl.h>`, `<sys/stat.h>`, `<sys/types.h>`, `<unistd.h>`. These headers suggest interactions with threads, file operations, system calls, and string manipulation.
* **Macros:** `MAX_TASK_COMM_LEN`, `__BIONIC_WEAK_FOR_NATIVE_BRIDGE`, `TEMP_FAILURE_RETRY`. These provide important context about limitations, linking behavior, and error handling.
* **System Calls:** `open`, `read`, `write`, `close`, `prctl`. These are the core OS interactions the functions rely on.
* **`/proc` filesystem:** The code references `/proc/self/task/%d/comm`, which immediately points to interacting with the process information in the Linux kernel.

**3. Function-by-Function Analysis:**

Now, focus on each function individually:

* **`__open_task_comm_fd`:**
    * **Purpose:**  The name and the use of `/proc/self/task/%d/comm` strongly suggest opening a file descriptor to communicate with a specific thread.
    * **Parameters:** `pthread_t t` (the thread ID), `int flags` (file access mode), `const char* caller` (for debugging).
    * **Implementation:**
        * Uses `snprintf` to construct the path to the `comm` file in `/proc`.
        * Calls `__pthread_internal_gettid` to get the underlying thread ID (tid) from the `pthread_t`. This is an internal Bionic function.
        * Calls `open` with the constructed path and `O_CLOEXEC` (important for security).
    * **Return Value:** A file descriptor or -1 on error.

* **`pthread_getname_np`:**
    * **Purpose:**  To get the name of a thread.
    * **Parameters:** `pthread_t t` (the thread ID), `char* buf` (buffer to store the name), `size_t buf_size` (buffer size).
    * **Implementation:**
        * **Self-Case:** If `t` is the current thread, use the `prctl(PR_GET_NAME, buf)` system call, which is a more direct way to get the current thread's name.
        * **Other Thread Case:**
            * Calls `__open_task_comm_fd` with `O_RDONLY` to open the target thread's `comm` file.
            * Reads the thread name from the file using `read`.
            * Handles potential errors from `open` and `read`.
            * Deals with the trailing newline character often present in `/proc/<pid>/comm`.
            * Checks for buffer overflow (`ERANGE`).
    * **Return Value:** 0 on success, an error code on failure.

* **`pthread_setname_np`:**
    * **Purpose:** To set the name of a thread.
    * **Parameters:** `pthread_t t` (the thread ID), `const char* thread_name` (the new name).
    * **Implementation:**
        * **Self-Case:** If `t` is the current thread, use the `prctl(PR_SET_NAME, thread_name)` system call.
        * **Other Thread Case:**
            * Calls `__open_task_comm_fd` with `O_WRONLY` to open the target thread's `comm` file.
            * Writes the `thread_name` to the file using `write`.
            * Handles potential errors from `open` and `write`.
            * Checks if the correct number of bytes were written (`EIO`).
    * **Return Value:** 0 on success, an error code on failure.

**4. Connecting to Android and Dynamic Linking:**

* **Android Relevance:**  Thread naming is crucial for debugging, profiling, and system monitoring in Android. Tools like `adb shell ps` rely on these names.
* **`__BIONIC_WEAK_FOR_NATIVE_BRIDGE`:** This macro is key. It signifies that these functions can be overridden by the native bridge, which is used to run older native code on newer Android versions. This allows for compatibility.

**5. Explaining `libc` and Dynamic Linker Aspects:**

* **`libc` Functions:**  Provide explanations for standard C library functions like `strlen`, `snprintf`, `open`, `read`, `write`, `close`. Emphasize their role in interacting with the operating system.
* **Dynamic Linker:** Explain the concept of shared libraries (`.so`), how the linker resolves symbols, and the role of `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` in allowing overrides. Create a simple example of `.so` layout.

**6. Error Handling and Common Mistakes:**

Think about common errors a programmer might make:

* **Buffer Overflow:**  Providing a buffer too small for `pthread_getname_np`.
* **Invalid Thread ID:** Trying to set/get the name of a non-existent thread.
* **Name Length Exceeded:**  Providing a thread name longer than `MAX_TASK_COMM_LEN`.

**7. Tracing Function Calls (Android Framework/NDK):**

* **NDK:** Provide a simple NDK example demonstrating direct usage.
* **Framework:** Describe how higher-level Android components (like the Activity Manager or System Server) might internally use these functions indirectly, potentially via JNI calls or other system services.

**8. Frida Hooking:**

Create a practical Frida script that demonstrates how to intercept calls to `pthread_setname_np` and log the thread ID and the new name. This involves:

* Targeting the correct library (`/system/lib64/bionic/libc.so` or similar).
* Using `Interceptor.attach` to hook the function.
* Extracting arguments and logging them.

**9. Structuring the Response:**

Organize the information logically with clear headings and subheadings. Use bullet points and code blocks to make the explanation easy to read and understand. Translate technical terms into understandable language.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This just sets the thread name."  **Correction:** Realize it involves interaction with the `/proc` filesystem and different paths for the current thread vs. other threads.
* **Initial thought:**  Focus heavily on the C++ syntax. **Correction:**  Shift focus to the underlying system calls and the high-level purpose within Android.
* **Initial thought:**  Assume the reader is an expert. **Correction:** Explain concepts like dynamic linking and `/proc` in a way that is accessible to a broader audience.
* **Missing Detail:**  Initially forgot to explicitly mention the `O_CLOEXEC` flag's importance for security. **Correction:** Added an explanation.

By following this systematic approach, combined with some domain knowledge about operating systems and Android internals, the detailed and accurate explanation can be generated.
好的，我们来详细分析一下 `bionic/libc/bionic/pthread_setname_np.cpp` 文件的功能和实现。

**文件功能概览**

`pthread_setname_np.cpp` 文件实现了两个主要的功能，用于设置和获取线程的名字：

1. **`pthread_setname_np(pthread_t t, const char* thread_name)`**:  设置指定线程 `t` 的名字为 `thread_name`。这是一个非 POSIX 标准的函数，`_np` 后缀表示 "non-portable"。
2. **`pthread_getname_np(pthread_t t, char* buf, size_t buf_size)`**: 获取指定线程 `t` 的名字，并将结果存储在 `buf` 中，`buf_size` 是缓冲区的大小。这也是一个非 POSIX 标准的函数。

**与 Android 功能的关系及举例**

这两个函数在 Android 系统中被广泛使用，用于给线程命名，方便开发者调试、监控和分析。

**举例说明:**

* **调试工具 (如 `adb shell ps`)**:  当你使用 `adb shell ps` 命令查看进程和线程信息时，看到的线程名称就是通过 `pthread_getname_np` 获取的。例如，你可能会看到类似 "RenderThread" 或 "AsyncTask #1" 这样的线程名称。这些名称通常由应用程序在创建线程时通过 `pthread_setname_np` 设置。
* **性能分析工具 (如 Systrace, Perfetto)**:  这些工具可以跟踪系统调用和事件，线程名称是识别特定执行路径的关键信息。通过设置有意义的线程名称，可以更容易地理解性能瓶颈或行为异常发生在哪里。
* **应用开发**:  开发者可以使用 `pthread_setname_np` 给自己的工作线程命名，提高代码可读性和调试效率。例如，一个下载模块可能会创建一个名为 "DownloadThread" 的线程。

**`libc` 函数的实现细节**

**1. `pthread_setname_np(pthread_t t, const char* thread_name)`**

* **参数校验**: 首先检查 `thread_name` 的长度，如果超过 `MAX_TASK_COMM_LEN` (通常为 16)，则返回 `ERANGE` 错误。
* **处理自身线程**: 如果 `t` 等于 `pthread_self()`，表示要设置当前线程的名字。这时，直接使用 `prctl(PR_SET_NAME, thread_name)` 系统调用来设置线程名。`prctl` 是一个 Linux 系统调用，用于对进程或线程执行各种控制操作。`PR_SET_NAME` 操作码用于设置线程名。
* **处理其他线程**: 如果 `t` 不是当前线程，则需要通过 `/proc` 文件系统来操作目标线程。
    * **打开 `comm` 文件**: 调用内部函数 `__open_task_comm_fd(t, O_WRONLY, "pthread_setname_np")`。
    * **`__open_task_comm_fd` 的实现**:
        * 使用 `__pthread_internal_gettid(t, caller)` 获取目标线程 `t` 的内核线程 ID (TID)。`__pthread_internal_gettid` 是 bionic 内部函数，用于将 `pthread_t` 转换为 TID。
        * 使用 `snprintf` 构造目标线程的 `comm` 文件路径，格式为 `/proc/self/task/<tid>/comm`。
        * 使用 `open` 系统调用以只写 (`O_WRONLY`) 模式打开该文件。`O_CLOEXEC` 标志确保在 `execve` 调用后关闭此文件描述符，防止泄露到子进程。
    * **写入线程名**: 使用 `write` 系统调用将 `thread_name` 写入到打开的 `comm` 文件中。
    * **错误处理**: 检查 `open` 和 `write` 的返回值，如果出错则返回相应的 `errno`。如果写入的字节数与线程名长度不符，则返回 `EIO` 错误。
    * **关闭文件**: 使用 `close` 系统调用关闭文件描述符。

**假设输入与输出 (针对 `pthread_setname_np`)**

* **假设输入**:
    * `t`: 一个有效的 `pthread_t` 值，代表一个正在运行的线程。
    * `thread_name`: 字符串 "MyWorkerThread"。
* **输出**:
    * 如果设置成功，返回 0。
    * 如果 `thread_name` 长度超过 `MAX_TASK_COMM_LEN`，返回 `ERANGE`。
    * 如果无法打开 `/proc/self/task/<tid>/comm` 文件，返回相应的 `errno` (例如 `ENOENT` 如果线程不存在)。
    * 如果写入操作失败，返回相应的 `errno` (例如 `EIO`)。

**2. `pthread_getname_np(pthread_t t, char* buf, size_t buf_size)`**

* **参数校验**: 检查 `buf_size` 是否小于 `MAX_TASK_COMM_LEN`，如果是则返回 `ERANGE`，因为线程名至少需要 `MAX_TASK_COMM_LEN` 字节的空间。
* **处理自身线程**: 如果 `t` 等于 `pthread_self()`，直接使用 `prctl(PR_GET_NAME, buf)` 系统调用获取当前线程的名字并存储到 `buf` 中。如果 `prctl` 调用失败，则返回 `errno`，否则返回 0。
* **处理其他线程**: 如果 `t` 不是当前线程：
    * **打开 `comm` 文件**: 调用 `__open_task_comm_fd(t, O_RDONLY, "pthread_getname_np")` 以只读模式打开目标线程的 `comm` 文件。
    * **读取线程名**: 使用 `read` 系统调用从打开的 `comm` 文件中读取线程名到 `buf` 中。
    * **错误处理**: 检查 `open` 和 `read` 的返回值，如果出错则返回相应的 `errno`。
    * **处理末尾换行符**:  内核在 `/proc/<pid>/comm` 文件中会在线程名后添加一个换行符 `\n`。代码检查并移除这个换行符。
    * **处理缓冲区溢出**: 如果读取的字节数等于 `buf_size`，则说明缓冲区可能不足以容纳完整的线程名，返回 `ERANGE`。否则，在读取到的字符串末尾添加 `\0` 作为字符串结束符。
    * **关闭文件**: 使用 `close` 系统调用关闭文件描述符。

**假设输入与输出 (针对 `pthread_getname_np`)**

* **假设输入**:
    * `t`: 一个有效的 `pthread_t` 值。
    * `buf`: 一个大小至少为 `MAX_TASK_COMM_LEN` 字节的字符数组。
    * `buf_size`: `buf` 的大小。
* **输出**:
    * 如果获取成功，线程名会存储在 `buf` 中，函数返回 0。
    * 如果 `buf_size` 太小，返回 `ERANGE`。
    * 如果无法打开 `/proc/self/task/<tid>/comm` 文件，返回相应的 `errno`。
    * 如果读取操作失败，返回相应的 `errno`。

**涉及 Dynamic Linker 的功能**

代码中使用了宏 `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` 修饰了 `pthread_getname_np` 和 `pthread_setname_np` 函数。这个宏在 Android Bionic 中用于实现对这些函数的弱符号链接，主要用于 Native Bridge 的兼容性。

**SO 布局样本:**

假设一个应用程序链接了 `libc.so`：

```
/system/lib64/libc.so:
    ... (其他代码段) ...
    .text:
        ... (其他函数代码) ...
        pthread_setname_np:  <--- 默认实现在这里
        pthread_getname_np:  <--- 默认实现在这里
        ...
    ...
```

当 Native Bridge (用于运行旧版 Native 代码) 存在时，它可能会提供自己的 `pthread_setname_np` 和 `pthread_getname_np` 实现。  这些实现会放在 Native Bridge 提供的 SO 中，例如：

```
/system/lib64/native_bridge.so:
    ...
    .text:
        pthread_setname_np:  <--- Native Bridge 提供的实现
        pthread_getname_np:  <--- Native Bridge 提供的实现
    ...
```

**链接的处理过程:**

1. **加载时**: 当应用加载时，动态链接器会加载所有依赖的共享库，包括 `libc.so` 和可能的 `native_bridge.so`。
2. **符号解析**: 当链接器解析 `pthread_setname_np` 和 `pthread_getname_np` 这两个符号时，由于使用了 `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` 宏，链接器会优先选择 Native Bridge 提供的实现（如果存在）。
3. **弱符号链接**: `__BIONIC_WEAK_FOR_NATIVE_BRIDGE` 创建的是弱符号，这意味着如果找到了更强的符号（例如 Native Bridge 提供的），则使用更强的符号。如果 Native Bridge 没有提供这些函数的实现，则会回退到 `libc.so` 中的默认实现。

**用户或编程常见的使用错误**

1. **缓冲区溢出 (针对 `pthread_getname_np`)**: 传递给 `pthread_getname_np` 的缓冲区 `buf` 太小，无法容纳完整的线程名称，可能导致程序崩溃或未定义的行为。
   ```c++
   char name[8]; // 缓冲区太小
   pthread_getname_np(thread_id, name, sizeof(name)); // 可能会溢出
   ```
2. **线程名称过长 (针对 `pthread_setname_np`)**: 尝试设置一个长度超过 `MAX_TASK_COMM_LEN` 的线程名称。
   ```c++
   pthread_setname_np(thread_id, "ThisIsAVeryLongThreadName"); // 会返回 ERANGE
   ```
3. **在错误的线程上下文中调用**: 虽然代码逻辑上允许设置其他线程的名字，但在实际应用中，通常只会在创建线程的线程中设置该线程的名字。尝试从不相关的线程修改其他线程的名字可能会导致意外情况或权限问题。
4. **假设线程 ID 是进程 ID**: `pthread_t` 是线程 ID，与进程 ID (PID) 不同。需要使用 `pthread_self()` 获取当前线程的 ID。
5. **忘记检查返回值**: 没有检查 `pthread_setname_np` 和 `pthread_getname_np` 的返回值，可能忽略了错误情况。

**Android Framework 或 NDK 如何到达这里**

**1. NDK (Native Development Kit)**

* **直接使用 Pthreads API**: 在 NDK 开发中，开发者可以直接使用 POSIX 线程 API，包括 `pthread_create` 来创建线程。
* **调用 `pthread_setname_np`**: 创建线程后，开发者可以显式地调用 `pthread_setname_np` 来命名线程。

   ```c++
   #include <pthread.h>
   #include <stdio.h>
   #include <string.h>
   #include <errno.h>

   void* worker_thread(void* arg) {
       pthread_setname_np(pthread_self(), "MyNDKWorker");
       // ... 线程逻辑 ...
       return nullptr;
   }

   int main() {
       pthread_t thread;
       pthread_create(&thread, nullptr, worker_thread, nullptr);
       pthread_join(thread, nullptr);
       return 0;
   }
   ```

**2. Android Framework**

Android Framework 通常不会直接调用 `pthread_setname_np` 或 `pthread_getname_np`。相反，它通常会通过以下方式间接使用：

* **Java 线程映射**: 当 Java 代码创建 `java.lang.Thread` 时，Android Runtime (ART) 会在 Native 层创建一个对应的 Native 线程。ART 内部可能会使用 `pthread_setname_np` 来设置与 Java 线程关联的 Native 线程的名称。例如，`Thread.setName()` 方法最终可能会调用到 Native 层的实现，进而调用 `pthread_setname_np`。
* **系统服务**: 一些系统服务（如 `system_server`）在 Native 层创建工作线程来执行任务。这些服务可能会使用 `pthread_setname_np` 来标识这些线程的功能。
* **JNI 调用**: Java 代码可以通过 JNI (Java Native Interface) 调用 Native 代码。Native 代码中创建的线程可以使用 `pthread_setname_np`。

**Frida Hook 示例**

以下是一个使用 Frida Hook `pthread_setname_np` 的示例，可以用来调试线程命名过程：

```javascript
if (Process.platform === 'android') {
  const libc = Process.getModuleByName("libc.so");
  const pthread_setname_np = libc.getExportByName("pthread_setname_np");

  if (pthread_setname_np) {
    Interceptor.attach(pthread_setname_np, {
      onEnter: function (args) {
        const threadId = args[0];
        const threadNamePtr = args[1];
        const threadName = threadNamePtr.readCString();
        console.log(`[pthread_setname_np] Thread ID: ${threadId}, Name: ${threadName}`);
      },
      onLeave: function (retval) {
        console.log(`[pthread_setname_np] Return value: ${retval}`);
      }
    });
    console.log("Hooked pthread_setname_np");
  } else {
    console.error("pthread_setname_np not found in libc.so");
  }
} else {
  console.log("This script is for Android.");
}
```

**使用方法:**

1. 将上述 JavaScript 代码保存到一个文件中，例如 `hook_pthread_setname.js`。
2. 使用 Frida 连接到目标 Android 进程：
   ```bash
   frida -U -f <package_name> -l hook_pthread_setname.js --no-pause
   # 或连接到正在运行的进程
   frida -U <process_id> -l hook_pthread_setname.js
   ```
   将 `<package_name>` 替换为要调试的应用程序的包名，或将 `<process_id>` 替换为进程 ID。

**调试步骤:**

1. 运行 Frida 脚本后，当目标应用程序中的线程调用 `pthread_setname_np` 时，Frida 会拦截该调用。
2. `onEnter` 函数会被执行，打印出线程 ID 和尝试设置的线程名称。
3. `onLeave` 函数会被执行，打印出 `pthread_setname_np` 的返回值，可以用来判断设置是否成功。

通过 Frida Hook，你可以观察应用程序在何时、何地以及如何命名线程，这对于理解应用程序的线程模型和调试线程相关问题非常有帮助。

希望以上详细的解释能够帮助你理解 `pthread_setname_np.cpp` 文件的功能和实现细节。

### 提示词
```
这是目录为bionic/libc/bionic/pthread_setname_np.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2008 The Android Open Source Project
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

#include <pthread.h>

#include <fcntl.h>
#include <stdio.h> // For snprintf.
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "private/bionic_defs.h"
#include "private/ErrnoRestorer.h"
#include "pthread_internal.h"

// This value is not exported by kernel headers.
#define MAX_TASK_COMM_LEN 16

static int __open_task_comm_fd(pthread_t t, int flags, const char* caller) {
  char comm_name[64];
  snprintf(comm_name, sizeof(comm_name), "/proc/self/task/%d/comm",
           __pthread_internal_gettid(t, caller));
  return open(comm_name, O_CLOEXEC | flags);
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int pthread_getname_np(pthread_t t, char* buf, size_t buf_size) {
  ErrnoRestorer errno_restorer;

  if (buf_size < MAX_TASK_COMM_LEN) return ERANGE;

  // Getting our own name is an easy special case.
  if (t == pthread_self()) {
    return prctl(PR_GET_NAME, buf) ? errno : 0;
  }

  // We have to get another thread's name.
  int fd = __open_task_comm_fd(t, O_RDONLY, "pthread_getname_np");
  if (fd == -1) return errno;

  ssize_t n = TEMP_FAILURE_RETRY(read(fd, buf, buf_size));
  close(fd);

  if (n == -1) return errno;

  // The kernel adds a trailing '\n' to the /proc file,
  // so this is actually the normal case for short names.
  if (n > 0 && buf[n - 1] == '\n') {
    buf[n - 1] = '\0';
    return 0;
  }

  if (n == static_cast<ssize_t>(buf_size)) return ERANGE;
  buf[n] = '\0';
  return 0;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
int pthread_setname_np(pthread_t t, const char* thread_name) {
  ErrnoRestorer errno_restorer;

  size_t thread_name_len = strlen(thread_name);
  if (thread_name_len >= MAX_TASK_COMM_LEN) return ERANGE;

  // Setting our own name is an easy special case.
  if (t == pthread_self()) {
    return prctl(PR_SET_NAME, thread_name) ? errno : 0;
  }

  // We have to set another thread's name.
  int fd = __open_task_comm_fd(t, O_WRONLY, "pthread_setname_np");
  if (fd == -1) return errno;

  ssize_t n = TEMP_FAILURE_RETRY(write(fd, thread_name, thread_name_len));
  close(fd);

  if (n == -1) return errno;
  if (n != static_cast<ssize_t>(thread_name_len)) return EIO;
  return 0;
}
```