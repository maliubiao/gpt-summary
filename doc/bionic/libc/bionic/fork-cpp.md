Response:
Let's break down the thought process to generate the comprehensive answer about `bionic/libc/bionic/fork.cpp`.

**1. Understanding the Core Request:**

The request asks for a deep dive into the functionality of the `fork.cpp` file in Android's Bionic library. It wants to understand its purpose, how it relates to Android, the implementation details of the C library functions involved, its interaction with the dynamic linker (if any), potential errors, and how it's used within the Android framework and NDK. It also requests a Frida hook example.

**2. Initial Analysis of the Code:**

The first step is to carefully read and understand the provided C++ code. Key observations:

* **Includes:**  The file includes `unistd.h`, `android/fdsan.h`, and some internal Bionic headers (`private/bionic_defs.h`, `private/bionic_fdtrack.h`, `pthread_internal.h`). This hints at the core functionality and potential interactions with file descriptor management and threads.
* **`__clone_for_fork()`:** This function uses the `clone()` system call. The flags `CLONE_CHILD_SETTID`, `CLONE_CHILD_CLEARTID`, and `SIGCHLD` are crucial for understanding how the child process is created and how its termination is signaled. It also interacts with the `pthread_internal_t` structure, suggesting thread-related operations.
* **`_Fork()`:** This is a simple wrapper around `__clone_for_fork()`. This might be for internal Bionic organization or potentially for future modifications.
* **`fork()`:** This is the publicly exposed function. It calls `__bionic_atfork_run_prepare()`, then `_Fork()`, and then different code blocks based on whether it's the parent or child process (indicated by `result == 0`). It also interacts with `android_fdsan_set_error_level()`, `android_fdtrack_set_globally_enabled()`, and `__set_stack_and_tls_vma_name()`. Finally, it calls `__bionic_atfork_run_child()` or `__bionic_atfork_run_parent()`.

**3. Deconstructing the Request – Identifying Key Areas:**

Based on the code and the request, I identified the following areas to focus on:

* **Functionality:** What does this file *do*? The name "fork.cpp" is a strong clue.
* **Android Relevance:** How does `fork()` relate to Android's process model?
* **Libc Function Details:**  What exactly do `clone()`, `gettid()`, and the `__bionic_atfork_*` functions do?
* **Dynamic Linker:**  Is the dynamic linker involved?  If so, how? (Initial analysis suggests minimal direct involvement in *this specific file*, but the `fork()` call itself is a fundamental building block for process creation, which can indirectly lead to dynamic linking in the child process.)
* **Logic and Assumptions:**  Are there any implicit assumptions or logical flows?
* **Common Errors:** What mistakes do developers often make when using `fork()`?
* **Android Framework/NDK Path:** How does a call to `fork()` get initiated from higher levels?
* **Frida Hook:** How can we observe the behavior of `fork()` using Frida?

**4. Answering Each Key Area Systematically:**

* **Functionality:**  Start with the most obvious – the file implements the `fork()` system call, allowing for process creation. Then delve into the slightly more nuanced aspect of using `clone()` internally.

* **Android Relevance:** Explain how `fork()` is crucial for multi-process architectures, allowing applications to create new processes. Give concrete examples, like app sandboxing or service creation.

* **Libc Function Details:**
    * **`fork()`:** Explain its general purpose.
    * **`clone()`:** Emphasize its flexibility and the specific flags used in `__clone_for_fork()`. Explain the purpose of each flag (`CLONE_CHILD_SETTID`, `CLONE_CHILD_CLEARTID`, `SIGCHLD`).
    * **`gettid()`:** Explain its purpose in retrieving the thread ID.
    * **`__bionic_atfork_*()`:** Explain that these are callbacks for handling forking safely, particularly regarding locks.
    * **`android_fdsan_*()`:** Explain the purpose of file descriptor sanitization.
    * **`android_fdtrack_*()`:** Explain the purpose of file descriptor tracking.
    * **`__set_stack_and_tls_vma_name()`:** Explain its purpose in process identification.

* **Dynamic Linker:**  Acknowledge that this *specific file* doesn't directly involve the dynamic linker. However, explain that `fork()` creates a new process, which *will* often involve the dynamic linker to load libraries. Provide a basic example of a shared library layout and explain the linking process. It's important to distinguish between the *forking* process itself and the subsequent actions in the *child* process, which may involve the linker.

* **Logic and Assumptions:** Explain the parent/child process distinction and how the return value of `fork()` distinguishes them.

* **Common Errors:**  Focus on resource leaks (file descriptors, memory) and unsafe operations in forked processes, especially concerning threads and mutexes.

* **Android Framework/NDK Path:**  Start from a high-level example (Java `ProcessBuilder`, NDK `fork()`), and trace the call down to the Bionic `fork()`. This involves understanding the Java Native Interface (JNI) for NDK calls.

* **Frida Hook:**  Provide a concrete Frida script that intercepts the `fork()` function, logs arguments and the return value, and demonstrates how to differentiate between parent and child processes.

**5. Structuring the Answer:**

Organize the information logically with clear headings and subheadings. Use bullet points for lists of features and explanations. Provide code examples where relevant (Frida hook, SO layout).

**6. Refinement and Review:**

After drafting the answer, review it for clarity, accuracy, and completeness. Ensure that all parts of the original request have been addressed. Double-check technical details and code examples. Make sure the language is clear and easy to understand. For instance, initially, I might have overemphasized the direct involvement of the dynamic linker in the `fork()` *function itself*. Reviewing helps to clarify that the linker's role is subsequent in the *child process*.

By following this structured thought process, starting with code analysis and progressively addressing each aspect of the request, a comprehensive and accurate answer can be generated. The key is to break down the complex request into manageable parts and tackle each part methodically.
好的，让我们详细分析一下 `bionic/libc/bionic/fork.cpp` 这个文件。

**功能列举:**

`fork.cpp` 文件的核心功能是实现了 `fork()` 系统调用，这个调用用于创建一个新的进程，它是当前进程的精确副本。更具体地说，这个文件实现了以下功能：

1. **`fork()` 系统调用的封装:**  它提供了标准 C 库函数 `fork()` 的实现。
2. **内部使用 `clone()` 系统调用:**  在 Bionic 中，`fork()` 的实现实际上是基于更底层的 `clone()` 系统调用。`clone()` 提供了更细粒度的进程创建控制。
3. **`atfork` 处理:** 实现了在 `fork()` 调用前后执行用户注册的处理程序 (`__bionic_atfork_run_prepare`, `__bionic_atfork_run_parent`, `__bionic_atfork_run_child`)，这对于确保多线程程序在 `fork()` 后的状态一致性至关重要，特别是在处理锁的时候。
4. **文件描述符管理 (fdsan 和 fdtrack):**  在子进程中禁用 `fdsan` (file descriptor sanitizer) 和 `fdtrack` (file descriptor tracking)。这是为了避免在子进程关闭父进程继承来的所有文件描述符后，错误地触发相关的错误检测。
5. **栈和 TLS VMA 名称重置:** 在子进程中，重置栈和线程本地存储 (TLS) 的虚拟内存区域 (VMA) 名称，以去除父进程的线程 ID 信息，使其更具通用性。

**与 Android 功能的关系及举例:**

`fork()` 是 Unix-like 系统中创建新进程的基础，在 Android 中扮演着至关重要的角色。以下是一些例子：

* **应用进程创建:** 当 Android 系统启动一个新的应用程序时，通常会使用 `fork()` (或其变种，如 `zygote` 的 `forkAndSpecialize`) 从一个已存在的进程（如 `zygote`）复制出一个新的进程来运行应用程序的代码。这实现了进程隔离，确保一个应用的崩溃不会影响到其他应用或系统。
    * **例子:**  当你点击一个应用图标启动它时，系统可能会执行类似的操作：`zygote` 进程调用 `fork()` 创建一个子进程，然后在这个子进程中加载并运行应用的 Dalvik/ART 虚拟机实例。
* **服务进程创建:** Android 的各种系统服务也经常通过 `fork()` 创建独立的进程运行，例如 `system_server` 会 `fork()` 出各种子服务进程。
    * **例子:**  `system_server` 可能会 `fork()` 一个新的进程来处理蓝牙相关的操作，或者处理网络连接。
* **NDK 开发:** 使用 NDK 进行原生开发的应用程序可以直接调用 `fork()` 来创建新的进程。
    * **例子:**  一个游戏引擎可以使用 `fork()` 创建一个独立的进程来执行一些后台计算任务，避免阻塞主渲染线程。

**Libc 函数的实现细节:**

1. **`fork()`:**
   - 首先调用 `__bionic_atfork_run_prepare()`。这个函数会遍历所有通过 `pthread_atfork()` 注册的 prepare 处理程序，这些处理程序通常用于在 `fork()` 前获取所有可能被父子进程共享的互斥锁，以防止死锁。
   - 接着调用 `_Fork()`，而 `_Fork()` 实际上是调用 `__clone_for_fork()`。
   - `__clone_for_fork()` 函数使用 `clone()` 系统调用创建子进程。
     - `clone(nullptr, nullptr, (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD), nullptr, nullptr, nullptr, &(self->tid))`
     - `nullptr, nullptr`:  指定子进程的栈顶指针和 TLS (Thread Local Storage)，这里使用 `nullptr` 表示使用默认值。
     - `CLONE_CHILD_SETTID`:  将子进程的线程 ID (TID) 写入到父进程的 `self->tid` 指向的内存位置。
     - `CLONE_CHILD_CLEARTID`: 当子进程终止时，内核会将子进程的 TID 写入到这个地址，并且发送一个信号 (通常是 SIGCHLD)。
     - `SIGCHLD`:  当子进程终止时，向父进程发送 `SIGCHLD` 信号。
     - `&(self->tid)`: 指向父进程中用于存储子进程 TID 的内存地址。
   - `clone()` 的返回值：
     - 在父进程中，返回子进程的进程 ID (PID)。
     - 在子进程中，返回 0。
     - 如果出错，返回 -1。
   - 如果 `_Fork()` 返回 0 (表示当前是子进程):
     - `android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_DISABLED)`: 禁用文件描述符 Sanitizer，防止子进程关闭继承的文件描述符时触发错误。
     - `android_fdtrack_set_globally_enabled(false)`: 禁用全局文件描述符跟踪。
     - `__set_stack_and_tls_vma_name(true)`:  设置子进程栈和 TLS 的 VMA 名称，使其不再包含父进程的 TID。
     - `__bionic_atfork_run_child()`:  运行所有通过 `pthread_atfork()` 注册的 child 处理程序，这些处理程序通常用于在子进程中释放之前在 prepare 阶段获取的锁。
   - 如果 `_Fork()` 返回非零值 (表示当前是父进程):
     - `__bionic_atfork_run_parent()`: 运行所有通过 `pthread_atfork()` 注册的 parent 处理程序。
   - 最后返回 `_Fork()` 的结果。

2. **`__clone_for_fork()`:**
   - 获取当前线程的内部结构 `pthread_internal_t* self = __get_thread();`。
   - 调用 `clone()` 系统调用，如上所述。
   - 如果 `clone()` 成功返回 0 (表示当前是子进程)，则更新子进程缓存的 PID：`self->set_cached_pid(gettid());`。因为 `clone()` 不会直接设置子进程的 `self->tid`，这个值是由内核更新的。

3. **`gettid()`:**
   - `gettid()` 是一个系统调用，用于获取当前线程的线程 ID。在子进程中调用 `gettid()` 可以获取到子进程的线程 ID，这个 ID 与父进程的线程 ID 不同。

**涉及 Dynamic Linker 的功能:**

在这个 `fork.cpp` 文件中，并没有直接涉及到 dynamic linker 的代码。`fork()` 的主要作用是创建新的进程，而 dynamic linker (例如 `linker64` 或 `linker`) 的作用是在进程启动时加载所需的共享库 (`.so` 文件) 并解析符号引用。

然而，`fork()` 创建的子进程通常会需要加载相同的共享库，因此 dynamic linker 在子进程的启动过程中扮演着重要的角色。

**SO 布局样本和链接处理过程 (在子进程中):**

假设一个应用进程加载了 `libfoo.so` 和 `libbar.so` 两个共享库。

**SO 布局样本 (内存地址是示意性的):**

```
          +-----------------------+
0x700000  | 可执行文件 (e.g., app_process64) |
          +-----------------------+
          | ...                   |
          +-----------------------+
0x710000  | libutils.so           |  // 系统库，可能被多个 SO 依赖
          +-----------------------+
          | ...                   |
          +-----------------------+
0x720000  | libfoo.so             |
          +-----------------------+
          | .text (代码段)         |
          +-----------------------+
          | .data (已初始化数据段)   |
          +-----------------------+
          | .bss (未初始化数据段)    |
          +-----------------------+
          | .plt/.got (用于动态链接) |
          +-----------------------+
0x730000  | libbar.so             |
          +-----------------------+
          | ...                   |
          +-----------------------+
  堆区 (Heap)
          +-----------------------+
  栈区 (Stack)
          +-----------------------+
```

**链接的处理过程 (在子进程中):**

1. **`fork()` 调用:** 父进程调用 `fork()` 创建子进程。子进程继承了父进程的内存映像，包括已经加载的共享库。
2. **子进程启动:** 子进程从 `fork()` 返回后开始执行。
3. **动态链接器的介入:**  子进程可能需要执行一些清理和重新映射操作，特别是涉及到地址空间布局随机化 (ASLR) 的情况下。动态链接器会检查是否有未完成的链接工作。
4. **重定位:**  由于 ASLR 的存在，共享库在每次加载时的基地址可能不同。动态链接器会遍历 `.rel.dyn` 或 `.rela.dyn` 段，这些段包含了需要重定位的信息。动态链接器会根据实际的加载地址更新全局偏移量表 (GOT) 和程序链接表 (PLT) 中的地址。
5. **符号解析:** 如果子进程的代码尝试调用共享库中的函数，并且这些函数是通过动态链接引用的，那么动态链接器会确保这些符号被正确解析，指向共享库中相应的函数地址。这通常发生在首次调用这些函数时 (延迟绑定)。

**假设输入与输出 (逻辑推理):**

* **假设输入:**
    - 父进程 PID: 1000
    - 父进程线程 ID: 1000
    - 父进程调用 `fork()`

* **输出:**
    - **父进程:**
        - `fork()` 返回值: 大于 0 的整数，例如 1001 (子进程的 PID)
    - **子进程:**
        - `fork()` 返回值: 0
        - 子进程 PID: 1001
        - 子进程线程 ID:  一个新的 ID，例如 1001 (通常与进程 ID 相同，但可以不同)

**用户或编程常见的使用错误:**

1. **忘记处理 `fork()` 的返回值:**  开发者必须检查 `fork()` 的返回值来区分父进程和子进程，并执行相应的逻辑。
   ```c
   pid_t pid = fork();
   if (pid == -1) {
       // 错误处理
       perror("fork");
       exit(EXIT_FAILURE);
   } else if (pid == 0) {
       // 子进程代码
       printf("我是子进程，我的 PID 是 %d\n", getpid());
       exit(EXIT_SUCCESS); // 子进程通常需要调用 exit 或 exec
   } else {
       // 父进程代码
       printf("我是父进程，我的 PID 是 %d，子进程的 PID 是 %d\n", getpid(), pid);
       wait(NULL); // 父进程通常需要等待子进程结束
   }
   ```
2. **在 `fork()` 后父子进程都修改共享资源而没有适当的同步机制:**  这可能导致数据竞争和未定义的行为。应该使用互斥锁、信号量等同步原语来保护共享资源。
3. **文件描述符泄露:**  子进程继承了父进程打开的文件描述符。如果子进程不再需要这些文件描述符，应该及时关闭，否则可能导致资源泄露。
4. **在多线程程序中使用 `fork()` 而没有正确处理锁:**  如果父进程在持有锁的状态下 `fork()`，子进程可能会继承这个锁的状态，导致死锁。`pthread_atfork()` 提供了一种机制来处理这种情况，但开发者需要正确使用。
5. **在子进程中不调用 `exec` 或 `exit`:**  如果子进程不执行新的程序 (`exec`) 或退出 (`exit`)，它将继续执行父进程的代码，这通常不是期望的行为。

**Android Framework 或 NDK 如何到达这里:**

1. **Java 代码 (Android Framework):**
   - 在 Android Framework 中，如果需要创建一个新的进程，通常会使用 `ProcessBuilder` 类或者 `ActivityManagerService` 等系统服务提供的接口。
   - 例如，启动一个新的 Activity 或 Service 可能会触发进程创建。
   - 这些高层 API 最终会调用到 Native 代码。

2. **Native 代码 (NDK 或 Framework Native 层):**
   - 在 NDK 中，开发者可以直接调用 `fork()` 函数（实际上会链接到 Bionic 的 `fork()` 实现）。
   - 在 Android Framework 的 Native 层，例如 `app_process` 或 `system_server` 的代码中，也会直接调用 `fork()` 或其变种（如 `zygote` 的 `forkAndSpecialize`，其内部也基于 `clone`）。

**具体步骤示例 (Framework -> Bionic):**

假设一个应用调用 `startActivity()` 启动一个新的 Activity。

1. **`ActivityManagerService` (Java):** 接收到启动 Activity 的请求。
2. **`ActivityManagerService` (Java):**  决定需要创建一个新的进程来运行该 Activity。
3. **`ActivityManagerService` (Java):**  可能会调用 `Process.start()` 或类似的函数，最终会调用到 Native 方法。
4. **`Runtime.exec()` 或相关 Native 方法 (Java -> JNI):** Java 代码通过 JNI (Java Native Interface) 调用到 Android 运行时的 Native 代码。
5. **`Process.java` (Java):**  内部可能使用 `Runtime.getRuntime().exec()` 来执行一个可执行文件，或者更直接地通过系统调用创建进程。
6. **`android_os_Process.cpp` (Native Framework):**  在 Android 运行时的 Native 层，可能会有代码处理进程创建，最终会调用到 Bionic 的 `fork()`。
7. **`fork()` in `bionic/libc/bionic/fork.cpp`:**  执行 Bionic 库中的 `fork()` 函数，创建新的进程。

**Frida Hook 示例调试步骤:**

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你要调试的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"找不到进程: {package_name}")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "fork"), {
    onEnter: function(args) {
        console.log("[+] fork() called");
        console.log("    Thread ID:", Process.getCurrentThreadId());
        console.log("    Process ID:", Process.getCurrentProcessId());
        this.startTime = Date.now();
    },
    onLeave: function(retval) {
        var endTime = Date.now();
        console.log("[+] fork() returned:", retval.toInt());
        console.log("    Execution time:", endTime - this.startTime, "ms");
        if (retval.toInt() === 0) {
            console.log("    [Child Process]");
            console.log("    Child Process ID:", Process.getCurrentProcessId());
            console.log("    Child Thread ID:", Process.getCurrentThreadId());
        } else if (retval.toInt() > 0) {
            console.log("    [Parent Process]");
            console.log("    Child PID:", retval.toInt());
        } else {
            console.log("    [Error]");
        }
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

print(f"[*] 正在 Hook 进程: {package_name}，请触发 fork() 调用...")
sys.stdin.read()
session.detach()
```

**Frida Hook 示例解释:**

1. **导入库:** 导入 `frida` 和 `sys` 库。
2. **定义 `on_message` 函数:**  处理 Frida 脚本发送的消息。
3. **连接到目标进程:** 使用 `frida.get_usb_device().attach(package_name)` 连接到指定包名的应用进程。
4. **Frida 脚本代码:**
   - `Interceptor.attach(Module.findExportByName("libc.so", "fork"), ...)`:  拦截 `libc.so` 中的 `fork` 函数。
   - `onEnter`:  在 `fork` 函数调用前执行。
     - 打印 "fork() called"。
     - 打印当前线程 ID 和进程 ID。
     - 记录开始时间。
   - `onLeave`: 在 `fork` 函数返回后执行。
     - 记录结束时间并计算执行时间。
     - 打印 "fork() returned" 以及返回值。
     - 根据返回值判断是父进程、子进程还是发生错误，并打印相应的消息和 PID/TID。
5. **创建并加载脚本:**  `session.create_script(script_code)` 创建脚本，`script.on('message', on_message)` 设置消息处理函数，`script.load()` 加载脚本。
6. **等待用户输入:**  `sys.stdin.read()` 让脚本保持运行状态，直到用户按下 Ctrl+C。
7. **分离会话:** `session.detach()` 在脚本结束时分离 Frida 会话。

**使用步骤:**

1. 确保你的 Android 设备已连接并通过 ADB 授权。
2. 安装 Frida 和 frida-tools (`pip install frida-tools`).
3. 替换 `package_name` 为你要调试的 Android 应用的包名。
4. 运行 Python 脚本。
5. 在你的 Android 设备上操作该应用，触发 `fork()` 调用（例如，启动新的 Activity、Service 或应用本身在某些情况下会 fork 出进程）。
6. 查看 Frida 输出，你会看到 `fork()` 函数被调用和返回的信息，包括父进程和子进程的 PID 和 TID。

通过以上分析，你应该对 `bionic/libc/bionic/fork.cpp` 文件的功能、实现细节、与 Android 的关系以及如何进行调试有了更深入的了解。

### 提示词
```
这是目录为bionic/libc/bionic/fork.cppandroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <unistd.h>

#include <android/fdsan.h>

#include "private/bionic_defs.h"
#include "private/bionic_fdtrack.h"
#include "pthread_internal.h"

__BIONIC_WEAK_FOR_NATIVE_BRIDGE_INLINE
int __clone_for_fork() {
  pthread_internal_t* self = __get_thread();

  int result = clone(nullptr, nullptr, (CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD),
                     nullptr, nullptr, nullptr, &(self->tid));

  if (result == 0) {
    // Update the cached pid in child, since clone() will not set it directly (as
    // self->tid is updated by the kernel).
    self->set_cached_pid(gettid());
  }

  return result;
}

int _Fork() {
  return __clone_for_fork();
}

int fork() {
  __bionic_atfork_run_prepare();
  int result = _Fork();
  if (result == 0) {
    // Disable fdsan and fdtrack post-fork, so we don't falsely trigger on processes that
    // fork, close all of their fds, and then exec.
    android_fdsan_set_error_level(ANDROID_FDSAN_ERROR_LEVEL_DISABLED);
    android_fdtrack_set_globally_enabled(false);

    // Reset the stack_and_tls VMA name so it doesn't end with a tid from the
    // parent process.
    __set_stack_and_tls_vma_name(true);

    __bionic_atfork_run_child();
  } else {
    __bionic_atfork_run_parent();
  }
  return result;
}
```