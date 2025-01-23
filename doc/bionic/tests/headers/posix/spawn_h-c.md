Response:
Let's break down the thought process for generating the comprehensive answer about `spawn_h.c`.

**1. Understanding the Core Request:**

The primary goal is to analyze the provided C code (`spawn_h.c`) and explain its functionality within the context of Android's Bionic library. The request has several specific sub-questions to address.

**2. Initial Code Analysis (Superficial):**

The first glance reveals that `spawn_h.c` isn't doing any real work. It's primarily a header check file. This means it's designed to verify the presence and correct declaration of types, macros, and functions related to the `spawn.h` header file. The `TYPE()` and `MACRO()` indicate type and macro existence checks, while `FUNCTION()` checks function signatures.

**3. Connecting to the Bigger Picture (Android/Bionic):**

The prompt explicitly states that this is part of Android's Bionic library. This immediately tells us that the checked elements (`posix_spawn`, related types, etc.) are fundamental components for process creation and management in Android.

**4. Addressing the Sub-Questions Systematically:**

* **Functionality:**  The core functionality is header validation. The code isn't *implementing* spawning, but *verifying* the interface for spawning.

* **Relationship to Android Functionality:** `posix_spawn` and its related functions are crucial for starting new processes in Android. This is how apps and system services are launched.

* **Explanation of libc Functions:** Since this is a header check, the *implementation* details aren't directly in this file. The focus should be on what these functions *do* conceptually: `posix_spawn` creates a new process, `posix_spawn_file_actions_*` manages file descriptors for the new process, and `posix_spawnattr_*` configures the attributes of the new process.

* **Dynamic Linker Aspects:**  `posix_spawn` indirectly involves the dynamic linker. When a new process is created, the linker is responsible for loading the necessary shared libraries. I need to explain the typical SO layout and the linking process, even though this file doesn't directly demonstrate the linker's actions.

* **Logical Inference (Assumptions and Outputs):**  Since this is a header check, the "input" is the `spawn.h` header file. The "output" is either successful compilation (if the header is correct) or a compilation error.

* **Common Usage Errors:**  Think about how developers might misuse the `posix_spawn` family of functions. Incorrect file descriptor handling, improper attribute setting, and failure to handle errors are common pitfalls.

* **Android Framework/NDK Integration:**  Trace the path from the Android framework or NDK down to these low-level functions. Apps use the `ProcessBuilder` or JNI calls, which eventually lead to system calls handled by Bionic.

* **Frida Hooking:**  Demonstrate how Frida can be used to intercept calls to these functions to inspect their behavior and arguments.

**5. Structuring the Answer:**

A logical flow is important for readability. I should start with the basic function of the code, then delve into the specifics, and finally discuss the larger context and debugging techniques.

**6. Elaborating on Key Concepts (Internal Monologue/Trial-and-Error):**

* **`posix_spawn` vs. `fork`/`exec`:**  Highlight that `posix_spawn` is designed to be a more efficient alternative to the traditional `fork` followed by `exec`.

* **File Actions and Attributes:** Explain the purpose of these structures and the specific functions that manipulate them.

* **Dynamic Linking Details:**  Provide a simplified view of the dynamic linker's role: locating, loading, and resolving symbols in shared libraries. A basic SO layout example is crucial here.

* **Error Handling:** Emphasize the importance of checking return values when using these functions.

* **Frida Example:**  Create a practical Frida script that shows how to hook `posix_spawn` and log its arguments.

**7. Refining the Language and Tone:**

The answer should be clear, concise, and informative. Avoid overly technical jargon where possible, or explain it if necessary. Maintain a helpful and explanatory tone.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe I should try to explain the exact implementation of `posix_spawn`. **Correction:** This file doesn't contain the implementation. Focus on the interface and its purpose.
* **Initial thought:**  Just list the functions. **Correction:** Explain what each function *does* and *why* it's important.
* **Initial thought:**  A very detailed SO layout is needed. **Correction:** A simplified layout showing the basic components (code, data, GOT, PLT) is sufficient for this context.
* **Initial thought:**  The Frida example should be very complex. **Correction:** A simple example demonstrating the basic hooking concept is more effective.

By following these steps and continuously refining the answer, I can generate a comprehensive and accurate explanation that addresses all aspects of the user's request.
这是一个位于 Android Bionic 库中 `bionic/tests/headers/posix/spawn_h.c` 的源代码文件。它的主要功能是 **测试 `spawn.h` 头文件的正确性**。

**具体来说，这个文件的功能是：**

1. **检查类型定义 (TYPE):**  验证 `spawn.h` 中定义的类型（如 `posix_spawnattr_t`, `posix_spawn_file_actions_t`, `pid_t`, `sigset_t`, `struct sched_param*` 等）是否存在且定义正确。
2. **检查宏定义 (MACRO):** 验证 `spawn.h` 中定义的宏（如 `POSIX_SPAWN_RESETIDS`, `POSIX_SPAWN_SETPGROUP` 等）是否存在且定义正确。
3. **检查函数声明 (FUNCTION):** 验证 `spawn.h` 中声明的函数（如 `posix_spawn`, `posix_spawn_file_actions_addclose`, `posix_spawnattr_init` 等）是否存在且函数签名正确（包括参数类型和返回值类型）。

**与 Android 功能的关系：**

`spawn.h` 中定义的函数和类型是 POSIX 标准中用于创建新进程的接口。在 Android 中，这些功能被广泛用于启动新的进程，包括：

* **应用启动:** 当用户点击应用图标时，Android 系统会使用类似 `posix_spawn` 的机制来启动应用的进程。
* **服务启动:** Android 系统中的各种服务（例如系统服务、后台服务）也经常使用 `posix_spawn` 或其变体来创建新的进程。
* **native 代码中的进程创建:**  通过 NDK 开发的 native 代码可以使用 `posix_spawn` 来创建子进程。

**举例说明：**

假设一个 Android 应用需要执行一个外部命令，比如 `ping google.com`。在 native 层，开发者可能会使用 `posix_spawn` 或 `posix_spawnp` 来创建新的进程执行 `ping` 命令。

**详细解释每一个 libc 函数的功能是如何实现的：**

由于 `spawn_h.c` 是一个 **测试文件**，它本身 **不实现** 这些 libc 函数的功能。这些函数的具体实现位于 Bionic 库的其他源文件中（例如，`bionic/libc/bionic/` 目录下）。

这里我们简要解释一下每个被测试的函数的功能：

* **`posix_spawn(pid_t *restrict pid, const char *restrict path, const posix_spawn_file_actions_t *restrict file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict])`:** 这是创建新进程的主要函数。
    * `pid`: 指向一个 `pid_t` 变量的指针，新创建的进程 ID 将会被写入该变量。
    * `path`:  要执行的可执行文件的路径。
    * `file_actions`:  指向 `posix_spawn_file_actions_t` 结构的指针，用于指定子进程的文件描述符操作（例如关闭、复制、打开文件）。
    * `attrp`: 指向 `posix_spawnattr_t` 结构的指针，用于设置子进程的属性（例如进程组 ID、调度参数、信号掩码）。
    * `argv`:  传递给新进程的命令行参数数组。
    * `envp`:  传递给新进程的环境变量数组。
    * **功能:**  创建一个新的进程，执行指定的程序。相比于先 `fork` 再 `exec`，`posix_spawn` 旨在提供更高效和更简洁的进程创建方式。

* **`posix_spawn_file_actions_addclose(posix_spawn_file_actions_t *file_actions, int fildes)`:** 向 `file_actions` 结构添加一个操作，指定在子进程中关闭指定的文件描述符 `fildes`。

* **`posix_spawn_file_actions_adddup2(posix_spawn_file_actions_t *file_actions, int fildes, int newfildes)`:** 向 `file_actions` 结构添加一个操作，指定在子进程中复制文件描述符 `fildes` 到 `newfildes` (相当于 `dup2(fildes, newfildes)`）。

* **`posix_spawn_file_actions_addopen(posix_spawn_file_actions_t *restrict file_actions, int fildes, const char *restrict path, int oflag, mode_t mode)`:** 向 `file_actions` 结构添加一个操作，指定在子进程中以指定模式打开文件 `path`，并将文件描述符设置为 `fildes` (相当于 `close(fildes); open(path, oflag, mode)`）。

* **`posix_spawn_file_actions_destroy(posix_spawn_file_actions_t *file_actions)`:**  释放 `posix_spawn_file_actions_t` 结构所占用的资源。

* **`posix_spawn_file_actions_init(posix_spawn_file_actions_t *file_actions)`:** 初始化一个 `posix_spawn_file_actions_t` 结构。

* **`posix_spawnattr_destroy(posix_spawnattr_t *attr)`:** 释放 `posix_spawnattr_t` 结构所占用的资源。

* **`posix_spawnattr_getflags(const posix_spawnattr_t *restrict attr, short *restrict flags)`:** 获取 `posix_spawnattr_t` 结构中设置的标志位。

* **`posix_spawnattr_getpgroup(const posix_spawnattr_t *restrict attr, pid_t *restrict pgroup)`:** 获取 `posix_spawnattr_t` 结构中设置的进程组 ID。

* **`posix_spawnattr_getschedparam(const posix_spawnattr_t *restrict attr, struct sched_param *restrict schedparam)`:** 获取 `posix_spawnattr_t` 结构中设置的调度参数。

* **`posix_spawnattr_getschedpolicy(const posix_spawnattr_t *restrict attr, int *restrict policy)`:** 获取 `posix_spawnattr_t` 结构中设置的调度策略。

* **`posix_spawnattr_getsigdefault(const posix_spawnattr_t *restrict attr, sigset_t *restrict sigdefault)`:** 获取 `posix_spawnattr_t` 结构中设置的默认信号处理方式。

* **`posix_spawnattr_getsigmask(const posix_spawnattr_t *restrict attr, sigset_t *restrict sigmask)`:** 获取 `posix_spawnattr_t` 结构中设置的信号掩码。

* **`posix_spawnattr_init(posix_spawnattr_t *attr)`:** 初始化一个 `posix_spawnattr_t` 结构。

* **`posix_spawnattr_setflags(posix_spawnattr_t *attr, short flags)`:** 设置 `posix_spawnattr_t` 结构的标志位。常见的标志位包括：
    * `POSIX_SPAWN_RESETIDS`: 在子进程中重置有效用户 ID 和组 ID 为实际用户 ID 和组 ID。
    * `POSIX_SPAWN_SETPGROUP`: 根据 `posix_spawnattr_setpgroup` 设置的进程组 ID 设置子进程的进程组。
    * `POSIX_SPAWN_SETSCHEDPARAM`: 根据 `posix_spawnattr_setschedparam` 设置的调度参数设置子进程的调度参数。
    * `POSIX_SPAWN_SETSCHEDULER`: 使用指定的调度策略和参数。
    * `POSIX_SPAWN_SETSIGDEF`: 根据 `posix_spawnattr_setsigdefault` 设置的默认信号处理方式设置子进程的默认信号处理方式。
    * `POSIX_SPAWN_SETSIGMASK`: 根据 `posix_spawnattr_setsigmask` 设置的信号掩码设置子进程的信号掩码。

* **`posix_spawnattr_setpgroup(posix_spawnattr_t *attr, pid_t pgroup)`:** 设置 `posix_spawnattr_t` 结构的进程组 ID。

* **`posix_spawnattr_setschedparam(posix_spawnattr_t *attr, const struct sched_param *schedparam)`:** 设置 `posix_spawnattr_t` 结构的调度参数。

* **`posix_spawnattr_setsigdefault(posix_spawnattr_t *attr, const sigset_t *sigdefault)`:** 设置 `posix_spawnattr_t` 结构的默认信号处理方式。

* **`posix_spawnattr_setsigmask(posix_spawnattr_t *attr, const sigset_t *sigmask)`:** 设置 `posix_spawnattr_t` 结构的信号掩码。

* **`posix_spawnp(pid_t *restrict pid, const char *restrict file, const posix_spawn_file_actions_t *restrict file_actions, const posix_spawnattr_t *restrict attrp, char *const argv[restrict], char *const envp[restrict])`:**  与 `posix_spawn` 类似，但 `file` 参数只需要提供可执行文件的文件名，系统会在环境变量 `PATH` 指定的目录中查找该文件。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程：**

`posix_spawn` 和 `posix_spawnp` 在创建新进程时，会涉及到 dynamic linker (在 Android 中是 `linker64` 或 `linker`)。当新创建的进程启动时，dynamic linker 负责加载该进程依赖的共享库 (`.so` 文件)。

**SO 布局样本：**

```
/system/lib64/libc.so       // C 标准库
/system/lib64/libm.so        // 数学库
/system/lib64/libutils.so    // Android 常用工具库
/data/app/com.example.myapp/lib/arm64-v8a/libnative.so // 应用的 native 库
```

**链接的处理过程：**

1. **加载可执行文件:**  当 `posix_spawn` 创建新进程后，内核会将可执行文件加载到内存中。可执行文件的头部包含有关 dynamic linker 的信息。
2. **启动 dynamic linker:** 内核根据可执行文件头部的指示，启动 dynamic linker。
3. **解析依赖:** dynamic linker 解析可执行文件的 "动态链接段" (Dynamic Section)，该段包含了程序依赖的共享库列表。
4. **加载共享库:** dynamic linker 根据依赖关系，依次加载所需的共享库到内存中。加载时会检查 SO 文件的头部信息，包括其依赖的其他共享库。
5. **符号解析 (Symbol Resolution):** dynamic linker 将可执行文件和已加载的共享库中的符号（函数名、全局变量名等）进行解析。这涉及到查找函数和变量的地址，并将调用指令中的占位符替换为实际地址。
    * **Global Offset Table (GOT):** 用于存储全局变量的地址。
    * **Procedure Linkage Table (PLT):** 用于延迟绑定外部函数的地址。首次调用外部函数时，会跳转到 PLT 中的一段代码，该代码负责调用 dynamic linker 解析函数地址并更新 GOT 表项。后续调用将直接跳转到 GOT 中已解析的地址。
6. **重定位 (Relocation):**  由于共享库加载到内存的地址可能不是编译时确定的地址，dynamic linker 需要修改代码和数据段中的地址引用，使其指向正确的内存位置。

**假设输入与输出 (针对 `posix_spawn`):**

**假设输入：**

* `path`: `/system/bin/ping` (ping 命令的可执行文件路径)
* `argv`: `{"ping", "google.com", NULL}` (命令行参数)
* `envp`: `NULL` (使用默认环境变量)
* `file_actions`: `NULL` (不进行文件描述符操作)
* `attrp`: `NULL` (使用默认属性)

**逻辑推理：**

`posix_spawn` 将创建一个新的进程，执行 `/system/bin/ping` 命令，并将 `google.com` 作为参数传递给 `ping` 命令。由于 `file_actions` 和 `attrp` 为 `NULL`，子进程将继承父进程的文件描述符和大部分属性。

**输出：**

* 新进程被创建，其进程 ID 被写入 `pid` 指针指向的变量。
* 新进程执行 `ping google.com` 命令，并在标准输出打印 ping 的结果。

**用户或者编程常见的使用错误：**

* **`path` 参数错误:** 提供的可执行文件路径不存在或者没有执行权限。
* **`argv` 或 `envp` 格式错误:**  数组必须以 `NULL` 结尾。
* **文件描述符操作错误:** 在 `file_actions` 中关闭了子进程需要的标准输入、输出或错误输出，导致子进程无法正常工作。
* **属性设置错误:**  不正确地设置了进程组 ID、调度参数或信号掩码，可能导致子进程行为异常。
* **资源泄漏:**  没有正确使用 `posix_spawn_file_actions_destroy` 和 `posix_spawnattr_destroy` 释放分配的内存。
* **错误处理不当:**  没有检查 `posix_spawn` 的返回值，导致无法发现进程创建失败的情况。

**Android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `posix_spawn` 的路径：**

1. **Java 层:**  在 Android Framework 中，如果需要执行一个外部进程，通常会使用 `java.lang.ProcessBuilder` 类或 `Runtime.exec()` 方法。
2. **Native 层 (zygote):**  对于应用进程的启动，zygote 进程会接收来自 AMS (ActivityManagerService) 的请求。zygote 是 Android 系统启动的第一个用户空间进程，它预先加载了常用的库和资源，用于快速创建新的应用进程。
3. **`forkAndSpecializeCommon()` 或类似函数:** zygote 进程内部会调用类似 `forkAndSpecializeCommon()` 的 native 函数，该函数会执行 `fork()` 系统调用创建子进程，并对子进程进行特殊化处理（例如设置用户 ID、组 ID、SELinux 上下文等）。
4. **`execve()` 或 `posix_spawn()`:** 在特殊化处理完成后，zygote 子进程会调用 `execve()` 系统调用来执行目标应用的 `main` 函数，或者在某些情况下，可能会使用 `posix_spawn()`。
5. **NDK:**  对于使用 NDK 开发的 native 代码，可以直接调用 `posix_spawn` 或 `posix_spawnp` 函数。

**Frida Hook 示例：**

假设我们要 hook `posix_spawn` 函数，查看其调用的参数。

```python
import frida
import sys

# 要 hook 的进程名称或进程 ID
package_name = "com.example.myapp"

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "posix_spawn"), {
    onEnter: function(args) {
        console.log("[+] posix_spawn called");
        console.log("    pid: " + args[0]);
        console.log("    path: " + Memory.readUtf8String(args[1]));
        // 可以进一步解析 file_actions, attrp, argv, envp 等参数
    },
    onLeave: function(retval) {
        console.log("[+] posix_spawn returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()

print("[*] 正在运行，按下 Ctrl+C 停止...")
sys.stdin.read()
```

**代码解释：**

1. **`frida.attach(package_name)`:**  连接到目标 Android 应用的进程。
2. **`Module.findExportByName("libc.so", "posix_spawn")`:**  在 `libc.so` 中查找 `posix_spawn` 函数的地址。
3. **`Interceptor.attach(...)`:**  拦截 `posix_spawn` 函数的调用。
4. **`onEnter`:**  在 `posix_spawn` 函数执行之前被调用。
    * `args`:  包含了传递给 `posix_spawn` 函数的参数。
    * `Memory.readUtf8String(args[1])`: 读取 `path` 参数（指向字符串的指针）。
5. **`onLeave`:** 在 `posix_spawn` 函数执行之后被调用。
    * `retval`:  包含了 `posix_spawn` 函数的返回值。
6. **`script.load()`:** 加载并执行 Frida 脚本。

**运行此脚本，当目标应用调用 `posix_spawn` 时，Frida 会打印出相关的调用信息，例如被执行的程序路径。**

这个 `spawn_h.c` 文件虽然本身只是一个测试文件，但它指向了 Android 系统中一个非常核心的功能：进程创建。理解这些 `posix_spawn` 相关的函数对于理解 Android 系统的运行机制至关重要。

### 提示词
```
这是目录为bionic/tests/headers/posix/spawn_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
```c
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

#include <spawn.h>

#include "header_checks.h"

static void spawn_h() {
  TYPE(posix_spawnattr_t);
  TYPE(posix_spawn_file_actions_t);

  TYPE(mode_t);
  TYPE(pid_t);

  TYPE(sigset_t);

  TYPE(struct sched_param*);

  MACRO(POSIX_SPAWN_RESETIDS);
  MACRO(POSIX_SPAWN_SETPGROUP);
  MACRO(POSIX_SPAWN_SETSCHEDPARAM);
  MACRO(POSIX_SPAWN_SETSCHEDULER);
  MACRO(POSIX_SPAWN_SETSIGDEF);
  MACRO(POSIX_SPAWN_SETSIGMASK);

  FUNCTION(posix_spawn, int (*f)(pid_t*, const char*, const posix_spawn_file_actions_t*, const posix_spawnattr_t*, char* const[], char* const[]));
  FUNCTION(posix_spawn_file_actions_addclose, int (*f)(posix_spawn_file_actions_t*, int));
  FUNCTION(posix_spawn_file_actions_adddup2, int (*f)(posix_spawn_file_actions_t*, int, int));
  FUNCTION(posix_spawn_file_actions_addopen, int (*f)(posix_spawn_file_actions_t*, int, const char*, int, mode_t));
  FUNCTION(posix_spawn_file_actions_destroy, int (*f)(posix_spawn_file_actions_t*));
  FUNCTION(posix_spawn_file_actions_init, int (*f)(posix_spawn_file_actions_t*));
  FUNCTION(posix_spawnattr_destroy, int (*f)(posix_spawnattr_t*));
  FUNCTION(posix_spawnattr_getflags, int (*f)(const posix_spawnattr_t*, short*));
  FUNCTION(posix_spawnattr_getpgroup, int (*f)(const posix_spawnattr_t*, pid_t*));
  FUNCTION(posix_spawnattr_getschedparam, int (*f)(const posix_spawnattr_t*, struct sched_param*));
  FUNCTION(posix_spawnattr_getschedpolicy, int (*f)(const posix_spawnattr_t*, int*));
  FUNCTION(posix_spawnattr_getsigdefault, int (*f)(const posix_spawnattr_t*, sigset_t*));
  FUNCTION(posix_spawnattr_getsigmask, int (*f)(const posix_spawnattr_t*, sigset_t*));
  FUNCTION(posix_spawnattr_init, int (*f)(posix_spawnattr_t*));
  FUNCTION(posix_spawnattr_setflags, int (*f)(posix_spawnattr_t*, short));
  FUNCTION(posix_spawnattr_setpgroup, int (*f)(posix_spawnattr_t*, pid_t));
  FUNCTION(posix_spawnattr_setschedparam, int (*f)(posix_spawnattr_t*, const struct sched_param*));
  FUNCTION(posix_spawnattr_setsigdefault, int (*f)(posix_spawnattr_t*, const sigset_t*));
  FUNCTION(posix_spawnattr_setsigmask, int (*f)(posix_spawnattr_t*, const sigset_t*));
  FUNCTION(posix_spawnp, int (*f)(pid_t*, const char*, const posix_spawn_file_actions_t*, const posix_spawnattr_t*, char* const[], char* const[]));
}
```