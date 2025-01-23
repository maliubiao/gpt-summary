Response:
Let's break down the thought process to address the user's request.

**1. Understanding the Core Request:**

The user provided a C source file (`limits_h.c`) from Android's Bionic library and wants a comprehensive analysis of its function, its relationship to Android, implementation details (if any), dynamic linking aspects, error handling, how Android reaches this code, and a Frida hooking example. The key is to understand that this is a *test* file, not the actual implementation of `limits.h`. This drastically changes the interpretation.

**2. Initial Analysis of the Code:**

* **Includes:** `#include <limits.h>` and `#include "header_checks.h"`. This immediately suggests the file is about testing the `limits.h` header. `header_checks.h` is likely a custom header for Bionic's testing framework.
* **`static void limits_h()`:** This is the main function within the test file. It's `static`, meaning it's only visible within this compilation unit.
* **`MACRO(identifier)` and `MACRO_VALUE(identifier, value)`:** These are clearly macros used to perform checks. They likely expand to assertions or comparisons to verify that the constants defined in `limits.h` have the expected values.
* **Conditional Compilation:**  `#if !defined(__BIONIC__) ...` This is a crucial clue. It shows that the test file behaves differently depending on the target C library (Bionic, GLIBC, or musl). This suggests the test aims to verify compliance with POSIX standards or specific library behaviors.
* **List of Constants:** The code contains a long list of constants like `AIO_MAX`, `OPEN_MAX`, `PATH_MAX`, etc. These are the limits the test is checking.
* **`_POSIX_` and `_XOPEN_` prefixes:** These prefixes indicate POSIX and X/Open standards, respectively, reinforcing the idea that the test verifies standard compliance.

**3. Reframing the Task Based on the Test File Nature:**

Since it's a test file, the questions about the *implementation* of `libc` functions become less relevant. The file itself *doesn't* implement `limits.h`. Instead, it *checks* that `limits.h` defines the correct constants.

**4. Addressing Each Part of the User's Request:**

* **功能 (Functionality):** The core function is to verify the correctness of the constants defined in `limits.h`. This involves checking if the macros are defined and if they have the expected values.
* **与 Android 的关系 (Relationship to Android):**  This test ensures Bionic (Android's libc) correctly implements the `limits.h` header, which is essential for application portability and predictable behavior on Android. Examples of how these limits are used in Android apps are crucial here.
* **libc 函数的实现 (Implementation of libc functions):** This needs to be carefully explained. The test file doesn't implement libc functions. It tests the *values* of constants defined by the *actual* `limits.h`. We can briefly explain *what* `limits.h` does (defines system-wide limits) and *why* it's important.
* **Dynamic Linker 功能 (Dynamic Linker Functionality):**  This test file itself doesn't directly involve the dynamic linker. However, `limits.h` and the behavior it defines can indirectly affect dynamic linking (e.g., `PATH_MAX` for finding shared libraries). A hypothetical scenario of loading a library with a very long path could illustrate this. The SO layout and linking process description should be a general overview, not specific to this test file.
* **逻辑推理 (Logical Reasoning):**  The assumptions are that the macros `MACRO` and `MACRO_VALUE` perform comparisons. The input is the compilation environment (specifically the defined macros like `__BIONIC__`). The output is either a successful test run or a failure (though the failure mechanism isn't explicitly shown in this code snippet).
* **用户或编程常见的使用错误 (Common User/Programming Errors):** Examples of exceeding the limits defined in `limits.h` (e.g., exceeding `PATH_MAX`, `OPEN_MAX`) are relevant.
* **Android Framework/NDK 如何到达这里 (How Android Framework/NDK Reaches Here):** This requires outlining the compilation process. When an app uses functions or includes headers that rely on `limits.h`, the compiler and linker will use the Bionic's `limits.h`. The NDK provides access to these headers.
* **Frida Hook 示例 (Frida Hook Example):** A Frida example should target the *usage* of a constant from `limits.h` in a running Android process. Hooking `open` and checking the length of the path against `PATH_MAX` is a good illustration.

**5. Structuring the Answer:**

Organize the answer according to the user's original questions. Clearly separate each section and use headings. Use clear and concise language.

**6. Iterative Refinement (Self-Correction):**

* **Initial thought:**  Focus on the individual constants and their meanings.
* **Correction:**  Realize the file is a test, so the focus should be on the *testing* aspect and the role of `limits.h` in general.
* **Initial thought:** Try to explain the implementation of each limit.
* **Correction:** Explain that this file doesn't implement them, but rather checks their values. Refer to the actual `limits.h` for the definitions.
* **Initial thought:** Provide very specific dynamic linking details for this file.
* **Correction:** Offer a general overview of dynamic linking concepts and how `limits.h` can indirectly be related.

By following this thought process,  emphasizing the testing nature of the file, and addressing each part of the user's request with appropriate detail and context, we arrive at a comprehensive and accurate answer.
这是一个名为 `limits_h.c` 的 C 源代码文件，位于 Android Bionic 库的测试目录中。它的主要功能是**测试 `limits.h` 头文件中定义的常量是否符合预期**。

**功能列表:**

1. **包含头文件:** 包含 `<limits.h>` 头文件，这是 POSIX 标准定义的包含各种系统限制常量的头文件。
2. **包含测试辅助头文件:** 包含 `"header_checks.h"`，这是一个 Bionic 内部用于辅助头文件测试的头文件，可能包含 `MACRO` 和 `MACRO_VALUE` 等宏定义。
3. **定义测试函数 `limits_h()`:**  该函数是测试的核心，它没有参数，也没有返回值。
4. **使用宏 `MACRO(identifier)` 测试宏定义:**  `MACRO` 宏（在 `header_checks.h` 中定义）用于检查 `limits.h` 中定义的宏是否被定义为常量。它针对的是那些在某些 libc 实现中可能是函数而不是常量的情况。
5. **使用宏 `MACRO_VALUE(identifier, value)` 测试宏的值:** `MACRO_VALUE` 宏（也在 `header_checks.h` 中定义）用于检查 `limits.h` 中定义的宏的值是否与预期的值相等。
6. **条件编译:** 使用 `#if !defined(__BIONIC__) ...` 等预处理指令，根据不同的 C 库实现（Bionic, GLIBC, musl）跳过某些测试。这是因为不同的 C 库可能对某些限制有不同的定义或行为。

**与 Android 功能的关系及举例:**

`limits.h` 中定义的常量在 Android 系统和应用程序开发中起着至关重要的作用。它们定义了各种系统资源的上限，例如文件名长度、路径长度、可以打开的文件数量、线程数量等等。

**举例说明:**

* **`PATH_MAX`:** 定义了文件路径的最大长度。Android 应用程序在创建、访问文件时，文件路径的长度不能超过 `PATH_MAX`。如果超过，相关的系统调用（如 `open`, `stat`）可能会失败并返回 `ENAMETOOLONG` 错误。
* **`OPEN_MAX`:** 定义了一个进程可以同时打开的最大文件描述符数量。Android 应用程序如果尝试打开超过 `OPEN_MAX` 限制的文件，`open` 系统调用将会失败并返回 `EMFILE` (进程文件描述符耗尽) 或 `ENFILE` (系统文件描述符耗尽) 错误。
* **`ARG_MAX`:** 定义了执行一个新程序时，传递给 `execve` 系统调用的参数和环境变量的总大小限制。Android 系统在启动新的进程时，如果传递的参数和环境变量过大，将会导致 `execve` 失败。
* **`PTHREAD_THREADS_MAX`:** 定义了一个进程可以创建的最大线程数。Android 应用程序创建线程时，如果超过这个限制，`pthread_create` 函数将会失败。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个 `limits_h.c` 文件本身 **不实现任何 libc 函数**。它是一个 **测试文件**，用于验证 `limits.h` 中定义的宏是否正确。

`limits.h` 本身也不是一个可执行的代码文件，而是一个 **头文件**，其中包含了各种宏定义。这些宏定义的值通常在编译时由编译器根据目标平台和 C 库的配置来确定。

在 Bionic 中，`limits.h` 的实现会考虑 Android 系统的特性和限制。例如，Android 基于 Linux 内核，因此许多限制会受到 Linux 内核的限制。Bionic 的开发者需要确保 `limits.h` 中定义的常量与实际的内核限制以及 Android 系统的设计目标一致。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个 `limits_h.c` 文件本身 **不直接涉及动态链接器**。它测试的是静态定义的常量。

然而，`limits.h` 中定义的某些常量可能会间接影响动态链接的过程。例如，`PATH_MAX` 限制了动态链接器搜索共享库路径的最大长度。

**假设场景：** 动态链接器需要加载一个位于 `/very/long/path/to/a/shared/library.so` 的共享库。

**SO 布局样本:**

```
# objdump -p /system/lib64/libc.so | grep NEEDED
  NEEDED               libm.so
  NEEDED               libdl.so
  NEEDED               libvndksupport.so
```

这是一个典型的共享库 (`libc.so`) 的依赖关系示例。`NEEDED` 条目列出了 `libc.so` 运行时需要链接的其他共享库。

**链接的处理过程:**

1. **加载器启动:** 当一个程序启动时，Linux 内核会加载程序的入口点，并将控制权交给动态链接器（在 Android 上通常是 `/system/bin/linker64` 或 `/system/bin/linker`）。
2. **解析依赖关系:** 动态链接器首先解析可执行文件头部的 `PT_DYNAMIC` 段，从中找到 `DT_NEEDED` 条目，这些条目指定了程序依赖的共享库。
3. **搜索共享库:** 对于每个依赖的共享库，动态链接器会按照一定的搜索路径顺序查找共享库文件。搜索路径通常包括：
    * `LD_LIBRARY_PATH` 环境变量（不推荐在 Android 上使用）。
    * `/vendor/lib64`, `/system/vendor/lib64` 等 vendor 分区库路径。
    * `/system/lib64` 等系统库路径。
4. **加载共享库:** 一旦找到共享库文件，动态链接器会将其加载到内存中。
5. **符号解析和重定位:** 动态链接器会解析共享库中的符号表，并将程序中对共享库函数的调用地址重定向到共享库中对应的函数地址。这个过程称为符号解析和重定位。
6. **执行程序:** 当所有依赖的共享库都被加载和链接后，动态链接器会将控制权交给程序的入口点。

**与 `limits.h` 的间接关系:** 如果共享库的路径长度超过 `PATH_MAX`，动态链接器在搜索共享库时可能会遇到问题，导致加载失败。

**逻辑推理，给出假设输入与输出:**

在这个 `limits_h.c` 文件中，逻辑推理主要体现在 `MACRO` 和 `MACRO_VALUE` 宏的展开和判断上。

**假设输入:**

* 编译时定义了 `__BIONIC__` 宏。
* `limits.h` 中 `PATH_MAX` 被定义为常量 `256`。

**预期输出:**

* 对于 `#if !defined(__BIONIC__) ... MACRO(ARG_MAX); ... #endif` 这样的代码块，由于定义了 `__BIONIC__`，`MACRO(ARG_MAX)` 将不会被执行。
* 对于 `MACRO_VALUE(PATH_MAX, 256);`，`MACRO_VALUE` 宏会展开，比较 `PATH_MAX` 的值是否等于 `256`。如果相等，则测试通过；否则，测试失败。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

* **超过 `PATH_MAX`:**
   ```c
   #include <stdio.h>
   #include <unistd.h>
   #include <limits.h>
   #include <errno.h>

   int main() {
       char path[PATH_MAX * 2]; // 尝试创建一个超长的路径
       for (int i = 0; i < PATH_MAX * 2 - 1; ++i) {
           path[i] = 'a';
       }
       path[PATH_MAX * 2 - 1] = '\0';

       if (access(path, F_OK) == -1) {
           perror("access");
           if (errno == ENAMETOOLONG) {
               printf("Error: Path is too long (exceeds PATH_MAX).\n");
           }
       }
       return 0;
   }
   ```
   这段代码尝试访问一个长度超过 `PATH_MAX` 的路径，会导致 `access` 函数失败并设置 `errno` 为 `ENAMETOOLONG`。

* **超过 `OPEN_MAX`:**
   ```c
   #include <stdio.h>
   #include <stdlib.h>
   #include <fcntl.h>
   #include <unistd.h>
   #include <limits.h>
   #include <errno.h>

   int main() {
       int fds[OPEN_MAX + 1];
       for (int i = 0; i < OPEN_MAX + 1; ++i) {
           fds[i] = open("/dev/null", O_RDONLY);
           if (fds[i] == -1) {
               perror("open");
               if (errno == EMFILE || errno == ENFILE) {
                   printf("Error: Reached the maximum number of open files (OPEN_MAX).\n");
               }
               break;
           }
       }

       // 关闭打开的文件
       for (int i = 0; i < OPEN_MAX + 1; ++i) {
           if (fds[i] != -1) {
               close(fds[i]);
           }
       }
       return 0;
   }
   ```
   这段代码尝试打开超过 `OPEN_MAX` 数量的文件，会导致 `open` 函数失败并设置 `errno` 为 `EMFILE` 或 `ENFILE`。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

`limits_h.c` 是 Bionic 库的测试代码，它本身不会在 Android Framework 或 NDK 应用程序的正常运行流程中直接被执行。它的作用是在 Bionic 库的构建和测试阶段，确保 `limits.h` 的定义是正确的。

**到达 `limits.h` 的步骤（间接）：**

1. **NDK 编译应用程序:** 当使用 NDK 编译 C/C++ 代码时，编译器会包含 NDK 提供的头文件，其中包括 Bionic 的 `limits.h`。
2. **应用程序使用标准库函数:**  应用程序中如果使用了依赖于 `limits.h` 中定义的常量的标准库函数（例如 `open`, `access`, `pthread_create` 等），编译器会将这些常量的值嵌入到应用程序的代码中。
3. **Android Framework 或系统服务:** Android Framework 或系统服务本身也使用了 Bionic 提供的各种库，包括依赖于 `limits.h` 的函数。

**Frida Hook 示例调试:**

我们可以使用 Frida Hook 应用程序中使用了 `limits.h` 中定义的常量的函数，来观察其行为。例如，我们可以 Hook `open` 函数，检查传入的路径长度是否超过了 `PATH_MAX`。

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['data']))
    else:
        print(message)

package_name = "com.example.myapp"  # 替换为你的应用程序包名

try:
    device = frida.get_usb_device(timeout=10)
    session = device.attach(package_name)
except frida.InvalidArgumentError:
    print("未找到 USB 设备或应用程序未运行")
    sys.exit()

script_code = """
    const PATH_MAX = Process.constants.PATH_MAX;

    Interceptor.attach(Module.findExportByName(null, "open"), {
        onEnter: function(args) {
            const path = Memory.readUtf8String(args[0]);
            this.path = path;
            send({ tag: "open", data: "Opening path: " + path });
            send({ tag: "open", data: "PATH_MAX: " + PATH_MAX });
            if (path.length > PATH_MAX) {
                send({ tag: "open", data: "Warning: Path length exceeds PATH_MAX!" });
            }
        },
        onLeave: function(retval) {
            send({ tag: "open", data: "open returned: " + retval });
        }
    });
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**示例解释:**

1. **获取 `PATH_MAX`:** 使用 `Process.constants.PATH_MAX` 获取当前进程的 `PATH_MAX` 值。
2. **Hook `open` 函数:** 使用 `Interceptor.attach` Hook `open` 函数。
3. **`onEnter`:** 在 `open` 函数调用之前执行，读取传入的路径参数，并与 `PATH_MAX` 进行比较。
4. **`onLeave`:** 在 `open` 函数返回之后执行，打印返回值。
5. **发送消息:** 使用 `send` 函数将信息发送回 Python 脚本。

**运行这个 Frida 脚本，并操作目标 Android 应用程序，如果应用程序尝试打开路径长度超过 `PATH_MAX` 的文件，你将在 Frida 的输出中看到相应的警告信息。**

总而言之，`limits_h.c` 是 Bionic 库的内部测试代码，用于确保 `limits.h` 中定义的系统限制常量是正确的。这些常量在 Android 系统和应用程序开发中至关重要，影响着文件操作、进程管理、线程管理等多个方面。虽然 `limits_h.c` 不会被直接执行，但它保证了 NDK 编译出的应用程序以及 Android Framework 自身的稳定性和一致性。

### 提示词
```
这是目录为bionic/tests/headers/posix/limits_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <limits.h>

#include "header_checks.h"

static void limits_h() {
  // These are only defined if they're constants.
#if !defined(__BIONIC__) && !defined(__GLIBC__) && !defined(ANDROID_HOST_MUSL)
  MACRO(AIO_LISTIO_MAX);
  MACRO(AIO_MAX);
#endif
#if !defined(__BIONIC__) && !defined(ANDROID_HOST_MUSL)
  MACRO(AIO_PRIO_DELTA_MAX);
#endif
#if !defined(__BIONIC__) && !defined(__GLIBC__)
  MACRO(ARG_MAX);
#endif
#if !defined(__BIONIC__) && !defined(__GLIBC__) && !defined(ANDROID_HOST_MUSL)
  MACRO(ATEXIT_MAX);
  MACRO(CHILD_MAX);
#endif
#if !defined(__BIONIC__)
  MACRO(DELAYTIMER_MAX);
#endif
  MACRO(HOST_NAME_MAX);
  MACRO(IOV_MAX);
  MACRO(LOGIN_NAME_MAX);
#if !defined(__BIONIC__) && !defined(__GLIBC__) && !defined(ANDROID_HOST_MUSL)
  MACRO(MQ_OPEN_MAX);
#endif
#if !defined(__BIONIC__)
  MACRO(MQ_PRIO_MAX);
#endif
#if !defined(__BIONIC__) && !defined(__GLIBC__) && !defined(ANDROID_HOST_MUSL)
  MACRO(OPEN_MAX);
#endif
#if !defined(__BIONIC__) && !defined(__GLIBC__)
  MACRO(PAGESIZE);
  MACRO(PAGE_SIZE);
#endif
  MACRO(PTHREAD_DESTRUCTOR_ITERATIONS);
  MACRO(PTHREAD_KEYS_MAX);
#if !defined(__BIONIC__)
  MACRO(PTHREAD_STACK_MIN);
#endif
#if !defined(__BIONIC__) && !defined(__GLIBC__) && !defined(ANDROID_HOST_MUSL)
  MACRO(PTHREAD_THREADS_MAX);
#endif
#if !defined(ANDROID_HOST_MUSL)
  MACRO(RTSIG_MAX);
#endif
#if !defined(__BIONIC__) && !defined(__GLIBC__)
  MACRO(SEM_NSEMS_MAX);
#endif
  MACRO(SEM_VALUE_MAX);
#if !defined(__BIONIC__) && !defined(__GLIBC__) && !defined(ANDROID_HOST_MUSL)
  MACRO(SIGQUEUE_MAX);
  MACRO(SS_REPL_MAX);
  MACRO(STREAM_MAX);
#endif
#if !defined(__BIONIC__) && !defined(__GLIBC__)
  MACRO(SYMLOOP_MAX);
#endif
#if !defined(__BIONIC__) && !defined(__GLIBC__) && !defined(ANDROID_HOST_MUSL)
  MACRO(TIMER_MAX);
#endif
#if !defined(__BIONIC__)
  MACRO(TTY_NAME_MAX);
#endif
#if !defined(__BIONIC__) && !defined(__GLIBC__)
  MACRO(TZNAME_MAX);
#endif

#if !defined(__BIONIC__) && !defined(__GLIBC__)
  MACRO(FILESIZEBITS);
#endif
#if !defined(__BIONIC__) && !defined(__GLIBC__) && !defined(ANDROID_HOST_MUSL)
  MACRO(LINK_MAX);
#endif
#if !defined(ANDROID_HOST_MUSL)
  MACRO(MAX_CANON);
  MACRO(MAX_INPUT);
#endif
  MACRO(NAME_MAX);
  MACRO(PATH_MAX);
  MACRO(PIPE_BUF);
#if 0 // No libc has these.
  MACRO(POSIX_ALLOC_SIZE_MIN);
  MACRO(POSIX_REC_INCR_XFER_SIZE);
  MACRO(POSIX_REC_MAX_XFER_SIZE);
  MACRO(POSIX_REC_MIN_XFER_SIZE);
  MACRO(POSIX_REC_XFER_ALIGN);
#endif
#if !defined(__BIONIC__) && !defined(__GLIBC__) && !defined(ANDROID_HOST_MUSL)
  MACRO(SYMLINK_MAX);
#endif

#if !defined(__BIONIC__)
  MACRO(BC_BASE_MAX);
  MACRO(BC_DIM_MAX);
  MACRO(BC_SCALE_MAX);
  MACRO(BC_STRING_MAX);
  MACRO(CHARCLASS_NAME_MAX);
  MACRO(COLL_WEIGHTS_MAX);
  MACRO(EXPR_NEST_MAX);
  MACRO(NGROUPS_MAX);
  MACRO(RE_DUP_MAX);
#endif
  MACRO(LINE_MAX);

  MACRO_VALUE(_POSIX_CLOCKRES_MIN, 20000000);

  MACRO_VALUE(_POSIX_AIO_LISTIO_MAX, 2);
  MACRO_VALUE(_POSIX_AIO_MAX, 1);
  MACRO_VALUE(_POSIX_ARG_MAX, 4096);
  MACRO_VALUE(_POSIX_CHILD_MAX, 25);
  MACRO_VALUE(_POSIX_DELAYTIMER_MAX, 32);
  MACRO_VALUE(_POSIX_HOST_NAME_MAX, 255);
  MACRO_VALUE(_POSIX_LINK_MAX, 8);
  MACRO_VALUE(_POSIX_LOGIN_NAME_MAX, 9);
  MACRO_VALUE(_POSIX_MAX_CANON, 255);
  MACRO_VALUE(_POSIX_MAX_INPUT, 255);
  MACRO_VALUE(_POSIX_MQ_OPEN_MAX, 8);
  MACRO_VALUE(_POSIX_MQ_PRIO_MAX, 32);
  MACRO_VALUE(_POSIX_NAME_MAX, 14);
  MACRO_VALUE(_POSIX_NGROUPS_MAX, 8);
  MACRO_VALUE(_POSIX_OPEN_MAX, 20);
  MACRO_VALUE(_POSIX_PATH_MAX, 256);
  MACRO_VALUE(_POSIX_PIPE_BUF, 512);
  MACRO_VALUE(_POSIX_RE_DUP_MAX, 255);
  MACRO_VALUE(_POSIX_RTSIG_MAX, 8);
  MACRO_VALUE(_POSIX_SEM_NSEMS_MAX, 256);
  MACRO_VALUE(_POSIX_SEM_VALUE_MAX, 32767);
  MACRO_VALUE(_POSIX_SIGQUEUE_MAX, 32);
  MACRO_VALUE(_POSIX_SSIZE_MAX, 32767);
#if !defined(__GLIBC__)
  MACRO_VALUE(_POSIX_SS_REPL_MAX, 4);
#endif
  MACRO_VALUE(_POSIX_STREAM_MAX, 8);
  MACRO_VALUE(_POSIX_SYMLINK_MAX, 255);
  MACRO_VALUE(_POSIX_SYMLOOP_MAX, 8);
  MACRO_VALUE(_POSIX_THREAD_DESTRUCTOR_ITERATIONS, 4);
  MACRO_VALUE(_POSIX_THREAD_KEYS_MAX, 128);
  MACRO_VALUE(_POSIX_THREAD_THREADS_MAX, 64);
  MACRO_VALUE(_POSIX_TIMER_MAX, 32);
#if !defined(__GLIBC__)
  MACRO_VALUE(_POSIX_TRACE_EVENT_NAME_MAX, 30);
  MACRO_VALUE(_POSIX_TRACE_NAME_MAX, 8);
  MACRO_VALUE(_POSIX_TRACE_SYS_MAX, 8);
  MACRO_VALUE(_POSIX_TRACE_USER_EVENT_MAX, 32);
#endif
  MACRO_VALUE(_POSIX_TTY_NAME_MAX, 9);
  MACRO_VALUE(_POSIX_TZNAME_MAX, 6);
  MACRO_VALUE(_POSIX2_BC_BASE_MAX, 99);
  MACRO_VALUE(_POSIX2_BC_DIM_MAX, 2048);
  MACRO_VALUE(_POSIX2_BC_SCALE_MAX, 99);
  MACRO_VALUE(_POSIX2_BC_STRING_MAX, 1000);
  MACRO_VALUE(_POSIX2_CHARCLASS_NAME_MAX, 14);
  MACRO_VALUE(_POSIX2_COLL_WEIGHTS_MAX, 2);
  MACRO_VALUE(_POSIX2_EXPR_NEST_MAX, 32);
  MACRO_VALUE(_POSIX2_LINE_MAX, 2048);
  MACRO_VALUE(_POSIX2_RE_DUP_MAX, 255);
#if !defined(__GLIBC__)
  MACRO_VALUE(_XOPEN_IOV_MAX, 16);
  MACRO_VALUE(_XOPEN_NAME_MAX, 255);
  MACRO_VALUE(_XOPEN_PATH_MAX, 1024);
#endif

  MACRO_VALUE(CHAR_BIT, 8);
  MACRO(CHAR_MAX);
  MACRO(CHAR_MIN);
  MACRO(INT_MAX);
  MACRO(INT_MIN);
  MACRO(LLONG_MAX);
  MACRO(LLONG_MIN);
  MACRO(LONG_BIT);
  MACRO(LONG_MAX);
  MACRO(LONG_MIN);
  MACRO(MB_LEN_MAX);
  MACRO_VALUE(SCHAR_MAX, 127);
  MACRO_VALUE(SCHAR_MIN, -128);
  MACRO(SHRT_MAX);
  MACRO(SHRT_MIN);
  MACRO(SSIZE_MAX);
  MACRO_VALUE(UCHAR_MAX, 255);
  MACRO(UINT_MAX);
  MACRO(ULLONG_MAX);
  MACRO(ULONG_MAX);
  MACRO(USHRT_MAX);
  MACRO(WORD_BIT);

  MACRO(NL_ARGMAX);
  MACRO(NL_LANGMAX);
  MACRO(NL_MSGMAX);
  MACRO(NL_SETMAX);
  MACRO(NL_TEXTMAX);
  MACRO(NZERO);
}
```