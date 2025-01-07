Response:
Let's break down the thought process for answering the user's request about `unistd_h.c`.

**1. Understanding the Core Question:**

The user provided a source file (`unistd_h.c`) from Android's Bionic library and wants to know its purpose and how it relates to Android. The key here is recognizing that this isn't the *implementation* of `unistd.h` but a *test file* for it.

**2. Identifying the File's Function:**

The code primarily consists of `MACRO()` and `FUNCTION()` calls. Looking at the content, it's clear this code isn't doing any actual work like reading/writing files. The `header_checks.h` include suggests it's verifying the presence and signatures of macros, types, and functions declared in `unistd.h`. Therefore, the core function is **header checking/validation**.

**3. Relating to Android:**

Bionic is Android's C library. `unistd.h` is a standard POSIX header, and Android needs to provide these standard interfaces. This test file ensures that Bionic's `unistd.h` correctly defines the expected symbols. This is crucial for application compatibility. If an NDK app relies on a specific POSIX function or macro, this test ensures Bionic provides it.

**4. Addressing Libc Function Implementations:**

The request asks for details on libc function implementations. *This is where the critical realization happens:* this test file *doesn't implement* any libc functions. It only *checks* for their presence. Therefore, the answer should explain this distinction clearly. Providing general information about how Bionic usually implements libc functions (system calls) is relevant but shouldn't be specific to this file.

**5. Dynamic Linker Aspects:**

Similarly, the request asks about dynamic linker aspects. This test file doesn't directly interact with the dynamic linker. It's checking the header file, which provides declarations used during linking. The answer should clarify this, then provide a general overview of how the dynamic linker works in Android and how `unistd.h` relates indirectly (function declarations needed for linking).

**6. Logical Reasoning and Examples:**

Since it's a test file, direct logical reasoning based on inputs and outputs isn't applicable in the same way as for an implementation file. However, we can reason about the *purpose* of the test. *Hypothetical Input/Output:*  The input is the `unistd.h` header file. The output is either "Test passed" (all macros and functions are defined correctly) or "Test failed" (some are missing or have incorrect signatures).

**7. Common Usage Errors:**

Since this is a header test, common usage errors are related to misusing the functions declared in `unistd.h`. Examples include incorrect arguments to functions like `open()` or `read()`, neglecting error checking, or using functions that might not be available on all Android versions.

**8. Tracing from Android Framework/NDK:**

This requires understanding how an Android app (both Java/Kotlin framework and native NDK) eventually uses these low-level functions.

* **Framework:**  High-level framework calls (e.g., `java.io.File`) eventually make system calls. The Java Native Interface (JNI) is the bridge.
* **NDK:** NDK code directly includes `unistd.h` and calls the functions.

The Frida hook example should demonstrate intercepting calls to functions *declared* in `unistd.h`. `read()` and `write()` are good choices as they are frequently used.

**9. Structuring the Answer:**

Organize the answer logically, addressing each part of the user's request. Use clear headings and bullet points for readability. Emphasize the distinction between a *test file* and an *implementation file*.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "Let me explain how `read()` is implemented."  *Correction:*  This file doesn't implement `read()`. Focus on the *testing* aspect.
* **Initial thought:** "Provide a complex dynamic linker scenario." *Correction:* Keep the dynamic linker explanation general and focused on how declarations in `unistd.h` are used.
* **Initial thought:**  "Give very technical details about system calls." *Correction:*  Keep the system call explanation at a conceptual level. The user didn't ask for deep kernel details.

By following this structured thought process and making necessary corrections, we arrive at a comprehensive and accurate answer that addresses all aspects of the user's request while clearly explaining the nature and purpose of the provided test file.
好的，让我们详细分析一下 `bionic/tests/headers/posix/unistd_h.c` 这个文件的功能和它在 Android Bionic 中的作用。

**1. 文件功能概览**

`unistd_h.c` 并不是 `unistd.h` 的实现代码，而是一个**测试文件**，它的主要功能是：

* **验证 `unistd.h` 头文件的正确性:**  这个文件通过一系列的 `MACRO()` 和 `FUNCTION()` 宏来检查 `unistd.h` 中定义的宏常量、类型定义和函数声明是否符合预期。
* **确保 POSIX 标准的兼容性:** `unistd.h` 定义了许多 POSIX 标准中规定的函数和常量。这个测试文件确保 Android Bionic 提供的 `unistd.h` 包含了这些标准定义，从而提高应用程序在不同 POSIX 系统之间的可移植性。
* **作为 Bionic 构建系统的一部分:** 这个测试文件会在 Bionic 库的构建过程中被编译和执行，以确保 `unistd.h` 的质量。

**简单来说，这个文件就像一个“体检报告”，用来检查 `unistd.h` 这个“身体”是否健康，是否符合标准。**

**2. 与 Android 功能的关系及举例**

`unistd.h` 中定义的函数和常量是构建在 Android 上运行的应用程序的基础。许多 Android 系统调用以及 NDK (Native Development Kit) 开发中使用的 C/C++ 函数都来源于 `unistd.h`。

**举例说明：**

* **文件操作:**  `open()`, `read()`, `write()`, `close()` 等函数用于进行文件和设备的操作。Android 应用程序需要读写文件、访问网络套接字等，这些底层操作都依赖于这些函数。
* **进程管理:** `fork()`, `execve()`, `getpid()`, `sleep()` 等函数用于进程的创建、执行和管理。Android 系统中的进程管理机制，以及应用程序的启动和生命周期管理，都离不开这些函数。
* **用户和组 ID:** `getuid()`, `geteuid()`, `getgid()`, `getegid()` 等函数用于获取用户和组的身份信息。Android 的权限管理和安全机制会使用这些信息来判断应用程序的权限。

**这个测试文件确保了这些关键的函数和常量在 Android Bionic 中被正确地声明，从而保证了应用程序能够正常地调用和使用它们。**

**3. 详细解释 libc 函数的功能是如何实现的**

**需要强调的是，`unistd_h.c` 文件本身并没有实现任何 libc 函数的功能。** 它只是检查 `unistd.h` 中声明的函数是否存在以及它们的函数签名是否正确。

libc 函数的具体实现位于 Bionic 库的其他源文件中，通常是汇编代码或者 C 代码，并最终通过系统调用与 Linux 内核进行交互。

例如，`read()` 函数的实现大致流程如下：

1. **用户空间调用 `read()`:** 应用程序调用 `read()` 函数，提供文件描述符、缓冲区地址和读取字节数。
2. **libc 中的 `read()` 实现:**  Bionic 的 `read()` 函数会将这些参数打包，并触发一个系统调用 (syscall)。
3. **系统调用陷入内核:** CPU 切换到内核模式，执行系统调用处理程序。
4. **内核处理 `read()` 系统调用:** Linux 内核根据文件描述符找到对应的文件，将数据从内核缓冲区复制到用户提供的缓冲区。
5. **返回用户空间:** 系统调用完成，内核将结果返回给用户空间的 `read()` 函数。

**对于 `unistd_h.c` 来说，它只是通过 `FUNCTION(read, ssize_t (*f)(int, void*, size_t));` 这一行代码来检查 `unistd.h` 中是否正确声明了 `read` 函数，并且其函数签名（参数和返回值类型）是否与预期一致。**

**4. 涉及 dynamic linker 的功能，so 布局样本，以及链接的处理过程**

`unistd_h.c` 文件本身**并不直接涉及动态链接器**的功能。它主要关注头文件的内容。

然而，`unistd.h` 中声明的函数最终会被链接到应用程序或者共享库中，而这个链接过程就涉及到动态链接器 (in Android, it's `linker64` or `linker`).

**SO 布局样本:**

假设我们有一个名为 `libmylib.so` 的共享库，它使用了 `unistd.h` 中声明的 `read()` 函数。其布局可能如下：

```
libmylib.so:
  .text:  // 代码段，包含函数指令
    my_function:
      ...
      call read  // 调用 read 函数
      ...
  .data:  // 数据段，包含全局变量
    ...
  .rodata: // 只读数据段，包含字符串常量等
    ...
  .dynsym: // 动态符号表，记录了导出的和导入的符号
    ...
    read  // 导入的 read 符号
    ...
  .dynstr: // 动态字符串表，存储符号名称字符串
    ...
    "read"
    ...
  .plt:   // 程序链接表，用于延迟绑定
    read@plt:
      ...
  .got:   // 全局偏移表，用于存储外部符号的地址
    read@got:
      ...
```

**链接的处理过程 (以调用 `read()` 为例):**

1. **编译时:** 编译器在编译 `libmylib.so` 时，遇到 `read()` 函数调用，会在 `.dynsym` 中记录需要导入的符号 `read`。
2. **加载时:** 当应用程序加载 `libmylib.so` 时，动态链接器会解析 `libmylib.so` 的动态链接信息。
3. **符号查找:** 动态链接器会在系统中已加载的共享库（通常是 `libc.so`）中查找 `read` 符号的定义。
4. **重定位:** 动态链接器会将 `read` 函数在 `libc.so` 中的实际地址填入 `libmylib.so` 的 `.got` 表中 `read@got` 的位置。
5. **延迟绑定 (Lazy Binding):** 默认情况下，Android 使用延迟绑定。最初，`libmylib.so` 中调用 `read` 函数的地方会跳转到 `.plt` 表中的 `read@plt`。
6. **首次调用:** 当 `my_function` 首次调用 `read` 时，`read@plt` 中的代码会触发动态链接器去真正解析 `read` 的地址，并将地址填入 `read@got`。
7. **后续调用:** 之后再次调用 `read` 时，会直接跳转到 `read@got` 中存储的 `read` 函数的实际地址，无需再次进行符号解析。

**`unistd_h.c` 的作用在于确保 `unistd.h` 中正确声明了 `read` 函数，这样编译器才能正确地生成需要导入 `read` 符号的动态链接信息。**

**5. 逻辑推理，假设输入与输出**

由于 `unistd_h.c` 是一个测试文件，它的“输入”是 `unistd.h` 的内容，而“输出”是测试结果（通过或失败）。

**假设输入:**

* **场景 1 (正常情况):** `unistd.h` 文件完整且正确地声明了所有 POSIX 标准要求的宏、类型和函数。
* **场景 2 (缺少宏):** `unistd.h` 文件缺少了 `_POSIX_VERSION` 宏的定义。
* **场景 3 (函数签名错误):** `unistd.h` 文件中 `read` 函数的声明为 `int read(int, void*, size_t);` (返回值类型错误)。

**假设输出:**

* **场景 1:** 测试程序执行完毕，所有 `MACRO()` 和 `FUNCTION()` 的检查都通过，输出类似于 "unistd_h.c: OK"。
* **场景 2:** 测试程序在检查 `MACRO(_POSIX_VERSION);` 时会报错，因为该宏未定义，输出类似于 "unistd_h.c: 错误：宏 _POSIX_VERSION 未定义"。
* **场景 3:** 测试程序在检查 `FUNCTION(read, ssize_t (*f)(int, void*, size_t));` 时会报错，因为 `unistd.h` 中 `read` 函数的声明与预期签名不符，输出类似于 "unistd_h.c: 错误：函数 read 的签名不匹配"。

**6. 涉及用户或者编程常见的使用错误**

虽然 `unistd_h.c` 不直接涉及用户编程，但它可以帮助发现 `unistd.h` 中的问题，从而避免用户在使用相关函数时遇到错误。

**常见的用户编程错误：**

* **头文件包含错误:**  忘记包含 `unistd.h` 头文件，导致编译器无法识别 `read()`, `write()` 等函数。
* **函数参数错误:**  传递给 `read()` 或 `write()` 函数的参数类型或值不正确，例如缓冲区指针为空、读取长度为负数等。
* **错误处理缺失:**  忽略 `read()` 或 `write()` 等函数的返回值，不检查是否发生错误。这些函数通常在出错时返回 -1，并设置 `errno` 变量指示错误类型。
* **使用未定义的宏:**  尝试使用 `unistd.h` 中未定义的宏，导致编译错误。例如，在不支持某些 POSIX 特性的平台上使用相关的宏。

**`unistd_h.c` 的测试可以帮助确保 Bionic 提供的 `unistd.h` 是准确的，从而减少因头文件定义错误导致的用户编程问题。**

**7. 说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

**Android Framework 到 `unistd.h` 的路径 (间接):**

1. **Java/Kotlin 代码:** Android Framework 的上层代码通常是用 Java 或 Kotlin 编写的。
2. **调用 Android SDK API:** Framework 代码会调用 Android SDK 提供的 API，例如 `java.io.File` 用于文件操作， `java.net.Socket` 用于网络操作。
3. **调用 Native 方法 (JNI):** 这些 SDK API 的底层实现通常会通过 JNI (Java Native Interface) 调用 Native 代码 (C/C++)。
4. **调用 Bionic libc 函数:** Native 代码会使用 Bionic 库提供的函数，例如 `open()`, `read()`, `write()` 等，这些函数的声明就在 `unistd.h` 中。
5. **系统调用:** Bionic libc 函数最终会通过系统调用与 Linux 内核进行交互。

**Android NDK 到 `unistd.h` 的路径 (直接):**

1. **NDK C/C++ 代码:** 使用 NDK 开发的应用程序可以直接包含 `unistd.h` 头文件。
2. **调用 `unistd.h` 中声明的函数:** NDK 代码可以直接调用 `read()`, `write()`, `fork()` 等函数。
3. **链接到 Bionic libc:** NDK 编译的共享库会链接到 Bionic libc，从而使用其提供的函数实现。
4. **系统调用:**  Bionic libc 函数最终会通过系统调用与 Linux 内核进行交互。

**Frida Hook 示例:**

我们可以使用 Frida 来 Hook `read()` 函数，观察它的调用过程。

```python
import frida
import sys

# 要 hook 的进程名称
process_name = "com.example.myapp"  # 替换为你的应用进程名

# Frida 脚本
script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "read"), {
    onEnter: function(args) {
        console.log("read() called!");
        console.log("  File Descriptor:", args[0]);
        console.log("  Buffer:", args[1]);
        console.log("  Size:", args[2]);
        // 可以读取缓冲区内容 (谨慎操作，可能很大)
        // var buffer = Memory.readByteArray(args[1], args[2].toInt());
        // console.log("  Buffer Content:", buffer);
    },
    onLeave: function(retval) {
        console.log("read() returned:", retval);
        if (retval.toInt() > 0) {
            // 读取成功，可以查看读取到的数据
            // var buffer = Memory.readByteArray(this.context.r1, retval.toInt()); // 假设缓冲区地址在 r1 寄存器
            // console.log("  Read Data:", buffer);
        }
    }
});
"""

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.attach(process_name)
    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()
    print("[*] Script loaded. Press Ctrl+C to exit.")
    sys.stdin.read()
except frida.ProcessNotFoundError:
    print(f"[-] Process '{process_name}' not found.")
except Exception as e:
    print(f"[-] An error occurred: {e}")
```

**使用步骤：**

1. **安装 Frida:** 确保你的设备上安装了 Frida 服务端，并且你的开发机上安装了 Frida Python 模块 (`pip install frida-tools`).
2. **找到目标进程:** 运行你要调试的 Android 应用程序，并找到它的进程名称。
3. **替换进程名称:** 将 `process_name` 变量替换为你应用的进程名称。
4. **运行 Frida 脚本:** 运行上面的 Python 脚本。
5. **触发 `read()` 调用:** 在你的 Android 应用中执行某些操作，例如打开文件、进行网络请求等，这些操作可能会导致 `read()` 函数被调用。
6. **查看 Frida 输出:** Frida 会拦截对 `read()` 函数的调用，并打印出相关信息，例如文件描述符、缓冲区地址、读取大小以及返回值。

**这个 Frida 示例可以帮助你理解 Android 应用程序是如何一步步地调用到 Bionic libc 中的 `read()` 函数的。你可以类似地 Hook 其他 `unistd.h` 中声明的函数进行调试。**

希望以上详细的解释能够帮助你理解 `bionic/tests/headers/posix/unistd_h.c` 文件的作用以及它在 Android Bionic 中的地位。记住，它是一个测试文件，用于确保 `unistd.h` 的正确性，而 `unistd.h` 中声明的函数是 Android 系统和应用程序的基础。

Prompt: 
```
这是目录为bionic/tests/headers/posix/unistd_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <unistd.h>

#include "header_checks.h"

static void unistd_h() {
  MACRO(_POSIX_VERSION);
  MACRO(_POSIX2_VERSION);
  MACRO(_XOPEN_VERSION);

  MACRO(_POSIX_ADVISORY_INFO);
  MACRO(_POSIX_ASYNCHRONOUS_IO);
  MACRO(_POSIX_BARRIERS);
  MACRO(_POSIX_CHOWN_RESTRICTED);
  MACRO(_POSIX_CLOCK_SELECTION);
  MACRO(_POSIX_CPUTIME);
  MACRO(_POSIX_FSYNC);
  MACRO(_POSIX_IPV6);
  MACRO(_POSIX_JOB_CONTROL);
  MACRO(_POSIX_MAPPED_FILES);
  MACRO(_POSIX_MEMLOCK);
  MACRO(_POSIX_MEMLOCK_RANGE);
  MACRO(_POSIX_MEMORY_PROTECTION);
  MACRO(_POSIX_MESSAGE_PASSING);
  MACRO(_POSIX_MONOTONIC_CLOCK);
  MACRO(_POSIX_NO_TRUNC);
#if !defined(ANDROID_HOST_MUSL)
  MACRO(_POSIX_PRIORITIZED_IO);
  MACRO(_POSIX_PRIORITY_SCHEDULING);
#endif
  MACRO(_POSIX_RAW_SOCKETS);
  MACRO(_POSIX_READER_WRITER_LOCKS);
  MACRO(_POSIX_REALTIME_SIGNALS);
  MACRO(_POSIX_REGEXP);
  MACRO(_POSIX_SAVED_IDS);
  MACRO(_POSIX_SEMAPHORES);
  MACRO(_POSIX_SHARED_MEMORY_OBJECTS);
  MACRO(_POSIX_SHELL);
  MACRO(_POSIX_SPAWN);
  MACRO(_POSIX_SPIN_LOCKS);
#if !defined(ANDROID_HOST_MUSL)
  MACRO(_POSIX_SPORADIC_SERVER);
  MACRO(_POSIX_SYNCHRONIZED_IO);
#endif
  MACRO(_POSIX_THREAD_ATTR_STACKADDR);
  MACRO(_POSIX_THREAD_ATTR_STACKSIZE);
  MACRO(_POSIX_THREAD_CPUTIME);
#if !defined(ANDROID_HOST_MUSL)
  MACRO(_POSIX_THREAD_PRIO_INHERIT);
  MACRO(_POSIX_THREAD_PRIO_PROTECT);
#endif
  MACRO(_POSIX_THREAD_PRIORITY_SCHEDULING);
  MACRO(_POSIX_THREAD_PROCESS_SHARED);
#if !defined(ANDROID_HOST_MUSL)
  MACRO(_POSIX_THREAD_ROBUST_PRIO_INHERIT);
  MACRO(_POSIX_THREAD_ROBUST_PRIO_PROTECT);
#endif
  MACRO(_POSIX_THREAD_SAFE_FUNCTIONS);
#if !defined(ANDROID_HOST_MUSL)
  MACRO(_POSIX_THREAD_SPORADIC_SERVER);
#endif
  MACRO(_POSIX_THREADS);
  MACRO(_POSIX_TIMEOUTS);
  MACRO(_POSIX_TIMERS);
#if !defined(ANDROID_HOST_MUSL)
  MACRO(_POSIX_TYPED_MEMORY_OBJECTS);
#endif
  MACRO(_POSIX2_C_BIND);
#if !defined(ANDROID_HOST_MUSL)
  MACRO(_POSIX2_CHAR_TERM);
  MACRO(_POSIX2_LOCALEDEF);
  MACRO(_POSIX2_SW_DEV);
#endif
#if 0 // No libc I can find actually has this.
  MACRO(_POSIX2_UPE);
#endif
#if !defined(ANDROID_HOST_MUSL)
  MACRO(_XOPEN_CRYPT);
#endif
  MACRO(_XOPEN_ENH_I18N);
#if !defined(ANDROID_HOST_MUSL)
  MACRO(_XOPEN_REALTIME);
  MACRO(_XOPEN_REALTIME_THREADS);
  MACRO(_XOPEN_SHM);
#endif
  MACRO(_XOPEN_UNIX);
#if defined(_XOPEN_UUCP)
#if _XOPEN_UUCP != -1 && _XOPEN_UUCP != 0 && _XOPEN_UUCP != 200809L
#error _XOPEN_UUCP
#endif
#endif

  MACRO(NULL);

  MACRO(F_OK);
  MACRO(R_OK);
  MACRO(W_OK);
  MACRO(X_OK);

#if !defined(__BIONIC__) // No confstr on Android.
  MACRO(_CS_PATH);
  MACRO(_CS_POSIX_V7_ILP32_OFF32_CFLAGS);
  MACRO(_CS_POSIX_V7_ILP32_OFF32_LDFLAGS);
  MACRO(_CS_POSIX_V7_ILP32_OFF32_LIBS);
  MACRO(_CS_POSIX_V7_ILP32_OFFBIG_CFLAGS);
  MACRO(_CS_POSIX_V7_ILP32_OFFBIG_LDFLAGS);
  MACRO(_CS_POSIX_V7_ILP32_OFFBIG_LIBS);
  MACRO(_CS_POSIX_V7_LP64_OFF64_CFLAGS);
  MACRO(_CS_POSIX_V7_LP64_OFF64_LDFLAGS);
  MACRO(_CS_POSIX_V7_LP64_OFF64_LIBS);
  MACRO(_CS_POSIX_V7_LPBIG_OFFBIG_CFLAGS);
  MACRO(_CS_POSIX_V7_LPBIG_OFFBIG_LDFLAGS);
  MACRO(_CS_POSIX_V7_LPBIG_OFFBIG_LIBS);
  MACRO(_CS_POSIX_V7_WIDTH_RESTRICTED_ENVS);
  MACRO(_CS_V7_ENV);
#endif

  MACRO(SEEK_CUR);
  MACRO(SEEK_END);
  MACRO(SEEK_SET);

  MACRO(F_LOCK);
  MACRO(F_TEST);
  MACRO(F_TLOCK);
  MACRO(F_ULOCK);

  MACRO(_PC_2_SYMLINKS);
  MACRO(_PC_ALLOC_SIZE_MIN);
  MACRO(_PC_ASYNC_IO);
  MACRO(_PC_CHOWN_RESTRICTED);
  MACRO(_PC_FILESIZEBITS);
  MACRO(_PC_LINK_MAX);
  MACRO(_PC_MAX_CANON);
  MACRO(_PC_MAX_INPUT);
  MACRO(_PC_NAME_MAX);
  MACRO(_PC_NO_TRUNC);
  MACRO(_PC_PATH_MAX);
  MACRO(_PC_PIPE_BUF);
  MACRO(_PC_PRIO_IO);
  MACRO(_PC_REC_INCR_XFER_SIZE);
  MACRO(_PC_REC_MAX_XFER_SIZE);
  MACRO(_PC_REC_MIN_XFER_SIZE);
  MACRO(_PC_REC_XFER_ALIGN);
  MACRO(_PC_SYMLINK_MAX);
  MACRO(_PC_SYNC_IO);
#if 0 // No libc I can find actually has this.
  MACRO(_PC_TIMESTAMP_RESOLUTION);
#endif
  MACRO(_PC_VDISABLE);

  MACRO(_SC_2_C_BIND);
  MACRO(_SC_2_C_DEV);
  MACRO(_SC_2_CHAR_TERM);
  MACRO(_SC_2_FORT_DEV);
  MACRO(_SC_2_FORT_RUN);
  MACRO(_SC_2_LOCALEDEF);
  MACRO(_SC_2_SW_DEV);
  MACRO(_SC_2_UPE);
  MACRO(_SC_2_VERSION);
  MACRO(_SC_ADVISORY_INFO);
  MACRO(_SC_AIO_LISTIO_MAX);
  MACRO(_SC_AIO_MAX);
  MACRO(_SC_AIO_PRIO_DELTA_MAX);
  MACRO(_SC_ARG_MAX);
  MACRO(_SC_ASYNCHRONOUS_IO);
  MACRO(_SC_ATEXIT_MAX);
  MACRO(_SC_BARRIERS);
  MACRO(_SC_BC_BASE_MAX);
  MACRO(_SC_BC_DIM_MAX);
  MACRO(_SC_BC_SCALE_MAX);
  MACRO(_SC_BC_STRING_MAX);
  MACRO(_SC_CHILD_MAX);
  MACRO(_SC_CLK_TCK);
  MACRO(_SC_CLOCK_SELECTION);
  MACRO(_SC_COLL_WEIGHTS_MAX);
  MACRO(_SC_CPUTIME);
  MACRO(_SC_DELAYTIMER_MAX);
  MACRO(_SC_EXPR_NEST_MAX);
  MACRO(_SC_FSYNC);
  MACRO(_SC_GETGR_R_SIZE_MAX);
  MACRO(_SC_GETPW_R_SIZE_MAX);
  MACRO(_SC_HOST_NAME_MAX);
  MACRO(_SC_IOV_MAX);
  MACRO(_SC_IPV6);
  MACRO(_SC_JOB_CONTROL);
  MACRO(_SC_LINE_MAX);
  MACRO(_SC_LOGIN_NAME_MAX);
  MACRO(_SC_MAPPED_FILES);
  MACRO(_SC_MEMLOCK);
  MACRO(_SC_MEMLOCK_RANGE);
  MACRO(_SC_MEMORY_PROTECTION);
  MACRO(_SC_MESSAGE_PASSING);
  MACRO(_SC_MONOTONIC_CLOCK);
  MACRO(_SC_MQ_OPEN_MAX);
  MACRO(_SC_MQ_PRIO_MAX);
  MACRO(_SC_NGROUPS_MAX);
  MACRO(_SC_OPEN_MAX);
  MACRO(_SC_PAGE_SIZE);
  MACRO(_SC_PAGESIZE);
  MACRO(_SC_PRIORITIZED_IO);
  MACRO(_SC_PRIORITY_SCHEDULING);
  MACRO(_SC_RAW_SOCKETS);
  MACRO(_SC_RE_DUP_MAX);
  MACRO(_SC_READER_WRITER_LOCKS);
  MACRO(_SC_REALTIME_SIGNALS);
  MACRO(_SC_REGEXP);
  MACRO(_SC_RTSIG_MAX);
  MACRO(_SC_SAVED_IDS);
  MACRO(_SC_SEM_NSEMS_MAX);
  MACRO(_SC_SEM_VALUE_MAX);
  MACRO(_SC_SEMAPHORES);
  MACRO(_SC_SHARED_MEMORY_OBJECTS);
  MACRO(_SC_SHELL);
  MACRO(_SC_SIGQUEUE_MAX);
  MACRO(_SC_SPAWN);
  MACRO(_SC_SPIN_LOCKS);
  MACRO(_SC_SPORADIC_SERVER);
  MACRO(_SC_SS_REPL_MAX);
  MACRO(_SC_STREAM_MAX);
  MACRO(_SC_SYMLOOP_MAX);
  MACRO(_SC_SYNCHRONIZED_IO);
  MACRO(_SC_THREAD_ATTR_STACKADDR);
  MACRO(_SC_THREAD_ATTR_STACKSIZE);
  MACRO(_SC_THREAD_CPUTIME);
  MACRO(_SC_THREAD_DESTRUCTOR_ITERATIONS);
  MACRO(_SC_THREAD_KEYS_MAX);
  MACRO(_SC_THREAD_PRIO_INHERIT);
  MACRO(_SC_THREAD_PRIO_PROTECT);
  MACRO(_SC_THREAD_PRIORITY_SCHEDULING);
  MACRO(_SC_THREAD_PROCESS_SHARED);
  MACRO(_SC_THREAD_ROBUST_PRIO_INHERIT);
  MACRO(_SC_THREAD_ROBUST_PRIO_PROTECT);
  MACRO(_SC_THREAD_SAFE_FUNCTIONS);
  MACRO(_SC_THREAD_SPORADIC_SERVER);
  MACRO(_SC_THREAD_STACK_MIN);
  MACRO(_SC_THREAD_THREADS_MAX);
  MACRO(_SC_THREADS);
  MACRO(_SC_TIMEOUTS);
  MACRO(_SC_TIMER_MAX);
  MACRO(_SC_TIMERS);
  MACRO(_SC_TRACE);
  MACRO(_SC_TRACE_EVENT_FILTER);
  MACRO(_SC_TRACE_EVENT_NAME_MAX);
  MACRO(_SC_TRACE_INHERIT);
  MACRO(_SC_TRACE_LOG);
  MACRO(_SC_TRACE_NAME_MAX);
  MACRO(_SC_TRACE_SYS_MAX);
  MACRO(_SC_TRACE_USER_EVENT_MAX);
  MACRO(_SC_TYPED_MEMORY_OBJECTS);
  MACRO(_SC_TZNAME_MAX);
  MACRO(_SC_V7_ILP32_OFF32);
  MACRO(_SC_VERSION);
  MACRO(_SC_XOPEN_CRYPT);
  MACRO(_SC_XOPEN_ENH_I18N);
  MACRO(_SC_XOPEN_REALTIME);
  MACRO(_SC_XOPEN_REALTIME_THREADS);
  MACRO(_SC_XOPEN_SHM);
  MACRO(_SC_XOPEN_STREAMS);
  MACRO(_SC_XOPEN_UNIX);
#if 0 // No libc I can find actually has this.
  MACRO(_SC_XOPEN_UUCP);
#endif
  MACRO(_SC_XOPEN_VERSION);

  MACRO_VALUE(STDERR_FILENO, 2);
  MACRO_VALUE(STDIN_FILENO, 0);
  MACRO_VALUE(STDOUT_FILENO, 1);

  MACRO(_POSIX_VDISABLE);

  TYPE(size_t);
  TYPE(ssize_t);
  TYPE(uid_t);
  TYPE(gid_t);
  TYPE(off_t);
  TYPE(pid_t);
  TYPE(intptr_t);

  FUNCTION(access, int (*f)(const char*, int));
  FUNCTION(alarm, unsigned (*f)(unsigned));
  FUNCTION(chdir, int (*f)(const char*));
  FUNCTION(chown, int (*f)(const char*, uid_t, gid_t));
  FUNCTION(close, int (*f)(int));
#if !defined(__BIONIC__)
  FUNCTION(confstr, size_t (*f)(int, char*, size_t));
  FUNCTION(crypt, char* (*f)(const char*, const char*));
#endif
  FUNCTION(dup, int (*f)(int));
  FUNCTION(dup2, int (*f)(int, int));
  FUNCTION(_exit, void (*f)(int));
#if !defined(__BIONIC__)
  FUNCTION(encrypt, void (*f)(char[64], int));
#endif
  FUNCTION(execl, int (*f)(const char*, const char*, ...));
  FUNCTION(execle, int (*f)(const char*, const char*, ...));
  FUNCTION(execlp, int (*f)(const char*, const char*, ...));
  FUNCTION(execv, int (*f)(const char*, char* const[]));
  FUNCTION(execve, int (*f)(const char*, char* const[], char* const[]));
  FUNCTION(execvp, int (*f)(const char*, char* const[]));
  FUNCTION(faccessat, int (*f)(int, const char*, int, int));
  FUNCTION(fchdir, int (*f)(int));
  FUNCTION(fchown, int (*f)(int, uid_t, gid_t));
  FUNCTION(fchownat, int (*f)(int, const char*, uid_t, gid_t, int));
  FUNCTION(fdatasync, int (*f)(int));
  FUNCTION(fexecve, int (*f)(int, char* const[], char* const[]));
  FUNCTION(fork, pid_t (*f)(void));
#if !defined(__GLIBC__) // Our glibc is too old.
  FUNCTION(_Fork, pid_t (*f)(void));
#endif
  FUNCTION(fpathconf, long (*f)(int, int));
  FUNCTION(fsync, int (*f)(int));
  FUNCTION(ftruncate, int (*f)(int, off_t));
  FUNCTION(getcwd, char* (*f)(char*, size_t));
  FUNCTION(getegid, gid_t (*f)(void));
  FUNCTION(geteuid, uid_t (*f)(void));
  FUNCTION(getgid, gid_t (*f)(void));
  FUNCTION(getgroups, int (*f)(int, gid_t[]));
#if !defined(__BIONIC__)
  FUNCTION(gethostid, long (*f)(void));
#endif
  FUNCTION(gethostname, int (*f)(char*, size_t));
  FUNCTION(getlogin, char* (*f)(void));
  FUNCTION(getlogin_r, int (*f)(char*, size_t));
  FUNCTION(getopt, int (*f)(int, char* const[], const char*));
  FUNCTION(getpgid, pid_t (*f)(pid_t));
  FUNCTION(getpgrp, pid_t (*f)(void));
  FUNCTION(getpid, pid_t (*f)(void));
  FUNCTION(getppid, pid_t (*f)(void));
  FUNCTION(getsid, pid_t (*f)(pid_t));
  FUNCTION(getuid, uid_t (*f)(void));
  FUNCTION(isatty, int (*f)(int));
  FUNCTION(lchown, int (*f)(const char*, uid_t, gid_t));
  FUNCTION(link, int (*f)(const char*, const char*));
  FUNCTION(linkat, int (*f)(int, const char*, int, const char*, int));
  FUNCTION(lockf, int (*f)(int, int, off_t));
  FUNCTION(lseek, off_t (*f)(int, off_t, int));
  FUNCTION(nice, int (*f)(int));
  FUNCTION(pathconf, long (*f)(const char*, int));
  FUNCTION(pause, int (*f)(void));
  FUNCTION(pipe, int (*f)(int[2]));
  FUNCTION(pread, ssize_t (*f)(int, void*, size_t, off_t));
  FUNCTION(pwrite, ssize_t (*f)(int, const void*, size_t, off_t));
  FUNCTION(read, ssize_t (*f)(int, void*, size_t));
  FUNCTION(readlink, ssize_t (*f)(const char*, char*, size_t));
  FUNCTION(readlinkat, ssize_t (*f)(int, const char*, char*, size_t));
  FUNCTION(rmdir, int (*f)(const char*));
  FUNCTION(setegid, int (*f)(gid_t));
  FUNCTION(seteuid, int (*f)(uid_t));
  FUNCTION(setgid, int (*f)(gid_t));
  FUNCTION(setpgid, int (*f)(pid_t, pid_t));
  FUNCTION(setpgrp, pid_t (*f)(void));
  FUNCTION(setregid, int (*f)(gid_t, gid_t));
  FUNCTION(setreuid, int (*f)(uid_t, uid_t));
  FUNCTION(setsid, pid_t (*f)(void));
  FUNCTION(setuid, int (*f)(uid_t));
  FUNCTION(sleep, unsigned (*f)(unsigned));
  FUNCTION(swab, void (*f)(const void*, void*, ssize_t));
  FUNCTION(symlink, int (*f)(const char*, const char*));
  FUNCTION(symlinkat, int (*f)(const char*, int, const char*));
  FUNCTION(sync, void (*f)(void));
  FUNCTION(sysconf, long (*f)(int));
  FUNCTION(tcgetpgrp, pid_t (*f)(int));
  FUNCTION(tcsetpgrp, int (*f)(int, pid_t));
  FUNCTION(truncate, int (*f)(const char*, off_t));
  FUNCTION(ttyname, char* (*f)(int));
  FUNCTION(ttyname_r, int (*f)(int, char*, size_t));
  FUNCTION(unlink, int (*f)(const char*));
  FUNCTION(unlinkat, int (*f)(int, const char*, int));
  FUNCTION(write, ssize_t (*f)(int, const void*, size_t));

  char* cp;
  cp = optarg;
  int i;
  i = opterr;
  i = optind;
  i = optopt;
}

"""

```