Response:
Let's break down the thought process for answering the user's request about `bionic/tests/headers/posix/signal_h.c`.

1. **Understanding the Core Request:** The user wants to understand the functionality of this specific C file within the Android Bionic library. They're asking for a breakdown of what it does, its relationship to Android, explanations of the included libc functions, dynamic linker implications, potential errors, and how Android frameworks/NDK reach this point, including a Frida example.

2. **Initial Assessment of the Code:**  A quick glance reveals this isn't a typical source file with complex logic. It's primarily composed of `TYPE()`, `STRUCT_MEMBER()`, `MACRO()`, and `FUNCTION()` macros. This immediately suggests it's a *header test file*. Its purpose is to verify the presence and correct definition of symbols (types, structure members, macros, functions) declared in the `signal.h` header file.

3. **Identifying the Key Functionality:** The core function of this file is *header checking*. It ensures that the `signal.h` header provides the necessary definitions and declarations for signal handling in a POSIX-compliant manner within the Android environment.

4. **Connecting to Android:**  Signals are fundamental to OS-level inter-process communication and event notification. Android, being a Linux-based system, relies heavily on signals. This file, therefore, plays a crucial role in ensuring that the signal handling mechanisms are correctly implemented within Bionic, the core C library of Android.

5. **Explaining libc Functions (and the Trick):** The request asks for explanations of *every* libc function. However, this test file *doesn't implement* those functions. It merely *declares* or checks for their existence. The key insight here is to recognize the distinction between *declaration/testing* and *implementation*. The explanation should focus on what the listed functions *do* in the context of signal handling, not how they are implemented *in this specific file*. The implementation resides in other parts of Bionic.

6. **Addressing Dynamic Linker Aspects:**  Signals are often used in inter-process communication, which involves the dynamic linker when libraries or executables are loaded. The dynamic linker ensures that the necessary signal handling routines are correctly resolved and linked. However, this specific test file doesn't directly interact with the dynamic linker in a demonstrable way. The connection is more about the dynamic linker's role in ensuring the correct loading of Bionic, which contains the *implementation* of the signal handling functions. The "so layout sample" and "linking process" become more generic descriptions of how dynamic linking works in Android, rather than something specific to this test file.

7. **Considering Logical Reasoning and Assumptions:** There's not a lot of direct logical inference to be done on this *test* file itself. The "input" is implicitly the presence of the `signal.h` header, and the "output" is successful compilation (meaning the header defines things correctly).

8. **Identifying Common Usage Errors:**  Since this file tests the header, common errors relate to *using* the signal functions incorrectly in user code. Examples include forgetting to set up signal handlers, using incorrect signal numbers, or having race conditions in signal handling.

9. **Tracing the Path from Framework/NDK:** This requires thinking about how an Android application interacts with the underlying system. An app might use Java APIs that internally rely on native code. The NDK allows direct use of C/C++ and, therefore, signal handling functions. The path involves calls from the framework down to native code, which then uses the Bionic library where `signal.h` and its associated implementations reside.

10. **Crafting the Frida Hook Example:**  To demonstrate interacting with the tested functions, a Frida hook targeting one of the signal-related functions (e.g., `sigaction`) is appropriate. The example should show how to intercept the function call and log its arguments.

11. **Structuring the Response:**  Organize the information clearly with headings and subheadings to address each part of the user's request. Use clear and concise language, explaining technical terms where necessary.

12. **Review and Refinement:**  Read through the generated response to ensure accuracy, completeness, and clarity. Double-check that the distinction between header testing and actual implementation is clear.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Perhaps I should try to explain how signals are *implemented* in the kernel. **Correction:** The request is about the *Bionic test file*. Focus on what *this file* does, which is primarily header checking. Refer to the actual implementation in Bionic only where necessary to explain the purpose of the declared functions.

* **Initial thought:**  Let's provide a very specific dynamic linker example related to signals. **Correction:**  This test file doesn't directly demonstrate complex dynamic linking. Provide a more general overview of how the dynamic linker plays a role in loading Bionic and resolving signal-related functions.

* **Initial thought:**  Just list the functions and their basic descriptions. **Correction:**  The user wants a detailed explanation of *how they are implemented*. While this file doesn't implement them, explain their *purpose* and how they work in signal handling.

By following these steps, including the refinement process, we arrive at the comprehensive and accurate answer provided previously. The key is to understand the *specific role* of the given source file within the larger context of the Android operating system and its C library.

好的，让我们详细分析一下 `bionic/tests/headers/posix/signal_h.c` 这个文件。

**文件的功能**

这个 C 源文件 (`signal_h.c`) 的主要功能是 **测试 `<signal.h>` 头文件的正确性**。它并不实现任何实际的信号处理逻辑。它通过使用一系列的宏（如 `TYPE`, `STRUCT_MEMBER`, `MACRO`, `FUNCTION`）来检查：

1. **类型定义 (Types):**  验证头文件中定义的各种类型（例如 `pthread_t`, `size_t`, `struct sigaction` 等）是否存在。
2. **结构体成员 (Structure Members):** 验证结构体（例如 `struct sigevent`, `struct sigaction`, `siginfo_t` 等）是否包含预期的成员，以及这些成员的类型是否正确。它还会检查结构体成员是否为函数指针。
3. **宏定义 (Macros):** 验证各种与信号相关的宏定义（例如 `SIG_DFL`, `SIGINT`, `SA_RESTART` 等）是否存在。
4. **函数声明 (Function Declarations):** 验证与信号处理相关的函数（例如 `kill`, `sigaction`, `pthread_kill` 等）是否被正确声明。

**与 Android 功能的关系**

`signal.h` 定义了 POSIX 标准中关于信号处理的接口。信号是 Unix/Linux 系统中用于进程间通信和事件通知的重要机制。Android 作为基于 Linux 内核的操作系统，其底层也大量使用了信号机制。

这个测试文件确保了 Bionic 库提供的 `signal.h` 头文件与 POSIX 标准一致，并且符合 Android 平台的特定需求。这对于以下方面至关重要：

* **应用程序开发:**  Android 应用程序（特别是使用 NDK 开发的 native 应用）依赖于 `<signal.h>` 中定义的接口来进行信号处理，例如注册信号处理函数、发送信号等。
* **系统服务和组件:** Android 系统中的各种服务和组件也可能使用信号来管理进程、处理错误等。
* **兼容性:**  确保 Bionic 库提供的信号处理接口与标准 POSIX 规范一致，有助于提高 Android 平台上应用程序的可移植性。

**举例说明:**

假设一个 Android Native 应用需要捕获 `SIGINT` 信号（通常由用户按下 Ctrl+C 产生）并执行一些清理操作。开发者会包含 `<signal.h>` 头文件，并使用 `sigaction` 函数来注册一个自定义的信号处理函数。`signal_h.c` 测试的就是 `sigaction` 函数是否被正确声明，以及 `struct sigaction` 结构体的定义是否正确，这直接影响到开发者能否正确地使用这个 API。

**详细解释每一个 libc 函数的功能是如何实现的**

需要强调的是，`signal_h.c` **本身并不实现这些 libc 函数**。它只是检查这些函数是否在头文件中被正确声明。这些函数的实际实现位于 Bionic 库的其他源文件中（通常在 `bionic/libc/bionic` 目录下）。

这里简要解释一下 `signal_h.c` 中列出的部分函数的用途：

* **`kill(pid_t pid, int sig)`:** 向指定的进程 ID (`pid`) 发送信号 `sig`。
* **`killpg(pid_t pgrp, int sig)`:** 向指定进程组 ID (`pgrp`) 的所有进程发送信号 `sig`。
* **`psiginfo(const siginfo_t *pinfo, const char *s)`:**  将 `siginfo_t` 结构体中包含的信号信息和可选的消息 `s` 输出到标准错误。
* **`psignal(int sig, const char *s)`:** 将信号编号 `sig` 的描述信息和可选的消息 `s` 输出到标准错误。
* **`pthread_kill(pthread_t thread, int sig)`:** 向指定的线程 ID (`thread`) 发送信号 `sig`。
* **`pthread_sigmask(int how, const sigset_t *newmask, sigset_t *oldmask)`:** 获取或修改调用线程的信号掩码。信号掩码指定了哪些信号会被阻塞。
* **`raise(int sig)`:** 向当前进程发送信号 `sig`。
* **`sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)`:**  检查或修改与特定信号 (`signum`) 关联的处理方式。
* **`sigaddset(sigset_t *set, int signum)`:** 将信号 `signum` 添加到信号集 `set` 中。
* **`sigaltstack(const stack_t *ss, stack_t *oss)`:** 设置或获取进程的备用信号栈。
* **`sigdelset(sigset_t *set, int signum)`:** 从信号集 `set` 中删除信号 `signum`。
* **`sigemptyset(sigset_t *set)`:** 初始化信号集 `set`，使其不包含任何信号。
* **`sigfillset(sigset_t *set)`:** 初始化信号集 `set`，使其包含所有信号。
* **`sighold(int sig)`:**  向调用线程的信号掩码中添加信号 `sig`（已废弃，推荐使用 `sigprocmask`）。
* **`sigignore(int sig)`:** 设置对信号 `sig` 的处理方式为忽略。
* **`siginterrupt(int sig, int flag)`:**  设置当信号 `sig` 处理函数返回时，被该信号中断的系统调用是否应该重新启动。
* **`sigismember(const sigset_t *set, int signum)`:** 检查信号 `signum` 是否是信号集 `set` 的成员。
* **`signal(int signum, signal_handler_type handler)`:** 设置对信号 `signum` 的处理方式（已废弃，推荐使用 `sigaction`）。
* **`sigpause(int sig)`:** 原子地取消阻塞指定信号集中的信号，并暂停调用线程的执行，直到接收到信号。
* **`sigpending(sigset_t *set)`:** 获取当前被阻塞且等待传递给调用线程的信号集。
* **`sigprocmask(int how, const sigset_t *newmask, sigset_t *oldmask)`:** 获取或修改调用线程的信号掩码。
* **`sigqueue(pid_t pid, int sig, union sigval value)`:** 向指定进程发送信号 `sig`，并携带额外的数据 `value`。
* **`sigrelse(int sig)`:**  从调用线程的信号掩码中移除信号 `sig`（已废弃，推荐使用 `sigprocmask`）。
* **`sigset(int signum, signal_handler_type handler)`:** 设置对信号 `signum` 的处理方式（已废弃，推荐使用 `sigaction`）。
* **`sigsuspend(const sigset_t *mask)`:**  用指定的信号掩码替换当前信号掩码，然后暂停调用线程的执行，直到接收到信号。
* **`sigtimedwait(const sigset_t *set, siginfo_t *info, const struct timespec *timeout)`:**  等待信号集 `set` 中的信号发生，并设置超时时间。
* **`sigwait(const sigset_t *set, int *sig)`:**  原子地阻塞调用线程，直到信号集 `set` 中的信号发生。
* **`sigwaitinfo(const sigset_t *set, siginfo_t *info)`:**  等待信号集 `set` 中的信号发生，并获取关于该信号的信息。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程**

虽然 `signal_h.c` 本身不直接涉及 dynamic linker 的具体操作，但信号处理机制的正确运行依赖于 dynamic linker。

**so 布局样本:**

假设一个使用了信号处理的 Native 库 `libmylib.so`，它的布局可能如下：

```
libmylib.so:
    .text         # 代码段
        my_signal_handler:  # 自定义的信号处理函数
            ...
        other_functions:
            ...
    .data         # 数据段
        global_variables:
            ...
    .dynamic      # 动态链接信息
        NEEDED      libc.so   # 依赖于 libc.so (包含信号处理函数的实现)
        ...
    .symtab       # 符号表
        _GLOBAL_OFFSET_TABLE_
        kill
        sigaction
        pthread_kill
        my_signal_handler
        ...
    .rel.dyn      # 动态重定位表
        relocation entry for kill
        relocation entry for sigaction
        relocation entry for pthread_kill
        ...
```

**链接的处理过程:**

1. **加载 `libmylib.so`:** 当 Android 系统加载 `libmylib.so` 时，dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 会被调用。
2. **解析依赖:** dynamic linker 会解析 `libmylib.so` 的 `.dynamic` 段，发现它依赖于 `libc.so`。
3. **加载 `libc.so`:** 如果 `libc.so` 尚未加载，dynamic linker 会将其加载到内存中。
4. **符号解析 (Symbol Resolution):** dynamic linker 会遍历 `libmylib.so` 的 `.rel.dyn` 段，找到需要重定位的符号，例如 `kill`, `sigaction`, `pthread_kill`。
5. **查找符号:** dynamic linker 会在已加载的共享库（包括 `libc.so`）的符号表 (`.symtab`) 中查找这些符号的地址。例如，它会在 `libc.so` 中找到 `kill`, `sigaction`, `pthread_kill` 的实现地址。
6. **重定位 (Relocation):** dynamic linker 会根据找到的地址，更新 `libmylib.so` 中对这些符号的引用。例如，将 `kill` 函数的调用地址替换为 `libc.so` 中 `kill` 函数的实际地址。

这样，当 `libmylib.so` 中的代码调用 `kill` 等信号处理函数时，实际上会调用到 `libc.so` 中对应的实现。

**假设输入与输出 (针对测试文件)**

对于 `signal_h.c` 这样的头文件测试，我们可以考虑其编译过程：

* **假设输入:** 编译器（例如 clang）尝试编译 `signal_h.c`，并包含 `<signal.h>` 头文件。
* **预期输出:** 如果 `<signal.h>` 头文件定义正确，`signal_h.c` 应该能够成功编译，不会产生编译错误。如果头文件缺少某些定义或定义不正确，编译器会报错。

例如，如果 `<signal.h>` 中没有定义 `SIGINT` 宏，那么 `MACRO(SIGINT);` 这行代码会导致编译错误。

**用户或者编程常见的使用错误**

使用信号处理时，常见的错误包括：

1. **忘记注册信号处理函数:**  如果程序需要捕获某个信号并进行处理，但没有使用 `signal` 或 `sigaction` 注册相应的处理函数，当该信号发生时，程序可能会采取默认行为（例如终止）。
   ```c
   #include <stdio.h>
   #include <signal.h>
   #include <unistd.h>

   void sigint_handler(int signum) {
       printf("收到 SIGINT 信号！\n");
   }

   int main() {
       // 错误：忘记注册信号处理函数
       while (1) {
           printf("运行中...\n");
           sleep(1);
       }
       return 0;
   }
   ```
   当程序运行时按下 Ctrl+C，程序可能会直接终止，而不是执行自定义的处理。

2. **信号处理函数中执行不安全的操作:** 信号处理函数应该尽可能地简洁和可重入。在信号处理函数中调用某些非异步信号安全的函数（例如 `printf`, `malloc` 等）可能会导致未定义的行为，例如死锁或崩溃。
   ```c
   #include <stdio.h>
   #include <signal.h>
   #include <unistd.h>
   #include <stdlib.h>

   void sigint_handler(int signum) {
       // 错误：在信号处理函数中调用 printf，可能不安全
       printf("收到 SIGINT 信号，正在清理...\n");
       exit(0); // 错误：在信号处理函数中调用 exit，可能绕过清理逻辑
   }

   int main() {
       signal(SIGINT, sigint_handler);
       while (1) {
           printf("运行中...\n");
           sleep(1);
       }
       return 0;
   }
   ```

3. **信号掩码处理不当:**  错误地设置或使用信号掩码可能会导致某些信号被意外阻塞，从而无法得到处理。

4. **竞态条件:** 在多线程程序中，信号处理可能会引发竞态条件，特别是当多个线程修改共享数据时。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

一个 Android 应用程序（无论是 Java 代码还是 Native 代码）最终都运行在 Linux 内核之上，信号机制是内核提供的基础功能。

1. **Android Framework (Java):**
   - Android Framework 中的某些高级 API 可能会在底层使用信号机制。例如，进程管理和监控服务可能会使用信号来通知进程状态变化。
   - 当一个 Java 应用程序崩溃时，Android Runtime (ART) 会捕获导致崩溃的信号（例如 `SIGSEGV`），并生成 ANR (Application Not Responding) 或 crash 信息。

2. **NDK (Native Development Kit):**
   - 使用 NDK 开发的 Native 代码可以直接调用 `<signal.h>` 中定义的信号处理函数。
   - 例如，一个 Native 库可以使用 `sigaction` 注册一个信号处理函数来捕获特定的错误信号。

**步骤:**

1. **应用程序发起操作:**  例如，用户点击屏幕触发某个操作，或者系统后台服务需要执行某个任务。
2. **Framework 层处理:**  Android Framework 的 Java 代码接收到操作请求，并可能需要调用 Native 代码来完成某些任务。
3. **JNI 调用:** Framework 层通过 JNI (Java Native Interface) 调用 Native 库中的函数。
4. **Native 代码执行:** Native 代码执行过程中，可能会遇到需要使用信号处理的场景：
   - **显式使用:** Native 代码直接调用 `signal` 或 `sigaction` 注册信号处理函数。
   - **隐式触发:**  某些操作可能会导致操作系统发送信号给进程，例如访问非法内存地址会触发 `SIGSEGV`。
5. **Bionic 库:** 当 Native 代码调用信号处理相关的函数时，实际上会调用 Bionic 库中这些函数的实现。`signal_h.c` 这个测试文件确保了 Bionic 库提供的 `<signal.h>` 头文件是正确的，这对于 Native 代码能够正确地使用这些函数至关重要。
6. **内核处理:** 最终，信号的发送和处理是由 Linux 内核完成的。

**Frida Hook 示例:**

我们可以使用 Frida 来 hook `sigaction` 函数，观察 Native 代码是如何注册信号处理函数的。

```python
import frida
import sys

package_name = "你的应用包名"  # 替换为你的应用包名

def on_message(message, data):
    if message['type'] == 'send':
        print(f"[*] {message['payload']}")
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"错误：找不到包名为 '{package_name}' 的进程。请确保应用正在运行。")
    sys.exit(1)

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "sigaction"), {
    onEnter: function(args) {
        var signum = args[0].toInt32();
        var act_ptr = ptr(args[1]);
        var oldact_ptr = ptr(args[2]);

        var signum_str;
        switch (signum) {
            case 2: signum_str = "SIGINT"; break;
            case 6: signum_str = "SIGABRT"; break;
            case 11: signum_str = "SIGSEGV"; break;
            // 添加其他你关心的信号
            default: signum_str = "Unknown (" + signum + ")"; break;
        }

        var act_handler = act_ptr.readPointer(); // 读取 sa_handler 或 sa_sigaction 的地址

        send({
            "type": "sigaction",
            "signum": signum_str,
            "act_handler": act_handler
        });
    },
    onLeave: function(retval) {
        //console.log("sigaction 返回值:", retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**使用步骤:**

1. **安装 Frida 和 frida-tools:**  确保你的开发机器上安装了 Frida 和 frida-tools。
2. **找到目标应用的包名:**  获取你想要调试的 Android 应用的包名。
3. **运行目标应用:**  在 Android 设备或模拟器上运行目标应用。
4. **运行 Frida 脚本:**  在你的开发机器上运行上面的 Python Frida 脚本，将 `package_name` 替换为目标应用的实际包名。

**预期输出:**

当目标应用调用 `sigaction` 函数时，Frida 脚本会拦截该调用，并输出相关信息，例如：

```
[*] {"type": "sigaction", "signum": "SIGINT", "act_handler": "0x7bxxxxxxxxx"}
[*] {"type": "sigaction", "signum": "SIGSEGV", "act_handler": "0x7bxxxxxxxxx"}
```

这表明应用正在注册 `SIGINT` 和 `SIGSEGV` 信号的处理函数，`act_handler` 指向的是处理函数的地址。

通过这种方式，我们可以观察到 Android 应用（尤其是 Native 代码）如何与底层的信号处理机制进行交互，并验证 `<signal.h>` 的正确性对于这些交互的重要性。

总结来说，`bionic/tests/headers/posix/signal_h.c` 虽然只是一个测试文件，但它对于确保 Android 系统中信号处理机制的正确性和可靠性至关重要。它验证了 `<signal.h>` 头文件的定义，为上层应用程序（包括 Framework 和 NDK 应用）正确使用信号处理 API 提供了保障。

Prompt: 
```
这是目录为bionic/tests/headers/posix/signal_h.candroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#include <signal.h>

#include "header_checks.h"

static void signal_h() {
  void (*h)(int);
  h = SIG_DFL;
  h = SIG_ERR;
  h = SIG_HOLD;
  h = SIG_IGN;

  TYPE(pthread_t);
  TYPE(size_t);
  TYPE(uid_t);

  TYPE(struct timespec);

  TYPE(sig_atomic_t);
  TYPE(pid_t);

  TYPE(pthread_attr_t);

  TYPE(struct sigevent);
  STRUCT_MEMBER(struct sigevent, int, sigev_notify);
  STRUCT_MEMBER(struct sigevent, int, sigev_signo);
  STRUCT_MEMBER(struct sigevent, union sigval, sigev_value);
  STRUCT_MEMBER_FUNCTION_POINTER(struct sigevent, void (*f)(union sigval), sigev_notify_function);
#if defined(__BIONIC__)
  STRUCT_MEMBER(struct sigevent, void*, sigev_notify_attributes);
#else
  STRUCT_MEMBER(struct sigevent, pthread_attr_t*, sigev_notify_attributes);
#endif

  MACRO(SIGEV_NONE);
  MACRO(SIGEV_SIGNAL);
  MACRO(SIGEV_THREAD);

#if !defined(__GLIBC__)  // Our glibc is too old.
  MACRO(SIG2STR_MAX);
#endif

  TYPE(union sigval);
  STRUCT_MEMBER(union sigval, int, sival_int);
  STRUCT_MEMBER(union sigval, void*, sival_ptr);

  int i;
  i = SIGRTMIN;
  i = SIGRTMAX;

  MACRO(SIGABRT);
  MACRO(SIGALRM);
  MACRO(SIGBUS);
  MACRO(SIGCHLD);
  MACRO(SIGCONT);
  MACRO(SIGFPE);
  MACRO(SIGHUP);
  MACRO(SIGILL);
  MACRO(SIGINT);
  MACRO(SIGKILL);
  MACRO(SIGPIPE);
  MACRO(SIGQUIT);
  MACRO(SIGSEGV);
  MACRO(SIGSTOP);
  MACRO(SIGTERM);
  MACRO(SIGTSTP);
  MACRO(SIGTTIN);
  MACRO(SIGTTOU);
  MACRO(SIGUSR1);
  MACRO(SIGUSR2);
  MACRO(SIGPOLL);
  MACRO(SIGPROF);
  MACRO(SIGSYS);
  MACRO(SIGTRAP);
  MACRO(SIGURG);
  MACRO(SIGVTALRM);
  MACRO(SIGXCPU);
  MACRO(SIGXFSZ);

  TYPE(struct sigaction);
  STRUCT_MEMBER_FUNCTION_POINTER(struct sigaction, void (*f)(int), sa_handler);
  STRUCT_MEMBER(struct sigaction, sigset_t, sa_mask);
  STRUCT_MEMBER(struct sigaction, int, sa_flags);
  STRUCT_MEMBER_FUNCTION_POINTER(struct sigaction, void (*f)(int, siginfo_t*, void*), sa_sigaction);

  i = SIG_BLOCK;
  i = SIG_UNBLOCK;
  i = SIG_SETMASK;

  MACRO(SA_NOCLDSTOP);
  MACRO(SA_ONSTACK);
  MACRO(SA_RESETHAND);
  MACRO(SA_RESTART);
  MACRO(SA_SIGINFO);
  MACRO(SA_NOCLDWAIT);
  MACRO(SA_NODEFER);

  MACRO(SS_ONSTACK);
  MACRO(SS_DISABLE);

  MACRO(MINSIGSTKSZ);
  MACRO(SIGSTKSZ);

  TYPE(mcontext_t);

  TYPE(ucontext_t);
  STRUCT_MEMBER(ucontext_t, ucontext_t*, uc_link);
  STRUCT_MEMBER(ucontext_t, sigset_t, uc_sigmask);
  STRUCT_MEMBER(ucontext_t, stack_t, uc_stack);
  STRUCT_MEMBER(ucontext_t, mcontext_t, uc_mcontext);

  TYPE(stack_t);
  STRUCT_MEMBER(stack_t, void*, ss_sp);
  STRUCT_MEMBER(stack_t, size_t, ss_size);
  STRUCT_MEMBER(stack_t, int, ss_flags);

  TYPE(siginfo_t);
  STRUCT_MEMBER(siginfo_t, int, si_signo);
  STRUCT_MEMBER(siginfo_t, int, si_code);
  STRUCT_MEMBER(siginfo_t, int, si_errno);
  STRUCT_MEMBER(siginfo_t, pid_t, si_pid);
  STRUCT_MEMBER(siginfo_t, uid_t, si_uid);
  STRUCT_MEMBER(siginfo_t, void*, si_addr);
  STRUCT_MEMBER(siginfo_t, int, si_status);
  STRUCT_MEMBER(siginfo_t, long, si_band);
  STRUCT_MEMBER(siginfo_t, union sigval, si_value);

  i = ILL_ILLOPC;
  i = ILL_ILLOPN;
  i = ILL_ILLADR;
  i = ILL_ILLTRP;
  i = ILL_PRVOPC;
  i = ILL_PRVREG;
  i = ILL_COPROC;
  i = ILL_BADSTK;

  i = FPE_INTDIV;
  i = FPE_INTOVF;
  i = FPE_FLTDIV;
  i = FPE_FLTOVF;
  i = FPE_FLTUND;
  i = FPE_FLTRES;
  i = FPE_FLTINV;
  i = FPE_FLTSUB;

  i = SEGV_MAPERR;
  i = SEGV_ACCERR;

  i = BUS_ADRALN;
  i = BUS_ADRERR;
  i = BUS_OBJERR;

  i = TRAP_BRKPT;
  i = TRAP_TRACE;

  i = CLD_EXITED;
  i = CLD_KILLED;
  i = CLD_DUMPED;
  i = CLD_TRAPPED;
  i = CLD_STOPPED;
  i = CLD_CONTINUED;

  i = POLL_IN;
  i = POLL_OUT;
  i = POLL_MSG;
  i = POLL_ERR;
  i = POLL_PRI;
  i = POLL_HUP;

  i = SI_USER;
  i = SI_QUEUE;
  i = SI_TIMER;
  i = SI_ASYNCIO;
  i = SI_MESGQ;

  typedef void (*signal_handler_type)(int);

  FUNCTION(kill, int (*f)(pid_t, int));
  FUNCTION(killpg, int (*f)(pid_t, int));
  FUNCTION(psiginfo, void (*f)(const siginfo_t*, const char*));
  FUNCTION(psignal, void (*f)(int, const char*));
  FUNCTION(pthread_kill, int (*f)(pthread_t, int));
  FUNCTION(pthread_sigmask, int (*f)(int, const sigset_t*, sigset_t*));
  FUNCTION(raise, int (*f)(int));
#if !defined(__GLIBC__)  // Our glibc is too old.
  FUNCTION(sig2str, int (*f)(int, char*));
#endif
  FUNCTION(sigaction, int (*f)(int, const struct sigaction*, struct sigaction*));
  FUNCTION(sigaddset, int (*f)(sigset_t*, int));
  FUNCTION(sigaltstack, int (*f)(const stack_t*, stack_t*));
  FUNCTION(sigdelset, int (*f)(sigset_t*, int));
  FUNCTION(sigemptyset, int (*f)(sigset_t*));
  FUNCTION(sigfillset, int (*f)(sigset_t*));
  FUNCTION(sighold, int (*f)(int));
  FUNCTION(sigignore, int (*f)(int));
  FUNCTION(siginterrupt, int (*f)(int, int));
  FUNCTION(sigismember, int (*f)(const sigset_t*, int));
  FUNCTION(signal, signal_handler_type (*f)(int, signal_handler_type));
  FUNCTION(sigpause, int (*f)(int));
  FUNCTION(sigpending, int (*f)(sigset_t*));
  FUNCTION(sigprocmask, int (*f)(int, const sigset_t*, sigset_t*));
  FUNCTION(sigqueue, int (*f)(pid_t, int, union sigval));
  FUNCTION(sigrelse, int (*f)(int));
  FUNCTION(sigset, signal_handler_type (*f)(int, signal_handler_type));
  FUNCTION(sigsuspend, int (*f)(const sigset_t*));
  FUNCTION(sigtimedwait, int (*f)(const sigset_t*, siginfo_t*, const struct timespec*));
  FUNCTION(sigwait, int (*f)(const sigset_t*, int*));
  FUNCTION(sigwaitinfo, int (*f)(const sigset_t*, siginfo_t*));
#if !defined(__GLIBC__)  // Our glibc is too old.
  FUNCTION(str2sig, int (*f)(const char*, int*));
#endif
}

"""

```