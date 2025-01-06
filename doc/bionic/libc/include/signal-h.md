Response:
Let's break down the thought process for analyzing the `signal.h` header file and generating the comprehensive response.

**1. Understanding the Request:**

The core request is to analyze the provided C header file (`signal.h` in Android's Bionic libc) and explain its functionality, especially its relationship with Android, the implementation details of its functions, interaction with the dynamic linker, potential errors, and how Android frameworks/NDK reach this code. The request also asks for Frida hooking examples.

**2. Initial Analysis of the Header File:**

* **Copyright Notice:**  Indicates it's part of the Android Open Source Project (AOSP).
* **Includes:**  The file includes other system headers (`sys/cdefs.h`, `sys/types.h`, `asm/sigcontext.h`, etc.). This immediately suggests it's dealing with low-level system functionality, specifically signal handling.
* **Macros:**  Defines `SIG_HOLD`, `SIGRTMIN`, and `SIGRTMAX`. This hints at managing signal states and real-time signals.
* **External Variables:** Declares `sys_siglist` and `sys_signame`, implying storage of signal names and numbers.
* **Function Declarations:** The bulk of the file consists of function declarations (prototypes). These are the core of the functionality we need to analyze. We see functions like `sigaction`, `signal`, `sigprocmask`, `kill`, `pthread_kill`, and more.
* **Conditional Compilation (`#if __BIONIC_AVAILABILITY_GUARD(...)`)**: This is crucial for understanding Android's evolution. It shows that some functions were introduced in specific Android API levels. This is a key point for relating the code to Android.
* **Deprecated Functions:** The `__attribute__((__deprecated__...))`  clearly marks functions that should no longer be used, along with the recommended replacements.
* **GNU Extensions:** The `#if defined(__USE_GNU)` section points to functions that might be specific to GNU-like systems or extensions supported by Bionic.

**3. Categorizing and Grouping Functionality:**

To make the analysis manageable, it's useful to group the functions by their purpose:

* **Signal Handling Setup:** `sigaction`, `signal`, `siginterrupt`. These functions configure how the process reacts to signals.
* **Signal Sets Manipulation:** `sigaddset`, `sigdelset`, `sigemptyset`, `sigfillset`, `sigismember`. These deal with creating and modifying sets of signals.
* **Signal Masking and Blocking:** `sigpending`, `sigprocmask`, `sigsuspend`. These control which signals a process is currently blocking.
* **Waiting for Signals:** `sigwait`, `sigtimedwait`, `sigwaitinfo`. These allow a process to wait for specific signals.
* **Sending Signals:** `raise`, `kill`, `killpg`, `tgkill`, `pthread_kill`, `sigqueue`, `pthread_sigqueue`. These functions are used to send signals to processes or threads.
* **Alternate Signal Stack:** `sigaltstack`. This manages a separate stack for signal handlers.
* **Signal Information:** `psiginfo`, `psignal`. These functions print information about signals.
* **Deprecated Functions (Important to Note):**  `sighold`, `sigignore`, `sigpause`, `sigrelse`, `sigset`.
* **String Conversion:** `sig2str`, `str2sig`. These convert between signal numbers and their string representations.
* **Thread-Specific Signal Handling:** `pthread_sigmask`. Controls signal masks for individual threads.

**4. Detailing Functionality (For Each Category):**

For each function or category of functions, the following questions are addressed:

* **What does it do?** (A concise description of its purpose)
* **How does it relate to Android?** (Mentioning API levels, framework/NDK usage, specific examples)
* **How is it implemented?** (A high-level overview, mentioning system calls like `syscall(__NR_sigaction, ...)`, acknowledging that the header doesn't show the *full* implementation)
* **Dynamic Linker Interaction:**  While this header doesn't directly *call* the dynamic linker, it's part of `libc.so`, which is loaded by the dynamic linker. The explanation focuses on how `libc.so` is a dependency, its loading process, and symbol resolution.
* **Common Errors:** (Examples of incorrect usage, such as mixing old and new APIs, improper signal masks).
* **Assumptions/Input/Output (If applicable):**  For simpler functions, providing examples of how they might be used and their expected behavior.

**5. Addressing Dynamic Linker Aspects:**

* **SO Layout:**  Describe the general structure of a shared object (`libc.so`), including sections like `.text`, `.data`, `.bss`, `.plt`, `.got`.
* **Linking Process:** Explain the steps involved in dynamic linking: loading dependencies, symbol resolution (using the `.plt` and `.got`), and relocation.

**6. Illustrating Android Framework/NDK Path:**

Trace a possible execution path, starting from a high-level Android component (like an Activity) and showing how an event could lead to signal generation and handling. Highlight the role of the NDK when native code is involved.

**7. Providing Frida Hook Examples:**

For representative functions (like `sigaction` and `kill`), provide concrete Frida code snippets demonstrating how to intercept and observe their behavior.

**8. Structuring the Response:**

Organize the information logically using headings and subheadings to improve readability. Start with a general overview and then delve into specific details for each function and concept. Use clear and concise language.

**9. Iteration and Refinement:**

Review the generated response to ensure accuracy, completeness, and clarity. Check for any missing information or areas that need further explanation. For instance, initially, I might not have explicitly mentioned the role of system calls. Upon review, I'd add that. I also would double-check the API level information for the conditionally compiled functions.

**Self-Correction Example During the Process:**

Initially, I might have focused too much on the *exact* implementation details within the kernel. However, the header file only provides the interface. The correction would be to emphasize that the *implementation* resides in the kernel and the `libc` provides the user-space interface to interact with it via system calls. The explanation would then shift to describing the role of the system call wrappers provided by the `libc`.
好的，让我们来详细分析一下 `bionic/libc/include/signal.h` 这个头文件。

**功能概述:**

这个头文件定义了与信号处理相关的接口和数据结构，它是 Android Bionic C 库的一部分。信号是 Unix-like 操作系统中一种进程间通信机制，用于通知进程发生了某些事件（例如，收到键盘中断、发生错误等）。`signal.h` 提供了用于注册、发送、阻塞和处理信号的函数和宏定义。

**与 Android 功能的关系及举例说明:**

信号处理在 Android 系统中扮演着至关重要的角色，它与多个核心功能息息相关：

1. **进程生命周期管理:** Android 系统使用信号来管理进程的生命周期。例如，当系统需要终止一个应用程序时，它可能会发送 `SIGKILL` 信号给该进程。应用程序可以通过捕获某些信号（例如 `SIGTERM`）来执行清理操作后再退出。
    * **例子:** 当用户强制停止一个应用程序时，Activity Manager Service (AMS) 会向该应用程序的进程发送 `SIGKILL` 信号，强制其终止。

2. **崩溃处理:** 当应用程序发生崩溃（例如，访问空指针）时，系统会生成一个信号（例如 `SIGSEGV`）。Bionic 的信号处理机制会捕获这些信号，生成 tombstone 文件记录崩溃信息，并最终终止该进程。这对于调试和问题分析至关重要。
    * **例子:**  一个 Native 代码的应用程序尝试访问一个已经被释放的内存地址，导致 `SIGSEGV` 信号。Android 的 `debuggerd` 进程会捕获这个信号，并生成崩溃报告。

3. **进程间通信 (IPC):**  信号也可以作为一种简单的进程间通信方式。一个进程可以使用 `kill` 函数向另一个进程发送信号。
    * **例子:**  一个守护进程可能定期向其管理的子进程发送 `SIGHUP` 信号，告知它们重新加载配置文件。

4. **异步事件通知:** 信号允许内核异步地通知进程发生的事件，而无需进程主动轮询。
    * **例子:** 当一个进程设置了定时器后，定时器到期时内核会向该进程发送 `SIGALRM` 信号。

5. **NDK 开发:**  对于使用 Android NDK 进行 Native 开发的开发者来说，`signal.h` 中定义的函数是处理 Native 代码中信号的基础。开发者可以使用这些函数来注册自己的信号处理函数，从而在 Native 层处理各种信号。

**libc 函数的功能实现 (详细解释):**

这个头文件本身只包含了函数声明（原型），并没有包含具体的实现代码。Bionic C 库的函数实现位于其对应的源文件（通常是 `.c` 文件）中。这些函数通常是对底层 Linux 系统调用的封装。

下面对一些重要的函数进行功能和实现方式的解释：

* **`sigaction(int __signal, const struct sigaction* _Nullable __new_action, struct sigaction* _Nullable __old_action)`:**
    * **功能:**  用于设置指定信号的处理方式。它可以指定当接收到信号时要执行的函数、信号掩码以及其他标志。这是推荐使用的信号处理函数，相比 `signal` 更加灵活和可靠。
    * **实现:**  `sigaction` 函数最终会调用底层的 `syscall(__NR_rt_sigaction, ...)` 系统调用，将新的信号处理信息传递给内核。内核会维护一个信号处理表的数组，每个进程都有自己的信号处理表。

* **`signal(int __signal, sighandler_t _Nullable __handler)`:**
    * **功能:**  一个更简单的设置信号处理方式的函数。`__handler` 可以是 `SIG_DFL` (默认处理)、`SIG_IGN` (忽略信号) 或者一个指向信号处理函数的指针。
    * **实现:**  在 Bionic 中，`signal` 函数通常会被实现为调用 `sigaction` 的一个简化版本。这是为了提高兼容性和可移植性，并避免 `signal` 在不同 Unix 版本上的语义差异。

* **`sigprocmask(int __how, const sigset_t* _Nullable __new_set, sigset_t* _Nullable __old_set)`:**
    * **功能:**  用于检查和更改进程的信号掩码。信号掩码指定了当前进程阻塞哪些信号。
    * **实现:**  `sigprocmask` 函数会调用底层的 `syscall(__NR_rt_sigprocmask, ...)` 系统调用，通知内核修改当前进程的信号掩码。

* **`kill(pid_t __pid, int __signal)`:**
    * **功能:**  向指定的进程 ID (`__pid`) 发送指定的信号 (`__signal`)。
    * **实现:**  `kill` 函数会调用底层的 `syscall(__NR_kill, ...)` 系统调用，请求内核向目标进程发送信号。只有具有足够权限的进程才能向其他进程发送信号。

* **`pthread_kill(pthread_t __pthread, int __signal)`:**
    * **功能:**  向指定的线程 (`__pthread`) 发送指定的信号。
    * **实现:**  `pthread_kill` 函数会调用底层的 `syscall(__NR_tkill, ...)` 系统调用，请求内核向目标线程发送信号。

* **信号集操作函数 (`sigemptyset`, `sigfillset`, `sigaddset`, `sigdelset`, `sigismember`):**
    * **功能:**  这些函数用于操作信号集 (`sigset_t`)。信号集是一个位掩码，用于表示一组信号。
        * `sigemptyset`:  初始化信号集为空。
        * `sigfillset`:  初始化信号集包含所有信号。
        * `sigaddset`:  向信号集中添加一个信号。
        * `sigdelset`:  从信号集中删除一个信号。
        * `sigismember`:  检查一个信号是否在信号集中。
    * **实现:**  这些函数通常是直接操作 `sigset_t` 结构体的位运算，没有直接的系统调用对应。

* **`sigsuspend(const sigset_t* _Nonnull __mask)`:**
    * **功能:**  原子地将进程的信号掩码设置为 `__mask`，然后挂起进程直到接收到一个信号。当信号处理函数返回时，进程的信号掩码会恢复到调用 `sigsuspend` 之前的状态。
    * **实现:**  `sigsuspend` 函数会调用底层的 `syscall(__NR_sigsuspend, ...)` 系统调用。这个操作是原子性的，确保在修改信号掩码和进入休眠状态之间不会有竞态条件。

**涉及 dynamic linker 的功能 (及其处理过程):**

这个头文件本身并不直接涉及 dynamic linker 的功能。但是，`signal.h` 中声明的函数都是 Bionic libc 的一部分，而 libc 是一个共享库 (`libc.so`)，它是由 dynamic linker (`/system/bin/linker64` 或 `/system/bin/linker`) 加载到进程的地址空间中的。

**SO 布局样本 (libc.so):**

```
libc.so:
    .text         # 存放可执行代码
    .data         # 存放已初始化的全局变量和静态变量
    .bss          # 存放未初始化的全局变量和静态变量
    .rodata       # 存放只读数据（例如字符串常量）
    .plt          # Procedure Linkage Table，用于延迟绑定
    .got          # Global Offset Table，存放全局变量和函数的地址
    .dynsym       # 动态符号表
    .dynstr       # 动态字符串表
    .hash         # 符号哈希表
    ...
```

**链接的处理过程:**

1. **加载:** 当一个应用程序启动时，操作系统会加载应用程序的可执行文件。应用程序的可执行文件会声明它依赖于 `libc.so`。
2. **dynamic linker 启动:** 操作系统会启动 dynamic linker，并将控制权交给它。
3. **依赖项解析:** dynamic linker 会解析应用程序的依赖项，包括 `libc.so`。
4. **加载共享库:** dynamic linker 会将 `libc.so` 加载到应用程序的地址空间中。这包括将 `.text`、`.data` 等段加载到内存中的合适位置。
5. **符号解析 (Symbol Resolution):** 当应用程序调用 `signal.h` 中声明的函数时，例如 `sigaction`，编译器会生成对该函数的未解析引用。dynamic linker 的作用就是将这些未解析的引用绑定到 `libc.so` 中实际的函数地址。
    * **延迟绑定 (Lazy Binding):** 默认情况下，Bionic 使用延迟绑定。这意味着函数地址的解析发生在第一次调用该函数时。
    * **PLT 和 GOT:**  延迟绑定是通过 Procedure Linkage Table (`.plt`) 和 Global Offset Table (`.got`) 实现的。
        * 第一次调用 `sigaction` 时，会跳转到 `.plt` 中对应的条目。
        * `.plt` 条目会跳转到 dynamic linker 的解析例程。
        * dynamic linker 会在 `libc.so` 的动态符号表 (`.dynsym`) 中查找 `sigaction` 的地址。
        * 找到地址后，dynamic linker 会将该地址写入 `.got` 中 `sigaction` 对应的条目。
        * 随后对 `sigaction` 的调用会直接跳转到 `.plt`，然后从 `.got` 中获取已解析的地址，直接调用 `libc.so` 中的 `sigaction` 函数。

**逻辑推理、假设输入与输出 (对于简单的宏定义):**

* **假设输入:** 一个程序尝试获取实时信号的最小值和最大值。
* **涉及宏:** `SIGRTMIN`, `SIGRTMAX`
* **逻辑推理:** `SIGRTMIN` 和 `SIGRTMAX` 是宏定义，它们分别调用 `__libc_current_sigrtmin()` 和 `__libc_current_sigrtmax()` 函数。这些函数会返回当前系统可用的实时信号的范围。
* **输出:**  `SIGRTMIN` 可能返回一个较小的整数值（例如 32），`SIGRTMAX` 可能返回一个较大的整数值（例如 63）。具体的数值取决于内核配置。

**用户或编程常见的使用错误:**

1. **不正确的信号处理函数签名:**  信号处理函数的签名必须符合特定的格式 (`void handler(int signum)` 或者带有 `siginfo_t` 和 `ucontext_t` 参数的更复杂的签名）。如果签名不正确，编译器可能不会报错，但在运行时可能会导致未定义的行为。

2. **在信号处理函数中调用非异步信号安全 (async-signal-safe) 的函数:** 信号处理函数可能会在程序执行的任何时刻被异步调用。因此，在信号处理函数中调用的函数必须是异步信号安全的，即在信号处理上下文中调用不会导致死锁或其他问题。例如，在信号处理函数中调用 `malloc` 或 `printf` 是不安全的。

3. **混用 `signal` 和 `sigaction`:** 尽管 `signal` 更简单，但 `sigaction` 提供了更多的控制和更好的可移植性。混用这两种 API 可能会导致意外的行为。建议使用 `sigaction`。

4. **忘记恢复被阻塞的信号:**  在使用 `sigprocmask` 阻塞信号后，必须确保在适当的时候恢复信号的阻塞状态，否则可能会导致程序无法响应某些信号。

5. **信号处理函数的竞态条件:** 如果多个信号处理函数访问共享资源，需要采取适当的同步措施（例如使用原子操作或互斥锁，但要注意异步信号安全）。

**Android Framework 或 NDK 如何一步步到达这里:**

1. **Android Framework (Java 层):**
    * 一些 Framework 组件可能会通过 JNI 调用 Native 代码，而 Native 代码可能会使用 `signal.h` 中定义的函数。
    * 例如，当一个 Java 层的线程遇到一个 Native 层的崩溃时，Dalvik/ART 虚拟机的 Native 代码会接收到信号，并使用 `sigaction` 或类似的机制来处理崩溃。

2. **Android NDK (Native 层):**
    * 使用 NDK 开发的应用程序可以直接包含 `signal.h` 头文件，并调用其中的函数。
    * **示例场景:**
        * 一个 Native 线程可能需要捕获 `SIGINT` 信号来优雅地处理用户中断。
        * 一个游戏引擎可能需要设置自定义的信号处理函数来处理特定的错误情况。

**Frida Hook 示例调试步骤:**

假设我们要 Hook `sigaction` 函数来观察应用程序如何设置信号处理程序。

```python
import frida
import sys

package_name = "your.package.name"  # 替换为目标应用的包名

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] Received: {}".format(message['payload']))
    else:
        print(message)

try:
    session = frida.get_usb_device().attach(package_name)
except frida.ProcessNotFoundError:
    print(f"进程 '{package_name}' 未找到，请确保应用正在运行。")
    sys.exit()

script_code = """
Interceptor.attach(Module.findExportByName("libc.so", "sigaction"), {
    onEnter: function(args) {
        var signal = args[0].toInt32();
        var new_action_ptr = args[1];
        var old_action_ptr = args[2];

        var signalName = "";
        try {
            signalName = Process.enumerateModules()[0].enumerateSymbols().find(sym => sym.address.equals(Module.findExportByName(null, "sys_signame").add(signal*Process.pointerSize))).name;
        } catch (e) {
            signalName = "Unknown Signal (" + signal + ")";
        }

        console.log("\\n[*] sigaction called for signal: " + signalName);
        console.log("    Signal Number: " + signal);
        console.log("    New Action Pointer: " + new_action_ptr);
        console.log("    Old Action Pointer: " + old_action_ptr);

        if (new_action_ptr.isNull() == false) {
            var new_action = ptr(new_action_ptr);
            var sa_handler_ptr = new_action.readPointer();
            console.log("    New Handler Address: " + sa_handler_ptr);

            // 尝试解析处理函数的符号名（可能不可靠）
            var handlerName = "Unknown Handler";
            try {
                handlerName = DebugSymbol.fromAddress(sa_handler_ptr).name;
            } catch (e) {
                // Ignore if symbol cannot be resolved
            }
            console.log("    Handler Name: " + handlerName);

            // 可以进一步读取 sigaction 结构体的其他字段
        }
    },
    onLeave: function(retval) {
        console.log("[*] sigaction returned: " + retval);
    }
});
"""

script = session.create_script(script_code)
script.on('message', on_message)
script.load()
sys.stdin.read()
```

**调试步骤:**

1. **安装 Frida 和 adb:** 确保你的电脑上安装了 Frida 和 Android Debug Bridge (adb)。
2. **连接 Android 设备:** 使用 USB 连接 Android 设备，并确保 adb 可以识别设备。
3. **找到目标应用的包名:** 替换 `your.package.name` 为你要调试的 Android 应用的包名。
4. **运行 Frida 脚本:** 运行上面的 Python 脚本。
5. **触发信号处理:** 在目标应用程序中执行某些操作，这些操作可能会导致信号处理函数的调用。例如，如果 Hook 的是处理崩溃的信号，你可以尝试触发一个崩溃。
6. **观察 Frida 输出:** Frida 会拦截对 `sigaction` 的调用，并打印出相关的参数信息，例如信号编号、新的信号处理函数地址等。你可以根据这些信息来分析应用程序是如何设置信号处理的。

这个 Frida 脚本会拦截对 `sigaction` 的调用，并在每次调用时打印出信号编号、新的处理函数地址等信息。这可以帮助你理解应用程序如何配置其信号处理程序。你可以根据需要修改脚本来 Hook 其他信号处理相关的函数。

希望这个详尽的解释能够帮助你理解 `bionic/libc/include/signal.h` 的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/include/signal.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#ifndef _SIGNAL_H_
#define _SIGNAL_H_

#include <sys/cdefs.h>
#include <sys/types.h>

#include <asm/sigcontext.h>
#include <bits/pthread_types.h>
#include <bits/signal_types.h>
#include <bits/timespec.h>
#include <limits.h>

#include <sys/ucontext.h>
#define __BIONIC_HAVE_UCONTEXT_T

__BEGIN_DECLS

/* The kernel headers define SIG_DFL (0) and SIG_IGN (1) but not SIG_HOLD, since
 * SIG_HOLD is only used by the deprecated SysV signal API.
 */
#define SIG_HOLD __BIONIC_CAST(reinterpret_cast, sighandler_t, 2)

/* We take a few real-time signals for ourselves. May as well use the same names as glibc. */
#define SIGRTMIN (__libc_current_sigrtmin())
#define SIGRTMAX (__libc_current_sigrtmax())
int __libc_current_sigrtmin(void);
int __libc_current_sigrtmax(void);

extern const char* _Nonnull const sys_siglist[_NSIG];
extern const char* _Nonnull const sys_signame[_NSIG]; /* BSD compatibility. */

#define si_timerid si_tid /* glibc compatibility. */

int sigaction(int __signal, const struct sigaction* _Nullable __new_action, struct sigaction* _Nullable __old_action);

#if __BIONIC_AVAILABILITY_GUARD(28)
int sigaction64(int __signal, const struct sigaction64* _Nullable __new_action, struct sigaction64* _Nullable __old_action) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */


int siginterrupt(int __signal, int __flag);

sighandler_t _Nonnull signal(int __signal, sighandler_t _Nullable __handler);
int sigaddset(sigset_t* _Nonnull __set, int __signal);

#if __BIONIC_AVAILABILITY_GUARD(28)
int sigaddset64(sigset64_t* _Nonnull __set, int __signal) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

int sigdelset(sigset_t* _Nonnull __set, int __signal);

#if __BIONIC_AVAILABILITY_GUARD(28)
int sigdelset64(sigset64_t* _Nonnull __set, int __signal) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

int sigemptyset(sigset_t* _Nonnull __set);

#if __BIONIC_AVAILABILITY_GUARD(28)
int sigemptyset64(sigset64_t* _Nonnull __set) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

int sigfillset(sigset_t* _Nonnull __set);

#if __BIONIC_AVAILABILITY_GUARD(28)
int sigfillset64(sigset64_t* _Nonnull __set) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

int sigismember(const sigset_t* _Nonnull __set, int __signal);

#if __BIONIC_AVAILABILITY_GUARD(28)
int sigismember64(const sigset64_t* _Nonnull __set, int __signal) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */


int sigpending(sigset_t* _Nonnull __set);

#if __BIONIC_AVAILABILITY_GUARD(28)
int sigpending64(sigset64_t* _Nonnull __set) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

int sigprocmask(int __how, const sigset_t* _Nullable __new_set, sigset_t* _Nullable __old_set);

#if __BIONIC_AVAILABILITY_GUARD(28)
int sigprocmask64(int __how, const sigset64_t* _Nullable __new_set, sigset64_t* _Nullable __old_set) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

int sigsuspend(const sigset_t* _Nonnull __mask);

#if __BIONIC_AVAILABILITY_GUARD(28)
int sigsuspend64(const sigset64_t* _Nonnull __mask) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */

int sigwait(const sigset_t* _Nonnull __set, int* _Nonnull __signal);

#if __BIONIC_AVAILABILITY_GUARD(28)
int sigwait64(const sigset64_t* _Nonnull __set, int* _Nonnull __signal) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */



#if __BIONIC_AVAILABILITY_GUARD(26)
int sighold(int __signal)
  __attribute__((__deprecated__("use sigprocmask() or pthread_sigmask() instead")))
  __INTRODUCED_IN(26);
int sigignore(int __signal)
  __attribute__((__deprecated__("use sigaction() instead"))) __INTRODUCED_IN(26);
int sigpause(int __signal)
  __attribute__((__deprecated__("use sigsuspend() instead"))) __INTRODUCED_IN(26);
int sigrelse(int __signal)
  __attribute__((__deprecated__("use sigprocmask() or pthread_sigmask() instead")))
  __INTRODUCED_IN(26);
sighandler_t _Nonnull sigset(int __signal, sighandler_t _Nullable __handler)
  __attribute__((__deprecated__("use sigaction() instead"))) __INTRODUCED_IN(26);
#endif /* __BIONIC_AVAILABILITY_GUARD(26) */


int raise(int __signal);
int kill(pid_t __pid, int __signal);
int killpg(int __pgrp, int __signal);
int tgkill(int __tgid, int __tid, int __signal);

int sigaltstack(const stack_t* _Nullable __new_signal_stack, stack_t*  _Nullable __old_signal_stack);

void psiginfo(const siginfo_t* _Nonnull __info, const char* _Nullable __msg);
void psignal(int __signal, const char* _Nullable __msg);

int pthread_kill(pthread_t __pthread, int __signal);
#if defined(__USE_GNU)

#if __BIONIC_AVAILABILITY_GUARD(29)
int pthread_sigqueue(pthread_t __pthread, int __signal, const union sigval __value) __INTRODUCED_IN(29);
#endif /* __BIONIC_AVAILABILITY_GUARD(29) */

#endif

int pthread_sigmask(int __how, const sigset_t* _Nullable __new_set, sigset_t* _Nullable __old_set);

#if __BIONIC_AVAILABILITY_GUARD(28)
int pthread_sigmask64(int __how, const sigset64_t* _Nullable __new_set, sigset64_t* _Nullable __old_set) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */



#if __BIONIC_AVAILABILITY_GUARD(23)
int sigqueue(pid_t __pid, int __signal, const union sigval __value) __INTRODUCED_IN(23);
int sigtimedwait(const sigset_t* _Nonnull __set, siginfo_t* _Nullable __info, const struct timespec* _Nullable __timeout) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(28)
int sigtimedwait64(const sigset64_t* _Nonnull __set, siginfo_t* _Nullable __info, const struct timespec* _Nullable __timeout) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */


#if __BIONIC_AVAILABILITY_GUARD(23)
int sigwaitinfo(const sigset_t* _Nonnull __set, siginfo_t* _Nullable __info) __INTRODUCED_IN(23);
#endif /* __BIONIC_AVAILABILITY_GUARD(23) */


#if __BIONIC_AVAILABILITY_GUARD(28)
int sigwaitinfo64(const sigset64_t* _Nonnull __set, siginfo_t* _Nullable __info) __INTRODUCED_IN(28);
#endif /* __BIONIC_AVAILABILITY_GUARD(28) */


/**
 * Buffer size suitable for any call to sig2str().
 */
#define SIG2STR_MAX 32

/**
 * [sig2str(3)](https://man7.org/linux/man-pages/man3/sig2str.3.html)
 * converts the integer corresponding to SIGSEGV (say) into a string
 * like "SEGV" (not including the "SIG" used in the constants).
 * SIG2STR_MAX is a safe size to use for the buffer.
 *
 * Returns 0 on success, and returns -1 _without_ setting errno otherwise.
 *
 * Available since API level 36.
 */

#if __BIONIC_AVAILABILITY_GUARD(36)
int sig2str(int __signal, char* _Nonnull __buf) __INTRODUCED_IN(36);

/**
 * [str2sig(3)](https://man7.org/linux/man-pages/man3/str2sig.3.html)
 * converts a string like "SEGV" (not including the "SIG" used in the constants)
 * into the integer corresponding to SIGSEGV.
 *
 * Returns 0 on success, and returns -1 _without_ setting errno otherwise.
 *
 * Available since API level 36.
 */
int str2sig(const char* _Nonnull __name, int* _Nonnull __signal) __INTRODUCED_IN(36);
#endif /* __BIONIC_AVAILABILITY_GUARD(36) */


__END_DECLS

#endif

"""

```