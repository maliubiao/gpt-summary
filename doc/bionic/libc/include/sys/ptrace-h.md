Response:
Let's break down the thought process to answer the request about `bionic/libc/include/sys/ptrace.h`.

**1. Understanding the Core Request:**

The user wants to understand the purpose and functionality of the provided header file. Key aspects include:

* **Functionality of the file itself:** What does this header provide?
* **Relationship to Android:** How does it connect to the Android operating system?
* **Detailed explanation of functions:**  What do the functions *do*? How are they *implemented* (even though the header only declares them)?
* **Dynamic Linker Impact:**  Does this file relate to the dynamic linker? If so, how?
* **Usage Errors:** Common mistakes developers make when using these functions.
* **Android Framework/NDK Path:** How does code execution reach this header?
* **Frida Hooking:**  Examples of using Frida for debugging.

**2. Initial Analysis of the Header File:**

The header file is relatively simple. The `#ifndef _SYS_PTRACE_H_` pattern indicates it's a header guard to prevent multiple inclusions. The core content is a series of `#define` statements and a function declaration for `ptrace`.

* **`#define` Directives:**  These are clearly mapping symbolic constants. The comments explicitly state they're bridging differences between glibc's and the kernel's naming conventions for `ptrace` operations. This is a crucial insight: this header *doesn't* implement `ptrace`, it provides *aliases* for interacting with the underlying kernel system call.

* **`long ptrace(int __op, ...);`:** This declares the `ptrace` function. The `...` indicates a variadic function (it can take a variable number of arguments).

**3. Addressing Specific Request Points:**

* **Functionality:**  The primary function is to provide a consistent interface to the `ptrace` system call, abstracting away naming differences. It *defines* symbolic names that are easier to use than the raw kernel constants.

* **Relationship to Android:** This is a core part of the Bionic libc, which is the C library for Android. Therefore, any program using standard C library functions that interact with debugging or tracing will likely use definitions from this header.

* **Detailed Explanation of `ptrace`:**  Since the header only declares the function, a *true* implementation explanation isn't possible. The focus should be on the *purpose* of `ptrace` and what each defined constant *means*. This requires some background knowledge of debugging and process control. Mentioning the arguments (request, pid, addr, data) is essential.

* **Dynamic Linker:**  `ptrace` is *not* directly used by the dynamic linker for its core function of resolving and loading libraries. *However*, `ptrace` can be used *to debug* the dynamic linker or programs it loads. This is an important distinction. Therefore, the explanation should highlight this indirect relationship. The SO layout example would be a standard shared library, and the linking process explanation would be the standard dynamic linking process (symbol resolution, relocation).

* **Usage Errors:** Common mistakes involve improper usage of the `ptrace` request codes, incorrect address/data arguments, and race conditions if not used carefully. Security implications are also vital to mention.

* **Android Framework/NDK Path:**  The path starts with high-level Java code in the Android Framework that needs to interact with low-level debugging capabilities. This often goes through JNI calls to native code, which then uses the `ptrace` function declared in this header. The NDK provides developers with the ability to write such native code directly.

* **Frida Hooking:**  Frida allows intercepting function calls. The example should demonstrate hooking the `ptrace` function itself and potentially examining its arguments.

**4. Structuring the Answer:**

A logical flow for the answer would be:

* **Introduction:** Briefly state the file's purpose and its location within Bionic.
* **Functionality:** Describe what the header achieves (consistent `ptrace` interface).
* **Relationship to Android:** Emphasize its role in debugging and system calls.
* **`ptrace` Function Explanation:** Detail the arguments and common operation codes. Explain what each `#define` represents in terms of kernel operations.
* **Dynamic Linker:** Explain the indirect connection through debugging. Provide a standard SO layout and a brief overview of dynamic linking.
* **Usage Errors:** List common pitfalls and security concerns.
* **Android Framework/NDK Path:** Illustrate the call flow from Java to native code.
* **Frida Hooking:** Provide a practical example with explanation.
* **Conclusion:** Summarize the key takeaways.

**5. Refining and Detailing:**

* **Be specific with examples:** Instead of just saying "debugging," mention attaching to a process, reading memory, setting breakpoints, etc.
* **Explain the "why" behind the `#define`s:**  Emphasize the glibc/kernel difference and the benefit of abstraction.
* **Provide clear explanations of the `ptrace` operations:**  Don't just list them; explain what each one is used for.
* **Keep the dynamic linker explanation concise:**  Focus on the *interaction* with `ptrace` for debugging, not a full explanation of dynamic linking itself.
* **Make the Frida example practical and easy to understand.**

**Self-Correction/Refinement during the process:**

* **Initial thought:** Focus solely on the declarations in the header.
* **Correction:** Realize the need to explain the *underlying* `ptrace` system call since the header is just an interface to it.
* **Initial thought:**  `ptrace` is deeply involved in dynamic linking.
* **Correction:**  Clarify that it's mainly used for *debugging* the dynamic linker and loaded libraries, not the core linking process itself.
* **Initial thought:**  Just list the `#define`s.
* **Correction:**  Explain the *purpose* of each definition and its corresponding kernel operation.

By following these steps, iteratively refining the understanding, and anticipating the user's needs, a comprehensive and accurate answer can be constructed.
好的，让我们来详细分析一下 `bionic/libc/include/sys/ptrace.h` 这个头文件。

**功能概述**

`bionic/libc/include/sys/ptrace.h` 的主要功能是为用户空间的程序提供一个与 Linux 内核 `ptrace` 系统调用交互的接口。它定义了一些常量和函数声明，使得开发者可以使用 `ptrace` 来观察和控制另一个进程的执行。

具体来说，这个头文件做了以下几件事：

1. **引入必要的头文件:**  包含了 `<sys/cdefs.h>` 和 `<sys/types.h>`，提供了一些基本的类型定义和编译器相关的宏。同时，包含了 `<linux/ptrace.h>`，这个头文件来自于 Linux 内核，包含了内核实际使用的 `PTRACE_` 开头的宏定义。

2. **重新定义 `ptrace` 操作码 (opcodes):**  由于 glibc（GNU C Library，许多 Linux 系统使用的标准 C 库）和 Linux 内核对于 `ptrace` 的某些操作码使用了不同的命名，这个头文件将 glibc 的命名（以 `PT_` 开头）映射到内核的命名（以 `PTRACE_` 开头）。例如：
   - `PTRACE_POKEUSER` 被定义为 `PTRACE_POKEUSR`
   - `PTRACE_PEEKUSER` 被定义为 `PTRACE_PEEKUSR`
   - `PT_TRACE_ME` 被定义为 `PTRACE_TRACEME`
   - ...等等。

3. **声明 `ptrace` 函数:** 声明了 `long ptrace(int __op, ...);` 函数。这是一个可变参数函数，第一个参数 `__op` 指定要执行的 `ptrace` 操作，后面的参数根据不同的操作码而变化。

**与 Android 功能的关系及举例说明**

`ptrace` 是一个非常底层的系统调用，它在 Android 中被广泛用于各种调试、性能分析和安全相关的工具和机制。

**举例说明：**

* **调试器 (Debugger, e.g., gdb, lldb):**  调试器是 `ptrace` 最典型的应用场景。当你在 Android 上使用 gdb 或 lldb 调试一个程序时，调试器进程会使用 `ptrace` 来：
    * **ATTACH:** 附加到目标进程 (`PTRACE_ATTACH` 或 `PT_ATTACH`)。
    * **设置断点:**  通过修改目标进程的指令，插入断点指令 (`PTRACE_POKETEXT` 或 `PT_WRITE_I`)。
    * **单步执行:**  让目标进程执行一条指令然后停止 (`PTRACE_SINGLESTEP` 或 `PT_STEP`)。
    * **读取/写入内存:**  检查或修改目标进程的内存 (`PTRACE_PEEKDATA`/`PTRACE_POKEDATA` 或 `PT_READ_D`/`PT_WRITE_D`)。
    * **读取/写入寄存器:**  检查或修改目标进程的寄存器值 (`PTRACE_GETREGS`/`PTRACE_SETREGS`，尽管在这个头文件中没有直接定义这两个宏，但底层的 `ptrace` 系统调用支持这些操作)。
    * **继续执行:**  让目标进程继续执行 (`PTRACE_CONT` 或 `PT_CONT`)。
    * **分离:**  从目标进程分离 (`PTRACE_DETACH` 或 `PT_DETACH`)。
* **性能分析工具 (Profiler):** 一些性能分析工具也可能使用 `ptrace` 来收集目标进程的性能数据，例如跟踪系统调用 (`PTRACE_SYSCALL` 或 `PT_SYSCALL`)。
* **安全工具:**  一些安全工具可能会使用 `ptrace` 来监控进程的行为，例如检测恶意代码或沙箱环境。
* **Android Runtime (ART):**  ART 在某些场景下也可能使用 `ptrace`，例如在进行调试或性能分析时。
* **Frida:** Frida 是一个动态插桩工具，它大量依赖 `ptrace` 来附加到进程、修改内存、hook 函数等。

**libc 函数的实现**

`bionic/libc/include/sys/ptrace.h` 本身 **并没有实现任何 libc 函数**。 它只是一个头文件，提供了常量定义和函数声明。 真正的 `ptrace` 函数的实现是在 Bionic libc 的源代码中，并且最终会通过系统调用 (syscall) 进入 Linux 内核。

`ptrace` 函数的底层实现涉及到：

1. **系统调用:**  用户空间的 `ptrace` 函数会触发一个系统调用，进入内核空间。
2. **内核处理:**  Linux 内核会根据传入的 `op` 参数执行相应的操作，例如修改目标进程的内存、寄存器、控制其执行流程等。这通常涉及到进程调度、内存管理等内核子系统的交互。
3. **权限检查:**  `ptrace` 操作涉及到对其他进程的控制，因此内核会进行严格的权限检查，确保调用者有足够的权限执行操作。一般来说，只有父进程或者拥有 `CAP_SYS_PTRACE` 能力的进程才能 `ptrace` 其他进程。

**涉及 dynamic linker 的功能**

`ptrace` 本身 **不是 dynamic linker 的核心功能**。Dynamic linker (在 Android 上是 `linker64` 或 `linker`) 的主要职责是加载共享库 (`.so` 文件)，解析符号，并进行重定位。

然而，`ptrace` 可以 **用于调试 dynamic linker** 或 **被 dynamic linker 加载的程序**。

**SO 布局样本：**

一个典型的共享库 (`.so`) 的布局可能如下所示：

```
ELF Header
Program Headers (描述内存段，例如 .text, .data, .bss)
Section Headers (描述代码段、数据段等)

.text (代码段 - 可执行指令)
.rodata (只读数据段 - 常量字符串等)
.data (已初始化的数据段 - 全局变量等)
.bss (未初始化的数据段 - 未初始化的全局变量)
.plt (Procedure Linkage Table - 用于延迟绑定)
.got (Global Offset Table - 存储全局变量的地址)
.dynsym (动态符号表 - 存储导出的和导入的符号)
.dynstr (动态字符串表 - 存储符号名称)
.rel.dyn (动态重定位表 - 用于运行时调整地址)
.rel.plt (PLT 重定位表 - 用于运行时调整函数地址)
... 其他段 ...
```

**链接的处理过程：**

1. **编译时链接:** 当编译器和链接器将多个源文件编译成一个可执行文件或共享库时，会进行静态链接。此时，会生成符号表和重定位表。
2. **加载时链接 (Dynamic Linking):** 当程序运行时，dynamic linker 会负责加载所需的共享库。
3. **符号解析:** Dynamic linker 会查找共享库中导出的符号，并解析可执行文件或其他共享库中对这些符号的引用。
4. **重定位:** 由于共享库在内存中的加载地址可能每次都不同，dynamic linker 需要修改程序和共享库中的某些地址，使其指向正确的内存位置。这主要通过 `.rel.dyn` 和 `.rel.plt` 段中的信息来完成。
5. **延迟绑定 (Lazy Binding):** 为了提高启动速度，通常会使用延迟绑定。这意味着只有在第一次调用某个外部函数时，dynamic linker 才会解析该函数的地址并进行重定位。PLT 和 GOT 用于实现延迟绑定。

**`ptrace` 在调试 dynamic linker 时的应用：**

当你使用调试器调试一个使用了共享库的程序时，调试器可以使用 `ptrace` 来：

* **在 `dlopen` 等函数处设置断点:**  可以观察共享库的加载过程。
* **读取/写入 dynamic linker 的内存:**  可以检查 dynamic linker 的状态和数据结构。
* **单步执行 dynamic linker 的代码:**  可以详细了解链接和加载的步骤。
* **检查 GOT 和 PLT 表:**  可以查看符号解析和重定位的结果。

**假设输入与输出 (逻辑推理)**

由于 `ptrace.h` 只是头文件，不涉及具体的逻辑执行，我们更多地关注 `ptrace` 函数本身。

**假设输入：**

```c
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

int main() {
    pid_t child_pid = fork();
    if (child_pid == -1) {
        perror("fork");
        exit(EXIT_FAILURE);
    }

    if (child_pid == 0) {
        // 子进程
        printf("Child: Going to be traced...\n");
        if (ptrace(PT_TRACE_ME, 0, NULL, NULL) == -1) {
            perror("ptrace(PT_TRACE_ME)");
            exit(EXIT_FAILURE);
        }
        // 执行一些代码，等待父进程操作
        raise(SIGSTOP); // 发送 SIGSTOP 信号给自己，等待父进程继续
        printf("Child: I'm running again!\n");
    } else {
        // 父进程
        printf("Parent: Child PID is %d\n", child_pid);
        int status;
        waitpid(child_pid, &status, 0); // 等待子进程停止

        if (WIFSTOPPED(status)) {
            printf("Parent: Child stopped, going to continue it.\n");
            if (ptrace(PT_CONT, child_pid, NULL, NULL) == -1) {
                perror("ptrace(PT_CONT)");
                exit(EXIT_FAILURE);
            }
        } else {
            printf("Parent: Child did not stop as expected.\n");
        }
        waitpid(child_pid, NULL, 0); // 等待子进程结束
        printf("Parent: Child finished.\n");
    }
    return 0;
}
```

**预期输出：**

```
Parent: Child PID is <子进程的PID>
Child: Going to be traced...
Parent: Child stopped, going to continue it.
Child: I'm running again!
Parent: Child finished.
```

**解释：**

* 子进程调用 `ptrace(PT_TRACE_ME, ...)` 声明自己将被跟踪。
* 子进程调用 `raise(SIGSTOP)` 暂停自己的执行。
* 父进程等待子进程停止。
* 父进程调用 `ptrace(PT_CONT, ...)` 让子进程继续执行。
* 子进程继续执行并打印消息。
* 父进程等待子进程结束。

**用户或编程常见的使用错误**

1. **权限不足:**  尝试 `ptrace` 一个不属于当前用户或者没有足够权限的进程会导致失败。通常会返回 `-1` 并设置 `errno` 为 `EPERM`。
2. **多次 `PT_TRACE_ME`:**  一个进程只能被 `ptrace` 一次。多次调用 `PT_TRACE_ME` 会失败。
3. **不匹配的 `ptrace` 操作:**  例如，在子进程没有调用 `PT_TRACE_ME` 的情况下，父进程尝试 `ATTACH` 会失败。
4. **错误的 PID:**  传递错误的进程 ID 给 `ptrace` 函数会导致操作失败。
5. **不正确的地址或数据:**  在使用 `PTRACE_PEEKTEXT`/`PTRACE_POKETEXT` 或 `PTRACE_PEEKDATA`/`PTRACE_POKEDATA` 时，传递错误的内存地址可能导致程序崩溃或未定义的行为。
6. **忘记处理错误:**  `ptrace` 调用失败时会返回 `-1`，开发者应该检查返回值并处理错误情况。
7. **竞争条件:**  在多线程或多进程环境下，不小心使用 `ptrace` 可能导致竞争条件和难以调试的问题。
8. **安全风险:**  滥用 `ptrace` 可能会带来安全风险，例如被恶意程序利用来注入代码或窃取信息。

**Android Framework 或 NDK 如何到达这里**

1. **Android Framework (Java 层):**
   - 假设你需要调试一个应用，你可能会使用 Android Studio 的调试功能。
   - Android Studio 的调试器 (基于 JDWP - Java Debug Wire Protocol) 会与设备上的 `debuggable` 应用的进程通信。
   - 当需要进行底层调试操作时（例如设置 native 断点），Android Studio 会通过 `adb` (Android Debug Bridge) 与设备上的 `gdbserver` 或 `lldb-server` 通信。

2. **Native 调试器 (gdbserver/lldb-server):**
   - `gdbserver` 或 `lldb-server` 运行在目标 Android 设备上，以被调试应用的身份或拥有足够权限的用户身份运行。
   - 当收到来自 `adb` 的调试请求时，`gdbserver` 或 `lldb-server` 会使用 `ptrace` 系统调用来附加到目标进程。
   - 例如，当你要设置一个 native 断点时，`gdbserver` 或 `lldb-server` 会调用 `ptrace(PTRACE_POKETEXT, ...)` 来修改目标进程的内存，插入断点指令。

3. **NDK (Native Development Kit):**
   - 如果你的应用使用了 NDK 开发的 native 代码，你可能会直接在 native 代码中使用与调试相关的 API。
   - 然而，**开发者通常不会直接在 NDK 代码中调用 `ptrace`**，因为 `ptrace` 是一个非常底层的系统调用，直接使用它可能会很复杂并且容易出错。
   - 相反，开发者通常会依赖调试器或其他工具来使用 `ptrace` 进行调试。

**Frida Hook 示例调试步骤**

以下是一个使用 Frida Hook 拦截 `ptrace` 调用的示例：

```python
import frida
import sys

def on_message(message, data):
    if message['type'] == 'send':
        print("[*] {}: {}".format(message['payload']['tag'], message['payload']['data']))
    else:
        print(message)

def main():
    package_name = "com.example.myapp" # 替换为你要调试的应用包名

    try:
        session = frida.get_usb_device().attach(package_name)
    except frida.ProcessNotFoundError:
        print(f"[-] Process '{package_name}' not found. Please make sure the app is running.")
        sys.exit(1)

    script_code = """
    'use strict';

    Interceptor.attach(Module.findExportByName(null, "ptrace"), {
        onEnter: function (args) {
            var op = args[0].toInt();
            var pid = args[1].toInt();
            var addr = args[2];
            var data = args[3];

            var op_name = "";
            switch (op) {
                case 0: op_name = "PTRACE_TRACEME"; break;
                case 1: op_name = "PTRACE_PEEKTEXT"; break;
                case 2: op_name = "PTRACE_PEEKDATA"; break;
                case 3: op_name = "PTRACE_PEEKUSR"; break;
                case 4: op_name = "PTRACE_POKETEXT"; break;
                case 5: op_name = "PTRACE_POKEDATA"; break;
                case 6: op_name = "PTRACE_POKEUSR"; break;
                case 7: op_name = "PTRACE_CONT"; break;
                case 8: op_name = "PTRACE_KILL"; break;
                case 9: op_name = "PTRACE_SINGLESTEP"; break;
                case 14: op_name = "PTRACE_ATTACH"; break;
                case 15: op_name = "PTRACE_DETACH"; break;
                case 24: op_name = "PTRACE_SYSCALL"; break;
                // ... 添加其他你关心的 PTRACE_ 操作码
                default: op_name = "UNKNOWN (" + op + ")"; break;
            }

            send({ tag: "ptrace", data: "Called ptrace with op: " + op_name + ", pid: " + pid + ", addr: " + addr + ", data: " + data });
        },
        onLeave: function (retval) {
            send({ tag: "ptrace", data: "ptrace returned: " + retval });
        }
    });
    """

    script = session.create_script(script_code)
    script.on('message', on_message)
    script.load()

    print("[*] Frida script loaded. Intercepting ptrace calls...")
    input() # Keep the script running until Enter is pressed

    session.detach()

if __name__ == "__main__":
    main()
```

**调试步骤：**

1. **安装 Frida:**  确保你的电脑和 Android 设备上都安装了 Frida。
2. **运行目标应用:**  启动你要调试的 Android 应用。
3. **运行 Frida 脚本:**  执行上面的 Python 脚本。将 `com.example.myapp` 替换为你要调试的应用的实际包名。
4. **观察输出:**  当目标应用或其依赖的库调用 `ptrace` 函数时，Frida 脚本会拦截该调用，并打印出 `ptrace` 的操作码、进程 ID、地址和数据等信息。你可以通过观察这些信息来了解 `ptrace` 的使用情况。

这个 Frida 脚本会 hook `ptrace` 函数，并在函数调用前后打印相关信息，帮助你理解哪些组件在何时调用了 `ptrace`，以及调用时传递的参数。这对于理解 Android 系统底层的调试和监控机制非常有帮助。

希望这个详细的解答能够帮助你理解 `bionic/libc/include/sys/ptrace.h` 文件的功能以及它在 Android 系统中的作用。

Prompt: 
```
这是目录为bionic/libc/include/sys/ptrace.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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

#ifndef _SYS_PTRACE_H_
#define _SYS_PTRACE_H_

#include <sys/cdefs.h>
#include <sys/types.h>
#include <linux/ptrace.h>

__BEGIN_DECLS

/* glibc uses different PTRACE_ names from the kernel for these two... */
#define PTRACE_POKEUSER PTRACE_POKEUSR
#define PTRACE_PEEKUSER PTRACE_PEEKUSR

/* glibc exports a different set of PT_ names too... */
#define PT_TRACE_ME PTRACE_TRACEME
#define PT_READ_I PTRACE_PEEKTEXT
#define PT_READ_D PTRACE_PEEKDATA
#define PT_READ_U PTRACE_PEEKUSR
#define PT_WRITE_I PTRACE_POKETEXT
#define PT_WRITE_D PTRACE_POKEDATA
#define PT_WRITE_U PTRACE_POKEUSR
#define PT_CONT PTRACE_CONT
#define PT_KILL PTRACE_KILL
#define PT_STEP PTRACE_SINGLESTEP
#define PT_GETFPREGS PTRACE_GETFPREGS
#define PT_ATTACH PTRACE_ATTACH
#define PT_DETACH PTRACE_DETACH
#define PT_SYSCALL PTRACE_SYSCALL
#define PT_SETOPTIONS PTRACE_SETOPTIONS
#define PT_GETEVENTMSG PTRACE_GETEVENTMSG
#define PT_GETSIGINFO PTRACE_GETSIGINFO
#define PT_SETSIGINFO PTRACE_SETSIGINFO

long ptrace(int __op, ...);

__END_DECLS

#endif

"""

```