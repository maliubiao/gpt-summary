Response:
Let's break down the thought process to answer the request about `ucontext.handroid`.

1. **Understanding the Core Request:** The fundamental goal is to explain the functionality of the `ucontext.handroid` header file in Android's Bionic libc. This includes its role, its components, how it relates to Android, potential issues, and debugging.

2. **Initial Analysis of the Code:** The first step is to read through the provided code. Key observations:
    * It's a header file (`.h`).
    * It defines a `ucontext_t` structure.
    * The definition of `ucontext_t` is different based on the architecture (`__arm__`, `__aarch64__`, `__i386__`, `__x86_64__`, `__riscv`). This immediately suggests architecture-specific functionality.
    * It includes other header files like `signal.h` and `sys/user.h`, indicating a connection to signal handling and system-level user information.
    * It defines constants (like `REG_R0`, `NGREG`) related to processor registers.
    * It defines types like `greg_t`, `gregset_t`, and `fpregset_t`, which likely represent general-purpose registers and floating-point registers.
    * It includes architecture-specific `asm/sigcontext.h`, further solidifying the architecture-dependent nature.
    * The `ucontext_t` structure contains members like `uc_flags`, `uc_link`, `uc_stack`, `uc_mcontext`, and `uc_sigmask`. These names suggest the structure holds context information about a thread or process.

3. **Formulating the Functionality:** Based on the code analysis, the primary function of `ucontext.handroid` is to define the structure `ucontext_t`. This structure is crucial for:
    * **Context Switching:**  Saving and restoring the state of a thread or process. This is implied by the presence of register information, stack details, and signal masks.
    * **Signal Handling:** The `uc_sigmask` member strongly suggests its involvement in managing blocked signals.
    * **Architecture Abstraction:** The conditional compilation (`#if defined(...)`) highlights the need for architecture-specific context information.

4. **Connecting to Android:**  How does this relate to Android?
    * **Signal Handling:** Android uses signals extensively for inter-process communication and handling events like crashes or user interrupts. `ucontext_t` is essential for signal handlers to understand the context in which the signal occurred.
    * **Threading:** While Android has higher-level threading mechanisms (like `pthread`), the underlying system relies on the ability to switch between threads. `ucontext_t` provides the raw data needed for this.
    * **Debugging/Crash Analysis:** When an application crashes, the system needs to capture the state of the process. `ucontext_t` is a key data structure for this.

5. **Explaining Libc Functions (and realizing there are none *directly* defined):** The request asks about explaining the implementation of libc functions. A careful look at the header file reveals that **it doesn't define any functions**. It only defines a data structure. Therefore, the explanation needs to focus on how the *structure* is used by libc functions. Functions like `getcontext`, `setcontext`, `makecontext`, and `swapcontext` (though not explicitly in the header) are the key players here. The explanation should describe the *purpose* of these functions in relation to `ucontext_t`.

6. **Dynamic Linker Connection:**  The prompt asks about the dynamic linker. While `ucontext.handroid` itself doesn't *directly* implement dynamic linking, the *context* it represents is crucial. When the dynamic linker resolves symbols and loads shared libraries, it operates within a process's context. If an error occurs during linking, the system might use signals and `ucontext_t` to report the error. The example SO layout and linking process explanation should illustrate this indirect relationship – the linker modifies memory and jumps to code within the process context described by `ucontext_t`.

7. **Logical Reasoning and Examples:**  Think about practical scenarios where `ucontext_t` is important. Signal handlers are the most obvious. Craft a simple example where a signal handler accesses register information from the `ucontext_t`. Also, consider the case where `ucontext_t` is improperly used (e.g., modifying it incorrectly).

8. **Android Framework/NDK Path:** Trace how a signal might be generated and handled, leading to the use of `ucontext_t`. A crash is a good example. The kernel generates a signal, which is then handled by the process. The signal handler receives the `ucontext_t`. For NDK, a native crash will also follow a similar path.

9. **Frida Hooking:** How can we inspect this in practice?  Frida is a powerful tool for dynamic instrumentation. Focus on hooking the `sigaction` system call (where signal handlers are registered) or the signal handler function itself. This allows you to inspect the `ucontext_t` passed to the handler.

10. **Structuring the Answer:** Organize the information logically, following the points in the request:
    * Functionality of the file.
    * Relationship to Android (with examples).
    * Explanation of *how* `ucontext_t` is used (since no functions are defined).
    * Dynamic linker aspects (SO layout and linking process).
    * Logical reasoning/examples (input/output).
    * Common errors.
    * Android Framework/NDK path.
    * Frida hooking example.

11. **Refinement and Language:** Ensure the language is clear, concise, and in Chinese as requested. Use technical terms accurately but explain them if necessary. Review for clarity and completeness.

By following these steps, we can construct a comprehensive and accurate answer that addresses all aspects of the original request. The key is to break down the problem, analyze the code, understand the context (Android system), and then synthesize the information into a well-structured explanation.
这个 `bionic/libc/include/sys/ucontext.handroid` 文件定义了在 Android Bionic libc 中用于表示进程或线程上下文的 `ucontext_t` 结构体。这个结构体用于保存和恢复执行上下文，这在实现协程、用户态线程、信号处理等功能时至关重要。

**它的功能:**

这个头文件定义了以下关键内容：

1. **`ucontext_t` 结构体:**  这是核心，用于存储执行上下文。它包含以下关键成员：
    * `uc_flags`:  上下文标志，目前未使用。
    * `uc_link`: 指向前一个上下文的指针，用于上下文链式切换。
    * `uc_stack`:  描述当前上下文使用的栈的信息，包括栈底地址和大小。
    * `uc_mcontext`:  一个 `mcontext_t` 结构体，存储了机器相关的上下文信息，例如通用寄存器、程序计数器（PC）、栈指针（SP）、浮点寄存器等。
    * `uc_sigmask`/`uc_sigmask64`:  信号掩码，指示当前上下文中阻塞的信号。

2. **`mcontext_t` 结构体:**  这是一个机器相关的结构体，定义了特定架构下的寄存器集合。可以看到代码中针对不同的架构（ARM, AArch64, i386, x86_64, RISC-V）定义了不同的 `mcontext_t`。
    * 它包含了 `gregset_t` (通用寄存器集合) 和 `fpregset_t` (浮点寄存器集合)。
    * 不同的架构其寄存器数量和名称有所不同，因此需要针对性定义。

3. **寄存器宏定义 (`REG_R0`, `REG_RIP` 等):**  为了方便访问 `mcontext_t` 中的寄存器，定义了一系列宏，将寄存器名称映射到数组的索引。例如，在 ARM 架构下，`REG_R0` 对应通用寄存器 R0。

4. **类型定义 (`greg_t`, `gregset_t`, `fpregset_t`):**  定义了用于表示通用寄存器、通用寄存器集合和浮点寄存器集合的类型。这些类型也是架构相关的。

**与 Android 功能的关系及举例说明:**

`ucontext_t` 在 Android 系统中扮演着至关重要的角色，尤其在以下几个方面：

1. **信号处理 (Signal Handling):** 当一个进程接收到信号时，操作系统会创建一个新的执行上下文，并将信号处理函数的地址设置到这个上下文中。信号处理函数执行完毕后，可以通过 `sigreturn` 系统调用恢复到之前的上下文。`ucontext_t` 结构体就用于保存信号发生时的进程状态，供信号处理函数使用和恢复。

   **举例:** 当一个程序发生段错误（SIGSEGV）时，操作系统会创建一个新的 `ucontext_t` 结构体，其中 `uc_mcontext` 会包含导致错误的指令地址（保存在程序计数器中）和其他寄存器信息。然后，系统会调用预先注册的信号处理函数（如果存在）。崩溃报告工具可以使用 `ucontext_t` 中的信息来生成堆栈回溯。

2. **用户态线程库 (User-level Threading):** 一些用户态线程库（虽然在 Android 上不常见，但原理类似）会使用 `ucontext_t` 来实现线程的切换。通过 `getcontext` 保存当前线程的上下文，使用 `setcontext` 或 `swapcontext` 切换到另一个线程的上下文。

   **举例:** 假设一个简单的协程库。当一个协程需要让出执行权时，它会调用 `getcontext` 保存自己的状态到一个 `ucontext_t` 结构体中，然后使用 `setcontext` 切换到调度器的上下文。调度器选择下一个要执行的协程后，会使用 `setcontext` 恢复该协程的上下文。

3. **异常处理和调试:**  调试器和崩溃转储工具会利用 `ucontext_t` 中的信息来分析程序崩溃时的状态。

   **举例:**  当使用 GDB 调试程序时，如果程序暂停或崩溃，GDB 可以访问 `ucontext_t` 中的寄存器值、栈信息等，帮助开发者定位问题。

**详细解释每一个 libc 函数的功能是如何实现的:**

这个头文件本身**没有定义任何 libc 函数**。它只是定义了一个数据结构。 然而，`ucontext_t` 结构体是被以下 libc 函数所使用和操作的：

* **`getcontext(ucontext_t *ucp)`:**  这个函数用于获取当前调用线程的执行上下文，并将其保存在 `ucp` 指向的 `ucontext_t` 结构体中。它会保存当前的栈指针、程序计数器、信号掩码、以及机器相关的寄存器状态。

   **实现原理 (简述):**  `getcontext` 的实现通常会涉及到内联汇编代码，用于直接读取 CPU 的寄存器值并存储到 `ucp->uc_mcontext` 中。栈指针和程序计数器可以通过一些特定的指令获取。信号掩码可以通过系统调用获取。

* **`setcontext(const ucontext_t *ucp)`:** 这个函数用于恢复由 `ucp` 指向的 `ucontext_t` 结构体所描述的执行上下文。调用 `setcontext` 会跳转到 `ucp->uc_mcontext` 中保存的程序计数器指向的地址，并恢复其他寄存器状态和栈。**注意：`setcontext` 不会返回。**

   **实现原理 (简述):** `setcontext` 的实现也主要依赖于内联汇编。它会将 `ucp->uc_mcontext` 中的寄存器值加载到 CPU 寄存器中，并跳转到 `ucp->uc_mcontext` 中的程序计数器指定的地址。恢复栈指针也会涉及到修改 CPU 的栈寄存器。

* **`makecontext(ucontext_t *ucp, void (*func)(void), int argc, ...)` (已废弃，通常不直接使用):**  这个函数用于修改由 `getcontext` 获取的上下文，以便后续可以通过 `setcontext` 跳转到指定的函数 `func` 执行。它会设置新的栈空间、程序计数器和参数。

   **实现原理 (简述):** `makecontext` 会为新的上下文分配栈空间，并将参数传递给目标函数。它会将 `ucp->uc_mcontext` 中的程序计数器设置为 `func` 的地址，并将栈指针设置为新分配的栈顶。

* **`swapcontext(ucontext_t *oucp, const ucontext_t *ucp)`:** 这个函数用于原子地保存当前上下文到 `oucp` 指向的 `ucontext_t` 结构体，并恢复由 `ucp` 指向的 `ucontext_t` 结构体所描述的上下文。

   **实现原理 (简述):** `swapcontext` 的实现是 `getcontext` 和 `setcontext` 的组合，但保证了操作的原子性。它先保存当前上下文到 `oucp`，然后恢复 `ucp` 指向的上下文。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

虽然 `ucontext.handroid` 本身不直接涉及 dynamic linker 的实现，但当 dynamic linker 执行链接过程或者发生错误时，会涉及到上下文的切换和信号处理，这时 `ucontext_t` 就发挥了作用。

**SO 布局样本:**

假设我们有一个简单的共享库 `libexample.so`：

```c
// libexample.c
#include <stdio.h>

void example_function() {
    printf("Hello from libexample.so!\n");
}
```

编译生成 `libexample.so`：

```bash
gcc -shared -fPIC libexample.c -o libexample.so
```

`libexample.so` 的布局大致如下（简化）：

```
.text        # 代码段，包含 example_function 的机器码
.data        # 已初始化数据段
.bss         # 未初始化数据段
.dynsym      # 动态符号表，包含 example_function 的符号信息
.dynstr      # 动态字符串表，包含符号名称
.rel.plt     # PLT 重定位表
.rel.dyn     # 数据段重定位表
...
```

**链接的处理过程 (涉及到 `ucontext_t` 的场景):**

1. **程序启动:** 当一个 Android 应用启动时，`zygote` 进程会 fork 出一个新的进程。
2. **加载器 (loader) 启动:**  内核会将控制权交给 `linker64` (或 `linker`)，这是 Android 的 dynamic linker。
3. **加载共享库:**  如果应用依赖于 `libexample.so`，linker 会找到该共享库并将其加载到进程的内存空间。
4. **符号解析和重定位:**  linker 会解析应用中对 `example_function` 的引用，并在 `libexample.so` 的 `.dynsym` 中找到该符号的地址。然后，它会修改应用代码中的相应位置，将对 `example_function` 的未定义引用替换为 `libexample.so` 中 `example_function` 的实际地址。这个过程称为重定位。
5. **错误处理 (涉及 `ucontext_t`):**  如果在链接过程中发生错误（例如，找不到依赖的共享库，或者符号未定义），linker 可能会触发一个信号 (例如 `SIGSEGV`)。

   **这时 `ucontext_t` 就发挥作用了：**

   * 当信号发生时，内核会创建一个 `ucontext_t` 结构体，其中会包含 linker 当前的执行状态，例如程序计数器（指向发生错误的 linker 代码），栈信息，以及其他寄存器值。
   * 如果有注册了信号处理函数（通常系统会有一个默认的信号处理），该函数会接收到这个 `ucontext_t` 结构体的指针。
   * 崩溃报告机制可以利用 `ucontext_t` 中的信息来生成 linker 的崩溃报告，帮助开发者诊断链接错误。

**链接失败的 SO 布局样本 (假设 `example_function` 未导出):**

如果 `libexample.so` 在编译时没有将 `example_function` 导出为动态符号，那么在链接时就会发生错误。 此时 `libexample.so` 的 `.dynsym` 中可能不会包含 `example_function` 的信息。 当 linker 尝试解析应用中对 `example_function` 的引用时，会在 `libexample.so` 的 `.dynsym` 中找不到该符号，从而导致链接错误。

**假设输入与输出 (逻辑推理):**

**假设输入:**

* 一个 Android 应用 `app` 依赖于共享库 `libmylib.so`。
* `libmylib.so` 中定义了一个函数 `my_function`。
* `app` 的代码中调用了 `my_function`。

**输出 (正常情况):**

* 当 `app` 启动时，dynamic linker 会成功加载 `libmylib.so`。
* linker 会解析 `app` 中对 `my_function` 的引用，并将其重定位到 `libmylib.so` 中 `my_function` 的地址。
* 程序正常执行，当调用 `my_function` 时，会跳转到 `libmylib.so` 中对应的代码。

**输出 (链接错误情况):**

* 如果 `libmylib.so` 不存在，或者 `my_function` 没有被导出，dynamic linker 在链接时会失败。
* 系统可能会发送一个信号给 `app` 进程。
* 信号处理函数可能会收到一个包含 linker 状态的 `ucontext_t` 结构体。
* 可能会打印错误信息，例如 "dlopen failed: cannot find library ..."。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

1. **错误地修改 `ucontext_t`:** 直接修改 `ucontext_t` 结构体中的值，特别是 `uc_mcontext` 中的寄存器值，如果操作不当，可能导致程序行为不可预测，甚至崩溃。例如，错误地修改程序计数器可能导致跳转到无效的内存地址。

   **举例:**  尝试手动修改 `ucontext_t` 中的栈指针，但没有正确地分配和管理新的栈空间。在恢复上下文后，程序可能会写入或读取无效的内存，导致崩溃。

2. **不匹配的上下文切换:**  在某些用户态线程库中，如果错误地使用 `getcontext` 和 `setcontext`，例如，尝试恢复一个从未被正确初始化的上下文，会导致未定义的行为。

3. **信号处理中的不安全操作:** 在信号处理函数中修改了被信号打断的上下文（保存在 `ucontext_t` 中），可能会导致恢复上下文后程序状态不一致。信号处理函数应该尽量避免修改 `ucontext_t`。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework 触发信号:**
   * **Java 代码抛出异常:** 当 Android Framework 的 Java 代码中发生未捕获的异常时，JVM 会将该异常转换为一个信号（例如 `SIGABRT` 或 `SIGSEGV`）。
   * **Native 代码发送信号:**  Framework 或应用的 Native 代码可以通过 `tgkill` 或 `pthread_kill` 等系统调用显式地发送信号给进程或线程。

2. **Kernel 处理信号:**
   * 当进程收到信号时，内核会暂停当前进程的执行。
   * 内核会创建一个新的栈帧，并将信号处理函数的地址压入栈中。
   * **内核会填充 `ucontext_t` 结构体，包含当前线程的寄存器状态、栈信息、信号掩码等。**
   * 内核会调用注册的信号处理函数，并将信号编号和指向 `siginfo_t` 和 `ucontext_t` 结构体的指针作为参数传递给信号处理函数。

3. **信号处理函数执行:**
   * Android Framework 可能会注册一些全局的信号处理函数，例如 `app_crash_handler`。
   * 这个信号处理函数会接收到 `ucontext_t` 指针。
   * 信号处理函数可能会记录崩溃信息，生成 tombstone 文件，或者执行其他清理操作。
   * 崩溃报告机制会利用 `ucontext_t` 中的信息来生成堆栈回溯。

4. **NDK 中的信号:**
   * 当 NDK 代码发生错误，例如空指针解引用，会导致硬件异常，进而被内核转换为信号 (通常是 `SIGSEGV`).
   * 处理流程与 Framework 类似，内核会创建并填充 `ucontext_t`，并调用注册的信号处理函数。

**Frida Hook 示例:**

我们可以使用 Frida Hook `sigaction` 系统调用来查看信号处理函数的注册，或者 Hook 信号处理函数本身来检查 `ucontext_t` 的内容。

**Hook `sigaction`:**

```javascript
if (Process.platform === 'android') {
  const sigactionPtr = Module.findExportByName(null, 'sigaction');
  if (sigactionPtr) {
    Interceptor.attach(sigactionPtr, {
      onEnter: function (args) {
        const signum = args[0].toInt32();
        const act = ptr(args[1]);
        const oldact = ptr(args[2]);

        console.log(`[Sigaction] Signal: ${signum}`);

        const sa_sigaction = act.readPointer(); // 尝试读取 sa_sigaction (函数指针)
        if (!sa_sigaction.isNull()) {
          console.log(`[Sigaction] New handler address: ${sa_sigaction}`);
        }
      }
    });
  } else {
    console.log("Failed to find sigaction");
  }
}
```

这个 Frida 脚本会 Hook `sigaction` 系统调用，并打印注册的信号编号和信号处理函数的地址。

**Hook 信号处理函数 (假设我们知道信号处理函数的地址):**

```javascript
if (Process.platform === 'android') {
  const handlerAddress = ptr("0x..."); // 替换为实际的信号处理函数地址

  Interceptor.attach(handlerAddress, {
    onEnter: function (args) {
      const signum = args[0].toInt32();
      const info = ptr(args[1]);
      const ucontext = ptr(args[2]);

      console.log(`[Signal Handler] Signal: ${signum}`);
      console.log(`[Signal Handler] ucontext: ${ucontext}`);

      // 读取 ucontext_t 中的一些关键信息 (以 ARM64 为例)
      const uc_mcontext_ptr = ucontext.add(Process.pointerSize * 3); // 跳过 uc_flags, uc_link, uc_stack
      const pc = uc_mcontext_ptr.add(Process.pointerSize * 32).readPointer(); // 读取 PC 寄存器
      const sp = uc_mcontext_ptr.add(Process.pointerSize * 31).readPointer(); // 读取 SP 寄存器
      console.log(`[Signal Handler] PC: ${pc}`);
      console.log(`[Signal Handler] SP: ${sp}`);
    }
  });
}
```

这个 Frida 脚本会 Hook 指定地址的信号处理函数，并在进入函数时打印信号编号和 `ucontext_t` 结构体的地址。然后，它会尝试读取 `ucontext_t` 中的程序计数器 (PC) 和栈指针 (SP) 的值。你需要根据具体的架构调整偏移量。

**总结:**

`bionic/libc/include/sys/ucontext.handroid` 定义了关键的 `ucontext_t` 结构体，它是 Android 系统中实现上下文切换、信号处理和错误报告的基础。虽然这个文件本身没有定义函数，但 `ucontext_t` 被 `getcontext`, `setcontext`, `makecontext`, 和 `swapcontext` 等 libc 函数所使用。理解 `ucontext_t` 的结构对于理解 Android 系统底层的运行机制至关重要。 通过 Frida 可以方便地观察和调试涉及 `ucontext_t` 的代码执行过程。

### 提示词
```
这是目录为bionic/libc/include/sys/ucontext.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * Copyright (C) 2014 The Android Open Source Project
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

#pragma once

#include <sys/cdefs.h>

#include <signal.h>
#include <sys/user.h>

__BEGIN_DECLS

#if defined(__arm__)

enum {
  REG_R0 = 0,
#define REG_R0 REG_R0
  REG_R1,
#define REG_R1 REG_R1
  REG_R2,
#define REG_R2 REG_R2
  REG_R3,
#define REG_R3 REG_R3
  REG_R4,
#define REG_R4 REG_R4
  REG_R5,
#define REG_R5 REG_R5
  REG_R6,
#define REG_R6 REG_R6
  REG_R7,
#define REG_R7 REG_R7
  REG_R8,
#define REG_R8 REG_R8
  REG_R9,
#define REG_R9 REG_R9
  REG_R10,
#define REG_R10 REG_R10
  REG_R11,
#define REG_R11 REG_R11
  REG_R12,
#define REG_R12 REG_R12
  REG_R13,
#define REG_R13 REG_R13
  REG_R14,
#define REG_R14 REG_R14
  REG_R15,
#define REG_R15 REG_R15
};

#define NGREG 18 /* Like glibc. */

typedef int greg_t;
typedef greg_t gregset_t[NGREG];
typedef struct user_fpregs fpregset_t;

#include <asm/sigcontext.h>
typedef struct sigcontext mcontext_t;

typedef struct ucontext {
  unsigned long uc_flags;
  struct ucontext* uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  union {
    struct {
      sigset_t uc_sigmask;
      /* Android has a wrong (smaller) sigset_t on ARM. */
      uint32_t __padding_rt_sigset;
    };
    sigset64_t uc_sigmask64;
  };
  /* The kernel adds extra padding after uc_sigmask to match glibc sigset_t on ARM. */
  char __padding[120];
  unsigned long uc_regspace[128] __attribute__((__aligned__(8)));
} ucontext_t;

#elif defined(__aarch64__)

#define NGREG 34 /* x0..x30 + sp + pc + pstate */
typedef unsigned long greg_t;
typedef greg_t gregset_t[NGREG];
typedef struct user_fpsimd_struct fpregset_t;

#include <asm/sigcontext.h>
typedef struct sigcontext mcontext_t;

typedef struct ucontext {
  unsigned long uc_flags;
  struct ucontext *uc_link;
  stack_t uc_stack;
  union {
    sigset_t uc_sigmask;
    sigset64_t uc_sigmask64;
  };
  /* The kernel adds extra padding after uc_sigmask to match glibc sigset_t on ARM64. */
  char __padding[128 - sizeof(sigset_t)];
  mcontext_t uc_mcontext;
} ucontext_t;

#elif defined(__i386__)

enum {
  REG_GS = 0,
#define REG_GS REG_GS
  REG_FS,
#define REG_FS REG_FS
  REG_ES,
#define REG_ES REG_ES
  REG_DS,
#define REG_DS REG_DS
  REG_EDI,
#define REG_EDI REG_EDI
  REG_ESI,
#define REG_ESI REG_ESI
  REG_EBP,
#define REG_EBP REG_EBP
  REG_ESP,
#define REG_ESP REG_ESP
  REG_EBX,
#define REG_EBX REG_EBX
  REG_EDX,
#define REG_EDX REG_EDX
  REG_ECX,
#define REG_ECX REG_ECX
  REG_EAX,
#define REG_EAX REG_EAX
  REG_TRAPNO,
#define REG_TRAPNO REG_TRAPNO
  REG_ERR,
#define REG_ERR REG_ERR
  REG_EIP,
#define REG_EIP REG_EIP
  REG_CS,
#define REG_CS REG_CS
  REG_EFL,
#define REG_EFL REG_EFL
  REG_UESP,
#define REG_UESP REG_UESP
  REG_SS,
#define REG_SS REG_SS
  NGREG
#define NGREG NGREG
};

typedef int greg_t;
typedef greg_t gregset_t[NGREG];

struct _libc_fpreg {
  unsigned short significand[4];
  unsigned short exponent;
};

struct _libc_fpstate {
  unsigned long cw;
  unsigned long sw;
  unsigned long tag;
  unsigned long ipoff;
  unsigned long cssel;
  unsigned long dataoff;
  unsigned long datasel;
  struct _libc_fpreg _st[8];
  unsigned long status;
};

typedef struct _libc_fpstate* fpregset_t;

typedef struct {
  gregset_t gregs;
  fpregset_t fpregs;
  unsigned long oldmask;
  unsigned long cr2;
} mcontext_t;

typedef struct ucontext {
  unsigned long uc_flags;
  struct ucontext* uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  union {
    struct {
      sigset_t uc_sigmask;
      /* Android has a wrong (smaller) sigset_t on x86. */
      uint32_t __padding_rt_sigset;
    };
    sigset64_t uc_sigmask64;
  };
  struct _libc_fpstate __fpregs_mem;
} ucontext_t;

#elif defined(__x86_64__)

enum {
  REG_R8 = 0,
#define REG_R8 REG_R8
  REG_R9,
#define REG_R9 REG_R9
  REG_R10,
#define REG_R10 REG_R10
  REG_R11,
#define REG_R11 REG_R11
  REG_R12,
#define REG_R12 REG_R12
  REG_R13,
#define REG_R13 REG_R13
  REG_R14,
#define REG_R14 REG_R14
  REG_R15,
#define REG_R15 REG_R15
  REG_RDI,
#define REG_RDI REG_RDI
  REG_RSI,
#define REG_RSI REG_RSI
  REG_RBP,
#define REG_RBP REG_RBP
  REG_RBX,
#define REG_RBX REG_RBX
  REG_RDX,
#define REG_RDX REG_RDX
  REG_RAX,
#define REG_RAX REG_RAX
  REG_RCX,
#define REG_RCX REG_RCX
  REG_RSP,
#define REG_RSP REG_RSP
  REG_RIP,
#define REG_RIP REG_RIP
  REG_EFL,
#define REG_EFL REG_EFL
  REG_CSGSFS,
#define REG_CSGSFS REG_CSGSFS
  REG_ERR,
#define REG_ERR REG_ERR
  REG_TRAPNO,
#define REG_TRAPNO REG_TRAPNO
  REG_OLDMASK,
#define REG_OLDMASK REG_OLDMASK
  REG_CR2,
#define REG_CR2 REG_CR2
  NGREG
#define NGREG NGREG
};

typedef long greg_t;
typedef greg_t gregset_t[NGREG];

struct _libc_fpxreg {
  unsigned short significand[4];
  unsigned short exponent;
  unsigned short padding[3];
};

struct _libc_xmmreg {
  uint32_t element[4];
};

struct _libc_fpstate {
  uint16_t cwd;
  uint16_t swd;
  uint16_t ftw;
  uint16_t fop;
  uint64_t rip;
  uint64_t rdp;
  uint32_t mxcsr;
  uint32_t mxcr_mask;
  struct _libc_fpxreg _st[8];
  struct _libc_xmmreg _xmm[16];
  uint32_t padding[24];
};

typedef struct _libc_fpstate* fpregset_t;

typedef struct {
  gregset_t gregs;
  fpregset_t fpregs;
  unsigned long __reserved1[8];
} mcontext_t;

typedef struct ucontext {
  unsigned long uc_flags;
  struct ucontext* uc_link;
  stack_t uc_stack;
  mcontext_t uc_mcontext;
  union {
    sigset_t uc_sigmask;
    sigset64_t uc_sigmask64;
  };
  struct _libc_fpstate __fpregs_mem;
} ucontext_t;

#elif defined(__riscv)

#define NGREG 32

#if defined(__USE_GNU)

enum {
  REG_PC = 0,
#define REG_PC REG_PC
  REG_RA = 1,
#define REG_RA REG_RA
  REG_SP = 2,
#define REG_SP REG_SP
  REG_TP = 4,
#define REG_TP REG_TP
  REG_S0 = 8,
#define REG_S0 REG_S0
  REG_A0 = 10,
#define REG_A0 REG_A0
};

#endif // defined(__USE_GNU)

typedef unsigned long __riscv_mc_gp_state[NGREG];

typedef unsigned long greg_t;
typedef unsigned long gregset_t[NGREG];
typedef union __riscv_mc_fp_state fpregset_t;

/* These match the kernel <asm/ptrace.h> types but with different names. */

struct __riscv_mc_f_ext_state {
  uint32_t __f[32];
  uint32_t __fcsr;
};

struct __riscv_mc_d_ext_state {
  uint64_t __f[32];
  uint32_t __fcsr;
};

struct __riscv_mc_q_ext_state {
  uint64_t __f[64] __attribute__((__aligned__(16)));
  uint32_t __fcsr;
  uint32_t __reserved[3];
};

union __riscv_mc_fp_state {
  struct __riscv_mc_f_ext_state __f;
  struct __riscv_mc_d_ext_state __d;
  struct __riscv_mc_q_ext_state __q;
};

/* This matches the kernel <asm/sigcontext.h> but with different names. */

typedef struct mcontext_t {
  __riscv_mc_gp_state __gregs;
  union __riscv_mc_fp_state __fpregs;
} mcontext_t;

/* This matches the kernel <asm/ucontext.h> but using mcontext_t. */

typedef struct ucontext {
  unsigned long uc_flags;
  struct ucontext* uc_link;
  stack_t uc_stack;
  union {
    sigset_t uc_sigmask;
    sigset64_t uc_sigmask64;
  };
  /* The kernel adds extra padding here to allow sigset_t to grow. */
  char __padding[128 - sizeof(sigset_t)];
  mcontext_t uc_mcontext;
} ucontext_t;

#endif

__END_DECLS
```