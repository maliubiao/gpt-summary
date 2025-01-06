Response:
Let's break down the thought process for analyzing the provided C header file `sigcontext.handroid`.

**1. Understanding the Context:**

The first step is to recognize the context: "bionic/libc/kernel/uapi/asm-x86/asm/sigcontext.handroid". This immediately tells us:

* **bionic:** We're dealing with Android's core C library. This implies a connection to the operating system's low-level functionality.
* **libc:**  Specifically within the C library. This suggests it's related to standard C concepts.
* **kernel/uapi:** This is crucial. "uapi" stands for "user API". This means the structures defined here are the *interface* between user-space programs and the Linux kernel. User-space programs use these definitions to understand data passed to and from the kernel.
* **asm-x86/asm:** This specifies the architecture: x86 (and further differentiated by 32-bit and 64-bit).
* **sigcontext.handroid:** The filename itself strongly hints at its purpose:  it's about the context of a signal. The ".handroid" likely signifies Android-specific adjustments or configurations.

**2. High-Level Purpose Identification:**

Based on the filename and path, the core function is clearly related to **signal handling**. Signals are asynchronous notifications to a process, often due to errors, system events, or user actions (like pressing Ctrl+C). The `sigcontext` structure holds the CPU's state at the moment a signal occurs.

**3. Deconstructing the Structures:**

The next step is to go through each structure definition and understand its components:

* **`_fpx_sw_bytes`:**  The name suggests floating-point extended state, likely related to saving and restoring the state of the floating-point unit (FPU). The `magic1` and `magic2` fields are common for identifying data structures.
* **`_fpreg`, `_fpxreg`, `_xmmreg`:** These clearly represent different types of floating-point registers. `_fpreg` and `_fpxreg` are related to older x87 FPU instructions, while `_xmmreg` represents the newer SSE/AVX registers.
* **`_fpstate_32`, `_fpstate_64`:** These are the core floating-point state structures for 32-bit and 64-bit architectures, respectively. They contain the registers defined above, along with status and control words. The union with padding is a common way to ensure proper alignment or reserve space. The `sw_reserved` member suggests a specific area for software-related information within the FPU state.
* **`_header`:** This structure likely contains metadata about the extended processor state, particularly the `xfeatures` field which indicates which extended features are active.
* **`_ymmh_state`:** Related to AVX instructions, storing the upper halves of the YMM registers.
* **`_xstate`:** This structure combines the basic floating-point state (`_fpstate`) with the extended state information (`_header` and `_ymmh_state`).
* **`sigcontext_32`, `sigcontext_64`:** These are the most important structures. They hold the entire CPU context (general-purpose registers, instruction pointer, stack pointer, flags, etc.) at the time of the signal. The presence of separate 32-bit and 64-bit versions is expected. The `fpstate` member is a pointer to the floating-point state.
* **`sigcontext`:** This is a conditional definition, using preprocessor directives (`#ifdef __i386__`) to select the appropriate `sigcontext_32` or `sigcontext_64` structure based on the architecture.

**4. Identifying Key Functionality:**

From the structure definitions, the core functionality is clearly:

* **Saving and Restoring CPU State:** The `sigcontext` structure is essential for this during signal handling. When a signal arrives, the kernel saves the current process's state into this structure. When the signal handler returns, the kernel restores the state.
* **Managing Floating-Point State:** The `_fpstate` and related structures handle the saving and restoring of the FPU's state. This is crucial because signal handlers might use floating-point operations.
* **Handling Extended Processor State (SSE/AVX):** The `_xstate`, `_ymmh_state`, and related fields support saving and restoring the state of newer processor features like SSE and AVX.

**5. Connecting to Android Functionality:**

Now, bridge the gap between the low-level structures and Android's functionality:

* **Signal Handling in Android:**  Android applications, like any Linux process, rely on signals for various purposes (e.g., receiving notifications, handling errors). The `sigcontext` structure is fundamental to how Android manages these signals.
* **NDK and Native Code:**  Developers using the NDK write native code (C/C++) that directly interacts with the operating system. This code can register signal handlers, and when a signal occurs, the handler receives a pointer to a `sigcontext` structure.
* **Debugging:** Debuggers like GDB and tools like Frida need to understand the CPU state to effectively inspect and manipulate processes. The `sigcontext` structure provides this information.
* **Crash Reporting:** When an application crashes due to a signal (like SIGSEGV), the information in `sigcontext` is crucial for generating crash reports and understanding the cause of the crash.

**6. Explaining Libc Functions (Focus on `signal`, `sigaction`, etc.):**

Think about the standard C library functions that directly interact with signals. `signal()` and `sigaction()` are the primary examples. Explain *how* these functions use the `sigcontext` information internally (though the header file doesn't define the *implementation*, it defines the *data structure* used by the implementation). Mention the role of the kernel in delivering signals and how it populates the `sigcontext`.

**7. Dynamic Linker and Shared Libraries:**

Consider how signals might interact with the dynamic linker. For instance, a signal might occur while the dynamic linker is resolving symbols. In this case, the `sigcontext` would reflect the state of the dynamic linker's code. Create a simple example of a shared library and how the dynamic linker maps it into memory. Explain the linking process conceptually – symbol resolution, relocation.

**8. User/Programming Errors:**

Think about common mistakes developers make related to signal handling:

* **Not restoring the original signal handler:** This can lead to unexpected behavior.
* **Doing unsafe things in signal handlers:**  Signal handlers are executed asynchronously and have restrictions on what functions can be safely called.
* **Incorrectly interpreting the `sigcontext`:**  Understanding the layout and meaning of the fields is crucial.

**9. Frida Hooking Example:**

Provide a concrete Frida example that demonstrates how to access and inspect the `sigcontext` when a signal occurs. This will make the explanation more tangible. Focus on hooking the signal handler registration or the signal delivery mechanism.

**10. Refining and Structuring the Output:**

Finally, organize the information logically, using clear headings and explanations. Provide examples where appropriate. Use precise terminology. Make sure the language is understandable and avoids overly technical jargon where simpler terms suffice. Ensure all parts of the prompt are addressed.

By following this detailed thought process, we can effectively analyze the `sigcontext.handroid` header file and provide a comprehensive explanation of its purpose, functionality, and relationship to Android.这个文件 `bionic/libc/kernel/uapi/asm-x86/asm/sigcontext.handroid` 定义了在 x86 架构下，当进程接收到信号时，内核传递给用户空间的上下文信息结构体 `sigcontext`。这个结构体包含了进程在收到信号那一刻的 CPU 寄存器状态和其他关键信息。由于它位于 `uapi` 目录下，这意味着它是用户空间程序可以直接访问和使用的内核头文件。

**主要功能:**

1. **保存和恢复 CPU 状态:**  `sigcontext` 结构体的主要目的是保存进程在接收到信号时的 CPU 寄存器状态，包括通用寄存器（如 `ax`, `bx`, `cx`, `dx`, `sp`, `bp`, `si`, `di`, `r8`-`r15`），指令指针 (`ip`/`rip`)，标志寄存器 (`flags`/`eflags`)，段寄存器 (`cs`, `ds`, `es`, `fs`, `gs`, `ss`) 等。这样，在信号处理函数执行完毕后，可以将 CPU 的状态恢复到接收信号之前的状态，保证程序的正常执行流程。

2. **保存浮点单元 (FPU) 状态:**  该文件还定义了与浮点数运算相关的结构体，例如 `_fpreg`, `_fpxreg`, `_xmmreg`, `_fpstate_32`, `_fpstate_64`, 和 `_xstate`。这些结构体用于保存和恢复进程的浮点寄存器和相关控制信息。这对于确保在信号处理函数中使用浮点运算不会破坏程序原有的浮点运算状态至关重要。

3. **传递信号相关信息:**  `sigcontext` 结构体还包含了一些与信号本身相关的信息，例如 `trapno`（导致信号的陷阱号）、`err`（错误代码）和 `oldmask`（旧的信号掩码）。

4. **支持不同的 x86 架构:** 文件中定义了 `sigcontext_32` 和 `sigcontext_64` 两个结构体，分别对应 32 位和 64 位 x86 架构，并使用条件编译 `#ifdef __i386__` 来选择使用哪个结构体。

**与 Android 功能的关系及举例:**

`sigcontext.handroid` 中定义的结构体是 Android 操作系统进行信号处理的基础。当 Android 上的一个进程接收到信号时，内核会将进程的当前状态封装到 `sigcontext` 结构体中，并传递给为该信号注册的信号处理函数。

**举例说明:**

* **崩溃处理 (Crash Handling):** 当一个 Android 应用发生崩溃（例如，访问了无效内存地址，触发 SIGSEGV 信号），内核会创建一个包含崩溃时 CPU 状态的 `sigcontext` 结构体。Android 的 runtime (例如 ART 或 Dalvik) 或者崩溃报告机制会捕获这个信号，并利用 `sigcontext` 中的信息来生成崩溃报告，包括导致崩溃的指令地址、寄存器值、堆栈信息等，帮助开发者定位问题。
* **调试器 (Debugger):** 像 `gdb` 或者 Android Studio 的 debugger 在调试 Android 应用时，也需要访问进程的寄存器状态。当程序暂停在断点或者发生信号时，debugger 可以读取 `sigcontext` 结构体中的信息，显示当前的 CPU 状态，方便开发者进行调试。
* **性能分析工具 (Profiling Tools):** 一些性能分析工具可能会利用信号机制来定期采样程序的执行状态。在每次采样时，工具可以访问 `sigcontext` 来获取当时的指令指针，从而分析程序的性能瓶颈。

**详细解释 libc 函数的实现 (与 `sigcontext` 相关的):**

`sigcontext.handroid` 本身是一个数据结构定义文件，并不包含 libc 函数的具体实现代码。然而，libc 中与信号处理相关的函数，例如 `signal()`, `sigaction()`, `sigprocmask()`, `sigsuspend()` 等，都会间接地使用到 `sigcontext` 结构体。

* **`signal(int signum, sighandler_t handler)` 和 `sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)`:** 这些函数用于注册信号处理函数。当指定的信号 `signum` 发生时，内核会调用注册的处理函数 `handler`。内核在调用处理函数时，会将包含当前进程状态的 `sigcontext` 结构体（以及其他信息）作为参数传递给处理函数（尽管通常不直接暴露给用户，而是封装在 `ucontext_t` 中）。

* **`sigprocmask(int how, const sigset_t *set, sigset_t *oldset)`:**  这个函数用于设置和获取进程的信号掩码，控制哪些信号被阻塞。虽然它不直接操作 `sigcontext`，但信号掩码的状态可能会影响信号的处理流程，进而间接地影响到 `sigcontext` 的内容。

* **`sigsuspend(const sigset_t *mask)`:** 这个函数用于原子地用给定的信号掩码替换当前的信号掩码，并暂停进程执行，直到接收到一个信号。当信号处理函数返回时，进程的信号掩码会被恢复到调用 `sigsuspend` 之前的状态。

**实现细节（内核层面，与 `sigcontext` 紧密相关）:**

当一个信号被传递给进程时，内核会执行以下步骤（简化）：

1. **保存当前进程的 CPU 状态:** 内核会将当前进程的寄存器状态（包括通用寄存器、指令指针、标志寄存器、浮点寄存器等）保存到一个 `pt_regs` 结构体（在内核中）和一个或多个用户空间的结构体（例如 `sigcontext` 或封装后的 `ucontext_t`）。

2. **构造信号帧 (Signal Frame):** 内核会在用户空间的栈上创建一个信号帧，用于存放信号处理函数的返回地址、`sigcontext` 结构体、以及其他与信号处理相关的信息。

3. **修改指令指针:** 内核会将进程的指令指针修改为信号处理函数的入口地址。

4. **执行信号处理函数:**  进程开始执行信号处理函数。信号处理函数可以通过 `ucontext_t` 间接地访问到 `sigcontext` 中的信息，例如检查发生信号时的寄存器值。

5. **恢复 CPU 状态:** 当信号处理函数执行完毕并返回时，内核会从信号帧中恢复之前保存的 CPU 状态（主要是通过 `sigreturn` 系统调用），包括恢复指令指针，使得进程可以从接收信号之前的位置继续执行。

**涉及 dynamic linker 的功能及 so 布局样本和链接处理过程:**

虽然 `sigcontext` 本身不直接参与 dynamic linker 的链接过程，但在某些情况下，信号的发生可能与 dynamic linker 的状态有关。例如：

* **在链接过程中发生错误:** 如果在 dynamic linker 加载共享库或者解析符号的过程中发生错误，可能会触发信号（例如 SIGSEGV 如果访问了无效内存）。此时，`sigcontext` 会反映 dynamic linker 代码执行时的状态。

**so 布局样本:**

假设我们有一个简单的共享库 `libexample.so`：

```c
// libexample.c
int add(int a, int b) {
  return a + b;
}
```

编译成共享库：

```bash
gcc -shared -fPIC libexample.c -o libexample.so
```

其在内存中的布局（简化）：

```
[内存地址低端]
...
  ELF Header (libexample.so)
  Program Headers (描述内存段的属性，如可读、可执行)
  .text (代码段，包含 add 函数的机器码)
  .rodata (只读数据段)
  .data (已初始化数据段)
  .bss (未初始化数据段)
  .dynamic (动态链接信息)
  .symtab (符号表)
  .strtab (字符串表)
  .rel.dyn / .rel.plt (重定位表)
...
[内存地址高端]
```

**链接的处理过程:**

1. **加载共享库:** 当程序需要使用 `libexample.so` 中的函数时，dynamic linker（通常是 `/system/bin/linker` 或 `/system/bin/linker64`）会将其加载到进程的地址空间。

2. **符号解析:** 如果程序中调用了 `libexample.so` 中的 `add` 函数，dynamic linker 需要找到 `add` 函数在 `libexample.so` 中的地址。这通过查找 `libexample.so` 的符号表 (`.symtab`) 来完成。

3. **重定位:**  由于共享库被加载到不同的内存地址，其中一些指令和数据引用的地址需要被调整。这个过程称为重定位，dynamic linker 会根据重定位表 (`.rel.dyn` 和 `.rel.plt`) 中的信息修改这些地址。例如，`add` 函数内部可能引用了全局变量，这些引用需要在加载时根据实际的加载地址进行调整。

**假设输入与输出 (针对 `sigcontext`)：**

假设一个程序在调用 `libexample.so` 中的 `add` 函数时，由于某种原因（例如传递了无效的参数导致内部错误），触发了一个信号（例如 SIGSEGV）。

**假设输入:**

* CPU 处于执行 `libexample.so` 中 `add` 函数的指令。
* 寄存器 `rdi` 和 `rsi` 存储了传递给 `add` 函数的参数。
* 寄存器 `rip` 指向 `add` 函数内部导致错误的指令地址。
* 其他寄存器存储了当时的上下文信息。

**输出 (在 `sigcontext` 结构体中):**

* `rip`:  `add` 函数内部导致信号的指令地址。
* `rdi`, `rsi`:  传递给 `add` 函数的参数值。
* 其他通用寄存器 (`rax`, `rbx`, `rcx`, `rdx`, `rbp`, `rsp`, `r8`-`r15`):  在信号发生时的值。
* `eflags`:  标志寄存器的值。
* `cs`, `ss`, `ds`, `es`, `fs`, `gs`:  段寄存器的值。
* `trapno`:  触发的信号编号（例如，SIGSEGV 的编号）。
* `err`:  可能包含与错误相关的附加信息。
* `fpstate`:  指向保存的浮点单元状态的指针。

**用户或编程常见的使用错误:**

1. **在信号处理函数中进行不安全的操作:**  信号处理函数应该尽量简洁，避免执行可能导致重入或死锁的操作，例如调用 `malloc`, `printf` 等非异步信号安全的函数。如果在信号处理函数中访问了与 `sigcontext` 相关的结构体，务必小心处理指针，避免野指针。

2. **错误地理解或解析 `sigcontext`:**  `sigcontext` 的结构和内容是与架构相关的。开发者需要正确理解其字段的含义和布局，才能正确地分析信号发生时的状态。直接修改 `sigcontext` 中的值通常是不安全的，除非你非常清楚自己在做什么。

3. **没有正确恢复信号处理之前的上下文:**  虽然 `sigreturn` 系统调用通常会自动处理状态恢复，但在某些高级的信号处理场景下，如果手动修改了上下文，需要确保正确地恢复。

**Android framework 或 ndk 是如何一步步的到达这里:**

1. **应用层 (Java/Kotlin):**  一个 Android 应用可能因为各种原因触发一个错误，例如空指针异常。

2. **ART/Dalvik 虚拟机:**  虚拟机捕捉到这些错误，并将其转换为 POSIX 信号（例如，空指针异常可能导致 SIGSEGV）。

3. **内核 (Kernel):** 当信号发生时，内核会暂停进程的执行，保存当前的 CPU 状态到内核数据结构中。

4. **查找信号处理函数:** 内核会查找为该信号注册的信号处理函数。如果应用通过 NDK 注册了自定义的信号处理函数（使用 `sigaction` 等），内核会调用该函数。如果没有自定义的处理函数，可能会使用默认的处理方式（例如终止进程）。

5. **构造用户空间上下文:** 内核会将之前保存的 CPU 状态复制到用户空间的 `sigcontext` 结构体中，并将其作为参数传递给信号处理函数（通常是通过 `ucontext_t` 间接传递）。

6. **NDK 信号处理函数:** 如果是通过 NDK 编写的信号处理函数，它可以接收一个 `ucontext_t` 结构体指针作为参数，该结构体包含了 `sigcontext`。

**Frida hook 示例调试这些步骤:**

可以使用 Frida hook 与信号处理相关的函数或者在信号发生时执行的代码，来观察 `sigcontext` 的内容。

```python
import frida
import sys

# 要hook的进程名称或PID
package_name = "your.app.package.name"

session = frida.attach(package_name)

script_code = """
Interceptor.attach(Module.findExportByName(null, "sigaction"), {
    onEnter: function(args) {
        var signum = args[0].toInt32();
        var act = ptr(args[1]);
        var oldact = ptr(args[2]);
        console.log("sigaction called for signal:", signum);
        if (!act.isNull()) {
            var sa_handler = act.readPointer();
            console.log("  sa_handler:", sa_handler);
            // 可以进一步解析 sigaction 结构体的其他成员
        }
    }
});

// Hook 信号处理函数的入口 (这里只是一个示例，实际 hook 点可能需要根据具体情况调整)
// 假设我们知道某个自定义信号处理函数的地址
var signal_handler_address = Module.findExportByName(null, "_my_signal_handler"); // 替换为实际地址

if (signal_handler_address) {
    Interceptor.attach(signal_handler_address, {
        onEnter: function(args) {
            console.log("Signal handler called!");
            var ucontext = ptr(args[0]);
            if (!ucontext.isNull()) {
                // 解析 ucontext_t 结构体来访问 sigcontext
                var uc_mcontext = ucontext.add(8 * 5); // 假设在特定架构下 mcontext 的偏移
                if (!uc_mcontext.isNull()) {
                    console.log("  mcontext:", uc_mcontext);
                    // 根据架构解析 mcontext 中的寄存器信息，例如对于 x86_64
                    var rip = uc_mcontext.add(8 * 16).readU64(); // 假设 rip 的偏移
                    console.log("  RIP:", rip.toString(16));
                    // 读取其他寄存器...
                }
            }
        }
    });
}
"""

script = session.create_script(script_code)

def on_message(message, data):
    print(message)

script.on('message', on_message)
script.load()
sys.stdin.read()
```

**解释 Frida 代码:**

1. **Hook `sigaction`:**  这段代码首先 hook 了 `sigaction` 函数，用于监控应用注册的信号处理函数。这可以帮助我们找到自定义信号处理函数的地址。

2. **Hook 信号处理函数:**  然后，它尝试 hook 一个假设的自定义信号处理函数 `_my_signal_handler`。你需要将其替换为实际的函数名或地址。

3. **解析 `ucontext_t` 和 `sigcontext`:** 在信号处理函数的 `onEnter` 中，我们尝试解析 `ucontext_t` 结构体，从中提取 `sigcontext` 的信息。`ucontext_t` 是一个更高级的上下文结构，通常包含 `sigcontext` 作为其成员。具体的偏移量需要根据目标架构和 Android 版本确定。代码中 `uc_mcontext = ucontext.add(8 * 5)` 和 `rip = uc_mcontext.add(8 * 16).readU64()` 是示例，需要根据实际情况调整。

通过这种方式，你可以在 Frida 中动态地观察当信号发生时，传递给信号处理函数的上下文信息，包括 `sigcontext` 中的寄存器状态，从而调试信号处理流程。

请注意，直接操作或修改 `sigcontext` 中的值通常是不推荐的，除非你对信号处理机制有深入的理解，并且知道自己在做什么。错误的操作可能导致程序崩溃或其他不可预测的行为。 这个头文件的主要作用是定义数据结构，供内核和用户空间程序理解信号处理期间的上下文信息。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/asm-x86/asm/sigcontext.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
 * This file is auto-generated. Modifications will be lost.
 *
 * See https://android.googlesource.com/platform/bionic/+/master/libc/kernel/
 * for more information.
 */
#ifndef _UAPI_ASM_X86_SIGCONTEXT_H
#define _UAPI_ASM_X86_SIGCONTEXT_H
#include <linux/compiler.h>
#include <linux/types.h>
#define FP_XSTATE_MAGIC1 0x46505853U
#define FP_XSTATE_MAGIC2 0x46505845U
#define FP_XSTATE_MAGIC2_SIZE sizeof(FP_XSTATE_MAGIC2)
struct _fpx_sw_bytes {
  __u32 magic1;
  __u32 extended_size;
  __u64 xfeatures;
  __u32 xstate_size;
  __u32 padding[7];
};
struct _fpreg {
  __u16 significand[4];
  __u16 exponent;
};
struct _fpxreg {
  __u16 significand[4];
  __u16 exponent;
  __u16 padding[3];
};
struct _xmmreg {
  __u32 element[4];
};
#define X86_FXSR_MAGIC 0x0000
struct _fpstate_32 {
  __u32 cw;
  __u32 sw;
  __u32 tag;
  __u32 ipoff;
  __u32 cssel;
  __u32 dataoff;
  __u32 datasel;
  struct _fpreg _st[8];
  __u16 status;
  __u16 magic;
  __u32 _fxsr_env[6];
  __u32 mxcsr;
  __u32 reserved;
  struct _fpxreg _fxsr_st[8];
  struct _xmmreg _xmm[8];
  union {
    __u32 padding1[44];
    __u32 padding[44];
  };
  union {
    __u32 padding2[12];
    struct _fpx_sw_bytes sw_reserved;
  };
};
struct _fpstate_64 {
  __u16 cwd;
  __u16 swd;
  __u16 twd;
  __u16 fop;
  __u64 rip;
  __u64 rdp;
  __u32 mxcsr;
  __u32 mxcsr_mask;
  __u32 st_space[32];
  __u32 xmm_space[64];
  __u32 reserved2[12];
  union {
    __u32 reserved3[12];
    struct _fpx_sw_bytes sw_reserved;
  };
};
#ifdef __i386__
#define _fpstate _fpstate_32
#else
#define _fpstate _fpstate_64
#endif
struct _header {
  __u64 xfeatures;
  __u64 reserved1[2];
  __u64 reserved2[5];
};
struct _ymmh_state {
  __u32 ymmh_space[64];
};
struct _xstate {
  struct _fpstate fpstate;
  struct _header xstate_hdr;
  struct _ymmh_state ymmh;
};
struct sigcontext_32 {
  __u16 gs, __gsh;
  __u16 fs, __fsh;
  __u16 es, __esh;
  __u16 ds, __dsh;
  __u32 di;
  __u32 si;
  __u32 bp;
  __u32 sp;
  __u32 bx;
  __u32 dx;
  __u32 cx;
  __u32 ax;
  __u32 trapno;
  __u32 err;
  __u32 ip;
  __u16 cs, __csh;
  __u32 flags;
  __u32 sp_at_signal;
  __u16 ss, __ssh;
  __u32 fpstate;
  __u32 oldmask;
  __u32 cr2;
};
struct sigcontext_64 {
  __u64 r8;
  __u64 r9;
  __u64 r10;
  __u64 r11;
  __u64 r12;
  __u64 r13;
  __u64 r14;
  __u64 r15;
  __u64 di;
  __u64 si;
  __u64 bp;
  __u64 bx;
  __u64 dx;
  __u64 ax;
  __u64 cx;
  __u64 sp;
  __u64 ip;
  __u64 flags;
  __u16 cs;
  __u16 gs;
  __u16 fs;
  __u16 ss;
  __u64 err;
  __u64 trapno;
  __u64 oldmask;
  __u64 cr2;
  __u64 fpstate;
  __u64 reserved1[8];
};
#define _fpstate_ia32 _fpstate_32
#define sigcontext_ia32 sigcontext_32
#ifdef __i386__
struct sigcontext {
  __u16 gs, __gsh;
  __u16 fs, __fsh;
  __u16 es, __esh;
  __u16 ds, __dsh;
  __u32 edi;
  __u32 esi;
  __u32 ebp;
  __u32 esp;
  __u32 ebx;
  __u32 edx;
  __u32 ecx;
  __u32 eax;
  __u32 trapno;
  __u32 err;
  __u32 eip;
  __u16 cs, __csh;
  __u32 eflags;
  __u32 esp_at_signal;
  __u16 ss, __ssh;
  struct _fpstate  * fpstate;
  __u32 oldmask;
  __u32 cr2;
};
#else
struct sigcontext {
  __u64 r8;
  __u64 r9;
  __u64 r10;
  __u64 r11;
  __u64 r12;
  __u64 r13;
  __u64 r14;
  __u64 r15;
  __u64 rdi;
  __u64 rsi;
  __u64 rbp;
  __u64 rbx;
  __u64 rdx;
  __u64 rax;
  __u64 rcx;
  __u64 rsp;
  __u64 rip;
  __u64 eflags;
  __u16 cs;
  __u16 gs;
  __u16 fs;
  union {
    __u16 ss;
    __u16 __pad0;
  };
  __u64 err;
  __u64 trapno;
  __u64 oldmask;
  __u64 cr2;
  struct _fpstate  * fpstate;
#ifdef __ILP32__
  __u32 __fpstate_pad;
#endif
  __u64 reserved1[8];
};
#endif
#endif

"""

```