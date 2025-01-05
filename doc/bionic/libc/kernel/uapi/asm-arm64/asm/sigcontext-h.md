Response:
Let's break down the thought process for analyzing the `sigcontext.handroid` file.

**1. Understanding the Context:**

The initial prompt provides crucial context:

* **File Location:** `bionic/libc/kernel/uapi/asm-arm64/asm/sigcontext.handroid`
* **Project:** Bionic, Android's C library, math library, and dynamic linker.
* **Purpose:**  The "uapi" part strongly suggests this file defines user-space API structures related to kernel data. The "asm-arm64" indicates it's for the ARM64 architecture. "sigcontext" points to signal handling.

**2. Initial Scan and Keyword Identification:**

A quick read-through reveals key terms and patterns:

* `struct sigcontext`: This is the main structure, likely containing general register information.
* `fpsimd_context`, `esr_context`, `poe_context`, `extra_context`, `sve_context`, `tpidr2_context`, `fpmr_context`, `za_context`, `zt_context`: These look like specialized contexts, probably for different processor features or states. The `_context` suffix reinforces this.
* `MAGIC`:  Constants like `FPSIMD_MAGIC` suggest these structures might be tagged for identification.
* `__u64`, `__u32`, `__u16`, `__u8`, `__uint128_t`: These are size-specific integer types, hinting at memory layout.
* `regs`, `sp`, `pc`, `pstate`, `fault_address`: These are clearly CPU register names.
* `sve`, `za`, `zt`:  These are likely extensions to the ARM architecture.
* `#ifndef _UAPI__ASM_SIGCONTEXT_H`, `#define _UAPI__ASM_SIGCONTEXT_H`, `#ifndef __ASSEMBLY__`:  Standard header file guards to prevent multiple inclusions.
* `#include <linux/types.h>`, `#include <asm/sve_context.h>`: Inclusion of other header files, indicating dependencies.
* `__attribute__((__aligned__(16)))`:  Specifies memory alignment requirements.
* Macros like `SVE_VQ_BYTES`, `SVE_SIG_REGS_OFFSET`, etc.: These are used for calculating sizes and offsets within the `sve_context` and related structures.

**3. Deconstructing the Structures and Their Purposes:**

Now, let's examine each structure more closely and infer its function:

* **`sigcontext`:**  Likely holds the core register state of a thread at the point a signal was received. `fault_address` suggests information about memory access errors. `regs`, `sp`, `pc`, `pstate` are essential for resuming execution.

* **Specialized Contexts (`fpsimd_context`, etc.):**  The "MAGIC" numbers and specific fields suggest these are used to save and restore the state of optional or advanced CPU features during signal handling.

    * `fpsimd_context`:  Floating-point and SIMD registers (`fpsr`, `fpcr`, `vregs`).
    * `esr_context`: Exception Syndrome Register (`esr`), crucial for understanding the cause of exceptions.
    * `poe_context`: Process State Override (`por_el0`), related to security and privilege levels.
    * `extra_context`:  Additional data (`datap`, `size`). The name suggests it holds supplemental information.
    * `sve_context`, `za_context`, `zt_context`:  These are clearly related to the Scalable Vector Extension (SVE) and its associated features (Scalable Matrix Extension (SME) with ZA and ZT). They contain vector length (`vl`), flags, and potentially the vector register data itself (though some are defined with offsets).
    * `tpidr2_context`: Thread Pointer ID Register (user space) - useful for thread-local storage.
    * `fpmr_context`: Floating-Point Mask Register (`fpmr`).

**4. Analyzing Macros and Their Implications:**

The macros are primarily involved in calculating the size and offset of different parts of the `sve_context`, `za_context`, and `zt_context`. This is essential for:

* **Memory Management:**  Knowing the exact size needed to store the context.
* **Data Access:**  Precisely locating the different register sets within the saved context.
* **Kernel/Userspace Interaction:** Ensuring consistent interpretation of the memory layout.

The alignment macro `__attribute__((__aligned__(16)))` in `sigcontext` is crucial for performance, ensuring efficient memory access.

**5. Connecting to Android and Bionic:**

This file is part of Bionic, so its connection to Android is direct. Specifically, it's used in:

* **Signal Handling:** When a signal is delivered to a process, the kernel saves the current thread's state into a `sigcontext` structure (and potentially other context structures). This allows the signal handler to run and, optionally, for the interrupted process to resume execution later.
* **Exception Handling:** Similar to signals, exceptions (like segmentation faults) can lead to saving the context.
* **Debugging:** Debuggers (like GDB or those used by Android Studio) rely on these structures to inspect the state of a program when it's paused or crashes.
* **Process Management:** The kernel uses this information when switching between processes.

**6. Considering Dynamic Linking (and acknowledging limitations):**

While the file itself doesn't *directly* implement dynamic linking, the saved register state is *critical* for the dynamic linker's operation. When a shared library is loaded or unloaded, or when functions in shared libraries are called, the program's registers need to be managed correctly. The `sigcontext` plays a role in preserving and restoring this state during these transitions. *However*, this file doesn't contain the *code* of the dynamic linker.

**7. Considering Potential Errors:**

Common errors might involve:

* **Incorrectly interpreting the `sigcontext` data:**  Trying to access registers at the wrong offsets.
* **Modifying the `sigcontext` in a signal handler incorrectly:**  This can lead to unpredictable behavior when the process resumes.
* **Not considering the alignment requirements.**

**8. Thinking About the Journey from Framework/NDK to this File:**

The path involves:

1. **Framework/NDK Action:** An event triggers a signal (e.g., a Java exception leading to a native signal, a deliberate `kill()` call, a hardware fault).
2. **Kernel Intervention:** The kernel intercepts the signal.
3. **Context Saving:** The kernel saves the thread's state, populating the `sigcontext` and other related structures. This is where the definitions in this file are *used*.
4. **Signal Handler Invocation:** The kernel jumps to the registered signal handler. The `sigcontext` (or a pointer to it) is often passed as an argument to the handler.

**9. Frida Hooking (Conceptual):**

To hook, you'd target the system call or kernel function responsible for delivering signals and saving the context. You'd need to understand the kernel's internal structures and how they map to the `sigcontext`. A high-level idea would be to hook a function like `do_signal` in the kernel.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:**  Maybe the `extra_context` is for user-defined data. **Correction:**  While possible, its name suggests it's still related to system-level context, just "extra" to the main registers.
* **Initial thought:** Focus heavily on *implementing* dynamic linking within this file. **Correction:** Realized this file defines *data structures* used *by* the dynamic linker and kernel, not the linker's logic itself. Shifted focus to how the saved context is relevant to linking.
* **Realization about macro complexity:** Initially underestimated the purpose of the SVE/ZA/ZT macros. Realized they're crucial for handling the variable-length nature of these extensions.

By following this structured approach, combining code analysis with contextual knowledge, and iteratively refining understanding, we can arrive at a comprehensive explanation of the `sigcontext.handroid` file.
这是一个定义了与信号处理相关的上下文数据结构的头文件，专门用于 ARM64 架构的 Android 系统。它定义了在发生信号时，需要保存和恢复的处理器状态信息。

**主要功能:**

1. **定义信号上下文结构体 `sigcontext`:**  这是最核心的结构体，用于保存发生信号时的 CPU 寄存器状态。这使得在信号处理程序执行完毕后，程序可以恢复到中断前的状态继续执行。
2. **定义扩展上下文结构体 (例如 `fpsimd_context`, `esr_context`, `sve_context` 等):**  这些结构体用于保存更细粒度的处理器状态，例如浮点和 SIMD 寄存器、异常状态寄存器、以及 SVE (Scalable Vector Extension) 相关的寄存器状态。这些是可选的，只有在使用了对应功能时才会被保存。
3. **定义魔数 (Magic Numbers):** 每个扩展上下文结构体都有一个关联的魔数（例如 `FPSIMD_MAGIC`），用于在内存中识别不同的上下文类型。
4. **定义宏 (Macros):**  提供了一些宏来计算 SVE、ZA 和 ZT 上下文结构体的大小和内部偏移量，这在处理可变长度的 SVE 寄存器时非常重要。

**与 Android 功能的关系及举例说明:**

这个文件是 Android Bionic 库的一部分，与 Android 的信号处理机制紧密相关。信号是 Unix-like 系统中进程间通信和进程与内核通信的重要方式。

* **信号处理:** 当 Android 进程接收到一个信号 (例如 `SIGSEGV` 内存错误，`SIGINT` Ctrl+C 中断)，操作系统需要暂停进程的执行，并调用相应的信号处理函数。为了能够让信号处理函数执行完毕后，进程能恢复到中断前的状态，就需要保存当时的 CPU 状态。`sigcontext` 结构体就是用来存储这些关键状态的。

   **举例:**  一个 Android 应用访问了非法内存地址，导致内核发送 `SIGSEGV` 信号给该应用。内核会填充 `sigcontext` 结构体，包括导致错误的内存地址 (`fault_address`)，以及当时的寄存器值 (`regs`, `sp`, `pc`, `pstate`)。然后，内核会调用应用注册的 `SIGSEGV` 信号处理函数，并将 `sigcontext` 信息传递给它（通常是通过 `ucontext_t` 结构体，其中包含了 `sigcontext`）。如果信号处理函数返回，内核会使用 `sigcontext` 中的信息恢复应用的执行。

* **异常处理:**  类似于信号，当发生硬件异常或软件异常时，也需要保存上下文信息。例如，浮点运算异常可能会导致保存 `fpsimd_context`。

* **调试:**  调试器 (例如 GDB 或 Android Studio 的调试器) 在调试 Android 应用时，也需要访问这些上下文信息来了解程序的状态，例如查看寄存器值，当前执行的指令地址等。

**详细解释 libc 函数的功能是如何实现的:**

这个头文件本身 **并不包含任何 libc 函数的实现代码**。它只是定义了数据结构。libc 中处理信号相关的函数（例如 `signal`, `sigaction`, `sigprocmask`, `pthread_sigmask` 等）的实现会用到这些数据结构。

这些 libc 函数的功能大致如下：

* **`signal(int signum, sighandler_t handler)`:**  用于注册一个信号的处理函数。当指定的信号 `signum` 发生时，调用 `handler` 函数。内核在传递信号时，会使用 `sigcontext` 保存进程状态。
* **`sigaction(int signum, const struct sigaction *act, struct sigaction *oldact)`:**  比 `signal` 更强大和灵活的信号处理函数。它允许更细致地控制信号的处理方式，包括指定信号处理掩码、是否在信号处理期间重置处理方式等。同样，内核在处理信号时会用到 `sigcontext`。
* **`sigprocmask(int how, const sigset_t *set, sigset_t *oldset)`:**  用于屏蔽或取消屏蔽某些信号，控制哪些信号会被进程接收。
* **`pthread_sigmask(int how, const sigset_t *set, sigset_t *oldset)`:**  类似于 `sigprocmask`，但作用于线程。

**实现细节 (内核层面，非 libc 函数本身):**

当信号发生时，内核会执行以下步骤（简化版）：

1. **保存上下文:** 内核会分配内存，并将当前进程或线程的 CPU 寄存器状态保存到 `sigcontext` 结构体中。如果需要，还会保存其他扩展上下文信息（例如浮点寄存器、SVE 寄存器等）。
2. **查找信号处理函数:** 内核会根据信号的类型，查找进程或线程注册的信号处理函数。
3. **准备调用信号处理函数:** 内核会创建一个新的栈帧，并将一些参数传递给信号处理函数，包括信号编号和指向 `ucontext_t` 结构体的指针。`ucontext_t` 结构体中包含了保存的 `sigcontext` 信息。
4. **执行信号处理函数:** 内核跳转到信号处理函数的入口地址开始执行。
5. **恢复上下文 (如果信号处理函数返回):** 当信号处理函数执行完毕并返回后，内核会使用之前保存的 `sigcontext` 信息恢复进程或线程的 CPU 状态。这包括恢复寄存器值、程序计数器等，使得进程可以从中断的地方继续执行。

**对于涉及 dynamic linker 的功能，请给对应的 so 布局样本，以及链接的处理过程:**

这个头文件本身 **不直接涉及 dynamic linker 的具体实现**。但是，dynamic linker (例如 Android 的 `linker64`) 的运行和信号处理之间存在一些间接关系。

**so 布局样本:**

一个典型的 Android shared object (`.so`) 文件的布局可能如下：

```
ELF Header
Program Headers (描述内存段，例如 .text, .data, .dynamic)
Section Headers (描述节，例如 .symtab, .strtab, .rel.dyn, .rel.plt)

.text          (代码段)
.rodata        (只读数据段)
.data          (可读写数据段)
.bss           (未初始化数据段)
.dynamic       (动态链接信息，例如依赖的库，符号表位置)
.symtab        (符号表)
.strtab        (字符串表)
.rel.dyn       (数据重定位表)
.rel.plt       (过程链接表重定位)
... 其他节 ...
```

**链接的处理过程:**

当一个程序启动或者加载一个共享库时，dynamic linker 负责以下主要任务：

1. **加载共享库:** 将共享库的代码和数据段加载到进程的地址空间。
2. **符号解析:**  解决程序和共享库之间的符号引用。例如，程序中调用了一个共享库中的函数，dynamic linker 需要找到该函数的地址。
3. **重定位:**  由于共享库被加载到内存的哪个地址是不确定的（地址空间布局随机化 - ASLR），dynamic linker 需要修改代码和数据中的地址引用，使其指向正确的内存位置。

**`sigcontext` 与 dynamic linker 的间接关系:**

* **在动态链接过程中发生错误:** 如果 dynamic linker 在加载或链接共享库的过程中遇到错误（例如找不到依赖的库，符号未定义），可能会导致进程接收到信号，例如 `SIGSEGV` 或 `SIGABRT`。此时，`sigcontext` 会保存 dynamic linker 运行时的状态。
* **在共享库的代码中发生信号:**  如果信号发生在共享库的代码执行期间，`sigcontext` 会包含共享库中的代码地址和寄存器状态。

**由于这个头文件只定义了数据结构，并没有具体的 dynamic linker 代码，所以无法直接展示链接的处理过程。**  链接的处理过程主要发生在 `linker64` 进程的代码中。

**如果做了逻辑推理，请给出假设输入与输出:**

这个头文件主要定义数据结构，本身不涉及逻辑推理。但是，可以假设在信号处理过程中，内核使用这些结构体进行数据存取。

**假设输入:**

一个 `sigcontext` 结构体在信号发生时被内核填充，其部分字段的值如下：

```
fault_address = 0x0000007fffffffff00  // 导致错误的内存地址
regs[30] = 0x0000007ffff7a00000  // LR (链接寄存器) 的值
pc = 0x0000007ffff7a01234     // 程序计数器 (发生信号时的指令地址)
```

**输出 (推断):**

根据这些输入，可以推断出：

* 进程尝试访问地址 `0x0000007fffffffff00` 时发生了错误。
* 在信号发生前，程序正在执行地址 `0x0000007ffff7a01234` 的指令。
* 函数调用链中，上一个返回地址被保存在寄存器 `regs[30]` (LR) 中，值为 `0x0000007ffff7a00000`。

**如果涉及用户或者编程常见的使用错误，请举例说明:**

虽然这个文件本身不是用户直接操作的，但了解其背后的原理可以帮助避免与信号处理相关的错误。

1. **在信号处理函数中修改 `sigcontext` 不当:**  用户可以编写信号处理函数，并且可以通过 `ucontext_t` 访问到 `sigcontext`。 **错误的做法是随意修改 `sigcontext` 中的值，特别是 `pc` (程序计数器) 和 `sp` (栈指针)**。  这样做可能导致程序行为不可预测，甚至崩溃。

   **错误示例 (假设在信号处理函数中):**

   ```c
   #include <ucontext.h>

   void signal_handler(int signum, siginfo_t *info, void *context) {
       ucontext_t *uc = (ucontext_t *)context;
       // 错误：尝试跳转到任意地址
       uc->uc_mcontext.pc = 0x12345678;
   }
   ```

2. **不理解信号处理的异步性:** 信号是异步发生的，信号处理函数可能会在程序执行的任意时刻被调用。如果在信号处理函数中访问了主线程中正在操作的数据，可能会导致数据竞争和未定义行为。

3. **在信号处理函数中使用非线程安全函数:**  信号处理函数中应该只使用异步信号安全 (async-signal-safe) 的函数。调用非线程安全的函数（例如 `printf`, `malloc`）可能导致死锁或崩溃。

**说明 android framework or ndk 是如何一步步的到达这里，给出 frida hook 示例调试这些步骤。**

1. **Android Framework / NDK 层操作:**  一个事件在 Android Framework 或 NDK 层发生，最终导致一个信号的产生。这可能是：
   * **Java 层异常导致 native crash:**  Java 代码抛出异常，而 native 代码没有正确处理，最终导致 native crash 并产生 `SIGSEGV` 等信号。
   * **NDK 代码主动触发信号:**  开发者在 NDK 代码中使用 `raise()` 或 `kill()` 函数发送信号。
   * **系统事件:**  例如，进程接收到 `SIGCHLD` 信号，表明子进程状态发生变化。

2. **Binder 调用 (Framework -> Native):**  如果事件发生在 Framework 层，通常会通过 Binder 机制调用到 Native 层。

3. **Native 代码执行:** Native 代码执行过程中，如果发生错误或主动触发信号。

4. **内核信号处理:**
   * 当信号发生时，内核会暂停当前进程或线程的执行。
   * 内核会查找该信号对应的处理方式（用户自定义的信号处理函数，或默认处理方式）。
   * **内核填充 `sigcontext`:**  这是关键步骤。内核会将当前进程或线程的 CPU 寄存器状态，包括通用寄存器、PC、SP、CPSR 等，填充到 `sigcontext` 结构体中。如果涉及到浮点或 SIMD 操作，还会填充相应的扩展上下文结构体。
   * **调用信号处理函数:** 如果用户注册了信号处理函数，内核会创建一个新的栈帧，并将包含 `sigcontext` 信息的 `ucontext_t` 结构体作为参数传递给信号处理函数。

5. **信号处理函数执行 (可选):** 用户自定义的信号处理函数被执行。

6. **恢复执行 (如果信号处理函数返回):** 如果信号处理函数返回，内核会使用 `sigcontext` 中的信息恢复进程或线程的执行。

**Frida Hook 示例:**

可以使用 Frida hook 内核中处理信号的关键函数，来观察 `sigcontext` 的填充过程。由于这涉及到内核级别的操作，需要 root 权限。

以下是一个使用 Frida C API 的概念性示例 (可能需要根据具体的内核版本进行调整):

```c
#include <frida-core.h>
#include <stdio.h>

static void on_message (FridaSession *session, FridaMessage *message, gpointer user_data) {
  // 处理 Frida 发送的消息
  if (FRIDA_IS_SCRIPT_MESSAGE (message)) {
    FridaScriptMessage *script_message = FRIDA_SCRIPT_MESSAGE (message);
    const gchar *text = frida_script_message_get_text (script_message);
    printf("收到消息: %s\n", text);
  }
}

int main (int argc, char *argv[]) {
  GError *error = NULL;
  FridaDeviceManager *manager = frida_device_manager_new ();
  FridaDevice *device = frida_device_manager_get_device_sync (manager, FRIDA_DEVICE_TYPE_LOCAL, 1000, NULL);
  if (device == NULL) {
    g_printerr("无法连接到设备\n");
    return 1;
  }

  FridaSession *session = frida_device_attach_sync (device, 0, NULL, &error);
  if (session == NULL) {
    g_printerr("无法附加到进程: %s\n", error->message);
    g_error_free(error);
    g_object_unref(device);
    g_object_unref(manager);
    return 1;
  }

  frida_session_on_message (session, on_message, NULL);

  // Frida Script，用于 hook 内核函数并打印 sigcontext 信息
  const gchar *script_source =
    "Interceptor.attach(ptr('" KERNEL_SIGNAL_HANDLER_ADDRESS "'), {\n" // 替换为实际的内核信号处理函数地址
    "  onEnter: function (args) {\n"
    "    console.log(\"进入内核信号处理函数\");\n"
    "    let sig = args[0].toInt();\n"
    "    let info = ptr(args[1]);\n"
    "    let ucontextPtr = ptr(args[2]);\n"
    "    console.log(\"信号: \" + sig);\n"
    "    console.log(\"siginfo_t: \" + info);\n"
    "    console.log(\"ucontext_t 指针: \" + ucontextPtr);\n"
    "    if (ucontextPtr.isNull() === false) {\n"
    "      let sigcontextPtr = ucontextPtr.add(offsetof( 'ucontext_t', 'uc_mcontext' )); // 假设 uc_mcontext 是 sigcontext\n"
    "      console.log(\"sigcontext 指针: \" + sigcontextPtr);\n"
    "      // 读取 sigcontext 的一些字段\n"
    "      console.log(\"fault_address: \" + sigcontextPtr.readU64());\n"
    "      console.log(\"pc: \" + sigcontextPtr.add(8 * 31).readU64()); // 假设 pc 是 regs 之后\n"
    "    }\n"
    "  }\n"
    "});\n";

  FridaScript *script = frida_session_create_script_sync (session, script_source, NULL, &error);
  if (script == NULL) {
    g_printerr("创建脚本失败: %s\n", error->message);
    g_error_free(error);
    g_object_unref(session);
    g_object_unref(device);
    g_object_unref(manager);
    return 1;
  }

  frida_script_load_sync (script, NULL, &error);
  if (error != NULL) {
    g_printerr("加载脚本失败: %s\n", error->message);
    g_error_free(error);
    g_object_unref(script);
    g_object_unref(session);
    g_object_unref(device);
    g_object_unref(manager);
    return 1;
  }

  // 等待直到手动停止
  getchar();

  frida_script_unload_sync (script, NULL);
  g_object_unref(script);
  frida_session_detach_sync (session, NULL);
  g_object_unref(session);
  g_object_unref(device);
  g_object_unref(manager);

  return 0;
}
```

**关键点:**

* **`KERNEL_SIGNAL_HANDLER_ADDRESS`:**  你需要找到内核中实际处理信号的函数的地址。这取决于 Android 的内核版本。可以使用 `adb shell cat /proc/kallsyms` 来查找可能的函数名，例如 `do_signal`, `__do_sys_sigaltstack` 等。
* **`offsetof`:**  Frida 的 JavaScript API 中没有直接的 `offsetof`，你可能需要手动计算 `sigcontext` 字段的偏移量，或者使用 CModule 在 Native 代码中计算并传递给 JavaScript。
* **`ucontext_t`:**  信号处理函数通常会接收到一个 `ucontext_t` 结构体的指针，其中包含了 `sigcontext` 信息。你需要了解 `ucontext_t` 的结构来访问 `sigcontext`。

**使用步骤:**

1. 确保你的 Android 设备已 root 并安装了 Frida 服务。
2. 编译上述 C 代码并 push 到设备上。
3. 运行编译后的程序。
4. 在设备上触发一个会导致信号产生的操作 (例如，运行一个会 crash 的应用)。
5. 查看 Frida 的输出，它会打印出进入内核信号处理函数时的 `sigcontext` 相关信息。

请注意，hook 内核函数需要深入的了解内核结构，并且有一定的风险。在生产环境中应谨慎操作。 这个示例仅用于调试和学习目的。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/asm-arm64/asm/sigcontext.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__ASM_SIGCONTEXT_H
#define _UAPI__ASM_SIGCONTEXT_H
#ifndef __ASSEMBLY__
#include <linux/types.h>
struct sigcontext {
  __u64 fault_address;
  __u64 regs[31];
  __u64 sp;
  __u64 pc;
  __u64 pstate;
  __u8 __reserved[4096] __attribute__((__aligned__(16)));
};
struct _aarch64_ctx {
  __u32 magic;
  __u32 size;
};
#define FPSIMD_MAGIC 0x46508001
struct fpsimd_context {
  struct _aarch64_ctx head;
  __u32 fpsr;
  __u32 fpcr;
  __uint128_t vregs[32];
};
#define ESR_MAGIC 0x45535201
struct esr_context {
  struct _aarch64_ctx head;
  __u64 esr;
};
#define POE_MAGIC 0x504f4530
struct poe_context {
  struct _aarch64_ctx head;
  __u64 por_el0;
};
#define EXTRA_MAGIC 0x45585401
struct extra_context {
  struct _aarch64_ctx head;
  __u64 datap;
  __u32 size;
  __u32 __reserved[3];
};
#define SVE_MAGIC 0x53564501
struct sve_context {
  struct _aarch64_ctx head;
  __u16 vl;
  __u16 flags;
  __u16 __reserved[2];
};
#define SVE_SIG_FLAG_SM 0x1
#define TPIDR2_MAGIC 0x54504902
struct tpidr2_context {
  struct _aarch64_ctx head;
  __u64 tpidr2;
};
#define FPMR_MAGIC 0x46504d52
struct fpmr_context {
  struct _aarch64_ctx head;
  __u64 fpmr;
};
#define ZA_MAGIC 0x54366345
struct za_context {
  struct _aarch64_ctx head;
  __u16 vl;
  __u16 __reserved[3];
};
#define ZT_MAGIC 0x5a544e01
struct zt_context {
  struct _aarch64_ctx head;
  __u16 nregs;
  __u16 __reserved[3];
};
#endif
#include <asm/sve_context.h>
#define SVE_VQ_BYTES __SVE_VQ_BYTES
#define SVE_VQ_MIN __SVE_VQ_MIN
#define SVE_VQ_MAX __SVE_VQ_MAX
#define SVE_VL_MIN __SVE_VL_MIN
#define SVE_VL_MAX __SVE_VL_MAX
#define SVE_NUM_ZREGS __SVE_NUM_ZREGS
#define SVE_NUM_PREGS __SVE_NUM_PREGS
#define sve_vl_valid(vl) __sve_vl_valid(vl)
#define sve_vq_from_vl(vl) __sve_vq_from_vl(vl)
#define sve_vl_from_vq(vq) __sve_vl_from_vq(vq)
#define SVE_SIG_ZREG_SIZE(vq) __SVE_ZREG_SIZE(vq)
#define SVE_SIG_PREG_SIZE(vq) __SVE_PREG_SIZE(vq)
#define SVE_SIG_FFR_SIZE(vq) __SVE_FFR_SIZE(vq)
#define SVE_SIG_REGS_OFFSET ((sizeof(struct sve_context) + (__SVE_VQ_BYTES - 1)) / __SVE_VQ_BYTES * __SVE_VQ_BYTES)
#define SVE_SIG_ZREGS_OFFSET (SVE_SIG_REGS_OFFSET + __SVE_ZREGS_OFFSET)
#define SVE_SIG_ZREG_OFFSET(vq,n) (SVE_SIG_REGS_OFFSET + __SVE_ZREG_OFFSET(vq, n))
#define SVE_SIG_ZREGS_SIZE(vq) __SVE_ZREGS_SIZE(vq)
#define SVE_SIG_PREGS_OFFSET(vq) (SVE_SIG_REGS_OFFSET + __SVE_PREGS_OFFSET(vq))
#define SVE_SIG_PREG_OFFSET(vq,n) (SVE_SIG_REGS_OFFSET + __SVE_PREG_OFFSET(vq, n))
#define SVE_SIG_PREGS_SIZE(vq) __SVE_PREGS_SIZE(vq)
#define SVE_SIG_FFR_OFFSET(vq) (SVE_SIG_REGS_OFFSET + __SVE_FFR_OFFSET(vq))
#define SVE_SIG_REGS_SIZE(vq) (__SVE_FFR_OFFSET(vq) + __SVE_FFR_SIZE(vq))
#define SVE_SIG_CONTEXT_SIZE(vq) (SVE_SIG_REGS_OFFSET + SVE_SIG_REGS_SIZE(vq))
#define ZA_SIG_REGS_OFFSET ((sizeof(struct za_context) + (__SVE_VQ_BYTES - 1)) / __SVE_VQ_BYTES * __SVE_VQ_BYTES)
#define ZA_SIG_REGS_SIZE(vq) (((vq) * __SVE_VQ_BYTES) * ((vq) * __SVE_VQ_BYTES))
#define ZA_SIG_ZAV_OFFSET(vq,n) (ZA_SIG_REGS_OFFSET + (SVE_SIG_ZREG_SIZE(vq) * (n)))
#define ZA_SIG_CONTEXT_SIZE(vq) (ZA_SIG_REGS_OFFSET + ZA_SIG_REGS_SIZE(vq))
#define ZT_SIG_REG_SIZE 512
#define ZT_SIG_REG_BYTES (ZT_SIG_REG_SIZE / 8)
#define ZT_SIG_REGS_OFFSET sizeof(struct zt_context)
#define ZT_SIG_REGS_SIZE(n) (ZT_SIG_REG_BYTES * (n))
#define ZT_SIG_CONTEXT_SIZE(n) (sizeof(struct zt_context) + ZT_SIG_REGS_SIZE(n))
#endif

"""

```