Response:
Let's break down the thought process for analyzing this C header file.

**1. Initial Understanding and Context:**

The first step is to recognize the context. The prompt clearly states this is a header file (`ptrace.h`) located within the Android Bionic library (`bionic/libc/kernel/uapi/asm-arm64/asm/`). This immediately suggests it deals with low-level system interaction, specifically related to debugging and process tracing (`ptrace`). The `asm-arm64` part indicates it's for the ARM64 architecture. The "uapi" prefix suggests it's the user-space API view of kernel structures.

**2. High-Level Overview of Functionality:**

Skimming the file, we see a few distinct sections:

* **Preprocessor directives:** `#ifndef`, `#define`, `#include`. These are standard C/C++ for preventing multiple inclusions and bringing in other necessary definitions.
* **Macros defining Processor State (PSR) bits:**  `PSR_MODE_EL0t`, `PSR_F_BIT`, etc. These are bit flags likely related to the ARM64 processor's status register.
* **`PTRACE_` constants:**  `PTRACE_SYSEMU`, `PTRACE_PEEKMTETAGS`. These clearly relate to `ptrace` system calls and their various operations.
* **`struct user_pt_regs`:** This looks like a structure to hold the general-purpose registers of a user-space thread.
* **`struct user_fpsimd_state`:**  Likely related to floating-point and SIMD register state.
* **`struct user_hwdebug_state`:**  Deals with hardware debugging registers.
* **Sections related to SVE and ZA:**  These abbreviations likely stand for Scalable Vector Extension and something related to it (Zeroing Array?). The definitions around `SVE_PT_*` and `ZA_PT_*` suggest how to access different parts of the SVE/ZA context during `ptrace`.

**3. Detailed Analysis of Key Sections:**

Now, let's go through each section in more detail:

* **PSR Macros:** The names are fairly self-explanatory (e.g., `PSR_MODE_EL0t` likely means "Processor State Register, Mode, Exception Level 0, with Thumb"). The values are bitmasks. The `#define` statements are just giving symbolic names to these bit patterns. The shift operations like `PSR_BTYPE_SHIFT` and the `PSR_BTYPE_*` constants suggest different encodings for branch types.

* **`PTRACE_` Constants:** These are relatively straightforward. They define integer constants that are passed as arguments to the `ptrace` system call to specify the desired operation. The new ones like `PTRACE_PEEKMTETAGS` and `PTRACE_POKEMTETAGS` hint at memory tagging functionality, a more recent addition to ARM architectures.

* **`struct user_pt_regs`:**  This is a fundamental structure for `ptrace`. It holds the values of the general-purpose registers (`regs`), the stack pointer (`sp`), the program counter (`pc`), and the processor status register (`pstate`). This is crucial for inspecting and manipulating the state of a traced process.

* **`struct user_fpsimd_state`:** This structure holds the state of the floating-point and SIMD registers. `vregs` likely holds the vector registers, and `fpsr`/`fpcr` are the floating-point status and control registers.

* **`struct user_hwdebug_state`:** This structure allows access to hardware debugging resources, like breakpoints and watchpoints. `dbg_regs` likely holds the addresses and control settings for these hardware debuggers.

* **SVE and ZA Sections:**  These are more complex. The `user_sve_header` and `user_za_header` structures probably contain metadata about the size and configuration of the SVE/ZA state. The `SVE_PT_*` and `ZA_PT_*` macros define offsets and sizes for accessing specific parts of the SVE/ZA register files. The presence of `vq` in the macro names likely refers to the "vector length quotient," a parameter determining the actual vector length at runtime.

**4. Connecting to Android:**

The key connection to Android is through the `ptrace` system call. Android's debugging tools (like `gdbserver`, debuggers in Android Studio), profiling tools, and security features (like sandboxing and exploit mitigation) often rely on `ptrace` to inspect and control processes. The structures defined in this header file are the data structures exchanged between user-space debugging tools and the kernel during `ptrace` operations.

**5. Dynamic Linker Relevance:**

While this specific header doesn't *directly* define dynamic linker data structures, `ptrace` is used by debuggers when examining processes, including examining the loaded shared libraries and their memory layout. A debugger might use `ptrace` and the register information in `user_pt_regs` to step through code within a dynamically linked library.

**6. Hypothesizing Inputs and Outputs (Logical Reasoning):**

Imagine a debugger uses `ptrace` with `PTRACE_GETREGS`. The *input* from the kernel's perspective would be the process ID being traced. The *output* would be the data populated into a `user_pt_regs` structure, containing the register values of the traced process at that moment. Similarly, `PTRACE_PEEKMTETAGS` would take an address as input and output the memory tag associated with that address.

**7. Common Usage Errors:**

Thinking about how developers might misuse `ptrace`, a few things come to mind:

* **Incorrect `ptrace` request:**  Using an invalid or unsupported `ptrace` constant.
* **Permissions issues:**  Trying to trace a process without sufficient privileges.
* **Incorrect address/size:**  Providing invalid memory addresses or sizes when using `PTRACE_PEEKDATA` or `PTRACE_POKEDATA`.
* **Interfering with the traced process:**  Incorrectly modifying the traced process's state, leading to crashes or unexpected behavior.

**8. Tracing the Path from Framework/NDK:**

To reach this header file, an application or framework component would:

1. **Make a system call:**  This is the fundamental entry point to kernel functionality. The specific system call would be `ptrace`.
2. **The `ptrace` system call handler in the kernel:** This kernel code would receive the `ptrace` request and its arguments.
3. **Accessing process state:** The kernel would then access the state of the target process, populating structures like `pt_regs` (the kernel's equivalent of `user_pt_regs`).
4. **Copying data to user space:**  The kernel needs to copy the relevant information back to the user-space process that initiated the `ptrace` call. This involves copying data into user-space buffers, potentially using the structures defined in this header file.

**9. Frida Hooking:**

A Frida hook to inspect this would target the `ptrace` system call itself. We'd want to examine the arguments passed to `ptrace`, particularly the request type and the address of any data buffers.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe this file defines all `ptrace` requests.
* **Correction:** Realized it primarily defines *data structures* used *by* `ptrace`, not the request codes themselves (though some request codes are present).
* **Initial thought:** Focused too much on individual libc functions.
* **Correction:**  Recognized this is a kernel header, so it's about system calls and kernel-user space interaction, not necessarily high-level libc functions directly. The libc will provide wrappers for the `ptrace` syscall.
* **Considering SVE/ZA:**  Initially, I might have overlooked the significance of the SVE/ZA sections. Realized these are modern ARM extensions relevant to performance and need to be included in the analysis.

By following this structured breakdown, starting broad and then going into specifics, connecting the concepts to the Android ecosystem, and considering practical aspects like usage errors and debugging, we can arrive at a comprehensive understanding of this seemingly simple header file.
这个文件 `bionic/libc/kernel/uapi/asm-arm64/asm/ptrace.h` 是 Android Bionic C 库中定义了与 `ptrace` 系统调用相关的用户空间 API 的头文件，专门针对 ARM64 架构。`ptrace` 是一个强大的工具，允许一个进程（debugger）控制另一个进程（tracee），用于调试、跟踪系统调用、实现断点等功能。

**文件功能概览:**

这个文件的主要功能是定义了与 `ptrace` 系统调用交互时使用的数据结构和常量，这些结构和常量使得用户空间程序能够正确地与内核进行关于进程跟踪的信息交换。具体来说，它定义了：

1. **处理器状态 (PSR) 的位定义 (Macros for PSR bits):**  定义了 ARM64 架构处理器状态寄存器 (PSTATE) 中各个位的含义，例如运行模式 (EL0t, EL1t 等)、中断屏蔽位 (I_BIT, F_BIT, A_BIT)、条件码位 (N_BIT, Z_BIT, C_BIT, V_BIT) 等。这些宏允许用户空间程序检查和修改被跟踪进程的处理器状态。

2. **`ptrace` 系统调用请求常量 (PTRACE request constants):** 定义了传递给 `ptrace` 系统调用的请求类型，例如 `PTRACE_SYSEMU`（系统调用模拟）、`PTRACE_SYSEMU_SINGLESTEP`（单步系统调用模拟）、`PTRACE_PEEKMTETAGS` 和 `PTRACE_POKEMTETAGS` (用于访问内存标签)。

3. **用户空间寄存器结构体 (`struct user_pt_regs`):** 定义了用户空间表示被跟踪进程通用寄存器的结构体，包括 31 个通用寄存器、栈指针 (sp)、程序计数器 (pc) 和处理器状态寄存器 (pstate)。通过 `ptrace` 可以读取和修改这些寄存器的值。

4. **用户空间浮点和 SIMD 状态结构体 (`struct user_fpsimd_state`):** 定义了用于保存被跟踪进程浮点和 SIMD 寄存器状态的结构体，包括 32 个 128 位的向量寄存器、浮点状态寄存器 (fpsr) 和浮点控制寄存器 (fpcr)。

5. **用户空间硬件调试状态结构体 (`struct user_hwdebug_state`):** 定义了用于访问和修改被跟踪进程的硬件调试寄存器的结构体，例如断点地址和控制寄存器。

6. **SVE (Scalable Vector Extension) 相关结构体和定义:** 定义了与 ARMv8.2-A 引入的 SVE 扩展相关的结构体和宏，用于访问和管理 SVE 寄存器的状态。这包括 SVE 头的结构体 (`struct user_sve_header`) 以及用于计算 SVE 寄存器偏移和大小的宏。

7. **PAC (Pointer Authentication Code) 相关结构体:** 定义了用于保存 PAC 掩码 (`struct user_pac_mask`) 和密钥 (`struct user_pac_address_keys`, `struct user_pac_generic_keys`) 的结构体，PAC 是一种增强安全性的机制，用于验证指针的完整性。

8. **ZA (Zeroing Array) 相关结构体和定义:** 定义了与 SVE2 引入的 ZA 扩展相关的结构体和宏，用于访问和管理 ZA 数组的状态。

**与 Android 功能的关系举例:**

* **调试器 (Debugger):**  Android 的调试器，如 Android Studio 的调试功能或命令行工具 `gdbserver`，在底层使用了 `ptrace` 系统调用来控制被调试的应用进程。这个头文件中定义的 `user_pt_regs` 结构体会被用来读取和修改被调试进程的寄存器值，从而实现断点、单步执行等调试功能。例如，当你在调试器中设置断点时，调试器会使用 `ptrace` 修改目标进程的指令，并在断点命中时读取其寄存器状态。

* **系统调用跟踪 (System Call Tracing):**  工具如 `strace` 可以利用 `ptrace` 来监控应用进程执行的系统调用。这个头文件中的 `PTRACE_SYSEMU` 和 `PTRACE_SYSEMU_SINGLESTEP` 常量以及 `user_pt_regs` 结构体可以用来捕获系统调用入口和出口时的寄存器状态，从而了解系统调用的参数和返回值。

* **性能分析工具 (Profiling Tools):**  一些性能分析工具可能会使用 `ptrace` 来采样进程的执行状态，例如程序计数器 (pc)，以了解代码热点。

* **安全特性 (Security Features):**  Android 的一些安全机制，例如沙箱或某些 exploit mitigation 技术，可能会在内部使用 `ptrace` 来监控或限制进程的行为。例如，检查某些敏感操作是否发生。

* **内存标签 (Memory Tagging):** `PTRACE_PEEKMTETAGS` 和 `PTRACE_POKEMTETAGS` 与 ARMv8.5 引入的内存标签扩展相关，允许调试器读取和修改内存地址的标签，用于检测内存安全问题。

**libc 函数的实现:**

这个头文件本身并不包含 libc 函数的实现，它只是定义了与内核交互的数据结构。libc 中与 `ptrace` 相关的函数，例如 `ptrace()` 函数本身，是系统调用的包装器。其实现会使用这个头文件中定义的常量和结构体，将用户空间的请求转换为内核能够理解的格式，并处理内核返回的数据。

例如，`ptrace()` 函数的 libc 实现大致流程如下：

1. 接收用户传入的 `request` 参数 (例如 `PTRACE_PEEKUSER`)，`pid` 参数，`addr` 参数和 `data` 参数。
2. 根据 `request` 参数，确定需要与内核交换的数据类型和大小。
3. 如果需要读取或写入被跟踪进程的寄存器，libc 函数会使用 `user_pt_regs` 结构体来组织数据。
4. 调用底层的系统调用指令 (例如 `svc` 或 `syscall`)，将 `ptrace` 系统调用的编号和参数传递给内核。
5. 内核的 `ptrace` 系统调用处理函数会根据 `request` 执行相应的操作，例如读取或修改被跟踪进程的内存或寄存器。
6. 内核将结果返回给 libc 函数。
7. libc 函数将内核返回的数据转换为用户空间可以使用的格式，并返回给调用者。

**Dynamic Linker 的功能和 SO 布局:**

虽然这个头文件不直接涉及 dynamic linker 的核心功能，但 `ptrace` 可以用于调试动态链接的程序，观察动态链接的过程。

**SO 布局样本:**

```
Memory Map of a Process with Shared Libraries:

00400000-00401000 r-xp    /path/to/my_app  (Executable)
00401000-00402000 r--p    /path/to/my_app
00402000-00403000 rw-p    /path/to/my_app
...
b6f00000-b6f20000 r-xp    /system/lib64/libc.so
b6f20000-b6f30000 r--p    /system/lib64/libc.so
b6f30000-b6f34000 rw-p    /system/lib64/libc.so
...
b7000000-b7010000 r-xp    /system/lib64/libm.so
b7010000-b7011000 r--p    /system/lib64/libm.so
b7011000-b7012000 rw-p    /system/lib64/libm.so
...
```

* **可执行文件段 (.text, .rodata, .data, .bss):**  包含程序的主要代码和数据。
* **共享库段 (.text, .rodata, .data, .bss):** 每个加载的共享库（如 `libc.so`, `libm.so`）都有自己的代码和数据段。
* **加载地址:**  共享库被加载到进程地址空间的不同位置。
* **权限:**  每个内存区域有不同的权限（r-读，w-写，x-执行，p-私有）。

**链接的处理过程:**

1. **加载可执行文件:**  当 Android 启动一个应用时，zygote 进程 (或 app_process) 首先加载可执行文件。
2. **解析 ELF 头:**  系统会解析可执行文件的 ELF 头，查找 `PT_INTERP` 段，该段指定了 dynamic linker 的路径 (`/system/bin/linker64` 或类似)。
3. **加载 Dynamic Linker:**  内核将控制权交给 dynamic linker。
4. **解析动态段:**  Dynamic linker 解析可执行文件的 `.dynamic` 段，查找需要的共享库 (NEEDED entries)。
5. **加载共享库:**  Dynamic linker 根据 `NEEDED` 条目，加载所需的共享库到进程的地址空间。
6. **符号解析和重定位:**  Dynamic linker 解析共享库的符号表，并将可执行文件和共享库中未解析的符号引用 (例如函数调用) 链接到它们的实际地址。这包括：
    * **全局偏移表 (GOT):**  用于存储全局变量和函数的地址。
    * **过程链接表 (PLT):**  用于延迟绑定函数调用。
7. **执行初始化函数:**  Dynamic linker 执行共享库中的初始化函数 (`.init` 和 `.init_array` 段)。
8. **将控制权交给应用:**  Dynamic linker 完成后，将控制权交还给应用程序的入口点。

在调试过程中，你可以使用 `ptrace` 来观察 dynamic linker 的行为，例如：

* 使用 `PTRACE_PEEKTEXT` 读取 dynamic linker 的代码。
* 使用 `PTRACE_PEEKDATA` 读取 dynamic linker 的数据结构，例如 GOT 和 PLT 的内容。
* 设置断点在 dynamic linker 的关键函数上，例如 `_dl_relocate_object` 或 `_dl_map_file_flags`。

**假设输入与输出 (逻辑推理):**

假设一个调试器使用 `ptrace` 来读取被跟踪进程的程序计数器 (pc)：

* **假设输入:**
    * `request`: `PTRACE_GETREGS`
    * `pid`: 被跟踪进程的 ID
    * `addr`: 0 (对于 `PTRACE_GETREGS`，`addr` 通常被忽略)
    * `data`: 指向 `struct user_pt_regs` 结构体的指针 (用于接收数据)

* **输出:**
    * 内核会将当前被跟踪进程的寄存器状态填充到 `data` 指向的 `user_pt_regs` 结构体中，包括 `pc` 字段。
    * 调试器可以通过访问 `data->pc` 来获取被跟踪进程的程序计数器的值。

假设一个调试器想要修改被跟踪进程的程序计数器：

* **假设输入:**
    * `request`: `PTRACE_SETREGS`
    * `pid`: 被跟踪进程的 ID
    * `addr`: 0 (对于 `PTRACE_SETREGS`，`addr` 通常被忽略)
    * `data`: 指向 `struct user_pt_regs` 结构体的指针，其中 `pc` 字段已被修改为新的值。

* **输出:**
    * 内核会将 `data` 指向的 `user_pt_regs` 结构体中的寄存器值写回到被跟踪进程的上下文，包括更新其程序计数器。
    * 当被跟踪进程恢复执行时，它将从新的 `pc` 地址开始执行。

**用户或编程常见的使用错误:**

1. **权限错误:** 尝试 `ptrace` 一个不属于当前用户或权限更高的进程会失败。
2. **错误的 `request` 参数:**  传递了无效或不适用的 `ptrace` 请求常量。
3. **地址错误:**  在使用 `PTRACE_PEEKDATA` 或 `PTRACE_POKEDATA` 时，提供了无效的内存地址。
4. **大小错误:**  在使用 `PTRACE_PEEKDATA` 或 `PTRACE_POKEDATA` 时，指定了错误的数据大小。
5. **竞争条件:**  在多线程环境下，使用 `ptrace` 需要小心处理竞争条件，确保操作的原子性。
6. **死锁:**  不小心地使用 `ptrace` 可能会导致死锁，例如，一个进程尝试 `ptrace` 自己或相互 `ptrace`。
7. **不正确的结构体使用:**  没有正确地初始化或理解 `user_pt_regs` 等结构体，导致数据传递错误。
8. **忘记处理错误返回值:**  `ptrace` 调用可能会失败，没有检查返回值可能导致程序行为不可预测。

**Android Framework 或 NDK 如何到达这里:**

1. **NDK 开发:**  如果你使用 NDK 开发，并需要进行一些底层的调试或性能分析，你可能会直接调用 `ptrace` 系统调用，或者使用提供 `ptrace` 功能的库。在这种情况下，你的代码会包含 `#include <sys/ptrace.h>` (或者类似的头文件，最终会包含到这里)。

2. **Android Framework:**  Android Framework 中的某些组件，例如 `app_process` (用于启动应用)、`debuggerd` (系统崩溃守护进程) 和一些系统服务，可能会在内部使用 `ptrace`。

3. **调试流程:**
   a. **开发者启动调试:**  开发者在 Android Studio 或使用 `adb` 命令启动应用的调试会话。
   b. **调试器连接:**  调试器 (例如 Android Studio 的调试器或 `gdbserver`) 会连接到目标应用进程。
   c. **`ptrace` 调用:**  调试器会使用 `ptrace` 系统调用来控制目标进程：
      * 使用 `PTRACE_ATTACH` 附加到目标进程。
      * 使用 `PTRACE_CONT` 让目标进程继续执行。
      * 使用 `PTRACE_SINGLESTEP` 让目标进程单步执行。
      * 使用 `PTRACE_PEEKUSER` 读取目标进程的寄存器状态（使用 `user_pt_regs` 结构体）。
      * 使用 `PTRACE_POKEUSER` 修改目标进程的寄存器状态。
      * 使用 `PTRACE_PEEKTEXT` 和 `PTRACE_POKETEXT` 读取和修改目标进程的代码。
      * 使用 `PTRACE_DETACH` 从目标进程分离。
   d. **内核交互:**  每次 `ptrace` 调用都会涉及到用户空间和内核空间的交互，内核会根据请求操作目标进程，并将结果返回给调试器。这个头文件中定义的结构体是这种交互的关键数据格式。

**Frida Hook 示例调试步骤:**

假设你想使用 Frida hook 来观察对 `ptrace` 系统调用的调用，并查看传递的 `request` 参数：

```javascript
// hook_ptrace.js

if (Process.arch === 'arm64') {
  const ptrace = Module.findExportByName(null, 'ptrace');
  if (ptrace) {
    Interceptor.attach(ptrace, {
      onEnter: function (args) {
        const request = args[0].toInt();
        const pid = args[1].toInt();
        console.log(`ptrace called with request: ${request}, pid: ${pid}`);

        // 你可以进一步解析 request 的值，例如：
        const PTRACE_ATTACH = 16;
        const PTRACE_PEEKUSER = 12;
        if (request === PTRACE_ATTACH) {
          console.log("  Request is PTRACE_ATTACH");
        } else if (request === PTRACE_PEEKUSER) {
          console.log("  Request is PTRACE_PEEKUSER");
        }
        // ... 添加更多你关心的请求类型
      },
      onLeave: function (retval) {
        // console.log('ptrace returned:', retval);
      }
    });
    console.log("Ptrace hook installed.");
  } else {
    console.log("Ptrace symbol not found.");
  }
} else {
  console.log("This script is for arm64.");
}
```

**调试步骤:**

1. **将 Frida 脚本保存为 `hook_ptrace.js`。**
2. **找到目标应用的进程 ID (PID)。**
3. **使用 Frida 连接到目标应用并运行脚本:**
   ```bash
   frida -U -f <your_app_package_name> -l hook_ptrace.js --no-pause
   # 或者，如果应用已经在运行：
   frida -U <your_app_package_name> -l hook_ptrace.js
   ```
4. **观察输出:**  当目标应用或其他进程调用 `ptrace` 系统调用时，Frida 会在控制台上打印出 `ptrace` 的 `request` 和 `pid`。你可以根据需要添加更多的解析逻辑来查看其他参数。

通过这种方式，你可以动态地观察哪些进程在调用 `ptrace`，以及它们正在执行哪些 `ptrace` 操作，这对于理解系统行为、调试和安全分析非常有用。这个头文件中的定义是你理解这些 `ptrace` 操作的基础。

Prompt: 
```
这是目录为bionic/libc/kernel/uapi/asm-arm64/asm/ptrace.handroid bionic的源代码文件，bionic is Android's C library, math library, and dynamic linker. 
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
#ifndef _UAPI__ASM_PTRACE_H
#define _UAPI__ASM_PTRACE_H
#include <linux/types.h>
#include <asm/hwcap.h>
#include <asm/sve_context.h>
#define PSR_MODE_EL0t 0x00000000
#define PSR_MODE_EL1t 0x00000004
#define PSR_MODE_EL1h 0x00000005
#define PSR_MODE_EL2t 0x00000008
#define PSR_MODE_EL2h 0x00000009
#define PSR_MODE_EL3t 0x0000000c
#define PSR_MODE_EL3h 0x0000000d
#define PSR_MODE_MASK 0x0000000f
#define PSR_MODE32_BIT 0x00000010
#define PSR_F_BIT 0x00000040
#define PSR_I_BIT 0x00000080
#define PSR_A_BIT 0x00000100
#define PSR_D_BIT 0x00000200
#define PSR_BTYPE_MASK 0x00000c00
#define PSR_SSBS_BIT 0x00001000
#define PSR_PAN_BIT 0x00400000
#define PSR_UAO_BIT 0x00800000
#define PSR_DIT_BIT 0x01000000
#define PSR_TCO_BIT 0x02000000
#define PSR_V_BIT 0x10000000
#define PSR_C_BIT 0x20000000
#define PSR_Z_BIT 0x40000000
#define PSR_N_BIT 0x80000000
#define PSR_BTYPE_SHIFT 10
#define PSR_f 0xff000000
#define PSR_s 0x00ff0000
#define PSR_x 0x0000ff00
#define PSR_c 0x000000ff
#define PSR_BTYPE_NONE (0b00 << PSR_BTYPE_SHIFT)
#define PSR_BTYPE_JC (0b01 << PSR_BTYPE_SHIFT)
#define PSR_BTYPE_C (0b10 << PSR_BTYPE_SHIFT)
#define PSR_BTYPE_J (0b11 << PSR_BTYPE_SHIFT)
#define PTRACE_SYSEMU 31
#define PTRACE_SYSEMU_SINGLESTEP 32
#define PTRACE_PEEKMTETAGS 33
#define PTRACE_POKEMTETAGS 34
#ifndef __ASSEMBLY__
struct user_pt_regs {
  __u64 regs[31];
  __u64 sp;
  __u64 pc;
  __u64 pstate;
};
struct user_fpsimd_state {
  __uint128_t vregs[32];
  __u32 fpsr;
  __u32 fpcr;
  __u32 __reserved[2];
};
struct user_hwdebug_state {
  __u32 dbg_info;
  __u32 pad;
  struct {
    __u64 addr;
    __u32 ctrl;
    __u32 pad;
  } dbg_regs[16];
};
struct user_sve_header {
  __u32 size;
  __u32 max_size;
  __u16 vl;
  __u16 max_vl;
  __u16 flags;
  __u16 __reserved;
};
#define SVE_PT_REGS_MASK (1 << 0)
#define SVE_PT_REGS_FPSIMD 0
#define SVE_PT_REGS_SVE SVE_PT_REGS_MASK
#define SVE_PT_VL_INHERIT ((1 << 17) >> 16)
#define SVE_PT_VL_ONEXEC ((1 << 18) >> 16)
#define SVE_PT_REGS_OFFSET ((sizeof(struct user_sve_header) + (__SVE_VQ_BYTES - 1)) / __SVE_VQ_BYTES * __SVE_VQ_BYTES)
#define SVE_PT_FPSIMD_OFFSET SVE_PT_REGS_OFFSET
#define SVE_PT_FPSIMD_SIZE(vq,flags) (sizeof(struct user_fpsimd_state))
#define SVE_PT_SVE_ZREG_SIZE(vq) __SVE_ZREG_SIZE(vq)
#define SVE_PT_SVE_PREG_SIZE(vq) __SVE_PREG_SIZE(vq)
#define SVE_PT_SVE_FFR_SIZE(vq) __SVE_FFR_SIZE(vq)
#define SVE_PT_SVE_FPSR_SIZE sizeof(__u32)
#define SVE_PT_SVE_FPCR_SIZE sizeof(__u32)
#define SVE_PT_SVE_OFFSET SVE_PT_REGS_OFFSET
#define SVE_PT_SVE_ZREGS_OFFSET (SVE_PT_REGS_OFFSET + __SVE_ZREGS_OFFSET)
#define SVE_PT_SVE_ZREG_OFFSET(vq,n) (SVE_PT_REGS_OFFSET + __SVE_ZREG_OFFSET(vq, n))
#define SVE_PT_SVE_ZREGS_SIZE(vq) (SVE_PT_SVE_ZREG_OFFSET(vq, __SVE_NUM_ZREGS) - SVE_PT_SVE_ZREGS_OFFSET)
#define SVE_PT_SVE_PREGS_OFFSET(vq) (SVE_PT_REGS_OFFSET + __SVE_PREGS_OFFSET(vq))
#define SVE_PT_SVE_PREG_OFFSET(vq,n) (SVE_PT_REGS_OFFSET + __SVE_PREG_OFFSET(vq, n))
#define SVE_PT_SVE_PREGS_SIZE(vq) (SVE_PT_SVE_PREG_OFFSET(vq, __SVE_NUM_PREGS) - SVE_PT_SVE_PREGS_OFFSET(vq))
#define SVE_PT_SVE_FFR_OFFSET(vq) (SVE_PT_REGS_OFFSET + __SVE_FFR_OFFSET(vq))
#define SVE_PT_SVE_FPSR_OFFSET(vq) ((SVE_PT_SVE_FFR_OFFSET(vq) + SVE_PT_SVE_FFR_SIZE(vq) + (__SVE_VQ_BYTES - 1)) / __SVE_VQ_BYTES * __SVE_VQ_BYTES)
#define SVE_PT_SVE_FPCR_OFFSET(vq) (SVE_PT_SVE_FPSR_OFFSET(vq) + SVE_PT_SVE_FPSR_SIZE)
#define SVE_PT_SVE_SIZE(vq,flags) ((SVE_PT_SVE_FPCR_OFFSET(vq) + SVE_PT_SVE_FPCR_SIZE - SVE_PT_SVE_OFFSET + (__SVE_VQ_BYTES - 1)) / __SVE_VQ_BYTES * __SVE_VQ_BYTES)
#define SVE_PT_SIZE(vq,flags) (((flags) & SVE_PT_REGS_MASK) == SVE_PT_REGS_SVE ? SVE_PT_SVE_OFFSET + SVE_PT_SVE_SIZE(vq, flags) : ((((flags) & SVE_PT_REGS_MASK) == SVE_PT_REGS_FPSIMD ? SVE_PT_FPSIMD_OFFSET + SVE_PT_FPSIMD_SIZE(vq, flags) : SVE_PT_REGS_OFFSET)))
struct user_pac_mask {
  __u64 data_mask;
  __u64 insn_mask;
};
struct user_pac_address_keys {
  __uint128_t apiakey;
  __uint128_t apibkey;
  __uint128_t apdakey;
  __uint128_t apdbkey;
};
struct user_pac_generic_keys {
  __uint128_t apgakey;
};
struct user_za_header {
  __u32 size;
  __u32 max_size;
  __u16 vl;
  __u16 max_vl;
  __u16 flags;
  __u16 __reserved;
};
#define ZA_PT_VL_INHERIT ((1 << 17) >> 16)
#define ZA_PT_VL_ONEXEC ((1 << 18) >> 16)
#define ZA_PT_ZA_OFFSET ((sizeof(struct user_za_header) + (__SVE_VQ_BYTES - 1)) / __SVE_VQ_BYTES * __SVE_VQ_BYTES)
#define ZA_PT_ZAV_OFFSET(vq,n) (ZA_PT_ZA_OFFSET + ((vq * __SVE_VQ_BYTES) * n))
#define ZA_PT_ZA_SIZE(vq) ((vq * __SVE_VQ_BYTES) * (vq * __SVE_VQ_BYTES))
#define ZA_PT_SIZE(vq) (ZA_PT_ZA_OFFSET + ZA_PT_ZA_SIZE(vq))
#endif
#endif

"""

```