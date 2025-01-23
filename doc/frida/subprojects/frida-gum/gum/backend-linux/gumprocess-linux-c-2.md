Response:
The user wants a summary of the functionality of the provided C code snippet, which is part of the Frida dynamic instrumentation tool. The file `gumprocess-linux.c` seems to deal with process-related operations on Linux.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the core purpose of the file:** The filename and the content (dealing with `ucontext_t`, `GumCpuContext`, `ptrace`, etc.) strongly suggest this file handles low-level interactions with a running process on Linux, likely for inspection and manipulation.

2. **Categorize the functions:**  Go through each function and group them based on their apparent purpose. This leads to categories like:
    * Register manipulation (parsing and unparsing CPU contexts)
    * Thread information retrieval (name, state)
    * Memory mapping information (page protection)
    * Low-level system calls (clone, read, write, waitpid, ptrace)

3. **Analyze each function's role within Frida:** Consider how these functions contribute to Frida's dynamic instrumentation capabilities. For example:
    * Register manipulation is crucial for intercepting and modifying program execution.
    * Thread information helps understand the target process's structure and state.
    * `ptrace` is a fundamental system call for debugging and process inspection, which Frida leverages.

4. **Connect to reverse engineering:**  Think about how these functionalities are directly related to reverse engineering. Modifying registers, inspecting memory, and controlling execution flow are core tasks in reverse engineering.

5. **Identify Linux/Android kernel and framework connections:** Look for functions or data structures that are specific to the Linux kernel or the Android environment (if applicable, even though the path suggests it's specifically for Linux). `ptrace`, `/proc` filesystem, and the register structures are clear indicators.

6. **Look for logical reasoning:** Are there conditional statements or logic that transforms input into output? The `gum_thread_state_from_proc_status_character` and `gum_page_protection_from_proc_perms_string` functions are examples of this, converting character representations to enum values.

7. **Identify potential user errors:**  Consider how a programmer using Frida might misuse these functions or encounter errors. Incorrectly setting registers or attempting to access restricted memory are potential issues.

8. **Trace user actions:**  Imagine a typical Frida workflow. A user would attach to a process, potentially set breakpoints, and then Frida would use these low-level functions to interact with the target process.

9. **Synthesize the information into a structured answer:** Organize the findings into clear categories as requested by the user, providing examples and explanations for each.

10. **Focus on the summary:**  For the final part (part 3), extract the most important overarching functionalities. The key is the manipulation of process state via system calls, register access, and memory information.

**Self-Correction/Refinement during the process:**

* Initially, I might have focused too much on the specific register names. Realizing that the core functionality is *register manipulation* is more important than listing every register.
*  I need to explicitly mention the role of `ptrace` as it's a cornerstone of Frida's operation on Linux.
* While the code doesn't explicitly mention Android frameworks, it's important to acknowledge the commonality of the Linux kernel and low-level concepts between Linux and Android.
*  For user errors, I should focus on the *consequences* of incorrect usage (e.g., crashing the target process) rather than just stating a misuse.
* The debugging clue should link the user's high-level actions in Frida to the execution of these low-level functions.

By following these steps and iteratively refining the analysis, I can construct a comprehensive and accurate summary of the provided code.
好的，让我们来归纳一下 `frida/subprojects/frida-gum/gum/backend-linux/gumprocess-linux.c` 文件的功能，这是第 3 部分的总结。

**功能归纳**

该文件的核心功能是提供 Frida 在 Linux 系统上与目标进程进行交互的底层实现，主要集中在以下几个方面：

1. **进程上下文管理：**  它提供了在 Frida 的 `GumCpuContext` 结构和 Linux 系统原生 `ucontext_t` 结构以及 `user_regs_struct`/`user_fpregs_struct` 结构之间进行转换的能力。这意味着 Frida 可以读取和修改目标进程的 CPU 寄存器状态。

2. **线程信息获取：**  它实现了获取目标进程中线程的名称和状态的功能，这对于理解目标进程的并发行为至关重要。

3. **内存保护信息获取：** 提供了从 `/proc` 文件系统中解析内存映射权限信息，并将其转换为 Frida 内部使用的 `GumPageProtection` 枚举的能力。

4. **底层系统调用封装：**  它封装了关键的 Linux 系统调用，如 `clone` (用于创建新线程)、`read`、`write`、`waitpid` (用于等待子进程状态变化) 和最核心的 `ptrace` (用于进程跟踪和控制)。  这些封装可能包含一些架构特定的处理和错误处理逻辑。

**与逆向方法的关联**

该文件是 Frida 实现动态 instrumentation 的基础，与逆向方法紧密相关。以下是一些例子：

* **寄存器修改：**  逆向工程师可以使用 Frida 脚本来修改目标进程的寄存器值，例如修改程序计数器 (PC/RIP/EIP) 来跳转到特定的代码位置，或者修改函数参数来改变函数的行为。`gum_linux_parse_ucontext` 和 `gum_linux_unparse_ucontext` 就实现了 `ucontext_t` 和 `GumCpuContext` 之间的转换，使得 Frida 能够读取和设置这些寄存器。

   **举例：** 假设你想跳过一个函数调用，可以修改程序计数器，让其指向函数返回后的下一条指令。你可以使用 Frida 的 API 获取当前的 `GumCpuContext`，修改其中的 PC 寄存器，然后用修改后的上下文更新进程状态。

* **观察程序状态：**  通过读取寄存器值，逆向工程师可以了解程序的当前状态，例如函数调用的参数、局部变量的值等。`gum_linux_parse_ucontext` 可以将 `ucontext_t` 中的寄存器信息提取到 `GumCpuContext` 中，供 Frida 脚本读取。

* **拦截函数调用：** Frida 经常通过修改目标函数的入口指令来实现拦截。在拦截点，Frida 需要保存原始的寄存器状态，执行自定义的代码，然后在恢复执行前恢复寄存器状态。  `gum_linux_parse_ucontext` 和 `gum_linux_unparse_ucontext` 在这个过程中用于保存和恢复寄存器状态。

* **内存分析：** 虽然这个文件主要关注进程和线程，但它提供的底层系统调用封装，如 `ptrace`，是 Frida 读取和修改目标进程内存的基础。通过 `ptrace`，Frida 可以读取内存中的数据，分析数据结构和算法。

**涉及的二进制底层、Linux、Android 内核及框架知识**

* **二进制底层知识：**
    * **CPU 寄存器：** 文件中大量代码处理不同架构（x86, ARM, ARM64, MIPS）的 CPU 寄存器，需要了解这些寄存器的用途（如程序计数器、栈指针、通用寄存器等）。
    * **调用约定：** 修改寄存器时需要了解目标架构的调用约定，例如函数参数如何传递，返回值如何获取等。
    * **内存布局：**  理解进程的内存布局，例如代码段、数据段、栈等，有助于分析寄存器和内存数据的含义。

* **Linux 知识：**
    * **`ucontext_t` 结构体：**  这是 Linux 系统中用于保存进程上下文的关键结构体，包含了 CPU 寄存器、信号掩码、栈信息等。
    * **`/proc` 文件系统：**  文件使用 `/proc/self/task/<tid>/comm` 和 `/proc/self/task/<tid>/stat` 来获取线程名称和状态，需要了解 `/proc` 文件系统的作用和结构。
    * **`ptrace` 系统调用：**  这是 Linux 提供的强大的进程跟踪和控制机制，Frida 深度依赖它。需要理解 `ptrace` 的各种请求类型（如 `PTRACE_GETREGS`, `PTRACE_SETREGS`, `PTRACE_GETREGSET`, `PTRACE_SETREGSET`）。
    * **`clone` 系统调用：**  用于创建新的进程或线程。
    * **系统调用号 (`__NR_...`)：**  代码中使用了大量的系统调用号，这是在用户空间发起系统调用的方式。
    * **`iovec` 结构体：** 用于 `ptrace(PTRACE_GETREGSET/SETREGSET)`，允许一次性获取或设置多个寄存器。

* **Android 内核及框架知识：**
    * 虽然该文件路径明确指出是 Linux 后端，但 Android 底层也是基于 Linux 内核的。因此，其中涉及的 `ptrace`、`/proc` 文件系统、CPU 寄存器等概念在 Android 中同样适用。
    * Android 的进程和线程模型与 Linux 基本一致。

**逻辑推理**

* **假设输入：**  一个指向 `ucontext_t` 结构体的指针，该结构体包含了目标进程在某个时刻的 CPU 寄存器状态。
* **输出：**  `gum_linux_parse_ucontext` 函数会将 `ucontext_t` 中的寄存器值提取出来，并填充到 `GumCpuContext` 结构体中。反之，`gum_linux_unparse_ucontext` 则将 `GumCpuContext` 的值写回 `ucontext_t`。

* **假设输入：**  一个线程 ID (`GumThreadId`)。
* **输出：** `gum_thread_read_name` 函数会尝试读取 `/proc/self/task/<tid>/comm` 文件，返回线程的名称。`gum_thread_read_state` 函数会读取 `/proc/self/task/<tid>/stat` 文件，解析出线程的状态并返回 `GumThreadState` 枚举值。

* **假设输入：**  一个表示内存映射权限的字符串 (例如 "rwxp")。
* **输出：** `gum_page_protection_from_proc_perms_string` 函数会根据字符串中的字符 ('r', 'w', 'x')，返回对应的 `GumPageProtection` 枚举值。

**用户或编程常见的使用错误**

* **架构不匹配：**  如果 Frida 运行的架构与目标进程的架构不一致，尝试使用这些函数可能会导致错误或未定义的行为。例如，尝试在 32 位 Frida 中操作 64 位进程的寄存器。
* **错误的寄存器名称或索引：**  在 Frida 脚本中操作寄存器时，如果使用了错误的寄存器名称或索引，将无法正确读取或修改寄存器值。
* **权限不足：**  `ptrace` 操作需要一定的权限。如果运行 Frida 的用户没有足够的权限跟踪目标进程，`gum_libc_ptrace` 调用将会失败。
* **不正确的系统调用参数：**  直接使用封装的系统调用函数时，如果传递了错误的参数类型、大小或值，可能会导致系统调用失败或目标进程崩溃。
* **修改关键寄存器导致崩溃：**  不小心修改了目标进程的关键寄存器，如栈指针 (SP/RSP/ESP) 或程序计数器 (PC/RIP/EIP) 为非法值，可能导致目标进程崩溃。

**用户操作是如何一步步的到达这里，作为调试线索**

1. **用户启动 Frida 脚本，并尝试 attach 到一个 Linux 进程。**
2. **Frida Core 会与目标进程建立连接。**
3. **用户可能在 Frida 脚本中使用 `Interceptor` 或 `Stalker` API 来拦截函数调用或追踪代码执行。**
4. **当需要读取或修改目标进程的 CPU 寄存器时，Frida Gum (JavaScript 引擎和 Native 桥梁) 会调用到 `gumprocess-linux.c` 中的函数。** 例如：
   * 使用 `Process.getThreadContext()` 获取线程上下文时，最终会调用 `gum_linux_parse_ucontext`。
   * 使用 `Thread. Hijack` 或 `Interceptor.replace` 时，在保存和恢复上下文的过程中会用到 `gum_linux_parse_ucontext` 和 `gum_linux_unparse_ucontext`。
5. **如果用户尝试创建一个新的线程，Frida 可能会调用 `gum_libc_clone`。**
6. **如果用户需要在目标进程中分配或修改内存，Frida 会通过 `ptrace` 系统调用来实现，这会调用到 `gum_libc_ptrace`。**
7. **在调试过程中，如果目标进程崩溃或出现异常，Frida 可能会尝试获取崩溃时的上下文信息，这也会涉及到 `gum_linux_parse_ucontext`。**

因此，`gumprocess-linux.c` 中的代码通常是在 Frida 框架处理用户发起的 instrumentation 请求时被间接调用的，作为与目标进程进行底层交互的桥梁。当调试 Frida 脚本或分析目标进程行为时，理解这个文件的功能可以帮助你更好地理解 Frida 的工作原理和定位问题。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-linux/gumprocess-linux.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
EG_RIP];

  ctx->r15 = gr[REG_R15];
  ctx->r14 = gr[REG_R14];
  ctx->r13 = gr[REG_R13];
  ctx->r12 = gr[REG_R12];
  ctx->r11 = gr[REG_R11];
  ctx->r10 = gr[REG_R10];
  ctx->r9 = gr[REG_R9];
  ctx->r8 = gr[REG_R8];

  ctx->rdi = gr[REG_RDI];
  ctx->rsi = gr[REG_RSI];
  ctx->rbp = gr[REG_RBP];
  ctx->rsp = gr[REG_RSP];
  ctx->rbx = gr[REG_RBX];
  ctx->rdx = gr[REG_RDX];
  ctx->rcx = gr[REG_RCX];
  ctx->rax = gr[REG_RAX];
#elif defined (HAVE_ARM) && defined (HAVE_LEGACY_MCONTEXT)
  const elf_greg_t * gr = uc->uc_mcontext.gregs;

  ctx->pc = gr[R15];
  ctx->sp = gr[R13];
  ctx->cpsr = 0; /* FIXME: Anything we can do about this? */

  ctx->r8 = gr[R8];
  ctx->r9 = gr[R9];
  ctx->r10 = gr[R10];
  ctx->r11 = gr[R11];
  ctx->r12 = gr[R12];

  memset (ctx->v, 0, sizeof (ctx->v));

  ctx->r[0] = gr[R0];
  ctx->r[1] = gr[R1];
  ctx->r[2] = gr[R2];
  ctx->r[3] = gr[R3];
  ctx->r[4] = gr[R4];
  ctx->r[5] = gr[R5];
  ctx->r[6] = gr[R6];
  ctx->r[7] = gr[R7];
  ctx->lr = gr[R14];
#elif defined (HAVE_ARM)
  const mcontext_t * mc = &uc->uc_mcontext;

  ctx->pc = mc->arm_pc;
  ctx->sp = mc->arm_sp;
  ctx->cpsr = mc->arm_cpsr;

  ctx->r8 = mc->arm_r8;
  ctx->r9 = mc->arm_r9;
  ctx->r10 = mc->arm_r10;
  ctx->r11 = mc->arm_fp;
  ctx->r12 = mc->arm_ip;

  memset (ctx->v, 0, sizeof (ctx->v));

  ctx->r[0] = mc->arm_r0;
  ctx->r[1] = mc->arm_r1;
  ctx->r[2] = mc->arm_r2;
  ctx->r[3] = mc->arm_r3;
  ctx->r[4] = mc->arm_r4;
  ctx->r[5] = mc->arm_r5;
  ctx->r[6] = mc->arm_r6;
  ctx->r[7] = mc->arm_r7;
  ctx->lr = mc->arm_lr;
#elif defined (HAVE_ARM64)
  const mcontext_t * mc = &uc->uc_mcontext;
  gsize i;

  ctx->pc = mc->pc;
  ctx->sp = mc->sp;
  ctx->nzcv = 0;

  for (i = 0; i != G_N_ELEMENTS (ctx->x); i++)
    ctx->x[i] = mc->regs[i];
  ctx->fp = mc->regs[29];
  ctx->lr = mc->regs[30];

  memset (ctx->v, 0, sizeof (ctx->v));
#elif defined (HAVE_MIPS)
  const greg_t * gr = uc->uc_mcontext.gregs;

  ctx->at = (guint32) gr[1];

  ctx->v0 = (guint32) gr[2];
  ctx->v1 = (guint32) gr[3];

  ctx->a0 = (guint32) gr[4];
  ctx->a1 = (guint32) gr[5];
  ctx->a2 = (guint32) gr[6];
  ctx->a3 = (guint32) gr[7];

  ctx->t0 = (guint32) gr[8];
  ctx->t1 = (guint32) gr[9];
  ctx->t2 = (guint32) gr[10];
  ctx->t3 = (guint32) gr[11];
  ctx->t4 = (guint32) gr[12];
  ctx->t5 = (guint32) gr[13];
  ctx->t6 = (guint32) gr[14];
  ctx->t7 = (guint32) gr[15];

  ctx->s0 = (guint32) gr[16];
  ctx->s1 = (guint32) gr[17];
  ctx->s2 = (guint32) gr[18];
  ctx->s3 = (guint32) gr[19];
  ctx->s4 = (guint32) gr[20];
  ctx->s5 = (guint32) gr[21];
  ctx->s6 = (guint32) gr[22];
  ctx->s7 = (guint32) gr[23];

  ctx->t8 = (guint32) gr[24];
  ctx->t9 = (guint32) gr[25];

  ctx->k0 = (guint32) gr[26];
  ctx->k1 = (guint32) gr[27];

  ctx->gp = (guint32) gr[28];
  ctx->sp = (guint32) gr[29];
  ctx->fp = (guint32) gr[30];
  ctx->ra = (guint32) gr[31];

  ctx->hi = (guint32) uc->uc_mcontext.mdhi;
  ctx->lo = (guint32) uc->uc_mcontext.mdlo;

  ctx->pc = (guint32) uc->uc_mcontext.pc;
#else
# error FIXME
#endif
}

void
gum_linux_unparse_ucontext (const GumCpuContext * ctx,
                            ucontext_t * uc)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  greg_t * gr = uc->uc_mcontext.gregs;

  gr[REG_EIP] = ctx->eip;

  gr[REG_EDI] = ctx->edi;
  gr[REG_ESI] = ctx->esi;
  gr[REG_EBP] = ctx->ebp;
  gr[REG_ESP] = ctx->esp;
  gr[REG_EBX] = ctx->ebx;
  gr[REG_EDX] = ctx->edx;
  gr[REG_ECX] = ctx->ecx;
  gr[REG_EAX] = ctx->eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  greg_t * gr = uc->uc_mcontext.gregs;

  gr[REG_RIP] = ctx->rip;

  gr[REG_R15] = ctx->r15;
  gr[REG_R14] = ctx->r14;
  gr[REG_R13] = ctx->r13;
  gr[REG_R12] = ctx->r12;
  gr[REG_R11] = ctx->r11;
  gr[REG_R10] = ctx->r10;
  gr[REG_R9] = ctx->r9;
  gr[REG_R8] = ctx->r8;

  gr[REG_RDI] = ctx->rdi;
  gr[REG_RSI] = ctx->rsi;
  gr[REG_RBP] = ctx->rbp;
  gr[REG_RSP] = ctx->rsp;
  gr[REG_RBX] = ctx->rbx;
  gr[REG_RDX] = ctx->rdx;
  gr[REG_RCX] = ctx->rcx;
  gr[REG_RAX] = ctx->rax;
#elif defined (HAVE_ARM) && defined (HAVE_LEGACY_MCONTEXT)
  elf_greg_t * gr = uc->uc_mcontext.gregs;

  /* FIXME: Anything we can do about cpsr? */
  gr[R15] = ctx->pc;
  gr[R13] = ctx->sp;

  gr[R8] = ctx->r8;
  gr[R9] = ctx->r9;
  gr[R10] = ctx->r10;
  gr[R11] = ctx->r11;
  gr[R12] = ctx->r12;

  gr[R0] = ctx->r[0];
  gr[R1] = ctx->r[1];
  gr[R2] = ctx->r[2];
  gr[R3] = ctx->r[3];
  gr[R4] = ctx->r[4];
  gr[R5] = ctx->r[5];
  gr[R6] = ctx->r[6];
  gr[R7] = ctx->r[7];
  gr[R14] = ctx->lr;
#elif defined (HAVE_ARM)
  mcontext_t * mc = &uc->uc_mcontext;

  mc->arm_pc = ctx->pc;
  mc->arm_sp = ctx->sp;
  mc->arm_cpsr = ctx->cpsr;

  mc->arm_r8 = ctx->r8;
  mc->arm_r9 = ctx->r9;
  mc->arm_r10 = ctx->r10;
  mc->arm_fp = ctx->r11;
  mc->arm_ip = ctx->r12;

  mc->arm_r0 = ctx->r[0];
  mc->arm_r1 = ctx->r[1];
  mc->arm_r2 = ctx->r[2];
  mc->arm_r3 = ctx->r[3];
  mc->arm_r4 = ctx->r[4];
  mc->arm_r5 = ctx->r[5];
  mc->arm_r6 = ctx->r[6];
  mc->arm_r7 = ctx->r[7];
  mc->arm_lr = ctx->lr;
#elif defined (HAVE_ARM64)
  mcontext_t * mc = &uc->uc_mcontext;
  gsize i;

  mc->pc = ctx->pc;
  mc->sp = ctx->sp;

  for (i = 0; i != G_N_ELEMENTS (ctx->x); i++)
    mc->regs[i] = ctx->x[i];
  mc->regs[29] = ctx->fp;
  mc->regs[30] = ctx->lr;
#elif defined (HAVE_MIPS)
  greg_t * gr = uc->uc_mcontext.gregs;

  gr[1] = (guint64) ctx->at;

  gr[2] = (guint64) ctx->v0;
  gr[3] = (guint64) ctx->v1;

  gr[4] = (guint64) ctx->a0;
  gr[5] = (guint64) ctx->a1;
  gr[6] = (guint64) ctx->a2;
  gr[7] = (guint64) ctx->a3;

  gr[8] = (guint64) ctx->t0;
  gr[9] = (guint64) ctx->t1;
  gr[10] = (guint64) ctx->t2;
  gr[11] = (guint64) ctx->t3;
  gr[12] = (guint64) ctx->t4;
  gr[13] = (guint64) ctx->t5;
  gr[14] = (guint64) ctx->t6;
  gr[15] = (guint64) ctx->t7;

  gr[16] = (guint64) ctx->s0;
  gr[17] = (guint64) ctx->s1;
  gr[18] = (guint64) ctx->s2;
  gr[19] = (guint64) ctx->s3;
  gr[20] = (guint64) ctx->s4;
  gr[21] = (guint64) ctx->s5;
  gr[22] = (guint64) ctx->s6;
  gr[23] = (guint64) ctx->s7;

  gr[24] = (guint64) ctx->t8;
  gr[25] = (guint64) ctx->t9;

  gr[26] = (guint64) ctx->k0;
  gr[27] = (guint64) ctx->k1;

  gr[28] = (guint64) ctx->gp;
  gr[29] = (guint64) ctx->sp;
  gr[30] = (guint64) ctx->fp;
  gr[31] = (guint64) ctx->ra;

  uc->uc_mcontext.mdhi = (guint64) ctx->hi;
  uc->uc_mcontext.mdlo = (guint64) ctx->lo;

  uc->uc_mcontext.pc = (guint64) ctx->pc;
#else
# error FIXME
#endif
}

static void
gum_parse_gp_regs (const GumGPRegs * regs,
                   GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  ctx->eip = regs->eip;

  ctx->edi = regs->edi;
  ctx->esi = regs->esi;
  ctx->ebp = regs->ebp;
  ctx->esp = regs->esp;
  ctx->ebx = regs->ebx;
  ctx->edx = regs->edx;
  ctx->ecx = regs->ecx;
  ctx->eax = regs->eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  ctx->rip = regs->rip;

  ctx->r15 = regs->r15;
  ctx->r14 = regs->r14;
  ctx->r13 = regs->r13;
  ctx->r12 = regs->r12;
  ctx->r11 = regs->r11;
  ctx->r10 = regs->r10;
  ctx->r9 = regs->r9;
  ctx->r8 = regs->r8;

  ctx->rdi = regs->rdi;
  ctx->rsi = regs->rsi;
  ctx->rbp = regs->rbp;
  ctx->rsp = regs->rsp;
  ctx->rbx = regs->rbx;
  ctx->rdx = regs->rdx;
  ctx->rcx = regs->rcx;
  ctx->rax = regs->rax;
#elif defined (HAVE_ARM)
  gsize i;

  ctx->pc = regs->ARM_pc;
  ctx->sp = regs->ARM_sp;
  ctx->cpsr = regs->ARM_cpsr;

  ctx->r8 = regs->uregs[8];
  ctx->r9 = regs->uregs[9];
  ctx->r10 = regs->uregs[10];
  ctx->r11 = regs->uregs[11];
  ctx->r12 = regs->uregs[12];

  memset (ctx->v, 0, sizeof (ctx->v));

  for (i = 0; i != G_N_ELEMENTS (ctx->r); i++)
    ctx->r[i] = regs->uregs[i];
  ctx->lr = regs->ARM_lr;
#elif defined (HAVE_ARM64)
  gsize i;

  ctx->pc = regs->pc;
  ctx->sp = regs->sp;
  ctx->nzcv = 0;

  for (i = 0; i != G_N_ELEMENTS (ctx->x); i++)
    ctx->x[i] = regs->regs[i];
  ctx->fp = regs->regs[29];
  ctx->lr = regs->regs[30];

  memset (ctx->v, 0, sizeof (ctx->v));
#elif defined (HAVE_MIPS)
  ctx->at = regs->regs[1];

  ctx->v0 = regs->regs[2];
  ctx->v1 = regs->regs[3];

  ctx->a0 = regs->regs[4];
  ctx->a1 = regs->regs[5];
  ctx->a2 = regs->regs[6];
  ctx->a3 = regs->regs[7];

  ctx->t0 = regs->regs[8];
  ctx->t1 = regs->regs[9];
  ctx->t2 = regs->regs[10];
  ctx->t3 = regs->regs[11];
  ctx->t4 = regs->regs[12];
  ctx->t5 = regs->regs[13];
  ctx->t6 = regs->regs[14];
  ctx->t7 = regs->regs[15];

  ctx->s0 = regs->regs[16];
  ctx->s1 = regs->regs[17];
  ctx->s2 = regs->regs[18];
  ctx->s3 = regs->regs[19];
  ctx->s4 = regs->regs[20];
  ctx->s5 = regs->regs[21];
  ctx->s6 = regs->regs[22];
  ctx->s7 = regs->regs[23];

  ctx->t8 = regs->regs[24];
  ctx->t9 = regs->regs[25];

  ctx->k0 = regs->regs[26];
  ctx->k1 = regs->regs[27];

  ctx->gp = regs->regs[28];
  ctx->sp = regs->regs[29];
  ctx->fp = regs->regs[30];

  ctx->ra = regs->regs[31];

  ctx->hi = regs->hi;
  ctx->lo = regs->lo;

  ctx->pc = regs->cp0_epc;
#else
# error Unsupported architecture
#endif
}

static void
gum_unparse_gp_regs (const GumCpuContext * ctx,
                     GumGPRegs * regs)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  regs->eip = ctx->eip;

  regs->edi = ctx->edi;
  regs->esi = ctx->esi;
  regs->ebp = ctx->ebp;
  regs->esp = ctx->esp;
  regs->ebx = ctx->ebx;
  regs->edx = ctx->edx;
  regs->ecx = ctx->ecx;
  regs->eax = ctx->eax;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  regs->rip = ctx->rip;

  regs->r15 = ctx->r15;
  regs->r14 = ctx->r14;
  regs->r13 = ctx->r13;
  regs->r12 = ctx->r12;
  regs->r11 = ctx->r11;
  regs->r10 = ctx->r10;
  regs->r9 = ctx->r9;
  regs->r8 = ctx->r8;

  regs->rdi = ctx->rdi;
  regs->rsi = ctx->rsi;
  regs->rbp = ctx->rbp;
  regs->rsp = ctx->rsp;
  regs->rbx = ctx->rbx;
  regs->rdx = ctx->rdx;
  regs->rcx = ctx->rcx;
  regs->rax = ctx->rax;
#elif defined (HAVE_ARM)
  gsize i;

  regs->ARM_pc = ctx->pc;
  regs->ARM_sp = ctx->sp;
  regs->ARM_cpsr = ctx->cpsr;

  regs->uregs[8] = ctx->r8;
  regs->uregs[9] = ctx->r9;
  regs->uregs[10] = ctx->r10;
  regs->uregs[11] = ctx->r11;
  regs->uregs[12] = ctx->r12;

  for (i = 0; i != G_N_ELEMENTS (ctx->r); i++)
    regs->uregs[i] = ctx->r[i];
  regs->ARM_lr = ctx->lr;
#elif defined (HAVE_ARM64)
  gsize i;

  regs->pc = ctx->pc;
  regs->sp = ctx->sp;

  for (i = 0; i != G_N_ELEMENTS (ctx->x); i++)
    regs->regs[i] = ctx->x[i];
  regs->regs[29] = ctx->fp;
  regs->regs[30] = ctx->lr;
#elif defined (HAVE_MIPS)
  regs->regs[1] = ctx->at;

  regs->regs[2] = ctx->v0;
  regs->regs[3] = ctx->v1;

  regs->regs[4] = ctx->a0;
  regs->regs[5] = ctx->a1;
  regs->regs[6] = ctx->a2;
  regs->regs[7] = ctx->a3;

  regs->regs[8] = ctx->t0;
  regs->regs[9] = ctx->t1;
  regs->regs[10] = ctx->t2;
  regs->regs[11] = ctx->t3;
  regs->regs[12] = ctx->t4;
  regs->regs[13] = ctx->t5;
  regs->regs[14] = ctx->t6;
  regs->regs[15] = ctx->t7;

  regs->regs[16] = ctx->s0;
  regs->regs[17] = ctx->s1;
  regs->regs[18] = ctx->s2;
  regs->regs[19] = ctx->s3;
  regs->regs[20] = ctx->s4;
  regs->regs[21] = ctx->s5;
  regs->regs[22] = ctx->s6;
  regs->regs[23] = ctx->s7;

  regs->regs[24] = ctx->t8;
  regs->regs[25] = ctx->t9;

  regs->regs[26] = ctx->k0;
  regs->regs[27] = ctx->k1;

  regs->regs[28] = ctx->gp;
  regs->regs[29] = ctx->sp;
  regs->regs[30] = ctx->fp;

  regs->regs[31] = ctx->ra;

  regs->hi = ctx->hi;
  regs->lo = ctx->lo;

  regs->cp0_epc = ctx->pc;
#else
# error Unsupported architecture
#endif
}

static gchar *
gum_thread_read_name (GumThreadId thread_id)
{
  gchar * name = NULL;
  gchar * path;
  gchar * comm = NULL;

  path = g_strdup_printf ("/proc/self/task/%" G_GSIZE_FORMAT "/comm",
      thread_id);
  if (!g_file_get_contents (path, &comm, NULL, NULL))
    goto beach;
  name = g_strchomp (g_steal_pointer (&comm));

beach:
  g_free (comm);
  g_free (path);

  return name;
}

static gboolean
gum_thread_read_state (GumThreadId tid,
                       GumThreadState * state)
{
  gboolean success = FALSE;
  gchar * path, * info = NULL;

  path = g_strdup_printf ("/proc/self/task/%" G_GSIZE_FORMAT "/stat", tid);
  if (g_file_get_contents (path, &info, NULL, NULL))
  {
    gchar * p;

    p = strrchr (info, ')') + 2;

    *state = gum_thread_state_from_proc_status_character (*p);
    success = TRUE;
  }

  g_free (info);
  g_free (path);

  return success;
}

static GumThreadState
gum_thread_state_from_proc_status_character (gchar c)
{
  switch (g_ascii_toupper (c))
  {
    case 'R': return GUM_THREAD_RUNNING;
    case 'S': return GUM_THREAD_WAITING;
    case 'D': return GUM_THREAD_UNINTERRUPTIBLE;
    case 'Z': return GUM_THREAD_UNINTERRUPTIBLE;
    case 'T': return GUM_THREAD_STOPPED;
    case 'W':
    default:
      return GUM_THREAD_UNINTERRUPTIBLE;
  }
}

static GumPageProtection
gum_page_protection_from_proc_perms_string (const gchar * perms)
{
  GumPageProtection prot = GUM_PAGE_NO_ACCESS;

  if (perms[0] == 'r')
    prot |= GUM_PAGE_READ;
  if (perms[1] == 'w')
    prot |= GUM_PAGE_WRITE;
  if (perms[2] == 'x')
    prot |= GUM_PAGE_EXECUTE;

  return prot;
}

static gssize
gum_get_regs (pid_t pid,
              guint type,
              gpointer data,
              gsize * size)
{
  if (gum_is_regset_supported)
  {
    struct iovec io = {
      .iov_base = data,
      .iov_len = *size
    };
    gssize ret = gum_libc_ptrace (PTRACE_GETREGSET, pid,
        GUINT_TO_POINTER (type), &io);
    if (ret >= 0)
    {
      *size = io.iov_len;
      return ret;
    }
    if (ret == -EPERM || ret == -ESRCH)
      return ret;
    gum_is_regset_supported = FALSE;
  }

  return gum_libc_ptrace (PTRACE_GETREGS, pid, NULL, data);
}

static gssize
gum_set_regs (pid_t pid,
              guint type,
              gconstpointer data,
              gsize size)
{
  if (gum_is_regset_supported)
  {
    struct iovec io = {
      .iov_base = (void *) data,
      .iov_len = size
    };
    gssize ret = gum_libc_ptrace (PTRACE_SETREGSET, pid,
        GUINT_TO_POINTER (type), &io);
    if (ret >= 0)
      return ret;
    if (ret == -EPERM || ret == -ESRCH)
      return ret;
    gum_is_regset_supported = FALSE;
  }

  return gum_libc_ptrace (PTRACE_SETREGS, pid, NULL, (gpointer) data);
}

static gssize
gum_libc_clone (GumCloneFunc child_func,
                gpointer child_stack,
                gint flags,
                gpointer arg,
                pid_t * parent_tidptr,
                GumUserDesc * tls,
                pid_t * child_tidptr)
{
  gssize result;
  gpointer * child_sp = child_stack;

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  *(--child_sp) = arg;
  *(--child_sp) = child_func;

  {
    register          gint ebx asm ("ebx") = flags;
    register    gpointer * ecx asm ("ecx") = child_sp;
    register       pid_t * edx asm ("edx") = parent_tidptr;
    register GumUserDesc * esi asm ("esi") = tls;
    register       pid_t * edi asm ("edi") = child_tidptr;

    asm volatile (
        "int $0x80\n\t"
        "test %%eax, %%eax\n\t"
        "jnz 1f\n\t"

        /* child: */
        "popl %%eax\n\t"
        "call *%%eax\n\t"
        "movl %%eax, %%ebx\n\t"
        "movl %[exit_syscall], %%eax\n\t"
        "int $0x80\n\t"

        /* parent: */
        "1:\n\t"
        : "=a" (result)
        : "0" (__NR_clone),
          "r" (ebx),
          "r" (ecx),
          "r" (edx),
          "r" (esi),
          "r" (edi),
          [exit_syscall] "i" (__NR_exit)
        : "cc", "memory"
    );
  }
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  *(--child_sp) = arg;
  *(--child_sp) = child_func;
  *(--child_sp) = tls;

  {
    register          gint rdi asm ("rdi") = flags;
    register    gpointer * rsi asm ("rsi") = child_sp;
    register       pid_t * rdx asm ("rdx") = parent_tidptr;
    register GumUserDesc * r10 asm ("r10") = tls;
    register       pid_t *  r8 asm ( "r8") = child_tidptr;

    asm volatile (
        "syscall\n\t"
        "test %%rax, %%rax\n\t"
        "jnz 1f\n\t"

        /* child: */
        "movq %[prctl_syscall], %%rax\n\t"
        "movq %[arch_set_fs], %%rdi\n\t"
        "popq %%rsi\n\t"
        "syscall\n\t"

        "popq %%rax\n\t"
        "popq %%rdi\n\t"
        "call *%%rax\n\t"
        "movq %%rax, %%rdi\n\t"
        "movq %[exit_syscall], %%rax\n\t"
        "syscall\n\t"

        /* parent: */
        "1:\n\t"
        : "=a" (result)
        : "0" (__NR_clone),
          "r" (rdi),
          "r" (rsi),
          "r" (rdx),
          "r" (r10),
          "r" (r8),
          [prctl_syscall] "i" (__NR_arch_prctl),
          [arch_set_fs] "i" (ARCH_SET_FS),
          [exit_syscall] "i" (__NR_exit)
        : "rcx", "r11", "cc", "memory"
    );
  }
#elif defined (HAVE_ARM) && defined (__ARM_EABI__)
  *(--child_sp) = child_func;
  *(--child_sp) = arg;

  {
    register        gssize r6 asm ("r6") = __NR_clone;
    register          gint r0 asm ("r0") = flags;
    register    gpointer * r1 asm ("r1") = child_sp;
    register       pid_t * r2 asm ("r2") = parent_tidptr;
    register GumUserDesc * r3 asm ("r3") = tls;
    register       pid_t * r4 asm ("r4") = child_tidptr;

    asm volatile (
        "push {r7}\n\t"
        "mov r7, r6\n\t"
        "swi 0x0\n\t"
        "cmp r0, #0\n\t"
        "bne 1f\n\t"

        /* child: */
        "pop {r0, r1}\n\t"
        "blx r1\n\t"
        "mov r7, %[exit_syscall]\n\t"
        "swi 0x0\n\t"

        /* parent: */
        "1:\n\t"
        "pop {r7}\n\t"
        : "+r" (r0)
        : "r" (r1),
          "r" (r2),
          "r" (r3),
          "r" (r4),
          "r" (r6),
          [exit_syscall] "i" (__NR_exit)
        : "cc", "memory"
    );

    result = r0;
  }
#elif defined (HAVE_ARM)
  *(--child_sp) = child_func;
  *(--child_sp) = arg;

  {
    register          gint r0 asm ("r0") = flags;
    register    gpointer * r1 asm ("r1") = child_sp;
    register       pid_t * r2 asm ("r2") = parent_tidptr;
    register GumUserDesc * r3 asm ("r3") = tls;
    register       pid_t * r4 asm ("r4") = child_tidptr;

    asm volatile (
        "swi %[clone_syscall]\n\t"
        "cmp r0, #0\n\t"
        "bne 1f\n\t"

        /* child: */
        "ldmia sp!, {r0, r1}\n\t"
        "blx r1\n\t"
        "swi %[exit_syscall]\n\t"

        /* parent: */
        "1:\n\t"
        : "+r" (r0)
        : "r" (r1),
          "r" (r2),
          "r" (r3),
          "r" (r4),
          [clone_syscall] "i" (__NR_clone),
          [exit_syscall] "i" (__NR_exit)
        : "cc", "memory"
    );

    result = r0;
  }
#elif defined (HAVE_ARM64)
  *(--child_sp) = child_func;
  *(--child_sp) = arg;

  {
    register        gssize x8 asm ("x8") = __NR_clone;
    register          gint x0 asm ("x0") = flags;
    register    gpointer * x1 asm ("x1") = child_sp;
    register       pid_t * x2 asm ("x2") = parent_tidptr;
    register GumUserDesc * x3 asm ("x3") = tls;
    register       pid_t * x4 asm ("x4") = child_tidptr;

    asm volatile (
        "svc 0x0\n\t"
        "cbnz x0, 1f\n\t"

        /* child: */
        "ldp x0, x1, [sp], #16\n\t"
        "blr x1\n\t"
        "mov x8, %x[exit_syscall]\n\t"
        "svc 0x0\n\t"

        /* parent: */
        "1:\n\t"
        : "+r" (x0)
        : "r" (x1),
          "r" (x2),
          "r" (x3),
          "r" (x4),
          "r" (x8),
          [exit_syscall] "i" (__NR_exit)
        : "cc", "memory"
    );

    result = x0;
  }
#elif defined (HAVE_MIPS)
  *(--child_sp) = child_func;
  *(--child_sp) = arg;

  {
    register          gint a0 asm ("$a0") = flags;
    register    gpointer * a1 asm ("$a1") = child_sp;
    register       pid_t * a2 asm ("$a2") = parent_tidptr;
    register GumUserDesc * a3 asm ("$a3") = tls;
    register       pid_t * a4 asm ("$t0") = child_tidptr;
    int status;
    gssize retval;

    asm volatile (
        ".set noreorder\n\t"
        "addiu $sp, $sp, -24\n\t"
        "sw $t0, 16($sp)\n\t"
        "li $v0, %[clone_syscall]\n\t"
        "syscall\n\t"
        "bne $a3, $0, 1f\n\t"
        "nop\n\t"
        "bne $v0, $0, 1f\n\t"
        "nop\n\t"

        /* child: */
        "lw $a0, 0($sp)\n\t"
        "lw $t9, 4($sp)\n\t"
        "addiu $sp, $sp, 8\n\t"
        "jalr $t9\n\t"
        "nop\n\t"
        "move $a0, $2\n\t"
        "li $v0, %[exit_syscall]\n\t"
        "syscall\n\t"

        /* parent: */
        "1:\n\t"
        "addiu $sp, $sp, 24\n\t"
        "move %0, $a3\n\t"
        "move %1, $v0\n\t"
        ".set reorder\n\t"
        : "=r" (status),
          "=r" (retval)
        : "r" (a0),
          "r" (a1),
          "r" (a2),
          "r" (a3),
          "r" (a4),
          [clone_syscall] "i" (__NR_clone),
          [exit_syscall] "i" (__NR_exit)
        : "$1", "$2", "$3",
          "$10", "$11", "$12", "$13", "$14", "$15",
          "$24", "$25",
          "hi", "lo",
          "memory"
    );

    if (status == 0)
    {
      result = retval;
    }
    else
    {
      result = -1;
      errno = retval;
    }
  }
#endif

  return result;
}

static gssize
gum_libc_read (gint fd,
               gpointer buf,
               gsize count)
{
  return gum_libc_syscall_3 (__NR_read, fd, GPOINTER_TO_SIZE (buf), count);
}

static gssize
gum_libc_write (gint fd,
                gconstpointer buf,
                gsize count)
{
  return gum_libc_syscall_3 (__NR_write, fd, GPOINTER_TO_SIZE (buf), count);
}

static pid_t
gum_libc_waitpid (pid_t pid,
                  int * status,
                  int options)
{
#ifdef __NR_waitpid
  return gum_libc_syscall_3 (__NR_waitpid, pid, GPOINTER_TO_SIZE (status),
      options);
#else
  return gum_libc_syscall_4 (__NR_wait4, pid, GPOINTER_TO_SIZE (status),
      options, 0);
#endif
}

static gssize
gum_libc_ptrace (gsize request,
                 pid_t pid,
                 gpointer address,
                 gpointer data)
{
  return gum_libc_syscall_4 (__NR_ptrace, request, pid,
      GPOINTER_TO_SIZE (address), GPOINTER_TO_SIZE (data));
}

static gssize
gum_libc_syscall_4 (gsize n,
                    gsize a,
                    gsize b,
                    gsize c,
                    gsize d)
{
  gssize result;

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  {
    register gsize ebx asm ("ebx") = a;
    register gsize ecx asm ("ecx") = b;
    register gsize edx asm ("edx") = c;
    register gsize esi asm ("esi") = d;

    asm volatile (
        "int $0x80\n\t"
        : "=a" (result)
        : "0" (n),
          "r" (ebx),
          "r" (ecx),
          "r" (edx),
          "r" (esi)
        : "cc", "memory"
    );
  }
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  {
    register gsize rdi asm ("rdi") = a;
    register gsize rsi asm ("rsi") = b;
    register gsize rdx asm ("rdx") = c;
    register gsize r10 asm ("r10") = d;

    asm volatile (
        "syscall\n\t"
        : "=a" (result)
        : "0" (n),
          "r" (rdi),
          "r" (rsi),
          "r" (rdx),
          "r" (r10)
        : "rcx", "r11", "cc", "memory"
    );
  }
#elif defined (HAVE_ARM) && defined (__ARM_EABI__)
  {
    register gssize r6 asm ("r6") = n;
    register  gsize r0 asm ("r0") = a;
    register  gsize r1 asm ("r1") = b;
    register  gsize r2 asm ("r2") = c;
    register  gsize r3 asm ("r3") = d;

    asm volatile (
        "push {r7}\n\t"
        "mov r7, r6\n\t"
        "swi 0x0\n\t"
        "pop {r7}\n\t"
        : "+r" (r0)
        : "r" (r1),
          "r" (r2),
          "r" (r3),
          "r" (r6)
        : "memory"
    );

    result = r0;
  }
#elif defined (HAVE_ARM)
  {
    register gssize r0 asm ("r0") = n;
    register  gsize r1 asm ("r1") = a;
    register  gsize r2 asm ("r2") = b;
    register  gsize r3 asm ("r3") = c;
    register  gsize r4 asm ("r4") = d;

    asm volatile (
        "swi %[syscall]\n\t"
        : "+r" (r0)
        : "r" (r1),
          "r" (r2),
          "r" (r3),
          "r" (r4),
          [syscall] "i" (__NR_syscall)
        : "memory"
    );

    result = r0;
  }
#elif defined (HAVE_ARM64)
  {
    register gssize x8 asm ("x8") = n;
    register  gsize x0 asm ("x0") = a;
    register  gsize x1 asm ("x1") = b;
    register  gsize x2 asm ("x2") = c;
    register  gsize x3 asm ("x3") = d;

    asm volatile (
        "svc 0x0\n\t"
        : "+r" (x0)
        : "r" (x1),
          "r" (x2),
          "r" (x3),
          "r" (x8)
        : "memory"
    );

    result = x0;
  }
#elif defined (HAVE_MIPS)
  {
    register gssize v0 asm ("$16") = n;
    register  gsize a0 asm ("$4") = a;
    register  gsize a1 asm ("$5") = b;
    register  gsize a2 asm ("$6") = c;
    register  gsize a3 asm ("$7") = d;
    int status;
    gssize retval;

    asm volatile (
        ".set noreorder\n\t"
        "move $2, %1\n\t"
        "syscall\n\t"
        "move %0, $7\n\t"
        "move %1, $2\n\t"
        ".set reorder\n\t"
        : "=r" (status),
          "=r" (retval)
        : "r" (v0),
          "r" (a0),
          "r" (a1),
          "r" (a2),
          "r" (a3)
        : "$1", "$2", "$3",
          "$10", "$11", "$12", "$13", "$14", "$15",
          "$24", "$25",
          "hi", "lo",
          "memory"
    );

    if (status == 0)
    {
      result = retval;
    }
    else
    {
      result = -1;
      errno = retval;
    }
  }
#endif

  return result;
}
```