Response:
Let's break down the thought process for analyzing this C code and generating the detailed response.

**1. Understanding the Request:**

The request asks for an analysis of the `gumexceptor-posix.c` file from the Frida dynamic instrumentation tool. The core of the request is to identify the file's functionality and connect it to several key areas: reverse engineering, low-level details (kernel, architecture), logical reasoning, common user errors, and how the code is reached during debugging.

**2. Initial Code Scan and Keyword Identification:**

The first step is to read through the code, looking for prominent keywords and structures. This immediately reveals:

* **Includes:**  `signal.h`, OS-specific headers (`gumdarwin.h`, `gumlinux.h` etc.), `capstone.h`. This suggests handling signals and instruction disassembly.
* **Data Structures:** `GumExceptorBackend`, `GumExceptionHandler`, `GumExceptionDetails`, `GumCpuContext`. These are key data structures related to exception handling.
* **Function Names:**  Functions like `gum_exceptor_backend_on_signal`, `gum_parse_context`, `gum_unparse_context`, `gum_infer_memory_operation`, `gum_disassemble_instruction_at` are very telling about the file's purpose.
* **Global Variables:** `the_backend`, `gum_original_signal`, `gum_original_sigaction`. These hint at a singleton pattern and the interception/replacement of system calls.
* **Preprocessor Directives:**  `#ifndef GUM_DIET`, platform-specific `#ifdef` blocks. This signals conditional compilation based on the target OS.
* **GObject:**  The use of `G_DEFINE_TYPE` and `GObject` inheritance indicates this is part of a larger GLib-based framework.

**3. High-Level Functionality Identification:**

Based on the initial scan, the core functionality becomes apparent:  **This code is responsible for intercepting and handling signals (especially those indicating errors like segmentation faults) within a process, allowing Frida to analyze and potentially modify the process's behavior when these signals occur.**

**4. Deeper Dive into Specific Functionality and Connections:**

Now, let's go through the request's specific points and connect them to the code:

* **Functionality Listing:**  This involves summarizing the purpose of the main functions and their interactions. Think of the lifecycle of an exception:  attaching handlers, the signal occurring, Frida's handler being called, information extraction, and potentially resuming execution.

* **Relationship to Reverse Engineering:** This is a core aspect of Frida. The ability to intercept signals allows reverse engineers to:
    * **Identify crash locations:**  SIGSEGV/SIGBUS are prime examples.
    * **Analyze program state at the crash:**  The `GumCpuContext` provides register values.
    * **Modify program behavior:** Frida can potentially alter the context to skip the faulting instruction or change data.

* **Binary/Low-Level Details:** The code interacts heavily with:
    * **Signals:**  Fundamental OS mechanism for inter-process communication and error notification.
    * **CPU Context:**  Direct manipulation of register values, instruction pointers, etc.
    * **Instruction Disassembly:**  Using Capstone to understand the instruction that caused the error.
    * **Memory Operations:** Inferring whether an access violation was a read, write, or execute.
    * **Kernel and Framework:**  The code interacts with kernel-level signal handling and relies on frameworks like GLib.

* **Logical Reasoning (Hypothetical Input/Output):**  Consider a scenario where a segmentation fault occurs. The input would be the signal (`SIGSEGV`), the `siginfo_t` (containing the faulting address), and the CPU context. The output would be the populated `GumExceptionDetails` structure, providing Frida with structured information about the error.

* **User/Programming Errors:** Think about common mistakes that lead to the intercepted signals:
    * **Null pointer dereference:**  Leads to SIGSEGV.
    * **Accessing out-of-bounds memory:**  Also leads to SIGSEGV or SIGBUS.
    * **Division by zero:** Leads to SIGFPE.
    * **Executing invalid instructions:** Leads to SIGILL.

* **User Steps to Reach the Code (Debugging Context):** Trace the user actions that would trigger this code:
    1. Attaching Frida to a process.
    2. Frida setting up its exception handlers (`gum_exceptor_backend_attach`).
    3. The target process encountering an error signal.
    4. The OS invoking Frida's signal handler (`gum_exceptor_backend_on_signal`).

**5. Structuring the Response:**

Organize the information clearly based on the request's categories. Use headings and bullet points for readability. Provide concrete examples to illustrate the concepts. Explain the code's logic in a way that's understandable even without deep C knowledge.

**6. Refining and Expanding:**

After the initial draft, review and refine the response:

* **Add more detail:**  Explain the purpose of specific functions or code blocks.
* **Provide more specific examples:** Instead of just saying "null pointer dereference," show how it might manifest in code.
* **Clarify technical terms:** Briefly explain terms like "signal," "CPU context," and "disassembly" if necessary.
* **Ensure accuracy:** Double-check the code to make sure the explanations are correct.

**Self-Correction Example during the process:**

Initially, I might have focused too much on the signal interception aspect. However, realizing the importance of `gum_infer_memory_operation` and the use of Capstone, I would then expand on the instruction disassembly and memory operation inference capabilities, as these are crucial for understanding the context of the exception. Similarly, initially, I might have overlooked the explanation of how the user interacts with Frida to trigger this code, and then added the "User Steps" section for clarity.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/gum/backend-posix/gumexceptor-posix.c` 这个文件。

**文件功能概述**

这个 C 源代码文件 `gumexceptor-posix.c` 是 Frida 动态 instrumentation 工具中负责处理 POSIX 系统（例如 Linux、macOS、FreeBSD、QNX 等）上的异常（exceptions）的核心组件。它的主要功能是：

1. **注册和管理信号处理函数:**  它会拦截并替换进程中默认的信号处理函数，特别是那些指示程序错误的信号，例如 `SIGSEGV` (段错误), `SIGABRT` (中止), `SIGILL` (非法指令) 等。
2. **在异常发生时捕获上下文信息:** 当上述信号发生时，Frida 的这个模块会接管控制权，并提取发生异常时的详细信息，包括：
    * 导致异常的线程 ID。
    * 异常的类型（访问违规、非法指令等）。
    * 发生异常的内存地址。
    * CPU 的上下文信息（寄存器值，指令指针等）。
3. **调用用户定义的回调函数:**  Frida 允许用户注册一个异常处理回调函数。当捕获到异常时，`gumexceptor-posix.c` 会调用这个用户提供的函数，并将捕获到的异常信息传递给它。用户可以在这个回调函数中执行自定义的操作，例如打印日志、修改程序状态、阻止程序崩溃等。
4. **恢复程序执行或传递给原始处理函数:**  根据用户回调函数的返回值，Frida 可以选择：
    * 修改 CPU 上下文后恢复程序的执行，尝试绕过导致异常的指令。
    * 将异常传递给进程原有的信号处理函数（如果存在），让系统按照默认的方式处理异常（通常会导致程序崩溃）。

**与逆向方法的关系及举例说明**

`gumexceptor-posix.c` 在逆向工程中扮演着至关重要的角色，因为它允许逆向工程师在程序发生错误时进行精细的控制和分析。

**举例说明:**

* **捕获和分析崩溃:**  当逆向一个不熟悉的程序，尤其是那些没有源代码的二进制程序时，程序崩溃是很常见的。`gumexceptor-posix.c` 可以捕获 `SIGSEGV` 或 `SIGABRT` 等信号，并提供崩溃时的指令地址、寄存器状态等信息，帮助逆向工程师定位崩溃的原因。例如，如果一个程序因为访问空指针而崩溃，Frida 可以报告导致崩溃的指令和当时寄存器中保存的空指针地址。
* **动态调试和代码插桩:** 逆向工程师可以通过 Frida 注册一个异常处理回调函数，当特定的异常发生时，例如执行到某个特定的非法指令（可以通过修改代码或内存来触发），可以暂停程序执行，检查内存和寄存器状态，甚至修改这些状态，然后恢复程序的执行，以观察程序的后续行为。
* **绕过反调试机制:**  某些程序会使用反调试技术，例如检测是否被调试器附加，并故意触发异常来干扰调试。Frida 可以捕获这些预期的异常，并阻止程序崩溃，从而绕过这些反调试机制。例如，程序可能会尝试访问一个已知会导致异常的地址，如果被调试器附加，这个访问可能不会立即崩溃，从而被程序检测到。Frida 可以截获这个异常，让程序误以为没有被调试。

**涉及的二进制底层、Linux/Android 内核及框架知识及举例说明**

`gumexceptor-posix.c` 深入到操作系统的底层，涉及到以下知识：

* **POSIX 信号机制:**  它依赖于 POSIX 标准定义的信号 (signals) 机制来捕获和处理程序运行时的事件，特别是错误信号。代码中使用了 `signal.h` 头文件，以及 `sigaction` 结构体来设置自定义的信号处理函数。
* **CPU 上下文 (CPU Context):**  当信号发生时，操作系统会将 CPU 的当前状态（包括寄存器值、指令指针等）保存在一个称为上下文的结构中。`gumexceptor-posix.c` 中的 `gum_parse_context` 和 `gum_unparse_context` 函数负责解析和修改这个上下文结构。这部分代码会根据不同的架构（x86, ARM, ARM64 等）调用不同的平台相关函数 (例如 `gum_darwin_parse_native_thread_state`, `gum_linux_parse_ucontext` 等)。
* **指令反汇编 (Instruction Disassembly):**  为了更精确地判断异常的原因，例如判断一个内存访问违规是读操作还是写操作，`gumexceptor-posix.c` 使用了 Capstone 反汇编引擎 (`capstone.h`)。`gum_disassemble_instruction_at` 函数用于反汇编导致异常的指令。
* **内存操作推断 (Memory Operation Inference):**  `gum_infer_memory_operation` 函数通过分析导致异常的指令，尝试推断出导致内存访问违规的具体操作类型（读、写或执行）。这需要理解不同 CPU 架构的指令集和寻址方式。
* **Linux/Android 内核 API (间接涉及):** 虽然代码本身不直接调用 Linux/Android 内核 API，但它所处理的信号机制是内核提供的功能。Frida 通过标准 C 库的接口与内核进行交互。在 Android 上，可能需要考虑 bionic C 库的特定实现。
* **动态链接和符号解析:**  为了替换 `signal` 和 `sigaction` 等系统调用，`gumexceptor-posix.c` 使用了动态链接和符号解析的技术 (`gum_resolve_symbol`) 来找到这些函数的地址。

**举例说明:**

* **`gum_parse_context(context, cpu_context)`:**  这个函数接收操作系统传递过来的 `ucontext_t` 结构体（在 Linux 上）或 `mcontext_t` 结构体（在 macOS 上），并将其中的 CPU 寄存器信息提取到 Frida 自定义的 `GumCpuContext` 结构体中。对于 ARM 架构，可能需要从 `uc->uc_mcontext->__ss.__pc` 中获取程序计数器 (PC) 的值。
* **`gum_infer_arm_memory_operation(cs_insn * insn)`:**  这个函数分析反汇编后的 ARM 指令，例如，如果指令是 `STR` (存储寄存器到内存)，则推断出这是一个写操作。
* **`gum_original_sigaction = gum_resolve_symbol ("sigaction", module_candidates);`:** 这行代码尝试在 libc 或 libpthread 等共享库中找到 `sigaction` 函数的地址，以便 Frida 可以替换它。

**逻辑推理及假设输入与输出**

`gumexceptor-posix.c` 中包含一些逻辑推理，例如：

* **判断内存访问类型:**  `gum_infer_memory_operation` 函数基于反汇编的指令进行逻辑判断，推断内存操作是读还是写。
* **判断是否需要链式调用旧的信号处理函数:** `gum_is_signal_handler_chainable` 函数判断旧的信号处理函数是否是默认的处理方式，如果是，则在 Frida 的处理之后，可以选择调用旧的处理函数。

**假设输入与输出 (以 SIGSEGV 为例):**

**假设输入:**

* **信号:** `SIGSEGV` (段错误)。
* **`siginfo_t * siginfo`:** 包含导致错误的内存地址，例如 `siginfo->si_addr = 0x12345678`。
* **`void * context`:**  包含发生错误时的 CPU 上下文信息，例如指令指针指向 `0x40001000`，寄存器 R0 的值为 `0x0` (可能是导致空指针访问的原因)。

**逻辑推理过程 (在 `gum_exceptor_backend_on_signal` 中):**

1. 接收到 `SIGSEGV` 信号。
2. 设置异常类型 `ed.type = GUM_EXCEPTION_ACCESS_VIOLATION;`。
3. 调用 `gum_parse_context(context, cpu_context)` 解析 CPU 上下文，`cpu_context->pc` 将被设置为 `0x40001000`，`cpu_context` 的其他成员也会被填充。
4. 设置异常发生的地址 `ed.address = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XIP (cpu_context));` (在 ARM 上可能是 `cpu_context->pc`)，即 `0x40001000`。
5. 调用 `gum_infer_memory_operation(ed.address, cpu_context)` 反汇编 `0x40001000` 处的指令，并尝试判断内存访问类型。如果指令是 `LDR R1, [R0]` 并且 R0 的值为 `0x0`，则推断出这是一个读操作。
6. 设置内存操作细节 `md->operation = GUM_MEMOP_READ; md->address = siginfo->si_addr;`，即读取地址 `0x12345678` 失败。
7. 调用用户注册的异常处理回调函数 `self->handler (&ed, self->handler_data)`，将包含上述信息的 `ed` 传递给用户。

**假设输出:**

* **`GumExceptionDetails ed`:**  包含以下信息：
    * `ed.type = GUM_EXCEPTION_ACCESS_VIOLATION`
    * `ed.address = (void *)0x40001000`
    * `ed.memory.operation = GUM_MEMOP_READ`
    * `ed.memory.address = (void *)0x12345678`
    * `ed.context.pc = 0x40001000`
    * `ed.context.r0 = 0x0`
    * ...其他寄存器值

**用户或编程常见的使用错误及举例说明**

尽管 `gumexceptor-posix.c` 是 Frida 内部的组件，但用户在使用 Frida 时的一些错误操作或对 API 的不当理解可能会间接地与这个文件产生关联。

**举例说明:**

* **用户提供的异常处理回调函数不当:**  如果用户提供的回调函数尝试执行一些不安全的操作，例如访问无效的内存，可能会导致回调函数自身崩溃，从而触发新的异常。虽然不是 `gumexceptor-posix.c` 的直接错误，但会影响 Frida 的整体行为。
* **在异常处理回调函数中修改了错误的 CPU 上下文:**  用户可以在回调函数中修改 `GumExceptionDetails` 中的 `context` 字段，从而影响程序恢复后的执行。如果修改不当，可能会导致程序行为异常或崩溃。例如，用户可能错误地修改了指令指针，导致程序跳转到无效的地址。
* **误解 Frida 的异常处理机制:**  用户可能认为 Frida 能捕获所有类型的异常，但实际上 `gumexceptor-posix.c` 主要处理的是由信号引起的异常。对于 C++ 异常或其他语言的异常，需要使用 Frida 提供的其他机制进行处理。

**用户操作是如何一步步的到达这里，作为调试线索**

当用户使用 Frida 对一个运行中的进程进行动态 instrumentation 时，如果目标进程发生了由信号引起的异常，那么控制流就会到达 `gumexceptor-posix.c` 中的代码。以下是一个可能的步骤：

1. **用户编写 Frida 脚本:** 用户使用 JavaScript 或 Python 编写 Frida 脚本，并使用 Frida 客户端 (例如 `frida` 命令行工具或 Python 库) 将脚本注入到目标进程中。
2. **Frida 初始化:** Frida 的 Gum 库在目标进程中被加载和初始化。`gumexceptor-posix.c` 中的 `gum_exceptor_backend_new` 函数会被调用，创建一个 `GumExceptorBackend` 实例，并注册 Frida 的信号处理函数来替换原有的处理函数 (`gum_exceptor_backend_attach`)。
3. **目标进程运行并发生异常:** 目标进程在执行过程中遇到了错误，例如尝试访问空指针，导致操作系统发送一个 `SIGSEGV` 信号给该进程。
4. **操作系统传递信号:** 操作系统内核会暂停目标进程的执行，并将 `SIGSEGV` 信号传递给进程。由于 Frida 已经替换了默认的 `SIGSEGV` 处理函数，所以 Frida 的 `gum_exceptor_backend_on_signal` 函数被调用。
5. **Frida 捕获异常并调用用户回调:** `gum_exceptor_backend_on_signal` 函数会提取异常信息，并调用用户在 Frida 脚本中注册的异常处理回调函数（如果注册了）。
6. **用户回调处理 (可选):** 用户提供的回调函数可以检查异常信息，例如打印日志，修改程序状态，或者指示 Frida 恢复程序的执行。
7. **Frida 恢复或传递异常:** 根据用户回调函数的返回值，Frida 可以选择修改 CPU 上下文并恢复目标进程的执行 (`gum_unparse_context`)，或者将异常传递给原有的信号处理函数，导致程序崩溃。

**作为调试线索:**

当你在调试 Frida 脚本或目标进程的行为时，如果发现程序在发生错误时 Frida 的异常处理机制没有按预期工作，或者你想深入了解 Frida 如何处理异常，那么 `gumexceptor-posix.c` 的代码可以提供重要的线索：

* **检查 Frida 是否成功拦截了信号:**  你可以通过日志或断点确认 `gum_exceptor_backend_on_signal` 函数是否被调用。
* **查看捕获到的异常信息:**  通过在 `gum_exceptor_backend_on_signal` 中设置断点，你可以检查 `GumExceptionDetails` 结构体中的内容，了解异常的类型、地址、以及当时的 CPU 上下文。
* **理解 Frida 如何推断内存操作类型:**  分析 `gum_infer_memory_operation` 函数的代码可以帮助你理解 Frida 是如何判断一个内存访问违规是读还是写的。
* **排查用户回调函数的问题:** 如果用户提供的回调函数导致问题，你可以检查 `gumexceptor-posix.c` 中调用回调函数的逻辑，以及回调函数的返回值如何影响 Frida 的后续行为。

总而言之，`gumexceptor-posix.c` 是 Frida 处理 POSIX 系统异常的核心，它连接了操作系统底层的信号机制、CPU 上下文以及 Frida 用户提供的自定义处理逻辑，为动态 instrumentation 提供了强大的能力。理解这个文件的功能和实现细节，对于深入使用 Frida 进行逆向工程和动态分析至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-posix/gumexceptor-posix.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2015-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumexceptorbackend.h"

#include "guminterceptor.h"
#ifdef HAVE_DARWIN
# include "gum/gumdarwin.h"
#endif
#ifdef HAVE_LINUX
# include "gum/gumlinux.h"
#endif
#ifdef HAVE_FREEBSD
# include "gum/gumfreebsd.h"
#endif
#ifdef HAVE_QNX
# include "gum/gumqnx.h"
/* Work around conflict between QNX headers and Capstone. */
# undef ARM_REG_R0
# undef ARM_REG_R1
# undef ARM_REG_R2
# undef ARM_REG_R3
# undef ARM_REG_R4
# undef ARM_REG_R5
# undef ARM_REG_R6
# undef ARM_REG_R7
# undef ARM_REG_R8
# undef ARM_REG_R9
# undef ARM_REG_R10
# undef ARM_REG_R11
# undef ARM_REG_R12
# undef ARM_REG_R13
# undef ARM_REG_R14
# undef ARM_REG_R15
# undef ARM_REG_SPSR
# undef ARM_REG_FP
# undef ARM_REG_IP
# undef ARM_REG_SP
# undef ARM_REG_LR
# undef ARM_REG_PC
#endif

#include <capstone.h>
#include <signal.h>
#include <stdlib.h>
#ifdef HAVE_QNX
# include <sys/debug.h>
# include <unix.h>
#endif

#if defined (HAVE_DARWIN) || defined (HAVE_FREEBSD) || defined (HAVE_QNX)
typedef sig_t GumSignalHandler;
#else
typedef sighandler_t GumSignalHandler;
#endif

struct _GumExceptorBackend
{
  GObject parent;

  gboolean disposed;

  GumExceptionHandler handler;
  gpointer handler_data;

  struct sigaction ** old_handlers;
  gint num_old_handlers;

  GumInterceptor * interceptor;
};

static void gum_exceptor_backend_dispose (GObject * object);

static void gum_exceptor_backend_attach (GumExceptorBackend * self);
static void gum_exceptor_backend_detach (GumExceptorBackend * self);
static void gum_exceptor_backend_detach_handler (GumExceptorBackend * self,
    int sig);
static sig_t gum_exceptor_backend_replacement_signal (int sig, sig_t handler);
static int gum_exceptor_backend_replacement_sigaction (int sig,
    const struct sigaction * act, struct sigaction * oact);
static void gum_exceptor_backend_on_signal (int sig, siginfo_t * siginfo,
    void * context);
static void gum_exceptor_backend_abort (GumExceptorBackend * self,
    GumExceptionDetails * details);

static gboolean gum_is_signal_handler_chainable (sig_t handler);

static gpointer gum_resolve_symbol (const gchar * symbol_name,
    const gchar ** module_candidates);
static gpointer gum_try_resolve_symbol (const gchar * symbol_name,
    const gchar ** module_candidates);

static void gum_parse_context (gconstpointer context,
    GumCpuContext * ctx);
static void gum_unparse_context (const GumCpuContext * ctx,
    gpointer context);

static GumMemoryOperation gum_infer_memory_operation (gconstpointer address,
    GumCpuContext * context);
static cs_insn * gum_disassemble_instruction_at (gconstpointer address,
    GumCpuContext * context);
#if defined (HAVE_I386)
static GumMemoryOperation gum_infer_x86_memory_operation (cs_insn * insn);
#elif defined (HAVE_ARM)
static GumMemoryOperation gum_infer_arm_memory_operation (cs_insn * insn);
#elif defined (HAVE_ARM64)
static GumMemoryOperation gum_infer_arm64_memory_operation (
    cs_insn * insn);
#endif

G_DEFINE_TYPE (GumExceptorBackend, gum_exceptor_backend, G_TYPE_OBJECT)

static GumExceptorBackend * the_backend = NULL;

static GumSignalHandler (* gum_original_signal) (int signum,
    GumSignalHandler handler);
static int (* gum_original_sigaction) (int signum, const struct sigaction * act,
    struct sigaction * oldact);

void
_gum_exceptor_backend_prepare_to_fork (void)
{
}

void
_gum_exceptor_backend_recover_from_fork_in_parent (void)
{
}

void
_gum_exceptor_backend_recover_from_fork_in_child (void)
{
}

static void
gum_exceptor_backend_class_init (GumExceptorBackendClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);
  const gchar * libc;
  gchar * libdir = NULL;
  gchar * pthread = NULL;
  const gchar * module_candidates[3];

  object_class->dispose = gum_exceptor_backend_dispose;

  libc = gum_process_query_libc_name ();

#if defined (HAVE_DARWIN)
  module_candidates[0] = libc;
  module_candidates[1] = NULL;

  gum_original_signal = gum_resolve_symbol ("signal", module_candidates);
#elif defined (HAVE_ANDROID)
  module_candidates[0] = libc;
  module_candidates[1] = NULL;

  gum_original_signal = gum_try_resolve_symbol ("signal", module_candidates);
  if (gum_original_signal == NULL)
    gum_original_signal = gum_resolve_symbol ("bsd_signal", module_candidates);
#elif defined (HAVE_QNX)
  module_candidates[0] = libc;
  module_candidates[1] = NULL;

  gum_original_signal = gum_resolve_symbol ("signal", module_candidates);
#else
  libdir = g_path_get_dirname (libc);
  pthread = g_build_filename (libdir, "libpthread.so.0", NULL);

  module_candidates[0] = pthread;
  module_candidates[1] = libc;
  module_candidates[2] = NULL;

  gum_original_signal = gum_resolve_symbol ("signal", module_candidates);
#endif

  gum_original_sigaction = gum_resolve_symbol ("sigaction", module_candidates);

  g_free (pthread);
  g_free (libdir);
}

static void
gum_exceptor_backend_init (GumExceptorBackend * self)
{
  self->interceptor = gum_interceptor_obtain ();

  the_backend = self;
}

static void
gum_exceptor_backend_dispose (GObject * object)
{
  GumExceptorBackend * self = GUM_EXCEPTOR_BACKEND (object);

  if (!self->disposed)
  {
    self->disposed = TRUE;

    gum_exceptor_backend_detach (self);

    g_object_unref (self->interceptor);
    self->interceptor = NULL;

    the_backend = NULL;
  }

  G_OBJECT_CLASS (gum_exceptor_backend_parent_class)->dispose (object);
}

GumExceptorBackend *
gum_exceptor_backend_new (GumExceptionHandler handler,
                          gpointer user_data)
{
  GumExceptorBackend * backend;

  backend = g_object_new (GUM_TYPE_EXCEPTOR_BACKEND, NULL);
  backend->handler = handler;
  backend->handler_data = user_data;

  gum_exceptor_backend_attach (backend);

  return backend;
}

static void
gum_exceptor_backend_attach (GumExceptorBackend * self)
{
  GumInterceptor * interceptor = self->interceptor;
  const gint handled_signals[] = {
    SIGABRT,
    SIGSEGV,
    SIGBUS,
    SIGILL,
    SIGFPE,
    SIGTRAP,
    SIGSYS,
  };
  gint highest, i;
  struct sigaction action;

  highest = 0;
  for (i = 0; i != G_N_ELEMENTS (handled_signals); i++)
    highest = MAX (handled_signals[i], highest);
  g_assert (highest > 0);
  self->num_old_handlers = highest + 1;
  self->old_handlers = g_new0 (struct sigaction *, self->num_old_handlers);

  action.sa_sigaction = gum_exceptor_backend_on_signal;
  sigemptyset (&action.sa_mask);
  action.sa_flags = SA_SIGINFO | SA_NODEFER;
#ifdef SA_ONSTACK
  action.sa_flags |= SA_ONSTACK;
#endif
  for (i = 0; i != G_N_ELEMENTS (handled_signals); i++)
  {
    gint sig = handled_signals[i];
    struct sigaction * old_handler;

    old_handler = g_slice_new0 (struct sigaction);
    self->old_handlers[sig] = old_handler;
    gum_original_sigaction (sig, &action, old_handler);
  }

  gum_interceptor_begin_transaction (interceptor);

  gum_interceptor_replace (interceptor, gum_original_signal,
      gum_exceptor_backend_replacement_signal, self, NULL);
  gum_interceptor_replace (interceptor, gum_original_sigaction,
      gum_exceptor_backend_replacement_sigaction, self, NULL);

  gum_interceptor_end_transaction (interceptor);
}

static void
gum_exceptor_backend_detach (GumExceptorBackend * self)
{
  GumInterceptor * interceptor = self->interceptor;
  gint i;

  gum_interceptor_begin_transaction (interceptor);

  gum_interceptor_revert (interceptor, gum_original_signal);
  gum_interceptor_revert (interceptor, gum_original_sigaction);

  gum_interceptor_end_transaction (interceptor);

  for (i = 0; i != self->num_old_handlers; i++)
    gum_exceptor_backend_detach_handler (self, i);
  g_free (self->old_handlers);
  self->old_handlers = NULL;
  self->num_old_handlers = 0;
}

static void
gum_exceptor_backend_detach_handler (GumExceptorBackend * self,
                                     int sig)
{
  struct sigaction * old_handler;

  old_handler = self->old_handlers[sig];
  if (old_handler == NULL)
    return;

  self->old_handlers[sig] = NULL;
  gum_original_sigaction (sig, old_handler, NULL);
  g_slice_free (struct sigaction, old_handler);
}

static struct sigaction *
gum_exceptor_backend_get_old_handler (GumExceptorBackend * self,
                                      gint sig)
{
  if (sig < 0 || sig >= self->num_old_handlers)
    return NULL;

  return self->old_handlers[sig];
}

static sig_t
gum_exceptor_backend_replacement_signal (int sig,
                                         sig_t handler)
{
  GumExceptorBackend * self;
  GumInvocationContext * ctx;
  struct sigaction * old_handler;
  sig_t result;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  self = GUM_EXCEPTOR_BACKEND (
      gum_invocation_context_get_replacement_data (ctx));

  old_handler = gum_exceptor_backend_get_old_handler (self, sig);
  if (old_handler == NULL)
    return gum_original_signal (sig, handler);

  result = ((old_handler->sa_flags & SA_SIGINFO) == 0)
      ? old_handler->sa_handler
      : SIG_DFL;

  old_handler->sa_handler = handler;
  old_handler->sa_flags &= ~SA_SIGINFO;

  return result;
}

static int
gum_exceptor_backend_replacement_sigaction (int sig,
                                            const struct sigaction * act,
                                            struct sigaction * oact)
{
  GumExceptorBackend * self;
  GumInvocationContext * ctx;
  struct sigaction * old_handler;
  struct sigaction previous_old_handler;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert (ctx != NULL);

  self = GUM_EXCEPTOR_BACKEND (
      gum_invocation_context_get_replacement_data (ctx));

  old_handler = gum_exceptor_backend_get_old_handler (self, sig);
  if (old_handler == NULL)
    return gum_original_sigaction (sig, act, oact);

  previous_old_handler = *old_handler;
  if (act != NULL)
    *old_handler = *act;
  if (oact != NULL)
    *oact = previous_old_handler;

  return 0;
}

static void
gum_exceptor_backend_on_signal (int sig,
                                siginfo_t * siginfo,
                                void * context)
{
  GumExceptorBackend * self = the_backend;
  GumExceptionDetails ed;
  GumExceptionMemoryDetails * md = &ed.memory;
  GumCpuContext * cpu_context = &ed.context;
  struct sigaction * action;

  action = self->old_handlers[sig];

  ed.thread_id = gum_process_get_current_thread_id ();

  switch (sig)
  {
    case SIGABRT:
      ed.type = GUM_EXCEPTION_ABORT;
      break;
    case SIGSEGV:
    case SIGBUS:
      ed.type = GUM_EXCEPTION_ACCESS_VIOLATION;
      break;
    case SIGILL:
      ed.type = GUM_EXCEPTION_ILLEGAL_INSTRUCTION;
      break;
    case SIGFPE:
      ed.type = GUM_EXCEPTION_ARITHMETIC;
      break;
    case SIGTRAP:
      ed.type = GUM_EXCEPTION_BREAKPOINT;
      break;
    default:
      ed.type = GUM_EXCEPTION_SYSTEM;
      break;
  }

  gum_parse_context (context, cpu_context);
  ed.native_context = context;

#if defined (HAVE_I386)
  ed.address = GSIZE_TO_POINTER (GUM_CPU_CONTEXT_XIP (cpu_context));
#elif defined (HAVE_ARM) || defined (HAVE_ARM64)
  ed.address = GSIZE_TO_POINTER (cpu_context->pc);
#elif defined (HAVE_MIPS)
  ed.address = GSIZE_TO_POINTER (cpu_context->pc);
#else
# error Unsupported architecture
#endif

  switch (sig)
  {
    case SIGSEGV:
    case SIGBUS:
      if (siginfo->si_addr == ed.address)
        md->operation = GUM_MEMOP_EXECUTE;
      else
        md->operation = gum_infer_memory_operation (ed.address, cpu_context);
      md->address = siginfo->si_addr;
      break;
    default:
      md->operation = GUM_MEMOP_INVALID;
      md->address = NULL;
      break;
  }

  if (action == NULL)
    gum_exceptor_backend_abort (self, &ed);

  if (self->handler (&ed, self->handler_data))
  {
    gum_unparse_context (cpu_context, context);
    return;
  }

  if ((action->sa_flags & SA_SIGINFO) != 0)
  {
    void (* old_sigaction) (int, siginfo_t *, void *) = action->sa_sigaction;

    if (old_sigaction != NULL)
      old_sigaction (sig, siginfo, context);
    else
      goto panic;
  }
  else
  {
    void (* old_handler) (int) = action->sa_handler;

    if (gum_is_signal_handler_chainable (old_handler))
      old_handler (sig);
    else if (action->sa_handler != SIG_IGN)
      goto panic;
  }

  if (sig == SIGABRT)
    goto panic;

  return;

panic:
  gum_exceptor_backend_detach_handler (self, sig);
}

static void
gum_exceptor_backend_abort (GumExceptorBackend * self,
                            GumExceptionDetails * details)
{
  /* TODO: should we create a backtrace and log it? */
  abort ();
}

static gboolean
gum_is_signal_handler_chainable (sig_t handler)
{
  return handler != SIG_DFL && handler != SIG_IGN && handler != SIG_ERR;
}

static gpointer
gum_resolve_symbol (const gchar * symbol_name,
                    const gchar ** module_candidates)
{
  gpointer result;

  result = gum_try_resolve_symbol (symbol_name, module_candidates);
  if (result == NULL)
    gum_panic ("Unable to locate %s(); please file a bug", symbol_name);

  return result;
}

static gpointer
gum_try_resolve_symbol (const gchar * symbol_name,
                        const gchar ** module_candidates)
{
  const gchar ** cur, * module_name;

  for (cur = module_candidates; (module_name = *cur) != NULL; cur++)
  {
    GumAddress address;

    address = gum_module_find_export_by_name (module_name, symbol_name);
    if (address != 0)
      return GSIZE_TO_POINTER (address);
  }

  return NULL;
}

#if defined (HAVE_DARWIN)

static void
gum_parse_context (gconstpointer context,
                   GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_darwin_parse_native_thread_state (&uc->uc_mcontext->__ss, ctx);
}

static void
gum_unparse_context (const GumCpuContext * ctx,
                     gpointer context)
{
  ucontext_t * uc = context;

  gum_darwin_unparse_native_thread_state (ctx, &uc->uc_mcontext->__ss);
}

#elif defined (HAVE_LINUX)

static void
gum_parse_context (gconstpointer context,
                   GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_linux_parse_ucontext (uc, ctx);
}

static void
gum_unparse_context (const GumCpuContext * ctx,
                     gpointer context)
{
  ucontext_t * uc = context;

  gum_linux_unparse_ucontext (ctx, uc);
}

#elif defined (HAVE_FREEBSD)

static void
gum_parse_context (gconstpointer context,
                   GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_freebsd_parse_ucontext (uc, ctx);
}

static void
gum_unparse_context (const GumCpuContext * ctx,
                     gpointer context)
{
  ucontext_t * uc = context;

  gum_freebsd_unparse_ucontext (ctx, uc);
}

#elif defined (HAVE_QNX)

static void
gum_parse_context (gconstpointer context,
                   GumCpuContext * ctx)
{
  const ucontext_t * uc = context;

  gum_qnx_parse_ucontext (uc, ctx);
}

static void
gum_unparse_context (const GumCpuContext * ctx,
                     gpointer context)
{
  ucontext_t * uc = context;

  gum_qnx_unparse_ucontext (ctx, uc);
}

#endif

static GumMemoryOperation
gum_infer_memory_operation (gconstpointer address,
                            GumCpuContext * context)
{
  GumMemoryOperation op;
  cs_insn * insn;

  insn = gum_disassemble_instruction_at (address, context);
  if (insn == NULL)
    return GUM_MEMOP_READ;

#if defined (HAVE_I386)
  op = gum_infer_x86_memory_operation (insn);
#elif defined (HAVE_ARM)
  op = gum_infer_arm_memory_operation (insn);
#elif defined (HAVE_ARM64)
  op = gum_infer_arm64_memory_operation (insn);
#else
  op = GUM_MEMOP_READ;
#endif

  cs_free (insn, 1);

  return op;
}

static cs_insn *
gum_disassemble_instruction_at (gconstpointer address,
                                GumCpuContext * context)
{
  cs_insn * insn = NULL;
  csh capstone;
  cs_err err;

  gum_cs_arch_register_native ();
#if defined (HAVE_I386)
  err = cs_open (CS_ARCH_X86, GUM_CPU_MODE, &capstone);
#elif defined (HAVE_ARM)
  err = cs_open (CS_ARCH_ARM,
      (((context->cpsr & GUM_PSR_T_BIT) != 0) ? CS_MODE_THUMB : CS_MODE_ARM) |
      CS_MODE_V8 | GUM_DEFAULT_CS_ENDIAN, &capstone);
#elif defined (HAVE_ARM64)
  err = cs_open (CS_ARCH_ARM64, GUM_DEFAULT_CS_ENDIAN, &capstone);
#else
  return NULL;
#endif

  if (err != CS_ERR_OK)
    return NULL;

  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);
  cs_disasm (capstone, address, 16, GPOINTER_TO_SIZE (address), 1, &insn);
  cs_close (&capstone);

  return insn;
}

#if defined (HAVE_I386)

static GumMemoryOperation
gum_infer_x86_memory_operation (cs_insn * insn)
{
  switch (insn->id)
  {
    case X86_INS_CLI:
    case X86_INS_STI:
    case X86_INS_CLC:
    case X86_INS_STC:
    case X86_INS_CLAC:
    case X86_INS_CLGI:
    case X86_INS_CLTS:
    case X86_INS_CLWB:
    case X86_INS_STAC:
    case X86_INS_STGI:
    case X86_INS_CPUID:
    case X86_INS_MOVNTQ:
    case X86_INS_MOVNTDQA:
    case X86_INS_MOVNTDQ:
    case X86_INS_MOVNTI:
    case X86_INS_MOVNTPD:
    case X86_INS_MOVNTPS:
    case X86_INS_MOVNTSD:
    case X86_INS_MOVNTSS:
    case X86_INS_VMOVNTDQA:
    case X86_INS_VMOVNTDQ:
    case X86_INS_VMOVNTPD:
    case X86_INS_VMOVNTPS:
    case X86_INS_MOVSS:
    case X86_INS_MOV:
    case X86_INS_MOVAPS:
    case X86_INS_MOVAPD:
    case X86_INS_MOVZX:
    case X86_INS_MOVUPS:
    case X86_INS_MOVABS:
    case X86_INS_MOVHPD:
    case X86_INS_MOVHPS:
    case X86_INS_MOVLPD:
    case X86_INS_MOVLPS:
    case X86_INS_MOVBE:
    case X86_INS_MOVSB:
    case X86_INS_MOVSD:
    case X86_INS_MOVSQ:
    case X86_INS_MOVSX:
    case X86_INS_MOVSXD:
    case X86_INS_MOVSW:
    case X86_INS_MOVD:
    case X86_INS_MOVQ:
    case X86_INS_MOVDQ2Q:
    case X86_INS_RDRAND:
    case X86_INS_RDSEED:
    case X86_INS_RDMSR:
    case X86_INS_RDPMC:
    case X86_INS_RDTSC:
    case X86_INS_RDTSCP:
    case X86_INS_CRC32:
    case X86_INS_SHA1MSG1:
    case X86_INS_SHA1MSG2:
    case X86_INS_SHA1NEXTE:
    case X86_INS_SHA1RNDS4:
    case X86_INS_SHA256MSG1:
    case X86_INS_SHA256MSG2:
    case X86_INS_SHA256RNDS2:
    case X86_INS_AESDECLAST:
    case X86_INS_AESDEC:
    case X86_INS_AESENCLAST:
    case X86_INS_AESENC:
    case X86_INS_AESIMC:
    case X86_INS_AESKEYGENASSIST:
    case X86_INS_PACKSSDW:
    case X86_INS_PACKSSWB:
    case X86_INS_PACKUSWB:
    case X86_INS_XCHG:
    case X86_INS_CLD:
    case X86_INS_STD:
      switch (insn->detail->x86.operands[0].type)
      {
        case X86_OP_MEM:
          return GUM_MEMOP_WRITE;
        case X86_OP_REG:
          if (insn->detail->x86.operands[1].type == X86_OP_MEM)
            return GUM_MEMOP_READ;
        default:
          return GUM_MEMOP_READ;
      }
    default:
      return GUM_MEMOP_READ;
  }
}

#elif defined (HAVE_ARM)

static GumMemoryOperation
gum_infer_arm_memory_operation (cs_insn * insn)
{
  switch (insn->id)
  {
    case ARM_INS_STREX:
    case ARM_INS_STREXB:
    case ARM_INS_STREXD:
    case ARM_INS_STREXH:
    case ARM_INS_STR:
    case ARM_INS_STRB:
    case ARM_INS_STRD:
    case ARM_INS_STRBT:
    case ARM_INS_STRH:
    case ARM_INS_STRHT:
    case ARM_INS_STRT:
      return GUM_MEMOP_WRITE;
    default:
      return GUM_MEMOP_READ;
  }
}

#elif defined (HAVE_ARM64)

static GumMemoryOperation
gum_infer_arm64_memory_operation (cs_insn * insn)
{
  switch (insn->id)
  {
    case ARM64_INS_STRB:
    case ARM64_INS_STURB:
    case ARM64_INS_STUR:
    case ARM64_INS_STR:
    case ARM64_INS_STP:
    case ARM64_INS_STNP:
    case ARM64_INS_STXR:
    case ARM64_INS_STXRH:
    case ARM64_INS_STLXRH:
    case ARM64_INS_STXRB:
      return GUM_MEMOP_WRITE;
    default:
      return GUM_MEMOP_READ;
  }
}

#endif

#endif
```