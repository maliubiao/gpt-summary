Response:
Let's break down the thought process for analyzing this C code and generating the explanation.

**1. Understanding the Goal:**

The request asks for a detailed breakdown of `gumdbghelpbacktracer.c`, focusing on its functionality, relationship to reverse engineering, low-level details, logical reasoning, potential errors, and usage context. Essentially, it wants a comprehensive analysis of this specific backtracer implementation within the Frida ecosystem.

**2. Initial Code Scan and Keyword Identification:**

First, I'd scan the code for key terms and structures. This helps to quickly grasp the high-level purpose:

* **`GumDbghelpBacktracer`:** This is the central structure, suggesting it's responsible for backtracing using the `dbghelp` library.
* **`GumBacktracer` interface:**  The code implements this interface, indicating it's part of a broader backtracing mechanism within Frida.
* **`dbghelp`:**  This strongly points to the Windows Debug Help Library.
* **`StackWalk64`:** This is a crucial function in `dbghelp` for retrieving stack frames.
* **`CONTEXT` and `STACKFRAME64`:**  These are standard Windows structures used in debugging and stack walking.
* **`GumCpuContext`:** This likely represents a cross-platform CPU context abstraction in Frida.
* **`GumReturnAddressArray`:**  This clearly stores the result of the backtrace.
* **Platform-specific `#ifdef` directives (`HAVE_ARM64`, `GLIB_SIZEOF_VOID_P`, `_MSC_VER`, `HAVE_I386`):**  Indicates platform-dependent logic.
* **`gum_interceptor_get_current_stack()`:**  This suggests interaction with Frida's interception mechanism.
* **`gum_windows_unparse_context()`:** Implies a translation between Frida's abstract CPU context and the Windows-specific `CONTEXT`.
* **`gum_invocation_stack_translate()`:** Hints at address translation or manipulation within Frida's interception context.

**3. Deciphering the Core Functionality (`gum_dbghelp_backtracer_generate`):**

This function is the heart of the backtracer. I'd analyze its steps:

* **Initialization:** Getting the `GumDbghelpImpl` and current invocation stack.
* **Capturing Initial Context:** Using `RtlCaptureContext` to get the current CPU state.
* **Handling `cpu_context` (Hook Context):**  If a `cpu_context` is provided (meaning we're in a hooked function):
    * Translate the Frida `GumCpuContext` to a Windows `CONTEXT`.
    * Populate the `STACKFRAME64` structure with initial information from the `cpu_context`.
    * Handle potential FFI (Foreign Function Interface) frames and adjust skipping logic.
* **Handling No `cpu_context` (Native Context):** If no `cpu_context` is given (native execution):
    * Populate the `STACKFRAME64` directly from the captured `CONTEXT`.
    * Set default skipping logic.
* **Stack Walking Loop:**  The core loop using `dbghelp->StackWalk64`:
    * Iterates up to the `limit`.
    * Calls `StackWalk64` to get the next stack frame.
    * Checks for invalid frames (PC == Return Address, PC == 0).
    * Translates the program counter (`pc`) using `gum_invocation_stack_translate`.
    * Stores the translated PC in the `return_addresses` array.
    * Potentially updates the `CONTEXT` and `frame` with the translated PC.
    * Handles skipping frames based on the initial analysis.
* **Finalization:** Sets the `len` of the `return_addresses` and unlocks the `dbghelp` mutex.

**4. Connecting to Reverse Engineering:**

Based on the functionality, I'd identify the clear connection to reverse engineering:

* **Stack Trace Acquisition:**  This is a fundamental technique in debugging and reverse engineering to understand the program's execution flow.
* **Hooking and Context Switching:** The handling of `cpu_context` directly relates to dynamic instrumentation, a key reverse engineering technique. Frida injects code and intercepts function calls.
* **Address Translation:** The `gum_invocation_stack_translate` function is vital for mapping addresses within Frida's injected environment to the original process's memory space.

**5. Identifying Low-Level Details:**

* **Platform-Specific Code:** The `#ifdef` blocks highlight the need to handle different architectures (ARM64, x86/x64) and operating systems (Windows via `dbghelp`).
* **Windows API Usage:** Direct use of `RtlCaptureContext`, `StackWalk64`, `CONTEXT`, `STACKFRAME64`, `GetCurrentProcess`, `GetCurrentThread`.
* **Memory Alignment:** The `GUM_ALIGNED(64)` macro is important for data structure alignment, especially when interacting with low-level APIs.

**6. Inferring Logical Reasoning:**

* **Conditional Skipping of Frames:** The logic for `n_skip` is based on whether the backtrace originates from a hooked function or native code. This is to remove Frida's internal call frames from the backtrace for clarity.
* **FFI Handling:** The special handling for FFI frames suggests that Frida needs to account for transitions between managed (e.g., JavaScript) and native code.

**7. Considering User Errors:**

* **Incorrect `limit`:** Providing a very large `limit` could lead to unnecessary processing.
* **Frida Not Attached:** The code relies on Frida's interception mechanisms. If Frida isn't properly attached to the target process, the backtrace might be incomplete or incorrect.

**8. Tracing User Operations (Debugging Clue):**

I'd consider the typical Frida workflow:

1. **User writes a Frida script.**
2. **Script uses `Interceptor.attach` to hook a function.**
3. **The hooked function is called.**
4. **Inside the hook handler, the user calls a Frida API to get a stack trace (e.g., `Thread.backtrace()`).**
5. **Frida's internal mechanisms trigger the `gum_dbghelp_backtracer_generate` function to generate the backtrace for the current thread's context or a captured context from the hook.**

**9. Structuring the Explanation:**

Finally, I'd organize the information into logical sections as requested in the prompt: functionality, reverse engineering relevance, low-level details, logical reasoning, potential errors, and usage context. Using clear headings and examples helps in presenting the information effectively.

This structured approach, combining code analysis with understanding of the broader Frida context and reverse engineering concepts, allows for a comprehensive and accurate explanation of the `gumdbghelpbacktracer.c` file.
好的，让我们详细分析一下 `gumdbghelpbacktracer.c` 文件的功能和它在 Frida 动态Instrumentation 工具中的作用。

**功能概览:**

`gumdbghelpbacktracer.c` 文件的核心功能是**生成调用堆栈回溯 (Call Stack Backtrace)**。它利用 Windows 平台的 `dbghelp.dll` 库来实现这个目标。 具体来说，当 Frida 需要获取当前或指定线程的调用堆栈时，这个文件中的代码会被执行，它会：

1. **获取 CPU 上下文 (CPU Context):**  它可以从当前线程获取 CPU 上下文，也可以接收一个由 Frida 提供的、在拦截 (interception) 发生时的 CPU 上下文。这个上下文包含了程序执行的关键寄存器状态，例如指令指针 (PC/IP)、栈指针 (SP)、帧指针 (FP) 等。

2. **配置 `STACKFRAME64` 结构:**  这是一个 `dbghelp.dll` 中定义的结构体，用于描述一个栈帧。代码会根据获取到的 CPU 上下文信息，填充这个结构体的各个字段，例如程序计数器地址、栈地址、帧地址等。

3. **调用 `dbghelp.dll` 的 `StackWalk64` 函数:**  这是执行栈回溯的核心函数。它根据提供的 CPU 上下文和栈帧信息，向上遍历调用栈，找到前一个调用者的栈帧。

4. **翻译地址 (Address Translation):** Frida 在进行动态 Instrumentation 时，会在目标进程中注入代码。因此，获取到的原始地址可能指向 Frida 注入的代码区域。`gum_invocation_stack_translate` 函数的作用是将这些地址翻译回目标进程原始的代码地址。

5. **存储返回地址:**  遍历调用栈的过程中，每个栈帧的返回地址会被提取出来，并存储到 `GumReturnAddressArray` 结构中。

**与逆向方法的关联及举例说明:**

这个文件与逆向方法紧密相关，因为它提供的**调用堆栈回溯**是逆向工程中非常重要的技术。

**举例说明:**

假设你想逆向一个 Windows 应用程序，并想了解当程序调用某个特定函数 `target_function` 时，是哪些函数调用了它。你可以使用 Frida 脚本进行 hook：

```javascript
Interceptor.attach(Module.findExportByName(null, "target_function"), {
  onEnter: function (args) {
    console.log("进入 target_function，调用栈：");
    console.log(Thread.backtrace().map(DebugSymbol.fromAddress).join("\\n"));
  }
});
```

当 `target_function` 被调用时，`onEnter` 函数会被执行。`Thread.backtrace()` 会触发 `gumdbghelpbacktracer.c` 中的代码来生成调用堆栈。输出结果可能如下：

```
进入 target_function，调用栈：
0x00007ff7a0001000  ; module1.dll!target_function
0x00007ff7a0001234  ; module1.dll!caller_function_a + 0x24
0x00007ff79ff05678  ; module2.dll!caller_function_b + 0x118
0x00007ff79fe09abc  ; module3.dll!main_loop + 0x5bc
...
```

这个调用栈清楚地展示了 `target_function` 是被 `caller_function_a` 调用的，而 `caller_function_a` 又被 `caller_function_b` 调用，以此类推。这对于理解程序的执行流程和函数调用关系至关重要。

**涉及二进制底层、Linux/Android 内核及框架的知识 (Windows 特有):**

虽然这个文件专门针对 Windows 平台，使用了 `dbghelp.dll`，但其背后的原理与在 Linux/Android 上进行堆栈回溯是类似的。

**二进制底层:**

* **CPU 上下文 (CPU Context):** 代码需要理解不同架构 (x86, x64, ARM64) 的 CPU 寄存器结构，例如指令指针 (EIP/RIP/PC)、栈指针 (ESP/RSP/SP)、帧指针 (EBP/RBP/FP) 等。这些寄存器是程序执行状态的直接体现。
* **栈帧 (Stack Frame):**  理解函数调用时栈帧的布局至关重要，包括返回地址、局部变量、函数参数等在栈上的存储方式。`StackWalk64` 的工作原理就是基于对栈帧结构的理解。

**Windows 平台相关:**

* **`dbghelp.dll` 库:**  这个库是 Windows 提供的用于调试和符号处理的库。`StackWalk64`、`SymFunctionTableAccess64`、`SymGetModuleBase64` 等函数都是该库提供的。
* **`CONTEXT` 和 `STACKFRAME64` 结构:**  这些是 Windows 定义的特定数据结构，用于表示 CPU 上下文和栈帧信息。
* **线程句柄 (HANDLE):**  代码使用 `GetCurrentProcess()` 和 `GetCurrentThread()` 获取当前进程和线程的句柄，以便 `StackWalk64` 函数可以操作正确的上下文。

**Android/Linux 内核及框架的类比:**

在 Android 或 Linux 上，实现堆栈回溯通常依赖于：

* **`libunwind` 库 (Android):**  类似于 `dbghelp.dll`，用于在运行时展开堆栈。
* **`backtrace` 函数 (glibc):**  一个更简单的堆栈回溯函数。
* **帧指针 (Frame Pointer) 的使用:**  一些架构和编译选项会使用帧指针来辅助堆栈展开。
* **DWARF 调试信息:**  在没有帧指针的情况下，堆栈展开可能依赖于 DWARF 调试信息来确定函数的栈帧布局。
* **内核符号表:**  对于内核态的堆栈回溯，需要访问内核的符号表。

**逻辑推理、假设输入与输出:**

**假设输入:**

* `backtracer`: 一个 `GumDbghelpBacktracer` 实例。
* `cpu_context`:  一个指向 `GumCpuContext` 结构的指针。假设这个上下文代表着程序执行到一个函数 `example_function` 中间的状态，指令指针指向 `example_function` 的某条指令。
* `return_addresses`: 一个预先分配的 `GumReturnAddressArray` 结构。
* `limit`:  回溯的最大深度，例如设置为 10。

**逻辑推理过程:**

1. `gum_dbghelp_backtracer_generate` 函数被调用。
2. 如果 `cpu_context` 不为空 (意味着是从一个 hook 点触发的)，代码会使用 `gum_windows_unparse_context` 将 `GumCpuContext` 转换为 Windows 的 `CONTEXT` 结构。
3. 初始化 `STACKFRAME64` 结构，例如将 `AddrPC.Offset` 设置为 `cpu_context` 中的指令指针。
4. 进入循环，调用 `dbghelp->StackWalk64`。`StackWalk64` 会根据当前的栈帧信息，查找调用者的栈帧。
5. 每次 `StackWalk64` 成功返回，就提取当前栈帧的返回地址 (`frame.AddrReturn.Offset`)，并使用 `gum_invocation_stack_translate` 进行翻译。
6. 将翻译后的返回地址存储到 `return_addresses->items` 数组中。
7. 循环继续，直到达到 `limit` 或者 `StackWalk64` 失败。

**假设输出:**

`return_addresses` 结构的内容可能如下（地址为示例）：

```
return_addresses->len = 3;
return_addresses->items[0] = 0x00007ff7a0011234; // 调用 example_function 的函数的返回地址
return_addresses->items[1] = 0x00007ff79ff22345; // 调用上一个函数的函数的返回地址
return_addresses->items[2] = 0x00007ff79fe33456; // 调用上上个函数的函数的返回地址
```

**涉及用户或编程常见的使用错误及举例说明:**

1. **`dbghelp.dll` 加载失败或版本不兼容:** 如果系统缺少 `dbghelp.dll` 或者版本不兼容，`GumDbghelpImpl` 的初始化可能会失败，导致堆栈回溯功能无法正常工作。
   * **错误场景:** 用户在精简版的 Windows 系统上运行 Frida，该系统可能没有包含完整的调试支持库。

2. **目标进程没有符号信息:**  `StackWalk64` 函数在没有符号信息的情况下仍然可以工作，但只能获取到裸地址，无法解析出函数名和代码行号。这会降低回溯结果的可读性。
   * **错误场景:** 用户尝试回溯一个没有发布调试符号的 Release 版本程序。

3. **`limit` 设置过大:**  虽然不会导致错误，但设置过大的 `limit` 可能会导致不必要的性能开销，尤其是在深层调用栈的情况下。

4. **在不适当的时机调用堆栈回溯:**  在某些非常底层的或异常处理的代码中调用堆栈回溯可能导致程序崩溃或产生不准确的结果。
   * **错误场景:**  在中断处理程序或非常早期的初始化代码中尝试获取堆栈回溯。

**说明用户操作是如何一步步到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:**  用户编写 JavaScript 或 Python 代码，使用 Frida 的 API 来 hook 目标进程的函数。例如：

   ```javascript
   Interceptor.attach(Module.findExportByName(null, "some_function"), {
     onEnter: function (args) {
       console.log(Thread.backtrace().map(DebugSymbol.fromAddress).join("\\n"));
     }
   });
   ```

2. **Frida 注入代码并进行拦截:**  当目标进程执行到 `some_function` 时，Frida 注入的代码会捕获这次调用，并执行用户定义的 `onEnter` 函数。

3. **调用 `Thread.backtrace()`:**  在 `onEnter` 函数中，用户调用了 `Thread.backtrace()` 来获取当前的调用堆栈。

4. **Frida 内部处理 `Thread.backtrace()`:**  Frida 的 JavaScript 绑定会将 `Thread.backtrace()` 的调用转换为 Native 代码的请求。

5. **调用 `gum_backtracer_generate`:**  Frida 的内部机制会根据当前平台的 Backtracer 实现 (在 Windows 上就是 `GumDbghelpBacktracer`)，调用其 `generate` 方法，即 `gum_dbghelp_backtracer_generate` 函数。

6. **`gum_dbghelp_backtracer_generate` 执行:**  该函数会获取 CPU 上下文，调用 `dbghelp.dll` 的函数进行堆栈回溯，并将结果返回给 Frida。

**作为调试线索:**

当用户在使用 Frida 时遇到堆栈回溯相关的问题（例如，回溯不完整、地址不正确、程序崩溃），可以按照以下思路进行调试：

* **检查 `dbghelp.dll` 是否存在且版本正确。**
* **确认目标进程是否加载了符号信息。**
* **查看 Frida 的日志输出，是否有关于 `dbghelp` 初始化的错误信息。**
* **尝试在不同的代码位置或时机调用 `Thread.backtrace()`，排除特定上下文导致的问题。**
* **对比不同 Frida 版本的行为，排查 Frida 本身引入的 bug。**

总而言之，`gumdbghelpbacktracer.c` 是 Frida 在 Windows 平台上实现调用堆栈回溯的关键组件，它利用了 Windows 提供的调试支持库，为逆向工程师提供了强大的运行时代码执行流程分析能力。理解其工作原理有助于更好地使用 Frida 并解决相关问题。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-dbghelp/gumdbghelpbacktracer.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2008-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gum/gumdbghelpbacktracer.h"

#include "guminterceptor.h"

#if defined (HAVE_ARM64)
# define GUM_BACKTRACER_MACHINE_TYPE IMAGE_FILE_MACHINE_ARM64
#elif GLIB_SIZEOF_VOID_P == 8
# define GUM_BACKTRACER_MACHINE_TYPE IMAGE_FILE_MACHINE_AMD64
#else
# define GUM_BACKTRACER_MACHINE_TYPE IMAGE_FILE_MACHINE_I386
# define GUM_FFI_STACK_SKIP 44
#endif

#ifdef _MSC_VER
# define GUM_ALIGNED(n) __declspec (align (n))
#else
# define GUM_ALIGNED(n) __attribute__ ((aligned (n)))
#endif

struct _GumDbghelpBacktracer
{
  GObject parent;

  GumDbghelpImpl * dbghelp;
};

static void gum_dbghelp_backtracer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_dbghelp_backtracer_generate (GumBacktracer * backtracer,
    const GumCpuContext * cpu_context, GumReturnAddressArray * return_addresses,
    guint limit);

G_DEFINE_TYPE_EXTENDED (GumDbghelpBacktracer,
                        gum_dbghelp_backtracer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_BACKTRACER,
                            gum_dbghelp_backtracer_iface_init))

static void
gum_dbghelp_backtracer_class_init (GumDbghelpBacktracerClass * klass)
{
}

static void
gum_dbghelp_backtracer_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumBacktracerInterface * iface = g_iface;

  iface->generate = gum_dbghelp_backtracer_generate;
}

static void
gum_dbghelp_backtracer_init (GumDbghelpBacktracer * self)
{
}

GumBacktracer *
gum_dbghelp_backtracer_new (GumDbghelpImpl * dbghelp)
{
  GumDbghelpBacktracer * backtracer;

  g_assert (dbghelp != NULL);

  backtracer = g_object_new (GUM_TYPE_DBGHELP_BACKTRACER, NULL);
  backtracer->dbghelp = dbghelp;

  return GUM_BACKTRACER (backtracer);
}

static void
gum_dbghelp_backtracer_generate (GumBacktracer * backtracer,
                                 const GumCpuContext * cpu_context,
                                 GumReturnAddressArray * return_addresses,
                                 guint limit)
{
  GumDbghelpBacktracer * self;
  GumDbghelpImpl * dbghelp;
  GumInvocationStack * invocation_stack;
  GUM_ALIGNED (64) CONTEXT context = { 0, };
#if GLIB_SIZEOF_VOID_P == 4
  GUM_ALIGNED (64) CONTEXT context_next = { 0, };
#endif
  STACKFRAME64 frame = { 0, };
  gboolean has_ffi_frames;
  gint start_index, n_skip, depth, i;
  HANDLE current_process, current_thread;

  self = GUM_DBGHELP_BACKTRACER (backtracer);
  dbghelp = self->dbghelp;
  invocation_stack = gum_interceptor_get_current_stack ();

  /* Get the raw addresses */
  RtlCaptureContext (&context);

  frame.AddrPC.Mode = AddrModeFlat;
  frame.AddrFrame.Mode = AddrModeFlat;
  frame.AddrStack.Mode = AddrModeFlat;

  if (cpu_context != NULL)
  {
    gum_windows_unparse_context (cpu_context, &context);

#ifdef HAVE_I386
# if GLIB_SIZEOF_VOID_P == 4
    if (context.Eip == 0)
      context.Eip = *((gsize *) GSIZE_TO_POINTER (cpu_context->esp));

    frame.AddrPC.Offset = context.Eip;
    frame.AddrFrame.Offset = cpu_context->ebp;
    frame.AddrStack.Offset = cpu_context->esp;
# else
    if (context.Rip == 0)
      context.Rip = *((gsize *) GSIZE_TO_POINTER (cpu_context->rsp));

    frame.AddrPC.Offset = context.Rip;
    frame.AddrFrame.Offset = cpu_context->rsp;
    frame.AddrStack.Offset = cpu_context->rsp;
# endif

    has_ffi_frames = GUM_CPU_CONTEXT_XIP (cpu_context) == 0;
#else
    if (context.Pc == 0)
      context.Pc = cpu_context->lr;

    frame.AddrPC.Offset = context.Pc;
    frame.AddrFrame.Offset = cpu_context->fp;
    frame.AddrStack.Offset = cpu_context->sp;

    has_ffi_frames = cpu_context->pc == 0;
#endif

    if (has_ffi_frames)
    {
      start_index = 0;
      n_skip = 2;
    }
    else
    {
#if GLIB_SIZEOF_VOID_P == 4
      return_addresses->items[0] = gum_invocation_stack_translate (
          invocation_stack, *((GumReturnAddress *) GSIZE_TO_POINTER (
              GUM_CPU_CONTEXT_XSP (cpu_context))));
      start_index = 1;
      n_skip = 0;
#else
      start_index = 0;
      n_skip = 1;
#endif
    }
  }
  else
  {
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
    frame.AddrPC.Offset = context.Eip;
    frame.AddrFrame.Offset = context.Ebp;
    frame.AddrStack.Offset = context.Esp;
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
    frame.AddrPC.Offset = context.Rip;
    frame.AddrFrame.Offset = context.Rsp;
    frame.AddrStack.Offset = context.Rsp;
#else
    frame.AddrPC.Offset = context.Pc;
    frame.AddrFrame.Offset = context.Fp;
    frame.AddrStack.Offset = context.Sp;
#endif

    start_index = 0;
    n_skip = 1; /* Leave out this function. */
#ifdef HAVE_ARM64
    n_skip++;
#endif
    has_ffi_frames = FALSE;
  }

  current_process = GetCurrentProcess ();
  current_thread = GetCurrentThread ();

  depth = MIN (limit, G_N_ELEMENTS (return_addresses->items));

  dbghelp->Lock ();

  for (i = start_index; i < depth; i++)
  {
    BOOL success;
    gpointer pc, translated_pc;

#if GLIB_SIZEOF_VOID_P == 4
    if (has_ffi_frames && n_skip == 0)
    {
      if (i == 0)
      {
        context_next = context;
        context.Ebp = context.Esp + GUM_FFI_STACK_SKIP - 4;
      }
      else if (i == 1)
      {
        context = context_next;
      }
    }
#endif

    success = dbghelp->StackWalk64 (GUM_BACKTRACER_MACHINE_TYPE,
        current_process, current_thread, &frame, &context, NULL,
        dbghelp->SymFunctionTableAccess64, dbghelp->SymGetModuleBase64, NULL);
    if (!success)
      break;
    if (frame.AddrPC.Offset == frame.AddrReturn.Offset)
      continue;
    if (frame.AddrPC.Offset == 0)
      continue;

    pc = GSIZE_TO_POINTER (frame.AddrPC.Offset);
    translated_pc = gum_invocation_stack_translate (invocation_stack, pc);

    return_addresses->items[i] = translated_pc;

    if (translated_pc != pc)
    {
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
      context.Eip = GPOINTER_TO_SIZE (translated_pc);
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
      context.Rip = GPOINTER_TO_SIZE (translated_pc);
#else
      context.Pc = GPOINTER_TO_SIZE (translated_pc);
#endif
      frame.AddrPC.Offset = GPOINTER_TO_SIZE (translated_pc);
    }

    if (n_skip > 0)
    {
      n_skip--;
      i--;
    }
  }
  return_addresses->len = i;

  dbghelp->Unlock ();
}

#endif
```