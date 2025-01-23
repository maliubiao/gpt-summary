Response:
Let's break down the thought process for analyzing this C code. The request asks for a comprehensive analysis, covering functionality, relationship to reverse engineering, low-level details, logic, user errors, and debugging context.

**1. Initial Understanding - Purpose of the File:**

The first step is to read the header comments and includes. It clearly states "fridaDynamic instrumentation tool" and the path `frida/subprojects/frida-gum/gum/backend-x86/guminterceptor-x86.c`. This immediately tells us:

* **Domain:** Dynamic instrumentation.
* **Tool:** Part of Frida.
* **Specifics:**  Handles interception on x86 architectures.

The `#include` statements confirm this, showing dependencies on other Frida-Gum modules like `gumlibc`, `gummemory`, `gumsysinternals`, `gumx86reader`, and `gumx86relocator`. These hints point to core functionalities like memory manipulation, system interaction, and x86-specific instruction handling.

**2. Core Data Structures - The "Nerves" of the Code:**

Next, I scanned for the main data structures (`struct`). These are crucial for understanding how the code organizes information:

* `GumInterceptorBackend`: This seems to be the central structure managing the interception process. It contains an allocator, x86 writer and relocator, and pre-generated thunks.
* `GumX86FunctionContextData`: This structure holds x86-specific data for a function being intercepted, particularly the `redirect_code_size` and a pointer related to shadow stacks (`push_to_shadow_stack`).

**3. Key Functions - The "Actions" of the Code:**

I then looked for key function names, paying attention to prefixes and suffixes:

* `_gum_interceptor_backend_create/destroy`:  Lifecycle management for the `GumInterceptorBackend`.
* `_gum_interceptor_backend_claim_grafted_trampoline`:  Appears to be related to reusing existing trampolines.
* `_gum_interceptor_backend_prepare_trampoline/create_trampoline/destroy_trampoline/activate_trampoline/deactivate_trampoline`: These strongly suggest the core interception mechanism – creating and managing temporary code snippets (trampolines) to redirect execution.
* `_gum_interceptor_backend_get_function_address/resolve_redirect`:  Functions for retrieving the target function's address and resolving jumps.
* `gum_interceptor_backend_create_thunks/destroy_thunks`:  Manage the pre-generated "thunks" used for entering and leaving intercepted functions.
* `gum_emit_enter_thunk/gum_emit_leave_thunk`: Generate the code for the enter and leave thunks.
* `gum_emit_prolog/gum_emit_epilog`: Generate standard function prologue and epilogue code, crucial for stack management and saving/restoring registers.

**4. Analyzing Functionality and Connecting to Concepts:**

With the key structures and functions identified, I started connecting them to the request's points:

* **Functionality:**  I described the purpose of each key function based on its name and the operations within it. For example, `_gum_interceptor_backend_create_trampoline` clearly involves allocating memory, writing code to it, and setting up redirects.

* **Reverse Engineering:** The code heavily uses concepts central to reverse engineering:
    * **Code Injection:**  Frida injects code to intercept function calls.
    * **Trampolines:**  The core mechanism for redirecting execution. I explained how they work.
    * **Prologue/Epilogue Manipulation:** The code explicitly deals with the function's setup and teardown.
    * **Instruction Relocation:**  `GumX86Relocator` is crucial for copying and adjusting instructions.
    * **Instruction Decoding:**  `GumX86Reader` is used to analyze instructions.

* **Binary/Low-Level/Kernel/Framework:**
    * **x86 Assembly:** The code directly manipulates x86 instructions (e.g., `jmp`, `push`, `mov`, `call`).
    * **Memory Management:**  `GumCodeAllocator` deals with allocating executable memory.
    * **Stack Manipulation:**  The prologue and epilogue code directly manipulates the stack pointer (`rsp/esp`) and frame pointer (`rbp/ebp`).
    * **CPU Flags:** The code saves and restores CPU flags.
    * **Shadow Stack (CET):**  The code includes specific handling for Intel's Control-flow Enforcement Technology (CET), involving a shadow stack.

* **Logic and Assumptions:**  I analyzed specific code blocks, particularly in `gum_interceptor_backend_create_trampoline`, to understand the logic behind:
    * **Near vs. Far Jumps:** The code tries to allocate the trampoline near the target for efficiency.
    * **Relocation:** The loop in `create_trampoline` ensures enough bytes are relocated to accommodate the jump.
    * **Padding:** NOP instructions are added to ensure the overwritten prologue is the correct size.

* **User Errors:**  I considered scenarios where users might make mistakes, such as:
    * Intercepting very short functions.
    * Incorrectly handling function arguments within their interceptor.
    * Memory corruption issues if the interceptor code is buggy.

* **Debugging:** I explained how the code serves as a debugging aid by allowing users to:
    * Inspect function arguments and return values.
    * Modify function behavior.
    * Trace execution flow.

**5. Iterative Refinement and Structuring:**

Throughout this process, I mentally structured the information according to the request's categories. I also revisited sections to ensure clarity and accuracy. For example, when describing trampolines, I made sure to explain the "on_enter" and "on_leave" concepts. The use of bullet points and clear headings helps organize the detailed information.

**Self-Correction/Refinement Example:**

Initially, I might have just stated that the code deals with function interception. However, upon closer inspection of `create_trampoline` and the handling of `redirect_code_size`, I realized the importance of explaining the near vs. far jump optimization. This added a more nuanced understanding of the code's behavior and efficiency considerations. Similarly, noticing the `#if GLIB_SIZEOF_VOID_P == 4` block highlighted the differences between 32-bit and 64-bit architectures. Seeing the `GUM_CPU_CET_SS` checks made me research and explain the shadow stack functionality.

By following these steps – understanding the purpose, analyzing structures and functions, connecting to relevant concepts, considering edge cases, and iteratively refining the analysis – I could generate a comprehensive response addressing all aspects of the request.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/gum/backend-x86/guminterceptor-x86.c` 这个文件的功能。

**文件功能概述**

这个 C 文件是 Frida 动态插桩工具的核心组件之一，专门负责在 x86 架构上实现函数拦截（interception）的功能。它的主要目标是在目标进程的函数执行前后插入自定义的代码，从而实现诸如参数监控、返回值修改、代码替换等动态分析和修改行为。

**核心功能分解**

1. **Trampoline 创建和管理:**
   - **分配内存 (`gum_code_allocator_alloc_slice`, `gum_code_allocator_try_alloc_slice_near`):**  负责在目标进程中分配可执行内存，用于存放 trampoline 代码。Trampoline 是一小段代码，用于将程序执行流从原始函数重定向到 Frida 的处理逻辑。
   - **生成 Trampoline 代码 (`gum_x86_writer_*` 系列函数):** 使用 `GumX86Writer` 结构体及其相关函数，动态生成 x86 汇编指令，构建 trampoline 代码。这些代码通常包括保存寄存器状态、跳转到 Frida 的处理函数、以及恢复寄存器状态等操作。
   - **重定位原始指令 (`GumX86Relocator`):**  为了让原始函数在拦截后仍然可以被调用，需要将原始函数的一部分指令复制到 trampoline 中，并进行必要的重定位，以确保指令在新的内存位置仍然可以正确执行。
   - **激活和停用 Trampoline (`_gum_interceptor_backend_activate_trampoline`, `_gum_interceptor_backend_deactivate_trampoline`):**  通过修改目标函数的起始指令，将执行流重定向到 trampoline。停用时，则恢复原始函数的指令。

2. **Thunk 的创建和使用:**
   - **Enter Thunk (`gum_emit_enter_thunk`):**  在进入被拦截函数之前执行的代码。它负责保存 CPU 上下文（寄存器状态等）、调用 Frida 的回调函数（用户定义的 `onEnter` 函数）。
   - **Leave Thunk (`gum_emit_leave_thunk`):** 在离开被拦截函数之前执行的代码。它负责调用 Frida 的回调函数（用户定义的 `onLeave` 函数）。
   - **Thunk 的内存分配 (`gum_code_allocator_alloc_slice`):**  预先分配内存用于存放 enter 和 leave thunk 的代码。

3. **CPU 上下文管理:**
   - **保存和恢复 CPU 上下文 (`gum_emit_prolog`, `gum_emit_epilog`):**  在 enter thunk 中，需要保存当前函数的 CPU 上下文，以便在执行用户代码后能够恢复。leave thunk 中则负责恢复 CPU 上下文。
   - **`GumCpuContext` 结构体:**  用于存储 CPU 的各种寄存器状态和标志位。

4. **函数上下文管理 (`GumFunctionContext`):**
   -  存储与特定函数拦截相关的信息，例如原始函数地址、trampoline 地址、用户定义的回调函数等。
   -  `GumX86FunctionContextData` 结构体存储 x86 平台特有的拦截数据，例如重定向代码的大小。

5. **代码写入和重定位辅助:**
   - **`GumX86Writer`:**  提供了一系列函数，用于方便地生成 x86 汇编指令，例如 `gum_x86_writer_put_jmp_address` (写入跳转指令)、`gum_x86_writer_put_push_near_ptr` (写入 push 指令) 等。
   - **`GumX86Relocator`:**  负责将原始函数的指令复制到 trampoline 并进行地址重定位，以确保跳转目标等地址在新的内存位置仍然有效。

**与逆向方法的关系及举例说明**

这个文件是实现动态逆向的核心组件。通过函数拦截，逆向工程师可以：

* **监控函数调用:**  记录目标进程中特定函数的调用时机、参数值。例如，可以拦截 `open` 函数来查看程序打开了哪些文件，拦截 `connect` 函数来监控网络连接。
* **修改函数行为:**  在函数执行前后修改参数、返回值，或者完全替换函数的实现。例如，可以修改 `strcmp` 函数的返回值来绕过某些验证逻辑。
* **代码追踪:**  在函数入口和出口插入代码，用于记录执行路径、寄存器状态等信息。
* **Hook 特定 API:**  拦截操作系统或库的 API 调用，例如拦截 `malloc` 来分析内存分配情况，拦截 `LoadLibrary` 来监控动态链接库的加载。

**举例说明:**

假设我们要拦截 `malloc` 函数，监控其分配的内存大小：

1. **Frida 用户脚本会指定要拦截的函数和回调函数：**
   ```javascript
   Interceptor.attach(Module.findExportByName(null, 'malloc'), {
     onEnter: function (args) {
       var size = args[0].toInt();
       console.log('malloc called with size: ' + size);
     }
   });
   ```
2. **Frida 内部会将 `malloc` 函数的地址传递给 `guminterceptor-x86.c` 中的相关函数。**
3. **`guminterceptor-x86.c` 会执行以下操作：**
   - 分配一块可执行内存用于存放 trampoline 代码。
   - 使用 `GumX86Writer` 生成 trampoline 代码，该代码会：
     - 保存当前寄存器状态。
     - 将 `GumFunctionContext` 的指针压入栈。
     - 跳转到 `enter_thunk` 代码段。
   - 使用 `GumX86Relocator` 将 `malloc` 函数开头的几条指令复制到 trampoline 中。
   - 修改 `malloc` 函数的起始指令，将其跳转到刚刚创建的 trampoline。
4. **当目标进程调用 `malloc` 时，执行流会先跳转到 trampoline。**
5. **Trampoline 代码执行后，会跳转到 `enter_thunk`。**
6. **`enter_thunk` 代码会：**
   - 进一步保存 CPU 上下文。
   - 将参数（`malloc` 的 size）传递给 JavaScript 定义的 `onEnter` 函数。
7. **JavaScript 的 `onEnter` 函数执行，打印分配的内存大小。**
8. **`enter_thunk` 代码执行完毕后，会跳回到 trampoline 中被复制的原始 `malloc` 指令。**
9. **执行完原始 `malloc` 的指令后，会跳转到 `leave_thunk` (如果定义了 `onLeave`)，然后再返回到 `malloc` 函数的调用者。**

**涉及的二进制底层、Linux、Android 内核及框架知识**

* **x86 汇编指令:**  代码直接操作 x86 汇编指令，例如 `jmp` (跳转), `push` (压栈), `mov` (移动数据), `call` (调用函数) 等。需要理解这些指令的编码格式和执行方式。
* **内存管理:**  涉及到在进程内存空间中分配和管理可执行内存。需要了解操作系统的内存管理机制，例如虚拟地址空间、内存页等。
* **函数调用约定 (Calling Conventions):**  理解 x86 平台上的函数调用约定（例如 cdecl, stdcall），以便正确地保存和恢复寄存器，以及传递函数参数。
* **CPU 寄存器:**  需要了解 x86 CPU 的通用寄存器（EAX, EBX, ECX, EDX, ESI, EDI, EBP, ESP 等）和标志寄存器，以及它们在函数调用中的作用。
* **代码重定位:**  理解在代码被移动到新的内存地址后，如何修改指令中的地址引用，以确保代码仍然可以正确执行。
* **Linux/Android 进程模型:**  Frida 在 Linux 和 Android 等操作系统上运行，需要了解进程的内存布局、代码段、数据段等概念。
* **动态链接:**  当拦截动态链接库中的函数时，需要了解动态链接的过程和原理。
* **内核 API (间接涉及):**  虽然这个文件主要处理用户态的拦截，但其底层可能涉及到一些与内核交互的操作，例如修改内存保护属性以使分配的内存可执行。
* **Android 框架 (间接涉及):**  在 Android 上进行 hook 时，可能涉及到对 ART 虚拟机或 Native 代码的拦截，需要了解 Android 的应用框架和运行机制。
* **CET (Control-flow Enforcement Technology):** 代码中出现了 `GUM_CPU_CET_SS` 相关的判断，这涉及到 Intel 的 CET 技术，特别是 Shadow Stack，用于增强控制流完整性。

**逻辑推理、假设输入与输出**

**假设输入:**

* `function_address`:  要拦截的目标函数的起始地址。
* `replacement_function` (可选):  用户提供的替换函数地址（用于完全替换原始函数）。
* `on_enter_callback` (可选):  用户提供的在函数入口处执行的回调函数。
* `on_leave_callback` (可选):  用户提供的在函数出口处执行的回调函数。
* `interceptor_type`:  拦截类型，例如 `GUM_INTERCEPTOR_TYPE_DEFAULT` (标准拦截), `GUM_INTERCEPTOR_TYPE_FAST` (快速拦截)。

**逻辑推理 (部分):**

在 `gum_interceptor_backend_create_trampoline` 函数中，会根据拦截类型和目标函数地址尝试分配 trampoline 内存：

* **如果 `ctx->type == GUM_INTERCEPTOR_TYPE_DEFAULT`:**  尝试在目标函数附近分配内存 (`gum_code_allocator_try_alloc_slice_near`)，如果成功，可以使用较短的近跳转指令 (`GUM_INTERCEPTOR_NEAR_REDIRECT_SIZE`)，减少需要覆盖的原始指令长度。
* **如果分配失败，或者 `ctx->type == GUM_INTERCEPTOR_TYPE_FAST`:**  使用远跳转指令 (`GUM_INTERCEPTOR_FULL_REDIRECT_SIZE`)，需要在目标函数起始处覆盖更多的字节。

**假设输出:**

* **成功拦截:**  目标函数被调用时，会先执行用户定义的回调函数（如果存在），然后执行原始函数（或替换函数）。
* **`ctx->trampoline_slice->data`:**  指向新分配的 trampoline 代码的内存地址。
* **目标函数起始处的指令被修改为跳转到 trampoline 代码。**
* **`ctx->overwritten_prologue`:**  存储了被覆盖的原始函数的指令。

**用户或编程常见的使用错误及举例说明**

1. **拦截过短的函数:**  如果目标函数非常短，以至于其长度小于 trampoline 代码的大小，则无法完成拦截。Frida 可能会报错或者行为异常。
2. **在 `onEnter` 或 `onLeave` 回调函数中操作不当:**
   - **修改了不应该修改的寄存器:**  可能导致程序崩溃或行为异常。
   - **内存泄漏:**  如果在回调函数中分配了内存而没有释放。
   - **执行时间过长:**  会影响目标进程的性能。
3. **多线程环境下的同步问题:**  如果在多线程程序中进行 hook，需要注意线程安全问题，避免数据竞争。
4. **hook 位置错误:**  如果 hook 的位置不正确，可能无法达到预期的效果，或者导致程序崩溃。例如，尝试 hook 一个已经被内联的函数。
5. **内存分配失败:**  虽然 `gum_code_allocator` 负责内存分配，但如果系统内存不足，仍然可能导致分配失败，拦截也会失败。
6. **不正确的函数签名:**  当进行函数替换时，必须确保替换函数的签名与原始函数完全一致（参数类型、返回值类型、调用约定），否则可能导致栈不平衡等问题。

**用户操作是如何一步步到达这里，作为调试线索**

1. **用户编写 Frida 脚本:**  用户使用 JavaScript 或 Python 编写 Frida 脚本，指定要 hook 的函数、回调函数等信息。例如：
   ```javascript
   Interceptor.attach(Module.findExportByName(null, 'my_function'), {
     onEnter: function (args) {
       console.log('my_function called!');
     }
   });
   ```
2. **Frida Client 发送 hook 请求:**  Frida 的客户端（例如 Python 脚本）将用户的 hook 请求发送到目标进程中的 Frida Agent。
3. **Frida Agent 接收请求并解析:**  Frida Agent 接收到 hook 请求，解析出要 hook 的函数地址、回调函数等信息。
4. **调用 Gum API:**  Frida Agent 内部会调用 Gum 库的 API，例如 `GumInterceptor` 提供的函数，来执行实际的 hook 操作。
5. **`_gum_interceptor_backend_create` 创建 backend:**  在创建拦截器时，会调用 `_gum_interceptor_backend_create` 函数，初始化 x86 相关的 backend。
6. **`_gum_interceptor_backend_create_trampoline` 创建 trampoline:**  接着会调用 `_gum_interceptor_backend_create_trampoline` 函数，负责分配内存、生成 trampoline 代码、重定位原始指令。在这个过程中，会使用 `GumX86Writer` 和 `GumX86Relocator`。
7. **`_gum_interceptor_backend_activate_trampoline` 激活 trampoline:**  最后，调用 `_gum_interceptor_backend_activate_trampoline` 函数，将目标函数的起始指令修改为跳转到 trampoline。

**作为调试线索:**

* **如果 hook 没有生效:**  可以检查 Frida 脚本中指定的函数名是否正确，目标进程是否加载了该模块。还可以检查 `gum_interceptor_backend_create_trampoline` 的返回值，看是否成功创建了 trampoline。
* **如果程序崩溃:**  可能是由于 trampoline 代码生成错误，或者回调函数中存在问题。可以使用 Frida 提供的调试功能（例如 `Process.getCurrentThread().context`）来查看崩溃时的寄存器状态。
* **如果性能受到影响:**  可以考虑使用更高效的 hook 方式，例如 `Interceptor.replace` 或优化回调函数的执行逻辑。
* **查看 Frida 日志:**  Frida 提供了详细的日志输出，可以帮助定位问题。可以通过设置环境变量或使用 Frida 命令行选项来启用更详细的日志。

总而言之，`guminterceptor-x86.c` 是 Frida 在 x86 平台上实现动态代码插桩的关键组成部分，它深入到二进制层面，通过精巧地修改目标代码，实现了在运行时动态地改变程序行为的能力，这对于软件逆向工程、安全分析和动态调试至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-x86/guminterceptor-x86.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 * Copyright (C) 2024 Yannis Juglaret <yjuglaret@mozilla.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gumlibc.h"
#include "gummemory.h"
#include "gumsysinternals.h"
#include "gumx86reader.h"
#include "gumx86relocator.h"

#include <string.h>

#define GUM_INTERCEPTOR_FULL_REDIRECT_SIZE  16
#define GUM_INTERCEPTOR_NEAR_REDIRECT_SIZE  5
#define GUM_X86_JMP_MAX_DISTANCE            (G_MAXINT32 - 16384)

#define GUM_FRAME_OFFSET_CPU_CONTEXT 0
#define GUM_FRAME_OFFSET_CPU_FLAGS \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + sizeof (GumCpuContext))
#define GUM_FRAME_OFFSET_NEXT_HOP \
    (GUM_FRAME_OFFSET_CPU_FLAGS + sizeof (gpointer))
#define GUM_FRAME_OFFSET_TOP \
    (GUM_FRAME_OFFSET_NEXT_HOP + sizeof (gpointer))

#define GUM_FCDATA(context) \
    ((GumX86FunctionContextData *) (context)->backend_data.storage)

typedef struct _GumX86FunctionContextData GumX86FunctionContextData;

struct _GumInterceptorBackend
{
  GumCodeAllocator * allocator;

  GumX86Writer writer;
  GumX86Relocator relocator;

  GumCodeSlice * enter_thunk;
  GumCodeSlice * leave_thunk;
};

struct _GumX86FunctionContextData
{
  guint redirect_code_size;
  gpointer push_to_shadow_stack;
};

G_STATIC_ASSERT (sizeof (GumX86FunctionContextData)
    <= sizeof (GumFunctionContextBackendData));

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static void gum_emit_enter_thunk (GumX86Writer * cw);
static void gum_emit_leave_thunk (GumX86Writer * cw);

static void gum_emit_prolog (GumX86Writer * cw,
    gssize stack_displacement);
static void gum_emit_epilog (GumX86Writer * cw, GumPointCut point_cut);

GumInterceptorBackend *
_gum_interceptor_backend_create (GRecMutex * mutex,
                                 GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new (GumInterceptorBackend);
  backend->allocator = allocator;

  gum_x86_writer_init (&backend->writer, NULL);
  gum_x86_relocator_init (&backend->relocator, NULL, &backend->writer);

  gum_interceptor_backend_create_thunks (backend);

  return backend;
}

void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  gum_interceptor_backend_destroy_thunks (backend);

  gum_x86_relocator_clear (&backend->relocator);
  gum_x86_writer_clear (&backend->writer);

  g_slice_free (GumInterceptorBackend, backend);
}

gboolean
_gum_interceptor_backend_claim_grafted_trampoline (GumInterceptorBackend * self,
                                                   GumFunctionContext * ctx)
{
  return FALSE;
}

static gboolean
gum_interceptor_backend_prepare_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumX86FunctionContextData * data = GUM_FCDATA (ctx);
#if GLIB_SIZEOF_VOID_P == 4
  data->redirect_code_size = GUM_INTERCEPTOR_NEAR_REDIRECT_SIZE;

  ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
#else
  GumAddressSpec spec;
  gsize default_alignment = 0;

  spec.near_address = ctx->function_address;
  spec.max_distance = GUM_X86_JMP_MAX_DISTANCE;

  /*
   * When creating a fast interceptor, we won't be vectoring from the target
   * function to the trampoline slice, we will instead be re-directing direct to
   * the target replacement function and therefore must consider the worst case
   * scenario of a JMP with RIP-relative immediate embedded in the code stream.
   * We will still use the trampoline slice for writing the trampoline for the
   * original function in the event that the patched function wishes to call the
   * original. Thus it isn't important where the trampoline slice is located.
   *
   * When creating a normal interceptor, the patch to the target function
   * re-directs first to the on_enter trampoline written to the trampoline
   * slice. If we are able to allocate the slice nearby the target function,
   * then we are able to use a near rather than far jump and hence a shorter
   * op-code. This reduces the amount of the target function prologue which
   * needs to be over-written. If we cannot allocate nearby, however, we
   * just revert to assuming the worst case scenario.
   */
  if (ctx->type == GUM_INTERCEPTOR_TYPE_DEFAULT)
  {
    ctx->trampoline_slice = gum_code_allocator_try_alloc_slice_near (
        self->allocator, &spec, default_alignment);
  }

  if (ctx->trampoline_slice == NULL)
  {
    data->redirect_code_size = GUM_INTERCEPTOR_FULL_REDIRECT_SIZE;

    ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
  }
  else
  {
    data->redirect_code_size = GUM_INTERCEPTOR_NEAR_REDIRECT_SIZE;
  }
#endif

  if (!gum_x86_relocator_can_relocate (ctx->function_address,
        data->redirect_code_size, NULL))
    goto not_enough_space;

  return TRUE;

not_enough_space:
  {
    gum_code_slice_unref (ctx->trampoline_slice);
    ctx->trampoline_slice = NULL;
    return FALSE;
  }
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumX86Writer * cw = &self->writer;
  GumX86Relocator * rl = &self->relocator;
  GumX86FunctionContextData * data = GUM_FCDATA (ctx);
  GumAddress function_ctx_ptr;
  gpointer after_push_to_shadow_stack;
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx))
    return FALSE;

  gum_x86_writer_reset (cw, ctx->trampoline_slice->data);

  if (ctx->type != GUM_INTERCEPTOR_TYPE_FAST)
  {
    function_ctx_ptr = GUM_ADDRESS (gum_x86_writer_cur (cw));
    gum_x86_writer_put_bytes (cw, (guint8 *) &ctx,
        sizeof (GumFunctionContext *));

    ctx->on_enter_trampoline = gum_x86_writer_cur (cw);

    gum_x86_writer_put_push_near_ptr (cw, function_ctx_ptr);
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (self->enter_thunk->data));

    if ((cw->cpu_features & GUM_CPU_CET_SS) != 0)
    {
      /*
       * Jumping to push_to_shadow_stack will push the on_leave_trampoline
       * address onto the shadow stack, thereby making it a legit address to
       * return to. Then it will jump back through XAX.
       */

      after_push_to_shadow_stack = gum_x86_writer_cur (cw);

      gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
          GUM_X86_XSP, (gssize) sizeof (gpointer));

      gum_x86_writer_put_jmp_reg (cw, GUM_X86_XAX);

      data->push_to_shadow_stack = gum_x86_writer_cur (cw);

      gum_x86_writer_put_call_address (cw,
          GUM_ADDRESS (after_push_to_shadow_stack));
    }

    ctx->on_leave_trampoline = gum_x86_writer_cur (cw);

    gum_x86_writer_put_push_near_ptr (cw, function_ctx_ptr);
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (self->leave_thunk->data));

    gum_x86_writer_flush (cw);
    g_assert (gum_x86_writer_offset (cw) <= ctx->trampoline_slice->size);
  }

  ctx->on_invoke_trampoline = gum_x86_writer_cur (cw);
  gum_x86_relocator_reset (rl, (guint8 *) ctx->function_address, cw);

  do
  {
    reloc_bytes = gum_x86_relocator_read_one (rl, NULL);
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < data->redirect_code_size);
  gum_x86_relocator_write_all (rl);

  if (!gum_x86_relocator_eoi (rl))
  {
    gum_x86_writer_put_jmp_address (cw,
        GUM_ADDRESS (ctx->function_address) + reloc_bytes);
  }

  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  gum_memcpy (ctx->overwritten_prologue, ctx->function_address, reloc_bytes);

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
  gum_code_slice_unref (ctx->trampoline_slice);
  ctx->trampoline_slice = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer prologue)
{
  GumX86Writer * cw = &self->writer;
  guint padding;

  gum_x86_writer_reset (cw, prologue);
  cw->pc = GPOINTER_TO_SIZE (ctx->function_address);

  if (ctx->type == GUM_INTERCEPTOR_TYPE_FAST)
  {
    gum_x86_writer_put_jmp_address (cw,
        GUM_ADDRESS (ctx->replacement_function));
  }
  else
  {
    gum_x86_writer_put_jmp_address (cw,
        GUM_ADDRESS (ctx->on_enter_trampoline));
  }

  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= GUM_FCDATA (ctx)->redirect_code_size);
  g_assert (gum_x86_writer_offset (cw) <= ctx->overwritten_prologue_len);

  padding = ctx->overwritten_prologue_len - gum_x86_writer_offset (cw);
  gum_x86_writer_put_nop_padding (cw, padding);
  gum_x86_writer_flush (cw);
}

void
_gum_interceptor_backend_deactivate_trampoline (GumInterceptorBackend * self,
                                                GumFunctionContext * ctx,
                                                gpointer prologue)
{
  gum_memcpy (prologue, ctx->overwritten_prologue,
      ctx->overwritten_prologue_len);
}

gpointer
_gum_interceptor_backend_get_function_address (GumFunctionContext * ctx)
{
  return ctx->function_address;
}

gpointer
_gum_interceptor_backend_resolve_redirect (GumInterceptorBackend * self,
                                           gpointer address)
{
  gpointer target;

  target = gum_x86_reader_try_get_relative_jump_target (address);
  if (target == NULL)
    target = gum_x86_reader_try_get_indirect_jump_target (address);

  return target;
}

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumX86Writer * cw = &self->writer;

  self->enter_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_x86_writer_reset (cw, self->enter_thunk->data);
  gum_emit_enter_thunk (cw);
  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= self->enter_thunk->size);

  self->leave_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_x86_writer_reset (cw, self->leave_thunk->data);
  gum_emit_leave_thunk (cw);
  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= self->leave_thunk->size);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_code_slice_unref (self->leave_thunk);

  gum_code_slice_unref (self->enter_thunk);
}

static void
gum_emit_enter_thunk (GumX86Writer * cw)
{
  const gssize return_address_stack_displacement = 0;
  const gchar * prepare_trap_on_leave = "prepare_trap_on_leave";

  gum_emit_prolog (cw, return_address_stack_displacement);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSI,
      GUM_X86_XBP, GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XDX,
      GUM_X86_XBP, GUM_FRAME_OFFSET_TOP);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XCX,
      GUM_X86_XBP, GUM_FRAME_OFFSET_NEXT_HOP);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, GUM_X86_XBX,
      GUM_ARG_REGISTER, GUM_X86_XSI,
      GUM_ARG_REGISTER, GUM_X86_XDX,
      GUM_ARG_REGISTER, GUM_X86_XCX);

  if ((cw->cpu_features & GUM_CPU_CET_SS) != 0)
  {
    gpointer epilog;

    gum_x86_writer_put_test_reg_reg (cw, GUM_X86_EAX, GUM_X86_EAX);
    gum_x86_writer_put_jcc_short_label (cw, X86_INS_JNE, prepare_trap_on_leave,
        GUM_NO_HINT);

    epilog = gum_x86_writer_cur (cw);
    gum_emit_epilog (cw, GUM_POINT_ENTER);

    gum_x86_writer_put_label (cw, prepare_trap_on_leave);
    gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX, GUM_ADDRESS (epilog));
    gum_x86_writer_put_jmp_reg_offset_ptr (cw, GUM_X86_XBX,
        G_STRUCT_OFFSET (GumFunctionContext, backend_data) +
        G_STRUCT_OFFSET (GumX86FunctionContextData, push_to_shadow_stack));
  }
  else
  {
    gum_emit_epilog (cw, GUM_POINT_ENTER);
  }
}

static void
gum_emit_leave_thunk (GumX86Writer * cw)
{
  const gssize next_hop_stack_displacement = -((gssize) sizeof (gpointer));

  gum_emit_prolog (cw, next_hop_stack_displacement);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSI,
      GUM_X86_XBP, GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XDX,
      GUM_X86_XBP, GUM_FRAME_OFFSET_NEXT_HOP);

  gum_x86_writer_put_call_address_with_aligned_arguments (cw, GUM_CALL_CAPI,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, GUM_X86_XBX,
      GUM_ARG_REGISTER, GUM_X86_XSI,
      GUM_ARG_REGISTER, GUM_X86_XDX);

  gum_emit_epilog (cw, GUM_POINT_LEAVE);
}

static void
gum_emit_prolog (GumX86Writer * cw,
                 gssize stack_displacement)
{
  guint8 fxsave[] = {
    0x0f, 0xae, 0x04, 0x24 /* fxsave [esp] */
  };

  /*
   * Set up our stack frame:
   *
   * [next_hop] <-- already pushed before the branch to our thunk
   * [cpu_flags]
   * [cpu_context] <-- xbp points to the start of the cpu_context
   * [alignment_padding]
   * [extended_context]
   */
  gum_x86_writer_put_pushfx (cw);
  gum_x86_writer_put_cld (cw); /* C ABI mandates this */
  gum_x86_writer_put_pushax (cw); /* all of GumCpuContext except for xip */
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
      GUM_X86_XSP, -((gssize) sizeof (gpointer))); /* GumCpuContext.xip */

  /* fixup the GumCpuContext stack pointer */
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XAX,
      GUM_X86_XSP, GUM_FRAME_OFFSET_TOP + stack_displacement);
  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw,
      GUM_X86_XSP, GUM_CPU_CONTEXT_OFFSET_XSP,
      GUM_X86_XAX);

  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XBX, GUM_X86_XSP,
      GUM_FRAME_OFFSET_NEXT_HOP);
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XBP, GUM_X86_XSP);
  gum_x86_writer_put_and_reg_u32 (cw, GUM_X86_XSP, (guint32) ~(16 - 1));
  gum_x86_writer_put_sub_reg_imm (cw, GUM_X86_XSP, 512);
  gum_x86_writer_put_bytes (cw, fxsave, sizeof (fxsave));
}

static void
gum_emit_epilog (GumX86Writer * cw,
                 GumPointCut point_cut)
{
  guint8 fxrstor[] = {
    0x0f, 0xae, 0x0c, 0x24 /* fxrstor [esp] */
  };

  gum_x86_writer_put_bytes (cw, fxrstor, sizeof (fxrstor));
  gum_x86_writer_put_mov_reg_reg (cw, GUM_X86_XSP, GUM_X86_XBP);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
      GUM_X86_XSP, sizeof (gpointer)); /* discard
                                          GumCpuContext.xip */
  gum_x86_writer_put_popax (cw);
  gum_x86_writer_put_popfx (cw);

  if (point_cut == GUM_POINT_LEAVE)
  {
    gum_x86_writer_put_ret (cw);
  }
  else
  {
    /* Emulate a ret without affecting the shadow stack. */
    gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
        GUM_X86_XSP, sizeof (gpointer));
    gum_x86_writer_put_jmp_reg_offset_ptr (cw, GUM_X86_XSP,
        -((gssize) sizeof (gpointer)));
  }
}
```