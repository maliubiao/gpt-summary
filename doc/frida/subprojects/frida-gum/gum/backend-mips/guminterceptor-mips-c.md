Response:
Let's break down the thought process for analyzing this C code and generating the detailed response.

**1. Initial Skim and Keyword Recognition:**

The first step is a quick read-through to identify key components and functionalities. Keywords like "interceptor," "hook," "trampoline," "MIPS," "relocator," "writer," "thunk," "CPU context," "prologue," "epilogue," and register names (`T0`, `AT`, `SP`, etc.) immediately stand out. These provide a high-level understanding of the code's purpose: intercepting function calls on the MIPS architecture.

**2. Understanding the Core Functionality (The "What"):**

The comments at the beginning are crucial:  "This constant represents the size of the hook assembly sequence which is to be written over the prologue of the intercepted function." This tells us the code is about modifying the beginning of functions. The mention of "trampoline" suggests a detour mechanism. The structure definitions (`GumInterceptorBackend`, `GumMipsFunctionContextData`) hint at how the interception is managed.

**3. Identifying Key Data Structures and Their Roles:**

*   `GumInterceptorBackend`:  This likely holds global state and resources for the interceptor, like the code allocator and the MIPS-specific writer and relocator.
*   `GumFunctionContext`:  This appears to be a per-intercepted-function structure, storing information like the original function address, the trampoline's location, and the overwritten prologue.
*   `GumMipsFunctionContextData`:  MIPS-specific data within the function context, including the size of the redirect code and a scratch register.
*   `GumCodeAllocator`: Responsible for allocating memory for the trampoline and thunks.
*   `GumMipsWriter`:  Facilitates writing MIPS assembly instructions.
*   `GumMipsRelocator`:  Handles the process of copying and adjusting instructions from the original function's prologue to the trampoline.

**4. Tracing the Interception Flow (The "How"):**

Follow the core functions like `_gum_interceptor_backend_create_trampoline` and `_gum_interceptor_backend_activate_trampoline`. This reveals the steps involved in setting up an interception:

*   **`_gum_interceptor_backend_prepare_trampoline`:** Decides if a direct hook or a "deflector" is needed based on the size limitations for overwriting the prologue. Allocates memory for the trampoline.
*   **`_gum_interceptor_backend_create_trampoline`:**  Writes the trampoline code. This involves:
    *   Saving the current CPU context.
    *   Calling the "enter thunk" to execute pre-invocation logic.
    *   Calling the "leave thunk" for post-invocation logic.
    *   Relocating the original function's prologue to the trampoline.
    *   Jumping back to the original function after the relocated prologue.
*   **`_gum_interceptor_backend_activate_trampoline`:** Overwrites the original function's prologue with a jump to the trampoline.
*   **`_gum_interceptor_backend_deactivate_trampoline`:** Restores the original prologue.

**5. Analyzing the Thunks:**

The `gum_emit_enter_thunk` and `gum_emit_leave_thunk` functions are crucial. They set up the arguments and call the `_gum_function_context_begin_invocation` and `_gum_function_context_end_invocation` functions. The `gum_emit_prolog` and `gum_emit_epilog` functions within the thunks are responsible for saving and restoring all the relevant MIPS registers, ensuring the intercepted function's state is preserved.

**6. Connecting to Reverse Engineering:**

At this point, the connection to reverse engineering becomes clear. The code *directly manipulates the execution flow* of a program. By overwriting the prologue, it redirects execution to Frida's code. This is a fundamental technique used in dynamic instrumentation and reverse engineering to observe and modify program behavior.

**7. Identifying Low-Level Details:**

Focus on the MIPS assembly instructions used by `GumMipsWriter`. Instructions like `put_la_reg_address` (load address), `put_jr_reg` (jump register), `put_push_reg` (push onto stack), `put_pop_reg` (pop from stack), and the various arithmetic and move instructions are key. Understanding MIPS calling conventions (how arguments are passed, which registers are used) is essential for interpreting the thunk logic. The handling of the return address (`ra`) is also important.

**8. Connecting to OS/Kernel Concepts:**

*   **Memory Management:** The use of `GumCodeAllocator` highlights the need to allocate executable memory. This ties into OS concepts of memory protection and how dynamic code generation works.
*   **Context Switching (Implicit):** While not explicitly a context switch, the saving and restoring of CPU registers in the prologue and epilogue mimic aspects of it. Frida needs to preserve the original function's execution environment.
*   **Function Call Conventions:** The thunks directly interact with the MIPS calling convention to pass arguments to Frida's callback functions.

**9. Logical Reasoning and Input/Output Examples:**

Consider what happens when a function is intercepted. The *input* is the address of the function to intercept. The *output* is the ability to execute custom code before and after the original function's execution. Think about the conditions under which a "deflector" is needed – when the prologue is too small for a direct jump.

**10. Identifying Potential User Errors:**

Think about how a user might interact with Frida. Incorrectly specifying the function address to intercept, or writing Frida scripts that interfere with the trampoline's operation, are potential errors. The code itself has assertions (`g_assert`) which act as internal checks.

**11. Tracing User Actions to Code Execution:**

Imagine a user writing a Frida script that attaches to a process and calls `Interceptor.attach(address, { onEnter: ..., onLeave: ... })`. This action would eventually lead to the execution of the functions within `guminterceptor-mips.c` to set up the interception.

**Self-Correction/Refinement During Analysis:**

*   **Initial Misunderstanding:**  Perhaps initially, the role of the "deflector" isn't immediately clear. Reading the surrounding code and comments clarifies its purpose in handling cases with limited prologue space.
*   **Register Usage:** Double-checking the comments regarding register usage on MIPS64 versus MIPS32 helps ensure accurate interpretation of the assembly code.
*   **Focus on the "Why":**  Constantly ask "Why is this piece of code here?" This helps connect the individual parts to the overall goal of function interception.

By following these steps, one can systematically analyze the provided C code and generate a comprehensive explanation covering its functionality, relationship to reverse engineering, low-level details, OS concepts, logical reasoning, potential errors, and user interaction.
这是一个Frida动态插桩工具的源代码文件，专门用于MIPS架构的函数拦截。以下是它的功能以及与逆向、底层知识、逻辑推理和用户错误相关的说明：

**功能列举:**

1. **函数拦截 (Function Interception):** 这是该文件的核心功能。它允许在目标进程的函数执行前后插入自定义的代码，即所谓的“hook”。
2. **Trampoline 创建 (Trampoline Creation):**  为了实现拦截，需要创建一个“trampoline”。Trampoline 是一小段动态生成的代码，它被放置在被拦截函数的入口处。当目标函数被调用时，执行流程会先跳转到 trampoline。
3. **Thunk 创建 (Thunk Creation):**  创建 "enter thunk" 和 "leave thunk"。这些是预先生成的代码片段，用于在 trampoline 中调用 Frida 的 C 代码，分别在被拦截函数执行之前和之后执行用户自定义的 JavaScript 代码。
4. **上下文保存与恢复 (Context Saving and Restoring):**  在进入和离开被拦截函数时，需要保存和恢复 CPU 的寄存器状态（context），以保证被拦截函数的正常执行不受干扰。
5. **代码重定位 (Code Relocation):**  将被拦截函数的前几条指令（prologue）复制到 trampoline 中，并可能需要进行重定位，因为这些指令现在位于不同的内存地址。
6. **指令写入 (Instruction Writing):** 使用 `GumMipsWriter` 来生成 MIPS 汇编指令，用于构建 trampoline 和 thunk。
7. **内存分配 (Memory Allocation):** 使用 `GumCodeAllocator` 来动态分配用于 trampoline 和 thunk 的内存。
8. **处理不同字长 (Handling Different Word Sizes):** 代码中使用了 `GLIB_SIZEOF_VOID_P` 来区分 MIPS32 和 MIPS64 架构，并针对性地生成不同的汇编代码。
9. **处理直接跳转和间接跳转 (Handling Direct and Indirect Jumps):**  根据被拦截函数 prologue 的大小和跳转距离，选择合适的跳转指令。

**与逆向方法的关系及举例说明:**

该文件是实现动态逆向的核心组件。通过 Frida，逆向工程师可以：

*   **监控函数调用:**  在 `onEnter` 中记录函数的参数值，可以了解函数被如何调用，传递了哪些数据。
    *   **举例:** 假设要逆向一个加密函数 `encrypt(data, key)`，可以在 `onEnter` 中打印 `data` 和 `key` 的值，从而分析加密过程。
*   **修改函数行为:** 在 `onEnter` 或 `onLeave` 中修改函数的参数或返回值，可以改变程序的执行流程或结果。
    *   **举例:**  对于一个校验函数 `checkLicense()`，可以在 `onEnter` 中直接修改其返回值，使其始终返回成功，绕过授权验证。
*   **追踪代码执行路径:** 通过在多个关键函数上设置 hook，可以了解代码的执行顺序和逻辑。
*   **动态分析内存:**  在 hook 中可以读取和修改内存中的数据，例如查看敏感数据的存储位置和内容。

**涉及二进制底层、Linux、Android内核及框架的知识及举例说明:**

1. **MIPS 汇编指令:**  代码中大量使用了 MIPS 汇编指令，例如 `la` (load address), `jr` (jump register), `addi` (add immediate), `push`, `pop` 等。理解这些指令是理解代码功能的基础。
    *   **举例:** `gum_mips_writer_put_la_reg_address (cw, MIPS_REG_AT, GUM_ADDRESS (self->enter_thunk->data));`  这行代码将 `enter_thunk` 的地址加载到 `AT` 寄存器中。
2. **MIPS 调用约定:** 代码中需要按照 MIPS 的调用约定来保存和恢复寄存器，以及传递参数。例如，MIPS64 中前 8 个参数通过寄存器传递 (a0-a7)。
3. **内存管理:**  `GumCodeAllocator` 涉及到操作系统底层的内存分配和管理，特别是需要分配可执行内存。
4. **代码段和数据段:**  hook 的实现需要在代码段中插入新的指令（trampoline），并可能需要在数据段中存储一些状态信息。
5. **函数 prologue 和 epilogue:**  代码需要理解 MIPS 函数的 prologue (函数开始时的指令，通常用于保存寄存器和分配栈空间) 以便安全地覆盖并恢复。
6. **Linux/Android 进程内存布局:**  Frida 需要在目标进程的内存空间中操作，理解进程的内存布局对于实现 hook 至关重要。
7. **动态代码生成:**  Trampoline 是在运行时动态生成的代码，这涉及到操作系统提供的内存保护机制和权限管理。

**逻辑推理及假设输入与输出:**

*   **假设输入:** 要 hook 的目标函数地址 `function_address`。
*   **逻辑推理:**
    *   `gum_interceptor_backend_prepare_trampoline`:  根据 `function_address` 和 `GUM_HOOK_SIZE` 判断是否可以直接覆盖 prologue，或者需要创建一个更长的 trampoline 甚至 deflector。
    *   如果 `gum_mips_relocator_can_relocate` 返回 `TRUE`，则说明可以直接覆盖 prologue，`redirect_code_size` 将被设置为 `GUM_HOOK_SIZE`。
    *   否则，会尝试在目标地址附近分配 trampoline，如果失败，则分配一个远端的 trampoline 并设置 `need_deflector` 为 `TRUE`。
    *   `gum_interceptor_backend_create_trampoline`:  根据 `need_deflector` 的值生成不同的 trampoline 代码。
    *   如果不需要 deflector，则在 trampoline 中直接跳转到 enter thunk，执行用户代码，然后跳转回原始函数或 leave thunk。
    *   如果需要 deflector (目前代码中 `g_assert_not_reached ()`)，则需要更复杂的逻辑来处理跳转。
    *   `gum_interceptor_backend_activate_trampoline`:  将 trampoline 的入口地址写入到目标函数的 prologue 中，实现 hook。
*   **假设输出:**
    *   成功创建 trampoline 并激活 hook 后，当目标函数被调用时，会先执行 Frida 注入的 JavaScript 代码 (通过 enter 和 leave thunk)。
    *   如果创建 trampoline 失败，`_gum_interceptor_backend_create_trampoline` 会返回 `FALSE`。

**涉及用户或编程常见的使用错误及举例说明:**

1. **尝试 hook 非常小的函数:** 如果被 hook 的函数 prologue 比 `GUM_HOOK_SIZE` 还小，Frida 可能无法安全地插入 trampoline。这会导致程序崩溃或行为异常。
2. **在 `onEnter` 或 `onLeave` 中执行耗时操作:** 这会影响目标程序的性能，甚至导致程序无响应。
3. **错误地修改了上下文 (CPU 寄存器):**  如果在 `onEnter` 或 `onLeave` 中不小心修改了某些关键寄存器的值，而没有正确恢复，可能会导致被 hook 的函数执行出错。
    *   **举例:**  错误地修改了返回地址寄存器 `ra`，会导致函数返回到错误的位置。
4. **内存访问错误:**  在 hook 代码中访问了无效的内存地址，会导致程序崩溃。
5. **Hook 了不应该 hook 的函数:**  Hook 了操作系统或关键库的内部函数，可能会导致系统不稳定。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 用户使用 JavaScript 编写 Frida 脚本，指定要 hook 的函数地址或符号，并定义 `onEnter` 和 `onLeave` 回调函数。
    ```javascript
    Interceptor.attach(ptr("0x12345678"), {
      onEnter: function(args) {
        console.log("Entering function at 0x12345678");
      },
      onLeave: function(retval) {
        console.log("Leaving function at 0x12345678");
      }
    });
    ```
2. **Frida 执行脚本:** 用户使用 Frida 命令行工具或 API 将脚本注入到目标进程中。
    ```bash
    frida -p <pid> -l script.js
    ```
3. **Frida 解析脚本并调用 Interceptor API:** Frida 的 JavaScript 引擎解析脚本，并调用 `Interceptor.attach` 方法。
4. **Interceptor 模块处理 attach 请求:**  `Interceptor.attach` 内部会调用到 Gum 库的相关代码。
5. **Gum 库调用 backend 实现:**  对于 MIPS 架构，会调用到 `gum/backend-mips/guminterceptor-mips.c` 中的函数，例如 `_gum_interceptor_backend_create_trampoline` 和 `_gum_interceptor_backend_activate_trampoline`。
6. **执行 `guminterceptor-mips.c` 中的代码:**  该文件中的代码负责分配内存，生成 trampoline 和 thunk 的汇编指令，并将 trampoline 写入到目标函数的 prologue 中。

作为调试线索，如果用户发现 hook 没有生效，或者目标程序崩溃，可以检查以下几点：

*   **目标函数地址是否正确:** 使用正确的地址非常关键。
*   **是否有足够的权限:** Frida 需要有足够的权限在目标进程中分配内存和修改代码。
*   **目标函数是否被内联或优化:**  某些情况下，编译器可能会内联或优化函数，导致无法直接 hook。
*   **Trampoline 是否创建成功:**  可以查看 Frida 的日志输出，或者在 GDB 中断点到 `guminterceptor-mips.c` 中的代码，查看 trampoline 的创建过程和内存布局。
*   **是否存在与其他 hook 的冲突:**  如果多个 Frida 脚本 hook 了同一个函数，可能会发生冲突。

总而言之，`guminterceptor-mips.c` 是 Frida 在 MIPS 架构下实现动态插桩的关键组成部分，它涉及到汇编编程、操作系统底层知识以及对目标进程内存结构的理解。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-mips/guminterceptor-mips.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2014-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor-priv.h"

#include "gummipsreader.h"
#include "gummipsrelocator.h"
#include "gummipswriter.h"
#include "gumlibc.h"
#include "gummemory.h"

#include <string.h>
#include <unistd.h>

/*
 * This constant represents the size of the hook assembly sequence which
 * is to be written over the prologue of the intercepted function. This
 * is a minimalist stub which simply vectors to the larger trampoline which
 * stores the CPU context and transitions to C code passing the necessary
 * landmarks.
 *
 * On MIPS64, whilst data access can be 64 bits wide, the instruction stream
 * is only 32 bits. With fixed width 32-bit instructions, it is only possible
 * to load 16 bit immediate values at a time. Hence loading a 64-bit immediate
 * value takes rather more instructions.
 */
#if GLIB_SIZEOF_VOID_P == 8
# define GUM_HOOK_SIZE 28
#else
# define GUM_HOOK_SIZE 16
#endif

#define GUM_FRAME_OFFSET_CPU_CONTEXT 0
#define GUM_FRAME_OFFSET_NEXT_HOP \
    (GUM_FRAME_OFFSET_CPU_CONTEXT + sizeof (GumCpuContext))

#define GUM_FCDATA(context) \
    ((GumMipsFunctionContextData *) (context)->backend_data.storage)

typedef struct _GumMipsFunctionContextData GumMipsFunctionContextData;

struct _GumInterceptorBackend
{
  GumCodeAllocator * allocator;

  GumMipsWriter writer;
  GumMipsRelocator relocator;

  GumCodeSlice * enter_thunk;
  GumCodeSlice * leave_thunk;
};

struct _GumMipsFunctionContextData
{
  guint redirect_code_size;
  mips_reg scratch_reg;
};

G_STATIC_ASSERT (sizeof (GumMipsFunctionContextData)
    <= sizeof (GumFunctionContextBackendData));

static void gum_interceptor_backend_create_thunks (
    GumInterceptorBackend * self);
static void gum_interceptor_backend_destroy_thunks (
    GumInterceptorBackend * self);

static void gum_emit_enter_thunk (GumMipsWriter * aw);
static void gum_emit_leave_thunk (GumMipsWriter * aw);

static void gum_emit_prolog (GumMipsWriter * aw);
static void gum_emit_epilog (GumMipsWriter * aw);

GumInterceptorBackend *
_gum_interceptor_backend_create (GRecMutex * mutex,
                                 GumCodeAllocator * allocator)
{
  GumInterceptorBackend * backend;

  backend = g_slice_new (GumInterceptorBackend);
  backend->allocator = allocator;

  gum_mips_writer_init (&backend->writer, NULL);
  gum_mips_relocator_init (&backend->relocator, NULL, &backend->writer);

  gum_interceptor_backend_create_thunks (backend);

  return backend;
}

void
_gum_interceptor_backend_destroy (GumInterceptorBackend * backend)
{
  gum_interceptor_backend_destroy_thunks (backend);

  gum_mips_relocator_clear (&backend->relocator);
  gum_mips_writer_clear (&backend->writer);

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
                                            GumFunctionContext * ctx,
                                            gboolean * need_deflector)
{
  GumMipsFunctionContextData * data = GUM_FCDATA (ctx);
  gpointer function_address = ctx->function_address;
  guint redirect_limit;

  *need_deflector = FALSE;

  if (gum_mips_relocator_can_relocate (function_address, GUM_HOOK_SIZE,
      GUM_SCENARIO_ONLINE, &redirect_limit, &data->scratch_reg))
  {
    data->redirect_code_size = GUM_HOOK_SIZE;

    ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
  }
  else
  {
    GumAddressSpec spec;
    gsize alignment;

    if (redirect_limit >= 8)
    {
      data->redirect_code_size = 8;

      spec.near_address = function_address;
      spec.max_distance = GUM_MIPS_J_MAX_DISTANCE;
      alignment = 0;
    }
    else
    {
      return FALSE;
    }

    ctx->trampoline_slice = gum_code_allocator_try_alloc_slice_near (
        self->allocator, &spec, alignment);
    if (ctx->trampoline_slice == NULL)
    {
      ctx->trampoline_slice = gum_code_allocator_alloc_slice (self->allocator);
      *need_deflector = TRUE;
    }
  }

  if (data->scratch_reg == MIPS_REG_INVALID)
    return FALSE;

  return TRUE;
}

gboolean
_gum_interceptor_backend_create_trampoline (GumInterceptorBackend * self,
                                            GumFunctionContext * ctx)
{
  GumMipsWriter * cw = &self->writer;
  GumMipsRelocator * rl = &self->relocator;
  gpointer function_address = ctx->function_address;
  GumMipsFunctionContextData * data = GUM_FCDATA (ctx);
  gboolean need_deflector;
  guint reloc_bytes;

  if (!gum_interceptor_backend_prepare_trampoline (self, ctx, &need_deflector))
    return FALSE;

  gum_mips_writer_reset (cw, ctx->trampoline_slice->data);

  ctx->on_enter_trampoline = gum_mips_writer_cur (cw);

  if (need_deflector)
  {
    /* TODO: implement deflector behavior */
    g_assert_not_reached ();
  }

  /* TODO: save $t0 on the stack? */

#if GLIB_SIZEOF_VOID_P == 8
  /*
   * On MIPS64 the calling convention is that 8 arguments are passed in
   * registers. The additional registers used for these arguments are a4-a7,
   * these replace the registers t0-t3 used in MIPS32. Hence t4 is now our first
   * available register, otherwise we will start clobbering function parameters.
   */
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T4, GUM_ADDRESS (ctx));
#else
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T0, GUM_ADDRESS (ctx));
#endif
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_AT,
      GUM_ADDRESS (self->enter_thunk->data));
  gum_mips_writer_put_jr_reg (cw, MIPS_REG_AT);

  ctx->on_leave_trampoline = gum_mips_writer_cur (cw);

  /* TODO: save $t0 on the stack? */
#if GLIB_SIZEOF_VOID_P == 8
  /* See earlier comment on clobbered registers. */
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T4, GUM_ADDRESS (ctx));
#else
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T0, GUM_ADDRESS (ctx));
#endif
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_AT,
      GUM_ADDRESS (self->leave_thunk->data));
  gum_mips_writer_put_jr_reg (cw, MIPS_REG_AT);

  gum_mips_writer_flush (cw);
  g_assert (gum_mips_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->on_invoke_trampoline = gum_mips_writer_cur (cw);

  /* Fix t9 to point to the original function address */
  gum_mips_writer_put_la_reg_address (cw, MIPS_REG_T9,
      GUM_ADDRESS (function_address));

  gum_mips_relocator_reset (rl, function_address, cw);

  do
  {
    reloc_bytes = gum_mips_relocator_read_one (rl, NULL);
    g_assert (reloc_bytes != 0);
  }
  while (reloc_bytes < data->redirect_code_size || rl->delay_slot_pending);

  gum_mips_relocator_write_all (rl);

  if (!rl->eoi)
  {
    GumAddress resume_at;

    resume_at = GUM_ADDRESS (function_address) + reloc_bytes;
    gum_mips_writer_put_la_reg_address (cw, data->scratch_reg, resume_at);
    gum_mips_writer_put_jr_reg (cw, data->scratch_reg);
  }

  gum_mips_writer_flush (cw);
  g_assert (gum_mips_writer_offset (cw) <= ctx->trampoline_slice->size);

  ctx->overwritten_prologue_len = reloc_bytes;
  gum_memcpy (ctx->overwritten_prologue, function_address, reloc_bytes);

  return TRUE;
}

void
_gum_interceptor_backend_destroy_trampoline (GumInterceptorBackend * self,
                                             GumFunctionContext * ctx)
{
  gum_code_slice_unref (ctx->trampoline_slice);
  gum_code_deflector_unref (ctx->trampoline_deflector);
  ctx->trampoline_slice = NULL;
  ctx->trampoline_deflector = NULL;
}

void
_gum_interceptor_backend_activate_trampoline (GumInterceptorBackend * self,
                                              GumFunctionContext * ctx,
                                              gpointer prologue)
{
  GumMipsWriter * cw = &self->writer;
  GumMipsFunctionContextData * data = GUM_FCDATA (ctx);
  GumAddress on_enter = GUM_ADDRESS (ctx->on_enter_trampoline);

  gum_mips_writer_reset (cw, prologue);
  cw->pc = GUM_ADDRESS (ctx->function_address);

  if (ctx->trampoline_deflector != NULL)
  {
    /* TODO: implement branch to deflector */
    g_assert_not_reached ();
  }
  else
  {
    switch (data->redirect_code_size)
    {
      case 8:
        gum_mips_writer_put_j_address (cw, on_enter);
        break;
      case GUM_HOOK_SIZE:
#if GLIB_SIZEOF_VOID_P == 8
        /*
         * On MIPS64 loading a 64-bit immediate requires 16-bits of the
         * immediate to be loaded at a time since instructions are only 32-bits
         * wide. This results in a large number of instructions both for the
         * loading as well as logical shifting of the immediate.
         *
         * Therefore on 64-bit platforms we instead embed the immediate in the
         * code stream and read its value from there. However, we need to know
         * the address from which to load the value. Since our hook is to be
         * written over the prolog of an existing function, we can rely upon
         * this.
         *
         * MIPS has no architectural visibility of the instruction pointer.
         * That is its value cannot be read and there is no RIP-relative
         * addressing. Therefore convention is that a general purpose register
         * (T9) is set to the address of the function to be called. We can
         * therefore use this register to locate the immediate we need to load.
         * However, this mechanism only works for loading immediates for the
         * hook since if we are writing instructions to load an immediate
         * elsewhere, we don't know how far our RIP is from the start of the
         * function. However, in these cases we don't care about code size and
         * we can instead revert to the old method of shuffling 16-bits at
         * a time.
         */
        gum_mips_writer_put_prologue_trampoline (cw, MIPS_REG_AT, on_enter);
#else
        gum_mips_writer_put_la_reg_address (cw, MIPS_REG_AT, on_enter);
        gum_mips_writer_put_jr_reg (cw, MIPS_REG_AT);
#endif
        break;
      default:
        g_assert_not_reached ();
    }
  }

  gum_mips_writer_flush (cw);
  g_assert (gum_mips_writer_offset (cw) <= data->redirect_code_size);
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
  /* TODO: implement resolve redirect */
  return NULL;
}

static void
gum_interceptor_backend_create_thunks (GumInterceptorBackend * self)
{
  GumMipsWriter * cw = &self->writer;

  self->enter_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_mips_writer_reset (cw, self->enter_thunk->data);
  gum_emit_enter_thunk (cw);
  gum_mips_writer_flush (cw);
  g_assert (gum_mips_writer_offset (cw) <= self->enter_thunk->size);

  self->leave_thunk = gum_code_allocator_alloc_slice (self->allocator);
  gum_mips_writer_reset (cw, self->leave_thunk->data);
  gum_emit_leave_thunk (cw);
  gum_mips_writer_flush (cw);
  g_assert (gum_mips_writer_offset (cw) <= self->leave_thunk->size);
}

static void
gum_interceptor_backend_destroy_thunks (GumInterceptorBackend * self)
{
  gum_code_slice_unref (self->leave_thunk);

  gum_code_slice_unref (self->enter_thunk);
}

static void
gum_emit_enter_thunk (GumMipsWriter * cw)
{
  gum_emit_prolog (cw);

  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A1, MIPS_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A2, MIPS_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT + G_STRUCT_OFFSET (GumCpuContext, ra));
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A3, MIPS_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);

#if GLIB_SIZEOF_VOID_P == 8
  /* See earlier comment on clobbered registers. */
  gum_mips_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, MIPS_REG_T4,
      GUM_ARG_REGISTER, MIPS_REG_A1,  /* cpu_context */
      GUM_ARG_REGISTER, MIPS_REG_A2,  /* return_address */
      GUM_ARG_REGISTER, MIPS_REG_A3); /* next_hop */
#else
  gum_mips_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_begin_invocation), 4,
      GUM_ARG_REGISTER, MIPS_REG_T0,
      GUM_ARG_REGISTER, MIPS_REG_A1,  /* cpu_context */
      GUM_ARG_REGISTER, MIPS_REG_A2,  /* return_address */
      GUM_ARG_REGISTER, MIPS_REG_A3); /* next_hop */
#endif

  gum_emit_epilog (cw);
}

static void
gum_emit_leave_thunk (GumMipsWriter * cw)
{
  gum_emit_prolog (cw);

  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A1, MIPS_REG_SP,
      GUM_FRAME_OFFSET_CPU_CONTEXT);
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_A2, MIPS_REG_SP,
      GUM_FRAME_OFFSET_NEXT_HOP);
#if GLIB_SIZEOF_VOID_P == 8
  /* See earlier comment on clobbered registers. */
  gum_mips_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, MIPS_REG_T4,
      GUM_ARG_REGISTER, MIPS_REG_A1,  /* cpu_context */
      GUM_ARG_REGISTER, MIPS_REG_A2); /* next_hop */
#else
  gum_mips_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (_gum_function_context_end_invocation), 3,
      GUM_ARG_REGISTER, MIPS_REG_T0,
      GUM_ARG_REGISTER, MIPS_REG_A1,  /* cpu_context */
      GUM_ARG_REGISTER, MIPS_REG_A2); /* next_hop */
#endif

  gum_emit_epilog (cw);
}

static void
gum_emit_prolog (GumMipsWriter * cw)
{
  /*
   * Set up our stack frame:
   *
   * [next_hop]
   * [cpu_context]
   */

  /* Reserve space for next_hop. */
  gum_mips_writer_put_push_reg (cw, MIPS_REG_ZERO);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_K1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_K0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_S7);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S6);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S5);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S4);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S3);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S2);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_S0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_T9);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T8);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T7);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T6);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T5);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T4);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T3);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T2);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_T0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_A3);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_A2);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_A1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_A0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_V1);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_AT);

  gum_mips_writer_put_mflo_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_mfhi_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_RA);
  gum_mips_writer_put_push_reg (cw, MIPS_REG_FP);

  /*
   * SP
   *
   * Here we are calculating the original stack pointer (before we stored) all
   * the context above and saving it to the stack so that it can be read as part
   * of the CpuContext structure.
   */
#if GLIB_SIZEOF_VOID_P == 8
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_V0, MIPS_REG_SP,
      8 + (30 * 8));
#else
  gum_mips_writer_put_addi_reg_reg_imm (cw, MIPS_REG_V0, MIPS_REG_SP,
      4 + (30 * 4));
#endif
  gum_mips_writer_put_push_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_push_reg (cw, MIPS_REG_GP);

  /* Dummy PC */
  gum_mips_writer_put_push_reg (cw, MIPS_REG_ZERO);
}

static void
gum_emit_epilog (GumMipsWriter * cw)
{
  /* Dummy PC */
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_GP);

  /* Dummy SP */
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_FP);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_RA);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_mthi_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_mtlo_reg (cw, MIPS_REG_V0);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_AT);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_V1);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_A0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_A1);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_A2);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_A3);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T1);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T2);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T3);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T4);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T5);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T6);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T7);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T8);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T9);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S1);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S2);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S3);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S4);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S5);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S6);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_S7);

  gum_mips_writer_put_pop_reg (cw, MIPS_REG_K0);
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_K1);

  /*
   * Pop and jump to the next_hop.
   *
   * This needs to be via t9 so that PIC code works.
   */
  gum_mips_writer_put_pop_reg (cw, MIPS_REG_T9);
  gum_mips_writer_put_jr_reg (cw, MIPS_REG_T9);
}

"""

```