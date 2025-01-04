Response:
The user wants a summary of the functionalities of the provided C code snippet, which is a part of Frida's Stalker for ARM64 architecture. I need to identify the key actions and data structures being manipulated. The request also asks for connections to reverse engineering, binary/OS concepts, logical reasoning, potential user errors, and how a user might reach this code.

Here's a breakdown of the code's function:

1. **Execution Context Management:** The code defines and manipulates `GumExecCtx`, which seems to represent the context of code execution being tracked by Stalker. This involves creating, destroying, and managing the state of this context.

2. **Code and Data Slab Management:** The code uses `GumCodeSlab`, `GumSlowSlab`, and `GumDataSlab` to allocate and manage memory for instrumented code and related data. This involves adding new slabs and freeing them.

3. **Code Block Management:** `GumExecBlock` appears to represent a block of original code that has been instrumented. The code handles obtaining blocks, compiling them, recompiling them, and switching between them during execution. This includes managing a cache of these blocks (`ctx->mappings`).

4. **Code Generation and Transformation:**  The code uses `GumArm64Writer` and `GumArm64Relocator` to rewrite and relocate instructions. The `transform_block_impl` member of `GumExecCtx` suggests the core instrumentation logic is applied here.

5. **Observer Pattern:** The code interacts with a `GumStalkerObserver` to notify about events like block execution, calls, returns, and compilations. This is a key part of Frida's dynamic instrumentation capabilities.

6. **Callout Mechanism:** The code provides a way to inject custom C code (`GumStalkerCallout`) during the execution flow.

7. **Control Flow Manipulation:** The `gum_exec_ctx_switch_block` function handles transitions between code blocks, potentially triggered by branches, calls, or returns. It also deals with "unfollowing" which is likely stopping the instrumentation.

8. **Inline Helpers:** The code ensures that small helper functions (prolog, epilog, invalidator) are available for use within the generated code.

9. **Potential User Errors:**  The code has some checks related to the state of the execution context, hinting at potential misuses.

10. **Reverse Engineering Relevance:** The entire process is fundamentally about reverse engineering, by intercepting and modifying code execution.

11. **Binary/OS Concepts:** Concepts like code relocation, memory management, instruction rewriting, and handling system calls are present.

12. **Logical Reasoning:**  The decision-making around recompilation based on `trust_threshold` and memory comparisons involves logical reasoning.

13. **User Operations:**  The code is reached through Frida's API calls that initiate the stalking process.

Now I can construct the summarized functionalities and examples based on these points.
这是frida-gum中用于ARM64架构的Stalker组件的一部分，专注于管理和执行被插桩的代码。 从提供的代码片段来看，它主要负责 `GumExecCtx` （执行上下文）的生命周期管理以及与代码块(`GumExecBlock`)相关的操作。

**主要功能归纳:**

1. **执行上下文的生命周期管理 (`gum_exec_ctx_free`, `gum_exec_ctx_dispose`):**  负责创建、清理和释放 `GumExecCtx` 实例。这包括释放分配的内存，取消对相关对象的引用（如 sink, transformer, observer），以及清除代码写入器和重定位器。
2. **代码和慢速代码 Slab 的管理 (`gum_exec_ctx_add_code_slab`, `gum_exec_ctx_add_slow_slab`):**  管理用于存储生成代码的内存区域（Slab）。代码被分到快速执行的代码和慢速执行的代码，分别存储在不同的 Slab 中。
3. **数据 Slab 的管理 (`gum_exec_ctx_add_data_slab`):**  管理用于存储数据的内存区域。
4. **计算地址规范 (`gum_exec_ctx_compute_code_address_spec`, `gum_exec_ctx_compute_data_address_spec`):**  计算在生成的代码中访问 `GumExecCtx` 和 `GumExecBlock` 成员时的地址偏移量限制，确保可以使用 32 位偏移进行访问。
5. **管理停止跟踪的状态 (`gum_exec_ctx_maybe_unfollow`, `gum_exec_ctx_unfollow`):**  处理停止代码跟踪的逻辑，允许在特定时机或满足某些条件时停止 Stalker 的执行。
6. **判断是否已执行 (`gum_exec_ctx_has_executed`):**  检查执行上下文是否已经开始执行。
7. **判断地址是否在上下文中 (`gum_exec_ctx_contains`):**  检查给定的内存地址是否属于当前执行上下文生成的代码或慢速代码区域。
8. **判断是否可以进行回填 (`gum_exec_ctx_may_now_backpatch`):**  判断是否可以对特定的代码块进行回填优化，这通常基于代码块的执行次数等因素。
9. **入口网关 (`GUM_DEFINE_ENTRYGATE`):** 定义了各种入口点，用于在执行过程中切换代码块，例如处理立即数调用、寄存器调用、返回、跳转等指令。这些入口点会记录执行信息并调用 `gum_exec_ctx_switch_block` 来完成实际的切换。
10. **代码块切换的核心逻辑 (`gum_exec_ctx_switch_block`):**  负责在不同的代码块之间切换执行。它会获取目标地址的代码块，并通知观察者（observer）进行回调。如果目标地址不在当前上下文中，则会获取或编译新的代码块。
11. **查询代码块切换回调 (`gum_exec_ctx_query_block_switch_callback`):**  在代码块切换前通知观察者，允许用户修改目标地址或执行其他操作。
12. **重新编译和切换代码块 (`gum_exec_ctx_recompile_and_switch_block`):**  当需要更新代码块时，会先重新编译该代码块，然后切换到新编译的代码。
13. **获取代码块 (`gum_exec_ctx_obtain_block_for`):**  根据给定的实际地址获取对应的 `GumExecBlock`。如果代码块已存在且是最新的，则直接返回；否则，可能需要重新编译。
14. **重新编译代码块的实现 (`gum_exec_ctx_recompile_block`):**  负责将一个过期的代码块重新编译，并根据情况更新代码块的存储方式，例如当新编译的代码大小超过原有空间时，可能会创建一个新的存储块。
15. **将代码写入 Scratch Slab (`gum_exec_ctx_write_scratch_slab`):**  在重新编译代码块时，先将新的代码写入到一个临时的 Scratch Slab 中，然后再复制到最终的代码块。
16. **编译代码块的核心逻辑 (`gum_exec_ctx_compile_block`):**  使用 `GumArm64Writer` 和 `GumArm64Relocator` 将原始指令转换为插桩后的代码。它会遍历原始指令，并根据需要插入额外的代码（例如事件通知、调用探测等）。
17. **发出编译事件 (`gum_exec_ctx_maybe_emit_compile_event`):**  在代码块编译完成后，如果配置了相应的 sink mask，则会发出一个编译事件。
18. **Stalker 迭代器的核心功能 (`gum_stalker_iterator_next`, `gum_stalker_iterator_keep`):**  `gum_stalker_iterator_next` 用于获取下一条需要处理的指令，`gum_stalker_iterator_keep` 用于处理当前指令，包括可能插入事件代码、进行分支虚拟化等操作。
19. **获取内存访问模式 (`gum_stalker_iterator_get_memory_access`):**  返回当前的内存访问模式，区分是否使用了独占访问指令。
20. **发射各种事件 (`gum_exec_ctx_emit_call_event`, `gum_exec_ctx_emit_ret_event`, `gum_exec_ctx_emit_exec_event`, `gum_exec_ctx_emit_block_event`):**  在代码执行的不同阶段（调用、返回、执行基本块等）发出相应的事件通知。
21. **插入 Callout (`gum_stalker_iterator_put_callout`):**  允许在执行流中插入自定义的 C 代码回调。
22. **调用 Callout 的实际执行 (`gum_stalker_invoke_callout`):**  当执行到插入的 Callout 时，会调用用户提供的回调函数。
23. **插入链式返回 (`gum_stalker_iterator_put_chaining_return`):**  用于实现函数执行完毕后跳回到原始的返回地址，常用于 hook 函数的场景。
24. **获取 Capstone 实例 (`gum_stalker_iterator_get_capstone`):**  提供访问 Capstone 反汇编引擎实例的接口。
25. **写入 Prolog 和 Epilog 代码 (`gum_exec_ctx_write_prolog`, `gum_exec_ctx_write_epilog`):**  在生成的代码块的开头和结尾插入 prolog 和 epilog 代码，用于保存和恢复寄存器等操作。
26. **确保 Inline Helper 可达 (`gum_exec_ctx_ensure_inline_helpers_reachable`):**  确保一些小的辅助函数（例如 prolog, epilog, invalidator）在生成的代码中可以被直接调用。
27. **写入各种类型的 Prolog 和 Epilog Helper 函数 (`gum_exec_ctx_write_minimal_prolog_helper` 等):**  定义了不同类型的 prolog 和 epilog 辅助函数的具体实现，这些函数用于处理寄存器的保存和恢复，以及可能的栈对齐操作。

**与逆向方法的关联及举例说明:**

* **动态代码插桩:** Stalker 的核心功能就是动态地修改目标进程的执行流程，这是逆向工程中常用的技术，用于分析程序行为，例如追踪函数调用、修改函数返回值、记录执行轨迹等。
    * **举例:** 逆向工程师可以使用 Frida 的 JavaScript API 来 hook 一个函数，Stalker 会在函数入口处插入代码，当程序执行到该函数时，Stalker 就会捕获到，并可以执行用户自定义的代码，比如打印函数参数。
* **代码重写:** Stalker 会将原始的代码片段重新编译，并在其中插入额外的指令，这是实现插桩的基础。
    * **举例:** 为了追踪一个函数的执行，Stalker 可能会在函数入口处插入代码来调用一个 Frida 提供的回调函数，并在函数返回前插入另一个回调。
* **控制流劫持:** 通过修改跳转指令的目标地址，Stalker 可以将程序的执行流程引导到插桩的代码中。
    * **举例:** 当程序执行到一个 `call` 指令时，Stalker 可以修改其目标地址，使其先跳转到 Stalker 生成的代码中，执行完插桩逻辑后再跳转回原始目标或新的目标。

**涉及的二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **ARM64 汇编指令:** 代码中大量使用了 ARM64 汇编指令的操作，例如 `ldp`, `stp`, `bl`, `brk` 等。理解这些指令的功能是理解 Stalker 如何进行代码插桩的基础。
    * **举例:** `gum_arm64_writer_put_ldp_reg_reg_reg_offset` 函数用于生成 `ldp` (load pair) 指令，该指令用于从内存中加载一对寄存器的值。这在保存和恢复寄存器状态时非常常见。
* **内存管理:** Stalker 需要管理自己生成的代码和数据的内存区域，使用了 `GumCodeSlab` 等结构来组织这些内存。
    * **举例:** `gum_exec_ctx_add_code_slab` 函数用于添加新的代码 Slab，这意味着 Stalker 需要理解如何在进程的地址空间中分配和管理内存。
* **函数调用约定:**  在插入 hook 代码时，Stalker 需要遵循 ARM64 的函数调用约定，正确传递参数和处理返回值。
    * **举例:** `gum_arm64_writer_put_call_address_with_arguments` 函数在插入 callout 时，需要按照 ARM64 的调用约定设置参数寄存器。
* **页表和内存保护:** `gum_ensure_code_readable` 函数表明 Stalker 需要确保要读取的代码页是可读的，这涉及到操作系统底层的内存保护机制。
* **Linux/Android 进程模型:** Stalker 在目标进程的上下文中运行，需要理解进程的地址空间布局。
* **信号处理:**  `GUM_CODE_INTERRUPTIBLE`  可能与 Stalker 处理中断或信号的方式有关。

**逻辑推理、假设输入与输出:**

* **假设输入:**  Stalker 尝试插桩地址 `0x1000` 处的代码块。该代码块包含一个 `bl` 指令调用地址 `0x2000`。
* **逻辑推理:**
    1. `gum_exec_ctx_obtain_block_for(ctx, 0x1000, ...)` 会被调用以获取 `0x1000` 的代码块。
    2. 如果该代码块之前未被插桩，则会调用 `gum_exec_ctx_compile_block` 进行编译。
    3. 在编译过程中，当遇到 `bl` 指令时，`gum_exec_block_virtualize_branch_insn` 可能会被调用来处理分支。
    4. Stalker 会生成新的代码，当执行到原始的 `bl` 指令时，会先跳转到 Stalker 生成的入口网关 (`GUM_ENTRYGATE (call_imm)`)。
    5. `GUM_ENTRYGATE (call_imm)` 会调用 `gum_exec_ctx_switch_block`。
    6. `gum_exec_ctx_switch_block` 会尝试获取 `0x2000` 的代码块。
* **预期输出:**  Stalker 生成的代码会在 `bl` 指令执行前后插入额外的逻辑，例如记录调用信息、执行用户定义的 hook 代码等。最终，程序可能会跳转到 `0x2000` 或被 hook 改变了目标。

**用户或编程常见的使用错误及举例说明:**

* **不正确的内存管理:** 用户在实现 `GumStalkerCallout` 时，如果分配了内存但忘记释放，可能导致内存泄漏。
    * **举例:** 在一个 callout 中使用 `g_malloc` 分配了缓冲区，但在 callout 函数返回前没有使用 `g_free` 释放。
* **修改了不应该修改的 CPU 上下文:** 用户在 callout 中可能会错误地修改了 CPU 上下文中不应该修改的寄存器，导致程序行为异常。
    * **举例:**  在一个 callout 中，错误地修改了 `cpu_context->pc`，导致程序跳转到错误的地址。
* **在多线程环境中使用非线程安全的操作:**  Stalker 运行在目标进程的上下文中，如果用户在 callout 中使用了非线程安全的操作，可能会导致竞争条件。
* **配置错误的 sink mask:** 用户可能没有配置正确的 sink mask，导致 Stalker 没有捕获到预期的事件。
    * **举例:** 用户想要追踪函数调用，但 sink mask 中没有包含 `GUM_CALL`，导致 call 事件没有被触发。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:**  用户使用 Frida 的 JavaScript API 编写脚本，例如使用 `Interceptor.attach` 或 `Stalker.follow` 来启动 Stalker。
2. **Frida 将脚本注入目标进程:** Frida 将用户的 JavaScript 脚本以及 Frida Agent (包含 frida-gum) 注入到目标进程中。
3. **启动 Stalker:**  用户的脚本调用 `Stalker.follow()` 或在 `Interceptor.attach` 的实现中，会触发 Stalker 的初始化。
4. **执行目标代码:** 目标进程继续执行，当执行到被 Stalker 跟踪的代码区域时。
5. **遇到需要插桩的指令:** 当执行到需要被 Stalker 插桩的指令（例如函数调用、跳转等）时，Stalker 之前生成的入口网关代码会被执行。
6. **进入 `gumstalker-arm64.c`:** 入口网关代码会调用 `gum_exec_ctx_switch_block` 或其他相关的函数，这些函数定义在 `gumstalker-arm64.c` 中，从而进入了您提供的代码片段。

**这是第3部分，共6部分，请归纳一下它的功能:**

这部分代码主要负责 **`GumExecCtx` 的生命周期管理、代码块的管理和切换、以及代码的编译和重写过程中的核心逻辑**。它定义了 Stalker 如何分配和管理内存来存储生成的代码，如何获取和编译需要插桩的代码块，以及如何在执行过程中在不同的代码块之间切换。 它是 Stalker 实现动态插桩功能的核心组成部分，连接了代码的表示（`GumExecBlock`）和实际的执行流程。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能

"""
!= NULL)
  {
    GumCodeSlab * next = (GumCodeSlab *) code_slab->slab.next;
    gum_code_slab_free (code_slab);
    code_slab = next;
  }

  g_object_unref (ctx->sink);
  g_object_unref (ctx->transformer);
  g_clear_object (&ctx->observer);

  gum_arm64_relocator_clear (&ctx->relocator);
  gum_arm64_writer_clear (&ctx->slow_writer);
  gum_arm64_writer_clear (&ctx->code_writer);

  g_object_unref (stalker);

  gum_memory_free (ctx, stalker->ctx_size);
}

static void
gum_exec_ctx_dispose (GumExecCtx * ctx)
{
  GumStalker * stalker = ctx->stalker;
  GumSlab * slab;
  GumExecBlock * block;

  for (slab = &ctx->code_slab->slab; slab != NULL; slab = slab->next)
  {
    gum_stalker_thaw (stalker, gum_slab_start (slab), slab->offset);
  }

  for (slab = &ctx->slow_slab->slab; slab != NULL; slab = slab->next)
  {
    gum_stalker_thaw (stalker, gum_slab_start (slab), slab->offset);
  }

  for (block = ctx->block_list; block != NULL; block = block->next)
  {
    gum_exec_block_clear (block);
  }

#ifdef HAVE_LINUX
  gum_metal_hash_table_unref (ctx->excluded_calls);
#endif
}

static GumCodeSlab *
gum_exec_ctx_add_code_slab (GumExecCtx * ctx,
                            GumCodeSlab * code_slab)
{
  code_slab->slab.next = &ctx->code_slab->slab;
  ctx->code_slab = code_slab;
  return code_slab;
}

static GumSlowSlab *
gum_exec_ctx_add_slow_slab (GumExecCtx * ctx,
                            GumSlowSlab * slow_slab)
{
  slow_slab->slab.next = &ctx->slow_slab->slab;
  ctx->slow_slab = slow_slab;
  return slow_slab;
}

static GumDataSlab *
gum_exec_ctx_add_data_slab (GumExecCtx * ctx,
                            GumDataSlab * data_slab)
{
  data_slab->slab.next = &ctx->data_slab->slab;
  ctx->data_slab = data_slab;
  return data_slab;
}

static void
gum_exec_ctx_compute_code_address_spec (GumExecCtx * ctx,
                                        gsize slab_size,
                                        GumAddressSpec * spec)
{
  GumStalker * stalker = ctx->stalker;

  /* Code must be able to reference ExecCtx fields using 32-bit offsets. */
  spec->near_address = ctx;
  spec->max_distance = G_MAXINT32 - stalker->ctx_size - slab_size;
}

static void
gum_exec_ctx_compute_data_address_spec (GumExecCtx * ctx,
                                        gsize slab_size,
                                        GumAddressSpec * spec)
{
  GumStalker * stalker = ctx->stalker;

  /* Code must be able to reference ExecBlock fields using 32-bit offsets. */
  spec->near_address = ctx->code_slab;
  spec->max_distance = G_MAXINT32 - stalker->code_slab_size_dynamic - slab_size;
}

static gboolean
gum_exec_ctx_maybe_unfollow (GumExecCtx * ctx,
                             gpointer resume_at)
{
  if (g_atomic_int_get (&ctx->state) != GUM_EXEC_CTX_UNFOLLOW_PENDING)
    return FALSE;

  if (ctx->pending_calls > 0)
    return FALSE;

  gum_exec_ctx_unfollow (ctx, resume_at);

  return TRUE;
}

static void
gum_exec_ctx_unfollow (GumExecCtx * ctx,
                       gpointer resume_at)
{
  ctx->current_block = NULL;

  ctx->resume_at = resume_at;

  g_private_set (&gum_stalker_exec_ctx_private, NULL);

  ctx->destroy_pending_since = g_get_monotonic_time ();
  g_atomic_int_set (&ctx->state, GUM_EXEC_CTX_DESTROY_PENDING);
}

static gboolean
gum_exec_ctx_has_executed (GumExecCtx * ctx)
{
  return ctx->resume_at != NULL;
}

static gboolean
gum_exec_ctx_contains (GumExecCtx * ctx,
                       gconstpointer address)
{
  GumSlab * cur = &ctx->code_slab->slab;
  GumSlab * slow_slab = &ctx->slow_slab->slab;

  do
  {
    if ((const guint8 *) address >= cur->data &&
        (const guint8 *) address < (guint8 *) gum_slab_cursor (cur))
    {
      return TRUE;
    }

    cur = cur->next;
  }
  while (cur != NULL);

  do
  {
    if ((const guint8 *) address >= slow_slab->data &&
        (const guint8 *) address < (guint8 *) gum_slab_cursor (slow_slab))
    {
      return TRUE;
    }

    slow_slab = slow_slab->next;
  }
  while (slow_slab != NULL);

  return FALSE;
}

static gboolean
gum_exec_ctx_may_now_backpatch (GumExecCtx * ctx,
                                GumExecBlock * target_block)
{
  if (g_atomic_int_get (&ctx->state) != GUM_EXEC_CTX_ACTIVE)
    return FALSE;

  if ((target_block->flags & GUM_EXEC_BLOCK_ACTIVATION_TARGET) != 0)
    return FALSE;

  if (target_block->recycle_count < ctx->stalker->trust_threshold)
    return FALSE;

  return TRUE;
}

#define GUM_ENTRYGATE(name) \
    gum_exec_ctx_replace_current_block_from_##name
#define GUM_DEFINE_ENTRYGATE(name) \
    static gpointer \
    GUM_ENTRYGATE (name) ( \
        GumExecBlock * block, \
        gpointer start_address, \
        gpointer from_insn) \
    { \
      GumExecCtx * ctx = block->ctx; \
      \
      if (ctx->observer != NULL) \
        gum_stalker_observer_increment_##name (ctx->observer); \
      \
      return gum_exec_ctx_switch_block (ctx, block, start_address, from_insn); \
    }

GUM_DEFINE_ENTRYGATE (call_imm)
GUM_DEFINE_ENTRYGATE (call_reg)
GUM_DEFINE_ENTRYGATE (excluded_call_imm)
GUM_DEFINE_ENTRYGATE (excluded_call_reg)
GUM_DEFINE_ENTRYGATE (ret)

GUM_DEFINE_ENTRYGATE (jmp_imm)
GUM_DEFINE_ENTRYGATE (jmp_reg)

GUM_DEFINE_ENTRYGATE (jmp_cond_cc)
GUM_DEFINE_ENTRYGATE (jmp_cond_cbz)
GUM_DEFINE_ENTRYGATE (jmp_cond_cbnz)
GUM_DEFINE_ENTRYGATE (jmp_cond_tbz)
GUM_DEFINE_ENTRYGATE (jmp_cond_tbnz)

GUM_DEFINE_ENTRYGATE (jmp_continuation)

static gpointer
gum_exec_ctx_switch_block (GumExecCtx * ctx,
                           GumExecBlock * block,
                           gpointer start_address,
                           gpointer from_insn)
{
  if (ctx->observer != NULL)
    gum_stalker_observer_increment_total (ctx->observer);

  if (start_address == gum_unfollow_me_address ||
      start_address == gum_deactivate_address)
  {
    ctx->unfollow_called_while_still_following = TRUE;
    ctx->current_block = NULL;
    ctx->resume_at = start_address;
  }
  else if (start_address == gum_thread_exit_address)
  {
    gum_exec_ctx_unfollow (ctx, start_address);
  }
  else if (gum_exec_ctx_maybe_unfollow (ctx, start_address))
  {
  }
  else if (gum_exec_ctx_contains (ctx, start_address))
  {
    ctx->current_block = NULL;
    ctx->resume_at = start_address;
  }
  else
  {
    ctx->current_block = gum_exec_ctx_obtain_block_for (ctx, start_address,
        &ctx->resume_at);

    if (start_address == ctx->activation_target)
    {
      ctx->activation_target = NULL;
      ctx->current_block->flags |= GUM_EXEC_BLOCK_ACTIVATION_TARGET;
    }

    gum_exec_ctx_maybe_unfollow (ctx, start_address);
  }

  /*
   * When we fetch a block to be executed, before we make use of the
   * code_address, we first call-back to the observer to allow the user to make
   * any modifications to it. We also pass the user the instruction which was
   * executed immediately before the transition as well as the real address of
   * the target for the branch which resulted in this transition.
   *
   * The user can observe or modify the code being written to a given
   * instrumented address by making use of a transformer. This callback gives
   * the user the ability to modify control-flow rather than just the
   * instructions being executed.
   *
   * It should be noted that as well as making an instantaneous change to the
   * control flow, in the event that backpatching is enabled, this will result
   * in any backpatches being modified accordingly. It is therefore expected
   * that if the user is making use of backpatching that any callback should
   * provide a consistent result when called multiple times with the same
   * inputs.
   *
   * Stalker for AArch64, however, prefixes all blocks with:
   *
   *   ldp x16, x17, [sp], #0x90
   *
   * This is necessary since if we must reach the block with an indirect branch
   * (e.g. it is too far away for an immediate branch) then we must clobber a
   * register since AArch64 only has limited range for direct calls. If however,
   * the block can be reached with an immediate branch, then this first
   * instruction is skipped by the backpatcher.
   *
   * This peculiarity may cause issues for integrators which wish to optionally
   * skip a preamble emitted at the start of a block.
   */
  gum_exec_ctx_query_block_switch_callback (ctx, block, start_address,
      from_insn, &ctx->resume_at);

  return ctx->resume_at;
}

static void
gum_exec_ctx_query_block_switch_callback (GumExecCtx * ctx,
                                          GumExecBlock * block,
                                          gpointer start_address,
                                          gpointer from_insn,
                                          gpointer * target)
{
  gpointer from;

  if (ctx->observer == NULL)
    return;

  from = (block != NULL) ? block->real_start : NULL;

  gum_stalker_observer_switch_callback (ctx->observer, from, start_address,
      from_insn, target);
}

static void
gum_exec_ctx_recompile_and_switch_block (GumExecCtx * ctx,
                                         GumExecBlock * block)
{
  const gpointer start_address = block->real_start;

  if (gum_exec_ctx_maybe_unfollow (ctx, start_address))
    return;

  gum_exec_ctx_recompile_block (ctx, block);

  ctx->current_block = block;
  ctx->resume_at = block->code_start;

  if (start_address == ctx->activation_target)
  {
    ctx->activation_target = NULL;
    ctx->current_block->flags |= GUM_EXEC_BLOCK_ACTIVATION_TARGET;
  }

  gum_exec_ctx_maybe_unfollow (ctx, start_address);
}

static GumExecBlock *
gum_exec_ctx_obtain_block_for (GumExecCtx * ctx,
                               gpointer real_address,
                               gpointer * code_address)
{
  GumExecBlock * block;

  gum_spinlock_acquire (&ctx->code_lock);

  block = gum_metal_hash_table_lookup (ctx->mappings, real_address);
  if (block != NULL)
  {
    const gint trust_threshold = ctx->stalker->trust_threshold;
    gboolean still_up_to_date;

    still_up_to_date =
        (trust_threshold >= 0 && block->recycle_count >= trust_threshold) ||
        memcmp (block->real_start, gum_exec_block_get_snapshot_start (block),
            block->real_size) == 0;

    gum_spinlock_release (&ctx->code_lock);

    if (still_up_to_date)
    {
      if (trust_threshold > 0)
        block->recycle_count++;
    }
    else
    {
      gum_exec_ctx_recompile_block (ctx, block);
    }
  }
  else
  {
    block = gum_exec_block_new (ctx);
    block->real_start = real_address;
    gum_exec_block_maybe_inherit_exclusive_access_state (block, block->next);
    gum_exec_ctx_compile_block (ctx, block, real_address, block->code_start,
        GUM_ADDRESS (block->code_start), &block->real_size, &block->code_size,
        &block->slow_size);
    gum_exec_block_commit (block);
    gum_exec_block_propagate_exclusive_access_state (block);

    gum_metal_hash_table_insert (ctx->mappings, real_address, block);

    gum_spinlock_release (&ctx->code_lock);

    gum_exec_ctx_maybe_emit_compile_event (ctx, block);
  }

  *code_address = block->code_start;

  return block;
}

static void
gum_exec_ctx_recompile_block (GumExecCtx * ctx,
                              GumExecBlock * block)
{
  GumStalker * stalker = ctx->stalker;
  guint8 * internal_code = block->code_start;
  guint8 * scratch_base = ctx->scratch_slab->slab.data;
  guint input_size, output_size, slow_size;
  gsize new_block_size, new_snapshot_size;

  gum_spinlock_acquire (&ctx->code_lock);

  gum_exec_ctx_write_scratch_slab (ctx, block, &input_size, &output_size,
      &slow_size);

  new_snapshot_size =
      gum_stalker_snapshot_space_needed_for (stalker, input_size);

  new_block_size = output_size + new_snapshot_size;

  gum_stalker_thaw (stalker, internal_code, block->capacity);

  if (new_block_size <= block->capacity)
  {
    block->real_size = input_size;
    block->code_size = output_size;

    memcpy (internal_code, scratch_base, output_size);
    memcpy (gum_exec_block_get_snapshot_start (block), block->real_start,
        new_snapshot_size);

    gum_stalker_freeze (stalker, internal_code, new_block_size);
  }
  else
  {
    GumExecBlock * storage_block;
    GumArm64Writer * cw = &ctx->code_writer;
    GumAddress external_code_address;

    storage_block = gum_exec_block_new (ctx);
    storage_block->real_start = block->real_start;
    gum_exec_ctx_compile_block (ctx, storage_block, block->real_start,
        storage_block->code_start, GUM_ADDRESS (storage_block->code_start),
        &storage_block->real_size, &storage_block->code_size,
        &storage_block->slow_size);
    gum_exec_block_commit (storage_block);
    block->storage_block = storage_block;

    gum_stalker_thaw (stalker, internal_code, block->capacity);
    gum_arm64_writer_reset (cw, internal_code);

    external_code_address = GUM_ADDRESS (storage_block->code_start);
    if (gum_arm64_writer_can_branch_directly_between (cw,
        GUM_ADDRESS (internal_code), external_code_address))
    {
      gum_arm64_writer_put_b_imm (cw, external_code_address);
      gum_arm64_writer_put_b_imm (cw, external_code_address + sizeof (guint32));
    }
    else
    {
      gconstpointer already_saved = cw->code + 1;

      gum_arm64_writer_put_b_label (cw, already_saved);
      gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
          ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
          GUM_INDEX_PRE_ADJUST);
      gum_arm64_writer_put_label (cw, already_saved);
      gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
          external_code_address);
      gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X16);
    }

    gum_arm64_writer_flush (cw);
    gum_stalker_freeze (stalker, internal_code, block->capacity);
  }

  gum_spinlock_release (&ctx->code_lock);

  gum_exec_ctx_maybe_emit_compile_event (ctx, block);
}

static void
gum_exec_ctx_write_scratch_slab (GumExecCtx * ctx,
                                 GumExecBlock * block,
                                 guint * input_size,
                                 guint * output_size,
                                 guint * slow_size)
{
  GumStalker * stalker = ctx->stalker;
  guint8 * internal_code = block->code_start;
  GumSlowSlab * slow_slab;
  gsize slow_available;
  gpointer slow_start;
  GumCodeSlab * prev_code_slab;
  GumSlowSlab * prev_slow_slab;
  guint8 * scratch_base;

  gum_exec_block_maybe_create_new_code_slabs (ctx);
  gum_exec_block_maybe_create_new_data_slab (ctx);

  slow_slab = ctx->slow_slab;

  slow_available = gum_slab_available (&slow_slab->slab);

  gum_scratch_slab_init (ctx->scratch_slab, GUM_SCRATCH_SLAB_SIZE);

  slow_start = gum_slab_cursor (&slow_slab->slab);
  slow_available = gum_slab_available (&slow_slab->slab);
  gum_stalker_thaw (stalker, slow_start, slow_available);

  if (block->storage_block != NULL)
    gum_exec_block_clear (block->storage_block);
  gum_exec_block_clear (block);

  prev_code_slab = block->code_slab;
  prev_slow_slab = block->slow_slab;

  block->code_slab = ctx->scratch_slab;
  block->slow_slab = ctx->slow_slab;
  block->slow_start = gum_slab_cursor (&slow_slab->slab);
  scratch_base = ctx->scratch_slab->slab.data;
  ctx->scratch_slab->invalidator = prev_code_slab->invalidator;

  gum_exec_ctx_compile_block (ctx, block, block->real_start, scratch_base,
      GUM_ADDRESS (internal_code), input_size, output_size, slow_size);
  gum_slab_reserve (&slow_slab->slab, *slow_size);
  gum_stalker_freeze (stalker, slow_start, *slow_size);

  block->code_slab = prev_code_slab;
  block->slow_slab = prev_slow_slab;
}

static void
gum_exec_ctx_compile_block (GumExecCtx * ctx,
                            GumExecBlock * block,
                            gconstpointer input_code,
                            gpointer output_code,
                            GumAddress output_pc,
                            guint * input_size,
                            guint * output_size,
                            guint * slow_size)
{
  GumArm64Writer * cw = &ctx->code_writer;
  GumArm64Writer * cws = &ctx->slow_writer;
  GumArm64Relocator * rl = &ctx->relocator;
  GumGeneratorContext gc;
  GumStalkerIterator iterator;
  GumStalkerOutput output;
  gboolean all_labels_resolved;
  gboolean all_slow_labels_resolved;

  gum_arm64_writer_reset (cw, output_code);
  cw->pc = output_pc;

  gum_arm64_writer_reset (cws, block->slow_start);
  cws->pc = GUM_ADDRESS (block->slow_start);

  gum_arm64_relocator_reset (rl, input_code, cw);

  gum_ensure_code_readable (input_code, ctx->stalker->page_size);

  gc.instruction = NULL;
  gc.relocator = rl;
  gc.code_writer = cw;
  gc.slow_writer = cws;
  gc.continuation_real_address = NULL;
  gc.opened_prolog = GUM_PROLOG_NONE;

  iterator.exec_context = ctx;
  iterator.exec_block = block;
  iterator.generator_context = &gc;

  iterator.instruction.ci = NULL;
  iterator.instruction.start = NULL;
  iterator.instruction.end = NULL;
  iterator.requirements = GUM_REQUIRE_NOTHING;

  output.writer.arm64 = cw;
  output.encoding = GUM_INSTRUCTION_DEFAULT;

  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE, GUM_INDEX_POST_ADJUST);

  gum_exec_block_maybe_write_call_probe_code (block, &gc);

  ctx->pending_calls++;
  ctx->transform_block_impl (ctx->transformer, &iterator, &output);
  ctx->pending_calls--;

  if (gc.continuation_real_address != NULL)
  {
    GumBranchTarget continue_target = { 0, };

    continue_target.absolute_address = gc.continuation_real_address;
    continue_target.reg = ARM64_REG_INVALID;
    gum_exec_block_write_jmp_transfer_code (block, &continue_target,
        GUM_ENTRYGATE (jmp_continuation), &gc);
  }

  gum_arm64_writer_put_brk_imm (cw, 14);

  all_labels_resolved = gum_arm64_writer_flush (cw);
  if (!all_labels_resolved)
    gum_panic ("Failed to resolve labels");

  all_slow_labels_resolved = gum_arm64_writer_flush (cws);
  if (!all_slow_labels_resolved)
    gum_panic ("Failed to resolve slow labels");

  *input_size = rl->input_cur - rl->input_start;
  *output_size = gum_arm64_writer_offset (cw);
  *slow_size = gum_arm64_writer_offset (cws);
}

static void
gum_exec_ctx_maybe_emit_compile_event (GumExecCtx * ctx,
                                       GumExecBlock * block)
{
  if ((ctx->sink_mask & GUM_COMPILE) != 0)
  {
    GumEvent ev;

    ev.type = GUM_COMPILE;
    ev.compile.start = block->real_start;
    ev.compile.end = block->real_start + block->real_size;

    ctx->sink_process_impl (ctx->sink, &ev, NULL);
  }
}

gboolean
gum_stalker_iterator_next (GumStalkerIterator * self,
                           const cs_insn ** insn)
{
  GumGeneratorContext * gc = self->generator_context;
  GumArm64Relocator * rl = gc->relocator;
  GumInstruction * instruction;
  gboolean is_first_instruction;
  guint n_read;

  instruction = self->generator_context->instruction;
  is_first_instruction = instruction == NULL;

  if (instruction != NULL)
  {
    gboolean skip_implicitly_requested;

    skip_implicitly_requested = rl->outpos != rl->inpos;
    if (skip_implicitly_requested)
    {
      gum_arm64_relocator_skip_one (rl);
    }

    if (gum_stalker_iterator_is_out_of_space (self))
    {
      gc->continuation_real_address = instruction->end;
      return FALSE;
    }

    if (!skip_implicitly_requested && gum_arm64_relocator_eob (rl))
      return FALSE;
  }

  instruction = &self->instruction;

  n_read = gum_arm64_relocator_read_one (rl, &instruction->ci);
  if (n_read == 0)
    return FALSE;

  instruction->start = GSIZE_TO_POINTER (instruction->ci->address);
  instruction->end = instruction->start + instruction->ci->size;

  self->generator_context->instruction = instruction;

  if (is_first_instruction &&
     (self->exec_context->sink_mask & GUM_BLOCK) != 0 &&
     (self->exec_block->flags & GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS) == 0)
  {
    gum_exec_block_write_block_event_code (self->exec_block, gc,
        GUM_CODE_INTERRUPTIBLE);
  }

  if (insn != NULL)
    *insn = instruction->ci;

  return TRUE;
}

static gboolean
gum_stalker_iterator_is_out_of_space (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumSlab * slab = &block->code_slab->slab;
  gsize capacity, snapshot_size;

  capacity = (guint8 *) gum_slab_end (slab) -
      (guint8 *) gum_arm64_writer_cur (self->generator_context->code_writer);

  snapshot_size = gum_stalker_snapshot_space_needed_for (
      self->exec_context->stalker,
      self->generator_context->instruction->end - block->real_start);

  return capacity < GUM_EXEC_BLOCK_MIN_CAPACITY + snapshot_size;
}

void
gum_stalker_iterator_keep (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  GumArm64Relocator * rl = gc->relocator;
  const cs_insn * insn = gc->instruction->ci;
  GumVirtualizationRequirements requirements;

  requirements = GUM_REQUIRE_NOTHING;

  switch (insn->id)
  {
    case ARM64_INS_LDAXR:
    case ARM64_INS_LDAXP:
    case ARM64_INS_LDAXRB:
    case ARM64_INS_LDAXRH:
    case ARM64_INS_LDXR:
    case ARM64_INS_LDXP:
    case ARM64_INS_LDXRB:
    case ARM64_INS_LDXRH:
      block->flags |= GUM_EXEC_BLOCK_HAS_EXCLUSIVE_LOAD;
      break;
    case ARM64_INS_STXR:
    case ARM64_INS_STXP:
    case ARM64_INS_STXRB:
    case ARM64_INS_STXRH:
    case ARM64_INS_STLXR:
    case ARM64_INS_STLXP:
    case ARM64_INS_STLXRB:
    case ARM64_INS_STLXRH:
      block->flags |= GUM_EXEC_BLOCK_HAS_EXCLUSIVE_STORE;
      break;
    default:
      break;
  }

  if ((self->exec_context->sink_mask & GUM_EXEC) != 0 &&
      (block->flags & GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS) == 0)
  {
    gum_exec_block_write_exec_event_code (block, gc, GUM_CODE_INTERRUPTIBLE);
  }

  switch (insn->id)
  {
    case ARM64_INS_B:
    case ARM64_INS_BR:
    case ARM64_INS_BRAA:
    case ARM64_INS_BRAAZ:
    case ARM64_INS_BRAB:
    case ARM64_INS_BRABZ:
    case ARM64_INS_BL:
    case ARM64_INS_BLR:
    case ARM64_INS_BLRAA:
    case ARM64_INS_BLRAAZ:
    case ARM64_INS_BLRAB:
    case ARM64_INS_BLRABZ:
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
      requirements = gum_exec_block_virtualize_branch_insn (block, gc);
      break;
    case ARM64_INS_RET:
    case ARM64_INS_RETAA:
    case ARM64_INS_RETAB:
      requirements = gum_exec_block_virtualize_ret_insn (block, gc);
      break;
    case ARM64_INS_SVC:
      requirements = gum_exec_block_virtualize_sysenter_insn (block, gc);
      break;
    case ARM64_INS_SMC:
    case ARM64_INS_HVC:
      g_assert_not_reached ();
      break;
    default:
      requirements = GUM_REQUIRE_RELOCATION;
  }

  gum_exec_block_close_prolog (block, gc, gc->code_writer);

  if ((requirements & GUM_REQUIRE_RELOCATION) != 0)
    gum_arm64_relocator_write_one (rl);

  self->requirements = requirements;
}

GumMemoryAccess
gum_stalker_iterator_get_memory_access (GumStalkerIterator * self)
{
  return ((self->exec_block->flags & GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS) != 0)
      ? GUM_MEMORY_ACCESS_EXCLUSIVE
      : GUM_MEMORY_ACCESS_OPEN;
}

static void
gum_exec_ctx_emit_call_event (GumExecCtx * ctx,
                              gpointer location,
                              gpointer target,
                              GumCpuContext * cpu_context)
{
  GumEvent ev;
  GumCallEvent * call = &ev.call;

  ev.type = GUM_CALL;

  call->location = location;
  call->target = target;
  call->depth = ctx->depth;

  cpu_context->pc = GPOINTER_TO_SIZE (location);

  ctx->sink_process_impl (ctx->sink, &ev, cpu_context);
}

static void
gum_exec_ctx_emit_ret_event (GumExecCtx * ctx,
                             gpointer location,
                             gpointer target,
                             GumCpuContext * cpu_context)
{
  GumEvent ev;
  GumRetEvent * ret = &ev.ret;

  ev.type = GUM_RET;

  ret->location = location;
  ret->target = target;
  ret->depth = ctx->depth;

  cpu_context->pc = GPOINTER_TO_SIZE (location);

  ctx->sink_process_impl (ctx->sink, &ev, cpu_context);
}

static void
gum_exec_ctx_emit_exec_event (GumExecCtx * ctx,
                              gpointer location,
                              GumCpuContext * cpu_context)
{
  GumEvent ev;
  GumExecEvent * exec = &ev.exec;

  ev.type = GUM_EXEC;

  exec->location = location;

  cpu_context->pc = GPOINTER_TO_SIZE (location);

  ctx->sink_process_impl (ctx->sink, &ev, cpu_context);
}

static void
gum_exec_ctx_emit_block_event (GumExecCtx * ctx,
                               const GumExecBlock * block,
                               GumCpuContext * cpu_context)
{
  GumEvent ev;
  GumBlockEvent * bev = &ev.block;

  ev.type = GUM_BLOCK;

  bev->start = block->real_start;
  bev->end = block->real_start + block->real_size;

  cpu_context->pc = GPOINTER_TO_SIZE (block->real_start);

  ctx->sink_process_impl (ctx->sink, &ev, cpu_context);
}

void
gum_stalker_iterator_put_callout (GumStalkerIterator * self,
                                  GumStalkerCallout callout,
                                  gpointer data,
                                  GDestroyNotify data_destroy)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  GumArm64Writer * cw = gc->code_writer;
  GumCalloutEntry entry;
  GumAddress entry_address;

  entry.callout = callout;
  entry.data = data;
  entry.data_destroy = data_destroy;
  entry.pc = gc->instruction->start;
  entry.exec_context = self->exec_context;
  entry.next = gum_exec_block_get_last_callout_entry (block);
  gum_exec_block_write_inline_data (cw, &entry, sizeof (entry), &entry_address);

  gum_exec_block_set_last_callout_entry (block,
      GSIZE_TO_POINTER (entry_address));

  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, gc->code_writer);
  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_stalker_invoke_callout), 2,
      GUM_ARG_ADDRESS, entry_address,
      GUM_ARG_REGISTER, ARM64_REG_X20);
  gum_exec_block_close_prolog (block, gc, gc->code_writer);
}

static void
gum_stalker_invoke_callout (GumCalloutEntry * entry,
                            GumCpuContext * cpu_context)
{
  GumExecCtx * ec = entry->exec_context;

  cpu_context->pc = GPOINTER_TO_SIZE (entry->pc);

  ec->pending_calls++;
  entry->callout (cpu_context, entry->data);
  ec->pending_calls--;
}

void
gum_stalker_iterator_put_chaining_return (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;

  if ((block->ctx->sink_mask & GUM_RET) != 0)
    gum_exec_block_write_ret_event_code (block, gc, GUM_CODE_INTERRUPTIBLE);

  gum_exec_block_write_chaining_return_code (block, gc, ARM64_REG_X30);
}

csh
gum_stalker_iterator_get_capstone (GumStalkerIterator * self)
{
  return self->exec_context->relocator.capstone;
}

/*
 * Note that as well as providing a GumArm64Writer to the functions for writing
 * a prolog or epilog, we must also provide a parameter indicating whether it is
 * being written to the code (fast) or slow slabs. This is necessary since we
 * have a separate copy of these inline helpers in each slab to mitigate the
 * issue of AArch64 not being able to make immediate branches larger than a
 * 28-bit signed offset. Note that we cannot provide the GeneratorContext here
 * since not all places where such a prolog or epilog is written is provided
 * with one.
 */
static void
gum_exec_ctx_write_prolog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumArm64Writer * cw)
{
  gpointer helper;

  helper = (type == GUM_PROLOG_MINIMAL)
      ? ctx->last_prolog_minimal
      : ctx->last_prolog_full;

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X19,
      ARM64_REG_LR, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (helper));
}

static void
gum_exec_ctx_write_epilog (GumExecCtx * ctx,
                           GumPrologType type,
                           GumArm64Writer * cw)
{
  gpointer helper;

  helper = (type == GUM_PROLOG_MINIMAL)
      ? ctx->last_epilog_minimal
      : ctx->last_epilog_full;

  gum_arm64_writer_put_bl_imm (cw, GUM_ADDRESS (helper));
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X19,
      ARM64_REG_X20, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
}

static void
gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx)
{
  GumSlab * code_slab = &ctx->code_slab->slab;
  GumSlab * slow_slab = &ctx->slow_slab->slab;
  GumArm64Writer * cw = &ctx->code_writer;

  gum_exec_ctx_ensure_helper_reachable (ctx, code_slab, slow_slab, cw,
      &ctx->last_prolog_minimal, gum_exec_ctx_write_minimal_prolog_helper);
  gum_exec_ctx_ensure_helper_reachable (ctx, code_slab, slow_slab, cw,
      &ctx->last_epilog_minimal, gum_exec_ctx_write_minimal_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, code_slab, slow_slab, cw,
      &ctx->last_prolog_full, gum_exec_ctx_write_full_prolog_helper);
  gum_exec_ctx_ensure_helper_reachable (ctx, code_slab, slow_slab, cw,
      &ctx->last_epilog_full, gum_exec_ctx_write_full_epilog_helper);

  gum_exec_ctx_ensure_helper_reachable (ctx, code_slab, slow_slab, cw,
      &ctx->last_invalidator, gum_exec_ctx_write_invalidator);
  ctx->code_slab->invalidator = ctx->last_invalidator;
  ctx->slow_slab->invalidator = ctx->last_invalidator;
}

static void
gum_exec_ctx_write_minimal_prolog_helper (GumExecCtx * ctx,
                                          GumArm64Writer * cw)
{
  gum_exec_ctx_write_prolog_helper (ctx, GUM_PROLOG_MINIMAL, cw);
}

static void
gum_exec_ctx_write_minimal_epilog_helper (GumExecCtx * ctx,
                                          GumArm64Writer * cw)
{
  gum_exec_ctx_write_epilog_helper (ctx, GUM_PROLOG_MINIMAL, cw);
}

static void
gum_exec_ctx_write_full_prolog_helper (GumExecCtx * ctx,
                                       GumArm64Writer * cw)
{
  gum_exec_ctx_write_prolog_helper (ctx, GUM_PROLOG_FULL, cw);
}

static void
gum_exec_ctx_write_full_epilog_helper (GumExecCtx * ctx,
                                       GumArm64Writer * cw)
{
  gum_exec_ctx_write_epilog_helper (ctx, GUM_PROLOG_FULL, cw);
}

static void
gum_exec_ctx_write_prolog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumArm64Writer * cw)
{
  gint i;

  /* X19 and LR have been pushed by our caller */

  /*
   * Our prolog and epilog code makes extensive use of the stack to store and
   * restore registers. However, on AArch64, the stack pointer must be aligned
   * to a 16-byte boundary when it is used to access memory. One anti-Frida
   * technique observed in the wild has been to deliberately misalign the stack
   * pointer to violate this assumption and cause Stalker to attempt to access
   * data on a misaligned stack.
   *
   * In order to mitigate this, we use another register as a proxy for the stack
   * pointer and use this to perform our loads and stores. Since the other
   * registers have no alignment requirements this avoids the issue. We still
   * have the issue that this proxy stack register needs to be saved somewhere
   * so that it can be restored when control returns to the target. We therefore
   * accept that this initial store must be carried out using the stack pointer
   * and will therefore incur an exception.
   *
   * Accordingly, we install an exception handler to cope with these exceptions
   * and this exception handler simply emulates the instruction in question.
   * Since we have minimized the amount of misaligned stack usage, we only have
   * a handful of instructions which we need to emulate and these can therefore
   * be whitelisted.
   *
   * As part of the prolog code, the stack is correctly aligned once the prolog
   * is opened (such that if we call any C code from within the Stalker engine
   * itself, it will take place with the stack aligned and hence we won't need
   * to emulate additional, compiler dependent, instructions). The stack pointer
   * is restored to its original (possibly misaligned) value once the epilogue
   * is executed.
   *
   * Note that in order to simplify this code, we also ensure that both the FULL
   * and MINIMAL prologs both store the register state in the GumCpuContext
   * format, although in the case of the MINIMAL context, it is not necessary to
   * save a number of the registers and these can simply be skipped by adjusting
   * the proxy stack pointer.
   */
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_SP);

  if (type == GUM_PROLOG_MINIMAL)
  {
    /* GumCpuContext.v[0:8] plus padding for v[8:32] */
    for (i = 6; i != -2; i -= 2)
    {
  
"""


```