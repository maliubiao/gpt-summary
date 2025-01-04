Response:
The user wants to understand the functionality of the provided C code snippet from `gumstalker-x86.c`, a part of the Frida dynamic instrumentation tool.

I need to:

1. **List the functionalities** present in the code.
2. **Explain the relation to reverse engineering** with examples.
3. **Explain the relation to binary internals, Linux/Android kernel and framework** with examples.
4. **Identify logical reasoning** and provide input/output examples.
5. **Point out common user/programming errors** with examples.
6. **Describe the user operations** leading to this code execution for debugging.
7. **Summarize the overall functionality** of this specific part of the code.

The code mainly deals with backpatching and virtualizing branch instructions within the Frida stalker. It involves modifying the generated code on the fly to handle control flow changes.

**Functionalities:**

- Backpatching conditional and unconditional jumps.
- Handling inline caches for performance optimization.
- Virtualizing various branch instructions (CALL, JMP, RET, SYSCALL, SYSENTER, INT).
- Special handling for direct jumps to PLT/GOT entries.
- Managing the call stack depth.
- Dealing with WOW64 transitions (32-bit code on 64-bit Windows).
- Handling Linux system calls, including special considerations for `clone`.

Let's break down each requirement with the provided code.
这是文件 `frida/subprojects/frida-gum/gum/backend-x86/gumstalker-x86.c` 的一部分源代码，它属于 Frida 动态插桩工具。这部分代码主要负责在 x86 架构下，处理程序执行过程中的控制流转移指令（如跳转和调用），并进行相应的插桩操作。

以下是代码段中列出的功能：

1. **`gum_exec_block_backpatch_conditional_branch`**:  用于回填条件跳转指令。当程序执行到一个条件跳转指令时，Frida Stalker 会根据实际的执行路径（是否跳转）来修改之前生成的代码块，以便后续执行能够正确跳转到目标地址。

2. **`gum_exec_block_get_adjacent`**:  获取给定代码块在内存中紧邻的下一个代码块。这用于优化条件跳转，如果未跳转的分支紧跟着当前块，可以直接填充 NOP 指令，避免额外的跳转指令。

3. **`gum_exec_block_backpatch_unconditional_jmp`**: 用于回填无条件跳转指令。类似于条件跳转，但不需要判断条件，直接修改跳转目标。

4. **`gum_exec_block_is_adjacent`**: 判断给定的目标地址是否紧邻着 `from` 代码块。

5. **`gum_exec_block_backpatch_inline_cache`**:  用于回填内联缓存。内联缓存用于存储最近执行的代码块的目标地址，以加速后续的跳转。当一个新的目标块被执行到时，会更新内联缓存。

6. **`gum_exec_block_virtualize_branch_insn`**:  虚拟化分支指令。这是核心功能，它根据不同的分支指令类型（CALL, JMP 等）生成相应的插桩代码，以便在执行到这些指令时，Frida 可以拦截并执行自定义的操作。

7. **`gum_exec_block_is_direct_jmp_to_plt_got`**:  判断是否是直接跳转到 PLT (Procedure Linkage Table) 或 GOT (Global Offset Table) 表项。这通常发生在调用共享库函数时。

8. **`gum_exec_ctx_get_plt_got_ranges`**, **`gum_exec_ctx_deinit_plt_got_ranges`**, **`gum_exec_ctx_find_plt_got`**, **`gum_exec_check_elf_section`**:  这些函数用于获取 PLT 和 GOT 表的内存范围。在 Linux 等系统中，共享库函数的调用会通过这些表进行间接跳转。

9. **`gum_exec_block_handle_direct_jmp_to_plt_got`**:  处理直接跳转到 PLT/GOT 表项的情况。Frida 会拦截这种跳转，并进行相应的处理，例如在插桩代码中直接调用目标函数。

10. **`gum_exec_block_virtualize_ret_insn`**: 虚拟化返回指令 (RET)。当执行到 RET 指令时，Frida 可以插入代码来监控或修改返回值等。

11. **`gum_exec_block_write_adjust_depth`**:  调整函数调用深度。Frida 可以跟踪函数调用栈的深度，用于分析程序行为。

12. **`gum_exec_block_virtualize_sysenter_insn`**: 虚拟化 `sysenter` 指令。`sysenter` 是一种快速的系统调用指令，Frida 需要特殊处理以拦截系统调用。

13. **`gum_exec_block_virtualize_syscall_insn`**: 虚拟化 `syscall` 指令。这是另一种系统调用指令，需要类似 `sysenter` 的处理。

14. **`gum_exec_block_virtualize_int_insn`**: 虚拟化 `int` 指令，特别是 `int 0x80`，这是 Linux 系统中常用的系统调用方式。

15. **`gum_exec_block_virtualize_linux_syscall`**:  专门处理 Linux 系统调用（包括 `syscall` 和 `int 0x80`）。它会检查是否是 `clone` 系统调用，并进行特殊处理以确保子进程的正确插桩。

16. **`gum_exec_ctx_write_int80_helper`**, **`gum_exec_ctx_write_syscall_helper`**, **`gum_exec_ctx_write_aligned_syscall`**: 这些辅助函数用于生成处理系统调用的插桩代码，特别是针对 `clone` 系统调用，需要将其放置在单独的内存页上以避免竞态条件。

17. **`gum_exec_block_virtualize_wow64_transition`**:  处理 WOW64 转换（在 64 位 Windows 上执行 32 位代码）。当 32 位代码调用 64 位代码时，需要进行特殊的转换处理。

18. **`gum_exec_block_write_call_invoke_code`**:  生成处理 `CALL` 指令的插桩代码。它会处理内联缓存、静态回填等优化。

**与逆向方法的关系及举例说明：**

这段代码是 Frida 动态插桩的核心组成部分，它通过在程序运行时修改其指令流来实现监控和控制程序执行的目的，这正是动态逆向分析的关键技术。

* **代码插桩 (Code Instrumentation)**:  Frida 通过在目标程序的关键位置插入额外的代码（如跳转到 Frida 的处理函数）来截获程序的执行流程。例如，`gum_exec_block_virtualize_branch_insn` 函数会为 `CALL` 指令插入代码，使得在调用发生时，Frida 可以记录调用信息、修改参数或返回值。

* **控制流跟踪 (Control Flow Tracing)**:  `gum_exec_block_backpatch_conditional_branch` 和 `gum_exec_block_backpatch_unconditional_jmp` 确保 Frida 能够准确地跟踪程序的执行路径，即使程序中有复杂的跳转逻辑。

* **API Hooking**: 当程序调用系统 API 或共享库函数时（例如通过 PLT/GOT 表），`gum_exec_block_handle_direct_jmp_to_plt_got` 允许 Frida 拦截这些调用，执行自定义的 Hook 函数，从而监控或修改 API 的行为。例如，可以 Hook `open` 系统调用来记录程序打开的文件。

* **系统调用监控 (System Call Monitoring)**: `gum_exec_block_virtualize_syscall_insn` 和相关的函数使得 Frida 能够拦截程序发起的系统调用，获取系统调用的参数和返回值。这对于理解程序与操作系统之间的交互至关重要。

**涉及到二进制底层、Linux/Android 内核及框架的知识及举例说明：**

* **x86 指令集**: 代码中使用了 `gum_x86_writer_*` 系列函数来生成 x86 汇编指令，例如 `gum_x86_writer_put_jcc_near` 用于生成条件跳转指令。理解 x86 指令的编码格式和行为是编写此类代码的基础。

* **内存管理**:  `gum_stalker_thaw` 和 `gum_stalker_freeze` 涉及到对内存页的读写执行权限的修改，这是操作系统内存管理的核心概念。Frida 需要确保插桩代码所在的内存页具有执行权限。

* **PLT 和 GOT**: `gum_exec_block_is_direct_jmp_to_plt_got` 和相关函数处理了 Linux 等系统中共享库调用的实现机制。理解 PLT 和 GOT 的作用以及动态链接的过程对于正确 Hook 共享库函数至关重要。

* **系统调用机制**:  `gum_exec_block_virtualize_syscall_insn` 等函数处理了系统调用的底层实现，包括 `syscall`、`sysenter` 和 `int 0x80` 等不同的系统调用指令。在不同的操作系统和架构上，系统调用的实现方式有所不同。

* **`clone` 系统调用**:  代码中特别提到了 `clone` 系统调用，这是 Linux 中创建进程或线程的关键系统调用。由于子进程会复制父进程的内存空间，Frida 需要特殊处理以确保子进程也能被正确插桩。`gum_exec_ctx_write_aligned_syscall` 将 `clone` 指令放置在独立的内存页上，以避免父进程修改页属性导致子进程执行异常。

* **WOW64**: `gum_exec_block_virtualize_wow64_transition` 处理了 32 位程序在 64 位 Windows 系统上的运行情况，涉及到 32 位和 64 位代码之间的切换。

**如果做了逻辑推理，请给出假设输入与输出：**

假设程序执行到一个条件跳转指令 `jz 0x401050`，并且 Frida 已经开始跟踪执行。

* **假设输入**:
    * `from`: 指向当前代码块的 `GumExecBlock` 结构。
    * `block`: 指向目标代码块 (地址 `0x401050`) 的 `GumExecBlock` 结构。
    * `from_insn`: 指向 `jz` 指令的地址。
    * `id`: `X86_INS_JZ`，表示这是一个 `jz` 指令。
    * `target_taken`: 目标跳转地址 `0x401050`。
    * `code_start`:  Frida 为当前代码块分配的用于存放插桩代码的起始地址。
    * `code_max_size`:  分配给当前代码块的插桩代码的最大大小。

* **逻辑推理**:
    1. `gum_exec_ctx_query_block_switch_callback` 可能会被调用，以允许用户自定义的回调函数在跳转发生前执行。
    2. `gum_x86_writer_put_jcc_near` 会生成一个条件跳转指令，其跳转目标取决于 `target_taken`。
    3. 如果未跳转的分支紧邻当前块，则会填充 NOP 指令。

* **假设输出 (生成的插桩代码)**:
    可能会生成如下形式的汇编代码：
    ```assembly
    jz <地址A>  ; 如果条件成立，跳转到 Frida 生成的代码处理目标块
    nop         ; 如果未跳转，并且下一个块紧邻，则填充 NOP
    nop
    ...
    <地址A>:
    jmp <地址B>  ; 跳转到 Frida 生成的用于处理目标块的代码
    ```
    其中，`<地址B>` 是 Frida 为目标代码块生成的插桩代码的起始地址。

**如果涉及用户或者编程常见的使用错误，请举例说明：**

* **忘记调用 `gum_stalker_begin` 或 `gum_stalker_end`**: 用户在使用 Frida Stalker 时，必须将需要跟踪的代码段包含在 `gum_stalker_begin` 和 `gum_stalker_end` 之间。如果忘记调用，Stalker 将不会拦截相应的执行流程。

* **插桩代码过大导致溢出**:  Frida 为每个代码块分配了有限的内存空间用于存放插桩代码。如果用户插入的 Hook 函数逻辑过于复杂，生成的插桩代码超过了分配的空间 (`code_max_size`)，会导致程序崩溃或行为异常。`g_assert (gum_x86_writer_offset (cw) <= code_max_size)` 用于进行断言检查，帮助开发者发现此类问题。

* **错误的 Hook 函数签名**:  如果用户自定义的 Hook 函数的参数或返回值类型与被 Hook 的函数不匹配，可能会导致栈破坏或其他未定义的行为。

* **在不安全的时间修改内存**: 在 Frida Stalker 正在修改代码块时，如果其他线程也在尝试执行同一块代码，可能会导致竞态条件和崩溃。代码中的 `gum_spinlock_acquire` 和 `gum_spinlock_release` 用于保护代码块的修改操作。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本**: 用户使用 Python 或 JavaScript 编写 Frida 脚本，指定要附加的目标进程和需要 Hook 的函数或代码地址。
2. **Frida 连接到目标进程**: Frida Agent (Gum) 被注入到目标进程中。
3. **用户启用 Stalker**: 脚本中调用 `Stalker.follow()` 或类似的方法启动 Stalker，开始跟踪指定线程的执行。
4. **程序执行到分支指令**: 当目标进程的被跟踪线程执行到条件跳转、无条件跳转、调用或返回等指令时，CPU 会尝试执行这些指令。
5. **Stalker 拦截执行**: Frida Stalker 在执行这些分支指令之前或之后，会拦截执行流程。
6. **调用 `gum_exec_block_virtualize_branch_insn`**: Stalker 会分析当前指令，并调用 `gum_exec_block_virtualize_branch_insn` 或相关的函数来生成插桩代码，以处理控制流的转移。
7. **回填插桩代码**:  `gum_exec_block_backpatch_*` 系列函数会被调用，根据实际的执行情况回填或修改之前生成的插桩代码，例如更新跳转目标地址。

作为调试线索，如果程序在执行分支指令附近崩溃，可以检查以下内容：

* **Stalker 是否正确跟踪了执行流**: 检查 Frida 的日志输出，确认 Stalker 是否按预期拦截了分支指令。
* **插桩代码是否正确生成**:  可以使用 Frida 的调试功能查看生成的插桩代码，确认是否有语法错误或逻辑错误。
* **内存访问冲突**:  检查是否因为插桩代码尝试访问无效的内存地址导致崩溃。
* **竞态条件**:  如果多线程环境下出现问题，需要考虑是否存在竞态条件，例如多个线程同时尝试修改同一块代码。

**归纳一下它的功能（第5部分，共7部分）：**

这部分代码是 Frida Stalker 在 x86 架构下处理程序控制流转移指令的核心逻辑。它负责在程序执行到分支指令时，动态地生成和修改插桩代码，以便 Frida 能够跟踪执行路径、拦截函数调用和系统调用，并执行用户自定义的操作。其主要功能是确保 Frida 能够透明地监控和控制目标程序的执行流程，为动态逆向分析提供基础支持。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-x86/gumstalker-x86.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共7部分，请归纳一下它的功能

"""
* needed, if the instrumented block for the not taken branch is immediately
   * adjacent, we can simply fill remainder of the block with NOPs to avoid the
   * additional JMP for that not taken branch of execution too.
   */

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (ctx->stalker, code_start, code_max_size);

  gum_x86_writer_reset (cw, code_start);

  gum_exec_ctx_query_block_switch_callback (ctx, from, block->real_start,
      from_insn, &target_taken);

  g_assert (opened_prolog == GUM_PROLOG_NONE);

  gum_x86_writer_put_jcc_near (cw, id, target_taken, GUM_NO_HINT);

  next_block = gum_exec_block_get_adjacent (from);
  if (next_block != NULL)
  {
    gpointer target_not_taken = next_block->code_start;

    gum_exec_ctx_query_block_switch_callback (ctx, from, next_block->real_start,
        from_insn, &target_not_taken);

    if (gum_exec_block_is_adjacent (target_not_taken, from))
    {
      gsize remaining = code_max_size - gum_x86_writer_offset (cw);
      gum_x86_writer_put_nop_padding (cw, remaining);
    }
  }

  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= code_max_size);
  gum_stalker_freeze (ctx->stalker, code_start, code_max_size);

  gum_spinlock_release (&ctx->code_lock);
}

static GumExecBlock *
gum_exec_block_get_adjacent (GumExecBlock * from)
{
  gpointer real_address = from->real_start + from->real_size;

  return gum_metal_hash_table_lookup (from->ctx->mappings, real_address);
}

static void
gum_exec_block_backpatch_unconditional_jmp (GumExecBlock * block,
                                            GumExecBlock * from,
                                            gpointer from_insn,
                                            gboolean is_eob,
                                            gsize code_offset,
                                            GumPrologType opened_prolog)
{
  GumExecCtx * ctx = block->ctx;
  guint8 * code_start = from->code_start + code_offset;
  const gsize code_max_size = from->code_size - code_offset;
  GumX86Writer * cw = &ctx->code_writer;
  gpointer target = block->code_start;

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (ctx->stalker, code_start, code_max_size);

  gum_x86_writer_reset (cw, code_start);

  gum_exec_ctx_query_block_switch_callback (ctx, from, block->real_start,
      from_insn, &target);

  if (opened_prolog != GUM_PROLOG_NONE)
  {
    gum_exec_ctx_write_epilog (block->ctx, opened_prolog, cw);
  }

  if (is_eob && gum_exec_block_is_adjacent (target, from))
  {
    gsize remaining = code_max_size - gum_x86_writer_offset (cw);
    gum_x86_writer_put_nop_padding (cw, remaining);
  }
  else
  {
    gum_x86_writer_put_jmp_address (cw, GUM_ADDRESS (target));
  }

  gum_x86_writer_flush (cw);
  g_assert (gum_x86_writer_offset (cw) <= code_max_size);
  gum_stalker_freeze (ctx->stalker, code_start, code_max_size);

  gum_spinlock_release (&ctx->code_lock);
}

static gboolean
gum_exec_block_is_adjacent (gpointer target,
                            GumExecBlock * from)
{
  if (from->code_start + from->code_size != target)
    return FALSE;

  return TRUE;
}

static void
gum_exec_block_backpatch_inline_cache (GumExecBlock * block,
                                       GumExecBlock * from,
                                       gpointer from_insn)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  gpointer target;
  GumIcEntry * ic_entries;
  guint num_ic_entries, i;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;
  if (!gum_exec_ctx_may_now_backpatch (ctx, block))
    return;

  target = block->code_start;
  gum_exec_ctx_query_block_switch_callback (ctx, from, block->real_start,
      from_insn, &target);

  ic_entries = from->ic_entries;
  num_ic_entries = ctx->stalker->ic_entries;

  for (i = 0; i != num_ic_entries; i++)
  {
    if (ic_entries[i].real_start == block->real_start)
      return;
  }

  gum_spinlock_acquire (&ctx->code_lock);

  /*
   * Shift all of the entries in the inline cache down one space and insert
   * our new entry at the beginning. If the inline cache is full, then the last
   * entry in the list is effectively removed.
   */
  memmove (&ic_entries[1], &ic_entries[0],
      (num_ic_entries - 1) * sizeof (GumIcEntry));

  ic_entries[0].real_start = block->real_start;
  ic_entries[0].code_start = target;

  gum_spinlock_release (&ctx->code_lock);

  if (ctx->observer != NULL)
  {
    GumBackpatch p;

    p.type = GUM_BACKPATCH_INLINE_CACHE;
    p.to = block->real_start;
    p.from = from->real_start;
    p.from_insn = from_insn;

    gum_stalker_observer_notify_backpatch (ctx->observer, &p, sizeof (p));
  }
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_branch_insn (GumExecBlock * block,
                                       GumGeneratorContext * gc)
{
  GumExecCtx * ctx = block->ctx;
  GumInstruction * insn = gc->instruction;
  GumX86Writer * cw = gc->code_writer;
  gboolean is_conditional;
  cs_x86 * x86 = &insn->ci->detail->x86;
  cs_x86_op * op = &x86->operands[0];
  GumBranchTarget target = { 0, };

  is_conditional =
      (insn->ci->id != X86_INS_CALL && insn->ci->id != X86_INS_JMP);

  target.origin_ip = insn->end;

  if (op->type == X86_OP_IMM)
  {
    target.absolute_address = GSIZE_TO_POINTER (op->imm);
    target.is_indirect = FALSE;
    target.pfx_seg = X86_REG_INVALID;
    target.base = X86_REG_INVALID;
    target.index = X86_REG_INVALID;
    target.scale = 0;
  }
  else if (op->type == X86_OP_MEM)
  {
#if GLIB_SIZEOF_VOID_P == 4 && defined (HAVE_WINDOWS)
    if (op->mem.segment == X86_REG_INVALID &&
        op->mem.base == X86_REG_INVALID &&
        op->mem.index == X86_REG_INVALID)
    {
      GArray * impls = ctx->stalker->wow_transition_impls;
      guint i;

      for (i = 0; i != impls->len; i++)
      {
        gpointer impl = g_array_index (impls, gpointer, i);

        if (GSIZE_TO_POINTER (op->mem.disp) == impl)
          return gum_exec_block_virtualize_wow64_transition (block, gc, impl);
      }
    }
#endif

#ifdef HAVE_WINDOWS
    /* Can't follow WoW64 */
    if (op->mem.segment == X86_REG_FS && op->mem.disp == 0xc0)
      return GUM_REQUIRE_SINGLE_STEP;
#endif

    if (op->mem.base == X86_REG_INVALID && op->mem.index == X86_REG_INVALID)
      target.absolute_address = GSIZE_TO_POINTER (op->mem.disp);
    else
      target.relative_offset = op->mem.disp;

    target.is_indirect = TRUE;
    target.pfx_seg = op->mem.segment;
    target.base = op->mem.base;
    target.index = op->mem.index;
    target.scale = op->mem.scale;
  }
  else if (op->type == X86_OP_REG)
  {
    target.is_indirect = FALSE;
    target.pfx_seg = X86_REG_INVALID;
    target.base = op->reg;
    target.index = X86_REG_INVALID;
    target.scale = 0;
  }
  else
  {
    g_assert_not_reached ();
  }

  if (insn->ci->id == X86_INS_CALL)
  {
    gboolean target_is_excluded = FALSE;

    if ((ctx->sink_mask & GUM_CALL) != 0)
    {
      gum_exec_block_write_call_event_code (block, &target, gc,
          GUM_CODE_INTERRUPTIBLE);
    }

    gum_exec_block_write_adjust_depth (block, gc->code_writer, 1);

    if (!target.is_indirect && target.base == X86_REG_INVALID &&
        ctx->activation_target == NULL)
    {
      target_is_excluded =
          gum_stalker_is_excluding (ctx->stalker, target.absolute_address);
    }

    if (target_is_excluded)
    {
      GumBranchTarget next_instruction = { 0, };
#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
      gpointer start_of_call;
      guint call_length;
      gpointer end_of_call;
#endif

      gum_exec_block_open_prolog (block, GUM_PROLOG_IC, gc, gc->code_writer);
      gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX,
          GUM_ADDRESS (insn->end));
      gum_x86_writer_put_mov_near_ptr_reg (cw,
          GUM_ADDRESS (&ctx->pending_return_location), GUM_X86_XAX);
      gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX,
          GUM_ADDRESS (&ctx->pending_calls));
      gum_x86_writer_put_inc_reg_ptr (cw, GUM_X86_PTR_DWORD, GUM_X86_XAX);
      gum_exec_block_close_prolog (block, gc, gc->code_writer);

#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
      start_of_call = GSIZE_TO_POINTER (cw->pc);
#endif

      gum_x86_relocator_write_one_no_label (gc->relocator);

#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
      call_length = gum_x86_reader_insn_length (start_of_call);

      /*
       * We can't just write the instruction and then use cw->pc to get the
       * end of the call instruction since the relocator may need to embed the
       * target address in the code stream. In which case it is written
       * immediately after the instruction.
       */
      end_of_call =
          GSIZE_TO_POINTER (GPOINTER_TO_SIZE (start_of_call) + call_length);

      /*
       * We insert into our hashtable the real address of the next instruction
       * using the code address of the next instrumented instruction as a key.
       */
      gum_metal_hash_table_insert (ctx->excluded_calls, end_of_call, insn->end);
#endif

      gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc,
          gc->code_writer);

      gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX,
          GUM_ADDRESS (&ctx->pending_calls));
      gum_x86_writer_put_dec_reg_ptr (cw, GUM_X86_PTR_DWORD, GUM_X86_XAX);

      next_instruction.is_indirect = FALSE;
      next_instruction.absolute_address = insn->end;
      gum_exec_block_write_jmp_transfer_code (block, &next_instruction,
          GUM_ENTRYGATE (excluded_call_imm), gc, X86_INS_JMP, GUM_ADDRESS (0));

      return GUM_REQUIRE_NOTHING;
    }

    gum_x86_relocator_skip_one_no_label (gc->relocator);
    gum_exec_block_write_call_invoke_code (block, &target, gc);
  }
  else if (insn->ci->id == X86_INS_JECXZ || insn->ci->id == X86_INS_JRCXZ)
  {
    gpointer is_true;
    GumBranchTarget false_target = { 0, };

    gum_x86_relocator_skip_one_no_label (gc->relocator);

    is_true =
        GUINT_TO_POINTER ((GPOINTER_TO_UINT (insn->start) << 16) | 0xbeef);

    gum_exec_block_close_prolog (block, gc, gc->code_writer);

    gum_x86_writer_put_jcc_short_label (cw, X86_INS_JMP, is_true, GUM_NO_HINT);

    false_target.is_indirect = FALSE;
    false_target.absolute_address = insn->end;
    gum_exec_block_write_jmp_transfer_code (block, &false_target,
        GUM_ENTRYGATE (jmp_cond_jcxz), gc, X86_INS_JMP, GUM_ADDRESS (0));

    gum_x86_writer_put_label (cw, is_true);

    /*
     * x86/64 only supports short jumps for JECXZ/JRCXZ so we can't backpatch
     * the Jcc instruction itself.
     */
    gum_exec_block_write_jmp_transfer_code (block, &target,
        GUM_ENTRYGATE (jmp_cond_jcxz), gc, X86_INS_JMP, GUM_ADDRESS (0));
  }
  else if (gum_exec_block_is_direct_jmp_to_plt_got (block, gc, &target))
  {
    /*
     * Functions in Linux typically call thunks in the `.plt.got` or `.plt.sec`
     * to invoke functions located in other shared libraries. However, in the
     * event of a tail-call, rather than using a CALL instruction, a JMP
     * instruction will be used instead.
     *
     * We normally only handle CALLs to excluded ranges and therefore such
     * tail-calls will result in execution being followed into the excluded
     * range until a subsequent CALL instruction is encountered. Generally,
     * however, we cannot differentiate these tail-calls from a JMP to an
     * excluded range and therefore we must accept this additional overhead or
     * risk losing control of the target execution.
     *
     * However, if the tail-call is to the `.plt.got` or `.plt.sec`, then we
     * know that this is in fact a function call and can be treated as such. We
     * pop the return value from the stack and stash it in the data slab, then
     * emit a call into the target function from the instrumnented code so that
     * control returns there after the excluded function and follow this with
     * the standard jump handling code with the stashed value in the data slab
     * as an indirect target.
     */
    gum_exec_block_handle_direct_jmp_to_plt_got (block, gc, &target);
    return GUM_REQUIRE_NOTHING;
  }
  else
  {
    gpointer is_true;
    GumAddress jcc_address = 0;
    GumExecCtxReplaceCurrentBlockFunc regular_entry_func, cond_entry_func;

    gum_x86_relocator_skip_one_no_label (gc->relocator);

    is_true =
        GUINT_TO_POINTER ((GPOINTER_TO_UINT (insn->start) << 16) | 0xbeef);

    if (is_conditional)
    {
      g_assert (!target.is_indirect);

      gum_exec_block_close_prolog (block, gc, gc->code_writer);

      jcc_address = cw->pc;
      gum_x86_writer_put_jcc_near_label (cw, insn->ci->id, is_true,
          GUM_NO_HINT);
    }

    if (target.is_indirect)
    {
      regular_entry_func = GUM_ENTRYGATE (jmp_mem);
      cond_entry_func = GUM_ENTRYGATE (jmp_cond_mem);
    }
    else if (target.base != X86_REG_INVALID)
    {
      regular_entry_func = GUM_ENTRYGATE (jmp_reg);
      cond_entry_func = GUM_ENTRYGATE (jmp_cond_reg);
    }
    else
    {
      regular_entry_func = GUM_ENTRYGATE (jmp_imm);
      cond_entry_func = GUM_ENTRYGATE (jmp_cond_imm);
    }

    if (is_conditional)
    {
      GumBranchTarget cond_target = { 0, };

      cond_target.is_indirect = FALSE;
      cond_target.absolute_address = insn->end;

      gum_exec_block_write_jmp_transfer_code (block, &cond_target,
          cond_entry_func, gc, X86_INS_JMP, GUM_ADDRESS (0));

      gum_x86_writer_put_label (cw, is_true);

      gum_exec_block_write_jmp_transfer_code (block, &target, cond_entry_func,
          gc, insn->ci->id, jcc_address);
    }
    else
    {
      gum_exec_block_write_jmp_transfer_code (block, &target,
          regular_entry_func, gc, insn->ci->id, GUM_ADDRESS (0));
    }
  }

  return GUM_REQUIRE_NOTHING;
}

static gboolean
gum_exec_block_is_direct_jmp_to_plt_got (GumExecBlock * block,
                                         GumGeneratorContext * gc,
                                         GumBranchTarget * target)
{
#ifdef HAVE_LINUX
  GumExecCtx * ctx = block->ctx;
  const cs_insn * insn = gc->instruction->ci;
  GArray * ranges;
  guint i;

  if (target->is_indirect)
    return FALSE;

  if (target->base != X86_REG_INVALID)
    return FALSE;

  if (ctx->activation_target != NULL)
    return FALSE;

  if (!gum_stalker_is_excluding (ctx->stalker, target->absolute_address))
    return FALSE;

  if (insn->id != X86_INS_JMP)
    return FALSE;

  ranges = gum_exec_ctx_get_plt_got_ranges ();

  for (i = 0; i != ranges->len; i++)
  {
    GumMemoryRange * range = &g_array_index (ranges, GumMemoryRange, i);

    if (GUM_MEMORY_RANGE_INCLUDES (range,
        GPOINTER_TO_SIZE (target->absolute_address)))
    {
      return TRUE;
    }
  }
#endif

  return FALSE;
}

#ifdef HAVE_LINUX

static GArray *
gum_exec_ctx_get_plt_got_ranges (void)
{
  static gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GArray * ranges = g_array_new (FALSE, FALSE, sizeof (GumMemoryRange));

    gum_process_enumerate_modules (gum_exec_ctx_find_plt_got, ranges);

    _gum_register_early_destructor (gum_exec_ctx_deinit_plt_got_ranges);

    g_once_init_leave (&gonce_value, GPOINTER_TO_SIZE (ranges));
  }

  return GSIZE_TO_POINTER (gonce_value);
}

static void
gum_exec_ctx_deinit_plt_got_ranges (void)
{
  g_array_free (gum_exec_ctx_get_plt_got_ranges (), TRUE);
}

static gboolean
gum_exec_ctx_find_plt_got (const GumModuleDetails * details,
                           gpointer user_data)
{
  GArray * ranges = user_data;
  GumElfModule * elf;

  if (details->path == NULL)
    return TRUE;

  elf = gum_elf_module_new_from_memory (details->path,
      details->range->base_address, NULL);
  if (elf == NULL)
    return TRUE;

  gum_elf_module_enumerate_sections (elf, gum_exec_check_elf_section, ranges);

  g_object_unref (elf);

  return TRUE;
}

static gboolean
gum_exec_check_elf_section (const GumElfSectionDetails * details,
                            gpointer user_data)
{
  GArray * ranges = user_data;
  GumMemoryRange range;

  if (details->name == NULL)
    return TRUE;

  if (strcmp (details->name, ".plt.got") != 0 &&
      strcmp (details->name, ".plt.sec") != 0)
  {
    return TRUE;
  }

  range.base_address = details->address;
  range.size = details->size;
  g_array_append_val (ranges, range);

  return TRUE;
}

#endif

static void
gum_exec_block_handle_direct_jmp_to_plt_got (GumExecBlock * block,
                                             GumGeneratorContext * gc,
                                             GumBranchTarget * target)
{
  GumX86Writer * cw = gc->code_writer;
  GumSlab * data_slab = &block->ctx->data_slab->slab;
  gpointer * return_address;
  GumBranchTarget continue_target = { 0, };

  return_address = gum_slab_reserve (data_slab, sizeof (gpointer));

  gum_x86_writer_put_mov_reg_offset_ptr_reg (cw, GUM_X86_XSP,
      -(GUM_RED_ZONE_SIZE + (gssize) sizeof (gpointer)), GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_reg_ptr (cw, GUM_X86_XAX, GUM_X86_XSP);
  gum_x86_writer_put_mov_near_ptr_reg (cw, GUM_ADDRESS (return_address),
      GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_reg_offset_ptr (cw, GUM_X86_XAX, GUM_X86_XSP,
      -(GUM_RED_ZONE_SIZE + (gssize) sizeof (gpointer)));

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP, GUM_X86_XSP,
      sizeof (gpointer));

  gum_x86_writer_put_call_address (cw, GUM_ADDRESS (target->absolute_address));

  continue_target.is_indirect = TRUE;
  continue_target.absolute_address = return_address;
  gum_exec_block_write_jmp_transfer_code (block, &continue_target,
      GUM_ENTRYGATE (excluded_call_imm), gc, X86_INS_JMP, GUM_ADDRESS (0));
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_ret_insn (GumExecBlock * block,
                                    GumGeneratorContext * gc)
{
  if ((block->ctx->sink_mask & GUM_RET) != 0)
    gum_exec_block_write_ret_event_code (block, gc, GUM_CODE_INTERRUPTIBLE);

  gum_exec_block_write_adjust_depth (block, gc->code_writer, -1);

  gum_x86_relocator_skip_one_no_label (gc->relocator);

  gum_exec_block_write_ret_transfer_code (block, gc);

  return GUM_REQUIRE_NOTHING;
}

static void
gum_exec_block_write_adjust_depth (GumExecBlock * block,
                                   GumX86Writer * cw,
                                   gssize adj)
{
  GumAddress depth_addr = GUM_ADDRESS (&block->ctx->depth);

  if ((block->ctx->sink_mask & (GUM_CALL | GUM_RET)) == 0)
    return;

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP, GUM_X86_XSP,
      -GUM_RED_ZONE_SIZE);
  gum_x86_writer_put_push_reg (cw, GUM_X86_XAX);
  gum_x86_writer_put_mov_reg_near_ptr (cw, GUM_X86_EAX, depth_addr);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_EAX, GUM_X86_EAX, adj);
  gum_x86_writer_put_mov_near_ptr_reg (cw, depth_addr, GUM_X86_EAX);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XAX);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP, GUM_X86_XSP,
      GUM_RED_ZONE_SIZE);
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_sysenter_insn (GumExecBlock * block,
                                         GumGeneratorContext * gc)
{
#if GLIB_SIZEOF_VOID_P == 4 && !defined (HAVE_QNX)
  GumX86Writer * cw = gc->code_writer;
#if defined (HAVE_WINDOWS)
  guint8 code[] = {
    /* 00 */ 0x50,                                /* push eax              */
    /* 01 */ 0x8b, 0x02,                          /* mov eax, [edx]        */
    /* 03 */ 0xa3, 0xaa, 0xaa, 0xaa, 0xaa,        /* mov [0xaaaaaaaa], eax */
    /* 08 */ 0xc7, 0x02, 0xbb, 0xbb, 0xbb, 0xbb,  /* mov [edx], 0xbbbbbbbb */
    /* 0e */ 0x58,                                /* pop eax               */
    /* 0f */ 0x0f, 0x34,                          /* sysenter              */
    /* 11 */ 0xcc, 0xcc, 0xcc, 0xcc               /* <saved ret-addr here> */
  };
  const gsize store_ret_addr_offset = 0x03 + 1;
  const gsize load_continuation_addr_offset = 0x08 + 2;
  const gsize saved_ret_addr_offset = 0x11;
#elif defined (HAVE_DARWIN)
  guint8 code[] = {
    /* 00 */ 0x89, 0x15, 0xaa, 0xaa, 0xaa, 0xaa, /* mov [0xaaaaaaaa], edx */
    /* 06 */ 0xba, 0xbb, 0xbb, 0xbb, 0xbb,       /* mov edx, 0xbbbbbbbb   */
    /* 0b */ 0x0f, 0x34,                         /* sysenter              */
    /* 0d */ 0xcc, 0xcc, 0xcc, 0xcc              /* <saved ret-addr here> */
  };
  const gsize store_ret_addr_offset = 0x00 + 2;
  const gsize load_continuation_addr_offset = 0x06 + 1;
  const gsize saved_ret_addr_offset = 0x0d;
#elif defined (HAVE_LINUX)
  guint8 code[] = {
    /* 00 */ 0x8b, 0x54, 0x24, 0x0c,             /* mov edx, [esp + 12]   */
    /* 04 */ 0x89, 0x15, 0xaa, 0xaa, 0xaa, 0xaa, /* mov [0xaaaaaaaa], edx */
    /* 0a */ 0xba, 0xbb, 0xbb, 0xbb, 0xbb,       /* mov edx, 0xbbbbbbbb   */
    /* 0f */ 0x89, 0x54, 0x24, 0x0c,             /* mov [esp + 12], edx   */
    /* 13 */ 0x8b, 0x54, 0x24, 0x04,             /* mov edx, [esp + 4]    */
    /* 17 */ 0x0f, 0x34,                         /* sysenter              */
    /* 19 */ 0xcc, 0xcc, 0xcc, 0xcc              /* <saved ret-addr here> */
  };
  const gsize store_ret_addr_offset = 0x04 + 2;
  const gsize load_continuation_addr_offset = 0x0a + 1;
  const gsize saved_ret_addr_offset = 0x19;
#endif
  gpointer * saved_ret_addr;
  gpointer continuation;

  gum_exec_block_close_prolog (block, gc, gc->code_writer);

  saved_ret_addr = GSIZE_TO_POINTER (cw->pc + saved_ret_addr_offset);
  continuation = GSIZE_TO_POINTER (cw->pc + saved_ret_addr_offset + 4);
  *((gpointer *) (code + store_ret_addr_offset)) = saved_ret_addr;
  *((gpointer *) (code + load_continuation_addr_offset)) = continuation;

  gum_x86_writer_put_bytes (cw, code, sizeof (code));

  gum_exec_block_write_sysenter_continuation_code (block, gc, saved_ret_addr);

  return GUM_REQUIRE_NOTHING;
#else
  return GUM_REQUIRE_RELOCATION;
#endif
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_syscall_insn (GumExecBlock * block,
                                        GumGeneratorContext * gc)
{
#if GLIB_SIZEOF_VOID_P == 8 && defined (HAVE_LINUX)
  return gum_exec_block_virtualize_linux_syscall (block, gc);
#else
  return GUM_REQUIRE_RELOCATION;
#endif
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_int_insn (GumExecBlock * block,
                                    GumGeneratorContext * gc)
{
#if GLIB_SIZEOF_VOID_P == 4 && defined (HAVE_LINUX)
  const cs_insn * insn = gc->instruction->ci;
  cs_x86 * x86 = &insn->detail->x86;
  cs_x86_op * op = &x86->operands[0];

  g_assert (x86->op_count == 1);
  g_assert (op->type == X86_OP_IMM);

  if (op->imm != 0x80)
    return GUM_REQUIRE_RELOCATION;

  return gum_exec_block_virtualize_linux_syscall (block, gc);
#else
  return GUM_REQUIRE_RELOCATION;
#endif
}

#ifdef HAVE_LINUX

/*
 * SYSCALL on x64 and INT 0x80 on x86 are synonymous and both result in a
 * mode switch, we can handle them both similarly.
 */
static GumVirtualizationRequirements
gum_exec_block_virtualize_linux_syscall (GumExecBlock * block,
                                         GumGeneratorContext * gc)
{
  GumX86Writer * cw = gc->code_writer;
  const cs_insn * insn = gc->instruction->ci;
  gconstpointer perform_clone_syscall = cw->code + 1;
  gconstpointer perform_regular_syscall = cw->code + 2;
  gconstpointer perform_next_instruction = cw->code + 3;

  gum_x86_relocator_skip_one (gc->relocator);

  if (gc->opened_prolog != GUM_PROLOG_NONE)
    gum_exec_block_close_prolog (block, gc, cw);

  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
      GUM_X86_XSP, -GUM_RED_ZONE_SIZE);
  gum_x86_writer_put_pushfx (cw);

  gum_x86_writer_put_cmp_reg_i32 (cw, GUM_X86_XAX, __NR_clone);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JE, perform_clone_syscall,
      GUM_NO_HINT);
  gum_x86_writer_put_cmp_reg_i32 (cw, GUM_X86_XAX, __NR_clone3);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JNE, perform_regular_syscall,
      GUM_NO_HINT);

  gum_x86_writer_put_label (cw, perform_clone_syscall);

  /*
   * Store the return address. Note that we cannot use the stack to store this
   * since the spawned child will be given its own copy of the stack. We cannot
   * reasonably expect any value stored to be copied into the child stack unless
   * we store it in a place which the target is expected to be using. We can't
   * do this without interfering with the program state.
   */
  gum_x86_writer_put_push_reg (cw, GUM_X86_XAX);
  gum_x86_writer_put_push_reg (cw, GUM_X86_XBX);
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XAX,
      GUM_ADDRESS (&block->ctx->syscall_end));
  gum_x86_writer_put_mov_reg_address (cw, GUM_X86_XBX,
      GUM_ADDRESS (gc->instruction->end));
  gum_x86_writer_put_mov_reg_ptr_reg (cw, GUM_X86_XAX, GUM_X86_XBX);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XBX);
  gum_x86_writer_put_pop_reg (cw, GUM_X86_XAX);

  /*
   * If our syscall is a clone, then we must place the syscall instruction
   * itself on a page of its own to prevent the parent thread from changing the
   * protection of the page as it writes more code to the slab.
   */
  g_assert (insn->size == 2);

  if (memcmp (insn->bytes, gum_int80_code,
        sizeof (gum_int80_code)) == 0)
  {
    gum_x86_writer_put_call_address (cw,
        GUM_ADDRESS (block->ctx->last_int80));
  }
  else if (memcmp (insn->bytes, gum_syscall_code,
        sizeof (gum_syscall_code)) == 0)
  {
    gum_x86_writer_put_call_address (cw,
        GUM_ADDRESS (block->ctx->last_syscall));
  }
  else
  {
    g_assert_not_reached ();
  }

  gum_x86_writer_put_jmp_short_label (cw, perform_next_instruction);

  gum_x86_writer_put_label (cw, perform_regular_syscall);

  gum_x86_writer_put_popfx (cw);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
      GUM_X86_XSP, GUM_RED_ZONE_SIZE);

  gum_x86_writer_put_bytes (cw, insn->bytes, insn->size);

  gum_x86_writer_put_label (cw, perform_next_instruction);

  return GUM_REQUIRE_NOTHING;
}

static void
gum_exec_ctx_write_int80_helper (GumExecCtx * ctx,
                                 GumX86Writer * cw)
{
  gum_exec_ctx_write_aligned_syscall (ctx, cw, gum_int80_code,
      sizeof (gum_int80_code));
}

static void
gum_exec_ctx_write_syscall_helper (GumExecCtx * ctx,
                                   GumX86Writer * cw)
{
  gum_exec_ctx_write_aligned_syscall (ctx, cw, gum_syscall_code,
      sizeof (gum_syscall_code));
}

static void
gum_exec_ctx_write_aligned_syscall (GumExecCtx * ctx,
                                    GumX86Writer * cw,
                                    const guint8 * syscall_insn,
                                    gsize syscall_size)
{
  gsize page_size, page_mask;
  guint page_offset_start, pad_start, i;
  guint page_offset_end, pad_end;
  gconstpointer start = cw->code + 1;
  gconstpointer parent = cw->code + 2;
  gconstpointer end = cw->code + 3;

  /*
   * If we have reached this point, then we know that the syscall being
   * performed was a clone. This means that both the calling thread and the
   * newly spawned thread will begin execution from the point immediately after
   * the syscall instruction. However, this causes a potential race condition,
   * if the calling thread attempts to either compile a new block, or backpatch
   * an existing one in the same page. During patching the block may be thawed
   * leading to the target thread (which may be stalled at the mercy of the
   * scheduler) attempting to execute a non-executable page.
   */

  page_size = gum_query_page_size ();
  page_mask = page_size - 1;

  /* Insert padding until we reach a page boundary */
  gum_x86_writer_put_jmp_near_label (cw, start);

  page_offset_start = GPOINTER_TO_SIZE (cw->code) & page_mask;
  pad_start = page_size - page_offset_start;

  for (i = 0; i != pad_start; i++)
    gum_x86_writer_put_breakpoint (cw);

  gum_x86_writer_put_label (cw, start);

  /* Pop the return address */
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
      GUM_X86_XSP, GLIB_SIZEOF_VOID_P);

  /* Restore state */
  gum_x86_writer_put_popfx (cw);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
      GUM_X86_XSP, GUM_RED_ZONE_SIZE);

  /* Put the original syscall instruction */
  gum_x86_writer_put_bytes (cw, syscall_insn, syscall_size);

  /* Save state */
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
      GUM_X86_XSP, -GUM_RED_ZONE_SIZE);
  gum_x86_writer_put_pushfx (cw);

  /* Compare the return value from the syscall to see if we are the parent */
  gum_x86_writer_put_test_reg_reg (cw, GUM_X86_XAX, GUM_X86_XAX);
  gum_x86_writer_put_jcc_near_label (cw, X86_INS_JNE, parent, GUM_NO_HINT);

  /* Restore state */
  gum_x86_writer_put_popfx (cw);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
      GUM_X86_XSP, GUM_RED_ZONE_SIZE);

  /*
   * Direct the child back to the real address, otherwise it will continue
   * running inside Stalker using the same GumExecCtx as the parent. This will
   * result in re-entrancy issues (since by design each thread must have its
   * own GumExecCtx) and in turn horrible corruption.
   */
  gum_x86_writer_put_jmp_near_ptr (cw, GUM_ADDRESS (&ctx->syscall_end));

  gum_x86_writer_put_label (cw, parent);

  /* Restore state */
  gum_x86_writer_put_popfx (cw);
  gum_x86_writer_put_lea_reg_reg_offset (cw, GUM_X86_XSP,
      GUM_X86_XSP, GUM_RED_ZONE_SIZE);

  gum_x86_writer_put_jmp_near_label (cw, end);

  page_offset_end = GPOINTER_TO_SIZE (cw->code) & page_mask;
  pad_end = page_size - page_offset_end;

  for (i = 0; i != pad_end; i++)
    gum_x86_writer_put_breakpoint (cw);

  gum_x86_writer_put_label (cw, end);
  gum_x86_writer_put_jmp_reg_offset_ptr (cw, GUM_X86_XSP,
      -(GUM_RED_ZONE_SIZE + (2 * GLIB_SIZEOF_VOID_P)));
}

#endif

#if GLIB_SIZEOF_VOID_P == 4 && defined (HAVE_WINDOWS)

static GumVirtualizationRequirements
gum_exec_block_virtualize_wow64_transition (GumExecBlock * block,
                                            GumGeneratorContext * gc,
                                            gpointer impl)
{
  GumX86Writer * cw = gc->code_writer;
  guint8 code[] = {
    /* 00 */ 0x50,                        /* push eax */
    /* 01 */ 0x8b, 0x44, 0x24, 0x04,      /* mov eax, dword [esp + 4] */
    /* 05 */ 0x89, 0x05, 0xaa, 0xaa, 0xaa,
             0xaa,                        /* mov dword [0xaaaaaaaa], eax */
    /* 0b */ 0xc7, 0x44, 0x24, 0x04, 0xbb,
             0xbb, 0xbb, 0xbb,            /* mov dword [esp + 4], 0xbbbbbbbb */
    /* 13 */ 0x58,                        /* pop eax */
    /* 14 */ 0xff, 0x25, 0xcc, 0xcc, 0xcc,
             0xcc,                        /* jmp dword [0xcccccccc] */
    /* 1a */ 0x90, 0x90, 0x90, 0x90       /* <saved ret-addr here> */
  };
  const gsize store_ret_addr_offset = 0x05 + 2;
  const gsize load_continuation_addr_offset = 0x0b + 4;
  const gsize wow64_transition_addr_offset = 0x14 + 2;
  const gsize saved_ret_addr_offset = 0x1a;

  gum_exec_block_close_prolog (block, gc, gc->code_writer);

  gpointer * saved_ret_addr = GSIZE_TO_POINTER (cw->pc + saved_ret_addr_offset);
  gpointer continuation = GSIZE_TO_POINTER (cw->pc + saved_ret_addr_offset + 4);

  *((gpointer *) (code + store_ret_addr_offset)) = saved_ret_addr;
  *((gpointer *) (code + load_continuation_addr_offset)) = continuation;
  *((gpointer *) (code + wow64_transition_addr_offset)) = impl;

  gum_x86_writer_put_bytes (cw, code, sizeof (code));

  gum_exec_block_write_sysenter_continuation_code (block, gc, saved_ret_addr);

  return GUM_REQUIRE_NOTHING;
}

#endif

/*
 * We handle CALL instructions much like a JMP instruction, but we must push the
 * real return address onto the stack immediately before we branch so that the
 * application code sees the correct value on its stack (should it make use of
 * it). We don't need to emit a landing pad, since RET instructions are handled
 * in the same way as an indirect branch.
 */
static void
gum_exec_block_write_call_invoke_code (GumExecBlock * block,
                                       const GumBranchTarget * target,
                                       GumGeneratorContext * gc)
{
  GumStalker * stalker = block->ctx->stalker;
  const gint trust_threshold = stalker->trust_threshold;
  GumX86Writer * cw = gc->code_writer;
  const GumAddress call_code_start = cw->pc;
  GumX86Writer * cws = gc->slow_writer;
  const GumPrologType opened_prolog = gc->opened_prolog;
  gboolean can_backpatch_statically;
  gpointer * ic_match = NULL;
  GumExecCtxReplaceCurrentBlockFunc entry_func;
  GumAddress ret_code_address = 0;
  GumAddress ret_real_address = GUM_ADDRESS (gc->instruction->end);

  can_backpatch_statically =
      trust_threshold >= 0 &&
      !target->is_indirect &&
      target->base == X86_REG_INVALID;

  if (trust_threshold >= 0 && !can_backpatch_statically)
  {
    gum_exec_block_close_prolog (block, gc, gc->code_writer)
"""


```