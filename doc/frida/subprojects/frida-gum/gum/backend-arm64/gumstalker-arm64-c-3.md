Response:
The user wants a summary of the functionality of the `gumstalker-arm64.c` file, which is part of Frida. I need to extract the key responsibilities of this file by analyzing the provided code snippet. The snippet focuses on saving and restoring CPU state, handling exceptions, and managing code blocks.

Here's a breakdown of the code's functionality:

1. **Saving and Restoring CPU Context:** The functions `gum_exec_ctx_write_prolog_helper` and `gum_exec_ctx_write_epilog_helper` are responsible for generating assembly code to save and restore the CPU's registers (general-purpose and vector registers) before and after executing instrumented code. Different prologue types (`GUM_PROLOG_MINIMAL`, `GUM_PROLOG_FULL`) indicate different levels of register saving.

2. **Handling Invalid Code Blocks:** `gum_exec_ctx_write_invalidator` generates code to handle situations where an execution block is no longer valid. This involves calling `gum_exec_ctx_recompile_and_switch_block` to recompile the block.

3. **Ensuring Helper Function Reachability:** `gum_exec_ctx_ensure_helper_reachable` checks if helper functions are within direct branching distance and relocates them if necessary.

4. **Loading Register Values:** `gum_exec_ctx_load_real_register_into` generates code to load the current value of a register into another register. It considers the active prologue type to correctly access the saved register values from the `GumCpuContext`.

5. **Handling Stack Misalignment Exceptions:** `gum_exec_ctx_try_handle_exception`, `gum_exec_ctx_handle_stp`, and `gum_exec_ctx_handle_ldp` handle exceptions caused by stack misalignment. They emulate `stp` (store pair) and `ldp` (load pair) instructions to maintain correct stack operations.

6. **Managing Execution Blocks:** The code includes functions for creating (`gum_exec_block_new`), managing the lifecycle (`gum_exec_block_clear`, `gum_exec_block_commit`, `gum_exec_block_invalidate`), and backpatching (`gum_exec_block_backpatch_call`, `gum_exec_block_backpatch_jmp`, `gum_exec_block_backpatch_inline_cache`) execution blocks. Backpatching involves modifying previously generated code to redirect execution flow.

7. **Branching to Execution Blocks:** `gum_exec_block_write_jmp_to_block_start` generates code to jump to the beginning of an execution block, handling cases where a direct branch is not possible.

8. **Virtualizing Branch Instructions:** `gum_exec_block_virtualize_branch_insn` (partially shown) is responsible for generating code to handle branch instructions, potentially making them conditional or redirecting them.

Now, I need to structure this information into a concise summary that answers the user's request.
这是`frida/subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c`文件的第4部分，主要关注于**管理和操作代码执行块（GumExecBlock）以及处理执行上下文（GumExecCtx）相关的操作，尤其是在ARM64架构下进行动态代码生成和控制流程管理的关键功能。**

以下是基于代码片段的功能归纳：

**核心功能：执行上下文和代码块的管理**

1. **保存和恢复CPU上下文（Prolog和Epilog）：**
    *   `gum_exec_ctx_write_prolog_helper`:  生成汇编代码，在执行用户提供的代码前保存当前CPU的寄存器状态到 `GumCpuContext` 结构体中。它支持两种类型的Prolog：`GUM_PROLOG_MINIMAL`（保存少量寄存器）和 `GUM_PROLOG_FULL`（保存更多寄存器）。
    *   `gum_exec_ctx_write_epilog_helper`: 生成汇编代码，在执行完用户代码后，从 `GumCpuContext` 中恢复之前保存的寄存器状态。同样对应 `GUM_PROLOG_MINIMAL` 和 `GUM_PROLOG_FULL` 两种类型。
    *   **与逆向的关系：** 在逆向工程中，经常需要分析函数的调用约定和寄存器使用情况。Frida通过这种方式在执行目标代码前后捕获和修改寄存器状态，为逆向分析提供了强大的工具，例如可以查看函数调用时的参数值，或者在函数返回前修改返回值。
    *   **二进制底层知识：** 这部分代码直接操作ARM64汇编指令，例如 `stp` (store pair) 和 `ldp` (load pair) 指令用于存储和加载寄存器对到/从栈内存。`mov` 指令用于移动数据，`sub` 和 `add` 用于栈指针的调整。
    *   **逻辑推理（假设输入与输出）：**
        *   **假设输入：**  `type` 参数为 `GUM_PROLOG_MINIMAL`，`cw` 是一个指向当前代码生成位置的 `GumArm64Writer` 实例。
        *   **预期输出：**  生成的汇编代码会将一部分通用寄存器（如X0, X1），状态寄存器（NZCV），帧指针（FP）和链接寄存器（LR）保存到栈上 `ARM64_REG_X19` 指向的内存区域，并调整栈指针。
    *   **用户或编程常见的使用错误：**  如果在生成 Prolog 和 Epilog 时，`type` 参数不匹配实际需要保存的寄存器集合，可能会导致程序崩溃或行为异常。例如，如果一个函数依赖于某个被调用者保存的寄存器，但 Prolog 类型设置为 `GUM_PROLOG_MINIMAL` 而没有保存该寄存器，恢复时就会出错。

2. **处理无效代码块（Invalidator）：**
    *   `gum_exec_ctx_write_invalidator`:  当一个代码块由于某些原因（例如被修改）而失效时，生成一段代码来跳转到 `gum_exec_ctx_recompile_and_switch_block` 函数，以便重新编译并切换到新的有效代码块。
    *   **与逆向的关系：**  在动态插桩过程中，目标代码可能会被修改或重新加载。Frida需要处理这些情况，确保程序执行的连贯性和正确性。Invalidator 机制就是一种处理方式，保证执行流在代码失效时能够平滑过渡。

3. **确保辅助函数的可达性：**
    *   `gum_exec_ctx_ensure_helper_reachable`:  检查辅助函数是否在当前代码块的跳转范围内。如果不在，则将辅助函数相关的代码段复制到当前代码块，确保可以被直接调用。
    *   `gum_exec_ctx_is_helper_reachable`: 判断一个辅助函数是否可以通过直接跳转指令到达。
    *   **与逆向的关系：**  Frida在运行时可能会注入一些辅助函数来实现特定的功能。为了提高效率，通常希望这些辅助函数能够被直接调用，避免额外的跳转开销。

4. **加载实际寄存器值：**
    *   `gum_exec_ctx_load_real_register_into`:  生成代码将指定的寄存器的值加载到目标寄存器中。它会根据当前的 Prolog 类型（`GUM_PROLOG_MINIMAL` 或 `GUM_PROLOG_FULL`）从正确的位置（栈上或直接从寄存器）加载。
    *   **与逆向的关系：**  在插桩代码中，可能需要读取目标程序运行时的寄存器值。这个函数提供了实现这一功能的底层机制。

5. **处理栈不对齐异常：**
    *   `gum_exec_ctx_try_handle_exception`: 尝试处理由于栈指针 (`sp`) 没有按照16字节对齐而引发的异常。一些反调试技术会故意使栈不对齐，导致依赖对齐访问的指令出错。
    *   `gum_exec_ctx_handle_stp`:  模拟 `stp` 指令的操作，手动调整栈指针并存储寄存器值。
    *   `gum_exec_ctx_handle_ldp`:  模拟 `ldp` 指令的操作，手动加载寄存器值并调整栈指针。
    *   **与逆向的关系：**  这部分代码直接涉及到对底层硬件行为的理解，特别是ARM64架构的内存访问对齐要求。Frida需要处理这些异常情况，使其能够绕过一些简单的反调试策略。
    *   **Linux/Android内核及框架知识：**  Linux和Android内核通常会强制执行栈对齐，但某些情况下（例如信号处理）可能会出现临时不对齐。理解这些内核行为有助于理解为何需要这种异常处理机制。
    *   **逻辑推理（假设输入与输出）：**
        *   **假设输入：** `cpu_context->sp` 的值不是16的倍数，且 `cpu_context->pc` 指向的指令是 `stp x0, x1, [sp, #-0x10]!`。
        *   **预期输出：**  `gum_exec_ctx_handle_stp` 会被调用，它会先将 `cpu_context->sp` 减去 16，然后将寄存器 `X0` 和 `X1` 的值存储到新的栈顶位置，最后将 `cpu_context->pc` 加 4，模拟指令的执行。

6. **执行块的管理：**
    *   `gum_exec_block_new`:  创建一个新的代码执行块 `GumExecBlock`，并分配内存空间。
    *   `gum_exec_block_maybe_create_new_code_slabs`:  检查是否有足够的空间来创建新的代码 slab。
    *   `gum_exec_block_maybe_create_new_data_slab`: 检查是否有足够的空间来创建新的数据 slab。
    *   `gum_exec_block_clear`:  清除执行块中的资源，例如释放与调用相关的回调数据。
    *   `gum_exec_block_commit`:  提交执行块，使其变为可执行状态。
    *   `gum_exec_block_invalidate`:  使一个执行块失效，通常通过插入跳转到 Invalidator 的指令来实现。
    *   `gum_exec_block_backpatch_call`:  在已生成的代码中回填（修改）跳转指令，使其跳转到目标代码块的起始位置，用于处理函数调用。
    *   `gum_exec_block_backpatch_jmp`:  类似 `gum_exec_block_backpatch_call`，但用于处理无条件跳转。
    *   `gum_exec_block_backpatch_inline_cache`: 回填内联缓存，优化代码块之间的跳转。
    *   `gum_exec_block_write_jmp_to_block_start`: 生成跳转到代码块起始位置的汇编代码，会考虑目标地址是否在直接跳转范围内。
    *   **与逆向的关系：**  Frida通过管理执行块来组织和控制动态生成的代码。回填机制允许在运行时修改代码的执行流程，这是动态插桩的核心能力。
    *   **二进制底层知识：**  回填操作直接修改内存中的机器码。`gum_arm64_writer_put_b_imm` 用于生成近距离跳转指令，`gum_arm64_writer_put_ldr_reg_address` 和 `gum_arm64_writer_put_br_reg_no_auth` 用于生成远距离跳转指令。
    *   **用户操作是如何一步步的到达这里，作为调试线索：**
        1. 用户编写Frida脚本，使用 `Interceptor.attach()` 或 `Stalker.follow()` 等API来拦截目标函数的执行或跟踪代码执行流程。
        2. 当目标代码执行到被拦截的位置时，Frida的 Stalker 组件会尝试生成新的代码块来执行用户提供的插桩代码。
        3. `gum_exec_block_new` 等函数会被调用来创建和管理这些代码块。
        4. `gum_exec_ctx_write_prolog_helper` 会被调用来保存当前上下文。
        5. 用户提供的 JavaScript 回调函数会被编译成机器码并插入到新生成的代码块中。
        6. 当需要跳转到其他代码块时，`gum_exec_block_backpatch_call` 或 `gum_exec_block_backpatch_jmp` 会被调用来修改之前的跳转指令。
        7. 如果发生栈不对齐异常，`gum_exec_ctx_try_handle_exception` 会尝试处理。

7. **虚拟化分支指令：**
    *   `gum_exec_block_virtualize_branch_insn`:  （部分展示）用于处理分支指令，可能会根据条件或目标地址生成不同的代码。
    *   **与逆向的关系：**  通过虚拟化分支指令，Frida可以控制程序的执行流程，例如可以条件性地执行某些代码，或者将分支目标重定向到其他位置。

**总结第4部分的功能：**

这部分代码主要负责 Frida 在 ARM64 架构下动态生成和管理代码执行块的核心逻辑。它涵盖了保存和恢复 CPU 上下文、处理代码失效、确保辅助函数可达、加载寄存器值、处理栈不对齐异常以及执行块的创建、提交、失效和回填等关键功能。这些功能共同支撑了 Frida 的动态插桩能力，使其能够在运行时修改目标程序的行为，为逆向工程、安全分析和动态调试提供了基础。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
gssize size = 2 * sizeof (GumArm64VectorReg);

      if (i == 6)
        size += (32 - 8) * sizeof (GumArm64VectorReg);

      gum_arm64_writer_put_stp_reg_reg_reg_offset (cw,
          ARM64_REG_Q0 + i, ARM64_REG_Q1 + i,
          ARM64_REG_X19, -size, GUM_INDEX_PRE_ADJUST);
    }

    /* GumCpuContext.{fp,lr}, LR being a placeholder updated below */
    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw,
        ARM64_REG_FP, ARM64_REG_XZR,
        ARM64_REG_X19, -16, GUM_INDEX_PRE_ADJUST);

    /* GumCpuContext.x[19:29]: skipped as X19-X28 are callee-saved registers */
    gum_arm64_writer_put_sub_reg_reg_imm (cw, ARM64_REG_X19, ARM64_REG_X19,
        (29 - 19) * 8);

    /* GumCpuContext.x[1:19] */
    for (i = 17; i != -1; i -= 2)
    {
      gum_arm64_writer_put_stp_reg_reg_reg_offset (cw,
          ARM64_REG_X0 + i, ARM64_REG_X1 + i,
          ARM64_REG_X19, -16, GUM_INDEX_PRE_ADJUST);
    }

    /* GumCpuContext.{nzcv,x0} */
    gum_arm64_writer_put_mov_reg_nzcv (cw, ARM64_REG_X1);
    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw,
        ARM64_REG_X1, ARM64_REG_X0,
        ARM64_REG_X19, -16, GUM_INDEX_PRE_ADJUST);

    /* GumCpuContext.{pc,sp} */
    gum_arm64_writer_put_sub_reg_reg_imm (cw, ARM64_REG_X19, ARM64_REG_X19, 16);
  }
  else if (type == GUM_PROLOG_FULL)
  {
    guint distance_to_top = 0;

    /* GumCpuContext.v[32] */
    for (i = 30; i != -2; i -= 2)
    {
      const gssize vector_pair_size = 2 * sizeof (GumArm64VectorReg);

      gum_arm64_writer_put_stp_reg_reg_reg_offset (cw,
          ARM64_REG_Q0 + i, ARM64_REG_Q1 + i,
          ARM64_REG_X19, -vector_pair_size,
          GUM_INDEX_PRE_ADJUST);

      distance_to_top += vector_pair_size;
    }

    /* GumCpuContext.{fp,lr}, LR being a placeholder updated below */
    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw,
        ARM64_REG_FP, ARM64_REG_XZR,
        ARM64_REG_X19, -16, GUM_INDEX_PRE_ADJUST);
    distance_to_top += 16;

    /* GumCpuContext.x[1:29] */
    for (i = 27; i != -1; i -= 2)
    {
      if (i == 19)
      {
        /*
         * X19 has been stored above our CpuContext by the prologue code, we
         * reach up and grab it here and copy it to the right place in the
         * context. Here we use X28 as scratch since it has already been saved
         * in the context above.
         */
        gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X28,
            ARM64_REG_X19, distance_to_top);
        gum_arm64_writer_put_stp_reg_reg_reg_offset (cw,
            ARM64_REG_X28, ARM64_REG_X20,
            ARM64_REG_X19, -16, GUM_INDEX_PRE_ADJUST);
        distance_to_top += 16;
        continue;
      }

      gum_arm64_writer_put_stp_reg_reg_reg_offset (cw,
          ARM64_REG_X0 + i, ARM64_REG_X1 + i,
          ARM64_REG_X19, -16, GUM_INDEX_PRE_ADJUST);
      distance_to_top += 16;
    }

    /* GumCpuContext.{nzcv,x0} */
    gum_arm64_writer_put_mov_reg_nzcv (cw, ARM64_REG_X1);
    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw,
        ARM64_REG_X1, ARM64_REG_X0,
        ARM64_REG_X19, -16, GUM_INDEX_PRE_ADJUST);
    distance_to_top += 16;

    /* GumCpuContext.{pc,sp} */
    gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X0,
        ARM64_REG_X19, distance_to_top + 16 + GUM_RED_ZONE_SIZE);
    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw,
        ARM64_REG_XZR, ARM64_REG_X0,
        ARM64_REG_X19, -16, GUM_INDEX_PRE_ADJUST);
    distance_to_top += 16;
  }

  /*
   * Read the value of the LR stored by the prologue code above the CpuContext
   * and copy it to its correct place in the CpuContext structure.
   */
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X0, ARM64_REG_X19,
      sizeof (GumCpuContext) + 8);
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X0, ARM64_REG_X19,
      G_STRUCT_OFFSET (GumCpuContext, lr));

  /*
   * Store the value of X20 in its place above the GumCpuContext. We have to
   * add 8 bytes beyond the context to reach the value of LR pushed in the
   * prolog code.
   */
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X20, ARM64_REG_X19,
      sizeof (GumCpuContext) + 8);

  /* Align our stack pointer */
  gum_arm64_writer_put_and_reg_reg_imm (cw, ARM64_REG_SP, ARM64_REG_X19, ~0xf);

  /* Set X20 as our context pointer */
  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X20, ARM64_REG_X19);

  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_LR);
}

static void
gum_exec_ctx_write_epilog_helper (GumExecCtx * ctx,
                                  GumPrologType type,
                                  GumArm64Writer * cw)
{
  gint i;

  /* X19 and X20 have been pushed by our caller */

  if (type == GUM_PROLOG_FULL)
  {
    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw,
        ARM64_REG_X0, ARM64_REG_X1,
        ARM64_REG_X20, G_STRUCT_OFFSET (GumCpuContext, x[19]),
        GUM_INDEX_SIGNED_OFFSET);
    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw,
        ARM64_REG_X0, ARM64_REG_X1,
        ARM64_REG_X20, sizeof (GumCpuContext),
        GUM_INDEX_SIGNED_OFFSET);
  }

  if (type == GUM_PROLOG_MINIMAL)
  {
    /* GumCpuContext.{pc,sp}: skipped */
    gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X20, ARM64_REG_X20, 16);

    /* GumCpuContext.{nzcv,x[0]} */
    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X1, ARM64_REG_X0,
        ARM64_REG_X20, 16, GUM_INDEX_POST_ADJUST);

    /* Restore status */
    gum_arm64_writer_put_mov_nzcv_reg (cw, ARM64_REG_X1);

    /* GumCpuContext.x[1:19] */
    for (i = 1; i != 19; i += 2)
    {
      gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw,
          ARM64_REG_X0 + i, ARM64_REG_X1 + i,
          ARM64_REG_X20, 16, GUM_INDEX_POST_ADJUST);
    }

    /* GumCpuContext.x[19:29]: skipped as X19-X28 are callee-saved registers */
    gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X20, ARM64_REG_X20,
        (29 - 19) * 8);

    /* Last chance to grab LR so we can return from this thunk */
    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_LR);

    /* GumCpuContext.{fp,lr} */
    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw,
        ARM64_REG_FP, ARM64_REG_LR,
        ARM64_REG_X20, 16, GUM_INDEX_POST_ADJUST);

    /* GumCpuContext.v[0:8] plus padding for v[8:32] */
    for (i = 0; i != 8; i += 2)
    {
      gssize size = 2 * sizeof (GumArm64VectorReg);

      if (i == 6)
        size += (32 - 8) * sizeof (GumArm64VectorReg);

      gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw,
          ARM64_REG_Q0 + i, ARM64_REG_Q1 + i,
          ARM64_REG_X20, size, GUM_INDEX_POST_ADJUST);
    }
  }
  else if (type == GUM_PROLOG_FULL)
  {
    /* GumCpuContext.{pc,sp}: skipped */
    gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X20, ARM64_REG_X20, 16);

    /* GumCpuContext.{nzcv,x[0]} */
    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X1, ARM64_REG_X0,
        ARM64_REG_X20, 16, GUM_INDEX_POST_ADJUST);

    /* Restore status */
    gum_arm64_writer_put_mov_nzcv_reg (cw, ARM64_REG_X1);

    /* GumCpuContext.x[1:29] */
    for (i = 1; i != 29; i += 2)
    {
      if (i == 19)
      {
        /* We already dealt with X19 and X20 above */
        gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X20,
            ARM64_REG_X20, 16);
        continue;
      }

      gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw,
          ARM64_REG_X0 + i, ARM64_REG_X1 + i,
          ARM64_REG_X20, 16, GUM_INDEX_POST_ADJUST);
    }

    /* Last chance to grab LR so we can return from this thunk */
    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X19, ARM64_REG_LR);

    /* GumCpuContext.{fp,lr} */
    gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw,
        ARM64_REG_FP, ARM64_REG_LR,
        ARM64_REG_X20, 16, GUM_INDEX_POST_ADJUST);

    /* GumCpuContext.v[0:32] */
    for (i = 0; i != 32; i += 2)
    {
      gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw,
          ARM64_REG_Q0 + i, ARM64_REG_Q1 + i,
          ARM64_REG_X20, 2 * sizeof (GumArm64VectorReg), GUM_INDEX_POST_ADJUST);
    }
  }

  gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_SP, ARM64_REG_X20);

  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X19);
}

static void
gum_exec_ctx_write_invalidator (GumExecCtx * ctx,
                                GumArm64Writer * cw)
{
  gum_exec_ctx_write_prolog (ctx, GUM_PROLOG_MINIMAL, cw);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_recompile_and_switch_block), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_REGISTER, ARM64_REG_X17);

  gum_exec_ctx_write_epilog (ctx, GUM_PROLOG_MINIMAL, cw);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE, GUM_INDEX_POST_ADJUST);

  gum_exec_block_write_exec_generated_code (cw, ctx);
}

static void
gum_exec_ctx_ensure_helper_reachable (GumExecCtx * ctx,
                                      GumSlab * code_slab,
                                      GumSlab * slow_slab,
                                      GumArm64Writer * cw,
                                      gpointer * helper_ptr,
                                      GumExecHelperWriteFunc write)
{
  gboolean code_reachable, slow_reachable;
  gpointer start;

  code_reachable = gum_exec_ctx_is_helper_reachable (ctx, code_slab, cw,
      helper_ptr);
  slow_reachable = gum_exec_ctx_is_helper_reachable (ctx, slow_slab, cw,
      helper_ptr);
  if (code_reachable && slow_reachable)
    return;

  start = gum_slab_cursor (code_slab);
  gum_stalker_thaw (ctx->stalker, start, gum_slab_available (code_slab));
  gum_arm64_writer_reset (cw, start);
  *helper_ptr = gum_arm64_writer_cur (cw);

  write (ctx, cw);

  gum_arm64_writer_flush (cw);
  gum_stalker_freeze (ctx->stalker, cw->base, gum_arm64_writer_offset (cw));

  gum_slab_reserve (code_slab, gum_arm64_writer_offset (cw));
}

static gboolean
gum_exec_ctx_is_helper_reachable (GumExecCtx * ctx,
                                  GumSlab * slab,
                                  GumArm64Writer * cw,
                                  gpointer * helper_ptr)
{
  GumAddress helper, start, end;

  helper = GUM_ADDRESS (*helper_ptr);
  if (helper == 0)
    return FALSE;

  start = GUM_ADDRESS (gum_slab_start (slab));
  end = GUM_ADDRESS (gum_slab_end (slab));

  if (!gum_arm64_writer_can_branch_directly_between (cw, start, helper))
    return FALSE;

  return gum_arm64_writer_can_branch_directly_between (cw, end, helper);
}

static void
gum_exec_ctx_write_push_branch_target_address (GumExecCtx * ctx,
                                               const GumBranchTarget * target,
                                               GumGeneratorContext * gc,
                                               GumArm64Writer * cw)
{
  if (target->reg == ARM64_REG_INVALID)
  {
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X15,
        GUM_ADDRESS (target->absolute_address));
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X15, ARM64_REG_X15);
  }
  else
  {
    gum_exec_ctx_load_real_register_into (ctx, ARM64_REG_X15, target->reg, gc,
        cw);
    if ((ctx->stalker->cpu_features & GUM_CPU_PTRAUTH) != 0)
      gum_arm64_writer_put_xpaci_reg (cw, ARM64_REG_X15);
    gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X15, ARM64_REG_X15);
  }
}

static void
gum_exec_ctx_load_real_register_into (GumExecCtx * ctx,
                                      arm64_reg target_register,
                                      arm64_reg source_register,
                                      GumGeneratorContext * gc,
                                      GumArm64Writer * cw)
{
  if (gc->opened_prolog == GUM_PROLOG_MINIMAL)
  {
    gum_exec_ctx_load_real_register_from_minimal_frame_into (ctx,
        target_register, source_register, gc, cw);
    return;
  }
  else if (gc->opened_prolog == GUM_PROLOG_FULL)
  {
    gum_exec_ctx_load_real_register_from_full_frame_into (ctx, target_register,
        source_register, gc, cw);
    return;
  }

  g_assert_not_reached ();
}

/*
 * The layout of the MINIMAL context is actually the same as the FULL context,
 * except that the callee saved registers are not stored into the GumCpuContext.
 * Instead we must retrieve these directly from the register itself. With the
 * exception of X19 and X20 which are used in the prolog/epilog itself, we
 * deliberately therefore avoid using these callee saved registers since they
 * are not restored from the MINIMAL context. Since they are callee saved, any
 * C functions which are called from Stalker will be guaranteed not to clobber
 * them either.
 */
static void
gum_exec_ctx_load_real_register_from_minimal_frame_into (
    GumExecCtx * ctx,
    arm64_reg target_register,
    arm64_reg source_register,
    GumGeneratorContext * gc,
    GumArm64Writer * cw)
{
  if (source_register >= ARM64_REG_X0 && source_register <= ARM64_REG_X18)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, x) +
        ((source_register - ARM64_REG_X0) * 8));
  }
  else if (source_register == ARM64_REG_X19 || source_register == ARM64_REG_X20)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        sizeof (GumCpuContext) + ((source_register - ARM64_REG_X19) * 8));
  }
  else if (source_register == ARM64_REG_X29)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, fp));
  }
  else if (source_register == ARM64_REG_X30)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, lr));
  }
  else
  {
    gum_arm64_writer_put_mov_reg_reg (cw, target_register, source_register);
  }
}

static void
gum_exec_ctx_load_real_register_from_full_frame_into (GumExecCtx * ctx,
                                                      arm64_reg target_register,
                                                      arm64_reg source_register,
                                                      GumGeneratorContext * gc,
                                                      GumArm64Writer * cw)
{
  if (source_register >= ARM64_REG_X0 && source_register <= ARM64_REG_X28)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, x) +
        ((source_register - ARM64_REG_X0) * 8));
  }
  else if (source_register == ARM64_REG_X29)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, fp));
  }
  else if (source_register == ARM64_REG_X30)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, target_register, ARM64_REG_X20,
        G_STRUCT_OFFSET (GumCpuContext, lr));
  }
  else
  {
    gum_arm64_writer_put_mov_reg_reg (cw, target_register, source_register);
  }
}

/*
 * This exception handler deals with exceptions caused by attempts to access the
 * stack when it isn't 16-byte aligned. Anti-Frida techniques have been observed
 * in the wild where the stack is deliberately misaligned to cause Stalker to
 * crash when it executes. Since an exception is only thrown when an attempt is
 * made to load or store from a misaligned stack pointer, this anti-Frida code
 * can misalign the stack and cause a branch without accessing stack data and
 * hence therefore force FRIDA to deal with a misaligned stack without
 * incurring any exceptions itself.
 *
 * We cope with this scenario by making use of a register to act as a proxy for
 * the stack pointer during the prolog and epilogue (where extensive use of the
 * stack is made) and having the prolog ensure the stack is aligned once it has
 * finished executing. Since all C code called from within Stalker must be
 * called from within a prolog, we can therefore ensure that no such
 * misalignment errors occur during its execution.
 *
 * This still leaves the matter of the initial instructions at the start of the
 * prolog and end of the epilogue which must save/restore the proxy register, we
 * emulate these instructions in this exception handler and advance the
 * instruction pointer. There is also code on the fast path which executes
 * outside a prolog, this code has been rationalised to make use of a minimum
 * selection of instructions which operate on the stack and therefore we only
 * need to emulate a handful of individual instructions below.
 */
static gboolean
gum_exec_ctx_try_handle_exception (GumExecCtx * ctx,
                                   GumExceptionDetails * details)
{
  GumCpuContext * cpu_context = &details->context;
  const guint32 * insn;

  insn = GSIZE_TO_POINTER (cpu_context->pc);

  if (!gum_exec_ctx_contains (ctx, insn))
    return FALSE;

  if (cpu_context->sp % GUM_STACK_ALIGNMENT == 0)
    return FALSE;

  switch (*insn)
  {
    /* STP */
    case 0xa9bf07e0: /* stp x0, x1, [sp, #-0x10]! */
      gum_exec_ctx_handle_stp (cpu_context, ARM64_REG_X0, ARM64_REG_X1, 16);
      return TRUE;

    case 0xa9b747f0: /* stp x16, x17, [sp, #-(16 + GUM_RED_ZONE_SIZE)]! */
      gum_exec_ctx_handle_stp (cpu_context, ARM64_REG_X16, ARM64_REG_X17,
          16 + GUM_RED_ZONE_SIZE);
      return TRUE;

    case 0xa9b77bf3: /* stp x19, x30, [sp, #-(16 + GUM_RED_ZONE_SIZE)]! */
      gum_exec_ctx_handle_stp (cpu_context, ARM64_REG_X19, ARM64_REG_X30,
          16 + GUM_RED_ZONE_SIZE);
      return TRUE;

    /* LDP */
    case 0xa8c107e0: /* ldp x0, x1, [sp], #0x10 */
      gum_exec_ctx_handle_ldp (cpu_context, ARM64_REG_X0, ARM64_REG_X1, 16);
      return TRUE;

    case 0xa8c947f0: /* ldp x16, x17, [sp], #(16 + GUM_RED_ZONE_SIZE) */
      gum_exec_ctx_handle_ldp (cpu_context, ARM64_REG_X16, ARM64_REG_X17,
          16 + GUM_RED_ZONE_SIZE);
      return TRUE;

    case 0xa8c953f3: /* ldp x19, x20, [sp], #(16 + GUM_RED_ZONE_SIZE) */
      gum_exec_ctx_handle_ldp (cpu_context, ARM64_REG_X19, ARM64_REG_X20,
          16 + GUM_RED_ZONE_SIZE);
      return TRUE;

    default:
      break;
  }

  return FALSE;
}

static void
gum_exec_ctx_handle_stp (GumCpuContext * cpu_context,
                         arm64_reg reg1,
                         arm64_reg reg2,
                         gsize offset)
{
  guint64 * sp;

  cpu_context->sp -= offset;

  sp = GSIZE_TO_POINTER (cpu_context->sp);
  sp[0] = gum_exec_ctx_read_register (cpu_context, reg1);
  sp[1] = gum_exec_ctx_read_register (cpu_context, reg2);

  cpu_context->pc += 4;
}

static void
gum_exec_ctx_handle_ldp (GumCpuContext * cpu_context,
                         arm64_reg reg1,
                         arm64_reg reg2,
                         gsize offset)
{
  guint64 * sp = GSIZE_TO_POINTER (cpu_context->sp);

  gum_exec_ctx_write_register (cpu_context, reg1, sp[0]);
  gum_exec_ctx_write_register (cpu_context, reg2, sp[1]);

  cpu_context->sp += offset;
  cpu_context->pc += 4;
}

static guint64
gum_exec_ctx_read_register (GumCpuContext * cpu_context,
                            arm64_reg reg)
{
  if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
    return cpu_context->x[reg - ARM64_REG_X0];

  switch (reg)
  {
    case ARM64_REG_X29:
      return cpu_context->fp;
    case ARM64_REG_X30:
      return cpu_context->lr;
    default:
      g_assert_not_reached ();
  }
}

static void
gum_exec_ctx_write_register (GumCpuContext * cpu_context,
                             arm64_reg reg,
                             guint64 value)
{
  if (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X28)
  {
    cpu_context->x[reg - ARM64_REG_X0] = value;
    return;
  }

  switch (reg)
  {
    case ARM64_REG_X29:
      cpu_context->fp = value;
      break;
    case ARM64_REG_X30:
      cpu_context->lr = value;
      break;
    default:
      g_assert_not_reached ();
  }
}

static GumExecBlock *
gum_exec_block_new (GumExecCtx * ctx)
{
  GumStalker * stalker = ctx->stalker;
  GumCodeSlab * code_slab;
  GumSlowSlab * slow_slab;
  GumDataSlab * data_slab;
  gsize code_available, slow_available;
  GumExecBlock * block;

  gum_exec_block_maybe_create_new_code_slabs (ctx);
  gum_exec_block_maybe_create_new_data_slab (ctx);

  code_slab = ctx->code_slab;
  slow_slab = ctx->slow_slab;
  data_slab = ctx->data_slab;

  code_available = gum_slab_available (&code_slab->slab);
  slow_available = gum_slab_available (&slow_slab->slab);

  block = gum_slab_reserve (&data_slab->slab, sizeof (GumExecBlock));

  block->next = ctx->block_list;
  ctx->block_list = block;

  block->ctx = ctx;
  block->code_slab = code_slab;
  block->slow_slab = slow_slab;

  block->code_start = gum_slab_cursor (&code_slab->slab);
  block->slow_start = gum_slab_cursor (&slow_slab->slab);

  gum_stalker_thaw (stalker, block->code_start, code_available);
  gum_stalker_thaw (stalker, block->slow_start, slow_available);

  return block;
}

static void
gum_exec_block_maybe_create_new_code_slabs (GumExecCtx * ctx)
{
  gsize code_available, slow_available;
  gboolean enough_code, enough_slow;

  code_available = gum_slab_available (&ctx->code_slab->slab);
  slow_available = gum_slab_available (&ctx->slow_slab->slab);

  /*
   * Whilst we don't write the inline cache entry into the code slab any more,
   * we do write an unrolled loop which walks the table looking for the right
   * entry, so we need to ensure we have some extra space for that anyway.
   */
  enough_code = code_available >= GUM_EXEC_BLOCK_MIN_CAPACITY +
      gum_stalker_get_ic_entry_size (ctx->stalker);
  enough_slow = slow_available >= GUM_EXEC_BLOCK_MIN_CAPACITY;
  if (enough_code && enough_slow)
    return;

  gum_exec_ctx_add_code_slab (ctx, gum_code_slab_new (ctx));
  gum_exec_ctx_add_slow_slab (ctx, gum_slab_end (&ctx->code_slab->slab));

  gum_exec_ctx_ensure_inline_helpers_reachable (ctx);
}

static void
gum_exec_block_maybe_create_new_data_slab (GumExecCtx * ctx)
{
  GumDataSlab * data_slab = ctx->data_slab;
  GumAddressSpec data_spec;
  gsize data_available;
  gboolean enough_data, address_ok;

  gum_exec_ctx_compute_data_address_spec (ctx, data_slab->slab.size,
      &data_spec);

  data_available = gum_slab_available (&data_slab->slab);

  enough_data = data_available >= GUM_DATA_BLOCK_MIN_CAPACITY +
      gum_stalker_get_ic_entry_size (ctx->stalker);
  address_ok = gum_address_spec_is_satisfied_by (&data_spec,
      gum_slab_start (&data_slab->slab));
  if (enough_data && address_ok)
    return;

  data_slab = gum_exec_ctx_add_data_slab (ctx, gum_data_slab_new (ctx));
}

static void
gum_exec_block_clear (GumExecBlock * block)
{
  GumCalloutEntry * entry;

  for (entry = gum_exec_block_get_last_callout_entry (block);
      entry != NULL;
      entry = entry->next)
  {
    if (entry->data_destroy != NULL)
      entry->data_destroy (entry->data);
  }
  block->last_callout_offset = 0;

  block->storage_block = NULL;
}

static gconstpointer
gum_exec_block_check_address_for_exclusion (GumExecBlock * block,
                                            gconstpointer address)
{
  GumExecCtx * ctx = block->ctx;

  if (ctx->activation_target != NULL)
    return address;

  if (gum_stalker_is_excluding (ctx->stalker, address))
    return NULL;

  return address;
}

static void
gum_exec_block_commit (GumExecBlock * block)
{
  GumStalker * stalker = block->ctx->stalker;
  gsize snapshot_size;

  snapshot_size =
      gum_stalker_snapshot_space_needed_for (stalker, block->real_size);
  memcpy (gum_exec_block_get_snapshot_start (block), block->real_start,
      snapshot_size);

  block->capacity = block->code_size + snapshot_size;

  gum_slab_reserve (&block->code_slab->slab, block->capacity);
  gum_stalker_freeze (stalker, block->code_start, block->code_size);

  gum_slab_reserve (&block->slow_slab->slab, block->slow_size);
  gum_stalker_freeze (stalker, block->slow_start, block->slow_size);
}

static void
gum_exec_block_invalidate (GumExecBlock * block)
{
  GumExecCtx * ctx = block->ctx;
  GumStalker * stalker = ctx->stalker;
  GumArm64Writer * cw = &ctx->code_writer;
  const gsize max_size = GUM_INVALIDATE_TRAMPOLINE_MAX_SIZE;
  gconstpointer already_saved = cw->code + 1;

  g_assert (block->code_size >= GUM_INVALIDATE_TRAMPOLINE_MAX_SIZE);

  gum_stalker_thaw (stalker, block->code_start, max_size);
  gum_arm64_writer_reset (cw, block->code_start);

  gum_arm64_writer_put_b_label (cw, already_saved);
  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE), GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_label (cw, already_saved);
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X17, GUM_ADDRESS (block));
  gum_arm64_writer_put_b_imm (cw, GUM_ADDRESS (block->code_slab->invalidator));

  gum_arm64_writer_flush (cw);
  g_assert (gum_arm64_writer_offset (cw) <= max_size);
  gum_stalker_freeze (stalker, block->code_start, max_size);
}

static gpointer
gum_exec_block_get_snapshot_start (GumExecBlock * block)
{
  return block->code_start + block->code_size;
}

static GumCalloutEntry *
gum_exec_block_get_last_callout_entry (const GumExecBlock * block)
{
  const guint last_callout_offset = block->last_callout_offset;

  if (last_callout_offset == 0)
    return NULL;

  return (GumCalloutEntry *) (block->code_start + last_callout_offset);
}

static void
gum_exec_block_set_last_callout_entry (GumExecBlock * block,
                                       GumCalloutEntry * entry)
{
  block->last_callout_offset = (guint8 *) entry - block->code_start;
}

static void
gum_exec_block_backpatch_call (GumExecBlock * block,
                               GumExecBlock * from,
                               gpointer from_insn,
                               gsize code_offset,
                               GumPrologType opened_prolog,
                               gpointer ret_real_address)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  gpointer target;
  guint8 * code_start = from->code_start + code_offset;
  const gsize code_max_size = from->code_size - code_offset;
  GumArm64Writer * cw;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;
  if (!gum_exec_ctx_may_now_backpatch (ctx, block))
    return;

  target = block->code_start;
  gum_exec_ctx_query_block_switch_callback (ctx, block, block->real_start,
      from_insn, &target);

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (ctx->stalker, code_start, code_max_size);

  cw = &ctx->code_writer;
  gum_arm64_writer_reset (cw, code_start);

  if (opened_prolog != GUM_PROLOG_NONE)
    gum_exec_ctx_write_epilog (block->ctx, opened_prolog, cw);

  gum_exec_ctx_write_adjust_depth (ctx, cw, 1);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_LR,
      GUM_ADDRESS (ret_real_address));
  gum_exec_block_write_jmp_to_block_start (block, target);

  gum_arm64_writer_flush (cw);
  g_assert (gum_arm64_writer_offset (cw) <= code_max_size);
  gum_stalker_freeze (ctx->stalker, code_start, code_max_size);

  gum_spinlock_release (&ctx->code_lock);

  if (ctx->observer != NULL)
  {
    GumBackpatch p;

    p.type = GUM_BACKPATCH_CALL;
    p.to = block->real_start;
    p.from = from->real_start;
    p.from_insn = from_insn;
    p.call.code_offset = code_offset;
    p.call.opened_prolog = opened_prolog;
    p.call.ret_real_address = ret_real_address;

    gum_stalker_observer_notify_backpatch (ctx->observer, &p, sizeof (p));
  }
}

static void
gum_exec_block_backpatch_jmp (GumExecBlock * block,
                              GumExecBlock * from,
                              gpointer from_insn,
                              gsize code_offset,
                              GumPrologType opened_prolog)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  gpointer target;
  guint8 * code_start = from->code_start + code_offset;
  const gsize code_max_size = from->code_size - code_offset;
  GumArm64Writer * cw;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;
  if (!gum_exec_ctx_may_now_backpatch (ctx, block))
    return;

  target = block->code_start;
  gum_exec_ctx_query_block_switch_callback (ctx, block, block->real_start,
      from_insn, &target);

  gum_spinlock_acquire (&ctx->code_lock);

  gum_stalker_thaw (ctx->stalker, code_start, code_max_size);

  cw = &ctx->code_writer;
  gum_arm64_writer_reset (cw, code_start);

  if (opened_prolog != GUM_PROLOG_NONE)
    gum_exec_ctx_write_epilog (block->ctx, opened_prolog, cw);

  gum_exec_block_write_jmp_to_block_start (block, target);

  gum_arm64_writer_flush (cw);
  g_assert (gum_arm64_writer_offset (cw) <= code_max_size);
  gum_stalker_freeze (ctx->stalker, code_start, code_max_size);

  gum_spinlock_release (&ctx->code_lock);

  if (ctx->observer != NULL)
  {
    GumBackpatch p;

    p.type = GUM_BACKPATCH_JMP;
    p.to = block->real_start;
    p.from = from->real_start;
    p.from_insn = from_insn;
    p.jmp.code_offset = code_offset;
    p.jmp.opened_prolog = opened_prolog;

    gum_stalker_observer_notify_backpatch (ctx->observer, &p, sizeof (p));
  }
}

/*
 * In AArch64, we are limited to 28-bit signed offsets for immediate branches.
 * If we need to branch a larger distance, then we must clobber a register to
 * hold the destination address. If this is the case, we first push those
 * registers beyond the red-zone and then perform the branch.
 *
 * Each GumExecBlock is initialized to start with a:
 *
 *   ldp x16, x17, [sp], #0x90
 *
 * Therefore if we are able to branch directly to a block, we skip this first
 * instruction. Since this is emitted before any code generated by the
 * transformer, this anomaly goes largely unnoticed by the user. However, care
 * must be taken when using the switch-block callback to take this into account.
 */
static void
gum_exec_block_write_jmp_to_block_start (GumExecBlock * block,
                                         gpointer block_start)
{
  GumArm64Writer * cw = &block->ctx->code_writer;
  const GumAddress address = GUM_ADDRESS (block_start);
  const GumAddress body_address = address + GUM_RESTORATION_PROLOG_SIZE;

  if (gum_arm64_writer_can_branch_directly_between (cw, cw->pc, body_address))
  {
    gum_arm64_writer_put_b_imm (cw, body_address);
  }
  else
  {
    gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
        ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
        GUM_INDEX_PRE_ADJUST);
    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16, address);
    gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X16);
  }
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
  gum_exec_ctx_query_block_switch_callback (ctx, block, block->real_start,
      from_insn, &target);

  ic_entries = from->ic_entries;
  g_assert (ic_entries != NULL);
  num_ic_entries = ctx->stalker->ic_entries;

  for (i = 0; i != num_ic_entries; i++)
  {
    if (ic_entries[i].real_start == NULL)
      break;
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
  const guint id = insn->ci->id;
  GumArm64Writer * cw = gc->code_writer;
  cs_arm64 * arm64 = &insn->ci->detail->arm64;
  cs_arm64_op * op = &arm64->operands[0];
  cs_arm64_op * op2 = NULL;
  cs_arm64_op * op3 = NULL;
  arm64_cc cc = arm64->cc;
  gboolean is_conditional;
  GumBranchTarget target = { 0, };

  g_assert (arm64->op_count != 0);

  is_conditional = (id == ARM64_INS_B && cc != ARM64_CC_INVALID) ||
      (id == ARM64_INS_CBZ) || (id == ARM64_INS_CBNZ
```