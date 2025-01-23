Response:
Let's break down the thought process for analyzing this C code snippet.

**1. Initial Understanding & Context:**

* **File Path:** `frida/subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c` immediately tells us this is part of Frida's dynamic instrumentation engine, specifically the Stalker component for ARM64 architecture. Stalker is responsible for tracing and manipulating code execution.
* **"Part 5 of 6":**  This suggests we're looking at a modular piece of a larger system. The current part likely handles specific aspects of code instrumentation.
* **Keywords:** "dynamic instrumentation," "stalker," "ARM64" are crucial for framing the functionality.

**2. High-Level Goal Identification:**

The core function of Stalker is to *intercept and modify the execution flow* of a program. This file likely contains the logic for intercepting specific ARM64 instructions and redirecting execution to Frida's instrumentation code.

**3. Analyzing Key Functions (Iterative Process):**

I would start by looking at the functions that appear to handle different instruction types. The naming is quite descriptive:

* `gum_exec_block_virtualize_unconditional_branch_insn`:  Handles unconditional branches (like `B`, `BL`).
* `gum_exec_block_virtualize_conditional_branch_insn`: Handles conditional branches (`CBZ`, `CBNZ`, `TBZ`, `TBNZ`).
* `gum_exec_block_virtualize_ret_insn`: Handles `RET` instructions.
* `gum_exec_block_virtualize_sysenter_insn` and `gum_exec_block_virtualize_linux_sysenter`: Handle system calls (`SVC`).

For each of these, I would try to understand the following:

* **Input:** What information does the function receive? (e.g., `GumExecBlock`, `GumGeneratorContext`, instruction details).
* **Core Logic:** What are the main steps involved?  Look for key operations like:
    * **Instruction Decoding:**  Accessing `insn->ci->detail->arm64` and its operands.
    * **Code Generation:** Using `GumArm64Writer` to emit new ARM64 instructions.
    * **Relocation:**  Using `gum_arm64_relocator_skip_one` or `gum_arm64_relocator_write_one`.
    * **Entry Gates:**  Calls to `GUM_ENTRYGATE(...)`, indicating transitions to pre-compiled Frida runtime code.
    * **Event Emission:** Calls to `gum_exec_block_write_*_event_code`, suggesting notifications of events like calls or returns.
    * **Slab Management:**  References to "fast slab" and "slow slab."
    * **Backpatching:**  Functions like `gum_exec_block_backpatch_call`, `gum_exec_block_backpatch_jmp`, `gum_exec_block_backpatch_inline_cache`.
* **Output:**  What does the function conceptually produce? (Modified execution flow, generated code).

**4. Identifying Connections to Reverse Engineering:**

As I analyze the code generation logic, I'd be looking for how Frida intercepts the original instruction's behavior and inserts its own. For example:

* **Branch Redirection:**  How branches are modified to jump to Frida's code.
* **Call Interception:** How calls are intercepted to execute Frida's logic before or after the original call.
* **Return Interception:** How returns are intercepted.
* **Register Manipulation:**  While not heavily present in *this* snippet, I'd be aware that Frida often needs to save/restore registers.

**5. Identifying Connections to Low-Level Concepts:**

* **ARM64 Architecture:** The code uses ARM64-specific data structures (`cs_arm64`, `arm64_reg`), instruction IDs (`ARM64_INS_B`), and calling conventions.
* **Binary Code:**  The code manipulates raw bytes of instructions (`insn->bytes`).
* **Memory Management:** Concepts like "red zone," "page size," and memory addresses are present.
* **Operating System (Linux/Android):** The handling of `SYSENTER` and the `#ifdef HAVE_LINUX` clearly link to OS-specific system call mechanisms. The mention of `__NR_clone` is a direct reference to a Linux system call number.
* **Kernel/Framework (Implicit):** While not directly interacting with the kernel in this code, the *purpose* of this code is to instrument applications running on top of the kernel and potentially frameworks.

**6. Logical Reasoning and Assumptions:**

* **Conditional Logic:**  The `if (is_conditional)` blocks show how conditional branches are handled differently.
* **Assumptions:** The `g_assert` statements highlight assumptions the code makes about the structure of instructions. For example, `g_assert (op->type == ARM64_OP_IMM);` assumes a specific operand type for certain instructions.
* **Input/Output (Hypothetical):** If I saw a `B` instruction with a specific target address, I could trace how Frida would generate code to jump to its instrumentation logic and then potentially to the original target.

**7. Identifying Potential User Errors:**

I'd look for scenarios where improper Frida usage could lead to issues:

* **Incorrect Instrumentation Logic:** If a user's transformer code corrupts registers or the stack, it could break the program.
* **Performance Overhead:**  Excessive instrumentation can slow down the target process.
* **Conflicts with Other Tools:** Frida might interfere with other debugging or instrumentation tools.

**8. Tracing User Actions (Debugging Clues):**

I'd consider how a developer using Frida would reach this code:

1. **Attach to a process:** The user uses Frida to connect to a running application.
2. **Enable Stalker:** The user activates Frida's Stalker to begin tracing execution.
3. **Specify instrumentation points:**  The user defines where they want to intercept code (e.g., at function entry, specific addresses).
4. **Stalker encounters an instruction:** As the target application runs, Stalker encounters instructions within the specified ranges.
5. **Dispatch to virtualization functions:** Stalker determines the instruction type and calls the appropriate `gum_exec_block_virtualize_*` function in this file.

**9. Synthesizing the Summary (Instruction Following and Code Generation):**

By combining the understanding of individual functions and their roles, I can summarize the overall purpose: This part of Frida's Stalker for ARM64 is responsible for intercepting specific control-flow instructions (branches, calls, returns, system calls), generating new code that redirects execution to Frida's instrumentation logic, and managing the transitions between the original code and the generated code. It uses techniques like inline caching and backpatching to optimize performance and ensure correct execution flow.

**Self-Correction/Refinement:**

During this process, I might initially misinterpret a function's purpose or overlook certain details. Reviewing the code comments, paying attention to variable names, and understanding the context of the surrounding code helps refine my understanding. For instance, initially, I might not fully grasp the purpose of the "fast slab" and "slow slab," but further analysis of the code generation and backpatching logic would clarify their roles in optimizing execution.
Let's break down the functionality of the `gumstalker-arm64.c` file, focusing on its role within Frida's dynamic instrumentation framework.

**Core Functionality Summarized (Based on the Snippet):**

This code file is a crucial part of Frida's Stalker component on ARM64 architecture. Its primary responsibility is to **dynamically rewrite and instrument ARM64 machine code** as the target process executes. It intercepts specific instructions and replaces them with code that transfers control to Frida's runtime, allowing for inspection and modification of program behavior.

**Detailed Breakdown of Functionality and Connections:**

**1. Instruction Virtualization and Code Generation:**

* **Identifying Control Flow Instructions:** The code focuses heavily on intercepting instructions that alter the program's control flow:
    * **Branches (B, BL, BR, CBZ, CBNZ, TBZ, TBNZ):**  These instructions change the execution address.
    * **Calls (BL, BLR):** These instructions invoke subroutines.
    * **Returns (RET):** These instructions return from subroutines.
    * **System Calls (SYSENTER - Linux Specific):** These instructions request services from the operating system kernel.
* **"Virtualization":**  The functions named `gum_exec_block_virtualize_*_insn` are responsible for "virtualizing" these instructions. This means they don't let the original instruction execute directly. Instead, they generate new sequences of ARM64 instructions that:
    * **Potentially execute Frida's instrumentation logic:**  This could involve calling user-defined JavaScript hooks, logging data, or modifying registers/memory.
    * **Handle transitions between original and instrumented code:** This often involves jumping to Frida's runtime environment.
    * **Optionally execute the original instruction or its intended effect:** For example, a branch might be redirected to Frida's code and then, after instrumentation, continue to the original branch target.
* **Code Writers (`GumArm64Writer`):** The code uses `GumArm64Writer` to generate the new ARM64 instructions that implement the virtualization logic. This involves putting specific opcode sequences into memory.

**2. Relationship to Reverse Engineering:**

* **Dynamic Code Analysis:** This is a fundamental technique in reverse engineering. Frida, with components like Stalker, allows reverse engineers to observe the runtime behavior of an application, including:
    * **Tracing Execution Flow:**  See the exact sequence of instructions executed.
    * **Inspecting Function Calls and Returns:** Understand how functions interact.
    * **Monitoring System Calls:** Observe the application's interactions with the operating system.
    * **Analyzing Conditional Branches:** Determine the conditions that lead to different execution paths.
* **Example:** When a `BL` (Branch with Link, a call instruction) is encountered, this code can intercept it. Frida can then:
    1. **Log the call:** Record the address of the called function and the arguments.
    2. **Modify arguments:** Change the values passed to the function.
    3. **Prevent the call:**  Stop the original function from being executed.
    4. **Execute custom code before or after the call:** Implement custom logic to analyze the function's behavior.

**3. Binary Level, Linux, Android Kernel & Framework Knowledge:**

* **ARM64 Instruction Set:** The code directly manipulates ARM64 instructions. Understanding opcodes, operand types (registers, immediates), and addressing modes is crucial. You see this in the `switch` statements based on `insn->id` (instruction ID) and the handling of operands (`op`, `op2`, `op3`).
* **Binary Code Manipulation:**  The code works at the level of raw bytes (`insn->bytes`). Frida needs to be able to read, interpret, and rewrite these bytes.
* **Linux System Calls:** The `gum_exec_block_virtualize_sysenter_insn` and related functions demonstrate knowledge of how system calls are made on Linux (using the `SVC` instruction, often historically referred to as `SYSENTER` on x86). The code specifically checks for the `clone` system call (`__NR_clone`) and handles it specially due to its implications for process forking.
* **Memory Management (Red Zone, Page Size):** The code mentions the "red zone" (a small area below the stack pointer that functions can use without explicitly allocating space) and "page size" (the granularity of memory management). This indicates an understanding of low-level memory layout.
* **Function Calling Conventions:** The way Frida intercepts calls and returns implies an understanding of the ARM64 calling convention (how arguments are passed, where the return address is stored, etc.).
* **Excluded Calls (Implicit Framework Knowledge):** The handling of `target_is_excluded` suggests that Frida can be configured to avoid instrumenting certain function calls. This might be for performance reasons or to avoid interfering with critical system functions.

**4. Logical Reasoning and Assumptions:**

* **Instruction Decoding Assumptions:** The `g_assert` statements make assumptions about the structure of the decoded instructions (e.g., the number and types of operands). If these assumptions are violated (due to malformed code or unexpected instruction variations), the code might crash or behave incorrectly.
* **Conditional Branch Logic:** The code correctly handles conditional branches by generating code that checks the condition codes and jumps accordingly. The `is_conditional` flag and the manipulation of condition codes (`cc`, `not_cc`) are evidence of this.
* **Call/Return Stack Management:** The `gum_exec_ctx_write_adjust_depth` function suggests that Frida tracks the call stack depth, which is important for managing the instrumentation context.
* **Inline Caching (Optimization):** The code mentions "inline caches" and "fast slab/slow slab." This is an optimization technique. Frequently executed code paths (the "fast slab") might have direct jumps, while less frequent paths or those requiring more complex instrumentation go through a "slow slab" with more overhead.

**5. User or Programming Errors:**

* **Incorrect Transformer Logic:** If a user writes a Frida script that modifies registers or memory in a way that violates the ARM64 calling convention or program invariants, it can lead to crashes or unexpected behavior.
* **Infinite Loops in Transformers:** If the instrumentation logic itself enters an infinite loop, it will hang the target process.
* **Resource Exhaustion:**  Excessive logging or complex instrumentation can consume a lot of memory or CPU, potentially crashing the target application.
* **Example (Conceptual):** A user might write a Frida script to intercept a function call and modify an argument that is expected to be within a specific range. If the user sets it to an out-of-bounds value, the called function might crash.

**6. User Operations to Reach This Code (Debugging Clues):**

1. **User attaches Frida to a target process:**  For example, using `frida -p <pid>`.
2. **User enables Stalker:**  In the Frida script, the user would likely use `Stalker.follow()` or `Stalker.add(ranges)`.
3. **Target process executes code:** As the target application runs, the CPU fetches and decodes instructions.
4. **Stalker intercepts a relevant instruction:** When the instruction pointer (IP) reaches an instruction that Stalker is monitoring (e.g., a `BL` instruction within a followed range), Stalker's core logic identifies it.
5. **Dispatch to the appropriate `gum_exec_block_virtualize_*` function:** Based on the instruction's opcode, the execution is routed to the corresponding virtualization function in `gumstalker-arm64.c`.
6. **Code generation and backpatching occur:** The functions in this file generate new ARM64 code to perform the instrumentation, potentially modifying the original code in memory (backpatching).

**7. Summary of Functionality (Part 5 of 6):**

This specific part of `gumstalker-arm64.c` focuses on the **core logic of intercepting and rewriting control flow instructions (branches, calls, returns, and system calls) on ARM64**. It generates the necessary ARM64 code to redirect execution to Frida's instrumentation runtime, enabling dynamic analysis and manipulation of the target process. It leverages knowledge of the ARM64 architecture, binary code structure, and operating system calling conventions to achieve this. The concepts of "fast" and "slow" paths (slabs) suggest an optimization strategy for handling frequently and infrequently instrumented code.

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
) ||
      (id == ARM64_INS_TBZ) || (id == ARM64_INS_TBNZ);

  target.origin_ip = insn->end;

  switch (id)
  {
    case ARM64_INS_B:
    case ARM64_INS_BL:
      g_assert (op->type == ARM64_OP_IMM);

      target.absolute_address = GSIZE_TO_POINTER (op->imm);
      target.reg = ARM64_REG_INVALID;

      break;
    case ARM64_INS_BR:
    case ARM64_INS_BRAA:
    case ARM64_INS_BRAAZ:
    case ARM64_INS_BRAB:
    case ARM64_INS_BRABZ:
    case ARM64_INS_BLR:
    case ARM64_INS_BLRAA:
    case ARM64_INS_BLRAAZ:
    case ARM64_INS_BLRAB:
    case ARM64_INS_BLRABZ:
      g_assert (op->type == ARM64_OP_REG);

      target.reg = op->reg;

      break;
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
      op2 = &arm64->operands[1];

      g_assert (op->type == ARM64_OP_REG);
      g_assert (op2->type == ARM64_OP_IMM);

      target.absolute_address = GSIZE_TO_POINTER (op2->imm);
      target.reg = ARM64_REG_INVALID;

      break;
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
      op2 = &arm64->operands[1];
      op3 = &arm64->operands[2];

      g_assert (op->type == ARM64_OP_REG);
      g_assert (op2->type == ARM64_OP_IMM);
      g_assert (op3->type == ARM64_OP_IMM);

      target.absolute_address = GSIZE_TO_POINTER (op3->imm);
      target.reg = ARM64_REG_INVALID;

      break;
    default:
      g_assert_not_reached ();
  }

  switch (id)
  {
    case ARM64_INS_B:
    case ARM64_INS_BR:
    case ARM64_INS_BRAA:
    case ARM64_INS_BRAAZ:
    case ARM64_INS_BRAB:
    case ARM64_INS_BRABZ:
    case ARM64_INS_CBZ:
    case ARM64_INS_CBNZ:
    case ARM64_INS_TBZ:
    case ARM64_INS_TBNZ:
    {
      gpointer is_false;
      GumExecCtxReplaceCurrentBlockFunc regular_entry_func, cond_entry_func;

      gum_arm64_relocator_skip_one (gc->relocator);

      is_false =
          GUINT_TO_POINTER ((GPOINTER_TO_UINT (insn->start) << 16) | 0xbeef);

      if (is_conditional)
      {
        gum_exec_block_close_prolog (block, gc, gc->code_writer);

        regular_entry_func = NULL;

        /* jump to is_false if is_false */
        switch (id)
        {
          case ARM64_INS_B:
          {
            arm64_cc not_cc;

            g_assert (cc != ARM64_CC_INVALID);
            g_assert (cc > ARM64_CC_INVALID);
            g_assert (cc <= ARM64_CC_NV);

            not_cc = cc + 2 * (cc % 2) - 1;
            gum_arm64_writer_put_b_cond_label (cw, not_cc, is_false);

            cond_entry_func = GUM_ENTRYGATE (jmp_cond_cc);

            break;
          }
          case ARM64_INS_CBZ:
            gum_arm64_writer_put_cbnz_reg_label (cw, op->reg, is_false);
            cond_entry_func = GUM_ENTRYGATE (jmp_cond_cbz);
            break;
          case ARM64_INS_CBNZ:
            gum_arm64_writer_put_cbz_reg_label (cw, op->reg, is_false);
            cond_entry_func = GUM_ENTRYGATE (jmp_cond_cbnz);
            break;
          case ARM64_INS_TBZ:
            gum_arm64_writer_put_tbnz_reg_imm_label (cw, op->reg, op2->imm,
                is_false);
            cond_entry_func = GUM_ENTRYGATE (jmp_cond_tbz);
            break;
          case ARM64_INS_TBNZ:
            gum_arm64_writer_put_tbz_reg_imm_label (cw, op->reg, op2->imm,
                is_false);
            cond_entry_func = GUM_ENTRYGATE (jmp_cond_tbnz);
            break;
          default:
            cond_entry_func = NULL;
            g_assert_not_reached ();
        }
      }
      else
      {
        if (target.reg != ARM64_REG_INVALID)
          regular_entry_func = GUM_ENTRYGATE (jmp_reg);
        else
          regular_entry_func = GUM_ENTRYGATE (jmp_imm);
        cond_entry_func = NULL;
      }

      gum_exec_block_write_jmp_transfer_code (block, &target,
          is_conditional ? cond_entry_func : regular_entry_func, gc);

      if (is_conditional)
      {
        GumBranchTarget cond_target = { 0, };

        cond_target.absolute_address = insn->end;
        cond_target.reg = ARM64_REG_INVALID;

        gum_arm64_writer_put_label (cw, is_false);

        gum_exec_block_write_jmp_transfer_code (block, &cond_target,
            cond_entry_func, gc);
      }

      break;
    }
    case ARM64_INS_BL:
    case ARM64_INS_BLR:
    case ARM64_INS_BLRAA:
    case ARM64_INS_BLRAAZ:
    case ARM64_INS_BLRAB:
    case ARM64_INS_BLRABZ:
    {
      gboolean target_is_excluded = FALSE;

      if ((ctx->sink_mask & GUM_CALL) != 0)
      {
        gum_exec_block_write_call_event_code (block, &target, gc,
            GUM_CODE_INTERRUPTIBLE);
      }

      if (target.reg == ARM64_REG_INVALID &&
          ctx->activation_target == NULL)
      {
        target_is_excluded =
            gum_stalker_is_excluding (ctx->stalker, target.absolute_address);
      }

      if (target_is_excluded)
      {
        GumBranchTarget next_instruction = { 0, };

        gum_exec_block_close_prolog (block, gc, gc->code_writer);

        /*
         * Since write_begin_call() and write_end_call() are implemented as
         * generated code, we can make the necessary updates to the ExecCtx
         * without the overhead of opening and closing a prolog.
         */
        gum_exec_ctx_write_begin_call (ctx, cw, insn->end);
        gum_arm64_relocator_write_one (gc->relocator);
#ifdef HAVE_LINUX
        gum_metal_hash_table_insert (ctx->excluded_calls, cw->code, insn->end);
#endif
        gum_exec_ctx_write_end_call (ctx, cw);

        next_instruction.absolute_address = insn->end;
        next_instruction.reg = ARM64_REG_INVALID;
        gum_exec_block_write_jmp_transfer_code (block, &next_instruction,
            GUM_ENTRYGATE (excluded_call_imm), gc);

        return GUM_REQUIRE_NOTHING;
      }

      gum_arm64_relocator_skip_one (gc->relocator);
      gum_exec_block_write_call_invoke_code (block, &target, gc);

      break;
    }
    default:
      g_assert_not_reached ();
  }

  return GUM_REQUIRE_NOTHING;
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_ret_insn (GumExecBlock * block,
                                    GumGeneratorContext * gc)
{
  GumInstruction * insn;
  cs_arm64 * arm64;
  cs_arm64_op * op;
  arm64_reg ret_reg;

  if ((block->ctx->sink_mask & GUM_RET) != 0)
    gum_exec_block_write_ret_event_code (block, gc, GUM_CODE_INTERRUPTIBLE);

  insn = gc->instruction;
  arm64 = &insn->ci->detail->arm64;

  if (arm64->op_count == 0)
  {
    ret_reg = ARM64_REG_X30;
  }
  else
  {
    g_assert (arm64->op_count == 1);

    op = &arm64->operands[0];
    g_assert (op->type == ARM64_OP_REG);

    ret_reg = op->reg;
  }
  gum_arm64_relocator_skip_one (gc->relocator);
  gum_exec_block_write_ret_transfer_code (block, gc, ret_reg);

  return GUM_REQUIRE_NOTHING;
}

static GumVirtualizationRequirements
gum_exec_block_virtualize_sysenter_insn (GumExecBlock * block,
                                         GumGeneratorContext * gc)
{
#ifdef HAVE_LINUX
  return gum_exec_block_virtualize_linux_sysenter (block, gc);
#else
  return GUM_REQUIRE_RELOCATION;
#endif
}

#ifdef HAVE_LINUX

static GumVirtualizationRequirements
gum_exec_block_virtualize_linux_sysenter (GumExecBlock * block,
                                          GumGeneratorContext * gc)
{
  GumArm64Writer * cw = gc->code_writer;
  const cs_insn * insn = gc->instruction->ci;
  gconstpointer perform_clone_syscall = cw->code + 1;
  gconstpointer perform_regular_syscall = cw->code + 2;
  gconstpointer perform_next_instruction = cw->code + 3;

  gum_arm64_relocator_skip_one (gc->relocator);

  if (gc->opened_prolog != GUM_PROLOG_NONE)
    gum_exec_block_close_prolog (block, gc, cw);

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X15, ARM64_REG_X17,
      ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE), GUM_INDEX_PRE_ADJUST);
  gum_arm64_writer_put_mov_reg_nzcv (cw, ARM64_REG_X15);

  gum_arm64_writer_put_sub_reg_reg_imm (cw, ARM64_REG_X17,
      ARM64_REG_X8, __NR_clone);
  gum_arm64_writer_put_cbz_reg_label (cw, ARM64_REG_X17,
      perform_clone_syscall);
  gum_arm64_writer_put_b_label (cw, perform_regular_syscall);

  gum_arm64_writer_put_label (cw, perform_clone_syscall);
  gum_arm64_writer_put_mov_nzcv_reg (cw, ARM64_REG_X15);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X15,
      ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
  gum_exec_block_put_aligned_syscall (block, gc, insn);
  gum_arm64_writer_put_b_label (cw, perform_next_instruction);

  gum_arm64_writer_put_label (cw, perform_regular_syscall);
  gum_arm64_writer_put_mov_nzcv_reg (cw, ARM64_REG_X15);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X15,
      ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
  gum_arm64_writer_put_bytes (cw, insn->bytes, 4);

  gum_arm64_writer_put_label (cw, perform_next_instruction);

  return GUM_REQUIRE_NOTHING;
}

static void
gum_exec_block_put_aligned_syscall (GumExecBlock * block,
                                    GumGeneratorContext * gc,
                                    const cs_insn * insn)
{
  GumArm64Writer * cw = gc->code_writer;
  gsize page_size, page_mask;
  guint page_offset_start, pad_start;
  guint page_offset_end, pad_end;
  guint i;
  gconstpointer start = cw->code + 1;
  gconstpointer not_child = cw->code + 2;
  gconstpointer end = cw->code + 3;

  /*
   * If we have reached this point, then we know that the syscall being
   * performed was a clone. This means that both the calling thread and the
   * newly spawned thread will begin execution from the point immediately after
   * the SVC instruction. However, this causes a potential race condition, if
   * the calling thread attempts to either compile a new block, or backpatch
   * an existing one in the same page. During patching the block may be thawed
   * leading to the target thread (which may be stalled at the mercy of the
   * scheduler) attempting to execute a non-executable page.
   */

  page_size = gum_query_page_size ();
  page_mask = page_size - 1;

  page_offset_start = GPOINTER_TO_SIZE (cw->code) & page_mask;
  g_assert ((page_offset_start % 4) == 0);
  pad_start = (page_size - page_offset_start) / 4;

  if (pad_start != 0)
  {
    gum_arm64_writer_put_b_label (cw, start);

    for (i = 0; i != pad_start; i++)
      gum_arm64_writer_put_brk_imm (cw, 15);

    gum_arm64_writer_put_label (cw, start);
  }

  gum_arm64_writer_put_bytes (cw, insn->bytes, insn->size);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X0, not_child);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X17,
      GUM_ADDRESS (gc->instruction->start + GUM_RESTORATION_PROLOG_SIZE));
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X17);

  gum_arm64_writer_put_label (cw, not_child);

  page_offset_end = GPOINTER_TO_SIZE (cw->code) & page_mask;
  g_assert ((page_offset_end % 4) == 0);
  pad_end = (page_size - page_offset_end) / 4;

  if (pad_end != 0)
  {
    gum_arm64_writer_put_b_label (cw, end);

    for (i = 0; i != pad_end; i++)
      gum_arm64_writer_put_brk_imm (cw, 16);

    gum_arm64_writer_put_label (cw, end);
  }
}

#endif

static void
gum_exec_block_write_call_invoke_code (GumExecBlock * block,
                                       const GumBranchTarget * target,
                                       GumGeneratorContext * gc)
{
  GumExecCtx * ctx = block->ctx;
  GumStalker * stalker = ctx->stalker;
  const gint trust_threshold = stalker->trust_threshold;
  GumArm64Writer * cw = gc->code_writer;
  GumArm64Writer * cws = gc->slow_writer;
  const GumAddress call_code_start = cw->pc;
  const GumPrologType opened_prolog = gc->opened_prolog;
  gboolean can_backpatch_statically;
  GumAddress ret_real_address = GUM_ADDRESS (gc->instruction->end);
  GumPrologType second_prolog;
  GumExecCtxReplaceCurrentBlockFunc entry_func;
  gconstpointer is_excluded = cw->code + 1;
  gconstpointer keep_this_blr = cw->code + 2;

  can_backpatch_statically =
      trust_threshold >= 0 &&
      target->reg == ARM64_REG_INVALID;

  gum_exec_ctx_write_adjust_depth (ctx, cw, 1);

  if (trust_threshold >= 0 && !can_backpatch_statically)
  {
    arm64_reg result_reg;

    gum_exec_block_close_prolog (block, gc, cw);

    /*
     * The call invoke code will transfer control to the slow slab in the event
     * of a cache miss. Otherwise, it will return control to the code (fast)
     * slab with the values of X16/X17 still pushed above the red-zone.
     *
     * If the low bit of the target address is set, then this denotes an
     * excluded call and we therefore branch further down the fast slab to
     * handle it.
     */
    result_reg = gum_exec_block_write_inline_cache_code (block, target->reg,
        cw, cws);

    gum_arm64_writer_put_tbnz_reg_imm_label (cw, result_reg, 0, is_excluded);

    gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_LR, ret_real_address);
    gum_arm64_writer_put_br_reg_no_auth (cw, result_reg);

    /* Handle excluded call */
    gum_arm64_writer_put_label (cw, is_excluded);
  }
  else
  {
    guint i;

    /*
     * If we don't have an inline cache (the branch is immediate or the code
     * isn't trusted), then we jump directly to the slow slab. If an indirect
     * branch is backpatched, then this will be overwritten along with the
     * subsequent padding with code to carry out a direct branch to the relevant
     * instrumented block.
     */
    gum_exec_block_write_slab_transfer_code (cw, cws);

    /*
     * We need some padding so the backpatching doesn't overwrite the return
     * handling logic below.
     */
    for (i = 0; i != 10; i++)
      gum_arm64_writer_put_nop (cw);
  }

  /* Slow Path */

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc, cws);
  second_prolog = gc->opened_prolog;

  if (target->reg == ARM64_REG_INVALID)
  {
    entry_func = GUM_ENTRYGATE (call_imm);
  }
  else
  {
    /*
     * Check if the call target is excluded, and branch further down the slow
     * slab to perform any necessary backpatching before it is called.
     */
    gum_exec_ctx_write_push_branch_target_address (ctx, target, gc, cws);
    gum_arm64_writer_put_pop_reg_reg (cws, ARM64_REG_X0, ARM64_REG_X1);

    gum_arm64_writer_put_call_address_with_arguments (cws,
        GUM_ADDRESS (gum_exec_block_check_address_for_exclusion), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_REGISTER, ARM64_REG_X1);

    gum_arm64_writer_put_cbz_reg_label (cws, ARM64_REG_X0, keep_this_blr);

    entry_func = GUM_ENTRYGATE (call_reg);
  }

  /*
   * Fetch the relevant block using the entry gate.
   */
  gum_exec_ctx_write_push_branch_target_address (ctx, target, gc, cws);
  gum_arm64_writer_put_pop_reg_reg (cws, ARM64_REG_X0, ARM64_REG_X1);

  gum_arm64_writer_put_call_address_with_arguments (cws,
      GUM_ADDRESS (entry_func), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM64_REG_X1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  /* Perform any relevant backpatching */
  if (trust_threshold >= 0)
  {
    gum_arm64_writer_put_ldr_reg_address (cws, ARM64_REG_X0,
        GUM_ADDRESS (&ctx->current_block));
    gum_arm64_writer_put_ldr_reg_reg_offset (cws, ARM64_REG_X0,
        ARM64_REG_X0, 0);
  }

  if (can_backpatch_statically)
  {
    gum_arm64_writer_put_call_address_with_arguments (cws,
        GUM_ADDRESS (gum_exec_block_backpatch_call), 6,
        GUM_ARG_REGISTER, ARM64_REG_X0,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
        GUM_ARG_ADDRESS, call_code_start - GUM_ADDRESS (block->code_start),
        GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog),
        GUM_ARG_ADDRESS, ret_real_address);
  }
  else if (trust_threshold >= 0)
  {
    gum_arm64_writer_put_call_address_with_arguments (cws,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 3,
        GUM_ARG_REGISTER, ARM64_REG_X0,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  }

  /* Branch to the target block */
  gum_exec_block_close_prolog (block, gc, cws);
  gum_arm64_writer_put_ldr_reg_address (cws, ARM64_REG_LR, ret_real_address);
  gum_exec_block_write_exec_generated_code (cws, ctx);

  if (target->reg != ARM64_REG_INVALID)
  {
    GumInstruction * insn = gc->instruction;
    GumBranchTarget next_insn_as_target = { 0, };

    next_insn_as_target.absolute_address = insn->end;
    next_insn_as_target.reg = ARM64_REG_INVALID;

    /* Handle excluded calls */
    gum_arm64_writer_put_label (cws, keep_this_blr);

    if (target->reg != ARM64_REG_X1)
      gum_arm64_writer_put_mov_reg_reg (cws, ARM64_REG_X1, target->reg);

    /*
     * Backpatch the excluded call into the same inline cache used for
     * non-excluded calls above. We set the low bit of the code_address to
     * denote that this should be handled as an excluded call.
     */
    gum_arm64_writer_put_call_address_with_arguments (cws,
        GUM_ADDRESS (gum_exec_block_backpatch_excluded_call), 3,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_REGISTER, ARM64_REG_X1,
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

    gc->opened_prolog = second_prolog;

    gum_exec_block_close_prolog (block, gc, cws);

    /* Branch back to the fast slab to actually execute the target function */
    gum_exec_block_write_slab_transfer_code (cws, cw);

    /* Fast Path */
    gum_exec_ctx_write_begin_call (ctx, cw, gc->instruction->end);

    /*
     * We use the original target register as the target for the branch and
     * therefore don't have to strip the low bit from the target address
     * returned from the inline cache code.
     */
    gum_arm64_writer_put_bytes (cw, insn->start, insn->ci->size);

#ifdef HAVE_LINUX
    gum_metal_hash_table_insert (ctx->excluded_calls, cw->code, insn->end);
#endif

    gum_exec_ctx_write_end_call (ctx, cw);

    /*
     * Write the standard jmp transfer code to vector to the instruction
     * immediately following the call.
     */
    gum_exec_block_write_jmp_transfer_code (block, &next_insn_as_target,
        GUM_ENTRYGATE (excluded_call_reg), gc);
  }
}

static void
gum_exec_ctx_write_begin_call (GumExecCtx * ctx,
                               GumArm64Writer * cw,
                               gpointer ret_addr)
{
  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
      ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);

  /* ctx->pending_return_location = ret_addr; */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->pending_return_location));
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X17,
      GUM_ADDRESS (ret_addr));
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);

  /* ctx->pending_calls++ */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->pending_calls));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);
  gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X17, ARM64_REG_X17, 1);
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);

  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
      ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
}

static void
gum_exec_ctx_write_end_call (GumExecCtx * ctx,
                             GumArm64Writer * cw)
{
  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
      ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);

  /* ctx->pending_calls-- */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->pending_calls));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);
  gum_arm64_writer_put_sub_reg_reg_imm (cw, ARM64_REG_X17, ARM64_REG_X17, 1);
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);

  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16,
      ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);
}

static void
gum_exec_block_backpatch_excluded_call (GumExecBlock * block,
                                        gpointer target,
                                        gpointer from_insn)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  GumIcEntry * ic_entries;
  guint num_ic_entries, i;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;
  if (!gum_exec_ctx_may_now_backpatch (ctx, block))
    return;
  if (!gum_exec_ctx_contains (ctx, target))
    return;

  ic_entries = block->ic_entries;
  g_assert (ic_entries != NULL);
  num_ic_entries = ctx->stalker->ic_entries;

  for (i = 0; i != num_ic_entries; i++)
  {
    if (ic_entries[i].real_start == target)
      return;
  }

  gum_spinlock_acquire (&ctx->code_lock);

  memmove (&ic_entries[1], &ic_entries[0],
      (num_ic_entries - 1) * sizeof (GumIcEntry));

  ic_entries[0].real_start = target;
  ic_entries[0].code_start = (guint8 *) target + 1;

  gum_spinlock_release (&ctx->code_lock);

  /*
   * We can prefetch backpatches to excluded calls since we are dealing with
   * real rather than instrumented addresses. Whilst blocks may not necessarily
   * be instrumented in the same location in the forkserver and its child
   * (block may not be compiled in the same order for example, or allocators may
   * be non-deterministic), since the address space is the same for each, the
   * real addresses which we are dealing with here will be the same. Note that
   * this is contrary to backpatches for returns into the slab.
   */
  if (ctx->observer != NULL)
  {
    GumBackpatch p;

    p.type = GUM_BACKPATCH_EXCLUDED_CALL;
    p.to = target;
    p.from = block->real_start;
    p.from_insn = from_insn;

    gum_stalker_observer_notify_backpatch (ctx->observer, &p, sizeof (p));
  }
}

static void
gum_exec_block_write_jmp_transfer_code (GumExecBlock * block,
                                        const GumBranchTarget * target,
                                        GumExecCtxReplaceCurrentBlockFunc func,
                                        GumGeneratorContext * gc)
{
  GumStalker * stalker = block->ctx->stalker;
  const gint trust_threshold = stalker->trust_threshold;
  GumArm64Writer * cw = gc->code_writer;
  GumArm64Writer * cws = gc->slow_writer;
  const GumAddress code_start = cw->pc;
  const GumPrologType opened_prolog = gc->opened_prolog;
  gboolean can_backpatch_statically;

  can_backpatch_statically =
      trust_threshold >= 0 &&
      target->reg == ARM64_REG_INVALID;

  if (trust_threshold >= 0 && !can_backpatch_statically)
  {
    arm64_reg result_reg;

    gum_exec_block_close_prolog (block, gc, cw);

    /*
     * The call invoke code will transfer control to the slow slab in the event
     * of a cache miss. Otherwise, it will return control to the code (fast)
     * slab with the values of X16/X17 still pushed above the red-zone.
     */
    result_reg = gum_exec_block_write_inline_cache_code (block, target->reg,
        cw, cws);
    gum_arm64_writer_put_br_reg_no_auth (cw, result_reg);
  }
  else
  {
    guint i;

    /*
     * If we don't have an inline cache (the branch is immediate or the code
     * isn't trusted), then we jump directly to the slow slab. If an indirect
     * branch is backpatched, then this will be overwritten along with the
     * subsequent padding with code to carry out a direct branch to the relevant
     * instrumented block.
     */
    gum_exec_block_write_slab_transfer_code (cw, cws);

    for (i = 0; i != 10; i++)
      gum_arm64_writer_put_nop (cw);
  }

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc, cws);

  gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc, cws);
  gum_arm64_writer_put_pop_reg_reg (cws, ARM64_REG_X0, ARM64_REG_X1);

  gum_arm64_writer_put_call_address_with_arguments (cws,
      GUM_ADDRESS (func), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM64_REG_X1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  if (trust_threshold >= 0)
  {
    gum_arm64_writer_put_ldr_reg_address (cws, ARM64_REG_X0,
        GUM_ADDRESS (&block->ctx->current_block));
    gum_arm64_writer_put_ldr_reg_reg_offset (cws, ARM64_REG_X0,
        ARM64_REG_X0, 0);
  }

  if (can_backpatch_statically)
  {
    gum_arm64_writer_put_call_address_with_arguments (cws,
        GUM_ADDRESS (gum_exec_block_backpatch_jmp), 5,
        GUM_ARG_REGISTER, ARM64_REG_X0,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
        GUM_ARG_ADDRESS, code_start - GUM_ADDRESS (block->code_start),
        GUM_ARG_ADDRESS, GUM_ADDRESS (opened_prolog));
  }
  else if (trust_threshold >= 0)
  {
    gum_arm64_writer_put_call_address_with_arguments (cws,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 3,
        GUM_ARG_REGISTER, ARM64_REG_X0,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  }

  gum_exec_block_close_prolog (block, gc, cws);
  gum_exec_block_write_exec_generated_code (cws, block->ctx);
}

static void
gum_exec_block_write_ret_transfer_code (GumExecBlock * block,
                                        GumGeneratorContext * gc,
                                        arm64_reg ret_reg)
{
  gum_exec_block_write_chaining_return_code (block, gc, ret_reg);
}

static void
gum_exec_block_write_chaining_return_code (GumExecBlock * block,
                                           GumGeneratorContext  * gc,
                                           arm64_reg ret_reg)
{
  GumArm64Writer * cw = gc->code_writer;
  GumArm64Writer * cws = gc->slow_writer;
  const gint trust_threshold = block->ctx->stalker->trust_threshold;
  GumExecCtx * ctx = block->ctx;
  arm64_reg result_reg;

  gum_exec_ctx_write_adjust_depth (ctx, cw, -1);

  gum_exec_block_close_prolog (block, gc, cw);

  if (trust_threshold >= 0)
  {
    /*
     * The call invoke code will transfer control to the slow slab in the event
     * of a cache miss. Otherwise, it will return control to the code (fast)
     * slab with the values of X16/X17 still pushed above the red-zone.
     */
    result_reg = gum_exec_block_write_inline_cache_code (block, ret_reg,
        cw, cws);
    gum_arm64_writer_put_br_reg_no_auth (cw, result_reg);
  }
  else
  {
    /*
     * If we don't have an inline cache, or we have a cache miss, we branch to
     * to the slow slab, never to return.
     */
    gum_exec_block_write_slab_transfer_code (cw, cws);
  }

  /* Slow Path */

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cws, ARM64_REG_X16,
      ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);

  if (ret_reg != ARM64_REG_X16)
    gum_arm64_writer_put_mov_reg_reg (cws, ARM64_REG_X16, ret_reg);

  if ((ctx->stalker->cpu_features & GUM_CPU_PTRAUTH) != 0)
    gum_arm64_writer_put_xpaci_reg (cws, ARM64_REG_X16);

  gum_arm64_writer_put_ldr_reg_address (cws, ARM64_REG_X17,
      GUM_ADDRESS (&ctx->return_at));
  gum_arm64_writer_put_str_reg_reg_offset (cws, ARM64_REG_X16,
      ARM64_REG_X17, 0);

   gum_arm64_writer_put_ldp_reg_reg_reg_offset (cws, ARM64_REG_X16,
      ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);

  gum_exec_block_open_prolog (block, GUM_PROLOG_MINIMAL, gc, cws);

  gum_arm64_writer_put_ldr_reg_address (cws, ARM64_REG_X0,
      GUM_ADDRESS (&ctx->return_at));
  gum_arm64_writer_put_ldr_reg_reg_offset (cws, ARM64_REG_X1, ARM64_REG_X0, 0);

  /* Fetch the target block */
  gum_arm64_writer_put_call_address_with_arguments (cws,
      GUM_ADDRESS (GUM_ENTRYGATE (ret)), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM64_REG_X1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  if (trust_threshold >= 0)
  {
    gum_arm64_writer_put_ldr_reg_address (cws, ARM64_REG_X0,
        GUM_ADDRESS (&ctx->current_block));
    gum_arm64_writer_put_ldr_reg_reg_offset (cws, ARM64_REG_X0,
        ARM64_REG_X0, 0);

    gum_arm64_writer_put_call_address_with_arguments (cws,
        GUM_ADDRESS (gum_exec_block_backpatch_inline_cache), 3,
        GUM_ARG_REGISTER, ARM64_REG_X0,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

    /*
     * If the user emits a BL instruction from within their transformer, then
     * this will result in control flow returning back to the code slab when
     * that function returns. The target address for this RET is therefore not
     * an instrumented block (e.g. a real address within the application which
     * has been instrumented), but actually a code address within an
     * instrumented block itself. This therefore needs to be treated as a
     * special case.
     *
     * Also since we cannot guarantee that code addresses between a Stalker
     * instance and an observer are identical (hence prefetched backpatches are
     * communicated in terms of their real address), whilst these can be
     * backpatched by adding them to the inline cache, they cannot be
     * prefetched.
     *
     * This block handles the backpatching of the entry into the inline cache,
     * but the block is still fetched by the call to `ret_slow_path` above, but
     * since ctx->current_block is not set and therefore the block is not
     * backpatched by backpatch_inline_cache() in the traditional way.
     */
    gum_exec_ctx_load_real_register_into (ctx, ARM64_REG_X1, ret_reg, gc, cws);
    gum_arm64_writer_put_call_address_with_arguments (cws,
        GUM_ADDRESS (gum_exec_block_backpatch_slab), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_REGISTER, ARM64_REG_X1);
  }

  gum_exec_block_close_prolog (block, gc, cws);
  gum_exec_block_write_exec_generated_code (cws, ctx);
}

static void
gum_exec_block_write_slab_transfer_code (GumArm64Writer * from,
                                         GumArm64Writer * to)
{
  /*
   * We ensure that our code (fast) and slow slabs are allocated so that we can
   * perform an immediate branch between them. Otherwise Arm64Writer is forced
   * to perform an indirect branch and clobber a register (which is obviously
   * undesirable).
   */
  g_assert (gum_arm64_writer_can_branch_directly_between (from, from->pc,
      GUM_ADDRESS (to->code)));
  gum_arm64_writer_put_branch_address (from, GUM_ADDRESS (to->code));
}

/*
 * This function is responsible for backpatching code_slab addresses into the
 * inline cache. This may be encountered, for example when control flow returns
 * following execution of a CALL instruction emitted by a transformer. Note that
 * these cannot be prefetched, since there is no guarantee that the address of
 * instrumented blocks will be the same between the forkserver and its child.
 * This may be because, for example, blocks are compiled in a different order,
 * or the allocators are non-deterministic.
 */
static void
gum_exec_block_backpatch_slab (GumExecBlock * block,
                               gpointer target)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  GumIcEntry * ic_entries;
  guint num_ic_entries, i;

  just_unfollowed = block == NULL;
  if (just_unfollowed)
    return;

  ctx = block->ctx;
  if (!gum_exec_ctx_may_now_backpatch (ctx, block))
    return;
  if (!gum_exec_ctx_contains (ctx, target))
    return;

  ic_entries = block->ic_entries;
  g_assert (ic_entries != NULL);
  num_ic_entries = ctx->stalker->ic_entries;

  for (i = 0; i != num_ic_entries; i++)
  {
    if (ic_entries[i].real_start == target)
      return;
  }

  gum_spinlock_acquire (&ctx->code_lock);

  memmove (&ic_entries[1], &ic_entries[0],
      (num_ic_entries - 1) * sizeof (GumIcEntry));

  ic_entries[0].real_start = target;
  ic_entries[0].code_start = target;

  gum_spinlock_release (&ctx->code_lock);
}

static void
gum_exec_block_maybe_inherit_exclusive_access_state (GumExecBlock * block,
                                                     GumExecBlock * reference)
{
  const guint8 * real_address = block->real_start;
  GumExecBlock * cur;

  for (cur = reference; cur != NULL; cur = cur->next)
  {
    if ((cur->flags & GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS) == 0)
      return;

    if (real_address >= cur->real_start &&
        real_address < cur->real_start + cur->real_size)
    {
      block->flags |= GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS;
      return;
    }
  }
}

static void
gum_exec_block_propagate_exclusive_access_state (GumExecBlock * block)
{
  GumExecBlock * block_containing_load, * cur;
  guint i;

  if ((block->flags & GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS) != 0)
    return;

  if ((block->flags & GUM_EXEC_BLOCK_HAS_EXCLUSIVE_STORE) == 0
```