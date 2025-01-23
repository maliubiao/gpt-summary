Response:
Let's break down the thought process for analyzing this C code snippet.

**1. Initial Understanding of the Context:**

The prompt clearly states this is part of Frida, a dynamic instrumentation toolkit. The specific path `frida/subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c` pinpoints its role: it's the ARM backend for Frida's "stalker" component. The "stalker" is responsible for tracing and instrumenting code execution dynamically.

**2. High-Level Function Identification:**

The first step is to scan the code for function definitions (`static void`, `static gpointer`). This gives a broad overview of the different actions the code performs. We can group these functions conceptually:

* **Code Generation:** Functions with `gum_exec_block_write_*` (e.g., `gum_exec_block_write_arm_handle_continue`, `gum_exec_block_write_thumb_call_event_code`). These functions clearly deal with emitting ARM/Thumb instructions.
* **Context Switching/Management:** Functions involving `gum_exec_ctx_*` (e.g., `gum_exec_ctx_switch_block`, `gum_exec_ctx_emit_call_event`). These seem to manage the execution context during instrumentation.
* **Stack Frame Manipulation:** Functions like `gum_exec_block_write_arm_push_stack_frame` and `gum_exec_block_pop_stack_frame`. These are likely related to handling function calls and returns.
* **Probing:** Functions with `gum_exec_block_*probe*` (e.g., `gum_exec_block_maybe_write_call_probe_code`, `gum_exec_block_invoke_call_probes`). This suggests support for inserting custom code at specific points.
* **Code/Data Slab Management:** Functions with `gum_code_slab_*` and `gum_data_slab_*`. These manage memory allocation for the generated code and potentially data.
* **Utility Functions:** Functions like `gum_strip_thumb_bit`, `gum_is_thumb`, `gum_is_exclusive_load_insn`. These are helper functions for ARM/Thumb specific operations.

**3. Analyzing Key Function Groups and Their Relevance:**

Now, let's delve deeper into the identified groups and connect them to the prompt's requirements.

* **Code Generation (`gum_exec_block_write_*`):**
    * **Functionality:** The core of dynamic instrumentation. These functions generate ARM/Thumb instructions to redirect execution, record events, and manage context.
    * **Reverse Engineering:**  Crucial for hooking and tracing. By understanding how these functions generate code, a reverse engineer can understand *how* Frida modifies the target process. The examples in the prompt are generated *by* these functions.
    * **Binary/Kernel/Android:**  They directly interact with the ARM instruction set (binary level). Concepts like instruction encoding (ARM vs. Thumb), condition codes (`ARM_CC_AL`), and register usage (`ARM_REG_R0`, `ARM_REG_PC`) are fundamental. While not directly kernel or Android *code*, the generated code will execute within those environments.
    * **Logic/Input-Output:** Consider `gum_exec_block_write_arm_handle_branch`. If `cc != ARM_CC_AL` (not always), it emits conditional branch instructions. Input: the condition code `cc`. Output: conditional branch instructions or a sequence for unconditional execution.
    * **User Errors:** If a user's Frida script attempts to hook an instruction within a very small code block, Frida might not have enough space to insert its instrumentation code. This can lead to crashes or unexpected behavior. The `GUM_INVALIDATE_TRAMPOLINE_SIZE` constant hints at this.

* **Context Switching/Management (`gum_exec_ctx_*`):**
    * **Functionality:**  Essential for transitioning between the original code and Frida's instrumentation code. This ensures that the target process's state is preserved and restored.
    * **Reverse Engineering:** Understanding these functions is key to comprehending *how* Frida intercepts execution without crashing the target.
    * **Binary/Kernel/Android:**  These functions often involve manipulating processor registers (like the program counter), which is a low-level operation. In the context of Android, this might involve interacting with the Android Runtime (ART).
    * **Logic/Input-Output:**  `gum_exec_ctx_switch_block` takes the current and next blocks as input and manages the transition. The output is the change in the execution flow.

* **Stack Frame Manipulation (`gum_exec_block_*stack_frame*`):**
    * **Functionality:**  Correctly handling function calls and returns is vital for accurate tracing and instrumentation.
    * **Reverse Engineering:**  Understanding how Frida tracks the call stack helps in reconstructing the execution flow of the target.
    * **Binary/Kernel/Android:**  Stack management is a fundamental part of any architecture and operating system.
    * **Logic/Input-Output:** `gum_exec_block_push_stack_frame` pushes the return address onto a managed stack. Input: return address. Output: modification of the Frida-managed stack.

* **Probing (`gum_exec_block_*probe*`):**
    * **Functionality:**  Allows users to insert custom callbacks at specific code locations.
    * **Reverse Engineering:**  This is a powerful feature for dynamic analysis and can be used to observe the target's behavior at precise points.
    * **User Errors:**  If a probe's callback function is poorly written and crashes, it can crash the target process.

* **Code/Data Slab Management (`gum_*_slab_*`):**
    * **Functionality:**  Efficiently manages memory allocation for Frida's instrumentation code and data.
    * **Binary/Kernel/Android:**  Memory management is a core OS concept. The code allocates memory within the target process.
    * **User Errors:** While less direct, memory leaks in Frida's internal structures could theoretically occur if these functions aren't used correctly, though this is an internal implementation detail.

* **Utility Functions:**
    * **Functionality:**  Provide low-level operations specific to the ARM architecture.
    * **Reverse Engineering:**  Helpful for understanding the nuances of ARM/Thumb execution.
    * **Binary:** Directly related to the binary encoding of instructions.

**4. Addressing Specific Prompt Points:**

* **Relationship to Reverse Engineering:**  Constantly make these connections while analyzing the code. How does this function help someone understand the target program?
* **Binary/Kernel/Android:** Explicitly point out the interactions with the ARM instruction set, registers, and potentially OS-level concepts.
* **Logic/Input-Output:** For significant functions, try to define simple input and expected output scenarios. This helps demonstrate understanding of the function's purpose.
* **User Errors:**  Think about how a user's interaction with Frida could lead to issues related to this specific code.
* **User Operations:** Consider the typical Frida workflow: attaching to a process, specifying code to instrument, and running the process. How does this lead to the execution of this C code?
* **Summary (Part 6):**  Synthesize the findings into a concise summary of the file's overall role.

**5. Iteration and Refinement:**

After the initial pass, review the analysis. Are the explanations clear and accurate? Have all the prompt's points been addressed?  Are the examples relevant?  For instance, initially, I might focus too much on the low-level details of individual instructions. Then, I would refine the analysis to emphasize the higher-level functionalities and their implications for dynamic instrumentation and reverse engineering.

This structured approach helps to systematically analyze the code snippet and generate a comprehensive and informative response that addresses all aspects of the prompt.
This is the source code file `gumstalker-arm.c` for the ARM backend of Frida's Stalker. Stalker is Frida's dynamic code tracing and instrumentation engine. This file contains the architecture-specific logic for generating code on ARM (and Thumb) to intercept and modify the execution flow of a target process.

Here's a breakdown of its functionalities, relating them to reverse engineering, binary/kernel/Android knowledge, logic, user errors, and debugging:

**Functionalities of `gumstalker-arm.c`:**

1. **Code Generation for Instrumentation:** The primary function is to generate ARM and Thumb assembly code on the fly to insert Frida's instrumentation logic into the target process. This involves:
    * **Prologues and Epilogues:**  Functions like `gum_exec_block_arm_open_prolog`, `gum_exec_block_thumb_close_prolog` write code to save and restore the execution context (registers) of the target process before and after Frida's code executes. This is crucial for maintaining the target's state.
    * **Branch Handling:**  Functions like `gum_exec_block_write_arm_handle_branch` generate code to intercept branches (jumps, calls, returns). This allows Frida to gain control whenever the target program changes its execution path. It handles both conditional and unconditional branches, and different ARM instruction encodings (ARM and Thumb).
    * **Continue Handling:** `gum_exec_block_write_arm_handle_continue` and `gum_exec_block_write_thumb_handle_continue` generate code to return control back to the original execution flow after Frida's instrumentation.
    * **Writeback Handling:** `gum_exec_block_write_arm_handle_writeback` and `gum_exec_block_write_thumb_handle_writeback` handle instructions with writeback effects (where the instruction modifies the base register).
    * **Directly Executing Generated Code:** `gum_exec_block_write_arm_exec_generated_code` and `gum_exec_block_write_thumb_exec_generated_code` generate code to jump to the dynamically generated instrumentation code.
    * **Inline Data Embedding:** `gum_exec_block_write_arm_inline_data` and `gum_exec_block_write_thumb_inline_data` allow embedding data directly within the generated code.

2. **Event Emission:** This code generates calls to functions that notify Frida's core about execution events:
    * **Call Events:** `gum_exec_block_write_arm_call_event_code`, `gum_exec_block_write_thumb_call_event_code` generate code to emit an event when a function call is detected.
    * **Return Events:** `gum_exec_block_write_arm_ret_event_code`, `gum_exec_block_write_thumb_ret_event_code` do the same for function returns.
    * **Execution Events:** `gum_exec_block_write_arm_exec_event_code`, `gum_exec_block_write_thumb_exec_event_code` generate code to emit events for the execution of basic blocks (sequences of instructions).
    * **Block Events:** `gum_exec_block_write_arm_block_event_code`, `gum_exec_block_write_thumb_block_event_code` seem related to emitting events when entering a code block managed by Stalker.

3. **Stack Frame Management:**
    * `gum_exec_block_write_arm_push_stack_frame`, `gum_exec_block_write_thumb_push_stack_frame`, and `gum_exec_block_push_stack_frame` are involved in maintaining a shadow stack or tracking function call depths. This is important for reconstructing call stacks during tracing.
    * `gum_exec_block_write_arm_pop_stack_frame`, `gum_exec_block_write_thumb_pop_stack_frame`, and `gum_exec_block_pop_stack_frame` handle popping stack frames, likely on function returns.

4. **Call Probing:**
    * `gum_exec_block_maybe_write_call_probe_code`, `gum_exec_block_write_arm_call_probe_code`, `gum_exec_block_write_thumb_call_probe_code`, and `gum_exec_block_invoke_call_probes` implement Frida's "call probes" feature. This allows users to insert custom code that gets executed *before* a function call.

5. **Code and Data Slab Management:**
    * The code includes functions for managing memory allocation for the generated code (`gum_code_slab_new`, `gum_code_slab_free`, `gum_code_slab_init`) and potentially for storing data (`gum_data_slab_new`, `gum_data_slab_free`, `gum_data_slab_init`). This helps Frida efficiently manage the memory used for instrumentation.

6. **Utility Functions:**  Several helper functions provide architecture-specific logic:
    * `gum_strip_thumb_bit`: Removes the Thumb bit from an address.
    * `gum_is_thumb`: Checks if an address is a Thumb address.
    * `gum_is_kuser_helper`: Detects calls to specific kernel helper functions (relevant for kernel-level instrumentation).
    * `gum_is_exclusive_load_insn`, `gum_is_exclusive_store_insn`: Identify instructions used for atomic operations (important for correctness when instrumenting concurrent code).
    * Bit manipulation functions (`gum_count_bits_set`, `gum_count_trailing_zeros`).

**Relationship to Reverse Engineering:**

* **Dynamic Analysis:** This code is the heart of Frida's dynamic analysis capabilities. By understanding how it generates instrumentation code, a reverse engineer can:
    * **Trace Execution:** See the exact sequence of instructions executed by the target.
    * **Inspect Function Arguments and Return Values:** The call and return event emission logic allows observing data flow in and out of functions.
    * **Hook Functions:** The branch handling and prologue/epilogue logic is used to intercept function calls and redirect execution to custom code.
    * **Modify Program Behavior:** By injecting custom code, reverse engineers can change how the target program behaves.

**Example:** If a reverse engineer wants to know the arguments of a function `foo` at address `0x12345678`, Frida, using the logic in this file, would generate code to:
    1. **At the beginning of `foo` (or before the call to `foo` if using a call probe):**
        * Save the current registers.
        * Load the function arguments (which are typically in registers on ARM, e.g., R0, R1, R2, R3) into known locations.
        * Call a Frida function to report these arguments.
        * Restore the original registers.
        * Jump back to the original start of `foo`.

    The functions like `gum_exec_block_write_arm_call_event_code` are responsible for generating the assembly instructions to perform these steps.

**Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

* **ARM Architecture:**  The code directly manipulates ARM and Thumb instructions. Understanding the ARM instruction set, registers (R0-R15, SP, LR, PC), condition codes, and calling conventions is essential to comprehend this code.
* **Instruction Encoding:** The code distinguishes between ARM and Thumb modes (16-bit and 32-bit instruction encodings) and generates appropriate code for each. The `gum_is_thumb` function and the separate code generation paths for ARM and Thumb demonstrate this.
* **Memory Management:**  The code interacts with memory allocation within the target process. Knowledge of how memory is organized and managed in Linux/Android is helpful.
* **Calling Conventions:** The generated code needs to respect the ARM calling conventions to correctly save and restore registers and access function arguments.
* **Kernel Interaction (Potentially):** The `gum_is_kuser_helper` function suggests that Frida can potentially instrument code that calls into the Linux kernel. Understanding system calls and kernel entry/exit points would be relevant here.
* **Android Framework (Indirectly):** While this code doesn't directly interact with Android framework APIs, Frida is commonly used to instrument Android applications. The concepts of Dalvik/ART bytecode and native code execution in Android are indirectly related. Frida bridges the gap between these layers.

**Logical Reasoning and Assumptions:**

* **Assumption:**  The code assumes that it can allocate and execute code within the target process's memory space.
* **Assumption:** It assumes the availability of functions like `gum_exec_ctx_switch_block` and event emission functions, which are likely defined in other parts of Frida.
* **Conditional Logic:** The code uses conditional statements (e.g., `if (cc != ARM_CC_AL)`) to generate different instrumentation code based on the type of instruction being intercepted (e.g., conditional branches).
* **Input/Output (Example with `gum_exec_block_write_arm_handle_branch`):**
    * **Input:** `cw` (GumArmWriter - for writing ARM instructions), `taken` (label for the target of the branch), `cc` (ARM condition code).
    * **Logic:** If `cc` is `ARM_CC_AL` (always), generate an unconditional branch. Otherwise, generate a conditional branch.
    * **Output:** ARM assembly instructions written to `cw` that implement the branch interception.

**User or Programming Common Usage Errors:**

* **Instrumenting Very Short Code Blocks:** If a user tries to instrument an instruction in a very small function or code block, Frida might not have enough space to insert the necessary prologue, event emission, and epilogue code. This could lead to crashes or unexpected behavior. The `GUM_INVALIDATE_TRAMPOLINE_SIZE` constant suggests a minimum size requirement for instrumentation.
* **Incorrectly Handling Register State in Custom Instrumentation:** If a user writes custom instrumentation code (e.g., using Frida's `Interceptor.attach`) without properly saving and restoring registers, it can corrupt the target process's state and cause crashes. The prologue and epilogue logic in this file is designed to prevent this, but user-provided code needs to be careful.
* **Infinite Recursion in Instrumentation:** If the instrumentation logic itself triggers the same instrumentation repeatedly (e.g., hooking a function that is called by the hook), it can lead to infinite recursion and stack overflow.

**User Operation Steps to Reach This Code (Debugging Clue):**

1. **User starts a Frida session and connects to a target process (e.g., an Android app or a Linux executable).**
2. **User uses Frida's API (e.g., `Interceptor.attach`, `Stalker.follow`) to specify code locations or modules to instrument.**
3. **Frida's core determines the architecture of the target process (in this case, ARM).**
4. **When execution reaches an instruction or code block that needs to be instrumented (based on the user's directives), Frida's Stalker engine will invoke functions within `gumstalker-arm.c` to generate the necessary ARM/Thumb instrumentation code.**
5. **The generated code is then written into the target process's memory.**
6. **Execution continues in the target process, and when it hits the instrumented code, Frida's logic is executed.**

**Part 6 Summary (Overall Functionality):**

In summary, `gumstalker-arm.c` is a critical component of Frida's Stalker engine for ARM architectures. It's responsible for the low-level details of dynamically generating and injecting ARM and Thumb assembly code into a target process. This generated code allows Frida to intercept and observe the target's execution flow, inspect data, and even modify its behavior, making it a powerful tool for dynamic analysis and reverse engineering on ARM-based systems like Android. It leverages a deep understanding of the ARM architecture, instruction encodings, and calling conventions to achieve its goals.

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
_b_label_wide (cw, taken);

    gum_thumb_writer_put_label (cw, cb_not_taken);
  }
  else if (cc != ARM_CC_AL)
  {
    gum_thumb_writer_put_b_cond_label_wide (cw, cc, taken);
  }

  if (cc != ARM_CC_AL)
  {
    GumPrologState backpatch_prolog_state;
    GumAddress backpatch_code_start;

    if ((ec->sink_mask & GUM_EXEC) != 0 &&
        (block->flags & GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS) == 0)
    {
      gum_exec_block_thumb_open_prolog (block, gc);
      backpatch_prolog_state = GUM_PROLOG_OPEN;

      gum_exec_block_write_thumb_exec_event_code (block, gc);
    }
    else
    {
      backpatch_prolog_state = GUM_PROLOG_CLOSED;
    }

    backpatch_code_start = cw->pc;

    if (backpatch_prolog_state == GUM_PROLOG_CLOSED)
      gum_exec_block_thumb_open_prolog (block, gc);

    gum_thumb_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_switch_block), 4,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ec),
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->end + 1),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start + 1));

    if (ec->stalker->trust_threshold >= 0 &&
        target->type == GUM_TARGET_DIRECT_ADDRESS &&
        gum_is_thumb (target->value.direct_address.address))
    {
      const guint padding_size = 5;
      guint i;

      for (i = 0; i != padding_size; i++)
        gum_thumb_writer_put_nop (cw);

      gum_thumb_writer_put_ldr_reg_address (cw, ARM_REG_R5,
          GUM_ADDRESS (&block->ctx->current_block));
      gum_thumb_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R5, ARM_REG_R5, 0);

      gum_thumb_writer_put_call_address_with_arguments (cw,
          GUM_ADDRESS (gum_exec_ctx_backpatch_thumb_branch_to_current), 5,
          GUM_ARG_REGISTER, ARM_REG_R5,
          GUM_ARG_ADDRESS, GUM_ADDRESS (block),
          GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
          GUM_ARG_ADDRESS,
            backpatch_code_start - GUM_ADDRESS (block->code_start),
          GUM_ARG_ADDRESS, GUM_ADDRESS (backpatch_prolog_state));
    }

    gum_exec_block_thumb_close_prolog (block, gc);

    gum_exec_block_write_thumb_exec_generated_code (cw, ec);

    gum_thumb_writer_put_label (cw, taken);
  }
}

static void
gum_exec_block_write_arm_handle_continue (GumExecBlock * block,
                                          GumGeneratorContext * gc)
{
  /*
   * Use the address of the end of the current instruction as the address of the
   * next block to execute. This is the case after handling a call instruction
   * to an excluded range whereby upon return you want to continue with the next
   * instruction, or when a conditional instruction is not executed resulting in
   * a branch not being taken. Instrument the block and then vector to it.
   */

  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_ctx_switch_block), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->end),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  gum_exec_block_arm_close_prolog (block, gc);

  gum_exec_block_write_arm_exec_generated_code (gc->arm_writer, block->ctx);
}

static void
gum_exec_block_write_thumb_handle_continue (GumExecBlock * block,
                                            GumGeneratorContext * gc)
{
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_ctx_switch_block), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->end + 1),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start + 1));

  gum_exec_block_thumb_close_prolog (block, gc);

  gum_exec_block_write_thumb_exec_generated_code (gc->thumb_writer, block->ctx);
}

static void
gum_exec_block_write_arm_handle_writeback (GumExecBlock * block,
                                           const GumWriteback * writeback,
                                           GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->arm_writer;
  gssize offset;

  if (writeback->target == ARM_REG_INVALID)
    return;

  offset = writeback->offset;
  if (offset >= 0)
    gum_arm_writer_put_add_reg_u32 (cw, writeback->target, offset);
  else
    gum_arm_writer_put_sub_reg_u32 (cw, writeback->target, -offset);
}

static void
gum_exec_block_write_thumb_handle_writeback (GumExecBlock * block,
                                             const GumWriteback * writeback,
                                             GumGeneratorContext * gc)
{
  GumThumbWriter * cw = gc->thumb_writer;
  gssize offset;

  if (writeback->target == ARM_REG_INVALID)
    return;

  offset = writeback->offset;

  if (offset >= 0)
    gum_thumb_writer_put_add_reg_imm (cw, writeback->target, offset);
  else
    gum_thumb_writer_put_sub_reg_imm (cw, writeback->target, -offset);
}

static void
gum_exec_block_write_arm_exec_generated_code (GumArmWriter * cw,
                                              GumExecCtx * ctx)
{
  /*
   * This function writes code to vector to the address of the last instrumented
   * block. Given that this code is emitted before the block is actually
   * instrumented, the value of ctx->resume_at will change between this code
   * being emitted and it being executed. It must therefore use &ctx->resume_at
   * and re-read the value from memory at runtime.
   *
   * This however means that we must use a scratch register to calculate the
   * final address. Given that this is also used to transition between blocks
   * within a function, we cannot rely upon the fact the R12 is a callee saved
   * register and clobber the value since it may be being used within the
   * function scope. We therefore push and pop this register to and from the
   * stack.
   */

  /*
   * Here we push the values of R0 which we will use as scratch space and PC we
   * will overwrite the value of PC on the stack at (SP+4) with the value from
   * resume_at before we subsequently pop both registers. This allows us to
   * branch to an arbitrary address without clobbering any registers.
   */
  gum_arm_writer_put_push_regs (cw, 2, ARM_REG_R0, ARM_REG_PC);
  gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R0,
      GUM_ADDRESS (&ctx->resume_at));
  gum_arm_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_R0, 0);

  gum_arm_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_SP, 4);
  gum_arm_writer_put_pop_regs (cw, 2, ARM_REG_R0, ARM_REG_PC);
}

static void
gum_exec_block_write_thumb_exec_generated_code (GumThumbWriter * cw,
                                                GumExecCtx * ctx)
{
  /*
   * We can't push PC in Thumb encoding without Thumb 2, and we clobber the
   * value so it doesn't matter what we push. It ends up popped back into PC.
   */
  gum_thumb_writer_put_push_regs (cw, 2, ARM_REG_R0, ARM_REG_R1);
  gum_thumb_writer_put_ldr_reg_address (cw, ARM_REG_R0,
      GUM_ADDRESS (&ctx->resume_at));
  gum_thumb_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_R0, 0);
  gum_thumb_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_SP, 4);
  gum_thumb_writer_put_pop_regs (cw, 2, ARM_REG_R0, ARM_REG_PC);
}

static void
gum_exec_block_write_arm_call_event_code (GumExecBlock * block,
                                          const GumBranchTarget * target,
                                          GumGeneratorContext * gc)
{
  gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R2, gc);
  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_call_event), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, ARM_REG_R2,
      GUM_ARG_REGISTER, ARM_REG_R10);
}

static void
gum_exec_block_write_thumb_call_event_code (GumExecBlock * block,
                                            const GumBranchTarget * target,
                                            GumGeneratorContext * gc)
{
  gum_exec_ctx_write_thumb_mov_branch_target (block->ctx, target, ARM_REG_R2,
      gc);
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_call_event), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start + 1),
      GUM_ARG_REGISTER, ARM_REG_R2,
      GUM_ARG_REGISTER, ARM_REG_R10);
}

static void
gum_exec_block_write_arm_ret_event_code (GumExecBlock * block,
                                         const GumBranchTarget * target,
                                         GumGeneratorContext * gc)
{
  gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R2, gc);
  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_ret_event), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, ARM_REG_R2,
      GUM_ARG_REGISTER, ARM_REG_R10);
}

static void
gum_exec_block_write_thumb_ret_event_code (GumExecBlock * block,
                                           const GumBranchTarget * target,
                                           GumGeneratorContext * gc)
{
  gum_exec_ctx_write_thumb_mov_branch_target (block->ctx, target, ARM_REG_R2,
      gc);
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_ret_event), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start + 1),
      GUM_ARG_REGISTER, ARM_REG_R2,
      GUM_ARG_REGISTER, ARM_REG_R10);
}

static void
gum_exec_block_write_arm_exec_event_code (GumExecBlock * block,
                                          GumGeneratorContext * gc)
{
  if ((block->flags & GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS) != 0)
    return;

  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_exec_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, ARM_REG_R10);
}

static void
gum_exec_block_write_thumb_exec_event_code (GumExecBlock * block,
                                            GumGeneratorContext * gc)
{
  if ((block->flags & GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS) != 0)
    return;

  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_exec_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start + 1),
      GUM_ARG_REGISTER, ARM_REG_R10);
}

static void
gum_exec_block_write_arm_block_event_code (GumExecBlock * block,
                                           GumGeneratorContext * gc)
{
  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_block_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM_REG_R10);
}

static void
gum_exec_block_write_thumb_block_event_code (GumExecBlock * block,
                                             GumGeneratorContext * gc)
{
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_block_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM_REG_R10);
}

static void
gum_exec_block_write_arm_push_stack_frame (GumExecBlock * block,
                                           gpointer ret_real_address,
                                           GumGeneratorContext * gc)
{
  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_block_push_stack_frame), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (ret_real_address));
}

static void
gum_exec_block_write_thumb_push_stack_frame (GumExecBlock * block,
                                             gpointer ret_real_address,
                                             GumGeneratorContext * gc)
{
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_block_push_stack_frame), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (ret_real_address));
}

static void
gum_exec_block_push_stack_frame (GumExecCtx * ctx,
                                 gpointer ret_real_address)
{
  if (ctx->current_frame != ctx->frames)
  {
    ctx->current_frame->real_address = ret_real_address;
    ctx->current_frame--;
  }
}

static void
gum_exec_block_write_arm_pop_stack_frame (GumExecBlock * block,
                                          const GumBranchTarget * target,
                                          GumGeneratorContext * gc)
{
  gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R1, gc);
  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_block_pop_stack_frame), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_REGISTER, ARM_REG_R1);
}

static void
gum_exec_block_write_thumb_pop_stack_frame (GumExecBlock * block,
                                            const GumBranchTarget * target,
                                            GumGeneratorContext * gc)
{
  gum_exec_ctx_write_thumb_mov_branch_target (block->ctx, target, ARM_REG_R1,
      gc);
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_block_pop_stack_frame), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_REGISTER, ARM_REG_R1);
}

static void
gum_exec_block_pop_stack_frame (GumExecCtx * ctx,
                                gpointer ret_real_address)
{
  /*
   * Since with ARM32, there is no clear CALL and RET instructions, it is
   * difficult to determine the difference between instructions being used to
   * perform a CALL, a BRANCH or a RETURN. We therefore check to see if the
   * target address is the return address from a previous call instruction to
   * determine whether to pop the frame from the stack. Note, however, that this
   * approach may not work in the event that the user be allowed to make
   * call-outs to modify the control flow.
   */
  if (ctx->current_frame != ctx->first_frame)
  {
    GumExecFrame * next_frame = ctx->current_frame + 1;
    if (next_frame->real_address == ret_real_address)
      ctx->current_frame = next_frame;
  }
}

static void
gum_exec_block_maybe_write_call_probe_code (GumExecBlock * block,
                                            GumGeneratorContext * gc)
{
  GumStalker * stalker = block->ctx->stalker;

  if (!stalker->any_probes_attached)
    return;

  gum_spinlock_acquire (&stalker->probe_lock);

  if (g_hash_table_contains (stalker->probe_array_by_address,
          gum_exec_block_encode_instruction_pointer (block, block->real_start)))
  {
    if ((block->flags & GUM_EXEC_BLOCK_THUMB) != 0)
      gum_exec_block_write_thumb_call_probe_code (block, gc);
    else
      gum_exec_block_write_arm_call_probe_code (block, gc);
  }

  gum_spinlock_release (&stalker->probe_lock);
}

static void
gum_exec_block_write_arm_call_probe_code (GumExecBlock * block,
                                          GumGeneratorContext * gc)
{
  gum_exec_block_arm_open_prolog (block, gc);
  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_block_invoke_call_probes), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM_REG_R10);
  gum_exec_block_arm_close_prolog (block, gc);
}

static void
gum_exec_block_write_thumb_call_probe_code (GumExecBlock * block,
                                            GumGeneratorContext * gc)
{
  gum_exec_block_thumb_open_prolog (block, gc);
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_block_invoke_call_probes), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM_REG_R10);
  gum_exec_block_thumb_close_prolog (block, gc);
}

static void
gum_exec_block_invoke_call_probes (GumExecBlock * block,
                                   GumCpuContext * cpu_context)
{
  GumStalker * stalker = block->ctx->stalker;
  gpointer target_address;
  GumCallProbe ** probes_copy;
  guint num_probes, i;
  GumCallDetails d;

  target_address =
      gum_exec_block_encode_instruction_pointer (block, block->real_start);

  probes_copy = NULL;
  num_probes = 0;
  {
    GPtrArray * probes;

    gum_spinlock_acquire (&stalker->probe_lock);

    probes =
        g_hash_table_lookup (stalker->probe_array_by_address, target_address);
    if (probes != NULL)
    {
      num_probes = probes->len;
      probes_copy = g_newa (GumCallProbe *, num_probes);
      for (i = 0; i != num_probes; i++)
      {
        probes_copy[i] = gum_call_probe_ref (g_ptr_array_index (probes, i));
      }
    }

    gum_spinlock_release (&stalker->probe_lock);
  }
  if (num_probes == 0)
    return;

  d.target_address = target_address;
  d.return_address = GSIZE_TO_POINTER (cpu_context->lr);
  d.stack_data = GSIZE_TO_POINTER (cpu_context->sp);
  d.cpu_context = cpu_context;

  cpu_context->pc = GPOINTER_TO_SIZE (block->real_start);

  for (i = 0; i != num_probes; i++)
  {
    GumCallProbe * probe = probes_copy[i];

    probe->callback (&d, probe->user_data);

    gum_call_probe_unref (probe);
  }
}

static gpointer
gum_exec_block_write_arm_inline_data (GumArmWriter * cw,
                                      gconstpointer data,
                                      gsize size,
                                      GumAddress * address)
{
  gpointer location;
  gconstpointer after_data = cw->code + 1;

  g_assert (size % 4 == 0);

  while (gum_arm_writer_offset (cw) < GUM_INVALIDATE_TRAMPOLINE_SIZE)
  {
    gum_arm_writer_put_nop (cw);
  }

  gum_arm_writer_put_b_label (cw, after_data);

  location = gum_arm_writer_cur (cw);
  if (address != NULL)
    *address = cw->pc;
  gum_arm_writer_put_bytes (cw, data, size);

  gum_arm_writer_put_label (cw, after_data);

  return location;
}

static gpointer
gum_exec_block_write_thumb_inline_data (GumThumbWriter * cw,
                                        gconstpointer data,
                                        gsize size,
                                        GumAddress * address)
{
  gpointer location;
  gconstpointer after_data = cw->code + 1;

  g_assert (size % 4 == 0);

  while (gum_thumb_writer_offset (cw) < GUM_INVALIDATE_TRAMPOLINE_SIZE)
  {
    gum_thumb_writer_put_nop (cw);
  }

  gum_thumb_writer_put_b_label (cw, after_data);

  if (gum_thumb_writer_offset (cw) % 4 != 0)
    gum_thumb_writer_put_nop (cw);
  location = gum_thumb_writer_cur (cw);
  if (address != NULL)
    *address = cw->pc;
  gum_thumb_writer_put_bytes (cw, data, size);

  gum_thumb_writer_put_label (cw, after_data);

  return location;
}

static void
gum_exec_block_arm_open_prolog (GumExecBlock * block,
                                GumGeneratorContext * gc)
{
  gum_exec_ctx_write_arm_prolog (block->ctx, gc->arm_writer);
}

static void
gum_exec_block_thumb_open_prolog (GumExecBlock * block,
                                  GumGeneratorContext * gc)
{
  gum_exec_ctx_write_thumb_prolog (block->ctx, gc->thumb_writer);
}

static void
gum_exec_block_arm_close_prolog (GumExecBlock * block,
                                 GumGeneratorContext * gc)
{
  gum_exec_ctx_write_arm_epilog (block->ctx, gc->arm_writer);
}

static void
gum_exec_block_thumb_close_prolog (GumExecBlock * block,
                                   GumGeneratorContext * gc)
{
  gum_exec_ctx_write_thumb_epilog (block->ctx, gc->thumb_writer);
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

  if ((block->flags & GUM_EXEC_BLOCK_HAS_EXCLUSIVE_STORE) == 0)
    return;

  block_containing_load = NULL;
  for (cur = block, i = 0;
      cur != NULL && i != GUM_EXCLUSIVE_ACCESS_MAX_DEPTH;
      cur = cur->next, i++)
  {
    if ((cur->flags & GUM_EXEC_BLOCK_HAS_EXCLUSIVE_LOAD) != 0)
    {
      block_containing_load = cur;
      break;
    }
  }
  if (block_containing_load == NULL)
    return;

  for (cur = block; TRUE; cur = cur->next)
  {
    cur->flags |= GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS;
    gum_exec_block_invalidate (cur);

    if (cur == block_containing_load)
      break;
  }
}

static GumCodeSlab *
gum_code_slab_new (GumExecCtx * ctx)
{
  GumCodeSlab * slab;
  GumStalker * stalker = ctx->stalker;
  const gsize slab_size = stalker->code_slab_size_dynamic;
  GumAddressSpec spec;

  gum_exec_ctx_compute_code_address_spec (ctx, slab_size, &spec);

  slab = gum_memory_allocate_near (&spec, slab_size, stalker->page_size,
      stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);

  gum_code_slab_init (slab, slab_size, stalker->page_size);

  return slab;
}

static void
gum_code_slab_free (GumCodeSlab * code_slab)
{
  gum_slab_free (&code_slab->slab);
}

static void
gum_code_slab_init (GumCodeSlab * code_slab,
                    gsize slab_size,
                    gsize page_size)
{
  /*
   * We don't want to thaw and freeze the header just to update the offset,
   * so we trade a little memory for speed.
   */
  const gsize header_size = GUM_ALIGN_SIZE (sizeof (GumCodeSlab), page_size);

  gum_slab_init (&code_slab->slab, slab_size, header_size);

  code_slab->arm_invalidator = NULL;
  code_slab->thumb_invalidator = NULL;
}

static GumDataSlab *
gum_data_slab_new (GumExecCtx * ctx)
{
  GumDataSlab * slab;
  GumStalker * stalker = ctx->stalker;
  const gsize slab_size = stalker->data_slab_size_dynamic;
  GumAddressSpec spec;

  gum_exec_ctx_compute_data_address_spec (ctx, slab_size, &spec);

  slab = gum_memory_allocate_near (&spec, slab_size, stalker->page_size,
      GUM_PAGE_RW);

  gum_data_slab_init (slab, slab_size);

  return slab;
}

static void
gum_data_slab_free (GumDataSlab * data_slab)
{
  gum_slab_free (&data_slab->slab);
}

static void
gum_data_slab_init (GumDataSlab * data_slab,
                    gsize slab_size)
{
  GumSlab * slab = &data_slab->slab;
  const gsize header_size = sizeof (GumDataSlab);

  gum_slab_init (slab, slab_size, header_size);
}

static void
gum_scratch_slab_init (GumCodeSlab * scratch_slab,
                       gsize slab_size)
{
  const gsize header_size = sizeof (GumCodeSlab);

  gum_slab_init (&scratch_slab->slab, slab_size, header_size);

  scratch_slab->arm_invalidator = NULL;
  scratch_slab->thumb_invalidator = NULL;
}

static void
gum_slab_free (GumSlab * slab)
{
  const gsize header_size = slab->data - (guint8 *) slab;

  gum_memory_free (slab, header_size + slab->size);
}

static void
gum_slab_init (GumSlab * slab,
               gsize slab_size,
               gsize header_size)
{
  slab->data = (guint8 *) slab + header_size;
  slab->offset = 0;
  slab->size = slab_size - header_size;
  slab->next = NULL;
}

static gsize
gum_slab_available (GumSlab * self)
{
  return self->size - self->offset;
}

static gpointer
gum_slab_start (GumSlab * self)
{
  return self->data;
}

static gpointer
gum_slab_end (GumSlab * self)
{
  return self->data + self->size;
}

static gpointer
gum_slab_cursor (GumSlab * self)
{
  return self->data + self->offset;
}

static gpointer
gum_slab_align_cursor (GumSlab * self,
                       guint alignment)
{
  self->offset = GUM_ALIGN_SIZE (self->offset, alignment);

  return gum_slab_cursor (self);
}

static gpointer
gum_slab_reserve (GumSlab * self,
                  gsize size)
{
  gpointer cursor;

  cursor = gum_slab_try_reserve (self, size);
  g_assert (cursor != NULL);

  return cursor;
}

static gpointer
gum_slab_try_reserve (GumSlab * self,
                      gsize size)
{
  gpointer cursor;

  if (gum_slab_available (self) < size)
    return NULL;

  cursor = gum_slab_cursor (self);
  self->offset += size;

  return cursor;
}

static gpointer
gum_find_thread_exit_implementation (void)
{
#if defined (HAVE_GLIBC)
  return GSIZE_TO_POINTER (gum_module_find_export_by_name (
        gum_process_query_libc_name (),
        "__call_tls_dtors"));
#elif defined (HAVE_ANDROID)
  return GSIZE_TO_POINTER (gum_module_find_export_by_name (
        gum_process_query_libc_name (),
        "pthread_exit"));
#else
  return NULL;
#endif
}

static gpointer
gum_strip_thumb_bit (gpointer address)
{
  return GSIZE_TO_POINTER (GPOINTER_TO_SIZE (address) & ~0x1);
}

static gboolean
gum_is_thumb (gconstpointer address)
{
  return (GPOINTER_TO_SIZE (address) & 0x1) != 0;
}

static gboolean
gum_is_kuser_helper (gconstpointer address)
{
#ifdef HAVE_LINUX
  switch (GPOINTER_TO_SIZE (address))
  {
    case 0xffff0fa0: /* __kernel_memory_barrier */
    case 0xffff0fc0: /* __kernel_cmpxchg */
    case 0xffff0fe0: /* __kernel_get_tls */
    case 0xffff0f60: /* __kernel_cmpxchg64 */
      return TRUE;
    default:
      return FALSE;
  }
#else
  return FALSE;
#endif
}

static gboolean
gum_is_exclusive_load_insn (const cs_insn * insn)
{
  switch (insn->id)
  {
    case ARM_INS_LDAEX:
    case ARM_INS_LDAEXB:
    case ARM_INS_LDAEXD:
    case ARM_INS_LDAEXH:
    case ARM_INS_LDREX:
    case ARM_INS_LDREXB:
    case ARM_INS_LDREXD:
    case ARM_INS_LDREXH:
      return TRUE;
    default:
      return FALSE;
  }
}

static gboolean
gum_is_exclusive_store_insn (const cs_insn * insn)
{
  switch (insn->id)
  {
    case ARM_INS_STREX:
    case ARM_INS_STREXB:
    case ARM_INS_STREXD:
    case ARM_INS_STREXH:
    case ARM_INS_STLEX:
    case ARM_INS_STLEXB:
    case ARM_INS_STLEXD:
    case ARM_INS_STLEXH:
      return TRUE;
    default:
      return FALSE;
  }
}

static guint
gum_count_bits_set (guint16 value)
{
#if defined (HAVE_POPCOUNT)
  return __builtin_popcount (value);
#else
  guint num_ones = 0;
  guint16 bits = value;
  guint i;

  for (i = 0; i != 16; i++)
  {
    if ((bits & 1) == 1)
      num_ones++;
    bits >>= 1;
  }

  return num_ones;
#endif
}

static guint
gum_count_trailing_zeros (guint16 value)
{
#if defined (HAVE_CLTZ)
  return __builtin_ctz (value);
#else
  guint num_zeros = 0;
  guint16 bits = value;

  while ((bits & 1) == 0)
  {
    num_zeros++;
    bits >>= 1;
  }

  return num_zeros;
#endif
}

#endif
```