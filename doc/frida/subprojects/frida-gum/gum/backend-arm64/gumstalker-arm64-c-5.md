Response:
The user wants a breakdown of the `gumstalker-arm64.c` file, which is part of Frida, a dynamic instrumentation toolkit. They are looking for information about its functionalities, relevance to reverse engineering, interaction with low-level systems, logical reasoning, potential user errors, debugging context, and a summary.

Here's a plan to address each of these points:

1. **Functionality Listing:**  Scan the code for key functions and their purpose. Group related functions to describe larger features. Focus on what each function does in the context of dynamic instrumentation.

2. **Reverse Engineering Relevance:** Identify aspects of the code that directly facilitate reverse engineering tasks, like code tracing, function hooking, and understanding program flow. Provide concrete examples of how these features are used in reverse engineering.

3. **Binary/Kernel/Framework Interaction:** Look for code that interacts with processor registers (ARM64 specific), memory management (slabs, allocation), and potentially OS-level concepts like threads (though this file seems more focused on code generation). Highlight areas that demonstrate an understanding of the underlying system.

4. **Logical Reasoning (Input/Output):** Analyze functions with clear logic and potential branching. Create simple hypothetical scenarios with input values and the expected outcome based on the code. For example, the inline cache logic has inputs (target address) and outputs (cached address or a miss).

5. **User Errors:** Think about common mistakes a user might make when interacting with Frida or Stalker, which could lead to the execution reaching this code. This might involve misconfiguring Stalker or providing incorrect input to instrumentation functions.

6. **Debugging Context:** Consider how a developer would end up examining this specific file during debugging. What kinds of issues would lead them to this part of the Frida codebase?  Focus on the role of this code in the overall instrumentation process.

7. **Summary:**  Provide a concise overview of the main purpose of `gumstalker-arm64.c` based on the previous points.

**Mental Walkthrough:**

* **Code Generation:**  The file heavily uses `GumArm64Writer`, suggesting it's involved in generating ARM64 assembly code. The `gum_exec_block_write_*` functions are strong indicators of this.
* **Code Blocks:** The concept of `GumExecBlock` is central. It likely represents a region of instrumented code.
* **Instrumentation Events:** Functions like `gum_exec_block_write_call_event_code` and `gum_exec_block_write_ret_event_code` suggest the ability to insert code for tracing function calls and returns.
* **Inline Cache:**  `gum_exec_block_write_inline_cache_code` points to an optimization technique for handling branches.
* **Slab Allocation:** The `gum_code_slab_new` and `gum_data_slab_new` functions indicate a custom memory management system for the generated code and data.
* **Context Management:**  `GumExecCtx` appears to hold the context of the instrumentation process.

**Confidence Score:** 4/5 - I'm confident I can extract the main functionalities and their connections to the requested topics. The trickiest part might be precisely pinpointing the user's journey to this specific file during debugging, as it's a low-level component.

Let's start generating the response based on this plan.
This is the 6th and final part of the source code for `gumstalker-arm64.c`, a crucial component of Frida's dynamic instrumentation engine on ARM64 architecture. This file is responsible for the core logic of the Stalker, Frida's code tracing and instrumentation engine. Here's a breakdown of its functionalities:

**Functionalities of `gumstalker-arm64.c` (Summary and Details):**

This file primarily handles the **dynamic generation of ARM64 machine code** to instrument target processes. It implements the logic for:

1. **Managing Instrumented Code Blocks (`GumExecBlock`):**
    *   Creating, tracking, and invalidating blocks of generated code that correspond to the original execution flow.
    *   Associating these blocks with a context (`GumExecCtx`) containing information about the instrumentation session.
    *   Implementing logic to handle exclusive access and dependencies between blocks.

2. **Generating Code for Different Instrumentation Events:**
    *   **Function Calls (`gum_exec_block_write_call_event_code`):** Generates code to intercept function calls, allowing Frida to execute custom JavaScript code or perform other actions. It pushes the target address and calls the event emission function.
    *   **Function Returns (`gum_exec_block_write_ret_event_code`):** Generates code to intercept function returns, similarly enabling custom actions. It loads the return address from the link register (LR) and calls the event emission function.
    *   **Basic Block Execution (`gum_exec_block_write_block_event_code`):** Generates code to be executed at the beginning of each basic block, useful for tracking control flow.
    *   **Arbitrary Code Execution (`gum_exec_block_write_exec_event_code`):** Generates code to intercept execution at specific instruction addresses.

3. **Implementing an Inline Cache (`gum_exec_block_write_inline_cache_code`):**
    *   Optimizes branch handling by caching the target addresses of branches within instrumented code. This reduces the overhead of looking up the target block every time a branch occurs.
    *   If a branch target is found in the cache (cache hit), it directly jumps to the instrumented version.
    *   If there's a cache miss, it transfers control to a "slow slab" to handle the lookup and potentially create a new instrumented block.

4. **Managing Code and Data Slabs (`gum_code_slab_new`, `gum_data_slab_new`):**
    *   Allocates memory regions (slabs) to store the dynamically generated machine code and associated data structures.
    *   Uses a custom slab allocation system for efficiency. It aims to allocate code slabs near the original code to potentially improve performance.

5. **Handling Prologues and Epilogues (`gum_exec_block_open_prolog`, `gum_exec_block_close_prolog`):**
    *   Generates necessary setup code (prologue) and cleanup code (epilogue) for the instrumented sections. This often involves saving and restoring registers.

6. **Implementing "Unfollow" Logic (`gum_exec_block_write_unfollow_check_code`):**
    *   Allows the instrumentation to be selectively disabled or modified based on runtime conditions. This is crucial for performance and for handling scenarios where instrumentation is no longer needed.

7. **Supporting Call Probes (`gum_exec_block_maybe_write_call_probe_code`, `gum_exec_block_invoke_call_probes`):**
    *   Provides a mechanism to inject custom code or callbacks at the beginning of function calls, even if the function itself isn't being fully traced.

8. **Writing Inline Data (`gum_exec_block_write_inline_data`):**
    *   Allows embedding data directly within the generated code stream.

9. **Adjusting Execution Context Depth (`gum_exec_ctx_write_adjust_depth`):**
    *   Manages a depth counter within the execution context, potentially used for tracking nested calls or other execution states.

**Relationship with Reverse Engineering:**

This file is **fundamental** to the reverse engineering capabilities of Frida. Here's how:

*   **Code Tracing:** The core functionality of Stalker, driven by this code, enables reverse engineers to trace the exact execution flow of a program. By observing the sequence of basic blocks or instructions executed, they can understand how a program works, identify key algorithms, and locate vulnerabilities.
    *   **Example:** A reverse engineer wants to understand how a specific licensing check works. By using Frida's Stalker to trace the execution path when the application starts, they can pinpoint the exact functions and instructions involved in the license verification process.

*   **Function Hooking:** The code generation for call and return events allows reverse engineers to intercept function calls. This is essential for:
    *   **Analyzing function arguments and return values:** Understanding the inputs and outputs of functions can reveal their purpose and behavior.
    *   **Modifying function behavior:** By hooking a function, a reverse engineer can change its arguments, return values, or even redirect execution to a different piece of code, allowing them to bypass security checks or inject custom logic.
    *   **Example:** A reverse engineer suspects a function is responsible for decrypting network traffic. They can hook this function to examine the decrypted data before it's processed.

*   **Understanding Control Flow:** The block execution events and inline caching mechanisms help visualize and analyze the control flow of the target application, especially for complex or obfuscated code.

**Binary Underlying, Linux, Android Kernel and Framework Knowledge:**

This file demonstrates significant knowledge of the underlying system:

*   **ARM64 Architecture:** The code directly manipulates ARM64 registers (e.g., `ARM64_REG_X16`, `ARM64_REG_LR`, `ARM64_REG_SP`) and uses ARM64 assembly instructions (e.g., `stp`, `ldr`, `str`, `b`, `bl`). The functions in `GumArm64Writer` abstract the assembly generation, but the logic behind them is specific to ARM64.
*   **Memory Management:** The implementation of custom slab allocators (`GumCodeSlab`, `GumDataSlab`) shows an understanding of memory layout and the need for efficient memory allocation in dynamic instrumentation. The attempt to allocate code slabs near the original code reflects an awareness of potential performance benefits related to instruction cache locality.
*   **Code Caching and Optimization:** The inline cache mechanism is a clear example of optimizing for performance by reducing the overhead of repeatedly looking up instrumented code blocks.
*   **Red Zones:** The code mentions `GUM_RED_ZONE_SIZE`, indicating awareness of the ARM64 Application Binary Interface (ABI) and the concept of red zones in the stack for temporary storage.
*   **Pointer Authentication (`GUM_CPU_PTRAUTH`):** The code checks for and handles ARM's Pointer Authentication feature, showing awareness of security enhancements in newer ARM architectures.
*   **Operating System Concepts:** Although not directly interacting with kernel APIs in this specific file, the concepts of code injection, memory protection (RWX pages), and thread context manipulation (as seen in the call probe implementation) are inherently related to OS-level functionalities. Frida as a whole relies heavily on OS-specific mechanisms for process attachment and code injection.
*   **Dynamic Linking and Symbol Resolution:** The `gum_find_thread_exit_implementation` function shows an understanding of how to locate functions in shared libraries at runtime, a crucial aspect of dynamic linking in Linux and Android.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `gum_exec_block_write_inline_cache_code` function:

*   **Hypothetical Input:**
    *   `block`: A `GumExecBlock` representing a block of instrumented code.
    *   `target_reg`: `ARM64_REG_X2` (let's say the branch target address is in X2).
    *   The inline cache in `block->ic_entries` is initially empty (all `code_start` are `GUM_IC_MAGIC_EMPTY`).
    *   `stalker->ic_entries`: 4 (the inline cache can hold 4 entries).
    *   The target address in `X2` does *not* match any `real_start` in the cache.

*   **Expected Output:**
    *   The generated code will first save X16 and X17 on the stack.
    *   It will load the address of the inline cache (`block->ic_entries`) into X17.
    *   It will iterate through the cache entries, comparing the target address in X2 (moved to X16) with each `real_start`.
    *   Since there's a cache miss, the comparison will always result in a non-zero value, causing the `cbnz` instruction to jump to the `mismatch` label.
    *   In the `mismatch` block, it will increment the pointer in X17 to point to the next cache entry.
    *   After iterating through all cache entries without a match, it will execute `gum_exec_block_write_slab_transfer_code`, which likely handles transferring control to the slow slab for further processing.
    *   The original values of X16 and X17 will be restored from the stack in the slow slab code.
    *   The function `gum_exec_block_write_inline_cache_code` itself returns `ARM64_REG_X17`, but in this miss scenario, the value in X17 after the function returns will likely be the address within the slow slab.

**User or Programming Common Usage Errors:**

While this file is a low-level implementation detail, user errors in Frida can indirectly lead to issues here:

*   **Incorrect Stalker Configuration:** If a user configures Stalker with very small code or data slab sizes, it can lead to frequent slab allocations and potentially performance problems or even crashes when the slabs run out of space. This could manifest as errors or unexpected behavior originating from the slab allocation logic in this file.
*   **Instrumenting Very Large Code Regions:**  Attempting to trace or instrument a massive amount of code can overwhelm Stalker's resources, leading to memory allocation failures within the slab system.
*   **Conflicting Instrumentation Logic:** If a user's JavaScript code interacts in a way that creates inconsistencies in Stalker's internal state (though less directly related to *this* file), it could lead to unexpected code generation or invalidations.
*   **Attaching to Processes with Unusual Memory Layouts:** While Frida tries to handle various scenarios, attaching to processes with highly fragmented or unusual memory layouts might expose edge cases in the slab allocation logic.

**User Operation Steps to Reach Here (Debugging Clues):**

A developer might end up examining `gumstalker-arm64.c` during debugging if they encounter issues like:

1. **Performance Problems with Stalker:** If Stalker is causing a significant performance slowdown, a developer might investigate the code generation and caching mechanisms in this file to identify bottlenecks.
2. **Crashes or Unexpected Behavior During Instrumentation:** If the target application crashes or behaves erratically after Frida instrumentation, the developer might suspect issues with the generated code, incorrect register handling, or problems with the slab allocation. They might step through the code generation functions to see what instructions are being generated.
3. **Issues with Branch Handling:** If control flow seems to be incorrectly redirected during tracing, the developer might examine the inline cache logic in `gum_exec_block_write_inline_cache_code` to see if there are cache misses or incorrect cache updates.
4. **Memory Allocation Errors Related to Stalker:** If there are errors indicating memory allocation failures within Stalker, the developer would likely investigate the `gum_code_slab_new` and `gum_data_slab_new` functions.

**Typical Debugging Scenario:**

A user reports that their Frida script causes the target application to crash intermittently. The developer might:

1. **Examine the Frida script:** Look for potential logic errors or resource leaks in the JavaScript code.
2. **Enable Frida's debug logs:** This might provide hints about where the crash is occurring within the Frida engine.
3. **Use a debugger (like GDB) to attach to the Frida agent:** Set breakpoints in `gumstalker-arm64.c`, particularly in functions involved in code generation (`gum_exec_block_write_*`) or slab allocation (`gum_code_slab_new`).
4. **Step through the code:** Observe the generated ARM64 instructions and the state of the `GumExecCtx` and `GumExecBlock` structures to identify any inconsistencies or errors.
5. **Analyze memory allocation:** Check the state of the code and data slabs to see if there are any issues with memory exhaustion or corruption.

**归纳一下它的功能 (Summarizing its Functionality):**

In essence, `gumstalker-arm64.c` is the **core code generation engine for Frida's Stalker on ARM64**. It dynamically generates machine code to intercept and instrument program execution, enabling features like code tracing, function hooking, and runtime analysis. It manages the allocation of memory for this generated code and implements optimizations like inline caching to improve performance. This file embodies the low-level mechanics that empower Frida's dynamic instrumentation capabilities on ARM64 systems.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm64/gumstalker-arm64.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第6部分，共6部分，请归纳一下它的功能

"""
)
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

static void
gum_exec_ctx_write_adjust_depth (GumExecCtx * ctx,
                                 GumArm64Writer * cw,
                                 gssize adj)
{
  /* ctx->depth += adj */
  if ((ctx->sink_mask & (GUM_CALL | GUM_RET)) == 0)
    return;

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE), GUM_INDEX_PRE_ADJUST);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->depth));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);
  if (adj > 0)
  {
    gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X17,
        ARM64_REG_X17, adj);
  }
  else
  {
    gum_arm64_writer_put_sub_reg_reg_imm (cw, ARM64_REG_X17,
        ARM64_REG_X17, -adj);
  }
  gum_arm64_writer_put_str_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);

  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE, GUM_INDEX_POST_ADJUST);
}

/*
 * This function generates code required to search the inline cache stored in
 * the data slab in search of the target address of a branch. If successful, the
 * code (instrumented) address from the inline cache is returned in the register
 * returned by the function (fixed at X17). In this case, the values of X16 and
 * X17 stored beyond the red-zone are not restored (this facilitates the
 * indirect branching to the target block if necessary).
 *
 * If there is a cache miss, however, control passes to the slow slab, and the
 * values of X16 and X17 are restored from the stack.
 */
static arm64_reg
gum_exec_block_write_inline_cache_code (GumExecBlock * block,
                                        arm64_reg target_reg,
                                        GumArm64Writer * cw,
                                        GumArm64Writer * cws)
{
  GumSlab * data_slab = &block->ctx->data_slab->slab;
  GumStalker * stalker = block->ctx->stalker;
  guint i;
  const gsize empty_val = GUM_IC_MAGIC_EMPTY;
  gconstpointer match, mismatch;

  block->ic_entries = gum_slab_reserve (data_slab,
      gum_stalker_get_ic_entry_size (stalker));

  for (i = 0; i != stalker->ic_entries; i++)
  {
    block->ic_entries[i].real_start = NULL;
    block->ic_entries[i].code_start = GSIZE_TO_POINTER (empty_val);
  }

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16,
      ARM64_REG_X17, ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE),
      GUM_INDEX_PRE_ADJUST);

  gum_arm64_writer_put_push_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);

  if (target_reg != ARM64_REG_X16)
    gum_arm64_writer_put_mov_reg_reg (cw, ARM64_REG_X16, target_reg);

  if ((stalker->cpu_features & GUM_CPU_PTRAUTH) != 0)
    gum_arm64_writer_put_xpaci_reg (cw, ARM64_REG_X16);

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X17,
      GUM_ADDRESS (block->ic_entries));

  match = gum_arm64_writer_cur (cw);
  for (i = 0; i != stalker->ic_entries; i++)
  {
    gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X0, ARM64_REG_X17,
        G_STRUCT_OFFSET (GumIcEntry, real_start));
    gum_arm64_writer_put_sub_reg_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X0,
        ARM64_REG_X16);

    mismatch = gum_arm64_writer_cur (cw);
    gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X0, mismatch);
    gum_arm64_writer_put_b_label (cw, match);

    gum_arm64_writer_put_label (cw, mismatch);
    gum_arm64_writer_put_add_reg_reg_imm (cw, ARM64_REG_X17, ARM64_REG_X17,
        sizeof (GumIcEntry));
  }

  gum_exec_block_write_slab_transfer_code (cw, cws);
  gum_arm64_writer_put_pop_reg_reg (cws, ARM64_REG_X0, ARM64_REG_X1);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cws, ARM64_REG_X16,
      ARM64_REG_X17, ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE,
      GUM_INDEX_POST_ADJUST);

  gum_arm64_writer_put_label (cw, match);
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X0, ARM64_REG_X1);
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X17,
      G_STRUCT_OFFSET (GumIcEntry, code_start));

  return ARM64_REG_X17;
}

static void
gum_exec_block_write_exec_generated_code (GumArm64Writer * cw,
                                          GumExecCtx * ctx)
{
  gconstpointer dont_pop_now = cw->code + 1;

  gum_arm64_writer_put_stp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, -(16 + GUM_RED_ZONE_SIZE), GUM_INDEX_PRE_ADJUST);

  /*
   * If there is an instrumented target block (ctx->current_block), then we
   * perform an indirect branch to (ctx->resume_at) leaving the values of X16
   * and X17 on the stack. Otherwise, our branch target is not an instrumented
   * block and we must therefore pop these values from the stack before we carry
   * out the branch. In this case, we don't care about the fact we clobber X16
   * below as the AArch64 documentation denotes X16 and X17 as IP0 and IP1 and
   * states:
   *
   * "Registers r16 (IP0) and r17 (IP1) may be used by a linker as a scratch
   * register between a routine and any subroutine it calls."
   */
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->current_block));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);
  gum_arm64_writer_put_cbnz_reg_label (cw, ARM64_REG_X17, dont_pop_now);
  gum_arm64_writer_put_ldp_reg_reg_reg_offset (cw, ARM64_REG_X16, ARM64_REG_X17,
      ARM64_REG_SP, 16 + GUM_RED_ZONE_SIZE, GUM_INDEX_POST_ADJUST);

  gum_arm64_writer_put_label (cw, dont_pop_now);
  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->resume_at));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16, 0);
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X17);
}

static void
gum_exec_block_write_call_event_code (GumExecBlock * block,
                                      const GumBranchTarget * target,
                                      GumGeneratorContext * gc,
                                      GumCodeContext cc)
{
  GumArm64Writer * cw = gc->code_writer;

  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, cw);

  gum_exec_ctx_write_push_branch_target_address (block->ctx, target, gc,
      gc->code_writer);
  gum_arm64_writer_put_pop_reg_reg (cw, ARM64_REG_X2, ARM64_REG_XZR);

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_emit_call_event), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, ARM64_REG_X2,
      GUM_ARG_REGISTER, ARM64_REG_X20);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
}

static void
gum_exec_block_write_ret_event_code (GumExecBlock * block,
                                     GumGeneratorContext * gc,
                                     GumCodeContext cc)
{
  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, gc->code_writer);

  gum_exec_ctx_load_real_register_into (block->ctx, ARM64_REG_X2, ARM64_REG_LR,
      gc, gc->code_writer);

  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_ret_event), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, ARM64_REG_X2,
      GUM_ARG_REGISTER, ARM64_REG_X20);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
}

static void
gum_exec_block_write_exec_event_code (GumExecBlock * block,
                                      GumGeneratorContext * gc,
                                      GumCodeContext cc)
{
  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, gc->code_writer);

  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_exec_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
      GUM_ARG_REGISTER, ARM64_REG_X20);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
}

static void
gum_exec_block_write_block_event_code (GumExecBlock * block,
                                       GumGeneratorContext * gc,
                                       GumCodeContext cc)
{
  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, gc->code_writer);

  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_exec_ctx_emit_block_event), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM64_REG_X20);

  gum_exec_block_write_unfollow_check_code (block, gc, cc);
}

static void
gum_exec_block_write_unfollow_check_code (GumExecBlock * block,
                                          GumGeneratorContext * gc,
                                          GumCodeContext cc)
{
  GumExecCtx * ctx = block->ctx;
  GumArm64Writer * cw = gc->code_writer;
  gconstpointer beach = cw->code + 1;
  GumPrologType opened_prolog;

  if (cc != GUM_CODE_INTERRUPTIBLE)
    return;

  gum_arm64_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_maybe_unfollow), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
  gum_arm64_writer_put_cbz_reg_label (cw, ARM64_REG_X0, beach);

  opened_prolog = gc->opened_prolog;
  gum_exec_block_close_prolog (block, gc, cw);
  gc->opened_prolog = opened_prolog;

  gum_arm64_writer_put_ldr_reg_address (cw, ARM64_REG_X16,
      GUM_ADDRESS (&ctx->resume_at));
  gum_arm64_writer_put_ldr_reg_reg_offset (cw, ARM64_REG_X17, ARM64_REG_X16,
      0);
  gum_arm64_writer_put_br_reg_no_auth (cw, ARM64_REG_X17);

  gum_arm64_writer_put_label (cw, beach);
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
          block->real_start))
  {
    gum_exec_block_write_call_probe_code (block, gc);
  }

  gum_spinlock_release (&stalker->probe_lock);
}

static void
gum_exec_block_write_call_probe_code (GumExecBlock * block,
                                      GumGeneratorContext * gc)
{
  g_assert (gc->opened_prolog == GUM_PROLOG_NONE);
  gum_exec_block_open_prolog (block, GUM_PROLOG_FULL, gc, gc->code_writer);

  gum_arm64_writer_put_call_address_with_arguments (gc->code_writer,
      GUM_ADDRESS (gum_exec_block_invoke_call_probes), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM64_REG_X20);
}

static void
gum_exec_block_invoke_call_probes (GumExecBlock * block,
                                   GumCpuContext * cpu_context)
{
  GumStalker * stalker = block->ctx->stalker;
  const gpointer target_address = block->real_start;
  GumCallProbe ** probes_copy;
  guint num_probes, i;
  GumCallDetails d;

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

  cpu_context->pc = GPOINTER_TO_SIZE (target_address);

  for (i = 0; i != num_probes; i++)
  {
    GumCallProbe * probe = probes_copy[i];

    probe->callback (&d, probe->user_data);

    gum_call_probe_unref (probe);
  }
}

static gpointer
gum_exec_block_write_inline_data (GumArm64Writer * cw,
                                  gconstpointer data,
                                  gsize size,
                                  GumAddress * address)
{
  gpointer location;
  gconstpointer after_data = cw->code + 1;

  g_assert (size % 4 == 0);

  while (gum_arm64_writer_offset (cw) < GUM_INVALIDATE_TRAMPOLINE_MAX_SIZE)
  {
    gum_arm64_writer_put_nop (cw);
  }

  gum_arm64_writer_put_b_label (cw, after_data);

  location = gum_arm64_writer_cur (cw);
  if (address != NULL)
    *address = cw->pc;
  gum_arm64_writer_put_bytes (cw, data, size);

  gum_arm64_writer_put_label (cw, after_data);

  return location;
}

static void
gum_exec_block_open_prolog (GumExecBlock * block,
                            GumPrologType type,
                            GumGeneratorContext * gc,
                            GumArm64Writer * cw)
{
  if (gc->opened_prolog >= type)
    return;

  /* We don't want to handle this case for performance reasons */
  g_assert (gc->opened_prolog == GUM_PROLOG_NONE);

  gc->opened_prolog = type;

  gum_exec_ctx_write_prolog (block->ctx, type, cw);
}

static void
gum_exec_block_close_prolog (GumExecBlock * block,
                             GumGeneratorContext * gc,
                             GumArm64Writer * cw)
{
  if (gc->opened_prolog == GUM_PROLOG_NONE)
    return;

  gum_exec_ctx_write_epilog (block->ctx, gc->opened_prolog, cw);

  gc->opened_prolog = GUM_PROLOG_NONE;
}

static GumCodeSlab *
gum_code_slab_new (GumExecCtx * ctx)
{
  GumStalker * stalker = ctx->stalker;
  gsize total_size;
  GumCodeSlab * code_slab;
  GumSlowSlab * slow_slab;
  GumAddressSpec spec;

  total_size = stalker->code_slab_size_dynamic +
      stalker->slow_slab_size_dynamic;

  gum_exec_ctx_compute_code_address_spec (ctx, total_size, &spec);

  code_slab = gum_memory_allocate_near (&spec, total_size, stalker->page_size,
      stalker->is_rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW);
  if (code_slab == NULL)
  {
    g_error ("Unable to allocate code slab near %p with max_distance=%zu",
        spec.near_address, spec.max_distance);
  }

  gum_code_slab_init (code_slab, stalker->code_slab_size_dynamic, total_size,
      stalker->page_size);

  slow_slab = gum_slab_end (&code_slab->slab);
  gum_slow_slab_init (slow_slab, stalker->slow_slab_size_dynamic, 0,
      stalker->page_size);

  return code_slab;
}

static void
gum_code_slab_free (GumCodeSlab * code_slab)
{
  gum_slab_free (&code_slab->slab);
}

static void
gum_code_slab_init (GumCodeSlab * code_slab,
                    gsize slab_size,
                    gsize memory_size,
                    gsize page_size)
{
  /*
   * We don't want to thaw and freeze the header just to update the offset,
   * so we trade a little memory for speed.
   */
  const gsize header_size = GUM_ALIGN_SIZE (sizeof (GumCodeSlab), page_size);

  gum_slab_init (&code_slab->slab, slab_size, memory_size, header_size);

  code_slab->invalidator = NULL;
}

static void
gum_slow_slab_init (GumSlowSlab * slow_slab,
                    gsize slab_size,
                    gsize memory_size,
                    gsize page_size)
{
  /*
   * We don't want to thaw and freeze the header just to update the offset,
   * so we trade a little memory for speed.
   */
  const gsize header_size = GUM_ALIGN_SIZE (sizeof (GumCodeSlab), page_size);

  gum_slab_init (&slow_slab->slab, slab_size, memory_size, header_size);

  slow_slab->invalidator = NULL;
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
  if (slab == NULL)
  {
    g_error ("Unable to allocate data slab near %p with max_distance=%zu",
        spec.near_address, spec.max_distance);
  }

  gum_data_slab_init (slab, slab_size, slab_size);

  return slab;
}

static void
gum_data_slab_free (GumDataSlab * data_slab)
{
  gum_slab_free (&data_slab->slab);
}

static void
gum_data_slab_init (GumDataSlab * data_slab,
                    gsize slab_size,
                    gsize memory_size)
{
  GumSlab * slab = &data_slab->slab;
  const gsize header_size = sizeof (GumDataSlab);

  gum_slab_init (slab, slab_size, memory_size, header_size);
}

static void
gum_scratch_slab_init (GumCodeSlab * scratch_slab,
                       gsize slab_size)
{
  const gsize header_size = sizeof (GumCodeSlab);

  gum_slab_init (&scratch_slab->slab, slab_size, slab_size, header_size);

  scratch_slab->invalidator = NULL;
}

static void
gum_slab_free (GumSlab * slab)
{
  if (slab->memory_size != 0)
    gum_memory_free (slab, slab->memory_size);
}

static void
gum_slab_init (GumSlab * slab,
               gsize slab_size,
               gsize memory_size,
               gsize header_size)
{
  slab->data = (guint8 *) slab + header_size;
  slab->offset = 0;
  slab->size = slab_size - header_size;
  slab->memory_size = memory_size;
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
#if defined (HAVE_DARWIN)
  guint32 * cursor;

  cursor = GSIZE_TO_POINTER (gum_strip_code_address (
      gum_module_find_export_by_name ("/usr/lib/system/libsystem_pthread.dylib",
          "pthread_exit")));

  do
  {
    guint32 insn = *cursor;

    if (gum_is_bl_imm (insn))
    {
      union
      {
        gint32 i;
        guint32 u;
      } distance;

      distance.u = insn & GUM_INT26_MASK;
      if ((distance.u & (1 << (26 - 1))) != 0)
        distance.u |= 0xfc000000;

      return cursor + distance.i;
    }

    cursor++;
  }
  while (TRUE);
#elif defined (HAVE_GLIBC)
  return GSIZE_TO_POINTER (gum_module_find_export_by_name (
        gum_process_query_libc_name (),
        "__call_tls_dtors"));
#elif defined (HAVE_ANDROID)
  return GSIZE_TO_POINTER (gum_module_find_export_by_name (
        gum_process_query_libc_name (),
        "pthread_exit"));
#elif defined (HAVE_FREEBSD)
  return GSIZE_TO_POINTER (gum_module_find_export_by_name (
        "/lib/libthr.so.3",
        "_pthread_exit"));
#else
  return NULL;
#endif
}

static gboolean
gum_is_bl_imm (guint32 insn)
{
  return (insn & ~GUM_INT26_MASK) == 0x94000000;
}

#endif

"""


```