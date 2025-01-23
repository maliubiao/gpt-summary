Response:
The user wants a summary of the functionalities of the C code provided, which is a part of Frida's dynamic instrumentation tool, specifically focusing on the ARM architecture. The request also asks for connections to reverse engineering, low-level concepts (binary, Linux/Android kernel/framework), logical inferences, potential user errors, and how the execution flow reaches this code.

Here's a breakdown of the thought process to generate the answer:

1. **Identify the Core Function:** The filename `gumstalker-arm.c` and the function names (e.g., `gum_exec_block_virtualize_arm_branch_insn`, `gum_exec_block_virtualize_thumb_call_insn`) clearly indicate that this code is responsible for *virtualizing* or *instrumenting* ARM and Thumb instructions. This is the central function.

2. **Categorize Functionalities:**  Scan through the code and group similar actions. Keywords like "virtualize," "write," "handle," and the specific instruction types (branch, call, return, SVC) provide clues. The prominent patterns are:
    * **Instruction Handling:** Different functions for various instruction types (branch, call, return, SVC).
    * **Conditional Execution:** Handling conditional execution of instructions.
    * **Event Handling:**  Generating events for execution, calls, and returns.
    * **Stack Management:** Pushing and popping stack frames.
    * **Block Switching:**  Switching between instrumented code blocks.
    * **Excluded Ranges:** Handling code sections that should not be instrumented.
    * **Kernel User Helpers:** Special handling for calls to kernel user helpers.
    * **Code Generation:**  Using `GumArmWriter` and `GumThumbWriter` to generate new code.
    * **Relocation:** Using `GumArmRelocator` and `GumThumbRelocator` to adjust code addresses.
    * **Backpatching:** Modifying generated code after initial generation.

3. **Relate to Reverse Engineering:** How does this code aid reverse engineering?  The ability to intercept and modify the execution flow of a program is fundamental to dynamic analysis. Key aspects to highlight:
    * **Dynamic Analysis:**  The core function is to enable dynamic analysis.
    * **Tracing:** The execution events allow for tracing program flow.
    * **Hooking:** The ability to insert code before and after instructions is a form of hooking.
    * **Understanding Behavior:** Observing the program's behavior at runtime.

4. **Connect to Low-Level Concepts:** Identify areas where the code interacts with low-level details:
    * **ARM Architecture:**  The code is specific to ARM, handling ARM and Thumb instruction sets, registers, and condition codes.
    * **Instruction Formats:**  The code parses and manipulates instructions.
    * **Memory Management:**  Allocation of code blocks, understanding memory addresses.
    * **Stack Frames:**  Explicit manipulation of the stack.
    * **System Calls (SVC):**  Special handling for system calls, specific to Linux (`__NR_clone`).
    * **Kernel User Helpers:** Interaction with a kernel-level optimization.
    * **Relocation:** Necessary because the instrumented code is placed at different memory locations.

5. **Identify Logical Inferences (with hypothetical input/output):** Look for conditional logic and the transformations applied. A simple example is the handling of conditional branches:
    * **Input:** An ARM `BEQ` instruction (branch if equal).
    * **Logic:** The code checks the zero flag.
    * **Output:** If the zero flag is set, execution jumps to the target; otherwise, it continues to the next instruction. Frida adds instrumentation to both paths.

6. **Consider User/Programming Errors:** Think about common mistakes when using a dynamic instrumentation tool:
    * **Incorrect Filter:**  Not specifying the correct functions or addresses to instrument.
    * **Over-Instrumentation:**  Instrumenting too much code, leading to performance issues.
    * **Conflicting Hooks:**  Multiple instrumentation points interfering with each other.
    * **Memory Corruption:**  Errors in the instrumentation logic potentially corrupting the target process's memory.

7. **Describe User Interaction (Debugging Clue):**  How does a user initiate the process that leads to this code being executed?  Think about the general workflow of using Frida:
    * **Frida Client:** The user interacts with the Frida client (Python, JavaScript).
    * **Attaching to Process:** The client attaches to a target process.
    * **Stalker:** The user utilizes Frida's Stalker API to specify what code to instrument.
    * **Instrumentation Logic:** Stalker uses this `gumstalker-arm.c` code to generate the instrumentation.

8. **Summarize the Functionality (Part 5 of 6):** Combine the identified functionalities into a concise summary, acknowledging that this is one part of a larger system. Emphasize the core role of instruction virtualization and the various aspects it encompasses.

9. **Review and Refine:** Read through the generated answer to ensure clarity, accuracy, and completeness. Check if all aspects of the prompt have been addressed. Ensure the language is appropriate and avoids overly technical jargon where possible, while still being informative.
好的，我们来归纳一下 `frida/subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c` 这个文件的功能，基于你提供的代码片段。

**核心功能归纳:**

这个文件的核心功能是**在 ARM 架构上实现代码块的虚拟化（Virtualization）和插桩（Instrumentation）**。它是 Frida Stalker 组件在 ARM 平台上的核心组成部分，负责将目标进程的原生代码转化为 Frida 可以监控和控制的等效代码，从而实现动态插桩。

更具体地说，它完成了以下任务：

1. **指令级别的处理:**  针对不同的 ARM 和 Thumb 指令（例如分支指令、调用指令、返回指令、SVC 指令），提供了不同的虚拟化处理函数。这些函数会生成新的代码，用于在原始指令执行前后插入额外的逻辑。

2. **控制流劫持:**  通过修改分支、调用和返回指令的行为，将程序的控制流导向 Frida 生成的插桩代码，从而在关键执行点上执行用户定义的逻辑。

3. **事件通知:**  在执行到特定的指令时（例如分支、调用、返回），会生成相应的事件通知，以便 Frida 用户可以监控程序的执行轨迹。这体现在 `gum_exec_block_write_arm_exec_event_code`、`gum_exec_block_write_arm_call_event_code` 和 `gum_exec_block_write_arm_ret_event_code` 等函数中。

4. **栈帧管理:**  对于调用和返回指令，会显式地管理栈帧，例如在调用前压栈，在返回前弹栈。这确保了插桩代码的正确执行，并为事件通知提供了必要的上下文信息。

5. **代码生成:**  使用 `GumArmWriter` 和 `GumThumbWriter` 来生成新的 ARM 和 Thumb 代码。这些 writer 提供了便捷的接口来构建指令序列。

6. **代码重定位:**  使用 `GumArmRelocator` 和 `GumThumbRelocator` 来处理原始指令的重定位。由于插桩代码插入后，原始指令的地址可能会发生变化，需要进行调整以确保其功能不变。

7. **处理排除范围:**  支持排除特定的代码范围不进行插桩。`gum_exec_block_write_arm_handle_excluded` 和 `gum_exec_block_write_thumb_handle_excluded` 函数实现了这个功能，会在执行到排除范围内的代码时，直接执行原始指令。

8. **特殊处理内核辅助函数 (kuser_helper):**  针对 Linux 内核中的 `kuser_helper` 机制进行了特殊处理。由于这些辅助函数在用户空间执行，但其代码可能并不在当前进程的内存中，Frida 需要特别处理这种情况，通常会选择在 Stalker 引擎外部执行这些代码。

9. **条件执行处理:**  正确处理 ARM 指令的条件执行码 (condition code)，确保在原始指令不满足条件时不执行插桩逻辑。

**与逆向方法的关联举例说明:**

* **动态追踪:**  通过插桩分支指令和调用指令，可以追踪程序的执行路径。例如，每当执行到一个 `B` (branch) 指令或 `BL` (branch with link) 指令时，Frida 可以记录下跳转的目标地址，从而还原程序的控制流图。
* **Hooking 函数:**  通过插桩函数调用的入口和出口，可以实现对特定函数的 Hook。例如，可以插桩 `gum_exec_block_virtualize_arm_call_insn` 和 `gum_exec_block_virtualize_thumb_call_insn`，在函数调用前后执行自定义的代码，例如修改函数参数或返回值。
* **观察寄存器和内存:**  在插桩代码中，可以访问和修改程序的寄存器和内存状态。例如，在 `gum_exec_block_virtualize_arm_branch_insn` 中，可以看到操作寄存器的代码，可以扩展这些代码来记录关键寄存器的值。
* **代码覆盖率分析:**  通过记录哪些代码块被执行到，可以进行代码覆盖率分析，帮助理解程序的执行路径和测试覆盖率。

**涉及二进制底层、Linux、Android 内核及框架的知识举例说明:**

* **ARM 指令集架构:**  代码中直接操作 ARM 和 Thumb 指令，例如 `gum_arm_writer_put_b_cond_label` (生成条件分支指令)，`gum_thumb_writer_put_ldr_reg_address` (生成加载指令)。这需要深入理解 ARM 指令的编码格式和执行语义。
* **寄存器约定:**  代码中使用了特定的寄存器，例如 `ARM_REG_R5`，`ARM_REG_LR` (Link Register)，`ARM_REG_PC` (Program Counter)，这需要了解 ARM 架构的寄存器用途和调用约定。
* **条件码 (Condition Codes):**  `arm_cc cc` 参数和对条件码的处理，如 `ARM_CC_NE` (不等于)，`ARM_CC_EQ` (等于)，体现了对 ARM 指令条件执行机制的理解。
* **栈帧结构:**  `gum_exec_block_write_arm_push_stack_frame` 和 `gum_exec_block_write_arm_pop_stack_frame` 函数涉及到栈帧的压栈和弹栈操作，需要了解 ARM 架构上的栈帧布局和管理方式。
* **SVC 指令 (System Calls):**  `gum_exec_block_virtualize_arm_svc_insn` 和 `gum_exec_block_virtualize_thumb_svc_insn` 函数处理了系统调用指令，并且特别关注了 `clone` 系统调用 (`__NR_clone`)，这涉及到 Linux 系统调用的知识。
* **内核辅助函数 (kuser_helper):**  对 `kuser_helper` 的特殊处理体现了对 Linux 内核机制的理解。这些辅助函数通常用于在用户空间执行一些特权操作。
* **Android 框架 (间接相关):**  虽然代码本身没有直接涉及 Android 框架的 API，但 Frida 常用于 Android 平台的动态分析和 Hook，因此这个文件是 Frida 在 Android 上工作的基础。

**逻辑推理的假设输入与输出举例:**

假设输入是一个 ARM `BNE 0x1000` 指令 (如果不等于则跳转到地址 0x1000)。

* **假设输入:**  一个 `GumExecBlock` 对象，包含当前代码块的信息；一个 `GumBranchTarget` 对象，指向目标地址 0x1000；`arm_cc` 为 `ARM_CC_NE`。
* **逻辑推理:**  `gum_exec_block_virtualize_arm_branch_insn` 函数会被调用。由于条件码不是 `ARM_CC_AL` (总是执行)，`gum_exec_block_write_arm_handle_not_taken` 会被调用。
* **输出 (部分):**  生成的插桩代码可能包含一个条件分支指令，类似于 `BNE <label_taken>`，如果条件不满足，则执行后续的事件通知和 block 切换逻辑。如果条件满足，则跳转到 `label_taken`，其中包含了原始的分支行为。

**用户或编程常见的使用错误举例说明:**

* **Hook 了过多的指令:**  如果用户使用 Frida Stalker 监控了大量的指令，会导致性能开销很大。`gumstalker-arm.c` 负责对每一条被监控的指令进行虚拟化和插桩，过多的指令会显著增加 CPU 负担。
* **不正确的排除范围:**  用户可能错误地排除了需要监控的代码范围，导致 Frida 无法捕获到关键的执行流程。
* **与其它 Frida 功能冲突:**  用户可能同时使用了多个 Frida 功能，例如 Memory Access Watchpoint 和 Stalker，如果配置不当，可能会导致冲突。
* **假设输入与实际不符:**  在编写 Frida 脚本时，用户可能对目标程序的行为做出错误的假设，例如假设某个分支一定会发生，但实际情况并非如此，这可能导致插桩逻辑无法按预期执行。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **用户启动 Frida 客户端:**  用户在 PC 上运行 Frida 的 Python 或 JavaScript 客户端。
2. **用户连接到目标进程:**  客户端通过 USB 或 TCP 连接到目标设备上的目标 Android 进程。
3. **用户使用 Stalker API:**  在 Frida 脚本中，用户使用 `Stalker.follow()` 或 `Stalker. ম্যানুয়াল()` 等 API 来启动 Stalker，并指定要监控的线程或代码范围。例如：
   ```javascript
   Stalker.follow({
     onReceive: function (events) { /* 处理事件 */ },
     transform: function (iterator) { /* 自定义插桩逻辑 */ }
   });
   ```
4. **Frida 将 Stalker 配置发送到 Agent:**  Frida 客户端将用户的 Stalker 配置信息发送到目标进程中的 Frida Agent。
5. **Stalker 在目标进程中启动:**  Frida Agent 接收到配置后，会启动 Stalker 组件。
6. **Stalker 拦截指令:**  当目标进程执行到 Stalker 监控范围内的指令时，Stalker 会拦截这些指令。
7. **调用 `gumstalker-arm.c` 中的函数:**  对于 ARM 架构的进程，Stalker 会调用 `gumstalker-arm.c` 中相应的虚拟化函数，例如 `gum_exec_block_virtualize_arm_branch_insn` 来处理分支指令。
8. **生成和执行插桩代码:**  `gumstalker-arm.c` 中的函数会生成包含事件通知和控制流切换的插桩代码，并将程序的执行权转移到这些代码。

因此，当用户使用 Frida Stalker 功能对 ARM 进程进行动态插桩时，目标进程执行的每一条被监控的指令都会经过 `gumstalker-arm.c` 中的代码处理。这个文件是 Frida Stalker 在 ARM 平台上实现动态插桩的关键环节。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
->observer, &p, sizeof (p));
  }
}

static void
gum_exec_block_virtualize_arm_branch_insn (GumExecBlock * block,
                                           const GumBranchTarget * target,
                                           arm_cc cc,
                                           GumWriteback * writeback,
                                           GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  GumArmWriter * cw = gc->arm_writer;
  GumPrologState backpatch_prolog_state;
  GumAddress backpatch_code_start;

  gum_exec_block_write_arm_handle_not_taken (block, target, cc, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0 &&
      (block->flags & GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS) == 0)
  {
    gum_exec_block_arm_open_prolog (block, gc);
    backpatch_prolog_state = GUM_PROLOG_OPEN;

    gum_exec_block_write_arm_exec_event_code (block, gc);
  }
  else
  {
    backpatch_prolog_state = GUM_PROLOG_CLOSED;
  }

  backpatch_code_start = cw->pc;

  if (backpatch_prolog_state == GUM_PROLOG_CLOSED)
    gum_exec_block_arm_open_prolog (block, gc);

  gum_exec_block_write_arm_handle_excluded (block, target, FALSE, gc);
  gum_exec_block_write_arm_handle_kuser_helper (block, target, gc);
  gum_exec_block_write_arm_call_switch_block (block, target, gc);
  gum_exec_block_write_arm_pop_stack_frame (block, target, gc);

  if (ec->stalker->trust_threshold >= 0 &&
      target->type == GUM_TARGET_DIRECT_ADDRESS &&
      !gum_is_thumb (target->value.direct_address.address))
  {
    gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R5,
        GUM_ADDRESS (&block->ctx->current_block));
    gum_arm_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R5,
        ARM_REG_R5, 0);

    gum_arm_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_backpatch_arm_branch_to_current), 5,
        GUM_ARG_REGISTER, ARM_REG_R5,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
        GUM_ARG_ADDRESS, backpatch_code_start - GUM_ADDRESS (block->code_start),
        GUM_ARG_ADDRESS, GUM_ADDRESS (backpatch_prolog_state));
  }

  gum_exec_block_arm_close_prolog (block, gc);

  gum_exec_block_write_arm_handle_writeback (block, writeback, gc);
  gum_exec_block_write_arm_exec_generated_code (gc->arm_writer, block->ctx);
}

static void
gum_exec_block_virtualize_thumb_branch_insn (GumExecBlock * block,
                                             const GumBranchTarget * target,
                                             arm_cc cc,
                                             arm_reg cc_reg,
                                             GumWriteback * writeback,
                                             GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  GumThumbWriter * cw = gc->thumb_writer;
  GumPrologState backpatch_prolog_state;
  GumAddress backpatch_code_start;

  gum_exec_block_write_thumb_handle_not_taken (block, target, cc, cc_reg, gc);

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

  gum_exec_block_write_thumb_handle_excluded (block, target, FALSE, gc);
  gum_exec_block_write_thumb_handle_kuser_helper (block, target, gc);

  gum_exec_block_write_thumb_call_switch_block (block, target, gc);
  gum_exec_block_write_thumb_pop_stack_frame (block, target, gc);

  if (ec->stalker->trust_threshold >= 0 &&
      target->type == GUM_TARGET_DIRECT_ADDRESS &&
      gum_is_thumb (target->value.direct_address.address))
  {
    gum_thumb_writer_put_ldr_reg_address (cw, ARM_REG_R5,
        GUM_ADDRESS (&block->ctx->current_block));
    gum_thumb_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R5,
        ARM_REG_R5, 0);

    gum_thumb_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_backpatch_thumb_branch_to_current), 5,
        GUM_ARG_REGISTER, ARM_REG_R5,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
        GUM_ARG_ADDRESS, backpatch_code_start - GUM_ADDRESS (block->code_start),
        GUM_ARG_ADDRESS, GUM_ADDRESS (backpatch_prolog_state));
  }

  gum_exec_block_thumb_close_prolog (block, gc);

  gum_exec_block_write_thumb_handle_writeback (block, writeback, gc);
  gum_exec_block_write_thumb_exec_generated_code (cw, block->ctx);

  /*
   * We MUST do this last to account for IT blocks.
   * gum_thumb_relocator_skip_one() will complete the IT branch, so if we do
   * this early (like on ARM), then the end branch will be relocated into the
   * middle of the relocated branch.
   */
  gum_thumb_relocator_skip_one (gc->thumb_relocator);
}

static void
gum_exec_block_virtualize_arm_call_insn (GumExecBlock * block,
                                         const GumBranchTarget * target,
                                         arm_cc cc,
                                         GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  gpointer ret_real_address = gc->instruction->end;

  gum_exec_block_write_arm_handle_not_taken (block, target, cc, gc);

  gum_exec_block_arm_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
    gum_exec_block_write_arm_exec_event_code (block, gc);

  if ((ec->sink_mask & GUM_CALL) != 0)
    gum_exec_block_write_arm_call_event_code (block, target, gc);

  gum_exec_block_write_arm_handle_excluded (block, target, TRUE, gc);
  gum_exec_block_write_arm_push_stack_frame (block, ret_real_address, gc);
  gum_exec_block_write_arm_call_switch_block (block, target, gc);

  gum_exec_block_arm_close_prolog (block, gc);

  gum_arm_writer_put_ldr_reg_address (gc->arm_writer, ARM_REG_LR,
      GUM_ADDRESS (ret_real_address));
  gum_exec_block_write_arm_exec_generated_code (gc->arm_writer, block->ctx);
}

static void
gum_exec_block_virtualize_thumb_call_insn (GumExecBlock * block,
                                           const GumBranchTarget * target,
                                           GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  gpointer ret_real_address = gc->instruction->end + 1;

  gum_exec_block_thumb_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
    gum_exec_block_write_thumb_exec_event_code (block, gc);

  if ((ec->sink_mask & GUM_CALL) != 0)
    gum_exec_block_write_thumb_call_event_code (block, target, gc);

  gum_exec_block_write_thumb_handle_excluded (block, target, TRUE, gc);
  gum_exec_block_write_thumb_push_stack_frame (block, ret_real_address, gc);
  gum_exec_block_write_thumb_call_switch_block (block, target, gc);

  gum_exec_block_thumb_close_prolog (block, gc);

  gum_thumb_writer_put_ldr_reg_address (gc->thumb_writer, ARM_REG_LR,
      GUM_ADDRESS (ret_real_address));
  gum_exec_block_write_thumb_exec_generated_code (gc->thumb_writer, block->ctx);

  /*
   * We MUST do this last to account for IT blocks.
   * gum_thumb_relocator_skip_one() will complete the IT branch, so if we do
   * this early (like on ARM), then the end branch will be relocated into the
   * middle of the relocated branch.
   */
  gum_thumb_relocator_skip_one (gc->thumb_relocator);
}

static void
gum_exec_block_virtualize_arm_ret_insn (GumExecBlock * block,
                                        const GumBranchTarget * target,
                                        arm_cc cc,
                                        gboolean pop,
                                        guint16 mask,
                                        GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;

  gum_exec_block_write_arm_handle_not_taken (block, target, cc, gc);

  gum_exec_block_arm_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
    gum_exec_block_write_arm_exec_event_code (block, gc);

  gum_exec_block_write_arm_pop_stack_frame (block, target, gc);

  if ((ec->sink_mask & GUM_RET) != 0)
    gum_exec_block_write_arm_ret_event_code (block, target, gc);

  gum_exec_block_write_arm_call_switch_block (block, target, gc);

  gum_exec_block_arm_close_prolog (block, gc);

  /*
   * If the instruction we are virtualizing is a POP (or indeed LDMIA)
   * instruction, then as well as determining the location at which control flow
   * should continue, we must ensure we load any other registers in the register
   * list of the instruction from the stack. Lastly, we must increment that
   * stack pointer to remove the value of PC which would have been restored,
   * since we will instead control PC to continue execution of instrumented
   * code.
   */
  if (pop)
  {
    const GumBranchIndirectRegOffset * tv = &target->value.indirect_reg_offset;

    g_assert (target->type == GUM_TARGET_INDIRECT_REG_OFFSET);

    if (mask != 0)
    {
      if (tv->write_back)
        gum_arm_writer_put_ldmia_reg_mask_wb (gc->arm_writer, tv->reg, mask);
      else
        gum_arm_writer_put_ldmia_reg_mask (gc->arm_writer, tv->reg, mask);
    }

    if (tv->write_back)
    {
      gum_arm_writer_put_add_reg_reg_imm (gc->arm_writer, tv->reg, tv->reg,
          4);
    }
  }

  gum_exec_block_write_arm_exec_generated_code (gc->arm_writer, block->ctx);

  gum_arm_relocator_skip_one (gc->arm_relocator);
}

static void
gum_exec_block_virtualize_thumb_ret_insn (GumExecBlock * block,
                                          const GumBranchTarget * target,
                                          gboolean pop,
                                          guint16 mask,
                                          GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;

  gum_exec_block_thumb_open_prolog (block, gc);

  if ((ec->sink_mask & GUM_EXEC) != 0)
    gum_exec_block_write_thumb_exec_event_code (block, gc);

  gum_exec_block_write_thumb_pop_stack_frame (block, target, gc);

  if ((ec->sink_mask & GUM_RET) != 0)
    gum_exec_block_write_thumb_ret_event_code (block, target, gc);

  gum_exec_block_write_thumb_call_switch_block (block, target, gc);

  gum_exec_block_thumb_close_prolog (block, gc);

  if (pop)
  {
    const GumBranchIndirectRegOffset * tv = &target->value.indirect_reg_offset;
    guint displacement = 4;

    g_assert (target->type == GUM_TARGET_INDIRECT_REG_OFFSET);

    if (mask != 0)
    {
      if (gum_count_bits_set (mask) == 1)
      {
        arm_reg target_register = ARM_REG_R0 + gum_count_trailing_zeros (mask);
        gum_thumb_writer_put_ldr_reg_reg_offset (gc->thumb_writer,
            target_register, tv->reg, 0);
        displacement += 4;
      }
      else
      {
        gum_thumb_writer_put_ldmia_reg_mask (gc->thumb_writer, tv->reg, mask);
      }
    }

    gum_thumb_writer_put_add_reg_reg_imm (gc->thumb_writer, tv->reg, tv->reg,
        displacement);
  }

  gum_exec_block_write_thumb_exec_generated_code (gc->thumb_writer, block->ctx);
}

static void
gum_exec_block_virtualize_arm_svc_insn (GumExecBlock * block,
                                        GumGeneratorContext * gc)
{
  gum_exec_block_dont_virtualize_arm_insn (block, gc);

#ifdef HAVE_LINUX
  {
    GumArmWriter * cw = gc->arm_writer;
    gconstpointer not_cloned_child = cw->code + 1;

    /* Save the flags */
    gum_arm_writer_put_push_regs (cw, 1, ARM_REG_R1);
    gum_arm_writer_put_mov_reg_cpsr (cw, ARM_REG_R1);

    /* Check the SVC number */
    gum_arm_writer_put_cmp_reg_imm (cw, ARM_REG_R7, __NR_clone);
    gum_arm_writer_put_b_cond_label (cw, ARM_CC_NE, not_cloned_child);

    /* Check the returned TID */
    gum_arm_writer_put_cmp_reg_imm (cw, ARM_REG_R0, 0);
    gum_arm_writer_put_b_cond_label (cw, ARM_CC_NE, not_cloned_child);

    /* Restore the flags */
    gum_arm_writer_put_mov_cpsr_reg (cw, ARM_REG_R1);
    gum_arm_writer_put_pop_regs (cw, 1, ARM_REG_R1);

    /* Vector to the original next instruction */
    gum_arm_writer_put_push_regs (cw, 2, ARM_REG_R0, ARM_REG_PC);
    gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R0,
        GUM_ADDRESS (gc->instruction->end));
    gum_arm_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_SP, 4);
    gum_arm_writer_put_pop_regs (cw, 2, ARM_REG_R0, ARM_REG_PC);

    gum_arm_writer_put_label (cw, not_cloned_child);

    /* Restore the flags */
    gum_arm_writer_put_mov_cpsr_reg (cw, ARM_REG_R1);
    gum_arm_writer_put_pop_regs (cw, 1, ARM_REG_R1);
  }
#endif
}

static void
gum_exec_block_virtualize_thumb_svc_insn (GumExecBlock * block,
                                          GumGeneratorContext * gc)
{
  gum_exec_block_dont_virtualize_thumb_insn (block, gc);

#ifdef HAVE_LINUX
  {
    GumThumbWriter * cw = gc->thumb_writer;
    gconstpointer goto_not_cloned_child = cw->code + 1;
    gconstpointer cloned_child = cw->code + 2;
    gconstpointer not_cloned_child = cw->code + 3;

    /* Save the SVC number */
    gum_thumb_writer_put_push_regs (cw, 1, ARM_REG_R7);

    /* Check the SVC number */
    gum_thumb_writer_put_sub_reg_imm (cw, ARM_REG_R7, __NR_clone);
    gum_thumb_writer_put_cbnz_reg_label (cw, ARM_REG_R7, goto_not_cloned_child);

    /* Check the returned TID */
    gum_thumb_writer_put_cbnz_reg_label (cw, ARM_REG_R0, goto_not_cloned_child);
    gum_thumb_writer_put_b_label (cw, cloned_child);

    gum_thumb_writer_put_label (cw, goto_not_cloned_child);
    gum_thumb_writer_put_b_label (cw, not_cloned_child);

    gum_thumb_writer_put_label (cw, cloned_child);
    /* Restore the SVC number */
    gum_thumb_writer_put_pop_regs (cw, 1, ARM_REG_R7);

    /* Vector to the original next instruction */

    /*
     * We can't push PC in Thumb encoding without Thumb 2, and we clobber the
     * value so it doesn't matter what we push. It ends up popped back into PC.
     */
    gum_thumb_writer_put_push_regs (cw, 2, ARM_REG_R0, ARM_REG_R1);
    gum_thumb_writer_put_ldr_reg_address (cw, ARM_REG_R0,
        GUM_ADDRESS (gc->instruction->end + 1));
    gum_thumb_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_SP, 4);
    gum_thumb_writer_put_pop_regs (cw, 2, ARM_REG_R0, ARM_REG_PC);

    gum_thumb_writer_put_label (cw, not_cloned_child);

    /* Restore the SVC number */
    gum_thumb_writer_put_pop_regs (cw, 1, ARM_REG_R7);
  }
#endif
}

static void
gum_exec_block_write_arm_handle_kuser_helper (GumExecBlock * block,
                                              const GumBranchTarget * target,
                                              GumGeneratorContext * gc)
{
#ifdef HAVE_LINUX
  GumExecCtx * ctx = block->ctx;
  GumArmWriter * cw = gc->arm_writer;
  gconstpointer not_kuh = cw->code + 1;
  GumBranchTarget ret_target;

  /*
   * The kuser_helper is a mechanism implemented by the Linux kernel to expose a
   * page of code into the user address space so that it can be used by glibc in
   * order to carry out a number of heavily architecture specific operations
   * without having to perform architecture detection of its own (see
   * https://www.kernel.org/doc/Documentation/arm/kernel_user_helpers.txt).
   *
   * When running in qemu-user (which is useful for running target code on the
   * bench, or simply testing when you don't have access to a target), since
   * qemu-user is emulating the ARM instructions on an alterative architecture
   * (likely x86_64) then the code page exposed by the host kernel will be of
   * the native architecture accordingly. Rather than attempting to emulate this
   * very machine specific code, QEMU instead detects when the application
   * attempts to execute one of these handlers (see the function do_kernel_trap
   * in https://github.com/qemu/qemu/blob/master/linux-user/arm/cpu_loop.c) and
   * performs the necessary emulation on behalf of the application. Thus it is
   * not possible to read the page at this address and retrieve ARM code to be
   * instrumented.
   *
   * Rather than attempt to detect the target on which we are running, as it is
   * vanishingly unlikely that a user will care to stalk this platform specific
   * code we simply execute it outside of the Stalker engine, similar to the way
   * in which an excluded range is handled.
   */

  /*
   * If the branch target is deterministic (e.g. not based on register
   * contents), we can perform the check during instrumentation rather than at
   * runtime and omit this code if we can determine we will not enter a
   * kuser_helper.
   */
  if (target->type == GUM_TARGET_DIRECT_ADDRESS)
  {
    if (!gum_is_kuser_helper (target->value.direct_address.address))
      return;
  }

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
  {
    gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R0,
        gc);
    gum_arm_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_is_kuser_helper), 1,
        GUM_ARG_REGISTER, ARM_REG_R0);
    gum_arm_writer_put_cmp_reg_imm (cw, ARM_REG_R0, 0);
    gum_arm_writer_put_b_cond_label (cw, ARM_CC_EQ, not_kuh);
  }

  gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R0, gc);
  gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R1,
      GUM_ADDRESS (&ctx->kuh_target));
  gum_arm_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_R1, 0);

  gum_exec_block_arm_close_prolog (block, gc);

  gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R12,
      GUM_ADDRESS (&ctx->kuh_target));
  gum_arm_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R12, ARM_REG_R12, 0);

  /*
   * Unlike an excluded range, where the function is executed by a call
   * instruction. It is quite common for kuser_helpers to instead be executed by
   * the following instruction sequence.
   *
   * mvn r0, #0xf000
   * sub pc, r0, #0x1f
   *
   * This is effectively a tail call within a thunk function. But as we can see
   * when we vector to the kuser_helper we actually find a branch instruction
   * and not a call and hence were we to simply emit it, then we would not be
   * able to return to the Stalker engine after it has completed in order to
   * continue stalking. We must therefore emit a call instead.
   *
   * Note, however that per the documentation at kernel.org, the helpers are in
   * fact functions and so we can simply call and they will return control back
   * to the address contained in LR. One last thing to note here, is that we
   * store and restore the application LR value either side of our call so that
   * we can preserve it. This does have the effect of changing the normal
   * application stack pointer during the duration of the call, but the
   * documentation states that all of the input and output make use of registers
   * rather than the stack.
   */
  gum_arm_writer_put_push_regs (cw, 1, ARM_REG_LR);
  gum_arm_writer_put_call_reg (cw, ARM_REG_R12);
  gum_arm_writer_put_pop_regs (cw, 1, ARM_REG_LR);

  gum_exec_block_arm_open_prolog (block, gc);

  ret_target.type = GUM_TARGET_DIRECT_REG_OFFSET;
  ret_target.value.direct_reg_offset.reg = ARM_REG_LR;
  ret_target.value.direct_reg_offset.offset = 0;
  ret_target.value.direct_reg_offset.mode = GUM_ARM_MODE_AUTO;

  /*
   * We pop the stack frame here since the actual kuser_helper will have been
   * called by a thunk which looks like this:
   *
   * thunk_EXT_FUN_ffff0fe0:
   *     mvn r0, #0xf000
   *     sub pc => SUB_ffff0fe0, r0, #0x1f
   *
   * This will result in the stack frame being pushed for the call to this
   * thunk. Since this performs a tail call, and we don't stalk the actual
   * helper, we don't instrument the eventual return instruction and hence
   * include the stack pop at that point. We therefore pop the stack here
   * to make things line up.
   */
  gum_exec_block_write_arm_pop_stack_frame (block, &ret_target, gc);
  gum_exec_block_write_arm_call_switch_block (block, &ret_target, gc);
  gum_exec_block_arm_close_prolog (block, gc);

  gum_exec_block_write_arm_exec_generated_code (cw, block->ctx);

  gum_arm_writer_put_breakpoint (cw);

  /*
   * This label is only required if we weren't able to determine at
   * instrumentation time whether the target was a kuser_helper. If we could
   * then we either emit the handler if it is, or do nothing if not.
   */
  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
    gum_arm_writer_put_label (cw, not_kuh);
#endif
}

static void
gum_exec_block_write_thumb_handle_kuser_helper (GumExecBlock * block,
                                                const GumBranchTarget * target,
                                                GumGeneratorContext * gc)
{
#ifdef HAVE_LINUX
  GumExecCtx * ctx = block->ctx;
  GumThumbWriter * cw = gc->thumb_writer;
  gconstpointer kuh = cw->code + 1;
  gconstpointer not_kuh = cw->code + 2;
  GumBranchTarget ret_target;

  if (target->type == GUM_TARGET_DIRECT_ADDRESS)
  {
    if (!gum_is_kuser_helper (target->value.direct_address.address))
      return;
  }

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
  {
    gum_exec_ctx_write_thumb_mov_branch_target (block->ctx,
        target, ARM_REG_R0, gc);
    gum_thumb_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_is_kuser_helper), 1,
        GUM_ARG_REGISTER, ARM_REG_R0);
    gum_thumb_writer_put_cbnz_reg_label (cw, ARM_REG_R0, kuh);
    gum_thumb_writer_put_b_label (cw, not_kuh);
    gum_thumb_writer_put_label (cw, kuh);
  }

  gum_exec_ctx_write_thumb_mov_branch_target (block->ctx, target, ARM_REG_R0,
      gc);
  gum_thumb_writer_put_ldr_reg_address (cw, ARM_REG_R1,
      GUM_ADDRESS (&ctx->kuh_target));
  gum_thumb_writer_put_str_reg_reg_offset (cw, ARM_REG_R0, ARM_REG_R1, 0);

  gum_exec_block_thumb_close_prolog (block, gc);

  gum_thumb_writer_put_ldr_reg_address (cw, ARM_REG_R12,
      GUM_ADDRESS (&ctx->kuh_target));
  gum_thumb_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R12, ARM_REG_R12, 0);

  gum_thumb_writer_put_push_regs (cw, 1, ARM_REG_LR);
  gum_thumb_writer_put_bx_reg (cw, ARM_REG_R12);
  gum_thumb_writer_put_pop_regs (cw, 1, ARM_REG_LR);

  gum_exec_block_thumb_open_prolog (block, gc);

  ret_target.type = GUM_TARGET_DIRECT_REG_OFFSET;
  ret_target.value.direct_reg_offset.reg = ARM_REG_LR;
  ret_target.value.direct_reg_offset.offset = 0;
  ret_target.value.direct_reg_offset.mode = GUM_ARM_MODE_AUTO;

  gum_exec_block_write_thumb_pop_stack_frame (block, &ret_target, gc);
  gum_exec_block_write_thumb_call_switch_block (block, &ret_target,
      gc);
  gum_exec_block_thumb_close_prolog (block, gc);

  gum_exec_block_write_thumb_exec_generated_code (cw, block->ctx);

  gum_thumb_writer_put_breakpoint (cw);

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
    gum_thumb_writer_put_label (cw, not_kuh);
#endif
}

static void
gum_exec_block_write_arm_call_switch_block (GumExecBlock * block,
                                            const GumBranchTarget * target,
                                            GumGeneratorContext * gc)
{
  gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R2, gc);
  gum_arm_writer_put_call_address_with_arguments (gc->arm_writer,
      GUM_ADDRESS (gum_exec_ctx_switch_block), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM_REG_R2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));
}

static void
gum_exec_block_write_thumb_call_switch_block (GumExecBlock * block,
                                              const GumBranchTarget * target,
                                              GumGeneratorContext * gc)
{
  gum_exec_ctx_write_thumb_mov_branch_target (block->ctx, target, ARM_REG_R2,
      gc);
  gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
      GUM_ADDRESS (gum_exec_ctx_switch_block), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_REGISTER, ARM_REG_R2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start) + 1);
}

static void
gum_exec_block_dont_virtualize_arm_insn (GumExecBlock * block,
                                         GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;

  if ((ec->sink_mask & GUM_EXEC) != 0)
  {
    gum_exec_block_arm_open_prolog (block, gc);
    gum_exec_block_write_arm_exec_event_code (block, gc);
    gum_exec_block_arm_close_prolog (block, gc);
  }

  gum_arm_relocator_write_all (gc->arm_relocator);
}

static void
gum_exec_block_dont_virtualize_thumb_insn (GumExecBlock * block,
                                           GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;

  if ((ec->sink_mask & GUM_EXEC) != 0)
  {
    gum_exec_block_thumb_open_prolog (block, gc);
    gum_exec_block_write_thumb_exec_event_code (block, gc);
    gum_exec_block_thumb_close_prolog (block, gc);
  }

  gum_thumb_relocator_write_all (gc->thumb_relocator);
}

static void
gum_exec_block_write_arm_handle_excluded (GumExecBlock * block,
                                          const GumBranchTarget * target,
                                          gboolean call,
                                          GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->arm_writer;
  gconstpointer not_excluded = cw->code + 1;
  GumCheckExcludedFunc check;

  if (call)
    check = gum_stalker_is_call_excluding;
  else
    check = gum_stalker_is_branch_excluding;

  /*
   * If the branch target is deterministic (e.g. not based on register
   * contents). We can perform the check during instrumentation rather than at
   * runtime and omit this code if we can determine we will not enter an
   * excluded range.
   */
  if (target->type == GUM_TARGET_DIRECT_ADDRESS)
  {
    if (!check (block->ctx, target->value.direct_address.address))
    {
      gum_arm_relocator_skip_one (gc->arm_relocator);
      return;
    }
  }

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
  {
    gum_exec_ctx_write_arm_mov_branch_target (block->ctx, target, ARM_REG_R1,
        gc);
    gum_arm_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (check), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
        GUM_ARG_REGISTER, ARM_REG_R1);
    gum_arm_writer_put_cmp_reg_imm (cw, ARM_REG_R0, 0);
    gum_arm_writer_put_b_cond_label (cw, ARM_CC_EQ, not_excluded);
  }

  if (call)
  {
    gum_arm_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_begin_call), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->end));
  }

  gum_exec_block_arm_close_prolog (block, gc);

  /* Emit the original instruction (relocated) */
  gum_arm_relocator_write_one (gc->arm_relocator);

  gum_exec_block_arm_open_prolog (block, gc);

  if (call)
  {
    gum_arm_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_end_call), 1,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx));
  }

  gum_exec_block_write_arm_handle_continue (block, gc);

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
    gum_arm_writer_put_label (cw, not_excluded);
}

static void
gum_exec_block_write_thumb_handle_excluded (GumExecBlock * block,
                                            const GumBranchTarget * target,
                                            gboolean call,
                                            GumGeneratorContext * gc)
{
  GumThumbWriter * cw = gc->thumb_writer;
  gsize unique_id = GPOINTER_TO_SIZE (cw->code) << 1;
  gconstpointer is_excluded = GSIZE_TO_POINTER (unique_id | 1);
  gconstpointer not_excluded = GSIZE_TO_POINTER (unique_id | 0);
  GumCheckExcludedFunc check;

  if (call)
    check = gum_stalker_is_call_excluding;
  else
    check = gum_stalker_is_branch_excluding;

  if (target->type == GUM_TARGET_DIRECT_ADDRESS)
  {
    if (!check (block->ctx, target->value.direct_address.address))
      return;
  }

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
  {
    gum_exec_ctx_write_thumb_mov_branch_target (block->ctx, target, ARM_REG_R1,
        gc);
    gum_thumb_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (check), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
        GUM_ARG_REGISTER, ARM_REG_R1);
    gum_thumb_writer_put_cbnz_reg_label (cw, ARM_REG_R0, is_excluded);
    gum_thumb_writer_put_b_label (cw, not_excluded);
    gum_thumb_writer_put_label (cw, is_excluded);
  }

  if (call)
  {
    gum_thumb_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_begin_call), 2,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->end + 1));
  }

  gum_exec_block_thumb_close_prolog (block, gc);

  gum_thumb_relocator_copy_one (gc->thumb_relocator);

  gum_exec_block_thumb_open_prolog (block, gc);

  if (call)
  {
    gum_thumb_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_end_call), 1,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx));
  }

  gum_exec_block_write_thumb_handle_continue (block, gc);

  if (target->type != GUM_TARGET_DIRECT_ADDRESS)
    gum_thumb_writer_put_label (cw, not_excluded);
}

static void
gum_exec_block_write_arm_handle_not_taken (GumExecBlock * block,
                                           const GumBranchTarget * target,
                                           arm_cc cc,
                                           GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  GumArmWriter * cw = gc->arm_writer;
  gconstpointer taken = cw->code + 1;
  GumPrologState backpatch_prolog_state;
  GumAddress backpatch_code_start;

  /*
   * Many ARM instructions can be conditionally executed based upon the state of
   * register flags. If our instruction is not always executed (ARM_CC_AL), we
   * emit a branch with the same condition code as the original instruction to
   * bypass the continuation handler.
   */

  if (cc == ARM_CC_AL)
    return;

  gum_arm_writer_put_b_cond_label (cw, cc, taken);

  /*
   * If the branch is not taken on account that the instruction is conditionally
   * executed, then emit any necessary events and continue execution by
   * instrumenting and vectoring to the block immediately after the conditional
   * instruction.
   */

  if ((ec->sink_mask & GUM_EXEC) != 0 &&
      (block->flags & GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS) == 0)
  {
    gum_exec_block_arm_open_prolog (block, gc);
    backpatch_prolog_state = GUM_PROLOG_OPEN;

    gum_exec_block_write_arm_exec_event_code (block, gc);
  }
  else
  {
    backpatch_prolog_state = GUM_PROLOG_CLOSED;
  }

  backpatch_code_start = cw->pc;

  if (backpatch_prolog_state == GUM_PROLOG_CLOSED)
    gum_exec_block_arm_open_prolog (block, gc);

  gum_arm_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_switch_block), 4,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ec),
      GUM_ARG_ADDRESS, GUM_ADDRESS (block),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->end),
      GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start));

  if (ec->stalker->trust_threshold >= 0 &&
      target->type == GUM_TARGET_DIRECT_ADDRESS &&
      !gum_is_thumb (target->value.direct_address.address))
  {
    const guint padding_size = 4;
    guint i;

    for (i = 0; i != padding_size; i++)
      gum_arm_writer_put_nop (cw);

    gum_arm_writer_put_ldr_reg_address (cw, ARM_REG_R5,
        GUM_ADDRESS (&block->ctx->current_block));
    gum_arm_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R5,
        ARM_REG_R5, 0);

    gum_arm_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_backpatch_arm_branch_to_current), 5,
        GUM_ARG_REGISTER, ARM_REG_R5,
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc->instruction->start),
        GUM_ARG_ADDRESS, backpatch_code_start - GUM_ADDRESS (block->code_start),
        GUM_ARG_ADDRESS, GUM_ADDRESS (backpatch_prolog_state));
  }

  gum_exec_block_arm_close_prolog (block, gc);

  gum_exec_block_write_arm_exec_generated_code (cw, ec);

  gum_arm_writer_put_label (cw, taken);
}

static void
gum_exec_block_write_thumb_handle_not_taken (GumExecBlock * block,
                                             const GumBranchTarget * target,
                                             arm_cc cc,
                                             arm_reg cc_reg,
                                             GumGeneratorContext * gc)
{
  GumExecCtx * ec = block->ctx;
  GumThumbWriter * cw = gc->thumb_writer;
  gconstpointer cb_not_taken = cw->code + 1;
  gconstpointer taken = cw->code + 2;

  if (cc_reg != ARM_REG_INVALID)
  {
    if (cc == ARM_CC_EQ)
      gum_thumb_writer_put_cbnz_reg_label (cw, cc_reg, cb_not_taken);
    else if (cc == ARM_CC_NE)
      gum_thumb_writer_put_cbz_reg_label (cw, cc_reg, cb_not_taken);
    else
      g_assert_not_reached ();

    gum_thumb_writer_put
```