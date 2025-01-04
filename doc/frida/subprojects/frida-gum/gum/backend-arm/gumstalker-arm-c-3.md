Response:
Let's break down the thought process for analyzing this C code snippet and fulfilling the request.

**1. Understanding the Goal:**

The primary goal is to analyze a specific C source file (`gumstalker-arm.c`) related to Frida, a dynamic instrumentation tool. The request asks for various aspects of its functionality, including its relation to reverse engineering, low-level details, logical reasoning, potential errors, debugging, and a final summary. The prompt also specifies that this is part 4 of 6, hinting at a larger context.

**2. Initial Code Scan and Keyword Recognition:**

The first step is to quickly scan the code, looking for recognizable patterns and keywords. Key observations from this initial scan:

* **`GumExecCtx`:**  This structure seems central, appearing in almost every function. It likely holds the execution context information.
* **`GumArmWriter` and `GumThumbWriter`:** These strongly suggest code generation for ARM and Thumb architectures. The "writer" suffix implies they are used to emit assembly instructions.
* **`gum_arm_writer_put_*` and `gum_thumb_writer_put_*`:** These function prefixes confirm the assembly generation idea. They write specific ARM/Thumb instructions (e.g., `push_regs`, `mov_reg_cpsr`, `bl_imm`).
* **Prolog and Epilog:**  The functions `gum_exec_ctx_write_arm_prolog` and `gum_exec_ctx_write_arm_epilog` (and their Thumb counterparts) are a classic pattern for setting up and tearing down a function call stack. This is fundamental to how functions operate at the assembly level.
* **CPU Features (`GUM_CPU_VFP2`, `GUM_CPU_VFPD32`):**  The code checks for CPU features, indicating it's dealing with hardware-specific capabilities, likely related to floating-point units.
* **Stack Manipulation:** Instructions manipulating the stack pointer (`SP`) are prevalent, confirming the prolog/epilog setup.
* **Register Saving/Restoring:**  The code pushes and pops registers, crucial for preserving the state of the program during instrumentation.
* **`gum_exec_ctx_recompile_and_switch_block`:**  This function name hints at dynamic recompilation, a core technique used in dynamic instrumentation.
* **Invalidation (`gum_exec_ctx_write_arm_invalidator`, `gum_exec_ctx_write_thumb_invalidator`):** These functions suggest a mechanism for invalidating previously generated code, forcing re-execution.
* **Branching (`gum_exec_ctx_write_arm_mov_branch_target`, `gum_exec_ctx_write_thumb_mov_branch_target`):**  The code handles different types of branch targets, essential for controlling program flow.
* **`GumExecBlock`:** This structure appears related to managing blocks of generated code.
* **Backpatching (`gum_exec_ctx_backpatch_arm_branch_to_current`, `gum_exec_ctx_backpatch_thumb_branch_to_current`):**  This is a key optimization in dynamic instrumentation, allowing the modification of previously generated code to directly jump to new locations.

**3. Answering the Specific Questions:**

With a good overview of the code, we can now address each point in the request:

* **Functionality:**  Systematically go through the key functions identified in step 2 and describe their purpose. Focus on what each function *does*.
* **Relation to Reverse Engineering:** Connect the code's actions to common reverse engineering techniques. For example, the prolog/epilog manipulation is directly related to how debuggers and disassemblers analyze function calls. Code injection and dynamic recompilation are also core concepts.
* **Binary/Low-Level/Kernel/Framework:**  Identify specific elements that demonstrate knowledge of these areas. ARM/Thumb assembly, register conventions, stack alignment, CPU features, and the concept of code slabs are all relevant. The interaction with the "stalker" (likely a core Frida component managing code interception) also fits here.
* **Logical Reasoning (Hypothetical Input/Output):** Choose a function that involves some conditional logic (e.g., handling different branch target types) and illustrate how different inputs would lead to different assembly code being generated.
* **User/Programming Errors:** Think about how a user interacting with Frida might cause issues that manifest in this code. Incorrect instrumentation logic or assumptions about register usage are good examples.
* **User Operation to Reach Here (Debugging):**  Imagine the steps a user takes to instrument code and how that execution flow would eventually call into these functions. Setting breakpoints in Frida's instrumentation logic is a relevant scenario.
* **Summary:**  Synthesize the key functionalities identified earlier into a concise overview of the file's role.

**4. Structuring the Answer:**

Organize the information logically, using headings and bullet points to make it easy to read and understand. Group related functionalities together.

**5. Refining and Elaborating:**

Review the initial answers and add more detail and explanation where necessary. For example, instead of just saying "it saves registers," explain *why* it saves registers and what the structure of the saved context looks like.

**Self-Correction/Refinement during the process:**

* **Initial Misinterpretation:**  Perhaps initially, one might focus too much on the individual assembly instructions without understanding the higher-level goal. Recognizing the prolog/epilog pattern and the concept of a CPU context helps to correct this.
* **Overlooking Connections:**  Ensure the connections to reverse engineering, low-level details, etc., are explicitly stated and not just implied.
* **Clarity and Conciseness:**  Strive for clear and concise explanations. Avoid jargon where possible, or explain it if necessary.

By following this systematic approach, combining code analysis with an understanding of the underlying concepts of dynamic instrumentation and ARM architecture, one can effectively analyze this C source file and address the various aspects of the request.
好的，让我们来分析一下 `frida/subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c` 文件的功能，并根据您的要求进行详细说明。

**文件功能归纳**

这个 C 文件是 Frida Gum 库中针对 ARM 架构的 Stalker 后端实现的核心部分。它的主要功能是**动态代码生成和管理**，用于在目标进程中插入和执行用户自定义的 JavaScript 代码。更具体地说，它负责：

1. **构建执行上下文 (Execution Context)：**  创建和维护一个 `GumExecCtx` 结构，用于跟踪当前代码生成的状态，包括代码段、数据段、寄存器状态等。
2. **生成 ARM/Thumb 汇编代码:**  提供函数来生成 ARM 和 Thumb 指令集的汇编代码，这些代码负责保存和恢复寄存器状态、调用用户提供的回调函数以及实现代码块之间的跳转。
3. **管理代码块 (Code Blocks):**  创建、管理和维护 `GumExecBlock` 结构，这些结构代表了 Frida 注入的目标代码的基本单元。它负责分配内存、写入生成的代码、标记代码块的状态（例如，是否有效、是否需要重新编译）。
4. **实现代码块链接和跳转 (Backpatching):**  当目标代码的执行流发生改变时，负责更新之前生成的代码块中的跳转指令，使其指向新的目标代码块。这是一种优化技术，可以提高性能。
5. **处理函数序言和尾声 (Prolog and Epilog):**  在生成的代码中插入函数序言（保存寄存器）和尾声（恢复寄存器），以确保 Frida 的代码能够安全地与目标进程的代码交互。
6. **处理 VFP (Vector Floating Point) 寄存器:**  考虑了 ARM 架构中 VFP 单元的存在，并在保存和恢复寄存器状态时处理 VFP 寄存器。
7. **实现代码失效 (Invalidation):**  当代码块需要重新生成时，提供机制来使旧的代码块失效，防止其被继续执行。
8. **提供辅助函数 (Helper Functions):**  生成一些辅助函数，例如 `gum_exec_ctx_recompile_and_switch_block`，用于处理代码块的重新编译和切换。

**与逆向方法的关系及举例说明**

这个文件直接服务于动态 instrumentation，这是逆向工程中一种强大的技术。

* **动态代码注入:** Frida 通过 Stalker 机制，能够将用户自定义的代码（通常是 JavaScript，然后被编译成机器码）注入到目标进程的内存空间中执行。`gumstalker-arm.c` 负责生成这些注入的代码。
    * **例子:**  逆向工程师可以使用 Frida 脚本拦截目标进程中某个函数的调用，并在函数执行前后执行自定义的 JavaScript 代码来记录参数、修改返回值或执行其他操作。`gumstalker-arm.c` 会生成相应的 ARM/Thumb 汇编代码来实现这个拦截和回调过程。
* **运行时修改程序行为:**  通过动态地修改目标进程的执行流程，逆向工程师可以绕过安全检查、修改程序逻辑或探索程序的内部状态。
    * **例子:**  可以使用 Frida 脚本跳过目标程序中的某个授权验证步骤。`gumstalker-arm.c` 生成的代码会修改目标代码的跳转指令，使其不再执行验证逻辑。
* **Hooking 技术:** Frida 的核心功能是 Hooking，即拦截目标函数的调用并执行自定义代码。`gumstalker-arm.c` 生成的代码是实现 Hooking 的基础，它负责保存原始寄存器状态、调用用户的 Hook 函数，并在 Hook 函数返回后恢复寄存器状态并跳转回原始代码。
    * **例子:**  逆向工程师可以 Hook `open` 系统调用来监控目标进程打开的文件。`gumstalker-arm.c` 生成的代码会在 `open` 调用前后执行用户提供的 JavaScript 回调，记录打开的文件名。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明**

这个文件深入到二进制底层和操作系统相关的知识：

* **ARM/Thumb 指令集:** 文件中大量使用了 `gum_arm_writer_put_*` 和 `gum_thumb_writer_put_*` 函数，这些函数直接操作 ARM 和 Thumb 指令，例如 `push_regs` (压栈寄存器), `mov_reg_cpsr` (移动 CPSR 寄存器), `bl_imm` (带链接的立即数跳转) 等。这需要对 ARM 架构的寄存器、指令格式和寻址模式有深入的理解。
    * **例子:**  `gum_exec_ctx_write_arm_prolog` 函数生成 ARM 汇编代码来保存目标进程的寄存器状态，以便 Frida 的代码执行后能够恢复现场。这涉及到选择合适的寄存器保存指令和存储位置（通常是栈上）。
* **寄存器约定 (Calling Convention):**  代码中注释提到了 "callee saved register"，这涉及到 ARM 的函数调用约定，规定了哪些寄存器在函数调用过程中需要被调用者（callee）保存和恢复。Frida 需要遵守这些约定，以避免破坏目标进程的执行。
    * **例子:**  代码选择 `R10` 寄存器来存储 `GumCpuContext` 结构的地址，因为它是一个 callee-saved 寄存器，保证在调用其他 C 代码时其值不会被随意修改。
* **栈帧结构:**  `gum_exec_ctx_write_arm_prolog` 和 `gum_exec_ctx_write_thumb_prolog` 函数构建了一个特定的栈帧结构来存储目标进程的 CPU 上下文。这需要理解 ARM 架构的栈增长方向和栈帧的组织方式。
    * **例子:**  代码将 PC, SP, CPSR 和其他通用寄存器以及 VFP 寄存器压入栈中，形成一个 `GumArmCpuContext` 结构。
* **内存对齐:**  代码中强调了栈的 8 字节对齐，这是 ARM ABI 的要求。未对齐的栈可能导致程序崩溃或性能下降。
    * **例子:**  `gum_exec_ctx_write_arm_prolog` 和 `gum_exec_ctx_write_thumb_prolog` 中都有代码来确保栈指针是 8 字节对齐的。
* **CPU 特性检测:** 代码检查了 CPU 的 VFP (Vector Floating Point) 特性 (`GUM_CPU_VFP2`, `GUM_CPU_VFPD32`)，并根据这些特性来决定是否需要保存和恢复 VFP 寄存器。这与 Android 内核和硬件抽象层提供的 CPU 信息有关。
    * **例子:**  只有当检测到目标设备支持 VFP 时，代码才会生成保存和恢复 VFP 寄存器的指令。
* **代码缓存 (Code Cache) 管理:**  Stalker 需要管理生成的代码的内存，并确保这些代码在执行前被刷新到指令缓存中。`gum_stalker_thaw` 和 `gum_stalker_freeze` 等函数可能与此有关 (尽管在这个文件中没有直接看到具体实现，但这是 Stalker 的核心功能)。 这涉及到操作系统内核的内存管理和缓存一致性机制。
* **Android 框架 (间接相关):** 虽然这个文件不直接涉及 Android 框架的 Java 代码，但 Frida 经常被用于分析和修改 Android 应用程序的行为，因此理解 Android 框架的运行机制对于编写有效的 Frida 脚本至关重要。`gumstalker-arm.c` 是 Frida 在 Android 上工作的基础。

**逻辑推理、假设输入与输出**

让我们以 `gum_exec_ctx_write_arm_mov_branch_target` 函数为例，它负责生成将分支目标地址加载到寄存器的代码。

**假设输入:**

* `ctx`: 一个有效的 `GumExecCtx` 结构。
* `target`: 一个 `GumBranchTarget` 结构，假设其 `type` 为 `GUM_TARGET_DIRECT_ADDRESS`，并且 `target->value.direct_address.address` 指向内存地址 `0x12345678`。
* `reg`: 目标寄存器，假设为 `ARM_REG_R0`。
* `gc`: 一个有效的 `GumGeneratorContext` 结构，包含了用于写入 ARM 代码的 `GumArmWriter`。

**逻辑推理:**

函数会根据 `target->type` 进入 `GUM_TARGET_DIRECT_ADDRESS` 分支。在这个分支中，它会调用 `gum_arm_writer_put_ldr_reg_address(cw, reg, GUM_ADDRESS(value->address))`。

**预期输出 (生成的 ARM 汇编代码):**

```assembly
ldr r0, =0x12345678
```

这条指令会将地址 `0x12345678` 加载到寄存器 `r0` 中。  `=` 符号在 ARM 汇编中通常表示加载一个地址常量。

**假设输入 (另一种情况):**

* `ctx`: 一个有效的 `GumExecCtx` 结构。
* `target`: 一个 `GumBranchTarget` 结构，假设其 `type` 为 `GUM_TARGET_DIRECT_REG_OFFSET`，并且 `target->value.direct_reg_offset.reg` 为 `ARM_REG_R1`， `target->value.direct_reg_offset.offset` 为 `8`。
* `reg`: 目标寄存器，假设为 `ARM_REG_R2`。
* `gc`: 一个有效的 `GumGeneratorContext` 结构。

**逻辑推理:**

函数会进入 `GUM_TARGET_DIRECT_REG_OFFSET` 分支。它首先调用 `gum_exec_ctx_arm_load_real_register_into(ctx, reg, value->reg, gc)`，这会生成代码将目标进程的 `R1` 寄存器的值加载到 `R2`。然后，它调用 `gum_arm_writer_put_add_reg_reg_imm(cw, reg, reg, value->offset)`。

**预期输出 (生成的 ARM 汇编代码):**

```assembly
ldr r2, [r10, #offset_of_r1_in_GumCpuContext]  // 假设 offset_of_r1_in_GumCpuContext 是 R1 在 GumCpuContext 中的偏移
add r2, r2, #8
```

这里会先从 `GumCpuContext` 中加载原始的 `R1` 的值到 `R2`，然后将 `R2` 的值加上偏移量 `8`。

**涉及用户或者编程常见的使用错误及举例说明**

虽然用户不直接编写 C 代码与这个文件交互，但 Frida 脚本的编写或 Frida 本身的开发中可能出现错误，这些错误可能最终在这个代码的执行中显现出来。

* **错误的 Hook 逻辑导致栈不平衡:**  如果用户编写的 Frida 脚本在 Hook 函数中错误地修改了栈指针（SP）但没有正确恢复，可能会导致 `gum_exec_ctx_write_arm_epilog` 或 `gum_exec_ctx_write_thumb_epilog` 中的恢复操作出错，最终可能导致程序崩溃。
    * **例子:**  一个错误的 Hook 函数可能 `push` 了一些寄存器，但在返回前忘记 `pop` 相应的寄存器。
* **假设错误的寄存器状态:**  如果 Frida 脚本错误地假设了目标进程在某个点的寄存器状态，并在 Hook 函数中依赖这些假设，可能会导致不可预测的行为。`gumstalker-arm.c` 尽力保存和恢复寄存器，但如果用户脚本的逻辑有缺陷，仍然可能出错。
    * **例子:**  脚本可能假设某个寄存器总是包含某个特定的值，但在实际运行时这个假设不成立。
* **尝试 Hook 不可 Hook 的位置:**  如果用户尝试 Hook 的地址位于代码段的中间，而不是一个函数的入口点，`gumstalker-arm.c` 生成的代码可能会破坏原始指令，导致程序崩溃。Frida 通常会进行一些检查来避免这种情况，但理论上是可能发生的。
* **内存分配失败:** 虽然不太常见，但在内存资源紧张的情况下，`gum_exec_block_new` 等函数可能会因为内存分配失败而返回错误，这会导致 Frida 的功能异常。

**说明用户操作是如何一步步的到达这里，作为调试线索**

1. **用户编写 Frida 脚本:** 用户使用 JavaScript 编写 Frida 脚本，指定要 Hook 的函数、要执行的操作等。
2. **用户运行 Frida:** 用户运行 Frida，并将脚本附加到目标进程。
3. **Frida 解析脚本:** Frida 的前端（通常是 Python 或 Node.js 组件）解析用户脚本，并将其转换为内部表示。
4. **Stalker 启动:** 当用户脚本包含需要动态代码生成的 Hook 或其他 instrumentation 时，Frida 的 Stalker 机制会被激活。
5. **Gum 调用:** Stalker 会调用 Gum 库中的相关函数，例如 `Gum.Interceptor.attach`。
6. **`gumstalker-arm.c` 参与:**  对于 ARM 架构的目标进程，Gum 库会使用 `gumstalker-arm.c` 中提供的函数来生成用于 Hook 和 instrumentation 的 ARM/Thumb 汇编代码。
    * **例如:**  当需要为一个函数生成 Prolog 时，会调用 `gum_exec_ctx_write_arm_prolog` 或 `gum_exec_ctx_write_thumb_prolog`。当需要生成跳转指令时，会调用 `gum_exec_ctx_backpatch_arm_branch_to_current` 或 `gum_exec_ctx_backpatch_thumb_branch_to_current`。
7. **代码注入和执行:** 生成的机器码会被注入到目标进程的内存空间中，并在目标代码执行到被 Hook 的位置时被执行。

**调试线索:**

* **在 Frida 脚本中设置日志:** 用户可以在 Frida 脚本中使用 `console.log` 来跟踪脚本的执行流程和变量值。
* **使用 Frida 的调试模式:** Frida 提供了一些调试选项，可以输出更详细的内部信息。
* **使用 GDB 等调试器附加到 Frida 自身或目标进程:**  高级用户可以使用 GDB 等调试器来跟踪 Frida 的内部执行流程，包括 `gumstalker-arm.c` 中的代码。在相关的函数入口或关键代码段设置断点，可以观察寄存器状态、内存内容和函数调用栈。
* **查看 Frida 的源代码:**  正如您所做的那样，查看 Frida 的源代码是理解其工作原理的重要手段。

**第 4 部分功能归纳**

在提供的代码片段中，主要关注的是以下功能：

* **ARM 和 Thumb 指令集的代码生成:**  提供了生成 ARM 和 Thumb 汇编指令的函数，用于实现函数序言 (prologue)、尾声 (epilogue)、函数调用、条件跳转等。
* **执行上下文的管理:**  定义了 `GumExecCtx` 结构，并提供了操作该结构的函数，用于跟踪代码生成的状态。
* **代码失效机制:** 实现了代码块失效的逻辑，当需要重新编译代码块时，会生成特定的指令来跳转到重新编译的入口点。
* **确保辅助函数可达:**  提供了机制来确保一些辅助函数（例如，代码失效处理函数）在代码块中可以被直接跳转到。
* **处理不同类型的分支目标:**  实现了将不同类型的分支目标地址加载到寄存器的逻辑，包括直接地址、寄存器偏移、寄存器移位等。
* **加载真实寄存器值:** 提供了从 `GumCpuContext` 结构中加载目标进程真实寄存器值的函数。
* **代码块的创建和管理:**  实现了创建新的 `GumExecBlock` 和清除代码块内容的函数。

总而言之，这个代码片段是 Frida Stalker 在 ARM 架构上进行动态代码生成和管理的关键组成部分，负责生成用于 Hook、代码注入和控制目标程序执行流程的底层机器码。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共6部分，请归纳一下它的功能

"""
c = self->generator_context;

  return gc->is_thumb
      ? gc->thumb_relocator->capstone
      : gc->arm_relocator->capstone;
}

static void
gum_exec_ctx_write_arm_prolog (GumExecCtx * ctx,
                               GumArmWriter * cw)
{
  const GumCpuFeatures cpu_features = ctx->stalker->cpu_features;

  /*
   * For our context, we want to build up the following structure so that
   * Stalker can read the register state of the application.
   *
   * struct _GumArmCpuContext
   * {
   *   guint32 pc;
   *   guint32 sp;
   *   guint32 cpsr;
   *
   *   guint32 r8;
   *   guint32 r9;
   *   guint32 r10;
   *   guint32 r11;
   *   guint32 r12;
   *
   *   GumArmVectorReg q[16];
   *
   *   guint32 _padding;
   *
   *   guint32 r[8];
   *   guint32 lr;
   * };
   */

  /* Store R0 through R7 and LR */
  gum_arm_writer_put_push_regs (cw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
      ARM_REG_R3, ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);

  /* Take note of CPSR and where GumCpuContext ends/application stack begins */
  gum_arm_writer_put_mov_reg_cpsr (cw, ARM_REG_R5);
  gum_arm_writer_put_add_reg_reg_imm (cw, ARM_REG_R4, ARM_REG_SP, 9 * 4);

  /* Add padding followed by VFP registers */
  if ((cpu_features & GUM_CPU_VFP2) != 0)
  {
    if ((cpu_features & GUM_CPU_VFPD32) != 0)
    {
      gum_arm_writer_put_sub_reg_u16 (cw, ARM_REG_SP, 4);
      gum_arm_writer_put_vpush_range (cw, ARM_REG_Q8, ARM_REG_Q15);
    }
    else
    {
      gum_arm_writer_put_sub_reg_u16 (cw, ARM_REG_SP,
          (8 * sizeof (GumArmVectorReg)) + 4);
    }

    gum_arm_writer_put_vpush_range (cw, ARM_REG_Q0, ARM_REG_Q7);
  }
  else
  {
    gum_arm_writer_put_sub_reg_u16 (cw, ARM_REG_SP,
        (16 * sizeof (GumArmVectorReg)) + 4);
  }

  /* Store SP, CPSR, followed by R8-R12 */
  gum_arm_writer_put_push_regs (cw, 7,
      ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12);

  /* Reserve space for the PC placeholder */
  gum_arm_writer_put_sub_reg_u16 (cw, ARM_REG_SP, 4);

  /*
   * Now that the context structure has been pushed onto the stack, we store the
   * address of this structure on the stack into register R10. This register can
   * be chosen fairly arbitrarily but it should be a callee saved register so
   * that any C code called from our instrumented code is obliged by the calling
   * convention to preserve its value across the function call. In particular
   * register R12 is a caller saved register and as such any C function can
   * modify its value and not restore it. Similary registers R0 through R3
   * contain the arguments to the function and the return result and are
   * accordingly not preserved.
   *
   * We have elected not to use R11 since this can be used as a frame pointer by
   * some compilers and as such can confuse some debuggers. The function
   * load_real_register_into() makes use of this register R10 in order to access
   * this context structure.
   */
  gum_arm_writer_put_mov_reg_reg (cw, ARM_REG_R10, ARM_REG_SP);

  /*
   * We must now ensure that the stack is 8 byte aligned, since this is expected
   * by the ABI. Since the context was on the top of the stack and we retain
   * this address in R10, we don't need to save the original stack pointer for
   * re-alignment in the epilogue since we can simply restore SP from R10.
   */
  gum_arm_writer_put_ands_reg_reg_imm (cw, ARM_REG_R0, ARM_REG_SP, 7);
  gum_arm_writer_put_sub_reg_reg_reg (cw, ARM_REG_SP, ARM_REG_SP, ARM_REG_R0);
}

static void
gum_exec_ctx_write_thumb_prolog (GumExecCtx * ctx,
                                 GumThumbWriter * cw)
{
  const GumCpuFeatures cpu_features = ctx->stalker->cpu_features;

  gum_thumb_writer_put_push_regs (cw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
      ARM_REG_R3, ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);

  /*
   * Note that we stash the CPSR (flags) here first since the Thumb instruction
   * set doesn't support short form instructions for SUB. Hence, the ADD/SUB
   * instructions below where the destination is not SP are actually ADDS/SUBS
   * and will clobber the flags.
   */
  gum_thumb_writer_put_mov_reg_cpsr (cw, ARM_REG_R5);
  gum_thumb_writer_put_add_reg_reg_imm (cw, ARM_REG_R4, ARM_REG_SP, 9 * 4);

  if ((cpu_features & GUM_CPU_VFP2) != 0)
  {
    if ((cpu_features & GUM_CPU_VFPD32) != 0)
    {
      gum_thumb_writer_put_sub_reg_imm (cw, ARM_REG_SP, 4);
      gum_thumb_writer_put_vpush_range (cw, ARM_REG_Q8, ARM_REG_Q15);
    }
    else
    {
      gum_thumb_writer_put_sub_reg_imm (cw, ARM_REG_SP,
          (8 * sizeof (GumArmVectorReg)) + 4);
    }

    gum_thumb_writer_put_vpush_range (cw, ARM_REG_Q0, ARM_REG_Q7);
  }
  else
  {
    gum_thumb_writer_put_sub_reg_imm (cw, ARM_REG_SP,
        (16 * sizeof (GumArmVectorReg)) + 4);
  }

  gum_thumb_writer_put_push_regs (cw, 7,
      ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12);

  gum_thumb_writer_put_sub_reg_imm (cw, ARM_REG_SP, 4);

  gum_thumb_writer_put_mov_reg_reg (cw, ARM_REG_R10, ARM_REG_SP);

  /*
   * Like in the ARM prolog we must now ensure that the stack is 8 byte aligned.
   * Note that unlike the ARM prolog, which simply rounds down the stack
   * pointer, the Thumb instruction set often requires wide, or Thumb v2
   * instructions to work with registers other than R0-R7. We therefore retard
   * the stack by 8, before rounding back up. This works as we know the stack
   * must be 4 byte aligned since ARM architecture does not support unaligned
   * data access. e.g. if the stack was already aligned, we simply retard the
   * pointer by 8 (although wasting a few bytes of stack space, this still
   * retains alignment), if it was misaligned, we retard the pointer by 8 before
   * advancing back 4 bytes.
   */
  gum_thumb_writer_put_and_reg_reg_imm (cw, ARM_REG_R0, ARM_REG_SP, 7);
  gum_thumb_writer_put_sub_reg_reg_imm (cw, ARM_REG_SP, ARM_REG_SP, 8);
  gum_thumb_writer_put_add_reg_reg_reg (cw, ARM_REG_SP, ARM_REG_SP, ARM_REG_R0);
}

static void
gum_exec_ctx_write_arm_epilog (GumExecCtx * ctx,
                               GumArmWriter * cw)
{
  const GumCpuFeatures cpu_features = ctx->stalker->cpu_features;

  /*
   * We know that the context structure was at the top of the stack at the end
   * of the prolog, before the stack was aligned. Rather than working out how
   * much alignment was needed, we can simply restore R10 back into SP to
   * retrieve our stack pointer pre-alignment before we continue restoring the
   * rest of the context.
   */
  gum_arm_writer_put_mov_reg_reg (cw, ARM_REG_SP, ARM_REG_R10);

  gum_arm_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R5, ARM_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, cpsr));

  /* Skip PC, SP, and CPSR */
  gum_arm_writer_put_add_reg_u16 (cw, ARM_REG_SP, 3 * 4);

  gum_arm_writer_put_pop_regs (cw, 5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12);

  if ((cpu_features & GUM_CPU_VFP2) != 0)
  {
    gum_arm_writer_put_vpop_range (cw, ARM_REG_Q0, ARM_REG_Q7);

    if ((cpu_features & GUM_CPU_VFPD32) != 0)
    {
      gum_arm_writer_put_vpop_range (cw, ARM_REG_Q8, ARM_REG_Q15);
      gum_arm_writer_put_add_reg_u16 (cw, ARM_REG_SP, 4);
    }
    else
    {
      gum_arm_writer_put_add_reg_u16 (cw, ARM_REG_SP,
          (8 * sizeof (GumArmVectorReg)) + 4);
    }
  }
  else
  {
    gum_arm_writer_put_add_reg_u16 (cw, ARM_REG_SP,
        (16 * sizeof (GumArmVectorReg)) + 4);
  }

  gum_arm_writer_put_mov_cpsr_reg (cw, ARM_REG_R5);

  gum_arm_writer_put_pop_regs (cw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
      ARM_REG_R3, ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);
}

static void
gum_exec_ctx_write_thumb_epilog (GumExecCtx * ctx,
                                 GumThumbWriter * cw)
{
  const GumCpuFeatures cpu_features = ctx->stalker->cpu_features;

  gum_thumb_writer_put_mov_reg_reg (cw, ARM_REG_SP, ARM_REG_R10);

  gum_thumb_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R5, ARM_REG_SP,
      G_STRUCT_OFFSET (GumCpuContext, cpsr));

  gum_thumb_writer_put_add_reg_imm (cw, ARM_REG_SP, 3 * 4);

  gum_thumb_writer_put_pop_regs (cw, 5,
      ARM_REG_R8, ARM_REG_R9, ARM_REG_R10, ARM_REG_R11, ARM_REG_R12);

  if ((cpu_features & GUM_CPU_VFP2) != 0)
  {
    gum_thumb_writer_put_vpop_range (cw, ARM_REG_Q0, ARM_REG_Q7);

    if ((cpu_features & GUM_CPU_VFPD32) != 0)
    {
      gum_thumb_writer_put_vpop_range (cw, ARM_REG_Q8, ARM_REG_Q15);
      gum_thumb_writer_put_add_reg_imm (cw, ARM_REG_SP, 4);
    }
    else
    {
      gum_thumb_writer_put_add_reg_imm (cw, ARM_REG_SP,
          (8 * sizeof (GumArmVectorReg)) + 4);
    }
  }
  else
  {
    gum_thumb_writer_put_add_reg_imm (cw, ARM_REG_SP,
        (16 * sizeof (GumArmVectorReg)) + 4);
  }

  gum_thumb_writer_put_mov_cpsr_reg (cw, ARM_REG_R5);

  gum_thumb_writer_put_pop_regs (cw, 9,
      ARM_REG_R0, ARM_REG_R1, ARM_REG_R2,
      ARM_REG_R3, ARM_REG_R4, ARM_REG_R5,
      ARM_REG_R6, ARM_REG_R7, ARM_REG_LR);
}

static void
gum_exec_ctx_ensure_inline_helpers_reachable (GumExecCtx * ctx)
{
  gum_exec_ctx_ensure_arm_helper_reachable (ctx, &ctx->last_arm_invalidator,
      gum_exec_ctx_write_arm_invalidator);
  gum_exec_ctx_ensure_thumb_helper_reachable (ctx, &ctx->last_thumb_invalidator,
      gum_exec_ctx_write_thumb_invalidator);
  ctx->code_slab->arm_invalidator = ctx->last_arm_invalidator;
  ctx->code_slab->thumb_invalidator = ctx->last_thumb_invalidator;
}

static void
gum_exec_ctx_write_arm_invalidator (GumExecCtx * ctx,
                                    GumArmWriter * cw)
{
  gum_exec_ctx_write_arm_prolog (ctx, cw);

  gum_arm_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_recompile_and_switch_block), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_REGISTER, ARM_REG_LR);

  gum_exec_ctx_write_arm_epilog (ctx, cw);
  gum_arm_writer_put_pop_regs (cw, 1, ARM_REG_LR);

  gum_exec_block_write_arm_exec_generated_code (cw, ctx);
}

static void
gum_exec_ctx_write_thumb_invalidator (GumExecCtx * ctx,
                                      GumThumbWriter * cw)
{
  gum_exec_ctx_write_thumb_prolog (ctx, cw);

  gum_thumb_writer_put_call_address_with_arguments (cw,
      GUM_ADDRESS (gum_exec_ctx_recompile_and_switch_block), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
      GUM_ARG_REGISTER, ARM_REG_LR);

  gum_exec_ctx_write_thumb_epilog (ctx, cw);
  gum_thumb_writer_put_pop_regs (cw, 2, ARM_REG_R0, ARM_REG_LR);

  gum_exec_block_write_thumb_exec_generated_code (cw, ctx);
}

static void
gum_exec_ctx_ensure_arm_helper_reachable (GumExecCtx * ctx,
                                          gpointer * helper_ptr,
                                          GumArmHelperWriteFunc write)
{
  GumSlab * slab = &ctx->code_slab->slab;
  GumArmWriter * cw = &ctx->arm_writer;
  gpointer start;

  if (gum_exec_ctx_is_arm_helper_reachable (ctx, helper_ptr))
    return;

  start = gum_slab_align_cursor (slab, 4);
  gum_stalker_thaw (ctx->stalker, start, gum_slab_available (slab));
  gum_arm_writer_reset (cw, start);
  *helper_ptr = gum_arm_writer_cur (cw);

  write (ctx, cw);

  gum_arm_writer_flush (cw);
  gum_stalker_freeze (ctx->stalker, cw->base, gum_arm_writer_offset (cw));

  gum_slab_reserve (slab, gum_arm_writer_offset (cw));
}

static void
gum_exec_ctx_ensure_thumb_helper_reachable (GumExecCtx * ctx,
                                            gpointer * helper_ptr,
                                            GumThumbHelperWriteFunc write)
{
  GumSlab * slab = &ctx->code_slab->slab;
  GumThumbWriter * cw = &ctx->thumb_writer;
  gpointer start;

  if (gum_exec_ctx_is_thumb_helper_reachable (ctx, helper_ptr))
    return;

  start = gum_slab_align_cursor (slab, 2);
  gum_stalker_thaw (ctx->stalker, start, gum_slab_available (slab));
  gum_thumb_writer_reset (cw, start);
  *helper_ptr = gum_thumb_writer_cur (cw);

  write (ctx, cw);

  gum_thumb_writer_flush (cw);
  gum_stalker_freeze (ctx->stalker, cw->base, gum_thumb_writer_offset (cw));

  gum_slab_reserve (slab, gum_thumb_writer_offset (cw));
}

static gboolean
gum_exec_ctx_is_arm_helper_reachable (GumExecCtx * ctx,
                                      gpointer * helper_ptr)
{
  GumSlab * slab = &ctx->code_slab->slab;
  GumArmWriter * cw = &ctx->arm_writer;
  GumAddress helper, start, end;

  helper = GUM_ADDRESS (*helper_ptr);
  if (helper == 0)
    return FALSE;

  start = GUM_ADDRESS (gum_slab_start (slab));
  end = GUM_ADDRESS (gum_slab_end (slab));

  if (!gum_arm_writer_can_branch_directly_between (cw, start, helper))
    return FALSE;

  return gum_arm_writer_can_branch_directly_between (cw, end, helper);
}

static gboolean
gum_exec_ctx_is_thumb_helper_reachable (GumExecCtx * ctx,
                                        gpointer * helper_ptr)
{
  GumSlab * slab = &ctx->code_slab->slab;
  GumThumbWriter * cw = &ctx->thumb_writer;
  GumAddress helper, start, end;

  helper = GUM_ADDRESS (*helper_ptr);
  if (helper == 0)
    return FALSE;

  start = GUM_ADDRESS (gum_slab_start (slab));
  end = GUM_ADDRESS (gum_slab_end (slab));

  if (!gum_thumb_writer_can_branch_directly_between (cw, start, helper))
    return FALSE;

  return gum_thumb_writer_can_branch_directly_between (cw, end, helper);
}

static void
gum_exec_ctx_write_arm_mov_branch_target (GumExecCtx * ctx,
                                          const GumBranchTarget * target,
                                          arm_reg reg,
                                          GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->arm_writer;

  switch (target->type)
  {
    case GUM_TARGET_DIRECT_ADDRESS: /* E.g. 'B #1234' */
    {
      const GumBranchDirectAddress * value = &target->value.direct_address;

      gum_arm_writer_put_ldr_reg_address (cw, reg,
          GUM_ADDRESS (value->address));

      break;
    }
    case GUM_TARGET_DIRECT_REG_OFFSET: /* E.g. 'ADD/SUB pc, r1, #32' */
    {
      const GumBranchDirectRegOffset * value = &target->value.direct_reg_offset;

      gum_exec_ctx_arm_load_real_register_into (ctx, reg, value->reg, gc);

      if (value->offset >= 0)
        gum_arm_writer_put_add_reg_reg_imm (cw, reg, reg, value->offset);
      else
        gum_arm_writer_put_sub_reg_reg_imm (cw, reg, reg, -value->offset);

      break;
    }
    case GUM_TARGET_DIRECT_REG_SHIFT: /* E.g. 'ADD pc, r1, r2 lsl #4' */
    {
      const GumBranchDirectRegShift * value = &target->value.direct_reg_shift;

      gum_exec_ctx_arm_load_real_register_into (ctx, reg, value->base, gc);

      /*
       * Here we are going to use R12 as additional scratch space. Since we
       * typically use this function to load the target into a register so that
       * it can be used as a function parameter, R12 is unlikely to be our
       * target register. Although R12 is not callee saved, the instruction
       * being handled may not represent a function call or return, but rather a
       * transition between blocks within a function and therefore we store and
       * restore its contents. Note that we do this above the redzone to avoid
       * clobbering any data stored there, and also do so without modifying SP
       * since that may be one of the operands of the branch instruction.
       */
      if (reg == ARM_REG_R12)
      {
        gum_panic ("Cannot support ADD/SUB reg, reg, reg when target is "
            "ARM_REG_R12");
      }

      gum_arm_writer_put_str_reg_reg_offset (cw, ARM_REG_R12, ARM_REG_SP,
          -GUM_RED_ZONE_SIZE - 4);

      /*
       * Load the second register value from the context into R12 before adding
       * to the original and applying any necessary shift.
       */
      gum_exec_ctx_arm_load_real_register_into (ctx, ARM_REG_R12, value->index,
          gc);

      gum_arm_writer_put_add_reg_reg_reg_shift (cw, reg, reg, ARM_REG_R12,
          value->shifter, value->shift_value);

      gum_arm_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R12, ARM_REG_SP,
          -GUM_RED_ZONE_SIZE - 4);

      break;
    }
    case GUM_TARGET_INDIRECT_REG_OFFSET: /* E.g. 'LDR pc, [r3, #4]' */
    {
      const GumBranchIndirectRegOffset * value =
          &target->value.indirect_reg_offset;

      gum_exec_ctx_arm_load_real_register_into (ctx, reg, value->reg, gc);

      /*
       * If the target is indirect, then we need to dereference it.
       * E.g. LDR pc, [r3, #4]
       */
      gum_arm_writer_put_ldr_reg_reg_offset (cw, reg, reg, value->offset);

      break;
    }
    case GUM_TARGET_INDIRECT_REG_SHIFT: /* E.g. 'LDR pc, [pc, r0, lsl #2]' */
    {
      const GumBranchIndirectRegShift * value =
          &target->value.indirect_reg_shift;

      gum_exec_ctx_arm_load_real_register_into (ctx, reg, value->base, gc);

      /*
       * Here we are going to use R12 as additional scratch space. Since we
       * typically use this function to load the target into a register so that
       * it can be used as a function parameter, R12 is unlikely to be our
       * target register. Although R12 is not callee saved, the instruction
       * being handled may not represent a function call or return, but rather a
       * transition between blocks within a function and therefore we store and
       * restore its contents. Note that we do this above the redzone to avoid
       * clobbering any data stored there, and also do so without modifying SP
       * since that may be one of the operands of the branch instruction.
       */
      if (reg == ARM_REG_R12)
      {
        gum_panic ("Cannot support LDR reg, reg, SHIFT when target is "
            "ARM_REG_R12");
      }

      gum_arm_writer_put_str_reg_reg_offset (cw, ARM_REG_R12, ARM_REG_SP,
          -GUM_RED_ZONE_SIZE - 4);

      /*
       * Load the second register value from the context into R12 before adding
       * to the original and applying any necessary shift.
       */
      gum_exec_ctx_arm_load_real_register_into (ctx, ARM_REG_R12, value->index,
          gc);

      gum_arm_writer_put_add_reg_reg_reg_shift (cw, reg, reg, ARM_REG_R12,
          value->shifter, value->shift_value);

      gum_arm_writer_put_ldr_reg_reg_offset (cw, ARM_REG_R12, ARM_REG_SP,
          -GUM_RED_ZONE_SIZE - 4);

      gum_arm_writer_put_ldr_reg_reg (cw, reg, reg);

      break;
    }
    default:
      g_assert_not_reached ();
  }
}

static void
gum_exec_ctx_write_thumb_mov_branch_target (GumExecCtx * ctx,
                                            const GumBranchTarget * target,
                                            arm_reg reg,
                                            GumGeneratorContext * gc)
{
  GumThumbWriter * cw = gc->thumb_writer;

  switch (target->type)
  {
    case GUM_TARGET_DIRECT_ADDRESS:
    {
      const GumBranchDirectAddress * value = &target->value.direct_address;

      gum_thumb_writer_put_ldr_reg_address (cw, reg,
          GUM_ADDRESS (value->address));

      break;
    }
    case GUM_TARGET_DIRECT_REG_OFFSET:
    {
      const GumBranchDirectRegOffset * value = &target->value.direct_reg_offset;

      g_assert (value->offset >= 0);

      gum_exec_ctx_thumb_load_real_register_into (ctx, reg, value->reg, gc);

      gum_thumb_writer_put_add_reg_reg_imm (cw, reg, reg, value->offset);

      if (value->mode == GUM_ARM_MODE_CURRENT)
        gum_thumb_writer_put_or_reg_reg_imm (cw, reg, reg, 0x1);

      break;
    }
    case GUM_TARGET_DIRECT_REG_SHIFT:
    {
      g_assert_not_reached ();
      break;
    }
    case GUM_TARGET_INDIRECT_REG_OFFSET:
    {
      const GumBranchIndirectRegOffset * value =
          &target->value.indirect_reg_offset;

      g_assert (value->offset >= 0);

      gum_exec_ctx_thumb_load_real_register_into (ctx, reg, value->reg, gc);

      /*
       * If the target is indirect, then we need to dereference it.
       * E.g. LDR pc, [r3, #4]
       */
      gum_thumb_writer_put_ldr_reg_reg_offset (cw, reg, reg, value->offset);

      break;
    }
    case GUM_TARGET_INDIRECT_PCREL_TABLE:
    {
      const GumBranchIndirectPcrelTable * value =
          &target->value.indirect_pcrel_table;
      arm_reg offset_reg;

      gum_exec_ctx_thumb_load_real_register_into (ctx, reg, value->base, gc);

      offset_reg = (reg != ARM_REG_R0) ? ARM_REG_R0 : ARM_REG_R1;
      gum_thumb_writer_put_push_regs (cw, 1, offset_reg);

      gum_exec_ctx_thumb_load_real_register_into (ctx, offset_reg, value->index,
          gc);
      if (value->element_size == 2)
      {
        /* Transform index to offset. */
        gum_thumb_writer_put_lsl_reg_reg_imm (cw, offset_reg, offset_reg, 1);
      }

      /* Add base address. */
      gum_thumb_writer_put_add_reg_reg (cw, offset_reg, reg);

      /* Read the uint8 or uint16 at the given index. */
      if (value->element_size == 1)
        gum_thumb_writer_put_ldrb_reg_reg (cw, offset_reg, offset_reg);
      else
        gum_thumb_writer_put_ldrh_reg_reg (cw, offset_reg, offset_reg);
      /* Transform index to offset. */
      gum_thumb_writer_put_lsl_reg_reg_imm (cw, offset_reg, offset_reg, 1);

      /* Add Thumb bit. */
      gum_thumb_writer_put_add_reg_imm (cw, offset_reg, 1);

      /* Now we have an offset we can add to the base. */
      gum_thumb_writer_put_add_reg_reg_reg (cw, reg, reg, offset_reg);

      gum_thumb_writer_put_pop_regs (cw, 1, offset_reg);

      break;
    }
    case GUM_TARGET_INDIRECT_REG_SHIFT: /* E.g. 'LDR pc, [pc, r0, lsl #2]' */
    {
      g_assert_not_reached ();
      break;
    }
    default:
      g_assert_not_reached ();
  }
}

static void
gum_exec_ctx_arm_load_real_register_into (GumExecCtx * ctx,
                                          arm_reg target_register,
                                          arm_reg source_register,
                                          GumGeneratorContext * gc)
{
  GumArmWriter * cw = gc->arm_writer;

  /*
   * For the most part, we simply need to identify the offset of the
   * source_register within the GumCpuContext structure and load the value
   * accordingly. However, in the case of the PC, we instead load the address of
   * the current instruction in the iterator. Note that we add the fixed offset
   * of 8 since the value of PC is always interpreted in ARM32 as being 8 bytes
   * past the start of the instruction.
   */
  if (source_register >= ARM_REG_R0 && source_register <= ARM_REG_R7)
  {
    gum_arm_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, r) +
        ((source_register - ARM_REG_R0) * 4));
  }
  else if (source_register >= ARM_REG_R8 && source_register <= ARM_REG_R12)
  {
    gum_arm_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, r8) +
        ((source_register - ARM_REG_R8) * 4));
  }
  else if (source_register == ARM_REG_LR)
  {
    gum_arm_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, lr));
  }
  else if (source_register == ARM_REG_SP)
  {
    gum_arm_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, sp));
  }
  else if (source_register == ARM_REG_PC)
  {
    gum_arm_writer_put_ldr_reg_address (cw, target_register,
        GUM_ADDRESS (gc->instruction->start + 8));
  }
  else
  {
    g_assert_not_reached ();
  }
}

static void
gum_exec_ctx_thumb_load_real_register_into (GumExecCtx * ctx,
                                            arm_reg target_register,
                                            arm_reg source_register,
                                            GumGeneratorContext * gc)
{
  GumThumbWriter * cw = gc->thumb_writer;

  if (source_register >= ARM_REG_R0 && source_register <= ARM_REG_R7)
  {
    gum_thumb_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, r) +
        ((source_register - ARM_REG_R0) * 4));
  }
  else if (source_register >= ARM_REG_R8 && source_register <= ARM_REG_R12)
  {
    gum_thumb_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, r8) +
        ((source_register - ARM_REG_R8) * 4));
  }
  else if (source_register == ARM_REG_LR)
  {
    gum_thumb_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, lr));
  }
  else if (source_register == ARM_REG_SP)
  {
    gum_thumb_writer_put_ldr_reg_reg_offset (cw, target_register, ARM_REG_R10,
        G_STRUCT_OFFSET (GumCpuContext, sp));
  }
  else if (source_register == ARM_REG_PC)
  {
    gum_thumb_writer_put_ldr_reg_address (cw, target_register,
        GUM_ADDRESS (gc->instruction->start + 4));
  }
  else
  {
    g_assert_not_reached ();
  }
}

static GumExecBlock *
gum_exec_block_new (GumExecCtx * ctx)
{
  GumExecBlock * block;
  GumStalker * stalker = ctx->stalker;
  GumCodeSlab * code_slab = ctx->code_slab;
  GumDataSlab * data_slab = ctx->data_slab;
  gsize code_available;

  code_available = gum_slab_available (&code_slab->slab);
  if (code_available < GUM_EXEC_BLOCK_MIN_CAPACITY)
  {
    GumAddressSpec data_spec;

    code_slab = gum_exec_ctx_add_code_slab (ctx, gum_code_slab_new (ctx));

    gum_exec_ctx_compute_data_address_spec (ctx, data_slab->slab.size,
        &data_spec);
    if (!gum_address_spec_is_satisfied_by (&data_spec,
            gum_slab_start (&data_slab->slab)))
    {
      data_slab = gum_exec_ctx_add_data_slab (ctx, gum_data_slab_new (ctx));
    }

    gum_exec_ctx_ensure_inline_helpers_reachable (ctx);

    code_available = gum_slab_available (&code_slab->slab);
  }

  block = gum_slab_try_reserve (&data_slab->slab, sizeof (GumExecBlock));
  if (block == NULL)
  {
    data_slab = gum_exec_ctx_add_data_slab (ctx, gum_data_slab_new (ctx));
    block = gum_slab_reserve (&data_slab->slab, sizeof (GumExecBlock));
  }

  /*
   * Instrumented ARM code needs to be 4 byte aligned. We will make all code
   * blocks (both ARM and Thumb) 4 byte aligned for simplicity.
   */
  gum_slab_align_cursor (&code_slab->slab, 4);

  block->next = ctx->block_list;
  ctx->block_list = block;

  block->ctx = ctx;
  block->code_slab = code_slab;

  block->code_start = gum_slab_cursor (&code_slab->slab);

  gum_stalker_thaw (stalker, block->code_start, code_available);

  return block;
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
}

static void
gum_exec_block_invalidate (GumExecBlock * block)
{
  GumExecCtx * ctx = block->ctx;
  GumStalker * stalker = ctx->stalker;
  const gsize trampoline_size = GUM_INVALIDATE_TRAMPOLINE_SIZE;

  gum_stalker_thaw (stalker, block->code_start, trampoline_size);

  if ((block->flags & GUM_EXEC_BLOCK_THUMB) != 0)
  {
    GumThumbWriter * cw = &ctx->thumb_writer;

    gum_thumb_writer_reset (cw, block->code_start);

    gum_thumb_writer_put_nop (cw);
    gum_thumb_writer_put_push_regs (cw, 2, ARM_REG_R0, ARM_REG_LR);
    gum_thumb_writer_put_bl_imm (cw,
        GUM_ADDRESS (block->code_slab->thumb_invalidator));
    gum_thumb_writer_put_bytes (cw, (guint8 *) &block, sizeof (GumExecBlock *));

    gum_thumb_writer_flush (cw);
    g_assert (gum_thumb_writer_offset (cw) == trampoline_size);
  }
  else
  {
    GumArmWriter * cw = &ctx->arm_writer;

    gum_arm_writer_reset (cw, block->code_start);

    gum_arm_writer_put_push_regs (cw, 1, ARM_REG_LR);
    gum_arm_writer_put_bl_imm (cw,
        GUM_ADDRESS (block->code_slab->arm_invalidator));
    gum_arm_writer_put_bytes (cw, (guint8 *) &block, sizeof (GumExecBlock *));

    gum_arm_writer_flush (cw);
    g_assert (gum_arm_writer_offset (cw) == trampoline_size);
  }

  gum_stalker_freeze (stalker, block->code_start, trampoline_size);
}

static gpointer
gum_exec_block_encode_instruction_pointer (const GumExecBlock * block,
                                           gpointer ptr)
{
  gpointer result = ptr;

  if ((block->flags & GUM_EXEC_BLOCK_THUMB) != 0)
    result = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (result) | 1);

  return result;
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
gum_exec_ctx_backpatch_arm_branch_to_current (GumExecBlock * block,
                                              GumExecBlock * from,
                                              gpointer from_insn,
                                              gsize code_offset,
                                              GumPrologState opened_prolog)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  gpointer target;
  guint8 * code_start = from->code_start + code_offset;
  const gsize code_max_size = from->code_size - code_offset;
  GumArmWriter * cw;

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

  cw = &ctx->arm_writer;
  gum_arm_writer_reset (cw, code_start);

  if (opened_prolog == GUM_PROLOG_OPEN)
    gum_exec_ctx_write_arm_epilog (ctx, cw);

  gum_arm_writer_put_branch_address (cw, GUM_ADDRESS (target));

  gum_arm_writer_flush (cw);
  g_assert (gum_arm_writer_offset (cw) <= code_max_size);
  gum_stalker_freeze (ctx->stalker, code_start, code_max_size);

  gum_spinlock_release (&ctx->code_lock);

  if (ctx->observer)
  {
    GumBackpatch p;

    p.type = GUM_BACKPATCH_ARM;
    p.to = block->real_start;
    p.from = from->real_start;
    p.from_insn = from_insn;
    p.code_offset = code_offset;
    p.opened_prolog = opened_prolog;

    gum_stalker_observer_notify_backpatch (ctx->observer, &p, sizeof (p));
  }
}

static void
gum_exec_ctx_backpatch_thumb_branch_to_current (GumExecBlock * block,
                                                GumExecBlock * from,
                                                gpointer from_insn,
                                                gsize code_offset,
                                                GumPrologState opened_prolog)
{
  gboolean just_unfollowed;
  GumExecCtx * ctx;
  gpointer target;
  guint8 * code_start = from->code_start + code_offset;
  const gsize code_max_size = from->code_size - code_offset;
  GumThumbWriter * cw;

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

  cw = &ctx->thumb_writer;
  gum_thumb_writer_reset (cw, code_start);

  if (opened_prolog == GUM_PROLOG_OPEN)
    gum_exec_ctx_write_thumb_epilog (ctx, cw);

  gum_thumb_writer_put_branch_address (cw, GUM_ADDRESS (target));

  gum_thumb_writer_flush (cw);
  g_assert (gum_thumb_writer_offset (cw) <= code_max_size);
  gum_stalker_freeze (ctx->stalker, code_start, code_max_size);

  gum_spinlock_release (&ctx->code_lock);

  if (ctx->observer)
  {
    GumBackpatch p;

    p.type = GUM_BACKPATCH_THUMB;
    p.to = block->real_start;
    p.from = from->real_start;
    p.from_insn = from_insn;
    p.code_offset = code_offset;
    p.opened_prolog = opened_prolog;

    gum_stalker_observer_notify_backpatch (ctx
"""


```