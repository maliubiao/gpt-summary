Response:
The user wants a summary of the functionality of the provided C code snippet from `gumstalker-arm.c`. The snippet contains several functions related to code transformation and execution within the Frida dynamic instrumentation framework on ARM architectures.

Here's a breakdown of how to approach the request:

1. **Identify Key Functions:**  Scan the code for function definitions. Each function likely represents a distinct piece of functionality.

2. **Understand Function Purpose:**  Analyze the code within each function to understand its role in the overall process. Look for variable names, function calls to other `gum` library functions, and control flow.

3. **Relate to Dynamic Instrumentation:** Connect the observed functionality to the concepts of dynamic instrumentation, such as code tracing, modification, and interception.

4. **Address Specific Requirements:**  Go through the user's specific questions:
    * **Relation to Reverse Engineering:** How does this code facilitate understanding or altering the behavior of existing binaries?
    * **Binary/Kernel/Framework Interaction:**  Are there any points where the code interacts with low-level aspects of the operating system or target application's environment?
    * **Logical Reasoning:** Are there any conditional statements or loops that involve specific input and predictable output?
    * **User Errors:** What common mistakes might a user make when interacting with or using the functionality exposed by this code?
    * **User Path:** How does a user's interaction with Frida eventually lead to the execution of this code?
    * **Overall Functionality (Summary):**  Synthesize the identified function purposes into a concise description of the code's main role.

5. **Structure the Response:** Organize the information clearly, addressing each of the user's points systematically. Use examples where appropriate to illustrate concepts.

**Detailed Analysis of the Code Snippet:**

* **`gum_exec_ctx_compile_arm_block` and `gum_exec_ctx_compile_thumb_block`:** These functions are clearly responsible for compiling blocks of ARM and Thumb code, respectively. They take input code, an output buffer, and perform transformations. Key elements include:
    * **Relocation:**  `GumArmRelocator` and `GumThumbRelocator` suggest handling address dependencies when moving code.
    * **Code Writing:** `GumArmWriter` and `GumThumbWriter` are used to generate the transformed code.
    * **Probes:** `gum_exec_block_maybe_write_call_probe_code` implies the insertion of instrumentation points.
    * **Context Switching:** `gum_exec_ctx_switch_block` hints at managing transitions between original and instrumented code.
    * **Breakpoints:** `gum_arm_writer_put_breakpoint` and `gum_thumb_writer_put_breakpoint` suggest placing breakpoints for debugging or control flow.

* **`gum_exec_ctx_maybe_emit_compile_event`:** This function appears to generate an event notification when a block of code is compiled, likely for tracking or logging.

* **`gum_stalker_iterator_next`:** This function acts as an iterator over the instructions in a code block, fetching the next instruction. It has separate implementations for ARM and Thumb.

* **`gum_stalker_iterator_arm_next` and `gum_stalker_iterator_thumb_next`:** These functions handle the logic for fetching the next instruction in ARM and Thumb mode, respectively. They also seem to insert block entry events.

* **`gum_stalker_iterator_is_out_of_space`:** This function checks if there's enough space remaining in the output buffer to continue compiling.

* **`gum_stalker_iterator_keep`:** This function determines whether to "keep" the current instruction. It seems to handle special cases for exclusive load/store instructions.

* **`gum_stalker_iterator_get_memory_access`:** This function returns the type of memory access (exclusive or open) based on block flags.

* **`gum_stalker_iterator_arm_keep` and `gum_stalker_iterator_thumb_keep`:** These functions handle the details of keeping an ARM or Thumb instruction, potentially virtualizing branch instructions.

* **`gum_stalker_iterator_handle_thumb_branch_insn`:** This function specifically handles branch instructions in Thumb mode, virtualizing them for instrumentation.

* **`gum_stalker_iterator_handle_thumb_it_insn`:** This function deals with the special case of the IT (If-Then-Else) instruction block in Thumb mode, ensuring proper instrumentation.

* **`gum_stalker_save_cpsr` and `gum_stalker_restore_cpsr`:** These functions handle saving and restoring the CPU's condition flags (CPSR), which is crucial for maintaining program state during instrumentation.

* **`gum_stalker_get_target_address`:** This function analyzes an instruction to determine the target address of a branch, call, or return, handling various addressing modes.

* **`gum_stalker_get_writeback`:** This function extracts information about writeback behavior for certain load instructions.

* **`gum_exec_ctx_emit_call_event`, `gum_exec_ctx_emit_ret_event`, `gum_exec_ctx_emit_exec_event`, `gum_exec_ctx_emit_block_event`:** These functions generate different types of events (call, return, execution, block entry) during the instrumentation process.

* **`gum_stalker_iterator_put_callout`:** This function allows inserting custom function calls (callouts) into the instrumented code.

* **`gum_stalker_invoke_callout`:** This function is the actual invoker of the custom callout function.

* **`gum_stalker_iterator_put_chaining_return`:** This function inserts a return instruction that chains back to the original code.

* **`gum_stalker_iterator_get_capstone`:** This function likely returns a Capstone disassembler instance.

By combining the understanding of individual function purposes, we can arrive at a comprehensive summary of the code's functionality.
这是 `frida/subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c` 文件的一部分代码，主要负责 Frida Stalker (代码追踪和修改引擎) 在 ARM 架构上的代码块编译和处理逻辑。以下是这段代码的功能归纳：

**核心功能：代码块的编译和转换**

这段代码的核心功能是将原始的 ARM 或 Thumb 指令块编译和转换成 Frida 可以监控和干预的新的代码块。这个过程包括：

1. **初始化编译上下文:**  `gum_exec_ctx_compile_arm_block` 和 `gum_exec_ctx_compile_thumb_block` 函数分别负责 ARM 和 Thumb 指令集的编译。它们会初始化写代码 (`GumArmWriter`, `GumThumbWriter`) 和重定位 (`GumArmRelocator`, `GumThumbRelocator`) 的上下文。

2. **处理指令迭代:**  通过 `GumStalkerIterator` 结构体和相关的 `gum_stalker_iterator_next` 函数，逐条读取原始代码块的指令。

3. **插入探针代码:**  `gum_exec_block_maybe_write_call_probe_code` 函数用于在代码块的开头插入用于监控函数调用的探针代码。

4. **指令转换:**  `ctx->transform_block_impl` 指针指向的函数负责实际的指令转换逻辑，这部分代码在这段截取中没有给出，但它是 Stalker 核心的指令改写功能。

5. **处理代码块的延续:** 如果在编译过程中遇到需要跳转到原始代码块的情况 (`gc.continuation_real_address != NULL`)，会生成一段代码来切换回原始代码的执行。`gum_exec_ctx_switch_block` 函数负责这个切换过程。

6. **插入断点:** `gum_arm_writer_put_breakpoint` 和 `gum_thumb_writer_put_breakpoint` 用于在编译后的代码块末尾插入断点，以便在执行完编译后的代码后能够重新回到 Frida 的控制。

7. **刷新和确认:** `gum_arm_writer_flush` 和 `gum_thumb_writer_flush` 刷新写入的代码，并检查所有标签是否都被正确解析。

8. **记录编译事件:** `gum_exec_ctx_maybe_emit_compile_event` 函数会在编译完成后发送一个事件通知，告知代码块的起始和结束地址。

**与逆向方法的关系及举例说明:**

这段代码是 Frida 动态插桩的核心组成部分，与逆向工程的方法紧密相关。通过编译和转换代码块，Frida 可以在目标进程运行时动态地插入代码，实现以下逆向分析目的：

* **代码追踪 (Tracing):**  通过在每个基本块或特定指令前后插入探针代码，可以记录程序的执行流程，例如函数调用顺序、执行的指令序列等。
    * **举例:** 逆向工程师可以使用 Frida 脚本，当程序执行到某个特定函数时，记录其参数值和返回值，或者记录特定循环的执行次数。这段代码中的 `gum_exec_block_maybe_write_call_probe_code` 就是实现这个功能的基础。

* **代码覆盖率分析:**  通过记录哪些代码块被执行过，可以分析程序的代码覆盖率，帮助理解代码的执行路径。
    * **举例:** 逆向工程师可以使用 Frida 脚本来统计程序运行过程中执行过的函数或代码块，从而了解测试用例的覆盖范围。`gum_exec_ctx_maybe_emit_compile_event` 可以用于生成编译事件，结合执行事件可以分析覆盖率。

* **动态修改代码行为:**  通过修改原始指令或插入新的指令，可以改变程序的执行流程或行为。
    * **举例:** 逆向工程师可以使用 Frida 脚本来 Hook (拦截) 某个函数，修改其参数或返回值，或者跳过某些特定的代码逻辑。 `ctx->transform_block_impl` 负责具体的指令修改，而生成的新的代码块会包含修改后的指令。

* **内存访问监控:**  虽然这段代码没有直接体现内存访问监控，但 Stalker 可以与其他 Frida 组件结合，监控特定内存区域的读写操作。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

这段代码涉及到了以下方面的知识：

* **ARM 指令集架构:**  代码中大量使用了 `GumArmWriter`、`GumThumbWriter`、`GumArmRelocator`、`GumThumbRelocator` 等结构体和函数，它们都与 ARM 和 Thumb 指令集的编码和重定位相关。
    * **举例:**  `gum_arm_writer_put_call_address_with_arguments` 函数需要知道如何在 ARM 指令集中编码函数调用指令并传递参数。

* **二进制代码重定位:**  在动态插桩过程中，原始代码被复制到新的内存区域，代码中的跳转目标地址可能需要调整，这就是重定位。`GumArmRelocator` 和 `GumThumbRelocator` 负责计算和应用这些偏移。
    * **举例:**  如果一个跳转指令 `B label` 中的 `label` 在原始代码中的地址是 `0x1000`，但在新的内存区域变成了 `0x2000`，重定位器需要将跳转指令的目标地址修改为 `0x2000`。

* **函数调用约定:**  `gum_arm_writer_put_call_address_with_arguments` 函数在生成函数调用代码时，需要遵循 ARM 的函数调用约定 (例如，参数如何传递，返回值如何获取)。

* **内存管理:**  Frida 需要在目标进程的内存空间中分配新的内存来存放编译后的代码。

* **进程上下文切换:**  `gum_exec_ctx_switch_block` 函数涉及到在原始代码和 Frida 生成的代码之间切换执行上下文。这在 Linux 和 Android 中涉及到 CPU 寄存器的保存和恢复等底层操作。

* **事件通知机制:**  `gum_exec_ctx_maybe_emit_compile_event` 函数利用 Frida 的事件通知机制，将编译事件传递给 Frida 客户端。这在 Android 中可能涉及到 Binder IPC 等机制。

**逻辑推理及假设输入与输出:**

* **假设输入:** 一个指向 ARM 指令序列的指针 `input_code`，以及一个用于存放编译后代码的缓冲区 `output_code`。
* **逻辑推理:**  `gum_exec_ctx_compile_arm_block` 或 `gum_exec_ctx_compile_thumb_block` 函数会遍历 `input_code` 中的指令，并根据 Stalker 的配置（例如，是否需要插入探针）生成新的指令序列写入 `output_code`。如果遇到需要跳转回原始代码的情况，还会生成相应的跳转代码。
* **输出:**
    * `*input_size`:  被编译的原始代码块的大小。
    * `*output_size`: 编译后代码块的大小，通常会比原始代码块大，因为插入了额外的探针代码或跳转代码。
    * `output_code`:  包含了转换后的指令序列，可能包含探针代码、跳转代码以及原始代码的修改版本。

**涉及用户或编程常见的使用错误及举例说明:**

* **输出缓冲区过小:** 如果提供的 `output_code` 缓冲区大小不足以存放编译后的代码，会导致 `gum_panic ("Failed to resolve labels")` 错误，因为代码写入过程中可能会超出缓冲区边界。
    * **举例:** 用户在调用 Frida 的 Stalker API 时，没有为 `transform` 函数提供足够大的输出缓冲区。

* **错误的指令集模式:**  如果目标代码是 Thumb 指令集，但使用了 `gum_exec_ctx_compile_arm_block` 函数进行编译，或者反之，会导致指令解析和编译错误。
    * **举例:**  用户在附加到目标进程后，没有正确判断目标代码的指令集模式，导致 Stalker 尝试用错误的模式进行编译。

* **不正确的 Stalker 配置:**  如果 Stalker 的配置与目标代码的行为不匹配，例如，错误地配置了需要 Hook 的函数或地址，可能会导致程序崩溃或行为异常。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 用户使用 Python 或 JavaScript 编写 Frida 脚本，使用 Stalker API 来追踪或修改目标进程的代码。
2. **Frida 连接到目标进程:**  Frida 通过注入或其他方式连接到目标进程。
3. **用户启用 Stalker:**  Frida 脚本调用 `Stalker.follow()` 或相关方法来启动 Stalker。
4. **Stalker 遇到新的代码块:** 当目标进程执行到新的代码块，并且该代码块尚未被 Stalker 处理时，Stalker 会尝试编译这个代码块。
5. **调用 `gum_exec_ctx_compile_arm_block` 或 `gum_exec_ctx_compile_thumb_block`:**  根据目标代码块的指令集，Frida 内部会调用相应的编译函数。
6. **执行代码块编译逻辑:**  代码会执行这段代码中的逻辑，包括指令迭代、探针插入、指令转换等。
7. **如果发生错误:**  如果在编译过程中出现问题，例如输出缓冲区不足或指令解析错误，可能会触发 `gum_panic`，并在 Frida 的日志或控制台中显示错误信息，帮助用户进行调试。

**这段代码的功能归纳：**

这段代码是 Frida Stalker 在 ARM 架构上的核心编译模块，负责将目标进程的原始 ARM 或 Thumb 代码块转换成 Frida 可以监控和干预的新代码块。这个过程包括指令的读取、分析、修改以及探针代码的插入，为实现动态代码追踪、修改和 Hook 等功能提供了基础。它涉及到对 ARM 指令集、二进制代码重定位、函数调用约定等底层知识的运用。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-arm/gumstalker-arm.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
uction.start = NULL;
  iterator.instruction.end = NULL;

  output.writer.arm = cw;
  output.encoding = GUM_INSTRUCTION_DEFAULT;

  gum_exec_block_maybe_write_call_probe_code (block, &gc);

  ctx->pending_calls++;

  ctx->transform_block_impl (ctx->transformer, &iterator, &output);

  ctx->pending_calls--;

  if (gc.continuation_real_address != NULL)
  {
    gum_exec_block_arm_open_prolog (block, &gc);

    gum_arm_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_switch_block), 4,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc.continuation_real_address),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc.instruction->start));

    gum_exec_block_arm_close_prolog (block, &gc);

    gum_exec_block_write_arm_exec_generated_code (cw, ctx);
  }

  gum_arm_writer_put_breakpoint (cw);

  all_labels_resolved = gum_arm_writer_flush (cw);
  if (!all_labels_resolved)
    gum_panic ("Failed to resolve labels");

  *input_size = rl->input_cur - rl->input_start;
  *output_size = gum_arm_writer_offset (cw);
}

static void
gum_exec_ctx_compile_thumb_block (GumExecCtx * ctx,
                                  GumExecBlock * block,
                                  gconstpointer input_code,
                                  gpointer output_code,
                                  GumAddress output_pc,
                                  guint * input_size,
                                  guint * output_size)
{
  GumThumbWriter * cw = &ctx->thumb_writer;
  GumThumbRelocator * rl = &ctx->thumb_relocator;
  GumGeneratorContext gc;
  GumStalkerIterator iterator;
  GumStalkerOutput output;
  gboolean all_labels_resolved;

  gum_thumb_writer_reset (cw, output_code);
  cw->pc = output_pc;
  gum_thumb_relocator_reset (rl, input_code, cw);

  gum_ensure_code_readable (input_code, ctx->stalker->page_size);

  gc.instruction = NULL;
  gc.is_thumb = TRUE;
  gc.thumb_relocator = rl;
  gc.thumb_writer = cw;
  gc.continuation_real_address = NULL;

  iterator.exec_context = ctx;
  iterator.exec_block = block;
  iterator.generator_context = &gc;

  iterator.instruction.ci = NULL;
  iterator.instruction.start = NULL;
  iterator.instruction.end = NULL;

  output.writer.thumb = cw;
  output.encoding = GUM_INSTRUCTION_SPECIAL;

  gum_exec_block_maybe_write_call_probe_code (block, &gc);

  ctx->pending_calls++;

  ctx->transform_block_impl (ctx->transformer, &iterator, &output);

  ctx->pending_calls--;

  if (gc.continuation_real_address != NULL)
  {
    gum_exec_block_thumb_open_prolog (block, &gc);

    gum_thumb_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_exec_ctx_switch_block), 4,
        GUM_ARG_ADDRESS, GUM_ADDRESS (ctx),
        GUM_ARG_ADDRESS, GUM_ADDRESS (block),
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc.continuation_real_address) + 1,
        GUM_ARG_ADDRESS, GUM_ADDRESS (gc.instruction->start) + 1);

    gum_exec_block_thumb_close_prolog (block, &gc);

    gum_exec_block_write_thumb_exec_generated_code (cw, ctx);
  }

  gum_thumb_writer_put_breakpoint (cw);

  all_labels_resolved = gum_thumb_writer_flush (cw);
  if (!all_labels_resolved)
    gum_panic ("Failed to resolve labels");

  *input_size = rl->input_cur - rl->input_start;
  *output_size = gum_thumb_writer_offset (cw);
}

static void
gum_exec_ctx_maybe_emit_compile_event (GumExecCtx * ctx,
                                       GumExecBlock * block)
{
  if ((ctx->sink_mask & GUM_COMPILE) != 0)
  {
    GumEvent ev;

    ev.type = GUM_COMPILE;
    ev.compile.start = gum_exec_block_encode_instruction_pointer (block,
        block->real_start);
    ev.compile.end = gum_exec_block_encode_instruction_pointer (block,
        block->real_start + block->real_size);

    ctx->sink_process_impl (ctx->sink, &ev, NULL);
  }
}

gboolean
gum_stalker_iterator_next (GumStalkerIterator * self,
                           const cs_insn ** insn)
{
  GumGeneratorContext * gc = self->generator_context;

  if (gc->is_thumb)
    return gum_stalker_iterator_thumb_next (self, insn);
  else
    return gum_stalker_iterator_arm_next (self, insn);
}

static gboolean
gum_stalker_iterator_arm_next (GumStalkerIterator * self,
                               const cs_insn ** insn)
{
  GumGeneratorContext * gc = self->generator_context;
  GumArmRelocator * rl = gc->arm_relocator;
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
      gum_arm_relocator_skip_one (rl);
    }

    if (gum_stalker_iterator_is_out_of_space (self))
    {
      gc->continuation_real_address = instruction->end;
      return FALSE;
    }

    if (!skip_implicitly_requested && gum_arm_relocator_eob (rl))
      return FALSE;
  }

  instruction = &self->instruction;

  n_read = gum_arm_relocator_read_one (rl, &instruction->ci);
  if (n_read == 0)
    return FALSE;

  instruction->start = GSIZE_TO_POINTER (instruction->ci->address);
  instruction->end = (guint8 *) rl->input_cur;

  self->generator_context->instruction = instruction;

  if (is_first_instruction && (self->exec_context->sink_mask & GUM_BLOCK) != 0)
  {
    GumExecBlock * block = self->exec_block;

    gum_exec_block_arm_open_prolog (block, gc);
    gum_exec_block_write_arm_block_event_code (block, gc);
    gum_exec_block_arm_close_prolog (block, gc);
  }

  if (insn != NULL)
    *insn = instruction->ci;

  return TRUE;
}

static gboolean
gum_stalker_iterator_thumb_next (GumStalkerIterator * self,
                                 const cs_insn ** insn)
{
  GumGeneratorContext * gc = self->generator_context;
  GumThumbRelocator * rl = gc->thumb_relocator;
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
      gum_thumb_relocator_skip_one (rl);
    }

    if (gum_stalker_iterator_is_out_of_space (self))
    {
      gc->continuation_real_address = instruction->end;
      return FALSE;
    }

    if (!skip_implicitly_requested && gum_thumb_relocator_eob (rl))
      return FALSE;
  }

  instruction = &self->instruction;

  n_read = gum_thumb_relocator_read_one (rl, &instruction->ci);
  if (n_read == 0)
    return FALSE;

  instruction->start = GSIZE_TO_POINTER (instruction->ci->address);
  instruction->end = (guint8 *) rl->input_cur;

  self->generator_context->instruction = instruction;

  if (is_first_instruction && (self->exec_context->sink_mask & GUM_BLOCK) != 0)
  {
    GumExecBlock * block = self->exec_block;

    gum_exec_block_thumb_open_prolog (block, gc);
    gum_exec_block_write_thumb_block_event_code (block, gc);
    gum_exec_block_thumb_close_prolog (block, gc);
  }

  if (insn != NULL)
    *insn = instruction->ci;

  return TRUE;
}

static gboolean
gum_stalker_iterator_is_out_of_space (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  GumSlab * slab = &block->code_slab->slab;
  guint8 * cursor;
  gsize capacity, snapshot_size;

  cursor = gc->is_thumb
      ? gum_thumb_writer_cur (gc->thumb_writer)
      : gum_arm_writer_cur (gc->arm_writer);

  capacity = (guint8 *) gum_slab_end (slab) - cursor;

  snapshot_size = gum_stalker_snapshot_space_needed_for (
      self->exec_context->stalker,
      gc->instruction->end - block->real_start);

  return capacity < GUM_EXEC_BLOCK_MIN_CAPACITY + snapshot_size;
}

void
gum_stalker_iterator_keep (GumStalkerIterator * self)
{
  GumGeneratorContext * gc = self->generator_context;
  const cs_insn * insn = gc->instruction->ci;

  if (gum_is_exclusive_load_insn (insn))
    self->exec_block->flags |= GUM_EXEC_BLOCK_HAS_EXCLUSIVE_LOAD;
  else if (gum_is_exclusive_store_insn (insn))
    self->exec_block->flags |= GUM_EXEC_BLOCK_HAS_EXCLUSIVE_STORE;

  if (gc->is_thumb)
    gum_stalker_iterator_thumb_keep (self);
  else
    gum_stalker_iterator_arm_keep (self);
}

GumMemoryAccess
gum_stalker_iterator_get_memory_access (GumStalkerIterator * self)
{
  return ((self->exec_block->flags & GUM_EXEC_BLOCK_USES_EXCLUSIVE_ACCESS) != 0)
      ? GUM_MEMORY_ACCESS_EXCLUSIVE
      : GUM_MEMORY_ACCESS_OPEN;
}

static void
gum_stalker_iterator_arm_keep (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  const cs_insn * insn = gc->instruction->ci;

  if (gum_arm_relocator_eob (gc->arm_relocator))
  {
    GumBranchTarget target;
    guint16 mask;
    cs_arm * arm = &insn->detail->arm;
    GumWriteback writeback = { .target = ARM_REG_INVALID };

    mask = 0;

    gum_stalker_get_target_address (insn, FALSE, &target, &mask);

    switch (insn->id)
    {
      case ARM_INS_LDR:
        gum_stalker_get_writeback (insn, &writeback);
        /* Deliberate fall-through */
      case ARM_INS_SUB:
      case ARM_INS_ADD:
      case ARM_INS_B:
      case ARM_INS_BX:
        gum_exec_block_virtualize_arm_branch_insn (block, &target, arm->cc,
            &writeback, gc);
        break;
      case ARM_INS_BL:
      case ARM_INS_BLX:
        gum_exec_block_virtualize_arm_call_insn (block, &target, arm->cc, gc);
        break;
      case ARM_INS_MOV:
        gum_exec_block_virtualize_arm_ret_insn (block, &target, arm->cc, FALSE,
            0, gc);
        break;
      case ARM_INS_POP:
      case ARM_INS_LDM:
        gum_exec_block_virtualize_arm_ret_insn (block, &target, arm->cc, TRUE,
            mask, gc);
        break;
      case ARM_INS_SMC:
      case ARM_INS_HVC:
        gum_panic ("not implemented");
        break;
      default:
        g_assert_not_reached ();
        break;
    }
  }
  else if (insn->id == ARM_INS_SVC)
  {
    gum_exec_block_virtualize_arm_svc_insn (block, gc);
  }
  else
  {
    gum_exec_block_dont_virtualize_arm_insn (block, gc);
  }
}

static void
gum_stalker_iterator_thumb_keep (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  const cs_insn * insn = gc->instruction->ci;

  if (gum_thumb_relocator_eob (gc->thumb_relocator))
    gum_stalker_iterator_handle_thumb_branch_insn (self, insn);
  else if (insn->id == ARM_INS_SVC)
    gum_exec_block_virtualize_thumb_svc_insn (block, gc);
  else
    gum_exec_block_dont_virtualize_thumb_insn (block, gc);
}

static void
gum_stalker_iterator_handle_thumb_branch_insn (GumStalkerIterator * self,
                                               const cs_insn * insn)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  cs_arm * arm = &insn->detail->arm;
  GumBranchTarget target;
  guint16 mask;
  GumWriteback writeback = { .target = ARM_REG_INVALID };

  switch (insn->id)
  {
    case ARM_INS_LDR:
      gum_stalker_get_writeback (insn, &writeback);
      /* Deliberate fall-through */
    case ARM_INS_B:
    case ARM_INS_BX:
    case ARM_INS_TBB:
    case ARM_INS_TBH:
      gum_stalker_get_target_address (insn, TRUE, &target, &mask);
      gum_exec_block_virtualize_thumb_branch_insn (block, &target, arm->cc,
          ARM_REG_INVALID, &writeback, gc);
      break;
    case ARM_INS_CBZ:
      g_assert (arm->operands[0].type == ARM_OP_REG);
      gum_stalker_get_target_address (insn, TRUE, &target, &mask);
      gum_exec_block_virtualize_thumb_branch_insn (block, &target, ARM_CC_EQ,
          arm->operands[0].reg, &writeback, gc);
      break;
    case ARM_INS_CBNZ:
      g_assert (arm->operands[0].type == ARM_OP_REG);
      gum_stalker_get_target_address (insn, TRUE, &target, &mask);
      gum_exec_block_virtualize_thumb_branch_insn (block, &target, ARM_CC_NE,
          arm->operands[0].reg, &writeback, gc);
      break;
    case ARM_INS_BL:
    case ARM_INS_BLX:
      gum_stalker_get_target_address (insn, TRUE, &target, &mask);
      gum_exec_block_virtualize_thumb_call_insn (block, &target, gc);
      break;
    case ARM_INS_MOV:
      gum_stalker_get_target_address (insn, TRUE, &target, &mask);
      gum_exec_block_virtualize_thumb_ret_insn (block, &target, FALSE, 0, gc);
      gum_thumb_relocator_skip_one (gc->thumb_relocator);
      break;
    case ARM_INS_POP:
    case ARM_INS_LDM:
      gum_stalker_get_target_address (insn, TRUE, &target, &mask);
      gum_exec_block_virtualize_thumb_ret_insn (block, &target, TRUE, mask, gc);
      gum_thumb_relocator_skip_one (gc->thumb_relocator);
      break;
    case ARM_INS_SMC:
    case ARM_INS_HVC:
      gum_panic ("Unsupported");
      break;
    case ARM_INS_IT:
      gum_stalker_iterator_handle_thumb_it_insn (self);
      break;
    default:
      g_assert_not_reached ();
      break;
  }
}

static void
gum_stalker_iterator_handle_thumb_it_insn (GumStalkerIterator * self)
{
  GumExecBlock * block = self->exec_block;
  GumGeneratorContext * gc = self->generator_context;
  GumThumbRelocator * rl = gc->thumb_relocator;
  const cs_insn * insn;

  /*
   * This function needs only to handle IT blocks which terminate with a branch
   * instruction. Those which contain no branches will not set the EOB condition
   * when read by the relocator and will be handled without the need for
   * virtualization. The block will simply be processed as usual by the
   * relocator.
   */

  /*
   * We emit a single EXEC event for an IT block. Execution of a final branch
   * instruction contained within it can result in additional events being
   * generated. We cannot emit one event for each instruction that is contained
   * within the IT block since they are re-ordered by the relocator. This is
   * necessary since the original IT block must be replaced with branches and
   * labels as individual instructions may need to be replaced by multiple
   * instructions as a result of relocation.
   */
  if ((block->ctx->sink_mask & GUM_EXEC) != 0)
  {
    gum_exec_block_thumb_open_prolog (block, gc);
    gum_exec_block_write_thumb_exec_event_code (block, gc);
    gum_exec_block_thumb_close_prolog (block, gc);
  }

  for (insn = gum_thumb_relocator_peek_next_write_insn (rl);
      insn != NULL;
      insn = gum_thumb_relocator_peek_next_write_insn (rl))
  {
    if (gum_thumb_relocator_is_eob_instruction (insn))
    {
      /*
       * Remove unnecessary conditional execution of the instruction since it is
       * wrapped within a series of branches by the relocator to handle the
       * if/then/else conditional execution.
       */
      insn->detail->arm.cc = ARM_CC_AL;
      gum_stalker_iterator_handle_thumb_branch_insn (self, insn);
    }
    else
    {
      gboolean preserve_flags;

      switch (insn->id)
      {
        case ARM_INS_CMN:
        case ARM_INS_CMP:
        case ARM_INS_TST:
          preserve_flags = FALSE;
          break;
        default:
          preserve_flags = TRUE;
          break;
      }

      /*
       * If the instruction in the IT block is not a branch, then just emit the
       * relocated instruction as normal. We must preserve the flags in the CPSR
       * unless we are executing a CMN, CMP or TST instruction:
       *
       * https://developer.arm.com/documentation/dui0489/c/
       *     arm-and-thumb-instructions/branch-and-control-instructions/it
       */

      if (preserve_flags)
      {
        gum_exec_block_thumb_open_prolog (block, gc);

        gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
            GUM_ADDRESS (gum_stalker_save_cpsr), 2,
            GUM_ARG_REGISTER, ARM_REG_R10,
            GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx));

        gum_exec_block_thumb_close_prolog (block, gc);
      }

      gum_thumb_relocator_write_one (gc->thumb_relocator);

      if (preserve_flags)
      {
        gum_exec_block_thumb_open_prolog (block, gc);

        gum_thumb_writer_put_call_address_with_arguments (gc->thumb_writer,
            GUM_ADDRESS (gum_stalker_restore_cpsr), 2,
            GUM_ARG_REGISTER, ARM_REG_R10,
            GUM_ARG_ADDRESS, GUM_ADDRESS (block->ctx));

        gum_exec_block_thumb_close_prolog (block, gc);
      }
    }
  }

  /*
   * Should we reach the end of the IT block (e.g. we did not take the branch)
   * we write code here to continue with the next instruction after the IT block
   * just as we do following a branch or call instruction. (We do this for
   * branches too as we cannot detect tail-calls and we can't be sure the callee
   * won't return). This results in the continuation code being written twice,
   * which is not strictly necessary. However, attempting to optimize this is
   * likely to be quite tricky.
   */
  gum_exec_block_thumb_open_prolog (block, gc);
  gum_exec_block_write_thumb_handle_continue (block, gc);
}

static void
gum_stalker_save_cpsr (GumCpuContext * cpu_context,
                       GumExecCtx * ctx)
{
  ctx->cpsr = cpu_context->cpsr;
}

static void
gum_stalker_restore_cpsr (GumCpuContext * cpu_context,
                          GumExecCtx * ctx)
{
  cpu_context->cpsr = ctx->cpsr;
}

static void
gum_stalker_get_target_address (const cs_insn * insn,
                                gboolean thumb,
                                GumBranchTarget * target,
                                guint16 * mask)
{
  cs_arm * arm = &insn->detail->arm;
  cs_arm_op * op1 = &arm->operands[0];

  /*
   * The complex nature of the ARM32 instruction set means that determining the
   * target address for an instruction which affects control flow is also
   * complex.
   *
   * Instructions such as 'BL label' will make use of the absolute_address
   * field. 'BL reg' and 'BLX' reg will make use of the reg field. 'LDR pc,
   * [reg]' however makes use of the reg field and sets is_indirect to TRUE.
   * This means that the reg field doesn't contain the target itself, but the
   * address in memory where the target is stored. 'LDR pc, [reg, #x]'
   * additionally sets the offset field which needs to be added to the register
   * before it is dereferenced.
   *
   * The POP and LDM instructions both read multiple values from where a base
   * register points, and store them into a listed set of registers. In the case
   * of the POP instruction, this base register is always SP, i.e. the stack
   * pointer. Again the is_indirect field is set and the value of the offset
   * field is determined by how many registers are included in the register list
   * before PC.
   *
   * Finally, ADD and SUB instructions can be used to modify control flow. ADD
   * instructions have two main forms. Firstly 'ADD pc, reg, #x', in this case
   * the reg and offset fields are both set accordingly. Secondly, if the form
   * 'ADD pc, reg, reg2' is used, then the values of reg and reg2 are set
   * accordingly. This form has the additional complexity of allowing a suffix
   * which can describe a shift operation (one of 4 types) and a value
   * indicating how many places to shift to be applied to reg2 before it is
   * added. This information is encoded in the shifter and shift_value fields
   * accordingly. Lastly the SUB instruction is identical to ADD except the
   * offset is negative, to indicate that reg2 should be subtracted rather than
   * added.
   *
   * This complex target field is processed by write_$mode_mov_branch_target()
   * in order to write instructions into the instrumented block to recover the
   * target address from these different forms of instruction.
   *
   * Lastly, we should note that many of these instructions can be conditionally
   * executed depending on the status of processor flags. For example, BLEQ will
   * only take affect if the previous instruction which set the flags indicated
   * the result of the operation was equal.
   */

  /*
   * The mask is used when POP or LDMIA instructions are encountered. This is
   * used to encode the other registers which are included in the operation.
   * Note, however, that the register PC is omitted from this mask.
   *
   * This is processed by virtualize_ret_insn() so that after the epilogue has
   * been executed and the application registers are restored. A replacement POP
   * or LDMIA instruction can be generated to restore the values of the other
   * registers from the stack. Note that we don't restore the value of PC from
   * the stack and instead simply increment the stack pointer since we instead
   * want to pass control back into Stalker to instrument the next block.
   */
  *mask = 0;

  switch (insn->id)
  {
    case ARM_INS_B:
    case ARM_INS_BL:
    {
      GumBranchDirectAddress * value = &target->value.direct_address;

      g_assert (op1->type == ARM_OP_IMM);

      target->type = GUM_TARGET_DIRECT_ADDRESS;

      /*
       * If the case of the B and BL instructions, the instruction mode never
       * changes from ARM to Thumb or vice-versa and hence the low bit of the
       * target address should be retained.
       */
      if (thumb)
        value->address = GSIZE_TO_POINTER (op1->imm + 1);
      else
        value->address = GSIZE_TO_POINTER (op1->imm);

      break;
    }
    case ARM_INS_BX:
    case ARM_INS_BLX:
    {
      if (op1->type == ARM_OP_REG)
      {
        GumBranchDirectRegOffset * value = &target->value.direct_reg_offset;

        target->type = GUM_TARGET_DIRECT_REG_OFFSET;

        value->reg = op1->reg;
        value->offset = 0;
        value->mode = GUM_ARM_MODE_AUTO;
      }
      else
      {
        GumBranchDirectAddress * value = &target->value.direct_address;

        target->type = GUM_TARGET_DIRECT_ADDRESS;

        /*
         * In the case of the BX and BLX instructions, the instruction mode
         * always changes from ARM to Thumb or vice-versa and hence the low
         * bit of the target address should be inverted.
         */
        if (thumb)
          value->address = GSIZE_TO_POINTER (op1->imm);
        else
          value->address = GSIZE_TO_POINTER (op1->imm) + 1;
      }

      break;
    }
    case ARM_INS_CBZ:
    case ARM_INS_CBNZ:
    {
      GumBranchDirectAddress * value = &target->value.direct_address;
      cs_arm_op * op2 = &arm->operands[1];

      /*
       * If the case of the CBZ and CBNZ instructions, the instruction mode
       * never changes and hence the low bit of the target address should be
       * retained. These are only supported in Thumb mode.
       */
      g_assert (thumb);

      target->type = GUM_TARGET_DIRECT_ADDRESS;

      value->address = GSIZE_TO_POINTER (op2->imm + 1);

      break;
    }
    case ARM_INS_POP:
    {
      GumBranchIndirectRegOffset * value = &target->value.indirect_reg_offset;
      guint8 i;

      target->type = GUM_TARGET_INDIRECT_REG_OFFSET;

      value->reg = ARM_REG_SP;
      value->offset = 0;
      value->write_back = TRUE;

      for (i = 0; i != insn->detail->arm.op_count; i++)
      {
        cs_arm_op * op = &arm->operands[i];

        if (op->reg == ARM_REG_PC)
        {
          value->offset = i * 4;
        }
        else
        {
          GumArmRegInfo ri;
          gum_arm_reg_describe (op->reg, &ri);
          *mask |= 1 << ri.index;
        }
      }

      break;
    }
    case ARM_INS_LDM:
    {
      GumBranchIndirectRegOffset * value = &target->value.indirect_reg_offset;
      guint8 i;

      target->type = GUM_TARGET_INDIRECT_REG_OFFSET;

      value->reg = op1->reg;
      value->offset = 0;
      value->write_back = insn->detail->arm.writeback;

      for (i = 1; i != insn->detail->arm.op_count; i++)
      {
        cs_arm_op * op = &arm->operands[i];

        if (op->reg == ARM_REG_PC)
        {
          value->offset = (i - 1) * 4;
        }
        else
        {
          GumArmRegInfo ri;
          gum_arm_reg_describe (op->reg, &ri);
          *mask |= 1 << ri.index;
        }
      }

      break;
    }
    case ARM_INS_LDR:
    {
      cs_arm_op * op2 = &arm->operands[1];
      g_assert (op2->type == ARM_OP_MEM);

      if (op2->shift.value == 0)
      {
        GumBranchIndirectRegOffset * value = &target->value.indirect_reg_offset;

        target->type = GUM_TARGET_INDIRECT_REG_OFFSET;

        value->reg = op2->mem.base;
        g_assert (op2->mem.index == ARM_REG_INVALID);
        value->offset = op2->mem.disp;
        value->write_back = FALSE;
      }
      else
      {
        GumBranchIndirectRegShift * value = &target->value.indirect_reg_shift;

        target->type = GUM_TARGET_INDIRECT_REG_SHIFT;

        value->base = op2->mem.base;
        value->index = op2->mem.index;
        value->shifter = op2->shift.type;
        value->shift_value = op2->shift.value;
      }

      break;
    }
    case ARM_INS_MOV:
    {
      GumBranchDirectRegOffset * value = &target->value.direct_reg_offset;

      cs_arm_op * op2 = &arm->operands[1];

      target->type = GUM_TARGET_DIRECT_REG_OFFSET;

      value->reg = op2->reg;
      value->offset = 0;
      value->mode = GUM_ARM_MODE_CURRENT;

      break;
    }
    case ARM_INS_ADD:
    case ARM_INS_SUB:
    {
      cs_arm_op * base = &arm->operands[1];
      cs_arm_op * index = &arm->operands[2];

      g_assert (base->type == ARM_OP_REG);

      if (index->type == ARM_OP_REG)
      {
        GumBranchDirectRegShift * value = &target->value.direct_reg_shift;

        target->type = GUM_TARGET_DIRECT_REG_SHIFT;

        value->base = base->reg;
        value->index = index->reg;
        value->shifter = index->shift.type;
        value->shift_value = index->shift.value;
      }
      else
      {
        GumBranchDirectRegOffset * value = &target->value.direct_reg_offset;

        target->type = GUM_TARGET_DIRECT_REG_OFFSET;

        value->reg = base->reg;
        value->offset = (insn->id == ARM_INS_SUB) ? -index->imm : index->imm;
        value->mode = GUM_ARM_MODE_CURRENT;
      }

      break;
    }
    case ARM_INS_TBB:
    case ARM_INS_TBH:
    {
      arm_op_mem * op = &arm->operands[0].mem;
      GumBranchIndirectPcrelTable * value = &target->value.indirect_pcrel_table;

      target->type = GUM_TARGET_INDIRECT_PCREL_TABLE;

      value->base = op->base;
      value->index = op->index;

      value->element_size = (insn->id == ARM_INS_TBB)
          ? sizeof (guint8)
          : sizeof (guint16);

      break;
    }
    default:
      g_assert_not_reached ();
  }
}

static void
gum_stalker_get_writeback (const cs_insn * insn,
                           GumWriteback * writeback)
{
  cs_arm * arm = &insn->detail->arm;
  cs_arm_op * op2 = &arm->operands[1];

  writeback->target = ARM_REG_INVALID;
  writeback->offset = 0;

  if (!arm->writeback)
    return;

  if (insn->id != ARM_INS_LDR)
    gum_panic ("Writeback for unexpected op-code: %d", insn->id);

  if (op2->type != ARM_OP_MEM)
    gum_panic ("Writeback for unexpected operand");

  if (op2->mem.index != ARM_REG_INVALID)
    gum_panic ("Writeback for register operands not supported");

  writeback->target = op2->mem.base;

  switch (arm->op_count)
  {
    case 2: /* pre-increment/decrement */
    {
      writeback->offset = op2->mem.disp;
      break;
    }
    case 3: /* post-increment/decrement */
    {
      cs_arm_op * op3 = &arm->operands[2];

      g_assert (op3->type == ARM_OP_IMM);

      writeback->offset = op3->subtracted ? -op3->imm : op3->imm;

      break;
    }
    default:
    {
      g_assert_not_reached ();
    }
  }
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
  call->depth = ctx->first_frame - ctx->current_frame;

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
  ret->depth = ctx->first_frame - ctx->current_frame;

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

  /*
   * Suppress generation of multiple EXEC events for IT blocks. An exec event
   * is already generated for the IT block, but a subsequent one may be
   * generated by the handling of a virtualized branch instruction if it is
   * taken. We simply ignore the request if the location is the same as the
   * previously emitted event.
   */
  if (location == ctx->last_exec_location)
    return;

  ctx->last_exec_location = location;

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

  bev->start = gum_exec_block_encode_instruction_pointer (block,
      block->real_start);
  bev->end = gum_exec_block_encode_instruction_pointer (block,
      block->real_start + block->real_size);

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
  GumCalloutEntry entry, * live_entry;
  GumAddress entry_address;

  entry.callout = callout;
  entry.data = data;
  entry.data_destroy = data_destroy;
  entry.pc = gc->instruction->start;
  entry.exec_context = self->exec_context;
  entry.next = NULL;

  if (gc->is_thumb)
  {
    GumThumbWriter * cw = gc->thumb_writer;

    live_entry = gum_exec_block_write_thumb_inline_data (cw, &entry,
        sizeof (entry), &entry_address);

    gum_exec_block_thumb_open_prolog (block, gc);
    gum_thumb_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_stalker_invoke_callout), 2,
        GUM_ARG_ADDRESS, entry_address,
        GUM_ARG_REGISTER, ARM_REG_R10);
    gum_exec_block_thumb_close_prolog (block, gc);
  }
  else
  {
    GumArmWriter * cw = gc->arm_writer;

    live_entry = gum_exec_block_write_arm_inline_data (cw, &entry,
        sizeof (entry), &entry_address);

    gum_exec_block_arm_open_prolog (block, gc);
    gum_arm_writer_put_call_address_with_arguments (cw,
        GUM_ADDRESS (gum_stalker_invoke_callout), 2,
        GUM_ARG_ADDRESS, entry_address,
        GUM_ARG_REGISTER, ARM_REG_R10);
    gum_exec_block_arm_close_prolog (block, gc);
  }

  live_entry->next = gum_exec_block_get_last_callout_entry (block);
  gum_exec_block_set_last_callout_entry (block,
      GSIZE_TO_POINTER (entry_address));
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
   GumBranchTarget target;
   GumBranchDirectRegOffset * value;

   target.type = GUM_TARGET_DIRECT_REG_OFFSET;
   value = &target.value.direct_reg_offset;
   value->reg = ARM_REG_LR;
   value->offset = 0;
   value->mode = GUM_ARM_MODE_CURRENT;

  if (gc->is_thumb)
  {
    gum_exec_block_virtualize_thumb_ret_insn (block, &target, FALSE, 0, gc);
  }
  else
  {
    gum_exec_block_virtualize_arm_ret_insn (block, &target, ARM_CC_AL, FALSE, 0,
        gc);
  }
}

csh
gum_stalker_iterator_get_capstone (GumStalkerIterator * self)
{
  const GumGeneratorContext * g
```