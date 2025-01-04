Response:
The user wants to understand the functionality of the provided C code snippet, which is part of the Frida dynamic instrumentation tool. The code is specifically located within the `stalker-x86.c` file, suggesting it's related to the Stalker component on the x86 architecture.

Here's a breakdown of the thought process to address the user's request:

1. **Identify the Core Functionality:** The code consists of several `TESTCASE` functions. This immediately indicates that it's a unit test file. Each `TESTCASE` likely examines a specific scenario or feature of the Frida Stalker.

2. **Analyze Individual Test Cases:**  Go through each `TESTCASE` and understand its purpose. Look for keywords like `unfollow`, `invalidate`, `follow`, `call`, `jump`, etc., as these hint at the functionality being tested.

3. **Connect to Frida Stalker Concepts:**  Relate the test cases to the core concepts of Frida Stalker:
    * **Stalking:**  The ability to trace the execution of code.
    * **Following/Unfollowing:**  Starting and stopping the tracing of code execution.
    * **Transformers:** Modifying the code being traced.
    * **Callouts:** Executing custom code during tracing.
    * **Invalidation:**  Forcing the Stalker to re-examine code, useful when code changes dynamically.
    * **Event Sink:**  Receiving notifications about traced events.
    * **Instruction Types:**  Handling different types of instructions like jumps and calls.

4. **Identify Relationships to Reverse Engineering:**  Consider how these Stalker features are relevant to reverse engineering:
    * Tracing execution flow is fundamental to understanding how software works.
    * Modifying code on-the-fly can help bypass security measures or change program behavior.
    * Observing calls and jumps provides insight into program structure.

5. **Pinpoint Binary/Kernel/Android Relevance:** Look for aspects that touch on lower-level details:
    * **CPU Context (`GumCpuContext`):** Accessing and modifying CPU registers.
    * **Instruction Pointers:**  Working with memory addresses.
    * **Thread IDs:**  Dealing with multi-threaded applications.
    * **Code Generation (`GumX86Writer`):**  Dynamically creating and modifying machine code.
    * **Memory Management (`gum_alloc_n_pages_near`, `gum_free_pages`, `gum_mprotect`):** Interacting with the operating system's memory management.

6. **Infer Logic and Provide Examples:** For test cases that involve conditional behavior or specific inputs, provide hypothetical examples:
    * **`unfollow_during_transform`:**  The `max_instructions` variable controls when unfollowing happens.
    * **`modify_to_return_true_after_three_calls`:** The `n` counter tracks the number of calls.
    * **Jump instructions:** The conditional jumps have different execution paths based on the input (`arg`).

7. **Identify Potential User Errors:**  Think about how a user might misuse the API:
    * Incorrectly managing the follow/unfollow lifecycle.
    * Providing invalid memory addresses.
    * Errors in the transformer logic.

8. **Trace User Steps to Reach the Code:**  Consider the general workflow of using Frida and how a developer would interact with the Stalker:
    * Attaching to a process.
    * Creating a Stalker instance.
    * Defining a transformer.
    * Calling `follow_me` or `follow`.

9. **Summarize the Functionality:**  Condense the findings into a concise summary of what the code does.

10. **Address the "Part 2" Instruction:** Since this is part 2 of a 4-part series, focus on summarizing the functionality covered *in this specific snippet*. Avoid rehashing information from previous parts or anticipating future content.

**Self-Correction/Refinement:**

* **Initial thought:** Focus heavily on the internal workings of the Stalker.
* **Correction:**  Realize the user needs a higher-level understanding of *what* the code is testing, not necessarily *how* the Stalker implements it.
* **Initial thought:** Provide very detailed explanations of each function.
* **Correction:**  Keep the explanations concise and focus on the overall purpose of each test case.
* **Initial thought:**  Assume the user has deep knowledge of Frida internals.
* **Correction:** Explain concepts in a way that is accessible to someone familiar with reverse engineering but perhaps not a Frida expert.

By following this thought process, the generated answer addresses all the user's requirements in a structured and informative way.
这是 frida 动态 Instrumentation 工具源代码文件 `frida/subprojects/frida-gum/tests/core/arch-x86/stalker-x86.c` 的第二部分，主要包含了一系列针对 Stalker 组件在 x86 架构下的功能测试用例。Stalker 是 Frida 的一个核心组件，负责追踪程序执行流并允许用户在执行过程中插入自定义代码。

**归纳一下它的功能:**

这部分代码主要测试了 Frida Stalker 的以下功能：

* **灵活的取消追踪 (Unfollow) 机制:**  测试了在 Stalker 转换代码块的不同阶段（转换前、转换中、转换后）取消追踪的可能性和正确性。这允许用户更精细地控制 Stalker 的行为，只在感兴趣的代码区域进行追踪。
* **支持空事件接收器:** 验证了 `gum_stalker_follow_me` 函数在不提供事件接收器的情况下也能正常工作。
* **基于调用次数的代码失效 (Invalidation):**  测试了在特定函数被调用一定次数后，使该函数的 Stalker 缓存失效的能力。这对于处理自修改代码或需要重新分析的场景非常重要。
* **针对特定线程的代码失效:**  验证了可以只针对特定线程使 Stalker 缓存失效，这在多线程环境中非常有用，可以避免影响其他线程的追踪。
* **代码失效允许代码块增长:**  测试了当 Stalker 缓存失效后，如果目标函数的代码大小发生变化（增长），Stalker 能够正确处理并继续追踪。
* **各种跳转指令的处理:**  详细测试了 Stalker 对不同类型的跳转指令（无条件跳转、短条件跳转、长条件跳转、基于计数器的条件跳转 `jcxz`）的追踪能力，包括跳转成立和不成立的情况。
* **函数调用和返回的追踪:**  测试了 Stalker 对 `call` 和 `ret` 指令的追踪，包括 `stdcall` 调用约定和带有 `repne` 前缀的 `ret` 指令。
* **深度取消追踪:**  验证了在多层函数调用中正确取消追踪的能力。
* **处理紧随 `call` 指令后的无用数据:** 测试了 Stalker 是否能正确处理 `call` 指令后跟随的非指令数据的情况。
* **间接调用的追踪:**  详细测试了 Stalker 对各种形式的间接调用指令的追踪，包括通过立即数寻址和寄存器寻址的间接调用，以及在目标地址存在偏移量的情况。

**与逆向方法的关系举例说明:**

* **追踪执行流:** Stalker 的核心功能就是追踪程序的执行流。逆向工程师可以使用 Stalker 来观察程序是如何一步步执行的，从而理解程序的逻辑。例如，通过观察跳转指令的执行，可以了解程序的控制流走向。
* **动态修改代码:**  虽然这部分代码没有直接展示修改代码，但 Stalker 的设计允许用户通过 Transformer 回调函数在执行过程中修改代码。这在逆向分析中非常有用，例如，可以跳过特定的函数调用、修改函数返回值，或者插入额外的日志代码。
* **定位关键函数:**  通过追踪 `call` 指令，逆向工程师可以快速定位程序调用的函数，这对于理解程序的功能模块划分非常有帮助。例如，可以追踪某个按钮点击事件最终调用了哪些函数。
* **分析恶意代码:**  Stalker 可以用来分析恶意代码的行为，例如，追踪恶意代码的网络请求、文件操作等，从而了解其攻击方式。

**涉及到二进制底层、Linux、Android 内核及框架的知识举例说明:**

* **二进制指令:** 代码中直接操作二进制指令，例如 `0x33, 0xc0` (xor eax, eax)，`0xc3` (ret)。这需要对 x86 汇编语言有深入的了解。
* **内存地址:** 代码中大量使用了内存地址，例如 `insn->address`，`GPOINTER_TO_SIZE`。这涉及到进程的内存布局和寻址方式。
* **CPU 上下文:**  `GumCpuContext` 结构体用于访问和修改 CPU 寄存器的值，例如 `GUM_CPU_CONTEXT_XAX (cpu_context) = 0xc001;`，这直接操作了底层的 CPU 状态。
* **线程 ID:**  测试用例中使用了线程相关的 API，例如 `gum_process_get_current_thread_id()`，`gum_stalker_follow`，`gum_stalker_unfollow`，`gum_stalker_invalidate_for_thread`，这涉及到操作系统提供的线程管理机制。
* **代码段标记:**  `gum_memory_mark_code` 函数用于将内存区域标记为代码段，这与操作系统的内存保护机制有关。
* **页分配:** `gum_alloc_n_pages_near` 函数用于在指定地址附近分配内存页，这涉及到操作系统底层的内存管理。
* **内存保护:** `gum_mprotect` 函数用于修改内存页的保护属性（例如，设置为可读可写可执行），这涉及到操作系统的内存保护机制。
* **调用约定:**  测试用例中涉及到 `stdcall` 调用约定，这是一种在 Windows 系统中常见的函数调用方式。

**逻辑推理的假设输入与输出举例:**

以 `TESTCASE (short_conditional_jump_true)` 为例：

* **假设输入:**
    * 被追踪的代码段包含一个短条件跳转指令 `jz +5` (如果零标志位为真则跳转)。
    * 在执行到该跳转指令时，零标志位为真（例如，之前的 `cmp` 指令比较结果相等）。
    * Stalker 处于追踪执行事件的状态 (`GUM_EXEC`)。
* **预期输出:**
    * Stalker 会记录跳转前的指令执行事件。
    * 由于条件成立，Stalker 会记录跳转目标地址的指令执行事件。
    * Stalker 不会记录跳转指令之后、跳转目标之前的指令执行事件。
    * 最终的事件序列会反映正确的执行路径。

**涉及用户或者编程常见的使用错误举例说明:**

* **在不应该取消追踪的时候取消追踪:**  如果用户在 Stalker 还在处理某个代码块的时候就调用 `gum_stalker_unfollow_me`，可能会导致程序崩溃或出现未定义的行为。测试用例 `unfollow_should_be_allowed_before_first_transform` 等就是为了确保在各种取消追踪的时机下 Stalker 都能正常工作。
* **错误的内存地址:**  如果用户在 Transformer 回调函数中试图访问或修改无效的内存地址，会导致程序崩溃。
* **Transformer 回调函数中的逻辑错误:**  如果在 Transformer 回调函数中编写了错误的逻辑，可能会导致 Stalker 的行为不符合预期，例如，修改了错误的寄存器值或跳转到了错误的地址。
* **忘记取消追踪:**  如果在长时间的追踪过程中忘记调用 `gum_stalker_unfollow_me`，可能会导致性能下降，因为 Stalker 会持续记录执行事件。
* **在多线程环境中使用 Stalker 但没有正确处理线程同步:**  如果多个线程同时操作同一个 Stalker 实例，可能会导致数据竞争和未定义的行为。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 用户首先会编写一个 JavaScript 或 Python 的 Frida 脚本，用于 hook 目标进程。
2. **在脚本中使用 Stalker:**  在脚本中，用户会获取一个 `Stalker` 对象，并配置其行为，例如，设置 Transformer 回调函数、事件掩码等。
3. **调用 `Stalker.follow()` 或 `Stalker.followMe()`:**  用户会调用 `follow()` 方法来开始追踪特定线程的代码执行，或者调用 `followMe()` 来追踪当前脚本运行的线程。
4. **目标代码执行:** 当目标进程执行到被 Stalker 追踪的代码区域时，Stalker 会介入。
5. **Transformer 回调执行:** 如果用户设置了 Transformer，Stalker 会在执行目标代码之前调用 Transformer 回调函数，允许用户修改代码。
6. **事件发送:**  如果用户设置了事件接收器，Stalker 会将执行事件（例如，执行了哪些指令、调用了哪些函数）发送给接收器。
7. **用户分析事件:** 用户可以通过分析接收到的事件来理解目标程序的执行流程。
8. **调试 Stalker 本身:** 如果 Stalker 的行为不符合预期，Frida 的开发者或者高级用户可能会需要深入到 Stalker 的 C++ 源代码进行调试，而 `stalker-x86.c` 这样的测试文件就是他们理解 Stalker 内部工作原理的重要参考。他们可能会阅读这些测试用例，或者编写新的测试用例来复现和修复 bug。

总而言之，这部分代码是 Frida Stalker 组件在 x86 架构下的功能测试，它涵盖了 Stalker 的核心特性，并提供了丰富的测试用例来验证其正确性和健壮性。这些测试用例也能够帮助用户和开发者理解 Stalker 的工作原理和使用方法。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-x86/stalker-x86.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
   gpointer user_data)
{
  const guint8 * func_start = user_data;
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (insn->address == GPOINTER_TO_SIZE (func_start + 5))
    {
      gum_stalker_iterator_put_callout (iterator, callout_set_cool, NULL, NULL);
      gum_stalker_iterator_put_chaining_return (iterator);
      continue;
    }

    gum_stalker_iterator_keep (iterator);
  }
}

static void
callout_set_cool (GumCpuContext * cpu_context,
                  gpointer user_data)
{
  GUM_CPU_CONTEXT_XAX (cpu_context) = 0xc001;
}

TESTCASE (unfollow_should_be_allowed_before_first_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 0;
  ctx.max_instructions = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
}

TESTCASE (unfollow_should_be_allowed_mid_first_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 0;
  ctx.max_instructions = 1;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
}

TESTCASE (unfollow_should_be_allowed_after_first_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 0;
  ctx.max_instructions = -1;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
}

TESTCASE (unfollow_should_be_allowed_before_second_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 1;
  ctx.max_instructions = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
}

TESTCASE (unfollow_should_be_allowed_mid_second_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 1;
  ctx.max_instructions = 1;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
}

TESTCASE (unfollow_should_be_allowed_after_second_transform)
{
  UnfollowTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.num_blocks_transformed = 0;
  ctx.target_block = 1;
  ctx.max_instructions = -1;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      unfollow_during_transform, &ctx, NULL);

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 2);
}

static void
unfollow_during_transform (GumStalkerIterator * iterator,
                           GumStalkerOutput * output,
                           gpointer user_data)
{
  UnfollowTransformContext * ctx = user_data;
  const cs_insn * insn;

  if (ctx->num_blocks_transformed == ctx->target_block)
  {
    gint n;

    for (n = 0; n != ctx->max_instructions &&
        gum_stalker_iterator_next (iterator, &insn); n++)
    {
      gum_stalker_iterator_keep (iterator);
    }

    gum_stalker_unfollow_me (ctx->stalker);
  }
  else
  {
    while (gum_stalker_iterator_next (iterator, &insn))
      gum_stalker_iterator_keep (iterator);
  }

  ctx->num_blocks_transformed++;
}

TESTCASE (follow_me_should_support_nullable_event_sink)
{
  gpointer p;

  gum_stalker_follow_me (fixture->stalker, NULL, NULL);
  p = malloc (1);
  free (p);
  gum_stalker_unfollow_me (fixture->stalker);
}

static const guint8 test_is_finished_code[] = {
  0x33, 0xc0, /* xor eax, eax */
  0xc3,       /* ret          */
};

TESTCASE (invalidation_for_current_thread_should_be_supported)
{
  TestIsFinishedFunc test_is_finished;
  InvalidationTransformContext ctx;

  test_is_finished = GUM_POINTER_TO_FUNCPTR (TestIsFinishedFunc,
      test_stalker_fixture_dup_code (fixture, test_is_finished_code,
          sizeof (test_is_finished_code)));

  ctx.stalker = fixture->stalker;
  ctx.target_function = test_is_finished;
  ctx.n = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      modify_to_return_true_after_three_calls, &ctx, NULL);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer, NULL);

  while (!test_is_finished ())
  {
  }

  gum_stalker_unfollow_me (fixture->stalker);
}

static void
modify_to_return_true_after_three_calls (GumStalkerIterator * iterator,
                                         GumStalkerOutput * output,
                                         gpointer user_data)
{
  InvalidationTransformContext * ctx = user_data;
  guint i;
  const cs_insn * insn;
  gboolean in_target_function = FALSE;

  for (i = 0; gum_stalker_iterator_next (iterator, &insn); i++)
  {
    if (i == 0)
    {
      in_target_function =
          insn->address == GPOINTER_TO_SIZE (ctx->target_function);

      if (in_target_function && ctx->n == 0)
      {
        gum_stalker_iterator_put_callout (iterator,
            invalidate_after_three_calls, ctx, NULL);
      }
    }

    if (insn->id == X86_INS_RET && in_target_function && ctx->n == 3)
    {
      gum_x86_writer_put_mov_reg_u32 (output->writer.x86, GUM_X86_EAX, TRUE);
    }

    gum_stalker_iterator_keep (iterator);
  }
}

static void
invalidate_after_three_calls (GumCpuContext * cpu_context,
                              gpointer user_data)
{
  InvalidationTransformContext * ctx = user_data;

  if (++ctx->n == 3)
  {
    gum_stalker_invalidate (ctx->stalker, ctx->target_function);
  }
}

TESTCASE (invalidation_for_specific_thread_should_be_supported)
{
  TestIsFinishedFunc test_is_finished;
  InvalidationTarget a, b;

  test_is_finished = GUM_POINTER_TO_FUNCPTR (TestIsFinishedFunc,
      test_stalker_fixture_dup_code (fixture, test_is_finished_code,
          sizeof (test_is_finished_code)));

  start_invalidation_target (&a, test_is_finished, fixture);
  start_invalidation_target (&b, test_is_finished, fixture);

  gum_stalker_invalidate_for_thread (fixture->stalker, a.thread_id,
      test_is_finished);
  join_invalidation_target (&a);

  g_usleep (50000);
  g_assert_false (b.finished);

  gum_stalker_invalidate_for_thread (fixture->stalker, b.thread_id,
      test_is_finished);
  join_invalidation_target (&b);
  g_assert_true (b.finished);
}

static void
start_invalidation_target (InvalidationTarget * target,
                           gconstpointer target_function,
                           TestStalkerFixture * fixture)
{
  InvalidationTransformContext * ctx = &target->ctx;
  StalkerDummyChannel * channel = &target->channel;

  ctx->stalker = fixture->stalker;
  ctx->target_function = target_function;
  ctx->n = 0;

  target->transformer = gum_stalker_transformer_make_from_callback (
      modify_to_return_true_on_subsequent_transform, ctx, NULL);

  target->finished = FALSE;

  sdc_init (channel);

  target->thread = g_thread_new ("stalker-invalidation-target",
      run_stalked_until_finished, target);
  target->thread_id = sdc_await_thread_id (channel);

  gum_stalker_follow (ctx->stalker, target->thread_id, target->transformer,
      NULL);
  sdc_put_follow_confirmation (channel);

  sdc_await_run_confirmation (channel);
}

static void
join_invalidation_target (InvalidationTarget * target)
{
  GumStalker * stalker = target->ctx.stalker;

  g_thread_join (target->thread);

  gum_stalker_unfollow (stalker, target->thread_id);

  sdc_finalize (&target->channel);

  g_object_unref (target->transformer);
}

static gpointer
run_stalked_until_finished (gpointer data)
{
  InvalidationTarget * target = data;
  TestIsFinishedFunc test_is_finished =
      GUM_POINTER_TO_FUNCPTR (TestIsFinishedFunc, target->ctx.target_function);
  StalkerDummyChannel * channel = &target->channel;
  gboolean first_iteration;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  first_iteration = TRUE;

  while (!test_is_finished ())
  {
    if (first_iteration)
    {
      sdc_put_run_confirmation (channel);
      first_iteration = FALSE;
    }

    g_thread_yield ();
  }

  target->finished = TRUE;

  return NULL;
}

static void
modify_to_return_true_on_subsequent_transform (GumStalkerIterator * iterator,
                                               GumStalkerOutput * output,
                                               gpointer user_data)
{
  InvalidationTransformContext * ctx = user_data;
  guint i;
  const cs_insn * insn;
  gboolean in_target_function = FALSE;

  for (i = 0; gum_stalker_iterator_next (iterator, &insn); i++)
  {
    if (i == 0)
    {
      in_target_function =
          insn->address == GPOINTER_TO_SIZE (ctx->target_function);
      if (in_target_function)
        ctx->n++;
    }

    if (insn->id == X86_INS_RET && in_target_function && ctx->n > 1)
    {
      gum_x86_writer_put_mov_reg_u32 (output->writer.x86, GUM_X86_EAX, TRUE);
    }

    gum_stalker_iterator_keep (iterator);
  }
}

static const guint8 get_magic_number_code[] = {
  0xb8, 0x2a, 0x00, 0x00, 0x00, /* mov eax, 42 */
  0xc3,                         /* ret         */
};

TESTCASE (invalidation_should_allow_block_to_grow)
{
  GetMagicNumberFunc get_magic_number;
  InvalidationTransformContext ctx;

  get_magic_number = GUM_POINTER_TO_FUNCPTR (GetMagicNumberFunc,
      test_stalker_fixture_dup_code (fixture, get_magic_number_code,
          sizeof (get_magic_number_code)));

  ctx.stalker = fixture->stalker;
  ctx.target_function = get_magic_number;
  ctx.n = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      add_n_return_value_increments, &ctx, NULL);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer, NULL);

  g_assert_cmpint (get_magic_number (), ==, 42);

  ctx.n = 1;
  gum_stalker_invalidate (fixture->stalker, ctx.target_function);
  g_assert_cmpint (get_magic_number (), ==, 43);
  g_assert_cmpint (get_magic_number (), ==, 43);

  ctx.n = 2;
  gum_stalker_invalidate (fixture->stalker, ctx.target_function);
  g_assert_cmpint (get_magic_number (), ==, 44);

  gum_stalker_unfollow_me (fixture->stalker);
}

static void
add_n_return_value_increments (GumStalkerIterator * iterator,
                               GumStalkerOutput * output,
                               gpointer user_data)
{
  InvalidationTransformContext * ctx = user_data;
  guint i;
  const cs_insn * insn;
  gboolean in_target_function = FALSE;

  for (i = 0; gum_stalker_iterator_next (iterator, &insn); i++)
  {
    if (i == 0)
    {
      in_target_function =
          insn->address == GPOINTER_TO_SIZE (ctx->target_function);
    }

    if (insn->id == X86_INS_RET && in_target_function)
    {
      guint increment_index;

      for (increment_index = 0; increment_index != ctx->n; increment_index++)
      {
        gum_x86_writer_put_inc_reg (output->writer.x86, GUM_X86_EAX);
      }
    }

    gum_stalker_iterator_keep (iterator);
  }
}

TESTCASE (unconditional_jumps)
{
  invoke_jumpy (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 2);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 5);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, fixture->code + 7);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 4),
      ==, fixture->code + 14);
}

static StalkerTestFunc
invoke_short_condy (TestStalkerFixture * fixture,
                    GumEventType mask,
                    gint arg)
{
  const guint8 code[] = {
    0x83, 0xf9, 0x2a,             /* cmp ecx, 42    */
    0x74, 0x05,                   /* jz +5          */
    0xe9, 0x06, 0x00, 0x00, 0x00, /* jmp dword +6   */

    0xb8, 0x39, 0x05, 0x00, 0x00, /* mov eax, 1337  */
    0xc3,                         /* ret            */

    0xb8, 0xcb, 0x04, 0x00, 0x00, /* mov eax, 1227  */
    0xc3,                         /* ret            */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, arg);

  g_assert_cmpint (ret, ==, (arg == 42) ? 1337 : 1227);

  return func;
}

TESTCASE (short_conditional_jump_true)
{
  invoke_short_condy (fixture, GUM_EXEC, 42);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 4);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 3);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 10);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, fixture->code + 15);
}

TESTCASE (short_conditional_jump_false)
{
  invoke_short_condy (fixture, GUM_EXEC, 43);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 3);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 5);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, fixture->code + 16);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 4),
      ==, fixture->code + 21);
}

static StalkerTestFunc
invoke_short_jcxz (TestStalkerFixture * fixture,
                   GumEventType mask,
                   gint arg)
{
  const guint8 code[] = {
    0xe3, 0x05,                   /* jecxz/jrcxz +5 */
    0xe9, 0x06, 0x00, 0x00, 0x00, /* jmp dword +6   */

    0xb8, 0x39, 0x05, 0x00, 0x00, /* mov eax, 1337  */
    0xc3,                         /* ret            */

    0xb8, 0xcb, 0x04, 0x00, 0x00, /* mov eax, 1227  */
    0xc3,                         /* ret            */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, arg);

  g_assert_cmpint (ret, ==, (arg == 0) ? 1337 : 1227);

  return func;
}

TESTCASE (short_conditional_jcxz_true)
{
  invoke_short_jcxz (fixture, GUM_EXEC, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 3);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 7);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 12);
}

TESTCASE (short_conditional_jcxz_false)
{
  invoke_short_jcxz (fixture, GUM_EXEC, 0x11223344);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 4);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 0),
      ==, fixture->code + 0);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 1),
      ==, fixture->code + 2);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 2),
      ==, fixture->code + 13);
  GUM_ASSERT_CMPADDR (NTH_EXEC_EVENT_LOCATION (INVOKER_IMPL_OFFSET + 3),
      ==, fixture->code + 18);
}

static StalkerTestFunc
invoke_long_condy (TestStalkerFixture * fixture,
                   GumEventType mask,
                   gint arg)
{
  const guint8 code[] = {
    0xe9, 0x0c, 0x01, 0x00, 0x00,         /* jmp +268             */

    0xb8, 0x39, 0x05, 0x00, 0x00,         /* mov eax, 1337        */
    0xc3,                                 /* ret                  */

    0xb8, 0xcb, 0x04, 0x00, 0x00,         /* mov eax, 1227        */
    0xc3,                                 /* ret                  */

    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,
    0xcc, 0xcc, 0xcc, 0xcc, 0xcc, 0xcc,

    0x81, 0xc1, 0xff, 0xff, 0xff, 0xff,   /* add ecx, G_MAXUINT32 */
    0x0f, 0x83, 0xee, 0xfe, 0xff, 0xff,   /* jnc dword -274       */
    0xe9, 0xe3, 0xfe, 0xff, 0xff,         /* jmp dword -285       */
  };
  StalkerTestFunc func;
  gint ret;

  g_assert_true (arg == FALSE || arg == TRUE);

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, arg);

  g_assert_cmpint (ret, ==, (arg == TRUE) ? 1337 : 1227);

  return func;
}

TESTCASE (long_conditional_jump)
{
  invoke_long_condy (fixture, GUM_EXEC, TRUE);
  invoke_long_condy (fixture, GUM_EXEC, FALSE);
}

#if GLIB_SIZEOF_VOID_P == 4
# define FOLLOW_RETURN_EXTRA_INSN_COUNT 2
#elif GLIB_SIZEOF_VOID_P == 8
# if GUM_NATIVE_ABI_IS_WINDOWS
#  define FOLLOW_RETURN_EXTRA_INSN_COUNT 3
# else
#  define FOLLOW_RETURN_EXTRA_INSN_COUNT 1
# endif
#endif

TESTCASE (follow_return)
{
  fixture->sink->mask = GUM_EXEC;

  invoke_follow_return_code (fixture);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, 5 + FOLLOW_RETURN_EXTRA_INSN_COUNT);
}

static void
invoke_follow_return_code (TestStalkerFixture * fixture)
{
  GumAddressSpec spec;
  guint8 * code;
  GumX86Writer cw;
#if GLIB_SIZEOF_VOID_P == 4
  guint align_correction_follow = 12;
  guint align_correction_unfollow = 8;
#else
  guint align_correction_follow = 0;
  guint align_correction_unfollow = 8;
#endif
  const gchar * start_following_lbl = "start_following";
  GCallback invoke_func;

  spec.near_address = gum_stalker_follow_me;
  spec.max_distance = G_MAXINT32 / 2;

  code = gum_alloc_n_pages_near (1, GUM_PAGE_RW, &spec);

  gum_x86_writer_init (&cw, code);

  gum_x86_writer_put_call_near_label (&cw, start_following_lbl);
  gum_x86_writer_put_nop (&cw);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_X86_XSP, align_correction_unfollow);
  gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_X86_XSP, align_correction_unfollow);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, start_following_lbl);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_X86_XSP, align_correction_follow);
  gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_X86_XSP, align_correction_follow);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  gum_memory_mark_code (cw.base, gum_x86_writer_offset (&cw));
  gum_x86_writer_clear (&cw);

  invoke_func = GUM_POINTER_TO_FUNCPTR (GCallback, code);
  invoke_func ();

  gum_free_pages (code);
}

TESTCASE (follow_stdcall)
{
  const guint8 stdcall_code[] =
  {
    0x68, 0xef, 0xbe, 0x00, 0x00, /* push dword 0xbeef */
    0xe8, 0x02, 0x00, 0x00, 0x00, /* call func         */
    0xc3,                         /* ret               */
    0xcc,                         /* int3              */

  /* func: */
    0x8b, 0x44, 0x24,             /* mov eax, [esp+X]  */
          sizeof (gpointer),
    0xc2, sizeof (gpointer), 0x00 /* ret X             */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, stdcall_code,
          sizeof (stdcall_code)));

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);

  g_assert_cmpint (ret, ==, 0xbeef);
}

TESTCASE (follow_repne_ret)
{
  const guint8 repne_ret_code[] =
  {
    0xb8, 0xef, 0xbe, 0x00, 0x00, /* mov eax, 0xbeef     */
    0xf2, 0xc3,                   /* repne ret           */
    0xcc,                         /* int3                */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, repne_ret_code,
          sizeof (repne_ret_code)));

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 2);

  g_assert_cmpint (ret, ==, 0xbeef);
}

TESTCASE (follow_repne_jb)
{
  const guint8 repne_jb_code[] =
  {
    0x68, 0xef, 0xbe, 0x00, 0x00, /* push dword 0xbeef   */
    0xb8, 0xff, 0x00, 0x00, 0x00, /* mov eax, 0xff       */
    0xb9, 0xfe, 0x00, 0x00, 0x00, /* mov ecx, 0xfe       */
    0x3b, 0xc8,                   /* cmp ecx, eax        */
    0xf2, 0x72, 0x02,             /* repne jb short func */
    0xc3,                         /* ret                 */
    0xcc,                         /* int3                */

                                  /* func:               */
    0x58,                         /* pop eax             */
    0xc3,                         /* ret                 */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, repne_jb_code,
          sizeof (repne_jb_code)));

  g_assert_cmpint (func (0), ==, 0xbeef);

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 7);

  g_assert_cmpint (ret, ==, 0xbeef);
}

#if GLIB_SIZEOF_VOID_P == 4
#define UNFOLLOW_DEEP_EXTRA_INSN_COUNT 1
#elif GLIB_SIZEOF_VOID_P == 8
# if GUM_NATIVE_ABI_IS_WINDOWS
#  define UNFOLLOW_DEEP_EXTRA_INSN_COUNT 2
# else
#  define UNFOLLOW_DEEP_EXTRA_INSN_COUNT 0
# endif
#endif

TESTCASE (unfollow_deep)
{
  fixture->sink->mask = GUM_EXEC;

  invoke_unfollow_deep_code (fixture);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, 7 + UNFOLLOW_DEEP_EXTRA_INSN_COUNT);
}

static void
invoke_unfollow_deep_code (TestStalkerFixture * fixture)
{
  GumAddressSpec spec;
  guint8 * code;
  GumX86Writer cw;
#if GLIB_SIZEOF_VOID_P == 4
  guint align_correction_follow = 0;
  guint align_correction_unfollow = 12;
#else
  guint align_correction_follow = 8;
  guint align_correction_unfollow = 0;
#endif
  const gchar * func_a_lbl = "func_a";
  const gchar * func_b_lbl = "func_b";
  const gchar * func_c_lbl = "func_c";
  GCallback invoke_func;

  spec.near_address = gum_stalker_follow_me;
  spec.max_distance = G_MAXINT32 / 2;

  code = gum_alloc_n_pages_near (1, GUM_PAGE_RW, &spec);

  gum_x86_writer_init (&cw, code);

  gum_x86_writer_put_sub_reg_imm (&cw, GUM_X86_XSP, align_correction_follow);
  gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_X86_XSP, align_correction_follow);
  gum_x86_writer_put_call_near_label (&cw, func_a_lbl);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, func_a_lbl);
  gum_x86_writer_put_call_near_label (&cw, func_b_lbl);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, func_b_lbl);
  gum_x86_writer_put_call_near_label (&cw, func_c_lbl);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_put_label (&cw, func_c_lbl);
  gum_x86_writer_put_sub_reg_imm (&cw, GUM_X86_XSP, align_correction_unfollow);
  gum_x86_writer_put_call_address_with_arguments (&cw, GUM_CALL_CAPI,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_x86_writer_put_add_reg_imm (&cw, GUM_X86_XSP, align_correction_unfollow);
  gum_x86_writer_put_ret (&cw);

  gum_x86_writer_flush (&cw);
  gum_memory_mark_code (cw.base, gum_x86_writer_offset (&cw));
  gum_x86_writer_clear (&cw);

  invoke_func = GUM_POINTER_TO_FUNCPTR (GCallback, code);
  invoke_func ();

  gum_free_pages (code);
}

TESTCASE (call_followed_by_junk)
{
  const guint8 code[] =
  {
    0xe8, 0x05, 0x00, 0x00, 0x00, /* call func         */
    0xff, 0xff, 0xff, 0xff, 0xff, /* <junk>            */
    0x58,                         /* pop eax           */
    0x68, 0xef, 0xbe, 0x00, 0x00, /* push dword 0xbeef */
    0x58,                         /* pop eax           */
    0xc3                          /* ret               */
  };
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len,
      ==, INVOKER_INSN_COUNT + 5);

  g_assert_cmpint (ret, ==, 0xbeef);
}

typedef struct _CallTemplate CallTemplate;

struct _CallTemplate
{
  const guint8 * code_template;
  guint code_size;
  guint call_site_offset;
  guint target_mov_offset;
  guint target_address_offset;
  gboolean target_address_offset_points_directly_to_function;
  guint target_func_offset;
  gint target_func_immediate_fixup;
  guint instruction_count;
  guint ia32_padding_instruction_count;
  gboolean enable_probe;
};

static void probe_template_func_invocation (GumCallDetails * details,
    gpointer user_data);

static StalkerTestFunc
invoke_call_from_template (TestStalkerFixture * fixture,
                           const CallTemplate * call_template)
{
  guint8 * code;
  StalkerTestFunc func;
  gpointer target_func_address;
  gsize target_actual_address;
  guint expected_insn_count;
  gint ret;
  GumProbeId probe_id;

  code = test_stalker_fixture_dup_code (fixture,
      call_template->code_template, call_template->code_size);
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, code);

  gum_mprotect (code, call_template->code_size, GUM_PAGE_RW);

  target_func_address = code + call_template->target_func_offset;
  if (call_template->target_address_offset_points_directly_to_function)
    target_actual_address = GPOINTER_TO_SIZE (target_func_address);
  else
    target_actual_address = GPOINTER_TO_SIZE (&target_func_address);
  *((gsize *) (code + call_template->target_address_offset)) =
      target_actual_address + call_template->target_func_immediate_fixup;

#if GLIB_SIZEOF_VOID_P == 8
  if (call_template->target_mov_offset != 0)
    *(code + call_template->target_mov_offset - 1) = 0x48;
#endif

  gum_memory_mark_code (code, call_template->code_size);

  expected_insn_count = INVOKER_INSN_COUNT + call_template->instruction_count;
#if GLIB_SIZEOF_VOID_P == 4
  expected_insn_count += call_template->ia32_padding_instruction_count;
#endif

  fixture->sink->mask = GUM_EXEC;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, ==, 1337);
  g_assert_cmpuint (fixture->sink->events->len, ==, expected_insn_count);

  gum_fake_event_sink_reset (fixture->sink);

  fixture->sink->mask = GUM_CALL;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, ==, 1337);
  g_assert_cmpuint (fixture->sink->events->len, ==, 2 + 1);
  GUM_ASSERT_CMPADDR (NTH_EVENT_AS_CALL (1)->location,
      ==, code + call_template->call_site_offset);
  GUM_ASSERT_CMPADDR (NTH_EVENT_AS_CALL (1)->target,
      ==, code + call_template->target_func_offset);

  probe_id = gum_stalker_add_call_probe (fixture->stalker, target_func_address,
      probe_template_func_invocation, NULL, NULL);
  fixture->sink->mask = GUM_NOTHING;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpint (ret, == , 1337);
  gum_stalker_remove_call_probe (fixture->stalker, probe_id);

  return func;
}

static void
probe_template_func_invocation (GumCallDetails * details,
                                gpointer user_data)
{
}

TESTCASE (indirect_call_with_immediate)
{
  const guint8 code[] = {
    0xeb, 0x08,                         /* jmp +8          */

    0x00, 0x00, 0x00, 0x00,             /* address padding */
    0x00, 0x00, 0x00, 0x00,

    0xff, 0x15, 0xf2, 0xff, 0xff, 0xff, /* call            */
    0xc3,                               /* ret             */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337   */
    0xc3,                               /* ret             */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_address_offset = 12;
  call_template.target_func_offset = 17;
  call_template.instruction_count = 5;

#if GLIB_SIZEOF_VOID_P == 8
  call_template.target_address_offset -= 10;
  call_template.target_address_offset_points_directly_to_function = TRUE;
#endif

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (indirect_call_with_register_and_no_immediate)
{
  const guint8 code[] = {
    0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X           */
                0x90, 0x90, 0x90, 0x90,
    0xff, 0x10,                         /* call [xax]           */
    0xc3,                               /* ret                  */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
    0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 13;
  call_template.instruction_count = 5;
  call_template.ia32_padding_instruction_count = 5;

  invoke_call_from_template (fixture, &call_template);
}

TESTCASE (indirect_call_with_register_and_positive_byte_immediate)
{
  const guint8 code[] = {
    0x90, 0xb8, 0x00, 0x00, 0x00, 0x00, /* mov xax, X           */
                0x90, 0x90, 0x90, 0x90,
    0xff, 0x50, 0x54,                   /* call [xax + 0x54]    */
    0xc3,                               /* ret                  */

    0xb8, 0x39, 0x05, 0x00, 0x00,       /* mov eax, 1337        */
    0xc3,                               /* ret                  */
  };
  CallTemplate call_template = { 0, };

  call_template.code_template = code;
  call_template.code_size = sizeof (code);
  call_template.call_site_offset = 10;
  call_template.target_mov_offset = 1;
  call_template.target_address_offset = 2;
  call_template.target_func_offset = 14;
  call_template.target_func_immediate
"""


```