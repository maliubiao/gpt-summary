Response:
The user wants to understand the functionality of the C code provided, which is a test file for Frida's Stalker on ARM architecture. I need to explain what the code does, how it relates to reverse engineering, low-level concepts, and potential user errors. Since this is part 4 of 4, I also need to provide a summary of its overall purpose.

Here's a breakdown of how to address each point:

1. **Functionality:** Analyze the code to identify the main testing scenarios. Look for `TESTCASE` macros and the functions they call. The code tests various aspects of Stalker's behavior on ARM, including:
    * Basic code interception and modification.
    * Handling of ARM and Thumb instructions.
    * Invalidation of code blocks and their growth.
    * Correct handling of exclusive load/store instructions.
    * Following system calls and threads.
    * Handling thread termination during stalking.
    * Interacting with `pthread_create`.
    * Monitoring heap API calls.
    * Prefetching code blocks.
    * Running code on specific threads.

2. **Relationship to Reverse Engineering:** Explain how the tested functionalities are relevant to reverse engineering. Stalker is a dynamic instrumentation tool used for reverse engineering, so the tests demonstrate core capabilities like code tracing, modification, and understanding program flow.

3. **Binary/Kernel/Framework Knowledge:** Identify code sections that demonstrate interaction with low-level concepts. This includes:
    * Direct manipulation of ARM/Thumb instructions (`gum_arm_writer_...`, `gum_thumb_writer_...`).
    * Use of system calls (`g_usleep`, `pthread_create`).
    * Interaction with thread management.
    * Memory patching (`gum_memory_patch_code`).
    * Awareness of kernel concepts like dumpable processes (`prctl`).

4. **Logical Reasoning (Input/Output):** For test cases that involve code modification, specify the initial state and the expected outcome after Stalker's intervention. The `arm_get_magic_number` and `thumb_get_magic_number` tests are good examples here.

5. **User/Programming Errors:**  Consider how a user might misuse the Stalker API or encounter issues related to the tested functionalities. Examples include incorrect target addresses, race conditions when following threads, or misunderstanding the implications of code invalidation.

6. **User Operations to Reach This Point:** Describe a typical Frida workflow that would involve Stalker and potentially lead to the execution of this test code (although the test itself isn't directly executed by a typical user). This would involve using Frida to attach to a process, using Stalker to intercept and modify code, and observing the effects.

7. **Summary:**  Synthesize the individual functionalities into a concise overview of the file's purpose. This file primarily tests the core functionalities of Frida's Stalker on ARM architecture.

**Mental Sandbox:**

* **`arm_get_magic_number` and `thumb_get_magic_number`:**  These are straightforward. They define simple functions and the tests modify their return values. Input: executing these functions. Output: modified return values.
* **Invalidation tests:** These showcase Stalker's ability to handle changes in the traced code. Input: executing the target function multiple times after invalidation. Output: the return value increases with each invalidation.
* **Exclusive load/store tests (`ldrex`, `strex`):**  Important for ensuring Stalker doesn't interfere with atomic operations. The tests insert callouts *around* these instructions to verify their undisturbed execution. Input: executing code with `ldrex`/`strex`. Output: the value is incremented correctly and the callouts are triggered as expected.
* **Following syscalls and threads:** These test Stalker's ability to track execution across system calls and in multi-threaded environments. Input: making system calls or creating new threads. Output: Stalker events are generated.
* **`prefetch` test:** This is more complex, involving forking and IPC. It tests Stalker's ability to optimize code generation by prefetching blocks. Input: running code, then prefetching the executed blocks and running it again. Output: the second run should have fewer compilations.
* **`run_on_thread` tests:**  Verify that Stalker can execute code in the context of specific threads, either synchronously or asynchronously.

By analyzing these test cases and their respective helper functions, I can build a comprehensive explanation of the file's functionality and its relevance to the points requested by the user.
这是 `frida/subprojects/frida-gum/tests/core/arch-arm/stalker-arm.c` 文件的第四部分，延续了之前部分对 Frida Stalker 工具在 ARM 架构上的功能测试。让我们归纳一下这部分代码的功能，并结合您提出的几个方面进行详细说明。

**这部分代码的主要功能是测试 Frida Stalker 在更复杂的场景下的行为，包括：**

* **预取 (Prefetching) 代码块:** 测试 Stalker 是否可以预先编译即将执行的代码块，以提高性能。
* **在指定线程上运行代码:** 测试 `gum_stalker_run_on_thread` 和 `gum_stalker_run_on_thread_sync` 函数，确保 Stalker 能够在指定的线程上下文中执行代码。

接下来，我们针对您提出的几个方面进行详细分析：

**1. 功能列举:**

* **`TESTCASE (prefetch)`:**  测试 Stalker 的预取功能。它创建了一个子进程，该子进程执行一段代码，并记录下编译和执行的代码块。父进程读取这些信息，然后使用 `gum_stalker_prefetch` 来预取这些代码块。再次运行子进程，验证预取是否生效，即第二次运行时编译的代码块数量应该减少。
* **`TESTCASE (run_on_thread_current)` 和 `TESTCASE (run_on_thread_current_sync)`:** 测试在当前线程上执行代码的功能。`gum_stalker_run_on_thread` 是异步的，而 `gum_stalker_run_on_thread_sync` 是同步的。这些测试验证了在当前线程调用时，回调函数能够被正确执行。
* **`TESTCASE (run_on_thread_other)` 和 `TESTCASE (run_on_thread_other_sync)`:** 测试在其他线程上执行代码的功能。它们创建了一个新的线程，然后尝试使用 `gum_stalker_run_on_thread` 和 `gum_stalker_run_on_thread_sync` 在该线程上执行代码。这验证了 Stalker 跨线程执行代码的能力。
* **辅助函数:**
    * `prefetch_on_event`:  在预取测试中，用于记录编译和执行的事件。
    * `prefetch_run_child`:  在预取测试中，创建并运行子进程。
    * `prefetch_activation_target`:  一个空函数，用于标记 Stalker 激活的目标位置。
    * `prefetch_write_blocks` 和 `prefetch_read_blocks`:  在预取测试中，用于在父进程和子进程之间通过管道传递代码块地址。
    * `run_on_thread`:  在 `run_on_thread` 测试中，用于在目标线程上执行的代码。
    * `create_sleeping_dummy_thread_sync`:  创建一个休眠的线程，用于 `run_on_thread_other` 测试。
    * `sleeping_dummy`:  新创建的休眠线程的入口函数。

**2. 与逆向方法的关系及举例说明:**

* **预取 (Prefetching):** 在逆向工程中，了解程序执行的热点路径非常重要。Stalker 的预取功能可以帮助逆向工程师识别经常执行的代码块，从而将精力集中在这些关键部分。例如，逆向一个加密算法时，可以先运行程序，然后使用 Stalker 的预取功能来找出加密循环的核心代码，接着重点分析这些代码。
* **在指定线程上运行代码:**  现代程序通常是多线程的，分析特定线程的行为对于理解程序的功能至关重要。例如，一个游戏程序可能将渲染逻辑放在一个线程，将网络通信放在另一个线程。逆向工程师可以使用 `gum_stalker_run_on_thread` 在渲染线程中插入代码，来观察渲染过程中的数据变化，或者在网络通信线程中拦截数据包。

**3. 涉及到二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层:**
    * **代码块地址:** 预取功能和 Stalker 的基本工作原理都涉及到对二进制代码块地址的理解和操作。
    * **指令执行:** Stalker 能够追踪指令的执行，这需要对 ARM 指令集有深入的了解。
* **Linux:**
    * **进程和线程管理:** `fork()`, `waitpid()`, `pthread_create()`, `pthread_join()` 等函数的使用表明了对 Linux 进程和线程管理机制的依赖。
    * **管道 (pipe):** 预取测试中使用管道在父子进程之间传递数据，这是 Linux 中进程间通信的一种方式。
    * **`/proc` 文件系统:**  虽然代码中没有直接使用，但 Stalker 的实现可能依赖于 `/proc` 文件系统来获取进程和线程的信息。
    * **`prctl` 系统调用:** 在 `TESTCASE (follow_thread)` 中使用 `prctl(PR_GET_DUMPABLE)` 和 `prctl(PR_SET_DUMPABLE)` 来设置进程的 dumpable 属性，这在 Android 环境下处理非 debuggable 应用时很有用。
* **Android 内核及框架:**
    * **非 debuggable 应用:**  在 `TESTCASE (follow_thread)` 中提到了 Android 可能会将非 debuggable 应用设置为不可 dump，这体现了对 Android 安全机制的考虑。

**4. 逻辑推理、假设输入与输出:**

* **`TESTCASE (prefetch)`:**
    * **假设输入:** 运行一个包含多个代码块的程序。
    * **预期输出:** 第一次运行时，Stalker 会编译和执行多个代码块。第二次运行时，由于预取的作用，编译的代码块数量会减少，但执行的代码块数量不变。可以通过比较 `compiled_size_run1` 和 `compiled_size_run2` 的值来验证。
* **`TESTCASE (run_on_thread_current)` 和 `TESTCASE (run_on_thread_current_sync)`:**
    * **假设输入:** 在当前线程调用 `gum_stalker_run_on_thread` 或 `gum_stalker_run_on_thread_sync`，并传入一个修改 `ctx.thread_id` 的回调函数。
    * **预期输出:** 回调函数会被立即执行，`ctx.thread_id` 的值会被设置为当前线程的 ID。
* **`TESTCASE (run_on_thread_other)` 和 `TESTCASE (run_on_thread_other_sync)`:**
    * **假设输入:** 创建一个新的线程，并在主线程中调用 `gum_stalker_run_on_thread` 或 `gum_stalker_run_on_thread_sync`，指定在新线程上执行回调函数。
    * **预期输出:** 回调函数会在新线程的上下文中执行，`ctx.thread_id` 的值会被设置为新线程的 ID。

**5. 涉及用户或编程常见的使用错误及举例说明:**

* **预取错误:** 用户可能错误地预取了不相关的代码块，导致性能提升不明显甚至下降。例如，预取了只执行一次的代码块。
* **在指定线程上运行代码错误:**
    * **线程 ID 错误:** 用户可能传递了错误的线程 ID，导致回调函数无法执行。
    * **死锁:** 如果在回调函数中尝试获取已经被目标线程持有的锁，可能会导致死锁。
    * **竞态条件:**  在异步执行 (`gum_stalker_run_on_thread`) 的情况下，如果没有进行适当的同步，可能会出现竞态条件。
* **资源泄漏:** 在预取测试中，如果管道没有正确关闭，可能会导致资源泄漏。

**6. 说明用户操作是如何一步步的到达这里，作为调试线索:**

虽然用户通常不会直接运行这些测试代码，但这些测试反映了 Frida Stalker 的使用场景。一个用户可能进行如下操作：

1. **编写 Frida 脚本:** 用户编写一个 Frida 脚本，使用 `Stalker` API 来追踪目标进程的行为。
2. **选择目标进程和线程:** 用户可能需要选择特定的进程和线程进行追踪。
3. **使用 `Stalker.follow()` 或 `Stalker.attach()`:**  用户使用这些 API 将 Stalker 附加到目标进程或线程。
4. **使用 `Stalker.instrument()` 或 `Stalker.transform()`:** 用户配置 Stalker 来拦截特定的代码块或函数，并进行代码注入或修改。
5. **使用 `Stalker.prefetch()`:** 为了优化性能，用户可能会尝试使用 `Stalker.prefetch()` 来预先编译代码。
6. **使用 `Stalker.runOnThread()`:**  用户可能需要在特定的线程上下文中执行一些操作，例如读取线程局部变量。

当用户在使用这些 API 时遇到问题，例如预取没有生效，或者在指定线程上运行代码失败，那么开发者可能会查看类似 `stalker-arm.c` 这样的测试代码，来理解这些 API 的预期行为和潜在的问题。这些测试用例提供了很好的调试线索，可以帮助开发者理解 Stalker 的内部工作原理，并找出用户脚本中的错误。

**归纳其功能 (作为第 4 部分):**

作为 Frida Stalker ARM 架构测试的第四部分，这部分代码主要关注 **Stalker 的高级功能和在复杂场景下的行为**。它深入测试了 Stalker 的 **代码预取优化能力** 以及在 **多线程环境中指定线程执行代码的能力**。这些测试确保了 Stalker 在性能优化和精细化控制方面能够稳定可靠地工作，为 Frida 用户提供了更强大和灵活的动态 instrumentation 工具。这部分内容相对于之前的部分，更加侧重于性能和多线程协作方面的测试。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-arm/stalker-arm.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共4部分，请归纳一下它的功能

"""
 {
        gum_thumb_writer_put_mov_reg_u8 (output->writer.thumb, ARM_REG_R0,
            TRUE);
      }
      else
      {
        gum_arm_writer_put_ldr_reg_address (output->writer.arm, ARM_REG_R0,
            TRUE);
      }
    }

    gum_stalker_iterator_keep (iterator);
  }
}

TESTCODE (arm_get_magic_number,
  0x2a, 0x00, 0xa0, 0xe3, /* mov r0, 42  */
  0x1e, 0xff, 0x2f, 0xe1, /* bx lr       */
);

TESTCODE (thumb_get_magic_number,
  0x2a, 0x20,             /* movs r0, 42 */
  0x70, 0x47,             /* bx lr       */
);

TESTCASE (arm_invalidation_should_allow_block_to_grow)
{
  test_invalidation_block_growth_with_target (
      DUP_TESTCODE (arm_get_magic_number),
      fixture);
}

TESTCASE (thumb_invalidation_should_allow_block_to_grow)
{
  test_invalidation_block_growth_with_target (
      DUP_TESTCODE (thumb_get_magic_number) + 1,
      fixture);
}

static void
test_invalidation_block_growth_with_target (GumAddress target,
                                            TestArmStalkerFixture * fixture)
{
  int (* get_magic_number) (void) = GSIZE_TO_POINTER (target);
  InvalidationTransformContext ctx;

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
          insn->address == (GPOINTER_TO_SIZE (ctx->target_function) & ~1);
    }

    if (insn->id == ARM_INS_BX && in_target_function)
    {
      guint increment_index;

      for (increment_index = 0; increment_index != ctx->n; increment_index++)
      {
        if (output->encoding == GUM_INSTRUCTION_SPECIAL)
        {
          gum_thumb_writer_put_add_reg_imm (output->writer.thumb, ARM_REG_R0,
              1);
        }
        else
        {
          gum_arm_writer_put_add_reg_u16 (output->writer.arm, ARM_REG_R0, 1);
        }
      }
    }

    gum_stalker_iterator_keep (iterator);
  }
}

TESTCODE (arm_ldrex_strex,
  0x44, 0x00, 0x9f, 0xe5, /* ldr r0, [pointer_to_value] */
  /* retry:                                             */
  0x9f, 0x1f, 0x90, 0xe1, /* ldrex r1, [r0]             */
  0x01, 0x00, 0x51, 0xe3, /* cmp r1, 1                  */
  0x0b, 0x00, 0x00, 0x0a, /* beq nope                   */
  0x02, 0x00, 0x51, 0xe3, /* cmp r1, 2                  */
  0x09, 0x00, 0x00, 0x0a, /* beq nope                   */
  0x03, 0x00, 0x51, 0xe3, /* cmp r1, 3                  */
  0x07, 0x00, 0x00, 0x0a, /* beq nope                   */
  0x04, 0x00, 0x51, 0xe3, /* cmp r1, 4                  */
  0x05, 0x00, 0x00, 0x0a, /* beq nope                   */
  0x01, 0x10, 0x81, 0xe2, /* add r1, r1, 1              */
  0x91, 0x2f, 0x80, 0xe1, /* strex r2, r1, [r0]         */
  0x00, 0x00, 0x52, 0xe3, /* cmp r2, 0                  */
  0xf2, 0xff, 0xff, 0x1a, /* bne retry                  */
  0x01, 0x00, 0xa0, 0xe3, /* mov r0, 1                  */
  0x1e, 0xff, 0x2f, 0xe1, /* bx lr                      */
  /* nope:                                              */
  0x1f, 0xf0, 0x7f, 0xf5, /* clrex                      */
  0x00, 0x00, 0xa0, 0xe3, /* mov r0, 0                  */
  0x1e, 0xff, 0x2f, 0xe1, /* bx lr                      */
  /* pointer_to_value:                                  */
  0x11, 0x22, 0x33, 0x44,
);

TESTCASE (arm_exclusive_load_store_should_not_be_disturbed)
{
  guint32 code[CODE_SIZE (arm_ldrex_strex) / sizeof (guint32)], val;
  gint num_cmp_callouts;

  memcpy (code, arm_ldrex_strex, CODE_SIZE (arm_ldrex_strex));
  code[G_N_ELEMENTS (code) - 1] = GPOINTER_TO_SIZE (&val);

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      insert_callout_after_cmp, &num_cmp_callouts, NULL);

  val = 5;
  num_cmp_callouts = 0;
  INVOKE_ARM_EXPECTING (GUM_EXEC, code, 1);
  g_assert_cmpint (val, ==, 6);
  g_assert_cmpint (num_cmp_callouts, ==, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 19);
}

TESTCODE (thumb_ldrex_strex,
  0x0c, 0x48,             /* ldr r0, [pointer_to_value] */
  /* retry:                                             */
  0x50, 0xe8, 0x00, 0x1f, /* ldrex r1, [r0]             */
  0x01, 0x29,             /* cmp r1, 1                  */
  0x0e, 0xd0,             /* beq nope                   */
  0x02, 0x29,             /* cmp r1, 2                  */
  0x0c, 0xd0,             /* beq nope                   */
  0x03, 0x29,             /* cmp r1, 3                  */
  0x0a, 0xd0,             /* beq nope                   */
  0x04, 0x29,             /* cmp r1, 4                  */
  0x08, 0xd0,             /* beq nope                   */
  0x01, 0xf1, 0x01, 0x01, /* add.w r1, r1, 1            */
  0x40, 0xe8, 0x00, 0x12, /* strex r2, r1, [r0]         */
  0x00, 0x2a,             /* cmp r2, 0                  */
  0xef, 0xd1,             /* bne retry                  */
  0x4f, 0xf0, 0x01, 0x00, /* mov.w r0, 1                */
  0x70, 0x47,             /* bx lr                      */
  /* nope:                                              */
  0xbf, 0xf3, 0x2f, 0x8f, /* clrex                      */
  0x4f, 0xf0, 0x00, 0x00, /* mov.w r0, 0                */
  0x70, 0x47,             /* bx lr                      */
  0x00, 0x00,             /* <alignment padding>        */
  /* pointer_to_value:                                  */
  0x11, 0x22, 0x33, 0x44,
);

TESTCASE (thumb_exclusive_load_store_should_not_be_disturbed)
{
  guint32 code[CODE_SIZE (thumb_ldrex_strex) / sizeof (guint32)], val;
  gint num_cmp_callouts;

  memcpy (code, thumb_ldrex_strex, CODE_SIZE (thumb_ldrex_strex));
  code[G_N_ELEMENTS (code) - 1] = GPOINTER_TO_SIZE (&val);

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      insert_callout_after_cmp, &num_cmp_callouts, NULL);

  val = 5;
  num_cmp_callouts = 0;
  INVOKE_THUMB_EXPECTING (GUM_EXEC, code, 1);
  g_assert_cmpint (val, ==, 6);
  g_assert_cmpint (num_cmp_callouts, ==, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 19);
}

static void
insert_callout_after_cmp (GumStalkerIterator * iterator,
                          GumStalkerOutput * output,
                          gpointer user_data)
{
  gint * num_cmp_callouts = user_data;
  GumMemoryAccess access;
  const cs_insn * insn;

  access = gum_stalker_iterator_get_memory_access (iterator);

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    gum_stalker_iterator_keep (iterator);

    if (insn->id == ARM_INS_CMP && access == GUM_MEMORY_ACCESS_OPEN)
    {
      gum_stalker_iterator_put_callout (iterator, bump_num_cmp_callouts,
          num_cmp_callouts, NULL);
    }
  }
}

static void
bump_num_cmp_callouts (GumCpuContext * cpu_context,
                       gpointer user_data)
{
  gint * num_cmp_callouts = user_data;

  g_atomic_int_inc (num_cmp_callouts);
}

TESTCASE (follow_syscall)
{
  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  g_usleep (1);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCASE (follow_thread)
{
  StalkerDummyChannel channel;
  GThread * thread;
  GumThreadId thread_id;
#ifdef HAVE_LINUX
  int prev_dumpable;

  /* Android spawns non-debuggable applications as not dumpable by default. */
  prev_dumpable = prctl (PR_GET_DUMPABLE);
  prctl (PR_SET_DUMPABLE, 0);
#endif

  sdc_init (&channel);

  thread = g_thread_new ("stalker-test-target", run_stalked_briefly, &channel);
  thread_id = sdc_await_thread_id (&channel);

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;
  gum_stalker_follow (fixture->stalker, thread_id, NULL,
      GUM_EVENT_SINK (fixture->sink));
  sdc_put_follow_confirmation (&channel);

  sdc_await_run_confirmation (&channel);
  g_assert_cmpuint (fixture->sink->events->len, >, 0);

  gum_stalker_unfollow (fixture->stalker, thread_id);
  sdc_put_unfollow_confirmation (&channel);

  sdc_await_flush_confirmation (&channel);
  gum_fake_event_sink_reset (fixture->sink);

  sdc_put_finish_confirmation (&channel);

  g_thread_join (thread);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);

  sdc_finalize (&channel);

#ifdef HAVE_LINUX
  prctl (PR_SET_DUMPABLE, prev_dumpable);
#endif
}

static gpointer
run_stalked_briefly (gpointer data)
{
  StalkerDummyChannel * channel = data;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  sdc_put_run_confirmation (channel);

  sdc_await_unfollow_confirmation (channel);

  sdc_put_flush_confirmation (channel);

  sdc_await_finish_confirmation (channel);

  return NULL;
}

TESTCASE (unfollow_should_handle_terminated_thread)
{
  guint i;

  for (i = 0; i != 10; i++)
  {
    StalkerDummyChannel channel;
    GThread * thread;
    GumThreadId thread_id;

    sdc_init (&channel);

    thread = g_thread_new ("stalker-test-target", run_stalked_into_termination,
        &channel);
    thread_id = sdc_await_thread_id (&channel);

    fixture->sink->mask = GUM_CALL | GUM_RET;
    gum_stalker_follow (fixture->stalker, thread_id, NULL,
        GUM_EVENT_SINK (fixture->sink));
    sdc_put_follow_confirmation (&channel);

    g_thread_join (thread);

    if (i % 2 == 0)
      g_usleep (50000);

    gum_stalker_unfollow (fixture->stalker, thread_id);

    sdc_finalize (&channel);

    while (gum_stalker_garbage_collect (fixture->stalker))
      g_usleep (10000);
  }
}

static gpointer
run_stalked_into_termination (gpointer data)
{
  StalkerDummyChannel * channel = data;

  sdc_put_thread_id (channel, gum_process_get_current_thread_id ());

  sdc_await_follow_confirmation (channel);

  return NULL;
}

TESTCASE (pthread_create)
{
  int ret;
  pthread_t thread;
  int number = 0;

  fixture->sink->mask = GUM_NOTHING;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  ret = pthread_create (&thread, NULL, increment_integer, &number);
  g_assert_cmpint (ret, ==, 0);

  ret = pthread_join (thread, NULL);
  g_assert_cmpint (ret, ==, 0);

  g_assert_cmpint (number, ==, 1);

  gum_stalker_unfollow_me (fixture->stalker);
}

static gpointer
increment_integer (gpointer data)
{
  int * number = (int *) data;
  *number += 1;
  return NULL;
}

TESTCASE (heap_api)
{
  gpointer p;

#if defined (HAVE_ANDROID) && defined (HAVE_ARM)
  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }
#endif

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  p = malloc (1);
  free (p);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

static void
patch_code_pointer (GumAddress code,
                    guint offset,
                    GumAddress value)
{
  gum_memory_patch_code (GSIZE_TO_POINTER (code + offset), sizeof (gpointer),
      patch_code_pointer_slot, GSIZE_TO_POINTER (value));
}

static void
patch_code_pointer_slot (gpointer mem,
                         gpointer user_data)
{
  gpointer * slot = mem;
  gpointer value = user_data;

  *slot = value;
}

#ifdef HAVE_LINUX

TESTCASE (prefetch)
{
  GumMemoryRange runner_range;
  gint trust;
  int compile_pipes[2] = { -1, -1 };
  int execute_pipes[2] = { -1, -1 };
  GumEventSink * sink;
  GHashTable * compiled_run1;
  GHashTable * executed_run1;
  guint compiled_size_run1;
  guint executed_size_run1;
  GHashTableIter iter;
  gpointer iter_key, iter_value;
  GHashTable * compiled_run2;
  GHashTable * executed_run2;
  guint compiled_size_run2;
  guint executed_size_run2;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  /* Initialize workload parameters */
  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);
  g_assert_cmpuint (runner_range.base_address, !=, 0);
  g_assert_cmpuint (runner_range.size, !=, 0);

  /* Initialize Stalker */
  gum_stalker_set_trust_threshold (fixture->stalker, 3);
  trust = gum_stalker_get_trust_threshold (fixture->stalker);

  /*
   * Create IPC.
   *
   * The pipes by default are 64 KB in size. At 8-bytes per-block, (the block
   * address) we thus have capacity to communicate up to 8192 blocks back to the
   * parent before the child's write() call blocks and we deadlock in waitpid().
   *
   * We can increase the size of these pipes using fcntl(F_SETPIPE_SZ), but we
   * need to be careful so we don't exceed the limit set in
   * /proc/sys/fs/pipe-max-size.
   *
   * Since our test has approx 1300 blocks, we don't need to worry about this.
   * However, production implementations may need to handle this error.
   */
  g_assert_cmpint (pipe (compile_pipes), ==, 0);
  g_assert_cmpint (pipe (execute_pipes), ==, 0);
  g_assert_true (g_unix_set_fd_nonblocking (compile_pipes[0], TRUE, NULL));
  g_assert_true (g_unix_set_fd_nonblocking (compile_pipes[1], TRUE, NULL));
  g_assert_true (g_unix_set_fd_nonblocking (execute_pipes[0], TRUE, NULL));
  g_assert_true (g_unix_set_fd_nonblocking (execute_pipes[1], TRUE, NULL));

  /* Configure Stalker */
  sink = gum_event_sink_make_from_callback (GUM_COMPILE | GUM_BLOCK,
      prefetch_on_event, NULL, NULL);
  gum_stalker_follow_me (fixture->stalker, NULL, sink);
  gum_stalker_deactivate (fixture->stalker);

  /* Run the child */
  prefetch_run_child (fixture->stalker, &runner_range,
      compile_pipes[STDOUT_FILENO], execute_pipes[STDOUT_FILENO]);

  /* Read the results */
  compiled_run1 = g_hash_table_new (NULL, NULL);
  prefetch_read_blocks (compile_pipes[STDIN_FILENO], compiled_run1);
  executed_run1 = g_hash_table_new (NULL, NULL);
  prefetch_read_blocks (execute_pipes[STDIN_FILENO], executed_run1);

  compiled_size_run1 = g_hash_table_size (compiled_run1);
  executed_size_run1 = g_hash_table_size (executed_run1);

  if (g_test_verbose ())
  {
    g_print ("\tcompiled: %d\n", compiled_size_run1);
    g_print ("\texecuted: %d\n", executed_size_run1);
  }

  g_assert_cmpuint (compiled_size_run1, >, 0);
  g_assert_cmpuint (compiled_size_run1, ==, executed_size_run1);

  /* Prefetch the blocks */
  g_hash_table_iter_init (&iter, compiled_run1);
  while (g_hash_table_iter_next (&iter, &iter_key, &iter_value))
  {
    gum_stalker_prefetch (fixture->stalker, iter_key, trust);
  }

  /* Run the child again */
  prefetch_run_child (fixture->stalker, &runner_range,
      compile_pipes[STDOUT_FILENO], execute_pipes[STDOUT_FILENO]);

  /* Read the results */
  compiled_run2 = g_hash_table_new (NULL, NULL);
  prefetch_read_blocks (compile_pipes[STDIN_FILENO], compiled_run2);
  executed_run2 = g_hash_table_new (NULL, NULL);
  prefetch_read_blocks (execute_pipes[STDIN_FILENO], executed_run2);

  compiled_size_run2 = g_hash_table_size (compiled_run2);
  executed_size_run2 = g_hash_table_size (executed_run2);

  if (g_test_verbose ())
  {
    g_print ("\tcompiled2: %d\n", compiled_size_run2);
    g_print ("\texecuted2: %d\n", executed_size_run2);
  }

  g_assert_cmpuint (compiled_size_run2, ==, 0);
  g_assert_cmpuint (executed_size_run2, ==, executed_size_run1);

  /* Free resources */
  g_hash_table_unref (compiled_run2);
  g_hash_table_unref (executed_run2);
  g_hash_table_unref (compiled_run1);
  g_hash_table_unref (executed_run1);

  close (execute_pipes[STDIN_FILENO]);
  close (execute_pipes[STDOUT_FILENO]);
  close (compile_pipes[STDIN_FILENO]);
  close (compile_pipes[STDOUT_FILENO]);

  gum_stalker_unfollow_me (fixture->stalker);
  g_object_unref (sink);
}

static void
prefetch_on_event (const GumEvent * event,
                   GumCpuContext * cpu_context,
                   gpointer user_data)
{
  switch (event->type)
  {
    case GUM_COMPILE:
    {
      const GumCompileEvent * compile = &event->compile;

      if (prefetch_compiled != NULL)
        g_hash_table_add (prefetch_compiled, compile->start);

      break;
    }
    case GUM_BLOCK:
    {
      const GumBlockEvent * block = &event->block;

      if (prefetch_executed != NULL)
        g_hash_table_add (prefetch_executed, block->start);

      break;
    }
    default:
      break;
  }
}

static void
prefetch_run_child (GumStalker * stalker,
                    GumMemoryRange * runner_range,
                    int compile_fd,
                    int execute_fd)
{
  pid_t pid;
  int res;
  int status;

  pid = fork ();
  g_assert_cmpint (pid, >=, 0);

  if (pid == 0)
  {
    /* Child */

    prefetch_compiled = g_hash_table_new (NULL, NULL);
    prefetch_executed = g_hash_table_new (NULL, NULL);

    gum_stalker_activate (stalker, prefetch_activation_target);
    prefetch_activation_target ();
    pretend_workload (runner_range);
    gum_stalker_unfollow_me (stalker);

    prefetch_write_blocks (compile_fd, prefetch_compiled);
    prefetch_write_blocks (execute_fd, prefetch_executed);

    exit (0);
  }

  /* Wait for the child */
  res = waitpid (pid, &status, 0);
  g_assert_cmpint (res, ==, pid);
  g_assert_cmpint (WIFEXITED (status), !=, 0);
  g_assert_cmpint (WEXITSTATUS (status), ==, 0);
}

GUM_NOINLINE static void
prefetch_activation_target (void)
{
  /* Avoid calls being optimized out */
  asm ("");
}

static void
prefetch_write_blocks (int fd,
                       GHashTable * table)
{
  GHashTableIter iter;
  gpointer iter_key, iter_value;

  g_hash_table_iter_init (&iter, table);
  while (g_hash_table_iter_next (&iter, &iter_key, &iter_value))
  {
    int res = write (fd, &iter_key, sizeof (gpointer));
    g_assert_cmpint (res, ==, sizeof (gpointer));
  }
}

static void
prefetch_read_blocks (int fd,
                      GHashTable * table)
{
  gpointer block_address;

  while (read (fd, &block_address, sizeof (gpointer)) == sizeof (gpointer))
  {
    g_hash_table_add (table, block_address);
  }
}

#endif

TESTCASE (run_on_thread_current)
{
  GumThreadId thread_id;
  RunOnThreadCtx ctx;
  gboolean accepted;

  thread_id = gum_process_get_current_thread_id ();
  ctx.caller_id = thread_id;
  ctx.thread_id = G_MAXSIZE;

  accepted = gum_stalker_run_on_thread (fixture->stalker, thread_id,
      run_on_thread, &ctx, NULL);
  g_assert_true (accepted);
  g_assert_cmpuint (ctx.thread_id, ==, thread_id);
}

TESTCASE (run_on_thread_current_sync)
{
  GumThreadId thread_id;
  RunOnThreadCtx ctx;
  gboolean accepted;

  thread_id = gum_process_get_current_thread_id ();
  ctx.caller_id = thread_id;
  ctx.thread_id = G_MAXSIZE;

  accepted = gum_stalker_run_on_thread_sync (fixture->stalker, thread_id,
      run_on_thread, &ctx);
  g_assert_true (accepted);
  g_assert_cmpuint (thread_id, ==, ctx.thread_id);
}

static void
run_on_thread (const GumCpuContext * cpu_context,
               gpointer user_data)
{
  RunOnThreadCtx * ctx = user_data;

  g_usleep (250000);
  ctx->thread_id = gum_process_get_current_thread_id ();

  if (ctx->thread_id == ctx->caller_id)
    g_assert_null (cpu_context);
  else
    g_assert_nonnull (cpu_context);
}

TESTCASE (run_on_thread_other)
{
  GThread * thread;
  gboolean done = FALSE;
  GumThreadId other_id, this_id;
  RunOnThreadCtx ctx;
  gboolean accepted;

  thread = create_sleeping_dummy_thread_sync (&done, &other_id);

  this_id = gum_process_get_current_thread_id ();
  g_assert_cmphex (this_id, !=, other_id);
  ctx.caller_id = this_id;
  ctx.thread_id = G_MAXSIZE;

  accepted = gum_stalker_run_on_thread (fixture->stalker, other_id,
      run_on_thread, &ctx, NULL);
  g_assert_true (accepted);
  done = TRUE;
  g_thread_join (thread);
  g_assert_cmphex (ctx.thread_id, ==, other_id);
}

TESTCASE (run_on_thread_other_sync)
{
  GThread * thread;
  gboolean done = FALSE;
  GumThreadId other_id, this_id;
  RunOnThreadCtx ctx;
  gboolean accepted;

  thread = create_sleeping_dummy_thread_sync (&done, &other_id);

  this_id = gum_process_get_current_thread_id ();
  g_assert_cmphex (this_id, !=, other_id);
  ctx.caller_id = this_id;
  ctx.thread_id = G_MAXSIZE;

  accepted = gum_stalker_run_on_thread_sync (fixture->stalker, other_id,
      run_on_thread, &ctx);
  g_assert_true (accepted);
  done = TRUE;
  g_thread_join (thread);
  g_assert_cmpuint (ctx.thread_id, ==, other_id);
}

static GThread *
create_sleeping_dummy_thread_sync (gboolean * done,
                                   GumThreadId * thread_id)
{
  GThread * thread;
  TestThreadSyncData sync_data;

  g_mutex_init (&sync_data.mutex);
  g_cond_init (&sync_data.cond);
  sync_data.started = FALSE;
  sync_data.thread_id = 0;
  sync_data.done = done;

  g_mutex_lock (&sync_data.mutex);

  thread = g_thread_new ("sleepy", sleeping_dummy, &sync_data);

  while (!sync_data.started)
    g_cond_wait (&sync_data.cond, &sync_data.mutex);

  *thread_id = sync_data.thread_id;

  g_mutex_unlock (&sync_data.mutex);

  g_cond_clear (&sync_data.cond);
  g_mutex_clear (&sync_data.mutex);

  return thread;
}

static gpointer
sleeping_dummy (gpointer data)
{
  TestThreadSyncData * sync_data = data;
  gboolean * done = sync_data->done;

  g_mutex_lock (&sync_data->mutex);
  sync_data->started = TRUE;
  sync_data->thread_id = gum_process_get_current_thread_id ();
  g_cond_signal (&sync_data->cond);
  g_mutex_unlock (&sync_data->mutex);

  while (!(*done))
    g_thread_yield ();

  return NULL;
}

"""


```