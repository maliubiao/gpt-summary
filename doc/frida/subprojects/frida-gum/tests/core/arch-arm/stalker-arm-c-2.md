Response:
The user wants a summary of the functionality of the provided C code, which is a test file for Frida's Stalker on ARM architecture. I need to go through each `TESTCASE` and `TESTCODE` block and describe what it's testing.

Here's a plan:
1. **Identify the core functionality:** The file tests the `gum_stalker`, a component of Frida that allows tracing and instrumenting code execution dynamically.
2. **Analyze each `TESTCODE` block:** These blocks define ARM or Thumb assembly code snippets used for testing.
3. **Analyze each `TESTCASE` block:** These blocks set up the test environment, execute the code defined in the corresponding `TESTCODE` block, and assert the expected behavior.
4. **Relate to reverse engineering:** Explain how Stalker's capabilities are useful for reverse engineering.
5. **Relate to binary, Linux, Android:** Point out where the tests interact with low-level concepts and operating system features.
6. **Identify logic and assumptions:**  Where possible, infer the intended input and output of the test functions.
7. **Spot potential user errors:**  Think about how a user might misuse Frida or Stalker based on the test scenarios.
8. **Explain the user's path:** Describe how a user might end up interacting with this code or the functionalities it tests.
9. **Summarize the overall functionality:** Condense the findings into a concise summary for part 3.
好的，这是对提供的Frida Stalker测试代码片段的功能归纳：

**功能归纳 (第 3 部分):**

这个代码片段主要集中在测试 Frida Stalker 在 ARM 架构上处理以下几种情况的能力：

* **排除特定地址范围的跟踪:** `arm_exclude_range` 测试了 `gum_stalker_exclude` 函数，确保 Stalker 可以忽略指定的代码区域，不生成跟踪事件。
* **Thumb 指令集的 IT (If-Then) 块处理:**  一系列以 `thumb_it_` 开头的测试用例，例如 `thumb_it_eq_pop`，`thumb_itttt_eq_blx_reg`，`thumb_it_flags`，`thumb_it_flags2`，验证了 Stalker 能正确跟踪和处理 Thumb 指令集中的条件执行块 (`it`, `itttt` 等)，包括涉及跳转、标志位以及寄存器调用的复杂情况。
* **Thumb 指令集的表跳转 (`tbb`, `tbh`):** `thumb_tbb` 和 `thumb_tbh` 测试了 Stalker 对 Thumb 指令集中用于表跳转的 `tbb` 和 `tbh` 指令的处理，确保能正确识别目标地址。
* **自修改代码的检测:** `self_modifying_code_should_be_detected_with_threshold_minus_one`， `self_modifying_code_should_not_be_detected_with_threshold_zero`， `self_modifying_code_should_be_detected_with_threshold_one` 这三个测试用例验证了 Stalker 能够检测到正在执行的代码被修改的情况，并且可以通过设置信任阈值来控制检测的灵敏度。
* **ARM 和 Thumb 指令集的调用处理:** `call_thumb` 测试了从 ARM 代码调用 Thumb 代码，以及 Thumb 代码内部调用的情况，验证了 Stalker 能正确跟踪跨指令集边界的调用。
* **ARM 指令集的分支处理:** `branch_thumb` 测试了 ARM 代码中各种分支指令 (`b`, `bx`) 的跟踪，确保 Stalker 能正确识别代码块的边界。
* **跟踪工作负载:** `can_follow_workload` 测试了一个更实际的场景，Stalker 被用来跟踪一个模拟的工作负载函数 (`pretend_workload`) 的执行，并对比跟踪前后的结果，验证其功能的正确性。
* **性能测试:** `performance`  进行了一个简单的性能基准测试，对比了在有 Stalker 跟踪和没有 Stalker 跟踪的情况下，同一段代码的执行耗时，用于评估 Stalker 的性能开销。
* **自定义代码转换 (Transformer):**  一系列以 `custom_transformer`， `arm_callout`， `thumb_callout`， `arm_transformer_should_be_able_to_replace_call_with_callout`， `arm_transformer_should_be_able_to_replace_jumpout_with_callout` 开头的测试用例，演示了如何使用 Stalker 的 Transformer 功能来修改代码执行流程，例如插入自定义的 callout 函数，替换原有的调用或跳转指令。
* **动态取消跟踪 (Unfollow):**  `unfollow_should_be_allowed_before_first_transform` 到 `unfollow_should_be_allowed_after_second_transform`  这些测试用例验证了在代码跟踪的不同阶段调用 `gum_stalker_unfollow_me` 的安全性，包括在 Transformer 回调函数中途取消跟踪。
* **支持空事件接收器:** `follow_me_should_support_nullable_event_sink` 确认了 `gum_stalker_follow_me` 可以接受空的事件接收器，这在某些只需要 Transformer 功能而不需要记录事件的场景下很有用。
* **针对特定线程的代码失效:**  `arm_invalidation_for_current_thread_should_be_supported`， `thumb_invalidation_for_current_thread_should_be_supported`， `arm_invalidation_for_specific_thread_should_be_supported`， `thumb_invalidation_for_specific_thread_should_be_supported`  这些测试用例验证了 Stalker 提供的代码失效机制，可以针对当前线程或特定线程使 Stalker 重新分析和转换代码，这在处理动态生成或修改代码的场景中非常重要。

**与逆向方法的联系及举例说明:**

* **动态代码执行跟踪:** Stalker 的核心功能就是动态跟踪代码执行。逆向工程师可以使用 Stalker 来观察程序运行时的指令执行流程，这对于理解程序的行为、查找漏洞、分析恶意代码至关重要。例如，通过跟踪一个函数调用，可以了解它的参数传递、返回值以及内部执行逻辑。
* **代码覆盖率分析:** Stalker 可以帮助确定哪些代码被执行到，哪些没有，这对于测试和漏洞分析很有帮助。例如，可以跟踪程序的运行，然后分析 Stalker 的输出，查看是否覆盖了所有预期的代码路径。
* **运行时插桩和修改:** 通过 Transformer 功能，逆向工程师可以在运行时修改程序的行为，例如修改函数返回值、跳过特定代码块、插入自定义的日志输出。例如，`arm_transformer_should_be_able_to_replace_call_with_callout` 测试展示了如何将一个函数调用替换为调用自定义的 callout 函数。这在调试、绕过检测、或者进行动态分析时非常有用。
* **自修改代码分析:**  `self_modifying_code_should_be_detected...` 测试用例表明 Stalker 可以检测自修改代码，这对于分析加壳或具有混淆技术的程序至关重要。逆向工程师可以使用 Stalker 来观察代码是如何在运行时被修改的。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **ARM/Thumb 汇编指令:**  所有的 `TESTCODE` 都直接操作 ARM 或 Thumb 汇编指令，需要对这些指令的含义和执行方式有深入的理解。例如，`bl` 指令用于跳转并保存返回地址，`bx` 指令用于跳转到指定地址，并可以切换指令集状态（ARM/Thumb）。
* **内存地址和代码段:** 测试用例中大量涉及到内存地址的计算和比较，例如 `GUM_ASSERT_EVENT_ADDR` 宏用于断言 Stalker 记录的事件地址是否正确。这需要理解程序在内存中的布局，特别是代码段的位置。
* **函数调用约定:**  测试用例间接地涉及函数调用约定，例如 `push {lr}` 和 `pop {pc}` 用于保存和恢复返回地址。
* **进程和线程:** `gum_process_enumerate_modules` 函数用于枚举进程的模块，`gum_process_get_current_thread_id` 用于获取当前线程 ID。代码失效的测试用例也直接操作线程 ID。
* **动态链接:**  Frida 本身就是一个动态插桩工具，需要理解动态链接的原理才能有效地使用它。
* **Linux/Android 内核的某些概念 (间接):** 虽然测试代码本身没有直接调用内核 API，但 Stalker 的实现依赖于操作系统提供的机制来实现代码跟踪，例如 ptrace (Linux) 或类似的机制 (Android)。

**逻辑推理、假设输入与输出:**

以 `thumb_it_eq_pop` 为例：

* **假设输入:**  执行 `thumb_it_eq_pop` 定义的 Thumb 代码，初始时寄存器 `r0` 的值为某个值 (测试中并未显式设置，但逻辑上会影响条件分支)。
* **代码逻辑:**
    1. `push {lr}`: 将返回地址压栈。
    2. `subs r0, r0, r0`: 将 `r0` 清零。
    3. `adds r0, #1`: 将 `r0` 加 1，此时 `r0` 为 1。
    4. `bl part_two`: 跳转到 `part_two` 子程序。
    5. `bl part_two`: 再次跳转到 `part_two` 子程序。
    6. `pop {pc}`:  从栈中弹出返回地址，返回。
    7. `part_two`:
        * `push {r2, lr}`: 保存 `r2` 和返回地址。
        * `cmp r0, #2`: 比较 `r0` 和 2。
        * `it eq`: 如果相等，则执行下一条指令。
        * `pop {r2, pc}`: 如果 `r0` 等于 2，则返回。
        * `adds r0, #1`: 如果 `r0` 不等于 2，则将 `r0` 加 1。
        * `pop {r2, pc}`: 返回。
* **预期输出 (根据测试用例):** 测试用例期望 `INVOKE_THUMB_EXPECTING (GUM_RET, thumb_it_eq_pop, 2)` 返回后，`fixture->sink->events->len` 为 3，并且记录了特定的返回事件，其 `location` 和 `target` 地址与代码中的返回点对应。

**涉及用户或者编程常见的使用错误及举例说明:**

* **不正确的地址计算:** 在使用 `gum_stalker_exclude` 或断言事件地址时，如果地址计算错误，会导致 Stalker 的行为不符合预期，或者断言失败。例如，在 ARM 和 Thumb 代码混合的情况下，需要注意 Thumb 代码地址的最低位是 1。
* **Transformer 回调函数中的错误:**  如果在 Transformer 回调函数中引入错误（例如内存访问越界），可能会导致程序崩溃。
* **对 Stalker 的生命周期管理不当:**  例如，在没有调用 `gum_stalker_unfollow_me` 的情况下就释放了 `GumStalker` 对象，可能会导致资源泄漏或程序崩溃。
* **对信任阈值的误解:**  如果用户不理解信任阈值的作用，可能会导致 Stalker 无法检测到自修改代码，或者过度报告误报。
* **在多线程环境中使用 Stalker 不当:**  需要在多线程环境中使用 Stalker 时，需要注意线程安全问题，并合理地使用 `gum_stalker_follow` 和 `gum_stalker_unfollow`。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户想要使用 Frida 动态插桩一个 ARM 架构的程序。**
2. **用户编写了一个 Frida 脚本，使用了 `Stalker` 模块来跟踪目标程序的代码执行。**
3. **用户可能遇到了关于代码排除、Thumb 指令集处理、自修改代码检测、函数调用跟踪、代码转换或者线程特定的跟踪等问题。**
4. **为了验证 Frida 的行为或调试他们自己的脚本，用户可能会查看 Frida 的源代码，特别是 Stalker 相关的测试用例。**
5. **用户可能会阅读 `frida/subprojects/frida-gum/tests/core/arch-arm/stalker-arm.c` 这个文件，来了解 Stalker 在 ARM 架构上的具体实现和测试情况。**
6. **用户可以通过这些测试用例来理解 Stalker 的各种功能，例如如何使用 `gum_stalker_exclude`，如何处理 Thumb 的 IT 块，如何检测自修改代码，以及如何使用 Transformer 进行代码转换。**
7. **当用户遇到问题时，这些测试用例可以作为参考，帮助他们理解 Stalker 的预期行为，并找到他们自己脚本中的错误。**

总而言之，这个代码片段是 Frida Stalker 在 ARM 架构上的一个综合性测试文件，涵盖了 Stalker 的核心功能和各种使用场景，对于理解 Stalker 的工作原理和正确使用它进行动态分析至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-arm/stalker-arm.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共4部分，请归纳一下它的功能

"""
  .base_address = GUM_ADDRESS (func) + 28,
      .size = 6
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_EXEC;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 1);

    g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 10);

    GUM_ASSERT_EVENT_ADDR (exec,  2, location, func +  0 + 1);
    GUM_ASSERT_EVENT_ADDR (exec,  3, location, func +  2 + 1);
    GUM_ASSERT_EVENT_ADDR (exec,  4, location, func +  4 + 1);
    GUM_ASSERT_EVENT_ADDR (exec,  5, location, func +  6 + 1);
    GUM_ASSERT_EVENT_ADDR (exec,  6, location, func +  8 + 1);
    GUM_ASSERT_EVENT_ADDR (exec,  7, location, func + 10 + 1);
    GUM_ASSERT_EVENT_ADDR (exec,  8, location, func + 16 + 1);
    GUM_ASSERT_EVENT_ADDR (exec,  9, location, func + 18 + 1);
    GUM_ASSERT_EVENT_ADDR (exec, 10, location, func + 20 + 1);
    GUM_ASSERT_EVENT_ADDR (exec, 11, location, func + 26 + 1);
  }
}

TESTCODE (thumb_it_eq_pop,
  0x00, 0xb5,             /* push {lr}       */
  0x00, 0x1a,             /* subs r0, r0, r0 */
  0x01, 0x30,             /* adds r0, #1     */
  0x00, 0xf0, 0x03, 0xf8, /* bl part_two     */
  0x00, 0xf0, 0x01, 0xf8, /* bl part_two     */
  0x00, 0xbd,             /* pop {pc}        */

  /* part_two:                               */
  0x04, 0xb5,             /* push {r2, lr}   */
  0x02, 0x28,             /* cmp r0, #2      */
  0x08, 0xbf,             /* it eq           */
  0x04, 0xbd,             /* pop {r2, pc}    */
  0x01, 0x30,             /* adds r0, #1     */
  0x04, 0xbd,             /* pop {r2, pc}    */
);

TESTCASE (thumb_it_eq_pop)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_it_eq_pop, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 3);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 26 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 10 + 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 20 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 1, target, func + 14 + 1);

  GUM_ASSERT_EVENT_ADDR (ret, 2, location, func + 14 + 1);
}

TESTCODE (thumb_itttt_eq_blx_reg,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x49, 0x1a, /* subs r1, r1, r1 */
  0x79, 0x44, /* add r1, pc      */
  0x1b, 0x31, /* adds r1, #27    */
  0x00, 0x28, /* cmp r0, #0      */
  0x01, 0xbf, /* itttt eq        */
  0x01, 0x30, /* adds r0, #1     */
  0x01, 0x30, /* adds r0, #1     */
  0x01, 0x30, /* adds r0, #1     */
  0x88, 0x47, /* blx r1          */

  /* part_two:                   */
  0x00, 0x28, /* cmp r0, #0      */
  0x01, 0xbf, /* itttt eq        */
  0x02, 0x30, /* adds r0, #2     */
  0x02, 0x30, /* adds r0, #2     */
  0x02, 0x30, /* adds r0, #2     */
  0x88, 0x47, /* blx r1          */
  0x00, 0xbd, /* pop {pc}        */

  /* part_three:                 */
  0x00, 0xb5, /* push {lr}       */
  0x01, 0x30, /* adds r0, #1     */
  0x00, 0xbd, /* pop {pc}        */
);

TESTCASE (thumb_itttt_eq_blx_reg)
{
  INVOKE_THUMB_EXPECTING (GUM_EXEC | GUM_CALL, thumb_itttt_eq_blx_reg, 4);
  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 16);
}

TESTCODE (thumb_it_flags,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x00, 0x28, /* cmp r0, #0      */
  0x08, 0xbf, /* it eq           */
  0x01, 0x30, /* adds r0, #1     */

  /* part_two:                   */
  0x08, 0xbf, /* it eq           */
  0x02, 0x30, /* adds r0, #2     */
  0x00, 0xbd, /* pop {pc}        */
);

TESTCASE (thumb_it_flags)
{
  INVOKE_THUMB_EXPECTING (GUM_NOTHING, thumb_it_flags, 3);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCODE (thumb_it_flags2,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x00, 0x28, /* cmp r0, #0      */
  0x08, 0xbf, /* it eq           */
  0x01, 0x28, /* cmp.eq r0, #1   */

  /* part_two:                   */
  0x18, 0xbf, /* it ne           */
  0x02, 0x30, /* adds r0, #2     */
  0x00, 0xbd, /* pop {pc}        */
);

TESTCASE (thumb_it_flags2)
{
  INVOKE_THUMB_EXPECTING (GUM_NOTHING, thumb_it_flags2, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCODE (thumb_tbb,
  0x00, 0xb5,             /* push {lr}            */
  0x00, 0x20,             /* movs r0, 0           */

  0x01, 0x21,             /* movs r1, 1           */
  0xdf, 0xe8, 0x01, 0xf0, /* tbb [pc, r1]         */

  /* table1:                                      */
  0x02,                   /* (one - table1) / 2   */
  0x03,                   /* (two - table1) / 2   */
  0x04,                   /* (three - table1) / 2 */
  0xff,                   /* <alignment padding>  */

  /* one:                                         */
  0x40, 0x1c,             /* adds r0, r0, 1       */
  /* two:                                         */
  0x80, 0x1c,             /* adds r0, r0, 2       */
  /* three:                                       */
  0xc0, 0x1c,             /* adds r0, r0, 3       */

  0x00, 0xbd,             /* pop {pc}             */
);

TESTCASE (thumb_tbb)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_tbb, 5);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 20 + 1);
}

TESTCODE (thumb_tbh,
  0x00, 0xb5,             /* push {lr}            */
  0x00, 0x20,             /* movs r0, 0           */

  0x5f, 0xf0, 0x02, 0x0c, /* movs.w ip, 2         */
  0xdf, 0xe8, 0x1c, 0xf0, /* tbh [pc, ip, lsl 1]  */

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  /* table1:                                      */
  0x03, 0x00,             /* (one - table1) / 2   */
  0x04, 0x00,             /* (two - table1) / 2   */
  0x05, 0x00,             /* (three - table1) / 2 */
#else
  /* table1:                                      */
  0x00, 0x03,             /* (one - table1) / 2   */
  0x00, 0x04,             /* (two - table1) / 2   */
  0x00, 0x05,             /* (three - table1) / 2 */
#endif

  /* one:                                         */
  0x40, 0x1c,             /* adds r0, r0, 1       */
  /* two:                                         */
  0x80, 0x1c,             /* adds r0, r0, 2       */
  /* three:                                       */
  0xc0, 0x1c,             /* adds r0, r0, 3       */

  0x00, 0xbd,             /* pop {pc}             */
);

TESTCASE (thumb_tbh)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_tbh, 3);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 24 + 1);
}

TESTCODE (self_modifying_code_should_be_detected,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr     */
);

TESTCASE (self_modifying_code_should_be_detected_with_threshold_minus_one)
{
  GumAddress func;
  guint (* f) (void);
  guint value;

  func = DUP_TESTCODE (self_modifying_code_should_be_detected);
  f = GUM_POINTER_TO_FUNCPTR (guint (*) (void), func);

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_set_trust_threshold (fixture->stalker, -1);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  value = f ();
  g_assert_cmpuint (value, ==, 1);

  patch_code_pointer (func, 4, GSIZE_TO_LE (0xe2800002));
  value = f ();
  g_assert_cmpuint (value, ==, 2);
  f ();
  f ();

  patch_code_pointer (func, 4, GSIZE_TO_LE (0xe2800003));
  value = f ();
  g_assert_cmpuint (value, ==, 3);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCASE (self_modifying_code_should_not_be_detected_with_threshold_zero)
{
  GumAddress func;
  guint (* f) (void);
  guint value;

  func = DUP_TESTCODE (self_modifying_code_should_be_detected);
  f = GUM_POINTER_TO_FUNCPTR (guint (*) (void), func);

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_set_trust_threshold (fixture->stalker, 0);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  value = f ();
  g_assert_cmpuint (value, ==, 1);

  patch_code_pointer (func, 4, GSIZE_TO_LE (0xe2800002));
  value = f ();
  g_assert_cmpuint (value, ==, 1);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCASE (self_modifying_code_should_be_detected_with_threshold_one)
{
  GumAddress func;
  guint (* f) (void);
  guint value;

  func = DUP_TESTCODE (self_modifying_code_should_be_detected);
  f = GUM_POINTER_TO_FUNCPTR (guint (*) (void), func);

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_set_trust_threshold (fixture->stalker, 1);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  value = f ();
  g_assert_cmpuint (value, ==, 1);

  patch_code_pointer (func, 4, GSIZE_TO_LE (0xe2800002));
  value = f ();
  g_assert_cmpuint (value, ==, 2);
  f ();
  f ();

  patch_code_pointer (func, 4, GSIZE_TO_LE (0xe2800003));
  value = f ();
  g_assert_cmpuint (value, ==, 2);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCODE (call_thumb,
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}      */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x05, 0x00, 0x00, 0xfa, /* blx func_c     */
  0x00, 0x00, 0x00, 0xeb, /* bl func_a      */
  0x04, 0xf0, 0x9d, 0xe4, /* pop {pc}       */

  /* func_a:                                */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr     */

  /* func_b:                                */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr     */

  /* func_c:                                */
  0x00, 0xb5,             /* push {lr}      */
  0x01, 0x30,             /* adds r0, 1     */
  0xff, 0xf7, 0xf8, 0xef, /* blx func_b     */
  0x00, 0xbd,             /* pop {pc}       */
);

TESTCASE (call_thumb)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_CALL, call_thumb, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 3);

  GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 12);
  GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 40 + 1);
  GUM_ASSERT_EVENT_ADDR (call, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR (call, 2, location, func + 44 + 1);
  GUM_ASSERT_EVENT_ADDR (call, 2, target, func + 32);
  GUM_ASSERT_EVENT_ADDR (call, 2, depth, 2);

  GUM_ASSERT_EVENT_ADDR (call, 3, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (call, 3, target, func + 24);
  GUM_ASSERT_EVENT_ADDR (call, 3, depth, 1);
}

TESTCODE (branch_thumb,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x08, 0x10, 0x8f, 0xe2, /* adr r1, func_a */
  0x14, 0x20, 0x8f, 0xe2, /* adr r2, func_c */
  0x01, 0x20, 0x82, 0xe2, /* add r2, r2, 1  */
  0x12, 0xff, 0x2f, 0xe1, /* bx r2          */

  /* func_a:                                */
  0x00, 0x00, 0x00, 0xea, /* b func_b       */

  /* beach:                                 */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr     */

  /* func_b:                                */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0xfc, 0xff, 0xff, 0xea, /* b beach        */

  /* func_c:                                */
  0x01, 0x30,             /* adds r0, 1     */
  0x08, 0x47              /* bx r1          */
);

TESTCASE (branch_thumb)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_BLOCK, branch_thumb, 3);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 4);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, start, func);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, end, func + 24);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 1, start, func + 40 + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 1, end, func + 44 + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 2, start, func + 24);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 2, end, func + 28);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 3, start, func + 32);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 3, end, func + 40);
}

TESTCODE (call_workload,
  0x02, 0x40, 0x2d, 0xe9, /* push {r1, lr}         */
  0x04, 0x10, 0x9f, 0xe5, /* ldr r1, workload_addr */
  0x31, 0xff, 0x2f, 0xe1, /* blx r1                */
  0x02, 0x80, 0xbd, 0xe8  /* pop {r1, pc}          */
);

TESTCASE (can_follow_workload)
{
  GumAddress func;
  guint32 (* call_workload_impl) (GumMemoryRange * runner_range);
  GumMemoryRange runner_range;
  guint32 crc, crc_followed;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  func = DUP_TESTCODE (call_workload);
  patch_code_pointer (func, 4 * 4, GUM_ADDRESS (pretend_workload));
  call_workload_impl = GSIZE_TO_POINTER (func);

  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);

  crc = call_workload_impl (&runner_range);

  g_test_log_set_fatal_handler (test_log_fatal_func, NULL);
  g_log_set_writer_func (test_log_writer_func, NULL, NULL);

  fixture->sink->mask = GUM_RET;
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  call_workload_impl (&runner_range);

  gum_stalker_unfollow_me (fixture->stalker);

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  crc_followed = call_workload_impl (&runner_range);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (crc_followed, ==, crc);

  GUM_ASSERT_EVENT_ADDR (ret, fixture->sink->events->len - 1, location,
      func + 12);
}

TESTCASE (performance)
{
  GumMemoryRange runner_range;
  GTimer * timer;
  gdouble normal_cold, normal_hot;
  gdouble stalker_cold, stalker_hot;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);

  timer = g_timer_new ();
  pretend_workload (&runner_range);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  normal_cold = g_timer_elapsed (timer, NULL);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  normal_hot = g_timer_elapsed (timer, NULL);

  g_test_log_set_fatal_handler (test_log_fatal_func, NULL);
  g_log_set_writer_func (test_log_writer_func, NULL, NULL);

  fixture->sink->mask = GUM_NOTHING;
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  stalker_cold = g_timer_elapsed (timer, NULL);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  stalker_hot = g_timer_elapsed (timer, NULL);

  gum_stalker_unfollow_me (fixture->stalker);

  g_timer_destroy (timer);

  g_print ("\n");
  g_print ("\t<normal_cold=%f>\n", normal_cold);
  g_print ("\t<normal_hot=%f>\n", normal_hot);
  g_print ("\t<stalker_cold=%f>\n", stalker_cold);
  g_print ("\t<stalker_hot=%f>\n", stalker_hot);
  g_print ("\t<ratio_cold=%f>\n", stalker_cold / normal_hot);
  g_print ("\t<ratio_hot=%f>\n", stalker_hot / normal_hot);
}

static gboolean
store_range_of_test_runner (const GumModuleDetails * details,
                            gpointer user_data)
{
  GumMemoryRange * runner_range = user_data;

  if (strstr (details->name, "gum-tests") != NULL)
  {
    *runner_range = *details->range;
    return FALSE;
  }

  return TRUE;
}

GUM_NOINLINE static guint32
pretend_workload (GumMemoryRange * runner_range)
{
  guint32 crc;
  lzma_stream stream = LZMA_STREAM_INIT;
  const uint32_t preset = LZMA_PRESET_DEFAULT;
  lzma_ret ret;
  guint8 * outbuf;
  gsize outbuf_size;
  const gsize outbuf_size_increment = 1024 * 1024;

  ret = lzma_easy_encoder (&stream, preset, LZMA_CHECK_CRC64);
  g_assert_cmpint (ret, ==, LZMA_OK);

  outbuf_size = outbuf_size_increment;
  outbuf = malloc (outbuf_size);

  stream.next_in = GSIZE_TO_POINTER (runner_range->base_address);
  stream.avail_in = MIN (runner_range->size, 65536);
  stream.next_out = outbuf;
  stream.avail_out = outbuf_size;

  while (TRUE)
  {
    ret = lzma_code (&stream, LZMA_FINISH);

    if (stream.avail_out == 0)
    {
      gsize compressed_size;

      compressed_size = outbuf_size;

      outbuf_size += outbuf_size_increment;
      outbuf = realloc (outbuf, outbuf_size);

      stream.next_out = outbuf + compressed_size;
      stream.avail_out = outbuf_size - compressed_size;
    }

    if (ret != LZMA_OK)
    {
      g_assert_cmpint (ret, ==, LZMA_STREAM_END);
      break;
    }
  }

  lzma_end (&stream);

  crc = crc32b (outbuf, stream.total_out);

  free (outbuf);

  return crc;
}

static guint32
crc32b (const guint8 * message,
        gsize size)
{
  guint32 crc;
  gint i;

  crc = 0xffffffff;

  for (i = 0; i != size; i++)
  {
    guint32 byte;
    gint j;

    byte = message[i];

    crc = crc ^ byte;

    for (j = 7; j >= 0; j--)
    {
      guint32 mask = -(crc & 1);

      crc = (crc >> 1) ^ (0xedb88320 & mask);
    }
  }

  return ~crc;
}

static gboolean
test_log_fatal_func (const gchar * log_domain,
                     GLogLevelFlags log_level,
                     const gchar * message,
                     gpointer user_data)
{
  return FALSE;
}

static GLogWriterOutput
test_log_writer_func (GLogLevelFlags log_level,
                      const GLogField * fields,
                      gsize n_fields,
                      gpointer user_data)
{
  return G_LOG_WRITER_HANDLED;
}

TESTCASE (custom_transformer)
{
  fixture->transformer = gum_stalker_transformer_make_from_callback (
      duplicate_adds, NULL, NULL);

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 4);
}

static void
duplicate_adds (GumStalkerIterator * iterator,
                GumStalkerOutput * output,
                gpointer user_data)
{
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    gum_stalker_iterator_keep (iterator);

    if (insn->id == ARM_INS_ADD)
      gum_arm_writer_put_bytes (output->writer.arm, insn->bytes, insn->size);
  }
}

TESTCASE (arm_callout)
{
  gpointer magic = GSIZE_TO_POINTER (0xbaadface);

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      transform_arm_return_value, magic, NULL);

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 42);
}

static void
transform_arm_return_value (GumStalkerIterator * iterator,
                            GumStalkerOutput * output,
                            gpointer user_data)
{
  gpointer magic = user_data;
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (is_arm_mov_pc_lr (insn->bytes, insn->size))
    {
      gum_stalker_iterator_put_callout (iterator, on_arm_ret, magic, NULL);
    }

    gum_stalker_iterator_keep (iterator);
  }
}

static void
on_arm_ret (GumCpuContext * cpu_context,
            gpointer user_data)
{
  gpointer magic = user_data;
  const guint8 * bytes = GSIZE_TO_POINTER (cpu_context->pc);

  g_assert_cmphex (GPOINTER_TO_SIZE (magic), ==, 0xbaadface);
  g_assert_cmpuint (cpu_context->r[0], ==, 2);
  g_assert_true (is_arm_mov_pc_lr (bytes, 4));

  cpu_context->r[0] = 42;
}

static gboolean
is_arm_mov_pc_lr (const guint8 * bytes,
                  gsize size)
{
  const guint8 mov_pc_lr[] = { 0x0e, 0xf0, 0xa0, 0xe1 };

  if (size != sizeof (mov_pc_lr))
    return FALSE;

  return memcmp (bytes, mov_pc_lr, size) == 0;
}

TESTCASE (thumb_callout)
{
  gpointer magic = GSIZE_TO_POINTER (0xfacef00d);

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      transform_thumb_return_value, magic, NULL);

  INVOKE_THUMB_EXPECTING (GUM_NOTHING, thumb_flat_code, 24);
}

static void
transform_thumb_return_value (GumStalkerIterator * iterator,
                              GumStalkerOutput * output,
                              gpointer user_data)
{
  gpointer magic = user_data;
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (is_thumb_pop_pc (insn->bytes, insn->size))
    {
      gum_stalker_iterator_put_callout (iterator, on_thumb_ret, magic, NULL);
    }

    gum_stalker_iterator_keep (iterator);
  }
}

static void
on_thumb_ret (GumCpuContext * cpu_context,
              gpointer user_data)
{
  gpointer magic = user_data;
  const guint8 * bytes = GSIZE_TO_POINTER (cpu_context->pc);

  g_assert_cmphex (GPOINTER_TO_SIZE (magic), ==, 0xfacef00d);
  g_assert_cmpuint (cpu_context->r[0], ==, 2);
  g_assert_true (is_thumb_pop_pc (bytes, 2));

  cpu_context->r[0] = 24;
}

static gboolean
is_thumb_pop_pc (const guint8 * bytes,
                 gsize size)
{
  guint8 pop_pc[] = { 0x00, 0xbd };

  if (size != sizeof (pop_pc))
    return FALSE;

  return memcmp (bytes, pop_pc, size) == 0;
}

TESTCODE (arm_simple_call,
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}      */
  0x0d, 0x00, 0x00, 0xe3, /* mov r0, 13     */
  0x00, 0x00, 0x00, 0xeb, /* bl bump_number */
  0x04, 0xf0, 0x9d, 0xe4, /* pop {pc}       */
  /* bump_number:                           */
  0x25, 0x00, 0x80, 0xe2, /* add r0, 37     */
  0x1e, 0xff, 0x2f, 0xe1, /* bx lr          */
);

TESTCASE (arm_transformer_should_be_able_to_replace_call_with_callout)
{
  fixture->transformer = gum_stalker_transformer_make_from_callback (
      replace_call_with_callout, NULL, NULL);

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_simple_call, 0xc001);
}

static void
replace_call_with_callout (GumStalkerIterator * iterator,
                           GumStalkerOutput * output,
                           gpointer user_data)
{
  const cs_insn * insn;
  static int insn_num = 0;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (insn_num == 4)
      gum_stalker_iterator_put_callout (iterator, callout_set_cool, NULL, NULL);
    else
      gum_stalker_iterator_keep (iterator);
    insn_num++;
  }
}

TESTCODE (arm_simple_jumpout,
  0x0d, 0x00, 0x00, 0xe3, /* mov r0, 13    */
  0xff, 0xff, 0xff, 0xea, /* b bump_number */
  /* bump_number:                          */
  0x25, 0x00, 0x80, 0xe2, /* add r0, 37    */
  0x1e, 0xff, 0x2f, 0xe1, /* bx lr         */
);

TESTCASE (arm_transformer_should_be_able_to_replace_jumpout_with_callout)
{
  fixture->transformer = gum_stalker_transformer_make_from_callback (
      replace_jumpout_with_callout, NULL, NULL);

  INVOKE_ARM_EXPECTING (GUM_EXEC, arm_simple_jumpout, 0xc001);
}

static void
replace_jumpout_with_callout (GumStalkerIterator * iterator,
                              GumStalkerOutput * output,
                              gpointer user_data)
{
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (insn->id == ARM_INS_B)
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
  cpu_context->r[0] = 0xc001;
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

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);
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

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);
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

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);
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

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);
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

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);
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

  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);
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

TESTCODE (arm_test_is_finished,
  0x00, 0x00, 0xa0, 0xe3, /* mov r0, 0       */
  0x1e, 0xff, 0x2f, 0xe1, /* bx lr           */
);

TESTCODE (thumb_test_is_finished,
  0x00, 0x1a,             /* subs r0, r0, r0 */
  0x70, 0x47,             /* bx lr           */
);

TESTCASE (arm_invalidation_for_current_thread_should_be_supported)
{
  test_invalidation_for_current_thread_with_target (
      DUP_TESTCODE (arm_test_is_finished),
      fixture);
}

TESTCASE (thumb_invalidation_for_current_thread_should_be_supported)
{
  test_invalidation_for_current_thread_with_target (
      DUP_TESTCODE (thumb_test_is_finished) + 1,
      fixture);
}

static void
test_invalidation_for_current_thread_with_target (
    GumAddress target,
    TestArmStalkerFixture * fixture)
{
  gboolean (* test_is_finished) (void) = GSIZE_TO_POINTER (target);
  InvalidationTransformContext ctx;

  ctx.stalker = fixture->stalker;
  ctx.target_function = test_is_finished;
  ctx.n = 0;

  g_clear_object (&fixture->transformer);
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
          insn->address == (GPOINTER_TO_SIZE (ctx->target_function) & ~1);

      if (in_target_function && ctx->n == 0)
      {
        gum_stalker_iterator_put_callout (iterator,
            invalidate_after_three_calls, ctx, NULL);
      }
    }

    if (insn->id == ARM_INS_BX && in_target_function && ctx->n == 3)
    {
      if (output->encoding == GUM_INSTRUCTION_SPECIAL)
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

TESTCASE (arm_invalidation_for_specific_thread_should_be_supported)
{
  test_invalidation_for_specific_thread_with_target (
      DUP_TESTCODE (arm_test_is_finished),
      fixture);
}

TESTCASE (thumb_invalidation_for_specific_thread_should_be_supported)
{
  test_invalidation_for_specific_thread_with_target (
      DUP_TESTCODE (thumb_test_is_finished) + 1,
      fixture);
}

static void
test_invalidation_for_specific_thread_with_target (
    GumAddress target,
    TestArmStalkerFixture * fixture)
{
  gboolean (* test_is_finished) (void) = GSIZE_TO_POINTER (target);
  InvalidationTarget a, b;

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
                           TestArmStalkerFixture * fixture)
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
  gboolean (* test_is_finished) (void) = target->ctx.target_function;
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
          insn->address == (GPOINTER_TO_SIZE (ctx->target_function) & ~1);
      if (in_target_function)
        ctx->n++;
    }

    if (insn->id == ARM_INS_BX && in_target_function && ctx->n > 1)
    {
      if (output->encoding == GUM_INSTRUCTION_SPECIAL)
     
"""


```