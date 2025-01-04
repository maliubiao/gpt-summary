Response:
The user wants a summary of the functionality of the provided C code snippet, which is part of the Frida dynamic instrumentation tool. I need to analyze the code, identify its core purpose, and relate it to reverse engineering, low-level programming, and potential user errors.

The code defines several test cases for the Frida Stalker component, specifically focusing on how it handles various ARM and Thumb instructions that modify the program counter (PC), leading to control flow changes.

**Plan:**
1. Identify the main purpose of the code: testing the Stalker's ability to track control flow.
2. Analyze individual test cases and their functionality.
3. Relate the test cases to reverse engineering concepts.
4. Highlight connections to binary, Linux/Android kernel, and frameworks.
5. Look for examples of logical reasoning in the tests.
6. Identify potential user errors.
7. Explain how a user might reach this code.
8. Summarize the functionality of this specific part.
这是 `frida/subprojects/frida-gum/tests/core/arch-arm/stalker-arm.c` 文件的一部分，其主要功能是**测试 Frida Stalker 在 ARM 架构下对返回指令的处理和事件生成能力**。

具体来说，这部分代码定义了一系列针对 ARM 和 Thumb 指令集的测试用例，这些指令会影响程序的返回流程，例如通过修改 PC 寄存器来实现返回。Stalker 是 Frida 的一个核心组件，用于跟踪程序执行流程。这些测试用例旨在验证 Stalker 是否能正确识别和报告这些返回事件。

**功能归纳:**

1. **测试 ARM 和 Thumb 指令集中的返回指令：**  代码中定义了多种模拟返回行为的指令序列，例如 `pop {..., pc}`、`ldm ..., {..., pc}`、`mov pc, lr` 等。这些指令在不同的场景下被执行，以测试 Stalker 的覆盖范围。
2. **验证返回事件的生成：**  每个测试用例都断言 Stalker 生成了预期的 `GUM_RET` 事件。这些事件记录了返回发生的位置 (`location`)、返回的目标地址 (`target`) 以及调用深度 (`depth`)。
3. **检查事件的属性：** 测试用例使用 `GUM_ASSERT_EVENT_ADDR` 宏来断言生成的返回事件的 `location`、`target` 和 `depth` 属性是否与预期值相符。这确保了 Stalker 能够准确地识别返回指令并提取相关信息。
4. **区分 ARM 和 Thumb 模式：** 代码中分别提供了针对 ARM 和 Thumb 指令集的测试用例，这体现了 Stalker 需要处理不同指令集架构的能力。Thumb 指令通常地址是奇数，而 ARM 指令地址是偶数，测试用例中也注意了这一点。

**与逆向方法的关联及举例说明:**

* **控制流分析：**  逆向工程中，理解程序的控制流至关重要。Stalker 模拟了在动态分析过程中跟踪程序执行的能力。通过观察 Stalker 生成的 `GUM_RET` 事件，逆向工程师可以了解函数调用的返回情况，构建程序的调用图。例如，在分析一个使用了自定义返回机制的程序时，Stalker 可以帮助识别这些特殊的返回点。
    * **举例：**  如果一个恶意软件使用 `pop {r0-r3, pc}` 而不是标准的 `bx lr` 进行返回，Stalker 应该能够捕获到这个非标准返回，并记录下返回的位置和目标地址，这有助于逆向分析人员理解其控制流。

**涉及二进制底层、Linux/Android 内核及框架的知识及举例说明:**

* **ARM/Thumb 指令集：** 代码直接操作 ARM 和 Thumb 汇编指令的二进制表示。理解这些指令的编码格式和执行方式是编写这些测试用例的基础。例如，`0xf0, 0x81, 0xbd, 0xe8` 是 ARM 指令 `pop {r4-r8, pc}` 的二进制编码。
* **寄存器操作：** 测试用例涉及对 PC 寄存器的操作，PC 寄存器存储着下一条要执行的指令地址，控制着程序的执行流程。返回指令通常会修改 PC 寄存器的值。
* **栈操作：**  `push` 和 `pop` 指令涉及到栈的使用。返回地址通常会被压入栈中，然后通过 `pop` 指令恢复到 PC 寄存器。例如，`push {lr}` 将链接寄存器 (LR) 的值压入栈中，`pop {pc}` 则将栈顶的值弹出到 PC 寄存器，实现返回。
* **函数调用约定：** 虽然这部分代码没有直接涉及复杂的函数调用约定，但返回机制是函数调用约定的一部分。Stalker 需要理解不同平台和架构的调用约定，才能正确识别返回事件。
* **Frida 框架：**  这段代码是 Frida 框架内部的测试代码，它使用了 Frida 提供的 API（例如 `GUM_ASSERT_EVENT_ADDR`）来验证 Stalker 的行为。理解 Frida 的架构和工作原理有助于理解这段代码的目的。

**逻辑推理、假设输入与输出:**

每个 `TESTCASE` 都是一个逻辑推理的体现。

* **假设输入：**  一段特定的 ARM 或 Thumb 指令序列（例如 `arm_pop_pc` 中的指令）。
* **预期输出：** Stalker 应该生成特定数量和类型的事件，并且这些事件的属性（如 `location`, `target`, `depth`) 应该与预期值相符。
* **推理过程：**  基于对 ARM/Thumb 指令执行机制的理解，以及 Stalker 的工作原理，可以推断出在执行给定指令序列后，Stalker 应该会生成哪些事件。例如，对于 `arm_pop_pc`，执行 `pop {r4-r8, pc}` 指令会导致程序跳转到之前 `push {r4-r8, lr}` 指令保存的返回地址，因此 Stalker 应该生成一个 `GUM_RET` 事件。

**用户或编程常见的使用错误及举例说明:**

虽然这段代码是测试代码，但它可以帮助理解 Stalker 的工作方式，从而避免用户在使用 Frida 时可能犯的错误。

* **误解 Stalker 的跟踪范围：** 用户可能错误地认为 Stalker 可以跟踪所有类型的控制流变化。但实际上，Stalker 的准确性依赖于其对目标架构指令的理解。如果目标程序使用了非常规的控制流转移方式，Stalker 可能无法正确跟踪。
* **错误配置事件掩码：**  用户可以通过配置事件掩码来选择 Stalker 跟踪的事件类型。如果用户没有启用 `GUM_RET` 事件的跟踪，即使程序发生了返回，用户也无法观察到相应的事件。
* **不理解 Thumb 模式切换：**  ARM 架构支持 ARM 和 Thumb 两种指令集。如果用户不了解这两种模式的切换机制，可能会对 Stalker 报告的地址感到困惑。例如，Thumb 代码的地址通常是奇数，而 ARM 代码的地址是偶数。

**用户操作如何一步步的到达这里，作为调试线索:**

1. **用户想要调试一个运行在 ARM 设备上的程序。**
2. **用户选择使用 Frida 进行动态分析。**
3. **用户可能希望跟踪函数的调用和返回，以理解程序的执行流程。**
4. **用户可能会遇到 Stalker 没有正确报告返回事件的情况，或者对 Stalker 报告的返回事件感到困惑。**
5. **为了理解 Stalker 的工作原理，或者为了排查问题，用户可能会查看 Frida 的源代码，特别是与 Stalker 和 ARM 架构相关的代码。**
6. **用户最终可能会找到 `frida/subprojects/frida-gum/tests/core/arch-arm/stalker-arm.c` 这个文件，并阅读其中的测试用例，以了解 Stalker 是如何处理返回指令的。**

总而言之，这部分代码是 Frida Stalker 组件在 ARM 架构下的返回指令处理功能的单元测试，用于确保 Stalker 能够准确地识别和报告程序执行过程中的返回事件，这对于动态逆向分析至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-arm/stalker-arm.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共4部分，请归纳一下它的功能

"""
cmpuint (fixture->sink->events->len, ==, 2);

    GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 20 + 1);
    GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 14 + 1);
    GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

    GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 14 + 1);
    GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
  }
}

TESTCODE (arm_pop_pc,
  0xf0, 0x41, 0x2d, 0xe9, /* push {r4-r8, lr} */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x00, 0x00, 0x00, 0xeb, /* bl inner         */
  0xf0, 0x81, 0xbd, 0xe8, /* pop {r4-r8, pc}  */

  /* inner:                                   */
  0x0e, 0x40, 0x2d, 0xe9, /* push {r1-r3, lr} */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x0e, 0x80, 0xbd, 0xe8  /* pop {r1-r3, pc}  */
);

TESTCASE (arm_pop_pc_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_RET, arm_pop_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 28);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
}

TESTCODE (thumb_pop_pc,
  0xf0, 0xb5,             /* push {r4-r7, lr} */
  0x00, 0x1a,             /* subs r0, r0, r0  */
  0x01, 0x30,             /* adds r0, 1       */
  0x00, 0xf0, 0x01, 0xf8, /* bl inner         */
  0xf0, 0xbd,             /* pop {r4-r7, pc}  */

  /* inner:                                   */
  0x0e, 0xb5,             /* push {r1-r3, lr} */
  0x01, 0x30,             /* adds r0, 1       */
  0x0e, 0xbd              /* pop {r1-r3, pc}  */
);

TESTCASE (thumb_pop_pc_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_pop_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 16 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 10 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 10 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
}

TESTCODE (arm_pop_just_pc,
  0xf0, 0x41, 0x2d, 0xe9, /* push {r4-r8, lr} */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x00, 0x00, 0x00, 0xeb, /* bl inner         */
  0xf0, 0x81, 0xbd, 0xe8, /* pop {r4-r8, pc}  */

  /* inner:                                   */
  0x00, 0x40, 0x2d, 0xe9, /* stmdb sp!, {lr}  */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x00, 0x80, 0xbd, 0xe8  /* ldm sp!, {pc}    */
);

TESTCASE (arm_pop_just_pc_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_RET, arm_pop_just_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 28);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
}

TESTCODE (thumb_pop_just_pc,
  0xf0, 0xb5,             /* push {r4-r7, lr} */
  0x00, 0x1a,             /* subs r0, r0, r0  */
  0x01, 0x30,             /* adds r0, 1       */
  0x00, 0xf0, 0x01, 0xf8, /* bl inner         */
  0xf0, 0xbd,             /* pop {r4-r7, pc}  */

  /* inner:                                   */
  0x00, 0xb5,             /* push {lr}        */
  0x01, 0x30,             /* adds r0, 1       */
  0x00, 0xbd              /* pop {pc}         */
);

TESTCASE (thumb_pop_just_pc_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_pop_just_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 16 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 10 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 10 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
}

TESTCODE (thumb_pop_just_pc2,
  0xf0, 0xb5,             /* push {r4-r7, lr} */
  0x00, 0x1a,             /* subs r0, r0, r0  */
  0x01, 0x30,             /* adds r0, 1       */
  0x00, 0xf0, 0x01, 0xf8, /* bl inner         */
  0xf0, 0xbd,             /* pop {r4-r7, pc}  */

  /* inner:                                   */
  0x00, 0xb5,             /* push {lr}        */
  0x01, 0x30,             /* adds r0, 1       */
  0x5d, 0xf8, 0x04, 0xfb, /* ldr pc, [sp], #4 */
);

TESTCASE (thumb_pop_just_pc2_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_pop_just_pc2, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 10 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 0);
}

TESTCODE (arm_ldm_pc,
  0xf0, 0x41, 0x2d, 0xe9, /* push {r4-r8, lr}       */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0         */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1          */
  0x00, 0x00, 0x00, 0xeb, /* bl inner               */
  0xf0, 0x81, 0xbd, 0xe8, /* pop {r4-r8, pc}        */

  /* inner:                                         */
  0x00, 0x30, 0x8d, 0xe2, /* add r3, sp, 0          */
  0xf0, 0x41, 0x23, 0xe9, /* stmdb r3!, {r4-r8, lr} */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1          */
  0xf0, 0x81, 0xb3, 0xe8  /* ldm r3!, {r4-r8, pc}   */
);

TESTCASE (arm_ldm_pc_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_RET, arm_ldm_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 32);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
}

TESTCODE (thumb_ldm_pc,
  0xf0, 0xb5,             /* push {r4-r7, lr}        */
  0x00, 0x1a,             /* subs r0, r0, r0         */
  0x01, 0x30,             /* adds r0, 1              */
  0x00, 0xf0, 0x01, 0xf8, /* bl inner                */
  0xf0, 0xbd,             /* pop {r4-r7, pc}         */

  /* inner:                                          */
  0x00, 0xab,             /* add r3, sp, 0           */
  0x23, 0xe9, 0x06, 0x40, /* stmdb r3!, {r1, r2, lr} */
  0x01, 0x30,             /* adds r0, 1              */
  0xb3, 0xe8, 0x06, 0x80  /* ldm.w r3!, {r1, r2, pc} */
);

TESTCASE (thumb_ldm_pc_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_ldm_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);

  g_assert_cmpint (
      g_array_index (fixture->sink->events, GumEvent, 0).type, ==, GUM_RET);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 20 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 10 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 10 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
}

TESTCODE (arm_b_cc,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x01, 0x10, 0x41, 0xe0, /* sub r1, r1, r1 */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0      */
  0x00, 0x00, 0x00, 0x0a, /* beq after_a    */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  /* after_a:                               */

  0x01, 0x00, 0x51, 0xe3, /* cmp r1, 1      */
  0x00, 0x00, 0x00, 0x0a, /* beq after_b    */
  0x02, 0x00, 0x80, 0xe2, /* add r0, r0, 2  */
  /* after_b:                               */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0      */
  0x00, 0x00, 0x00, 0xaa, /* bge after_c    */
  0x04, 0x00, 0x80, 0xe2, /* add r0, r0, 4  */
  /* after_c:                               */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0      */
  0x00, 0x00, 0x00, 0xba, /* blt after_d    */
  0x08, 0x00, 0x80, 0xe2, /* add r0, r0, 8  */
  /* after_d:                               */

  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr     */
);

TESTCASE (arm_branch_cc_block_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_BLOCK, arm_b_cc, 10);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 4);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, start, func);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, end, func + 16);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 1, start, func + 20);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 1, end, func + 28);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 2, start, func + 28);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 2, end, func + 40);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 3, start, func + 44);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 3, end, func + 52);
}

TESTCODE (thumb_b_cc,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x49, 0x1a, /* subs r1, r1, r1 */

  0x00, 0x29, /* cmp r1, 0       */
  0x00, 0xd0, /* beq after_a     */
  0x01, 0x30, /* adds r0, 1      */
  /* after_a:                    */

  0x01, 0x29, /* cmp r1, 1       */
  0x00, 0xd0, /* beq after_b     */
  0x02, 0x30, /* adds r0, 2      */
  /* after_b:                    */

  0x00, 0x29, /* cmp r1, 0       */
  0x00, 0xda, /* bge after_c     */
  0x04, 0x30, /* adds r0, 4      */
  /* after_c:                    */

  0x00, 0x29, /* cmp r1, 0       */
  0x00, 0xdb, /* blt after_d     */
  0x08, 0x30, /* adds r0, 8      */
  /* after_d:                    */

  0x00, 0xbd  /* pop {pc}        */
);

TESTCASE (thumb_branch_cc_block_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_BLOCK, thumb_b_cc, 10);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 4);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, start, func + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, end, func + 10 + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 1, start, func + 12 + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 1, end, func + 16 + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 2, start, func + 16 + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 2, end, func + 22 + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 3, start, func + 24 + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 3, end, func + 28 + 1);
}

TESTCODE (thumb_cbz_cbnz,
  0x00, 0xb5, /* push {lr}        */
  0x00, 0x1a, /* subs r0, r0, r0  */
  0x49, 0x1a, /* subs r1, r1, r1  */
  0x92, 0x1a, /* subs r2, r2, r2  */
  0x01, 0x32, /* adds r2, 1       */

  0x01, 0xb1, /* cbz r1, after_a  */
  0x01, 0x30, /* adds r0, 1       */
  /* after_a:                     */

  0x01, 0xb9, /* cbnz r1, after_b */
  0x02, 0x30, /* adds r0, 2       */
  /* after_b:                     */

  0x02, 0xb1, /* cbz r2, after_c  */
  0x04, 0x30, /* adds r0, 4       */
  /* after_c:                     */

  0x02, 0xb9, /* cbnz r2, after_d */
  0x08, 0x30, /* adds r0, 8       */
  /* after_d:                     */

  0x00, 0xbd  /* pop {pc}         */
);

TESTCASE (thumb_cbz_cbnz_block_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_BLOCK, thumb_cbz_cbnz, 6);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 4);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, start, func + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, end, func + 12 + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 1, start, func + 14 + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 1, end, func + 16 + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 2, start, func + 16 + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 2, end, func + 20 + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 3, start, func + 20 + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 3, end, func + 24 + 1);
}

TESTCODE (thumb2_mov_pc_reg,
  0x40, 0xb5, /* push {r6, lr}    */
  0x00, 0x1a, /* subs r0, r0, r0  */
  0x01, 0x4e, /* ldr r6, [pc, #4] */
  0xb7, 0x46, /* mov pc, r6       */

  0x0a, 0xde, /* udf 0x10         */
  0x0a, 0xde, /* udf 0x10         */
  /* inner_addr:                  */
  0xaa, 0xbb, 0xcc, 0xdd,

  /* inner:                       */
  0x01, 0x30, /* adds r0, #1      */
  0x40, 0xbd  /* pop {r6, pc}     */
);

TESTCASE (thumb2_mov_pc_reg_exec_events_generated)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb2_mov_pc_reg);
  patch_code_pointer (func, 6 * 2, func + (8 * 2) + 1);

  fixture->sink->mask = GUM_EXEC;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 1);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 6);

  GUM_ASSERT_EVENT_ADDR (exec, 2, location, func +  0 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 3, location, func +  2 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 4, location, func +  4 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 5, location, func +  6 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 16 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 7, location, func + 18 + 1);
}

TESTCASE (thumb2_mov_pc_reg_without_thumb_bit_set)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb2_mov_pc_reg);
  patch_code_pointer (func, 6 * 2, func + (8 * 2) + 0);

  fixture->sink->mask = GUM_EXEC;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 1);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 6);

  GUM_ASSERT_EVENT_ADDR (exec, 2, location, func +  0 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 3, location, func +  2 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 4, location, func +  4 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 5, location, func +  6 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 16 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 7, location, func + 18 + 1);
}

TESTCODE (thumb2_mov_pc_reg_no_clobber_reg,
  0x60, 0xb5, /* push {r5, r6, lr} */
  0x00, 0x1a, /* subs r0, r0, r0   */
  0x01, 0x4e, /* ldr r6, [pc, #4]  */
  0x35, 0x46, /* mov r5, r6        */
  0xb7, 0x46, /* mov pc, r6        */

  0x0a, 0xde, /* udf 0x10          */
  /* inner_addr:                   */
  0xaa, 0xbb, 0xcc, 0xdd,

  /* inner:                        */
  0xa8, 0x1b, /* subs r0, r5, r6   */
  0x60, 0xbd  /* pop {r5,r6, pc}   */
);

TESTCASE (thumb2_mov_pc_reg_no_clobber_reg)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb2_mov_pc_reg_no_clobber_reg);
  patch_code_pointer (func, 6 * 2, func + (8 * 2) + 0);

  fixture->sink->mask = GUM_EXEC;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 7);

  GUM_ASSERT_EVENT_ADDR (exec, 2, location, func +  0 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 3, location, func +  2 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 4, location, func +  4 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 5, location, func +  6 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 6, location, func +  8 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 7, location, func + 16 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 8, location, func + 18 + 1);
}

TESTCODE (arm_bl_cc,
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}         */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0    */
  0x01, 0x10, 0x41, 0xe0, /* sub r1, r1, r1    */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0         */
  0x06, 0x00, 0x00, 0x0b, /* bleq func_a       */

  0x01, 0x00, 0x51, 0xe3, /* cmp r1, 1         */
  0x06, 0x00, 0x00, 0x0b, /* bleq func_b       */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0         */
  0x06, 0x00, 0x00, 0xab, /* blge func_c       */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0         */
  0x06, 0x00, 0x00, 0xbb, /* bllt func_d       */

  0x04, 0xf0, 0x9d, 0xe4, /* pop {pc}          */

  /* func_a:                                   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr        */

  /* func_b:                                   */
  0x02, 0x00, 0x80, 0xe2, /* add r0, r0, 2     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr        */

  /* func_c:                                   */
  0x04, 0x00, 0x80, 0xe2, /* add r0, r0, 4     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr        */

  /* func_d:                                   */
  0x08, 0x00, 0x80, 0xe2, /* add r0, r0, 8     */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr        */
);

TESTCASE (arm_branch_link_cc_block_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_CALL, arm_bl_cc, 5);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 2);

  GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 16);
  GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 48);

  GUM_ASSERT_EVENT_ADDR (call, 2, location, func + 32);
  GUM_ASSERT_EVENT_ADDR (call, 2, target, func + 64);
}

TESTCODE (arm_cc_excluded_range,
  0x00, 0x40, 0x2d, 0xe9, /* stmdb sp!, {lr}   */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0    */
  0x01, 0x10, 0x41, 0xe0, /* sub r1, r1, r1    */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0         */
  0x03, 0x00, 0x00, 0x0b, /* bleq func_a       */

  0x00, 0x00, 0x51, 0xe3, /* cmp r1, 0         */
  0x05, 0x00, 0x00, 0x1b, /* blne func_b       */

  0x00, 0x40, 0xbd, 0xe8, /* ldm sp!, {lr}     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr        */

  /* func_a:                                   */
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}         */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1     */
  0x04, 0x00, 0x00, 0xeb, /* bl func_c         */
  0x04, 0xf0, 0x9d, 0xe4, /* pop {pc}          */

  /* func_b:                                   */
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}         */
  0x02, 0x00, 0x80, 0xe2, /* add r0, r0, 2     */
  0x00, 0x00, 0x00, 0xeb, /* bl func_c         */
  0x04, 0xf0, 0x9d, 0xe4, /* pop {pc}          */

  /* func_c:                                   */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr        */
);

TESTCASE (arm_cc_excluded_range)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_cc_excluded_range);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 36,
      .size = 36
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_CALL;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 1);

    g_assert_cmpuint (fixture->sink->events->len, ==,
        INVOKER_CALL_INSN_COUNT + 1);

    GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 16);
    GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 36);
  }
}

TESTCODE (arm_ldr_pc,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0     */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1      */
  0x04, 0xf0, 0x9f, 0xe5, /* ldr pc, inner_addr */
  0xf0, 0x01, 0xf0, 0xe7, /* udf 0x10           */

  0xec, 0xec, 0xec, 0xec,
  /* inner_addr:                                */
  0xaa, 0xbb, 0xcc, 0xdd,

  /* inner:                                     */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1      */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr         */
);

TESTCASE (arm_ldr_pc)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_ldr_pc);
  patch_code_pointer (func, 5 * 4, func + (6 * 4));

  fixture->sink->mask = GUM_BLOCK;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, start, func);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, end, func + 12);
}

TESTCODE (arm_ldr_pc_pre_index_imm,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x04, 0x10, 0x8f, 0xe2, /* adr r1, imm_data */
  0x08, 0xf0, 0xb1, 0xe5, /* ldr pc, [r1, 8]! */
  0xf0, 0x01, 0xf0, 0xe7, /* udf 0x10         */

  /* imm_data:                                */
  0xec, 0xec, 0xec, 0xec,
  0xf0, 0xf0, 0xf0, 0xf0,
  /* inner_addr:                              */
  0xaa, 0xbb, 0xcc, 0xdd,
  0xba, 0xba, 0xba, 0xba,

  /* inner:                                   */
  0x04, 0x10, 0x91, 0xe5, /* ldr r1, [r1, 4]  */
  0x01, 0x00, 0x80, 0xe0, /* add r0, r0, r1   */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr       */
);

TESTCASE (arm_ldr_pc_pre_index_imm)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_ldr_pc_pre_index_imm);
  patch_code_pointer (func, 7 * 4, func + (9 * 4));

  fixture->sink->mask = GUM_BLOCK;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 0xbabababb);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, start, func);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, end, func + 16);
}

TESTCODE (arm_ldr_pc_post_index_imm,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0     */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1      */
  0x04, 0x10, 0x8f, 0xe2, /* adr r1, inner_addr */
  0x08, 0xf0, 0x91, 0xe4, /* ldr pc, [r1], 8    */
  0xf0, 0x01, 0xf0, 0xe7, /* udf 0x10           */

  /* inner_addr:                                */
  0xaa, 0xbb, 0xcc, 0xdd,
  0xf0, 0xf0, 0xf0, 0xf0,
  0xba, 0xba, 0xba, 0xba,

  /* inner:                                     */
  0x00, 0x10, 0x91, 0xe5, /* ldr r1, [r1]       */
  0x01, 0x00, 0x80, 0xe0, /* add r0, r0, r1     */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr         */
);

TESTCASE (arm_ldr_pc_post_index_imm)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_ldr_pc_post_index_imm);
  patch_code_pointer (func, 5 * 4, func + (8 * 4));

  fixture->sink->mask = GUM_BLOCK;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 0xbabababb);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, start, func);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, end, func + 16);
}

TESTCODE (arm_ldr_pc_pre_index_imm_negative,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0        */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1         */
  0x0c, 0x10, 0x8f, 0xe2, /* adr r1, negative_data */
  0x08, 0xf0, 0x31, 0xe5, /* ldr pc, [r1, -8]!     */
  0xf0, 0x01, 0xf0, 0xe7, /* udf 0x10              */

  /* inner_addr:                                   */
  0xaa, 0xbb, 0xcc, 0xdd,
  0xec, 0xec, 0xec, 0xec,
  /* negative_data:                                */
  0xf0, 0xf0, 0xf0, 0xf0,
  0xba, 0xba, 0xba, 0xba,

  /* inner:                                        */
  0x0c, 0x10, 0x91, 0xe5, /* ldr r1, [r1, 12]      */
  0x01, 0x00, 0x80, 0xe0, /* add r0, r0, r1        */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr            */
);

TESTCASE (arm_ldr_pc_pre_index_imm_negative)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_ldr_pc_pre_index_imm_negative);
  patch_code_pointer (func, 5 * 4, func + (9 * 4));

  fixture->sink->mask = GUM_BLOCK;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 0xbabababb);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, start, func);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, end, func + 16);
}

TESTCODE (arm_ldr_pc_post_index_imm_negative,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0     */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1      */
  0x0c, 0x10, 0x8f, 0xe2, /* adr r1, inner_addr */
  0x08, 0xf0, 0x11, 0xe4, /* ldr pc, [r1], -8   */
  0xf0, 0x01, 0xf0, 0xe7, /* udf 0x10           */

  0xba, 0xba, 0xba, 0xba,
  0xf0, 0xf0, 0xf0, 0xf0,
  /* inner_addr:                                */
  0xaa, 0xbb, 0xcc, 0xdd,

  /* inner:                                     */
  0x00, 0x10, 0x91, 0xe5, /* ldr r1, [r1]       */
  0x01, 0x00, 0x80, 0xe0, /* add r0, r0, r1     */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr         */
);

TESTCASE (arm_ldr_pc_post_index_imm_negative)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_ldr_pc_post_index_imm_negative);
  patch_code_pointer (func, 7 * 4, func + (8 * 4));

  fixture->sink->mask = GUM_BLOCK;
  g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 0xbabababb);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, start, func);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, end, func + 16);
}

TESTCODE (arm_ldr_pc_shift_code,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0           */
  0x04, 0x00, 0x80, 0xe2, /* add r0, r0, 4            */
  0x00, 0xf1, 0x9f, 0xe7, /* ldr pc, [pc, r0, lsl #2] */
  0xf0, 0x01, 0xf0, 0xe7, /* udf 0x10                 */

  0x22, 0x22, 0x22, 0x22,
  0x44, 0x44, 0x44, 0x44,
  0x66, 0x66, 0x66, 0x66,
  0x88, 0x88, 0x88, 0x88,
  0xaa, 0xaa, 0xaa, 0xaa, /* Branch Target            */

  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr               */
);

TESTCASE (arm_ldr_pc_shift)
{
  GumAddress func;
  guint32 * code;

  func = DUP_TESTCODE (arm_ldr_pc_shift_code);
  code = GSIZE_TO_POINTER (func);
  g_assert_cmpuint (code[8], ==, 0xaaaaaaaa);
  patch_code_pointer (func, 8 * sizeof (gsize), func + (9 * sizeof (gsize)));

  g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCODE (arm_sub_pc,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x01, 0x00, 0x00, 0xea, /* b part_two     */

  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr     */

  /* part_two:                              */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x14, 0xf0, 0x4f, 0xe2  /* sub pc, pc, 20 */
);

TESTCASE (arm_sub_pc)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_BLOCK, arm_sub_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 2);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, start, func);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, end, func + 8);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 1, start, func + 16);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 1, end, func + 24);
}

TESTCODE (arm_add_pc,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x04, 0xf0, 0x8f, 0xe2, /* add pc, pc, 4  */

  /* beach:                                 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr     */

  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0xfb, 0xff, 0xff, 0xea  /* b beach        */
);

TESTCASE (arm_add_pc)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_BLOCK, arm_add_pc, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 2);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, start, func);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, end, func + 8);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 1, start, func + 16);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 1, end, func + 24);
}

TESTCODE (arm_ldmia_pc,
  0x0d, 0xc0, 0xa0, 0xe1, /* mov r12, sp                                   */
  0x78, 0xd8, 0x2d, 0xe9, /* stmdb sp!, {r3, r4, r5, r6, r11, r12, lr, pc} */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0                                */
  0x78, 0xa8, 0x9d, 0xe8, /* ldmia sp, {r3, r4, r5, r6, r11, sp, pc}       */
);

TESTCASE (arm_ldmia_pc)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_BLOCK, arm_ldmia_pc, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, start, func);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX + 0, end, func + 16);
}

TESTCODE (thumb_it_eq,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x00, 0x28, /* cmp r0, #0      */
  0x08, 0xbf, /* it eq           */
  0x01, 0x30, /* adds r0, #1     */

  /* part_two:                   */
  0x00, 0x28, /* cmp r0, #0      */
  0x08, 0xbf, /* it eq           */
  0x02, 0x30, /* adds r0, #2     */
  0x00, 0xbd, /* pop {pc}        */
);

TESTCASE (thumb_it_eq)
{
  INVOKE_THUMB_EXPECTING (GUM_NOTHING, thumb_it_eq, 1);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCODE (thumb_it_al,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0xe8, 0xbf, /* it al           */
  0x01, 0x30, /* adds r0, #1     */

  /* part_two:                   */
  0xe8, 0xbf, /* it al           */
  0x02, 0x30, /* adds r0, #2     */
  0x04, 0x30, /* adds r0, #4     */
  0x00, 0xbd, /* pop {pc}        */
);

TESTCASE (thumb_it_al)
{
  INVOKE_THUMB_EXPECTING (GUM_NOTHING, thumb_it_al, 7);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCODE (thumb_it_eq_branch,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x00, 0x28, /* cmp r0, #0      */
  0x08, 0xbf, /* it eq           */
  0x00, 0xe0, /* b part_two      */
  0x00, 0xde, /* udf 0           */

  /* part_two:                   */
  0x01, 0x28, /* cmp r0, #1      */
  0x08, 0xbf, /* it eq           */
  0x00, 0xe0, /* b part_three    */
  0x00, 0xbd, /* pop {pc}        */

  /* part_three:                 */
  0x00, 0xde  /* udf 0           */
);

TESTCASE (thumb_it_eq_branch)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_BLOCK, thumb_it_eq_branch, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 2);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, start, func + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, end, func + 10 + 1);
}

TESTCODE (thumb_itt_eq_branch,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x49, 0x1a, /* subs r1, r1, r1 */
  0x00, 0x29, /* cmp r1, #0      */
  0x04, 0xbf, /* itt eq          */
  0x01, 0x30, /* add r0, #1      */
  0x00, 0xe0, /* b part_two      */
  0x00, 0xde, /* udf 0           */

  /* part_two:                   */
  0x01, 0x29, /* cmp r1, #1      */
  0x04, 0xbf, /* itt eq          */
  0x02, 0x30, /* add r0, #2      */
  0x00, 0xe0, /* b part_three    */
  0x00, 0xbd, /* pop {pc}        */

  /* part_three:                 */
  0x00, 0xde  /* udf 0           */
);

TESTCASE (thumb_itt_eq_branch)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_BLOCK, thumb_itt_eq_branch, 1);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 2);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, start, func + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, end, func + 14 + 1);
}

TESTCODE (thumb_ite_eq_branch,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x49, 0x1a, /* subs r1, r1, r1 */
  0x01, 0x29, /* cmp r1, #1      */
  0x0c, 0xbf, /* ite eq          */
  0x01, 0x30, /* add r0, #1      */
  0x00, 0xe0, /* b part_two      */
  0x00, 0xde, /* udf 0           */

  /* part_two:                   */
  0x00, 0x29, /* cmp r1, #0      */
  0x0c, 0xbf, /* ite eq          */
  0x02, 0x30, /* add r0, #2      */
  0x00, 0xe0, /* b part_three    */
  0x00, 0xbd, /* pop {pc}        */

  /* part_three:                 */
  0x00, 0xde  /* udf 0           */
);

TESTCASE (thumb_ite_eq_branch)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_BLOCK, thumb_ite_eq_branch, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 2);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, start, func + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, end, func + 14 + 1);
}

TESTCODE (thumb_it_eq_branch_link,
  0x00, 0xb5,             /* push {lr}       */
  0x00, 0x1a,             /* subs r0, r0, r0 */
  0x49, 0x1a,             /* subs r1, r1, r1 */
  0x01, 0x31,             /* adds r1, #1     */
  0x00, 0x28,             /* cmp r0, #0      */
  0x08, 0xbf,             /* it eq           */
  0x00, 0xf0, 0x06, 0xf8, /* bl part_three   */

  /* part_two:                               */
  0x01, 0x31,             /* adds r1, #1     */
  0x00, 0x28,             /* cmp r0, #0      */
  0x08, 0xbf,             /* it eq           */
  0x00, 0xf0, 0x01, 0xf8, /* bl part_three   */
  0x00, 0xbd,             /* pop {pc}        */

  /* part_three:                             */
  0x00, 0xb5,             /* push {lr}       */
  0x08, 0x44,             /* add r0, r1      */
  0x00, 0xbd,             /* pop {pc}        */
);

TESTCASE (thumb_it_eq_branch_link)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_CALL, thumb_it_eq_branch_link, 1);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 10 + 1);
  GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 28 + 1);
}

TESTCASE (thumb_it_eq_branch_link_excluded)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb_it_eq_branch_link);

  {
    GumMemoryRange r = {
    
"""


```