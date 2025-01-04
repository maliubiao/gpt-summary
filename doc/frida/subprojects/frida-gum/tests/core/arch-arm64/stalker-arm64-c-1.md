Response:
The user wants a summary of the functionalities of the C code provided, which seems to be a set of test cases for Frida's Stalker on ARM64 architecture.

Here's a breakdown of the thought process to arrive at the summary:

1. **Identify the Core Functionality:** The code uses `gum_arm64_writer_*` functions to generate ARM64 assembly code. It then uses `gum_stalker_*` functions to intercept and trace the execution of this generated code. The `TESTCASE` macros indicate that these are unit tests.

2. **Recognize Key Components:**
    * `GumArm64Writer`: For assembling ARM64 instructions.
    * `gum_stalker_*`:  The core of the functionality being tested. Specifically `follow_me`, `unfollow_me`, `exclude`.
    * `fixture`: A test fixture, likely containing a `stalker`, `transformer`, and `sink`.
    * `GUM_EXEC`, `GUM_CALL`, `GUM_RET`:  Flags indicating different types of events to track.
    * `g_assert_*`: Assertion macros for verifying expected behavior.

3. **Analyze Individual Test Cases:**  Go through each `TESTCASE` and identify the primary action being tested:
    * `exclude_b_with_unfollow`: Tests excluding a branch instruction (`b`) with `unfollow_me`.
    * `exclude_bl_with_unfollow`: Tests excluding a branch-and-link instruction (`bl`) with `unfollow_me`.
    * `exclude_blr_with_unfollow`: Tests excluding a branch-to-register instruction (`blr`) with `unfollow_me`.
    * `unconditional_branch`: Tests following unconditional branch instructions (`b`).
    * `unconditional_branch_reg`: Tests following unconditional branch-to-register instructions (`br`).
    * `conditional_branch`: Tests following conditional branch instructions (`b.cond`).
    * `compare_and_branch`: Tests following compare-and-branch instructions (`cbz`, `cbnz`).
    * `test_bit_and_branch`: Tests following test-bit-and-branch instructions (`tbz`, `tbnz`).
    * `follow_std_call`: Tests following standard function calls (`bl`) and returns (`ret`).
    * `follow_return`: Tests following return instructions (`ret`).
    * `follow_misaligned_stack`: Tests Stalker's behavior with code that manipulates the stack pointer in a non-standard way.
    * `follow_syscall`: Tests Stalker's ability to follow system calls.
    * `follow_thread`: Tests Stalker's ability to follow execution in a separate thread.
    * `unfollow_should_handle_terminated_thread`: Tests Stalker's ability to unfollow threads that have already terminated.
    * `self_modifying_code_should_be_detected_with_threshold_*`: Tests Stalker's ability to detect self-modifying code based on a trust threshold.
    * `exclusive_load_store_should_not_be_disturbed`: Tests that Stalker doesn't interfere with exclusive load/store instructions used for synchronization.
    * `pthread_create`: Tests Stalker's interaction with thread creation (if not on Windows).
    * `heap_api`: Tests Stalker's ability to follow memory allocation and deallocation functions.
    * `no_register_clobber`: Tests that Stalker doesn't corrupt registers during its instrumentation (not on Darwin).
    * `performance`:  A performance test to measure the overhead introduced by Stalker.

4. **Group Similar Functionalities:**  Notice patterns in the test cases, such as those related to:
    * Excluding code from tracing.
    * Following different types of branch instructions.
    * Following function calls and returns.
    * Handling multi-threaded scenarios.
    * Detecting self-modifying code.
    * Ensuring correctness with specific instruction types.

5. **Synthesize a Summary:**  Combine the observations from the individual test cases and the grouped functionalities into a concise summary. Focus on the "what" and "why" of the tests.

6. **Address the "Part 2" Request:**  The prompt specifically asks for a summary of the *provided code snippet*. The snippet focuses on a few specific test cases involving `exclude` and different branch instructions with `unfollow_me`. Therefore, the summary should emphasize these aspects within the context of the broader file.

7. **Review and Refine:** Ensure the summary is accurate, clear, and addresses the user's request. Avoid overly technical jargon where possible, but retain necessary terms like "stalker," "instrumentation," and "ARM64."

By following these steps, we can generate a comprehensive and informative summary of the provided code snippet within the context of the larger file.
这是 frida Dynamic Instrumentation Tool 针对 ARM64 架构的 Stalker 组件的测试代码片段，主要测试了在代码执行过程中排除特定代码区域不被跟踪的功能，并涉及到 `gum_stalker_unfollow_me` 函数的使用。

**功能归纳:**

这段代码片段主要测试了 `gum_stalker_exclude` 和 `gum_stalker_unfollow_me` 结合使用时，Stalker 的行为。具体来说，它验证了当 Stalker 跟踪代码执行时，通过 `gum_stalker_exclude` 排除掉包含特定跳转指令（`b`, `bl`, `blr`）的目标地址的代码区域后，Stalker 会停止跟踪该区域的指令，并且在执行到该区域时，如果调用了 `gum_stalker_unfollow_me`，Stalker 会正确地取消跟踪。

**与逆向方法的关联举例:**

在逆向分析中，我们常常需要聚焦于特定的代码逻辑，而忽略一些不感兴趣或者已知功能的代码。Stalker 的排除功能就提供了这样的能力。

**举例:** 假设我们正在逆向一个加密算法的实现，我们已经分析清楚了算法的初始化部分，并且只想关注加密的核心运算部分。我们可以使用 Stalker 先跟踪整个加密流程，然后通过 `gum_stalker_exclude` 排除掉初始化函数的地址范围，这样 Stalker 就不会记录初始化过程中的指令执行，从而减少干扰，提高分析效率。

**涉及二进制底层、Linux、Android 内核及框架的知识举例:**

* **二进制底层:** 代码中使用了 `gum_arm64_writer_*` 系列函数来直接生成 ARM64 汇编指令，例如 `gum_arm64_writer_put_add_reg_reg_imm` 生成加法指令，`gum_arm64_writer_put_ret` 生成返回指令。这需要对 ARM64 指令集有深入的了解。
* **Linux/Android 内核:** Stalker 的实现原理涉及到对进程内存的监控和代码注入。`gum_stalker_follow_me` 函数会启动 Stalker 对目标代码的跟踪，这可能需要在内核层面进行一些操作，例如修改内存页的权限，插入 hook 代码等。`gum_sign_code_pointer` 函数可能涉及到代码地址的签名或校验，这在一些有安全机制的系统（如 Android）中比较常见。
* **Frida 框架:** 这段代码是 Frida 框架的一部分，使用了 Frida 提供的 API，例如 `gum_alloc_n_pages` 用于分配内存，`gum_memory_mark_code` 用于标记内存为代码页，`GUM_ADDRESS` 用于获取地址， `GUM_POINTER_TO_FUNCPTR` 将内存地址转换为函数指针。

**逻辑推理的假设输入与输出:**

以 `TESTCASE (exclude_b_with_unfollow)` 为例：

**假设输入:**

* `fixture->stalker`: 一个已经初始化好的 Stalker 实例。
* `fixture->transformer`: 一个用于转换跟踪事件的 Transformer 实例。
* `fixture->sink`: 一个用于接收跟踪事件的 Sink 实例，其 `mask` 设置为 `GUM_EXEC`，表示只记录执行事件。
* `func` 函数被调用，输入参数为 `2`。

**预期输出:**

* 在调用 `func(2)` 后，`fixture->sink->events->len` 的值应该为特定的数值（在非 Darwin 平台是 42，Darwin 平台是 41）。
* `func(2)` 的返回值应该为 `12`。
* 在 `gum_stalker_exclude` 之前，Stalker 会跟踪 `func_a` 指向的代码（加法和返回指令）。
* 由于排除了 `func_a` 指向的代码区域，Stalker 不会再跟踪该区域的指令执行。
* 在执行到 `gum_stalker_unfollow_me` 之后，Stalker 停止跟踪。

**用户或编程常见的使用错误举例:**

* **排除范围过大或过小:** 如果 `memory_range.size` 设置不正确，可能会导致排除的代码范围不是预期的，要么漏掉需要排除的代码，要么排除了不应该排除的代码。例如，如果 `memory_range.size` 设置为 4 而不是 8，则可能只排除了 `add` 指令，而没有排除 `ret` 指令。
* **在排除区域内没有调用 `gum_stalker_unfollow_me`:**  如果在排除的代码区域内没有调用 `gum_stalker_unfollow_me`，Stalker 仍然可能尝试对该区域进行操作，虽然它不会记录执行事件，但可能会导致一些意想不到的行为。
* **忘记设置 `fixture->sink->mask`:** 如果 `fixture->sink->mask` 没有正确设置，即使 Stalker 跟踪了代码，Sink 也可能不会记录任何事件，导致测试结果不符合预期。

**用户操作如何一步步到达这里作为调试线索:**

1. **用户想要测试 Stalker 的排除功能:** 用户可能正在开发或调试使用了 Frida Stalker 的代码，需要确保排除功能能够正常工作。
2. **查看或编写 Stalker 的相关测试用例:**  用户会查看 Frida 源代码中关于 Stalker 的测试用例，或者自己编写新的测试用例来验证排除功能的正确性。
3. **定位到 `stalker-arm64.c` 文件:** 因为用户需要测试 ARM64 架构下的 Stalker，所以会找到 `frida/subprojects/frida-gum/tests/core/arch-arm64/stalker-arm64.c` 这个文件。
4. **查看 `exclude_b_with_unfollow` 等测试用例:** 用户会仔细阅读这些测试用例的代码，理解其测试逻辑和预期结果。
5. **运行测试用例:** 用户会编译并运行这些测试用例，例如使用 `make check` 命令。
6. **如果测试失败，进行调试:** 如果测试结果与预期不符，用户可能会使用 GDB 等调试器来单步执行测试代码，查看 Stalker 的内部状态，分析问题的原因。 例如，用户可能会在 `gum_stalker_exclude` 调用前后设置断点，查看排除操作是否成功，以及在执行到被排除的代码区域时，Stalker 的行为是否符合预期。

**这是第2部分，共3部分，请归纳一下它的功能:**

作为第二部分，这段代码的功能可以归纳为：**验证 Frida Stalker 在 ARM64 架构下，结合 `gum_stalker_exclude` 和 `gum_stalker_unfollow_me` API，能够正确地排除指定的代码区域不被跟踪，并在执行到被排除区域时，能够根据 `gum_stalker_unfollow_me` 的调用停止跟踪。**  它专注于测试排除功能在遇到不同类型的跳转指令时的行为。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-arm64/stalker-arm64.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共3部分，请归纳一下它的功能

"""
rm64_writer_cur (&cw);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 10);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, start_lbl);
  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_ldr_reg_address (&cw, ARM64_REG_X1,
      GUM_ADDRESS (gum_sign_code_pointer (func_a)));
  gum_arm64_writer_put_blr_reg (&cw, ARM64_REG_X1);
  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_flush (&cw);
  gum_memory_mark_code (code, gum_arm64_writer_offset (&cw));
  gum_arm64_writer_clear (&cw);

  memory_range.base_address = GUM_ADDRESS (func_a);
  memory_range.size = 4 * 2;
  gum_stalker_exclude (fixture->stalker, &memory_range);

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, gum_sign_code_pointer (code));

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);

  g_assert_cmpint (func (2), ==, 12);

#ifdef HAVE_DARWIN
  g_assert_cmpuint (fixture->sink->events->len, ==, 41);
#else
  g_assert_cmpuint (fixture->sink->events->len, ==, 42);
#endif

  gum_free_pages (code);
}

TESTCASE (exclude_bl_with_unfollow)
{
  StalkerTestFunc func;
  guint8 * code;
  GumArm64Writer cw;
  gpointer func_a;
  GumMemoryRange memory_range;
  const gchar * start_lbl = "start";

  fixture->sink->mask = GUM_EXEC;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_b_label (&cw, start_lbl);

  func_a = gum_arm64_writer_cur (&cw);
  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 10);
  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_arm64_writer_put_pop_all_x_registers (&cw);
  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, start_lbl);

  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_bl_imm (&cw, GUM_ADDRESS (func_a));
  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_flush (&cw);
  gum_memory_mark_code (code, gum_arm64_writer_offset (&cw));
  gum_arm64_writer_clear (&cw);

  memory_range.base_address = GUM_ADDRESS (func_a);
  memory_range.size = 4 * 20;
  gum_stalker_exclude (fixture->stalker, &memory_range);

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, gum_sign_code_pointer (code));

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);

  g_assert_cmpint (func (2), ==, 12);

  g_assert_cmpuint (fixture->sink->events->len, ==, 20);

  gum_free_pages (code);
}

TESTCASE (exclude_blr_with_unfollow)
{
  StalkerTestFunc func;
  guint8 * code;
  GumArm64Writer cw;
  gpointer func_a;
  GumMemoryRange memory_range;
  const gchar * start_lbl = "start";

  fixture->sink->mask = GUM_EXEC;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_b_label (&cw, start_lbl);

  func_a = gum_arm64_writer_cur (&cw);
  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 10);
  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_arm64_writer_put_pop_all_x_registers (&cw);
  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, start_lbl);

  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_ldr_reg_address (&cw, ARM64_REG_X1,
      GUM_ADDRESS (gum_sign_code_pointer (func_a)));
  gum_arm64_writer_put_blr_reg (&cw, ARM64_REG_X1);
  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_flush (&cw);
  gum_memory_mark_code (code, gum_arm64_writer_offset (&cw));
  gum_arm64_writer_clear (&cw);

  memory_range.base_address = GUM_ADDRESS (func_a);
  memory_range.size = 4 * 20;
  gum_stalker_exclude (fixture->stalker, &memory_range);

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, gum_sign_code_pointer (code));

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);

  g_assert_cmpint (func (2), ==, 12);

  g_assert_cmpuint (fixture->sink->events->len, ==, 21);

  gum_free_pages (code);
}

TESTCASE (unconditional_branch)
{
  guint8 * code;
  GumArm64Writer cw;
  GumAddress address;
  const gchar * my_ken_lbl = "my_ken";
  StalkerTestFunc func;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_b_label (&cw, my_ken_lbl);

  address = GUM_ADDRESS (gum_arm64_writer_cur (&cw));
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 10);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_b_imm (&cw, address);

  gum_arm64_writer_flush (&cw);
  gum_memory_mark_code (code, gum_arm64_writer_offset (&cw));
  gum_arm64_writer_clear (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, gum_sign_code_pointer (code));

  g_assert_cmpint (func (2), ==, 13);

  gum_free_pages (code);
}

TESTCASE (unconditional_branch_reg)
{
  guint8 * code;
  GumArm64Writer cw;
  GumAddress address;
  const gchar * my_ken_lbl = "my_ken";
  StalkerTestFunc func;
  arm64_reg reg = ARM64_REG_X13;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_b_label (&cw, my_ken_lbl);

  address = GUM_ADDRESS (gum_arm64_writer_cur (&cw));
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 10);
  if (reg == ARM64_REG_X29 || reg == ARM64_REG_X30)
    gum_arm64_writer_put_pop_reg_reg (&cw, reg, ARM64_REG_XZR);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  if (reg == ARM64_REG_X29 || reg == ARM64_REG_X30)
    gum_arm64_writer_put_push_reg_reg (&cw, reg, reg);
  gum_arm64_writer_put_ldr_reg_address (&cw, reg, address);
  gum_arm64_writer_put_br_reg (&cw, reg);

  gum_arm64_writer_flush (&cw);
  gum_memory_mark_code (code, gum_arm64_writer_offset (&cw));
  gum_arm64_writer_clear (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, gum_sign_code_pointer (code));

  g_assert_cmpint (func (2), ==, 13);

  gum_free_pages (code);
}

TESTCASE (conditional_branch)
{
  guint8 * code;
  GumArm64Writer cw;
  GumAddress address;
  arm64_cc cc = ARM64_CC_EQ;
  const gchar * my_ken_lbl = "my_ken";
  StalkerTestFunc func;
  gint r;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_instruction (&cw, 0xF1000800);  /* SUBS X0, X0, #2 */
  gum_arm64_writer_put_b_cond_label (&cw, cc, my_ken_lbl);

  address = GUM_ADDRESS (gum_arm64_writer_cur (&cw));
  gum_arm64_writer_put_nop (&cw);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_b_imm (&cw, address);

  gum_arm64_writer_flush (&cw);
  gum_memory_mark_code (code, gum_arm64_writer_offset (&cw));
  gum_arm64_writer_clear (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, gum_sign_code_pointer (code));
  r = func (2);

  g_assert_cmpint (r, ==, 1);

  gum_free_pages (code);
}

TESTCASE (compare_and_branch)
{
  guint8 * code;
  GumArm64Writer cw;
  const gchar * my_ken_lbl = "my_ken";
  const gchar * my_nken_lbl = "my_nken";
  StalkerTestFunc func;
  gint r;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_sub_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 2);
  gum_arm64_writer_put_cbz_reg_label (&cw, ARM64_REG_X0, my_ken_lbl);

  gum_arm64_writer_put_label (&cw, my_nken_lbl);
  gum_arm64_writer_put_nop (&cw);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_cbnz_reg_label (&cw, ARM64_REG_X0, my_nken_lbl);

  gum_arm64_writer_flush (&cw);
  gum_memory_mark_code (code, gum_arm64_writer_offset (&cw));
  gum_arm64_writer_clear (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, gum_sign_code_pointer (code));
  r = func (2);

  g_assert_cmpint (r, ==, 1);

  gum_free_pages (code);
}

TESTCASE (test_bit_and_branch)
{
  guint8 * code;
  GumArm64Writer cw;
  const gchar * my_ken_lbl = "my_ken";
  const gchar * my_nken_lbl = "my_nken";
  StalkerTestFunc func;
  gint r;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_sub_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 2);
  gum_arm64_writer_put_tbz_reg_imm_label (&cw, ARM64_REG_W0, 0, my_ken_lbl);

  gum_arm64_writer_put_label (&cw, my_nken_lbl);
  gum_arm64_writer_put_nop (&cw);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_tbnz_reg_imm_label (&cw, ARM64_REG_W0, 0, my_nken_lbl);

  gum_arm64_writer_flush (&cw);
  gum_memory_mark_code (code, gum_arm64_writer_offset (&cw));
  gum_arm64_writer_clear (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, gum_sign_code_pointer (code));
  r = func (2);

  g_assert_cmpint (r, ==, 1);

  gum_free_pages (code);
}

TESTCASE (follow_std_call)
{
  guint8 * code;
  GumArm64Writer cw;
  GumAddress address;
  const gchar * my_ken_lbl = "my_ken";
  StalkerTestFunc func;
  gint r;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X30, ARM64_REG_X29);
  gum_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_X29, ARM64_REG_SP);

  gum_arm64_writer_put_b_label (&cw, my_ken_lbl);

  address = GUM_ADDRESS (gum_arm64_writer_cur (&cw));
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_arm64_writer_put_pop_all_x_registers (&cw);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_bl_imm (&cw, address);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X30, ARM64_REG_X29);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_flush (&cw);
  gum_memory_mark_code (code, gum_arm64_writer_offset (&cw));
  gum_arm64_writer_clear (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, gum_sign_code_pointer (code));
  r = func (2);

  g_assert_cmpint (r, ==, 4);

  gum_free_pages (code);
}

TESTCASE (follow_return)
{
  guint8 * code;
  GumArm64Writer cw;
  GumAddress address;
  const gchar * my_ken_lbl = "my_ken";
  StalkerTestFunc func;
  gint r;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X30, ARM64_REG_X29);
  gum_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_X29, ARM64_REG_SP);

  gum_arm64_writer_put_b_label (&cw, my_ken_lbl);

  address = GUM_ADDRESS (gum_arm64_writer_cur (&cw));
  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_arm64_writer_put_pop_all_x_registers (&cw);
  /*
   * alternative for instruction RET X15
   * gum_arm64_writer_put_mov_reg_reg (&cw, ARM64_REG_X15, ARM64_REG_X30);
   * gum_arm64_writer_put_instruction (&cw, 0xD65F01E0);
   */
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, my_ken_lbl);
  gum_arm64_writer_put_nop (&cw);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);
  gum_arm64_writer_put_bl_imm (&cw, address);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 1);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X30, ARM64_REG_X29);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_flush (&cw);
  gum_memory_mark_code (code, gum_arm64_writer_offset (&cw));
  gum_arm64_writer_clear (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, gum_sign_code_pointer (code));
  r = func (2);

  g_assert_cmpint (r, ==, 4);

  gum_free_pages (code);
}

TESTCASE (follow_misaligned_stack)
{
  const guint32 code_template[] =
  {
    0xa9bf7bf4, /* stp x20, lr, [sp, #-0x10]! */
    0xd10023ff, /* sub sp, sp, #8             */
    0x14000002, /* b part_two                 */
    0xd4200540, /* brk #42                    */
    /* part_two:                              */
    0x94000009, /* bl get_base_value          */
    0x10000070, /* adr x16, part_three        */
    0xd61f0200, /* br x16                     */
    0xd4200560, /* brk #43                    */
    /* part_three:                            */
    0x100000f0, /* adr x16, add_other_value   */
    0xd63f0200, /* blr x16                    */
    0x910023ff, /* add sp, sp, #8             */
    0xa8c17bf4, /* ldp x20, lr, [sp], #0x10   */
    0xd65f03c0, /* ret                        */
    /* get_base_value:                        */
    0xd2800500, /* mov x0, #40                */
    0xd65f03c0, /* ret                        */
    /* add_other_value:                       */
    0x91000800, /* add x0, x0, #2             */
    0xd65f03c0, /* ret                        */
  };
  StalkerTestFunc func;

  fixture->sink->mask = GUM_EXEC;

  func = (StalkerTestFunc) test_arm64_stalker_fixture_dup_code (fixture,
      code_template, sizeof (code_template));

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);

  test_arm64_stalker_fixture_follow_and_invoke (fixture, func, 42);

  g_assert_cmpuint (fixture->sink->events->len, ==, 21);
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

    fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;
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

TESTCASE (self_modifying_code_should_be_detected_with_threshold_minus_one)
{
  FlatFunc f;

  f = (FlatFunc) test_arm64_stalker_fixture_dup_code (fixture, flat_code,
      sizeof (flat_code));

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_set_trust_threshold (fixture->stalker, -1);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  g_assert_cmpuint (f (), ==, 2);

  patch_instruction (f, 4, 0x1100a400);
  g_assert_cmpuint (f (), ==, 42);
  f ();
  f ();

  patch_instruction (f, 4, 0x1114e000);
  g_assert_cmpuint (f (), ==, 1337);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCASE (self_modifying_code_should_not_be_detected_with_threshold_zero)
{
  FlatFunc f;

  f = (FlatFunc) test_arm64_stalker_fixture_dup_code (fixture, flat_code,
      sizeof (flat_code));

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_set_trust_threshold (fixture->stalker, 0);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  g_assert_cmpuint (f (), ==, 2);

  patch_instruction (f, 4, 0x1100a400);
  g_assert_cmpuint (f (), ==, 2);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCASE (self_modifying_code_should_be_detected_with_threshold_one)
{
  FlatFunc f;

  f = (FlatFunc) test_arm64_stalker_fixture_dup_code (fixture, flat_code,
      sizeof (flat_code));

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_set_trust_threshold (fixture->stalker, 1);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  g_assert_cmpuint (f (), ==, 2);

  patch_instruction (f, 4, 0x1100a400);
  g_assert_cmpuint (f (), ==, 42);
  f ();
  f ();

  patch_instruction (f, 4, 0x1114e000);
  g_assert_cmpuint (f (), ==, 42);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCASE (exclusive_load_store_should_not_be_disturbed)
{
  guint32 code_template[] =
  {
    0x58000200, /* ldr x0, [pointer_to_value] */
    /* retry:                                 */
    0xc85f7c01, /* ldxr x1, [x0]              */
    0xf100043f, /* cmp x1, #1                 */
    0x54000160, /* b.eq nope                  */
    0xf100083f, /* cmp x1, #2                 */
    0x54000120, /* b.eq nope                  */
    0xf1000c3f, /* cmp x1, #3                 */
    0x540000e0, /* b.eq nope                  */
    0xf100103f, /* cmp x1, #4                 */
    0x540000a0, /* b.eq nope                  */
    0x91000421, /* add x1, x1, #1             */
    0xc8027c01, /* stxr w2, x1, [x0]          */
    0x35fffea2, /* cbnz w2, retry             */
    0xd65f03c0, /* ret                        */
    /* nope:                                  */
    0xd5033f5f, /* clrex                      */
    0xd65f03c0, /* ret                        */
    /* pointer_to_value:                      */
    0x44332211, 0x88776655,
  };
  StalkerTestFunc func;
  guint64 val;
  gint num_cmp_callouts;

  fixture->sink->mask = GUM_EXEC;

  *((guint64 **) (code_template + G_N_ELEMENTS (code_template) - 2)) = &val;
  func = (StalkerTestFunc) test_arm64_stalker_fixture_dup_code (fixture,
      code_template, sizeof (code_template));

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      insert_callout_after_cmp, &num_cmp_callouts, NULL);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);

  val = 5;
  num_cmp_callouts = 0;
  test_arm64_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (val, ==, 6);
  g_assert_cmpint (num_cmp_callouts, ==, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 17);
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

    if (insn->id == ARM64_INS_CMP && access == GUM_MEMORY_ACCESS_OPEN)
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

static void
patch_instruction (gpointer code,
                   guint offset,
                   guint32 insn)
{
  gum_memory_patch_code ((guint8 *) code + offset, sizeof (insn),
      do_patch_instruction, GSIZE_TO_POINTER (insn));
}

static void
do_patch_instruction (gpointer mem,
                      gpointer user_data)
{
  guint32 * insn = mem;
  guint32 new_insn = GPOINTER_TO_SIZE (user_data);

  *insn = new_insn;
}

#ifndef HAVE_WINDOWS

TESTCASE (pthread_create)
{
  int ret;
  pthread_t thread;
  int number = 0;

  fixture->sink->mask = GUM_COMPILE;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  ret = pthread_create (&thread, NULL, increment_integer, (gpointer) &number);
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

#endif

TESTCASE (heap_api)
{
  gpointer p;

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  p = malloc (1);
  free (p);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

typedef void (* ClobberFunc) (GumCpuContext * ctx);

TESTCASE (no_register_clobber)
{
#ifndef HAVE_DARWIN
  guint8 * code;
  GumArm64Writer cw;
  gint i;
  ClobberFunc func;
  GumCpuContext ctx;

  code = gum_alloc_n_pages (1, GUM_PAGE_RW);
  gum_arm64_writer_init (&cw, code);

  gum_arm64_writer_put_push_all_x_registers (&cw);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_follow_me), 3,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->transformer),
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->sink));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  for (i = ARM64_REG_X0; i <= ARM64_REG_X28; i++)
  {
    gboolean is_platform_register = i == ARM64_REG_X18;
    if (is_platform_register)
      continue;
    gum_arm64_writer_put_ldr_reg_u64 (&cw, i, i);
  }
  gum_arm64_writer_put_ldr_reg_u64 (&cw, ARM64_REG_FP, ARM64_REG_FP);
  gum_arm64_writer_put_ldr_reg_u64 (&cw, ARM64_REG_LR, ARM64_REG_LR);

  gum_arm64_writer_put_push_all_x_registers (&cw);
  gum_arm64_writer_put_call_address_with_arguments (&cw,
      GUM_ADDRESS (gum_stalker_unfollow_me), 1,
      GUM_ARG_ADDRESS, GUM_ADDRESS (fixture->stalker));
  gum_arm64_writer_put_pop_all_x_registers (&cw);

  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);
  gum_arm64_writer_put_ldr_reg_reg_offset (&cw, ARM64_REG_FP, ARM64_REG_SP,
      (2 + 30) * sizeof (gpointer));
  for (i = ARM64_REG_X0; i <= ARM64_REG_X28; i++)
  {
    gum_arm64_writer_put_str_reg_reg_offset (&cw, i, ARM64_REG_FP,
        G_STRUCT_OFFSET (GumCpuContext, x[i - ARM64_REG_X0]));
  }
  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_FP, ARM64_REG_LR);

  gum_arm64_writer_put_ldr_reg_reg_offset (&cw, ARM64_REG_X0, ARM64_REG_SP,
      30 * sizeof (gpointer));
  gum_arm64_writer_put_str_reg_reg_offset (&cw, ARM64_REG_FP, ARM64_REG_X0,
      G_STRUCT_OFFSET (GumCpuContext, fp));
  gum_arm64_writer_put_str_reg_reg_offset (&cw, ARM64_REG_LR, ARM64_REG_X0,
      G_STRUCT_OFFSET (GumCpuContext, lr));

  gum_arm64_writer_put_pop_all_x_registers (&cw);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_flush (&cw);
  gum_memory_mark_code (code, gum_arm64_writer_offset (&cw));
  gum_arm64_writer_clear (&cw);

  fixture->sink->mask = GUM_CALL | GUM_RET | GUM_EXEC;
  func = GUM_POINTER_TO_FUNCPTR (ClobberFunc, code);
  func (&ctx);

  for (i = ARM64_REG_X0; i <= ARM64_REG_X28; i++)
  {
    gboolean is_platform_register = i == ARM64_REG_X18;
    if (is_platform_register)
      continue;
    g_assert_cmphex (ctx.x[i - ARM64_REG_X0], ==, i);
  }
  g_assert_cmphex (ctx.fp, ==, ARM64_REG_FP);
  g_assert_cmphex (ctx.lr, ==, ARM64_REG_LR);

  gum_free_pages (code);
#endif
}

TESTCASE (performance)
{
  GumMemoryRange runner_range;
  GTimer * timer;
  gdouble duration_direct, duration_stalked;

  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);
  g_assert_true (runner_range.base_address != 0 && runner_range.size != 0);

  timer = g_timer_new ();
  pretend_workload (&runner_range);

  g_timer_reset (timer);
  pretend_workload (&runner_range);
  duration_direct = g_timer_elapsed (timer, NULL);

  fixture->sink->mask = GUM_NOTHING;

  gum_stalker_set_trust_threshold (fixture->stalker, 0);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  /* warm-up */
  g_timer_reset (timer);
  pretend_workload (&runner_range);
  g_timer_elapsed (timer, NULL);

  /* the real deal */
  g_timer_reset (timer);
  pretend_workload (&runner_range);
  duration_stalked = g_timer_e
"""


```