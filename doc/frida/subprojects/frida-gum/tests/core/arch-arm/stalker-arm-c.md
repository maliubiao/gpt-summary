Response:
The user wants to understand the functionality of the C code provided, which is part of the Frida dynamic instrumentation tool. Specifically, they are asking for:

1. **Functionality Summary:** A general overview of what the code does.
2. **Relationship to Reverse Engineering:** How this code relates to techniques used in reverse engineering.
3. **Low-Level Details:**  Connections to binary formats, Linux, Android kernel/framework.
4. **Logical Reasoning:**  Analysis of potential inputs and outputs based on the code's logic.
5. **Common User Errors:** Examples of mistakes users might make when interacting with this code.
6. **User Journey:**  How a user might end up running this specific code.
7. **Summary of Functionality (Part 1):** A concise summary focusing on the provided code snippet.

**Code Analysis (Part 1):**

The provided code snippet primarily defines a series of test cases within the Frida framework. It uses a macro-based testing structure (`TESTLIST_BEGIN`, `TESTENTRY`, `TESTLIST_END`, `TESTCASE`, `TESTCODE`) which suggests a unit testing framework.

The names of the test cases (`trust_should_be_one_by_default`, `arm_no_events`, `thumb_no_events`, etc.) hint at the specific aspects of the `stalker` component being tested. The `stalker` is likely responsible for tracing the execution of code, and the tests seem to cover different architectural modes (ARM, Thumb), event types (execution, calls, blocks, returns), and configurations (excluded ranges, call probes).

The `TESTCODE` macro defines snippets of ARM and Thumb assembly code that are used as inputs for the tests. The `INVOKE_ARM_EXPECTING` and `INVOKE_THUMB_EXPECTING` macros likely execute this assembly code under the control of the Frida stalker and then assert that certain events are generated or not generated.

**Planning the Response:**

I will structure the response to address each of the user's points:

1. **Functionality Summary:** Explain that this file contains unit tests for the `stalker` component of Frida, specifically for ARM architectures. The tests verify the correct generation of execution traces and events under various conditions.

2. **Relationship to Reverse Engineering:** Explain that Frida's `stalker` is a key tool for dynamic analysis in reverse engineering. It allows researchers to observe the runtime behavior of software, which is crucial for understanding complex or obfuscated code. Provide examples like tracing function calls to understand program flow or observing memory accesses.

3. **Low-Level Details:** Discuss how the tests deal with ARM and Thumb instruction sets (binary level), how Frida interacts with the underlying operating system (Linux, potentially Android), and how it might hook into process execution.

4. **Logical Reasoning:**  For example, with `arm_no_events`, the expectation is that with no event mask specified, no events are generated. For `arm_exec_events_generated`, with `GUM_EXEC` mask, execution events are expected for each instruction.

5. **Common User Errors:** Focus on incorrect configuration of the stalker, such as forgetting to set the event mask, misunderstanding how excluded ranges work, or using incorrect addresses.

6. **User Journey:** Describe a typical reverse engineering workflow where a user might attach Frida to a process and use the `Stalker` API to trace execution.

7. **Summary of Functionality (Part 1):** Reiterate that this part of the code defines and executes unit tests for Frida's ARM stalker functionality.
好的，让我们来分析一下 `frida/subprojects/frida-gum/tests/core/arch-arm/stalker-arm.c` 这个文件的功能。

**文件功能归纳 (第 1 部分):**

这个 C 代码文件的主要功能是**为 Frida 动态 instrumentation 工具的 `stalker` 组件，在 ARM 架构下，定义了一系列的单元测试用例。**

**更详细的解释：**

1. **单元测试框架:**  代码使用了类似单元测试的结构 (`TESTLIST_BEGIN`, `TESTENTRY`, `TESTLIST_END`, `TESTCASE`)，这表明它的目的是验证 `stalker` 组件在 ARM 环境下的各项功能是否正常工作。

2. **测试目标：Stalker 组件:**  文件名和代码内容都明确指出，这些测试是针对 Frida 的 `stalker` 组件的。`stalker` 是 Frida 中用于追踪代码执行流程的核心组件，它可以记录程序执行的指令、函数调用等信息。

3. **目标架构：ARM:** 文件路径 (`arch-arm`) 和测试用例名称（例如 `arm_no_events`, `thumb_no_events`）都表明这些测试是专门针对 ARM 架构的。其中，`arm_` 前缀通常指 ARM 指令集，而 `thumb_` 前缀通常指 Thumb 指令集（ARM 的一个精简指令集）。

4. **测试用例:**  `TESTENTRY` 宏定义了具体的测试用例，每个用例名称暗示了它要测试的功能点，例如：
   - `trust_should_be_one_by_default`: 验证 `stalker` 的默认信任阈值是否为 1。
   - `arm_no_events`/`thumb_no_events`:  验证在没有指定事件类型时，是否不会生成任何事件。
   - `arm_exec_events_generated`/`thumb_exec_events_generated`: 验证是否能正确生成指令执行事件。
   - `arm_call_events_generated`/`thumb_call_events_generated`: 验证是否能正确生成函数调用事件。
   - 等等... 这些用例覆盖了 `stalker` 的多种功能和配置场景，包括事件生成、代码块追踪、排除范围、调用探测、自修改代码检测、线程跟踪等。

5. **测试代码片段:**  `TESTCODE` 宏定义了一些 ARM 和 Thumb 汇编代码片段。这些代码片段是测试用例的输入，用于模拟被追踪的目标代码。

6. **断言和验证:**  在每个测试用例中，可能会使用 `g_assert_cmpuint` 等断言宏来验证 `stalker` 的行为是否符合预期。例如，检查生成的事件数量、事件的地址等。

7. **辅助函数和结构体:**  代码中定义了一些辅助的结构体 (`RunOnThreadCtx`, `TestThreadSyncData`, `CallProbeContext`) 和函数 (`store_range_of_test_runner`, `pretend_workload`, `crc32b`, 等等)。这些辅助函数和结构体用于支持测试用例的执行和验证。

**与逆向方法的关联：**

Frida 本身就是一个强大的逆向工程工具，而 `stalker` 组件是其核心功能之一。这个测试文件直接关联到逆向方法，因为它验证了 `stalker` 在模拟真实逆向场景下的行为。

**举例说明：**

* **动态代码跟踪:**  像 `arm_exec_events_generated` 和 `thumb_exec_events_generated` 这样的测试用例，验证了 `stalker` 是否能够准确地记录目标代码执行的每一条指令。这在逆向分析中非常重要，可以帮助分析者理解代码的执行流程。逆向工程师可以使用 Frida 的 `Stalker.follow()` API 来追踪目标进程的代码执行，并获取执行事件，就像这些测试用例所做的那样。

* **函数调用分析:** `arm_call_events_generated` 和 `thumb_call_events_generated` 测试了 `stalker` 捕获函数调用的能力。逆向工程师经常需要分析函数的调用关系来理解程序的结构和行为。Frida 的 `Stalker` 可以配置为只捕获 `call` 事件，从而专注于函数调用分析。

* **代码块分析:** `arm_block_events_generated` 和 `thumb_block_events_generated` 测试了 `stalker` 识别和记录代码块执行的能力。这可以帮助逆向工程师识别程序的逻辑单元，例如循环、条件分支等。

* **排除特定代码范围:** `arm_excluded_range` 和相关的测试用例验证了 `stalker` 可以被配置为忽略某些代码区域的跟踪。这在逆向分析中很有用，例如，当分析者只想关注特定模块或函数时，可以排除其他不相关的代码。

* **调用探测 (Call Probing):** `arm_call_probe` 和 `thumb_call_probe` 测试了 `stalker` 的调用探测功能。这允许逆向工程师在特定的函数调用发生时执行自定义的代码，例如检查函数参数、返回值或修改函数行为。

**涉及的二进制底层、Linux、Android 内核及框架知识：**

* **二进制底层知识:**
    * **ARM 和 Thumb 指令集:** 测试用例中使用了大量的 ARM 和 Thumb 汇编指令，这直接涉及到对二进制指令的理解。`stalker` 需要能够解析和理解这些指令，才能正确地跟踪代码执行和生成事件。
    * **内存布局:**  `stalker` 需要理解进程的内存布局，才能确定指令的地址、函数的入口点等。测试用例中的地址计算和断言都依赖于对内存布局的理解。
    * **函数调用约定:**  像 `arm_call_probe` 这样的测试用例涉及到函数调用约定，例如参数传递方式、返回值处理等。`stalker` 的调用探测功能需要能够获取这些信息。

* **Linux/Android 内核知识:**
    * **进程和线程管理:**  `stalker` 需要与操作系统交互才能跟踪目标进程的执行。像 `follow_thread` 和 `pthread_create` 这样的测试用例涉及到对进程和线程的管理。
    * **系统调用:** `follow_syscall` 测试用例表明 `stalker` 可以跟踪系统调用。这需要 `stalker` 能够识别和捕获系统调用事件，这通常需要与内核进行交互。
    * **内存管理:**  `stalker` 需要能够访问目标进程的内存，才能读取指令和数据。

* **Android 框架知识 (可能间接涉及):**
    * 虽然这个特定的文件没有直接涉及 Android 特定的 API，但 Frida 通常用于 Android 逆向。`stalker` 在 Android 环境下的工作原理可能涉及到对 ART (Android Runtime) 或 Dalvik 虚拟机内部机制的理解。

**逻辑推理和假设输入/输出：**

以 `arm_no_events` 测试用例为例：

* **假设输入:**  执行 `arm_flat_code` 这段 ARM 汇编代码，并且没有在 `stalker` 中设置任何事件类型的掩码（例如，不监听 `GUM_EXEC`, `GUM_CALL` 等事件）。
* **预期输出:**  `fixture->sink->events->len` 的值为 0，这意味着 `stalker` 没有生成任何事件。

以 `arm_exec_events_generated` 测试用例为例：

* **假设输入:** 执行 `arm_flat_code`，并且在 `stalker` 中设置了 `GUM_EXEC` 事件类型的掩码。
* **预期输出:** `fixture->sink->events->len` 的值等于 `INVOKER_INSN_COUNT + (CODE_SIZE (arm_flat_code) / 4)`。这意味着 `stalker` 生成了预期的执行事件数量，包括 invoker 代码的执行事件和 `arm_flat_code` 中每条指令的执行事件。测试用例中还断言了每个执行事件的 `location` 属性是否正确。

**用户或编程常见的使用错误：**

* **未设置事件掩码:**  用户忘记设置 `stalker` 的事件掩码，导致没有捕获到任何事件，就像 `arm_no_events` 和 `thumb_no_events` 测试用例所验证的那样。
* **错误的地址:**  在配置 `stalker` 的排除范围或调用探测时，用户可能使用了错误的内存地址，导致 `stalker` 的行为不符合预期。
* **不理解 ARM/Thumb 模式切换:**  在 ARM 架构中，代码可以在 ARM 和 Thumb 模式之间切换。用户可能没有考虑到这一点，导致 `stalker` 在解析指令时出现错误。
* **对 `trust_threshold` 的误解:**  用户可能不理解 `trust_threshold` 的作用，导致在处理自修改代码时出现意外的行为。`self_modifying_code_should_be_detected_with_threshold_minus_one` 等测试用例就是为了验证这方面的功能。
* **在多线程环境下的使用错误:**  在多线程环境下使用 `stalker` 时，用户可能没有正确地同步对 `stalker` 状态的访问，导致数据竞争或其他并发问题。`pthread_create` 和 `RunOnThread` 相关的测试用例可能覆盖了这方面。

**用户操作如何一步步到达这里 (作为调试线索)：**

1. **用户想要使用 Frida 进行 ARM 架构的动态分析。**
2. **用户编写了一个 Frida 脚本，使用了 `Stalker` API 来追踪目标进程的执行。**  例如，用户可能使用了 `Stalker.follow()` 方法来启动跟踪，并设置了想要捕获的事件类型。
3. **在测试或调试脚本时，用户可能遇到了 `stalker` 行为不符合预期的情况。** 例如，没有捕获到预期的事件，或者捕获到的事件地址不正确。
4. **为了排查问题，用户可能会查看 Frida 的源代码，特别是 `stalker` 组件的相关代码。**  `frida/subprojects/frida-gum/tests/core/arch-arm/stalker-arm.c` 这个测试文件可以作为用户理解 `stalker` 工作原理的重要参考。
5. **用户可以运行这些测试用例，来验证 `stalker` 在各种场景下的行为，并与自己的脚本行为进行对比，从而找到问题所在。**  测试用例中的 `INVOKE_ARM_EXPECTING` 和 `INVOKE_THUMB_EXPECTING` 宏模拟了 Frida 脚本调用 `stalker` 的过程。

希望以上分析能够帮助你理解这个代码文件的功能。 如果有任何疑问，请随时提出。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-arm/stalker-arm.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2009-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-arm-fixture.c"

#ifdef HAVE_LINUX
# include <errno.h>
# include <fcntl.h>
# include <unistd.h>
# include <sys/wait.h>
#endif

TESTLIST_BEGIN (stalker)
  TESTENTRY (trust_should_be_one_by_default)

  TESTENTRY (arm_no_events)
  TESTENTRY (thumb_no_events)
  TESTENTRY (arm_exec_events_generated)
  TESTENTRY (thumb_exec_events_generated)
  TESTENTRY (arm_call_events_generated)
  TESTENTRY (thumb_call_events_generated)
  TESTENTRY (arm_block_events_generated)
  TESTENTRY (thumb_block_events_generated)
  TESTENTRY (arm_nested_call_events_generated)
  TESTENTRY (thumb_nested_call_events_generated)
  TESTENTRY (arm_nested_ret_events_generated)
  TESTENTRY (thumb_nested_ret_events_generated)
  TESTENTRY (arm_unmodified_lr)
  TESTENTRY (thumb_unmodified_lr)
  TESTENTRY (arm_excluded_range)
  TESTENTRY (thumb_excluded_range)
  TESTENTRY (arm_excluded_range_call_events)
  TESTENTRY (thumb_excluded_range_call_events)
  TESTENTRY (arm_excluded_range_ret_events)
  TESTENTRY (thumb_excluded_range_ret_events)
  TESTENTRY (arm_pop_pc_ret_events_generated)
  TESTENTRY (thumb_pop_pc_ret_events_generated)
  TESTENTRY (arm_pop_just_pc_ret_events_generated)
  TESTENTRY (thumb_pop_just_pc_ret_events_generated)
  TESTENTRY (thumb_pop_just_pc2_ret_events_generated)
  TESTENTRY (arm_ldm_pc_ret_events_generated)
  TESTENTRY (thumb_ldm_pc_ret_events_generated)
  TESTENTRY (arm_branch_cc_block_events_generated)
  TESTENTRY (thumb_branch_cc_block_events_generated)

  TESTENTRY (thumb_cbz_cbnz_block_events_generated)

  TESTENTRY (thumb2_mov_pc_reg_exec_events_generated)
  TESTENTRY (thumb2_mov_pc_reg_without_thumb_bit_set)
  TESTENTRY (thumb2_mov_pc_reg_no_clobber_reg)

  /*
   * The following tests have no Thumb equivalent as Thumb does not support
   * conditional instructions nor is PC allowed as the destination register
   * for some opcodes.
   */
  TESTENTRY (arm_branch_link_cc_block_events_generated)
  TESTENTRY (arm_cc_excluded_range)
  TESTENTRY (arm_ldr_pc)
  TESTENTRY (arm_ldr_pc_pre_index_imm)
  TESTENTRY (arm_ldr_pc_post_index_imm)
  TESTENTRY (arm_ldr_pc_pre_index_imm_negative)
  TESTENTRY (arm_ldr_pc_post_index_imm_negative)
  TESTENTRY (arm_ldr_pc_shift)
  TESTENTRY (arm_sub_pc)
  TESTENTRY (arm_add_pc)
  TESTENTRY (arm_ldmia_pc)

  TESTENTRY (thumb_it_eq)
  TESTENTRY (thumb_it_al)
  TESTENTRY (thumb_it_eq_branch)
  TESTENTRY (thumb_itt_eq_branch)
  TESTENTRY (thumb_ite_eq_branch)
  TESTENTRY (thumb_it_eq_branch_link)
  TESTENTRY (thumb_it_eq_branch_link_excluded)
  TESTENTRY (thumb_it_eq_pop)
  TESTENTRY (thumb_itttt_eq_blx_reg)
  TESTENTRY (thumb_it_flags)
  TESTENTRY (thumb_it_flags2)
  TESTENTRY (thumb_tbb)
  TESTENTRY (thumb_tbh)

  TESTENTRY (arm_call_probe)
  TESTENTRY (thumb_call_probe)

  TESTENTRY (self_modifying_code_should_be_detected_with_threshold_minus_one)
  TESTENTRY (self_modifying_code_should_not_be_detected_with_threshold_zero)
  TESTENTRY (self_modifying_code_should_be_detected_with_threshold_one)

  TESTENTRY (call_thumb)
  TESTENTRY (branch_thumb)
  TESTENTRY (can_follow_workload)
  TESTENTRY (performance)

  TESTENTRY (custom_transformer)
  TESTENTRY (arm_callout)
  TESTENTRY (thumb_callout)
  TESTENTRY (arm_transformer_should_be_able_to_replace_call_with_callout)
  TESTENTRY (arm_transformer_should_be_able_to_replace_jumpout_with_callout)
  TESTENTRY (unfollow_should_be_allowed_before_first_transform)
  TESTENTRY (unfollow_should_be_allowed_mid_first_transform)
  TESTENTRY (unfollow_should_be_allowed_after_first_transform)
  TESTENTRY (unfollow_should_be_allowed_before_second_transform)
  TESTENTRY (unfollow_should_be_allowed_mid_second_transform)
  TESTENTRY (unfollow_should_be_allowed_after_second_transform)
  TESTENTRY (follow_me_should_support_nullable_event_sink)
  TESTENTRY (arm_invalidation_for_current_thread_should_be_supported)
  TESTENTRY (thumb_invalidation_for_current_thread_should_be_supported)
  TESTENTRY (arm_invalidation_for_specific_thread_should_be_supported)
  TESTENTRY (thumb_invalidation_for_specific_thread_should_be_supported)
  TESTENTRY (arm_invalidation_should_allow_block_to_grow)
  TESTENTRY (thumb_invalidation_should_allow_block_to_grow)

  TESTENTRY (arm_exclusive_load_store_should_not_be_disturbed)
  TESTENTRY (thumb_exclusive_load_store_should_not_be_disturbed)

  TESTENTRY (follow_syscall)
  TESTENTRY (follow_thread)
  TESTENTRY (unfollow_should_handle_terminated_thread)
  TESTENTRY (pthread_create)
  TESTENTRY (heap_api)

#ifdef HAVE_LINUX
  TESTENTRY (prefetch)
#endif

  TESTGROUP_BEGIN ("RunOnThread")
    TESTENTRY (run_on_thread_current)
    TESTENTRY (run_on_thread_current_sync)
    TESTENTRY (run_on_thread_other)
    TESTENTRY (run_on_thread_other_sync)
  TESTGROUP_END ()
TESTLIST_END ()

typedef struct _RunOnThreadCtx RunOnThreadCtx;
typedef struct _TestThreadSyncData TestThreadSyncData;

struct _RunOnThreadCtx
{
  GumThreadId caller_id;
  GumThreadId thread_id;
};

struct _TestThreadSyncData
{
  GMutex mutex;
  GCond cond;
  gboolean started;
  GumThreadId thread_id;
  gboolean * done;
};

static gboolean store_range_of_test_runner (const GumModuleDetails * details,
    gpointer user_data);
static guint32 pretend_workload (GumMemoryRange * runner_range);
static guint32 crc32b (const guint8 * message, gsize size);
static gboolean test_log_fatal_func (const gchar * log_domain,
    GLogLevelFlags log_level, const gchar * message, gpointer user_data);
static GLogWriterOutput test_log_writer_func (GLogLevelFlags log_level,
    const GLogField * fields, gsize n_fields, gpointer user_data);
static void duplicate_adds (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void transform_arm_return_value (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void on_arm_ret (GumCpuContext * cpu_context, gpointer user_data);
static gboolean is_arm_mov_pc_lr (const guint8 * bytes, gsize size);
static void transform_thumb_return_value (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void on_thumb_ret (GumCpuContext * cpu_context,
    gpointer user_data);
static gboolean is_thumb_pop_pc (const guint8 * bytes, gsize size);
static void replace_call_with_callout (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void replace_jumpout_with_callout (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void callout_set_cool (GumCpuContext * cpu_context, gpointer user_data);
static void unfollow_during_transform (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void test_invalidation_for_current_thread_with_target (GumAddress target,
    TestArmStalkerFixture * fixture);
static void modify_to_return_true_after_three_calls (
    GumStalkerIterator * iterator, GumStalkerOutput * output,
    gpointer user_data);
static void invalidate_after_three_calls (GumCpuContext * cpu_context,
    gpointer user_data);
static void test_invalidation_for_specific_thread_with_target (
    GumAddress target, TestArmStalkerFixture * fixture);
static void start_invalidation_target (InvalidationTarget * target,
    gconstpointer target_function, TestArmStalkerFixture * fixture);
static void join_invalidation_target (InvalidationTarget * target);
static gpointer run_stalked_until_finished (gpointer data);
static void modify_to_return_true_on_subsequent_transform (
    GumStalkerIterator * iterator, GumStalkerOutput * output,
    gpointer user_data);
static void test_invalidation_block_growth_with_target (GumAddress target,
    TestArmStalkerFixture * fixture);
static void add_n_return_value_increments (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void insert_callout_after_cmp (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void bump_num_cmp_callouts (GumCpuContext * cpu_context,
    gpointer user_data);
static gpointer run_stalked_briefly (gpointer data);
static gpointer run_stalked_into_termination (gpointer data);
static gpointer increment_integer (gpointer data);
static void patch_code_pointer (GumAddress code, guint offset,
    GumAddress value);
static void patch_code_pointer_slot (gpointer mem, gpointer user_data);

#ifdef HAVE_LINUX
static void prefetch_on_event (const GumEvent * event,
    GumCpuContext * cpu_context, gpointer user_data);
static void prefetch_run_child (GumStalker * stalker,
    GumMemoryRange * runner_range, int compile_fd, int execute_fd);
static void prefetch_activation_target (void);
static void prefetch_write_blocks (int fd, GHashTable * table);
static void prefetch_read_blocks (int fd, GHashTable * table);

static GHashTable * prefetch_compiled = NULL;
static GHashTable * prefetch_executed = NULL;
#endif

static void run_on_thread (const GumCpuContext * cpu_context,
    gpointer user_data);
static GThread * create_sleeping_dummy_thread_sync (gboolean * done,
    GumThreadId * thread_id);
static gpointer sleeping_dummy (gpointer data);

TESTCASE (trust_should_be_one_by_default)
{
  g_assert_cmpuint (gum_stalker_get_trust_threshold (fixture->stalker), ==, 1);
}

TESTCASE (deactivate_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
      "Activate/deactivate unsupported");
  gum_stalker_deactivate (fixture->stalker);
  g_test_assert_expected_messages ();
}

TESTCASE (activate_unsupported)
{
  g_test_expect_message (G_LOG_DOMAIN, G_LOG_LEVEL_WARNING,
      "Activate/deactivate unsupported");
  gum_stalker_activate (fixture->stalker, NULL);
  g_test_assert_expected_messages ();
}

TESTCODE (arm_flat_code,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0  */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1   */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr      */
);

TESTCODE (thumb_flat_code,
  0x00, 0xb5,             /* push {lr}       */
  0x00, 0x1a,             /* subs r0, r0, r0 */
  0x01, 0x30,             /* adds r0, 1      */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xbd              /* pop {pc}        */
);

TESTCASE (arm_no_events)
{
  INVOKE_ARM_EXPECTING (GUM_NOTHING, arm_flat_code, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCASE (thumb_no_events)
{
  INVOKE_THUMB_EXPECTING (GUM_NOTHING, thumb_flat_code, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCASE (arm_exec_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_EXEC, arm_flat_code, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_INSN_COUNT + (CODE_SIZE (arm_flat_code) / 4));

  GUM_ASSERT_EVENT_ADDR (exec, 0, location,
      fixture->invoker + INVOKER_IMPL_OFFSET);
  GUM_ASSERT_EVENT_ADDR (exec, 1, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 4);

  GUM_ASSERT_EVENT_ADDR (exec, 2, location, func);
  GUM_ASSERT_EVENT_ADDR (exec, 3, location, func + 4);
  GUM_ASSERT_EVENT_ADDR (exec, 4, location, func + 8);
  GUM_ASSERT_EVENT_ADDR (exec, 5, location, func + 12);

  GUM_ASSERT_EVENT_ADDR (exec, 6, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 8);
  GUM_ASSERT_EVENT_ADDR (exec, 7, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 12);
  GUM_ASSERT_EVENT_ADDR (exec, 8, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 16);
  GUM_ASSERT_EVENT_ADDR (exec, 9, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 20);
}

TESTCASE (thumb_exec_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_EXEC, thumb_flat_code, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_INSN_COUNT + (CODE_SIZE (thumb_flat_code) / 2));

  GUM_ASSERT_EVENT_ADDR (exec, 0, location,
      fixture->invoker + INVOKER_IMPL_OFFSET);
  GUM_ASSERT_EVENT_ADDR (exec, 1, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 4);

  GUM_ASSERT_EVENT_ADDR (exec, 2, location, func + 0 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 3, location, func + 2 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 4, location, func + 4 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 5, location, func + 6 + 1);
  GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 8 + 1);

  GUM_ASSERT_EVENT_ADDR (exec, 7, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 8);
  GUM_ASSERT_EVENT_ADDR (exec, 8, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 12);
  GUM_ASSERT_EVENT_ADDR (exec, 9, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 16);
  GUM_ASSERT_EVENT_ADDR (exec, 10, location,
      fixture->invoker + INVOKER_IMPL_OFFSET + 20);
}

TESTCASE (arm_call_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_CALL, arm_flat_code, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT);

  GUM_ASSERT_EVENT_ADDR (call, 0, target, func);
  GUM_ASSERT_EVENT_ADDR (call, 0, depth, 0);
}

TESTCASE (thumb_call_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_CALL, thumb_flat_code, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_CALL_INSN_COUNT);

  GUM_ASSERT_EVENT_ADDR (call, 0, target, func + 1);
  GUM_ASSERT_EVENT_ADDR (call, 0, depth, 0);
}

TESTCODE (arm_block_events,
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x00, 0x00, 0x00, 0xea, /* b beach        */

  0xf0, 0x00, 0xf0, 0xe7, /* udf 0          */

  /* beach:                                 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1  */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr     */
);

TESTCASE (arm_block_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_BLOCK, arm_block_events, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, start, func);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, end, func + (3 * 4));
}

TESTCODE (thumb_block_events,
  0x00, 0xb5, /* push {lr}       */
  0x00, 0x1a, /* subs r0, r0, r0 */
  0x01, 0x30, /* adds r0, 1      */
  0x00, 0xe0, /* b beach         */

  0x00, 0xde, /* udf 0           */

  /* beach:                      */
  0x01, 0x30, /* adds r0, 1      */
  0x00, 0xbd  /* pop {pc}        */
);

TESTCASE (thumb_block_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_BLOCK, thumb_block_events, 2);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_BLOCK_COUNT + 1);

  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, start, func + 1);
  GUM_ASSERT_EVENT_ADDR (block, INVOKEE_BLOCK_INDEX, end, func + (4 * 2) + 1);
}

TESTCODE (arm_nested_call,
  0x00, 0x40, 0x2d, 0xe9, /* stmdb sp!, {lr} */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0  */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1   */
  0x02, 0x00, 0x00, 0xeb, /* bl func_a       */
  0x06, 0x00, 0x00, 0xeb, /* bl func_b       */
  0x00, 0x40, 0xbd, 0xe8, /* ldm sp!, {lr}   */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr      */

  /* func_a:                                 */
  0x00, 0x40, 0x2d, 0xe9, /* stmdb sp!, {lr} */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1   */
  0x01, 0x00, 0x00, 0xeb, /* bl func_b       */
  0x00, 0x40, 0xbd, 0xe8, /* ldm sp!, {lr}   */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr      */

  /* func_b:                                 */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1   */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr      */
);

TESTCASE (arm_nested_call_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_CALL, arm_nested_call, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 3);

  GUM_ASSERT_EVENT_ADDR (call, 0, target, func);
  GUM_ASSERT_EVENT_ADDR (call, 0, depth, 0);

  GUM_ASSERT_EVENT_ADDR (call, 1, location, func + (3 * 4));
  GUM_ASSERT_EVENT_ADDR (call, 1, target, func + (7 * 4));
  GUM_ASSERT_EVENT_ADDR (call, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR (call, 2, location, func + (9 * 4));
  GUM_ASSERT_EVENT_ADDR (call, 2, target, func + (12 * 4));
  GUM_ASSERT_EVENT_ADDR (call, 2, depth, 2);

  GUM_ASSERT_EVENT_ADDR (call, 3, location, func + (4 * 4));
  GUM_ASSERT_EVENT_ADDR (call, 3, target, func + (12 * 4));
  GUM_ASSERT_EVENT_ADDR (call, 3, depth, 1);
}

TESTCODE (thumb_nested_call,
  0x00, 0xb5,             /* push {lr}       */
  0x00, 0x1a,             /* subs r0, r0, r0 */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xf0, 0x03, 0xf8, /* bl func_a       */
  0x00, 0xf0, 0x06, 0xf8, /* bl func_b       */
  0x00, 0xbd,             /* pop {pc}        */

  /* func_a:                                 */
  0x00, 0xb5,             /* push {lr}       */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xf0, 0x01, 0xf8, /* bl func_b       */
  0x00, 0xbd,             /* pop {pc}        */

  /* func_b:                                 */
  0x00, 0xb5,             /* push {lr}       */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xbd              /* pop {pc}        */
);

TESTCASE (thumb_nested_call_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_CALL, thumb_nested_call, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==,
      INVOKER_CALL_INSN_COUNT + 3);

  GUM_ASSERT_EVENT_ADDR (call, 0, target, func + 1);
  GUM_ASSERT_EVENT_ADDR (call, 0, depth, 0);

  GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 6 + 1);
  GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 16 + 1);
  GUM_ASSERT_EVENT_ADDR (call, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR (call, 2, location, func + 20 + 1);
  GUM_ASSERT_EVENT_ADDR (call, 2, target, func + 26 + 1);
  GUM_ASSERT_EVENT_ADDR (call, 2, depth, 2);

  GUM_ASSERT_EVENT_ADDR (call, 3, location, func + 10 + 1);
  GUM_ASSERT_EVENT_ADDR (call, 3, target, func + 26 + 1);
  GUM_ASSERT_EVENT_ADDR (call, 3, depth, 1);
}

TESTCASE (arm_nested_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_ARM_EXPECTING (GUM_RET, arm_nested_call, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + (13 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + (10 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 2);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + (11 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 1, target, func + (4 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 2, location, func + (13 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 2, target, func + (5 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 2, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 3, location, func + (6 * 4));
  GUM_ASSERT_EVENT_ADDR (ret, 3, depth, 0);
}

TESTCASE (thumb_nested_ret_events_generated)
{
  GumAddress func;

  func = INVOKE_THUMB_EXPECTING (GUM_RET, thumb_nested_call, 4);

  g_assert_cmpuint (fixture->sink->events->len, ==, 4);

  GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 30 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 24 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 2);

  GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 24 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 1, target, func + 10 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 2, location, func + 30 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 2, target, func + 14 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 2, depth, 1);

  GUM_ASSERT_EVENT_ADDR (ret, 3, location, func + 14 + 1);
  GUM_ASSERT_EVENT_ADDR (ret, 3, depth, 0);
}

typedef struct _CallProbeContext CallProbeContext;

struct _CallProbeContext
{
  guint num_calls;
  gpointer target_address;
  gpointer return_address;
};

static void test_call_probe (GumAddress func, GumAddress func_a,
    GumAddress return_address, TestArmStalkerFixture * fixture);
static void probe_func_a_invocation (GumCallDetails * details,
    gpointer user_data);

TESTCODE (arm_call_probe,
  0x00, 0x44, 0x2d, 0xe9, /* push {r10, lr}   */
  0xaa, 0xa0, 0xa0, 0xe3, /* mov r10, 0xaa    */
  0x44, 0x30, 0xa0, 0xe3, /* mov r3, 0x44     */
  0x33, 0x20, 0xa0, 0xe3, /* mov r2, 0x33     */
  0x22, 0x10, 0xa0, 0xe3, /* mov r1, 0x22     */
  0x11, 0x00, 0xa0, 0xe3, /* mov r0, 0x11     */
  0x03, 0x00, 0x2d, 0xe9, /* push {r0, r1}    */
  0x06, 0x00, 0x00, 0xeb, /* bl func_a        */
  0x03, 0x00, 0xbd, 0xe8, /* pop {r0, r1}     */
  0x88, 0x30, 0xa0, 0xe3, /* mov r3, 0x88     */
  0x77, 0x20, 0xa0, 0xe3, /* mov r2, 0x77     */
  0x66, 0x10, 0xa0, 0xe3, /* mov r1, 0x66     */
  0x55, 0x00, 0xa0, 0xe3, /* mov r0, 0x55     */
  0x02, 0x00, 0x00, 0xeb, /* bl func_b        */
  0x00, 0x84, 0xbd, 0xe8, /* pop {r10, pc}    */

  /* func_a: */
  0x88, 0x00, 0xa0, 0xe3, /* mov r0, 0x88     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr       */

  /* func_b: */
  0x99, 0x00, 0xa0, 0xe3, /* mov r0, 0x99     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr       */
);

TESTCODE (thumb_call_probe,
  0x2d, 0xe9, 0x00, 0x44, /* push.w {r10, lr} */
  0x4f, 0xf0, 0xaa, 0x0a, /* mov.w r10, 0xaa  */
  0x4f, 0xf0, 0x44, 0x03, /* mov.w r3, 0x44   */
  0x4f, 0xf0, 0x33, 0x02, /* mov.w r2, 0x33   */
  0x4f, 0xf0, 0x22, 0x01, /* mov.w r1, 0x22   */
  0x4f, 0xf0, 0x11, 0x00, /* mov.w r0, 0x11   */
  0x03, 0xb4,             /* push {r0, r1}    */
  0x00, 0xf0, 0x0d, 0xf8, /* bl func_a        */
  0x03, 0xbc,             /* pop {r0, r1}     */
  0x4f, 0xf0, 0x88, 0x03, /* mov.w r3, 0x88   */
  0x4f, 0xf0, 0x77, 0x02, /* mov.w r2, 0x77   */
  0x4f, 0xf0, 0x66, 0x01, /* mov.w r1, 0x66   */
  0x4f, 0xf0, 0x55, 0x00, /* mov.w r0, 0x55   */
  0x00, 0xf0, 0x05, 0xf8, /* bl func_b        */
  0xbd, 0xe8, 0x00, 0x84, /* pop.w {r10, pc}  */

  /* func_a: */
  0x4f, 0xf0, 0x88, 0x00, /* mov.w r0, 0x88   */
  0x70, 0x47,             /* bx lr            */

  /* func_b: */
  0x4f, 0xf0, 0x99, 0x00, /* mov.w r0, 0x99   */
  0x70, 0x47,             /* bx lr            */
);

TESTCASE (arm_call_probe)
{
  GumAddress func = DUP_TESTCODE (arm_call_probe);

  test_call_probe (
      func,
      func + 15 * 4,
      func + 8 * 4,
      fixture);
}

TESTCASE (thumb_call_probe)
{
  GumAddress func = DUP_TESTCODE (thumb_call_probe);

  test_call_probe (
      func + 1,
      func + 56 + 1,
      func + 30 + 1,
      fixture);
}

static void
test_call_probe (GumAddress func,
                 GumAddress func_a,
                 GumAddress return_address,
                 TestArmStalkerFixture * fixture)
{
  gpointer func_a_ptr;
  CallProbeContext probe_ctx, secondary_probe_ctx;
  GumProbeId probe_id;

  func_a_ptr = GSIZE_TO_POINTER (func_a);

  probe_ctx.num_calls = 0;
  probe_ctx.target_address = func_a_ptr;
  probe_ctx.return_address = GSIZE_TO_POINTER (return_address);
  probe_id = gum_stalker_add_call_probe (fixture->stalker, func_a_ptr,
      probe_func_a_invocation, &probe_ctx, NULL);
  FOLLOW_AND_INVOKE (func);
  g_assert_cmpuint (probe_ctx.num_calls, ==, 1);

  secondary_probe_ctx.num_calls = 0;
  secondary_probe_ctx.target_address = probe_ctx.target_address;
  secondary_probe_ctx.return_address = probe_ctx.return_address;
  gum_stalker_add_call_probe (fixture->stalker, func_a_ptr,
      probe_func_a_invocation, &secondary_probe_ctx, NULL);
  FOLLOW_AND_INVOKE (func);
  g_assert_cmpuint (probe_ctx.num_calls, ==, 2);
  g_assert_cmpuint (secondary_probe_ctx.num_calls, ==, 1);

  gum_stalker_remove_call_probe (fixture->stalker, probe_id);
  FOLLOW_AND_INVOKE (func);
  g_assert_cmpuint (probe_ctx.num_calls, ==, 2);
  g_assert_cmpuint (secondary_probe_ctx.num_calls, ==, 2);
}

static void
probe_func_a_invocation (GumCallDetails * details,
                         gpointer user_data)
{
  CallProbeContext * ctx = user_data;
  gsize * stack_values = details->stack_data;
  GumCpuContext * cpu_context = details->cpu_context;

  ctx->num_calls++;

  GUM_ASSERT_CMPADDR (details->target_address, ==, ctx->target_address);
  GUM_ASSERT_CMPADDR (details->return_address, ==, ctx->return_address);

  g_assert_cmphex (GPOINTER_TO_SIZE (
      gum_cpu_context_get_nth_argument (cpu_context, 0)), ==, 0x11);
  g_assert_cmphex (GPOINTER_TO_SIZE (
      gum_cpu_context_get_nth_argument (cpu_context, 1)), ==, 0x22);

  g_assert_cmphex (stack_values[0], ==, 0x11);
  g_assert_cmphex (stack_values[1], ==, 0x22);

  g_assert_cmphex (cpu_context->pc, ==,
      GPOINTER_TO_SIZE (ctx->target_address) & ~1);
  g_assert_cmphex (cpu_context->lr, ==,
      GPOINTER_TO_SIZE (ctx->return_address));
  g_assert_cmphex (cpu_context->r[0], ==, 0x11);
  g_assert_cmphex (cpu_context->r[1], ==, 0x22);
  g_assert_cmphex (cpu_context->r[2], ==, 0x33);
  g_assert_cmphex (cpu_context->r[3], ==, 0x44);
  g_assert_cmphex (cpu_context->r10, ==, 0xaa);
}

TESTCODE (arm_unmodified_lr,
  0x00, 0x40, 0x2d, 0xe9, /* stmdb sp!, {lr} */
  0x00, 0x00, 0x00, 0xeb, /* bl part_two     */

  0xec, 0xec, 0xec, 0xec,

  /* part_two:                               */
  0x00, 0x00, 0x9e, 0xe5, /* ldr r0, [lr]    */
  0x00, 0x40, 0xbd, 0xe8, /* ldm sp!, {lr}   */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr      */
);

TESTCASE (arm_unmodified_lr)
{
  INVOKE_ARM_EXPECTING (0, arm_unmodified_lr, 0xecececec);
}

TESTCODE (thumb_unmodified_lr,
  0x00, 0xb5,             /* push {lr}       */
  0x00, 0xf0, 0x02, 0xf8, /* bl part_two     */

  0xec, 0xec, 0xec, 0xec,

  /* part_two:                               */
  0x49, 0x1a,             /* subs r1, r1, r1 */
  0x01, 0x31,             /* adds r1, 1      */
  0x70, 0x46,             /* mov r0, lr      */
  0x88, 0x43,             /* bics r0, r1     */
  0x00, 0x68,             /* ldr r0, [r0]    */
  0x00, 0xbd              /* pop {pc}        */
);

TESTCASE (thumb_unmodified_lr)
{
  INVOKE_THUMB_EXPECTING (0, thumb_unmodified_lr, 0xecececec);
}

TESTCODE (arm_excluded_range,
  0x00, 0x40, 0x2d, 0xe9, /* stmdb sp!, {lr}  */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x01, 0x00, 0x00, 0xeb, /* bl excluded_func */
  0x00, 0x40, 0xbd, 0xe8, /* ldm sp!, {lr}    */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr       */

  /* excluded_func:                           */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1    */
  0x0e, 0xf0, 0xa0, 0xe1  /* mov pc, lr       */
);

TESTCASE (arm_excluded_range)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_excluded_range);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 24,
      .size = 8
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_EXEC;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 2);

    g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 6);

    GUM_ASSERT_EVENT_ADDR (exec, 2, location, func);
    GUM_ASSERT_EVENT_ADDR (exec, 3, location, func + 4);
    GUM_ASSERT_EVENT_ADDR (exec, 4, location, func + 8);
    GUM_ASSERT_EVENT_ADDR (exec, 5, location, func + 12);
    GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 16);
    GUM_ASSERT_EVENT_ADDR (exec, 7, location, func + 20);
  }
}

TESTCODE (thumb_excluded_range,
  0x00, 0xb5,             /* push {lr}        */
  0x00, 0x1a,             /* subs r0, r0, r0  */
  0x01, 0x30,             /* adds r0, 1       */
  0x00, 0xf0, 0x01, 0xf8, /* bl excluded_func */
  0x00, 0xbd,             /* pop {pc}         */

  /* excluded_func:                           */
  0x00, 0xb5,             /* push {lr}        */
  0x01, 0x30,             /* adds r0, 1       */
  0x00, 0xbd              /* pop {pc}         */
);

TESTCASE (thumb_excluded_range)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb_excluded_range);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 12,
      .size = 6
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_EXEC;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 2);

    g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 5);

    GUM_ASSERT_EVENT_ADDR (exec, 2, location, func +  0 + 1);
    GUM_ASSERT_EVENT_ADDR (exec, 3, location, func +  2 + 1);
    GUM_ASSERT_EVENT_ADDR (exec, 4, location, func +  4 + 1);
    GUM_ASSERT_EVENT_ADDR (exec, 5, location, func +  6 + 1);
    GUM_ASSERT_EVENT_ADDR (exec, 6, location, func + 10 + 1);
  }
}

TESTCODE (arm_excluded_range_call,
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}         */
  0x00, 0x00, 0x40, 0xe0, /* sub r0, r0, r0    */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1     */
  0x05, 0x00, 0x00, 0xeb, /* bl func_c         */
  0x00, 0x00, 0x00, 0xeb, /* bl func_a         */
  0x04, 0xf0, 0x9d, 0xe4, /* pop {pc}          */

  /* func_a:                                   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr        */

  /* func_b:                                   */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1     */
  0x0e, 0xf0, 0xa0, 0xe1, /* mov pc, lr        */

  /* func_c:                                   */
  0x04, 0xe0, 0x2d, 0xe5, /* push {lr}         */
  0x01, 0x00, 0x80, 0xe2, /* add r0, r0, 1     */
  0xfa, 0xff, 0xff, 0xeb, /* bl func_b         */
  0x04, 0xf0, 0x9d, 0xe4  /* pop {pc}          */
);

TESTCASE (arm_excluded_range_call_events)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_excluded_range_call);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 40,
      .size = 16
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_CALL;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 4);

    g_assert_cmpuint (fixture->sink->events->len, ==,
        INVOKER_CALL_INSN_COUNT + 2);

    GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 12);
    GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 40);
    GUM_ASSERT_EVENT_ADDR (call, 1, depth, 1);

    GUM_ASSERT_EVENT_ADDR (call, 2, location, func + 16);
    GUM_ASSERT_EVENT_ADDR (call, 2, target, func + 24);
    GUM_ASSERT_EVENT_ADDR (call, 2, depth, 1);
  }
}

TESTCODE (thumb_excluded_range_call,
  0x00, 0xb5,             /* push {lr}       */
  0x00, 0x1a,             /* subs r0, r0, r0 */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xf0, 0x09, 0xf8, /* bl func_c       */
  0x00, 0xf0, 0x01, 0xf8, /* bl func_a       */
  0x00, 0xbd,             /* pop {pc}        */

  /* func_a:                                 */
  0x00, 0xb5,             /* push {lr}       */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xbd,             /* pop {pc}        */

  /* func_b:                                 */
  0x00, 0xb5,             /* push {lr}       */
  0x01, 0x30,             /* adds r0, 1      */
  0x00, 0xbd,             /* pop {pc}        */

  /* func_c:                                 */
  0x00, 0xb5,             /* push {lr}       */
  0x01, 0x30,             /* adds r0, 1      */
  0xff, 0xf7, 0xf9, 0xff, /* bl func_b       */
  0x00, 0xbd              /* pop {pc}        */
);

TESTCASE (thumb_excluded_range_call_events)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb_excluded_range_call);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 28,
      .size = 10
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_CALL;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 4);

    g_assert_cmpuint (fixture->sink->events->len, ==,
        INVOKER_CALL_INSN_COUNT + 2);

    GUM_ASSERT_EVENT_ADDR (call, 1, location, func + 6 + 1);
    GUM_ASSERT_EVENT_ADDR (call, 1, target, func + 28 + 1);
    GUM_ASSERT_EVENT_ADDR (call, 1, depth, 1);

    GUM_ASSERT_EVENT_ADDR (call, 2, location, func + 10 + 1);
    GUM_ASSERT_EVENT_ADDR (call, 2, target, func + 16 + 1);
    GUM_ASSERT_EVENT_ADDR (call, 2, depth, 1);
  }
}

TESTCASE (arm_excluded_range_ret_events)
{
  GumAddress func;

  func = DUP_TESTCODE (arm_excluded_range_call);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 40,
      .size = 16
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_RET;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func), ==, 4);

    g_assert_cmpuint (fixture->sink->events->len, ==, 2);

    GUM_ASSERT_EVENT_ADDR (ret, 0, location, func + 28);
    GUM_ASSERT_EVENT_ADDR (ret, 0, target, func + 20);
    GUM_ASSERT_EVENT_ADDR (ret, 0, depth, 1);

    GUM_ASSERT_EVENT_ADDR (ret, 1, location, func + 20);
    GUM_ASSERT_EVENT_ADDR (ret, 1, depth, 0);
  }
}

TESTCASE (thumb_excluded_range_ret_events)
{
  GumAddress func;

  func = DUP_TESTCODE (thumb_excluded_range_call);

  {
    GumMemoryRange r = {
      .base_address = GUM_ADDRESS (func) + 28,
      .size = 10
    };

    gum_stalker_exclude (fixture->stalker, &r);
  }

  {
    fixture->sink->mask = GUM_RET;
    g_assert_cmpuint (FOLLOW_AND_INVOKE (func + 1), ==, 4);

    g_assert_
```