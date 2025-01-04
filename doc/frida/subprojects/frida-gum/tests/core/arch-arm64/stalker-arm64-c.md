Response:
The user wants a summary of the functionality of the C code provided. The code is a test suite for the `stalker` component of the Frida dynamic instrumentation tool, specifically for the ARM64 architecture.

Here's a breakdown of the thought process:

1. **Identify the Core Functionality:** The file name `stalker-arm64.c` and the include `stalker-arm64-fixture.c` strongly suggest this is a test suite for the Frida Stalker on ARM64.

2. **Analyze the `TESTLIST_BEGIN` Block:** This block lists numerous test cases. Each `TESTENTRY` corresponds to a specific feature or scenario being tested. Listing these out will give a good overview of the stalker's capabilities.

3. **Categorize the Tests:**  The test names themselves provide clues about the functionality. Look for common themes and group the tests accordingly (e.g., "EVENTS", "PROBES", "TRANSFORMERS", etc.). This structure is already provided in the code, so leveraging it is efficient.

4. **Examine Key Data Structures and Functions:**  Look for typedefs, structs, and static functions. These often reveal the underlying mechanisms being tested. For instance, `GumStalkerIterator`, `GumStalkerOutput`, `GumCpuContext` are important types related to how the stalker operates and how transformations are applied.

5. **Connect Tests to Concepts:** For each category of tests, try to articulate the high-level concept being validated. For example, the "EVENTS" tests are about capturing different execution events. "TRANSFORMERS" relate to modifying the code stream during stalking.

6. **Address the Specific Questions:** Go through the user's questions systematically:
    * **Functionality:** This is covered by listing and categorizing the test cases.
    * **Relationship to Reverse Engineering:** Explain how Stalker's ability to trace execution, intercept function calls, and modify code is directly applicable to reverse engineering. Give concrete examples from the test cases, like tracing calls (`call`, `ret` events), instrumenting functions (`call_probe`), and changing code behavior (`custom_transformer`).
    * **Binary/OS/Kernel Knowledge:** Point out the low-level aspects, such as dealing with assembly instructions, CPU contexts, memory management, and threading, and connect these to relevant headers and test cases. For example, `cs_insn` relates to instruction handling, `GumCpuContext` to register access, and tests involving `pthread_create` or system calls to OS-level interactions.
    * **Logic and Assumptions:**  Where test cases involve conditional logic or specific input/output scenarios,  infer the assumptions being made. For instance, the `call_depth` test implies the stalker tracks the call stack depth. The "TRANSFORMERS" tests involve assumptions about the order of execution and how modifications are applied.
    * **User/Programming Errors:**  Think about how a user might misuse the Stalker API based on the test scenarios. Examples include incorrect masking of events, improper transformer logic leading to crashes, or errors in managing follow/unfollow operations.
    * **User Operation to Reach Here:** Describe the general steps a user would take to utilize Frida and potentially trigger the functionality being tested, starting from using the Frida client to interact with a target process.

7. **Structure the Response:** Organize the information clearly with headings and bullet points to make it easy to read and understand. Start with a concise summary of the overall functionality.

8. **Refine and Review:** Read through the generated summary to ensure accuracy, clarity, and completeness. Make sure all aspects of the user's request are addressed. For example, initially I might focus heavily on individual tests, but then I need to step back and provide a more holistic view of the Stalker's role in dynamic instrumentation. Also, ensure the examples provided are relevant and illustrative.好的，让我们来分析一下 `frida/subprojects/frida-gum/tests/core/arch-arm64/stalker-arm64.c` 这个文件的功能。

**总的来说，这个文件是 Frida 动态 instrumentation 工具中，针对 ARM64 架构的 Stalker 组件的测试代码。** Stalker 是 Frida 的核心功能之一，用于追踪目标进程的指令执行流。这个测试文件通过一系列的单元测试，验证了 Stalker 在 ARM64 架构下的各种功能和特性是否正常工作。

**具体功能归纳如下：**

1. **事件追踪 (Events):**
   - 测试 Stalker 能否正确地报告不同类型的执行事件，例如：
     - `no_events`: 不追踪任何事件。
     - `call`:  追踪函数调用事件。
     - `ret`:   追踪函数返回事件。
     - `exec`:  追踪每个指令的执行事件。
     - `call_depth`: 追踪函数调用的深度。

2. **探针 (Probes):**
   - 测试 Stalker 能否在特定的函数调用处插入探针 (Probe)，并执行用户自定义的代码：
     - `call_probe`: 在函数入口处插入探针，可以获取函数参数和上下文信息。

3. **转换器 (Transformers):**
   - 测试 Stalker 的转换器机制，允许在指令执行前修改指令流：
     - `custom_transformer`: 使用自定义的转换器函数。
     - `transformer_should_be_able_to_skip_call`: 转换器能够跳过特定的函数调用指令。
     - `transformer_should_be_able_to_replace_call_with_callout`: 转换器能够将函数调用替换为用户自定义的回调函数 (callout)。
     - `transformer_should_be_able_to_replace_tailjump_with_callout`: 转换器能够将尾调用跳转替换为用户自定义的回调函数。
     - `unfollow_should_be_allowed_*_transform`: 测试在转换的不同阶段取消追踪 (unfollow) 的能力。
     - `follow_me_should_support_nullable_event_sink`: 测试当事件接收器为空时 `follow_me` 的行为。
     - `invalidation_for_current_thread_should_be_supported`: 测试使当前线程的 Stalker 缓存失效的功能。
     - `invalidation_for_specific_thread_should_be_supported`: 测试使特定线程的 Stalker 缓存失效的功能。
     - `invalidation_should_allow_block_to_grow`: 测试缓存失效后，代码块可以增长。

4. **排除 (Exclusion):**
   - 测试 Stalker 排除特定代码区域的功能，使其不被追踪：
     - `exclude_bl`: 排除 `bl` (Branch with Link) 指令。
     - `exclude_blr`: 排除 `blr` (Branch with Link to Register) 指令。
     - `exclude_bl_with_unfollow`: 排除 `bl` 指令并取消追踪。
     - `exclude_blr_with_unfollow`: 排除 `blr` 指令并取消追踪。

5. **分支 (Branch):**
   - 测试 Stalker 对不同类型分支指令的处理：
     - `unconditional_branch`: 无条件跳转指令。
     - `unconditional_branch_reg`: 基于寄存器的无条件跳转指令。
     - `conditional_branch`: 条件跳转指令。
     - `compare_and_branch`: 比较并跳转指令。
     - `test_bit_and_branch`: 测试位并跳转指令。

6. **追踪 (Follows):**
   - 测试 Stalker 如何追踪不同的执行流程：
     - `follow_std_call`: 追踪标准的函数调用。
     - `follow_return`: 追踪函数返回。
     - `follow_misaligned_stack`: 追踪栈未对齐的情况。
     - `follow_syscall`: 追踪系统调用。
     - `follow_thread`: 追踪新创建的线程。
     - `unfollow_should_handle_terminated_thread`: 测试取消追踪已终止的线程。
     - `self_modifying_code_should_be_detected_with_threshold_*`: 测试检测自修改代码的能力。

7. **独占加载/存储 (Exclusive Loads/Stores):**
   - 测试 Stalker 是否会干扰独占加载/存储指令：
     - `exclusive_load_store_should_not_be_disturbed`: 确保 Stalker 不会影响独占指令的正常执行。

8. **额外功能 (Extra):**
   - 测试一些额外的功能：
     - `pthread_create`: (非 Windows 平台) 测试追踪 `pthread_create` 创建的线程。
     - `heap_api`: 测试 Stalker 与堆操作相关的行为。
     - `no_register_clobber`: 确保 Stalker 不会意外地修改寄存器。
     - `performance`: 进行性能测试。
     - `prefetch`: (Linux 平台) 测试预取功能。
     - `observer`: (Linux 平台) 测试观察者模式。

9. **在线程上运行 (RunOnThread):**
   - 测试在特定线程上运行代码的功能：
     - `run_on_thread_current`: 在当前线程运行。
     - `run_on_thread_current_sync`: 在当前线程同步运行。
     - `run_on_thread_other`: 在其他线程运行。
     - `run_on_thread_other_sync`: 在其他线程同步运行。

**与逆向方法的关系：**

Stalker 是一个强大的逆向工程工具，因为它允许逆向工程师动态地观察目标程序的执行流程。

* **代码执行跟踪:**  通过 `exec` 事件，逆向工程师可以逐条指令地跟踪程序的执行，理解代码的实际运行路径。这对于理解混淆代码或者查找程序漏洞非常有帮助。
* **函数调用分析:** `call` 和 `ret` 事件可以帮助逆向工程师分析程序的函数调用关系，构建调用图，理解程序的模块结构。
* **函数参数和返回值分析:**  `call_probe` 允许在函数调用时获取参数值，有助于理解函数的输入。结合返回事件，可以分析函数的行为。
* **代码修改和Hook:** 通过转换器，逆向工程师可以在程序运行时修改代码，例如跳过特定的检查、修改函数返回值，实现动态 Hook 或破解。例如，`transformer_should_be_able_to_skip_call` 演示了如何跳过一个函数调用，这在破解软件时经常用到。`transformer_should_be_able_to_replace_call_with_callout` 则展示了如何将函数调用重定向到自定义的函数，这是一种常见的 Hook 技术。
* **自修改代码分析:**  Stalker 可以检测自修改代码，这对于分析恶意软件非常重要，因为恶意软件经常使用自修改技术来躲避静态分析。

**涉及二进制底层、Linux/Android 内核及框架的知识：**

* **二进制指令:** Stalker 的核心是解析和处理二进制指令，例如 ARM64 指令集 (`bl`, `blr`, `add`, `sub`, `ret` 等)。测试代码中使用了 `cs_insn` 结构体，这是来自 Capstone 反汇编库的结构体，用于表示反汇编后的指令。
* **CPU 寄存器:** 测试代码中直接操作 CPU 寄存器，例如 `ARM64_REG_X0`，这在转换器和探针的回调函数中很常见，用于读取或修改函数参数和返回值。`GumCpuContext` 结构体用于表示 CPU 的上下文信息。
* **内存管理:** Stalker 需要管理目标进程的内存，包括代码段、数据段、栈等。例如，测试代码中使用 `gum_alloc_n_pages` 分配内存，`gum_memory_mark_code` 将内存标记为可执行。
* **函数调用约定:**  理解 ARM64 的函数调用约定对于编写探针和转换器非常重要，因为这决定了函数参数如何传递，返回值如何获取。
* **线程和进程:** Stalker 需要处理多线程和多进程环境。测试代码中使用了 `pthread_create` (在 Linux 平台) 来模拟多线程场景，并测试了在不同线程上追踪和取消追踪的能力。
* **系统调用:**  `follow_syscall` 测试了追踪系统调用的能力。系统调用是用户空间程序与内核交互的接口，理解系统调用的执行对于深入分析程序行为至关重要。
* **Linux 特性:**  `prefetch` 和 `observer` 测试涉及到 Linux 特有的功能。预取可能与内核的内存管理或调度有关，观察者模式则可能用于监控 Stalker 的内部状态。

**逻辑推理、假设输入与输出：**

很多测试用例都包含了逻辑推理，这里举几个例子：

* **`call_depth` 测试:**
    - **假设输入:** 调用一个会嵌套调用两个函数的代码片段。
    - **预期输出:** Stalker 产生的 `CALL` 和 `RET` 事件应该具有正确的深度信息，反映出函数调用的层次结构。例如，第一个 `CALL` 事件深度为 0，第二个 `CALL` 事件深度为 1，第一个 `RET` 事件深度为 2，等等。

* **`transformer_should_be_able_to_skip_call` 测试:**
    - **假设输入:**  一段包含函数调用的代码。
    - **预期输出:**  编写一个转换器，识别出函数调用指令并阻止其执行。最终程序的行为应该像是跳过了那个函数调用。

* **`invalidation_for_current_thread_should_be_supported` 测试:**
    - **假设输入:** 一个循环执行的函数。
    - **预期输出:** 在执行几次后，通过 `gum_stalker_invalidate` 使 Stalker 的缓存失效，导致后续执行重新进入 Stalker 进行追踪和转换。

**用户或编程常见的使用错误：**

* **事件掩码设置错误:** 用户可能设置了错误的事件掩码 (`fixture->sink->mask`)，导致 Stalker 没有追踪到预期的事件，或者追踪了过多的事件，影响性能。
* **转换器逻辑错误:**
    - 转换器代码中可能存在 Bug，导致修改后的指令无效或者程序崩溃。例如，在 `insert_extra_add_after_sub` 中，如果对非 `SUB` 指令也进行了错误的操作，可能会导致问题。
    - 转换器可能没有正确处理指令边界，导致修改后的指令跨越了指令的结尾。
    - 转换器中调用了可能导致副作用的函数，例如修改了不应该修改的内存区域。
* **Follow/Unfollow 不匹配:** 用户可能在没有 `follow_me` 的情况下调用 `gum_stalker_unfollow_me`，或者多次 `follow_me` 但只 `unfollow_me` 一次，这可能导致资源泄漏或程序状态异常。
* **在转换器中进行耗时操作:**  转换器会在每次执行到被追踪的代码块时运行，如果转换器中包含耗时操作，会显著降低程序性能。
* **不正确的内存地址使用:**  在探针或转换器中，如果错误地计算或使用了内存地址，可能会导致程序崩溃。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **使用 Frida Client 连接到目标进程:** 用户首先会使用 Frida 的客户端 (例如 Python 绑定) 连接到想要进行动态分析的目标进程。
2. **创建 Stalker 实例:**  在 Frida 的 JavaScript 环境中，用户会创建一个 `Stalker` 的实例，用于追踪目标进程的执行。
3. **设置事件监听器 (可选):** 用户可以选择设置事件监听器，例如监听 `call`、`ret` 或 `exec` 事件，以便在这些事件发生时执行自定义的代码。
4. **添加转换器 (可选):**  用户可以添加一个或多个转换器，以在指令执行前修改指令流。转换器通常是用 JavaScript 编写的。
5. **调用 `Stalker.follow()` 或 `Stalker.attach()`:** 用户调用 `Stalker.follow()` 来开始追踪当前线程，或者使用 `Stalker.attach()` 追踪特定的线程或所有线程。
6. **目标进程执行代码:**  一旦 Stalker 开始追踪，目标进程继续执行其代码。每当执行到 Stalker 监控的代码区域时，就会触发相应的事件或者执行用户定义的转换器。
7. **在转换器或事件监听器中进行操作:** 用户在转换器或事件监听器中编写的 JavaScript 代码会被执行，可以读取和修改目标进程的内存、寄存器等信息。
8. **分析结果:** 用户分析 Stalker 收集到的事件信息或者转换器修改程序行为后的结果，以达到逆向分析的目的。

**例如，如果用户想要调试一个函数 `foo` 的调用过程，可能会执行以下步骤:**

1. 使用 Frida 连接到目标进程。
2. 创建一个 Stalker 实例。
3. 添加一个事件监听器，监听 `call` 事件，并判断 `call` 事件的目标地址是否为函数 `foo` 的地址。
4. 调用 `Stalker.follow()` 开始追踪。
5. 当程序执行到 `foo` 函数时，Frida 会捕获到 `call` 事件，并执行用户定义的监听器代码，用户可以在监听器中打印函数参数的值。

这个测试文件中的每个 `TESTCASE` 实际上模拟了 Frida 用户可能进行的各种操作和场景，用于确保 Stalker 组件在各种情况下都能正常工作。

希望以上分析能够帮助你理解 `stalker-arm64.c` 的功能。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-arm64/stalker-arm64.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2009-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2017 Antonio Ken Iannillo <ak.iannillo@gmail.com>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-arm64-fixture.c"

#include <lzma.h>
#ifdef HAVE_LINUX
# include <errno.h>
# include <fcntl.h>
# include <unistd.h>
# include <sys/prctl.h>
# include <sys/wait.h>
#endif

TESTLIST_BEGIN (stalker)

  /* EVENTS */
  TESTENTRY (no_events)
  TESTENTRY (call)
  TESTENTRY (ret)
  TESTENTRY (exec)
  TESTENTRY (call_depth)

  /* PROBES */
  TESTENTRY (call_probe)

  /* TRANSFORMERS */
  TESTENTRY (custom_transformer)
  TESTENTRY (transformer_should_be_able_to_skip_call)
  TESTENTRY (transformer_should_be_able_to_replace_call_with_callout)
  TESTENTRY (transformer_should_be_able_to_replace_tailjump_with_callout)
  TESTENTRY (unfollow_should_be_allowed_before_first_transform)
  TESTENTRY (unfollow_should_be_allowed_mid_first_transform)
  TESTENTRY (unfollow_should_be_allowed_after_first_transform)
  TESTENTRY (unfollow_should_be_allowed_before_second_transform)
  TESTENTRY (unfollow_should_be_allowed_mid_second_transform)
  TESTENTRY (unfollow_should_be_allowed_after_second_transform)
  TESTENTRY (follow_me_should_support_nullable_event_sink)
  TESTENTRY (invalidation_for_current_thread_should_be_supported)
  TESTENTRY (invalidation_for_specific_thread_should_be_supported)
  TESTENTRY (invalidation_should_allow_block_to_grow)

  /* EXCLUSION */
  TESTENTRY (exclude_bl)
  TESTENTRY (exclude_blr)
  TESTENTRY (exclude_bl_with_unfollow)
  TESTENTRY (exclude_blr_with_unfollow)

  /* BRANCH */
  TESTENTRY (unconditional_branch)
  TESTENTRY (unconditional_branch_reg)
  TESTENTRY (conditional_branch)
  TESTENTRY (compare_and_branch)
  TESTENTRY (test_bit_and_branch)

  /* FOLLOWS */
  TESTENTRY (follow_std_call)
  TESTENTRY (follow_return)
  TESTENTRY (follow_misaligned_stack)
  TESTENTRY (follow_syscall)
  TESTENTRY (follow_thread)
  TESTENTRY (unfollow_should_handle_terminated_thread)
  TESTENTRY (self_modifying_code_should_be_detected_with_threshold_minus_one)
  TESTENTRY (self_modifying_code_should_not_be_detected_with_threshold_zero)
  TESTENTRY (self_modifying_code_should_be_detected_with_threshold_one)

  /* EXCLUSIVE LOADS/STORES */
  TESTENTRY (exclusive_load_store_should_not_be_disturbed)

  /* EXTRA */
#ifndef HAVE_WINDOWS
  TESTENTRY (pthread_create)
#endif
  TESTENTRY (heap_api)
  TESTENTRY (no_register_clobber)
  TESTENTRY (performance)

#ifdef HAVE_LINUX
  TESTENTRY (prefetch)
  TESTENTRY (observer)
#endif

  TESTGROUP_BEGIN ("RunOnThread")
    TESTENTRY (run_on_thread_current)
    TESTENTRY (run_on_thread_current_sync)
    TESTENTRY (run_on_thread_other)
    TESTENTRY (run_on_thread_other_sync)
  TESTGROUP_END ()
TESTLIST_END ()

#ifdef HAVE_LINUX

struct _GumTestStalkerObserver
{
  GObject parent;

  guint64 total;
};

#endif

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

static void insert_extra_add_after_sub (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void store_x0 (GumCpuContext * cpu_context, gpointer user_data);
static void skip_call (GumStalkerIterator * iterator, GumStalkerOutput * output,
    gpointer user_data);
static void replace_call_with_callout (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void replace_jmp_with_callout (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void callout_set_cool (GumCpuContext * cpu_context, gpointer user_data);
static void unfollow_during_transform (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static gboolean test_is_finished (void);
static void modify_to_return_true_after_three_calls (
    GumStalkerIterator * iterator, GumStalkerOutput * output,
    gpointer user_data);
static void invalidate_after_three_calls (GumCpuContext * cpu_context,
    gpointer user_data);
static void start_invalidation_target (InvalidationTarget * target,
    TestArm64StalkerFixture * fixture);
static void join_invalidation_target (InvalidationTarget * target);
static gpointer run_stalked_until_finished (gpointer data);
static void modify_to_return_true_on_subsequent_transform (
    GumStalkerIterator * iterator, GumStalkerOutput * output,
    gpointer user_data);
static int get_magic_number (void);
static void add_n_return_value_increments (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static gpointer run_stalked_briefly (gpointer data);
static gpointer run_stalked_into_termination (gpointer data);
static void insert_callout_after_cmp (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void bump_num_cmp_callouts (GumCpuContext * cpu_context,
    gpointer user_data);
static void patch_instruction (gpointer code, guint offset, guint32 insn);
static void do_patch_instruction (gpointer mem, gpointer user_data);
#ifndef HAVE_WINDOWS
static gpointer increment_integer (gpointer data);
#endif
static gboolean store_range_of_test_runner (const GumModuleDetails * details,
    gpointer user_data);
static void pretend_workload (GumMemoryRange * runner_range);

volatile gboolean stalker_invalidation_test_is_finished = FALSE;
volatile gint stalker_invalidation_magic_number = 42;

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

#define GUM_TYPE_TEST_STALKER_OBSERVER (gum_test_stalker_observer_get_type ())
G_DECLARE_FINAL_TYPE (GumTestStalkerObserver, gum_test_stalker_observer, GUM,
                      TEST_STALKER_OBSERVER, GObject)

static void gum_test_stalker_observer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_test_stalker_observer_class_init (
    GumTestStalkerObserverClass * klass);
static void gum_test_stalker_observer_init (GumTestStalkerObserver * self);
static void gum_test_stalker_observer_increment_total (
    GumStalkerObserver * observer);

G_DEFINE_TYPE_EXTENDED (GumTestStalkerObserver,
                        gum_test_stalker_observer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_STALKER_OBSERVER,
                            gum_test_stalker_observer_iface_init))
#endif

static void run_on_thread (const GumCpuContext * cpu_context,
    gpointer user_data);
static GThread * create_sleeping_dummy_thread_sync (gboolean * done,
    GumThreadId * thread_id);
static gpointer sleeping_dummy (gpointer data);

static const guint32 flat_code[] = {
    0xcb000000, /* sub w0, w0, w0 */
    0x91000400, /* add w0, w0, #1 */
    0x91000400, /* add w0, w0, #1 */
    0xd65f03c0  /* ret            */
};

static StalkerTestFunc
invoke_flat_expecting_return_value (TestArm64StalkerFixture * fixture,
                                    GumEventType mask,
                                    guint expected_return_value)
{
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_arm64_stalker_fixture_dup_code (fixture,
      flat_code, sizeof (flat_code));

  fixture->sink->mask = mask;
  ret = test_arm64_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, expected_return_value);

  return func;
}

static StalkerTestFunc
invoke_flat (TestArm64StalkerFixture * fixture,
             GumEventType mask)
{
  return invoke_flat_expecting_return_value (fixture, mask, 2);
}

TESTCASE (no_events)
{
  invoke_flat (fixture, GUM_NOTHING);
  g_assert_cmpuint (fixture->sink->events->len, ==, 0);
}

TESTCASE (call)
{
  StalkerTestFunc func;
  GumCallEvent * ev;

  func = invoke_flat (fixture, GUM_CALL);

  g_assert_cmpuint (fixture->sink->events->len, ==, 2);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_CALL);
  ev = &g_array_index (fixture->sink->events, GumEvent, 0).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, fixture->last_invoke_calladdr);
  GUM_ASSERT_CMPADDR (ev->target, ==, gum_strip_code_pointer (func));
}

TESTCASE (ret)
{
  StalkerTestFunc func;
  GumRetEvent * ev;

  func = invoke_flat (fixture, GUM_RET);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      0).type, ==, GUM_RET);

  ev = &g_array_index (fixture->sink->events, GumEvent, 0).ret;

  GUM_ASSERT_CMPADDR (ev->location, ==,
      (guint8 *) gum_strip_code_pointer (func) + 3 * 4);
  GUM_ASSERT_CMPADDR (ev->target, ==, fixture->last_invoke_retaddr);
}

TESTCASE (exec)
{
  StalkerTestFunc func;
  GumRetEvent * ev;

  func = invoke_flat (fixture, GUM_EXEC);

  g_assert_cmpuint (fixture->sink->events->len, ==, INVOKER_INSN_COUNT + 4);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent,
      INVOKER_IMPL_OFFSET).type, ==, GUM_EXEC);
  ev =
      &g_array_index (fixture->sink->events, GumEvent, INVOKER_IMPL_OFFSET).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, gum_strip_code_pointer (func));
}

TESTCASE (call_depth)
{
  guint8 * code;
  GumArm64Writer cw;
  gpointer func_a, func_b;
  const gchar * start_lbl = "start";
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

  gum_arm64_writer_put_b_label (&cw, start_lbl);

  func_b = gum_arm64_writer_cur (&cw);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 7);
  gum_arm64_writer_put_ret (&cw);

  func_a = gum_arm64_writer_cur (&cw);
  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_add_reg_reg_imm (&cw, ARM64_REG_X0, ARM64_REG_X0, 3);
  gum_arm64_writer_put_bl_imm (&cw, GUM_ADDRESS (func_b));
  gum_arm64_writer_put_pop_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_ret (&cw);

  gum_arm64_writer_put_label (&cw, start_lbl);
  gum_arm64_writer_put_push_reg_reg (&cw, ARM64_REG_X19, ARM64_REG_LR);
  gum_arm64_writer_put_bl_imm (&cw, GUM_ADDRESS (func_a));
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

  fixture->sink->mask = GUM_CALL | GUM_RET;
  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc, gum_sign_code_pointer (code));
  r = func (2);

  g_assert_cmpint (r, ==, 12);
  g_assert_cmpuint (fixture->sink->events->len, ==, 5);
  g_assert_cmpint (NTH_EVENT_AS_CALL (0)->depth, ==, 0);
  g_assert_cmpint (NTH_EVENT_AS_CALL (1)->depth, ==, 1);
  g_assert_cmpint (NTH_EVENT_AS_RET (2)->depth, ==, 2);
  g_assert_cmpint (NTH_EVENT_AS_RET (3)->depth, ==, 1);

  gum_free_pages (code);
}

typedef struct _CallProbeContext CallProbeContext;

struct _CallProbeContext
{
  guint num_calls;
  gpointer target_address;
  gpointer return_address;
};

static void probe_func_a_invocation (GumCallDetails * details,
    gpointer user_data);

TESTCASE (call_probe)
{
  const guint32 code_template[] =
  {
    0xa9bf7bf3, /* push {x19, lr} */
    0xd2801553, /* mov x19, #0xaa */
    0xd2800883, /* mov x3, #0x44  */
    0xd2800662, /* mov x2, #0x33  */
    0xd2800441, /* mov x1, #0x22  */
    0xd2800220, /* mov x0, #0x11  */
    0xa9bf07e0, /* push {x0, x1}  */
    0x94000009, /* bl func_a      */
    0xa8c107e0, /* pop {x0, x1}   */
    0xd2801103, /* mov x3, #0x88  */
    0xd2800ee2, /* mov x2, #0x77  */
    0xd2800cc1, /* mov x1, #0x66  */
    0xd2800aa0, /* mov x0, #0x55  */
    0x94000005, /* bl func_b      */
    0xa8c17bf3, /* pop {x19, lr}  */
    0xd65f03c0, /* ret            */

    /* func_a: */
    0xd2801100, /* mov x0, #0x88  */
    0xd65f03c0, /* ret            */

    /* func_b: */
    0xd2801320, /* mov x0, #0x99  */
    0xd65f03c0, /* ret            */
  };
  StalkerTestFunc func;
  guint8 * func_a;
  CallProbeContext probe_ctx, secondary_probe_ctx;
  GumProbeId probe_id;

  func = (StalkerTestFunc) test_arm64_stalker_fixture_dup_code (fixture,
      code_template, sizeof (code_template));

  func_a = fixture->code + (16 * 4);

  probe_ctx.num_calls = 0;
  probe_ctx.target_address = func_a;
  probe_ctx.return_address = fixture->code + (8 * 4);
  probe_id = gum_stalker_add_call_probe (fixture->stalker, func_a,
      probe_func_a_invocation, &probe_ctx, NULL);
  test_arm64_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (probe_ctx.num_calls, ==, 1);

  secondary_probe_ctx.num_calls = 0;
  secondary_probe_ctx.target_address = probe_ctx.target_address;
  secondary_probe_ctx.return_address = probe_ctx.return_address;
  gum_stalker_add_call_probe (fixture->stalker, func_a, probe_func_a_invocation,
      &secondary_probe_ctx, NULL);
  test_arm64_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (probe_ctx.num_calls, ==, 2);
  g_assert_cmpuint (secondary_probe_ctx.num_calls, ==, 1);

  gum_stalker_remove_call_probe (fixture->stalker, probe_id);
  test_arm64_stalker_fixture_follow_and_invoke (fixture, func, 0);
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

  g_assert_cmphex (cpu_context->pc, ==, GPOINTER_TO_SIZE (ctx->target_address));
  g_assert_cmphex (cpu_context->lr, ==, GPOINTER_TO_SIZE (ctx->return_address));
  g_assert_cmphex (cpu_context->x[0], ==, 0x11);
  g_assert_cmphex (cpu_context->x[1], ==, 0x22);
  g_assert_cmphex (cpu_context->x[2], ==, 0x33);
  g_assert_cmphex (cpu_context->x[3], ==, 0x44);
  g_assert_cmphex (cpu_context->x[19], ==, 0xaa);
}

TESTCASE (custom_transformer)
{
  guint64 last_x0 = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      insert_extra_add_after_sub, &last_x0, NULL);

  g_assert_cmpuint (last_x0, ==, 0);

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 3);

  g_assert_cmpuint (last_x0, ==, 3);
}

static void
insert_extra_add_after_sub (GumStalkerIterator * iterator,
                            GumStalkerOutput * output,
                            gpointer user_data)
{
  guint64 * last_x0 = user_data;
  const cs_insn * insn;
  gboolean in_leaf_func;

  in_leaf_func = FALSE;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (in_leaf_func && insn->id == ARM64_INS_RET)
    {
      gum_stalker_iterator_put_callout (iterator, store_x0, last_x0, NULL);
    }

    gum_stalker_iterator_keep (iterator);

    if (insn->id == ARM64_INS_SUB)
    {
      in_leaf_func = TRUE;

      gum_arm64_writer_put_add_reg_reg_imm (output->writer.arm64, ARM64_REG_W0,
          ARM64_REG_W0, 1);
    }
  }
}

static void
store_x0 (GumCpuContext * cpu_context,
          gpointer user_data)
{
  guint64 * last_x0 = user_data;

  *last_x0 = cpu_context->x[0];
}

TESTCASE (transformer_should_be_able_to_skip_call)
{
  guint32 code_template[] =
  {
    0xa9bf7bfd, /* push {x29, x30} */
    0xd280a280, /* mov x0, #1300   */
    0x94000003, /* bl bump_number  */
    0xa8c17bfd, /* pop {x29, x30}  */
    0xd65f03c0, /* ret             */
    /* bump_number:                */
    0x91009400, /* add x0, x0, #37 */
    0xd65f03c0, /* ret             */
  };
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_arm64_stalker_fixture_dup_code (fixture,
      code_template, sizeof (code_template));

  fixture->transformer = gum_stalker_transformer_make_from_callback (skip_call,
      func, NULL);

  ret = test_arm64_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (ret, ==, 1300);
}

static void
skip_call (GumStalkerIterator * iterator,
           GumStalkerOutput * output,
           gpointer user_data)
{
  const guint32 * func_start = user_data;
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (insn->address == GPOINTER_TO_SIZE (func_start + 2))
      continue;

    gum_stalker_iterator_keep (iterator);
  }
}

TESTCASE (transformer_should_be_able_to_replace_call_with_callout)
{
  guint32 code_template[] =
  {
    0xa9bf7bfd, /* push {x29, x30} */
    0xd280a280, /* mov x0, #1300   */
    0x94000003, /* bl bump_number  */
    0xa8c17bfd, /* pop {x29, x30}  */
    0xd65f03c0, /* ret             */
    /* bump_number:                */
    0x91009400, /* add x0, x0, #37 */
    0xd65f03c0, /* ret             */
  };
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_arm64_stalker_fixture_dup_code (fixture,
      code_template, sizeof (code_template));

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      replace_call_with_callout, func, NULL);

  ret = test_arm64_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (ret, ==, 0xc001);
}

static void
replace_call_with_callout (GumStalkerIterator * iterator,
                           GumStalkerOutput * output,
                           gpointer user_data)
{
  const guint32 * func_start = user_data;
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (insn->address == GPOINTER_TO_SIZE (func_start + 2))
    {
      gum_stalker_iterator_put_callout (iterator, callout_set_cool, NULL, NULL);
      continue;
    }

    gum_stalker_iterator_keep (iterator);
  }
}

TESTCASE (transformer_should_be_able_to_replace_tailjump_with_callout)
{
  guint32 code_template[] =
  {
    0xd280a280, /* mov x0, #1300   */
    0x14000001, /* b bump_number   */
    /* bump_number:                */
    0x91009400, /* add x0, x0, #37 */
    0xd65f03c0, /* ret             */
  };
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_arm64_stalker_fixture_dup_code (fixture,
      code_template, sizeof (code_template));

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      replace_jmp_with_callout, func, NULL);

  ret = test_arm64_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (ret, ==, 0xc001);
}

static void
replace_jmp_with_callout (GumStalkerIterator * iterator,
                          GumStalkerOutput * output,
                          gpointer user_data)
{
  const guint32 * func_start = user_data;
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (insn->address == GPOINTER_TO_SIZE (func_start + 1))
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
  cpu_context->x[0] = 0xc001;
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

TESTCASE (invalidation_for_current_thread_should_be_supported)
{
  InvalidationTransformContext ctx;

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

static gboolean GUM_NOINLINE
test_is_finished (void)
{
  return stalker_invalidation_test_is_finished;
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

    if (insn->id == ARM64_INS_RET && in_target_function && ctx->n == 3)
    {
      gum_arm64_writer_put_ldr_reg_u32 (output->writer.arm64, ARM64_REG_W0,
          TRUE);
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
  InvalidationTarget a, b;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  start_invalidation_target (&a, fixture);
  start_invalidation_target (&b, fixture);

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
                           TestArm64StalkerFixture * fixture)
{
  InvalidationTransformContext * ctx = &target->ctx;
  StalkerDummyChannel * channel = &target->channel;

  ctx->stalker = fixture->stalker;
  ctx->target_function = test_is_finished;
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

    if (insn->id == ARM64_INS_RET && in_target_function && ctx->n > 1)
    {
      gum_arm64_writer_put_ldr_reg_u32 (output->writer.arm64, ARM64_REG_W0,
          TRUE);
    }

    gum_stalker_iterator_keep (iterator);
  }
}

TESTCASE (invalidation_should_allow_block_to_grow)
{
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

static int GUM_NOINLINE
get_magic_number (void)
{
  return stalker_invalidation_magic_number;
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

    if (insn->id == ARM64_INS_RET && in_target_function)
    {
      guint increment_index;

      for (increment_index = 0; increment_index != ctx->n; increment_index++)
      {
        gum_arm64_writer_put_add_reg_reg_imm (output->writer.arm64,
            ARM64_REG_W0, ARM64_REG_W0, 1);
      }
    }

    gum_stalker_iterator_keep (iterator);
  }
}

TESTCASE (exclude_bl)
{
  const guint32 code_template[] =
  {
    0xa9bf7bf3, /* push {x19, lr} */
    0xd2801553, /* mov x19, #0xaa */
    0xd2800883, /* mov x3, #0x44  */
    0xd2800662, /* mov x2, #0x33  */
    0xd2800441, /* mov x1, #0x22  */
    0xd2800220, /* mov x0, #0x11  */
    0xa9bf07e0, /* push {x0, x1}  */
    0x94000009, /* bl func_a      */
    0xa8c107e0, /* pop {x0, x1}   */
    0xd2801103, /* mov x3, #0x88  */
    0xd2800ee2, /* mov x2, #0x77  */
    0xd2800cc1, /* mov x1, #0x66  */
    0xd2800aa0, /* mov x0, #0x55  */
    0x94000005, /* bl func_b      */
    0xa8c17bf3, /* pop {x19, lr}  */
    0xd65f03c0, /* ret            */

    /* func_a: */
    0xd2801100, /* mov x0, #0x88  */
    0xd65f03c0, /* ret            */

    /* func_b: */
    0xd2801320, /* mov x0, #0x99  */
    0xd65f03c0, /* ret            */
  };
  StalkerTestFunc func;
  guint8 * func_a_address;
  GumMemoryRange memory_range;

  fixture->sink->mask = GUM_EXEC;

  func = (StalkerTestFunc) test_arm64_stalker_fixture_dup_code (fixture,
      code_template, sizeof (code_template));

  func_a_address = fixture->code + (16 * 4);
  memory_range.base_address = (GumAddress) func_a_address;
  memory_range.size = 4 * 2;
  gum_stalker_exclude (fixture->stalker, &memory_range);

  g_assert_cmpuint (fixture->sink->events->len, ==, 0);

  test_arm64_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, 24);
}

TESTCASE (exclude_blr)
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

  func_a = gum_a
"""


```