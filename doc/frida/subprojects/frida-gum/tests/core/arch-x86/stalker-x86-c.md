Response:
The user wants a summary of the C source code file `stalker-x86.c` which is part of the Frida dynamic instrumentation tool. I need to identify the core functionalities of this file, focusing on aspects relevant to reverse engineering, binary manipulation, interaction with the Linux/Android kernel and frameworks, logical reasoning within the code, potential user errors, and how a user's actions might lead to the execution of this code.

**Plan:**

1. **Identify the main purpose:** The filename and the presence of `TESTLIST_BEGIN` strongly suggest this file contains unit tests for the Stalker component of Frida, specifically for the x86 architecture.
2. **Analyze the `#include` directives:**  These reveal dependencies and areas of functionality being tested (e.g., `lzma.h`, `pthread.h`, `unistd.h`, etc.).
3. **Examine the `TESTLIST_BEGIN`:**  The names of the individual tests provide a good overview of the features being tested (e.g., `call`, `ret`, `exec`, `follow_syscall`, `self_modifying_code`, etc.).
4. **Look for keywords related to reverse engineering:**  Terms like "call", "ret", "jump", "indirect call", "self-modifying code" are strong indicators.
5. **Look for keywords related to the operating system and kernel:**  Terms like "syscall", "thread", "Linux", "Windows" are relevant.
6. **Identify test cases that involve logical reasoning or specific input/output:** Test names like `short_conditional_jump_true`, `short_conditional_jump_false` suggest this.
7. **Consider potential user errors:**  While the code is for testing, understanding the tested functionalities can reveal common usage errors of the Stalker API.
8. **Think about how a user interacts with Frida to trigger Stalker:**  The user generally uses Frida's API to attach to a process and then uses Stalker to trace execution.
9. **Synthesize the findings into a concise summary.**这个C源代码文件 `stalker-x86.c` 是 Frida 动态 Instrumentation 工具中 `stalker` 组件针对 x86 架构的测试文件。`stalker` 的核心功能是动态追踪目标进程的执行流程，并提供在代码执行过程中插入自定义逻辑的能力。

**主要功能归纳:**

这个测试文件的主要目的是验证 `stalker` 组件在 x86 架构下的各种功能和特性是否按预期工作。它通过一系列的单元测试来覆盖 `stalker` 的不同使用场景和边界情况。

**具体测试的功能点包括 (根据 `TESTLIST_BEGIN` 中的条目):**

*   **基本的代码追踪:**
    *   `no_events`:  测试在不启用任何事件的情况下 `stalker` 的行为。
    *   `call`, `ret`, `exec`: 测试追踪函数调用、返回和基本代码执行的能力。
    *   `call_depth`: 测试追踪函数调用深度的能力。
*   **自定义代码注入 (Transformer):**
    *   `custom_transformer`: 测试用户自定义代码转换器 (Transformer) 的功能，允许在代码执行前修改或插入代码。
    *   `transformer_should_be_able_to_skip_call`: 测试 Transformer 跳过某些调用的能力。
    *   `transformer_should_be_able_to_replace_call_with_callout`: 测试 Transformer 将调用替换为自定义回调函数的能力。
    *   `transformer_should_be_able_to_replace_tailjump_with_callout`: 测试 Transformer 将尾部跳转替换为自定义回调函数的能力。
*   **动态控制追踪流程 (Unfollow/Follow):**
    *   `unfollow_should_be_allowed_before/mid/after_first/second_transform`: 测试在 Transformer 执行的不同阶段取消追踪的能力。
    *   `follow_me_should_support_nullable_event_sink`: 测试 `follow_me` 函数支持可为空的事件接收器。
*   **代码失效 (Invalidation):**
    *   `invalidation_for_current_thread_should_be_supported`: 测试使当前线程的代码失效的能力。
    *   `invalidation_for_specific_thread_should_be_supported`: 测试使特定线程的代码失效的能力。
    *   `invalidation_should_allow_block_to_grow`: 测试代码失效是否允许代码块增长。
*   **各种跳转指令的追踪:**
    *   `unconditional_jumps`: 测试无条件跳转指令的追踪。
    *   `short_conditional_jump_true/false`: 测试短条件跳转指令在条件成立和不成立时的追踪。
    *   `short_conditional_jcxz_true/false`: 测试 `jcxz` 指令在条件成立和不成立时的追踪。
    *   `long_conditional_jump`: 测试长条件跳转指令的追踪。
*   **函数调用约定追踪:**
    *   `follow_return`: 测试追踪 `ret` 指令返回的能力。
    *   `follow_stdcall`: 测试追踪 `stdcall` 调用约定的能力。
    *   `follow_repne_ret/jb`: 测试追踪带有 `repne` 前缀的 `ret` 和 `jb` 指令的能力。
*   **深度取消追踪 (Unfollow Deep):**
    *   `unfollow_deep`: 测试深度取消追踪的能力。
*   **处理异常指令:**
    *   `call_followed_by_junk`: 测试处理调用指令后跟随无效代码的情况。
*   **间接调用/跳转:**
    *   `indirect_call_with_immediate/...`: 测试各种带有立即数的间接调用指令的追踪。
    *   `indirect_jump_with_immediate/...`: 测试各种带有立即数的间接跳转指令的追踪。
*   **直接调用:**
    *   `direct_call_with_register`: 测试带有寄存器的直接调用。
*   **特定指令的测试:**
    *   `popcnt`: 测试 `popcnt` 指令的追踪。
*   **寄存器和栈的保护:**
    *   `no_register_clobber`: 测试是否会错误地修改寄存器 (仅限 32 位)。
    *   `no_red_zone_clobber`: 测试是否会破坏红区 (x64 架构中栈帧下方的区域)。
*   **处理大型代码块:**
    *   `big_block`: 测试处理大型代码块的能力。
*   **API 测试:**
    *   `heap_api`: 测试与堆内存操作相关的 API 调用追踪。
    *   `follow_syscall`: 测试追踪系统调用的能力。
    *   `follow_thread`: 测试追踪新创建线程的能力。
    *   `create_thread`: 测试追踪线程创建的能力 (仅限 Linux)。
    *   `unfollow_should_handle_terminated_thread`: 测试取消追踪已终止线程的能力。
*   **自修改代码检测:**
    *   `self_modifying_code_should_be_detected_with_threshold_minus_one/one`: 测试在不同阈值下检测自修改代码的能力。
    *   `self_modifying_code_should_not_be_detected_with_threshold_zero`: 测试在阈值为零时不检测自修改代码。
*   **性能测试:**
    *   `performance`:  进行基本的性能测试 (非 Windows)。
*   **平台特定的测试 (Windows/Linux):**
    *   `win32_indirect_call_seg`: 测试 Windows 下与段相关的间接调用 (仅限 32 位)。
    *   `win32_messagebeep_api`: 测试 Windows `MessageBeep` API 的追踪。
    *   `win32_follow_user_to_kernel_to_callback`: 测试 Windows 下从用户态到内核态再到回调函数的追踪。
    *   `win32_follow_callback_to_kernel_to_user`: 测试 Windows 下从回调函数到内核态再到用户态的追踪。
    *   `prefetch`, `prefetch_backpatch`, `observer`: 测试与预取和观察者模式相关的特性 (仅限 Linux)。
*   **与实例控制变量 (IC Var) 相关的功能:**
    *   `ic_var`: (非 Windows)。
*   **异常处理测试 (Linux):**
    *   `no_exceptions`, `try_and_catch`, `try_and_catch_excluded`, `try_and_dont_catch`, `try_and_dont_catch_excluded`: 测试 `stalker` 对异常处理流程的追踪。
*   **在特定线程上运行代码:**
    *   `run_on_thread_current/sync`, `run_on_thread_other/sync`: 测试在当前线程或其他线程上运行代码的能力。

**与逆向方法的关系：**

`stalker` 是一个强大的逆向工程工具，这个测试文件验证了其核心功能，这些功能直接应用于逆向分析：

*   **动态代码执行追踪:**  `call`, `ret`, `exec` 等测试验证了追踪目标程序执行流的能力，这对于理解程序行为至关重要。逆向工程师可以使用 `stalker` 观察函数调用关系、代码执行路径，从而理解程序逻辑。
    *   **举例:**  在分析恶意软件时，可以使用 `stalker` 追踪恶意代码的执行流程，观察其与系统 API 的交互，从而理解其恶意行为。
*   **代码注入和修改:** `custom_transformer` 等测试验证了在目标程序执行过程中动态修改代码的能力。这可以用于插桩、hook 函数、修改程序行为等。
    *   **举例:**  可以使用 Transformer 在特定函数调用前后插入代码，记录函数参数和返回值，或者修改函数的行为以绕过某些安全检查。
*   **理解程序控制流:**  对各种跳转指令的测试 (`unconditional_jumps`, `conditional_jumps`, `indirect_call/jump`)  有助于验证 `stalker` 理解和追踪复杂的程序控制流的能力。
    *   **举例:**  在分析加壳程序时，可以使用 `stalker` 追踪程序如何解密和执行原始代码，即使程序使用了各种复杂的跳转指令。
*   **系统调用追踪:** `follow_syscall` 测试验证了追踪程序与操作系统内核交互的能力。这对于理解程序如何利用系统资源、执行特权操作非常重要。
    *   **举例:**  可以追踪程序调用的文件操作、网络操作等系统调用，了解程序的行为模式。
*   **线程追踪:** `follow_thread`, `create_thread` 等测试验证了追踪多线程程序的能力。现代程序通常是多线程的，理解线程之间的交互和执行流程是逆向分析的关键。
    *   **举例:**  可以追踪一个网络服务器程序的不同线程如何处理客户端连接，理解其并发模型。
*   **自修改代码分析:**  对自修改代码的测试验证了 `stalker` 检测和处理动态修改自身代码的程序的能力，这在分析病毒和恶意软件时非常重要。
    *   **举例:**  可以追踪病毒如何解密自身代码并执行，即使病毒在运行时会改变其代码。

**涉及二进制底层、Linux, Android 内核及框架的知识：**

*   **二进制底层:**
    *   测试文件直接操作和检查二进制指令 (`flat_code`, `code_template` 等)。
    *   涉及到 x86 汇编指令的理解，例如 `mov`, `call`, `ret`, `jmp`, `xor`, `inc` 等。
    *   测试间接调用和跳转时，需要理解内存地址的计算方式。
    *   自修改代码的测试涉及到在运行时修改内存中的代码。
*   **Linux:**
    *   使用了 Linux 特有的头文件，如 `<errno.h>`, `<fcntl.h>`, `<unistd.h>`, `<pthread.h>`, `<sys/wait.h>`.
    *   测试了线程创建 (`create_thread`) 和系统调用追踪 (`follow_syscall`)，这直接涉及到 Linux 内核的接口。
    *   提到了 pipe (`F_SETPIPE_SZ`)，这是 Linux 中进程间通信的一种方式。
    *   异常处理测试 (`ExceptionHandling` group) 涉及到 Linux 的信号机制和异常处理流程。
*   **Android 内核及框架:**
    *   虽然测试文件名中没有显式提及 Android，但 Frida 通常用于 Android 平台的动态分析。一些 Linux 相关的测试也适用于 Android，因为 Android 基于 Linux 内核。
    *   在 Android 平台上，`stalker` 可以用于追踪 Java 代码的执行（通过 ART 虚拟机），这涉及到对 Android 运行时框架的理解。
*   **Windows:**
    *   条件编译块 (`#ifdef HAVE_WINDOWS`) 中包含了 Windows 特有的测试，例如 `win32_indirect_call_seg`, `win32_messagebeep_api`, `win32_follow_user_to_kernel_to_callback`, `win32_follow_callback_to_kernel_to_user`。
    *   这些测试涉及到 Windows API 的调用，用户态到内核态的切换，以及回调函数的执行流程。

**逻辑推理的假设输入与输出:**

很多测试都涉及到逻辑推理，例如条件跳转指令的测试：

*   **假设输入 (以 `short_conditional_jump_true` 为例):**
    *   被追踪的代码中包含一个短条件跳转指令 (例如 `jz`)。
    *   在执行到该指令时，条件码满足跳转条件 (例如，Zero Flag 为 1)。
*   **预期输出:**
    *   `stalker` 应该能够正确识别并追踪到跳转发生后的目标地址。
    *   事件流中会包含跳转后的代码执行事件。

*   **假设输入 (以 `short_conditional_jump_false` 为例):**
    *   被追踪的代码中包含一个短条件跳转指令。
    *   在执行到该指令时，条件码不满足跳转条件。
*   **预期输出:**
    *   `stalker` 应该能够正确识别并追踪到顺序执行的下一条指令。
    *   事件流中不会包含跳转目标地址的执行事件。

类似的逻辑推理存在于其他条件分支、循环、函数调用等测试中。

**涉及用户或者编程常见的使用错误 (基于测试用例):**

*   **未正确设置事件掩码:**  用户可能忘记设置 `fixture->sink->mask` 来指定需要追踪的事件类型 (`GUM_CALL`, `GUM_RET`, `GUM_EXEC` 等)。这将导致 `stalker` 追踪到不期望的事件，或者根本没有事件产生。
*   **在不合适的时机调用 `follow`/`unfollow`:**  测试用例 `unfollow_should_be_allowed_before/mid/after_transform` 表明，在 Transformer 执行的不同阶段调用 `unfollow` 是允许的，但用户可能错误地在不允许的或者不期望的时机调用这些函数，导致追踪行为异常。
*   **对已终止的线程进行操作:** `unfollow_should_handle_terminated_thread` 测试表明 `stalker` 可以处理取消追踪已终止的线程的情况。用户可能会错误地尝试追踪或取消追踪已经结束的线程。
*   **错误地设置自修改代码检测阈值:**  `self_modifying_code_should_be_detected_with_threshold_minus_one/zero/one` 测试了不同的阈值。用户如果将阈值设置为 0，可能会忽略某些恶意的自修改代码。
*   **不理解 Transformer 的工作方式:**  用户编写的 Transformer 代码可能会有逻辑错误，例如跳过了不应该跳过的指令，或者错误地修改了指令。
*   **资源管理错误:**  虽然测试代码没有直接展示用户资源管理错误，但在实际使用 `stalker` 时，用户可能会忘记释放分配的内存或资源，导致内存泄漏。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 用户首先会编写一个 Frida 脚本，使用 JavaScript 或 Python 调用 Frida 的 API。
2. **用户选择目标进程:**  脚本中会指定要附加的目标进程的 PID 或进程名。
3. **用户使用 `Stalker` API:** 脚本中会调用 `Stalker` 相关的 API，例如 `Stalker.follow()`, `Stalker.transform()`, `Stalker.unfollow()` 等。
4. **Frida 将脚本注入目标进程:** Frida 框架会将用户的脚本注入到目标进程中。
5. **Stalker 组件被激活:**  当脚本调用 `Stalker.follow()` 时，目标进程中的 `stalker` 组件会被激活。
6. **执行到被追踪的代码:** 目标进程继续执行，当执行到用户指定需要追踪的代码区域时，`stalker` 会捕获执行事件。
7. **Transformer 执行 (如果设置):** 如果用户通过 `Stalker.transform()` 设置了 Transformer，在代码实际执行之前，Transformer 的回调函数会被调用，允许修改代码。
8. **事件被发送到 Frida 客户端:**  `stalker` 产生的事件数据会被发送回运行 Frida 脚本的客户端。
9. **用户观察和分析事件:** 用户可以通过 Frida 客户端接收到的事件数据来分析目标程序的执行流程。

如果 `stalker` 的行为不符合预期，开发者可能会查看 `stalker-x86.c` 中的测试用例，以理解 `stalker` 的预期行为，并找到调试的线索。例如，如果用户发现 `stalker` 没有正确追踪某个特定的跳转指令，他们可能会在 `stalker-x86.c` 中查找与该指令相关的测试用例，看是否已经有类似的测试覆盖，或者是否存在相关的 bug 报告。

总而言之，`stalker-x86.c` 是一个非常重要的测试文件，它详细地验证了 Frida `stalker` 组件在 x86 架构下的各项功能，为开发者提供了理解和调试 `stalker` 行为的重要参考。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/core/arch-x86/stalker-x86.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共4部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2009-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2010-2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "stalker-x86-fixture.c"

#ifndef HAVE_WINDOWS
# include <lzma.h>
#endif

#ifdef HAVE_LINUX
# include <errno.h>
# include <fcntl.h>
# include <unistd.h>
# include <pthread.h>
# include <sys/wait.h>
# ifndef F_SETPIPE_SZ
#  define F_SETPIPE_SZ 1031
# endif
#endif

TESTLIST_BEGIN (stalker)
  TESTENTRY (no_events)
  TESTENTRY (call)
  TESTENTRY (ret)
  TESTENTRY (exec)
  TESTENTRY (call_depth)
  TESTENTRY (call_probe)
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

  TESTENTRY (unconditional_jumps)
  TESTENTRY (short_conditional_jump_true)
  TESTENTRY (short_conditional_jump_false)
  TESTENTRY (short_conditional_jcxz_true)
  TESTENTRY (short_conditional_jcxz_false)
  TESTENTRY (long_conditional_jump)
  TESTENTRY (follow_return)
  TESTENTRY (follow_stdcall)
  TESTENTRY (follow_repne_ret)
  TESTENTRY (follow_repne_jb)
  TESTENTRY (unfollow_deep)
  TESTENTRY (call_followed_by_junk)
  TESTENTRY (indirect_call_with_immediate)
  TESTENTRY (indirect_call_with_register_and_no_immediate)
  TESTENTRY (indirect_call_with_register_and_positive_byte_immediate)
  TESTENTRY (indirect_call_with_register_and_negative_byte_immediate)
  TESTENTRY (indirect_call_with_register_and_positive_dword_immediate)
  TESTENTRY (indirect_call_with_register_and_negative_dword_immediate)
#if GLIB_SIZEOF_VOID_P == 8
  TESTENTRY (indirect_call_with_extended_registers_and_immediate)
#endif
  TESTENTRY (indirect_call_with_esp_and_byte_immediate)
  TESTENTRY (indirect_call_with_esp_and_dword_immediate)
  TESTENTRY (indirect_jump_with_immediate)
  TESTENTRY (indirect_jump_with_immediate_and_scaled_register)
  TESTENTRY (direct_call_with_register)
#if GLIB_SIZEOF_VOID_P == 8
  TESTENTRY (direct_call_with_extended_register)
#endif
  TESTENTRY (popcnt)
#if GLIB_SIZEOF_VOID_P == 4
  TESTENTRY (no_register_clobber)
#endif
  TESTENTRY (no_red_zone_clobber)
  TESTENTRY (big_block)

  TESTENTRY (heap_api)
  TESTENTRY (follow_syscall)
  TESTENTRY (follow_thread)
#ifdef HAVE_LINUX
  TESTENTRY (create_thread)
#endif
  TESTENTRY (unfollow_should_handle_terminated_thread)
  TESTENTRY (self_modifying_code_should_be_detected_with_threshold_minus_one)
  TESTENTRY (self_modifying_code_should_not_be_detected_with_threshold_zero)
  TESTENTRY (self_modifying_code_should_be_detected_with_threshold_one)
#ifndef HAVE_WINDOWS
  TESTENTRY (performance)
#endif

#ifdef HAVE_WINDOWS
# if GLIB_SIZEOF_VOID_P == 4
  TESTENTRY (win32_indirect_call_seg)
# endif
  TESTENTRY (win32_messagebeep_api)
  TESTENTRY (win32_follow_user_to_kernel_to_callback)
  TESTENTRY (win32_follow_callback_to_kernel_to_user)
#endif

#ifdef HAVE_LINUX
  TESTENTRY (prefetch)
  TESTENTRY (prefetch_backpatch)
  TESTENTRY (observer)
#endif

#ifndef HAVE_WINDOWS
  TESTENTRY (ic_var)
#endif

#if defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
  TESTGROUP_BEGIN ("ExceptionHandling")
    TESTENTRY (no_exceptions)
    TESTENTRY (try_and_catch)
    TESTENTRY (try_and_catch_excluded)
    TESTENTRY (try_and_dont_catch)
    TESTENTRY (try_and_dont_catch_excluded)
  TESTGROUP_END ()
#endif

  TESTGROUP_BEGIN ("RunOnThread")
    TESTENTRY (run_on_thread_current)
    TESTENTRY (run_on_thread_current_sync)
    TESTENTRY (run_on_thread_other)
    TESTENTRY (run_on_thread_other_sync)
  TESTGROUP_END ()
TESTLIST_END ()

#ifdef HAVE_LINUX

#define GUM_TYPE_TEST_STALKER_OBSERVER (gum_test_stalker_observer_get_type ())
G_DECLARE_FINAL_TYPE (GumTestStalkerObserver, gum_test_stalker_observer, GUM,
                      TEST_STALKER_OBSERVER, GObject)

typedef struct _PrefetchBackpatchContext PrefetchBackpatchContext;

struct _GumTestStalkerObserver
{
  GObject parent;

  guint64 total;
};

struct _PrefetchBackpatchContext
{
  GumStalker * stalker;
  int pipes[2];
  GumTestStalkerObserver * observer;
  GumMemoryRange runner_range;
  GumStalkerTransformer * transformer;
  gboolean entry_reached;
  guint count;
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

static gpointer run_stalked_briefly (gpointer data);
#ifdef HAVE_LINUX
static gpointer run_spawned_thread (gpointer data);
#endif
static gpointer run_stalked_into_termination (gpointer data);
static void patch_code (gpointer code, gconstpointer new_code, gsize size);
static void do_patch_instruction (gpointer mem, gpointer user_data);
#ifndef HAVE_WINDOWS
static gboolean store_range_of_test_runner (const GumModuleDetails * details,
    gpointer user_data);
static void pretend_workload (GumMemoryRange * runner_range);
#endif
static void insert_extra_increment_after_xor (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void store_xax (GumCpuContext * cpu_context, gpointer user_data);
static void skip_call (GumStalkerIterator * iterator, GumStalkerOutput * output,
    gpointer user_data);
static void replace_call_with_callout (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void replace_jmp_with_callout (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void callout_set_cool (GumCpuContext * cpu_context, gpointer user_data);
static void unfollow_during_transform (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void modify_to_return_true_after_three_calls (
    GumStalkerIterator * iterator, GumStalkerOutput * output,
    gpointer user_data);
static void invalidate_after_three_calls (GumCpuContext * cpu_context,
    gpointer user_data);
static void start_invalidation_target (InvalidationTarget * target,
    gconstpointer target_function, TestStalkerFixture * fixture);
static void join_invalidation_target (InvalidationTarget * target);
static gpointer run_stalked_until_finished (gpointer data);
static void modify_to_return_true_on_subsequent_transform (
    GumStalkerIterator * iterator, GumStalkerOutput * output,
    gpointer user_data);
static void add_n_return_value_increments (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void invoke_follow_return_code (TestStalkerFixture * fixture);
static void invoke_unfollow_deep_code (TestStalkerFixture * fixture);

#ifdef HAVE_LINUX
static void prefetch_on_event (const GumEvent * event,
    GumCpuContext * cpu_context, gpointer user_data);
static void prefetch_run_child (GumStalker * stalker,
    GumMemoryRange * runner_range, int compile_fd, int execute_fd);
static void prefetch_activation_target (void);
static void prefetch_write_blocks (int fd, GHashTable * table);
static void prefetch_read_blocks (int fd, GHashTable * table);

static void prefetch_backpatch_tranform (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void entry_callout (GumCpuContext * cpu_context, gpointer user_data);
static int prefetch_on_fork (void);
static void prefetch_backpatch_simple_workload (GumMemoryRange * runner_range);

static void gum_test_stalker_observer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_test_stalker_observer_class_init (
    GumTestStalkerObserverClass * klass);
static void gum_test_stalker_observer_init (GumTestStalkerObserver * self);
static void gum_test_stalker_observer_increment_total (
    GumStalkerObserver * observer);
static void gum_test_stalker_observer_notify_backpatch (
    GumStalkerObserver * self, const GumBackpatch * backpatch, gsize size);

static gsize get_max_pipe_size (void);

G_DEFINE_TYPE_EXTENDED (GumTestStalkerObserver,
                        gum_test_stalker_observer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_STALKER_OBSERVER,
                            gum_test_stalker_observer_iface_init))

static GHashTable * prefetch_compiled = NULL;
static GHashTable * prefetch_executed = NULL;
static PrefetchBackpatchContext bp_ctx;

#ifndef HAVE_ANDROID
static void callback_at_end (GumStalkerIterator * iterator,
    GumStalkerOutput * output, gpointer user_data);
static void callout_at_end (GumCpuContext * cpu_context, gpointer user_data);
static void test_check_followed (void);
#endif

extern void __cxa_throw (void * thrown_exception, void * type,
    void (* destructor) (void *));

void test_check_bit (guint32 * val, guint8 bit);
void test_try_and_catch (guint32 * val);
void test_try_and_dont_catch (guint32 * val);
#endif

static void run_on_thread (const GumCpuContext * cpu_context,
    gpointer user_data);
static GThread * create_sleeping_dummy_thread_sync (gboolean * done,
    GumThreadId * thread_id);
static gpointer sleeping_dummy (gpointer data);

static const guint8 flat_code[] = {
  0x33, 0xc0, /* xor eax, eax */
  0xff, 0xc0, /* inc eax      */
  0xff, 0xc0, /* inc eax      */
  0xc3        /* retn         */
};

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

  /*gum_fake_event_sink_dump (fixture->sink);*/
}

TESTCASE (follow_syscall)
{
  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));
  g_usleep (1);
  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);

  /*gum_fake_event_sink_dump (fixture->sink);*/
}

TESTCASE (follow_thread)
{
  StalkerDummyChannel channel;
  GThread * thread;
  GumThreadId thread_id;

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

#ifdef HAVE_LINUX

TESTCASE (create_thread)
{
  pthread_t thread;
  gpointer result;

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  pthread_create (&thread, NULL, run_spawned_thread, NULL);
  pthread_join (thread, &result);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert (result == GSIZE_TO_POINTER (0xdeadface));
}

static gpointer
run_spawned_thread (gpointer data)
{
  return GSIZE_TO_POINTER (0xdeadface);
}

#endif

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
  guint8 mov_eax_imm_plus_nop[] = {
    0xb8, 0x00, 0x00, 0x00, 0x00, /* mov eax, <imm> */
    0x90                          /* nop padding    */
  };

  f = GUM_POINTER_TO_FUNCPTR (FlatFunc,
      test_stalker_fixture_dup_code (fixture, flat_code, sizeof (flat_code)));

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_set_trust_threshold (fixture->stalker, -1);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  g_assert_cmpuint (f (), ==, 2);

  *((guint32 *) (mov_eax_imm_plus_nop + 1)) = 42;
  patch_code (f, mov_eax_imm_plus_nop, sizeof (mov_eax_imm_plus_nop));
  g_assert_cmpuint (f (), ==, 42);
  f ();
  f ();

  *((guint32 *) (mov_eax_imm_plus_nop + 1)) = 1337;
  patch_code (f, mov_eax_imm_plus_nop, sizeof (mov_eax_imm_plus_nop));
  g_assert_cmpuint (f (), ==, 1337);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCASE (self_modifying_code_should_not_be_detected_with_threshold_zero)
{
  FlatFunc f;
  guint8 mov_eax_imm_plus_nop[] = {
    0xb8, 0x00, 0x00, 0x00, 0x00, /* mov eax, <imm> */
    0x90                          /* nop padding    */
  };

  f = GUM_POINTER_TO_FUNCPTR (FlatFunc,
      test_stalker_fixture_dup_code (fixture, flat_code, sizeof (flat_code)));

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_set_trust_threshold (fixture->stalker, 0);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  g_assert_cmpuint (f (), ==, 2);

  *((guint32 *) (mov_eax_imm_plus_nop + 1)) = 42;
  patch_code (f, mov_eax_imm_plus_nop, sizeof (mov_eax_imm_plus_nop));
  g_assert_cmpuint (f (), ==, 2);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

TESTCASE (self_modifying_code_should_be_detected_with_threshold_one)
{
  FlatFunc f;
  guint8 mov_eax_imm_plus_nop[] = {
    0xb8, 0x00, 0x00, 0x00, 0x00, /* mov eax, <imm> */
    0x90                          /* nop padding    */
  };

  f = GUM_POINTER_TO_FUNCPTR (FlatFunc,
      test_stalker_fixture_dup_code (fixture, flat_code, sizeof (flat_code)));

  fixture->sink->mask = GUM_EXEC | GUM_CALL | GUM_RET;

  gum_stalker_set_trust_threshold (fixture->stalker, 1);
  gum_stalker_follow_me (fixture->stalker, fixture->transformer,
      GUM_EVENT_SINK (fixture->sink));

  g_assert_cmpuint (f (), ==, 2);

  *((guint32 *) (mov_eax_imm_plus_nop + 1)) = 42;
  patch_code (f, mov_eax_imm_plus_nop, sizeof (mov_eax_imm_plus_nop));
  g_assert_cmpuint (f (), ==, 42);
  f ();
  f ();

  *((guint32 *) (mov_eax_imm_plus_nop + 1)) = 1337;
  patch_code (f, mov_eax_imm_plus_nop, sizeof (mov_eax_imm_plus_nop));
  g_assert_cmpuint (f (), ==, 42);

  gum_stalker_unfollow_me (fixture->stalker);

  g_assert_cmpuint (fixture->sink->events->len, >, 0);
}

static void
patch_code (gpointer code,
            gconstpointer new_code,
            gsize size)
{
  PatchCodeContext ctx = { new_code, size };

  gum_memory_patch_code (code, size, do_patch_instruction, &ctx);
}

static void
do_patch_instruction (gpointer mem,
                      gpointer user_data)
{
  PatchCodeContext * ctx = user_data;

  memcpy (mem, ctx->code, ctx->size);
}

#ifndef HAVE_WINDOWS

TESTCASE (performance)
{
  GumMemoryRange runner_range;
  GTimer * timer;
  gdouble duration_direct, duration_stalked;

  runner_range.base_address = 0;
  runner_range.size = 0;
  gum_process_enumerate_modules (store_range_of_test_runner, &runner_range);
  g_assert_cmpuint (runner_range.base_address, !=, 0);
  g_assert_cmpuint (runner_range.size, !=, 0);

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
  duration_stalked = g_timer_elapsed (timer, NULL);

  gum_stalker_unfollow_me (fixture->stalker);

  g_timer_destroy (timer);

  g_print ("<duration_direct=%f duration_stalked=%f ratio=%f> ",
      duration_direct, duration_stalked, duration_stalked / duration_direct);
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

GUM_NOINLINE static void
pretend_workload (GumMemoryRange * runner_range)
{
  lzma_stream stream = LZMA_STREAM_INIT;
  const uint32_t preset = 9 | LZMA_PRESET_EXTREME;
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

  free (outbuf);
}

#endif

static StalkerTestFunc
invoke_flat_expecting_return_value (TestStalkerFixture * fixture,
                                    GumEventType mask,
                                    guint expected_return_value)
{
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, flat_code, sizeof (flat_code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, expected_return_value);

  return func;
}

static StalkerTestFunc
invoke_flat (TestStalkerFixture * fixture,
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
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent, 0).type,
      ==, GUM_CALL);
  ev = &g_array_index (fixture->sink->events, GumEvent, 0).call;
  GUM_ASSERT_CMPADDR (ev->location, ==, fixture->last_invoke_calladdr);
  GUM_ASSERT_CMPADDR (ev->target, ==, func);
}

TESTCASE (ret)
{
  StalkerTestFunc func;
  GumRetEvent * ev;

  func = invoke_flat (fixture, GUM_RET);

  g_assert_cmpuint (fixture->sink->events->len, ==, 1);
  g_assert_cmpint (g_array_index (fixture->sink->events, GumEvent, 0).type,
      ==, GUM_RET);
  ev = &g_array_index (fixture->sink->events, GumEvent, 0).ret;
  GUM_ASSERT_CMPADDR (ev->location,
      ==, ((guint8 *) GSIZE_TO_POINTER (func)) + 6);
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
  ev = &g_array_index (fixture->sink->events, GumEvent,
      INVOKER_IMPL_OFFSET).ret;
  GUM_ASSERT_CMPADDR (ev->location, ==, func);
}

TESTCASE (call_depth)
{
  const guint8 code[] =
  {
    0xb8, 0x07, 0x00, 0x00, 0x00, /* mov eax, 7 */
    0xff, 0xc8,                   /* dec eax    */
    0x74, 0x05,                   /* jz +5      */
    0xe8, 0xf7, 0xff, 0xff, 0xff, /* call -9    */
    0xc3,                         /* ret        */
    0xcc,                         /* int3       */
  };
  StalkerTestFunc func;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code, sizeof (code)));

  fixture->sink->mask = GUM_CALL | GUM_RET;
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);

  g_assert_cmpuint (fixture->sink->events->len, ==, 7 + 7 + 1);
  g_assert_cmpint (NTH_EVENT_AS_CALL (0)->depth, ==, 0);
  g_assert_cmpint (NTH_EVENT_AS_CALL (1)->depth, ==, 1);
  g_assert_cmpint (NTH_EVENT_AS_CALL (2)->depth, ==, 2);
  g_assert_cmpint (NTH_EVENT_AS_CALL (3)->depth, ==, 3);
  g_assert_cmpint (NTH_EVENT_AS_CALL (4)->depth, ==, 4);
  g_assert_cmpint (NTH_EVENT_AS_CALL (5)->depth, ==, 5);
  g_assert_cmpint (NTH_EVENT_AS_CALL (6)->depth, ==, 6);
  g_assert_cmpint (NTH_EVENT_AS_RET (7)->depth, ==, 7);
  g_assert_cmpint (NTH_EVENT_AS_RET (8)->depth, ==, 6);
  g_assert_cmpint (NTH_EVENT_AS_RET (9)->depth, ==, 5);
  g_assert_cmpint (NTH_EVENT_AS_RET (10)->depth, ==, 4);
  g_assert_cmpint (NTH_EVENT_AS_RET (11)->depth, ==, 3);
  g_assert_cmpint (NTH_EVENT_AS_RET (12)->depth, ==, 2);
  g_assert_cmpint (NTH_EVENT_AS_RET (13)->depth, ==, 1);
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
  const guint8 code_template[] =
  {
    0x68, 0x44, 0x44, 0xaa, 0xaa, /* push 0xaaaa4444     */
    0x68, 0x33, 0x33, 0xaa, 0xaa, /* push 0xaaaa3333     */
    0xba, 0x22, 0x22, 0xaa, 0xaa, /* mov edx, 0xaaaa2222 */
    0xb9, 0x11, 0x11, 0xaa, 0xaa, /* mov ecx, 0xaaaa1111 */
    0xe8, 0x1b, 0x00, 0x00, 0x00, /* call func_a         */
    0x68, 0x44, 0x44, 0xaa, 0xaa, /* push 0xbbbb4444     */
    0x68, 0x33, 0x33, 0xaa, 0xaa, /* push 0xbbbb3333     */
    0xba, 0x22, 0x22, 0xaa, 0xaa, /* mov edx, 0xbbbb2222 */
    0xb9, 0x11, 0x11, 0xaa, 0xaa, /* mov ecx, 0xbbbb1111 */
    0xe8, 0x06, 0x00, 0x00, 0x00, /* call func_b         */
    0xc3,                         /* ret                 */

    0xcc,                         /* int 3               */

    /* func_a: */
    0xc2, 2 * sizeof (gpointer), 0x00, /* ret x          */

    0xcc,                         /* int 3               */

    /* func_b: */
    0xc2, 2 * sizeof (gpointer), 0x00, /* ret x          */
  };
  StalkerTestFunc func;
  guint8 * func_a;
  CallProbeContext probe_ctx, secondary_probe_ctx;
  GumProbeId probe_id;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, code_template,
          sizeof (code_template)));

  func_a = fixture->code + 52;

  probe_ctx.num_calls = 0;
  probe_ctx.target_address = fixture->code + 52;
  probe_ctx.return_address = fixture->code + 25;
  probe_id = gum_stalker_add_call_probe (fixture->stalker, func_a,
      probe_func_a_invocation, &probe_ctx, NULL);
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (probe_ctx.num_calls, ==, 1);

  secondary_probe_ctx.num_calls = 0;
  secondary_probe_ctx.target_address = probe_ctx.target_address;
  secondary_probe_ctx.return_address = probe_ctx.return_address;
  gum_stalker_add_call_probe (fixture->stalker, func_a, probe_func_a_invocation,
      &secondary_probe_ctx, NULL);
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (probe_ctx.num_calls, ==, 2);
  g_assert_cmpuint (secondary_probe_ctx.num_calls, ==, 1);

  gum_stalker_remove_call_probe (fixture->stalker, probe_id);
  test_stalker_fixture_follow_and_invoke (fixture, func, 0);
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

#if GLIB_SIZEOF_VOID_P == 4
  g_assert_cmphex (GPOINTER_TO_SIZE (
      gum_cpu_context_get_nth_argument (cpu_context, 0)), ==, 0xaaaa3333);
  g_assert_cmphex (GPOINTER_TO_SIZE (
      gum_cpu_context_get_nth_argument (cpu_context, 1)), ==, 0xaaaa4444);
#endif

  g_assert_cmphex (stack_values[0], ==, GPOINTER_TO_SIZE (ctx->return_address));
  g_assert_cmphex (stack_values[1] & 0xffffffff, ==, 0xaaaa3333);
  g_assert_cmphex (stack_values[2] & 0xffffffff, ==, 0xaaaa4444);

  g_assert_cmphex (GUM_CPU_CONTEXT_XIP (cpu_context),
      ==, GPOINTER_TO_SIZE (ctx->target_address));
#if GLIB_SIZEOF_VOID_P == 4
  g_assert_cmphex (cpu_context->ecx, ==, 0xaaaa1111);
  g_assert_cmphex (cpu_context->edx, ==, 0xaaaa2222);
#else
  g_assert_cmphex (cpu_context->rcx & 0xffffffff, ==, 0xaaaa1111);
  g_assert_cmphex (cpu_context->rdx & 0xffffffff, ==, 0xaaaa2222);
#endif
}

static const guint8 jumpy_code[] = {
  0x31, 0xc0,                   /* xor eax, eax */
  0xeb, 0x01,                   /* jmp short +1 */
  0xcc,                         /* int3         */
  0xff, 0xc0,                   /* inc eax      */
  0xe9, 0x02, 0x00, 0x00, 0x00, /* jmp near +2  */
  0xcc,                         /* int3         */
  0xcc,                         /* int3         */
  0xc3                          /* ret          */
};

static StalkerTestFunc
invoke_jumpy (TestStalkerFixture * fixture,
              GumEventType mask)
{
  StalkerTestFunc func;
  gint ret;

  func = GUM_POINTER_TO_FUNCPTR (StalkerTestFunc,
      test_stalker_fixture_dup_code (fixture, jumpy_code, sizeof (jumpy_code)));

  fixture->sink->mask = mask;
  ret = test_stalker_fixture_follow_and_invoke (fixture, func, -1);
  g_assert_cmpint (ret, ==, 1);

  return func;
}

TESTCASE (custom_transformer)
{
  gsize last_xax = 0;

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      insert_extra_increment_after_xor, &last_xax, NULL);

  g_assert_cmpuint (last_xax, ==, 0);

  invoke_flat_expecting_return_value (fixture, GUM_NOTHING, 3);

  g_assert_cmpuint (last_xax, ==, 3);
}

static void
insert_extra_increment_after_xor (GumStalkerIterator * iterator,
                                  GumStalkerOutput * output,
                                  gpointer user_data)
{
  gsize * last_xax = user_data;
  const cs_insn * insn;
  gboolean in_leaf_func;

  in_leaf_func = FALSE;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (in_leaf_func && insn->id == X86_INS_RET)
    {
      gum_stalker_iterator_put_callout (iterator, store_xax, last_xax, NULL);
    }

    gum_stalker_iterator_keep (iterator);

    if (insn->id == X86_INS_XOR)
    {
      in_leaf_func = TRUE;

      gum_x86_writer_put_inc_reg (output->writer.x86, GUM_X86_EAX);
    }
  }
}

static void
store_xax (GumCpuContext * cpu_context,
           gpointer user_data)
{
  gsize * last_xax = user_data;

  *last_xax = GUM_CPU_CONTEXT_XAX (cpu_context);
}

TESTCASE (transformer_should_be_able_to_skip_call)
{
  guint8 code_template[] =
  {
    0xb8, 0x14, 0x05, 0x00, 0x00, /* mov eax, 1300    */
    0xe8, 0x01, 0x00, 0x00, 0x00, /* call bump_number */
    0xc3,                         /* ret              */
    /* bump_number:                                   */
    0x83, 0xc0, 0x25,             /* add eax, 37      */
    0xc3,                         /* ret              */
  };
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_stalker_fixture_dup_code (fixture,
      code_template, sizeof (code_template));

  fixture->transformer = gum_stalker_transformer_make_from_callback (skip_call,
      func, NULL);

  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (ret, ==, 1300);
}

static void
skip_call (GumStalkerIterator * iterator,
           GumStalkerOutput * output,
           gpointer user_data)
{
  const guint8 * func_start = user_data;
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (insn->address == GPOINTER_TO_SIZE (func_start + 5))
      continue;

    gum_stalker_iterator_keep (iterator);
  }
}

TESTCASE (transformer_should_be_able_to_replace_call_with_callout)
{
  guint8 code_template[] =
  {
    0xb8, 0x14, 0x05, 0x00, 0x00, /* mov eax, 1300    */
    0xe8, 0x01, 0x00, 0x00, 0x00, /* call bump_number */
    0xc3,                         /* ret              */
    /* bump_number:                                   */
    0x83, 0xc0, 0x25,             /* add eax, 37      */
    0xc3,                         /* ret              */
  };
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_stalker_fixture_dup_code (fixture,
      code_template, sizeof (code_template));

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      replace_call_with_callout, func, NULL);

  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (ret, ==, 0xc001);
}

static void
replace_call_with_callout (GumStalkerIterator * iterator,
                           GumStalkerOutput * output,
                           gpointer user_data)
{
  const guint8 * func_start = user_data;
  const cs_insn * insn;

  while (gum_stalker_iterator_next (iterator, &insn))
  {
    if (insn->address == GPOINTER_TO_SIZE (func_start + 5))
    {
      gum_stalker_iterator_put_callout (iterator, callout_set_cool, NULL, NULL);
      continue;
    }

    gum_stalker_iterator_keep (iterator);
  }
}

TESTCASE (transformer_should_be_able_to_replace_tailjump_with_callout)
{
  guint8 code_template[] =
  {
    0xb8, 0x14, 0x05, 0x00, 0x00, /* mov eax, 1300   */
    0xeb, 0x01,                   /* jmp bump_number */
    0x90,                         /* nop             */
    /* bump_number:                                  */
    0x83, 0xc0, 0x25,             /* add eax, 37     */
    0xc3,                         /* ret             */
  };
  StalkerTestFunc func;
  gint ret;

  func = (StalkerTestFunc) test_stalker_fixture_dup_code (fixture,
      code_template, sizeof (code_template));

  fixture->transformer = gum_stalker_transformer_make_from_callback (
      replace_jmp_with_callout, func, NULL);

  ret = test_stalker_fixture_follow_and_invoke (fixture, func, 0);
  g_assert_cmpuint (ret, ==, 0xc001);
}

static void
replace_jmp_with_callout (GumStalkerIterator * iterator,
                          GumStalkerOutput * output,
                       
"""


```