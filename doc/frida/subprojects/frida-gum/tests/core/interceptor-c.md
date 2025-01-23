Response:
Let's break down the thought process for analyzing this C test file for Frida.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of this `interceptor.c` file within the Frida framework and how it relates to various technical aspects like reverse engineering, low-level details, and potential user errors. It's essentially an audit of the code's purpose and implications.

**2. Initial Skim and Identification of Key Areas:**

A quick read-through reveals the file structure:

* **Includes:**  Points to dependencies like other test files and likely core Frida headers.
* **Test List:**  The `TESTLIST_BEGIN` and `TESTLIST_END` macros immediately flag this as a test suite. Each `TESTENTRY` is an individual test case.
* **Helper Functions:**  Declarations like `hit_target_function_repeatedly`, `replacement_malloc`, etc., suggest these are used to set up specific test scenarios.
* **Test Cases:**  The `TESTCASE` macro marks the start of each individual test function, like `attach_one`, `attach_two`, etc.

This initial skim helps to organize the thinking process. We know we need to analyze individual test cases and their purpose.

**3. Deconstructing Individual Test Cases (Pattern Recognition):**

Analyzing a few test cases reveals a pattern:

* **`interceptor_fixture_attach()`:** This function seems central to setting up interception, taking arguments like a function pointer (`target_function`), and likely some markers (like '>', '<'). This immediately connects to the core Frida functionality of intercepting function calls.
* **Function Calls:**  The test cases then call the `target_function` (or other functions being tested).
* **Assertions (`g_assert_cmpstr`, `g_assert_cmpint`, etc.):** These are used to verify the expected behavior after interception. They check things like string values, integer comparisons, etc.

This pattern helps to quickly understand the purpose of most test cases. They are about attaching interceptors to functions and verifying the effects.

**4. Connecting to Reverse Engineering Concepts:**

Knowing that Frida is a dynamic instrumentation tool, the concept of "interception" directly relates to reverse engineering. We can now connect specific test cases to reverse engineering techniques:

* **Attaching:**  This is fundamental to observing function behavior without modifying the original binary.
* **Replacing:**  This allows modifying function behavior, a common technique in patching or hooking.
* **Examining Arguments and Return Values:**  These tests showcase how Frida can be used to inspect data flowing through a function, vital for understanding its logic.
* **CPU Context Manipulation:**  Tests involving `GumCpuContext` highlight Frida's ability to interact with the processor's state, crucial for advanced analysis and manipulation.

**5. Identifying Low-Level and Kernel/Framework Connections:**

As we go through the test cases, certain names and concepts stand out:

* **`pthread_key_create`:** This is a standard POSIX threads API function, indicating interaction with the operating system's threading mechanisms.
* **`malloc`, `free`:** These are fundamental memory management functions, directly related to the binary's interaction with the heap. Testing interception of these functions highlights Frida's low-level capabilities.
* **`GumThreadId`:**  This indicates interaction with thread identifiers, a concept managed by the operating system kernel.
* **Conditional Compilation (`#ifdef`, `#ifndef`):**  The presence of checks for `G_OS_UNIX`, `HAVE_WINDOWS`, `HAVE_ANDROID`, etc., suggests platform-specific tests and interaction with different operating system features.

**6. Recognizing Logical Reasoning and Input/Output:**

Many test cases perform a sequence of actions and then assert the final state. For example, `attach_two` attaches two interceptors and then checks the combined output. This involves a logical flow. We can then define hypothetical inputs (e.g., calling `target_function`) and expected outputs based on the interception logic.

**7. Spotting Potential User Errors:**

Certain test cases explicitly check for error conditions:

* **`already_attached`:** Tests what happens when you try to attach to a function that's already intercepted.
* **`already_replaced`:**  Similar to the above, but for replacement.
* **`GUM_ATTACH_WRONG_SIGNATURE`, `GUM_REPLACE_WRONG_SIGNATURE`, `GUM_REPLACE_WRONG_TYPE`:** These error codes indicate cases where the user might try to intercept or replace a function with an incompatible signature or using the wrong type of interceptor.

**8. Tracing User Operations (Debugging Clues):**

To understand how a user might reach these test scenarios, we can think about the steps involved in using Frida:

1. **Attaching to a Process:** The user needs to select a target process.
2. **Creating a Frida Script:**  This script uses the Frida API.
3. **Using the `Interceptor` API:** The script will likely use functions like `Interceptor.attach()` or `Interceptor.replace()`.
4. **Specifying the Target Function:**  The user needs to provide the address or name of the function to intercept.
5. **Defining Callbacks or Replacement Functions:**  The user provides the logic to execute when the target function is called.

The test cases in `interceptor.c` directly mirror these steps, providing examples of how the `Interceptor` API is used and what happens in different scenarios.

**9. Iteration and Refinement:**

As you go through the test cases, your understanding deepens. You might initially miss some nuances and then revisit them. For example, the "fast interceptor" tests might require a second pass to fully grasp the performance implications.

**Self-Correction Example:**

Initially, I might just say "attaching allows observing function calls." But upon seeing tests involving `GumCpuContext`, I'd refine that to include "and even manipulating the CPU state during the call."  Similarly, simply stating "replacing changes function behavior" can be enhanced by understanding the `replace_keep_original` test, which showcases accessing the original function.

By following this structured approach of skimming, deconstruction, connecting to concepts, identifying low-level details, reasoning about logic, spotting errors, and tracing user steps, one can effectively analyze and understand the functionality of a test file like `interceptor.c` within the broader context of the Frida dynamic instrumentation framework.
这个 `interceptor.c` 文件是 Frida 动态插桩工具中 `frida-gum` 库的核心测试文件，专门用于测试 `Interceptor` 模块的功能。 `Interceptor` 是 Frida 中用于拦截和修改函数执行的关键组件。

以下是该文件列举的功能以及与逆向、底层知识、逻辑推理和用户错误的相关说明：

**核心功能列举:**

1. **基本拦截 (Attach):**
   - `attach_one`: 测试单个拦截器附加到目标函数的能力。
   - `attach_two`: 测试多个拦截器附加到同一个目标函数，并按顺序执行的能力。
   - `attach_to_recursive_function`: 测试附加到递归调用的函数的能力。
   - `attach_to_special_function`:  可能测试附加到具有特殊调用约定的函数的能力。
   - `attach_to_pthread_key_create` (Unix): 测试附加到 POSIX 线程库中关键函数的能力。
   - `attach_to_heap_api`: 测试附加到堆内存分配/释放函数 (如 `malloc`, `free`) 的能力。
   - `attach_to_own_api`: 测试在拦截器内部调用被拦截函数的能力。

2. **拦截的精细控制:**
   - `thread_id`:  测试获取当前线程 ID 的能力。
   - `intercepted_free_in_thread_exit`:  测试在线程退出时拦截 `free` 函数的能力。
   - `function_arguments`: 测试在函数入口处获取函数参数的能力。
   - `function_return_value`: 测试在函数出口处获取函数返回值的能力。
   - `function_cpu_context_on_enter`: 测试在函数入口处获取 CPU 上下文 (寄存器状态) 的能力。
   - `ignore_current_thread`: 测试忽略当前线程的拦截的能力。
   - `ignore_current_thread_nested`: 测试嵌套忽略当前线程拦截的能力。
   - `ignore_other_threads`: 测试只拦截当前线程，忽略其他线程的能力。
   - `detach`: 测试从目标函数移除拦截器的能力。
   - `listener_ref_count`: 测试拦截器监听器对象的引用计数管理。
   - `function_data`: 测试附加到拦截器的用户自定义数据的传递和使用。

3. **函数替换 (Replace):**
   - `replace_one`: 测试用自定义函数替换目标函数的能力。
   - `replace_two`: 测试同时替换多个函数的能力。
   - `replace_then_attach`: 测试先替换函数，然后附加拦截器的行为。
   - `replace_keep_original`: 测试替换函数时保留原始函数指针的能力。

4. **快速替换 (Fast Replace):**
   - `replace_then_replace_fast`: 测试先进行标准替换，然后尝试快速替换的行为。
   - `attach_then_replace_fast`: 测试先附加拦截器，然后尝试快速替换的行为。
   - `replace_fast_then_replace`: 测试先进行快速替换，然后尝试标准替换的行为。
   - `replace_fast_then_attach`: 测试先进行快速替换，然后尝试附加拦截器的行为。
   - `replace_one_fast`: 测试快速替换单个函数的能力。
   - `fast_interceptor_performance`: 测试快速拦截器与标准拦截器的性能差异。

5. **错误处理和边界情况:**
   - `i_can_has_attachability`:  测试尝试附加到不支持拦截的指令/函数的能力，验证错误处理。
   - `already_attached`: 测试重复附加同一个拦截器的行为。
   - `already_replaced`: 测试重复替换同一个函数的行为。
   - `i_can_has_replaceability`: 测试尝试替换不支持替换的指令/函数的能力，验证错误处理。
   - `i_can_has_replaceability_fast`: 测试尝试快速替换不支持替换的指令/函数的能力，验证错误处理。

6. **CPU 上下文和标志位操作:**
   - `cpu_register_clobber`: 测试拦截器是否会错误地修改 CPU 寄存器的值。
   - `cpu_flag_clobber`: 测试拦截器是否会错误地修改 CPU 标志位的值。

7. **针对特定架构的测试 (例如 x86):**
   - `relative_proxy_function`: 测试附加到使用相对跳转的代理函数的能力。
   - `absolute_indirect_proxy_function`: 测试附加到使用绝对间接跳转的代理函数的能力。
   - `two_indirects_to_function`: 测试附加到经过两次间接跳转的目标函数的能力。
   - `relocation_of_early_call`: 测试附加到包含早期调用的函数，并验证重定位的正确性。
   - `relocation_of_early_rip_relative_call` (x86_64): 测试附加到包含早期 RIP 相对调用的函数，并验证重定位的正确性。

**与逆向方法的关联及举例:**

* **代码Hook (Hooking):** `attach_one`, `attach_two`, `replace_one`, `replace_one_fast` 等测试直接关联代码 Hook 技术。逆向工程师可以使用 Frida 的 `Interceptor` 来 Hook 目标进程中的函数，在函数执行前后执行自定义代码，从而监控函数行为、修改参数、返回值等。
    * **举例:** 逆向一个恶意软件，可以使用 `Interceptor.attach` Hook `CreateFileA` 函数，记录恶意软件尝试创建的文件路径，从而分析其行为。

* **API 监控:** `attach_to_heap_api`, `attach_to_pthread_key_create` 等测试体现了对特定 API 的监控能力。逆向工程师可以 Hook 系统或库的 API，例如内存管理、线程管理等，来理解程序如何与操作系统交互。
    * **举例:** 逆向一个 Android 应用，可以 Hook `android.app.Activity.onCreate` 来追踪 Activity 的生命周期，或者 Hook `java.net.URL.openConnection` 来监控网络请求。

* **代码插桩:**  Frida 的 `Interceptor` 本身就是一种动态代码插桩技术。测试用例展示了如何将自定义代码注入到目标进程的执行流程中。
    * **举例:** 逆向一个加壳的程序，可以在解压代码的关键位置插入代码，dump 解压后的代码，方便进一步分析。

* **参数和返回值分析:** `function_arguments`, `function_return_value` 测试直接关联对函数调用上下文的分析。逆向工程师可以利用这些功能来获取函数的输入和输出，理解函数的功能。
    * **举例:** 逆向一个加密算法的实现，可以 Hook 加密函数，获取加密前的明文和加密后的密文，从而分析加密算法的原理。

* **CPU 上下文分析:** `function_cpu_context_on_enter` 测试涉及获取 CPU 寄存器状态。在更底层的逆向分析中，了解函数执行时的寄存器状态对于理解汇编代码和程序行为至关重要。
    * **举例:** 分析一个利用 Return-Oriented Programming (ROP) 技术的漏洞时，需要了解栈帧结构和寄存器的值，Frida 可以帮助获取这些信息。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

* **二进制代码执行:** 所有的拦截和替换操作都直接作用于目标进程的二进制代码。理解不同架构 (如 x86, ARM) 的指令集、调用约定、内存布局是使用 Frida 的基础。
    * **举例:** `relative_proxy_function`, `absolute_indirect_proxy_function`, `relocation_of_early_call` 等测试都涉及到 x86 架构下不同的代码跳转方式和重定位机制。

* **Linux 系统调用和库:** `attach_to_pthread_key_create`, `attach_to_heap_api` 等测试涉及到 Linux 操作系统提供的线程和内存管理 API。
    * **举例:** `pthread_key_create` 是 POSIX 线程库中用于创建线程特定数据的函数。拦截它可以分析程序如何使用线程局部存储。`malloc` 和 `free` 是 C 标准库提供的堆内存分配和释放函数。

* **Android 框架 (如果 Frida 用于 Android):** 虽然这个文件本身不直接涉及 Android 框架的具体 API，但 Frida 在 Android 上的应用会涉及到 Dalvik/ART 虚拟机、JNI 调用、Android 系统服务等知识。
    * **举例:** 在 Android 上使用 Frida 可以 Hook Java 层的方法或者 Native 层的函数，这需要理解 Android 的应用层和 Native 层的交互方式。

* **内存管理:** `attach_to_heap_api`, `replace_one` 等测试涉及到对进程内存的管理和修改。理解虚拟内存、堆、栈的概念，以及内存分配器的原理，有助于理解 Frida 的工作方式和可能产生的影响。

**逻辑推理的假设输入与输出举例:**

* **`attach_two` 测试:**
    * **假设输入:**  将两个分别添加字符 'a' 和 'c' (on_enter) 和 'b' 和 'd' (on_leave) 的拦截器附加到 `target_function`，然后调用 `target_function`。
    * **预期输出:** `fixture->result->str` 的值应该为 "ac|bd"，表示两个拦截器的 enter 和 leave 代码都按顺序执行了。

* **`ignore_current_thread` 测试:**
    * **假设输入:** 先附加一个在 enter 和 leave 时分别添加 '>' 和 '<' 的拦截器，然后正常调用 `target_function`，接着调用 `gum_interceptor_ignore_current_thread`，再次调用 `target_function`，然后调用 `gum_interceptor_unignore_current_thread`，最后再次调用 `target_function`。
    * **预期输出:**  第一次调用后 `fixture->result->str` 为 ">|<"，第二次调用后为 "|" (因为被忽略了)，第三次调用后为 ">|<"。

**用户或编程常见的使用错误举例:**

* **尝试附加到无效地址或非函数地址:**  虽然测试中没有直接展示，但用户可能会尝试将拦截器附加到一个不是函数起始地址的内存地址，或者是一个数据段的地址，导致程序崩溃或行为异常。`i_can_has_attachability` 测试尝试附加到已知不支持拦截的位置，模拟了这种错误，并验证 Frida 能否正确处理。

* **尝试替换具有不同调用约定的函数:**  如果用户尝试用一个具有不同参数或返回类型的函数来替换目标函数，可能会导致栈破坏或其他未定义行为。`i_can_has_replaceability` 和 `i_can_has_replaceability_fast` 测试尝试替换成签名不匹配的 `replacement_malloc`，模拟了这种错误。

* **在拦截器中发生错误导致无限循环或崩溃:** 如果 `on_enter` 或 `on_leave` 回调函数中存在错误，可能会导致被拦截的函数无法正常返回，或者程序崩溃。

* **忘记 detach 拦截器导致资源泄漏或意外行为:**  如果用户在完成监控或修改后忘记移除拦截器，可能会导致额外的性能开销或持续影响目标进程的行为。

* **在多线程环境下不正确地使用全局变量或共享资源:**  拦截器代码运行在目标进程的上下文中，如果多个线程同时触发拦截器并访问共享资源，可能会出现竞态条件。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 用户首先会编写一个 JavaScript 或 Python 脚本，使用 Frida 的 API 来进行动态插桩。

2. **使用 `Interceptor` API:**  在脚本中，用户会使用 `Frida.Interceptor` 对象的方法，例如 `attach()`, `replace()`, `detach()`, `flush()`, `revert()` 等。

3. **指定目标函数:**  用户需要指定要拦截或替换的目标函数。这可以通过函数名、内存地址或模块导出符号等方式完成。

4. **定义回调函数或替换函数:**
   - 对于 `attach()`, 用户需要提供 `onEnter` 和/或 `onLeave` 回调函数，这些函数会在目标函数执行前和执行后被调用。
   - 对于 `replace()`, 用户需要提供一个替换目标函数的自定义函数。

5. **运行 Frida 脚本:**  用户通过 Frida 命令行工具 (`frida`, `frida-trace`) 或 Python API 将脚本注入到目标进程中。

6. **目标进程执行到被拦截的代码:** 当目标进程执行到用户指定的函数时，Frida 的 `Interceptor` 模块会介入，执行用户定义的回调函数或替换函数。

7. **`interceptor.c` 中的测试模拟了上述步骤:**  例如，`TESTCASE(attach_one)` 模拟了用户调用 `Interceptor.attach()`，并定义了简单的 enter 和 leave 回调函数 (通过 `interceptor_fixture_attach`)，然后通过调用 `target_function` 来触发拦截，并验证回调函数的执行结果。

**作为调试线索:** 如果用户在使用 Frida 的 `Interceptor` 过程中遇到问题，例如拦截没有生效、回调函数没有按预期执行、程序崩溃等，可以参考 `interceptor.c` 中的测试用例。这些测试覆盖了 `Interceptor` 的各种功能和边界情况，可以帮助用户理解 `Interceptor` 的工作原理，并找到自己脚本中可能存在的问题。例如，如果用户尝试多次 attach 同一个函数遇到问题，可以查看 `already_attached` 测试用例来理解 Frida 的行为。如果涉及到性能问题，可以参考 `fast_interceptor_performance` 测试用例来了解不同拦截方式的性能差异。

总而言之，`interceptor.c` 是 Frida `Interceptor` 模块的功能验证和回归测试的基石，它不仅展示了该模块的各种能力，也间接反映了动态插桩技术在逆向工程、安全分析等领域的核心应用场景。通过阅读和理解这些测试用例，可以更深入地了解 Frida 的工作原理，并避免常见的用户错误。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/interceptor.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "interceptor-fixture.c"

TESTLIST_BEGIN (interceptor)
  TESTENTRY (cpu_register_clobber)
  TESTENTRY (cpu_flag_clobber)

  TESTENTRY (i_can_has_attachability)
#ifdef HAVE_I386
  TESTENTRY (already_attached)
  TESTENTRY (relative_proxy_function)
  TESTENTRY (absolute_indirect_proxy_function)
  TESTENTRY (two_indirects_to_function)
  TESTENTRY (relocation_of_early_call)
# if GLIB_SIZEOF_VOID_P == 8
  TESTENTRY (relocation_of_early_rip_relative_call)
# endif
#endif

  TESTENTRY (attach_one)
  TESTENTRY (attach_two)
  TESTENTRY (attach_to_recursive_function)
  TESTENTRY (attach_to_special_function)
#ifdef G_OS_UNIX
  TESTENTRY (attach_to_pthread_key_create)
#endif
#if !defined (HAVE_QNX) && !(defined (HAVE_ANDROID) && defined (HAVE_ARM64))
  TESTENTRY (attach_to_heap_api)
#endif
  TESTENTRY (attach_to_own_api)
#ifdef HAVE_WINDOWS
  TESTENTRY (attach_detach_torture)
#endif
  TESTENTRY (thread_id)
#if defined (HAVE_FRIDA_GLIB) && \
    !(defined (HAVE_ANDROID) && defined (HAVE_ARM64)) && \
    !defined (HAVE_ASAN)
  TESTENTRY (intercepted_free_in_thread_exit)
#endif
  TESTENTRY (function_arguments)
  TESTENTRY (function_return_value)
  TESTENTRY (function_cpu_context_on_enter)
  TESTENTRY (ignore_current_thread)
  TESTENTRY (ignore_current_thread_nested)
  TESTENTRY (ignore_other_threads)
  TESTENTRY (detach)
  TESTENTRY (listener_ref_count)
  TESTENTRY (function_data)

  TESTENTRY (i_can_has_replaceability)
  TESTENTRY (already_replaced)
#ifndef HAVE_ASAN
  TESTENTRY (replace_one)
# ifdef HAVE_FRIDA_GLIB
  TESTENTRY (replace_two)
# endif
#endif
  TESTENTRY (replace_then_attach)
  TESTENTRY (replace_keep_original)

  TESTENTRY (replace_then_replace_fast)
  TESTENTRY (attach_then_replace_fast)
  TESTENTRY (replace_fast_then_replace)
  TESTENTRY (replace_fast_then_attach)
  TESTENTRY (i_can_has_replaceability_fast)
  TESTENTRY (replace_one_fast)
  TESTENTRY (fast_interceptor_performance)
TESTLIST_END ()

#ifdef HAVE_WINDOWS
static gpointer hit_target_function_repeatedly (gpointer data);
#endif
static gpointer replacement_malloc (gsize size);
static gpointer replacement_target_function (GString * str);
static gpointer (* target_function_fast) (GString * str) = NULL;
static gpointer replacement_target_function_fast (GString * str);

TESTCASE (attach_one)
{
  interceptor_fixture_attach (fixture, 0, target_function, '>', '<');
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
}

TESTCASE (attach_two)
{
  interceptor_fixture_attach (fixture, 0, target_function, 'a', 'b');
  interceptor_fixture_attach (fixture, 1, target_function, 'c', 'd');
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "ac|bd");
}

void GUM_NOINLINE
recursive_function (GString * str,
                    gint count)
{
  if (count > 0)
    recursive_function (str, count - 1);

  g_string_append_printf (str, "%d", count);
}

TESTCASE (attach_to_recursive_function)
{
  interceptor_fixture_attach (fixture, 0, recursive_function, '>', '<');
  recursive_function (fixture->result, 4);
  g_assert_cmpstr (fixture->result->str, ==, ">>>>>0<1<2<3<4<");
}

TESTCASE (attach_to_special_function)
{
  interceptor_fixture_attach (fixture, 0, special_function, '>', '<');
  special_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
}

#ifdef G_OS_UNIX

TESTCASE (attach_to_pthread_key_create)
{
  int (* pthread_key_create_impl) (pthread_key_t * key,
      void (* destructor) (void *));
  pthread_key_t key;

  pthread_key_create_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name (NULL, "pthread_key_create"));

  interceptor_fixture_attach (fixture, 0, pthread_key_create_impl, '>', '<');

  g_assert_cmpint (pthread_key_create_impl (&key, NULL), ==, 0);

  pthread_key_delete (key);
}

#endif

TESTCASE (attach_to_heap_api)
{
  gpointer malloc_impl, free_impl;
  volatile gpointer p;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  malloc_impl = interceptor_fixture_get_libc_malloc ();
  free_impl = interceptor_fixture_get_libc_free ();

  gum_interceptor_ignore_current_thread (fixture->interceptor);
  interceptor_fixture_attach (fixture, 0, malloc_impl, '>', '<');
  interceptor_fixture_attach (fixture, 1, free_impl, 'a', 'b');
  gum_interceptor_unignore_current_thread (fixture->interceptor);
  p = malloc (1);
  free (p);
  g_assert_cmpstr (fixture->result->str, ==, "><ab");

  interceptor_fixture_detach (fixture, 0);
  interceptor_fixture_detach (fixture, 1);

  g_assert_cmpstr (fixture->result->str, ==, "><ab");
}

TESTCASE (attach_to_own_api)
{
  TestCallbackListener * listener;

  listener = test_callback_listener_new ();
  listener->on_enter = (TestCallbackListenerFunc) target_function;
  listener->on_leave = (TestCallbackListenerFunc) target_function;
  listener->user_data = fixture->result;

  gum_interceptor_attach (fixture->interceptor, target_function,
      GUM_INVOCATION_LISTENER (listener), NULL);
  target_function (fixture->result);
  gum_interceptor_detach (fixture->interceptor,
      GUM_INVOCATION_LISTENER (listener));

  g_assert_cmpstr (fixture->result->str, ==, "|||");

  g_object_unref (listener);
}

#ifdef HAVE_WINDOWS

TESTCASE (attach_detach_torture)
{
  GThread * th;
  volatile guint n_passes = 100;

  th = g_thread_new ("interceptor-test-torture",
      hit_target_function_repeatedly, (gpointer) &n_passes);

  g_thread_yield ();

  do
  {
    TestCallbackListener * listener;

    interceptor_fixture_attach (fixture, 0, target_function, 'a', 'b');

    listener = test_callback_listener_new ();

    gum_interceptor_attach (fixture->interceptor, target_function,
        GUM_INVOCATION_LISTENER (listener), NULL);
    gum_interceptor_detach (fixture->interceptor,
        GUM_INVOCATION_LISTENER (listener));
    interceptor_fixture_detach (fixture, 0);

    g_object_unref (listener);
  }
  while (--n_passes != 0);

  g_thread_join (th);
}

#endif

TESTCASE (thread_id)
{
  GumThreadId first_thread_id, second_thread_id;

  interceptor_fixture_attach (fixture, 0, target_function, 'a', 'b');

  target_function (fixture->result);
  first_thread_id = fixture->listener_context[0]->last_thread_id;

  g_thread_join (g_thread_new ("interceptor-test-thread-id",
      (GThreadFunc) target_function, fixture->result));
  second_thread_id = fixture->listener_context[0]->last_thread_id;

  g_assert_cmpuint (second_thread_id, !=, first_thread_id);
}

#if defined (HAVE_FRIDA_GLIB) && \
    !(defined (HAVE_ANDROID) && defined (HAVE_ARM64)) && \
    !defined (HAVE_ASAN)

TESTCASE (intercepted_free_in_thread_exit)
{
  interceptor_fixture_attach (fixture, 0, interceptor_fixture_get_libc_free (),
      'a', 'b');
  g_thread_join (g_thread_new ("interceptor-test-thread-exit",
      target_nop_function_a, NULL));
}

#endif

TESTCASE (function_arguments)
{
  interceptor_fixture_attach (fixture, 0, target_nop_function_a, 'a', 'b');
  target_nop_function_a (GSIZE_TO_POINTER (0x12349876));
  g_assert_cmphex (fixture->listener_context[0]->last_seen_argument,
      ==, 0x12349876);
}

TESTCASE (function_return_value)
{
  gpointer return_value;

  interceptor_fixture_attach (fixture, 0, target_nop_function_a, 'a', 'b');
  return_value = target_nop_function_a (NULL);
  g_assert_cmphex (
      GPOINTER_TO_SIZE (fixture->listener_context[0]->last_return_value),
      ==, GPOINTER_TO_SIZE (return_value));
}

TESTCASE (function_cpu_context_on_enter)
{
#if defined (HAVE_I386) || defined (HAVE_ARM) || defined (HAVE_ARM64)
  ClobberTestFunc * cursor;

  for (cursor = clobber_test_functions; *cursor != NULL; cursor++)
  {
    ClobberTestFunc target_func = *cursor;
    GumCpuContext input, output;

    interceptor_fixture_attach (fixture, 0, target_func, 'a', 'b');

    fill_cpu_context_with_magic_values (&input);
    invoke_clobber_test_function_with_cpu_context (target_func,
        &input, &output);
    g_assert_cmpstr (fixture->result->str, ==, "ab");
    assert_cpu_contexts_are_equal (&input,
        &fixture->listener_context[0]->last_on_enter_cpu_context);

    g_string_truncate (fixture->result, 0);
    interceptor_fixture_detach (fixture, 0);
  }
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (ignore_current_thread)
{
  interceptor_fixture_attach (fixture, 0, target_function, '>', '<');

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  gum_interceptor_ignore_current_thread (fixture->interceptor);
  g_string_truncate (fixture->result, 0);

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "|");

  gum_interceptor_unignore_current_thread (fixture->interceptor);
  g_string_truncate (fixture->result, 0);

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
}

TESTCASE (ignore_current_thread_nested)
{
  interceptor_fixture_attach (fixture, 0, target_function, '>', '<');

  gum_interceptor_ignore_current_thread (fixture->interceptor);
  gum_interceptor_ignore_current_thread (fixture->interceptor);
  gum_interceptor_unignore_current_thread (fixture->interceptor);
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "|");
  gum_interceptor_unignore_current_thread (fixture->interceptor);
}

TESTCASE (ignore_other_threads)
{
  interceptor_fixture_attach (fixture, 0, target_function, '>', '<');

  gum_interceptor_ignore_other_threads (fixture->interceptor);

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  g_thread_join (g_thread_new ("interceptor-test-ignore-others-a",
      (GThreadFunc) target_function, fixture->result));
  g_assert_cmpstr (fixture->result->str, ==, ">|<|");

  gum_interceptor_unignore_other_threads (fixture->interceptor);

  g_thread_join (g_thread_new ("interceptor-test-ignore-others-b",
      (GThreadFunc) target_function, fixture->result));
  g_assert_cmpstr (fixture->result->str, ==, ">|<|>|<");
}

TESTCASE (detach)
{
  interceptor_fixture_attach (fixture, 0, target_function, 'a', 'b');
  interceptor_fixture_attach (fixture, 1, target_function, 'c', 'd');

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "ac|bd");

  interceptor_fixture_detach (fixture, 0);
  g_string_truncate (fixture->result, 0);

  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, "c|d");
}

TESTCASE (listener_ref_count)
{
  interceptor_fixture_attach (fixture, 0, target_function, 'a', 'b');
  g_assert_cmpuint (
      G_OBJECT (fixture->listener_context[0]->listener)->ref_count, ==, 1);
}

TESTCASE (function_data)
{
  TestFunctionDataListener * fd_listener;
  GumInvocationListener * listener;
  gpointer a_data = "a", b_data = "b";

  fd_listener =
      g_object_new (TEST_TYPE_FUNCTION_DATA_LISTENER, NULL);
  listener = GUM_INVOCATION_LISTENER (fd_listener);
  g_assert_cmpint (gum_interceptor_attach (fixture->interceptor,
      target_nop_function_a, listener, a_data), ==, GUM_ATTACH_OK);
  g_assert_cmpint (gum_interceptor_attach (fixture->interceptor,
      target_nop_function_b, listener, b_data), ==, GUM_ATTACH_OK);

  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 0);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 0);
  g_assert_cmpuint (fd_listener->init_thread_state_count, ==, 0);

  target_nop_function_a ("badger");
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->init_thread_state_count, ==, 1);
  g_assert_true (fd_listener->last_on_enter_data.function_data == a_data);
  g_assert_true (fd_listener->last_on_leave_data.function_data == a_data);
  g_assert_cmpstr (fd_listener->last_on_enter_data.thread_data.name, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_leave_data.thread_data.name, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_enter_data.invocation_data.arg,
      ==, "badger");
  g_assert_cmpstr (fd_listener->last_on_leave_data.invocation_data.arg,
      ==, "badger");

  target_nop_function_a ("snake");
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 2);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 2);
  g_assert_cmpuint (fd_listener->init_thread_state_count, ==, 1);
  g_assert_true (fd_listener->last_on_enter_data.function_data == a_data);
  g_assert_true (fd_listener->last_on_leave_data.function_data == a_data);
  g_assert_cmpstr (fd_listener->last_on_enter_data.thread_data.name, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_leave_data.thread_data.name, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_enter_data.invocation_data.arg,
      ==, "snake");
  g_assert_cmpstr (fd_listener->last_on_leave_data.invocation_data.arg,
      ==, "snake");

  test_function_data_listener_reset (fd_listener);

  target_nop_function_b ("mushroom");
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->init_thread_state_count, ==, 0);
  g_assert_true (fd_listener->last_on_enter_data.function_data == b_data);
  g_assert_true (fd_listener->last_on_leave_data.function_data == b_data);
  g_assert_cmpstr (fd_listener->last_on_enter_data.thread_data.name, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_leave_data.thread_data.name, ==, "a1");
  g_assert_cmpstr (fd_listener->last_on_enter_data.invocation_data.arg,
      ==, "mushroom");
  g_assert_cmpstr (fd_listener->last_on_leave_data.invocation_data.arg,
      ==, "mushroom");

  test_function_data_listener_reset (fd_listener);

  g_thread_join (g_thread_new ("interceptor-test-function-data",
      target_nop_function_a, "bdgr"));
  g_assert_cmpuint (fd_listener->on_enter_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->on_leave_call_count, ==, 1);
  g_assert_cmpuint (fd_listener->init_thread_state_count, ==, 1);
  g_assert_true (fd_listener->last_on_enter_data.function_data == a_data);
  g_assert_true (fd_listener->last_on_leave_data.function_data == a_data);
  g_assert_cmpstr (fd_listener->last_on_enter_data.thread_data.name, ==, "a2");
  g_assert_cmpstr (fd_listener->last_on_leave_data.thread_data.name, ==, "a2");
  g_assert_cmpstr (fd_listener->last_on_enter_data.invocation_data.arg,
      ==, "bdgr");
  g_assert_cmpstr (fd_listener->last_on_leave_data.invocation_data.arg,
      ==, "bdgr");

  gum_interceptor_detach (fixture->interceptor, listener);
  g_object_unref (fd_listener);
}

TESTCASE (cpu_register_clobber)
{
#if defined (HAVE_I386) || defined (HAVE_ARM) || defined (HAVE_ARM64)
  ClobberTestFunc * cursor;

  for (cursor = clobber_test_functions; *cursor != NULL; cursor++)
  {
    ClobberTestFunc target_func = *cursor;
    GumCpuContext input, output;

    interceptor_fixture_attach (fixture, 0, target_func, '>', '<');

    fill_cpu_context_with_magic_values (&input);
    invoke_clobber_test_function_with_cpu_context (target_func,
        &input, &output);
    g_assert_cmpstr (fixture->result->str, ==, "><");
    assert_cpu_contexts_are_equal (&input, &output);

    g_string_truncate (fixture->result, 0);
    interceptor_fixture_detach (fixture, 0);
  }
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (cpu_flag_clobber)
{
#if defined (HAVE_I386) || defined (HAVE_ARM) || defined (HAVE_ARM64)
  ClobberTestFunc * cursor;

  for (cursor = clobber_test_functions; *cursor != NULL; cursor++)
  {
    ClobberTestFunc target_func = *cursor;
    gsize flags_input, flags_output;

    interceptor_fixture_attach (fixture, 0, target_func, '>', '<');

    invoke_clobber_test_function_with_carry_set (target_func,
        &flags_input, &flags_output);
    g_assert_cmpstr (fixture->result->str, ==, "><");
    g_assert_cmphex (flags_output, ==, flags_input);

    g_string_truncate (fixture->result, 0);
    interceptor_fixture_detach (fixture, 0);
  }
#else
  g_print ("<skipping, missing code for current architecture> ");
#endif
}

TESTCASE (i_can_has_attachability)
{
  UnsupportedFunction * unsupported_functions;
  guint count, i;

  unsupported_functions = unsupported_function_list_new (&count);

  for (i = 0; i < count; i++)
  {
    UnsupportedFunction * func = &unsupported_functions[i];

    g_assert_cmpint (interceptor_fixture_try_attach (fixture, 0,
        func->code + func->code_offset, '>', '<'),
        ==, GUM_ATTACH_WRONG_SIGNATURE);
  }

  unsupported_function_list_free (unsupported_functions);
}

#ifdef HAVE_I386

TESTCASE (already_attached)
{
  interceptor_fixture_attach (fixture, 0, target_function, '>', '<');
  g_assert_cmpint (gum_interceptor_attach (fixture->interceptor,
      target_function, GUM_INVOCATION_LISTENER (
          fixture->listener_context[0]->listener),
      NULL), ==, GUM_ATTACH_ALREADY_ATTACHED);
}

TESTCASE (relative_proxy_function)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_relative_with_target (target_function);

  interceptor_fixture_attach (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  proxy_func_free (proxy_func);
}

TESTCASE (absolute_indirect_proxy_function)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_absolute_indirect_with_target (target_function);

  interceptor_fixture_attach (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  proxy_func_free (proxy_func);
}

TESTCASE (two_indirects_to_function)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_two_jumps_with_target (target_function);

  interceptor_fixture_attach (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");

  proxy_func_free (proxy_func);
}

TESTCASE (relocation_of_early_call)
{
  ProxyFunc proxy_func;

  proxy_func = proxy_func_new_early_call_with_target (target_function);

  interceptor_fixture_attach (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
  interceptor_fixture_detach (fixture, 0);

  proxy_func_free (proxy_func);
}

# if GLIB_SIZEOF_VOID_P == 8

TESTCASE (relocation_of_early_rip_relative_call)
{
  ProxyFunc proxy_func;

  proxy_func =
      proxy_func_new_early_rip_relative_call_with_target (target_function);

  interceptor_fixture_attach (fixture, 0, proxy_func, '>', '<');
  proxy_func (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">|<");
  interceptor_fixture_detach (fixture, 0);

  proxy_func_free (proxy_func);
}

# endif

#endif /* HAVE_I386 */

#ifndef HAVE_ASAN

TESTCASE (replace_one)
{
  gpointer (* malloc_impl) (gsize size);
  guint counter = 0;
  volatile gpointer ret;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  malloc_impl = interceptor_fixture_get_libc_malloc ();

  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor, malloc_impl,
      replacement_malloc, &counter, NULL), ==, GUM_REPLACE_OK);
  ret = malloc_impl (0x42);

  /*
   * This statement is needed so the compiler doesn't move the malloc() call
   * to after revert().  We do the real assert after reverting, as failing
   * asserts with broken malloc() are quite tricky to debug. :)
   */
  g_assert_nonnull (ret);

  gum_interceptor_revert (fixture->interceptor, malloc_impl);
  g_assert_cmpint (counter, ==, 1);
  g_assert_cmphex (GPOINTER_TO_SIZE (ret), ==, 0x42);

  ret = malloc_impl (1);
  g_assert_cmpint (counter, ==, 1);
  free (ret);
}

#ifdef HAVE_FRIDA_GLIB

static gpointer replacement_malloc_calling_malloc_and_replaced_free (
    gsize size);
static void replacement_free_doing_nothing (gpointer mem);

TESTCASE (replace_two)
{
  gpointer malloc_impl, free_impl;
  guint malloc_counter = 0, free_counter = 0;
  volatile gpointer ret;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  malloc_impl = interceptor_fixture_get_libc_malloc ();
  free_impl = interceptor_fixture_get_libc_free ();

  gum_interceptor_replace (fixture->interceptor, malloc_impl,
      replacement_malloc_calling_malloc_and_replaced_free, &malloc_counter,
      NULL);
  gum_interceptor_replace (fixture->interceptor, free_impl,
      replacement_free_doing_nothing, &free_counter, NULL);

  ret = malloc (0x42);
  g_assert_nonnull (ret);

  gum_interceptor_revert (fixture->interceptor, malloc_impl);
  gum_interceptor_revert (fixture->interceptor, free_impl);
  g_assert_cmpint (malloc_counter, ==, 1);
  g_assert_cmpint (free_counter, ==, 1);

  free (ret);
}

static gpointer
replacement_malloc_calling_malloc_and_replaced_free (gsize size)
{
  GumInvocationContext * ctx;
  guint * counter;
  gpointer result;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert_nonnull (ctx);

  counter = (guint *) gum_invocation_context_get_replacement_data (ctx);
  (*counter)++;

  result = malloc (1);
  free (result); /* should do nothing because we replace free */

#if defined (__GNUC__) && __GNUC__ >= 12
# pragma GCC diagnostic push
# pragma GCC diagnostic ignored "-Wuse-after-free"
#endif
  return result;
#if defined (__GNUC__) && __GNUC__ >= 12
# pragma GCC diagnostic pop
#endif
}

static void
replacement_free_doing_nothing (gpointer mem)
{
  GumInvocationContext * ctx;
  guint * counter;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert_nonnull (ctx);

  counter = (guint *) gum_invocation_context_get_replacement_data (ctx);
  (*counter)++;
}

#endif
#endif

TESTCASE (replace_then_attach)
{
  guint target_counter = 0;

  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
      target_function, replacement_target_function, &target_counter, NULL),
      ==, GUM_REPLACE_OK);
  interceptor_fixture_attach (fixture, 0, target_function, '>', '<');
  target_function (fixture->result);
  g_assert_cmpstr (fixture->result->str, ==, ">/|\\<");
  gum_interceptor_revert (fixture->interceptor, target_function);
}

TESTCASE (replace_keep_original)
{
  gpointer (* malloc_impl) (gsize size);
  gpointer (* original_impl) (gsize size) = NULL;
  guint counter = 0;
  volatile gpointer ret;

  if (RUNNING_ON_VALGRIND)
  {
    g_print ("<skipping, not compatible with Valgrind> ");
    return;
  }

  malloc_impl = interceptor_fixture_get_libc_malloc ();

  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor, malloc_impl,
      replacement_malloc, &counter, (void **) &original_impl),
      ==, GUM_REPLACE_OK);
  g_assert_nonnull (original_impl);
  ret = original_impl (0x42);

  /*
   * This statement is needed so the compiler doesn't move the malloc() call
   * to after revert().  We do the real assert after reverting, as failing
   * asserts with broken malloc() are quite tricky to debug. :)
   */
  g_assert_nonnull (ret);

  gum_interceptor_revert (fixture->interceptor, malloc_impl);
  g_assert_cmpint (counter, ==, 0);
  g_assert_cmphex (GPOINTER_TO_SIZE (ret), !=, 0x42);

  free (ret);
}

static gpointer
replacement_target_function (GString * str)
{
  gpointer result;

  g_string_append_c (str, '/');
  result = target_function (str);
  g_string_append_c (str, '\\');

  return result;
}

TESTCASE (i_can_has_replaceability)
{
  UnsupportedFunction * unsupported_functions;
  guint count, i;

  unsupported_functions = unsupported_function_list_new (&count);

  for (i = 0; i < count; i++)
  {
    UnsupportedFunction * func = &unsupported_functions[i];

    g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
        func->code + func->code_offset, replacement_malloc, NULL, NULL),
        ==, GUM_REPLACE_WRONG_SIGNATURE);
  }

  unsupported_function_list_free (unsupported_functions);
}

TESTCASE (already_replaced)
{
  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
        target_function, malloc, NULL, NULL), ==, GUM_REPLACE_OK);
  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
        target_function, malloc, NULL, NULL), ==, GUM_REPLACE_ALREADY_REPLACED);
  gum_interceptor_revert (fixture->interceptor, target_function);
}

#ifdef HAVE_WINDOWS

static gpointer
hit_target_function_repeatedly (gpointer data)
{
  volatile guint * n_passes = (guint *) data;
  GString * str;

  str = g_string_new ("");

  do
  {
    target_function (NULL);
  }
  while (*n_passes != 0);

  g_string_free (str, TRUE);

  return NULL;
}

#endif

typedef gpointer (* MallocFunc) (gsize size);

static gpointer
replacement_malloc (gsize size)
{
  GumInvocationContext * ctx;
  MallocFunc malloc_impl;
  guint * counter;
  gpointer a;

  ctx = gum_interceptor_get_current_invocation ();
  g_assert_nonnull (ctx);

  malloc_impl = (MallocFunc) ctx->function;
  counter = (guint *) gum_invocation_context_get_replacement_data (ctx);

  (*counter)++;

  a = malloc_impl (1);
  free (a);

  /* equivalent to the above */
  a = malloc (1);
  free (a);

  g_assert_cmpuint ((gsize) gum_invocation_context_get_nth_argument (ctx, 0),
      ==, size);

  return GSIZE_TO_POINTER (size);
}

TESTCASE (replace_then_replace_fast)
{
  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
        target_function, replacement_target_function, NULL, NULL),
      ==, GUM_REPLACE_OK);
  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function, NULL),
      ==, GUM_REPLACE_WRONG_TYPE);
  gum_interceptor_revert (fixture->interceptor, target_function);
}

TESTCASE (attach_then_replace_fast)
{
  TestCallbackListener * listener;

  listener = test_callback_listener_new ();
  listener->on_enter = (TestCallbackListenerFunc) target_function;
  listener->on_leave = (TestCallbackListenerFunc) target_function;
  listener->user_data = fixture->result;

  g_assert_cmpint (gum_interceptor_attach (fixture->interceptor,
        target_function, GUM_INVOCATION_LISTENER (listener), NULL),
      ==, GUM_ATTACH_OK);
  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function, NULL),
      ==, GUM_REPLACE_WRONG_TYPE);
  gum_interceptor_detach (fixture->interceptor,
      GUM_INVOCATION_LISTENER (listener));

  g_object_unref (listener);
}

TESTCASE (replace_fast_then_replace)
{
  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function, NULL),
      ==, GUM_REPLACE_OK);
  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
        target_function, replacement_target_function, NULL, NULL),
      ==, GUM_REPLACE_WRONG_TYPE);
  gum_interceptor_revert (fixture->interceptor, target_function);
}

TESTCASE (replace_fast_then_attach)
{
  TestCallbackListener * listener;

  listener = test_callback_listener_new ();
  listener->on_enter = (TestCallbackListenerFunc) target_function;
  listener->on_leave = (TestCallbackListenerFunc) target_function;
  listener->user_data = fixture->result;

  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function, NULL),
      ==, GUM_REPLACE_OK);

  g_assert_cmpint (gum_interceptor_attach (fixture->interceptor,
        target_function, GUM_INVOCATION_LISTENER (listener), NULL),
      ==, GUM_ATTACH_WRONG_TYPE);

  gum_interceptor_revert (fixture->interceptor, target_function);
  g_object_unref (listener);
}

TESTCASE (replace_fast_then_replace_fast)
{
  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function, NULL),
      ==, GUM_REPLACE_OK);
  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function, NULL),
      ==, GUM_REPLACE_ALREADY_REPLACED);
  gum_interceptor_revert (fixture->interceptor, target_function);
}

TESTCASE (i_can_has_replaceability_fast)
{
  UnsupportedFunction * unsupported_functions;
  guint count, i;

  unsupported_functions = unsupported_function_list_new (&count);

  for (i = 0; i != count; i++)
  {
    UnsupportedFunction * func = &unsupported_functions[i];

    g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
          func->code + func->code_offset, replacement_malloc, NULL),
        ==, GUM_REPLACE_WRONG_SIGNATURE);
  }

  unsupported_function_list_free (unsupported_functions);
}

TESTCASE (replace_one_fast)
{
  gpointer result;

  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function_fast,
        (gpointer *) &target_function_fast),
      ==, GUM_REPLACE_OK);

  result = target_function (fixture->result);

  gum_interceptor_revert (fixture->interceptor, target_function);
  g_assert_cmphex (GPOINTER_TO_SIZE (result), ==, 0);
  g_assert_cmpstr (fixture->result->str, ==, "/|\\");

  g_string_free (fixture->result, TRUE);
  fixture->result = g_string_sized_new (4096);

  result = target_function (fixture->result);
  g_assert_cmphex (GPOINTER_TO_SIZE (result), ==, 0);
  g_assert_cmpstr (fixture->result->str, ==, "|");
}

static gpointer
replacement_target_function_fast (GString * str)
{
  gpointer result;

  g_string_append_c (str, '/');
  result = target_function_fast (str);
  g_string_append_c (str, '\\');

  return result;
}

TESTCASE (fast_interceptor_performance)
{
  GTimer * timer;
  gpointer result;
  gdouble duration_default, duration_fast;

  timer = g_timer_new ();

  /* Normal Interceptor */
  g_assert_cmpint (gum_interceptor_replace (fixture->interceptor,
        target_function, replacement_target_function_fast, NULL,
        (gpointer *) &target_function_fast),
      ==, GUM_REPLACE_OK);
  g_timer_reset (timer);

  for (gsize i = 0; i != 1000000; i++)
  {
    g_string_truncate (fixture->result, 0);
    result = target_function (fixture->result);
    g_assert_cmphex (GPOINTER_TO_SIZE (result), ==, 0);
    g_assert_cmpstr (fixture->result->str, ==, "/|\\");
  }
  duration_default = g_timer_elapsed (timer, NULL);
  gum_interceptor_revert (fixture->interceptor, target_function);

  /* Fast Interceptor */
  g_assert_cmpint (gum_interceptor_replace_fast (fixture->interceptor,
        target_function, replacement_target_function_fast,
        (gpointer *) &target_function_fast),
      ==, GUM_REPLACE_OK);
  g_timer_reset (timer);
  for (gsize i = 0; i != 1000000; i++)
  {
    g_string_truncate (fixture->result, 0);
    result = target_function (fixture->result);
    g_assert_cmphex (GPOINTER_TO_SIZE (result), ==, 0);
    g_assert_cmpstr (fixture->result->str, ==, "/|\\");
  }
  duration_fast = g_timer_elapsed (timer, NULL);
  gum_interceptor_revert (fixture->interceptor, target_function);

  g_timer_destroy (timer);

  g_print ("<duration_fast=%f duration_default=%f ratio=%f> ",
      duration_fast, duration_default, duration_fast / duration_default);
}
```