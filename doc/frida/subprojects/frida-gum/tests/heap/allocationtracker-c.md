Response:
Let's break down the thought process to analyze the provided C code.

**1. Understanding the Goal:**

The request asks for a functional analysis of a C source file (`allocationtracker.c`) that's part of a larger dynamic instrumentation tool (Frida). The core goal is to understand what the code *does*, especially in relation to reverse engineering, low-level concepts, and potential user errors.

**2. Initial Code Scan (Keywords and Structure):**

My first step is to quickly scan the code for recognizable keywords and structural elements. I see:

* `#include`:  Indicates this file uses other code. `allocationtracker-fixture.c` suggests test setup.
* `TESTLIST_BEGIN`, `TESTENTRY`, `TESTCASE`:  Strongly suggests a testing framework. This means the primary function of this code is *testing* the `GumAllocationTracker`.
* `GumAllocationTracker`: This is the central object being tested. The name suggests it's responsible for tracking memory allocations.
* `gum_allocation_tracker_*`:  Numerous functions with this prefix confirm that `GumAllocationTracker` has a specific API for managing allocation tracking.
* `gum_allocation_tracker_begin`, `gum_allocation_tracker_end`:  Likely start and stop points for tracking.
* `gum_allocation_tracker_on_malloc`, `gum_allocation_tracker_on_realloc`, `gum_allocation_tracker_on_free`:  Functions to notify the tracker about allocation events.
* `gum_allocation_tracker_peek_*`: Functions to retrieve information about tracked allocations.
* `GList`:  A standard GLib linked list, used to store lists of allocations and groups.
* `GumBacktracer`: Indicates the ability to capture call stacks for allocation sites.
* `DUMMY_BLOCK_*`:  Constants used as placeholder memory addresses during testing.
* `g_assert_*`:  Assertion macros from GLib, used for verifying expected behavior during tests.
* `#ifdef HAVE_WINDOWS`: Conditional compilation, indicating platform-specific behavior.

**3. Deconstructing Test Cases:**

Knowing it's a test suite, I start analyzing individual `TESTCASE` blocks. Each test case focuses on a specific aspect of the `GumAllocationTracker`'s functionality. I try to understand:

* **What is being tested?** (e.g., the `begin` and `end` functions, the `block_count`, etc.)
* **What actions are performed?** (e.g., calling `on_malloc`, `on_free`, `realloc`, then calling `peek_*` functions)
* **What are the assertions checking?** (e.g., that the block count is correct, the total size is correct, the lists contain the expected data).

For example, in the `begin` test:

* It calls `gum_allocation_tracker_begin`.
* It calls `gum_allocation_tracker_on_malloc` *before* and *after* `begin`.
* It asserts that `peek_*` functions return 0 or NULL before `begin`, and correct values after. This tells me `begin` activates the tracking.

**4. Identifying Core Functionality:**

By analyzing the test cases, I can deduce the core functionalities of `GumAllocationTracker`:

* **Starting and Stopping Tracking:** `begin` and `end`.
* **Recording Allocation Events:**  Tracking `malloc`, `realloc`, and `free` calls.
* **Counting Allocations:** `block_count`.
* **Tracking Total Allocated Size:** `block_total_size`.
* **Listing Active Allocations:** `block_list_pointers`, `block_list_sizes`, `block_list_backtraces`.
* **Grouping Allocations by Size:** `block_groups`.
* **Filtering Allocations:** `filter_function`.
* **Handling Reallocations:**  Specific tests for different `realloc` scenarios.
* **Memory Usage Analysis:** Tests to ensure the tracker itself doesn't consume excessive memory.
* **Backtracing:**  Integration with a backtracer to record call stacks.

**5. Relating to Reverse Engineering:**

With the core functionality understood, I can connect it to reverse engineering:

* **Heap Analysis:**  The tracker allows an analyst to observe heap behavior in a running process. This is crucial for understanding memory management, identifying leaks, and finding vulnerabilities.
* **Identifying Allocation Patterns:** Grouping allocations by size can reveal common allocation patterns within an application.
* **Tracing Allocation Origins:** Backtraces pinpoint where allocations occur, helping to understand the call flow leading to memory usage.
* **Dynamic Analysis:** This tool is inherently part of dynamic analysis, as it operates on a running process.

**6. Identifying Low-Level and Kernel/Framework Aspects:**

* **Binary Level:**  The code deals with memory addresses (pointers), which is a fundamental concept at the binary level.
* **Operating System Interaction:**  Memory allocation is an OS-level function. While the Frida tool itself interacts with the OS to intercept these calls, the test code simulates these interactions. The mention of Windows-specific tests also highlights OS differences.
* **Kernel/Framework (Android):** While this specific file doesn't directly interact with the Android kernel, the larger Frida context is heavily used for Android instrumentation. The concepts of memory management and heap analysis are directly relevant to Android app security and reverse engineering.

**7. Logical Reasoning and Input/Output:**

The test cases themselves provide examples of logical reasoning and input/output. For instance, the `block_count` test:

* **Input:** A sequence of `on_malloc`, `on_realloc`, and `on_free` calls.
* **Logic:** The tracker maintains a count of active allocations.
* **Output:** The `peek_block_count` function returns the expected count after each operation.

I can create my own hypothetical scenarios based on the code's behavior.

**8. Identifying Potential User Errors:**

By looking at the API and how it's used in the tests, I can identify potential misuse:

* **Forgetting `begin`:** Calling `on_malloc` before `begin` won't track allocations.
* **Incorrectly Matching `realloc`:**  Providing an unknown address to `realloc` might lead to unexpected behavior (as tested).
* **Not Calling `end`:**  Leaving the tracker active might consume resources unnecessarily.
* **Misinterpreting `peek_*` results:** Users need to understand that `peek_*` provides a snapshot in time.

**9. Tracing User Operations:**

To understand how a user might reach this code:

1. **User wants to analyze memory allocation in a target process.**
2. **User uses Frida to attach to the process.**
3. **User utilizes Frida's API (likely in Python or JavaScript) to interact with `GumAllocationTracker`.**  This might involve creating a `GumAllocationTracker` instance, setting up a backtracer, and beginning tracking.
4. **Frida's instrumentation engine injects code into the target process.** This injected code intercepts `malloc`, `realloc`, and `free` calls.
5. **The intercepted calls trigger the corresponding `gum_allocation_tracker_on_*` functions in the injected Frida code.** This is where the logic of `allocationtracker.c` comes into play.
6. **The user then uses Frida's API to query the tracker's state** (using functions like `peek_block_count`, `peek_block_list`, etc.).

This step-by-step breakdown helps connect the C code to the higher-level user experience of using Frida.

By following these steps, I can systematically analyze the C code and generate a comprehensive explanation covering its functionality, relation to reverse engineering, low-level details, logical reasoning, potential user errors, and the user journey.
好的，让我们详细分析一下 `frida/subprojects/frida-gum/tests/heap/allocationtracker.c` 这个文件。

**文件功能总览**

这个 C 文件是 Frida 框架中 `frida-gum` 模块下 `heap` 组件的一个测试文件，主要用于测试 `GumAllocationTracker` 这个类的功能。 `GumAllocationTracker` 的核心功能是**动态追踪目标进程的内存分配和释放行为**。

具体来说，这个测试文件涵盖了 `GumAllocationTracker` 的以下功能：

* **启动和停止追踪:** 测试 `gum_allocation_tracker_begin` 和 `gum_allocation_tracker_end` 函数，验证它们是否正确地开始和结束内存分配追踪。
* **统计分配块的数量和总大小:** 测试 `gum_allocation_tracker_peek_block_count` 和 `gum_allocation_tracker_peek_block_total_size` 函数，验证它们能否正确获取当前已分配内存块的数量和总大小。
* **获取分配块的列表:** 测试 `gum_allocation_tracker_peek_block_list` 函数，验证它能否返回当前所有已分配内存块的指针列表，并能获取每个块的大小。
* **获取分配块的回溯信息:** 测试 `gum_allocation_tracker_peek_block_backtraces` 函数，验证它能否获取内存分配时的调用堆栈信息（backtrace）。
* **按大小分组统计分配块:** 测试 `gum_allocation_tracker_peek_block_groups` 函数，验证它能否将分配的内存块按大小进行分组统计，包括当前存活数量、峰值存活数量和总峰值数量。
* **过滤追踪的分配:** 测试 `gum_allocation_tracker_set_filter_function` 函数，验证它能否设置一个过滤函数，只追踪满足特定条件的内存分配。
* **处理 `realloc` 操作:** 测试 `gum_allocation_tracker_on_realloc` 函数在不同场景下的行为，包括新分配、未知块的重新分配和大小为零的重新分配，并验证是否能正确记录 `realloc` 操作的回溯信息。
* **内存使用情况:** 测试在启用和禁用回溯功能时，`GumAllocationTracker` 自身的内存使用情况，确保其内存占用在合理范围内。
* **与 Windows 平台特性的互操作性 (HAVE_WINDOWS 宏定义下):**
    * 测试 `backtracer_gtype_interop`: 验证回溯功能与 GType 系统的互操作性。
    * 测试 `avoid_heap_priv` 和 `avoid_heap_public`:  验证 `GumAllocationTracker` 内部操作是否避免了不必要的堆访问。
    * 测试 `hashtable_resize` 和 `hashtable_life`: 验证内部哈希表在调整大小和生命周期中的行为。

**与逆向方法的关系及举例说明**

`GumAllocationTracker` 是一个强大的逆向分析工具，因为它允许在运行时动态地观察目标程序的内存分配行为。这对于理解程序的内部工作原理、发现内存泄漏、定位漏洞至关重要。

**举例说明:**

1. **内存泄漏检测:**  逆向工程师可以使用 `GumAllocationTracker` 追踪程序运行过程中不断增加的内存分配，但没有对应的释放操作。通过 `gum_allocation_tracker_peek_block_list` 可以查看所有已分配的内存块，结合 `gum_allocation_tracker_peek_block_backtraces` 获取分配时的调用栈，可以定位到内存泄漏发生的代码位置。

   * **假设输入:**  运行一个存在内存泄漏的目标程序，并使用 Frida 脚本启动 `GumAllocationTracker` 进行追踪。
   * **输出:**  通过 `gum_allocation_tracker_peek_block_list` 观察到内存块的数量持续增加。 通过 `gum_allocation_tracker_peek_block_backtraces` 可以看到大量相同调用栈的内存分配，指向泄漏的代码。

2. **理解对象生命周期:**  通过追踪特定类型对象的分配和释放，可以理解这些对象在程序中的生命周期。例如，追踪某个类实例的分配，并观察其何时被释放，有助于理解该类的作用范围和使用方式。

   * **假设输入:**  目标程序中有一个关键的类 `MyObject`。 使用 Frida 脚本，结合 `gum_allocation_tracker_set_filter_function`，只追踪 `MyObject` 大小的内存分配。
   * **输出:**  可以观察到 `MyObject` 实例何时被创建（通过 `gum_allocation_tracker_on_malloc`），何时被释放（通过 `gum_allocation_tracker_on_free`），以及在哪些代码路径上进行分配和释放。

3. **漏洞分析:**  某些类型的漏洞，如堆溢出，往往与不正确的内存分配和释放有关。通过 `GumAllocationTracker`，可以观察到异常的内存分配行为，例如分配了过大的内存块，或者释放了不应该释放的内存。

   * **假设输入:**  运行一个存在堆溢出漏洞的程序，并使用 `GumAllocationTracker` 监控内存分配。
   * **输出:**  可能会观察到在溢出发生前后，某些内存块的大小异常增大，或者在溢出发生后，访问了属于其他内存块的地址。

**涉及二进制底层、Linux/Android 内核及框架的知识**

`GumAllocationTracker` 的实现和测试涉及到以下底层知识：

* **二进制底层:**
    * **内存地址:**  `GumAllocationTracker` 追踪的是内存块的地址 (`DUMMY_BLOCK_A`, `DUMMY_BLOCK_B` 等是测试中使用的虚拟地址)。
    * **内存大小:** 追踪内存块的大小，这直接对应于二进制数据占用的字节数。
    * **指针操作:** 所有的内存操作都基于指针。
    * **调用堆栈 (Backtrace):**  获取调用堆栈需要访问底层的寄存器和栈帧信息。

* **Linux/Android 内核:**
    * **内存管理:**  `malloc`, `realloc`, `free` 等函数是操作系统提供的内存管理接口。Frida 需要 hook 这些系统调用或库函数才能实现追踪。
    * **进程内存空间:**  理解进程的内存布局（堆、栈、代码段、数据段）是进行内存分析的基础。
    * **系统调用:** Frida 的工作原理依赖于操作系统提供的进程间通信和代码注入机制，这些通常涉及到系统调用。
    * **Android 框架 (在 Android 平台上):** 在 Android 上，`GumAllocationTracker` 可以用于分析 Dalvik/ART 虚拟机的堆分配情况，这需要理解 Android 框架的内存管理机制。

**逻辑推理及假设输入与输出**

很多测试用例都体现了逻辑推理。例如 `block_count` 这个测试用例：

* **假设输入:**  依次调用 `on_malloc`, `on_malloc`, `on_realloc`, `on_free`, `on_free`。
* **逻辑推理:**  `on_malloc` 增加计数器，`on_realloc` 不改变计数器（只是修改了已存在的块），`on_free` 减少计数器。
* **预期输出:**  通过 `gum_allocation_tracker_peek_block_count` 观察到的计数器值应依次为 1, 2, 2, 1, 0。

再如 `block_groups` 这个测试用例：

* **假设输入:**  分配多个大小相同的块，释放其中一些，然后分配不同大小的块，并进行重新分配。
* **逻辑推理:**  `GumAllocationTracker` 会根据分配的内存大小对块进行分组，并统计每个组的当前存活数量、峰值存活数量和总峰值数量。
* **预期输出:**  `gum_allocation_tracker_peek_block_groups` 返回的列表中，不同大小的组的统计信息应与输入的操作对应。例如，分配了 3 个大小为 42 的块，然后释放一个，再分配一个，那么大小为 42 的组的 `alive_now` 应该是 2，`alive_peak` 应该是 3，`total_peak` 应该是 4。

**涉及用户或编程常见的使用错误及举例说明**

* **忘记调用 `gum_allocation_tracker_begin`:** 如果在调用 `gum_allocation_tracker_begin` 之前调用 `gum_allocation_tracker_on_malloc` 等函数，追踪器不会记录任何信息。测试用例 `begin` 就演示了这一点。

   * **错误代码:**
     ```c
     GumAllocationTracker *t = fixture->tracker;
     gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 123); // 错误：在 begin 之前调用
     gum_allocation_tracker_begin (t);
     ```
   * **预期结果:**  `gum_allocation_tracker_peek_block_count` 和 `gum_allocation_tracker_peek_block_total_size` 仍然为 0，因为这次分配没有被追踪到。

* **错误地使用 `realloc` 追踪:**  如果 `realloc` 的旧地址是一个未被追踪的地址，`GumAllocationTracker` 不会将其视为一个已存在的块的重新分配。测试用例 `realloc_unknown_block` 就说明了这一点。

   * **错误代码:**
     ```c
     GumAllocationTracker *t = fixture->tracker;
     gum_allocation_tracker_begin(t);
     gum_allocation_tracker_on_realloc(t, DUMMY_BLOCK_A, DUMMY_BLOCK_A, 1337); // 错误：DUMMY_BLOCK_A 没有被分配过
     ```
   * **预期结果:** `gum_allocation_tracker_peek_block_count` 仍然为 0。

* **不匹配的 `begin` 和 `end`:**  如果只调用了 `begin` 而没有调用 `end`，追踪器会一直记录内存分配，可能会消耗额外的资源。虽然这在功能上不是错误，但可能不是用户的预期行为。

**用户操作是如何一步步到达这里的，作为调试线索**

一个开发者或逆向工程师可能会按照以下步骤使用 Frida 并涉及到 `GumAllocationTracker` 的代码：

1. **安装 Frida:** 用户首先需要在他们的系统上安装 Frida。
2. **编写 Frida 脚本:** 用户会编写 JavaScript 或 Python 脚本来使用 Frida 的 API。
3. **Attach 到目标进程:**  在脚本中，用户会使用 Frida 的 API (例如 `frida.attach()`) 连接到他们想要分析的目标进程。
4. **获取 `Gum` 句柄:**  用户需要获取 `Gum` 模块的句柄，这是 Frida 内部 Gum 引擎的接口。
5. **创建 `GumAllocationTracker` 实例:**  通过 `Gum.AllocationTracker()` 或类似的 API 创建一个 `GumAllocationTracker` 的实例。
6. **配置追踪器 (可选):** 用户可能会设置过滤器 (`tracker.setFilterFunction()`) 或配置回溯功能。
7. **启动追踪:**  调用 `tracker.begin()` 开始追踪内存分配。这最终会调用到 C 代码中的 `gum_allocation_tracker_begin` 函数。
8. **执行目标程序:**  让目标程序运行，执行会触发内存分配和释放操作的代码。
9. **Frida 拦截内存操作:** 当目标程序调用 `malloc`, `realloc`, `free` 等函数时，Frida 的 hook 机制会拦截这些调用，并通知 `GumAllocationTracker`。这会触发 C 代码中的 `gum_allocation_tracker_on_malloc`, `gum_allocation_tracker_on_realloc`, `gum_allocation_tracker_on_free` 等函数。
10. **获取追踪结果:** 用户在脚本中调用 `tracker.getBlocks()`, `tracker.getBlockCount()`, `tracker.getBlockGroups()` 等方法来获取追踪到的内存分配信息。这些方法最终会调用到 C 代码中的 `gum_allocation_tracker_peek_block_list`, `gum_allocation_tracker_peek_block_count`, `gum_allocation_tracker_peek_block_groups` 等函数。
11. **停止追踪:** 用户可以调用 `tracker.end()` 停止追踪。这会调用到 C 代码中的 `gum_allocation_tracker_end` 函数。
12. **分析结果:** 用户分析获取到的内存分配信息，例如查找内存泄漏、理解对象生命周期等。

**调试线索:**

当用户在使用 Frida 的内存追踪功能时遇到问题，例如追踪不到预期的内存分配，或者获取到的信息不正确，他们可能会查看 Frida 的日志输出，或者使用调试器来检查 Frida 脚本的执行流程。如果问题涉及到 `GumAllocationTracker` 的行为，他们可能需要查看 `frida-gum` 的源代码，包括 `allocationtracker.c`，来理解追踪器的工作原理，并找到问题的原因。

例如，如果用户发现设置了过滤器但仍然追踪到了不应该追踪的内存分配，他们可能会查看 `filter_function` 的测试用例，了解过滤函数的预期行为，并检查他们自己的过滤函数是否正确。

总而言之，`allocationtracker.c` 是 Frida 框架中一个非常重要的测试文件，它详细验证了 `GumAllocationTracker` 的各项功能，而 `GumAllocationTracker` 本身是进行动态逆向分析和理解程序内存行为的关键组件。理解这个文件的内容有助于更深入地理解 Frida 的工作原理以及如何有效地使用它进行安全研究和漏洞分析。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/heap/allocationtracker.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "allocationtracker-fixture.c"

TESTLIST_BEGIN (allocation_tracker)
  TESTENTRY (begin)
  TESTENTRY (end)

  TESTENTRY (block_count)
  TESTENTRY (block_total_size)
  TESTENTRY (block_list_pointers)
  TESTENTRY (block_list_sizes)
  TESTENTRY (block_list_backtraces)
  TESTENTRY (block_groups)

  TESTENTRY (filter_function)

  TESTENTRY (realloc_new_block)
  TESTENTRY (realloc_unknown_block)
  TESTENTRY (realloc_zero_size)
  TESTENTRY (realloc_backtrace)

  TESTENTRY (memory_usage_without_backtracer_should_be_sensible)
  TESTENTRY (memory_usage_with_backtracer_should_be_sensible)

#ifdef HAVE_WINDOWS
  TESTENTRY (backtracer_gtype_interop)

  TESTENTRY (avoid_heap_priv)
  TESTENTRY (avoid_heap_public)
  TESTENTRY (hashtable_resize)
  TESTENTRY (hashtable_life)
#endif
TESTLIST_END ()

TESTCASE (begin)
{
  GumAllocationTracker * t = fixture->tracker;
  GList * blocks, * groups;

  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 0);
  g_assert_null (gum_allocation_tracker_peek_block_list (t));
  g_assert_null (gum_allocation_tracker_peek_block_groups (t));
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 123);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 0);
  g_assert_null (gum_allocation_tracker_peek_block_list (t));
  g_assert_null (gum_allocation_tracker_peek_block_groups (t));

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 321);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 321);

  blocks = gum_allocation_tracker_peek_block_list (t);
  g_assert_cmpuint (g_list_length (blocks), ==, 1);
  gum_allocation_block_list_free (blocks);

  groups = gum_allocation_tracker_peek_block_groups (t);
  g_assert_cmpuint (g_list_length (groups), ==, 1);
  gum_allocation_group_list_free (groups);
}

TESTCASE (end)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 321);
  gum_allocation_tracker_end (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 313);

  g_assert_null (gum_allocation_tracker_peek_block_list (t));
  g_assert_null (gum_allocation_tracker_peek_block_groups (t));

  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 0);
}

TESTCASE (block_count)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 42);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 1337);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 2);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, DUMMY_BLOCK_A, 84);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 2);

  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_A);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);

  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_B);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
}

TESTCASE (block_total_size)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);

  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 0);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 31);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 31);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 19);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 50);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, DUMMY_BLOCK_A, 81);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 100);

  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_A);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 19);

  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_B);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_total_size (t), ==, 0);
}

TESTCASE (block_list_pointers)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 42);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 24);

  {
    GList * blocks, * cur;

    blocks = gum_allocation_tracker_peek_block_list (t);
    g_assert_cmpuint (g_list_length (blocks), ==, 2);

    for (cur = blocks; cur != NULL; cur = cur->next)
    {
      GumAllocationBlock * block = cur->data;
      g_assert_true (block->address == DUMMY_BLOCK_A ||
          block->address == DUMMY_BLOCK_B);
    }

    gum_allocation_block_list_free (blocks);
  }

  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_A);

  {
    GList * blocks;
    GumAllocationBlock * block;

    blocks = gum_allocation_tracker_peek_block_list (t);
    g_assert_cmpuint (g_list_length (blocks), ==, 1);

    block = blocks->data;
    g_assert_true (block->address == DUMMY_BLOCK_B);

    gum_allocation_block_list_free (blocks);
  }

  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_B);
}

TESTCASE (block_list_sizes)
{
  GumAllocationTracker * t = fixture->tracker;
  GList * blocks, * cur;

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 42);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 24);

  blocks = gum_allocation_tracker_peek_block_list (t);
  g_assert_cmpuint (g_list_length (blocks), ==, 2);

  for (cur = blocks; cur != NULL; cur = cur->next)
  {
    GumAllocationBlock * block = cur->data;

    if (block->address == DUMMY_BLOCK_A)
      g_assert_cmpuint (block->size, ==, 42);
    else if (block->address == DUMMY_BLOCK_B)
      g_assert_cmpuint (block->size, ==, 24);
    else
      g_assert_not_reached ();
  }

  gum_allocation_block_list_free (blocks);
}

TESTCASE (block_list_backtraces)
{
  GumBacktracer * backtracer;
  GumAllocationTracker * t;
  GList * blocks;
  GumAllocationBlock * block;

  backtracer = gum_fake_backtracer_new (dummy_return_addresses_a,
      G_N_ELEMENTS (dummy_return_addresses_a));
  t = gum_allocation_tracker_new_with_backtracer (backtracer);

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 42);

  blocks = gum_allocation_tracker_peek_block_list (t);
  g_assert_cmpuint (g_list_length (blocks), ==, 1);

  block = (GumAllocationBlock *) blocks->data;
  g_assert_true (block->address == DUMMY_BLOCK_A);

  g_assert_cmpuint (block->return_addresses.len, ==, 2);
  g_assert_true (block->return_addresses.items[0] ==
      dummy_return_addresses_a[0]);
  g_assert_true (block->return_addresses.items[1] ==
      dummy_return_addresses_a[1]);

  gum_allocation_block_list_free (blocks);

  g_object_unref (t);
  g_object_unref (backtracer);
}

TESTCASE (block_groups)
{
  GumAllocationTracker * t = fixture->tracker;
  GList * groups, * cur;

  gum_allocation_tracker_begin (t);

  groups = gum_allocation_tracker_peek_block_groups (t);
  g_assert_cmpuint (g_list_length (groups), ==, 0);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 42);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 42);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_C, 42);
  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_C);
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_C, 42);
  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_C);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_D, 1337);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, DUMMY_BLOCK_E, 1000);
  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_E);

  groups = gum_allocation_tracker_peek_block_groups (t);
  g_assert_cmpuint (g_list_length (groups), ==, 3);

  for (cur = groups; cur != NULL; cur = cur->next)
  {
    GumAllocationGroup * group = (GumAllocationGroup *) cur->data;

    if (group->size == 42)
    {
      g_assert_cmpuint (group->alive_now, ==, 1);
      g_assert_cmpuint (group->alive_peak, ==, 3);
      g_assert_cmpuint (group->total_peak, ==, 4);
    }
    else if (group->size == 1000)
    {
      g_assert_cmpuint (group->alive_now, ==, 0);
      g_assert_cmpuint (group->alive_peak, ==, 1);
      g_assert_cmpuint (group->total_peak, ==, 1);
    }
    else if (group->size == 1337)
    {
      g_assert_cmpuint (group->alive_now, ==, 1);
      g_assert_cmpuint (group->alive_peak, ==, 1);
      g_assert_cmpuint (group->total_peak, ==, 1);
    }
    else
      g_assert_not_reached ();
  }

  gum_allocation_group_list_free (groups);
}

TESTCASE (filter_function)
{
  GumBacktracer * backtracer;
  GumAllocationTracker * t;
  guint counter = 0;

  backtracer = gum_fake_backtracer_new (dummy_return_addresses_a,
      G_N_ELEMENTS (dummy_return_addresses_a));
  t = gum_allocation_tracker_new_with_backtracer (backtracer);

  gum_allocation_tracker_set_filter_function (t, filter_cb, &counter);

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 1337);
  g_assert_cmpuint (counter, ==, 1);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_B, 42);
  g_assert_cmpuint (counter, ==, 2);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 2);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_B, DUMMY_BLOCK_C, 84);
  g_assert_cmpuint (counter, ==, 2);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 2);

  g_object_unref (t);
  g_object_unref (backtracer);
}

static gboolean
filter_cb (GumAllocationTracker * tracker,
           gpointer address,
           guint size,
           gpointer user_data)
{
  guint * counter = (guint *) user_data;

  (*counter)++;

  return (size == 1337);
}

TESTCASE (realloc_new_block)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_realloc (t, NULL, DUMMY_BLOCK_A, 1337);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);
}

TESTCASE (realloc_unknown_block)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, DUMMY_BLOCK_A, 1337);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
}

TESTCASE (realloc_zero_size)
{
  GumAllocationTracker * t = fixture->tracker;

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_realloc (t, NULL, DUMMY_BLOCK_A, 1337);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 1);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, NULL, 0);
  g_assert_cmpuint (gum_allocation_tracker_peek_block_count (t), ==, 0);
}

TESTCASE (realloc_backtrace)
{
  GumBacktracer * backtracer;
  GumAllocationTracker * t;
  GList * blocks_before, * blocks_after;
  GumReturnAddressArray * addrs_before, * addrs_after;

  backtracer = gum_fake_backtracer_new (dummy_return_addresses_a,
      G_N_ELEMENTS (dummy_return_addresses_a));
  t = gum_allocation_tracker_new_with_backtracer (backtracer);

  gum_allocation_tracker_begin (t);

  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 42);

  blocks_before = gum_allocation_tracker_peek_block_list (t);
  addrs_before = &GUM_ALLOCATION_BLOCK (blocks_before->data)->return_addresses;

  GUM_FAKE_BACKTRACER (backtracer)->ret_addrs = dummy_return_addresses_b;
  GUM_FAKE_BACKTRACER (backtracer)->num_ret_addrs =
      G_N_ELEMENTS (dummy_return_addresses_b);

  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_A, DUMMY_BLOCK_A, 84);

  blocks_after = gum_allocation_tracker_peek_block_list (t);
  addrs_after = &GUM_ALLOCATION_BLOCK (blocks_after->data)->return_addresses;

  g_assert_true (gum_return_address_array_is_equal (addrs_before, addrs_after));

  gum_allocation_block_list_free (blocks_before);
  gum_allocation_block_list_free (blocks_after);

  g_object_unref (t);
  g_object_unref (backtracer);
}

TESTCASE (memory_usage_without_backtracer_should_be_sensible)
{
  GumAllocationTracker * t = fixture->tracker;
  const guint num_allocations = 10000;
  guint bytes_before, bytes_after, i, bytes_per_allocation;

  t = gum_allocation_tracker_new ();
  gum_allocation_tracker_begin (t);

  bytes_before = gum_peek_private_memory_usage ();
  for (i = 0; i != num_allocations; i++)
    gum_allocation_tracker_on_malloc (t, GUINT_TO_POINTER (0x50000 + (i * 64)),
        64);
  bytes_after = gum_peek_private_memory_usage ();

  bytes_per_allocation = (bytes_after - bytes_before) / num_allocations;
  g_assert_cmpuint (bytes_per_allocation, <=, 50);

  g_object_unref (t);
}

TESTCASE (memory_usage_with_backtracer_should_be_sensible)
{
  GumBacktracer * backtracer;
  GumAllocationTracker * t;
  const guint num_allocations = 10;
  guint bytes_before, bytes_after, i, bytes_per_allocation;

  backtracer = gum_fake_backtracer_new (dummy_return_addresses_a,
      G_N_ELEMENTS (dummy_return_addresses_a));
  t = gum_allocation_tracker_new_with_backtracer (backtracer);
  gum_allocation_tracker_begin (t);

  bytes_before = gum_peek_private_memory_usage ();
  for (i = 0; i != num_allocations; i++)
    gum_allocation_tracker_on_malloc (t, GUINT_TO_POINTER (0x50000 + (i * 64)),
        64);
  bytes_after = gum_peek_private_memory_usage ();

  bytes_per_allocation = (bytes_after - bytes_before) / num_allocations;
  g_assert_cmpuint (bytes_per_allocation, <=, 128);

  g_object_unref (backtracer);
  g_object_unref (t);
}

#ifdef HAVE_WINDOWS

TESTCASE (backtracer_gtype_interop)
{
  GumBacktracer * backtracer;
  GumAllocationTracker * tracker;
  GumAllocatorProbe * probe;
  ZooZebra * zebra;

  backtracer = gum_backtracer_make_accurate ();
  tracker = gum_allocation_tracker_new_with_backtracer (backtracer);
  gum_allocation_tracker_begin (tracker);

  probe = gum_allocator_probe_new ();
  g_object_set (probe, "allocation-tracker", tracker, NULL);
  gum_allocator_probe_attach (probe);

  zebra = g_object_new (ZOO_TYPE_ZEBRA, NULL);
  g_object_unref (zebra);

  g_object_unref (probe);
  g_object_unref (tracker);
  g_object_unref (backtracer);
}

TESTCASE (avoid_heap_priv)
{
  GumAllocationTracker * t = fixture->tracker;
  GumSampler * heap_access_counter;

  gum_allocation_tracker_begin (t);

  heap_access_counter = heap_access_counter_new ();
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 321);
  gum_allocation_tracker_on_free (t, DUMMY_BLOCK_A);
  gum_allocation_tracker_on_realloc (t, NULL, DUMMY_BLOCK_B, 10);
  gum_allocation_tracker_on_realloc (t, DUMMY_BLOCK_B, DUMMY_BLOCK_C, 20);
  g_assert_cmpint (gum_sampler_sample (heap_access_counter), ==, 0);
  g_object_unref (heap_access_counter);

  gum_allocation_tracker_end (t);
}

TESTCASE (avoid_heap_public)
{
  GumAllocationTracker * t = fixture->tracker;
  GumSampler * heap_access_counter;
  GList * blocks, * groups;

  gum_allocation_tracker_begin (t);

  heap_access_counter = heap_access_counter_new ();
  gum_allocation_tracker_on_malloc (t, DUMMY_BLOCK_A, 321);
  gum_allocation_tracker_on_realloc (t, NULL, DUMMY_BLOCK_B, 10);
  blocks = gum_allocation_tracker_peek_block_list (t);
  gum_allocation_block_list_free (blocks);
  groups = gum_allocation_tracker_peek_block_groups (t);
  gum_allocation_group_list_free (groups);
  g_assert_cmpint (gum_sampler_sample (heap_access_counter), ==, 0);
  g_object_unref (heap_access_counter);

  gum_allocation_tracker_end (t);
}

TESTCASE (hashtable_resize)
{
  GumAllocationTracker * t = fixture->tracker;
  GumSampler * heap_access_counter;
  guint i;

  gum_allocation_tracker_begin (t);

  heap_access_counter = heap_access_counter_new ();
  for (i = 0; i < 100; i++)
  {
    gum_allocation_tracker_on_malloc (t, GUINT_TO_POINTER (0xf00d + i), i + 1);
    g_assert_cmpint (gum_sampler_sample (heap_access_counter), ==, 0);
  }
  g_object_unref (heap_access_counter);

  gum_allocation_tracker_end (t);
}

TESTCASE (hashtable_life)
{
  GumSampler * heap_access_counter;
  GHashTable * hashtable;
  guint i;

  heap_access_counter = heap_access_counter_new ();
  hashtable = g_hash_table_new (NULL, NULL);
  for (i = 0; i < 10000; i++)
  {
    g_hash_table_insert (hashtable, GUINT_TO_POINTER (i + 1),
        GUINT_TO_POINTER (2 * i));
  }
  g_hash_table_unref (hashtable);
  g_assert_cmpint (gum_sampler_sample (heap_access_counter), ==, 0);

  g_object_unref (heap_access_counter);
}

#endif /* HAVE_WINDOWS */

"""

```