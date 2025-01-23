Response:
Let's break down the thought process for analyzing this C code and generating the detailed explanation.

1. **Understand the Goal:** The request asks for a comprehensive analysis of the `gumsanitychecker.c` file, specifically focusing on its functionality, relationship to reverse engineering, interaction with the OS and kernel, logical reasoning, potential user errors, and how a user might reach this code.

2. **Initial Skim for High-Level Understanding:**  The first step is a quick read-through of the code to grasp its overall purpose. Keywords like "sanity checker," "leaks," "backtraces," "bounds," and function names like `gum_sanity_checker_new`, `gum_sanity_checker_run`, `gum_sanity_checker_begin`, and `gum_sanity_checker_end` immediately suggest it's a debugging and memory checking tool. The inclusion of "Gum" in the names indicates it's part of a larger Frida component.

3. **Identify Key Data Structures and Components:**  Pay attention to the `struct _GumSanityCheckerPrivate`. This reveals the core components the checker uses:
    * `GumHeapApiList`:  Interaction with the target process's heap.
    * `GumSanityOutputFunc`:  How the checker reports issues.
    * `GumInstanceTracker`: Tracking object instances for leaks.
    * `GumAllocatorProbe` and `GumAllocationTracker`: Monitoring memory allocations and deallocations for leaks.
    * `GumBoundsChecker`: Detecting out-of-bounds memory access.
    * `GumBacktracer`: Recording call stacks for debugging.

4. **Analyze the Public Interface:** Focus on the functions that start with `gum_sanity_checker_`. These represent the API users interact with:
    * `gum_sanity_checker_new`: Creating a checker instance.
    * `gum_sanity_checker_run`:  The main function to execute checks.
    * `gum_sanity_checker_begin` and `gum_sanity_checker_end`:  Controlling the start and end of specific checks (instance leaks, block leaks, bounds).
    * `gum_sanity_checker_enable_backtraces_for_blocks_of_all_sizes` and `gum_sanity_checker_enable_backtraces_for_blocks_of_size`: Configuring backtrace collection.
    * `gum_sanity_checker_set_front_alignment_granularity`:  Setting alignment requirements for memory.

5. **Deconstruct `gum_sanity_checker_run`:** This function is central to understanding the workflow. It reveals the three main checks performed sequentially: instance leaks, block leaks, and bounds checking. The initial call to `func(user_data)` *without* instrumentation is important; it suggests a warm-up phase to avoid reporting initial static allocations as leaks.

6. **Examine `gum_sanity_checker_begin` and `gum_sanity_checker_end`:** These functions handle the setup and teardown for each type of check. Notice how they attach and detach probes and trackers, and how they use flags to determine which checks to perform.

7. **Analyze the Private Helper Functions:** Look at the static functions. These implement the core logic:
    * `gum_sanity_checker_filter_out_gparam`:  Filtering out specific types during instance leak detection.
    * `gum_sanity_checker_filter_backtrace_block_size`:  Filtering allocations for backtracing based on size.
    * `gum_sanity_checker_print_*`:  Functions for formatting and outputting the results of the checks.
    * `gum_sanity_checker_count_leaks_by_type_name`:  Aggregating leak information.
    * `gum_sanity_checker_details_from_instance`:  Extracting details about leaked instances.
    * `gum_sanity_checker_compare_*`:  Comparison functions for sorting leak reports.

8. **Connect to Reverse Engineering Concepts:**  Think about how the checker aids reverse engineering:
    * **Leak Detection:**  Identifying memory leaks is crucial for understanding object lifecycles and potential vulnerabilities.
    * **Bounds Checking:**  Detecting buffer overflows is a classic reverse engineering task for vulnerability analysis.
    * **Backtraces:** Essential for pinpointing the origin of errors and understanding code execution flow.
    * **Dynamic Analysis:** The checker operates during program execution, making it a dynamic analysis tool.

9. **Identify OS/Kernel/Framework Interactions:**
    * **Heap APIs:** The checker directly interacts with the target process's heap allocation functions (like `malloc`, `free`). This requires knowledge of the underlying OS's memory management.
    * **Backtracing:** Backtracing relies on OS-specific mechanisms for accessing stack information.
    * **Process Instrumentation:** Frida itself is a dynamic instrumentation framework that interacts deeply with the target process.
    * **GObject System:** The code uses GObject, a common object system in Linux and some Android components.

10. **Consider Logical Reasoning and Assumptions:** Look for places where the code makes assumptions or performs logical deductions:
    * The sequential execution of checks in `gum_sanity_checker_run`.
    * The filtering logic for backtraces and instance tracking.
    * The comparison logic for sorting leak reports.

11. **Brainstorm Potential User Errors:**  Think about how a developer using this tool might misuse it or encounter issues:
    * Incorrectly interpreting leak reports.
    * Not understanding the limitations of the checker.
    * Using incorrect flags or configurations.

12. **Trace User Operations to the Code:**  Imagine the steps a user would take to trigger the functionality in this file:
    * Writing a Frida script.
    * Creating a `GumSanityChecker` instance.
    * Calling `gum_sanity_checker_run` with a function to execute.
    * Observing the output from the checker.

13. **Structure the Explanation:** Organize the findings into logical sections:
    * Overview of functionality.
    * Connections to reverse engineering.
    * OS/kernel/framework interactions.
    * Logical reasoning.
    * User errors.
    * User journey/debugging.

14. **Refine and Elaborate:** Go back through each section and add specific details, code examples (even if conceptual), and explanations of *why* certain aspects are important. Use clear and concise language. For example, instead of just saying "it checks for leaks," explain the difference between instance leaks and block leaks.

15. **Review and Edit:**  Read through the entire explanation to ensure accuracy, clarity, and completeness. Correct any errors or omissions. Make sure the examples are relevant and easy to understand.

By following these steps, systematically analyzing the code, and connecting it to relevant concepts, a comprehensive and accurate explanation like the example provided can be generated.
好的，让我们详细分析一下 `gumsanitychecker.c` 文件的功能和它在 Frida 动态插桩工具中的作用。

**功能概览**

`gumsanitychecker.c` 文件实现了 Frida Gum 库中的一个核心组件：**健全性检查器 (Sanity Checker)**。它的主要目的是在目标进程运行时，通过动态插桩技术，来检测和报告各种潜在的内存错误和资源泄漏问题。  更具体地说，它主要关注以下几点：

1. **实例泄漏检测 (Instance Leaks):** 跟踪由特定类型创建的对象实例，并在检查结束时报告那些仍然存活（未被释放）的实例，即内存泄漏。
2. **内存块泄漏检测 (Block Leaks):** 跟踪通过 `malloc` 等堆分配函数分配的内存块，并在检查结束时报告那些仍然被分配但未被释放的内存块。
3. **边界检查 (Bounds Checking):**  检测对已分配内存块的越界访问（读或写）。

**与逆向方法的关联和举例说明**

健全性检查器是逆向工程中非常有用的工具，尤其是在进行动态分析时。它可以帮助逆向工程师发现目标程序中潜在的缺陷和漏洞，从而更好地理解程序的行为。

* **内存泄漏分析:**
    * **逆向场景:**  你正在逆向一个程序，怀疑它存在内存泄漏，导致长时间运行后性能下降或者崩溃。
    * **使用健全性检查器:** 你可以使用 Frida 加载这个程序，并使用 `gum_sanity_checker_run` 函数来运行健全性检查。
    * **举例说明:**
        ```javascript
        // Frida 脚本
        const sanity = new GumSanityChecker();

        function runTarget() {
          // 这里放置调用目标程序中可能导致内存泄漏的代码
          // 例如，调用某个函数多次
        }

        sanity.run(runTarget);
        ```
        健全性检查器会报告泄漏的实例类型和内存块大小，以及分配这些内存的位置（通过回溯信息），帮助你定位泄漏的根源。例如，它可能会报告 "X类型的对象泄漏了 10 个，总大小为 Y 字节"，并给出这些对象分配时的调用栈。

* **越界访问检测:**
    * **逆向场景:** 你怀疑程序中存在缓冲区溢出或者其他类型的内存越界访问漏洞。
    * **使用健全性检查器:**  启用边界检查后，任何越界读写操作都会被检测到并报告。
    * **举例说明:**
        ```javascript
        // Frida 脚本
        const sanity = new GumSanityChecker();
        sanity.begin(Gum.SanityCheck.BOUNDS);

        // 触发可能发生越界访问的代码
        // 例如，向一个固定大小的缓冲区写入超过其容量的数据

        sanity.end();
        ```
        健全性检查器会报告发生越界访问的地址、访问类型（读或写）以及当时的调用栈，这对于漏洞分析至关重要。

**涉及的二进制底层、Linux/Android 内核及框架知识**

`gumsanitychecker.c` 的实现深度依赖于对二进制底层、操作系统内核和相关框架的理解：

* **二进制底层:**
    * **堆内存管理:**  健全性检查器需要理解目标进程的堆内存管理机制，才能有效地跟踪内存分配和释放。这涉及到对 `malloc`, `free`, `new`, `delete` 等内存管理函数的 hook 和监控。
    * **函数调用约定和栈帧结构:**  为了实现回溯 (backtrace)，健全性检查器需要理解目标架构的函数调用约定以及栈帧的结构，从而能够遍历调用栈。
    * **指令集架构 (ISA):**  回溯功能的实现会受到目标 CPU 架构的影响。

* **Linux/Android 内核:**
    * **进程内存空间:**  Frida 需要能够访问和操作目标进程的内存空间，这涉及到操作系统提供的进程间通信和内存访问机制。
    * **动态链接器 (Dynamic Linker):**  为了 hook 目标进程中的函数，Frida 需要理解动态链接的过程，找到需要 hook 的函数入口点。
    * **系统调用:**  Frida 的某些操作可能需要通过系统调用来实现，例如修改进程内存。

* **框架知识 (例如 Android):**
    * **ART/Dalvik 虚拟机:**  如果目标是 Android 应用程序，健全性检查器需要能够理解 Android 运行时环境 (ART 或 Dalvik) 的内存管理机制，以及如何跟踪 Java 对象的生命周期。
    * **Bionic Libc:** Android 系统使用 Bionic Libc，其内存管理函数的实现可能与标准的 glibc 有所不同。
    * **GObject 系统:** 代码中使用了 GObject，这是一种在 GNOME 和其他 Linux 桌面环境中常用的对象系统。理解 GObject 的引用计数机制对于实例泄漏检测非常重要。

**逻辑推理和假设输入与输出**

健全性检查器的逻辑主要围绕着在目标程序执行特定代码段前后，对比内存分配和对象实例的状态。

**假设输入:**

1. **目标程序运行:** 目标进程正在执行。
2. **Frida 插桩:** Frida 已经将健全性检查器的代码注入到目标进程中。
3. **用户指定的检查范围:** 用户通过 Frida 脚本指定了要检查的代码范围 (通过 `sanity.begin()` 和 `sanity.end()` 控制)。
4. **目标程序执行分配和释放操作:** 在检查范围内，目标程序执行了内存分配 (例如 `malloc`) 和对象创建操作，以及可能的释放操作 (例如 `free`)。

**逻辑推理:**

* **实例泄漏检测:**
    * **假设:** 在 `sanity.begin(Gum.SanityCheck.INSTANCE_LEAKS)` 之后，目标程序创建了一些 GObject 实例。
    * **推理:** `GumInstanceTracker` 会记录这些实例的创建。在 `sanity.end()` 时，它会检查哪些被记录的实例仍然存活（引用计数不为零或没有被 unref）。
    * **输出:** 报告泄漏的实例的类型、地址和引用计数。

* **内存块泄漏检测:**
    * **假设:** 在 `sanity.begin(Gum.SanityCheck.BLOCK_LEAKS)` 之后，目标程序使用 `malloc` 分配了一些内存块。
    * **推理:** `GumAllocatorProbe` 会 hook `malloc` 和 `free` 等函数，`GumAllocationTracker` 会记录已分配但尚未释放的内存块。
    * **输出:** 报告泄漏的内存块的地址和大小，以及分配时的回溯信息。

* **边界检查:**
    * **假设:** 在 `sanity.begin(Gum.SanityCheck.BOUNDS)` 之后，目标程序尝试访问一个已分配的内存块。
    * **推理:** `GumBoundsChecker` 会监控内存访问操作。如果访问的地址超出已分配内存块的范围，则触发检测。
    * **输出:** 报告发生越界访问的地址、访问类型（读或写）和当时的调用栈。

**涉及用户或编程常见的使用错误和举例说明**

用户在使用健全性检查器时可能会遇到一些常见错误：

1. **误报 (False Positives):**
    * **场景:** 某些内存可能被有意地持有并在稍后释放，但在检查的时刻仍然存活，导致误报为泄漏。
    * **解决方法:**  需要仔细分析报告，结合对目标程序行为的理解来判断是否真的是泄漏。可以使用更细粒度的检查范围，或者在释放操作之后再进行检查。
    * **举例:**  一个单例对象在程序生命周期内一直存在，会被报告为泄漏，但这通常是正常的。

2. **漏报 (False Negatives):**
    * **场景:**  某些类型的内存泄漏可能无法被健全性检查器直接检测到，例如，资源句柄泄漏（文件描述符、socket 等）。
    * **解决方法:**  健全性检查器主要关注堆内存和 GObject 实例。对于其他类型的泄漏，可能需要使用其他工具或方法。

3. **性能开销过大:**
    * **场景:**  在大型程序中启用所有类型的健全性检查可能会带来显著的性能开销，因为每个内存分配、释放和访问操作都需要进行额外的检查。
    * **解决方法:**  根据需要选择要启用的检查类型。例如，在初步调试时可以先关注内存泄漏，之后再启用边界检查。

4. **不正确的检查范围:**
    * **场景:**  用户定义的检查范围过大或过小，导致无法捕获到目标问题。
    * **解决方法:**  需要仔细分析目标程序，选择合适的检查点。通常，围绕可疑的代码段进行检查是比较有效的方法。

5. **与目标程序的行为冲突:**
    * **场景:** 健全性检查器的插桩行为可能会干扰目标程序的正常执行，导致崩溃或行为异常。
    * **解决方法:**  这通常是 Frida 本身的问题，可能需要调整 Frida 的配置或使用不同的插桩策略。

**用户操作如何一步步到达这里，作为调试线索**

以下是一个典型的用户操作流程，最终会涉及到 `gumsanitychecker.c` 中的代码执行：

1. **用户编写 Frida 脚本:**  用户创建一个 JavaScript 文件，使用 Frida 的 API 来进行动态插桩。
2. **引入 Gum 模块:**  在脚本中，用户会引入 `Gum` 模块，因为 `GumSanityChecker` 是 `Gum` 的一部分。
   ```javascript
   const Gum = require('frida-gum');
   ```
3. **创建 GumSanityChecker 实例:** 用户创建一个 `GumSanityChecker` 的实例。
   ```javascript
   const sanity = new GumSanityChecker();
   ```
4. **定义要检查的代码范围:** 用户可以使用 `sanity.begin()` 和 `sanity.end()` 来指定要进行健全性检查的代码区域。这通常围绕着用户怀疑存在问题的函数或代码块。
   ```javascript
   sanity.begin(Gum.SanityCheck.BLOCK_LEAKS | Gum.SanityCheck.INSTANCE_LEAKS);
   // ... 调用目标程序中需要检查的函数 ...
   sanity.end();
   ```
5. **或者使用 `sanity.run()`:**  更简洁的方式是使用 `sanity.run()`，它会在执行传入的函数前后自动执行 `begin` 和 `end`。
   ```javascript
   function runMyCode() {
       // ... 调用目标程序中的代码 ...
   }
   sanity.run(runMyCode);
   ```
6. **Frida 启动并连接到目标进程:** 用户使用 Frida 命令行工具 (例如 `frida`, `frida-trace`) 或通过编程方式将脚本加载到目标进程中。
7. **Frida 执行脚本:** Frida 的引擎会解析并执行用户编写的 JavaScript 脚本。
8. **`GumSanityChecker` 的方法被调用:** 当执行到创建 `GumSanityChecker` 实例或调用其 `begin`, `end`, `run` 等方法时，Frida 会调用 `gumsanitychecker.c` 中相应的 C 代码。
9. **插桩和监控:**  `GumSanityChecker` 内部会利用 Frida 的插桩能力，在目标进程的内存分配、释放和对象创建等关键点插入代码，以便跟踪内存使用情况和对象生命周期。
10. **执行用户指定的代码:**  用户在 `run` 函数中定义的或者 `begin`/`end` 之间的目标程序代码会被执行。
11. **健全性检查:** 在 `sanity.end()` 被调用时，或者在 `sanity.run()` 执行完毕后，`gumsanitychecker.c` 中的代码会分析收集到的信息，检测是否存在内存泄漏或越界访问。
12. **输出报告:**  检查结果会通过用户在创建 `GumSanityChecker` 时指定的回调函数 (`GumSanityOutputFunc`) 输出，通常会打印到控制台。

**作为调试线索:**

当用户观察到健全性检查器输出的报告时，这些信息就成为了重要的调试线索：

* **泄漏报告:**  如果报告了实例泄漏或内存块泄漏，用户可以查看泄漏对象的类型、大小和分配时的回溯信息，从而定位到可能存在内存管理错误的代码位置。
* **边界错误报告:** 如果报告了越界访问，用户可以查看发生访问的地址、访问类型以及当时的调用栈，这有助于找到导致缓冲区溢出或其他内存破坏的原因。

总而言之，`gumsanitychecker.c` 是 Frida Gum 库中一个强大的调试工具，它通过动态插桩技术帮助逆向工程师和开发者检测和诊断内存相关的错误，是理解目标程序行为和发现潜在问题的重要手段。

### 提示词
```
这是目录为frida/subprojects/frida-gum/libs/gum/heap/gumsanitychecker.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2010 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsanitychecker.h"

#include "gumallocatorprobe.h"
#include "gumallocationtracker.h"
#include "gumallocationblock.h"
#include "gumallocationgroup.h"
#include "gumboundschecker.h"
#include "guminstancetracker.h"
#include "gummemory.h"

#include <string.h>

struct _GumSanityCheckerPrivate
{
  GumHeapApiList * heap_apis;
  GumSanityOutputFunc output;
  gpointer output_user_data;
  gint backtrace_block_size;
  guint front_alignment_granularity;

  GumInstanceTracker * instance_tracker;

  GumAllocatorProbe * alloc_probe;
  GumAllocationTracker * alloc_tracker;

  GumBoundsChecker * bounds_checker;
};

static gboolean gum_sanity_checker_filter_out_gparam (
    GumInstanceTracker * tracker, GType gtype, gpointer user_data);
static gboolean gum_sanity_checker_filter_backtrace_block_size (
    GumAllocationTracker * tracker, gpointer address, guint size,
    gpointer user_data);

static void gum_sanity_checker_print_instance_leaks_summary (
    GumSanityChecker * self, GList * stale);
static void gum_sanity_checker_print_instance_leaks_details (
    GumSanityChecker * self, GList * stale);
static void gum_sanity_checker_print_block_leaks_summary (
    GumSanityChecker * self, GList * block_groups);
static void gum_sanity_checker_print_block_leaks_details (
    GumSanityChecker * self, GList * stale);

static GHashTable * gum_sanity_checker_count_leaks_by_type_name (
    GumSanityChecker * self, GList * instances);

static void gum_sanity_checker_details_from_instance (GumSanityChecker * self,
    GumInstanceDetails * details, gconstpointer instance);

static gint gum_sanity_checker_compare_type_names (gconstpointer a,
    gconstpointer b, gpointer user_data);
static gint gum_sanity_checker_compare_instances (gconstpointer a,
    gconstpointer b, gpointer user_data);
static gint gum_sanity_checker_compare_groups (gconstpointer a,
    gconstpointer b, gpointer user_data);
static gint gum_sanity_checker_compare_blocks (gconstpointer a,
    gconstpointer b, gpointer user_data);

static void gum_sanity_checker_printf (GumSanityChecker * self,
    const gchar * format, ...);
static void gum_sanity_checker_print (GumSanityChecker * self,
    const gchar * text);

GumSanityChecker *
gum_sanity_checker_new (GumSanityOutputFunc func,
                        gpointer user_data)
{
  GumHeapApiList * apis;
  GumSanityChecker * checker;

  apis = gum_process_find_heap_apis ();
  checker = gum_sanity_checker_new_with_heap_apis (apis, func, user_data);
  gum_heap_api_list_free (apis);

  return checker;
}

GumSanityChecker *
gum_sanity_checker_new_with_heap_apis (const GumHeapApiList * heap_apis,
                                       GumSanityOutputFunc func,
                                       gpointer user_data)
{
  GumSanityChecker * checker;
  GumSanityCheckerPrivate * priv;

  checker = (GumSanityChecker *) g_malloc0 (sizeof (GumSanityChecker) +
      sizeof (GumSanityCheckerPrivate));
  checker->priv = (GumSanityCheckerPrivate *) (checker + 1);

  priv = checker->priv;
  priv->heap_apis = gum_heap_api_list_copy (heap_apis);
  priv->output = func;
  priv->output_user_data = user_data;
  priv->backtrace_block_size = 0;
  priv->front_alignment_granularity = 1;

  return checker;
}

void
gum_sanity_checker_destroy (GumSanityChecker * checker)
{
  GumSanityCheckerPrivate * priv = checker->priv;

  g_clear_object (&priv->bounds_checker);

  g_clear_object (&priv->instance_tracker);

  g_clear_object (&priv->alloc_probe);
  g_clear_object (&priv->alloc_tracker);

  gum_heap_api_list_free (checker->priv->heap_apis);

  g_free (checker);
}

void
gum_sanity_checker_enable_backtraces_for_blocks_of_all_sizes (
    GumSanityChecker * self)
{
  self->priv->backtrace_block_size = -1;
}

void
gum_sanity_checker_enable_backtraces_for_blocks_of_size (
    GumSanityChecker * self,
    guint size)
{
  g_assert (size != 0);

  self->priv->backtrace_block_size = size;
}

void
gum_sanity_checker_set_front_alignment_granularity (GumSanityChecker * self,
                                                    guint granularity)
{
  self->priv->front_alignment_granularity = granularity;
}

gboolean
gum_sanity_checker_run (GumSanityChecker * self,
                        GumSanitySequenceFunc func,
                        gpointer user_data)
{
  gboolean no_leaks_of_any_kind;

  /*
   * First run without any instrumentation
   *
   * This also warms up any static allocations.
   */
  func (user_data);

  gum_sanity_checker_begin (self, GUM_CHECK_INSTANCE_LEAKS);
  func (user_data);
  no_leaks_of_any_kind = gum_sanity_checker_end (self);

  if (no_leaks_of_any_kind)
  {
    gum_sanity_checker_begin (self, GUM_CHECK_BLOCK_LEAKS);
    func (user_data);
    no_leaks_of_any_kind = gum_sanity_checker_end (self);
  }

  if (no_leaks_of_any_kind)
  {
    gum_sanity_checker_begin (self, GUM_CHECK_BOUNDS);
    func (user_data);
    no_leaks_of_any_kind = gum_sanity_checker_end (self);
  }

  return no_leaks_of_any_kind;
}

void
gum_sanity_checker_begin (GumSanityChecker * self,
                          guint flags)
{
  GumSanityCheckerPrivate * priv = self->priv;
  GumBacktracer * backtracer = NULL;

  if (priv->backtrace_block_size != 0)
    backtracer = gum_backtracer_make_accurate ();

  if ((flags & GUM_CHECK_BLOCK_LEAKS) != 0)
  {
    priv->alloc_tracker =
        gum_allocation_tracker_new_with_backtracer (backtracer);

    if (priv->backtrace_block_size > 0)
    {
      gum_allocation_tracker_set_filter_function (priv->alloc_tracker,
          gum_sanity_checker_filter_backtrace_block_size, self);
    }

    priv->alloc_probe = gum_allocator_probe_new ();
    g_object_set (priv->alloc_probe, "allocation-tracker", priv->alloc_tracker,
        NULL);
  }

  if ((flags & GUM_CHECK_INSTANCE_LEAKS) != 0)
  {
    priv->instance_tracker = gum_instance_tracker_new ();
    gum_instance_tracker_set_type_filter_function (priv->instance_tracker,
        gum_sanity_checker_filter_out_gparam, self);
    gum_instance_tracker_begin (priv->instance_tracker, NULL);
  }

  if ((flags & GUM_CHECK_BLOCK_LEAKS) != 0)
  {
    gum_allocation_tracker_begin (priv->alloc_tracker);
    gum_allocator_probe_attach_to_apis (priv->alloc_probe, priv->heap_apis);
  }

  if ((flags & GUM_CHECK_BOUNDS) != 0)
  {
    priv->bounds_checker = gum_bounds_checker_new (backtracer,
        priv->output, priv->output_user_data);
    g_object_set (priv->bounds_checker,
        "front-alignment", priv->front_alignment_granularity, NULL);
    gum_bounds_checker_attach_to_apis (priv->bounds_checker, priv->heap_apis);
  }

  if (backtracer != NULL)
    g_object_unref (backtracer);
}

gboolean
gum_sanity_checker_end (GumSanityChecker * self)
{
  GumSanityCheckerPrivate * priv = self->priv;
  gboolean all_checks_passed = TRUE;

  if (priv->bounds_checker != NULL)
  {
    gum_bounds_checker_detach (priv->bounds_checker);

    g_object_unref (priv->bounds_checker);
    priv->bounds_checker = NULL;
  }

  if (priv->instance_tracker != NULL)
  {
    GList * stale_instances;

    gum_instance_tracker_end (priv->instance_tracker);

    stale_instances =
        gum_instance_tracker_peek_instances (priv->instance_tracker);

    if (stale_instances != NULL)
    {
      all_checks_passed = FALSE;

      gum_sanity_checker_printf (self, "Instance leaks detected:\n\n");
      gum_sanity_checker_print_instance_leaks_summary (self, stale_instances);
      gum_sanity_checker_print (self, "\n");
      gum_sanity_checker_print_instance_leaks_details (self, stale_instances);

      g_list_free (stale_instances);
    }

    g_object_unref (priv->instance_tracker);
    priv->instance_tracker = NULL;
  }

  if (priv->alloc_probe != NULL)
  {
    GList * stale_blocks;

    gum_allocator_probe_detach (priv->alloc_probe);

    stale_blocks =
        gum_allocation_tracker_peek_block_list (priv->alloc_tracker);

    if (stale_blocks != NULL)
    {
      if (all_checks_passed)
      {
        GList * block_groups;

        block_groups =
            gum_allocation_tracker_peek_block_groups (priv->alloc_tracker);

        gum_sanity_checker_printf (self, "Block leaks detected:\n\n");
        gum_sanity_checker_print_block_leaks_summary (self, block_groups);
        gum_sanity_checker_print (self, "\n");
        gum_sanity_checker_print_block_leaks_details (self, stale_blocks);

        gum_allocation_group_list_free (block_groups);
      }

      all_checks_passed = FALSE;

      gum_allocation_block_list_free (stale_blocks);
    }

    g_object_unref (priv->alloc_probe);
    priv->alloc_probe = NULL;

    g_object_unref (priv->alloc_tracker);
    priv->alloc_tracker = NULL;
  }

  return all_checks_passed;
}

static gboolean
gum_sanity_checker_filter_out_gparam (GumInstanceTracker * tracker,
                                      GType gtype,
                                      gpointer user_data)
{
  GumSanityChecker * self = (GumSanityChecker *) user_data;
  const GumInstanceVTable * vtable;

  vtable =
      gum_instance_tracker_get_current_vtable (self->priv->instance_tracker);
  return !g_str_has_prefix (vtable->type_id_to_name (gtype), "GParam");
}

static gboolean
gum_sanity_checker_filter_backtrace_block_size (GumAllocationTracker * tracker,
                                                gpointer address,
                                                guint size,
                                                gpointer user_data)
{
  GumSanityChecker * self = (GumSanityChecker *) user_data;

  return ((gint) size == self->priv->backtrace_block_size);
}

static void
gum_sanity_checker_print_instance_leaks_summary (GumSanityChecker * self,
                                                 GList * stale)
{
  GHashTable * count_by_type;
  GList * cur, * keys;

  count_by_type = gum_sanity_checker_count_leaks_by_type_name (self, stale);

  keys = g_hash_table_get_keys (count_by_type);
  keys = g_list_sort_with_data (keys,
      gum_sanity_checker_compare_type_names, count_by_type);

  gum_sanity_checker_print (self, "\tCount\tGType\n");
  gum_sanity_checker_print (self, "\t-----\t-----\n");

  for (cur = keys; cur != NULL; cur = cur->next)
  {
    const gchar * type_name = (const gchar *) cur->data;
    guint count;

    count = GPOINTER_TO_UINT (g_hash_table_lookup (count_by_type,
        type_name));
    gum_sanity_checker_printf (self, "\t%u\t%s\n", count, type_name);
  }

  g_list_free (keys);

  g_hash_table_unref (count_by_type);
}

static void
gum_sanity_checker_print_instance_leaks_details (GumSanityChecker * self,
                                                 GList * stale)
{
  GList * instances, * cur;

  instances = g_list_copy (stale);
  instances = g_list_sort_with_data (instances,
      gum_sanity_checker_compare_instances, self);

  gum_sanity_checker_print (self, "\tAddress\t\tRefCount\tGType\n");
  gum_sanity_checker_print (self, "\t--------\t--------\t-----\n");

  for (cur = instances; cur != NULL; cur = cur->next)
  {
    GumInstanceDetails details;

    gum_sanity_checker_details_from_instance (self, &details, cur->data);

    gum_sanity_checker_printf (self, "\t%p\t%d%s\t%s\n",
        details.address,
        details.ref_count,
        details.ref_count <= 9 ? "\t" : "",
        details.type_name);
  }

  g_list_free (instances);
}

static void
gum_sanity_checker_print_block_leaks_summary (GumSanityChecker * self,
                                              GList * block_groups)
{
  GList * groups, * cur;

  groups = g_list_copy (block_groups);
  groups = g_list_sort_with_data (groups,
      gum_sanity_checker_compare_groups, self);

  gum_sanity_checker_print (self, "\tCount\tSize\n");
  gum_sanity_checker_print (self, "\t-----\t----\n");

  for (cur = groups; cur != NULL; cur = cur->next)
  {
    GumAllocationGroup * group = (GumAllocationGroup *) cur->data;

    if (group->alive_now == 0)
      continue;

    gum_sanity_checker_printf (self, "\t%u\t%u\n",
        group->alive_now, group->size);
  }

  g_list_free (groups);
}

static void
gum_sanity_checker_print_block_leaks_details (GumSanityChecker * self,
                                              GList * stale)
{
  GList * blocks, * cur;

  blocks = g_list_copy (stale);
  blocks = g_list_sort_with_data (blocks,
      gum_sanity_checker_compare_blocks, self);

  gum_sanity_checker_print (self, "\tAddress\t\tSize\n");
  gum_sanity_checker_print (self, "\t--------\t----\n");

  for (cur = blocks; cur != NULL; cur = cur->next)
  {
    GumAllocationBlock * block = (GumAllocationBlock *) cur->data;
    guint i;

    gum_sanity_checker_printf (self, "\t%p\t%u\n",
        block->address, block->size);

    for (i = 0; i != block->return_addresses.len; i++)
    {
      GumReturnAddress addr = block->return_addresses.items[i];
      GumReturnAddressDetails rad;

      if (gum_return_address_details_from_address (addr, &rad))
      {
        gchar * file_basename;

        file_basename = g_path_get_basename (rad.file_name);
        gum_sanity_checker_printf (self, "\t    %p %s!%s %s:%u\n",
            rad.address,
            rad.module_name, rad.function_name,
            file_basename, rad.line_number);
        g_free (file_basename);
      }
      else
      {
        gum_sanity_checker_printf (self, "\t    %p\n", addr);
      }
    }
  }

  g_list_free (blocks);
}

static GHashTable *
gum_sanity_checker_count_leaks_by_type_name (GumSanityChecker * self,
                                             GList * instances)
{
  GHashTable * count_by_type;
  const GumInstanceVTable * vtable;
  GList * cur;

  count_by_type = g_hash_table_new_full (g_str_hash, g_str_equal, NULL, NULL);

  vtable =
      gum_instance_tracker_get_current_vtable (self->priv->instance_tracker);

  for (cur = instances; cur != NULL; cur = cur->next)
  {
    const gchar * type_name;
    guint count;

    type_name = vtable->type_id_to_name (G_TYPE_FROM_INSTANCE (cur->data));
    count = GPOINTER_TO_UINT (g_hash_table_lookup (count_by_type,
        type_name));
    count++;
    g_hash_table_insert (count_by_type, (gpointer) type_name,
        GUINT_TO_POINTER (count));
  }

  return count_by_type;
}

static void
gum_sanity_checker_details_from_instance (GumSanityChecker * self,
                                          GumInstanceDetails * details,
                                          gconstpointer instance)
{
  const GumInstanceVTable * vtable;
  GType type;

  vtable =
      gum_instance_tracker_get_current_vtable (self->priv->instance_tracker);

  details->address = instance;
  type = G_TYPE_FROM_INSTANCE (instance);
  details->type_name = vtable->type_id_to_name (type);
  if (g_type_is_a (type, G_TYPE_OBJECT))
    details->ref_count = ((GObject *) instance)->ref_count;
  else
    details->ref_count = 1;
}

static gint
gum_sanity_checker_compare_type_names (gconstpointer a,
                                       gconstpointer b,
                                       gpointer user_data)
{
  const gchar * name_a = (const gchar *) a;
  const gchar * name_b = (const gchar *) b;
  GHashTable * count_by_type = (GHashTable *) user_data;
  guint count_a, count_b;

  count_a = GPOINTER_TO_UINT (g_hash_table_lookup (count_by_type, name_a));
  count_b = GPOINTER_TO_UINT (g_hash_table_lookup (count_by_type, name_b));
  if (count_a > count_b)
    return -1;
  else if (count_a < count_b)
    return 1;
  else
    return strcmp (name_a, name_b);
}

static gint
gum_sanity_checker_compare_instances (gconstpointer a,
                                      gconstpointer b,
                                      gpointer user_data)
{
  GumSanityChecker * self = (GumSanityChecker *) user_data;
  GumInstanceDetails da, db;
  gint name_equality;

  gum_sanity_checker_details_from_instance (self, &da, a);
  gum_sanity_checker_details_from_instance (self, &db, b);

  name_equality = strcmp (da.type_name, db.type_name);
  if (name_equality != 0)
    return name_equality;

  if (da.ref_count > db.ref_count)
    return -1;
  else if (da.ref_count < db.ref_count)
    return 1;

  if (da.address > db.address)
    return -1;
  else if (da.address < db.address)
    return 1;
  else
    return 0;
}

static gint
gum_sanity_checker_compare_groups (gconstpointer a,
                                   gconstpointer b,
                                   gpointer user_data)
{
  GumAllocationGroup * group_a = (GumAllocationGroup *) a;
  GumAllocationGroup * group_b = (GumAllocationGroup *) b;

  if (group_a->alive_now > group_b->alive_now)
    return -1;
  else if (group_a->alive_now < group_b->alive_now)
    return 1;

  if (group_a->size > group_b->size)
    return -1;
  else if (group_a->size < group_b->size)
    return 1;
  else
    return 0;
}

static gint
gum_sanity_checker_compare_blocks (gconstpointer a,
                                   gconstpointer b,
                                   gpointer user_data)
{
  GumAllocationBlock * block_a = (GumAllocationBlock *) a;
  GumAllocationBlock * block_b = (GumAllocationBlock *) b;
  gsize addr_a, addr_b;

  if (block_a->size > block_b->size)
    return -1;
  else if (block_a->size < block_b->size)
    return 1;

  addr_a = GPOINTER_TO_SIZE (block_a->address);
  addr_b = GPOINTER_TO_SIZE (block_b->address);
  if (addr_a > addr_b)
    return -1;
  else if (addr_a < addr_b)
    return 1;
  else
    return 0;
}

static void
gum_sanity_checker_printf (GumSanityChecker * self,
                           const gchar * format,
                           ...)
{
  va_list args;
  gchar * text;

  va_start (args, format);

  text = g_strdup_vprintf (format, args);
  gum_sanity_checker_print (self, text);
  g_free (text);

  va_end (args);
}

static void
gum_sanity_checker_print (GumSanityChecker * self,
                          const gchar * text)
{
  self->priv->output (text, self->priv->output_user_data);
}
```