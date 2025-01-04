Response:
Let's break down the request and the provided C code. The goal is to understand the functionality of `profiler-fixture.c` in the context of Frida, dynamic instrumentation, and potential connections to reverse engineering and low-level concepts.

**1. Understanding the Goal:** The core request is to analyze a test fixture file for Frida's profiler. This means the file likely sets up and tears down the necessary components to test the profiler's functionality.

**2. Initial Code Scan and Keyword Spotting:** I immediately scanned the code for keywords and patterns that suggest its purpose:

*   `TestProfilerFixture`, `TestProfileReportFixture`:  Strong indicators of test fixture structures.
*   `GumProfiler`, `GumSampler`, `GumFakeSampler`, `GumProfileReport`, `GumProfileReportNode`: These types suggest the main components being tested: the profiler itself, samplers to generate data, a fake sampler for controlled testing, and report generation structures.
*   `gum_profiler_new`, `gum_fake_sampler_new`, `gum_profiler_generate_report`, `gum_profile_report_emit_xml`: Functions that create and interact with the profiler and its reporting.
*   `TESTCASE`, `TESTENTRY`, `REPORT_TESTCASE`, `REPORT_TESTENTRY`:  Macros used for defining test cases, suggesting a testing framework is in use.
*   `assert_...`: A family of assertion functions, further reinforcing the testing nature of the file.
*   `GUM_NOINLINE`, `GUM_CDECL`, `GUM_STDCALL`: Function attributes related to optimization and calling conventions, hinting at low-level considerations.
*   `example_...`, `simple_...`:  Prefixed function names used as "guinea pigs" for testing the profiler. These are simple functions with controlled behavior.
*   `instrument_function`:  A function to connect the profiler to specific functions.

**3. Deconstructing the Functionality:** Based on the keywords and structures, I started to piece together the functionality:

*   **Setup and Teardown:** The `*_fixture_setup` and `*_fixture_teardown` functions clearly manage the lifecycle of the profiler and sampler objects for each test. The `TestProfileReportFixture` also manages the `GumProfileReport`.
*   **Fake Sampler:** The use of `GumFakeSampler` is crucial. It allows for deterministic testing by simulating sample data instead of relying on real-time sampling. This makes tests reproducible.
*   **Instrumentation:** The `instrument_function` macro and `instrument_example_functions`/`instrument_simple_functions` demonstrate how the profiler is connected to the functions it will monitor.
*   **Report Generation:** `gum_profiler_generate_report` creates a profile report, and `gum_profile_report_emit_xml` suggests the report can be exported in XML format.
*   **Assertions:** The `assert_...` functions are used to verify the correctness of the generated reports, such as the number of top-level nodes, the call depth, and the XML output.
*   **Test Cases:** The `test_profiler_*` and `test_profile_report_*` functions (defined by the macros) represent individual test cases for different aspects of the profiler.
*   **Guinea Pig Functions:** The `example_...` and `simple_...` functions are the targets of the profiling. They are designed to exhibit various call patterns (linear, recursive, cyclic) and have controlled execution times (through `gum_fake_sampler_advance`).

**4. Connecting to Reverse Engineering:**  The profiler's purpose itself is directly related to reverse engineering. By dynamically instrumenting code, it helps understand the execution flow, identify performance bottlenecks, and potentially reveal hidden behavior. The ability to generate call graphs (implied by the report structure) is a valuable reverse engineering technique.

**5. Connecting to Low-Level Concepts:**

*   **Binary Instrumentation:** The core of Frida and this profiler is about modifying the execution of a binary at runtime. This involves interacting with the process's memory and instruction stream.
*   **Calling Conventions:** The `GUM_CDECL` and `GUM_STDCALL` attributes are directly related to how functions are called at the assembly level. The profiler needs to be aware of these conventions to correctly intercept and analyze function calls.
*   **Memory Management:** The use of `g_object_unref` suggests the use of a reference counting mechanism for memory management, common in C-based libraries.
*   **Platform Dependence (`HAVE_WINDOWS`):** The `#ifdef HAVE_WINDOWS` block indicates that the code has platform-specific parts, likely due to differences in how profiling is implemented on Windows versus other systems (like Linux).

**6. Logic Inference (Hypothetical Input and Output):** I imagined a simple test case: instrumenting `example_a`, calling it once, and then generating a report. The expected output would be a report showing `example_a` as the root, with calls to `example_c` and `example_b` as children. The `gum_fake_sampler_advance` calls within these functions would contribute to the reported execution times.

**7. User/Programming Errors:** I considered potential mistakes in using such a profiler:

*   **Incorrect Instrumentation:**  Instrumenting the wrong functions or missing crucial ones.
*   **Sampler Configuration:** If using a real-time sampler, incorrect sampling rates could lead to inaccurate or incomplete profiles.
*   **Report Interpretation:** Misunderstanding the structure or meaning of the generated report.
*   **Resource Leaks:**  While the test fixture handles cleanup, in a real application, failing to properly dispose of profiler objects could lead to memory leaks.

**8. User Steps to Reach the Code:** I thought about the development workflow:

1. **Developer wants to test the Frida profiler.**
2. **They navigate to the `frida/subprojects/frida-gum/tests/prof/` directory.**
3. **They open `profiler-fixture.c` to understand how the profiler is being tested.**
4. **They might be writing a new test case or debugging an existing one.**

This detailed thought process, breaking down the code into its components and relating it to the broader context of Frida and reverse engineering, allows for a comprehensive understanding of the `profiler-fixture.c` file.
这个文件 `profiler-fixture.c` 是 Frida (一个动态 instrumentation 工具) 的一部分，具体来说，它位于 Frida-gum (Frida 的核心引擎) 的测试套件中。它的主要功能是为一个或多个测试用例提供一个**测试环境 (fixture)**，用于测试 Frida 的**性能分析器 (profiler)** 功能。

让我们逐点分析其功能以及与相关概念的联系：

**1. 主要功能：提供性能分析器的测试环境**

*   **创建和管理 `GumProfiler` 对象:**  `GumProfiler` 是 Frida 中负责性能分析的核心对象。Fixture 负责创建 (`gum_profiler_new`) 和销毁 (`g_object_unref`)  `GumProfiler` 实例，确保每个测试用例都能在一个干净的环境中运行。
*   **创建和管理 `GumSampler` 对象:** `GumSampler` 负责实际的性能数据采样。在这个 fixture 中，使用了 `GumFakeSampler` (`gum_fake_sampler_new`)。`GumFakeSampler` 是一个模拟的采样器，允许测试在可控的环境中进行，无需依赖真实的系统性能数据。这对于单元测试非常重要，因为它确保了测试结果的可重复性。
*   **提供辅助函数:**  Fixture 提供了诸如 `test_profiler_fixture_setup`, `test_profiler_fixture_teardown`, `test_profile_report_fixture_setup`, `test_profile_report_fixture_teardown` 等 setup 和 teardown 函数，用于在每个测试用例执行前后进行必要的初始化和清理工作。
*   **提供断言辅助函数:**  Fixture 包含诸如 `assert_n_top_nodes`, `assert_depth_from_root_node`, `assert_same_xml` 等辅助函数，用于验证性能分析器输出的报告是否符合预期。这些函数允许测试用例方便地检查生成的性能报告的结构和内容。
*   **包含被测试的示例函数 (Guinea pig functions):**  文件中定义了许多以 `example_` 和 `simple_` 开头的函数，例如 `example_a`, `example_b`, `simple_cdecl_42` 等。这些函数作为被分析的目标代码，用于模拟不同的代码执行场景，例如函数调用、递归调用、不同的调用约定等。
*   **提供函数插桩的辅助函数:** `instrument_function` 宏和 `instrument_example_functions`, `instrument_simple_functions` 函数用于将 `GumProfiler` 和 `GumSampler` 连接到特定的示例函数，使其能够被性能分析器监控。
*   **生成和验证性能报告:** `test_profile_report_fixture_get_root_nodes` 函数和相关的断言函数展示了如何生成 (`gum_profiler_generate_report`) 和验证 (`gum_profile_report_get_root_nodes_for_thread`, `gum_profile_report_emit_xml`) 性能分析报告。

**2. 与逆向方法的联系 (举例说明)**

性能分析是逆向工程中非常重要的一部分，它可以帮助逆向工程师理解程序的执行流程、性能瓶颈以及潜在的恶意行为。这个 fixture 文件直接测试了 Frida 的性能分析能力，而 Frida 本身就是一个强大的动态逆向工具。

*   **识别热点函数:**  通过性能分析，逆向工程师可以快速找到程序中执行频率最高或耗时最长的函数，这些函数往往是程序的核心逻辑所在，是逆向分析的重点。例如，使用基于这个 fixture 的测试用例，我们可以测试 Frida 能否正确识别 `example_a` 函数调用 `example_b` 和 `example_c` 的次数和耗时。
*   **分析函数调用关系:** 性能分析报告可以展示函数的调用栈，帮助逆向工程师理解复杂的函数调用关系。Fixture 中的 `assert_depth_from_root_node` 函数就是用来验证调用栈的深度和顺序是否符合预期。在逆向分析中，这可以帮助理解一个操作是如何通过一系列函数调用实现的。
*   **分析不同代码路径的执行情况:** 通过控制输入或程序状态，逆向工程师可以触发不同的代码路径，并使用性能分析来观察这些路径的执行情况，例如哪些函数被调用，执行时间如何等。Fixture 中的 `example_cyclic_a` 和 `example_cyclic_b` 函数模拟了循环调用的场景，可以测试性能分析器在处理这种复杂调用关系时的能力。
*   **检测性能瓶颈:** 性能分析可以帮助识别程序中的性能瓶颈，这在逆向分析恶意软件时尤为重要，因为恶意软件可能会故意引入性能瓶颈来逃避检测或消耗系统资源。

**3. 涉及二进制底层、Linux、Android 内核及框架的知识 (举例说明)**

虽然这个 fixture 文件主要关注用户态的性能分析，但它背后的机制涉及到一些底层的概念：

*   **二进制插桩:** Frida 的核心原理是动态二进制插桩，这意味着它会在程序运行时修改程序的二进制代码，插入额外的指令来收集性能数据。这个 fixture 文件通过 `gum_profiler_instrument_function` 函数来指定要插桩的函数。
*   **函数调用约定 (Calling Convention):**  代码中出现了 `GUM_CDECL` 和 `GUM_STDCALL` 宏，这与不同的函数调用约定有关。不同的平台和编译器可能使用不同的调用约定，这些约定决定了函数参数的传递方式、栈的清理方式等。Frida 的性能分析器需要能够处理不同的调用约定才能正确地跟踪函数调用。这在逆向 Windows 平台的代码时尤其重要，因为 Windows API 经常使用 `STDCALL` 调用约定。
*   **内存管理:**  代码中使用了 `g_object_unref`，这是 GLib 库提供的用于引用计数的内存管理机制。Frida 内部也使用了类似的机制来管理其创建的对象，避免内存泄漏。
*   **线程 ID:** `gum_profile_report_get_root_nodes_for_thread (fixture->report, 0)`  表明性能报告是按线程组织的。在多线程程序中，理解不同线程的性能表现非常重要。
*   **信号处理 (Implied):** 真实的性能分析器通常会使用操作系统提供的机制 (例如信号) 来进行周期性的采样。虽然 `GumFakeSampler` 模拟了这个过程，但真实的实现会涉及到 Linux 或 Android 内核的信号处理机制。
*   **Android 框架 (Potential):**  虽然这个 fixture 文件本身不直接涉及 Android 框架，但 Frida 常用于 Android 平台的动态分析。Frida 可以在 Android 应用的 Dalvik/ART 虚拟机中进行插桩，监控 Java 代码的执行。性能分析器可以帮助理解 Android 应用的性能瓶颈或特定功能的实现方式。

**4. 逻辑推理 (假设输入与输出)**

假设我们运行一个测试用例，其中：

*   **输入:**
    *   使用 `instrument_function` 插桩了 `example_a` 函数。
    *   `example_a` 函数内部调用了 `example_c` 和 `example_b` 函数。
    *   `gum_fake_sampler_advance` 在 `example_a` 中前进 2 个单位，在 `example_c` 中前进 4 个单位，在 `example_b` 中前进 3 个单位。
*   **预期输出 (通过断言验证):**
    *   性能报告的根节点应该包含 `example_a` 函数。
    *   `example_a` 节点的子节点应该包含 `example_c` 和 `example_b` 函数。
    *   `example_a` 的总耗时应该包含其自身以及子函数的耗时 (可以根据测试用例的具体实现方式决定是否包含子函数耗时)。
    *   生成的 XML 报告应该包含相应的函数调用和耗时信息。

例如，`assert_n_top_nodes(fixture, 1, "example_a", "example_c")`  会断言有一个顶层节点名为 "example_a"，并且它的直接子节点名为 "example_c"。  `assert_depth_from_root_node(fixture, 0, "example_a", "example_b", NULL)` 会断言第一个根节点 ("example_a") 的调用链是 "example_a" -> "example_b"。

**5. 涉及用户或编程常见的使用错误 (举例说明)**

*   **忘记插桩函数:** 用户可能忘记使用 `gum_profiler_instrument_function` 插桩他们想要分析的函数，导致性能报告中缺少关键信息。
*   **使用真实的 `GumSampler` 但没有合适的权限:** 如果用户尝试在没有足够权限的情况下使用真实的采样器 (例如需要内核权限的采样器)，可能会导致程序崩溃或性能分析失败。
*   **误解性能报告的含义:** 用户可能会错误地理解性能报告中的数据，例如将某个函数的自身耗时误认为总耗时，或者忽略了上下文切换等因素。
*   **过度插桩:** 插桩过多的函数会引入显著的性能开销，影响被分析程序的运行，甚至可能导致程序不稳定。
*   **在多线程环境中使用不当:**  如果用户没有正确处理多线程环境下的性能数据收集和分析，可能会得到不一致或不准确的结果。
*   **内存泄漏 (在集成到更大系统时):** 虽然 fixture 自身会清理资源，但在实际使用中，如果用户没有正确地释放 `GumProfiler` 和 `GumSampler` 对象，可能会导致内存泄漏。

**6. 说明用户操作是如何一步步的到达这里，作为调试线索**

一个开发者可能因为以下原因查看或修改这个文件：

1. **开发新的性能分析功能:** 开发者可能正在为 Frida 添加新的性能分析功能，需要编写新的测试用例来验证其正确性，这会涉及到修改或添加新的 fixture 代码。
2. **修复性能分析相关的 Bug:** 如果用户报告了性能分析功能存在 Bug，开发者可能会查看相关的测试用例，尝试复现 Bug，并修改 fixture 或测试用例来更好地覆盖 Bug 场景。
3. **理解 Frida 性能分析的实现:**  新的 Frida 开发者可能会查看这个 fixture 文件来学习如何使用 `GumProfiler` 和相关的 API，理解性能分析的内部工作原理。
4. **优化性能分析的性能:**  开发者可能会分析现有的测试用例，尝试优化性能分析的实现，并使用 fixture 来衡量优化效果。
5. **移植 Frida 到新的平台:** 在将 Frida 移植到新的操作系统或架构时，开发者可能需要修改或添加平台特定的测试用例和 fixture 代码。
6. **调试测试失败:** 当 Frida 的性能分析测试用例失败时，开发者会查看这个 fixture 文件以及相关的测试用例代码，分析失败原因。

**总结:**

`profiler-fixture.c` 是 Frida 性能分析功能的核心测试环境。它通过模拟采样器和提供一系列辅助函数，允许开发者编写可控的、可重复的测试用例，验证性能分析器的功能是否正确。这个文件涉及到动态二进制插桩、函数调用约定、内存管理等底层概念，并与逆向工程中的性能分析技术紧密相关。理解这个文件对于理解 Frida 的性能分析机制以及如何对其进行测试至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/prof/profiler-fixture.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2008-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprofiler.h"

#ifdef HAVE_WINDOWS

#include "fakesampler.h"
#include "lowlevelhelpers.h"
#include "testutil.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TESTCASE(NAME) \
    void test_profiler_ ## NAME ( \
        TestProfilerFixture * fixture, gconstpointer data)
#define TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("Prof/Profiler", test_profiler, NAME, \
        TestProfilerFixture)

#define REPORT_TESTCASE(NAME) \
    void test_profile_report_ ## NAME ( \
        TestProfileReportFixture * fixture, gconstpointer data)
#define REPORT_TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("Prof/ProfileReport", test_profile_report, NAME, \
        TestProfileReportFixture)

typedef struct _TestProfilerFixture
{
  GumProfiler * profiler;

  GumSampler * sampler;
  GumFakeSampler * fake_sampler;
} TestProfilerFixture;

typedef struct _TestProfileReportFixture
{
  GumProfiler * profiler;

  GumSampler * sampler;
  GumFakeSampler * fake_sampler;

  GumProfileReport * report;
  const GPtrArray * root_nodes;
} TestProfileReportFixture;

static void
test_profiler_fixture_setup (TestProfilerFixture * fixture,
                             gconstpointer data)
{
  fixture->profiler = gum_profiler_new ();
  fixture->sampler = gum_fake_sampler_new ();
  fixture->fake_sampler = GUM_FAKE_SAMPLER (fixture->sampler);
}

static void
test_profiler_fixture_teardown (TestProfilerFixture * fixture,
                                gconstpointer data)
{
  g_object_unref (fixture->sampler);
  g_object_unref (fixture->profiler);
}

static void
test_profile_report_fixture_setup (TestProfileReportFixture * fixture,
                                   gconstpointer data)
{
  fixture->profiler = gum_profiler_new ();
  fixture->sampler = gum_fake_sampler_new ();
  fixture->fake_sampler = GUM_FAKE_SAMPLER (fixture->sampler);
  fixture->report = NULL;
  fixture->root_nodes = NULL;
}

static void
test_profile_report_fixture_teardown (TestProfileReportFixture * fixture,
                                      gconstpointer data)
{
  g_object_unref (fixture->report);
  g_object_unref (fixture->sampler);
  g_object_unref (fixture->profiler);
}

static const GPtrArray *
test_profile_report_fixture_get_root_nodes (TestProfileReportFixture * fixture)
{
  fixture->report = gum_profiler_generate_report (fixture->profiler);
  g_assert_nonnull (fixture->report);

  fixture->root_nodes =
      gum_profile_report_get_root_nodes_for_thread (fixture->report, 0);
  g_assert_nonnull (fixture->root_nodes);

  return fixture->root_nodes;
}

static void
assert_n_top_nodes (TestProfileReportFixture * fixture,
                    guint n,
                    ...)
{
  const GPtrArray * root_nodes;
  va_list args;
  guint i;

  root_nodes = test_profile_report_fixture_get_root_nodes (fixture);
  g_assert_cmpuint (root_nodes->len, ==, n);

  va_start (args, n);

  for (i = 0; i < n; i++)
  {
    const gchar * name, * child_name;
    GumProfileReportNode * node;

    name = va_arg (args, const gchar *);
    child_name = va_arg (args, const gchar *);

    node = (GumProfileReportNode *) g_ptr_array_index (root_nodes, i);
    g_assert_cmpstr (node->name, ==, name);
    g_assert_nonnull (node->child);
    g_assert_cmpstr (node->child->name, ==, child_name);
  }
}

void
assert_depth_from_root_node (TestProfileReportFixture * fixture,
                             guint root_node_index,
                             ...)
{
  GumProfileReportNode * root_node, * cur_node;
  va_list args;

  root_node = (GumProfileReportNode *) g_ptr_array_index (fixture->root_nodes,
      root_node_index);
  cur_node = root_node;

  va_start (args, root_node_index);

  while (TRUE)
  {
    const gchar * expected_node_name;

    expected_node_name = va_arg (args, const gchar *);
    if (expected_node_name == NULL)
    {
      g_assert_null (cur_node);
      break;
    }

    g_assert_cmpstr (cur_node->name, ==, expected_node_name);

    cur_node = cur_node->child;
  }
}

void
assert_same_xml (TestProfileReportFixture * fixture,
                 const gchar * expected_xml)
{
  gchar * generated_xml;

  fixture->report = gum_profiler_generate_report (fixture->profiler);
  g_assert_nonnull (fixture->report);

  generated_xml = gum_profile_report_emit_xml (fixture->report);
  if (strcmp (generated_xml, expected_xml) != 0)
  {
    GString * message;
    gchar * diff;

    message = g_string_new ("Generated XML not like expected:\n\n");

    diff = test_util_diff_xml (expected_xml, generated_xml);
    g_string_append (message, diff);
    g_free (diff);

    g_assertion_message (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC,
        message->str);

    g_string_free (message, TRUE);
  }

  g_free (generated_xml);
}

/*
 * Guinea pig functions:
 */

static void GUM_NOINLINE example_b (GumFakeSampler * sampler);
static void GUM_NOINLINE example_c (GumFakeSampler * sampler);
static void GUM_NOINLINE example_f (GumFakeSampler * sampler);
static void GUM_NOINLINE example_g (GumFakeSampler * sampler);
static void GUM_NOINLINE example_cyclic_b (GumFakeSampler * sampler,
    gint flag);
static void deep_recursive_caller (gint count);
static void GUM_NOINLINE example_b_dynamic (GumFakeSampler * sampler,
    guint cost);

gint dummy_variable_to_trick_optimizer = 0;

static void GUM_NOINLINE
sleepy_function (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 1000);
}

static void GUM_NOINLINE
example_a (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 2);
  example_c (sampler);
  example_b (sampler);
}

static void GUM_NOINLINE
example_b (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 3);
}

static void GUM_NOINLINE
example_c (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 4);
}

static void GUM_NOINLINE
example_d (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 7);
  example_c (sampler);
}

static void GUM_NOINLINE
example_e (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 3);
  example_f (sampler);
}

static void GUM_NOINLINE
example_f (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 4);
  example_g (sampler);
}

static void GUM_NOINLINE
example_g (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 5);
}

static void GUM_NOINLINE
example_cyclic_a (GumFakeSampler * sampler,
                  gint flag)
{
  gum_fake_sampler_advance (sampler, 1);

  if (flag)
    example_cyclic_b (sampler, 0);
}

static void GUM_NOINLINE
example_cyclic_b (GumFakeSampler * sampler,
                  gint flag)
{
  gum_fake_sampler_advance (sampler, 2);
  example_cyclic_a (sampler, flag);
}

static gboolean
exclude_simple_stdcall_50 (const gchar * match,
                           gpointer user_data)
{
  return strcmp (match, "simple_stdcall_50") != 0;
}

static void GUM_NOINLINE GUM_CDECL
simple_cdecl_42 (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 42);
}

static void GUM_NOINLINE GUM_STDCALL
simple_stdcall_48 (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 48);
}

static void GUM_NOINLINE GUM_STDCALL
simple_stdcall_50 (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 50);
}

static void
recursive_function (gint count)
{
  if (--count > 0)
  {
    recursive_function (count);
    dummy_variable_to_trick_optimizer += 3;
  }
  else
  {
    dummy_variable_to_trick_optimizer += 5;
  }
}

static void
deep_recursive_function (gint count)
{
  dummy_variable_to_trick_optimizer += 42;

  if (--count > 0)
  {
    deep_recursive_function (count);
    deep_recursive_caller (count);

    dummy_variable_to_trick_optimizer += 1337;
  }
}

static void
deep_recursive_caller (gint count)
{
  if (count == 1)
    deep_recursive_function (count);
}

G_GNUC_UNUSED static void
spin_for_one_tenth_second (void)
{
  GTimer * timer;
  guint i;
  guint b = 0;

  timer = g_timer_new ();

  do
  {
    for (i = 0; i < 1000000; i++)
      b += i * i;
  }
  while (g_timer_elapsed (timer, NULL) < 0.1);

  g_timer_destroy (timer);
}

static void GUM_NOINLINE
example_a_calls_b_thrice (GumFakeSampler * sampler)
{
  example_b_dynamic (sampler, 1);
  example_b_dynamic (sampler, 3);
  example_b_dynamic (sampler, 2);
}

static void GUM_NOINLINE
example_b_dynamic (GumFakeSampler * sampler,
                   guint cost)
{
  gum_fake_sampler_advance (sampler, cost);
}

static void GUM_NOINLINE
example_worst_case_info (GumFakeSampler * sampler,
                         const gchar * magic,
                         GumSample cost)
{
  gum_fake_sampler_advance (sampler, cost);
}

static void GUM_NOINLINE
example_worst_case_recursive (gint count,
                              GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 1);

  if (count > 0)
    example_worst_case_recursive (count - 1, sampler);
}

static void
inspect_worst_case_info (GumInvocationContext * context,
                         gchar * output_buf,
                         guint output_buf_len,
                         gpointer user_data)
{
  const gchar * magic;

  magic = (gchar *) gum_invocation_context_get_nth_argument (context, 1);

#ifdef _MSC_VER
  strcpy_s (output_buf, output_buf_len, magic);
#else
  strcpy (output_buf, magic);
#endif
}

static void
inspect_recursive_worst_case_info (GumInvocationContext * context,
                                   gchar * output_buf,
                                   guint output_buf_len,
                                   gpointer user_data)
{
  gint count;

  count = GPOINTER_TO_INT (
      gum_invocation_context_get_nth_argument (context, 0));

#ifdef _MSC_VER
  sprintf_s (output_buf, output_buf_len, "%d", count);
#else
  sprintf (output_buf, "%d", count);
#endif
}

/* These three should be kept in this order to increase the likelihood of
 * function addresses being non-consecutive... */

static void GUM_NOINLINE
simple_2 (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 2);

  dummy_variable_to_trick_optimizer += 2;
}

static void GUM_NOINLINE
simple_1 (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 1);

  dummy_variable_to_trick_optimizer += 1;
}

static void GUM_NOINLINE
simple_3 (GumFakeSampler * sampler)
{
  gum_fake_sampler_advance (sampler, 3);

  dummy_variable_to_trick_optimizer += 3;
}

#define INSTRUMENT_FUNCTION(f) \
    gum_profiler_instrument_function (fixture->profiler, f, fixture->sampler)

static void
instrument_example_functions (TestProfileReportFixture * fixture)
{
  INSTRUMENT_FUNCTION (example_a);
  INSTRUMENT_FUNCTION (example_b);
  INSTRUMENT_FUNCTION (example_c);
  INSTRUMENT_FUNCTION (example_d);
  INSTRUMENT_FUNCTION (example_e);
  INSTRUMENT_FUNCTION (example_f);
  INSTRUMENT_FUNCTION (example_g);
  INSTRUMENT_FUNCTION (example_cyclic_a);
  INSTRUMENT_FUNCTION (example_cyclic_b);
  INSTRUMENT_FUNCTION (example_a_calls_b_thrice);
  INSTRUMENT_FUNCTION (example_b_dynamic);
  INSTRUMENT_FUNCTION (example_worst_case_info);
}

static void
instrument_simple_functions (TestProfileReportFixture * fixture)
{
  INSTRUMENT_FUNCTION (simple_cdecl_42);
  INSTRUMENT_FUNCTION (simple_stdcall_48);
  INSTRUMENT_FUNCTION (simple_stdcall_50);
  INSTRUMENT_FUNCTION (simple_2);
  INSTRUMENT_FUNCTION (simple_1);
  INSTRUMENT_FUNCTION (simple_3);
}

#endif /* HAVE_WINDOWS */

"""

```