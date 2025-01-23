Response:
Let's break down the thought process to analyze the C code and address the user's prompt.

**1. Understanding the Goal:**

The core goal is to analyze the provided C code snippet (`profiler.c`) and explain its functionality, relating it to reverse engineering, low-level concepts, potential user errors, and how a user might end up executing this code.

**2. Initial Code Scan & Keyword Identification:**

The first step is to quickly scan the code for recognizable patterns and keywords. I see:

* `#include`:  Indicates reliance on other code. `profiler-fixture.c` is immediately interesting.
* `#ifdef HAVE_WINDOWS`, `#ifdef HAVE_I386`:  Conditional compilation, suggesting platform-specific behavior.
* `TESTLIST_BEGIN`, `TESTENTRY`, `TESTCASE`, `REPORT_TESTCASE`, `TESTLIST_END`:  Strong indicators of a testing framework. This suggests the primary purpose of this file is to *test* the profiling functionality.
* `GumProfiler *`: A data type likely related to the profiling mechanism being tested.
* `gum_profiler_instrument_function`, `gum_profiler_get_number_of_threads`, `gum_profiler_get_total_duration_of`, `gum_profiler_instrument_functions_matching`, `gum_profiler_get_worst_case_duration_of`, `gum_profiler_get_worst_case_info_of`:  These function calls are the *core* of the profiling functionality being tested. They suggest actions like instrumenting functions (injecting code to track execution) and retrieving profiling data.
* `sleepy_function`, `example_a`, `example_b`, `recursive_function`, etc.: These look like simple example functions used for testing.
* `g_assert_cmpint`, `g_assert_cmpuint`, `g_assert_cmpstr`: Assertion macros, common in testing frameworks.
* `g_thread_new`, `g_thread_join`: Functions related to multi-threading.
* `assert_same_xml`: A custom assertion likely comparing generated XML output.

**3. Inferring Functionality:**

Based on the keywords, I can deduce the following:

* **Purpose:** This code tests a profiling library (`GumProfiler`). It's not the profiler itself, but rather a suite of tests for it.
* **Instrumentation:** The library likely works by "instrumenting" functions – adding code to the beginning and end (or at key points) to record entry/exit times, potentially other information.
* **Data Collection:**  It collects data like the number of times a function is called, the total time spent in the function, and potentially worst-case scenarios.
* **Reporting:**  The `REPORT_TESTCASE` and XML-related assertions suggest the profiler can generate reports, possibly in XML format.
* **Multi-threading Support:**  The presence of thread-related functions indicates the profiler can handle multi-threaded applications.

**4. Connecting to Reverse Engineering:**

* **Dynamic Analysis:** Profiling is a classic dynamic analysis technique. By running the code and observing its behavior, we can gain insights into performance bottlenecks, function call sequences, and execution paths. This is directly related to reverse engineering, where understanding how a program behaves is crucial.
* **Identifying Bottlenecks:** The tests like `bottleneck` and `bottlenecks` demonstrate how profiling can pinpoint performance issues, which is valuable in understanding and optimizing software, including reverse-engineering targets.
* **Understanding Control Flow:**  The tests with recursion and nested calls show how profiling can help visualize the call stack and understand the order of execution.

**5. Linking to Low-Level Concepts:**

* **Binary Instrumentation:** The act of inserting code into existing functions requires knowledge of the target architecture's instruction set and executable file format. Frida, as a dynamic instrumentation tool, operates at this level.
* **Memory Management:**  The profiler needs to manage memory to store profiling data.
* **Threads and Processes:**  Understanding operating system concepts like threads and how they are managed is essential for a multi-threaded profiler.
* **System Calls (Implicit):** While not explicitly shown in this snippet, a real-world profiler might rely on system calls to get accurate time measurements.

**6. Considering Linux/Android Kernel & Frameworks:**

* **Kernel Interaction (Implicit):** While this snippet is at the user-space level, the underlying profiler likely interacts with the kernel for timekeeping and potentially for accessing execution information. On Android, this could involve interacting with the Android Runtime (ART).
* **Framework Usage (Implicit):** Depending on what's being profiled, the target application might use specific frameworks (e.g., UI frameworks on Android). The profiler would need to work within that context.

**7. Developing Assumptions and Examples (Logical Reasoning):**

* **Hypothesis about `gum_profiler_instrument_function`:** I assumed this function modifies the target function's code to insert profiling probes. The `GUM_INSTRUMENT_OK`, `GUM_INSTRUMENT_WRONG_SIGNATURE`, and `GUM_INSTRUMENT_WAS_INSTRUMENTED` return values support this.
* **Input/Output Examples:**  I created scenarios (e.g., calling `sleepy_function`) and predicted the output based on the function names and the `g_assert_cmpuint` calls. For example, calling `sleepy_function` once should result in a `total_duration` of 1000.
* **XML Output:**  I analyzed the `assert_same_xml` calls and the structure of the XML to understand how the profiling data is represented.

**8. Identifying Potential User Errors:**

* **Incorrect Function Signature:** The `i_can_has_instrumentability` test explicitly checks for this, showing a common error.
* **Instrumenting the Same Function Twice:** The `already_instrumented` test highlights that attempting to instrument a function that's already instrumented will result in a specific error.
* **Not Running the Instrumented Code:**  If the user instruments a function but doesn't execute it, the profiler won't collect any data.

**9. Tracing User Steps (Debugging):**

I considered how a developer using Frida might arrive at this test code:

* **Developing Frida:** They are actively working on the Frida framework.
* **Implementing Profiling:** They are building or extending the profiling functionality within Frida.
* **Writing Unit Tests:**  They are writing tests to ensure the profiler works correctly. This specific file is a unit test file.
* **Debugging Test Failures:** If a test fails, they would examine the code in this file to understand why the assertions are failing.

**Self-Correction/Refinement:**

Initially, I might have focused too much on the specific functions being tested (e.g., `sleepy_function`). I realized that the *structure* and *intent* of the code (testing a profiler) were more important for a high-level understanding. I also made sure to explicitly link the concepts to reverse engineering and low-level details, as requested. The examples were refined to be clear and directly related to the test cases.
这个 `profiler.c` 文件是 Frida 工具中 `frida-gum` 子项目下的一个测试文件，专门用于测试 `GumProfiler` 的功能。 `GumProfiler` 是 Frida 的一个核心组件，用于动态分析目标进程的函数调用和性能。

下面详细列举一下它的功能，并结合逆向、底层知识、逻辑推理以及用户常见错误进行说明：

**1. 功能列表:**

* **函数插桩 (Instrumentation):**  测试 `gum_profiler_instrument_function` 函数，验证其能否成功地在目标函数中插入探针代码，以便在函数执行时记录相关信息。
* **重复插桩检测:** 测试 `gum_profiler_instrument_function`  对于已经插桩的函数是否能正确处理，并返回 `GUM_INSTRUMENT_WAS_INSTRUMENTED` 错误码。
* **基本函数调用跟踪:**  测试对于简单的、非嵌套的函数调用 (`flat_function`)，`GumProfiler` 是否能正确记录调用次数和总执行时间。
* **多次函数调用跟踪:** 测试对于同一个函数多次调用的情况 (`two_calls`)，`GumProfiler` 能否正确累加执行时间和调用次数。
* **调用链分析 (Bottleneck Detection):**  通过 `REPORT_TESTCASE` 标记的测试用例，测试 `GumProfiler` 分析函数调用链的能力，例如找出执行时间最长的路径和“瓶颈”函数 (`bottleneck`, `bottlenecks`)。
* **调用深度分析:** 测试 `GumProfiler`  能否记录函数调用的深度 (`child_depth`)。
* **递归调用处理:** 测试 `GumProfiler` 对于递归函数的处理能力 (`recursion`, `deep_recursion`, `cyclic_recursion`)，包括正确记录调用次数和时间，以及避免无限循环。
* **最坏情况分析 (Worst Case Analysis):** 测试 `GumProfiler` 能够识别并记录函数调用链中的最长执行路径和相关信息 (`worst_case_duration`, `worst_case_info`, `worst_case_info_on_recursion`)。
* **基于名称匹配的插桩:** 测试 `gum_profiler_instrument_functions_matching` 函数，验证其能否根据通配符匹配多个函数进行插桩 (`profile_matching_functions`)。
* **多线程支持:** 测试 `GumProfiler` 在多线程环境下的工作情况 (`xml_multiple_threads`)，能否正确区分和记录不同线程的函数调用信息。
* **XML 报告生成:**  测试 `GumProfiler` 生成 XML 格式的性能分析报告的能力 (`xml_basic`, `xml_loop`, `xml_loop_implicit`, `xml_multiple_threads`, `xml_worst_case_info`, `xml_thread_ordering`)，报告中包含函数调用关系、执行时间、调用次数等信息。
* **自定义信息注入:** 测试使用 `gum_profiler_instrument_function_with_inspector` 函数，在插桩时可以指定一个回调函数 (`inspect_worst_case_info`, `inspect_recursive_worst_case_info`) 来收集额外的用户自定义信息，并将其包含在分析报告中。

**2. 与逆向方法的关联及举例:**

这个文件直接测试了 Frida 动态插桩的核心功能，而动态插桩是逆向工程中非常重要的技术。

* **动态分析:** 通过插桩目标程序，逆向工程师可以在程序运行时观察函数的调用顺序、执行时间、参数和返回值，从而理解程序的行为和逻辑。例如，`bottleneck` 测试用例模拟了通过分析调用链找到性能瓶颈的场景，逆向工程师可以用类似的方法找到目标程序中耗时较长的函数，并进一步分析其实现。
* **恶意代码分析:** 分析恶意软件时，可以使用 Frida 的 Profiler 功能来快速定位恶意行为发生的函数，例如网络连接、文件操作、注册表修改等相关的函数。
* **漏洞挖掘:** 通过监控程序的执行流程和函数调用，逆向工程师可以发现潜在的漏洞，例如缓冲区溢出、整数溢出等。`worst_case_duration` 这样的测试用例可以帮助理解在特定执行路径下可能出现的最坏情况。
* **理解未知代码:**  对于没有源码的二进制程序，Profiler 可以帮助逆向工程师理解程序的内部结构和运行机制，例如通过观察函数之间的调用关系来推断程序的功能模块。

**3. 涉及的二进制底层、Linux、Android 内核及框架知识及举例:**

* **二进制底层:**
    * **指令注入:** `gum_profiler_instrument_function` 的核心在于修改目标函数的机器码，插入额外的指令（通常是跳转指令）来执行 Profiler 的探针代码。这需要对目标平台的指令集架构 (例如 x86, ARM) 有深入的理解。 `i_can_has_instrumentability` 测试用例中，尝试插桩 `unsupported_functions`，并断言返回 `GUM_INSTRUMENT_WRONG_SIGNATURE`，这可能与目标函数的调用约定或代码结构不兼容有关，涉及到对二进制代码的理解。
    * **调用约定:**  不同的平台和编译器有不同的函数调用约定（例如 cdecl, stdcall）。Profiler 需要能够处理这些不同的约定，确保在函数入口和出口正确地保存和恢复寄存器状态。`profile_matching_functions` 测试用例中使用了 `exclude_simple_stdcall_50` 函数作为排除条件，暗示了对调用约定的考虑。
* **Linux/Android 内核:**
    * **进程管理:** Frida 需要与目标进程进行交互，进行内存读写、代码注入等操作，这涉及到操作系统提供的进程管理相关的 API (例如 `ptrace` on Linux)。
    * **内存管理:**  Profiler 需要在目标进程的内存空间中分配和管理用于存储 profiling 数据的结构。
    * **线程管理:**  对于多线程程序，Profiler 需要能够正确地跟踪和区分不同线程的执行情况。这需要理解操作系统提供的线程管理机制。`xml_multiple_threads` 测试用例模拟了多线程场景。
* **Android 框架:**
    * **ART/Dalvik 虚拟机:** 如果目标是 Android 应用，Frida 需要与 Android 运行时环境 (ART 或 Dalvik) 进行交互，Hook Java 或 Native 函数。
    * **系统服务:** Android 应用通常会调用各种系统服务，Profiler 可以用于跟踪这些跨进程的调用。

**4. 逻辑推理、假设输入与输出:**

以 `flat_function` 测试用例为例：

* **假设输入:**
    * 调用 `gum_profiler_instrument_function(prof, &sleepy_function, fixture->sampler)`，成功插桩 `sleepy_function`。
    * 调用 `sleepy_function(fixture->fake_sampler)` 一次。
* **逻辑推理:**
    * 插桩后，当 `sleepy_function` 被调用时，Profiler 的探针代码会被执行。
    * `sleepy_function` 内部模拟了 1000 单位的执行时间。
    * Profiler 会记录到有一个线程执行了 `sleepy_function`。
    * Profiler 会记录到该线程执行 `sleepy_function` 的总时间为 1000。
* **预期输出:**
    * `gum_profiler_get_number_of_threads(prof)` 返回 1。
    * `gum_profiler_get_total_duration_of(prof, 0, &sleepy_function)` 返回 1000。

以 `xml_basic` 测试用例为例：

* **假设输入:**
    * `example_a` 函数被插桩。
    * 调用 `example_a(fixture->fake_sampler)`。
* **逻辑推理:**
    * 查看 `example_a` 的实现 (在 `profiler-fixture.c` 中)，可以知道它会调用 `example_c`。
    * `example_a` 模拟执行时间 9，`example_c` 模拟执行时间 4。
    * Profiler 会记录 `example_a` 调用了 `example_c`。
* **预期输出:**  `assert_same_xml` 断言生成的 XML 报告内容如下:
  ```xml
  <ProfileReport>
    <Thread>
      <Node name="example_a" total_calls="1" total_duration="9">
        <WorstCase duration="9"></WorstCase>
        <Node name="example_c" total_calls="1" total_duration="4">
          <WorstCase duration="4"></WorstCase>
        </Node>
      </Node>
    </Thread>
  </ProfileReport>
  ```

**5. 涉及用户或者编程常见的使用错误及举例:**

* **尝试插桩签名不兼容的函数:**  `i_can_has_instrumentability` 测试用例模拟了这种情况，如果尝试插桩一个签名与 Profiler 预期不符的函数，会返回错误码。用户可能错误地尝试插桩一些特殊类型的函数，例如使用了变长参数列表或者特殊的调用约定。
* **重复插桩同一个函数:** `already_instrumented` 测试用例表明，重复插桩同一个函数会导致错误。用户可能在不清楚函数是否已经被插桩的情况下再次进行插桩操作。
* **忘记运行被插桩的代码:** 用户可能成功插桩了函数，但是没有执行到这些代码路径，导致 Profiler 没有收集到任何数据。
* **在多线程环境下使用 Profiler 但未正确处理线程上下文:**  虽然 Profiler 自身支持多线程，但用户在分析多线程程序时需要理解不同线程的执行情况，并正确地使用 Profiler 提供的 API 来获取特定线程的数据。
* **误解 Profiler 的输出:** 用户可能对 Profiler 生成的报告理解有偏差，例如将总执行时间误解为函数自身的执行时间，而忽略了子函数的调用时间。

**6. 用户操作如何一步步到达这里作为调试线索:**

这个 `profiler.c` 文件是 Frida 开发团队编写的单元测试代码，普通用户在直接使用 Frida 工具时通常不会直接接触到这个文件。但是，作为调试线索，以下步骤可能导致开发者或高级用户接触到这个文件：

1. **Frida 开发和贡献者:** 如果有开发者正在为 Frida 贡献代码，特别是涉及到 Profiler 功能的开发或 bug 修复，他们会阅读、修改和运行这个测试文件，以验证其代码的正确性。
2. **Frida 内部原理研究:**  对 Frida 内部实现感兴趣的高级用户或安全研究人员，可能会深入研究 Frida 的源代码，包括这个测试文件，以了解 Profiler 的工作机制和实现细节。
3. **Profiler 功能调试:** 如果在使用 Frida 的 Profiler 功能时遇到问题，例如数据不准确或程序崩溃，开发者可能会查看这个测试文件，了解 Frida 团队是如何测试 Profiler 的，并参考测试用例来编写自己的调试代码。他们可能会尝试修改 `profiler-fixture.c` 中定义的示例函数或者添加新的测试用例来复现和解决问题。
4. **构建和测试 Frida:** 在构建 Frida 工具的过程中，会执行这些单元测试，以确保构建出的 Frida 版本功能正常。如果测试失败，开发者需要查看失败的测试用例代码（包括这个文件）来定位问题。

总而言之，`frida/subprojects/frida-gum/tests/prof/profiler.c` 是 Frida Profiler 功能的核心测试代码，它涵盖了 Profiler 的各种功能和使用场景，对于理解 Frida 的动态插桩机制和进行相关开发调试具有重要的参考价值。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/prof/profiler.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2008-2010 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "profiler-fixture.c"

#ifdef HAVE_WINDOWS

TESTLIST_BEGIN (profiler)
#ifdef HAVE_I386
  TESTENTRY (i_can_has_instrumentability)
#endif
  TESTENTRY (already_instrumented)

  TESTENTRY (flat_function)
  TESTENTRY (two_calls)
  TESTENTRY (profile_matching_functions)
  TESTENTRY (recursion)
  TESTENTRY (deep_recursion)
  TESTENTRY (worst_case_duration)
  TESTENTRY (worst_case_info)
  TESTENTRY (worst_case_info_on_recursion)

  REPORT_TESTENTRY (bottleneck)
  REPORT_TESTENTRY (bottlenecks)
  REPORT_TESTENTRY (child_depth)
  REPORT_TESTENTRY (cyclic_recursion)
  REPORT_TESTENTRY (xml_basic)
  REPORT_TESTENTRY (xml_loop)
  REPORT_TESTENTRY (xml_loop_implicit)
  REPORT_TESTENTRY (xml_multiple_threads)
  REPORT_TESTENTRY (xml_worst_case_info)
  REPORT_TESTENTRY (xml_thread_ordering)
TESTLIST_END ()

#ifdef HAVE_I386

TESTCASE (i_can_has_instrumentability)
{
  UnsupportedFunction * unsupported_functions;
  guint count;

  unsupported_functions = unsupported_function_list_new (&count);

  g_assert_cmpint (gum_profiler_instrument_function (fixture->profiler,
      unsupported_functions[0].code, fixture->sampler), ==,
      GUM_INSTRUMENT_WRONG_SIGNATURE);

  unsupported_function_list_free (unsupported_functions);
}

#endif

TESTCASE (already_instrumented)
{
  g_assert_cmpint (gum_profiler_instrument_function (fixture->profiler,
      &sleepy_function, fixture->sampler), ==, GUM_INSTRUMENT_OK);
  g_assert_cmpint (gum_profiler_instrument_function (fixture->profiler,
      &sleepy_function, fixture->sampler), ==,
      GUM_INSTRUMENT_WAS_INSTRUMENTED);
}

TESTCASE (flat_function)
{
  GumProfiler * prof = fixture->profiler;

  g_assert_cmpint (gum_profiler_instrument_function (prof,
      &sleepy_function, fixture->sampler), ==, GUM_INSTRUMENT_OK);

  g_assert_cmpuint (gum_profiler_get_number_of_threads (prof), ==, 0);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (prof, 0,
      &sleepy_function), ==, 0);

  sleepy_function (fixture->fake_sampler);

  g_assert_cmpuint (gum_profiler_get_number_of_threads (prof), ==, 1);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (prof, 0,
      &sleepy_function), ==, 1000);
}

TESTCASE (two_calls)
{
  GumProfiler * prof = fixture->profiler;

  gum_profiler_instrument_function (prof, &sleepy_function, fixture->sampler);

  g_assert_cmpuint (gum_profiler_get_number_of_threads (prof), ==, 0);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (prof, 0,
      &sleepy_function), ==, 0);

  sleepy_function (fixture->fake_sampler);
  sleepy_function (fixture->fake_sampler);

  g_assert_cmpuint (gum_profiler_get_number_of_threads (prof), ==, 1);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (prof, 0,
      &sleepy_function), ==, 2 * 1000);
}

REPORT_TESTCASE (bottleneck)
{
  instrument_example_functions (fixture);

  example_a (fixture->fake_sampler);

  assert_n_top_nodes (fixture, 1, "example_a", "example_c");
}

REPORT_TESTCASE (bottlenecks)
{
  instrument_example_functions (fixture);

  example_a (fixture->fake_sampler);
  example_d (fixture->fake_sampler);

  assert_n_top_nodes (fixture, 2,
      "example_d", "example_c",
      "example_a", "example_c");
}

REPORT_TESTCASE (child_depth)
{
  instrument_example_functions (fixture);

  example_e (fixture->fake_sampler);

  assert_n_top_nodes (fixture, 1, "example_e", "example_f");
  assert_depth_from_root_node (fixture, 0, "example_e", "example_f",
      "example_g", NULL);
}

REPORT_TESTCASE (cyclic_recursion)
{
  instrument_example_functions (fixture);

  example_cyclic_a (fixture->fake_sampler, 1);

  assert_n_top_nodes (fixture, 1, "example_cyclic_a", "example_cyclic_b");
  assert_depth_from_root_node (fixture, 0, "example_cyclic_a",
      "example_cyclic_b", NULL);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (fixture->profiler, 0,
      &example_cyclic_a), ==, 4);
}

REPORT_TESTCASE (xml_basic)
{
  instrument_example_functions (fixture);

  example_a (fixture->fake_sampler);

  assert_same_xml (fixture,
      "<ProfileReport>"
        "<Thread>"
          "<Node name=\"example_a\" total_calls=\"1\" total_duration=\"9\">"
            "<WorstCase duration=\"9\"></WorstCase>"
            "<Node name=\"example_c\" total_calls=\"1\" total_duration=\"4\">"
              "<WorstCase duration=\"4\"></WorstCase>"
            "</Node>"
          "</Node>"
        "</Thread>"
      "</ProfileReport>");
}

REPORT_TESTCASE (xml_loop)
{
  instrument_example_functions (fixture);

  example_cyclic_a (fixture->fake_sampler, 1);

  assert_same_xml (fixture,
      "<ProfileReport>"
        "<Thread>"
          "<Node name=\"example_cyclic_a\" total_calls=\"2\" "
              "total_duration=\"4\">"
            "<WorstCase duration=\"4\"></WorstCase>"
            "<Node name=\"example_cyclic_b\" total_calls=\"1\" "
                "total_duration=\"3\">"
              "<WorstCase duration=\"3\"></WorstCase>"
            "</Node>"
          "</Node>"
        "</Thread>"
      "</ProfileReport>");
}

REPORT_TESTCASE (xml_loop_implicit)
{
  instrument_example_functions (fixture);

  example_cyclic_a (fixture->fake_sampler, 1);
  example_cyclic_b (fixture->fake_sampler, 0);

  assert_same_xml (fixture,
      "<ProfileReport>"
        "<Thread>"
          "<Node name=\"example_cyclic_b\" total_calls=\"2\" "
              "total_duration=\"6\">"
            "<WorstCase duration=\"3\"></WorstCase>"
            "<Node name=\"example_cyclic_a\" total_calls=\"3\" "
                "total_duration=\"5\">"
              "<WorstCase duration=\"4\"></WorstCase>"
            "</Node>"
          "</Node>"
          "<Node name=\"example_cyclic_a\" total_calls=\"3\" "
              "total_duration=\"5\">"
            "<WorstCase duration=\"4\"></WorstCase>"
            "<Node name=\"example_cyclic_b\" total_calls=\"2\" "
                "total_duration=\"6\">"
              "<WorstCase duration=\"3\"></WorstCase>"
            "</Node>"
          "</Node>"
        "</Thread>"
      "</ProfileReport>");
}

REPORT_TESTCASE (xml_multiple_threads)
{
  instrument_example_functions (fixture);

  example_a (fixture->fake_sampler);
  g_thread_join (g_thread_new ("profiler-test-multiple-threads",
      (GThreadFunc) example_d, fixture->fake_sampler));

  assert_same_xml (fixture,
      "<ProfileReport>"
        "<Thread>"
          "<Node name=\"example_d\" total_calls=\"1\" total_duration=\"11\">"
            "<WorstCase duration=\"11\"></WorstCase>"
            "<Node name=\"example_c\" total_calls=\"1\" total_duration=\"4\">"
              "<WorstCase duration=\"4\"></WorstCase>"
            "</Node>"
          "</Node>"
        "</Thread>"
        "<Thread>"
          "<Node name=\"example_a\" total_calls=\"1\" total_duration=\"9\">"
            "<WorstCase duration=\"9\"></WorstCase>"
            "<Node name=\"example_c\" total_calls=\"1\" total_duration=\"4\">"
              "<WorstCase duration=\"4\"></WorstCase>"
            "</Node>"
          "</Node>"
        "</Thread>"
      "</ProfileReport>");
}

REPORT_TESTCASE (xml_worst_case_info)
{
  gum_profiler_instrument_function_with_inspector (fixture->profiler,
      &example_worst_case_info, fixture->sampler, inspect_worst_case_info,
      NULL);

  example_worst_case_info (fixture->fake_sampler, "early", 1);
  example_worst_case_info (fixture->fake_sampler, "mid", 3);
  example_worst_case_info (fixture->fake_sampler, "late", 2);

  assert_same_xml (fixture,
      "<ProfileReport>"
        "<Thread>"
          "<Node name=\"example_worst_case_info\" total_calls=\"3\" "
              "total_duration=\"6\">"
            "<WorstCase duration=\"3\">mid</WorstCase>"
          "</Node>"
        "</Thread>"
      "</ProfileReport>");
}

REPORT_TESTCASE (xml_thread_ordering)
{
  instrument_simple_functions (fixture);

  simple_1 (fixture->fake_sampler);
  g_thread_join (g_thread_new ("profiler-test-helper-a",
      (GThreadFunc) simple_2, fixture->fake_sampler));
  g_thread_join (g_thread_new ("profiler-test-helper-b",
      (GThreadFunc) simple_3, fixture->fake_sampler));

  assert_same_xml (fixture,
      "<ProfileReport>"
        "<Thread>"
          "<Node name=\"simple_3\" total_calls=\"1\" total_duration=\"3\">"
            "<WorstCase duration=\"3\"></WorstCase>"
          "</Node>"
        "</Thread>"
        "<Thread>"
          "<Node name=\"simple_2\" total_calls=\"1\" total_duration=\"2\">"
            "<WorstCase duration=\"2\"></WorstCase>"
          "</Node>"
        "</Thread>"
        "<Thread>"
          "<Node name=\"simple_1\" total_calls=\"1\" total_duration=\"1\">"
            "<WorstCase duration=\"1\"></WorstCase>"
          "</Node>"
        "</Thread>"
      "</ProfileReport>");
}

TESTCASE (profile_matching_functions)
{
  gum_profiler_instrument_functions_matching (fixture->profiler, "simple_*",
      fixture->sampler, exclude_simple_stdcall_50, NULL);

  simple_cdecl_42 (fixture->fake_sampler);
  simple_stdcall_48 (fixture->fake_sampler);
  simple_stdcall_50 (fixture->fake_sampler);

  g_assert_cmpuint (gum_profiler_get_total_duration_of (fixture->profiler, 0,
      &simple_cdecl_42), ==, 42);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (fixture->profiler, 0,
      &simple_stdcall_48), ==, 48);
  g_assert_cmpuint (gum_profiler_get_total_duration_of (fixture->profiler, 0,
      &simple_stdcall_50), ==, 0);
}

TESTCASE (recursion)
{
  gum_profiler_instrument_function (fixture->profiler, &recursive_function,
      fixture->sampler);
  recursive_function (2);
}

TESTCASE (deep_recursion)
{
  gum_profiler_instrument_function (fixture->profiler,
      &deep_recursive_function, fixture->sampler);
  gum_profiler_instrument_function (fixture->profiler,
      &deep_recursive_caller, fixture->sampler);
  deep_recursive_function (3);
}

TESTCASE (worst_case_duration)
{
  gum_profiler_instrument_function (fixture->profiler,
      &example_a_calls_b_thrice, fixture->sampler);
  gum_profiler_instrument_function (fixture->profiler,
      &example_b_dynamic, fixture->sampler);

  g_assert_cmpuint (gum_profiler_get_worst_case_duration_of (fixture->profiler,
      0, &example_b_dynamic), ==, 0);

  example_a_calls_b_thrice (fixture->fake_sampler);

  g_assert_cmpuint (gum_profiler_get_worst_case_duration_of (fixture->profiler,
      0, &example_b_dynamic), ==, 3);
}

TESTCASE (worst_case_info)
{
  gum_profiler_instrument_function_with_inspector (fixture->profiler,
      &example_worst_case_info, fixture->sampler, inspect_worst_case_info,
      NULL);

  g_assert_cmpstr (gum_profiler_get_worst_case_info_of (fixture->profiler, 0,
      &example_worst_case_info), ==, "");

  example_worst_case_info (fixture->fake_sampler, "early", 1);
  example_worst_case_info (fixture->fake_sampler, "mid", 3);
  example_worst_case_info (fixture->fake_sampler, "late", 2);

  g_assert_cmpstr (gum_profiler_get_worst_case_info_of (fixture->profiler, 0,
      &example_worst_case_info), ==, "mid");
}

TESTCASE (worst_case_info_on_recursion)
{
  gum_profiler_instrument_function_with_inspector (fixture->profiler,
      &example_worst_case_recursive, fixture->sampler,
      inspect_recursive_worst_case_info, NULL);

  example_worst_case_recursive (2, fixture->fake_sampler);

  g_assert_cmpstr (gum_profiler_get_worst_case_info_of (fixture->profiler, 0,
      &example_worst_case_recursive), ==, "2");
}

#endif /* HAVE_WINDOWS */
```