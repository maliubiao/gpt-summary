Response:
Let's break down the thought process for analyzing the `gumtest.c` file and addressing the prompt's requirements.

**1. Understanding the Goal:**

The core objective is to analyze the `gumtest.c` file, identify its functionalities, and relate them to specific concepts like reverse engineering, low-level programming, kernel interactions, common user errors, and debugging.

**2. Initial Scan and Keyword Identification:**

The first step is to quickly scan the code for significant keywords and patterns. This immediately reveals:

* **Test Framework:**  The use of `g_test_init`, `TESTLIST_REGISTER`, `g_test_run` clearly indicates this is a test suite. The file's name, `gumtest.c`, reinforces this.
* **Frida/Gum Specifics:** Includes like `gum.h`, `gumscriptbackend.h`, `interceptor.h`, `stalker.h` point to Frida's Gum library and its components for dynamic instrumentation.
* **Operating System Dependencies:**  `#ifdef` directives for `HAVE_WINDOWS`, `HAVE_DARWIN`, `HAVE_ANDROID`, `HAVE_IOS`, `HAVE_QNX` signal platform-specific code and functionalities.
* **Low-Level Components:** Includes like `capstone.h` (disassembly), potential memory management functions (`gum_malloc`, `gum_free`), and signal handling functions suggest interaction with lower levels of the system.
* **Dynamic Libraries:**  Use of `dlopen` (on some platforms) hints at interaction with shared libraries.
* **Debugging/Memory Management:**  `DEBUG_HEAP_LEAKS`, `_CrtSetDbgFlag` (Windows), `RUNNING_ON_VALGRIND`, `HAVE_ASAN` indicate features related to debugging and memory safety.
* **Scripting:** `HAVE_GUMJS`, `GumScriptBackend` suggest the ability to test JavaScript integration.

**3. Functional Breakdown (Grouping by Keyword/Concept):**

Based on the initial scan, I can start grouping functionalities:

* **Core Testing:** Setting up the test environment, registering test cases, running tests, and reporting results. This is the primary function of the `main` function.
* **Dynamic Instrumentation (Frida/Gum):**  Testing core Gum features like interception, stalking, memory access monitoring, API resolution, and backtracing. The `TESTLIST_REGISTER` calls for modules like `interceptor`, `stalker`, etc., confirm this.
* **Platform-Specific Testing:** The `#ifdef` blocks reveal tests tailored to specific operating systems, potentially due to OS-specific APIs or behaviors related to dynamic instrumentation.
* **Memory Management Testing:**  Testing allocation tracking, allocator probing (Windows), bounds checking, and sanity checks. This is evident from the `allocation_tracker`, `allocator_probe`, `boundschecker`, etc., registrations.
* **Scripting Engine Testing:** Testing the integration with JavaScript engines (QuickJS and V8) through the `script` and `kscript` test registrations.
* **Low-Level Utilities:** Testing utilities like writers and relocators for different architectures (x86, ARM, ARM64), which are essential for code manipulation during instrumentation.
* **Debugging and Memory Safety:** Setting up heap leak detection (Windows), integrating with Valgrind, and handling AddressSanitizer (ASAN) requirements.

**4. Relating to Reverse Engineering:**

* **Interception:** The `interceptor` tests directly relate to the core of dynamic instrumentation used in reverse engineering. It validates Frida's ability to hook and modify function calls.
* **Stalker:** The `stalker` tests relate to tracing execution flow, a critical technique in reverse engineering to understand program behavior.
* **Memory Access Monitoring:** Tests for `memoryaccessmonitor` are relevant for understanding how a program interacts with memory, useful for finding vulnerabilities or understanding data flow.
* **API Resolver:** Testing the `api_resolver` is important for reverse engineers who need to understand which system or library functions an application is using.
* **Backtracer:** Testing the `backtracer` is essential for debugging and understanding the call stack during reverse engineering.
* **Disassembly/Relocation:** The tests for `x86writer`, `armwriter`, `arm64writer`, and their corresponding relocators are fundamental for understanding how Frida manipulates code at the assembly level.

**5. Relating to Binary/Kernel/Framework:**

* **Binary Level:** The tests for writers and relocators directly interact with binary code and instruction encoding.
* **Operating System Kernels:**  The platform-specific tests (e.g., `interceptor_darwin`, `interceptor_android`) often interact with OS kernel features related to process management, memory, and signal handling. The `dlopen` calls and the iOS entitlement code are examples.
* **Frameworks:**  The Darwin-specific code that loads the Foundation framework demonstrates interaction with higher-level OS frameworks.

**6. Logical Reasoning (Assumptions and Outputs):**

While this file is primarily for testing, logical reasoning comes into play when understanding the test structure. For example:

* **Assumption:** Each `TESTLIST_REGISTER` call registers a suite of related tests.
* **Input:** Running the `gumtest` executable.
* **Output:** A series of pass/fail messages for each registered test, and a summary of the total tests run and the time taken.

**7. Common User Errors:**

* **Incorrect Environment Setup:** The ASAN warning highlights a common mistake where users might not disable ASAN's segv handling, which interferes with Frida's exception handling tests.
* **Missing Dependencies:**  If the required libraries (like `libjailbreak.dylib` on iOS) are not present, certain tests might fail or behave unexpectedly.
* **Debugger Interference:** The note about skipping BoundsChecker tests when a debugger is attached illustrates a scenario where the testing environment needs to be carefully considered.

**8. Debugging and User Steps:**

* **Compilation:** The user first needs to compile the Frida Gum library, which will include building this `gumtest.c` file. This typically involves using build systems like CMake or Meson.
* **Execution:** The user then executes the compiled `gumtest` binary from the command line.
* **Test Output:** The output of the execution provides debugging information, indicating which tests passed or failed. Failed tests are the starting point for further investigation.
* **Analyzing Failures:**  Developers would then look at the specific failed test case, examine the corresponding test code, and use debugging tools (like GDB or lldb) or logging to understand why the test failed. The `g_assert_*` macros within the test code are crucial for identifying discrepancies.

**Self-Correction/Refinement during the Process:**

Initially, I might focus too heavily on the low-level aspects. However, recognizing the overarching structure as a test suite helps to prioritize understanding the testing framework (`g_test`) before diving into individual test cases. Also, noticing the platform-specific `#ifdef` blocks early on is crucial for understanding that the functionality isn't monolithic and varies across operating systems. Finally, connecting the individual test modules back to the core concepts of Frida (interception, stalking, etc.) provides a higher-level understanding of the file's purpose.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/tests/gumtest.c` 这个文件。

**文件功能总览**

`gumtest.c` 是 Frida Dynamic Instrumentation 工具的核心组件 Frida-Gum 的一个测试套件的主程序文件。它的主要功能是：

1. **注册并运行 Frida-Gum 的各种单元测试和集成测试。** 这些测试覆盖了 Frida-Gum 库的各个模块，例如：
    * **核心功能:**  TLS (线程局部存储), Cloak (隐藏技术), 内存管理, 进程操作, 符号工具, 代码写入器 (针对 x86, ARM, ARM64), 代码重定位器, 代码拦截器, 内存访问监控器, Stalker (代码跟踪器), API 解析器, Backtracer (调用栈回溯)。
    * **堆管理:**  Allocation Tracker (分配跟踪), Allocator Probe (分配器探测 - Windows), CObjectTracker (C++ 对象跟踪 - Windows), InstanceTracker (实例跟踪 - Windows), Page Pool (页面池), BoundsChecker (边界检查), SanityChecker (健全性检查 - Windows)。
    * **性能分析:** Sampler (采样器), Profiler (性能分析器 - Windows)。
    * **脚本引擎集成:**  GumJS (JavaScript 引擎集成，支持 QuickJS 和 V8)。
    * **Gum++ (C++ 绑定):**  Gum++ Backtracer。
2. **初始化和清理测试环境。** 这包括初始化 Frida-Gum 库，设置 GLib 库，处理平台特定的初始化 (例如，在 macOS 上加载 Foundation 框架，在 iOS 上进行授权)，以及在测试结束后进行清理工作。
3. **处理与操作系统相关的配置。** 例如，根据不同的操作系统启用或禁用某些测试，或者设置特定的环境变量。
4. **提供一些辅助函数和宏。** 例如 `TESTLIST_REGISTER` 用于注册测试套件。
5. **处理一些调试和内存管理相关的设置。** 例如，支持检测内存泄漏 (Windows)，与 Valgrind 集成，处理 AddressSanitizer (ASAN) 的配置。

**与逆向方法的关系及举例说明**

`gumtest.c` 本身不是直接进行逆向操作的工具，但它测试的 Frida-Gum 库是进行动态逆向分析的核心。许多测试用例直接验证了 Frida-Gum 在逆向分析中常用的功能：

* **代码拦截 (Interceptor):**  测试用例会验证 Frida-Gum 是否能够成功拦截目标进程中的函数调用，并在调用前后执行自定义的代码。这在逆向分析中用于：
    * **Hook 关键 API:** 截获对敏感 API 的调用，例如文件操作、网络通信、加密解密等，以监控和修改其行为。
    * **修改函数参数或返回值:** 在函数执行前后修改其输入或输出，以探索不同的执行路径或绕过安全检查。
    * **注入自定义逻辑:** 在目标进程中插入额外的代码，以实现日志记录、功能增强或行为修改。
* **代码跟踪 (Stalker):** 测试用例验证 Frida-Gum 的 Stalker 组件能否跟踪目标进程的代码执行流程。这在逆向分析中用于：
    * **理解程序执行逻辑:** 观察函数调用顺序、基本块执行情况等，从而理解程序的运作方式。
    * **寻找特定代码路径:** 定位到负责特定功能的代码段。
    * **分析恶意代码行为:** 跟踪恶意软件的执行流程，了解其恶意行为的触发条件和执行过程。
* **内存访问监控 (MemoryAccessMonitor):** 测试用例验证 Frida-Gum 是否能够监控目标进程对特定内存区域的访问。这在逆向分析中用于：
    * **查找内存读写漏洞:** 监控对关键数据结构的访问，检测是否存在越界读写等漏洞。
    * **理解数据结构布局:** 观察程序如何读写内存，从而推断数据结构的组成和含义。
* **API 解析 (ApiResolver):** 测试用例验证 Frida-Gum 能否解析目标进程中使用的动态库符号。这在逆向分析中用于：
    * **识别使用的系统或第三方库:** 了解目标程序依赖的外部功能。
    * **查找特定 API 的地址:** 为后续的 Hook 操作提供目标地址。
* **调用栈回溯 (Backtracer):** 测试用例验证 Frida-Gum 能否获取当前函数的调用栈信息。这在逆向分析中用于：
    * **理解函数调用关系:** 了解当前函数是被哪些函数调用的。
    * **辅助定位问题:** 在调试过程中追踪代码的执行路径。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明**

`gumtest.c` 的测试用例中包含了大量与二进制底层、Linux/Android 内核及框架相关的知识：

* **二进制指令操作:**
    * **代码写入器 (x86writer, armwriter, arm64writer):** 测试用例会生成各种架构的机器码指令，并验证其正确性。这涉及到对不同 CPU 架构的指令集编码的深入理解。
    * **代码重定位器 (x86relocator, armrelocator, arm64relocator):** 测试用例验证在代码被移动到新的内存地址后，指令中的地址引用能否被正确调整。这涉及到对不同架构下指令寻址方式和重定位表的理解。
* **内存管理:**
    * **Page Pool:** 测试用例涉及到对内存页的分配和管理，这与操作系统内核的内存管理机制密切相关。
    * **BoundsChecker:** 测试用例会尝试触发内存访问越界，验证 Frida-Gum 能否检测到这些错误。这涉及到对进程内存空间布局、内存保护机制的理解。
* **进程操作:**
    * **Interceptor:** Hook 函数的实现需要在底层修改目标进程的指令流或函数入口点，这涉及到对操作系统进程管理、内存保护机制、代码注入技术的理解。
    * **Stalker:** 代码跟踪的实现需要在底层监控目标进程的执行流程，这涉及到对操作系统调度、中断、异常处理机制的理解。
* **Linux/Android 内核及框架:**
    * **信号处理:** 代码中包含对信号处理函数的调用 (`ClaimSignalChain`, `UnclaimSignalChain` 等)，这与 Linux/Android 的信号机制相关。Frida 需要处理信号以实现某些功能，例如中断代码执行。
    * **动态链接:**  在 macOS 上使用 `dlopen` 加载 Foundation 框架，反映了对动态链接机制的理解。Frida 需要与目标进程的动态链接器交互。
    * **Android 特有的信号链管理 (`ClaimSignalChain`, `UnclaimSignalChain`):** 这些函数是为 Android 特有的信号处理链机制提供的，用于确保 Frida 的信号处理程序能够正确地与系统和其他库的信号处理程序协同工作。
    * **iOS 授权 (`jb_oneshot_entitle_now`):** 在 iOS 上，Frida 需要获取特定的权限才能进行动态 instrumentation，这需要与 iOS 的安全机制进行交互。
* **CPU 架构特定知识:** 针对不同 CPU 架构 (x86, ARM, ARM64) 编写的测试用例，体现了对各自架构的寄存器、指令集、调用约定、内存模型的深入理解。

**逻辑推理及假设输入与输出**

由于 `gumtest.c` 是一个测试程序，其核心是验证各种功能的正确性。每个测试用例都包含一定的逻辑推理，例如：

* **假设输入:**  调用某个 Frida-Gum 的 API，例如 `gum_interceptor_replace` 来 Hook 一个函数。
* **预期输出:**  被 Hook 的函数在被调用时，会先执行 Frida-Gum 设定的回调函数，然后再执行原始函数 (或者不执行原始函数，取决于 Hook 的方式)。测试用例会断言 (使用 `g_assert_*` 宏) 这个行为是否符合预期。

**举例说明 Interceptor 的一个简单测试用例的逻辑推理：**

* **假设输入:**
    1. 定义一个简单的 C 函数 `int add(int a, int b) { return a + b; }`。
    2. 使用 `gum_interceptor_replace` Hook `add` 函数，替换为一个新的回调函数 `int my_add(int a, int b) { return a * b; }`。
    3. 调用原始的 `add` 函数。
* **预期输出:**
    1. 实际执行的是 `my_add` 函数。
    2. `add(2, 3)` 的返回值将是 `2 * 3 = 6`，而不是 `2 + 3 = 5`。
* **测试用例代码片段 (简化):**
   ```c
   #include <gum/gum.h>
   #include <glib.h>

   int add(int a, int b) { return a + b; }
   int my_add(GumInvocationContext * ic, int a, int b, gpointer user_data) {
       return a * b;
   }

   static void
   test_interceptor_replace (void)
   {
       GumInterceptor * interceptor = gum_interceptor_obtain();
       gum_interceptor_begin_transaction(interceptor);
       gum_interceptor_replace(interceptor, GSIZE_TO_POINTER(add), my_add, NULL);
       gum_interceptor_end_transaction(interceptor);

       g_assert_cmpint(add(2, 3), ==, 6); // 断言结果为 6
   }
   ```

**涉及用户或者编程常见的使用错误及举例说明**

`gumtest.c` 虽然主要用于测试 Frida-Gum 本身，但它间接地也反映了一些用户在使用 Frida 或类似动态 instrumentation 工具时可能遇到的错误：

* **Hook 不存在的函数地址:** 如果用户提供的 Hook 目标地址不正确 (例如，函数名拼写错误，或者库未加载)，Frida-Gum 可能会抛出异常或导致程序崩溃。测试用例会验证 Frida-Gum 在这种情况下是否能够正确处理。
* **回调函数签名不匹配:** Frida-Gum 的回调函数需要与被 Hook 函数的调用约定和参数类型匹配。如果签名不匹配，可能会导致栈破坏或其他未定义行为。测试用例会验证 Frida-Gum 能否检测到这种不匹配。
* **在回调函数中不当操作:**  例如，在回调函数中进行死循环、访问非法内存等操作，会导致目标进程不稳定。测试用例可能会模拟这些场景，验证 Frida-Gum 的健壮性。
* **忘记取消 Hook:** 如果用户在完成 instrumentation 后忘记取消 Hook，可能会导致目标进程的行为一直被修改。虽然测试用例不直接模拟这个错误，但测试 Frida-Gum 的 `gum_interceptor_revert` 功能可以间接反映如何避免这个问题。
* **多线程环境下的 Hook 问题:** 在多线程程序中进行 Hook 需要考虑线程安全和同步问题。测试用例会验证 Frida-Gum 在多线程环境下的 Hook 功能是否稳定可靠。
* **ASAN 的配置问题:**  代码中特别提到了 ASAN 的 `handle_segv` 配置，这是一个用户在使用 ASAN 进行开发和测试时经常需要注意的点。如果配置不当，可能会干扰 Frida-Gum 的异常处理测试。

**用户操作是如何一步步的到达这里，作为调试线索**

作为一个 Frida-Gum 的开发者或贡献者，或者一个想要深入了解 Frida-Gum 内部机制的用户，可能会按照以下步骤接触到 `gumtest.c`：

1. **克隆 Frida 的源代码仓库:**  用户首先需要从 GitHub 上克隆 Frida 的源代码。
2. **浏览源代码:**  用户可能出于以下目的浏览源代码：
    * **学习 Frida-Gum 的使用方法:** 查看测试用例可以了解如何使用 Frida-Gum 的各种 API。
    * **理解 Frida-Gum 的内部实现:** 测试用例通常会覆盖核心功能，可以帮助理解代码是如何工作的。
    * **调试 Frida-Gum 的问题:** 当 Frida-Gum 出现 Bug 时，开发者可能会查看相关的测试用例，或者编写新的测试用例来复现和修复 Bug。
    * **贡献代码:**  如果用户想要为 Frida-Gum 贡献新的功能或修复 Bug，通常需要编写相应的测试用例来验证代码的正确性。
3. **定位到 `gumtest.c`:**  用户会根据要了解或调试的 Frida-Gum 组件，在源代码目录结构中找到对应的测试文件。`gumtest.c` 作为主测试程序，是了解 Frida-Gum 整体测试情况的入口。
4. **阅读和分析测试用例:** 用户会阅读 `gumtest.c` 中注册的各个测试套件 (例如 `TESTLIST_REGISTER (interceptor);`)，然后深入到具体的测试用例代码中去理解其功能和实现方式。
5. **运行测试:** 用户会编译并运行 Frida 的测试套件，以验证 Frida-Gum 的功能是否正常。这通常涉及到使用构建工具 (例如 Meson)。
6. **调试测试失败的情况:** 如果某个测试用例失败，用户会分析失败的原因，查看测试用例的代码、Frida-Gum 的相关代码，并使用调试器 (例如 GDB) 来定位问题。

总而言之，`gumtest.c` 是 Frida-Gum 项目中至关重要的一个文件，它不仅用于验证代码的正确性，也是开发者学习、理解和调试 Frida-Gum 的重要资源。通过分析这个文件，可以深入了解 Frida 动态 instrumentation 的底层原理和实现细节。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/gumtest.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2008-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#define DEBUG_HEAP_LEAKS 0

#include "testutil.h"

#include "lowlevelhelpers.h"
#ifdef HAVE_GUMJS
# include "gumscriptbackend.h"
#endif
#include "valgrind.h"

#include <capstone.h>
#include <glib.h>
#ifdef HAVE_GUMJS
# include <gio/gio.h>
#endif
#ifdef HAVE_GIOOPENSSL
# include <gioopenssl.h>
#endif
#include <gum/gum.h>
#include <string.h>

#ifdef HAVE_WINDOWS
# include <windows.h>
# include <conio.h>
# include <crtdbg.h>
# include <stdio.h>
#endif

#if defined (HAVE_DARWIN) || defined (HAVE_QNX)
# include <dlfcn.h>
#endif

#ifdef HAVE_IOS
# include <unistd.h>
#endif

static guint get_number_of_tests_in_suite (GTestSuite * suite);

gint
main (gint argc, gchar * argv[])
{
#if defined (HAVE_FRIDA_GLIB) && !DEBUG_HEAP_LEAKS && !defined (HAVE_ASAN)
  GMemVTable mem_vtable = {
    gum_malloc,
    gum_realloc,
    gum_memalign,
    gum_free,
    gum_calloc,
    gum_malloc,
    gum_realloc
  };
#endif
  gint result;
  GTimer * timer;
  guint num_tests;
  gdouble t;

#if defined (HAVE_WINDOWS) && DEBUG_HEAP_LEAKS
  {
    int tmp_flag;

    /*_CrtSetBreakAlloc (1337);*/

    _CrtSetReportMode (_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile (_CRT_ERROR, _CRTDBG_FILE_STDERR);

    tmp_flag = _CrtSetDbgFlag (_CRTDBG_REPORT_FLAG);

    tmp_flag |= _CRTDBG_ALLOC_MEM_DF;
    tmp_flag |= _CRTDBG_LEAK_CHECK_DF;
    tmp_flag &= ~_CRTDBG_CHECK_CRT_DF;

    _CrtSetDbgFlag (tmp_flag);
  }
#endif

#ifdef HAVE_WINDOWS
  {
    WORD version_requested = MAKEWORD (2, 2);
    WSADATA wsa_data;
    int err;

    err = WSAStartup (version_requested, &wsa_data);
    g_assert_cmpint (err, ==, 0);
  }
#endif

#ifdef HAVE_DARWIN
  /* Simulate an application where Foundation is available */
  dlopen ("/System/Library/Frameworks/Foundation.framework/Foundation",
      RTLD_LAZY | RTLD_GLOBAL);
#endif

  gum_internal_heap_ref ();
#if !DEBUG_HEAP_LEAKS && !defined (HAVE_ASAN)
  if (RUNNING_ON_VALGRIND)
  {
    g_setenv ("G_SLICE", "always-malloc", TRUE);
  }
  else
  {
#ifdef HAVE_FRIDA_GLIB
    g_mem_set_vtable (&mem_vtable);
#endif
  }
#else
  g_setenv ("G_SLICE", "always-malloc", TRUE);
#endif
  g_setenv ("G_DEBUG", "fatal-warnings:fatal-criticals", TRUE);
#ifdef HAVE_FRIDA_GLIB
  glib_init ();
# ifdef HAVE_GUMJS
  gio_init ();
# endif
#endif
#ifdef HAVE_GIOOPENSSL
  g_io_module_openssl_register ();
#endif
  g_test_init (&argc, &argv, NULL);
  gum_init ();

  _test_util_init ();
  lowlevel_helpers_init ();

#ifdef HAVE_ASAN
  {
    const gchar * asan_options;

    asan_options = g_getenv ("ASAN_OPTIONS");
    if (asan_options == NULL || strstr (asan_options, "handle_segv=0") == NULL)
    {
      g_printerr (
          "\n"
          "You must disable AddressSanitizer's segv-handling. For example:\n"
          "\n"
          "$ export ASAN_OPTIONS=handle_segv=0\n"
          "\n"
          "This is required for testing Gum's exception-handling.\n"
          "\n");
      exit (1);
    }
  }
#endif

#ifdef HAVE_IOS
  if (g_file_test ("/usr/lib/libjailbreak.dylib", G_FILE_TEST_EXISTS))
  {
    void * module;
    void (* entitle_now) (pid_t pid);

    module = dlopen ("/usr/lib/libjailbreak.dylib", RTLD_LAZY | RTLD_GLOBAL);
    g_assert_nonnull (module);

    entitle_now = dlsym (module, "jb_oneshot_entitle_now");
    g_assert_nonnull (entitle_now);

    entitle_now (getpid ());

    dlclose (module);
  }
#endif

#ifdef HAVE_QNX
  dlopen (SYSTEM_MODULE_NAME, RTLD_LAZY | RTLD_GLOBAL);
#endif

#ifdef _MSC_VER
#pragma warning (push)
#pragma warning (disable: 4210)
#endif

  /* Core */
  TESTLIST_REGISTER (testutil);
  TESTLIST_REGISTER (tls);
  TESTLIST_REGISTER (cloak);
  TESTLIST_REGISTER (memory);
  TESTLIST_REGISTER (process);
#if !defined (HAVE_QNX) && !(defined (HAVE_ANDROID) && defined (HAVE_ARM64))
  TESTLIST_REGISTER (symbolutil);
#endif
  TESTLIST_REGISTER (x86writer);
  if (cs_support (CS_ARCH_X86))
    TESTLIST_REGISTER (x86relocator);
  TESTLIST_REGISTER (armwriter);
  if (cs_support (CS_ARCH_ARM))
    TESTLIST_REGISTER (armrelocator);
  TESTLIST_REGISTER (thumbwriter);
  if (cs_support (CS_ARCH_ARM))
    TESTLIST_REGISTER (thumbrelocator);
  TESTLIST_REGISTER (arm64writer);
  if (cs_support (CS_ARCH_ARM64))
    TESTLIST_REGISTER (arm64relocator);
  TESTLIST_REGISTER (interceptor);
#ifdef HAVE_DARWIN
  TESTLIST_REGISTER (interceptor_darwin);
#endif
#ifdef HAVE_ANDROID
  TESTLIST_REGISTER (interceptor_android);
#endif
#ifdef HAVE_ARM
  TESTLIST_REGISTER (interceptor_arm);
#endif
#ifdef HAVE_ARM64
  TESTLIST_REGISTER (interceptor_arm64);
#endif
#if !(defined (HAVE_FREEBSD) && defined (HAVE_ARM64))
  TESTLIST_REGISTER (memoryaccessmonitor);
#endif

  if (gum_stalker_is_supported ())
  {
    gum_stalker_activate_experimental_unwind_support ();

#if defined (HAVE_I386) || defined (HAVE_ARM) || defined (HAVE_ARM64)
    TESTLIST_REGISTER (stalker);
#endif
#ifdef HAVE_MACOS
    TESTLIST_REGISTER (stalker_macos);
#endif
#if defined (HAVE_ARM64) && defined (HAVE_DARWIN)
    TESTLIST_REGISTER (stalker_darwin);
#endif
  }

  TESTLIST_REGISTER (api_resolver);
#if !defined (HAVE_QNX) && \
    !(defined (HAVE_MIPS))
  TESTLIST_REGISTER (backtracer);
#endif

  /* Heap */
  TESTLIST_REGISTER (allocation_tracker);
#ifdef HAVE_WINDOWS
  TESTLIST_REGISTER (allocator_probe);
  TESTLIST_REGISTER (allocator_probe_cxx);
  TESTLIST_REGISTER (cobjecttracker);
  TESTLIST_REGISTER (instancetracker);
#endif
  TESTLIST_REGISTER (pagepool);
#ifndef HAVE_WINDOWS
  if (gum_is_debugger_present ())
  {
    g_print (
        "\n"
        "***\n"
        "NOTE: Skipping BoundsChecker tests because debugger is attached\n"
        "***\n"
        "\n");
  }
  else
#endif
  {
#ifdef HAVE_WINDOWS
    TESTLIST_REGISTER (boundschecker);
#endif
  }
#ifdef HAVE_WINDOWS
  TESTLIST_REGISTER (sanitychecker);
#endif

  /* Prof */
#if !defined (HAVE_IOS) && !(defined (HAVE_ANDROID) && defined (HAVE_ARM64))
  TESTLIST_REGISTER (sampler);
#endif
#ifdef HAVE_WINDOWS
  TESTLIST_REGISTER (profiler);
#endif

#if defined (HAVE_GUMJS) && defined (HAVE_FRIDA_GLIB)
  /* GumJS */
  {
    GumScriptBackend * qjs_backend, * v8_backend;

    qjs_backend = gum_script_backend_obtain_qjs ();
    if (qjs_backend != NULL)
      TESTLIST_REGISTER_WITH_DATA (script, qjs_backend);

    v8_backend = gum_script_backend_obtain_v8 ();
    if (v8_backend != NULL)
      TESTLIST_REGISTER_WITH_DATA (script, v8_backend);

# ifndef HAVE_ASAN
    if (g_test_slow () && gum_kernel_api_is_available ())
      TESTLIST_REGISTER (kscript);
# endif
  }
#endif

#if defined (HAVE_GUMPP) && defined (HAVE_WINDOWS)
  /* Gum++ */
  TESTLIST_REGISTER (gumpp_backtracer);
#endif

#ifdef _MSC_VER
#pragma warning (pop)
#endif

  num_tests = get_number_of_tests_in_suite (g_test_get_root ());

  timer = g_timer_new ();
  result = g_test_run ();
  t = g_timer_elapsed (timer, NULL);
  g_timer_destroy (timer);

  g_print ("\nRan %d tests in %.2f seconds\n", num_tests, t);

#if DEBUG_HEAP_LEAKS || defined (HAVE_ASAN)
  {
    GMainContext * context;

    context = g_main_context_get_thread_default ();
    while (g_main_context_pending (context))
      g_main_context_iteration (context, FALSE);
  }

  gum_shutdown ();
# ifdef HAVE_GUMJS
  gio_shutdown ();
# endif
  glib_shutdown ();

  _test_util_deinit ();

# ifdef HAVE_I386
  lowlevel_helpers_deinit ();
# endif

  gum_deinit ();
# ifdef HAVE_GUMJS
  gio_deinit ();
# endif
  glib_deinit ();
  gum_internal_heap_unref ();

# ifdef HAVE_WINDOWS
  WSACleanup ();
# endif
#endif

#if defined (HAVE_WINDOWS) && !DEBUG_HEAP_LEAKS
  if (IsDebuggerPresent ())
  {
    printf ("\nPress a key to exit.\n");
    _getch ();
  }
#endif

  return result;
}

/* HACK */
struct GTestSuite
{
  gchar * name;
  GSList * suites;
  GSList * cases;
};

static guint
get_number_of_tests_in_suite (GTestSuite * suite)
{
  guint total;
  GSList * cur;

  total = g_slist_length (suite->cases);
  for (cur = suite->suites; cur != NULL; cur = cur->next)
    total += get_number_of_tests_in_suite (cur->data);

  return total;
}

#ifdef HAVE_ANDROID

void
ClaimSignalChain (int signal,
                  struct sigaction * oldaction)
{
  /* g_print ("ClaimSignalChain(signal=%d)\n", signal); */
}

void
UnclaimSignalChain (int signal)
{
  /* g_print ("UnclaimSignalChain(signal=%d)\n", signal); */
}

void
InvokeUserSignalHandler (int signal,
                         siginfo_t * info,
                         void * context)
{
  /* g_print ("InvokeUserSignalHandler(signal=%d)\n", signal); */
}

void
InitializeSignalChain (void)
{
  /* g_print ("InitializeSignalChain()\n"); */
}

void
EnsureFrontOfChain (int signal,
                    struct sigaction * expected_action)
{
  /* g_print ("EnsureFrontOfChain(signal=%d)\n", signal); */
}

void
SetSpecialSignalHandlerFn (int signal,
                           gpointer fn)
{
  /* g_print ("SetSpecialSignalHandlerFn(signal=%d)\n", signal); */
}

void
AddSpecialSignalHandlerFn (int signal,
                           gpointer sa)
{
  /* g_print ("AddSpecialSignalHandlerFn(signal=%d)\n", signal); */
}

void
RemoveSpecialSignalHandlerFn (int signal,
                              bool (* fn) (int, siginfo_t *, void *))
{
  /* g_print ("RemoveSpecialSignalHandlerFn(signal=%d)\n", signal); */
}

#endif

"""

```