Response:
Let's break down the thought process to analyze this C code and address the prompt's requirements.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `testutil.c` within the Frida framework. It's located in the `tests` directory, so it likely provides utility functions specifically for writing and running tests. The prompt asks for a breakdown of its features, how it relates to reverse engineering, low-level concepts, logic, common errors, and debugging.

**2. Initial Code Scan (High-Level):**

* **Includes:**  The `#include` directives give initial clues. We see standard library headers (`stdlib.h`, `string.h`), OS-specific headers (`windows.h`, `unistd.h`, `dlfcn.h`), and Frida-specific headers (`gum/gum...`). This suggests OS abstraction and interaction with Frida's core.
* **Macros:** `TESTCASE` and `TESTENTRY` are clearly test-related. They define the structure for individual tests. `TESTLIST_BEGIN` and `TESTLIST_END` define a collection of tests.
* **Function Prototypes:**  These offer a quick overview of the available functionalities. Functions like `test_util_diff_binary`, `test_util_diff_text`, and `test_util_diff_xml` immediately stand out as core features.
* **Global Variables:** The `_test_util_own_range`, `_test_util_system_module_name`, and `_test_util_heap_apis` suggest state management or caching of information relevant to the tests.
* **Test Cases:** The defined test cases (`binary_diff`, `text_diff`, etc.) directly demonstrate the intended functionality of the utility functions.

**3. Detailed Function Analysis (Focus on Key Areas):**

* **Diffing Functions:** The `test_util_diff_binary`, `test_util_diff_text`, and `test_util_diff_xml` functions are central. They take "expected" and "actual" data as input and produce a human-readable diff. This is crucial for verifying test outcomes.
    * **Reverse Engineering Relevance:**  Diffing is fundamental in reverse engineering. Comparing patched binaries, analyzing network protocols, or examining memory states all involve diffing.
    * **Binary Level:** `test_util_diff_binary` operates directly on byte arrays, showcasing its understanding of binary data.
    * **Logic:**  The internal logic of `diff_line` is a simple character-by-character comparison to highlight the differences.
* **XML Pretty Printing (`prettify_xml`):** This function takes raw XML and formats it for better readability.
    * **Reverse Engineering Relevance:**  Many configuration files, data formats, and even some communication protocols use XML. Pretty printing makes it easier to analyze.
    * **Logic:**  Uses a `GMarkupParser` to traverse the XML structure and adds indentation based on nesting levels.
* **Getting System Information:**  `test_util_get_data_dir` and `test_util_get_system_module_name` are about obtaining environment-specific information.
    * **OS-Specific Knowledge:** These functions use platform-specific APIs (e.g., `_dyld_get_image_name` on macOS, `/proc/self/exe` on Linux, `IsDebuggerPresent` on Windows). This indicates a need to handle different operating systems.
    * **Reverse Engineering Relevance:** Knowing the paths of libraries and the presence of a debugger are crucial during dynamic analysis.
* **Heap API Discovery (`test_util_heap_apis`):** This function retrieves information about the memory allocation functions used by the target process.
    * **Low-Level Knowledge:** This involves understanding how memory management works at a low level.
    * **Reverse Engineering Relevance:**  Hooking or monitoring heap allocation functions is a common technique in dynamic analysis to understand object creation and memory usage.
* **Exception Handling (`gum_try_read_and_write_at`):** This function attempts to read and write to a memory location and catches potential exceptions.
    * **Low-Level and Kernel Knowledge:** This deals directly with memory access and how operating systems handle invalid memory operations (segmentation faults, etc.). The code uses OS-specific exception handling mechanisms (SEH on Windows, signals on other platforms).
    * **Reverse Engineering Relevance:**  This is useful for testing the behavior of Frida's memory manipulation capabilities, ensuring it doesn't crash the target process unnecessarily.
* **Debugger Detection (`gum_is_debugger_present`):** This function determines if a debugger is attached to the process.
    * **OS-Specific Knowledge:**  Uses OS-specific APIs to check for debugger presence.
    * **Reverse Engineering Relevance:**  Detecting debuggers is a common anti-debugging technique used by malware. Frida needs to be aware of this.

**4. Addressing Specific Prompt Points:**

* **Functionality Listing:**  Summarize the identified features based on the function analysis.
* **Reverse Engineering Examples:**  Connect the functionalities (diffing, XML parsing, heap API info, etc.) to common reverse engineering tasks.
* **Binary/OS/Kernel/Framework Knowledge:** Highlight the code sections demonstrating interaction with binary data, Linux, Android, and Windows APIs, and core OS concepts like signals and exception handling.
* **Logical Reasoning (Input/Output):** For the diffing functions, provide concrete examples of input strings/byte arrays and the expected output diff.
* **Common Usage Errors:**  Think about how a *developer* using these test utilities might make mistakes. For example, providing incorrect data types or expecting the diff to handle very large inputs without considering performance.
* **User Operation to Reach Here:**  Imagine a developer working on Frida. They might be writing a new hooking function or testing an existing one. If a test fails, the `testutil` functions are used to pinpoint the discrepancies. This helps trace the path to this code.

**5. Structuring the Answer:**

Organize the findings logically, using headings and bullet points for clarity. Start with a general overview of the file's purpose and then delve into specific functionalities. Provide clear connections to the prompt's requirements (reverse engineering, low-level details, etc.).

**Self-Correction/Refinement During Analysis:**

* **Initial thought:** "This is just for testing."  **Correction:** While primarily for testing, the utilities themselves are built on core Frida capabilities and demonstrate important concepts.
* **Focusing too much on individual lines:** **Correction:**  Zoom out and focus on the *purpose* of each function and how it contributes to testing and broader Frida functionality.
* **Not explicitly linking to the prompt:** **Correction:**  Make sure each point in the analysis directly addresses a specific part of the prompt (e.g., "Reverse Engineering Relevance," "Binary Level").

By following this structured approach, combining high-level understanding with detailed analysis, and constantly relating back to the prompt's requirements, it's possible to generate a comprehensive and accurate explanation of the `testutil.c` file.
这个文件 `frida/subprojects/frida-gum/tests/testutil.c` 是 Frida 动态 instrumentation 工具套件中的一个测试实用程序文件。它的主要目的是为 Frida 的单元测试提供辅助功能，简化测试用例的编写和结果验证。

以下是它的主要功能及其与逆向、底层知识、逻辑推理、用户错误和调试线索的关系：

**1. 功能列举：**

* **二进制数据比较 (`test_util_diff_binary`)**:  比较两个字节数组的差异，以十六进制和二进制格式输出差异信息。
* **文本比较 (`test_util_diff_text`)**:  比较两个文本字符串的差异，逐行标记出不同的地方。
* **XML 比较 (`test_util_diff_xml`)**:  比较两个 XML 字符串的差异，在比较前会先进行格式化（美化），然后逐行标记出不同之处。
* **XML 格式化 (`prettify_xml`)**:  将一段 XML 字符串格式化成易于阅读的格式，添加缩进和换行。
* **单行文本比较 (`diff_line`)**:  比较两行文本，找出第一个不同的字符，并标记出来。
* **获取数据目录 (`test_util_get_data_dir`)**:  尝试确定测试数据文件所在的目录。
* **获取系统模块名称 (`test_util_get_system_module_name`)**:  获取操作系统核心库的名称（例如，Windows 上的 `kernel32.dll`，macOS 上的 `libSystem.B.dylib`，Android 上的 `libc.so`）。
* **获取 Android Java VM 模块名称 (`test_util_get_android_java_vm_module_name`)**:  获取 Android 系统上 Java 虚拟机库的名称 (`libart.so` 或 `libdvm.so`)。
* **获取堆 API 列表 (`test_util_heap_apis`)**:  获取目标进程中使用的堆分配相关 API 的信息。
* **检测调试器是否存在 (`gum_is_debugger_present`)**:  判断当前进程是否被调试器附加。
* **尝试读写内存并捕获异常 (`gum_try_read_and_write_at`)**:  尝试读取和写入指定的内存地址，并捕获可能发生的内存访问异常（例如，段错误）。
* **初始化和清理 (`_test_util_init`, `_test_util_deinit`)**:  执行测试前的初始化工作，例如查找自身代码所在的内存范围，并在测试结束后进行清理。
* **堆访问计数器 (`heap_access_counter_new`)**: 创建一个用于跟踪堆分配和释放操作的采样器。
* **断言文件名相等 (`assert_basename_equals`)**:  比较两个文件路径的basename是否相等。

**2. 与逆向方法的关系 (举例说明)：**

* **二进制数据比较**: 在逆向工程中，经常需要比较两个二进制文件（例如，原始文件和修改后的文件），以找出差异和修改点。`test_util_diff_binary` 可以用于自动化地比较内存中的代码片段，例如，比较 hook 前后的函数指令。
    * **例子**: 假设你需要测试一个 Frida 脚本，该脚本修改了某个函数的开头几个字节。你可以先获取原始函数的字节码，执行 hook 后再次获取，然后使用 `test_util_diff_binary` 比较这两个字节数组，验证你的 hook 是否按照预期修改了指令。
* **文本/XML 比较**:  逆向分析时，配置文件、网络协议或者一些数据结构可能以文本或 XML 格式存在。`test_util_diff_text` 和 `test_util_diff_xml` 可以用来比较修改前后的配置或数据，方便分析修改的影响。
    * **例子**: 你可能需要测试 Frida 脚本是否正确修改了应用程序的偏好设置（通常以 XML 格式存储）。你可以先读取原始的偏好设置 XML，运行脚本后再次读取，然后使用 `test_util_diff_xml` 比较，确认修改是否正确。
* **获取系统模块名称**: 在进行动态 hook 时，经常需要定位特定的系统库或模块。`test_util_get_system_module_name` 可以帮助测试用例验证是否能够正确获取目标模块的名称，这对于编写跨平台的 Frida 脚本非常有用。
    * **例子**: 你编写了一个 hook，需要 hook Windows 系统库 `kernel32.dll` 中的某个函数。测试用例可以使用 `test_util_get_system_module_name` 确保在 Windows 环境下返回的是 "kernel32.dll"。
* **获取堆 API 列表**: 逆向分析时，了解目标程序如何进行内存管理至关重要。`test_util_heap_apis` 提供的功能可以帮助测试 Frida 在不同平台和架构上正确识别堆分配 API，这对于 hook 内存分配函数非常重要。
    * **例子**: 你需要测试一个 Frida 脚本，该脚本 hook 了 `malloc` 函数。测试用例可以使用 `test_util_heap_apis` 获取 `malloc` 的地址，并验证 hook 是否成功。

**3. 涉及二进制底层，Linux, Android 内核及框架的知识 (举例说明)：**

* **二进制数据比较**:  直接操作 `guint8` 类型的字节数组，涉及对二进制数据结构的理解。输出差异时，以十六进制和二进制两种形式展示，需要对数字的进制转换有一定了解。
* **获取数据目录**: 在不同的操作系统上，获取可执行文件路径的方式不同（例如，Linux 上通过读取 `/proc/self/exe` 链接，macOS 上使用 `_dyld_get_image_name`， FreeBSD 使用 `gum_freebsd_query_program_path_for_self`）。这体现了对不同操作系统底层机制的了解。
* **获取系统模块名称**:  依赖于操作系统提供的 API 来获取动态链接库的信息，例如 Linux/Android 上的 `dlfcn.h` 中的 `dlsym` 和 `dladdr`，Windows 上的相关 API。Android 上还需要区分 API level，因为不同版本的 Android 使用不同的 Java 虚拟机库 (Dalvik 或 ART)。
* **获取 Android Java VM 模块名称**:  直接调用 `gum_android_get_api_level()` 来判断 Android 版本，并返回对应的 VM 库名称，这需要了解 Android 系统框架的知识。
* **尝试读写内存并捕获异常**:  使用了操作系统提供的异常处理机制。在 Windows 上使用 SEH (`__try`, `__except`) 和 Vectored Exception Handlers，在其他平台上使用信号处理 (`signal.h`, `sigaction`)。这需要对操作系统如何处理内存访问错误有深入的理解，包括信号的传递和处理流程。在 Android 上还提到了 Bionic 库的一个 bug 的 workaround，体现了对 Android 底层细节的了解。
* **检测调试器是否存在**:  在不同的操作系统上，检测调试器的方法也不同。Windows 上使用 `IsDebuggerPresent()`，macOS 上使用 `sysctl` 查询进程信息，这需要了解各操作系统的调试机制。

**4. 逻辑推理 (假设输入与输出)：**

* **`test_util_diff_binary`**:
    * **假设输入**:
        * `expected_bytes`: `{ 0x01, 0x02, 0x03 }`
        * `actual_bytes`: `{ 0x01, 0x0A, 0x03 }`
    * **预期输出**:  包含以下差异信息的字符串：
        ```
        In hex:
        -------

        01 02 03  <-- Expected
           #
        01 0a 03  <-- Wrong

        In binary:
        ----------

        0000 0001  0000 0010  0000 0011  <-- Expected
                 #
        0000 0001  0000 1010  0000 0011  <-- Wrong
        ```

* **`test_util_diff_text`**:
    * **假设输入**:
        * `expected_text`: `"hello\nworld"`
        * `actual_text`: `"hello\nWOrld"`
    * **预期输出**:
        ```
        hello

        world  <-- Expected
            #
        WOrld  <-- Wrong
        ```

* **`prettify_xml`**:
    * **假设输入**: `<tagA><tagB attr="value">text</tagB></tagA>`
    * **预期输出**:
        ```xml
        <tagA>
          <tagB attr="value">
            text
          </tagB>
        </tagA>
        ```

**5. 涉及用户或者编程常见的使用错误 (举例说明)：**

* **`test_util_diff_binary` 和 `test_util_diff_text`**:
    * **错误**: 传入的 `expected` 和 `actual` 数据的长度不匹配。
    * **结果**:  虽然程序不会崩溃，但比较结果可能不完整或产生误导，因为比较会提前结束。测试编写者需要确保比较的数据长度一致。
* **`test_util_diff_xml`**:
    * **错误**:  传入的字符串不是合法的 XML。
    * **结果**:  `g_markup_parse_context_parse` 函数会返回错误，但 `prettify_xml` 并没有进行严格的错误处理，可能会返回部分格式化的结果或者直接崩溃。编写测试时应确保输入是有效的 XML。
* **使用 `gum_try_read_and_write_at`**:
    * **错误**:  传入的内存地址是完全无效的，例如 `NULL`。
    * **结果**:  即使有异常处理，也可能导致程序崩溃，因为操作系统可能在 Frida 的异常处理机制介入前就终止了进程。用户需要谨慎选择要尝试读写的内存地址。

**6. 说明用户操作是如何一步步的到达这里，作为调试线索：**

假设一个 Frida 开发者正在编写一个用于 hook Android 应用的脚本，并且需要测试这个脚本是否正确修改了某个函数的行为。

1. **编写 Frida 脚本**: 开发者编写了一个 JavaScript 脚本，使用 Frida 的 API (例如 `Interceptor.replace`) 来替换目标函数的实现。
2. **编写单元测试**: 为了验证脚本的正确性，开发者会编写 C 语言的单元测试，该测试会：
    * 启动目标 Android 应用。
    * 加载 Frida agent (包含编写的 JavaScript 脚本)。
    * 执行目标应用中被 hook 的函数。
    * 获取 hook 执行后的状态 (例如，函数的返回值，内存中的数据)。
    * 将实际结果与预期结果进行比较。
3. **使用 `testutil.c` 中的函数**:  在比较实际结果和预期结果时，开发者可能会使用 `testutil.c` 中提供的比较函数，例如：
    * 如果需要比较 hook 前后内存中某个数据结构的字节，会使用 `test_util_diff_binary`。
    * 如果需要比较 hook 前后某个文本配置文件的内容，会使用 `test_util_diff_text` 或 `test_util_diff_xml`。
4. **运行测试**: 开发者运行单元测试。
5. **测试失败**: 如果实际结果与预期结果不符，测试将会失败，并且 `testutil.c` 中的比较函数会生成详细的差异报告。
6. **查看差异报告**: 开发者查看测试输出的差异报告，例如 `test_util_diff_binary` 会输出十六进制和二进制的差异，帮助开发者定位问题所在，例如，hook 代码是否修改了错误的字节。
7. **调试 Frida 脚本或 C 代码**:  根据差异报告，开发者可能会：
    * 检查 Frida 脚本中的 hook 逻辑是否正确。
    * 检查 C 语言测试代码中获取实际结果的方式是否正确。
    * 使用 Frida 的调试功能 (例如 `console.log`) 或 GDB 等工具进一步调试。

因此，`testutil.c` 作为一个测试辅助工具，在 Frida 的开发过程中扮演着至关重要的角色，帮助开发者验证代码的正确性，并通过清晰的差异报告提供调试线索。当测试失败时，开发者会直接接触到 `testutil.c` 生成的输出，从而了解到期望结果和实际结果之间的差异，进而分析问题根源。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/testutil.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2008-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#include "valgrind.h"
#ifdef HAVE_ANDROID
# include "gum/gumandroid.h"
#endif
#ifdef HAVE_FREEBSD
# include "gum/gumfreebsd.h"
#endif
#ifdef HAVE_QNX
# include "gum/gumqnx.h"
#endif

#if defined (HAVE_WINDOWS) && defined (_DEBUG)
# include <crtdbg.h>
#endif
#ifdef HAVE_WINDOWS
# include <excpt.h>
# define VC_EXTRALEAN
# include <windows.h>
#else
# include <setjmp.h>
# include <signal.h>
# ifdef HAVE_DARWIN
#  include <unistd.h>
#  include <mach-o/dyld.h>
#  include <sys/sysctl.h>
#  include <sys/types.h>
# else
#  include <stdio.h>
# endif
# if defined (HAVE_LINUX) || defined (HAVE_FREEBSD)
#  include <dlfcn.h>
# endif
#endif
#include <stdlib.h>
#include <string.h>

#define TESTCASE(NAME) \
    void test_testutil_ ## NAME (void)
#define TESTENTRY(NAME) \
    TESTENTRY_SIMPLE ("TestUtil", test_testutil, NAME)

TESTLIST_BEGIN (testutil)
  TESTENTRY (line_diff)
  TESTENTRY (binary_diff)
  TESTENTRY (text_diff)
  TESTENTRY (xml_pretty_split)
  TESTENTRY (xml_multiline_diff_same_size)
TESTLIST_END ()

#ifndef HAVE_WINDOWS
static gchar * find_data_dir_from_executable_path (const gchar * path);
#endif

static gchar * byte_array_to_hex_string (const guint8 * bytes, guint length);
static gchar * byte_array_to_bin_string (const guint8 * bytes, guint length);
static gchar * prettify_xml (const gchar * input_xml);
static void on_start_element (GMarkupParseContext * context,
    const gchar * element_name, const gchar ** attribute_names,
    const gchar ** attribute_values, gpointer user_data,
    GError ** error);
static void on_end_element (GMarkupParseContext * context,
    const gchar * element_name, gpointer user_data, GError ** error);
static void on_text (GMarkupParseContext * context, const gchar * text,
    gsize text_len, gpointer user_data, GError ** error);
static gchar * diff_line (const gchar * expected_line,
    const gchar * actual_line);
static void append_indent (GString * str, guint indent_level);

TESTCASE (binary_diff)
{
  const guint8 expected_bytes[] = { 0x48, 0x8b, 0x40, 0x07 };
  const guint8 bad_bytes[] = { 0x4c, 0x8b, 0x40, 0x07 };
  const gchar * expected_diff =
      "In hex:\n"
      "-------\n"
      "\n"
      "48 8b 40 07  <-- Expected\n"
      " #\n"
      "4c 8b 40 07  <-- Wrong\n"
      "\n"
      "In binary:\n"
      "----------\n"
      "\n"
      "0100 1000  1000 1011  0100 0000  0000 0111  <-- Expected\n"
      "      #\n"
      "0100 1100  1000 1011  0100 0000  0000 0111  <-- Wrong\n";
  gchar * diff;

  diff = test_util_diff_binary (expected_bytes, sizeof (expected_bytes),
      bad_bytes, sizeof (bad_bytes));
  g_assert_cmpstr (diff, ==, expected_diff);
  g_free (diff);
}

TESTCASE (text_diff)
{
  const gchar * expected_text = "Badger\nSnake\nMushroom";
  const gchar * bad_text      = "Badger\nSnakE\nMushroom";
  const gchar * expected_diff = "Badger\n"
                                "\n"
                                "Snake  <-- Expected\n"
                                "    #\n"
                                "SnakE  <-- Wrong\n"
                                "\n"
                                "Mushroom\n";
  gchar * diff;

  diff = test_util_diff_text (expected_text, bad_text);
  g_assert_cmpstr (diff, ==, expected_diff);
  g_free (diff);
}

TESTCASE (xml_pretty_split)
{
  const gchar * input_xml = "<foo><bar id=\"2\">Woot</bar></foo>";
  const gchar * expected_xml =
      "<foo>\n"
      "  <bar id=\"2\">\n"
      "    Woot\n"
      "  </bar>\n"
      "</foo>\n";
  gchar * output_xml;

  output_xml = prettify_xml (input_xml);
  g_assert_cmpstr (output_xml, ==, expected_xml);
  g_free (output_xml);
}

TESTCASE (xml_multiline_diff_same_size)
{
  const gchar * expected_xml = "<foo><bar id=\"4\"></bar></foo>";
  const gchar * bad_xml      = "<foo><bar id=\"5\"></bar></foo>";
  const gchar * expected_diff = "<foo>\n"
                                "\n"
                                "  <bar id=\"4\">  <-- Expected\n"
                                "           #\n"
                                "  <bar id=\"5\">  <-- Wrong\n"
                                "\n"
                                "  </bar>\n"
                                "</foo>\n";
  gchar * diff;

  diff = test_util_diff_xml (expected_xml, bad_xml);
  g_assert_cmpstr (diff, ==, expected_diff);
  g_free (diff);
}

TESTCASE (line_diff)
{
  const gchar * expected_xml = "<tag/>";
  const gchar * bad_xml = "<taG/>";
  const gchar * expected_diff = "\n"
                                "<tag/>  <-- Expected\n"
                                "   #\n"
                                "<taG/>  <-- Wrong\n";
  gchar * diff;

  diff = diff_line (expected_xml, bad_xml);
  g_assert_cmpstr (diff, ==, expected_diff);
  g_free (diff);
}

/* Implementation */

static gboolean gum_test_assign_own_range_if_matching (
    const GumModuleDetails * details, gpointer user_data);

static GumMemoryRange _test_util_own_range = { 0, 0 };
static gchar * _test_util_system_module_name = NULL;
static GumHeapApiList * _test_util_heap_apis = NULL;

void
_test_util_init (void)
{
  gum_process_enumerate_modules (gum_test_assign_own_range_if_matching,
      &_test_util_own_range);
}

static gboolean
gum_test_assign_own_range_if_matching (const GumModuleDetails * details,
                                       gpointer user_data)
{
  if (GUM_MEMORY_RANGE_INCLUDES (details->range,
      GUM_ADDRESS (gum_test_assign_own_range_if_matching)))
  {
    GumMemoryRange * own_range = user_data;
    memcpy (own_range, details->range, sizeof (GumMemoryRange));
    return FALSE;
  }

  return TRUE;
}

void
_test_util_deinit (void)
{
  g_free (_test_util_system_module_name);
  _test_util_system_module_name = NULL;

  if (_test_util_heap_apis != NULL)
  {
    gum_heap_api_list_free (_test_util_heap_apis);
    _test_util_heap_apis = NULL;
  }
}

GumSampler *
heap_access_counter_new (void)
{
  return gum_call_count_sampler_new (malloc, calloc, realloc, free, NULL);
}

void
assert_basename_equals (const gchar * expected_filename,
                        const gchar * actual_filename)
{
  gchar * expected_basename, * actual_basename;

  expected_basename = g_path_get_basename (expected_filename);
  actual_basename = g_path_get_basename (actual_filename);

  g_assert_cmpstr (expected_basename, ==, actual_basename);

  g_free (expected_basename);
  g_free (actual_basename);
}

gchar *
test_util_diff_binary (const guint8 * expected_bytes,
                       guint expected_length,
                       const guint8 * actual_bytes,
                       guint actual_length)
{
  GString * full_diff;
  gchar * expected_str, * actual_str, * diff;

  full_diff = g_string_new ("In hex:\n");
  g_string_append (full_diff, "-------\n");
  expected_str = byte_array_to_hex_string (expected_bytes, expected_length);
  actual_str = byte_array_to_hex_string (actual_bytes, actual_length);
  diff = diff_line (expected_str, actual_str);
  g_string_append (full_diff, diff);
  g_free (diff);
  g_free (actual_str);
  g_free (expected_str);

  g_string_append_c (full_diff, '\n');

  g_string_append (full_diff, "In binary:\n");
  g_string_append (full_diff, "----------\n");
  expected_str = byte_array_to_bin_string (expected_bytes, expected_length);
  actual_str = byte_array_to_bin_string (actual_bytes, actual_length);
  diff = diff_line (expected_str, actual_str);
  g_string_append (full_diff, diff);
  g_free (diff);
  g_free (actual_str);
  g_free (expected_str);

  return g_string_free (full_diff, FALSE);
}

gchar *
test_util_diff_text (const gchar * expected_text,
                     const gchar * actual_text)
{
  GString * full_diff;
  gchar ** expected_lines, ** actual_lines;
  guint i;

  expected_lines = g_strsplit (expected_text, "\n", 0);
  actual_lines = g_strsplit (actual_text, "\n", 0);

  full_diff = g_string_sized_new (strlen (expected_text));

  for (i = 0; expected_lines[i] != NULL && actual_lines[i] != NULL; i++)
  {
    gchar * diff;

    if (expected_lines[i][0] == '\0' || actual_lines[i][0] == '\0')
      continue;

    diff = diff_line (expected_lines[i], actual_lines[i]);
    g_string_append (full_diff, diff);
    g_string_append_c (full_diff, '\n');
    g_free (diff);
  }

  g_strfreev (expected_lines);
  g_strfreev (actual_lines);

  return g_string_free (full_diff, FALSE);
}

gchar *
test_util_diff_xml (const gchar * expected_xml,
                    const gchar * actual_xml)
{
  gchar * expected_xml_pretty, * actual_xml_pretty, * diff;

  expected_xml_pretty = prettify_xml (expected_xml);
  actual_xml_pretty = prettify_xml (actual_xml);

  diff = test_util_diff_text (expected_xml_pretty, actual_xml_pretty);

  g_free (expected_xml_pretty);
  g_free (actual_xml_pretty);

  return diff;
}

gchar *
test_util_get_data_dir (void)
{
#if defined (HAVE_WINDOWS)
  g_assert_not_reached (); /* FIXME: once this is needed on Windows */
  return NULL;
#elif defined (HAVE_DARWIN)
  guint image_count, image_idx;

  image_count = _dyld_image_count ();
  for (image_idx = 0; image_idx != image_count; image_idx++)
  {
    const gchar * path = _dyld_get_image_name (image_idx);

    if (g_str_has_suffix (path, "/gum-tests"))
      return find_data_dir_from_executable_path (path);
  }

  return g_strdup ("/Library/Frida/tests/data");
#elif defined (HAVE_LINUX)
  gchar * result, * path;

  path = g_file_read_link ("/proc/self/exe", NULL);
  result = find_data_dir_from_executable_path (path);
  g_free (path);

  return result;
#elif defined (HAVE_FREEBSD)
  gchar * result, * path;

  path = gum_freebsd_query_program_path_for_self (NULL);
  result = find_data_dir_from_executable_path (path);
  g_free (path);

  return result;
#elif defined (HAVE_QNX)
  gchar * result, * path;

  path = gum_qnx_query_program_path_for_self (NULL);
  result = find_data_dir_from_executable_path (path);
  g_free (path);

  return result;
#else
# error Implement support for your OS here
#endif
}

#ifndef HAVE_WINDOWS

static gchar *
find_data_dir_from_executable_path (const gchar * path)
{
  gchar * result, * dir;

  dir = g_path_get_dirname (path);
  result = g_build_filename (dir, "data", NULL);
  g_free (dir);

  return result;
}

#endif

const gchar *
test_util_get_system_module_name (void)
{
#if defined (HAVE_WINDOWS)
  return "kernel32.dll";
#elif defined (HAVE_DARWIN)
  return "libSystem.B.dylib";
#elif defined (HAVE_ANDROID)
  return "libc.so";
#elif defined (HAVE_QNX)
  return "libbacktrace.so.1";
#else
  if (_test_util_system_module_name == NULL)
  {
    gpointer libc_open;
    Dl_info info;
    gchar * target, * libc_path;

    libc_open = dlsym (RTLD_DEFAULT, "fopen");
    g_assert_nonnull (libc_open);

    g_assert_true (dladdr (libc_open, &info) != 0);
    g_assert_nonnull (info.dli_fname);

    target = g_file_read_link (info.dli_fname, NULL);
    if (target != NULL)
    {
      gchar * libc_dir;

      libc_dir = g_path_get_dirname (info.dli_fname);

      libc_path = g_canonicalize_filename (target, libc_dir);

      g_free (libc_dir);
      g_free (target);
    }
    else
    {
      libc_path = g_strdup (info.dli_fname);
    }

    _test_util_system_module_name = g_path_get_basename (libc_path);

    g_free (libc_path);
  }

  return _test_util_system_module_name;
#endif
}

#ifdef HAVE_ANDROID

const gchar *
test_util_get_android_java_vm_module_name (void)
{
  return (gum_android_get_api_level () >= 21) ? "libart.so" : "libdvm.so";
}

#endif

const GumHeapApiList *
test_util_heap_apis (void)
{
  if (_test_util_heap_apis == NULL)
    _test_util_heap_apis = gum_process_find_heap_apis ();
  return _test_util_heap_apis;
}

gboolean
gum_is_debugger_present (void)
{
#if defined (HAVE_WINDOWS)
  return IsDebuggerPresent ();
#elif defined (HAVE_DARWIN)
  int mib[4];
  struct kinfo_proc info;
  size_t size;

  info.kp_proc.p_flag = 0;
  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PID;
  mib[3] = getpid ();

  size = sizeof (info);
  sysctl (mib, G_N_ELEMENTS (mib), &info, &size, NULL, 0);

  return (info.kp_proc.p_flag & P_TRACED) != 0;
#else
  /* FIXME */
  return FALSE;
#endif
}

#if defined (_MSC_VER)

guint8
gum_try_read_and_write_at (guint8 * a,
                           guint i,
                           gboolean * exception_raised_on_read,
                           gboolean * exception_raised_on_write)
{
  guint8 dummy_value_to_trick_optimizer = 0;

  if (exception_raised_on_read != NULL)
    *exception_raised_on_read = FALSE;
  if (exception_raised_on_write != NULL)
    *exception_raised_on_write = FALSE;

  __try
  {
    dummy_value_to_trick_optimizer = a[i];
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    if (exception_raised_on_read != NULL)
      *exception_raised_on_read = TRUE;
  }

  __try
  {
    a[i] = 42;
  }
  __except (EXCEPTION_EXECUTE_HANDLER)
  {
    if (exception_raised_on_write != NULL)
      *exception_raised_on_write = TRUE;
  }

  return dummy_value_to_trick_optimizer;
}

#elif defined (HAVE_WINDOWS)

static WINAPI LONG on_exception (PEXCEPTION_POINTERS info);
static void recover_from_exception (void);

static jmp_buf gum_try_read_and_write_context;
static guint64 gum_temp_stack[512];

guint8
gum_try_read_and_write_at (guint8 * a,
                           guint i,
                           gboolean * exception_raised_on_read,
                           gboolean * exception_raised_on_write)
{
  guint8 dummy_value_to_trick_optimizer = 0;
  GumExceptor * exceptor;
  PVOID handler;

  if (exception_raised_on_read != NULL)
    *exception_raised_on_read = FALSE;
  if (exception_raised_on_write != NULL)
    *exception_raised_on_write = FALSE;

  exceptor = gum_exceptor_obtain ();

  handler = AddVectoredExceptionHandler (TRUE, on_exception);

  if (setjmp (gum_try_read_and_write_context) == 0)
  {
    dummy_value_to_trick_optimizer = a[i];
  }
  else
  {
    if (exception_raised_on_read != NULL)
      *exception_raised_on_read = TRUE;
  }

  if (setjmp (gum_try_read_and_write_context) == 0)
  {
    a[i] = 42;
  }
  else
  {
    if (exception_raised_on_write != NULL)
      *exception_raised_on_write = TRUE;
  }

  RemoveVectoredExceptionHandler (handler);

  g_object_unref (exceptor);

  return dummy_value_to_trick_optimizer;
}

static WINAPI LONG
on_exception (PEXCEPTION_POINTERS info)
{
# if GLIB_SIZEOF_VOID_P == 8
  info->ContextRecord->Rip = GPOINTER_TO_SIZE (recover_from_exception);
  info->ContextRecord->Rsp = GPOINTER_TO_SIZE (gum_temp_stack +
      G_N_ELEMENTS (gum_temp_stack));
# else
  info->ContextRecord->Eip = GPOINTER_TO_SIZE (recover_from_exception);
  info->ContextRecord->Esp = GPOINTER_TO_SIZE (gum_temp_stack +
      G_N_ELEMENTS (gum_temp_stack));
# endif
  return EXCEPTION_CONTINUE_EXECUTION;
}

static void
recover_from_exception (void)
{
  longjmp (gum_try_read_and_write_context, 1337);
}

#else

# ifdef HAVE_DARWIN
#  define GUM_SETJMP(env) setjmp (env)
#  define GUM_LONGJMP(env, val) longjmp (env, val)
   typedef jmp_buf gum_jmp_buf;
# else
#  define GUM_SETJMP(env) sigsetjmp (env, 1)
#  define GUM_LONGJMP(env, val) siglongjmp (env, val)
   typedef sigjmp_buf gum_jmp_buf;
# endif

static gum_jmp_buf gum_try_read_and_write_context;
static struct sigaction gum_test_old_sigsegv;
static struct sigaction gum_test_old_sigbus;

static gboolean gum_test_should_forward_signal_to (gpointer handler);

static void
gum_test_on_signal (int sig,
                    siginfo_t * siginfo,
                    void * context)
{
  struct sigaction * action;

  action = (sig == SIGSEGV) ? &gum_test_old_sigsegv : &gum_test_old_sigbus;
  if ((action->sa_flags & SA_SIGINFO) != 0)
  {
    if (gum_test_should_forward_signal_to (action->sa_sigaction))
      action->sa_sigaction (sig, siginfo, context);
  }
  else
  {
    if (gum_test_should_forward_signal_to (action->sa_handler))
      action->sa_handler (sig);
  }

  GUM_LONGJMP (gum_try_read_and_write_context, 1337);
}

static gboolean
gum_test_should_forward_signal_to (gpointer handler)
{
  if (handler == NULL)
    return FALSE;

  return GUM_MEMORY_RANGE_INCLUDES (&_test_util_own_range,
      GUM_ADDRESS (handler));
}

guint8
gum_try_read_and_write_at (guint8 * a,
                           guint i,
                           gboolean * exception_raised_on_read,
                           gboolean * exception_raised_on_write)
{
  struct sigaction action;
  guint8 dummy_value_to_trick_optimizer = 0;
  GumExceptor * exceptor;

  if (exception_raised_on_read != NULL)
    *exception_raised_on_read = FALSE;
  if (exception_raised_on_write != NULL)
    *exception_raised_on_write = FALSE;

  exceptor = gum_exceptor_obtain ();

  action.sa_sigaction = gum_test_on_signal;
  sigemptyset (&action.sa_mask);
  action.sa_flags = SA_SIGINFO;
  sigaction (SIGSEGV, &action, &gum_test_old_sigsegv);
  sigaction (SIGBUS, &action, &gum_test_old_sigbus);

# ifdef HAVE_ANDROID
  /* Work-around for Bionic bug up to and including Android L */
  sigset_t mask;

  sigprocmask (SIG_SETMASK, NULL, &mask);
# endif

  if (GUM_SETJMP (gum_try_read_and_write_context) == 0)
  {
    dummy_value_to_trick_optimizer = a[i];
  }
  else
  {
    if (exception_raised_on_read != NULL)
      *exception_raised_on_read = TRUE;
  }

# ifdef HAVE_ANDROID
  sigprocmask (SIG_SETMASK, &mask, NULL);
# endif

  if (GUM_SETJMP (gum_try_read_and_write_context) == 0)
  {
    a[i] = 42;
  }
  else
  {
    if (exception_raised_on_write != NULL)
      *exception_raised_on_write = TRUE;
  }

# ifdef HAVE_ANDROID
  sigprocmask (SIG_SETMASK, &mask, NULL);
# endif

  sigaction (SIGSEGV, &gum_test_old_sigsegv, NULL);
  memset (&gum_test_old_sigsegv, 0, sizeof (gum_test_old_sigsegv));
  sigaction (SIGBUS, &gum_test_old_sigbus, NULL);
  memset (&gum_test_old_sigbus, 0, sizeof (gum_test_old_sigbus));

  g_object_unref (exceptor);

  return dummy_value_to_trick_optimizer;
}

#endif

static gchar *
byte_array_to_hex_string (const guint8 * bytes,
                          guint length)
{
  GString * result;
  guint byte_idx;

  result = g_string_sized_new (length * 2 + length - 1);

  for (byte_idx = 0; byte_idx != length; byte_idx++)
  {
    if (byte_idx != 0)
      g_string_append_c (result, ' ');
    g_string_append_printf (result, "%02x", bytes[byte_idx]);
  }

  return g_string_free (result, FALSE);
}

static gchar *
byte_array_to_bin_string (const guint8 * bytes,
                          guint length)
{
  GString * result;
  guint byte_idx;

  result = g_string_sized_new (length * 9 + length * 2 - 2);

  for (byte_idx = 0; byte_idx != length; byte_idx++)
  {
    guint bit_idx;

    if (byte_idx != 0)
      g_string_append (result, "  ");

    for (bit_idx = 0; bit_idx != 8; bit_idx++)
    {
      gboolean bit_is_set;

      bit_is_set = (bytes[byte_idx] >> (7 - bit_idx)) & 1;

      if (bit_idx == 4)
        g_string_append_c (result, ' ');
      g_string_append_c (result, bit_is_set ? '1' : '0');
    }
  }

  return g_string_free (result, FALSE);
}

typedef struct _PrettifyState PrettifyState;

struct _PrettifyState
{
  GString * output_xml;
  guint indentation_level;
};

static gchar *
prettify_xml (const gchar * input_xml)
{
  PrettifyState state;
  GMarkupParser parser = { NULL, };
  GMarkupParseContext * context;

  state.output_xml = g_string_sized_new (80);
  state.indentation_level = 0;

  parser.start_element = on_start_element;
  parser.end_element = on_end_element;
  parser.text = on_text;

  context = g_markup_parse_context_new (&parser, 0, &state, NULL);
  g_markup_parse_context_parse (context, input_xml, strlen (input_xml), NULL);
  g_markup_parse_context_free (context);

  return g_string_free (state.output_xml, FALSE);
}

static void
on_start_element (GMarkupParseContext * context,
                  const gchar * element_name,
                  const gchar ** attribute_names,
                  const gchar ** attribute_values,
                  gpointer user_data,
                  GError ** error)
{
  PrettifyState * state = user_data;
  guint i;

  append_indent (state->output_xml, state->indentation_level);
  g_string_append_printf (state->output_xml, "<%s", element_name);

  for (i = 0; attribute_names[i] != NULL; i++)
  {
    g_string_append_printf (state->output_xml, " %s=\"%s\"",
        attribute_names[i], attribute_values[i]);
  }

  g_string_append (state->output_xml, ">\n");

  state->indentation_level++;
}

static void
on_end_element (GMarkupParseContext * context,
                const gchar * element_name,
                gpointer user_data,
                GError ** error)
{
  PrettifyState * state = user_data;

  state->indentation_level--;

  append_indent (state->output_xml, state->indentation_level);
  g_string_append_printf (state->output_xml, "</%s>\n", element_name);
}

static void
on_text (GMarkupParseContext * context,
         const gchar * text,
         gsize text_len,
         gpointer user_data,
         GError ** error)
{
  PrettifyState * state = user_data;

  if (text_len > 0)
  {
    append_indent (state->output_xml, state->indentation_level);
    g_string_append_len (state->output_xml, text, text_len);
    g_string_append_printf (state->output_xml, "\n");
  }
}

static gchar *
diff_line (const gchar * expected_line,
           const gchar * actual_line)
{
  GString * diff_str;
  guint diff_pos = 0;
  const gchar * expected = expected_line;
  const gchar * actual   = actual_line;

  if (strcmp (expected_line, actual_line) == 0)
    return g_strdup (actual_line);

  while (*expected != '\0' && *actual != '\0')
  {
    if (*expected != *actual)
    {
      diff_pos = expected - expected_line;
      break;
    }

    expected++;
    actual++;
  }

  diff_str = g_string_sized_new (80);
  g_string_append_c (diff_str, '\n');
  g_string_append_printf (diff_str, "%s  <-- Expected\n", expected_line);
  g_string_append_printf (diff_str, "%*s#\n", diff_pos, "");
  g_string_append_printf (diff_str, "%s  <-- Wrong\n", actual_line);

  return g_string_free (diff_str, FALSE);
}

static void
append_indent (GString * str,
               guint indent_level)
{
  guint i;

  for (i = 0; i < indent_level; i++)
    g_string_append (str, "  ");
}

"""

```