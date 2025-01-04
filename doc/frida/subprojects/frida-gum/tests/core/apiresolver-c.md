Response:
Let's break down the thought process for analyzing the provided C code.

**1. Initial Understanding - What is this?**

The first lines give a crucial clue: "fridaDynamic instrumentation tool". This immediately tells me it's related to dynamic analysis, hooking, and potentially modifying program behavior at runtime. The file path `frida/subprojects/frida-gum/tests/core/apiresolver.c`  suggests this file is a *test* for a component called `apiresolver` within the larger Frida framework (specifically `frida-gum`, the core engine).

**2. Core Functionality - What does `apiresolver` do?**

The filename and the test case names are highly descriptive:

* `module_exports_can_be_resolved...`:  Suggests finding exported symbols (functions, variables) within loaded modules (like shared libraries or executables).
* `module_imports_can_be_resolved`: Indicates finding symbols that a module *imports* from other modules.
* `module_sections_can_be_resolved`:  Points to locating specific sections within a module's binary file (e.g., `.text`, `.data`).
* `objc_methods_can_be_resolved...`:  Specifically for Objective-C, this means finding methods of classes and objects.
* `swift_method_can_be_resolved`:  Similar to Objective-C, but for Swift.
* `linker_exports_can_be_resolved_on_android`:  Focuses on finding symbols exported by the Android linker, which is responsible for loading shared libraries.

From these names, the central function of `apiresolver` becomes clear: **to locate and identify specific code or data elements within running processes.**

**3. How does the code *test* this functionality?**

The structure of the file reveals it uses a testing framework (likely a custom one, given `TESTLIST_BEGIN`, `TESTENTRY`, `TESTCASE`). Each `TESTCASE` function exercises a specific aspect of the `apiresolver`. The common pattern is:

* **Setup:** Create an `api_resolver` instance using `gum_api_resolver_make()`.
* **Execution:** Call `gum_api_resolver_enumerate_matches()` with a *query string*. This is how the tests specify what they want to find (e.g., "exports:*!open*").
* **Verification:**  Use assertion macros like `g_assert_nonnull`, `g_assert_no_error`, `g_assert_cmpuint`, etc., to check if the results are as expected. Callbacks like `match_found_cb`, `check_module_import`, etc., are used to process the found matches and perform further checks.

**4. Connecting to Reverse Engineering**

With the understanding of `apiresolver`'s purpose, the connection to reverse engineering becomes apparent. Reverse engineers often need to:

* **Find specific functions:** To understand how a particular piece of functionality is implemented.
* **Identify data structures:** To decipher how data is organized and manipulated.
* **Locate imported functions:** To see what external libraries a program depends on.
* **Analyze Objective-C/Swift methods:**  Crucial for understanding iOS and macOS applications.

The examples provided in the comments of the thought process clearly illustrate these connections.

**5. Binary/OS/Kernel/Framework Connections**

The code itself hints at these connections through:

* **Platform-specific `#ifdef` directives:**  `HAVE_WINDOWS`, `HAVE_DARWIN`, `HAVE_ANDROID`, `HAVE_ELF` indicate that the `apiresolver` interacts with platform-specific mechanisms for symbol resolution and module loading.
* **References to "linker" on Android:** This directly relates to the dynamic linking process on Android.
* **Objective-C and Swift tests:**  Show interaction with the runtime environments of these languages, which are deeply tied to the operating system (macOS, iOS).
* **The concept of "sections"**: This is a fundamental concept in binary file formats (like ELF and Mach-O).

**6. Logical Inference and Assumptions**

When analyzing the test cases, I look for the *inputs* to `gum_api_resolver_enumerate_matches()` (the query string) and the *expected outputs* (verified by the assertions and callbacks).

For instance, in `module_exports_can_be_resolved_case_sensitively`:

* **Input:** `exports:*!open*` (or `exports:*!_open*` on Windows).
* **Assumption:** The test environment has a module (likely the test executable itself) that exports a function named `open` (or `_open`).
* **Expected Output:** The `match_found_cb` should be called at least once.

**7. User Errors and Debugging**

Thinking about how a *user* of Frida might interact with this component leads to potential error scenarios:

* **Incorrect Query Syntax:** The query strings have a specific format. Typos or incorrect wildcards could lead to no matches.
* **Target Process Issues:** If the target process doesn't have the module or symbol being searched for, the resolver won't find it.
* **Permissions:** Frida needs sufficient privileges to inspect the target process.
* **API Level Differences (Android):** The `linker` path and library names can vary across Android versions, as the test for `linker_exports_can_be_resolved_on_android` demonstrates.

The explanation of how a user might arrive at this code (debugging Frida) is a logical conclusion given the context of a test file.

**Self-Correction/Refinement during the process:**

* Initially, I might have just focused on the individual test cases. However, recognizing the common pattern of setup, execution, and verification provides a more holistic understanding.
*  Realizing the significance of the `#ifdef` blocks is key to understanding the cross-platform nature of Frida.
* Connecting the test case names directly to reverse engineering concepts is crucial for fulfilling that part of the prompt.
*  Thinking about the *user* perspective adds practical value to the analysis.

By following this structured approach, combining code analysis with knowledge of dynamic instrumentation and reverse engineering principles, a comprehensive understanding of the `apiresolver.c` file can be achieved.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/tests/core/apiresolver.c` 这个文件。

**文件功能概述:**

这个 C 代码文件是 Frida 框架中 `frida-gum` 核心库的测试代码，专门用于测试 `GumApiResolver` 组件的功能。 `GumApiResolver` 的主要功能是**解析和查找目标进程中的各种 API（应用程序接口）信息**，例如：

* **模块导出 (Module Exports):**  查找指定模块（如动态链接库或可执行文件）导出的函数或变量。
* **模块导入 (Module Imports):** 查找指定模块导入的其他模块的函数或变量。
* **模块段 (Module Sections):** 查找指定模块中的代码段、数据段等内存区域。
* **Objective-C 方法 (Objective-C Methods):**  查找 Objective-C 类的实例方法和类方法。
* **Swift 函数 (Swift Functions):** 查找 Swift 语言编写的函数。
* **链接器导出 (Linker Exports):** 在 Android 系统上，查找链接器（负责加载动态库）导出的符号。

**与逆向方法的关系及举例说明:**

`GumApiResolver` 是 Frida 进行动态 Instrumentation 的核心组成部分，与逆向工程方法紧密相关。逆向工程师经常需要了解目标程序的内部结构和行为，而 `GumApiResolver` 提供了便捷的手段来获取这些信息。

**举例说明:**

1. **查找关键函数地址以进行 Hook:**
   - **场景:**  逆向一个恶意软件，想要在它调用 `open` 系统调用打开文件时进行拦截。
   - **Frida 操作:** 可以使用 `gum_api_resolver_enumerate_matches` 函数，并设置 `query` 为 `"exports:*!open*"` (或 Windows 下的 `"exports:*!_open*"`)。这将遍历所有加载的模块，找到导出的名为 `open` 的函数。
   - **逆向意义:** 获得 `open` 函数的地址后，可以使用 Frida 的 `Interceptor` API 来 hook 这个函数，在它执行前后执行自定义的代码，例如记录打开的文件名，阻止某些文件的访问等。

2. **定位关键数据结构:**
   - **场景:** 分析一个游戏的内存布局，想要找到存储玩家金币数量的变量。
   - **Frida 操作:** 可以尝试查找包含特定名称的模块段，例如 `"sections:game_module!*data*"`，然后遍历这些数据段的内存，寻找疑似存储金币数量的特征值。
   - **逆向意义:** 找到金币变量的地址后，可以编写 Frida 脚本来监控金币变化，或者修改金币的值。

3. **分析 Objective-C 应用的方法调用:**
   - **场景:**  逆向一个 iOS 应用，想要了解某个按钮点击后会执行哪些方法。
   - **Frida 操作:**  可以使用 `gum_api_resolver_enumerate_matches`，并设置 `query` 为类似 `"+[ViewController buttonTapped:]"` 来查找 `ViewController` 类中名为 `buttonTapped:` 的类方法。或者使用 `"-[MyClass doSomething]"` 查找实例方法。
   - **逆向意义:**  找到方法的地址后，可以 hook 这个方法，分析其参数和返回值，理解按钮点击后的具体逻辑。

**涉及二进制底层、Linux、Android 内核及框架的知识:**

`GumApiResolver` 的实现需要深入理解操作系统和二进制文件格式的底层细节：

1. **二进制文件格式 (ELF, Mach-O, PE):**
   - 为了解析模块的导出、导入和段信息，`GumApiResolver` 需要解析不同平台下的二进制文件格式，如 Linux 的 ELF，macOS 和 iOS 的 Mach-O，以及 Windows 的 PE 格式。
   - 代码中的 `#ifdef HAVE_DARWIN`、`#ifdef HAVE_ELF` 等预编译指令表明了对不同平台的支持。

2. **动态链接 (Dynamic Linking):**
   - 模块的导入和导出是动态链接的关键概念。`GumApiResolver` 需要理解动态链接器如何加载和链接共享库。
   - 在 Android 平台上，测试用例 `linker_exports_can_be_resolved_on_android` 就直接针对了 Android 链接器 (`linker` 或 `linker64`) 的导出符号进行测试。

3. **操作系统 API:**
   - 在不同平台上，获取模块信息、符号信息等需要调用相应的操作系统 API。例如，在 Linux 上可能使用 `dlopen`, `dlsym` 等，在 macOS 上可能使用 `NSModule`, `NSLookupSymbol` 等。

4. **Objective-C Runtime:**
   - 解析 Objective-C 方法需要与 Objective-C 运行时环境交互，了解其消息传递机制和方法查找过程。

5. **Android 框架:**
   - 在 Android 上，需要了解 Android 的进程模型、动态链接机制，以及 ART (Android Runtime) 或 Dalvik 虚拟机如何管理对象和方法。测试用例中获取 Android API Level (`gum_android_get_api_level()`) 并根据 API Level 选择不同的链接器路径就体现了对 Android 框架的理解。

**逻辑推理、假设输入与输出:**

以 `TESTCASE (module_exports_can_be_resolved_case_sensitively)` 为例：

* **假设输入:**
    - `fixture->resolver` 是一个已创建的用于解析模块导出的 `GumApiResolver` 实例。
    - `query` 是字符串 `"exports:*!open*"` (或 Windows 下的 `"exports:*!_open*"`)。
    - 当前测试的进程或加载的模块中存在一个导出的函数名为 `open`（或 `_open`）。
* **逻辑推理:**
    - `gum_api_resolver_enumerate_matches` 函数会遍历所有加载的模块，检查它们的导出符号表。
    - `query` 中的 `exports:` 指定了查找类型为导出符号。
    - `*!open*` 是一个模式匹配，`!` 前面的 `*` 表示匹配任意模块名，`!` 后面的 `open` 表示匹配以 `open` 结尾的符号名。
    - `match_found_cb` 回调函数会在找到匹配的符号时被调用。
* **预期输出:**
    - `ctx.number_of_calls` 的值会大于 1，因为通常标准库中会有 `open` 或类似的函数。
    - 第二次调用 `gum_api_resolver_enumerate_matches` 时，由于 `ctx.value_to_return` 被设置为 `FALSE`，回调函数在第一次找到匹配后会返回 `FALSE`，导致搜索提前结束，所以 `ctx.number_of_calls` 的值会等于 1。

**用户或编程常见的使用错误及举例说明:**

1. **错误的查询语法:**
   - **错误示例:**  `"export:*!open"` (缺少 `s`) 或 `"exports:!open*"` (缺少模块名匹配符)。
   - **后果:** 无法找到预期的 API。
   - **调试提示:** 仔细检查查询字符串的格式，参考 Frida 的文档。

2. **大小写敏感性问题:**
   - **错误示例:** 在期望大小写不敏感匹配时，使用了大小写敏感的查询，例如在查找 Objective-C 方法时使用 `"+[MyClass dosomething:]"` 而不是 `"+[MyClass doSomething:]/i`。
   - **后果:** 可能无法找到目标 API。
   - **调试提示:** 注意查询字符串中是否需要使用 `/i` 标志来表示大小写不敏感。

3. **目标模块或 API 不存在:**
   - **错误示例:**  尝试查找一个未加载的模块的导出，或者查找一个不存在的函数名。
   - **后果:** `gum_api_resolver_enumerate_matches` 不会找到任何匹配。
   - **调试提示:** 确认目标模块已经加载，并且 API 名称拼写正确。可以使用其他工具（如 `lsof`，`nm` 等）来验证模块和符号的存在。

4. **在不支持的平台上使用特定功能:**
   - **错误示例:** 在非 Android 平台上使用 `linker` 相关的查询。
   - **后果:**  可能会导致错误或找不到结果。
   - **调试提示:**  注意代码中的平台判断 (`#ifdef HAVE_ANDROID`)，确保在正确的平台上使用相应的功能。

**用户操作是如何一步步到达这里的，作为调试线索:**

通常，用户不会直接编写或修改 `frida-gum` 的测试代码。但是，如果用户在调试 Frida 本身或其核心功能时遇到了问题，可能会查看这些测试代码来理解 `GumApiResolver` 的工作原理，或者尝试复现问题。

**调试线索:**

1. **用户在使用 Frida 脚本时，发现无法 hook 到预期的函数或方法。** 这可能是因为 `GumApiResolver` 没有正确找到目标 API 的地址。用户可能会查看 `apiresolver.c` 的测试代码，学习如何构造正确的查询字符串，或者验证 Frida 的 API 解析功能是否正常。

2. **用户在开发基于 Frida 的工具时，遇到了与 API 解析相关的问题。** 例如，他们可能使用了 `Module.findExportByName` 或类似的 Frida API，这些 API 的底层可能就使用了 `GumApiResolver`。当出现查找失败或其他异常时，他们可能会研究 `apiresolver.c` 的测试用例，来理解这些 API 的正确用法和预期行为。

3. **Frida 开发者在添加新功能或修复 Bug 时，可能会修改或新增 `apiresolver.c` 中的测试用例，以确保 `GumApiResolver` 的功能正确性。**  如果用户报告了与 API 解析相关的问题，开发者可能会参考现有的测试用例，并编写新的测试用例来复现和验证修复。

**总结:**

`frida/subprojects/frida-gum/tests/core/apiresolver.c` 是 Frida 框架中一个非常重要的测试文件，它详细测试了 `GumApiResolver` 组件的各种 API 解析功能。理解这个文件的内容，可以帮助我们更好地理解 Frida 的工作原理，以及如何在逆向工程中利用 Frida 来获取目标进程的内部信息。它也为 Frida 的开发者提供了一个确保代码质量和功能正确性的重要手段。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/core/apiresolver.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2016-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "apiresolver-fixture.c"

TESTLIST_BEGIN (api_resolver)
  TESTENTRY (module_exports_can_be_resolved_case_sensitively)
  TESTENTRY (module_exports_can_be_resolved_case_insensitively)
  TESTENTRY (module_imports_can_be_resolved)
  TESTENTRY (module_sections_can_be_resolved)
  TESTENTRY (objc_methods_can_be_resolved_case_sensitively)
  TESTENTRY (objc_methods_can_be_resolved_case_insensitively)
#ifdef HAVE_DARWIN
  TESTENTRY (objc_method_can_be_resolved_from_class_method_address)
  TESTENTRY (objc_method_can_be_resolved_from_instance_method_address)
  TESTENTRY (swift_method_can_be_resolved)
#endif
#ifdef HAVE_ANDROID
  TESTENTRY (linker_exports_can_be_resolved_on_android)
#endif
TESTLIST_END ()

TESTCASE (module_exports_can_be_resolved_case_sensitively)
{
  TestForEachContext ctx;
  GError * error = NULL;
#ifdef HAVE_WINDOWS
  const gchar * query = "exports:*!_open*";
#else
  const gchar * query = "exports:*!open*";
#endif

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert_nonnull (fixture->resolver);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_api_resolver_enumerate_matches (fixture->resolver, query, match_found_cb,
      &ctx, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_api_resolver_enumerate_matches (fixture->resolver, query, match_found_cb,
      &ctx, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

TESTCASE (module_exports_can_be_resolved_case_insensitively)
{
  TestForEachContext ctx;
  GError * error = NULL;
#ifdef HAVE_WINDOWS
  const gchar * query = "exports:*!_OpEn*/i";
#else
  const gchar * query = "exports:*!OpEn*/i";
#endif

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert_nonnull (fixture->resolver);

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_api_resolver_enumerate_matches (fixture->resolver, query, match_found_cb,
      &ctx, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);
}

TESTCASE (module_imports_can_be_resolved)
{
#ifdef HAVE_DARWIN
  GError * error = NULL;
  const gchar * query = "imports:gum-tests!*";
  guint number_of_imports_seen = 0;

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert_nonnull (fixture->resolver);

  gum_api_resolver_enumerate_matches (fixture->resolver, query,
      check_module_import, &number_of_imports_seen, &error);
  g_assert_no_error (error);
#else
  (void) check_module_import;
#endif
}

static gboolean
check_module_import (const GumApiDetails * details,
                     gpointer user_data)
{
  guint * number_of_imports_seen = user_data;

  g_assert_null (strstr (details->name, "gum-tests"));

  (*number_of_imports_seen)++;

  return TRUE;
}

TESTCASE (module_sections_can_be_resolved)
{
#if defined (HAVE_DARWIN) || defined (HAVE_ELF)
  GError * error = NULL;
  const gchar * query = "sections:gum-tests!*data*";
  guint number_of_sections_seen = 0;

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert_nonnull (fixture->resolver);

  gum_api_resolver_enumerate_matches (fixture->resolver, query, check_section,
      &number_of_sections_seen, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (number_of_sections_seen, >, 1);
#else
  (void) check_section;
#endif
}

static gboolean
check_section (const GumApiDetails * details,
               gpointer user_data)
{
  guint * number_of_sections_seen = user_data;

  g_assert_nonnull (strstr (details->name, "data"));

  (*number_of_sections_seen)++;

  return TRUE;
}

TESTCASE (objc_methods_can_be_resolved_case_sensitively)
{
  TestForEachContext ctx;
  GError * error = NULL;

  fixture->resolver = gum_api_resolver_make ("objc");
  if (fixture->resolver == NULL)
  {
    g_print ("<skipping, not available> ");
    return;
  }

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_api_resolver_enumerate_matches (fixture->resolver, "+[*Arr* arr*]",
      match_found_cb, &ctx, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);

  ctx.number_of_calls = 0;
  ctx.value_to_return = FALSE;
  gum_api_resolver_enumerate_matches (fixture->resolver, "+[*Arr* arr*]",
      match_found_cb, &ctx, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, ==, 1);
}

TESTCASE (objc_methods_can_be_resolved_case_insensitively)
{
  TestForEachContext ctx;
  GError * error = NULL;

  fixture->resolver = gum_api_resolver_make ("objc");
  if (fixture->resolver == NULL)
  {
    g_print ("<skipping, not available> ");
    return;
  }

  ctx.number_of_calls = 0;
  ctx.value_to_return = TRUE;
  gum_api_resolver_enumerate_matches (fixture->resolver, "+[*Arr* aRR*]/i",
      match_found_cb, &ctx, &error);
  g_assert_no_error (error);
  g_assert_cmpuint (ctx.number_of_calls, >, 1);
}

static gboolean
match_found_cb (const GumApiDetails * details,
                gpointer user_data)
{
  TestForEachContext * ctx = (TestForEachContext *) user_data;

  ctx->number_of_calls++;

  return ctx->value_to_return;
}

#ifdef HAVE_DARWIN

static gboolean resolve_method_impl (const GumApiDetails * details,
    gpointer user_data);
static gboolean accumulate_matches (const GumApiDetails * details,
    gpointer user_data);

TESTCASE (objc_method_can_be_resolved_from_class_method_address)
{
  GumAddress address;
  gchar * method = NULL;
  GError * error = NULL;

  fixture->resolver = gum_api_resolver_make ("objc");
  if (fixture->resolver == NULL)
  {
    g_print ("<skipping, not available> ");
    return;
  }

  gum_api_resolver_enumerate_matches (fixture->resolver, "+[NSArray array]",
      resolve_method_impl, &address, &error);
  g_assert_no_error (error);

  method = _gum_objc_api_resolver_find_method_by_address (fixture->resolver,
      address);
  g_assert_nonnull (method);
  g_free (method);
}

TESTCASE (objc_method_can_be_resolved_from_instance_method_address)
{
  GumAddress address;
  gchar * method = NULL;
  GError * error = NULL;

  fixture->resolver = gum_api_resolver_make ("objc");
  if (fixture->resolver == NULL)
  {
    g_print ("<skipping, not available> ");
    return;
  }

  gum_api_resolver_enumerate_matches (fixture->resolver,
      "-[NSArray initWithArray:]", resolve_method_impl, &address, &error);
  g_assert_no_error (error);

  method = _gum_objc_api_resolver_find_method_by_address (fixture->resolver,
      address);
  g_assert_nonnull (method);
  g_free (method);
}

TESTCASE (swift_method_can_be_resolved)
{
  guint num_matches;
  GError * error = NULL;

  fixture->resolver = gum_api_resolver_make ("swift");

  num_matches = 0;
  gum_api_resolver_enumerate_matches (fixture->resolver,
      "functions:*!*", accumulate_matches, &num_matches, &error);
  if (g_error_matches (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED))
    goto not_supported;
  g_assert_no_error (error);

  return;

not_supported:
  {
    g_print ("<skipping, not available> ");

    g_error_free (error);
  }
}

static gboolean
resolve_method_impl (const GumApiDetails * details,
                     gpointer user_data)
{
  GumAddress * address = user_data;

  *address = details->address;

  return FALSE;
}

static gboolean
accumulate_matches (const GumApiDetails * details,
                    gpointer user_data)
{
  guint * total = user_data;

  (*total)++;

  return TRUE;
}

#endif

#ifdef HAVE_ANDROID

typedef struct _TestLinkerExportsContext TestLinkerExportsContext;

struct _TestLinkerExportsContext
{
  guint number_of_calls;

  gchar * expected_name;
  GumAddress expected_address;
};

static gboolean check_linker_export (const GumApiDetails * details,
    gpointer user_data);

TESTCASE (linker_exports_can_be_resolved_on_android)
{
  const gchar * linker_name, * libdl_name;
  const gchar * linker_exports[] =
  {
    "dlopen",
    "dlsym",
    "dlclose",
    "dlerror",
  };
  const gchar * correct_module_name, * incorrect_module_name;
  guint i;

  if (gum_android_get_api_level () >= 29)
  {
    linker_name = (sizeof (gpointer) == 4)
        ? "/apex/com.android.runtime/bin/linker"
        : "/apex/com.android.runtime/bin/linker64";
    libdl_name = (sizeof (gpointer) == 4)
        ? "/apex/com.android.runtime/lib/bionic/libdl.so"
        : "/apex/com.android.runtime/lib64/bionic/libdl.so";
  }
  else
  {
    linker_name = (sizeof (gpointer) == 4)
        ? "/system/bin/linker"
        : "/system/bin/linker64";
    libdl_name = (sizeof (gpointer) == 4)
        ? "/system/lib/libdl.so"
        : "/system/lib64/libdl.so";
  }

  if (gum_android_get_api_level () >= 26)
  {
    correct_module_name = libdl_name;
    incorrect_module_name = linker_name;
  }
  else
  {
    correct_module_name = linker_name;
    incorrect_module_name = libdl_name;
  }

  fixture->resolver = gum_api_resolver_make ("module");
  g_assert_nonnull (fixture->resolver);

  for (i = 0; i != G_N_ELEMENTS (linker_exports); i++)
  {
    const gchar * func_name = linker_exports[i];
    gchar * query;
    TestLinkerExportsContext ctx;
    GError * error = NULL;

    query = g_strconcat ("exports:*!", func_name, NULL);

    g_assert_true (
        gum_module_find_export_by_name (incorrect_module_name, func_name) == 0);

    ctx.number_of_calls = 0;
    ctx.expected_name =
        g_strdup_printf ("%s!%s", correct_module_name, func_name);
    ctx.expected_address =
        gum_module_find_export_by_name (correct_module_name, func_name);
    g_assert_cmpuint (ctx.expected_address, !=, 0);

    gum_api_resolver_enumerate_matches (fixture->resolver, query,
        check_linker_export, &ctx, &error);
    g_assert_no_error (error);
    g_assert_cmpuint (ctx.number_of_calls, >=, 1);

    g_free (ctx.expected_name);

    g_free (query);
  }
}

static gboolean
check_linker_export (const GumApiDetails * details,
                     gpointer user_data)
{
  TestLinkerExportsContext * ctx = (TestLinkerExportsContext *) user_data;

  g_assert_cmpstr (details->name, ==, ctx->expected_name);
  g_assert_cmphex (details->address, ==, ctx->expected_address);

  ctx->number_of_calls++;

  return TRUE;
}

#endif

"""

```