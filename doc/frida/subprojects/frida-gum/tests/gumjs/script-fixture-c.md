Response:
Let's break down the thought process for analyzing this C code for the Frida test fixture.

**1. Initial Understanding and Goal:**

The first step is to recognize the context. The file path `frida/subprojects/frida-gum/tests/gumjs/script-fixture.c` immediately suggests this is part of Frida's testing framework, specifically for testing JavaScript interaction within the Gum library (Frida's core). The "fixture" part is a strong indicator it's used to set up and tear down a controlled environment for running tests. The goal is to understand its functionalities and how they relate to reverse engineering, low-level aspects, and potential user errors.

**2. High-Level Structure Scan:**

Quickly scan the code for key elements:

* **Includes:** Notice headers like `gum-init.h`, `guminspectorserver.h`, `gumquickscriptbackend.h`, `gumscriptbackend.h`, `glib.h`, and system headers like `stdio.h`, `stdlib.h`, `string.h`, `unistd.h`, `windows.h` (conditional). This confirms the file interacts with Frida/Gum components, uses GLib for utility functions, and handles platform differences.
* **Macros:**  A large number of macros starting with `TESTCASE`, `TESTENTRY`, `COMPILE_AND_LOAD_SCRIPT`, `EXPECT_*`. These are likely the core API provided by this fixture for writing tests. The `EXPECT_*` macros suggest a mechanism for verifying the behavior of the code under test (the Frida scripts).
* **Typedefs and Structs:**  `TestScriptFixture` and `TestScriptMessageItem`. This reveals the main data structures used to manage the test environment and track messages.
* **Functions:** Scan for function names starting with `test_script_fixture_`. These are the implementation details of the fixture. Look for keywords like `setup`, `teardown`, `compile`, `load`, `unload`, `post`, `expect`.
* **Global Variables:**  `exceptor`. This hints at exception handling within the testing framework.

**3. Deeper Dive into Key Functionalities:**

Now, go back and analyze the most important parts more closely:

* **`TestScriptFixture` Structure:** Understand the members: `backend` (script engine), `script` (the loaded script), `loop`/`context` (GLib's event loop for asynchronous operations), `messages` (a queue to capture messages from the script), `timeouts`, `tempfiles`, `heap_blocks` (resource management during testing).
* **`test_script_fixture_setup` and `test_script_fixture_teardown`:** These are standard test fixture lifecycle functions. Setup initializes the environment, and teardown cleans it up, preventing interference between tests. Note the resource management here (freeing memory, unlinking temp files).
* **`test_script_fixture_compile_and_load_script`:** This function takes JavaScript source code as input, compiles it using the selected backend (`GumScriptBackend`), and loads it into the Frida environment. This is crucial for testing script execution.
* **`test_script_fixture_store_message`:** This is the callback function that receives messages sent from the JavaScript code running within Frida. It stores these messages in the `messages` queue. Notice the handling of log messages separately.
* **`test_script_fixture_try_pop_message` and `_test_script_fixture_pop_message`:**  These functions retrieve messages sent from the script, with a timeout mechanism. This allows tests to wait for expected messages.
* **`EXPECT_*` Macros:**  These are assertion helpers. Analyze what they do:
    * `EXPECT_SEND_MESSAGE_WITH`: Checks for a specific message payload.
    * `EXPECT_SEND_MESSAGE_WITH_PREFIX`: Checks if a message starts with a certain prefix.
    * `EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA`: Checks both payload and raw data.
    * `EXPECT_ERROR_MESSAGE_WITH`: Checks for specific error messages, including line numbers.
    * `EXPECT_LOG_MESSAGE_WITH`: Checks for log messages with a specific level and payload.
* **Resource Management:** Pay attention to how temporary files are created (`test_script_fixture_make_tempfile_containing`) and cleaned up. The `heap_blocks` queue suggests tracking allocated memory for cleanup.

**4. Connecting to the Prompts:**

Now, specifically address each part of the prompt:

* **Functionality:** Summarize the purpose of each major function and the overall goal of the fixture (providing a controlled environment for testing Frida scripts).
* **Reverse Engineering:**  Think about how Frida is used in reverse engineering. This fixture facilitates testing scripts that hook into processes, modify behavior, and extract information. The example of hooking a function and sending back arguments/return value is a direct application of Frida in reverse engineering.
* **Binary/Low-Level/Kernel:** Identify parts that touch upon these areas. The inclusion of architecture-specific register names (`GUM_RETURN_VALUE_REGISTER_NAME`) shows awareness of low-level details. The handling of raw data in messages relates to binary data. While the fixture itself doesn't directly interact with the kernel, it *enables* the testing of scripts that *do*. Mention concepts like process injection and code modification. The platform-specific socket handling is also relevant.
* **Logical Reasoning (Assumptions/Inputs/Outputs):** Focus on the `EXPECT_*` macros. Imagine a simple test case: loading a script that sends a message "hello". The input is the script source, the expected output is the captured message. Consider error scenarios too.
* **User/Programming Errors:** Think about how someone might misuse the fixture. Forgetting to unload scripts, incorrect assertions, not handling asynchronous operations properly (timeouts), and resource leaks are common errors in testing.
* **User Steps to Reach Here (Debugging):** Trace the typical workflow of a Frida user developing a script and running tests. They write a script, write a test using this fixture, run the tests, and if a test fails, they might need to examine the fixture's behavior.

**5. Refine and Organize:**

Finally, organize the findings into a clear and structured answer, using headings and bullet points for readability. Ensure that the examples are relevant and illustrate the points being made. Use precise language and avoid jargon where possible, or explain it when necessary. Review and edit for clarity and accuracy.

This iterative process of understanding the code's structure, diving into details, and connecting it to the specific requirements of the prompt helps to produce a comprehensive and accurate analysis.
这是 `frida/subprojects/frida-gum/tests/gumjs/script-fixture.c` 文件的源代码，它是一个用于 Frida 动态Instrumentation工具的测试框架的一部分。这个文件的主要目的是提供一个方便的 C API，用于创建和管理用于测试 Frida JavaScript 脚本的环境。

以下是它的功能以及与逆向、底层知识、逻辑推理和用户错误的关联：

**功能列举:**

1. **创建和销毁 Frida 脚本环境:**  它提供了 `test_script_fixture_setup` 和 `test_script_fixture_teardown` 函数，用于在每个测试用例执行前后初始化和清理 Frida 脚本运行所需的上下文。这包括创建 `GumScriptBackend` (例如 V8 或 QuickJS) 和管理消息循环。
2. **编译和加载 Frida 脚本:** `test_script_fixture_compile_and_load_script` 函数允许将 JavaScript 源代码编译并加载到 Frida 的 Gum 引擎中。
3. **卸载 Frida 脚本:**  提供了 `UNLOAD_SCRIPT()` 宏，用于安全地卸载已加载的 Frida 脚本，释放相关资源。
4. **向 Frida 脚本发送消息:** `POST_MESSAGE(MSG)` 宏允许从 C 代码向正在运行的 Frida 脚本发送消息。
5. **断言没有收到消息:** `EXPECT_NO_MESSAGES()` 宏用于验证在一定时间内是否没有从 Frida 脚本接收到消息。
6. **断言收到特定消息:** 提供了一系列 `EXPECT_SEND_MESSAGE_WITH*` 宏，用于断言从 Frida 脚本接收到的消息的内容是否符合预期，可以匹配完整的 payload，payload的前缀，或者 payload 和二进制数据。
7. **断言收到错误消息:** `EXPECT_ERROR_MESSAGE_WITH` 和 `EXPECT_ERROR_MESSAGE_MATCHING` 宏用于断言从 Frida 脚本接收到的错误消息的内容和行号是否符合预期，支持精确匹配和正则表达式匹配。
8. **断言收到日志消息:** `EXPECT_LOG_MESSAGE_WITH` 宏用于断言从 Frida 脚本接收到的日志消息的级别和内容是否符合预期。
9. **管理消息接收超时:** `PUSH_TIMEOUT` 和 `POP_TIMEOUT` 宏允许在测试用例中临时修改消息接收的超时时间。
10. **禁用日志消息处理:** `DISABLE_LOG_MESSAGE_HANDLING()` 宏可以禁用测试框架对 Frida 脚本日志消息的自动打印。
11. **创建包含特定内容的临时文件:** `MAKE_TEMPFILE_CONTAINING` 宏方便在测试中创建包含特定内容的临时文件，用于模拟 Frida 脚本需要访问的文件场景。
12. **转义路径:** `ESCAPE_PATH` 宏用于处理不同操作系统下路径表示的差异，尤其是在 Windows 上需要转义反斜杠。

**与逆向方法的关联 (举例说明):**

Frida 本身就是一个强大的逆向工程工具，这个 fixture 文件是为了测试使用 Frida 进行逆向操作的脚本。

* **例子:** 假设我们想测试一个 Frida 脚本，该脚本 hook 了 `open` 系统调用，并在打开特定文件时发送一条消息。我们可以使用这个 fixture 文件编写如下测试用例：

```c
TESTCASE (test_open_hook)
{
  COMPILE_AND_LOAD_SCRIPT (
    "Interceptor.attach(Module.findExportByName(null, 'open'), {"
    "  onEnter: function (args) {"
    "    if (args[0].readUtf8String().indexOf('secret.txt') !== -1) {"
    "      send('opening secret file');"
    "    }"
    "  }"
    "});"
  );
  // 假设目标程序打开了名为 "secret.txt" 的文件
  // ... (模拟触发目标程序打开文件的操作) ...
  EXPECT_SEND_MESSAGE_WITH ("\"opening secret file\"");
  UNLOAD_SCRIPT();
}
```

在这个例子中，`COMPILE_AND_LOAD_SCRIPT` 加载了 hook `open` 调用的 Frida 脚本。然后，测试用例会模拟触发目标程序打开 "secret.txt" 文件的行为。`EXPECT_SEND_MESSAGE_WITH` 断言我们是否收到了预期的消息 "opening secret file"，这验证了我们的 Frida 脚本是否成功 hook 并执行了预期的操作。

**涉及二进制底层，Linux, Android 内核及框架的知识 (举例说明):**

* **二进制底层:**
    * `GUM_PTR_CONST` 宏定义了指针的格式化字符串，直接涉及到内存地址的表示，这是二进制层面的概念。
    * `test_script_fixture_expect_send_message_with_payload_and_data` 函数处理发送带有二进制数据的消息，需要理解二进制数据的表示和传输。
    * `GUM_RETURN_VALUE_REGISTER_NAME` 宏根据不同的 CPU 架构定义了返回值寄存器的名称 (如 "eax", "rax", "r0", "x0")，这直接关联到计算机的指令集架构和寄存器使用约定。

* **Linux/Android 内核及框架:**
    * 该 fixture 依赖于 Frida Gum 库，Frida Gum 能够与目标进程进行交互，包括内存读写、函数 hook 等操作，这些操作在底层会涉及到操作系统内核提供的 API (如 ptrace)。
    * 测试中模拟的目标程序行为，例如打开文件，实际上是模拟了 Linux 或 Android 系统调用的执行。
    * 在 Android 平台上，Frida 能够 hook Java 层的方法，这涉及到 Android 运行时的知识，例如 ART/Dalvik 虚拟机。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  一个包含 JavaScript 代码的字符串，例如 `"send('hello');"`。
* **对应函数:** `test_script_fixture_compile_and_load_script` 被调用，并将该字符串作为 `source_template` 参数传递。
* **预期输出:**  Frida 脚本被成功编译和加载，并且可以通过 `test_script_fixture_store_message` 函数接收到来自脚本的消息。如果随后调用 `EXPECT_SEND_MESSAGE_WITH("\"hello\"")`，则测试会通过。

* **假设输入:** 一个包含错误 JavaScript 语法的字符串，例如 `"send('hello')"` (缺少引号)。
* **对应函数:** `test_script_fixture_compile_and_load_script` 被调用。
* **预期输出:**  `gum_script_backend_create_sync` 函数会返回一个错误，并且 `fixture->script` 将为 NULL。测试框架会断言 `g_assert_nonnull (fixture->script)` 失败，指示脚本编译失败。

**涉及用户或者编程常见的使用错误 (举例说明):**

1. **忘记卸载脚本:** 用户可能在测试用例中加载了脚本，但在测试结束时忘记调用 `UNLOAD_SCRIPT()` 或相应的卸载函数。这会导致资源泄漏，并可能影响后续的测试用例。Fixture 的 `test_script_fixture_teardown` 函数会确保即使测试用例本身忘记卸载，也会进行清理。
2. **错误的断言:** 用户可能使用了错误的 `EXPECT_*` 宏来断言接收到的消息。例如，期望收到包含特定字符串的消息，却使用了精确匹配的 `EXPECT_SEND_MESSAGE_WITH`，导致测试失败。
3. **超时设置不当:** 如果 Frida 脚本执行的操作需要一定时间，用户可能需要调整消息接收的超时时间。如果超时时间设置过短，即使脚本发送了消息，测试也可能因为超时而失败。`PUSH_TIMEOUT` 和 `POP_TIMEOUT` 提供了调整超时时间的机制，但用户需要根据实际情况进行设置。
4. **异步操作处理不当:** Frida 的某些操作是异步的。用户可能期望在加载脚本后立即收到消息，但实际上消息可能在稍后才发送。这时需要理解 Frida 的异步模型，并使用适当的等待机制或断言方式。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **开发 Frida 脚本:**  用户首先会编写一个 Frida JavaScript 脚本，用于实现特定的动态 Instrumentation 功能，例如 hook 函数、修改内存、跟踪调用等。
2. **编写测试用例:** 为了验证脚本的正确性，用户会编写 C 代码的测试用例，使用这个 `script-fixture.c` 文件提供的 API。他们会包含头文件，定义 `TESTCASE`，使用 `COMPILE_AND_LOAD_SCRIPT` 加载他们的 Frida 脚本。
3. **执行测试:** 用户会使用构建系统 (例如 `meson`) 和测试运行器 (例如 `gtester`) 来编译和执行这些测试用例。
4. **测试失败:**  如果测试用例中的断言失败，用户会查看测试输出，了解哪个断言失败了。
5. **调试:**  为了找出问题所在，用户可能会：
    * **查看 Frida 脚本的输出:**  通过 `console.log` 等方式在 Frida 脚本中打印调试信息，fixture 会将这些信息输出到终端。
    * **检查 `EXPECT_*` 宏的参数:**  确保断言的目标消息内容、正则表达式、行号等是正确的。
    * **使用调试器调试 C 代码:**  如果怀疑是 fixture 本身的问题或者 C 代码的逻辑错误，用户可以使用 GDB 等调试器来逐步执行测试用例的代码，查看变量的值，跟踪函数的调用。
    * **阅读 `script-fixture.c` 的源代码:**  当遇到难以理解的测试行为时，用户可能会直接查看 `script-fixture.c` 的源代码，了解各个宏和函数的具体实现，例如消息是如何接收和存储的，超时是如何控制的等等。

总而言之，`frida/subprojects/frida-gum/tests/gumjs/script-fixture.c` 是 Frida 测试框架的关键组成部分，它为开发者提供了一种结构化的方式来测试他们的 Frida JavaScript 脚本，确保其功能正确可靠。理解这个文件的功能和实现，对于开发和调试 Frida 相关的项目至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/script-fixture.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2010-2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 * Copyright (C) 2020-2021 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2020 Marcus Mengs <mame8282@googlemail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "testutil.h"

#include "gum-init.h"
#include "guminspectorserver.h"
#include "gumquickscriptbackend.h"
#include "gumscriptbackend.h"
#include "valgrind.h"

#include <limits.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <glib/gstdio.h>
#include <gio/gio.h>
#ifdef HAVE_WINDOWS
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <intrin.h>
# include <tchar.h>
# include <windows.h>
# include <winsock2.h>
# include <ws2tcpip.h>
#else
# include <errno.h>
# include <fcntl.h>
# include <netinet/in.h>
# include <sys/socket.h>
# include <sys/un.h>
# include <unistd.h>
#endif
#if HAVE_DARWIN
# include <mach/mach.h>
#endif
#ifdef HAVE_QNX
# include <unix.h>
#endif

#define ANY_LINE_NUMBER -1
#define SCRIPT_MESSAGE_DEFAULT_TIMEOUT_MSEC 500

#ifndef SCRIPT_SUITE
# define SCRIPT_SUITE ""
#endif
#define TESTCASE(NAME) \
    void test_script_ ## NAME (TestScriptFixture * fixture, gconstpointer data)
#define TESTENTRY(NAME)                                                   \
    G_STMT_START                                                          \
    {                                                                     \
      extern void test_script_ ##NAME (TestScriptFixture * fixture,       \
          gconstpointer data);                                            \
      gchar * path;                                                       \
                                                                          \
      path = g_strconcat ("/GumJS/Script/" SCRIPT_SUITE, group, #NAME "#",\
          GUM_QUICK_IS_SCRIPT_BACKEND (fixture_data) ? "QJS" : "V8",      \
          NULL);                                                          \
                                                                          \
      g_test_add (path,                                                   \
          TestScriptFixture,                                              \
          fixture_data,                                                   \
          test_script_fixture_setup,                                      \
          test_script_ ##NAME,                                            \
          test_script_fixture_teardown);                                  \
                                                                          \
      g_free (path);                                                      \
    }                                                                     \
    G_STMT_END;

#define COMPILE_AND_LOAD_SCRIPT(SOURCE, ...) \
    test_script_fixture_compile_and_load_script (fixture, SOURCE, \
    ## __VA_ARGS__)
#define UNLOAD_SCRIPT() \
    gum_script_unload_sync (fixture->script, NULL); \
    g_object_unref (fixture->script); \
    fixture->script = NULL;
#define POST_MESSAGE(MSG) \
    gum_script_post (fixture->script, MSG, NULL)
#define EXPECT_NO_MESSAGES() \
    g_assert_null (test_script_fixture_try_pop_message (fixture, 1))
#define EXPECT_SEND_MESSAGE_WITH(PAYLOAD, ...) \
    test_script_fixture_expect_send_message_with (fixture, G_STRFUNC, \
        __FILE__, __LINE__, PAYLOAD, ## __VA_ARGS__)
#define EXPECT_SEND_MESSAGE_WITH_PREFIX(PREFIX, ...) \
    test_script_fixture_expect_send_message_with_prefix (fixture, G_STRFUNC, \
        __FILE__, __LINE__, PREFIX, ## __VA_ARGS__)
#define EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA(PAYLOAD, DATA) \
    test_script_fixture_expect_send_message_with_payload_and_data (fixture, \
        G_STRFUNC, __FILE__, __LINE__, PAYLOAD, DATA)
#define EXPECT_SEND_MESSAGE_WITH_POINTER() \
    test_script_fixture_expect_send_message_with_pointer (fixture, G_STRFUNC, \
        __FILE__, __LINE__)
#define EXPECT_ERROR_MESSAGE_WITH(LINE_NUMBER, DESC) \
    test_script_fixture_expect_error_message_with (fixture, G_STRFUNC, \
        __FILE__, __LINE__, LINE_NUMBER, DESC)
#define EXPECT_ERROR_MESSAGE_MATCHING(LINE_NUMBER, PATTERN) \
    test_script_fixture_expect_error_message_matching (fixture, G_STRFUNC, \
        __FILE__, __LINE__, LINE_NUMBER, PATTERN)
#define EXPECT_LOG_MESSAGE_WITH(LEVEL, PAYLOAD, ...) \
    test_script_fixture_expect_log_message_with (fixture, G_STRFUNC, \
        __FILE__, __LINE__, LEVEL, PAYLOAD, ## __VA_ARGS__)
#define PUSH_TIMEOUT(value) test_script_fixture_push_timeout (fixture, value)
#define POP_TIMEOUT() test_script_fixture_pop_timeout (fixture)
#define DISABLE_LOG_MESSAGE_HANDLING() \
    fixture->enable_log_message_handling = FALSE
#define MAKE_TEMPFILE_CONTAINING(str) \
    test_script_fixture_make_tempfile_containing (fixture, str)
#define ESCAPE_PATH(path) \
    test_script_fixture_escape_path (fixture, path)
#define test_script_fixture_pop_message(fixture) \
    _test_script_fixture_pop_message (fixture, G_STRFUNC, __FILE__, __LINE__)

#define GUM_PTR_CONST "ptr(\"0x%" G_GSIZE_MODIFIER "x\")"

#define gum_assert_cmpstr(func, file, line, s1, cmp, s2) \
    G_STMT_START \
    { \
      const char * __s1 = (s1), * __s2 = (s2); \
      if (g_strcmp0 (__s1, __s2) cmp 0) ; else \
        g_assertion_message_cmpstr (G_LOG_DOMAIN, file, line, func, \
            #s1 " " #cmp " " #s2, __s1, #cmp, __s2); \
    } \
    G_STMT_END
#define gum_assert_true(func, file, line, expr) \
    G_STMT_START \
    { \
      if G_LIKELY (expr) ; else \
        g_assertion_message (G_LOG_DOMAIN, file, line, func, \
            "'" #expr "' should be TRUE"); \
    } \
    G_STMT_END
#define gum_assert_false(func, file, line, expr) \
    G_STMT_START \
    { \
      if G_LIKELY (!(expr)) ; else \
        g_assertion_message (G_LOG_DOMAIN, file, line, func, \
            "'" #expr "' should be FALSE"); \
    } \
    G_STMT_END
#define gum_assert_null(func, file, line, expr) \
    G_STMT_START \
    { \
      if G_LIKELY ((expr) == NULL) ; else \
        g_assertion_message (G_LOG_DOMAIN, file, line, func, \
            "'" #expr "' should be NULL"); \
    } \
    G_STMT_END
#define gum_assert_nonnull(func, file, line, expr) \
    G_STMT_START \
    { \
      if G_LIKELY ((expr) != NULL) ; else \
        g_assertion_message (G_LOG_DOMAIN, file, line, func, \
            "'" #expr "' should not be NULL"); \
    } \
    G_STMT_END
#define gum_assert_cmpint(func, file, line, n1, cmp, n2) \
    G_STMT_START \
    { \
      gint64 __n1 = (n1), __n2 = (n2); \
      if (__n1 cmp __n2) ; else \
        g_assertion_message_cmpnum (G_LOG_DOMAIN, file, line, func, \
            #n1 " " #cmp " " #n2, (long double) __n1, #cmp,\
            (long double) __n2, 'i'); \
    } \
    G_STMT_END

#ifdef HAVE_WINDOWS
# define GUM_CLOSE_SOCKET(s) closesocket (s)
#else
# define GUM_CLOSE_SOCKET(s) close (s)
#endif

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
# define GUM_RETURN_VALUE_REGISTER_NAME "eax"
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
# define GUM_RETURN_VALUE_REGISTER_NAME "rax"
#elif defined (HAVE_ARM)
# define GUM_RETURN_VALUE_REGISTER_NAME "r0"
#elif defined (HAVE_ARM64)
# define GUM_RETURN_VALUE_REGISTER_NAME "x0"
#elif defined (HAVE_MIPS)
# define GUM_RETURN_VALUE_REGISTER_NAME "v0"
#else
# error Unsupported architecture
#endif

typedef struct _TestScriptFixture TestScriptFixture;
typedef struct _TestScriptMessageItem TestScriptMessageItem;

struct _TestScriptFixture
{
  GumScriptBackend * backend;
  GumScript * script;
  GMainLoop * loop;
  GMainContext * context;
  GQueue messages;
  GQueue timeouts;
  GQueue tempfiles;
  GQueue heap_blocks;
  gboolean enable_log_message_handling;
};

struct _TestScriptMessageItem
{
  gchar * message;
  gchar * data;
  GBytes * raw_data;
};

static void test_script_message_item_free (TestScriptMessageItem * item);
static gboolean test_script_fixture_try_handle_log_message (
    TestScriptFixture * self, const gchar * raw_message);
static TestScriptMessageItem * test_script_fixture_try_pop_message (
    TestScriptFixture * fixture, guint timeout);
static gboolean test_script_fixture_stop_loop (TestScriptFixture * fixture);
static void test_script_fixture_expect_send_message_with_prefix (
    TestScriptFixture * fixture, const gchar * func, const gchar * file,
    gint line, const gchar * prefix_template, ...);
static void test_script_fixture_expect_send_message_with_payload_and_data (
    TestScriptFixture * fixture, const gchar * func, const gchar * file,
    gint line, const gchar * payload, const gchar * data);
static void test_script_fixture_expect_error_message_with (
    TestScriptFixture * fixture, const gchar * func, const gchar * file,
    gint line, gint line_number, const gchar * description);
static void test_script_fixture_expect_error_message_matching (
    TestScriptFixture * fixture, const gchar * func, const gchar * file,
    gint line, gint line_number, const gchar * pattern);
static void test_script_fixture_expect_log_message_with (
    TestScriptFixture * fixture, const gchar * func, const gchar * file,
    gint line, const gchar * level, const gchar * payload_template, ...);
static void test_script_fixture_push_timeout (TestScriptFixture * fixture,
    guint timeout);
static void test_script_fixture_pop_timeout (TestScriptFixture * fixture);

static GumExceptor * exceptor = NULL;

static void
test_script_fixture_deinit (void)
{
  g_object_unref (exceptor);
  exceptor = NULL;
}

static void
test_script_fixture_setup (TestScriptFixture * fixture,
                           gconstpointer data)
{
  (void) test_script_fixture_expect_send_message_with_prefix;
  (void) test_script_fixture_expect_send_message_with_payload_and_data;
  (void) test_script_fixture_expect_error_message_with;
  (void) test_script_fixture_expect_error_message_matching;
  (void) test_script_fixture_expect_log_message_with;
  (void) test_script_fixture_pop_timeout;

  fixture->backend = (GumScriptBackend *) data;
  fixture->context = g_main_context_ref_thread_default ();
  fixture->loop = g_main_loop_new (fixture->context, FALSE);
  g_queue_init (&fixture->messages);
  g_queue_init (&fixture->timeouts);
  g_queue_init (&fixture->tempfiles);
  g_queue_init (&fixture->heap_blocks);
  fixture->enable_log_message_handling = TRUE;

  test_script_fixture_push_timeout (fixture,
      SCRIPT_MESSAGE_DEFAULT_TIMEOUT_MSEC);

  if (exceptor == NULL)
  {
    exceptor = gum_exceptor_obtain ();
    _gum_register_destructor (test_script_fixture_deinit);
  }
}

static void
test_script_fixture_teardown (TestScriptFixture * fixture,
                              gconstpointer data)
{
  gchar * path;
  TestScriptMessageItem * item;

  if (fixture->script != NULL)
  {
    gum_script_unload_sync (fixture->script, NULL);
    g_object_unref (fixture->script);
  }

  while (g_main_context_pending (fixture->context))
    g_main_context_iteration (fixture->context, FALSE);

  g_queue_clear_full (&fixture->heap_blocks, g_free);

  while ((path = g_queue_pop_tail (&fixture->tempfiles)) != NULL)
  {
    g_unlink (path);
    g_free (path);
  }

  while ((item = test_script_fixture_try_pop_message (fixture, 1)) != NULL)
  {
    test_script_message_item_free (item);
  }

  g_queue_clear (&fixture->timeouts);

  g_main_loop_unref (fixture->loop);
  g_main_context_unref (fixture->context);
}

static void
test_script_message_item_free (TestScriptMessageItem * item)
{
  g_free (item->message);
  g_free (item->data);
  g_bytes_unref (item->raw_data);
  g_slice_free (TestScriptMessageItem, item);
}

static void
test_script_fixture_store_message (const gchar * message,
                                   GBytes * data,
                                   gpointer user_data)
{
  TestScriptFixture * self = (TestScriptFixture *) user_data;
  TestScriptMessageItem * item;

  if (test_script_fixture_try_handle_log_message (self, message))
    return;

  item = g_slice_new (TestScriptMessageItem);
  item->message = g_strdup (message);

  if (data != NULL)
  {
    const guint8 * data_elements;
    gsize data_size, i;
    GString * s;

    data_elements = g_bytes_get_data (data, &data_size);

    s = g_string_sized_new (3 * data_size);
    for (i = 0; i != data_size; i++)
    {
      if (i != 0)
        g_string_append_c (s, ' ');
      g_string_append_printf (s, "%02x", (int) data_elements[i]);
    }

    item->data = g_string_free (s, FALSE);
    item->raw_data = g_bytes_ref (data);
  }
  else
  {
    item->data = NULL;
    item->raw_data = NULL;
  }

  g_queue_push_tail (&self->messages, item);
  g_main_loop_quit (self->loop);
}

static gboolean
test_script_fixture_try_handle_log_message (TestScriptFixture * self,
                                            const gchar * raw_message)
{
  gboolean handled = FALSE;
  JsonNode * message;
  JsonReader * reader;
  const gchar * text;
  const gchar * level;
  guint color = 37;

  if (!self->enable_log_message_handling)
    return FALSE;

  message = json_from_string (raw_message, NULL);
  reader = json_reader_new (message);
  json_node_unref (message);

  json_reader_read_member (reader, "type");
  if (strcmp (json_reader_get_string_value (reader), "log") != 0)
    goto beach;
  json_reader_end_member (reader);

  json_reader_read_member (reader, "payload");
  text = json_reader_get_string_value (reader);
  json_reader_end_member (reader);

  json_reader_read_member (reader, "level");
  level = json_reader_get_string_value (reader);
  json_reader_end_member (reader);
  if (strcmp (level, "info") == 0)
    color = 36;
  else if (strcmp (level, "warning") == 0)
    color = 33;
  else if (strcmp (level, "error") == 0)
    color = 31;
  else
    g_assert_not_reached ();

  g_printerr (
      "\033[0;%um"
      "%s"
      "\033[0m"
      "\n",
      color, text);

  handled = TRUE;

beach:
  g_object_unref (reader);

  return handled;
}

static void
test_script_fixture_compile_and_load_script (TestScriptFixture * fixture,
                                             const gchar * source_template,
                                             ...)
{
  va_list args;
  gchar * source;
  GError * err = NULL;

  if (fixture->script != NULL)
  {
    gum_script_unload_sync (fixture->script, NULL);
    g_object_unref (fixture->script);
    fixture->script = NULL;
  }

  va_start (args, source_template);
  source = g_strdup_vprintf (source_template, args);
  va_end (args);

  fixture->script = gum_script_backend_create_sync (fixture->backend,
      "testcase", source, NULL, NULL, &err);
  if (err != NULL)
    g_printerr ("%s\n", err->message);
  g_assert_nonnull (fixture->script);
  g_assert_null (err);

  g_free (source);

  gum_script_set_message_handler (fixture->script,
      test_script_fixture_store_message, fixture, NULL);

  gum_script_load_sync (fixture->script, NULL);
}

static TestScriptMessageItem *
test_script_fixture_try_pop_message (TestScriptFixture * fixture,
                                     guint timeout)
{
  if (g_queue_is_empty (&fixture->messages))
  {
    GSource * source;

    source = g_timeout_source_new (timeout);
    g_source_set_callback (source, (GSourceFunc) test_script_fixture_stop_loop,
        fixture, NULL);
    g_source_attach (source, fixture->context);

    g_main_loop_run (fixture->loop);

    g_source_destroy (source);
    g_source_unref (source);
  }

  return g_queue_pop_head (&fixture->messages);
}

static gboolean
test_script_fixture_stop_loop (TestScriptFixture * fixture)
{
  g_main_loop_quit (fixture->loop);

  return FALSE;
}

static TestScriptMessageItem *
_test_script_fixture_pop_message (TestScriptFixture * fixture,
                                  const gchar * func,
                                  const gchar * file,
                                  gint line)
{
  guint timeout;
  TestScriptMessageItem * item;

  timeout = GPOINTER_TO_UINT (g_queue_peek_tail (&fixture->timeouts));

  item = test_script_fixture_try_pop_message (fixture, timeout);
  gum_assert_nonnull (func, file, line, item);

  return item;
}

static void
test_script_fixture_expect_send_message_with (TestScriptFixture * fixture,
                                              const gchar * func,
                                              const gchar * file,
                                              gint line,
                                              const gchar * payload_template,
                                              ...)
{
  va_list args;
  gchar * payload;
  TestScriptMessageItem * item;
  gchar * expected_message;

  va_start (args, payload_template);
  payload = g_strdup_vprintf (payload_template, args);
  va_end (args);

  item = _test_script_fixture_pop_message (fixture, func, file, line);
  expected_message =
      g_strconcat ("{\"type\":\"send\",\"payload\":", payload, "}", NULL);
  gum_assert_cmpstr (func, file, line, item->message, ==, expected_message);
  test_script_message_item_free (item);
  g_free (expected_message);

  g_free (payload);
}

static void
test_script_fixture_expect_send_message_with_prefix (
    TestScriptFixture * fixture,
    const gchar * func,
    const gchar * file,
    gint line,
    const gchar * prefix_template,
    ...)
{
  va_list args;
  gchar * prefix;
  TestScriptMessageItem * item;
  gchar * expected_message_prefix;

  va_start (args, prefix_template);
  prefix = g_strdup_vprintf (prefix_template, args);
  va_end (args);

  item = _test_script_fixture_pop_message (fixture, func, file, line);
  expected_message_prefix =
      g_strconcat ("{\"type\":\"send\",\"payload\":", prefix, NULL);
  gum_assert_true (func, file, line,
      g_str_has_prefix (item->message, expected_message_prefix));
  test_script_message_item_free (item);
  g_free (expected_message_prefix);

  g_free (prefix);
}

static void
test_script_fixture_expect_send_message_with_payload_and_data (
    TestScriptFixture * fixture,
    const gchar * func,
    const gchar * file,
    gint line,
    const gchar * payload,
    const gchar * data)
{
  TestScriptMessageItem * item;
  gchar * expected_message;

  item = _test_script_fixture_pop_message (fixture, func, file, line);
  expected_message =
      g_strconcat ("{\"type\":\"send\",\"payload\":", payload, "}", NULL);
  gum_assert_cmpstr (func, file, line, item->message, ==, expected_message);
  if (data != NULL)
  {
    gum_assert_nonnull (func, file, line, item->data);
    gum_assert_cmpstr (func, file, line, item->data, ==, data);
  }
  else
  {
    gum_assert_null (func, file, line, item->data);
  }
  test_script_message_item_free (item);
  g_free (expected_message);
}

static gpointer
test_script_fixture_expect_send_message_with_pointer (
    TestScriptFixture * fixture,
    const gchar * func,
    const gchar * file,
    gint line)
{
  TestScriptMessageItem * item;
  gpointer ptr;

  item = _test_script_fixture_pop_message (fixture, func, file, line);
  ptr = NULL;
  sscanf (item->message, "{\"type\":\"send\",\"payload\":"
      "\"0x%" G_GSIZE_MODIFIER "x\"}", (gsize *) &ptr);
  test_script_message_item_free (item);

  return ptr;
}

static gchar *
test_script_fixture_pop_error_description (TestScriptFixture * fixture,
                                           const gchar * func,
                                           const gchar * file,
                                           gint caller_line,
                                           gint * line_number)
{
  TestScriptMessageItem * item;
  gchar description[1024], stack[1024], file_name[64];
  gint line, column;

  item = _test_script_fixture_pop_message (fixture, func, file, caller_line);

  description[0] = '\0';
  stack[0] = '\0';
  file_name[0] = '\0';
  line = -1;
  column = -1;
  sscanf (item->message, "{"
          "\"type\":\"error\","
          "\"description\":\"%[^\"]\","
          "\"stack\":\"%[^\"]\","
          "\"fileName\":\"%[^\"]\","
          "\"lineNumber\":%d,"
          "\"columnNumber\":%d"
      "}",
      description,
      stack,
      file_name,
      &line,
      &column);
  if (column == -1)
  {
    sscanf (item->message, "{"
            "\"type\":\"error\","
            "\"description\":\"%[^\"]\""
        "}",
        description);
  }

  test_script_message_item_free (item);

  gum_assert_false (func, file, line, description[0] == '\0');

  if (line_number != NULL)
    *line_number = line;

  return g_strdup (description);
}

static void
test_script_fixture_expect_error_message_with (TestScriptFixture * fixture,
                                               const gchar * func,
                                               const gchar * file,
                                               gint line,
                                               gint line_number,
                                               const gchar * description)
{
  gchar * actual_description;
  gint actual_line_number;

  actual_description =
      test_script_fixture_pop_error_description (fixture, func, file, line,
          &actual_line_number);

  if (line_number != ANY_LINE_NUMBER)
    gum_assert_cmpint (func, file, line, actual_line_number, ==, line_number);

  gum_assert_cmpstr (func, file, line, actual_description, ==, description);

  g_free (actual_description);
}

static void
test_script_fixture_expect_error_message_matching (TestScriptFixture * fixture,
                                                   const gchar * func,
                                                   const gchar * file,
                                                   gint line,
                                                   gint line_number,
                                                   const gchar * pattern)
{
  gchar * actual_description;
  gint actual_line_number;

  actual_description =
      test_script_fixture_pop_error_description (fixture, func, file, line,
          &actual_line_number);

  if (line_number != ANY_LINE_NUMBER)
    gum_assert_cmpint (func, file, line, actual_line_number, ==, line_number);

  gum_assert_true (func, file, line,
      g_regex_match_simple (pattern, actual_description, 0, 0));

  g_free (actual_description);
}

static void
test_script_fixture_expect_log_message_with (TestScriptFixture * fixture,
                                             const gchar * func,
                                             const gchar * file,
                                             gint line,
                                             const gchar * level,
                                             const gchar * payload_template,
                                             ...)
{
  va_list args;
  gchar * payload;
  TestScriptMessageItem * item;
  gchar * expected_message;

  va_start (args, payload_template);
  payload = g_strdup_vprintf (payload_template, args);
  va_end (args);

  item = _test_script_fixture_pop_message (fixture, func, file, line);
  expected_message = g_strconcat ("{\"type\":\"log\",\"level\":\"", level,
      "\",\"payload\":\"", payload, "\"}", NULL);
  gum_assert_cmpstr (func, file, line, item->message, ==, expected_message);
  test_script_message_item_free (item);
  g_free (expected_message);

  g_free (payload);
}

static void
test_script_fixture_push_timeout (TestScriptFixture * fixture,
                                  guint timeout)
{
  g_queue_push_tail (&fixture->timeouts, GUINT_TO_POINTER (timeout));
}

static void
test_script_fixture_pop_timeout (TestScriptFixture * fixture)
{
  g_queue_pop_tail (&fixture->timeouts);
}

static const gchar *
test_script_fixture_make_tempfile_containing (TestScriptFixture * fixture,
                                              const gchar * contents)
{
  gchar * path;
  gint fd;
  FILE * file;

  fd = g_file_open_tmp ("gum-tests.XXXXXX", &path, NULL);
  g_assert_cmpint (fd, !=, -1);

#ifdef _MSC_VER
  file = _fdopen (fd, "wb");
#else
  file = fdopen (fd, "wb");
#endif
  g_assert_nonnull (file);

  fputs (contents, file);

  fclose (file);

  g_queue_push_tail (&fixture->tempfiles, path);

  return path;
}

static const gchar *
test_script_fixture_escape_path (TestScriptFixture * fixture,
                                 const gchar * path)
{
#ifdef HAVE_WINDOWS
  gchar * result;
  GString * escaped;

  escaped = g_string_new (path);
  g_string_replace (escaped, "\\", "\\\\", 0);
  result = g_string_free (escaped, FALSE);

  g_queue_push_tail (&fixture->heap_blocks, result);

  return result;
#else
  return path;
#endif
}

"""

```