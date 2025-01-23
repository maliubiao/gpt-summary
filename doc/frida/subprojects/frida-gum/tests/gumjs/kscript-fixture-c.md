Response:
My thinking process to analyze the C code and generate the comprehensive explanation involved several steps:

1. **Understand the Goal:** The request asks for an explanation of the C code's functionality, focusing on its relation to reverse engineering, binary/kernel aspects, logic, common errors, and debugging. Essentially, I need to translate the technical code into a user-understandable description, highlighting its relevance in a dynamic instrumentation context.

2. **Identify Key Structures and Functions:**  I started by scanning the code for prominent data structures and function definitions. Keywords like `struct`, `typedef`, and function declarations (`static void`, `void`, etc.) helped me quickly locate these core elements.

    * `TestScriptFixture`:  This immediately stood out as a central structure holding the state needed for testing. The members (`backend`, `kscript`, `loop`, `context`, `messages`, `timeout`) hinted at the interaction with a scripting engine and an event loop.
    * `TestScriptMessageItem`: This structure suggested a mechanism for handling messages sent or received during script execution.
    * `test_kscript_fixture_setup`, `test_kscript_fixture_teardown`:  These function names strongly suggested setup and cleanup procedures for the test environment.
    * Functions starting with `test_kscript_fixture_`: These appeared to be helper functions for managing the test fixture, such as loading scripts, sending/receiving messages, and asserting expectations.
    * Macros like `TESTCASE`, `TESTENTRY`, `COMPILE_AND_LOAD_SCRIPT`, `POST_MESSAGE`, `EXPECT_SEND_MESSAGE_WITH`, etc.: These are syntactic sugar providing a more concise way to define and execute tests.

3. **Trace the Execution Flow (Conceptual):**  I mentally sketched the lifecycle of a test using this fixture:

    * **Setup:** Initialize the necessary components (`GumScriptBackend`, `GMainLoop`, `GQueue`).
    * **Script Execution:** Compile and load a JavaScript (`kscript`) using `gum_script_backend_create_sync` and `gum_script_load_sync`.
    * **Message Handling:**  Set up a message handler (`test_kscript_fixture_store_message`) to intercept messages from the script.
    * **Interaction and Assertion:** Send messages to the script (if needed), and then check for expected messages or errors using the `EXPECT_*` macros. This likely involves waiting for the event loop to process events.
    * **Teardown:** Unload the script, clean up resources.

4. **Analyze Functionality Based on Structure and Flow:** With the overall structure in mind, I went back to analyze the purpose of individual functions and data members.

    * `GumScriptBackend`, `GumScript`:  These clearly relate to Frida's core functionality of managing and executing scripts within a target process.
    * `GMainLoop`, `GMainContext`: These are GLib components for handling asynchronous events, essential for Frida's non-blocking operation.
    * `GQueue messages`: This confirms the message queue mechanism for inter-process communication or communication between Frida's engine and the test environment.
    * The `EXPECT_*` functions are assertion helpers, confirming that the script's behavior matches expectations. They decode the JSON-formatted messages and compare them to expected values.

5. **Connect to Reverse Engineering Concepts:** This is where I mapped the code's functionality to practical reverse engineering scenarios:

    * **Dynamic Instrumentation:** The core purpose of the code is to *test* Frida's ability to execute JavaScript code within a target process. This is the essence of dynamic instrumentation.
    * **Hooking and Interception:** The message passing mechanism mirrors how Frida intercepts function calls, reads/writes memory, and communicates with the user. The `EXPECT_SEND_MESSAGE_WITH` family of functions simulates verifying the results of a hook.
    * **Scripting for Automation:** The ability to load and execute scripts enables automation of reverse engineering tasks.

6. **Identify Binary/Kernel/Framework Connections:**  I looked for indicators of interaction with the underlying system:

    * The inclusion of `gumscriptbackend.h` suggests interaction with Frida's internal scripting engine, which itself interacts with the target process's memory and execution.
    * The mention of Linux and Android kernels in the explanation is based on Frida's typical use cases. While not explicitly present in *this specific file*, the broader Frida project heavily interacts with these kernels. The concepts of process memory, system calls, and libraries are fundamental.

7. **Infer Logic and Examples:**  The `EXPECT_*` macros provide clear examples of logical assertions. I created hypothetical scenarios to illustrate the input and output of these assertions, showcasing how the test fixture validates the script's behavior.

8. **Consider Common Errors:** I thought about typical mistakes users might make when writing Frida scripts or using its API, and how this test fixture might help detect those errors:

    * Incorrect message format.
    * Errors in the JavaScript code itself (syntax, logic).
    * Timing issues (expecting a message too early or late).

9. **Trace User Actions to the Code:**  I described the steps a user would take to arrive at the execution of this code: writing a Frida script, running tests, and potentially debugging.

10. **Structure and Refine:** Finally, I organized the information into a clear and logical structure, using headings and bullet points to enhance readability. I reviewed and refined the language to ensure it was accurate and accessible. I paid attention to the specific keywords and concepts from the request (e.g., "逆向的方法", "二进制底层").

By following these steps, I was able to decompose the C code, understand its purpose within the larger Frida ecosystem, and explain its relevance to reverse engineering, system-level interactions, and user workflows. The key was to connect the technical details of the code to the higher-level concepts and practical applications of Frida.
这是文件 `frida/subprojects/frida-gum/tests/gumjs/kscript-fixture.c` 的源代码，它是一个用于测试 Frida 的 GumJS 组件中 KScript 功能的测试脚手架 (test fixture)。 它的主要目的是提供一个方便的环境来编写和执行针对 KScript 的单元测试。

下面详细列举它的功能，并根据你的要求进行说明：

**主要功能:**

1. **创建和管理 GumScript 实例:**
   - `test_kscript_fixture_setup`:  初始化测试环境，包括获取 `GumScriptBackend` 实例，创建 GLib 的 `GMainLoop` 和 `GMainContext` 用于处理异步事件，以及创建一个消息队列 `messages`。
   - `test_kscript_fixture_teardown`: 清理测试环境，卸载并释放 `GumScript` 实例，释放消息队列和 GLib 相关资源。
   - `test_kscript_fixture_compile_and_load_kscript`:  根据提供的 JavaScript 源代码（`source_template`）编译并加载 KScript。它负责创建 `GumScript` 对象，设置消息处理函数，并最终加载脚本。如果之前有加载的脚本，会先卸载。

2. **模拟和断言消息传递:**
   - `test_kscript_fixture_store_message`:  当加载的 KScript 通过 `send()` 函数发送消息时，此函数会被调用。它将消息内容和可选的数据（二进制数据会转换成十六进制字符串）存储到 `messages` 队列中。
   - `test_kscript_fixture_try_pop_message`: 尝试从消息队列中取出一个消息。如果队列为空，它会启动一个定时器，等待消息到达或超时。
   - `test_kscript_fixture_pop_message`: 从消息队列中取出一个消息，如果队列为空则会断言失败。
   - `test_kscript_fixture_expect_send_message_with`:  断言接收到的消息是一个 "send" 类型的消息，并且其 payload 与提供的模板匹配。
   - `test_kscript_fixture_expect_send_message_with_payload_and_data`: 断言接收到的消息是一个 "send" 类型的消息，并且其 payload 和 data 分别与提供的参数匹配。
   - `test_kscript_fixture_expect_error_message_with`: 断言接收到的消息是一个 "error" 类型的消息，并且其行号和描述与提供的参数匹配。

3. **辅助宏定义:**
   - `TESTCASE(NAME)`: 定义一个测试用例函数。
   - `TESTENTRY(NAME)`: 将测试用例注册到测试框架中。
   - `COMPILE_AND_LOAD_SCRIPT(SOURCE, ...)`: 简化编译和加载 KScript 的操作。
   - `POST_MESSAGE(MSG)`:  允许测试代码向 KScript 发送消息 (虽然在这个文件中没有直接使用，但通常 Frida 的测试用例会用到)。
   - `EXPECT_NO_MESSAGES()`: 断言在一定时间内没有收到任何消息。
   - `EXPECT_SEND_MESSAGE_WITH(...)`, `EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA(...)`, `EXPECT_ERROR_MESSAGE_WITH(...)`:  简化断言消息的操作。
   - `GUM_PTR_CONST`:  定义一个用于格式化指针地址的字符串常量。

**与逆向方法的关系及举例说明:**

这个文件本身不是直接进行逆向操作的代码，而是 **测试** Frida 动态插桩功能的代码。逆向工程师使用 Frida 来分析目标进程的行为，例如：

- **Hook 函数:**  拦截目标进程中特定函数的调用，查看参数、返回值等。
- **修改内存:**  在运行时修改目标进程的内存数据或代码。
- **跟踪执行流程:**  观察目标进程的执行路径。

`kscript-fixture.c` 通过加载包含 JavaScript 代码的 KScript，并断言脚本的行为是否符合预期，来测试 Frida 的这些核心能力。

**举例说明:**

假设我们要测试 Frida 能否成功 hook 一个函数并发送消息：

1. **测试用例 JavaScript 代码 (在其他文件中定义，由 fixture 加载):**
   ```javascript
   rpc.exports = {
     test_hook: function() {
       Interceptor.attach(Module.findExportByName(null, 'puts'), {
         onEnter: function(args) {
           send({ type: 'log', message: 'puts called with: ' + args[0].readUtf8String() });
         }
       });
     }
   };
   ```

2. **C 代码测试用例 (使用 fixture):**
   ```c
   TESTCASE (basic_hook)
   {
     COMPILE_AND_LOAD_SCRIPT (
       "rpc.exports = {\n"
       "  test_hook: function() {\n"
       "    Interceptor.attach(Module.findExportByName(null, 'puts'), {\n"
       "      onEnter: function(args) {\n"
       "        send({ type: 'log', message: 'puts called with: ' + args[0].readUtf8String() });\n"
       "      }\n"
       "    });\n"
       "  }\n"
       "};"
     );

     // 调用 JavaScript 中暴露的 test_hook 函数
     gum_script_call_function_sync (fixture->kscript, "test_hook", NULL, NULL);

     // 假设目标进程调用了 puts 函数，我们期望收到一个包含特定消息的 send
     EXPECT_SEND_MESSAGE_WITH ("{\"type\":\"log\",\"message\":\"puts called with: %s\"}", "some string");
   }
   TESTENTRY (basic_hook);
   ```

在这个例子中，`kscript-fixture.c` 提供的功能允许我们加载包含 hook `puts` 函数的 JavaScript 代码，执行 JavaScript 函数，并断言是否收到了预期的消息。这验证了 Frida 的 hook 功能是否正常工作。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

`kscript-fixture.c` 本身并没有直接操作二进制底层或内核，但它测试的代码（通过 `COMPILE_AND_LOAD_SCRIPT` 加载的 JavaScript 代码）会涉及到这些方面。

- **二进制底层:**
    - `Module.findExportByName(null, 'puts')`:  这个 JavaScript API 调用需要理解动态链接和符号导出的概念，即在二进制文件中查找特定函数的地址。
    - `Interceptor.attach(...)`:  Frida 的 `Interceptor` API 涉及到在目标进程的指令流中插入代码，这需要对目标架构的指令集和内存布局有深入的了解。
    - `args[0].readUtf8String()`:  读取目标进程内存中的字符串，需要理解内存地址和数据类型的概念。

- **Linux/Android 内核及框架:**
    - `puts`:  这是一个标准的 C 库函数，在 Linux 和 Android 上都有实现。Frida 能够 hook 这个函数，意味着它能够与操作系统提供的动态链接器和进程管理机制进行交互。
    - Android 框架中的 API Hook：Frida 也可以用于 hook Android 应用程序框架中的 Java 或 Native 函数，这需要理解 Android 的运行时环境 (ART/Dalvik) 和 Binder IPC 机制。

**举例说明:**

如果测试的 JavaScript 代码尝试 hook 一个特定的系统调用，例如 `open()`，那么测试脚手架实际上间接地验证了 Frida 与 Linux 内核的交互能力。测试代码可能会断言在调用 `open()` 时，Frida 能否成功拦截并获取到文件名等参数。

**逻辑推理及假设输入与输出:**

`kscript-fixture.c` 中主要的逻辑推理发生在各种 `EXPECT_*` 函数中。

**假设输入:**

- 加载的 KScript 代码发送了一条消息：`{"type":"send", "payload":"hello"}`

**EXPECT_SEND_MESSAGE_WITH 的输出:**

- 如果我们调用 `EXPECT_SEND_MESSAGE_WITH ("{\"type\":\"send\", \"payload\":\"%s\"}", "hello");`，则断言成功，因为实际收到的消息与期望的模式匹配。
- 如果我们调用 `EXPECT_SEND_MESSAGE_WITH ("{\"type\":\"send\", \"payload\":\"%s\"}", "world");`，则断言失败，因为实际收到的 payload 是 "hello"，而不是 "world"。

**EXPECT_ERROR_MESSAGE_WITH 的输出:**

- 如果 KScript 代码抛出一个错误，并且 Frida 捕获到了错误信息（包括文件名、行号、列号和描述），`EXPECT_ERROR_MESSAGE_WITH` 可以用来验证这些信息是否正确。
- 例如，如果 KScript 中第 5 行有一个语法错误，`EXPECT_ERROR_MESSAGE_WITH (5, "SyntaxError: Unexpected token ...");` 会断言接收到的错误消息的行号和描述是否与预期一致。

**涉及用户或编程常见的使用错误及举例说明:**

虽然 `kscript-fixture.c` 本身是测试代码，但它测试的功能是用户经常使用的。以下是一些可能的用户错误，可以通过类似的测试用例来发现：

1. **错误的 `send()` 消息格式:** 用户可能在 JavaScript 中使用 `send()` 发送的消息格式不正确，例如缺少 `type` 字段或 payload 不是 JSON 对象。测试用例会断言接收到的消息是否符合预期格式。
   ```c
   // 用户 JavaScript 代码可能错误地写成: send("hello");
   // 测试用例可以断言这种情况会产生错误或被忽略
   EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "TypeError: ..."); // 假设 Frida 会抛出类型错误
   ```

2. **Hook 不存在的函数:** 用户可能尝试 hook 一个在目标进程中不存在的函数。测试用例可以验证在这种情况下 Frida 是否会抛出错误或采取适当的处理措施。
   ```c
   // 用户 JavaScript 代码: Interceptor.attach(Module.findExportByName(null, 'nonExistentFunction'), ...);
   // 测试用例可以断言会收到特定的错误消息
   EXPECT_ERROR_MESSAGE_WITH (ANY_LINE_NUMBER, "Error: unable to find export with name 'nonExistentFunction'");
   ```

3. **异步消息处理错误:** 用户可能假设消息会立即到达，但在异步环境中，消息的接收需要等待事件循环。测试用例通过设置超时时间来模拟这种情况，并确保在没有消息到达时不会无限期等待。

**说明用户操作是如何一步步到达这里，作为调试线索:**

1. **编写 Frida JavaScript 脚本:** 用户首先编写一个 Frida JavaScript 脚本，该脚本使用 Frida 的 API（例如 `Interceptor`, `Module`, `send`）来执行动态插桩操作。

2. **编写测试用例:** 为了验证脚本的正确性，开发者会编写 C 代码的测试用例，使用 `kscript-fixture.c` 提供的功能。

3. **使用测试框架:**  开发者会使用像 `gtester` 这样的测试框架来运行这些测试用例。`TESTENTRY` 宏会将测试用例注册到测试框架中。

4. **`test_kscript_fixture_setup` 执行:** 当运行包含 `TESTENTRY (your_test_name);` 的测试用例时，首先会执行 `test_kscript_fixture_setup` 函数，初始化测试环境。

5. **`COMPILE_AND_LOAD_SCRIPT` 执行:**  测试用例通常会调用 `COMPILE_AND_LOAD_SCRIPT` 宏，传入要测试的 JavaScript 代码。这个宏会调用 `test_kscript_fixture_compile_and_load_kscript` 函数，编译并加载脚本到 Frida 的 GumJS 引擎中。

6. **JavaScript 代码执行:** 加载的 JavaScript 代码会在 Frida 的环境中执行。如果脚本使用了 `send()` 函数发送消息，`test_kscript_fixture_store_message` 函数会被调用，将消息存储到队列中。

7. **`EXPECT_*` 函数执行:** 测试用例会使用 `EXPECT_SEND_MESSAGE_WITH` 或其他 `EXPECT_*` 宏来断言脚本的行为。这些宏会调用相应的 `test_kscript_fixture_expect_*` 函数，从消息队列中取出消息并进行比较。

8. **`test_kscript_fixture_teardown` 执行:** 测试用例执行完毕后，`test_kscript_fixture_teardown` 函数会被调用，清理测试环境。

**作为调试线索:**

如果测试用例失败，`kscript-fixture.c` 中的代码可以提供调试线索：

- **断言失败信息:**  `g_assert_cmpstr` 和 `g_assert_cmpint` 等断言宏会提供详细的失败信息，例如期望的消息内容是什么，实际收到的消息内容是什么，这有助于定位问题是出在 JavaScript 脚本还是测试用例的断言逻辑上。
- **消息队列检查:**  可以通过查看消息队列中的内容来了解脚本发送了哪些消息，以及消息的顺序。
- **日志输出:**  虽然此文件没有直接的日志输出，但 Frida 内部的日志系统可以提供更底层的执行信息。

总而言之，`kscript-fixture.c` 是一个关键的测试基础设施，它允许 Frida 的开发者验证 GumJS 和 KScript 功能的正确性，并帮助用户理解和调试他们自己的 Frida 脚本。它通过提供加载脚本、模拟消息传递和进行断言的功能，有效地将动态插桩的测试过程自动化和结构化。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/gumjs/kscript-fixture.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptbackend.h"

#include "testutil.h"

#include <stdio.h>

#define ANY_LINE_NUMBER -1
#define KSCRIPT_MESSAGE_DEFAULT_TIMEOUT_MSEC 500

#ifndef KSCRIPT_SUITE
# define KSCRIPT_SUITE ""
#endif
#define TESTCASE(NAME) \
    void test_kscript_ ## NAME (TestScriptFixture * fixture, gconstpointer data)
#define TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("GumJS/KScript" KSCRIPT_SUITE, test_kscript, \
        NAME, TestScriptFixture)

#define COMPILE_AND_LOAD_SCRIPT(SOURCE, ...) \
    test_kscript_fixture_compile_and_load_kscript (fixture, SOURCE, \
    ## __VA_ARGS__)
#define POST_MESSAGE(MSG) \
    gum_script_post_message (fixture->kscript, MSG)
#define EXPECT_NO_MESSAGES() \
    g_assert_null (test_kscript_fixture_try_pop_message (fixture, 1))
#define EXPECT_SEND_MESSAGE_WITH(PAYLOAD, ...) \
    test_kscript_fixture_expect_send_message_with (fixture, PAYLOAD, \
    ## __VA_ARGS__)
#define EXPECT_SEND_MESSAGE_WITH_PAYLOAD_AND_DATA(PAYLOAD, DATA) \
    test_kscript_fixture_expect_send_message_with_payload_and_data (fixture, \
        PAYLOAD, DATA)
#define EXPECT_ERROR_MESSAGE_WITH(LINE_NUMBER, DESC) \
    test_kscript_fixture_expect_error_message_with (fixture, LINE_NUMBER, DESC)

#define GUM_PTR_CONST "ptr(\"0x%" G_GSIZE_MODIFIER "x\")"

typedef struct _TestScriptFixture
{
  GumScriptBackend * backend;
  GumScript * kscript;
  GMainLoop * loop;
  GMainContext * context;
  GQueue * messages;
  guint timeout;
} TestScriptFixture;

typedef struct _TestScriptMessageItem
{
  gchar * message;
  gchar * data;
} TestScriptMessageItem;

static void test_kscript_message_item_free (TestScriptMessageItem * item);
static TestScriptMessageItem * test_kscript_fixture_try_pop_message (
    TestScriptFixture * fixture, guint timeout);
static gboolean test_kscript_fixture_stop_loop (TestScriptFixture * fixture);
static void test_kscript_fixture_expect_send_message_with_payload_and_data (
    TestScriptFixture * fixture, const gchar * payload, const gchar * data);
static void test_kscript_fixture_expect_error_message_with (
    TestScriptFixture * fixture, gint line_number, const gchar * description);

static void
test_kscript_fixture_setup (TestScriptFixture * fixture,
                            gconstpointer data)
{
  (void) test_kscript_fixture_expect_send_message_with_payload_and_data;
  (void) test_kscript_fixture_expect_error_message_with;

  fixture->backend = gum_script_backend_obtain ();
  fixture->context = g_main_context_ref_thread_default ();
  fixture->loop = g_main_loop_new (fixture->context, FALSE);
  fixture->messages = g_queue_new ();
  fixture->timeout = KSCRIPT_MESSAGE_DEFAULT_TIMEOUT_MSEC;
}

static void
test_kscript_fixture_teardown (TestScriptFixture * fixture,
                               gconstpointer data)
{
  TestScriptMessageItem * item;

  if (fixture->kscript != NULL)
  {
    gum_script_unload_sync (fixture->kscript, NULL);
    g_object_unref (fixture->kscript);
  }

  while (g_main_context_pending (fixture->context))
    g_main_context_iteration (fixture->context, FALSE);

  while ((item = test_kscript_fixture_try_pop_message (fixture, 1)) != NULL)
  {
    test_kscript_message_item_free (item);
  }
  g_queue_free (fixture->messages);

  g_main_loop_unref (fixture->loop);
  g_main_context_unref (fixture->context);
}

static void
test_kscript_message_item_free (TestScriptMessageItem * item)
{
  g_free (item->message);
  g_free (item->data);
  g_slice_free (TestScriptMessageItem, item);
}

static void
test_kscript_fixture_store_message (const gchar * message,
                                    GBytes * data,
                                    gpointer user_data)
{
  TestScriptFixture * self = (TestScriptFixture *) user_data;
  TestScriptMessageItem * item;

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
  }
  else
  {
    item->data = NULL;
  }

  g_queue_push_tail (self->messages, item);
  g_main_loop_quit (self->loop);
}

static void
test_kscript_fixture_compile_and_load_kscript (TestScriptFixture * fixture,
                                               const gchar * source_template,
                                               ...)
{
  va_list args;
  gchar * source;
  GError * err = NULL;

  if (fixture->kscript != NULL)
  {
    gum_script_unload_sync (fixture->kscript, NULL);
    g_object_unref (fixture->kscript);
    fixture->kscript = NULL;
  }

  va_start (args, source_template);
  source = g_strdup_vprintf (source_template, args);
  va_end (args);

  fixture->kscript = gum_script_backend_create_sync (fixture->backend,
      "testcase", source, NULL, NULL, &err);
  g_assert_nonnull (fixture->kscript);
  g_assert_null (err);

  g_free (source);

  gum_script_set_message_handler (fixture->kscript,
      test_kscript_fixture_store_message, fixture, NULL);

  gum_script_load_sync (fixture->kscript, NULL);
}

static TestScriptMessageItem *
test_kscript_fixture_try_pop_message (TestScriptFixture * fixture,
                                      guint timeout)
{
  if (g_queue_is_empty (fixture->messages))
  {
    GSource * source;

    source = g_timeout_source_new (timeout);
    g_source_set_callback (source, (GSourceFunc) test_kscript_fixture_stop_loop,
        fixture, NULL);
    g_source_attach (source, fixture->context);

    g_main_loop_run (fixture->loop);

    g_source_destroy (source);
    g_source_unref (source);
  }

  return g_queue_pop_head (fixture->messages);
}

static gboolean
test_kscript_fixture_stop_loop (TestScriptFixture * fixture)
{
  g_main_loop_quit (fixture->loop);

  return FALSE;
}

static TestScriptMessageItem *
test_kscript_fixture_pop_message (TestScriptFixture * fixture)
{
  TestScriptMessageItem * item;

  item = test_kscript_fixture_try_pop_message (fixture, fixture->timeout);
  g_assert_nonnull (item);

  return item;
}

static void
test_kscript_fixture_expect_send_message_with (TestScriptFixture * fixture,
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

  item = test_kscript_fixture_pop_message (fixture);
  expected_message =
      g_strconcat ("{\"type\":\"send\",\"payload\":", payload, "}", NULL);
  g_assert_cmpstr (item->message, ==, expected_message);
  test_kscript_message_item_free (item);
  g_free (expected_message);

  g_free (payload);
}

static void
test_kscript_fixture_expect_send_message_with_payload_and_data (
    TestScriptFixture * fixture,
    const gchar * payload,
    const gchar * data)
{
  TestScriptMessageItem * item;
  gchar * expected_message;

  item = test_kscript_fixture_pop_message (fixture);
  expected_message =
      g_strconcat ("{\"type\":\"send\",\"payload\":", payload, "}", NULL);
  g_assert_cmpstr (item->message, ==, expected_message);
  if (data != NULL)
  {
    g_assert_nonnull (item->data);
    g_assert_cmpstr (item->data, ==, data);
  }
  else
  {
    g_assert_null (item->data);
  }
  test_kscript_message_item_free (item);
  g_free (expected_message);
}

static void
test_kscript_fixture_expect_error_message_with (TestScriptFixture * fixture,
                                                gint line_number,
                                                const gchar * description)
{
  TestScriptMessageItem * item;
  gchar actual_description[256];
  gchar actual_stack[512];
  gchar actual_file_name[64];
  gint actual_line_number;
  gint actual_column_number;

  item = test_kscript_fixture_pop_message (fixture);
  sscanf (item->message, "{"
          "\"type\":\"error\","
          "\"description\":\"%[^\"]\","
          "\"stack\":\"%[^\"]\","
          "\"fileName\":\"%[^\"]\","
          "\"lineNumber\":%d,"
          "\"columnNumber\":%d"
      "}",
      actual_description,
      actual_stack,
      actual_file_name,
      &actual_line_number,
      &actual_column_number);
  if (line_number != ANY_LINE_NUMBER)
    g_assert_cmpint (actual_line_number, ==, line_number);
  g_assert_cmpstr (actual_description, ==, description);
  test_kscript_message_item_free (item);
}
```