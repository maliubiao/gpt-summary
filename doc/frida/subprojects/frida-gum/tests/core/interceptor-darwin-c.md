Response:
Let's break down the thought process for analyzing this C code and answering the prompt.

**1. Initial Skim and Understanding the Context:**

The first step is to quickly read through the code to get a general idea of what it's doing. Keywords like `TESTCASE`, `TESTLIST`, `gum_interceptor`, and function names like `can_attach_to_*` immediately suggest this is a testing file for a dynamic instrumentation library (Frida, based on the file path). The inclusion of Darwin-specific headers (`gumdarwin.h`, `<spawn.h>`, `<sys/socket.h>`) tells us it's focused on macOS/iOS.

**2. Identifying Core Functionality:**

The next step is to pinpoint the main actions being performed in the tests. The recurring pattern is:

* **Find a symbol (function) in a shared library:** `gum_module_find_export_by_name`.
* **Attach an interceptor:** `interceptor_fixture_attach`, `gum_interceptor_attach`. This is the core Frida functionality being tested.
* **Execute the original function.**
* **Assert expected behavior:** `g_assert_cmp*`.
* **Optionally, detach the interceptor:** `interceptor_fixture_detach`.

Some tests also involve replacing functions: `gum_interceptor_replace`. Performance testing is also evident with `attach_performance` and `replace_performance`.

**3. Categorizing Functionality based on the Prompt:**

Now, let's address the specific questions in the prompt systematically:

* **的功能 (Functionality):** List the actions observed. This translates to summarizing what each `TESTCASE` does. Focus on the *what*, not necessarily the *how* at this stage.

* **与逆向的方法的关系 (Relationship with Reverse Engineering):**  Consider *why* this code is being written. Dynamic instrumentation is a core technique in reverse engineering. Think about how the tests demonstrate the ability to intercept and potentially modify function behavior, which is crucial for analyzing closed-source software. Relate the specific tested functions (e.g., `strcmp`, `read`, `accept`) to common reverse engineering tasks like understanding string comparisons, file I/O, and network interactions.

* **涉及二进制底层，linux, android内核及框架的知识 (Involvement of Binary Low-Level, Linux, Android Kernel/Framework):**  While this specific file is Darwin-focused,  recognize that dynamic instrumentation in general deals with binary code. Note the mention of `cpu_type_t`, `mach_port_t`, and XPC, which are macOS-specific. Acknowledge the general principles of hooking shared library functions and how they relate to OS internals, even if the direct examples are macOS-centric. The Cydia Substrate test points to iOS environment specifics.

* **做了逻辑推理，请给出假设输入与输出 (Logical Reasoning with Input/Output):**  For each test case, consider the input to the intercepted function and the expected output *after* the interception. For example, in the `can_attach_to_strcmp` test, the input is two strings, and the expected (unmodified) output is the comparison result. The interceptor's side effect (appending ">" and "<" to a string) is also a form of output. The `can_attach_to_read` example is more complex, involving a thread and a pipe, so focus on the data being read and the assertion.

* **涉及用户或者编程常见的使用错误 (Common User/Programming Errors):** Think about potential pitfalls when using an instrumentation library. Consider issues like:
    * Incorrectly specifying the target function name.
    * Type mismatches between the original function and the interceptor/replacement. The test code even mentions "wrong signature."
    * Trying to attach to the same function multiple times.
    * Resource leaks if attachments aren't properly managed.
    * Race conditions in multithreaded scenarios (though less directly demonstrated here, it's a general concern).

* **说明用户操作是如何一步步的到达这里，作为调试线索 (User Steps to Reach Here as a Debugging Clue):**  Imagine a developer using Frida. How would they arrive at needing to debug this specific part of the Frida codebase?  This points to scenarios like:
    * Encountering issues attaching to functions on macOS/iOS.
    * Performance problems with attaching or replacing functions.
    * Suspecting issues with code signing on iOS after using Frida.
    * General debugging of Frida's core interceptor functionality.

**4. Structuring the Answer:**

Organize the findings logically, mirroring the prompt's structure. Use clear headings and bullet points for readability. Provide specific examples from the code to support each point.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** "This is just a bunch of tests."
* **Correction:** "No, these tests demonstrate specific capabilities of Frida's interceptor on Darwin. I need to analyze *what* each test is demonstrating."

* **Initial thought:** "The performance tests are just measuring speed."
* **Correction:** "While speed is the metric, these tests also highlight how Frida handles attaching/replacing a large number of functions, which is relevant to real-world use cases."

* **Initial thought:**  "The Cydia Substrate test is just about another hooking framework."
* **Correction:**  "It's about ensuring Frida's actions don't break code signing on iOS, a critical security feature. This has implications for reverse engineering on locked-down devices."

By following this thought process, systematically analyzing the code, and relating it back to the prompt's questions, we can generate a comprehensive and insightful answer.
这个C源代码文件 `interceptor-darwin.c` 是 Frida 动态 instrumentation 工具中，专门针对 Darwin (macOS 和 iOS) 平台的 Interceptor 组件的测试用例。它的主要功能是测试 Frida 的 Interceptor API 在 Darwin 平台上的各种能力，包括：

**核心功能：**

1. **函数拦截 (Attaching):**
   - **功能:** 测试 Frida 能否成功拦截指定模块（共享库）中的函数。
   - **代码示例:** `interceptor_fixture_attach (fixture, 0, error_impl, '>', '<');`  这行代码尝试拦截 `libSystem.B.dylib` 中的 `__error` 函数。
   - **逆向关系:** 这是动态逆向的核心技术之一。通过拦截函数，可以在函数执行前后观察其参数、返回值以及执行上下文，从而理解函数的行为。例如，拦截 `strcmp` 可以了解程序在进行哪些字符串比较，拦截 `read` 可以监控程序的 I/O 操作。
   - **二进制底层/内核知识:** 拦截需要在二进制层面修改目标进程的指令流，将执行流程重定向到 Frida 提供的回调函数。这涉及到对目标进程内存布局、指令集架构以及操作系统提供的动态链接机制的理解。在 Darwin 上，这涉及到 Mach-O 文件格式和 dyld 的工作原理。
   - **逻辑推理 (假设输入与输出):**
     - **假设输入:** 目标进程调用被拦截的函数，例如 `strcmp("hello", "world")`。
     - **预期输出:** Frida 的回调函数会被执行，可能会记录参数 "hello" 和 "world"，然后原始的 `strcmp` 会被执行并返回结果（-1），测试用例会断言返回值是否正确。
   - **用户常见错误:**
     - **错误的函数名或模块名:**  如果用户提供的函数名或模块名不存在，`gum_module_find_export_by_name` 将返回 NULL，导致后续拦截失败。
     - **权限问题:**  如果 Frida 运行的用户没有足够的权限访问目标进程或加载目标模块，拦截可能会失败。

2. **函数替换 (Replacing):**
   - **功能:** 测试 Frida 能否将目标函数替换为自定义的函数。
   - **代码示例:** 虽然在这个文件中没有直接展示 `gum_interceptor_replace` 的使用，但 `replace_performance` 测试用例中使用了 `gum_interceptor_replace` 来替换 `libsqlite3.dylib` 中的多个函数。
   - **逆向关系:** 函数替换允许修改程序的行为。例如，可以替换一个返回错误的函数，使其始终返回成功，或者修改一个校验函数来绕过验证。
   - **二进制底层/内核知识:** 函数替换需要在二进制层面修改目标函数的入口地址，使其跳转到 Frida 提供的替换函数。这需要更深入地理解目标进程的内存管理和代码执行流程。
   - **用户常见错误:**
     - **替换函数签名不匹配:**  如果替换函数的参数和返回值类型与原始函数不一致，可能会导致程序崩溃或行为异常。
     - **替换函数实现错误:**  替换函数中的错误逻辑可能导致目标进程出现不可预测的行为。

3. **性能测试:**
   - **功能:**  测试 Frida 在 Darwin 平台上进行大量函数拦截和替换时的性能表现。
   - **代码示例:** `attach_performance` 和 `replace_performance` 测试用例分别测试了拦截和替换 `libsqlite3.dylib` 中大量导出函数的耗时。
   - **逆向关系:** 对于大型程序，需要拦截或替换大量函数时，性能至关重要。如果拦截过程过于缓慢，可能会影响目标程序的正常运行，甚至被检测到。
   - **用户常见错误:**  在高频调用的函数上进行过于复杂的拦截逻辑，可能会显著降低程序性能。

4. **特定 Darwin API 的拦截:**
   - **功能:**  测试 Frida 对特定 Darwin 系统 API 的拦截能力，例如 `posix_spawnattr_setbinpref_np` (进程创建属性设置), `pid_for_task` (获取 task 对应的 PID), `mach_host_self` (获取主机端口), `xpc_retain` (XPC 对象引用计数), `sqlite3_close` (SQLite 数据库关闭) 等。
   - **二进制底层/内核知识:** 这些测试涉及到对 Darwin 操作系统的进程管理、Mach IPC 机制、XPC 服务通信以及特定库（如 SQLite）的理解。
   - **逆向关系:** 拦截这些 API 可以深入了解程序的底层行为，例如程序如何创建子进程、如何进行进程间通信、如何使用系统服务等。

5. **代码签名状态保持 (iOS 特有):**
   - **功能:** (在定义了 `HAVE_IOS` 的情况下) 测试 Frida 在 iOS 上拦截函数后，是否会影响目标进程的代码签名状态。
   - **二进制底层/内核知识:** iOS 具有严格的代码签名机制。动态修改代码可能会导致签名失效，从而被操作系统阻止。这个测试验证了 Frida 在进行拦截操作时，能够尽量保持代码签名的有效性。
   - **逆向关系:**  在 iOS 逆向中，保持代码签名状态对于某些操作至关重要，例如在非越狱设备上进行分析。

**调试线索和用户操作:**

用户通常通过 Frida 的客户端 API (例如 Python 或 JavaScript) 来操作目标进程，并最终触发这些测试用例中涉及的底层 Frida 功能。以下是一个可能的调试场景：

1. **用户编写 Frida 脚本:** 用户使用 Frida 的 JavaScript API 编写脚本，尝试拦截目标 App 中的某个函数，例如 `strcmp`。
   ```javascript
   Interceptor.attach(Module.findExportByName("libSystem.B.dylib", "strcmp"), {
     onEnter: function(args) {
       console.log("strcmp called with:", args[0].readUtf8String(), args[1].readUtf8String());
     },
     onLeave: function(retval) {
       console.log("strcmp returned:", retval);
     }
   });
   ```

2. **Frida Client 发送请求:** Frida 客户端将这个脚本发送到 Frida Server，Frida Server 运行在目标设备上。

3. **Frida Server 执行脚本:** Frida Server 解析脚本，并调用 Frida Gum 库的相应 API，例如 `gum_interceptor_attach`。

4. **触发测试用例的场景:** 如果用户在使用 Frida 进行函数拦截时遇到问题，例如拦截失败、程序崩溃、性能下降等，开发者可能会尝试运行 Frida 的测试用例来验证 Frida 自身的功能是否正常。  `interceptor-darwin.c` 中的测试用例就是用来验证 Frida 在 Darwin 平台上的拦截功能的。

5. **调试线索:** 如果特定的测试用例失败，例如 `can_attach_to_strcmp` 失败，则表明 Frida 在拦截 `strcmp` 函数时存在问题。这可以帮助开发者定位问题是在 Frida 的哪个环节出错，例如：
   - `gum_module_find_export_by_name` 是否正确找到了 `strcmp` 的地址？
   - `gum_interceptor_attach` 是否成功修改了目标进程的指令？
   - Frida 的回调函数是否被正确调用？

**总结:**

`interceptor-darwin.c` 文件是 Frida 工具针对 Darwin 平台 Interceptor 组件的功能和性能的系统性测试。它涵盖了函数拦截、替换、特定 API 的处理以及性能评估等方面，为 Frida 在 macOS 和 iOS 上的稳定性和可靠性提供了保障。这些测试用例也反映了 Frida 作为动态逆向工具的核心能力和所涉及的底层技术。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/interceptor-darwin.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2015-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "interceptor-darwin-fixture.c"

#include "gum/gumdarwin.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <spawn.h>
#include <sys/socket.h>
#include <unistd.h>

TESTLIST_BEGIN (interceptor_darwin)
  TESTENTRY (can_attach_to_errno)
  TESTENTRY (can_attach_to_strcmp)
  TESTENTRY (can_attach_to_strrchr)
  TESTENTRY (can_attach_to_read)
  TESTENTRY (can_attach_to_accept)
  TESTENTRY (can_attach_to_posix_spawnattr_setbinpref_np)
  TESTENTRY (can_attach_to_pid_for_task)
  TESTENTRY (can_attach_to_mach_host_self)
  TESTENTRY (can_attach_to_xpc_retain)
  TESTENTRY (can_attach_to_sqlite3_close)
  TESTENTRY (can_attach_to_sqlite3_thread_cleanup)

  TESTENTRY (attach_performance)
  TESTENTRY (replace_performance)

#ifdef HAVE_IOS
  TESTENTRY (should_retain_code_signing_status)
  TESTENTRY (cydia_substrate_replace_performance)
#endif
TESTLIST_END ()

typedef struct _TestPerformanceContext TestPerformanceContext;

struct _TestPerformanceContext
{
  GumInterceptor * interceptor;
  GumInvocationListener * listener;

  void (* MSHookFunction) (void * symbol, void * replace, void ** result);

  guint count;
};

static gpointer perform_read (gpointer data);

static gboolean attach_if_function_export (const GumExportDetails * details,
    gpointer user_data);
static gboolean replace_if_function_export (const GumExportDetails * details,
    gpointer user_data);

static void dummy_replacement_never_called (void);

TESTCASE (can_attach_to_errno)
{
  int * (* error_impl) (void);
  int ret;

  error_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "__error"));

  interceptor_fixture_attach (fixture, 0, error_impl, '>', '<');

  errno = ECONNREFUSED;
  ret = *(error_impl ());
  g_assert_cmpint (ret, ==, ECONNREFUSED);
  g_assert_cmpstr (fixture->result->str, ==, "><><");
}

TESTCASE (can_attach_to_strcmp)
{
  int (* strcmp_impl) (const char * s1, const char * s2);

  strcmp_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "strcmp"));

  interceptor_fixture_attach (fixture, 0, strcmp_impl, '>', '<');

  g_assert_cmpint (strcmp_impl ("badger", "badger"), ==, 0);
}

TESTCASE (can_attach_to_strrchr)
{
  char * (* strrchr_impl) (const char * s, int c);
  const char * s = "badger";

  strrchr_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "strrchr"));

  interceptor_fixture_attach (fixture, 0, strrchr_impl, '>', '<');

  g_assert_true (strrchr_impl (s, 'd') == s + 2);
  g_assert_cmpstr (fixture->result->str, ==, "><");
}

TESTCASE (can_attach_to_read)
{
  ssize_t (* read_impl) (int fd, void * buf, size_t n);
  int ret, fds[2];
  GThread * read_thread;
  guint8 value = 42;

  read_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "read"));

  ret = pipe (fds);
  g_assert_cmpint (ret, ==, 0);

  read_thread =
      g_thread_new ("perform-read", perform_read, GSIZE_TO_POINTER (fds[0]));
  g_usleep (G_USEC_PER_SEC / 10);
  interceptor_fixture_attach (fixture, 0, read_impl, '>', '<');
  write (fds[1], &value, sizeof (value));
  g_thread_join (read_thread);
  g_assert_cmpstr (fixture->result->str, ==, "");

  close (fds[0]);

  value = 0;
  ret = read_impl (fds[0], &value, sizeof (value));
  g_assert_cmpint (ret, ==, -1);
  g_assert_cmpuint (value, ==, 0);
  g_assert_cmpstr (fixture->result->str, ==, "><");

  close (fds[1]);
}

TESTCASE (can_attach_to_accept)
{
  int server, client, ret;
  int (* accept_impl) (int socket, struct sockaddr * address,
      socklen_t * address_len);
  struct sockaddr_in addr = { 0, };
  socklen_t addr_len;

  server = socket (AF_INET, SOCK_STREAM, 0);
  g_assert_cmpint (server, !=, -1);

  addr.sin_family = AF_INET;
  addr.sin_port = g_random_int_range (1337, 31337);
  addr.sin_addr.s_addr = INADDR_ANY;
  ret = bind (server, (struct sockaddr *) &addr, sizeof (addr));
  g_assert_cmpint (ret, ==, 0);

  ret = listen (server, 1);
  g_assert_cmpint (ret, ==, 0);

  client = socket (AF_INET, SOCK_STREAM, 0);
  g_assert_cmpint (client, !=, -1);
  ret = fcntl (client, F_SETFL, O_NONBLOCK);
  g_assert_cmpint (ret, ==, 0);
  ret = connect (client, (struct sockaddr *) &addr, sizeof (addr));
  g_assert_true (ret == -1 && errno == EINPROGRESS);

  accept_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "accept"));

  interceptor_fixture_attach (fixture, 0, accept_impl, '>', '<');

  addr_len = sizeof (addr);
  ret = accept_impl (server, (struct sockaddr *) &addr, &addr_len);
  g_assert_cmpint (ret, >=, 0);

  close (ret);
  close (client);
  close (server);
}

TESTCASE (can_attach_to_posix_spawnattr_setbinpref_np)
{
#ifdef HAVE_POSIX_SPAWNATTR_INIT
  int (* posix_spawnattr_setbinpref_np_impl) (posix_spawnattr_t * attr,
      size_t count, cpu_type_t * pref, size_t * ocount);
  posix_spawnattr_t attr;
  cpu_type_t pref;
  size_t ocount;
  int ret;

  posix_spawnattr_setbinpref_np_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib",
      "posix_spawnattr_setbinpref_np"));

  interceptor_fixture_attach (fixture, 0, posix_spawnattr_setbinpref_np_impl,
      '>', '<');

  posix_spawnattr_init (&attr);
  pref = CPU_TYPE_ARM64;
  ret = posix_spawnattr_setbinpref_np_impl (&attr, 1, &pref, &ocount);
  g_assert_cmpint (ret, ==, 0);
  g_assert_cmpstr (fixture->result->str, ==, "><");
  posix_spawnattr_destroy (&attr);
#else
  g_print ("<not supported by OS> ");
#endif
}

TESTCASE (can_attach_to_pid_for_task)
{
  mach_port_t self;
  int * (* pid_for_task_impl) (void);
  int pid = 0, ret;

  self = mach_task_self ();

  pid_for_task_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "pid_for_task"));

  interceptor_fixture_attach (fixture, 0, pid_for_task_impl, '>', '<');

  ret = pid_for_task (self, &pid);
  g_assert_cmpint (ret, ==, KERN_SUCCESS);
  g_assert_cmpstr (fixture->result->str, ==, "><");

  g_assert_cmpint (pid, ==, getpid ());
}

TESTCASE (can_attach_to_mach_host_self)
{
  mach_port_t (* mach_host_self_impl) (void);
  mach_port_t host;

  mach_host_self_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "mach_host_self"));

  interceptor_fixture_attach (fixture, 0, mach_host_self_impl, '>', '<');

  host = mach_host_self_impl ();
  g_assert_cmpint (host, !=, 0);
  g_assert_cmpstr (fixture->result->str, ==, "><");

  interceptor_fixture_detach (fixture, 0);

  g_assert_cmpint (host, ==, mach_host_self_impl ());
}

TESTCASE (can_attach_to_xpc_retain)
{
  gpointer (* xpc_dictionary_create_impl) (const gchar * const * keys,
      gconstpointer * values, gsize count);
  gpointer (* xpc_retain_impl) (gpointer object);
  void (* xpc_release_impl) (gpointer object);
  gpointer dict;

  xpc_dictionary_create_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib",
      "xpc_dictionary_create"));
  xpc_retain_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "xpc_retain"));
  xpc_release_impl = GSIZE_TO_POINTER (
      gum_module_find_export_by_name ("libSystem.B.dylib", "xpc_release"));

  dict = xpc_dictionary_create_impl (NULL, NULL, 0);

  xpc_retain_impl (dict);

  interceptor_fixture_attach (fixture, 0, xpc_retain_impl, '>', '<');

  xpc_retain_impl (dict);
  g_assert_cmpstr (fixture->result->str, ==, "><");

  xpc_release_impl (dict);
  xpc_release_impl (dict);
  xpc_release_impl (dict);
}

TESTCASE (can_attach_to_sqlite3_close)
{
  gint (* close_impl) (gpointer connection);

  close_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (
      "libsqlite3.dylib", "sqlite3_close"));

  interceptor_fixture_attach (fixture, 0, close_impl, '>', '<');

  close_impl (NULL);
  g_assert_cmpstr (fixture->result->str, ==, "><");
}

TESTCASE (can_attach_to_sqlite3_thread_cleanup)
{
#ifndef HAVE_ARM
  void (* thread_cleanup_impl) (void);

  thread_cleanup_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (
      "libsqlite3.dylib", "sqlite3_thread_cleanup"));

  interceptor_fixture_attach (fixture, 0, thread_cleanup_impl, '>', '<');

  thread_cleanup_impl ();
  g_assert_cmpstr (fixture->result->str, ==, "><");

  interceptor_fixture_detach (fixture, 0);
  g_string_truncate (fixture->result, 0);
#endif
}

static gpointer
perform_read (gpointer data)
{
  gint fd = GPOINTER_TO_SIZE (data);
  guint8 value = 0;
  int ret;

  ret = read (fd, &value, sizeof (value));
  g_assert_cmpint (ret, ==, 1);
  g_assert_cmpuint (value, ==, 42);

  return NULL;
}

TESTCASE (attach_performance)
{
  gpointer sqlite;
  TestPerformanceContext ctx;
  GTimer * timer;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  ctx.interceptor = fixture->interceptor;
  ctx.listener = GUM_INVOCATION_LISTENER (test_callback_listener_new ());
  ctx.count = 0;

  sqlite = dlopen ("/usr/lib/libsqlite3.0.dylib", RTLD_LAZY | RTLD_GLOBAL);
  g_assert_nonnull (sqlite);

  timer = g_timer_new ();

  gum_interceptor_begin_transaction (ctx.interceptor);

  gum_module_enumerate_exports ("libsqlite3.dylib", attach_if_function_export,
      &ctx);

  gum_interceptor_end_transaction (ctx.interceptor);

  g_print ("<hooked %u functions in %u ms> ", ctx.count,
      (guint) (g_timer_elapsed (timer, NULL) * 1000.0));
  g_timer_destroy (timer);

  dlclose (sqlite);

  g_object_unref (ctx.listener);
}

TESTCASE (replace_performance)
{
  gpointer sqlite;
  TestPerformanceContext ctx;
  GTimer * timer;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  ctx.interceptor = fixture->interceptor;
  ctx.listener = NULL;
  ctx.count = 0;

  sqlite = dlopen ("/usr/lib/libsqlite3.0.dylib", RTLD_LAZY | RTLD_GLOBAL);
  g_assert_nonnull (sqlite);

  timer = g_timer_new ();

  gum_interceptor_begin_transaction (ctx.interceptor);

  gum_module_enumerate_exports ("libsqlite3.dylib", replace_if_function_export,
      &ctx);

  gum_interceptor_end_transaction (ctx.interceptor);

  g_print ("<hooked %u functions in %u ms> ", ctx.count,
      (guint) (g_timer_elapsed (timer, NULL) * 1000.0));
  g_timer_destroy (timer);

  dlclose (sqlite);
}

static gboolean
attach_if_function_export (const GumExportDetails * details,
                           gpointer user_data)
{
  if (details->type == GUM_EXPORT_FUNCTION &&
      strcmp (details->name, "sqlite3_thread_cleanup") != 0)
  {
    TestPerformanceContext * ctx = user_data;
    GumAttachReturn attach_ret;

    attach_ret = gum_interceptor_attach (ctx->interceptor,
        GSIZE_TO_POINTER (details->address), ctx->listener, NULL);
    if (attach_ret == GUM_ATTACH_OK)
    {
      ctx->count++;
    }
    else
    {
      g_printerr ("\n\nFailed to attach to %s: %s\n", details->name,
          (attach_ret == GUM_ATTACH_WRONG_SIGNATURE)
              ? "wrong signature"
              : "already attached");
    }
  }

  return TRUE;
}

static gboolean
replace_if_function_export (const GumExportDetails * details,
                            gpointer user_data)
{
  if (details->type == GUM_EXPORT_FUNCTION &&
      strcmp (details->name, "sqlite3_thread_cleanup") != 0)
  {
    TestPerformanceContext * ctx = user_data;
    GumReplaceReturn replace_ret;

    replace_ret = gum_interceptor_replace (ctx->interceptor,
        GSIZE_TO_POINTER (details->address), dummy_replacement_never_called,
        NULL, NULL);
    if (replace_ret == GUM_REPLACE_OK)
    {
      ctx->count++;
    }
    else
    {
      g_printerr ("\n\nFailed to replace %s: %s\n", details->name,
          (replace_ret == GUM_REPLACE_WRONG_SIGNATURE)
              ? "wrong signature"
              : "already attached");
    }
  }

  return TRUE;
}

static void
dummy_replacement_never_called (void)
{
}

#ifdef HAVE_IOS

#define CS_OPS_STATUS 0
#define CS_VALID 0x0000001

extern int csops (pid_t pid, unsigned int ops, void * useraddr,
    size_t usersize);

static gboolean replace_with_cydia_substrate_if_function_export (
    const GumExportDetails * details, gpointer user_data);

TESTCASE (should_retain_code_signing_status)
{
  gint (* close_impl) (gpointer connection);
  gint res;
  uint32_t attributes;

  if (g_file_test ("/electra", G_FILE_TEST_IS_DIR))
  {
    g_print ("<skipped on Electra> ");
    return;
  }

  close_impl = GSIZE_TO_POINTER (gum_module_find_export_by_name (
      "libsqlite3.dylib", "sqlite3_close"));
  interceptor_fixture_attach (fixture, 0, close_impl, '>', '<');

  g_assert_cmpstr (fixture->result->str, ==, "");
  close_impl (NULL);
  g_assert_cmpstr (fixture->result->str, ==, "><");

  attributes = 0;
  res = csops (0, CS_OPS_STATUS, &attributes, sizeof (attributes));
  g_assert_cmpint (res, !=, -1);

  g_assert_true ((attributes & CS_VALID) != 0);
}

TESTCASE (cydia_substrate_replace_performance)
{
  gpointer cydia_substrate, sqlite;
  TestPerformanceContext ctx;
  GTimer * timer;

  if (!g_test_slow ())
  {
    g_print ("<skipping, run in slow mode> ");
    return;
  }

  cydia_substrate = dlopen (
      "/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate",
      RTLD_LAZY | RTLD_GLOBAL);
  g_assert_nonnull (cydia_substrate);

  ctx.MSHookFunction = dlsym (cydia_substrate, "MSHookFunction");
  g_assert_nonnull (ctx.MSHookFunction);

  ctx.count = 0;

  sqlite = dlopen ("/usr/lib/libsqlite3.0.dylib", RTLD_LAZY | RTLD_GLOBAL);
  g_assert_nonnull (sqlite);

  timer = g_timer_new ();

  gum_module_enumerate_exports ("libsqlite3.dylib",
      replace_with_cydia_substrate_if_function_export, &ctx);

  g_print ("<hooked %u functions in %u ms> ", ctx.count,
      (guint) (g_timer_elapsed (timer, NULL) * 1000.0));
  g_timer_destroy (timer);

  dlclose (sqlite);

  dlclose (cydia_substrate);
}

static gboolean
replace_with_cydia_substrate_if_function_export (
    const GumExportDetails * details,
    gpointer user_data)
{
  if (details->type == GUM_EXPORT_FUNCTION &&
      strcmp (details->name, "sqlite3_thread_cleanup") != 0)
  {
    TestPerformanceContext * ctx = user_data;
    void * original;

    ctx->MSHookFunction (GSIZE_TO_POINTER (details->address),
        dummy_replacement_never_called, &original);
    ctx->count++;
  }

  return TRUE;
}

#endif
```