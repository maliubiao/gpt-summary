Response:
My thought process to answer the request about `interceptor-fixture.c` goes like this:

1. **Understand the Goal:** The request asks for the functionality of the file, its relation to reverse engineering, its use of low-level/kernel concepts, logical reasoning, common user errors, and how a user reaches this code (debugging context).

2. **Initial Skim for Key Information:** I quickly scan the code looking for defining structures, function names, included headers, and macros. This gives me a high-level understanding of what the code is doing. Key things that jump out:
    * Includes like `guminterceptor.h`, `dlfcn.h`, `unistd.h`, suggesting interaction with dynamic linking and system calls.
    * Macros like `TESTCASE` and `TESTENTRY` hint at a testing framework.
    * Structures like `TestInterceptorFixture` and `ListenerContext` clearly define data organization.
    * Functions like `gum_interceptor_obtain`, `gum_interceptor_attach`, `gum_invocation_context_get_nth_argument`, etc., are related to Frida's interception capabilities.
    * Conditional compilation based on OS (HAVE_WINDOWS, HAVE_LINUX, etc.) and architecture.

3. **Identify Core Functionality:** Based on the includes and function names, the primary function of this file is to provide a *fixture* for testing Frida's interception mechanism. It sets up and tears down the environment needed to test intercepting function calls. The `TestInterceptorFixture` structure holds the necessary components: a `GumInterceptor` instance and listener contexts.

4. **Reverse Engineering Relevance:**  The core purpose of Frida is dynamic instrumentation for reverse engineering. This fixture directly relates because it's testing the fundamental ability of Frida to intercept and monitor function execution. Examples include modifying arguments, inspecting return values, and observing control flow.

5. **Low-Level/Kernel Connections:**
    * **Binary Level:** The use of `dlopen` and `dlsym` (or their Windows equivalents) directly interacts with the binary loading process and symbol resolution. The code manipulates function pointers.
    * **Linux/Android Kernel/Framework:** While the fixture itself doesn't directly call kernel functions, the *interceptor* being tested *does*. Frida's interception mechanism often involves manipulating instruction pointers, setting breakpoints, and managing context switches, all of which are low-level operating system concepts. On Android, interacting with the Dalvik/ART runtime for Java interception is also relevant (though not explicitly shown in *this* file).

6. **Logical Reasoning and Input/Output:** The fixture sets up listeners that record events (entering and leaving functions). The `enter_char` and `leave_char` in `ListenerContext` are used to build a string (`fixture->result`) representing the execution flow. By attaching these listeners to target functions, we can infer the execution order.

    * **Hypothetical Input:** Attach a listener with `enter_char = 'E'` and `leave_char = 'L'` to `target_function`. Call `target_function` once.
    * **Expected Output:** The `fixture->result` would be "EL". If the function is called multiple times or other functions are intercepted, the output would reflect that sequence.

7. **Common User Errors:** The most likely user errors would be related to the setup and teardown of the fixture or incorrect usage of the Frida API it tests:
    * **Forgetting to detach listeners:**  This could lead to unexpected behavior in subsequent tests or even crashes.
    * **Incorrectly specifying the target function:**  Attaching to the wrong address won't intercept the intended function.
    * **Memory management issues in custom listeners:**  If a user wrote their own listener callbacks and didn't manage memory correctly, it could cause problems.

8. **Debugging Context (How to reach this code):** A developer working on Frida itself or extending its core functionality might interact with this file. The most common scenario is running the Frida test suite:
    1. **Clone the Frida repository.**
    2. **Navigate to the `frida-gum` subdirectory.**
    3. **Execute the test command** (likely using a build system like Meson/Ninja). The specific command would depend on the build setup, but it would involve running tests for the `core/interceptor` component.
    4. **If a test involving `interceptor-fixture.c` fails**, the developer would likely examine the output, set breakpoints in the fixture setup/teardown or the test cases themselves, and step through the code to understand the failure.

**Self-Correction/Refinement during Thought Process:**

* **Initial thought:** Focus only on the C code itself.
* **Correction:** Remember the broader context of Frida and its purpose in dynamic instrumentation. Connect the fixture's actions to real-world reverse engineering scenarios.
* **Initial thought:**  Only describe the direct functionality of the code.
* **Correction:**  Address all aspects of the request, including low-level details, logical reasoning, user errors, and the debugging context.
* **Initial thought:** Provide very technical details.
* **Correction:** Balance technical accuracy with clarity and explain concepts in a way that is understandable even without deep knowledge of Frida's internals. Use analogies where helpful.

By following these steps and refining my understanding along the way, I can construct a comprehensive and accurate answer to the request.

这个C源代码文件 `interceptor-fixture.c` 是 Frida (一个动态 instrumentation工具) 的一部分，具体来说，它位于 `frida-gum` 子项目中的 `tests/core` 目录，这表明它是一个用于测试 `GumInterceptor` 模块的测试辅助代码 (fixture)。

让我们逐一分析其功能以及与你提出的各个方面的关系：

**1. 功能列举:**

* **提供测试环境:**  `interceptor-fixture.c` 的主要目的是创建一个可重复使用的测试环境，用于测试 Frida 的拦截 (interception) 功能。它设置了必要的对象和状态，以便编写针对 `GumInterceptor` 的单元测试。
* **初始化 GumInterceptor:**  文件中使用 `gum_interceptor_obtain()` 创建一个 `GumInterceptor` 的实例。`GumInterceptor` 是 Frida 中负责拦截函数调用的核心组件。
* **管理监听器 (Listeners):**  它定义了 `ListenerContext` 结构体，用于存储拦截回调函数的上下文信息，例如监听器对象、要记录的字符、以及一些状态数据。
* **注册和注销拦截器:** 提供了 `interceptor_fixture_attach()` 和 `interceptor_fixture_detach()` 函数，用于在测试目标函数上注册和注销拦截器。这些函数使用了 `gum_interceptor_attach()` 和 `gum_interceptor_detach()` Frida API。
* **定义拦截回调函数:**  `listener_context_on_enter()` 和 `listener_context_on_leave()` 是在函数调用进入和退出时执行的回调函数。它们记录了执行流程 (通过 `g_string_append_c` 添加字符到 `fixture->result`)，并捕获了一些上下文信息，如线程 ID、参数和返回值。
* **加载测试目标函数:**  代码会根据不同的操作系统和架构，动态加载包含测试目标函数的共享库 (`targetfunctions` 和 `specialfunctions`)。这通过 `dlopen` 和 `dlsym` (在非 Windows 系统上) 或相应的 Windows API 实现。
* **提供访问 Libc 函数的辅助函数:** `interceptor_fixture_get_libc_malloc()` 和 `interceptor_fixture_get_libc_free()` 用于获取 libc 库中 `malloc` 和 `free` 函数的地址，方便在测试中使用。
* **定义测试用例的宏:**  `TESTCASE` 和 `TESTENTRY` 是用于定义和注册测试用例的宏，虽然这些宏的实现可能在其他文件中，但 `interceptor-fixture.c` 使用它们来组织测试。
* **内存管理:** 包含了对 `ListenerContext` 的分配和释放 (`g_slice_new0` 和 `g_slice_free`)，以及 `GString` 对象的管理。

**2. 与逆向方法的关系:**

这个文件是 Frida 逆向工具的一部分，其核心功能就是测试函数拦截，这与逆向分析密切相关：

* **动态分析:** Frida 的拦截功能是动态分析的核心。逆向工程师可以使用 Frida 拦截目标进程中的函数调用，观察参数、返回值、执行流程，从而理解程序的行为。
* **Hooking 技术:** `GumInterceptor` 实现了 hooking 技术，允许在不修改目标程序二进制文件的情况下，劫持函数的执行流程，执行自定义的代码。`interceptor-fixture.c` 就是在测试这种 hooking 能力。
* **行为监控:** 通过在函数的入口和出口设置拦截点，可以监控函数的调用频率、参数变化、资源使用情况等，这对于理解程序的运行时行为至关重要。

**举例说明:**

假设逆向工程师想了解某个恶意软件如何解密其配置信息。他可以使用 Frida 脚本，利用 `GumInterceptor` 拦截与解密相关的函数 (可能通过字符串搜索或者初步分析找到)，例如 `decrypt_config`。

`interceptor-fixture.c` 中的测试用例可能会模拟这种场景：

```c
TESTCASE (basic_interception)
{
  TestInterceptorFixture * fixture = data;

  interceptor_fixture_attach (fixture, 0, target_function, 'E', 'L');

  g_assert_null (target_function (fixture->result));

  g_assert_cmpstr (fixture->result->str, "EL");

  interceptor_fixture_detach (fixture, 0);
}
```

在这个简化的测试用例中，`target_function` 可以代表恶意软件的 `decrypt_config` 函数。通过 attach 拦截器，并在 `on_enter` 和 `on_leave` 回调中记录字符，可以验证拦截器是否成功工作。在真实的逆向场景中，回调函数会做更复杂的事情，例如打印参数值、修改返回值、调用其他函数等。

**3. 涉及二进制底层，Linux, Android 内核及框架的知识:**

* **二进制底层:**
    * **函数指针:** 代码中大量使用了函数指针 (`gpointer (* target_function) (GString * str)`)，这是与二进制代码交互的基础。拦截器的核心就是修改或替换函数指针，或者在函数入口处插入跳转指令。
    * **动态链接:** 使用 `dlopen` 和 `dlsym` (或 Windows 上的相应 API) 来加载共享库和查找函数符号，这直接涉及到操作系统的动态链接器。
    * **指令级别的操作:** 虽然 `interceptor-fixture.c` 没有直接操作机器指令，但 `GumInterceptor` 内部的实现会涉及到指令级别的修改，例如插入 hook 代码、保存原始指令等。
* **Linux:**
    * **共享库 (.so):**  在 Linux 上，测试目标函数被编译成共享库，通过 `dlopen` 加载。
    * **`dlfcn.h`:** 使用了 `dlfcn.h` 头文件提供的 API 来进行动态链接操作。
    * **`unistd.h`:**  可能间接使用 `unistd.h` 中的函数，例如在路径操作中。
* **Android 内核及框架:**
    * **尽管此文件本身不直接涉及 Android 内核，但 Frida 在 Android 上的应用会涉及到:**
        * **ART/Dalvik 虚拟机:**  Frida 能够 hook Java 代码，这需要理解 Android 运行时的内部机制。
        * **System calls:**  底层的拦截机制可能涉及到对系统调用的监控或修改。
        * **进程间通信 (IPC):** Frida 需要与目标进程通信来注入代码和接收事件。
* **操作系统差异:** 代码中使用了大量的条件编译 (`#ifdef HAVE_WINDOWS`, `#elif defined (HAVE_LINUX)`, 等) 来处理不同操作系统之间的差异，尤其是在加载共享库的方式上。

**4. 逻辑推理，假设输入与输出:**

考虑 `basic_interception` 测试用例：

* **假设输入:**
    * 注册一个拦截器到 `target_function`，`on_enter` 回调添加 'E'，`on_leave` 回调添加 'L'。
    * 调用 `target_function(fixture->result)`。
* **逻辑推理:**
    1. 当 `target_function` 被调用时，拦截器的 `on_enter` 回调函数会首先执行。
    2. `on_enter` 回调会将字符 'E' 添加到 `fixture->result` 指向的字符串中。
    3. 接着，`target_function` 本身的代码会执行 (在这个测试中，`target_function` 似乎没有实际操作 `fixture->result`)。
    4. 当 `target_function` 执行完毕准备返回时，拦截器的 `on_leave` 回调函数会执行。
    5. `on_leave` 回调会将字符 'L' 添加到 `fixture->result` 指向的字符串中。
* **预期输出:**  `fixture->result` 指向的字符串应该为 "EL"。

**5. 用户或编程常见的使用错误:**

* **忘记 detach 拦截器:** 如果在测试结束后忘记调用 `interceptor_fixture_detach`，可能会导致后续的测试受到干扰，或者在真实应用中引起意想不到的行为。
* **错误的函数指针:** 在使用 Frida API 时，如果提供了错误的函数地址或符号名称，`gum_interceptor_attach` 可能会失败，或者 hook 到错误的函数。
* **回调函数中的错误:** `on_enter` 或 `on_leave` 回调函数中的错误 (例如，内存访问错误、未处理的异常) 可能会导致目标进程崩溃或 Frida 自身出现问题。
* **多线程问题:**  如果目标程序是多线程的，需要在回调函数中考虑线程安全问题，避免数据竞争。
* **对只读内存进行修改:** 尝试在回调函数中修改位于只读内存段的数据可能会导致程序崩溃。

**举例说明:**

一个常见的错误是用户在编写 Frida 脚本时，尝试 hook 一个不存在的函数名，或者拼写错误：

```javascript
// 错误的函数名
Interceptor.attach(Module.findExportByName(null, "nonExistentFunction"), {
  onEnter: function(args) {
    console.log("Entering nonExistentFunction");
  }
});
```

在这种情况下，`Module.findExportByName` 会返回 `null`，导致 `Interceptor.attach` 抛出错误。虽然 `interceptor-fixture.c` 是测试代码，但它测试的正是 Frida API 的正确使用，帮助开发者避免这类错误。

**6. 用户操作是如何一步步的到达这里，作为调试线索:**

通常，普通 Frida 用户不会直接接触到 `interceptor-fixture.c` 这个文件。这个文件是 Frida 开发人员在开发和测试 `frida-gum` 核心库时使用的。一个用户可能间接涉及到这里的情况如下：

1. **用户遇到 Frida 的 bug:**  用户在使用 Frida 脚本进行逆向分析时，可能会遇到一些意想不到的行为或者崩溃。
2. **报告 bug 或寻求帮助:** 用户会将问题报告给 Frida 的开发者社区，或者在论坛上寻求帮助，提供相关的 Frida 脚本、目标程序信息和错误日志。
3. **开发者进行调试:** Frida 的开发者会尝试复现用户报告的问题。为了定位 bug，他们可能会：
    * **阅读用户的脚本:** 理解用户的使用场景和意图。
    * **分析错误日志:**  查找错误发生的上下文。
    * **编写或修改测试用例:**  可能会创建一个新的测试用例，或者修改现有的测试用例 (例如 `interceptor-fixture.c` 中的测试用例)，来精确地复现用户遇到的问题。
    * **运行测试:**  开发者会在自己的开发环境中运行这些测试用例。如果涉及到 `GumInterceptor` 的问题，他们可能会执行与 `interceptor-fixture.c` 相关的测试。
    * **设置断点和单步调试:**  在运行测试时，开发者可能会在 `interceptor-fixture.c` 或 `guminterceptor.c` 等核心代码中设置断点，单步执行代码，观察变量的值和程序流程，以找出 bug 的根源。
    * **查看源代码:**  为了理解代码的实现细节，开发者会查看 `interceptor-fixture.c` 以及相关的源代码文件。

**作为调试线索，`interceptor-fixture.c` 可以提供以下信息:**

* **验证 Frida 核心功能的正确性:** 如果一个用户报告了一个关于函数拦截的问题，开发者可以查看 `interceptor-fixture.c` 中的测试用例，确认基本的拦截功能是否正常工作。如果测试用例失败，则说明是 Frida 自身的核心库存在 bug。
* **提供示例代码:**  测试用例本身可以作为 Frida API 的使用示例，帮助开发者理解如何正确地使用 `GumInterceptor`。
* **隔离问题:**  通过编写针对特定场景的测试用例，开发者可以更好地隔离问题，缩小 bug 的范围。
* **回归测试:**  在修复 bug 后，相应的测试用例可以作为回归测试，确保该 bug 不会在未来的版本中再次出现。

总之，`interceptor-fixture.c` 虽然不是普通 Frida 用户直接操作的文件，但它是 Frida 开发和测试过程中至关重要的组成部分，对于保证 Frida 的质量和稳定性起着关键作用，并且在调试用户报告的问题时可以提供重要的线索。

### 提示词
```
这是目录为frida/subprojects/frida-gum/tests/core/interceptor-fixture.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor.h"

#include "interceptor-callbacklistener.h"
#include "interceptor-functiondatalistener.h"
#include "lowlevelhelpers.h"
#include "testutil.h"
#include "valgrind.h"

#include <stdlib.h>
#include <string.h>

#ifdef HAVE_WINDOWS
# include "targetfunctions/targetfunctions.c"
#else
# include <dlfcn.h>
# include <unistd.h>
#endif

#define TESTCASE(NAME) \
    void test_interceptor_ ## NAME ( \
        TestInterceptorFixture * fixture, gconstpointer data)
#define TESTENTRY(NAME) \
    TESTENTRY_WITH_FIXTURE ("Core/Interceptor", \
        test_interceptor, NAME, TestInterceptorFixture)

/* TODO: fix this in GLib */
#ifdef HAVE_DARWIN
# undef G_MODULE_SUFFIX
# define G_MODULE_SUFFIX "dylib"
#endif

#if defined (HAVE_WINDOWS)
# define GUM_TEST_SHLIB_OS "windows"
#elif defined (HAVE_MACOS)
# define GUM_TEST_SHLIB_OS "macos"
#elif defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
# define GUM_TEST_SHLIB_OS "linux"
#elif defined (HAVE_IOS)
# define GUM_TEST_SHLIB_OS "ios"
#elif defined (HAVE_WATCHOS)
# define GUM_TEST_SHLIB_OS "watchos"
#elif defined (HAVE_TVOS)
# define GUM_TEST_SHLIB_OS "tvos"
#elif defined (HAVE_ANDROID)
# define GUM_TEST_SHLIB_OS "android"
#elif defined (HAVE_FREEBSD)
# define GUM_TEST_SHLIB_OS "freebsd"
#elif defined (HAVE_QNX)
# define GUM_TEST_SHLIB_OS "qnx"
#else
# error Unknown OS
#endif

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_TEST_SHLIB_ARCH "x86"
# else
#  define GUM_TEST_SHLIB_ARCH "x86_64"
# endif
#elif defined (HAVE_ARM)
# ifdef __ARM_PCS_VFP
#  define GUM_TEST_SHLIB_ARCH "armhf"
# else
#  define GUM_TEST_SHLIB_ARCH "arm"
# endif
#elif defined (HAVE_ARM64)
# ifdef HAVE_PTRAUTH
#  define GUM_TEST_SHLIB_ARCH "arm64e"
# else
#  define GUM_TEST_SHLIB_ARCH "arm64"
# endif
#elif defined (HAVE_MIPS)
# if G_BYTE_ORDER == G_LITTLE_ENDIAN
#  if GLIB_SIZEOF_VOID_P == 8
#    define GUM_TEST_SHLIB_ARCH "mips64el"
#  else
#    define GUM_TEST_SHLIB_ARCH "mipsel"
#  endif
# else
#  if GLIB_SIZEOF_VOID_P == 8
#    define GUM_TEST_SHLIB_ARCH "mips64"
#  else
#    define GUM_TEST_SHLIB_ARCH "mips"
#  endif
# endif
#else
# error Unknown CPU
#endif

typedef struct _TestInterceptorFixture TestInterceptorFixture;
typedef struct _ListenerContext        ListenerContext;

struct _ListenerContext
{
  TestCallbackListener * listener;

  TestInterceptorFixture * fixture;
  gchar enter_char;
  gchar leave_char;
  GumThreadId last_thread_id;
  gsize last_seen_argument;
  gpointer last_return_value;
  GumCpuContext last_on_enter_cpu_context;
};

struct _TestInterceptorFixture
{
  GumInterceptor * interceptor;
  GString * result;
  ListenerContext * listener_context[2];
};

static void listener_context_free (ListenerContext * ctx);
static void listener_context_on_enter (ListenerContext * self,
    GumInvocationContext * context);
static void listener_context_on_leave (ListenerContext * self,
    GumInvocationContext * context);

gpointer (* target_function) (GString * str) = NULL;
gpointer (* target_nop_function_a) (gpointer data);
gpointer (* target_nop_function_b) (gpointer data);
gpointer (* target_nop_function_c) (gpointer data);

gpointer (* special_function) (GString * str) = NULL;

static void
test_interceptor_fixture_setup (TestInterceptorFixture * fixture,
                                gconstpointer data)
{
  fixture->interceptor = gum_interceptor_obtain ();
  fixture->result = g_string_sized_new (4096);

  memset (&fixture->listener_context, 0, sizeof (fixture->listener_context));

  if (target_function == NULL)
  {
#ifdef HAVE_WINDOWS
    target_function = gum_test_target_function;
    special_function = gum_test_target_function;
    target_nop_function_a = gum_test_target_nop_function_a;
    target_nop_function_b = gum_test_target_nop_function_b;
    target_nop_function_c = gum_test_target_nop_function_c;
#else
    gchar * testdir, * filename;
    void * lib;

    testdir = test_util_get_data_dir ();

    filename = g_build_filename (testdir,
        "targetfunctions-" GUM_TEST_SHLIB_OS "-" GUM_TEST_SHLIB_ARCH
        "." G_MODULE_SUFFIX, NULL);
    lib = dlopen (filename, RTLD_NOW | RTLD_GLOBAL);
    if (lib == NULL)
      g_print ("failed to open '%s'\n", filename);
    g_assert_nonnull (lib);
    g_free (filename);

    target_function = dlsym (lib, "gum_test_target_function");
    g_assert_nonnull (target_function);

    target_nop_function_a = dlsym (lib, "gum_test_target_nop_function_a");
    g_assert_nonnull (target_nop_function_a);

    target_nop_function_b = dlsym (lib, "gum_test_target_nop_function_b");
    g_assert_nonnull (target_nop_function_b);

    target_nop_function_c = dlsym (lib, "gum_test_target_nop_function_c");
    g_assert_nonnull (target_nop_function_c);

    filename = g_build_filename (testdir,
        "specialfunctions-" GUM_TEST_SHLIB_OS "-" GUM_TEST_SHLIB_ARCH
        "." G_MODULE_SUFFIX, NULL);
    lib = dlopen (filename, RTLD_LAZY | RTLD_GLOBAL);
    g_assert_nonnull (lib);
    g_free (filename);

    special_function = dlsym (lib, "gum_test_special_function");
    g_assert_nonnull (special_function);

    g_free (testdir);
#endif
  }
}

static void
test_interceptor_fixture_teardown (TestInterceptorFixture * fixture,
                                   gconstpointer data)
{
  guint i;

  for (i = 0; i < G_N_ELEMENTS (fixture->listener_context); i++)
  {
    ListenerContext * ctx = fixture->listener_context[i];

    if (ctx != NULL)
    {
      gum_interceptor_detach (fixture->interceptor,
          GUM_INVOCATION_LISTENER (ctx->listener));
      listener_context_free (ctx);
    }
  }

  g_string_free (fixture->result, TRUE);
  g_object_unref (fixture->interceptor);
}

static GumAttachReturn
interceptor_fixture_try_attach (TestInterceptorFixture * h,
                                guint listener_index,
                                gpointer test_func,
                                gchar enter_char,
                                gchar leave_char)
{
  GumAttachReturn result;
  ListenerContext * ctx;

  ctx = h->listener_context[listener_index];
  if (ctx != NULL)
  {
    listener_context_free (ctx);
    h->listener_context[listener_index] = NULL;
  }

  ctx = g_slice_new0 (ListenerContext);

  ctx->listener = test_callback_listener_new ();
  ctx->listener->on_enter =
      (TestCallbackListenerFunc) listener_context_on_enter;
  ctx->listener->on_leave =
      (TestCallbackListenerFunc) listener_context_on_leave;
  ctx->listener->user_data = ctx;

  ctx->fixture = h;
  ctx->enter_char = enter_char;
  ctx->leave_char = leave_char;

  result = gum_interceptor_attach (h->interceptor, test_func,
      GUM_INVOCATION_LISTENER (ctx->listener), NULL);
  if (result == GUM_ATTACH_OK)
  {
    h->listener_context[listener_index] = ctx;
  }
  else
  {
    listener_context_free (ctx);
  }

  return result;
}

static void
interceptor_fixture_attach (TestInterceptorFixture * h,
                            guint listener_index,
                            gpointer test_func,
                            gchar enter_char,
                            gchar leave_char)
{
  g_assert_cmpint (interceptor_fixture_try_attach (h, listener_index, test_func,
      enter_char, leave_char), ==, GUM_ATTACH_OK);
}

static void
interceptor_fixture_detach (TestInterceptorFixture * h,
                            guint listener_index)
{
  gum_interceptor_detach (h->interceptor,
      GUM_INVOCATION_LISTENER (h->listener_context[listener_index]->listener));
}

static gpointer
interceptor_fixture_get_libc_malloc (void)
{
  return gum_heap_api_list_get_nth (test_util_heap_apis (), 0)->malloc;
}

static gpointer
interceptor_fixture_get_libc_free (void)
{
  return gum_heap_api_list_get_nth (test_util_heap_apis (), 0)->free;
}

static void
listener_context_free (ListenerContext * ctx)
{
  g_object_unref (ctx->listener);
  g_slice_free (ListenerContext, ctx);
}

static void
listener_context_on_enter (ListenerContext * self,
                           GumInvocationContext * context)
{
  g_assert_cmpuint (gum_invocation_context_get_point_cut (context), ==,
      GUM_POINT_ENTER);

  g_string_append_c (self->fixture->result, self->enter_char);

  self->last_seen_argument = (gsize)
      gum_invocation_context_get_nth_argument (context, 0);
  self->last_on_enter_cpu_context = *context->cpu_context;

  self->last_thread_id = gum_invocation_context_get_thread_id (context);
}

static void
listener_context_on_leave (ListenerContext * self,
                           GumInvocationContext * context)
{
  g_assert_cmpuint (gum_invocation_context_get_point_cut (context), ==,
      GUM_POINT_LEAVE);

  g_string_append_c (self->fixture->result, self->leave_char);

  self->last_return_value = gum_invocation_context_get_return_value (context);
}
```