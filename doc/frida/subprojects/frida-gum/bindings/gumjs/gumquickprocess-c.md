Response:
Let's break down the thought process to analyze the `gumquickprocess.c` file and answer the user's request.

**1. Initial Understanding of the Request:**

The user wants to understand the functionality of a specific Frida source file. Key aspects of the request are:

* **Functionality Listing:** What does this code *do*?
* **Relevance to Reverse Engineering:** How can this be used in a reverse engineering context?
* **Binary/Kernel/Framework Knowledge:** What low-level system concepts are involved?
* **Logic and I/O:** Are there any obvious input/output relationships?
* **Common Usage Errors:** What mistakes might users make when using this?
* **Debugging Context:** How does a user end up interacting with this code?

**2. High-Level Code Overview (Skimming):**

I'll quickly read through the code, focusing on:

* **Includes:** These hint at the libraries and system features being used (`gum/gumdarwin.h`, platform-specific defines like `HAVE_LINUX`, `HAVE_WINDOWS`).
* **Data Structures:**  `GumQuickMatchContext`, `GumQuickRunOnThreadContext`, etc. These structures reveal how information is organized and passed around.
* **Function Declarations:**  `gumjs_process_get_main_module`, `gumjs_process_enumerate_threads`, etc. The naming suggests the purpose of these functions. The `GUMJS_DECLARE_*` and `GUMJS_DEFINE_*` macros indicate these are likely functions exposed to the JavaScript side of Frida.
* **`gumjs_process_entries`:** This array of `JSCFunctionListEntry` is crucial. It maps JavaScript property names (like "arch", "platform", "mainModule") to their C implementations.

**3. Deeper Dive - Functionality Extraction:**

Now, I'll go through the `gumjs_process_entries` array and the corresponding function definitions more systematically:

* **`arch`, `platform`, `pointerSize`:** These are simple properties exposing system information. Directly related to understanding the target environment in reverse engineering.
* **`mainModule` (getter):**  Fetches information about the main executable. Essential for understanding the entry point and core components of a process.
* **`getCurrentDir`, `getHomeDir`, `getTmpDir`:** Basic file system information. Useful for understanding the process's environment.
* **`isDebuggerAttached`:**  A classic anti-debugging check, vital for reverse engineers to detect and bypass.
* **`getCurrentThreadId`:**  Allows introspection of the current execution context.
* **`_enumerateThreads`:**  Crucial for understanding the process's concurrency model. The underscore suggests it might be an internal/less user-facing API.
* **`_runOnThread`:** Enables executing code in the context of another thread. Powerful for interacting with specific parts of a multithreaded application. This immediately flags potential race conditions or synchronization issues in reverse engineering.
* **`findModuleByName`, `_enumerateModules`:**  Essential for locating and inspecting loaded libraries. A cornerstone of reverse engineering.
* **`findRangeByAddress`, `_enumerateRanges`, `enumerateSystemRanges`, `_enumerateMallocRanges`:**  Deal with memory management and layout. Critical for understanding how data is stored and manipulated, identifying vulnerabilities (like buffer overflows), and analyzing memory corruption.
* **`setExceptionHandler`:**  Allows intercepting and potentially modifying exception handling. Useful for understanding error handling logic and potentially exploiting vulnerabilities.

**4. Connecting to Reverse Engineering:**

As I extracted the functionality, I actively thought about how each function could be used in a reverse engineering scenario. For example:

* **`isDebuggerAttached`:**  Bypassing debugger detection.
* **`_enumerateModules`:** Finding specific libraries to hook functions in.
* **`_runOnThread`:** Injecting code into a specific thread to observe its behavior or modify its execution.
* **Memory enumeration functions:** Locating specific data structures or code segments in memory.

**5. Identifying Binary/Kernel/Framework Concepts:**

Again, while analyzing the functionality, I paid attention to the underlying concepts:

* **Architecture (arch):** Instruction sets, register sizes.
* **Platform:** Operating system specifics (system calls, APIs).
* **Pointer Size:**  Memory addressing.
* **Modules/Libraries:** Dynamic linking, code organization.
* **Threads:** Concurrency, scheduling.
* **Memory Ranges/Protection:** Virtual memory, access permissions.
* **Exception Handling:** Operating system's error reporting mechanisms.
* **Stalker:** Frida's code tracing engine (though the file focuses on *managing* the Stalker in this process context, not its core implementation).
* **`mach_task_self()` (macOS):** Getting the current task port, a fundamental kernel concept.

**6. Logical Reasoning and I/O (Simple Cases):**

For straightforward functions:

* **`getCurrentDir`:** Input: None (implicitly the current process). Output: String representing the directory.
* **`findModuleByName`:** Input: String (module name). Output:  Module object or null.

For more complex ones (like the enumeration functions), the "input" is the process state, and the "output" is a sequence of callbacks.

**7. Common Usage Errors:**

I thought about typical mistakes developers might make when interacting with these features via the Frida JavaScript API:

* **Incorrect module names:**  Case sensitivity, typos.
* **Invalid addresses:**  Leading to errors or crashes.
* **Misunderstanding thread IDs:**  Targeting the wrong thread.
* **Improper use of callbacks:**  Not handling the `onComplete` correctly, errors in the `onMatch` function.
* **Stalker misuse:** Not understanding the performance implications of tracing.

**8. Debugging Context:**

I considered how a developer would interact with these functions during debugging:

* **Frida Script:**  The user writes JavaScript code using the `Process` object and its methods.
* **Frida CLI/API:** The user executes the script, which then interacts with the target process via Frida's core.
* **Error Messages:** If something goes wrong (e.g., `_gum_quick_args_parse` fails), Frida will likely throw an exception back to the JavaScript.

**9. Structuring the Answer:**

Finally, I organized the information according to the user's request:

* **Functionality List:** A bulleted list of the main features, explained concisely.
* **Reverse Engineering Relevance:** Explicitly linking the functionality to common reverse engineering tasks with examples.
* **Binary/Kernel/Framework Knowledge:**  Listing the relevant low-level concepts and providing brief explanations.
* **Logical Reasoning (Input/Output):**  Providing examples of input and output for some functions.
* **Common Usage Errors:**  Illustrating typical mistakes.
* **User Operation to Reach Here (Debugging):** Describing the sequence of steps a user would take to invoke this code.

**Self-Correction/Refinement during the Process:**

* **Initial Skim vs. Deep Dive:** Realizing that a quick skim gives a general idea, but the `gumjs_process_entries` array is the key to understanding the exposed API.
* **Connecting C to JavaScript:** Recognizing the role of the `GUMJS_DECLARE_*` and `GUMJS_DEFINE_*` macros in bridging the C code to the JavaScript environment.
* **Specificity of Examples:**  Moving from general statements to concrete examples of how each feature could be used in reverse engineering.
* **Considering the "Why":**  Not just listing the functions, but explaining *why* they are useful in the context of dynamic instrumentation and reverse engineering.

By following this structured approach, combining code analysis with an understanding of Frida's architecture and common reverse engineering practices, I could generate a comprehensive and informative answer to the user's request.
好的，让我们来分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumquickprocess.c` 这个文件，它是 Frida 中用于处理目标进程相关功能的 C 源代码。

**文件功能列表:**

这个文件定义了 Frida (更具体地说是 GumJS 绑定层) 中 `Process` 对象的实现。它提供了一系列与目标进程交互的功能，这些功能可以通过 JavaScript API 暴露给用户。核心功能包括：

1. **获取进程基本信息:**
   - 获取架构 (arch) 和平台 (platform)。
   - 获取指针大小 (pointerSize)。
   - 获取主模块 (mainModule) 的信息。
   - 获取当前工作目录 (getCurrentDir)。
   - 获取用户主目录 (getHomeDir)。
   - 获取临时目录 (getTmpDir)。
   - 获取进程 ID (id)。
   - 获取页面大小 (pageSize)。
   - 获取代码签名策略 (codeSigningPolicy)。

2. **进程状态查询:**
   - 判断调试器是否已附加 (isDebuggerAttached)。
   - 获取当前线程 ID (getCurrentThreadId)。

3. **线程管理:**
   - 枚举进程中的所有线程 (_enumerateThreads)。
   - 在指定的线程上执行代码 (_runOnThread)。

4. **模块管理 (类似动态链接库):**
   - 通过名称查找模块 (findModuleByName)。
   - 枚举进程中加载的所有模块 (_enumerateModules)。

5. **内存管理:**
   - 通过地址查找内存区域 (findRangeByAddress)。
   - 枚举具有特定保护属性的内存区域 (_enumerateRanges)。
   - 枚举系统保留的内存区域 (enumerateSystemRanges)。
   - 枚举通过 malloc 分配的内存区域 (_enumerateMallocRanges)。

6. **异常处理:**
   - 设置全局异常处理回调函数 (setExceptionHandler)。

**与逆向方法的关联及举例说明:**

这个文件提供的功能是 Frida 作为动态插桩工具的核心能力，与逆向工程密切相关。以下是一些例子：

* **代码注入和执行:**  `_runOnThread` 功能允许逆向工程师将自定义的 JavaScript 代码注入到目标进程的特定线程中执行。这可以用于：
    * **Hook 函数:**  在目标函数的入口或出口插入代码，监视参数、返回值或修改行为。
    * **修改内存数据:**  改变进程运行时的数据，例如修改游戏中的生命值、金币数量等。
    * **调用目标进程的函数:**  执行目标进程内部的特定功能。

    **例子:** 假设你想在 Android 应用中 hook `java.lang.System.exit` 方法，阻止应用退出。你可以使用 `_enumerateModules` 找到 `libandroid_runtime.so` (通常包含 Java 运行时)，然后使用 `findExportByName` (在其他 Frida 代码中) 找到 `System.exit` 的地址，最后通过 `Interceptor.attach` (在 Frida JavaScript API 中，底层可能用到这里的 `_runOnThread`) 插入你的 hook 代码。

* **内存分析:** `_enumerateRanges`、`findRangeByAddress` 和 `_enumerateMallocRanges` 允许逆向工程师了解目标进程的内存布局。这对于：
    * **查找敏感数据:**  例如，在内存中搜索用户名、密码或其他加密密钥。
    * **分析数据结构:**  理解目标进程使用的数据结构，例如对象、链表等。
    * **发现漏洞:**  例如，查找栈溢出或堆溢出的潜在位置。

    **例子:** 你可能想分析一个 Native 代码的 Android 游戏，查看游戏角色的属性存储在哪个内存区域。你可以使用 `_enumerateRanges` 找到具有读写权限的内存区域，然后通过扫描这些区域，根据已知的角色属性值来定位相关的内存地址。

* **模块分析:** `_enumerateModules` 和 `findModuleByName` 允许逆向工程师了解目标进程加载了哪些动态链接库。这对于：
    * **定位关键功能:**  确定特定功能所在的模块。
    * **分析依赖关系:**  了解目标进程依赖哪些第三方库。
    * **绕过反调试:**  某些反调试技术可能会检测特定的模块。

    **例子:** 在分析一个 Windows 恶意软件时，你可能想使用 `findModuleByName` 找到 `kernel32.dll`，然后 hook 其中的 API 函数，例如 `CreateProcessW` 或 `WriteFile`，来监控恶意软件的行为。

* **异常处理分析:** `setExceptionHandler` 允许逆向工程师捕获目标进程抛出的异常。这可以用于：
    * **理解错误处理机制:**  了解目标进程如何处理错误。
    * **定位崩溃原因:**  在程序崩溃时获取详细信息。
    * **进行 Fuzzing:**  通过观察异常来发现潜在的漏洞。

    **例子:**  在测试一个应用程序的安全性时，你可以设置一个全局异常处理程序，记录所有发生的异常，以便发现潜在的输入验证漏洞或内存访问错误。

**涉及的二进制底层、Linux、Android 内核及框架知识:**

这个文件是 Frida 中间层的一部分，它抽象了底层的操作系统细节，但仍然涉及到一些底层的概念：

* **二进制底层:**
    * **进程和线程:**  理解操作系统中进程和线程的概念，以及它们如何被管理和调度。
    * **内存管理:**  理解虚拟内存、内存分页、内存保护属性 (如读、写、执行权限) 等概念。
    * **模块 (共享库/动态链接库):**  理解模块的加载、卸载以及符号解析过程。
    * **地址空间:**  理解每个进程拥有独立的地址空间。

* **Linux/Android 内核:**
    * **系统调用:**  Frida 底层会使用系统调用与内核进行交互，例如，枚举线程、读取内存等。虽然这个文件没有直接调用系统调用，但它依赖于 `gum` 库，而 `gum` 库会处理这些底层交互。
    * **进程信息:**  依赖于 Linux/Android 内核提供的机制来获取进程、线程和模块的信息 (例如，读取 `/proc` 文件系统)。
    * **内存映射:**  理解内核如何管理进程的内存映射。

* **Android 框架:**
    * **Dalvik/ART 虚拟机:**  在 Android 平台上，Frida 经常需要与 Java 虚拟机交互。虽然这个文件本身不直接涉及 VM 的细节，但它提供的功能是构建与 VM 交互的更高级别 API 的基础。
    * **代码签名:**  `codeSigningPolicy` 的获取涉及到 Android 的代码签名机制。

**逻辑推理、假设输入与输出:**

让我们以 `findModuleByName` 函数为例进行逻辑推理：

**假设输入:**

* `fc.name`:  一个字符串，表示要查找的模块名称，例如 "libc.so" 或 "/system/lib64/libc.so"。
* 目标进程中加载了一些模块。

**逻辑推理:**

1. `gum_process_enumerate_modules` 函数会被调用，遍历目标进程中所有已加载的模块。
2. 对于每个模块，`gum_store_module_if_name_matches` 函数会被调用。
3. `gum_store_module_if_name_matches` 函数会比较当前模块的名称或路径与 `fc.name`。
4. 如果找到匹配的模块，`_gum_quick_module_new` 函数会被调用，创建一个表示该模块的 JavaScript 对象，并将其赋值给 `fc.result`。
5. 遍历过程会提前结束 (通过 `proceed = FALSE`)，因为已经找到了目标模块。
6. 如果遍历完所有模块都没有找到匹配项，`fc.result` 将保持为 `JS_NULL`。

**输出:**

* 如果找到匹配的模块，返回一个表示该模块的 JavaScript 对象，包含模块的基址、大小、路径等信息。
* 如果没有找到匹配的模块，返回 `JS_NULL`。

**涉及用户或编程常见的使用错误及举例说明:**

* **模块名称错误:** 用户在使用 `findModuleByName` 时，可能会输入错误的模块名称，例如拼写错误、大小写错误 (在某些平台上)。
    * **例子:** 在 Linux 上，输入 "LIBC.so" 而不是 "libc.so"。
* **假设模块一定存在:** 用户可能会假设某个模块一定会被加载，但实际上由于某些原因 (例如条件加载、错误处理) 模块可能没有加载。
    * **例子:**  尝试查找一个仅在特定版本的操作系统上存在的库。
* **不理解路径与名称的区别:**  `findModuleByName` 可以接受模块的完整路径或简单的名称。用户可能不清楚应该使用哪种格式。
    * **例子:** 在 Windows 上，输入 "C:\Windows\System32\kernel32.dll" 而不是 "kernel32.dll"。
* **在使用枚举函数时，`onMatch` 回调函数中发生错误:**  如果用户提供的 `onMatch` 回调函数抛出异常，可能会导致枚举过程提前终止或产生意外的行为。
    * **例子:** `onMatch` 函数尝试访问一个未定义的变量。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **编写 Frida 脚本:** 用户首先会编写一个 Frida JavaScript 脚本，该脚本使用 `Process` 对象及其提供的方法。例如：

   ```javascript
   console.log("Process ID:", Process.id);
   console.log("Main Module:", Process.mainModule.name);
   Process.enumerateModules({
       onMatch: function(module) {
           console.log("Found module:", module.name);
       },
       onComplete: function() {
           console.log("Module enumeration complete.");
       }
   });
   ```

2. **运行 Frida 脚本:** 用户使用 Frida 命令行工具 (例如 `frida -p <pid> -l script.js`) 或通过 Frida 的 API 将脚本注入到目标进程中。

3. **JavaScript 代码执行:** Frida 的 JavaScript 引擎 (QuickJS，在 `gumjs` 中实现绑定) 会执行用户编写的脚本。

4. **调用 `Process` 对象的方法:** 当 JavaScript 代码调用 `Process.id`、`Process.mainModule` 或 `Process.enumerateModules` 等方法时，这些调用会通过 GumJS 绑定层映射到 C 代码中的相应函数。

5. **进入 `gumquickprocess.c`:** 例如，当调用 `Process.enumerateModules` 时，会最终调用 `gumjs_process_enumerate_modules` 函数，该函数在 `gumquickprocess.c` 文件中定义。

6. **底层 Gum 库调用:**  `gumjs_process_enumerate_modules` 函数会调用更底层的 Gum 库函数 (例如 `gum_process_enumerate_modules`) 来实际执行操作，与目标进程进行交互。

7. **结果返回:**  Gum 库的操作结果会返回给 `gumjs_process_enumerate_modules`，然后被封装成 JavaScript 对象或值，最终返回给用户的 JavaScript 脚本。

**调试线索:**

如果用户在使用 Frida 时遇到问题，例如无法找到特定的模块，调试线索可能包括：

* **检查 JavaScript 代码:**  确认 `findModuleByName` 的参数是否正确，大小写是否匹配。
* **查看 Frida 输出:**  Frida 可能会输出错误信息或警告，指示哪里出了问题。
* **使用 Frida 的 `console.log`:**  在 JavaScript 代码中添加日志输出，查看中间步骤的结果。
* **阅读 Frida 文档和源代码:**  理解 `Process` 对象方法的具体行为和参数。
* **使用 Frida 的调试功能:**  Frida 提供了一些调试功能，可以帮助开发者定位问题。
* **分析目标进程:**  使用其他工具 (例如 `pmap`，`lsof` 等) 查看目标进程的模块加载情况，确认要查找的模块是否真的存在。

总而言之，`gumquickprocess.c` 是 Frida 连接 JavaScript API 和底层进程操作的关键桥梁，它提供了丰富的功能，使得逆向工程师能够动态地分析和操控目标进程。理解这个文件的功能和背后的原理对于有效地使用 Frida 进行逆向工程至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickprocess.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2020-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020-2023 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2023 Grant Douglas <me@hexplo.it>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickprocess.h"

#include "gumquickmacros.h"

#ifdef HAVE_DARWIN
# include <gum/gumdarwin.h>
#endif

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_SCRIPT_ARCH "ia32"
# else
#  define GUM_SCRIPT_ARCH "x64"
# endif
#elif defined (HAVE_ARM)
# define GUM_SCRIPT_ARCH "arm"
#elif defined (HAVE_ARM64)
# define GUM_SCRIPT_ARCH "arm64"
#elif defined (HAVE_MIPS)
# define GUM_SCRIPT_ARCH "mips"
#endif

#if defined (HAVE_LINUX)
# define GUM_SCRIPT_PLATFORM "linux"
#elif defined (HAVE_DARWIN)
# define GUM_SCRIPT_PLATFORM "darwin"
#elif defined (HAVE_WINDOWS)
# define GUM_SCRIPT_PLATFORM "windows"
#elif defined (HAVE_FREEBSD)
# define GUM_SCRIPT_PLATFORM "freebsd"
#elif defined (HAVE_QNX)
# define GUM_SCRIPT_PLATFORM "qnx"
#endif

typedef struct _GumQuickMatchContext GumQuickMatchContext;
typedef struct _GumQuickRunOnThreadContext GumQuickRunOnThreadContext;
typedef struct _GumQuickFindModuleByNameContext GumQuickFindModuleByNameContext;
typedef struct _GumQuickFindRangeByAddressContext
    GumQuickFindRangeByAddressContext;

struct _GumQuickExceptionHandler
{
  JSValue callback;
  GumQuickCore * core;
};

struct _GumQuickMatchContext
{
  JSValue on_match;
  JSValue on_complete;
  GumQuickMatchResult result;

  JSContext * ctx;
  GumQuickProcess * parent;
};

struct _GumQuickRunOnThreadContext
{
  JSValue user_func;
  GumQuickCore * core;
};

struct _GumQuickFindModuleByNameContext
{
  const gchar * name;
  gboolean name_is_canonical;
  JSValue result;

  JSContext * ctx;
  GumQuickModule * module;
};

struct _GumQuickFindRangeByAddressContext
{
  GumAddress address;
  JSValue result;

  JSContext * ctx;
  GumQuickCore * core;
};

static void gumjs_free_main_module_value (GumQuickProcess * self);
GUMJS_DECLARE_GETTER (gumjs_process_get_main_module)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_dir)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_home_dir)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_tmp_dir)
GUMJS_DECLARE_FUNCTION (gumjs_process_is_debugger_attached)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_thread_id)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_threads)
static gboolean gum_emit_thread (const GumThreadDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_run_on_thread)
static void gum_quick_run_on_thread_context_free (
    GumQuickRunOnThreadContext * rc);
static void gum_do_call_on_thread (const GumCpuContext * cpu_context,
    gpointer user_data);
static void gum_quick_process_maybe_start_stalker_gc_timer (
    GumQuickProcess * self, GumQuickScope * scope);
static gboolean gum_quick_process_on_stalker_gc_timer_tick (
    GumQuickProcess * self);
GUMJS_DECLARE_FUNCTION (gumjs_process_find_module_by_name)
static gboolean gum_store_module_if_name_matches (
    const GumModuleDetails * details, GumQuickFindModuleByNameContext * fc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_modules)
static gboolean gum_emit_module (const GumModuleDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_find_range_by_address)
static gboolean gum_store_range_if_containing_address (
    const GumRangeDetails * details, GumQuickFindRangeByAddressContext * fc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_system_ranges)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
GUMJS_DECLARE_FUNCTION (gumjs_process_set_exception_handler)

static GumQuickExceptionHandler * gum_quick_exception_handler_new (
    JSValue callback, GumQuickCore * core);
static void gum_quick_exception_handler_free (
    GumQuickExceptionHandler * handler);
static gboolean gum_quick_exception_handler_on_exception (
    GumExceptionDetails * details, GumQuickExceptionHandler * handler);

static const JSCFunctionListEntry gumjs_process_entries[] =
{
  JS_PROP_STRING_DEF ("arch", GUM_SCRIPT_ARCH, JS_PROP_C_W_E),
  JS_PROP_STRING_DEF ("platform", GUM_SCRIPT_PLATFORM, JS_PROP_C_W_E),
  JS_PROP_INT32_DEF ("pointerSize", GLIB_SIZEOF_VOID_P, JS_PROP_C_W_E),
  JS_CGETSET_DEF ("mainModule", gumjs_process_get_main_module, NULL),
  JS_CFUNC_DEF ("getCurrentDir", 0, gumjs_process_get_current_dir),
  JS_CFUNC_DEF ("getHomeDir", 0, gumjs_process_get_home_dir),
  JS_CFUNC_DEF ("getTmpDir", 0, gumjs_process_get_tmp_dir),
  JS_CFUNC_DEF ("isDebuggerAttached", 0, gumjs_process_is_debugger_attached),
  JS_CFUNC_DEF ("getCurrentThreadId", 0, gumjs_process_get_current_thread_id),
  JS_CFUNC_DEF ("_enumerateThreads", 0, gumjs_process_enumerate_threads),
  JS_CFUNC_DEF ("_runOnThread", 0, gumjs_process_run_on_thread),
  JS_CFUNC_DEF ("findModuleByName", 0, gumjs_process_find_module_by_name),
  JS_CFUNC_DEF ("_enumerateModules", 0, gumjs_process_enumerate_modules),
  JS_CFUNC_DEF ("findRangeByAddress", 0, gumjs_process_find_range_by_address),
  JS_CFUNC_DEF ("_enumerateRanges", 0, gumjs_process_enumerate_ranges),
  JS_CFUNC_DEF ("enumerateSystemRanges", 0,
      gumjs_process_enumerate_system_ranges),
  JS_CFUNC_DEF ("_enumerateMallocRanges", 0,
      gumjs_process_enumerate_malloc_ranges),
  JS_CFUNC_DEF ("setExceptionHandler", 0, gumjs_process_set_exception_handler),
};

void
_gum_quick_process_init (GumQuickProcess * self,
                         JSValue ns,
                         GumQuickModule * module,
                         GumQuickThread * thread,
                         GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue obj;

  self->module = module;
  self->thread = thread;
  self->core = core;

  self->main_module_value = JS_UNINITIALIZED;

  self->stalker = NULL;
  self->stalker_gc_timer = NULL;

  _gum_quick_core_store_module_data (core, "process", self);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_process_entries,
      G_N_ELEMENTS (gumjs_process_entries));
  JS_DefinePropertyValueStr (ctx, obj, "id",
      JS_NewInt32 (ctx, gum_process_get_id ()), JS_PROP_C_W_E);
  JS_DefinePropertyValueStr (ctx, obj, "pageSize",
      JS_NewInt32 (ctx, gum_query_page_size ()), JS_PROP_C_W_E);
  JS_DefinePropertyValueStr (ctx, obj, "codeSigningPolicy",
      JS_NewString (ctx, gum_code_signing_policy_to_string (
          gum_process_get_code_signing_policy ())),
      JS_PROP_C_W_E);
  JS_DefinePropertyValueStr (ctx, ns, "Process", obj, JS_PROP_C_W_E);
}

void
_gum_quick_process_flush (GumQuickProcess * self)
{
  g_clear_pointer (&self->exception_handler, gum_quick_exception_handler_free);
  gumjs_free_main_module_value (self);
}

void
_gum_quick_process_dispose (GumQuickProcess * self)
{
  g_assert (self->stalker_gc_timer == NULL);

  g_clear_pointer (&self->exception_handler, gum_quick_exception_handler_free);
  gumjs_free_main_module_value (self);
}

static void
gumjs_free_main_module_value (GumQuickProcess * self)
{
  if (JS_IsUninitialized (self->main_module_value))
    return;

  JS_FreeValue (self->core->ctx, self->main_module_value);
  self->main_module_value = JS_UNINITIALIZED;
}

void
_gum_quick_process_finalize (GumQuickProcess * self)
{
  g_clear_object (&self->stalker);
}

static GumQuickProcess *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "process");
}

GUMJS_DEFINE_GETTER (gumjs_process_get_main_module)
{
  GumQuickProcess * self;

  self = gumjs_get_parent_module (core);

  if (JS_IsUninitialized (self->main_module_value))
  {
    self->main_module_value = _gum_quick_module_new (ctx,
        gum_process_get_main_module (), self->module);
  }

  return JS_DupValue (ctx, self->main_module_value);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_dir)
{
  JSValue result;
  gchar * dir_opsys, * dir_utf8;

  dir_opsys = g_get_current_dir ();
  dir_utf8 = g_filename_display_name (dir_opsys);
  result = JS_NewString (ctx, dir_utf8);
  g_free (dir_utf8);
  g_free (dir_opsys);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_home_dir)
{
  JSValue result;
  gchar * dir;

  dir = g_filename_display_name (g_get_home_dir ());
  result = JS_NewString (ctx, dir);
  g_free (dir);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_tmp_dir)
{
  JSValue result;
  gchar * dir;

  dir = g_filename_display_name (g_get_tmp_dir ());
  result = JS_NewString (ctx, dir);
  g_free (dir);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_is_debugger_attached)
{
  return JS_NewBool (ctx, gum_process_is_debugger_attached ());
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_thread_id)
{
  return JS_NewInt64 (ctx, gum_process_get_current_thread_id ());
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_threads)
{
  GumQuickMatchContext mc;

  if (!_gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.parent = gumjs_get_parent_module (core);

  gum_process_enumerate_threads ((GumFoundThreadFunc) gum_emit_thread, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_thread (const GumThreadDetails * details,
                 GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  JSValue thread, result;

  thread = _gum_quick_thread_new (ctx, details, mc->parent->thread);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &thread);

  JS_FreeValue (ctx, thread);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_run_on_thread)
{
  GumQuickProcess * self;
  GumThreadId thread_id;
  JSValue user_func;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  GumQuickRunOnThreadContext * rc;
  gboolean success;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "ZF", &thread_id, &user_func))
    return JS_EXCEPTION;

  if (self->stalker == NULL)
    self->stalker = gum_stalker_new ();

  rc = g_slice_new (GumQuickRunOnThreadContext);
  rc->user_func = JS_DupValue (core->ctx, user_func);
  rc->core = core;

  _gum_quick_scope_suspend (&scope);

  success = gum_stalker_run_on_thread (self->stalker, thread_id,
      gum_do_call_on_thread, rc,
      (GDestroyNotify) gum_quick_run_on_thread_context_free);

  _gum_quick_scope_resume (&scope);

  gum_quick_process_maybe_start_stalker_gc_timer (self, &scope);

  if (!success)
    goto run_failed;

  return JS_UNDEFINED;

run_failed:
  {
    _gum_quick_throw_literal (ctx, "failed to run on thread");

    return JS_EXCEPTION;
  }
}

static void
gum_quick_run_on_thread_context_free (GumQuickRunOnThreadContext * rc)
{
  GumQuickCore * core = rc->core;
  GumQuickScope scope;

  _gum_quick_scope_enter (&scope, core);
  JS_FreeValue (core->ctx, rc->user_func);
  _gum_quick_scope_leave (&scope);

  g_slice_free (GumQuickRunOnThreadContext, rc);
}

static void
gum_do_call_on_thread (const GumCpuContext * cpu_context,
                       gpointer user_data)
{
  GumQuickRunOnThreadContext * rc = user_data;
  GumQuickScope scope;

  _gum_quick_scope_enter (&scope, rc->core);
  _gum_quick_scope_call (&scope, rc->user_func, JS_UNDEFINED, 0, NULL);
  _gum_quick_scope_leave (&scope);
}

static void
gum_quick_process_maybe_start_stalker_gc_timer (GumQuickProcess * self,
                                                GumQuickScope * scope)
{
  GumQuickCore * core = self->core;
  GSource * source;

  if (self->stalker_gc_timer != NULL)
    return;

  if (!gum_stalker_garbage_collect (self->stalker))
    return;

  source = g_timeout_source_new (10);
  g_source_set_callback (source,
      (GSourceFunc) gum_quick_process_on_stalker_gc_timer_tick, self, NULL);
  self->stalker_gc_timer = source;

  _gum_quick_core_pin (core);
  _gum_quick_scope_suspend (scope);

  g_source_attach (source,
      gum_script_scheduler_get_js_context (core->scheduler));
  g_source_unref (source);

  _gum_quick_scope_resume (scope);
}

static gboolean
gum_quick_process_on_stalker_gc_timer_tick (GumQuickProcess * self)
{
  gboolean pending_garbage;

  pending_garbage = gum_stalker_garbage_collect (self->stalker);
  if (!pending_garbage)
  {
    GumQuickCore * core = self->core;
    GumQuickScope scope;

    _gum_quick_scope_enter (&scope, core);

    _gum_quick_core_unpin (core);
    self->stalker_gc_timer = NULL;

    _gum_quick_scope_leave (&scope);
  }

  return pending_garbage ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_find_module_by_name)
{
  GumQuickFindModuleByNameContext fc;
  gchar * allocated_name = NULL;

  if (!_gum_quick_args_parse (args, "s", &fc.name))
    return JS_EXCEPTION;
  fc.name_is_canonical = g_path_is_absolute (fc.name);
  fc.result = JS_NULL;
  fc.ctx = ctx;
  fc.module = gumjs_get_parent_module (core)->module;

#ifdef HAVE_WINDOWS
  allocated_name = g_utf8_casefold (fc.name, -1);
  fc.name = allocated_name;
#endif

  gum_process_enumerate_modules (
      (GumFoundModuleFunc) gum_store_module_if_name_matches, &fc);

  g_free (allocated_name);

  return fc.result;
}

static gboolean
gum_store_module_if_name_matches (const GumModuleDetails * details,
                                  GumQuickFindModuleByNameContext * fc)
{
  gboolean proceed = TRUE;
  const gchar * key;
  gchar * allocated_key = NULL;

  key = fc->name_is_canonical ? details->path : details->name;

#ifdef HAVE_WINDOWS
  allocated_key = g_utf8_casefold (key, -1);
  key = allocated_key;
#endif

  if (strcmp (key, fc->name) == 0)
  {
    fc->result = _gum_quick_module_new (fc->ctx, details, fc->module);

    proceed = FALSE;
  }

  g_free (allocated_key);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_modules)
{
  GumQuickMatchContext mc;

  if (!_gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.parent = gumjs_get_parent_module (core);

  gum_process_enumerate_modules ((GumFoundModuleFunc) gum_emit_module, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  JSValue module, result;

  module = _gum_quick_module_new (ctx, details, mc->parent->module);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &module);

  JS_FreeValue (ctx, module);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_find_range_by_address)
{
  GumQuickFindRangeByAddressContext fc;
  gpointer ptr;

  if (!_gum_quick_args_parse (args, "p", &ptr))
    return JS_EXCEPTION;
  fc.address = GUM_ADDRESS (ptr);
  fc.result = JS_NULL;
  fc.ctx = ctx;
  fc.core = core;

  gum_process_enumerate_ranges (GUM_PAGE_NO_ACCESS,
      (GumFoundRangeFunc) gum_store_range_if_containing_address, &fc);

  return fc.result;
}

static gboolean
gum_store_range_if_containing_address (const GumRangeDetails * details,
                                       GumQuickFindRangeByAddressContext * fc)
{
  gboolean proceed = TRUE;

  if (GUM_MEMORY_RANGE_INCLUDES (details->range, fc->address))
  {
    fc->result = _gum_quick_range_details_new (fc->ctx, details, fc->core);

    proceed = FALSE;
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_ranges)
{
  GumQuickMatchContext mc;
  GumPageProtection prot;

  if (!_gum_quick_args_parse (args, "mF{onMatch,onComplete}", &prot,
      &mc.on_match, &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.parent = gumjs_get_parent_module (core);

  gum_process_enumerate_ranges (prot, (GumFoundRangeFunc) gum_emit_range, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  JSValue range, result;

  range = _gum_quick_range_details_new (ctx, details, mc->parent->core);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &range);

  JS_FreeValue (ctx, range);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_system_ranges)
{
  JSValue ranges = JS_NewObject (ctx);

#ifdef HAVE_DARWIN
  {
    GumMemoryRange dsc;

    if (gum_darwin_query_shared_cache_range (mach_task_self (), &dsc))
    {
      JS_DefinePropertyValueStr (ctx, ranges, "dyldSharedCache",
          _gum_quick_memory_range_new (ctx, &dsc, args->core),
          JS_PROP_C_W_E);
    }
  }
#endif

  return ranges;
}

#if defined (HAVE_WINDOWS) || defined (HAVE_DARWIN)

static gboolean gum_emit_malloc_range (const GumMallocRangeDetails * details,
    GumQuickMatchContext * mc);

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  GumQuickMatchContext mc;

  if (!_gum_quick_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.parent = gumjs_get_parent_module (core);

  gum_process_enumerate_malloc_ranges (
      (GumFoundMallocRangeFunc) gum_emit_malloc_range, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_malloc_range (const GumMallocRangeDetails * details,
                       GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->parent->core;
  JSValue range, result;

  range = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, range,
      GUM_QUICK_CORE_ATOM (core, base),
      _gum_quick_native_pointer_new (ctx,
          GSIZE_TO_POINTER (details->range->base_address), core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, range,
      GUM_QUICK_CORE_ATOM (core, size),
      JS_NewInt64 (ctx, details->range->size),
      JS_PROP_C_W_E);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &range);

  JS_FreeValue (ctx, range);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

#else

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  return _gum_quick_throw_literal (ctx,
      "not yet implemented for " GUM_SCRIPT_PLATFORM);
}

#endif

GUMJS_DEFINE_FUNCTION (gumjs_process_set_exception_handler)
{
  GumQuickProcess * self;
  JSValue callback;
  GumQuickExceptionHandler * new_handler, * old_handler;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "F?", &callback))
    return JS_EXCEPTION;

  new_handler = !JS_IsNull (callback)
      ? gum_quick_exception_handler_new (callback, self->core)
      : NULL;

  old_handler = self->exception_handler;
  self->exception_handler = new_handler;

  if (old_handler != NULL)
    gum_quick_exception_handler_free (old_handler);

  return JS_UNDEFINED;
}

static GumQuickExceptionHandler *
gum_quick_exception_handler_new (JSValue callback,
                                 GumQuickCore * core)
{
  GumQuickExceptionHandler * handler;

  handler = g_slice_new (GumQuickExceptionHandler);
  handler->callback = JS_DupValue (core->ctx, callback);
  handler->core = core;

  gum_exceptor_add (core->exceptor,
      (GumExceptionHandler) gum_quick_exception_handler_on_exception, handler);

  return handler;
}

static void
gum_quick_exception_handler_free (GumQuickExceptionHandler * handler)
{
  GumQuickCore * core = handler->core;

  gum_exceptor_remove (core->exceptor,
      (GumExceptionHandler) gum_quick_exception_handler_on_exception, handler);

  JS_FreeValue (core->ctx, handler->callback);

  g_slice_free (GumQuickExceptionHandler, handler);
}

static gboolean
gum_quick_exception_handler_on_exception (GumExceptionDetails * details,
                                          GumQuickExceptionHandler * handler)
{
  GumQuickCore * core = handler->core;
  JSContext * ctx = core->ctx;
  gboolean handled;
  GumQuickScope scope;
  JSValue d, r;
  GumQuickCpuContext * cpu_context;

  if (gum_quick_script_backend_is_scope_mutex_trapped (core->backend))
    return FALSE;

  _gum_quick_scope_enter (&scope, core);

  d = _gum_quick_exception_details_new (ctx, details, core, &cpu_context);

  r = _gum_quick_scope_call (&scope, handler->callback, JS_UNDEFINED, 1, &d);

  handled = JS_IsBool (r) && JS_VALUE_GET_BOOL (r);

  _gum_quick_cpu_context_make_read_only (cpu_context);

  JS_FreeValue (ctx, r);
  JS_FreeValue (ctx, d);

  _gum_quick_scope_leave (&scope);

  return handled;
}

"""

```