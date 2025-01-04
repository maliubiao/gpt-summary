Response:
Let's break down the thought process for analyzing this C code and generating the comprehensive explanation.

**1. Initial Skim and Overall Goal Identification:**

First, I quickly scanned the code, noting the header comments about Frida, the file name (`gumsymbolutil-darwin.c`), and key includes like `gumsymbolutil.h`, `gumdarwinsymbolicator.h`, and `mach-o/dyld.h`. This immediately suggests the code deals with symbol resolution on macOS (Darwin). The "gum" prefix hints at a utility library within Frida.

**2. Function-by-Function Analysis:**

Next, I examined each function individually. For each function, I asked myself:

* **What does it do?** (Based on its name, parameters, return type, and internal logic)
* **What are its dependencies?** (What other functions or data structures does it use?)
* **Is it conditional?** (Does `#ifndef GUM_DIET` affect its behavior?)

For instance, with `gum_symbol_details_from_address`, it's clear it takes an address and populates a `GumDebugSymbolDetails` struct. It calls `gum_try_obtain_symbolicator` and `gum_darwin_symbolicator_details_from_address`, pointing towards the use of a `GumDarwinSymbolicator` object for the core symbol lookup.

**3. Identifying Key Concepts and Data Structures:**

As I analyzed the functions, I started noting recurring patterns and important data structures:

* **`GumDarwinSymbolicator`:** This is clearly central to the symbol resolution process. I made a mental note to investigate its role.
* **`GumDebugSymbolDetails`:**  This struct likely holds the detailed symbol information retrieved.
* **`GArray`:** Used to store arrays of pointers, important for functions returning multiple matches.
* **`G_LOCK_DEFINE_STATIC` and `G_LOCK` / `G_UNLOCK`:** Indicates the presence of locking mechanisms, suggesting potential concurrency issues or the need to protect shared resources.
* **`_dyld_register_func_for_add_image` and `_dyld_register_func_for_remove_image`:** These functions are related to dynamic library loading and unloading events, indicating a mechanism for keeping the symbol cache consistent.
* **`GumInterceptor`:** Used for intercepting function calls, specifically related to dyld notifications in this case.
* **`GUM_DIET` macro:**  This is a preprocessor directive that significantly changes the functionality, suggesting different build configurations or feature sets.

**4. Connecting to Reverse Engineering:**

With a grasp of the core functionality, I started thinking about how this relates to reverse engineering:

* **Symbol resolution is fundamental:**  Reverse engineers rely heavily on function names and addresses to understand program behavior. This code directly facilitates that.
* **Dynamic analysis:** Frida is a dynamic instrumentation tool. The ability to find symbols at runtime is crucial for hooking functions and observing their execution.
* **Understanding library loading:**  The dyld integration is key for reverse engineering as it reveals how libraries are loaded and how symbols become available.

**5. Identifying Low-Level Details:**

The inclusion of `<mach-o/dyld.h>`, and conditional code using `capstone.h` and architecture-specific headers (`gumx86reader.h`, `gumarm64reader.h`) highlighted the low-level aspects:

* **Mach-O format:** The use of `mach_header` directly points to the Mach-O executable format on macOS.
* **Dynamic linking:**  The dyld functions are central to dynamic linking.
* **Instruction disassembly:** The `capstone` library integration suggests the code might need to inspect raw instructions in certain scenarios (likely related to detecting breakpoints set by debuggers).

**6. Inferring Logic and Potential Issues:**

Based on the structure and function names, I could infer the following:

* **Caching:** The `GumSymbolCacheInvalidator` and the locking mechanism strongly suggest a caching strategy for symbol information to improve performance.
* **Cache invalidation:**  The dyld notification handlers are designed to invalidate the cache when libraries are loaded or unloaded, ensuring the symbol information remains accurate.
* **Potential race conditions:** The locking mechanisms are there to prevent race conditions when multiple threads try to access or modify the symbol cache.

**7. Considering User Interaction and Debugging:**

I then considered how a user might end up triggering this code:

* **Basic Frida usage:**  Any Frida script that tries to resolve a symbol name or get details about an address will likely call functions in this file.
* **Advanced Frida features:**  Features that rely on intercepting library loading events would also involve this code.
* **Debugging scenarios:** When Frida interacts with a debugger, the `gum_symbol_cache_invalidator_on_dyld_debugger_notification` function is triggered.

**8. Structuring the Explanation:**

Finally, I organized the information into a logical flow, starting with the overall purpose and then diving into specifics:

* **Core Functionality:** List the primary tasks the code performs.
* **Relationship to Reverse Engineering:** Explain how each function or concept aids in reverse engineering.
* **Binary/Kernel/Framework Aspects:** Discuss the low-level interactions.
* **Logical Reasoning (Hypothetical Inputs/Outputs):** Provide concrete examples to illustrate function behavior.
* **Common Usage Errors:** Point out potential pitfalls for users.
* **User Operation and Debugging:** Explain how users might interact with this code indirectly.

**Self-Correction/Refinement During the Process:**

* **Initial confusion about `GUM_DIET`:** I initially wasn't sure what this meant. By observing how it conditionally includes or excludes large chunks of code, I realized it was likely a build option for a "lighter" or "stripped-down" version of Frida.
* **Connecting `capstone` to dyld notifications:**  It took a bit of thinking to connect the instruction disassembly with the debugger notifications. Realizing that the code was checking for breakpoint instructions (`INT3`, `BRK`) in the dyld notification handler made sense in the context of detecting debugger presence.

By following this systematic approach, I could break down the complex C code into understandable components and explain its significance within the context of Frida and reverse engineering.
这个 frida 源代码文件 `gumsymbolutil-darwin.c` 的主要功能是 **提供在 Darwin (macOS 和 iOS) 平台上进行符号解析和操作的能力**。它允许 Frida 运行时获取关于程序运行时加载的库和函数的各种信息，这对于动态 instrumentation 至关重要。

下面是该文件的功能列表以及与逆向、底层知识、逻辑推理和用户错误相关的举例说明：

**核心功能:**

1. **获取符号信息:**
   - `gum_symbol_details_from_address(gpointer address, GumDebugSymbolDetails * details)`:  根据给定的内存地址，填充 `GumDebugSymbolDetails` 结构体，包含符号的名称、所属的库、偏移量等详细信息。
   - `gum_symbol_name_from_address(gpointer address)`: 根据给定的内存地址，返回符号的名称。

2. **查找函数:**
   - `gum_find_function(const gchar * name)`:  根据函数名称查找函数的地址。
   - `gum_find_functions_named(const gchar * name)`:  查找所有具有给定名称的函数的地址（可能存在重载或多个库包含同名函数）。
   - `gum_find_functions_matching(const gchar * str)`:  查找函数名称匹配给定字符串的所有函数的地址（可以使用通配符或正则表达式，具体实现可能在 `gum_darwin_symbolicator` 中）。

3. **符号缓存管理 (非 GUM_DIET 编译):**
   - `GumSymbolCacheInvalidator`: 一个类，用于监听 Darwin 的动态链接器 (dyld) 事件，例如库的加载和卸载，并相应地更新符号缓存，以保持缓存的有效性。
   - 通过 `_dyld_register_func_for_add_image` 和 `_dyld_register_func_for_remove_image` 注册回调函数，以便在库加载和卸载时得到通知。
   - 通过拦截 dyld 的调试器通知 (在启用调试器的情况下)，来清除符号缓存。

4. **内部辅助函数:**
   - `gum_try_obtain_symbolicator()`:  获取或创建 `GumDarwinSymbolicator` 对象的单例实例，这是实际执行符号解析的类。
   - `gum_pointer_array_new_empty()` 和 `gum_pointer_array_new_take_addresses()`: 用于创建和管理存储地址的 `GArray` 对象。

**与逆向方法的关系及举例说明:**

* **动态符号解析:**  逆向工程师经常需要在运行时确定某个内存地址对应的函数或变量。`gum_symbol_name_from_address` 和 `gum_symbol_details_from_address` 提供了这种能力。
    * **例子:** 假设你正在逆向一个 Objective-C 应用，你想知道当点击某个按钮时调用的方法是什么。你可以通过 Frida hook 按钮的 action 方法，获取方法执行时的返回地址 (RA)，然后使用 `gum_symbol_name_from_address(RA)` 来获取方法名。

* **查找和 Hook 函数:**  在 Frida 中进行 Hook 操作，首先需要找到目标函数的地址。`gum_find_function` 和 `gum_find_functions_named` 可以帮助实现这一点。
    * **例子:** 你想 hook `NSString` 的 `stringWithString:` 方法。你可以使用 `gum_find_function("-[NSString stringWithString:]")` 来获取该方法的地址，然后在该地址设置 hook。

* **理解库加载和符号变化:** `GumSymbolCacheInvalidator` 的机制帮助 Frida 在库动态加载和卸载时保持符号信息的准确性。这对于逆向动态加载的插件或模块非常重要。
    * **例子:** 某些恶意软件可能会在运行时动态加载额外的代码。Frida 可以通过监听 dyld 事件，及时更新符号信息，从而能够 hook 到动态加载的代码中的函数。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **Mach-O 文件格式 (二进制底层):**  该文件使用了 `<mach-o/dyld.h>` 头文件，这表明它直接与 macOS 和 iOS 的可执行文件格式 Mach-O 打交道。dyld 是 Darwin 系统的动态链接器，负责加载 Mach-O 文件。
    * **例子:** `gum_symbol_cache_invalidator_on_dyld_runtime_notification` 函数接收 `mach_header` 结构体指针，这是 Mach-O 文件的头部，包含了关于该二进制文件的元数据信息。

* **动态链接 (二进制底层):**  通过与 dyld 交互，该文件深入了解了动态链接的过程，即程序在运行时如何加载和链接共享库。
    * **例子:** `_dyld_register_func_for_add_image` 和 `_dyld_register_func_for_remove_image` 是 dyld 提供的 API，用于注册在新的共享库被加载或卸载时调用的回调函数。

* **指令集架构 (二进制底层 - 非 GUM_DIET 编译):**  在非 `GUM_DIET` 编译下，代码包含对指令进行反汇编的逻辑 (使用 `capstone.h`)，针对 x86 和 ARM64 架构。这用于检测 dyld 通知机制中可能存在的断点指令。
    * **例子:**  代码检查 dyld 通知地址的开头指令是否是断点指令 (`INT3` for x86, `BRK` for ARM64)。这是一种优化手段，可能与处理调试器附加的情况有关。

* **进程和内存管理 (操作系统):**  `gum_try_obtain_symbolicator` 使用 `mach_task_self()` 获取当前任务的端口，这涉及到 macOS 的进程和任务管理。符号解析需要在目标进程的内存空间中进行。

* **虽然主要针对 Darwin，但设计思想可以应用于其他平台:**  虽然这个文件是 Darwin 特定的，但符号解析是动态 instrumentation 的通用需求。在 Linux 上，Frida 会使用类似的方法与 ELF 文件格式和 Linux 的动态链接器进行交互。在 Android 上，则会与 ELF 文件格式和 Android 的 linker 进行交互。Android 的框架层面，例如 ART 虚拟机，也有自己的符号管理机制。

**逻辑推理、假设输入与输出:**

假设我们有以下场景：

* **输入:**  一个正在运行的 macOS 进程，加载了 `libSystem.dylib` 库。
* **调用:**  `gum_find_function("strcmp")`

**逻辑推理过程:**

1. `gum_find_function` 被调用，传递函数名 "strcmp"。
2. `gum_try_obtain_symbolicator` 被调用，获取 `GumDarwinSymbolicator` 的实例。
3. `gum_darwin_symbolicator_find_function` 被调用，在已加载的库中查找名为 "strcmp" 的符号。
4. `GumDarwinSymbolicator` 内部会遍历已加载的 Mach-O 文件 (包括 `libSystem.dylib`) 的符号表。
5. 如果在 `libSystem.dylib` 的符号表中找到了 "strcmp"，则返回其地址。

**可能的输出:**

* **成功:**  返回 `strcmp` 函数在内存中的地址 (例如 `0x7ff809876543`).
* **失败:**  如果 `strcmp` 函数没有被加载 (不太可能，因为 `libSystem.dylib` 是系统库)，则返回 `NULL`.

**涉及用户或者编程常见的使用错误及举例说明:**

* **在 `GUM_DIET` 编译模式下使用符号缓存相关功能:**  如果在编译 Frida 时定义了 `GUM_DIET` 宏，那么符号缓存管理的功能将被禁用。用户可能会错误地期望符号缓存能够自动更新，但实际上它并没有运行。
    * **例子:** 用户编写了一个 Frida 脚本，依赖于动态加载的库的符号解析，但在 `GUM_DIET` 模式下运行，可能会遇到找不到符号的情况。

* **传递错误的函数名:**  `gum_find_function` 等函数依赖于准确的函数名。如果传递了错误的名称 (例如拼写错误、缺少命名空间或参数信息)，将无法找到函数。
    * **例子:** 用户尝试使用 `gum_find_function("strcmp")` 查找 C++ 的 `std::strcmp`，但需要使用带有命名空间的名称，如 `gum_find_function("_ZNSt3strcmpEPKcS1_")` (名称 mangling 后的形式)。

* **在符号未加载前尝试查找:**  如果在一个库尚未加载到内存中时尝试查找该库的符号，将会失败。
    * **例子:** 用户尝试在程序启动的早期阶段 hook 一个动态加载的插件中的函数，但该插件尚未被加载。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户启动 Frida 脚本或使用 Frida REPL:** 用户通过命令行运行 `frida -p <pid>` 或启动 Frida REPL 并 attach 到一个进程。

2. **Frida Agent 加载到目标进程:** Frida 的 agent (通常是一个动态链接库) 会被加载到目标进程的内存空间中。

3. **用户在 Frida 脚本中调用符号相关的 API:**  用户在 JavaScript 或 Python 编写的 Frida 脚本中调用了 `Module.findExportByName()`, `Module.getExportByName()`, `DebugSymbol.fromAddress()` 等 API。

4. **Frida Agent 将请求转发到 `gumsymbolutil-darwin.c`:** 当 Frida 的 JavaScript 引擎需要解析符号时，它会调用 Frida agent 内部的 C/C++ 代码。对于 Darwin 平台，这些请求最终会路由到 `gumsymbolutil-darwin.c` 中相应的函数。

5. **例如，调用 `Module.findExportByName("strcmp")`:**
   - JavaScript 代码调用 `Module.findExportByName("strcmp")`.
   - Frida agent 接收到请求，并确定需要在目标进程中查找符号。
   - Frida agent 内部调用 `gum_find_function("strcmp")` (或其他类似的函数)。
   - 这就直接进入了 `gumsymbolutil-darwin.c` 文件中的 `gum_find_function` 函数执行。

6. **调试线索:** 如果用户在使用 Frida 时遇到符号解析的问题 (例如找不到符号)，他们可以检查以下内容，这些都与 `gumsymbolutil-darwin.c` 的功能相关：
   - **目标库是否已加载？** (与 dyld 通知和符号缓存有关)
   - **函数名是否正确？**
   - **是否在 `GUM_DIET` 模式下运行？**
   - **是否存在符号剥离？** (虽然 `gumsymbolutil-darwin.c` 主要处理已加载的符号，但符号是否被剥离会影响可用的符号信息)

总而言之，`gumsymbolutil-darwin.c` 是 Frida 在 Darwin 平台上进行动态 instrumentation 的一个关键组成部分，它提供了基础的符号解析能力，使得 Frida 能够理解和操作目标进程的运行时结构。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gumsymbolutil-darwin.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Matt Oh <oh.jeongwook@gmail.com>
 * Copyright (C) 2024 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumsymbolutil.h"

#include "gum-init.h"
#include "gum/gumdarwinsymbolicator.h"

#include <mach-o/dyld.h>

#ifndef GUM_DIET

# include <capstone.h>
# if defined (HAVE_I386)
#  include "gumx86reader.h"
# elif defined (HAVE_ARM64)
#  include "gumarm64reader.h"
# endif

# define GUM_TYPE_SYMBOL_CACHE_INVALIDATOR \
    (gum_symbol_cache_invalidator_get_type ())
GUM_DECLARE_FINAL_TYPE (GumSymbolCacheInvalidator,
                        gum_symbol_cache_invalidator,
                        GUM, SYMBOL_CACHE_INVALIDATOR,
                        GObject)

struct _GumSymbolCacheInvalidator
{
  GObject parent;

  GumInterceptor * interceptor;
};

static void do_deinit (void);
#endif

static GArray * gum_pointer_array_new_empty (void);
static GArray * gum_pointer_array_new_take_addresses (GumAddress * addresses,
    gsize len);

#ifndef GUM_DIET
static void gum_symbol_cache_invalidator_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_symbol_cache_invalidator_dispose (GObject * object);
static void gum_symbol_cache_invalidator_stop (
    GumSymbolCacheInvalidator * self);
static void gum_symbol_cache_invalidator_on_dyld_debugger_notification (
    GumInvocationListener * self, GumInvocationContext * context);
static void gum_symbol_cache_invalidator_on_dyld_runtime_notification (
    const struct mach_header * mh, intptr_t vmaddr_slide);
static void gum_clear_symbolicator_object (void);

G_LOCK_DEFINE_STATIC (symbolicator);
static GumDarwinSymbolicator * symbolicator = NULL;
static GumSymbolCacheInvalidator * invalidator = NULL;
static gboolean invalidator_initialized = FALSE;

G_DEFINE_TYPE_EXTENDED (GumSymbolCacheInvalidator,
                        gum_symbol_cache_invalidator,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_symbol_cache_invalidator_iface_init))
#endif

static GumDarwinSymbolicator *
gum_try_obtain_symbolicator (void)
{
  GumDarwinSymbolicator * result = NULL;

#ifndef GUM_DIET
  G_LOCK (symbolicator);

  if (symbolicator == NULL)
  {
    symbolicator =
        gum_darwin_symbolicator_new_with_task (mach_task_self (), NULL);
  }

  if (invalidator == NULL)
  {
    invalidator = g_object_new (GUM_TYPE_SYMBOL_CACHE_INVALIDATOR, NULL);

    _gum_register_early_destructor (do_deinit);
  }

  if (symbolicator != NULL)
    result = g_object_ref (symbolicator);

  G_UNLOCK (symbolicator);

  invalidator_initialized = TRUE;
#endif

  return result;
}

#ifndef GUM_DIET

static void
do_deinit (void)
{
  G_LOCK (symbolicator);

  g_clear_object (&symbolicator);

  gum_symbol_cache_invalidator_stop (invalidator);
  g_clear_object (&invalidator);

  invalidator_initialized = FALSE;

  G_UNLOCK (symbolicator);
}

#endif

gboolean
gum_symbol_details_from_address (gpointer address,
                                 GumDebugSymbolDetails * details)
{
  gboolean success;
  GumDarwinSymbolicator * symbolicator;

  if ((symbolicator = gum_try_obtain_symbolicator ()) == NULL)
    return FALSE;

  success = gum_darwin_symbolicator_details_from_address (symbolicator,
      GUM_ADDRESS (address), details);

  gum_object_unref (symbolicator);

  return success;
}

gchar *
gum_symbol_name_from_address (gpointer address)
{
  gchar * name;
  GumDarwinSymbolicator * symbolicator;

  if ((symbolicator = gum_try_obtain_symbolicator ()) == NULL)
    return NULL;

  name = gum_darwin_symbolicator_name_from_address (symbolicator,
      GUM_ADDRESS (address));

  gum_object_unref (symbolicator);

  return name;
}

gpointer
gum_find_function (const gchar * name)
{
  gpointer address;
  GumDarwinSymbolicator * symbolicator;

  if ((symbolicator = gum_try_obtain_symbolicator ()) == NULL)
    return NULL;

  address = GSIZE_TO_POINTER (
      gum_darwin_symbolicator_find_function (symbolicator, name));

  gum_object_unref (symbolicator);

  return address;
}

GArray *
gum_find_functions_named (const gchar * name)
{
  GumDarwinSymbolicator * symbolicator;
  GumAddress * addresses;
  gsize len;

  if ((symbolicator = gum_try_obtain_symbolicator ()) == NULL)
    return gum_pointer_array_new_empty ();

  addresses =
      gum_darwin_symbolicator_find_functions_named (symbolicator, name, &len);

  gum_object_unref (symbolicator);

  return gum_pointer_array_new_take_addresses (addresses, len);
}

GArray *
gum_find_functions_matching (const gchar * str)
{
  GumDarwinSymbolicator * symbolicator;
  GumAddress * addresses;
  gsize len;

  if ((symbolicator = gum_try_obtain_symbolicator ()) == NULL)
    return gum_pointer_array_new_empty ();

  addresses =
      gum_darwin_symbolicator_find_functions_matching (symbolicator, str, &len);

  gum_object_unref (symbolicator);

  return gum_pointer_array_new_take_addresses (addresses, len);
}

gboolean
gum_load_symbols (const gchar * path)
{
  return FALSE;
}

static GArray *
gum_pointer_array_new_empty (void)
{
  return g_array_new (FALSE, FALSE, sizeof (gpointer));
}

static GArray *
gum_pointer_array_new_take_addresses (GumAddress * addresses,
                                      gsize len)
{
  GArray * result;
  gsize i;

  result = g_array_sized_new (FALSE, FALSE, sizeof (gpointer), len);

  for (i = 0; i != len; i++)
  {
    gpointer address = GSIZE_TO_POINTER (addresses[i]);
    g_array_append_val (result, address);
  }

  g_free (addresses);

  return result;
}

#ifndef GUM_DIET

static void
gum_symbol_cache_invalidator_class_init (GumSymbolCacheInvalidatorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_symbol_cache_invalidator_dispose;

  (void) GUM_IS_SYMBOL_CACHE_INVALIDATOR;
  (void) GUM_SYMBOL_CACHE_INVALIDATOR;
  (void) glib_autoptr_cleanup_GumSymbolCacheInvalidator;
}

static void
gum_symbol_cache_invalidator_iface_init (gpointer g_iface,
                                         gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_symbol_cache_invalidator_on_dyld_debugger_notification;
}

static void
gum_symbol_cache_invalidator_init (GumSymbolCacheInvalidator * self)
{
  static gsize registered = FALSE;

  if (gum_process_get_teardown_requirement () == GUM_TEARDOWN_REQUIREMENT_FULL)
  {
    GumDarwinAllImageInfos infos;
    G_GNUC_UNUSED gconstpointer notification_impl;
    G_GNUC_UNUSED cs_insn * first_instruction;
    gsize offset = 0;

    if (!gum_darwin_query_all_image_infos (mach_task_self (), &infos))
      return;

    notification_impl = GSIZE_TO_POINTER (
        gum_strip_code_address (infos.notification_address));

#if defined (HAVE_I386)
    first_instruction =
        gum_x86_reader_disassemble_instruction_at (notification_impl);
    if (first_instruction != NULL && first_instruction->id == X86_INS_INT3)
      offset = first_instruction->size;
#elif defined (HAVE_ARM64)
    first_instruction =
        gum_arm64_reader_disassemble_instruction_at (notification_impl);
    if (first_instruction != NULL && first_instruction->id == ARM64_INS_BRK)
      offset = first_instruction->size;
#endif

    self->interceptor = gum_interceptor_obtain ();

    gum_interceptor_attach (self->interceptor,
        (gpointer) (notification_impl + offset),
        GUM_INVOCATION_LISTENER (self), NULL);
  }
  else if (g_once_init_enter (&registered))
  {
    _dyld_register_func_for_add_image (
        gum_symbol_cache_invalidator_on_dyld_runtime_notification);
    _dyld_register_func_for_remove_image (
        gum_symbol_cache_invalidator_on_dyld_runtime_notification);

    g_once_init_leave (&registered, TRUE);
  }
}

static void
gum_symbol_cache_invalidator_dispose (GObject * object)
{
  GumSymbolCacheInvalidator * self = GUM_SYMBOL_CACHE_INVALIDATOR (object);

  g_clear_object (&self->interceptor);

  G_OBJECT_CLASS (gum_symbol_cache_invalidator_parent_class)->dispose (object);
}

static void
gum_symbol_cache_invalidator_stop (GumSymbolCacheInvalidator * self)
{
  gum_interceptor_detach (self->interceptor, GUM_INVOCATION_LISTENER (self));
}

static void
gum_symbol_cache_invalidator_on_dyld_debugger_notification (
    GumInvocationListener * self,
    GumInvocationContext * context)
{
  gum_clear_symbolicator_object ();
}

static void
gum_symbol_cache_invalidator_on_dyld_runtime_notification (
    const struct mach_header * mh,
    intptr_t vmaddr_slide)
{
  if (!invalidator_initialized)
    return;

  gum_clear_symbolicator_object ();
}

static void
gum_clear_symbolicator_object (void)
{
  G_LOCK (symbolicator);

  g_clear_object (&symbolicator);

  G_UNLOCK (symbolicator);
}

#endif

"""

```