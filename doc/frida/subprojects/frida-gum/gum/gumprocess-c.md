Response:
Let's break down the thought process for analyzing this C source code and generating the detailed explanation.

**1. Understanding the Goal:**

The primary goal is to analyze the provided `gumprocess.c` file, which is part of Frida, and explain its functionality in several key areas: its core purpose, its relationship to reverse engineering, its use of low-level concepts, any logical deductions it makes, potential user errors, and how a user might end up interacting with this code.

**2. Initial Code Scan and High-Level Overview:**

The first step is a quick read-through of the code, paying attention to:

* **Includes:**  `gumprocess-priv.h`, `gum-init.h`, `gumcloak.h`. These hint at private data structures, initialization routines, and some form of "cloaking" or hiding mechanism.
* **Data Structures:**  `GumEmitThreadsContext`, `GumResolveModulePointerContext`, etc. These suggest the file is involved in iterating and gathering information about threads, modules, and memory ranges. The `func` members within these structures indicate callback functions are a core part of the design.
* **Function Declarations:**  Names like `gum_process_enumerate_threads`, `gum_process_get_main_module`, `gum_process_resolve_module_pointer` immediately suggest process-level introspection capabilities.
* **Conditional Compilation:** The `#if defined (HAVE_WINDOWS)`, etc., block reveals platform-specific handling.
* **Static Variables:** `gum_teardown_requirement`, `gum_code_signing_policy` indicate configurable behaviors.
* **Helper Functions:**  Functions like `gum_emit_thread_if_not_cloaked` and `gum_try_resolve_module_pointer_from` suggest filtering or specific logic applied during enumeration.

**3. Deeper Dive into Key Functionality Areas:**

After the initial scan, the next step is to analyze the major functions and their interactions:

* **Thread Enumeration (`gum_process_enumerate_threads`):** The code iterates through threads and calls a provided callback function (`GumFoundThreadFunc`). The `gum_emit_thread_if_not_cloaked` function introduces the "cloaking" concept, indicating Frida might be able to hide threads from introspection.
* **Module Handling (`gum_process_get_main_module`, `gum_process_resolve_module_pointer`, `gum_process_enumerate_modules`):** These functions deal with obtaining information about loaded modules. The `resolve_module_pointer` function is crucial for understanding where a given memory address belongs. The "cloaking" mechanism also applies to modules.
* **Memory Range Enumeration (`gum_process_enumerate_ranges`):** This function allows iterating through memory regions with specific protection attributes. The `gum_emit_range_if_not_cloaked` function demonstrates how the "cloaking" mechanism can split memory ranges, providing a more granular level of hiding.
* **Symbol Resolution (`gum_module_find_symbol_by_name`):** This function allows looking up the address of a specific symbol within a module.
* **Code Signing (`gum_process_get_code_signing_policy`, `gum_process_set_code_signing_policy`):** This indicates Frida's awareness of code signing and the ability to potentially interact with it.

**4. Connecting to Reverse Engineering:**

With a solid understanding of the functions, the next step is to explicitly link them to common reverse engineering tasks:

* **Inspecting Process State:** Enumerating threads and modules is fundamental for understanding the structure and components of a running process.
* **Finding Code and Data:** Resolving module pointers and enumerating memory ranges helps locate specific code segments or data structures.
* **Analyzing Function Calls:** Finding symbols by name is crucial for identifying and potentially hooking functions.
* **Understanding Memory Layout:** Enumerating ranges provides insights into how memory is organized.
* **Circumventing Anti-Debugging:** The "cloaking" mechanism is directly related to hiding Frida's presence from the target process.

**5. Identifying Low-Level Concepts:**

This involves recognizing the underlying operating system and architecture concepts:

* **Process and Threads:** The core abstractions of modern operating systems.
* **Modules (DLLs/SOs):**  Dynamically loaded libraries.
* **Memory Management:** Virtual memory, page protection flags (read, write, execute).
* **System Calls (Implicit):** Although not explicitly shown in this snippet, the functions rely on underlying OS system calls to obtain process information.
* **ELF/Mach-O:** The mention of specific symbol types indicates knowledge of executable formats.
* **Kernel Interaction (Implicit):**  Accessing process information often requires interaction with the kernel.

**6. Considering Logical Inferences and User Errors:**

* **Logical Inferences:** The `gum_emit_*_if_not_cloaked` functions demonstrate a clear logical filtering based on the "cloaking" state. The `gum_try_resolve_module_pointer_from` function stops iterating once a match is found.
* **User Errors:** Common mistakes include providing incorrect module or symbol names, forgetting to allocate memory for output parameters, and misunderstanding how the "cloaking" mechanism affects results.

**7. Tracing User Interaction:**

This requires thinking about how a typical Frida user would interact with the API:

* **Scripting Language (JavaScript/Python):**  Frida is primarily controlled through scripting languages.
* **Frida API Calls:**  Users would call functions like `enumerateModules()`, `getModuleByName()`, `findExportByName()`, etc., which are high-level wrappers around the C code being analyzed.
* **Debugging Scenarios:**  Users might use these functions to inspect a running application during debugging or reverse engineering.

**8. Structuring the Explanation:**

Finally, the information gathered needs to be organized logically. Using headings, bullet points, and code examples (even conceptual ones) greatly improves clarity. The specific structure requested in the prompt (functionality, reverse engineering relation, low-level concepts, logic, errors, user steps) provides a good framework.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the "cloaking" is purely for Frida's internal use.
* **Correction:**  The description of `gum_emit_*_if_not_cloaked` makes it clear this is a feature to *hide* information from introspection, directly relevant to anti-debugging.
* **Initial thought:** Focus only on the direct function calls.
* **Refinement:**  Realize that even though system calls aren't explicitly in the code, the functions fundamentally rely on them, making it a relevant low-level concept.
* **Initial thought:**  Provide very technical, low-level C examples for user errors.
* **Refinement:** Frame user errors in terms of how they would interact with the *Frida API*, as that's the primary user interface.

By following these steps, iteratively exploring the code, and connecting it to the broader context of Frida and reverse engineering, a comprehensive and accurate explanation can be generated.好的，让我们来详细分析一下 `frida/subprojects/frida-gum/gum/gumprocess.c` 这个文件的功能。

**文件功能概述:**

`gumprocess.c` 文件是 Frida (一个动态代码插桩工具) 的 Gum 库中负责处理**目标进程信息**的核心组件。它提供了一系列函数，用于**枚举、查询和操作目标进程的各种属性**，例如线程、模块（动态链接库/共享对象）、内存区域以及符号等。

**核心功能点:**

1. **枚举和访问进程线程:**
   - `gum_process_enumerate_threads()`:  遍历目标进程中的所有线程，并对每个线程调用用户提供的回调函数 (`GumFoundThreadFunc`)，传递线程的详细信息 (`GumThreadDetails`)。
   - `gum_process_modify_thread()`:  （虽然代码中只有声明，但功能是）暂停指定的线程，允许修改其状态（例如寄存器），然后再恢复执行。这对于在特定线程上下文中进行分析和修改非常有用。
   - `gum_emit_thread_if_not_cloaked()`:  在枚举线程时，检查线程是否被 Frida 的 "cloak" 机制隐藏，如果未隐藏，则调用用户提供的回调函数。

2. **枚举和访问进程模块 (动态链接库/共享对象):**
   - `gum_process_enumerate_modules()`: 遍历目标进程中加载的所有模块，并对每个模块调用用户提供的回调函数 (`GumFoundModuleFunc`)，传递模块的详细信息 (`GumModuleDetails`)，包括模块的名称、加载地址范围和路径。
   - `gum_process_get_main_module()`: 获取目标进程主执行模块的详细信息。
   - `gum_process_resolve_module_pointer()`:  给定一个内存地址，判断该地址属于哪个模块。
   - `gum_emit_module_if_not_cloaked()`:  在枚举模块时，检查模块的加载地址是否被 Frida 的 "cloak" 机制隐藏。

3. **枚举和访问进程内存区域:**
   - `gum_process_enumerate_ranges()`: 遍历目标进程的内存区域，可以指定最小的保护属性（例如只读、读写、可执行），并对符合条件的内存区域调用用户提供的回调函数 (`GumFoundRangeFunc`)，传递内存区域的详细信息 (`GumRangeDetails`)，包括起始地址、大小、保护属性和关联的文件（如果有）。
   - `gum_emit_range_if_not_cloaked()`:  在枚举内存区域时，处理 Frida 的 "cloak" 机制。如果一个内存区域部分被隐藏，则会将未隐藏的部分拆分成子区域分别报告。

4. **枚举和访问模块的导入、导出和符号:**
   - `gum_module_enumerate_imports()`:  枚举指定模块的导入符号。
   - `gum_module_enumerate_exports()`:  枚举指定模块的导出符号。
   - `gum_module_enumerate_symbols()`:  枚举指定模块的所有符号。
   - `gum_module_find_symbol_by_name()`:  在指定模块中查找指定名称的符号，并返回其地址。
   - `gum_store_address_if_name_matches()`:  在枚举符号时，如果符号名称匹配，则保存其地址。

5. **获取和设置进程属性:**
   - `gum_process_get_native_os()`: 获取目标进程运行的操作系统。
   - `gum_process_get_teardown_requirement()` / `gum_process_set_teardown_requirement()`: 获取和设置 Frida 在与目标进程断开连接时的清理要求。
   - `gum_process_get_code_signing_policy()` / `gum_process_set_code_signing_policy()`: 获取和设置 Frida 对代码签名的策略。

6. **Frida 的 "Cloak" 机制集成:**
   - 该文件大量使用了 `gum_cloak_*` 函数，这表明 Frida 有一种隐藏自身或特定内存区域/线程不被枚举到的机制，用于对抗某些反调试技术。

**与逆向方法的关系及举例说明:**

这个文件提供的功能是逆向工程中**最基础和最重要的环节之一：信息收集**。逆向工程师需要了解目标进程的结构、加载的模块、内存布局、执行流程等，才能进行后续的分析和修改。

**举例说明:**

* **查找关键函数地址:** 逆向工程师可以使用 `gum_process_enumerate_modules()` 找到目标模块，然后使用 `gum_module_find_symbol_by_name()` 找到特定函数（例如加密函数、认证函数）的地址，以便进行 Hook 操作。
    ```c
    // 假设用户通过 Frida 的 API 获取到模块名 "target_module" 和函数名 "important_function"
    const gchar *module_name = "target_module";
    const gchar *symbol_name = "important_function";
    GumAddress function_address = gum_module_find_symbol_by_name(module_name, symbol_name);
    if (function_address != 0) {
        g_print("Found function %s at address: %p\n", symbol_name, (void*)function_address);
        // 接下来就可以使用 function_address 进行 Hook 操作
    } else {
        g_print("Function %s not found in module %s\n", symbol_name, module_name);
    }
    ```

* **枚举内存区域以查找数据:** 逆向工程师可以使用 `gum_process_enumerate_ranges()` 配合合适的保护属性（例如只读数据段），来查找存储敏感信息（例如密钥、配置）的内存区域。

* **分析线程执行流程:**  通过 `gum_process_enumerate_threads()` 获取线程 ID，然后可能结合其他 Frida 功能（例如 Stalker）跟踪特定线程的执行流程。

* **绕过反调试:** Frida 的 "cloak" 机制本身就是为了对抗反调试技术。这个文件中的 `gum_emit_*_if_not_cloaked()` 系列函数体现了这种对抗。逆向工程师可以使用 Frida 的配置来启用或调整 cloak 策略，以避免被目标进程的反调试机制检测到。

**涉及到的二进制底层、Linux/Android 内核及框架的知识及举例说明:**

这个文件是 Frida Gum 库的一部分，Gum 库是 Frida 的底层组件，直接与目标进程的操作系统进行交互。因此，它涉及到大量的底层知识：

* **进程和线程:**  这是操作系统提供的基本抽象。Frida 需要使用操作系统提供的 API (例如 Linux 的 `gettid()`, `pthread_t`, `/proc/[pid]/task/`, Windows 的 `GetCurrentThreadId()`, `HANDLE`) 来枚举和管理线程。
* **模块加载和动态链接:** 涉及到操作系统加载和管理动态链接库/共享对象的方式，例如 Linux 的 `dlopen`, `dlsym`, `/proc/[pid]/maps`，Windows 的 `LoadLibrary`, `GetProcAddress`, `GetModuleHandle`, `EnumProcessModules`。
* **内存管理:**  涉及到虚拟内存、内存页、内存保护属性（例如读、写、执行），操作系统提供的内存管理 API (例如 Linux 的 `mmap`, `mprotect`, `/proc/[pid]/maps`)。
* **符号表:**  涉及到可执行文件格式（例如 ELF, Mach-O, PE）中的符号表结构，用于存储函数和变量的名称和地址信息。Frida 需要解析这些符号表来提供 `gum_module_find_symbol_by_name()` 等功能。
* **Linux `/proc` 文件系统:**  在 Linux 系统上，Frida 可能会使用 `/proc/[pid]/maps` 来获取进程的内存映射信息，使用 `/proc/[pid]/task/` 来获取线程信息。
* **Android 内核和框架:** 在 Android 系统上，Frida 需要与 Android 的 Bionic Libc 和 ART (Android Runtime) 进行交互，获取模块加载、内存分配等信息。例如，枚举 ART 虚拟机加载的 dex 文件可以被视为枚举模块的一种形式。

**举例说明:**

* **枚举 Linux 进程的内存映射:**  `gum_process_enumerate_ranges()` 的底层实现很可能在 Linux 上会读取 `/proc/[pid]/maps` 文件，解析每一行的信息（起始地址、结束地址、权限、偏移量、设备、inode、路径名），并将其转换为 `GumRangeDetails` 结构体。

* **查找 Android 模块的符号:**  在 Android 上，Frida 可能需要解析 ELF 文件格式的动态链接库（`.so` 文件）中的符号表（例如 `.dynsym`, `.symtab` 段），才能找到函数的地址。

**逻辑推理、假设输入与输出:**

该文件中的逻辑推理主要体现在对操作系统 API 返回数据的处理和转换上，以及 Frida "cloak" 机制的实现。

**假设输入与输出举例:**

* **函数:** `gum_process_resolve_module_pointer(ptr, path, range)`
    * **假设输入:**
        * `ptr`:  一个指向目标进程中某个内存地址的指针，例如 `0x7fff80001000`。
    * **逻辑推理:** 函数会遍历目标进程加载的所有模块的内存范围，检查 `ptr` 是否落在其中某个模块的范围内。
    * **假设输出:**
        * 如果 `ptr` 属于模块 `/usr/lib/libSystem.B.dylib`，并且该模块的加载范围是 `0x7fff80000000 - 0x7fff80100000`，则：
            * `success` 为 `TRUE`。
            * `path` 指向的字符串为 `/usr/lib/libSystem.B.dylib`。
            * `range` 结构体包含的范围为 `0x7fff80000000` 到 `0x7fff80100000`。
        * 如果 `ptr` 不属于任何已加载的模块，则 `success` 为 `FALSE`， `path` 和 `range` 的值未定义或保持初始状态。

* **函数:** `gum_emit_range_if_not_cloaked(details, user_data)`
    * **假设输入:**
        * `details`: 一个 `GumRangeDetails` 结构体，描述了一个内存区域，例如起始地址 `0x1000`, 大小 `0x2000`。
    * **逻辑推理:** 函数会调用 Frida 的 `gum_cloak_clip_range()` 函数，检查该内存区域是否被 cloak 机制部分或全部隐藏。
    * **假设输出:**
        * 如果该区域未被隐藏，则用户提供的回调函数 `ctx->func` 会被调用一次，参数为原始的 `details`。
        * 如果该区域的中间一部分 (例如 `0x1800 - 0x1C00`) 被隐藏，则 `gum_cloak_clip_range()` 会返回一个包含两个子区域的数组：`[0x1000-0x1800, 0x1C00-0x3000]`。然后，用户提供的回调函数 `ctx->func` 会被调用两次，分别处理这两个子区域。

**涉及用户或编程常见的使用错误及举例说明:**

* **传递无效的模块或符号名称:**  如果用户在调用 `gum_module_find_symbol_by_name()` 时传递了不存在的模块名或符号名，函数将返回 0。用户需要检查返回值以处理这种情况。
    ```c
    GumAddress addr = gum_module_find_symbol_by_name("non_existent_module", "non_existent_symbol");
    if (addr == 0) {
        g_warning("Symbol not found!");
    }
    ```

* **忘记分配输出参数的空间:**  像 `gum_process_resolve_module_pointer()` 这样的函数，如果用户不为 `path` 或 `range` 分配内存，会导致程序崩溃或产生未定义行为。
    ```c
    gchar *module_path = NULL;
    GumMemoryRange range;
    gboolean resolved = gum_process_resolve_module_pointer((gconstpointer)0x12345678, &module_path, &range);
    if (resolved) {
        // 使用 module_path，但需要确保在使用后 g_free(module_path);
    }
    ```

* **假设模块总是存在:**  在动态加载的环境中，模块可能会在不同的时间点加载和卸载。如果用户假设某个模块总是存在并尝试获取其符号，可能会失败。应该在操作模块前检查其是否存在。

* **不理解 Frida 的 "cloak" 机制的影响:**  如果目标进程使用了 Frida 的 cloak 机制隐藏了某些模块或内存区域，用户在枚举时可能无法看到这些内容，导致分析结果不完整。用户需要了解目标进程的 cloak 配置。

**用户操作是如何一步步的到达这里，作为调试线索:**

通常，Frida 的用户不会直接调用 `gumprocess.c` 中的 C 函数。他们主要通过 Frida 提供的 Python 或 JavaScript API 进行交互。这些高级 API 会在底层调用 Gum 库的 C 函数。

**调试线索示例:**

1. **用户编写 Frida 脚本（Python 或 JavaScript）:**
   ```python
   # Python 示例
   import frida

   def on_message(message, data):
       print(message)

   session = frida.attach("target_process")
   script = session.create_script("""
       // JavaScript 示例
       Process.enumerateModules({
           onMatch: function(module){
               send("Module found: " + module.name + " at " + module.base);
           },
           onComplete: function(){
               send("Module enumeration complete");
           }
       });
   """)
   script.on('message', on_message)
   script.load()
   input()
   ```

2. **Frida 脚本执行:** 当用户运行这个脚本时，Frida 会将 JavaScript 代码注入到目标进程中。

3. **JavaScript API 调用:** `Process.enumerateModules()` 是 Frida 提供的一个 JavaScript API。

4. **Frida Bridge:** Frida 的 JavaScript 引擎会将 `Process.enumerateModules()` 的调用转换为对 Frida Agent (通常是用 C/C++ 编写) 的请求。

5. **Gum 库调用:** Frida Agent 内部会调用 Gum 库的函数，其中就包括 `gum_process_enumerate_modules()`。

6. **操作系统 API 调用:** `gum_process_enumerate_modules()` 内部会调用操作系统提供的 API（例如 Linux 的 `/proc/[pid]/maps` 读取或 Windows 的 `EnumProcessModules`）来获取模块信息。

7. **回调执行:**  对于找到的每个模块，`gum_process_enumerate_modules()` 会调用用户在 JavaScript 中提供的 `onMatch` 回调函数，并将模块信息传递回去。

**调试线索:**  如果用户在使用 `Process.enumerateModules()` 时遇到了问题（例如没有枚举到预期的模块），那么调试的线索可能包括：

* **检查 Frida 是否成功注入到目标进程。**
* **检查目标进程是否使用了反调试技术阻止 Frida 的枚举操作。**
* **使用 Frida 的日志功能查看 Gum 库的内部调用情况，例如是否成功打开了 `/proc/[pid]/maps`，或者 `EnumProcessModules` 是否返回了错误。**
* **检查 Frida 的 "cloak" 设置，确认是否意外地隐藏了某些模块。**

总而言之，`gumprocess.c` 是 Frida 用于理解目标进程结构和状态的关键组成部分，它连接了 Frida 的高级 API 和底层的操作系统信息，为逆向工程提供了强大的数据支撑。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/gumprocess.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2015-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023-2024 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "gum-init.h"
#include "gumcloak.h"

typedef struct _GumEmitThreadsContext GumEmitThreadsContext;
typedef struct _GumResolveModulePointerContext GumResolveModulePointerContext;
typedef struct _GumEmitModulesContext GumEmitModulesContext;
typedef struct _GumEmitRangesContext GumEmitRangesContext;
typedef struct _GumResolveSymbolContext GumResolveSymbolContext;

struct _GumEmitThreadsContext
{
  GumFoundThreadFunc func;
  gpointer user_data;
};

struct _GumResolveModulePointerContext
{
  gconstpointer ptr;
  gboolean success;
  gchar ** path;
  GumMemoryRange * range;
};

struct _GumEmitModulesContext
{
  GumFoundModuleFunc func;
  gpointer user_data;
};

struct _GumEmitRangesContext
{
  GumFoundRangeFunc func;
  gpointer user_data;
};

struct _GumResolveSymbolContext
{
  const gchar * name;
  GumAddress result;
};

static gboolean gum_emit_thread_if_not_cloaked (
    const GumThreadDetails * details, gpointer user_data);
static void gum_deinit_main_module (void);
static gboolean gum_try_resolve_module_pointer_from (
    const GumModuleDetails * details, gpointer user_data);
static gboolean gum_emit_module_if_not_cloaked (
    const GumModuleDetails * details, gpointer user_data);
static gboolean gum_emit_range_if_not_cloaked (const GumRangeDetails * details,
    gpointer user_data);
static gboolean gum_store_address_if_name_matches (
    const GumSymbolDetails * details, gpointer user_data);

static GumTeardownRequirement gum_teardown_requirement =
    GUM_TEARDOWN_REQUIREMENT_FULL;
static GumCodeSigningPolicy gum_code_signing_policy = GUM_CODE_SIGNING_OPTIONAL;

GUM_DEFINE_BOXED_TYPE (GumModuleDetails, gum_module_details,
                       gum_module_details_copy, gum_module_details_free)

GumOS
gum_process_get_native_os (void)
{
#if defined (HAVE_WINDOWS)
  return GUM_OS_WINDOWS;
#elif defined (HAVE_MACOS)
  return GUM_OS_MACOS;
#elif defined (HAVE_LINUX) && !defined (HAVE_ANDROID)
  return GUM_OS_LINUX;
#elif defined (HAVE_IOS)
  return GUM_OS_IOS;
#elif defined (HAVE_WATCHOS)
  return GUM_OS_WATCHOS;
#elif defined (HAVE_TVOS)
  return GUM_OS_TVOS;
#elif defined (HAVE_ANDROID)
  return GUM_OS_ANDROID;
#elif defined (HAVE_FREEBSD)
  return GUM_OS_FREEBSD;
#elif defined (HAVE_QNX)
  return GUM_OS_QNX;
#else
# error Unknown OS
#endif
}

GumTeardownRequirement
gum_process_get_teardown_requirement (void)
{
  return gum_teardown_requirement;
}

void
gum_process_set_teardown_requirement (GumTeardownRequirement requirement)
{
  gum_teardown_requirement = requirement;
}

GumCodeSigningPolicy
gum_process_get_code_signing_policy (void)
{
  return gum_code_signing_policy;
}

void
gum_process_set_code_signing_policy (GumCodeSigningPolicy policy)
{
  gum_code_signing_policy = policy;
}

/**
 * gum_process_modify_thread:
 * @thread_id: ID of thread to modify
 * @func: (scope call): function to apply the modifications
 * @user_data: data to pass to @func
 * @flags: flags to customize behavior
 *
 * Modifies a given thread by first pausing it, reading its state, and then
 * passing that to @func, followed by writing back the new state and then
 * resuming the thread. May also be used to inspect the current state without
 * modifying it.
 *
 * Returns: whether the modifications were successfully applied
 */

/**
 * gum_process_enumerate_threads:
 * @func: (scope call): function called with #GumThreadDetails
 * @user_data: data to pass to @func
 *
 * Enumerates all threads, calling @func with #GumThreadDetails about each
 * thread found.
 */
void
gum_process_enumerate_threads (GumFoundThreadFunc func,
                               gpointer user_data)
{
  GumEmitThreadsContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  _gum_process_enumerate_threads (gum_emit_thread_if_not_cloaked, &ctx);
}

static gboolean
gum_emit_thread_if_not_cloaked (const GumThreadDetails * details,
                                gpointer user_data)
{
  GumEmitThreadsContext * ctx = user_data;

  if (gum_cloak_has_thread (details->id))
    return TRUE;

  return ctx->func (details, ctx->user_data);
}

/**
 * gum_process_get_main_module:
 *
 * Returns the details of the module representing the main executable
 * of the process.
 */
const GumModuleDetails *
gum_process_get_main_module (void)
{
  static gsize cached_result = 0;

  if (g_once_init_enter (&cached_result))
  {
    GumModuleDetails * result;

    gum_process_enumerate_modules (_gum_process_collect_main_module, &result);

    _gum_register_destructor (gum_deinit_main_module);

    g_once_init_leave (&cached_result, GPOINTER_TO_SIZE (result) + 1);
  }

  return GSIZE_TO_POINTER (cached_result - 1);
}

static void
gum_deinit_main_module (void)
{
  gum_module_details_free ((GumModuleDetails *) gum_process_get_main_module ());
}

/**
 * gum_process_resolve_module_pointer:
 * @ptr: memory location potentially belonging to a module
 * @path: (out) (optional): absolute path of module
 * @range: (out caller-allocates) (optional): memory range of module
 *
 * Determines which module @ptr belongs to, if any.
 *
 * Returns: whether the pointer resolved to a module
 */
gboolean
gum_process_resolve_module_pointer (gconstpointer ptr,
                                    gchar ** path,
                                    GumMemoryRange * range)
{
  GumResolveModulePointerContext ctx = {
    .ptr = ptr,
    .success = FALSE,
    .path = path,
    .range = range
  };

  gum_process_enumerate_modules (gum_try_resolve_module_pointer_from, &ctx);

  return ctx.success;
}

static gboolean
gum_try_resolve_module_pointer_from (const GumModuleDetails * details,
                                     gpointer user_data)
{
  GumResolveModulePointerContext * ctx = user_data;

  if (GUM_MEMORY_RANGE_INCLUDES (details->range, GUM_ADDRESS (ctx->ptr)))
  {
    ctx->success = TRUE;

    if (ctx->path != NULL)
      *ctx->path = g_strdup (details->path);

    if (ctx->range != NULL)
      *ctx->range = *details->range;

    return FALSE;
  }

  return TRUE;
}

/**
 * gum_process_enumerate_modules:
 * @func: (scope call): function called with #GumModuleDetails
 * @user_data: data to pass to @func
 *
 * Enumerates modules loaded right now, calling @func with #GumModuleDetails
 * about each module found.
 */
void
gum_process_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  GumEmitModulesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  _gum_process_enumerate_modules (gum_emit_module_if_not_cloaked, &ctx);
}

static gboolean
gum_emit_module_if_not_cloaked (const GumModuleDetails * details,
                                gpointer user_data)
{
  GumEmitModulesContext * ctx = user_data;

  if (gum_cloak_has_range_containing (details->range->base_address))
    return TRUE;

  return ctx->func (details, ctx->user_data);
}

/**
 * gum_process_enumerate_ranges:
 * @prot: bitfield specifying the minimum protection
 * @func: (scope call): function called with #GumRangeDetails
 * @user_data: data to pass to @func
 *
 * Enumerates memory ranges satisfying @prot, calling @func with
 * #GumRangeDetails about each such range found.
 */
void
gum_process_enumerate_ranges (GumPageProtection prot,
                              GumFoundRangeFunc func,
                              gpointer user_data)
{
  GumEmitRangesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;
  _gum_process_enumerate_ranges (prot, gum_emit_range_if_not_cloaked, &ctx);
}

static gboolean
gum_emit_range_if_not_cloaked (const GumRangeDetails * details,
                               gpointer user_data)
{
  GumEmitRangesContext * ctx = user_data;
  GArray * sub_ranges;

  sub_ranges = gum_cloak_clip_range (details->range);
  if (sub_ranges != NULL)
  {
    gboolean carry_on = TRUE;
    GumRangeDetails sub_details;
    guint i;

    sub_details.protection = details->protection;
    sub_details.file = details->file;

    for (i = 0; i != sub_ranges->len && carry_on; i++)
    {
      sub_details.range = &g_array_index (sub_ranges, GumMemoryRange, i);

      carry_on = ctx->func (&sub_details, ctx->user_data);
    }

    g_array_free (sub_ranges, TRUE);

    return carry_on;
  }

  return ctx->func (details, ctx->user_data);
}

/**
 * gum_process_enumerate_malloc_ranges:
 * @func: (scope call): function called with #GumMallocRangeDetails
 * @user_data: data to pass to @func
 *
 * Enumerates individual memory allocations known to the system heap, calling
 * @func with #GumMallocRangeDetails about each range found.
 */

/**
 * gum_module_enumerate_imports:
 * @module_name: name of module
 * @func: (scope call): function called with #GumImportDetails
 * @user_data: data to pass to @func
 *
 * Enumerates imports of the specified module, calling @func with
 * #GumImportDetails about each import found.
 */

/**
 * gum_module_enumerate_exports:
 * @module_name: name of module
 * @func: (scope call): function called with #GumExportDetails
 * @user_data: data to pass to @func
 *
 * Enumerates exports of the specified module, calling @func with
 * #GumExportDetails about each export found.
 */

/**
 * gum_module_enumerate_symbols:
 * @module_name: name of module
 * @func: (scope call): function called with #GumSymbolDetails
 * @user_data: data to pass to @func
 *
 * Enumerates symbols of the specified module, calling @func with
 * #GumSymbolDetails about each symbol found.
 */

/**
 * gum_module_enumerate_ranges:
 * @module_name: name of module
 * @prot: bitfield specifying the minimum protection
 * @func: (scope call): function called with #GumRangeDetails
 * @user_data: data to pass to @func
 *
 * Enumerates memory ranges of the specified module that satisfy @prot,
 * calling @func with #GumRangeDetails about each such range found.
 */

GumAddress
gum_module_find_symbol_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumResolveSymbolContext ctx;

  ctx.name = symbol_name;
  ctx.result = 0;

  gum_module_enumerate_symbols (module_name, gum_store_address_if_name_matches,
      &ctx);

  return ctx.result;
}

static gboolean
gum_store_address_if_name_matches (const GumSymbolDetails * details,
                                   gpointer user_data)
{
  GumResolveSymbolContext * ctx = user_data;
  gboolean carry_on = TRUE;

  if (strcmp (details->name, ctx->name) == 0)
  {
    ctx->result = details->address;
    carry_on = FALSE;
  }

  return carry_on;
}

const gchar *
gum_code_signing_policy_to_string (GumCodeSigningPolicy policy)
{
  switch (policy)
  {
    case GUM_CODE_SIGNING_OPTIONAL: return "optional";
    case GUM_CODE_SIGNING_REQUIRED: return "required";
  }

  g_assert_not_reached ();
  return NULL;
}

GumModuleDetails *
gum_module_details_copy (const GumModuleDetails * module)
{
  GumModuleDetails * copy;

  copy = g_slice_new (GumModuleDetails);

  copy->name = g_strdup (module->name);
  copy->range = gum_memory_range_copy (module->range);
  copy->path = g_strdup (module->path);

  return copy;
}

void
gum_module_details_free (GumModuleDetails * module)
{
  if (module == NULL)
    return;

  g_free ((gpointer) module->name);
  gum_memory_range_free ((GumMemoryRange *) module->range);
  g_free ((gpointer) module->path);

  g_slice_free (GumModuleDetails, module);
}

const gchar *
gum_symbol_type_to_string (GumSymbolType type)
{
  switch (type)
  {
    /* Common */
    case GUM_SYMBOL_UNKNOWN:            return "unknown";
    case GUM_SYMBOL_SECTION:            return "section";

    /* Mach-O */
    case GUM_SYMBOL_UNDEFINED:          return "undefined";
    case GUM_SYMBOL_ABSOLUTE:           return "absolute";
    case GUM_SYMBOL_PREBOUND_UNDEFINED: return "prebound-undefined";
    case GUM_SYMBOL_INDIRECT:           return "indirect";

    /* ELF */
    case GUM_SYMBOL_OBJECT:             return "object";
    case GUM_SYMBOL_FUNCTION:           return "function";
    case GUM_SYMBOL_FILE:               return "file";
    case GUM_SYMBOL_COMMON:             return "common";
    case GUM_SYMBOL_TLS:                return "tls";
  }

  g_assert_not_reached ();
  return NULL;
}
```