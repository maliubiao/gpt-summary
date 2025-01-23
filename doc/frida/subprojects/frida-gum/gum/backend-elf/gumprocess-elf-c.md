Response:
Let's break down the thought process for analyzing this C code snippet. The goal is to understand its functionality, its relation to reverse engineering, its use of low-level concepts, logical inferences, potential errors, and how a user might trigger its execution within Frida.

**1. Initial Reading and High-Level Understanding:**

The first step is to read through the code and identify the key data structures and functions. I see structs like `GumEnumerateImportsContext`, `GumDependencyExport`, etc., and functions like `gum_module_enumerate_imports`, `gum_module_enumerate_exports`, etc. The naming suggests that this code deals with inspecting properties of loaded modules (likely ELF files, given the `backend-elf` directory and `GumElfModule`).

**2. Identifying Core Functionality - The "What":**

Based on the function names and the context, I can start inferring the primary functionalities:

* **Enumerating Imports:**  `gum_module_enumerate_imports` and related functions (`gum_emit_import`, `gum_collect_dependency_exports`, `gum_collect_dependency_export`). This clearly involves finding what external symbols a module uses.
* **Enumerating Exports:** `gum_module_enumerate_exports`. This involves finding the symbols a module makes available to others.
* **Enumerating Symbols:** `gum_module_enumerate_symbols` and `gum_emit_symbol`. This appears to be a more general way to list all symbols within a module, including both imports and exports, and potentially internal ones.
* **Enumerating Ranges:** `gum_module_enumerate_ranges` and `gum_emit_range_if_module_name_matches`. This seems to deal with memory regions (ranges) belonging to a specific module.
* **Enumerating Sections:** `gum_module_enumerate_sections` and `gum_emit_section`. This focuses on the different sections within an ELF file (e.g., `.text`, `.data`, `.bss`).
* **Enumerating Dependencies:** `gum_module_enumerate_dependencies`. This finds the other libraries a given module relies on.
* **Finding Base Address:** `gum_module_find_base_address`. This gets the starting memory address where a module is loaded.

**3. Connecting to Reverse Engineering - The "Why":**

Now, I need to link these functionalities to common reverse engineering tasks:

* **Understanding Program Behavior:** Enumerating imports and exports reveals the APIs a program uses and exposes. This is crucial for understanding how different parts of a system interact. Knowing dependencies helps map out the entire software ecosystem.
* **Identifying Security Vulnerabilities:** Knowing the functions a program calls (imports) can highlight potential attack surfaces if those functions are known to have vulnerabilities.
* **Analyzing Malware:**  Reverse engineers use these techniques to understand the inner workings of malicious software.
* **Hooking and Instrumentation:**  Frida's purpose is dynamic instrumentation. The information gathered by these enumeration functions (addresses of functions, data sections, etc.) is essential for setting up hooks to intercept function calls or modify data.

**4. Spotting Low-Level Concepts - The "How":**

The code makes use of several low-level concepts:

* **ELF Format:** The "backend-elf" directory and functions like `gum_elf_module_new_from_memory` clearly indicate interaction with the ELF (Executable and Linkable Format) file format, which is standard for Linux executables and libraries.
* **Dynamic Linking:** Functions like `dlfcn.h`'s `dlsym` are used to resolve symbols at runtime, a core concept of dynamic linking.
* **Memory Management:**  The code deals with memory addresses (`GumAddress`), memory ranges, and page protections.
* **Linux/Android:** The context of Frida points to Linux and Android. The ELF format is prominent in these systems. Concepts like process memory maps are implicitly used.

**5. Looking for Logical Inferences and Assumptions - The "If/Then":**

Here, I analyze the code's conditional logic:

* **Import Resolution:** The `gum_emit_import` function attempts to find the address of an imported symbol. It first checks if the dependency's exports have been collected. If not, it uses `dlsym`. This implies an assumption that symbols might be provided by dependencies or the system's dynamic linker.
* **Module Name Matching:** `gum_emit_range_if_module_name_matches` shows a clear filtering logic based on module names. This implies that the caller might want to operate on memory ranges belonging to a specific module.

**6. Identifying Potential User Errors - The "Oops":**

Thinking about how a programmer might misuse this code:

* **Incorrect Module Name:** Providing a non-existent or misspelled module name to functions like `gum_module_enumerate_imports` will likely result in no results or errors.
* **Incorrect Function Pointers:** The `GumFound...Func` type indicates the use of callback functions. If a user provides an invalid or crashing callback, it could lead to problems.
* **Memory Management Issues (if directly using GumElfModule):** While the provided code seems to handle `GumElfModule` lifecycle, incorrect usage of the underlying `gum_elf_module_*` functions (not shown here) could lead to leaks.

**7. Tracing User Interaction - The "Path":**

How does a user end up calling this code within Frida?

1. **Frida Scripting:** A user writes a JavaScript (or Python) Frida script.
2. **Module Access:** The script uses Frida's API to interact with loaded modules in the target process. For example, `Process.getModuleByName("...")`.
3. **Enumeration Calls:**  The Frida API internally calls functions in the `frida-gum` library. The functions in this C code (`gum_module_enumerate_imports`, etc.) are part of this library's backend for handling ELF files.
4. **Callback Implementation:** The user provides callback functions in their Frida script to process the information returned by the enumeration functions (e.g., a function to print the name and address of each imported symbol).

**Self-Correction/Refinement during the thought process:**

* Initially, I might have just focused on the individual enumeration functions. Then, I realized the importance of connecting them to the overall goal of Frida – dynamic instrumentation.
* I might have overlooked the `dlfcn.h` include. Recognizing its significance in dynamic linking adds valuable context.
* I also considered that the `_gum_process_resolve_module_name` function (not defined in the snippet) is crucial and likely involves looking up loaded modules in the process's memory map. This helps to understand how Frida finds the module based on its name.

By following these steps, I can systematically analyze the provided code snippet and generate a comprehensive explanation that covers its functionality, relevance to reverse engineering, technical details, potential issues, and usage context within Frida.
这个C源代码文件 `gumprocess-elf.c` 是 Frida 动态 instrumentation 工具中负责处理 ELF (Executable and Linkable Format) 文件的模块的一部分。它的主要功能是提供接口来枚举和访问加载到进程内存中的 ELF 模块（例如可执行文件、共享库）的各种信息。

以下是该文件的功能列表，并结合逆向、底层知识、逻辑推理和用户错误进行说明：

**1. 枚举模块导入 (Imports): `gum_module_enumerate_imports`**

* **功能:**  列出一个指定 ELF 模块所依赖的外部符号（函数、变量）。这对于理解模块的功能和依赖关系至关重要。
* **与逆向的关系:**
    * **识别关键 API:** 逆向工程师可以通过查看导入表，快速了解目标程序使用了哪些系统调用或第三方库的函数。例如，如果看到导入了 `connect` 或 `send`，可能暗示程序有网络通信行为。
    * **寻找潜在 Hook 点:**  导入的函数是动态链接的，是 Frida 进行 Hook (拦截和修改函数调用) 的常见目标。了解导入的函数可以帮助选择合适的 Hook 位置。
    * **依赖分析:** 分析导入可以帮助理解模块的依赖关系，从而推断其功能和行为。
* **涉及底层知识:**
    * **ELF 文件格式:**  导入信息存储在 ELF 文件的特定 section (例如 `.plt.got`) 中。该函数需要解析 ELF 文件的结构来提取这些信息。
    * **动态链接:**  导入是在运行时由动态链接器 (如 `ld-linux.so`) 解析和绑定的。Frida 需要理解这个过程才能找到正确的导入地址。
    * **`dlfcn.h`:** 代码中使用了 `dlsym(RTLD_DEFAULT, details->name)` 来查找符号的地址。 `dlsym` 是 Linux/Android 中动态链接库加载和符号查找的关键函数。 `RTLD_DEFAULT` 表示在全局符号表中查找。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:**  `module_name` 为 "libc.so"， `func` 是一个打印导入符号名称的回调函数。
    * **预期输出:** `func` 回调会被多次调用，每次传入一个 `GumImportDetails` 结构体，包含 `libc.so` 依赖的外部符号的名称（例如 "malloc", "printf", "open"），以及它们的类型和可能的地址。
* **用户或编程常见的使用错误:**
    * **错误的模块名:**  如果 `module_name` 拼写错误或者指定的模块没有加载到进程中，`gum_open_elf_module` 将返回 `NULL`，导致枚举失败。
    * **回调函数错误:**  如果 `func` 回调函数内部出现错误（例如访问了无效内存），可能导致 Frida 崩溃或目标进程异常。
* **用户操作到达这里的步骤 (调试线索):**
    1. 用户编写 Frida 脚本，使用 `Process.getModuleByName("libc.so")` 获取 `libc.so` 模块的句柄。
    2. 用户调用 `Module.enumerateImports()` 方法，传入 `libc.so` 的句柄和一个回调函数。
    3. Frida 的 JavaScript 桥接层会将调用转发到 GumJS (Frida 的 JavaScript 引擎)。
    4. GumJS 内部会调用 Gum 核心库的相应函数，最终会调用到 `gum_module_enumerate_imports`，并将用户提供的回调函数转换为 C 函数指针。
    5. `gum_module_enumerate_imports` 打开 `libc.so` 的 ELF 文件，遍历其导入表，并为每个导入调用用户提供的回调函数。

**2. 枚举模块导出 (Exports): `gum_module_enumerate_exports`**

* **功能:** 列出一个指定 ELF 模块提供的外部符号（函数、变量）。这有助于理解模块的功能接口。
* **与逆向的关系:**
    * **理解模块接口:**  导出符号是其他模块可以调用的函数或访问的变量。逆向分析导出可以快速了解模块提供的功能。
    * **寻找 Hook 点:** 导出的函数是其他模块 Hook 的目标。
* **涉及底层知识:**
    * **ELF 文件格式:** 导出信息存储在 ELF 文件的特定 section (例如 `.symtab`, `.dynsym`) 中。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** `module_name` 为程序自身的可执行文件名称，`func` 是一个打印导出符号名称和地址的回调函数。
    * **预期输出:** `func` 回调会被多次调用，每次传入一个 `GumExportDetails` 结构体，包含程序导出的全局函数和变量的名称和地址。
* **用户或编程常见的使用错误:**
    * 与枚举导入类似，错误的模块名或回调函数错误都可能导致问题。
* **用户操作到达这里的步骤:**
    类似于枚举导入，用户在 Frida 脚本中使用 `Process.getModuleByName("my_program")` 并调用 `Module.enumerateExports()`。

**3. 枚举模块符号 (Symbols): `gum_module_enumerate_symbols`**

* **功能:** 列出一个指定 ELF 模块的所有符号，包括导入、导出和模块内部的符号。这是一个更全面的符号信息枚举。
* **与逆向的关系:**
    * **更深入的分析:**  可以查看模块内部的静态函数和变量，用于更细致的逆向分析。
    * **代码结构理解:**  符号信息可以帮助理解代码的组织结构。
* **涉及底层知识:**
    * **ELF 文件格式:** 需要解析符号表 (symbol table) 中的各种类型的符号。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** `module_name` 为 "libutils.so"， `func` 是一个回调函数，用于记录所有全局函数符号的名称。
    * **预期输出:** `func` 回调会被多次调用，针对 `libutils.so` 中的每个符号。如果符号是全局函数，则记录其名称。
* **用户操作到达这里的步骤:**
    用户在 Frida 脚本中使用 `Process.getModuleByName("libutils.so")` 并调用 `Module.enumerateSymbols()`。

**4. 枚举模块内存范围 (Ranges): `gum_module_enumerate_ranges`**

* **功能:** 枚举指定模块的内存映射范围，可以按内存保护属性 (例如可读、可写、可执行) 进行过滤。
* **与逆向的关系:**
    * **内存布局理解:** 了解模块的代码段、数据段等在内存中的分布。
    * **查找代码和数据:**  可以根据内存保护属性定位代码段或可写的数据段。
    * **动态分析:**  可以监控特定内存范围的变化。
* **涉及底层知识:**
    * **进程内存映射:**  依赖于操作系统提供的接口来获取进程的内存映射信息 (例如 Linux 的 `/proc/<pid>/maps`)。
    * **内存保护属性:**  理解如 `PROT_READ`, `PROT_WRITE`, `PROT_EXEC` 等内存保护标志。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** `module_name` 为 "my_app"， `prot` 为 `GUM_PAGE_EXECUTE`， `func` 是一个打印可执行内存范围的回调函数。
    * **预期输出:** `func` 回调会被调用，每次传入一个 `GumRangeDetails` 结构体，包含 `my_app` 中所有可执行内存范围的起始地址、大小和文件映射信息。
* **用户操作到达这里的步骤:**
    用户在 Frida 脚本中使用 `Process.getModuleByName("my_app")` 并调用 `Module.enumerateRanges('r-x', ...)`。

**5. 枚举模块节区 (Sections): `gum_module_enumerate_sections`**

* **功能:** 枚举指定 ELF 模块的节区 (sections)，例如 `.text` (代码段), `.data` (已初始化数据段), `.bss` (未初始化数据段) 等。
* **与逆向的关系:**
    * **代码和数据定位:**  可以精确地获取代码段和数据段的地址和大小。
    * **文件结构理解:**  深入了解 ELF 文件的内部结构。
* **涉及底层知识:**
    * **ELF 文件格式:**  需要解析 ELF 文件头和节区头表。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** `module_name` 为 "libcrypto.so"， `func` 是一个打印节区名称和地址的回调函数。
    * **预期输出:** `func` 回调会被多次调用，每次传入一个 `GumSectionDetails` 结构体，包含 `libcrypto.so` 的各个节区的名称（例如 ".text", ".data", ".rodata"）和它们的地址和大小。
* **用户操作到达这里的步骤:**
    用户在 Frida 脚本中使用 `Process.getModuleByName("libcrypto.so")` 并调用 `Module.enumerateSections()`。

**6. 枚举模块依赖 (Dependencies): `gum_module_enumerate_dependencies`**

* **功能:** 列出一个指定 ELF 模块所依赖的其他共享库。
* **与逆向的关系:**
    * **依赖关系分析:**  理解模块的依赖关系有助于构建软件的全貌，识别潜在的攻击面或需要 Hook 的其他模块。
* **涉及底层知识:**
    * **ELF 文件格式:**  依赖信息通常存储在 `.dynamic` 节区中。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** `module_name` 为程序自身的可执行文件名称， `func` 是一个打印依赖库名称的回调函数。
    * **预期输出:** `func` 回调会被多次调用，每次传入一个 `GumDependencyDetails` 结构体，包含程序依赖的共享库的名称（例如 "libc.so", "libdl.so"）。
* **用户操作到达这里的步骤:**
    用户在 Frida 脚本中使用 `Process.getModuleByName("my_program")` 并调用 `Module.enumerateDependencies()`。

**7. 查找模块基址 (Base Address): `gum_module_find_base_address`**

* **功能:** 获取指定 ELF 模块在进程内存中的加载基址。
* **与逆向的关系:**
    * **地址计算:**  在动态分析中，需要基址来计算模块内部符号的实际内存地址。
* **涉及底层知识:**
    * **进程内存映射:**  需要查询进程的内存映射信息。
* **逻辑推理 (假设输入与输出):**
    * **假设输入:** `module_name` 为 "libart.so"。
    * **预期输出:** 返回 `libart.so` 在当前进程中的加载基址。
* **用户操作到达这里的步骤:**
    用户在 Frida 脚本中使用 `Process.getModuleByName("libart.so").base`。

**辅助函数:**

* `gum_open_elf_module`:  根据模块名称打开并解析 ELF 文件，返回 `GumElfModule` 对象，该对象封装了对 ELF 文件的访问。
* 静态函数 `gum_emit_*`: 这些是辅助回调函数，用于将从 ELF 文件中提取的信息传递给用户提供的回调函数。
* `gum_collect_dependency_exports` 和 `gum_collect_dependency_export`:  用于收集依赖库的导出符号，以便在枚举导入时能够找到导入符号的来源模块和地址。

**总结:**

`gumprocess-elf.c` 文件是 Frida 动态 instrumentation 工具中处理 ELF 文件的核心组件。它通过解析 ELF 文件结构和查询进程内存映射信息，提供了丰富的功能来枚举模块的各种属性，为逆向工程师提供了强大的工具来理解程序的结构、功能和行为，并为 Frida 的 Hook 功能提供了必要的信息。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-elf/gumprocess-elf.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2010-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-elf.h"

#include "gumelfmodule.h"

#include <dlfcn.h>

typedef struct _GumEnumerateImportsContext GumEnumerateImportsContext;
typedef struct _GumDependencyExport GumDependencyExport;
typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;
typedef struct _GumEnumerateRangesContext GumEnumerateRangesContext;
typedef struct _GumEnumerateSectionsContext GumEnumerateSectionsContext;

struct _GumEnumerateImportsContext
{
  GumFoundImportFunc func;
  gpointer user_data;

  GHashTable * dependency_exports;
  GumElfModule * current_dependency;
  GumModuleMap * module_map;
};

struct _GumDependencyExport
{
  gchar * module;
  GumAddress address;
};

struct _GumEnumerateSymbolsContext
{
  GumFoundSymbolFunc func;
  gpointer user_data;
};

struct _GumEnumerateRangesContext
{
  gchar * module_name;
  GumFoundRangeFunc func;
  gpointer user_data;
};

struct _GumEnumerateSectionsContext
{
  GumFoundSectionFunc func;
  gpointer user_data;
};

static gboolean gum_emit_import (const GumImportDetails * details,
    gpointer user_data);
static gboolean gum_collect_dependency_exports (
    const GumDependencyDetails * details, gpointer user_data);
static gboolean gum_collect_dependency_export (const GumExportDetails * details,
    gpointer user_data);
static GumDependencyExport * gum_dependency_export_new (const gchar * module,
    GumAddress address);
static void gum_dependency_export_free (GumDependencyExport * export);
static gboolean gum_emit_symbol (const GumElfSymbolDetails * details,
    gpointer user_data);
static gboolean gum_emit_range_if_module_name_matches (
    const GumRangeDetails * details, gpointer user_data);
static gboolean gum_emit_section (const GumElfSectionDetails * details,
    gpointer user_data);

static GumElfModule * gum_open_elf_module (const gchar * name);

void
gum_module_enumerate_imports (const gchar * module_name,
                              GumFoundImportFunc func,
                              gpointer user_data)
{
  GumElfModule * module;
  GumEnumerateImportsContext ctx;

  module = gum_open_elf_module (module_name);
  if (module == NULL)
    return;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.dependency_exports = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) gum_dependency_export_free);
  ctx.current_dependency = NULL;
  ctx.module_map = NULL;

  gum_elf_module_enumerate_dependencies (module, gum_collect_dependency_exports,
      &ctx);

  gum_elf_module_enumerate_imports (module, gum_emit_import, &ctx);

  if (ctx.module_map != NULL)
    gum_object_unref (ctx.module_map);
  g_hash_table_unref (ctx.dependency_exports);

  gum_object_unref (module);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumImportDetails d;
  GumDependencyExport * exp;

  d.type = details->type;
  d.name = details->name;
  d.slot = details->slot;

  exp = g_hash_table_lookup (ctx->dependency_exports, details->name);
  if (exp != NULL)
  {
    d.module = exp->module;
    d.address = exp->address;
  }
  else
  {
    d.module = NULL;
    d.address = GUM_ADDRESS (dlsym (RTLD_DEFAULT, details->name));

    if (d.address != 0)
    {
      const GumModuleDetails * module;

      if (ctx->module_map == NULL)
        ctx->module_map = gum_module_map_new ();
      module = gum_module_map_find (ctx->module_map, d.address);
      if (module != NULL)
        d.module = module->path;
    }
  }

  return ctx->func (&d, ctx->user_data);
}

static gboolean
gum_collect_dependency_exports (const GumDependencyDetails * details,
                                gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumElfModule * module;

  module = gum_open_elf_module (details->name);
  if (module == NULL)
    return TRUE;
  ctx->current_dependency = module;
  gum_elf_module_enumerate_exports (module, gum_collect_dependency_export, ctx);
  ctx->current_dependency = NULL;
  gum_object_unref (module);

  return TRUE;
}

static gboolean
gum_collect_dependency_export (const GumExportDetails * details,
                               gpointer user_data)
{
  GumEnumerateImportsContext * ctx = user_data;
  GumElfModule * module = ctx->current_dependency;

  g_hash_table_insert (ctx->dependency_exports,
      g_strdup (details->name),
      gum_dependency_export_new (gum_elf_module_get_source_path (module),
          details->address));

  return TRUE;
}

static GumDependencyExport *
gum_dependency_export_new (const gchar * module,
                           GumAddress address)
{
  GumDependencyExport * export;

  export = g_slice_new (GumDependencyExport);
  export->module = g_strdup (module);
  export->address = address;

  return export;
}

static void
gum_dependency_export_free (GumDependencyExport * export)
{
  g_free (export->module);
  g_slice_free (GumDependencyExport, export);
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  GumElfModule * module;

  module = gum_open_elf_module (module_name);
  if (module == NULL)
    return;
  gum_elf_module_enumerate_exports (module, func, user_data);
  gum_object_unref (module);
}

void
gum_module_enumerate_symbols (const gchar * module_name,
                              GumFoundSymbolFunc func,
                              gpointer user_data)
{
  GumElfModule * module;
  GumEnumerateSymbolsContext ctx;

  module = gum_open_elf_module (module_name);
  if (module == NULL)
    return;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_symbols (module, gum_emit_symbol, &ctx);

  gum_object_unref (module);
}

static gboolean
gum_emit_symbol (const GumElfSymbolDetails * details,
                 gpointer user_data)
{
  GumEnumerateSymbolsContext * ctx = user_data;
  GumSymbolDetails symbol;
  const GumElfSectionDetails * section;
  GumSymbolSection symsect;

  symbol.is_global = details->bind == GUM_ELF_BIND_GLOBAL ||
      details->bind == GUM_ELF_BIND_WEAK;

  switch (details->type)
  {
    case GUM_ELF_SYMBOL_OBJECT:  symbol.type = GUM_SYMBOL_OBJECT;   break;
    case GUM_ELF_SYMBOL_FUNC:    symbol.type = GUM_SYMBOL_FUNCTION; break;
    case GUM_ELF_SYMBOL_SECTION: symbol.type = GUM_SYMBOL_SECTION;  break;
    case GUM_ELF_SYMBOL_FILE:    symbol.type = GUM_SYMBOL_FILE;     break;
    case GUM_ELF_SYMBOL_COMMON:  symbol.type = GUM_SYMBOL_COMMON;   break;
    case GUM_ELF_SYMBOL_TLS:     symbol.type = GUM_SYMBOL_TLS;      break;
    default:                     symbol.type = GUM_SYMBOL_UNKNOWN;  break;
  }

  section = details->section;
  if (section != NULL)
  {
    symsect.id = section->id;
    symsect.protection = section->protection;
    symbol.section = &symsect;
  }
  else
  {
    symbol.section = NULL;
  }

  symbol.name = details->name;
  symbol.address = details->address;
  symbol.size = details->size;

  return ctx->func (&symbol, ctx->user_data);
}

void
gum_module_enumerate_ranges (const gchar * module_name,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  GumEnumerateRangesContext ctx;

  if (!_gum_process_resolve_module_name (module_name, &ctx.module_name, NULL))
    return;
  ctx.func = func;
  ctx.user_data = user_data;

  gum_process_enumerate_ranges (prot, gum_emit_range_if_module_name_matches,
      &ctx);

  g_free (ctx.module_name);
}

static gboolean
gum_emit_range_if_module_name_matches (const GumRangeDetails * details,
                                       gpointer user_data)
{
  GumEnumerateRangesContext * ctx = user_data;

  if (details->file == NULL)
    return TRUE;
  if (strcmp (details->file->path, ctx->module_name) != 0)
    return TRUE;

  return ctx->func (details, ctx->user_data);
}

void
gum_module_enumerate_sections (const gchar * module_name,
                               GumFoundSectionFunc func,
                               gpointer user_data)
{
  GumElfModule * module;
  GumEnumerateSectionsContext ctx;

  module = gum_open_elf_module (module_name);
  if (module == NULL)
    return;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_elf_module_enumerate_sections (module, gum_emit_section, &ctx);

  gum_object_unref (module);
}

static gboolean
gum_emit_section (const GumElfSectionDetails * details,
                  gpointer user_data)
{
  GumEnumerateSectionsContext * ctx = user_data;
  GumSectionDetails section;

  section.id = details->id;
  section.name = details->name;
  section.address = details->address;
  section.size = details->size;

  return ctx->func (&section, ctx->user_data);
}

void
gum_module_enumerate_dependencies (const gchar * module_name,
                                   GumFoundDependencyFunc func,
                                   gpointer user_data)
{
  GumElfModule * module = gum_open_elf_module (module_name);
  if (module == NULL)
    return;

  gum_elf_module_enumerate_dependencies (module, func, user_data);

  gum_object_unref (module);
}

GumAddress
gum_module_find_base_address (const gchar * module_name)
{
  GumAddress base;

  if (!_gum_process_resolve_module_name (module_name, NULL, &base))
    return 0;

  return base;
}

static GumElfModule *
gum_open_elf_module (const gchar * name)
{
  gchar * path;
  GumAddress base_address;
  GumElfModule * module;

  if (!_gum_process_resolve_module_name (name, &path, &base_address))
    return NULL;

  module = gum_elf_module_new_from_memory (path, base_address, NULL);

  g_free (path);

  return module;
}
```