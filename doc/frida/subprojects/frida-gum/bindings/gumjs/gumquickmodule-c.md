Response:
Let's break down the thought process for analyzing this C code for Frida.

**1. Understanding the Goal:**

The core request is to understand the *functionality* of this C file within the context of Frida, focusing on its relationship to reverse engineering, low-level details, logic, potential errors, and how a user might reach this code.

**2. Initial Code Scan and Identification of Key Structures and Functions:**

The first step is a quick skim to identify the major components. Keywords like `struct`, function declarations (especially those with `GUMJS_DECLARE_*` and `GUMJS_DEFINE_*`), and function names themselves provide clues.

* **Structures:** `GumQuickMatchContext`, `GumQuickModuleFilter`. These likely represent internal data structures used for specific tasks.
* **Function Declarations:** The `GUMJS_DECLARE_*` macros suggest functions that interact with JavaScript. The names like `gumjs_module_load`, `gumjs_module_enumerate_imports`, etc., clearly indicate the operations this module provides. The `static gboolean gum_emit_*` functions hint at callback mechanisms.
* **Function Definitions:** The `GUMJS_DEFINE_*` macros mark the actual implementations of the declared functions.
* **Data Structures for Modules:** The code clearly defines how module information (name, base address, size, path) is handled and passed between C and JavaScript.
* **Module Map:**  The presence of `gumjs_module_map_*` functions suggests a way to manage and query loaded modules.

**3. Deeper Dive into Functionality - Connecting C to JavaScript:**

The `GUMJS_DECLARE_*` and `GUMJS_DEFINE_*` macros are crucial. They strongly suggest a bridge between C code (the core Frida functionality) and the JavaScript environment where users write their instrumentation scripts.

* **`gumjs_module_construct`:**  Likely not directly called by users, as it throws an error. This suggests internal instantiation.
* **`gumjs_module_load`:**  Takes a module name as input, hinting at dynamically loading libraries. The use of `gum_module_load` confirms this.
* **`gumjs_module_ensure_initialized`:**  Suggests a check for whether a module is already loaded.
* **`gumjs_module_enumerate_*`:** These functions are central to reverse engineering. They allow introspection of a module's imports, exports, symbols, memory ranges, sections, and dependencies. The callbacks (`onMatch`, `onComplete`) point to how JavaScript receives this information.
* **`gumjs_module_find_base_address`, `gumjs_module_find_export_by_name`:**  Directly related to locating code and data within modules.
* **`gumjs_module_map_*`:**  Functions for creating, managing, and querying a collection of loaded modules. The filtering capability (`gum_module_map_new_filtered`) is interesting.

**4. Identifying Reverse Engineering Relationships:**

Once the core functionality is understood, the connections to reverse engineering become clearer:

* **Introspection:** The `enumerate_*` functions are classic reverse engineering techniques for understanding a binary's structure and dependencies.
* **Symbol Resolution:** `find_export_by_name` is a fundamental operation in dynamic analysis.
* **Memory Layout:**  `enumerate_ranges` and `enumerate_sections` provide insights into how the module is laid out in memory.
* **Dependency Analysis:** `enumerate_dependencies` helps understand the module's external linkages.

**5. Spotting Low-Level Details:**

The code contains several indicators of low-level interactions:

* **Pointers:** Frequent use of `gpointer`, `GumAddress`, and functions that convert between them (`GSIZE_TO_POINTER`).
* **Memory Concepts:**  "Ranges," "sections," "base address" are all core to understanding memory organization.
* **Operating System Concepts:**  "Imports," "exports," and "dependencies" are related to how shared libraries work in operating systems like Linux and Android.
* **Page Protection:** The `GumPageProtection` type and its usage in `gum_emit_range` and `gum_emit_symbol` connect to memory management and security at the OS level.

**6. Logical Reasoning and Input/Output Examples:**

For each function, consider what it does and how a user might interact with it through JavaScript.

* **`gumjs_module_load("libc.so")`:** Loads the `libc.so` library. No direct output, but success/failure.
* **`gumjs_module_enumerate_exports("my_app", { onMatch: function(e) { console.log(e.name); } })`:**  Iterates through the exports of `my_app` and logs the name of each export.

**7. Identifying Potential User Errors:**

Think about how a user might misuse the API.

* **Incorrect Module Name:** Passing a non-existent module name to `gumjs_module_load` or enumeration functions.
* **Incorrect Argument Types:**  Providing a string where a callback function is expected.
* **Callback Errors:** The `onMatch` callback might throw an exception, potentially halting the enumeration.

**8. Tracing User Actions to the Code:**

Imagine a typical Frida workflow:

1. **User writes a JavaScript script:** This script uses Frida's API.
2. **Script calls `Module.load("...")`:** This directly maps to `gumjs_module_load`.
3. **Script calls `Module.enumerateExports("...")`:** This maps to `gumjs_module_enumerate_exports`.
4. **Frida's JavaScript bridge invokes the corresponding C function:** This is the point where the execution enters `gumquickmodule.c`.

**9. Iteration and Refinement:**

After the initial pass, review the code again. Are there any details missed?  Are the explanations clear and accurate? For instance, the `ModuleMap` section needs attention to its filtering capabilities.

**Self-Correction Example During Analysis:**

Initially, I might have just said "loads a module" for `gumjs_module_load`. But on closer inspection, the `GError` handling suggests that loading can fail, and it's important to mention this for debugging and error handling in user scripts. Similarly, for the enumeration functions, realizing the importance of the `onMatch` and `onComplete` callbacks is crucial for understanding how the results are delivered to the JavaScript side.

By following these steps systematically, one can effectively analyze C code like this and extract the relevant information for understanding its role in a dynamic instrumentation framework like Frida.
这个文件 `gumquickmodule.c` 是 Frida 工具中 `frida-gum` 库的组成部分，负责提供 JavaScript 绑定 (bindings) 中与模块 (Module) 操作相关的核心功能。它允许 JavaScript 代码与目标进程的模块进行交互，是实现动态 instrumentation 的关键部分。

以下是该文件的功能列表，并结合逆向方法、底层知识、逻辑推理、用户错误和调试线索进行说明：

**主要功能:**

1. **模块加载 (`gumjs_module_load`):**
   - **功能:** 允许 JavaScript 代码动态加载目标进程中的模块 (例如共享库 `.so` 文件或 DLL 文件)。
   - **逆向方法:** 在逆向分析时，可能需要加载特定的库来 hook 其内部函数或查看其数据结构。例如，加载 `libc.so` 来 hook `malloc` 或 `free`。
   - **底层知识:** 依赖于操作系统提供的加载库的机制，如 Linux 的 `dlopen` 或 Windows 的 `LoadLibrary`。 Frida 封装了这些底层调用。
   - **用户错误:** 如果用户尝试加载一个不存在或路径错误的模块，此函数会抛出异常。 例如，`Module.load("non_existent_library")` 将会失败。
   - **调试线索:** 用户在 JavaScript 中调用 `Module.load("...")` 时，会触发 `gumjs_module_load` 函数的执行。

2. **确保模块初始化 (`gumjs_module_ensure_initialized`):**
   - **功能:** 检查指定的模块是否已加载和初始化。
   - **逆向方法:** 在 hook 某个模块的函数之前，确保该模块已经被加载，避免因模块未加载而导致的错误。
   - **底层知识:** 某些模块可能需要特定的初始化步骤。这个函数可能利用操作系统或模块自身的机制来检查初始化状态。
   - **逻辑推理:** 假设用户想 hook `libnative.so` 中的一个函数，他会先调用 `Module.ensureInitialized("libnative.so")`，如果返回 `true`，则继续进行 hook 操作。
   - **用户错误:** 如果尝试确保一个不存在的模块初始化，此函数会抛出异常。
   - **调试线索:**  用户在 JavaScript 中调用 `Module.ensureInitialized("...")` 时，会触发此函数的执行。

3. **枚举模块的导入 (`gumjs_module_enumerate_imports`):**
   - **功能:** 遍历指定模块的导入符号 (它依赖的其他模块的函数或变量)。
   - **逆向方法:** 可以用来分析模块的依赖关系，了解它使用了哪些其他库的功能。
   - **二进制底层:** 需要解析模块的二进制格式 (如 ELF 或 PE) 中的导入表 (Import Table)。
   - **逻辑推理:** 假设目标进程加载了 `app` 模块，`Module.enumerateImports("app", { onMatch: function(imp) { console.log(imp.name); } })` 会打印出 `app` 模块引用的所有外部符号的名称。
   - **用户错误:**  如果提供的模块名不正确，枚举操作可能不会产生任何结果或抛出错误。
   - **调试线索:** 用户在 JavaScript 中调用 `Module.enumerateImports("...", { ... })` 时，会触发此函数的执行。`gum_emit_import` 是用于将枚举到的导入信息传递回 JavaScript 的回调函数。

4. **枚举模块的导出 (`gumjs_module_enumerate_exports`):**
   - **功能:** 遍历指定模块的导出符号 (它提供的可以被其他模块调用的函数或变量)。
   - **逆向方法:** 可以用来查找模块提供的功能入口点，是进行函数 hook 的重要前提。
   - **二进制底层:** 需要解析模块二进制格式中的导出表 (Export Table)。
   - **逻辑推理:** 假设目标进程加载了 `libcrypto.so`，`Module.enumerateExports("libcrypto.so", { onMatch: function(exp) { console.log(exp.name, exp.address); } })` 会打印出 `libcrypto.so` 导出的所有函数和变量的名称和地址。
   - **用户错误:**  如果提供的模块名不正确，枚举操作可能不会产生任何结果或抛出错误。
   - **调试线索:** 用户在 JavaScript 中调用 `Module.enumerateExports("...", { ... })` 时，会触发此函数的执行。 `gum_emit_export` 用于将枚举到的导出信息传递回 JavaScript。

5. **枚举模块的符号 (`gumjs_module_enumerate_symbols`):**
   - **功能:** 遍历模块的所有符号，包括导入和导出，以及内部定义的符号。
   - **逆向方法:** 提供更全面的模块信息，可以用于查找内部函数、全局变量等。
   - **二进制底层:**  需要解析符号表 (Symbol Table)，例如 ELF 文件的 `.symtab` 或 PE 文件的符号信息。
   - **逻辑推理:**  `Module.enumerateSymbols("my_app", { onMatch: function(sym) { if (sym.type === 'function') console.log(sym.name); } })` 会打印出 `my_app` 模块中所有函数符号的名称。
   - **用户错误:**  如果提供的模块名不正确，枚举操作可能不会产生任何结果或抛出错误。
   - **调试线索:** 用户在 JavaScript 中调用 `Module.enumerateSymbols("...", { ... })` 时，会触发此函数的执行。 `gum_emit_symbol` 用于传递枚举到的符号信息。

6. **枚举模块的内存范围 (`gumjs_module_enumerate_ranges`):**
   - **功能:** 遍历模块在内存中的所有加载范围，可以指定内存保护属性 (例如只读、可执行等)。
   - **逆向方法:** 可以用来了解模块的内存布局，查找代码段、数据段等。对于寻找动态生成的代码或进行内存扫描很有用。
   - **Linux, Android 内核及框架:** 涉及到进程的内存管理，与 Linux 的 `/proc/[pid]/maps` 或 Android 类似机制获取的内存映射信息相关。
   - **逻辑推理:** `Module.enumerateRanges("my_game", 'r-x', { onMatch: function(range) { console.log(range.base, range.size); } })` 会打印出 `my_game` 模块中所有可执行的内存区域的起始地址和大小。
   - **用户错误:**  如果提供的模块名不正确或内存保护属性参数错误，可能不会得到预期的结果。
   - **调试线索:** 用户在 JavaScript 中调用 `Module.enumerateRanges("...", "...", { ... })` 时，会触发此函数的执行。 `gum_emit_range` 用于传递枚举到的内存范围信息。

7. **枚举模块的节区 (`gumjs_module_enumerate_sections`):**
   - **功能:** 遍历模块的节区 (sections)，如 `.text` (代码段)、`.data` (数据段)、`.bss` 等。
   - **逆向方法:**  更精细地了解模块的结构，每个节区有不同的用途和属性。
   - **二进制底层:** 需要解析模块二进制格式的节区头 (Section Header)。
   - **逻辑推理:** `Module.enumerateSections("mylib.so", { onMatch: function(section) { console.log(section.id, section.address, section.size); } })` 会打印出 `mylib.so` 的所有节区的 ID、起始地址和大小。
   - **用户错误:**  如果提供的模块名不正确，枚举操作可能不会产生任何结果或抛出错误。
   - **调试线索:** 用户在 JavaScript 中调用 `Module.enumerateSections("...", { ... })` 时，会触发此函数的执行。 `gum_emit_section` 用于传递枚举到的节区信息。

8. **枚举模块的依赖 (`gumjs_module_enumerate_dependencies`):**
   - **功能:** 遍历模块所依赖的其他模块。
   - **逆向方法:**  分析模块的依赖树，了解其运行所需的其他库。
   - **Linux, Android 内核及框架:** 与动态链接器的行为相关，例如 Linux 的 `ld-linux.so`。
   - **逻辑推理:** `Module.enumerateDependencies("target_app", { onMatch: function(dep) { console.log(dep.name, dep.type); } })` 会打印出 `target_app` 依赖的所有其他库的名称和依赖类型。
   - **用户错误:**  如果提供的模块名不正确，枚举操作可能不会产生任何结果或抛出错误。
   - **调试线索:** 用户在 JavaScript 中调用 `Module.enumerateDependencies("...", { ... })` 时，会触发此函数的执行。 `gum_emit_dependency` 用于传递枚举到的依赖信息。

9. **查找模块的基地址 (`gumjs_module_find_base_address`):**
   - **功能:** 获取指定模块在内存中的加载基地址。
   - **逆向方法:**  hook 函数或访问模块内的全局变量时，需要知道模块的基地址来计算偏移。
   - **底层知识:**  依赖于操作系统提供的获取模块加载地址的机制。
   - **逻辑推理:** `Module.findBaseAddress("another_lib.so")` 会返回 `another_lib.so` 在内存中的起始地址。
   - **用户错误:** 如果提供的模块名不正确，此函数会返回 `null`。
   - **调试线索:** 用户在 JavaScript 中调用 `Module.findBaseAddress("...")` 时，会触发此函数的执行。

10. **通过名称查找模块的导出 (`gumjs_module_find_export_by_name`):**
    - **功能:**  在指定模块中查找具有特定名称的导出符号的地址。
    - **逆向方法:**  直接获取目标函数的地址，用于 hook 操作。
    - **底层知识:** 涉及到符号表的查找。
    - **逻辑推理:** `Module.findExportByName("libutils.so", "calculate_hash")` 会返回 `libutils.so` 中 `calculate_hash` 函数的地址。
    - **用户错误:** 如果提供的模块名或符号名不正确，此函数会返回 `null`。
    - **调试线索:** 用户在 JavaScript 中调用 `Module.findExportByName("...", "...")` 时，会触发此函数的执行。

11. **模块映射 (ModuleMap) 相关功能 (`gumjs_module_map_*`):**
    - **功能:**  提供了一种管理和查询已加载模块集合的机制。可以创建一个 `ModuleMap` 对象，并通过地址查找模块信息。
    - **逆向方法:**  在处理多个模块时，可以使用 `ModuleMap` 来高效地查找特定地址所属的模块。例如，在拦截到某个内存地址后，快速确定是哪个模块的代码。
    - **数据结构:** 内部维护一个模块信息的数据结构，允许按地址查找。
    - **逻辑推理:** 用户可以通过 `Process.enumerateModules()` 获取一个 `ModuleMap`，然后使用 `moduleMap.find(address)` 来查找包含特定地址的模块。
    - **用户错误:** 尝试在未初始化的 `ModuleMap` 上调用方法可能会导致错误。
    - **调试线索:**  用户在 JavaScript 中创建或操作 `ModuleMap` 对象时，会触发这些函数的执行。例如，调用 `Process.enumerateModules()` 会创建一个 `ModuleMap` 并填充数据。

**用户操作到达 `gumquickmodule.c` 的步骤 (调试线索):**

1. **用户编写 Frida JavaScript 脚本 (`.js` 文件)。**
2. **脚本中使用 `Module` 对象的方法，例如 `Module.load("...")`, `Module.enumerateExports("...")` 等。**
3. **Frida 命令行工具 (`frida`, `frida-ps`, `frida-trace` 等) 或 Frida API 将脚本注入到目标进程中。**
4. **当 JavaScript 代码执行到 `Module` 对象的方法时，Frida 的 JavaScript 引擎 (QuickJS) 会调用相应的 C 函数绑定。**
5. **这些 C 函数绑定就在 `gumquickmodule.c` 文件中实现。**
6. **例如，当执行 `Module.load("my_library")` 时，QuickJS 会调用 `gumjs_module_load` 函数，并将参数 `"my_library"` 传递给它。**

**总结:**

`gumquickmodule.c` 是 Frida 中用于模块操作的关键 C 代码文件，它通过 JavaScript 绑定暴露了底层的模块信息和操作能力，是实现动态 instrumentation 和逆向分析的重要组成部分。它涉及到了操作系统加载库的机制、模块的二进制格式解析、进程内存管理等底层知识。理解这个文件的功能有助于深入理解 Frida 的工作原理以及如何使用 Frida 进行有效的逆向工程。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickmodule.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2020-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickmodule.h"

#include "gumquickmacros.h"

typedef struct _GumQuickMatchContext GumQuickMatchContext;
typedef struct _GumQuickModuleFilter GumQuickModuleFilter;

struct _GumQuickMatchContext
{
  JSValue on_match;
  JSValue on_complete;
  GumQuickMatchResult result;

  JSContext * ctx;
  GumQuickCore * core;
};

struct _GumQuickModuleFilter
{
  JSValue callback;

  GumQuickModule * parent;
};

GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_construct)
GUMJS_DECLARE_FUNCTION (gumjs_module_load)
GUMJS_DECLARE_FUNCTION (gumjs_module_ensure_initialized)
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_imports)
static gboolean gum_emit_import (const GumImportDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_exports)
static gboolean gum_emit_export (const GumExportDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_symbols)
static gboolean gum_emit_symbol (const GumSymbolDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_sections)
static gboolean gum_emit_section (const GumSectionDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_dependencies)
static gboolean gum_emit_dependency (const GumDependencyDetails * details,
    GumQuickMatchContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_find_base_address)
GUMJS_DECLARE_FUNCTION (gumjs_module_find_export_by_name)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_map_construct)
GUMJS_DECLARE_FINALIZER (gumjs_module_map_finalize)
GUMJS_DECLARE_GETTER (gumjs_module_map_get_handle)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_has)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find_name)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find_path)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_update)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_copy_values)

static void gum_quick_module_filter_free (GumQuickModuleFilter * filter);
static gboolean gum_quick_module_filter_matches (
    const GumModuleDetails * details, GumQuickModuleFilter * self);

static const JSClassDef gumjs_module_def =
{
  .class_name = "Module",
};

static const JSCFunctionListEntry gumjs_module_entries[] =
{
  JS_CFUNC_DEF ("_load", 0, gumjs_module_load),
  JS_CFUNC_DEF ("ensureInitialized", 0, gumjs_module_ensure_initialized),
  JS_CFUNC_DEF ("_enumerateImports", 0, gumjs_module_enumerate_imports),
  JS_CFUNC_DEF ("_enumerateExports", 0, gumjs_module_enumerate_exports),
  JS_CFUNC_DEF ("_enumerateSymbols", 0, gumjs_module_enumerate_symbols),
  JS_CFUNC_DEF ("_enumerateRanges", 0, gumjs_module_enumerate_ranges),
  JS_CFUNC_DEF ("_enumerateSections", 0, gumjs_module_enumerate_sections),
  JS_CFUNC_DEF ("_enumerateDependencies", 0,
      gumjs_module_enumerate_dependencies),
  JS_CFUNC_DEF ("findBaseAddress", 0, gumjs_module_find_base_address),
  JS_CFUNC_DEF ("findExportByName", 0, gumjs_module_find_export_by_name),
};

static const JSClassDef gumjs_module_map_def =
{
  .class_name = "ModuleMap",
  .finalizer = gumjs_module_map_finalize,
};

static const JSCFunctionListEntry gumjs_module_map_entries[] =
{
  JS_CGETSET_DEF ("handle", gumjs_module_map_get_handle, NULL),
  JS_CFUNC_DEF ("has", 0, gumjs_module_map_has),
  JS_CFUNC_DEF ("find", 0, gumjs_module_map_find),
  JS_CFUNC_DEF ("findName", 0, gumjs_module_map_find_name),
  JS_CFUNC_DEF ("findPath", 0, gumjs_module_map_find_path),
  JS_CFUNC_DEF ("update", 0, gumjs_module_map_update),
  JS_CFUNC_DEF ("values", 0, gumjs_module_map_copy_values),
};

void
_gum_quick_module_init (GumQuickModule * self,
                        JSValue ns,
                        GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue proto, ctor;

  self->core = core;

  _gum_quick_core_store_module_data (core, "module", self);

  _gum_quick_create_class (ctx, &gumjs_module_def, core, &self->module_class,
      &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_module_construct,
      gumjs_module_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, ctor, gumjs_module_entries,
      G_N_ELEMENTS (gumjs_module_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_module_def.class_name, ctor,
      JS_PROP_C_W_E);

  _gum_quick_create_class (ctx, &gumjs_module_map_def, core,
      &self->module_map_class, &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_module_map_construct,
      gumjs_module_map_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_module_map_entries,
      G_N_ELEMENTS (gumjs_module_map_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_module_map_def.class_name, ctor,
      JS_PROP_C_W_E);
}

void
_gum_quick_module_dispose (GumQuickModule * self)
{
}

void
_gum_quick_module_finalize (GumQuickModule * self)
{
}

JSValue
_gum_quick_module_new (JSContext * ctx,
                       const GumModuleDetails * details,
                       GumQuickModule * parent)
{
  GumQuickCore * core = parent->core;
  JSValue m;

  m = JS_NewObjectClass (ctx, parent->module_class);

  JS_DefinePropertyValue (ctx, m,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, m,
      GUM_QUICK_CORE_ATOM (core, base),
      _gum_quick_native_pointer_new (ctx,
          GSIZE_TO_POINTER (details->range->base_address), core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, m,
      GUM_QUICK_CORE_ATOM (core, size),
      JS_NewInt32 (ctx, details->range->size),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, m,
      GUM_QUICK_CORE_ATOM (core, path),
      JS_NewString (ctx, details->path),
      JS_PROP_C_W_E);

  return m;
}

static GumQuickModule *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "module");
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_construct)
{
  return _gum_quick_throw_literal (ctx, "not user-instantiable");
}

GUMJS_DEFINE_FUNCTION (gumjs_module_load)
{
  const gchar * name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  GError * error;

  if (!_gum_quick_args_parse (args, "s", &name))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  error = NULL;
  gum_module_load (name, &error);

  _gum_quick_scope_resume (&scope);

  if (error != NULL)
    return _gum_quick_throw_error (ctx, &error);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_ensure_initialized)
{
  const gchar * name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  gboolean success;

  if (!_gum_quick_args_parse (args, "s", &name))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  success = gum_module_ensure_initialized (name);

  _gum_quick_scope_resume (&scope);

  if (!success)
    return _gum_quick_throw (ctx, "unable to find module '%s'", name);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_imports)
{
  GumQuickMatchContext mc;
  const gchar * name;

  if (!_gum_quick_args_parse (args, "sF{onMatch,onComplete}", &name,
      &mc.on_match, &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_module_enumerate_imports (name, (GumFoundImportFunc) gum_emit_import,
      &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->core;
  JSValue imp, result;

  imp = JS_NewObject (ctx);

  if (details->type != GUM_IMPORT_UNKNOWN)
  {
    JS_DefinePropertyValue (ctx, imp,
        GUM_QUICK_CORE_ATOM (core, type),
        JS_NewString (ctx, (details->type == GUM_IMPORT_FUNCTION)
            ? "function" : "variable"),
        JS_PROP_C_W_E);
  }
  JS_DefinePropertyValue (ctx, imp,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  if (details->module != NULL)
  {
    JS_DefinePropertyValue (ctx, imp,
        GUM_QUICK_CORE_ATOM (core, module),
        JS_NewString (ctx, details->module),
        JS_PROP_C_W_E);
  }
  if (details->address != 0)
  {
    JS_DefinePropertyValue (ctx, imp,
        GUM_QUICK_CORE_ATOM (core, address),
        _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (details->address),
            core),
        JS_PROP_C_W_E);
  }
  if (details->slot != 0)
  {
    JS_DefinePropertyValue (ctx, imp,
        GUM_QUICK_CORE_ATOM (core, slot),
        _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (details->slot),
            core),
        JS_PROP_C_W_E);
  }

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &imp);

  JS_FreeValue (ctx, imp);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_exports)
{
  GumQuickMatchContext mc;
  const gchar * name;

  if (!_gum_quick_args_parse (args, "sF{onMatch,onComplete}", &name,
      &mc.on_match, &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_module_enumerate_exports (name, (GumFoundExportFunc) gum_emit_export,
      &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_export (const GumExportDetails * details,
                 GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->core;
  JSValue exp, result;

  exp = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, exp,
      GUM_QUICK_CORE_ATOM (core, type),
      JS_NewString (ctx, (details->type == GUM_EXPORT_FUNCTION)
          ? "function" : "variable"),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, exp,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, exp,
      GUM_QUICK_CORE_ATOM (core, address),
      _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (details->address),
          core),
      JS_PROP_C_W_E);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &exp);

  JS_FreeValue (ctx, exp);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_symbols)
{
  GumQuickMatchContext mc;
  const gchar * name;

  if (!_gum_quick_args_parse (args, "sF{onMatch,onComplete}", &name,
      &mc.on_match, &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_module_enumerate_symbols (name, (GumFoundSymbolFunc) gum_emit_symbol,
      &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_symbol (const GumSymbolDetails * details,
                 GumQuickMatchContext * mc)
{
  const GumSymbolSection * section = details->section;
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->core;
  JSValue sym, result;

  sym = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, sym,
      GUM_QUICK_CORE_ATOM (core, isGlobal),
      JS_NewBool (ctx, details->is_global),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, sym,
      GUM_QUICK_CORE_ATOM (core, type),
      JS_NewString (ctx, gum_symbol_type_to_string (details->type)),
      JS_PROP_C_W_E);
  if (section != NULL)
  {
    JSValue sect = JS_NewObject (ctx);

    JS_DefinePropertyValue (ctx, sect,
        GUM_QUICK_CORE_ATOM (core, id),
        JS_NewString (ctx, section->id),
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, sect,
        GUM_QUICK_CORE_ATOM (core, protection),
        _gum_quick_page_protection_new (ctx, section->protection),
        JS_PROP_C_W_E);

    JS_DefinePropertyValue (ctx, sym,
        GUM_QUICK_CORE_ATOM (core, section),
        sect,
        JS_PROP_C_W_E);
  }
  JS_DefinePropertyValue (ctx, sym,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, sym,
      GUM_QUICK_CORE_ATOM (core, address),
      _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (details->address),
          core),
      JS_PROP_C_W_E);
  if (details->size != -1)
  {
    JS_DefinePropertyValue (ctx, sym,
        GUM_QUICK_CORE_ATOM (core, size),
        JS_NewInt64 (ctx, details->size),
        JS_PROP_C_W_E);
  }

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &sym);

  JS_FreeValue (ctx, sym);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_ranges)
{
  GumQuickMatchContext mc;
  gchar * name;
  GumPageProtection prot;

  if (!_gum_quick_args_parse (args, "smF{onMatch,onComplete}", &name, &prot,
      &mc.on_match, &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_module_enumerate_ranges (name, prot, (GumFoundRangeFunc) gum_emit_range,
      &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->core;
  JSValue d, result;

  d = _gum_quick_range_details_new (ctx, details, core);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &d);

  JS_FreeValue (ctx, d);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_sections)
{
  GumQuickMatchContext mc;
  gchar * name;

  if (!_gum_quick_args_parse (args, "sF{onMatch,onComplete}", &name,
      &mc.on_match, &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_module_enumerate_sections (name, (GumFoundSectionFunc) gum_emit_section,
      &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_section (const GumSectionDetails * details,
                  GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->core;
  JSValue section, result;

  section = JS_NewObject (ctx);
  JS_DefinePropertyValue (ctx, section,
      GUM_QUICK_CORE_ATOM (core, id),
      JS_NewString (ctx, details->id),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, section,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, section,
      GUM_QUICK_CORE_ATOM (core, address),
      _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (details->address),
          core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, section,
      GUM_QUICK_CORE_ATOM (core, size),
      JS_NewUint32 (ctx, details->size),
      JS_PROP_C_W_E);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &section);

  JS_FreeValue (ctx, section);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_dependencies)
{
  GumQuickMatchContext mc;
  gchar * name;

  if (!_gum_quick_args_parse (args, "sF{onMatch,onComplete}", &name,
      &mc.on_match, &mc.on_complete))
    return JS_EXCEPTION;
  mc.result = GUM_QUICK_MATCH_CONTINUE;
  mc.ctx = ctx;
  mc.core = core;

  gum_module_enumerate_dependencies (name,
      (GumFoundDependencyFunc) gum_emit_dependency, &mc);

  return _gum_quick_maybe_call_on_complete (ctx, mc.result, mc.on_complete);
}

static gboolean
gum_emit_dependency (const GumDependencyDetails * details,
                     GumQuickMatchContext * mc)
{
  JSContext * ctx = mc->ctx;
  GumQuickCore * core = mc->core;
  JSValue dep, result;

  dep = JS_NewObject (ctx);
  JS_DefinePropertyValue (ctx, dep,
      GUM_QUICK_CORE_ATOM (core, name),
      JS_NewString (ctx, details->name),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, dep,
      GUM_QUICK_CORE_ATOM (core, type),
      _gum_quick_enum_new (ctx, details->type, GUM_TYPE_DEPENDENCY_TYPE),
      JS_PROP_C_W_E);

  result = JS_Call (ctx, mc->on_match, JS_UNDEFINED, 1, &dep);

  JS_FreeValue (ctx, dep);

  return _gum_quick_process_match_result (ctx, &result, &mc->result);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_base_address)
{
  const gchar * name;
  GumAddress address;

  if (!_gum_quick_args_parse (args, "s", &name))
    return JS_EXCEPTION;

  address = gum_module_find_base_address (name);

  if (address == 0)
    return JS_NULL;

  return _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (address), core);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_export_by_name)
{
  const gchar * module_name, * symbol_name;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  GumAddress address;

  if (!_gum_quick_args_parse (args, "s?s", &module_name, &symbol_name))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  address = gum_module_find_export_by_name (module_name, symbol_name);

  _gum_quick_scope_resume (&scope);

  if (address == 0)
    return JS_NULL;

  return _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (address), core);
}

static gboolean
gum_quick_module_map_get (JSContext * ctx,
                          JSValueConst val,
                          GumQuickCore * core,
                          GumModuleMap ** map)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->module_map_class, core,
      (gpointer *) map);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_map_construct)
{
  JSValue wrapper = JS_NULL;
  GumQuickModule * parent;
  JSValue filter_callback;
  JSValue proto;
  GumModuleMap * map;

  parent = gumjs_get_parent_module (core);

  filter_callback = JS_NULL;
  if (!_gum_quick_args_parse (args, "|F", &filter_callback))
    return JS_EXCEPTION;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, parent->module_map_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    return JS_EXCEPTION;

  if (JS_IsNull (filter_callback))
  {
    map = gum_module_map_new ();
  }
  else
  {
    GumQuickModuleFilter * filter;

    filter = g_slice_new (GumQuickModuleFilter);
    filter->callback = filter_callback;
    filter->parent = parent;

    map = gum_module_map_new_filtered (
        (GumModuleMapFilterFunc) gum_quick_module_filter_matches,
        filter, (GDestroyNotify) gum_quick_module_filter_free);

    JS_DefinePropertyValue (ctx, wrapper,
        GUM_QUICK_CORE_ATOM (core, resource),
        JS_DupValue (ctx, filter_callback),
        0);
  }

  JS_SetOpaque (wrapper, map);

  return wrapper;
}

GUMJS_DEFINE_FINALIZER (gumjs_module_map_finalize)
{
  GumModuleMap * m;

  m = JS_GetOpaque (val, gumjs_get_parent_module (core)->module_map_class);
  if (m == NULL)
    return;

  g_object_unref (m);
}

GUMJS_DEFINE_GETTER (gumjs_module_map_get_handle)
{
  GumModuleMap * self;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx, self, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_has)
{
  GumModuleMap * self;
  gpointer address;
  const GumModuleDetails * details;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "p", &address))
    return JS_EXCEPTION;

  details = gum_module_map_find (self, GUM_ADDRESS (address));

  return JS_NewBool (ctx, details != NULL);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_find)
{
  GumModuleMap * self;
  gpointer address;
  const GumModuleDetails * details;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "p", &address))
    return JS_EXCEPTION;

  details = gum_module_map_find (self, GUM_ADDRESS (address));
  if (details == NULL)
    return JS_NULL;

  return _gum_quick_module_new (ctx, details, gumjs_get_parent_module (core));
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_find_name)
{
  GumModuleMap * self;
  gpointer address;
  const GumModuleDetails * details;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "p", &address))
    return JS_EXCEPTION;

  details = gum_module_map_find (self, GUM_ADDRESS (address));
  if (details == NULL)
    return JS_NULL;

  return JS_NewString (ctx, details->name);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_find_path)
{
  GumModuleMap * self;
  gpointer address;
  const GumModuleDetails * details;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "p", &address))
    return JS_EXCEPTION;

  details = gum_module_map_find (self, GUM_ADDRESS (address));
  if (details == NULL)
    return JS_NULL;

  return JS_NewString (ctx, details->path);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_update)
{
  GumModuleMap * self;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  gum_module_map_update (self);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_map_copy_values)
{
  JSValue result;
  GumModuleMap * self;
  GumQuickModule * parent;
  const GArray * values;
  guint i;

  if (!gum_quick_module_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  parent = gumjs_get_parent_module (core);

  values = gum_module_map_get_values (self);

  result = JS_NewArray (ctx);
  for (i = 0; i != values->len; i++)
  {
    GumModuleDetails * d = &g_array_index (values, GumModuleDetails, i);
    JS_DefinePropertyValueUint32 (ctx, result, i,
        _gum_quick_module_new (ctx, d, parent),
        JS_PROP_C_W_E);
  }

  return result;
}

static void
gum_quick_module_filter_free (GumQuickModuleFilter * filter)
{
  g_slice_free (GumQuickModuleFilter, filter);
}

static gboolean
gum_quick_module_filter_matches (const GumModuleDetails * details,
                                 GumQuickModuleFilter * self)
{
  GumQuickModule * parent = self->parent;
  GumQuickCore * core = parent->core;
  JSContext * ctx = core->ctx;
  gboolean is_match;
  JSValue m, v;

  m = _gum_quick_module_new (ctx, details, parent);

  v = _gum_quick_scope_call (core->current_scope, self->callback, JS_UNDEFINED,
      1, &m);

  is_match = JS_IsBool (v) && JS_VALUE_GET_BOOL (v);

  JS_FreeValue (ctx, v);
  JS_FreeValue (ctx, m);

  return is_match;
}

"""

```