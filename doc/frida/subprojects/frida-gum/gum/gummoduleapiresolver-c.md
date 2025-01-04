Response:
Let's break down the thought process for analyzing this C code and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to understand what this specific C file does within the Frida framework. The prompt specifically asks for:

* **Functionality:** What are its core actions?
* **Relation to Reversing:** How does it help in reverse engineering?
* **Low-Level Details:** Connections to binary formats, Linux/Android internals.
* **Logic and I/O:**  Hypothetical inputs and outputs.
* **User Errors:** Common mistakes when using it.
* **User Journey:** How a user might end up interacting with this code.

**2. Initial Code Scan and Keyword Identification:**

First, I'd quickly scan the code for important keywords and structures:

* **`GumModuleApiResolver`:** This is the main structure, likely the core component.
* **`GumApiResolver`:**  It implements this interface, suggesting a more general mechanism for API resolution.
* **`enumerate_matches`:** A key function for finding matching APIs.
* **`imports`, `exports`, `sections`:**  Keywords related to binary file structure.
* **`GumModuleMap`:**  Likely a data structure holding information about loaded modules.
* **`GHashTable`:**  Used for storing data efficiently (likely function names and metadata).
* **`GRegex`:** For pattern matching of queries.
* **`GumModuleDetails`, `GumImportDetails`, `GumExportDetails`, `GumSectionDetails`:** Structures holding information about modules and their components.
* **`gum_module_find_export_by_name`, `gum_module_enumerate_imports`, `gum_module_enumerate_exports`, `gum_module_enumerate_sections`:** Functions that directly interact with module information.

**3. Deciphering the Core Functionality (`enumerate_matches`):**

The `gum_module_api_resolver_enumerate_matches` function seems central. I'd analyze its steps:

* **Query Parsing:** It uses a regular expression (`query_pattern`) to parse the search query. The format looks like `collection:module!item`.
* **Module Iteration:** It iterates through loaded modules using `self->module_by_name`.
* **Filtering Modules:** It uses `g_pattern_spec_match_string` to filter modules based on the module part of the query.
* **Accessing Imports, Exports, Sections:** Based on the `collection` part of the query ("imports", "exports", or "sections"), it retrieves the corresponding information using functions like `gum_module_metadata_get_imports`.
* **Filtering Items:** It uses `g_pattern_spec_match_string` again to filter imports, exports, or sections based on the `item` part of the query.
* **Callback Invocation:**  For each matching API, it calls the `func` callback (of type `GumFoundApiFunc`) with the API details.

**4. Connecting to Reverse Engineering:**

With the understanding of `enumerate_matches`, the connection to reverse engineering becomes clear:

* **Dynamic Analysis:** Frida is a dynamic instrumentation tool. This code helps find functions and data within a *running* process.
* **API Discovery:**  Reverse engineers often need to find the addresses of specific functions or data structures to understand how software works. This resolver helps locate them by name within loaded modules.
* **Understanding Interactions:**  By finding imported and exported functions, a reverse engineer can understand how different modules interact.
* **Data Exploration:** Locating sections helps identify areas in memory where specific types of data (e.g., `.data`, `.bss`) are stored.

**5. Identifying Low-Level Details:**

The code hints at low-level concepts:

* **Binary Structure:** The terms "imports," "exports," and "sections" are fundamental concepts in executable file formats (like ELF on Linux/Android, PE on Windows).
* **Module Loading:** The existence of `GumModuleMap` and functions to enumerate imports, exports, and sections implies interaction with the operating system's module loading mechanism.
* **Memory Addresses:** `GumAddress` is used to represent memory addresses, a core concept in low-level programming.
* **System Calls (Implied):** While not directly visible in *this* file, the functions like `gum_module_enumerate_imports` would likely involve system calls to query the operating system about loaded modules.

**6. Constructing Hypothetical I/O:**

Based on the query format and functionality, creating input/output examples becomes straightforward:

* **Input:**  `exports:libc.so!open` (Find the `open` function in `libc.so` exports)
* **Output:**  Details about the `open` function (name, address, potentially size).

**7. Identifying User Errors:**

Considering how users might interact with the API resolver through Frida, potential errors emerge:

* **Incorrect Query Syntax:**  Mistyping the query format.
* **Typos in Module or Item Names:**  Spelling errors.
* **Wildcard Issues:** Misunderstanding how wildcards work in the query.
* **Case Sensitivity (Potentially):**  The code has logic for case-insensitive searching, but users might assume it's always case-insensitive.

**8. Tracing the User Journey:**

Thinking about how a Frida user would use this leads to the following steps:

1. **Attach to a Process:** The user would first need to attach Frida to a running process.
2. **Access the API Resolver:** Frida's API would provide a way to access the API resolver. This might involve using `Module.enumerateExports()`, `Module.enumerateImports()`, or a more direct `ApiResolver` interface.
3. **Construct a Query:** The user would formulate a query string based on what they want to find.
4. **Execute the Query:** Frida would then use the `GumModuleApiResolver` to process the query.
5. **Receive Results:** The `GumFoundApiFunc` callback would be invoked for each match, providing the user with the API details.

**9. Iterative Refinement:**

Throughout this process, I'd constantly refer back to the code and the prompt to ensure accuracy and completeness. For instance, noticing the `ignore_case` logic in `enumerate_matches` would be important for accurately describing the functionality and potential user errors.

By following these steps, combining code analysis with an understanding of Frida's purpose and common reverse engineering tasks, a comprehensive answer like the example can be constructed.
好的，让我们来分析一下 `frida/subprojects/frida-gum/gum/gummoduleapiresolver.c` 这个文件的功能。

**文件功能概述**

`GumModuleApiResolver` 的主要功能是在当前加载的模块中搜索特定的 API（应用程序编程接口）。它通过检查模块的导出符号表（exports）、导入符号表（imports）以及节区（sections）来定位目标 API。

这个文件实现了 `GumApiResolver` 接口，这意味着它是 Frida 中用于解析 API 地址的一种机制。Frida 允许用户通过名称来查找函数或数据，而 `GumModuleApiResolver` 就是负责在模块级别进行查找的组件。

**与逆向方法的关系及举例**

`GumModuleApiResolver` 与动态逆向分析紧密相关。在逆向工程中，经常需要定位特定函数的地址以便进行 hook、追踪或分析其行为。

**举例说明：**

假设你想 hook `libc.so` 中的 `open` 函数，以便在程序打开文件时记录相关信息。你可以使用 Frida 的 API，而 Frida 内部就会使用 `GumModuleApiResolver` 来找到 `open` 函数的地址。

```javascript
// JavaScript 代码，用于 Frida hook
Interceptor.attach(Module.findExportByName("libc.so", "open"), {
  onEnter: function (args) {
    console.log("Opening file:", args[0].readUtf8String());
  },
  onLeave: function (retval) {
    console.log("Open returned:", retval);
  }
});
```

在幕后，`Module.findExportByName("libc.so", "open")` 这个 JavaScript 函数会调用 Frida 的 Gum 核心库，最终会使用 `GumModuleApiResolver` 来执行以下操作：

1. **查找模块：**  根据模块名 "libc.so" 找到对应的模块信息。
2. **查找导出：** 在 `libc.so` 的导出符号表中查找名为 "open" 的符号。
3. **返回地址：** 如果找到，则返回 `open` 函数的内存地址。

**涉及的二进制底层、Linux/Android 内核及框架知识**

* **二进制文件结构：**  理解可执行文件（如 ELF）的结构至关重要，特别是导出符号表、导入符号表和节区的概念。`GumModuleApiResolver` 需要解析这些结构来查找 API。
    * **导出符号表：**  列出了模块提供的可以被其他模块调用的函数和全局变量。
    * **导入符号表：**  列出了模块依赖的其他模块提供的函数和全局变量。
    * **节区：**  将程序的不同部分（代码、数据等）组织成逻辑段。
* **模块加载：**  需要了解操作系统如何加载动态链接库（.so 文件在 Linux/Android 中）。Frida 需要获取当前进程加载的所有模块的信息。
* **内存地址：**  `GumAddress` 类型表示内存地址，这是进行 hook 和动态分析的基础。
* **操作系统 API：**  Frida 内部会使用操作系统提供的 API 来获取模块信息，例如在 Linux 中可以使用 `dlopen`、`dlsym` 等相关函数，或者读取 `/proc/[pid]/maps` 文件。在 Android 中，可能涉及到解析 `/proc/[pid]/maps` 或使用 linker 的 API。
* **Android Framework (部分相关)：**  虽然这个文件本身不直接涉及 Android Framework 的高级概念，但 Frida 常用于分析 Android 应用，因此理解 Android 的进程模型和库加载机制是有帮助的。

**逻辑推理、假设输入与输出**

`gum_module_api_resolver_enumerate_matches` 函数是核心，它根据查询字符串来查找匹配的 API。

**假设输入：**

* `query`:  一个字符串，指定要查找的 API。格式为 `(imports|exports|sections):模块名!符号名(/i)?`，例如：
    * `exports:libc.so!open` (查找 `libc.so` 导出的 `open` 函数)
    * `imports:my_app!MessageBoxA` (查找名为 `my_app` 的模块导入的 `MessageBoxA` 函数)
    * `sections:libart.so!.text` (查找 `libart.so` 中名为 `.text` 的节区)
    * `exports:libnative-lib.so!JNI_OnLoad/i` (查找 `libnative-lib.so` 导出的 `JNI_OnLoad` 函数，忽略大小写)
* `func`: 一个回调函数 `GumFoundApiFunc`，当找到匹配的 API 时会被调用，参数包含 API 的详细信息（名称、地址、大小）。
* `user_data`: 用户提供的数据，会传递给回调函数。

**假设输出（回调函数的调用）：**

如果输入的 `query` 是 `exports:libc.so!open` 并且 `libc.so` 中存在导出的 `open` 函数，则 `func` 回调函数会被调用，`GumApiDetails` 结构体可能包含以下信息：

* `details.name`: "libc.so!open"
* `details.address`: `open` 函数在内存中的地址 (例如：0xb778a180)
* `details.size`:  `GUM_API_SIZE_NONE` (通常函数的大小不会在这里直接提供)

如果 `query` 是 `imports:my_app!MessageBoxA` 并且 `my_app` 导入了 `MessageBoxA`，则 `details.name` 可能是 "USER32.dll!MessageBoxA"， `details.address` 是 `MessageBoxA` 在内存中的地址。

**涉及用户或编程常见的使用错误**

* **查询字符串格式错误：** 用户可能没有按照指定的格式编写查询字符串，例如忘记了 `!` 分隔符，或者使用了错误的集合名称（不是 `imports`, `exports`, `sections`）。
    * **示例：** 使用 `"libc.so_open"` 而不是 `"exports:libc.so!open"`。
* **模块或符号名称拼写错误：**  如果模块或符号的名称拼写错误，`GumModuleApiResolver` 将无法找到匹配项。
    * **示例：** 使用 `"liblc.so"` 而不是 `"libc.so"`。
* **大小写敏感性问题：**  默认情况下，搜索是区分大小写的。如果用户没有使用 `/i` 标志，但目标符号的大小写不匹配，则会找不到。
    * **示例：** 查找 `"open"` 但实际导出的是 `"Open"`。
* **目标 API 不存在：** 用户尝试查找的 API 根本不存在于指定的模块中。
* **在错误的上下文中查找：**  例如，尝试在一个没有加载目标模块的进程中查找其 API。

**用户操作是如何一步步到达这里的（作为调试线索）**

1. **用户编写 Frida 脚本：** 用户开始编写一个 Frida 脚本，目标是 hook 或分析某个应用程序。
2. **使用 Frida 的 API 查找 API：** 在脚本中，用户使用 Frida 提供的 API 来查找目标函数的地址，例如：
   * `Module.findExportByName("module_name", "function_name")`
   * `Module.findImportByName("module_name", "function_name")`
   * `Module.enumerateExports()` 或 `Module.enumerateImports()` 结合过滤条件
   * `Process.findModuleByName("module_name").base` (获取模块基址，虽然不直接通过这个文件，但相关)
3. **Frida 内部调用 Gum 的 API：**  这些 Frida 的 JavaScript API 在底层会调用 Frida 的 Gum 核心库。
4. **调用 `gum_module_api_resolver_new` 创建解析器：** 当需要解析模块级别的 API 时，会创建 `GumModuleApiResolver` 的实例。
5. **调用 `gum_module_api_resolver_enumerate_matches` 执行查找：**  用户提供的模块名和符号名（或模式）会被传递给 `gum_module_api_resolver_enumerate_matches` 函数。
6. **解析查询字符串：**  `gum_module_api_resolver_enumerate_matches` 首先会解析用户提供的查询字符串。
7. **遍历模块：**  接着，它会遍历当前进程加载的所有模块。
8. **查找符号表或节区：**  对于每个匹配的模块，它会根据查询类型（imports, exports, sections）读取相应的符号表或节区信息。
9. **匹配符号或节区名称：**  它会将符号或节区的名称与查询中的模式进行匹配（可以使用通配符）。
10. **调用回调函数：**  如果找到匹配的 API，`GumFoundApiFunc` 回调函数会被调用，将 API 的详细信息传递给用户脚本。

**调试线索：**

如果用户在使用 Frida 时遇到 API 查找失败的问题，可以检查以下几点，这些都与 `GumModuleApiResolver` 的行为有关：

* **确认目标模块已加载：** 使用 `Process.enumerateModules()` 检查目标模块是否确实被加载到进程中。
* **检查符号名称拼写和大小写：** 使用类似 `readelf -s <module.so>` (Linux) 或相关工具查看模块的符号表，确认符号名称和大小写是否正确。
* **确认查询字符串格式正确：**  仔细检查查询字符串的格式是否符合要求。
* **查看 Frida 的日志输出：**  Frida 可能会输出一些调试信息，帮助定位问题。
* **逐步调试 Frida 脚本：**  在 Frida 脚本中使用 `console.log` 输出中间结果，例如要查找的模块名和符号名，以确认传递给 Frida API 的参数是否正确。

希望以上分析能够帮助你理解 `frida/subprojects/frida-gum/gum/gummoduleapiresolver.c` 文件的功能和它在 Frida 中的作用。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/gummoduleapiresolver.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2016-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2020 Grant Douglas <grant@reconditorium.uk>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

/**
 * GumModuleApiResolver:
 *
 * Resolves APIs by searching exports, imports, and sections of currently loaded
 * modules.
 *
 * See [iface@Gum.ApiResolver] for more information.
 */

#ifndef GUM_DIET

#include "gummoduleapiresolver.h"

#include "gummodulemap.h"
#include "gumprocess.h"

#include <string.h>

typedef struct _GumModuleMetadata GumModuleMetadata;
typedef struct _GumFunctionMetadata GumFunctionMetadata;

struct _GumModuleApiResolver
{
  GObject parent;

  GRegex * query_pattern;

  GumModuleMap * all_modules;
  GHashTable * module_by_name;
};

struct _GumModuleMetadata
{
  gint ref_count;

  const gchar * name;
  const gchar * path;

  GHashTable * import_by_name;
  GHashTable * export_by_name;
  GArray * sections;
};

struct _GumFunctionMetadata
{
  gchar * name;
  GumAddress address;
  gchar * module;
};

static void gum_module_api_resolver_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_module_api_resolver_finalize (GObject * object);
static void gum_module_api_resolver_enumerate_matches (
    GumApiResolver * resolver, const gchar * query, GumFoundApiFunc func,
    gpointer user_data, GError ** error);

static void gum_module_metadata_unref (GumModuleMetadata * module);
static GHashTable * gum_module_metadata_get_imports (GumModuleMetadata * self);
static GHashTable * gum_module_metadata_get_exports (GumModuleMetadata * self);
static GArray * gum_module_metadata_get_sections (GumModuleMetadata * self);
static gboolean gum_module_metadata_collect_import (
    const GumImportDetails * details, gpointer user_data);
static gboolean gum_module_metadata_collect_export (
    const GumExportDetails * details, gpointer user_data);
static gboolean gum_module_metadata_collect_section (
    const GumSectionDetails * details, gpointer user_data);

static GumFunctionMetadata * gum_function_metadata_new (const gchar * name,
    GumAddress address, const gchar * module);
static void gum_function_metadata_free (GumFunctionMetadata * function);

static void gum_section_details_free (GumSectionDetails * self);

G_DEFINE_TYPE_EXTENDED (GumModuleApiResolver,
                        gum_module_api_resolver,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_API_RESOLVER,
                            gum_module_api_resolver_iface_init))

static void
gum_module_api_resolver_class_init (GumModuleApiResolverClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_module_api_resolver_finalize;
}

static void
gum_module_api_resolver_iface_init (gpointer g_iface,
                                    gpointer iface_data)
{
  GumApiResolverInterface * iface = g_iface;

  iface->enumerate_matches = gum_module_api_resolver_enumerate_matches;
}

static void
gum_module_api_resolver_init (GumModuleApiResolver * self)
{
  GArray * entries;
  guint i;

  self->query_pattern =
      g_regex_new ("(imports|exports|sections):(.+)!([^\\n\\r\\/]+)(\\/i)?",
          0, 0, NULL);

  self->all_modules = gum_module_map_new ();
  self->module_by_name = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      (GDestroyNotify) gum_module_metadata_unref);
  entries = gum_module_map_get_values (self->all_modules);
  for (i = 0; i != entries->len; i++)
  {
    GumModuleDetails * d = &g_array_index (entries, GumModuleDetails, i);
    GumModuleMetadata * module;

    module = g_slice_new (GumModuleMetadata);
    module->ref_count = 2;
    module->name = d->name;
    module->path = d->path;
    module->import_by_name = NULL;
    module->export_by_name = NULL;
    module->sections = NULL;

    g_hash_table_insert (self->module_by_name, g_strdup (module->name), module);
    g_hash_table_insert (self->module_by_name, g_strdup (module->path), module);
  }
}

static void
gum_module_api_resolver_finalize (GObject * object)
{
  GumModuleApiResolver * self = GUM_MODULE_API_RESOLVER (object);

  g_hash_table_unref (self->module_by_name);
  g_object_unref (self->all_modules);

  g_regex_unref (self->query_pattern);

  G_OBJECT_CLASS (gum_module_api_resolver_parent_class)->finalize (object);
}

/**
 * gum_module_api_resolver_new:
 *
 * Creates a new resolver that searches exports and imports of currently loaded
 * modules.
 *
 * Returns: (transfer full): the newly created resolver instance
 */
GumApiResolver *
gum_module_api_resolver_new (void)
{
  return g_object_new (GUM_TYPE_MODULE_API_RESOLVER, NULL);
}

static void
gum_module_api_resolver_enumerate_matches (GumApiResolver * resolver,
                                           const gchar * query,
                                           GumFoundApiFunc func,
                                           gpointer user_data,
                                           GError ** error)
{
  GumModuleApiResolver * self = GUM_MODULE_API_RESOLVER (resolver);
  GMatchInfo * query_info;
  gboolean ignore_case;
  gchar * collection, * module_query, * item_query;
  gboolean no_patterns_in_item_query;
  GPatternSpec * module_spec, * item_spec;
  GHashTableIter module_iter;
  GHashTable * seen_modules;
  gboolean carry_on;
  GumModuleMetadata * module;

  g_regex_match (self->query_pattern, query, 0, &query_info);
  if (!g_match_info_matches (query_info))
    goto invalid_query;

  ignore_case = g_match_info_get_match_count (query_info) >= 5;

  collection = g_match_info_fetch (query_info, 1);
  module_query = g_match_info_fetch (query_info, 2);
  item_query = g_match_info_fetch (query_info, 3);

  g_match_info_free (query_info);

  if (ignore_case)
  {
    gchar * str;

    str = g_utf8_strdown (module_query, -1);
    g_free (module_query);
    module_query = str;

    str = g_utf8_strdown (item_query, -1);
    g_free (item_query);
    item_query = str;
  }

  no_patterns_in_item_query =
      !ignore_case &&
      strchr (item_query, '*') == NULL &&
      strchr (item_query, '?') == NULL;

  module_spec = g_pattern_spec_new (module_query);
  item_spec = g_pattern_spec_new (item_query);

  g_hash_table_iter_init (&module_iter, self->module_by_name);
  seen_modules = g_hash_table_new (NULL, NULL);
  carry_on = TRUE;

  while (carry_on &&
      g_hash_table_iter_next (&module_iter, NULL, (gpointer *) &module))
  {
    const gchar * module_name = module->name;
    const gchar * module_path = module->path;
    gchar * module_name_copy = NULL;
    gchar * module_path_copy = NULL;

    if (g_hash_table_contains (seen_modules, module))
      continue;
    g_hash_table_add (seen_modules, module);

    if (ignore_case)
    {
      module_name_copy = g_utf8_strdown (module_name, -1);
      module_name = module_name_copy;

      module_path_copy = g_utf8_strdown (module_path, -1);
      module_path = module_path_copy;
    }

    if (g_pattern_spec_match_string (module_spec, module_name) ||
        g_pattern_spec_match_string (module_spec, module_path))
    {
      GHashTable * functions;
      GHashTableIter function_iter;
      GumFunctionMetadata * function;

      if (collection[0] == 's')
      {
        GArray * sections;
        guint i;

        sections = gum_module_metadata_get_sections (module);
        for (i = 0; i != sections->len; i++)
        {
          const GumSectionDetails * section = &g_array_index (sections,
              GumSectionDetails, i);

          if (g_pattern_spec_match_string (item_spec, section->name))
          {
            GumApiDetails details;

            details.name = g_strconcat (
                module->path,
                "!",
                section->id,
                NULL);
            details.address = section->address;
            details.size = section->size;

            carry_on = func (&details, user_data);

            g_free ((gpointer) details.name);
          }
        }

        continue;
      }

      if (collection[0] == 'e' && no_patterns_in_item_query)
      {
        GumApiDetails details;

        details.address =
            gum_module_find_export_by_name (module->path, item_query);
        details.size = GUM_API_SIZE_NONE;

#ifndef HAVE_WINDOWS
        if (details.address != 0)
        {
          const GumModuleDetails * module_containing_address;
          gboolean match_is_in_a_different_module;

          module_containing_address =
              gum_module_map_find (self->all_modules, details.address);

          match_is_in_a_different_module =
              module_containing_address != NULL &&
              strcmp (module_containing_address->path, module->path) != 0;

          if (match_is_in_a_different_module)
            details.address = 0;
        }
#endif

        if (details.address != 0)
        {
          details.name = g_strconcat (module->path, "!", item_query, NULL);

          carry_on = func (&details, user_data);

          g_free ((gpointer) details.name);
        }

        g_assert (module_name_copy == NULL && module_path_copy == NULL);

        continue;
      }

      functions = (collection[0] == 'i')
          ? gum_module_metadata_get_imports (module)
          : gum_module_metadata_get_exports (module);

      g_hash_table_iter_init (&function_iter, functions);
      while (carry_on &&
          g_hash_table_iter_next (&function_iter, NULL, (gpointer *) &function))
      {
        const gchar * function_name = function->name;
        gchar * function_name_copy = NULL;

        if (ignore_case)
        {
          function_name_copy = g_utf8_strdown (function_name, -1);
          function_name = function_name_copy;
        }

        if (g_pattern_spec_match_string (item_spec, function_name))
        {
          GumApiDetails details;

          details.name = g_strconcat (
              (function->module != NULL) ? function->module : module->path,
              "!",
              function->name,
              NULL);
          details.address = function->address;
          details.size = GUM_API_SIZE_NONE;

          carry_on = func (&details, user_data);

          g_free ((gpointer) details.name);
        }

        g_free (function_name_copy);
      }
    }

    g_free (module_path_copy);
    g_free (module_name_copy);
  }

  g_hash_table_unref (seen_modules);

  g_pattern_spec_free (item_spec);
  g_pattern_spec_free (module_spec);

  g_free (item_query);
  g_free (module_query);
  g_free (collection);

  return;

invalid_query:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "invalid query; format is: "
        "exports:*!open*, exports:libc.so!*, imports:notepad.exe!*, "
        "or sections:libc.so!*data*");
  }
}

static void
gum_module_metadata_unref (GumModuleMetadata * module)
{
  module->ref_count--;
  if (module->ref_count == 0)
  {
    if (module->sections != NULL)
      g_array_unref (module->sections);

    if (module->export_by_name != NULL)
      g_hash_table_unref (module->export_by_name);

    if (module->import_by_name != NULL)
      g_hash_table_unref (module->import_by_name);

    g_slice_free (GumModuleMetadata, module);
  }
}

static GHashTable *
gum_module_metadata_get_imports (GumModuleMetadata * self)
{
  if (self->import_by_name == NULL)
  {
    self->import_by_name = g_hash_table_new_full (g_str_hash, g_str_equal,
        g_free, (GDestroyNotify) gum_function_metadata_free);
    gum_module_enumerate_imports (self->path,
        gum_module_metadata_collect_import, self->import_by_name);
  }

  return self->import_by_name;
}

static GHashTable *
gum_module_metadata_get_exports (GumModuleMetadata * self)
{
  if (self->export_by_name == NULL)
  {
    self->export_by_name = g_hash_table_new_full (g_str_hash, g_str_equal,
        g_free, (GDestroyNotify) gum_function_metadata_free);
    gum_module_enumerate_exports (self->path,
        gum_module_metadata_collect_export, self->export_by_name);
  }

  return self->export_by_name;
}

static GArray *
gum_module_metadata_get_sections (GumModuleMetadata * self)
{
  if (self->sections == NULL)
  {
    self->sections = g_array_new (FALSE, FALSE, sizeof (GumSectionDetails));
    g_array_set_clear_func (self->sections,
        (GDestroyNotify) gum_section_details_free);
    gum_module_enumerate_sections (self->path,
        gum_module_metadata_collect_section, self->sections);
  }

  return self->sections;
}

static gboolean
gum_module_metadata_collect_import (const GumImportDetails * details,
                                    gpointer user_data)
{
  GHashTable * import_by_name = user_data;

  if (details->type == GUM_IMPORT_FUNCTION && details->address != 0)
  {
    GumFunctionMetadata * function;

    function = gum_function_metadata_new (details->name, details->address,
        details->module);
    g_hash_table_insert (import_by_name, g_strdup (function->name), function);
  }

  return TRUE;
}

static gboolean
gum_module_metadata_collect_export (const GumExportDetails * details,
                                    gpointer user_data)
{
  GHashTable * export_by_name = user_data;

  if (details->type == GUM_EXPORT_FUNCTION)
  {
    GumFunctionMetadata * function;

    function = gum_function_metadata_new (details->name, details->address,
        NULL);
    g_hash_table_insert (export_by_name, g_strdup (function->name), function);
  }

  return TRUE;
}

static gboolean
gum_module_metadata_collect_section (const GumSectionDetails * details,
                                     gpointer user_data)
{
  GArray * sections = user_data;
  GumSectionDetails d;

  d = *details;
  d.id = g_strdup (d.id);
  d.name = g_strdup (d.name);
  g_array_append_val (sections, d);

  return TRUE;
}

static GumFunctionMetadata *
gum_function_metadata_new (const gchar * name,
                           GumAddress address,
                           const gchar * module)
{
  GumFunctionMetadata * function;

  function = g_slice_new (GumFunctionMetadata);
  function->name = g_strdup (name);
  function->address = address;
  function->module = g_strdup (module);

  return function;
}

static void
gum_function_metadata_free (GumFunctionMetadata * function)
{
  g_free (function->module);
  g_free (function->name);

  g_slice_free (GumFunctionMetadata, function);
}

static void
gum_section_details_free (GumSectionDetails * self)
{
  g_free ((gpointer) self->id);
  g_free ((gpointer) self->name);
}

#endif

"""

```