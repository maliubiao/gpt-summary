Response:
Let's break down the thought process for analyzing this C code snippet for Frida.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C code for Frida and explain its functionality, connections to reverse engineering, low-level details, logical inferences, potential user errors, and how a user might reach this code.

**2. Initial Code Scan and Identification of Key Components:**

The first step is a quick scan to identify recognizable patterns and structures. Keywords like `struct`, `typedef`, function declarations (`GUMJS_DECLARE_FUNCTION`), `static`, and the `gum` prefix immediately stand out. The `#include` directives also provide crucial context (`gum/gumsymbolutil.h`).

* **Data Structures:** The `GumSymbol` struct is central, holding information about a symbol (resolved status and details).
* **Function Declarations:**  The `GUMJS_DECLARE_FUNCTION` macros suggest functions that are likely exposed to the JavaScript side of Frida. The names are suggestive (e.g., `gumjs_symbol_from_address`, `gumjs_symbol_from_name`).
* **Static Functions:** Functions prefixed with `static` are internal helpers within this C file.
* **`gum` Prefix:** This indicates interaction with the core Frida Gum library.
* **JavaScript Interaction:** The presence of `JSContext`, `JSValue`, and functions manipulating them strongly suggests this code bridges C and JavaScript.

**3. Analyzing Function Functionality (Grouping by Purpose):**

Next, analyze each function, grouping them by their apparent purpose:

* **Symbol Creation:** `gum_symbol_new`, `gumjs_symbol_construct` (although the latter throws an error, indicating it's not for direct user creation). These are responsible for creating the internal `GumSymbol` objects.
* **Symbol Resolution:** `gumjs_symbol_from_address`, `gumjs_symbol_from_name`. These are the primary ways to create a `DebugSymbol` object by providing either an address or a name.
* **Symbol Information Retrieval (Getters):** `gumjs_symbol_get_address`, `gumjs_symbol_get_name`, `gumjs_symbol_get_module_name`, etc. These provide access to the details of a resolved symbol.
* **Symbol Searching:** `gumjs_symbol_get_function_by_name`, `gumjs_symbol_find_functions_named`, `gumjs_symbol_find_functions_matching`. These allow searching for functions by name or pattern.
* **Symbol Loading:** `gumjs_symbol_load`. This function likely loads debugging symbols from a file.
* **String and JSON Representation:** `gumjs_symbol_to_string`, `gumjs_symbol_to_json`. These handle converting the symbol information into human-readable strings or structured JSON.
* **Internal Helpers:** Functions like `gumjs_get_parent_module`, `gum_quick_pointer_array_new`, `gum_symbol_get`. These assist the main functions.

**4. Connecting to Reverse Engineering:**

Now, think about how these functions are relevant to reverse engineering:

* **Inspecting Memory:** `gumjs_symbol_from_address` allows looking up symbols at specific memory locations, crucial for understanding what code is being executed.
* **Finding Functions:** `gumjs_symbol_from_name`, `gumjs_symbol_get_function_by_name`, `gumjs_symbol_find_functions_named`, `gumjs_symbol_find_functions_matching` are essential for locating functions of interest within a target process. This is fundamental for hooking and analysis.
* **Understanding Code Structure:** The getters provide details like module name, filename, and line number, which help map addresses back to source code, aiding in understanding the application's structure.
* **Dynamic Analysis:** Frida is a *dynamic* instrumentation tool. This code enables real-time symbol resolution during the execution of a program.

**5. Identifying Low-Level Concepts:**

Consider the underlying operating system and architecture:

* **Memory Addresses:** The core concept revolves around memory addresses and how symbols relate to them.
* **Modules/Libraries:** The code deals with module names, indicating an understanding of how programs are organized into libraries.
* **Debugging Symbols:** The presence of `gum_load_symbols` and the details extracted (filename, line number) point to the use of debugging information (like DWARF).
* **Function Pointers:** The functions returning "native pointers" (`_gum_quick_native_pointer_new`) are returning memory addresses that can be treated as function entry points.
* **Linux/Android:** Although not explicitly tied to a specific kernel in *this* file, the concepts of processes, memory spaces, and shared libraries are common to both. Frida's usage is prevalent on these platforms.

**6. Logical Inferences and Examples:**

Consider how the functions might be used and what the inputs and outputs would be:

* **`fromAddress`:** Input: a memory address (e.g., `0x7ffff7a00000`). Output: a `DebugSymbol` object (if resolved, containing name, module, etc.; otherwise, just the address).
* **`fromName`:** Input: a function name (e.g., `"malloc"`). Output: a `DebugSymbol` object (containing the address and details of `malloc`).
* **`findFunctionsNamed`:** Input: a function name (e.g., `"open"`). Output: an array of memory addresses of all functions named "open" in the loaded modules.

**7. Potential User Errors:**

Think about how a developer using Frida might misuse these functions:

* **Invalid Address:** Passing an address that doesn't correspond to any loaded code or data. This might result in a `DebugSymbol` with `resolved` being false.
* **Incorrect Function Name:**  Typing a function name incorrectly will lead to `fromName` or `getFunctionByName` failing to find the symbol.
* **Loading Wrong Symbols:** Using `load` with an incorrect or irrelevant symbol file won't provide useful information.
* **Not Loading Symbols:** Trying to get detailed information (filename, line number) when symbols haven't been loaded will result in null or zero values for those properties.

**8. Tracing User Interaction:**

Imagine a typical Frida script:

1. **`Frida.attach(...)`**:  The user attaches to a process.
2. **`Module.getBaseAddress(...)` or `Process.enumerateModules()`**: The user might get the base address of a module.
3. **`DebugSymbol.fromAddress(address)`**: The user uses the obtained address to create a `DebugSymbol`.
4. **Accessing properties**: The user accesses properties like `symbol.name`, `symbol.moduleName`, etc. to inspect the symbol.
5. **`DebugSymbol.findFunctionsNamed("someFunction")`**: The user searches for functions by name.
6. **`DebugSymbol.load("/path/to/symbols")`**: The user explicitly loads symbols for more detailed information.

**9. Structuring the Explanation:**

Finally, organize the gathered information into the requested categories (functionality, reverse engineering, low-level details, etc.), providing clear explanations and examples. Use bullet points and code snippets to enhance readability.

This iterative process of code scanning, functional analysis, connecting to domain knowledge (reverse engineering, OS concepts), and considering usage scenarios allows for a comprehensive understanding of the provided C code.
这个文件 `gumquicksymbol.c` 是 Frida 中 `frida-gum` 库的一部分，负责在 JavaScript 中提供访问和操作程序符号 (symbols) 的功能。 符号通常指的是函数名、变量名等，它们在程序编译链接后被记录在可执行文件或共享库的符号表中，用于调试和链接。

**功能列举：**

1. **创建 `DebugSymbol` 对象:**
   - `gumjs_symbol_from_address`:  根据给定的内存地址创建一个 `DebugSymbol` 对象。
   - `gumjs_symbol_from_name`:  根据给定的符号名称创建一个 `DebugSymbol` 对象。
   - `gum_symbol_new`:  这是一个内部函数，用于实际分配和初始化 `DebugSymbol` 结构体。

2. **查找符号:**
   - `gumjs_symbol_get_function_by_name`: 根据函数名查找函数的地址。如果找不到，会抛出异常。
   - `gumjs_symbol_find_functions_named`:  查找所有具有给定名称的函数，返回一个包含函数地址的数组。
   - `gumjs_symbol_find_functions_matching`:  根据给定的正则表达式查找匹配的函数名，返回一个包含函数地址的数组。

3. **加载符号:**
   - `gumjs_symbol_load`:  加载指定路径的符号文件 (例如 .so 的调试符号)。这允许 Frida 获取更详细的符号信息，如文件名和行号。

4. **访问 `DebugSymbol` 对象的属性 (Getters):**
   - `gumjs_symbol_get_address`: 获取符号的内存地址。
   - `gumjs_symbol_get_name`: 获取符号的名称。
   - `gumjs_symbol_get_module_name`: 获取符号所在模块 (例如共享库) 的名称。
   - `gumjs_symbol_get_file_name`: 获取符号定义所在的文件名 (需要加载符号)。
   - `gumjs_symbol_get_line_number`: 获取符号定义所在的行号 (需要加载符号)。
   - `gumjs_symbol_get_column`: 获取符号定义所在的列号 (需要加载符号)。

5. **将 `DebugSymbol` 对象转换为字符串或 JSON:**
   - `gumjs_symbol_to_string`:  将 `DebugSymbol` 对象转换为易于阅读的字符串表示形式，包含地址、模块名、符号名以及可能的文件名和行号。
   - `gumjs_symbol_to_json`: 将 `DebugSymbol` 对象转换为 JSON 格式，方便在 JavaScript 中处理。

**与逆向方法的关系及举例：**

这个文件是 Frida 逆向工具的核心组成部分，其功能直接服务于动态分析和逆向工程：

* **动态定位函数地址:**  通过 `fromName` 或 `getFunctionByName`，逆向工程师可以在运行时根据函数名称找到其在内存中的地址。这对于 hook (拦截和修改函数行为) 非常关键。

   **举例:**  假设你想 hook `open` 系统调用来监控程序的打开文件行为。你可以使用 Frida 的 JavaScript API，最终会调用到这里的 C 代码：
   ```javascript
   const openPtr = Module.findExportByName(null, 'open'); // 或者使用 DebugSymbol.fromName('open').address
   Interceptor.attach(openPtr, {
     onEnter: function (args) {
       console.log('Opening file:', args[0].readUtf8String());
     }
   });
   ```
   `Module.findExportByName` 内部可能会利用符号查找机制，而 `DebugSymbol.fromName` 会直接调用 `gumjs_symbol_from_name`。

* **识别代码模块和结构:**  通过 `get_module_name`，可以确定特定地址或符号属于哪个共享库或可执行文件。这有助于理解程序的模块化结构。

   **举例:**  在分析一个大型应用时，你可能会遇到一个未知的函数地址。使用 `DebugSymbol.fromAddress(unknownAddress).moduleName` 可以快速确定该函数属于哪个模块，从而缩小分析范围。

* **获取更详细的调试信息:**  通过 `load` 加载符号文件后，可以获取文件名和行号，这对于理解代码逻辑至关重要，尤其是在没有源代码的情况下。

   **举例:**  当你 hook 一个函数时，`this.fileName` 和 `this.lineNumber` (在 JavaScript 中访问 `DebugSymbol` 对象) 可以告诉你被 hook 的代码在源代码中的位置，即使你没有应用的完整源代码。

* **批量查找函数:**  `findFunctionsNamed` 和 `findFunctionsMatching` 允许批量查找具有特定名称或模式的函数，这对于识别特定功能的实现或查找潜在的漏洞点非常有用。

   **举例:**  你可以使用 `DebugSymbol.findFunctionsNamed('encrypt')` 来查找所有名称包含 "encrypt" 的函数，从而快速定位可能的加密算法实现。

**涉及到的二进制底层、Linux/Android 内核及框架的知识：**

* **二进制文件结构:**  代码需要理解可执行文件和共享库的结构，特别是符号表 (symbol table) 的格式，以便查找和解析符号信息。
* **内存地址空间:**  所有操作都围绕着内存地址展开，需要理解进程的地址空间布局，如何加载和管理代码段、数据段等。
* **动态链接:**  `gum_find_function` 等函数需要理解动态链接器 (例如 ld-linux.so) 的工作原理，如何解析符号并将其绑定到内存地址。
* **ELF 格式 (Linux):**  在 Linux 系统上，可执行文件和共享库通常是 ELF 格式，符号信息存储在 ELF 结构的特定 section 中。
* **Dwarf 调试信息:**  `gum_load_symbols` 函数涉及到解析 DWARF 等调试信息格式，这些信息包含了文件名、行号等更详细的源代码级别信息.
* **Android 的 Bionic libc:**  在 Android 上，符号查找可能涉及到 Bionic libc 提供的接口。
* **动态加载库:**  Frida 可以在运行时加载和卸载库，这需要与操作系统提供的动态链接 API 进行交互。

**逻辑推理及假设输入与输出：**

假设输入：一个进程中 `malloc` 函数的地址为 `0x7ffff7badd90`。

调用 `gumjs_symbol_from_address(ctx, address)`，其中 `address` 对应 `0x7ffff7badd90`。

**预期输出：**

- 创建一个新的 `GumSymbol` 对象。
- `sym->details.address` 将被设置为 `0x7ffff7badd90`。
- 如果系统能够解析该地址的符号信息，`sym->resolved` 将为 `true`，并且 `sym->details` 结构体将包含：
    - `symbol_name`: "malloc"
    - `module_name`:  例如 "libc.so.6"
    - `file_name`:  例如 "/build/glibc-XXXXXX/glibc-2.XX/malloc/malloc.c" (如果加载了符号)
    - `line_number`:  例如 3092 (如果加载了符号)
    - `column`: 例如 1 (如果加载了符号)
- 返回一个封装了该 `GumSymbol` 对象的 JavaScript `DebugSymbol` 对象。

如果符号信息无法解析，`sym->resolved` 将为 `false`，其他详细信息可能为空或默认值。

**用户或编程常见的使用错误举例：**

1. **传递无效的内存地址给 `fromAddress`:**
   - **错误:** 用户传递了一个未映射到任何有效代码或数据的地址，例如一个栈上的临时变量地址在函数返回后。
   - **结果:** `DebugSymbol` 对象会被创建，但其 `resolved` 属性可能为 `false`，并且除了地址外的大部分属性将为空。

2. **拼写错误的函数名给 `fromName` 或 `getFunctionByName`:**
   - **错误:** 用户尝试查找一个不存在的函数，例如 `DebugSymbol.fromName("openn")` (拼写错误)。
   - **结果:** `fromName` 会创建一个 `DebugSymbol` 对象，但其 `resolved` 属性可能为 `false`。 `getFunctionByName` 会抛出一个 JavaScript 异常，提示找不到该函数。

3. **忘记加载符号文件导致信息不完整:**
   - **错误:** 用户尝试获取文件名或行号等详细信息，但在调用 `fromAddress` 或 `fromName` 之前没有使用 `DebugSymbol.load()` 加载相应的符号文件。
   - **结果:** `DebugSymbol` 对象的 `fileName`、`lineNumber` 和 `column` 属性将为 `null` 或 `0`。

4. **加载了错误的符号文件:**
   - **错误:** 用户使用 `DebugSymbol.load()` 加载了与目标进程或模块不匹配的符号文件。
   - **结果:**  即使符号被 "解析"，获取到的文件名和行号信息也可能是不正确的或指向错误的源代码位置。

**用户操作如何一步步到达这里作为调试线索：**

假设用户在 Frida 脚本中执行了以下操作，导致代码执行到 `gumjs_symbol_from_address`:

1. **启动 Frida 并连接到目标进程:** 用户使用 Frida CLI 或 API 连接到他们想要分析的应用程序。
   ```bash
   frida -p <pid>
   ```
   或在 JavaScript 中：
   ```javascript
   const session = await frida.attach(<pid>);
   ```

2. **获取内存地址:** 用户可能通过多种方式获取到一个内存地址：
   - **枚举模块并计算偏移:**
     ```javascript
     const module = Process.getModuleByName('libc.so.6');
     const mallocAddress = module.baseAddress.add(0x12345); // 假设已知 malloc 的偏移
     ```
   - **调用其他 Frida API，例如 `Module.findExportByName` 返回的是指针:**
     ```javascript
     const openPtr = Module.findExportByName(null, 'open');
     ```
   - **在 hook 函数时，`this.context.pc` 提供了当前指令的地址。**

3. **使用 `DebugSymbol.fromAddress`:** 用户使用获取到的地址创建 `DebugSymbol` 对象：
   ```javascript
   const symbol = DebugSymbol.fromAddress(mallocAddress);
   console.log(symbol.name);
   console.log(symbol.moduleName);
   ```

**调试线索:**

当用户报告 `DebugSymbol.fromAddress` 返回的结果不符合预期时（例如，`resolved` 为 `false`，或者名称不正确），调试线索可以从以下几个方面入手：

* **确认提供的内存地址是否有效:**  使用其他工具（如 `maps` 文件或 GDB）验证该地址是否属于目标进程的有效内存区域。
* **检查符号是否已加载:**  确认是否已使用 `DebugSymbol.load()` 加载了相关的符号文件。
* **核对符号文件的正确性:**  确保加载的符号文件与目标进程的确切版本匹配。不匹配的版本可能导致地址偏移错误。
* **检查地址是否被 ASLR 影响:**  地址空间布局随机化 (ASLR) 会导致每次程序运行时地址发生变化。确保用于查找符号的地址是当前进程的实际地址，而不是硬编码的地址。
* **查看 Frida 日志:**  Frida 可能会输出一些调试信息，有助于了解符号查找过程中的错误。

总而言之，`gumquicksymbol.c` 是 Frida 中一个关键的模块，它将底层的符号操作能力暴露给 JavaScript 开发者，使得动态分析和逆向工程任务更加便捷和强大。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquicksymbol.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Matt Oh <oh.jeongwook@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquicksymbol.h"

#include "gumquickmacros.h"

#include <gum/gumsymbolutil.h>

typedef struct _GumSymbol GumSymbol;

struct _GumSymbol
{
  gboolean resolved;
  GumDebugSymbolDetails details;
};

GUMJS_DECLARE_FUNCTION (gumjs_symbol_from_address)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_from_name)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_get_function_by_name)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_find_functions_named)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_find_functions_matching)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_load)

static JSValue gum_symbol_new (JSContext * ctx, GumQuickSymbol * parent,
    GumSymbol ** symbol);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_symbol_construct)
GUMJS_DECLARE_FINALIZER (gumjs_symbol_finalize)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_address)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_name)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_module_name)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_file_name)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_line_number)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_column)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_to_json)

static JSValue gum_quick_pointer_array_new (JSContext * ctx, GArray * pointers,
    GumQuickCore * core);

static const JSClassDef gumjs_symbol_def =
{
  .class_name = "DebugSymbol",
  .finalizer = gumjs_symbol_finalize,
};

static const JSCFunctionListEntry gumjs_symbol_module_entries[] =
{
  JS_CFUNC_DEF ("fromAddress", 0, gumjs_symbol_from_address),
  JS_CFUNC_DEF ("fromName", 0, gumjs_symbol_from_name),
  JS_CFUNC_DEF ("getFunctionByName", 0, gumjs_symbol_get_function_by_name),
  JS_CFUNC_DEF ("findFunctionsNamed", 0, gumjs_symbol_find_functions_named),
  JS_CFUNC_DEF ("findFunctionsMatching", 0,
      gumjs_symbol_find_functions_matching),
  JS_CFUNC_DEF ("load", 0, gumjs_symbol_load),
};

static const JSCFunctionListEntry gumjs_symbol_entries[] =
{
  JS_CGETSET_DEF ("address", gumjs_symbol_get_address, NULL),
  JS_CGETSET_DEF ("name", gumjs_symbol_get_name, NULL),
  JS_CGETSET_DEF ("moduleName", gumjs_symbol_get_module_name, NULL),
  JS_CGETSET_DEF ("fileName", gumjs_symbol_get_file_name, NULL),
  JS_CGETSET_DEF ("lineNumber", gumjs_symbol_get_line_number, NULL),
  JS_CGETSET_DEF ("column", gumjs_symbol_get_column, NULL),
  JS_CFUNC_DEF ("toString", 0, gumjs_symbol_to_string),
  JS_CFUNC_DEF ("toJSON", 0, gumjs_symbol_to_json),
};

void
_gum_quick_symbol_init (GumQuickSymbol * self,
                        JSValue ns,
                        GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue proto, ctor;

  self->core = core;

  _gum_quick_core_store_module_data (core, "debug-symbol", self);

  _gum_quick_create_class (ctx, &gumjs_symbol_def, core, &self->symbol_class,
      &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_symbol_construct,
      gumjs_symbol_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, ctor, gumjs_symbol_module_entries,
      G_N_ELEMENTS (gumjs_symbol_module_entries));
  JS_SetPropertyFunctionList (ctx, proto, gumjs_symbol_entries,
      G_N_ELEMENTS (gumjs_symbol_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_symbol_def.class_name, ctor,
      JS_PROP_C_W_E);
}

void
_gum_quick_symbol_dispose (GumQuickSymbol * self)
{
}

void
_gum_quick_symbol_finalize (GumQuickSymbol * self)
{
}

static GumQuickSymbol *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "debug-symbol");
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_from_address)
{
  JSValue wrapper;
  gpointer address;
  GumSymbol * sym;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);

  if (!_gum_quick_args_parse (args, "p", &address))
    return JS_EXCEPTION;

  wrapper = gum_symbol_new (ctx, gumjs_get_parent_module (core), &sym);

  sym->details.address = GPOINTER_TO_SIZE (address);

  _gum_quick_scope_suspend (&scope);

  sym->resolved = gum_symbol_details_from_address (address, &sym->details);

  _gum_quick_scope_resume (&scope);

  return wrapper;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_from_name)
{
  JSValue wrapper;
  const gchar * name;
  GumSymbol * sym;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  gpointer address;

  if (!_gum_quick_args_parse (args, "s", &name))
    return JS_EXCEPTION;

  wrapper = gum_symbol_new (ctx, gumjs_get_parent_module (core), &sym);

  _gum_quick_scope_suspend (&scope);

  address = gum_find_function (name);
  if (address != NULL)
    sym->resolved = gum_symbol_details_from_address (address, &sym->details);

  _gum_quick_scope_resume (&scope);

  return wrapper;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_get_function_by_name)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  const gchar * name;
  gpointer address;

  if (!_gum_quick_args_parse (args, "s", &name))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  address = gum_find_function (name);

  _gum_quick_scope_resume (&scope);

  if (address == NULL)
  {
    return _gum_quick_throw (ctx,
        "unable to find function with name '%s'",
        name);
  }

  return _gum_quick_native_pointer_new (ctx, address, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_find_functions_named)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  gchar * name;
  GArray * functions;

  if (!_gum_quick_args_parse (args, "s", &name))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  functions = gum_find_functions_named (name);

  _gum_quick_scope_resume (&scope);

  return gum_quick_pointer_array_new (ctx, functions, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_find_functions_matching)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  const gchar * str;
  GArray * functions;

  if (!_gum_quick_args_parse (args, "s", &str))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  functions = gum_find_functions_matching (str);

  _gum_quick_scope_resume (&scope);

  return gum_quick_pointer_array_new (ctx, functions, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_load)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  const gchar * path;
  gboolean success;

  if (!_gum_quick_args_parse (args, "s", &path))
    return JS_EXCEPTION;

  _gum_quick_scope_suspend (&scope);

  success = gum_load_symbols (path);

  _gum_quick_scope_resume (&scope);

  if (!success)
    return _gum_quick_throw_literal (ctx, "unable to load symbols");

  return JS_UNDEFINED;
}

static JSValue
gum_symbol_new (JSContext * ctx,
                GumQuickSymbol * parent,
                GumSymbol ** symbol)
{
  JSValue wrapper;
  GumSymbol * sym;

  wrapper = JS_NewObjectClass (ctx, parent->symbol_class);

  sym = g_slice_new0 (GumSymbol);

  JS_SetOpaque (wrapper, sym);

  *symbol = sym;
  return wrapper;
}

static gboolean
gum_symbol_get (JSContext * ctx,
                JSValueConst val,
                GumQuickCore * core,
                GumSymbol ** symbol)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->symbol_class, core, (gpointer *) symbol);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_symbol_construct)
{
  return _gum_quick_throw_literal (ctx, "not user-instantiable");
}

GUMJS_DEFINE_FINALIZER (gumjs_symbol_finalize)
{
  GumSymbol * s;

  s = JS_GetOpaque (val, gumjs_get_parent_module (core)->symbol_class);
  if (s == NULL)
    return;

  g_slice_free (GumSymbol, s);
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_address)
{
  GumSymbol * self;

  if (!gum_symbol_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx,
      GSIZE_TO_POINTER (self->details.address), core);
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_name)
{
  GumSymbol * self;

  if (!gum_symbol_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!self->resolved)
    return JS_NULL;

  return JS_NewString (ctx, self->details.symbol_name);
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_module_name)
{
  GumSymbol * self;

  if (!gum_symbol_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!self->resolved)
    return JS_NULL;

  return JS_NewString (ctx, self->details.module_name);
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_file_name)
{
  GumSymbol * self;

  if (!gum_symbol_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!self->resolved)
    return JS_NULL;

  return JS_NewString (ctx, self->details.file_name);
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_line_number)
{
  GumSymbol * self;

  if (!gum_symbol_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!self->resolved)
    return JS_NULL;

  return JS_NewInt32 (ctx, self->details.line_number);
}

GUMJS_DEFINE_GETTER (gumjs_symbol_get_column)
{
  GumSymbol * self;

  if (!gum_symbol_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!self->resolved)
    return JS_NULL;

  return JS_NewInt32 (ctx, self->details.column);
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_to_string)
{
  JSValue result;
  GumSymbol * self;
  const GumDebugSymbolDetails * d;
  GString * s;

  if (!gum_symbol_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  d = &self->details;

  s = g_string_new ("0");

  if (self->resolved)
  {
    g_string_append_printf (s, "x%" G_GINT64_MODIFIER "x %s!%s", d->address,
        d->module_name, d->symbol_name);
    if (d->file_name[0] != '\0')
    {
      if (d->column != 0)
      {
        g_string_append_printf (s, " %s:%u:%u", d->file_name, d->line_number,
            d->column);
      }
      else
      {
        g_string_append_printf (s, " %s:%u", d->file_name, d->line_number);
      }
    }
  }
  else if (d->address != 0)
  {
    g_string_append_printf (s, "x%" G_GINT64_MODIFIER "x", d->address);
  }

  result = JS_NewString (ctx, s->str);

  g_string_free (s, TRUE);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_to_json)
{
  JSValue result;
  guint i;

  result = JS_NewObject (ctx);

  for (i = 0; i != G_N_ELEMENTS (gumjs_symbol_entries); i++)
  {
    const JSCFunctionListEntry * e = &gumjs_symbol_entries[i];
    JSValue val;

    if (e->def_type != JS_DEF_CGETSET)
      continue;

    val = JS_GetPropertyStr (ctx, this_val, e->name);
    if (JS_IsException (val))
      goto propagate_exception;
    JS_SetPropertyStr (ctx, result, e->name, val);
  }

  return result;

propagate_exception:
  {
    JS_FreeValue (ctx, result);

    return JS_EXCEPTION;
  }
}

static JSValue
gum_quick_pointer_array_new (JSContext * ctx,
                             GArray * pointers,
                             GumQuickCore * core)
{
  JSValue result;
  guint i;

  result = JS_NewArray (ctx);

  for (i = 0; i != pointers->len; i++)
  {
    gpointer address = g_array_index (pointers, gpointer, i);

    JS_DefinePropertyValueUint32 (ctx, result, i,
        _gum_quick_native_pointer_new (ctx, address, core),
        JS_PROP_C_W_E);
  }

  g_array_free (pointers, TRUE);

  return result;
}

"""

```