Response:
Let's break down the thought process for analyzing this C++ code for Frida.

**1. Initial Scan and Keyword Recognition:**

* **Headers:**  `gumv8module.h`, `gumv8macros.h`, `<gum/gum-init.h>`, `<string.h>`, `v8.h`. This immediately signals interaction with the Gum library (Frida's core instrumentation engine) and V8 (the JavaScript engine). The "v8" in many names further confirms this.
* **Namespaces:** `using namespace v8;`. This tells us we're directly using V8's C++ API.
* **Macros:** `GUMJS_DECLARE_FUNCTION`, `GUMJS_DEFINE_FUNCTION`, `GUMJS_DECLARE_CONSTRUCTOR`, etc. These are likely Frida-specific macros for simplifying the creation of JavaScript-callable functions within the V8 environment.
* **Data Structures:** Structures like `GumV8ImportsContext`, `GumV8ExportsContext`, `GumV8ModuleMap`, `GumV8ModuleFilter`. These represent internal data used for managing information about modules, their imports, exports, etc.
* **Function Names:** `gumjs_module_load`, `gumjs_module_enumerate_imports`, `gumjs_module_find_base_address`, etc. These directly hint at the functionality exposed to the JavaScript side.

**2. Understanding the Core Purpose:**

Based on the file path (`frida/subprojects/frida-gum/bindings/gumjs/gumv8module.cpp`) and the included headers, the primary function of this file is to bridge the gap between Frida's native instrumentation capabilities (provided by `libgum`) and the JavaScript environment within Frida. It exposes functionalities related to inspecting and interacting with loaded modules.

**3. Analyzing Function by Function (or Grouping):**

* **Static Functions (declared with `GUMJS_DECLARE_FUNCTION` and defined with `GUMJS_DEFINE_FUNCTION`):**  This is where the core logic lies. Go through each one and try to infer its purpose based on its name:
    * `gumjs_module_load`: Likely loads a module by name.
    * `gumjs_module_ensure_initialized`: Checks if a module is loaded and initializes it if needed.
    * `gumjs_module_enumerate_imports`, `gumjs_module_enumerate_exports`, `gumjs_module_enumerate_symbols`, `gumjs_module_enumerate_ranges`, `gumjs_module_enumerate_sections`, `gumjs_module_enumerate_dependencies`:  These clearly deal with iterating through different aspects of a module (imports, exports, symbols, memory ranges, sections, dependencies).
    * `gumjs_module_find_base_address`, `gumjs_module_find_export_by_name`: Functions to locate specific information within a module.
* **Constructor and Methods for `ModuleMap` (declared with `GUMJS_DECLARE_CONSTRUCTOR`, `GUMJS_DECLARE_GETTER`, `GUMJS_DEFINE_CLASS_METHOD`):**  The `ModuleMap` class seems to be a way to represent and manipulate a collection of loaded modules. The methods suggest operations like checking if a module exists at an address (`has`), finding module information by address (`find`, `findName`, `findPath`), updating the map (`update`), and retrieving all modules (`values`).
* **Helper Functions:**  Functions like `gum_emit_import`, `gum_emit_export`, `gum_emit_symbol`, `gum_emit_range`, `gum_emit_section`, `gum_emit_dependency` are likely callback functions used by the `gum_module_enumerate_*` functions to process and format the data for the JavaScript side. `gum_v8_module_map_new`, `gum_v8_module_map_free`, `gum_v8_module_map_on_weak_notify`, `gum_v8_module_filter_free`, `gum_v8_module_filter_matches` are internal functions for managing the `ModuleMap` and filtering.
* **Initialization and Disposal:** `_gum_v8_module_init`, `_gum_v8_module_realize`, `_gum_v8_module_dispose`, `_gum_v8_module_finalize` manage the lifecycle of the `GumV8Module` object, setting up the V8 integration and cleaning up resources.

**4. Identifying Relationships with Reverse Engineering:**

As the analysis progresses, the connection to reverse engineering becomes apparent. Functions for enumerating imports, exports, symbols, and memory ranges are fundamental for understanding the structure and behavior of a program. Finding base addresses and exports is crucial for hooking or manipulating specific functions.

**5. Pinpointing Binary/OS/Kernel/Framework Connections:**

* **`gum_module_load`:** Directly interacts with the operating system's dynamic linker to load libraries.
* **Enumeration functions:** These functions query the operating system's loader or process information to retrieve details about loaded modules, their segments, symbols, etc. This involves understanding the underlying executable format (like ELF on Linux/Android, Mach-O on macOS/iOS, PE on Windows) and the OS's memory management.
* **`GumModuleMap`:** Represents the memory layout of the process, which is a core concept in operating systems and reverse engineering.

**6. Inferring Logic and Providing Examples:**

For functions like `gumjs_module_enumerate_imports`, think about the inputs (module name, callbacks) and how the code iterates through imports and calls the provided callback with details. Create simple examples in JavaScript to illustrate this. For `gumjs_module_map_find`, consider providing a memory address and showing how it can be used to retrieve module information.

**7. Considering User Errors:**

Think about what could go wrong from a JavaScript user's perspective:
* Providing an incorrect module name.
* Not handling asynchronous operations correctly (if callbacks are used).
* Trying to access properties that might not exist (e.g., `details->module` being NULL).

**8. Tracing User Actions:**

Imagine a typical Frida script that interacts with modules. The user might start by listing loaded modules, then try to find a specific function in a module, and finally hook that function. Map these actions back to the C++ code.

**Self-Correction/Refinement During Analysis:**

* **Initial Misinterpretations:**  I might initially misunderstand the purpose of a structure or function. Reading the code carefully and looking at how it's used in other functions helps correct these misunderstandings.
* **Looking for Patterns:**  The consistent use of `GumV8MatchContext` and the `gum_emit_*` functions for enumeration suggests a common pattern for handling these operations.
* **Consulting Documentation (if available):**  If I were unsure about a specific Gum or V8 API, I'd consult their respective documentation. Since this is provided code, the surrounding code and the names are strong clues.

By following this structured approach, I can systematically analyze the C++ code and extract the required information about its functionality, relationships to reverse engineering, system-level interactions, logic, potential errors, and user workflows.
这个C++源代码文件 `gumv8module.cpp` 是 Frida 动态Instrumentation 工具中一个非常核心的组件，它负责将 Frida 的 Gum 库（一个用于在运行时操作进程的引擎）的功能暴露给 JavaScript 环境。简单来说，它定义了 JavaScript 中 `Module` 对象的行为和功能。

**以下是 `gumv8module.cpp` 的功能列表：**

1. **模块加载与初始化:**
   - `gumjs_module_load`:  允许 JavaScript 代码动态加载指定的模块（例如共享库）。
   - `gumjs_module_ensure_initialized`: 确保指定的模块已经被加载并初始化。

2. **模块信息枚举:**
   - `gumjs_module_enumerate_imports`:  枚举指定模块的导入（依赖的其他库的符号）。
   - `gumjs_module_enumerate_exports`: 枚举指定模块的导出（自身提供的符号）。
   - `gumjs_module_enumerate_symbols`: 枚举指定模块的所有符号（包括导入和导出以及内部符号）。
   - `gumjs_module_enumerate_ranges`: 枚举指定模块的内存映射范围及其保护属性（例如可读、可写、可执行）。
   - `gumjs_module_enumerate_sections`: 枚举指定模块的段（sections），例如 `.text` (代码段), `.data` (数据段) 等。
   - `gumjs_module_enumerate_dependencies`: 枚举指定模块依赖的其他模块。

3. **模块信息查找:**
   - `gumjs_module_find_base_address`: 查找指定模块的基地址（在内存中的起始地址）。
   - `gumjs_module_find_export_by_name`: 根据名称查找指定模块导出的符号的地址。

4. **模块映射 (`ModuleMap` 类):**
   - 提供了一个 `ModuleMap` 类，用于表示当前进程中加载的所有模块的映射。
   - `gumjs_module_map_construct`:  `ModuleMap` 类的构造函数，可以接受一个可选的过滤函数，用于筛选需要包含的模块。
   - `gumjs_module_map_get_handle`: 获取 `ModuleMap` 内部的 Gum 句柄。
   - `gumjs_module_map_has`: 检查指定的内存地址是否属于任何已加载的模块。
   - `gumjs_module_map_find`:  查找包含指定内存地址的模块的信息。
   - `gumjs_module_map_find_name`: 查找包含指定内存地址的模块的名称。
   - `gumjs_module_map_find_path`: 查找包含指定内存地址的模块的路径。
   - `gumjs_module_map_update`: 更新模块映射，以反映进程中新加载或卸载的模块。
   - `gumjs_module_map_copy_values`: 获取 `ModuleMap` 中所有模块信息的数组。

**与逆向方法的关系及举例说明:**

这个文件中的功能与逆向工程息息相关，因为它提供了运行时动态分析目标进程的能力。以下是一些例子：

* **动态查找函数地址进行 Hook:** 逆向工程师可以使用 `Module.findExportByName("libnative.so", "Java_com_example_MainActivity_stringFromJNI")`  来动态获取 `libnative.so` 库中 `Java_com_example_MainActivity_stringFromJNI` 函数的地址，然后使用 Frida 的 `Interceptor` API 对其进行 Hook，从而在函数执行前后插入自定义的代码，以分析其行为或修改其返回值。

* **枚举模块导入导出分析依赖关系:**  通过 `Module.enumerateImports("target_app")` 和 `Module.enumerateExports("target_app")`，逆向工程师可以了解目标程序依赖了哪些库以及自身导出了哪些函数，从而理解程序的架构和功能组成。例如，如果发现导入了加密相关的库，可能暗示程序进行了加密操作。

* **枚举内存范围分析内存布局:** 使用 `Module.enumerateRanges("target_app", 'rwx')` 可以找到目标程序中具有可执行权限的内存区域，这对于查找动态生成的代码或者理解代码的加载方式很有帮助。

* **枚举 Section 分析代码和数据分布:** 通过 `Module.enumerateSections("target_app")` 可以了解代码段、数据段等在内存中的位置和大小，这对于静态分析和理解程序的内存组织结构非常重要。

**涉及到二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **二进制底层知识:**
    - **加载模块:** `gum_module_load` 函数底层会调用操作系统提供的加载器接口（例如 Linux 的 `dlopen`，Android 的 `android_dlopen_ext`），这涉及到操作系统加载可执行文件和共享库的二进制格式（如 ELF）。
    - **符号解析:** 枚举导入导出和查找符号地址涉及到对二进制文件符号表的解析，理解如 GOT (Global Offset Table) 和 PLT (Procedure Linkage Table) 等概念。
    - **内存布局:**  枚举内存范围和 Section 涉及到理解进程的内存布局，包括代码段、数据段、堆、栈等在内存中的组织方式。

* **Linux/Android 内核及框架知识:**
    - **进程内存管理:** Frida 需要读取目标进程的内存信息，这涉及到操作系统提供的进程内存管理机制，例如 `/proc/[pid]/maps` 文件在 Linux/Android 中的作用。
    - **动态链接器:** `gum_module_load` 的实现依赖于操作系统的动态链接器，理解动态链接的过程（包括符号查找、重定位等）是必要的。
    - **Android 特性:** 在 Android 上，加载器和符号解析可能涉及到 ART/Dalvik 虚拟机以及 Android 的 Bionic C 库。例如，枚举导入导出可能需要处理 JNI 函数。

**逻辑推理、假设输入与输出:**

假设 JavaScript 代码调用了 `Module.findBaseAddress("libart.so")`:

* **假设输入:** 字符串 "libart.so" (模块名称)。
* **逻辑推理:** `gumjs_module_find_base_address` 函数会调用 `gum_module_find_base_address`，后者会在内部查找当前进程加载的模块列表中是否存在名为 "libart.so" 的模块，如果找到，则返回其基地址。
* **可能输出:**
    * **成功:** 返回一个表示 `libart.so` 基地址的 NativePointer 对象，例如 `NativePointer("0x7b80000000")`。
    * **失败:** 如果 "libart.so" 未加载，则返回 `null`。

假设 JavaScript 代码调用了 `Module.enumerateExports("libc.so", { onMatch: function(exportInfo) { console.log(exportInfo.name); } })`:

* **假设输入:** 字符串 "libc.so" (模块名称)，以及一个包含 `onMatch` 回调函数的对象。
* **逻辑推理:** `gumjs_module_enumerate_exports` 会调用 `gum_module_enumerate_exports`，后者会遍历 `libc.so` 的导出符号表，对于每个导出的符号，都会调用 `gum_emit_export` 来创建一个包含符号信息的 JavaScript 对象，并将其传递给用户提供的 `onMatch` 回调函数。
* **可能输出:**  在控制台上打印 `libc.so` 导出的所有函数和变量的名称，例如 `printf`, `malloc`, `free` 等。

**涉及用户或者编程常见的使用错误及举例说明:**

* **模块名称拼写错误:** 用户可能错误地拼写模块名称，例如 `Module.findBaseAddress("libary.so")` 而实际上想查找的是 `library.so`，这将导致函数返回 `null`。

* **尝试操作未加载的模块:** 用户可能尝试枚举或查找一个尚未被目标进程加载的模块，例如在应用启动初期尝试访问某个动态加载的插件库。这会导致相应的枚举或查找函数找不到模块。

* **异步操作理解不足:**  `enumerateImports`、`enumerateExports` 等函数是异步操作，它们通过回调函数返回结果。用户如果没有正确处理回调，可能会导致结果丢失或者程序逻辑错误。例如，错误地认为 `Module.enumerateImports` 会直接返回一个数组。

* **在错误的上下文中调用:** 某些 Frida API 可能需要在特定的上下文中调用（例如在 `Interceptor.attach` 的回调函数中）。如果在不合适的时机调用 `Module` 的某些方法，可能会导致错误。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **编写 Frida 脚本:** 用户首先会编写一个 Frida JavaScript 脚本，例如：
   ```javascript
   console.log("Script loaded");

   function hook_function() {
       const nativeFuncAddr = Module.findExportByName(" vulnerable_app", "dangerous_function");
       if (nativeFuncAddr) {
           Interceptor.attach(nativeFuncAddr, {
               onEnter: function(args) {
                   console.log("Entering dangerous_function");
               },
               onLeave: function(retval) {
                   console.log("Leaving dangerous_function");
               }
           });
       } else {
           console.log("dangerous_function not found");
       }
   }

   setImmediate(hook_function);
   ```

2. **执行 Frida 脚本:** 用户使用 Frida 命令行工具或 API 将该脚本注入到目标进程：
   ```bash
   frida -l my_script.js vulnerable_app
   ```

3. **JavaScript 调用 `Module` API:** 在 `my_script.js` 中，`Module.findExportByName(" vulnerable_app", "dangerous_function")` 这行代码会触发对 `gumv8module.cpp` 中 `gumjs_module_find_export_by_name` 函数的调用。

4. **Frida Bridge:** Frida 的内部机制会将 JavaScript 的调用转换为对 C++ 层的调用。具体来说，V8 JavaScript 引擎会执行这段 JavaScript 代码，当遇到 `Module.findExportByName` 时，会查找对应的 Native 函数绑定。

5. **`gumv8module.cpp` 中的处理:** `gumjs_module_find_export_by_name` 函数会被执行，它会解析 JavaScript 传递的参数 (" vulnerable_app" 和 "dangerous_function")，然后调用 Gum 库的 `gum_module_find_export_by_name` 函数来查找符号地址。

6. **Gum 库的查找:** `gum_module_find_export_by_name` 函数会在目标进程的内存中查找指定模块的导出符号表，找到匹配的符号并返回其地址。

7. **结果返回:** `gumjs_module_find_export_by_name` 函数会将找到的地址（或者 `null`）转换成 JavaScript 的 `NativePointer` 对象并返回给 JavaScript 代码。

**作为调试线索:** 如果用户报告 `Module.findExportByName` 没有找到预期的函数，调试时可以检查以下几点：

* **模块名称是否正确:**  用户可能拼写错误或者使用了不正确的模块名。
* **函数名称是否正确:**  用户可能拼写错误或者目标函数实际上并不存在。
* **模块是否已加载:**  可以在脚本中使用 `Process.enumerateModules()` 来确认目标模块是否已经被加载。
* **符号是否被导出:**  可以使用其他工具（如 `readelf` 或 `objdump`）来检查目标模块的符号表，确认该函数是否确实被导出。
* **权限问题:** 在某些情况下，由于权限限制，Frida 可能无法访问目标进程的某些信息。

总而言之，`gumv8module.cpp` 是 Frida 将其强大的底层能力暴露给 JavaScript 开发者的关键桥梁，它使得用户能够方便地在运行时检查和操控目标进程的各种属性，是进行动态分析和逆向工程的核心组成部分。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8module.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8module.h"

#include "gumv8macros.h"
#include "gumv8matchcontext.h"

#include <gum/gum-init.h>
#include <string.h>

#define GUMJS_MODULE_NAME Module

using namespace v8;

class GumV8ImportsContext : public GumV8MatchContext<GumV8Module>
{
public:
  GumV8ImportsContext (Isolate * isolate, GumV8Module * parent)
    : GumV8MatchContext (isolate, parent)
  {
  }

  Local<Object> imp;
  Local<String> type;
  Local<String> name;
  Local<String> module;
  Local<String> address;
  Local<String> slot;
  Local<String> variable;
};

struct GumV8ExportsContext : public GumV8MatchContext<GumV8Module>
{
public:
  GumV8ExportsContext (Isolate * isolate, GumV8Module * parent)
    : GumV8MatchContext (isolate, parent)
  {
  }

  Local<Object> exp;
  Local<String> type;
  Local<String> name;
  Local<String> address;
  Local<String> variable;
};

struct GumV8ModuleMap
{
  Global<Object> * wrapper;
  GumModuleMap * handle;

  GumV8Module * module;
};

struct GumV8ModuleFilter
{
  Global<Function> * callback;

  GumV8Module * module;
};

GUMJS_DECLARE_FUNCTION (gumjs_module_load)
GUMJS_DECLARE_FUNCTION (gumjs_module_ensure_initialized)
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_imports)
static gboolean gum_emit_import (const GumImportDetails * details,
    GumV8ImportsContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_exports)
static gboolean gum_emit_export (const GumExportDetails * details,
    GumV8ExportsContext * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_symbols)
static gboolean gum_emit_symbol (const GumSymbolDetails * details,
    GumV8MatchContext<GumV8Module> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumV8MatchContext<GumV8Module> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_sections)
static gboolean gum_emit_section (const GumSectionDetails * details,
    GumV8MatchContext<GumV8Module> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_enumerate_dependencies)
static gboolean gum_emit_dependency (const GumDependencyDetails * details,
    GumV8MatchContext<GumV8Module> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_module_find_base_address)
GUMJS_DECLARE_FUNCTION (gumjs_module_find_export_by_name)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_module_map_construct)
GUMJS_DECLARE_GETTER (gumjs_module_map_get_handle)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_has)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find_name)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_find_path)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_update)
GUMJS_DECLARE_FUNCTION (gumjs_module_map_copy_values)

static GumV8ModuleMap * gum_v8_module_map_new (Local<Object> wrapper,
    GumModuleMap * handle, GumV8Module * module);
static void gum_v8_module_map_free (GumV8ModuleMap * self);
static void gum_v8_module_map_on_weak_notify (
    const WeakCallbackInfo<GumV8ModuleMap> & info);

static void gum_v8_module_filter_free (GumV8ModuleFilter * filter);
static gboolean gum_v8_module_filter_matches (const GumModuleDetails * details,
    GumV8ModuleFilter * self);

static const GumV8Function gumjs_module_static_functions[] =
{
  { "_load", gumjs_module_load },
  { "ensureInitialized", gumjs_module_ensure_initialized },
  { "_enumerateImports", gumjs_module_enumerate_imports },
  { "_enumerateExports", gumjs_module_enumerate_exports },
  { "_enumerateSymbols", gumjs_module_enumerate_symbols },
  { "_enumerateRanges", gumjs_module_enumerate_ranges },
  { "_enumerateSections", gumjs_module_enumerate_sections },
  { "_enumerateDependencies", gumjs_module_enumerate_dependencies },
  { "findBaseAddress", gumjs_module_find_base_address },
  { "findExportByName", gumjs_module_find_export_by_name },

  { NULL, NULL }
};

static const GumV8Property gumjs_module_map_values[] =
{
  { "handle", gumjs_module_map_get_handle, NULL },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_module_map_functions[] =
{
  { "has", gumjs_module_map_has },
  { "find", gumjs_module_map_find },
  { "findName", gumjs_module_map_find_name },
  { "findPath", gumjs_module_map_find_path },
  { "update", gumjs_module_map_update },
  { "values", gumjs_module_map_copy_values },

  { NULL, NULL }
};

void
_gum_v8_module_init (GumV8Module * self,
                     GumV8Core * core,
                     Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto klass = _gum_v8_create_class ("Module", nullptr, scope, module, isolate);
  _gum_v8_class_add_static (klass, gumjs_module_static_functions, module,
      isolate);
  self->klass = new Global<FunctionTemplate> (isolate, klass);

  auto map = _gum_v8_create_class ("ModuleMap", gumjs_module_map_construct,
      scope, module, isolate);
  _gum_v8_class_add (map, gumjs_module_map_values, module, isolate);
  _gum_v8_class_add (map, gumjs_module_map_functions, module, isolate);
}

void
_gum_v8_module_realize (GumV8Module * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  self->maps = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_module_map_free);

  auto type_key = _gum_v8_string_new_ascii (isolate, "type");
  self->type_key = new Global<String> (isolate, type_key);
  auto name_key = _gum_v8_string_new_ascii (isolate, "name");
  self->name_key = new Global<String> (isolate, name_key);
  auto module_key = _gum_v8_string_new_ascii (isolate, "module");
  self->module_key = new Global<String> (isolate, module_key);
  auto address_key = _gum_v8_string_new_ascii (isolate, "address");
  self->address_key = new Global<String> (isolate, address_key);
  auto slot_key = _gum_v8_string_new_ascii (isolate, "slot");
  self->slot_key = new Global<String> (isolate, slot_key);

  auto function_value = _gum_v8_string_new_ascii (isolate, "function");
  auto variable_value = _gum_v8_string_new_ascii (isolate, "variable");
  self->variable_value = new Global<String> (isolate, variable_value);

  auto empty_string = String::Empty (isolate);

  auto imp = Object::New (isolate);
  imp->Set (context, type_key, function_value).FromJust ();
  imp->Set (context, name_key, empty_string).FromJust ();
  imp->Set (context, module_key, empty_string).FromJust ();
  imp->Set (context, address_key, _gum_v8_native_pointer_new (
      GSIZE_TO_POINTER (NULL), self->core)).FromJust ();
  self->import_value = new Global<Object> (isolate, imp);

  auto exp = Object::New (isolate);
  exp->Set (context, type_key, function_value).FromJust ();
  exp->Set (context, name_key, empty_string).FromJust ();
  exp->Set (context, address_key, _gum_v8_native_pointer_new (
      GSIZE_TO_POINTER (NULL), self->core)).FromJust ();
  self->export_value = new Global<Object> (isolate, exp);
}

void
_gum_v8_module_dispose (GumV8Module * self)
{
  g_hash_table_unref (self->maps);
  self->maps = NULL;

  delete self->klass;
  self->klass = nullptr;

  delete self->import_value;
  delete self->export_value;
  self->import_value = nullptr;
  self->export_value = nullptr;

  delete self->type_key;
  delete self->name_key;
  delete self->module_key;
  delete self->address_key;
  delete self->slot_key;
  delete self->variable_value;
  self->type_key = nullptr;
  self->name_key = nullptr;
  self->module_key = nullptr;
  self->address_key = nullptr;
  self->slot_key = nullptr;
  self->variable_value = nullptr;
}

void
_gum_v8_module_finalize (GumV8Module * self)
{
}

Local<Object>
_gum_v8_module_value_new (const GumModuleDetails * details,
                          GumV8Module * module)
{
  auto core = module->core;
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto klass = Local<FunctionTemplate>::New (isolate, *module->klass);
  auto value = klass->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  _gum_v8_object_set_utf8 (value, "name", details->name, core);
  _gum_v8_object_set_pointer (value, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (value, "size", details->range->size, core);
  _gum_v8_object_set_utf8 (value, "path", details->path, core);
  return value;
}

GUMJS_DEFINE_FUNCTION (gumjs_module_load)
{
  gchar * name;
  if (!_gum_v8_args_parse (args, "s", &name))
    return;

  GError * error;
  {
    ScriptUnlocker unlocker (core);

    error = NULL;
    gum_module_load (name, &error);
  }

  _gum_v8_maybe_throw (isolate, &error);

  g_free (name);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_ensure_initialized)
{
  gchar * name;
  if (!_gum_v8_args_parse (args, "s", &name))
    return;

  gboolean success;
  {
    ScriptUnlocker unlocker (core);

    success = gum_module_ensure_initialized (name);
  }

  if (!success)
  {
    _gum_v8_throw (isolate, "unable to find module '%s'", name);
  }

  g_free (name);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_imports)
{
  gchar * name;
  GumV8ImportsContext ic (isolate, module);
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name, &ic.on_match,
      &ic.on_complete))
    return;

  ic.imp = Local<Object>::New (isolate, *module->import_value);
  ic.type = Local<String>::New (isolate, *module->type_key);
  ic.name = Local<String>::New (isolate, *module->name_key);
  ic.module = Local<String>::New (isolate, *module->module_key);
  ic.address = Local<String>::New (isolate, *module->address_key);
  ic.slot = Local<String>::New (isolate, *module->slot_key);
  ic.variable = Local<String>::New (isolate, *module->variable_value);

  gum_module_enumerate_imports (name, (GumFoundImportFunc) gum_emit_import,
      &ic);

  ic.OnComplete ();

  g_free (name);
}

static gboolean
gum_emit_import (const GumImportDetails * details,
                 GumV8ImportsContext * ic)
{
  auto core = ic->parent->core;
  auto isolate = ic->isolate;
  auto context = ic->context;

  auto imp = ic->imp->Clone ();

  switch (details->type)
  {
    case GUM_IMPORT_FUNCTION:
    {
      /* the default value in our template */
      break;
    }
    case GUM_IMPORT_VARIABLE:
    {
      imp->Set (context, ic->type, ic->variable).FromJust ();
      break;
    }
    case GUM_IMPORT_UNKNOWN:
    {
      imp->Delete (context, ic->type).FromJust ();
      break;
    }
    default:
    {
      g_assert_not_reached ();
      break;
    }
  }

  imp->Set (context, ic->name,
      _gum_v8_string_new_ascii (isolate, details->name)).FromJust ();

  if (details->module != NULL)
  {
    imp->Set (context, ic->module,
        _gum_v8_string_new_ascii (isolate, details->module)).FromJust ();
  }
  else
  {
    imp->Delete (context, ic->module).FromJust ();
  }

  if (details->address != 0)
  {
    imp->Set (context, ic->address,
        _gum_v8_native_pointer_new (GSIZE_TO_POINTER (details->address), core))
        .FromJust ();
  }
  else
  {
    imp->Delete (context, ic->address).FromJust ();
  }

  if (details->slot != 0)
  {
    imp->Set (context, ic->slot,
        _gum_v8_native_pointer_new (GSIZE_TO_POINTER (details->slot), core))
        .FromJust ();
  }
  else
  {
    imp->Delete (context, ic->slot).FromJust ();
  }

  return ic->OnMatch (imp);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_exports)
{
  gchar * name;
  GumV8ExportsContext ec (isolate, module);
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name, &ec.on_match,
      &ec.on_complete))
    return;

  ec.exp = Local<Object>::New (isolate, *module->export_value);
  ec.type = Local<String>::New (isolate, *module->type_key);
  ec.name = Local<String>::New (isolate, *module->name_key);
  ec.address = Local<String>::New (isolate, *module->address_key);
  ec.variable = Local<String>::New (isolate, *module->variable_value);

  gum_module_enumerate_exports (name, (GumFoundExportFunc) gum_emit_export,
      &ec);

  ec.OnComplete ();

  g_free (name);
}

static gboolean
gum_emit_export (const GumExportDetails * details,
                 GumV8ExportsContext * ec)
{
  auto core = ec->parent->core;
  auto isolate = ec->isolate;
  auto context = ec->context;

  auto exp = ec->exp->Clone ();

  if (details->type != GUM_EXPORT_FUNCTION)
  {
    exp->Set (context, ec->type, ec->variable).FromJust ();
  }

  exp->Set (context, ec->name,
      _gum_v8_string_new_ascii (isolate, details->name)).FromJust ();

  exp->Set (context, ec->address,
      _gum_v8_native_pointer_new (GSIZE_TO_POINTER (details->address), core))
      .FromJust ();

  return ec->OnMatch (exp);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_symbols)
{
  gchar * name;
  GumV8MatchContext<GumV8Module> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name, &mc.on_match,
      &mc.on_complete))
    return;

  gum_module_enumerate_symbols (name, (GumFoundSymbolFunc) gum_emit_symbol,
      &mc);

  mc.OnComplete ();

  g_free (name);
}

static gboolean
gum_emit_symbol (const GumSymbolDetails * details,
                 GumV8MatchContext<GumV8Module> * mc)
{
  auto core = mc->parent->core;
  auto isolate = mc->isolate;

  auto symbol = Object::New (isolate);
  _gum_v8_object_set (symbol, "isGlobal",
      Boolean::New (isolate, details->is_global), core);
  _gum_v8_object_set_ascii (symbol, "type",
      gum_symbol_type_to_string (details->type), core);

  auto s = details->section;
  if (s != NULL)
  {
    auto section = Object::New (isolate);
    _gum_v8_object_set_ascii (section, "id", s->id, core);
    _gum_v8_object_set_page_protection (section, "protection", s->protection,
        core);
    _gum_v8_object_set (symbol, "section", section, core);
  }

  _gum_v8_object_set_ascii (symbol, "name", details->name, core);
  _gum_v8_object_set_pointer (symbol, "address", details->address, core);
  if (details->size != -1)
    _gum_v8_object_set_uint (symbol, "size", details->size, core);

  return mc->OnMatch (symbol);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_ranges)
{
  gchar * name;
  GumPageProtection prot;
  GumV8MatchContext<GumV8Module> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "smF{onMatch,onComplete}", &name, &prot,
      &mc.on_match, &mc.on_complete))
    return;

  gum_module_enumerate_ranges (name, prot, (GumFoundRangeFunc) gum_emit_range,
      &mc);

  mc.OnComplete ();

  g_free (name);
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumV8MatchContext<GumV8Module> * mc)
{
  auto core = mc->parent->core;
  auto isolate = mc->isolate;

  auto range = Object::New (isolate);
  _gum_v8_object_set_pointer (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);
  _gum_v8_object_set_page_protection (range, "protection", details->protection,
      core);

  return mc->OnMatch (range);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_sections)
{
  gchar * name;
  GumV8MatchContext<GumV8Module> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name,
      &mc.on_match, &mc.on_complete))
    return;

  gum_module_enumerate_sections (name, (GumFoundSectionFunc) gum_emit_section,
      &mc);

  mc.OnComplete ();

  g_free (name);
}

static gboolean
gum_emit_section (const GumSectionDetails * details,
                  GumV8MatchContext<GumV8Module> * mc)
{
  auto core = mc->parent->core;
  auto isolate = mc->isolate;

  auto section = Object::New (isolate);
  _gum_v8_object_set_utf8 (section, "id", details->id, core);
  _gum_v8_object_set_utf8 (section, "name", details->name, core);
  _gum_v8_object_set_pointer (section, "address", details->address, core);
  _gum_v8_object_set_uint (section, "size", details->size, core);

  return mc->OnMatch (section);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_enumerate_dependencies)
{
  gchar * name;
  GumV8MatchContext<GumV8Module> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "sF{onMatch,onComplete}", &name,
      &mc.on_match, &mc.on_complete))
    return;

  gum_module_enumerate_dependencies (name,
      (GumFoundDependencyFunc) gum_emit_dependency, &mc);

  mc.OnComplete ();

  g_free (name);
}

static gboolean
gum_emit_dependency (const GumDependencyDetails * details,
                     GumV8MatchContext<GumV8Module> * mc)
{
  auto core = mc->parent->core;
  auto isolate = mc->isolate;

  auto dependency = Object::New (isolate);
  _gum_v8_object_set_utf8 (dependency, "name", details->name, core);
  _gum_v8_object_set_enum (dependency, "type", details->type,
      GUM_TYPE_DEPENDENCY_TYPE, core);

  return mc->OnMatch (dependency);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_base_address)
{
  gchar * name;
  if (!_gum_v8_args_parse (args, "s", &name))
    return;

  auto address = gum_module_find_base_address (name);
  if (address != 0)
  {
    info.GetReturnValue ().Set (
        _gum_v8_native_pointer_new (GSIZE_TO_POINTER (address), core));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }

  g_free (name);
}

GUMJS_DEFINE_FUNCTION (gumjs_module_find_export_by_name)
{
  gchar * module_name, * symbol_name;
  if (!_gum_v8_args_parse (args, "s?s", &module_name, &symbol_name))
    return;

  GumAddress address;
  {
    ScriptUnlocker unlocker (core);

    address = gum_module_find_export_by_name (module_name, symbol_name);
  }

  if (address != 0)
  {
    info.GetReturnValue ().Set (
        _gum_v8_native_pointer_new (GSIZE_TO_POINTER (address), core));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }

  g_free (module_name);
  g_free (symbol_name);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_module_map_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use constructor syntax to create a new instance");
    return;
  }

  Local<Function> filter_callback;
  if (!_gum_v8_args_parse (args, "|F", &filter_callback))
    return;

  GumModuleMap * handle;
  if (filter_callback.IsEmpty ())
  {
    handle = gum_module_map_new ();
  }
  else
  {
    GumV8ModuleFilter * filter;

    filter = g_slice_new (GumV8ModuleFilter);
    filter->callback = new Global<Function> (isolate, filter_callback);
    filter->module = module;

    handle = gum_module_map_new_filtered (
        (GumModuleMapFilterFunc) gum_v8_module_filter_matches,
        filter, (GDestroyNotify) gum_v8_module_filter_free);
  }

  auto map = gum_v8_module_map_new (wrapper, handle, module);
  wrapper->SetAlignedPointerInInternalField (0, map);
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_module_map_get_handle, GumV8ModuleMap)
{
  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (self->handle, core));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_has, GumV8ModuleMap)
{
  gpointer address;
  if (!_gum_v8_args_parse (args, "p", &address))
    return;

  auto details = gum_module_map_find (self->handle, GUM_ADDRESS (address));

  info.GetReturnValue ().Set (details != NULL);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_find, GumV8ModuleMap)
{
  gpointer address;
  if (!_gum_v8_args_parse (args, "p", &address))
    return;

  auto details = gum_module_map_find (self->handle, GUM_ADDRESS (address));
  if (details == NULL)
  {
    info.GetReturnValue ().SetNull ();
    return;
  }

  info.GetReturnValue ().Set (_gum_v8_module_value_new (details, module));
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_find_name, GumV8ModuleMap)
{
  gpointer address;
  if (!_gum_v8_args_parse (args, "p", &address))
    return;

  auto details = gum_module_map_find (self->handle, GUM_ADDRESS (address));
  if (details == NULL)
  {
    info.GetReturnValue ().SetNull ();
    return;
  }

  info.GetReturnValue ().Set (String::NewFromUtf8 (isolate, details->name)
      .ToLocalChecked ());
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_find_path, GumV8ModuleMap)
{
  gpointer address;
  if (!_gum_v8_args_parse (args, "p", &address))
    return;

  auto details = gum_module_map_find (self->handle, GUM_ADDRESS (address));
  if (details == NULL)
  {
    info.GetReturnValue ().SetNull ();
    return;
  }

  info.GetReturnValue ().Set (String::NewFromUtf8 (isolate, details->path)
      .ToLocalChecked ());
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_update, GumV8ModuleMap)
{
  gum_module_map_update (self->handle);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_module_map_copy_values, GumV8ModuleMap)
{
  auto context = isolate->GetCurrentContext ();

  auto values = gum_module_map_get_values (self->handle);
  auto result = Array::New (isolate, values->len);

  for (guint i = 0; i != values->len; i++)
  {
    auto details = &g_array_index (values, GumModuleDetails, i);
    auto m = _gum_v8_module_value_new (details, module);
    result->Set (context, i, m).Check ();
  }

  info.GetReturnValue ().Set (result);
}

static GumV8ModuleMap *
gum_v8_module_map_new (Local<Object> wrapper,
                       GumModuleMap * handle,
                       GumV8Module * module)
{
  auto map = g_slice_new (GumV8ModuleMap);
  map->wrapper = new Global<Object> (module->core->isolate, wrapper);
  map->wrapper->SetWeak (map, gum_v8_module_map_on_weak_notify,
      WeakCallbackType::kParameter);
  map->handle = handle;
  map->module = module;

  g_hash_table_add (module->maps, map);

  return map;
}

static void
gum_v8_module_map_free (GumV8ModuleMap * map)
{
  g_object_unref (map->handle);

  delete map->wrapper;

  g_slice_free (GumV8ModuleMap, map);
}

static void
gum_v8_module_map_on_weak_notify (const WeakCallbackInfo<GumV8ModuleMap> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->maps, self);
}

static void
gum_v8_module_filter_free (GumV8ModuleFilter * filter)
{
  delete filter->callback;

  g_slice_free (GumV8ModuleFilter, filter);
}

static gboolean
gum_v8_module_filter_matches (const GumModuleDetails * details,
                              GumV8ModuleFilter * self)
{
  auto core = self->module->core;
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto module = _gum_v8_module_value_new (details, self->module);

  auto callback (Local<Function>::New (isolate, *self->callback));
  auto recv = Undefined (isolate);
  Local<Value> argv[] = { module };
  Local<Value> result;
  if (callback->Call (context, recv, G_N_ELEMENTS (argv), argv)
      .ToLocal (&result))
  {
    return result->IsBoolean () && result.As<Boolean> ()->Value ();
  }
  else
  {
    core->current_scope->ProcessAnyPendingException ();
    return FALSE;
  }
}
```