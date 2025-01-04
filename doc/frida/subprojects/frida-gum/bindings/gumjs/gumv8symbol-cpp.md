Response:
Let's break down the thought process for analyzing this C++ code for Frida.

**1. Initial Understanding and Goal Setting:**

The first step is to recognize the context: this is a C++ file within Frida, specifically for the `gumjs` binding, which suggests it's bridging between JavaScript and the underlying Frida/Gum engine. The filename `gumv8symbol.cpp` strongly hints at dealing with symbols and the V8 JavaScript engine. The goal is to understand its functionality, its relationship to reverse engineering, low-level details, logic, potential errors, and how a user might trigger this code.

**2. High-Level Code Structure and Key Components:**

Quickly scan the code for key elements:

* **Includes:** `gumv8symbol.h`, `gumv8macros.h`, `gum/gumsymbolutil.h`. These suggest dependencies on other Frida-related headers, especially for symbol manipulation (`gumsymbolutil.h`).
* **Namespaces:** `using namespace v8;` indicates interaction with the V8 JavaScript engine.
* **`GumSymbol` struct:** This likely represents a symbol object in the C++ layer, holding information like address, resolution status, and details. The `wrapper` member points to a V8 JavaScript object, confirming the bridge.
* **`GUMJS_DECLARE_FUNCTION` and `GUMJS_DEFINE_FUNCTION` macros:**  These are likely used to expose C++ functions to JavaScript. Listing these out helps identify the core functionalities exposed.
* **`GUMJS_DECLARE_GETTER` and `GUMJS_DEFINE_CLASS_GETTER` macros:** Similar to the above, but for accessing properties of the `GumSymbol` object.
* **Static arrays:** `gumjs_symbol_module_functions`, `gumjs_symbol_values`, `gumjs_symbol_functions` – these likely define the mapping of JavaScript names to C++ functions and properties for the `Symbol` module and its instances.
* **Initialization functions:** `_gum_v8_symbol_init`, `_gum_v8_symbol_realize`, `_gum_v8_symbol_dispose`, `_gum_v8_symbol_finalize`. These are standard lifecycle management functions.
* **V8 specific types:** `Local<Object>`, `Isolate`, `Context`, `String`, etc. indicate interaction with the V8 engine.
* **GLib types:** `gpointer`, `gboolean`, `gchar`, `GArray`, `GHashTable`, `GString`. This points to the use of GLib, a common C library.

**3. Functionality Breakdown (Iterating through `GUMJS_DEFINE_FUNCTION`):**

Go through each exposed function and deduce its purpose:

* **`gumjs_symbol_from_address`:** Takes an address, tries to resolve symbol details, returns a `Symbol` object.
* **`gumjs_symbol_from_name`:** Takes a function name, tries to find its address and resolve details, returns a `Symbol` object.
* **`gumjs_symbol_get_function_by_name`:** Takes a function name, returns the address as a raw pointer. Throws an error if not found.
* **`gumjs_symbol_find_functions_named`:** Takes a name, finds all functions with that name, returns an array of addresses.
* **`gumjs_symbol_find_functions_matching`:** Takes a pattern (likely a regex or wildcard), finds matching function names, returns an array of addresses.
* **`gumjs_symbol_load`:** Takes a path to a symbol file (like a `.so` or `.pdb`), attempts to load it.

**4. Connecting to Reverse Engineering:**

Consider how these functions are useful in reverse engineering:

* **Examining code at specific addresses:** `fromAddress` is crucial for understanding what code exists at a given memory location.
* **Finding function entry points:** `fromName` and `getFunctionByName` are fundamental for hooking and analyzing specific functions.
* **Discovering related functions:** `findFunctionsNamed` and `findFunctionsMatching` help uncover groups of functions based on naming conventions or patterns, which can reveal design patterns or related functionalities.
* **Loading external symbols:** `load` allows analyzing libraries or modules whose symbols aren't loaded by default.

**5. Identifying Low-Level and Kernel/Framework Interactions:**

Look for functions that interact with the operating system or low-level concepts:

* **Memory Addresses (`gpointer`, `address`):**  The core concept revolves around memory addresses, a fundamental aspect of binary execution.
* **Symbol Resolution:** The functions rely on the operating system's or debugger's ability to map addresses to symbolic names. This often involves reading debug information like DWARF or PDB.
* **Dynamic Linking (`gum_find_function`, `gum_find_functions_named`, `gum_find_functions_matching`, `gum_load_symbols`):** These functions interact with the dynamic linker/loader, responsible for loading and resolving symbols in shared libraries. This is very relevant to Linux and Android, where shared libraries are heavily used. `gum_load_symbols` explicitly deals with loading symbols, often from `.so` files on Linux/Android.
* **`ScriptUnlocker`:** This hints at the interaction with Frida's scripting environment and the need to temporarily release locks when performing potentially long-running operations like symbol resolution. This is related to concurrency and avoiding deadlocks.

**6. Logic and Assumptions:**

Analyze the code's flow and make assumptions about inputs and outputs:

* **`gum_symbol_from_address`:** Input: a memory address (e.g., `0x7ffff7a00000`). Output: a `Symbol` object. If the address corresponds to a known function, the `Symbol` will have its name, module name, file name, and line number populated. If not, only the address will be available.
* **`gum_symbol_from_name`:** Input: a function name (e.g., `"malloc"`). Output: a `Symbol` object containing the address and details if the function is found, otherwise, the address will be 0 and `resolved` will be false.
* **Error Handling:**  Notice the use of `_gum_v8_throw` when a function isn't found in `gumjs_symbol_get_function_by_name` and `gumjs_symbol_load`.

**7. User Errors:**

Consider common mistakes a user might make:

* **Incorrect address:** Passing an invalid or unmapped memory address to `fromAddress`.
* **Typo in function name:**  Providing a misspelled function name to `fromName` or `getFunctionByName`.
* **Incorrect or missing symbol file path:** Providing a wrong path to `load`, or trying to load symbols for an architecture that doesn't match the target process.
* **Using patterns that are too broad or too specific:** In `findFunctionsMatching`, poorly crafted regular expressions might return too many or no results.

**8. Tracing User Actions (Debugging Clues):**

Think about how a user's actions in the Frida environment would lead to this code:

1. **Frida script execution:** The user starts a Frida script targeting a specific process.
2. **Accessing the `DebugSymbol` module:** The script uses `DebugSymbol.fromAddress(addr)`, `DebugSymbol.fromName(name)`, etc.
3. **Calling the C++ functions:** These JavaScript calls are routed to the corresponding `gumjs_symbol_*` functions in the C++ code through Frida's bridging mechanism.
4. **Interacting with Gum:** The C++ functions call functions from the `gum` library (`gum_find_function`, `gum_symbol_details_from_address`, etc.) to perform the actual symbol resolution and lookup.
5. **Returning results to JavaScript:** The C++ code creates V8 objects (like the `Symbol` wrapper) and returns them to the JavaScript environment.

**Self-Correction/Refinement during the process:**

* Initially, I might just skim the code. Then, realizing the importance of the exposed functions, I would go back and analyze each `GUMJS_DEFINE_FUNCTION` in detail.
* When seeing `ScriptUnlocker`, I'd initially think it's about thread safety, but then I'd refine it to be about avoiding blocking the main Frida thread during potentially long-running operations.
* I'd initially just say "symbol resolution" but then expand on it by mentioning DWARF, PDB, and the role of the dynamic linker.

By following these steps, a comprehensive understanding of the code's functionality, its relevance to reverse engineering, and potential user issues can be achieved. The process involves both a top-down (understanding the overall structure) and bottom-up (analyzing individual functions) approach.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumv8symbol.cpp` 这个文件。

**功能概述**

这个文件定义了 Frida 中用于处理调试符号的 C++ 代码，并将其通过 V8 引擎暴露给 JavaScript 环境。它的核心功能是：

1. **符号查找和表示:**  它允许你通过内存地址或符号名称查找调试信息，并将这些信息封装成一个 `Symbol` 对象，方便在 JavaScript 中访问。
2. **符号信息获取:**  可以获取符号的地址、名称、所属模块名称、源文件名和行号等详细信息。
3. **加载符号文件:**  允许动态加载外部的符号文件，以便分析未默认加载符号的模块。
4. **函数查找:**  提供基于名称和模式匹配查找函数地址的功能。

**与逆向方法的关系及举例**

这个文件是 Frida 动态 instrumentation 工具进行逆向分析的核心组件之一。它提供的功能直接服务于多种逆向分析方法：

* **动态跟踪:**  通过 `Symbol.fromAddress(address)` 可以获取当前执行代码位置的符号信息，帮助理解程序执行流程。例如，在 hook 函数入口时，可以打印出入口的符号信息，方便定位和识别被 hook 的函数。

   ```javascript
   // 假设我们想 hook 一个地址为 0x7ffff7a00000 的函数
   const symbol = DebugSymbol.fromAddress(ptr('0x7ffff7a00000'));
   if (symbol) {
     console.log(`Hooking function at ${symbol.address} (${symbol.moduleName}!${symbol.name})`);
     Interceptor.attach(symbol.address, {
       onEnter: function(args) {
         console.log('Entered!');
       }
     });
   } else {
     console.log('No symbol found at that address.');
   }
   ```

* **函数识别与分析:** `Symbol.fromName(name)` 和 `Symbol.findFunctionsNamed(name)` 可以帮助逆向工程师根据函数名找到目标函数，并获取其地址和其他信息。例如，想要分析 `malloc` 函数的行为：

   ```javascript
   const mallocSymbol = DebugSymbol.fromName('malloc');
   if (mallocSymbol) {
     console.log(`malloc found at ${mallocSymbol.address}`);
     // 可以进一步 hook mallocSymbol.address 进行分析
   } else {
     console.log('malloc not found.');
   }

   DebugSymbol.findFunctionsNamed('memcpy').forEach(address => {
       const symbol = DebugSymbol.fromAddress(address);
       console.log(`memcpy variant found at ${symbol.address} (${symbol.moduleName}!${symbol.name})`);
   });
   ```

* **模式匹配查找:** `Symbol.findFunctionsMatching(pattern)` 可以根据正则表达式查找函数，这在需要批量识别具有相似命名模式的函数时非常有用。例如，查找所有以 "onButtonClick" 开头的函数：

   ```javascript
   DebugSymbol.findFunctionsMatching('^onButtonClick').forEach(address => {
       const symbol = DebugSymbol.fromAddress(address);
       console.log(`Found button click handler: ${symbol.moduleName}!${symbol.name} at ${symbol.address}`);
   });
   ```

* **加载外部符号进行分析:** 对于没有默认加载符号信息的库，可以使用 `Symbol.load(path)` 加载符号文件，从而可以获取更详细的函数信息。这在分析第三方库或系统库时非常重要。

   ```javascript
   // 假设要加载 /system/lib64/libart.so 的符号
   try {
     DebugSymbol.load('/system/lib64/libart.so');
     const artAlloc = DebugSymbol.fromName('_ZN3artL20AllocateObjectAlignedENS_6ThreadEPNS_6mirror_4ClassEj');
     if (artAlloc) {
       console.log(`art::AllocateObjectAligned found at ${artAlloc.address}`);
     }
   } catch (e) {
     console.error('Failed to load symbols for libart.so:', e);
   }
   ```

**涉及的二进制底层、Linux、Android 内核及框架知识**

这个文件涉及到了以下方面的知识：

* **二进制文件结构和调试信息:**  理解 ELF (Linux) 或 Mach-O (macOS) 等二进制文件的结构，以及 DWARF 或 PDB 等调试信息的格式，是 `gum_symbol_details_from_address` 和 `gum_load_symbols` 等函数的基础。这些函数需要解析这些数据结构来获取符号信息。
* **内存地址:**  所有的操作都围绕着内存地址展开，包括函数入口地址、数据地址等。理解进程的内存布局是使用这些功能的前提。
* **动态链接和加载:**  `gum_find_function`, `gum_find_functions_named`, `gum_find_functions_matching` 等函数依赖于操作系统提供的动态链接器 (ld.so) 的功能，或者通过读取进程的内存映射信息来查找已加载的库和符号。在 Android 上，这涉及到 `linker` 和 `dlopen/dlsym` 等机制。
* **符号表:**  操作系统和链接器维护着符号表，将符号名称映射到内存地址。这个文件中的功能就是为了访问和利用这些符号表信息。
* **Linux/Android 系统调用:**  虽然这个文件本身没有直接的系统调用，但其底层依赖的 Frida Gum 库可能会使用系统调用来读取进程内存、加载库等。例如，`process_vm_readv` 或 `mmap` 等。
* **Android Framework:** 在 Android 环境下，加载系统库的符号涉及到对 Android Framework 的理解，例如 ART 虚拟机、System Server 等。加载这些库的符号可以帮助分析 Android 系统的底层行为。

**逻辑推理、假设输入与输出**

* **`gumjs_symbol_from_address`:**
    * **假设输入:**  一个有效的内存地址，例如 `0x7fff80001000`。
    * **输出:**  一个 JavaScript `Symbol` 对象。如果该地址对应一个已知的函数，该对象可能包含 `name` (函数名, 例如 "pthread_create")、`moduleName` (模块名, 例如 "libc.so.6")、`fileName` (源文件名，如果有) 和 `lineNumber` (行号，如果有)。如果该地址没有对应的符号信息，则 `name` 等属性可能为 null。

* **`gumjs_symbol_from_name`:**
    * **假设输入:**  一个字符串形式的函数名，例如 `"open"`.
    * **输出:**  一个 JavaScript `Symbol` 对象。如果找到该函数，对象包含其 `address` (函数地址)、`name`、`moduleName` 等信息。如果找不到，`address` 可能为 0，`name` 等属性为 null。

* **`gumjs_symbol_find_functions_named`:**
    * **假设输入:**  一个字符串形式的函数名，例如 `"pthread_mutex_lock"`.
    * **输出:**  一个 JavaScript 数组，包含所有名为 "pthread_mutex_lock" 的函数的地址。数组中的每个元素都是一个表示内存地址的 `NativePointer` 对象。

* **`gumjs_symbol_find_functions_matching`:**
    * **假设输入:**  一个正则表达式字符串，例如 `"^Java_.*_onClick$"`.
    * **输出:**  一个 JavaScript 数组，包含所有函数名匹配该正则表达式的函数的地址。

**用户或编程常见的使用错误**

* **传递无效的地址给 `fromAddress`:**  如果传递的地址不属于任何已加载模块的代码或数据段，可能无法找到对应的符号，或者导致程序崩溃（如果 Frida 尝试访问非法内存）。
* **拼写错误的函数名给 `fromName` 或 `findFunctionsNamed`:**  如果函数名拼写错误，将无法找到目标函数。
* **使用过于宽泛或错误的正则表达式给 `findFunctionsMatching`:**  可能导致返回过多不相关的函数，或者没有返回期望的结果。
* **尝试加载不存在的符号文件给 `load`:**  会导致加载失败，抛出异常。
* **在目标进程没有加载符号信息的情况下尝试获取符号信息:**  很多 release 版本的程序会去除调试符号以减小体积，此时 `fromAddress` 和 `fromName` 可能无法返回有意义的结果。
* **权限问题:** 在 Android 等平台上，加载某些系统库的符号可能需要 root 权限。

**用户操作是如何一步步的到达这里，作为调试线索**

1. **编写 Frida 脚本:** 用户首先会编写一个 JavaScript 脚本，使用 Frida 提供的 API。
2. **使用 `DebugSymbol` 模块:** 在脚本中，用户会调用 `DebugSymbol` 模块的方法，例如 `DebugSymbol.fromAddress(addr)` 或 `DebugSymbol.fromName(name)`.
3. **Frida Bridge:** 当 JavaScript 引擎执行到这些调用时，Frida 的桥接机制会将这些调用转发到对应的 C++ 代码。
4. **进入 `gumv8symbol.cpp`:**  例如，如果调用了 `DebugSymbol.fromAddress(addr)`，那么会执行 `gumjs_symbol_from_address` 函数。
5. **调用 Gum 库:**  在 `gumjs_symbol_from_address` 函数内部，会调用 Frida Gum 库提供的函数，如 `gum_symbol_details_from_address`，来实际查找符号信息。
6. **创建 V8 对象并返回:**  查找到的符号信息会被封装到 `GumSymbol` 结构体中，并创建一个对应的 V8 `Object` (通过 `gum_symbol_new`) 返回给 JavaScript 环境。

**调试线索:**

* **查看 Frida 脚本的 `console.log` 输出:**  用户在脚本中打印的日志可以帮助了解脚本的执行流程和 `DebugSymbol` 返回的结果。
* **使用 Frida 的 `rpc.exports` 功能:**  可以将 C++ 层的内部状态或变量暴露给 JavaScript，方便调试。虽然这个文件本身没有直接使用 `rpc.exports`，但在 Frida 的其他部分可能会用到。
* **使用 V8 调试器:**  可以连接到 Frida 的 V8 引擎，使用 Chrome DevTools 或 Node.js 的调试工具来调试 JavaScript 代码。
* **GDB 调试 Frida Agent:**  如果需要深入了解 C++ 层的行为，可以使用 GDB 连接到 Frida Agent 进程进行调试，设置断点在 `gumjs_symbol_from_address` 等函数中，查看变量的值和执行流程。
* **查看 Frida 的日志输出:**  Frida 本身会输出一些调试信息，可以帮助了解其内部运行状态。

总而言之，`gumv8symbol.cpp` 是 Frida 中一个至关重要的组件，它将底层的符号处理能力暴露给 JavaScript，使得逆向工程师能够方便地进行动态分析和理解目标程序的结构和行为。理解这个文件的功能和原理，对于高效地使用 Frida 进行逆向工作至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8symbol.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020 Matt Oh <oh.jeongwook@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8symbol.h"

#include "gumv8macros.h"

#include <gum/gumsymbolutil.h>

#define GUMJS_MODULE_NAME Symbol

using namespace v8;

struct GumSymbol
{
  Global<Object> * wrapper;
  gboolean resolved;
  GumDebugSymbolDetails details;
  GumV8Symbol * module;
};

GUMJS_DECLARE_FUNCTION (gumjs_symbol_from_address)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_from_name)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_get_function_by_name)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_find_functions_named)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_find_functions_matching)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_load)

static Local<Object> gum_symbol_new (GumV8Symbol * module,
    GumSymbol ** symbol);
static void gum_symbol_free (GumSymbol * self);
GUMJS_DECLARE_GETTER (gumjs_symbol_get_address)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_name)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_module_name)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_file_name)
GUMJS_DECLARE_GETTER (gumjs_symbol_get_line_number)
GUMJS_DECLARE_FUNCTION (gumjs_symbol_to_string)
static void gum_symbol_on_weak_notify (
    const WeakCallbackInfo<GumSymbol> & info);

static const GumV8Function gumjs_symbol_module_functions[] =
{
  { "fromAddress", gumjs_symbol_from_address },
  { "fromName", gumjs_symbol_from_name },
  { "getFunctionByName", gumjs_symbol_get_function_by_name },
  { "findFunctionsNamed", gumjs_symbol_find_functions_named },
  { "findFunctionsMatching", gumjs_symbol_find_functions_matching },
  { "load", gumjs_symbol_load },

  { NULL, NULL }
};

static const GumV8Property gumjs_symbol_values[] =
{
  { "address", gumjs_symbol_get_address, NULL },
  { "name", gumjs_symbol_get_name, NULL },
  { "moduleName", gumjs_symbol_get_module_name, NULL },
  { "fileName", gumjs_symbol_get_file_name, NULL },
  { "lineNumber", gumjs_symbol_get_line_number, NULL },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_symbol_functions[] =
{
  { "toString", gumjs_symbol_to_string },

  { NULL, NULL }
};

void
_gum_v8_symbol_init (GumV8Symbol * self,
                     GumV8Core * core,
                     Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto klass = _gum_v8_create_class ("DebugSymbol", nullptr, scope, module,
      isolate);
  _gum_v8_class_add_static (klass, gumjs_symbol_module_functions, module,
      isolate);
  _gum_v8_class_add (klass, gumjs_symbol_values, module, isolate);
  _gum_v8_class_add (klass, gumjs_symbol_functions, module, isolate);
  self->klass = new Global<FunctionTemplate> (isolate, klass);
}

void
_gum_v8_symbol_realize (GumV8Symbol * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  self->symbols = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_symbol_free);

  auto klass = Local<FunctionTemplate>::New (isolate, *self->klass);
  auto object = klass->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->template_object = new Global<Object> (isolate, object);
}

void
_gum_v8_symbol_dispose (GumV8Symbol * self)
{
  g_hash_table_unref (self->symbols);
  self->symbols = NULL;

  delete self->template_object;
  self->template_object = nullptr;

  delete self->klass;
  self->klass = nullptr;
}

void
_gum_v8_symbol_finalize (GumV8Symbol * self)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_from_address)
{
  gpointer address;
  if (!_gum_v8_args_parse (args, "p", &address))
    return;

  GumSymbol * symbol;
  auto object = gum_symbol_new (module, &symbol);

  symbol->details.address = GPOINTER_TO_SIZE (address);

  {
    ScriptUnlocker unlocker (core);

    symbol->resolved =
        gum_symbol_details_from_address (address, &symbol->details);
  }

  info.GetReturnValue ().Set (object);
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_from_name)
{
  gchar * name;
  if (!_gum_v8_args_parse (args, "s", &name))
    return;

  GumSymbol * symbol;
  auto object = gum_symbol_new (module, &symbol);

  {
    ScriptUnlocker unlocker (core);

    auto address = gum_find_function (name);
    if (address != NULL)
    {
      symbol->resolved =
          gum_symbol_details_from_address (address, &symbol->details);
    }
    else
    {
      symbol->resolved = FALSE;
      symbol->details.address = 0;
    }
  }

  g_free (name);

  info.GetReturnValue ().Set (object);
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_get_function_by_name)
{
  gchar * name;
  if (!_gum_v8_args_parse (args, "s", &name))
    return;

  gpointer address;

  {
    ScriptUnlocker unlocker (core);

    address = gum_find_function (name);
  }

  if (address != NULL)
  {
    info.GetReturnValue ().Set (_gum_v8_native_pointer_new (address, core));
  }
  else
  {
    _gum_v8_throw (isolate, "unable to find function with name '%s'", name);
  }

  g_free (name);
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_find_functions_named)
{
  auto context = isolate->GetCurrentContext ();

  gchar * name;
  if (!_gum_v8_args_parse (args, "s", &name))
    return;

  GArray * functions;

  {
    ScriptUnlocker unlocker (core);

    functions = gum_find_functions_named (name);
  }

  auto result = Array::New (isolate, functions->len);
  for (guint i = 0; i != functions->len; i++)
  {
    auto address = g_array_index (functions, gpointer, i);
    result->Set (context, i, _gum_v8_native_pointer_new (address, core))
        .Check ();
  }

  info.GetReturnValue ().Set (result);

  g_array_free (functions, TRUE);

  g_free (name);
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_find_functions_matching)
{
  auto context = isolate->GetCurrentContext ();

  gchar * str;
  if (!_gum_v8_args_parse (args, "s", &str))
    return;

  GArray * functions;

  {
    ScriptUnlocker unlocker (core);

    functions = gum_find_functions_matching (str);
  }

  auto result = Array::New (isolate, functions->len);
  for (guint i = 0; i != functions->len; i++)
  {
    auto address = g_array_index (functions, gpointer, i);
    result->Set (context, i, _gum_v8_native_pointer_new (address, core))
        .Check ();
  }

  info.GetReturnValue ().Set (result);

  g_array_free (functions, TRUE);

  g_free (str);
}

GUMJS_DEFINE_FUNCTION (gumjs_symbol_load)
{
  gchar * path;
  if (!_gum_v8_args_parse (args, "s", &path))
    return;

  gboolean success;
  {
    ScriptUnlocker unlocker (core);

    success = gum_load_symbols (path);
  }

  if (!success)
    _gum_v8_throw (isolate, "unable to load symbols");

  g_free (path);
}

static Local<Object>
gum_symbol_new (GumV8Symbol * module,
                GumSymbol ** symbol)
{
  auto isolate = module->core->isolate;

  auto template_object = Local<Object>::New (isolate, *module->template_object);
  auto object = template_object->Clone ();

  auto s = g_slice_new (GumSymbol);
  s->wrapper = new Global<Object> (isolate, object);
  s->wrapper->SetWeak (s, gum_symbol_on_weak_notify,
      WeakCallbackType::kParameter);
  s->module = module;

  object->SetAlignedPointerInInternalField (0, s);

  isolate->AdjustAmountOfExternalAllocatedMemory (sizeof (GumSymbol));

  g_hash_table_add (module->symbols, s);

  *symbol = s;

  return object;
}

static void
gum_symbol_free (GumSymbol * self)
{
  self->module->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -((gssize) sizeof (GumSymbol)));

  delete self->wrapper;

  g_slice_free (GumSymbol, self);
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_symbol_get_address, GumSymbol)
{
  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (GSIZE_TO_POINTER (self->details.address),
          core));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_symbol_get_name, GumSymbol)
{
  if (self->resolved)
  {
    info.GetReturnValue ().Set (
        String::NewFromUtf8 (isolate, self->details.symbol_name)
        .ToLocalChecked ());
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_symbol_get_module_name, GumSymbol)
{
  if (self->resolved)
  {
    info.GetReturnValue ().Set (
        String::NewFromUtf8 (isolate, self->details.module_name)
        .ToLocalChecked ());
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_symbol_get_file_name, GumSymbol)
{
  if (self->resolved)
  {
    info.GetReturnValue ().Set (
        String::NewFromUtf8 (isolate, self->details.file_name)
        .ToLocalChecked ());
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_symbol_get_line_number, GumSymbol)
{
  if (self->resolved)
  {
    info.GetReturnValue ().Set ((uint32_t) self->details.line_number);
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_symbol_to_string, GumSymbol)
{
  auto * d = &self->details;

  auto s = g_string_new ("0");

  if (self->resolved)
  {
    g_string_append_printf (s, "x%" G_GINT64_MODIFIER "x %s!%s", d->address,
        d->module_name, d->symbol_name);
    if (d->file_name[0] != '\0')
    {
      g_string_append_printf (s, " %s:%u", d->file_name, d->line_number);
    }
  }
  else if (d->address != 0)
  {
    g_string_append_printf (s, "x%" G_GINT64_MODIFIER "x", d->address);
  }

  info.GetReturnValue ().Set (String::NewFromUtf8 (isolate, s->str)
      .ToLocalChecked ());

  g_string_free (s, TRUE);
}

static void
gum_symbol_on_weak_notify (const WeakCallbackInfo<GumSymbol> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->symbols, self);
}

"""

```