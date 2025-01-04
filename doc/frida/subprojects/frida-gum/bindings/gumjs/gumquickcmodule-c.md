Response:
Let's break down the thought process for analyzing this C code. The goal is to understand the functionality of `gumquickcmodule.c` within the Frida context.

**1. Initial Scan and Identification of Key Structures:**

The first step is a quick scan of the code to identify the main data structures and functions. Keywords like `struct`, `typedef`, function definitions (`static`, `void`, `gboolean`), and macros (like `GUMJS_DECLARE_*`, `GUMJS_DEFINE_*`, `GUM_QUICK_*`) are important.

*   **Data Structures:**  `GumGetBuiltinsOperation`, `GumAddCSymbolsOperation`, `GumQuickCModule`. These suggest operations related to built-ins and symbols within a C module.
*   **Key Functions:**  Functions starting with `gumjs_cmodule_` are likely the main interface points exposed to JavaScript. Functions like `gum_store_builtin_define`, `gum_parse_cmodule_options`, `gum_add_csymbol` seem to be helper functions.
*   **Macros:**  The `GUMJS_` macros strongly suggest bindings between C and JavaScript. The `GUM_QUICK_` macros hint at a higher-level framework within Frida.

**2. Understanding the Core Functionality (Top-Down):**

The `_gum_quick_cmodule_init` function is clearly the initialization function. It creates a JavaScript class named "CModule" and sets up its prototype and constructor. This strongly suggests that this C code is responsible for providing a way to load and interact with native C code from JavaScript within Frida.

**3. Deeper Dive into Key Functions and Structures:**

*   **`GumQuickCModule`:** This structure likely holds the state for the C module functionality, including a hash table `cmodules` to store loaded C modules and a pointer to the `GumQuickCore`.
*   **`gumjs_cmodule_construct`:** This is the constructor for the "CModule" JavaScript class. It takes arguments related to the C module source (or binary), symbols, and options. It handles the actual loading of the C module using `gum_cmodule_new`, adding symbols, and linking the module.
*   **`gumjs_cmodule_get_builtins`:** This function retrieves built-in definitions and headers, suggesting access to predefined constants and structures.
*   **`gum_add_csymbol`:**  This function takes a C symbol's name and address and makes it accessible as a property on the JavaScript CModule object.

**4. Connecting to Reverse Engineering Concepts:**

The ability to load and interact with native C code directly relates to dynamic instrumentation, a core concept in reverse engineering. Being able to load arbitrary C code or interact with existing native libraries within a process opens up possibilities for:

*   **Hooking:**  Replacing function implementations or inserting code at specific points.
*   **Inspection:**  Reading memory, examining data structures, and understanding program behavior.
*   **Modification:**  Changing program state or altering execution flow.

**5. Identifying Relationships to Binary/OS Concepts:**

*   **Binary Loading:** The constructor handles loading both source code (which needs compilation) and pre-compiled binaries. This involves understanding executable formats (like ELF on Linux/Android).
*   **Symbol Management:**  The concept of symbols (function names, variable names) is fundamental to compiled code and linking. The code explicitly deals with adding and accessing symbols.
*   **Memory Management:**  Pointers and addresses are directly manipulated, highlighting the low-level nature of interacting with native code.
*   **Toolchain:** The "toolchain" option points to the need for compilers (like GCC or Clang) to build C code.
*   **Kernel/Framework Interaction:** While not explicitly detailed in this *file*, the ability to load code into a running process implies interaction with the operating system's process management and potentially dynamic linking mechanisms. On Android, this might involve interacting with the Android runtime (ART).

**6. Logical Inference and Hypothetical Inputs/Outputs:**

Consider a simple C module:

```c
// my_module.c
int add(int a, int b) {
  return a + b;
}
```

**Hypothetical JavaScript Input:**

```javascript
const module = new CModule(`
  int add(int a, int b) {
    return a + b;
  }
`);
const result = module.add(5, 3);
console.log(result); // Expected Output: 8
```

This illustrates how the `CModule` class allows calling C functions from JavaScript.

**7. Identifying Potential User Errors:**

*   **Incorrect Syntax:**  Providing invalid C code will lead to compilation errors.
*   **Missing Symbols:** Trying to access a symbol that wasn't defined or added.
*   **Type Mismatches:**  Passing arguments of the wrong type to C functions.
*   **Memory Errors:**  If the loaded C code has bugs (e.g., buffer overflows), it can crash the process.
*   **Toolchain Issues:** If the required compiler is not available or configured correctly.

**8. Tracing User Actions to the Code:**

A user typically interacts with this code by:

1. **Writing Frida scripts:**  These scripts use the `CModule` class.
2. **Creating a `CModule` instance:** This calls the `gumjs_cmodule_construct` function in the C code.
3. **Providing C code or a binary:** This data is passed as an argument to the constructor.
4. **Optionally providing symbols:** This allows mapping JavaScript names to C function pointers.
5. **Calling methods on the `CModule` object:** This interacts with the loaded C code.

**Self-Correction/Refinement during the Process:**

*   Initially, I might focus too much on the specific details of the `JSValue` and QuickJS API. However, the core functionality is about bridging C and JavaScript. It's important to abstract away the QuickJS specifics to understand the higher-level purpose.
*   Recognizing the naming conventions (`gum_`, `gumjs_`, `_gum_quick_`) helps identify related components and the overall structure of the Frida Gum library.
*   Realizing that this is just *one part* of a larger system (Frida) helps set the scope of the analysis. This file doesn't handle the *execution* of the C code within the target process, but rather the loading and symbol management aspects.

By following these steps, we can systematically analyze the C code and extract its key functionalities, its relevance to reverse engineering, and its interactions with lower-level system concepts.
这个C代码文件 `gumquickcmodule.c` 是 Frida 工具中用于在 JavaScript 中加载和使用 C 模块的功能实现。它定义了 JavaScript 的 `CModule` 类的行为，允许用户在 Frida 脚本中动态地加载 C 代码或预编译的二进制文件，并与之交互。

以下是其主要功能和相关说明：

**1. 创建和管理 C 模块 (JavaScript `CModule` 类):**

*   **功能:**  定义了 JavaScript 中 `CModule` 类的构造函数 (`gumjs_cmodule_construct`)，允许用户通过提供 C 源代码字符串或预编译的二进制数据来创建 `CModule` 的实例。
*   **逆向方法关联:**  这是 Frida 动态插桩的核心能力之一。逆向工程师可以使用它来加载自定义的 C 代码，以扩展 Frida 的功能，例如：
    *   **注入自定义逻辑:**  加载包含 hook 函数的 C 代码，用于替换或拦截目标进程中的函数调用。
    *   **执行底层操作:** 加载可以直接操作内存、调用系统 API 等的 C 代码，执行 JavaScript 难以完成的底层任务。
*   **二进制底层/Linux/Android 内核及框架:**
    *   **二进制底层:** 可以直接加载预编译的二进制文件 (`.so` 或 `.dll`)，这涉及到对二进制文件格式（如 ELF、PE）的理解。
    *   **Linux/Android:**  加载的 C 模块会在目标进程的地址空间中运行，可以调用目标进程中已有的函数或加载额外的共享库。在 Android 上，这可能涉及到与 ART (Android Runtime) 或 Dalvik 虚拟机的交互。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** JavaScript 代码 `const myModule = new CModule('int add(int a, int b) { return a + b; }');`
    *   **输出:**  在 JavaScript 中创建了一个 `myModule` 对象，该对象上会有一个名为 `add` 的属性，其值是一个可以调用 C 函数 `add` 的 JavaScript 函数。
*   **用户或编程常见的使用错误:**
    *   **错误的 C 语法:** 如果提供的 C 源代码包含语法错误，`gum_cmodule_new` 函数会返回错误，并在 JavaScript 中抛出异常。
    *   **缺少符号:** 如果加载的 C 代码依赖于目标进程或系统库中存在的符号，但在创建 `CModule` 时没有正确处理，链接过程可能会失败。
    *   **内存管理错误:** 加载的 C 代码中可能存在内存泄漏或访问非法内存等问题，导致目标进程崩溃。
*   **用户操作到达此处的步骤:**
    1. 用户编写 Frida 脚本。
    2. 脚本中使用 `new CModule(sourceCode)` 或 `new CModule(binaryData)` 来创建一个 `CModule` 对象。
    3. Frida 的 JavaScript 引擎执行到这行代码时，会调用 `gumjs_cmodule_construct` 函数。

**2. 获取内置定义和头文件 (`gumjs_cmodule_get_builtins`):**

*   **功能:**  提供了一种机制，允许 JavaScript 获取 Frida Gum 库中预定义的 C 宏定义 (`defines`) 和头文件内容 (`headers`)。
*   **逆向方法关联:**  这对于编写需要与 Frida Gum 库交互的 C 模块非常有用。逆向工程师可以通过这些内置的定义和头文件，了解 Frida Gum 提供的各种结构体、常量和函数，从而更方便地在自定义的 C 代码中使用它们。
*   **二进制底层/Linux/Android 内核及框架:**  这些内置的定义和头文件通常涉及到 Frida Gum 库对底层操作系统和架构的抽象。例如，可能包含与内存操作、线程管理、进程间通信等相关的定义。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** JavaScript 代码访问 `CModule.builtins` 属性。
    *   **输出:**  返回一个 JavaScript 对象，包含 `defines` 和 `headers` 两个属性，分别存储了内置的 C 宏定义和头文件内容（字符串形式）。
*   **用户或编程常见的使用错误:**  通常不会直接导致错误，但如果用户错误地理解或使用了这些内置的定义，可能会在后续的 C 模块中使用错误的数据类型或常量。
*   **用户操作到达此处的步骤:**
    1. 用户编写 Frida 脚本。
    2. 脚本中尝试访问 `CModule.builtins` 属性，例如 `console.log(CModule.builtins.defines.SOME_CONSTANT);`。
    3. Frida 的 JavaScript 引擎执行到这行代码时，会调用 `gumjs_cmodule_get_builtins` 函数。

**3. 添加 C 符号 (`gum_add_csymbol`):**

*   **功能:**  在 `CModule` 加载后，将 C 模块中的符号（函数或全局变量）暴露给 JavaScript。用户可以在创建 `CModule` 时提供一个符号映射对象，将 C 符号名映射到 JavaScript 可访问的属性。
*   **逆向方法关联:**  这是让 JavaScript 代码能够调用加载的 C 代码的关键步骤。逆向工程师可以通过这种方式，方便地从 JavaScript 脚本中调用自定义 C 模块中的函数或访问全局变量。
*   **二进制底层/Linux/Android 内核及框架:**  这涉及到对符号表的理解，以及如何在运行时解析和访问这些符号。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  创建 `CModule` 时，提供符号映射 `{ "my_c_function": ptr("0x12345678") }`，其中 `0x12345678` 是 `my_c_function` 在目标进程中的地址。
    *   **输出:**  在 JavaScript 中创建的 `CModule` 对象上会有一个名为 `my_c_function` 的属性，其值是一个可以调用位于 `0x12345678` 的 C 函数的 JavaScript 函数。
*   **用户或编程常见的使用错误:**
    *   **错误的符号地址:**  如果提供的符号地址不正确，调用该 JavaScript 函数会导致程序崩溃或产生未预期的行为。
    *   **符号名拼写错误:**  如果符号映射中的符号名与 C 代码中的不一致，将无法正确映射。
*   **用户操作到达此处的步骤:**
    1. 用户编写 Frida 脚本。
    2. 脚本中使用 `new CModule(sourceCode, { my_c_function: ptr(address) })` 来创建一个 `CModule` 对象，并提供符号映射。
    3. 在 `gumjs_cmodule_construct` 函数中，会遍历提供的符号映射，并调用 `gum_cmodule_add_symbol`，最终调用 `gum_add_csymbol` 来完成映射。

**4. 处理 C 模块的选项 (`gum_parse_cmodule_options`):**

*   **功能:**  解析创建 `CModule` 时提供的选项，例如指定编译工具链 (`toolchain`)。
*   **逆向方法关联:**  允许用户更精细地控制 C 模块的加载和编译过程，例如选择使用内部的或外部的编译器。
*   **用户或编程常见的使用错误:**  提供不支持的或错误的选项值会导致创建 `CModule` 失败。
*   **用户操作到达此处的步骤:**
    1. 用户编写 Frida 脚本。
    2. 脚本中使用 `new CModule(sourceCode, null, { toolchain: 'external' })` 来创建一个 `CModule` 对象，并指定选项。
    3. 在 `gumjs_cmodule_construct` 函数中，会调用 `gum_parse_cmodule_options` 来解析这些选项。

**5. 释放 C 模块资源 (`gumjs_cmodule_dispose` 和 `gumjs_cmodule_finalize`):**

*   **功能:**  负责在 `CModule` 对象不再使用时，释放其占用的资源，包括卸载加载的 C 模块。
*   **逆向方法关联:**  确保资源的正确释放对于长时间运行的 Frida 脚本至关重要，避免内存泄漏。
*   **用户操作到达此处的步骤:**
    1. 用户在 JavaScript 中显式调用 `cModuleInstance.dispose()`。
    2. JavaScript 对象的垃圾回收机制触发 `gumjs_cmodule_finalize` 函数的调用。

**与逆向方法的关系举例:**

假设你需要 hook 一个 Android 应用中的 native 函数 `com.example.app.native_function(int)`。你可以创建一个包含 hook 代码的 C 模块，并使用 `CModule` 加载它：

```javascript
const nativeFuncAddr = Module.findExportByName("libnative-lib.so", "com.example.app.native_function");

const cModuleSource = `
#include <frida-gum.h>

void my_native_function(GumInvocationContext *ctx, int arg) {
  g_print("Called native_function with arg: %d\\n", arg);
  gum_invocation_context_resume(ctx); // 继续执行原始函数
}
`;

const cModule = new CModule(cModuleSource);

Interceptor.attach(nativeFuncAddr, {
  onEnter: function(args) {
    const argValue = args[0].toInt32();
    cModule.my_native_function(this.context, argValue);
  }
});
```

在这个例子中，`CModule` 用于加载包含 `my_native_function` 的 C 代码。当 `native_function` 被调用时，Frida 会先执行 `onEnter` 中的代码，其中调用了 C 模块中定义的 `my_native_function`，实现了 hook 的目的。

**涉及到二进制底层、Linux、Android 内核及框架的知识举例:**

*   **二进制底层:**  `CModule` 可以加载预编译的 `.so` 文件，这需要理解 ELF 文件格式、动态链接等概念。
*   **Linux:**  加载的 C 模块会作为共享库加载到目标进程的地址空间中，遵循 Linux 的进程和内存管理机制。
*   **Android 内核及框架:** 在 Android 上，加载 native 库涉及到与 Android 的 linker (`linker64` 或 `linker`) 交互。如果加载的 C 模块需要调用 Android 系统库，需要了解 Android 的 NDK 和 JNI 接口。

总而言之，`gumquickcmodule.c` 是 Frida 中一个关键的组件，它通过 JavaScript 的 `CModule` 类，为动态插桩提供了强大的 native 代码扩展能力，是实现复杂逆向分析和修改的重要工具。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickcmodule.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2020-2021 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickcmodule.h"

#include "gumcmodule.h"
#include "gumquickmacros.h"

#include <string.h>

typedef struct _GumGetBuiltinsOperation GumGetBuiltinsOperation;
typedef struct _GumAddCSymbolsOperation GumAddCSymbolsOperation;

struct _GumGetBuiltinsOperation
{
  JSContext * ctx;
  JSValue container;
};

struct _GumAddCSymbolsOperation
{
  JSValue wrapper;
  GumQuickCore * core;
};

GUMJS_DECLARE_GETTER (gumjs_cmodule_get_builtins)
static void gum_store_builtin_define (const GumCDefineDetails * details,
    GumGetBuiltinsOperation * op);
static void gum_store_builtin_header (const GumCHeaderDetails * details,
    GumGetBuiltinsOperation * op);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_cmodule_construct)
static gboolean gum_parse_cmodule_options (JSContext * ctx, JSValue options_val,
    GumQuickCore * core, GumCModuleOptions * options);
static gboolean gum_parse_cmodule_toolchain (JSContext * ctx, JSValue val,
    GumCModuleToolchain * toolchain);
static gboolean gum_add_csymbol (const GumCSymbolDetails * details,
    GumAddCSymbolsOperation * op);
GUMJS_DECLARE_FINALIZER (gumjs_cmodule_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_cmodule_dispose)

static const JSCFunctionListEntry gumjs_cmodule_module_entries[] =
{
  JS_CGETSET_DEF ("builtins", gumjs_cmodule_get_builtins, NULL),
};

static const JSClassDef gumjs_cmodule_def =
{
  .class_name = "CModule",
  .finalizer = gumjs_cmodule_finalize,
};

static const JSCFunctionListEntry gumjs_cmodule_entries[] =
{
  JS_CFUNC_DEF ("dispose", 0, gumjs_cmodule_dispose),
};

void
_gum_quick_cmodule_init (GumQuickCModule * self,
                         JSValue ns,
                         GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue proto, ctor;

  self->core = core;

  self->cmodules = g_hash_table_new_full (NULL, NULL, NULL, g_object_unref);

  _gum_quick_core_store_module_data (core, "cmodule", self);

  _gum_quick_create_class (ctx, &gumjs_cmodule_def, core, &self->cmodule_class,
      &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_cmodule_construct,
      gumjs_cmodule_def.class_name, 1, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, ctor, gumjs_cmodule_module_entries,
      G_N_ELEMENTS (gumjs_cmodule_module_entries));
  JS_SetPropertyFunctionList (ctx, proto, gumjs_cmodule_entries,
      G_N_ELEMENTS (gumjs_cmodule_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_cmodule_def.class_name, ctor,
      JS_PROP_C_W_E);
}

void
_gum_quick_cmodule_dispose (GumQuickCModule * self)
{
  g_hash_table_remove_all (self->cmodules);
}

void
_gum_quick_cmodule_finalize (GumQuickCModule * self)
{
  g_clear_pointer (&self->cmodules, g_hash_table_unref);
}

static GumQuickCModule *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "cmodule");
}

static gboolean
gum_quick_cmodule_get (JSContext * ctx,
                       JSValueConst val,
                       GumQuickCore * core,
                       GumCModule ** cmodule)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->cmodule_class, core,
      (gpointer *) cmodule);
}

GUMJS_DEFINE_GETTER (gumjs_cmodule_get_builtins)
{
  JSValue result;
  GumGetBuiltinsOperation op;

  result = JS_NewObject (ctx);

  op.ctx = ctx;

  op.container = JS_NewObject (ctx);
  gum_cmodule_enumerate_builtin_defines (
      (GumFoundCDefineFunc) gum_store_builtin_define, &op);
  JS_DefinePropertyValueStr (ctx, result, "defines", op.container,
      JS_PROP_C_W_E);

  op.container = JS_NewObject (ctx);
  gum_cmodule_enumerate_builtin_headers (
      (GumFoundCHeaderFunc) gum_store_builtin_header, &op);
  JS_DefinePropertyValueStr (ctx, result, "headers", op.container,
      JS_PROP_C_W_E);

  return result;
}

static void
gum_store_builtin_define (const GumCDefineDetails * details,
                          GumGetBuiltinsOperation * op)
{
  JSContext * ctx = op->ctx;

  JS_DefinePropertyValueStr (ctx, op->container, details->name,
      (details->value != NULL) ? JS_NewString (ctx, details->value) : JS_TRUE,
      JS_PROP_C_W_E);
}

static void
gum_store_builtin_header (const GumCHeaderDetails * details,
                          GumGetBuiltinsOperation * op)
{
  JSContext * ctx = op->ctx;

  if (details->kind != GUM_CHEADER_FRIDA)
    return;

  JS_DefinePropertyValueStr (ctx, op->container, details->name,
      JS_NewString (ctx, details->data),
      JS_PROP_C_W_E);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_cmodule_construct)
{
  JSValue result;
  GumQuickCModule * parent;
  const gchar * source;
  GBytes * binary;
  JSValue symbols;
  JSValue options_val;
  GumCModuleOptions options;
  JSValue proto;
  JSValue wrapper = JS_NULL;
  GumCModule * cmodule = NULL;
  GError * error;
  JSPropertyEnum * properties = NULL;
  uint32_t n = 0;
  uint32_t i;
  const char * name = NULL;
  JSValue val = JS_NULL;
  GumAddCSymbolsOperation add_op;

  parent = gumjs_get_parent_module (core);

  source = NULL;
  binary = NULL;
  symbols = JS_NULL;
  options_val = JS_NULL;
  if (!JS_IsObject (args->elements[0]))
  {
    if (!_gum_quick_args_parse (args, "s|O?O?", &source, &symbols,
        &options_val))
      goto propagate_exception;
  }
  else
  {
    if (!_gum_quick_args_parse (args, "B|O?O?", &binary, &symbols,
        &options_val))
      goto propagate_exception;
  }

  if (!gum_parse_cmodule_options (ctx, options_val, core, &options))
    goto propagate_exception;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, parent->cmodule_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  error = NULL;
  cmodule = gum_cmodule_new (source, binary, &options, &error);
  if (error != NULL)
    goto propagate_error;

  if (!JS_IsNull (symbols))
  {
    if (JS_GetOwnPropertyNames (ctx, &properties, &n, symbols,
        JS_GPN_STRING_MASK | JS_GPN_ENUM_ONLY) != 0)
      goto propagate_exception;

    for (i = 0; i != n; i++)
    {
      JSAtom name_atom = properties[i].atom;
      gpointer v;

      name = JS_AtomToCString (ctx, name_atom);
      if (name == NULL)
        goto propagate_exception;

      val = JS_GetProperty (ctx, symbols, name_atom);
      if (JS_IsException (val))
        goto propagate_exception;

      if (!_gum_quick_native_pointer_get (ctx, val, core, &v))
        goto propagate_exception;

      gum_cmodule_add_symbol (cmodule, name, v);

      JS_FreeValue (ctx, val);
      val = JS_NULL;

      JS_FreeCString (ctx, name);
      name = NULL;
    }

    /* Anchor lifetime to CModule instance. */
    JS_DefinePropertyValue (ctx, wrapper,
        GUM_QUICK_CORE_ATOM (core, resource),
        JS_DupValue (ctx, symbols),
        0);
  }

  if (!gum_cmodule_link (cmodule, &error))
    goto propagate_error;

  add_op.wrapper = wrapper;
  add_op.core = core;
  gum_cmodule_enumerate_symbols (cmodule, (GumFoundCSymbolFunc) gum_add_csymbol,
      &add_op);

  gum_cmodule_drop_metadata (cmodule);

  g_hash_table_add (parent->cmodules, cmodule);

  JS_SetOpaque (wrapper, g_steal_pointer (&cmodule));

  result = wrapper;
  wrapper = JS_NULL;

  goto beach;

propagate_error:
  {
    _gum_quick_throw_error (ctx, &error);
    goto propagate_exception;
  }
propagate_exception:
  {
    result = JS_EXCEPTION;
    goto beach;
  }
beach:
  {
    JS_FreeValue (ctx, val);
    JS_FreeCString (ctx, name);

    for (i = 0; i != n; i++)
      JS_FreeAtom (ctx, properties[i].atom);
    js_free (ctx, properties);

    g_clear_object (&cmodule);

    JS_FreeValue (ctx, wrapper);

    return result;
  }
}

static gboolean
gum_parse_cmodule_options (JSContext * ctx,
                           JSValue options_val,
                           GumQuickCore * core,
                           GumCModuleOptions * options)
{
  JSValue val;

  options->toolchain = GUM_CMODULE_TOOLCHAIN_ANY;

  if (JS_IsNull (options_val))
    return TRUE;

  val = JS_GetProperty (ctx, options_val,
      GUM_QUICK_CORE_ATOM (core, toolchain));
  if (JS_IsException (val))
    return FALSE;
  if (!JS_IsUndefined (val))
  {
    if (!gum_parse_cmodule_toolchain (ctx, val, &options->toolchain))
      goto invalid_value;
    JS_FreeValue (ctx, val);
  }

  return TRUE;

invalid_value:
  {
    JS_FreeValue (ctx, val);

    return FALSE;
  }
}

static gboolean
gum_parse_cmodule_toolchain (JSContext * ctx,
                             JSValue val,
                             GumCModuleToolchain * toolchain)
{
  gboolean valid;
  const char * str;

  if (!_gum_quick_string_get (ctx, val, &str))
    return FALSE;

  valid = TRUE;

  if (strcmp (str, "any") == 0)
  {
    *toolchain = GUM_CMODULE_TOOLCHAIN_ANY;
  }
  else if (strcmp (str, "internal") == 0)
  {
    *toolchain = GUM_CMODULE_TOOLCHAIN_INTERNAL;
  }
  else if (strcmp (str, "external") == 0)
  {
    *toolchain = GUM_CMODULE_TOOLCHAIN_EXTERNAL;
  }
  else
  {
    _gum_quick_throw_literal (ctx, "invalid toolchain value");
    valid = FALSE;
  }

  JS_FreeCString (ctx, str);

  return valid;
}

static gboolean
gum_add_csymbol (const GumCSymbolDetails * details,
                 GumAddCSymbolsOperation * op)
{
  GumQuickCore * core = op->core;
  JSContext * ctx = core->ctx;

  JS_DefinePropertyValueStr (ctx, op->wrapper,
      details->name,
      _gum_quick_native_pointer_new (ctx, details->address, core),
      JS_PROP_C_W_E);

  return TRUE;
}

GUMJS_DEFINE_FINALIZER (gumjs_cmodule_finalize)
{
  GumQuickCModule * parent;
  GumCModule * m;

  parent = gumjs_get_parent_module (core);

  m = JS_GetOpaque (val, parent->cmodule_class);
  if (m == NULL)
    return;

  g_hash_table_remove (parent->cmodules, m);
}

GUMJS_DEFINE_FUNCTION (gumjs_cmodule_dispose)
{
  GumCModule * self;

  if (!gum_quick_cmodule_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (self != NULL)
  {
    g_hash_table_remove (gumjs_get_parent_module (core)->cmodules, self);

    JS_SetOpaque (this_val, NULL);
  }

  return JS_UNDEFINED;
}

"""

```