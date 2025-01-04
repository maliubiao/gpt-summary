Response:
Let's break down the thought process for analyzing this C++ code. The request asks for various aspects of the code's functionality, its relation to reverse engineering, low-level details, logic, potential errors, and how a user might reach this code.

**1. High-Level Understanding:**

The first step is to get a general idea of what the code does. The filename `gumv8cmodule.cpp` and the presence of `Gum` and `v8` in the code strongly suggest this is about integrating C modules with the V8 JavaScript engine within the Frida framework. The `#include` directives confirm this, as `gumcmodule.h` and `gumv8macros.h` are likely part of the Frida Gum library.

**2. Identifying Key Structures and Classes:**

Next, identify the core data structures and classes. Looking at the struct definitions:

* `GumCModuleEntry`: This seems to be a wrapper around a `GumCModule` (likely the core C module representation) and its corresponding JavaScript objects (`wrapper`, `symbols`). The presence of `Global<>` indicates these are V8 persistent objects.
* `GumGetBuiltinsOperation` and `GumAddCSymbolsOperation`: These appear to be helper structures for specific operations, holding context like the V8 core and related objects.

The central class seems to be `GumV8CModule`.

**3. Analyzing Key Functions:**

Now, examine the main functions and their roles:

* `_gum_v8_cmodule_init`: This looks like the initialization function for the `GumV8CModule`. It creates the JavaScript `CModule` class template and associates it with C++ functionality. The `External::New` suggests binding C++ data to the JavaScript object.
* `_gum_v8_cmodule_realize`: This seems to handle resource allocation, creating a hash table `cmodules` to store `GumCModuleEntry` instances.
* `_gum_v8_cmodule_dispose` and `_gum_v8_cmodule_finalize`: These are likely for cleanup, releasing resources like the hash table and other allocated memory.
* `gumjs_cmodule_get_builtins`: This function retrieves built-in definitions and headers from the C module and makes them available to JavaScript.
* `gumjs_cmodule_construct`:  This is the constructor for the JavaScript `CModule` object. It handles parsing arguments (source code or binary, symbols, options), creating the underlying `GumCModule`, linking it, and then populating the JavaScript object with the C module's symbols.
* `gum_parse_cmodule_options` and `gum_parse_cmodule_toolchain`: These handle parsing options passed to the `CModule` constructor, specifically the toolchain.
* `gum_add_csymbol`: This function adds a C symbol (name and address) to the JavaScript wrapper object.
* `gumjs_cmodule_dispose`: This is the JavaScript-accessible dispose method, freeing the associated C module.
* `gum_cmodule_entry_new`, `gum_cmodule_entry_free`, `gum_cmodule_entry_on_weak_notify`: These functions manage the lifecycle of the `GumCModuleEntry`, including handling weak references to prevent memory leaks.

**4. Connecting to Reverse Engineering Concepts:**

With an understanding of the functions, consider how they relate to reverse engineering:

* **Dynamic Instrumentation:** The core purpose of Frida is dynamic instrumentation. This code is a key part of *how* Frida lets you load and interact with native code.
* **Code Injection:** Loading a C module is a form of code injection.
* **Symbol Resolution:** The `symbols` argument and the `gum_cmodule_add_symbol` function directly relate to resolving and accessing functions and variables within the injected C module.
* **Interception and Hooking:** While this specific file doesn't implement hooking *itself*, the ability to load arbitrary C code with defined symbols is a prerequisite for building hooks. You could write C code that intercepts function calls in the target process.
* **Memory Manipulation:**  Loading a C module allows direct manipulation of memory within the target process.

**5. Identifying Low-Level Details:**

Focus on interactions with the operating system and hardware:

* **Binary Loading:** The ability to load a compiled binary (`GBytes * binary`) directly interacts with the OS loader.
* **Memory Management:**  The code uses `g_slice_new`, `g_slice_free`, `g_hash_table_new_full`, and `AdjustAmountOfExternalAllocatedMemory`. The latter is a V8 function for tracking external memory usage, important for garbage collection.
* **Toolchains (Internal/External):** The concept of internal and external toolchains suggests handling differences in how the C module is built and linked relative to the target process (e.g., position-independent code).
* **Kernel/Framework (Less Direct):** While this code doesn't directly interact with the kernel, the ability to inject code into an Android app, for instance, relies on Android's framework allowing such operations (often through mechanisms like `dlopen` or similar).

**6. Logical Reasoning (Hypothetical Inputs/Outputs):**

Consider what happens with specific inputs:

* **Input:**  JavaScript code `new CModule("int add(int a, int b) { return a + b; }");`
* **Output:** The `gumjs_cmodule_construct` function would parse the source, compile it (using the chosen toolchain), load it, and expose the `add` function as a symbol that can be called from JavaScript.

* **Input:** JavaScript code `new CModule(binaryData, { "my_global": ptr(0x12345678) });`
* **Output:** The constructor would load the binary data and associate the address `0x12345678` with the JavaScript symbol `my_global`.

**7. Common Usage Errors:**

Think about mistakes a developer might make:

* **Incorrect Toolchain:** Specifying the wrong toolchain (e.g., trying to load code compiled for a different architecture).
* **Missing Symbols:**  Trying to access a symbol in JavaScript that wasn't properly exported or defined in the C module.
* **Memory Leaks in C Module:** If the loaded C code has memory leaks, Frida's tracking might not catch them directly.
* **Incorrect Pointer Types:** Passing the wrong type of pointer or address for symbols.
* **Compilation Errors:**  Providing C source that doesn't compile.

**8. Tracing User Operations (Debugging Clues):**

Imagine debugging an issue related to `CModule`:

* A user calls `new CModule(...)` in their Frida script.
* This call enters the V8 JavaScript engine.
* V8 routes the `new CModule` call to the `gumjs_cmodule_construct` function in this C++ code.
* Inside `gumjs_cmodule_construct`, errors in parsing arguments, compiling the C code, linking, or symbol resolution could occur. Logging within this function would be helpful for debugging.
* If the C module loads successfully, subsequent attempts to access symbols would involve looking up pointers stored in the JavaScript wrapper object, which were populated by `gum_add_csymbol`.

**Self-Correction/Refinement during the Thought Process:**

* Initially, I might focus too much on individual function details. It's important to step back and see the bigger picture of how the components interact.
* Realizing the significance of the `Global<>` objects and weak references is crucial for understanding memory management in the V8 context.
* Connecting the "toolchain" concept to cross-compilation and target architecture is an important refinement.
* Remembering that this code is *part* of Frida, not the entire Frida implementation, helps set the right scope.

By following these steps, systematically analyzing the code, and connecting it to relevant concepts, we can generate a comprehensive explanation like the example provided in the prompt.
This C++ source file, `gumv8cmodule.cpp`, is a crucial part of Frida's dynamic instrumentation capabilities. It's responsible for bridging the gap between JavaScript (running within the V8 engine) and native C modules that can be loaded and executed within a target process. Here's a breakdown of its functionality:

**Core Functionality: Loading and Managing Native C Modules**

The primary purpose of this file is to enable Frida users to load and interact with compiled C code (either from source or a binary) within the target process being instrumented. It provides the JavaScript `CModule` class, which acts as a representation of the loaded native module.

**Key Features and Their Explanations:**

1. **`CModule` Class Creation and Management:**
   - **`_gum_v8_cmodule_init`**: This function initializes the `CModule` JavaScript class within the V8 environment. It sets up the constructor (`gumjs_cmodule_construct`) and associates static and instance methods with the class.
   - **`_gum_v8_cmodule_realize`**:  This function sets up internal data structures, specifically a hash table (`cmodules`) to keep track of loaded `CModule` instances.
   - **`_gum_v8_cmodule_dispose` and `_gum_v8_cmodule_finalize`**: These functions handle the cleanup process when a `CModule` instance is no longer needed, releasing resources and unreferencing the underlying native module.
   - **`GumCModuleEntry`**: This structure holds information about each loaded C module, including:
     - `wrapper`: A V8 `Object` representing the JavaScript `CModule` instance.
     - `symbols`: A V8 `Object` containing the symbols (functions and variables) exported by the native module.
     - `handle`: A pointer to the underlying `GumCModule` structure (from Frida's core C library).
     - `module`: A pointer back to the `GumV8CModule` instance.

2. **Loading C Modules from Source or Binary:**
   - **`gumjs_cmodule_construct`**: This is the constructor for the JavaScript `CModule` class. It takes either C source code or a compiled binary as input.
   - It uses Frida's core functionality (`gum_cmodule_new`) to compile (if source is provided) and load the C module into the target process.
   - It handles optional arguments for providing pre-defined symbols.

3. **Exposing Built-in Definitions and Headers:**
   - **`gumjs_cmodule_get_builtins`**: This static getter on the `CModule` class provides access to built-in C definitions and headers that Frida makes available.
   - **`gum_store_builtin_define` and `gum_store_builtin_header`**: These functions populate the JavaScript object with these built-in definitions and headers. This allows developers to use common types and constants within their dynamically loaded C code.

4. **Managing Symbols:**
   - **`gumjs_cmodule_construct`**: After loading the module, this function iterates through the symbols (functions and variables) exported by the native module.
   - **`gum_add_csymbol`**: This function takes a C symbol name and its address and adds it as a property to the JavaScript `CModule` instance. This allows JavaScript code to directly interact with functions and data within the loaded C module.

5. **Disposing of C Modules:**
   - **`gumjs_cmodule_dispose`**: This function (accessible from JavaScript) allows users to explicitly unload a loaded C module, freeing its resources in the target process.

6. **Handling Module Options:**
   - **`gum_parse_cmodule_options`**: This function parses options passed to the `CModule` constructor, such as the `toolchain` to use for compilation.
   - **`gum_parse_cmodule_toolchain`**: This helper function validates the `toolchain` option.

**Relationship to Reverse Engineering:**

This file is fundamental to many reverse engineering tasks performed with Frida:

* **Code Injection and Extension:**  The ability to load arbitrary C code into a running process is a core code injection technique. This allows reverse engineers to extend the functionality of the target process, add custom instrumentation, or even modify its behavior.
    * **Example:** A reverse engineer could write a C module that intercepts calls to a specific function within the target application and logs the arguments. This module can then be loaded using `CModule` to gain insights into the function's usage.
* **Accessing and Manipulating Native Data Structures:** By loading a C module, you can define structs and access memory locations within the target process. The exposed symbols allow JavaScript to read and write to these structures.
    * **Example:**  If a reverse engineer knows the address of a critical data structure in memory, they could load a C module that defines the structure's layout. Then, using the exposed symbol for the base address, they can read and potentially modify the data from JavaScript.
* **Implementing Complex Logic in Native Code:** For performance-sensitive or complex instrumentation tasks, writing the logic in C and loading it with `CModule` can be more efficient than performing all operations in JavaScript.
    * **Example:**  A reverse engineer might need to perform complex cryptographic operations on intercepted data. Implementing this in C within a loaded module would likely be faster than doing it directly in the JavaScript hook.

**Involvement of Binary Underpinnings, Linux/Android Kernel & Framework:**

* **Binary Loading and Linking:**  The `gum_cmodule_new` and `gum_cmodule_link` functions (from Frida's core library, called by this file) interact with the operating system's dynamic linker. This involves understanding the executable and linking format (like ELF on Linux/Android) to load and resolve symbols within the target process's memory space.
* **Memory Management:**  The code uses `g_slice_new` and `g_slice_free` for allocating memory. More importantly, it interacts with V8's memory management through `AdjustAmountOfExternalAllocatedMemory`. When a C module is loaded, it consumes memory in the target process, and this needs to be tracked to prevent issues with V8's garbage collection.
* **Toolchains and Compilation:** The concept of `toolchain` (internal or external) refers to how the C code is compiled. An "internal" toolchain might refer to using Frida's built-in compilation capabilities (often leveraging `libtooling` or similar), while an "external" toolchain implies the user provides a pre-compiled shared library. This highlights the need to understand compilation processes and the target architecture.
* **Operating System APIs (Indirectly):** While this specific file doesn't directly make syscalls, the underlying `GumCModule` and the loaded C code will likely interact with operating system APIs (e.g., for memory access, file operations, networking). On Android, this might involve interactions with the Android framework (Binder, services) if the loaded C module interacts with those components.

**Logical Reasoning (Hypothetical Input & Output):**

**Scenario:** A Frida script attempts to load a C module with a function that adds two integers.

**Hypothetical Input (JavaScript):**

```javascript
const cm = new CModule(`
  int add(int a, int b) {
    return a + b;
  }
`, {}); // Empty symbols for simplicity

const result = cm.add(5, 3);
console.log(result);
```

**Logical Flow and Potential Output within `gumv8cmodule.cpp`:**

1. The `new CModule(...)` call in JavaScript triggers `gumjs_cmodule_construct`.
2. `gumjs_cmodule_construct` receives the C source code string.
3. It calls `gum_cmodule_new` (not shown in this file, but part of Frida's core) to compile the C code.
4. Assuming compilation is successful, `gum_cmodule_link` is called to link the module.
5. `gum_cmodule_enumerate_symbols` is called, and for the `add` function, `gum_add_csymbol` is invoked.
6. `gum_add_csymbol` adds a property named "add" to the JavaScript `cm` object. The value of this property will be a pointer (represented in a way V8 understands) to the `add` function's address in the loaded module.
7. When `cm.add(5, 3)` is called in JavaScript:
   - V8 looks up the "add" property, finds the pointer to the native function.
   - V8 marshals the arguments (5 and 3) and calls the native `add` function.
   - The `add` function executes (outside the scope of this file).
   - The return value (8) is marshalled back to JavaScript.
8. The `console.log(result)` in JavaScript will output `8`.

**Common User/Programming Errors:**

1. **Incorrect C Source Code:** Providing C code with syntax errors that fails to compile.
   * **Example:** Missing a semicolon, using undeclared variables. This would lead to an error during the `gum_cmodule_new` stage, and Frida would likely throw an exception in JavaScript.
2. **Incorrectly Specifying Symbols:** Trying to access a symbol in JavaScript that wasn't actually exported by the C module or misspelling the symbol name.
   * **Example:** The C module defines a function `calculateSum`, but the JavaScript tries to call `cm.computeSum()`. This would result in an "undefined" error in JavaScript.
3. **Memory Leaks in the Loaded C Module:** If the user's C code allocates memory but doesn't free it, this can lead to memory leaks in the target process. Frida's `CModule` itself doesn't directly manage the memory allocated *within* the loaded C code.
4. **Type Mismatches When Calling C Functions:** Passing JavaScript arguments to the C function that don't match the expected types can lead to crashes or unexpected behavior.
   * **Example:** The C function expects an `int`, but the JavaScript passes a string.
5. **Incorrect Toolchain Options:**  Using the wrong toolchain setting can result in the C module being compiled for the wrong architecture or with incompatible settings, causing loading or execution failures.

**User Operations Leading to this Code (Debugging Clues):**

A user typically interacts with this code indirectly through the Frida API in their JavaScript scripts. Here's a potential step-by-step flow that would lead to execution within `gumv8cmodule.cpp`:

1. **User writes a Frida script:** This script includes code that uses the `CModule` class.
   ```javascript
   const moduleSource = `
     int multiply(int a, int b) {
       return a * b;
     }
   `;
   const myModule = new CModule(moduleSource, {});
   const product = myModule.multiply(7, 6);
   console.log(product);
   ```
2. **User runs the Frida script:** They execute a command like `frida -p <process_id> -s script.js`.
3. **Frida core initializes:** Frida attaches to the target process and starts its JavaScript environment (using V8).
4. **`CModule` constructor is called:** When the JavaScript engine encounters `new CModule(moduleSource, {})`, it calls the `gumjs_cmodule_construct` function in `gumv8cmodule.cpp`.
5. **C Module compilation and loading:** Inside `gumjs_cmodule_construct`, the C source code is passed to Frida's core library to be compiled and loaded into the target process.
6. **Symbol registration:** The `multiply` function's address is obtained, and `gum_add_csymbol` is called to make it accessible as `myModule.multiply` in JavaScript.
7. **JavaScript calls the native function:** When `myModule.multiply(7, 6)` is executed, V8 looks up the native function pointer associated with `multiply` and calls it.
8. **Native function executes:** The `multiply` function in the loaded C module calculates the result (42).
9. **Result returned to JavaScript:** The result is passed back to the JavaScript environment.

If the user encounters an error (e.g., compilation failure, accessing an undefined symbol), the execution path within `gumv8cmodule.cpp` might take different branches, potentially throwing exceptions that are then caught and reported back to the user in the Frida console. Debugging would involve looking at Frida's logs and potentially using a debugger to step through the C++ code in `gumv8cmodule.cpp` and the underlying Frida core libraries.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8cmodule.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2019-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8cmodule.h"

#include "gumcmodule.h"
#include "gumv8macros.h"

#define GUMJS_MODULE_NAME CModule

using namespace v8;

struct GumCModuleEntry
{
  Global<Object> * wrapper;
  Global<Object> * symbols;
  GumCModule * handle;
  GumV8CModule * module;
};

struct GumGetBuiltinsOperation
{
  Local<Object> container;
  GumV8Core * core;
};

struct GumAddCSymbolsOperation
{
  Local<Object> wrapper;
  GumV8Core * core;
};

GUMJS_DECLARE_GETTER (gumjs_cmodule_get_builtins)
static void gum_store_builtin_define (const GumCDefineDetails * details,
    GumGetBuiltinsOperation * op);
static void gum_store_builtin_header (const GumCHeaderDetails * details,
    GumGetBuiltinsOperation * op);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_cmodule_construct)
static gboolean gum_parse_cmodule_options (Local<Object> options_val,
    GumCModuleOptions * options, Local<Context> context, GumV8CModule * parent);
static gboolean gum_parse_cmodule_toolchain (Local<Value> val,
    GumCModuleToolchain * toolchain, Isolate * isolate);
static gboolean gum_add_csymbol (const GumCSymbolDetails * details,
    GumAddCSymbolsOperation * op);
GUMJS_DECLARE_FUNCTION (gumjs_cmodule_dispose)

static GumCModuleEntry * gum_cmodule_entry_new (Local<Object> wrapper,
    Local<Object> symbols, GumCModule * handle, GumV8CModule * module);
static void gum_cmodule_entry_free (GumCModuleEntry * self);
static void gum_cmodule_entry_on_weak_notify (
    const WeakCallbackInfo<GumCModuleEntry> & info);

static const GumV8Property gumjs_cmodule_module_values[] =
{
  { "builtins", gumjs_cmodule_get_builtins, NULL },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_cmodule_functions[] =
{
  { "dispose", gumjs_cmodule_dispose },

  { NULL, NULL }
};

void
_gum_v8_cmodule_init (GumV8CModule * self,
                      GumV8Core * core,
                      Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto cmodule = _gum_v8_create_class ("CModule", gumjs_cmodule_construct,
      scope, module, isolate);
  _gum_v8_class_add_static (cmodule, gumjs_cmodule_module_values, module,
      isolate);
  _gum_v8_class_add (cmodule, gumjs_cmodule_functions, module, isolate);
}

void
_gum_v8_cmodule_realize (GumV8CModule * self)
{
  auto isolate = self->core->isolate;

  self->cmodules = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_cmodule_entry_free);

  self->toolchain_key = new Global<String> (isolate,
      _gum_v8_string_new_ascii (isolate, "toolchain"));
}

void
_gum_v8_cmodule_dispose (GumV8CModule * self)
{
  g_hash_table_remove_all (self->cmodules);

  delete self->toolchain_key;
  self->toolchain_key = nullptr;
}

void
_gum_v8_cmodule_finalize (GumV8CModule * self)
{
  g_clear_pointer (&self->cmodules, g_hash_table_unref);
}

GUMJS_DEFINE_GETTER (gumjs_cmodule_get_builtins)
{
  auto result = Object::New (isolate);

  GumGetBuiltinsOperation op;
  op.core = core;

  op.container = Object::New (isolate);
  gum_cmodule_enumerate_builtin_defines (
      (GumFoundCDefineFunc) gum_store_builtin_define, &op);
  _gum_v8_object_set (result, "defines", op.container, core);

  op.container = Object::New (isolate);
  gum_cmodule_enumerate_builtin_headers (
      (GumFoundCHeaderFunc) gum_store_builtin_header, &op);
  _gum_v8_object_set (result, "headers", op.container, core);

  info.GetReturnValue ().Set (result);
}

static void
gum_store_builtin_define (const GumCDefineDetails * details,
                          GumGetBuiltinsOperation * op)
{
  auto core = op->core;

  if (details->value != NULL)
  {
    _gum_v8_object_set_utf8 (op->container, details->name, details->value,
        core);
  }
  else
  {
    _gum_v8_object_set (op->container, details->name, True (core->isolate),
        core);
  }
}

static void
gum_store_builtin_header (const GumCHeaderDetails * details,
                          GumGetBuiltinsOperation * op)
{
  if (details->kind != GUM_CHEADER_FRIDA)
    return;

  _gum_v8_object_set_utf8 (op->container, details->name, details->data,
      op->core);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_cmodule_construct)
{
  Local<Context> context = isolate->GetCurrentContext ();

  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new CModule()` to create a new instance");
    return;
  }

  if (info.Length () == 0)
  {
    _gum_v8_throw_ascii_literal (isolate, "missing argument");
    return;
  }

  gchar * source = NULL;
  GBytes * binary = NULL;
  Local<Object> symbols;
  Local<Object> options_val;
  if (!info[0]->IsObject ())
  {
    if (!_gum_v8_args_parse (args, "s|O?O?", &source, &symbols, &options_val))
      return;
  }
  else
  {
    if (!_gum_v8_args_parse (args, "B|O?O?", &binary, &symbols, &options_val))
      return;
  }

  GumCModuleOptions options;
  if (!gum_parse_cmodule_options (options_val, &options, context, module))
  {
    g_free (source);
    g_bytes_unref (binary);
    return;
  }

  GError * error = NULL;
  auto handle = gum_cmodule_new (source, binary, &options, &error);

  g_free (source);
  g_bytes_unref (binary);

  if (error == NULL && !symbols.IsEmpty ())
  {
    gboolean valid = TRUE;

    Local<Array> names;
    if (symbols->GetOwnPropertyNames (context).ToLocal (&names))
    {
      guint count = names->Length ();
      for (guint i = 0; i != count; i++)
      {
        Local<Value> name_val;
        if (!names->Get (context, i).ToLocal (&name_val))
        {
          valid = FALSE;
          break;
        }

        Local<String> name_str;
        if (!name_val->ToString (context).ToLocal (&name_str))
        {
          valid = FALSE;
          break;
        }

        String::Utf8Value name_utf8 (isolate, name_str);

        Local<Value> value_val;
        if (!symbols->Get (context, name_val).ToLocal (&value_val))
        {
          valid = FALSE;
          break;
        }

        gpointer value;
        if (!_gum_v8_native_pointer_get (value_val, &value, core))
        {
          valid = FALSE;
          break;
        }

        gum_cmodule_add_symbol (handle, *name_utf8, value);
      }
    }
    else
    {
      valid = FALSE;
    }

    if (!valid)
    {
      g_object_unref (handle);
      return;
    }
  }

  if (error == NULL)
    gum_cmodule_link (handle, &error);

  if (_gum_v8_maybe_throw (isolate, &error))
  {
    g_clear_object (&handle);
    return;
  }

  GumAddCSymbolsOperation op;
  op.wrapper = wrapper;
  op.core = core;

  gum_cmodule_enumerate_symbols (handle, (GumFoundCSymbolFunc) gum_add_csymbol,
      &op);

  gum_cmodule_drop_metadata (handle);

  auto entry = gum_cmodule_entry_new (wrapper, symbols, handle, module);
  wrapper->SetAlignedPointerInInternalField (0, entry);
}

static gboolean
gum_parse_cmodule_options (Local<Object> options_val,
                           GumCModuleOptions * options,
                           Local<Context> context,
                           GumV8CModule * parent)
{
  auto isolate = parent->core->isolate;
  Local<Value> v;

  options->toolchain = GUM_CMODULE_TOOLCHAIN_ANY;

  if (options_val.IsEmpty ())
    return TRUE;

  if (!options_val->Get (context, Local<String>::New (isolate,
      *parent->toolchain_key)).ToLocal (&v))
    return FALSE;
  if (!v->IsUndefined ())
  {
    if (!gum_parse_cmodule_toolchain (v, &options->toolchain, isolate))
      return FALSE;
  }

  return TRUE;
}

static gboolean
gum_parse_cmodule_toolchain (Local<Value> val,
                             GumCModuleToolchain * toolchain,
                             Isolate * isolate)
{
  if (val->IsString ())
  {
    String::Utf8Value str_val (isolate, val);
    auto str = *str_val;

    if (strcmp (str, "any") == 0)
    {
      *toolchain = GUM_CMODULE_TOOLCHAIN_ANY;
      return TRUE;
    }

    if (strcmp (str, "internal") == 0)
    {
      *toolchain = GUM_CMODULE_TOOLCHAIN_INTERNAL;
      return TRUE;
    }

    if (strcmp (str, "external") == 0)
    {
      *toolchain = GUM_CMODULE_TOOLCHAIN_EXTERNAL;
      return TRUE;
    }
  }

  _gum_v8_throw_ascii_literal (isolate, "invalid toolchain value");
  return FALSE;
}

static gboolean
gum_add_csymbol (const GumCSymbolDetails * details,
                 GumAddCSymbolsOperation * op)
{
  _gum_v8_object_set_pointer (op->wrapper, details->name,
      details->address, op->core);

  return TRUE;
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_cmodule_dispose, GumCModuleEntry)
{
  if (self != NULL)
  {
    wrapper->SetAlignedPointerInInternalField (0, NULL);

    g_hash_table_remove (module->cmodules, self);
  }
}

static GumCModuleEntry *
gum_cmodule_entry_new (Local<Object> wrapper,
                       Local<Object> symbols,
                       GumCModule * handle,
                       GumV8CModule * module)
{
  auto isolate = module->core->isolate;
  const GumMemoryRange * range;

  auto entry = g_slice_new (GumCModuleEntry);
  entry->wrapper = new Global<Object> (isolate, wrapper);
  entry->wrapper->SetWeak (entry, gum_cmodule_entry_on_weak_notify,
      WeakCallbackType::kParameter);
  entry->symbols = new Global<Object> (isolate, symbols);
  entry->handle = handle;
  entry->module = module;

  range = gum_cmodule_get_range (handle);
  module->core->isolate->AdjustAmountOfExternalAllocatedMemory (range->size);

  g_hash_table_add (module->cmodules, entry);

  return entry;
}

static void
gum_cmodule_entry_free (GumCModuleEntry * self)
{
  const GumMemoryRange * range;

  range = gum_cmodule_get_range (self->handle);
  self->module->core->isolate->AdjustAmountOfExternalAllocatedMemory (
      -((gssize) range->size));

  g_object_unref (self->handle);

  delete self->symbols;
  delete self->wrapper;

  g_slice_free (GumCModuleEntry, self);
}

static void
gum_cmodule_entry_on_weak_notify (
    const WeakCallbackInfo<GumCModuleEntry> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->module->cmodules, self);
}

"""

```