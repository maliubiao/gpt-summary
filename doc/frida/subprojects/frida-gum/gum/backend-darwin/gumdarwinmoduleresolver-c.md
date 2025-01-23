Response:
Let's break down the thought process for analyzing this C code and generating the detailed explanation.

**1. Understanding the Core Purpose:**

The first step is to read the initial comments and the overall structure of the code. The filename `gumdarwinmoduleresolver.c` and the inclusion of `<mach-o/loader.h>` strongly suggest this code is about resolving modules (like shared libraries or executables) in a Darwin (macOS/iOS) environment. The `frida` prefix confirms it's related to the Frida instrumentation framework. The `Gum` prefix indicates this is likely a part of Frida's internal "glue" or core library.

**2. Identifying Key Data Structures and Functions:**

Next, scan the code for important structures and functions. Notice:

* `GumDarwinModuleResolver`: This is the central object. It holds the state and provides the functionality.
* `GumDarwinModule`:  Likely represents a single loaded module.
* `GumExportDetails`:  Information about exported symbols within a module.
* `gum_darwin_module_resolver_new`, `gum_darwin_module_resolver_load`: Obvious constructor and loading functions.
* `gum_darwin_module_resolver_find_module`, `gum_darwin_module_resolver_find_export`, etc.: Functions for looking up modules and symbols.
* `gum_darwin_enumerate_modules`:  A function interacting with the operating system to get a list of loaded modules.
* `GumCollectModulesContext`:  A helper struct to pass data during module enumeration.

**3. Tracing the Initialization Process (`gum_darwin_module_resolver_new`, `gum_darwin_module_resolver_load`):**

Follow the flow of execution when a `GumDarwinModuleResolver` is created.

* `gum_darwin_module_resolver_new` creates the object and calls `gum_darwin_module_resolver_load`.
* `gum_darwin_module_resolver_load` does the heavy lifting:
    * Checks if modules are already loaded.
    * Queries the target process (`task`) for features like pointer authentication (`gum_darwin_query_ptrauth_support`) and page size.
    * Gets the process ID (`pid_for_task`).
    * Gets the CPU architecture (`gum_darwin_cpu_type_from_pid`).
    * **Crucially**, it uses `gum_darwin_enumerate_modules` twice:
        * First with `gum_find_sysroot` to determine the system root directory. This is important for resolving system libraries.
        * Second with `gum_store_module` to actually create `GumDarwinModule` objects and store them in a hash table (`self->modules`).

**4. Analyzing Module and Symbol Resolution (`gum_darwin_module_resolver_find_module`, `gum_darwin_module_resolver_find_export`, etc.):**

Understand how Frida finds modules and specific functions or variables within them.

* `gum_darwin_module_resolver_find_module` looks up modules by name or path in the `self->modules` hash table. It also has special handling for system libraries under `/usr/lib/system/`.
* `gum_darwin_module_resolver_find_export` (and its mangled name variant) is more complex:
    * It first tries to resolve the symbol within the given `module`.
    * If not found, and the module has re-exports, it iterates through the re-exported libraries and tries to find the symbol there.
* `gum_darwin_module_resolver_resolve_export` handles the details of how an exported symbol's address is calculated, considering re-exports, stubs, and pointer authentication.

**5. Identifying Interactions with the Operating System and Architecture:**

Look for functions with prefixes like `gum_darwin_`. These likely interact with Darwin-specific APIs.

* `gum_darwin_enumerate_modules`:  Obtains the list of loaded modules. This is a direct interaction with the OS kernel.
* `gum_darwin_query_ptrauth_support`, `gum_darwin_query_page_size`: Querying kernel information.
* `pid_for_task`:  Getting process information.
* `<mach-o/loader.h>`:  Includes definitions for the Mach-O binary format, which is fundamental to how executables and libraries are structured on macOS/iOS.

**6. Considering the Frida Context:**

Remember this code is part of Frida. Think about how this component fits into the larger picture. Frida allows inspecting and manipulating the runtime behavior of applications. This module resolver is essential for:

* **Hooking:** Frida needs to know the addresses of functions to place hooks.
* **Interception:** Understanding function boundaries and arguments.
* **Code Injection:**  Knowing where to load and execute custom code.

**7. Addressing the Specific Questions:**

Now, go through the prompt's questions systematically:

* **Functionality:** Summarize the key functions and their roles.
* **Relationship to Reversing:** Explain how module and symbol resolution are fundamental to reverse engineering (identifying functions, understanding program structure).
* **Binary/Kernel/Framework Knowledge:**  Point out the use of Mach-O, the interaction with the Darwin kernel (through `task` ports and functions like `gum_darwin_enumerate_modules`), and the relevance to Android (in terms of shared library concepts, although this specific code is Darwin-focused).
* **Logical Inference:**  Consider scenarios, like failing to find a module or export, and the corresponding error handling.
* **User Errors:**  Think about how incorrect usage of Frida or providing an invalid target process could lead to errors in this code.
* **User Operation to Reach Here:** Describe the typical Frida workflow that would involve this module resolver.

**8. Refinement and Examples:**

Finally, review and refine the explanation. Add concrete examples to illustrate the concepts (e.g., hooking `malloc`, resolving system library functions). Ensure the language is clear and addresses all aspects of the prompt. For the "user error" section, think about common mistakes a Frida user might make. For the "debugging" section, outline the typical steps that lead to the execution of this code.

By following these steps, you can systematically analyze the code and generate a comprehensive and informative explanation. The key is to understand the code's purpose, identify its key components, and connect it to the broader context of Frida and the underlying operating system.
This is the source code for `gumdarwinmoduleresolver.c`, a component of the Frida dynamic instrumentation toolkit specifically designed for Darwin (macOS, iOS, etc.) based systems. Its primary function is to **resolve modules (like libraries and executables) and their exported symbols within a target process.** Let's break down its functionalities and connections to the topics you mentioned.

**Functionalities:**

1. **Module Discovery and Storage:**
   - It can discover all loaded modules in a target process specified by a Mach task port (`task`).
   - It stores information about these modules (name, path, base address, etc.) in a hash table (`self->modules`). This allows for efficient lookup later.
   - It differentiates between the module's full path and its base name for lookup. It also handles cases where the module path might be under a simulated root (`/usr/lib/dyld_sim`).

2. **Symbol Resolution:**
   - It can find the address of exported symbols (functions and variables) within a given module.
   - It handles both regular symbols and re-exported symbols (symbols exported by one module but actually residing in another).
   - It considers the Mach-O binary format's specific ways of exporting symbols, including stubs and resolvers.
   - It integrates with pointer authentication (PAC) if supported by the target architecture, signing function addresses where necessary.

3. **Dynamic Symbol Lookup:**
   - It allows setting a custom handler (`lookup_dynamic_func`) for resolving symbols that might not be statically exported or are resolved at runtime (e.g., through `dlsym`).

4. **System Root Detection:**
   - It attempts to identify the system root directory based on the presence of `dyld_sim`. This is relevant in simulated environments.

5. **Error Handling:**
   - It includes basic error handling, particularly for invalid task ports (meaning the target process might be dead).

**Relationship to Reverse Engineering:**

This module resolver is a **fundamental component of reverse engineering on Darwin**. Here's how:

* **Identifying Function Addresses:**  Reverse engineers often need to find the memory address of specific functions (e.g., `malloc`, `strcmp`, API calls) to analyze their behavior, set breakpoints, or hook them. `gum_darwin_module_resolver_find_export_address` directly provides this functionality.
    * **Example:** A reverse engineer might want to hook the `-[NSString stringWithUTF8String:]` method in `Foundation.framework`. Frida would use `GumDarwinModuleResolver` to find the base address of `Foundation.framework` and then the offset of the `stringWithUTF8String:` symbol within that module to calculate its runtime address.
* **Understanding Program Structure:** By listing all loaded modules, a reverse engineer can gain insights into the different libraries a program uses and how they are organized in memory.
* **Analyzing Re-exports:** The ability to handle re-exports is crucial because many system libraries re-export symbols from other lower-level libraries. Without this, finding the actual implementation of a function could be difficult.
    * **Example:**  A function like `pthread_mutex_lock` might be declared in `libpthread.dylib` but its actual implementation might reside in `libsystem_pthread.dylib`. `GumDarwinModuleResolver` can trace this re-export.
* **Dynamic Analysis:**  Frida, built upon this module resolver, enables dynamic analysis techniques like hooking and tracing function calls. Knowing the correct addresses of functions is essential for placing these hooks.

**Involvement of Binary, Linux, Android Kernel/Framework Knowledge:**

* **Binary Bottom Layer (Mach-O):** The code directly interacts with concepts from the Mach-O executable format, which is the standard binary format on Darwin systems. The code includes `<mach-o/loader.h>`, which provides structures and definitions for parsing Mach-O headers and load commands. Understanding segments, sections, and the symbol table is necessary to implement this module resolver.
* **Darwin Kernel:** The code uses Darwin kernel APIs, particularly those related to tasks and memory management. The `mach_port_t task` represents a port through which the Frida agent can interact with the target process's kernel representation. Functions like `pid_for_task` directly interact with the kernel. `gum_darwin_enumerate_modules` is a higher-level abstraction, but it internally relies on kernel calls to retrieve module information.
* **Linux Kernel (Indirect Relation):** While this code is specific to Darwin, the fundamental concepts of module loading, symbol resolution, and dynamic linking are also present in Linux. Understanding how shared libraries (`.so` files) work on Linux, how the dynamic linker (`ld.so`) resolves symbols, and concepts like the Global Offset Table (GOT) and Procedure Linkage Table (PLT) provides a broader context for understanding the purpose of this Darwin-specific module resolver.
* **Android Kernel/Framework (Indirect Relation):** Similar to Linux, Android uses a Linux-based kernel and has its own system for loading shared libraries (`.so` files, often in ELF format). While the specific APIs and binary formats differ from Darwin, the core problem of finding modules and their symbols is the same. Someone familiar with Android's linker (`linker64` or `linker`) and its handling of symbols would grasp the high-level goals of this code.

**Logical Inference (Hypothetical Input/Output):**

**Hypothetical Input:**

* `task`: A valid Mach task port representing a running process (e.g., the Safari browser).
* `module_name`: `"libsystem_c.dylib"`
* `symbol`: `"malloc"`

**Logical Output:**

1. **`gum_darwin_module_resolver_find_module(self, "libsystem_c.dylib")`:** This would likely return a pointer to a `GumDarwinModule` structure containing information about `libsystem_c.dylib`, including its base address in the target process's memory.
2. **`gum_darwin_module_resolver_find_export_address(self, module, "malloc")`:** This would calculate the absolute memory address of the `malloc` function within the loaded `libsystem_c.dylib` module. This address would be relative to the module's base address and the offset of the `malloc` symbol within the module's symbol table. If pointer authentication is active, the address might be signed using `gum_sign_code_address`.

**Hypothetical Input (Failure Case):**

* `task`: A valid Mach task port.
* `module_name`: `"nonexistent_library.dylib"`
* `symbol`: `"some_function"`

**Logical Output:**

1. **`gum_darwin_module_resolver_find_module(self, "nonexistent_library.dylib")`:** This would return `NULL` because the library is not loaded in the target process.
2. **`gum_darwin_module_resolver_find_export_address(self, NULL, "some_function")`:**  Since the module is `NULL`, this would likely return `0` or some other indicator of failure. Error checking within Frida would then handle this.

**User or Programming Common Usage Errors:**

1. **Invalid Task Port:** Providing an invalid or dead task port to `gum_darwin_module_resolver_new`. This will likely lead to errors during the `gum_darwin_module_resolver_load` phase, as system calls to query the process will fail. The error message "Process is dead" indicates this scenario.
    * **Example:** A user might try to attach to a process that has already exited.
2. **Incorrect Module Name:**  Providing an incorrect or misspelled module name to `gum_darwin_module_resolver_find_module`. This will result in the function returning `NULL`.
    * **Example:**  A user might type `"libSystem.dylib"` instead of `"libsystem.dylib"`.
3. **Incorrect Symbol Name:** Providing an incorrect or misspelled symbol name to `gum_darwin_module_resolver_find_export_address`. This will result in the function returning `0`. Note that symbol names are often mangled (prefixed with an underscore on Darwin), so users need to be aware of this.
    * **Example:**  Trying to find `"printf"` instead of `"_printf"`. Frida usually handles this mangling, but direct usage of this low-level API might require awareness.
4. **Trying to Resolve Symbols in Unloaded Modules:** Attempting to find symbols in a module that is not currently loaded in the target process. The `gum_darwin_module_resolver_find_module` function would return `NULL` in this case.

**User Operation Steps to Reach Here (Debugging Clues):**

The user's interaction with Frida that leads to this code being executed typically involves attaching to a running process and then performing operations that require resolving module and symbol information. Here's a possible sequence:

1. **User Starts a Frida Session:** The user initiates Frida, typically through the command-line interface (`frida`) or programmatically using the Frida API.
2. **User Attaches to a Process:** The user specifies the target process they want to instrument, either by process ID, process name, or by spawning a new process. Frida establishes a connection to the target process, obtaining its Mach task port.
3. **Frida Agent Injection:** Frida injects a lightweight agent (written in JavaScript or other languages) into the target process. This agent communicates back to the Frida host process.
4. **Agent Requests Module/Symbol Information:** The injected agent (or the user interacting with the agent) performs actions that require resolving module or symbol addresses. This could be:
    * **Listing Loaded Modules:** The agent might call a Frida API function to get a list of all loaded modules. This would trigger `gum_darwin_enumerate_modules` within the `GumDarwinModuleResolver`.
    * **Hooking a Function:** The user specifies a function they want to hook (intercept). Frida needs to find the address of this function. This involves:
        * Using `gum_darwin_module_resolver_find_module` to locate the module containing the function.
        * Using `gum_darwin_module_resolver_find_export_address` to get the function's address.
    * **Reading/Writing Memory:**  If the user wants to read or write memory at a specific location within a module, Frida needs to resolve the module's base address.
5. **`GumDarwinModuleResolver` is Used:**  The Frida core library, specifically the `gum` component and this `gumdarwinmoduleresolver.c` file, is invoked to perform the module and symbol resolution tasks as described above. The `GumDarwinModuleResolver` object is created (or reused), and its methods are called to fulfill the agent's requests.

**In summary, `gumdarwinmoduleresolver.c` is a critical low-level component in Frida that enables dynamic instrumentation on Darwin-based systems by providing the fundamental ability to locate and understand the memory layout of target processes.**

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gumdarwinmoduleresolver.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2015-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gum/gumdarwinmoduleresolver.h"

#include "gum/gumdarwin.h"

#include <mach-o/loader.h>

typedef struct _GumCollectModulesContext GumCollectModulesContext;

enum
{
  PROP_0,
  PROP_TASK
};

struct _GumCollectModulesContext
{
  GumDarwinModuleResolver * self;
  guint index;
  gchar * sysroot;
  guint sysroot_length;
};

static void gum_darwin_module_resolver_constructed (GObject * object);
static void gum_darwin_module_resolver_finalize (GObject * object);
static void gum_darwin_module_resolver_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_darwin_module_resolver_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gboolean gum_find_sysroot (const GumModuleDetails * details,
    gpointer user_data);
static gboolean gum_store_module (const GumModuleDetails * details,
    gpointer user_data);

G_DEFINE_TYPE (GumDarwinModuleResolver,
               gum_darwin_module_resolver,
               G_TYPE_OBJECT)

static void
gum_darwin_module_resolver_class_init (GumDarwinModuleResolverClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_darwin_module_resolver_constructed;
  object_class->finalize = gum_darwin_module_resolver_finalize;
  object_class->get_property = gum_darwin_module_resolver_get_property;
  object_class->set_property = gum_darwin_module_resolver_set_property;

  g_object_class_install_property (object_class, PROP_TASK,
      g_param_spec_uint ("task", "task", "Mach task", 0, G_MAXUINT,
      MACH_PORT_NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_module_resolver_init (GumDarwinModuleResolver * self)
{
  self->modules = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      g_object_unref);
}

static void
gum_darwin_module_resolver_constructed (GObject * object)
{
}

static void
gum_darwin_module_resolver_finalize (GObject * object)
{
  GumDarwinModuleResolver * self = GUM_DARWIN_MODULE_RESOLVER (object);

  gum_darwin_module_resolver_set_dynamic_lookup_handler (self, NULL, NULL,
      NULL);

  g_free (self->sysroot);
  g_hash_table_unref (self->modules);

  G_OBJECT_CLASS (gum_darwin_module_resolver_parent_class)->finalize (object);
}

static void
gum_darwin_module_resolver_get_property (GObject * object,
                                         guint property_id,
                                         GValue * value,
                                         GParamSpec * pspec)
{
  GumDarwinModuleResolver * self = GUM_DARWIN_MODULE_RESOLVER (object);

  switch (property_id)
  {
    case PROP_TASK:
      g_value_set_uint (value, self->task);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_darwin_module_resolver_set_property (GObject * object,
                                         guint property_id,
                                         const GValue * value,
                                         GParamSpec * pspec)
{
  GumDarwinModuleResolver * self = GUM_DARWIN_MODULE_RESOLVER (object);

  switch (property_id)
  {
    case PROP_TASK:
      self->task = g_value_get_uint (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinModuleResolver *
gum_darwin_module_resolver_new (mach_port_t task,
                                GError ** error)
{
  GumDarwinModuleResolver * resolver;

  resolver = g_object_new (GUM_DARWIN_TYPE_MODULE_RESOLVER,
      "task", task,
      NULL);
  if (!gum_darwin_module_resolver_load (resolver, error))
  {
    g_object_unref (resolver);
    resolver = NULL;
  }

  return resolver;
}

gboolean
gum_darwin_module_resolver_load (GumDarwinModuleResolver * self,
                                 GError ** error)
{
  int pid;
  GumCollectModulesContext ctx;

  if (g_hash_table_size (self->modules) != 0)
    return TRUE;

  if (!gum_darwin_query_ptrauth_support (self->task, &self->ptrauth_support))
    goto invalid_task;

  if (!gum_darwin_query_page_size (self->task, &self->page_size))
    goto invalid_task;

  if (pid_for_task (self->task, &pid) != KERN_SUCCESS)
    goto invalid_task;

  if (!gum_darwin_cpu_type_from_pid (pid, &self->cpu_type))
    goto invalid_task;

  ctx.self = self;
  ctx.index = 0;
  ctx.sysroot = NULL;
  ctx.sysroot_length = 0;

  gum_darwin_enumerate_modules (self->task, gum_find_sysroot, &ctx);
  gum_darwin_enumerate_modules (self->task, gum_store_module, &ctx);
  if (ctx.index == 0)
    goto invalid_task;

  self->sysroot = ctx.sysroot;

  return TRUE;

invalid_task:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Process is dead");
    return FALSE;
  }
}

void
gum_darwin_module_resolver_set_dynamic_lookup_handler (
    GumDarwinModuleResolver * self,
    GumDarwinModuleResolverLookupFunc func,
    gpointer data,
    GDestroyNotify data_destroy)
{
  if (self->lookup_dynamic_data_destroy != NULL)
    self->lookup_dynamic_data_destroy (self->lookup_dynamic_data);

  self->lookup_dynamic_func = func;
  self->lookup_dynamic_data = data;
  self->lookup_dynamic_data_destroy = data_destroy;
}

GumDarwinModule *
gum_darwin_module_resolver_find_module (GumDarwinModuleResolver * self,
                                        const gchar * module_name)
{
  GumDarwinModule * module;

  module = g_hash_table_lookup (self->modules, module_name);
  if (module != NULL)
    return module;

  if (g_str_has_prefix (module_name, "/usr/lib/system/"))
  {
    gchar * alias =
        g_strconcat ("/usr/lib/system/introspection/", module_name + 16, NULL);

    module = g_hash_table_lookup (self->modules, alias);

    g_free (alias);
  }

  return module;
}

gboolean
gum_darwin_module_resolver_find_export (GumDarwinModuleResolver * self,
                                        GumDarwinModule * module,
                                        const gchar * symbol,
                                        GumExportDetails * details)
{
  gchar * mangled_symbol;
  gboolean success;

  mangled_symbol = g_strconcat ("_", symbol, NULL);
  success = gum_darwin_module_resolver_find_export_by_mangled_name (self,
      module, mangled_symbol, details);
  g_free (mangled_symbol);

  return success;
}

GumAddress
gum_darwin_module_resolver_find_export_address (GumDarwinModuleResolver * self,
                                                GumDarwinModule * module,
                                                const gchar * symbol)
{
  GumExportDetails details;

  if (!gum_darwin_module_resolver_find_export (self, module, symbol, &details))
    return 0;

  return details.address;
}

gboolean
gum_darwin_module_resolver_find_export_by_mangled_name (
    GumDarwinModuleResolver * self,
    GumDarwinModule * module,
    const gchar * symbol,
    GumExportDetails * details)
{
  GumDarwinModule * m;
  GumDarwinExportDetails d;
  gboolean found;

  found = gum_darwin_module_resolve_export (module, symbol, &d);
  if (found)
  {
    m = module;
  }
  else if (gum_darwin_module_get_lacks_exports_for_reexports (module))
  {
    GPtrArray * reexports = module->reexports;
    guint i;

    for (i = 0; !found && i != reexports->len; i++)
    {
      GumDarwinModule * reexport;

      reexport = gum_darwin_module_resolver_find_module (self,
          g_ptr_array_index (reexports, i));
      if (reexport != NULL)
      {
        found = gum_darwin_module_resolve_export (reexport, symbol, &d);
        if (found)
          m = reexport;
      }
    }

    if (!found)
      return FALSE;
  }
  else
  {
    return FALSE;
  }

  return gum_darwin_module_resolver_resolve_export (self, m, &d, details);
}

gboolean
gum_darwin_module_resolver_resolve_export (
    GumDarwinModuleResolver * self,
    GumDarwinModule * module,
    const GumDarwinExportDetails * export,
    GumExportDetails * result)
{
  if ((export->flags & EXPORT_SYMBOL_FLAGS_REEXPORT) != 0)
  {
    const gchar * target_module_name;
    GumDarwinModule * target_module;
    gboolean is_reexporting_itself;

    target_module_name = gum_darwin_module_get_dependency_by_ordinal (module,
        export->reexport_library_ordinal);
    target_module = gum_darwin_module_resolver_find_module (self,
        target_module_name);
    if (target_module == NULL)
      return FALSE;

    is_reexporting_itself = (target_module == module &&
        strcmp (export->reexport_symbol, export->name) == 0);
    if (is_reexporting_itself)
    {
      /*
       * Happens with a few of the Security.framework exports on High Sierra
       * beta 4, and seems like a bug given that dlsym() crashes with a
       * stack-overflow when asked to resolve these.
       */
      return FALSE;
    }

    return gum_darwin_module_resolver_find_export_by_mangled_name (self,
        target_module, export->reexport_symbol, result);
  }

  result->name = gum_symbol_name_from_darwin (export->name);

  switch (export->flags & GUM_DARWIN_EXPORT_KIND_MASK)
  {
    case GUM_DARWIN_EXPORT_REGULAR:
      if ((export->flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) != 0)
      {
        /* XXX: we ignore resolver and interposing */
        result->address = module->base_address + export->stub;
      }
      else
      {
        result->address = module->base_address + export->offset;
      }
      break;
    case GUM_DARWIN_EXPORT_THREAD_LOCAL:
      result->address = module->base_address + export->offset;
      break;
    case GUM_DARWIN_EXPORT_ABSOLUTE:
      result->address = export->offset;
      break;
    default:
      g_assert_not_reached ();
      break;
  }

  result->type =
      gum_darwin_module_is_address_in_text_section (module, result->address)
      ? GUM_EXPORT_FUNCTION
      : GUM_EXPORT_VARIABLE;

  if (result->type == GUM_EXPORT_FUNCTION &&
      self->ptrauth_support == GUM_PTRAUTH_SUPPORTED)
  {
    result->address = gum_sign_code_address (result->address);
  }

  return TRUE;
}

GumAddress
gum_darwin_module_resolver_find_dynamic_address (GumDarwinModuleResolver * self,
                                                 const gchar * symbol)
{
  if (self->lookup_dynamic_func != NULL)
    return self->lookup_dynamic_func (symbol, self->lookup_dynamic_data);

  return 0;
}

static gboolean
gum_find_sysroot (const GumModuleDetails * details,
                  gpointer user_data)
{
  GumCollectModulesContext * ctx = user_data;

  if (g_str_has_suffix (details->path, "/usr/lib/dyld_sim"))
  {
    ctx->sysroot_length = strlen (details->path) - 17;
    ctx->sysroot = g_strndup (details->path, ctx->sysroot_length);
    return FALSE;
  }

  return TRUE;
}

static gboolean
gum_store_module (const GumModuleDetails * details,
                  gpointer user_data)
{
  GumCollectModulesContext * ctx = user_data;
  GumDarwinModuleResolver * self = ctx->self;
  GumDarwinModule * module;

  module = gum_darwin_module_new_from_memory (details->path, self->task,
      details->range->base_address, GUM_DARWIN_MODULE_FLAGS_NONE, NULL);
  g_hash_table_insert (self->modules, g_strdup (details->name),
      module);
  g_hash_table_insert (self->modules, g_strdup (details->path),
      g_object_ref (module));
  if (ctx->sysroot != NULL && g_str_has_prefix (details->path, ctx->sysroot))
  {
    g_hash_table_insert (self->modules,
        g_strdup (details->path + ctx->sysroot_length), g_object_ref (module));
  }

  ctx->index++;

  return TRUE;
}

#endif
```