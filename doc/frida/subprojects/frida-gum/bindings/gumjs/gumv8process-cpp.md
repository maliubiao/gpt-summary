Response:
Let's break down the thought process for analyzing this C++ code and generating the detailed explanation.

1. **Understand the Goal:** The request asks for an explanation of the `gumv8process.cpp` file's functionality within the Frida context. It specifically calls for connections to reverse engineering, low-level details (binary, Linux/Android kernel), logical reasoning, common user errors, and debugging steps.

2. **Initial Scan and Keyword Spotting:**  Quickly read through the code, paying attention to:
    * **Includes:** `gumv8process.h`, standard library headers (`string.h`), OS-specific headers (`gumdarwin.h`). This gives an immediate clue about dependencies and platform considerations.
    * **Macros:** `GUMJS_MODULE_NAME`, `GUM_SCRIPT_ARCH`, `GUM_SCRIPT_PLATFORM`. These are constants defining key aspects of the module.
    * **Structs:** `GumV8ExceptionHandler`, `GumV8RunOnThreadContext`, `GumV8FindModuleByNameContext`. These are data structures used for internal organization and passing information.
    * **Function Declarations with `GUMJS_DECLARE_*` and `GUMJS_DEFINE_*`:** These are the core functionalities exposed by this module to the JavaScript side of Frida. They are the primary actions the code performs. List these out: `get_main_module`, `get_current_dir`, `get_home_dir`, `get_tmp_dir`, `is_debugger_attached`, `get_current_thread_id`, `enumerate_threads`, `run_on_thread`, `find_module_by_name`, `enumerate_modules`, `enumerate_ranges`, `enumerate_system_ranges`, `enumerate_malloc_ranges`, `set_exception_handler`.
    * **Helper Functions (static):** Functions like `gum_emit_thread`, `gum_v8_run_on_thread_context_free`, `gum_do_call_on_thread`, etc. These implement the logic behind the exposed functions.
    * **`gum_*` prefixes:** These strongly suggest interactions with the underlying `gum` library, which is a core part of Frida's functionality.

3. **Categorize Functionality (Relate to the Request):** Now, go through the list of exposed functions and categorize them based on the request's categories:

    * **Reverse Engineering:**  Functions like `findModuleByName`, `enumerateModules`, `enumerateRanges`, `enumerateSystemRanges`, `enumerateMallocRanges` directly provide information about the target process's memory layout, loaded modules, and memory allocations. This is crucial for reverse engineering. `isDebuggerAttached` is also relevant.
    * **Binary/Low-Level:** The presence of `GUM_SCRIPT_ARCH`, `GUM_SCRIPT_PLATFORM`, `pageSize`, `pointerSize` clearly indicates awareness of the underlying architecture. Functions dealing with memory ranges and thread IDs are also low-level. The `Stalker` functionality is deeply involved in code tracing and manipulation.
    * **Linux/Android Kernel/Framework:** Conditional compilation based on `HAVE_LINUX`, `HAVE_DARWIN`, `HAVE_WINDOWS` indicates platform-specific handling. The `enumerate_system_ranges` function specifically mentions `dyldSharedCache` (macOS). While Android isn't explicitly mentioned in the *code*, the Frida context implies its relevance. Consider how these functions would work differently on different OSes (e.g., process memory maps).
    * **Logical Reasoning:**  Consider the flow of execution within functions like `run_on_thread`. There's a clear sequence of steps: allocating context, calling `gum_stalker_run_on_thread`, potentially starting a garbage collection timer. Think about the *purpose* of each step.
    * **User Errors:**  Think about how a user might misuse the provided API. For example, providing an incorrect module name, trying to run code on an invalid thread ID, or forgetting to handle exceptions.
    * **Debugging Steps:** How does a user end up interacting with this code? They're likely using the Frida JavaScript API, which then calls into this C++ layer. Think about the structure of a typical Frida script.

4. **Deep Dive into Key Functions:** Select a few key functions to analyze in more detail. `enumerateModules`, `enumerateRanges`, and especially `run_on_thread` are good examples.

    * **`enumerateModules`:**  Trace the call flow. The JavaScript call triggers `gumjs_process_enumerate_modules`, which calls `gum_process_enumerate_modules` from the `gum` library. The callback `gum_emit_module` is used to convert the `GumModuleDetails` to a JavaScript object.
    * **`enumerateRanges`:** Similar to `enumerateModules`, but also demonstrates how filtering by page protection (`GumPageProtection`) works.
    * **`run_on_thread`:** This is more complex. Pay attention to the `Stalker`, the `GumV8RunOnThreadContext`, and the `gum_do_call_on_thread` callback. Understand the purpose of the `ScriptUnlocker` and `ScriptScope`. The garbage collection timer mechanism is also interesting.

5. **Illustrate with Examples:**  For each category, provide concrete examples based on the code. This makes the explanation much clearer. For instance, show how `findModuleByName` can be used in reverse engineering to locate a specific library. Explain how `run_on_thread` can be used to execute code in the context of another thread, which is a powerful debugging technique.

6. **Address the "Why":** Don't just describe *what* the code does, explain *why* it does it. Why is it necessary to have a garbage collection timer for the stalker? Why is platform-specific code needed?

7. **Structure and Refine:** Organize the explanation logically using headings and bullet points. Ensure clarity and conciseness. Review and refine the language to make it easy to understand for someone familiar with reverse engineering and basic programming concepts. Specifically address each point raised in the original request.

8. **Self-Correction/Refinement During the Process:**
    * **Initial thought:**  "This file just exposes process information."  **Correction:** "It does more than that; it allows execution on other threads and setting exception handlers."
    * **Initial thought:** "The platform-specific code is just boilerplate." **Correction:** "It's important for handling OS differences in memory management and module loading."
    * **Missing connection:** Initially might forget to explicitly link `run_on_thread` to dynamic instrumentation. **Correction:**  Emphasize how this allows modifying program behavior at runtime.

By following this structured approach, combining code analysis with an understanding of the request's specific requirements, and continually refining the explanation, we can arrive at a comprehensive and accurate description of the `gumv8process.cpp` file.
This C++ source file, `gumv8process.cpp`, is a crucial part of Frida's dynamic instrumentation capabilities. It provides the JavaScript binding for interacting with the target process. Essentially, it allows JavaScript code running within Frida to inspect and manipulate aspects of the process being instrumented.

Here's a breakdown of its functionality, categorized as requested:

**1. Core Functionality (Listing):**

* **Process Information Retrieval:**
    * **`get_main_module`:** Retrieves information about the main executable module of the process.
    * **`get_current_dir`:**  Gets the current working directory of the process.
    * **`get_home_dir`:** Gets the home directory of the user running the process.
    * **`get_tmp_dir`:** Gets the temporary directory of the system.
    * **`is_debugger_attached`:** Checks if a debugger is currently attached to the process.
    * **`get_current_thread_id`:** Gets the ID of the currently executing thread within the Frida script.
    * **Constants:**  Exposes process-related constants like `id` (process ID), `arch` (architecture - "ia32", "x64", "arm", "arm64", "mips"), `platform` ("linux", "darwin", "windows", "freebsd", "qnx"), `pageSize`, `pointerSize`, and `codeSigningPolicy`.

* **Process Introspection:**
    * **`enumerate_threads`:**  Allows iterating through all the threads currently running in the target process.
    * **`find_module_by_name`:** Finds a specific module (like a shared library or the main executable) by its name.
    * **`enumerate_modules`:** Allows iterating through all the loaded modules in the target process.
    * **`enumerate_ranges`:**  Allows iterating through memory regions within the process, filtering by memory protection (e.g., readable, writable, executable).
    * **`enumerate_system_ranges`:** Provides information about specific system memory regions, like the dyld shared cache on macOS.
    * **`enumerate_malloc_ranges`:** (Platform-dependent) Enumerates memory ranges allocated by `malloc` (or similar allocators).

* **Process Manipulation:**
    * **`run_on_thread`:** Executes a provided JavaScript function in the context of a specific thread within the target process. This is a powerful feature for targeting specific thread activities.
    * **`set_exception_handler`:** Allows setting a JavaScript function as a global exception handler for the target process. If an exception occurs in the target process, this JavaScript function will be called.

**2. Relationship to Reverse Engineering (with Examples):**

This file is fundamental to many reverse engineering tasks performed with Frida:

* **Identifying Key Libraries:**  Using `find_module_by_name("libssl.so")` or `enumerate_modules` to find cryptographic libraries, anti-tampering mechanisms, or other libraries of interest. Knowing the base address of these modules is crucial for setting hooks.
* **Analyzing Memory Layout:**  `enumerate_ranges` can be used to understand the memory organization of the process. For instance, identifying regions with `rwx` (read, write, execute) permissions could indicate dynamically generated code or unpacking routines.
* **Understanding Threading Models:** `enumerate_threads` helps identify different threads and their activities. Combining this with `run_on_thread` allows targeting specific thread behaviors for analysis or modification.
* **Examining Dynamic Allocation:** `enumerate_malloc_ranges` (where available) helps in understanding how the process manages memory and can be useful for identifying memory leaks or vulnerabilities.
* **Circumventing Anti-Debugging:** While not a direct feature, knowing if a debugger is attached (`is_debugger_attached`) can help in developing scripts that behave differently when being actively debugged, potentially making it harder for anti-debugging techniques to detect Frida.
* **Exception Handling Analysis:** `set_exception_handler` allows observing and potentially modifying the behavior of the process when exceptions occur, which can be valuable for understanding error handling or even exploiting vulnerabilities related to exceptions.

**3. Binary Underlying, Linux/Android Kernel & Framework Knowledge (with Examples):**

This file directly interacts with low-level operating system concepts:

* **Process ID (PID):** The `id` property reflects the OS-level process identifier.
* **Memory Management:**  Functions like `enumerate_ranges` and `enumerate_malloc_ranges` directly query the operating system's memory management structures to retrieve information about memory regions and their attributes (permissions, mappings to files, etc.). This involves understanding concepts like virtual memory, memory pages, and memory protection flags.
    * **Linux:**  On Linux, `enumerate_ranges` might involve reading the `/proc/[pid]/maps` file, which provides information about the process's memory mappings.
    * **Android:**  Similar to Linux, it interacts with the Android kernel's memory management.
* **Modules/Shared Libraries:**  The concepts of modules and shared libraries are fundamental to operating systems. The functions dealing with modules interact with the OS loader and dynamic linker to retrieve information about loaded libraries and their addresses.
    * **Linux:** This involves understanding ELF (Executable and Linkable Format) files and how the dynamic linker (`ld.so`) works.
    * **Android:**  This involves understanding the Android linker and the structure of APKs and shared libraries (`.so` files).
* **Threads:**  The thread enumeration and execution functions interact directly with the operating system's threading mechanisms.
    * **Linux/Android:**  This involves POSIX threads (pthreads) and the kernel's thread scheduling.
* **System Calls:**  While not explicitly visible in this code, the underlying `gum` library that this code relies on makes system calls to interact with the kernel and retrieve process information (e.g., `getpid()`, `ptrace()`, memory mapping system calls).
* **File System Interaction:**  `get_current_dir`, `get_home_dir`, and `get_tmp_dir` rely on operating system functions to retrieve file system paths.
* **Code Signing:** The `codeSigningPolicy` reflects the operating system's code signing enforcement, which is a security feature.

**4. Logical Reasoning (with Assumptions and Outputs):**

Let's take the `find_module_by_name` function as an example:

* **Assumption (Input):** A Frida script calls `Process.findModuleByName("libc.so")`.
* **Logical Steps:**
    1. The `gumjs_process_find_module_by_name` function is invoked with the module name "libc.so".
    2. It prepares a context (`GumV8FindModuleByNameContext`) to store the search name.
    3. It calls `gum_process_enumerate_modules`, which iterates through all loaded modules in the target process.
    4. For each module, the `gum_store_module_if_name_matches` function is called.
    5. `gum_store_module_if_name_matches` compares the current module's name (or path if the provided name is absolute) with "libc.so". On Windows, it performs case-insensitive comparison.
    6. If a match is found, it creates a JavaScript object representing the module and stores it in the context. The iteration is stopped.
* **Output:**
    * **Success:** If "libc.so" is loaded, the function returns a JavaScript object containing information about the `libc.so` module (base address, size, path).
    * **Failure:** If "libc.so" is not found, the function returns `null`.

**5. User or Programming Common Usage Errors (with Examples):**

* **Incorrect Module Name:**  Calling `Process.findModuleByName("nonexistent_module.so")` will result in the function returning `null`. Users might not check for `null` and try to access properties of a non-existent module, leading to errors in their Frida script.
* **Invalid Thread ID in `run_on_thread`:**  Providing a thread ID that doesn't exist or has already terminated will cause `gum_stalker_run_on_thread` to fail, and the JavaScript function will throw an error ("failed to run on thread"). Users need to ensure they are targeting valid thread IDs obtained from `enumerate_threads`.
* **Incorrect Memory Protection Flags in `enumerate_ranges`:**  Using an incorrect `GumPageProtection` value might not yield the expected memory regions. For example, searching only for executable memory (`'x'`) might miss regions that are readable and executable (`'rx'`).
* **Forgetting to Handle Exceptions:** If a user sets an exception handler with `set_exception_handler`, but the handler function itself throws an error, it might disrupt Frida's operation or lead to unexpected behavior. Robust error handling within the exception handler is crucial.
* **Performance Issues with Broad Enumerations:**  Enumerating all modules or memory ranges can be computationally expensive, especially in large processes. Users should be mindful of the performance impact and try to filter or target their queries as much as possible.

**6. User Operation Steps to Reach Here (Debugging Clues):**

The user interacts with this C++ code primarily through Frida's JavaScript API. Here's a typical sequence:

1. **User Writes a Frida Script:** The user creates a JavaScript file (e.g., `my_script.js`) that utilizes the `Process` object. For example:
   ```javascript
   console.log("Process ID:", Process.id);
   var libc = Process.findModuleByName("libc.so");
   if (libc) {
       console.log("libc base address:", libc.base);
   } else {
       console.log("libc not found.");
   }

   Process.enumerateModules({
       onMatch: function(module) {
           console.log("Module:", module.name, "at", module.base);
       },
       onComplete: function() {
           console.log("Module enumeration complete.");
       }
   });
   ```

2. **User Executes Frida:** The user runs Frida, targeting a specific process:
   ```bash
   frida -l my_script.js com.example.targetapp
   ```
   or
   ```bash
   frida -p <process_id> -l my_script.js
   ```

3. **Frida Injects into the Target Process:** Frida injects its agent (which includes the JavaScript engine and the native component with this C++ code) into the target process.

4. **JavaScript Execution and Bridge to C++:** When the JavaScript code in `my_script.js` calls methods of the `Process` object (like `Process.findModuleByName` or `Process.enumerateModules`), these calls are bridged to the corresponding C++ functions in `gumv8process.cpp`. This bridging is handled by Frida's internal mechanisms, which involve V8's (the JavaScript engine) native function integration.

5. **C++ Code Execution:** The C++ functions in `gumv8process.cpp` then interact with the underlying operating system (through the `gum` library) to retrieve the requested information or perform the requested actions on the target process.

**Debugging Clues:**

* **Frida Script Errors:** If the user's JavaScript script has errors related to accessing `Process` properties or calling its methods incorrectly, the V8 engine will throw JavaScript exceptions. These exceptions will often point to the line of code where the error occurred, providing a starting point for debugging.
* **Frida Console Output:** The `console.log` statements in the JavaScript script will print information to the Frida console, which can help trace the execution flow and the values of variables.
* **Frida's `-d` (debug) flag:** Running Frida with the `-d` flag provides more verbose output, including information about module loading and other internal Frida activities, which can be useful for diagnosing issues related to Frida's interaction with the target process.
* **Examining Frida's Source Code:** For advanced debugging, understanding the Frida agent's architecture and how the JavaScript-to-native bridge works is essential. Examining Frida's source code (including this `gumv8process.cpp` file) can provide deeper insights into the underlying mechanisms.

In summary, `gumv8process.cpp` is a foundational component of Frida, acting as the bridge between JavaScript and the target process's internals. It provides a rich set of functionalities for introspection and manipulation, making it a powerful tool for dynamic analysis, reverse engineering, and security research.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8process.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020-2023 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2023 Grant Douglas <me@hexplo.it>
 * Copyright (C) 2024 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8process.h"

#include "gumv8macros.h"
#include "gumv8matchcontext.h"
#include "gumv8scope.h"

#include <string.h>
#ifdef HAVE_DARWIN
# include <gum/gumdarwin.h>
#endif

#define GUMJS_MODULE_NAME Process

#if defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
#  define GUM_SCRIPT_ARCH "ia32"
# else
#  define GUM_SCRIPT_ARCH "x64"
# endif
#elif defined (HAVE_ARM)
# define GUM_SCRIPT_ARCH "arm"
#elif defined (HAVE_ARM64)
# define GUM_SCRIPT_ARCH "arm64"
#elif defined (HAVE_MIPS)
# define GUM_SCRIPT_ARCH "mips"
#endif

#if defined (HAVE_LINUX)
# define GUM_SCRIPT_PLATFORM "linux"
#elif defined (HAVE_DARWIN)
# define GUM_SCRIPT_PLATFORM "darwin"
#elif defined (HAVE_WINDOWS)
# define GUM_SCRIPT_PLATFORM "windows"
#elif defined (HAVE_FREEBSD)
# define GUM_SCRIPT_PLATFORM "freebsd"
#elif defined (HAVE_QNX)
# define GUM_SCRIPT_PLATFORM "qnx"
#endif

using namespace v8;

struct GumV8ExceptionHandler
{
  Global<Function> * callback;

  GumV8Core * core;
};

struct GumV8RunOnThreadContext
{
  Global<Function> * user_func;

  GumV8Core * core;
};

struct GumV8FindModuleByNameContext
{
  gchar * name;
  gboolean name_is_canonical;

  Local<Object> module;

  GumV8Process * parent;
};

GUMJS_DECLARE_GETTER (gumjs_process_get_main_module)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_dir)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_home_dir)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_tmp_dir)
GUMJS_DECLARE_FUNCTION (gumjs_process_is_debugger_attached)
GUMJS_DECLARE_FUNCTION (gumjs_process_get_current_thread_id)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_threads)
static gboolean gum_emit_thread (const GumThreadDetails * details,
    GumV8MatchContext<GumV8Process> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_run_on_thread)
static void gum_v8_run_on_thread_context_free (GumV8RunOnThreadContext * rc);
static void gum_do_call_on_thread (const GumCpuContext * cpu_context,
    gpointer user_data);
static void gum_v8_process_maybe_start_stalker_gc_timer (GumV8Process * self);
static gboolean gum_v8_process_on_stalker_gc_timer_tick (GumV8Process * self);
GUMJS_DECLARE_FUNCTION (gumjs_process_find_module_by_name)
static gboolean gum_store_module_if_name_matches (
    const GumModuleDetails * details, GumV8FindModuleByNameContext * fc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_modules)
static gboolean gum_emit_module (const GumModuleDetails * details,
    GumV8MatchContext<GumV8Process> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_ranges)
static gboolean gum_emit_range (const GumRangeDetails * details,
    GumV8MatchContext<GumV8Process> * mc);
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_system_ranges)
GUMJS_DECLARE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
GUMJS_DECLARE_FUNCTION (gumjs_process_set_exception_handler)

static GumV8ExceptionHandler * gum_v8_exception_handler_new (
    Local<Function> callback, GumV8Core * core);
static void gum_v8_exception_handler_free (
    GumV8ExceptionHandler * handler);
static gboolean gum_v8_exception_handler_on_exception (
    GumExceptionDetails * details, GumV8ExceptionHandler * handler);

const gchar * gum_v8_script_exception_type_to_string (GumExceptionType type);

static const GumV8Property gumjs_process_values[] =
{
  { "mainModule", gumjs_process_get_main_module, NULL },

  { NULL, NULL }
};

static const GumV8Function gumjs_process_functions[] =
{
  { "getCurrentDir", gumjs_process_get_current_dir },
  { "getHomeDir", gumjs_process_get_home_dir },
  { "getTmpDir", gumjs_process_get_tmp_dir },
  { "isDebuggerAttached", gumjs_process_is_debugger_attached },
  { "getCurrentThreadId", gumjs_process_get_current_thread_id },
  { "_enumerateThreads", gumjs_process_enumerate_threads },
  { "_runOnThread", gumjs_process_run_on_thread },
  { "findModuleByName", gumjs_process_find_module_by_name },
  { "_enumerateModules", gumjs_process_enumerate_modules },
  { "_enumerateRanges", gumjs_process_enumerate_ranges },
  { "enumerateSystemRanges", gumjs_process_enumerate_system_ranges },
  { "_enumerateMallocRanges", gumjs_process_enumerate_malloc_ranges },
  { "setExceptionHandler", gumjs_process_set_exception_handler },
  { NULL, NULL }
};

void
_gum_v8_process_init (GumV8Process * self,
                      GumV8Module * module,
                      GumV8Thread * thread,
                      GumV8Core * core,
                      Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->module = module;
  self->thread = thread;
  self->core = core;

  self->stalker = NULL;

  auto process_module = External::New (isolate, self);

  auto process = _gum_v8_create_module ("Process", scope, isolate);
  process->Set (_gum_v8_string_new_ascii (isolate, "id"),
      Number::New (isolate, gum_process_get_id ()), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "arch"),
      String::NewFromUtf8Literal (isolate, GUM_SCRIPT_ARCH), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "platform"),
      String::NewFromUtf8Literal (isolate, GUM_SCRIPT_PLATFORM), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "pageSize"),
      Number::New (isolate, gum_query_page_size ()), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "pointerSize"),
      Number::New (isolate, GLIB_SIZEOF_VOID_P), ReadOnly);
  process->Set (_gum_v8_string_new_ascii (isolate, "codeSigningPolicy"),
      String::NewFromUtf8 (isolate, gum_code_signing_policy_to_string (
      gum_process_get_code_signing_policy ())).ToLocalChecked (), ReadOnly);
  _gum_v8_module_add (process_module, process, gumjs_process_values, isolate);
  _gum_v8_module_add (process_module, process,
      gumjs_process_functions, isolate);
}

void
_gum_v8_process_realize (GumV8Process * self)
{
}

void
_gum_v8_process_flush (GumV8Process * self)
{
  g_clear_pointer (&self->exception_handler, gum_v8_exception_handler_free);

  delete self->main_module_value;
  self->main_module_value = nullptr;
}

void
_gum_v8_process_dispose (GumV8Process * self)
{
  g_assert (self->stalker_gc_timer == NULL);

  g_clear_pointer (&self->exception_handler, gum_v8_exception_handler_free);

  delete self->main_module_value;
  self->main_module_value = nullptr;
}

void
_gum_v8_process_finalize (GumV8Process * self)
{
  g_clear_object (&self->stalker);
}

GUMJS_DEFINE_GETTER (gumjs_process_get_main_module)
{
  auto self = module;

  if (self->main_module_value == nullptr)
  {
    self->main_module_value = new Global<Object> (isolate,
        _gum_v8_module_value_new (gum_process_get_main_module (),
          self->module));
  }

  info.GetReturnValue ().Set (
      Local<Object>::New (isolate, *module->main_module_value));
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_dir)
{
  gchar * dir_opsys = g_get_current_dir ();
  gchar * dir_utf8 = g_filename_display_name (dir_opsys);
  info.GetReturnValue ().Set (
      String::NewFromUtf8 (isolate, dir_utf8).ToLocalChecked ());
  g_free (dir_utf8);
  g_free (dir_opsys);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_home_dir)
{
  gchar * dir = g_filename_display_name (g_get_home_dir ());
  info.GetReturnValue ().Set (
      String::NewFromUtf8 (isolate, dir).ToLocalChecked ());
  g_free (dir);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_tmp_dir)
{
  gchar * dir = g_filename_display_name (g_get_tmp_dir ());
  info.GetReturnValue ().Set (
      String::NewFromUtf8 (isolate, dir).ToLocalChecked ());
  g_free (dir);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_is_debugger_attached)
{
  info.GetReturnValue ().Set (!!gum_process_is_debugger_attached ());
}

GUMJS_DEFINE_FUNCTION (gumjs_process_get_current_thread_id)
{
  info.GetReturnValue ().Set ((uint32_t) gum_process_get_current_thread_id ());
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_threads)
{
  GumV8MatchContext<GumV8Process> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return;

  gum_process_enumerate_threads ((GumFoundThreadFunc) gum_emit_thread, &mc);

  mc.OnComplete ();
}

static gboolean
gum_emit_thread (const GumThreadDetails * details,
                 GumV8MatchContext<GumV8Process> * mc)
{
  return mc->OnMatch (_gum_v8_thread_new (details, mc->parent->thread));
}

GUMJS_DEFINE_FUNCTION (gumjs_process_run_on_thread)
{
  GumThreadId thread_id;
  Local<Function> user_func;
  if (!_gum_v8_args_parse (args, "ZF", &thread_id, &user_func))
    return;

  if (module->stalker == NULL)
    module->stalker = gum_stalker_new ();

  auto rc = g_slice_new (GumV8RunOnThreadContext);
  rc->user_func = new Global<Function> (isolate, user_func);
  rc->core = core;

  gboolean success;
  {
    ScriptUnlocker unlocker (core);

    success = gum_stalker_run_on_thread (module->stalker, thread_id,
        gum_do_call_on_thread, rc,
        (GDestroyNotify) gum_v8_run_on_thread_context_free);
  }

  gum_v8_process_maybe_start_stalker_gc_timer (module);

  if (!success)
    _gum_v8_throw_ascii_literal (isolate, "failed to run on thread");

  return;
}

static void
gum_v8_run_on_thread_context_free (GumV8RunOnThreadContext * rc)
{
  ScriptScope scope (rc->core->script);
  delete rc->user_func;

  g_slice_free (GumV8RunOnThreadContext, rc);
}

static void
gum_do_call_on_thread (const GumCpuContext * cpu_context,
                       gpointer user_data)
{
  auto rc = (GumV8RunOnThreadContext *) user_data;
  auto core = rc->core;

  ScriptScope scope (core->script);
  auto isolate = core->isolate;

  auto user_func = Local<Function>::New (isolate, *rc->user_func);
  auto result = user_func->Call (isolate->GetCurrentContext (),
      Undefined (isolate), 0, nullptr);
  _gum_v8_ignore_result (result);
}

static void
gum_v8_process_maybe_start_stalker_gc_timer (GumV8Process * self)
{
  GumV8Core * core = self->core;

  if (self->stalker_gc_timer != NULL)
    return;

  if (!gum_stalker_garbage_collect (self->stalker))
    return;

  auto source = g_timeout_source_new (10);
  g_source_set_callback (source,
      (GSourceFunc) gum_v8_process_on_stalker_gc_timer_tick, self, NULL);
  self->stalker_gc_timer = source;

  _gum_v8_core_pin (core);

  {
    ScriptUnlocker unlocker (core);

    g_source_attach (source,
        gum_script_scheduler_get_js_context (core->scheduler));
    g_source_unref (source);
  }
}

static gboolean
gum_v8_process_on_stalker_gc_timer_tick (GumV8Process * self)
{
  gboolean pending_garbage;

  pending_garbage = gum_stalker_garbage_collect (self->stalker);
  if (!pending_garbage)
  {
    GumV8Core * core = self->core;

    ScriptScope scope (core->script);

    _gum_v8_core_unpin (core);
    self->stalker_gc_timer = NULL;
  }

  return pending_garbage ? G_SOURCE_CONTINUE : G_SOURCE_REMOVE;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_find_module_by_name)
{
  GumV8FindModuleByNameContext fc;
  if (!_gum_v8_args_parse (args, "s", &fc.name))
    return;
  fc.name_is_canonical = g_path_is_absolute (fc.name);
  fc.parent = module;

#ifdef HAVE_WINDOWS
  gchar * folded_name = g_utf8_casefold (fc.name, -1);
  g_free (fc.name);
  fc.name = folded_name;
#endif

  gum_process_enumerate_modules (
      (GumFoundModuleFunc) gum_store_module_if_name_matches, &fc);

  if (!fc.module.IsEmpty ())
    info.GetReturnValue ().Set (fc.module);
  else
    info.GetReturnValue ().SetNull ();

  g_free (fc.name);
}

static gboolean
gum_store_module_if_name_matches (const GumModuleDetails * details,
                                  GumV8FindModuleByNameContext * fc)
{
  gboolean proceed = TRUE;

  const gchar * key = fc->name_is_canonical ? details->path : details->name;
  gchar * allocated_key = NULL;

#ifdef HAVE_WINDOWS
  allocated_key = g_utf8_casefold (key, -1);
  key = allocated_key;
#endif

  if (strcmp (key, fc->name) == 0)
  {
    fc->module = _gum_v8_module_value_new (details, fc->parent->module);

    proceed = FALSE;
  }

  g_free (allocated_key);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_modules)
{
  GumV8MatchContext<GumV8Process> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return;

  gum_process_enumerate_modules ((GumFoundModuleFunc) gum_emit_module, &mc);

  mc.OnComplete ();
}

static gboolean
gum_emit_module (const GumModuleDetails * details,
                 GumV8MatchContext<GumV8Process> * mc)
{
  auto module = _gum_v8_module_value_new (details, mc->parent->module);

  return mc->OnMatch (module);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_ranges)
{
  GumPageProtection prot;
  GumV8MatchContext<GumV8Process> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "mF{onMatch,onComplete}", &prot, &mc.on_match,
      &mc.on_complete))
    return;

  gum_process_enumerate_ranges (prot, (GumFoundRangeFunc) gum_emit_range, &mc);

  mc.OnComplete ();
}

static gboolean
gum_emit_range (const GumRangeDetails * details,
                GumV8MatchContext<GumV8Process> * mc)
{
  auto core = mc->parent->core;
  auto isolate = core->isolate;

  auto range = Object::New (isolate);
  _gum_v8_object_set_pointer (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);
  _gum_v8_object_set_page_protection (range, "protection", details->protection,
      core);

  auto f = details->file;
  if (f != NULL)
  {
    auto file = Object::New (isolate);
    _gum_v8_object_set_utf8 (file, "path", f->path, core);
    _gum_v8_object_set_uint (file, "offset", f->offset, core);
    _gum_v8_object_set_uint (file, "size", f->size, core);
    _gum_v8_object_set (range, "file", file, core);
  }

  return mc->OnMatch (range);
}

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_system_ranges)
{
  auto ranges = Object::New (isolate);

#ifdef HAVE_DARWIN
  {
    GumMemoryRange dsc;

    if (gum_darwin_query_shared_cache_range (mach_task_self (), &dsc))
    {
      auto range = Object::New (isolate);
      _gum_v8_object_set_pointer (range, "base", dsc.base_address, core);
      _gum_v8_object_set_uint (range, "size", dsc.size, core);
      _gum_v8_object_set (ranges, "dyldSharedCache", range, core);
    }
  }
#endif

  info.GetReturnValue ().Set (ranges);
}

#if defined (HAVE_WINDOWS) || defined (HAVE_DARWIN)

static gboolean gum_emit_malloc_range (const GumMallocRangeDetails * details,
    GumV8MatchContext<GumV8Process> * mc);

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  GumV8MatchContext<GumV8Process> mc (isolate, module);
  if (!_gum_v8_args_parse (args, "F{onMatch,onComplete}", &mc.on_match,
      &mc.on_complete))
    return;

  gum_process_enumerate_malloc_ranges (
      (GumFoundMallocRangeFunc) gum_emit_malloc_range, &mc);

  mc.OnComplete ();
}

static gboolean
gum_emit_malloc_range (const GumMallocRangeDetails * details,
                       GumV8MatchContext<GumV8Process> * mc)
{
  auto core = mc->parent->core;

  auto range = Object::New (mc->isolate);
  _gum_v8_object_set_pointer (range, "base", details->range->base_address,
      core);
  _gum_v8_object_set_uint (range, "size", details->range->size, core);

  return mc->OnMatch (range);
}

#else

GUMJS_DEFINE_FUNCTION (gumjs_process_enumerate_malloc_ranges)
{
  _gum_v8_throw_ascii_literal (isolate,
      "not yet implemented for " GUM_SCRIPT_PLATFORM);
}

#endif

GUMJS_DEFINE_FUNCTION (gumjs_process_set_exception_handler)
{
  Local<Function> callback;
  if (!_gum_v8_args_parse (args, "F?", &callback))
    return;

  auto new_handler = !callback.IsEmpty ()
      ? gum_v8_exception_handler_new (callback, core)
      : NULL;

  auto old_handler = module->exception_handler;
  module->exception_handler = new_handler;

  if (old_handler != NULL)
    gum_v8_exception_handler_free (old_handler);
}

static GumV8ExceptionHandler *
gum_v8_exception_handler_new (Local<Function> callback,
                              GumV8Core * core)
{
  auto handler = g_slice_new (GumV8ExceptionHandler);
  handler->callback = new Global<Function> (core->isolate, callback);
  handler->core = core;

  gum_exceptor_add (core->exceptor,
      (GumExceptionHandler) gum_v8_exception_handler_on_exception, handler);

  return handler;
}

static void
gum_v8_exception_handler_free (GumV8ExceptionHandler * handler)
{
  gum_exceptor_remove (handler->core->exceptor,
      (GumExceptionHandler) gum_v8_exception_handler_on_exception, handler);

  delete handler->callback;

  g_slice_free (GumV8ExceptionHandler, handler);
}

static gboolean
gum_v8_exception_handler_on_exception (GumExceptionDetails * details,
                                       GumV8ExceptionHandler * handler)
{
  auto core = handler->core;

  if (gum_v8_script_backend_is_scope_mutex_trapped (core->backend))
    return FALSE;

  ScriptScope scope (core->script);
  auto isolate = core->isolate;

  auto callback = Local<Function>::New (isolate, *handler->callback);

  Local<Object> ex, context;
  _gum_v8_parse_exception_details (details, ex, context, core);

  gboolean handled = FALSE;
  Local<Value> argv[] = { ex };
  Local<Value> result;
  if (callback->Call (isolate->GetCurrentContext (), Undefined (isolate),
      G_N_ELEMENTS (argv), argv).ToLocal (&result))
  {
    if (result->IsBoolean ())
      handled = result.As<Boolean> ()->Value ();
  }

  _gum_v8_cpu_context_free_later (new Global<Object> (isolate, context), core);

  return handled;
}

"""

```