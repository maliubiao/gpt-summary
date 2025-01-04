Response:
Let's break down the thought process for analyzing this C code and fulfilling the request.

**1. Initial Understanding of the Request:**

The core request is to analyze a specific C source file (`gumprocess-qnx.c`) for the Frida dynamic instrumentation tool. The key areas to focus on are:

* **Functionality:** What does this code *do*?
* **Relevance to Reverse Engineering:** How can these functions be used in reverse engineering scenarios?
* **Low-Level Details:** Connections to binary formats, Linux/Android kernels, and frameworks (though this is QNX-specific).
* **Logical Reasoning:** Any decisions or transformations within the code that can be demonstrated with examples.
* **Common User Errors:**  Mistakes programmers or users might make when interacting with the functionality (directly or indirectly).
* **Debugging Context:** How a user might end up at this specific code location during a debugging session.

**2. High-Level Overview of the Code:**

The filename and initial includes (`gumprocess-priv.h`, `backend-elf/gumprocess-elf.h`, `gum/gumqnx.h`, etc.) strongly suggest this code is responsible for process-related operations *specifically on the QNX operating system*. The "gum" prefix indicates it's part of the Frida "gum" library, which deals with in-process code manipulation.

**3. Dissecting Functionality (Iterative Process):**

I'd go through the code function by function, reading the documentation comments and the code itself. Here's a possible internal thought process for a few key functions:

* **`gum_process_query_libc_name`:**  This clearly aims to find the name of the libc library. It uses `dlsym(RTLD_NEXT, "exit")` which is a common technique to get a handle to libc. This is fundamental for interacting with standard library functions.

* **`gum_process_is_debugger_attached`:** The use of `/proc/self` and `DCMD_PROC_TIDSTATUS` is a strong indicator of checking for a debugger. This is a classic anti-debugging technique (though Frida itself is a debugger, it's checking from the *target* process's perspective).

* **`gum_process_get_id` and `gum_process_get_current_thread_id`:** These are straightforward system calls for getting process and thread IDs. Essential for process introspection.

* **`gum_process_modify_thread`:** This looks complex. The use of `ThreadCtl` to hold and continue threads, along with `vfork()` to create a child process to modify registers, suggests a way to manipulate the state of a thread without directly doing it in the current process's memory. This has clear reverse engineering implications – modifying execution flow.

* **`_gum_process_enumerate_threads`:** Iterating through `/proc/self/as` and using `DCMD_PROC_TIDSTATUS` to get thread information is a standard way to enumerate threads. Crucial for understanding multi-threaded applications.

* **`_gum_process_enumerate_modules`:**  The use of `dlopen(NULL, RTLD_NOW)` and iterating through the linked list of loaded modules is the standard QNX way to find loaded libraries.

* **`gum_qnx_enumerate_ranges` and `_gum_process_enumerate_ranges`:**  These functions use `/proc/<pid>/as` and `DCMD_PROC_PAGEDATA`/`DCMD_PROC_MAPDEBUG` to get memory map information. This is fundamental for understanding the memory layout of a process.

* **`gum_thread_suspend` and `gum_thread_resume`:**  Direct use of `ThreadCtl` to control thread execution. Basic debugging primitives.

* **`gum_module_load` and `gum_module_ensure_initialized`:** Functions to load dynamic libraries. Essential for instrumentation.

* **`gum_module_find_export_by_name`:** Using `dlopen` and `dlsym` to find function addresses within modules. This is a core functionality for hooking and intercepting function calls.

* **`gum_qnx_cpu_type_from_file` and `gum_qnx_cpu_type_from_pid`:** These functions parse ELF headers or `/proc/<pid>/auxv` to determine the target architecture. Important for architecture-aware instrumentation.

* **`gum_qnx_query_program_path_for_self`:** Gets the executable path of the current process.

* **`_gum_process_resolve_module_name`:** Tries to find the full path of a module by name.

* **`gum_cpu_context_from_qnx` and `gum_cpu_context_to_qnx`:** These functions translate between the QNX-specific `debug_greg_t` structure and Frida's generic `GumCpuContext`. This is crucial for architecture abstraction.

* **`gum_qnx_parse_ucontext` and `gum_qnx_unparse_ucontext`:** Similar to the above, but dealing with `ucontext_t`, which is used for signal handling and context switching.

**4. Connecting to Reverse Engineering:**

Once I understood the functionality, I started thinking about how these functions are relevant to reverse engineering:

* **Inspection:** Functions like `enumerate_modules`, `enumerate_ranges`, `get_id`, `has_thread` provide information about the target process, crucial for understanding its structure and state.
* **Manipulation:** `modify_thread`, `suspend`, `resume`, `set/unset_hardware_breakpoint/watchpoint` allow for direct control and modification of the target process's execution.
* **Code Injection/Hooking:** `module_load`, `find_export_by_name` are essential for injecting code or intercepting function calls in the target process.

**5. Identifying Low-Level Details:**

This involved looking for interactions with:

* **Operating System APIs:**  The heavy use of `devctl`, `ThreadCtl`, `/proc`, `dlopen`, `dlsym` are clear indicators of direct OS interaction.
* **Binary Formats:** Parsing ELF headers in `gum_qnx_cpu_type_from_file`.
* **Kernel Concepts:**  Understanding process and thread management, memory maps, and the role of `/proc`.

**6. Logical Reasoning, Assumptions, and Outputs:**

For functions with logic, I considered:

* **Inputs:** What kind of data does the function expect?
* **Processing:** What transformations or decisions are made?
* **Outputs:** What does the function return or modify?

For example, in `gum_process_modify_thread`, the assumption is that holding the thread allows for safe modification in a child process. The input is a thread ID, a function to apply, and user data. The output is a boolean indicating success.

**7. Common User Errors:**

This required thinking about how someone using Frida (or the underlying gum library) might misuse these functions:

* **Incorrect Module Names:** Passing the wrong name to `module_load` or `find_export_by_name`.
* **Invalid Addresses:** Trying to set breakpoints or watchpoints at invalid memory locations.
* **Incorrect Permissions:** Issues when trying to access `/proc` if the Frida agent doesn't have sufficient privileges.
* **Race Conditions:** Potential issues when multiple threads are trying to modify the same target process state.

**8. Debugging Context:**

I imagined a scenario where a developer is using Frida and encounters an issue:

* They might be trying to hook a function and it's not working. Stepping through Frida's code, they might end up in `gum_module_find_export_by_name` to see why the symbol isn't being found.
* They might be investigating a crash and want to examine the memory map of the target process. This would lead them to functions like `_gum_process_enumerate_ranges`.
* They might be trying to set a breakpoint and it's not being hit, leading them to investigate `gum_thread_set_hardware_breakpoint` (and realize it's not supported on QNX).

**Self-Correction/Refinement during the Process:**

* **Initial Overgeneralization:**  I might initially think of Linux kernel concepts and then realize the code is QNX-specific and adjust my explanations accordingly.
* **Focusing on Key Functions:** I wouldn't spend too much time on very simple getter functions and prioritize the more complex and interesting ones.
* **Providing Concrete Examples:**  Instead of just saying "it can modify memory," giving an example of modifying a return value makes the explanation clearer.
* **Iterative Review:**  After drafting the initial analysis, I'd reread the code and my explanations to ensure accuracy and completeness. I'd also double-check that I addressed all parts of the prompt.

By following this structured, iterative process, I can systematically analyze the C code and generate a comprehensive response that addresses all aspects of the request.
This C source file, `gumprocess-qnx.c`, is a crucial part of the Frida dynamic instrumentation toolkit, specifically tailored for the QNX operating system. It provides the low-level mechanisms for Frida to interact with and manipulate processes running on QNX. Here's a breakdown of its functionalities:

**Core Functionalities:**

* **Process Information Retrieval:**
    * **`gum_process_get_id()`:** Returns the process ID of the currently running process.
    * **`gum_process_get_current_thread_id()`:** Returns the ID of the current thread.
    * **`gum_process_has_thread(GumThreadId thread_id)`:** Checks if a thread with the given ID exists in the process.
    * **`_gum_process_enumerate_threads(GumFoundThreadFunc func, gpointer user_data)`:** Iterates through all threads within the process, calling the provided `func` for each thread. This allows Frida to get information about each thread.
    * **`_gum_process_enumerate_modules(GumFoundModuleFunc func, gpointer user_data)`:**  Enumerates all loaded modules (executables and shared libraries) within the process. It retrieves information like module base address, size, and path.
    * **`_gum_process_collect_main_module()`:** A specific function used within the module enumeration to find and store details of the main executable.
    * **`gum_qnx_enumerate_ranges(pid_t pid, GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data)` and `_gum_process_enumerate_ranges(GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data)`:**  Enumerate memory ranges (segments) within a process (either a specific PID or the current process). It allows filtering by memory protection attributes (read, write, execute).
    * **`gum_qnx_query_program_path_for_self(GError ** error)`:** Retrieves the absolute path of the currently running executable.

* **Thread Manipulation:**
    * **`gum_process_modify_thread(GumThreadId thread_id, GumModifyThreadFunc func, gpointer user_data, GumModifyThreadFlags flags)`:** This is a core function for Frida's instrumentation. It allows modifying the state of a specific thread. It temporarily suspends the target thread, executes the provided `func` (which can modify the thread's CPU context), and then resumes the thread.
    * **`gum_thread_suspend(GumThreadId thread_id, GError ** error)`:** Suspends the execution of a specific thread.
    * **`gum_thread_resume(GumThreadId thread_id, GError ** error)`:** Resumes the execution of a suspended thread.
    * **`gum_thread_set_hardware_breakpoint(GumThreadId thread_id, guint breakpoint_id, GumAddress address, GError ** error)` and `gum_thread_unset_hardware_breakpoint(...)`:** Attempts to set or unset hardware breakpoints on a specific thread at a given address. (Note: The current implementation indicates this is not yet supported on QNX).
    * **`gum_thread_set_hardware_watchpoint(...)` and `gum_thread_unset_hardware_watchpoint(...)`:** Attempts to set or unset hardware watchpoints, monitoring memory access. (Note: Also marked as not supported).

* **Module and Symbol Handling:**
    * **`gum_module_load(const gchar * module_name, GError ** error)`:** Attempts to load a dynamic library into the process using `dlopen`.
    * **`gum_module_ensure_initialized(const gchar * module_name)`:** Checks if a module is loaded and initializes it if necessary.
    * **`gum_module_find_export_by_name(const gchar * module_name, const gchar * symbol_name)`:**  Locates the address of an exported symbol (function or variable) within a specific module or the global scope.

* **CPU Context Management:**
    * **`gum_cpu_context_from_qnx(const debug_greg_t * gregs, GumCpuContext * ctx)`:**  Converts the QNX-specific CPU register structure (`debug_greg_t`) to Frida's generic CPU context structure (`GumCpuContext`).
    * **`gum_cpu_context_to_qnx(const GumCpuContext * ctx, debug_greg_t * gregs)`:**  Performs the reverse conversion, from Frida's CPU context to the QNX structure.
    * **`gum_qnx_parse_ucontext(const ucontext_t * uc, GumCpuContext * ctx)`:** Parses a `ucontext_t` structure (used for signal handling) to extract CPU context information.
    * **`gum_qnx_unparse_ucontext(const GumCpuContext * ctx, ucontext_t * uc)`:**  Sets the CPU context within a `ucontext_t` structure.

* **Operating System Interaction:**
    * **`gum_process_is_debugger_attached()`:** Checks if a debugger is currently attached to the process. It does this by querying the process status using `devctl`.
    * **`gum_thread_get_system_error()` and `gum_thread_set_system_error()`:** Get and set the current thread's `errno` value.

* **Utility Functions:**
    * **`gum_process_query_libc_name()`:**  Attempts to determine the name of the libc library loaded in the process.
    * **`gum_qnx_cpu_type_from_file(const gchar * path, GError ** error)` and `gum_qnx_cpu_type_from_pid(pid_t pid, GError ** error)`:** Determine the CPU architecture (e.g., ARM, x86) by inspecting an executable file or a running process.
    * **`_gum_process_resolve_module_name()`:**  Attempts to find the full path of a module given its name.
    * **`gum_resolve_path()`:**  Resolves symbolic links in a given path.

**Relationship to Reverse Engineering:**

This file is fundamentally important for reverse engineering using Frida. Here are some examples:

* **Code Injection and Hooking:**
    * **`gum_module_load()`:** A reverse engineer can use this to load custom shared libraries into a target process, injecting their own code.
    * **`gum_module_find_export_by_name()`:**  Essential for finding the address of functions they want to intercept (hook). For example, to intercept a security-sensitive function like `authenticate_user`, a reverse engineer would use this to get its address.
    * **`gum_process_modify_thread()`:** After finding the target function's address, this can be used to modify the thread's instruction pointer (`pc` or `eip`) to redirect execution to the injected code (the hook). Alternatively, the hook can modify registers or memory before returning control to the original function.
    * **Example:** A reverse engineer wants to analyze how a specific encryption algorithm is implemented in a QNX application. They would:
        1. Use `gum_module_find_export_by_name()` to locate the encryption function (e.g., `encrypt_data`).
        2. Write a Frida script that defines a hook function.
        3. Use `Interceptor.attach()` (which internally utilizes the functions in this file) to redirect calls to `encrypt_data` to their hook function.
        4. Inside the hook function, they could examine the input arguments, the return value, or even modify them.

* **Analyzing Process Behavior:**
    * **`_gum_process_enumerate_threads()`:** Useful for understanding the threading model of the application and identifying specific threads of interest.
    * **`_gum_process_enumerate_modules()`:** Helps to identify the loaded libraries and the address space they occupy, which is crucial for understanding the application's architecture and potential vulnerabilities.
    * **`_gum_process_enumerate_ranges()`:** Allows examining the memory layout of the process, identifying code segments, data segments, and heap regions. This is crucial for understanding memory management and potentially finding memory corruption issues.
    * **Example:** A reverse engineer suspects a memory leak. They could use `_gum_process_enumerate_ranges()` to monitor the heap region over time and observe if it's growing unexpectedly.

* **Dynamic Analysis and Debugging:**
    * **`gum_thread_suspend()` and `gum_thread_resume()`:** Allow pausing and resuming specific threads, enabling controlled debugging and analysis of specific execution paths.
    * **`gum_process_modify_thread()`:** Can be used to examine and modify the CPU context (registers, stack pointer, etc.) of a thread at a specific point in time, providing insights into its state.
    * **`gum_thread_set_hardware_breakpoint()` (if supported):** Would allow setting breakpoints at specific instructions, halting execution when reached, and examining the program state.

**Involvement of Binary底层, Linux, Android 内核及框架的知识:**

While this file is specific to QNX, understanding concepts from other operating systems like Linux and Android is helpful for grasping the underlying principles:

* **Binary 底层 (Binary Low-Level):**
    * **ELF (Executable and Linkable Format):** The code interacts with ELF headers to determine CPU architecture (`gum_qnx_cpu_type_from_file`). Understanding the ELF structure (e.g., the `e_machine` field) is necessary.
    * **Memory Layout:** Functions like `_gum_process_enumerate_ranges()` deal directly with the process's memory map, which is a fundamental binary-level concept. The code uses `procfs_mapinfo` to get information about memory regions.
    * **CPU Architecture:** The code differentiates between CPU architectures (ARM, x86) and uses appropriate register structures (`X86_CPU_REGISTERS`, `ARM_CPU_REGISTERS`). This requires knowledge of the target architecture's register set.
    * **Dynamic Linking (`dlopen`, `dlsym`):**  The functions dealing with modules rely on the operating system's dynamic linking mechanisms. Understanding how shared libraries are loaded and symbols are resolved is crucial.

* **Linux Kernel (Conceptual Overlap):**
    * **`/proc` Filesystem:** The code heavily uses the `/proc` filesystem (or its QNX equivalent) to access process information (e.g., `/proc/self/as` for memory access, `/proc/<pid>/auxv` for architecture). Linux also uses `/proc` for similar purposes.
    * **Process and Thread Management:**  Concepts like process IDs (PIDs), thread IDs (TIDs), and thread states are fundamental to both QNX and Linux.
    * **Memory Management:**  The idea of memory regions with different protection attributes (read, write, execute) is common across operating systems.

* **Android Framework (Indirect Relevance):**
    * While this code is for QNX, Frida is also used on Android. The general concepts of process instrumentation, code injection, and hooking are similar, although the underlying OS APIs and data structures differ. For instance, on Android, one would interact with the `ptrace` system call and the Android runtime (ART) instead of QNX-specific APIs.

**Logical Reasoning (Hypothetical Input and Output):**

Let's consider the `gum_process_modify_thread` function:

**Hypothetical Input:**

* `thread_id`: 1234 (the ID of a running thread in the process)
* `func`: A function pointer to a C function defined as `void my_modifier(GumThreadId thread_id, GumCpuContext * cpu_context, gpointer user_data)`
* `user_data`: A pointer to some data (e.g., an integer `5`) that `my_modifier` might need.
* `flags`: `GUM_MODIFY_THREAD_FLAGS_ABORT_SAFELY`

**Logical Processing:**

1. The function attempts to hold (suspend) the thread with ID 1234 using `ThreadCtl(_NTO_TCTL_ONE_THREAD_HOLD, ...)`.
2. It then uses `vfork()` to create a lightweight child process.
3. **In the child process:**
    * It opens `/proc/<parent_pid>/as` to access the parent's memory.
    * It retrieves the CPU registers of thread 1234 using `devctl(fd, DCMD_PROC_GETGREG, ...)`.
    * It converts the QNX register structure to Frida's `GumCpuContext`.
    * It calls the provided `my_modifier` function, passing the thread ID, the CPU context, and the `user_data` pointer.
    * **Inside `my_modifier` (example):**  The function might modify `cpu_context->eip` (or `cpu_context->pc`) to change the next instruction to be executed, or modify register values. It could also access the `user_data` (the integer `5` in this case).
    * After `my_modifier` returns, the modified CPU context is converted back to the QNX structure.
    * The modified registers are set back into the thread using `devctl(fd, DCMD_PROC_SETGREG, ...)`.
    * The child process exits.
4. **In the parent process:**
    * It waits for the child process to finish.
    * It releases the hold on thread 1234 using `ThreadCtl(_NTO_TCTL_ONE_THREAD_CONT, ...)`.

**Hypothetical Output:**

* The function returns `TRUE` (assuming no errors occurred).
* The state of thread 1234 in the target process is now modified according to the actions performed by the `my_modifier` function. For instance, if `my_modifier` changed the instruction pointer, the thread will now execute a different code path when it resumes.

**Common User or Programming Errors:**

* **Incorrect Module Names:** When using `gum_module_load()` or `gum_module_find_export_by_name()`, providing an incorrect module name will lead to failure (returning `FALSE` or `0`).
    * **Example:** `gum_module_load("my_injected_code.so")` will fail if the file `my_injected_code.so` does not exist in a location where the dynamic linker can find it.
* **Invalid Symbol Names:**  Providing an incorrect symbol name to `gum_module_find_export_by_name()` will result in a `NULL` address being returned.
    * **Example:**  Trying to find `gum_module_find_export_by_name("libc.so", "non_existent_function")` will return 0.
* **Trying to Modify a Non-Existent Thread:** Using an invalid `thread_id` with functions like `gum_process_modify_thread()` or `gum_thread_suspend()` will likely result in an error (e.g., `errno` being set to `ESRCH`).
* **Incorrectly Modifying CPU Context:** When using `gum_process_modify_thread()`, if the provided modification function (`func`) corrupts the CPU context (e.g., sets the stack pointer to an invalid address), it can lead to crashes or unpredictable behavior when the thread resumes.
* **Permissions Issues:**  Frida needs sufficient privileges to interact with the target process. If the user running the Frida script doesn't have the necessary permissions to access `/proc/<pid>/as` or use `devctl`, these operations will fail.
* **Race Conditions:** If multiple Frida scripts (or multiple parts of the same script) try to modify the same thread or process memory concurrently without proper synchronization, it can lead to race conditions and unpredictable outcomes.
* **Unsupported Operations:** Attempting to use features that are marked as "not supported" (like hardware breakpoints/watchpoints on QNX in this code) will result in errors.

**User Operation Steps Leading Here (Debugging Scenario):**

Imagine a developer is using Frida to debug a QNX application and wants to intercept a function call:

1. **Write a Frida Script:** The developer writes a JavaScript (or Python) Frida script that uses the `Interceptor` API to attach to a function.
   ```javascript
   // Frida script (example)
   Interceptor.attach(Module.findExportByName("my_app", "vulnerable_function"), {
     onEnter: function(args) {
       console.log("vulnerable_function called with:", args);
     }
   });
   ```
2. **Run the Frida Script:** The developer runs the script against the target QNX application using the Frida CLI or API:
   ```bash
   frida -p <process_id> -l my_script.js
   ```
3. **Frida's Internal Workflow:**
   * Frida's core (written in C) needs to perform the following steps to enable the interception:
     * **Find the Module:** It will likely use functions like `_gum_process_resolve_module_name()` and the underlying QNX APIs to locate the "my_app" module in the target process's memory.
     * **Find the Exported Function:** It will call `gum_module_find_export_by_name("my_app", "vulnerable_function")` to get the memory address of the `vulnerable_function`. This is where the code in `gumprocess-qnx.c` gets involved.
     * **Prepare the Hook:** Frida sets up the necessary code to redirect execution to the `onEnter` function in the JavaScript script. This might involve:
         * **Modifying Instructions:**  It might overwrite the beginning of the `vulnerable_function` with a jump instruction to a Frida-controlled trampoline. This would likely involve using `gum_process_modify_thread()` to modify the memory where the function's code resides.
         * **Setting Breakpoints:** Alternatively, it might set a software breakpoint at the beginning of the function.
     * **When the Function is Called:** When the target application calls `vulnerable_function`, execution will be redirected to Frida's code.
     * **Execute JavaScript:** Frida's runtime environment within the target process will execute the `onEnter` function in the script.

**Therefore, the code in `gumprocess-qnx.c` acts as the foundational layer that enables Frida's high-level APIs (like `Interceptor`) to interact with the QNX process at a low level. When a user performs actions like attaching to a function, enumerating modules, or modifying thread state, the Frida core will ultimately call the functions implemented in this `gumprocess-qnx.c` file to perform the necessary operations on the QNX operating system.**

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-qnx/gumprocess-qnx.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2015-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "backend-elf/gumprocess-elf.h"
#include "gum-init.h"
#include "gum/gumqnx.h"
#include "gumqnx-priv.h"

#include <devctl.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/link.h>
#include <sys/neutrino.h>
#include <sys/procfs.h>
#include <ucontext.h>

#define GUM_QNX_MODULE_FLAG_EXECUTABLE 0x00000200

#define GUM_PSR_THUMB 0x20

typedef struct _GumQnxListHead GumQnxListHead;
typedef struct _GumQnxModuleList GumQnxModuleList;
typedef struct _GumQnxModule GumQnxModule;

struct _GumQnxListHead
{
  GumQnxListHead * next;
  GumQnxListHead * prev;
};

struct _GumQnxModuleList
{
  GumQnxListHead list;
  GumQnxModule * module;
  GumQnxListHead * root;
  guint flags;
};

struct _GumQnxModule
{
  Link_map map;
  gint ref_count;
  guint flags;
  const gchar * name;
  /* ... */
};

static gchar * gum_try_init_libc_name (void);
static void gum_deinit_libc_name (void);

static void gum_store_cpu_context (GumThreadId thread_id,
    GumCpuContext * cpu_context, gpointer user_data);
static void gum_enumerate_ranges_of (const gchar * device_path,
    GumPageProtection prot, GumFoundRangeFunc func, gpointer user_data);

static gboolean gum_maybe_resolve_program_module (const gchar * name,
    gchar ** path, GumAddress * base);
static gboolean gum_module_path_equals (const gchar * path,
    const gchar * name_or_path);
static gchar * gum_resolve_path (const gchar * path);

static void gum_cpu_context_from_qnx (const debug_greg_t * gregs,
    GumCpuContext * ctx);
static void gum_cpu_context_to_qnx (const GumCpuContext * ctx,
    debug_greg_t * gregs);

static GumThreadState gum_thread_state_from_system_thread_state (int state);

static gchar * gum_libc_name;

const gchar *
gum_process_query_libc_name (void)
{
  static GOnce once = G_ONCE_INIT;

  g_once (&once, (GThreadFunc) gum_try_init_libc_name, NULL);

  if (once.retval == NULL)
    gum_panic ("Unable to locate the libc; please file a bug");

  return once.retval;
}

static gchar *
gum_try_init_libc_name (void)
{
  const gpointer exit_impl = dlsym (RTLD_NEXT, "exit");

  if (!gum_process_resolve_module_pointer (exit_impl, &gum_libc_name, NULL))
    return NULL;

  _gum_register_destructor (gum_deinit_libc_name);

  return gum_libc_name;
}

static void
gum_deinit_libc_name (void)
{
  g_free (gum_libc_name);
}

gboolean
gum_process_is_debugger_attached (void)
{
  gint fd, res G_GNUC_UNUSED;
  procfs_status status;

  fd = open ("/proc/self", O_RDONLY);
  g_assert (fd != -1);

  status.tid = gettid ();
  res = devctl (fd, DCMD_PROC_TIDSTATUS, &status, sizeof (status), NULL);
  g_assert (res == 0);

  close (fd);

  return status.flags != 0;
}

GumProcessId
gum_process_get_id (void)
{
  return getpid ();
}

GumThreadId
gum_process_get_current_thread_id (void)
{
  return gettid ();
}

gboolean
gum_process_has_thread (GumThreadId thread_id)
{
  gboolean found = FALSE;
  gint fd;
  procfs_status status;

  fd = open ("/proc/self", O_RDONLY);
  g_assert (fd != -1);

  status.tid = thread_id;
  if (devctl (fd, DCMD_PROC_TIDSTATUS, &status, sizeof (status), NULL) != EOK)
    goto beach;

  found = status.tid == thread_id;

beach:
  close (fd);

  return found;
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data,
                           GumModifyThreadFlags flags)
{
  gboolean success = FALSE;
  gboolean holding = FALSE;
  pid_t child;
  int status;

  if (ThreadCtl (_NTO_TCTL_ONE_THREAD_HOLD, GSIZE_TO_POINTER (thread_id)) == -1)
    goto beach;
  holding = TRUE;

  child = vfork ();
  if (child == -1)
    goto beach;

  if (child == 0)
  {
    gchar as_path[PATH_MAX];
    int fd, res G_GNUC_UNUSED;
    procfs_greg gregs;
    GumCpuContext cpu_context;

    sprintf (as_path, "/proc/%d/as", getppid ());

    fd = open (as_path, O_RDWR);
    g_assert (fd != -1);

    res = devctl (fd, DCMD_PROC_CURTHREAD, &thread_id, sizeof (thread_id),
        NULL);
    g_assert (res == 0);

    res = devctl (fd, DCMD_PROC_GETGREG, &gregs, sizeof (gregs), NULL);
    g_assert (res == 0);

    gum_cpu_context_from_qnx (&gregs, &cpu_context);
    func (thread_id, &cpu_context, user_data);
    gum_cpu_context_to_qnx (&cpu_context, &gregs);

    res = devctl (fd, DCMD_PROC_SETGREG, &gregs, sizeof (gregs), NULL);
    g_assert (res == 0);

    close (fd);
    _exit (0);
  }

  waitpid (child, &status, 0);

  success = TRUE;

beach:
  if (holding)
    ThreadCtl (_NTO_TCTL_ONE_THREAD_CONT, GSIZE_TO_POINTER (thread_id));

  return success;
}

void
_gum_process_enumerate_threads (GumFoundThreadFunc func,
                                gpointer user_data)
{
  gint fd, res G_GNUC_UNUSED;
  debug_process_t info;
  debug_thread_t thread;
  gboolean carry_on = TRUE;

  fd = open ("/proc/self/as", O_RDONLY);
  g_assert (fd != -1);

  res = devctl (fd, DCMD_PROC_INFO, &info, sizeof (info), NULL);
  g_assert (res == 0);

  thread.tid = 1;
  while (carry_on &&
      (devctl (fd, DCMD_PROC_TIDSTATUS, &thread, sizeof (thread), NULL) == 0))
  {
    GumThreadDetails details;
    gchar thread_name[_NTO_THREAD_NAME_MAX];

    details.id = thread.tid;

    if (pthread_getname_np (thread.tid, thread_name,
          sizeof (thread_name)) == 0 && thread_name[0] != '\0')
    {
      details.name = thread_name;
    }
    else
    {
      details.name = NULL;
    }

    details.state = gum_thread_state_from_system_thread_state (thread.state);

    if (thread.state != STATE_DEAD &&
        gum_process_modify_thread (details.id, gum_store_cpu_context,
          &details.cpu_context, GUM_MODIFY_THREAD_FLAGS_ABORT_SAFELY))
    {
      carry_on = func (&details, user_data);
    }

    thread.tid++;
  }

  close (fd);
}

static void
gum_store_cpu_context (GumThreadId thread_id,
                       GumCpuContext * cpu_context,
                       gpointer user_data)
{
  memcpy (user_data, cpu_context, sizeof (GumCpuContext));
}

gboolean
_gum_process_collect_main_module (const GumModuleDetails * details,
                                  gpointer user_data)
{
  GumModuleDetails ** out = user_data;

  *out = gum_module_details_copy (details);

  return FALSE;
}

void
_gum_process_enumerate_modules (GumFoundModuleFunc func,
                                gpointer user_data)
{
  GumQnxListHead * handle;
  GumQnxListHead * cur;
  gboolean carry_on = TRUE;

  handle = dlopen (NULL, RTLD_NOW);

  for (cur = handle->next; carry_on && cur != handle; cur = cur->next)
  {
    const GumQnxModuleList * l = (GumQnxModuleList *) cur;
    const GumQnxModule * mod = l->module;
    const Link_map * map = &mod->map;
    gchar * resolved_path, * resolved_name;
    GumModuleDetails details;
    GumMemoryRange range;
    const Elf32_Ehdr * ehdr;
    const Elf32_Phdr * phdr;
    guint i;

    if ((mod->flags & GUM_QNX_MODULE_FLAG_EXECUTABLE) != 0)
    {
      resolved_path = gum_qnx_query_program_path_for_self (NULL);
      g_assert (resolved_path != NULL);
      resolved_name = g_path_get_basename (resolved_path);

      details.name = resolved_name;
      details.path = resolved_path;
    }
    else
    {
      resolved_path = gum_resolve_path (map->l_path);
      resolved_name = NULL;

      details.name = map->l_name;
      details.path = resolved_path;
    }

    details.range = &range;
    range.base_address = map->l_addr;
    range.size = 0;
    ehdr = GSIZE_TO_POINTER (map->l_addr);
    phdr = (gconstpointer) ehdr + ehdr->e_ehsize;
    for (i = 0; i != ehdr->e_phnum; i++)
    {
      const Elf32_Phdr * h = &phdr[i];
      if (h->p_type == PT_LOAD)
        range.size += h->p_memsz;
    }

    carry_on = func (&details, user_data);

    g_free (resolved_name);
    g_free (resolved_path);
  }

  dlclose (handle);
}

void
gum_qnx_enumerate_ranges (pid_t pid,
                          GumPageProtection prot,
                          GumFoundRangeFunc func,
                          gpointer user_data)
{
  gchar * as_path = g_strdup_printf ("/proc/%d/as", pid);
  gum_enumerate_ranges_of (as_path, prot, func, user_data);
  g_free (as_path);
}

void
_gum_process_enumerate_ranges (GumPageProtection prot,
                               GumFoundRangeFunc func,
                               gpointer user_data)
{
  gum_enumerate_ranges_of ("/proc/self/as", prot, func, user_data);
}

static void
gum_enumerate_ranges_of (const gchar * device_path,
                         GumPageProtection prot,
                         GumFoundRangeFunc func,
                         gpointer user_data)
{
  gint fd, res G_GNUC_UNUSED;
  gboolean carry_on = TRUE;
  gint mapinfo_count;
  procfs_mapinfo * mapinfo_entries;
  gsize mapinfo_size;
  procfs_debuginfo * debuginfo;
  const gsize debuginfo_size = sizeof (procfs_debuginfo) + 0x100;
  gint i;

  fd = open (device_path, O_RDONLY);
  if (fd == -1)
    return;

  res = devctl (fd, DCMD_PROC_PAGEDATA, 0, 0, &mapinfo_count);
  g_assert (res == 0);
  mapinfo_size = mapinfo_count * sizeof (procfs_mapinfo);
  mapinfo_entries = g_malloc (mapinfo_size);

  debuginfo = g_malloc (debuginfo_size);

  res = devctl (fd, DCMD_PROC_PAGEDATA, mapinfo_entries, mapinfo_size,
      &mapinfo_count);
  g_assert (res == 0);

  for (i = 0; carry_on && i != mapinfo_count; i++)
  {
    const procfs_mapinfo * mapinfo = &mapinfo_entries[i];
    GumRangeDetails details;
    GumMemoryRange range;
    GumFileMapping file;
    gchar * path = NULL;

    details.range = &range;
    details.protection = _gum_page_protection_from_posix (mapinfo->flags);

    range.base_address = mapinfo->vaddr;
    range.size = mapinfo->size;

    debuginfo->vaddr = mapinfo->vaddr;
    res = devctl (fd, DCMD_PROC_MAPDEBUG, debuginfo, debuginfo_size, NULL);
    g_assert (res == 0);
    if (strcmp (debuginfo->path, "/dev/zero") != 0)
    {
      if (debuginfo->path[0] != '/')
      {
        path = g_strconcat ("/", debuginfo->path, NULL);
        file.path = path;
      }
      else
      {
        file.path = debuginfo->path;
      }

      file.offset = mapinfo->offset;
      file.size = mapinfo->size;

      details.file = &file;
    }
    else
    {
      details.file = NULL;
    }

    if ((details.protection & prot) == prot)
    {
      carry_on = func (&details, user_data);
    }

    g_free (path);
  }

  g_free (debuginfo);
  g_free (mapinfo_entries);

  close (fd);
}

void
gum_process_enumerate_malloc_ranges (GumFoundMallocRangeFunc func,
                                     gpointer user_data)
{
  /* Not implemented */
}

guint
gum_thread_try_get_ranges (GumMemoryRange * ranges,
                           guint max_length)
{
  /* Not implemented */
  return 0;
}

gint
gum_thread_get_system_error (void)
{
  return errno;
}

void
gum_thread_set_system_error (gint value)
{
  errno = value;
}

gboolean
gum_thread_suspend (GumThreadId thread_id,
                    GError ** error)
{
  if (ThreadCtl (_NTO_TCTL_ONE_THREAD_HOLD, GSIZE_TO_POINTER (thread_id)) == -1)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED, "%s", g_strerror (errno));
    return FALSE;
  }
}

gboolean
gum_thread_resume (GumThreadId thread_id,
                   GError ** error)
{
  if (ThreadCtl (_NTO_TCTL_ONE_THREAD_CONT, GSIZE_TO_POINTER (thread_id)) == -1)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED, "%s", g_strerror (errno));
    return FALSE;
  }
}

gboolean
gum_thread_set_hardware_breakpoint (GumThreadId thread_id,
                                    guint breakpoint_id,
                                    GumAddress address,
                                    GError ** error)
{
  g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
      "Hardware breakpoints are not yet supported on this platform");
  return FALSE;
}

gboolean
gum_thread_unset_hardware_breakpoint (GumThreadId thread_id,
                                      guint breakpoint_id,
                                      GError ** error)
{
  g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
      "Hardware breakpoints are not yet supported on this platform");
  return FALSE;
}

gboolean
gum_thread_set_hardware_watchpoint (GumThreadId thread_id,
                                    guint watchpoint_id,
                                    GumAddress address,
                                    gsize size,
                                    GumWatchConditions wc,
                                    GError ** error)
{
  g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
      "Hardware watchpoints are not yet supported on this platform");
  return FALSE;
}

gboolean
gum_thread_unset_hardware_watchpoint (GumThreadId thread_id,
                                      guint watchpoint_id,
                                      GError ** error)
{
  g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
      "Hardware watchpoints are not yet supported on this platform");
  return FALSE;
}

gboolean
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  if (dlopen (module_name, RTLD_LAZY) == NULL)
    goto not_found;

  return TRUE;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND, "%s", dlerror ());
    return FALSE;
  }
}

gboolean
gum_module_ensure_initialized (const gchar * module_name)
{
  gboolean success;
  gchar * name = NULL;
  void * module;

  success = FALSE;

  if (!_gum_process_resolve_module_name (module_name, &name, NULL))
    goto beach;

  module = dlopen (name, RTLD_LAZY);
  if (module == NULL)
    goto beach;
  dlclose (module);

  success = TRUE;

beach:
  g_free (name);

  return success;
}

GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumAddress result;
  void * module;

  if (module_name != NULL)
  {
    gchar * name;

    if (!_gum_process_resolve_module_name (module_name, &name, NULL))
      return 0;
    module = dlopen (name, RTLD_LAZY);
    g_free (name);

    if (module == NULL)
      return 0;
  }
  else
  {
    module = RTLD_DEFAULT;
  }

  result = GUM_ADDRESS (dlsym (module, symbol_name));

  if (module != RTLD_DEFAULT)
    dlclose (module);

  return result;
}

GumCpuType
gum_qnx_cpu_type_from_file (const gchar * path,
                            GError ** error)
{
  GumCpuType result = -1;
  FILE * file;
  guint8 ei_data;
  guint16 e_machine;

  file = fopen (path, "rb");
  if (file == NULL)
    goto beach;

  if (fseek (file, EI_DATA, SEEK_SET) != 0)
    goto beach;
  if (fread (&ei_data, sizeof (ei_data), 1, file) != 1)
    goto beach;

  if (fseek (file, 0x12, SEEK_SET) != 0)
    goto beach;
  if (fread (&e_machine, sizeof (e_machine), 1, file) != 1)
    goto beach;

  if (ei_data == ELFDATA2LSB)
    e_machine = GUINT16_FROM_LE (e_machine);
  else if (ei_data == ELFDATA2MSB)
    e_machine = GUINT16_FROM_BE (e_machine);
  else
    goto unsupported_ei_data;

  switch (e_machine)
  {
    case 0x0003:
      result = GUM_CPU_IA32;
      break;
    case 0x003e:
      result = GUM_CPU_AMD64;
      break;
    case 0x0028:
      result = GUM_CPU_ARM;
      break;
    case 0x00b7:
      result = GUM_CPU_ARM64;
      break;
    case 0x0008:
      result = GUM_CPU_MIPS;
      break;
    default:
      goto unsupported_executable;
  }

  goto beach;

unsupported_ei_data:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "Unsupported ELF EI_DATA");
    goto beach;
  }
unsupported_executable:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "Unsupported executable");
    goto beach;
  }
beach:
  {
    if (file != NULL)
      fclose (file);

    return result;
  }
}

GumCpuType
gum_qnx_cpu_type_from_pid (pid_t pid,
                           GError ** error)
{
  GumCpuType result = -1;
  gchar * auxv_path;
  guint8 * auxv;
  gsize auxv_size, i;

  auxv_path = g_strdup_printf ("/proc/%d/auxv", pid);

  auxv = NULL;
  if (!g_file_get_contents (auxv_path, (gchar **) &auxv, &auxv_size, NULL))
    goto not_found;

#ifdef HAVE_I386
  result = GUM_CPU_AMD64;
#else
  result = GUM_CPU_ARM64;
#endif

  for (i = 0; i < auxv_size; i += 16)
  {
    if (auxv[4] != 0 || auxv[5] != 0 ||
        auxv[6] != 0 || auxv[7] != 0)
    {
#ifdef HAVE_I386
      result = GUM_CPU_IA32;
#else
      result = GUM_CPU_ARM;
#endif
      break;
    }
  }

  goto beach;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND, "Process not found");
    goto beach;
  }
beach:
  {
    g_free (auxv_path);

    return result;
  }
}

gchar *
gum_qnx_query_program_path_for_self (GError ** error)
{
  gchar * program_path = NULL;
  int fd;
  struct
  {
    procfs_debuginfo info;
    char buffer[PATH_MAX];
  } name;

  fd = open ("/proc/self/as", O_RDONLY);
  if (fd == -1)
    goto failure;

  if (devctl (fd, DCMD_PROC_MAPDEBUG_BASE, &name, sizeof (name), 0) != EOK)
    goto failure;

  if (g_path_is_absolute (name.info.path))
  {
    program_path = g_strdup (name.info.path);
  }
  else
  {
    gchar * cwd = g_get_current_dir ();
    program_path = g_canonicalize_filename (name.info.path, cwd);
    g_free (cwd);
  }

  goto beach;

failure:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED, "%s", g_strerror (errno));
    goto beach;
  }
beach:
  {
    if (fd != -1)
      close (fd);

    return program_path;
  }
}

gboolean
_gum_process_resolve_module_name (const gchar * name,
                                  gchar ** path,
                                  GumAddress * base)
{
  GumQnxListHead * handle;
  const GumQnxModule * module;

  handle = dlopen (name, RTLD_LAZY | RTLD_NOLOAD);
  if (handle == NULL)
    return gum_maybe_resolve_program_module (name, path, base);

  module = ((GumQnxModuleList *) handle->next->next)->module;

  if (path != NULL)
    *path = gum_resolve_path (module->map.l_path);

  if (base != NULL)
    *base = module->map.l_addr;

  dlclose (handle);

  return TRUE;
}

static gboolean
gum_maybe_resolve_program_module (const gchar * name,
                                  gchar ** path,
                                  GumAddress * base)
{
  gchar * program_path;

  program_path = gum_qnx_query_program_path_for_self (NULL);
  g_assert (program_path != NULL);

  if (!gum_module_path_equals (program_path, name))
    goto not_the_program;

  if (path != NULL)
    *path = g_steal_pointer (&program_path);

  if (base != NULL)
  {
    GumQnxListHead * handle;
    const GumQnxModule * program;

    handle = dlopen (NULL, RTLD_NOW);

    program = ((GumQnxModuleList *) handle->next)->module;
    *base = program->map.l_addr;

    dlclose (handle);
  }

  g_free (program_path);

  return TRUE;

not_the_program:
  {
    g_free (program_path);

    return FALSE;
  }
}

static gboolean
gum_module_path_equals (const gchar * path,
                        const gchar * name_or_path)
{
  gchar * s;

  if (name_or_path[0] == '/')
    return strcmp (name_or_path, path) == 0;

  if ((s = strrchr (path, '/')) != NULL)
    return strcmp (name_or_path, s + 1) == 0;

  return strcmp (name_or_path, path) == 0;
}

static gchar *
gum_resolve_path (const gchar * path)
{
  gchar * target, * parent_dir, * canonical_path;

  target = g_file_read_link (path, NULL);
  if (target == NULL)
    return g_strdup (path);

  parent_dir = g_path_get_dirname (path);

  canonical_path = g_canonicalize_filename (target, parent_dir);

  g_free (parent_dir);
  g_free (target);

  return canonical_path;
}

static void
gum_cpu_context_from_qnx (const debug_greg_t * gregs,
                          GumCpuContext * ctx)
{
#if defined (HAVE_I386)
  const X86_CPU_REGISTERS * regs = &gregs->x86;

  ctx->eip = regs->eip;

  ctx->edi = regs->edi;
  ctx->esi = regs->esi;
  ctx->ebp = regs->ebp;
  ctx->esp = regs->esp;
  ctx->ebx = regs->ebx;
  ctx->edx = regs->edx;
  ctx->ecx = regs->ecx;
  ctx->eax = regs->eax;
#elif defined (HAVE_ARM)
  const ARM_CPU_REGISTERS * regs = &gregs->arm;

  ctx->pc = regs->gpr[ARM_REG_R15];
  ctx->sp = regs->gpr[ARM_REG_R13];
  ctx->cpsr = regs->spsr;

  ctx->r8 = regs->gpr[ARM_REG_R8];
  ctx->r9 = regs->gpr[ARM_REG_R9];
  ctx->r10 = regs->gpr[ARM_REG_R10];
  ctx->r11 = regs->gpr[ARM_REG_R11];
  ctx->r12 = regs->gpr[ARM_REG_R12];

  memset (ctx->v, 0, sizeof (ctx->v));

  memcpy (ctx->r, regs->gpr, sizeof (ctx->r));
  ctx->lr = regs->gpr[ARM_REG_R14];
#else
# error Fix this for other architectures
#endif
}

static void
gum_cpu_context_to_qnx (const GumCpuContext * ctx,
                        debug_greg_t * gregs)
{
#if defined (HAVE_I386)
  X86_CPU_REGISTERS * regs = &gregs->x86;

  regs->eip = ctx->eip;

  regs->edi = ctx->edi;
  regs->esi = ctx->esi;
  regs->ebp = ctx->ebp;
  regs->esp = ctx->esp;
  regs->ebx = ctx->ebx;
  regs->edx = ctx->edx;
  regs->ecx = ctx->ecx;
  regs->eax = ctx->eax;
#elif defined (HAVE_ARM)
  ARM_CPU_REGISTERS * regs = &gregs->arm;

  regs->gpr[ARM_REG_R15] = ctx->pc;
  regs->gpr[ARM_REG_R13] = ctx->sp;
  regs->spsr = ctx->cpsr;

  regs->gpr[ARM_REG_R8] = ctx->r8;
  regs->gpr[ARM_REG_R9] = ctx->r9;
  regs->gpr[ARM_REG_R10] = ctx->r10;
  regs->gpr[ARM_REG_R11] = ctx->r11;
  regs->gpr[ARM_REG_R12] = ctx->r12;

  memcpy (regs->gpr, ctx->r, sizeof (ctx->r));
  regs->gpr[ARM_REG_R14] = ctx->lr;
#else
# error Fix this for other architectures
#endif
}

static GumThreadState
gum_thread_state_from_system_thread_state (gint state)
{
  switch (state)
  {
    case STATE_RUNNING:
      return GUM_THREAD_RUNNING;
    case STATE_CONDVAR:
    case STATE_INTR:
    case STATE_JOIN:
    case STATE_MUTEX:
    case STATE_NET_REPLY:
    case STATE_NET_SEND:
    case STATE_READY:
    case STATE_RECEIVE:
    case STATE_REPLY:
    case STATE_NANOSLEEP:
    case STATE_SEM:
    case STATE_SEND:
    case STATE_SIGSUSPEND:
    case STATE_SIGWAITINFO:
    case STATE_STACK:
    case STATE_WAITCTX:
    case STATE_WAITPAGE:
    case STATE_WAITTHREAD:
      return GUM_THREAD_WAITING;
    case STATE_STOPPED:
      return GUM_THREAD_STOPPED;
    case STATE_DEAD:
      return GUM_THREAD_HALTED;
    default:
      g_assert_not_reached ();
      break;
  }
}

void
gum_qnx_parse_ucontext (const ucontext_t * uc,
                        GumCpuContext * ctx)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  const X86_CPU_REGISTERS * cpu = &uc->uc_mcontext.cpu;

  ctx->eip = cpu->eip;

  ctx->edi = cpu->edi;
  ctx->esi = cpu->esi;
  ctx->ebp = cpu->ebp;
  ctx->esp = cpu->esp;
  ctx->ebx = cpu->ebx;
  ctx->edx = cpu->edx;
  ctx->ecx = cpu->ecx;
  ctx->eax = cpu->eax;
#elif defined (HAVE_ARM)
  const ARM_CPU_REGISTERS * cpu = &uc->uc_mcontext.cpu;
  guint i;

  ctx->pc = cpu->gpr[ARM_REG_PC];
  ctx->sp = cpu->gpr[ARM_REG_SP];
  ctx->cpsr = cpu->spsr;

  ctx->r8 = cpu->gpr[ARM_REG_R8];
  ctx->r9 = cpu->gpr[ARM_REG_R9];
  ctx->r10 = cpu->gpr[ARM_REG_R10];
  ctx->r11 = cpu->gpr[ARM_REG_R11];
  ctx->r12 = cpu->gpr[ARM_REG_R12];

  memset (ctx->v, 0, sizeof (ctx->v));

  for (i = 0; i != G_N_ELEMENTS (ctx->r); i++)
    ctx->r[i] = cpu->gpr[i];
  ctx->lr = cpu->gpr[ARM_REG_LR];
#else
# error FIXME
#endif
}

void
gum_qnx_unparse_ucontext (const GumCpuContext * ctx,
                          ucontext_t * uc)
{
#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  X86_CPU_REGISTERS * cpu = &uc->uc_mcontext.cpu;

  cpu->eip = ctx->eip;

  cpu->edi = ctx->edi;
  cpu->esi = ctx->esi;
  cpu->ebp = ctx->ebp;
  cpu->esp = ctx->esp;
  cpu->ebx = ctx->ebx;
  cpu->edx = ctx->edx;
  cpu->ecx = ctx->ecx;
  cpu->eax = ctx->eax;
#elif defined (HAVE_ARM)
  ARM_CPU_REGISTERS * cpu = &uc->uc_mcontext.cpu;
  guint i;

  cpu->gpr[ARM_REG_PC] = ctx->pc;
  cpu->gpr[ARM_REG_SP] = ctx->sp;
  cpu->spsr = ctx->cpsr;
  if (ctx->pc & 1)
    cpu->spsr |= GUM_PSR_THUMB;
  else
    cpu->spsr &= ~GUM_PSR_THUMB;

  cpu->gpr[ARM_REG_R8] = ctx->r8;
  cpu->gpr[ARM_REG_R9] = ctx->r9;
  cpu->gpr[ARM_REG_R10] = ctx->r10;
  cpu->gpr[ARM_REG_R11] = ctx->r11;
  cpu->gpr[ARM_REG_R12] = ctx->r12;

  for (i = 0; i != G_N_ELEMENTS (ctx->r); i++)
    cpu->gpr[i] = ctx->r[i];
  cpu->gpr[ARM_REG_LR] = ctx->lr;
#else
# error FIXME
#endif
}


"""

```