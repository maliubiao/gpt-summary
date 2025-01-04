Response:
Let's break down the thought process for analyzing this C code snippet for Frida, aiming to extract its functionalities and connections to reverse engineering, low-level aspects, and potential user errors.

**1. Initial Reading and Keyword Spotting:**

First, I'd read through the code, not necessarily understanding every detail, but looking for keywords and structures that give clues about its purpose. I'd notice:

* **`guminterceptor.h`**: This strongly suggests the file is related to interception, a core concept in dynamic instrumentation.
* **`Copyright (C) ... Ole André Vadla Ravnås ... fridaDynamic instrumentation tool`**:  This confirms the context and purpose of the code.
* **`#include` directives**: These point to dependencies like `gumcodesegment.h`, `gumlibc.h`, `gummemory.h`, `gumprocess-priv.h`, `gumtls.h`. These hints at functionalities related to code manipulation, standard library interactions, memory management, process-level operations, and thread-local storage.
* **`typedef struct ...`**:  These define various data structures, suggesting the organization of the interceptor's state and operations. I'd pay attention to names like `GumInterceptorTransaction`, `GumFunctionContext`, `GumInvocationListener`, `GumInvocationStackEntry`.
* **Function names like `gum_interceptor_attach`, `gum_interceptor_detach`, `gum_interceptor_replace`, `gum_interceptor_revert`**: These are explicit indicators of core interception operations.
* **Macros like `GUM_INTERCEPTOR_LOCK` and `GUM_INTERCEPTOR_UNLOCK`**: These point to thread safety mechanisms.
* **Enums like `enum _GumInstrumentationError`**: These define potential errors during instrumentation.

**2. Identifying Core Functionalities (based on function names and data structures):**

Based on the initial scan, I'd start listing the apparent functionalities:

* **Attaching/Detaching Listeners:**  `gum_interceptor_attach`, `gum_interceptor_detach`, `GumInvocationListener`. This suggests the ability to insert custom code at function entry/exit.
* **Replacing Functions:** `gum_interceptor_replace`, `gum_interceptor_replace_fast`. This indicates the capability to completely substitute a function's implementation.
* **Transaction Management:** `GumInterceptorTransaction`, `gum_interceptor_begin_transaction`, `gum_interceptor_end_transaction`, `gum_interceptor_flush`. This implies a mechanism to group multiple interception operations together and apply them atomically.
* **Invocation Context Management:** `GumInvocationContext`, `GumInvocationStack`, `gum_interceptor_get_current_invocation`, `gum_interceptor_get_current_stack`. This suggests the tracking of function calls and their associated state.
* **Thread Management:** `gum_interceptor_ignore_current_thread`, `gum_interceptor_unignore_current_thread`, `gum_interceptor_ignore_other_threads`, `gum_interceptor_unignore_other_threads`. This points to the ability to selectively apply interception to specific threads.
* **Code Allocation:** `GumCodeAllocator`. This is necessary for creating trampolines and potentially storing injected code.

**3. Connecting to Reverse Engineering:**

With the identified functionalities, I'd consider how they relate to reverse engineering:

* **Attaching Listeners:** Directly supports dynamic analysis by allowing the inspection of function arguments, return values, and internal state *without* modifying the original function's core logic. This is crucial for understanding function behavior.
* **Replacing Functions:** Enables modifying program behavior on the fly. This can be used for patching vulnerabilities, bypassing security checks, or even adding new features during runtime analysis.
* **Invocation Context/Stack:**  Provides a call trace, which is invaluable for understanding the execution flow leading to a specific function call. This helps in tracing back how a particular state was reached.

**4. Identifying Low-Level/Kernel Aspects:**

Looking at the included headers and certain function names helps identify low-level interactions:

* **`gumcodesegment.h`**: Implies direct manipulation of code segments in memory, a very low-level operation.
* **`gummemory.h`**: Suggests interaction with memory management, including potentially `mprotect` calls for changing memory permissions.
* **`gumprocess-priv.h`**: Indicates interaction with process-level details, like thread IDs and enumeration.
* **`#ifdef HAVE_DARWIN ... mach/mach.h`**: Shows OS-specific handling, in this case, for macOS (Darwin), likely involving Mach ports for thread manipulation.
* **`gum_page_address_from_pointer`, `gum_mprotect`, `gum_clear_cache`**: These functions clearly point to operating system-level interactions related to memory pages and cache coherence.

**5. Inferring Logic and Potential User Errors:**

By examining the function signatures and the transactional nature of operations, I can infer some logic and potential pitfalls:

* **Transactions:** The code uses transactions to ensure that multiple interception changes are applied atomically. A user error could be forgetting to `end_transaction`, leading to changes not being applied.
* **Attaching/Replacing Already Attached/Replaced Functions:** The `GumAttachReturn` and `GumReplaceReturn` enums include `_ALREADY_ATTACHED` and `_ALREADY_REPLACED` errors. This indicates that attempting to attach or replace a function that is already intercepted is a potential user error.
* **Incorrect Signatures/Types:** The `GUM_INSTRUMENTATION_ERROR_WRONG_SIGNATURE` and `GUM_INSTRUMENTATION_ERROR_WRONG_TYPE` errors highlight that Frida likely performs checks on the function's signature or type before attempting interception. Providing incorrect replacements or listeners could lead to these errors.
* **Thread Safety:** The use of mutexes (`g_rec_mutex`) suggests that the interceptor is designed to be thread-safe. However, improper usage, like calling interception functions without holding necessary locks (if exposed externally), could lead to race conditions (though this seems internally managed).

**6. Tracing User Operations (Conceptual):**

I'd think about the typical Frida workflow:

1. **Scripting:** A user writes a Frida script using the Frida API (likely in JavaScript or Python).
2. **Target Selection:** The script targets a specific process or application.
3. **API Calls:** The script uses Frida's API to interact with the target process, for example, calling `Interceptor.attach()` or `Interceptor.replace()`.
4. **Under the Hood:**  These higher-level API calls eventually translate to calls to the C code in `guminterceptor.c`. For instance, `Interceptor.attach(address, { onEnter: ... })` would eventually lead to a call to `gum_interceptor_attach` with the provided address and a generated `GumInvocationListener`.

**7. Iterative Refinement:**

Throughout this process, I'd revisit the code as I gain more understanding. For example, after noticing the transaction mechanism, I'd go back and look at how `is_dirty` is used and how the pending tasks are handled.

By following this systematic approach, focusing on keywords, data structures, and function names, I can effectively analyze the C code and extract its key functionalities, its relevance to reverse engineering, its low-level aspects, and potential user errors.
This C source code file, `guminterceptor.c`, is a core component of Frida's dynamic instrumentation engine. It handles the central logic for intercepting function calls within a target process. Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Function Interception Management:**
   - **Attaching Listeners (`gum_interceptor_attach`):**  Allows users to register callbacks (listeners) that will be executed when a specific function is called. These listeners can inspect and modify function arguments and return values.
   - **Detaching Listeners (`gum_interceptor_detach`):** Removes previously registered listeners from a function.
   - **Replacing Functions (`gum_interceptor_replace`, `gum_interceptor_replace_fast`):** Enables users to completely replace the original implementation of a function with their own custom code.
   - **Reverting Replacements (`gum_interceptor_revert`):** Restores a function to its original implementation after it has been replaced.
   - **Tracking Intercepted Functions:** Maintains a hash table (`function_by_address`) to store information about intercepted functions, including their original address, replacement function (if any), and attached listeners.

2. **Transaction Management (`gum_interceptor_begin_transaction`, `gum_interceptor_end_transaction`, `gum_interceptor_flush`):**
   - Provides a mechanism to group multiple interception operations (attach, detach, replace) into a single atomic transaction. This ensures that changes are applied consistently and avoids race conditions.
   - `gum_interceptor_begin_transaction` starts a new transaction.
   - `gum_interceptor_end_transaction` commits the changes made within the transaction.
   - `gum_interceptor_flush` forces the application of pending changes.

3. **Invocation Context Management:**
   - **Tracking Function Call Stacks (`GumInvocationStack`):** Maintains a stack of currently active intercepted function calls for the current thread. This is crucial for understanding the call flow and accessing context-specific information.
   - **Accessing Current Invocation (`gum_interceptor_get_current_invocation`):** Provides access to information about the currently executing intercepted function call, such as arguments and context.
   - **Accessing Live Replacement Invocation (`gum_interceptor_get_live_replacement_invocation`):**  Allows access to the invocation context specifically when inside a replacement function.
   - **Ignoring/Unignoring Threads (`gum_interceptor_ignore_current_thread`, `gum_interceptor_unignore_current_thread`, `gum_interceptor_ignore_other_threads`, `gum_interceptor_unignore_other_threads`):** Offers control over which threads are affected by interception. Users can temporarily disable interception for the current thread or focus interception on a specific thread.
   - **Saving and Restoring Invocation State (`gum_interceptor_save`, `gum_interceptor_restore`):** Allows saving the current state of the invocation stack and restoring it later, which can be useful for complex instrumentation scenarios.

4. **Low-Level Code Manipulation:**
   - **Trampoline Management:**  The code uses trampolines (small pieces of generated code) to redirect execution flow from the original function to the interception logic and back. This involves allocating executable memory, writing machine code, and managing the execution flow.
   - **Code Allocation (`GumCodeAllocator`):** Manages the allocation of memory for trampolines and other injected code.
   - **Memory Protection (`gum_mprotect`):**  Potentially uses system calls like `mprotect` to change the memory protection attributes of code pages (e.g., making them writable and executable temporarily).
   - **Cache Coherency (`gum_clear_cache`):** Ensures that CPU caches are synchronized after modifying code in memory.

5. **Thread Context Management:**
   - **Thread-Local Storage (`GPrivate`, `GumTlsKey`):** Uses thread-local storage to maintain per-thread interception context, including the invocation stack and listener data. This ensures that interception data is isolated between threads.

**Relationship to Reverse Engineering:**

This file is *fundamentally* related to reverse engineering. Its core purpose is to enable dynamic analysis and manipulation of running processes. Here are some examples:

* **Hooking Functions:**  Attaching listeners (`gum_interceptor_attach`) is a primary technique in reverse engineering to understand how functions are called, what arguments they receive, and what they return. This can reveal the internal workings of a program.
    * **Example:** A reverse engineer could attach a listener to the `open` system call to track which files an application is accessing.
* **Function Replacement:**  Replacing functions (`gum_interceptor_replace`) is used to modify program behavior. This can be for:
    * **Bypassing Security Checks:**  Replacing authentication functions to gain access.
    * **Fuzzing:**  Replacing input processing functions to inject malicious data.
    * **Debugging:** Replacing problematic functions with versions that log more information or behave predictably.
    * **Example:**  A reverse engineer could replace a function that checks for a license key to bypass the licensing mechanism.
* **Call Stack Analysis:**  Accessing the invocation stack (`gum_interceptor_get_current_stack`) helps to understand the sequence of function calls leading to a particular point in the program. This is essential for tracing bugs or understanding complex program logic.
    * **Example:** If an application crashes, a reverse engineer can use the call stack to identify the series of function calls that led to the crash.

**Binary Underlying, Linux/Android Kernel and Framework Knowledge:**

The code heavily interacts with the underlying binary and operating system. Here's how:

* **Binary Underlying:**
    * **Instruction Pointer Manipulation:** Trampolines directly manipulate the instruction pointer (IP or RIP register) to redirect execution.
    * **Calling Conventions:** The interception logic needs to be aware of the calling conventions used by the target architecture (e.g., how arguments are passed, where return values are stored).
    * **Machine Code Generation:**  Frida dynamically generates machine code for trampolines.
* **Linux/Android Kernel:**
    * **Memory Management System Calls:** Functions like `mprotect` are direct interactions with the kernel's memory management.
    * **Thread Management:**  The code interacts with the operating system's thread management to suspend and resume threads. The use of `mach_port_mod_refs` under `HAVE_DARWIN` indicates macOS-specific thread handling.
    * **Code Signing Policy:** The code checks `gum_process_get_code_signing_policy()`, which is relevant to systems with code signing enforcement (like iOS and modern macOS).
* **Framework Knowledge (Indirectly):** While this file doesn't directly interact with Android framework APIs, the broader Frida ecosystem often targets Android applications. Understanding the Android runtime (ART) and its specific function calling conventions is crucial for successful interception on Android.

**Logical Reasoning with Assumptions:**

Let's consider `gum_interceptor_attach`:

**Assumed Input:**
   - `self`: A valid `GumInterceptor` object.
   - `function_address`: A valid memory address of a function in the target process.
   - `listener`: A pointer to a `GumInvocationListener` structure containing the callbacks to execute.
   - `listener_function_data`:  Optional data to be passed to the listener callbacks.

**Reasoning:**
1. The function attempts to resolve the `function_address` to its actual location in memory.
2. It checks if the function is already instrumented. If not, it attempts to instrument it (create a trampoline).
3. It checks if the provided `listener` is already attached to this function.
4. If not, it adds the `listener` to the list of listeners associated with the function.

**Output:**
   - Returns `GUM_ATTACH_OK` on successful attachment.
   - Returns other `GumAttachReturn` values (e.g., `GUM_ATTACH_ALREADY_ATTACHED`, `GUM_ATTACH_WRONG_SIGNATURE`) if there are issues.

**User or Programming Common Usage Errors:**

1. **Attaching to an Invalid Address:** Providing an incorrect or non-existent memory address for `function_address` will lead to errors during instrumentation or crashes.
2. **Attaching the Same Listener Multiple Times:** The code prevents attaching the same listener multiple times to the same function, returning `GUM_ATTACH_ALREADY_ATTACHED`. Users might unintentionally try to do this.
3. **Incorrect Listener Implementation:** If the callbacks within the `GumInvocationListener` are not implemented correctly (e.g., incorrect function signatures), it can lead to crashes or unexpected behavior.
4. **Forgetting to Detach Listeners:**  Failing to detach listeners when they are no longer needed can lead to performance overhead and unexpected behavior if the listeners interfere with other parts of the application.
5. **Race Conditions (less likely with the transaction mechanism):**  Without proper use of transactions, attempting to attach/detach/replace from multiple threads simultaneously could lead to inconsistent state. However, the provided code has internal locking mechanisms.
6. **Replacing Functions Incorrectly:**  Replacing a function with a replacement that has a different calling convention or doesn't preserve the original function's behavior can break the application.
7. **Calling Interceptor Functions Without a Transaction (for operations that require it):** While the code manages transactions internally, misunderstandings about when transactions are necessary could lead to unexpected behavior if external API calls don't properly initiate or respect these boundaries.

**User Operation Steps Leading Here (as a debugging clue):**

1. **User writes a Frida script (e.g., in JavaScript or Python).**
2. **The script uses Frida's `Interceptor` API.** For example:
   ```javascript
   Interceptor.attach(Module.findExportByName("libexample.so", "some_function"), {
     onEnter: function(args) {
       console.log("Entering some_function with arguments:", args);
     },
     onLeave: function(retval) {
       console.log("Leaving some_function with return value:", retval);
     }
   });
   ```
3. **Frida's JavaScript bindings translate this `Interceptor.attach` call into a call to the underlying C++ Frida agent.**
4. **The C++ agent eventually calls the `gum_interceptor_obtain()` function in `guminterceptor.c` to get a handle to the global interceptor object.**
5. **The C++ agent then calls `gum_interceptor_attach()` in `guminterceptor.c`, passing the target function address and information about the listener (generated from the JavaScript `onEnter` and `onLeave` functions).**
6. **If a user is debugging Frida or encountering issues with interception, they might step into the `guminterceptor.c` code to understand why an attach operation is failing or behaving unexpectedly.**

**Summary of Functionality (Part 1):**

This file, `guminterceptor.c`, is the core of Frida's function interception mechanism. It provides the fundamental building blocks for dynamically attaching listeners to function calls and replacing function implementations. It manages the state of intercepted functions, handles transactions to ensure consistency, and provides access to the function call context. It operates at a low level, interacting with memory management and thread control within the target process.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/guminterceptor.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2008-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 * Copyright (C) 2024 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2024 Yannis Juglaret <yjuglaret@mozilla.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "guminterceptor.h"

#include "gumcodesegment.h"
#include "guminterceptor-priv.h"
#include "gumlibc.h"
#include "gummemory.h"
#include "gumprocess-priv.h"
#include "gumtls.h"

#include <string.h>
#ifdef HAVE_DARWIN
# include <mach/mach.h>
#endif

#ifdef HAVE_MIPS
# define GUM_INTERCEPTOR_CODE_SLICE_SIZE 1024
#else
# define GUM_INTERCEPTOR_CODE_SLICE_SIZE 256
#endif

#define GUM_INTERCEPTOR_LOCK(o) g_rec_mutex_lock (&(o)->mutex)
#define GUM_INTERCEPTOR_UNLOCK(o) g_rec_mutex_unlock (&(o)->mutex)

typedef struct _GumInterceptorTransaction GumInterceptorTransaction;
typedef guint GumInstrumentationError;
typedef struct _GumDestroyTask GumDestroyTask;
typedef struct _GumUpdateTask GumUpdateTask;
typedef struct _GumSuspendOperation GumSuspendOperation;
typedef struct _ListenerEntry ListenerEntry;
typedef struct _InterceptorThreadContext InterceptorThreadContext;
typedef struct _GumInvocationStackEntry GumInvocationStackEntry;
typedef struct _ListenerDataSlot ListenerDataSlot;
typedef struct _ListenerInvocationState ListenerInvocationState;

typedef void (* GumUpdateTaskFunc) (GumInterceptor * self,
    GumFunctionContext * ctx, gpointer prologue);

struct _GumInterceptorTransaction
{
  gboolean is_dirty;
  gint level;
  GQueue * pending_destroy_tasks;
  GHashTable * pending_update_tasks;

  GumInterceptor * interceptor;
};

struct _GumInterceptor
{
#ifndef GUM_DIET
  GObject parent;
#else
  GumObject parent;
#endif

  GRecMutex mutex;

  GHashTable * function_by_address;

  GumInterceptorBackend * backend;
  GumCodeAllocator allocator;

  volatile guint selected_thread_id;

  GumInterceptorTransaction current_transaction;
};

enum _GumInstrumentationError
{
  GUM_INSTRUMENTATION_ERROR_NONE,
  GUM_INSTRUMENTATION_ERROR_WRONG_SIGNATURE,
  GUM_INSTRUMENTATION_ERROR_POLICY_VIOLATION,
  GUM_INSTRUMENTATION_ERROR_WRONG_TYPE,
};

struct _GumDestroyTask
{
  GumFunctionContext * ctx;
  GDestroyNotify notify;
  gpointer data;
};

struct _GumUpdateTask
{
  GumFunctionContext * ctx;
  GumUpdateTaskFunc func;
};

struct _GumSuspendOperation
{
  GumThreadId current_thread_id;
  GQueue suspended_threads;
};

struct _ListenerEntry
{
#ifndef GUM_DIET
  GumInvocationListenerInterface * listener_interface;
  GumInvocationListener * listener_instance;
#else
  union
  {
    GumInvocationListener * listener_interface;
    GumInvocationListener * listener_instance;
  };
#endif
  gpointer function_data;
};

struct _InterceptorThreadContext
{
  GumInvocationBackend listener_backend;
  GumInvocationBackend replacement_backend;

  gint ignore_level;

  GumInvocationStack * stack;

  GArray * listener_data_slots;
};

struct _GumInvocationStackEntry
{
  GumFunctionContext * function_ctx;
  gpointer caller_ret_addr;
  GumInvocationContext invocation_context;
  GumCpuContext cpu_context;
  guint8 listener_invocation_data[GUM_MAX_LISTENERS_PER_FUNCTION]
      [GUM_MAX_LISTENER_DATA];
  gboolean calling_replacement;
  gint original_system_error;
};

struct _ListenerDataSlot
{
  GumInvocationListener * owner;
  guint8 data[GUM_MAX_LISTENER_DATA];
};

struct _ListenerInvocationState
{
  GumPointCut point_cut;
  ListenerEntry * entry;
  InterceptorThreadContext * interceptor_ctx;
  guint8 * invocation_data;
};

#ifndef GUM_DIET
static void gum_interceptor_dispose (GObject * object);
static void gum_interceptor_finalize (GObject * object);

static void the_interceptor_weak_notify (gpointer data,
    GObject * where_the_object_was);
#endif
static GumReplaceReturn gum_interceptor_replace_with_type (
    GumInterceptor * self, GumInterceptorType type, gpointer function_address,
    gpointer replacement_function, gpointer replacement_data,
    gpointer * original_function);
static GumFunctionContext * gum_interceptor_instrument (GumInterceptor * self,
    GumInterceptorType type, gpointer function_address,
    GumInstrumentationError * error);
static void gum_interceptor_activate (GumInterceptor * self,
    GumFunctionContext * ctx, gpointer prologue);
static void gum_interceptor_deactivate (GumInterceptor * self,
    GumFunctionContext * ctx, gpointer prologue);

static void gum_interceptor_transaction_init (
    GumInterceptorTransaction * transaction, GumInterceptor * interceptor);
static void gum_interceptor_transaction_destroy (
    GumInterceptorTransaction * transaction);
static void gum_interceptor_transaction_begin (
    GumInterceptorTransaction * self);
static void gum_interceptor_transaction_end (GumInterceptorTransaction * self);
static gboolean gum_maybe_suspend_thread (const GumThreadDetails * details,
    gpointer user_data);
static void gum_interceptor_transaction_schedule_destroy (
    GumInterceptorTransaction * self, GumFunctionContext * ctx,
    GDestroyNotify notify, gpointer data);
static void gum_interceptor_transaction_schedule_update (
    GumInterceptorTransaction * self, GumFunctionContext * ctx,
    GumUpdateTaskFunc func);

static GumFunctionContext * gum_function_context_new (
    GumInterceptor * interceptor, gpointer function_address,
    GumInterceptorType type);
static void gum_function_context_finalize (GumFunctionContext * function_ctx);
static void gum_function_context_destroy (GumFunctionContext * function_ctx);
static void gum_function_context_perform_destroy (
    GumFunctionContext * function_ctx);
static gboolean gum_function_context_is_empty (
    GumFunctionContext * function_ctx);
static void gum_function_context_add_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener,
    gpointer function_data);
static void gum_function_context_remove_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener);
static void listener_entry_free (ListenerEntry * entry);
static gboolean gum_function_context_has_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener);
static ListenerEntry ** gum_function_context_find_listener (
    GumFunctionContext * function_ctx, GumInvocationListener * listener);
static ListenerEntry ** gum_function_context_find_taken_listener_slot (
    GumFunctionContext * function_ctx);
static void gum_function_context_fixup_cpu_context (
    GumFunctionContext * function_ctx, GumCpuContext * cpu_context);

static InterceptorThreadContext * get_interceptor_thread_context (void);
static void release_interceptor_thread_context (
    InterceptorThreadContext * context);
static InterceptorThreadContext * interceptor_thread_context_new (void);
static void interceptor_thread_context_destroy (
    InterceptorThreadContext * context);
static gpointer interceptor_thread_context_get_listener_data (
    InterceptorThreadContext * self, GumInvocationListener * listener,
    gsize required_size);
static void interceptor_thread_context_forget_listener_data (
    InterceptorThreadContext * self, GumInvocationListener * listener);
static GumInvocationStackEntry * gum_invocation_stack_push (
    GumInvocationStack * stack, GumFunctionContext * function_ctx,
    gpointer caller_ret_addr);
static gpointer gum_invocation_stack_pop (GumInvocationStack * stack);
static GumInvocationStackEntry * gum_invocation_stack_peek_top (
    GumInvocationStack * stack);

static gpointer gum_interceptor_resolve (GumInterceptor * self,
    gpointer address);
static gboolean gum_interceptor_has (GumInterceptor * self,
    gpointer function_address);

static gpointer gum_page_address_from_pointer (gpointer ptr);
static gint gum_page_address_compare (gconstpointer a, gconstpointer b);

#ifndef GUM_DIET
G_DEFINE_TYPE (GumInterceptor, gum_interceptor, G_TYPE_OBJECT)
#endif

static GMutex _gum_interceptor_lock;
static GumInterceptor * _the_interceptor = NULL;

static GumSpinlock gum_interceptor_thread_context_lock = GUM_SPINLOCK_INIT;
static GHashTable * gum_interceptor_thread_contexts;
static GPrivate gum_interceptor_context_private =
    G_PRIVATE_INIT ((GDestroyNotify) release_interceptor_thread_context);
static GumTlsKey gum_interceptor_guard_key;

static GumInvocationStack _gum_interceptor_empty_stack = { NULL, 0 };

#ifndef GUM_DIET

static void
gum_interceptor_class_init (GumInterceptorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_interceptor_dispose;
  object_class->finalize = gum_interceptor_finalize;
}

#endif

void
_gum_interceptor_init (void)
{
  gum_interceptor_thread_contexts = g_hash_table_new_full (NULL, NULL,
      (GDestroyNotify) interceptor_thread_context_destroy, NULL);

  gum_interceptor_guard_key = gum_tls_key_new ();
}

void
_gum_interceptor_deinit (void)
{
  gum_tls_key_free (gum_interceptor_guard_key);

  g_hash_table_unref (gum_interceptor_thread_contexts);
  gum_interceptor_thread_contexts = NULL;
}

static void
gum_interceptor_init (GumInterceptor * self)
{
  g_rec_mutex_init (&self->mutex);

  self->function_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_function_context_destroy);

  gum_code_allocator_init (&self->allocator, GUM_INTERCEPTOR_CODE_SLICE_SIZE);

  gum_interceptor_transaction_init (&self->current_transaction, self);
}

static void
gum_interceptor_do_dispose (GumInterceptor * self)
{
  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction);
  self->current_transaction.is_dirty = TRUE;

  g_hash_table_remove_all (self->function_by_address);

  gum_interceptor_transaction_end (&self->current_transaction);
  GUM_INTERCEPTOR_UNLOCK (self);
}

static void
gum_interceptor_do_finalize (GumInterceptor * self)
{
  gum_interceptor_transaction_destroy (&self->current_transaction);

  if (self->backend != NULL)
    _gum_interceptor_backend_destroy (self->backend);

  g_rec_mutex_clear (&self->mutex);

  g_hash_table_unref (self->function_by_address);

  gum_code_allocator_free (&self->allocator);
}

#ifndef GUM_DIET

static void
gum_interceptor_dispose (GObject * object)
{
  gum_interceptor_do_dispose (GUM_INTERCEPTOR (object));

  G_OBJECT_CLASS (gum_interceptor_parent_class)->dispose (object);
}

static void
gum_interceptor_finalize (GObject * object)
{
  gum_interceptor_do_finalize (GUM_INTERCEPTOR (object));

  G_OBJECT_CLASS (gum_interceptor_parent_class)->finalize (object);
}

#else

static void
gum_interceptor_finalize (GumObject * object)
{
  GumInterceptor * self = GUM_INTERCEPTOR (object);

  g_mutex_lock (&_gum_interceptor_lock);
  if (_the_interceptor == self)
    _the_interceptor = NULL;
  g_mutex_unlock (&_gum_interceptor_lock);

  gum_interceptor_do_dispose (self);
  gum_interceptor_do_finalize (self);
}

#endif

GumInterceptor *
gum_interceptor_obtain (void)
{
  GumInterceptor * interceptor;

  g_mutex_lock (&_gum_interceptor_lock);

#ifndef GUM_DIET
  if (_the_interceptor != NULL)
  {
    interceptor = GUM_INTERCEPTOR (g_object_ref (_the_interceptor));
  }
  else
  {
    _the_interceptor = g_object_new (GUM_TYPE_INTERCEPTOR, NULL);
    g_object_weak_ref (G_OBJECT (_the_interceptor),
        the_interceptor_weak_notify, NULL);

    interceptor = _the_interceptor;
  }
#else
  if (_the_interceptor != NULL)
  {
    interceptor = gum_object_ref (_the_interceptor);
  }
  else
  {
    _the_interceptor = g_new0 (GumInterceptor, 1);
    _the_interceptor->parent.ref_count = 1;
    _the_interceptor->parent.finalize = gum_interceptor_finalize;
    gum_interceptor_init (_the_interceptor);

    interceptor = _the_interceptor;
  }
#endif

  g_mutex_unlock (&_gum_interceptor_lock);

  return interceptor;
}

#ifndef GUM_DIET

static void
the_interceptor_weak_notify (gpointer data,
                             GObject * where_the_object_was)
{
  g_mutex_lock (&_gum_interceptor_lock);

  g_assert (_the_interceptor == (GumInterceptor *) where_the_object_was);
  _the_interceptor = NULL;

  g_mutex_unlock (&_gum_interceptor_lock);
}

#endif

GumAttachReturn
gum_interceptor_attach (GumInterceptor * self,
                        gpointer function_address,
                        GumInvocationListener * listener,
                        gpointer listener_function_data)
{
  GumAttachReturn result = GUM_ATTACH_OK;
  GumFunctionContext * function_ctx;
  GumInstrumentationError error;

  gum_interceptor_ignore_current_thread (self);
  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction);
  self->current_transaction.is_dirty = TRUE;

  function_address = gum_interceptor_resolve (self, function_address);

  function_ctx = gum_interceptor_instrument (self, GUM_INTERCEPTOR_TYPE_DEFAULT,
      function_address, &error);

  if (function_ctx == NULL)
    goto instrumentation_error;

  if (gum_function_context_has_listener (function_ctx, listener))
    goto already_attached;

  gum_function_context_add_listener (function_ctx, listener,
      listener_function_data);

  goto beach;

instrumentation_error:
  {
    switch (error)
    {
      case GUM_INSTRUMENTATION_ERROR_WRONG_SIGNATURE:
        result = GUM_ATTACH_WRONG_SIGNATURE;
        break;
      case GUM_INSTRUMENTATION_ERROR_POLICY_VIOLATION:
        result = GUM_ATTACH_POLICY_VIOLATION;
        break;
      case GUM_INSTRUMENTATION_ERROR_WRONG_TYPE:
        result = GUM_ATTACH_WRONG_TYPE;
        break;
      default:
        g_assert_not_reached ();
    }
    goto beach;
  }
already_attached:
  {
    result = GUM_ATTACH_ALREADY_ATTACHED;
    goto beach;
  }
beach:
  {
    gum_interceptor_transaction_end (&self->current_transaction);
    GUM_INTERCEPTOR_UNLOCK (self);
    gum_interceptor_unignore_current_thread (self);

    return result;
  }
}

void
gum_interceptor_detach (GumInterceptor * self,
                        GumInvocationListener * listener)
{
  GHashTableIter iter;
  gpointer key, value;

  gum_interceptor_ignore_current_thread (self);
  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction);
  self->current_transaction.is_dirty = TRUE;

  g_hash_table_iter_init (&iter, self->function_by_address);
  while (g_hash_table_iter_next (&iter, NULL, &value))
  {
    GumFunctionContext * function_ctx = value;

    if (gum_function_context_has_listener (function_ctx, listener))
    {
      gum_function_context_remove_listener (function_ctx, listener);

      gum_interceptor_transaction_schedule_destroy (&self->current_transaction,
          function_ctx,
#ifndef GUM_DIET
          g_object_unref, g_object_ref (listener)
#else
          gum_object_unref, gum_object_ref (listener)
#endif
      );

      if (gum_function_context_is_empty (function_ctx))
      {
        g_hash_table_iter_remove (&iter);
      }
    }
  }

  gum_spinlock_acquire (&gum_interceptor_thread_context_lock);
  g_hash_table_iter_init (&iter, gum_interceptor_thread_contexts);
  while (g_hash_table_iter_next (&iter, &key, NULL))
  {
    InterceptorThreadContext * thread_ctx = key;

    interceptor_thread_context_forget_listener_data (thread_ctx, listener);
  }
  gum_spinlock_release (&gum_interceptor_thread_context_lock);

  gum_interceptor_transaction_end (&self->current_transaction);
  GUM_INTERCEPTOR_UNLOCK (self);
  gum_interceptor_unignore_current_thread (self);
}

GumReplaceReturn
gum_interceptor_replace (GumInterceptor * self,
                         gpointer function_address,
                         gpointer replacement_function,
                         gpointer replacement_data,
                         gpointer * original_function)
{
  return gum_interceptor_replace_with_type (self, GUM_INTERCEPTOR_TYPE_DEFAULT,
      function_address, replacement_function, replacement_data,
      original_function);
}

GumReplaceReturn
gum_interceptor_replace_fast (GumInterceptor * self,
                              gpointer function_address,
                              gpointer replacement_function,
                              gpointer * original_function)
{
  return gum_interceptor_replace_with_type (self, GUM_INTERCEPTOR_TYPE_FAST,
      function_address, replacement_function, NULL,
      original_function);
}

static GumReplaceReturn
gum_interceptor_replace_with_type (GumInterceptor * self,
                                   GumInterceptorType type,
                                   gpointer function_address,
                                   gpointer replacement_function,
                                   gpointer replacement_data,
                                   gpointer * original_function)
{
  GumReplaceReturn result = GUM_REPLACE_OK;
  GumFunctionContext * function_ctx;
  GumInstrumentationError error;

  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction);
  self->current_transaction.is_dirty = TRUE;

  function_address = gum_interceptor_resolve (self, function_address);

  function_ctx =
      gum_interceptor_instrument (self, type, function_address, &error);

  if (function_ctx == NULL)
    goto instrumentation_error;

  if (function_ctx->replacement_function != NULL)
    goto already_replaced;

  function_ctx->replacement_data = replacement_data;
  function_ctx->replacement_function = replacement_function;

  if (original_function != NULL)
    *original_function = function_ctx->on_invoke_trampoline;

  goto beach;

instrumentation_error:
  {
    switch (error)
    {
      case GUM_INSTRUMENTATION_ERROR_WRONG_SIGNATURE:
        result = GUM_REPLACE_WRONG_SIGNATURE;
        break;
      case GUM_INSTRUMENTATION_ERROR_POLICY_VIOLATION:
        result = GUM_REPLACE_POLICY_VIOLATION;
        break;
      case GUM_INSTRUMENTATION_ERROR_WRONG_TYPE:
        result = GUM_REPLACE_WRONG_TYPE;
        break;
      default:
        g_assert_not_reached ();
    }
    goto beach;
  }
already_replaced:
  {
    result = GUM_REPLACE_ALREADY_REPLACED;
    goto beach;
  }
beach:
  {
    gum_interceptor_transaction_end (&self->current_transaction);
    GUM_INTERCEPTOR_UNLOCK (self);

    return result;
  }
}

void
gum_interceptor_revert (GumInterceptor * self,
                        gpointer function_address)
{
  GumFunctionContext * function_ctx;

  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction);
  self->current_transaction.is_dirty = TRUE;

  function_address = gum_interceptor_resolve (self, function_address);

  function_ctx = (GumFunctionContext *) g_hash_table_lookup (
      self->function_by_address, function_address);
  if (function_ctx == NULL)
    goto beach;

  function_ctx->replacement_function = NULL;
  function_ctx->replacement_data = NULL;

  if (gum_function_context_is_empty (function_ctx))
  {
    g_hash_table_remove (self->function_by_address, function_address);
  }

beach:
  gum_interceptor_transaction_end (&self->current_transaction);
  GUM_INTERCEPTOR_UNLOCK (self);
}

void
gum_interceptor_begin_transaction (GumInterceptor * self)
{
  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_begin (&self->current_transaction);
  GUM_INTERCEPTOR_UNLOCK (self);
}

void
gum_interceptor_end_transaction (GumInterceptor * self)
{
  GUM_INTERCEPTOR_LOCK (self);
  gum_interceptor_transaction_end (&self->current_transaction);
  GUM_INTERCEPTOR_UNLOCK (self);
}

gboolean
gum_interceptor_flush (GumInterceptor * self)
{
  gboolean flushed = FALSE;

  GUM_INTERCEPTOR_LOCK (self);

  if (self->current_transaction.level == 0)
  {
    gum_interceptor_transaction_begin (&self->current_transaction);
    gum_interceptor_transaction_end (&self->current_transaction);

    flushed =
        g_queue_is_empty (self->current_transaction.pending_destroy_tasks);
  }

  GUM_INTERCEPTOR_UNLOCK (self);

  return flushed;
}

GumInvocationContext *
gum_interceptor_get_current_invocation (void)
{
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStackEntry * entry;

  interceptor_ctx = get_interceptor_thread_context ();
  entry = gum_invocation_stack_peek_top (interceptor_ctx->stack);
  if (entry == NULL)
    return NULL;

  return &entry->invocation_context;
}

GumInvocationContext *
gum_interceptor_get_live_replacement_invocation (gpointer replacement_function)
{
  InterceptorThreadContext * interceptor_ctx;
  GumInvocationStackEntry * entry;

  interceptor_ctx = get_interceptor_thread_context ();
  entry = gum_invocation_stack_peek_top (interceptor_ctx->stack);
  if (entry == NULL)
    return NULL;
  if (!entry->calling_replacement)
    return NULL;
  if (replacement_function != entry->function_ctx->replacement_function)
    return NULL;

  return &entry->invocation_context;
}

GumInvocationStack *
gum_interceptor_get_current_stack (void)
{
  InterceptorThreadContext * context;

  context = g_private_get (&gum_interceptor_context_private);
  if (context == NULL)
    return &_gum_interceptor_empty_stack;

  return context->stack;
}

void
gum_interceptor_ignore_current_thread (GumInterceptor * self)
{
  InterceptorThreadContext * interceptor_ctx;

  interceptor_ctx = get_interceptor_thread_context ();
  interceptor_ctx->ignore_level++;
}

void
gum_interceptor_unignore_current_thread (GumInterceptor * self)
{
  InterceptorThreadContext * interceptor_ctx;

  interceptor_ctx = get_interceptor_thread_context ();
  interceptor_ctx->ignore_level--;
}

gboolean
gum_interceptor_maybe_unignore_current_thread (GumInterceptor * self)
{
  InterceptorThreadContext * interceptor_ctx;

  interceptor_ctx = get_interceptor_thread_context ();
  if (interceptor_ctx->ignore_level <= 0)
    return FALSE;

  interceptor_ctx->ignore_level--;
  return TRUE;
}

void
gum_interceptor_ignore_other_threads (GumInterceptor * self)
{
  self->selected_thread_id = gum_process_get_current_thread_id ();
}

void
gum_interceptor_unignore_other_threads (GumInterceptor * self)
{
  g_assert (self->selected_thread_id == gum_process_get_current_thread_id ());
  self->selected_thread_id = 0;
}

gpointer
gum_invocation_stack_translate (GumInvocationStack * self,
                                gpointer return_address)
{
  guint i;

  for (i = 0; i != self->len; i++)
  {
    GumInvocationStackEntry * entry;

    entry = &g_array_index (self, GumInvocationStackEntry, i);
    if (entry->function_ctx->on_leave_trampoline == return_address)
      return entry->caller_ret_addr;
  }

  return return_address;
}

void
gum_interceptor_save (GumInvocationState * state)
{
  *state = gum_interceptor_get_current_stack ()->len;
}

void
gum_interceptor_restore (GumInvocationState * state)
{
  GumInvocationStack * stack;
  guint old_depth, new_depth, i;

  stack = gum_interceptor_get_current_stack ();

  old_depth = *state;
  new_depth = stack->len;
  if (new_depth == old_depth)
    return;

  for (i = old_depth; i != new_depth; i++)
  {
    GumInvocationStackEntry * entry;

    entry = &g_array_index (stack, GumInvocationStackEntry, i);

    g_atomic_int_dec_and_test (&entry->function_ctx->trampoline_usage_counter);
  }

  g_array_set_size (stack, old_depth);
}

void
gum_interceptor_with_lock_held (GumInterceptor * self,
                                GumInterceptorLockedFunc func,
                                gpointer user_data)
{
  GUM_INTERCEPTOR_LOCK (self);
  func (user_data);
  GUM_INTERCEPTOR_UNLOCK (self);
}

gboolean
gum_interceptor_is_locked (GumInterceptor * self)
{
  if (!g_rec_mutex_trylock (&self->mutex))
    return TRUE;

  GUM_INTERCEPTOR_UNLOCK (self);
  return FALSE;
}

gpointer
_gum_interceptor_peek_top_caller_return_address (void)
{
  GumInvocationStack * stack;
  GumInvocationStackEntry * entry;

  stack = gum_interceptor_get_current_stack ();
  if (stack->len == 0)
    return NULL;

  entry = &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);

  return entry->caller_ret_addr;
}

gpointer
_gum_interceptor_translate_top_return_address (gpointer return_address)
{
  GumInvocationStack * stack;
  GumInvocationStackEntry * entry;

  stack = gum_interceptor_get_current_stack ();
  if (stack->len == 0)
    goto fallback;

  entry = &g_array_index (stack, GumInvocationStackEntry, stack->len - 1);
  if (entry->function_ctx->on_leave_trampoline != return_address)
    goto fallback;

  return entry->caller_ret_addr;

fallback:
  return return_address;
}

static GumFunctionContext *
gum_interceptor_instrument (GumInterceptor * self,
                            GumInterceptorType type,
                            gpointer function_address,
                            GumInstrumentationError * error)
{
  GumFunctionContext * ctx;

  *error = GUM_INSTRUMENTATION_ERROR_NONE;

  ctx = (GumFunctionContext *) g_hash_table_lookup (self->function_by_address,
      function_address);

  if (ctx != NULL)
  {
    if (ctx->type != type)
    {
      *error = GUM_INSTRUMENTATION_ERROR_WRONG_TYPE;
      return NULL;
    }
    return ctx;
  }

  if (self->backend == NULL)
  {
    self->backend =
        _gum_interceptor_backend_create (&self->mutex, &self->allocator);
  }

  ctx = gum_function_context_new (self, function_address, type);

  if (gum_process_get_code_signing_policy () == GUM_CODE_SIGNING_REQUIRED)
  {
    if (!_gum_interceptor_backend_claim_grafted_trampoline (self->backend, ctx))
      goto policy_violation;
  }
  else
  {
    if (!_gum_interceptor_backend_create_trampoline (self->backend, ctx))
      goto wrong_signature;
  }

  g_hash_table_insert (self->function_by_address, function_address, ctx);

  gum_interceptor_transaction_schedule_update (&self->current_transaction, ctx,
      gum_interceptor_activate);

  return ctx;

policy_violation:
  {
    *error = GUM_INSTRUMENTATION_ERROR_POLICY_VIOLATION;
    goto propagate_error;
  }
wrong_signature:
  {
    *error = GUM_INSTRUMENTATION_ERROR_WRONG_SIGNATURE;
    goto propagate_error;
  }
propagate_error:
  {
    gum_function_context_finalize (ctx);

    return NULL;
  }
}

static void
gum_interceptor_activate (GumInterceptor * self,
                          GumFunctionContext * ctx,
                          gpointer prologue)
{
  if (ctx->destroyed)
    return;

  g_assert (!ctx->activated);
  ctx->activated = TRUE;

  _gum_interceptor_backend_activate_trampoline (self->backend, ctx,
      prologue);
}

static void
gum_interceptor_deactivate (GumInterceptor * self,
                            GumFunctionContext * ctx,
                            gpointer prologue)
{
  GumInterceptorBackend * backend = self->backend;

  g_assert (ctx->activated);
  ctx->activated = FALSE;

  _gum_interceptor_backend_deactivate_trampoline (backend, ctx, prologue);
}

static void
gum_interceptor_transaction_init (GumInterceptorTransaction * transaction,
                                  GumInterceptor * interceptor)
{
  transaction->is_dirty = FALSE;
  transaction->level = 0;
  transaction->pending_destroy_tasks = g_queue_new ();
  transaction->pending_update_tasks = g_hash_table_new_full (
      NULL, NULL, NULL, (GDestroyNotify) g_array_unref);

  transaction->interceptor = interceptor;
}

static void
gum_interceptor_transaction_destroy (GumInterceptorTransaction * transaction)
{
  GumDestroyTask * task;

  g_hash_table_unref (transaction->pending_update_tasks);

  while ((task = g_queue_pop_head (transaction->pending_destroy_tasks)) != NULL)
  {
    task->notify (task->data);

    g_slice_free (GumDestroyTask, task);
  }
  g_queue_free (transaction->pending_destroy_tasks);
}

static void
gum_interceptor_transaction_begin (GumInterceptorTransaction * self)
{
  self->level++;
}

static void
gum_interceptor_transaction_end (GumInterceptorTransaction * self)
{
  GumInterceptor * interceptor = self->interceptor;
  GumInterceptorTransaction transaction_copy;
  GList * addresses, * cur;

  self->level--;
  if (self->level > 0)
    return;

  if (!self->is_dirty)
    return;

  gum_interceptor_ignore_current_thread (interceptor);

  gum_code_allocator_commit (&interceptor->allocator);

  if (g_queue_is_empty (self->pending_destroy_tasks) &&
      g_hash_table_size (self->pending_update_tasks) == 0)
  {
    interceptor->current_transaction.is_dirty = FALSE;
    goto no_changes;
  }

  transaction_copy = interceptor->current_transaction;
  self = &transaction_copy;
  gum_interceptor_transaction_init (&interceptor->current_transaction,
      interceptor);

  addresses = g_hash_table_get_keys (self->pending_update_tasks);
  addresses = g_list_sort (addresses, gum_page_address_compare);

  if (gum_process_get_code_signing_policy () == GUM_CODE_SIGNING_REQUIRED)
  {
    for (cur = addresses; cur != NULL; cur = cur->next)
    {
      gpointer target_page = cur->data;
      GArray * pending;
      guint i;

      pending = g_hash_table_lookup (self->pending_update_tasks, target_page);
      g_assert (pending != NULL);

      for (i = 0; i != pending->len; i++)
      {
        GumUpdateTask * update;

        update = &g_array_index (pending, GumUpdateTask, i);

        update->func (interceptor, update->ctx,
            _gum_interceptor_backend_get_function_address (update->ctx));
      }
    }
  }
  else
  {
    guint page_size;
    gboolean rwx_supported, code_segment_supported;

    page_size = gum_query_page_size ();

    rwx_supported = gum_query_is_rwx_supported ();
    code_segment_supported = gum_code_segment_is_supported ();

    if (rwx_supported || !code_segment_supported)
    {
      GumPageProtection protection;
      GumSuspendOperation suspend_op = { 0, G_QUEUE_INIT };

      protection = rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW;

      if (!rwx_supported)
      {
        suspend_op.current_thread_id = gum_process_get_current_thread_id ();
        _gum_process_enumerate_threads (gum_maybe_suspend_thread, &suspend_op);
      }

      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        gpointer target_page = cur->data;

        gum_mprotect (target_page, page_size, protection);
      }

      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        gpointer target_page = cur->data;
        GArray * pending;
        guint i;

        pending = g_hash_table_lookup (self->pending_update_tasks,
            target_page);
        g_assert (pending != NULL);

        for (i = 0; i != pending->len; i++)
        {
          GumUpdateTask * update;

          update = &g_array_index (pending, GumUpdateTask, i);

          update->func (interceptor, update->ctx,
              _gum_interceptor_backend_get_function_address (update->ctx));
        }
      }

      if (!rwx_supported)
      {
        /*
         * We don't bother restoring the protection on RWX systems, as we would
         * have to determine the old protection to be able to do so safely.
         *
         * While we could easily do that, it would add overhead, but it's not
         * really clear that it would have any tangible upsides.
         */
        for (cur = addresses; cur != NULL; cur = cur->next)
        {
          gpointer target_page = cur->data;

          gum_mprotect (target_page, page_size, GUM_PAGE_RX);
        }
      }

      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        gpointer target_page = cur->data;

        gum_clear_cache (target_page, page_size);
      }

      if (!rwx_supported)
      {
        gpointer raw_id;

        while (
            (raw_id = g_queue_pop_tail (&suspend_op.suspended_threads)) != NULL)
        {
          gum_thread_resume (GPOINTER_TO_SIZE (raw_id), NULL);
#ifdef HAVE_DARWIN
          mach_port_mod_refs (mach_task_self (), GPOINTER_TO_SIZE (raw_id),
              MACH_PORT_RIGHT_SEND, -1);
#endif
        }
      }
    }
    else
    {
      guint num_pages;
      GumCodeSegment * segment;
      guint8 * source_page, * current_page;
      gsize source_offset;

      num_pages = g_hash_table_size (self->pending_update_tasks);
      segment = gum_code_segment_new (num_pages * page_size, NULL);

      source_page = gum_code_segment_get_address (segment);

      current_page = source_page;
      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        guint8 * target_page = cur->data;

        memcpy (current_page, target_page, page_size);

        current_page += page_size;
      }

      for (cur = addresses; cur != NULL; cur = cur->next)
      {
        guint8 * target_page = cur->data;
        GArray * pending;
        guint i;

        pending = g_hash_table_lookup (self->pending_update_tasks,
            target_page);
        g_assert (pending != NULL);

        for (i = 0; i != pending->len; i++)
        {
          GumUpdateTask * update;

          update = &g_array_index (pending, GumUpdateTask, i);

          update->func (interceptor, update->ctx, source_page +
              ((guint8 *) _gum_interceptor_backend_get_function_address (
           
"""


```