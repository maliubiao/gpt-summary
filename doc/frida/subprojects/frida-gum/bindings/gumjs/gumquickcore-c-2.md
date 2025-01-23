Response:
Let's break down the thought process to analyze this C code snippet for Frida.

**1. Understanding the Goal:**

The core request is to understand the functionality of `gumquickcore.c` within the Frida context, specifically focusing on its relationship with reverse engineering, interaction with low-level systems (Linux, Android), logical inferences, common user errors, and debugging. The prompt emphasizes summarizing the functionality based on a provided code snippet.

**2. Initial Code Scan and Identification of Key Structures:**

The first step is to quickly scan the code and identify the primary functions and data structures. Keywords like `void`, `_gum_quick_core_`, `GumQuickCore`, `JSValue`, and `g_` (referencing GLib) are immediate clues. I notice functions like `_gum_quick_core_setup`, `_gum_quick_core_teardown`, `_gum_quick_core_pin`, `_gum_quick_core_post`, `_gum_quick_scope_enter`, `_gum_quick_scope_leave`, and many `GUMJS_DEFINE_FUNCTION` macros. These macros strongly suggest that this code is interfacing JavaScript with native C code.

**3. Deconstructing Function Categories:**

I mentally group the functions based on their apparent purpose:

* **Initialization/Teardown:**  `_gum_quick_core_setup`, `_gum_quick_core_teardown`, `_gum_quick_core_finalize`. These manage the lifecycle of the `GumQuickCore` object.
* **Reference Counting:** `_gum_quick_core_pin`, `_gum_quick_core_unpin`. These are for managing the lifetime of the core object.
* **Error Handling:** `_gum_quick_core_on_unhandled_exception`, `_gum_quick_scope_catch_and_emit`. These deal with JavaScript exceptions.
* **Message Passing:** `_gum_quick_core_post`. This seems to handle communication between the JavaScript and native sides.
* **Job Scheduling:** `_gum_quick_core_push_job`. This suggests asynchronous task execution.
* **Module Data Management:** `_gum_quick_core_store_module_data`, `_gum_quick_core_load_module_data`. This allows storing and retrieving data associated with modules.
* **Scope Management:** `_gum_quick_scope_enter`, `_gum_quick_scope_leave`, `_gum_quick_scope_suspend`, `_gum_quick_scope_resume`, `_gum_quick_scope_call`, `_gum_quick_scope_call_void`, `_gum_quick_scope_perform_pending_io`. These are critical for managing the execution context of JavaScript within the Frida environment, handling locking, and context switching.
* **JavaScript Function Bindings:**  The `GUMJS_DEFINE_FUNCTION` macros. These are the entry points from JavaScript into the native code, implementing features like `frida.heapSize`, `frida.objc.load`, `send`, `setTimeout`, etc.
* **Weak References:** Functions involving `weak_map`, `weak_ref`, and callbacks. These are for managing object lifetimes and preventing memory leaks.
* **Global Access Handling:** `gumjs_script_set_global_access_handler`, `gum_quick_core_on_global_get`. This allows intercepting and customizing global variable access in JavaScript.
* **Int64/UInt64/Native Pointer Handling:**  Functions with prefixes like `gumjs_int64_`, `gumjs_uint64_`, `gumjs_native_pointer_`. These provide ways to work with 64-bit integers and raw memory addresses within the JavaScript environment.

**4. Connecting to Reverse Engineering Concepts:**

With the function categories in mind, I start to connect them to reverse engineering concepts:

* **Dynamic Instrumentation:** The entire file is part of Frida, a *dynamic* instrumentation framework. The ability to execute JavaScript within a running process is central to this.
* **Interception/Hooking:**  The mention of `gum_interceptor` in the scope functions is a direct link to Frida's core capability to intercept function calls.
* **Memory Inspection:** The `gumjs_frida_get_heap_size` function and the handling of native pointers are related to inspecting the target process's memory.
* **Code Injection:**  The `gumjs_script_evaluate` and `gumjs_script_load` functions are the mechanisms for injecting and executing JavaScript code.
* **API Hooking (ObjC, Swift, Java):** The `gumjs_frida_objc_load`, `gumjs_frida_swift_load`, and `gumjs_frida_java_load` functions directly relate to hooking into runtime environments of these languages.
* **Weak References:** Crucial for avoiding memory leaks when hooking objects, ensuring that your hooks don't keep objects alive indefinitely.

**5. Connecting to Low-Level Concepts:**

* **Threading and Synchronization:** The use of `g_mutex`, `g_cond`, `g_rec_mutex`, `gum_process_get_current_thread_id` highlights the need to manage concurrency when injecting code into multi-threaded processes.
* **Event Loops:** The `g_main_loop` and related functions are essential for managing asynchronous operations and integrating with the target process's event handling.
* **Memory Management:**  Functions using `g_slice_new`, `g_slice_free`, `g_strdup`, `g_free`, and `GBytes` are directly related to memory allocation and deallocation.
* **Kernel Interaction (Implicit):** While not directly calling kernel functions here, the ability to intercept function calls and inspect memory implies underlying mechanisms that interact with the operating system kernel. On Android, this involves the Android runtime (ART) and the underlying Linux kernel.
* **Framework Interaction (Android):** The Java bridge functions (`gumjs_frida_java_load`) are specifically for interacting with the Android framework.

**6. Logical Inferences (Hypothetical Inputs and Outputs):**

For the logical inferences, I consider specific functions:

* **`_gum_quick_core_post`:** *Input:* a message string and data (GBytes). *Output:*  If a message sink is registered, the message is delivered, `event_count` increments, and the event loop is quit. If no sink, the data is freed.
* **`gumjs_script_evaluate`:** *Input:* a script name and source code. *Output:* If the code parses, it's evaluated and the result is returned. If there's a parse error, an exception is thrown with source map decorations.
* **`gumjs_set_timeout`:** *Input:* a function and a delay. *Output:*  A timer is scheduled, and an ID is returned. The function will be called after the delay.

**7. Common User Errors:**

I think about common mistakes users make when using Frida:

* **Incorrect Argument Types:** The `_gum_quick_args_parse` function suggests that passing the wrong data types to JavaScript functions will cause errors.
* **Memory Leaks:**  Not properly unbinding weak references or managing allocated memory in native modules could lead to leaks.
* **Concurrency Issues:**  If users don't understand the threading model, they might introduce race conditions when interacting with shared data.
* **Incorrect Usage of `setTimeout`/`setInterval`:**  Forgetting to `clearTimeout`/`clearInterval` can lead to unintended repeated execution of code.
* **Uncaught Exceptions:** Not handling exceptions in JavaScript callbacks will lead to the `unhandled_exception_sink` being invoked.

**8. Debugging Clues (How to Reach This Code):**

I consider how a user's actions in Frida might lead to the execution of this code:

* **Attaching to a process:**  When Frida attaches, it initializes the JavaScript environment, likely calling `_gum_quick_core_setup`.
* **Injecting JavaScript:**  Using `session.create_script()` and then calling `script.load()` or `script.evaluate()` will execute the `gumjs_script_load` or `gumjs_script_evaluate` functions.
* **Using `send()` from JavaScript:**  This directly calls `gumjs_send`.
* **Setting up hooks (using `Interceptor`, `ObjC.API`, etc.):**  These higher-level APIs eventually rely on the underlying mechanisms in this file for managing the JavaScript environment and communicating with the native side.
* **Using `setTimeout` or `setInterval`:** These JavaScript functions are directly implemented here.
* **Observing memory usage (if `frida.heapSize` is used):** This calls the corresponding function in this file.
* **Receiving messages from the injected script:** The message handling logic in this file comes into play.

**9. Summarization (Instruction #6):**

Finally, I synthesize the information to provide a concise summary of the file's functionality, focusing on its role as the core of the JavaScript execution environment within Frida.

By following these steps, I can systematically analyze the code snippet and address all the points raised in the prompt, even without deep prior knowledge of every single function. The key is to identify patterns, understand the overall context of Frida, and make logical connections.
This code snippet represents a portion of `gumquickcore.c`, a core file within Frida's GumJS binding. It focuses on the lifecycle management, execution context, and some key functionalities of the JavaScript engine embedded within Frida. Let's break down its functions according to your request:

**Functionalities Illustrated in this Snippet:**

1. **Initialization and Teardown of the JavaScript Core:**
   - `_gum_quick_core_setup()`:  Initializes various components of the JavaScript engine, including:
     - Setting up the QuickJS runtime (`rt`) and context (`ctx`).
     - Creating global objects and prototypes (like `Int64`, `UInt64`, `NativePointer`).
     - Initializing data structures like hash tables for subclasses, workers, scheduled callbacks, and module data.
     - Setting up weak reference management (`WeakMap`).
   - `_gum_quick_core_teardown()`:  Releases resources allocated during setup, like freeing JS values and tearing down atoms.
   - `_gum_quick_core_finalize()`:  Releases higher-level resources like hash tables and the event loop.

2. **Reference Counting:**
   - `_gum_quick_core_pin()`: Increments a usage counter, indicating that the `GumQuickCore` is being used.
   - `_gum_quick_core_unpin()`: Decrements the usage counter. This mechanism is likely used to manage the lifetime of the `GumQuickCore` instance.

3. **Handling Unhandled JavaScript Exceptions:**
   - `_gum_quick_core_on_unhandled_exception()`:  Receives a JavaScript exception and, if an `unhandled_exception_sink` is registered, passes the exception to it for processing (likely reporting back to the Frida client).

4. **Posting Messages from Native to JavaScript:**
   - `_gum_quick_core_post()`:  Sends a message and optional data from the native side to the JavaScript side.
     - It acquires a scope using `_gum_quick_scope_enter`.
     - If an `incoming_message_sink` is registered, it uses it to deliver the message.
     - It signals the event loop to wake up, allowing the JavaScript side to process the message.

5. **Scheduling Jobs on a Thread Pool:**
   - `_gum_quick_core_push_job()`:  Adds a function (`job_func`) and its associated data to a thread pool for asynchronous execution.

6. **Managing Module Data:**
   - `_gum_quick_core_store_module_data()`: Stores data associated with a specific module using a key-value pair in a hash table.
   - `_gum_quick_core_load_module_data()`: Retrieves data associated with a module using its key.

7. **Managing JavaScript Execution Scope:**
   - `_gum_quick_scope_enter()`:  Enters a new JavaScript execution scope. This is crucial for managing the context in which JavaScript code runs.
     - It can begin an interceptor transaction (if an interceptor is present).
     - It acquires a mutex to ensure thread safety.
     - It enters the QuickJS runtime.
     - It initializes queues for tick callbacks and scheduled sources.
   - `_gum_quick_scope_suspend()`:  Suspends the current JavaScript execution scope, saving its state. This is likely used when moving execution to a different thread or waiting for events.
   - `_gum_quick_scope_resume()`: Resumes a previously suspended JavaScript execution scope.
   - `_gum_quick_scope_call()`:  Calls a JavaScript function within the current scope. It handles potential exceptions thrown by the JavaScript code.
   - `_gum_quick_scope_call_void()`: Calls a JavaScript function and discards the result.
   - `_gum_quick_scope_catch_and_emit()`:  Catches a JavaScript exception and passes it to the unhandled exception handler.
   - `_gum_quick_scope_perform_pending_io()`: Executes pending JavaScript jobs and callbacks (like `nextTick` and scheduled sources).
   - `_gum_quick_scope_leave()`:  Leaves the current JavaScript execution scope.
     - It performs pending I/O.
     - It leaves the QuickJS runtime.
     - It releases the mutex.
     - It can trigger a flush notification if needed.
     - It processes pending stalker operations.

8. **Exposing Native Functionality to JavaScript (using `GUMJS_DEFINE_*` macros):**
   - `GUMJS_DEFINE_GETTER(gumjs_frida_get_heap_size)`:  Exposes a getter for the current heap size to JavaScript.
   - `GUMJS_DEFINE_FUNCTION(gumjs_frida_objc_load)`, `gumjs_frida_swift_load`, `gumjs_frida_java_load`: Expose functions to load the respective bridge modules (for interacting with Objective-C, Swift, and Java).
   - `GUMJS_DEFINE_FUNCTION(gumjs_script_evaluate)`:  Allows evaluating a string of JavaScript code.
   - `GUMJS_DEFINE_FUNCTION(gumjs_script_load)`:  Allows loading a JavaScript module.
   - `GUMJS_DEFINE_FUNCTION(gumjs_script_register_source_map)`, `gumjs_script_find_source_map`:  Deal with source map management for debugging.
   - `GUMJS_DEFINE_FUNCTION(gumjs_script_next_tick)`:  Implements `process.nextTick` functionality.
   - `GUMJS_DEFINE_FUNCTION(gumjs_script_pin)`, `gumjs_script_unpin`: Likely relate to keeping the script environment alive.
   - `GUMJS_DEFINE_FUNCTION(gumjs_script_bind_weak)`, `gumjs_script_unbind_weak`, `gumjs_script_deref_weak`:  Implement weak reference management in JavaScript, allowing callbacks when objects are garbage collected.
   - `GUMJS_DEFINE_FINALIZER(gumjs_weak_ref_finalize)`:  A finalizer for weak reference objects, triggered during garbage collection.
   - `GUMJS_DEFINE_FUNCTION(gumjs_script_set_global_access_handler)`: Allows intercepting access to global variables in JavaScript.
   - `GUMJS_DEFINE_FUNCTION(gumjs_set_timeout)`, `gumjs_set_interval`, `gumjs_clear_timer`: Implement the standard timer functions.
   - `GUMJS_DEFINE_FUNCTION(gumjs_gc)`:  Allows triggering garbage collection manually.
   - `GUMJS_DEFINE_FUNCTION(gumjs_send)`:  Provides a mechanism for sending messages from JavaScript back to the Frida client.
   - `GUMJS_DEFINE_FUNCTION(gumjs_set_unhandled_exception_callback)`, `gumjs_set_incoming_message_callback`:  Allow JavaScript to register handlers for unhandled exceptions and incoming messages.
   - `GUMJS_DEFINE_FUNCTION(gumjs_wait_for_event)`:  Allows JavaScript to wait for events posted from the native side.
   - `GUMJS_DEFINE_CONSTRUCTOR(gumjs_int64_construct)`, `GUMJS_DEFINE_FINALIZER(gumjs_int64_finalize)`, and related `GUMJS_DEFINE_FUNCTION` for arithmetic and comparison operations: Implement the `Int64` object in JavaScript for handling 64-bit integers. Similar patterns exist for `UInt64` and `NativePointer`.

**Relationship with Reverse Engineering:**

This code is fundamental to Frida's ability to perform dynamic instrumentation, a key technique in reverse engineering.

* **Code Injection and Execution:** Functions like `gumjs_script_evaluate` and `gumjs_script_load` are the primary ways Frida injects and executes JavaScript code within the target process. This allows reverse engineers to add their own logic and inspect the application's behavior at runtime.
* **API Hooking:** The interaction with `gum_interceptor` within the scope management functions, and the `gumjs_frida_*_load` functions for specific platforms (ObjC, Swift, Java), are directly related to Frida's ability to hook and intercept API calls. This is crucial for understanding how an application uses system libraries and frameworks.
* **Memory Inspection and Manipulation:**  The `gumjs_frida_get_heap_size` function and the `NativePointer` object expose the target process's memory to JavaScript. This allows reverse engineers to inspect memory contents, read variables, and even modify data.
* **Dynamic Analysis:** The ability to set timers (`gumjs_set_timeout`, `gumjs_set_interval`), send messages (`gumjs_send`), and wait for events (`gumjs_wait_for_event`) allows for complex dynamic analysis scenarios, where the reverse engineer can interact with the target application's execution flow.
* **Weak References:** In reverse engineering, when hooking objects, it's important to avoid memory leaks. The weak reference mechanism ensures that Frida's hooks don't unintentionally keep objects alive, which is a common concern in dynamic instrumentation.

**Examples Related to Reverse Engineering:**

* **Hooking a Function:** A reverse engineer might use JavaScript code that, behind the scenes, utilizes the `gum_interceptor` (through Frida's `Interceptor` API) within a `GumQuickScope`. When the hooked function is called in the target process, the execution will enter a `GumQuickScope`, potentially triggering `gum_interceptor_begin_transaction` and `gum_interceptor_end_transaction`.
* **Reading Memory:** A reverse engineer could use `NativePointer(address).readU32()` in JavaScript. This interacts with the underlying `GumQuickNativePointer` object and the native code that allows reading memory at a given address.
* **Tracing API Calls:** By hooking functions using Frida's JavaScript API, the reverse engineer can log arguments and return values. This involves the JavaScript code interacting with the native interception mechanisms managed within `gumquickcore.c`.

**Binary Bottom, Linux, Android Kernel & Framework Knowledge:**

* **Binary Bottom:** This code deals with the low-level representation of data, such as 64-bit integers (`Int64`, `UInt64`) and raw memory addresses (`NativePointer`). It needs to correctly handle the binary representation of these types.
* **Linux:** The use of GLib primitives (like `g_hash_table`, `g_mutex`, `g_cond`, `g_main_loop`) indicates reliance on Linux-specific libraries for threading, synchronization, and event handling.
* **Android Kernel & Framework:**
    - The `gumjs_frida_java_load` function is specifically designed to interact with the Android runtime (ART) and the Java framework. This likely involves JNI (Java Native Interface) calls under the hood.
    - Concepts like thread IDs (`gum_process_get_current_thread_id()`) are relevant to understanding process and thread management in Linux and Android.
    - The event loop (`g_main_loop`) is a common pattern in GUI frameworks and event-driven systems, including Android's main looper.

**Logical Inference (Hypothetical Input and Output):**

Let's take the `_gum_quick_core_post` function:

* **Hypothetical Input:**
    - `message`: "my_event"
    - `data`: A `GBytes` object containing the binary representation of the integer `123`.
* **Logical Output:**
    - If an `incoming_message_sink` is registered on the JavaScript side (e.g., using `recv()` in Frida's Python API), that sink's callback function will be invoked with the message "my_event" and the data (which JavaScript can then interpret to get the integer 123).
    - The `event_count` within `GumQuickCore` will be incremented.
    - The event loop will be signaled, potentially waking up a waiting JavaScript thread.

**User or Programming Common Usage Errors:**

* **Incorrect Argument Types in JavaScript:** If a user calls a JavaScript function exposed by Frida (like those defined with `GUMJS_DEFINE_FUNCTION`) with arguments of the wrong type, the `_gum_quick_args_parse` macro will likely fail, leading to a JavaScript exception. For example, calling `send(123)` instead of `send("message")`.
* **Memory Leaks with Weak References:** If a user uses `bindWeak` to create a weak reference but forgets to `unbindWeak` when it's no longer needed, the associated callback might still be held, potentially causing unexpected behavior or memory leaks if the callback holds onto other resources.
* **Concurrency Issues:** If a user's Frida script spawns its own threads and interacts with Frida's APIs without proper synchronization, it could lead to race conditions and unpredictable results, especially when interacting with shared resources managed by `GumQuickCore`.

**User Operations to Reach This Code (Debugging Clues):**

1. **Attaching to a Process:** When a Frida client attaches to a process, the Frida agent is loaded, and the `GumQuickCore` is initialized using `_gum_quick_core_setup`.
2. **Creating a Script:** When a user creates a Frida script (e.g., using `session.create_script()` in Python), this will eventually lead to the creation of a JavaScript context managed by `GumQuickCore`.
3. **Loading or Evaluating JavaScript Code:** When `script.load()` or `script.evaluate()` is called, the corresponding `gumjs_script_load` or `gumjs_script_evaluate` functions in this file are executed to run the provided JavaScript code within the `GumQuickCore`'s context.
4. **Using `send()` in JavaScript:** When the JavaScript code calls the `send()` function, it directly invokes the `gumjs_send` function in this file, which then uses `_gum_quick_core_post` to send the message back to the client.
5. **Setting Hooks:** Using Frida's `Interceptor` or platform-specific APIs like `ObjC.API.implementationFor` will involve the scope management functions (`_gum_quick_scope_enter`, `_gum_quick_scope_leave`) to manage the execution context during hook execution.
6. **Using Timers:** Calling `setTimeout` or `setInterval` in the injected JavaScript will directly use the `gumjs_set_timeout` and `gumjs_set_interval` implementations in this file, which schedule callbacks using the underlying event loop.
7. **Observing Heap Size:** If a user executes `frida.heapSize` in their JavaScript code, it will call the `gumjs_frida_get_heap_size` function defined here.

**Summary of Functionality (Part 3 of 6):**

This specific snippet of `gumquickcore.c` primarily focuses on:

- **Lifecycle management of the core JavaScript environment within Frida**, including initialization, teardown, and reference counting.
- **Providing the fundamental mechanisms for executing JavaScript code**, managing execution scopes, and handling exceptions.
- **Exposing key native functionalities to JavaScript**, such as interacting with platform-specific bridges (ObjC, Swift, Java), managing memory (heap size, native pointers), and sending/receiving messages.
- **Implementing essential JavaScript features** like timers, weak references, and global variable access interception.

Essentially, this section of `gumquickcore.c` lays the groundwork for Frida's dynamic instrumentation capabilities by providing the environment and tools necessary for executing and interacting with JavaScript code within a target process. It bridges the gap between the native world of the target application and the dynamic analysis capabilities offered by Frida's JavaScript API.

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickcore.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共6部分，请归纳一下它的功能
```

### 源代码
```c
= JS_NULL;
  self->weak_map_ctor = JS_NULL;
  self->weak_map_get_method = JS_NULL;
  self->weak_map_set_method = JS_NULL;
  self->weak_map_delete_method = JS_NULL;

  gum_quick_core_teardown_atoms (self);
}

void
_gum_quick_core_finalize (GumQuickCore * self)
{
  g_hash_table_unref (self->subclasses);
  self->subclasses = NULL;

  g_hash_table_unref (self->workers);
  self->workers = NULL;

  g_hash_table_unref (self->scheduled_callbacks);
  self->scheduled_callbacks = NULL;

  g_hash_table_unref (self->weak_callbacks);
  self->weak_callbacks = NULL;

  g_main_loop_unref (self->event_loop);
  self->event_loop = NULL;
  g_mutex_clear (&self->event_mutex);
  g_cond_clear (&self->event_cond);

  g_assert (self->current_scope == NULL);
  self->ctx = NULL;

  g_hash_table_unref (self->module_data);
  self->module_data = NULL;
}

void
_gum_quick_core_pin (GumQuickCore * self)
{
  self->usage_count++;
}

void
_gum_quick_core_unpin (GumQuickCore * self)
{
  self->usage_count--;
}

void
_gum_quick_core_on_unhandled_exception (GumQuickCore * self,
                                        JSValue exception)
{
  if (self->unhandled_exception_sink == NULL)
    return;

  gum_quick_exception_sink_handle_exception (self->unhandled_exception_sink,
      exception);
}

void
_gum_quick_core_post (GumQuickCore * self,
                      const gchar * message,
                      GBytes * data)
{
  gboolean delivered = FALSE;
  GumQuickScope scope;

  _gum_quick_scope_enter (&scope, self);

  if (self->incoming_message_sink != NULL)
  {
    gum_quick_message_sink_post (self->incoming_message_sink, message, data,
        &scope);
    delivered = TRUE;
  }

  _gum_quick_scope_leave (&scope);

  if (delivered)
  {
    g_mutex_lock (&self->event_mutex);
    self->event_count++;
    g_cond_broadcast (&self->event_cond);
    g_mutex_unlock (&self->event_mutex);

    g_main_loop_quit (self->event_loop);
  }
  else
  {
    g_bytes_unref (data);
  }
}

void
_gum_quick_core_push_job (GumQuickCore * self,
                          GumScriptJobFunc job_func,
                          gpointer data,
                          GDestroyNotify data_destroy)
{
  gum_script_scheduler_push_job_on_thread_pool (self->scheduler, job_func,
      data, data_destroy);
}

void
_gum_quick_core_store_module_data (GumQuickCore * self,
                                   const gchar * key,
                                   gpointer value)
{
  g_hash_table_insert (self->module_data, g_strdup (key), value);
}

gpointer
_gum_quick_core_load_module_data (GumQuickCore * self,
                                  const gchar * key)
{
  return g_hash_table_lookup (self->module_data, key);
}

void
_gum_quick_scope_enter (GumQuickScope * self,
                        GumQuickCore * core)
{
  self->core = core;

  if (core->interceptor != NULL)
    gum_interceptor_begin_transaction (core->interceptor->interceptor);

  g_rec_mutex_lock (core->mutex);

  _gum_quick_core_pin (core);
  core->mutex_depth++;

  if (core->mutex_depth == 1)
  {
    g_assert (core->current_scope == NULL);
    core->current_scope = self;
    core->current_owner = gum_process_get_current_thread_id ();

    JS_Enter (core->rt);
  }

  g_queue_init (&self->tick_callbacks);
  g_queue_init (&self->scheduled_sources);

  self->pending_stalker_level = 0;
  self->pending_stalker_transformer = NULL;
  self->pending_stalker_sink = NULL;
}

void
_gum_quick_scope_suspend (GumQuickScope * self)
{
  GumQuickCore * core = self->core;
  guint i;

  JS_Suspend (core->rt, &self->thread_state);

  g_assert (core->current_scope != NULL);
  self->previous_scope = g_steal_pointer (&core->current_scope);
  self->previous_owner = core->current_owner;
  core->current_owner = GUM_THREAD_ID_INVALID;

  self->previous_mutex_depth = core->mutex_depth;
  core->mutex_depth = 0;

  for (i = 0; i != self->previous_mutex_depth; i++)
    g_rec_mutex_unlock (core->mutex);

  if (core->interceptor != NULL)
    gum_interceptor_end_transaction (core->interceptor->interceptor);
}

void
_gum_quick_scope_resume (GumQuickScope * self)
{
  GumQuickCore * core = self->core;
  guint i;

  if (core->interceptor != NULL)
    gum_interceptor_begin_transaction (core->interceptor->interceptor);

  for (i = 0; i != self->previous_mutex_depth; i++)
    g_rec_mutex_lock (core->mutex);

  g_assert (core->current_scope == NULL);
  core->current_scope = g_steal_pointer (&self->previous_scope);
  core->current_owner = self->previous_owner;

  core->mutex_depth = self->previous_mutex_depth;
  self->previous_mutex_depth = 0;

  JS_Resume (core->rt, &self->thread_state);
}

JSValue
_gum_quick_scope_call (GumQuickScope * self,
                       JSValueConst func_obj,
                       JSValueConst this_obj,
                       int argc,
                       JSValueConst * argv)
{
  JSValue result;
  GumQuickCore * core = self->core;
  JSContext * ctx = core->ctx;

  result = JS_Call (ctx, func_obj, this_obj, argc, argv);

  if (JS_IsException (result))
    _gum_quick_scope_catch_and_emit (self);

  return result;
}

gboolean
_gum_quick_scope_call_void (GumQuickScope * self,
                            JSValueConst func_obj,
                            JSValueConst this_obj,
                            int argc,
                            JSValueConst * argv)
{
  JSValue result;

  result = _gum_quick_scope_call (self, func_obj, this_obj, argc, argv);
  if (JS_IsException (result))
    return FALSE;

  JS_FreeValue (self->core->ctx, result);

  return TRUE;
}

void
_gum_quick_scope_catch_and_emit (GumQuickScope * self)
{
  GumQuickCore * core = self->core;
  JSContext * ctx = core->ctx;
  JSValue exception;

  exception = JS_GetException (ctx);
  if (JS_IsNull (exception))
    return;

  _gum_quick_core_on_unhandled_exception (core, exception);

  JS_FreeValue (ctx, exception);
}

void
_gum_quick_scope_perform_pending_io (GumQuickScope * self)
{
  GumQuickCore * core = self->core;
  JSContext * ctx = core->ctx;
  gboolean io_performed;

  do
  {
    JSContext * pctx;
    JSValue * tick_callback;
    GSource * source;

    io_performed = FALSE;

    do
    {
      int res = JS_ExecutePendingJob (core->rt, &pctx);
      if (res == -1)
        _gum_quick_scope_catch_and_emit (self);
    }
    while (pctx != NULL);

    while ((tick_callback = g_queue_pop_head (&self->tick_callbacks)) != NULL)
    {
      _gum_quick_scope_call_void (self, *tick_callback, JS_UNDEFINED, 0, NULL);

      JS_FreeValue (ctx, *tick_callback);
      g_slice_free (JSValue, tick_callback);

      io_performed = TRUE;
    }

    while ((source = g_queue_pop_head (&self->scheduled_sources)) != NULL)
    {
      if (!g_source_is_destroyed (source))
      {
        g_source_attach (source,
            gum_script_scheduler_get_js_context (core->scheduler));
      }

      g_source_unref (source);

      io_performed = TRUE;
    }
  }
  while (io_performed);
}

void
_gum_quick_scope_leave (GumQuickScope * self)
{
  GumQuickCore * core = self->core;
  GumQuickFlushNotify flush_notify = NULL;
  gpointer flush_data = NULL;
  GDestroyNotify flush_data_destroy = NULL;

  _gum_quick_scope_perform_pending_io (self);

  if (core->mutex_depth == 1)
  {
    JS_Leave (core->rt);

    core->current_scope = NULL;
    core->current_owner = GUM_THREAD_ID_INVALID;
  }

  core->mutex_depth--;
  _gum_quick_core_unpin (core);

  if (core->flush_notify != NULL && core->usage_count == 0)
  {
    flush_notify = g_steal_pointer (&core->flush_notify);
    flush_data = g_steal_pointer (&core->flush_data);
    flush_data_destroy = g_steal_pointer (&core->flush_data_destroy);
  }

  g_rec_mutex_unlock (core->mutex);

  if (self->core->interceptor != NULL)
    gum_interceptor_end_transaction (self->core->interceptor->interceptor);

  if (flush_notify != NULL)
  {
    gum_quick_core_notify_flushed (core, flush_notify, flush_data,
        flush_data_destroy);
  }

  _gum_quick_stalker_process_pending (core->stalker, self);
}

GUMJS_DEFINE_GETTER (gumjs_frida_get_heap_size)
{
  return JS_NewUint32 (ctx, gum_peek_private_memory_usage ());
}

GUMJS_DEFINE_FUNCTION (gumjs_frida_objc_load)
{
  JSValue loaded = JS_FALSE;

#ifdef HAVE_OBJC_BRIDGE
  gum_quick_bundle_load (gumjs_objc_modules, ctx);
  loaded = JS_TRUE;
#endif

  return loaded;
}

GUMJS_DEFINE_FUNCTION (gumjs_frida_swift_load)
{
  JSValue loaded = JS_FALSE;

#ifdef HAVE_SWIFT_BRIDGE
  gum_quick_bundle_load (gumjs_swift_modules, ctx);
  loaded = JS_TRUE;
#endif

  return loaded;
}

GUMJS_DEFINE_FUNCTION (gumjs_frida_java_load)
{
  JSValue loaded = JS_FALSE;

#ifdef HAVE_JAVA_BRIDGE
  gum_quick_bundle_load (gumjs_java_modules, ctx);
  loaded = JS_TRUE;
#endif

  return loaded;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_evaluate)
{
  const gchar * name, * source;
  JSValue func;
  gchar * source_map;

  if (!_gum_quick_args_parse (args, "ss", &name, &source))
    return JS_EXCEPTION;

  func = JS_Eval (ctx, source, strlen (source), name,
      JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_STRICT | JS_EVAL_FLAG_COMPILE_ONLY |
      JS_EVAL_FLAG_BACKTRACE_BARRIER);
  if (JS_IsException (func))
  {
    return _gum_quick_script_rethrow_parse_error_with_decorations (core->script,
        ctx, name);
  }

  source_map = gum_script_backend_extract_inline_source_map (source);
  if (source_map != NULL)
  {
    gchar * map_name = g_strconcat (name, ".map", NULL);
    g_hash_table_insert (core->program->es_assets, map_name,
        gum_es_asset_new_take (map_name, source_map, strlen (source_map)));
  }

  return JS_EvalFunction (ctx, func);
}

GUMJS_DEFINE_FUNCTION (gumjs_script_load)
{
  GHashTable * es_assets = core->program->es_assets;
  const gchar * name, * source;
  JSValue perform_init, module;
  gchar * name_copy, * source_map;
  GumQuickModuleInitOperation * op;
  GSource * gsource;

  if (!_gum_quick_args_parse (args, "ssF", &name, &source, &perform_init))
    return JS_EXCEPTION;

  if (g_hash_table_contains (es_assets, name))
    return _gum_quick_throw (ctx, "module '%s' already exists", name);

  module = JS_Eval (ctx, source, strlen (source), name,
      JS_EVAL_TYPE_MODULE | JS_EVAL_FLAG_STRICT | JS_EVAL_FLAG_COMPILE_ONLY |
      JS_EVAL_FLAG_BACKTRACE_BARRIER);
  if (JS_IsException (module))
  {
    return _gum_quick_script_rethrow_parse_error_with_decorations (core->script,
        ctx, name);
  }

  name_copy = g_strdup (name);
  g_hash_table_insert (es_assets, name_copy,
      gum_es_asset_new_take (name_copy, NULL, 0));

  source_map = gum_script_backend_extract_inline_source_map (source);
  if (source_map != NULL)
  {
    gchar * map_name = g_strconcat (name, ".map", NULL);
    g_hash_table_insert (es_assets, map_name,
        gum_es_asset_new_take (map_name, source_map, strlen (source_map)));
  }

  /*
   * QuickJS does not support having a synchronously evaluating module
   * dynamically define and evaluate a new module depending on itself.
   * This is only allowed if it is an asynchronously evaluating module.
   * We defer the evaluation to avoid this edge-case.
   */
  op = g_slice_new (GumQuickModuleInitOperation);
  op->module = module;
  op->perform_init = JS_DupValue (ctx, perform_init);
  op->core = core;

  gsource = g_idle_source_new ();
  g_source_set_callback (gsource, (GSourceFunc) gum_quick_core_init_module,
      op, NULL);
  g_source_attach (gsource,
      gum_script_scheduler_get_js_context (core->scheduler));
  g_source_unref (gsource);

  _gum_quick_core_pin (core);

  return JS_UNDEFINED;
}

static gboolean
gum_quick_core_init_module (GumQuickModuleInitOperation * op)
{
  GumQuickCore * self = op->core;
  JSContext * ctx = self->ctx;
  GumQuickScope scope;
  JSValue result;

  _gum_quick_scope_enter (&scope, self);

  result = JS_EvalFunction (ctx, op->module);
  _gum_quick_scope_call_void (&scope, op->perform_init, JS_UNDEFINED,
      1, &result);
  JS_FreeValue (ctx, result);

  JS_FreeValue (ctx, op->perform_init);
  g_slice_free (GumQuickModuleInitOperation, op);

  _gum_quick_core_unpin (self);

  _gum_quick_scope_leave (&scope);

  return G_SOURCE_REMOVE;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_register_source_map)
{
  const gchar * name, * json;
  gchar * map_name;

  if (!_gum_quick_args_parse (args, "ss", &name, &json))
    return JS_EXCEPTION;

  map_name = g_strconcat (name, ".map", NULL);
  g_hash_table_insert (core->program->es_assets, map_name,
      gum_es_asset_new_take (map_name, g_strdup (json), strlen (json)));

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_find_source_map)
{
  GumESProgram * program = core->program;
  JSValue map = JS_NULL;
  const gchar * name, * json;

  if (!_gum_quick_args_parse (args, "s", &name))
    return JS_EXCEPTION;

  json = NULL;

  if (program->es_assets != NULL)
  {
    gchar * map_name;
    GumESAsset * map_asset;

    map_name = g_strconcat (name, ".map", NULL);

    map_asset = g_hash_table_lookup (program->es_assets, map_name);
    if (map_asset != NULL)
    {
      json = map_asset->data;
    }

    g_free (map_name);
  }

  if (json == NULL)
  {
    if (g_strcmp0 (name, program->global_filename) == 0)
    {
      json = program->global_source_map;
    }
    else if (strcmp (name, "/_frida.js") == 0)
    {
      json = core->runtime_source_map;
    }
#ifdef HAVE_OBJC_BRIDGE
    else if (strcmp (name, "/_objc.js") == 0)
    {
      json = gumjs_objc_source_map;
    }
#endif
#ifdef HAVE_SWIFT_BRIDGE
    else if (strcmp (name, "/_swift.js") == 0)
    {
      json = gumjs_swift_source_map;
    }
#endif
#ifdef HAVE_JAVA_BRIDGE
    else if (strcmp (name, "/_java.js") == 0)
    {
      json = gumjs_java_source_map;
    }
#endif
  }

  if (json != NULL)
    map = gumjs_source_map_new (json, core);

  return map;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_next_tick)
{
  JSValue callback;

  if (!_gum_quick_args_parse (args, "F", &callback))
    return JS_EXCEPTION;

  JS_DupValue (ctx, callback);
  g_queue_push_tail (&core->current_scope->tick_callbacks,
      g_slice_dup (JSValue, &callback));

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_pin)
{
  _gum_quick_core_pin (core);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_unpin)
{
  _gum_quick_core_unpin (core);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_bind_weak)
{
  guint id;
  JSValue target, callback;
  JSValue wrapper = JS_NULL;
  GumQuickWeakRef * ref;
  GumQuickWeakCallback entry;

  if (!_gum_quick_args_parse (args, "VF", &target, &callback))
    goto propagate_exception;

  wrapper = JS_Call (ctx, core->weak_map_get_method, core->weak_objects,
      1, &target);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  if (JS_IsUndefined (wrapper))
  {
    JSValue argv[2], val;

    wrapper = JS_NewObjectClass (ctx, core->weak_ref_class);

    ref = g_slice_new (GumQuickWeakRef);
    ref->target = target;
    ref->callbacks = g_array_new (FALSE, FALSE, sizeof (GumQuickWeakCallback));

    JS_SetOpaque (wrapper, ref);

    argv[0] = target;
    argv[1] = wrapper;
    val = JS_Call (ctx, core->weak_map_set_method, core->weak_objects,
        G_N_ELEMENTS (argv), argv);
    if (JS_IsException (val))
      goto propagate_exception;
    JS_FreeValue (ctx, val);
  }
  else
  {
    ref = JS_GetOpaque2 (ctx, wrapper, core->weak_ref_class);
  }

  id = core->next_weak_callback_id++;

  entry.id = id;
  entry.callback = JS_DupValue (ctx, callback);
  g_array_append_val (ref->callbacks, entry);

  g_hash_table_insert (core->weak_callbacks, GUINT_TO_POINTER (id), ref);

  JS_FreeValue (ctx, wrapper);

  return JS_NewInt32 (ctx, id);

propagate_exception:
  {
    JS_FreeValue (ctx, wrapper);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_script_unbind_weak)
{
  guint id;
  GumQuickWeakRef * ref;
  GArray * callbacks;

  if (!_gum_quick_args_parse (args, "u", &id))
    return JS_EXCEPTION;

  ref = g_hash_table_lookup (core->weak_callbacks, GUINT_TO_POINTER (id));
  if (ref == NULL)
    return JS_FALSE;

  callbacks = ref->callbacks;

  if (callbacks->len == 1)
  {
    JS_Call (ctx, core->weak_map_delete_method, core->weak_objects,
        1, &ref->target);
  }
  else
  {
    guint i;
    JSValue cb_val = JS_NULL;

    g_hash_table_remove (core->weak_callbacks, GUINT_TO_POINTER (id));

    for (i = 0; i != callbacks->len; i++)
    {
      GumQuickWeakCallback * entry =
          &g_array_index (callbacks, GumQuickWeakCallback, i);

      if (entry->id == id)
      {
        cb_val = entry->callback;
        g_array_remove_index (callbacks, i);
        break;
      }
    }

    _gum_quick_scope_call_void (core->current_scope, cb_val, JS_UNDEFINED,
        0, NULL);

    JS_FreeValue (ctx, cb_val);
  }

  return JS_TRUE;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_deref_weak)
{
  guint id;
  GumQuickWeakRef * ref;

  if (!_gum_quick_args_parse (args, "u", &id))
    return JS_EXCEPTION;

  ref = g_hash_table_lookup (core->weak_callbacks, GUINT_TO_POINTER (id));
  if (ref == NULL)
    return JS_UNDEFINED;

  return JS_DupValue (ctx, ref->target);
}

GUMJS_DEFINE_FINALIZER (gumjs_weak_ref_finalize)
{
  GumQuickWeakRef * ref;
  GArray * callbacks;
  guint i;

  ref = JS_GetOpaque (val, core->weak_ref_class);

  ref->target = JS_UNDEFINED;

  callbacks = ref->callbacks;
  for (i = 0; i != callbacks->len; i++)
  {
    GumQuickWeakCallback * entry =
        &g_array_index (callbacks, GumQuickWeakCallback, i);
    g_hash_table_remove (core->weak_callbacks, GUINT_TO_POINTER (entry->id));
  }

  g_queue_push_tail (&core->pending_weak_refs, ref);

  if (core->pending_weak_source == NULL)
  {
    GSource * source = g_idle_source_new ();

    g_source_set_callback (source,
        (GSourceFunc) gum_quick_core_invoke_pending_weak_callbacks_in_idle,
        core, NULL);
    g_source_attach (source,
        gum_script_scheduler_get_js_context (core->scheduler));
    g_source_unref (source);

    _gum_quick_core_pin (core);

    core->pending_weak_source = source;
  }
}

static gboolean
gum_quick_core_invoke_pending_weak_callbacks_in_idle (GumQuickCore * self)
{
  GumQuickWeakRef * ref;
  GumQuickScope scope;

  _gum_quick_scope_enter (&scope, self);

  self->pending_weak_source = NULL;

  while ((ref = g_queue_pop_head (&self->pending_weak_refs)) != NULL)
  {
    GArray * callbacks = ref->callbacks;
    guint i;

    for (i = 0; i != callbacks->len; i++)
    {
      GumQuickWeakCallback * entry =
          &g_array_index (callbacks, GumQuickWeakCallback, i);
      _gum_quick_scope_call_void (&scope, entry->callback, JS_UNDEFINED,
          0, NULL);
      JS_FreeValue (self->ctx, entry->callback);
    }
    g_array_free (callbacks, TRUE);

    g_slice_free (GumQuickWeakRef, ref);
  }

  _gum_quick_core_unpin (self);

  _gum_quick_scope_leave (&scope);

  return FALSE;
}

GUMJS_DEFINE_FUNCTION (gumjs_script_set_global_access_handler)
{
  JSValueConst * argv = args->elements;
  JSValue receiver, get;

  if (!JS_IsNull (argv[0]))
  {
    receiver = argv[0];
    if (!_gum_quick_args_parse (args, "F{get}", &get))
      return JS_EXCEPTION;
  }
  else
  {
    receiver = JS_NULL;
    get = JS_NULL;
  }

  if (JS_IsNull (receiver))
    JS_SetGlobalAccessFunctions (ctx, NULL);

  JS_FreeValue (ctx, core->on_global_get);
  JS_FreeValue (ctx, core->global_receiver);
  core->on_global_get = JS_NULL;
  core->global_receiver = JS_NULL;

  if (!JS_IsNull (receiver))
  {
    JSGlobalAccessFunctions funcs;

    core->on_global_get = JS_DupValue (ctx, get);
    core->global_receiver = JS_DupValue (ctx, receiver);

    funcs.get = gum_quick_core_on_global_get;
    funcs.opaque = core;
    JS_SetGlobalAccessFunctions (ctx, &funcs);
  }

  return JS_UNDEFINED;
}

static JSValue
gum_quick_core_on_global_get (JSContext * ctx,
                              JSAtom name,
                              void * opaque)
{
  GumQuickCore * self = opaque;
  JSValue result;
  JSValue name_val;

  name_val = JS_AtomToValue (ctx, name);

  result = _gum_quick_scope_call (self->current_scope, self->on_global_get,
      self->global_receiver, 1, &name_val);

  JS_FreeValue (ctx, name_val);

  return result;
}

GUMJS_DEFINE_FUNCTION (gumjs_set_timeout)
{
  GumQuickCore * self = core;

  return gum_quick_core_schedule_callback (self, args, FALSE);
}

GUMJS_DEFINE_FUNCTION (gumjs_set_interval)
{
  GumQuickCore * self = core;

  return gum_quick_core_schedule_callback (self, args, TRUE);
}

GUMJS_DEFINE_FUNCTION (gumjs_clear_timer)
{
  GumQuickCore * self = core;
  gint id;
  GumQuickScheduledCallback * callback;

  if (!JS_IsNumber (args->elements[0]))
    goto invalid_handle;

  if (!_gum_quick_args_parse (args, "i", &id))
    return JS_EXCEPTION;

  callback = gum_quick_core_try_steal_scheduled_callback (self, id);
  if (callback != NULL)
  {
    _gum_quick_core_pin (self);
    g_source_destroy (callback->source);
  }

  return JS_NewBool (ctx, callback != NULL);

invalid_handle:
  {
    return JS_NewBool (ctx, FALSE);
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_gc)
{
  JS_RunGC (core->rt);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_send)
{
  GumQuickCore * self = core;
  GumInterceptor * interceptor = (self->interceptor != NULL)
      ? self->interceptor->interceptor
      : NULL;
  const char * message;
  GBytes * data;

  if (!_gum_quick_args_parse (args, "sB?", &message, &data))
    return JS_EXCEPTION;

  /*
   * Synchronize Interceptor state before sending the message. The application
   * might be waiting for an acknowledgement that APIs have been instrumented.
   *
   * This is very important for the RPC API.
   */
  if (interceptor != NULL)
  {
    gum_interceptor_end_transaction (interceptor);
    gum_interceptor_begin_transaction (interceptor);
  }

  self->message_emitter (message, data, self->message_emitter_data);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_set_unhandled_exception_callback)
{
  GumQuickCore * self = core;
  JSValue callback;
  GumQuickExceptionSink * new_sink, * old_sink;

  if (!_gum_quick_args_parse (args, "F?", &callback))
    return JS_EXCEPTION;

  new_sink = !JS_IsNull (callback)
      ? gum_quick_exception_sink_new (callback, self)
      : NULL;

  old_sink = self->unhandled_exception_sink;
  self->unhandled_exception_sink = new_sink;

  if (old_sink != NULL)
    gum_quick_exception_sink_free (old_sink);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_set_incoming_message_callback)
{
  GumQuickCore * self = core;
  JSValue callback;
  GumQuickMessageSink * new_sink, * old_sink;

  if (!_gum_quick_args_parse (args, "F?", &callback))
    return JS_EXCEPTION;

  new_sink = !JS_IsNull (callback)
      ? gum_quick_message_sink_new (callback, self)
      : NULL;

  old_sink = self->incoming_message_sink;
  self->incoming_message_sink = new_sink;

  if (old_sink != NULL)
    gum_quick_message_sink_free (old_sink);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_wait_for_event)
{
  GumQuickCore * self = core;
  guint start_count;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (self);
  GMainContext * context;
  gboolean called_from_js_thread;
  gboolean event_source_available;

  g_mutex_lock (&self->event_mutex);
  start_count = self->event_count;
  g_mutex_unlock (&self->event_mutex);

  _gum_quick_scope_perform_pending_io (self->current_scope);

  _gum_quick_scope_suspend (&scope);

  context = gum_script_scheduler_get_js_context (self->scheduler);
  called_from_js_thread = g_main_context_is_owner (context);

  g_mutex_lock (&self->event_mutex);

  while (self->event_count == start_count && self->event_source_available)
  {
    if (called_from_js_thread)
    {
      g_mutex_unlock (&self->event_mutex);
      g_main_loop_run (self->event_loop);
      g_mutex_lock (&self->event_mutex);
    }
    else
    {
      g_cond_wait (&self->event_cond, &self->event_mutex);
    }
  }

  event_source_available = self->event_source_available;

  g_mutex_unlock (&self->event_mutex);

  _gum_quick_scope_resume (&scope);

  if (!event_source_available)
    return _gum_quick_throw_literal (ctx, "script is unloading");

  return JS_UNDEFINED;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_int64_construct)
{
  JSValue wrapper;
  gint64 value;
  JSValue proto;
  GumQuickInt64 * i64;

  if (!_gum_quick_args_parse (args, "q~", &value))
    return JS_EXCEPTION;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, core->int64_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    return JS_EXCEPTION;

  i64 = g_slice_new (GumQuickInt64);
  i64->value = value;

  JS_SetOpaque (wrapper, i64);

  return wrapper;
}

GUMJS_DEFINE_FINALIZER (gumjs_int64_finalize)
{
  GumQuickInt64 * i;

  i = JS_GetOpaque (val, core->int64_class);
  if (i == NULL)
    return;

  g_slice_free (GumQuickInt64, i);
}

#define GUM_DEFINE_INT64_OP_IMPL(name, op) \
    GUMJS_DEFINE_FUNCTION (gumjs_int64_##name) \
    { \
      GumQuickInt64 * self; \
      gint64 lhs, rhs, result; \
      \
      if (!_gum_quick_int64_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      lhs = self->value; \
      \
      if (!_gum_quick_args_parse (args, "q~", &rhs)) \
        return JS_EXCEPTION; \
      \
      result = lhs op rhs; \
      \
      return _gum_quick_int64_new (ctx, result, core); \
    }

GUM_DEFINE_INT64_OP_IMPL (add, +)
GUM_DEFINE_INT64_OP_IMPL (sub, -)
GUM_DEFINE_INT64_OP_IMPL (and, &)
GUM_DEFINE_INT64_OP_IMPL (or,  |)
GUM_DEFINE_INT64_OP_IMPL (xor, ^)
GUM_DEFINE_INT64_OP_IMPL (shr, >>)
GUM_DEFINE_INT64_OP_IMPL (shl, <<)

#define GUM_DEFINE_INT64_UNARY_OP_IMPL(name, op) \
    GUMJS_DEFINE_FUNCTION (gumjs_int64_##name) \
    { \
      GumQuickInt64 * self; \
      gint64 result; \
      \
      if (!_gum_quick_int64_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      result = op self->value; \
      \
      return _gum_quick_int64_new (ctx, result, core); \
    }

GUM_DEFINE_INT64_UNARY_OP_IMPL (not, ~)

GUMJS_DEFINE_FUNCTION (gumjs_int64_compare)
{
  GumQuickInt64 * self;
  gint64 lhs, rhs;
  gint result;

  if (!_gum_quick_int64_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;
  lhs = self->value;

  if (!_gum_quick_args_parse (args, "q~", &rhs))
    return JS_EXCEPTION;

  result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  return JS_NewInt32 (ctx, result);
}

GUMJS_DEFINE_FUNCTION (gumjs_int64_to_number)
{
  GumQuickInt64 * self;

  if (!_gum_quick_int64_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewInt64 (ctx, self->value);
}

GUMJS_DEFINE_FUNCTION (gumjs_int64_to_string)
{
  GumQuickInt64 * self;
  gint64 value;
  gint radix;
  gchar str[32];

  if (!_gum_quick_int64_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;
  value = self->value;

  radix = 10;
  if (!_gum_quick_args_parse (args, "|u", &radix))
    return JS_EXCEPTION;
  if (radix != 10 && radix != 16)
    return _gum_quick_throw_literal (ctx, "unsupported radix");

  if (radix == 10)
    sprintf (str, "%" G_GINT64_FORMAT, value);
  else if (value >= 0)
    sprintf (str, "%" G_GINT64_MODIFIER "x", value);
  else
    sprintf (str, "-%" G_GINT64_MODIFIER "x", -value);

  return JS_NewString (ctx, str);
}

GUMJS_DEFINE_FUNCTION (gumjs_int64_to_json)
{
  GumQuickInt64 * self;
  gchar str[32];

  if (!_gum_quick_int64_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  sprintf (str, "%" G_GINT64_FORMAT, self->value);

  return JS_NewString (ctx, str);
}

GUMJS_DEFINE_FUNCTION (gumjs_int64_value_of)
{
  GumQuickInt64 * self;

  if (!_gum_quick_int64_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewInt64 (ctx, self->value);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_uint64_construct)
{
  JSValue wrapper;
  guint64 value;
  JSValue proto;
  GumQuickUInt64 * u64;

  if (!_gum_quick_args_parse (args, "Q~", &value))
    return JS_EXCEPTION;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, core->uint64_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    return JS_EXCEPTION;

  u64 = g_slice_new (GumQuickUInt64);
  u64->value = value;

  JS_SetOpaque (wrapper, u64);

  return wrapper;
}

GUMJS_DEFINE_FINALIZER (gumjs_uint64_finalize)
{
  GumQuickUInt64 * u;

  u = JS_GetOpaque (val, core->uint64_class);
  if (u == NULL)
    return;

  g_slice_free (GumQuickUInt64, u);
}

#define GUM_DEFINE_UINT64_OP_IMPL(name, op) \
    GUMJS_DEFINE_FUNCTION (gumjs_uint64_##name) \
    { \
      GumQuickUInt64 * self; \
      guint64 lhs, rhs, result; \
      \
      if (!_gum_quick_uint64_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      lhs = self->value; \
      \
      if (!_gum_quick_args_parse (args, "Q~", &rhs)) \
        return JS_EXCEPTION; \
      \
      result = lhs op rhs; \
      \
      return _gum_quick_uint64_new (ctx, result, core); \
    }

GUM_DEFINE_UINT64_OP_IMPL (add, +)
GUM_DEFINE_UINT64_OP_IMPL (sub, -)
GUM_DEFINE_UINT64_OP_IMPL (and, &)
GUM_DEFINE_UINT64_OP_IMPL (or,  |)
GUM_DEFINE_UINT64_OP_IMPL (xor, ^)
GUM_DEFINE_UINT64_OP_IMPL (shr, >>)
GUM_DEFINE_UINT64_OP_IMPL (shl, <<)

#define GUM_DEFINE_UINT64_UNARY_OP_IMPL(name, op) \
    GUMJS_DEFINE_FUNCTION (gumjs_uint64_##name) \
    { \
      GumQuickUInt64 * self; \
      guint64 result; \
      \
      if (!_gum_quick_uint64_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      result = op self->value; \
      \
      return _gum_quick_uint64_new (ctx, result, core); \
    }

GUM_DEFINE_UINT64_UNARY_OP_IMPL (not, ~)

GUMJS_DEFINE_FUNCTION (gumjs_uint64_compare)
{
  GumQuickUInt64 * self;
  guint64 lhs, rhs;
  gint result;

  if (!_gum_quick_uint64_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;
  lhs = self->value;

  if (!_gum_quick_args_parse (args, "Q~", &rhs))
    return JS_EXCEPTION;

  result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  return JS_NewInt32 (ctx, result);
}

GUMJS_DEFINE_FUNCTION (gumjs_uint64_to_number)
{
  GumQuickUInt64 * self;

  if (!_gum_quick_uint64_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewFloat64 (ctx, (double) self->value);
}

GUMJS_DEFINE_FUNCTION (gumjs_uint64_to_string)
{
  GumQuickUInt64 * self;
  guint64 value;
  gint radix;
  gchar str[32];

  if (!_gum_quick_uint64_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;
  value = self->value;

  radix = 10;
  if (!_gum_quick_args_parse (args, "|u", &radix))
    return JS_EXCEPTION;
  if (radix != 10 && radix != 16)
    return _gum_quick_throw_literal (ctx, "unsupported radix");

  if (radix == 10)
    sprintf (str, "%" G_GUINT64_FORMAT, value);
  else
    sprintf (str, "%" G_GINT64_MODIFIER "x", value);

  return JS_NewString (ctx, str);
}

GUMJS_DEFINE_FUNCTION (gumjs_uint64_to_json)
{
  GumQuickUInt64 * self;
  gchar str[32];

  if (!_gum_quick_uint64_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  sprintf (str, "%" G_GUINT64_FORMAT, self->value);

  return JS_NewString (ctx, str);
}

GUMJS_DEFINE_FUNCTION (gumjs_uint64_value_of)
{
  GumQuickUInt64 * self;

  if (!_gum_quick_uint64_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewInt64 (ctx, self->value);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_pointer_construct)
{
  JSValue wrapper;
  gpointer ptr;
  JSValue proto;
  GumQuickNativePointer * np;

  if (!_gum_quick_args_parse (args, "p~", &ptr))
    return JS_EXCEPTION;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, core->native_pointer_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    return JS_EXCEPTION;

  np = g_slice_new0 (GumQuickNativePointer);
  np->value = ptr;

  JS_SetOpaque (wrapper, np);

  return wrapper;
}

GUMJS_DEFINE_FINALIZER (gumjs_native_pointer_finalize)
{
  GumQuickNativePointer * p;

  p = JS_GetOpaque (val, core->native_pointer_class);
  if (p == NULL)
    return;

  g_slice_free (GumQuickNativePointer, p);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_is_null)
{
  GumQuickNativePointer * self;

  if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewBool (ctx, self->value == NULL);
}

#define GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL(name, op) \
    GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_##name) \
    { \
      GumQuickNativePointer * self; \
      gpointer lhs_ptr, rhs_ptr; \
      gsize lhs_bits, rhs_bits; \
      gpointer result; \
      \
      if (!_gum_quick_native_pointer_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      lhs_ptr = self->value; \
      \
      if (!_gum_quick_args_parse (args, "p~
```