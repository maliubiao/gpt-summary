Response:
The user wants a summary of the functionality of the `gumv8stalker.cpp` file, which is part of the Frida dynamic instrumentation toolkit. I need to extract the key features and functionalities implemented in this code.

Here's a breakdown of the functionalities I can identify from the code:

1. **Stalker Core Functionality**: This file seems to wrap the core Frida Stalker functionality for use within the V8 JavaScript environment. This involves tracing code execution.
2. **Call Probes**: The code includes functions for adding and removing "call probes," which allow users to execute custom JavaScript code when specific functions are called.
3. **Instruction Stalking**: The presence of iterators (`GumV8StalkerDefaultIterator`, `GumV8StalkerSpecialIterator`) suggests the ability to iterate through and inspect executed instructions.
4. **Code Exclusion**: There's functionality to exclude specific memory ranges from being tracked by the stalker.
5. **Following/Unfollowing Threads**: The code provides functions to start and stop tracing execution on specific threads.
6. **Invalidation**: The `invalidate` function suggests a mechanism to mark certain code as invalid, likely to force re-instrumentation.
7. **Data Parsing**:  The `parse` function indicates the ability to process the raw event data collected by the stalker.
8. **JavaScript Callbacks**: The use of `GumV8CallbackTransformer` suggests the ability to define JavaScript functions that are called during the stalking process to transform the collected data.
9. **Queue Management**: The presence of properties like `queueCapacity` and `queueDrainInterval` suggests the Stalker uses a queue to buffer events, and these settings control its behavior.
10. **Garbage Collection**:  A `garbageCollect` function is present, likely for managing resources used by the Stalker.
11. **Flush**: The `flush` function likely forces the Stalker to process any buffered events.

I will organize these points into a concise summary, keeping in mind the constraints mentioned in the prompt (reverse engineering, low-level details, logic, user errors, debugging).
This C++ source code file, `gumv8stalker.cpp`, is a crucial component of Frida's dynamic instrumentation capabilities, specifically designed to integrate the core "Stalker" functionality with the V8 JavaScript engine. Here's a breakdown of its main functions:

1. **Code Tracing and Monitoring (Stalker Core Integration):** This file provides the JavaScript bindings for Frida's "Stalker." The Stalker is a core component responsible for dynamically tracing the execution of code within a process. It allows users to observe the flow of execution, including function calls, returns, and executed instructions.

2. **JavaScript Callback Integration for Code Transformation:** It enables the definition of JavaScript functions (`GumV8CallbackTransformer`) that can be invoked during the Stalker's tracing process. These callbacks can be used to analyze, filter, or modify the collected trace data in real-time.

3. **Instruction-Level Iteration and Inspection:** The code defines iterators (`GumV8StalkerDefaultIterator`, `GumV8StalkerSpecialIterator`) that allow JavaScript code to step through the instructions captured by the Stalker. This enables fine-grained analysis of the executed code.

4. **Call Probing:**  The file implements functionality to insert "call probes" (`addCallProbe`, `removeCallProbe`). These probes trigger JavaScript callbacks when specific functions are called, allowing users to intercept and potentially modify function arguments, return values, or execution flow.

5. **Control over Stalker Behavior:** It exposes properties like `trustThreshold`, `queueCapacity`, and `queueDrainInterval` to JavaScript. These settings allow users to fine-tune the Stalker's performance and resource usage.

6. **Managing Tracing Sessions (Follow/Unfollow):** The `follow` and `unfollow` functions provide the ability to start and stop tracing execution on specific threads.

7. **Excluding Code from Tracing:** The `exclude` function allows users to specify memory regions that the Stalker should ignore, which can be useful for focusing on specific areas of interest or improving performance.

8. **Invalidating Traced Code:** The `invalidate` function provides a mechanism to inform the Stalker that certain code has been modified and needs to be re-analyzed.

9. **Parsing Raw Stalker Data:** The `parse` function enables the interpretation of the raw binary data collected by the Stalker, converting it into a more human-readable format (arrays of events).

10. **Resource Management (Flush and Garbage Collection):** The `flush` function forces the Stalker to process any buffered events, while `garbageCollect` is responsible for cleaning up internal resources used by the Stalker.

**Relationship to Reverse Engineering:**

*   **Dynamic Analysis:** The entire Stalker functionality is a cornerstone of dynamic analysis in reverse engineering. By tracing code execution, reverse engineers can understand how a program behaves at runtime, identify the sequence of function calls, and observe data flow.
    *   **Example:** A reverse engineer might use `Stalker.follow()` to trace a specific function call in a target application. They could then use the iterators to step through the executed instructions and identify the logic within that function. Call probes can be used to inspect the arguments passed to the function and the return value.
*   **Hooking and Interception:** Call probes directly enable hooking and interception techniques. By placing a probe on a function of interest, a reverse engineer can execute their own code before or after the original function executes.
    *   **Example:** A reverse engineer could use `Stalker.addCallProbe()` to intercept a function that checks for license validity. Their callback could then always return a successful status, effectively bypassing the license check.

**Involvement of Binary, Linux/Android Kernel and Framework Knowledge:**

*   **Binary Code Analysis:** The Stalker operates at the level of binary code. Understanding instruction sets (like ARM or x86), assembly language, and calling conventions is crucial for interpreting the trace data. The `parse` function explicitly deals with the binary representation of events.
*   **Memory Addresses and Ranges:** Functions like `exclude` and the event data in `parse` deal with raw memory addresses and sizes. Knowledge of how memory is organized in the target process is essential.
*   **Thread IDs:** The `follow` and `unfollow` functions take thread IDs as arguments, requiring an understanding of how operating systems manage threads. This is relevant in both Linux and Android environments.
*   **System Calls (Indirectly):** While not explicitly manipulating system calls in this file, the Stalker often traces code that eventually interacts with the kernel through system calls. Understanding common system calls can provide context to the traced execution.
*   **Android Framework (Potentially):** When used on Android, the Stalker can trace code within the Android runtime environment (ART) and framework libraries. Knowledge of the Android framework structure and common APIs can be helpful for interpreting traces.

**Logic and Assumptions (Hypothetical Input and Output for `parse`):**

*   **Assumption:**  The Stalker has been running and has captured a sequence of `GUM_CALL` and `GUM_RET` events.
*   **Input to `gumjs_stalker_parse`:**
    *   `events_value`: An `ArrayBuffer` containing the raw binary data of the captured `GUM_CALL` and `GUM_RET` events.
    *   `annotate`: `true` (to include event type annotations).
    *   `stringify`: `true` (to represent memory addresses as strings).
*   **Output from `gumjs_stalker_parse`:** A JavaScript array of arrays, where each inner array represents an event:
    ```javascript
    [
      ["call", "0x12345678", "0x9ABCDEF0", 0], // Call event
      ["ret", "0x123456AA", "0x9ABCDEF0", 0]   // Return event
    ]
    ```
    *   The first element of each inner array is the event type ("call" or "ret").
    *   The second element is the location of the event.
    *   For call and return events, the third element is the target address.
    *   The last element (for call and return) is the call depth.

**Common User or Programming Errors:**

*   **Incorrect Memory Range for Exclusion:**  Providing an invalid memory range to `exclude` might not have the intended effect or could even lead to errors.
    *   **Example:**  A user might provide a size that doesn't align with the actual memory region, causing only a portion of the intended code to be excluded.
*   **Forgetting to `unfollow`:** If a user calls `follow` but forgets to call `unfollow`, the Stalker will continue tracing, potentially consuming resources and generating a large amount of data.
    *   **Debugging Clue:**  A program running slower than expected or consuming excessive memory after using Stalker might indicate a forgotten `unfollow`.
*   **Incorrectly Parsing Event Data:**  If a user attempts to manually interpret the raw event data without using the `parse` function or misunderstands the structure of the `GumEvent` struct, they might misinterpret the traced events.
*   **Callback Errors in Transformers/Probes:** If the JavaScript callback functions provided to `follow` (as a transformer) or `addCallProbe` throw errors, it can disrupt the Stalker's operation or lead to unexpected behavior.
    *   **Debugging Clue:** Frida might report JavaScript exceptions during the tracing process if a callback throws an error.

**User Operation Flow to Reach This Code (Debugging Context):**

1. A user writes a Frida script in JavaScript.
2. The script uses the `Stalker` API (e.g., `Stalker.follow()`, `Stalker.addCallProbe()`).
3. When the Frida script is executed, the JavaScript code interacts with the V8 engine.
4. The V8 engine calls into the native C++ code of Frida, specifically the functions exposed in `gumv8stalker.cpp`.
5. For instance, if the script calls `Stalker.follow()`, the `gumjs_stalker_follow` function in this file will be executed.
6. This C++ code then interacts with the core Stalker implementation (which is in other files) to start the tracing process.
7. During tracing, when events occur, the core Stalker may call back into JavaScript through mechanisms defined in this file (like the `GumV8CallbackTransformer`).
8. If the user uses an iterator (e.g., `Stalker.trace. SchnellerIterator()`), the JavaScript will call the methods defined for `GumV8StalkerDefaultIterator` or `GumV8StalkerSpecialIterator` in this file.
9. If the user calls `Stalker.parse()`, the `gumjs_stalker_parse` function in this file is invoked to process the raw event data.

In essence, this file acts as the bridge between the JavaScript API that Frida users interact with and the underlying C++ implementation of the Stalker. When debugging issues related to code tracing or call probes, examining this file and the related core Stalker implementation would be necessary.

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8stalker.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2010-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8stalker.h"

#include "gumv8eventsink.h"
#include "gumv8macros.h"
#include "gumv8scope.h"

#include <glib/gprintf.h>

#define GUMJS_MODULE_NAME Stalker

#define GUM_V8_TYPE_CALLBACK_TRANSFORMER \
    (gum_v8_callback_transformer_get_type ())
#define GUM_V8_CALLBACK_TRANSFORMER_CAST(obj) \
    ((GumV8CallbackTransformer *) (obj))

using namespace v8;

struct GumV8CallbackTransformer
{
  GObject parent;

  GumThreadId thread_id;
  Global<Function> * callback;

  GumV8Stalker * module;
};

struct GumV8CallbackTransformerClass
{
  GObjectClass parent_class;
};

struct GumV8StalkerIterator
{
  GumStalkerIterator * handle;
  GumV8InstructionValue * instruction;

  GumV8Stalker * module;
};

struct GumV8StalkerDefaultIterator
{
  GumV8DefaultWriter parent;
  GumV8StalkerIterator iterator;
};

struct GumV8StalkerSpecialIterator
{
  GumV8SpecialWriter parent;
  GumV8StalkerIterator iterator;
};

struct GumV8Callout
{
  Global<Function> * callback;

  GumV8Stalker * module;
};

struct GumV8CallProbe
{
  Global<Function> * callback;

  GumV8Stalker * module;
};

static gboolean gum_v8_stalker_on_flush_timer_tick (GumV8Stalker * self);

GUMJS_DECLARE_GETTER (gumjs_stalker_get_trust_threshold)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_trust_threshold)

GUMJS_DECLARE_GETTER (gumjs_stalker_get_queue_capacity)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_queue_capacity)

GUMJS_DECLARE_GETTER (gumjs_stalker_get_queue_drain_interval)
GUMJS_DECLARE_SETTER (gumjs_stalker_set_queue_drain_interval)

GUMJS_DECLARE_FUNCTION (gumjs_stalker_flush)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_garbage_collect)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_exclude)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_follow)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_unfollow)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_invalidate)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_add_call_probe)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_remove_call_probe)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_parse)

static void gum_v8_callback_transformer_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_callback_transformer_dispose (GObject * object);
G_DEFINE_TYPE_EXTENDED (GumV8CallbackTransformer,
                        gum_v8_callback_transformer,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_STALKER_TRANSFORMER,
                            gum_v8_callback_transformer_iface_init))

static GumV8StalkerDefaultIterator *
    gum_v8_stalker_default_iterator_new_persistent (GumV8Stalker * parent);
static void gum_v8_stalker_default_iterator_release_persistent (
    GumV8StalkerDefaultIterator * self);
static void gum_v8_stalker_default_iterator_on_weak_notify (
    const WeakCallbackInfo<GumV8StalkerDefaultIterator> & info);
static void gum_v8_stalker_default_iterator_free (
    GumV8StalkerDefaultIterator * self);
static void gum_v8_stalker_default_iterator_reset (
    GumV8StalkerDefaultIterator * self, GumStalkerIterator * handle,
    GumStalkerOutput * output);
GUMJS_DECLARE_GETTER (gumjs_stalker_default_iterator_get_memory_access)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_default_iterator_next)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_default_iterator_keep)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_default_iterator_put_callout)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_default_iterator_put_chaining_return)

static GumV8StalkerSpecialIterator *
    gum_v8_stalker_special_iterator_new_persistent (GumV8Stalker * parent);
static void gum_v8_stalker_special_iterator_release_persistent (
    GumV8StalkerSpecialIterator * self);
static void gum_v8_stalker_special_iterator_on_weak_notify (
    const WeakCallbackInfo<GumV8StalkerSpecialIterator> & info);
static void gum_v8_stalker_special_iterator_free (
    GumV8StalkerSpecialIterator * self);
static void gum_v8_stalker_special_iterator_reset (
    GumV8StalkerSpecialIterator * self, GumStalkerIterator * handle,
    GumStalkerOutput * output);
GUMJS_DECLARE_GETTER (gumjs_stalker_special_iterator_get_memory_access)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_special_iterator_next)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_special_iterator_keep)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_special_iterator_put_callout)
GUMJS_DECLARE_FUNCTION (gumjs_stalker_special_iterator_put_chaining_return)

static void gum_v8_callout_free (GumV8Callout * callout);
static void gum_v8_callout_on_invoke (GumCpuContext * cpu_context,
    GumV8Callout * self);

static void gum_v8_call_probe_free (GumV8CallProbe * probe);
static void gum_v8_call_probe_on_fire (GumCallDetails * details,
    GumV8CallProbe * self);

static void gumjs_probe_args_get_nth (uint32_t index,
    const PropertyCallbackInfo<Value> & info);
static void gumjs_probe_args_set_nth (uint32_t index, Local<Value> value,
    const PropertyCallbackInfo<Value> & info);

static GumV8StalkerDefaultIterator * gum_v8_stalker_obtain_default_iterator (
    GumV8Stalker * self);
static void gum_v8_stalker_release_default_iterator (GumV8Stalker * self,
    GumV8StalkerDefaultIterator * iterator);
static GumV8StalkerSpecialIterator * gum_v8_stalker_obtain_special_iterator (
    GumV8Stalker * self);
static void gum_v8_stalker_release_special_iterator (GumV8Stalker * self,
    GumV8StalkerSpecialIterator * iterator);
static GumV8InstructionValue * gum_v8_stalker_obtain_instruction (
    GumV8Stalker * self);
static void gum_v8_stalker_release_instruction (GumV8Stalker * self,
    GumV8InstructionValue * value);

static Local<Value> gum_make_pointer (gpointer value, gboolean stringify,
    GumV8Core * core);

static const GumV8Property gumjs_stalker_values[] =
{
  {
    "trustThreshold",
    gumjs_stalker_get_trust_threshold,
    gumjs_stalker_set_trust_threshold
  },
  {
    "queueCapacity",
    gumjs_stalker_get_queue_capacity,
    gumjs_stalker_set_queue_capacity
  },
  {
    "queueDrainInterval",
    gumjs_stalker_get_queue_drain_interval,
    gumjs_stalker_set_queue_drain_interval
  },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_stalker_functions[] =
{
  { "flush", gumjs_stalker_flush },
  { "garbageCollect", gumjs_stalker_garbage_collect },
  { "_exclude", gumjs_stalker_exclude },
  { "_follow", gumjs_stalker_follow },
  { "unfollow", gumjs_stalker_unfollow },
  { "invalidate", gumjs_stalker_invalidate },
  { "addCallProbe", gumjs_stalker_add_call_probe },
  { "removeCallProbe", gumjs_stalker_remove_call_probe },
  { "_parse", gumjs_stalker_parse },

  { NULL, NULL }
};

static const GumV8Property gumjs_stalker_default_iterator_values[] =
{
  { "memoryAccess", gumjs_stalker_default_iterator_get_memory_access, NULL },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_stalker_default_iterator_functions[] =
{
  { "next", gumjs_stalker_default_iterator_next },
  { "keep", gumjs_stalker_default_iterator_keep },
  { "putCallout", gumjs_stalker_default_iterator_put_callout },
  { "putChainingReturn", gumjs_stalker_default_iterator_put_chaining_return },

  { NULL, NULL }
};

static const GumV8Property gumjs_stalker_special_iterator_values[] =
{
  { "memoryAccess", gumjs_stalker_special_iterator_get_memory_access, NULL },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_stalker_special_iterator_functions[] =
{
  { "next", gumjs_stalker_special_iterator_next },
  { "keep", gumjs_stalker_special_iterator_keep },
  { "putCallout", gumjs_stalker_special_iterator_put_callout },
  { "putChainingReturn", gumjs_stalker_special_iterator_put_chaining_return },

  { NULL, NULL }
};

void
_gum_v8_stalker_init (GumV8Stalker * self,
                      GumV8CodeWriter * writer,
                      GumV8Instruction * instruction,
                      GumV8Core * core,
                      Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->writer = writer;
  self->instruction = instruction;
  self->core = core;

  self->stalker = NULL;
  self->queue_capacity = 16384;
  self->queue_drain_interval = 250;

  self->flush_timer = NULL;

  self->default_iterators = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_stalker_default_iterator_free);
  self->special_iterators = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_stalker_special_iterator_free);

  auto module = External::New (isolate, self);

  auto stalker = _gum_v8_create_module ("Stalker", scope, isolate);
  _gum_v8_module_add (module, stalker, gumjs_stalker_values, isolate);
  _gum_v8_module_add (module, stalker, gumjs_stalker_functions, isolate);

  {
    auto iter = _gum_v8_create_class ("StalkerDefaultIterator", nullptr, scope,
        module, isolate);
    auto default_writer = Local<FunctionTemplate>::New (isolate,
        *writer->GUM_V8_DEFAULT_WRITER_FIELD);
    iter->Inherit (default_writer);
    _gum_v8_class_add (iter, gumjs_stalker_default_iterator_values, module,
        isolate);
    _gum_v8_class_add (iter, gumjs_stalker_default_iterator_functions, module,
        isolate);
    iter->InstanceTemplate ()->SetInternalFieldCount (2);
    self->default_iterator = new Global<FunctionTemplate> (isolate, iter);
  }

  {
    auto iter = _gum_v8_create_class ("StalkerSpecialIterator", nullptr, scope,
        module, isolate);
    auto special_writer = Local<FunctionTemplate>::New (isolate,
        *writer->GUM_V8_SPECIAL_WRITER_FIELD);
    iter->Inherit (special_writer);
    _gum_v8_class_add (iter, gumjs_stalker_special_iterator_values, module,
        isolate);
    _gum_v8_class_add (iter, gumjs_stalker_special_iterator_functions, module,
        isolate);
    iter->InstanceTemplate ()->SetInternalFieldCount (2);
    self->special_iterator = new Global<FunctionTemplate> (isolate, iter);
  }
}

void
_gum_v8_stalker_realize (GumV8Stalker * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  {
    auto iter = Local<FunctionTemplate>::New (isolate, *self->default_iterator);
    auto iter_value = iter->GetFunction (context).ToLocalChecked ()
        ->NewInstance (context, 0, nullptr).ToLocalChecked ();
    self->default_iterator_value = new Global<Object> (isolate, iter_value);
  }

  {
    auto iter = Local<FunctionTemplate>::New (isolate, *self->special_iterator);
    auto iter_value = iter->GetFunction (context).ToLocalChecked ()
        ->NewInstance (context, 0, nullptr).ToLocalChecked ();
    self->special_iterator_value = new Global<Object> (isolate, iter_value);
  }

  auto args = ObjectTemplate::New (isolate);
  args->SetInternalFieldCount (2);
  args->SetIndexedPropertyHandler (gumjs_probe_args_get_nth,
      gumjs_probe_args_set_nth);
  self->probe_args = new Global<ObjectTemplate> (isolate, args);

  self->cached_default_iterator =
      gum_v8_stalker_default_iterator_new_persistent (self);
  self->cached_default_iterator_in_use = FALSE;

  self->cached_special_iterator =
      gum_v8_stalker_special_iterator_new_persistent (self);
  self->cached_special_iterator_in_use = FALSE;

  self->cached_instruction =
      _gum_v8_instruction_new_persistent (self->instruction);
  self->cached_instruction_in_use = FALSE;
}

void
_gum_v8_stalker_flush (GumV8Stalker * self)
{
  auto core = self->core;
  gboolean pending_garbage;

  if (self->stalker == NULL)
    return;

  {
    ScriptUnlocker unlocker (core);

    gum_stalker_stop (self->stalker);

    pending_garbage = gum_stalker_garbage_collect (self->stalker);
  }

  if (pending_garbage)
  {
    if (self->flush_timer == NULL)
    {
      auto source = g_timeout_source_new (10);
      g_source_set_callback (source,
          (GSourceFunc) gum_v8_stalker_on_flush_timer_tick, self, NULL);
      self->flush_timer = source;

      _gum_v8_core_pin (core);

      {
        ScriptUnlocker unlocker (core);

        g_source_attach (source,
            gum_script_scheduler_get_js_context (core->scheduler));
        g_source_unref (source);
      }
    }
  }
  else
  {
    g_object_unref (self->stalker);
    self->stalker = NULL;
  }
}

static gboolean
gum_v8_stalker_on_flush_timer_tick (GumV8Stalker * self)
{
  gboolean pending_garbage;

  pending_garbage = gum_stalker_garbage_collect (self->stalker);
  if (!pending_garbage)
  {
    GumV8Core * core = self->core;

    ScriptScope scope (core->script);
    _gum_v8_core_unpin (core);
    self->flush_timer = NULL;
  }

  return pending_garbage;
}

void
_gum_v8_stalker_dispose (GumV8Stalker * self)
{
  g_assert (self->flush_timer == NULL);

  _gum_v8_instruction_release_persistent (self->cached_instruction);
  self->cached_instruction = NULL;

  gum_v8_stalker_special_iterator_release_persistent (
      self->cached_special_iterator);
  self->cached_special_iterator = NULL;

  gum_v8_stalker_default_iterator_release_persistent (
      self->cached_default_iterator);
  self->cached_default_iterator = NULL;

  delete self->probe_args;
  self->probe_args = nullptr;

  delete self->special_iterator_value;
  self->special_iterator_value = nullptr;

  delete self->default_iterator_value;
  self->default_iterator_value = nullptr;

  delete self->special_iterator;
  self->special_iterator = nullptr;

  delete self->default_iterator;
  self->default_iterator = nullptr;

  g_hash_table_unref (self->special_iterators);
  self->special_iterators = NULL;

  g_hash_table_unref (self->default_iterators);
  self->default_iterators = NULL;
}

void
_gum_v8_stalker_finalize (GumV8Stalker * self)
{
}

GumStalker *
_gum_v8_stalker_get (GumV8Stalker * self)
{
  if (self->stalker == NULL)
    self->stalker = gum_stalker_new ();

  return self->stalker;
}

void
_gum_v8_stalker_process_pending (GumV8Stalker * self,
                                 ScriptStalkerScope * scope)
{
  if (scope->pending_level > 0)
  {
    gum_stalker_follow_me (_gum_v8_stalker_get (self), scope->transformer,
        scope->sink);
  }
  else if (scope->pending_level < 0)
  {
    gum_stalker_unfollow_me (_gum_v8_stalker_get (self));
  }
  scope->pending_level = 0;

  g_clear_object (&scope->sink);
  g_clear_object (&scope->transformer);
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_trust_threshold)
{
  auto stalker = _gum_v8_stalker_get (module);

  info.GetReturnValue ().Set (gum_stalker_get_trust_threshold (stalker));
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_trust_threshold)
{
  auto stalker = _gum_v8_stalker_get (module);

  gint threshold;
  if (!_gum_v8_int_get (value, &threshold, core))
    return;

  gum_stalker_set_trust_threshold (stalker, threshold);
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_capacity)
{
  info.GetReturnValue ().Set (module->queue_capacity);
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_capacity)
{
  guint capacity;
  if (!_gum_v8_uint_get (value, &capacity, core))
    return;

  module->queue_capacity = capacity;
}

GUMJS_DEFINE_GETTER (gumjs_stalker_get_queue_drain_interval)
{
  info.GetReturnValue ().Set (module->queue_drain_interval);
}

GUMJS_DEFINE_SETTER (gumjs_stalker_set_queue_drain_interval)
{
  guint interval;
  if (!_gum_v8_uint_get (value, &interval, core))
    return;

  module->queue_drain_interval = interval;
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_flush)
{
  auto stalker = _gum_v8_stalker_get (module);

  gum_stalker_flush (stalker);
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_garbage_collect)
{
  auto stalker = _gum_v8_stalker_get (module);

  gum_stalker_garbage_collect (stalker);
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_exclude)
{
  auto stalker = _gum_v8_stalker_get (module);

  gpointer base;
  gsize size;
  if (!_gum_v8_args_parse (args, "pZ", &base, &size))
    return;

  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (base);
  range.size = size;

  gum_stalker_exclude (stalker, &range);
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_follow)
{
  auto stalker = _gum_v8_stalker_get (module);

  GumThreadId thread_id;

  Local<Function> transformer_callback_js;
  GumStalkerTransformerCallback transformer_callback_c;

  GumV8EventSinkOptions so;
  so.core = core;
  so.main_context = gum_script_scheduler_get_js_context (core->scheduler);
  so.queue_capacity = module->queue_capacity;
  so.queue_drain_interval = module->queue_drain_interval;

  gpointer user_data;

  if (!_gum_v8_args_parse (args, "ZF*?uF?F?pp", &thread_id,
      &transformer_callback_js, &transformer_callback_c,
      &so.event_mask, &so.on_receive, &so.on_call_summary,
      &so.on_event, &user_data))
    return;

  so.user_data = user_data;

  GumStalkerTransformer * transformer = NULL;

  if (!transformer_callback_js.IsEmpty ())
  {
    auto cbt = (GumV8CallbackTransformer *)
        g_object_new (GUM_V8_TYPE_CALLBACK_TRANSFORMER, NULL);
    cbt->thread_id = thread_id;
    cbt->callback = new Global<Function> (isolate, transformer_callback_js);
    cbt->module = module;

    transformer = GUM_STALKER_TRANSFORMER (cbt);
  }
  else if (transformer_callback_c != NULL)
  {
    transformer = gum_stalker_transformer_make_from_callback (
        transformer_callback_c, user_data, NULL);
  }

  auto sink = gum_v8_event_sink_new (&so);
  if (thread_id == gum_process_get_current_thread_id ())
  {
    ScriptStalkerScope * scope = &core->current_scope->stalker_scope;

    scope->pending_level = 1;

    g_clear_object (&scope->transformer);
    g_clear_object (&scope->sink);
    scope->transformer = transformer;
    scope->sink = sink;
  }
  else
  {
    gum_stalker_follow (stalker, thread_id, transformer, sink);
    g_object_unref (sink);
    g_clear_object (&transformer);
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_unfollow)
{
  GumStalker * stalker;
  GumThreadId current_thread_id = gum_process_get_current_thread_id ();

  stalker = _gum_v8_stalker_get (module);

  GumThreadId thread_id = current_thread_id;
  if (!_gum_v8_args_parse (args, "|Z", &thread_id))
    return;

  if (thread_id == current_thread_id)
    core->current_scope->stalker_scope.pending_level--;
  else
    gum_stalker_unfollow (stalker, thread_id);
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_invalidate)
{
  GumStalker * stalker = _gum_v8_stalker_get (module);

  if (info.Length () <= 1)
  {
    gpointer address;
    if (!_gum_v8_args_parse (args, "p", &address))
      return;

    gum_stalker_invalidate (stalker, address);
  }
  else
  {
    GumThreadId thread_id;
    gpointer address;
    if (!_gum_v8_args_parse (args, "Zp", &thread_id, &address))
      return;

    {
      ScriptUnlocker unlocker (core);

      gum_stalker_invalidate_for_thread (stalker, thread_id, address);
    }
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_add_call_probe)
{
  GumStalker * stalker = _gum_v8_stalker_get (module);

  gpointer target_address;
  Local<Function> callback_js;
  GumCallProbeCallback callback_c;
  gpointer user_data = NULL;
  if (!_gum_v8_args_parse (args, "pF*|p", &target_address, &callback_js,
      &callback_c, &user_data))
    return;

  GumProbeId id;
  if (!callback_js.IsEmpty ())
  {
    auto probe = g_slice_new (GumV8CallProbe);
    probe->callback = new Global<Function> (isolate, callback_js);
    probe->module = module;

    id = gum_stalker_add_call_probe (stalker, target_address,
        (GumCallProbeCallback) gum_v8_call_probe_on_fire, probe,
        (GDestroyNotify) gum_v8_call_probe_free);
  }
  else
  {
    id = gum_stalker_add_call_probe (stalker, target_address, callback_c,
        user_data, NULL);
  }

  info.GetReturnValue ().Set (id);
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_remove_call_probe)
{
  GumProbeId id;
  if (!_gum_v8_args_parse (args, "u", &id))
    return;

  gum_stalker_remove_call_probe (_gum_v8_stalker_get (module), id);
}

GUMJS_DEFINE_FUNCTION (gumjs_stalker_parse)
{
  auto context = isolate->GetCurrentContext ();

  Local<Value> events_value;
  gboolean annotate, stringify;
  if (!_gum_v8_args_parse (args, "Vtt", &events_value, &annotate, &stringify))
    return;

  if (!events_value->IsArrayBuffer ())
  {
    _gum_v8_throw_ascii_literal (isolate, "expected an ArrayBuffer");
    return;
  }

  auto events_store = events_value.As<ArrayBuffer> ()->GetBackingStore ();
  const GumEvent * events = (const GumEvent *) events_store->Data ();
  size_t size = events_store->ByteLength ();
  if (size % sizeof (GumEvent) != 0)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid buffer shape");
    return;
  }

  size_t count = size / sizeof (GumEvent);

  auto rows = Array::New (isolate, (int) count);

  const GumEvent * ev;
  size_t row_index;
  for (ev = events, row_index = 0;
      row_index != count;
      ev++, row_index++)
  {
    Local<Array> row;
    guint column_index = 0;

    switch (ev->type)
    {
      case GUM_CALL:
      {
        const GumCallEvent * call = &ev->call;

        if (annotate)
        {
          row = Array::New (isolate, 4);
          row->Set (context, column_index++,
              _gum_v8_string_new_ascii (isolate, "call")).Check ();
        }
        else
        {
          row = Array::New (isolate, 3);
        }

        row->Set (context, column_index++,
            gum_make_pointer (call->location, stringify, core)).Check ();
        row->Set (context, column_index++,
            gum_make_pointer (call->target, stringify, core)).Check ();
        row->Set (context, column_index++, Integer::New (isolate, call->depth))
            .Check ();

        break;
      }
      case GUM_RET:
      {
        const GumRetEvent * ret = &ev->ret;

        if (annotate)
        {
          row = Array::New (isolate, 4);
          row->Set (context, column_index++,
              _gum_v8_string_new_ascii (isolate, "ret")).Check ();
        }
        else
        {
          row = Array::New (isolate, 3);
        }

        row->Set (context, column_index++,
            gum_make_pointer (ret->location, stringify, core)).Check ();
        row->Set (context, column_index++,
            gum_make_pointer (ret->target, stringify, core)).Check ();
        row->Set (context, column_index++, Integer::New (isolate, ret->depth))
            .Check ();

        break;
      }
      case GUM_EXEC:
      {
        const GumExecEvent * exec = &ev->exec;

        if (annotate)
        {
          row = Array::New (isolate, 2);
          row->Set (context, column_index++,
              _gum_v8_string_new_ascii (isolate, "exec")).Check ();
        }
        else
        {
          row = Array::New (isolate, 1);
        }

        row->Set (context, column_index++,
            gum_make_pointer (exec->location, stringify, core)).Check ();

        break;
      }
      case GUM_BLOCK:
      {
        const GumBlockEvent * block = &ev->block;

        if (annotate)
        {
          row = Array::New (isolate, 3);
          row->Set (context, column_index++,
              _gum_v8_string_new_ascii (isolate, "block")).Check ();
        }
        else
        {
          row = Array::New (isolate, 2);
        }

        row->Set (context, column_index++,
            gum_make_pointer (block->start, stringify, core)).Check ();
        row->Set (context, column_index++,
            gum_make_pointer (block->end, stringify, core)).Check ();

        break;
      }
      case GUM_COMPILE:
      {
        const GumCompileEvent * compile = &ev->compile;

        if (annotate)
        {
          row = Array::New (isolate, 3);
          row->Set (context, column_index++,
              _gum_v8_string_new_ascii (isolate, "compile")).Check ();
        }
        else
        {
          row = Array::New (isolate, 2);
        }

        row->Set (context, column_index++,
            gum_make_pointer (compile->start, stringify, core)).Check ();
        row->Set (context, column_index++,
            gum_make_pointer (compile->end, stringify, core)).Check ();

        break;
      }
      default:
        _gum_v8_throw_ascii_literal (isolate, "invalid event type");
        return;
    }

    rows->Set (context, (uint32_t) row_index, row).Check ();
  }

  info.GetReturnValue ().Set (rows);
}

static void
gum_v8_callback_transformer_transform_block (
    GumStalkerTransformer * transformer,
    GumStalkerIterator * iterator,
    GumStalkerOutput * output)
{
  GumV8SystemErrorPreservationScope error_scope;

  auto self = GUM_V8_CALLBACK_TRANSFORMER_CAST (transformer);
  auto module = self->module;
  auto core = module->core;

  gboolean transform_threw_an_exception;
  {
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    auto callback = Local<Function>::New (isolate, *self->callback);

    GumV8StalkerDefaultIterator * default_iter = NULL;
    GumV8StalkerSpecialIterator * special_iter = NULL;
    Global<v8::Object> * iter_object_handle;
    if (output->encoding == GUM_INSTRUCTION_DEFAULT)
    {
      default_iter = gum_v8_stalker_obtain_default_iterator (module);
      gum_v8_stalker_default_iterator_reset (default_iter, iterator, output);
      iter_object_handle = default_iter->parent.object;
    }
    else
    {
      special_iter = gum_v8_stalker_obtain_special_iterator (module);
      gum_v8_stalker_special_iterator_reset (special_iter, iterator, output);
      iter_object_handle = special_iter->parent.object;
    }

    auto iter_object = Local<Object>::New (isolate, *iter_object_handle);

    auto recv = Undefined (isolate);
    Local<Value> argv[] = { iter_object };
    auto result = callback->Call (context, recv, G_N_ELEMENTS (argv), argv);
    transform_threw_an_exception = result.IsEmpty ();
    if (transform_threw_an_exception)
      scope.ProcessAnyPendingException ();

    if (default_iter != NULL)
    {
      gum_v8_stalker_default_iterator_reset (default_iter, NULL, NULL);
      gum_v8_stalker_release_default_iterator (module, default_iter);
    }
    else
    {
      gum_v8_stalker_special_iterator_reset (special_iter, NULL, NULL);
      gum_v8_stalker_release_special_iterator (module, special_iter);
    }
  }

  if (transform_threw_an_exception)
    gum_stalker_unfollow (module->stalker, self->thread_id);
}

static void
gum_v8_callback_transformer_class_init (GumV8CallbackTransformerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_callback_transformer_dispose;
}

static void
gum_v8_callback_transformer_iface_init (gpointer g_iface,
                                        gpointer iface_data)
{
  auto iface = (GumStalkerTransformerInterface *) g_iface;

  iface->transform_block = gum_v8_callback_transformer_transform_block;
}

static void
gum_v8_callback_transformer_init (GumV8CallbackTransformer * self)
{
}

static void
gum_v8_callback_transformer_dispose (GObject * object)
{
  auto self = GUM_V8_CALLBACK_TRANSFORMER_CAST (object);

  ScriptScope scope (self->module->core->script);

  delete self->callback;
  self->callback = nullptr;

  G_OBJECT_CLASS (gum_v8_callback_transformer_parent_class)->dispose (object);
}

static void
gum_v8_stalker_iterator_init (GumV8StalkerIterator * iter,
                              GumV8Stalker * parent)
{
  iter->handle = NULL;
  iter->instruction = NULL;

  iter->module = parent;
}

static void
gum_v8_stalker_iterator_reset (GumV8StalkerIterator * self,
                               GumStalkerIterator * handle)
{
  self->handle = handle;

  if (self->instruction != NULL)
  {
    self->instruction->insn = NULL;
    gum_v8_stalker_release_instruction (self->module, self->instruction);
  }
  self->instruction = (handle != NULL)
      ? gum_v8_stalker_obtain_instruction (self->module)
      : NULL;
}

static gboolean
gum_v8_stalker_iterator_check_valid (GumV8StalkerIterator * self,
                                     Isolate * isolate)
{
  if (self->handle == NULL)
  {
    _gum_v8_throw (isolate, "invalid operation");
    return FALSE;
  }

  return TRUE;
}

static void
gum_v8_stalker_iterator_get_memory_access (
    GumV8StalkerIterator * self,
    const PropertyCallbackInfo<Value> & info,
    Isolate * isolate)
{
  if (!gum_v8_stalker_iterator_check_valid (self, isolate))
    return;

  Local<String> val;
  switch (gum_stalker_iterator_get_memory_access (self->handle))
  {
    case GUM_MEMORY_ACCESS_OPEN:
      val = _gum_v8_string_new_ascii (isolate, "open");
      break;
    case GUM_MEMORY_ACCESS_EXCLUSIVE:
      val = _gum_v8_string_new_ascii (isolate, "exclusive");
      break;
    default:
      g_assert_not_reached ();
  }
  info.GetReturnValue ().Set (val);
}

static void
gum_v8_stalker_iterator_next (GumV8StalkerIterator * self,
                              const FunctionCallbackInfo<Value> & info,
                              Isolate * isolate)
{
  if (!gum_v8_stalker_iterator_check_valid (self, isolate))
    return;

  if (gum_stalker_iterator_next (self->handle, &self->instruction->insn))
  {
    info.GetReturnValue ().Set (
        Local<Object>::New (isolate, *self->instruction->object));
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

static void
gum_v8_stalker_iterator_keep (GumV8StalkerIterator * self,
                              Isolate * isolate)
{
  if (!gum_v8_stalker_iterator_check_valid (self, isolate))
    return;

  gum_stalker_iterator_keep (self->handle);
}

static void
gum_v8_stalker_iterator_put_callout (GumV8StalkerIterator * self,
                                     const GumV8Args * args,
                                     Isolate * isolate)
{
  if (!gum_v8_stalker_iterator_check_valid (self, isolate))
    return;

  Local<Function> callback_js;
  GumStalkerCallout callback_c;
  gpointer user_data = NULL;
  if (!_gum_v8_args_parse (args, "F*|p", &callback_js, &callback_c, &user_data))
    return;

  if (!callback_js.IsEmpty ())
  {
    auto callout = g_slice_new (GumV8Callout);
    callout->callback = new Global<Function> (isolate, callback_js);
    callout->module = self->module;

    gum_stalker_iterator_put_callout (self->handle,
        (GumStalkerCallout) gum_v8_callout_on_invoke, callout,
        (GDestroyNotify) gum_v8_callout_free);
  }
  else
  {
    gum_stalker_iterator_put_callout (self->handle, callback_c, user_data,
        NULL);
  }
}

static void
gum_v8_stalker_iterator_put_chaining_return (GumV8StalkerIterator * self,
                                             Isolate * isolate)
{
  if (!gum_v8_stalker_iterator_check_valid (self, isolate))
    return;

  gum_stalker_iterator_put_chaining_return (self->handle);
}

static GumV8StalkerDefaultIterator *
gum_v8_stalker_default_iterator_new_persistent (GumV8Stalker * parent)
{
  auto isolate = parent->core->isolate;

  auto iter = g_slice_new (GumV8StalkerDefaultIterator);

  auto writer = &iter->parent;
  _gum_v8_default_writer_init (writer, parent->writer);

  gum_v8_stalker_iterator_init (&iter->iterator, parent);

  auto iter_value =
      Local<Object>::New (isolate, *parent->default_iterator_value);
  auto object = iter_value->Clone ();
  object->SetAlignedPointerInInternalField (0, writer);
  object->SetAlignedPointerInInternalField (1, iter);
  writer->object = new Global<Object> (isolate, object);

  return iter;
}

static void
gum_v8_stalker_default_iterator_release_persistent (
    GumV8StalkerDefaultIterator * self)
{
  auto object = self->parent.object;

  object->SetWeak (self, gum_v8_stalker_default_iterator_on_weak_notify,
      WeakCallbackType::kParameter);

  g_hash_table_add (self->iterator.module->default_iterators, self);
}

static void
gum_v8_stalker_default_iterator_on_weak_notify (
    const WeakCallbackInfo<GumV8StalkerDefaultIterator> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();

  g_hash_table_remove (self->iterator.module->default_iterators, self);
}

static void
gum_v8_stalker_default_iterator_free (GumV8StalkerDefaultIterator * self)
{
  _gum_v8_default_writer_finalize (&self->parent);

  g_slice_free (GumV8StalkerDefaultIterator, self);
}

static void
gum_v8_stalker_default_iterator_reset (GumV8StalkerDefaultIterator * self,
                                       GumStalkerIterator * handle,
                                       GumStalkerOutput * output)
{
  _gum_v8_default_writer_reset (&self->parent, (GumV8DefaultWriterImpl *)
      ((output != NULL) ? output->writer.instance : NULL));
  gum_v8_stalker_iterator_reset (&self->iterator, handle);
}

GUMJS_DEFINE_DIRECT_SUBCLASS_GETTER (
    gumjs_stalker_default_iterator_get_memory_access,
    GumV8StalkerDefaultIterator)
{
  gum_v8_stalker_iterator_get_memory_access (&self->iterator, info, isolate);
}

GUMJS_DEFINE_DIRECT_SUBCLASS_METHOD (gumjs_stalker_default_iterator_next,
                                     GumV8StalkerDefaultIterator)
{
  gum_v8_stalker_iterator_next (&self->iterator, info, isolate);
}

GUMJS_DEFINE_DIRECT_SUBCLASS_METHOD (gumjs_stalker_default_iterator_keep,
```