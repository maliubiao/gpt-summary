Response:
The user wants a summary of the provided C++ code snippet, which is part of Frida. I need to extract the functionalities implemented in this file, relate them to reverse engineering concepts, and discuss their interaction with the underlying operating system.

Here's a breakdown of how to approach this:

1. **Identify Core Classes:** Look for class definitions (using `typedef` and `struct`) like `GumV8Interceptor`, `GumV8CCallListener`, `GumV8CProbeListener`, `GumV8InvocationContext`, `GumV8InvocationArgs`, and `GumV8InvocationReturnValue`. These likely represent the main actors.

2. **Analyze Class Functionality:** Examine the methods within each class. Pay attention to methods like `init`, `dispose`, and those associated with interfaces (like `on_enter`, `on_leave`). These methods reveal the lifecycle and core operations of each class.

3. **Connect to Reverse Engineering:**  Think about how these classes facilitate interaction with target processes. The names like "interceptor," "listener," and "invocation context" strongly suggest features for hooking and observing function calls. Relate these to common reverse engineering techniques.

4. **Identify System Interactions:** Look for functions interacting with system resources or low-level concepts. Keywords like "thread ID," "return address," "CPU context," and "system error" indicate interaction with the operating system's process management and execution environment.

5. **Trace Data Flow:** Observe how data is passed and manipulated between different classes. The `GumInvocationContext` appears central to holding information about function calls. See how listeners access and potentially modify this context.

6. **Examine Memory Management:**  Note the use of `g_slice_new`, `g_slice_free`, `new`, `delete`, and weak references. This shows how Frida manages the memory associated with intercepted calls.

7. **Look for JavaScript Integration:** The "V8" in the class names and functions like `GUMJS_DEFINE_CLASS_GETTER` and `GUMJS_DEFINE_FUNCTION` indicate interaction with the V8 JavaScript engine. This is crucial for Frida's user-facing API.

8. **Infer User Actions:**  Consider how a user might trigger the functionality in this code. They would likely use Frida's JavaScript API to set up interceptors and define actions to take when functions are called.

9. **Formulate Examples:**  Create hypothetical scenarios to illustrate how the code works. For instance, show how a user might intercept a function, access its arguments, modify its return value, or get the CPU context.

10. **Address Potential Errors:** Think about common mistakes users might make when using these features, such as accessing invalid memory or mishandling resources.

11. **Synthesize the Summary:** Combine all the observations into a concise description of the file's purpose and functionalities.

**Self-Correction/Refinement during the thought process:**

* **Initial thought:** Focus solely on the `GumV8Interceptor`.
* **Correction:** Realize the listeners (`GumV8CCallListener`, `GumV8CProbeListener`) are crucial for defining the interception behavior and need equal attention.
* **Initial thought:** Only describe the high-level functionality.
* **Refinement:** Include details about memory management and the interaction with the V8 engine, as these are important aspects of the code.
* **Initial thought:**  Provide only technical descriptions.
* **Refinement:** Add user-centric examples and discuss potential user errors to make the explanation more comprehensive.
* **Initial thought:** Focus on individual functions in isolation.
* **Refinement:**  Emphasize the relationships and interactions between the different classes and how they work together to achieve the overall goal of interception.
Based on the provided C++ code snippet for `gumv8interceptor.cpp`, here's a breakdown of its functionalities, focusing on reverse engineering relevance, low-level details, logical inferences, potential user errors, and how a user reaches this code:

**归纳其功能 (Summary of Functionality):**

This code snippet defines the core components for intercepting function calls within a target process using Frida's Gum engine and integrating it with the V8 JavaScript engine. It manages the lifecycle of interceptors and the context surrounding intercepted function calls, allowing JavaScript code to observe and modify the execution flow.

**Detailed Functionalities:**

1. **Interceptor Management (`GumV8Interceptor`):**
   - Acts as a central manager for intercepting function calls. While not explicitly shown in this snippet, it likely holds data structures to track active interceptors.
   - Creates and manages persistent and cached instances of `GumV8InvocationContext`, `GumV8InvocationArgs`, and `GumV8InvocationReturnValue` to optimize performance by reusing objects.

2. **Call Interception (`GumV8CCallListener`):**
   - Represents a listener that gets notified at the entry and exit points of a function call.
   - Implements the `GumInvocationListenerInterface` with `on_enter` and `on_leave` callbacks.
   - These callbacks are triggered by the Gum engine when an intercepted function is called or returns.
   - It allows JavaScript to execute code before and after the original function call.

3. **Probe Interception (`GumV8CProbeListener`):**
   - Represents a listener that gets notified at a specific point (probe) within a function's execution.
   - Implements the `GumInvocationListenerInterface` with an `on_enter` callback (and `on_leave` is set to `NULL`, implying it only triggers at the entry point of the probe).
   - This enables finer-grained interception at arbitrary locations within a function, not just at the beginning or end.

4. **Invocation Context (`GumV8InvocationContext`):**
   - Holds information about a specific function invocation.
   - Contains a pointer to the underlying Gum's `GumInvocationContext` (`handle`).
   - Provides accessors (getters) for:
     - `return_address`: The address the function will return to.
     - `cpu_context`:  The CPU register state at the time of the call.
     - `system_error`: Any system error code associated with the call.
     - `thread_id`: The ID of the thread where the function is being executed.
     - `depth`: The call stack depth.
   - Provides setters for:
     - `system_error`: Allows modification of the system error code.
   - Allows setting arbitrary properties, making the context extensible for JavaScript.

5. **Invocation Arguments (`GumV8InvocationArgs`):**
   - Provides access to the arguments passed to the intercepted function.
   - Uses a dynamic property getter (`gumjs_invocation_args_get_nth`) and setter (`gumjs_invocation_args_set_nth`) to access individual arguments by index.
   - Allows JavaScript to inspect and modify function arguments.

6. **Invocation Return Value (`GumV8InvocationReturnValue`):**
   - Provides access to the return value of the intercepted function.
   - The `gumjs_invocation_return_value_replace` function allows JavaScript to replace the original return value with a custom one.

7. **Integration with V8:**
   - The code heavily uses V8 API (`Local<Object>`, `Isolate`, `HandleScope`, etc.) to bridge the gap between Frida's C++ core and JavaScript.
   - It creates V8 objects that wrap the underlying C++ data structures, making them accessible from JavaScript.
   - Uses internal fields in V8 objects to store pointers to the corresponding C++ objects.

**与逆向的方法的关系及举例说明 (Relationship with Reverse Engineering Methods and Examples):**

This code is fundamental to dynamic instrumentation, a core technique in reverse engineering.

* **Function Hooking:**  `GumV8CCallListener` and `GumV8CProbeListener` are the mechanisms for hooking functions. By attaching these listeners, reverse engineers can intercept function calls.
    * **Example:** A reverse engineer wants to understand how a specific encryption function works. They can use Frida to hook the entry point of this function using `Interceptor.attach()` (which would eventually use the mechanisms in this code) with `GumV8CCallListener`. In the `onEnter` callback in JavaScript, they can log the function arguments, effectively observing the input to the encryption routine.

* **Argument and Return Value Manipulation:** `GumV8InvocationArgs` and `GumV8InvocationReturnValue` enable modifying function behavior.
    * **Example:** To bypass a license check, a reverse engineer might hook a function responsible for verifying the license. Using `GumV8InvocationReturnValue`, they can force the function to always return a value indicating a valid license, regardless of the actual check's outcome.

* **Code Tracing and Analysis:**  Probe listeners (`GumV8CProbeListener`) allow for tracing execution within a function.
    * **Example:**  To pinpoint where a specific vulnerability lies, a reverse engineer can set up probes at various points within a suspect function. By logging information in the `onEnter` callback of these probes, they can trace the flow of execution and identify the exact location of the bug.

* **Context Inspection:**  Accessing `cpu_context` allows for inspecting the CPU state, which is crucial for understanding low-level operations and register usage.
    * **Example:** When analyzing packed or obfuscated code, inspecting the CPU context at certain points can reveal the actual instructions being executed after unpacking or deobfuscation.

**涉及二进制底层，linux, android内核及框架的知识及举例说明 (Involvement of Binary, Linux, Android Kernel and Framework Knowledge and Examples):**

* **Binary Level:** The code deals with raw memory addresses (`gpointer`), function pointers, and CPU registers, demonstrating a direct interaction with the target process's binary representation in memory.
    * **Example:**  Accessing the `return_address` directly operates on the stack frame, a fundamental concept in how function calls are managed at the binary level.

* **Linux/Android Kernel:** Concepts like thread IDs (`gumjs_invocation_context_get_thread_id`) and system error codes (`gumjs_invocation_context_get_system_error`) are directly related to the underlying operating system.
    * **Example:**  Analyzing the `system_error` after a function call can help understand if the function encountered any issues at the OS level, such as file access problems or permission errors.

* **Android Framework:** While not explicitly tied to Android framework APIs in this snippet, in the context of Frida on Android, the intercepted functions could be part of the Android runtime (ART) or system services. The principles here enable hooking into Java methods through the JNI interface or native Android libraries.

**逻辑推理，假设输入与输出 (Logical Inference, Assumed Inputs and Outputs):**

* **Assumption:** A JavaScript script uses Frida's API to attach an interceptor to a function named `calculate_sum` which takes two integer arguments.

* **Input (within the C++ code when the intercepted function is called):**
    - `ic->handle` (within `gum_v8_c_call_listener_on_enter`) points to a `GumInvocationContext` containing:
        - The address of the `calculate_sum` function.
        - The values of the two integer arguments.
        - The current CPU register state.
        - The return address.
    - `listener` (within `gum_v8_c_call_listener_on_enter`) points to a `GumV8CCallListener` instance associated with the JavaScript callback.

* **Output (effects of this C++ code):**
    - A `GumV8InvocationContext` object (`jic`) is created and populated with data from `ic->handle`.
    - This `jic` object is wrapped in a V8 JavaScript object and passed to the JavaScript `onEnter` callback function.
    - The JavaScript callback can then access the arguments (through `GumV8InvocationArgs`), the CPU context, and other information exposed by the V8 wrapper of `GumV8InvocationContext`.

**用户或编程常见的使用错误及举例说明 (Common User or Programming Errors and Examples):**

* **Accessing Invalid Memory:** If the JavaScript code attempts to dereference a raw pointer obtained from the `GumV8InvocationContext` or `GumV8InvocationArgs` without proper validation or understanding of memory layout, it can lead to crashes.
    * **Example:**  Incorrectly assuming the size or type of an argument and trying to access memory beyond its bounds.

* **Incorrect Argument/Return Value Manipulation:** Modifying arguments or return values with incorrect types or sizes can lead to unexpected behavior or crashes in the target process.
    * **Example:** Replacing an integer argument with a pointer without ensuring the target function expects a pointer at that position.

* **Resource Leaks:** While the code snippet shows mechanisms for releasing resources (e.g., `gum_v8_invocation_listener_release_resource`), incorrect usage in JavaScript callbacks could lead to resource leaks if persistent objects are not properly managed.

* **Invalid Operation Errors:**  Trying to access or modify the invocation context, arguments, or return value after the interception point has passed can result in errors (as indicated by the checks in the getter/setter functions).
    * **Example:** Trying to modify an argument in the `onLeave` callback of a `GumV8CCallListener`, which might be too late in the execution flow.

**用户操作是如何一步步的到达这里，作为调试线索 (How User Operations Reach This Code as Debugging Clues):**

1. **User Writes Frida Script:** The user starts by writing a JavaScript script using Frida's API. This script might use `Interceptor.attach()` to hook a specific function.
2. **Frida Processes the Script:** When the script is executed, Frida's JavaScript engine (V8) interprets the `Interceptor.attach()` call.
3. **Binding to Gum:** Frida's JavaScript bindings translate the `Interceptor.attach()` call into a request to the underlying Gum engine.
4. **Gum Sets Up Interceptor:** Gum then sets up the actual interception mechanism at the target function's address. This involves creating either a `GumV8CCallListener` or `GumV8CProbeListener` (depending on the type of interception).
5. **Target Function is Called:** When the target function is executed in the target process, Gum's interception mechanism kicks in.
6. **Listener Notification:** Gum calls the `on_enter` (or `on_leave`) method of the appropriate listener (`GumV8CCallListener` or `GumV8CProbeListener`). This is where the code in this snippet becomes active.
7. **Context Creation:**  Functions like `_gum_v8_interceptor_obtain_invocation_context` are called to create or retrieve a `GumV8InvocationContext`.
8. **Data Population:** The `GumInvocationContext` (from Gum's core) is used to populate the `GumV8InvocationContext` with details about the function call.
9. **V8 Object Creation:**  V8 objects are created to wrap the `GumV8InvocationContext`, `GumV8InvocationArgs`, and `GumV8InvocationReturnValue`.
10. **JavaScript Callback:** These V8 objects are passed to the user-defined JavaScript callback function.

**Debugging Clues:** If a user encounters issues, understanding this flow can provide valuable debugging clues:

* **Crash in `onEnter`/`onLeave`:** Indicates a problem within the JavaScript callback or how the V8 objects are being used.
* **Incorrect Argument Values:** Might point to issues with how the arguments are being accessed or interpreted in the JavaScript code, or potentially a problem in Gum's argument extraction.
* **Unexpected Return Values:** Could be due to incorrect manipulation of the return value in the JavaScript `onLeave` callback.
* **Performance Issues:** Might be related to excessive creation of persistent objects or inefficient JavaScript callback code.

This detailed breakdown provides a comprehensive understanding of the functionalities within the `gumv8interceptor.cpp` file and its crucial role in Frida's dynamic instrumentation capabilities.

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8interceptor.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
LL);
  _gum_v8_interceptor_release_invocation_context (module, jic);
}

static void
gum_v8_c_call_listener_class_init (GumV8CCallListenerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_c_call_listener_dispose;
}

static void
gum_v8_c_call_listener_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  auto iface = (GumInvocationListenerInterface *) g_iface;

  iface->on_enter = gum_v8_c_call_listener_on_enter;
  iface->on_leave = gum_v8_c_call_listener_on_leave;
}

static void
gum_v8_c_call_listener_init (GumV8CCallListener * self)
{
}

static void
gum_v8_c_call_listener_dispose (GObject * object)
{
  auto base_listener = GUM_V8_INVOCATION_LISTENER (object);

  {
    ScriptScope scope (base_listener->module->core->script);

    gum_v8_invocation_listener_release_resource (base_listener);
  }

  G_OBJECT_CLASS (gum_v8_c_call_listener_parent_class)->dispose (object);
}

static void
gum_v8_c_call_listener_on_enter (GumInvocationListener * listener,
                                 GumInvocationContext * ic)
{
  auto self = GUM_V8_C_CALL_LISTENER_CAST (listener);

  if (self->on_enter != NULL)
    self->on_enter (ic);
}

static void
gum_v8_c_call_listener_on_leave (GumInvocationListener * listener,
                                 GumInvocationContext * ic)
{
  auto self = GUM_V8_C_CALL_LISTENER_CAST (listener);

  if (self->on_leave != NULL)
    self->on_leave (ic);
}

static void
gum_v8_c_probe_listener_class_init (GumV8CProbeListenerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_c_probe_listener_dispose;
}

static void
gum_v8_c_probe_listener_iface_init (gpointer g_iface,
                                    gpointer iface_data)
{
  auto iface = (GumInvocationListenerInterface *) g_iface;

  iface->on_enter = gum_v8_c_probe_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_v8_c_probe_listener_init (GumV8CProbeListener * self)
{
}

static void
gum_v8_c_probe_listener_dispose (GObject * object)
{
  auto base_listener = GUM_V8_INVOCATION_LISTENER (object);

  {
    ScriptScope scope (base_listener->module->core->script);

    gum_v8_invocation_listener_release_resource (base_listener);
  }

  G_OBJECT_CLASS (gum_v8_c_probe_listener_parent_class)->dispose (object);
}

static void
gum_v8_c_probe_listener_on_enter (GumInvocationListener * listener,
                                  GumInvocationContext * ic)
{
  GUM_V8_C_PROBE_LISTENER_CAST (listener)->on_hit (ic);
}

static GumV8InvocationContext *
gum_v8_invocation_context_new_persistent (GumV8Interceptor * parent)
{
  auto isolate = parent->core->isolate;

  auto jic = g_slice_new (GumV8InvocationContext);

  auto invocation_context_value = Local<Object>::New (isolate,
      *parent->invocation_context_value);
  auto object = invocation_context_value->Clone ();
  object->SetAlignedPointerInInternalField (0, jic);
  jic->object = new Global<Object> (isolate, object);
  jic->handle = NULL;
  jic->cpu_context = nullptr;
  jic->dirty = FALSE;

  jic->module = parent;

  return jic;
}

static void
gum_v8_invocation_context_release_persistent (GumV8InvocationContext * self)
{
  self->object->SetWeak (self, gum_v8_invocation_context_on_weak_notify,
      WeakCallbackType::kParameter);

  g_hash_table_add (self->module->invocation_context_values, self);
}

static void
gum_v8_invocation_context_on_weak_notify (
    const WeakCallbackInfo<GumV8InvocationContext> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();

  g_hash_table_remove (self->module->invocation_context_values, self);
}

static void
gum_v8_invocation_context_free (GumV8InvocationContext * self)
{
  delete self->object;

  g_slice_free (GumV8InvocationContext, self);
}

void
_gum_v8_invocation_context_reset (GumV8InvocationContext * self,
                                  GumInvocationContext * handle)
{
  self->handle = handle;

  if (self->cpu_context != nullptr)
  {
    _gum_v8_cpu_context_free_later (self->cpu_context, self->module->core);
    self->cpu_context = nullptr;
  }
}

static gboolean
gum_v8_invocation_context_check_valid (GumV8InvocationContext * self,
                                       Isolate * isolate)
{
  if (self->handle == NULL)
  {
    _gum_v8_throw (isolate, "invalid operation");
    return FALSE;
  }

  return TRUE;
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_return_address,
                           GumV8InvocationContext)
{
  if (!gum_v8_invocation_context_check_valid (self, isolate))
    return;

  auto return_address =
      gum_invocation_context_get_return_address (self->handle);
  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (return_address, core));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_cpu_context,
                           GumV8InvocationContext)
{
  if (!gum_v8_invocation_context_check_valid (self, isolate))
    return;

  auto context = self->cpu_context;
  if (context == nullptr)
  {
    context = new Global<Object> (isolate,
        _gum_v8_cpu_context_new_mutable (self->handle->cpu_context, core));
    self->cpu_context = context;
  }

  info.GetReturnValue ().Set (Local<Object>::New (isolate, *context));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_system_error,
                           GumV8InvocationContext)
{
  if (!gum_v8_invocation_context_check_valid (self, isolate))
    return;

  info.GetReturnValue ().Set (self->handle->system_error);
}

GUMJS_DEFINE_CLASS_SETTER (gumjs_invocation_context_set_system_error,
                           GumV8InvocationContext)
{
  if (!gum_v8_invocation_context_check_valid (self, isolate))
    return;

  gint system_error;
  if (!_gum_v8_int_get (value, &system_error, core))
    return;

  self->handle->system_error = system_error;
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_thread_id,
                           GumV8InvocationContext)
{
  if (!gum_v8_invocation_context_check_valid (self, isolate))
    return;

  info.GetReturnValue ().Set (
      gum_invocation_context_get_thread_id (self->handle));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_invocation_context_get_depth,
                           GumV8InvocationContext)
{
  if (!gum_v8_invocation_context_check_valid (self, isolate))
    return;

  info.GetReturnValue ().Set (
      (int32_t) gum_invocation_context_get_depth (self->handle));
}

static void
gumjs_invocation_context_set_property (Local<Name> property,
                                       Local<Value> value,
                                       const PropertyCallbackInfo<Value> & info)
{
  auto holder = info.Holder ();
  auto self =
      (GumV8InvocationContext *) holder->GetAlignedPointerFromInternalField (0);
  auto module =
      (GumV8Interceptor *) info.Data ().As<External> ()->Value ();

  if (holder == *module->cached_invocation_context->object)
  {
    module->cached_invocation_context =
        gum_v8_invocation_context_new_persistent (module);
    module->cached_invocation_context_in_use = FALSE;
  }

  self->dirty = TRUE;
}

static GumV8InvocationArgs *
gum_v8_invocation_args_new_persistent (GumV8Interceptor * parent)
{
  auto isolate = parent->core->isolate;

  auto args = g_slice_new (GumV8InvocationArgs);

  auto invocation_args_value = Local<Object>::New (isolate,
      *parent->invocation_args_value);
  auto object = invocation_args_value->Clone ();
  object->SetAlignedPointerInInternalField (0, args);
  args->object = new Global<Object> (isolate, object);
  args->ic = NULL;

  args->module = parent;

  return args;
}

static void
gum_v8_invocation_args_release_persistent (GumV8InvocationArgs * self)
{
  self->object->SetWeak (self, gum_v8_invocation_args_on_weak_notify,
      WeakCallbackType::kParameter);

  g_hash_table_add (self->module->invocation_args_values, self);
}

static void
gum_v8_invocation_args_on_weak_notify (
    const WeakCallbackInfo<GumV8InvocationArgs> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();

  g_hash_table_remove (self->module->invocation_args_values, self);
}

static void
gum_v8_invocation_args_free (GumV8InvocationArgs * self)
{
  delete self->object;

  g_slice_free (GumV8InvocationArgs, self);
}

static void
gum_v8_invocation_args_reset (GumV8InvocationArgs * self,
                              GumInvocationContext * ic)
{
  self->ic = ic;
}

template<typename T>
static GumV8InvocationArgs *
gum_v8_invocation_args_get (const PropertyCallbackInfo<T> & info)
{
  return (GumV8InvocationArgs *)
      info.Holder ()->GetAlignedPointerFromInternalField (0);
}

static void
gumjs_invocation_args_get_nth (uint32_t index,
                               const PropertyCallbackInfo<Value> & info)
{
  auto self = gum_v8_invocation_args_get (info);
  auto core = self->module->core;

  if (self->ic == NULL)
  {
    _gum_v8_throw_ascii_literal (core->isolate, "invalid operation");
    return;
  }

  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (
      gum_invocation_context_get_nth_argument (self->ic, index), core));
}

static void
gumjs_invocation_args_set_nth (uint32_t index,
                               Local<Value> value,
                               const PropertyCallbackInfo<Value> & info)
{
  auto self = gum_v8_invocation_args_get (info);
  auto core = self->module->core;

  if (self->ic == NULL)
  {
    _gum_v8_throw_ascii_literal (core->isolate, "invalid operation");
    return;
  }

  info.GetReturnValue ().Set (value);

  gpointer raw_value;
  if (!_gum_v8_native_pointer_get (value, &raw_value, core))
    return;

  gum_invocation_context_replace_nth_argument (self->ic, index, raw_value);
}

static GumV8InvocationReturnValue *
gum_v8_invocation_return_value_new_persistent (GumV8Interceptor * parent)
{
  auto isolate = parent->core->isolate;

  auto retval = g_slice_new (GumV8InvocationReturnValue);

  auto template_object = Local<Object>::New (isolate,
      *parent->invocation_return_value);
  auto object = template_object->Clone ();
  object->SetAlignedPointerInInternalField (1, retval);
  retval->object = new Global<Object> (isolate, object);
  retval->ic = NULL;

  retval->module = parent;

  return retval;
}

static void
gum_v8_invocation_return_value_release_persistent (
    GumV8InvocationReturnValue * self)
{
  self->object->SetWeak (self, gum_v8_invocation_return_value_on_weak_notify,
      WeakCallbackType::kParameter);

  g_hash_table_add (self->module->invocation_return_values, self);
}

static void
gum_v8_invocation_return_value_on_weak_notify (
    const WeakCallbackInfo<GumV8InvocationReturnValue> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();

  g_hash_table_remove (self->module->invocation_return_values, self);
}

static void
gum_v8_invocation_return_value_free (GumV8InvocationReturnValue * self)
{
  delete self->object;

  g_slice_free (GumV8InvocationReturnValue, self);
}

static void
gum_v8_invocation_return_value_reset (GumV8InvocationReturnValue * self,
                                      GumInvocationContext * ic)
{
  self->ic = ic;
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_return_value_replace)
{
  auto wrapper = info.Holder ();
  auto self = (GumV8InvocationReturnValue *)
      wrapper->GetAlignedPointerFromInternalField (1);

  if (self->ic == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid operation");
    return;
  }

  gpointer value;
  if (!_gum_v8_args_parse (args, "p~", &value))
    return;

  wrapper->SetInternalField (0,
      BigInt::NewFromUnsigned (isolate, GPOINTER_TO_SIZE (value)));

  gum_invocation_context_replace_return_value (self->ic, value);
}

GumV8InvocationContext *
_gum_v8_interceptor_obtain_invocation_context (GumV8Interceptor * self)
{
  GumV8InvocationContext * jic;

  if (!self->cached_invocation_context_in_use)
  {
    jic = self->cached_invocation_context;
    self->cached_invocation_context_in_use = TRUE;
  }
  else
  {
    jic = gum_v8_invocation_context_new_persistent (self);
  }

  return jic;
}

void
_gum_v8_interceptor_release_invocation_context (GumV8Interceptor * self,
                                                GumV8InvocationContext * jic)
{
  if (jic == self->cached_invocation_context)
    self->cached_invocation_context_in_use = FALSE;
  else
    gum_v8_invocation_context_release_persistent (jic);
}

static GumV8InvocationArgs *
gum_v8_interceptor_obtain_invocation_args (GumV8Interceptor * self)
{
  GumV8InvocationArgs * args;

  if (!self->cached_invocation_args_in_use)
  {
    args = self->cached_invocation_args;
    self->cached_invocation_args_in_use = TRUE;
  }
  else
  {
    args = gum_v8_invocation_args_new_persistent (self);
  }

  return args;
}

static void
gum_v8_interceptor_release_invocation_args (GumV8Interceptor * self,
                                            GumV8InvocationArgs * args)
{
  if (args == self->cached_invocation_args)
    self->cached_invocation_args_in_use = FALSE;
  else
    gum_v8_invocation_args_release_persistent (args);
}

static GumV8InvocationReturnValue *
gum_v8_interceptor_obtain_invocation_return_value (GumV8Interceptor * self)
{
  GumV8InvocationReturnValue * retval;

  if (!self->cached_invocation_return_value_in_use)
  {
    retval = self->cached_invocation_return_value;
    self->cached_invocation_return_value_in_use = TRUE;
  }
  else
  {
    retval = gum_v8_invocation_return_value_new_persistent (self);
  }

  return retval;
}

static void
gum_v8_interceptor_release_invocation_return_value (
    GumV8Interceptor * self,
    GumV8InvocationReturnValue * retval)
{
  if (retval == self->cached_invocation_return_value)
    self->cached_invocation_return_value_in_use = FALSE;
  else
    gum_v8_invocation_return_value_release_persistent (retval);
}
```