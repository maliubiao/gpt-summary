Response:
The user wants a summary of the functionality of the provided C code snippet, which is part of Frida's dynamic instrumentation tool. I need to analyze the code and extract its key features, focusing on:

1. **Core Functionality:** What does this code do at a high level?
2. **Relationship to Reversing:** How does this code facilitate reverse engineering?
3. **Low-Level Interactions:** What aspects of the OS, kernel, or hardware does it touch?
4. **Logic and Data Flow:**  What are the inputs and outputs of its operations?
5. **Common User Errors:** What mistakes might developers make when using this code?
6. **User Journey:** How does a user's interaction lead to this code being executed?
7. **Overall Summary:** A concise recap of its purpose.

**Plan:**

1. **Identify Key Data Structures:** Look for `struct` definitions and how they are used.
2. **Analyze Functions:** Understand the purpose of each function and its interactions with other functions. Pay close attention to functions prefixed with `gum_quick_`.
3. **Trace Execution Flow:**  Follow how data is passed between functions, especially related to invocation contexts and arguments.
4. **Look for System Calls or Low-Level APIs:**  Identify interactions with operating system primitives if present.
5. **Consider the Context of Frida:** Remember that this code is part of a dynamic instrumentation framework, so its purpose is likely related to intercepting and modifying function calls.
6. **Infer User Interaction:**  Think about how a Frida user would configure or initiate the interception process.
7. **Synthesize the Information:** Combine the analysis into clear, concise explanations for each of the user's requests.

**Key Observations from the Code:**

* **`GumQuickInterceptor`:** A central structure likely responsible for managing interception.
* **`GumInvocationContext`:**  Represents the context of a function call (arguments, return address, CPU context, etc.).
* **`GumInvocationArgs`:**  Holds the arguments passed to the intercepted function.
* **`GumInvocationRetval`:**  Stores the return value of the intercepted function.
* **Listeners (`GumQuickCCallListener`, `GumQuickCProbeListener`):**  Handle events at the entry and exit of intercepted functions.
* **JavaScript Integration:** The code interacts with a JavaScript engine (likely QuickJS, given the `JSValue` and `JSContext` types).
* **Caching:** There's evidence of caching invocation contexts, arguments, and return values for performance.
* **`_gum_quick_scope_enter`/`_gum_quick_scope_leave`:**  Likely manages a scope or context, possibly related to error handling or resource management.

**Detailed Analysis of Function Groups:**

* **Listener Functions (`gum_quick_c_call_listener_*`, `gum_quick_c_probe_listener_*`):** These functions define how Frida reacts when an intercepted function is called. `on_enter` is executed before the original function, and `on_leave` is executed after. `CProbeListener` only has `on_enter`.
* **Invocation Context Functions (`gum_quick_invocation_context_*`):** These functions manage the `GumInvocationContext` object, allowing access to and modification of the function call's state (arguments, return address, CPU context, etc.). The `getters` and `setters` expose these properties to the JavaScript side.
* **Invocation Arguments Functions (`gum_quick_invocation_args_*`):**  These handle the `GumInvocationArgs` object, providing access to the function's arguments. The `get_property` and `set_property` functions enable accessing and modifying arguments via array-like syntax in JavaScript.
* **Invocation Return Value Functions (`gum_quick_invocation_retval_*`):**  These manage the `GumQuickInvocationRetval` object, allowing access to and modification of the function's return value.
* **Interceptor Functions (`_gum_quick_interceptor_obtain_*`, `_gum_quick_interceptor_release_*`):** These functions handle the creation, retrieval, and caching of the context, arguments, and return value objects.

By systematically analyzing these components, I can address each of the user's questions.
这是 `gumquickinterceptor.c` 文件的第二部分，继续分析其功能。

**归纳其功能：**

这部分代码主要负责管理 Frida 中快速拦截器 (`GumQuickInterceptor`) 的核心数据结构和生命周期，以及 C 函数调用和探测 (probe) 的监听器实现。它将 C 函数调用的上下文信息（参数、返回值、CPU 状态等）暴露给 JavaScript 环境，并允许 JavaScript 代码在 C 函数调用前后进行检查和修改。

更具体地说，这部分代码的功能可以归纳为：

1. **管理调用上下文 (Invocation Context):**
   - 创建、销毁和重置 `GumQuickInvocationContext` 结构体，该结构体封装了 C 函数调用的上下文信息，例如返回地址、CPU 上下文、系统错误码、线程 ID 和调用深度。
   - 提供 JavaScript 访问和修改这些上下文信息的接口 (getters 和 setters)。
   - 实现了惰性加载 CPU 上下文，只有在 JavaScript 代码尝试访问时才会创建和填充。
   - 维护一个缓存的调用上下文对象，以提高性能。

2. **管理调用参数 (Invocation Arguments):**
   - 创建、销毁和重置 `GumQuickInvocationArgs` 结构体，用于表示 C 函数调用的参数。
   - 提供 JavaScript 访问和修改函数参数的接口，可以通过索引像访问数组一样访问参数。
   - 同样维护一个缓存的调用参数对象。

3. **管理返回值 (Invocation Return Value):**
   - 创建、销毁和重置 `GumQuickInvocationRetval` 结构体，用于表示 C 函数调用的返回值。
   - 提供 JavaScript 访问和修改返回值的接口。
   - 同样维护一个缓存的返回值对象。

4. **实现 C 函数调用监听器 (`GumQuickCCallListener`):**
   - 定义了 `GumQuickCCallListener` 类，用于监听 C 函数的调用。
   - 提供了 `on_enter` 和 `on_leave` 回调函数，分别在 C 函数执行前和执行后被调用。
   - 在这些回调中，会将调用上下文和参数传递给预先注册的 JavaScript 回调函数。

5. **实现 C 函数探测监听器 (`GumQuickCProbeListener`):**
   - 定义了 `GumQuickCProbeListener` 类，用于在 C 函数的入口处进行探测。
   - 只提供了 `on_enter` 回调函数，在 C 函数执行前被调用。
   - 类似于 C 函数调用监听器，会将调用上下文传递给 JavaScript 回调。

6. **对象生命周期管理:**
   - 提供了 `dispose` 方法来释放监听器占用的资源。
   - 使用 GLib 的对象系统进行内存管理。

**与逆向方法的关系及举例说明：**

这段代码是 Frida 动态插桩的核心部分，直接支持逆向分析人员在运行时检查和修改程序的行为。

**举例：**

假设你要逆向一个 C 函数 `int calculate(int a, int b)`，你想在调用该函数时查看它的参数，并在函数返回前修改返回值。

1. **Hook 函数:** 使用 Frida 的 JavaScript API，你可以 hook 这个 `calculate` 函数。
2. **进入 `on_enter`:** 当程序执行到 `calculate` 函数时，`gum_quick_c_call_listener_on_enter` 会被调用。
3. **访问参数:** 在 JavaScript 的 `onEnter` 回调中，你可以通过 `arguments[0]` 和 `arguments[1]` 访问到 `a` 和 `b` 的值，这得益于 `gum_quick_invocation_args_get_property` 函数将 C 层的参数暴露出来。
4. **进入 `on_leave`:** 函数执行完毕即将返回时，`gum_quick_c_call_listener_on_leave` 会被调用。
5. **访问和修改返回值:** 在 JavaScript 的 `onLeave` 回调中，你可以通过访问 `retval.value` 获取原始返回值，并使用 `retval.replace(newValue)` 修改返回值，这对应于 `gumjs_invocation_retval_replace` 函数的功能。

**涉及到的二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **二进制底层:**
    * **CPU 上下文:**  `gum_quick_invocation_context_get_cpu_context` 和相关的代码涉及到获取和操作 CPU 寄存器的值。这需要了解目标架构的寄存器定义和调用约定。例如，在 x86-64 架构上，函数参数通常通过寄存器传递（如 `rdi`, `rsi`, `rdx`, `rcx`, `r8`, `r9`）。
    * **内存地址:** 代码中传递和操作的是内存地址，例如函数参数和返回值的地址。逆向工程师需要理解进程的内存布局。
* **Linux/Android 内核:**
    * **系统调用错误码:** `gumjs_invocation_context_get_system_error` 和 `gumjs_invocation_context_set_system_error` 允许访问和修改系统调用的错误码。这需要了解 Linux/Android 的系统调用机制和错误码的含义。
    * **线程 ID:** `gumjs_invocation_context_get_thread_id` 涉及获取当前线程的 ID，这依赖于操作系统提供的线程管理机制。
* **框架知识:**
    * **Frida 的内部机制:**  这段代码是 Frida `gum` 库的一部分，它负责底层的代码注入和拦截。理解 Frida 的架构有助于理解这段代码的作用。
    * **JavaScript 引擎集成:** 代码与 JavaScript 引擎 (QuickJS) 集成，需要理解 JavaScript 和 C 之间的数据类型转换和交互方式。

**逻辑推理、假设输入与输出：**

**假设输入:**

1. **JavaScript 代码:**  使用 Frida API hook 了一个 C 函数 `void process_data(int *data, size_t size)`.
2. **程序执行到被 hook 的函数:** 当程序调用 `process_data` 时。

**逻辑推理过程:**

1. **`gum_quick_c_call_listener_on_enter` 被调用:**  Frida 的拦截机制会触发这个函数。
2. **获取调用上下文和参数:**  `_gum_quick_interceptor_obtain_invocation_context` 和 `gum_quick_interceptor_obtain_invocation_args` 被调用，获取或创建用于表示当前函数调用的上下文和参数的对象。
3. **重置上下文和参数对象:**  `_gum_quick_invocation_context_reset` 和 `gum_quick_invocation_args_reset` 使用当前的调用信息填充这些对象。
4. **调用 JavaScript `onEnter` 回调:**  `_gum_quick_scope_call_void` 执行 JavaScript 代码，并将封装了上下文和参数的对象传递给 `onEnter` 回调。
5. **JavaScript 代码访问参数:**  在 `onEnter` 回调中，JavaScript 可以通过类似 `args[0]` 访问 `data` 指针，通过 `args[1]` 访问 `size`。`gumjs_invocation_args_get_property` 会被调用，根据索引获取对应的参数。
6. **`gum_quick_c_call_listener_on_leave` 被调用 (假设存在 `onLeave` 回调):**  在 C 函数执行完毕后。
7. **获取返回值对象:** `gum_quick_interceptor_obtain_invocation_retval` 被调用。
8. **重置返回值对象:** `gum_quick_invocation_retval_reset` 使用当前的返回值填充对象。
9. **调用 JavaScript `onLeave` 回调:**  `_gum_quick_scope_call_void` 执行 JavaScript 代码，并将封装了返回值的对象传递给 `onLeave` 回调。
10. **JavaScript 代码访问返回值 (如果函数有返回值):** 在 `onLeave` 回调中，JavaScript 可以通过 `retval.value` 访问返回值。

**假设输出 (在 JavaScript `onEnter` 中):**

如果 `data` 指向的地址为 `0x12345678`，`size` 的值为 `10`，那么在 JavaScript 的 `onEnter` 回调中，`args[0]` 可能会返回一个表示 `0x12345678` 的 Frida NativePointer 对象，`args[1]` 可能会返回数字 `10`。

**涉及用户或编程常见的使用错误及举例说明：**

1. **在 `onEnter` 中修改只读的上下文信息:** 某些上下文信息（如返回地址）可能被标记为只读。尝试在 `onEnter` 中修改这些信息可能会导致程序崩溃或其他不可预测的行为。
2. **错误地访问参数索引:** 如果被 hook 的函数参数数量少于 JavaScript 代码尝试访问的索引，会导致访问越界或错误。例如，如果函数只有两个参数，尝试访问 `args[2]` 会出错。
3. **忘记释放资源 (虽然这部分代码主要负责管理内部资源):**  在更高级的 Frida 使用中，用户可能会分配一些需要在 hook 逻辑结束后释放的资源。如果忘记释放，可能会导致内存泄漏。
4. **在 `onLeave` 中访问已经被释放的参数:**  在 `onLeave` 回调中，如果尝试访问 `args` 对象，可能会因为其内部数据已经被重置或释放而导致错误。应该主要关注 `retval` 对象。
5. **类型不匹配地修改参数或返回值:**  如果 C 函数期望一个整数，而 JavaScript 代码尝试用一个字符串替换，可能会导致类型错误或程序崩溃。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **编写 Frida JavaScript 脚本:** 用户首先会编写一个 JavaScript 脚本，使用 Frida 的 API 来 hook 目标进程中的某个 C 函数。例如：

   ```javascript
   Interceptor.attach(Module.findExportByName(null, "my_c_function"), {
     onEnter: function(args) {
       console.log("Entering my_c_function");
       console.log("Argument 0:", args[0]);
     },
     onLeave: function(retval) {
       console.log("Leaving my_c_function");
       console.log("Return value:", retval);
     }
   });
   ```

2. **运行 Frida:** 用户使用 Frida 命令行工具或 API 将该脚本注入到目标进程中。例如：

   ```bash
   frida -p <process_id> -l my_script.js
   ```

3. **目标进程执行到被 hook 的函数:** 当目标进程执行到 `my_c_function` 时，Frida 的拦截机制会介入。

4. **`Interceptor.attach` 触发 `GumInterceptor` 的创建:**  `Interceptor.attach`  在底层会创建或配置一个 `GumInterceptor` 对象来管理对目标函数的拦截。

5. **`onEnter` 触发 `gum_quick_c_call_listener_on_enter`:**  当目标函数被调用，并且执行到函数入口时，与该 hook 关联的 `GumQuickCCallListener` 的 `on_enter` 方法会被 Frida 的引擎调用。

6. **执行 `gum_quick_c_call_listener_on_enter` 中的逻辑:**  这就是提供的代码片段开始执行的地方。它负责获取调用上下文、参数，并将它们传递给 JavaScript 的 `onEnter` 回调。

7. **JavaScript `onEnter` 回调执行:**  用户在 JavaScript 脚本中定义的 `onEnter` 函数会被执行，可以访问和操作传递进来的参数。

8. **目标函数继续执行 (如果 `onEnter` 没有阻止):**  在 `onEnter` 执行完毕后，目标 C 函数会继续执行。

9. **`onLeave` 触发 `gum_quick_c_call_listener_on_leave`:** 当目标 C 函数执行完毕并即将返回时，`gum_quick_c_call_listener_on_leave` 方法会被调用。

10. **执行 `gum_quick_c_call_listener_on_leave` 中的逻辑:**  这个方法负责获取返回值，并将其传递给 JavaScript 的 `onLeave` 回调。

11. **JavaScript `onLeave` 回调执行:**  用户在 JavaScript 脚本中定义的 `onLeave` 函数会被执行，可以访问和操作返回值。

因此，这段 C 代码是 Frida 实现动态插桩的核心组成部分，用户通过编写和运行 Frida JavaScript 脚本来触发其执行，从而实现对目标进程函数调用的监控和修改。 作为调试线索，理解这段代码的功能有助于分析 Frida hook 的底层行为，排查 hook 失败或行为异常的问题。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickinterceptor.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
_CAST (listener);
  parent = GUM_QUICK_INVOCATION_LISTENER_CAST (listener)->parent;

  _gum_quick_scope_enter (&scope, parent->core);

  jic = _gum_quick_interceptor_obtain_invocation_context (parent);
  _gum_quick_invocation_context_reset (jic, ic);

  args = gum_quick_interceptor_obtain_invocation_args (parent);
  gum_quick_invocation_args_reset (args, ic);

  _gum_quick_scope_call_void (&scope, self->on_hit, jic->wrapper, 1,
      &args->wrapper);

  gum_quick_invocation_args_reset (args, NULL);
  gum_quick_interceptor_release_invocation_args (parent, args);

  _gum_quick_invocation_context_reset (jic, NULL);
  _gum_quick_interceptor_release_invocation_context (parent, jic);

  _gum_quick_scope_leave (&scope);
}

static void
gum_quick_c_call_listener_class_init (GumQuickCCallListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_c_call_listener_dispose;
}

static void
gum_quick_c_call_listener_iface_init (gpointer g_iface,
                                      gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_quick_c_call_listener_on_enter;
  iface->on_leave = gum_quick_c_call_listener_on_leave;
}

static void
gum_quick_c_call_listener_init (GumQuickCCallListener * self)
{
}

static void
gum_quick_c_call_listener_dispose (GObject * object)
{
  GumQuickInvocationListener * base_listener;
  GumQuickCore * core;
  GumQuickScope scope;

  base_listener = GUM_QUICK_INVOCATION_LISTENER (object);
  core = base_listener->parent->core;

  _gum_quick_scope_enter (&scope, core);

  gum_quick_invocation_listener_release_wrapper (base_listener, core->ctx);

  _gum_quick_scope_leave (&scope);

  G_OBJECT_CLASS (gum_quick_c_call_listener_parent_class)->dispose (object);
}

static void
gum_quick_c_call_listener_on_enter (GumInvocationListener * listener,
                                    GumInvocationContext * ic)
{
  GumQuickCCallListener * self = GUM_QUICK_C_CALL_LISTENER_CAST (listener);

  if (self->on_enter != NULL)
    self->on_enter (ic);
}

static void
gum_quick_c_call_listener_on_leave (GumInvocationListener * listener,
                                    GumInvocationContext * ic)
{
  GumQuickCCallListener * self = GUM_QUICK_C_CALL_LISTENER_CAST (listener);

  if (self->on_leave != NULL)
    self->on_leave (ic);
}

static void
gum_quick_c_probe_listener_class_init (GumQuickCProbeListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_c_probe_listener_dispose;
}

static void
gum_quick_c_probe_listener_iface_init (gpointer g_iface,
                                       gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_quick_c_probe_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_quick_c_probe_listener_init (GumQuickCProbeListener * self)
{
}

static void
gum_quick_c_probe_listener_dispose (GObject * object)
{
  GumQuickInvocationListener * base_listener;
  GumQuickCore * core;
  GumQuickScope scope;

  base_listener = GUM_QUICK_INVOCATION_LISTENER (object);
  core = base_listener->parent->core;

  _gum_quick_scope_enter (&scope, core);

  gum_quick_invocation_listener_release_wrapper (base_listener, core->ctx);

  _gum_quick_scope_leave (&scope);

  G_OBJECT_CLASS (gum_quick_c_probe_listener_parent_class)->dispose (object);
}

static void
gum_quick_c_probe_listener_on_enter (GumInvocationListener * listener,
                                     GumInvocationContext * ic)
{
  GUM_QUICK_C_PROBE_LISTENER_CAST (listener)->on_hit (ic);
}

static JSValue
gum_quick_invocation_context_new (GumQuickInterceptor * parent,
                                  GumQuickInvocationContext ** context)
{
  JSContext * ctx = parent->core->ctx;
  JSValue wrapper;
  GumQuickInvocationContext * jic;

  wrapper = JS_NewObjectClass (ctx, parent->invocation_context_class);

  jic = g_slice_new (GumQuickInvocationContext);
  jic->wrapper = wrapper;
  jic->handle = NULL;
  jic->cpu_context = NULL;
  jic->initial_property_count = JS_GetOwnPropertyCountUnchecked (wrapper);
  jic->interceptor = parent;

  JS_SetOpaque (wrapper, jic);

  *context = jic;

  return wrapper;
}

static void
gum_quick_invocation_context_release (GumQuickInvocationContext * self)
{
  JS_FreeValue (self->interceptor->core->ctx, self->wrapper);
}

void
_gum_quick_invocation_context_reset (GumQuickInvocationContext * self,
                                     GumInvocationContext * handle)
{
  self->handle = handle;

  if (self->cpu_context != NULL)
  {
    _gum_quick_cpu_context_make_read_only (self->cpu_context);
    JS_FreeValue (self->interceptor->core->ctx, self->cpu_context->wrapper);
    self->cpu_context = NULL;
  }
}

static gboolean
gum_quick_invocation_context_get (JSContext * ctx,
                                  JSValueConst val,
                                  GumQuickCore * core,
                                  GumQuickInvocationContext ** ic)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->invocation_context_class, core,
      (gpointer *) ic);
}

static gboolean
gum_quick_invocation_context_is_dirty (GumQuickInvocationContext * self)
{
  return JS_GetOwnPropertyCountUnchecked (self->wrapper) !=
      self->initial_property_count;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_context_finalize)
{
  GumQuickInvocationContext * c;

  c = JS_GetOpaque (val,
      gumjs_get_parent_module (core)->invocation_context_class);
  if (c == NULL)
    return;

  g_slice_free (GumQuickInvocationContext, c);
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_return_address)
{
  GumQuickInvocationContext * self;

  if (!gum_quick_invocation_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return _gum_quick_native_pointer_new (ctx,
      gum_invocation_context_get_return_address (self->handle), core);
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_cpu_context)
{
  GumQuickInvocationContext * self;

  if (!gum_quick_invocation_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (self->cpu_context == NULL)
  {
    _gum_quick_cpu_context_new (ctx, self->handle->cpu_context,
        GUM_CPU_CONTEXT_READWRITE, core, &self->cpu_context);
  }

  return JS_DupValue (ctx, self->cpu_context->wrapper);
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_system_error)
{
  GumQuickInvocationContext * self;

  if (!gum_quick_invocation_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewInt32 (ctx, self->handle->system_error);
}

GUMJS_DEFINE_SETTER (gumjs_invocation_context_set_system_error)
{
  GumQuickInvocationContext * self;
  gint value;

  if (!gum_quick_invocation_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_int_get (ctx, val, &value))
    return JS_EXCEPTION;

  self->handle->system_error = value;

  return JS_UNDEFINED;
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_thread_id)
{
  GumQuickInvocationContext * self;

  if (!gum_quick_invocation_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewUint32 (ctx,
      gum_invocation_context_get_thread_id (self->handle));
}

GUMJS_DEFINE_GETTER (gumjs_invocation_context_get_depth)
{
  GumQuickInvocationContext * self;

  if (!gum_quick_invocation_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewUint32 (ctx, gum_invocation_context_get_depth (self->handle));
}

static JSValue
gum_quick_invocation_args_new (GumQuickInterceptor * parent,
                               GumQuickInvocationArgs ** args)
{
  JSContext * ctx = parent->core->ctx;
  JSValue wrapper;
  GumQuickInvocationArgs * ia;

  wrapper = JS_NewObjectClass (ctx, parent->invocation_args_class);

  ia = g_slice_new (GumQuickInvocationArgs);
  ia->wrapper = wrapper;
  ia->ic = NULL;
  ia->ctx = ctx;

  JS_SetOpaque (wrapper, ia);

  *args = ia;

  return wrapper;
}

static void
gum_quick_invocation_args_release (GumQuickInvocationArgs * self)
{
  JS_FreeValue (self->ctx, self->wrapper);
}

static void
gum_quick_invocation_args_reset (GumQuickInvocationArgs * self,
                                 GumInvocationContext * ic)
{
  self->ic = ic;
}

static gboolean
gum_quick_invocation_args_get (JSContext * ctx,
                               JSValueConst val,
                               GumQuickCore * core,
                               GumQuickInvocationArgs ** args)
{
  GumQuickInvocationArgs * a;

  if (!_gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->invocation_args_class, core,
      (gpointer *) &a))
    return FALSE;

  if (a->ic == NULL)
  {
    _gum_quick_throw_literal (ctx, "invalid operation");
    return FALSE;
  }

  *args = a;
  return TRUE;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_args_finalize)
{
  GumQuickInvocationArgs * a;

  a = JS_GetOpaque (val, gumjs_get_parent_module (core)->invocation_args_class);
  if (a == NULL)
    return;

  g_slice_free (GumQuickInvocationArgs, a);
}

static JSValue
gumjs_invocation_args_get_property (JSContext * ctx,
                                    JSValueConst obj,
                                    JSAtom atom,
                                    JSValueConst receiver)
{
  JSValue result;
  const char * prop_name;

  prop_name = JS_AtomToCString (ctx, atom);

  if (strcmp (prop_name, "toJSON") == 0)
  {
    result = JS_NewString (ctx, "invocation-args");
  }
  else
  {
    GumQuickCore * core;
    GumQuickInvocationArgs * self;
    guint64 n;
    const gchar * end;

    core = JS_GetContextOpaque (ctx);

    if (!gum_quick_invocation_args_get (ctx, receiver, core, &self))
      goto propagate_exception;

    n = g_ascii_strtoull (prop_name, (gchar **) &end, 10);
    if (end != prop_name + strlen (prop_name))
      goto invalid_array_index;

    result = _gum_quick_native_pointer_new (ctx,
        gum_invocation_context_get_nth_argument (self->ic, n), core);
  }

  JS_FreeCString (ctx, prop_name);

  return result;

invalid_array_index:
  {
    JS_ThrowRangeError (ctx, "invalid array index");
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeCString (ctx, prop_name);

    return JS_EXCEPTION;
  }
}

static int
gumjs_invocation_args_set_property (JSContext * ctx,
                                    JSValueConst obj,
                                    JSAtom atom,
                                    JSValueConst value,
                                    JSValueConst receiver,
                                    int flags)
{
  const char * prop_name;
  GumQuickCore * core;
  GumQuickInvocationArgs * self;
  guint64 n;
  const gchar * end;
  gpointer v;

  prop_name = JS_AtomToCString (ctx, atom);

  core = JS_GetContextOpaque (ctx);

  if (!gum_quick_invocation_args_get (ctx, receiver, core, &self))
    goto propagate_exception;

  n = g_ascii_strtoull (prop_name, (gchar **) &end, 10);
  if (end != prop_name + strlen (prop_name))
    goto invalid_array_index;

  if (!_gum_quick_native_pointer_get (ctx, value, core, &v))
    goto propagate_exception;

  gum_invocation_context_replace_nth_argument (self->ic, n, v);

  JS_FreeCString (ctx, prop_name);

  return TRUE;

invalid_array_index:
  {
    JS_ThrowRangeError (ctx, "invalid array index");
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeCString (ctx, prop_name);

    return -1;
  }
}

static JSValue
gum_quick_invocation_retval_new (GumQuickInterceptor * parent,
                                 GumQuickInvocationRetval ** retval)
{
  JSContext * ctx = parent->core->ctx;
  JSValue wrapper;
  GumQuickInvocationRetval * rv;
  GumQuickNativePointer * ptr;

  wrapper = JS_NewObjectClass (ctx, parent->invocation_retval_class);

  rv = g_slice_new (GumQuickInvocationRetval);
  ptr = &rv->native_pointer;
  ptr->value = NULL;
  rv->wrapper = wrapper;
  rv->ic = NULL;
  rv->ctx = ctx;

  JS_SetOpaque (wrapper, rv);

  *retval = rv;

  return wrapper;
}

static void
gum_quick_invocation_retval_release (GumQuickInvocationRetval * self)
{
  JS_FreeValue (self->ctx, self->wrapper);
}

static void
gum_quick_invocation_retval_reset (GumQuickInvocationRetval * self,
                                   GumInvocationContext * ic)
{
  GumQuickNativePointer * ptr;

  ptr = &self->native_pointer;
  if (ic != NULL)
    ptr->value = gum_invocation_context_get_return_value (ic);
  else
    ptr->value = NULL;

  self->ic = ic;
}

static gboolean
gum_quick_invocation_retval_get (JSContext * ctx,
                                 JSValueConst val,
                                 GumQuickCore * core,
                                 GumQuickInvocationRetval ** retval)
{
  GumQuickInvocationRetval * r;

  if (!_gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->invocation_retval_class, core,
      (gpointer *) &r))
    return FALSE;

  if (r->ic == NULL)
  {
    _gum_quick_throw_literal (ctx, "invalid operation");
    return FALSE;
  }

  *retval = r;
  return TRUE;
}

GUMJS_DEFINE_FINALIZER (gumjs_invocation_retval_finalize)
{
  GumQuickInvocationRetval * r;

  r = JS_GetOpaque (val,
      gumjs_get_parent_module (core)->invocation_retval_class);
  if (r == NULL)
    return;

  g_slice_free (GumQuickInvocationRetval, r);
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_retval_replace)
{
  GumQuickInvocationRetval * self;
  gpointer v;

  if (!gum_quick_invocation_retval_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "p~", &v))
    return JS_EXCEPTION;

  self->native_pointer.value = v;

  gum_invocation_context_replace_return_value (self->ic, v);

  return JS_UNDEFINED;
}

GumQuickInvocationContext *
_gum_quick_interceptor_obtain_invocation_context (GumQuickInterceptor * self)
{
  GumQuickInvocationContext * jic;

  if (!self->cached_invocation_context_in_use)
  {
    jic = self->cached_invocation_context;
    self->cached_invocation_context_in_use = TRUE;
  }
  else
  {
    gum_quick_invocation_context_new (self, &jic);
  }

  return jic;
}

void
_gum_quick_interceptor_release_invocation_context (
    GumQuickInterceptor * self,
    GumQuickInvocationContext * jic)
{
  if (jic == self->cached_invocation_context)
    self->cached_invocation_context_in_use = FALSE;
  else
    gum_quick_invocation_context_release (jic);
}

static void
gum_quick_interceptor_check_invocation_context (GumQuickInterceptor * self,
                                                GumQuickInvocationContext * jic,
                                                gboolean * jic_is_dirty)
{
  gboolean is_dirty;

  is_dirty = gum_quick_invocation_context_is_dirty (jic);

  if (is_dirty && jic == self->cached_invocation_context)
  {
    gum_quick_invocation_context_new (self, &self->cached_invocation_context);
    self->cached_invocation_context_in_use = FALSE;
  }

  if (jic_is_dirty != NULL)
    *jic_is_dirty = is_dirty;
}

static GumQuickInvocationArgs *
gum_quick_interceptor_obtain_invocation_args (GumQuickInterceptor * self)
{
  GumQuickInvocationArgs * args;

  if (!self->cached_invocation_args_in_use)
  {
    args = self->cached_invocation_args;
    self->cached_invocation_args_in_use = TRUE;
  }
  else
  {
    gum_quick_invocation_args_new (self, &args);
  }

  return args;
}

static void
gum_quick_interceptor_release_invocation_args (GumQuickInterceptor * self,
                                               GumQuickInvocationArgs * args)
{
  if (args == self->cached_invocation_args)
    self->cached_invocation_args_in_use = FALSE;
  else
    gum_quick_invocation_args_release (args);
}

static GumQuickInvocationRetval *
gum_quick_interceptor_obtain_invocation_retval (GumQuickInterceptor * self)
{
  GumQuickInvocationRetval * retval;

  if (!self->cached_invocation_retval_in_use)
  {
    retval = self->cached_invocation_retval;
    self->cached_invocation_retval_in_use = TRUE;
  }
  else
  {
    gum_quick_invocation_retval_new (self, &retval);
  }

  return retval;
}

static void
gum_quick_interceptor_release_invocation_retval (
    GumQuickInterceptor * self,
    GumQuickInvocationRetval * retval)
{
  if (retval == self->cached_invocation_retval)
    self->cached_invocation_retval_in_use = FALSE;
  else
    gum_quick_invocation_retval_release (retval);
}

"""


```