Response:
The user wants a summary of the functionalities present in the provided C++ code snippet for Frida, specifically the `gumv8core.cpp` file. They are also interested in how these functionalities relate to reverse engineering, low-level system details (Linux/Android kernel/framework), logical reasoning, potential user errors, and debugging.

**Plan:**

1. **Identify Key Functionalities:** Analyze the code and group related functions and classes by their purpose.
2. **Relate to Reverse Engineering:** Explain how each functionality can be used in the context of dynamic instrumentation and reverse engineering.
3. **Highlight System Interactions:** Point out any code sections dealing with low-level concepts like CPU context, memory manipulation, or interactions with the operating system.
4. **Look for Logical Reasoning:** Identify functions that involve conditional logic or parsing of input values. Create hypothetical input/output examples.
5. **Identify Potential User Errors:** Analyze the code for error handling and common mistakes a user might make when interacting with these functionalities.
6. **Trace User Operations:**  Infer how a user might trigger the execution of these code sections through Frida's API.
7. **Summarize the Overall Functionality:** Provide a concise overview of the code's purpose.

**Detailed Analysis of the Code Snippet:**

*   **Options Parsing:** Functions like `gum_v8_runtime_options_parse`, `gum_v8_scheduling_behavior_parse`, `gum_v8_exceptions_behavior_parse`, and `gum_v8_code_traps_parse` are responsible for parsing user-provided options, which is a crucial part of configuring Frida's behavior.
*   **Native Callback Handling:** The `GumV8NativeCallback` class and related functions (`gumjs_native_callback_construct`, `gum_v8_native_callback_invoke`) deal with creating and invoking native (C/C++) functions from JavaScript. This is a core feature for interacting with the target process.
*   **Callback Context:** The `GumV8CallbackContext` class and associated functions (`gum_v8_callback_context_new_persistent`, `gumjs_callback_context_get_return_address`, etc.) provide information about the context in which a callback is executed, including CPU state and return address.
*   **CPU Context Manipulation:** The `GumV8CpuContext` class and its methods (`gumjs_cpu_context_construct`, `gumjs_cpu_context_get_gpr`, `gumjs_cpu_context_set_gpr`, etc.) allow access and modification of the target process's CPU registers and flags.
*   **Match Pattern:** The `GumV8MatchPattern` class and its constructor (`gumjs_match_pattern_construct`) are used for defining patterns to match against memory addresses or function names.
*   **Source Map Handling:** The `GumV8SourceMap` class and its methods (`gumjs_source_map_construct`, `gumjs_source_map_resolve`) are used for working with source maps, which are helpful for debugging obfuscated code.
*   **Exception and Message Handling:**  The `GumV8ExceptionSink` and `GumV8MessageSink` classes and related functions are used for intercepting exceptions and messages in the target process.
*   **FFI Type Conversion:** Functions like `gum_v8_ffi_type_get`, `gum_v8_ffi_abi_get`, `gum_v8_value_to_ffi_type`, and `gum_v8_value_from_ffi_type` handle the conversion between JavaScript values and C/C++ data types for Foreign Function Interface (FFI) calls.

**Drafting the Response:** Based on the identified functionalities, construct the response according to the user's request, providing examples and explanations for each aspect.
这是 `gumv8core.cpp` 文件的第四部分，主要负责以下几个核心功能：

**1. 处理本地（Native）回调：**

*   **`gumjs_native_callback_construct`**:  这是一个构造函数，用于在 JavaScript 中创建 `NativeCallback` 对象的实例。这个对象允许 JavaScript 调用本地 C/C++ 函数。
    *   **功能**:  它接收 JavaScript 中提供的函数、返回值类型、参数类型以及调用约定（ABI）等信息，并创建一个 C 语言的闭包 (closure)。这个闭包包含了指向 JavaScript 函数的指针以及其他必要的信息，使得在本地代码中调用这个闭包时，能够回调执行对应的 JavaScript 函数。
    *   **与逆向的关系**:  这是 Frida 非常核心的功能。逆向工程师可以使用 `NativeCallback` 来：
        *   **Hook 函数并执行自定义 JavaScript 代码**:  例如，可以创建一个 `NativeCallback` 指向一个自定义的 JavaScript 函数，然后在目标进程的某个关键函数入口处进行 Hook，当目标函数被调用时，会先执行我们自定义的 JavaScript 代码。
        *   **模拟函数调用**:  可以创建一个 `NativeCallback`，其行为类似于目标进程中的某个函数，用于测试或欺骗目标进程。
    *   **涉及二进制底层，linux, android内核及框架的知识**:
        *   **二进制底层 (ffi_closure, ffi_cif, ffi_type)**: 代码使用了 `libffi` 库来动态创建函数调用接口 (CIF - Call Interface) 和闭包。`ffi_closure` 是实际的闭包结构，`ffi_cif` 描述了函数的调用约定、参数和返回值类型，`ffi_type` 定义了各种数据类型。这是与底层 ABI 和函数调用约定紧密相关的。
        *   **内存管理 (g_slice_new0, ffi_closure_alloc, g_new)**: 代码中使用了 GLib 的内存管理函数以及 `ffi_closure_alloc` 来分配和管理内存，这涉及到进程的内存空间。
    *   **逻辑推理**:
        *   **假设输入**:  在 JavaScript 中创建 `NativeCallback` 时，提供了以下参数：
            ```javascript
            const myCallback = new NativeCallback(
              function(arg1, arg2) { return arg1 + arg2; }, // JavaScript 函数
              'int', // 返回值类型
              ['int', 'int'] // 参数类型
            );
            ```
        *   **预期输出**:  在 C++ 代码中，会创建一个 `GumV8NativeCallback` 结构，其中 `callback->func` 指向 JavaScript 的 `function(arg1, arg2) { return arg1 + arg2; }`，`callback->cif` 描述了这是一个接受两个整型参数并返回整型的函数调用。`callback->closure` 是一个可以被本地代码调用的闭包。
    *   **用户或编程常见的使用错误**:
        *   **类型不匹配**: 用户在 JavaScript 中声明的返回值类型或参数类型与实际的本地函数不符，会导致调用时的数据解析错误或崩溃。例如，本地函数返回一个指针，但 JavaScript 中声明为 `int`。
        *   **ABI 错误**:  如果指定的 ABI 不正确，会导致栈的破坏或参数传递错误。
    *   **用户操作如何一步步的到达这里**:
        1. 用户在 Frida 的 JavaScript 代码中使用 `new NativeCallback(...)` 创建一个新的本地回调对象。
        2. V8 引擎执行 JavaScript 代码，并调用 `gumjs_native_callback_construct` 函数作为 `NativeCallback` 的构造函数。

*   **`gum_v8_native_callback_on_weak_notify`**:  当 `NativeCallback` 对象在 JavaScript 中被垃圾回收时，会触发此回调。
    *   **功能**:  清理与该 `NativeCallback` 相关的资源，例如从哈希表中移除。

*   **`gum_v8_native_callback_ref` 和 `gum_v8_native_callback_unref`**:  用于管理 `GumV8NativeCallback` 对象的引用计数。

*   **`gum_v8_native_callback_clear`**:  释放 `GumV8NativeCallback` 对象中持有的 JavaScript 对象的全局句柄。

*   **`gum_v8_native_callback_invoke`**:  当本地代码调用之前创建的闭包时，会执行此函数。
    *   **功能**:  它负责将本地的参数转换为 JavaScript 值，调用相应的 JavaScript 函数，并将 JavaScript 函数的返回值转换回本地类型。
    *   **与逆向的关系**:  这是 `NativeCallback` 功能的核心执行部分。当逆向工程师 Hook 了一个函数并使用了 `NativeCallback`，当目标函数被调用时，`gum_v8_native_callback_invoke` 会被触发，从而执行用户自定义的 JavaScript 代码。
    *   **涉及二进制底层，linux, android内核及框架的知识**:
        *   **获取 CPU 上下文 (ReturnAddress, stack_pointer, frame_pointer)**:  代码尝试获取当前的返回地址、栈指针和帧指针，这些是与 CPU 架构和调用约定相关的底层概念。不同的架构（x86, ARM, ARM64）获取方式不同。
        *   **调用 JavaScript 函数 (func->Call)**:  涉及到 V8 引擎的 API 调用，将控制权转移到 JavaScript 环境。
    *   **逻辑推理**:
        *   **假设输入**: 本地代码调用了一个通过 `NativeCallback` 创建的闭包，传递了两个整数参数。
        *   **预期输出**: `gum_v8_native_callback_invoke` 会将这两个整数转换为 JavaScript 的 Number 对象，然后调用与该闭包关联的 JavaScript 函数。JavaScript 函数的返回值会被转换回本地的整数类型。
    *   **用户或编程常见的使用错误**:
        *   **JavaScript 代码抛出异常**:  如果在 `func->Call` 期间，JavaScript 代码抛出异常，`gum_v8_native_callback_invoke` 需要妥善处理，避免导致目标进程崩溃。
        *   **返回值类型不匹配**:  如果 JavaScript 函数的返回值类型与 `NativeCallback` 声明的返回值类型不一致，会导致数据转换错误。

**2. 处理回调上下文（CallbackContext）：**

*   **`gum_v8_callback_context_new_persistent`**: 创建一个 `GumV8CallbackContext` 对象，用于表示本地回调执行时的上下文信息。
    *   **功能**: 它捕获当前的 CPU 上下文（寄存器状态等）和系统错误码，并将其包装成一个可以在 JavaScript 中访问的对象。
    *   **与逆向的关系**:  在 Frida 中，当使用 `Interceptor.attach` 或 `NativeCallback` 时，可以获取到当前的回调上下文，这对于分析函数执行时的状态非常有用。
    *   **涉及二进制底层，linux, android内核及框架的知识**:
        *   **CPU 上下文 (GumCpuContext)**:  封装了 CPU 寄存器的值，这是与底层硬件架构紧密相关的。
    *   **逻辑推理**:
        *   **假设输入**:  一个通过 Frida Hook 的函数被调用。
        *   **预期输出**: `gum_v8_callback_context_new_persistent` 会创建一个 `GumV8CallbackContext` 对象，其中包含了该函数被调用时的 CPU 寄存器状态、系统错误码以及返回地址等信息。
*   **`gum_v8_callback_context_free`**:  释放 `GumV8CallbackContext` 对象占用的内存。
*   **`gumjs_callback_context_get_return_address`**:  获取回调发生的返回地址。
    *   **功能**: 它尝试通过回溯栈帧来获取准确的返回地址。如果回溯失败，则使用原始的返回地址。
    *   **与逆向的关系**:  返回地址是分析函数调用流程的关键信息。
    *   **涉及二进制底层，linux, android内核及框架的知识**:
        *   **栈回溯 (gum_backtracer_make_accurate, gum_backtracer_generate_with_limit)**:  使用了栈回溯技术，这依赖于操作系统的栈结构和调试信息。
*   **`gumjs_callback_context_get_cpu_context`**:  获取回调时的 CPU 上下文对象。
*   **`gumjs_callback_context_get_system_error` 和 `gumjs_callback_context_set_system_error`**:  获取和设置回调时的系统错误码。

**3. 处理 CPU 上下文（CpuContext）：**

*   **`gumjs_cpu_context_construct`**:  构造 `CpuContext` 对象。
    *   **功能**:  它接收一个 `GumCpuContext` 结构体的指针，并将其包装成一个可以在 JavaScript 中访问的对象。可以选择是否将该上下文标记为可变。
*   **`gumjs_cpu_context_get_gpr` 和 `gumjs_cpu_context_set_gpr`**:  用于获取和设置通用寄存器的值。
    *   **功能**:  允许 JavaScript 代码读取和修改目标进程的 CPU 寄存器。
    *   **与逆向的关系**:  这是动态修改程序行为的关键。逆向工程师可以通过修改寄存器的值来跳过某些指令、修改函数参数或返回值等。
    *   **涉及二进制底层，linux, android内核及框架的知识**:
        *   **CPU 寄存器**:  直接操作底层硬件的寄存器。
*   **`gumjs_cpu_context_get_vector` 和 `gumjs_cpu_context_set_vector`**:  用于获取和设置向量寄存器的值。
*   **`gumjs_cpu_context_get_double`, `gumjs_cpu_context_set_double`, `gumjs_cpu_context_get_float`, `gumjs_cpu_context_set_float`**:  用于获取和设置浮点寄存器的值。
*   **`gumjs_cpu_context_get_flags` 和 `gumjs_cpu_context_set_flags`**:  用于获取和设置标志寄存器的值。

**总结本部分的功能:**

这部分代码主要负责在 Frida 的 JavaScript 环境中提供与本地代码交互的能力。它允许用户创建可以调用本地函数的 JavaScript 对象 (`NativeCallback`)，并提供了访问和修改本地代码执行上下文信息 (`CallbackContext` 和 `CpuContext`) 的能力。这些功能是 Frida 动态插桩的核心，为逆向工程师提供了强大的工具来分析和操纵目标进程的行为。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8core.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第4部分，共5部分，请归纳一下它的功能

"""
 Local<String>::New (isolate,
          *core->traps_key)).ToLocal (&v))
        return FALSE;
      if (!v->IsUndefined ())
      {
        if (!gum_v8_code_traps_parse (v, &params->traps, isolate))
          return FALSE;
      }
    }
    else
    {
      _gum_v8_throw_ascii_literal (isolate,
          "expected string or object containing options");
      return FALSE;
    }
  }

  return TRUE;
}

static gboolean
gum_v8_scheduling_behavior_parse (Local<Value> value,
                                  GumV8SchedulingBehavior * behavior,
                                  Isolate * isolate)
{
  if (value->IsString ())
  {
    String::Utf8Value str_value (isolate, value);
    auto str = *str_value;

    if (strcmp (str, "cooperative") == 0)
    {
      *behavior = GUM_V8_SCHEDULING_COOPERATIVE;
      return TRUE;
    }

    if (strcmp (str, "exclusive") == 0)
    {
      *behavior = GUM_V8_SCHEDULING_EXCLUSIVE;
      return TRUE;
    }
  }

  _gum_v8_throw_ascii_literal (isolate, "invalid scheduling behavior value");
  return FALSE;
}

static gboolean
gum_v8_exceptions_behavior_parse (Local<Value> value,
                                  GumV8ExceptionsBehavior * behavior,
                                  Isolate * isolate)
{
  if (value->IsString ())
  {
    String::Utf8Value str_value (isolate, value);
    auto str = *str_value;

    if (strcmp (str, "steal") == 0)
    {
      *behavior = GUM_V8_EXCEPTIONS_STEAL;
      return TRUE;
    }

    if (strcmp (str, "propagate") == 0)
    {
      *behavior = GUM_V8_EXCEPTIONS_PROPAGATE;
      return TRUE;
    }
  }

  _gum_v8_throw_ascii_literal (isolate, "invalid exceptions behavior value");
  return FALSE;
}

static gboolean
gum_v8_code_traps_parse (Local<Value> value,
                         GumV8CodeTraps * traps,
                         Isolate * isolate)
{
  if (value->IsString ())
  {
    String::Utf8Value str_value (isolate, value);
    auto str = *str_value;

    if (strcmp (str, "default") == 0)
    {
      *traps = GUM_V8_CODE_TRAPS_DEFAULT;
      return TRUE;
    }

    if (strcmp (str, "none") == 0)
    {
      *traps = GUM_V8_CODE_TRAPS_NONE;
      return TRUE;
    }

    if (strcmp (str, "all") == 0)
    {
      *traps = GUM_V8_CODE_TRAPS_ALL;
      return TRUE;
    }
  }

  _gum_v8_throw_ascii_literal (isolate, "invalid code traps value");
  return FALSE;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_callback_construct)
{
  auto context = isolate->GetCurrentContext ();
  Local<Function> func_value;
  Local<Value> rtype_value;
  Local<Array> atypes_array;
  Local<Value> abi_value;
  GumV8NativeCallback * callback;
  ffi_type * rtype;
  uint32_t nargs, i;
  ffi_abi abi;
  gpointer func = NULL;

  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new NativeCallback()` to create a new instance");
    return;
  }

  if (!_gum_v8_args_parse (args, "FVA|V", &func_value, &rtype_value,
      &atypes_array, &abi_value))
    return;

  callback = g_slice_new0 (GumV8NativeCallback);
  callback->ref_count = 1;
  callback->func = new Global<Function> (isolate, func_value);
  callback->core = core;

  if (!gum_v8_ffi_type_get (core, rtype_value, &rtype, &callback->data))
    goto error;

  nargs = atypes_array->Length ();
  callback->atypes = g_new (ffi_type *, nargs);
  for (i = 0; i != nargs; i++)
  {
    Local<Value> v;
    if (!atypes_array->Get (context, i).ToLocal (&v))
      goto error;

    if (!gum_v8_ffi_type_get (core, v, &callback->atypes[i], &callback->data))
      goto error;
  }

  abi = FFI_DEFAULT_ABI;
  if (!abi_value.IsEmpty ())
  {
    if (!gum_v8_ffi_abi_get (core, abi_value, &abi))
      goto error;
  }

  callback->closure =
      (ffi_closure *) ffi_closure_alloc (sizeof (ffi_closure), &func);
  if (callback->closure == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate, "failed to allocate closure");
    goto error;
  }

  if (ffi_prep_cif (&callback->cif, abi, nargs, rtype,
      callback->atypes) != FFI_OK)
  {
    _gum_v8_throw_ascii_literal (isolate,
        "failed to compile function call interface");
    goto error;
  }

  if (ffi_prep_closure_loc (callback->closure, &callback->cif,
      gum_v8_native_callback_invoke, callback, func) != FFI_OK)
  {
    _gum_v8_throw_ascii_literal (isolate, "failed to prepare closure");
    goto error;
  }

  wrapper->SetInternalField (0,
      BigInt::NewFromUnsigned (isolate, GPOINTER_TO_SIZE (func)));
  wrapper->SetInternalField (1, External::New (isolate, callback));

  callback->wrapper = new Global<Object> (isolate, wrapper);
  callback->wrapper->SetWeak (callback,
      gum_v8_native_callback_on_weak_notify, WeakCallbackType::kParameter);
  callback->ptr_value = func;

  g_hash_table_add (core->native_callbacks, callback);

  return;

error:
  gum_v8_native_callback_unref (callback);
}

static void
gum_v8_native_callback_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeCallback> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->core->native_callbacks, self);
}

static GumV8NativeCallback *
gum_v8_native_callback_ref (GumV8NativeCallback * callback)
{
  g_atomic_int_inc (&callback->ref_count);

  return callback;
}

static void
gum_v8_native_callback_unref (GumV8NativeCallback * callback)
{
  if (!g_atomic_int_dec_and_test (&callback->ref_count))
    return;

  gum_v8_native_callback_clear (callback);

  ffi_closure_free (callback->closure);

  while (callback->data != NULL)
  {
    auto head = callback->data;
    g_free (head->data);
    callback->data = g_slist_delete_link (callback->data, head);
  }
  g_free (callback->atypes);

  g_slice_free (GumV8NativeCallback, callback);
}

static void
gum_v8_native_callback_clear (GumV8NativeCallback * self)
{
  delete self->wrapper;
  delete self->func;
  self->wrapper = nullptr;
  self->func = nullptr;
}

static void
gum_v8_native_callback_invoke (ffi_cif * cif,
                               void * return_value,
                               void ** args,
                               void * user_data)
{
  GumV8SystemErrorPreservationScope error_scope;
  guintptr return_address = 0;
  guintptr stack_pointer = 0;
  guintptr frame_pointer = 0;
#if defined (_MSC_VER)
  return_address = GPOINTER_TO_SIZE (_ReturnAddress ());
  stack_pointer = GPOINTER_TO_SIZE (_AddressOfReturnAddress ());
  frame_pointer = *((guintptr *) stack_pointer - 1);
#elif defined (HAVE_I386)
# if GLIB_SIZEOF_VOID_P == 4
  asm ("mov %%esp, %0" : "=m" (stack_pointer));
  asm ("mov %%ebp, %0" : "=m" (frame_pointer));
# else
  asm ("movq %%rsp, %0" : "=m" (stack_pointer));
  asm ("movq %%rbp, %0" : "=m" (frame_pointer));
# endif
#elif defined (HAVE_ARM)
  asm ("mov %0, lr" : "=r" (return_address));
  asm ("mov %0, sp" : "=r" (stack_pointer));
  asm ("mov %0, r7" : "=r" (frame_pointer));
#elif defined (HAVE_ARM64)
  asm ("mov %0, lr" : "=r" (return_address));
  asm ("mov %0, sp" : "=r" (stack_pointer));
  asm ("mov %0, x29" : "=r" (frame_pointer));

# ifdef HAVE_DARWIN
  return_address &= G_GUINT64_CONSTANT (0x7fffffffff);
# endif
#elif defined (HAVE_MIPS)
  asm ("move %0, $ra" : "=r" (return_address));
  asm ("move %0, $sp" : "=r" (stack_pointer));
  asm ("move %0, $fp" : "=r" (frame_pointer));
#endif

  auto self = (GumV8NativeCallback *) user_data;
  ScriptScope scope (self->core->script);
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  gum_v8_native_callback_ref (self);

  auto rtype = cif->rtype;
  auto retval = (GumFFIValue *) return_value;
  if (rtype != &ffi_type_void)
  {
    /*
     * Ensure:
     * - high bits of values smaller than a pointer are cleared to zero
     * - we return something predictable in case of a JS exception
     */
    retval->v_pointer = NULL;
  }

  auto argv = g_newa (Local<Value>, cif->nargs);
  for (guint i = 0; i != cif->nargs; i++)
  {
    new (&argv[i]) Local<Value> ();
    if (!gum_v8_value_from_ffi_type (self->core, &argv[i],
        (GumFFIValue *) args[i], cif->arg_types[i]))
    {
      for (guint j = 0; j <= i; j++)
        argv[j].~Local<Value> ();
      return;
    }
  }

  auto func (Local<Function>::New (isolate, *self->func));

  Local<Value> recv;
  auto interceptor = &self->core->script->interceptor;
  GumV8InvocationContext * jic = NULL;
  GumV8CallbackContext * jcc = NULL;
  auto ic = gum_interceptor_get_live_replacement_invocation (self->ptr_value);
  if (ic != NULL)
  {
    jic = _gum_v8_interceptor_obtain_invocation_context (interceptor);
    _gum_v8_invocation_context_reset (jic, ic);
    recv = Local<Object>::New (isolate, *jic->object);
  }
  else
  {
    GumCpuContext cpu_context = { 0, };
#if defined (HAVE_I386)
    GUM_CPU_CONTEXT_XSP (&cpu_context) = stack_pointer;
    GUM_CPU_CONTEXT_XBP (&cpu_context) = frame_pointer;
#elif defined (HAVE_ARM)
    cpu_context.lr = return_address;
    cpu_context.sp = stack_pointer;
    cpu_context.r[7] = frame_pointer;
#elif defined (HAVE_ARM64)
    cpu_context.lr = return_address;
    cpu_context.sp = stack_pointer;
    cpu_context.fp = frame_pointer;
#endif

    jcc = gum_v8_callback_context_new_persistent (self->core, &cpu_context,
        &error_scope.saved_error, return_address);
    recv = Local<Object>::New (isolate, *jcc->wrapper);
  }

  Local<Value> result;
  bool have_result = func->Call (context, recv, cif->nargs, argv)
      .ToLocal (&result);

  if (jic != NULL)
  {
    _gum_v8_invocation_context_reset (jic, NULL);
    _gum_v8_interceptor_release_invocation_context (interceptor, jic);
  }

  if (jcc != NULL)
  {
    _gum_v8_cpu_context_free_later (jcc->cpu_context, self->core);
    delete jcc->cpu_context;
    gum_v8_callback_context_free (jcc);
  }

  if (cif->rtype != &ffi_type_void)
  {
    if (have_result)
      gum_v8_value_to_ffi_type (self->core, result, retval, cif->rtype);
  }

  for (guint i = 0; i != cif->nargs; i++)
    argv[i].~Local<Value> ();

  gum_v8_native_callback_unref (self);
}

static GumV8CallbackContext *
gum_v8_callback_context_new_persistent (GumV8Core * core,
                                        GumCpuContext * cpu_context,
                                        gint * system_error,
                                        GumAddress raw_return_address)
{
  auto isolate = core->isolate;

  auto jcc = g_slice_new (GumV8CallbackContext);

  auto callback_context_value = Local<Object>::New (isolate,
      *core->callback_context_value);
  auto wrapper = callback_context_value->Clone ();
  wrapper->SetAlignedPointerInInternalField (0, jcc);

  jcc->wrapper = new Global<Object> (isolate, wrapper);
  jcc->cpu_context = new Global<Object> (isolate,
      _gum_v8_cpu_context_new_immutable (cpu_context, core));
  jcc->system_error = system_error;
  jcc->return_address = 0;
  jcc->raw_return_address = raw_return_address;

  return jcc;
}

static void
gum_v8_callback_context_free (GumV8CallbackContext * self)
{
  delete self->wrapper;

  g_slice_free (GumV8CallbackContext, self);
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_callback_context_get_return_address,
                           GumV8CallbackContext)
{
  if (self->return_address == 0)
  {
    auto instance (Local<Object>::New (isolate, *self->cpu_context));
    auto cpu_context =
        (GumCpuContext *) instance->GetAlignedPointerFromInternalField (0);

    auto backtracer = gum_backtracer_make_accurate ();

    if (backtracer == NULL)
    {
      self->return_address = self->raw_return_address;
    }
    else
    {
      GumReturnAddressArray ret_addrs;

      gum_backtracer_generate_with_limit (backtracer, cpu_context,
          &ret_addrs, 1);
      self->return_address = GPOINTER_TO_SIZE (ret_addrs.items[0]);
    }

    g_clear_object (&backtracer);
  }

  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (GSIZE_TO_POINTER (self->return_address),
        core));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_callback_context_get_cpu_context,
                           GumV8CallbackContext)
{
  auto context = self->cpu_context;
  if (context == nullptr)
  {
    _gum_v8_throw (isolate, "invalid operation");
    return;
  }

  info.GetReturnValue ().Set (Local<Object>::New (isolate, *context));
}

GUMJS_DEFINE_CLASS_GETTER (gumjs_callback_context_get_system_error,
                           GumV8CallbackContext)
{
  info.GetReturnValue ().Set (*self->system_error);
}

GUMJS_DEFINE_CLASS_SETTER (gumjs_callback_context_set_system_error,
                           GumV8CallbackContext)
{
  gint system_error;
  if (!_gum_v8_int_get (value, &system_error, core))
    return;

  *self->system_error = system_error;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_cpu_context_construct)
{
  GumCpuContext * cpu_context = NULL;
  gboolean is_mutable = FALSE;
  if (!_gum_v8_args_parse (args, "|Xt", &cpu_context, &is_mutable))
    return;

  wrapper->SetAlignedPointerInInternalField (0, cpu_context);
  wrapper->SetInternalField (1, Boolean::New (isolate, !!is_mutable));
  wrapper->SetAlignedPointerInInternalField (2, core);
}

static void
gumjs_cpu_context_get_gpr (Local<Name> property,
                           const PropertyCallbackInfo<Value> & info)
{
  auto wrapper = info.Holder ();
  auto core = (GumV8Core *) wrapper->GetAlignedPointerFromInternalField (2);
  auto cpu_context = (guint8 *) wrapper->GetAlignedPointerFromInternalField (0);
  const gsize offset = info.Data ().As<Integer> ()->Value ();

  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (*(gpointer *) (cpu_context + offset), core));
}

static void
gumjs_cpu_context_set_gpr (Local<Name> property,
                           Local<Value> value,
                           const PropertyCallbackInfo<void> & info)
{
  auto isolate = info.GetIsolate ();
  auto wrapper = info.Holder ();
  auto core = (GumV8Core *) wrapper->GetAlignedPointerFromInternalField (2);
  auto cpu_context = (guint8 *) wrapper->GetAlignedPointerFromInternalField (0);
  bool is_mutable = wrapper->GetInternalField (1).As<Boolean> ()->Value ();
  const gsize offset = info.Data ().As<Integer> ()->Value ();

  if (!is_mutable)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid operation");
    return;
  }

  _gum_v8_native_pointer_parse (value, (gpointer *) (cpu_context + offset),
      core);
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4505)
#endif

static void
gumjs_cpu_context_get_vector (Local<Name> property,
                              const PropertyCallbackInfo<Value> & info)
{
  auto wrapper = info.Holder ();
  auto cpu_context = (guint8 *) wrapper->GetAlignedPointerFromInternalField (0);
  gsize spec = info.Data ().As<Integer> ()->Value ();
  const gsize offset = spec >> 8;
  const gsize size = spec & 0xff;

  auto result = ArrayBuffer::New (info.GetIsolate (), size);
  auto store = result.As<ArrayBuffer> ()->GetBackingStore ();
  memcpy (store->Data (), cpu_context + offset, size);

  info.GetReturnValue ().Set (result);
}

static void
gumjs_cpu_context_set_vector (Local<Name> property,
                              Local<Value> value,
                              const PropertyCallbackInfo<void> & info)
{
  auto isolate = info.GetIsolate ();
  auto wrapper = info.Holder ();
  auto core = (GumV8Core *) wrapper->GetAlignedPointerFromInternalField (2);
  auto cpu_context = (guint8 *) wrapper->GetAlignedPointerFromInternalField (0);
  bool is_mutable = wrapper->GetInternalField (1).As<Boolean> ()->Value ();
  gsize spec = info.Data ().As<Integer> ()->Value ();
  const gsize offset = spec >> 8;
  const gsize size = spec & 0xff;

  if (!is_mutable)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid operation");
    return;
  }

  GBytes * new_bytes = _gum_v8_bytes_get (value, core);
  if (new_bytes == NULL)
    return;

  gsize new_size;
  gconstpointer new_data = g_bytes_get_data (new_bytes, &new_size);
  if (new_size != size)
  {
    g_bytes_unref (new_bytes);
    _gum_v8_throw_ascii_literal (isolate, "incorrect vector size");
    return;
  }

  memcpy (cpu_context + offset, new_data, new_size);

  g_bytes_unref (new_bytes);
}

static void
gumjs_cpu_context_get_double (Local<Name> property,
                              const PropertyCallbackInfo<Value> & info)
{
  auto wrapper = info.Holder ();
  auto cpu_context = (guint8 *) wrapper->GetAlignedPointerFromInternalField (0);
  const gsize offset = info.Data ().As<Integer> ()->Value ();

  info.GetReturnValue ().Set (
      Number::New (info.GetIsolate (), *(gdouble *) (cpu_context + offset)));
}

static void
gumjs_cpu_context_set_double (Local<Name> property,
                              Local<Value> value,
                              const PropertyCallbackInfo<void> & info)
{
  auto isolate = info.GetIsolate ();
  auto wrapper = info.Holder ();
  auto cpu_context = (guint8 *) wrapper->GetAlignedPointerFromInternalField (0);
  bool is_mutable = wrapper->GetInternalField (1).As<Boolean> ()->Value ();
  const gsize offset = info.Data ().As<Integer> ()->Value ();

  if (!is_mutable)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid operation");
    return;
  }

  if (!value->IsNumber ())
  {
    _gum_v8_throw_ascii_literal (isolate, "expected a number");
    return;
  }
  gdouble d = value.As<Number> ()->Value ();

  *(gdouble *) (cpu_context + offset) = d;
}

static void
gumjs_cpu_context_get_float (Local<Name> property,
                             const PropertyCallbackInfo<Value> & info)
{
  auto wrapper = info.Holder ();
  auto cpu_context = (guint8 *) wrapper->GetAlignedPointerFromInternalField (0);
  const gsize offset = info.Data ().As<Integer> ()->Value ();

  info.GetReturnValue ().Set (
      Number::New (info.GetIsolate (), *(gfloat *) (cpu_context + offset)));
}

static void
gumjs_cpu_context_set_float (Local<Name> property,
                             Local<Value> value,
                             const PropertyCallbackInfo<void> & info)
{
  auto isolate = info.GetIsolate ();
  auto wrapper = info.Holder ();
  auto cpu_context = (guint8 *) wrapper->GetAlignedPointerFromInternalField (0);
  bool is_mutable = wrapper->GetInternalField (1).As<Boolean> ()->Value ();
  const gsize offset = info.Data ().As<Integer> ()->Value ();

  if (!is_mutable)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid operation");
    return;
  }

  if (!value->IsNumber ())
  {
    _gum_v8_throw_ascii_literal (isolate, "expected a number");
    return;
  }
  gdouble d = value.As<Number> ()->Value ();

  *(gfloat *) (cpu_context + offset) = (gfloat) d;
}

static void
gumjs_cpu_context_get_flags (Local<Name> property,
                             const PropertyCallbackInfo<Value> & info)
{
  auto wrapper = info.Holder ();
  auto cpu_context = (guint8 *) wrapper->GetAlignedPointerFromInternalField (0);
  const gsize offset = info.Data ().As<Integer> ()->Value ();

  info.GetReturnValue ().Set (
      Integer::NewFromUnsigned (info.GetIsolate (),
        *(gsize *) (cpu_context + offset)));
}

static void
gumjs_cpu_context_set_flags (Local<Name> property,
                             Local<Value> value,
                             const PropertyCallbackInfo<void> & info)
{
  auto isolate = info.GetIsolate ();
  auto wrapper = info.Holder ();
  auto cpu_context = (guint8 *) wrapper->GetAlignedPointerFromInternalField (0);
  bool is_mutable = wrapper->GetInternalField (1).As<Boolean> ()->Value ();
  auto core = (GumV8Core *) wrapper->GetAlignedPointerFromInternalField (2);
  const gsize offset = info.Data ().As<Integer> ()->Value ();

  if (!is_mutable)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid operation");
    return;
  }

  gsize f;
  if (!_gum_v8_size_get (value, &f, core))
    return;

  *(gsize *) (cpu_context + offset) = f;
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

GUMJS_DEFINE_CONSTRUCTOR (gumjs_match_pattern_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new MatchPattern()` to create a new instance");
    return;
  }

  gchar * pattern_str;
  if (!_gum_v8_args_parse (args, "s", &pattern_str))
    return;

  auto pattern = gum_match_pattern_new_from_string (pattern_str);

  g_free (pattern_str);

  if (pattern == NULL)
  {
    _gum_v8_throw_literal (isolate, "invalid match pattern");
    return;
  }

  wrapper->SetInternalField (0, External::New (isolate, pattern));
  gum_v8_match_pattern_new (wrapper, pattern, module);
}

static GumV8MatchPattern *
gum_v8_match_pattern_new (Local<Object> wrapper,
                          GumMatchPattern * handle,
                          GumV8Core * core)
{
  auto pattern = g_slice_new (GumV8MatchPattern);

  pattern->wrapper = new Global<Object> (core->isolate, wrapper);
  pattern->handle = handle;

  g_hash_table_add (core->match_patterns, pattern);

  return pattern;
}

static void
gum_v8_match_pattern_free (GumV8MatchPattern * self)
{
  delete self->wrapper;

  gum_match_pattern_unref (self->handle);

  g_slice_free (GumV8MatchPattern, self);
}

static MaybeLocal<Object>
gumjs_source_map_new (const gchar * json,
                      GumV8Core * core)
{
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto ctor = Local<FunctionTemplate>::New (isolate, *core->source_map);

  Local<Value> args[] = {
    String::NewFromUtf8 (isolate, json).ToLocalChecked ()
  };

  return ctor->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, G_N_ELEMENTS (args), args);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_source_map_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new SourceMap()` to create a new instance");
    return;
  }

  gchar * json;
  if (!_gum_v8_args_parse (args, "s", &json))
    return;

  auto handle = gum_source_map_new (json);

  g_free (json);

  if (handle == NULL)
  {
    _gum_v8_throw (isolate, "invalid source map");
    return;
  }

  auto map = gum_v8_source_map_new (wrapper, handle, module);
  wrapper->SetAlignedPointerInInternalField (0, map);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_source_map_resolve, GumV8SourceMap)
{
  guint line, column;

  if (args->info->Length () == 1)
  {
    if (!_gum_v8_args_parse (args, "u", &line))
      return;
    column = G_MAXUINT;
  }
  else
  {
    if (!_gum_v8_args_parse (args, "uu", &line, &column))
      return;
  }

  const gchar * source, * name;
  if (gum_source_map_resolve (self->handle, &line, &column, &source, &name))
  {
    auto result = Array::New (isolate, 4);

    auto context = isolate->GetCurrentContext ();
    result->Set (context, 0,
        String::NewFromUtf8 (isolate, source).ToLocalChecked ()).Check ();
    result->Set (context, 1, Integer::NewFromUnsigned (isolate, line)).Check ();
    result->Set (context, 2, Integer::NewFromUnsigned (isolate, column))
        .Check ();
    if (name != NULL)
    {
      result->Set (context, 3,
          String::NewFromUtf8 (isolate, name).ToLocalChecked ()).Check ();
    }
    else
    {
      result->Set (context, 3, Null (isolate)).Check ();
    }

    info.GetReturnValue ().Set (result);
  }
  else
  {
    info.GetReturnValue ().SetNull ();
  }
}

static GumV8SourceMap *
gum_v8_source_map_new (Local<Object> wrapper,
                       GumSourceMap * handle,
                       GumV8Core * core)
{
  auto map = g_slice_new (GumV8SourceMap);
  map->wrapper = new Global<Object> (core->isolate, wrapper);
  map->wrapper->SetWeak (map, gum_v8_source_map_on_weak_notify,
      WeakCallbackType::kParameter);
  map->handle = handle;

  map->core = core;

  g_hash_table_add (core->source_maps, map);

  return map;
}

static void
gum_v8_source_map_free (GumV8SourceMap * self)
{
  g_object_unref (self->handle);

  delete self->wrapper;

  g_slice_free (GumV8SourceMap, self);
}

static void
gum_v8_source_map_on_weak_notify (const WeakCallbackInfo<GumV8SourceMap> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->core->source_maps, self);
}

static GumV8ExceptionSink *
gum_v8_exception_sink_new (Local<Function> callback,
                           Isolate * isolate)
{
  auto sink = g_slice_new (GumV8ExceptionSink);
  sink->callback = new Global<Function> (isolate, callback);
  sink->isolate = isolate;
  return sink;
}

static void
gum_v8_exception_sink_free (GumV8ExceptionSink * sink)
{
  delete sink->callback;

  g_slice_free (GumV8ExceptionSink, sink);
}

static void
gum_v8_exception_sink_handle_exception (GumV8ExceptionSink * self,
                                        Local<Value> exception)
{
  auto isolate = self->isolate;
  auto context = isolate->GetCurrentContext ();

  auto callback (Local<Function>::New (isolate, *self->callback));
  auto recv = Undefined (isolate);
  Local<Value> argv[] = { exception };
  auto result = callback->Call (context, recv, G_N_ELEMENTS (argv), argv);
  _gum_v8_ignore_result (result);
}

static GumV8MessageSink *
gum_v8_message_sink_new (Local<Function> callback,
                         Isolate * isolate)
{
  auto sink = g_slice_new (GumV8MessageSink);
  sink->callback = new Global<Function> (isolate, callback);
  sink->isolate = isolate;
  return sink;
}

static void
gum_v8_message_sink_free (GumV8MessageSink * sink)
{
  delete sink->callback;

  g_slice_free (GumV8MessageSink, sink);
}

static void
gum_v8_message_sink_post (GumV8MessageSink * self,
                          const gchar * message,
                          GBytes * data)
{
  auto isolate = self->isolate;
  auto context = isolate->GetCurrentContext ();

  Local<Value> data_value;
  if (data != NULL)
  {
    gpointer base;
    gsize size;

    base = (gpointer) g_bytes_get_data (data, &size);

    data_value = ArrayBuffer::New (isolate, ArrayBuffer::NewBackingStore (
        base, size, gum_delete_bytes_reference, data));
  }
  else
  {
    data_value = Null (isolate);
  }

  auto callback (Local<Function>::New (isolate, *self->callback));
  auto recv = Undefined (isolate);
  Local<Value> argv[] = {
    String::NewFromUtf8 (isolate, message).ToLocalChecked (),
    data_value
  };
  auto result = callback->Call (context, recv, G_N_ELEMENTS (argv), argv);
  _gum_v8_ignore_result (result);
}

static void
gum_delete_bytes_reference (void * data,
                            size_t length,
                            void * deleter_data)
{
  g_bytes_unref ((GBytes *) deleter_data);
}

static gboolean
gum_v8_ffi_type_get (GumV8Core * core,
                     Local<Value> name,
                     ffi_type ** type,
                     GSList ** data)
{
  auto isolate = core->isolate;

  if (name->IsString ())
  {
    String::Utf8Value str_value (isolate, name);
    if (gum_ffi_try_get_type_by_name (*str_value, type))
      return TRUE;
  }
  else if (name->IsArray ())
  {
    auto fields_value = name.As<Array> ();
    gsize length = fields_value->Length ();

    auto fields = g_new (ffi_type *, length + 1);
    *data = g_slist_prepend (*data, fields);

    auto context = isolate->GetCurrentContext ();
    for (gsize i = 0; i != length; i++)
    {
      Local<Value> field_value;
      if (fields_value->Get (context, i).ToLocal (&field_value))
      {
        if (!gum_v8_ffi_type_get (core, field_value, &fields[i], data))
          return FALSE;
      }
      else
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid field type specified");
        return FALSE;
      }
    }

    fields[length] = NULL;

    auto struct_type = g_new0 (ffi_type, 1);
    struct_type->type = FFI_TYPE_STRUCT;
    struct_type->elements = fields;
    *data = g_slist_prepend (*data, struct_type);

    *type = struct_type;
    return TRUE;
  }

  _gum_v8_throw_ascii_literal (isolate, "invalid type specified");
  return FALSE;
}

static gboolean
gum_v8_ffi_abi_get (GumV8Core * core,
                    Local<Value> name,
                    ffi_abi * abi)
{
  auto isolate = core->isolate;

  if (!name->IsString ())
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid abi specified");
    return FALSE;
  }

  String::Utf8Value str_value (isolate, name);
  if (gum_ffi_try_get_abi_by_name (*str_value, abi))
    return TRUE;

  _gum_v8_throw_ascii_literal (isolate, "invalid abi specified");
  return FALSE;
}

static gboolean
gum_v8_value_to_ffi_type (GumV8Core * core,
                          const Local<Value> svalue,
                          GumFFIValue * value,
                          const ffi_type * type)
{
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();

  if (type == &ffi_type_void)
  {
    value->v_pointer = NULL;
  }
  else if (type == &ffi_type_pointer)
  {
    if (!_gum_v8_native_pointer_get (svalue, &value->v_pointer, core))
      return FALSE;
  }
  else if (type == &ffi_type_sint8)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_sint8 = (gint8) svalue->Int32Value (context).ToChecked ();
  }
  else if (type == &ffi_type_uint8)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_uint8 = (guint8) svalue->Uint32Value (context).ToChecked ();
  }
  else if (type == &ffi_type_sint16)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_sint16 = (gint16) svalue->Int32Value (context).ToChecked ();
  }
  else if (type == &ffi_type_uint16)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_uint16 = (guint16) svalue->Uint32Value (context).ToChecked ();
  }
  else if (type == &ffi_type_sint32)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_sint32 = (gint32) svalue->Int32Value (context).ToChecked ();
  }
  else if (type == &ffi_type_uint32)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_uint32 = (guint32) svalue->Uint32Value (context).ToChecked ();
  }
  else if (type == &ffi_type_sint64)
  {
    if (!_gum_v8_int64_get (svalue, &value->v_sint64, core))
      return FALSE;
  }
  else if (type == &ffi_type_uint64)
  {
    if (!_gum_v8_uint64_get (svalue, &value->v_uint64, core))
      return FALSE;
  }
  else if (type == &gum_ffi_type_size_t)
  {
    guint64 u64;
    if (!_gum_v8_uint64_get (svalue, &u64, core))
      return FALSE;

    switch (type->size)
    {
      case 8:
        value->v_uint64 = u64;
        break;
      case 4:
        value->v_uint32 = u64;
        break;
      case 2:
        value->v_uint16 = u64;
        break;
      default:
        g_assert_not_reached ();
    }
  }
  else if (type == &gum_ffi_type_ssize_t)
  {
    gint64 i64;
    if (!_gum_v8_int64_get (svalue, &i64, core))
      return FALSE;

    switch (type->size)
    {
      case 8:
        value->v_sint64 = i64;
        break;
      case 4:
        value->v_sint32 = i64;
        break;
      case 2:
        value->v_sint16 = i64;
        break;
      default:
        g_assert_not_reached ();
    }
  }
  else if (type == &ffi_type_float)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_float = svalue->NumberValue (context).ToChecked ();
  }
  else if (type == &ffi_type_double)
  {
    if (!svalue->IsNumber ())
      goto error_expected_number;
    value->v_double = svalue->NumberValue (context).ToChecked ();
  }
  else if (type->type == FFI_TYPE_STRUCT)
  {
    if (!svalue->IsArray ())
    {
      _gum_v8_throw_ascii_literal (isolate, "expected array with fields");
      return FALSE;
    }
    auto field_svalues = svalue.As<Array> ();

    auto field_types = type->elements;
    gsize provided_length = field_svalues->Length ();
    gsize length = 0;
    for (auto t = field_types; *t != NULL; t++)
      length++;
    if (provided_length != length)
    {
      _gum_v8_throw_ascii_literal (isolate,
          "provided array length does not match number of fields");
      return FALSE;
    }

    auto field_values = (guint8 *) value;
    gsize offset = 0;
    for (gsize i = 0; i != length; i++)
    {
      auto field_type = field_types[i];

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);

      auto field_value = (GumFFIValue *) (field_values + offset);
      Local<Value> field_svalue;
      if (field_svalues->Get (context, i).ToLocal (&field_svalue))
      {
        if (!gum_v8_value_to_ffi_type (core, field_svalue, field_value,
            field_type))
        {
          return FALSE;
        }
      }
      else
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid field value specified");
        return FALSE;
      }

      offset += field_type->size;
    }
  }
  else
  {
    goto error_unsupported_type;
  }

  return TRUE;

error_expected_number:
  {
    _gum_v8_throw_ascii_literal (isolate, "expected number");
    return FALSE;
  }
error_unsupported_type:
  {
    _gum_v8_throw_ascii_literal (isolate, "unsupported type");
    
"""


```