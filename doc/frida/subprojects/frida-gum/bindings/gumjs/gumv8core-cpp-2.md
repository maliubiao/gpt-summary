Response:
The user wants a summary of the functionality of the C++ source code file `gumv8core.cpp` which is part of the Frida dynamic instrumentation tool. They are also asking for specific examples related to reverse engineering, low-level details (binary, Linux, Android kernel/framework), logical reasoning, common user errors, and debugging steps.

Here's a breakdown of how to approach this:

1. **Understand the Core Functionality:** The filename `gumv8core.cpp` strongly suggests that this file is responsible for the core integration between Frida and the V8 JavaScript engine. This includes managing the JavaScript runtime environment within Frida, allowing JavaScript code to interact with the target process.

2. **Identify Key Features by Analyzing the Code:** Scan through the code and identify the main functionalities implemented:
    * **Weak References:**  The code manages weak references from JavaScript objects to native C++ objects, allowing for proper garbage collection.
    * **Global Access Handler:**  This feature lets JavaScript code intercept and handle accesses to global variables.
    * **Job Queue:**  The code handles scheduling and executing tasks on a thread pool.
    * **Integer (Int64/UInt64) and Native Pointer Types:**  It defines custom JavaScript types to represent 64-bit integers and native memory addresses, with associated operations.
    * **ArrayBuffer Integration:**  Allows JavaScript to directly interact with raw memory buffers.
    * **Native Function Invocation:** The most significant part seems to be the ability to call native C/C++ functions from JavaScript. This involves handling argument marshalling, return values, error handling, and different calling conventions (ABIs).
    * **System Functions:**  A special type of native function that returns additional system error information.

3. **Address the Specific Questions:**
    * **Reverse Engineering:**  Think about how these features are used in reverse engineering. Calling native functions allows interacting with the target process's APIs. Manipulating pointers and integers allows inspecting and modifying memory.
    * **Binary/Low-Level/Kernel/Framework:**  Identify code sections that deal with pointers, memory allocation, system calls (indirectly through native function calls), and how this might relate to OS-level concepts.
    * **Logical Reasoning:** Look for functions that perform operations based on input values, like the arithmetic and bitwise operations on integers and pointers. Formulate simple input-output examples.
    * **User Errors:** Consider common mistakes when using these APIs, like incorrect argument types or counts when calling native functions.
    * **Debugging:**  Think about how a user might end up in this code during debugging. This likely involves calling JavaScript functions that interact with the native Frida core.

4. **Structure the Answer:** Organize the findings logically, addressing each part of the user's request.

5. **Refine the Summary:**  Condense the detailed analysis into a concise summary of the file's main function.

**Self-Correction/Refinement during thought process:**

* **Initial Thought:** Focus heavily on the V8 integration details.
* **Correction:** While V8 integration is crucial, the *purpose* of this integration within Frida is equally important. Emphasize the ability to interact with the target process.
* **Initial Thought:**  List all the defined functions.
* **Correction:** Group functions by their purpose (e.g., all the `gumjs_int64_*` functions relate to the Int64 type). This makes the explanation clearer.
* **Initial Thought:**  Provide very technical explanations of each V8 API.
* **Correction:**  Focus on the *Frida-specific* functionality and how these V8 APIs are used to achieve that. The user likely cares more about what Frida can do than the intricacies of the V8 engine itself.
* **Initial Thought:** Directly translate code into English.
* **Correction:**  Explain the *purpose* and *implications* of the code, not just a literal translation. For example, instead of saying "it frees memory", explain why this is important for avoiding leaks.

By following these steps and making these refinements, I can generate a comprehensive and helpful answer for the user.
这是Frida中负责V8 JavaScript引擎核心功能的C++代码文件。它主要负责在Frida的上下文中创建、管理和操作V8 JavaScript引擎的实例，使得Frida能够执行用户提供的JavaScript代码，并与目标进程进行交互。以下是其功能的详细列举：

**核心功能归纳：**

* **V8 引擎生命周期管理:**  负责 V8 引擎实例的创建、初始化、运行和销毁。
* **JavaScript 上下文管理:**  创建和管理 V8 引擎中的 JavaScript 执行上下文。
* **JavaScript 与 Native C++ 的桥梁:**  提供机制使得 JavaScript 代码能够调用底层的 C++ 代码，以及 C++ 代码能够操作 JavaScript 对象。
* **扩展 JavaScript 功能:**  注册一些自定义的 JavaScript 函数和对象，例如 `Int64`, `UInt64`, `NativePointer`, `NativeFunction`, `SystemFunction`, `ArrayBuffer`，以增强 JavaScript 在逆向分析中的能力。
* **弱引用管理:**  管理 JavaScript 对象对 C++ 对象的弱引用，防止内存泄漏。
* **异步任务调度:**  提供机制在后台线程池中执行任务。

**与逆向方法的关系及举例说明：**

* **调用 Native 函数:**  通过 `NativeFunction` 和 `SystemFunction`，JavaScript 代码可以调用目标进程中加载的任意函数。这对于理解函数行为、修改函数参数、替换函数实现等逆向操作至关重要。
    * **举例:**  假设你想在目标进程中调用 `malloc` 函数并查看其返回值。你可以使用 `NativeFunction` 创建一个 `malloc` 的 JavaScript 绑定，然后在 JavaScript 中调用它。
    ```javascript
    const malloc = new NativeFunction(Module.findExportByName(null, 'malloc'), 'pointer', ['size_t']);
    const buffer = malloc(1024);
    console.log(buffer); // 打印分配的内存地址
    ```
* **操作内存:** 通过 `NativePointer` 和 `ArrayBuffer`，JavaScript 代码可以直接读写目标进程的内存。这对于查看变量值、修改内存数据、注入 shellcode 等操作非常有用。
    * **举例:**  假设你知道某个全局变量的地址，你想读取它的值。你可以创建一个 `NativePointer` 对象指向该地址，然后读取其内容。
    ```javascript
    const address = ptr('0x12345678'); // 假设的全局变量地址
    const value = address.readInt();
    console.log(value);
    ```
* **Hook 函数:**  虽然这个文件本身不直接实现 Hook 机制，但它提供的 `NativeFunction` 是实现 Hook 的基础。通过 `Interceptor` API，你可以拦截目标函数的调用，并在 JavaScript 中执行自定义代码，这通常会用到 `NativeFunction` 来调用原始函数或替换后的函数。

**涉及二进制底层、Linux、Android内核及框架的知识及举例说明：**

* **二进制数据表示:** `Int64` 和 `UInt64` 类型允许 JavaScript 处理 64 位整数，这在处理内存地址、文件偏移等二进制数据时非常重要。
* **内存地址表示:** `NativePointer` 类型表示内存地址，可以直接与 C/C++ 的指针概念对应。
* **调用约定 (ABI):**  `NativeFunction` 和 `SystemFunction` 允许指定调用约定 (通过 `abi` 参数)，这对于调用不同库（例如标准 C 库与某些特定框架库）中的函数至关重要。不同的操作系统和架构可能有不同的调用约定。
    * **举例:**  在 x86_64 Linux 系统中，常用的调用约定是 `stdcall` 或 `cdecl`。在 Android 上，通常使用 `aapcs` 或 `aapcs-vfp`。在创建 `NativeFunction` 时，你需要根据目标函数的调用约定来设置 `abi` 参数。
* **指针运算:** `NativePointer` 提供了加减等指针运算，允许在内存中进行偏移。
* **字节序 (Endianness):** 虽然代码中没有直接体现字节序的处理，但在使用 `NativePointer` 读取多字节数据时，需要考虑目标进程的字节序 (大端或小端)。`gumjs_native_pointer_to_match_pattern` 函数中可以看到对字节序的处理。
* **PTRAUTH (Pointer Authentication):**  代码中包含对 ARMv8.3-A 引入的 PTRAUTH 功能的支持 (`gumjs_native_pointer_sign`, `gumjs_native_pointer_strip`, `gumjs_native_pointer_blend`)，这在逆向分析具有 PTRAUTH 保护的代码时非常重要，尤其是在 iOS 和部分 Android 设备上。
* **Android Tagged Pointers:** `gumjs_native_pointer_strip` 函数中也处理了 Android 上的 Tagged Pointers，这是一种优化技术，可能会影响指针的表示。

**逻辑推理及假设输入与输出：**

* **Int64/UInt64 运算:** 这些类型实现了基本的算术和位运算。
    * **假设输入:**  JavaScript 代码创建两个 `Int64` 对象，分别为 `int64(10)` 和 `int64(5)`，并执行加法操作。
    * **输出:**  加法操作的结果将是一个新的 `Int64` 对象，其值为 15。
* **NativePointer 运算:**  `NativePointer` 可以进行加减运算，用于计算内存地址。
    * **假设输入:**  一个 `NativePointer` 对象指向地址 `0x1000`，加上整数 `0x10`。
    * **输出:**  一个新的 `NativePointer` 对象，指向地址 `0x1010`。
* **NativePointer 比较:** 可以比较两个 `NativePointer` 的大小。
    * **假设输入:**  两个 `NativePointer` 对象，分别指向 `0x1000` 和 `0x2000`。
    * **输出:**  比较结果将是 -1 (第一个指针小于第二个指针)。

**涉及用户或编程常见的使用错误及举例说明：**

* **错误的 NativeFunction 参数类型或数量:**  如果 JavaScript 调用 `NativeFunction` 时提供的参数类型或数量与 C++ 函数的声明不符，会导致错误。
    * **举例:**  C++ 函数 `int add(int a, int b)` 需要两个整数参数，但在 JavaScript 中只提供了一个参数：
    ```javascript
    const add = new NativeFunction(Module.findExportByName(null, 'add'), 'int', ['int', 'int']);
    add(1); // 错误：缺少一个参数
    ```
* **未正确处理 NativeFunction 的返回值类型:**  如果 JavaScript 尝试以错误的类型解析 `NativeFunction` 的返回值，可能会导致崩溃或意外结果。
    * **举例:**  C++ 函数返回一个指针，但在 JavaScript 中尝试将其作为整数读取：
    ```javascript
    const getBuffer = new NativeFunction(Module.findExportByName(null, 'get_buffer'), 'pointer', []);
    const bufferPtr = getBuffer();
    console.log(bufferPtr.toInt32()); // 错误：尝试将指针作为 32 位整数读取
    ```
* **在错误的上下文中使用 V8 对象:**  V8 的对象和上下文是关联的，在错误的线程或上下文中使用会导致错误。Frida 已经处理了大部分上下文管理，但用户仍然可能在异步操作中遇到此类问题。
* **忘记使用 `ptr()` 创建 NativePointer:**  直接使用数字字面量作为内存地址会导致类型错误。
    * **举例:**
    ```javascript
    // 错误的做法
    const address = 0x12345678;
    // 正确的做法
    const address = ptr('0x12345678');
    ```
* **ArrayBuffer 使用错误:**  例如，尝试访问超出 `ArrayBuffer` 边界的内存。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida JavaScript 脚本:** 用户编写 JavaScript 代码，希望与目标进程进行交互。
2. **脚本调用 Frida API:**  脚本中会调用 Frida 提供的全局对象和函数，例如 `Module.findExportByName()`, `new NativeFunction()`, `ptr()`, `Memory.read*()` 等。
3. **Frida Core 处理 JavaScript 调用:**  当 JavaScript 代码调用这些 Frida API 时，Frida 的核心逻辑会介入。
4. **`gumv8core.cpp` 中的函数被调用:**  对于涉及到 V8 引擎交互的操作，例如创建 `NativeFunction` 对象、执行 JavaScript 代码、操作 `Int64` 或 `NativePointer` 对象，最终会调用 `gumv8core.cpp` 中定义的 C++ 函数。
5. **例如，创建 `NativeFunction` 的过程:**
    * 用户在 JavaScript 中执行 `new NativeFunction(...)`。
    * V8 引擎捕获到这个构造函数调用。
    * V8 引擎将调用转发到 Frida 注册的 `gumjs_native_function_construct` 函数（在 `gumv8core.cpp` 中定义）。
    * `gumjs_native_function_construct` 函数会解析 JavaScript 传递的参数，并调用 `gumjs_native_function_init` 来初始化 `NativeFunction` 对象。
6. **调试线索:**  如果在调试 Frida 脚本时遇到与 `Int64`, `NativePointer`, `NativeFunction` 等类型相关的错误，或者在调用 native 函数时出现问题，那么 `gumv8core.cpp` 中的代码很可能是问题发生的源头。可以使用 GDB 或 LLDB 等调试器附加到 Frida 服务进程，并设置断点在 `gumv8core.cpp` 的相关函数中，以追踪 JavaScript 调用是如何一步步到达 C++ 代码的，以及 C++ 代码的执行流程。

**归纳一下它的功能 (第 3 部分总结):**

`gumv8core.cpp` 是 Frida 中 V8 JavaScript 引擎的核心粘合层。它负责将 V8 引擎集成到 Frida 框架中，并扩展 JavaScript 的能力，使其能够方便地与目标进程的底层进行交互。这包括管理 V8 引擎的生命周期、提供 JavaScript 与 Native C++ 互相调用的机制、定义用于表示底层数据类型的 JavaScript 对象（如 `Int64`, `NativePointer`）以及处理弱引用和异步任务。这个文件是 Frida 实现动态 instrumentation 功能的关键组成部分。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8core.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第3部分，共5部分，请归纳一下它的功能

"""
ng_weak_callbacks_in_idle, core,
        NULL);
    g_source_attach (source,
        gum_script_scheduler_get_js_context (core->scheduler));
    g_source_unref (source);

    _gum_v8_core_pin (core);

    core->pending_weak_source = source;
  }

  g_slice_free (GumV8WeakRef, ref);
}

static void
gum_v8_weak_ref_on_weak_notify (const WeakCallbackInfo<GumV8WeakRef> & info)
{
  auto self = info.GetParameter ();

  g_hash_table_remove (self->core->weak_refs, GUINT_TO_POINTER (self->id));
}

static gboolean
gum_v8_core_invoke_pending_weak_callbacks_in_idle (GumV8Core * self)
{
  ScriptScope scope (self->script);

  self->pending_weak_source = NULL;

  gum_v8_core_invoke_pending_weak_callbacks (self, &scope);

  _gum_v8_core_unpin (self);

  return FALSE;
}

static void
gum_v8_core_invoke_pending_weak_callbacks (GumV8Core * self,
                                           ScriptScope * scope)
{
  auto isolate = self->isolate;
  auto context = isolate->GetCurrentContext ();

  auto recv = Undefined (isolate);

  Global<Function> * weak_callback;
  while ((weak_callback = (Global<Function> *)
      g_queue_pop_head (&self->pending_weak_callbacks)) != nullptr)
  {
    auto callback = Local<Function>::New (isolate, *weak_callback);

    auto result = callback->Call (context, recv, 0, nullptr);
    if (result.IsEmpty ())
      scope->ProcessAnyPendingException ();

    delete weak_callback;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_script_set_global_access_handler)
{
  Local<Function> on_get;
  Local<Object> callbacks;
  gboolean has_callbacks = !(info.Length () > 0 && info[0]->IsNull ());
  if (has_callbacks)
  {
    if (!_gum_v8_args_parse (args, "F{get}", &on_get))
      return;
    callbacks = info[0].As<Object> ();
  }

  delete core->on_global_get;
  delete core->global_receiver;
  core->on_global_get = nullptr;
  core->global_receiver = nullptr;

  if (has_callbacks)
  {
    core->on_global_get =
        new Global<Function> (isolate, on_get.As<Function> ());
    core->global_receiver = new Global<Object> (isolate, callbacks);
  }
}

void
_gum_v8_core_push_job (GumV8Core * self,
                       GumScriptJobFunc job_func,
                       gpointer data,
                       GDestroyNotify data_destroy)
{
  gum_script_scheduler_push_job_on_thread_pool (self->scheduler, job_func,
      data, data_destroy);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_int64_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate, "use `new Int64()` to create a new "
        "instance, or use the shorthand: `int64()`");
    return;
  }

  gint64 value;
  if (!_gum_v8_args_parse (args, "q~", &value))
    return;

  _gum_v8_int64_set_value (wrapper, value, isolate);
}

#define GUM_DEFINE_INT64_OP_IMPL(name, op) \
    GUMJS_DEFINE_FUNCTION (gumjs_int64_##name) \
    { \
      gint64 lhs = _gum_v8_int64_get_value (info.Holder ()); \
      \
      gint64 rhs; \
      if (!_gum_v8_args_parse (args, "q~", &rhs)) \
        return; \
      \
      gint64 result = lhs op rhs; \
      \
      info.GetReturnValue ().Set (_gum_v8_int64_new (result, core)); \
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
      gint64 value = _gum_v8_int64_get_value (info.Holder ()); \
      \
      gint64 result = op value; \
      \
      info.GetReturnValue ().Set (_gum_v8_int64_new (result, core)); \
    }

GUM_DEFINE_INT64_UNARY_OP_IMPL (not, ~)

GUMJS_DEFINE_FUNCTION (gumjs_int64_compare)
{
  gint64 lhs = _gum_v8_int64_get_value (info.Holder ());

  gint64 rhs;
  if (!_gum_v8_args_parse (args, "q~", &rhs))
    return;

  int32_t result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  info.GetReturnValue ().Set (result);
}

GUMJS_DEFINE_FUNCTION (gumjs_int64_to_number)
{
  info.GetReturnValue ().Set (
      (double) _gum_v8_int64_get_value (info.Holder ()));
}

GUMJS_DEFINE_FUNCTION (gumjs_int64_to_string)
{
  gint radix = 10;
  if (!_gum_v8_args_parse (args, "|u", &radix))
    return;
  if (radix != 10 && radix != 16)
  {
    _gum_v8_throw_ascii_literal (isolate, "unsupported radix");
    return;
  }

  auto value = _gum_v8_int64_get_value (info.Holder ());

  gchar str[32];
  if (radix == 10)
    g_sprintf (str, "%" G_GINT64_FORMAT, value);
  else if (value >= 0)
    g_sprintf (str, "%" G_GINT64_MODIFIER "x", value);
  else
    g_sprintf (str, "-%" G_GINT64_MODIFIER "x", -value);

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
}

GUMJS_DEFINE_FUNCTION (gumjs_int64_to_json)
{
  gchar str[32];
  g_sprintf (str, "%" G_GINT64_FORMAT,
      _gum_v8_int64_get_value (info.Holder ()));

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
}

GUMJS_DEFINE_FUNCTION (gumjs_int64_value_of)
{
  info.GetReturnValue ().Set (
      (double) _gum_v8_int64_get_value (info.Holder ()));
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_uint64_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate, "use `new UInt64()` to create a new "
        "instance, or use the shorthand: `uint64()`");
    return;
  }

  guint64 value;
  if (!_gum_v8_args_parse (args, "Q~", &value))
    return;

  _gum_v8_uint64_set_value (wrapper, value, isolate);
}

#define GUM_DEFINE_UINT64_OP_IMPL(name, op) \
    GUMJS_DEFINE_FUNCTION (gumjs_uint64_##name) \
    { \
      guint64 lhs = _gum_v8_uint64_get_value (info.Holder ()); \
      \
      guint64 rhs; \
      if (!_gum_v8_args_parse (args, "Q~", &rhs)) \
        return; \
      \
      guint64 result = lhs op rhs; \
      \
      info.GetReturnValue ().Set (_gum_v8_uint64_new (result, core)); \
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
      guint64 value = _gum_v8_uint64_get_value (info.Holder ()); \
      \
      guint64 result = op value; \
      \
      info.GetReturnValue ().Set (_gum_v8_uint64_new (result, core)); \
    }

GUM_DEFINE_UINT64_UNARY_OP_IMPL (not, ~)

GUMJS_DEFINE_FUNCTION (gumjs_uint64_compare)
{
  guint64 lhs = _gum_v8_uint64_get_value (info.Holder ());

  guint64 rhs;
  if (!_gum_v8_args_parse (args, "Q~", &rhs))
    return;

  int32_t result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  info.GetReturnValue ().Set (result);
}

GUMJS_DEFINE_FUNCTION (gumjs_uint64_to_number)
{
  info.GetReturnValue ().Set (
      (double) _gum_v8_uint64_get_value (info.Holder ()));
}

GUMJS_DEFINE_FUNCTION (gumjs_uint64_to_string)
{
  gint radix = 10;
  if (!_gum_v8_args_parse (args, "|u", &radix))
    return;
  if (radix != 10 && radix != 16)
  {
    _gum_v8_throw_ascii_literal (isolate, "unsupported radix");
    return;
  }

  auto value = _gum_v8_uint64_get_value (info.Holder ());

  gchar str[32];
  if (radix == 10)
    g_sprintf (str, "%" G_GUINT64_FORMAT, value);
  else
    g_sprintf (str, "%" G_GINT64_MODIFIER "x", value);

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
}

GUMJS_DEFINE_FUNCTION (gumjs_uint64_to_json)
{
  gchar str[32];
  g_sprintf (str, "%" G_GUINT64_FORMAT,
      _gum_v8_uint64_get_value (info.Holder ()));

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
}

GUMJS_DEFINE_FUNCTION (gumjs_uint64_value_of)
{
  info.GetReturnValue ().Set (
      (double) _gum_v8_uint64_get_value (info.Holder ()));
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_pointer_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate, "use `new NativePointer()` to "
        "create a new instance, or use one of the two shorthands: "
        "`ptr()` and `NULL`");
    return;
  }

  gpointer ptr;
  if (!_gum_v8_args_parse (args, "p~", &ptr))
    return;

  wrapper->SetInternalField (0,
      BigInt::NewFromUnsigned (isolate, GPOINTER_TO_SIZE (ptr)));
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_is_null)
{
  info.GetReturnValue ().Set (GUMJS_NATIVE_POINTER_VALUE (info.Holder ()) == 0);
}

#define GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL(name, op) \
    GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_##name) \
    { \
      gpointer lhs_ptr = GUMJS_NATIVE_POINTER_VALUE (info.Holder ()); \
      \
      gpointer rhs_ptr; \
      if (!_gum_v8_args_parse (args, "p~", &rhs_ptr)) \
        return; \
      \
      gsize lhs = GPOINTER_TO_SIZE (lhs_ptr); \
      gsize rhs = GPOINTER_TO_SIZE (rhs_ptr); \
      \
      gpointer result = GSIZE_TO_POINTER (lhs op rhs); \
      \
      info.GetReturnValue ().Set (_gum_v8_native_pointer_new (result, core)); \
    }

GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (add, +)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (sub, -)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (and, &)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (or,  |)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (xor, ^)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (shr, >>)
GUM_DEFINE_NATIVE_POINTER_BINARY_OP_IMPL (shl, <<)

#define GUM_DEFINE_NATIVE_POINTER_UNARY_OP_IMPL(name, op) \
    GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_##name) \
    { \
      gsize v = \
          GPOINTER_TO_SIZE (GUMJS_NATIVE_POINTER_VALUE (info.Holder ())); \
      \
      gpointer result = GSIZE_TO_POINTER (op v); \
      \
      info.GetReturnValue ().Set (_gum_v8_native_pointer_new (result, core)); \
    }

GUM_DEFINE_NATIVE_POINTER_UNARY_OP_IMPL (not, ~)

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_sign)
{
#ifdef HAVE_PTRAUTH
  gpointer value = GUMJS_NATIVE_POINTER_VALUE (info.Holder ());

  gchar * key = NULL;
  gpointer data = NULL;
  if (!_gum_v8_args_parse (args, "|sp~", &key, &data))
    return;

  bool valid = true;
  if (key == NULL || strcmp (key, "ia") == 0)
    value = ptrauth_sign_unauthenticated (value, ptrauth_key_asia, data);
  else if (strcmp (key, "ib") == 0)
    value = ptrauth_sign_unauthenticated (value, ptrauth_key_asib, data);
  else if (strcmp (key, "da") == 0)
    value = ptrauth_sign_unauthenticated (value, ptrauth_key_asda, data);
  else if (strcmp (key, "db") == 0)
    value = ptrauth_sign_unauthenticated (value, ptrauth_key_asdb, data);
  else
    valid = false;

  g_free (key);

  if (!valid)
  {
    _gum_v8_throw (isolate, "invalid key");
    return;
  }

  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (value, core));
#else
  info.GetReturnValue ().Set (info.This ());
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_strip)
{
#ifdef HAVE_PTRAUTH
  gpointer value = GUMJS_NATIVE_POINTER_VALUE (info.Holder ());

  gchar * key = NULL;
  if (!_gum_v8_args_parse (args, "|s", &key))
    return;

  bool valid = true;
  if (key == NULL || strcmp (key, "ia") == 0)
    value = ptrauth_strip (value, ptrauth_key_asia);
  else if (strcmp (key, "ib") == 0)
    value = ptrauth_strip (value, ptrauth_key_asib);
  else if (strcmp (key, "da") == 0)
    value = ptrauth_strip (value, ptrauth_key_asda);
  else if (strcmp (key, "db") == 0)
    value = ptrauth_strip (value, ptrauth_key_asdb);
  else
    valid = false;

  g_free (key);

  if (!valid)
  {
    _gum_v8_throw (isolate, "invalid key");
    return;
  }

  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (value, core));
#elif defined (HAVE_ANDROID) && defined (HAVE_ARM64)
  gpointer value = GUMJS_NATIVE_POINTER_VALUE (info.Holder ());

  /* https://source.android.com/devices/tech/debug/tagged-pointers */
  gpointer value_without_top_byte = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (value) & G_GUINT64_CONSTANT (0x00ffffffffffffff));

  if (value_without_top_byte == value)
  {
    info.GetReturnValue ().Set (info.This ());
    return;
  }

  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (value_without_top_byte, core));
#else
  info.GetReturnValue ().Set (info.This ());
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_blend)
{
#ifdef HAVE_PTRAUTH
  gpointer value = GUMJS_NATIVE_POINTER_VALUE (info.Holder ());

  guint small_integer;
  if (!_gum_v8_args_parse (args, "u", &small_integer))
    return;

  value = GSIZE_TO_POINTER (ptrauth_blend_discriminator (value, small_integer));

  info.GetReturnValue ().Set (_gum_v8_native_pointer_new (value, core));
#else
  info.GetReturnValue ().Set (info.This ());
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_compare)
{
  gpointer lhs_ptr = GUMJS_NATIVE_POINTER_VALUE (info.Holder ());

  gpointer rhs_ptr;
  if (!_gum_v8_args_parse (args, "p~", &rhs_ptr))
    return;

  gsize lhs = GPOINTER_TO_SIZE (lhs_ptr);
  gsize rhs = GPOINTER_TO_SIZE (rhs_ptr);

  int32_t result = (lhs == rhs) ? 0 : ((lhs < rhs) ? -1 : 1);

  info.GetReturnValue ().Set (result);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_int32)
{
  info.GetReturnValue ().Set ((int32_t) GPOINTER_TO_SIZE (
      GUMJS_NATIVE_POINTER_VALUE (info.Holder ())));
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_uint32)
{
  info.GetReturnValue ().Set ((uint32_t) GPOINTER_TO_SIZE (
      GUMJS_NATIVE_POINTER_VALUE (info.Holder ())));
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_string)
{
  gint radix = 0;
  if (!_gum_v8_args_parse (args, "|u", &radix))
    return;
  gboolean radix_specified = radix != 0;
  if (!radix_specified)
  {
    radix = 16;
  }
  else if (radix != 10 && radix != 16)
  {
    _gum_v8_throw_ascii_literal (isolate, "unsupported radix");
    return;
  }

  gsize ptr = GPOINTER_TO_SIZE (GUMJS_NATIVE_POINTER_VALUE (info.Holder ()));

  gchar str[32];
  if (radix == 10)
  {
    g_sprintf (str, "%" G_GSIZE_MODIFIER "u", ptr);
  }
  else
  {
    if (radix_specified)
      g_sprintf (str, "%" G_GSIZE_MODIFIER "x", ptr);
    else
      g_sprintf (str, "0x%" G_GSIZE_MODIFIER "x", ptr);
  }

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_json)
{
  gsize ptr = GPOINTER_TO_SIZE (GUMJS_NATIVE_POINTER_VALUE (info.Holder ()));

  gchar str[32];
  g_sprintf (str, "0x%" G_GSIZE_MODIFIER "x", ptr);

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, str));
}

GUMJS_DEFINE_FUNCTION (gumjs_native_pointer_to_match_pattern)
{
  gchar result[24];
  gint src, dst;
  const gint num_bits = GLIB_SIZEOF_VOID_P * 8;
  gsize ptr = GPOINTER_TO_SIZE (GUMJS_NATIVE_POINTER_VALUE (info.Holder ()));
  const gchar nibble_to_char[] = {
      '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
      'a', 'b', 'c', 'd', 'e', 'f'
  };

#if G_BYTE_ORDER == G_LITTLE_ENDIAN
  for (src = 0, dst = 0; src != num_bits; src += 8)
#else
  for (src = num_bits - 8, dst = 0; src >= 0; src -= 8)
#endif
  {
    if (dst != 0)
      result[dst++] = ' ';
    result[dst++] = nibble_to_char[(ptr >> (src + 4)) & 0xf];
    result[dst++] = nibble_to_char[(ptr >> (src + 0)) & 0xf];
  }
  result[dst] = '\0';

  info.GetReturnValue ().Set (_gum_v8_string_new_ascii (isolate, result));
}

GUMJS_DEFINE_FUNCTION (gumjs_array_buffer_wrap)
{
  Local<Value> result;

  gpointer address;
  gsize size;
  if (!_gum_v8_args_parse (args, "pZ", &address, &size))
    return;

  if (address != NULL && size > 0)
  {
    result = ArrayBuffer::New (isolate, ArrayBuffer::NewBackingStore (address,
        size, BackingStore::EmptyDeleter, nullptr));
  }
  else
  {
    result = ArrayBuffer::New (isolate, 0);
  }

  info.GetReturnValue ().Set (result);
}

GUMJS_DEFINE_FUNCTION (gumjs_array_buffer_unwrap)
{
  auto receiver = info.This ();
  if (!receiver->IsArrayBuffer ())
  {
    _gum_v8_throw_ascii_literal (isolate, "receiver must be an ArrayBuffer");
    return;
  }

  auto store = receiver.As<ArrayBuffer> ()->GetBackingStore ();
  info.GetReturnValue ().Set (
      _gum_v8_native_pointer_new (store->Data (), core));
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_native_function_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new NativeFunction()` to create a new instance");
    return;
  }

  GumV8NativeFunctionParams params;
  if (!gum_v8_native_function_params_init (&params, GUM_V8_RETURN_PLAIN, args))
    return;

  gumjs_native_function_init (wrapper, &params, core);
}

static void
gumjs_native_function_invoke (const FunctionCallbackInfo<Value> & info)
{
  auto self = (GumV8NativeFunction *)
      info.Holder ()->GetAlignedPointerFromInternalField (1);

  gum_v8_native_function_invoke (self, self->implementation, info, 0, nullptr);
}

GUMJS_DEFINE_FUNCTION (gumjs_native_function_call)
{
  auto num_args = info.Length ();

  Local<Object> receiver;
  if (num_args >= 1)
  {
    Local<Value> receiver_value = info[0];
    if (!receiver_value->IsNullOrUndefined ())
    {
      if (receiver_value->IsObject ())
      {
        receiver = receiver_value.As<Object> ();
      }
      else
      {
        _gum_v8_throw_ascii_literal (isolate, "invalid receiver");
        return;
      }
    }
  }

  GumV8NativeFunction * func;
  GCallback implementation;
  if (!gumjs_native_function_get (info, receiver, core, &func, &implementation))
    return;

  uint32_t argc = MAX ((int) num_args - 1, 0);

  Local<Value> * argv;
  if (argc > 0)
  {
    argv = g_newa (Local<Value>, argc);
    for (uint32_t i = 0; i != argc; i++)
    {
      new (&argv[i]) Local<Value> ();
      argv[i] = info[1 + i];
    }
  }
  else
  {
    argv = g_newa (Local<Value>, 1);
  }

  gum_v8_native_function_invoke (func, implementation, info, argc, argv);

  for (uint32_t i = 0; i != argc; i++)
    argv[i].~Local<Value> ();
}

GUMJS_DEFINE_FUNCTION (gumjs_native_function_apply)
{
  auto num_args = info.Length ();
  if (num_args < 1)
  {
    _gum_v8_throw_ascii_literal (isolate, "missing argument");
    return;
  }

  Local<Object> receiver;
  Local<Value> receiver_value = info[0];
  if (!receiver_value->IsNullOrUndefined ())
  {
    if (receiver_value->IsObject ())
    {
      receiver = receiver_value.As<Object> ();
    }
    else
    {
      _gum_v8_throw_ascii_literal (isolate, "invalid receiver");
      return;
    }
  }

  Local<Array> argv_array;
  if (num_args >= 2)
  {
    Local<Value> value = info[1];
    if (!value->IsNullOrUndefined ())
    {
      if (!value->IsArray ())
      {
        _gum_v8_throw_ascii_literal (isolate, "expected an array");
        return;
      }
      argv_array = value.As<Array> ();
    }
  }

  GumV8NativeFunction * func;
  GCallback implementation;
  if (!gumjs_native_function_get (info, receiver, core, &func, &implementation))
    return;

  uint32_t argc = (!argv_array.IsEmpty ()) ? argv_array->Length () : 0;

  Local<Value> * argv;
  if (argc > 0)
  {
    auto context = isolate->GetCurrentContext ();

    argv = g_newa (Local<Value>, argc);
    for (uint32_t i = 0; i != argc; i++)
    {
      new (&argv[i]) Local<Value> ();
      if (!argv_array->Get (context, i).ToLocal (&argv[i]))
      {
        for (uint32_t j = 0; j <= i; j++)
          argv[j].~Local<Value> ();
        return;
      }
    }
  }
  else
  {
    argv = g_newa (Local<Value>, 1);
  }

  gum_v8_native_function_invoke (func, implementation, info, argc, argv);

  for (uint32_t i = 0; i != argc; i++)
    argv[i].~Local<Value> ();
}

static gboolean
gumjs_native_function_get (const FunctionCallbackInfo<Value> & info,
                           Local<Object> receiver,
                           GumV8Core * core,
                           GumV8NativeFunction ** func,
                           GCallback * implementation)
{
  auto isolate = core->isolate;

  auto native_function = Local<FunctionTemplate>::New (isolate,
      *core->native_function);
  auto holder = info.Holder ();
  if (native_function->HasInstance (holder))
  {
    auto f =
        (GumV8NativeFunction *) holder->GetAlignedPointerFromInternalField (1);

    *func = f;

    if (!receiver.IsEmpty ())
    {
      if (!_gum_v8_native_pointer_get (receiver, (gpointer *) implementation,
          core))
        return FALSE;
    }
    else
    {
      *implementation = f->implementation;
    }
  }
  else
  {
    if (receiver.IsEmpty () || !native_function->HasInstance (receiver))
    {
      _gum_v8_throw_ascii_literal (isolate, "expected a NativeFunction");
      return FALSE;
    }

    auto f = (GumV8NativeFunction *)
        receiver->GetAlignedPointerFromInternalField (1);
    *func = f;
    *implementation = f->implementation;
  }

  return TRUE;
}

static GumV8NativeFunction *
gumjs_native_function_init (Local<Object> wrapper,
                            const GumV8NativeFunctionParams * params,
                            GumV8Core * core)
{
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();
  GumV8NativeFunction * func;
  ffi_type * rtype;
  uint32_t nargs_fixed, nargs_total, i;
  gboolean is_variadic;
  ffi_abi abi;

  func = g_slice_new0 (GumV8NativeFunction);
  func->implementation = params->implementation;
  func->scheduling = params->scheduling;
  func->exceptions = params->exceptions;
  func->traps = params->traps;
  func->return_shape = params->return_shape;
  func->core = core;

  if (!gum_v8_ffi_type_get (core, params->return_type, &rtype, &func->data))
    goto error;

  nargs_fixed = nargs_total = params->argument_types->Length ();
  is_variadic = FALSE;
  func->atypes = g_new (ffi_type *, nargs_total);
  for (i = 0; i != nargs_total; i++)
  {
    Local<Value> type;
    if (!params->argument_types->Get (context, i).ToLocal (&type))
      goto error;

    String::Utf8Value type_utf8 (isolate, type);
    if (strcmp (*type_utf8, "...") == 0)
    {
      if (i == 0 || is_variadic)
      {
        _gum_v8_throw_ascii_literal (isolate,
            "only one variadic marker may be specified, and can "
            "not be the first argument");
        goto error;
      }

      nargs_fixed = i;
      is_variadic = TRUE;
    }
    else
    {
      auto atype = &func->atypes[is_variadic ? i - 1 : i];

      if (!gum_v8_ffi_type_get (core, type, atype, &func->data))
        goto error;

      if (is_variadic)
        *atype = gum_ffi_maybe_promote_variadic (*atype);
    }
  }
  if (is_variadic)
    nargs_total--;

  abi = FFI_DEFAULT_ABI;
  if (!params->abi.IsEmpty ())
  {
    if (!gum_v8_ffi_abi_get (core, params->abi, &abi))
      goto error;
  }

  if (is_variadic)
  {
    if (ffi_prep_cif_var (&func->cif, abi, nargs_fixed, nargs_total, rtype,
        func->atypes) != FFI_OK)
    {
      _gum_v8_throw_ascii_literal (isolate,
          "failed to compile function call interface");
      goto error;
    }
  }
  else
  {
    if (ffi_prep_cif (&func->cif, abi, nargs_total, rtype,
        func->atypes) != FFI_OK)
    {
      _gum_v8_throw_ascii_literal (isolate,
          "failed to compile function call interface");
      goto error;
    }
  }

  func->is_variadic = nargs_fixed < nargs_total;
  func->nargs_fixed = nargs_fixed;
  func->abi = abi;

  for (i = 0; i != nargs_total; i++)
  {
    ffi_type * t = func->atypes[i];

    func->arglist_size = GUM_ALIGN_SIZE (func->arglist_size, t->alignment);
    func->arglist_size += t->size;
  }

  wrapper->SetInternalField (0, BigInt::NewFromUnsigned (isolate,
        GPOINTER_TO_SIZE (func->implementation)));
  wrapper->SetAlignedPointerInInternalField (1, func);

  func->wrapper = new Global<Object> (isolate, wrapper);
  func->wrapper->SetWeak (func, gum_v8_native_function_on_weak_notify,
      WeakCallbackType::kParameter);

  g_hash_table_add (core->native_functions, func);

  return func;

error:
  gum_v8_native_function_free (func);
  return NULL;
}

static void
gum_v8_native_function_free (GumV8NativeFunction * self)
{
  delete self->wrapper;

  while (self->data != NULL)
  {
    auto head = self->data;
    g_free (head->data);
    self->data = g_slist_delete_link (self->data, head);
  }
  g_free (self->atypes);

  g_slice_free (GumV8NativeFunction, self);
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

static void
gum_v8_native_function_invoke (GumV8NativeFunction * self,
                               GCallback implementation,
                               const FunctionCallbackInfo<Value> & info,
                               uint32_t argc,
                               Local<Value> * argv)
{
  auto core = (GumV8Core *) info.Data ().As<External> ()->Value ();
  auto script_scope = core->current_scope;
  auto isolate = core->isolate;
  auto cif = &self->cif;
  gsize num_args_declared = cif->nargs;
  gsize num_args_provided = (argv != nullptr) ? argc : info.Length ();
  gsize num_args_fixed = self->nargs_fixed;
  gboolean is_variadic = self->is_variadic;

  if ((is_variadic && num_args_provided < num_args_fixed) ||
      (!is_variadic && num_args_provided != num_args_declared))
  {
    _gum_v8_throw_ascii_literal (isolate, "bad argument count");
    return;
  }

  auto rtype = cif->rtype;
  auto atypes = cif->arg_types;
  gsize rsize = MAX (rtype->size, sizeof (gsize));
  gsize ralign = MAX (rtype->alignment, sizeof (gsize));
  auto rvalue = (GumFFIValue *) g_alloca (rsize + ralign - 1);
  rvalue = GUM_ALIGN_POINTER (GumFFIValue *, rvalue, ralign);

  void ** avalue;
  guint8 * avalues;
  ffi_cif tmp_cif;
  GumFFIValue tmp_value = { 0, };

  if (num_args_provided > 0)
  {
    gsize avalue_count = MAX (num_args_declared, num_args_provided);
    avalue = g_newa (void *, avalue_count);

    gsize arglist_size = self->arglist_size;
    if (is_variadic && num_args_provided > num_args_declared)
    {
      atypes = g_newa (ffi_type *, num_args_provided);

      memcpy (atypes, cif->arg_types, num_args_declared * sizeof (void *));
      for (gsize i = num_args_declared, type_idx = num_args_fixed;
          i != num_args_provided; i++)
      {
        ffi_type * t = cif->arg_types[type_idx];

        atypes[i] = t;
        arglist_size = GUM_ALIGN_SIZE (arglist_size, t->alignment);
        arglist_size += t->size;

        if (++type_idx >= num_args_declared)
          type_idx = num_args_fixed;
      }

      cif = &tmp_cif;
      if (ffi_prep_cif_var (cif, self->abi, num_args_fixed, num_args_provided,
          rtype, atypes) != FFI_OK)
      {
        _gum_v8_throw_ascii_literal (isolate,
            "failed to compile function call interface");
      }
    }

    gsize arglist_alignment = atypes[0]->alignment;
    avalues = (guint8 *) g_alloca (arglist_size + arglist_alignment - 1);
    avalues = GUM_ALIGN_POINTER (guint8 *, avalues, arglist_alignment);

    /* Prefill with zero to clear high bits of values smaller than a pointer. */
    memset (avalues, 0, arglist_size);

    gsize offset = 0;
    for (gsize i = 0; i != num_args_provided; i++)
    {
      auto t = atypes[i];

      offset = GUM_ALIGN_SIZE (offset, t->alignment);

      auto v = (GumFFIValue *) (avalues + offset);

      if (!gum_v8_value_to_ffi_type (core,
          (argv != nullptr) ? argv[i] : info[i], v, t))
        return;
      avalue[i] = v;

      offset += t->size;
    }

    for (gsize i = num_args_provided; i < num_args_declared; i++)
      avalue[i] = &tmp_value;
  }
  else
  {
    avalue = NULL;
  }

  auto scheduling = self->scheduling;
  auto exceptions = self->exceptions;
  auto traps = self->traps;
  auto return_shape = self->return_shape;
  GumExceptorScope exceptor_scope;
  GumInvocationState invocation_state;
  gint system_error = -1;

  {
    auto unlocker = g_newa (ScriptUnlocker, 1);
    auto interceptor = core->script->interceptor.interceptor;
    gboolean interceptor_was_ignoring_us = FALSE;
    GumStalker * stalker = NULL;

    if (exceptions == GUM_V8_EXCEPTIONS_PROPAGATE ||
        gum_exceptor_try (core->exceptor, &exceptor_scope))
    {
      if (exceptions == GUM_V8_EXCEPTIONS_STEAL)
        gum_interceptor_save (&invocation_state);

      if (scheduling == GUM_V8_SCHEDULING_COOPERATIVE)
      {
        new (unlocker) ScriptUnlocker (core);

        if (traps != GUM_V8_CODE_TRAPS_NONE)
        {
          interceptor_was_ignoring_us =
              gum_interceptor_maybe_unignore_current_thread (interceptor);
        }
      }

      if (traps == GUM_V8_CODE_TRAPS_ALL)
      {
        auto stalker_module = &core->script->stalker;

        _gum_v8_stalker_process_pending (stalker_module,
            &script_scope->stalker_scope);

        stalker = _gum_v8_stalker_get (stalker_module);
        gum_stalker_activate (stalker, GUM_FUNCPTR_TO_POINTER (implementation));
      }
      else if (traps == GUM_V8_CODE_TRAPS_NONE)
      {
        gum_interceptor_ignore_current_thread (interceptor);
      }

      ffi_call (cif, FFI_FN (implementation), rvalue, avalue);

      g_clear_pointer (&stalker, gum_stalker_deactivate);

      if (return_shape == GUM_V8_RETURN_DETAILED)
        system_error = gum_thread_get_system_error ();
    }

    g_clear_pointer (&stalker, gum_stalker_deactivate);

    if (traps == GUM_V8_CODE_TRAPS_NONE)
      gum_interceptor_unignore_current_thread (interceptor);

    if (scheduling == GUM_V8_SCHEDULING_COOPERATIVE)
    {
      if (traps != GUM_V8_CODE_TRAPS_NONE && interceptor_was_ignoring_us)
        gum_interceptor_ignore_current_thread (interceptor);

      unlocker->~ScriptUnlocker ();
    }
  }

  if (exceptions == GUM_V8_EXCEPTIONS_STEAL &&
      gum_exceptor_catch (core->exceptor, &exceptor_scope))
  {
    gum_interceptor_restore (&invocation_state);

    _gum_v8_throw_native (&exceptor_scope.exception, core);
    return;
  }

  Local<Value> result;
  if (!gum_v8_value_from_ffi_type (core, &result, rvalue, rtype))
    return;

  if (return_shape == GUM_V8_RETURN_DETAILED)
  {
    auto context = isolate->GetCurrentContext ();

    auto template_return_value =
        Local<Object>::New (isolate, *core->native_return_value);
    auto return_value = template_return_value->Clone ();
    return_value->Set (context,
        Local<String>::New (isolate, *core->value_key),
        result).Check ();
    return_value->Set (context,
        Local<String>::New (isolate, *core->system_error_key),
        Integer::New (isolate, system_error)).Check ();
    info.GetReturnValue ().Set (return_value);
  }
  else
  {
    info.GetReturnValue ().Set (result);
  }
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

static void
gum_v8_native_function_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeFunction> & info)
{
  HandleScope handle_scope (info.GetIsolate ());
  auto self = info.GetParameter ();
  g_hash_table_remove (self->core->native_functions, self);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_system_function_construct)
{
  if (!info.IsConstructCall ())
  {
    _gum_v8_throw_ascii_literal (isolate,
        "use `new SystemFunction()` to create a new instance");
    return;
  }

  GumV8NativeFunctionParams params;
  if (!gum_v8_native_function_params_init (&params, GUM_V8_RETURN_DETAILED,
      args))
    return;

  gumjs_native_function_init (wrapper, &params, core);
}

static gboolean
gum_v8_native_function_params_init (GumV8NativeFunctionParams * params,
                                    GumV8ReturnValueShape return_shape,
                                    const GumV8Args * args)
{
  auto core = args->core;
  auto isolate = core->isolate;

  Local<Value> abi_or_options;
  if (!_gum_v8_args_parse (args, "pVA|V", &params->implementation,
      &params->return_type, &params->argument_types, &abi_or_options))
    return FALSE;
  params->scheduling = GUM_V8_SCHEDULING_COOPERATIVE;
  params->exceptions = GUM_V8_EXCEPTIONS_STEAL;
  params->traps = GUM_V8_CODE_TRAPS_DEFAULT;
  params->return_shape = return_shape;

  if (!abi_or_options.IsEmpty ())
  {
    if (abi_or_options->IsString ())
    {
      params->abi = abi_or_options;
    }
    else if (abi_or_options->IsObject () && !abi_or_options->IsNull ())
    {
      Local<Object> options = abi_or_options.As<Object> ();

      auto context = isolate->GetCurrentContext ();
      Local<Value> v;

      if (!options->Get (context, Local<String>::New (isolate, *core->abi_key))
          .ToLocal (&v))
        return FALSE;
      if (!v->IsUndefined ())
        params->abi = v;

      if (!options->Get (context, Local<String>::New (isolate,
          *core->scheduling_key)).ToLocal (&v))
        return FALSE;
      if (!v->IsUndefined ())
      {
        if (!gum_v8_scheduling_behavior_parse (v, &params->scheduling, isolate))
          return FALSE;
      }

      if (!options->Get (context, Local<String>::New (isolate,
          *core->exceptions_key)).ToLocal (&v))
        return FALSE;
      if (!v->IsUndefined ())
      {
        if (!gum_v8_exceptions_behavior_parse (v, &params->exceptions, isolate))
          return FALSE;
      }

      if (!options->Get (context,
"""


```