Response:
Let's break down the thought process for analyzing the `gumquickthread.c` file.

**1. Understanding the Goal:** The core request is to understand the *functionality* of this specific C file within the Frida ecosystem, focusing on its relationship to reverse engineering, low-level details, logic, potential errors, and how a user might reach this code.

**2. Initial Code Scan (Keywords and Structure):**  A quick scan reveals key terms and structures:

* `#include`: Immediately indicates this file relies on other Frida components (`gumquickthread.h`, `gumquickmacros.h`).
* `enum _GumBacktracerType`: Suggests handling of different backtracing methods.
* `GUMJS_DECLARE_*`: A recurring pattern indicating functions exposed to JavaScript. This is a crucial observation, as it highlights the bridge between the C code and Frida's user-facing API.
* `static const JSClassDef gumjs_thread_def`: Defines the JavaScript class "Thread".
* `static const JSCFunctionListEntry`: Lists functions and properties associated with the "Thread" class and a "Backtracer" object.
* `_gum_quick_thread_init`:  A likely initialization function, setting up the JavaScript "Thread" object.
* `GUMJS_DEFINE_FUNCTION`: Defines the implementations of the JavaScript-exposed functions. The names (e.g., `gumjs_thread_backtrace`, `gumjs_thread_sleep`, `gumjs_thread_set_hardware_breakpoint`) are highly informative.

**3. Deciphering Functionality (Function by Function):** Now, the detailed analysis starts, focusing on each `GUMJS_DEFINE_FUNCTION`.

* **`gumjs_thread_backtrace`:**
    * Input: Optionally a `GumCpuContext` and `type` (accurate/fuzzy), and a `limit`.
    * Process:  Selects a backtracer (accurate or fuzzy) based on the `type`. Generates a backtrace using `gum_backtracer_generate` or `gum_backtracer_generate_with_limit`. Converts the raw addresses to JavaScript `NativePointer` objects.
    * Output: A JavaScript array of `NativePointer` objects representing the call stack.
    * Reverse Engineering Relevance: Directly related to understanding program flow.
    * Low-Level Details:  Deals with CPU context, return addresses. Mentions platform limitations ("not yet available").
    * Logic/Assumptions: Assumes valid `type` and `limit`.
    * User Error: Providing an invalid `type`.

* **`gumjs_thread_sleep`:**
    * Input: `delay` (in seconds).
    * Process: Suspends the current thread using `g_usleep`.
    * Output: `undefined`.
    * Reverse Engineering Relevance: Useful for timing analysis or delaying execution.
    * Low-Level Details: Uses `g_usleep`, a system-level sleep function.
    * Logic/Assumptions:  Handles negative delays.
    * User Error:  Providing a negative delay (although the code handles it gracefully).

* **`gumjs_thread_new`:**
    * Purpose: *Internal* function to create a JavaScript "Thread" object based on `GumThreadDetails`.
    * Input: `GumThreadDetails` (containing thread ID, name, state, CPU context).
    * Process: Creates a JavaScript object with properties like `id`, `name`, `state`, `context`.
    * Output: A JavaScript "Thread" object.
    * Low-Level Details:  Deals with `GumThreadDetails`, likely coming from the operating system or Frida's core.

* **`gumjs_thread_construct`:**
    * Purpose: Constructor for the JavaScript "Thread" class.
    * Input: A `thread_id`.
    * Process: Creates a new JavaScript object with the "Thread" prototype and sets its internal opaque data to the `thread_id`.

* **`gumjs_thread_set_hardware_breakpoint`:**
    * Input: `breakpoint_id`, `address`.
    * Process: Calls `gum_thread_set_hardware_breakpoint` to set a hardware breakpoint.
    * Output: `undefined`.
    * Reverse Engineering Relevance: Powerful debugging technique.
    * Low-Level Details:  Hardware breakpoints are a CPU feature.
    * User Error:  Incorrect `breakpoint_id` or `address`.

* **`gumjs_thread_unset_hardware_breakpoint`:**
    * Input: `breakpoint_id`.
    * Process: Calls `gum_thread_unset_hardware_breakpoint`.
    * Output: `undefined`.
    * User Error: Incorrect `breakpoint_id`.

* **`gumjs_thread_set_hardware_watchpoint`:**
    * Input: `watchpoint_id`, `address`, `size`, `conditions_str` (e.g., "rw").
    * Process: Parses the conditions string, then calls `gum_thread_set_hardware_watchpoint`.
    * Output: `undefined`.
    * Reverse Engineering Relevance:  Crucial for tracking memory access.
    * Low-Level Details: Hardware watchpoints are a CPU feature.
    * User Error: Invalid `conditions_str`, incorrect `watchpoint_id`, `address`, or `size`.

* **`gumjs_thread_unset_hardware_watchpoint`:**
    * Input: `watchpoint_id`.
    * Process: Calls `gum_thread_unset_hardware_watchpoint`.
    * Output: `undefined`.
    * User Error: Incorrect `watchpoint_id`.

**4. Identifying Key Concepts:**  From the function analysis, the core functionalities emerge:

* **Thread Management:**  Operations related to threads (getting backtraces, sleeping, setting breakpoints/watchpoints).
* **Backtracing:**  Retrieving the call stack.
* **Hardware Debugging:** Utilizing hardware breakpoints and watchpoints.
* **JavaScript Binding:** Exposing these functionalities to Frida's JavaScript API.

**5. Connecting to Reverse Engineering:**  Explicitly link the functionalities to reverse engineering tasks: analyzing program flow (backtrace), controlling execution (sleep), and monitoring memory/code execution (breakpoints/watchpoints).

**6. Identifying Low-Level Details:** Point out the interaction with CPU context, return addresses, hardware debugging features, and system-level functions like `g_usleep`. Mention the potential OS/architecture dependence of backtracing.

**7. Logical Reasoning and Examples:** For functions with clear logic (like `gumjs_thread_backtrace`), create simple "if-then" examples to illustrate input/output. For error handling, predict common user mistakes and how the code reacts.

**8. User Journey (Debugging Clue):**  Consider how a user would actually use these functions in a Frida script. Start with attaching to a process, accessing the `Thread` object, and then calling the relevant methods. This provides the "how did I get here?" context.

**9. Structuring the Output:** Organize the information logically using headings and bullet points for clarity. Group related functionalities together. Use code snippets (even simplified) to illustrate usage.

**Self-Correction/Refinement During the Process:**

* **Initial thought:** Focus solely on the C code.
* **Correction:** Realize the primary purpose is exposing functionality to *JavaScript*. The JavaScript API is the user's interface.
* **Initial thought:**  Just list the functions.
* **Correction:**  Explain *what* each function does, *why* it's useful for reverse engineering, and the underlying technical details.
* **Initial thought:**  Assume a deep understanding of Frida internals.
* **Correction:** Provide context and explain concepts like "hardware breakpoints" if necessary. Focus on making it understandable to someone learning Frida.

By following these steps, combining code analysis with an understanding of Frida's purpose and usage, you can arrive at a comprehensive explanation of the `gumquickthread.c` file.
这个文件 `gumquickthread.c` 是 Frida 工具中 `frida-gum` 库的组成部分，负责将与线程相关的底层功能暴露给 JavaScript 环境。它允许 Frida 用户通过 JavaScript 代码来操作和检查目标进程的线程。

以下是该文件的功能列表：

1. **线程回溯 (Backtrace):**
   - `gumjs_thread_backtrace`: 允许获取指定线程的调用栈信息。它支持两种模式：
     - `ACCURATE`: 尝试获取精确的回溯信息。
     - `FUZZY`: 在无法获取精确信息时，尝试获取模糊的回溯信息。
   - 这与逆向分析中理解程序执行流程至关重要。通过回溯，可以知道当前代码是如何被调用的，以及调用链上的函数。
   - **举例说明 (逆向):** 假设你Hook了一个函数，并想知道是哪个函数调用了它。你可以使用 `Thread.backtrace()` 来获取调用栈，从而找到调用者。

2. **线程休眠 (Sleep):**
   - `gumjs_thread_sleep`: 允许让当前 Frida 脚本执行的线程休眠指定的时间。
   - 这在逆向中可能用于同步操作或者在特定时间点执行某些代码。
   - **举例说明 (逆向):** 你可能需要在某个操作完成后等待一段时间，以便观察目标程序的后续行为。可以使用 `Thread.sleep(1)` 让 Frida 脚本休眠 1 秒。

3. **硬件断点 (Hardware Breakpoints):**
   - `gumjs_thread_set_hardware_breakpoint`: 允许在指定线程上设置硬件断点。硬件断点由 CPU 提供支持，通常用于在代码的特定地址执行时中断程序。
   - `gumjs_thread_unset_hardware_breakpoint`: 允许移除已设置的硬件断点。
   - 这在逆向中是一种强大的调试技术，可以精确地在某个指令执行前暂停程序，便于分析寄存器状态和内存。
   - **涉及二进制底层知识:** 硬件断点直接与 CPU 的调试寄存器交互，例如 x86 架构的 DR0-DR3 寄存器用于存储断点地址。
   - **举例说明 (逆向):** 你可能想在某个关键函数入口处暂停程序，查看参数传递情况。可以使用 `Thread.setHardwareBreakpoint(0, address)` 在地址 `address` 设置一个硬件断点（假设使用断点 ID 0）。

4. **硬件观察点 (Hardware Watchpoints):**
   - `gumjs_thread_set_hardware_watchpoint`: 允许在指定线程上设置硬件观察点。硬件观察点会在指定内存地址被读取或写入时中断程序。
   - `gumjs_thread_unset_hardware_watchpoint`: 允许移除已设置的硬件观察点。
   - 这在逆向中用于追踪特定内存地址的访问，例如查找修改某个关键变量的代码。
   - **涉及二进制底层知识:** 硬件观察点也依赖于 CPU 的调试寄存器，例如 x86 架构的 DR0-DR3 寄存器以及 DR7 寄存器用于配置观察点的类型和大小。
   - **涉及 Linux/Android 内核及框架的知识:**  操作系统内核需要支持硬件调试功能，并提供相应的接口供 Frida 等工具使用。Android 框架的底层也是基于 Linux 内核的。
   - **举例说明 (逆向):** 你想知道哪个代码修改了某个全局变量的值。可以使用 `Thread.setHardwareWatchpoint(0, address, size, 'w')` 在地址 `address` 处设置一个写观察点，观察 `size` 字节的内存。

5. **Thread 对象的创建和管理:**
   - `gumjs_thread_construct`:  JavaScript 中 `Thread` 对象的构造函数。它接收一个线程 ID。
   - `_gum_quick_thread_new`:  在 C 代码中创建并初始化 `Thread` 对象，将底层的线程信息（ID、名称、状态、CPU 上下文）关联到 JavaScript 对象。
   - 这使得 Frida 用户可以通过 JavaScript 代码来表示和操作目标进程的线程。
   - **涉及 Linux/Android 内核及框架的知识:**  线程的概念是操作系统提供的，Frida 需要与操作系统交互来获取线程信息。

**逻辑推理的举例说明:**

假设输入以下 Frida JavaScript 代码：

```javascript
const threadId = Process.getCurrentThreadId();
const thread = new Thread(threadId);
const backtrace = thread._backtrace();
console.log(backtrace);
```

**假设输入:** 当前 Frida 脚本运行在目标进程的某个线程中。

**输出:** `backtrace` 将是一个 JavaScript数组，包含了当前线程的调用栈地址。数组中的每个元素都是一个 `NativePointer` 对象，指向返回地址。

**用户或编程常见的使用错误:**

1. **尝试在所有线程上设置过多的硬件断点/观察点:**  硬件断点和观察点的数量通常是有限的（例如，x86 架构通常只有 4 个硬件断点寄存器）。尝试设置过多会导致错误或不可预测的行为。
   - **错误示例:**  在一个循环中，尝试为每个线程都设置一个硬件断点。
   - **Frida 可能会抛出异常:**  提示硬件资源不足。

2. **为硬件断点/观察点提供无效的地址或大小:** 提供的地址可能不是一个有效的内存地址，或者大小超出了限制。
   - **错误示例:** `Thread.setHardwareBreakpoint(0, 0x1);` (地址 0x1 可能无效).
   - **Frida 可能会抛出异常:** 指示地址无效。

3. **使用错误的硬件观察点条件字符串:**  `gumjs_thread_set_hardware_watchpoint` 期望的条件字符串是 "r" (读) 或 "w" (写) 或 "rw" (读写)。提供其他字符串会导致错误。
   - **错误示例:** `Thread.setHardwareWatchpoint(0, address, 4, 'x');`
   - **Frida 可能会抛出异常:**  提示条件字符串无效。

**用户操作是如何一步步到达这里（作为调试线索）:**

1. **用户启动 Frida 并附加到目标进程:** 用户使用 Frida 的命令行工具 (例如 `frida -p <pid>`) 或通过 API (例如 Python 的 `frida.attach()`) 连接到目标进程。

2. **用户编写 Frida 脚本并加载到目标进程:** 用户编写 JavaScript 代码，利用 Frida 提供的 API 来进行动态插桩。这个脚本可能包含对 `Thread` 对象的创建和操作。

3. **脚本中调用了 `Thread` 相关的 API:**  例如，用户在脚本中使用了 `Thread.backtrace()`、`Thread.sleep()`、`Thread.setHardwareBreakpoint()` 或 `Thread.setHardwareWatchpoint()`。

4. **Frida 的 JavaScript 引擎 (QuickJS) 执行到这些 API 调用:**  当 JavaScript 引擎执行到这些 `Thread` 对象的方法时，它会调用对应的 C 函数，这些 C 函数就在 `gumquickthread.c` 文件中实现。

5. **`gumquickthread.c` 中的函数被执行:**  例如，如果用户调用了 `Thread.backtrace()`, 那么 `gumjs_thread_backtrace` 函数会被调用。这个函数会进一步调用 Frida Gum 库的底层函数来获取线程的回溯信息。

**总结:**

`gumquickthread.c` 文件是 Frida 中与线程操作相关的核心组件，它通过 QuickJS 桥接了底层的 Gum 库功能和 JavaScript API，使得用户能够方便地在运行时检查和控制目标进程的线程行为，这对于动态逆向分析和安全研究至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickthread.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2020-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2024 DaVinci <nstefanclaudel13@gmail.com>
 * Copyright (C) 2024 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickthread.h"

#include "gumquickmacros.h"

enum _GumBacktracerType
{
  GUM_BACKTRACER_ACCURATE = 1,
  GUM_BACKTRACER_FUZZY = 2
};

GUMJS_DECLARE_FUNCTION (gumjs_thread_backtrace)
GUMJS_DECLARE_FUNCTION (gumjs_thread_sleep)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_thread_construct)
GUMJS_DECLARE_FUNCTION (gumjs_thread_set_hardware_breakpoint)
GUMJS_DECLARE_FUNCTION (gumjs_thread_unset_hardware_breakpoint)
GUMJS_DECLARE_FUNCTION (gumjs_thread_set_hardware_watchpoint)
GUMJS_DECLARE_FUNCTION (gumjs_thread_unset_hardware_watchpoint)

static const JSClassDef gumjs_thread_def =
{
  .class_name = "Thread",
};

static const JSCFunctionListEntry gumjs_thread_module_entries[] =
{
  JS_CFUNC_DEF ("_backtrace", 0, gumjs_thread_backtrace),
  JS_CFUNC_DEF ("sleep", 0, gumjs_thread_sleep),
};

static const JSCFunctionListEntry gumjs_thread_entries[] =
{
  JS_CFUNC_DEF ("setHardwareBreakpoint", 0,
      gumjs_thread_set_hardware_breakpoint),
  JS_CFUNC_DEF ("unsetHardwareBreakpoint", 0,
      gumjs_thread_unset_hardware_breakpoint),
  JS_CFUNC_DEF ("setHardwareWatchpoint", 0,
      gumjs_thread_set_hardware_watchpoint),
  JS_CFUNC_DEF ("unsetHardwareWatchpoint", 0,
      gumjs_thread_unset_hardware_watchpoint),
};

static const JSCFunctionListEntry gumjs_backtracer_entries[] =
{
  JS_PROP_INT32_DEF ("ACCURATE", GUM_BACKTRACER_ACCURATE, JS_PROP_C_W_E),
  JS_PROP_INT32_DEF ("FUZZY", GUM_BACKTRACER_FUZZY, JS_PROP_C_W_E),
};

void
_gum_quick_thread_init (GumQuickThread * self,
                        JSValue ns,
                        GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue obj, proto, ctor;

  self->core = core;

  _gum_quick_core_store_module_data (core, "thread", self);

  _gum_quick_create_class (ctx, &gumjs_thread_def, core, &self->thread_class,
      &proto);
  ctor = JS_NewCFunction2 (ctx, gumjs_thread_construct,
      gumjs_thread_def.class_name, 0, JS_CFUNC_constructor, 0);
  JS_SetConstructor (ctx, ctor, proto);
  JS_SetPropertyFunctionList (ctx, ctor, gumjs_thread_module_entries,
      G_N_ELEMENTS (gumjs_thread_module_entries));
  JS_SetPropertyFunctionList (ctx, proto, gumjs_thread_entries,
      G_N_ELEMENTS (gumjs_thread_entries));
  JS_DefinePropertyValueStr (ctx, ns, gumjs_thread_def.class_name, ctor,
      JS_PROP_C_W_E);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_backtracer_entries,
      G_N_ELEMENTS (gumjs_backtracer_entries));
  JS_DefinePropertyValueStr (ctx, ns, "Backtracer", obj, JS_PROP_C_W_E);
}

void
_gum_quick_thread_dispose (GumQuickThread * self)
{
}

void
_gum_quick_thread_finalize (GumQuickThread * self)
{
  g_clear_pointer (&self->accurate_backtracer, g_object_unref);
  g_clear_pointer (&self->fuzzy_backtracer, g_object_unref);
}

static GumQuickThread *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "thread");
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_backtrace)
{
  JSValue result;
  GumQuickThread * self;
  GumCpuContext * cpu_context;
  gint type;
  guint limit;
  GumBacktracer * backtracer;
  GumReturnAddressArray ret_addrs;
  guint i;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "C?iu", &cpu_context, &type, &limit))
    return JS_EXCEPTION;

  if (type != GUM_BACKTRACER_ACCURATE && type != GUM_BACKTRACER_FUZZY)
    goto invalid_type;

  if (type == GUM_BACKTRACER_ACCURATE)
  {
    if (self->accurate_backtracer == NULL)
      self->accurate_backtracer = gum_backtracer_make_accurate ();
    backtracer = self->accurate_backtracer;
  }
  else
  {
    if (self->fuzzy_backtracer == NULL)
      self->fuzzy_backtracer = gum_backtracer_make_fuzzy ();
    backtracer = self->fuzzy_backtracer;
  }
  if (backtracer == NULL)
    goto not_available;

  if (limit != 0)
  {
    gum_backtracer_generate_with_limit (backtracer, cpu_context, &ret_addrs,
        limit);
  }
  else
  {
    gum_backtracer_generate (backtracer, cpu_context, &ret_addrs);
  }

  result = JS_NewArray (ctx);

  for (i = 0; i != ret_addrs.len; i++)
  {
    JS_DefinePropertyValueUint32 (ctx, result, i,
        _gum_quick_native_pointer_new (ctx, ret_addrs.items[i], core),
        JS_PROP_C_W_E);
  }

  return result;

invalid_type:
  {
    return _gum_quick_throw_literal (ctx, "invalid backtracer enum value");
  }
not_available:
  {
    return _gum_quick_throw_literal (ctx, (type == GUM_BACKTRACER_ACCURATE)
        ? "backtracer not yet available for this platform; "
        "please try Thread.backtrace(context, Backtracer.FUZZY)"
        : "backtracer not yet available for this platform; "
        "please try Thread.backtrace(context, Backtracer.ACCURATE)");
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_sleep)
{
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  gdouble delay;

  if (!_gum_quick_args_parse (args, "n", &delay))
    return JS_EXCEPTION;

  if (delay < 0)
    return JS_UNDEFINED;

  _gum_quick_scope_suspend (&scope);

  g_usleep ((gulong) (delay * G_USEC_PER_SEC));

  _gum_quick_scope_resume (&scope);

  return JS_UNDEFINED;
}

JSValue
_gum_quick_thread_new (JSContext * ctx,
                       const GumThreadDetails * details,
                       GumQuickThread * parent)
{
  GumQuickCore * core = parent->core;
  JSValue thread;

  thread = JS_NewObjectClass (ctx, parent->thread_class);

  JS_SetOpaque (thread, GSIZE_TO_POINTER (details->id));

  JS_DefinePropertyValue (ctx, thread,
      GUM_QUICK_CORE_ATOM (core, id),
      JS_NewInt64 (ctx, details->id),
      JS_PROP_C_W_E);
  if (details->name != NULL)
  {
    JS_DefinePropertyValue (ctx, thread,
        GUM_QUICK_CORE_ATOM (core, name),
        JS_NewString (ctx, details->name),
        JS_PROP_C_W_E);
  }
  JS_DefinePropertyValue (ctx, thread,
      GUM_QUICK_CORE_ATOM (core, state),
      _gum_quick_thread_state_new (ctx, details->state),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, thread,
      GUM_QUICK_CORE_ATOM (core, context),
      _gum_quick_cpu_context_new (ctx, (GumCpuContext *) &details->cpu_context,
          GUM_CPU_CONTEXT_READONLY, core, NULL),
      JS_PROP_C_W_E);

  return thread;
}

static gboolean
gum_thread_get (JSContext * ctx,
                JSValueConst val,
                GumQuickCore * core,
                GumThreadId * thread_id)
{
  return _gum_quick_unwrap (ctx, val,
      gumjs_get_parent_module (core)->thread_class, core,
      (gpointer *) thread_id);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_thread_construct)
{
  JSValue wrapper = JS_NULL;
  GumThreadId thread_id;
  JSValue proto;

  if (!_gum_quick_args_parse (args, "Z", &thread_id))
    return JS_EXCEPTION;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto,
      gumjs_get_parent_module (core)->thread_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    return JS_EXCEPTION;

  JS_SetOpaque (wrapper, GSIZE_TO_POINTER (thread_id));

  return wrapper;
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_set_hardware_breakpoint)
{
  GumThreadId thread_id;
  guint breakpoint_id;
  gpointer address;
  GError * error;

  if (!gum_thread_get (ctx, this_val, core, &thread_id))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "up", &breakpoint_id, &address))
    return JS_EXCEPTION;

  error = NULL;
  gum_thread_set_hardware_breakpoint (thread_id, breakpoint_id,
      GUM_ADDRESS (address), &error);
  if (error != NULL)
    return _gum_quick_throw_error (ctx, &error);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_unset_hardware_breakpoint)
{
  GumThreadId thread_id;
  guint breakpoint_id;
  GError * error;

  if (!gum_thread_get (ctx, this_val, core, &thread_id))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "u", &breakpoint_id))
    return JS_EXCEPTION;

  error = NULL;
  gum_thread_unset_hardware_breakpoint (thread_id, breakpoint_id, &error);
  if (error != NULL)
    return _gum_quick_throw_error (ctx, &error);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_set_hardware_watchpoint)
{
  GumThreadId thread_id;
  guint watchpoint_id;
  gpointer address;
  gsize size;
  const gchar * conditions_str;
  GumWatchConditions conditions;
  const gchar * ch;
  GError * error;

  if (!gum_thread_get (ctx, this_val, core, &thread_id))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "upZs", &watchpoint_id, &address, &size,
        &conditions_str))
    return JS_EXCEPTION;

  conditions = 0;
  for (ch = conditions_str; *ch != '\0'; ch++)
  {
    switch (*ch)
    {
      case 'r':
        conditions |= GUM_WATCH_READ;
        break;
      case 'w':
        conditions |= GUM_WATCH_WRITE;
        break;
      default:
        goto invalid_conditions;
    }
  }
  if (conditions == 0)
    goto invalid_conditions;

  error = NULL;
  gum_thread_set_hardware_watchpoint (thread_id, watchpoint_id,
      GUM_ADDRESS (address), size, conditions, &error);
  if (error != NULL)
    return _gum_quick_throw_error (ctx, &error);

  return JS_UNDEFINED;

invalid_conditions:
  {
    _gum_quick_throw_literal (ctx,
        "expected a string specifying watch conditions, e.g. 'rw'");
    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_thread_unset_hardware_watchpoint)
{
  GumThreadId thread_id;
  guint watchpoint_id;
  GError * error;

  if (!gum_thread_get (ctx, this_val, core, &thread_id))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "u", &watchpoint_id))
    return JS_EXCEPTION;

  error = NULL;
  gum_thread_unset_hardware_watchpoint (thread_id, watchpoint_id, &error);
  if (error != NULL)
    return _gum_quick_throw_error (ctx, &error);

  return JS_UNDEFINED;
}

"""

```