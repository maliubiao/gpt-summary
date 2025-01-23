Response:
The user wants a summary of the functionality of the C++ source code file `gumv8core.cpp`. The summary should include connections to reverse engineering, low-level binary/OS/kernel concepts, logical reasoning, common user errors, and how a user's actions might lead to this code being executed.

Here's a plan to generate the summary:

1. **Identify Core Functionality:** Analyze the included headers, defined structs, enums, and function declarations to understand the file's primary purpose.
2. **Relate to Reverse Engineering:** Look for functions and data structures that facilitate interaction with a running process, like memory manipulation, function hooking, and accessing CPU state.
3. **Identify Low-Level Interactions:** Find elements that deal with system calls (via `ffi`), memory management, and platform-specific details (like architecture-specific register access).
4. **Infer Logical Reasoning:**  Analyze functions that take inputs and produce outputs, especially those involving data conversion or conditional logic. Create hypothetical input/output examples.
5. **Consider User Errors:** Think about how a user might misuse the provided API, leading to errors in this code.
6. **Trace User Actions:**  Imagine the sequence of steps a user would take when using Frida that would eventually involve this `gumv8core.cpp` file.
7. **Summarize Overall Functionality:** Concisely describe the main role of `gumv8core.cpp`.
这是 `frida/subprojects/frida-gum/bindings/gumjs/gumv8core.cpp` 文件的第一部分源代码，它主要负责 **Frida Gum 引擎与 V8 JavaScript 引擎的桥接和核心功能实现**。  简单来说，它将 Gum 提供的底层能力暴露给 JavaScript 环境，使得开发者可以使用 JavaScript 来进行动态 instrumentation。

**具体功能归纳：**

1. **V8 引擎集成:**  初始化和管理 V8 JavaScript 引擎实例，这是 Frida 使用 JavaScript 进行交互的基础。
2. **模块和全局对象注册:**  创建并注册名为 `Core`, `Frida`, 和 `Script` 的 JavaScript 模块，并将各种 Gum 提供的功能（例如定时器、消息传递、脚本加载等）以及 Frida 特有的功能（如 Objective-C, Swift, Java 的桥接）添加到这些模块中。
3. **数据类型映射:**  定义了 C++ 的数据结构（如 `GumV8WeakRef`, `GumV8ScheduledCallback`, `GumV8NativeFunction` 等）来表示 JavaScript 中使用的对象，并在 C++ 和 JavaScript 之间进行数据转换和同步。
4. **定时器管理:**  实现了 `setTimeout` 和 `setInterval` 等 JavaScript 定时器功能，并在 Gum 的事件循环中进行调度。
5. **消息传递:**  实现了 JavaScript 到 Frida Agent 的消息发送 (`send`) 以及 Frida Agent 到 JavaScript 的消息接收机制。
6. **异常和消息处理:**  允许用户设置 JavaScript 异常和消息的回调函数，以便在发生错误或有消息时进行处理。
7. **脚本操作:**  提供了加载、评估、绑定/解绑弱引用、管理 Source Map 等脚本相关的功能。
8. **扩展数据类型支持:**  实现了对 64 位整数 (`Int64`, `UInt64`) 和本地指针 (`NativePointer`) 等特殊数据类型的支持，使得 JavaScript 可以操作这些底层数据。
9. **本地函数调用:**  实现了 `NativeFunction` 的概念，允许 JavaScript 调用 C/C++ 函数，这是 Frida 核心 Hook 功能的基础。
10. **本地回调:** 实现了 `NativeCallback` 的概念，允许 C/C++ 代码回调到 JavaScript 函数。
11. **上下文访问:**  提供了 `CallbackContext` 和 `CpuContext` 对象，允许 JavaScript 代码访问和修改程序运行时的 CPU 寄存器状态。
12. **匹配模式:**  支持 `MatchPattern` 对象，用于在内存中查找特定的字节序列。
13. **Source Map 支持:**  实现了 Source Map 的注册和查找功能，方便调试和错误定位。

**与逆向方法的关联及举例：**

* **动态代码注入和执行:**  `gumjs_script_evaluate` 和 `gumjs_script_load` 函数允许用户加载和执行 JavaScript 代码到目标进程中，这是 Frida 最核心的逆向能力。
    * **举例:** 逆向工程师可以使用 `Script.evaluate('console.log("Hello from Frida!");')` 将打印语句注入到目标进程并执行，从而观察程序的行为。
* **函数 Hooking (通过 `NativeFunction`):** `gumjs_native_function_construct` 和 `gumjs_native_function_invoke` 等函数为创建和调用本地函数提供了支持，这是实现函数 Hook 的关键。
    * **举例:** 逆向工程师可以使用 `new NativeFunction(Address('0x12345678'), 'void', [])` 创建一个指向目标进程地址 `0x12345678` 的本地函数，并使用 `Interceptor.attach` 拦截对该函数的调用。
* **内存读取和修改 (通过 `NativePointer`):**  `gumjs_native_pointer_construct` 以及 `NativePointer` 对象上的各种方法（如 `add`, `read*`, `write*` 等，虽然这部分代码中没有直接体现读写，但这是 `NativePointer` 的典型用法）允许用户直接操作目标进程的内存。
    * **举例:** 逆向工程师可以使用 `Memory.readUtf8String(ptr('0x87654321'))` 读取目标进程地址 `0x87654321` 处的字符串。
* **访问和修改 CPU 寄存器状态 (通过 `CpuContext`):** `gumjs_cpu_context_construct` 以及 `CpuContext` 对象的 getter 和 setter 方法允许在函数执行的关键点检查或修改 CPU 寄存器的值，从而影响程序的执行流程。
    * **举例:** 在 Hook 一个函数时，逆向工程师可以使用 `context.r0 = 0` (假设是 ARM 架构) 将函数的第一个参数修改为 0。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例：**

* **Foreign Function Interface (FFI):** 代码中使用了 `<ffi.h>` 头文件，这是用于调用外部函数（例如 C 函数）的标准库。Frida 使用 FFI 来桥接 JavaScript 和本地代码。
    * **举例:** `ffi_cif` 和 `ffi_type` 等结构体用于描述本地函数的调用约定和参数类型，这直接关系到二进制层面上函数的调用方式（例如参数如何传递、返回值如何处理）。
* **ABI (Application Binary Interface):**  `gum_v8_ffi_abi_get` 函数用于获取和处理不同的 ABI，这在跨平台或不同架构的逆向中非常重要，因为它决定了函数调用的细节。
    * **举例:** 在 Android 上，可能需要处理 ARM 或 ARM64 的不同 ABI。
* **内存地址 (`GumAddress`):** 代码中大量使用了 `GumAddress` 类型，它代表了目标进程中的内存地址，这是进行内存操作和 Hooking 的基础概念。
* **CPU 寄存器访问:**  `gumjs_cpu_context_construct` 以及后续大量的 `GUM_DEFINE_CPU_CONTEXT_ACCESSOR_*` 宏定义了如何访问和修改不同架构（如 x86, ARM, ARM64）的 CPU 寄存器。这需要对目标平台的处理器架构有深入的了解。
    * **举例:** 宏定义中使用了 `G_STRUCT_OFFSET` 来获取 `GumCpuContext` 结构体中不同寄存器成员的偏移量，这与底层内存布局直接相关。
* **系统调用:** 虽然这段代码本身没有直接体现系统调用，但通过 `NativeFunction` 调用本地代码时，最终可能会执行系统调用。
* **Linux 和 Android 框架:**  `gumjs_frida_objc_load`, `gumjs_frida_swift_load`, `gumjs_frida_java_load` 等函数涉及到与 Objective-C runtime, Swift runtime, 和 Android 的 Dalvik/ART 虚拟机进行交互，这需要对这些平台的框架有了解。

**逻辑推理的假设输入与输出：**

* **假设输入:** 用户在 JavaScript 中调用 `setTimeout(function() { console.log("Hello"); }, 1000);`
* **输出:** `gumjs_set_timeout` 函数会被调用，创建一个 `GumV8ScheduledCallback` 结构体，并将其添加到 `self->scheduled_callbacks` 哈希表中。在 1000 毫秒后，`gum_v8_scheduled_callback_invoke` 函数会被调用，执行用户提供的 JavaScript 函数，最终在控制台打印 "Hello"。

* **假设输入:** 用户在 JavaScript 中使用 `new NativePointer("0x1000")` 创建一个 `NativePointer` 对象。
* **输出:** `gumjs_native_pointer_construct` 函数会被调用，创建一个表示内存地址 `0x1000` 的 V8 对象，该对象可以用于后续的内存操作。

**涉及用户或编程常见的使用错误及举例：**

* **错误的类型转换:**  在定义 `NativeFunction` 时，如果用户提供的参数类型或返回值类型与实际的 C 函数不符，会导致调用失败或程序崩溃。
    * **举例:** C 函数需要一个 `int` 参数，但用户在 JavaScript 中定义 `NativeFunction` 时指定了 `string` 类型。
* **内存地址错误:**  在使用 `NativePointer` 时，如果用户提供了无效的内存地址，会导致访问错误。
    * **举例:** 用户尝试读取一个未映射的内存地址。
* **竞态条件:**  在多线程环境下，如果没有正确地同步对共享数据的访问（例如在回调函数中操作全局变量），可能导致不可预测的结果。
    * **举例:** 多个 `setTimeout` 回调同时修改同一个 JavaScript 对象。
* **忘记解绑弱引用:** 如果使用 `Script.bindWeak` 绑定了弱引用，但在对象不再需要时忘记使用 `Script.unbindWeak` 解绑，可能导致内存泄漏。

**用户操作如何一步步的到达这里，作为调试线索：**

1. **启动 Frida:** 用户启动 Frida 工具，连接到目标进程。
2. **加载 JavaScript 代码:** 用户编写 Frida 脚本，并使用 `frida -p <pid> -l script.js` 或类似命令加载到目标进程中。
3. **脚本执行:** Frida 将用户的 JavaScript 代码发送到目标进程并执行。
4. **调用 Frida API:**  用户的 JavaScript 代码中可能调用了 Frida 提供的 API，例如 `Interceptor.attach`, `Memory.read*`, `NativeFunction`, `setTimeout` 等。
5. **进入 `gumv8core.cpp`:** 当 JavaScript 代码调用这些 API 时，会通过 V8 引擎的桥接机制，最终调用到 `gumv8core.cpp` 中相应的 C++ 函数。
    * 例如，调用 `setTimeout` 会触发 `gumjs_set_timeout` 函数。
    * 例如，使用 `new NativeFunction(...)` 会触发 `gumjs_native_function_construct` 函数。
    * 例如，使用 `Memory.read*` (虽然这里没有直接展示 Memory 的实现，但其底层会用到 `NativePointer` 的操作)。
6. **执行具体功能:** `gumv8core.cpp` 中的函数会根据用户调用的 API 执行相应的操作，例如设置定时器、创建本地函数对象、读取内存等。

作为调试线索，如果用户在使用 Frida 脚本时遇到问题，可以通过查看 Frida 的源代码（如 `gumv8core.cpp`）来理解 API 的底层实现，从而更好地定位问题。例如，如果 `NativeFunction` 调用失败，可以查看 `gumjs_native_function_invoke` 的实现来分析可能的错误原因，如参数类型不匹配、内存访问错误等。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8core.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2015 Asger Hautop Drewsen <asgerdrewsen@gmail.com>
 * Copyright (C) 2015 Marc Hartmayer <hello@hartmayer.com>
 * Copyright (C) 2020-2022 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2020 Marcus Mengs <mame8282@googlemail.com>
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 * Copyright (C) 2024 Simon Zuckerbraun <Simon_Zuckerbraun@trendmicro.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8core.h"

#include "gumffi.h"
#include "gumsourcemap.h"
#include "gumv8macros.h"
#include "gumv8scope.h"
#include "gumv8script-priv.h"
#ifdef HAVE_OBJC_BRIDGE
# include "gumv8script-objc.h"
#endif
#ifdef HAVE_SWIFT_BRIDGE
# include "gumv8script-swift.h"
#endif
#ifdef HAVE_JAVA_BRIDGE
# include "gumv8script-java.h"
#endif

#include <ffi.h>
#include <glib/gprintf.h>
#ifdef _MSC_VER
# include <intrin.h>
#endif
#ifdef HAVE_PTRAUTH
# include <ptrauth.h>
#endif
#include <string.h>
#include <gum/gum-init.h>

#define GUMJS_MODULE_NAME Core

using namespace v8;

typedef guint8 GumV8SchedulingBehavior;
typedef guint8 GumV8ExceptionsBehavior;
typedef guint8 GumV8CodeTraps;
typedef guint8 GumV8ReturnValueShape;

struct GumV8FlushCallback
{
  GumV8FlushNotify func;
  GumV8Script * script;
};

struct GumV8WeakRef
{
  guint id;
  Global<Value> * target;
  Global<Function> * callback;

  GumV8Core * core;
};

struct GumV8ScheduledCallback
{
  gint id;
  gboolean repeat;
  Global<Function> * func;
  GSource * source;

  GumV8Core * core;
};

struct GumV8ExceptionSink
{
  Global<Function> * callback;
  Isolate * isolate;
};

struct GumV8MessageSink
{
  Global<Function> * callback;
  Isolate * isolate;
};

struct GumV8NativeFunctionParams
{
  GCallback implementation;
  Local<Value> return_type;
  Local<Array> argument_types;
  Local<Value> abi;
  GumV8SchedulingBehavior scheduling;
  GumV8ExceptionsBehavior exceptions;
  GumV8CodeTraps traps;
  GumV8ReturnValueShape return_shape;
};

enum _GumV8SchedulingBehavior
{
  GUM_V8_SCHEDULING_COOPERATIVE,
  GUM_V8_SCHEDULING_EXCLUSIVE
};

enum _GumV8ExceptionsBehavior
{
  GUM_V8_EXCEPTIONS_STEAL,
  GUM_V8_EXCEPTIONS_PROPAGATE
};

enum _GumV8CodeTraps
{
  GUM_V8_CODE_TRAPS_DEFAULT,
  GUM_V8_CODE_TRAPS_NONE,
  GUM_V8_CODE_TRAPS_ALL
};

enum _GumV8ReturnValueShape
{
  GUM_V8_RETURN_PLAIN,
  GUM_V8_RETURN_DETAILED
};

struct GumV8NativeFunction
{
  Global<Object> * wrapper;

  GCallback implementation;
  GumV8SchedulingBehavior scheduling;
  GumV8ExceptionsBehavior exceptions;
  GumV8CodeTraps traps;
  GumV8ReturnValueShape return_shape;
  ffi_cif cif;
  ffi_type ** atypes;
  gsize arglist_size;
  gboolean is_variadic;
  uint32_t nargs_fixed;
  ffi_abi abi;
  GSList * data;

  GumV8Core * core;
};

struct GumV8NativeCallback
{
  gint ref_count;

  v8::Global<v8::Object> * wrapper;
  gpointer ptr_value;

  v8::Global<v8::Function> * func;
  ffi_closure * closure;
  ffi_cif cif;
  ffi_type ** atypes;
  GSList * data;

  GumV8Core * core;
};

struct GumV8CallbackContext
{
  Global<Object> * wrapper;
  Global<Object> * cpu_context;
  gint * system_error;
  GumAddress return_address;
  GumAddress raw_return_address;
};

struct GumV8MatchPattern
{
  Global<Object> * wrapper;
  GumMatchPattern * handle;
};

struct GumV8SourceMap
{
  Global<Object> * wrapper;
  GumSourceMap * handle;

  GumV8Core * core;
};

static gboolean gum_v8_core_handle_crashed_js (GumExceptionDetails * details,
    gpointer user_data);

static void gum_v8_core_clear_weak_refs (GumV8Core * self);
static void gum_v8_flush_callback_free (GumV8FlushCallback * self);
static gboolean gum_v8_flush_callback_notify (GumV8FlushCallback * self);

GUMJS_DECLARE_FUNCTION (gumjs_set_timeout)
GUMJS_DECLARE_FUNCTION (gumjs_set_interval)
static void gum_v8_core_schedule_callback (GumV8Core * self,
    const GumV8Args * args, gboolean repeat);
static GumV8ScheduledCallback * gum_v8_core_try_steal_scheduled_callback (
    GumV8Core * self, gint id);
GUMJS_DECLARE_FUNCTION (gumjs_clear_timer)
static GumV8ScheduledCallback * gum_v8_scheduled_callback_new (guint id,
    gboolean repeat, GSource * source, GumV8Core * core);
static void gum_v8_scheduled_callback_free (GumV8ScheduledCallback * callback);
static gboolean gum_v8_scheduled_callback_invoke (
    GumV8ScheduledCallback * self);
GUMJS_DECLARE_FUNCTION (gumjs_send)
GUMJS_DECLARE_FUNCTION (gumjs_set_unhandled_exception_callback)
GUMJS_DECLARE_FUNCTION (gumjs_set_incoming_message_callback)
GUMJS_DECLARE_FUNCTION (gumjs_wait_for_event)

static void gumjs_global_get (Local<Name> property,
    const PropertyCallbackInfo<Value> & info);

GUMJS_DECLARE_GETTER (gumjs_frida_get_heap_size)
GUMJS_DECLARE_FUNCTION (gumjs_frida_objc_load)
GUMJS_DECLARE_FUNCTION (gumjs_frida_swift_load)
GUMJS_DECLARE_FUNCTION (gumjs_frida_java_load)

GUMJS_DECLARE_FUNCTION (gumjs_script_evaluate)
GUMJS_DECLARE_FUNCTION (gumjs_script_load)
GUMJS_DECLARE_FUNCTION (gumjs_script_register_source_map)
GUMJS_DECLARE_FUNCTION (gumjs_script_find_source_map)
static gchar * gum_query_script_for_inline_source_map (Isolate * isolate,
    Local<Script> script);
GUMJS_DECLARE_FUNCTION (gumjs_script_next_tick)
GUMJS_DECLARE_FUNCTION (gumjs_script_pin)
GUMJS_DECLARE_FUNCTION (gumjs_script_unpin)
GUMJS_DECLARE_FUNCTION (gumjs_script_bind_weak)
GUMJS_DECLARE_FUNCTION (gumjs_script_unbind_weak)
static GumV8WeakRef * gum_v8_weak_ref_new (guint id, Local<Value> target,
    Local<Function> callback, GumV8Core * core);
static void gum_v8_weak_ref_clear (GumV8WeakRef * ref);
static void gum_v8_weak_ref_free (GumV8WeakRef * ref);
static void gum_v8_weak_ref_on_weak_notify (
    const WeakCallbackInfo<GumV8WeakRef> & info);
static gboolean gum_v8_core_invoke_pending_weak_callbacks_in_idle (
    GumV8Core * self);
static void gum_v8_core_invoke_pending_weak_callbacks (GumV8Core * self,
    ScriptScope * scope);
GUMJS_DECLARE_FUNCTION (gumjs_script_set_global_access_handler)

GUMJS_DECLARE_FUNCTION (gumjs_int64_construct)
GUMJS_DECLARE_FUNCTION (gumjs_int64_add)
GUMJS_DECLARE_FUNCTION (gumjs_int64_sub)
GUMJS_DECLARE_FUNCTION (gumjs_int64_and)
GUMJS_DECLARE_FUNCTION (gumjs_int64_or)
GUMJS_DECLARE_FUNCTION (gumjs_int64_xor)
GUMJS_DECLARE_FUNCTION (gumjs_int64_shr)
GUMJS_DECLARE_FUNCTION (gumjs_int64_shl)
GUMJS_DECLARE_FUNCTION (gumjs_int64_not)
GUMJS_DECLARE_FUNCTION (gumjs_int64_compare)
GUMJS_DECLARE_FUNCTION (gumjs_int64_to_number)
GUMJS_DECLARE_FUNCTION (gumjs_int64_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_int64_to_json)
GUMJS_DECLARE_FUNCTION (gumjs_int64_value_of)

GUMJS_DECLARE_FUNCTION (gumjs_uint64_construct)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_add)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_sub)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_and)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_or)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_xor)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_shr)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_shl)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_not)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_compare)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_to_number)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_to_json)
GUMJS_DECLARE_FUNCTION (gumjs_uint64_value_of)

GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_construct)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_is_null)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_add)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_sub)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_and)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_or)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_xor)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_shr)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_shl)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_not)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_sign)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_strip)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_blend)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_compare)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_int32)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_uint32)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_string)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_json)
GUMJS_DECLARE_FUNCTION (gumjs_native_pointer_to_match_pattern)

GUMJS_DECLARE_FUNCTION (gumjs_array_buffer_wrap)
GUMJS_DECLARE_FUNCTION (gumjs_array_buffer_unwrap)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_function_construct)
GUMJS_DECLARE_FUNCTION (gumjs_native_function_invoke)
GUMJS_DECLARE_FUNCTION (gumjs_native_function_call)
GUMJS_DECLARE_FUNCTION (gumjs_native_function_apply)
static gboolean gumjs_native_function_get (
    const FunctionCallbackInfo<Value> & info, Local<Object> receiver,
    GumV8Core * core, GumV8NativeFunction ** func, GCallback * implementation);
static GumV8NativeFunction * gumjs_native_function_init (Local<Object> wrapper,
    const GumV8NativeFunctionParams * params, GumV8Core * core);
static void gum_v8_native_function_free (GumV8NativeFunction * self);
static void gum_v8_native_function_invoke (GumV8NativeFunction * self,
    GCallback implementation, const FunctionCallbackInfo<Value> & info,
    uint32_t argc, Local<Value> * argv);
static void gum_v8_native_function_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeFunction> & info);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_system_function_construct)

static gboolean gum_v8_native_function_params_init (
    GumV8NativeFunctionParams * params, GumV8ReturnValueShape return_shape,
    const GumV8Args * args);
static gboolean gum_v8_scheduling_behavior_parse (Local<Value> value,
    GumV8SchedulingBehavior * behavior, Isolate * isolate);
static gboolean gum_v8_exceptions_behavior_parse (Local<Value> value,
    GumV8ExceptionsBehavior * behavior, Isolate * isolate);
static gboolean gum_v8_code_traps_parse (Local<Value> value,
    GumV8CodeTraps * traps, Isolate * isolate);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_callback_construct)
static void gum_v8_native_callback_on_weak_notify (
    const WeakCallbackInfo<GumV8NativeCallback> & info);
static GumV8NativeCallback * gum_v8_native_callback_ref (
    GumV8NativeCallback * callback);
static void gum_v8_native_callback_unref (GumV8NativeCallback * callback);
static void gum_v8_native_callback_clear (GumV8NativeCallback * self);
static void gum_v8_native_callback_invoke (ffi_cif * cif,
    void * return_value, void ** args, void * user_data);

static GumV8CallbackContext * gum_v8_callback_context_new_persistent (
    GumV8Core * core, GumCpuContext * cpu_context, gint * system_error,
    GumAddress raw_return_address);
static void gum_v8_callback_context_free (GumV8CallbackContext * self);
GUMJS_DECLARE_GETTER (gumjs_callback_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_callback_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_callback_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_callback_context_set_system_error)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_cpu_context_construct)
GUMJS_DECLARE_GETTER (gumjs_cpu_context_get_gpr)
GUMJS_DECLARE_SETTER (gumjs_cpu_context_set_gpr)
G_GNUC_UNUSED GUMJS_DECLARE_GETTER (gumjs_cpu_context_get_vector)
G_GNUC_UNUSED GUMJS_DECLARE_SETTER (gumjs_cpu_context_set_vector)
G_GNUC_UNUSED GUMJS_DECLARE_GETTER (gumjs_cpu_context_get_double)
G_GNUC_UNUSED GUMJS_DECLARE_SETTER (gumjs_cpu_context_set_double)
G_GNUC_UNUSED GUMJS_DECLARE_GETTER (gumjs_cpu_context_get_float)
G_GNUC_UNUSED GUMJS_DECLARE_SETTER (gumjs_cpu_context_set_float)
G_GNUC_UNUSED GUMJS_DECLARE_GETTER (gumjs_cpu_context_get_flags)
G_GNUC_UNUSED GUMJS_DECLARE_SETTER (gumjs_cpu_context_set_flags)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_match_pattern_construct)
static GumV8MatchPattern * gum_v8_match_pattern_new (Local<Object> wrapper,
    GumMatchPattern * pattern, GumV8Core * core);
static void gum_v8_match_pattern_free (GumV8MatchPattern * self);

static MaybeLocal<Object> gumjs_source_map_new (const gchar * json,
    GumV8Core * core);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_source_map_construct)
GUMJS_DECLARE_FUNCTION (gumjs_source_map_resolve)
static GumV8SourceMap * gum_v8_source_map_new (Local<Object> wrapper,
    GumSourceMap * handle, GumV8Core * core);
static void gum_v8_source_map_free (GumV8SourceMap * self);
static void gum_v8_source_map_on_weak_notify (
    const WeakCallbackInfo<GumV8SourceMap> & info);

static GumV8ExceptionSink * gum_v8_exception_sink_new (
    Local<Function> callback, Isolate * isolate);
static void gum_v8_exception_sink_free (GumV8ExceptionSink * sink);
static void gum_v8_exception_sink_handle_exception (GumV8ExceptionSink * self,
    Local<Value> exception);

static GumV8MessageSink * gum_v8_message_sink_new (Local<Function> callback,
    Isolate * isolate);
static void gum_v8_message_sink_free (GumV8MessageSink * sink);
static void gum_v8_message_sink_post (GumV8MessageSink * self,
    const gchar * message, GBytes * data);
static void gum_delete_bytes_reference (void * data, size_t length,
    void * deleter_data);

static gboolean gum_v8_ffi_type_get (GumV8Core * core, Local<Value> name,
    ffi_type ** type, GSList ** data);
static gboolean gum_v8_ffi_abi_get (GumV8Core * core, Local<Value> name,
    ffi_abi * abi);
static gboolean gum_v8_value_to_ffi_type (GumV8Core * core,
    const Local<Value> svalue, GumFFIValue * value, const ffi_type * type);
static gboolean gum_v8_value_from_ffi_type (GumV8Core * core,
    Local<Value> * svalue, const GumFFIValue * value, const ffi_type * type);

static const GumV8Function gumjs_global_functions[] =
{
  { "_setTimeout", gumjs_set_timeout, },
  { "_setInterval", gumjs_set_interval },
  { "clearTimeout", gumjs_clear_timer },
  { "clearInterval", gumjs_clear_timer },
  { "_send", gumjs_send },
  { "_setUnhandledExceptionCallback", gumjs_set_unhandled_exception_callback },
  { "_setIncomingMessageCallback", gumjs_set_incoming_message_callback },
  { "_waitForEvent", gumjs_wait_for_event },

  { NULL, NULL }
};

static const GumV8Property gumjs_frida_values[] =
{
  { "heapSize", gumjs_frida_get_heap_size, NULL },

  { NULL, NULL }
};

static const GumV8Function gumjs_frida_functions[] =
{
  { "_loadObjC", gumjs_frida_objc_load },
  { "_loadSwift", gumjs_frida_swift_load },
  { "_loadJava", gumjs_frida_java_load },

  { NULL, NULL }
};

static const GumV8Function gumjs_script_functions[] =
{
  { "evaluate", gumjs_script_evaluate },
  { "_load", gumjs_script_load },
  { "registerSourceMap", gumjs_script_register_source_map },
  { "_findSourceMap", gumjs_script_find_source_map },
  { "_nextTick", gumjs_script_next_tick },
  { "pin", gumjs_script_pin },
  { "unpin", gumjs_script_unpin },
  { "bindWeak", gumjs_script_bind_weak },
  { "unbindWeak", gumjs_script_unbind_weak },
  { "setGlobalAccessHandler", gumjs_script_set_global_access_handler },

  { NULL, NULL }
};

static const GumV8Function gumjs_int64_functions[] =
{
  { "add", gumjs_int64_add },
  { "sub", gumjs_int64_sub },
  { "and", gumjs_int64_and },
  { "or", gumjs_int64_or },
  { "xor", gumjs_int64_xor },
  { "shr", gumjs_int64_shr },
  { "shl", gumjs_int64_shl },
  { "not", gumjs_int64_not },
  { "compare", gumjs_int64_compare },
  { "toNumber", gumjs_int64_to_number },
  { "toString", gumjs_int64_to_string },
  { "toJSON", gumjs_int64_to_json },
  { "valueOf", gumjs_int64_value_of },

  { NULL, NULL }
};

static const GumV8Function gumjs_uint64_functions[] =
{
  { "add", gumjs_uint64_add },
  { "sub", gumjs_uint64_sub },
  { "and", gumjs_uint64_and },
  { "or", gumjs_uint64_or },
  { "xor", gumjs_uint64_xor },
  { "shr", gumjs_uint64_shr },
  { "shl", gumjs_uint64_shl },
  { "not", gumjs_uint64_not },
  { "compare", gumjs_uint64_compare },
  { "toNumber", gumjs_uint64_to_number },
  { "toString", gumjs_uint64_to_string },
  { "toJSON", gumjs_uint64_to_json },
  { "valueOf", gumjs_uint64_value_of },

  { NULL, NULL }
};

static const GumV8Function gumjs_native_pointer_functions[] =
{
  { "isNull", gumjs_native_pointer_is_null },
  { "add", gumjs_native_pointer_add },
  { "sub", gumjs_native_pointer_sub },
  { "and", gumjs_native_pointer_and },
  { "or", gumjs_native_pointer_or },
  { "xor", gumjs_native_pointer_xor },
  { "shr", gumjs_native_pointer_shr },
  { "shl", gumjs_native_pointer_shl },
  { "not", gumjs_native_pointer_not },
  { "sign", gumjs_native_pointer_sign },
  { "strip", gumjs_native_pointer_strip },
  { "blend", gumjs_native_pointer_blend },
  { "compare", gumjs_native_pointer_compare },
  { "toInt32", gumjs_native_pointer_to_int32 },
  { "toUInt32", gumjs_native_pointer_to_uint32 },
  { "toString", gumjs_native_pointer_to_string },
  { "toJSON", gumjs_native_pointer_to_json },
  { "toMatchPattern", gumjs_native_pointer_to_match_pattern },

  { NULL, NULL }
};

static const GumV8Function gumjs_native_function_functions[] =
{
  { "call", gumjs_native_function_call },
  { "apply", gumjs_native_function_apply },

  { NULL, NULL }
};

static const GumV8Property gumjs_callback_context_values[] =
{
  {
    "returnAddress",
    gumjs_callback_context_get_return_address,
    NULL
  },
  {
    "context",
    gumjs_callback_context_get_cpu_context,
    NULL
  },
  {
    GUMJS_SYSTEM_ERROR_FIELD,
    gumjs_callback_context_get_system_error,
    gumjs_callback_context_set_system_error
  },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_source_map_functions[] =
{
  { "_resolve", gumjs_source_map_resolve },

  { NULL, NULL }
};

void
_gum_v8_core_init (GumV8Core * self,
                   GumV8Script * script,
                   const gchar * runtime_source_map,
                   GumV8MessageEmitter message_emitter,
                   GumScriptScheduler * scheduler,
                   Isolate * isolate,
                   Local<ObjectTemplate> scope)
{
  self->script = script;
  self->backend = script->backend;
  self->runtime_source_map = runtime_source_map;
  self->core = self;
  self->message_emitter = message_emitter;
  self->scheduler = scheduler;
  self->exceptor = gum_exceptor_obtain ();
  self->isolate = isolate;

  self->current_scope = nullptr;
  self->current_owner = GUM_THREAD_ID_INVALID;
  self->usage_count = 0;
  self->flush_notify = NULL;

  self->event_loop = g_main_loop_new (
      gum_script_scheduler_get_js_context (scheduler), FALSE);
  g_mutex_init (&self->event_mutex);
  g_cond_init (&self->event_cond);
  self->event_count = 0;
  self->event_source_available = TRUE;

  self->weak_refs = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_weak_ref_free);

  self->scheduled_callbacks = g_hash_table_new (NULL, NULL);
  self->next_callback_id = 1;

  auto module = External::New (isolate, self);

  _gum_v8_module_add (module, scope, gumjs_global_functions, isolate);

  NamedPropertyHandlerConfiguration global_access;
  global_access.getter = gumjs_global_get;
  global_access.data = module;
  global_access.flags = (PropertyHandlerFlags) (
        (int) PropertyHandlerFlags::kNonMasking |
        (int) PropertyHandlerFlags::kOnlyInterceptStrings
      );
  scope->SetHandler (global_access);

  auto frida = _gum_v8_create_module ("Frida", scope, isolate);
  _gum_v8_module_add (module, frida, gumjs_frida_values, isolate);
  _gum_v8_module_add (module, frida, gumjs_frida_functions, isolate);
  frida->Set (_gum_v8_string_new_ascii (isolate, "version"),
      _gum_v8_string_new_ascii (isolate, FRIDA_VERSION), ReadOnly);

  auto script_module = _gum_v8_create_module ("Script", scope, isolate);
  _gum_v8_module_add (module, script_module, gumjs_script_functions, isolate);
  script_module->Set (_gum_v8_string_new_ascii (isolate, "runtime"),
      _gum_v8_string_new_ascii (isolate, "V8"), ReadOnly);

  auto int64 = _gum_v8_create_class ("Int64", gumjs_int64_construct, scope,
      module, isolate);
  _gum_v8_class_add (int64, gumjs_int64_functions, module, isolate);
  int64->InstanceTemplate ()->SetInternalFieldCount (1);
  self->int64 = new Global<FunctionTemplate> (isolate, int64);

  auto uint64 = _gum_v8_create_class ("UInt64", gumjs_uint64_construct, scope,
      module, isolate);
  _gum_v8_class_add (uint64, gumjs_uint64_functions, module, isolate);
  uint64->InstanceTemplate ()->SetInternalFieldCount (1);
  self->uint64 = new Global<FunctionTemplate> (isolate, uint64);

  auto native_pointer = _gum_v8_create_class ("NativePointer",
      gumjs_native_pointer_construct, scope, module, isolate);
  _gum_v8_class_add (native_pointer, gumjs_native_pointer_functions, module,
      isolate);
  self->native_pointer = new Global<FunctionTemplate> (isolate, native_pointer);

  auto native_function = _gum_v8_create_class ("NativeFunction",
      gumjs_native_function_construct, scope, module, isolate);
  native_function->Inherit (native_pointer);
  _gum_v8_class_add (native_function, gumjs_native_function_functions, module,
      isolate);
  auto native_function_object = native_function->InstanceTemplate ();
  native_function_object->SetCallAsFunctionHandler (
      gumjs_native_function_invoke, module);
  native_function_object->SetInternalFieldCount (2);
  self->native_function =
      new Global<FunctionTemplate> (isolate, native_function);

  auto system_function = _gum_v8_create_class ("SystemFunction",
      gumjs_system_function_construct, scope, module, isolate);
  system_function->Inherit (native_function);
  auto system_function_object = system_function->InstanceTemplate ();
  system_function_object->SetCallAsFunctionHandler (
      gumjs_native_function_invoke, module);
  system_function_object->SetInternalFieldCount (2);

  auto native_callback = _gum_v8_create_class ("NativeCallback",
      gumjs_native_callback_construct, scope, module, isolate);
  native_callback->Inherit (native_pointer);
  native_callback->InstanceTemplate ()->SetInternalFieldCount (2);

  auto cc = _gum_v8_create_class ("CallbackContext", nullptr, scope,
      module, isolate);
  _gum_v8_class_add (cc, gumjs_callback_context_values, module, isolate);
  self->callback_context = new Global<FunctionTemplate> (isolate, cc);

  auto cpu_context = _gum_v8_create_class ("CpuContext",
      gumjs_cpu_context_construct, scope, module, isolate);
  auto cpu_context_object = cpu_context->InstanceTemplate ();
  cpu_context_object->SetInternalFieldCount (3);
  self->cpu_context = new Global<FunctionTemplate> (isolate, cpu_context);

#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED(A, R) \
    cpu_context_object->SetAccessor ( \
        _gum_v8_string_new_ascii (isolate, G_STRINGIFY (A)), \
        gumjs_cpu_context_get_gpr, \
        gumjs_cpu_context_set_gpr, \
        Integer::NewFromUnsigned (isolate, \
            G_STRUCT_OFFSET (GumCpuContext, R)), \
        DEFAULT, \
        DontDelete)
#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR(R) \
    GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (R, R)

#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR(A, R) \
    cpu_context_object->SetAccessor ( \
        _gum_v8_string_new_ascii (isolate, G_STRINGIFY (A)), \
        gumjs_cpu_context_get_vector, \
        gumjs_cpu_context_set_vector, \
        Integer::NewFromUnsigned (isolate, \
            G_STRUCT_OFFSET (GumCpuContext, R) << 8 | \
              sizeof (((GumCpuContext *) NULL)->R)), \
        DEFAULT, \
        DontDelete)

#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE(A, R) \
    cpu_context_object->SetAccessor ( \
        _gum_v8_string_new_ascii (isolate, G_STRINGIFY (A)), \
        gumjs_cpu_context_get_double, \
        gumjs_cpu_context_set_double, \
        Integer::NewFromUnsigned (isolate, \
            G_STRUCT_OFFSET (GumCpuContext, R)), \
        DEFAULT, \
        DontDelete)

#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT(A, R) \
    cpu_context_object->SetAccessor ( \
        _gum_v8_string_new_ascii (isolate, G_STRINGIFY (A)), \
        gumjs_cpu_context_get_float, \
        gumjs_cpu_context_set_float, \
        Integer::NewFromUnsigned (isolate, \
            G_STRUCT_OFFSET (GumCpuContext, R)), \
        DEFAULT, \
        DontDelete)

#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLAGS(A, R) \
    cpu_context_object->SetAccessor ( \
        _gum_v8_string_new_ascii (isolate, G_STRINGIFY (A)), \
        gumjs_cpu_context_get_flags, \
        gumjs_cpu_context_set_flags, \
        Integer::NewFromUnsigned (isolate, \
            G_STRUCT_OFFSET (GumCpuContext, R)), \
        DEFAULT, \
        DontDelete)

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (pc, eip);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (sp, esp);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (eax);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (ecx);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (edx);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (ebx);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (esp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (ebp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (esi);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (edi);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (eip);
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (pc, rip);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (sp, rsp);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rax);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rcx);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rdx);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rbx);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rsp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rbp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rsi);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rdi);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r8);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r9);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r10);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r11);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r12);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r13);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r14);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r15);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rip);
#elif defined (HAVE_ARM)
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (pc);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (sp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLAGS (cpsr, cpsr);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r0, r[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r1, r[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r2, r[2]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r3, r[3]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r4, r[4]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r5, r[5]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r6, r[6]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r7, r[7]);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r8);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r9);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r10);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r11);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r12);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (lr);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q0, v[0].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q1, v[1].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q2, v[2].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q3, v[3].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q4, v[4].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q5, v[5].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q6, v[6].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q7, v[7].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q8, v[8].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q9, v[9].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q10, v[10].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q11, v[11].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q12, v[12].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q13, v[13].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q14, v[14].q);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q15, v[15].q);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d0, v[0].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d1, v[0].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d2, v[1].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d3, v[1].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d4, v[2].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d5, v[2].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d6, v[3].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d7, v[3].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d8, v[4].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d9, v[4].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d10, v[5].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d11, v[5].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d12, v[6].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d13, v[6].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d14, v[7].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d15, v[7].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d16, v[8].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d17, v[8].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d18, v[9].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d19, v[9].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d20, v[10].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d21, v[10].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d22, v[11].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d23, v[11].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d24, v[12].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d25, v[12].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d26, v[13].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d27, v[13].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d28, v[14].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d29, v[14].d[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d30, v[15].d[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d31, v[15].d[1]);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s0, v[0].s[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s1, v[0].s[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s2, v[0].s[2]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s3, v[0].s[3]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s4, v[1].s[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s5, v[1].s[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s6, v[1].s[2]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s7, v[1].s[3]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s8, v[2].s[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s9, v[2].s[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s10, v[2].s[2]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s11, v[2].s[3]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s12, v[3].s[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s13, v[3].s[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s14, v[3].s[2]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s15, v[3].s[3]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s16, v[4].s[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s17, v[4].s[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s18, v[4].s[2]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s19, v[4].s[3]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s20, v[5].s[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s21, v[5].s[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s22, v[5].s[2]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s23, v[5].s[3]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s24, v[6].s[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s25, v[6].s[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s26, v[6].s[2]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s27, v[6].s[3]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s28, v[7].s[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s29, v[7].s[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s30, v[7].s[2]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s31, v[7].s[3]);
#elif defined (HAVE_ARM64)
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (pc);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (sp);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLAGS (nzcv, nzcv);

  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x0, x[0]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x1, x[1]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x2, x[2]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x3, x[3]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x4, x[4]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x5, x[5]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x6, x[6]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x7, x[7]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x8, x[8]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x9, x[9]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x10, x[10]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x11, x[11]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x12, x[12]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x13, x[13]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x14, x[14]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x15, x[15]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x16, x[16]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x17, x[17]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x18, x[18]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x19, x[19]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x20, x[20]);
  GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x21, x[21]);
  GUM_DEFINE_CPU_CONTEXT_ACCE
```