Response:
Let's break down the thought process for analyzing this C code snippet and answering the prompt.

**1. Initial Scan and Keyword Identification:**

The first step is to quickly scan the code for prominent keywords and patterns. I'm looking for things like:

* **Includes:** `gumquickinterceptor.h`, `gumquickmacros.h`. These hint at the general domain of the code.
* **`#define` Macros:**  These often define constants or type checks. The ones starting with `GUM_QUICK_TYPE_` and `GUM_QUICK_...LISTENER` are important for understanding the structure.
* **`typedef struct`:** These define the core data structures. The `GumQuickInvocationListener`, `GumQuickJSCallListener`, `GumQuickJSProbeListener`, etc., suggest different ways of intercepting function calls.
* **Function Declarations:**  Lots of `GUMJS_DECLARE_FUNCTION` and `static` functions. This tells me about the functionality being implemented. The `gumjs_` prefix suggests JavaScript bindings.
* **`G_DEFINE_TYPE_EXTENDED`:**  This is a GObject macro for defining object types. It confirms this code is part of a GObject-based system.
* **`GumInterceptor` and `GumInvocationContext`:** These strongly suggest the code is related to function interception and managing the context of those interceptions.
* **JavaScript-related terms:** `JSValue`, `JSContext`, `JSAtom`, `JS_NewObject`, `JS_SetPropertyFunctionList`, etc. These clearly indicate integration with a JavaScript engine (likely QuickJS, given the `gumquick` prefix).

**2. Understanding Core Data Structures:**

Next, I focus on the `struct` definitions. These tell me what data the `GumQuickInterceptor` and related components manage:

* **`GumQuickInvocationListener`:**  A base structure, linking a JavaScript wrapper (`JSValue wrapper`) to a parent `GumQuickInterceptor`.
* **`GumQuickJSCallListener`, `GumQuickJSProbeListener`, `GumQuickCCallListener`, `GumQuickCProbeListener`:** These inherit from `GumQuickInvocationListener` and add specific callbacks (`on_enter`, `on_leave`, `on_hit`). The "JS" and "C" prefixes indicate whether the callbacks are JavaScript functions or C function pointers. "Call" suggests intercepting function entry and exit, while "Probe" implies intercepting at a specific point.
* **`GumQuickInvocationState`:** Holds a `GumQuickInvocationContext`, likely used to manage the context of an intercepted function call.
* **`GumQuickInvocationArgs` and `GumQuickInvocationRetval`:** Structures to hold arguments and return values of intercepted functions, with JavaScript wrappers.
* **`GumQuickReplaceEntry`:**  Used when a function is replaced entirely, storing the original target, the replacement function, and related data.

**3. Analyzing Key Functions:**

I then look at the most important functions, particularly those declared with `GUMJS_DECLARE_FUNCTION`, as these are the entry points from the JavaScript side:

* **`gumjs_interceptor_attach`:**  This is the core function for setting up interception. It takes a target address and a callback (either JavaScript or C). It handles different listener types (JS/C, call/probe).
* **`gumjs_interceptor_detach_all` and `gumjs_invocation_listener_detach`:** Functions for removing interceptions.
* **`gumjs_interceptor_replace` and `gumjs_interceptor_replace_fast`:** Functions to replace the implementation of a function.
* **`gumjs_interceptor_revert`:** Undoes a replacement.
* **`gumjs_interceptor_flush`:**  Likely related to synchronizing or applying interception changes.

**4. Connecting to Concepts:**

With an understanding of the data structures and functions, I can start connecting the dots to the concepts mentioned in the prompt:

* **Reverse Engineering:** Interception is a fundamental technique in dynamic analysis and reverse engineering. It allows you to observe and modify the behavior of a running program.
* **Binary/Low-Level:**  The code deals with memory addresses (`gpointer target`), function pointers (`GumQuickCHook`), and interacts with the underlying execution of the program.
* **Linux/Android Kernel & Frameworks:** Frida is commonly used on these platforms. While this specific file might not directly interact with kernel code, the interception mechanism it provides is often used to hook into system libraries and framework components.
* **Logic and Assumptions:**  I can infer the purpose of certain code blocks based on the function names and data structures. For example, the `gum_quick_interceptor_on_flush_timer_tick` function suggests a retry mechanism if `gum_interceptor_flush` fails initially.
* **User Errors:** By looking at the argument parsing (`_gum_quick_args_parse`) and the error handling within functions like `gumjs_interceptor_attach` and `gumjs_interceptor_replace`, I can identify potential user errors (e.g., providing incorrect arguments, trying to attach to the same function multiple times).
* **User Operation Flow:**  I consider how a user would interact with Frida's JavaScript API to trigger the execution of this C code. The `gumjs_interceptor_attach`, `gumjs_interceptor_replace`, etc., functions are the key entry points.

**5. Structuring the Answer:**

Finally, I organize the information into the categories requested by the prompt:

* **Functionality:**  A high-level summary of what the code does.
* **Relationship to Reverse Engineering:**  Explicitly connect the code to interception techniques used in reverse engineering.
* **Binary/Low-Level/Kernel/Framework Knowledge:** Detail the aspects related to memory, function pointers, and the operating system.
* **Logical Inference:** Explain any assumptions or deductions made about the code's behavior.
* **User Errors:** Provide examples of common mistakes.
* **User Operation Flow:** Describe how a user's actions in the Frida JavaScript API lead to this code being executed.
* **Summary of Functionality (Part 1):**  A concise summary of the functionality covered in the provided code snippet.

**Self-Correction/Refinement During the Process:**

* **Initial Misinterpretations:** I might initially focus too much on specific data structures without grasping the overall purpose. I'd then step back and look at the bigger picture by examining the function calls.
* **Jargon:** I need to ensure I explain any technical terms (like "GObject") if they're not common knowledge.
* **Conciseness:** While being thorough, I also aim for clarity and avoid unnecessary jargon or overly detailed explanations where a simpler explanation suffices. For example, I might initially go deep into the GObject type system but realize a simpler explanation of object creation is sufficient for this prompt.

By following these steps, combining code analysis with knowledge of Frida and reverse engineering principles, I can generate a comprehensive and accurate answer to the prompt.好的，让我们来分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumquickinterceptor.c` 文件的源代码，并尝试回答您的问题。

**文件功能归纳 (第 1 部分)**

这个 C 代码文件 `gumquickinterceptor.c` 是 Frida 动态 instrumentation 工具中 `frida-gum` 库的一部分，负责实现快速的函数拦截（interception）功能，并将其暴露给 JavaScript 环境使用。其核心功能可以概括为：

1. **提供 JavaScript 接口用于函数拦截:** 它定义了一系列可以从 JavaScript 代码中调用的函数，例如 `_attach`, `detachAll`, `_replace`, `_replaceFast`, `revert`, `flush`。这些函数允许用户在运行时动态地修改目标进程的行为。
2. **管理不同类型的拦截监听器:** 它定义了多种拦截监听器类型，用于处理不同场景下的拦截需求：
    * `GumQuickJSCallListener`: 用于拦截 JavaScript 函数调用，可以分别设置进入和离开时的回调函数。
    * `GumQuickJSProbeListener`: 用于在 JavaScript 函数的特定位置插入探针（probe），设置命中时的回调函数。
    * `GumQuickCCallListener`: 用于拦截 C 函数调用，可以分别设置进入和离开时的 C 函数指针回调。
    * `GumQuickCProbeListener`: 用于在 C 函数的特定位置插入探针，设置命中时的 C 函数指针回调。
3. **维护拦截状态:**  它使用哈希表 (`invocation_listeners`) 来存储当前已注册的拦截监听器，以便后续可以进行管理和移除。
4. **实现函数替换功能:**  它提供了替换目标函数实现的功能 (`_replace`, `_replaceFast`)，允许用户用自定义的函数替换目标函数的原始实现。
5. **管理函数替换条目:**  它使用哈希表 (`replacement_by_address`) 来存储已替换的函数地址和相应的替换信息，以便后续可以恢复原始实现。
6. **提供拦截上下文信息:** 它定义了 `GumQuickInvocationContext`, `GumQuickInvocationArgs`, `GumQuickInvocationRetval` 等结构体和相关的 JavaScript 类，用于在拦截回调中提供关于函数调用上下文（例如参数、返回值、寄存器状态等）的信息。
7. **处理拦截器的刷新:** 提供了 `flush` 操作，可能用于同步或应用拦截器的修改。
8. **处理 JavaScript 和 C 回调:** 能够处理 JavaScript 函数和 C 函数指针作为拦截回调。
9. **内存管理:** 使用 GObject 的机制进行内存管理，例如使用 `g_object_new`, `g_object_unref`, `g_slice_new`, `g_slice_free` 等。

**与逆向方法的关联及举例说明**

这个文件中的代码是 Frida 这种动态 instrumentation 工具的核心组成部分，而动态 instrumentation 本身就是一种强大的逆向分析方法。

* **动态分析:**  通过拦截和修改函数调用，逆向工程师可以在程序运行时观察其行为，例如查看函数的参数和返回值，监控敏感函数的调用，理解程序的执行流程。
    * **举例:**  逆向工程师可以使用 `Interceptor.attach` 在目标应用的某个关键 API 函数入口处设置断点，并在 JavaScript 回调中打印出该函数的参数值，从而了解该 API 的使用方式和输入。
* **Hooking (钩子):**  拦截本质上就是一种 hooking 技术。逆向工程师可以使用它来修改程序的行为，例如绕过安全检查、修改函数返回值、注入自定义代码等。
    * **举例:**  可以使用 `Interceptor.replace` 将目标应用的某个验证用户登录的函数替换为一个总是返回成功的函数，从而绕过登录验证。
* **代码注入:** 虽然这个文件本身不直接负责代码注入，但通过函数替换和拦截，可以间接地实现代码注入的效果，即在目标进程中执行自定义的 JavaScript 或 C 代码。
    * **举例:**  在拦截到某个函数调用时，可以在 JavaScript 回调中执行额外的代码，例如调用其他 JavaScript API 或执行系统命令。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明**

这个文件虽然主要是 C 代码，但它与 Frida 的其他部分共同协作，涉及到以下底层知识：

* **二进制代码执行:**  拦截的核心在于修改目标进程的指令流，例如修改函数入口处的指令，使其跳转到 Frida 的拦截处理代码。这需要理解目标平台的指令集架构（如 ARM, x86）。
    * **举例:**  `gum_interceptor_attach` 函数内部会涉及到修改目标函数的指令，这需要理解目标平台的汇编代码和内存布局。
* **内存管理:**  需要在目标进程的内存空间中分配和管理 Frida 的相关数据结构和代码。
    * **举例:**  拦截监听器和替换条目的存储需要动态分配内存。
* **函数调用约定:**  拦截器需要理解目标平台的函数调用约定（例如参数如何传递、返回值如何获取），以便正确地获取和修改函数的参数和返回值。
    * **举例:**  在 `GumInvocationContext` 中可以访问到函数的参数，这依赖于对目标平台调用约定的理解。
* **进程间通信 (IPC):**  Frida 需要与目标进程进行通信，以便注入代码、设置拦截器、获取执行结果等。
    * **说明:**  虽然这个文件本身不直接处理 IPC，但它是 Frida 架构的一部分，依赖于底层的 IPC 机制。
* **Linux/Android 系统调用:**  在某些情况下，拦截器可能需要与操作系统内核进行交互，例如访问进程信息、修改内存保护属性等。
    * **说明:**  `frida-gum` 库的底层实现可能会使用系统调用。
* **Android 框架 (例如 ART):**  在 Android 环境下，拦截器需要能够理解和操作 Android Runtime (ART) 的内部结构，例如如何 hook Java 方法。
    * **说明:**  虽然这个文件是 `gumjs` 的一部分，主要处理 C 函数拦截，但 Frida 的 Java 拦截机制也会与 `gum` 库交互。

**逻辑推理、假设输入与输出**

假设我们有以下 JavaScript 代码：

```javascript
const nativeFuncPtr = Module.findExportByName(null, 'some_native_function');
Interceptor.attach(nativeFuncPtr, {
  onEnter: function (args) {
    console.log('Entering some_native_function with arg:', args[0]);
    args[0] = ptr('0x12345678'); // 修改第一个参数
  },
  onLeave: function (retval) {
    console.log('Leaving some_native_function with return value:', retval);
    retval.replace(ptr('0x87654321')); // 修改返回值
  }
});
```

* **假设输入:**  `nativeFuncPtr` 指向目标进程中 `some_native_function` 的地址。
* **逻辑推理:**
    1. `Interceptor.attach` 函数会调用 C 代码中的 `gumjs_interceptor_attach`。
    2. `gumjs_interceptor_attach` 会创建一个 `GumQuickJSCallListener` 实例，并将 JavaScript 的 `onEnter` 和 `onLeave` 函数包装起来。
    3. 当 `some_native_function` 被调用时，Frida 的拦截机制会首先执行 `onEnter` 回调。
    4. 在 `onEnter` 回调中，`args[0]` 会被修改为 `0x12345678`。
    5. 目标函数 `some_native_function` 会使用修改后的参数执行。
    6. 当 `some_native_function` 执行完毕准备返回时，Frida 的拦截机制会执行 `onLeave` 回调。
    7. 在 `onLeave` 回调中，返回值 `retval` 会被修改为 `0x87654321`。
* **预期输出:**
    * 控制台会打印出 "Entering some_native_function with arg: [原始参数值]"。
    * 目标函数 `some_native_function` 接收到的第一个参数是 `0x12345678`。
    * 控制台会打印出 "Leaving some_native_function with return value: [原始返回值]"。
    * 实际返回给调用者的返回值是 `0x87654321`。

**用户或编程常见的使用错误及举例说明**

* **尝试多次 attach 到同一个函数，但没有正确处理已存在的监听器:**
    * **举例:** 用户多次调用 `Interceptor.attach(nativeFuncPtr, ...)`，而没有先调用 `detach`，可能导致意外的行为或资源泄漏。Frida 会抛出 "already attached to this function" 的异常。
* **在 `onEnter` 或 `onLeave` 回调中执行耗时操作或抛出异常:**
    * **举例:**  在回调中进行复杂的计算或网络请求可能会影响目标进程的性能甚至导致崩溃。未捕获的异常可能会中断拦截链。
* **在 C 回调中使用了错误的函数签名:**
    * **举例:**  `GumQuickCCallListener` 和 `GumQuickCProbeListener` 要求提供的 C 函数指针的签名与目标函数的调用约定兼容。如果签名不匹配，可能会导致程序崩溃或数据损坏。
* **在 `Interceptor.replace` 中提供了错误的替换函数指针:**
    * **举例:**  替换函数的参数和返回值类型必须与被替换函数兼容，否则可能导致程序崩溃。
* **忘记 `flush` 操作:**
    * **举例:** 在某些情况下，修改拦截器后可能需要调用 `Interceptor.flush()` 来确保修改被应用。

**用户操作如何一步步到达这里，作为调试线索**

1. **用户编写 Frida 脚本:**  用户开始编写 JavaScript 代码，使用 Frida 的 `Interceptor` API 来拦截目标进程中的函数。
   ```javascript
   Interceptor.attach(Module.findExportByName(null, 'my_function'), {
     onEnter: function(args) {
       console.log("Entering my_function");
     }
   });
   ```
2. **Frida 将 JavaScript 代码发送到目标进程:**  用户运行 Frida 脚本，Frida 客户端（通常是 Python）会将脚本发送到目标进程中的 Frida Agent。
3. **Frida Agent 加载 gum 库:**  目标进程中的 Frida Agent 会加载 `frida-gum` 库。
4. **JavaScript 引擎执行脚本:**  Frida Agent 内嵌的 JavaScript 引擎（例如 QuickJS）会执行用户编写的脚本。
5. **调用 `Interceptor.attach`:**  JavaScript 引擎执行到 `Interceptor.attach` 时，会调用 `gumjs_interceptor_attach` 函数（这个函数在 `gumquickinterceptor.c` 文件中定义）。
6. **`gumjs_interceptor_attach` 进行处理:**  `gumjs_interceptor_attach` 函数会解析 JavaScript 传递的参数（目标函数地址、回调函数等），创建相应的拦截监听器对象（例如 `GumQuickJSCallListener`），并调用 `gum_interceptor_attach`（在 `frida-gum` 的核心代码中）来实际设置拦截。
7. **拦截生效:**  当目标进程执行到 `my_function` 时，Frida 的拦截机制会捕获这次调用，并执行之前在 `onEnter` 中定义的 JavaScript 回调函数。

因此，用户通过在 JavaScript 中调用 `Interceptor` API，最终会触发 `gumquickinterceptor.c` 中的 C 代码执行，从而实现对目标进程函数的动态拦截。在调试过程中，如果发现拦截没有生效或者行为异常，可以检查 Frida 脚本中的 API 调用是否正确，以及目标进程中是否存在符号信息等。

希望以上分析对您有所帮助！如果您有关于 `gumquickinterceptor.c` 文件其他部分的问题，欢迎继续提问。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickinterceptor.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2020-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickinterceptor.h"

#include "gumquickmacros.h"

#define GUM_QUICK_TYPE_INVOCATION_LISTENER \
    (gum_quick_invocation_listener_get_type ())
#define GUM_QUICK_TYPE_JS_CALL_LISTENER \
    (gum_quick_js_call_listener_get_type ())
#define GUM_QUICK_TYPE_JS_PROBE_LISTENER \
    (gum_quick_js_probe_listener_get_type ())
#define GUM_QUICK_TYPE_C_CALL_LISTENER \
    (gum_quick_c_call_listener_get_type ())
#define GUM_QUICK_TYPE_C_PROBE_LISTENER \
    (gum_quick_c_probe_listener_get_type ())

#define GUM_QUICK_INVOCATION_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_QUICK_TYPE_INVOCATION_LISTENER, \
        GumQuickInvocationListener)
#define GUM_QUICK_JS_CALL_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_QUICK_TYPE_JS_CALL_LISTENER, \
        GumQuickJSCallListener)
#define GUM_QUICK_JS_PROBE_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_QUICK_TYPE_JS_PROBE_LISTENER, \
        GumQuickJSProbeListener)
#define GUM_QUICK_C_CALL_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_QUICK_TYPE_C_CALL_LISTENER, \
        GumQuickCCallListener)
#define GUM_QUICK_C_PROBE_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_QUICK_TYPE_C_PROBE_LISTENER, \
        GumQuickCProbeListener)

#define GUM_QUICK_INVOCATION_LISTENER_CAST(obj) \
    ((GumQuickInvocationListener *) (obj))
#define GUM_QUICK_JS_CALL_LISTENER_CAST(obj) \
    ((GumQuickJSCallListener *) (obj))
#define GUM_QUICK_JS_PROBE_LISTENER_CAST(obj) \
    ((GumQuickJSProbeListener *) (obj))
#define GUM_QUICK_C_CALL_LISTENER_CAST(obj) \
    ((GumQuickCCallListener *) (obj))
#define GUM_QUICK_C_PROBE_LISTENER_CAST(obj) \
    ((GumQuickCProbeListener *) (obj))

typedef struct _GumQuickInvocationListener GumQuickInvocationListener;
typedef struct _GumQuickInvocationListenerClass GumQuickInvocationListenerClass;
typedef struct _GumQuickJSCallListener GumQuickJSCallListener;
typedef struct _GumQuickJSCallListenerClass GumQuickJSCallListenerClass;
typedef struct _GumQuickJSProbeListener GumQuickJSProbeListener;
typedef struct _GumQuickJSProbeListenerClass GumQuickJSProbeListenerClass;
typedef struct _GumQuickCCallListener GumQuickCCallListener;
typedef struct _GumQuickCCallListenerClass GumQuickCCallListenerClass;
typedef struct _GumQuickCProbeListener GumQuickCProbeListener;
typedef struct _GumQuickCProbeListenerClass GumQuickCProbeListenerClass;
typedef struct _GumQuickInvocationState GumQuickInvocationState;
typedef struct _GumQuickReplaceEntry GumQuickReplaceEntry;

typedef void (* GumQuickCHook) (GumInvocationContext * ic);

struct _GumQuickInvocationListener
{
  GObject object;

  JSValue wrapper;

  GumQuickInterceptor * parent;
};

struct _GumQuickInvocationListenerClass
{
  GObjectClass object_class;
};

struct _GumQuickJSCallListener
{
  GumQuickInvocationListener listener;

  JSValue on_enter;
  JSValue on_leave;
};

struct _GumQuickJSCallListenerClass
{
  GumQuickInvocationListenerClass listener_class;
};

struct _GumQuickJSProbeListener
{
  GumQuickInvocationListener listener;

  JSValue on_hit;
};

struct _GumQuickJSProbeListenerClass
{
  GumQuickInvocationListenerClass listener_class;
};

struct _GumQuickCCallListener
{
  GumQuickInvocationListener listener;

  GumQuickCHook on_enter;
  GumQuickCHook on_leave;
};

struct _GumQuickCCallListenerClass
{
  GumQuickInvocationListenerClass listener_class;
};

struct _GumQuickCProbeListener
{
  GumQuickInvocationListener listener;

  GumQuickCHook on_hit;
};

struct _GumQuickCProbeListenerClass
{
  GumQuickInvocationListenerClass listener_class;
};

struct _GumQuickInvocationState
{
  GumQuickInvocationContext * jic;
};

struct _GumQuickInvocationArgs
{
  JSValue wrapper;
  GumInvocationContext * ic;
  JSContext * ctx;
};

struct _GumQuickInvocationRetval
{
  GumQuickNativePointer native_pointer;

  JSValue wrapper;
  GumInvocationContext * ic;
  JSContext * ctx;
};

struct _GumQuickReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  JSValue replacement;
  JSContext * ctx;
};

static gboolean gum_quick_interceptor_on_flush_timer_tick (
    GumQuickInterceptor * self);

GUMJS_DECLARE_FUNCTION (gumjs_interceptor_attach)
static void gum_quick_invocation_listener_destroy (
    GumQuickInvocationListener * listener);
static void gum_quick_interceptor_detach (GumQuickInterceptor * self,
    GumQuickInvocationListener * listener);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_detach_all)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_replace)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_replace_fast)
static void gum_quick_add_replace_entry (GumQuickInterceptor * self,
    gpointer target, JSValue replacement_value);
static JSValue gum_quick_handle_replace_ret (JSContext * ctx, gpointer target,
    GumReplaceReturn replace_ret);
static void gum_quick_replace_entry_revert_and_free (
    GumQuickReplaceEntry * entry);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_revert)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_flush)

GUMJS_DECLARE_FUNCTION (gumjs_invocation_listener_detach)
static void gum_quick_invocation_listener_dispose (GObject * object);
static void gum_quick_invocation_listener_release_wrapper (
    GumQuickInvocationListener * self, JSContext * ctx);
G_DEFINE_TYPE_EXTENDED (GumQuickInvocationListener,
                        gum_quick_invocation_listener,
                        G_TYPE_OBJECT,
                        G_TYPE_FLAG_ABSTRACT,
                        {})

static void gum_quick_js_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_js_call_listener_dispose (GObject * object);
static void gum_quick_js_call_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
static void gum_quick_js_call_listener_on_leave (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumQuickJSCallListener,
                        gum_quick_js_call_listener,
                        GUM_QUICK_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_quick_js_call_listener_iface_init))

static void gum_quick_js_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_js_probe_listener_dispose (GObject * object);
static void gum_quick_js_probe_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumQuickJSProbeListener,
                        gum_quick_js_probe_listener,
                        GUM_QUICK_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_quick_js_probe_listener_iface_init))

static void gum_quick_c_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_c_call_listener_dispose (GObject * object);
static void gum_quick_c_call_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
static void gum_quick_c_call_listener_on_leave (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumQuickCCallListener,
                        gum_quick_c_call_listener,
                        GUM_QUICK_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_quick_c_call_listener_iface_init))

static void gum_quick_c_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_quick_c_probe_listener_dispose (GObject * object);
static void gum_quick_c_probe_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumQuickCProbeListener,
                        gum_quick_c_probe_listener,
                        GUM_QUICK_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_quick_c_probe_listener_iface_init))

static JSValue gum_quick_invocation_context_new (GumQuickInterceptor * parent,
    GumQuickInvocationContext ** context);
static void gum_quick_invocation_context_release (
    GumQuickInvocationContext * self);
static gboolean gum_quick_invocation_context_is_dirty (
    GumQuickInvocationContext * self);
GUMJS_DECLARE_FINALIZER (gumjs_invocation_context_finalize)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_system_error)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_thread_id)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_depth)

static JSValue gum_quick_invocation_args_new (GumQuickInterceptor * parent,
    GumQuickInvocationArgs ** args);
static void gum_quick_invocation_args_release (GumQuickInvocationArgs * self);
static void gum_quick_invocation_args_reset (GumQuickInvocationArgs * self,
    GumInvocationContext * ic);
GUMJS_DECLARE_FINALIZER (gumjs_invocation_args_finalize)
static JSValue gumjs_invocation_args_get_property (JSContext * ctx,
    JSValueConst obj, JSAtom atom, JSValueConst receiver);
static int gumjs_invocation_args_set_property (JSContext * ctx,
    JSValueConst obj, JSAtom atom, JSValueConst value, JSValueConst receiver,
    int flags);

static JSValue gum_quick_invocation_retval_new (GumQuickInterceptor * parent,
    GumQuickInvocationRetval ** retval);
static void gum_quick_invocation_retval_release (
    GumQuickInvocationRetval * self);
static void gum_quick_invocation_retval_reset (
    GumQuickInvocationRetval * self, GumInvocationContext * ic);
GUMJS_DECLARE_FINALIZER (gumjs_invocation_retval_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_invocation_retval_replace)

static void gum_quick_interceptor_check_invocation_context (
    GumQuickInterceptor * self, GumQuickInvocationContext * jic,
    gboolean * jic_is_dirty);
static GumQuickInvocationArgs * gum_quick_interceptor_obtain_invocation_args (
    GumQuickInterceptor * self);
static void gum_quick_interceptor_release_invocation_args (
    GumQuickInterceptor * self, GumQuickInvocationArgs * args);
static GumQuickInvocationRetval *
gum_quick_interceptor_obtain_invocation_retval (GumQuickInterceptor * self);
static void gum_quick_interceptor_release_invocation_retval (
    GumQuickInterceptor * self, GumQuickInvocationRetval * retval);

static const JSCFunctionListEntry gumjs_interceptor_entries[] =
{
  JS_CFUNC_DEF ("_attach", 3, gumjs_interceptor_attach),
  JS_CFUNC_DEF ("detachAll", 0, gumjs_interceptor_detach_all),
  JS_CFUNC_DEF ("_replace", 0, gumjs_interceptor_replace),
  JS_CFUNC_DEF ("_replaceFast", 0, gumjs_interceptor_replace_fast),
  JS_CFUNC_DEF ("revert", 0, gumjs_interceptor_revert),
  JS_CFUNC_DEF ("flush", 0, gumjs_interceptor_flush),
};

static const JSClassDef gumjs_invocation_listener_def =
{
  .class_name = "InvocationListener",
};

static const JSCFunctionListEntry gumjs_invocation_listener_entries[] =
{
  JS_CFUNC_DEF ("detach", 0, gumjs_invocation_listener_detach),
};

static const JSClassDef gumjs_invocation_context_def =
{
  .class_name = "InvocationContext",
  .finalizer = gumjs_invocation_context_finalize,
};

static const JSCFunctionListEntry gumjs_invocation_context_entries[] =
{
  JS_CGETSET_DEF ("returnAddress", gumjs_invocation_context_get_return_address,
      NULL),
  JS_CGETSET_DEF ("context", gumjs_invocation_context_get_cpu_context, NULL),
  JS_CGETSET_DEF (GUMJS_SYSTEM_ERROR_FIELD,
      gumjs_invocation_context_get_system_error,
      gumjs_invocation_context_set_system_error),
  JS_CGETSET_DEF ("threadId", gumjs_invocation_context_get_thread_id, NULL),
  JS_CGETSET_DEF ("depth", gumjs_invocation_context_get_depth, NULL),
};

static const JSClassExoticMethods gumjs_invocation_args_exotic_methods =
{
  .get_property = gumjs_invocation_args_get_property,
  .set_property = gumjs_invocation_args_set_property,
};

static const JSClassDef gumjs_invocation_args_def =
{
  .class_name = "InvocationArguments",
  .finalizer = gumjs_invocation_args_finalize,
  .exotic = (JSClassExoticMethods *) &gumjs_invocation_args_exotic_methods,
};

static const JSClassDef gumjs_invocation_retval_def =
{
  .class_name = "InvocationReturnValue",
  .finalizer = gumjs_invocation_retval_finalize,
};

static const JSCFunctionListEntry gumjs_invocation_retval_entries[] =
{
  JS_CFUNC_DEF ("replace", 0, gumjs_invocation_retval_replace),
};

void
_gum_quick_interceptor_init (GumQuickInterceptor * self,
                             JSValue ns,
                             GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue obj, proto;

  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->invocation_listeners = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_quick_invocation_listener_destroy);
  self->replacement_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_quick_replace_entry_revert_and_free);
  self->flush_timer = NULL;

  _gum_quick_core_store_module_data (core, "interceptor", self);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_interceptor_entries,
      G_N_ELEMENTS (gumjs_interceptor_entries));
  JS_DefinePropertyValueStr (ctx, ns, "Interceptor", obj, JS_PROP_C_W_E);

  _gum_quick_create_class (ctx, &gumjs_invocation_listener_def, core,
      &self->invocation_listener_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_invocation_listener_entries,
      G_N_ELEMENTS (gumjs_invocation_listener_entries));

  _gum_quick_create_class (ctx, &gumjs_invocation_context_def, core,
      &self->invocation_context_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_invocation_context_entries,
      G_N_ELEMENTS (gumjs_invocation_context_entries));

  _gum_quick_create_class (ctx, &gumjs_invocation_args_def, core,
      &self->invocation_args_class, &proto);

  _gum_quick_create_subclass (ctx, &gumjs_invocation_retval_def,
      core->native_pointer_class, core->native_pointer_proto, core,
      &self->invocation_retval_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_invocation_retval_entries,
      G_N_ELEMENTS (gumjs_invocation_retval_entries));

  gum_quick_invocation_context_new (self, &self->cached_invocation_context);
  self->cached_invocation_context_in_use = FALSE;

  gum_quick_invocation_args_new (self, &self->cached_invocation_args);
  self->cached_invocation_args_in_use = FALSE;

  gum_quick_invocation_retval_new (self, &self->cached_invocation_retval);
  self->cached_invocation_retval_in_use = FALSE;
}

void
_gum_quick_interceptor_flush (GumQuickInterceptor * self)
{
  GumQuickCore * core = self->core;
  GumQuickScope scope = GUM_QUICK_SCOPE_INIT (core);
  gboolean flushed;

  g_hash_table_remove_all (self->invocation_listeners);
  g_hash_table_remove_all (self->replacement_by_address);

  _gum_quick_scope_suspend (&scope);

  flushed = gum_interceptor_flush (self->interceptor);

  _gum_quick_scope_resume (&scope);

  if (!flushed && self->flush_timer == NULL)
  {
    GSource * source;

    source = g_timeout_source_new (10);
    g_source_set_callback (source,
        (GSourceFunc) gum_quick_interceptor_on_flush_timer_tick, self, NULL);
    self->flush_timer = source;

    _gum_quick_core_pin (core);
    _gum_quick_scope_suspend (&scope);

    g_source_attach (source,
        gum_script_scheduler_get_js_context (core->scheduler));
    g_source_unref (source);

    _gum_quick_scope_resume (&scope);
  }
}

static gboolean
gum_quick_interceptor_on_flush_timer_tick (GumQuickInterceptor * self)
{
  gboolean flushed;

  flushed = gum_interceptor_flush (self->interceptor);
  if (flushed)
  {
    GumQuickCore * core = self->core;
    GumQuickScope scope;

    _gum_quick_scope_enter (&scope, core);
    _gum_quick_core_unpin (core);
    self->flush_timer = NULL;
    _gum_quick_scope_leave (&scope);
  }

  return !flushed;
}

void
_gum_quick_interceptor_dispose (GumQuickInterceptor * self)
{
  g_assert (self->flush_timer == NULL);

  gum_quick_invocation_context_release (self->cached_invocation_context);
  gum_quick_invocation_args_release (self->cached_invocation_args);
  gum_quick_invocation_retval_release (self->cached_invocation_retval);
}

void
_gum_quick_interceptor_finalize (GumQuickInterceptor * self)
{
  g_clear_pointer (&self->invocation_listeners, g_hash_table_unref);
  g_clear_pointer (&self->replacement_by_address, g_hash_table_unref);

  g_clear_pointer (&self->interceptor, g_object_unref);
}

static GumQuickInterceptor *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "interceptor");
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_attach)
{
  JSValue target_val = args->elements[0];
  JSValue cb_val = args->elements[1];
  JSValue data_val = args->elements[2];
  GumQuickInterceptor * self;
  gpointer target, cb_ptr;
  GumQuickInvocationListener * listener = NULL;
  gpointer listener_function_data;
  GumAttachReturn attach_ret;

  self = gumjs_get_parent_module (core);

  if (JS_IsFunction (ctx, cb_val))
  {
    GumQuickJSProbeListener * l;

    if (!_gum_quick_native_pointer_get (ctx, target_val, core, &target))
      goto propagate_exception;

    l = g_object_new (GUM_QUICK_TYPE_JS_PROBE_LISTENER, NULL);
    l->on_hit = JS_DupValue (ctx, cb_val);

    listener = GUM_QUICK_INVOCATION_LISTENER (l);
  }
  else if (_gum_quick_native_pointer_try_get (ctx, cb_val, core, &cb_ptr))
  {
    GumQuickCProbeListener * l;

    if (!_gum_quick_native_pointer_get (ctx, target_val, core, &target))
      goto propagate_exception;

    l = g_object_new (GUM_QUICK_TYPE_C_PROBE_LISTENER, NULL);
    l->on_hit = GUM_POINTER_TO_FUNCPTR (GumQuickCHook, cb_ptr);

    listener = GUM_QUICK_INVOCATION_LISTENER (l);
  }
  else
  {
    JSValue on_enter_js, on_leave_js;
    GumQuickCHook on_enter_c, on_leave_c;

    if (!_gum_quick_args_parse (args, "pF*{onEnter?,onLeave?}", &target,
        &on_enter_js, &on_enter_c,
        &on_leave_js, &on_leave_c))
      goto propagate_exception;

    if (!JS_IsNull (on_enter_js) || !JS_IsNull (on_leave_js))
    {
      GumQuickJSCallListener * l;

      l = g_object_new (GUM_QUICK_TYPE_JS_CALL_LISTENER, NULL);
      l->on_enter = JS_DupValue (ctx, on_enter_js);
      l->on_leave = JS_DupValue (ctx, on_leave_js);

      listener = GUM_QUICK_INVOCATION_LISTENER (l);
    }
    else if (on_enter_c != NULL || on_leave_c != NULL)
    {
      GumQuickCCallListener * l;

      l = g_object_new (GUM_QUICK_TYPE_C_CALL_LISTENER, NULL);
      l->on_enter = on_enter_c;
      l->on_leave = on_leave_c;

      listener = GUM_QUICK_INVOCATION_LISTENER (l);
    }
    else
    {
      goto expected_callback;
    }
  }

  if (!JS_IsUndefined (data_val))
  {
    if (!_gum_quick_native_pointer_get (ctx, data_val, core,
        &listener_function_data))
      goto propagate_exception;
  }
  else
  {
    listener_function_data = NULL;
  }

  listener->parent = self;

  attach_ret = gum_interceptor_attach (self->interceptor, target,
      GUM_INVOCATION_LISTENER (listener), listener_function_data);

  if (attach_ret != GUM_ATTACH_OK)
    goto unable_to_attach;

  listener->wrapper = JS_NewObjectClass (ctx, self->invocation_listener_class);
  JS_SetOpaque (listener->wrapper, listener);
  JS_DefinePropertyValue (ctx, listener->wrapper,
      GUM_QUICK_CORE_ATOM (core, resource),
      JS_DupValue (ctx, cb_val),
      0);

  g_hash_table_add (self->invocation_listeners, listener);

  return JS_DupValue (ctx, listener->wrapper);

unable_to_attach:
  {
    switch (attach_ret)
    {
      case GUM_ATTACH_WRONG_SIGNATURE:
        _gum_quick_throw (ctx, "unable to intercept function at %p; "
            "please file a bug", target);
        break;
      case GUM_ATTACH_ALREADY_ATTACHED:
        _gum_quick_throw_literal (ctx, "already attached to this function");
        break;
      case GUM_ATTACH_POLICY_VIOLATION:
        _gum_quick_throw_literal (ctx, "not permitted by code-signing policy");
        break;
      case GUM_ATTACH_WRONG_TYPE:
        _gum_quick_throw_literal (ctx, "wrong type");
        break;
      default:
        g_assert_not_reached ();
    }

    goto propagate_exception;
  }
expected_callback:
  {
    _gum_quick_throw_literal (ctx, "expected at least one callback");
    goto propagate_exception;
  }
propagate_exception:
  {
    g_clear_object (&listener);

    return JS_EXCEPTION;
  }
}

static void
gum_quick_invocation_listener_destroy (GumQuickInvocationListener * listener)
{
  gum_interceptor_detach (listener->parent->interceptor,
      GUM_INVOCATION_LISTENER (listener));
  g_object_unref (listener);
}

static void
gum_quick_interceptor_detach (GumQuickInterceptor * self,
                              GumQuickInvocationListener * listener)
{
  g_hash_table_remove (self->invocation_listeners, listener);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_detach_all)
{
  GumQuickInterceptor * self = gumjs_get_parent_module (core);

  g_hash_table_remove_all (self->invocation_listeners);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace)
{
  GumQuickInterceptor * self;
  gpointer target, replacement_function, replacement_data;
  JSValue replacement_value;
  GumReplaceReturn replace_ret;

  self = gumjs_get_parent_module (core);

  replacement_data = NULL;
  if (!_gum_quick_args_parse (args, "pO|p", &target, &replacement_value,
      &replacement_data))
    return JS_EXCEPTION;

  if (!_gum_quick_native_pointer_get (ctx, replacement_value, core,
      &replacement_function))
    return JS_EXCEPTION;

  replace_ret = gum_interceptor_replace (self->interceptor, target,
      replacement_function, replacement_data, NULL);
  if (replace_ret != GUM_REPLACE_OK)
    return gum_quick_handle_replace_ret (ctx, target, replace_ret);

  gum_quick_add_replace_entry (self, target, replacement_value);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace_fast)
{
  GumQuickInterceptor * self;
  gpointer target, replacement_function, original_function;
  JSValue replacement_value;
  GumReplaceReturn replace_ret;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "pO", &target, &replacement_value))
    return JS_EXCEPTION;

  if (!_gum_quick_native_pointer_get (ctx, replacement_value, core,
      &replacement_function))
    return JS_EXCEPTION;

  replace_ret = gum_interceptor_replace_fast (self->interceptor, target,
      replacement_function, &original_function);
  if (replace_ret != GUM_REPLACE_OK)
    return gum_quick_handle_replace_ret (ctx, target, replace_ret);

  gum_quick_add_replace_entry (self, target, replacement_value);

  return _gum_quick_native_pointer_new (ctx,
      GSIZE_TO_POINTER (original_function), core);
}

static void
gum_quick_add_replace_entry (GumQuickInterceptor * self,
                             gpointer target,
                             JSValue replacement_value)
{
  GumQuickCore * core = self->core;
  JSContext * ctx = core->ctx;
  GumQuickReplaceEntry * entry;

  entry = g_slice_new (GumQuickReplaceEntry);
  entry->interceptor = self->interceptor;
  entry->target = target;
  entry->replacement = JS_DupValue (ctx, replacement_value);
  entry->ctx = ctx;

  g_hash_table_insert (self->replacement_by_address, target, entry);
}

static JSValue
gum_quick_handle_replace_ret (JSContext * ctx,
                              gpointer target,
                              GumReplaceReturn replace_ret)
{
  switch (replace_ret)
  {
    case GUM_REPLACE_WRONG_SIGNATURE:
      _gum_quick_throw (ctx, "unable to intercept function at %p; "
          "please file a bug", target);
      break;
    case GUM_REPLACE_ALREADY_REPLACED:
      _gum_quick_throw_literal (ctx, "already replaced this function");
      break;
    case GUM_REPLACE_POLICY_VIOLATION:
      _gum_quick_throw_literal (ctx, "not permitted by code-signing policy");
      break;
    case GUM_REPLACE_WRONG_TYPE:
      _gum_quick_throw_literal (ctx, "wrong type");
      break;
    default:
      g_assert_not_reached ();
  }

  return JS_EXCEPTION;
}

static void
gum_quick_replace_entry_free (GumQuickReplaceEntry * entry)
{
  if (entry == NULL)
    return;

  JS_FreeValue (entry->ctx, entry->replacement);

  g_slice_free (GumQuickReplaceEntry, entry);
}

static void
gum_quick_replace_entry_revert_and_free (GumQuickReplaceEntry * entry)
{
  gum_interceptor_revert (entry->interceptor, entry->target);

  gum_quick_replace_entry_free (entry);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_revert)
{
  GumQuickInterceptor * self;
  gpointer target;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "p", &target))
    return JS_EXCEPTION;

  g_hash_table_remove (self->replacement_by_address, target);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_flush)
{
  GumQuickInterceptor * self = gumjs_get_parent_module (core);

  gum_interceptor_end_transaction (self->interceptor);
  gum_interceptor_begin_transaction (self->interceptor);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_invocation_listener_detach)
{
  GumQuickInterceptor * parent;
  GumQuickInvocationListener * listener;

  parent = gumjs_get_parent_module (core);

  if (!_gum_quick_unwrap (ctx, this_val, parent->invocation_listener_class,
      core, (gpointer *) &listener))
    return JS_EXCEPTION;

  if (listener != NULL)
    gum_quick_interceptor_detach (parent, listener);

  return JS_UNDEFINED;
}

static void
gum_quick_invocation_listener_class_init (
    GumQuickInvocationListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_invocation_listener_dispose;
}

static void
gum_quick_invocation_listener_init (GumQuickInvocationListener * self)
{
  self->wrapper = JS_NULL;
}

static void
gum_quick_invocation_listener_dispose (GObject * object)
{
  g_assert (JS_IsNull (GUM_QUICK_INVOCATION_LISTENER (object)->wrapper));

  G_OBJECT_CLASS (gum_quick_invocation_listener_parent_class)->dispose (object);
}

static void
gum_quick_invocation_listener_release_wrapper (
    GumQuickInvocationListener * self,
    JSContext * ctx)
{
  if (!JS_IsNull (self->wrapper))
  {
    JS_SetOpaque (self->wrapper, NULL);
    JS_FreeValue (ctx, self->wrapper);
    self->wrapper = JS_NULL;
  }
}

static void
gum_quick_js_call_listener_class_init (GumQuickJSCallListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_js_call_listener_dispose;
}

static void
gum_quick_js_call_listener_iface_init (gpointer g_iface,
                                       gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_quick_js_call_listener_on_enter;
  iface->on_leave = gum_quick_js_call_listener_on_leave;
}

static void
gum_quick_js_call_listener_init (GumQuickJSCallListener * self)
{
}

static void
gum_quick_js_call_listener_dispose (GObject * object)
{
  GumQuickJSCallListener * self;
  GumQuickInvocationListener * base_listener;
  GumQuickCore * core;
  JSContext * ctx;
  GumQuickScope scope;

  self = GUM_QUICK_JS_CALL_LISTENER (object);
  base_listener = GUM_QUICK_INVOCATION_LISTENER (object);
  core = base_listener->parent->core;
  ctx = core->ctx;

  _gum_quick_scope_enter (&scope, core);

  JS_FreeValue (ctx, self->on_enter);
  self->on_enter = JS_NULL;

  JS_FreeValue (ctx, self->on_leave);
  self->on_leave = JS_NULL;

  gum_quick_invocation_listener_release_wrapper (base_listener, ctx);

  _gum_quick_scope_leave (&scope);

  G_OBJECT_CLASS (gum_quick_js_call_listener_parent_class)->dispose (object);
}

static void
gum_quick_js_call_listener_on_enter (GumInvocationListener * listener,
                                     GumInvocationContext * ic)
{
  GumQuickJSCallListener * self;
  GumQuickInvocationState * state;

  self = GUM_QUICK_JS_CALL_LISTENER_CAST (listener);
  state = GUM_IC_GET_INVOCATION_DATA (ic, GumQuickInvocationState);

  if (!JS_IsNull (self->on_enter))
  {
    GumQuickInterceptor * parent;
    GumQuickScope scope;
    GumQuickInvocationContext * jic;
    GumQuickInvocationArgs * args;
    gboolean jic_is_dirty;

    parent = GUM_QUICK_INVOCATION_LISTENER_CAST (listener)->parent;

    _gum_quick_scope_enter (&scope, parent->core);

    jic = _gum_quick_interceptor_obtain_invocation_context (parent);
    _gum_quick_invocation_context_reset (jic, ic);

    args = gum_quick_interceptor_obtain_invocation_args (parent);
    gum_quick_invocation_args_reset (args, ic);

    _gum_quick_scope_call_void (&scope, self->on_enter, jic->wrapper, 1,
        &args->wrapper);

    gum_quick_invocation_args_reset (args, NULL);
    gum_quick_interceptor_release_invocation_args (parent, args);

    _gum_quick_invocation_context_reset (jic, NULL);
    gum_quick_interceptor_check_invocation_context (parent, jic, &jic_is_dirty);
    if (!JS_IsNull (self->on_leave) || jic_is_dirty)
    {
      state->jic = jic;
    }
    else
    {
      _gum_quick_interceptor_release_invocation_context (parent, jic);
      state->jic = NULL;
    }

    _gum_quick_scope_leave (&scope);
  }
  else
  {
    state->jic = NULL;
  }
}

static void
gum_quick_js_call_listener_on_leave (GumInvocationListener * listener,
                                     GumInvocationContext * ic)
{
  GumQuickJSCallListener * self;
  GumQuickInterceptor * parent;
  GumQuickInvocationState * state;

  self = GUM_QUICK_JS_CALL_LISTENER_CAST (listener);
  parent = GUM_QUICK_INVOCATION_LISTENER_CAST (listener)->parent;
  state = GUM_IC_GET_INVOCATION_DATA (ic, GumQuickInvocationState);

  if (!JS_IsNull (self->on_leave))
  {
    GumQuickScope scope;
    GumQuickInvocationContext * jic;
    GumQuickInvocationRetval * retval;

    _gum_quick_scope_enter (&scope, parent->core);

    jic = !JS_IsNull (self->on_enter) ? state->jic : NULL;
    if (jic == NULL)
    {
      jic = _gum_quick_interceptor_obtain_invocation_context (parent);
    }
    _gum_quick_invocation_context_reset (jic, ic);

    retval = gum_quick_interceptor_obtain_invocation_retval (parent);
    gum_quick_invocation_retval_reset (retval, ic);

    _gum_quick_scope_call_void (&scope, self->on_leave, jic->wrapper, 1,
        &retval->wrapper);

    gum_quick_invocation_retval_reset (retval, NULL);
    gum_quick_interceptor_release_invocation_retval (parent, retval);

    _gum_quick_invocation_context_reset (jic, NULL);
    gum_quick_interceptor_check_invocation_context (parent, jic, NULL);
    _gum_quick_interceptor_release_invocation_context (parent, jic);

    _gum_quick_scope_leave (&scope);
  }
  else if (state->jic != NULL)
  {
    GumQuickScope scope;

    _gum_quick_scope_enter (&scope, parent->core);

    _gum_quick_interceptor_release_invocation_context (parent, state->jic);

    _gum_quick_scope_leave (&scope);
  }
}

static void
gum_quick_js_probe_listener_class_init (GumQuickJSProbeListenerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_js_probe_listener_dispose;
}

static void
gum_quick_js_probe_listener_iface_init (gpointer g_iface,
                                        gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_quick_js_probe_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_quick_js_probe_listener_init (GumQuickJSProbeListener * self)
{
}

static void
gum_quick_js_probe_listener_dispose (GObject * object)
{
  GumQuickJSProbeListener * self;
  GumQuickInvocationListener * base_listener;
  GumQuickCore * core;
  JSContext * ctx;
  GumQuickScope scope;

  self = GUM_QUICK_JS_PROBE_LISTENER (object);
  base_listener = GUM_QUICK_INVOCATION_LISTENER (object);
  core = base_listener->parent->core;
  ctx = core->ctx;

  _gum_quick_scope_enter (&scope, core);

  JS_FreeValue (ctx, self->on_hit);
  self->on_hit = JS_NULL;

  gum_quick_invocation_listener_release_wrapper (base_listener, ctx);

  _gum_quick_scope_leave (&scope);

  G_OBJECT_CLASS (gum_quick_js_probe_listener_parent_class)->dispose (object);
}

static void
gum_quick_js_probe_listener_on_enter (GumInvocationListener * listener,
                                      GumInvocationContext * ic)
{
  GumQuickJSProbeListener * self;
  GumQuickInterceptor * parent;
  GumQuickScope scope;
  GumQuickInvocationContext * jic;
  GumQuickInvocationArgs * args;

  self = GUM_QUICK_JS_PROBE_LISTENER
```