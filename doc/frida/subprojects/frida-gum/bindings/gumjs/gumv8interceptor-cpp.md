Response:
My thinking process to answer the request goes like this:

1. **Understand the Goal:** The core request is to analyze the provided C++ code snippet (`gumv8interceptor.cpp`) and explain its functionality within the context of Frida, focusing on its role in dynamic instrumentation and its interactions with different system levels. The prompt specifically asks for connections to reverse engineering, low-level concepts, logical inference, common errors, and debugging.

2. **Initial Code Scan and Keyword Identification:** I'd first skim the code, looking for recognizable keywords and structures. This helps to get a high-level understanding. Key things I'd notice quickly:
    * `#include` statements (especially those mentioning "gum", "v8"):  Indicates interaction with Frida's core (`gum`) and the V8 JavaScript engine.
    * `struct` definitions (e.g., `GumV8InvocationListener`, `GumV8JSCallListener`): Suggests data structures for managing interception information.
    * Function declarations with `GUMJS_DECLARE_FUNCTION` and `GUMJS_DEFINE_FUNCTION`:  Clearly points to JavaScript bindings and functions exposed to the Frida user.
    * `gum_interceptor_*` functions: These are core Frida API calls for attaching, detaching, replacing, and reverting function hooks.
    * V8 namespace usage (`using namespace v8;`): Confirms interaction with the V8 JavaScript engine.
    * Data types like `gpointer`, `Global<Object>`, `Local<Value>`: Indicate interaction with C/C++ memory management and V8's object model.
    * References to "invocation", "call", "probe": Suggest different interception strategies.

3. **Identify Core Functionality Blocks:** Based on the keywords and structures, I'd start grouping related code sections to understand their purpose. For example:
    * **Listener Structures:** `GumV8InvocationListener`, `GumV8JSCallListener`, `GumV8JSProbeListener`, `GumV8CCallListener`, `GumV8CProbeListener`. These clearly define different types of interceptors, distinguishing between JavaScript and C callbacks, and call vs. probe interception.
    * **Invocation Context and Arguments:** `GumV8InvocationContext`, `GumV8InvocationArgs`, `GumV8InvocationReturnValue`. These structures manage the data passed to and from intercepted functions.
    * **Replace Functionality:**  `GumV8ReplaceEntry`, `gumjs_interceptor_replace`, `gumjs_interceptor_replace_fast`, `gumjs_interceptor_revert`. This section deals with replacing function implementations.
    * **Attach/Detach Functionality:** `gumjs_interceptor_attach`, `gumjs_interceptor_detach_all`, `gumjs_invocation_listener_detach`. This manages the process of setting up and removing interception hooks.
    * **Flush Mechanism:** `gumjs_interceptor_flush`, `gum_v8_interceptor_on_flush_timer_tick`. This deals with synchronizing instrumentation changes.

4. **Trace the Control Flow (Conceptual):** I'd mentally trace how a user might interact with this code. A typical Frida workflow involves:
    * **Identifying a target function:**  The user specifies an address or function name.
    * **Defining an action:** The user wants to observe the function (probe) or modify its behavior (call interception, replacement).
    * **Providing a callback:** The user writes JavaScript code to be executed when the target function is hit.
    * **Attaching the interceptor:** Frida sets up the hook.
    * **Execution:** The target application runs, and when the hooked function is called, Frida's code is executed.
    * **Detaching (optional):** The user removes the hook.

5. **Relate to Reverse Engineering Concepts:**  At this point, the connections to reverse engineering become clearer:
    * **Function Hooking:** The core functionality is intercepting and manipulating function calls, a fundamental technique in reverse engineering for understanding program behavior.
    * **Dynamic Analysis:** Frida operates at runtime, enabling dynamic analysis of applications.
    * **Code Injection:**  While not explicitly code injection in the traditional sense, Frida injects its instrumentation logic into the target process.
    * **API Hooking:**  The code allows hooking into both native (C/C++) and JavaScript functions.

6. **Identify Low-Level Interactions:** The code snippets dealing with `gpointer`, kernel concepts (implicitly through `gum_interceptor_*`), and V8's internals point to low-level interactions:
    * **Memory Addresses:**  `gpointer` represents raw memory addresses.
    * **Kernel Involvement:** Frida's interception mechanism often involves interacting with the operating system kernel to set up breakpoints or modify function entry points. While the code doesn't show direct kernel calls, the underlying `gum` library handles this.
    * **V8 Engine Internals:** The code interacts with V8's object model (`Local`, `Global`), function calls, and isolates.

7. **Consider Logical Inference, Assumptions, and Error Handling:**
    * **Assumptions:** The code assumes the target process is running and accessible. It assumes valid memory addresses are provided.
    * **Error Handling:**  The code includes checks for argument types and uses `_gum_v8_throw_ascii(_literal)` to report errors back to the JavaScript user. The `GumAttachReturn` and `GumReplaceReturn` enums represent different error conditions.

8. **Think About User Errors:** Common mistakes users might make include:
    * **Incorrect target address:** Providing a wrong memory address.
    * **Mismatched callback signatures:**  The provided JavaScript or C callback function might not match the expected arguments of the intercepted function.
    * **Attaching multiple times:** Trying to attach to the same function multiple times without detaching.
    * **Policy violations:** Trying to intercept functions protected by code-signing.

9. **Trace User Actions to Code Execution:** I'd visualize the steps a user takes in a Frida script that leads to this C++ code being executed:
    * `Interceptor.attach(targetAddress, callback)` in JavaScript translates to the `gumjs_interceptor_attach` function in C++.
    * `Interceptor.replace(targetAddress, replacementFunction)` maps to `gumjs_interceptor_replace`.
    * `listener.detach()` calls `gumjs_invocation_listener_detach`.

10. **Structure the Explanation:** Finally, I'd organize my findings into the categories requested by the prompt: functionality, relationship to reverse engineering, low-level details, logical inference, user errors, and debugging. I would use examples where appropriate to illustrate the concepts.

By following these steps, I can systematically analyze the C++ code and provide a comprehensive explanation of its role and features within the Frida framework. The process involves a combination of code reading, understanding the underlying concepts of dynamic instrumentation, and thinking about how a user interacts with the tool.
```cpp
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8interceptor.h"

#include "gumv8macros.h"
#include "gumv8scope.h"

#include <errno.h>

#define GUMJS_MODULE_NAME Interceptor

#define GUM_V8_TYPE_INVOCATION_LISTENER (gum_v8_invocation_listener_get_type ())
#define GUM_V8_TYPE_JS_CALL_LISTENER (gum_v8_js_call_listener_get_type ())
#define GUM_V8_TYPE_JS_PROBE_LISTENER (gum_v8_js_probe_listener_get_type ())
#define GUM_V8_TYPE_C_CALL_LISTENER (gum_v8_c_call_listener_get_type ())
#define GUM_V8_TYPE_C_PROBE_LISTENER (gum_v8_c_probe_listener_get_type ())

// ... (rest of the code)
```

这是 Frida 动态Instrumentation 工具中 `gumv8interceptor.cpp` 文件的第一部分。它的主要功能是：

**核心功能：提供 JavaScript 接口来拦截和修改程序执行流程。**

具体来说，这部分代码定义了与拦截器相关的核心数据结构和函数，用于在 JavaScript 代码中操作 Frida 的拦截功能。它主要关注以下几个方面：

1. **定义拦截器监听器类型:**
   - 它定义了不同类型的拦截器监听器，用于区分不同的拦截方式和回调类型：
     - `GumV8InvocationListener`:  一个抽象基类，表示通用的拦截监听器。
     - `GumV8JSCallListener`:  用于拦截 JavaScript 函数调用，并提供 `onEnter` 和 `onLeave` 回调（JavaScript 函数）。
     - `GumV8JSProbeListener`: 用于在 JavaScript 代码的特定位置插入探针，并提供 `onHit` 回调（JavaScript 函数）。
     - `GumV8CCallListener`: 用于拦截 C/C++ 函数调用，并提供 `onEnter` 和 `onLeave` 回调（C 函数指针）。
     - `GumV8CProbeListener`: 用于在 C/C++ 代码的特定位置插入探针，并提供 `onHit` 回调（C 函数指针）。
   - 这些宏定义 (`GUM_V8_TYPE_*`) 和类型检查宏 (`GUM_V8_*_LISTENER`) 用于在代码中安全地处理不同类型的监听器对象。

2. **定义拦截器监听器的数据结构:**
   - 为每种监听器类型定义了相应的结构体，用于存储与该监听器相关的信息：
     - `GumV8InvocationListener`: 包含一个指向 V8 `Object` 的全局句柄 (`resource`)，通常是用户提供的回调函数或对象，以及一个指向 `GumV8Interceptor` 模块的指针。
     - `GumV8JSCallListener`:  继承自 `GumV8InvocationListener`，并包含指向 JavaScript `Function` 对象的全局句柄 (`on_enter`, `on_leave`)，这些函数将在拦截到目标函数调用时执行。
     - `GumV8JSProbeListener`: 继承自 `GumV8InvocationListener`，并包含指向 JavaScript `Function` 对象的全局句柄 (`on_hit`)，当执行到探针位置时执行。
     - `GumV8CCallListener`: 继承自 `GumV8InvocationListener`，并包含 C 函数指针 (`on_enter`, `on_leave`)，当拦截到目标函数调用时执行。
     - `GumV8CProbeListener`: 继承自 `GumV8InvocationListener`，并包含 C 函数指针 (`on_hit`)，当执行到探针位置时执行。

3. **定义调用上下文和参数/返回值的数据结构:**
   - `GumV8InvocationState`:  用于存储单次函数调用过程中的状态信息。
   - `GumV8InvocationArgs`: 用于存储传递给被拦截函数的参数。它包含一个指向 V8 `Object` 的全局句柄，该对象在 JavaScript 中表示参数数组，以及一个指向 Frida 核心的 `GumInvocationContext` 的指针。
   - `GumV8InvocationReturnValue`: 用于存储被拦截函数的返回值。类似于 `GumV8InvocationArgs`，它包含一个指向 V8 `Object` 的全局句柄和一个指向 `GumInvocationContext` 的指针。

4. **定义替换条目的数据结构:**
   - `GumV8ReplaceEntry`: 用于记录函数替换的信息，包括指向 Frida 核心的 `GumInterceptor` 的指针、被替换的目标函数地址 (`target`) 和指向替换函数的 V8 `Value` 的全局句柄 (`replacement`)。

5. **声明与 JavaScript 交互的函数:**
   - 使用 `GUMJS_DECLARE_FUNCTION` 宏声明了一系列将在 JavaScript 中暴露的函数，例如：
     - `gumjs_interceptor_attach`: 用于将拦截器附加到目标函数。
     - `gumjs_interceptor_detach_all`: 用于移除所有拦截器。
     - `gumjs_interceptor_replace`: 用于替换目标函数的实现。
     - `gumjs_interceptor_revert`: 用于恢复被替换的函数。
     - `gumjs_interceptor_flush`: 用于刷新拦截器缓存。
     - `gumjs_invocation_listener_detach`: 用于移除特定的拦截器。
   - 这些声明是 Frida JavaScript 绑定的一部分，使得用户可以在 JavaScript 中调用这些 C++ 函数来控制拦截行为。

**与逆向方法的关系：**

这段代码是 Frida 实现动态 instrumentation 的核心部分，与逆向工程方法紧密相关。

* **代码注入和Hooking:** `gumv8interceptor.cpp` 提供了在运行时修改程序行为的能力。通过 `attach` 函数，可以将自定义的代码（JavaScript 或 C/C++ 回调）注入到目标进程的执行流程中，在目标函数执行前后或在指定位置执行。这是一种典型的 Hooking 技术，常用于逆向分析以监控函数调用、修改参数或返回值，甚至完全替换函数行为。

   **举例说明:**  逆向工程师可以使用 Frida JavaScript API 调用 `Interceptor.attach()` 来 hook Android 系统库 `libc.so` 中的 `open` 函数。通过 `onEnter` 回调，可以记录下每次 `open` 调用时打开的文件路径和标志。

   ```javascript
   Interceptor.attach(Module.findExportByName('libc.so', 'open'), {
     onEnter: function (args) {
       console.log("Opening file:", args[0].readUtf8String());
     }
   });
   ```

* **动态分析:**  这段代码支持动态地观察和修改程序行为，而不是静态地分析代码。这对于理解混淆代码、反调试机制或运行时生成的代码非常有用。

   **举例说明:** 逆向工程师可以使用 Frida 的 `Interceptor.replace()` 来替换某个关键的加密算法函数，以便在不理解算法细节的情况下绕过加密或提取加密密钥。

* **运行时修改:**  `Interceptor.replace()` 允许在运行时完全替换函数的实现。这在漏洞利用开发、破解或修改程序行为时非常有用。

   **举例说明:**  在 Android 应用程序逆向中，可以使用 `Interceptor.replace()` 来替换应用程序中的身份验证函数，使其始终返回“已认证”，从而绕过登录验证。

**涉及的二进制底层、Linux、Android 内核及框架的知识：**

* **二进制底层:**
    - **函数地址 (`gpointer target`)**:  `attach` 和 `replace` 等函数需要指定目标函数的内存地址。这需要理解目标进程的内存布局和如何找到函数的入口地址（例如，通过符号表）。
    - **C 函数指针 (`GumV8CHook on_enter`, `on_leave`, `on_hit`)**:  对于 C/C++ Hooking，需要使用函数指针来指向回调函数。这需要理解 C/C++ 的函数调用约定和指针操作。
    - **内存管理 (`g_slice_new`, `g_slice_free`)**: 代码使用了 GLib 的内存管理函数，这涉及到对内存分配和释放的理解。
    - **调用约定**:  Frida 的底层需要处理不同平台的调用约定，以便正确地传递参数和获取返回值。

* **Linux:**
    - **进程间通信 (Implicit):**  Frida 通过某种形式的进程间通信（通常是调试接口或共享内存）来与目标进程交互。虽然这段代码没有直接展示 IPC 的实现，但它是 Frida 工作的基础。
    - **动态链接库 (`.so` 文件):**  在 Android 和 Linux 环境中，目标函数通常位于动态链接库中。需要了解如何加载和查找这些库中的符号。

* **Android 内核及框架:**
    - **ART/Dalvik 虚拟机 (Implicit):**  对于 Android 应用程序，Frida 能够 hook Java 代码，这涉及到与 Android 运行时环境（ART 或 Dalvik）的交互。虽然这段 C++ 代码主要处理的是 Gum (Frida 的核心) 和 V8 (JavaScript 引擎) 的桥接，但底层的 Gum 库会处理与 ART/Dalvik 的交互。
    - **系统调用 (Implicit):**  一些底层的 Hooking 技术可能涉及到拦截系统调用。

**逻辑推理：**

* **假设输入:**  一个 JavaScript Frida 脚本尝试 hook  `libc.so` 中的 `malloc` 函数。脚本提供了目标函数的地址（通过 `Module.findExportByName('libc.so', 'malloc')` 获取）和一个 JavaScript 回调函数，该回调函数在 `malloc` 函数执行前打印分配的大小。

* **输出:** 当目标程序调用 `malloc` 时，`gumjs_interceptor_attach` 函数会被调用，创建一个 `GumV8JSCallListener` 对象来存储回调函数。Frida 的底层机制会将该监听器与 `malloc` 函数的地址关联起来。在 `malloc` 执行前，JavaScript 回调函数会被执行，将分配的大小打印到 Frida 控制台。

**用户或编程常见的使用错误：**

* **目标地址错误:** 用户可能提供了错误的函数地址，导致 Frida 无法找到目标函数并抛出异常或无法建立 Hook。
   **举例说明:**  在 JavaScript 中使用错误的模块名或函数名，例如 `Module.findExportByName('libcc.so', 'malloc')` (拼写错误)。

* **回调函数签名不匹配:**  用户提供的 JavaScript 或 C++ 回调函数的参数与目标函数的参数不匹配，可能导致运行时错误或崩溃。
   **举例说明:**  Hook 一个接受两个参数的函数，但提供的 `onEnter` 回调函数只期望一个参数。

* **重复附加拦截器:** 用户可能多次尝试附加同一个拦截器到同一个目标地址，可能导致意外行为。Frida 通常会检测到这种情况并抛出异常，如代码中 `GUM_ATTACH_ALREADY_ATTACHED` 所示。

* **资源泄漏 (C++ 回调):**  如果使用 C++ 回调，用户需要在 `onEnter` 或 `onLeave` 中正确管理分配的资源，否则可能导致内存泄漏。

* **在不安全的时间点操作内存:**  在回调函数中，用户需要小心操作目标进程的内存，避免访问无效地址或导致程序崩溃。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **编写 Frida 脚本:** 用户首先编写一个 Frida JavaScript 脚本，使用 `Interceptor` 模块的 API 来进行 Hooking 或替换操作。例如：
   ```javascript
   // attach to a function
   Interceptor.attach(Module.findExportByName(null, 'MessageBoxW'), {
     onEnter: function (args) {
       console.log("MessageBoxW called!");
     }
   });

   // replace a function
   Interceptor.replace(Module.findExportByName(null, 'strlen'), function (str) {
     console.log("strlen called with:", Memory.readUtf8String(str));
     return 0; // Always return 0
   });
   ```

2. **运行 Frida:** 用户使用 Frida 命令行工具或 API 将脚本加载到目标进程中。例如：
   ```bash
   frida -p <process_id> -l script.js
   ```

3. **Frida JavaScript 引擎执行脚本:** Frida 的 JavaScript 引擎（基于 V8）会解析并执行用户编写的脚本。

4. **调用 `Interceptor` API:** 当脚本执行到 `Interceptor.attach()` 或 `Interceptor.replace()` 等语句时，V8 引擎会调用相应的 C++ 函数，这些函数在 `gumv8interceptor.cpp` 中定义并暴露给 JavaScript。

5. **`gumv8interceptor.cpp` 中的函数被调用:** 例如，如果执行 `Interceptor.attach(...)`，则 `gumjs_interceptor_attach` 函数会被调用。这个函数会解析 JavaScript 传递的参数（目标地址、回调函数等），创建相应的监听器对象（如 `GumV8JSCallListener`），并调用 Frida 核心库 (`gum_interceptor_attach`) 来实际设置 Hook。

6. **Frida 核心库 (`libgum`) 进行底层操作:**  `gum_interceptor_attach` 函数会进行更底层的操作，例如在目标进程中分配内存、修改目标函数的指令等，来实现 Hooking。

**作为调试线索:** 当 Frida 脚本出现问题时，了解用户操作如何到达 `gumv8interceptor.cpp` 可以帮助定位问题：

* **查看 Frida 脚本中的 `Interceptor` 调用:** 检查脚本中 `Interceptor.attach`、`Interceptor.replace` 等调用的参数是否正确，例如目标地址是否有效，回调函数是否定义正确。
* **使用 Frida 的 `console.log` 输出:**  在 JavaScript 回调函数中添加 `console.log` 语句，可以跟踪脚本的执行流程和参数值。
* **检查 Frida 的错误信息:** Frida 通常会提供详细的错误信息，例如 Hooking 失败的原因（地址无效、权限不足等）。
* **阅读 `gumv8interceptor.cpp` 代码:**  了解 C++ 层的实现细节可以帮助理解 Frida 的内部工作原理，从而更好地调试复杂的问题。例如，如果看到 `GUM_ATTACH_WRONG_SIGNATURE` 错误，可以知道问题可能出在回调函数的签名与目标函数不匹配。

**第1部分功能归纳:**

`gumv8interceptor.cpp` 的第一部分主要负责定义 Frida 中拦截器的核心数据结构和 JavaScript 绑定接口。它定义了不同类型的拦截器监听器，用于处理 JavaScript 和 C/C++ 的函数调用和探针，并声明了用于在 JavaScript 中控制拦截行为的 C++ 函数。这部分代码是 Frida 实现动态 instrumentation 的基础，允许用户通过 JavaScript 脚本来监控和修改目标程序的执行流程。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8interceptor.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8interceptor.h"

#include "gumv8macros.h"
#include "gumv8scope.h"

#include <errno.h>

#define GUMJS_MODULE_NAME Interceptor

#define GUM_V8_TYPE_INVOCATION_LISTENER (gum_v8_invocation_listener_get_type ())
#define GUM_V8_TYPE_JS_CALL_LISTENER (gum_v8_js_call_listener_get_type ())
#define GUM_V8_TYPE_JS_PROBE_LISTENER (gum_v8_js_probe_listener_get_type ())
#define GUM_V8_TYPE_C_CALL_LISTENER (gum_v8_c_call_listener_get_type ())
#define GUM_V8_TYPE_C_PROBE_LISTENER (gum_v8_c_probe_listener_get_type ())

#define GUM_V8_INVOCATION_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_V8_TYPE_INVOCATION_LISTENER, \
        GumV8InvocationListener)
#define GUM_V8_JS_CALL_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_V8_TYPE_JS_CALL_LISTENER, \
        GumV8JSCallListener)
#define GUM_V8_JS_PROBE_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_V8_TYPE_JS_PROBE_LISTENER, \
        GumV8JSProbeListener)
#define GUM_V8_C_CALL_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_V8_TYPE_C_CALL_LISTENER, \
        GumV8CCallListener)
#define GUM_V8_C_PROBE_LISTENER(obj) \
    G_TYPE_CHECK_INSTANCE_CAST (obj, GUM_V8_TYPE_C_PROBE_LISTENER, \
        GumV8CProbeListener)

#define GUM_V8_INVOCATION_LISTENER_CAST(obj) ((GumV8InvocationListener *) (obj))
#define GUM_V8_JS_CALL_LISTENER_CAST(obj) ((GumV8JSCallListener *) (obj))
#define GUM_V8_JS_PROBE_LISTENER_CAST(obj) ((GumV8JSProbeListener *) (obj))
#define GUM_V8_C_CALL_LISTENER_CAST(obj) ((GumV8CCallListener *) (obj))
#define GUM_V8_C_PROBE_LISTENER_CAST(obj) ((GumV8CProbeListener *) (obj))

using namespace v8;

typedef void (* GumV8CHook) (GumInvocationContext * ic);

struct GumV8InvocationListener
{
  GObject object;

  Global<Object> * resource;

  GumV8Interceptor * module;
};

struct GumV8InvocationListenerClass
{
  GObjectClass object_class;
};

struct GumV8JSCallListener
{
  GumV8InvocationListener listener;

  Global<Function> * on_enter;
  Global<Function> * on_leave;
};

struct GumV8JSCallListenerClass
{
  GumV8InvocationListenerClass listener_class;
};

struct GumV8JSProbeListener
{
  GumV8InvocationListener listener;

  Global<Function> * on_hit;
};

struct GumV8JSProbeListenerClass
{
  GumV8InvocationListenerClass listener_class;
};

struct GumV8CCallListener
{
  GumV8InvocationListener listener;

  GumV8CHook on_enter;
  GumV8CHook on_leave;
};

struct GumV8CCallListenerClass
{
  GumV8InvocationListenerClass listener_class;
};

struct GumV8CProbeListener
{
  GumV8InvocationListener listener;

  GumV8CHook on_hit;
};

struct GumV8CProbeListenerClass
{
  GumV8InvocationListenerClass listener_class;
};

struct GumV8InvocationState
{
  GumV8InvocationContext * jic;
};

struct GumV8InvocationArgs
{
  Global<Object> * object;
  GumInvocationContext * ic;

  GumV8Interceptor * module;
};

struct GumV8InvocationReturnValue
{
  Global<Object> * object;
  GumInvocationContext * ic;

  GumV8Interceptor * module;
};

struct GumV8ReplaceEntry
{
  GumInterceptor * interceptor;
  gpointer target;
  Global<Value> * replacement;
};

static gboolean gum_v8_interceptor_on_flush_timer_tick (
    GumV8Interceptor * self);

GUMJS_DECLARE_FUNCTION (gumjs_interceptor_attach)
static void gum_v8_invocation_listener_destroy (
    GumV8InvocationListener * listener);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_detach_all)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_replace)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_replace_fast)
static void gum_v8_handle_replace_ret (GumV8Interceptor * self,
    gpointer target, Local<Value> replacement_value,
    GumReplaceReturn replace_ret);
static void gum_v8_replace_entry_free (GumV8ReplaceEntry * entry);
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_revert)
GUMJS_DECLARE_FUNCTION (gumjs_interceptor_flush)

GUMJS_DECLARE_FUNCTION (gumjs_invocation_listener_detach)
static void gum_v8_invocation_listener_dispose (GObject * object);
static void gum_v8_invocation_listener_release_resource (
    GumV8InvocationListener * self);
G_DEFINE_TYPE_EXTENDED (GumV8InvocationListener,
                        gum_v8_invocation_listener,
                        G_TYPE_OBJECT,
                        G_TYPE_FLAG_ABSTRACT,
                        {})

static void gum_v8_js_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_js_call_listener_dispose (GObject * object);
static void gum_v8_js_call_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
static void gum_v8_js_call_listener_on_leave (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumV8JSCallListener,
                        gum_v8_js_call_listener,
                        GUM_V8_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_v8_js_call_listener_iface_init))

static void gum_v8_js_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_js_probe_listener_dispose (GObject * object);
static void gum_v8_js_probe_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumV8JSProbeListener,
                        gum_v8_js_probe_listener,
                        GUM_V8_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_v8_js_probe_listener_iface_init))

static void gum_v8_c_call_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_c_call_listener_dispose (GObject * object);
static void gum_v8_c_call_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
static void gum_v8_c_call_listener_on_leave (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumV8CCallListener,
                        gum_v8_c_call_listener,
                        GUM_V8_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_v8_c_call_listener_iface_init))

static void gum_v8_c_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_c_probe_listener_dispose (GObject * object);
static void gum_v8_c_probe_listener_on_enter (
    GumInvocationListener * listener, GumInvocationContext * ic);
G_DEFINE_TYPE_EXTENDED (GumV8CProbeListener,
                        gum_v8_c_probe_listener,
                        GUM_V8_TYPE_INVOCATION_LISTENER,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_v8_c_probe_listener_iface_init))

static GumV8InvocationContext * gum_v8_invocation_context_new_persistent (
    GumV8Interceptor * parent);
static void gum_v8_invocation_context_release_persistent (
    GumV8InvocationContext * self);
static void gum_v8_invocation_context_on_weak_notify (
    const WeakCallbackInfo<GumV8InvocationContext> & info);
static void gum_v8_invocation_context_free (GumV8InvocationContext * self);
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_invocation_context_set_system_error)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_thread_id)
GUMJS_DECLARE_GETTER (gumjs_invocation_context_get_depth)
static void gumjs_invocation_context_set_property (Local<Name> property,
    Local<Value> value, const PropertyCallbackInfo<Value> & info);

static GumV8InvocationArgs * gum_v8_invocation_args_new_persistent (
    GumV8Interceptor * parent);
static void gum_v8_invocation_args_release_persistent (
    GumV8InvocationArgs * self);
static void gum_v8_invocation_args_on_weak_notify (
    const WeakCallbackInfo<GumV8InvocationArgs> & info);
static void gum_v8_invocation_args_free (GumV8InvocationArgs * self);
static void gum_v8_invocation_args_reset (GumV8InvocationArgs * self,
    GumInvocationContext * ic);
static void gumjs_invocation_args_get_nth (uint32_t index,
    const PropertyCallbackInfo<Value> & info);
static void gumjs_invocation_args_set_nth (uint32_t index,
    Local<Value> value, const PropertyCallbackInfo<Value> & info);

static GumV8InvocationReturnValue *
    gum_v8_invocation_return_value_new_persistent (GumV8Interceptor * parent);
static void gum_v8_invocation_return_value_release_persistent (
    GumV8InvocationReturnValue * self);
static void gum_v8_invocation_return_value_on_weak_notify (
    const WeakCallbackInfo<GumV8InvocationReturnValue> & info);
static void gum_v8_invocation_return_value_free (
    GumV8InvocationReturnValue * self);
static void gum_v8_invocation_return_value_reset (
    GumV8InvocationReturnValue * self, GumInvocationContext * ic);
GUMJS_DECLARE_FUNCTION (gumjs_invocation_return_value_replace)

static GumV8InvocationArgs * gum_v8_interceptor_obtain_invocation_args (
    GumV8Interceptor * self);
static void gum_v8_interceptor_release_invocation_args (GumV8Interceptor * self,
    GumV8InvocationArgs * args);
static GumV8InvocationReturnValue *
    gum_v8_interceptor_obtain_invocation_return_value (GumV8Interceptor * self);
static void gum_v8_interceptor_release_invocation_return_value (
    GumV8Interceptor * self, GumV8InvocationReturnValue * retval);

static const GumV8Function gumjs_interceptor_functions[] =
{
  { "_attach", gumjs_interceptor_attach },
  { "detachAll", gumjs_interceptor_detach_all },
  { "_replace", gumjs_interceptor_replace },
  { "_replaceFast", gumjs_interceptor_replace_fast },
  { "revert", gumjs_interceptor_revert },
  { "flush", gumjs_interceptor_flush },

  { NULL, NULL }
};

static const GumV8Function gumjs_invocation_listener_functions[] =
{
  { "detach", gumjs_invocation_listener_detach },

  { NULL, NULL }
};

static const GumV8Property gumjs_invocation_context_values[] =
{
  {
    "returnAddress",
    gumjs_invocation_context_get_return_address,
    NULL
  },
  {
    "context",
    gumjs_invocation_context_get_cpu_context,
    NULL
  },
  {
    GUMJS_SYSTEM_ERROR_FIELD,
    gumjs_invocation_context_get_system_error,
    gumjs_invocation_context_set_system_error
  },
  {
    "threadId",
    gumjs_invocation_context_get_thread_id,
    NULL
  },
  {
    "depth",
    gumjs_invocation_context_get_depth,
    NULL
  },

  { NULL, NULL, NULL }
};

static const GumV8Function gumjs_invocation_return_value_functions[] =
{
  { "replace", gumjs_invocation_return_value_replace },

  { NULL, NULL }
};

void
_gum_v8_interceptor_init (GumV8Interceptor * self,
                          GumV8Core * core,
                          Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  self->interceptor = gum_interceptor_obtain ();

  self->invocation_listeners = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_invocation_listener_destroy);
  self->invocation_context_values = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_invocation_context_free);
  self->invocation_args_values = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_invocation_args_free);
  self->invocation_return_values = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_invocation_return_value_free);
  self->replacement_by_address = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_v8_replace_entry_free);
  self->flush_timer = NULL;

  auto module = External::New (isolate, self);

  auto interceptor = _gum_v8_create_module ("Interceptor", scope, isolate);
  _gum_v8_module_add (module, interceptor, gumjs_interceptor_functions,
      isolate);

  auto listener = _gum_v8_create_class ("InvocationListener", nullptr, scope,
      module, isolate);
  _gum_v8_class_add (listener, gumjs_invocation_listener_functions, module,
      isolate);
  self->invocation_listener = new Global<FunctionTemplate> (isolate, listener);

  auto ic = _gum_v8_create_class ("InvocationContext", nullptr, scope,
      module, isolate);
  _gum_v8_class_add (ic, gumjs_invocation_context_values, module, isolate);
  NamedPropertyHandlerConfiguration ic_access;
  ic_access.setter = gumjs_invocation_context_set_property;
  ic_access.data = module;
  ic_access.flags = PropertyHandlerFlags::kNonMasking;
  ic->InstanceTemplate ()->SetHandler (ic_access);
  self->invocation_context = new Global<FunctionTemplate> (isolate, ic);

  auto ia = _gum_v8_create_class ("InvocationArgs", nullptr, scope, module,
      isolate);
  ia->InstanceTemplate ()->SetIndexedPropertyHandler (
      gumjs_invocation_args_get_nth, gumjs_invocation_args_set_nth, nullptr,
      nullptr, nullptr, module);
  self->invocation_args = new Global<FunctionTemplate> (isolate, ia);

  auto ir = _gum_v8_create_class ("InvocationReturnValue", nullptr, scope,
      module, isolate);
  auto native_pointer = Local<FunctionTemplate>::New (isolate,
      *core->native_pointer);
  ir->Inherit (native_pointer);
  _gum_v8_class_add (ir, gumjs_invocation_return_value_functions, module,
      isolate);
  ir->InstanceTemplate ()->SetInternalFieldCount (2);
  self->invocation_return = new Global<FunctionTemplate> (isolate, ir);
}

void
_gum_v8_interceptor_realize (GumV8Interceptor * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto listener = Local<FunctionTemplate>::New (isolate,
      *self->invocation_listener);
  auto listener_value = listener->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->invocation_listener_value =
      new Global<Object> (isolate, listener_value);

  auto ic = Local<FunctionTemplate>::New (isolate, *self->invocation_context);
  auto ic_value = ic->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->invocation_context_value = new Global<Object> (isolate, ic_value);

  auto ia = Local<FunctionTemplate>::New (isolate, *self->invocation_args);
  auto ia_value = ia->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->invocation_args_value = new Global<Object> (isolate, ia_value);

  auto ir = Local<FunctionTemplate>::New (isolate, *self->invocation_return);
  auto ir_value = ir->GetFunction (context).ToLocalChecked ()
      ->NewInstance (context, 0, nullptr).ToLocalChecked ();
  self->invocation_return_value = new Global<Object> (isolate, ir_value);

  self->cached_invocation_context =
      gum_v8_invocation_context_new_persistent (self);
  self->cached_invocation_context_in_use = FALSE;

  self->cached_invocation_args =
      gum_v8_invocation_args_new_persistent (self);
  self->cached_invocation_args_in_use = FALSE;

  self->cached_invocation_return_value =
      gum_v8_invocation_return_value_new_persistent (self);
  self->cached_invocation_return_value_in_use = FALSE;
}

void
_gum_v8_interceptor_flush (GumV8Interceptor * self)
{
  auto core = self->core;
  gboolean flushed;

  g_hash_table_remove_all (self->invocation_listeners);
  g_hash_table_remove_all (self->replacement_by_address);

  {
    ScriptUnlocker unlocker (core);

    flushed = gum_interceptor_flush (self->interceptor);
  }

  if (!flushed && self->flush_timer == NULL)
  {
    auto source = g_timeout_source_new (10);
    g_source_set_callback (source,
        (GSourceFunc) gum_v8_interceptor_on_flush_timer_tick, self, NULL);
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

static gboolean
gum_v8_interceptor_on_flush_timer_tick (GumV8Interceptor * self)
{
  gboolean flushed = gum_interceptor_flush (self->interceptor);
  if (flushed)
  {
    GumV8Core * core = self->core;

    ScriptScope scope (core->script);
    _gum_v8_core_unpin (core);
    self->flush_timer = NULL;
  }

  return !flushed;
}

void
_gum_v8_interceptor_dispose (GumV8Interceptor * self)
{
  g_assert (self->flush_timer == NULL);

  gum_v8_invocation_context_release_persistent (
      self->cached_invocation_context);
  gum_v8_invocation_args_release_persistent (
      self->cached_invocation_args);
  gum_v8_invocation_return_value_release_persistent (
      self->cached_invocation_return_value);
  self->cached_invocation_context = NULL;
  self->cached_invocation_args = NULL;
  self->cached_invocation_return_value = NULL;

  delete self->invocation_return_value;
  self->invocation_return_value = nullptr;

  delete self->invocation_args_value;
  self->invocation_args_value = nullptr;

  delete self->invocation_context_value;
  self->invocation_context_value = nullptr;

  delete self->invocation_listener_value;
  self->invocation_listener_value = nullptr;

  delete self->invocation_return;
  self->invocation_return = nullptr;

  delete self->invocation_args;
  self->invocation_args = nullptr;

  delete self->invocation_context;
  self->invocation_context = nullptr;

  delete self->invocation_listener;
  self->invocation_listener = nullptr;

  g_hash_table_unref (self->invocation_context_values);
  self->invocation_context_values = NULL;

  g_hash_table_unref (self->invocation_args_values);
  self->invocation_args_values = NULL;

  g_hash_table_unref (self->invocation_return_values);
  self->invocation_return_values = NULL;
}

void
_gum_v8_interceptor_finalize (GumV8Interceptor * self)
{
  g_hash_table_unref (self->invocation_listeners);
  g_hash_table_unref (self->replacement_by_address);

  g_object_unref (self->interceptor);
  self->interceptor = NULL;
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_attach)
{
  if (info.Length () < 3)
  {
    _gum_v8_throw_ascii_literal (isolate, "missing argument");
    return;
  }

  gpointer target;
  GumV8InvocationListener * listener;
  auto target_val = info[0];
  auto callback_val = info[1];
  auto native_pointer = Local<FunctionTemplate>::New (isolate,
      *core->native_pointer);
  if (callback_val->IsFunction ())
  {
    if (!_gum_v8_native_pointer_get (target_val, &target, core))
      return;

    auto l = GUM_V8_JS_PROBE_LISTENER (
        g_object_new (GUM_V8_TYPE_JS_PROBE_LISTENER, NULL));
    l->on_hit = new Global<Function> (isolate, callback_val.As<Function> ());

    listener = GUM_V8_INVOCATION_LISTENER (l);
  }
  else if (native_pointer->HasInstance (callback_val))
  {
    if (!_gum_v8_native_pointer_get (target_val, &target, core))
      return;

    auto l = GUM_V8_C_PROBE_LISTENER (
        g_object_new (GUM_V8_TYPE_C_PROBE_LISTENER, NULL));
    l->on_hit = GUM_POINTER_TO_FUNCPTR (GumV8CHook,
        GUMJS_NATIVE_POINTER_VALUE (callback_val.As<Object> ()));

    listener = GUM_V8_INVOCATION_LISTENER (l);
  }
  else
  {
    Local<Function> on_enter_js, on_leave_js;
    GumV8CHook on_enter_c, on_leave_c;

    if (!_gum_v8_args_parse (args, "pF*{onEnter?,onLeave?}", &target,
        &on_enter_js, &on_enter_c,
        &on_leave_js, &on_leave_c))
    {
      return;
    }

    if (!on_enter_js.IsEmpty () || !on_leave_js.IsEmpty ())
    {
      auto l = GUM_V8_JS_CALL_LISTENER (
          g_object_new (GUM_V8_TYPE_JS_CALL_LISTENER, NULL));
      if (!on_enter_js.IsEmpty ())
        l->on_enter = new Global<Function> (isolate, on_enter_js);
      if (!on_leave_js.IsEmpty ())
        l->on_leave = new Global<Function> (isolate, on_leave_js);

      listener = GUM_V8_INVOCATION_LISTENER (l);
    }
    else if (on_enter_c != NULL || on_leave_c != NULL)
    {
      auto l = GUM_V8_C_CALL_LISTENER (
          g_object_new (GUM_V8_TYPE_C_CALL_LISTENER, NULL));
      l->on_enter = on_enter_c;
      l->on_leave = on_leave_c;

      listener = GUM_V8_INVOCATION_LISTENER (l);
    }
    else
    {
      _gum_v8_throw_ascii_literal (isolate, "expected at least one callback");
      return;
    }
  }

  listener->resource = new Global<Object> (isolate, callback_val.As<Object> ());
  listener->module = module;

  gpointer listener_function_data;
  auto data_val = info[2];
  if (!data_val->IsUndefined ())
  {
    if (!_gum_v8_native_pointer_get (data_val, &listener_function_data, core))
    {
      g_object_unref (listener);
      return;
    }
  }
  else
  {
    listener_function_data = NULL;
  }

  auto attach_ret = gum_interceptor_attach (module->interceptor, target,
      GUM_INVOCATION_LISTENER (listener), listener_function_data);

  if (attach_ret == GUM_ATTACH_OK)
  {
    auto listener_template_value (Local<Object>::New (isolate,
        *module->invocation_listener_value));
    auto listener_value (listener_template_value->Clone ());
    listener_value->SetAlignedPointerInInternalField (0, listener);

    g_hash_table_add (module->invocation_listeners, listener);

    info.GetReturnValue ().Set (listener_value);
  }
  else
  {
    g_object_unref (listener);
  }

  switch (attach_ret)
  {
    case GUM_ATTACH_OK:
      break;
    case GUM_ATTACH_WRONG_SIGNATURE:
    {
      _gum_v8_throw_ascii (isolate, "unable to intercept function at %p; "
          "please file a bug", target);
      break;
    }
    case GUM_ATTACH_ALREADY_ATTACHED:
      _gum_v8_throw_ascii_literal (isolate,
          "already attached to this function");
      break;
    case GUM_ATTACH_POLICY_VIOLATION:
      _gum_v8_throw_ascii_literal (isolate,
          "not permitted by code-signing policy");
      break;
    case GUM_ATTACH_WRONG_TYPE:
      _gum_v8_throw_ascii_literal (isolate, "wrong type");
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
gum_v8_invocation_listener_destroy (GumV8InvocationListener * listener)
{
  gum_interceptor_detach (listener->module->interceptor,
      GUM_INVOCATION_LISTENER (listener));
  g_object_unref (listener);
}

static void
gum_v8_interceptor_detach (GumV8Interceptor * self,
                           GumV8InvocationListener * listener)
{
  g_hash_table_remove (self->invocation_listeners, listener);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_detach_all)
{
  g_hash_table_remove_all (module->invocation_listeners);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace)
{
  gpointer target, replacement_function, replacement_data = NULL;
  if (!_gum_v8_args_parse (args, "pp|p", &target, &replacement_function,
      &replacement_data))
    return;

  auto replace_ret = gum_interceptor_replace (module->interceptor, target,
      replacement_function, replacement_data, NULL);

  gum_v8_handle_replace_ret (module, target, info[1], replace_ret);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_replace_fast)
{
  gpointer target, replacement_function, original_function;
  if (!_gum_v8_args_parse (args, "pp", &target, &replacement_function))
    return;

  auto replace_ret = gum_interceptor_replace_fast (module->interceptor, target,
      replacement_function, &original_function);

  gum_v8_handle_replace_ret (module, target, info[1], replace_ret);

  if (replace_ret == GUM_REPLACE_OK)
  {
    info.GetReturnValue ().Set (_gum_v8_native_pointer_new (
          GSIZE_TO_POINTER (original_function), core));
  }
}

static void
gum_v8_handle_replace_ret (GumV8Interceptor * self,
                           gpointer target,
                           Local<Value> replacement_value,
                           GumReplaceReturn replace_ret)
{
  GumV8Core * core = self->core;
  auto isolate = core->isolate;

  switch (replace_ret)
  {
    case GUM_REPLACE_OK:
    {
      auto entry = g_slice_new (GumV8ReplaceEntry);
      entry->interceptor = self->interceptor;
      entry->target = target;
      entry->replacement = new Global<Value> (isolate, replacement_value);

      g_hash_table_insert (self->replacement_by_address, target, entry);

      break;
    }
    case GUM_REPLACE_WRONG_SIGNATURE:
    {
      _gum_v8_throw_ascii (isolate, "unable to intercept function at %p; "
          "please file a bug", target);
      break;
    }
    case GUM_REPLACE_ALREADY_REPLACED:
      _gum_v8_throw_ascii_literal (isolate, "already replaced this function");
      break;
    case GUM_REPLACE_POLICY_VIOLATION:
      _gum_v8_throw_ascii_literal (isolate,
          "not permitted by code-signing policy");
      break;
    case GUM_REPLACE_WRONG_TYPE:
      _gum_v8_throw_ascii_literal (isolate, "wrong type");
      break;
    default:
      g_assert_not_reached ();
  }
}

static void
gum_v8_replace_entry_free (GumV8ReplaceEntry * entry)
{
  gum_interceptor_revert (entry->interceptor, entry->target);

  delete entry->replacement;

  g_slice_free (GumV8ReplaceEntry, entry);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_revert)
{
  gpointer target;
  if (!_gum_v8_args_parse (args, "p", &target))
    return;

  g_hash_table_remove (module->replacement_by_address, target);
}

GUMJS_DEFINE_FUNCTION (gumjs_interceptor_flush)
{
  auto interceptor = module->interceptor;

  gum_interceptor_end_transaction (interceptor);
  gum_interceptor_begin_transaction (interceptor);
}

GUMJS_DEFINE_CLASS_METHOD (gumjs_invocation_listener_detach,
                           GumV8InvocationListener)
{
  if (self != NULL)
  {
    wrapper->SetAlignedPointerInInternalField (0, NULL);

    gum_v8_interceptor_detach (module, self);
  }
}

static void
gum_v8_invocation_listener_class_init (GumV8InvocationListenerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_invocation_listener_dispose;
}

static void
gum_v8_invocation_listener_init (GumV8InvocationListener * self)
{
}

static void
gum_v8_invocation_listener_dispose (GObject * object)
{
  g_assert (GUM_V8_INVOCATION_LISTENER (object)->resource == nullptr);

  G_OBJECT_CLASS (gum_v8_invocation_listener_parent_class)->dispose (object);
}

static void
gum_v8_invocation_listener_release_resource (GumV8InvocationListener * self)
{
  delete self->resource;
  self->resource = nullptr;
}

static void
gum_v8_js_call_listener_class_init (GumV8JSCallListenerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_js_call_listener_dispose;
}

static void
gum_v8_js_call_listener_iface_init (gpointer g_iface,
                                    gpointer iface_data)
{
  auto iface = (GumInvocationListenerInterface *) g_iface;

  iface->on_enter = gum_v8_js_call_listener_on_enter;
  iface->on_leave = gum_v8_js_call_listener_on_leave;
}

static void
gum_v8_js_call_listener_init (GumV8JSCallListener * self)
{
}

static void
gum_v8_js_call_listener_dispose (GObject * object)
{
  auto self = GUM_V8_JS_CALL_LISTENER (object);
  auto base_listener = GUM_V8_INVOCATION_LISTENER (object);

  {
    ScriptScope scope (base_listener->module->core->script);

    delete self->on_enter;
    self->on_enter = nullptr;

    delete self->on_leave;
    self->on_leave = nullptr;

    gum_v8_invocation_listener_release_resource (base_listener);
  }

  G_OBJECT_CLASS (gum_v8_js_call_listener_parent_class)->dispose (object);
}

static void
gum_v8_js_call_listener_on_enter (GumInvocationListener * listener,
                                  GumInvocationContext * ic)
{
  auto self = GUM_V8_JS_CALL_LISTENER_CAST (listener);
  auto state = GUM_IC_GET_INVOCATION_DATA (ic, GumV8InvocationState);

  if (self->on_enter != nullptr)
  {
    auto module = GUM_V8_INVOCATION_LISTENER_CAST (listener)->module;
    auto core = module->core;
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    auto on_enter = Local<Function>::New (isolate, *self->on_enter);

    auto jic = _gum_v8_interceptor_obtain_invocation_context (module);
    _gum_v8_invocation_context_reset (jic, ic);
    auto recv = Local<Object>::New (isolate, *jic->object);

    auto args = gum_v8_interceptor_obtain_invocation_args (module);
    gum_v8_invocation_args_reset (args, ic);
    auto args_object = Local<Object>::New (isolate, *args->object);

    Local<Value> argv[] = { args_object };
    auto result = on_enter->Call (context, recv, G_N_ELEMENTS (argv), argv);
    if (result.IsEmpty ())
      scope.ProcessAnyPendingException ();

    gum_v8_invocation_args_reset (args, NULL);
    gum_v8_interceptor_release_invocation_args (module, args);

    _gum_v8_invocation_context_reset (jic, NULL);
    if (self->on_leave != nullptr || jic->dirty)
    {
      state->jic = jic;
    }
    else
    {
      _gum_v8_interceptor_release_invocation_context (module, jic);
      state->jic = NULL;
    }
  }
  else
  {
    state->jic = NULL;
  }
}

static void
gum_v8_js_call_listener_on_leave (GumInvocationListener * listener,
                                  GumInvocationContext * ic)
{
  auto self = GUM_V8_JS_CALL_LISTENER_CAST (listener);
  auto module = GUM_V8_INVOCATION_LISTENER_CAST (listener)->module;
  auto core = module->core;
  auto state = GUM_IC_GET_INVOCATION_DATA (ic, GumV8InvocationState);

  if (self->on_leave != nullptr)
  {
    ScriptScope scope (core->script);
    auto isolate = core->isolate;
    auto context = isolate->GetCurrentContext ();

    auto on_leave = Local<Function>::New (isolate, *self->on_leave);

    auto jic = (self->on_enter != nullptr) ? state->jic : NULL;
    if (jic == NULL)
    {
      jic = _gum_v8_interceptor_obtain_invocation_context (module);
    }
    _gum_v8_invocation_context_reset (jic, ic);
    auto recv = Local<Object>::New (isolate, *jic->object);

    auto retval = gum_v8_interceptor_obtain_invocation_return_value (module);
    gum_v8_invocation_return_value_reset (retval, ic);
    auto retval_object = Local<Object>::New (isolate, *retval->object);
    retval_object->SetInternalField (0, BigInt::NewFromUnsigned (isolate,
        GPOINTER_TO_SIZE (gum_invocation_context_get_return_value (ic))));

    Local<Value> argv[] = { retval_object };
    auto result = on_leave->Call (context, recv, G_N_ELEMENTS (argv), argv);
    if (result.IsEmpty ())
      scope.ProcessAnyPendingException ();

    gum_v8_invocation_return_value_reset (retval, NULL);
    gum_v8_interceptor_release_invocation_return_value (module, retval);

    _gum_v8_invocation_context_reset (jic, NULL);
    _gum_v8_interceptor_release_invocation_context (module, jic);
  }
  else if (state->jic != NULL)
  {
    ScriptScope scope (core->script);

    _gum_v8_interceptor_release_invocation_context (module, state->jic);
  }
}

static void
gum_v8_js_probe_listener_class_init (GumV8JSProbeListenerClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_v8_js_probe_listener_dispose;
}

static void
gum_v8_js_probe_listener_iface_init (gpointer g_iface,
                                     gpointer iface_data)
{
  auto iface = (GumInvocationListenerInterface *) g_iface;

  iface->on_enter = gum_v8_js_probe_listener_on_enter;
  iface->on_leave = NULL;
}

static void
gum_v8_js_probe_listener_init (GumV8JSProbeListener * self)
{
}

static void
gum_v8_js_probe_listener_dispose (GObject * object)
{
  auto self = GUM_V8_JS_PROBE_LISTENER (object);
  auto base_listener = GUM_V8_INVOCATION_LISTENER (object);

  {
    ScriptScope scope (base_listener->module->core->script);

    delete self->on_hit;
    self->on_hit = nullptr;

    gum_v8_invocation_listener_release_resource (base_listener);
  }

  G_OBJECT_CLASS (gum_v8_js_probe_listener_parent_class)->dispose (object);
}

static void
gum_v8_js_probe_listener_on_enter (GumInvocationListener * listener,
                                   GumInvocationContext * ic)
{
  auto self = GUM_V8_JS_PROBE_LISTENER_CAST (listener);
  auto module = GUM_V8_INVOCATION_LISTENER_CAST (listener)->module;
  auto core = module->core;

  ScriptScope scope (core->script);
  auto isolate = core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto on_hit = Local<Function>::New (isolate, *self->on_hit);

  auto jic = _gum_v8_interceptor_obtain_invocation_context (module);
  _gum_v8_invocation_context_reset (jic, ic);
  auto recv = Local<Object>::New (isolate, *jic->object);

  auto args = gum_v8_interceptor_obtain_invocation_args (module);
  gum_v8_invocation_args_reset (args, ic);
  auto args_object = Local<Object>::New (isolate, *args->object);

  Local<Value> argv[] = { args_object };
  auto result = on_hit->Call (context, recv, G_N_ELEMENTS (argv), argv);
  if (result.IsEmpty ())
    scope.ProcessAnyPendingException ();

  gum_v8_invocation_args_reset (args, NULL);
  gum_v8_interceptor_release_invocation_args (module, args);

  _gum_v8_invocation_context_reset (jic, NU
```