Response:
Let's break down the thought process for analyzing this C code snippet and fulfilling the request.

**1. Initial Reading and Keyword Spotting:**

The first step is to quickly read through the code, not for deep understanding initially, but to get a general sense of what it's doing. I'd be looking for keywords and patterns:

* **Includes:** `gumquickcore.h`, `gumffi.h`, `gumquickinterceptor.h`, etc. These suggest the code is part of the Frida Gum library, specifically dealing with a "quick core." The presence of "ffi" hints at foreign function interface, likely for interacting with native code.
* **Struct definitions:**  `GumQuickWeakCallback`, `GumQuickFlushCallback`, `GumQuickFFIFunction`, etc. These represent the data structures the code manipulates. The names often give clues about their purpose (e.g., "WeakCallback" for managing weak references).
* **`GUMJS_DECLARE_FUNCTION` and `GUMJS_DECLARE_GETTER/SETTER` macros:** These are strong indicators of functions exposed to the JavaScript side. The names of these functions (e.g., `gumjs_set_timeout`, `gumjs_frida_get_heap_size`) directly reveal the JavaScript API.
* **`JSClassDef` structs:**  These define the classes available in the JavaScript environment (e.g., `gumjs_weak_ref_def`, `gumjs_int64_def`). The `.finalizer` and `.call` members are important for understanding object lifecycle and method invocation.
* **`ffi_cif`, `ffi_type`:** More confirmation of foreign function interface usage.
* **CPU context structures and accessors:** The large block of `GUM_DEFINE_CPU_CONTEXT_ACCESSOR_*` macros indicates functionality for inspecting and manipulating CPU registers.
* **"weak," "flush," "module," "ffi," "scheduled," "exception," "message," "callback," "context," "pointer," "pattern," "source map," "worker":** These words appear frequently and are key concepts within the code.

**2. Grouping Functionality by Area:**

After the initial read, I'd start grouping related code sections to understand the broader functional areas:

* **JavaScript Integration:** The `GUMJS_DECLARE_*` macros and `JSClassDef` structures clearly point to the code's role in exposing native functionality to JavaScript. The function names themselves are the API.
* **Foreign Function Interface (FFI):**  The presence of `gumffi.h`, `ffi_cif`, `ffi_type`, and functions like `gumjs_native_function_construct` and `gumjs_system_function_construct` signals the core's ability to call native functions from JavaScript and vice-versa.
* **Callbacks and Event Handling:** Structures like `GumQuickWeakCallback`, `GumQuickScheduledCallback`, `GumQuickExceptionSink`, and `GumQuickMessageSink`, along with functions like `gumjs_set_timeout` and `gumjs_send`, indicate mechanisms for asynchronous operations and communication between the native and JavaScript sides.
* **Memory Management and Weak References:**  The `GumQuickWeakRef` structure and associated functions like `gumjs_script_bind_weak` and `gumjs_weak_ref_finalize` deal with managing object lifecycles and preventing memory leaks.
* **CPU Context Inspection/Manipulation:** The extensive `GUM_DEFINE_CPU_CONTEXT_ACCESSOR_*` macros demonstrate the ability to access and modify CPU registers, crucial for dynamic instrumentation.
* **Source Maps:** The functions related to source maps (`gumjs_script_register_source_map`, `gumjs_script_find_source_map`) show support for mapping back from generated code to the original source.
* **Workers (Multithreading/Concurrency):** The `GumQuickWorker` structure and associated functions suggest support for running JavaScript code in separate threads.
* **Data Type Wrappers:** The definitions for `Int64`, `UInt64`, and `NativePointer` classes indicate the core handles these fundamental data types in the JavaScript environment.

**3. Connecting to Reverse Engineering Concepts:**

Now, I'd think about how these functional areas relate to reverse engineering:

* **Dynamic Instrumentation (Core Concept):** The entire file is about enabling dynamic instrumentation. The ability to intercept function calls (`gumquickinterceptor.h`), modify behavior, and inspect the CPU state are fundamental.
* **Interception/Hooking:** The FFI functionality allows intercepting calls to native functions. The `NativeFunction` and `SystemFunction` classes are likely used to create hooks.
* **Code Injection:** Evaluating and loading scripts (`gumjs_script_evaluate`, `gumjs_script_load`) allows injecting custom logic into the target process.
* **Memory Inspection and Manipulation:** The `NativePointer` class provides a way to work with memory addresses. The CPU context accessors allow examining register values.
* **Understanding Program Flow:**  The stalker (`gumquickstalker.h`, not directly in this snippet but related) helps trace program execution. The ability to set timeouts and intervals allows for timed execution of scripts.
* **Debugging:**  Source maps aid in debugging injected scripts. The unhandled exception and message callbacks provide mechanisms for error reporting and communication.

**4. Inferring Underlying Mechanisms (Binary, Linux, Android):**

Based on the functionality and the Frida context, I can infer some underlying details:

* **Binary Level:**  The FFI directly deals with function pointers and calling conventions at the binary level. Manipulating CPU contexts requires knowledge of the target architecture's registers and instruction set.
* **Linux/Android:** While not explicitly OS-specific in *this* file, the presence of concepts like processes, threads, and system calls (implied by "SystemFunction") suggests a Linux-like environment. Frida is commonly used on these platforms. The inclusion of Java and Objective-C bridges points towards Android and iOS respectively.
* **Kernel Interaction (Less Direct Here):** While this file doesn't directly interact with the kernel, other parts of Frida (and potentially modules loaded through this code) might use system calls for lower-level instrumentation.

**5. Logical Reasoning and Input/Output (Hypothetical):**

For logical reasoning, I'd focus on specific functions:

* **`gumjs_int64_add`:** *Input:* Two JavaScript `Int64` objects. *Output:* A new JavaScript `Int64` object representing their sum.
* **`gumjs_native_pointer_add`:** *Input:* A JavaScript `NativePointer` object and a number (offset). *Output:* A new `NativePointer` object pointing to the original address plus the offset.
* **`gumjs_set_timeout`:** *Input:* A JavaScript function and a delay (in milliseconds). *Output:* A timer ID.

**6. User Errors:**

I'd think about common mistakes developers might make when using this API:

* **Incorrect data types in FFI calls:**  Passing a string where an integer is expected, leading to crashes or unexpected behavior.
* **Memory management issues:**  Not unbinding weak references, leading to memory leaks. Incorrectly wrapping/unwrapping ArrayBuffers.
* **Incorrect pointer arithmetic:**  Adding or subtracting the wrong offsets from `NativePointer` objects, leading to accessing invalid memory.
* **Conflicting scheduling behaviors:** Using exclusive scheduling in multiple callbacks, potentially leading to deadlocks.
* **Not handling exceptions:**  Relying on default exception propagation, which might not be desired in all scenarios.

**7. Tracing User Actions (Debugging Clues):**

To understand how a user reaches this code, I'd consider the typical Frida workflow:

1. **Write a Frida script (JavaScript).**
2. **Use the Frida client (command-line tool or Python library) to inject the script into a target process.**
3. **The JavaScript code in the script interacts with the Frida API, which is backed by the C++ and C code.**

Specifically for this `gumquickcore.c` file, user actions would involve:

* Calling functions like `setTimeout`, `setInterval`, `send`, `recv`.
* Using the `Frida` global object to access properties like `version` or call methods like `loadObjC`, `loadSwift`, `loadJava`.
* Interacting with the `Script` object (evaluating, loading, pinning, etc.).
* Creating and manipulating `Int64`, `UInt64`, and `NativePointer` objects.
* Using `NativeFunction` and `SystemFunction` to hook native code.
* Accessing the `context` object within a hook to inspect CPU registers.

**8. Summarizing Functionality (For the Final归纳):**

Finally, I'd synthesize all the above points into a concise summary of the file's purpose. This involves identifying the core responsibilities and the key features it provides.

This iterative process of reading, grouping, connecting, inferring, and reasoning allows for a comprehensive understanding of the code's functionality and its role within the larger Frida ecosystem.
好的，让我们来分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumquickcore.c` 这个文件的功能。

**核心功能归纳：**

`gumquickcore.c` 是 Frida 中 Gum 库的 JavaScript 绑定层核心文件。它的主要职责是：**构建和管理一个 JavaScript 运行环境 (QuickJS) 的核心，并将 Frida Gum 库的底层功能以 JavaScript API 的形式暴露出来，供 Frida 脚本使用。**  它负责 JavaScript 和 Native (C/C++) 代码之间的桥梁，使得 JavaScript 脚本能够控制和操作目标进程的运行时行为。

**具体功能分解及举例说明：**

1. **JavaScript 运行时环境管理:**
   - 它负责初始化和维护一个 QuickJS 引擎实例，作为 Frida 脚本的执行环境。
   - 它定义了全局对象和内置函数，使得 JavaScript 脚本能够进行基本的操作，例如定时器 (`setTimeout`, `setInterval`)、垃圾回收 (`gc`)、以及发送消息 (`send`).
   - **举例 (与逆向方法的关系):**  逆向工程师在编写 Frida 脚本时，可以直接使用 `setTimeout` 来延迟执行某些操作，例如等待目标进程完成特定的初始化后再进行 hook。

2. **Frida Gum 核心功能的 JavaScript 绑定:**
   - 它将 Frida Gum 库中的核心组件（如 Interceptor, Stalker 等）的功能封装成 JavaScript 对象和方法。
   - 这使得 JavaScript 脚本能够使用 Frida 的强大功能，例如：
     - **代码插桩 (Instrumentation):** 通过 `Interceptor` 拦截和修改函数调用。
     - **代码跟踪 (Tracing):** 通过 `Stalker` 跟踪代码执行路径。
     - **内存操作:**  创建和操作 `NativePointer` 对象来读写目标进程的内存。
     - **调用 Native 函数 (FFI - Foreign Function Interface):**  通过 `NativeFunction` 和 `SystemFunction` 调用目标进程中的原生函数。
   - **举例 (与逆向方法的关系):**
     - 使用 `Interceptor.attach(address, { onEnter: function(args) { ... }, onLeave: function(retval) { ... } })` 可以 hook 目标进程中指定地址的函数，查看参数 (`args`) 和返回值 (`retval`)，或者修改它们的行为。
     - 使用 `Stalker.follow(...)` 可以跟踪目标进程的执行流程，帮助理解程序的运行逻辑。
     - 使用 `new NativePointer(address)` 创建一个指向目标进程内存的指针，并使用其方法读写内存数据。
     - 使用 `new NativeFunction(address, returnType, argTypes)` 创建一个 JavaScript 函数，可以调用目标进程中指定地址的 native 函数。

3. **数据类型转换和表示:**
   - 它定义了 JavaScript 中表示 Native 数据类型的类，例如 `Int64`, `UInt64`, `NativePointer`。
   - 提供了这些类型之间的转换方法，以及与 JavaScript 标准类型的转换。
   - **举例 (涉及到二进制底层知识):**  目标进程中的内存地址通常是 64 位的，`NativePointer` 类就是用来在 JavaScript 中安全地表示和操作这些地址的。  `Int64` 和 `UInt64` 用于处理 64 位整数，这在处理底层数据结构时非常常见。

4. **异常处理和消息传递:**
   - 提供了机制来处理 JavaScript 脚本中发生的未捕获异常，并将异常信息传递给 Frida 客户端。
   - 允许 JavaScript 脚本向 Frida 客户端发送消息 (`send`)，以及接收来自客户端的消息。
   - **举例 (涉及到 Linux, Android 内核及框架的知识):**  在 Android 逆向中，如果 hook 了系统框架的某个方法并导致崩溃，Frida 可以捕获这个异常并将堆栈信息等发送给逆向工程师进行分析。

5. **弱引用管理:**
   - 提供了 `WeakRef` 类以及相关的 `bindWeak`, `unbindWeak`, `derefWeak` 函数，用于管理 JavaScript 对象的弱引用，防止内存泄漏。
   - **举例 (涉及到二进制底层知识和内存管理):** 当 JavaScript 对象引用了目标进程中的某些资源时，使用弱引用可以避免 JavaScript 对象的生命周期影响到这些资源的生命周期，防止资源无法被及时释放。

6. **全局对象访问控制:**
   - 提供了设置全局访问处理器的功能 (`setGlobalAccessHandler`)，允许自定义 JavaScript 代码访问全局变量时的行为。
   - **举例 (与逆向方法的关系):**  可以用来监控或修改 JavaScript 脚本对全局变量的访问。

7. **CPU 上下文访问:**
   - 提供了 `CpuContext` 类，允许 JavaScript 脚本访问和修改目标进程的 CPU 寄存器状态。
   - **举例 (涉及到二进制底层, Linux, Android 内核及框架的知识):** 在 hook 函数的 `onEnter` 或 `onLeave` 回调中，可以通过 `this.context` 访问 `CpuContext` 对象，读取例如指令指针 (`rip`/`eip`/`pc`)、栈指针 (`rsp`/`esp`/`sp`) 等寄存器的值，进行更深入的分析，例如检查函数的调用来源或者参数传递的方式。在 Android 逆向中，可以用来分析 ART 虚拟机内部的运行状态。

8. **Source Map 支持:**
   - 提供了注册和查找 Source Map 的功能，用于在调试由高级语言编译或转换而来的 JavaScript 代码时，能够映射回原始代码。
   - **举例 (与逆向方法的关系):** 如果 Frida 脚本是由 TypeScript 或其他语言编译而来，Source Map 可以帮助逆向工程师在调试时查看原始的 TypeScript 代码，而不是编译后的 JavaScript 代码。

9. **Worker 支持:**
   - 提供了创建和管理 worker 线程的功能，允许在独立的线程中执行 JavaScript 代码。
   - **举例 (涉及到 Linux, Android 内核及框架的知识):**  在某些需要执行耗时操作但不希望阻塞主线程的情况下，可以使用 worker 线程。这涉及到操作系统提供的线程管理机制。

10. **FFI (Foreign Function Interface) 的实现细节:**
    - 定义了 `NativeFunction` 和 `SystemFunction` 类，用于从 JavaScript 中调用目标进程的 Native 函数。
    - 处理了参数类型和返回类型的转换，以及不同的调用约定 (ABI)。
    - **举例 (涉及到二进制底层, Linux, Android 内核及框架的知识):** 调用 Native 函数需要了解函数的地址、参数类型、返回类型以及调用约定 (如 cdecl, stdcall, 系统调用约定等)。在 Android 逆向中，可以使用 `NativeFunction` 调用 Android 系统库 (libc.so, libbinder.so 等) 中的函数。

**逻辑推理 (假设输入与输出):**

假设用户编写了一个 Frida 脚本，想要 hook `malloc` 函数并打印其参数：

**假设输入 (JavaScript 脚本):**

```javascript
Interceptor.attach(Module.findExportByName(null, 'malloc'), {
  onEnter: function(args) {
    console.log("malloc called with size:", args[0].toInt32());
  }
});
```

**gumquickcore.c 中的处理 (Simplified):**

1. 当 JavaScript 引擎执行到 `Interceptor.attach` 时，会调用到 `gumjs_script_pin` 等相关绑定函数 (尽管 `Interceptor.attach` 的实现更复杂，会涉及到 `gumquickinterceptor.c`)。
2. `Module.findExportByName` 会调用到底层的模块查找功能，返回 `malloc` 函数的地址，这个地址会以 `NativePointer` 的形式在 JavaScript 中表示。
3. `Interceptor.attach` 的参数 (函数地址和回调对象) 会被传递到 Native 代码。
4. 当目标进程调用 `malloc` 时，Frida 的 Interceptor 机制会触发 JavaScript 的 `onEnter` 回调。
5. `args[0]` 在 JavaScript 中是一个 `NativePointer` 对象，指向 `malloc` 的第一个参数 (size)。
6. `args[0].toInt32()` 会调用到 `gumjs_native_pointer_to_int32` 这样的绑定函数，将 Native 的内存数据转换为 JavaScript 的整数。
7. `console.log` 会在 JavaScript 控制台中打印输出。

**假设输出 (Console):**

```
malloc called with size: 1024
malloc called with size: 4096
...
```

**用户或编程常见的使用错误举例说明:**

1. **FFI 类型不匹配:**  使用 `NativeFunction` 调用 Native 函数时，如果定义的参数类型或返回类型与实际函数不符，可能会导致崩溃或不可预测的行为。
   - **例子:**  Native 函数的参数是 `uint64_t`，但在 JavaScript 中定义为 `int32`。

2. **内存操作错误:**  使用 `NativePointer` 读写内存时，访问了无效的地址，或者写入了错误的数据。
   - **例子:**  `ptr.writeU8(0x12)` 向一个只读内存地址写入数据。

3. **异步操作处理不当:**  在 `setTimeout` 或 `setInterval` 的回调函数中访问了已经被释放的资源。
   - **例子:**  在 `setTimeout` 的回调中访问了一个局部变量，但该局部变量在定时器触发时已经超出了作用域。

4. **Hook 时机错误:**  在目标函数尚未加载到内存之前就尝试 hook，导致 hook 失败。
   - **例子:**  在脚本的最开始就尝试 hook 一个动态链接库中的函数，但该库可能在稍后才被加载。

**用户操作如何一步步到达这里 (作为调试线索):**

1. **编写 Frida 脚本 (JavaScript):** 用户首先会编写一个 JavaScript 脚本，使用 Frida 提供的 API 来进行逆向操作。 例如，他们可能会使用 `Interceptor.attach` 来 hook 一个函数。

2. **使用 Frida 客户端注入脚本:** 用户会使用 Frida 的命令行工具 (`frida`, `frida-ps`, `frida-trace`) 或者 Python 库来将这个脚本注入到目标进程中。

3. **JavaScript 引擎执行脚本:** Frida 客户端会将脚本发送到目标进程，然后 `gumquickcore.c` 中初始化的 QuickJS 引擎会开始解析和执行这个脚本。

4. **调用 Frida API:** 当脚本执行到 Frida 相关的 API 调用时 (例如 `Interceptor.attach`, `Module.findExportByName`, `new NativePointer` 等)，这些调用会通过 JavaScript 绑定层 (也就是 `gumquickcore.c` 中定义的 `gumjs_*` 函数) 传递到 Frida Gum 库的 Native 代码。

5. **Native 代码执行:**  Frida Gum 库的 Native 代码会执行相应的操作，例如查找模块、hook 函数、读写内存等。

6. **结果返回:** Native 代码执行的结果会通过绑定层转换回 JavaScript 的对象或值，并返回给 JavaScript 脚本。

7. **回调执行:** 如果用户在 API 调用中提供了回调函数 (例如 `Interceptor.attach` 的 `onEnter` 和 `onLeave`)，当相应的事件发生时 (例如函数被调用或返回)，Frida 会再次通过绑定层调用到 JavaScript 的回调函数。

因此，作为调试线索，如果用户报告了与 Frida API 调用相关的问题，或者涉及到 JavaScript 和 Native 代码交互的问题，那么 `gumquickcore.c` 就是一个需要重点关注的文件，因为它负责管理 JavaScript 运行时环境和连接 Native 功能的桥梁。 例如，如果用户报告 `NativePointer` 的某些方法行为异常，或者 FFI 调用失败，那么就需要检查 `gumquickcore.c` 中对应的 `gumjs_native_pointer_*` 或 `gumjs_native_function_*` 函数的实现。

**总结 `gumquickcore.c` 的功能 (针对第 1 部分):**

`gumquickcore.c` 作为 Frida Gum 库 JavaScript 绑定的核心，主要负责搭建和维护 JavaScript 运行环境，并将 Frida Gum 的底层能力以 JavaScript API 的形式暴露出来。 它定义了 JavaScript 中用于操作 Native 数据的类型，处理 JavaScript 和 Native 代码之间的交互，并提供了基本的运行时功能 (如定时器、消息传递等)。 它是 Frida 脚本能够与目标进程进行动态交互的关键组成部分。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickcore.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共6部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2020-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2020-2022 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2020 Marcus Mengs <mame8282@googlemail.com>
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 * Copyright (C) 2024 Simon Zuckerbraun <Simon_Zuckerbraun@trendmicro.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickcore.h"

#include "gumffi.h"
#include "gumquickinterceptor.h"
#include "gumquickmacros.h"
#include "gumquickscript-priv.h"
#include "gumquickstalker.h"
#include "gumsourcemap.h"
#ifdef HAVE_OBJC_BRIDGE
# include "gumquickscript-objc.h"
#endif
#ifdef HAVE_SWIFT_BRIDGE
# include "gumquickscript-swift.h"
#endif
#ifdef HAVE_JAVA_BRIDGE
# include "gumquickscript-java.h"
#endif

#include <string.h>
#ifdef _MSC_VER
# include <intrin.h>
#endif
#ifdef HAVE_PTRAUTH
# include <ptrauth.h>
#endif

#define GUM_QUICK_FFI_FUNCTION_PARAMS_EMPTY { NULL, }

typedef struct _GumQuickWeakCallback GumQuickWeakCallback;
typedef struct _GumQuickFlushCallback GumQuickFlushCallback;
typedef struct _GumQuickModuleInitOperation GumQuickModuleInitOperation;
typedef struct _GumQuickFFIFunctionParams GumQuickFFIFunctionParams;
typedef guint8 GumQuickSchedulingBehavior;
typedef guint8 GumQuickExceptionsBehavior;
typedef guint8 GumQuickCodeTraps;
typedef guint8 GumQuickReturnValueShape;
typedef struct _GumQuickFFIFunction GumQuickFFIFunction;
typedef struct _GumQuickCallbackContext GumQuickCallbackContext;

struct _GumQuickFlushCallback
{
  GumQuickFlushNotify func;
  gpointer data;
  GDestroyNotify data_destroy;
};

struct _GumQuickModuleInitOperation
{
  JSValue module;
  JSValue perform_init;

  GumQuickCore * core;
};

struct _GumQuickWeakRef
{
  JSValue target;
  GArray * callbacks;
};

struct _GumQuickWeakCallback
{
  guint id;
  JSValue callback;
};

struct _GumQuickScheduledCallback
{
  gint id;
  gboolean repeat;
  JSValue func;
  GSource * source;

  GumQuickCore * core;
};

struct _GumQuickExceptionSink
{
  JSValue callback;
  GumQuickCore * core;
};

struct _GumQuickMessageSink
{
  JSValue callback;
  GumQuickCore * core;
};

struct _GumQuickFFIFunctionParams
{
  GCallback implementation;
  JSValueConst return_type;
  JSValueConst argument_types;
  const gchar * abi_name;
  GumQuickSchedulingBehavior scheduling;
  GumQuickExceptionsBehavior exceptions;
  GumQuickCodeTraps traps;
  GumQuickReturnValueShape return_shape;

  JSContext * ctx;
};

enum _GumQuickSchedulingBehavior
{
  GUM_QUICK_SCHEDULING_COOPERATIVE,
  GUM_QUICK_SCHEDULING_EXCLUSIVE
};

enum _GumQuickExceptionsBehavior
{
  GUM_QUICK_EXCEPTIONS_STEAL,
  GUM_QUICK_EXCEPTIONS_PROPAGATE
};

enum _GumQuickCodeTraps
{
  GUM_QUICK_CODE_TRAPS_DEFAULT,
  GUM_QUICK_CODE_TRAPS_NONE,
  GUM_QUICK_CODE_TRAPS_ALL
};

enum _GumQuickReturnValueShape
{
  GUM_QUICK_RETURN_PLAIN,
  GUM_QUICK_RETURN_DETAILED
};

struct _GumQuickFFIFunction
{
  GumQuickNativePointer native_pointer;

  GCallback implementation;
  GumQuickSchedulingBehavior scheduling;
  GumQuickExceptionsBehavior exceptions;
  GumQuickCodeTraps traps;
  GumQuickReturnValueShape return_shape;
  ffi_cif cif;
  ffi_type ** atypes;
  gsize arglist_size;
  gboolean is_variadic;
  guint nargs_fixed;
  ffi_abi abi;
  GSList * data;
};

struct _GumQuickCallbackContext
{
  JSValue wrapper;
  GumQuickCpuContext * cpu_context;
  gint * system_error;
  GumAddress return_address;
  GumAddress raw_return_address;
  int initial_property_count;
};

static gboolean gum_quick_core_handle_crashed_js (GumExceptionDetails * details,
    gpointer user_data);

static void gum_quick_flush_callback_free (GumQuickFlushCallback * self);
static gboolean gum_quick_flush_callback_notify (GumQuickFlushCallback * self);

GUMJS_DECLARE_FUNCTION (gumjs_set_timeout)
GUMJS_DECLARE_FUNCTION (gumjs_set_interval)
GUMJS_DECLARE_FUNCTION (gumjs_clear_timer)
GUMJS_DECLARE_FUNCTION (gumjs_gc)
GUMJS_DECLARE_FUNCTION (gumjs_send)
GUMJS_DECLARE_FUNCTION (gumjs_set_unhandled_exception_callback)
GUMJS_DECLARE_FUNCTION (gumjs_set_incoming_message_callback)
GUMJS_DECLARE_FUNCTION (gumjs_wait_for_event)

GUMJS_DECLARE_GETTER (gumjs_frida_get_heap_size)
GUMJS_DECLARE_FUNCTION (gumjs_frida_objc_load)
GUMJS_DECLARE_FUNCTION (gumjs_frida_swift_load)
GUMJS_DECLARE_FUNCTION (gumjs_frida_java_load)

GUMJS_DECLARE_FUNCTION (gumjs_script_evaluate)
GUMJS_DECLARE_FUNCTION (gumjs_script_load)
static gboolean gum_quick_core_init_module (GumQuickModuleInitOperation * op);
GUMJS_DECLARE_FUNCTION (gumjs_script_register_source_map)
GUMJS_DECLARE_FUNCTION (gumjs_script_find_source_map)
GUMJS_DECLARE_FUNCTION (gumjs_script_next_tick)
GUMJS_DECLARE_FUNCTION (gumjs_script_pin)
GUMJS_DECLARE_FUNCTION (gumjs_script_unpin)
GUMJS_DECLARE_FUNCTION (gumjs_script_bind_weak)
GUMJS_DECLARE_FUNCTION (gumjs_script_unbind_weak)
GUMJS_DECLARE_FUNCTION (gumjs_script_deref_weak)

GUMJS_DECLARE_FINALIZER (gumjs_weak_ref_finalize)
static gboolean gum_quick_core_invoke_pending_weak_callbacks_in_idle (
    GumQuickCore * self);

GUMJS_DECLARE_FUNCTION (gumjs_script_set_global_access_handler)
static JSValue gum_quick_core_on_global_get (JSContext * ctx, JSAtom name,
    void * opaque);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_int64_construct)
GUMJS_DECLARE_FINALIZER (gumjs_int64_finalize)
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

GUMJS_DECLARE_CONSTRUCTOR (gumjs_uint64_construct)
GUMJS_DECLARE_FINALIZER (gumjs_uint64_finalize)
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

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_pointer_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_pointer_finalize)
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

GUMJS_DECLARE_FINALIZER (gumjs_native_resource_finalize)

GUMJS_DECLARE_FINALIZER (gumjs_kernel_resource_finalize)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_function_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_function_finalize)
GUMJS_DECLARE_CALL_HANDLER (gumjs_native_function_invoke)
GUMJS_DECLARE_FUNCTION (gumjs_native_function_call)
GUMJS_DECLARE_FUNCTION (gumjs_native_function_apply)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_system_function_construct)
GUMJS_DECLARE_FINALIZER (gumjs_system_function_finalize)
GUMJS_DECLARE_CALL_HANDLER (gumjs_system_function_invoke)
GUMJS_DECLARE_FUNCTION (gumjs_system_function_call)
GUMJS_DECLARE_FUNCTION (gumjs_system_function_apply)

static GumQuickFFIFunction * gumjs_ffi_function_new (JSContext * ctx,
    const GumQuickFFIFunctionParams * params, GumQuickCore * core);
static void gum_quick_ffi_function_finalize (GumQuickFFIFunction * func);
static JSValue gum_quick_ffi_function_invoke (GumQuickFFIFunction * self,
    JSContext * ctx, GCallback implementation, guint argc, JSValueConst * argv,
    GumQuickCore * core);
static JSValue gumjs_ffi_function_invoke (JSContext * ctx,
    JSValueConst func_obj, JSClassID klass, GumQuickArgs * args,
    GumQuickCore * core);
static JSValue gumjs_ffi_function_call (JSContext * ctx, JSValueConst func_obj,
    JSClassID klass, GumQuickArgs * args, GumQuickCore * core);
static JSValue gumjs_ffi_function_apply (JSContext * ctx, JSValueConst func_obj,
    JSClassID klass, GumQuickArgs * args, GumQuickCore * core);
static gboolean gumjs_ffi_function_get (JSContext * ctx, JSValueConst func_obj,
    JSValueConst receiver, JSClassID klass, GumQuickCore * core,
    GumQuickFFIFunction ** func, GCallback * implementation);

static gboolean gum_quick_ffi_function_params_init (
    GumQuickFFIFunctionParams * params, GumQuickReturnValueShape return_shape,
    GumQuickArgs * args);
static void gum_quick_ffi_function_params_destroy (
    GumQuickFFIFunctionParams * params);

static gboolean gum_quick_scheduling_behavior_get (JSContext * ctx,
    JSValueConst val, GumQuickSchedulingBehavior * behavior);
static gboolean gum_quick_exceptions_behavior_get (JSContext * ctx,
    JSValueConst val, GumQuickExceptionsBehavior * behavior);
static gboolean gum_quick_code_traps_get (JSContext * ctx, JSValueConst val,
    GumQuickCodeTraps * traps);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_native_callback_construct)
GUMJS_DECLARE_FINALIZER (gumjs_native_callback_finalize)
static void gum_quick_native_callback_finalize (GumQuickNativeCallback * func);
static void gum_quick_native_callback_invoke (ffi_cif * cif,
    void * return_value, void ** args, void * user_data);

GUMJS_DECLARE_FINALIZER (gumjs_callback_context_finalize)
GUMJS_DECLARE_GETTER (gumjs_callback_context_get_return_address)
GUMJS_DECLARE_GETTER (gumjs_callback_context_get_cpu_context)
GUMJS_DECLARE_GETTER (gumjs_callback_context_get_system_error)
GUMJS_DECLARE_SETTER (gumjs_callback_context_set_system_error)
static JSValue gum_quick_callback_context_new (GumQuickCore * core,
    GumCpuContext * cpu_context, gint * system_error,
    GumAddress raw_return_address, GumQuickCallbackContext ** context);
static gboolean gum_quick_callback_context_get (JSContext * ctx,
    JSValueConst val, GumQuickCore * core, GumQuickCallbackContext ** ic);

GUMJS_DECLARE_FINALIZER (gumjs_cpu_context_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_cpu_context_to_json)
static JSValue gumjs_cpu_context_set_gpr (GumQuickCpuContext * self,
    JSContext * ctx, JSValueConst val, gpointer * reg);
G_GNUC_UNUSED static JSValue gumjs_cpu_context_set_vector (
    GumQuickCpuContext * self, JSContext * ctx, JSValueConst val,
    guint8 * bytes, gsize size);
G_GNUC_UNUSED static JSValue gumjs_cpu_context_set_double (
    GumQuickCpuContext * self, JSContext * ctx, JSValueConst val, gdouble * d);
G_GNUC_UNUSED static JSValue gumjs_cpu_context_set_float (
    GumQuickCpuContext * self, JSContext * ctx, JSValueConst val, gfloat * f);
G_GNUC_UNUSED static JSValue gumjs_cpu_context_set_flags (
    GumQuickCpuContext * self, JSContext * ctx, JSValueConst val, gsize * f);

GUMJS_DECLARE_CONSTRUCTOR (gumjs_match_pattern_construct)
GUMJS_DECLARE_FINALIZER (gumjs_match_pattern_finalize)

static JSValue gumjs_source_map_new (const gchar * json, GumQuickCore * core);
GUMJS_DECLARE_CONSTRUCTOR (gumjs_source_map_construct)
GUMJS_DECLARE_FINALIZER (gumjs_source_map_finalize)
GUMJS_DECLARE_FUNCTION (gumjs_source_map_resolve)

GUMJS_DECLARE_CONSTRUCTOR (gumjs_worker_construct)
static void gum_quick_worker_destroy (GumQuickWorker * worker);
GUMJS_DECLARE_FUNCTION (gumjs_worker_terminate)
GUMJS_DECLARE_FUNCTION (gumjs_worker_post)

static JSValue gum_quick_core_schedule_callback (GumQuickCore * self,
    GumQuickArgs * args, gboolean repeat);
static GumQuickScheduledCallback * gum_quick_core_try_steal_scheduled_callback (
    GumQuickCore * self, gint id);

static GumQuickScheduledCallback * gum_scheduled_callback_new (guint id,
    JSValueConst func, gboolean repeat, GSource * source, GumQuickCore * core);
static void gum_scheduled_callback_free (GumQuickScheduledCallback * callback);
static gboolean gum_scheduled_callback_invoke (
    GumQuickScheduledCallback * self);

static GumQuickExceptionSink * gum_quick_exception_sink_new (
    JSValueConst callback, GumQuickCore * core);
static void gum_quick_exception_sink_free (GumQuickExceptionSink * sink);
static void gum_quick_exception_sink_handle_exception (
    GumQuickExceptionSink * self, JSValueConst exception);

static GumQuickMessageSink * gum_quick_message_sink_new (JSValueConst callback,
    GumQuickCore * core);
static void gum_quick_message_sink_free (GumQuickMessageSink * sink);
static void gum_quick_message_sink_post (GumQuickMessageSink * self,
    const gchar * message, GBytes * data, GumQuickScope * scope);

static gboolean gum_quick_ffi_type_get (JSContext * ctx, JSValueConst val,
    GumQuickCore * core, ffi_type ** type, GSList ** data);
static gboolean gum_quick_ffi_abi_get (JSContext * ctx, const gchar * name,
    ffi_abi * abi);
static gboolean gum_quick_value_to_ffi (JSContext * ctx, JSValueConst sval,
    const ffi_type * type, GumQuickCore * core, GumFFIValue * val);
static JSValue gum_quick_value_from_ffi (JSContext * ctx,
    const GumFFIValue * val, const ffi_type * type, GumQuickCore * core);

static void gum_quick_core_setup_atoms (GumQuickCore * self);
static void gum_quick_core_teardown_atoms (GumQuickCore * self);

static const JSCFunctionListEntry gumjs_root_entries[] =
{
  JS_CFUNC_DEF ("_setTimeout", 0, gumjs_set_timeout),
  JS_CFUNC_DEF ("_setInterval", 0, gumjs_set_interval),
  JS_CFUNC_DEF ("clearTimeout", 1, gumjs_clear_timer),
  JS_CFUNC_DEF ("clearInterval", 1, gumjs_clear_timer),
  JS_CFUNC_DEF ("gc", 0, gumjs_gc),
  JS_CFUNC_DEF ("_send", 0, gumjs_send),
  JS_CFUNC_DEF ("_setUnhandledExceptionCallback", 0,
      gumjs_set_unhandled_exception_callback),
  JS_CFUNC_DEF ("_setIncomingMessageCallback", 0,
      gumjs_set_incoming_message_callback),
  JS_CFUNC_DEF ("_waitForEvent", 0, gumjs_wait_for_event),
};

static const JSCFunctionListEntry gumjs_frida_entries[] =
{
  JS_PROP_STRING_DEF ("version", FRIDA_VERSION, JS_PROP_C_W_E),
  JS_CGETSET_DEF ("heapSize", gumjs_frida_get_heap_size, NULL),
  JS_CFUNC_DEF ("_loadObjC", 0, gumjs_frida_objc_load),
  JS_CFUNC_DEF ("_loadSwift", 0, gumjs_frida_swift_load),
  JS_CFUNC_DEF ("_loadJava", 0, gumjs_frida_java_load),
};

static const JSCFunctionListEntry gumjs_script_entries[] =
{
  JS_PROP_STRING_DEF ("runtime", "QJS", JS_PROP_C_W_E),
  JS_CFUNC_DEF ("evaluate", 0, gumjs_script_evaluate),
  JS_CFUNC_DEF ("_load", 0, gumjs_script_load),
  JS_CFUNC_DEF ("registerSourceMap", 0, gumjs_script_register_source_map),
  JS_CFUNC_DEF ("_findSourceMap", 0, gumjs_script_find_source_map),
  JS_CFUNC_DEF ("_nextTick", 0, gumjs_script_next_tick),
  JS_CFUNC_DEF ("pin", 0, gumjs_script_pin),
  JS_CFUNC_DEF ("unpin", 0, gumjs_script_unpin),
  JS_CFUNC_DEF ("bindWeak", 0, gumjs_script_bind_weak),
  JS_CFUNC_DEF ("unbindWeak", 0, gumjs_script_unbind_weak),
  JS_CFUNC_DEF ("_derefWeak", 0, gumjs_script_deref_weak),
  JS_CFUNC_DEF ("setGlobalAccessHandler", 1,
      gumjs_script_set_global_access_handler),
};

static const JSClassDef gumjs_weak_ref_def =
{
  .class_name = "WeakRef",
  .finalizer = gumjs_weak_ref_finalize,
};

static const JSClassDef gumjs_int64_def =
{
  .class_name = "Int64",
  .finalizer = gumjs_int64_finalize,
};

static const JSCFunctionListEntry gumjs_int64_entries[] =
{
  JS_CFUNC_DEF ("add", 0, gumjs_int64_add),
  JS_CFUNC_DEF ("sub", 0, gumjs_int64_sub),
  JS_CFUNC_DEF ("and", 0, gumjs_int64_and),
  JS_CFUNC_DEF ("or", 0, gumjs_int64_or),
  JS_CFUNC_DEF ("xor", 0, gumjs_int64_xor),
  JS_CFUNC_DEF ("shr", 0, gumjs_int64_shr),
  JS_CFUNC_DEF ("shl", 0, gumjs_int64_shl),
  JS_CFUNC_DEF ("not", 0, gumjs_int64_not),
  JS_CFUNC_DEF ("compare", 0, gumjs_int64_compare),
  JS_CFUNC_DEF ("toNumber", 0, gumjs_int64_to_number),
  JS_CFUNC_DEF ("toString", 0, gumjs_int64_to_string),
  JS_CFUNC_DEF ("toJSON", 0, gumjs_int64_to_json),
  JS_CFUNC_DEF ("valueOf", 0, gumjs_int64_value_of),
};

static const JSClassDef gumjs_uint64_def =
{
  .class_name = "UInt64",
  .finalizer = gumjs_uint64_finalize,
};

static const JSCFunctionListEntry gumjs_uint64_entries[] =
{
  JS_CFUNC_DEF ("add", 0, gumjs_uint64_add),
  JS_CFUNC_DEF ("sub", 0, gumjs_uint64_sub),
  JS_CFUNC_DEF ("and", 0, gumjs_uint64_and),
  JS_CFUNC_DEF ("or", 0, gumjs_uint64_or),
  JS_CFUNC_DEF ("xor", 0, gumjs_uint64_xor),
  JS_CFUNC_DEF ("shr", 0, gumjs_uint64_shr),
  JS_CFUNC_DEF ("shl", 0, gumjs_uint64_shl),
  JS_CFUNC_DEF ("not", 0, gumjs_uint64_not),
  JS_CFUNC_DEF ("compare", 0, gumjs_uint64_compare),
  JS_CFUNC_DEF ("toNumber", 0, gumjs_uint64_to_number),
  JS_CFUNC_DEF ("toString", 0, gumjs_uint64_to_string),
  JS_CFUNC_DEF ("toJSON", 0, gumjs_uint64_to_json),
  JS_CFUNC_DEF ("valueOf", 0, gumjs_uint64_value_of),
};

static const JSClassDef gumjs_native_pointer_def =
{
  .class_name = "NativePointer",
  .finalizer = gumjs_native_pointer_finalize,
};

static const JSCFunctionListEntry gumjs_native_pointer_entries[] =
{
  JS_CFUNC_DEF ("isNull", 0, gumjs_native_pointer_is_null),
  JS_CFUNC_DEF ("add", 0, gumjs_native_pointer_add),
  JS_CFUNC_DEF ("sub", 0, gumjs_native_pointer_sub),
  JS_CFUNC_DEF ("and", 0, gumjs_native_pointer_and),
  JS_CFUNC_DEF ("or", 0, gumjs_native_pointer_or),
  JS_CFUNC_DEF ("xor", 0, gumjs_native_pointer_xor),
  JS_CFUNC_DEF ("shr", 0, gumjs_native_pointer_shr),
  JS_CFUNC_DEF ("shl", 0, gumjs_native_pointer_shl),
  JS_CFUNC_DEF ("not", 0, gumjs_native_pointer_not),
  JS_CFUNC_DEF ("sign", 0, gumjs_native_pointer_sign),
  JS_CFUNC_DEF ("strip", 0, gumjs_native_pointer_strip),
  JS_CFUNC_DEF ("blend", 0, gumjs_native_pointer_blend),
  JS_CFUNC_DEF ("compare", 0, gumjs_native_pointer_compare),
  JS_CFUNC_DEF ("toInt32", 0, gumjs_native_pointer_to_int32),
  JS_CFUNC_DEF ("toUInt32", 0, gumjs_native_pointer_to_uint32),
  JS_CFUNC_DEF ("toString", 0, gumjs_native_pointer_to_string),
  JS_CFUNC_DEF ("toJSON", 0, gumjs_native_pointer_to_json),
  JS_CFUNC_DEF ("toMatchPattern", 0,
      gumjs_native_pointer_to_match_pattern),
};

static const JSCFunctionListEntry gumjs_array_buffer_class_entries[] =
{
  JS_CFUNC_DEF ("wrap", 0, gumjs_array_buffer_wrap),
};

static const JSCFunctionListEntry gumjs_array_buffer_instance_entries[] =
{
  JS_CFUNC_DEF ("unwrap", 0, gumjs_array_buffer_unwrap),
};

static const JSClassDef gumjs_native_resource_def =
{
  .class_name = "NativeResource",
  .finalizer = gumjs_native_resource_finalize,
};

static const JSClassDef gumjs_kernel_resource_def =
{
  .class_name = "KernelResource",
  .finalizer = gumjs_kernel_resource_finalize,
};

static const JSClassDef gumjs_native_function_def =
{
  .class_name = "NativeFunction",
  .finalizer = gumjs_native_function_finalize,
  .call = gumjs_native_function_invoke,
};

static const JSCFunctionListEntry gumjs_native_function_entries[] =
{
  JS_CFUNC_DEF ("call", 0, gumjs_native_function_call),
  JS_CFUNC_DEF ("apply", 2, gumjs_native_function_apply),
};

static const JSClassDef gumjs_system_function_def =
{
  .class_name = "SystemFunction",
  .finalizer = gumjs_system_function_finalize,
  .call = gumjs_system_function_invoke,
};

static const JSCFunctionListEntry gumjs_system_function_entries[] =
{
  JS_CFUNC_DEF ("call", 0, gumjs_system_function_call),
  JS_CFUNC_DEF ("apply", 2, gumjs_system_function_apply),
};

static const JSClassDef gumjs_native_callback_def =
{
  .class_name = "NativeCallback",
  .finalizer = gumjs_native_callback_finalize,
};

static const JSClassDef gumjs_callback_context_def =
{
  .class_name = "CallbackContext",
  .finalizer = gumjs_callback_context_finalize,
};

static const JSCFunctionListEntry gumjs_callback_context_entries[] =
{
  JS_CGETSET_DEF ("returnAddress", gumjs_callback_context_get_return_address,
      NULL),
  JS_CGETSET_DEF ("context", gumjs_callback_context_get_cpu_context, NULL),
  JS_CGETSET_DEF (GUMJS_SYSTEM_ERROR_FIELD,
      gumjs_callback_context_get_system_error,
      gumjs_callback_context_set_system_error),
};

static const JSClassDef gumjs_cpu_context_def =
{
  .class_name = "CpuContext",
  .finalizer = gumjs_cpu_context_finalize,
};

#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED(A, R) \
    GUMJS_DEFINE_GETTER (gumjs_cpu_context_get_##A) \
    { \
      GumQuickCpuContext * self; \
      \
      if (!_gum_quick_cpu_context_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      return _gum_quick_native_pointer_new (ctx, \
          GSIZE_TO_POINTER (self->handle->R), core); \
    } \
    \
    GUMJS_DEFINE_SETTER (gumjs_cpu_context_set_##A) \
    { \
      GumQuickCpuContext * self; \
      \
      if (!_gum_quick_cpu_context_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      return gumjs_cpu_context_set_gpr (self, ctx, val, \
          (gpointer *) &self->handle->R); \
    }
#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR(R) \
    GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (R, R)

#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR(A, R) \
    GUMJS_DEFINE_GETTER (gumjs_cpu_context_get_##A) \
    { \
      GumQuickCpuContext * self; \
      \
      if (!_gum_quick_cpu_context_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      return JS_NewArrayBufferCopy (ctx, self->handle->R, \
          sizeof (self->handle->R)); \
    } \
    \
    GUMJS_DEFINE_SETTER (gumjs_cpu_context_set_##A) \
    { \
      GumQuickCpuContext * self; \
      \
      if (!_gum_quick_cpu_context_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      return gumjs_cpu_context_set_vector (self, ctx, val, self->handle->R, \
          sizeof (self->handle->R)); \
    }

#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE(A, R) \
    GUMJS_DEFINE_GETTER (gumjs_cpu_context_get_##A) \
    { \
      GumQuickCpuContext * self; \
      \
      if (!_gum_quick_cpu_context_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      return JS_NewFloat64 (ctx, self->handle->R); \
    } \
    \
    GUMJS_DEFINE_SETTER (gumjs_cpu_context_set_##A) \
    { \
      GumQuickCpuContext * self; \
      \
      if (!_gum_quick_cpu_context_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      return gumjs_cpu_context_set_double (self, ctx, val, &self->handle->R); \
    }

#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT(A, R) \
    GUMJS_DEFINE_GETTER (gumjs_cpu_context_get_##A) \
    { \
      GumQuickCpuContext * self; \
      \
      if (!_gum_quick_cpu_context_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      return JS_NewFloat64 (ctx, self->handle->R); \
    } \
    \
    GUMJS_DEFINE_SETTER (gumjs_cpu_context_set_##A) \
    { \
      GumQuickCpuContext * self; \
      \
      if (!_gum_quick_cpu_context_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      return gumjs_cpu_context_set_float (self, ctx, val, &self->handle->R); \
    }

#define GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLAGS(A, R) \
    GUMJS_DEFINE_GETTER (gumjs_cpu_context_get_##A) \
    { \
      GumQuickCpuContext * self; \
      \
      if (!_gum_quick_cpu_context_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      return JS_NewUint32 (ctx, self->handle->R); \
    } \
    \
    GUMJS_DEFINE_SETTER (gumjs_cpu_context_set_##A) \
    { \
      GumQuickCpuContext * self; \
      \
      if (!_gum_quick_cpu_context_unwrap (ctx, this_val, core, &self)) \
        return JS_EXCEPTION; \
      \
      return gumjs_cpu_context_set_flags (self, ctx, val, \
          (gsize *) &self->handle->R); \
    }

#define GUM_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED(A, R) \
    JS_CGETSET_DEF (G_STRINGIFY (A), gumjs_cpu_context_get_##R, \
        gumjs_cpu_context_set_##R)
#define GUM_EXPORT_CPU_CONTEXT_ACCESSOR(R) \
    GUM_EXPORT_CPU_CONTEXT_ACCESSOR_ALIASED (R, R)

#if defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (eax)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (ecx)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (edx)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (ebx)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (esp)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (ebp)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (esi)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (edi)

GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (eip)
#elif defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 8
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rax)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rcx)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rdx)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rbx)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rsp)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rbp)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rsi)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rdi)

GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r8)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r9)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r10)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r11)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r12)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r13)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r14)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r15)

GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (rip)
#elif defined (HAVE_ARM)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (pc)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (sp)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLAGS (cpsr, cpsr)

GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r0, r[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r1, r[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r2, r[2])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r3, r[3])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r4, r[4])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r5, r[5])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r6, r[6])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (r7, r[7])

GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r8)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r9)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r10)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r11)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (r12)

GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (lr)

GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q0, v[0].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q1, v[1].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q2, v[2].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q3, v[3].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q4, v[4].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q5, v[5].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q6, v[6].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q7, v[7].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q8, v[8].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q9, v[9].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q10, v[10].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q11, v[11].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q12, v[12].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q13, v[13].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q14, v[14].q)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_VECTOR (q15, v[15].q)

GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d0, v[0].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d1, v[0].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d2, v[1].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d3, v[1].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d4, v[2].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d5, v[2].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d6, v[3].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d7, v[3].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d8, v[4].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d9, v[4].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d10, v[5].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d11, v[5].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d12, v[6].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d13, v[6].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d14, v[7].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d15, v[7].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d16, v[8].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d17, v[8].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d18, v[9].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d19, v[9].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d20, v[10].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d21, v[10].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d22, v[11].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d23, v[11].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d24, v[12].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d25, v[12].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d26, v[13].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d27, v[13].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d28, v[14].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d29, v[14].d[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d30, v[15].d[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_DOUBLE (d31, v[15].d[1])

GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s0, v[0].s[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s1, v[0].s[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s2, v[0].s[2])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s3, v[0].s[3])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s4, v[1].s[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s5, v[1].s[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s6, v[1].s[2])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s7, v[1].s[3])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s8, v[2].s[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s9, v[2].s[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s10, v[2].s[2])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s11, v[2].s[3])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s12, v[3].s[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s13, v[3].s[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s14, v[3].s[2])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s15, v[3].s[3])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s16, v[4].s[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s17, v[4].s[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s18, v[4].s[2])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s19, v[4].s[3])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s20, v[5].s[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s21, v[5].s[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s22, v[5].s[2])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s23, v[5].s[3])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s24, v[6].s[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s25, v[6].s[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s26, v[6].s[2])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s27, v[6].s[3])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s28, v[7].s[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s29, v[7].s[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s30, v[7].s[2])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLOAT (s31, v[7].s[3])
#elif defined (HAVE_ARM64)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (pc)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR (sp)
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_FLAGS (nzcv, nzcv)

GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x0, x[0])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x1, x[1])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x2, x[2])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x3, x[3])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x4, x[4])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x5, x[5])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x6, x[6])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x7, x[7])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x8, x[8])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x9, x[9])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x10, x[10])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x11, x[11])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x12, x[12])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x13, x[13])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x14, x[14])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x15, x[15])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x16, x[16])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x17, x[17])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x18, x[18])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x19, x[19])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x20, x[20])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x21, x[21])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x22, x[22])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x23, x[23])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x24, x[24])
GUM_DEFINE_CPU_CONTEXT_ACCESSOR_GPR_ALIASED (x25, x[25])
GUM_DEFINE_CPU_CO
"""


```