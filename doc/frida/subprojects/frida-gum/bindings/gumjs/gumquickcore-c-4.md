Response:
Let's break down the thought process for analyzing this code snippet.

1. **Understand the Goal:** The core request is to analyze a specific C file (`gumquickcore.c`) within the Frida project, focusing on its functionality, its relation to reverse engineering, its interaction with low-level system aspects, its logic, potential user errors, and its role within a larger context (being part 5 of 6).

2. **High-Level Structure Scan:**  First, I'd quickly scan the code to identify key structural elements:
    * **Includes:**  Although not provided in the snippet, the file path (`frida/subprojects/frida-gum/bindings/gumjs/gumquickcore.c`) hints at bindings to JavaScript. We can infer it likely includes Frida-specific headers and standard C libraries.
    * **Static Functions:** The majority of the functions are `static`, meaning they're internal to this compilation unit. This suggests this file implements a specific set of closely related features.
    * **`GumQuick*` Types:**  The frequent use of `GumQuickCore`, `GumQuickNativeCallback`, `GumQuickCallbackContext`, etc., indicates this file defines and uses its own data structures, likely related to the quick integration with the JavaScript environment.
    * **`ffi_*` Functions:**  The presence of `ffi_closure_free`, `ffi_cif`, `ffi_type`, etc., strongly suggests the use of libffi, a library for dynamically creating function call interfaces. This is a major clue about how Frida bridges native code with JavaScript.
    * **`JS_*` Functions:**  Functions like `JS_DupValue`, `JS_FreeValue`, `JS_NewObject`, `JS_Call`, etc., clearly point to the use of a JavaScript engine, likely QuickJS given the file name.
    * **Macros:** Macros like `GUMJS_DEFINE_FINALIZER`, `GUMJS_DEFINE_GETTER`, `GUMJS_DEFINE_FUNCTION`, and `GUMJS_DEFINE_CONSTRUCTOR` are used to define JavaScript-callable functions and object properties. This is a pattern for exposing C functionality to JavaScript.
    * **Assembly Code:**  The snippets of assembly code (`asm`) within `gum_quick_native_callback_invoke` are crucial for understanding how Frida interacts with the CPU at a low level, retrieving register values like stack pointer, frame pointer, and return address.
    * **`g_*` Functions:** Functions starting with `g_` (like `g_free`, `g_slice_free`, `g_slist_delete_link`, `g_hash_table_insert`, `g_timeout_source_new`) indicate the use of GLib, a fundamental library providing core utility functions.

3. **Focus on Key Functionalities:**  Based on the structure, I'd start analyzing individual functions or groups of related functions:
    * **`gum_quick_native_callback_invoke`:** This function is central. It's an `ffi_closure` callback, meaning it gets invoked when JavaScript calls a native function that Frida has intercepted or created. The assembly code here is key for understanding how it captures the CPU state. The interaction with `GumInterceptor` and `GumQuickInvocationContext` highlights Frida's core interception mechanism.
    * **`gum_quick_callback_context_*`:** These functions manage a JavaScript object that represents the context of a native callback. The ability to get the return address and CPU context is important for introspection.
    * **`gum_quick_cpu_context_*`:**  These functions deal with a JavaScript representation of the CPU registers. The `READONLY` access flag is a notable detail.
    * **`gum_quick_worker_*`:** These functions handle the creation and management of JavaScript Web Workers, enabling concurrent execution.
    * **Scheduling (`gum_quick_core_schedule_callback`, `gum_scheduled_callback_*`):** This section deals with timers and idle tasks, allowing JavaScript to schedule actions.
    * **Exception and Message Handling (`gum_quick_exception_sink_*`, `gum_quick_message_sink_*`):**  These functions provide mechanisms for JavaScript to receive notifications about exceptions and messages from the native side.
    * **FFI Handling (`gum_quick_ffi_type_get`, `gum_quick_value_to_ffi`, `gum_quick_value_from_ffi`):** This is where the actual translation between JavaScript values and C data types happens, using libffi's type system.
    * **Atoms (`gum_quick_core_setup_atoms`, `gum_quick_core_teardown_atoms`):**  This relates to QuickJS's atom mechanism for efficient string handling.

4. **Connect to Reverse Engineering Concepts:**  As I analyze each function, I'd actively consider its relevance to reverse engineering:
    * **Interception:** The interaction with `GumInterceptor` is a direct link to function hooking and instrumentation, a fundamental reverse engineering technique.
    * **Context Inspection:** The ability to access CPU context (registers, stack) is crucial for understanding program execution flow and state during reverse engineering.
    * **Dynamic Native Calls:** The FFI functionality allows JavaScript to call arbitrary native functions, enabling interaction with the target process's code.
    * **Tracing and Logging:** The message and exception handling mechanisms can be used for logging and tracing program behavior.

5. **Identify Low-Level Interactions:**  Focus on code that directly interacts with the OS and hardware:
    * **Assembly Code:**  This is the most obvious indicator of low-level interaction.
    * **System Error Handling:**  The `gum_thread_get_system_error` and `gum_thread_set_system_error` functions suggest interaction with OS error codes.
    * **Backtracing:** The use of `gum_backtracer_make_accurate` indicates interaction with stack unwinding mechanisms, which are OS-specific.
    * **Memory Management:** Functions like `g_slice_new` and `g_free` are related to memory allocation.

6. **Infer Logic and Potential User Errors:**  For each function, consider:
    * **Inputs and Outputs:** What data does the function take, and what does it produce?  For example, `gum_quick_value_to_ffi` takes a JavaScript value and an FFI type and converts the value to a C representation.
    * **Assumptions:** What does the function assume about its inputs?  For example, the FFI conversion functions assume the JavaScript value is compatible with the specified C type.
    * **Error Conditions:** What can go wrong?  Invalid type conversions, incorrect function arguments, etc.

7. **Trace User Actions:** Think about how a user interacting with Frida would end up triggering these functions:
    * **`Interceptor.replace`:** This is the most direct way to get to `gum_quick_native_callback_invoke`.
    * **`NativeFunction`:** Creating and calling a `NativeFunction` using `Frida.NativeFunction` also uses the FFI mechanisms.
    * **`setTimeout`, `setInterval`, `postMessage`:**  These JavaScript APIs map to the scheduling and worker functionalities.
    * **Accessing `context` in an interceptor:** This would lead to the `gum_quick_callback_context_*` functions.
    * **Accessing `cpuContext` within the callback context:** This would use the `gum_quick_cpu_context_*` functions.

8. **Synthesize and Summarize:** Finally, based on the detailed analysis, synthesize the information into a concise summary of the file's functionality and its role within Frida. Emphasize the key aspects like bridging JavaScript and native code, enabling dynamic instrumentation, and providing access to low-level system information.

**Self-Correction/Refinement During the Process:**

* **Initial Overwhelm:**  The code can seem dense initially. Breaking it down function by function is essential.
* **Inferring Missing Information:** Since includes aren't provided, relying on naming conventions and common libraries (GLib, libffi, QuickJS) is necessary.
* **Connecting the Dots:**  Actively try to link different parts of the code together. For example, how does `gum_quick_native_callback_invoke` relate to the `Interceptor`?
* **Focusing on the "Why":**  Don't just describe *what* the code does, but also *why* it does it in the context of Frida's goals.

By following this structured approach, combining code analysis with knowledge of Frida's purpose and related technologies, one can effectively understand the functionality of a complex file like `gumquickcore.c`.
好的，让我们来分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumquickcore.c` 文件的第 5 部分的功能。

**本部分代码主要关注以下几个核心功能：**

1. **处理 Native 函数回调 (Callbacks):** 这部分代码定义了当 JavaScript 调用通过 Frida 拦截或创建的 Native 函数时，如何处理回调。核心是 `gum_quick_native_callback_invoke` 函数。

2. **提供回调上下文 (Callback Context):**  定义了 `GumQuickCallbackContext` 结构体和相关的函数，用于在 JavaScript 中表示 Native 回调的上下文信息，例如 CPU 寄存器状态、系统错误码、返回地址等。

3. **提供 CPU 上下文 (CPU Context):** 定义了 `GumQuickCpuContext` 结构体和相关的函数，用于在 JavaScript 中表示 CPU 的寄存器状态。

4. **实现匹配模式 (Match Pattern):** 提供了 `GumMatchPattern` 相关的结构体和函数，允许用户在 JavaScript 中创建和使用字符串匹配模式。

5. **处理 Source Map:** 提供了 `GumSourceMap` 相关的结构体和函数，允许用户在 JavaScript 中加载和使用 Source Map，用于将 JavaScript 代码的执行位置映射回原始源代码。

6. **实现 Web Worker:** 提供了 `GumQuickWorker` 相关的结构体和函数，允许用户在 Frida 的 JavaScript 环境中创建和管理 Web Worker，实现多线程并发。

7. **调度回调 (Scheduling Callbacks):** 提供了用于在 JavaScript 中设置定时器 (`setTimeout`, `setInterval`) 和空闲回调的机制。

8. **处理异常和消息 (Exception and Message Handling):**  定义了 `GumQuickExceptionSink` 和 `GumQuickMessageSink` 结构体和相关函数，用于将 Native 代码中的异常和消息传递到 JavaScript 端处理。

9. **FFI (Foreign Function Interface) 支持:** 提供了 `gum_quick_ffi_type_get`，`gum_quick_value_to_ffi`，`gum_quick_value_from_ffi` 等函数，用于在 JavaScript 和 Native 代码之间进行数据类型的转换，这是实现动态调用 Native 函数的关键。

10. **原子 (Atoms) 管理:**  定义了 `gum_quick_core_setup_atoms` 和 `gum_quick_core_teardown_atoms` 函数，用于管理 QuickJS 引擎中的原子 (interned strings)，提高性能。

**以下是对每个功能点的详细说明和举例：**

**1. 处理 Native 函数回调 (Callbacks)**

*   **功能:** 当 Frida 拦截了某个 Native 函数，或者用户通过 `Interceptor.replace` 或 `NativeFunction` 创建了一个指向 Native 代码的 JavaScript 函数时，`gum_quick_native_callback_invoke` 会被调用。
*   **逆向方法关系:**  这是 Frida 动态插桩的核心。通过拦截 Native 函数，Frida 可以在函数执行前后插入自定义的 JavaScript 代码，用于分析函数参数、返回值、修改执行流程等。
*   **二进制底层知识:**  此函数中包含了获取返回地址 (`return_address`)、栈指针 (`stack_pointer`) 和帧指针 (`frame_pointer`) 的汇编代码。这些都是理解函数调用栈的关键概念。不同的 CPU 架构 (x86, ARM, ARM64, MIPS) 使用不同的汇编指令来获取这些信息。
*   **Linux/Android 内核及框架知识:** 函数的调用约定、栈帧结构等是操作系统和架构相关的。理解这些可以帮助我们更好地分析 Native 代码的行为。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 一个被 Frida 拦截的 Native 函数被调用，参数为整数 1 和字符串 "hello"。
    *   **预期输出:** `gum_quick_native_callback_invoke` 会接收到这些参数，并将它们转换为 JavaScript 的值，然后调用用户定义的 JavaScript 回调函数。
*   **用户或编程常见错误:**  用户定义的 JavaScript 回调函数可能会抛出异常。Frida 需要妥善处理这些异常，避免导致目标进程崩溃。
*   **调试线索:** 当 Native 函数被调用时，Frida 的内部机制会调用到这个函数。用户操作可能是通过 Frida 的 JavaScript API (例如 `Interceptor.attach`) 设置了拦截点。

**2. 提供回调上下文 (Callback Context)**

*   **功能:** `GumQuickCallbackContext` 允许 JavaScript 代码访问关于 Native 回调发生时的上下文信息。
*   **逆向方法关系:**  在 Frida 的拦截回调中，用户可以通过访问 `this` 对象来获取回调上下文，从而获取 CPU 寄存器状态、系统错误码等，进行更深入的分析。
*   **二进制底层知识:**  `gumjs_callback_context_get_return_address` 函数使用了 `gum_backtracer_make_accurate` 来获取更精确的返回地址，这涉及到栈回溯的技术。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 在一个被拦截的函数的回调中，JavaScript 代码尝试访问 `this.returnAddress`。
    *   **预期输出:** `gumjs_callback_context_get_return_address` 会返回一个表示返回地址的 `NativePointer` 对象。
*   **用户或编程常见错误:**  尝试在回调之外访问回调上下文信息会导致错误。
*   **调试线索:** 用户在 Frida 脚本中访问拦截回调的 `this` 对象时，会触发这些 getter 函数。

**3. 提供 CPU 上下文 (CPU Context)**

*   **功能:** `GumQuickCpuContext` 允许 JavaScript 代码访问和修改 CPU 的寄存器状态。
*   **逆向方法关系:**  在 Frida 的拦截回调中，用户可以读取和修改 CPU 寄存器的值，例如修改函数的参数、返回值，甚至改变程序的执行流程。
*   **二进制底层知识:**  不同的 CPU 架构有不同的寄存器集合。`gumjs_cpu_context_entries` 定义了不同架构下需要暴露给 JavaScript 的寄存器。
*   **Linux/Android 内核及框架知识:**  理解不同架构的寄存器用途（例如，`sp` 是栈指针，`pc` 是程序计数器）是有效利用此功能的关键。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:** 在一个被拦截的函数的回调中，JavaScript 代码尝试读取 `this.context.cpuContext.pc` 的值。
    *   **预期输出:** `gumjs_callback_context_get_cpu_context` 和相关的 CPU 上下文 getter 函数会返回程序计数器的值。
*   **用户或编程常见错误:**  在只读的 CPU 上下文中尝试设置寄存器值会导致错误。
*   **调试线索:** 用户在 Frida 脚本中访问回调上下文的 `cpuContext` 属性，或者使用 `context.cpuContext.寄存器名 = 新值` 来修改寄存器时，会触发这些函数。

**4. 实现匹配模式 (Match Pattern)**

*   **功能:** `GumMatchPattern` 允许用户在 JavaScript 中创建和使用类似于通配符的字符串匹配模式。
*   **逆向方法关系:**  在 Frida 中，可以使用匹配模式来查找特定的模块、函数或内存地址。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  JavaScript 代码创建了一个 `MatchPattern` 对象，模式为 `"lib*.so"`。
    *   **预期输出:**  `gumjs_match_pattern_construct` 会创建一个 `GumMatchPattern` 对象，可以用于匹配以 "lib" 开头，以 ".so" 结尾的字符串。
*   **用户或编程常见错误:**  提供无效的匹配模式字符串会导致创建失败。
*   **调试线索:** 用户在 Frida 脚本中使用 `Module.findExportByName` 等函数时，可以传入匹配模式作为参数。

**5. 处理 Source Map**

*   **功能:** `GumSourceMap` 允许 Frida 将 JavaScript 代码的执行位置映射回原始的 TypeScript 或其他高级语言的源代码，方便调试。
*   **逆向方法关系:**  在逆向使用 Frida 编写的 JavaScript 代码时，Source Map 可以帮助开发者理解代码的原始逻辑。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  JavaScript 代码创建了一个 `SourceMap` 对象，并调用 `resolve` 方法传入一个行号和列号。
    *   **预期输出:**  `gumjs_source_map_resolve` 会根据 Source Map 的内容，返回原始源代码的文件名、行号、列号和符号名称。
*   **用户或编程常见错误:**  提供无效的 Source Map JSON 数据会导致创建失败。
*   **调试线索:**  Frida 通常会自动处理 Source Map，但用户也可以手动创建和使用 `SourceMap` 对象。

**6. 实现 Web Worker**

*   **功能:** `GumQuickWorker` 允许在 Frida 的 JavaScript 环境中创建和管理独立的执行线程，实现并发。
*   **逆向方法关系:**  在分析多线程的应用程序时，可以使用 Web Worker 在 Frida 脚本中模拟多线程行为或并行执行任务。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  JavaScript 代码创建了一个 `Worker` 对象，并传入一个包含工作线程代码的 URL 和一个消息处理函数。
    *   **预期输出:**  `gumjs_worker_construct` 会创建一个新的工作线程，并执行指定的代码。当主线程向工作线程发送消息时，工作线程的消息处理函数会被调用。
*   **用户或编程常见错误:**  在工作线程中访问某些 Frida 的全局对象可能会导致错误，因为它们不是线程安全的。
*   **调试线索:** 用户在 Frida 脚本中使用 `new Worker()` 创建工作线程时，会触发这些函数。

**7. 调度回调 (Scheduling Callbacks)**

*   **功能:**  Frida 提供了 `setTimeout` 和 `setInterval` 的实现，允许用户在 JavaScript 中设置延时执行或周期性执行的代码。
*   **逆向方法关系:**  在动态分析中，可以使用定时器来在特定时间点执行代码，例如在某个函数被调用一段时间后执行某些操作。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  JavaScript 代码调用 `setTimeout(function() { console.log("Hello"); }, 1000);`。
    *   **预期输出:**  `gum_quick_core_schedule_callback` 会创建一个定时器，1 秒后会调用指定的匿名函数打印 "Hello"。
*   **用户或编程常见错误:**  忘记取消定时器可能会导致资源泄漏。
*   **调试线索:** 用户在 Frida 脚本中使用 `setTimeout` 或 `setInterval` 时，会触发这些函数。

**8. 处理异常和消息 (Exception and Message Handling)**

*   **功能:**  Frida 允许 Native 代码向 JavaScript 端发送异常和消息，方便进行错误处理和信息传递。
*   **逆向方法关系:**  可以在 Frida 的 C 绑定代码中捕获异常并将其传递到 JavaScript 端进行处理，或者在 Native 代码中生成一些事件消息通知 JavaScript 端。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  Native 代码中发生了一个异常，并通过 Frida 的 API 将其传递到 JavaScript 端。
    *   **预期输出:**  `gum_quick_exception_sink_handle_exception` 会被调用，并将异常信息传递给用户定义的 JavaScript 异常处理回调函数。
*   **用户或编程常见错误:**  用户定义的异常处理回调函数可能会抛出新的异常，需要妥善处理。
*   **调试线索:**  Frida 的内部机制会调用这些 sink 函数来处理 Native 代码中产生的异常和消息。

**9. FFI (Foreign Function Interface) 支持**

*   **功能:**  Frida 允许在 JavaScript 中动态调用 Native 函数，这是其强大功能的基础。
*   **逆向方法关系:**  通过 FFI，可以调用目标进程中的任意函数，传递参数并获取返回值，实现与目标进程的深度交互。
*   **二进制底层知识:**  FFI 需要理解不同架构的函数调用约定 (例如，参数如何传递，返回值如何获取)。`ffi_type` 结构体用于描述 Native 函数的参数和返回值的类型。
*   **逻辑推理 (假设输入与输出):**
    *   **假设输入:**  JavaScript 代码使用 `new NativeFunction(address, 'void', ['int', 'pointer'])` 创建了一个 `NativeFunction` 对象，并传入一个地址和类型信息。然后调用该函数并传入整数和指针类型的参数。
    *   **预期输出:**  `gum_quick_value_to_ffi` 会将 JavaScript 的值转换为 Native 代码可以理解的格式，然后通过 libffi 调用指定的 Native 函数。`gum_quick_value_from_ffi` 会将 Native 函数的返回值转换回 JavaScript 的值。
*   **用户或编程常见错误:**  提供错误的参数类型或地址会导致程序崩溃。
*   **调试线索:** 用户在 Frida 脚本中使用 `NativeFunction` 或 `Interceptor.replace` 时，会涉及到 FFI 相关的函数。

**10. 原子 (Atoms) 管理**

*   **功能:**  QuickJS 使用原子来高效地存储和比较字符串。`gum_quick_core_setup_atoms` 用于创建常用的原子，`gum_quick_core_teardown_atoms` 用于释放它们。
*   **性能优化:** 使用原子可以减少字符串的创建和比较开销。
*   **调试线索:**  这些函数在 `GumQuickCore` 初始化和销毁时被调用，属于 Frida 的内部实现细节。

**总结本部分的功能**

总而言之，`frida/subprojects/frida-gum/bindings/gumjs/gumquickcore.c` 文件的第 5 部分是 Frida 中非常核心的一部分，它构建了 Frida 的 JavaScript 运行时环境与 Native 代码交互的关键桥梁。它提供了处理 Native 函数回调、访问上下文信息、操作 CPU 状态、实现匹配模式、处理 Source Map、支持 Web Worker、调度回调、处理异常和消息以及支持 FFI 的基础设施。这些功能共同构成了 Frida 强大的动态插桩能力，使其成为逆向工程、安全分析和动态调试的强大工具。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickcore.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第5部分，共6部分，请归纳一下它的功能

"""
allback_finalize (c);
}

static void
gum_quick_native_callback_finalize (GumQuickNativeCallback * callback)
{
  ffi_closure_free (callback->closure);

  while (callback->data != NULL)
  {
    GSList * head = callback->data;
    g_free (head->data);
    callback->data = g_slist_delete_link (callback->data, head);
  }
  g_free (callback->atypes);

  g_slice_free (GumQuickNativeCallback, callback);
}

static void
gum_quick_native_callback_invoke (ffi_cif * cif,
                                  void * return_value,
                                  void ** args,
                                  void * user_data)
{
  GumQuickNativeCallback * self = user_data;
  GumQuickCore * core = self->core;
  gint saved_system_error;
  guintptr return_address = 0;
  guintptr stack_pointer = 0;
  guintptr frame_pointer = 0;
  GumQuickScope scope;
  JSContext * ctx = core->ctx;
  ffi_type * rtype = cif->rtype;
  GumFFIValue * retval = return_value;
  GumInvocationContext * ic;
  GumQuickInvocationContext * jic = NULL;
  JSValue this_obj;
  GumQuickCallbackContext * jcc = NULL;
  int argc, i;
  JSValue * argv;
  JSValue result;

  saved_system_error = gum_thread_get_system_error ();

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

  _gum_quick_scope_enter (&scope, core);

  JS_DupValue (ctx, self->wrapper);

  if (rtype != &ffi_type_void)
  {
    /*
     * Ensure:
     * - high bits of values smaller than a pointer are cleared to zero
     * - we return something predictable in case of a JS exception
     */
    retval->v_pointer = NULL;
  }

  if (core->interceptor != NULL &&
      (ic = gum_interceptor_get_live_replacement_invocation (
        self->native_pointer.value)) != NULL)
  {
    jic = _gum_quick_interceptor_obtain_invocation_context (core->interceptor);
    _gum_quick_invocation_context_reset (jic, ic);

    this_obj = jic->wrapper;
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

    this_obj = gum_quick_callback_context_new (core, &cpu_context,
        &saved_system_error, return_address, &jcc);
  }

  argc = cif->nargs;
  argv = g_newa (JSValue, argc);

  for (i = 0; i != argc; i++)
    argv[i] = gum_quick_value_from_ffi (ctx, args[i], cif->arg_types[i], core);

  result = _gum_quick_scope_call (&scope, self->func, this_obj, argc, argv);

  for (i = 0; i != argc; i++)
    JS_FreeValue (ctx, argv[i]);

  if (jic != NULL)
  {
    _gum_quick_invocation_context_reset (jic, NULL);
    _gum_quick_interceptor_release_invocation_context (core->interceptor, jic);
  }

  if (jcc != NULL)
  {
    jcc->system_error = NULL;
    JS_FreeValue (ctx, jcc->cpu_context->wrapper);
    jcc->cpu_context = NULL;
    JS_FreeValue (ctx, jcc->wrapper);
  }

  if (!JS_IsException (result) && cif->rtype != &ffi_type_void)
  {
    if (!gum_quick_value_to_ffi (ctx, result, cif->rtype, core, retval))
      _gum_quick_scope_catch_and_emit (&scope);
  }
  JS_FreeValue (ctx, result);

  JS_FreeValue (ctx, self->wrapper);

  _gum_quick_scope_leave (&scope);

  gum_thread_set_system_error (saved_system_error);
}

GUMJS_DEFINE_FINALIZER (gumjs_callback_context_finalize)
{
  GumQuickCallbackContext * c;

  c = JS_GetOpaque (val, core->callback_context_class);
  if (c == NULL)
    return;

  g_slice_free (GumQuickCallbackContext, c);
}

static JSValue
gum_quick_callback_context_new (GumQuickCore * core,
                                GumCpuContext * cpu_context,
                                gint * system_error,
                                GumAddress raw_return_address,
                                GumQuickCallbackContext ** context)
{
  JSValue wrapper;
  GumQuickCallbackContext * jcc;
  JSContext * ctx = core->ctx;

  wrapper = JS_NewObjectClass (ctx, core->callback_context_class);

  jcc = g_slice_new (GumQuickCallbackContext);
  jcc->wrapper = wrapper;
  jcc->cpu_context = NULL;
  jcc->system_error = system_error;
  jcc->return_address = 0;
  jcc->raw_return_address = raw_return_address;
  jcc->initial_property_count = JS_GetOwnPropertyCountUnchecked (wrapper);

  _gum_quick_cpu_context_new (ctx, cpu_context, GUM_CPU_CONTEXT_READONLY,
      core, &jcc->cpu_context);

  JS_SetOpaque (wrapper, jcc);

  *context = jcc;

  return wrapper;
}

GUMJS_DEFINE_GETTER (gumjs_callback_context_get_return_address)
{
  GumQuickCallbackContext * self;

  if (!gum_quick_callback_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (self->return_address == 0)
  {
    GumCpuContext * cpu_context = self->cpu_context->handle;
    GumBacktracer * backtracer;

    backtracer = gum_backtracer_make_accurate ();

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

  return _gum_quick_native_pointer_new (ctx,
      GSIZE_TO_POINTER (self->return_address), core);
}

GUMJS_DEFINE_GETTER (gumjs_callback_context_get_cpu_context)
{
  GumQuickCallbackContext * self;

  if (!gum_quick_callback_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_DupValue (ctx, self->cpu_context->wrapper);
}

GUMJS_DEFINE_GETTER (gumjs_callback_context_get_system_error)
{
  GumQuickCallbackContext * self;

  if (!gum_quick_callback_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  return JS_NewInt32 (ctx, *self->system_error);
}

GUMJS_DEFINE_SETTER (gumjs_callback_context_set_system_error)
{
  GumQuickCallbackContext * self;
  gint value;

  if (!gum_quick_callback_context_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_int_get (ctx, val, &value))
    return JS_EXCEPTION;

  *self->system_error = value;

  return JS_UNDEFINED;
}

static gboolean
gum_quick_callback_context_get (JSContext * ctx,
                                JSValueConst val,
                                GumQuickCore * core,
                                GumQuickCallbackContext ** cc)
{
  GumQuickCallbackContext * c;

  if (!_gum_quick_unwrap (ctx, val, core->callback_context_class, core,
        (gpointer *) &c))
    return FALSE;

  if (c->cpu_context == NULL)
  {
    _gum_quick_throw_literal (ctx, "invalid operation");
    return FALSE;
  }

  *cc = c;
  return TRUE;
}

GUMJS_DEFINE_FINALIZER (gumjs_cpu_context_finalize)
{
  GumQuickCpuContext * c;

  c = JS_GetOpaque (val, core->cpu_context_class);
  if (c == NULL)
    return;

  g_slice_free (GumQuickCpuContext, c);
}

GUMJS_DEFINE_FUNCTION (gumjs_cpu_context_to_json)
{
  JSValue result;
  guint i;

  result = JS_NewObject (ctx);

  for (i = 0; i != G_N_ELEMENTS (gumjs_cpu_context_entries); i++)
  {
    const JSCFunctionListEntry * e = &gumjs_cpu_context_entries[i];
    JSValue val;

    if (e->def_type != JS_DEF_CGETSET)
      continue;

    val = JS_GetPropertyStr (ctx, this_val, e->name);
    if (JS_IsException (val))
      goto propagate_exception;
    JS_SetPropertyStr (ctx, result, e->name, val);
  }

  return result;

propagate_exception:
  {
    JS_FreeValue (ctx, result);

    return JS_EXCEPTION;
  }
}

static JSValue
gumjs_cpu_context_set_gpr (GumQuickCpuContext * self,
                           JSContext * ctx,
                           JSValueConst val,
                           gpointer * reg)
{
  if (self->access == GUM_CPU_CONTEXT_READONLY)
    return _gum_quick_throw_literal (ctx, "invalid operation");

  return _gum_quick_native_pointer_parse (ctx, val, self->core, reg)
      ? JS_UNDEFINED
      : JS_EXCEPTION;
}

static JSValue
gumjs_cpu_context_set_vector (GumQuickCpuContext * self,
                              JSContext * ctx,
                              JSValueConst val,
                              guint8 * bytes,
                              gsize size)
{
  GBytes * new_bytes;
  gconstpointer new_data;
  gsize new_size;

  if (self->access == GUM_CPU_CONTEXT_READONLY)
    return _gum_quick_throw_literal (ctx, "invalid operation");

  if (!_gum_quick_bytes_get (ctx, val, self->core, &new_bytes))
    return JS_EXCEPTION;

  new_data = g_bytes_get_data (new_bytes, &new_size);
  if (new_size != size)
    goto incorrect_size;

  memcpy (bytes, new_data, new_size);

  g_bytes_unref (new_bytes);

  return JS_UNDEFINED;

incorrect_size:
  {
    g_bytes_unref (new_bytes);
    return _gum_quick_throw_literal (ctx, "incorrect vector size");
  }
}

static JSValue
gumjs_cpu_context_set_double (GumQuickCpuContext * self,
                              JSContext * ctx,
                              JSValueConst val,
                              gdouble * d)
{
  if (self->access == GUM_CPU_CONTEXT_READONLY)
    return _gum_quick_throw_literal (ctx, "invalid operation");

  return _gum_quick_float64_get (ctx, val, d)
      ? JS_UNDEFINED
      : JS_EXCEPTION;
}

static JSValue
gumjs_cpu_context_set_float (GumQuickCpuContext * self,
                             JSContext * ctx,
                             JSValueConst val,
                             gfloat * f)
{
  gdouble d;

  if (self->access == GUM_CPU_CONTEXT_READONLY)
    return _gum_quick_throw_literal (ctx, "invalid operation");

  if (!_gum_quick_float64_get (ctx, val, &d))
    return JS_EXCEPTION;

  *f = (gfloat) d;

  return JS_UNDEFINED;
}

static JSValue
gumjs_cpu_context_set_flags (GumQuickCpuContext * self,
                             JSContext * ctx,
                             JSValueConst val,
                             gsize * f)
{
  return _gum_quick_size_get (ctx, val, self->core, f)
      ? JS_UNDEFINED
      : JS_EXCEPTION;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_match_pattern_construct)
{
  JSValue wrapper;
  const gchar * pattern_str;
  JSValue proto;
  GumMatchPattern * pattern;

  wrapper = JS_NULL;

  if (!_gum_quick_args_parse (args, "s", &pattern_str))
    goto propagate_exception;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, core->match_pattern_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  pattern = gum_match_pattern_new_from_string (pattern_str);
  if (pattern == NULL)
    goto invalid_match_pattern;

  JS_SetOpaque (wrapper, pattern);

  return wrapper;

invalid_match_pattern:
  {
    _gum_quick_throw_literal (ctx, "invalid match pattern");
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeValue (ctx, wrapper);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_match_pattern_finalize)
{
  GumMatchPattern * p;

  p = JS_GetOpaque (val, core->match_pattern_class);
  if (p == NULL)
    return;

  gum_match_pattern_unref (p);
}

static gboolean
gum_quick_source_map_get (JSContext * ctx,
                          JSValueConst val,
                          GumQuickCore * core,
                          GumSourceMap ** source_map)
{
  return _gum_quick_unwrap (ctx, val, core->source_map_class, core,
      (gpointer *) source_map);
}

static JSValue
gumjs_source_map_new (const gchar * json,
                      GumQuickCore * core)
{
  JSValue result;
  JSContext * ctx = core->ctx;
  JSValue json_val;

  json_val = JS_NewString (ctx, json);

  result = JS_CallConstructor (ctx, core->source_map_ctor, 1, &json_val);

  JS_FreeValue (ctx, json_val);

  return result;
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_source_map_construct)
{
  JSValue wrapper = JS_NULL;
  const gchar * json;
  JSValue proto;
  GumSourceMap * map;

  if (!_gum_quick_args_parse (args, "s", &json))
    goto propagate_exception;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, core->source_map_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  map = gum_source_map_new (json);
  if (map == NULL)
    goto invalid_source_map;

  JS_SetOpaque (wrapper, map);

  return wrapper;

invalid_source_map:
  {
    _gum_quick_throw_literal (ctx, "invalid source map");
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeValue (ctx, wrapper);

    return JS_EXCEPTION;
  }
}

GUMJS_DEFINE_FINALIZER (gumjs_source_map_finalize)
{
  GumSourceMap * m;

  m = JS_GetOpaque (val, core->source_map_class);
  if (m == NULL)
    return;

  g_object_unref (m);
}

GUMJS_DEFINE_FUNCTION (gumjs_source_map_resolve)
{
  GumSourceMap * self;
  guint line, column;
  const gchar * source, * name;

  if (!gum_quick_source_map_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (args->count == 1)
  {
    if (!_gum_quick_args_parse (args, "u", &line))
      return JS_EXCEPTION;
    column = G_MAXUINT;
  }
  else
  {
    if (!_gum_quick_args_parse (args, "uu", &line, &column))
      return JS_EXCEPTION;
  }

  if (gum_source_map_resolve (self, &line, &column, &source, &name))
  {
    JSValue pos;
    const int fl = JS_PROP_C_W_E;

    pos = JS_NewArray (ctx);
    JS_DefinePropertyValueUint32 (ctx, pos, 0, JS_NewString (ctx, source), fl);
    JS_DefinePropertyValueUint32 (ctx, pos, 1, JS_NewUint32 (ctx, line), fl);
    JS_DefinePropertyValueUint32 (ctx, pos, 2, JS_NewUint32 (ctx, column), fl);
    JS_DefinePropertyValueUint32 (ctx, pos, 3,
        (name != NULL) ? JS_NewString (ctx, name) : JS_NULL, fl);

    return pos;
  }
  else
  {
    return JS_NULL;
  }
}

static gboolean
gum_quick_worker_get (JSContext * ctx,
                      JSValueConst val,
                      GumQuickCore * core,
                      GumQuickWorker ** worker)
{
  return _gum_quick_unwrap (ctx, val, core->worker_class, core,
      (gpointer *) worker);
}

GUMJS_DEFINE_CONSTRUCTOR (gumjs_worker_construct)
{
  JSValue wrapper = JS_NULL;
  const gchar * url;
  JSValue on_message, proto;
  GumQuickWorker * worker;

  if (!_gum_quick_args_parse (args, "sF", &url, &on_message))
    goto propagate_exception;

  proto = JS_GetProperty (ctx, new_target,
      GUM_QUICK_CORE_ATOM (core, prototype));
  wrapper = JS_NewObjectProtoClass (ctx, proto, core->worker_class);
  JS_FreeValue (ctx, proto);
  if (JS_IsException (wrapper))
    goto propagate_exception;

  worker = _gum_quick_script_make_worker (core->script, url, on_message);
  if (worker == NULL)
    goto propagate_exception;

  JS_SetOpaque (wrapper, worker);
  JS_DefinePropertyValue (ctx, wrapper,
      GUM_QUICK_CORE_ATOM (core, resource),
      JS_DupValue (ctx, on_message),
      0);

  g_hash_table_add (core->workers, worker);

  return wrapper;

propagate_exception:
  {
    JS_FreeValue (ctx, wrapper);

    return JS_EXCEPTION;
  }
}

static void
gum_quick_worker_destroy (GumQuickWorker * worker)
{
  _gum_quick_worker_terminate (worker);
  _gum_quick_worker_unref (worker);
}

GUMJS_DEFINE_FUNCTION (gumjs_worker_terminate)
{
  GumQuickWorker * self;

  if (!gum_quick_worker_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  JS_SetOpaque (this_val, NULL);

  g_hash_table_remove (core->workers, self);

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_worker_post)
{
  GumQuickWorker * self;
  const char * message;
  GBytes * data;

  if (!gum_quick_worker_get (ctx, this_val, core, &self))
    return JS_EXCEPTION;

  if (!_gum_quick_args_parse (args, "sB?", &message, &data))
    return JS_EXCEPTION;

  _gum_quick_worker_post (self, message, data);

  return JS_UNDEFINED;
}

static JSValue
gum_quick_core_schedule_callback (GumQuickCore * self,
                                  GumQuickArgs * args,
                                  gboolean repeat)
{
  JSValue func;
  gsize delay;
  guint id;
  GSource * source;
  GumQuickScheduledCallback * callback;

  if (repeat)
  {
    if (!_gum_quick_args_parse (args, "FZ", &func, &delay))
      return JS_EXCEPTION;
  }
  else
  {
    delay = 0;
    if (!_gum_quick_args_parse (args, "F|Z", &func, &delay))
      return JS_EXCEPTION;
  }

  id = self->next_callback_id++;
  if (delay == 0)
    source = g_idle_source_new ();
  else
    source = g_timeout_source_new ((guint) delay);

  callback = gum_scheduled_callback_new (id, func, repeat, source, self);
  g_source_set_callback (source, (GSourceFunc) gum_scheduled_callback_invoke,
      callback, (GDestroyNotify) gum_scheduled_callback_free);

  g_hash_table_insert (self->scheduled_callbacks, GINT_TO_POINTER (id),
      callback);
  g_queue_push_tail (&self->current_scope->scheduled_sources, source);

  return JS_NewUint32 (self->ctx, id);
}

static GumQuickScheduledCallback *
gum_quick_core_try_steal_scheduled_callback (GumQuickCore * self,
                                             gint id)
{
  GumQuickScheduledCallback * callback;
  gpointer raw_id;

  raw_id = GINT_TO_POINTER (id);

  callback = g_hash_table_lookup (self->scheduled_callbacks, raw_id);
  if (callback == NULL)
    return NULL;

  g_hash_table_remove (self->scheduled_callbacks, raw_id);

  return callback;
}

static GumQuickScheduledCallback *
gum_scheduled_callback_new (guint id,
                            JSValueConst func,
                            gboolean repeat,
                            GSource * source,
                            GumQuickCore * core)
{
  GumQuickScheduledCallback * cb;

  cb = g_slice_new (GumQuickScheduledCallback);
  cb->id = id;
  cb->func = JS_DupValue (core->ctx, func);
  cb->repeat = repeat;
  cb->source = source;
  cb->core = core;

  return cb;
}

static void
gum_scheduled_callback_free (GumQuickScheduledCallback * callback)
{
  GumQuickCore * core = callback->core;
  GumQuickScope scope;

  _gum_quick_scope_enter (&scope, core);
  _gum_quick_core_unpin (core);
  JS_FreeValue (core->ctx, callback->func);
  _gum_quick_scope_leave (&scope);

  g_slice_free (GumQuickScheduledCallback, callback);
}

static gboolean
gum_scheduled_callback_invoke (GumQuickScheduledCallback * self)
{
  GumQuickCore * core = self->core;
  GumQuickScope scope;

  _gum_quick_scope_enter (&scope, self->core);

  _gum_quick_scope_call_void (&scope, self->func, JS_UNDEFINED, 0, NULL);

  if (!self->repeat)
  {
    if (gum_quick_core_try_steal_scheduled_callback (core, self->id) != NULL)
      _gum_quick_core_pin (core);
  }

  _gum_quick_scope_leave (&scope);

  return self->repeat;
}

static GumQuickExceptionSink *
gum_quick_exception_sink_new (JSValueConst callback,
                              GumQuickCore * core)
{
  GumQuickExceptionSink * sink;

  sink = g_slice_new (GumQuickExceptionSink);
  sink->callback = JS_DupValue (core->ctx, callback);
  sink->core = core;

  return sink;
}

static void
gum_quick_exception_sink_free (GumQuickExceptionSink * sink)
{
  JS_FreeValue (sink->core->ctx, sink->callback);

  g_slice_free (GumQuickExceptionSink, sink);
}

static void
gum_quick_exception_sink_handle_exception (GumQuickExceptionSink * self,
                                           JSValueConst exception)
{
  JSContext * ctx = self->core->ctx;
  JSValue result;

  result = JS_Call (ctx, self->callback, JS_UNDEFINED, 1, &exception);
  if (JS_IsException (result))
    _gum_quick_panic (ctx, "Error handler crashed");

  JS_FreeValue (ctx, result);
}

static GumQuickMessageSink *
gum_quick_message_sink_new (JSValueConst callback,
                            GumQuickCore * core)
{
  GumQuickMessageSink * sink;

  sink = g_slice_new (GumQuickMessageSink);
  sink->callback = JS_DupValue (core->ctx, callback);
  sink->core = core;

  return sink;
}

static void
gum_quick_message_sink_free (GumQuickMessageSink * sink)
{
  JS_FreeValue (sink->core->ctx, sink->callback);

  g_slice_free (GumQuickMessageSink, sink);
}

static void
gum_quick_message_sink_post (GumQuickMessageSink * self,
                             const gchar * message,
                             GBytes * data,
                             GumQuickScope * scope)
{
  JSContext * ctx = self->core->ctx;
  JSValue argv[2];

  argv[0] = JS_NewString (ctx, message);

  if (data != NULL)
  {
    gpointer data_buffer;
    gsize data_size;

    data_buffer = g_bytes_unref_to_data (data, &data_size);

    argv[1] = JS_NewArrayBuffer (ctx, data_buffer, data_size,
        _gum_quick_array_buffer_free, data_buffer, FALSE);
  }
  else
  {
    argv[1] = JS_NULL;
  }

  _gum_quick_scope_call_void (scope, self->callback, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[1]);
  JS_FreeValue (ctx, argv[0]);
}

static gboolean
gum_quick_ffi_type_get (JSContext * ctx,
                        JSValueConst val,
                        GumQuickCore * core,
                        ffi_type ** type,
                        GSList ** data)
{
  gboolean success = FALSE;
  JSValue field_value;

  if (JS_IsString (val))
  {
    const gchar * type_name = JS_ToCString (ctx, val);
    success = gum_ffi_try_get_type_by_name (type_name, type);
    JS_FreeCString (ctx, type_name);
  }
  else if (JS_IsArray (ctx, val))
  {
    guint length, i;
    ffi_type ** fields, * struct_type;

    if (!_gum_quick_array_get_length (ctx, val, core, &length))
      return FALSE;

    fields = g_new (ffi_type *, length + 1);
    *data = g_slist_prepend (*data, fields);

    for (i = 0; i != length; i++)
    {
      field_value = JS_GetPropertyUint32 (ctx, val, i);

      if (!gum_quick_ffi_type_get (ctx, field_value, core, &fields[i], data))
        goto invalid_field_value;

      JS_FreeValue (ctx, field_value);
    }

    fields[length] = NULL;

    struct_type = g_new0 (ffi_type, 1);
    struct_type->type = FFI_TYPE_STRUCT;
    struct_type->elements = fields;
    *data = g_slist_prepend (*data, struct_type);

    *type = struct_type;
    success = TRUE;
  }

  if (!success)
    _gum_quick_throw_literal (ctx, "invalid type specified");

  return success;

invalid_field_value:
  {
    JS_FreeValue (ctx, field_value);

    return FALSE;
  }
}

static gboolean
gum_quick_ffi_abi_get (JSContext * ctx,
                       const gchar * name,
                       ffi_abi * abi)
{
  if (gum_ffi_try_get_abi_by_name (name, abi))
    return TRUE;

  _gum_quick_throw_literal (ctx, "invalid abi specified");
  return FALSE;
}

static gboolean
gum_quick_value_to_ffi (JSContext * ctx,
                        JSValueConst sval,
                        const ffi_type * type,
                        GumQuickCore * core,
                        GumFFIValue * val)
{
  gint i;
  guint u;
  gint64 i64;
  guint64 u64;
  gdouble d;

  if (type == &ffi_type_void)
  {
    val->v_pointer = NULL;
  }
  else if (type == &ffi_type_pointer)
  {
    if (!_gum_quick_native_pointer_get (ctx, sval, core, &val->v_pointer))
      return FALSE;
  }
  else if (type == &ffi_type_sint8)
  {
    if (!_gum_quick_int_get (ctx, sval, &i))
      return FALSE;
    val->v_sint8 = i;
  }
  else if (type == &ffi_type_uint8)
  {
    if (!_gum_quick_uint_get (ctx, sval, &u))
      return FALSE;
    val->v_uint8 = u;
  }
  else if (type == &ffi_type_sint16)
  {
    if (!_gum_quick_int_get (ctx, sval, &i))
      return FALSE;
    val->v_sint16 = i;
  }
  else if (type == &ffi_type_uint16)
  {
    if (!_gum_quick_uint_get (ctx, sval, &u))
      return FALSE;
    val->v_uint16 = u;
  }
  else if (type == &ffi_type_sint32)
  {
    if (!_gum_quick_int_get (ctx, sval, &i))
      return FALSE;
    val->v_sint32 = i;
  }
  else if (type == &ffi_type_uint32)
  {
    if (!_gum_quick_uint_get (ctx, sval, &u))
      return FALSE;
    val->v_uint32 = u;
  }
  else if (type == &ffi_type_sint64)
  {
    if (!_gum_quick_int64_get (ctx, sval, core, &i64))
      return FALSE;
    val->v_sint64 = i64;
  }
  else if (type == &ffi_type_uint64)
  {
    if (!_gum_quick_uint64_get (ctx, sval, core, &u64))
      return FALSE;
    val->v_uint64 = u64;
  }
  else if (type == &gum_ffi_type_size_t)
  {
    if (!_gum_quick_uint64_get (ctx, sval, core, &u64))
      return FALSE;

    switch (type->size)
    {
      case 8:
        val->v_uint64 = u64;
        break;
      case 4:
        val->v_uint32 = u64;
        break;
      case 2:
        val->v_uint16 = u64;
        break;
      default:
        g_assert_not_reached ();
    }
  }
  else if (type == &gum_ffi_type_ssize_t)
  {
    if (!_gum_quick_int64_get (ctx, sval, core, &i64))
      return FALSE;

    switch (type->size)
    {
      case 8:
        val->v_sint64 = i64;
        break;
      case 4:
        val->v_sint32 = i64;
        break;
      case 2:
        val->v_sint16 = i64;
        break;
      default:
        g_assert_not_reached ();
    }
  }
  else if (type == &ffi_type_float)
  {
    if (!_gum_quick_float64_get (ctx, sval, &d))
      return FALSE;
    val->v_float = d;
  }
  else if (type == &ffi_type_double)
  {
    if (!_gum_quick_float64_get (ctx, sval, &d))
      return FALSE;
    val->v_double = d;
  }
  else if (type->type == FFI_TYPE_STRUCT)
  {
    ffi_type ** const field_types = type->elements, ** t;
    guint length, expected_length, field_index;
    guint8 * field_values;
    gsize offset;

    if (!_gum_quick_array_get_length (ctx, sval, core, &length))
      return FALSE;

    expected_length = 0;
    for (t = field_types; *t != NULL; t++)
      expected_length++;

    if (length != expected_length)
      return FALSE;

    field_values = (guint8 *) val;
    offset = 0;

    for (field_index = 0; field_index != length; field_index++)
    {
      const ffi_type * field_type = field_types[field_index];
      GumFFIValue * field_val;
      JSValue field_sval;
      gboolean valid;

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);

      field_val = (GumFFIValue *) (field_values + offset);

      field_sval = JS_GetPropertyUint32 (ctx, sval, field_index);
      if (JS_IsException (field_sval))
        return FALSE;

      valid =
          gum_quick_value_to_ffi (ctx, field_sval, field_type, core, field_val);

      JS_FreeValue (ctx, field_sval);

      if (!valid)
        return FALSE;

      offset += field_type->size;
    }
  }
  else
  {
    g_assert_not_reached ();
  }

  return TRUE;
}

static JSValue
gum_quick_value_from_ffi (JSContext * ctx,
                          const GumFFIValue * val,
                          const ffi_type * type,
                          GumQuickCore * core)
{
  if (type == &ffi_type_void)
  {
    return JS_UNDEFINED;
  }
  else if (type == &ffi_type_pointer)
  {
    return _gum_quick_native_pointer_new (ctx, val->v_pointer, core);
  }
  else if (type == &ffi_type_sint8)
  {
    return JS_NewInt32 (ctx, val->v_sint8);
  }
  else if (type == &ffi_type_uint8)
  {
    return JS_NewUint32 (ctx, val->v_uint8);
  }
  else if (type == &ffi_type_sint16)
  {
    return JS_NewInt32 (ctx, val->v_sint16);
  }
  else if (type == &ffi_type_uint16)
  {
    return JS_NewUint32 (ctx, val->v_uint16);
  }
  else if (type == &ffi_type_sint32)
  {
    return JS_NewInt32 (ctx, val->v_sint32);
  }
  else if (type == &ffi_type_uint32)
  {
    return JS_NewUint32 (ctx, val->v_uint32);
  }
  else if (type == &ffi_type_sint64)
  {
    return _gum_quick_int64_new (ctx, val->v_sint64, core);
  }
  else if (type == &ffi_type_uint64)
  {
    return _gum_quick_uint64_new (ctx, val->v_uint64, core);
  }
  else if (type == &gum_ffi_type_size_t)
  {
    guint64 u64;

    switch (type->size)
    {
      case 8:
        u64 = val->v_uint64;
        break;
      case 4:
        u64 = val->v_uint32;
        break;
      case 2:
        u64 = val->v_uint16;
        break;
      default:
        u64 = 0;
        g_assert_not_reached ();
    }

    return _gum_quick_uint64_new (ctx, u64, core);
  }
  else if (type == &gum_ffi_type_ssize_t)
  {
    gint64 i64;

    switch (type->size)
    {
      case 8:
        i64 = val->v_sint64;
        break;
      case 4:
        i64 = val->v_sint32;
        break;
      case 2:
        i64 = val->v_sint16;
        break;
      default:
        i64 = 0;
        g_assert_not_reached ();
    }

    return _gum_quick_int64_new (ctx, i64, core);
  }
  else if (type == &ffi_type_float)
  {
    return JS_NewFloat64 (ctx, val->v_float);
  }
  else if (type == &ffi_type_double)
  {
    return JS_NewFloat64 (ctx, val->v_double);
  }
  else if (type->type == FFI_TYPE_STRUCT)
  {
    ffi_type ** const field_types = type->elements, ** t;
    guint length, i;
    const guint8 * field_values;
    gsize offset;
    JSValue field_svalues;

    length = 0;
    for (t = field_types; *t != NULL; t++)
      length++;

    field_values = (const guint8 *) val;
    offset = 0;

    field_svalues = JS_NewArray (ctx);

    for (i = 0; i != length; i++)
    {
      const ffi_type * field_type = field_types[i];
      const GumFFIValue * field_val;
      JSValue field_sval;

      offset = GUM_ALIGN_SIZE (offset, field_type->alignment);
      field_val = (const GumFFIValue *) (field_values + offset);

      field_sval = gum_quick_value_from_ffi (ctx, field_val, field_type, core);

      JS_DefinePropertyValueUint32 (ctx, field_svalues, i, field_sval,
          JS_PROP_C_W_E);

      offset += field_type->size;
    }

    return field_svalues;
  }
  else
  {
    g_assert_not_reached ();
  }
}

static void
gum_quick_core_setup_atoms (GumQuickCore * self)
{
  JSContext * ctx = self->ctx;

#define GUM_SETUP_ATOM(id) \
    GUM_SETUP_ATOM_NAMED (id, G_STRINGIFY (id))
#define GUM_SETUP_ATOM_NAMED(id, name) \
    GUM_QUICK_CORE_ATOM (self, id) = JS_NewAtom (ctx, name)

  GUM_SETUP_ATOM (abi);
  GUM_SETUP_ATOM (access);
  GUM_SETUP_ATOM (address);
  GUM_SETUP_ATOM (autoClose);
  GUM_SETUP_ATOM (base);
  GUM_SETUP_ATOM_NAMED (cachedInput, "$i");
  GUM_SETUP_ATOM_NAMED (cachedOutput, "$o");
  GUM_SETUP_ATOM (context);
  GUM_SETUP_ATOM (exceptions);
  GUM_SETUP_ATOM (file);
  GUM_SETUP_ATOM (handle);
  GUM_SETUP_ATOM (id);
  GUM_SETUP_ATOM (ip);
  GUM_SETUP_ATOM (isGlobal);
  GUM_SETUP_ATOM (length);
  GUM_SETUP_ATOM (memory);
  GUM_SETUP_ATOM (message);
  GUM_SETUP_ATOM (module);
  GUM_SETUP_ATOM (name);
  GUM_SETUP_ATOM (nativeContext);
  GUM_SETUP_ATOM (offset);
  GUM_SETUP_ATOM (operation);
  GUM_SETUP_ATOM (path);
  GUM_SETUP_ATOM (pc);
  GUM_SETUP_ATOM (port);
  GUM_SETUP_ATOM (protection);
  GUM_SETUP_ATOM (prototype);
  GUM_SETUP_ATOM (read);
  GUM_SETUP_ATOM_NAMED (resource, "$r");
  GUM_SETUP_ATOM (scheduling);
  GUM_SETUP_ATOM (section);
  GUM_SETUP_ATOM (size);
  GUM_SETUP_ATOM (slot);
  GUM_SETUP_ATOM (state);
  GUM_SETUP_ATOM_NAMED (system_error, GUMJS_SYSTEM_ERROR_FIELD);
  GUM_SETUP_ATOM (toolchain);
  GUM_SETUP_ATOM (traps);
  GUM_SETUP_ATOM (type);
  GUM_SETUP_ATOM (value);
  GUM_SETUP_ATOM (written);

#if defined (HAVE_I386)
  GUM_SETUP_ATOM (disp);
  GUM_SETUP_ATOM (index);
  GUM_SETUP_ATOM (scale);
  GUM_SETUP_ATOM (segment);
#elif defined (HAVE_ARM)
  GUM_SETUP_ATOM (disp);
  GUM_SETUP_ATOM (index);
  GUM_SETUP_ATOM (scale);
  GUM_SETUP_ATOM (shift);
  GUM_SETUP_ATOM (subtracted);
  GUM_SETUP_ATOM (vectorIndex);
#elif defined (HAVE_ARM64)
  GUM_SETUP_ATOM (disp);
  GUM_SETUP_ATOM (ext);
  GUM_SETUP_ATOM (index);
  GUM_SETUP_ATOM (shift);
  GUM_SETUP_ATOM (vas);
  GUM_SETUP_ATOM (vectorIndex);
#elif defined (HAVE_MIPS)
  GUM_SETUP_ATOM (disp);
#endif

#undef GUM_SETUP_ATOM
}

static void
gum_quick_core_teardown_atoms (GumQuickCore * self)
{
  JSContext * ctx = self->ctx;

#define GUM_TEARDOWN_ATOM(id) \
    JS_FreeAtom (ctx, GUM_QUICK_CORE_ATOM (self, id)); \
    GUM_QUICK_CORE_ATOM (self, id) = JS_ATOM_NULL

  GUM_TEARDOWN_ATOM (abi);
  GUM_TEARDOWN_ATOM
"""


```