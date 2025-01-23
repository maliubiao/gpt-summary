Response:
Let's break down the thought process for analyzing this C code snippet from Frida.

**1. Initial Understanding of the Context:**

The prompt clearly states this is part of Frida's dynamic instrumentation tool, specifically within the `frida-gum` library and the `gumjs` bindings. The filename `gumquickvalue.c` suggests it deals with quickly converting Gum data structures (likely internal Frida representations) into JavaScript values, and vice-versa. The "Part 2" indicates there's a preceding part with related functionality.

**2. High-Level Goal Identification:**

The primary function of this code is to bridge the gap between Frida's C++ core (Gum) and the JavaScript environment where Frida scripts are executed. It handles the serialization and deserialization of various data types.

**3. Functional Breakdown (Iterating through the code):**

The most efficient way to understand the functionality is to go through the code function by function, noting the purpose and data types involved.

* **`_gum_quick_thread_state_to_string`:**  Simple enum-to-string conversion. Relatively straightforward.

* **`_gum_quick_range_details_new`:** Creates a JavaScript object representing `GumRangeDetails`. It includes memory range information and optionally file mapping details. This is a key structure in Frida, representing memory regions.

* **`_gum_quick_memory_range_new`:** Creates a JS object for `GumMemoryRange` (base address and size). A building block for the previous function.

* **`_gum_quick_memory_ranges_get`:**  Handles getting one or more `GumMemoryRange` objects from a JS value (either a single object or an array). Important for receiving memory range information from user scripts. Error handling (`goto`) is evident.

* **`_gum_quick_memory_range_get`:**  Extracts the `GumMemoryRange` data from a JS object.

* **`_gum_quick_page_protection_new`:** Converts `GumPageProtection` (read/write/execute) to a string like "rwx".

* **`_gum_quick_page_protection_get`:**  Parses a protection string back into `GumPageProtection`.

* **`_gum_quick_memory_operation_new`:** Enum-to-string for memory operations (read, write, execute).

* **`_gum_quick_array_get_length`:** Gets the length of a JavaScript array.

* **`_gum_quick_array_buffer_free`:**  A callback for freeing memory associated with array buffers.

* **`_gum_quick_process_match_result`:**  Handles the result of a matching operation, allowing the JS side to signal "stop" or indicate an error.

* **`_gum_quick_maybe_call_on_complete`:**  Calls a JS function provided as a callback.

* **`_gum_quick_exception_details_new`:** Creates a detailed JS object representing a `GumExceptionDetails` structure. This is crucial for reporting exceptions encountered during instrumentation.

* **`_gum_quick_error_new`:** Creates a basic JavaScript Error object.

* **`_gum_quick_error_new_take_error`:**  Handles converting a `GError` (GLib error type) to a JavaScript Error.

* **`_gum_quick_unwrap` and `_gum_quick_try_unwrap`:**  These are essential for safely casting opaque JavaScript objects back to their underlying C++ types. They enforce type safety.

* **`_gum_quick_create_class` and `_gum_quick_create_subclass`:**  Functions for registering C++ classes with the JavaScript engine so that instances can be created and interacted with from JS.

* **`gum_get_class_id_for_class_def` and `gum_deinit_class_ids`:**  Helper functions for managing class IDs, ensuring uniqueness.

* **`_gum_quick_throw`, `_gum_quick_throw_literal`, `_gum_quick_throw_error`, `_gum_quick_throw_native`:**  Functions for throwing JavaScript exceptions from C code. `_gum_quick_throw_native` is specifically for Frida exceptions.

* **`gum_exception_type_to_string`, `gum_thread_state_to_string`, `gum_memory_operation_to_string`:**  Helper enums to strings for exception types, thread states, and memory operations.

**4. Identifying Key Concepts and Relationships:**

As the function analysis progresses, patterns emerge:

* **Serialization/Deserialization:**  Many functions are about converting between C structures and JS objects.
* **Error Handling:**  Consistent use of `JS_IsException`, `goto`, and throwing errors.
* **Type Safety:** The `_gum_quick_unwrap` functions highlight the importance of ensuring the correct C++ type is associated with a JS object.
* **Object Representation:** The code defines how various Frida concepts (memory ranges, exceptions, etc.) are represented as JavaScript objects.

**5. Answering the Specific Questions:**

With the functional breakdown, it becomes easier to answer the prompt's questions:

* **Functionality:** Summarize the purpose of each function and the overall goal of the file.
* **Relationship to Reversing:** Identify functions directly related to inspecting memory, handling exceptions, and interacting with process state.
* **Binary/Kernel/Framework Knowledge:** Point out structures and functions that interact with low-level concepts like memory protection, addresses, and operating system primitives.
* **Logical Inference:**  Look for conditional logic and describe potential input/output scenarios.
* **User Errors:** Consider common mistakes developers might make when interacting with the API exposed by this code.
* **User Operations (Debugging Clue):** Trace how a user action in a Frida script might lead to the execution of these functions.

**6. Structuring the Answer:**

Organize the findings logically, starting with a high-level summary and then going into more detail for each aspect requested by the prompt. Use clear headings and examples.

**7. Part 2 Synthesis:**

The final step for "Part 2" is to synthesize the functions in this specific snippet. Focus on the core responsibilities:  handling memory ranges (getting and setting), dealing with memory protection, and processing match results and callbacks. Emphasize how these functions contribute to Frida's overall ability to interact with a target process's memory.

**Self-Correction/Refinement during the process:**

* **Initial Overgeneralization:**  Initially, I might just say "it converts C to JS."  But as I go through the functions, I refine this to be more specific: "it converts specific Gum data structures related to memory, exceptions, and thread states."
* **Missing Connections:**  I might initially miss the connection between `_gum_quick_unwrap` and type safety. Recognizing the use of `JSClassID` helps solidify this understanding.
* **Clarity of Examples:** Ensure the examples are concrete and illustrate the concept being explained. For instance, showing a JS object representing a memory range.

By following this systematic approach, combining code analysis with an understanding of Frida's purpose, it's possible to generate a comprehensive and accurate explanation of the provided C code.好的，我们来归纳一下 `frida/subprojects/frida-gum/bindings/gumjs/gumquickvalue.c` 文件（第二部分）的功能。

**总体功能归纳 (基于第二部分的代码):**

这部分代码主要负责将 Frida-gum 内部的 C 数据结构快速转换为 JavaScript 可以理解和操作的值（JSValue），以及反向地将 JavaScript 值转换为 C 数据结构。它专注于处理与内存、异常、线程状态等相关的核心概念。

**具体功能点:**

1. **内存范围 (Memory Ranges) 的转换:**
   - `_gum_quick_memory_ranges_get`:  将 JavaScript 中的一个内存范围对象或一个包含内存范围对象的数组转换为 C 结构 `GumMemoryRange` 的数组。这使得 JavaScript 代码可以传递内存范围信息给 Frida-gum 的 C 代码。
   - `_gum_quick_memory_range_get`: 将 JavaScript 中的一个内存范围对象转换为 C 结构 `GumMemoryRange`。

2. **内存保护 (Memory Protection) 的转换:**
   - `_gum_quick_page_protection_new`: 将 C 结构 `GumPageProtection`（表示内存页的读、写、执行权限）转换为 JavaScript 字符串 (例如 "rwx")。
   - `_gum_quick_page_protection_get`: 将 JavaScript 字符串形式的内存保护信息转换为 C 结构 `GumPageProtection`。

3. **内存操作 (Memory Operation) 的转换:**
   - `_gum_quick_memory_operation_new`: 将 C 枚举 `GumMemoryOperation`（如读、写、执行）转换为 JavaScript 字符串。

4. **数组长度获取:**
   - `_gum_quick_array_get_length`: 获取 JavaScript 数组的长度。

5. **数组缓冲区释放:**
   - `_gum_quick_array_buffer_free`:  用于释放 JavaScript 数组缓冲区相关的内存（在 C 侧分配）。

6. **匹配结果处理:**
   - `_gum_quick_process_match_result`: 处理 JavaScript 函数返回的匹配结果，允许 JavaScript 代码指示 Frida-gum 的匹配操作是继续、停止还是发生了错误。

7. **可选的回调函数调用:**
   - `_gum_quick_maybe_call_on_complete`:  在特定情况下调用 JavaScript 提供的完成回调函数。

8. **异常详情 (Exception Details) 的转换:**
   - `_gum_quick_exception_details_new`: 将 C 结构 `GumExceptionDetails`（包含异常类型、地址、上下文等信息）转换为一个详细的 JavaScript 错误对象。

9. **创建 JavaScript 错误对象:**
   - `_gum_quick_error_new`: 创建一个基本的 JavaScript 错误对象，包含错误消息。
   - `_gum_quick_error_new_take_error`: 将 C 的 `GError` 对象转换为 JavaScript 错误对象。

10. **类型解包 (Unwrapping) 和安全类型检查:**
    - `_gum_quick_unwrap`:  将一个 JavaScript 值（期望是一个特定 C++ 对象的包装器）解包为指向该 C++ 对象的指针。如果类型不匹配，则抛出 JavaScript 异常。
    - `_gum_quick_try_unwrap`:  尝试解包一个 JavaScript 值，如果类型匹配则返回指向 C++ 对象的指针，否则返回 `FALSE`。

11. **类 (Class) 的创建和子类化:**
    - `_gum_quick_create_class`: 在 JavaScript 环境中注册一个新的 C++ 类，使其可以通过 JavaScript 进行实例化和操作。
    - `_gum_quick_create_subclass`: 创建一个 C++ 类的子类并在 JavaScript 环境中注册。

12. **获取类 ID:**
    - `gum_get_class_id_for_class_def`: 为 C++ 类的定义获取一个唯一的 ID。
    - `gum_deinit_class_ids`:  清理类 ID 相关的资源。

13. **抛出 JavaScript 异常:**
    - `_gum_quick_throw`: 使用格式化字符串创建一个 JavaScript 错误并抛出。
    - `_gum_quick_throw_literal`: 使用预先定义的消息创建一个 JavaScript 错误并抛出。
    - `_gum_quick_throw_error`: 将一个 C 的 `GError` 对象转换为 JavaScript 错误并抛出。
    - `_gum_quick_throw_native`: 将一个 C 的 `GumExceptionDetails` 对象转换为 JavaScript 异常并抛出。

14. **枚举值到字符串的转换辅助函数:**
    - `gum_exception_type_to_string`: 将 `GumExceptionType` 枚举值转换为字符串。
    - `gum_thread_state_to_string`: 将 `GumThreadState` 枚举值转换为字符串。
    - `gum_memory_operation_to_string`: 将 `GumMemoryOperation` 枚举值转换为字符串。

**与逆向方法的关系及举例说明:**

- **内存范围操作:** 在逆向工程中，经常需要操作和检查目标进程的内存。这些函数允许 Frida 脚本获取和传递内存范围信息，例如要 hook 的函数的地址范围、要读取或写入的内存区域等。
    - **例子:** 一个 Frida 脚本可能需要获取目标进程中所有模块的内存映射，并对特定模块的 `.text` 段进行扫描以查找特定的指令模式。`_gum_quick_memory_ranges_get` 可以将 C 代码返回的内存映射信息转换为 JavaScript 数组，供脚本进一步处理。

- **异常处理:** 逆向过程中经常会遇到异常，例如访问无效内存地址。这些函数可以将目标进程中发生的异常信息（包括异常类型和发生地址）转换为 JavaScript 对象，方便脚本进行分析和处理。
    - **例子:** 当目标程序触发了一个访问违规异常时，Frida 可以捕获这个异常，并使用 `_gum_quick_exception_details_new` 将异常的详细信息（如引发异常的地址、操作类型等）传递给 JavaScript 脚本，脚本可以记录这些信息或采取进一步的行动。

- **内存保护修改:** 在某些逆向场景下，可能需要修改进程的内存保护属性，例如将只读内存页设置为可写，以便进行代码注入或修改。`_gum_quick_page_protection_new` 和 `_gum_quick_page_protection_get` 用于在 JavaScript 和 C 之间转换内存保护信息。
    - **例子:** Frida 脚本可以使用 `Memory.protect()` 函数来修改内存页的保护属性。这个函数最终会调用到 C 代码，而 `_gum_quick_page_protection_get` 就负责将 JavaScript 传递的保护字符串（如 "rwx"）转换为 C 的 `GumPageProtection` 枚举。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

- **内存地址和大小 (`GumMemoryRange`):**  `GumMemoryRange` 结构直接对应于进程地址空间中的一块连续内存区域，其 `base_address` 和 `size` 属性是二进制层面的概念。这与操作系统如何管理内存密切相关。
    - **例子:** 在 Linux 或 Android 中，进程的内存空间被划分为不同的段（如代码段、数据段、堆、栈）。`GumMemoryRange` 可以表示这些段的起始地址和大小。

- **内存保护属性 (`GumPageProtection`):**  `GumPageProtection` 直接映射到操作系统提供的内存保护机制，例如 Linux 的 `mprotect` 系统调用或 Android 内核中的相关机制。这些机制控制着内存页的访问权限。
    - **例子:**  `GUM_PAGE_READ`, `GUM_PAGE_WRITE`, `GUM_PAGE_EXECUTE` 这些常量对应于操作系统中用于设置内存页读、写、执行权限的标志位。

- **异常类型 (`GumExceptionType`):**  `GumExceptionType` 枚举列出的异常类型，如 `GUM_EXCEPTION_ACCESS_VIOLATION` 或 `GUM_EXCEPTION_BREAKPOINT`，直接对应于操作系统或处理器架构定义的异常或信号。
    - **例子:**  `GUM_EXCEPTION_ACCESS_VIOLATION` 在 Linux 上可能对应于 `SIGSEGV` 信号，表示进程尝试访问其无权访问的内存区域。

- **线程状态 (`GumThreadState`):**  `GumThreadState` 反映了操作系统对线程状态的抽象，例如运行、停止、等待等。这些状态是操作系统内核调度的基础。
    - **例子:**  在 Linux 或 Android 中，线程可能处于 `TASK_RUNNING`（运行）、`TASK_INTERRUPTIBLE`（可中断睡眠）等状态，这些状态会影响 Frida 对线程的监控和操作。

**逻辑推理的假设输入与输出:**

- **假设输入:** 一个 JavaScript 对象 `{ base: ptr("0x7fff0000"), size: 4096 }` 被传递给一个期望 `GumMemoryRange` 的 Frida API。
- **输出:**  `_gum_quick_memory_range_get` 函数会将这个 JavaScript 对象解析，并填充一个 C 结构 `GumMemoryRange`，其中 `range->base_address` 将是 `0x7fff0000`， `range->size` 将是 `4096`。

- **假设输入:**  一个 JavaScript字符串 `"r-x"` 被传递给一个期望内存保护信息的 Frida API。
- **输出:** `_gum_quick_page_protection_get` 函数会将这个字符串解析，并将 `prot` 指向的 `GumPageProtection` 值设置为 `GUM_PAGE_READ | GUM_PAGE_EXECUTE`。

**涉及用户或者编程常见的使用错误及举例说明:**

- **类型错误:** 用户可能在 JavaScript 中传递了错误类型的数据，例如期望一个内存范围对象，但却传递了一个数字或字符串。
    - **例子:**  如果一个 Frida 函数期望接收一个内存范围对象，用户却传递了 `"{ start: 0x1000, end: 0x2000 }"`（缺少 `base` 和 `size` 属性），`_gum_quick_memory_range_get` 将会失败并抛出一个 JavaScript 异常，提示期望一个 range 对象。

- **无效的内存保护字符串:** 用户可能传递了无法识别的内存保护字符串。
    - **例子:**  如果用户传递了 `"rwz"` 作为内存保护字符串，`_gum_quick_page_protection_get` 会检测到 `'z'` 是无效字符，并抛出一个 JavaScript 异常，提示期望一个指定内存保护的字符串。

- **尝试解包错误类型的对象:** 用户可能尝试将一个 JavaScript 对象解包为错误的 C++ 类型。
    - **例子:** 如果用户尝试使用 `_gum_quick_unwrap` 将一个表示线程对象的 JavaScript 值解包为 `GumMemoryRange` 类型的指针，`_gum_quick_unwrap` 将会检查类型不匹配并抛出一个 `TypeError`。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida 脚本:** 用户编写 JavaScript 代码，使用 Frida 提供的 API 来进行动态 instrumentation。

2. **调用 Frida API:**  脚本中调用了 Frida 提供的 JavaScript API，例如 `Memory.readByteArray(address, length)`，`Process.enumerateModules()`，或者设置 hook 时传递内存地址等。

3. **API 调用传递到 GumJS:** 这些 JavaScript API 的实现会调用到 Frida-gum 的 JavaScript 绑定层（GumJS）。

4. **需要转换数据类型:** 当需要在 JavaScript 和 Frida-gum 的 C 代码之间传递数据时，就需要进行类型转换。例如，`Process.enumerateModules()` 返回的模块信息（包括内存范围）需要从 C 的数据结构转换为 JavaScript 对象。反之，用户在 JavaScript 中指定的内存地址或保护属性需要转换为 C 的数据结构。

5. **`gumquickvalue.c` 中的函数被调用:**  在这个过程中，`gumquickvalue.c` 文件中的函数就被调用来执行这些转换。例如：
   - 当 `Process.enumerateModules()` 被调用时，C 代码返回的 `GumModuleDetails` 结构中的内存范围信息会通过 `_gum_quick_range_details_new` 和 `_gum_quick_memory_range_new` 转换为 JavaScript 对象。
   - 当用户使用 `Memory.protect(address, size, protection)` 时，JavaScript 传递的 `protection` 字符串会通过 `_gum_quick_page_protection_get` 转换为 C 的 `GumPageProtection` 枚举。
   - 当 Frida 捕获到异常时，`_gum_quick_exception_details_new` 会被调用来将异常信息转换为 JavaScript 错误对象，以便脚本可以捕获和处理。

因此，当你在调试 Frida 脚本时，如果遇到了与内存范围、内存保护、异常处理等相关的问题，并且堆栈信息指向了 `gumquickvalue.c` 文件中的这些函数，那么很可能是在 JavaScript 和 C 代码之间进行数据类型转换时出现了问题，例如数据类型不匹配、数据格式错误等。理解 `gumquickvalue.c` 的功能可以帮助你更好地理解 Frida 的内部机制，并更有效地调试你的 Frida 脚本。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickvalue.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
x, gum_thread_state_to_string (state));
}

JSValue
_gum_quick_range_details_new (JSContext * ctx,
                              const GumRangeDetails * details,
                              GumQuickCore * core)
{
  const GumFileMapping * f = details->file;
  JSValue d;

  d = _gum_quick_memory_range_new (ctx, details->range, core);

  JS_DefinePropertyValue (ctx, d,
      GUM_QUICK_CORE_ATOM (core, protection),
      _gum_quick_page_protection_new (ctx, details->protection),
      JS_PROP_C_W_E);

  if (f != NULL)
  {
    JSValue file = JS_NewObject (ctx);

    JS_DefinePropertyValue (ctx, file,
        GUM_QUICK_CORE_ATOM (core, path),
        JS_NewString (ctx, f->path),
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, file,
        GUM_QUICK_CORE_ATOM (core, offset),
        JS_NewInt64 (ctx, f->offset),
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, file,
        GUM_QUICK_CORE_ATOM (core, size),
        JS_NewInt64 (ctx, f->size),
        JS_PROP_C_W_E);

    JS_DefinePropertyValue (ctx, d,
        GUM_QUICK_CORE_ATOM (core, file),
        file,
        JS_PROP_C_W_E);
  }

  return d;
}

JSValue
_gum_quick_memory_range_new (JSContext * ctx,
                             const GumMemoryRange * range,
                             GumQuickCore * core)
{
  JSValue r = JS_NewObject (ctx);

  JS_DefinePropertyValue (ctx, r,
      GUM_QUICK_CORE_ATOM (core, base),
      _gum_quick_native_pointer_new (ctx,
          GSIZE_TO_POINTER (range->base_address), core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, r,
      GUM_QUICK_CORE_ATOM (core, size),
      JS_NewInt64 (ctx, range->size),
      JS_PROP_C_W_E);

  return r;
}

gboolean
_gum_quick_memory_ranges_get (JSContext * ctx,
                              JSValueConst val,
                              GumQuickCore * core,
                              GArray ** ranges)
{
  GArray * result = NULL;
  JSValue element = JS_NULL;
  GumMemoryRange range;

  if (JS_IsArray (ctx, val))
  {
    guint n, i;

    if (!_gum_quick_array_get_length (ctx, val, core, &n))
      return FALSE;

    result = g_array_sized_new (FALSE, FALSE, sizeof (GumMemoryRange), n);

    for (i = 0; i != n; i++)
    {
      element = JS_GetPropertyUint32 (ctx, val, i);
      if (JS_IsException (element))
        goto propagate_exception;

      if (!_gum_quick_memory_range_get (ctx, element, core, &range))
        goto propagate_exception;

      g_array_append_val (result, range);

      JS_FreeValue (ctx, element);
      element = JS_NULL;
    }
  }
  else if (_gum_quick_memory_range_get (ctx, val, core, &range))
  {
    result = g_array_sized_new (FALSE, FALSE, sizeof (GumMemoryRange), 1);
    g_array_append_val (result, range);
  }
  else
  {
    goto expected_array_of_ranges_or_range;
  }

  *ranges = result;
  return TRUE;

expected_array_of_ranges_or_range:
  {
    _gum_quick_throw_literal (ctx,
        "expected a range object or an array of range objects");
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeValue (ctx, element);
    if (result != NULL)
      g_array_free (result, TRUE);

    return FALSE;
  }
}

gboolean
_gum_quick_memory_range_get (JSContext * ctx,
                             JSValueConst val,
                             GumQuickCore * core,
                             GumMemoryRange * range)
{
  gboolean success = FALSE;
  JSValue v = JS_NULL;
  gpointer base;
  gsize size;

  v = JS_GetProperty (ctx, val, GUM_QUICK_CORE_ATOM (core, base));
  if (JS_IsException (v))
    goto expected_range;
  if (!_gum_quick_native_pointer_get (ctx, v, core, &base))
    goto expected_range;
  JS_FreeValue (ctx, v);

  v = JS_GetProperty (ctx, val, GUM_QUICK_CORE_ATOM (core, size));
  if (JS_IsException (v))
    goto expected_range;
  if (!_gum_quick_size_get (ctx, v, core, &size))
    goto expected_range;
  JS_FreeValue (ctx, v);

  v = JS_NULL;

  range->base_address = GUM_ADDRESS (base);
  range->size = size;

  success = TRUE;
  goto beach;

expected_range:
  {
    _gum_quick_throw_literal (ctx, "expected a range object");
    goto beach;
  }
beach:
  {
    JS_FreeValue (ctx, v);

    return success;
  }
}

JSValue
_gum_quick_page_protection_new (JSContext * ctx,
                                GumPageProtection prot)
{
  gchar str[4] = "---";

  if ((prot & GUM_PAGE_READ) != 0)
    str[0] = 'r';
  if ((prot & GUM_PAGE_WRITE) != 0)
    str[1] = 'w';
  if ((prot & GUM_PAGE_EXECUTE) != 0)
    str[2] = 'x';

  return JS_NewString (ctx, str);
}

gboolean
_gum_quick_page_protection_get (JSContext * ctx,
                                JSValueConst val,
                                GumPageProtection * prot)
{
  GumPageProtection p;
  const char * str = NULL;
  const char * ch;

  if (!JS_IsString (val))
    goto expected_protection;

  str = JS_ToCString (ctx, val);

  p = GUM_PAGE_NO_ACCESS;
  for (ch = str; *ch != '\0'; ch++)
  {
    switch (*ch)
    {
      case 'r':
        p |= GUM_PAGE_READ;
        break;
      case 'w':
        p |= GUM_PAGE_WRITE;
        break;
      case 'x':
        p |= GUM_PAGE_EXECUTE;
        break;
      case '-':
        break;
      default:
        goto expected_protection;
    }
  }

  JS_FreeCString (ctx, str);

  *prot = p;
  return TRUE;

expected_protection:
  {
    JS_FreeCString (ctx, str);

    _gum_quick_throw_literal (ctx,
        "expected a string specifying memory protection");
    return FALSE;
  }
}

JSValue
_gum_quick_memory_operation_new (JSContext * ctx,
                                 GumMemoryOperation operation)
{
  return JS_NewString (ctx, gum_memory_operation_to_string (operation));
}

gboolean
_gum_quick_array_get_length (JSContext * ctx,
                             JSValueConst array,
                             GumQuickCore * core,
                             guint * length)
{
  JSValue val;
  int res;
  uint32_t v;

  val = JS_GetProperty (ctx, array, GUM_QUICK_CORE_ATOM (core, length));
  if (JS_IsException (val))
    return FALSE;

  res = JS_ToUint32 (ctx, &v, val);

  JS_FreeValue (ctx, val);

  if (res != 0)
    return FALSE;

  *length = v;
  return TRUE;
}

void
_gum_quick_array_buffer_free (JSRuntime * rt,
                              void * opaque,
                              void * ptr)
{
  g_free (opaque);
}

gboolean
_gum_quick_process_match_result (JSContext * ctx,
                                 JSValue * val,
                                 GumQuickMatchResult * result)
{
  GumQuickMatchResult r = GUM_QUICK_MATCH_CONTINUE;
  JSValue v = *val;

  if (JS_IsString (v))
  {
    const gchar * str = JS_ToCString (ctx, v);
    if (strcmp (str, "stop") == 0)
      r = GUM_QUICK_MATCH_STOP;
    JS_FreeCString (ctx, str);
  }
  else if (JS_IsException (v))
  {
    r = GUM_QUICK_MATCH_ERROR;
  }

  JS_FreeValue (ctx, v);

  *val = JS_NULL;
  *result = r;

  return r == GUM_QUICK_MATCH_CONTINUE;
}

JSValue
_gum_quick_maybe_call_on_complete (JSContext * ctx,
                                   GumQuickMatchResult match_result,
                                   JSValue on_complete)
{
  JSValue val;

  if (match_result == GUM_QUICK_MATCH_ERROR)
    return JS_EXCEPTION;

  val = JS_Call (ctx, on_complete, JS_UNDEFINED, 0, NULL);
  if (JS_IsException (val))
    return JS_EXCEPTION;

  JS_FreeValue (ctx, val);

  return JS_UNDEFINED;
}

JSValue
_gum_quick_exception_details_new (JSContext * ctx,
                                  GumExceptionDetails * details,
                                  GumQuickCore * core,
                                  GumQuickCpuContext ** cpu_context)
{
  const GumExceptionMemoryDetails * md = &details->memory;
  JSValue d;
  gchar * message;

  message = gum_exception_details_to_string (details);
  d = _gum_quick_error_new (ctx, message, core);
  g_free (message);

  JS_DefinePropertyValue (ctx, d, GUM_QUICK_CORE_ATOM (core, type),
      JS_NewString (ctx, gum_exception_type_to_string (details->type)),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, d, GUM_QUICK_CORE_ATOM (core, address),
      _gum_quick_native_pointer_new (ctx, details->address, core),
      JS_PROP_C_W_E);

  if (md->operation != GUM_MEMOP_INVALID)
  {
    JSValue op = JS_NewError (ctx);

    JS_DefinePropertyValue (ctx, op, GUM_QUICK_CORE_ATOM (core, operation),
        _gum_quick_memory_operation_new (ctx, md->operation),
        JS_PROP_C_W_E);
    JS_DefinePropertyValue (ctx, op, GUM_QUICK_CORE_ATOM (core, address),
        _gum_quick_native_pointer_new (ctx, md->address, core),
        JS_PROP_C_W_E);

    JS_DefinePropertyValue (ctx, d, GUM_QUICK_CORE_ATOM (core, memory), op,
        JS_PROP_C_W_E);
  }

  JS_DefinePropertyValue (ctx, d, GUM_QUICK_CORE_ATOM (core, context),
      _gum_quick_cpu_context_new (ctx, &details->context,
          GUM_CPU_CONTEXT_READWRITE, core, cpu_context),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, d, GUM_QUICK_CORE_ATOM (core, nativeContext),
      _gum_quick_native_pointer_new (ctx, details->native_context, core),
      JS_PROP_C_W_E);

  return d;
}

JSValue
_gum_quick_error_new (JSContext * ctx,
                      const gchar * message,
                      GumQuickCore * core)
{
  JSValue error;

  error = JS_NewError (ctx);
  JS_SetProperty (ctx, error, GUM_QUICK_CORE_ATOM (core, message),
      JS_NewString (ctx, message));

  return error;
}

JSValue
_gum_quick_error_new_take_error (JSContext * ctx,
                                 GError ** error,
                                 GumQuickCore * core)
{
  JSValue result;
  GError * e;

  e = g_steal_pointer (error);
  if (e != NULL)
  {
    const gchar * m = e->message;
    GString * message;
    gboolean probably_starts_with_acronym;

    message = g_string_sized_new (strlen (m));

    probably_starts_with_acronym =
        g_unichar_isupper (g_utf8_get_char (m)) &&
        g_utf8_strlen (m, -1) >= 2 &&
        g_unichar_isupper (g_utf8_get_char (g_utf8_offset_to_pointer (m, 1)));

    if (probably_starts_with_acronym)
    {
      g_string_append (message, m);
    }
    else
    {
      g_string_append_unichar (message,
          g_unichar_tolower (g_utf8_get_char (m)));
      g_string_append (message, g_utf8_offset_to_pointer (m, 1));
    }

    result = _gum_quick_error_new (ctx, message->str, core);

    g_string_free (message, TRUE);
    g_error_free (e);
  }
  else
  {
    result = JS_NULL;
  }

  return result;
}

gboolean
_gum_quick_unwrap (JSContext * ctx,
                   JSValue val,
                   JSClassID klass,
                   GumQuickCore * core,
                   gpointer * instance)
{
  if (!_gum_quick_try_unwrap (val, klass, core, instance))
  {
    JS_ThrowTypeErrorInvalidClass (ctx, klass);
    return FALSE;
  }

  return TRUE;
}

gboolean
_gum_quick_try_unwrap (JSValue val,
                       JSClassID klass,
                       GumQuickCore * core,
                       gpointer * instance)
{
  gpointer result;
  JSClassID concrete_class;

  result = JS_GetAnyOpaque (val, &concrete_class);
  if (concrete_class == 0)
    return FALSE;

  if (concrete_class != klass)
  {
    JSClassID base_class = GPOINTER_TO_SIZE (g_hash_table_lookup (
        core->subclasses, GSIZE_TO_POINTER (concrete_class)));
    if (base_class != klass)
      return FALSE;
  }

  *instance = result;
  return TRUE;
}

void
_gum_quick_create_class (JSContext * ctx,
                         const JSClassDef * def,
                         GumQuickCore * core,
                         JSClassID * klass,
                         JSValue * prototype)
{
  JSClassID id;
  JSValue proto;

  id = gum_get_class_id_for_class_def (def);

  JS_NewClass (core->rt, id, def);

  proto = JS_NewObject (ctx);
  JS_SetClassProto (ctx, id, proto);

  *klass = id;
  *prototype = proto;
}

void
_gum_quick_create_subclass (JSContext * ctx,
                            const JSClassDef * def,
                            JSClassID parent_class,
                            JSValue parent_prototype,
                            GumQuickCore * core,
                            JSClassID * klass,
                            JSValue * prototype)
{
  JSClassID id;
  JSValue proto;

  id = gum_get_class_id_for_class_def (def);

  JS_NewClass (core->rt, id, def);

  proto = JS_NewObjectProto (ctx, parent_prototype);
  JS_SetClassProto (ctx, id, proto);

  g_hash_table_insert (core->subclasses, GSIZE_TO_POINTER (id),
      GSIZE_TO_POINTER (parent_class));

  *klass = id;
  *prototype = proto;
}

static JSClassID
gum_get_class_id_for_class_def (const JSClassDef * def)
{
  JSClassID id;

  G_LOCK (gum_class_ids);

  if (gum_class_ids == NULL)
  {
    gum_class_ids = g_hash_table_new (NULL, NULL);
    _gum_register_destructor (gum_deinit_class_ids);
  }

  id = GPOINTER_TO_UINT (g_hash_table_lookup (gum_class_ids, def));
  if (id == 0)
  {
    JS_NewClassID (&id);
    g_hash_table_insert (gum_class_ids, (gpointer) def, GUINT_TO_POINTER (id));
  }

  G_UNLOCK (gum_class_ids);

  return id;
}

static void
gum_deinit_class_ids (void)
{
  g_hash_table_unref (gum_class_ids);
}

JSValue
_gum_quick_throw (JSContext * ctx,
                  const gchar * format,
                  ...)
{
  JSValue result;
  va_list args;
  gchar * message;

  va_start (args, format);
  message = g_strdup_vprintf (format, args);
  result = _gum_quick_throw_literal (ctx, message);
  g_free (message);
  va_end (args);

  return result;
}

JSValue
_gum_quick_throw_literal (JSContext * ctx,
                          const gchar * message)
{
  return JS_Throw (ctx,
      _gum_quick_error_new (ctx, message, JS_GetContextOpaque (ctx)));
}

JSValue
_gum_quick_throw_error (JSContext * ctx,
                        GError ** error)
{
  return JS_Throw (ctx,
      _gum_quick_error_new_take_error (ctx, error, JS_GetContextOpaque (ctx)));
}

JSValue
_gum_quick_throw_native (JSContext * ctx,
                         GumExceptionDetails * details,
                         GumQuickCore * core)
{
  JSValue d;
  GumQuickCpuContext * cc;

  d = _gum_quick_exception_details_new (ctx, details, core, &cc);
  _gum_quick_cpu_context_make_read_only (cc);

  return JS_Throw (ctx, d);
}

static const gchar *
gum_exception_type_to_string (GumExceptionType type)
{
  switch (type)
  {
    case GUM_EXCEPTION_ABORT: return "abort";
    case GUM_EXCEPTION_ACCESS_VIOLATION: return "access-violation";
    case GUM_EXCEPTION_GUARD_PAGE: return "guard-page";
    case GUM_EXCEPTION_ILLEGAL_INSTRUCTION: return "illegal-instruction";
    case GUM_EXCEPTION_STACK_OVERFLOW: return "stack-overflow";
    case GUM_EXCEPTION_ARITHMETIC: return "arithmetic";
    case GUM_EXCEPTION_BREAKPOINT: return "breakpoint";
    case GUM_EXCEPTION_SINGLE_STEP: return "single-step";
    case GUM_EXCEPTION_SYSTEM: return "system";
    default: break;
  }

  return NULL;
}

static const gchar *
gum_thread_state_to_string (GumThreadState state)
{
  switch (state)
  {
    case GUM_THREAD_RUNNING: return "running";
    case GUM_THREAD_STOPPED: return "stopped";
    case GUM_THREAD_WAITING: return "waiting";
    case GUM_THREAD_UNINTERRUPTIBLE: return "uninterruptible";
    case GUM_THREAD_HALTED: return "halted";
    default: break;
  }

  return NULL;
}

static const gchar *
gum_memory_operation_to_string (GumMemoryOperation operation)
{
  switch (operation)
  {
    case GUM_MEMOP_INVALID: return "invalid";
    case GUM_MEMOP_READ: return "read";
    case GUM_MEMOP_WRITE: return "write";
    case GUM_MEMOP_EXECUTE: return "execute";
    default: break;
  }

  return NULL;
}
```