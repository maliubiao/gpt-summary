Response:
My thinking process to analyze the C code and generate the summary involved these steps:

1. **Understand the Goal:** The core request is to understand the functionality of `gumquickvalue.c` within the Frida dynamic instrumentation framework. Specifically, I need to identify its purpose, relate it to reverse engineering, discuss low-level aspects, analyze logic, anticipate errors, explain user interaction, and provide a concise summary.

2. **Initial Code Scan (High-Level Purpose):** I started by skimming the code, paying attention to includes, data structures (like `GumQuickArgs`), function names (starting with `gum_quick_`), and comments. This quickly revealed that the file deals with converting JavaScript values to C types and vice-versa within the Frida/Gum environment. The `GumQuickArgs` structure suggests it manages arguments passed from JavaScript to native C code.

3. **Identify Key Data Structures:** I noted the `GumQuickArgs` structure and its members: `ctx` (JavaScript context), `count`, `elements` (JS arguments), and `core` (likely a global Frida context). The presence of `values`, `cstrings`, `arrays`, `bytes`, and `match_patterns` as linked lists suggests a mechanism for managing and freeing resources associated with the converted values.

4. **Analyze Core Functions (`_gum_quick_args_init`, `_gum_quick_args_destroy`, `_gum_quick_args_parse`):** These functions are central to the argument handling process.
    * `_gum_quick_args_init`: Initializes the `GumQuickArgs` structure.
    * `_gum_quick_args_destroy`: Cleans up allocated resources, freeing JavaScript values, C strings, arrays, bytes, and match patterns. This highlights the importance of memory management when bridging JavaScript and native code.
    * `_gum_quick_args_parse`: This is the most crucial function. It takes a format string and a variable argument list (`...`) to parse JavaScript values into corresponding C types. The `switch` statement based on the format string characters (`i`, `u`, `q`, `Q`, `s`, `p`, `B`, etc.) clearly maps JavaScript types to C types. The error handling (`goto propagate_exception`) indicates type checking and potential issues.

5. **Focus on Type Conversions (`_gum_quick_int_get`, `_gum_quick_string_get`, `_gum_quick_bytes_get`, etc.):** The numerous functions starting with `_gum_quick_` followed by a type name (e.g., `int`, `string`, `bytes`) are responsible for the actual conversion. I observed:
    * Direct JavaScript type checks (e.g., `JS_IsString`, `JS_IsNumber`).
    * Use of QuickJS functions for conversion (e.g., `JS_ToInt32`, `JS_ToCString`).
    * Handling of different representations (e.g., numbers as strings, pointers as strings).
    * Support for custom types like `GumMatchPattern` and `GumCpuContext`.

6. **Relate to Reverse Engineering:**  I considered how these conversions are relevant in reverse engineering with Frida. Frida allows injecting JavaScript code into a running process to interact with its internals. `gumquickvalue.c` facilitates passing data (addresses, function pointers, memory contents, etc.) between the JavaScript injection and the native Frida agent. Examples: reading memory at a specific address, calling a native function with specific arguments, modifying CPU context.

7. **Identify Low-Level Aspects:** I looked for interactions with the underlying system. The code directly deals with pointers (`gpointer`), memory manipulation (`memcpy`), and data types like `gsize`, `gssize`. The inclusion of `<gum/gum-init.h>` and references to `GumCpuContext`, `GumPageProtection`, etc., point to the Gum library's low-level instrumentation capabilities.

8. **Analyze Logic and Assumptions:** The `_gum_quick_args_parse` function's format string parsing is a clear example of logic. The code assumes the JavaScript arguments are provided in the order specified by the format string. The handling of optional arguments (`|`) adds complexity.

9. **Consider User Errors:** Incorrect format strings, passing the wrong types from JavaScript, or attempting to convert values that are out of range or invalid are potential user errors. The error messages thrown by `_gum_quick_throw_literal` provide clues about these.

10. **Trace User Interaction (Debugging Clues):**  To reach this code, a user would write a Frida script that calls a native function or interacts with native structures. The JavaScript engine would then need to convert the JavaScript values passed as arguments into a format usable by the native Frida agent, leading to the execution of functions within `gumquickvalue.c`.

11. **Synthesize the Summary:**  Based on the above analysis, I formulated the summary points, focusing on:
    * Core Functionality: Converting JS values to C.
    * Key Function: `_gum_quick_args_parse`.
    * Role in Reverse Engineering: Bridging JS and native code.
    * Low-Level Interaction: Handling pointers and memory.
    * Error Handling: Type checking and error messages.
    * User Role: Providing arguments from JS.

12. **Review and Refine:** I reviewed the generated summary to ensure it was accurate, concise, and addressed all parts of the prompt. I made sure the examples were relevant and the explanations were clear. For instance, explicitly mentioning the format string and its role is crucial for understanding how `_gum_quick_args_parse` works.

This systematic approach, moving from a high-level understanding to detailed analysis and then synthesizing the findings, allowed me to effectively dissect the C code and generate a comprehensive response.
好的，让我们来分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumquickvalue.c` 这个文件的功能。

**文件功能归纳**

`gumquickvalue.c` 文件的核心功能是 **在 Frida 的 Gum 运行时环境中，实现 JavaScript 值与 C 类型值之间的快速转换和处理。** 它提供了一组工具函数，用于安全高效地将 JavaScript 传递给 native 层的参数转换为 C 语言中对应的数据类型，以及进行反向的转换。

**具体功能点拆解：**

1. **参数解析与转换 (`_gum_quick_args_parse`)**:
   - 这是该文件最核心的功能。它接收一个格式化字符串 (`format`) 和可变参数列表 (`...`)，以及一个 `GumQuickArgs` 结构体，该结构体封装了 JavaScript 传递过来的参数。
   - 格式化字符串用于描述期望的参数类型和顺序。
   - 根据格式化字符串的指示，它从 JavaScript 值中提取数据，并将其转换为相应的 C 类型，然后赋值给可变参数列表中的指针。
   - 支持多种数据类型的转换，包括：
     - **基本类型**: `i` (int), `u` (unsigned int), `q` (int64_t), `Q` (uint64_t), `z` (ssize_t), `Z` (size_t), `n` (double), `t` (bool).
     - **指针**: `p` (void*).
     - **字符串**: `s` (const char*).
     - **对象和数组**: `V` (JSValue，可以是对象或字符串), `O` (JSValue，必须是对象), `A` (JSValue，必须是数组).
     - **函数**: `F` (JSValue，可以是指向 JavaScript 函数的引用或 native 函数指针).
     - **字节数组**: `B` (GBytes*).
     - **CPU 上下文**: `C` (GumCpuContext*).
     - **内存范围**: `R` (GArray*，包含 GumMemoryRange).
     - **内存保护属性**: `m` (GumPageProtection).
     - **匹配模式**: `M` (GumMatchPattern*).
   - 提供了灵活的修饰符，如 `?` (nullable), `~` (fuzzy，允许字符串表示的数字或指针).

2. **快速创建特定类型的 JavaScript 值 (`_gum_quick_int64_new`, `_gum_quick_uint64_new`, `_gum_quick_native_pointer_new`, 等)**:
   - 提供了一系列函数，用于将 C 类型的值包装成 JavaScript 对象，以便从 native 层传递回 JavaScript 环境。例如，将 `int64_t` 包装成 JavaScript 的 `Int64` 对象。

3. **安全地获取和解包 JavaScript 值 (`_gum_quick_int64_get`, `_gum_quick_uint64_get`, `_gum_quick_native_pointer_get`, 等)**:
   - 提供了一系列函数，用于从 JavaScript 值中安全地提取 C 类型的值。
   - 针对特定的 Frida 类型（如 `NativePointer`, `Int64`, `UInt64`），提供了专门的解包函数 (`_gum_quick_int64_unwrap`, `_gum_quick_native_pointer_unwrap`)，用于获取其内部的 C 值。

4. **错误处理**:
   - 当类型不匹配或参数缺失时，会调用 `_gum_quick_throw_literal` 抛出 JavaScript 异常，提供清晰的错误信息。

5. **资源管理**:
   - `GumQuickArgs` 结构体内部维护了一些链表 (`values`, `cstrings`, `arrays`, `bytes`, `match_patterns`)，用于存储需要在函数调用结束后释放的资源，例如从 JavaScript 字符串转换来的 C 字符串，或者创建的 GArray 和 GBytes 对象。
   - `_gum_quick_args_destroy` 函数负责释放这些资源，防止内存泄漏。

**与逆向方法的关系及举例说明：**

`gumquickvalue.c` 在 Frida 动态插桩中扮演着至关重要的角色，因为它 **直接关系到 JavaScript 代码与被插桩进程的 native 代码之间的交互。**  逆向工程师经常需要从目标进程中读取内存、调用函数、修改参数等，而这些操作都需要跨越 JavaScript 和 native 代码的边界。

**举例说明：**

假设你想在 JavaScript 中调用目标进程的 `MessageBoxA` 函数，并读取其返回值。

1. **定位函数地址：** 你可以使用 Frida 的 API 找到 `MessageBoxA` 函数的地址。
2. **构造参数：** 你需要在 JavaScript 中构造 `MessageBoxA` 函数所需的参数，例如窗口句柄（可以为 `NULL` 或 `0`），消息内容，标题等。这些参数在 JavaScript 中是 JavaScript 的字符串或数字类型。
3. **参数传递与转换：** Frida 内部会使用类似 `_gum_quick_args_parse` 的机制，将你在 JavaScript 中提供的字符串和数字转换为 C 语言中 `MessageBoxA` 函数期望的 `HWND`, `LPCSTR` 等类型。格式化字符串会定义期望的参数类型顺序，例如 `"piiss"` (pointer, int, string, string)。
4. **调用 native 函数：** Frida 的 Gum 运行时会使用转换后的 C 类型参数调用 `MessageBoxA` 函数。
5. **处理返回值：**  如果 `MessageBoxA` 返回一个整数，Frida 可能会使用类似 `_gum_quick_int_new` 的函数将这个 C 的 `int` 值包装成一个 JavaScript 的 Number 对象，返回给你的 JavaScript 代码。

**涉及到二进制底层，Linux, Android 内核及框架的知识及举例说明：**

`gumquickvalue.c` 虽然本身不直接操作内核，但它所支持的数据类型和操作与底层系统密切相关：

* **指针 (`p`)**:  直接对应于内存地址，是二进制层面的核心概念。逆向时经常需要传递和操作内存地址。
* **`gsize`, `gssize`**:  表示内存大小，与 Linux 等系统的内存管理相关。
* **`GumCpuContext` (`C`)**:  代表 CPU 寄存器状态，是操作系统内核和处理器架构的直接抽象。在逆向分析中，修改 CPU 上下文可以改变程序的执行流程。这涉及到对不同架构（如 ARM, x86）寄存器名称和用法的理解。
* **`GumPageProtection` (`m`)**:  表示内存页的保护属性（如读、写、执行），与操作系统的内存管理机制紧密相关。在 Frida 中修改内存保护属性可以绕过某些安全机制。
* **`GBytes` (`B`)**:  代表原始的字节数据，是处理二进制文件、网络数据包等的基础。
* **内存范围 (`R`)**:  在逆向分析中，经常需要指定一段连续的内存区域进行操作，例如搜索特定的模式。

**举例说明：**

在 Android 逆向中，你可能需要 hook 一个 native 函数，该函数接收一个指向某个数据结构的指针。

1. **获取数据结构地址：** 你可能需要通过分析内存布局或者读取寄存器来获取该数据结构的地址。这个地址会以 JavaScript 的 Number 类型表示。
2. **转换为 native 指针：**  Frida 内部会使用 `_gum_quick_native_pointer_parse` 将 JavaScript 的数字转换为 C 的 `void*` 指针。
3. **读取结构体成员：**  有了指向数据结构的指针，你就可以在 JavaScript 中使用 Frida 的 `NativePointer` API，结合偏移量来读取结构体的成员变量。

**逻辑推理、假设输入与输出：**

`_gum_quick_args_parse` 函数的逻辑主要体现在根据格式化字符串来决定如何解析和转换 JavaScript 参数。

**假设输入：**

* **格式化字符串:** `"isp"`
* **JavaScript 参数:** `[123, "hello", ptr]`，其中 `ptr` 是一个 Frida 的 `NativePointer` 对象。

**逻辑推理：**

1. `i`:  期望一个整数。从第一个 JavaScript 参数 `123` 中提取整数值 `123`。
2. `s`:  期望一个字符串。从第二个 JavaScript 参数 `"hello"` 中提取 C 字符串 `"hello"`。
3. `p`:  期望一个指针。从第三个 JavaScript 参数 `ptr` 中解包出其内部的 C 指针。

**预期输出：**

`_gum_quick_args_parse` 函数会将提取出的 C 值赋值给传递给它的可变参数列表中的指针。例如，如果可变参数列表是 `va_list ap`，那么在函数内部会执行类似以下的操作：

```c
int arg1 = va_arg(ap, int);        // arg1 将被赋值为 123
const char* arg2 = va_arg(ap, const char*); // arg2 将指向 "hello"
void* arg3 = va_arg(ap, void*);      // arg3 将指向 ptr 指向的内存地址
```

**用户或编程常见的使用错误及举例说明：**

1. **格式化字符串与实际参数不匹配：**
   - **错误示例：** 格式化字符串为 `"i"`，但 JavaScript 传递了字符串 `"abc"`。
   - **结果：** `_gum_quick_int_get` 会尝试将字符串 `"abc"` 转换为整数，导致转换失败，并抛出 "expected an integer" 的异常。

2. **传递了 `null` 值但格式化字符串指示非 nullable：**
   - **错误示例：** 格式化字符串为 `"s"`，但 JavaScript 传递了 `null`。
   - **结果：** `_gum_quick_string_get` 会期望一个字符串，接收到 `null` 会导致错误，除非格式化字符串使用了 nullable 修饰符 `"s?"`。

3. **传递了错误类型的对象：**
   - **错误示例：** 格式化字符串为 `"O"` (期望一个对象)，但 JavaScript 传递了一个数字 `123`。
   - **结果：** `JS_IsObject(arg)` 会返回 `false`，导致抛出 "expected an object" 的异常。

4. **忘记释放资源：**
   - 虽然 `gumquickvalue.c` 内部有资源管理机制，但如果用户在 native hook 的实现中分配了内存，并且没有正确释放，仍然会导致内存泄漏。

**用户操作是如何一步步到达这里的，作为调试线索：**

1. **编写 Frida 脚本：** 用户首先会编写一个 JavaScript 脚本，使用 Frida 的 API 来进行插桩操作，例如 `Interceptor.attach` 来 hook native 函数。
2. **指定 hook 的函数和回调：** 在 `Interceptor.attach` 中，用户会指定要 hook 的 native 函数的地址或名称，并提供一个 JavaScript 回调函数，该回调函数会在目标函数执行前后被调用。
3. **在回调函数中访问参数：** 在 JavaScript 回调函数中，用户可能会尝试访问被 hook 函数的参数。例如，使用 `args[0]`, `args[1]` 等来获取参数值。
4. **Frida 内部处理参数：** 当 JavaScript 代码尝试访问或操作这些参数时，Frida 的 Gum 运行时系统需要将这些 JavaScript 值转换为 native 代码可以理解的 C 类型。
5. **调用 `_gum_quick_args_parse` 或类似的函数：**  Frida 内部会根据被 hook 函数的签名信息（如果已知）或者用户在 JavaScript 中提供的格式化字符串，调用 `gumquickvalue.c` 中的 `_gum_quick_args_parse` 函数或类似的函数来进行参数的解析和转换。
6. **类型检查和转换：** `_gum_quick_args_parse` 函数会根据格式化字符串逐个解析 JavaScript 参数，并尝试将其转换为对应的 C 类型。
7. **出现错误：** 如果 JavaScript 传递的参数类型与格式化字符串不匹配，或者发生了其他错误，`_gum_quick_args_parse` 函数会调用 `_gum_quick_throw_literal` 抛出一个 JavaScript 异常。
8. **JavaScript 捕获异常：** 用户编写的 Frida 脚本可能会捕获这个异常，或者如果没有捕获，Frida 会将异常信息打印出来，作为调试线索。

**总结 `gumquickvalue.c` 的功能 (第 1 部分):**

`gumquickvalue.c` 的主要功能是 **作为 Frida 框架中 JavaScript 与 native 代码之间数据类型转换的桥梁。** 它提供了一套机制，能够安全、高效地将 JavaScript 值解析和转换为 C 语言中的各种数据类型，以便在 native 代码中使用，并且能够将 native 的值转换回 JavaScript 对象。其核心函数 `_gum_quick_args_parse` 依赖于格式化字符串来指导转换过程，并提供了丰富的类型支持和错误处理机制。这个文件是 Frida 实现动态插桩功能的基础组成部分，使得 JavaScript 能够灵活地与目标进程的 native 代码进行交互。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickvalue.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
 * Copyright (C) 2020-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickvalue.h"

#include <gum/gum-init.h>

#include <stdarg.h>
#include <string.h>

#define GUM_MAX_JS_BYTE_ARRAY_LENGTH (100 * 1024 * 1024)

static void gum_quick_args_free_value_later (GumQuickArgs * self, JSValue v);
static void gum_quick_args_free_cstring_later (GumQuickArgs * self,
    const char * s);
static void gum_quick_args_free_array_later (GumQuickArgs * self, GArray * a);
static void gum_quick_args_free_bytes_later (GumQuickArgs * self, GBytes * b);
static void gum_quick_args_free_match_pattern_later (GumQuickArgs * self,
    GumMatchPattern * p);

static JSClassID gum_get_class_id_for_class_def (const JSClassDef * def);
static void gum_deinit_class_ids (void);

static const gchar * gum_exception_type_to_string (GumExceptionType type);
static const gchar * gum_thread_state_to_string (GumThreadState state);
static const gchar * gum_memory_operation_to_string (
    GumMemoryOperation operation);

G_LOCK_DEFINE_STATIC (gum_class_ids);
static GHashTable * gum_class_ids;

void
_gum_quick_args_init (GumQuickArgs * args,
                      JSContext * ctx,
                      int count,
                      JSValueConst * elements,
                      GumQuickCore * core)
{
  args->ctx = ctx;
  args->count = count;
  args->elements = elements;

  args->core = core;

  args->values = NULL;
  args->cstrings = NULL;
  args->arrays = NULL;
  args->bytes = NULL;
  args->match_patterns = NULL;
}

void
_gum_quick_args_destroy (GumQuickArgs * args)
{
  JSContext * ctx = args->ctx;
  GSList * cur, * next;
  GArray * values;

  g_slist_free_full (g_steal_pointer (&args->match_patterns),
      (GDestroyNotify) gum_match_pattern_unref);

  g_slist_free_full (g_steal_pointer (&args->bytes),
      (GDestroyNotify) g_bytes_unref);

  g_slist_free_full (g_steal_pointer (&args->arrays),
      (GDestroyNotify) g_array_unref);

  for (cur = g_steal_pointer (&args->cstrings); cur != NULL; cur = next)
  {
    char * str = cur->data;
    next = cur->next;

    JS_FreeCString (ctx, str);

    g_slist_free_1 (cur);
  }

  values = g_steal_pointer (&args->values);
  if (values != NULL)
  {
    guint i;

    for (i = 0; i != values->len; i++)
    {
      JSValue val = g_array_index (values, JSValue, i);
      JS_FreeValue (ctx, val);
    }

    g_array_free (values, TRUE);
  }
}

gboolean
_gum_quick_args_parse (GumQuickArgs * self,
                       const gchar * format,
                       ...)
{
  JSContext * ctx = self->ctx;
  GumQuickCore * core = self->core;
  va_list ap;
  int arg_index;
  const gchar * t;
  gboolean is_required;
  const gchar * error_message = NULL;

  va_start (ap, format);

  arg_index = 0;
  is_required = TRUE;
  for (t = format; *t != '\0'; t++)
  {
    JSValue arg;

    if (*t == '|')
    {
      is_required = FALSE;
      continue;
    }

    arg = (arg_index < self->count) ? self->elements[arg_index] : JS_UNDEFINED;

    if (JS_IsUndefined (arg))
    {
      if (is_required)
        goto missing_argument;
      else
        break;
    }

    switch (*t)
    {
      case 'i':
      {
        gint i;

        if (!_gum_quick_int_get (ctx, arg, &i))
          goto propagate_exception;

        *va_arg (ap, gint *) = i;

        break;
      }
      case 'u':
      {
        guint u;

        if (!_gum_quick_uint_get (ctx, arg, &u))
          goto propagate_exception;

        *va_arg (ap, guint *) = (guint) u;

        break;
      }
      case 'q':
      {
        gint64 i;
        gboolean is_fuzzy;

        is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;

        if (is_fuzzy)
        {
          if (!_gum_quick_int64_parse (ctx, arg, core, &i))
            goto propagate_exception;
        }
        else
        {
          if (!_gum_quick_int64_get (ctx, arg, core, &i))
            goto propagate_exception;
        }

        *va_arg (ap, gint64 *) = i;

        break;
      }
      case 'Q':
      {
        guint64 u;
        gboolean is_fuzzy;

        is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;

        if (is_fuzzy)
        {
          if (!_gum_quick_uint64_parse (ctx, arg, core, &u))
            goto propagate_exception;
        }
        else
        {
          if (!_gum_quick_uint64_get (ctx, arg, core, &u))
            goto propagate_exception;
        }

        *va_arg (ap, guint64 *) = u;

        break;
      }
      case 'z':
      {
        gssize value;

        if (!_gum_quick_ssize_get (ctx, arg, core, &value))
          goto propagate_exception;

        *va_arg (ap, gssize *) = value;

        break;
      }
      case 'Z':
      {
        gsize value;

        if (!_gum_quick_size_get (ctx, arg, core, &value))
          goto propagate_exception;

        *va_arg (ap, gsize *) = value;

        break;
      }
      case 'n':
      {
        gdouble d;

        if (!_gum_quick_float64_get (ctx, arg, &d))
          goto propagate_exception;

        *va_arg (ap, gdouble *) = d;

        break;
      }
      case 't':
      {
        gboolean b;

        if (!_gum_quick_boolean_get (ctx, arg, &b))
          goto propagate_exception;

        *va_arg (ap, gboolean *) = b;

        break;
      }
      case 'p':
      {
        gpointer ptr;
        gboolean is_fuzzy;

        is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;

        if (is_fuzzy)
        {
          if (!_gum_quick_native_pointer_parse (ctx, arg, core, &ptr))
            goto propagate_exception;
        }
        else
        {
          if (!_gum_quick_native_pointer_get (ctx, arg, core, &ptr))
            goto propagate_exception;
        }

        *va_arg (ap, gpointer *) = ptr;

        break;
      }
      case 's':
      {
        const gchar * str;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && JS_IsNull (arg))
          str = NULL;
        else if (!_gum_quick_string_get (ctx, arg, &str))
          goto propagate_exception;

        gum_quick_args_free_cstring_later (self, str);

        *va_arg (ap, const char **) = str;

        break;
      }
      case 'R':
      {
        GArray * ranges;

        if (!_gum_quick_memory_ranges_get (ctx, arg, core, &ranges))
          goto propagate_exception;

        gum_quick_args_free_array_later (self, ranges);

        *va_arg (ap, GArray **) = ranges;

        break;
      }
      case 'm':
      {
        GumPageProtection prot;

        if (!_gum_quick_page_protection_get (ctx, arg, &prot))
          goto propagate_exception;

        *va_arg (ap, GumPageProtection *) = prot;

        break;
      }
      case 'V':
      {
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (JS_IsNull (arg))
        {
          if (!is_nullable)
            goto expected_object_or_string;
        }
        else if (!JS_IsObject (arg) && !JS_IsString (arg))
        {
          goto expected_object_or_string;
        }

        *va_arg (ap, JSValue *) = arg;

        break;
      }
      case 'O':
      {
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (JS_IsNull (arg))
        {
          if (!is_nullable)
            goto expected_object;
        }
        else if (!JS_IsObject (arg))
        {
          goto expected_object;
        }

        *va_arg (ap, JSValue *) = arg;

        break;
      }
      case 'A':
      {
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (JS_IsNull (arg))
        {
          if (!is_nullable)
            goto expected_array;
        }
        else if (!JS_IsArray (ctx, arg))
        {
          goto expected_array;
        }

        *va_arg (ap, JSValue *) = arg;

        break;
      }
      case 'F':
      {
        JSValue func_js;
        gpointer func_c;
        gboolean accepts_pointer, is_expecting_object;

        accepts_pointer = t[1] == '*';
        if (accepts_pointer)
          t++;

        is_expecting_object = t[1] == '{';
        if (is_expecting_object)
          t += 2;

        if (is_expecting_object)
        {
          const gchar * next, * end, * t_end;

          if (!JS_IsObject (arg))
            goto expected_callback_object;

          do
          {
            gchar name[64];
            gsize length;
            gboolean is_optional;
            JSValue val;

            next = strchr (t, ',');
            end = strchr (t, '}');
            t_end = (next != NULL && next < end) ? next : end;
            length = t_end - t;
            strncpy (name, t, length);

            is_optional = name[length - 1] == '?';
            if (is_optional)
              name[length - 1] = '\0';
            else
              name[length] = '\0';

            val = JS_GetPropertyStr (ctx, arg, name);
            gum_quick_args_free_value_later (self, val);

            if (JS_IsFunction (ctx, val))
            {
              func_js = val;
              func_c = NULL;
            }
            else if (is_optional && JS_IsUndefined (val))
            {
              func_js = JS_NULL;
              func_c = NULL;
            }
            else if (accepts_pointer)
            {
              func_js = JS_NULL;
              if (!_gum_quick_native_pointer_get (ctx, val, core, &func_c))
                goto expected_callback_value;
            }
            else
            {
              goto expected_callback_value;
            }

            *va_arg (ap, JSValue *) = func_js;
            if (accepts_pointer)
              *va_arg (ap, gpointer *) = func_c;

            t = t_end + 1;
          }
          while (t_end != end);

          t--;
        }
        else
        {
          gboolean is_nullable;

          is_nullable = t[1] == '?';
          if (is_nullable)
            t++;

          if (JS_IsFunction (ctx, arg))
          {
            func_js = arg;
            func_c = NULL;
          }
          else if (is_nullable && JS_IsNull (arg))
          {
            func_js = arg;
            func_c = NULL;
          }
          else if (accepts_pointer)
          {
            func_js = JS_NULL;
            if (!_gum_quick_native_pointer_get (ctx, arg, core, &func_c))
              goto expected_function;
          }
          else
          {
            goto expected_function;
          }

          *va_arg (ap, JSValue *) = func_js;
          if (accepts_pointer)
            *va_arg (ap, gpointer *) = func_c;
        }

        break;
      }
      case 'B':
      {
        GBytes * bytes;
        gboolean is_fuzzy, is_nullable;

        is_fuzzy = t[1] == '~';
        if (is_fuzzy)
          t++;
        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && JS_IsNull (arg))
        {
          bytes = NULL;
        }
        else
        {
          gboolean success;

          if (is_fuzzy)
            success = _gum_quick_bytes_parse (ctx, arg, core, &bytes);
          else
            success = _gum_quick_bytes_get (ctx, arg, core, &bytes);

          if (!success)
            goto propagate_exception;
        }

        gum_quick_args_free_bytes_later (self, bytes);

        *va_arg (ap, GBytes **) = bytes;

        break;
      }
      case 'C':
      {
        GumCpuContext * cpu_context;
        gboolean is_nullable;

        is_nullable = t[1] == '?';
        if (is_nullable)
          t++;

        if (is_nullable && JS_IsNull (arg))
          cpu_context = NULL;
        else if (!_gum_quick_cpu_context_get (ctx, arg, core, &cpu_context))
          goto propagate_exception;

        *va_arg (ap, GumCpuContext **) = cpu_context;

        break;
      }
      case 'M':
      {
        GumMatchPattern * pattern;

        if (JS_IsString (arg))
        {
          const char * str;

          str = JS_ToCString (ctx, arg);
          if (str == NULL)
            goto propagate_exception;

          pattern = gum_match_pattern_new_from_string (str);

          JS_FreeCString (ctx, str);

          if (pattern == NULL)
            goto invalid_pattern;
        }
        else if (JS_IsObject (arg))
        {
          pattern = JS_GetOpaque (arg, core->match_pattern_class);
          if (pattern == NULL)
            goto expected_pattern;

          gum_match_pattern_ref (pattern);
        }
        else
        {
          goto expected_pattern;
        }

        *va_arg (ap, GumMatchPattern **) = pattern;

        gum_quick_args_free_match_pattern_later (self, pattern);

        break;
      }
      default:
        g_assert_not_reached ();
    }

    arg_index++;
  }

  va_end (ap);

  return TRUE;

missing_argument:
  {
    error_message = "missing argument";
    goto propagate_exception;
  }
expected_object_or_string:
  {
    error_message = "expected an object or string";
    goto propagate_exception;
  }
expected_object:
  {
    error_message = "expected an object";
    goto propagate_exception;
  }
expected_array:
  {
    error_message = "expected an array";
    goto propagate_exception;
  }
expected_callback_object:
  {
    error_message = "expected an object containing callbacks";
    goto propagate_exception;
  }
expected_callback_value:
  {
    error_message = "expected a callback value";
    goto propagate_exception;
  }
expected_function:
  {
    error_message = "expected a function";
    goto propagate_exception;
  }
invalid_pattern:
  {
    error_message = "invalid match pattern";
    goto propagate_exception;
  }
expected_pattern:
  {
    error_message = "expected either a pattern string or a MatchPattern object";
    goto propagate_exception;
  }
propagate_exception:
  {
    va_end (ap);

    if (error_message != NULL)
      _gum_quick_throw_literal (ctx, error_message);

    return FALSE;
  }
}

GBytes *
_gum_quick_args_steal_bytes (GumQuickArgs * self,
                             GBytes * bytes)
{
  self->bytes = g_slist_remove (self->bytes, bytes);
  return bytes;
}

static void
gum_quick_args_free_value_later (GumQuickArgs * self,
                                 JSValue v)
{
  if (!JS_VALUE_HAS_REF_COUNT (v))
    return;

  if (self->values == NULL)
    self->values = g_array_sized_new (FALSE, FALSE, sizeof (JSValue), 4);

  g_array_append_val (self->values, v);
}

static void
gum_quick_args_free_cstring_later (GumQuickArgs * self,
                                   const char * s)
{
  if (s == NULL)
    return;

  self->cstrings = g_slist_prepend (self->cstrings, (gpointer) s);
}

static void
gum_quick_args_free_array_later (GumQuickArgs * self,
                                 GArray * a)
{
  if (a == NULL)
    return;

  self->arrays = g_slist_prepend (self->arrays, a);
}

static void
gum_quick_args_free_bytes_later (GumQuickArgs * self,
                                 GBytes * b)
{
  if (b == NULL)
    return;

  self->bytes = g_slist_prepend (self->bytes, b);
}

static void
gum_quick_args_free_match_pattern_later (GumQuickArgs * self,
                                         GumMatchPattern * p)
{
  if (p == NULL)
    return;

  self->match_patterns = g_slist_prepend (self->match_patterns, p);
}

gboolean
_gum_quick_string_get (JSContext * ctx,
                       JSValueConst val,
                       const char ** str)
{
  if (!JS_IsString (val))
    goto expected_string;

  *str = JS_ToCString (ctx, val);
  return *str != NULL;

expected_string:
  {
    _gum_quick_throw_literal (ctx, "expected a string");
    return FALSE;
  }
}

gboolean
_gum_quick_bytes_get (JSContext * ctx,
                      JSValueConst val,
                      GumQuickCore * core,
                      GBytes ** bytes)
{
  uint8_t * data;
  size_t size;
  JSValue exception;
  gboolean buffer_is_empty;
  gboolean is_array_buffer;
  JSValue element = JS_NULL;
  guint8 * tmp_array = NULL;

  data = JS_GetArrayBuffer (ctx, &size, val);

  exception = JS_GetException (ctx);
  buffer_is_empty = data == NULL && JS_IsNull (exception);
  JS_FreeValue (ctx, exception);

  is_array_buffer = data != NULL || buffer_is_empty;

  if (!is_array_buffer)
  {
    JSValue buf;
    size_t byte_offset, byte_length;

    buf = JS_GetTypedArrayBuffer (ctx, val, &byte_offset, &byte_length, NULL);
    if (!JS_IsException (buf))
    {
      *bytes = g_bytes_new (JS_GetArrayBuffer (ctx, &size, buf) + byte_offset,
          byte_length);

      JS_FreeValue (ctx, buf);

      return TRUE;
    }
    else
    {
      JS_FreeValue (ctx, JS_GetException (ctx));
    }
  }

  if (is_array_buffer)
  {
    *bytes = g_bytes_new (data, size);
  }
  else if (JS_IsArray (ctx, val))
  {
    guint n, i;

    if (!_gum_quick_array_get_length (ctx, val, core, &n))
      return FALSE;

    if (n >= GUM_MAX_JS_BYTE_ARRAY_LENGTH)
      goto array_too_large;

    tmp_array = g_malloc (n);

    for (i = 0; i != n; i++)
    {
      uint32_t u;

      element = JS_GetPropertyUint32 (ctx, val, i);
      if (JS_IsException (element))
        goto propagate_exception;

      if (JS_ToUint32 (ctx, &u, element) != 0)
        goto propagate_exception;

      tmp_array[i] = u;

      JS_FreeValue (ctx, element);
      element = JS_NULL;
    }

    *bytes = g_bytes_new_take (tmp_array, n);
  }
  else
  {
    goto expected_bytes;
  }

  return TRUE;

expected_bytes:
  {
    _gum_quick_throw_literal (ctx, "expected a buffer-like object");
    goto propagate_exception;
  }
array_too_large:
  {
    _gum_quick_throw_literal (ctx, "array too large, use ArrayBuffer instead");
    goto propagate_exception;
  }
propagate_exception:
  {
    JS_FreeValue (ctx, element);
    g_free (tmp_array);

    return FALSE;
  }
}

gboolean
_gum_quick_bytes_parse (JSContext * ctx,
                        JSValueConst val,
                        GumQuickCore * core,
                        GBytes ** bytes)
{
  if (JS_IsString (val))
  {
    const char * str;

    str = JS_ToCString (ctx, val);

    *bytes = g_bytes_new (str, strlen (str));

    JS_FreeCString (ctx, str);

    return TRUE;
  }

  return _gum_quick_bytes_get (ctx, val, core, bytes);
}

gboolean
_gum_quick_boolean_get (JSContext * ctx,
                        JSValueConst val,
                        gboolean * b)
{
  if (!JS_IsBool (val))
    goto expected_boolean;

  *b = JS_VALUE_GET_BOOL (val);
  return TRUE;

expected_boolean:
  {
    _gum_quick_throw_literal (ctx, "expected a boolean");
    return FALSE;
  }
}

gboolean
_gum_quick_int_get (JSContext * ctx,
                    JSValueConst val,
                    gint * i)
{
  int32_t v;

  if (!JS_IsNumber (val))
    goto expected_int;

  if (JS_ToInt32 (ctx, &v, val) != 0)
    return FALSE;

  *i = v;
  return TRUE;

expected_int:
  {
    _gum_quick_throw_literal (ctx, "expected an integer");
    return FALSE;
  }
}

gboolean
_gum_quick_uint_get (JSContext * ctx,
                     JSValueConst val,
                     guint * u)
{
  uint32_t v;

  if (!JS_IsNumber (val))
    goto expected_uint;

  if (JS_ToUint32 (ctx, &v, val) != 0)
    return FALSE;

  *u = v;
  return TRUE;

expected_uint:
  {
    _gum_quick_throw_literal (ctx, "expected an unsigned integer");
    return FALSE;
  }
}

JSValue
_gum_quick_int64_new (JSContext * ctx,
                      gint64 i,
                      GumQuickCore * core)
{
  JSValue wrapper;
  GumQuickInt64 * i64;

  wrapper = JS_NewObjectClass (ctx, core->int64_class);

  i64 = g_slice_new (GumQuickInt64);
  i64->value = i;

  JS_SetOpaque (wrapper, i64);

  return wrapper;
}

gboolean
_gum_quick_int64_unwrap (JSContext * ctx,
                         JSValueConst val,
                         GumQuickCore * core,
                         GumQuickInt64 ** instance)
{
  return _gum_quick_unwrap (ctx, val, core->int64_class, core,
      (gpointer *) instance);
}

gboolean
_gum_quick_int64_get (JSContext * ctx,
                      JSValueConst val,
                      GumQuickCore * core,
                      gint64 * i)
{
  if (JS_IsNumber (val))
  {
    int64_t v;

    if (JS_ToInt64 (ctx, &v, val) != 0)
      return FALSE;

    *i = v;
  }
  else
  {
    GumQuickInt64 * i64;

    if (!_gum_quick_int64_unwrap (ctx, val, core, &i64))
      return FALSE;

    *i = i64->value;
  }

  return TRUE;
}

gboolean
_gum_quick_int64_parse (JSContext * ctx,
                        JSValueConst val,
                        GumQuickCore * core,
                        gint64 * i)
{
  if (JS_IsString (val))
  {
    const gchar * value_as_string, * end;
    gboolean valid;

    value_as_string = JS_ToCString (ctx, val);

    if (g_str_has_prefix (value_as_string, "0x"))
    {
      *i = g_ascii_strtoll (value_as_string + 2, (gchar **) &end, 16);
      valid = end != value_as_string + 2;
    }
    else
    {
      *i = g_ascii_strtoll (value_as_string, (gchar **) &end, 10);
      valid = end != value_as_string;
    }

    JS_FreeCString (ctx, value_as_string);

    if (!valid)
      _gum_quick_throw_literal (ctx, "expected an integer");

    return valid;
  }

  return _gum_quick_int64_get (ctx, val, core, i);
}

JSValue
_gum_quick_uint64_new (JSContext * ctx,
                       guint64 u,
                       GumQuickCore * core)
{
  JSValue wrapper;
  GumQuickUInt64 * u64;

  wrapper = JS_NewObjectClass (ctx, core->uint64_class);

  u64 = g_slice_new (GumQuickUInt64);
  u64->value = u;

  JS_SetOpaque (wrapper, u64);

  return wrapper;
}

gboolean
_gum_quick_uint64_unwrap (JSContext * ctx,
                          JSValueConst val,
                          GumQuickCore * core,
                          GumQuickUInt64 ** instance)
{
  return _gum_quick_unwrap (ctx, val, core->uint64_class, core,
      (gpointer *) instance);
}

gboolean
_gum_quick_uint64_get (JSContext * ctx,
                       JSValueConst val,
                       GumQuickCore * core,
                       guint64 * u)
{
  if (JS_IsNumber (val))
  {
    double v;

    if (JS_ToFloat64 (ctx, &v, val) != 0)
      return FALSE;

    if (v < 0)
      goto expected_uint;

    *u = (guint64) v;
  }
  else
  {
    GumQuickUInt64 * u64;

    if (!_gum_quick_uint64_unwrap (ctx, val, core, &u64))
      return FALSE;

    *u = u64->value;
  }

  return TRUE;

expected_uint:
  {
    _gum_quick_throw_literal (ctx, "expected an unsigned integer");
    return FALSE;
  }
}

gboolean
_gum_quick_uint64_parse (JSContext * ctx,
                         JSValueConst val,
                         GumQuickCore * core,
                         guint64 * u)
{
  if (JS_IsString (val))
  {
    const gchar * value_as_string, * end;
    gboolean valid;

    value_as_string = JS_ToCString (ctx, val);

    if (g_str_has_prefix (value_as_string, "0x"))
      *u = g_ascii_strtoull (value_as_string + 2, (gchar **) &end, 16);
    else
      *u = g_ascii_strtoull (value_as_string, (gchar **) &end, 10);

    valid = end == value_as_string + strlen (value_as_string);

    JS_FreeCString (ctx, value_as_string);

    if (!valid)
      _gum_quick_throw_literal (ctx, "expected an unsigned integer");

    return valid;
  }

  return _gum_quick_uint64_get (ctx, val, core, u);
}

gboolean
_gum_quick_size_get (JSContext * ctx,
                     JSValueConst val,
                     GumQuickCore * core,
                     gsize * size)
{
  GumQuickUInt64 * u64;
  GumQuickInt64 * i64;

  if (JS_IsNumber (val))
  {
    double v;

    if (JS_ToFloat64 (ctx, &v, val) != 0)
      return FALSE;

    if (v < 0)
      goto expected_uint;

    *size = (gsize) v;
  }
  else if (_gum_quick_try_unwrap (val, core->uint64_class, core,
      (gpointer *) &u64))
  {
    *size = u64->value;
  }
  else if (_gum_quick_try_unwrap (val, core->int64_class, core,
      (gpointer *) &i64))
  {
    if (i64->value < 0)
      goto expected_uint;

    *size = i64->value;
  }
  else
  {
    goto expected_uint;
  }

  return TRUE;

expected_uint:
  {
    _gum_quick_throw_literal (ctx, "expected an unsigned integer");
    return FALSE;
  }
}

gboolean
_gum_quick_ssize_get (JSContext * ctx,
                      JSValueConst val,
                      GumQuickCore * core,
                      gssize * size)
{
  GumQuickInt64 * i64;
  GumQuickUInt64 * u64;

  if (JS_IsNumber (val))
  {
    int64_t v;

    if (JS_ToInt64 (ctx, &v, val) != 0)
      goto expected_int;

    *size = v;
  }
  else if (_gum_quick_try_unwrap (val, core->int64_class, core,
      (gpointer *) &i64))
  {
    *size = i64->value;
  }
  else if (_gum_quick_try_unwrap (val, core->uint64_class, core,
      (gpointer *) &u64))
  {
    *size = u64->value;
  }
  else
  {
    goto expected_int;
  }

  return TRUE;

expected_int:
  {
    _gum_quick_throw_literal (ctx, "expected an integer");
    return FALSE;
  }
}

gboolean
_gum_quick_float64_get (JSContext * ctx,
                        JSValueConst val,
                        gdouble * d)
{
  double v;

  if (!JS_IsNumber (val))
    goto expected_number;

  if (JS_ToFloat64 (ctx, &v, val) != 0)
    return FALSE;

  *d = v;
  return TRUE;

expected_number:
  {
    _gum_quick_throw_literal (ctx, "expected a number");
    return FALSE;
  }
}

JSValue
_gum_quick_enum_new (JSContext * ctx,
                     gint value,
                     GType type)
{
  JSValue result;
  GEnumClass * enum_class;
  GEnumValue * enum_value;

  enum_class = g_type_class_ref (type);

  enum_value = g_enum_get_value (enum_class, value);
  g_assert (enum_value != NULL);

  result = JS_NewString (ctx, enum_value->value_nick);

  g_type_class_unref (enum_class);

  return result;
}

JSValue
_gum_quick_native_pointer_new (JSContext * ctx,
                               gpointer ptr,
                               GumQuickCore * core)
{
  JSValue wrapper;
  GumQuickNativePointer * np;

  wrapper = JS_NewObjectClass (ctx, core->native_pointer_class);

  np = g_slice_new (GumQuickNativePointer);
  np->value = ptr;

  JS_SetOpaque (wrapper, np);

  return wrapper;
}

gboolean
_gum_quick_native_pointer_unwrap (JSContext * ctx,
                                  JSValueConst val,
                                  GumQuickCore * core,
                                  GumQuickNativePointer ** instance)
{
  return _gum_quick_unwrap (ctx, val, core->native_pointer_class, core,
      (gpointer *) instance);
}

gboolean
_gum_quick_native_pointer_get (JSContext * ctx,
                               JSValueConst val,
                               GumQuickCore * core,
                               gpointer * ptr)
{
  if (!_gum_quick_native_pointer_try_get (ctx, val, core, ptr))
  {
    _gum_quick_throw_literal (ctx, "expected a pointer");
    return FALSE;
  }

  return TRUE;
}

gboolean
_gum_quick_native_pointer_try_get (JSContext * ctx,
                                   JSValueConst val,
                                   GumQuickCore * core,
                                   gpointer * ptr)
{
  gboolean success = FALSE;
  GumQuickNativePointer * p;

  if (_gum_quick_try_unwrap (val, core->native_pointer_class, core,
      (gpointer *) &p))
  {
    *ptr = p->value;
    success = TRUE;
  }
  else if (JS_IsObject (val))
  {
    JSValue handle;

    handle = JS_GetProperty (ctx, val, GUM_QUICK_CORE_ATOM (core, handle));
    if (!JS_IsException (val))
    {
      if (_gum_quick_try_unwrap (handle, core->native_pointer_class, core,
          (gpointer *) &p))
      {
        *ptr = p->value;
        success = TRUE;
      }

      JS_FreeValue (ctx, handle);
    }
    else
    {
      JS_FreeValue (ctx, JS_GetException (ctx));
    }
  }

  return success;
}

gboolean
_gum_quick_native_pointer_parse (JSContext * ctx,
                                 JSValueConst val,
                                 GumQuickCore * core,
                                 gpointer * ptr)
{
  GumQuickUInt64 * u64;
  GumQuickInt64 * i64;

  if (_gum_quick_native_pointer_try_get (ctx, val, core, ptr))
    return TRUE;

  if (JS_IsString (val))
  {
    const gchar * ptr_as_string, * end;
    gboolean valid;

    ptr_as_string = JS_ToCString (ctx, val);

    if (g_str_has_prefix (ptr_as_string, "0x"))
    {
      *ptr = GSIZE_TO_POINTER (
          g_ascii_strtoull (ptr_as_string + 2, (gchar **) &end, 16));
    }
    else
    {
      *ptr = GSIZE_TO_POINTER (
          g_ascii_strtoull (ptr_as_string, (gchar **) &end, 10));
    }

    valid = end == ptr_as_string + strlen (ptr_as_string);

    JS_FreeCString (ctx, ptr_as_string);

    if (!valid)
      goto expected_pointer;
  }
  else if (JS_IsNumber (val))
  {
#if G_BYTE_ORDER == G_LITTLE_ENDIAN || GLIB_SIZEOF_VOID_P == 8
    union
    {
      gpointer p;
      int64_t i;
    } v;
#else
    union
    {
      struct
      {
        gpointer _pad;
        gpointer p;
      };
      int64_t i;
    } v;
#endif

    JS_ToInt64 (ctx, &v.i, val);

    *ptr = v.p;
  }
  else if (_gum_quick_try_unwrap (val, core->uint64_class, core,
      (gpointer *) &u64))
  {
    *ptr = GSIZE_TO_POINTER (u64->value);
  }
  else if (_gum_quick_try_unwrap (val, core->int64_class, core,
      (gpointer *) &i64))
  {
    *ptr = GSIZE_TO_POINTER (i64->value);
  }
  else
  {
    goto expected_pointer;
  }

  return TRUE;

expected_pointer:
  {
    _gum_quick_throw_literal (ctx, "expected a pointer");
    return FALSE;
  }
}

JSValue
_gum_quick_native_resource_new (JSContext * ctx,
                                gpointer data,
                                GDestroyNotify notify,
                                GumQuickCore * core)
{
  JSValue wrapper;
  GumQuickNativeResource * res;
  GumQuickNativePointer * ptr;

  wrapper = JS_NewObjectClass (ctx, core->native_resource_class);

  res = g_slice_new (GumQuickNativeResource);
  ptr = &res->native_pointer;
  ptr->value = data;
  res->notify = notify;

  JS_SetOpaque (wrapper, res);

  return wrapper;
}

JSValue
_gum_quick_kernel_resource_new (JSContext * ctx,
                                GumAddress data,
                                GumQuickKernelDestroyNotify notify,
                                GumQuickCore * core)
{
  JSValue wrapper;
  GumQuickKernelResource * res;
  GumQuickUInt64 * u64;

  wrapper = JS_NewObjectClass (ctx, core->kernel_resource_class);

  res = g_slice_new (GumQuickKernelResource);
  u64 = &res->u64;
  u64->value = data;
  res->notify = notify;

  JS_SetOpaque (wrapper, res);

  return wrapper;
}

JSValue
_gum_quick_cpu_context_new (JSContext * ctx,
                            GumCpuContext * handle,
                            GumQuickCpuContextAccess access,
                            GumQuickCore * core,
                            GumQuickCpuContext ** cpu_context)
{
  GumQuickCpuContext * cc;
  JSValue wrapper;

  wrapper = JS_NewObjectClass (ctx, core->cpu_context_class);

  cc = g_slice_new (GumQuickCpuContext);
  cc->wrapper = wrapper;
  cc->core = core;

  JS_SetOpaque (wrapper, cc);

  _gum_quick_cpu_context_reset (cc, handle, access);

  if (cpu_context != NULL)
    *cpu_context = cc;

  return wrapper;
}

void
_gum_quick_cpu_context_reset (GumQuickCpuContext * self,
                              GumCpuContext * handle,
                              GumQuickCpuContextAccess access)
{
  if (handle != NULL)
  {
    if (access == GUM_CPU_CONTEXT_READWRITE)
    {
      self->handle = handle;
    }
    else
    {
      memcpy (&self->storage, handle, sizeof (GumCpuContext));
      self->handle = &self->storage;
    }
  }
  else
  {
    self->handle = NULL;
  }

  self->access = access;
}

void
_gum_quick_cpu_context_make_read_only (GumQuickCpuContext * self)
{
  if (self->access == GUM_CPU_CONTEXT_READWRITE)
  {
    memcpy (&self->storage, self->handle, sizeof (GumCpuContext));
    self->handle = &self->storage;
    self->access = GUM_CPU_CONTEXT_READONLY;
  }
}

gboolean
_gum_quick_cpu_context_unwrap (JSContext * ctx,
                               JSValueConst val,
                               GumQuickCore * core,
                               GumQuickCpuContext ** instance)
{
  return _gum_quick_unwrap (ctx, val, core->cpu_context_class, core,
      (gpointer *) instance);
}

gboolean
_gum_quick_cpu_context_get (JSContext * ctx,
                            JSValueConst val,
                            GumQuickCore * core,
                            GumCpuContext ** cpu_context)
{
  GumQuickCpuContext * instance;

  if (!_gum_quick_cpu_context_unwrap (ctx, val, core, &instance))
    return FALSE;

  *cpu_context = instance->handle;
  return TRUE;
}

JSValue
_gum_quick_thread_state_new (JSContext * ctx,
                             GumThreadState state)
{
  return JS_NewString (ct
```