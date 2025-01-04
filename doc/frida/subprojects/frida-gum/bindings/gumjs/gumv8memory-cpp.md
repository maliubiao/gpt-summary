Response:
The user wants a summary of the functionality of the provided C++ code file, `gumv8memory.cpp`, which is part of the Frida dynamic instrumentation tool. I need to go through the code and identify the main features it implements.

Here's a breakdown of the key functionalities:

1. **Memory Allocation and Deallocation:** Functions like `gumjs_memory_alloc` handle allocating memory, potentially near a specified address.
2. **Memory Manipulation:**  Functions like `gumjs_memory_copy` for copying memory, `gumjs_memory_protect` for changing memory protection, and read/write functions for various data types.
3. **Code Patching:** `gumjs_memory_patch_code` allows modifying code in memory.
4. **Memory Scanning:** `gumjs_memory_scan` and `gumjs_memory_scan_sync` provide mechanisms to search for patterns within memory ranges.
5. **Memory Access Monitoring:** `gumjs_memory_access_monitor_enable` and `gumjs_memory_access_monitor_disable` allow tracking memory accesses.
6. **String Handling:**  Functions to allocate and read/write various string types (ANSI, UTF-8, UTF-16).

I also need to address specific aspects:

- **Relationship to Reversing:**  Many of these functionalities are core to reverse engineering, allowing inspection and modification of a running process.
- **Binary/Kernel/Framework Knowledge:**  Memory management, protection, and code patching directly interact with the operating system's memory management and potentially the kernel. String handling often involves encoding knowledge.
- **Logic and I/O:** Memory operations inherently have inputs (address, data) and outputs (success, read values).
- **User Errors:**  Incorrect sizes, invalid addresses, and type mismatches are common user errors.
- **User Operations to Reach Here:**  A user would typically interact with the Frida API in a scripting language (like JavaScript or Python), which then calls into these native functions.

Finally, I need to provide a concise summary of the overall functionality as requested in the prompt's "第1部分" instruction.
这个C++源代码文件 `gumv8memory.cpp` 是 Frida 动态 instrumentation 工具中 `frida-gum` 组件的一部分，它主要负责提供 JavaScript 访问和操作目标进程内存的功能。  以下是它的功能归纳：

**功能归纳：**

该文件定义并实现了 `Memory` 模块，该模块在 JavaScript 中暴露了一系列函数，用于：

1. **内存的分配和释放：**  允许在目标进程的内存空间中分配新的内存块 (`_alloc`)，并提供不同策略的分配方式（如靠近指定地址分配）。
2. **内存的读取和写入：**  提供各种数据类型的内存读写操作 (`read*`, `write*`)，支持读取和写入指针、各种大小的整数（有符号和无符号）、浮点数、字节数组以及不同编码的字符串（C 字符串、UTF-8、UTF-16、ANSI）。
3. **内存的保护属性修改：**  允许修改目标进程内存区域的保护属性 (`protect`)，例如将其设置为可读、可写、可执行等。
4. **查询内存保护属性：**  可以查询指定内存地址的保护属性 (`queryProtection`)。
5. **代码的 Patch：**  允许修改目标进程内存中的代码 (`_patchCode`)，这在动态修改程序行为时非常有用。
6. **检查代码指针的有效性：** 提供一个函数来检查给定的指针是否指向可读的代码 (`_checkCodePointer`)。
7. **内存扫描：**  提供同步 (`scanSync`) 和异步 (`_scan`) 两种方式在指定的内存范围内搜索匹配特定模式的数据。
8. **内存访问监控：**  允许启用和禁用对特定内存区域的访问监控 (`enable`, `disable`)，当目标进程访问这些区域时会触发回调。
9. **特定类型字符串的分配：** 提供专门的函数用于分配并初始化 ANSI、UTF-8 和 UTF-16 编码的字符串 (`allocAnsiString`, `allocUtf8String`, `allocUtf16String`)。

**与逆向方法的关系及举例说明：**

这个文件提供的功能是逆向工程中的核心操作。逆向工程师经常需要查看和修改目标程序的内存来理解其行为或进行漏洞分析。

* **内存读取：**  逆向工程师可以使用 `read*` 函数来查看变量的值、数据结构的内容、函数参数等。例如，要查看地址 `0x12345678` 处的 32 位整数值，可以使用 JavaScript 代码 `Memory.readInt(ptr('0x12345678'))`。
* **内存写入：**  可以用来修改程序的状态。例如，修改一个布尔标志的值来绕过某些检查，可以使用 `Memory.writeInt(ptr('0x98765432'), 1)` 将地址 `0x98765432` 处的值设置为 1。
* **代码 Patch：**  在运行时修改函数指令是高级逆向技术。例如，可以将一个条件跳转指令修改为无条件跳转，从而跳过某个功能逻辑，可以使用 `Memory.patchCode(ptr('0xABCDEF00'), 'arm', [0xeafffffe])` （ARM 架构示例，具体指令需要根据目标架构调整）。
* **内存扫描：**  可以用来寻找特定的数据或代码模式。例如，在一段内存中搜索特定的字符串常量，可以使用 `Memory.scanSync(ptr('0x...'), 1024, "SEARCH_ME")`。
* **内存访问监控：** 用于追踪特定内存区域的访问情况，帮助理解程序的运行流程和数据流。例如，监控某个全局变量的写入操作，可以使用 `MemoryAccessMonitor.enable([{ base: ptr('0x...') , size: 4 }], { onAccess: function(details) { console.log(details); } })`。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

这个文件直接操作内存，因此与底层的操作系统和硬件架构密切相关。

* **二进制底层:**  读取和写入不同大小的整数（8位、16位、32位、64位）以及浮点数，需要理解这些数据类型在内存中的二进制表示方式（例如，大小端序）。
* **Linux/Android 内核:**  `gum_alloc_n_pages`, `gum_free_pages`, `gum_try_mprotect`, `gum_memory_query_protection` 等函数是与操作系统内核交互来管理内存的。例如，`gum_try_mprotect` 函数调用底层的 `mprotect` 系统调用来修改内存保护属性。在 Android 上，这涉及到 Linux 内核的内存管理机制。
* **框架知识:**  在 Android 平台上，Frida 经常用于 hook Java 层的代码。虽然这个文件直接操作 Native 层的内存，但它提供的能力是实现 Java hook 的基础。例如，可以通过内存操作找到 ART 虚拟机的内部结构，并修改方法入口地址以实现 hook。
* **页大小 (page size):** `gum_query_page_size()` 用于获取操作系统的内存页大小，这在分配内存时需要考虑，尤其是在 `gum_try_alloc_n_pages_near` 中，分配的尺寸必须是页大小的倍数。
* **内存保护属性 (GumPageProtection):**  枚举类型 `GumPageProtection` 定义了各种内存保护属性，例如 `GUM_PAGE_RW` (可读写)，`GUM_PAGE_EXECUTE` (可执行) 等。

**逻辑推理、假设输入与输出：**

例如 `gumjs_memory_copy` 函数：

* **假设输入：**
    * `destination`: 内存地址 `0x4000`
    * `source`: 内存地址 `0x5000`
    * `size`: 100 字节
* **逻辑推理：** 函数会调用 `memmove` 将从 `source` 地址开始的 100 字节数据复制到 `destination` 地址。`memmove` 保证了即使 `source` 和 `destination` 区域重叠，也能正确复制数据。
* **预期输出：** 内存地址 `0x4000` 到 `0x4063` 的内容将与内存地址 `0x5000` 到 `0x5063` 的原始内容相同。

例如 `gumjs_memory_protect` 函数：

* **假设输入：**
    * `address`: 内存地址 `0x6000`
    * `size`: 4096 字节 (假设页大小为 4096)
    * `prot`: `GUM_PAGE_READONLY`
* **逻辑推理：** 函数会尝试调用 `gum_try_mprotect` 将从 `address` 开始的 4096 字节内存区域的保护属性设置为只读。
* **预期输出：** 如果操作成功，返回 `true`，并且尝试写入该区域将会导致程序崩溃或产生异常。

**涉及用户或编程常见的使用错误及举例说明：**

* **无效的内存地址：**  如果用户传递了一个程序无法访问的内存地址，例如一个未映射的地址，尝试读取或写入该地址会导致错误。 例如，JavaScript 代码 `Memory.readInt(ptr('0x0'))` 可能会导致程序崩溃。
* **错误的大小参数：**  在读取或写入字节数组时，如果指定的大小超出了实际可访问的范围，会导致读取越界或写入越界。 例如，如果地址 `0x7000` 只分配了 10 个字节，但用户尝试 `Memory.readByteArray(ptr('0x7000'), 100)`，则会出错。
* **类型不匹配：**  使用错误的 `read*` 或 `write*` 函数读取或写入数据会导致数据解析错误。 例如，在一个存储着 64 位整数的地址使用 `Memory.readInt()` 读取，只会得到低 32 位的值。
* **在不允许的内存区域进行修改：** 尝试修改只读内存区域会导致错误。 例如，修改代码段的常量字符串可能会失败。
* **`_patchCode` 使用不当:**  提供的字节码不正确或者目标地址没有足够的空间容纳提供的指令，会导致程序崩溃或行为异常。

**用户操作是如何一步步的到达这里，作为调试线索：**

用户通常不会直接调用这些 C++ 函数。他们会使用 Frida 提供的脚本语言 API (通常是 JavaScript 或 Python)。

1. **用户编写 Frida 脚本：** 用户使用 JavaScript 代码调用 `Memory` 模块的函数，例如 `Memory.readInt(ptr('0x12345678'))`。
2. **Frida 脚本引擎解析执行：** Frida 的 JavaScript 引擎 (基于 V8) 解析并执行这些脚本。
3. **调用 GumJS 绑定层：** 当执行到 `Memory.readInt` 时，V8 引擎会调用到 `gumjs` 绑定层，该层会将 JavaScript 的调用转换为对相应的 C++ 函数的调用，例如 `gumjs_memory_read_S32`。
4. **执行 C++ 函数：** `gumjs_memory_read_S32` 函数会进一步调用底层的 Gum 库函数来执行实际的内存读取操作。
5. **底层 Gum 库交互：** Gum 库会与操作系统内核交互，完成内存读取或写入等操作。

**调试线索：**

当用户在使用 Frida 脚本时遇到问题，例如读取到错误的值或程序崩溃，可以从以下方面入手调试：

* **检查 JavaScript 代码：**  确认调用的函数名、参数类型和值是否正确。
* **查看 Frida 的日志输出：**  Frida 会输出一些调试信息，可以帮助定位问题。
* **使用 Frida 的 Inspector 或其他调试工具：**  可以查看目标进程的内存布局，确认要操作的地址是否正确，以及内存保护属性。
* **分析 C++ 源码 (如本文件)：**  如果怀疑是 Frida 自身的问题，可以查看 `gumv8memory.cpp` 等相关源码，了解 Frida 是如何处理用户请求的。例如，查看参数解析部分 (`_gum_v8_args_parse`) 是否有潜在的错误。
* **使用 GDB 等 C++ 调试器调试 Frida 服务端：**  可以 attach 到 Frida 的服务端进程，设置断点，查看 C++ 函数的调用堆栈和变量值，从而更深入地了解问题发生的原因。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8memory.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8memory.h"

#include "gumv8macros.h"
#include "gumv8scope.h"

#include <string.h>
#include <wchar.h>
#ifdef HAVE_WINDOWS
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
#endif

#define GUMJS_MODULE_NAME Memory

using namespace v8;

enum GumMemoryValueType
{
  GUM_MEMORY_VALUE_POINTER,
  GUM_MEMORY_VALUE_S8,
  GUM_MEMORY_VALUE_U8,
  GUM_MEMORY_VALUE_S16,
  GUM_MEMORY_VALUE_U16,
  GUM_MEMORY_VALUE_S32,
  GUM_MEMORY_VALUE_U32,
  GUM_MEMORY_VALUE_S64,
  GUM_MEMORY_VALUE_U64,
  GUM_MEMORY_VALUE_LONG,
  GUM_MEMORY_VALUE_ULONG,
  GUM_MEMORY_VALUE_FLOAT,
  GUM_MEMORY_VALUE_DOUBLE,
  GUM_MEMORY_VALUE_BYTE_ARRAY,
  GUM_MEMORY_VALUE_C_STRING,
  GUM_MEMORY_VALUE_UTF8_STRING,
  GUM_MEMORY_VALUE_UTF16_STRING,
  GUM_MEMORY_VALUE_ANSI_STRING
};

struct GumMemoryPatchContext
{
  Local<Function> apply;
  gboolean has_pending_exception;

  GumV8Core * core;
};

struct GumMemoryScanContext
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  Global<Function> * on_match;
  Global<Function> * on_error;
  Global<Function> * on_complete;

  GumV8Core * core;
};

struct GumMemoryScanSyncContext
{
  Local<Array> matches;

  GumV8Core * core;
};

GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc)
GUMJS_DECLARE_FUNCTION (gumjs_memory_copy)
GUMJS_DECLARE_FUNCTION (gumjs_memory_protect)
GUMJS_DECLARE_FUNCTION (gumjs_memory_query_protection)
GUMJS_DECLARE_FUNCTION (gumjs_memory_patch_code)
static void gum_memory_patch_context_apply (gpointer mem,
    GumMemoryPatchContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_memory_check_code_pointer)

static void gum_v8_memory_read (GumMemoryValueType type,
    const GumV8Args * args, ReturnValue<Value> return_value);
static void gum_v8_memory_write (GumMemoryValueType type,
    const GumV8Args * args);
GUMJS_DECLARE_FUNCTION (gum_v8_memory_read_volatile)

#ifdef HAVE_WINDOWS
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif

#define GUM_DEFINE_MEMORY_READ(T) \
    GUMJS_DEFINE_FUNCTION (gumjs_memory_read_##T) \
    { \
      gum_v8_memory_read (GUM_MEMORY_VALUE_##T, args, info.GetReturnValue ()); \
    }
#define GUM_DEFINE_MEMORY_WRITE(T) \
    GUMJS_DEFINE_FUNCTION (gumjs_memory_write_##T) \
    { \
      gum_v8_memory_write (GUM_MEMORY_VALUE_##T, args); \
    }
#define GUM_DEFINE_MEMORY_READ_WRITE(T) \
    GUM_DEFINE_MEMORY_READ (T); \
    GUM_DEFINE_MEMORY_WRITE (T)

#define GUMJS_EXPORT_MEMORY_READ(N, T) \
    { "read" N, gumjs_memory_read_##T }
#define GUMJS_EXPORT_MEMORY_WRITE(N, T) \
    { "write" N, gumjs_memory_write_##T }
#define GUMJS_EXPORT_MEMORY_READ_WRITE(N, T) \
    GUMJS_EXPORT_MEMORY_READ (N, T), \
    GUMJS_EXPORT_MEMORY_WRITE (N, T)

GUM_DEFINE_MEMORY_READ_WRITE (POINTER)
GUM_DEFINE_MEMORY_READ_WRITE (S8)
GUM_DEFINE_MEMORY_READ_WRITE (U8)
GUM_DEFINE_MEMORY_READ_WRITE (S16)
GUM_DEFINE_MEMORY_READ_WRITE (U16)
GUM_DEFINE_MEMORY_READ_WRITE (S32)
GUM_DEFINE_MEMORY_READ_WRITE (U32)
GUM_DEFINE_MEMORY_READ_WRITE (S64)
GUM_DEFINE_MEMORY_READ_WRITE (U64)
GUM_DEFINE_MEMORY_READ_WRITE (LONG)
GUM_DEFINE_MEMORY_READ_WRITE (ULONG)
GUM_DEFINE_MEMORY_READ_WRITE (FLOAT)
GUM_DEFINE_MEMORY_READ_WRITE (DOUBLE)
GUM_DEFINE_MEMORY_READ_WRITE (BYTE_ARRAY)
GUM_DEFINE_MEMORY_READ (C_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (UTF8_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (UTF16_STRING)
GUM_DEFINE_MEMORY_READ_WRITE (ANSI_STRING)

GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc_ansi_string)
GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc_utf8_string)
GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc_utf16_string)

GUMJS_DECLARE_FUNCTION (gumjs_memory_scan)
static void gum_memory_scan_context_free (GumMemoryScanContext * self);
static void gum_memory_scan_context_run (GumMemoryScanContext * self);
static gboolean gum_memory_scan_context_emit_match (GumAddress address,
    gsize size, GumMemoryScanContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_memory_scan_sync)
static gboolean gum_append_match (GumAddress address, gsize size,
    GumMemoryScanSyncContext * ctx);

GUMJS_DECLARE_FUNCTION (gumjs_memory_access_monitor_enable)
GUMJS_DECLARE_FUNCTION (gumjs_memory_access_monitor_disable)
static void gum_v8_memory_clear_monitor (GumV8Memory * self);
static void gum_v8_memory_on_access (GumMemoryAccessMonitor * monitor,
    const GumMemoryAccessDetails * details, GumV8Memory * self);

static const GumV8Function gumjs_memory_functions[] =
{
  { "_alloc", gumjs_memory_alloc },
  { "copy", gumjs_memory_copy },
  { "protect", gumjs_memory_protect },
  { "queryProtection", gumjs_memory_query_protection },
  { "_patchCode", gumjs_memory_patch_code },
  { "_checkCodePointer", gumjs_memory_check_code_pointer },

  GUMJS_EXPORT_MEMORY_READ_WRITE ("Pointer", POINTER),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S8", S8),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U8", U8),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S16", S16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U16", U16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S32", S32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U32", U32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("S64", S64),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("U64", U64),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Short", S16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("UShort", U16),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Int", S32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("UInt", U32),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Long", LONG),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("ULong", ULONG),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Float", FLOAT),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Double", DOUBLE),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("ByteArray", BYTE_ARRAY),
  GUMJS_EXPORT_MEMORY_READ ("CString", C_STRING),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Utf8String", UTF8_STRING),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("Utf16String", UTF16_STRING),
  GUMJS_EXPORT_MEMORY_READ_WRITE ("AnsiString", ANSI_STRING),
  { "readVolatile", gum_v8_memory_read_volatile },

  { "allocAnsiString", gumjs_memory_alloc_ansi_string },
  { "allocUtf8String", gumjs_memory_alloc_utf8_string },
  { "allocUtf16String", gumjs_memory_alloc_utf16_string },

  { "_scan", gumjs_memory_scan },
  { "scanSync", gumjs_memory_scan_sync },

  { NULL, NULL }
};

static const GumV8Function gumjs_memory_access_monitor_functions[] =
{
  { "enable", gumjs_memory_access_monitor_enable },
  { "disable", gumjs_memory_access_monitor_disable },

  { NULL, NULL }
};

void
_gum_v8_memory_init (GumV8Memory * self,
                     GumV8Core * core,
                     Local<ObjectTemplate> scope)
{
  auto isolate = core->isolate;

  self->core = core;

  auto module = External::New (isolate, self);

  auto memory = _gum_v8_create_module ("Memory", scope, isolate);
  _gum_v8_module_add (module, memory, gumjs_memory_functions, isolate);

  auto monitor = _gum_v8_create_module ("MemoryAccessMonitor", scope, isolate);
  _gum_v8_module_add (module, monitor, gumjs_memory_access_monitor_functions,
      isolate);
}

void
_gum_v8_memory_realize (GumV8Memory * self)
{
}

void
_gum_v8_memory_dispose (GumV8Memory * self)
{
  gum_v8_memory_clear_monitor (self);
}

void
_gum_v8_memory_finalize (GumV8Memory * self)
{
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc)
{
  gsize size;
  GumAddressSpec spec;
  if (!_gum_v8_args_parse (args, "ZpZ", &size, &spec.near_address,
      &spec.max_distance))
    return;

  if (size == 0 || size > 0x7fffffff)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid size");
    return;
  }

  GumV8NativeResource * res;

  gsize page_size = gum_query_page_size ();

  if (spec.near_address != NULL)
  {
    gpointer result;

    if ((size % page_size) != 0)
    {
      return _gum_v8_throw_ascii_literal (isolate,
          "size must be a multiple of page size");
    }

    result = gum_try_alloc_n_pages_near (size / page_size, GUM_PAGE_RW, &spec);
    if (result == NULL)
    {
      return _gum_v8_throw_ascii_literal (isolate,
          "unable to allocate free page(s) near address");
    }

    res = _gum_v8_native_resource_new (result, size, gum_free_pages, core);
  }
  else
  {
    if ((size % page_size) != 0)
    {
      res = _gum_v8_native_resource_new (g_malloc0 (size), size, g_free, core);
    }
    else
    {
      res = _gum_v8_native_resource_new (
          gum_alloc_n_pages (size / page_size, GUM_PAGE_RW), size,
          gum_free_pages, core);
    }
  }

  info.GetReturnValue ().Set (Local<Object>::New (isolate, *res->instance));
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

GUMJS_DEFINE_FUNCTION (gumjs_memory_copy)
{
  gpointer destination, source;
  gsize size;
  if (!_gum_v8_args_parse (args, "ppZ", &destination, &source, &size))
    return;

  if (size == 0)
  {
    return;
  }
  else if (size > 0x7fffffff)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid size");
    return;
  }

  auto exceptor = args->core->exceptor;
  GumExceptorScope scope;

  if (gum_exceptor_try (exceptor, &scope))
  {
    memmove (destination, source, size);
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_protect)
{
  gpointer address;
  gsize size;
  GumPageProtection prot;
  if (!_gum_v8_args_parse (args, "pZm", &address, &size, &prot))
    return;

  if (size > 0x7fffffff)
  {
    _gum_v8_throw_ascii_literal (isolate, "invalid size");
    return;
  }

  bool success;
  if (size != 0)
    success = !!gum_try_mprotect (address, size, prot);
  else
    success = true;

  info.GetReturnValue ().Set (success);
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_query_protection)
{
  gpointer address;
  GumPageProtection prot;

  if (!_gum_v8_args_parse (args, "p", &address))
    return;

  if (!gum_memory_query_protection (address, &prot))
  {
    _gum_v8_throw_ascii_literal (isolate, "failed to query address");
    return;
  }

  info.GetReturnValue ().Set (_gum_v8_page_protection_new (isolate,  prot));
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_patch_code)
{
  gpointer address;
  gsize size;
  GumMemoryPatchContext pc;
  gboolean success;

  if (!_gum_v8_args_parse (args, "pZF", &address, &size, &pc.apply))
    return;
  pc.has_pending_exception = FALSE;
  pc.core = core;

  success = gum_memory_patch_code (address, size,
      (GumMemoryPatchApplyFunc) gum_memory_patch_context_apply, &pc);
  if (!success && !pc.has_pending_exception)
    _gum_v8_throw_ascii_literal (isolate, "invalid address");
}

static void
gum_memory_patch_context_apply (gpointer mem,
                                GumMemoryPatchContext * self)
{
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  auto recv = Undefined (isolate);
  Local<Value> argv[] = { _gum_v8_native_pointer_new (mem, self->core) };
  auto result = self->apply->Call (context, recv, G_N_ELEMENTS (argv), argv);
  self->has_pending_exception = result.IsEmpty ();
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_check_code_pointer)
{
  const guint8 * ptr;
  auto exceptor = core->exceptor;
  GumExceptorScope scope;

  if (!_gum_v8_args_parse (args, "p", &ptr))
    return;

  ptr = (const guint8 *) gum_strip_code_pointer ((gpointer) ptr);

#ifdef HAVE_ARM
  ptr = (const guint8 *) GSIZE_TO_POINTER (GPOINTER_TO_SIZE (ptr) & ~1);
#endif

  gum_ensure_code_readable (ptr, 1);

  if (gum_exceptor_try (exceptor, &scope))
  {
    info.GetReturnValue ().Set (Integer::NewFromUnsigned (isolate, *ptr));
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
  }
}

static void
gum_v8_memory_read (GumMemoryValueType type,
                    const GumV8Args * args,
                    ReturnValue<Value> return_value)
{
  auto core = args->core;
  auto isolate = core->isolate;
  auto exceptor = core->exceptor;
  gpointer address;
  gssize length = -1;
  GumExceptorScope scope;
  Local<Value> result;
  std::shared_ptr<BackingStore> store;

  switch (type)
  {
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gum_v8_args_parse (args, "pZ", &address, &length))
        return;
      break;
    case GUM_MEMORY_VALUE_C_STRING:
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      if (!_gum_v8_args_parse (args, "p|z", &address, &length))
        return;
      break;
    default:
      if (!_gum_v8_args_parse (args, "p", &address))
        return;
      break;
  }

  if (gum_exceptor_try (exceptor, &scope))
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        result = _gum_v8_native_pointer_new (*((gpointer *) address), core);
        break;
      case GUM_MEMORY_VALUE_S8:
        result = Integer::New (isolate, *((gint8 *) address));
        break;
      case GUM_MEMORY_VALUE_U8:
        result = Integer::NewFromUnsigned (isolate, *((guint8 *) address));
        break;
      case GUM_MEMORY_VALUE_S16:
        result = Integer::New (isolate, *((gint16 *) address));
        break;
      case GUM_MEMORY_VALUE_U16:
        result = Integer::NewFromUnsigned (isolate, *((guint16 *) address));
        break;
      case GUM_MEMORY_VALUE_S32:
        result = Integer::New (isolate, *((gint32 *) address));
        break;
      case GUM_MEMORY_VALUE_U32:
        result = Integer::NewFromUnsigned (isolate, *((guint32 *) address));
        break;
      case GUM_MEMORY_VALUE_S64:
        result = _gum_v8_int64_new (*((gint64 *) address), core);
        break;
      case GUM_MEMORY_VALUE_U64:
        result = _gum_v8_uint64_new (*((guint64 *) address), core);
        break;
      case GUM_MEMORY_VALUE_LONG:
        result = _gum_v8_int64_new (*((glong *) address), core);
        break;
      case GUM_MEMORY_VALUE_ULONG:
        result = _gum_v8_uint64_new (*((gulong *) address), core);
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        result = Number::New (isolate, *((gfloat *) address));
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        result = Number::New (isolate, *((gdouble *) address));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        auto data = (guint8 *) address;
        if (data == NULL)
        {
          result = Null (isolate);
          break;
        }

        if (length > 0)
        {
          result = ArrayBuffer::New (isolate, length);
          store = result.As<ArrayBuffer> ()->GetBackingStore ();
          memcpy (store->Data (), data, length);
        }
        else
        {
          result = ArrayBuffer::New (isolate, 0);
        }

        break;
      }
      case GUM_MEMORY_VALUE_C_STRING:
      {
        auto data = (gchar *) address;
        if (data == NULL)
        {
          result = Null (isolate);
          break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, data, sizeof (guint8));

          gchar * str = g_utf8_make_valid (data, length);
          result = String::NewFromUtf8 (isolate, str).ToLocalChecked ();
          g_free (str);
        }
        else
        {
          result = String::Empty (isolate);
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        auto data = (gchar *) address;
        if (data == NULL)
        {
          result = Null (isolate);
          break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, data, sizeof (guint8));

          const gchar * end;
          if (!g_utf8_validate (data, length, &end))
          {
            _gum_v8_throw_ascii (isolate,
                "can't decode byte 0x%02x in position %u",
                (guint8) *end, (guint) (end - data));
            break;
          }

          result = String::NewFromUtf8 (isolate, data, NewStringType::kNormal,
              length).ToLocalChecked ();
        }
        else
        {
          result = String::Empty (isolate);
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        auto str_utf16 = (gunichar2 *) address;
        if (str_utf16 == NULL)
        {
          result = Null (isolate);
          break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, str_utf16, sizeof (guint8));
        }

        glong size;
        auto str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);
        if (str_utf8 == NULL)
        {
          _gum_v8_throw_ascii_literal (isolate, "invalid string");
          break;
        }

        if (size != 0)
        {
          result = String::NewFromUtf8 (isolate, str_utf8,
              NewStringType::kNormal, size).ToLocalChecked ();
        }
        else
        {
          result = String::Empty (isolate);
        }

        g_free (str_utf8);

        break;
      }
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
#ifdef HAVE_WINDOWS
        auto str_ansi = (gchar *) address;
        if (str_ansi == NULL)
        {
          result = Null (isolate);
          break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          memcpy (&dummy_to_trap_bad_pointer_early, str_ansi, sizeof (guint8));

          auto str_utf8 = gum_ansi_string_to_utf8 (str_ansi, length);
          auto size = g_utf8_offset_to_pointer (str_utf8,
              g_utf8_strlen (str_utf8, -1)) - str_utf8;
          result = String::NewFromUtf8 (isolate, str_utf8,
              NewStringType::kNormal, size).ToLocalChecked ();
          g_free (str_utf8);
        }
        else
        {
          result = String::Empty (isolate);
        }
#else
        _gum_v8_throw_ascii_literal (isolate,
            "ANSI API is only applicable on Windows");
#endif

        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
  }
  else
  {
    if (!result.IsEmpty ())
      return_value.Set (result);
  }
}

GUMJS_DEFINE_FUNCTION (gum_v8_memory_read_volatile)
{
  gpointer address;
  gsize length;
  if (!_gum_v8_args_parse (args, "pz", &address, &length))
    return;

  if (length == 0)
  {
    info.GetReturnValue ().SetNull ();
    return;
  }

  gsize n_bytes_read;
  guint8 * data = gum_memory_read (address, length, &n_bytes_read);
  if (data == NULL)
  {
    _gum_v8_throw_ascii_literal (isolate, "memory read failed");
    return;
  }

  Local<Value> result = ArrayBuffer::New (isolate, n_bytes_read);
  memcpy (result.As<ArrayBuffer> ()->GetBackingStore ()->Data (), data, length);
  info.GetReturnValue ().Set (result);

  g_free (data);
}

static void
gum_v8_memory_write (GumMemoryValueType type,
                     const GumV8Args * args)
{
  gpointer address = NULL;
  gpointer pointer = NULL;
  gssize s = 0;
  gsize u = 0;
  gint64 s64 = 0;
  guint64 u64 = 0;
  gdouble number = 0;
  GBytes * bytes = NULL;
  gchar * str = NULL;
  gsize str_length = 0;
  gunichar2 * str_utf16 = NULL;
#ifdef HAVE_WINDOWS
  gchar * str_ansi = NULL;
#endif
  auto core = args->core;
  auto exceptor = core->exceptor;
  GumExceptorScope scope;

  switch (type)
  {
    case GUM_MEMORY_VALUE_POINTER:
      if (!_gum_v8_args_parse (args, "pp", &address, &pointer))
        return;
      break;
    case GUM_MEMORY_VALUE_S8:
    case GUM_MEMORY_VALUE_S16:
    case GUM_MEMORY_VALUE_S32:
      if (!_gum_v8_args_parse (args, "pz", &address, &s))
        return;
      break;
    case GUM_MEMORY_VALUE_U8:
    case GUM_MEMORY_VALUE_U16:
    case GUM_MEMORY_VALUE_U32:
      if (!_gum_v8_args_parse (args, "pZ", &address, &u))
        return;
      break;
    case GUM_MEMORY_VALUE_S64:
    case GUM_MEMORY_VALUE_LONG:
      if (!_gum_v8_args_parse (args, "pq", &address, &s64))
        return;
      break;
    case GUM_MEMORY_VALUE_U64:
    case GUM_MEMORY_VALUE_ULONG:
      if (!_gum_v8_args_parse (args, "pQ", &address, &u64))
        return;
      break;
    case GUM_MEMORY_VALUE_FLOAT:
    case GUM_MEMORY_VALUE_DOUBLE:
      if (!_gum_v8_args_parse (args, "pn", &address, &number))
        return;
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gum_v8_args_parse (args, "pB", &address, &bytes))
        return;
      break;
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      if (!_gum_v8_args_parse (args, "ps", &address, &str))
        return;

      str_length = g_utf8_strlen (str, -1);
      if (type == GUM_MEMORY_VALUE_UTF16_STRING)
        str_utf16 = g_utf8_to_utf16 (str, -1, NULL, NULL, NULL);
#ifdef HAVE_WINDOWS
      else if (type == GUM_MEMORY_VALUE_ANSI_STRING)
        str_ansi = gum_ansi_string_from_utf8 (str);
#endif
      break;
    default:
      g_assert_not_reached ();
  }

  if (gum_exceptor_try (exceptor, &scope))
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        *((gpointer *) address) = pointer;
        break;
      case GUM_MEMORY_VALUE_S8:
        *((gint8 *) address) = (gint8) s;
        break;
      case GUM_MEMORY_VALUE_U8:
        *((guint8 *) address) = (guint8) u;
        break;
      case GUM_MEMORY_VALUE_S16:
        *((gint16 *) address) = (gint16) s;
        break;
      case GUM_MEMORY_VALUE_U16:
        *((guint16 *) address) = (guint16) u;
        break;
      case GUM_MEMORY_VALUE_S32:
        *((gint32 *) address) = (gint32) s;
        break;
      case GUM_MEMORY_VALUE_U32:
        *((guint32 *) address) = (guint32) u;
        break;
      case GUM_MEMORY_VALUE_S64:
        *((gint64 *) address) = s64;
        break;
      case GUM_MEMORY_VALUE_U64:
        *((guint64 *) address) = u64;
        break;
      case GUM_MEMORY_VALUE_LONG:
        *((glong *) address) = s64;
        break;
      case GUM_MEMORY_VALUE_ULONG:
        *((gulong *) address) = u64;
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        *((gfloat *) address) = number;
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        *((gdouble *) address) = number;
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        gsize size;
        auto data = g_bytes_get_data (bytes, &size);
        memcpy (address, data, size);
        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        gsize size = g_utf8_offset_to_pointer (str, str_length) - str + 1;
        memcpy (address, str, size);
        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        gsize size = (str_length + 1) * sizeof (gunichar2);
        memcpy (address, str_utf16, size);
        break;
      }
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
#ifdef HAVE_WINDOWS
        strcpy ((char *) address, str_ansi);
#else
        _gum_v8_throw_ascii_literal (core->isolate,
            "ANSI API is only applicable on Windows");
#endif
        break;
      }
      default:
        g_assert_not_reached ();
    }
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
  }

  g_bytes_unref (bytes);
  g_free (str);
  g_free (str_utf16);
#ifdef HAVE_WINDOWS
  g_free (str_ansi);
#endif
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

#ifdef HAVE_WINDOWS

static gchar *
gum_ansi_string_to_utf8 (const gchar * str_ansi,
                         gint length)
{
  if (length < 0)
    length = (gint) strlen (str_ansi);

  gint str_utf16_length = MultiByteToWideChar (CP_THREAD_ACP, 0,
      str_ansi, length, NULL, 0);
  gsize str_utf16_size = (str_utf16_length + 1) * sizeof (WCHAR);
  WCHAR * str_utf16 = (WCHAR *) g_malloc (str_utf16_size);

  str_utf16_length = MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, length,
      str_utf16, str_utf16_length);
  str_utf16[str_utf16_length] = L'\0';

  gchar * str_utf8 =
      g_utf16_to_utf8 ((gunichar2 *) str_utf16, -1, NULL, NULL, NULL);

  g_free (str_utf16);

  return str_utf8;
}

static gchar *
gum_ansi_string_from_utf8 (const gchar * str_utf8)
{
  auto str_utf16 = (WCHAR *)
      g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);

  gint str_ansi_size = WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1,
      NULL, 0, NULL, NULL);
  auto str_ansi = (gchar *) g_malloc (str_ansi_size);

  WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1,
      str_ansi, str_ansi_size, NULL, NULL);

  g_free (str_utf16);

  return str_ansi;
}

#endif

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_ansi_string)
{
#ifdef HAVE_WINDOWS
  gchar * str;
  if (!_gum_v8_args_parse (args, "s", &str))
    return;
  auto str_ansi = gum_ansi_string_from_utf8 (str);
  g_free (str);

  auto res = _gum_v8_native_resource_new (str_ansi, strlen (str_ansi), g_free,
      core);
  info.GetReturnValue ().Set (Local<Object>::New (isolate, *res->instance));
#else
  _gum_v8_throw_ascii_literal (isolate,
      "ANSI API is only applicable on Windows");
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf8_string)
{
  gchar * str;
  if (!_gum_v8_args_parse (args, "s", &str))
    return;

  auto res = _gum_v8_native_resource_new (str, strlen (str), g_free, core);
  info.GetReturnValue ().Set (Local<Object>::New (isolate, *res->instance));
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf16_string)
{
  gchar * str;
  if (!_gum_v8_args_parse (args, "s", &str))
    return;
  glong items_written;
  auto str_utf16 = g_utf8_to_utf16 (str, -1, NULL, &items_written, NULL);
  g_free (str);

  gsize size = (items_written + 1) * sizeof (gunichar2);

  GumV8NativeResource * res = _gum_v8_native_resource_new (str_utf16, size,
      g_free, core);
  info.GetReturnValue ().Set (Local<Object>::New (isolate, *res->instance));
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_scan)
{
  gpointer address;
  gsize size;
  GumMatchPattern * pattern;
  Local<Function> on_match, on_error, on_complete;
  if (!_gum_v8_args_parse (args, "pZMF{onMatch,onError,onComplete}", &address,
      &size, &pattern, &on_match, &on_error, &on_complete))
    return;

  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (address);
  range.size = size;

  auto ctx = g_slice_new0 (GumMemoryScanContext);
  ctx->range = range;
  ctx->pattern = pattern;
  ctx->on_match = new Global<Function> (isolate, on_match);
  ctx->on_error = new Global<Function> (isolate, on_error);
  ctx->on_complete = new Global<Function> (isolate, on_complete);
  ctx->core = core;

  _gum_v8_core_pin (core);
  _gum_v8_core_push_job (core, (GumScriptJobFunc) gum_memory_scan_context_run,
      ctx, (GDestroyNotify) gum_memory_scan_context_free);
}

static void
gum_memory_scan_context_free (GumMemoryScanContext * self)
{
  auto core = self->core;

  {
    ScriptScope script_scope (core->script);

    delete self->on_match;
    delete self->on_error;
    delete self->on_complete;

    _gum_v8_core_unpin (core);
  }

  gum_match_pattern_unref (self->pattern);

  g_slice_free (GumMemoryScanContext, self);
}

#ifdef _MSC_VER
# pragma warning (push)
# pragma warning (disable: 4611)
#endif

static void
gum_memory_scan_context_run (GumMemoryScanContext * self)
{
  auto core = self->core;
  auto exceptor = core->exceptor;
  auto isolate = core->isolate;
  GumExceptorScope scope;

  if (gum_exceptor_try (exceptor, &scope))
  {
    gum_memory_scan (&self->range, self->pattern,
        (GumMemoryScanMatchFunc) gum_memory_scan_context_emit_match, self);
  }

  if (gum_exceptor_catch (exceptor, &scope) && self->on_error != nullptr)
  {
    ScriptScope script_scope (core->script);
    auto context = isolate->GetCurrentContext ();

    auto message = gum_exception_details_to_string (&scope.exception);

    auto on_error = Local<Function>::New (isolate, *self->on_error);
    auto recv = Undefined (isolate);
    Local<Value> argv[] = {
      String::NewFromUtf8 (isolate, message).ToLocalChecked ()
    };
    auto result = on_error->Call (context, recv, G_N_ELEMENTS (argv), argv);
    _gum_v8_ignore_result (result);

    g_free (message);
  }

  {
    ScriptScope script_scope (core->script);
    auto context = isolate->GetCurrentContext ();

    auto on_complete (Local<Function>::New (isolate, *self->on_complete));
    auto recv = Undefined (isolate);
    auto result = on_complete->Call (context, recv, 0, nullptr);
    _gum_v8_ignore_result (result);
  }
}

static gboolean
gum_memory_scan_context_emit_match (GumAddress address,
                                    gsize size,
                                    GumMemoryScanContext * self)
{
  ScriptScope scope (self->core->script);
  auto isolate = self->core->isolate;
  auto context = isolate->GetCurrentContext ();

  gboolean proceed = TRUE;

  auto on_match = Local<Function>::New (isolate, *self->on_match);
  auto recv = Undefined (isolate);
  Local<Value> argv[] = {
    _gum_v8_native_pointer_new (GSIZE_TO_POINTER (address), self->core),
    Integer::NewFromUnsigned (isolate, size)
  };
  Local<Value> result;
  if (on_match->Call (context, recv, G_N_ELEMENTS (argv), argv)
      .ToLocal (&result) && result->IsString ())
  {
    String::Utf8Value str (isolate, result);
    proceed = strcmp (*str, "stop") != 0;
  }

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_scan_sync)
{
  if (info.Length () < 3)
  {
    _gum_v8_throw_ascii_literal (isolate, "missing argument");
    return;
  }

  gpointer address;
  gsize size;
  GumMatchPattern * pattern;
  if (!_gum_v8_args_parse (args, "pZM", &address, &size, &pattern))
    return;

  GumMemoryRange range;
  range.base_address = GUM_ADDRESS (address);
  range.size = size;

  GumMemoryScanSyncContext ctx;
  ctx.matches = Array::New (isolate);
  ctx.core = core;

  GumExceptorScope scope;

  if (gum_exceptor_try (core->exceptor, &scope))
  {
    gum_memory_scan (&range, pattern, (GumMemoryScanMatchFunc) gum_append_match,
        &ctx);
  }

  gum_match_pattern_unref (pattern);

  if (gum_exceptor_catch (core->exceptor, &scope))
  {
    _gum_v8_throw_native (&scope.exception, core);
  }
  else
  {
    info.GetReturnValue ().Set (ctx.matches);
  }
}

static gboolean
gum_append_match (GumAddress address,
                  gsize size,
                  GumMemoryScanSyncContext * ctx)
{
  GumV8Core * core = ctx->core;

  auto match = Object::New (core->isolate);
  _gum_v8_object_set_pointer (match, "address", address, core);
  _gum_v8_object_set_uint (match, "size", size, core);
  ctx->matches->Set (core->isolate->GetCurrentContext (),
      ctx->matches->Length (), match).ToChecked ();

  return TRUE;
}

#ifdef _MSC_VER
# pragma warning (pop)
#endif

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_enable)
{
  GArray * ranges;
  Local<Function> on_access;
  if (!_gum_v8_args_parse (args, "RF{onAccess}", &ranges, &on_access))
    return;

  if (ranges->len == 0)
  {
    _gum_v8_throw_ascii_literal (isolate, "expected one or more ranges");
    g_array_free (ranges, TRUE);
    return;
  }

  if (module->monitor != NULL)
  {
    gum_memory_access_monitor_disable (module->monitor);
    g_object_unref (module->monitor);
    module->monitor = NULL;
  }

  module->monitor = gum_memory_access_monitor_new (
      (GumMemoryRange *) ranges->data, ranges->len, GUM_PAGE_RWX, TRUE,
      (GumMemoryAccessNotify) gum_v8_memory_on_access, module, NULL);

  g_array_free (ranges, TRUE);

  delete module->on_access;
  module->on_access = new Global<Function> (isolate, on_access);

  GError * error = NULL;
  gum_memory_access_monitor_enable (module->monitor, &error);
  if (_gum_v8_maybe_throw (isolate, &error))
  {
    delete module->on_access;
    module->on_access = nullptr;

    g_object_unref (module->monitor);
    module->monitor = NULL;
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_disable)
{
  gum_v8_memory_clear_monitor (module);
}

static void
gum_v8_memory_clear_monitor (GumV8Memory * self)
{
  if (self->monitor != NULL)
  {
    gum_memory_access_monitor_disable (self->monitor);
    g_object_unref (self->monitor);
    self->monitor = NULL;
  }

  delete self->on_access;
  self->on_access = nullptr;
}

static void
gum_v8_memory_on_access (GumMemoryAccessMonitor * monitor,
                         const GumMemoryAccessDetails * details,
                         GumV8Memory * self)
{
  auto core = self->core;
  auto isolate = core->isolate;
  ScriptScope script_scope (core->script);

  auto d = Object::New (isolate);
  _gum_v8_object_set_ascii (d, "operation",
      _gum_v8_memory_operation_to_string (details->operation), core);
  _gum_v8_object_set_pointer (d, "from", details->from, core);
  _gum_v8_object_set_pointer (d, "address", details->address, core);

  _gum_v8_object_set_uint (d, "rangeIndex"
"""


```