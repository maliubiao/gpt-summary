Response:
My thought process for analyzing the provided C code snippet and fulfilling the request goes like this:

1. **Understand the Goal:** The request asks for a breakdown of the functionality of `gumquickmemory.c`, its relationship to reverse engineering, low-level details, logical inferences, potential user errors, and debugging hints, focusing on the provided first part of the file.

2. **Initial Code Scan and Keyword Recognition:** I first scanned the code for familiar C constructs and keywords related to memory manipulation and dynamic instrumentation. Keywords like `alloc`, `copy`, `protect`, `patch`, `scan`, `read`, `write`, `string`, and data types like `pointer`, `int`, `float`, `char` immediately stand out. The presence of `JSValue`, `JSContext`, and `GUMJS_DECLARE_FUNCTION` strongly indicate that this code is part of a bridge between C and JavaScript (likely QuickJS, given the `JS` prefix). The `Gum` prefix suggests it's part of the Frida framework.

3. **Identify Core Data Structures:** I noted the key data structures: `GumMemoryPatchContext`, `GumMemoryScanContext`, and `GumMemoryScanSyncContext`. These structures encapsulate the necessary information for performing patch and scan operations, both asynchronous and synchronous. The `GumMemoryValueType` enum defines the supported data types for memory access.

4. **Analyze Function Declarations (GUMJS_DECLARE_FUNCTION):** The numerous `GUMJS_DECLARE_FUNCTION` macros indicate a set of exported functions callable from the JavaScript side. I grouped these functions by their apparent purpose:
    * **Allocation:** `gumjs_memory_alloc`, `gumjs_memory_alloc_ansi_string`, etc.
    * **Manipulation:** `gumjs_memory_copy`, `gumjs_memory_protect`, `gumjs_memory_patch_code`.
    * **Reading/Writing:** `gumjs_memory_read_*`, `gumjs_memory_write_*`, `gum_quick_memory_read_volatile`. The different suffixes for read/write functions (e.g., `Pointer`, `S8`, `Utf8String`) clearly indicate type-specific memory access.
    * **Scanning:** `gumjs_memory_scan`, `gumjs_memory_scan_sync`.
    * **Access Monitoring:** `gumjs_memory_access_monitor_enable`, `gumjs_memory_access_monitor_disable`.

5. **Examine Function Implementations (GUMJS_DEFINE_FUNCTION):**  I then briefly looked at the implementations of some key functions to understand their logic:
    * **`gumjs_memory_alloc`:**  Demonstrates allocation with options for near-address allocation and page-aligned allocation.
    * **`gumjs_memory_copy`:** A straightforward `memmove`.
    * **`gumjs_memory_protect`:** Uses `gum_try_mprotect` for memory protection changes.
    * **`gumjs_memory_patch_code`:** Shows a mechanism for applying code patches via a callback.
    * **`gum_quick_memory_read` and `gum_quick_memory_write`:**  These functions have switch statements based on `GumMemoryValueType`, highlighting the type-aware nature of memory access.
    * **`gumjs_memory_scan` and `gumjs_memory_scan_sync`:** Illustrate asynchronous and synchronous memory scanning using `gum_memory_scan`.

6. **Connect to Reverse Engineering Concepts:**  With an understanding of the functions, I mapped them to common reverse engineering tasks:
    * **Memory Inspection:**  Reading different data types (`readPointer`, `readU32`, `readUtf8String`).
    * **Code Patching:**  Modifying program behavior (`patchCode`).
    * **Memory Searching:** Finding specific byte patterns or values (`scan`, `scanSync`).
    * **Memory Protection Analysis:**  Checking memory permissions (`queryProtection`).
    * **Dynamic Analysis:** Monitoring memory accesses (`memory_access_monitor_enable`).

7. **Identify Low-Level Details:** The code exposes several low-level aspects:
    * **Direct Memory Access:**  Functions operate on raw memory addresses (`gpointer`).
    * **Memory Protection:**  Interaction with OS memory protection mechanisms (`gum_try_mprotect`).
    * **Page Alignment:** The `gum_query_page_size()` and checks for page alignment in `gumjs_memory_alloc`.
    * **Endianness (Implicit):** While not explicitly handled, the type-specific read/write operations are sensitive to endianness.
    * **String Encodings:** Handling of ANSI, UTF-8, and UTF-16 strings, especially on Windows.

8. **Infer Logical Inferences (Assumptions and Outputs):** I considered the inputs and outputs of some functions:
    * **`read*` functions:** Input: memory address; Output: JavaScript representation of the value at that address.
    * **`write*` functions:** Input: memory address, value; Output: `undefined` (on success).
    * **`scan`:** Input: memory range, pattern; Output: Asynchronous callbacks for matches.
    * **`scanSync`:** Input: memory range, pattern; Output: JavaScript array of matches.

9. **Consider User Errors:** Based on the function parameters and error handling, I thought about common mistakes:
    * **Incorrect address:**  Leading to crashes or exceptions.
    * **Invalid size:**  For allocation, copy, or protection changes.
    * **Type mismatch:** Trying to read or write data with the wrong type.
    * **Incorrect string encoding:**  Especially with ANSI strings on Windows.
    * **Not handling asynchronous results of `scan` correctly.**

10. **Trace User Operations (Debugging Hints):** I considered how a user might arrive at this code:
    * **Frida scripts:**  Users write JavaScript code that utilizes the `Memory` object exposed by this module.
    * **Frida API calls:** The JavaScript functions map directly to the C functions in this file.
    * **Error messages:**  Exceptions thrown from C functions are propagated back to the JavaScript side, providing debugging clues.

11. **Synthesize the Summary:** Finally, I combined all the observations into a concise summary of the file's functionality, focusing on memory manipulation primitives for dynamic instrumentation. I highlighted its role as a bridge between JavaScript and low-level memory operations within the Frida framework.

By following this methodical approach, I could dissect the C code, understand its purpose within the Frida ecosystem, and address all aspects of the prompt. The key was to identify the core functionalities, connect them to relevant concepts, and then elaborate on the details.
好的，让我们来分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumquickmemory.c` 文件的功能。

**功能归纳:**

这个 C 文件 `gumquickmemory.c` 是 Frida 动态 instrumentation 工具中 `frida-gum` 组件的一部分，它主要负责在 JavaScript 环境中提供对目标进程内存进行快速操作的功能。  它充当了一个桥梁，允许 JavaScript 代码调用底层的 C 代码来执行内存的分配、释放、读写、保护属性修改、代码注入、以及扫描等操作。

**详细功能列表:**

1. **内存分配与释放:**
   - `gumjs_memory_alloc`:  允许在目标进程中分配内存，可以指定分配大小，以及尝试在特定地址附近分配。
   - `gumjs_memory_alloc_ansi_string`, `gumjs_memory_alloc_utf8_string`, `gumjs_memory_alloc_utf16_string`:  专门用于分配存储不同编码格式字符串的内存。

2. **内存读写:**
   - 提供了一系列以数据类型区分的内存读写函数，例如：
     - `gumjs_memory_read_Pointer`, `gumjs_memory_write_Pointer`: 读写指针类型。
     - `gumjs_memory_read_S8`, `gumjs_memory_write_S8`: 读写有符号 8 位整数。
     - `gumjs_memory_read_U32`, `gumjs_memory_write_U32`: 读写无符号 32 位整数。
     - `gumjs_memory_read_Float`, `gumjs_memory_write_Float`: 读写浮点数。
     - `gumjs_memory_read_Double`, `gumjs_memory_write_Double`: 读写双精度浮点数。
     - `gumjs_memory_read_ByteArray`, `gumjs_memory_write_ByteArray`: 读写字节数组。
     - `gumjs_memory_read_CString`, `gumjs_memory_write_CString`: 读写 C 风格字符串。
     - `gumjs_memory_read_Utf8String`, `gumjs_memory_write_Utf8String`: 读写 UTF-8 字符串。
     - `gumjs_memory_read_Utf16String`, `gumjs_memory_write_Utf16String`: 读写 UTF-16 字符串。
     - `gumjs_memory_read_AnsiString`, `gumjs_memory_write_AnsiString`: 读写 ANSI 字符串 (主要用于 Windows)。
   - `gum_quick_memory_read_volatile`:  执行易失性读取，通常用于读取可能被其他线程或硬件修改的内存。
   - `gumjs_memory_copy`:  将一块内存区域的内容复制到另一块内存区域。

3. **内存保护属性修改:**
   - `gumjs_memory_protect`:  修改目标进程中内存页的保护属性（例如，设置为可读、可写、可执行）。
   - `gumjs_memory_query_protection`:  查询指定内存地址的保护属性。

4. **代码 Patching (修改):**
   - `gumjs_memory_patch_code`:  允许修改目标进程中的代码，通常用于 hook 函数或者修改程序行为。它使用回调函数 `gum_memory_patch_context_apply` 在 JavaScript 上下文中执行具体的修改逻辑。
   - `gumjs_memory_check_code_pointer`:  检查一个指针是否指向可执行代码。

5. **内存扫描:**
   - `gumjs_memory_scan`:  在指定的内存范围内异步搜索匹配特定模式的字节序列。它允许指定匹配成功、出错和完成时的回调函数。
   - `gumjs_memory_scan_sync`:  在指定的内存范围内同步搜索匹配特定模式的字节序列，并返回所有匹配结果。

6. **内存访问监控:**
   - `gumjs_memory_access_monitor_enable`:  启用对特定内存区域的访问监控，当指定区域被读写时，会触发 JavaScript 回调函数。
   - `gumjs_memory_access_monitor_disable`:  禁用内存访问监控。

**与逆向方法的关联及举例说明:**

这个文件提供的功能是动态逆向分析的核心工具。通过这些功能，逆向工程师可以在程序运行时检查和修改其行为。

* **内存检查:**
    * **例子:** 使用 `Memory.readU32(address)` 可以读取目标进程指定地址的 32 位整数值，这可以用来查看变量的值或者数据结构的内容。
    * **例子:** 使用 `Memory.readUtf8String(address)` 可以读取目标进程中 C 风格的字符串，这对于分析程序中的文本信息非常有用。

* **代码 Hooking (通过代码 Patching):**
    * **例子:** 可以使用 `Memory.patchCode(address, size, callback)` 将目标函数开头的几条指令替换为跳转到自定义函数的指令，从而拦截对该函数的调用。`callback` 函数会接收到指向需要修改内存的指针，可以在其中写入新的指令字节码。

* **内存搜索:**
    * **例子:** 使用 `Memory.scan(address, size, pattern, { onMatch: function(address, size) { ... } })` 可以搜索指定内存区域中是否存在特定的字节序列，例如查找特定的 magic number 或者指令序列。

* **动态修改程序行为:**
    * **例子:**  可以使用 `Memory.writeU32(address, newValue)` 修改目标进程中变量的值，从而改变程序的执行逻辑。例如，跳过某些条件判断。

* **监控内存访问:**
    * **例子:** 使用 `MemoryAccessMonitor.enable([{ base: address, size: size }], { onAccess: function(details) { console.log(details); } })` 可以监控特定内存区域的读写操作，这可以帮助理解程序如何访问和修改数据。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

这个文件虽然是用 C 编写，并且暴露给 JavaScript 使用，但其底层操作直接涉及操作系统的内存管理机制和二进制数据的表示。

* **二进制底层:**
    * **数据类型:**  代码中定义了 `GumMemoryValueType` 枚举，明确区分了各种基本数据类型（如 `S8`, `U32`, `FLOAT` 等），这对应于内存中不同大小和格式的二进制表示。读写操作需要根据这些类型进行。
    * **字节序 (Endianness):** 虽然代码本身没有显式处理字节序，但通过 `readU32` 和 `readS32` 读取到的值会受到目标进程运行平台的字节序影响。逆向工程师需要了解目标平台的字节序才能正确解析数据。
    * **指针:**  `GUM_MEMORY_VALUE_POINTER` 类型直接操作内存地址，理解指针的概念是进行内存操作的基础。

* **Linux/Android 内核:**
    * **内存页 (Memory Pages):**  `gumjs_memory_alloc` 中提到的 `page_size` 以及 `gum_alloc_n_pages` 和 `gum_try_alloc_n_pages_near` 等函数，都与操作系统以页为单位管理内存有关。内存保护属性的修改也是以页为单位进行的。
    * **`mprotect` 系统调用:** `gum_try_mprotect` 函数是对 Linux 系统调用 `mprotect` 的封装，用于修改内存页的保护属性。这在动态修改代码执行权限时非常重要。
    * **地址空间布局:**  理解目标进程的地址空间布局（例如，代码段、数据段、堆、栈的位置）对于定位需要操作的内存地址至关重要。

* **框架知识 (Frida Gum):**
    * **`GumQuickCore`:** 这个结构体代表 Frida Gum 核心，负责管理脚本的执行上下文和与目标进程的交互。
    * **`GumMemoryRange` 和 `GumMatchPattern`:** 用于内存扫描功能，`GumMemoryRange` 定义了扫描的范围，`GumMatchPattern` 定义了要搜索的字节模式。
    * **`GumMemoryAccessMonitor`:**  Frida Gum 提供的用于监控内存访问的组件。

**逻辑推理、假设输入与输出:**

* **`gumjs_memory_alloc(size, near)`:**
    * **假设输入:** `size = 1024`, `near = null`
    * **逻辑推理:**  分配 1024 字节的内存。由于 `near` 为空，系统会在合适的地址分配。
    * **输出:**  返回一个表示分配的内存地址的 JavaScript 对象 (可以转换为 `NativePointer`)。

* **`gumjs_memory_read_U32(address)`:**
    * **假设输入:** `address = 0x70000000` (假设这是一个有效的内存地址，并且包含一个 32 位无符号整数)
    * **逻辑推理:** 读取地址 `0x70000000` 处的 4 个字节，并将其解释为一个无符号 32 位整数。
    * **输出:** 返回一个 JavaScript Number，表示读取到的整数值。

* **`gumjs_memory_patch_code(address, size, callback)`:**
    * **假设输入:** `address = 0x401000` (假设这是一个函数入口地址), `size = 5` (假设要修改 5 个字节), `callback` 是一个将前 5 个字节替换为 `0xCC` (int3) 的 JavaScript函数。
    * **逻辑推理:**  调用 `callback` 函数，并将指向地址 `0x401000` 的指针传递给它。`callback` 函数会将该地址开始的 5 个字节修改为 `0xCC`，从而在执行到该指令时触发断点。
    * **输出:** `undefined` (表示操作成功)。

**用户或编程常见的使用错误及举例说明:**

1. **无效的内存地址:**
   * **错误:** 尝试读取或写入未分配或无权访问的内存地址。
   * **例子:** `Memory.readU32(0x1)` (非常低的地址通常是受保护的)。
   * **结果:**  通常会导致程序崩溃或 Frida 抛出异常。

2. **错误的数据类型:**
   * **错误:** 使用错误的读写函数来操作内存。
   * **例子:**  尝试使用 `Memory.readUtf8String(address)` 读取一个实际上是整数值的内存位置。
   * **结果:**  可能读取到乱码或者导致程序逻辑错误。

3. **越界访问:**
   * **错误:** 在读写字节数组时，指定的长度超过了实际可访问的范围。
   * **例子:**  如果一个缓冲区实际大小为 100 字节，但尝试使用 `Memory.readByteArray(address, 200)` 读取 200 字节。
   * **结果:** 可能导致读取到不相关的数据或者程序崩溃。

4. **在代码 Patching 中引入错误:**
   * **错误:** 修改代码时，写入了错误的指令字节码，导致程序执行出错或崩溃。
   * **例子:**  修改函数入口时，没有正确计算跳转指令的目标地址。
   * **结果:**  目标程序行为异常或崩溃。

5. **异步 `scan` 的使用不当:**
   * **错误:**  期望 `Memory.scan` 立即返回结果，而没有处理 `onMatch` 回调。
   * **结果:**  可能无法获取到扫描结果。

**用户操作是如何一步步的到达这里，作为调试线索:**

1. **编写 Frida 脚本:**  用户首先会编写一个 Frida 脚本 (通常是 JavaScript 代码)。
2. **使用 `Memory` API:**  在脚本中，用户会使用 `Frida.Memory` 对象提供的 API，例如 `Memory.readU32()`, `Memory.patchCode()`, `Memory.scan()` 等。
3. **Frida Gum 的介入:** 当 JavaScript 代码调用 `Memory` 的这些方法时，Frida 的 JavaScript 绑定会将这些调用转发到 `gumjs` 模块中相应的 C 函数。
4. **`gumquickmemory.c` 的执行:**  例如，当调用 `Memory.readU32(address)` 时，最终会调用到 `gumjs_memory_read_U32` 函数。这个函数会解析 JavaScript 传入的参数 (`address`)，并调用底层的 Frida Gum API (例如 `gum_memory_read`) 来执行实际的内存读取操作。
5. **底层 Gum API 和操作系统交互:** Frida Gum 的底层 API 会与目标进程的地址空间进行交互，并可能涉及到操作系统内核的调用 (例如 `mprotect`)。
6. **结果返回:**  读取到的数据或操作的结果会通过 `gumjs` 模块的 C 函数返回给 JavaScript 环境。

**调试线索:**

* **查看 Frida 的控制台输出:**  Frida 通常会将错误信息和异常输出到控制台。
* **使用 `console.log()` 在 Frida 脚本中打印信息:**  可以打印变量的值，查看函数调用的参数等。
* **检查目标进程的状态:**  如果目标进程崩溃，可以尝试分析崩溃日志或使用调试器附加到目标进程。
* **逐步调试 Frida 脚本:**  虽然 Frida 本身不提供直接的脚本调试器，但可以通过添加大量的 `console.log()` 语句来追踪脚本的执行流程和变量的值。
* **查看 Frida Gum 的日志 (如果启用):**  Frida Gum 可以配置输出详细的日志信息，有助于理解底层的内存操作是否成功。

希望以上分析能够帮助你理解 `gumquickmemory.c` 文件的功能和它在 Frida 中的作用。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickmemory.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
 * Copyright (C) 2020 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2021 Abdelrahman Eid <hot3eed@gmail.com>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickmemory.h"

#include "gumquickmacros.h"

#include <string.h>
#ifdef HAVE_WINDOWS
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
#endif

typedef guint GumMemoryValueType;
typedef struct _GumMemoryPatchContext GumMemoryPatchContext;
typedef struct _GumMemoryScanContext GumMemoryScanContext;
typedef struct _GumMemoryScanSyncContext GumMemoryScanSyncContext;

enum _GumMemoryValueType
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

struct _GumMemoryPatchContext
{
  JSValue apply;

  JSContext * ctx;
  GumQuickCore * core;
};

struct _GumMemoryScanContext
{
  GumMemoryRange range;
  GumMatchPattern * pattern;
  JSValue on_match;
  JSValue on_error;
  JSValue on_complete;
  GumQuickMatchResult result;

  JSContext * ctx;
  GumQuickCore * core;
};

struct _GumMemoryScanSyncContext
{
  JSValue matches;
  uint32_t index;

  JSContext * ctx;
  GumQuickCore * core;
};

GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc)
GUMJS_DECLARE_FUNCTION (gumjs_memory_copy)
GUMJS_DECLARE_FUNCTION (gumjs_memory_protect)
GUMJS_DECLARE_FUNCTION (gumjs_memory_query_protection)
GUMJS_DECLARE_FUNCTION (gumjs_memory_patch_code)
static void gum_memory_patch_context_apply (gpointer mem,
    GumMemoryPatchContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_memory_check_code_pointer)

static JSValue gum_quick_memory_read (JSContext * ctx, GumMemoryValueType type,
    GumQuickArgs * args, GumQuickCore * core);
static JSValue gum_quick_memory_write (JSContext * ctx, GumMemoryValueType type,
    GumQuickArgs * args, GumQuickCore * core);
GUMJS_DECLARE_FUNCTION (gum_quick_memory_read_volatile)

static void gum_quick_memory_on_access (GumMemoryAccessMonitor * monitor,
    const GumMemoryAccessDetails * details, GumQuickMemory * self);

#ifdef HAVE_WINDOWS
static gchar * gum_ansi_string_to_utf8 (const gchar * str_ansi, gint length);
static gchar * gum_ansi_string_from_utf8 (const gchar * str_utf8);
#endif

#define GUMJS_DEFINE_MEMORY_READ(T) \
    GUMJS_DEFINE_FUNCTION (gumjs_memory_read_##T) \
    { \
      return gum_quick_memory_read (ctx, GUM_MEMORY_VALUE_##T, args, core); \
    }
#define GUMJS_DEFINE_MEMORY_WRITE(T) \
    GUMJS_DEFINE_FUNCTION (gumjs_memory_write_##T) \
    { \
      return gum_quick_memory_write (ctx, GUM_MEMORY_VALUE_##T, args, core); \
    }
#define GUMJS_DEFINE_MEMORY_READ_WRITE(T) \
    GUMJS_DEFINE_MEMORY_READ (T); \
    GUMJS_DEFINE_MEMORY_WRITE (T)

#define GUMJS_EXPORT_MEMORY_READ(N, T) \
    JS_CFUNC_DEF ("read" N, 0, gumjs_memory_read_##T)
#define GUMJS_EXPORT_MEMORY_WRITE(N, T) \
    JS_CFUNC_DEF ("write" N, 0, gumjs_memory_write_##T)
#define GUMJS_EXPORT_MEMORY_READ_WRITE(N, T) \
    GUMJS_EXPORT_MEMORY_READ (N, T), \
    GUMJS_EXPORT_MEMORY_WRITE (N, T)

GUMJS_DEFINE_MEMORY_READ_WRITE (POINTER)
GUMJS_DEFINE_MEMORY_READ_WRITE (S8)
GUMJS_DEFINE_MEMORY_READ_WRITE (U8)
GUMJS_DEFINE_MEMORY_READ_WRITE (S16)
GUMJS_DEFINE_MEMORY_READ_WRITE (U16)
GUMJS_DEFINE_MEMORY_READ_WRITE (S32)
GUMJS_DEFINE_MEMORY_READ_WRITE (U32)
GUMJS_DEFINE_MEMORY_READ_WRITE (S64)
GUMJS_DEFINE_MEMORY_READ_WRITE (U64)
GUMJS_DEFINE_MEMORY_READ_WRITE (LONG)
GUMJS_DEFINE_MEMORY_READ_WRITE (ULONG)
GUMJS_DEFINE_MEMORY_READ_WRITE (FLOAT)
GUMJS_DEFINE_MEMORY_READ_WRITE (DOUBLE)
GUMJS_DEFINE_MEMORY_READ_WRITE (BYTE_ARRAY)
GUMJS_DEFINE_MEMORY_READ (C_STRING)
GUMJS_DEFINE_MEMORY_READ_WRITE (UTF8_STRING)
GUMJS_DEFINE_MEMORY_READ_WRITE (UTF16_STRING)
GUMJS_DEFINE_MEMORY_READ_WRITE (ANSI_STRING)

GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc_ansi_string)
GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc_utf8_string)
GUMJS_DECLARE_FUNCTION (gumjs_memory_alloc_utf16_string)

GUMJS_DECLARE_FUNCTION (gumjs_memory_scan)
static void gum_memory_scan_context_free (GumMemoryScanContext * ctx);
static void gum_memory_scan_context_run (GumMemoryScanContext * self);
static gboolean gum_memory_scan_context_emit_match (GumAddress address,
    gsize size, GumMemoryScanContext * self);
GUMJS_DECLARE_FUNCTION (gumjs_memory_scan_sync)
static gboolean gum_append_match (GumAddress address, gsize size,
    GumMemoryScanSyncContext * sc);

GUMJS_DECLARE_FUNCTION (gumjs_memory_access_monitor_enable)
GUMJS_DECLARE_FUNCTION (gumjs_memory_access_monitor_disable)
static void gum_quick_memory_clear_monitor (GumQuickMemory * self,
    JSContext * ctx);

GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_operation)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_from)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_address)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_range_index)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_page_index)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_pages_completed)
GUMJS_DECLARE_GETTER (gumjs_memory_access_details_get_pages_total)

static const JSCFunctionListEntry gumjs_memory_entries[] =
{
  JS_CFUNC_DEF ("_alloc", 0, gumjs_memory_alloc),
  JS_CFUNC_DEF ("copy", 0, gumjs_memory_copy),
  JS_CFUNC_DEF ("protect", 0, gumjs_memory_protect),
  JS_CFUNC_DEF ("queryProtection", 0, gumjs_memory_query_protection),
  JS_CFUNC_DEF ("_patchCode", 0, gumjs_memory_patch_code),
  JS_CFUNC_DEF ("_checkCodePointer", 0, gumjs_memory_check_code_pointer),

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
  JS_CFUNC_DEF ("readVolatile", 0, gum_quick_memory_read_volatile),

  JS_CFUNC_DEF ("allocAnsiString", 0, gumjs_memory_alloc_ansi_string),
  JS_CFUNC_DEF ("allocUtf8String", 0, gumjs_memory_alloc_utf8_string),
  JS_CFUNC_DEF ("allocUtf16String", 0, gumjs_memory_alloc_utf16_string),

  JS_CFUNC_DEF ("_scan", 0, gumjs_memory_scan),
  JS_CFUNC_DEF ("scanSync", 0, gumjs_memory_scan_sync),
};

static const JSCFunctionListEntry gumjs_memory_access_monitor_entries[] =
{
  JS_CFUNC_DEF ("enable", 0, gumjs_memory_access_monitor_enable),
  JS_CFUNC_DEF ("disable", 0, gumjs_memory_access_monitor_disable),
};

static const JSClassDef gumjs_memory_access_details_def =
{
  .class_name = "MemoryAccessDetails",
};

static const JSCFunctionListEntry gumjs_memory_access_details_entries[] =
{
  JS_CGETSET_DEF ("operation", gumjs_memory_access_details_get_operation, NULL),
  JS_CGETSET_DEF ("from", gumjs_memory_access_details_get_from, NULL),
  JS_CGETSET_DEF ("address", gumjs_memory_access_details_get_address, NULL),
  JS_CGETSET_DEF ("rangeIndex", gumjs_memory_access_details_get_range_index,
      NULL),
  JS_CGETSET_DEF ("pageIndex", gumjs_memory_access_details_get_page_index,
      NULL),
  JS_CGETSET_DEF ("pagesCompleted",
      gumjs_memory_access_details_get_pages_completed, NULL),
  JS_CGETSET_DEF ("pagesTotal", gumjs_memory_access_details_get_pages_total,
      NULL),
};

void
_gum_quick_memory_init (GumQuickMemory * self,
                        JSValue ns,
                        GumQuickCore * core)
{
  JSContext * ctx = core->ctx;
  JSValue obj, proto;

  self->core = core;
  self->monitor = NULL;
  self->on_access = JS_NULL;

  _gum_quick_core_store_module_data (core, "memory", self);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_memory_entries,
      G_N_ELEMENTS (gumjs_memory_entries));
  JS_DefinePropertyValueStr (ctx, ns, "Memory", obj, JS_PROP_C_W_E);

  obj = JS_NewObject (ctx);
  JS_SetPropertyFunctionList (ctx, obj, gumjs_memory_access_monitor_entries,
      G_N_ELEMENTS (gumjs_memory_access_monitor_entries));
  JS_DefinePropertyValueStr (ctx, ns, "MemoryAccessMonitor", obj,
      JS_PROP_C_W_E);

  _gum_quick_create_class (ctx, &gumjs_memory_access_details_def, core,
      &self->memory_access_details_class, &proto);
  JS_SetPropertyFunctionList (ctx, proto, gumjs_memory_access_details_entries,
      G_N_ELEMENTS (gumjs_memory_access_details_entries));
}

void
_gum_quick_memory_dispose (GumQuickMemory * self)
{
  gum_quick_memory_clear_monitor (self, self->core->ctx);
}

void
_gum_quick_memory_finalize (GumQuickMemory * self)
{
}

static GumQuickMemory *
gumjs_get_parent_module (GumQuickCore * core)
{
  return _gum_quick_core_load_module_data (core, "memory");
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc)
{
  gsize size, page_size;
  GumAddressSpec spec;

  if (!_gum_quick_args_parse (args, "ZpZ", &size, &spec.near_address,
      &spec.max_distance))
    return JS_EXCEPTION;

  if (size == 0 || size > 0x7fffffff)
    return _gum_quick_throw_literal (ctx, "invalid size");

  page_size = gum_query_page_size ();

  if (spec.near_address != NULL)
  {
    gpointer result;

    if ((size % page_size) != 0)
    {
      return _gum_quick_throw_literal (ctx,
          "size must be a multiple of page size");
    }

    result = gum_try_alloc_n_pages_near (size / page_size, GUM_PAGE_RW, &spec);
    if (result == NULL)
    {
      return _gum_quick_throw_literal (ctx,
          "unable to allocate free page(s) near address");
    }

    return _gum_quick_native_resource_new (ctx, result, gum_free_pages, core);
  }
  else
  {
    if ((size % page_size) != 0)
    {
      return _gum_quick_native_resource_new (ctx, g_malloc0 (size), g_free,
          core);
    }
    else
    {
      return _gum_quick_native_resource_new (ctx,
          gum_alloc_n_pages (size / page_size, GUM_PAGE_RW), gum_free_pages,
          core);
    }
  }
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_copy)
{
  GumExceptor * exceptor = core->exceptor;
  gpointer destination, source;
  gsize size;
  GumExceptorScope scope;

  if (!_gum_quick_args_parse (args, "ppZ", &destination, &source, &size))
    return JS_EXCEPTION;

  if (size == 0)
    return JS_UNDEFINED;
  else if (size > 0x7fffffff)
    return _gum_quick_throw_literal (ctx, "invalid size");

  if (gum_exceptor_try (exceptor, &scope))
  {
    memmove (destination, source, size);
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    return _gum_quick_throw_native (ctx, &scope.exception, core);
  }

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_protect)
{
  gpointer address;
  gsize size;
  GumPageProtection prot;
  gboolean success;

  if (!_gum_quick_args_parse (args, "pZm", &address, &size, &prot))
    return JS_EXCEPTION;

  if (size > 0x7fffffff)
    return _gum_quick_throw_literal (ctx, "invalid size");

  if (size != 0)
    success = gum_try_mprotect (address, size, prot);
  else
    success = TRUE;

  return JS_NewBool (ctx, success);
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_query_protection)
{
  gpointer address;
  GumPageProtection prot;

  if (!_gum_quick_args_parse (args, "p", &address))
    goto propagate_exception;

  if (!gum_memory_query_protection (address, &prot))
    goto query_failed;

  return _gum_quick_page_protection_new (ctx, prot);

query_failed:
  _gum_quick_throw_literal (ctx, "failed to query address");

propagate_exception:
  return JS_EXCEPTION;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_patch_code)
{
  gpointer address;
  gsize size;
  GumMemoryPatchContext pc;
  gboolean success;

  if (!_gum_quick_args_parse (args, "pZF", &address, &size, &pc.apply))
    return JS_EXCEPTION;
  pc.ctx = ctx;
  pc.core = core;

  success = gum_memory_patch_code (address, size,
      (GumMemoryPatchApplyFunc) gum_memory_patch_context_apply, &pc);
  if (!success)
    return _gum_quick_throw_literal (ctx, "invalid address");

  return JS_UNDEFINED;
}

static void
gum_memory_patch_context_apply (gpointer mem,
                                GumMemoryPatchContext * self)
{
  JSContext * ctx = self->ctx;
  GumQuickCore * core = self->core;
  JSValue mem_val;

  mem_val = _gum_quick_native_pointer_new (ctx, mem, core);

  _gum_quick_scope_call_void (self->core->current_scope, self->apply,
      JS_UNDEFINED, 1, &mem_val);

  JS_FreeValue (ctx, mem_val);
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_check_code_pointer)
{
  JSValue result = JS_NULL;
  const guint8 * ptr;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope scope;

  if (!_gum_quick_args_parse (args, "p", &ptr))
    return JS_EXCEPTION;

  ptr = gum_strip_code_pointer ((gpointer) ptr);

#ifdef HAVE_ARM
  ptr = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (ptr) & ~1);
#endif

  gum_ensure_code_readable (ptr, 1);

  if (gum_exceptor_try (exceptor, &scope))
  {
    result = JS_NewUint32 (ctx, *ptr);
  }

  if (gum_exceptor_catch (exceptor, &scope))
  {
    return _gum_quick_throw_native (ctx, &scope.exception, core);
  }

  return result;
}

static JSValue
gum_quick_memory_read (JSContext * ctx,
                       GumMemoryValueType type,
                       GumQuickArgs * args,
                       GumQuickCore * core)
{
  JSValue result = JS_NULL;
  GumExceptor * exceptor = core->exceptor;
  gpointer address;
  gssize length = -1;
  GumExceptorScope scope;

  switch (type)
  {
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gum_quick_args_parse (args, "pZ", &address, &length))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_C_STRING:
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      if (!_gum_quick_args_parse (args, "p|z", &address, &length))
        return JS_EXCEPTION;
      break;
    default:
      if (!_gum_quick_args_parse (args, "p", &address))
        return JS_EXCEPTION;
      break;
  }

  if (gum_exceptor_try (exceptor, &scope))
  {
    switch (type)
    {
      case GUM_MEMORY_VALUE_POINTER:
        result =
            _gum_quick_native_pointer_new (ctx, *((gpointer *) address), core);
        break;
      case GUM_MEMORY_VALUE_S8:
        result = JS_NewInt32 (ctx, *((gint8 *) address));
        break;
      case GUM_MEMORY_VALUE_U8:
        result = JS_NewUint32 (ctx, *((guint8 *) address));
        break;
      case GUM_MEMORY_VALUE_S16:
        result = JS_NewInt32 (ctx, *((gint16 *) address));
        break;
      case GUM_MEMORY_VALUE_U16:
        result = JS_NewUint32 (ctx, *((guint16 *) address));
        break;
      case GUM_MEMORY_VALUE_S32:
        result = JS_NewInt32 (ctx, *((gint32 *) address));
        break;
      case GUM_MEMORY_VALUE_U32:
        result = JS_NewUint32 (ctx, *((guint32 *) address));
        break;
      case GUM_MEMORY_VALUE_S64:
        result = _gum_quick_int64_new (ctx, *((gint64 *) address), core);
        break;
      case GUM_MEMORY_VALUE_U64:
        result = _gum_quick_uint64_new (ctx, *((guint64 *) address), core);
        break;
      case GUM_MEMORY_VALUE_LONG:
        result = _gum_quick_int64_new (ctx, *((glong *) address), core);
        break;
      case GUM_MEMORY_VALUE_ULONG:
        result = _gum_quick_uint64_new (ctx, *((gulong *) address), core);
        break;
      case GUM_MEMORY_VALUE_FLOAT:
        result = JS_NewFloat64 (ctx, *((gfloat *) address));
        break;
      case GUM_MEMORY_VALUE_DOUBLE:
        result = JS_NewFloat64 (ctx, *((gdouble *) address));
        break;
      case GUM_MEMORY_VALUE_BYTE_ARRAY:
      {
        const guint8 * data = address;
        gpointer buffer_data;

        if (data == NULL)
        {
          result = JS_NULL;
          break;
        }

        buffer_data = g_malloc (length);
        result = JS_NewArrayBuffer (ctx, buffer_data, length,
            _gum_quick_array_buffer_free, buffer_data, FALSE);

        memcpy (buffer_data, data, length);

        break;
      }
      case GUM_MEMORY_VALUE_C_STRING:
      {
        const gchar * data = address;
        guint8 dummy_to_trap_bad_pointer_early;
        gchar * str;

        if (data == NULL)
        {
          result = JS_NULL;
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, data, sizeof (guint8));

        str = g_utf8_make_valid (data, length);
        result = JS_NewString (ctx, str);
        g_free (str);

        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        const gchar * data = address;
        guint8 dummy_to_trap_bad_pointer_early;
        const gchar * end;

        if (data == NULL)
        {
          result = JS_NULL;
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, data, sizeof (guint8));

        if (g_utf8_validate (data, length, &end))
        {
          result = JS_NewStringLen (ctx, data, end - data);
        }
        else
        {
          result = _gum_quick_throw (ctx,
              "can't decode byte 0x%02x in position %u",
              (guint8) *end, (guint) (end - data));
        }

        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        const gunichar2 * str_utf16 = address;
        gchar * str_utf8;
        guint8 dummy_to_trap_bad_pointer_early;
        glong size;

        if (str_utf16 == NULL)
        {
          result = JS_NULL;
          break;
        }

        if (length != 0)
          memcpy (&dummy_to_trap_bad_pointer_early, str_utf16, sizeof (guint8));

        str_utf8 = g_utf16_to_utf8 (str_utf16, length, NULL, &size, NULL);

        if (str_utf8 != NULL)
          result = JS_NewString (ctx, str_utf8);
        else
          result = _gum_quick_throw_literal (ctx, "invalid string");

        g_free (str_utf8);

        break;
      }
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
#ifdef HAVE_WINDOWS
        const gchar * str_ansi = address;

        if (str_ansi == NULL)
        {
          result = JS_NULL;
          break;
        }

        if (length != 0)
        {
          guint8 dummy_to_trap_bad_pointer_early;
          gchar * str_utf8;

          memcpy (&dummy_to_trap_bad_pointer_early, str_ansi, sizeof (guint8));

          str_utf8 = gum_ansi_string_to_utf8 (str_ansi, length);
          result = JS_NewString (ctx, str_utf8);
          g_free (str_utf8);
        }
        else
        {
          result = JS_NewString (ctx, "");
        }
#else
        result = _gum_quick_throw_literal (ctx,
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
    JS_FreeValue (ctx, result);
    result = _gum_quick_throw_native (ctx, &scope.exception, core);
  }

  return result;
}

static JSValue
gum_quick_memory_write (JSContext * ctx,
                        GumMemoryValueType type,
                        GumQuickArgs * args,
                        GumQuickCore * core)
{
  JSValue result = JS_UNDEFINED;
  GumExceptor * exceptor = core->exceptor;
  gpointer address = NULL;
  gpointer pointer = NULL;
  gssize s = 0;
  gsize u = 0;
  gint64 s64 = 0;
  guint64 u64 = 0;
  gdouble number = 0;
  GBytes * bytes = NULL;
  const gchar * str = NULL;
  gsize str_length = 0;
  gunichar2 * str_utf16 = NULL;
#ifdef HAVE_WINDOWS
  gchar * str_ansi = NULL;
#endif
  GumExceptorScope scope;

  switch (type)
  {
    case GUM_MEMORY_VALUE_POINTER:
      if (!_gum_quick_args_parse (args, "pp", &address, &pointer))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_S8:
    case GUM_MEMORY_VALUE_S16:
    case GUM_MEMORY_VALUE_S32:
      if (!_gum_quick_args_parse (args, "pz", &address, &s))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_U8:
    case GUM_MEMORY_VALUE_U16:
    case GUM_MEMORY_VALUE_U32:
      if (!_gum_quick_args_parse (args, "pZ", &address, &u))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_S64:
    case GUM_MEMORY_VALUE_LONG:
      if (!_gum_quick_args_parse (args, "pq", &address, &s64))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_U64:
    case GUM_MEMORY_VALUE_ULONG:
      if (!_gum_quick_args_parse (args, "pQ", &address, &u64))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_FLOAT:
    case GUM_MEMORY_VALUE_DOUBLE:
      if (!_gum_quick_args_parse (args, "pn", &address, &number))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_BYTE_ARRAY:
      if (!_gum_quick_args_parse (args, "pB", &address, &bytes))
        return JS_EXCEPTION;
      break;
    case GUM_MEMORY_VALUE_UTF8_STRING:
    case GUM_MEMORY_VALUE_UTF16_STRING:
    case GUM_MEMORY_VALUE_ANSI_STRING:
      if (!_gum_quick_args_parse (args, "ps", &address, &str))
        return JS_EXCEPTION;

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
        gconstpointer data;
        gsize size;

        data = g_bytes_get_data (bytes, &size);

        memcpy (address, data, size);
        break;
      }
      case GUM_MEMORY_VALUE_UTF8_STRING:
      {
        gsize size;

        size = g_utf8_offset_to_pointer (str, str_length) - str + 1;
        memcpy (address, str, size);
        break;
      }
      case GUM_MEMORY_VALUE_UTF16_STRING:
      {
        gsize size;

        size = (str_length + 1) * sizeof (gunichar2);
        memcpy (address, str_utf16, size);
        break;
      }
      case GUM_MEMORY_VALUE_ANSI_STRING:
      {
#ifdef HAVE_WINDOWS
        strcpy (address, str_ansi);
#else
        result = _gum_quick_throw_literal (ctx,
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
    result = _gum_quick_throw_native (ctx, &scope.exception, core);
  }

  g_free (str_utf16);
#ifdef HAVE_WINDOWS
  g_free (str_ansi);
#endif

  return result;
}

GUMJS_DEFINE_FUNCTION (gum_quick_memory_read_volatile)
{
  gpointer address;
  gsize length;
  gsize n_bytes_read;
  guint8 * data;

  if (!_gum_quick_args_parse (args, "pz", &address, &length))
    return JS_EXCEPTION;

  if (length == 0)
    return JS_NULL;

  data = gum_memory_read (address, length, &n_bytes_read);
  if (data == NULL)
    return _gum_quick_throw_literal (ctx, "memory read failed");

  return JS_NewArrayBuffer (ctx, data, n_bytes_read,
      _gum_quick_array_buffer_free, data, FALSE);
}

#ifdef HAVE_WINDOWS

static gchar *
gum_ansi_string_to_utf8 (const gchar * str_ansi,
                         gint length)
{
  gint str_utf16_length;
  gsize str_utf16_size;
  WCHAR * str_utf16;
  gchar * str_utf8;

  if (length < 0)
    length = (gint) strlen (str_ansi);

  str_utf16_length = MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, length,
      NULL, 0);
  str_utf16_size = (str_utf16_length + 1) * sizeof (WCHAR);
  str_utf16 = g_malloc (str_utf16_size);

  str_utf16_length = MultiByteToWideChar (CP_THREAD_ACP, 0, str_ansi, length,
      str_utf16, str_utf16_length);
  str_utf16[str_utf16_length] = L'\0';

  str_utf8 = g_utf16_to_utf8 ((gunichar2 *) str_utf16, -1, NULL, NULL, NULL);

  g_free (str_utf16);

  return str_utf8;
}

static gchar *
gum_ansi_string_from_utf8 (const gchar * str_utf8)
{
  WCHAR * str_utf16;
  gchar * str_ansi;
  gint str_ansi_size;

  str_utf16 = g_utf8_to_utf16 (str_utf8, -1, NULL, NULL, NULL);

  str_ansi_size = WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1,
      NULL, 0, NULL, NULL);
  str_ansi = g_malloc (str_ansi_size);

  WideCharToMultiByte (CP_THREAD_ACP, 0, str_utf16, -1,
      str_ansi, str_ansi_size, NULL, NULL);

  g_free (str_utf16);

  return str_ansi;
}

#endif

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_ansi_string)
{
#ifdef HAVE_WINDOWS
  const gchar * str;
  gchar * str_ansi;

  if (!_gum_quick_args_parse (args, "s", &str))
    return JS_EXCEPTION;

  str_ansi = gum_ansi_string_from_utf8 (str);

  return _gum_quick_native_resource_new (ctx, str_ansi, g_free, core);
#else
  return _gum_quick_throw_literal (ctx,
      "ANSI API is only applicable on Windows");
#endif
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf8_string)
{
  const gchar * str;

  if (!_gum_quick_args_parse (args, "s", &str))
    return JS_EXCEPTION;

  return _gum_quick_native_resource_new (ctx, g_strdup (str), g_free, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_alloc_utf16_string)
{
  const gchar * str;
  gunichar2 * str_utf16;

  if (!_gum_quick_args_parse (args, "s", &str))
    return JS_EXCEPTION;

  str_utf16 = g_utf8_to_utf16 (str, -1, NULL, NULL, NULL);

  return _gum_quick_native_resource_new (ctx, str_utf16, g_free, core);
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_scan)
{
  gpointer address;
  gsize size;
  GumMemoryScanContext sc;

  if (!_gum_quick_args_parse (args, "pZMF{onMatch,onError,onComplete}",
      &address, &size, &sc.pattern, &sc.on_match, &sc.on_error,
      &sc.on_complete))
    return JS_EXCEPTION;

  sc.range.base_address = GUM_ADDRESS (address);
  sc.range.size = size;

  gum_match_pattern_ref (sc.pattern);

  JS_DupValue (ctx, sc.on_match);
  JS_DupValue (ctx, sc.on_error);
  JS_DupValue (ctx, sc.on_complete);

  sc.result = GUM_QUICK_MATCH_CONTINUE;

  sc.ctx = ctx;
  sc.core = core;

  _gum_quick_core_pin (core);
  _gum_quick_core_push_job (core,
      (GumScriptJobFunc) gum_memory_scan_context_run,
      g_slice_dup (GumMemoryScanContext, &sc),
      (GDestroyNotify) gum_memory_scan_context_free);

  return JS_UNDEFINED;
}

static void
gum_memory_scan_context_free (GumMemoryScanContext * self)
{
  JSContext * ctx = self->ctx;
  GumQuickCore * core = self->core;
  GumQuickScope scope;

  _gum_quick_scope_enter (&scope, core);

  JS_FreeValue (ctx, self->on_match);
  JS_FreeValue (ctx, self->on_error);
  JS_FreeValue (ctx, self->on_complete);

  _gum_quick_core_unpin (core);
  _gum_quick_scope_leave (&scope);

  gum_match_pattern_unref (self->pattern);

  g_slice_free (GumMemoryScanContext, self);
}

static void
gum_memory_scan_context_run (GumMemoryScanContext * self)
{
  JSContext * ctx = self->ctx;
  GumQuickCore * core = self->core;
  GumExceptor * exceptor = core->exceptor;
  GumExceptorScope exceptor_scope;
  GumQuickScope script_scope;

  if (gum_exceptor_try (exceptor, &exceptor_scope))
  {
    gum_memory_scan (&self->range, self->pattern,
        (GumMemoryScanMatchFunc) gum_memory_scan_context_emit_match, self);
  }

  _gum_quick_scope_enter (&script_scope, core);

  if (gum_exceptor_catch (exceptor, &exceptor_scope))
  {
    if (!JS_IsNull (self->on_error))
    {
      gchar * message;
      JSValue message_val;

      message = gum_exception_details_to_string (&exceptor_scope.exception);
      message_val = JS_NewString (ctx, message);
      g_free (message);

      _gum_quick_scope_call_void (&script_scope, self->on_error, JS_UNDEFINED,
          1, &message_val);
    }
  }

  if (self->result != GUM_QUICK_MATCH_ERROR)
  {
    _gum_quick_scope_call_void (&script_scope, self->on_complete, JS_UNDEFINED,
        0, NULL);
  }

  _gum_quick_scope_leave (&script_scope);
}

static gboolean
gum_memory_scan_context_emit_match (GumAddress address,
                                    gsize size,
                                    GumMemoryScanContext * self)
{
  gboolean proceed;
  JSContext * ctx = self->ctx;
  GumQuickCore * core = self->core;
  GumQuickScope scope;
  JSValue argv[2];
  JSValue result;

  _gum_quick_scope_enter (&scope, core);

  argv[0] = _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (address),
      core);
  argv[1] = JS_NewUint32 (ctx, size);

  result = _gum_quick_scope_call (&scope, self->on_match, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[0]);

  proceed = _gum_quick_process_match_result (ctx, &result, &self->result);

  _gum_quick_scope_leave (&scope);

  return proceed;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_scan_sync)
{
  JSValue result;
  gpointer address;
  gsize size;
  GumMatchPattern * pattern;
  GumMemoryRange range;
  GumExceptorScope scope;

  if (!_gum_quick_args_parse (args, "pZM", &address, &size, &pattern))
    return JS_EXCEPTION;

  range.base_address = GUM_ADDRESS (address);
  range.size = size;

  result = JS_NewArray (ctx);

  if (gum_exceptor_try (core->exceptor, &scope))
  {
    GumMemoryScanSyncContext sc;

    sc.matches = result;
    sc.index = 0;

    sc.ctx = ctx;
    sc.core = core;

    gum_memory_scan (&range, pattern, (GumMemoryScanMatchFunc) gum_append_match,
        &sc);
  }

  if (gum_exceptor_catch (core->exceptor, &scope))
  {
    JS_FreeValue (ctx, result);
    result = _gum_quick_throw_native (ctx, &scope.exception, core);
  }

  return result;
}

static gboolean
gum_append_match (GumAddress address,
                  gsize size,
                  GumMemoryScanSyncContext * sc)
{
  JSContext * ctx = sc->ctx;
  GumQuickCore * core = sc->core;
  JSValue m;

  m = JS_NewObject (ctx);
  JS_DefinePropertyValue (ctx, m, GUM_QUICK_CORE_ATOM (core, address),
      _gum_quick_native_pointer_new (ctx, GSIZE_TO_POINTER (address), core),
      JS_PROP_C_W_E);
  JS_DefinePropertyValue (ctx, m, GUM_QUICK_CORE_ATOM (core, size),
      JS_NewUint32 (ctx, size),
      JS_PROP_C_W_E);

  JS_DefinePropertyValueUint32 (ctx, sc->matches, sc->index, m, JS_PROP_C_W_E);
  sc->index++;

  return TRUE;
}

GUMJS_DEFINE_FUNCTION (gumjs_memory_access_monitor_enable)
{
  GumQuickMemory * self;
  GArray * ranges;
  JSValue on_access;
  GError * error;

  self = gumjs_get_parent_module (core);

  if (!_gum_quick_args_parse (args, "RF{onAccess}", &ranges, &on_access))
    return JS_EXCEPTION;

  if (ranges->len == 0)
    return _gum_quick_throw_literal (ctx, "expected one or more ranges");

  gum_quick_memory_clear_monitor (self, ctx);

  self->on_access = JS_DupValue (ctx, on_access);
  self->monitor = gum_memory_access_monitor_new (
      (GumMemoryRange *) ranges->data, ranges->len, GUM_PAGE_RWX, TRUE,
      (GumMemoryAccessNotify) gum_quick_memory_on_access, self, NULL);

  if (!gum_memory_access_monitor_enable (self->monitor, &error))
  {
    _gum_quick_throw_error (ctx, &error);

    gum_quick_memory_clear_monitor (self, ctx);

    return JS_EXCEPTION;
  }

  return JS_UNDEFINED;
}

GUMJS_DEFINE_FUNCTION (gumjs_
```