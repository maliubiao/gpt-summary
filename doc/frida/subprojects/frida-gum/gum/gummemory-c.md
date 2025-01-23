Response:
Let's break down the thought process for analyzing this C code and generating the detailed response.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `gummemory.c` within the Frida instrumentation framework. This involves:

* **Listing functionalities:** Identifying the core tasks the code performs.
* **Relating to reverse engineering:**  Connecting these functionalities to common reverse engineering techniques.
* **Highlighting low-level details:**  Identifying interactions with the operating system kernel, especially Linux and Android, and binary concepts.
* **Inferring logic and providing examples:**  Demonstrating how certain functions might work with sample inputs and outputs.
* **Pointing out potential user errors:**  Identifying common mistakes a developer might make when using this code.
* **Tracing the usage:**  Explaining how a user's actions in Frida might lead to the execution of this code.

**2. Initial Code Scan and Keyword Identification:**

The first step is to quickly scan the code, looking for keywords and patterns that suggest specific functionalities. This involves:

* **Headers:**  `#include` statements reveal dependencies and areas of focus (e.g., `gumcloak.h`, `gumcodesegment.h`, `gumlibc.h`, `dlmalloc.c`, platform-specific headers like `<ptrauth.h>` and Android headers).
* **Function names:**  Names like `gum_memory_scan`, `gum_memory_patch_code`, `gum_match_pattern_new`, `gum_mprotect`, `gum_malloc`, `gum_free` are strong indicators of the operations being performed.
* **Data structures:**  `GumMatchPattern`, `GumMemoryRange`, `GumMatchToken` suggest the code deals with pattern matching and memory management.
* **Preprocessor directives:** `#ifdef`, `#ifndef` reveal conditional compilation for different platforms and configurations (e.g., `HAVE_PTRAUTH`, `HAVE_ANDROID`, `GUM_USE_SYSTEM_ALLOC`).
* **Memory-related terms:**  "page size," "protection," "RWX," "allocation," "free" point to memory manipulation.

**3. Grouping Functionalities and Identifying Core Modules:**

Based on the initial scan, we can start grouping related functions and identifying the key modules within the file:

* **Memory Allocation:** Functions like `gum_malloc`, `gum_free`, `gum_calloc`, `gum_realloc`, `gum_memalign`, and the inclusion of `dlmalloc.c` clearly indicate custom memory management (optionally).
* **Memory Protection:**  `gum_mprotect`, `gum_try_mprotect`, `gum_query_rwx_support`, and discussions of `GUM_PAGE_RWX`, `GUM_PAGE_RX` relate to changing memory permissions.
* **Code Patching:** `gum_memory_patch_code` is a central function for modifying code in memory.
* **Memory Scanning and Pattern Matching:** `gum_memory_scan`, `gum_match_pattern_new_from_string`, `gum_match_pattern_new_from_hexstring`, `gum_match_pattern_new_from_regex`, and the `GumMatchPattern` structure itself point to functionality for searching memory for specific byte sequences or regular expressions.
* **Pointer Authentication (PAC):** The presence of `HAVE_PTRAUTH`, `ptrauth_sign_unauthenticated`, and `ptrauth_strip` signifies support for pointer authentication, a security feature on some architectures.
* **Code Segment Management:**  `gum_code_segment_new`, `gum_code_segment_realize`, `gum_code_segment_map`, and `gum_code_segment_is_supported` suggest a mechanism for managing executable code in memory, potentially for cases where direct modification is restricted.
* **Android-Specific Features:** The `#ifdef HAVE_ANDROID` block and functions referencing `gum_android_get_api_level` indicate Android-specific handling, likely related to relaxed memory protection on older Android versions.

**4. Connecting Functionalities to Reverse Engineering:**

Now, the goal is to link these identified functionalities to common reverse engineering tasks:

* **Code patching:**  Directly modifying program behavior is a core technique in reverse engineering for things like disabling checks, altering function calls, or injecting custom code.
* **Memory scanning:** Searching for specific byte patterns (signatures) is used to identify functions, data structures, or vulnerabilities. Regular expressions extend this capability for more complex patterns.
* **Understanding memory layout and permissions:**  Knowing how memory is organized and protected is crucial for exploiting vulnerabilities or understanding how a program works.
* **Circumventing security measures:**  Understanding pointer authentication allows for analysis and manipulation of code on systems employing this protection.

**5. Identifying Low-Level Details:**

This involves recognizing interactions with the operating system and binary concepts:

* **Memory Protection (mprotect):**  Direct calls to `gum_try_mprotect` (likely wrapping the system's `mprotect` call) are a direct interaction with the OS kernel.
* **Page Size:** The concept of page size is fundamental to memory management in operating systems.
* **RWX Permissions:**  Understanding the read, write, and execute permissions on memory pages is essential for low-level reverse engineering.
* **Code Segments:**  The concept of separate memory regions for code and data is a basic binary organization principle.
* **Pointer Authentication:** This is a specific hardware/OS feature.
* **Custom Allocator (dlmalloc):**  Using a custom memory allocator demonstrates a lower-level approach to memory management than relying solely on the system's `malloc`.

**6. Inferring Logic and Providing Examples:**

For functions like `gum_memory_scan` and `gum_match_pattern_new_from_hexstring`,  we can make educated guesses about their behavior and create simple examples:

* **`gum_match_pattern_new_from_hexstring`:**  Consider how a hex string with wildcards (`?`) or masks (`:`) would be parsed and how the `GumMatchToken` structure would be populated.
* **`gum_memory_scan`:** Imagine searching a memory range for a specific pattern. Consider how the "longest token" optimization might work.

**7. Identifying Potential User Errors:**

Think about how a developer might misuse these functions:

* **Incorrect pattern syntax:**  Providing an invalid hex string or regular expression to `gum_match_pattern_new_from_string`.
* **Patching code incorrectly:**  Modifying the wrong bytes or introducing errors during the patching process.
* **Memory leaks:**  If the custom memory allocator is used and `gum_free` isn't called appropriately.
* **Incorrect use of memory protection:** Trying to set invalid memory protection flags.

**8. Tracing User Operations:**

Consider how a Frida user might interact with these functions:

* **Scripting API:** Frida's JavaScript API provides functions that map to the C functions in `gummemory.c`. For example, using `Memory.scan` in a Frida script would ultimately call `gum_memory_scan`. `Process.getModuleByName("...").base` would provide the `GumMemoryRange`. `Memory.patchCode` would call `gum_memory_patch_code`.

**9. Structuring the Response:**

Finally, organize the findings into a clear and structured response, addressing each part of the original prompt:

* **Functionalities:** List the main capabilities of the file.
* **Relationship to Reverse Engineering:**  Provide concrete examples of how each functionality is used in reverse engineering.
* **Binary/Kernel/Framework Knowledge:** Detail the low-level concepts involved.
* **Logical Inference and Examples:**  Illustrate the behavior of key functions with sample inputs and outputs.
* **User Errors:**  Provide practical examples of common mistakes.
* **Debugging Clues:** Explain how user actions lead to the code's execution.

By following these steps, we can systematically analyze the C code and generate a comprehensive and informative response that addresses all aspects of the prompt. The key is to combine code-level analysis with an understanding of the broader context of Frida and reverse engineering techniques.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/gum/gummemory.c` 这个文件的功能。

**文件功能概览:**

`gummemory.c` 文件是 Frida (基于 Gum 库) 中负责内存管理和操作的核心组件。它提供了以下主要功能：

1. **内存分配与释放:**
   - 封装了底层的内存分配和释放操作，可以选择使用系统默认的分配器 (`malloc`, `free`) 或者自定义的分配器 (`dlmalloc`)。
   - 提供了 `gum_malloc`, `gum_calloc`, `gum_realloc`, `gum_free` 等标准的内存分配函数。
   - 针对内部使用，提供了 `gum_internal_malloc`, `gum_internal_calloc`, `gum_internal_realloc`, `gum_internal_free`。
   - 实现了页对齐的内存分配 `gum_alloc_n_pages` 和 `gum_alloc_n_pages_near`，用于分配具有特定保护属性的内存页。

2. **内存保护:**
   - 提供了修改内存页保护属性的功能，例如将内存页设置为可读、可写、可执行 (`RWX`, `RX`, `RW`)。
   - 实现了 `gum_mprotect` 和 `gum_try_mprotect` 函数，用于修改内存保护属性。`gum_try_mprotect` 在修改失败时不会终止程序。
   - 提供了查询系统是否支持 `RWX` 内存保护的函数 `gum_query_is_rwx_supported` 和 `gum_query_rwx_support`。
   - 在 Android 平台上，针对 API Level < 29 的设备，提供了软化代码页的功能 `gum_ensure_code_readable`，允许在这些设备上读取和修改代码页。

3. **代码修改 (Patching):**
   - 提供了安全修改代码段的功能 `gum_memory_patch_code`。
   - 该函数会先尝试修改内存保护属性为可写，然后调用用户提供的回调函数 `GumMemoryPatchApplyFunc` 在可写内存上进行修改，最后清理缓存并恢复内存保护属性。
   - 对于不支持直接修改代码段的系统（如某些 iOS 版本），会使用 `GumCodeSegment` 创建一个临时的可写内存区域进行修改，然后再映射回原始位置。

4. **内存扫描与模式匹配:**
   - 提供了在指定内存范围内扫描特定字节模式的功能 `gum_memory_scan`。
   - 实现了 `GumMatchPattern` 数据结构，用于表示要搜索的模式，支持十六进制字符串模式和正则表达式模式。
   - `gum_match_pattern_new_from_string` 可以从字符串创建匹配模式，支持 `/regex/` 格式的正则表达式和十六进制字符串模式。
   - 十六进制字符串模式支持通配符 `?` 和掩码 `:`。
   - 提供了 `gum_match_pattern_ref` 和 `gum_match_pattern_unref` 用于管理 `GumMatchPattern` 的引用计数。

5. **指针认证 (Pointer Authentication, PAC):**
   - 针对支持指针认证的架构 (例如 ARMv8.3-A 及更高版本)，提供了签名和去除代码指针签名的功能 `gum_sign_code_pointer`, `gum_strip_code_pointer`, `gum_sign_code_address`, `gum_strip_code_address`。
   - 提供了查询系统是否支持指针认证的函数 `gum_query_ptrauth_support`。

6. **内部堆管理:**
   - 使用引用计数 `gum_heap_ref_count` 管理内部堆的初始化和反初始化。
   - 使用 `gum_internal_heap_ref` 和 `gum_internal_heap_unref` 进行引用计数操作。

**与逆向方法的关联及举例说明:**

1. **代码修改 (Patching):** 这是逆向工程中非常常见的技术，用于修改程序的行为。
   - **例子:** 假设你想禁用一个程序的许可证校验。你可以使用 Frida 找到校验函数的地址，然后使用 `gum_memory_patch_code` 将校验函数的返回值强制设置为成功，或者跳转到一个总是返回成功的地址。
     ```c
     // 假设找到了校验函数的地址为 0x12345678
     GumAddress check_license_address = 0x12345678;
     gsize patch_size = 1; // 假设只需要修改一个字节

     gboolean apply_patch(gpointer address, gpointer user_data) {
         // 将该地址的第一个字节修改为返回指令 (例如 ARM 上的 BX LR)
         *((guint8*)address) = 0x00; // 这只是一个占位符，实际指令需要根据架构确定
         return TRUE;
     }

     gum_memory_patch_code((gpointer)check_license_address, patch_size, apply_patch, NULL);
     ```

2. **内存扫描与模式匹配:** 用于查找特定的代码片段、数据结构或常量。
   - **例子:** 你想找到程序中某个特定函数的起始地址，但你只知道该函数开头的几个字节的指令。你可以使用 `gum_memory_scan` 扫描程序的内存，查找匹配该指令模式的位置。
     ```c
     // 假设要查找以指令 "55 48 89 e5" 开头的函数 (x86-64 的 push rbp; mov rbp, rsp)
     const gchar *pattern_string = "55 48 89 e5";
     GumMatchPattern *pattern = gum_match_pattern_new_from_hexstring(pattern_string);

     gboolean on_match(GumAddress address, guint size, gpointer user_data) {
         g_print("Found function start at: %p\n", (void*)address);
         return FALSE; // 找到一个就停止扫描
     }

     // 假设要扫描的内存范围
     GumMemoryRange range = { .base_address = 0x10000000, .size = 0x10000 };
     gum_memory_scan(&range, pattern, on_match, NULL);

     gum_match_pattern_unref(pattern);
     ```

3. **内存保护:** 了解内存保护机制可以帮助逆向工程师理解程序的安全策略和运行环境。
   - **例子:** 通过观察程序运行时内存页的保护属性，可以推断哪些内存区域用于存储代码、哪些用于存储可修改的数据，以及哪些区域是只读的。这对于分析程序的漏洞和保护机制很有帮助。

**涉及的二进制底层、Linux、Android 内核及框架知识:**

1. **二进制底层:**
   - **指令编码:** `gum_memory_scan` 和代码 patching 功能需要理解不同 CPU 架构的指令编码格式，才能准确地搜索和修改代码。
   - **内存布局:** 理解进程的内存布局（代码段、数据段、堆、栈等）是进行内存扫描和 patching 的基础。
   - **页对齐:** 内存保护操作通常以页为单位进行，因此需要理解页大小的概念。
   - **指针认证 (PAC):** 涉及到 ARM 架构中用于增强安全性的指针签名和验证机制。

2. **Linux 内核:**
   - **`mprotect` 系统调用:** `gum_mprotect` 和 `gum_try_mprotect` 实际上是对 Linux (或其他类 Unix 系统) 的 `mprotect` 系统调用的封装，用于修改内存页的权限。
   - **内存管理:** 理解 Linux 内核的虚拟内存管理机制有助于理解 `gummemory.c` 中内存分配和保护的相关操作。
   - **缓存一致性:** `gum_clear_cache` 涉及到清理 CPU 缓存，以确保修改后的代码能够立即生效。

3. **Android 内核及框架:**
   - **Android 的内存管理:** Android 基于 Linux 内核，其内存管理机制与 Linux 类似。
   - **ART (Android Runtime):**  在 Android 上进行动态 instrumentation 需要了解 ART 的内部机制，例如代码的加载、执行和内存管理方式。
   - **软化代码页:**  在旧版本的 Android 上，代码页通常是只读的，`gum_ensure_code_readable` 利用了 Android 框架的特性来临时修改代码页的权限，使得可以进行修改。

**逻辑推理及假设输入与输出:**

**示例：`gum_match_pattern_new_from_hexstring`**

**假设输入:** `match_combined_str = "41 b? c3"`

**逻辑推理:**
- 函数会解析十六进制字符串 "41 b? c3"。
- '41' 代表一个确定的字节 `0x41`。
- 'b?' 代表高 4 位是 `0xb`，低 4 位可以是任意值，对应的掩码是 `0xf0`。
- 'c3' 代表一个确定的字节 `0xc3`。
- 函数会创建 `GumMatchToken` 对象来表示这些匹配规则。

**可能的输出 (GumMatchPattern 结构体的部分内容):**
```
GumMatchPattern {
  ref_count: 1,
  tokens: [
    GumMatchToken { type: GUM_MATCH_EXACT, bytes: [0x41], masks: NULL, offset: 0 },
    GumMatchToken { type: GUM_MATCH_MASK,  bytes: [0xb0], masks: [0xf0], offset: 1 },
    GumMatchToken { type: GUM_MATCH_EXACT, bytes: [0xc3], masks: NULL, offset: 2 }
  ],
  size: 3,
  regex: NULL
}
```

**涉及用户或者编程常见的使用错误及举例说明:**

1. **错误的匹配模式格式:**
   - **错误示例:** `gum_match_pattern_new_from_string("invalid hex string")` // 无效的十六进制字符
   - **错误示例:** `gum_match_pattern_new_from_string("/invalid regex")` // 正则表达式语法错误

2. **尝试修改只读内存:**
   - **错误示例:** 在没有成功修改内存保护属性的情况下，直接尝试写入代码段。这会导致程序崩溃或出现未定义的行为。

3. **内存泄漏:**
   - **错误示例:**  如果使用了自定义的内存分配器并且没有正确调用 `gum_free` 释放分配的内存。

4. **`gum_memory_patch_code` 的回调函数中操作不当:**
   - **错误示例:** 在 `GumMemoryPatchApplyFunc` 回调函数中，写入的字节数超过了 `size` 参数，可能导致覆盖相邻的内存区域。
   - **错误示例:** 在回调函数中进行耗时操作，会阻塞 Frida 的执行。

5. **在不支持 RWX 的系统上假设可以使用:**
   - **错误示例:**  在 iOS 等不支持直接 RWX 内存保护的系统上，直接尝试使用 `gum_mprotect` 设置 `GUM_PAGE_RWX`，会导致失败。应该使用 `gum_memory_patch_code`，它会自动处理这种情况。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

Frida 的用户通常通过编写 JavaScript 脚本来与目标进程进行交互。以下是一些可能导致 `gummemory.c` 中的代码被执行的场景：

1. **使用 `Memory.scan` 函数进行内存扫描:**
   - 用户在 JavaScript 脚本中调用 `Memory.scan(address, size, pattern)`。
   - Frida 的 JavaScript 引擎会将这个调用转发到 Gum 库的 C 代码。
   - `pattern` 参数会被转换为 `GumMatchPattern` 对象，这会调用 `gum_match_pattern_new_from_string` 等函数。
   - `Memory.scan` 的底层实现会调用 `gum_memory_scan` 函数，遍历指定的内存范围并使用 `GumMatchPattern` 进行匹配。

2. **使用 `Memory.patchCode` 函数修改代码:**
   - 用户在 JavaScript 脚本中调用 `Memory.patchCode(address, data)` 或 `Interceptor.replace(target, replacement)`。
   - Frida 会解析目标地址和要写入的数据。
   - 底层会调用 `gum_memory_patch_code` 函数。
   - `gum_memory_patch_code` 会根据目标平台的特性，调用 `gum_try_mprotect` 修改内存保护属性，或者使用 `GumCodeSegment` 进行间接修改。
   - 用户提供的修改操作会在 `GumMemoryPatchApplyFunc` 回调函数中执行。

3. **使用 `Memory.alloc` 或 `Memory.protect` 等函数进行内存管理:**
   - 用户可以使用 `Memory.alloc(size)` 分配内存，这会调用 `gum_malloc` 或 `gum_calloc`。
   - 用户可以使用 `Memory.protect(address, size, protection)` 修改内存保护属性，这会调用 `gum_mprotect`。

4. **Frida 内部操作:**
   - Frida 的内部机制，例如 hook 函数、代码注入等，也会涉及到内存的分配、保护和修改，这些操作也会调用 `gummemory.c` 中的相关函数。

**调试线索:**

如果在 Frida 脚本执行过程中遇到与内存相关的错误，可以考虑以下调试线索：

- **查看 Frida 的错误信息:** Frida 通常会提供详细的错误信息，包括函数调用栈，可以帮助定位问题。
- **使用 Frida 的 `console.log` 输出:** 在脚本中添加 `console.log` 语句，输出关键变量的值，例如内存地址、大小、模式字符串等，可以帮助理解程序的执行流程。
- **检查内存保护属性:** 使用 Frida 脚本检查目标内存区域的保护属性，确认是否具有预期的权限。
- **逐步执行脚本:** 使用 Frida 提供的调试工具或方法，逐步执行脚本，观察每一步的内存操作。
- **分析目标进程的内存布局:** 了解目标进程的内存布局，可以帮助判断内存操作是否在合法的范围内。

总而言之，`gummemory.c` 是 Frida 进行动态 instrumentation 的基础，它提供了可靠且灵活的内存管理和操作接口，使得 Frida 能够安全地读取、修改目标进程的内存和代码，从而实现各种强大的逆向工程功能。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/gummemory.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2021 Abdelrahman Eid <hot3eed@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gumcloak-priv.h"
#include "gumcodesegment.h"
#include "gumlibc.h"
#include "gummemory-priv.h"

#ifdef HAVE_PTRAUTH
# include <ptrauth.h>
#endif
#include <stdlib.h>
#include <string.h>

#ifdef HAVE_ANDROID
# include "gum/gumandroid.h"
#endif
#ifndef GUM_USE_SYSTEM_ALLOC
# ifdef HAVE_DARWIN
#  define DARWIN                   1
# endif
# define MSPACES                   1
# define ONLY_MSPACES              1
# define USE_LOCKS                 1
# define FOOTERS                   0
# define INSECURE                  1
# define NO_MALLINFO               0
# define REALLOC_ZERO_BYTES_FREES  1
# ifdef HAVE_LIBC_MALLINFO
#  include <malloc.h>
#  define STRUCT_MALLINFO_DECLARED 1
# endif
# ifdef _MSC_VER
#  pragma warning (push)
#  pragma warning (disable: 4267 4702)
# endif
# ifdef _GNU_SOURCE
#  undef _GNU_SOURCE
# endif
# include "dlmalloc.c"
# ifdef _MSC_VER
#  pragma warning (pop)
# endif
#endif

struct _GumMatchPattern
{
  gint ref_count;
  GPtrArray * tokens;
  guint size;
  GRegex * regex;
};

static void gum_memory_scan_raw (const GumMemoryRange * range,
    const GumMatchPattern * pattern, GumMemoryScanMatchFunc func,
    gpointer user_data);
static void gum_memory_scan_regex (const GumMemoryRange * range,
    const GRegex * regex, GumMemoryScanMatchFunc func, gpointer user_data);
static GumMatchPattern * gum_match_pattern_new_from_hexstring (
    const gchar * match_combined_str);
static GumMatchPattern * gum_match_pattern_new_from_regex (
    const gchar * regex_str);
static GumMatchPattern * gum_match_pattern_new (void);
static void gum_match_pattern_update_computed_size (GumMatchPattern * self);
static GumMatchToken * gum_match_pattern_get_longest_token (
    const GumMatchPattern * self, GumMatchType type);
static gboolean gum_match_pattern_try_match_on (const GumMatchPattern * self,
    guint8 * bytes);
static gint gum_memcmp_mask (const guint8 * haystack, const guint8 * needle,
    const guint8 * mask, guint len);
static GumMatchToken * gum_match_pattern_push_token (GumMatchPattern * self,
    GumMatchType type);
static gboolean gum_match_pattern_seal (GumMatchPattern * self);

static GumMatchToken * gum_match_token_new (GumMatchType type);
static void gum_match_token_free (GumMatchToken * token);
static void gum_match_token_append (GumMatchToken * self, guint8 byte);
static void gum_match_token_append_with_mask (GumMatchToken * self,
    guint8 byte, guint8 mask);

static guint gum_heap_ref_count = 0;
#ifndef GUM_USE_SYSTEM_ALLOC
static mspace gum_mspace_main = NULL;
static mspace gum_mspace_internal = NULL;
#endif
static guint gum_cached_page_size;

#ifdef HAVE_ANDROID
G_LOCK_DEFINE_STATIC (gum_softened_code_pages);
static GHashTable * gum_softened_code_pages;
#endif

GUM_DEFINE_BOXED_TYPE (GumMatchPattern, gum_match_pattern,
                       gum_match_pattern_ref, gum_match_pattern_unref)
GUM_DEFINE_BOXED_TYPE (GumMemoryRange, gum_memory_range, gum_memory_range_copy,
                       gum_memory_range_free)

void
gum_internal_heap_ref (void)
{
  if (gum_heap_ref_count++ > 0)
    return;

  _gum_memory_backend_init ();

  gum_cached_page_size = _gum_memory_backend_query_page_size ();

  _gum_cloak_init ();

#ifndef GUM_USE_SYSTEM_ALLOC
  gum_mspace_main = create_mspace (0, TRUE);
  gum_mspace_internal = create_mspace (0, TRUE);
#endif
}

void
gum_internal_heap_unref (void)
{
  g_assert (gum_heap_ref_count != 0);
  if (--gum_heap_ref_count > 0)
    return;

#ifndef GUM_USE_SYSTEM_ALLOC
  destroy_mspace (gum_mspace_internal);
  gum_mspace_internal = NULL;

  destroy_mspace (gum_mspace_main);
  gum_mspace_main = NULL;

  (void) DESTROY_LOCK (&malloc_global_mutex);
#endif

  _gum_cloak_deinit ();

  _gum_memory_backend_deinit ();
}

gpointer
gum_sign_code_pointer (gpointer value)
{
#ifdef HAVE_PTRAUTH
  return ptrauth_sign_unauthenticated (value, ptrauth_key_asia, 0);
#else
  return value;
#endif
}

gpointer
gum_strip_code_pointer (gpointer value)
{
#ifdef HAVE_PTRAUTH
  return ptrauth_strip (value, ptrauth_key_asia);
#else
  return value;
#endif
}

GumAddress
gum_sign_code_address (GumAddress value)
{
#ifdef HAVE_PTRAUTH
  return GPOINTER_TO_SIZE (ptrauth_sign_unauthenticated (
      GSIZE_TO_POINTER (value), ptrauth_key_asia, 0));
#else
  return value;
#endif
}

GumAddress
gum_strip_code_address (GumAddress value)
{
#ifdef HAVE_PTRAUTH
  return GPOINTER_TO_SIZE (ptrauth_strip (
      GSIZE_TO_POINTER (value), ptrauth_key_asia));
#else
  return value;
#endif
}

GumPtrauthSupport
gum_query_ptrauth_support (void)
{
#ifdef HAVE_PTRAUTH
  return GUM_PTRAUTH_SUPPORTED;
#else
  return GUM_PTRAUTH_UNSUPPORTED;
#endif
}

guint
gum_query_page_size (void)
{
  return gum_cached_page_size;
}

gboolean
gum_query_is_rwx_supported (void)
{
  return gum_query_rwx_support () == GUM_RWX_FULL;
}

GumRwxSupport
gum_query_rwx_support (void)
{
#if defined (HAVE_DARWIN) && !defined (HAVE_I386)
  return GUM_RWX_NONE;
#else
  return GUM_RWX_FULL;
#endif
}

/**
 * gum_memory_patch_code:
 * @address: address to modify from
 * @size: number of bytes to modify
 * @apply: (scope call): function to apply the modifications
 *
 * Safely modifies @size bytes at @address. The supplied function @apply gets
 * called with a writable pointer where you must write the desired
 * modifications before returning. Do not make any assumptions about this being
 * the same location as @address, as some systems require modifications to be
 * written to a temporary location before being mapped into memory on top of the
 * original memory page (e.g. on iOS, where directly modifying in-memory code
 * may result in the process losing its CS_VALID status).
 *
 * Returns: whether the modifications were successfully applied
 */
gboolean
gum_memory_patch_code (gpointer address,
                       gsize size,
                       GumMemoryPatchApplyFunc apply,
                       gpointer apply_data)
{
  gsize page_size;
  guint8 * start_page, * end_page;
  gsize page_offset, range_size;
  gboolean rwx_supported;

  address = gum_strip_code_pointer (address);

  page_size = gum_query_page_size ();
  start_page = GSIZE_TO_POINTER (GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  end_page = GSIZE_TO_POINTER (
      (GPOINTER_TO_SIZE (address) + size - 1) & ~(page_size - 1));
  page_offset = ((guint8 *) address) - start_page;
  range_size = (end_page + page_size) - start_page;

  rwx_supported = gum_query_is_rwx_supported ();

  if (rwx_supported || !gum_code_segment_is_supported ())
  {
    GumPageProtection protection;

    protection = rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW;

    if (!gum_try_mprotect (start_page, range_size, protection))
      return FALSE;

    apply (address, apply_data);

    gum_clear_cache (address, size);

    if (!rwx_supported)
    {
      /*
       * We don't bother restoring the protection on RWX systems, as we would
       * have to determine the old protection to be able to do so safely.
       *
       * While we could easily do that, it would add overhead, but it's not
       * really clear that it would have any tangible upsides.
       *
       * This behavior is also consistent with Interceptor, so if we later
       * decide to change it, it also needs changing there.
       */
      if (!gum_try_mprotect (start_page, range_size, GUM_PAGE_RX))
        return FALSE;
    }
  }
  else
  {
    GumCodeSegment * segment;
    guint8 * scratch_page;

    segment = gum_code_segment_new (range_size, NULL);
    scratch_page = gum_code_segment_get_address (segment);
    memcpy (scratch_page, start_page, range_size);

    apply (scratch_page + page_offset, apply_data);

    gum_code_segment_realize (segment);
    gum_code_segment_map (segment, 0, range_size, start_page);

    gum_code_segment_free (segment);

    gum_clear_cache (address, size);
  }

  return TRUE;
}

gboolean
gum_memory_mark_code (gpointer address,
                      gsize size)
{
  gboolean success;

  if (gum_code_segment_is_supported ())
  {
    gsize page_size;
    guint8 * start_page, * end_page;

    page_size = gum_query_page_size ();
    start_page =
        GSIZE_TO_POINTER (GPOINTER_TO_SIZE (address) & ~(page_size - 1));
    end_page = GSIZE_TO_POINTER (
        (GPOINTER_TO_SIZE (address) + size - 1) & ~(page_size - 1));

    success = gum_code_segment_mark (start_page,
        end_page - start_page + page_size, NULL);
  }
  else
  {
    success = gum_try_mprotect (address, size, GUM_PAGE_RX);
  }

  gum_clear_cache (address, size);

  return success;
}

/**
 * gum_memory_scan:
 * @range: the #GumMemoryRange to scan
 * @pattern: the #GumMatchPattern to look for occurrences of
 * @func: (scope call): function to process each match
 * @user_data: data to pass to @func
 *
 * Scans @range for occurrences of @pattern, calling @func with each match.
 */
void
gum_memory_scan (const GumMemoryRange * range,
                 const GumMatchPattern * pattern,
                 GumMemoryScanMatchFunc func,
                 gpointer user_data)
{
  if (pattern->regex == NULL)
    gum_memory_scan_raw (range, pattern, func, user_data);
  else
    gum_memory_scan_regex (range, pattern->regex, func, user_data);
}

static void
gum_memory_scan_raw (const GumMemoryRange * range,
                     const GumMatchPattern * pattern,
                     GumMemoryScanMatchFunc func,
                     gpointer user_data)
{
  GumMatchToken * needle;
  guint8 * needle_data, * mask_data = NULL;
  guint needle_len, pattern_size;
  guint8 * cur, * end_address;

  needle = gum_match_pattern_get_longest_token (pattern, GUM_MATCH_EXACT);
  if (needle == NULL)
  {
    needle = gum_match_pattern_get_longest_token (pattern, GUM_MATCH_MASK);
    mask_data = (guint8 *) needle->masks->data;
  }

  needle_data = (guint8 *) needle->bytes->data;
  needle_len = needle->bytes->len;
  pattern_size = gum_match_pattern_get_size (pattern);

  cur = GSIZE_TO_POINTER (range->base_address);
  end_address = cur + range->size - (pattern_size - needle->offset) + 1;

  for (; cur < end_address; cur++)
  {
    guint8 * start;

    if (mask_data == NULL)
    {
      if (cur[0] != needle_data[0] ||
          memcmp (cur, needle_data, needle_len) != 0)
      {
        continue;
      }
    }
    else
    {
      if ((cur[0] & mask_data[0]) != (needle_data[0] & mask_data[0]) ||
          gum_memcmp_mask ((guint8 *) cur, (guint8 *) needle_data,
              (guint8 *) mask_data, needle_len) != 0)
      {
        continue;
      }
    }

    start = cur - needle->offset;

    if (gum_match_pattern_try_match_on (pattern, start))
    {
      if (!func (GUM_ADDRESS (start), pattern_size, user_data))
        return;

      cur = start + pattern_size - 1;
    }
  }
}

static void
gum_memory_scan_regex (const GumMemoryRange * range,
                       const GRegex * regex,
                       GumMemoryScanMatchFunc func,
                       gpointer user_data)
{
  GMatchInfo * info;

  g_regex_match_full (regex, GSIZE_TO_POINTER (range->base_address),
      range->size, 0, 0, &info, NULL);

  while (g_match_info_matches (info))
  {
    gint start_pos, end_pos;

    if (!g_match_info_fetch_pos (info, 0, &start_pos, &end_pos) ||
        (gsize) end_pos > range->size ||
        !func (GUM_ADDRESS (range->base_address + start_pos),
            end_pos - start_pos, user_data))
    {
      break;
    }

    g_match_info_next (info, NULL);
  }

  g_match_info_free (info);
}

GumMatchPattern *
gum_match_pattern_new_from_string (const gchar * pattern_str)
{
  GumMatchPattern * result;

  if (g_str_has_prefix (pattern_str, "/") &&
      g_str_has_suffix (pattern_str, "/"))
  {
    gchar * regex_str = g_strndup (pattern_str + 1, strlen (pattern_str) - 2);
    result = gum_match_pattern_new_from_regex (regex_str);
    g_free (regex_str);
  }
  else
  {
    result = gum_match_pattern_new_from_hexstring (pattern_str);
  }

  return result;
}

static GumMatchPattern *
gum_match_pattern_new_from_hexstring (const gchar * match_combined_str)
{
  GumMatchPattern * pattern = NULL;
  gchar ** parts;
  const gchar * match_str, * mask_str;
  gboolean has_mask = FALSE;
  GumMatchToken * token = NULL;
  const gchar * ch, * mh;

  parts = g_strsplit (match_combined_str, ":", 2);
  match_str = parts[0];
  if (match_str == NULL)
    goto parse_error;

  mask_str = parts[1];
  has_mask = mask_str != NULL;
  if (has_mask && strlen (mask_str) != strlen (match_str))
    goto parse_error;

  pattern = gum_match_pattern_new ();

  for (ch = match_str, mh = mask_str;
       *ch != '\0' && (!has_mask || *mh != '\0');
       ch++, mh++)
  {
    gint upper, lower;
    gint mask = 0xff;
    guint8 value;

    if (ch[0] == ' ')
      continue;

    if (has_mask)
    {
      while (mh[0] == ' ')
        mh++;
      if ((upper = g_ascii_xdigit_value (mh[0])) == -1)
        goto parse_error;
      if ((lower = g_ascii_xdigit_value (mh[1])) == -1)
        goto parse_error;
      mask = (upper << 4) | lower;
    }

    if (ch[0] == '?')
    {
      upper = 4;
      mask &= 0x0f;
    }
    else if ((upper = g_ascii_xdigit_value (ch[0])) == -1)
    {
      goto parse_error;
    }

    if (ch[1] == '?')
    {
      lower = 2;
      mask &= 0xf0;
    }
    else if ((lower = g_ascii_xdigit_value (ch[1])) == -1)
    {
      goto parse_error;
    }

    value = (upper << 4) | lower;

    if (mask == 0xff)
    {
      if (token == NULL || token->type != GUM_MATCH_EXACT)
        token = gum_match_pattern_push_token (pattern, GUM_MATCH_EXACT);
      gum_match_token_append (token, value);
    }
    else if (mask == 0x00)
    {
      if (token == NULL || token->type != GUM_MATCH_WILDCARD)
        token = gum_match_pattern_push_token (pattern, GUM_MATCH_WILDCARD);
      gum_match_token_append (token, 0x42);
    }
    else
    {
      if (token == NULL || token->type != GUM_MATCH_MASK)
        token = gum_match_pattern_push_token (pattern, GUM_MATCH_MASK);
      gum_match_token_append_with_mask (token, value, mask);
    }

    ch++;
    mh++;
  }

  if (!gum_match_pattern_seal (pattern))
    goto parse_error;

  g_strfreev (parts);

  return pattern;

  /* ERRORS */
parse_error:
  {
    g_strfreev (parts);
    if (pattern != NULL)
      gum_match_pattern_unref (pattern);

    return NULL;
  }
}

static GumMatchPattern *
gum_match_pattern_new_from_regex (const gchar * regex_str)
{
  GumMatchPattern * pattern;
  GRegex * regex;

  regex = g_regex_new (regex_str, G_REGEX_OPTIMIZE | G_REGEX_RAW,
      G_REGEX_MATCH_NOTEMPTY, NULL);
  if (regex == NULL)
    return NULL;

  pattern = gum_match_pattern_new ();
  pattern->regex = regex;

  return pattern;
}

static GumMatchPattern *
gum_match_pattern_new (void)
{
  GumMatchPattern * pattern;

  pattern = g_slice_new (GumMatchPattern);
  pattern->ref_count = 1;
  pattern->tokens =
      g_ptr_array_new_with_free_func ((GDestroyNotify) gum_match_token_free);
  pattern->size = 0;
  pattern->regex = NULL;

  return pattern;
}

GumMatchPattern *
gum_match_pattern_ref (GumMatchPattern * pattern)
{
  g_atomic_int_inc (&pattern->ref_count);

  return pattern;
}

void
gum_match_pattern_unref (GumMatchPattern * pattern)
{
  if (g_atomic_int_dec_and_test (&pattern->ref_count))
  {
    if (pattern->regex != NULL)
      g_regex_unref (pattern->regex);

    g_ptr_array_free (pattern->tokens, TRUE);

    g_slice_free (GumMatchPattern, pattern);
  }
}

guint
gum_match_pattern_get_size (const GumMatchPattern * pattern)
{
  return pattern->size;
}

/**
 * gum_match_pattern_get_tokens: (skip)
 */
GPtrArray *
gum_match_pattern_get_tokens (const GumMatchPattern * pattern)
{
  return pattern->tokens;
}

static void
gum_match_pattern_update_computed_size (GumMatchPattern * self)
{
  guint i;

  self->size = 0;

  for (i = 0; i != self->tokens->len; i++)
  {
    GumMatchToken * token;

    token = (GumMatchToken *) g_ptr_array_index (self->tokens, i);
    self->size += token->bytes->len;
  }
}

static GumMatchToken *
gum_match_pattern_get_longest_token (const GumMatchPattern * self,
                                     GumMatchType type)
{
  GumMatchToken * longest = NULL;
  guint i;

  for (i = 0; i != self->tokens->len; i++)
  {
    GumMatchToken * token;

    token = (GumMatchToken *) g_ptr_array_index (self->tokens, i);
    if (token->type == type && (longest == NULL
        || token->bytes->len > longest->bytes->len))
    {
      longest = token;
    }
  }

  return longest;
}

static gboolean
gum_match_pattern_try_match_on (const GumMatchPattern * self,
                                guint8 * bytes)
{
  guint i;
  gboolean no_masks = TRUE;

  for (i = 0; i != self->tokens->len; i++)
  {
    GumMatchToken * token;

    token = (GumMatchToken *) g_ptr_array_index (self->tokens, i);
    if (token->type == GUM_MATCH_EXACT)
    {
      gchar * p;

      p = (gchar *) bytes + token->offset;
      if (p == token->bytes->data ||
          memcmp (p, token->bytes->data, token->bytes->len) != 0)
      {
        return FALSE;
      }
    }
    else if (token->type == GUM_MATCH_MASK)
    {
      no_masks = FALSE;
    }
  }

  if (no_masks)
    return TRUE;

  for (i = 0; i != self->tokens->len; i++)
  {
    GumMatchToken * token;

    token = (GumMatchToken *) g_ptr_array_index (self->tokens, i);
    if (token->type == GUM_MATCH_MASK)
    {
      gchar * p;

      p = (gchar *) bytes + token->offset;
      if (gum_memcmp_mask ((guint8 *) p, (guint8 *) token->bytes->data,
          (guint8 *) token->masks->data, token->masks->len) != 0)
      {
        return FALSE;
      }
    }
  }

  return TRUE;
}

static gint
gum_memcmp_mask (const guint8 * haystack,
                 const guint8 * needle,
                 const guint8 * mask,
                 guint len)
{
  guint i;

  for (i = 0; i != len; i++)
  {
    guint8 value = *(haystack++) & mask[i];
    guint8 test_value = needle[i] & mask[i];
    if (value != test_value)
      return value - test_value;
  }

  return 0;
}

static GumMatchToken *
gum_match_pattern_push_token (GumMatchPattern * self,
                              GumMatchType type)
{
  GumMatchToken * token;

  gum_match_pattern_update_computed_size (self);

  token = gum_match_token_new (type);
  token->offset = self->size;
  g_ptr_array_add (self->tokens, token);

  return token;
}

static gboolean
gum_match_pattern_seal (GumMatchPattern * self)
{
  GumMatchToken * token;

  gum_match_pattern_update_computed_size (self);

  if (self->size == 0)
    return FALSE;

  token = (GumMatchToken *) g_ptr_array_index (self->tokens, 0);
  if (token->type == GUM_MATCH_WILDCARD)
    return FALSE;

  token = (GumMatchToken *) g_ptr_array_index (self->tokens,
      self->tokens->len - 1);
  if (token->type == GUM_MATCH_WILDCARD)
    return FALSE;

  return TRUE;
}

static GumMatchToken *
gum_match_token_new (GumMatchType type)
{
  GumMatchToken * token;

  token = g_slice_new (GumMatchToken);
  token->type = type;
  token->bytes = g_array_new (FALSE, FALSE, sizeof (guint8));
  token->masks = NULL;
  token->offset = 0;

  return token;
}

static void
gum_match_token_free (GumMatchToken * token)
{
  g_array_free (token->bytes, TRUE);
  if (token->masks != NULL)
    g_array_free (token->masks, TRUE);
  g_slice_free (GumMatchToken, token);
}

static void
gum_match_token_append (GumMatchToken * self,
                        guint8 byte)
{
  g_array_append_val (self->bytes, byte);
}

static void
gum_match_token_append_with_mask (GumMatchToken * self,
                                  guint8 byte,
                                  guint8 mask)
{
  g_array_append_val (self->bytes, byte);

  if (self->masks == NULL)
    self->masks = g_array_new (FALSE, FALSE, sizeof (guint8));

  g_array_append_val (self->masks, mask);
}

void
gum_ensure_code_readable (gconstpointer address,
                          gsize size)
{
  /*
   * We will make this more generic once it's needed on other OSes.
   */
#ifdef HAVE_ANDROID
  gsize page_size;
  gconstpointer start_page, end_page, cur_page;

  if (gum_android_get_api_level () < 29)
    return;

  page_size = gum_query_page_size ();
  start_page = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  end_page = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address + size - 1) & ~(page_size - 1)) + page_size;

  G_LOCK (gum_softened_code_pages);

  if (gum_softened_code_pages == NULL)
    gum_softened_code_pages = g_hash_table_new (NULL, NULL);

  for (cur_page = start_page; cur_page != end_page; cur_page += page_size)
  {
    if (!g_hash_table_contains (gum_softened_code_pages, cur_page))
    {
      if (gum_try_mprotect ((gpointer) cur_page, page_size, GUM_PAGE_RWX))
        g_hash_table_add (gum_softened_code_pages, (gpointer) cur_page);
    }
  }

  G_UNLOCK (gum_softened_code_pages);
#endif
}

void
gum_mprotect (gpointer address,
              gsize size,
              GumPageProtection prot)
{
  gboolean success;

  success = gum_try_mprotect (address, size, prot);
  if (!success)
    g_abort ();
}

#ifndef GUM_USE_SYSTEM_ALLOC

guint
gum_peek_private_memory_usage (void)
{
  guint total = 0;
  struct mallinfo info;

  info = mspace_mallinfo (gum_mspace_main);
  total += (guint) info.uordblks;

  info = mspace_mallinfo (gum_mspace_internal);
  total += (guint) info.uordblks;

  return total;
}

gpointer
gum_malloc (gsize size)
{
  return mspace_malloc (gum_mspace_main, size);
}

gpointer
gum_malloc0 (gsize size)
{
  return mspace_calloc (gum_mspace_main, 1, size);
}

gsize
gum_malloc_usable_size (gconstpointer mem)
{
  return mspace_usable_size (mem);
}

gpointer
gum_calloc (gsize count,
            gsize size)
{
  return mspace_calloc (gum_mspace_main, count, size);
}

gpointer
gum_realloc (gpointer mem,
             gsize size)
{
  return mspace_realloc (gum_mspace_main, mem, size);
}

gpointer
gum_memalign (gsize alignment,
              gsize size)
{
  return mspace_memalign (gum_mspace_main, alignment, size);
}

gpointer
gum_memdup (gconstpointer mem,
            gsize byte_size)
{
  gpointer result;

  result = mspace_malloc (gum_mspace_main, byte_size);
  memcpy (result, mem, byte_size);

  return result;
}

void
gum_free (gpointer mem)
{
  mspace_free (gum_mspace_main, mem);
}

gpointer
gum_internal_malloc (size_t size)
{
  return mspace_malloc (gum_mspace_internal, size);
}

gpointer
gum_internal_calloc (size_t count,
                     size_t size)
{
  return mspace_calloc (gum_mspace_internal, count, size);
}

gpointer
gum_internal_realloc (gpointer mem,
                      size_t size)
{
  return mspace_realloc (gum_mspace_internal, mem, size);
}

void
gum_internal_free (gpointer mem)
{
  mspace_free (gum_mspace_internal, mem);
}

#else

guint
gum_peek_private_memory_usage (void)
{
  return 0;
}

gpointer
gum_malloc (gsize size)
{
  return malloc (size);
}

gpointer
gum_malloc0 (gsize size)
{
  return calloc (1, size);
}

gsize
gum_malloc_usable_size (gconstpointer mem)
{
  return 0;
}

gpointer
gum_calloc (gsize count,
            gsize size)
{
  return calloc (count, size);
}

gpointer
gum_realloc (gpointer mem,
             gsize size)
{
  return realloc (mem, size);
}

gpointer
gum_memalign (gsize alignment,
              gsize size)
{
  /* TODO: Implement this. */
  g_assert_not_reached ();

  return NULL;
}

gpointer
gum_memdup (gconstpointer mem,
            gsize byte_size)
{
  gpointer result;

  result = malloc (byte_size);
  memcpy (result, mem, byte_size);

  return result;
}

void
gum_free (gpointer mem)
{
  free (mem);
}

gpointer
gum_internal_malloc (size_t size)
{
  return gum_malloc (size);
}

gpointer
gum_internal_calloc (size_t count,
                     size_t size)
{
  return gum_calloc (count, size);
}

gpointer
gum_internal_realloc (gpointer mem,
                      size_t size)
{
  return gum_realloc (mem, size);
}

void
gum_internal_free (gpointer mem)
{
  gum_free (mem);
}

#endif

gpointer
gum_alloc_n_pages (guint n_pages,
                   GumPageProtection prot)
{
  gpointer result;

  result = gum_try_alloc_n_pages (n_pages, prot);
  g_assert (result != NULL);

  return result;
}

gpointer
gum_alloc_n_pages_near (guint n_pages,
                        GumPageProtection prot,
                        const GumAddressSpec * spec)
{
  gpointer result;

  result = gum_try_alloc_n_pages_near (n_pages, prot, spec);
  g_assert (result != NULL);

  return result;
}

gboolean
gum_address_spec_is_satisfied_by (const GumAddressSpec * spec,
                                  gconstpointer address)
{
  gsize distance;

  distance =
      ABS ((const guint8 *) spec->near_address - (const guint8 *) address);

  return distance <= spec->max_distance;
}

GumMemoryRange *
gum_memory_range_copy (const GumMemoryRange * range)
{
  return g_slice_dup (GumMemoryRange, range);
}

void
gum_memory_range_free (GumMemoryRange * range)
{
  g_slice_free (GumMemoryRange, range);
}
```