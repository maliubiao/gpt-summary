Response:
Let's break down the thought process for analyzing this C code for Frida.

**1. Initial Understanding: Context is Key**

The first step is recognizing the context. The prompt explicitly states: "这是目录为frida/subprojects/frida-gum/gum/backend-posix/gummemory-posix.c的fridaDynamic instrumentation tool的源代码文件". This tells us several crucial things:

* **Frida:** This is related to the Frida dynamic instrumentation toolkit. This immediately brings to mind concepts like hooking, code injection, and memory manipulation.
* **Subprojects/frida-gum/gum/backend-posix:** This specifies a location within the Frida codebase. The "backend-posix" part strongly suggests this code handles memory operations on POSIX-compliant systems (Linux, macOS, Android).
* **gummemory-posix.c:** The filename indicates that this file likely deals with memory management within the "gum" component of Frida, specifically for POSIX systems.

**2. High-Level Code Scan: Identifying Key Functions**

Next, I'd quickly scan the code to identify the main functions. Looking for names that suggest memory operations is a good starting point. I'd notice functions like:

* `gum_memory_allocate`, `gum_memory_allocate_internal`, `gum_memory_allocate_near`
* `gum_try_alloc_n_pages`, `gum_try_alloc_n_pages_near`
* `gum_free_pages`, `gum_memory_free`, `gum_memory_release`
* `gum_memory_recommit`, `gum_memory_discard`, `gum_memory_decommit`
* `gum_query_page_size`, `gum_query_page_allocation_range`
* `gum_mprotect` (though not directly in this file, it's called)
* `gum_enumerate_free_ranges`

These function names strongly suggest the core functionality of this file: managing memory allocation, deallocation, and protection.

**3. Categorizing Functionality:  Relating to the Prompt's Questions**

Now, I'd start mapping the identified functions to the questions in the prompt:

* **功能 (Functions):** This is straightforward. List the purpose of each major function based on its name and what it does (allocate, free, protect, etc.).

* **逆向的方法 (Reverse Engineering Methods):**  Think about how Frida is used in reverse engineering. Code injection and hooking are prominent. Memory allocation is essential for injecting code. Modifying memory permissions (using `gum_mprotect`) is key to making injected code executable. The `gum_memory_allocate_near` function is interesting because it allows allocation close to existing memory, which can be useful for code injection. Mentioning ASLR is relevant here because it's a security mechanism that Frida often needs to bypass.

* **二进制底层, linux, android内核及框架 (Binary Low-Level, Linux, Android Kernel & Framework):** Focus on the underlying system calls and concepts. `mmap`, `munmap`, `mprotect`, `sysconf(_SC_PAGE_SIZE)`, `madvise`, and `posix_madvise` are all direct interactions with the kernel's memory management. Explain what each system call does and how it relates to memory operations. Mentioning the concept of memory pages is important. For Android, highlight that it's a Linux-based system and uses similar memory management principles.

* **逻辑推理 (Logical Reasoning):** Look for conditional logic and how the code behaves under different circumstances. `gum_try_alloc_n_pages_near` attempts allocation and then adjusts permissions. `gum_memory_allocate_near` tries an initial allocation and, if it doesn't meet the "near" criteria, it searches for free ranges. For the example, picking a specific scenario like `gum_memory_allocate_near` failing initially and then succeeding after searching free ranges is a good way to illustrate the logic. Clearly state the assumptions and the expected outcome.

* **用户或者编程常见的使用错误 (Common User/Programming Errors):** Think about how someone using these functions incorrectly could cause problems. Memory leaks (forgetting to `free`), using freed memory (use-after-free), and incorrect size/alignment calculations are classic memory management errors. Explain *why* these errors are problematic.

* **用户操作是如何一步步的到达这里，作为调试线索 (How User Actions Lead Here - Debugging Clues):** Imagine a user employing Frida for a specific purpose. If they're trying to hook a function, Frida will need to allocate memory for the hook code. If they're modifying data, Frida needs to access that memory. Trace the sequence of Frida operations that would eventually call the functions in `gummemory-posix.c`. Emphasize how these functions are fundamental building blocks for Frida's core capabilities.

**4. Structuring the Response**

Organize the information clearly, following the structure of the prompt's questions. Use headings and bullet points for readability. Provide clear and concise explanations. Use examples where appropriate to illustrate concepts.

**5. Refining and Reviewing**

Finally, review the entire response for accuracy, clarity, and completeness. Ensure that the explanations are technically correct and easy to understand. Check for any inconsistencies or missing information.

**Self-Correction Example During the Process:**

Initially, I might focus too much on the individual system calls without explicitly connecting them back to Frida's use cases in reverse engineering. During the review, I'd realize that the "逆向的方法" section needs stronger connections to how these memory operations enable Frida's core functionalities (hooking, code injection). I'd then add explanations about how `gum_memory_allocate` is used to allocate memory for injected code, and how `gum_mprotect` is used to make that code executable. Similarly, I might initially forget to mention ASLR in the reverse engineering context and would add that during the review.
好的，让我们来分析一下 `frida/subprojects/frida-gum/gum/backend-posix/gummemory-posix.c` 这个文件。

**文件功能概述:**

这个文件实现了 Frida Gum 框架在 POSIX 系统（例如 Linux、macOS、Android）上的底层内存管理功能。它提供了一组 API，用于在目标进程中分配、释放、修改内存保护属性（读、写、执行权限）以及执行其他与内存相关的操作。这些操作是 Frida 实现动态 instrumentation 的核心组成部分。

**与逆向方法的关系及举例:**

这个文件直接关系到 Frida 进行逆向工程的关键方法：**代码注入 (Code Injection)** 和 **Hooking (代码拦截/替换)**。

* **代码注入:**
    * **功能体现:** `gum_memory_allocate` 系列函数（例如 `gum_memory_allocate`, `gum_memory_allocate_near`, `gum_try_alloc_n_pages` 等）用于在目标进程的地址空间中分配新的内存区域。
    * **逆向应用举例:**  在逆向过程中，为了执行我们自己的代码，通常需要将这段代码注入到目标进程中。`gum_memory_allocate` 提供了在目标进程中申请内存的能力，我们可以将要注入的 shellcode 或自定义代码复制到这块新分配的内存中。
    * **底层原理:** 这些函数最终会调用 POSIX 系统的 `mmap` 系统调用来分配内存。

* **Hooking (代码拦截/替换):**
    * **功能体现:**
        * `gum_memory_allocate` 也可能被用于分配用于存放 trampoline 代码的内存。Trampoline 代码是 Hooking 机制中用于跳转回原始代码或跳转到我们自定义代码的小段代码。
        * `gum_mprotect` (虽然不是在这个文件中直接实现，但会被此文件中的函数间接调用) 用于修改内存区域的保护属性。在 Hooking 时，可能需要将目标函数的指令所在内存区域设置为可写，以便修改其指令；或者将注入的 shellcode 所在内存设置为可执行。
    * **逆向应用举例:**  假设我们要 Hook 一个函数 `foo`，以便在 `foo` 执行前后执行我们自己的逻辑。Frida 可能使用以下步骤：
        1. 使用 `gum_memory_allocate` 分配一块内存用于存放我们的 Hook 代码和 trampoline 代码。
        2. 将 trampoline 代码写入到分配的内存中。Trampoline 代码会先跳转到我们的 Hook 代码，执行完毕后再跳回 `foo` 函数的原始位置继续执行。
        3. 修改 `foo` 函数的起始几条指令，使其跳转到我们分配的 trampoline 代码的地址。这可能需要先使用 `gum_mprotect` 将 `foo` 所在的内存页设置为可写。
    * **底层原理:** `gum_mprotect` 最终会调用 POSIX 系统的 `mprotect` 系统调用。

**涉及的二进制底层、Linux、Android 内核及框架知识:**

* **二进制底层:**
    * **内存地址:**  代码中大量使用了指针 (`gpointer`) 和地址相关的操作，例如内存对齐 (`GUM_ALIGN_POINTER`)。理解内存地址的概念是理解这段代码的基础。
    * **内存页 (Page):** 代码中多次提到 `page_size`，并且 `gum_try_alloc_n_pages` 函数以页为单位分配内存。这涉及到操作系统内存管理的基本单元——内存页。
    * **内存保护属性:** `GumPageProtection` 枚举和相关的 `_gum_page_protection_to_posix` 函数将 Frida 的内存保护属性映射到 POSIX 系统的 `PROT_READ`, `PROT_WRITE`, `PROT_EXEC` 等标志。

* **Linux 内核:**
    * **系统调用:**  代码中直接或间接地使用了多个 Linux 系统调用，如：
        * `sysconf(_SC_PAGE_SIZE)`: 获取系统的页大小。
        * `mmap`:  用于分配内存区域，可以指定起始地址、大小、保护属性等。`gum_allocate_page_aligned` 函数是对 `mmap` 的封装。
        * `munmap`: 释放通过 `mmap` 分配的内存区域。`gum_memory_free` 函数是对 `munmap` 的封装。
        * `mprotect`: 修改内存区域的保护属性。`gum_try_mprotect` (虽然未在此文件中实现) 是对 `mprotect` 的封装。
        * `madvise` / `posix_madvise`:  向内核提供关于内存使用模式的建议，例如 `MADV_DONTNEED` 用于告知内核可以回收这部分内存。`gum_memory_discard` 函数使用了这些系统调用。
    * **进程地址空间:**  代码操作的是目标进程的地址空间。理解进程地址空间的布局对于理解内存分配和保护至关重要。

* **Android 内核及框架:**
    * Android 基于 Linux 内核，因此这段代码中的大部分概念和系统调用在 Android 上也是适用的。
    * Android 的内存管理机制与 Linux 类似，但可能有一些针对移动设备的优化。
    * Frida 在 Android 上进行 Hooking 和代码注入时，底层的内存操作仍然会涉及到这些系统调用。

**逻辑推理及假设输入与输出:**

**场景:** `gum_memory_allocate_near` 函数尝试在指定地址附近分配内存。

**假设输入:**
* `spec`: 一个 `GumAddressSpec` 结构体，指定了期望分配的地址范围，例如 `near_address = 0x70000000`, `max_distance = 0x1000`.
* `size`: 要分配的内存大小，例如 `0x1000`.
* `alignment`: 内存对齐要求，例如 `0x10`.
* `prot`: 内存保护属性，例如 `GUM_PAGE_READ | GUM_PAGE_WRITE`.

**逻辑推理:**

1. `gum_memory_allocate_near` 首先尝试在 `spec->near_address` 处直接分配内存。
2. 如果分配失败（例如，该地址已被占用），它会遍历目标进程的内存映射，寻找空闲的内存区域 (`gum_enumerate_free_ranges`)。
3. 对于每个空闲区域，`gum_try_alloc_in_range_if_near_enough` 会被调用。
4. `gum_try_suggest_allocation_base` 函数会尝试在当前空闲区域内找到一个满足 `spec` 指定的地址范围和对齐要求的起始地址。它会尝试在空闲区域的开头和结尾附近寻找合适的地址。
5. 如果找到合适的起始地址，`gum_memory_allocate_internal` 会被调用，尝试在该地址分配内存。
6. 如果分配成功且满足 `spec` 的要求，则返回分配的地址。

**可能输出:**

* **成功:** 返回一个指向已分配内存的指针，该指针位于 `0x70000000 - 0x1000` 到 `0x70000000 + 0x1000` 的范围内，并且满足对齐要求。
* **失败:** 如果没有找到合适的空闲区域或分配失败，返回 `NULL`.

**用户或编程常见的使用错误及举例:**

* **内存泄漏:**  分配了内存但忘记使用 `gum_memory_free` 或 `gum_free_pages` 释放。
    * **例子:** 用户调用 `gum_memory_allocate` 分配了一块内存用于存放 Hook 代码，但在 Hook 卸载时忘记释放这块内存，导致内存占用持续增加。
* **使用已释放的内存 (Use-After-Free):**  释放了内存后继续使用指向该内存的指针。
    * **例子:**  用户释放了一块用于存放 Hook 代码的内存，但仍然尝试执行该内存中的代码，导致程序崩溃。
* **内存访问越界:**  读写了分配内存区域之外的地址。
    * **例子:** 用户通过 `gum_memory_allocate` 分配了 100 字节的内存，但尝试写入第 150 字节，可能导致覆盖其他数据或程序崩溃。
* **错误的内存保护属性设置:**  例如，尝试执行没有执行权限的内存区域的代码，或者尝试写入只读内存区域。
    * **例子:** 用户分配了一块内存用于存放要注入的代码，但忘记使用 `gum_mprotect` 设置执行权限，导致注入的代码无法执行。
* **不正确的地址或大小计算:**  在调用内存操作函数时，传递了错误的地址或大小参数。
    * **例子:** 在调用 `gum_memory_free` 时，传递的地址不是通过 `gum_memory_allocate` 返回的原始地址，或者传递的大小与实际分配的大小不符，可能导致内存管理混乱。

**用户操作如何一步步到达这里作为调试线索:**

当用户使用 Frida 进行动态 instrumentation 时，许多操作最终会涉及到这个文件中的函数。以下是一些典型的场景：

1. **用户编写 JavaScript 代码，使用 Frida 的 API 进行 Hooking:**
   * 用户调用 `Interceptor.attach(address, { onEnter: ..., onLeave: ... })` 或 `Interceptor.replace(address, replacement)` 等 API。
   * Frida 的 JavaScript 引擎会将这些高级 API 调用转换为底层的 Gum API 调用。
   * 为了实现 Hook，Frida 需要在目标进程中分配内存来存放 Hook 代码 (例如 trampoline 代码)，这会调用 `gum_memory_allocate`。
   * 如果需要在目标函数入口处修改指令以进行跳转，Frida 可能会调用 `gum_mprotect` (通过其他 Gum 模块) 来修改内存保护属性。

2. **用户编写 JavaScript 代码，使用 `Memory.alloc(size)` 或 `Memory.allocUtf8String(str)` 等 API 在目标进程中分配内存:**
   * 这些 API 会直接或间接地调用 `gum_memory_allocate` 或其变体。
   * 例如，用户可能想在目标进程中创建一个新的字符串或数据缓冲区。

3. **用户编写 JavaScript 代码，使用 `Memory.protect(address, size, protection)` API 修改内存保护属性:**
   * 虽然 `gum_mprotect` 不在这个文件中，但用户通过 JavaScript API 调用修改内存保护属性最终会触发对底层系统调用 `mprotect` 的调用。Frida 的其他模块会处理这个调用。

4. **Frida 自身进行内部操作，例如加载 Gadget 或其他组件:**
   * Frida 运行时需要管理自身的内存，也可能会使用这些内存管理函数。

**调试线索:**

如果在 Frida 的使用过程中遇到与内存相关的错误（例如，程序崩溃、内存泄漏），并且怀疑是 Frida 自身的问题，可以按照以下步骤进行调试：

1. **查看 Frida 的日志输出:** Frida 可能会输出一些与内存操作相关的调试信息。
2. **使用 Frida 的调试模式或 GDB 等工具:** 可以逐步跟踪 Frida 的代码执行，观察内存分配和释放的情况。
3. **分析目标进程的内存映射:** 使用 `maps` 文件或 `pmap` 命令查看目标进程的内存布局，确认是否有异常的内存分配或释放。
4. **检查 Frida 的源代码:**  如果问题较为复杂，可能需要深入到 Frida 的 C++ 或 C 源代码中进行分析，理解内存操作的细节。

总而言之，`gummemory-posix.c` 是 Frida 在 POSIX 系统上进行动态 instrumentation 的基石，它提供的内存管理功能支撑了 Frida 的核心能力，理解这个文件的功能对于深入理解 Frida 的工作原理至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-posix/gummemory-posix.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2008-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gummemory-priv.h"
#include "gumprocess-priv.h"

#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>

typedef struct _GumAllocNearContext GumAllocNearContext;
typedef struct _GumEnumerateFreeRangesContext GumEnumerateFreeRangesContext;

struct _GumAllocNearContext
{
  const GumAddressSpec * spec;
  gsize size;
  gsize alignment;
  gsize page_size;
  GumPageProtection prot;

  gpointer result;
};

struct _GumEnumerateFreeRangesContext
{
  GumFoundRangeFunc func;
  gpointer user_data;
  GumAddress prev_end;
};

static gpointer gum_memory_allocate_internal (gpointer address, gsize size,
    gsize alignment, GumPageProtection prot, gint extra_flags);
static gboolean gum_try_alloc_in_range_if_near_enough (
    const GumRangeDetails * details, gpointer user_data);
static gboolean gum_try_suggest_allocation_base (const GumMemoryRange * range,
    const GumAllocNearContext * ctx, gpointer * allocation_base);
static gpointer gum_allocate_page_aligned (gpointer address, gsize size,
    gint prot, gint extra_flags);
static void gum_enumerate_free_ranges (GumFoundRangeFunc func,
    gpointer user_data);
static gboolean gum_emit_free_range (const GumRangeDetails * details,
    gpointer user_data);

void
_gum_memory_backend_init (void)
{
}

void
_gum_memory_backend_deinit (void)
{
}

guint
_gum_memory_backend_query_page_size (void)
{
  return sysconf (_SC_PAGE_SIZE);
}

gpointer
gum_try_alloc_n_pages (guint n_pages,
                       GumPageProtection prot)
{
  return gum_try_alloc_n_pages_near (n_pages, prot, NULL);
}

gpointer
gum_try_alloc_n_pages_near (guint n_pages,
                            GumPageProtection prot,
                            const GumAddressSpec * spec)
{
  guint8 * base;
  gsize page_size, size;

  page_size = gum_query_page_size ();
  size = (1 + n_pages) * page_size;

  base = gum_memory_allocate_near (spec, size, page_size, prot);
  if (base == NULL)
    return NULL;

  if ((prot & GUM_PAGE_WRITE) == 0)
    gum_mprotect (base, page_size, GUM_PAGE_RW);

  *((gsize *) base) = size;

  gum_mprotect (base, page_size, GUM_PAGE_READ);

  return base + page_size;
}

void
gum_query_page_allocation_range (gconstpointer mem,
                                 guint size,
                                 GumMemoryRange * range)
{
  gsize page_size = gum_query_page_size ();

  range->base_address = GUM_ADDRESS (mem - page_size);
  range->size = size + page_size;
}

void
gum_free_pages (gpointer mem)
{
  guint8 * start;
  gsize size;

  start = mem - gum_query_page_size ();
  size = *((gsize *) start);

  gum_memory_release (start, size);
}

gpointer
gum_memory_allocate (gpointer address,
                     gsize size,
                     gsize alignment,
                     GumPageProtection prot)
{
  return gum_memory_allocate_internal (address, size, alignment, prot, 0);
}

static gpointer
gum_memory_allocate_internal (gpointer address,
                              gsize size,
                              gsize alignment,
                              GumPageProtection prot,
                              gint extra_flags)
{
  gsize page_size, allocation_size;
  guint8 * base, * aligned_base;

  address = GUM_ALIGN_POINTER (gpointer, address, alignment);

  page_size = gum_query_page_size ();
  allocation_size = size + (alignment - page_size);
  allocation_size = GUM_ALIGN_SIZE (allocation_size, page_size);

  base = gum_allocate_page_aligned (address, allocation_size,
      _gum_page_protection_to_posix (prot), extra_flags);
  if (base == NULL)
    return NULL;

  aligned_base = GUM_ALIGN_POINTER (guint8 *, base, alignment);

  if (aligned_base != base)
  {
    gsize prefix_size = aligned_base - base;
    gum_memory_free (base, prefix_size);
    allocation_size -= prefix_size;
  }

  if (allocation_size != size)
  {
    gsize suffix_size = allocation_size - size;
    gum_memory_free (aligned_base + size, suffix_size);
    allocation_size -= suffix_size;
  }

  g_assert (allocation_size == size);

  return aligned_base;
}

gpointer
gum_memory_allocate_near (const GumAddressSpec * spec,
                          gsize size,
                          gsize alignment,
                          GumPageProtection prot)
{
  gpointer suggested_base, received_base;
  GumAllocNearContext ctx;

  suggested_base = (spec != NULL) ? spec->near_address : NULL;

  received_base = gum_memory_allocate (suggested_base, size, alignment, prot);
  if (received_base == NULL)
    return NULL;
  if (spec == NULL || gum_address_spec_is_satisfied_by (spec, received_base))
    return received_base;
  gum_memory_free (received_base, size);

  ctx.spec = spec;
  ctx.size = size;
  ctx.alignment = alignment;
  ctx.page_size = gum_query_page_size ();
  ctx.prot = prot;
  ctx.result = NULL;

  gum_enumerate_free_ranges (gum_try_alloc_in_range_if_near_enough, &ctx);

  return ctx.result;
}

static gboolean
gum_try_alloc_in_range_if_near_enough (const GumRangeDetails * details,
                                       gpointer user_data)
{
  GumAllocNearContext * ctx = user_data;
  gpointer suggested_base, received_base;

  if (!gum_try_suggest_allocation_base (details->range, ctx, &suggested_base))
    goto keep_looking;

#ifdef HAVE_FREEBSD
  received_base = gum_memory_allocate_internal (suggested_base, ctx->size,
      ctx->alignment, ctx->prot, MAP_FIXED | MAP_EXCL);
  if (received_base != NULL)
  {
    ctx->result = received_base;
    return FALSE;
  }
#endif

  received_base = gum_memory_allocate (suggested_base, ctx->size,
      ctx->alignment, ctx->prot);
  if (received_base == NULL)
    goto keep_looking;

  if (!gum_address_spec_is_satisfied_by (ctx->spec, received_base))
  {
    gum_memory_free (received_base, ctx->size);
    goto keep_looking;
  }

  ctx->result = received_base;
  return FALSE;

keep_looking:
  return TRUE;
}

static gboolean
gum_try_suggest_allocation_base (const GumMemoryRange * range,
                                 const GumAllocNearContext * ctx,
                                 gpointer * allocation_base)
{
  const gsize allocation_size = ctx->size + (ctx->alignment - ctx->page_size);
  gpointer base;
  gsize mask;

  if (range->size < allocation_size)
    return FALSE;

  mask = ~(ctx->alignment - 1);

  base = GSIZE_TO_POINTER ((range->base_address + ctx->alignment - 1) & mask);
  if (!gum_address_spec_is_satisfied_by (ctx->spec, base))
  {
    base = GSIZE_TO_POINTER ((range->base_address + range->size -
        allocation_size) & mask);
    if (!gum_address_spec_is_satisfied_by (ctx->spec, base))
      return FALSE;
  }

  *allocation_base = base;
  return TRUE;
}

static gpointer
gum_allocate_page_aligned (gpointer address,
                           gsize size,
                           gint prot,
                           gint extra_flags)
{
  gpointer result;
  const gint base_flags = MAP_PRIVATE | MAP_ANONYMOUS | extra_flags;
  gint region_flags = 0;

#if defined (HAVE_FREEBSD) && GLIB_SIZEOF_VOID_P == 8
  if (address != NULL &&
      GPOINTER_TO_SIZE (address) + size < G_MAXUINT32)
  {
    region_flags |= MAP_32BIT;
  }
#endif

  result = mmap (address, size, prot, base_flags | region_flags, -1, 0);

#if defined (HAVE_FREEBSD) && GLIB_SIZEOF_VOID_P == 8
  if (result == MAP_FAILED && (region_flags & MAP_32BIT) != 0)
  {
    result = mmap (NULL, size, prot, base_flags | region_flags, -1, 0);
    if (result == MAP_FAILED)
      result = mmap (address, size, prot, base_flags, -1, 0);
  }
#endif

  return (result != MAP_FAILED) ? result : NULL;
}

gboolean
gum_memory_free (gpointer address,
                 gsize size)
{
  return munmap (address, size) == 0;
}

gboolean
gum_memory_release (gpointer address,
                    gsize size)
{
  return gum_memory_free (address, size);
}

gboolean
gum_memory_recommit (gpointer address,
                     gsize size,
                     GumPageProtection prot)
{
  gboolean success;

  success = gum_try_mprotect (address, size, prot);

  if (success && prot == GUM_PAGE_NO_ACCESS)
    gum_memory_discard (address, size);

  return TRUE;
}

gboolean
gum_memory_discard (gpointer address,
                    gsize size)
{
#if defined (HAVE_MADVISE)
  return madvise (address, size, MADV_DONTNEED) == 0;
#elif defined (HAVE_POSIX_MADVISE)
  int advice;

# ifdef POSIX_MADV_DISCARD_NP
  advice = POSIX_MADV_DISCARD_NP;
# else
  advice = POSIX_MADV_DONTNEED;
# endif

  return posix_madvise (address, size, advice) == 0;
#else
# error FIXME
#endif
}

gboolean
gum_memory_decommit (gpointer address,
                     gsize size)
{
  return mmap (address, size, PROT_NONE,
      MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == address;
}

static void
gum_enumerate_free_ranges (GumFoundRangeFunc func,
                           gpointer user_data)
{
  GumEnumerateFreeRangesContext ctx = { func, user_data, 0 };

  _gum_process_enumerate_ranges (GUM_PAGE_NO_ACCESS, gum_emit_free_range, &ctx);
}

static gboolean
gum_emit_free_range (const GumRangeDetails * details,
                     gpointer user_data)
{
  GumEnumerateFreeRangesContext * ctx =
      (GumEnumerateFreeRangesContext *) user_data;
  const GumMemoryRange * range = details->range;
  GumAddress start = range->base_address;
  GumAddress end = start + range->size;
  gboolean carry_on = TRUE;

  if (ctx->prev_end != 0)
  {
    GumAddress gap_size;

    gap_size = start - ctx->prev_end;

    if (gap_size > 0)
    {
      GumRangeDetails d;
      GumMemoryRange r;

      d.range = &r;
      d.protection = GUM_PAGE_NO_ACCESS;
      d.file = NULL;

      r.base_address = ctx->prev_end;
      r.size = gap_size;

      carry_on = ctx->func (&d, ctx->user_data);
    }
  }

  ctx->prev_end = end;

  return carry_on;
}

gint
_gum_page_protection_to_posix (GumPageProtection prot)
{
  gint posix_prot = PROT_NONE;

  if ((prot & GUM_PAGE_READ) != 0)
    posix_prot |= PROT_READ;
  if ((prot & GUM_PAGE_WRITE) != 0)
    posix_prot |= PROT_WRITE;
  if ((prot & GUM_PAGE_EXECUTE) != 0)
    posix_prot |= PROT_EXEC;

  return posix_prot;
}


"""

```