Response:
Let's break down the thought process for analyzing the `gumcloak.c` file. The goal is to understand its functionality, its relation to reverse engineering, its interaction with low-level concepts, logical reasoning within the code, potential user errors, and how a user might reach this code.

**1. Initial Understanding of the Purpose (Reading the Doc Comments):**

The first and most crucial step is to read the high-level documentation at the beginning of the file. This immediately tells us the core purpose: "Keeps you from seeing yourself during process introspection."  The analogy of a cloak is very helpful. The documentation highlights that APIs like `Gum.process_enumerate_threads` will skip cloaked resources. This immediately flags the relevance to reverse engineering, where introspection is a key technique.

**2. Identifying Key Data Structures:**

Next, I scan the code for the main data structures used for cloaking. The `GumCloak` struct itself is a placeholder, but the important parts are:

* `cloaked_threads`: A `GumMetalArray` storing `GumThreadId`s. This suggests the ability to hide threads.
* `cloaked_ranges`: A `GumMetalArray` storing `GumCloakedRange` structs. This indicates the ability to hide memory regions. The `GumCloakedRange` structure itself holds `start` and `end` pointers, confirming the memory region aspect.
* `cloaked_fds`: A `GumMetalArray` storing `gint` (file descriptors). This indicates the ability to hide file descriptors.
* `cloak_lock`: A `GumSpinlock`. This signifies the presence of concurrent access and the need for thread safety.

**3. Analyzing Key Functions (Categorizing by Resource Type):**

I then go through the functions, grouping them by the resource they manage (threads, memory ranges, file descriptors):

* **Threads:** `gum_cloak_add_thread`, `gum_cloak_remove_thread`, `gum_cloak_has_thread`, `gum_cloak_enumerate_threads`. The naming is quite descriptive, making it easy to understand their purpose. The use of `bsearch` in `gum_cloak_index_of_thread` suggests efficient searching within a sorted array.
* **Memory Ranges:** `gum_cloak_add_range`, `gum_cloak_remove_range`, `gum_cloak_has_range_containing`, `gum_cloak_clip_range`, `gum_cloak_enumerate_ranges`. `gum_cloak_clip_range` is particularly interesting, hinting at the ability to determine *visible* parts of a range, crucial for accurate introspection. The logic within `gum_cloak_remove_range` is more complex, involving splitting and re-adding ranges, indicating a sophisticated approach to managing overlapping removals.
* **File Descriptors:** `gum_cloak_add_file_descriptor`, `gum_cloak_remove_file_descriptor`, `gum_cloak_has_file_descriptor`, `gum_cloak_enumerate_file_descriptors`. These are similar in structure to the thread management functions.
* **General/Utility:** `_gum_cloak_init`, `_gum_cloak_deinit`, `gum_cloak_with_lock_held`, `gum_cloak_is_locked`. These handle initialization, cleanup, and locking.

**4. Connecting to Reverse Engineering:**

With the functions identified, I consider how they relate to reverse engineering. The core connection is the manipulation of introspection APIs. Frida is used for dynamic instrumentation, and hiding Frida's presence is a common goal. I brainstorm examples of how an attacker/instrumenter would use this: hiding their own threads, memory allocations, and open files to avoid detection by anti-instrumentation techniques.

**5. Considering Low-Level Details:**

The code uses concepts like:

* **Thread IDs:** Operating system-level identifiers.
* **Memory Ranges:**  Base addresses and sizes, fundamental to memory management.
* **File Descriptors:**  Low-level handles to open files or other resources.
* **Spinlocks:**  A low-level synchronization primitive used in multithreaded environments.
* **`mmap` (implicitly):** While not explicitly called here, the concept of memory ranges is closely tied to `mmap` and other memory allocation mechanisms.
* **System Calls (implicitly):** Enumerating threads, memory ranges, and file descriptors often involves system calls.

I try to connect these to Linux and Android kernel/framework concepts, as the prompt requests.

**6. Logical Reasoning and Hypothetical Inputs/Outputs:**

For functions with clear logic, I create simple hypothetical scenarios:

* **`gum_cloak_has_thread`:** Input: a thread ID. Output: `true` if added, `false` otherwise.
* **`gum_cloak_clip_range`:**  Think of overlapping ranges. Input: a memory range and cloaked ranges. Output: the visible parts of the input range. This requires visualizing how the clipping would work.

**7. Identifying Potential User Errors:**

I consider how a developer using this API might make mistakes:

* **Forgetting to uncloak:** This could lead to unexpected behavior where resources become permanently invisible.
* **Incorrect range specification:**  Providing wrong start/end addresses could lead to unintended cloaking or clipping.
* **Race conditions (though less likely due to the spinlock):**  Improper synchronization when interacting with the cloak outside of the provided API could still be an issue.

**8. Tracing User Operations:**

I think about the steps a user would take to use this functionality. They would first initialize Gum, then potentially add cloaking for their own resources before performing any instrumentation that might trigger introspection. Debugging scenarios where someone might be investigating why a thread or memory region isn't showing up in Frida would lead them to this code.

**9. Refinement and Organization:**

Finally, I organize the information into the requested categories, ensuring clarity and providing specific code examples where possible. I reread the prompt to make sure all aspects have been addressed. I also try to use the vocabulary from the code (e.g., "cloak," "uncloak," "introspection").

This systematic approach of reading documentation, identifying core components, analyzing functions, connecting to the problem domain, considering low-level details, reasoning through the logic, anticipating errors, and tracing user flow allows for a comprehensive understanding of the `gumcloak.c` file.
好的，让我们来详细分析一下 `gumcloak.c` 这个文件，它在 Frida 的动态 instrumentation 框架中扮演着重要的角色。

**主要功能：阻止自身在进程内省期间被看到**

`gumcloak.c` 的核心功能是实现一种 "隐身" 机制。当 Frida 注入到一个目标进程并进行动态 instrumentation 时，它自身也会作为进程的一部分存在，拥有自己的线程、内存区域、文件描述符等资源。  然而，在某些场景下，我们希望 Frida 的存在对于目标进程的自省 API（例如，枚举线程、内存映射等）是不可见的。`gumcloak.c` 正是为了实现这个目标。

**功能分解：**

1. **管理被 "cloak" 的资源注册表:**
   - 它维护了三个主要的注册表，用于记录需要隐藏的线程 ID、内存范围和文件描述符。
   - 这些注册表使用 `GumMetalArray` 数据结构进行存储，这是一个专门为 Gum 设计的动态数组，优化了性能。
   - `cloaked_threads`: 存储需要隐藏的线程 ID (`GumThreadId`)。
   - `cloaked_ranges`: 存储需要隐藏的内存范围 (`GumCloakedRange`)，每个范围包含起始地址和结束地址。
   - `cloaked_fds`: 存储需要隐藏的文件描述符 (`gint`)。

2. **添加和移除被 "cloak" 的资源:**
   - 提供了 `gum_cloak_add_thread`, `gum_cloak_remove_thread`, `gum_cloak_add_range`, `gum_cloak_remove_range`, `gum_cloak_add_file_descriptor`, `gum_cloak_remove_file_descriptor` 等函数，允许用户将特定的线程、内存范围或文件描述符添加到或从隐藏列表中移除。

3. **检查资源是否被 "cloak":**
   - 提供了 `gum_cloak_has_thread`, `gum_cloak_has_range_containing`, `gum_cloak_has_file_descriptor` 等函数，用于检查给定的线程 ID、地址或文件描述符是否已被标记为隐藏。

4. **枚举被 "cloak" 的资源:**
   - 提供了 `gum_cloak_enumerate_threads`, `gum_cloak_enumerate_ranges`, `gum_cloak_enumerate_file_descriptors` 等函数，用于遍历当前所有被标记为隐藏的资源。需要注意的是，这些枚举函数的使用需要特别小心，避免在回调函数中调用可能触发 cloak 机制的 API。

5. **裁剪内存范围 (`gum_cloak_clip_range`):**
   - 这是一个更复杂的功能，用于确定给定的内存范围中有哪些部分是可见的。它会根据已注册的被 "cloak" 的内存范围，将输入的范围裁剪成多个不重叠的可见部分。如果整个范围都被 "cloak"，则返回一个空数组，如果完全可见，则返回 `NULL`。

6. **线程安全:**
   - 使用 `GumSpinlock` (`cloak_lock`) 来保护对 cloak 注册表的并发访问，确保在多线程环境下的数据一致性。

**与逆向方法的关联及举例说明：**

`gumcloak.c` 与逆向工程密切相关，因为它允许 instrumentation 代码隐藏自身的存在，这对于更隐蔽的分析或绕过某些安全机制至关重要。

**举例说明：**

假设你正在逆向一个应用程序，并使用 Frida 来 hook 某些关键函数。你不希望你的 Frida 脚本的线程出现在目标应用程序的线程列表中，以免引起怀疑或触发反调试措施。

1. **获取当前 Frida 脚本的线程 ID:**
   ```c
   GumThreadId current_thread_id = gum_process_get_current_thread_id();
   ```

2. **将该线程 ID 添加到 cloak 列表:**
   ```c
   gum_cloak_add_thread(current_thread_id);
   ```

现在，当目标应用程序调用类似 `pthread_enumerate()`（Linux）或使用 `/proc/[pid]/task`（Linux）来枚举线程时，Frida 脚本的线程将被排除在外，看起来就像没有额外的线程在运行。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明：**

1. **二进制底层：**
   - **内存地址和范围：** `gum_cloak_add_range` 和相关函数直接操作内存地址和大小，这涉及到对进程内存布局的理解。例如，需要知道堆、栈、代码段等区域的地址范围。
   - **文件描述符：** `gum_cloak_add_file_descriptor` 操作的是文件描述符，这是操作系统用于访问文件和其他 I/O 资源的整数句柄。理解文件描述符的生命周期和作用域对于正确使用此功能至关重要。

2. **Linux 内核：**
   - **线程 ID：** `GumThreadId` 抽象了操作系统提供的线程标识符（例如，Linux 中的 `pthread_t`）。 `gum_process_get_current_thread_id()` 内部会调用特定于操作系统的 API 来获取当前线程的 ID。
   - **进程内省 API：**  `gumcloak.c` 的目的是影响诸如 `/proc/[pid]/task`（用于列出线程）、`/proc/[pid]/maps`（用于列出内存映射）等 Linux 内核提供的进程自省机制的结果。
   - **`bsearch` 函数：** 在 `gum_cloak_index_of_thread` 和 `gum_cloak_index_of_fd` 中使用了 `bsearch` 函数，这是一个标准的 C 库函数，用于在已排序的数组中执行二分查找。这暗示了 cloak 列表是维护有序的，以提高查找效率。

3. **Android 内核和框架：**
   - Android 系统也基于 Linux 内核，因此很多概念是相同的。
   - **线程管理：** Android 上的线程管理基于 Linux 的 `pthread` 库或 Java 层的 `java.lang.Thread`。Frida 需要能够识别和操作这些线程。
   - **内存管理：** Android 的内存管理涉及 Dalvik/ART 虚拟机（对于 Java 代码）和底层的 Native 堆。 `gumcloak.c` 需要能够处理这些不同类型的内存区域。
   - **文件描述符：** Android 应用程序通常会打开文件、网络连接等，这些都会对应文件描述符。隐藏这些文件描述符可以防止检测到某些操作。

**逻辑推理、假设输入与输出：**

**示例：`gum_cloak_has_thread`**

- **假设输入:** 一个 `GumThreadId` 类型的变量 `target_thread_id`，其值为 `12345`。
- **假设条件:**
    - cloak 列表中已存在线程 ID `12345`。
- **逻辑推理:** `gum_cloak_has_thread(target_thread_id)` 函数会获取 cloak 锁，然后在 `cloaked_threads` 数组中搜索 `12345`。由于假设列表中存在该 ID，`gum_cloak_index_of_thread` 将返回一个非负的索引。
- **输出:** `gum_cloak_has_thread` 函数将返回 `TRUE`。

- **假设输入:**  相同的 `target_thread_id`，值为 `12345`。
- **假设条件:**
    - cloak 列表中不存在线程 ID `12345`。
- **逻辑推理:**  搜索将失败，`gum_cloak_index_of_thread` 将返回 `-1`。
- **输出:** `gum_cloak_has_thread` 函数将返回 `FALSE`。

**示例：`gum_cloak_clip_range`**

- **假设输入:**
    - `range`: 一个 `GumMemoryRange` 结构体，表示要检查的内存范围，例如 `base_address = 0x1000`, `size = 0x1000` (即范围是 `0x1000` 到 `0x1FFF`)。
    - `cloaked_ranges` 中存在一个被 "cloak" 的范围： `start = 0x1400`, `end = 0x1800`。
- **逻辑推理:** `gum_cloak_clip_range` 会比较输入范围与被 "cloak" 的范围。重叠部分是 `0x1400` 到 `0x17FF`。
- **输出:** `gum_cloak_clip_range` 将返回一个 `GArray`，其中包含两个 `GumMemoryRange` 结构体，表示可见的部分：
    - `base_address = 0x1000`, `size = 0x400` (对应 `0x1000` 到 `0x13FF`)
    - `base_address = 0x1800`, `size = 0x800` (对应 `0x1800` 到 `0x1FFF`)

**涉及用户或编程常见的使用错误及举例说明：**

1. **忘记移除 "cloak"：**
   - **错误示例:** 用户在执行某些操作后，忘记调用 `gum_cloak_remove_thread` 或其他移除函数。
   - **后果:**  Frida 注入的线程或内存区域将一直处于隐藏状态，即使不再需要隐藏。这可能导致后续的分析或操作出现意外，因为这些资源对于其他 Frida 功能或外部工具将不可见。

2. **错误地指定内存范围：**
   - **错误示例:** 用户在调用 `gum_cloak_add_range` 时，提供的 `GumMemoryRange` 结构体中的 `base_address` 或 `size` 不正确。
   - **后果:** 可能导致隐藏了错误的内存区域，或者没有隐藏预期的内存区域。更严重的情况下，如果指定的范围与目标进程的关键内存区域重叠，可能会导致程序崩溃或不稳定。

3. **在不应该使用 cloak API 的地方使用：**
   - **错误示例:**  在 `gum_cloak_enumerate_threads` 的回调函数中，再次调用了可能触发 cloak 机制的 API，例如 `gum_process_enumerate_threads`。
   - **后果:** 这可能导致无限循环或栈溢出，因为 cloak 机制可能会被递归触发。文档中明确指出需要特别小心。

4. **线程安全问题（尽管有 spinlock）：**
   - **错误示例:** 在没有获取 cloak 锁的情况下，直接访问或修改 `cloaked_threads`, `cloaked_ranges`, `cloaked_fds` 等数据结构。
   - **后果:**  尽管 `gumcloak.c` 内部使用了 spinlock，但如果用户在自己的代码中直接操作这些数据结构，仍然可能发生竞争条件，导致数据损坏或程序崩溃。正确的使用方式是通过提供的 API 函数进行操作。

**用户操作是如何一步步的到达这里，作为调试线索：**

假设用户在使用 Frida 脚本时遇到了以下问题：他们启动了一个目标应用程序，并使用 `Process.enumerateThreads()` 尝试列出目标进程中的所有线程，但发现 Frida 脚本自身创建的线程并没有出现在列表中。

1. **用户编写 Frida 脚本：** 用户编写了一个 Frida 脚本，其中使用了 `Process.enumerateThreads()` 来获取线程列表。

2. **Frida 注入目标进程：** 用户使用 Frida CLI 或 API 将脚本注入到目标应用程序的进程中。

3. **脚本执行，调用 `Process.enumerateThreads()`：**  脚本开始执行，当执行到 `Process.enumerateThreads()` 时，Frida 的 Gum 库会调用相应的内部实现。

4. **Gum 的线程枚举实现：**  在 Gum 的内部实现中，为了实现进程内省，可能会调用操作系统提供的 API 来获取线程信息（例如，Linux 上的 `getdents` 读取 `/proc/[pid]/task` 目录）。

5. **`gumcloak.c` 的介入：**  在 Gum 获取到线程列表后，会检查每个线程的 ID 是否在 `gumcloak.c` 的 `cloaked_threads` 注册表中。如果发现某个线程的 ID 在列表中，那么这个线程将被从结果中排除。

6. **用户发现问题并开始调试：** 用户发现自己的 Frida 脚本线程没有出现在列表中，感到困惑，开始查看 Frida 的文档或源代码。

7. **查看 `gumcloak.c` 的文档和代码：**  用户可能会搜索 "Frida hide thread" 或类似的关键词，从而找到 `gumcloak.c` 文件的相关信息。阅读文件开头的注释和函数文档，用户会了解到 `gumcloak.c` 的作用是隐藏 Frida 自身在目标进程中的存在。

8. **检查自己的代码或 Frida 的初始化过程：** 用户会检查自己的脚本是否显式地调用了 `gum_cloak_add_thread`，或者是否使用了某些 Frida 功能，这些功能在内部会自动将某些资源添加到 cloak 列表中（例如，使用 `Gum.init_embedded` 初始化 Gum 时，libffi 和 GLib 的资源会被自动 cloak）。

通过以上步骤，用户可以追踪问题的根源，理解 `gumcloak.c` 的工作原理，并最终解决问题，例如，如果他们不希望隐藏自己的线程，可以确保没有调用相关的 cloak 函数。

总而言之，`gumcloak.c` 是 Frida 中一个非常重要的组成部分，它提供了控制 Frida 自身可见性的能力，这对于实现更高级和隐蔽的动态 instrumentation 技术至关重要。理解其功能和使用方式对于 Frida 的高级用户来说是必不可少的。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/gumcloak.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2017-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2024 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

/**
 * GumCloak:
 *
 * Keeps you from seeing yourself during process introspection.
 *
 * Introspection APIs such as [func@Gum.process_enumerate_threads] ensure that
 * cloaked resources are skipped, and things appear as if you were not inside
 * the process being instrumented.
 *
 * If you use [func@Gum.init_embedded] to initialize Gum, any resources created
 * by libffi and GLib will be cloaked automatically. (Assuming that Gum was
 * built with Frida's versions of these two libraries.)
 *
 * This means you typically only need to manage cloaked resources if you use a
 * non-GLib API to create a given resource.
 *
 * Gum's memory allocation APIs, such as [func@Gum.malloc], are automatically
 * cloaked regardless of how Gum was initialized. These use an internal heap
 * implementation that is cloak-aware. The same implementation is also used by
 * GLib when Gum is initialized as described above.
 *
 * ## Using `GumCloak`
 *
 * ```c
 * // If the current thread wasn't created by GLib, do the following two steps:
 *
 * // (1): Ignore the thread ID
 * gum_cloak_add_thread (gum_process_get_current_thread_id ());
 *
 * // (2): Ignore the thread's memory ranges (stack space)
 * GumMemoryRange ranges[2];
 * guint n = gum_thread_try_get_ranges (&ranges, G_N_ELEMENTS (ranges));
 * for (guint i = 0; i != n; i++)
 *   gum_cloak_add_range (&ranges[i]);
 *
 * // If you create a file-descriptor with a non-GLib API, also do:
 * gum_cloak_add_file_descriptor (logfile_fd);
 * ```
 */

#include "gumcloak.h"

#include "gumlibc.h"
#include "gummetalarray.h"
#include "gumspinlock.h"

#include <stdlib.h>
#include <string.h>

typedef struct _GumCloakedRange GumCloakedRange;

struct _GumCloak
{
  guint8 dummy;
};

struct _GumCloakedRange
{
  const guint8 * start;
  const guint8 * end;
};

static gint gum_cloak_index_of_thread (GumThreadId id);
static gint gum_thread_id_compare (gconstpointer element_a,
    gconstpointer element_b);
static gint gum_cloak_index_of_fd (gint fd);
static gint gum_fd_compare (gconstpointer element_a, gconstpointer element_b);

static void gum_cloak_add_range_unlocked (const GumMemoryRange * range);
static void gum_cloak_remove_range_unlocked (const GumMemoryRange * range);

static GumSpinlock cloak_lock = GUM_SPINLOCK_INIT;
static GumMetalArray cloaked_threads;
static GumMetalArray cloaked_ranges;
static GumMetalArray cloaked_fds;

void
_gum_cloak_init (void)
{
  gum_metal_array_init (&cloaked_threads, sizeof (GumThreadId));
  gum_metal_array_init (&cloaked_ranges, sizeof (GumCloakedRange));
  gum_metal_array_init (&cloaked_fds, sizeof (gint));
}

void
_gum_cloak_deinit (void)
{
  gum_metal_array_free (&cloaked_fds);
  gum_metal_array_free (&cloaked_ranges);
  gum_metal_array_free (&cloaked_threads);
}

/**
 * gum_cloak_add_thread:
 * @id: the thread ID to cloak
 *
 * Updates the registry of cloaked resources so the given thread `id` becomes
 * invisible to cloak-aware APIs, such as [func@Gum.process_enumerate_threads].
 */
void
gum_cloak_add_thread (GumThreadId id)
{
  GumThreadId * element, * elements;
  gint i;

  gum_spinlock_acquire (&cloak_lock);

  element = NULL;

  elements = cloaked_threads.data;
  for (i = (gint) cloaked_threads.length - 1; i >= 0; i--)
  {
    if (id >= elements[i])
    {
      element = gum_metal_array_insert_at (&cloaked_threads, i + 1);
      break;
    }
  }

  if (element == NULL)
    element = gum_metal_array_insert_at (&cloaked_threads, 0);

  *element = id;

  gum_spinlock_release (&cloak_lock);
}

/**
 * gum_cloak_remove_thread:
 * @id: the thread ID to uncloak
 *
 * Updates the registry of cloaked resources so the given thread `id` becomes
 * visible to cloak-aware APIs, such as [func@Gum.process_enumerate_threads].
 */
void
gum_cloak_remove_thread (GumThreadId id)
{
  gint index_;

  gum_spinlock_acquire (&cloak_lock);

  index_ = gum_cloak_index_of_thread (id);
  if (index_ != -1)
    gum_metal_array_remove_at (&cloaked_threads, index_);

  gum_spinlock_release (&cloak_lock);
}

/**
 * gum_cloak_has_thread:
 * @id: the thread ID to check
 *
 * Checks whether the given thread `id` is currently being cloaked.
 *
 * Used internally by e.g. [func@Gum.process_enumerate_threads] to determine
 * whether a thread should be visible.
 *
 * May also be used by you to check if a thread is among your own, e.g.:
 *
 * ```c
 * if (gum_cloak_has_thread (gum_process_get_current_thread_id ()))
 *   return;
 * ```
 *
 * Returns: true if cloaked; false otherwise
 */
gboolean
gum_cloak_has_thread (GumThreadId id)
{
  gboolean result;

  gum_spinlock_acquire (&cloak_lock);

  result = gum_cloak_index_of_thread (id) != -1;

  gum_spinlock_release (&cloak_lock);

  return result;
}

/**
 * gum_cloak_enumerate_threads:
 * @func: (not nullable) (scope call): function called with each thread ID
 * @user_data: (nullable): data to pass to `func`
 *
 * Enumerates all currently cloaked thread IDs, calling `func` with each.
 *
 * The passed in function must take special care to avoid using APIs that result
 * in cloak APIs getting called. Exactly what this means is described in further
 * detail in the toplevel [struct@Gum.Cloak] documentation.
 */
void
gum_cloak_enumerate_threads (GumCloakFoundThreadFunc func,
                             gpointer user_data)
{
  guint length, size, i;
  GumThreadId * threads;

  gum_spinlock_acquire (&cloak_lock);

  length = cloaked_threads.length;
  size = length * cloaked_threads.element_size;
  threads = g_alloca (size);
  gum_memcpy (threads, cloaked_threads.data, size);

  gum_spinlock_release (&cloak_lock);

  for (i = 0; i != length; i++)
  {
    if (!func (threads[i], user_data))
      return;
  }
}

static gint
gum_cloak_index_of_thread (GumThreadId id)
{
  GumThreadId * elements, * element;

  elements = cloaked_threads.data;

  element = bsearch (&id, elements, cloaked_threads.length,
      cloaked_threads.element_size, gum_thread_id_compare);
  if (element == NULL)
    return -1;

  return element - elements;
}

static gint
gum_thread_id_compare (gconstpointer element_a,
                       gconstpointer element_b)
{
  GumThreadId a = *((GumThreadId *) element_a);
  GumThreadId b = *((GumThreadId *) element_b);

  if (a == b)
    return 0;
  if (a < b)
    return -1;
  return 1;
}

/**
 * gum_cloak_add_range:
 * @range: the range to cloak
 *
 * Updates the registry of cloaked resources so the given memory `range` becomes
 * invisible to cloak-aware APIs, such as [func@Gum.process_enumerate_ranges].
 */
void
gum_cloak_add_range (const GumMemoryRange * range)
{
  gum_spinlock_acquire (&cloak_lock);

  gum_cloak_add_range_unlocked (range);

  gum_spinlock_release (&cloak_lock);
}

/**
 * gum_cloak_remove_range:
 * @range: the range to uncloak
 *
 * Updates the registry of cloaked resources so the given memory `range` becomes
 * visible to cloak-aware APIs, such as [func@Gum.process_enumerate_ranges].
 */
void
gum_cloak_remove_range (const GumMemoryRange * range)
{
  gum_spinlock_acquire (&cloak_lock);

  gum_cloak_remove_range_unlocked (range);

  gum_spinlock_release (&cloak_lock);
}

static void
gum_cloak_add_range_unlocked (const GumMemoryRange * range)
{
  const guint8 * start, * end;
  gboolean added_to_existing;
  guint i;

  start = GSIZE_TO_POINTER (range->base_address);
  end = start + range->size;

  added_to_existing = FALSE;

  for (i = 0; i != cloaked_ranges.length && !added_to_existing; i++)
  {
    GumCloakedRange * cloaked;

    cloaked = gum_metal_array_element_at (&cloaked_ranges, i);

    if (cloaked->start == end)
    {
      cloaked->start = start;
      added_to_existing = TRUE;
    }
    else if (cloaked->end == start)
    {
      cloaked->end = end;
      added_to_existing = TRUE;
    }
  }

  if (!added_to_existing)
  {
    GumCloakedRange * r;

    r = gum_metal_array_append (&cloaked_ranges);
    r->start = start;
    r->end = end;
  }
}

static void
gum_cloak_remove_range_unlocked (const GumMemoryRange * range)
{
  const guint8 * start, * end;
  gboolean found_match;

  start = GSIZE_TO_POINTER (range->base_address);
  end = start + range->size;

  do
  {
    guint i;

    found_match = FALSE;

    for (i = 0; i != cloaked_ranges.length && !found_match; i++)
    {
      GumCloakedRange * cloaked;
      gsize bottom_remainder, top_remainder;
      gboolean slot_available;

      cloaked = gum_metal_array_element_at (&cloaked_ranges, i);

      if (cloaked->start >= end || start >= cloaked->end)
        continue;

      bottom_remainder = MAX (cloaked->start, start) - cloaked->start;
      top_remainder = cloaked->end - MIN (cloaked->end, end);

      found_match = TRUE;
      slot_available = TRUE;

      if (bottom_remainder + top_remainder == 0)
      {
        gum_metal_array_remove_at (&cloaked_ranges, i);
      }
      else
      {
        const guint8 * previous_top_end = cloaked->end;

        if (bottom_remainder != 0)
        {
          cloaked->end = cloaked->start + bottom_remainder;
          slot_available = FALSE;
        }

        if (top_remainder != 0)
        {
          GumMemoryRange top;

          top.base_address = GUM_ADDRESS (previous_top_end - top_remainder);
          top.size = top_remainder;

          if (slot_available)
          {
            cloaked->start = GSIZE_TO_POINTER (top.base_address);
            cloaked->end = cloaked->start + top.size;
          }
          else
          {
            gum_cloak_add_range_unlocked (&top);
          }
        }
      }
    }
  }
  while (found_match);
}

/**
 * gum_cloak_has_range_containing:
 * @address: the address to look for
 *
 * Determines whether a memory range containing `address` is currently cloaked.
 *
 * Returns: true if cloaked; false otherwise
 */
gboolean
gum_cloak_has_range_containing (GumAddress address)
{
  gboolean is_cloaked = FALSE;
  guint i;

  gum_spinlock_acquire (&cloak_lock);

  for (i = 0; i != cloaked_ranges.length; i++)
  {
    GumCloakedRange * cr = gum_metal_array_element_at (&cloaked_ranges, i);

    if (address >= GUM_ADDRESS (cr->start) && address < GUM_ADDRESS (cr->end))
    {
      is_cloaked = TRUE;
      break;
    }
  }

  gum_spinlock_release (&cloak_lock);

  return is_cloaked;
}

/**
 * gum_cloak_clip_range:
 * @range: the range to determine the visible parts of
 *
 * Determines how much of the given memory `range` is currently visible.
 * May return an empty array if the entire range is cloaked, or NULL if it is
 * entirely visible.
 *
 * Returns: (transfer full) (element-type Gum.MemoryRange): NULL if all
 * visible, or visible parts.
 */
GArray *
gum_cloak_clip_range (const GumMemoryRange * range)
{
  GArray * chunks;
  gboolean found_match, dirty;

  chunks = g_array_sized_new (FALSE, FALSE, sizeof (GumMemoryRange), 2);
  g_array_append_val (chunks, *range);

  dirty = FALSE;

  do
  {
    guint chunk_index;

    found_match = FALSE;

    gum_spinlock_acquire (&cloak_lock);

    for (chunk_index = 0;
        chunk_index != chunks->len && !found_match;
        chunk_index++)
    {
      GumMemoryRange * chunk;
      const guint8 * chunk_start, * chunk_end;
      guint cloaked_index;
      GumCloakedRange threads;
      GumCloakedRange ranges;

      chunk = &g_array_index (chunks, GumMemoryRange, chunk_index);
      chunk_start = GSIZE_TO_POINTER (chunk->base_address);
      chunk_end = chunk_start + chunk->size;

      gum_metal_array_get_extents (&cloaked_threads,
          (gpointer *) &threads.start, (gpointer *) &threads.end);
      gum_metal_array_get_extents (&cloaked_ranges,
          (gpointer *) &ranges.start, (gpointer *) &ranges.end);

      for (cloaked_index = 0;
          cloaked_index != 2 + cloaked_ranges.length && !found_match;
          cloaked_index++)
      {
        const GumCloakedRange * cloaked;
        const guint8 * lower_bound, * upper_bound;
        gsize bottom_remainder, top_remainder;
        gboolean chunk_available;

        if (cloaked_index == 0)
        {
          cloaked = &threads;
        }
        else if (cloaked_index == 1)
        {
          cloaked = &ranges;
        }
        else
        {
          cloaked = gum_metal_array_element_at (&cloaked_ranges,
              cloaked_index - 2);
        }

        lower_bound = MAX (cloaked->start, chunk_start);
        upper_bound = MIN (cloaked->end, chunk_end);
        if (lower_bound >= upper_bound)
          continue;

        bottom_remainder = lower_bound - chunk_start;
        top_remainder = chunk_end - upper_bound;

        found_match = TRUE;
        dirty = TRUE;
        chunk_available = TRUE;

        if (bottom_remainder + top_remainder == 0)
        {
          g_array_remove_index (chunks, chunk_index);
        }
        else
        {
          if (bottom_remainder != 0)
          {
            chunk->base_address = GUM_ADDRESS (chunk_start);
            chunk->size = bottom_remainder;
            chunk_available = FALSE;
          }

          if (top_remainder != 0)
          {
            GumMemoryRange top;

            top.base_address = GUM_ADDRESS (chunk_end - top_remainder);
            top.size = top_remainder;

            if (chunk_available)
            {
              chunk->base_address = top.base_address;
              chunk->size = top.size;
            }
            else
            {
              gum_spinlock_release (&cloak_lock);
              g_array_insert_val (chunks, chunk_index + 1, top);
              gum_spinlock_acquire (&cloak_lock);
            }
          }
        }
      }
    }

    gum_spinlock_release (&cloak_lock);
  }
  while (found_match);

  if (!dirty)
  {
    g_array_free (chunks, TRUE);
    return NULL;
  }

  return chunks;
}

/**
 * gum_cloak_enumerate_ranges:
 * @func: (not nullable) (scope call): function called with each memory range
 * @user_data: (nullable): data to pass to `func`
 *
 * Enumerates all currently cloaked memory ranges, calling `func` with each.
 *
 * The passed in function must take special care to avoid using APIs that result
 * in cloak APIs getting called. Exactly what this means is described in further
 * detail in the toplevel [struct@Gum.Cloak] documentation.
 */
void
gum_cloak_enumerate_ranges (GumCloakFoundRangeFunc func,
                            gpointer user_data)
{
  guint length, size, i;
  GumCloakedRange * ranges;

  gum_spinlock_acquire (&cloak_lock);

  length = cloaked_ranges.length;
  size = length * cloaked_ranges.element_size;
  ranges = g_alloca (size);
  gum_memcpy (ranges, cloaked_ranges.data, size);

  gum_spinlock_release (&cloak_lock);

  for (i = 0; i != length; i++)
  {
    GumCloakedRange * cr = &ranges[i];
    GumMemoryRange mr;

    mr.base_address = GPOINTER_TO_SIZE (cr->start);
    mr.size = cr->end - cr->start;

    if (!func (&mr, user_data))
      return;
  }
}

/**
 * gum_cloak_add_file_descriptor:
 * @fd: the file descriptor to cloak
 *
 * Updates the registry of cloaked resources so the given `fd` becomes invisible
 * to cloak-aware APIs.
 */
void
gum_cloak_add_file_descriptor (gint fd)
{
  gint * element, * elements;
  gint i;

  gum_spinlock_acquire (&cloak_lock);

  element = NULL;

  elements = cloaked_fds.data;
  for (i = (gint) cloaked_fds.length - 1; i >= 0; i--)
  {
    if (fd >= elements[i])
    {
      element = gum_metal_array_insert_at (&cloaked_fds, i + 1);
      break;
    }
  }

  if (element == NULL)
    element = gum_metal_array_insert_at (&cloaked_fds, 0);

  *element = fd;

  gum_spinlock_release (&cloak_lock);
}

/**
 * gum_cloak_remove_file_descriptor:
 * @fd: the file descriptor to uncloak
 *
 * Updates the registry of cloaked resources so the given `fd` becomes visible
 * to cloak-aware APIs.
 */
void
gum_cloak_remove_file_descriptor (gint fd)
{
  gint index_;

  gum_spinlock_acquire (&cloak_lock);

  index_ = gum_cloak_index_of_fd (fd);
  if (index_ != -1)
    gum_metal_array_remove_at (&cloaked_fds, index_);

  gum_spinlock_release (&cloak_lock);
}

/**
 * gum_cloak_has_file_descriptor:
 * @fd: the file descriptor to check
 *
 * Checks whether the given `fd` is currently being cloaked.
 *
 * Returns: true if cloaked; false otherwise
 */
gboolean
gum_cloak_has_file_descriptor (gint fd)
{
  gboolean result;

  gum_spinlock_acquire (&cloak_lock);

  result = gum_cloak_index_of_fd (fd) != -1;

  gum_spinlock_release (&cloak_lock);

  return result;
}

/**
 * gum_cloak_enumerate_file_descriptors:
 * @func: (not nullable) (scope call): function called with each file descriptor
 * @user_data: (nullable): data to pass to `func`
 *
 * Enumerates all currently cloaked file descriptors, calling `func` with each.
 *
 * The passed in function must take special care to avoid using APIs that result
 * in cloak APIs getting called. Exactly what this means is described in further
 * detail in the toplevel [struct@Gum.Cloak] documentation.
 */
void
gum_cloak_enumerate_file_descriptors (GumCloakFoundFDFunc func,
                                      gpointer user_data)
{
  guint length, size, i;
  gint * fds;

  gum_spinlock_acquire (&cloak_lock);

  length = cloaked_fds.length;
  size = length * cloaked_fds.element_size;
  fds = g_alloca (size);
  gum_memcpy (fds, cloaked_fds.data, size);

  gum_spinlock_release (&cloak_lock);

  for (i = 0; i != length; i++)
  {
    if (!func (fds[i], user_data))
      return;
  }
}

static gint
gum_cloak_index_of_fd (gint fd)
{
  gint * elements, * element;

  elements = cloaked_fds.data;

  element = bsearch (&fd, elements, cloaked_fds.length,
      cloaked_fds.element_size, gum_fd_compare);
  if (element == NULL)
    return -1;

  return element - elements;
}

static gint
gum_fd_compare (gconstpointer element_a,
                gconstpointer element_b)
{
  gint a = *((gint *) element_a);
  gint b = *((gint *) element_b);

  if (a == b)
    return 0;
  if (a < b)
    return -1;
  return 1;
}

void
gum_cloak_with_lock_held (GumCloakLockedFunc func,
                          gpointer user_data)
{
  gum_spinlock_acquire (&cloak_lock);
  func (user_data);
  gum_spinlock_release (&cloak_lock);
}

gboolean
gum_cloak_is_locked (void)
{
  if (!gum_spinlock_try_acquire (&cloak_lock))
    return TRUE;

  gum_spinlock_release (&cloak_lock);
  return FALSE;
}
```