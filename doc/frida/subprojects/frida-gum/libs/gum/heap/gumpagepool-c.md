Response:
Let's break down the thought process for analyzing the `gumpagepool.c` code and generating the detailed explanation.

**1. Initial Understanding of the Goal:**

The request asks for a comprehensive analysis of a C source file. This includes:

* **Functionality:** What does this code *do*?
* **Relevance to Reversing:** How can this be used or observed during reverse engineering?
* **Low-level Details:** How does it interact with the OS (Linux/Android), kernel, and hardware (memory)?
* **Logical Reasoning:** Can we deduce input/output behavior?
* **Common Errors:** What mistakes might a user make when using this?
* **User Journey:** How might a user's actions lead to this code being executed?

**2. High-Level Reading and Identifying Key Data Structures:**

The first step is to read through the code and identify the main components. I'd look for:

* **Data Structures:**  `GumPagePool`, `AlignmentCriteria`, `TailAlignResult`, `GumBlockDetails`. These are the building blocks. The most important is `GumPagePool`, as it seems to encapsulate the core functionality.
* **Key Functions:** Functions starting with `gum_page_pool_` are obviously related to the main purpose. Functions like `gum_alloc_n_pages`, `gum_free_pages`, `gum_mprotect`, and `gum_query_page_size` suggest interaction with lower-level memory management.
* **Macros and Constants:** `DEFAULT_PROTECT_MODE`, `MIN_POOL_SIZE`, `MAX_POOL_SIZE`, etc., define important parameters.

**3. Deciphering the Core Functionality of `GumPagePool`:**

Based on the data structures and key functions, the core purpose becomes clear: `GumPagePool` manages a pool of memory pages. It provides functions to:

* **Allocate:** `gum_page_pool_try_alloc` tries to allocate a block of memory within the pool.
* **Free:** `gum_page_pool_try_free` releases a previously allocated block.
* **Query:** `gum_page_pool_peek_available`, `gum_page_pool_peek_used`, `gum_page_pool_get_bounds`, `gum_page_pool_query_block_details` provide information about the pool's state.
* **Initialization:** `gum_page_pool_new` creates a new pool.

**4. Connecting to Reverse Engineering:**

Now, the question is, how does this relate to reverse engineering?  The key insight is that Frida, the tool this code belongs to, is used for dynamic instrumentation. This means it modifies the behavior of running processes. So, a memory pool like this is likely used to:

* **Store Instrumented Code:** When Frida injects code into a process, it needs memory to store that code. `GumPagePool` could be a mechanism for managing this injected code's memory.
* **Store Data:** Instrumented code might need to store data or communicate with the Frida agent. This pool could also be used for that.
* **Observe Memory Allocation:**  Reverse engineers might be interested in *how* a target process allocates memory. If Frida uses this pool, observing its usage could provide insights.

**5. Identifying Low-Level Interactions:**

The code directly calls functions like `gum_alloc_n_pages`, `gum_free_pages`, and `gum_mprotect`. This clearly indicates interaction with the operating system's memory management:

* **`gum_alloc_n_pages`:** Likely a wrapper around `mmap` (or similar) to allocate memory pages.
* **`gum_free_pages`:**  Likely a wrapper around `munmap` to release allocated memory.
* **`gum_mprotect`:**  A direct call to the system call that changes the memory protection attributes (read, write, execute) of pages. This is crucial for security and code injection.
* **`gum_query_page_size`:**  Retrieves the system's page size, a fundamental unit of memory management.

**6. Logical Reasoning and Input/Output:**

Let's consider `gum_page_pool_try_alloc`. The input is a `GumPagePool` object and a desired `size`. The output is a pointer to the allocated memory or `NULL` if allocation fails. The logic involves:

* Calculating the number of pages needed.
* Checking if enough pages are available.
* Finding a contiguous block of free pages.
* Marking those pages as allocated.
* Setting memory protection (using `gum_mprotect`).
* Performing alignment adjustments.

For `gum_page_pool_try_free`, the input is the pool and a memory address. The output is a boolean indicating success or failure. The logic involves:

* Finding the starting index of the allocated block.
* Marking the pages as free.
* Changing memory protection back to `GUM_PAGE_NO_ACCESS`.

**7. Considering User Errors:**

Common mistakes when using a memory pool like this might include:

* **Double Freeing:** Calling `gum_page_pool_try_free` on the same memory block twice.
* **Freeing Unallocated Memory:** Trying to free memory that wasn't allocated by the pool.
* **Memory Corruption:** Writing beyond the bounds of an allocated block. While the pool provides some protection with guard pages, it's still possible to corrupt adjacent blocks.

**8. Tracing the User Journey (Debugging Context):**

How does a user's action lead to this code?  Imagine a Frida script that:

1. **Attaches to a process.**
2. **Intercepts a function call.**
3. **Injects code to modify the function's behavior.**

To store this injected code, Frida needs memory. The `GumPagePool` might be used internally by Frida to allocate this memory. Therefore, the steps could be:

* **User runs a Frida script:** `frida -p <pid> script.js`
* **Frida agent loads into the target process.**
* **Script uses Frida's API to intercept a function.**
* **Frida allocates memory using `gum_page_pool_try_alloc` to store the injected code.**  This is where the `gumpagepool.c` code comes into play.

**9. Structuring the Explanation:**

Finally, the information needs to be organized logically. Using the categories from the original request (Functionality, Reversing, Low-Level, Logic, Errors, User Journey) provides a clear and structured way to present the analysis. Using code snippets and clear explanations for each point enhances understanding.
好的，让我们详细分析一下 `frida/subprojects/frida-gum/libs/gum/heap/gumpagepool.c` 这个文件。

**文件功能概述:**

`gumpagepool.c` 文件实现了一个基于页的内存池管理机制。其主要功能是：

1. **内存分配与释放:**  提供了一种高效的方式来分配和释放固定大小（页大小的整数倍）的内存块。它避免了频繁地调用系统级的内存分配函数（如 `malloc`/`free` 或 `mmap`/`munmap`），从而提高了性能。
2. **内存保护:**  可以为分配的内存块设置保护属性（读、写、执行权限），这对于动态 instrumentation 非常重要，可以控制注入代码的执行权限，防止意外的内存访问。
3. **对齐:**  支持在分配时进行内存对齐，这对于某些需要特定对齐方式的代码（例如，JIT 代码）至关重要。
4. **元数据管理:**  维护了关于内存池中每个页是否被分配以及分配给哪个块的元数据，用于快速查找和管理内存块。

**与逆向方法的关联及举例:**

这个文件与逆向工程的方法紧密相关，因为它为 Frida 这样的动态 instrumentation 工具提供了内存管理的基础设施。

* **代码注入:**  Frida 在运行时将代码注入到目标进程中。这些注入的代码需要存储在内存中。`GumPagePool` 可以用来分配存储这些注入代码的内存区域。
    * **例子:** 当你使用 Frida 的 `Interceptor.attach` 或 `Interceptor.replace` 来修改目标函数的行为时，Frida 会生成一些 trampoline 代码或者 hook 代码，这些代码需要被写入到目标进程的内存空间中。`GumPagePool` 就可能被用来分配这部分内存。
* **数据存储:**  注入的代码可能需要在目标进程中存储一些数据，例如 hook 函数的上下文信息、参数或者返回值。`GumPagePool` 也可以用于分配这些数据的存储空间。
    * **例子:**  假设你要 hook 一个函数的调用，并记录每次调用的参数。你可以在注入的代码中使用 `GumPagePool` 分配一块内存来存储这些参数信息。
* **观察内存分配:**  逆向工程师可以通过观察 Frida 使用 `GumPagePool` 的情况，来了解目标进程的内存布局以及 Frida 是如何在目标进程中分配内存的。
    * **例子:** 你可以使用 Frida 的 API 来跟踪 `gum_page_pool_try_alloc` 和 `gum_page_pool_try_free` 的调用，从而了解 Frida 在目标进程中分配了哪些内存，以及这些内存的用途。
* **内存保护分析:**  通过分析 `GumPagePool` 如何使用 `gum_mprotect` 设置内存保护属性，可以了解 Frida 对注入代码和数据的保护机制。
    * **例子:** 你可能会观察到 Frida 分配的用于存储注入代码的内存区域被设置为可读可执行，而用于存储数据的内存区域被设置为可读可写。

**涉及的二进制底层、Linux、Android 内核及框架知识及举例:**

这个文件涉及到多个底层的概念和技术：

* **内存页 (Memory Page):**  这是操作系统进行内存管理的基本单位。`GumPagePool` 正是基于页来管理内存的。文件中的 `page_size` 变量存储了系统页的大小，通常在 x86/x64 Linux 上是 4096 字节。
    * **例子:**  代码中多次使用 `self->page_size` 进行计算，例如在 `gum_page_pool_constructed` 中分配内存池时，以及在 `num_pages_needed_for` 中计算所需页数时。
* **内存保护 (Memory Protection):**  操作系统提供机制来控制内存区域的访问权限，例如读、写、执行。`GumPagePool` 使用 `gum_mprotect` 函数（可能是对系统调用 `mprotect` 的封装）来设置这些属性。
    * **例子:**  在 `claim_n_pages_at` 函数中，可以看到 `gum_mprotect` 被用来将分配的页设置为可读写权限 (`GUM_PAGE_READ | GUM_PAGE_WRITE`)。在 `release_n_pages_at` 函数中，则将其设置为不可访问 (`GUM_PAGE_NO_ACCESS`)。
* **内存对齐 (Memory Alignment):**  某些处理器架构对内存访问的地址有特定要求。未对齐的访问可能导致性能下降甚至程序崩溃。`GumPagePool` 提供了 `front_alignment` 参数来控制分配的内存块的起始地址对齐。
    * **例子:** `tail_align` 函数负责根据指定的对齐要求调整分配的内存块的起始地址，确保满足对齐约束。
* **`mmap` 和 `munmap` (或类似的系统调用):**  尽管代码中没有直接调用，但 `gum_alloc_n_pages` 和 `gum_free_pages` 极有可能是在内部使用了 `mmap` 来分配整页的内存，并使用 `munmap` 来释放。这是在用户空间管理大块内存的常见做法。
* **GObject 类型系统 (GLib):**  Frida 使用 GLib 库，`GumPagePool` 是一个 GObject，这意味着它使用了 GLib 的对象模型，包括属性、信号等机制。
    * **例子:**  代码中使用了 `G_DEFINE_TYPE` 宏来定义 `GumPagePool` 类型，并使用了 `g_object_class_install_property` 来注册 `page-size`, `protect-mode`, `size`, `front-alignment` 等属性。

**逻辑推理、假设输入与输出:**

假设我们创建一个大小为 4 页，保护模式为 `GUM_PROTECT_MODE_ABOVE`，前对齐为 16 字节的 `GumPagePool`，并尝试分配 100 字节的内存。

* **假设输入:**
    * `GumPagePool` 实例 `pool`，大小为 4 页 (假设页大小为 4096 字节)，保护模式为 `GUM_PROTECT_MODE_ABOVE`，前对齐为 16。
    * 调用 `gum_page_pool_try_alloc(pool, 100)`。
* **逻辑推理:**
    1. `num_pages_needed_for(pool, 100)` 将计算出需要 1 页内存 (因为 100 <= 4096)。
    2. `find_start_index_with_n_free_pages(pool, 1)` 将查找一个未分配的页的起始索引。假设找到了索引 0。
    3. `claim_n_pages_at(pool, 1, 0)` 将标记索引 0 的页为已分配，并将 `pool->available` 减 1。
    4. `tail_align` 函数将被调用，根据前对齐要求（16 字节）调整分配的起始地址。由于页的起始地址通常是 4096 的倍数，它已经满足了 16 字节的对齐，所以 `align_result.aligned_ptr` 可能与页的起始地址相同。
    5. 返回 `align_result.aligned_ptr`，指向分配的 100 字节内存块。
* **假设输出:**
    * `gum_page_pool_try_alloc` 返回一个非 `NULL` 的指针，指向内存池中一个 4096 字节页的起始地址（或稍有偏移，以满足对齐要求）。
    * `pool->available` 的值减 1。

如果再次尝试分配一个大于剩余可用空间大小的内存块，例如分配 5 * 4096 = 20480 字节，`gum_page_pool_try_alloc` 将返回 `NULL`。

**用户或编程常见的使用错误及举例:**

* **重复释放同一块内存 (Double Free):**  用户可能错误地调用 `gum_page_pool_try_free` 两次，释放同一块内存。这会导致内存池的元数据混乱，可能引发崩溃或其他未定义行为。
    * **例子:**
      ```c
      gpointer ptr = gum_page_pool_try_alloc(pool, 100);
      gum_page_pool_try_free(pool, ptr);
      gum_page_pool_try_free(pool, ptr); // 错误：重复释放
      ```
* **释放未由该内存池分配的内存:**  用户可能尝试释放一个不是由该 `GumPagePool` 对象分配的内存地址。这会导致 `find_start_index_for_address` 返回 -1，`gum_page_pool_try_free` 返回 `FALSE`，但如果用户没有检查返回值，可能会导致逻辑错误。
    * **例子:**
      ```c
      gpointer ptr = g_malloc(100); // 使用标准库分配
      gum_page_pool_try_free(pool, ptr); // 错误：释放不属于 pool 的内存
      g_free(ptr); // 正确的释放方式
      ```
* **内存泄漏:**  用户分配了内存，但忘记释放，导致内存池的可用空间逐渐减少。
    * **例子:**
      ```c
      for (int i = 0; i < 100; i++) {
          gum_page_pool_try_alloc(pool, 100); // 循环分配，但没有释放
      }
      // pool 的可用空间会减少
      ```
* **访问越界:**  虽然 `GumPagePool` 管理的是整页或多页的内存，但用户在使用分配到的内存时，仍然可能发生访问越界，写入超过分配大小的内存，这可能破坏内存池的元数据或其他已分配的内存块。

**用户操作是如何一步步的到达这里，作为调试线索:**

当你在使用 Frida 进行动态 instrumentation 时，你的操作会触发 Frida 内部的各种机制，其中就可能涉及到 `GumPagePool` 的使用。以下是一个可能的步骤：

1. **编写 Frida 脚本:**  你编写了一个 JavaScript 或 Python 脚本，使用 Frida 的 API 来 hook 目标进程中的某个函数。
2. **运行 Frida 命令:** 你使用 `frida` 或 `frida-trace` 等命令，指定目标进程和你的脚本。
   ```bash
   frida -p <target_process_id> -l your_script.js
   ```
3. **Frida Agent 加载:** Frida 会将一个 Agent 动态库注入到目标进程中。
4. **脚本执行:** 你的脚本在 Frida Agent 中执行。
5. **Hook 设置:** 脚本中使用 `Interceptor.attach` 或 `Interceptor.replace` 等 API 来设置 hook。
6. **内存分配:** 当 Frida 需要为 hook 代码（例如，trampoline 代码，你的回调函数）或存储 hook 上下文信息分配内存时，它可能会调用 `gum_page_pool_try_alloc`。
   * **调试线索:** 如果你在调试 Frida 脚本或 Frida 本身，并且怀疑内存分配有问题，你可以在 Frida 的源代码中设置断点，或者使用 tracing 工具观察 `gum_page_pool_try_alloc` 的调用，查看其参数（例如，分配的大小）。
7. **内存保护设置:** Frida 使用 `gum_mprotect` 来设置分配内存的保护属性，例如将存储 hook 代码的内存设置为可执行。
   * **调试线索:** 你可以观察 `gum_mprotect` 的调用，查看设置的保护标志和内存地址范围，以了解 Frida 如何保护注入的代码。
8. **Hook 触发:** 当目标进程执行到被 hook 的函数时，Frida 的 hook 代码会被执行。
9. **内存释放:** 当 hook 不再需要时（例如，脚本卸载），Frida 可能会调用 `gum_page_pool_try_free` 来释放之前分配的内存。
   * **调试线索:**  观察 `gum_page_pool_try_free` 的调用，确保分配的内存最终被正确释放，避免内存泄漏。

因此，当你使用 Frida 进行 hook、代码注入等操作时，`gumpagepool.c` 中的代码很可能在后台默默地工作，负责管理 Frida 在目标进程中使用的内存。 理解这个文件的功能对于深入理解 Frida 的工作原理以及调试相关的内存问题非常有帮助。

### 提示词
```
这是目录为frida/subprojects/frida-gum/libs/gum/heap/gumpagepool.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2008-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumpagepool.h"
#include "gummemory.h"

#define DEFAULT_PROTECT_MODE    GUM_PROTECT_MODE_ABOVE
#define MIN_POOL_SIZE           2
#define MAX_POOL_SIZE           G_MAXUINT32
#define DEFAULT_POOL_SIZE       G_MAXUINT16
#define DEFAULT_FRONT_ALIGNMENT 16

typedef struct _AlignmentCriteria AlignmentCriteria;
typedef struct _TailAlignResult   TailAlignResult;

struct _GumPagePool
{
  GObject parent;

  gboolean disposed;

  guint page_size;
  GumProtectMode protect_mode;
  guint size;
  guint front_alignment;

  guint available;
  guint cur_offset;
  guint8 * pool;
  guint8 * pool_end;
  GumBlockDetails * block_details;
};

enum
{
  PROP_0,
  PROP_PAGE_SIZE,
  PROP_PROTECT_MODE,
  PROP_SIZE,
  PROP_FRONT_ALIGNMENT
};

struct _AlignmentCriteria
{
  gsize front;
  gsize tail;
};

struct _TailAlignResult
{
  gpointer aligned_ptr;
  gpointer next_tail_ptr;
  gsize gap_size;
};

static void gum_page_pool_constructed (GObject * object);
static void gum_page_pool_finalize (GObject * object);
static void gum_page_pool_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_page_pool_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gint find_start_index_with_n_free_pages (GumPagePool * self,
    guint n_pages);
static gint find_start_index_for_address (GumPagePool * self, const guint8 * p);

static guint num_pages_needed_for (GumPagePool * self, guint size);

static gpointer claim_n_pages_at (GumPagePool * self, guint n_pages,
    guint start_index);
static gpointer release_n_pages_at (GumPagePool * self, guint n_pages,
    guint start_index);

static void tail_align (gpointer ptr, gsize size,
    const AlignmentCriteria * criteria, TailAlignResult * result);

G_DEFINE_TYPE (GumPagePool, gum_page_pool, G_TYPE_OBJECT)

static void
gum_page_pool_class_init (GumPagePoolClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_page_pool_constructed;
  object_class->finalize = gum_page_pool_finalize;
  object_class->get_property = gum_page_pool_get_property;
  object_class->set_property = gum_page_pool_set_property;

  g_object_class_install_property (object_class, PROP_PAGE_SIZE,
      g_param_spec_uint ("page-size", "Page Size", "System Page Size",
      4096, G_MAXUINT, 4096,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (object_class, PROP_PROTECT_MODE,
      g_param_spec_uint ("protect-mode", "Protect Mode", "Protect Mode",
      0, G_MAXUINT, DEFAULT_PROTECT_MODE,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (object_class, PROP_SIZE,
      g_param_spec_uint ("size", "Size", "Size in number of pages",
      MIN_POOL_SIZE, MAX_POOL_SIZE, DEFAULT_POOL_SIZE,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (object_class, PROP_FRONT_ALIGNMENT,
      g_param_spec_uint ("front-alignment", "Front Alignment",
      "Front alignment requirement",
      1, 64, DEFAULT_FRONT_ALIGNMENT,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static void
gum_page_pool_init (GumPagePool * self)
{
  self->page_size = gum_query_page_size ();
  self->protect_mode = DEFAULT_PROTECT_MODE;
  self->size = DEFAULT_POOL_SIZE;
  self->front_alignment = DEFAULT_FRONT_ALIGNMENT;
}

static void
gum_page_pool_constructed (GObject * object)
{
  GumPagePool * self = GUM_PAGE_POOL (object);

  self->available = self->size;
  self->pool = gum_alloc_n_pages (self->size, GUM_PAGE_NO_ACCESS);
  self->pool_end = self->pool + (self->size * self->page_size);
  self->block_details = g_malloc0 (self->size * sizeof (GumBlockDetails));
}

static void
gum_page_pool_finalize (GObject * object)
{
  GumPagePool * self = GUM_PAGE_POOL (object);

  g_free (self->block_details);
  gum_free_pages (self->pool);

  G_OBJECT_CLASS (gum_page_pool_parent_class)->finalize (object);
}

static void
gum_page_pool_get_property (GObject * object,
                            guint property_id,
                            GValue * value,
                            GParamSpec * pspec)
{
  GumPagePool * self = GUM_PAGE_POOL (object);

  switch (property_id)
  {
    case PROP_PAGE_SIZE:
      g_value_set_uint (value, self->page_size);
      break;
    case PROP_PROTECT_MODE:
      g_value_set_uint (value, self->protect_mode);
      break;
    case PROP_SIZE:
      g_value_set_uint (value, self->size);
      break;
    case PROP_FRONT_ALIGNMENT:
      g_value_set_uint (value, self->front_alignment);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_page_pool_set_property (GObject * object,
                            guint property_id,
                            const GValue * value,
                            GParamSpec * pspec)
{
  GumPagePool * self = GUM_PAGE_POOL (object);

  switch (property_id)
  {
    case PROP_PROTECT_MODE:
      self->protect_mode = g_value_get_uint (value);
      break;
    case PROP_SIZE:
      self->size = g_value_get_uint (value);
      break;
    case PROP_FRONT_ALIGNMENT:
      self->front_alignment = g_value_get_uint (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumPagePool *
gum_page_pool_new (GumProtectMode protect_mode,
                   guint n_pages)
{
  return g_object_new (GUM_TYPE_PAGE_POOL,
      "protect-mode", protect_mode,
      "size", n_pages,
      NULL);
}

gpointer
gum_page_pool_try_alloc (GumPagePool * self,
                         guint size)
{
  gpointer result = NULL;
  guint n_pages;

  g_assert (size != 0);

  n_pages = num_pages_needed_for (self, size);

  if (n_pages <= self->available)
  {
    gint start_index;

    start_index = find_start_index_with_n_free_pages (self, n_pages);
    if (start_index >= 0)
    {
      guint8 * page_start;
      AlignmentCriteria align_criteria;
      TailAlignResult align_result;
      guint i;

      page_start = claim_n_pages_at (self, n_pages, start_index);

      align_criteria.front = self->front_alignment;
      align_criteria.tail = self->page_size;
      tail_align (page_start, size, &align_criteria, &align_result);

      for (i = start_index; i < start_index + n_pages; i++)
      {
        GumBlockDetails * details = &self->block_details[i];

        details->address = align_result.aligned_ptr;
        details->size = size;

        details->guard = page_start + ((n_pages - 1) * self->page_size);
        details->guard_size = self->page_size;
      }

      result = align_result.aligned_ptr;
    }
  }

  return result;
}

gboolean
gum_page_pool_try_free (GumPagePool * self,
                        gpointer mem)
{
  gint start_index;
  guint n_pages;

  start_index = find_start_index_for_address (self, mem);
  if (start_index < 0)
    return FALSE;

  n_pages = num_pages_needed_for (self, self->block_details[start_index].size);
  release_n_pages_at (self, n_pages, start_index);

  return TRUE;
}

guint
gum_page_pool_peek_available (GumPagePool * self)
{
  return self->available;
}

guint
gum_page_pool_peek_used (GumPagePool * self)
{
  return self->size - self->available;
}

void
gum_page_pool_get_bounds (GumPagePool * self,
                          guint8 ** lower,
                          guint8 ** upper)
{
  *lower = self->pool;
  *upper = self->pool_end;
}

gboolean
gum_page_pool_query_block_details (GumPagePool * self,
                                   gconstpointer mem,
                                   GumBlockDetails * details)
{
  gint start_index;

  start_index = find_start_index_for_address (self, mem);
  if (start_index < 0)
    return FALSE;

  *details = self->block_details[start_index];
  return TRUE;
}

static gint
find_start_index_with_n_free_pages (GumPagePool * self,
                                    guint n_pages)
{
  gint result = -1;
  guint first_index;
  guint i, n;

  first_index = self->cur_offset;

start_over:

  for (i = first_index, n = 0; i < self->size && n < n_pages; i++)
  {
    if (!self->block_details[i].allocated)
      n++;
    else
      n = 0;
  }

  if (n == n_pages)
  {
    result = i - n_pages;
  }
  else if (first_index != 0)
  {
    first_index = 0;
    goto start_over;
  }

  return result;
}

static gint
find_start_index_for_address (GumPagePool * self,
                              const guint8 * p)
{
  if (p < self->pool || p > self->pool_end)
    return -1;

  return (p - self->pool) / self->page_size;
}

static guint
num_pages_needed_for (GumPagePool * self,
                      guint size)
{
  guint n_pages;

  n_pages = (size / self->page_size) + 1;
  if (size % self->page_size != 0)
    n_pages++;

  return n_pages;
}

#define POOL_ADDRESS_FROM_PAGE_INDEX(n) (self->pool + (n * self->page_size))

static gpointer
claim_n_pages_at (GumPagePool * self,
                  guint n_pages,
                  guint start_index)
{
  gpointer start_address;
  guint i;

  start_address = POOL_ADDRESS_FROM_PAGE_INDEX (start_index);

  self->cur_offset = start_index + n_pages;
  self->available -= n_pages;

  for (i = start_index; i < start_index + n_pages; i++)
  {
    GumBlockDetails * details = &self->block_details[i];

    details->allocated = TRUE;
  }

  gum_mprotect (start_address, (n_pages - 1) * self->page_size,
      GUM_PAGE_READ | GUM_PAGE_WRITE);
  return start_address;
}

static gpointer
release_n_pages_at (GumPagePool * self,
                    guint n_pages,
                    guint start_index)
{
  gpointer start_address;
  guint i;

  self->available += n_pages;

  for (i = start_index; i < start_index + n_pages; i++)
  {
    GumBlockDetails * details = &self->block_details[i];

    details->allocated = FALSE;
  }

  start_address = POOL_ADDRESS_FROM_PAGE_INDEX (start_index);
  gum_mprotect (start_address, n_pages - 1, GUM_PAGE_NO_ACCESS);

  return start_address;
}

static void
tail_align (gpointer ptr,
            gsize size,
            const AlignmentCriteria * criteria,
            TailAlignResult * result)
{
  gsize unaligned_start_address, unaligned_end_address;
  gsize next_tail_boundary;
  gsize aligned_start_address, aligned_end_address;

  unaligned_start_address = GPOINTER_TO_SIZE (ptr);
  unaligned_end_address = unaligned_start_address + size - 1;
  next_tail_boundary = ((unaligned_end_address / criteria->tail) + 1)
      * criteria->tail;

  aligned_start_address = ((next_tail_boundary - size) / criteria->front)
      * criteria->front;
  if (aligned_start_address < unaligned_start_address)
  {
    aligned_start_address += criteria->tail;
    next_tail_boundary += criteria->tail;
  }
  aligned_end_address = aligned_start_address + size - 1;

  result->aligned_ptr = GSIZE_TO_POINTER (aligned_start_address);
  result->next_tail_ptr = GSIZE_TO_POINTER (next_tail_boundary);
  result->gap_size = next_tail_boundary - (aligned_end_address + 1);
}
```