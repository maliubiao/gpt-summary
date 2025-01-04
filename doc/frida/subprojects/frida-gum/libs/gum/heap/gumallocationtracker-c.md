Response:
Let's break down the thought process for analyzing this C code and fulfilling the request.

**1. Understanding the Goal:**

The core request is to understand the functionality of `gumallocationtracker.c` within the Frida context and relate it to various software engineering concepts, especially reverse engineering and low-level details. The request specifically asks for functionality, relevance to reverse engineering, connections to OS/kernel details, logical inferences, common user errors, and debugging steps.

**2. Initial Code Scan and Keyword Spotting:**

The first step is to quickly scan the code, looking for recognizable patterns and keywords. This helps to form an initial high-level understanding:

* **Header includes:**  `gumallocationtracker.h`, `string.h`, `gumallocationblock.h`, `gumallocationgroup.h`, `gummemory.h`, `gumreturnaddress.h`, `gumbacktracer.h`. These immediately suggest the file deals with tracking memory allocations, likely with the ability to capture backtraces.
* **Data structures:** `GumAllocationTracker`, `GumAllocationTrackerBlock`. These are the main data containers. Noting the `GHashTable` usage for `known_blocks_ht` and `block_groups_ht` suggests efficient lookup of memory blocks and groups.
* **Function names:**  `gum_allocation_tracker_new`, `gum_allocation_tracker_begin`, `gum_allocation_tracker_end`, `gum_allocation_tracker_on_malloc`, `gum_allocation_tracker_on_free`, `gum_allocation_tracker_on_realloc`, `gum_allocation_tracker_peek_*`. These clearly indicate the file's purpose: creating, starting/stopping, and monitoring memory allocation events. The `peek_*` functions suggest retrieving aggregated information.
* **`G_DEFINE_TYPE` and `GObject`:** This signifies the use of the GLib object system, a common framework in projects like Frida.
* **Mutex usage:** `GMutex mutex`, `GUM_ALLOCATION_TRACKER_LOCK`, `GUM_ALLOCATION_TRACKER_UNLOCK`. This points to thread-safety concerns and the likelihood of concurrent access.
* **`backtracer`:** The presence of `GumBacktracerInterface` and functions related to it highlight the ability to record call stacks.

**3. Deeper Dive into Functionality:**

After the initial scan, the next step is to go through the functions more carefully, understanding their specific roles:

* **`gum_allocation_tracker_new`:** Creates an instance of the tracker, optionally with a backtracer.
* **`gum_allocation_tracker_set_filter_function`:** Allows setting a filter to selectively track allocations.
* **`gum_allocation_tracker_begin` and `gum_allocation_tracker_end`:**  Control the active tracking period, resetting internal counters.
* **`gum_allocation_tracker_on_malloc_full`, `gum_allocation_tracker_on_free_full`, `gum_allocation_tracker_on_realloc_full`:** These are the core functions where the tracking logic resides. They record allocation details (address, size, and optionally backtrace) when `malloc`, `free`, and `realloc` occur. The `_full` suffix suggests versions taking a `GumCpuContext` (important for cross-architecture support).
* **`gum_allocation_tracker_peek_*`:**  Provide ways to retrieve collected statistics (block count, total size, lists of blocks and groups).
* **Internal helper functions:**  `gum_allocation_tracker_size_stats_add_block` and `gum_allocation_tracker_size_stats_remove_block` manage aggregate statistics.

**4. Connecting to Reverse Engineering:**

This is where the analysis starts to relate the code to the specific prompt:

* **Tracking memory allocation:** This is fundamental to understanding how a program manages its data. Identifying leaks, understanding object lifetimes, and pinpointing the source of allocations are key reverse engineering tasks.
* **Backtraces:**  Crucial for identifying where an allocation originated, providing context and allowing the reverse engineer to trace the call path leading to the allocation. This helps in understanding the program's logic.

**5. Linking to Binary/Kernel/Android:**

* **Binary Level:**  The interaction with `malloc`, `free`, and `realloc` directly relates to the underlying memory management mechanisms at the binary level.
* **Linux/Android Kernel:** Memory allocation ultimately relies on system calls provided by the kernel. While this code doesn't directly interact with syscalls, it's built on top of libraries that do. The `GumCpuContext` hints at the need to handle different processor architectures, which is relevant to both Linux and Android.
* **Android Framework:**  Android's framework uses various memory allocation strategies. This tracker could be used to monitor allocations within Android applications or even parts of the framework itself.

**6. Logical Inferences and Examples:**

At this stage, constructing concrete examples helps solidify understanding:

* **Filter Function:**  Imagine tracking only allocations above a certain size to focus on larger objects.
* **Backtrace Example:**  Simulating a `malloc` call and showing how the backtrace would capture the call stack.

**7. Identifying User Errors:**

Thinking about how someone might misuse this component is crucial:

* **Forgetting `begin`/`end`:**  The tracker won't work correctly if these aren't called.
* **Incorrect Filtering:**  Setting up filters that are too broad or too narrow could lead to missing important information or collecting too much data.
* **Concurrency Issues (though the code tries to prevent this with mutexes):**  While the code uses mutexes, incorrect usage in the calling code could still lead to issues.

**8. Debugging Scenario:**

Thinking about how a user would arrive at this code during debugging helps provide context:

* **Memory Leak:** This is a classic scenario where an allocation tracker would be useful.
* **Unexpected Allocation:**  Investigating why and where memory is being allocated unexpectedly.

**9. Structuring the Answer:**

Finally, the information needs to be organized logically to address all parts of the request. Using clear headings and bullet points makes the answer easier to read and understand. The flow should go from general functionality to more specific aspects like reverse engineering and low-level details.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe the filter function is about filtering *already collected* data.
* **Correction:**  Looking at the `gum_allocation_tracker_on_malloc_full` function, it's clear the filter is applied *before* capturing the backtrace, optimizing performance.
* **Initial thought:** Focus only on user-space allocations.
* **Refinement:**  Recognize that Frida can also be used for system-level instrumentation, so mentioning kernel aspects is relevant, even if the code itself doesn't directly interact with the kernel.

By following these steps, combining code analysis with conceptual understanding, and relating the code to the specific context of Frida and reverse engineering, a comprehensive and accurate answer can be generated.
这是一个Frida动态Instrumentation工具的源代码文件，名为`gumallocationtracker.c`，位于Frida的子项目`frida-gum`的`libs/gum/heap`目录下。它的主要功能是**跟踪程序运行时的内存分配和释放操作**。

以下是其功能的详细列表，并根据您的要求进行了分类说明：

**1. 主要功能：内存分配跟踪**

* **监控 `malloc`, `free`, `realloc` 等内存管理函数:**  它通过Hook或者其他Instrumentation技术，拦截目标进程对这些函数的调用。
* **记录分配信息:**  当 `malloc` 被调用时，它会记录分配的内存地址和大小。
* **记录释放信息:** 当 `free` 被调用时，它会记录被释放的内存地址。
* **记录重新分配信息:** 当 `realloc` 被调用时，它会记录旧的地址、新的地址和新的大小。
* **可选的调用栈追踪 (Backtracer):** 可以配置为记录每次内存分配时的调用栈信息，帮助定位内存分配的来源。
* **过滤功能:** 可以设置过滤器来选择性地跟踪某些特定条件的内存分配，例如基于分配大小或调用栈。
* **统计信息:** 维护当前已分配的内存块数量和总大小。
* **分组统计:**  可以将分配的内存块按大小进行分组，并统计每个大小的块的数量和峰值。
* **提供已分配内存块的列表:** 可以获取当前所有已分配内存块的地址和大小的列表。

**2. 与逆向方法的关系及举例说明：**

`gumallocationtracker.c` 提供的功能对于逆向工程至关重要，可以帮助逆向工程师理解目标程序的内存管理行为，发现潜在的漏洞或安全问题。

* **内存泄漏检测:** 通过跟踪分配和释放，可以找出哪些内存被分配了却没有被释放，从而定位内存泄漏的位置。
    * **举例:** 逆向一个应用程序，发现其在处理特定网络请求后，`gum_allocation_tracker_peek_block_list` 返回的列表中的内存块数量持续增加，且某些地址长期存在，即使请求处理完毕也没有被释放，这很可能就是一个内存泄漏。
* **理解对象生命周期:** 跟踪对象的分配和释放，可以帮助理解对象的创建时机、使用范围和销毁时机，这对于理解程序的内部逻辑很有帮助。
    * **举例:** 逆向一个游戏引擎，通过跟踪特定游戏对象（例如角色、道具）的内存分配和释放，可以了解这些对象何时被创建、何时被销毁，以及它们在内存中的存在时间。
* **查找敏感数据的位置:** 有时敏感数据会被分配到堆内存中，通过跟踪内存分配，可以找到可能包含敏感数据的内存块。
    * **举例:** 逆向一个加密软件，跟踪其内存分配，可能会发现用于存储密钥或加密后数据的内存块。
* **分析堆溢出漏洞:**  跟踪内存分配可以帮助理解堆的布局，有助于分析堆溢出漏洞的原理和利用方式。
    * **举例:**  逆向一个存在堆溢出的程序，通过跟踪特定大小的内存分配，可以观察堆块的分配情况，从而理解溢出可能发生的位置和大小。

**3. 涉及到的二进制底层、Linux、Android内核及框架的知识及举例说明：**

`gumallocationtracker.c` 的实现依赖于对底层操作系统和编程语言内存管理机制的理解。

* **二进制底层:**
    * **内存地址:**  核心功能是跟踪内存地址，这直接涉及到程序在内存中的布局和寻址方式。
    * **堆内存:**  主要关注堆内存的分配和释放，理解堆的结构和管理方式是关键。
    * **函数调用约定:**  为了正确拦截 `malloc`, `free`, `realloc` 等函数，需要了解目标平台的函数调用约定，以便正确获取参数和返回值。
* **Linux:**
    * **glibc 的 `malloc`, `free`, `realloc`:**  在Linux环境下，通常需要Hook glibc提供的内存管理函数。
    * **进程内存空间:**  需要理解Linux进程的内存空间布局，例如代码段、数据段、堆、栈等。
    * **系统调用:**  底层的内存分配最终会涉及到内核提供的系统调用，例如 `brk`, `mmap` 等。
* **Android内核及框架:**
    * **Bionic libc:**  Android 使用 Bionic libc，其内存管理实现可能与 glibc 有差异。
    * **Dalvik/ART 虚拟机:**  对于运行在虚拟机上的Android应用，还需要考虑虚拟机自身的内存管理机制，例如对象分配和垃圾回收。
    * **Android 框架服务:**  Android 框架中的某些服务也可能使用自定义的内存管理方式。
    * **举例:**  在Android环境下，Frida需要利用其提供的API来Hook ART虚拟机中的内存分配函数，例如 `art::Heap::AllocObject` 等，而不是直接Hook Bionic libc 的 `malloc`。

**4. 逻辑推理及假设输入与输出：**

`gumallocationtracker.c` 内部进行了一些逻辑推理，例如：

* **假设输入:**
    * 用户调用 `gum_allocation_tracker_begin(tracker)` 启动跟踪。
    * 目标程序执行 `void* ptr = malloc(1024);`
    * 目标程序执行 `free(ptr);`
    * 用户调用 `gum_allocation_tracker_end(tracker)` 结束跟踪。
    * 用户调用 `gum_allocation_tracker_peek_block_count(tracker)` 和 `gum_allocation_tracker_peek_block_total_size(tracker)`。
* **逻辑推理:**
    * 当 `malloc(1024)` 被拦截时，`gum_allocation_tracker_on_malloc` 会被调用，记录分配地址 `ptr` 和大小 `1024`，并将块数和总大小增加。
    * 当 `free(ptr)` 被拦截时，`gum_allocation_tracker_on_free` 会被调用，根据地址 `ptr` 找到对应的分配记录，并将块数和总大小减少。
* **预期输出:**
    * `gum_allocation_tracker_peek_block_count(tracker)` 返回 `0` (因为分配后被释放)。
    * `gum_allocation_tracker_peek_block_total_size(tracker)` 返回 `0`。

* **假设输入（包含 Backtracer）:**
    * 用户创建 `GumAllocationTracker` 时启用了 Backtracer。
    * 目标程序在一个函数 `foo()` 中调用 `malloc(512)`。
* **逻辑推理:**
    * `gum_allocation_tracker_on_malloc_full` 被调用，除了记录地址和大小，还会调用 `backtracer_iface->generate` 获取调用栈信息。
* **预期输出:**
    * `gum_allocation_tracker_peek_block_list` 返回的 `GumAllocationBlock` 结构体中，`return_addresses` 数组会包含 `foo()` 函数的返回地址信息。

**5. 涉及用户或者编程常见的使用错误及举例说明：**

* **忘记调用 `gum_allocation_tracker_begin` 和 `gum_allocation_tracker_end`:** 如果不调用 `begin` 启动跟踪，或者在需要跟踪的程序执行完毕后忘记调用 `end`，则无法正确记录内存分配信息。
    * **举例:** 用户编写 Frida 脚本，直接在 `on('message', ...)` 中尝试获取内存块列表，而没有先调用 `tracker.begin()`，导致获取到的列表为空或不完整。
* **过滤条件设置不当:**  如果设置了过于严格的过滤条件，可能会漏掉一些想要跟踪的分配；如果设置的过于宽松，可能会导致记录过多的信息，影响性能。
    * **举例:** 用户只想跟踪大于 1MB 的分配，但误将过滤条件设置为小于 1MB，导致所有大于 1MB 的分配都被忽略。
* **在多线程环境下使用不当:** 虽然代码中使用了互斥锁 (`GMutex`) 来保护共享数据，但如果用户在多个 Frida 线程或脚本中同时访问同一个 `GumAllocationTracker` 实例，仍然可能存在并发问题。
* **过度依赖 Backtracer 影响性能:**  Backtracer 功能会显著降低程序运行速度，如果在不需要详细调用栈信息的情况下开启了 Backtracer，可能会导致性能问题。

**6. 用户操作是如何一步步的到达这里，作为调试线索：**

通常，用户与 `gumallocationtracker.c` 的交互是通过 Frida 的 JavaScript API 进行的，但其内部的实现最终会执行到这里的 C 代码。以下是一个典型的调试线索：

1. **用户编写 Frida JavaScript 脚本:** 用户编写一个 Frida 脚本，希望跟踪目标应用程序的内存分配情况。
2. **创建 `MemoryTracker` 对象:**  脚本中使用 `MemoryTracker.allocations()` 或类似的方法，这会在 Frida 的 GumJS 层面创建一个 `GumAllocationTracker` 对象的实例。
3. **调用 `begin()` 方法:** 脚本调用 `tracker.begin()` 方法，这会触发 GumJS 调用到 `gum_allocation_tracker_begin` 函数。
4. **目标程序执行内存分配:**  当目标应用程序执行 `malloc`, `free`, 或 `realloc` 等操作时，Frida 通过其 Instrumentation 技术拦截这些函数调用。
5. **调用 `gum_allocation_tracker_on_malloc(_full)`, `gum_allocation_tracker_on_free(_full)`, `gum_allocation_tracker_on_realloc(_full)`:** 拦截到的内存分配事件会触发 Frida 调用 `gumallocationtracker.c` 中的相应函数，记录分配信息。
6. **调用 `peek_*` 方法获取信息:**  脚本调用 `tracker.peekAll()` 或类似的函数来获取已分配的内存块列表或其他统计信息，这会触发 GumJS 调用到 `gum_allocation_tracker_peek_block_list` 等函数。
7. **查看结果并调试:** 用户在 Frida 控制台中查看输出的内存分配信息，如果发现异常（例如内存泄漏），可能会需要更深入地分析，例如查看分配时的调用栈，这会涉及到 `gumbacktracer.c` 等相关代码。

**作为调试线索，如果用户报告了以下问题，可能会需要查看 `gumallocationtracker.c` 的代码：**

* **内存跟踪功能无法正常工作:** 例如，`peekAll()` 返回空列表，即使知道目标程序有内存分配。
* **获取到的内存分配信息不准确:** 例如，分配的大小或地址与预期不符。
* **Backtracer 功能无法获取到调用栈信息:**  这可能意味着 Backtracer 的配置有问题，或者 `gumallocationtracker.c` 与 `gumbacktracer.c` 的集成存在问题。
* **性能问题:**  如果用户报告启用内存跟踪后程序运行速度明显下降，可能需要检查 `gumallocationtracker.c` 中是否有性能瓶颈，例如频繁的哈希表操作或 Backtracer 的开销。

总而言之，`gumallocationtracker.c` 是 Frida 中一个核心的组件，它提供了强大的内存分配跟踪功能，为动态逆向工程提供了重要的支持和信息。 理解其内部实现有助于更好地利用 Frida 进行程序分析和调试。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/libs/gum/heap/gumallocationtracker.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2008-2018 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumallocationtracker.h"

#include <string.h>

#include "gumallocationblock.h"
#include "gumallocationgroup.h"
#include "gummemory.h"
#include "gumreturnaddress.h"
#include "gumbacktracer.h"

typedef struct _GumAllocationTrackerBlock GumAllocationTrackerBlock;

struct _GumAllocationTracker
{
  GObject parent;

  gboolean disposed;

  GMutex mutex;

  volatile gint enabled;

  GumAllocationTrackerFilterFunction filter_func;
  gpointer filter_func_user_data;

  guint block_count;
  guint block_total_size;
  GHashTable * known_blocks_ht;
  GHashTable * block_groups_ht;

  GumBacktracerInterface * backtracer_iface;
  GumBacktracer * backtracer_instance;
};

enum
{
  PROP_0,
  PROP_BACKTRACER,
};

struct _GumAllocationTrackerBlock
{
  guint size;
  GumReturnAddress return_addresses[1];
};

#define GUM_ALLOCATION_TRACKER_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_ALLOCATION_TRACKER_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

static void gum_allocation_tracker_constructed (GObject * object);
static void gum_allocation_tracker_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);
static void gum_allocation_tracker_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_allocation_tracker_dispose (GObject * object);
static void gum_allocation_tracker_finalize (GObject * object);

static void gum_allocation_tracker_size_stats_add_block (
    GumAllocationTracker * self, guint size);
static void gum_allocation_tracker_size_stats_remove_block (
    GumAllocationTracker * self, guint size);

G_DEFINE_TYPE (GumAllocationTracker, gum_allocation_tracker, G_TYPE_OBJECT)

static void
gum_allocation_tracker_class_init (GumAllocationTrackerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);
  GParamSpec * pspec;

  object_class->set_property = gum_allocation_tracker_set_property;
  object_class->get_property = gum_allocation_tracker_get_property;
  object_class->dispose = gum_allocation_tracker_dispose;
  object_class->finalize = gum_allocation_tracker_finalize;
  object_class->constructed = gum_allocation_tracker_constructed;

  pspec = g_param_spec_object ("backtracer", "Backtracer",
      "Backtracer Implementation", GUM_TYPE_BACKTRACER,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | G_PARAM_CONSTRUCT_ONLY);
  g_object_class_install_property (object_class, PROP_BACKTRACER, pspec);
}

static void
gum_allocation_tracker_init (GumAllocationTracker * self)
{
  g_mutex_init (&self->mutex);
}

static void
gum_allocation_tracker_constructed (GObject * object)
{
  GumAllocationTracker * self = GUM_ALLOCATION_TRACKER (object);

  if (self->backtracer_instance != NULL)
  {
    self->known_blocks_ht = g_hash_table_new_full (NULL, NULL, NULL, g_free);
  }
  else
  {
    self->known_blocks_ht = g_hash_table_new (NULL, NULL);
  }

  self->block_groups_ht = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_allocation_group_free);
}

static void
gum_allocation_tracker_set_property (GObject * object,
                                     guint property_id,
                                     const GValue * value,
                                     GParamSpec * pspec)
{
  GumAllocationTracker * self = GUM_ALLOCATION_TRACKER (object);

  switch (property_id)
  {
    case PROP_BACKTRACER:
      if (self->backtracer_instance != NULL)
        g_object_unref (self->backtracer_instance);
      self->backtracer_instance = g_value_dup_object (value);

      if (self->backtracer_instance != NULL)
      {
        self->backtracer_iface =
            GUM_BACKTRACER_GET_IFACE (self->backtracer_instance);
      }
      else
      {
        self->backtracer_iface = NULL;
      }

      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_allocation_tracker_get_property (GObject * object,
                                     guint property_id,
                                     GValue * value,
                                     GParamSpec * pspec)
{
  GumAllocationTracker * self = GUM_ALLOCATION_TRACKER (object);

  switch (property_id)
  {
    case PROP_BACKTRACER:
      g_value_set_object (value, self->backtracer_instance);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_allocation_tracker_dispose (GObject * object)
{
  GumAllocationTracker * self = GUM_ALLOCATION_TRACKER (object);

  if (!self->disposed)
  {
    self->disposed = TRUE;

    g_clear_object (&self->backtracer_instance);
    self->backtracer_iface = NULL;

    g_hash_table_unref (self->known_blocks_ht);
    self->known_blocks_ht = NULL;

    g_hash_table_unref (self->block_groups_ht);
    self->block_groups_ht = NULL;
  }

  G_OBJECT_CLASS (gum_allocation_tracker_parent_class)->dispose (object);
}

static void
gum_allocation_tracker_finalize (GObject * object)
{
  GumAllocationTracker * self = GUM_ALLOCATION_TRACKER (object);

  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_allocation_tracker_parent_class)->finalize (object);
}

GumAllocationTracker *
gum_allocation_tracker_new (void)
{
  return gum_allocation_tracker_new_with_backtracer (NULL);
}

GumAllocationTracker *
gum_allocation_tracker_new_with_backtracer (GumBacktracer * backtracer)
{
  return g_object_new (GUM_TYPE_ALLOCATION_TRACKER,
      "backtracer", backtracer,
      NULL);
}

void
gum_allocation_tracker_set_filter_function (
    GumAllocationTracker * self,
    GumAllocationTrackerFilterFunction filter,
    gpointer user_data)
{
  g_assert (g_atomic_int_get (&self->enabled) == FALSE);

  self->filter_func = filter;
  self->filter_func_user_data = user_data;
}

void
gum_allocation_tracker_begin (GumAllocationTracker * self)
{
  GUM_ALLOCATION_TRACKER_LOCK (self);
  self->block_count = 0;
  self->block_total_size = 0;
  g_hash_table_remove_all (self->known_blocks_ht);
  GUM_ALLOCATION_TRACKER_UNLOCK (self);

  g_atomic_int_set (&self->enabled, TRUE);
}

void
gum_allocation_tracker_end (GumAllocationTracker * self)
{
  g_atomic_int_set (&self->enabled, FALSE);

  GUM_ALLOCATION_TRACKER_LOCK (self);
  self->block_count = 0;
  self->block_total_size = 0;
  g_hash_table_remove_all (self->known_blocks_ht);
  g_hash_table_remove_all (self->block_groups_ht);
  GUM_ALLOCATION_TRACKER_UNLOCK (self);
}

guint
gum_allocation_tracker_peek_block_count (GumAllocationTracker * self)
{
  return self->block_count;
}

guint
gum_allocation_tracker_peek_block_total_size (GumAllocationTracker * self)
{
  return self->block_total_size;
}

GList *
gum_allocation_tracker_peek_block_list (GumAllocationTracker * self)
{
  GList * blocks = NULL;
  GHashTableIter iter;
  gpointer key, value;

  GUM_ALLOCATION_TRACKER_LOCK (self);
  g_hash_table_iter_init (&iter, self->known_blocks_ht);
  while (g_hash_table_iter_next (&iter, &key, &value))
  {
    if (self->backtracer_instance != NULL)
    {
      GumAllocationTrackerBlock * tb = (GumAllocationTrackerBlock *) value;
      GumAllocationBlock * block;
      guint i;

      block = gum_allocation_block_new (key, tb->size);

      for (i = 0; tb->return_addresses[i] != NULL; i++)
        block->return_addresses.items[i] = tb->return_addresses[i];
      block->return_addresses.len = i;

      blocks = g_list_prepend (blocks, block);
    }
    else
    {
      blocks = g_list_prepend (blocks,
          gum_allocation_block_new (key, GPOINTER_TO_UINT (value)));
    }
  }
  GUM_ALLOCATION_TRACKER_UNLOCK (self);

  return blocks;
}

GList *
gum_allocation_tracker_peek_block_groups (GumAllocationTracker * self)
{
  GList * groups, * cur;

  GUM_ALLOCATION_TRACKER_LOCK (self);
  groups = g_hash_table_get_values (self->block_groups_ht);
  for (cur = groups; cur != NULL; cur = cur->next)
    cur->data = gum_allocation_group_copy ((GumAllocationGroup *) cur->data);
  GUM_ALLOCATION_TRACKER_UNLOCK (self);

  return groups;
}

void
gum_allocation_tracker_on_malloc (GumAllocationTracker * self,
                                  gpointer address,
                                  guint size)
{
  gum_allocation_tracker_on_malloc_full (self, address, size, NULL);
}

void
gum_allocation_tracker_on_free (GumAllocationTracker * self,
                                gpointer address)
{
  gum_allocation_tracker_on_free_full (self, address, NULL);
}

void
gum_allocation_tracker_on_realloc (GumAllocationTracker * self,
                                   gpointer old_address,
                                   gpointer new_address,
                                   guint new_size)
{
  gum_allocation_tracker_on_realloc_full (self, old_address, new_address,
      new_size, NULL);
}

void
gum_allocation_tracker_on_malloc_full (GumAllocationTracker * self,
                                       gpointer address,
                                       guint size,
                                       const GumCpuContext * cpu_context)
{
  gpointer value;

  if (!g_atomic_int_get (&self->enabled))
    return;

  if (self->backtracer_instance != NULL)
  {
    gboolean do_backtrace = TRUE;
    GumReturnAddressArray return_addresses;
    GumAllocationTrackerBlock * block;

    if (self->filter_func != NULL)
    {
      do_backtrace = self->filter_func (self, address, size,
          self->filter_func_user_data);
    }

    if (do_backtrace)
    {
      self->backtracer_iface->generate (self->backtracer_instance, cpu_context,
          &return_addresses, GUM_MAX_BACKTRACE_DEPTH);
    }
    else
    {
      return_addresses.len = 0;
    }

    block = (GumAllocationTrackerBlock *)
        g_malloc (sizeof (GumAllocationTrackerBlock) +
            (return_addresses.len * sizeof (GumReturnAddress)));
    block->size = size;
    block->return_addresses[return_addresses.len] = NULL;

    if (return_addresses.len > 0)
    {
      memcpy (block->return_addresses, &return_addresses.items,
          return_addresses.len * sizeof (GumReturnAddress));
    }

    value = block;
  }
  else
  {
    value = GUINT_TO_POINTER (size);
  }

  GUM_ALLOCATION_TRACKER_LOCK (self);

  g_hash_table_insert (self->known_blocks_ht, address, value);

  gum_allocation_tracker_size_stats_add_block (self, size);

  GUM_ALLOCATION_TRACKER_UNLOCK (self);
}

void
gum_allocation_tracker_on_free_full (GumAllocationTracker * self,
                                     gpointer address,
                                     const GumCpuContext * cpu_context)
{
  gpointer value;

  if (!g_atomic_int_get (&self->enabled))
    return;

  GUM_ALLOCATION_TRACKER_LOCK (self);

  value = g_hash_table_lookup (self->known_blocks_ht, address);
  if (value != NULL)
  {
    guint size;

    if (self->backtracer_instance != NULL)
      size = ((GumAllocationTrackerBlock *) value)->size;
    else
      size = GPOINTER_TO_UINT (value);

    gum_allocation_tracker_size_stats_remove_block (self, size);

    g_hash_table_remove (self->known_blocks_ht, address);
  }

  GUM_ALLOCATION_TRACKER_UNLOCK (self);
}

void
gum_allocation_tracker_on_realloc_full (GumAllocationTracker * self,
                                        gpointer old_address,
                                        gpointer new_address,
                                        guint new_size,
                                        const GumCpuContext * cpu_context)
{
  if (!g_atomic_int_get (&self->enabled))
    return;

  if (old_address != NULL)
  {
    if (new_size != 0)
    {
      gpointer value;

      GUM_ALLOCATION_TRACKER_LOCK (self);

      value = g_hash_table_lookup (self->known_blocks_ht, old_address);
      if (value != NULL)
      {
        guint old_size;

        g_hash_table_steal (self->known_blocks_ht, old_address);

        if (self->backtracer_instance != NULL)
        {
          GumAllocationTrackerBlock * block;

          block = (GumAllocationTrackerBlock *) value;

          g_hash_table_insert (self->known_blocks_ht, new_address, block);

          old_size = block->size;
          block->size = new_size;
        }
        else
        {
          g_hash_table_insert (self->known_blocks_ht, new_address,
              GUINT_TO_POINTER (new_size));

          old_size = GPOINTER_TO_UINT (value);
        }

        gum_allocation_tracker_size_stats_remove_block (self, old_size);
        gum_allocation_tracker_size_stats_add_block (self, new_size);
      }

      GUM_ALLOCATION_TRACKER_UNLOCK (self);
    }
    else
    {
      gum_allocation_tracker_on_free_full (self, old_address, cpu_context);
    }
  }
  else
  {
    gum_allocation_tracker_on_malloc_full (self, new_address, new_size,
        cpu_context);
  }
}

static void
gum_allocation_tracker_size_stats_add_block (GumAllocationTracker * self,
                                             guint size)
{
  GumAllocationGroup * group;

  self->block_count++;
  self->block_total_size += size;

  group = g_hash_table_lookup (self->block_groups_ht, GUINT_TO_POINTER (size));

  if (group == NULL)
  {
    group = gum_allocation_group_new (size);
    g_hash_table_insert (self->block_groups_ht, GUINT_TO_POINTER (size),
        group);
  }

  group->alive_now++;
  if (group->alive_now > group->alive_peak)
    group->alive_peak = group->alive_now;
  group->total_peak++;
}

static void
gum_allocation_tracker_size_stats_remove_block (GumAllocationTracker * self,
                                                guint size)
{
  GumAllocationGroup * group;

  self->block_count--;
  self->block_total_size -= size;

  group = g_hash_table_lookup (self->block_groups_ht, GUINT_TO_POINTER (size));
  group->alive_now--;
}

"""

```