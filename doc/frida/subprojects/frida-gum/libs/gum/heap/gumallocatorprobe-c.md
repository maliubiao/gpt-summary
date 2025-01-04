Response:
Let's break down the thought process for analyzing this Frida code.

**1. Understanding the Core Purpose:**

The first step is to read the initial comments and the overall structure. The file name "gumallocatorprobe.c" and the inclusion of headers like "guminterceptor.h" and "gumallocationtracker.h" strongly suggest this component is about *probing* or *monitoring* memory allocations. The "fridaDynamic instrumentation tool" context confirms it's used for runtime analysis.

**2. Identifying Key Data Structures:**

Next, I'd look for the main data structures. `GumAllocatorProbe` is clearly the central class. I'd examine its members:

* `interceptor`: This immediately points to Frida's interception mechanism. It suggests this code hooks into function calls.
* `function_contexts`:  This likely holds information about the functions being hooked. The `GPtrArray` implies multiple functions can be monitored.
* `allocation_tracker`: This confirms the purpose of tracking allocations.
* `enable_counters`, `malloc_count`, etc.: These are for basic statistics.

Then, I'd look at related structures:

* `FunctionContext`: Seems to store handlers for entering and leaving functions, plus thread-specific data.
* `ThreadContext`, `AllocThreadContext`, `ReallocThreadContext`, `FreeThreadContext`: These are specialized contexts for different allocation-related functions, carrying CPU context and function-specific arguments.
* `HeapHandlers`: A simple structure to bundle enter and leave handlers.

**3. Tracing the Workflow (Attaching and Detaching):**

I'd then look for key functions that manage the probe's lifecycle:

* `gum_allocator_probe_new()`: The constructor.
* `gum_allocator_probe_attach()` and `gum_allocator_probe_attach_to_apis()`:  These are crucial for understanding *how* the probe starts monitoring. The call to `gum_process_find_heap_apis()` and the loop iterating through `apis` reveals that it targets standard heap allocation functions. The `#define` macros (`GUM_ATTACH_TO_API_FUNC`) simplify the attachment process.
* `gum_allocator_probe_detach()`: The counterpart to `attach`, responsible for cleaning up.

**4. Analyzing the Interception Logic:**

The functions `gum_allocator_probe_on_enter()` and `gum_allocator_probe_on_leave()` are the heart of the interception mechanism. They are called by Frida when a hooked function is entered or exited.

* `gum_allocator_probe_on_enter()`: It gets the `FunctionContext`, marks the current thread to be ignored by the interceptor *temporarily* (to prevent recursive interception if the handlers themselves allocate memory), and calls the function-specific `enter_handler`.
* `gum_allocator_probe_on_leave()`:  It does the opposite of the "ignore" and calls the `leave_handler` if it exists and the thread wasn't marked as ignored.

**5. Examining the Handlers:**

The `on_*_enter_handler` and `on_*_leave_handler` functions are the core logic for each type of allocation function (malloc, calloc, realloc, free).

* **Enter Handlers:**  They typically extract the arguments of the intercepted function (like size for `malloc`) and store them in the thread-specific context.
* **Leave Handlers (for allocation):** They get the return value (the allocated address), and if it's valid, they call `gum_allocator_probe_on_malloc()` or `gum_allocator_probe_on_realloc()` to notify the `allocation_tracker`.
* **Enter Handler (for free):**  It gets the address to be freed and calls `gum_allocator_probe_on_free()`.

The `*_dbg` variants handle debug versions of the allocation functions and involve checking the block type.

**6. Connecting to Reverse Engineering and Underlying Systems:**

At this point, I'd start connecting the dots to the prompt's specific questions:

* **Reverse Engineering:**  The entire purpose of this code is for dynamic analysis, a key reverse engineering technique. The interception allows you to observe memory allocation behavior at runtime.
* **Binary/Linux/Android Kernel/Framework:** The code interacts with low-level concepts like memory addresses, CPU contexts, and threads. The `#include` of `gumprocess.h` suggests it interacts with process information, likely from the OS. While the code itself doesn't delve into kernel specifics, Frida, as a whole, relies on OS-level primitives for interception. On Android, this would involve interacting with the Android runtime and potentially native libraries.
* **Logic and Assumptions:** I'd consider the assumptions the code makes (e.g., the structure of arguments and return values of the hooked functions) and how the different handlers process this information.
* **User Errors:**  I'd think about how a user might misuse the API or misunderstand its behavior. For instance, attaching to the wrong processes or misinterpreting the collected data.
* **User Steps to Reach the Code:** I'd imagine a typical Frida workflow: attaching to a process, creating an instance of `GumAllocatorProbe`, and calling `attach()`.

**7. Identifying Advanced Features (Suppressions):**

The `gum_allocator_probe_suppress()` and related logic for default suppressions are an interesting detail. They show a way to filter out noise by ignoring allocations happening within specific functions (like glib's internal functions). This is important for focused analysis.

**8. Iterative Refinement:**

Throughout the process, I'd revisit sections of the code as my understanding grows, clarifying the roles of different functions and data structures. For example, initially, I might not fully grasp the purpose of the `ThreadContext` array in `FunctionContext`, but as I analyze the `on_enter` and `on_leave` handlers, it becomes clearer that this is a way to store thread-local information during the interception.

By following this structured approach, moving from the general purpose to specific details, and connecting the code to the broader context of Frida and system-level concepts, you can effectively analyze and explain the functionality of this `gumallocatorprobe.c` file.
这个 `gumallocatorprobe.c` 文件是 Frida 工具中一个用于监控和追踪内存分配行为的关键组件。它的主要功能是拦截目标进程中的内存分配和释放相关的函数调用，并记录这些事件，以便进行动态分析和调试。

以下是它的具体功能，以及与逆向、底层知识、逻辑推理和用户错误的相关说明：

**功能列举:**

1. **拦截内存分配函数:**  它可以拦截标准 C 库中的内存分配函数，例如 `malloc`, `calloc`, `realloc`, `free`。  通过 Frida 的 `GumInterceptor` 机制，它可以在这些函数执行前后插入自己的代码。
2. **追踪内存分配:**  当 `malloc` 或 `calloc` 被调用时，它可以记录分配的内存地址和大小。
3. **追踪内存释放:** 当 `free` 被调用时，它可以记录被释放的内存地址。
4. **追踪内存重分配:** 当 `realloc` 被调用时，它可以记录旧的内存地址、新的内存地址和新的大小。
5. **记录调用上下文:** 它可以获取调用内存分配函数的 CPU 上下文 (`GumCpuContext`)，这包括寄存器的值、指令指针等信息，可以用来追踪调用栈。
6. **提供计数器:** 可以选择启用计数器来统计 `malloc`, `realloc`, `free` 的调用次数。
7. **支持调试版本的内存分配函数:**  对于一些平台，例如 Windows，它也支持拦截调试版本的内存分配函数，例如 `_malloc_dbg`, `_calloc_dbg`, `_realloc_dbg`, `_free_dbg`。这些调试版本通常包含额外的参数，例如分配类型信息。
8. **抑制特定函数的拦截:** 它允许用户指定一些函数，在这些函数内部发生的内存分配/释放事件将被忽略，这可以用于减少噪音，专注于分析特定的代码区域。
9. **与 `GumAllocationTracker` 集成:** 它可以将追踪到的内存分配信息传递给 `GumAllocationTracker` 组件，后者可以提供更高级的内存分析功能，例如检测内存泄漏、悬挂指针等。
10. **线程隔离:**  为每个线程维护单独的上下文信息 (`ThreadContext`)，避免多线程环境下的数据竞争。

**与逆向方法的关联及举例:**

* **动态分析:** `gumallocatorprobe.c` 本身就是动态分析的核心组成部分。逆向工程师可以使用它来观察目标程序在运行时的内存分配行为，理解程序的内存管理策略。
    * **举例:** 逆向工程师想要分析一个程序是否发生了内存泄漏。他们可以使用 Frida 脚本加载 `GumAllocatorProbe` 并启用 `GumAllocationTracker`，监控程序的运行。如果发现程序在执行一段时间后，分配的内存持续增长而释放的内存很少，就可以初步判断存在内存泄漏。
* **理解数据结构:** 通过观察特定数据结构的内存分配过程，逆向工程师可以推断出该数据结构的布局和大小。
    * **举例:**  逆向工程师在一个游戏中发现了一个未知的对象。他们可以 hook 这个对象相关的函数，观察在创建这个对象时调用了哪些内存分配函数，分配了多少内存，从而推测出对象内部成员变量的大小和类型。
* **寻找漏洞:** 内存分配和释放相关的错误是常见的安全漏洞来源。通过监控内存分配行为，可以发现潜在的堆溢出、释放后使用等漏洞。
    * **举例:** 逆向工程师想要检查一个程序是否存在堆溢出漏洞。他们可以 hook `malloc` 和 `memcpy` 等函数，记录分配的内存大小和复制的数据大小。如果发现 `memcpy` 尝试写入的数据超过了分配的内存大小，就可能存在堆溢出漏洞。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例:**

* **二进制层面:** 该代码直接操作函数地址，通过 `GumInterceptor` 修改目标进程的指令流，实现 hook 功能。这需要理解目标平台的调用约定、指令集架构等底层知识。
    * **举例:**  Frida 需要知道目标平台上 `malloc` 函数的入口地址，才能在其入口处插入 hook 代码。这个地址是二进制层面的概念。
* **Linux 系统:** 在 Linux 系统上，内存分配通常通过 `glibc` 提供的 `malloc`, `calloc` 等函数实现。`gumallocatorprobe.c` 需要了解这些函数的接口和行为。
    * **举例:**  `gum_process_find_heap_apis()` 函数可能需要读取 `/proc/<pid>/maps` 文件来找到 `glibc` 库的加载地址，从而定位内存分配函数的地址。
* **Android 内核及框架:** 在 Android 系统上，native 代码的内存分配也主要依赖于 `libc` (Bionic libc)。`gumallocatorprobe.c` 在 Android 上也能工作，需要适配 Android 的内存管理机制。
    * **举例:**  在 Android 上，可能需要处理 ART 虚拟机的内存管理以及 native heap 的分配。`gum_allocator_probe_attach_to_apis` 函数需要能够找到 Android 系统中 `malloc` 等函数的地址。
* **调试符号:**  为了更方便地定位要 hook 的函数，通常会使用调试符号。`GumSymbolUtil` 模块可以用来解析符号表，将函数名映射到内存地址。

**逻辑推理及假设输入与输出:**

假设我们 hook 了 `malloc` 函数，并设置了 `enable_counters` 为 `TRUE`。

* **假设输入:**  目标程序调用 `malloc(1024)` 三次，`malloc(512)` 一次，然后调用 `free` 释放其中两个 1024 字节的内存块。
* **逻辑推理:**
    1. 每次 `malloc` 调用时，`on_malloc_enter_handler` 会记录分配的大小。
    2. 每次 `malloc` 返回时，`on_shared_xalloc_leave_handler` 会获取返回的内存地址，并调用 `gum_allocator_probe_on_malloc`，同时 `self->malloc_count` 会递增。
    3. 每次 `free` 调用时，`on_free_enter_handler` 会记录被释放的内存地址，并调用 `gum_allocator_probe_on_free`，同时 `self->free_count` 会递增。
* **预期输出:**
    * `malloc_count` 的值为 4。
    * `free_count` 的值为 2。
    * `allocation_tracker` 中会记录四次分配事件和两次释放事件，包含分配的地址、大小和 CPU 上下文。

**用户或编程常见的使用错误及举例:**

* **Hook 了错误的函数:** 用户可能错误地认为某个函数是内存分配函数并尝试 hook 它，导致程序行为异常或 Frida 报错。
    * **举例:**  用户尝试 hook 一个名为 `allocate_buffer` 的函数，但实际上这个函数只是在一个预先分配好的缓冲区中进行操作，并没有调用 `malloc`。
* **忘记 detach:** 在完成分析后，如果没有调用 `gum_allocator_probe_detach` 来移除 hook，可能会导致目标程序的性能下降，甚至崩溃。
* **在不安全的时机操作内存:**  在 hook 函数内部执行的操作可能会与目标程序的内存管理逻辑产生冲突，导致未定义的行为。
    * **举例:**  在 `free` 的 hook 中尝试访问已经被释放的内存。
* **误解计数器的含义:** 用户可能错误地认为 `malloc_count` 就是当前已分配的内存块数量，而忽略了 `free` 的调用。
* **未处理多线程问题:**  如果直接访问共享数据而没有适当的同步机制，在多线程环境下可能会出现数据竞争。虽然 `gumallocatorprobe.c` 自身考虑了线程隔离，但用户在编写自定义的处理逻辑时需要注意。

**用户操作是如何一步步到达这里的调试线索:**

1. **用户编写 Frida 脚本:** 用户首先会编写一个 Frida 脚本 (通常是 JavaScript 或 Python)。
2. **脚本中创建 `GumAllocatorProbe` 实例:**  脚本中会使用 Frida 提供的 API 创建一个 `GumAllocatorProbe` 的实例。例如，在 JavaScript 中可能是 `const allocatorProbe = new Frida.AllocatorProbe();`。
3. **配置 `GumAllocatorProbe` (可选):** 用户可能会设置一些属性，例如 `enable-counters` 或指定 `allocation-tracker`。
4. **调用 `attach` 方法:** 脚本会调用 `allocatorProbe.attach()` 方法，或者 `allocatorProbe.attach(moduleName, functionName)` 来指定要 hook 的内存分配函数。这会最终调用到 `gumallocatorprobe.c` 中的 `gum_allocator_probe_attach` 或相关的函数。
5. **Frida 将脚本注入目标进程:** Frida 框架会将用户的脚本注入到目标进程中执行。
6. **目标进程执行内存分配函数:** 当目标进程执行到被 hook 的内存分配函数时，`GumInterceptor` 会捕获这次调用。
7. **调用 `gum_allocator_probe_on_enter`:** `GumInterceptor` 会调用 `gumallocatorprobe.c` 中实现的 `gum_allocator_probe_on_enter` 函数，并将上下文信息传递给它。
8. **执行相应的 enter/leave handler:**  根据被 hook 的函数，会执行相应的 `on_malloc_enter_handler`, `on_free_enter_handler` 等函数，记录内存分配信息。
9. **用户在脚本中获取或处理数据:** 用户可以在脚本中读取 `GumAllocatorProbe` 的属性（例如 `malloc_count`）或者处理 `GumAllocationTracker` 收集到的数据。
10. **用户调用 `detach` 方法:** 分析完成后，用户可能会调用 `allocatorProbe.detach()` 来移除 hook。

**调试线索:** 如果在调试过程中发现内存分配追踪有问题，可以检查以下步骤：

* **确认 Frida 是否成功注入目标进程。**
* **检查 Frida 脚本中是否正确创建和配置了 `GumAllocatorProbe` 实例。**
* **确认 `attach` 方法是否成功调用，并且目标函数的地址是否正确。**
* **查看 Frida 的日志输出，是否有相关的错误信息。**
* **在 `gum_allocator_probe_on_enter` 和 `gum_allocator_probe_on_leave` 等关键函数中添加断点或日志输出，观察程序的执行流程和变量的值。**
* **检查是否与其他 Frida 脚本或 hook 产生了冲突。**

总而言之，`gumallocatorprobe.c` 是 Frida 中一个强大且基础的组件，它为动态内存分析提供了必要的底层支持，并与其他 Frida 模块协同工作，帮助逆向工程师理解程序的内存行为。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/libs/gum/heap/gumallocatorprobe.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2008-2021 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2008 Christian Berentsen <jc.berentsen@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumallocatorprobe.h"

#include "gum-init.h"
#include "guminterceptor.h"
#include "gumprocess.h"
#include "gumsymbolutil.h"

#define DEFAULT_ENABLE_COUNTERS FALSE

#define GUM_DBGCRT_UNKNOWN_BLOCK (-1)
#define GUM_DBGCRT_NORMAL_BLOCK (1)

#define GUM_DBGCRT_BLOCK_TYPE(type_bits) ((type_bits) & 0xffff)

typedef struct _FunctionContext      FunctionContext;
typedef struct _HeapHandlers         HeapHandlers;
typedef struct _ThreadContext        ThreadContext;
typedef struct _AllocThreadContext   AllocThreadContext;
typedef struct _ReallocThreadContext ReallocThreadContext;

typedef void (* HeapEnterHandler) (GumAllocatorProbe * self,
    gpointer thread_ctx, GumInvocationContext * invocation_ctx,
    gpointer user_data);
typedef void (* HeapLeaveHandler) (GumAllocatorProbe * self,
    gpointer thread_ctx, GumInvocationContext * invocation_ctx,
    gpointer user_data);

typedef gint (* GumReportBlockTypeFunc) (gpointer block);

struct _GumAllocatorProbe
{
  GObject parent;

  gboolean disposed;

  GumInterceptor * interceptor;
  GPtrArray * function_contexts;
  GumAllocationTracker * allocation_tracker;

  gboolean enable_counters;
  guint malloc_count;
  guint realloc_count;
  guint free_count;
};

enum
{
  PROP_0,
  PROP_ALLOCATION_TRACKER,
  PROP_ENABLE_COUNTERS,
  PROP_MALLOC_COUNT,
  PROP_REALLOC_COUNT,
  PROP_FREE_COUNT
};

struct _ThreadContext
{
  gboolean ignored;
  GumCpuContext cpu_context;
  gpointer function_specific_storage[4];
};

struct _HeapHandlers
{
  HeapEnterHandler enter_handler;
  HeapLeaveHandler leave_handler;
};

struct _FunctionContext
{
  HeapHandlers handlers;
  gpointer handler_data;
  ThreadContext thread_contexts[GUM_MAX_THREADS];
  volatile gint thread_context_count;
};

struct _AllocThreadContext
{
  gboolean ignored;
  GumCpuContext cpu_context;
  gsize size;
};

struct _ReallocThreadContext
{
  gboolean ignored;
  GumCpuContext cpu_context;
  gpointer old_address;
  gsize new_size;
};

struct _FreeThreadContext
{
  gboolean ignored;
  GumCpuContext cpu_context;
  gpointer address;
};

static void gum_allocator_probe_deinit (void);

static void gum_allocator_probe_listener_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_allocator_probe_dispose (GObject * object);
static void gum_allocator_probe_finalize (GObject * object);
static void gum_allocator_probe_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);
static void gum_allocator_probe_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);

static void gum_allocator_probe_apply_default_suppressions (
    GumAllocatorProbe * self);

static void gum_allocator_probe_on_enter (GumInvocationListener * listener,
    GumInvocationContext * context);
static void gum_allocator_probe_on_leave (GumInvocationListener * listener,
    GumInvocationContext * context);

static void attach_to_function (GumAllocatorProbe * self,
    gpointer function_address, const HeapHandlers * function_handlers,
    gpointer user_data);

static void gum_allocator_probe_on_malloc (GumAllocatorProbe * self,
    gpointer address, guint size, const GumCpuContext * cpu_context);
static void gum_allocator_probe_on_free (GumAllocatorProbe * self,
    gpointer address, const GumCpuContext * cpu_context);
static void gum_allocator_probe_on_realloc (GumAllocatorProbe * self,
    gpointer old_address, gpointer new_address, guint new_size,
    const GumCpuContext * cpu_context);

static void on_malloc_enter_handler (GumAllocatorProbe * self,
    AllocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_calloc_enter_handler (GumAllocatorProbe * self,
    AllocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_shared_xalloc_leave_handler (GumAllocatorProbe * self,
    AllocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_realloc_enter_handler (GumAllocatorProbe * self,
    ReallocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_realloc_leave_handler (GumAllocatorProbe * self,
    ReallocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_free_enter_handler (GumAllocatorProbe * self,
    gpointer thread_ctx, GumInvocationContext * invocation_ctx);

static void on_malloc_dbg_enter_handler (GumAllocatorProbe * self,
    AllocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_calloc_dbg_enter_handler (GumAllocatorProbe * self,
    AllocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_realloc_dbg_enter_handler (GumAllocatorProbe * self,
    ReallocThreadContext * thread_ctx, GumInvocationContext * invocation_ctx);
static void on_free_dbg_enter_handler (GumAllocatorProbe * self,
    ThreadContext * thread_ctx, GumInvocationContext * invocation_ctx,
    gpointer user_data);

static void decide_ignore_from_block_type (ThreadContext * thread_ctx,
    gint block_type);

G_DEFINE_TYPE_EXTENDED (GumAllocatorProbe,
                        gum_allocator_probe,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_INVOCATION_LISTENER,
                            gum_allocator_probe_listener_iface_init))

G_LOCK_DEFINE (_gum_allocator_probe_ignored_functions);
static GArray * _gum_allocator_probe_ignored_functions = NULL;

static void
gum_allocator_probe_class_init (GumAllocatorProbeClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);
  GParamSpec * pspec;

  object_class->set_property = gum_allocator_probe_set_property;
  object_class->get_property = gum_allocator_probe_get_property;
  object_class->dispose = gum_allocator_probe_dispose;
  object_class->finalize = gum_allocator_probe_finalize;

  pspec = g_param_spec_object ("allocation-tracker", "AllocationTracker",
      "AllocationTracker to use", GUM_TYPE_ALLOCATION_TRACKER,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_ALLOCATION_TRACKER,
      pspec);

  pspec = g_param_spec_boolean ("enable-counters", "Enable Counters",
      "Enable counters for probed functions", DEFAULT_ENABLE_COUNTERS,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_ENABLE_COUNTERS,
      pspec);

  pspec = g_param_spec_uint ("malloc-count", "Malloc Count",
      "Number of malloc() calls seen so far", 0, G_MAXUINT, 0,
      (GParamFlags) (G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_MALLOC_COUNT, pspec);

  pspec = g_param_spec_uint ("realloc-count", "Realloc Count",
      "Number of realloc() calls seen so far", 0, G_MAXUINT, 0,
      (GParamFlags) (G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_REALLOC_COUNT, pspec);

  pspec = g_param_spec_uint ("free-count", "Free Count",
      "Number of free() calls seen so far", 0, G_MAXUINT, 0,
      (GParamFlags) (G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_FREE_COUNT, pspec);

  _gum_register_destructor (gum_allocator_probe_deinit);
}

static void
gum_allocator_probe_deinit (void)
{
  if (_gum_allocator_probe_ignored_functions != NULL)
  {
    g_array_free (_gum_allocator_probe_ignored_functions, TRUE);
    _gum_allocator_probe_ignored_functions = NULL;
  }
}

static void
gum_allocator_probe_listener_iface_init (gpointer g_iface,
                                         gpointer iface_data)
{
  GumInvocationListenerInterface * iface = g_iface;

  iface->on_enter = gum_allocator_probe_on_enter;
  iface->on_leave = gum_allocator_probe_on_leave;
}

static void
gum_allocator_probe_init (GumAllocatorProbe * self)
{
  self->interceptor = gum_interceptor_obtain ();
  self->function_contexts = g_ptr_array_sized_new (3);

  self->enable_counters = DEFAULT_ENABLE_COUNTERS;
}

static void
gum_allocator_probe_dispose (GObject * object)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE (object);

  if (!self->disposed)
  {
    self->disposed = TRUE;

    gum_allocator_probe_detach (self);

    g_clear_object (&self->allocation_tracker);

    g_clear_object (&self->interceptor);
  }

  G_OBJECT_CLASS (gum_allocator_probe_parent_class)->dispose (object);
}

static void
gum_allocator_probe_finalize (GObject * object)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE (object);

  g_ptr_array_free (self->function_contexts, TRUE);

  G_OBJECT_CLASS (gum_allocator_probe_parent_class)->finalize (object);
}

static void
gum_allocator_probe_set_property (GObject * object,
                                  guint property_id,
                                  const GValue * value,
                                  GParamSpec * pspec)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE (object);

  switch (property_id)
  {
    case PROP_ALLOCATION_TRACKER:
      if (self->allocation_tracker != NULL)
        g_object_unref (self->allocation_tracker);
      self->allocation_tracker = g_value_dup_object (value);
      break;
    case PROP_ENABLE_COUNTERS:
      self->enable_counters = g_value_get_boolean (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_allocator_probe_get_property (GObject * object,
                                  guint property_id,
                                  GValue * value,
                                  GParamSpec * pspec)
{
  GumAllocatorProbe * self = GUM_ALLOCATOR_PROBE (object);

  switch (property_id)
  {
    case PROP_ALLOCATION_TRACKER:
      g_value_set_object (value, self->allocation_tracker);
      break;
    case PROP_ENABLE_COUNTERS:
      g_value_set_boolean (value, self->enable_counters);
      break;
    case PROP_MALLOC_COUNT:
      g_value_set_uint (value, self->malloc_count);
      break;
    case PROP_REALLOC_COUNT:
      g_value_set_uint (value, self->realloc_count);
      break;
    case PROP_FREE_COUNT:
      g_value_set_uint (value, self->free_count);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static gboolean
gum_allocator_probe_add_suppression_addresses_if_glib (
    const GumModuleDetails * details,
    gpointer user_data)
{
  static const gchar * glib_function_name[] = {
    "g_quark_from_string",
    "g_quark_from_static_string",
    NULL
  };
  static const gchar * gobject_function_name[] = {
    "g_signal_connect_data",
    "g_signal_handlers_destroy",
    "g_type_register_static",
    "g_type_add_interface_static",
    "g_param_spec_pool_insert",
    NULL
  };
  GArray * ignored = (GArray *) user_data;
  gchar * name_lowercase;
  static const gchar ** function_name;

  name_lowercase = g_ascii_strdown (details->name, -1);

  if (g_strstr_len (name_lowercase, -1, "glib-2.0") != NULL)
    function_name = glib_function_name;
  else if (g_strstr_len (name_lowercase, -1, "gobject-2.0") != NULL)
    function_name = gobject_function_name;
  else
    function_name = NULL;

  if (function_name != NULL)
  {
    guint i;

    for (i = 0; function_name[i] != NULL; i++)
    {
      gpointer address = GSIZE_TO_POINTER (gum_module_find_export_by_name (
          details->path, function_name[i]));
      g_array_append_val (ignored, address);
    }
  }

  g_free (name_lowercase);

  return TRUE;
}

static void
gum_allocator_probe_apply_default_suppressions (GumAllocatorProbe * self)
{
  GumInterceptor * interceptor = self->interceptor;
  GArray * ignored;
  guint i;

  G_LOCK (_gum_allocator_probe_ignored_functions);

  if (_gum_allocator_probe_ignored_functions == NULL)
  {
    static const gchar * internal_function_name[] = {
        "g_quark_new",
        "instance_real_class_set",
        "instance_real_class_remove",
        "gst_object_set_name_default"
    };

    ignored = g_array_new (FALSE, FALSE, sizeof (gpointer));

    for (i = 0; i != G_N_ELEMENTS (internal_function_name); i++)
    {
      GArray * addrs = gum_find_functions_named (internal_function_name[i]);
      if (addrs->len != 0)
        g_array_append_vals (ignored, addrs->data, addrs->len);
      g_array_free (addrs, TRUE);
    }

    gum_process_enumerate_modules (
        gum_allocator_probe_add_suppression_addresses_if_glib, ignored);

    _gum_allocator_probe_ignored_functions = ignored;
  }
  else
  {
    ignored = _gum_allocator_probe_ignored_functions;
  }

  G_UNLOCK (_gum_allocator_probe_ignored_functions);

  gum_interceptor_begin_transaction (interceptor);

  for (i = 0; i != ignored->len; i++)
    gum_allocator_probe_suppress (self, g_array_index (ignored, gpointer, i));

  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_quark_from_string));
  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_quark_from_static_string));

  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_signal_connect_data));
  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_signal_handlers_destroy));
  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_type_register_static));
  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_type_add_interface_static));
  gum_allocator_probe_suppress (self,
      GUM_FUNCPTR_TO_POINTER (g_param_spec_pool_insert));

  gum_interceptor_end_transaction (interceptor);
}

static void
gum_allocator_probe_on_enter (GumInvocationListener * listener,
                              GumInvocationContext * context)
{
  GumAllocatorProbe * self;
  FunctionContext * function_ctx;

  self = GUM_ALLOCATOR_PROBE (listener);
  function_ctx = GUM_IC_GET_FUNC_DATA (context, FunctionContext *);

  gum_interceptor_ignore_current_thread (self->interceptor);

  if (function_ctx != NULL)
  {
    ThreadContext * base_thread_ctx;

    base_thread_ctx = GUM_IC_GET_INVOCATION_DATA (context, ThreadContext);
    base_thread_ctx->ignored = FALSE;

    function_ctx->handlers.enter_handler (self, base_thread_ctx, context,
        function_ctx->handler_data);
  }
}

static void
gum_allocator_probe_on_leave (GumInvocationListener * listener,
                              GumInvocationContext * context)
{
  GumAllocatorProbe * self;
  FunctionContext * function_ctx;

  self = GUM_ALLOCATOR_PROBE (listener);
  function_ctx = GUM_IC_GET_FUNC_DATA (context, FunctionContext *);

  if (function_ctx != NULL)
  {
    ThreadContext * base_thread_ctx;

    base_thread_ctx = GUM_IC_GET_INVOCATION_DATA (context, ThreadContext);

    if (!base_thread_ctx->ignored)
    {
      if (function_ctx->handlers.leave_handler != NULL)
      {
        function_ctx->handlers.leave_handler (self, base_thread_ctx,
            context, function_ctx->handler_data);
      }
    }
  }

  gum_interceptor_unignore_current_thread (self->interceptor);
}

GumAllocatorProbe *
gum_allocator_probe_new (void)
{
  return g_object_new (GUM_TYPE_ALLOCATOR_PROBE, NULL);
}

static const HeapHandlers gum_malloc_handlers =
{
  (HeapEnterHandler) on_malloc_enter_handler,
  (HeapLeaveHandler) on_shared_xalloc_leave_handler
};

static const HeapHandlers gum_calloc_handlers =
{
  (HeapEnterHandler) on_calloc_enter_handler,
  (HeapLeaveHandler) on_shared_xalloc_leave_handler
};

static const HeapHandlers gum_realloc_handlers =
{
  (HeapEnterHandler) on_realloc_enter_handler,
  (HeapLeaveHandler) on_realloc_leave_handler
};

static const HeapHandlers gum_free_handlers =
{
  (HeapEnterHandler) on_free_enter_handler,
  NULL
};

static const HeapHandlers gum__malloc_dbg_handlers =
{
  (HeapEnterHandler) on_malloc_dbg_enter_handler,
  (HeapLeaveHandler) on_shared_xalloc_leave_handler
};

static const HeapHandlers gum__calloc_dbg_handlers =
{
  (HeapEnterHandler) on_calloc_dbg_enter_handler,
  (HeapLeaveHandler) on_shared_xalloc_leave_handler
};

static const HeapHandlers gum__realloc_dbg_handlers =
{
  (HeapEnterHandler) on_realloc_dbg_enter_handler,
  (HeapLeaveHandler) on_realloc_leave_handler
};

static const HeapHandlers gum__free_dbg_handlers =
{
  (HeapEnterHandler) on_free_dbg_enter_handler,
  NULL
};

void
gum_allocator_probe_attach (GumAllocatorProbe * self)
{
  GumHeapApiList * apis = gum_process_find_heap_apis ();
  gum_allocator_probe_attach_to_apis (self, apis);
  gum_heap_api_list_free (apis);
}

#define GUM_ATTACH_TO_API_FUNC(name) \
    attach_to_function (self, GUM_FUNCPTR_TO_POINTER (api->name), \
        &gum_##name##_handlers, NULL)
#define GUM_ATTACH_TO_API_FUNC_WITH_DATA(name, data) \
    attach_to_function (self, GUM_FUNCPTR_TO_POINTER (api->name), \
        &gum_##name##_handlers, data)

void
gum_allocator_probe_attach_to_apis (GumAllocatorProbe * self,
                                    const GumHeapApiList * apis)
{
  guint i;

  gum_interceptor_ignore_current_thread (self->interceptor);
  gum_interceptor_begin_transaction (self->interceptor);

  for (i = 0; i != apis->len; i++)
  {
    const GumHeapApi * api = gum_heap_api_list_get_nth (apis, i);

    GUM_ATTACH_TO_API_FUNC (malloc);
    GUM_ATTACH_TO_API_FUNC (calloc);
    GUM_ATTACH_TO_API_FUNC (realloc);
    GUM_ATTACH_TO_API_FUNC (free);

    if (api->_malloc_dbg != NULL)
    {
      GUM_ATTACH_TO_API_FUNC (_malloc_dbg);
      GUM_ATTACH_TO_API_FUNC (_calloc_dbg);
      GUM_ATTACH_TO_API_FUNC (_realloc_dbg);
      GUM_ATTACH_TO_API_FUNC_WITH_DATA (_free_dbg,
          GUM_FUNCPTR_TO_POINTER (api->_CrtReportBlockType));
    }
  }

  gum_allocator_probe_apply_default_suppressions (self);

  gum_interceptor_end_transaction (self->interceptor);
  gum_interceptor_unignore_current_thread (self->interceptor);
}

void
gum_allocator_probe_detach (GumAllocatorProbe * self)
{
  guint i;

  gum_interceptor_ignore_current_thread (self->interceptor);

  gum_interceptor_detach (self->interceptor, GUM_INVOCATION_LISTENER (self));

  for (i = 0; i < self->function_contexts->len; i++)
  {
    FunctionContext * function_ctx = (FunctionContext *)
        g_ptr_array_index (self->function_contexts, i);
    g_free (function_ctx);
  }

  g_ptr_array_set_size (self->function_contexts, 0);

  self->malloc_count = 0;
  self->realloc_count = 0;
  self->free_count = 0;

  gum_interceptor_unignore_current_thread (self->interceptor);
}

static void
attach_to_function (GumAllocatorProbe * self,
                    gpointer function_address,
                    const HeapHandlers * function_handlers,
                    gpointer user_data)
{
  GumInvocationListener * listener = GUM_INVOCATION_LISTENER (self);
  FunctionContext * function_ctx;

  function_ctx = g_new0 (FunctionContext, 1);
  function_ctx->handlers = *function_handlers;
  function_ctx->handler_data = user_data;
  g_ptr_array_add (self->function_contexts, function_ctx);

  gum_interceptor_attach (self->interceptor, function_address, listener,
      function_ctx);
}

void
gum_allocator_probe_suppress (GumAllocatorProbe * self,
                              gpointer function_address)
{
  GumInvocationListener * listener = GUM_INVOCATION_LISTENER (self);

  gum_interceptor_attach (self->interceptor, function_address, listener, NULL);
}

static void
gum_allocator_probe_on_malloc (GumAllocatorProbe * self,
                               gpointer address,
                               guint size,
                               const GumCpuContext * cpu_context)
{
  if (self->enable_counters)
    self->malloc_count++;

  if (self->allocation_tracker != NULL)
  {
    gum_allocation_tracker_on_malloc_full (self->allocation_tracker, address,
        size, cpu_context);
  }
}

static void
gum_allocator_probe_on_free (GumAllocatorProbe * self,
                             gpointer address,
                             const GumCpuContext * cpu_context)
{
  if (self->enable_counters)
    self->free_count++;

  if (self->allocation_tracker != NULL)
  {
    gum_allocation_tracker_on_free_full (self->allocation_tracker, address,
        cpu_context);
  }
}

static void
gum_allocator_probe_on_realloc (GumAllocatorProbe * self,
                                gpointer old_address,
                                gpointer new_address,
                                guint new_size,
                                const GumCpuContext * cpu_context)
{
  if (self->enable_counters)
    self->realloc_count++;

  if (self->allocation_tracker != NULL)
  {
    gum_allocation_tracker_on_realloc_full (self->allocation_tracker,
        old_address, new_address, new_size, cpu_context);
  }
}

static void
on_malloc_enter_handler (GumAllocatorProbe * self,
                         AllocThreadContext * thread_ctx,
                         GumInvocationContext * invocation_ctx)
{
  thread_ctx->cpu_context = *invocation_ctx->cpu_context;
  thread_ctx->size =
      (gsize) gum_invocation_context_get_nth_argument (invocation_ctx, 0);
}

static void
on_calloc_enter_handler (GumAllocatorProbe * self,
                         AllocThreadContext * thread_ctx,
                         GumInvocationContext * invocation_ctx)
{
  gsize num, size;

  num = (gsize) gum_invocation_context_get_nth_argument (invocation_ctx, 0);
  size = (gsize) gum_invocation_context_get_nth_argument (invocation_ctx, 1);

  thread_ctx->cpu_context = *invocation_ctx->cpu_context;
  thread_ctx->size = num * size;
}

static void
on_shared_xalloc_leave_handler (GumAllocatorProbe * self,
                                AllocThreadContext * thread_ctx,
                                GumInvocationContext * invocation_ctx)
{
  gpointer return_value;

  return_value = gum_invocation_context_get_return_value (invocation_ctx);

  if (return_value != NULL)
  {
    gum_allocator_probe_on_malloc (self, return_value, thread_ctx->size,
        &thread_ctx->cpu_context);
  }
}

static void
on_realloc_enter_handler (GumAllocatorProbe * self,
                          ReallocThreadContext * thread_ctx,
                          GumInvocationContext * invocation_ctx)
{
  thread_ctx->cpu_context = *invocation_ctx->cpu_context;
  thread_ctx->old_address =
      gum_invocation_context_get_nth_argument (invocation_ctx, 0);
  thread_ctx->new_size =
      (gsize) gum_invocation_context_get_nth_argument (invocation_ctx, 1);
}

static void
on_realloc_leave_handler (GumAllocatorProbe * self,
                          ReallocThreadContext * thread_ctx,
                          GumInvocationContext * invocation_ctx)
{
  gpointer return_value;

  return_value = gum_invocation_context_get_return_value (invocation_ctx);

  if (return_value != NULL)
  {
    gum_allocator_probe_on_realloc (self, thread_ctx->old_address,
        return_value, thread_ctx->new_size, &thread_ctx->cpu_context);
  }
}

static void
on_free_enter_handler (GumAllocatorProbe * self,
                       gpointer thread_ctx,
                       GumInvocationContext * invocation_ctx)
{
  gpointer address;

  address = gum_invocation_context_get_nth_argument (invocation_ctx, 0);

  gum_allocator_probe_on_free (self, address, invocation_ctx->cpu_context);
}

static void
on_malloc_dbg_enter_handler (GumAllocatorProbe * self,
                             AllocThreadContext * thread_ctx,
                             GumInvocationContext * invocation_ctx)
{
  gint block_type;

  block_type = (gint) GPOINTER_TO_SIZE (
      gum_invocation_context_get_nth_argument (invocation_ctx, 1));

  decide_ignore_from_block_type ((ThreadContext *) thread_ctx, block_type);

  if (!thread_ctx->ignored)
    on_malloc_enter_handler (self, thread_ctx, invocation_ctx);
}

static void
on_calloc_dbg_enter_handler (GumAllocatorProbe * self,
                             AllocThreadContext * thread_ctx,
                             GumInvocationContext * invocation_ctx)
{
  gint block_type;

  block_type = (gint) GPOINTER_TO_SIZE (
      gum_invocation_context_get_nth_argument (invocation_ctx, 2));

  decide_ignore_from_block_type ((ThreadContext *) thread_ctx, block_type);

  if (!thread_ctx->ignored)
    on_calloc_enter_handler (self, thread_ctx, invocation_ctx);
}

static void
on_realloc_dbg_enter_handler (GumAllocatorProbe * self,
                              ReallocThreadContext * thread_ctx,
                              GumInvocationContext * invocation_ctx)
{
  gint block_type;

  block_type = (gint) GPOINTER_TO_SIZE (
      gum_invocation_context_get_nth_argument (invocation_ctx, 2));

  decide_ignore_from_block_type ((ThreadContext *) thread_ctx, block_type);

  if (!thread_ctx->ignored)
    on_realloc_enter_handler (self, thread_ctx, invocation_ctx);
}

static void
on_free_dbg_enter_handler (GumAllocatorProbe * self,
                           ThreadContext * thread_ctx,
                           GumInvocationContext * invocation_ctx,
                           gpointer user_data)
{
  gint block_type;

  block_type = (gint) GPOINTER_TO_SIZE (
      gum_invocation_context_get_nth_argument (invocation_ctx, 1));
  if (block_type == GUM_DBGCRT_UNKNOWN_BLOCK)
  {
    gpointer block;
    GumReportBlockTypeFunc report_block_type;

    block = gum_invocation_context_get_nth_argument (invocation_ctx, 0);
    report_block_type =
        GUM_POINTER_TO_FUNCPTR (GumReportBlockTypeFunc, user_data);

    block_type = GUM_DBGCRT_BLOCK_TYPE (report_block_type (block));
  }

  decide_ignore_from_block_type ((ThreadContext *) thread_ctx, block_type);

  if (!thread_ctx->ignored)
    on_free_enter_handler (self, thread_ctx, invocation_ctx);
}

static void
decide_ignore_from_block_type (ThreadContext * thread_ctx,
                               gint block_type)
{
  thread_ctx->ignored = (block_type != GUM_DBGCRT_NORMAL_BLOCK);
}

"""

```