Response:
My thought process to analyze the `gumboundschecker.c` code and answer the user's request goes like this:

1. **Understand the Core Purpose:**  The filename and initial comments clearly indicate this is a bounds checker for heap memory within the Frida framework. The core idea is to detect out-of-bounds access (reading or writing beyond allocated memory) and use-after-free errors.

2. **Identify Key Components and Data Structures:** I scan the code for important structs, enums, and macros. This reveals:
    * `GumBoundsChecker`: The main object, holding configuration, state (attached, detaching), and pointers to other components.
    * `GumBoundsHookGroup`:  Used to group hooks for specific heap API functions.
    * `GumPagePool`:  Manages a pool of memory pages with guard pages for detecting overflows/underflows.
    * `GumInterceptor`: Used to intercept standard library functions like `malloc`, `free`, etc.
    * `GumExceptor`:  Used to catch access violation exceptions (SIGSEGV on Linux).
    * `GumBacktracer`: Used to obtain stack traces.
    * Macros like `BLOCK_ALLOC_RETADDRS` and `BLOCK_FREE_RETADDRS` indicate how metadata is stored around allocated blocks.

3. **Trace the Execution Flow - Attachment and Detachment:** I look for functions like `gum_bounds_checker_attach` and `gum_bounds_checker_detach`. This helps understand how the bounds checker is activated and deactivated.
    * **Attach:**  Finds heap API functions, replaces them with custom wrappers (`replacement_malloc`, `replacement_free`, etc.), and initializes the `GumPagePool`.
    * **Detach:** Reverts the replaced functions and cleans up resources.

4. **Analyze the Intercepted Functions (`replacement_...`)**: These are crucial. I examine how `replacement_malloc`, `replacement_calloc`, `replacement_realloc`, and `replacement_free` work:
    * They attempt to allocate/free memory using the `GumPagePool` first.
    * If the `GumPagePool` succeeds, they record allocation/free backtraces.
    * If the `GumPagePool` fails (likely because it's full or the allocation size is too large for the pool), they fall back to the original system `malloc`/`free`. This is an important design choice: the bounds checker doesn't *replace* the system allocator entirely, it augments it for more precise tracking within its controlled pool.

5. **Understand the Exception Handling (`gum_bounds_checker_on_exception`)**: This is the core of the error detection.
    * It checks for access violations (segmentation faults).
    * It verifies if the faulting address belongs to a block managed by the `GumPagePool`.
    * If it's a valid out-of-bounds access, it gathers information (allocation/free backtraces) and calls the `output` function (provided by the user) to report the error.

6. **Identify Interactions with Underlying Systems:** I look for calls to OS-level functionalities:
    * `gum_mprotect`:  This is key. It's used to set memory protection flags on the "guard pages" around allocated blocks, triggering exceptions on out-of-bounds access.
    * Heap API functions (`malloc`, `free`, etc.): These are system calls or calls into the C standard library, tightly linked to the OS.
    * Backtracing relies on architecture-specific mechanisms and potentially debugging symbols.

7. **Consider Reverse Engineering Implications:** The ability to intercept memory allocation and free functions, along with recording backtraces, makes this a powerful tool for reverse engineering. It allows tracing how memory is used and identifying potential vulnerabilities.

8. **Look for Logic and Assumptions:** I try to understand the conditional logic (e.g., the `if (self->detaching || self->handled_invalid_access)` checks) and any assumptions made about the environment. The use of guard pages and backtraces are key assumptions.

9. **Think About User Errors and Debugging:**  What mistakes could a user make that would lead to this code being executed? How can this tool help with debugging?  For example, forgetting to attach the bounds checker or having a small pool size could affect its effectiveness.

10. **Structure the Answer:**  Finally, I organize my findings according to the user's request, covering:
    * Functionality summary.
    * Relationship to reverse engineering with examples.
    * Interactions with the binary level, Linux/Android kernel/framework.
    * Logical reasoning examples (input/output).
    * Common user errors.
    * How the user reaches this code (debugging scenarios).

By following these steps, I can systematically analyze the code and provide a comprehensive and informative answer to the user's questions. The key is to understand the overall purpose, break down the code into manageable parts, and analyze the interactions between those parts and the underlying system.
好的，让我们详细分析一下 `gumboundschecker.c` 文件的功能和相关知识点。

**文件功能概述：**

`gumboundschecker.c` 文件实现了 Frida 的一个核心功能：**堆内存边界检查 (Heap Bounds Checker)**。它的主要目的是在程序运行时检测以下类型的内存错误：

* **堆溢出 (Heap Overflow):**  当程序向堆上分配的内存块写入数据时，超过了该内存块的边界。
* **堆下溢 (Heap Underflow):** 当程序向堆上分配的内存块写入数据时，写入的位置低于该内存块的起始地址。
* **释放后使用 (Use-After-Free):** 当程序尝试访问已经释放的堆内存。
* **重复释放 (Double Free):** 当程序尝试多次释放同一个堆内存块。

**与逆向方法的关系及举例说明：**

堆内存边界检查是逆向工程中非常重要的一个技术，它可以帮助逆向工程师：

* **发现安全漏洞：** 堆溢出和释放后使用是常见的安全漏洞。通过边界检查，可以快速定位这些漏洞，为漏洞分析和利用提供关键信息。
* **理解程序行为：** 观察程序如何分配和释放内存，以及在何处发生内存访问错误，可以帮助逆向工程师更深入地理解程序的内部逻辑和数据结构。
* **动态分析恶意代码：** 恶意代码经常利用堆内存漏洞来执行恶意操作。边界检查可以帮助分析人员识别恶意代码的内存操作模式。

**举例说明：**

假设一个程序存在堆溢出漏洞，当用户输入过长的字符串时，会覆盖堆上相邻的内存区域。使用 Frida 和 `gumboundschecker`，逆向工程师可以：

1. **加载目标进程并附加 Frida。**
2. **创建一个 `GumBoundsChecker` 实例并 attach 到目标进程。**
3. **运行程序并触发漏洞，例如输入一个非常长的字符串。**
4. **`gumboundschecker` 会检测到对已分配内存块的越界写入，并报告错误信息，包括:**
   * 错误类型（例如 "Heap block ... was accessed at offset ...")
   * 发生错误的内存地址和偏移量
   * 发生访问时的堆栈回溯 (如果配置了 Backtracer)
   * 分配该内存块时的堆栈回溯 (如果配置了 Backtracer)
   * 释放该内存块时的堆栈回溯 (如果是 Use-After-Free)

通过这些信息，逆向工程师可以精确定位导致溢出的代码位置，以及被覆盖的内存区域，从而理解漏洞的成因。

**涉及的二进制底层、Linux/Android 内核及框架知识及举例说明：**

`gumboundschecker.c` 的实现涉及到以下底层知识：

* **二进制层面：**
    * **内存布局：** 理解进程的内存空间布局，包括堆、栈等区域。`gumboundschecker` 需要理解堆内存的分配和管理方式。
    * **函数调用约定：**  拦截 (hook) 标准库的内存分配和释放函数（如 `malloc`, `free`, `calloc`, `realloc`）需要了解目标平台的函数调用约定，以便正确替换函数入口地址。
    * **指令集架构：**  Backtracer 功能需要理解目标 CPU 的指令集架构，才能正确解析堆栈信息。
* **Linux/Android 内核：**
    * **内存管理：**  `gumboundschecker` 依赖于操作系统提供的内存管理机制。它通过拦截系统级别的内存分配函数来实现监控。
    * **信号处理：**  `gum_bounds_checker_on_exception` 函数用于处理访问违规信号 (SIGSEGV)，这是操作系统在程序访问非法内存时发出的信号。
    * **`mprotect` 系统调用：** `gumboundschecker` 使用 `mprotect` 系统调用来修改内存页的保护属性，例如设置 guard pages 为不可访问，以便在发生越界访问时触发异常。
* **Frida 框架：**
    * **Gum 引擎：**  `gumboundschecker` 是 Frida Gum 引擎的一部分，利用了 Gum 提供的拦截 (Interceptor) 和异常处理 (Exceptor) 功能。
    * **Backtracer：**  `GumBacktracer` 组件用于获取函数调用堆栈信息。
    * **Page Pool：** `GumPagePool` 用于管理一块预先分配的内存池，用于追踪被监控的堆内存块。

**举例说明：**

* **`gum_interceptor_replace`：**  这个函数是 Frida Gum 引擎提供的 API，用于在运行时替换目标进程中的函数。`gumboundschecker` 使用它来替换 `malloc`, `free` 等函数，以便在这些函数被调用时执行自定义的检查逻辑。这涉及到修改目标进程的内存，需要对进程内存布局和代码注入有深入理解。
* **`gum_exceptor_add`：**  这个函数用于注册一个异常处理回调函数。当目标进程发生异常时（例如访问了受保护的内存页），注册的回调函数 `gum_bounds_checker_on_exception` 会被调用，从而检测到内存访问错误。这依赖于操作系统提供的信号处理机制。
* **`gum_mprotect(block.guard, block.guard_size, GUM_PAGE_NO_ACCESS)`：**  这行代码使用 `mprotect` 系统调用将分配的内存块周围的 "guard pages" 设置为不可访问。当程序尝试访问这些 guard pages 时，会触发访问违规异常，`gumboundschecker` 就可以捕获并报告错误。这直接与 Linux/Android 内核的内存保护机制相关。

**逻辑推理及假设输入与输出：**

`gumboundschecker` 的核心逻辑在于：

1. **拦截内存分配函数：** 当程序调用 `malloc` 等函数时，`gumboundschecker` 的 `replacement_malloc` 会被调用。
2. **使用 Page Pool 分配内存：** `replacement_malloc` 尝试从 `GumPagePool` 中分配内存，并在分配的内存块周围设置 guard pages。
3. **记录分配信息：** 如果配置了 Backtracer，会记录分配时的堆栈信息。
4. **拦截内存释放函数：** 当程序调用 `free` 时，`gumboundschecker` 的 `replacement_free` 会被调用。
5. **标记内存已释放：** `replacement_free` 会将对应的内存块标记为已释放，并记录释放时的堆栈信息。
6. **处理访问违规异常：** 当程序访问 guard pages 或已释放的内存时，会触发访问违规异常。
7. **分析异常信息：** `gum_bounds_checker_on_exception` 函数会分析异常发生的地址，判断是否是由于堆内存越界或释放后使用造成的。
8. **报告错误：** 如果检测到内存错误，会调用用户提供的 `output` 函数报告错误信息，包括错误类型、地址、大小以及相关的堆栈回溯。

**假设输入与输出：**

**假设输入：**

1. 程序调用 `malloc(10)` 分配了地址为 `0x1000` 的 10 字节内存。
2. 程序向地址 `0x100A` 写入一个字节的数据 (堆溢出，越界访问)。

**预期输出（通过 `output` 函数）：**

```
Oops! Heap block 0x1000 of 10 bytes was accessed at offset 10 from:
        <堆栈回溯信息，指示发生访问的代码位置>
Allocated at:
        <堆栈回溯信息，指示分配内存的代码位置>
```

**假设输入：**

1. 程序调用 `malloc(10)` 分配了地址为 `0x2000` 的 10 字节内存。
2. 程序调用 `free(0x2000)` 释放了该内存。
3. 程序再次尝试读取地址 `0x2005` 的数据 (释放后使用)。

**预期输出（通过 `output` 函数）：**

```
Oops! Freed block 0x2000 of 10 bytes was accessed at offset 5 from:
        <堆栈回溯信息，指示发生访问的代码位置>
Allocated at:
        <堆栈回溯信息，指示分配内存的代码位置>
Freed at:
        <堆栈回溯信息，指示释放内存的代码位置>
```

**涉及用户或者编程常见的使用错误及举例说明：**

* **忘记 attach `GumBoundsChecker`：** 用户创建了 `GumBoundsChecker` 实例，但没有调用 `gum_bounds_checker_attach` 方法，导致内存分配和释放函数没有被 hook，无法进行边界检查。
* **Pool Size 设置过小：**  `GumPagePool` 的大小决定了 `gumboundschecker` 可以追踪的堆内存大小。如果 Pool Size 设置过小，超出 Pool 管理的内存范围的分配将不会被监控。
* **Front Alignment 设置不当：**  Front Alignment 影响内存块的对齐方式。不当的设置可能导致内存分配失败或影响性能。
* **与其它 Frida 脚本冲突：** 如果有其他 Frida 脚本也在 hook 相同的内存分配和释放函数，可能会发生冲突，导致 `gumboundschecker` 工作异常。
* **目标进程使用了自定义的内存分配器：** 如果目标进程不使用标准的 `malloc` 和 `free`，而是使用了自定义的内存分配器，`gumboundschecker` 默认情况下无法监控这些内存操作，需要针对自定义分配器进行额外的 hook。

**用户操作是如何一步步的到达这里，作为调试线索：**

作为调试线索，了解用户操作如何一步步到达 `gumboundschecker.c` 的代码是很有帮助的：

1. **用户编写 Frida 脚本：** 用户首先需要编写一个 Frida 脚本来使用 `GumBoundsChecker`。
   ```javascript
   // JavaScript Frida 脚本示例
   function main() {
     const boundsChecker = new Frida.Gum.BoundsChecker({
       onOutput: function(message) {
         console.log(message);
       }
     });
     boundsChecker.attach();
     // ... 其他需要 hook 或操作的代码 ...
   }

   setImmediate(main);
   ```

2. **用户启动目标进程：** 用户需要运行需要进行堆内存边界检查的目标进程。

3. **用户使用 Frida 连接到目标进程：**  用户可以使用 Frida 的命令行工具（如 `frida`, `frida-trace`）或 API 将编写的脚本注入到目标进程中。例如：
   ```bash
   frida -p <进程ID> -l your_script.js
   ```
   或者连接到正在运行的 Android 应用：
   ```bash
   frida -U -n <应用包名> -l your_script.js
   ```

4. **Frida 加载脚本并执行：** Frida 将脚本加载到目标进程的内存空间中并开始执行。

5. **`GumBoundsChecker` 被实例化和 attach：** 脚本中的 `new Frida.Gum.BoundsChecker(...)` 会在目标进程中创建 `GumBoundsChecker` 的实例，`boundsChecker.attach()` 会调用 `gum_bounds_checker_attach` 函数，开始 hook 内存分配和释放函数。

6. **目标进程执行内存操作：**  目标进程继续执行，当它调用 `malloc`, `free`, `calloc`, `realloc` 等函数时，会被 Frida 拦截，并跳转到 `gumboundschecker.c` 中对应的 `replacement_...` 函数。

7. **发生内存访问错误（如果存在）：** 如果目标进程存在堆内存越界或释放后使用等错误，当访问到受保护的 guard pages 或已释放的内存时，会触发访问违规异常。

8. **`gum_bounds_checker_on_exception` 被调用：** Frida 的异常处理机制会捕获这个异常，并调用 `gum_bounds_checker_on_exception` 函数。

9. **错误信息被报告：** `gum_bounds_checker_on_exception` 分析异常信息后，调用用户在 JavaScript 脚本中提供的 `onOutput` 回调函数，将错误信息打印到控制台。

**调试线索：**

当用户报告 `gumboundschecker` 没有按预期工作时，可以按照以下线索进行调试：

* **检查 Frida 是否成功连接到目标进程。**
* **确认 `gum_bounds_checker_attach` 是否被成功调用。** 可以通过在 `gum_bounds_checker_attach` 函数入口处打印日志来确认。
* **检查目标进程是否真的调用了标准的内存分配和释放函数。** 可以使用 Frida 的 `Interceptor.attach` 来 hook 目标进程中可能使用的内存分配函数，查看是否被调用。
* **检查 `GumPagePool` 的大小设置是否合理。**
* **查看 Frida 的日志输出，是否有错误信息。**
* **尝试简化测试场景，编写一个最小的可复现问题的代码片段。**

总而言之，`gumboundschecker.c` 是 Frida 中一个强大的动态分析工具，用于检测堆内存相关的错误，对于逆向工程、安全分析和漏洞挖掘具有重要的价值。理解其内部实现机制有助于更好地利用它来分析目标程序。

### 提示词
```
这是目录为frida/subprojects/frida-gum/libs/gum/heap/gumboundschecker.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2008-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumboundschecker.h"

#include "gumexceptor.h"
#include "guminterceptor.h"
#include "gumlibc.h"
#include "gumpagepool.h"

#include <stdlib.h>
#include <string.h>

#define DEFAULT_POOL_SIZE       4096
#define DEFAULT_FRONT_ALIGNMENT   16

#define GUM_BOUNDS_CHECKER_LOCK() g_mutex_lock (&self->mutex)
#define GUM_BOUNDS_CHECKER_UNLOCK() g_mutex_unlock (&self->mutex)

#define BLOCK_ALLOC_RETADDRS(b) \
    ((GumReturnAddressArray *) (b)->guard)
#define BLOCK_FREE_RETADDRS(b) \
    ((GumReturnAddressArray *) ((guint8 *) (b)->guard + ((b)->guard_size / 2)))

typedef struct _GumBoundsHookGroup GumBoundsHookGroup;

struct _GumBoundsChecker
{
  GObject parent;

  gboolean disposed;

  GMutex mutex;

  GumBacktracerInterface * backtracer_iface;
  GumBacktracer * backtracer_instance;
  GumBoundsOutputFunc output;
  gpointer output_user_data;

  GumInterceptor * interceptor;
  GumExceptor * exceptor;
  GumHeapApiList * heap_apis;
  GumBoundsHookGroup * hook_groups;
  gboolean attached;
  volatile gboolean detaching;
  volatile gboolean handled_invalid_access;

  guint pool_size;
  guint front_alignment;
  GumPagePool * page_pool;
};

struct _GumBoundsHookGroup
{
  GumBoundsChecker * checker;
  const GumHeapApi * api;
};

enum
{
  PROP_0,
  PROP_BACKTRACER,
  PROP_POOL_SIZE,
  PROP_FRONT_ALIGNMENT
};

static void gum_bounds_checker_dispose (GObject * object);
static void gum_bounds_checker_finalize (GObject * object);

static void gum_bounds_checker_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_bounds_checker_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gpointer replacement_malloc (gsize size);
static gpointer replacement_calloc (gsize num, gsize size);
static gpointer replacement_realloc (gpointer old_address,
    gsize new_size);
static void replacement_free (gpointer address);

static gpointer gum_bounds_checker_try_alloc (GumBoundsChecker * self,
    guint size, GumInvocationContext * ctx);
static gboolean gum_bounds_checker_try_free (GumBoundsChecker * self,
    gpointer address, GumInvocationContext * ctx);

static gboolean gum_bounds_checker_on_exception (GumExceptionDetails * details,
    gpointer user_data);
static void gum_bounds_checker_append_backtrace (
    const GumReturnAddressArray * arr, GString * s);

G_DEFINE_TYPE (GumBoundsChecker, gum_bounds_checker, G_TYPE_OBJECT)

static void
gum_bounds_checker_class_init (GumBoundsCheckerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_bounds_checker_dispose;
  object_class->finalize = gum_bounds_checker_finalize;
  object_class->get_property = gum_bounds_checker_get_property;
  object_class->set_property = gum_bounds_checker_set_property;

  g_object_class_install_property (object_class, PROP_BACKTRACER,
      g_param_spec_object ("backtracer", "Backtracer",
      "Backtracer Implementation", GUM_TYPE_BACKTRACER,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS | G_PARAM_CONSTRUCT_ONLY));

  g_object_class_install_property (object_class, PROP_POOL_SIZE,
      g_param_spec_uint ("pool-size", "Pool Size",
      "Pool size in number of pages",
      2, G_MAXUINT, DEFAULT_POOL_SIZE,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));

  g_object_class_install_property (object_class, PROP_FRONT_ALIGNMENT,
      g_param_spec_uint ("front-alignment", "Front Alignment",
      "Front alignment requirement",
      1, 64, DEFAULT_FRONT_ALIGNMENT,
      G_PARAM_READWRITE | G_PARAM_STATIC_STRINGS));
}

static void
gum_bounds_checker_init (GumBoundsChecker * self)
{
  g_mutex_init (&self->mutex);

  self->interceptor = gum_interceptor_obtain ();
  self->exceptor = gum_exceptor_obtain ();
  self->pool_size = DEFAULT_POOL_SIZE;
  self->front_alignment = DEFAULT_FRONT_ALIGNMENT;

  gum_exceptor_add (self->exceptor, gum_bounds_checker_on_exception, self);
}

static void
gum_bounds_checker_dispose (GObject * object)
{
  GumBoundsChecker * self = GUM_BOUNDS_CHECKER (object);

  if (!self->disposed)
  {
    self->disposed = TRUE;

    gum_bounds_checker_detach (self);

    gum_exceptor_remove (self->exceptor, gum_bounds_checker_on_exception, self);
    g_object_unref (self->exceptor);
    self->exceptor = NULL;

    g_object_unref (self->interceptor);
    self->interceptor = NULL;

    g_clear_object (&self->backtracer_instance);
    self->backtracer_iface = NULL;
  }

  G_OBJECT_CLASS (gum_bounds_checker_parent_class)->dispose (object);
}

static void
gum_bounds_checker_finalize (GObject * object)
{
  GumBoundsChecker * self = GUM_BOUNDS_CHECKER (object);

  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_bounds_checker_parent_class)->finalize (object);
}

static void
gum_bounds_checker_get_property (GObject * object,
                                 guint property_id,
                                 GValue * value,
                                 GParamSpec * pspec)
{
  GumBoundsChecker * self = GUM_BOUNDS_CHECKER (object);

  switch (property_id)
  {
    case PROP_BACKTRACER:
      g_value_set_object (value, self->backtracer_instance);
      break;
    case PROP_POOL_SIZE:
      g_value_set_uint (value, gum_bounds_checker_get_pool_size (self));
      break;
    case PROP_FRONT_ALIGNMENT:
      g_value_set_uint (value, gum_bounds_checker_get_front_alignment (self));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_bounds_checker_set_property (GObject * object,
                                 guint property_id,
                                 const GValue * value,
                                 GParamSpec * pspec)
{
  GumBoundsChecker * self = GUM_BOUNDS_CHECKER (object);

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
    case PROP_POOL_SIZE:
      gum_bounds_checker_set_pool_size (self, g_value_get_uint (value));
      break;
    case PROP_FRONT_ALIGNMENT:
      gum_bounds_checker_set_front_alignment (self, g_value_get_uint (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumBoundsChecker *
gum_bounds_checker_new (GumBacktracer * backtracer,
                        GumBoundsOutputFunc func,
                        gpointer user_data)
{
  GumBoundsChecker * checker;

  checker = g_object_new (GUM_TYPE_BOUNDS_CHECKER,
      "backtracer", backtracer,
      NULL);

  checker->output = func;
  checker->output_user_data = user_data;

  return checker;
}

guint
gum_bounds_checker_get_pool_size (GumBoundsChecker * self)
{
  return self->pool_size;
}

void
gum_bounds_checker_set_pool_size (GumBoundsChecker * self,
                                  guint pool_size)
{
  g_assert (self->page_pool == NULL);
  self->pool_size = pool_size;
}

guint
gum_bounds_checker_get_front_alignment (GumBoundsChecker * self)
{
  return self->front_alignment;
}

void
gum_bounds_checker_set_front_alignment (GumBoundsChecker * self,
                                        guint pool_size)
{
  g_assert (self->page_pool == NULL);
  self->front_alignment = pool_size;
}

void
gum_bounds_checker_attach (GumBoundsChecker * self)
{
  GumHeapApiList * apis = gum_process_find_heap_apis ();
  gum_bounds_checker_attach_to_apis (self, apis);
  gum_heap_api_list_free (apis);
}

void
gum_bounds_checker_attach_to_apis (GumBoundsChecker * self,
                                   const GumHeapApiList * apis)
{
  guint i;

  g_assert (self->heap_apis == NULL);
  self->heap_apis = gum_heap_api_list_copy (apis);

  g_assert (self->hook_groups == NULL);
  self->hook_groups = g_new0 (GumBoundsHookGroup, apis->len);

  g_assert (self->page_pool == NULL);
  self->page_pool = gum_page_pool_new (GUM_PROTECT_MODE_ABOVE,
      self->pool_size);
  g_object_set (self->page_pool, "front-alignment", self->front_alignment,
      NULL);

  gum_interceptor_begin_transaction (self->interceptor);

  for (i = 0; i != apis->len; i++)
  {
    const GumHeapApi * api;
    GumBoundsHookGroup * group;

    api = gum_heap_api_list_get_nth (apis, i);

    group = &self->hook_groups[i];
    group->checker = self;
    group->api = api;

#define GUM_REPLACE_API_FUNC(name) \
    gum_interceptor_replace (self->interceptor, \
        GUM_FUNCPTR_TO_POINTER (api->name), \
        GUM_FUNCPTR_TO_POINTER (replacement_##name), group, NULL)

    GUM_REPLACE_API_FUNC (malloc);
    GUM_REPLACE_API_FUNC (calloc);
    GUM_REPLACE_API_FUNC (realloc);
    GUM_REPLACE_API_FUNC (free);

#undef GUM_REPLACE_API_FUNC
  }

  gum_interceptor_end_transaction (self->interceptor);

  self->attached = TRUE;
}

void
gum_bounds_checker_detach (GumBoundsChecker * self)
{
  if (self->attached)
  {
    guint i;

    self->attached = FALSE;
    self->detaching = TRUE;

    g_assert (gum_page_pool_peek_used (self->page_pool) == 0);

    gum_interceptor_begin_transaction (self->interceptor);

    for (i = 0; i != self->heap_apis->len; i++)
    {
      const GumHeapApi * api = gum_heap_api_list_get_nth (self->heap_apis, i);

#define GUM_REVERT_API_FUNC(name) \
      gum_interceptor_revert (self->interceptor, \
          GUM_FUNCPTR_TO_POINTER (api->name))

      GUM_REVERT_API_FUNC (malloc);
      GUM_REVERT_API_FUNC (calloc);
      GUM_REVERT_API_FUNC (realloc);
      GUM_REVERT_API_FUNC (free);

  #undef GUM_REVERT_API_FUNC
    }

    gum_interceptor_end_transaction (self->interceptor);

    g_object_unref (self->page_pool);
    self->page_pool = NULL;

    g_free (self->hook_groups);
    self->hook_groups = NULL;

    gum_heap_api_list_free (self->heap_apis);
    self->heap_apis = NULL;
  }
}

static gpointer
replacement_malloc (gsize size)
{
  GumInvocationContext * ctx;
  GumBoundsHookGroup * group;
  GumBoundsChecker * self;
  gpointer result;

  ctx = gum_interceptor_get_current_invocation ();
  group = GUM_IC_GET_REPLACEMENT_DATA (ctx, GumBoundsHookGroup *);
  self = group->checker;

  if (self->detaching || self->handled_invalid_access)
    goto fallback;

  GUM_BOUNDS_CHECKER_LOCK ();
  result = gum_bounds_checker_try_alloc (self, MAX (size, 1), ctx);
  GUM_BOUNDS_CHECKER_UNLOCK ();
  if (result == NULL)
    goto fallback;

  return result;

fallback:
  return group->api->malloc (size);
}

static gpointer
replacement_calloc (gsize num,
                    gsize size)
{
  GumInvocationContext * ctx;
  GumBoundsHookGroup * group;
  GumBoundsChecker * self;
  gpointer result;

  ctx = gum_interceptor_get_current_invocation ();
  group = GUM_IC_GET_REPLACEMENT_DATA (ctx, GumBoundsHookGroup *);
  self = group->checker;

  if (self->detaching || self->handled_invalid_access)
    goto fallback;

  GUM_BOUNDS_CHECKER_LOCK ();
  result = gum_bounds_checker_try_alloc (self, MAX (num * size, 1), ctx);
  GUM_BOUNDS_CHECKER_UNLOCK ();
  if (result != NULL)
    gum_memset (result, 0, num * size);
  else
    goto fallback;

  return result;

fallback:
  return group->api->calloc (num, size);
}

static gpointer
replacement_realloc (gpointer old_address,
                     gsize new_size)
{
  GumInvocationContext * ctx;
  GumBoundsHookGroup * group;
  GumBoundsChecker * self;
  gpointer result = NULL;
  GumBlockDetails old_block;

  ctx = gum_interceptor_get_current_invocation ();
  group = GUM_IC_GET_REPLACEMENT_DATA (ctx, GumBoundsHookGroup *);
  self = group->checker;

  if (old_address == NULL)
    return group->api->malloc (new_size);

  if (new_size == 0)
  {
    group->api->free (old_address);
    return NULL;
  }

  if (self->detaching || self->handled_invalid_access)
    goto fallback;

  GUM_BOUNDS_CHECKER_LOCK ();

  if (!gum_page_pool_query_block_details (self->page_pool, old_address,
      &old_block))
  {
    GUM_BOUNDS_CHECKER_UNLOCK ();

    goto fallback;
  }

  result = gum_bounds_checker_try_alloc (self, new_size, ctx);

  GUM_BOUNDS_CHECKER_UNLOCK ();

  if (result == NULL)
    result = group->api->malloc (new_size);

  if (result != NULL)
    gum_memcpy (result, old_address, MIN (old_block.size, new_size));

  GUM_BOUNDS_CHECKER_LOCK ();
  gum_bounds_checker_try_free (self, old_address, ctx);
  GUM_BOUNDS_CHECKER_UNLOCK ();

  return result;

fallback:
  return group->api->realloc (old_address, new_size);
}

static void
replacement_free (gpointer address)
{
  GumInvocationContext * ctx;
  GumBoundsHookGroup * group;
  GumBoundsChecker * self;
  gboolean freed;

  ctx = gum_interceptor_get_current_invocation ();
  group = GUM_IC_GET_REPLACEMENT_DATA (ctx, GumBoundsHookGroup *);
  self = group->checker;

  GUM_BOUNDS_CHECKER_LOCK ();
  freed = gum_bounds_checker_try_free (self, address, ctx);
  GUM_BOUNDS_CHECKER_UNLOCK ();

  if (!freed)
    group->api->free (address);
}

static gpointer
gum_bounds_checker_try_alloc (GumBoundsChecker * self,
                              guint size,
                              GumInvocationContext * ctx)
{
  gpointer result;

  result = gum_page_pool_try_alloc (self->page_pool, size);

  if (result != NULL && self->backtracer_instance != NULL)
  {
    GumBlockDetails block;

    gum_page_pool_query_block_details (self->page_pool, result, &block);

    gum_mprotect (block.guard, block.guard_size, GUM_PAGE_RW);

    g_assert (block.guard_size / 2 >= sizeof (GumReturnAddressArray));
    self->backtracer_iface->generate (self->backtracer_instance,
        ctx->cpu_context, BLOCK_ALLOC_RETADDRS (&block),
        GUM_MAX_BACKTRACE_DEPTH);

    BLOCK_FREE_RETADDRS (&block)->len = 0;

    gum_mprotect (block.guard, block.guard_size, GUM_PAGE_NO_ACCESS);
  }

  return result;
}

static gboolean
gum_bounds_checker_try_free (GumBoundsChecker * self,
                             gpointer address,
                             GumInvocationContext * ctx)
{
  gboolean freed;

  freed = gum_page_pool_try_free (self->page_pool, address);

  if (freed && self->backtracer_instance != NULL)
  {
    GumBlockDetails block;

    gum_page_pool_query_block_details (self->page_pool, address, &block);

    gum_mprotect (block.guard, block.guard_size, GUM_PAGE_RW);

    g_assert (block.guard_size / 2 >= sizeof (GumReturnAddressArray));
    self->backtracer_iface->generate (self->backtracer_instance,
        ctx->cpu_context, BLOCK_FREE_RETADDRS (&block),
        GUM_MAX_BACKTRACE_DEPTH);

    gum_mprotect (block.guard, block.guard_size, GUM_PAGE_NO_ACCESS);
  }

  return freed;
}

static gboolean
gum_bounds_checker_on_exception (GumExceptionDetails * details,
                                 gpointer user_data)
{
  GumBoundsChecker * self;
  GumMemoryOperation op;
  gconstpointer address;
  GumBlockDetails block;
  GString * message;
  GumReturnAddressArray accessed_at = { 0, };

  self = GUM_BOUNDS_CHECKER (user_data);

  if (details->type != GUM_EXCEPTION_ACCESS_VIOLATION)
    return FALSE;

  op = details->memory.operation;
  if (op != GUM_MEMOP_READ && op != GUM_MEMOP_WRITE)
    return FALSE;

  address = details->memory.address;

  if (!gum_page_pool_query_block_details (self->page_pool, address, &block))
    return FALSE;

  if (self->handled_invalid_access)
    return FALSE;
  self->handled_invalid_access = TRUE;

  if (self->output == NULL)
    return TRUE;

  message = g_string_sized_new (300);

  g_string_append_printf (message,
      "Oops! %s block %p of %" G_GSIZE_MODIFIER "d bytes"
      " was accessed at offset %" G_GSIZE_MODIFIER "d",
      block.allocated ? "Heap" : "Freed",
      block.address,
      block.size,
      (gsize) ((guint8 *) address - (guint8 *) block.address));

  if (self->backtracer_instance != NULL)
  {
    self->backtracer_iface->generate (self->backtracer_instance, NULL,
        &accessed_at, GUM_MAX_BACKTRACE_DEPTH);
  }

  if (accessed_at.len > 0)
  {
    g_string_append (message, " from:\n");
    gum_bounds_checker_append_backtrace (&accessed_at, message);
  }
  else
  {
    g_string_append_c (message, '\n');
  }

  if (self->backtracer_instance != NULL)
  {
    GumReturnAddressArray * allocated_at, * freed_at;

    gum_mprotect (block.guard, block.guard_size, GUM_PAGE_READ);

    allocated_at = BLOCK_ALLOC_RETADDRS (&block);
    if (allocated_at->len > 0)
    {
      g_string_append (message, "Allocated at:\n");
      gum_bounds_checker_append_backtrace (allocated_at, message);
    }

    freed_at = BLOCK_FREE_RETADDRS (&block);
    if (freed_at->len > 0)
    {
      g_string_append (message, "Freed at:\n");
      gum_bounds_checker_append_backtrace (freed_at, message);
    }

    gum_mprotect (block.guard, block.guard_size, GUM_PAGE_NO_ACCESS);
  }

  self->output (message->str, self->output_user_data);

  g_string_free (message, TRUE);

  return TRUE;
}

static void
gum_bounds_checker_append_backtrace (const GumReturnAddressArray * arr,
                                     GString * s)
{
  guint i;

  for (i = 0; i != arr->len; i++)
  {
    GumReturnAddress addr = arr->items[i];
    GumReturnAddressDetails rad;

    if (gum_return_address_details_from_address (addr, &rad))
    {
      gchar * file_basename;

      file_basename = g_path_get_basename (rad.file_name);
      g_string_append_printf (s, "\t%p %s!%s %s:%u\n",
          rad.address,
          rad.module_name, rad.function_name,
          file_basename, rad.line_number);
      g_free (file_basename);
    }
    else
    {
      g_string_append_printf (s, "\t%p\n", addr);
    }
  }
}
```