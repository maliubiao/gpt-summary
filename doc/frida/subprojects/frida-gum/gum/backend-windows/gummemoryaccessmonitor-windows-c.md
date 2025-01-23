Response:
Let's break down the thought process for analyzing the C code and generating the response.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of the provided C code (`gummemoryaccessmonitor-windows.c`) within the context of Frida, a dynamic instrumentation tool. The prompt specifically asks for:

* **Functionality:** What does the code do?
* **Relationship to Reversing:** How is it useful in reverse engineering?
* **Low-Level Details:** Connections to binary, Linux/Android kernel/framework (though this is a Windows-specific file).
* **Logical Reasoning:**  Input/output examples.
* **User Errors:** Common mistakes in usage.
* **Debugging Clues:** How a user might reach this code.

**2. Initial Code Scan and Keyword Identification:**

The first step is a quick scan of the code to identify key terms and structures. This involves looking for:

* **Function names:**  `gum_memory_access_monitor_new`, `gum_memory_access_monitor_enable`, `gum_memory_access_monitor_disable`, `gum_memory_access_monitor_on_exception`, `VirtualProtect`, `VirtualQuery`.
* **Data structures:** `GumMemoryAccessMonitor`, `GumMemoryRange`, `GumPageDetails`, `GumLiveRangeDetails`, `GumRangeStats`.
* **Windows API calls:**  `VirtualProtect`, `VirtualQuery`, `MEMORY_BASIC_INFORMATION`.
* **Frida/Gum specific elements:**  `GumExceptor`, `GumPageProtection`, `GumMemoryAccessNotify`, `G_DEFINE_TYPE`, `GObject`.
* **Control flow keywords:** `if`, `else`, `for`, `while`, `switch`.
* **Memory management functions:** `g_memdup2`, `g_free`, `g_realloc`.
* **Error handling:** `GError`, `g_set_error`.

**3. Deconstructing the Core Functionality - "What does it do?":**

Based on the identified keywords, we can start to piece together the main purpose of the code: **monitoring memory access**. The key functions that confirm this are:

* `gum_memory_access_monitor_new`:  Sets up the monitor, taking memory ranges and access masks as input.
* `gum_memory_access_monitor_enable`:  Activates the monitoring. Crucially, it uses `VirtualProtect` to modify page protections, adding guard pages or changing access rights.
* `gum_memory_access_monitor_disable`: Deactivates the monitoring, restoring original page protections with `VirtualProtect`.
* `gum_memory_access_monitor_on_exception`: This is the heart of the monitoring. It's called when a memory access violation or guard page exception occurs. It checks if the exception is within the monitored range and if it matches the configured access mask. If so, it calls the user-provided `notify_func`.

**4. Connecting to Reversing - "How is it related to reverse engineering?":**

With the understanding that it monitors memory access, the connection to reverse engineering becomes apparent. Reverse engineers often need to understand:

* **When memory is read/written:**  To track data flow and identify points of interest.
* **Which code accesses specific memory regions:** To understand the purpose of those regions and the functionality of the code.
* **When code attempts to execute in specific memory:** To analyze code execution paths and potentially identify vulnerabilities.

The `GumMemoryAccessMonitor` provides a mechanism to automate this tracking. By setting up the monitor on specific memory regions and access types, a reverse engineer can be notified when those regions are accessed, providing valuable insights.

**5. Identifying Low-Level Details:**

The use of Windows API functions like `VirtualProtect` and `VirtualQuery` clearly indicates interaction with the operating system's memory management. The code directly deals with page protections (e.g., `PAGE_NOACCESS`, `PAGE_READONLY`, `PAGE_GUARD`). This places the code firmly in the realm of low-level binary and operating system concepts. Although the prompt mentions Linux/Android, this particular file is Windows-specific. It's important to acknowledge this constraint.

**6. Logical Reasoning - Input/Output Examples:**

To illustrate the logic, simple scenarios help:

* **Scenario 1 (Read Monitoring):**  Monitor a data buffer for reads. When the target application reads from this buffer, the `notify_func` is called.
* **Scenario 2 (Write Monitoring):** Monitor a configuration variable for writes. When the target application modifies this variable, the notification occurs.
* **Scenario 3 (Execute Monitoring):** Monitor a code region for execution. When the target application attempts to execute code in that region (if the access mask allows), the notification triggers.

**7. Identifying User Errors:**

Thinking about how a user might misuse this API reveals potential errors:

* **Incorrect Range Specification:** Providing invalid memory addresses or sizes.
* **Conflicting Access Masks:**  Setting an access mask that doesn't align with the actual memory protection.
* **Not Handling Notifications:** Failing to implement the `notify_func` correctly or at all.
* **Enabling/Disabling Issues:**  Forgetting to disable the monitor or enabling it multiple times.

**8. Tracing User Operations - "How does the user reach here?":**

This requires understanding how Frida is used. A typical workflow involves:

1. **Writing a Frida script (usually in JavaScript or Python).**
2. **Using Frida's API to interact with the target process.**
3. **The Frida script calls Gum API functions.**  In this case, it would involve creating and enabling a `GumMemoryAccessMonitor` instance.

Therefore, the path to this C code involves the user's high-level Frida script interacting with the Gum library, which then uses the operating system's APIs.

**9. Structuring the Response:**

Finally, organize the information logically, following the prompts' structure. Use clear headings and examples to make the explanation easy to understand. Start with a general overview of the functionality and then delve into the specific details.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Perhaps this code directly hooks into kernel functions. **Correction:** The code uses `VirtualProtect`, which is a user-mode API. Frida's Gum likely handles the underlying mechanism of intercepting memory accesses.
* **Considering Linux/Android:** While the prompt mentions them, this specific file is clearly Windows-focused. Avoid speculating about how similar functionality might be implemented on other platforms unless there's a clear connection in the code.
* **Simplifying Explanations:**  Avoid overly technical jargon where possible. Focus on explaining the concepts in a way that is accessible to someone familiar with reverse engineering principles but perhaps not deeply knowledgeable about Frida's internals.

By following this iterative process of scanning, analyzing, connecting, and refining, we arrive at a comprehensive and accurate explanation of the C code's functionality within the Frida ecosystem.
好的，我们来详细分析一下 `gummemoryaccessmonitor-windows.c` 这个文件的功能及其在 Frida 动态插桩工具中的作用。

**文件功能概述**

`gummemoryaccessmonitor-windows.c` 文件的主要功能是提供一种机制，用于监控特定内存区域的访问行为（读取、写入、执行）。它利用 Windows 操作系统提供的 API 来实现这一目标，并在检测到指定类型的内存访问时通知用户。

**功能点详解**

1. **内存区域监控:**
   - 允许用户指定一个或多个内存区域 (`GumMemoryRange`) 进行监控。
   - 每个内存区域由起始地址 (`base_address`) 和大小 (`size`) 定义。

2. **访问类型监控:**
   - 用户可以指定需要监控的访问类型 (`GumPageProtection access_mask`)，包括：
     - `GUM_PAGE_READ`: 监控读取操作。
     - `GUM_PAGE_WRITE`: 监控写入操作。
     - `GUM_PAGE_EXECUTE`: 监控执行操作。
     - 可以组合使用，例如 `GUM_PAGE_READ | GUM_PAGE_WRITE` 监控读写操作。

3. **基于 Windows API 的实现:**
   - 核心机制是使用 Windows API 函数 `VirtualProtect` 来修改被监控内存页的保护属性。
   - 可以将内存页设置为 `PAGE_NOACCESS`，或者添加 `PAGE_GUARD` 标志。
     - 设置为 `PAGE_NOACCESS` 会导致任何访问都触发访问违规异常。
     - 添加 `PAGE_GUARD` 标志会导致首次访问时触发一个一次性的 guard page 异常。

4. **异常处理:**
   - 使用 `GumExceptor` 组件来捕获由内存访问触发的异常 (访问违规或 guard page 异常)。
   - `gum_memory_access_monitor_on_exception` 函数是异常处理的核心，它判断异常是否发生在被监控的内存区域，并根据配置的访问类型进行过滤。

5. **通知机制:**
   - 当检测到符合条件的内存访问时，会调用用户提供的回调函数 (`GumMemoryAccessNotify notify_func`)。
   - 回调函数会接收一个 `GumMemoryAccessDetails` 结构，其中包含了访问的详细信息，例如访问类型、访问地址、来源地址等。

6. **自动重置 (可选):**
   - `auto_reset` 参数控制在检测到访问后是否自动恢复内存页的原始保护属性。
   - 如果设置为 `TRUE`，对于 guard page 异常，会恢复原始保护，使得后续访问可以继续触发监控。

**与逆向方法的关系及举例说明**

`gummemoryaccessmonitor-windows.c` 文件提供的功能与逆向工程紧密相关，可以用于：

* **追踪数据访问:** 逆向工程师可以使用它来监控特定数据结构或变量的读取和写入操作，以理解程序如何使用和修改这些数据。
   - **举例:**  假设你要分析一个加密算法，你可以监控密钥存储的内存区域。每当程序读取密钥时，监控器会通知你，从而帮助你定位密钥的使用位置。
* **分析代码执行流程:**  监控特定代码区域的执行，可以帮助理解程序的控制流，特别是对于动态生成的代码或 shellcode 的分析。
   - **举例:**  在分析恶意软件时，可以监控可疑的代码段。如果程序尝试执行这些代码，监控器会触发，表明该代码段被执行。
* **检测内存破坏:** 监控关键数据结构的写入操作，可以帮助发现潜在的内存破坏漏洞。
   - **举例:**  监控虚函数表的内存区域。如果程序尝试修改虚函数表，这可能是一个利用漏洞的尝试，监控器会及时发出警报。
* **理解 API 使用:** 监控特定 API 函数参数或返回值的内存区域，可以更好地理解 API 的使用方式和效果。
   - **举例:**  监控 `CreateFile` 函数返回的文件句柄的内存区域。当程序后续使用该句柄进行读写操作时，监控器会记录这些操作，帮助理解文件 I/O 的过程。

**涉及二进制底层、Linux/Android 内核及框架的知识说明**

* **二进制底层 (Windows):**
    - 文件中大量使用了 Windows API，如 `VirtualProtect` 和 `VirtualQuery`，这些都是直接与操作系统内核交互的底层 API，用于管理进程的虚拟内存。
    - 涉及到内存页的概念，内存保护属性（例如 `PAGE_READONLY`，`PAGE_NOACCESS`，`PAGE_GUARD` 等），这些都是操作系统内存管理的核心概念。
    - 异常处理机制依赖于 Windows 的结构化异常处理 (SEH) 或向量化异常处理 (VEH)，`GumExceptor` 封装了这些机制。
* **Linux/Android 内核及框架 (对比):**
    - 虽然这个文件是 Windows 特定的，但类似的内存监控功能在 Linux 和 Android 上也有对应的实现机制。
    - **Linux:** 可以使用 `mprotect` 系统调用来修改内存页的保护属性，使用 `ptrace` 或内核模块来实现异常捕获和处理。
    - **Android:** 基于 Linux 内核，内存保护也使用 `mprotect`。Frida 在 Android 上的实现会利用 Android 特有的机制，例如 zygote 进程的特性进行插桩，并可能使用 `ptrace` 或 ART (Android Runtime) 的 API 来监控内存访问。
    - **框架层面:**  Frida 抽象了底层的操作系统差异，提供了一套统一的 API (`Gum`)，使得用户可以使用相同的代码来监控不同平台上的内存访问。`gummemoryaccessmonitor-windows.c` 就是 `Gum` 在 Windows 平台上的具体实现。

**逻辑推理 - 假设输入与输出**

假设我们有以下输入：

* **被监控内存区域:**
    - `ranges`: 一个包含一个 `GumMemoryRange` 的数组，该范围的 `base_address` 为 `0x00401000`，`size` 为 `0x1000` 字节。
* **监控的访问类型:**
    - `access_mask`: `GUM_PAGE_WRITE` (仅监控写入操作)。
* **自动重置:**
    - `auto_reset`: `FALSE` (不自动重置内存保护属性)。
* **回调函数:**
    - `notify_func`: 一个简单的函数，当检测到写入操作时，打印 "Write access detected at address: [访问地址]"。

**预期输出：**

1. **启用监控后:**  当目标进程尝试向 `0x00401000` 到 `0x00401FFF` 范围内的任何地址写入数据时，`gum_memory_access_monitor_on_exception` 函数会被调用。
2. **异常处理:** 该函数会判断异常类型是否为访问违规，并且访问操作是否为写入操作，且地址是否在监控范围内。
3. **回调触发:** 如果条件满足，`notify_func` 回调函数会被调用，并在控制台输出类似以下的信息：
   ```
   Write access detected at address: 00401050
   ```
   （假设写入操作发生在地址 `0x00401050`）
4. **内存保护:** 由于 `auto_reset` 设置为 `FALSE`，在第一次检测到写入操作后，该内存页的保护属性将保持为 `PAGE_NOACCESS` (或者其他阻止写入的属性，取决于具体的实现)，后续的写入操作仍然会触发异常，但如果 `gum_memory_access_monitor_on_exception` 不做特殊处理，可能不会再次触发 `notify_func` (因为已经处理过一次异常了)。

**用户或编程常见的使用错误举例说明**

1. **监控范围不正确:** 用户指定的 `GumMemoryRange` 可能与实际需要监控的内存区域不符，导致监控失效或误报。
   - **例子:**  用户想要监控一个动态分配的缓冲区的访问，但提供的范围是分配前的地址，导致实际访问发生时没有被监控到。
2. **访问类型配置错误:** 用户可能错误地配置了 `access_mask`，导致无法捕获到预期的访问类型。
   - **例子:**  用户只想监控写入操作，但错误地设置了 `access_mask` 为 `GUM_PAGE_READ`，导致读取操作也被监控到，产生大量不必要的通知。
3. **未正确处理回调函数:** 用户提供的 `notify_func` 可能存在错误，导致程序崩溃或无法正确记录监控信息。
   - **例子:**  回调函数中访问了已经被释放的内存，或者没有进行线程安全处理，导致多线程环境下出现问题。
4. **忘记禁用监控:** 在不需要监控时，用户可能忘记调用 `gum_memory_access_monitor_disable`，导致持续的性能开销和潜在的冲突。
5. **重复启用监控:**  用户可能多次调用 `gum_memory_access_monitor_enable` 而没有先禁用，可能导致资源泄漏或行为异常。
6. **假设内存布局:**  用户在硬编码内存地址时，可能会假设目标进程的内存布局是固定的，但实际情况下，由于 ASLR (地址空间布局随机化) 等机制，内存地址可能在每次运行或不同系统上都不同。

**用户操作是如何一步步的到达这里，作为调试线索**

1. **编写 Frida 脚本:** 用户首先会编写一个 Frida 脚本（通常是 JavaScript 或 Python），使用 Frida 的 API 来与目标进程进行交互。
2. **使用 `Gum` API:**  在 Frida 脚本中，用户会使用 `Gum` 库提供的接口来创建一个 `MemoryAccessMonitor` 的实例。这通常涉及到调用类似 `Gum.MemoryAccessMonitor()` 的方法，并传入需要监控的内存范围、访问类型和回调函数等参数。
3. **调用 `enable()` 方法:**  在配置好 `MemoryAccessMonitor` 实例后，用户会调用其 `enable()` 方法来激活内存监控。这在 Frida 内部会调用到 `gummemoryaccessmonitor_new` 和 `gum_memory_access_monitor_enable` 等 C 代码中的函数。
4. **目标进程执行并访问内存:**  当目标进程执行到访问被监控内存区域的代码时，如果访问类型与配置匹配，Windows 操作系统会抛出一个异常（访问违规或 guard page 异常）。
5. **`GumExceptor` 捕获异常:** Frida 的 `GumExceptor` 组件会捕获这个异常。
6. **调用 `gum_memory_access_monitor_on_exception`:** `GumExceptor` 会调用注册的异常处理回调函数，即 `gum_memory_access_monitor_on_exception`。
7. **处理异常和通知:**  在该函数内部，会判断异常是否与内存监控相关，并调用用户提供的 `notify_func` 回调函数，将内存访问的详细信息传递给用户。

**调试线索:**

当用户在 Frida 脚本中设置了内存监控，但没有收到预期的通知时，可以按照以下步骤进行调试：

1. **确认监控范围:** 仔细检查脚本中指定的内存范围是否正确，可以使用 Frida 的内存扫描功能或目标进程的调试信息来确认。
2. **核对访问类型:** 确认 `access_mask` 的设置是否与期望监控的访问类型一致。
3. **检查回调函数:** 确保回调函数没有错误，并且能够正确地处理接收到的信息。可以尝试在回调函数中添加简单的日志输出，以确认是否被调用。
4. **查看目标进程的内存保护属性:**  可以使用 Frida 提供的 API 或调试器来查看被监控内存区域的保护属性，确认是否被 `gum_memory_access_monitor_enable` 正确修改。
5. **分析异常信息:** 如果程序崩溃，查看异常信息，确认是否是由于内存访问违规引起的，以及异常发生的地址是否在监控范围内。
6. **使用 Frida 的日志功能:**  Frida 提供了日志输出功能，可以用来跟踪 `Gum` 内部的执行流程，查看是否有相关的错误或警告信息。

总而言之，`gummemoryaccessmonitor-windows.c` 是 Frida 在 Windows 平台上实现内存访问监控的核心组件，它利用 Windows 的内存管理和异常处理机制，为逆向工程师提供了一种强大的动态分析工具。理解其工作原理有助于更有效地使用 Frida 进行程序分析和漏洞挖掘。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-windows/gummemoryaccessmonitor-windows.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
 * Copyright (C) 2015 Eloi Vanderbeken <eloi.vanderbeken@synacktiv.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gummemoryaccessmonitor.h"

#include "gumexceptor.h"
#include "gum/gumwindows.h"

#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>

typedef struct _GumPageDetails GumPageDetails;
typedef struct _GumLiveRangeDetails GumLiveRangeDetails;
typedef struct _GumRangeStats GumRangeStats;

typedef gboolean (* GumFoundLiveRangeFunc) (const GumLiveRangeDetails * details,
    gpointer user_data);

struct _GumMemoryAccessMonitor
{
  GObject parent;

  guint page_size;

  gboolean enabled;
  GumExceptor * exceptor;

  GumMemoryRange * ranges;
  guint num_ranges;
  gint pages_remaining;
  gint pages_total;

  GumPageProtection access_mask;
  GumPageDetails * pages_details;
  guint num_pages;
  gboolean auto_reset;

  GumMemoryAccessNotify notify_func;
  gpointer notify_data;
  GDestroyNotify notify_data_destroy;
};

struct _GumPageDetails
{
  guint range_index;
  gpointer address;
  gboolean is_guarded;
  DWORD original_protection;
  guint completed;
};

struct _GumLiveRangeDetails
{
  const GumMemoryRange * range;
  guint range_index;
  DWORD protection;
};

struct _GumRangeStats
{
  guint live_size;
  guint guarded_size;
};

static void gum_memory_access_monitor_dispose (GObject * object);
static void gum_memory_access_monitor_finalize (GObject * object);

static gboolean gum_collect_range_stats (const GumLiveRangeDetails * details,
    gpointer user_data);
static gboolean gum_set_guard_flag (const GumLiveRangeDetails * details,
    gpointer user_data);
static gboolean gum_clear_guard_flag (const GumLiveRangeDetails * details,
    gpointer user_data);

static void gum_memory_access_monitor_enumerate_live_ranges (
    GumMemoryAccessMonitor * self, GumFoundLiveRangeFunc func,
    gpointer user_data);

static gboolean gum_memory_access_monitor_on_exception (
    GumExceptionDetails * details, gpointer user_data);

G_DEFINE_TYPE (GumMemoryAccessMonitor, gum_memory_access_monitor, G_TYPE_OBJECT)

static void
gum_memory_access_monitor_class_init (GumMemoryAccessMonitorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_memory_access_monitor_dispose;
  object_class->finalize = gum_memory_access_monitor_finalize;
}

static void
gum_memory_access_monitor_init (GumMemoryAccessMonitor * self)
{
  self->page_size = gum_query_page_size ();
}

static void
gum_memory_access_monitor_dispose (GObject * object)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR (object);

  gum_memory_access_monitor_disable (self);

  if (self->notify_data_destroy != NULL)
  {
    self->notify_data_destroy (self->notify_data);
    self->notify_data_destroy = NULL;
  }
  self->notify_data = NULL;
  self->notify_func = NULL;

  G_OBJECT_CLASS (gum_memory_access_monitor_parent_class)->dispose (object);
}

static void
gum_memory_access_monitor_finalize (GObject * object)
{
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR (object);

  g_free (self->ranges);

  G_OBJECT_CLASS (gum_memory_access_monitor_parent_class)->finalize (object);
}

GumMemoryAccessMonitor *
gum_memory_access_monitor_new (const GumMemoryRange * ranges,
                               guint num_ranges,
                               GumPageProtection access_mask,
                               gboolean auto_reset,
                               GumMemoryAccessNotify func,
                               gpointer data,
                               GDestroyNotify data_destroy)
{
  GumMemoryAccessMonitor * monitor;
  guint i;

  monitor = g_object_new (GUM_TYPE_MEMORY_ACCESS_MONITOR, NULL);

  monitor->ranges = g_memdup2 (ranges, num_ranges * sizeof (GumMemoryRange));
  monitor->num_ranges = num_ranges;
  monitor->access_mask = access_mask;
  monitor->auto_reset = auto_reset;
  for (i = 0; i != num_ranges; i++)
  {
    GumMemoryRange * r = &monitor->ranges[i];
    gsize aligned_start, aligned_end;
    guint num_pages;

    aligned_start = r->base_address & ~((gsize) monitor->page_size - 1);
    aligned_end = (r->base_address + r->size + monitor->page_size - 1) &
        ~((gsize) monitor->page_size - 1);
    r->base_address = aligned_start;
    r->size = aligned_end - aligned_start;

    num_pages = r->size / monitor->page_size;
    g_atomic_int_add (&monitor->pages_remaining, num_pages);
    monitor->pages_total += num_pages;
  }

  monitor->notify_func = func;
  monitor->notify_data = data;
  monitor->notify_data_destroy = data_destroy;

  return monitor;
}

gboolean
gum_memory_access_monitor_enable (GumMemoryAccessMonitor * self,
                                  GError ** error)
{
  GumRangeStats stats;

  if (self->enabled)
    return TRUE;

  stats.live_size = 0;
  stats.guarded_size = 0;
  gum_memory_access_monitor_enumerate_live_ranges (self,
      gum_collect_range_stats, &stats);

  if (stats.live_size != self->pages_total * self->page_size)
    goto error_invalid_pages;
  else if (stats.guarded_size != 0)
    goto error_guarded_pages;

  self->exceptor = gum_exceptor_obtain ();
  gum_exceptor_add (self->exceptor, gum_memory_access_monitor_on_exception,
      self);

  self->num_pages = 0;
  self->pages_details = NULL;
  gum_memory_access_monitor_enumerate_live_ranges (self, gum_set_guard_flag,
      self);

  self->enabled = TRUE;

  return TRUE;

error_invalid_pages:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "One or more pages are unallocated");
    return FALSE;
  }
error_guarded_pages:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "One or more pages already have the guard bit set");
    return FALSE;
  }
}

void
gum_memory_access_monitor_disable (GumMemoryAccessMonitor * self)
{
  if (!self->enabled)
    return;

  gum_memory_access_monitor_enumerate_live_ranges (self,
      gum_clear_guard_flag, self);

  gum_exceptor_remove (self->exceptor, gum_memory_access_monitor_on_exception,
      self);
  g_object_unref (self->exceptor);
  self->exceptor = NULL;

  g_free (self->pages_details);
  self->num_pages = 0;
  self->pages_details = NULL;
  self->enabled = FALSE;
}

static gboolean
gum_collect_range_stats (const GumLiveRangeDetails * details,
                         gpointer user_data)
{
  GumRangeStats * stats = (GumRangeStats *) user_data;

  stats->live_size += details->range->size;
  if ((details->protection & PAGE_GUARD) == PAGE_GUARD)
    stats->guarded_size += details->range->size;

  return TRUE;
}

static gboolean
gum_set_guard_flag (const GumLiveRangeDetails * details,
                    gpointer user_data)
{
  GumMemoryAccessMonitor * self;
  DWORD old_prot, new_prot;
  BOOL success;
  gboolean is_guarded = FALSE;
  guint num_pages;

  self = GUM_MEMORY_ACCESS_MONITOR (user_data);
  new_prot = PAGE_NOACCESS;

  if ((self->access_mask & GUM_PAGE_READ) != 0)
  {
    if (self->auto_reset)
    {
      is_guarded = TRUE;
      new_prot = details->protection | PAGE_GUARD;
    }
    else
    {
      new_prot = PAGE_NOACCESS;
    }
  }
  else
  {
    switch (details->protection & 0xFF)
    {
    case PAGE_EXECUTE:
      if ((self->access_mask & GUM_PAGE_EXECUTE) != 0)
        new_prot = PAGE_READONLY;
      else
        return TRUE;
      break;
    case PAGE_EXECUTE_READ:
      if ((self->access_mask & GUM_PAGE_EXECUTE) != 0)
        new_prot = PAGE_READONLY;
      else
        return TRUE;
      break;
    case PAGE_EXECUTE_READWRITE:
      if (self->access_mask == GUM_PAGE_WRITE)
        new_prot = PAGE_EXECUTE_READ;
      else if (self->access_mask == (GUM_PAGE_EXECUTE | GUM_PAGE_WRITE))
        new_prot = PAGE_READONLY;
      else if (self->access_mask == GUM_PAGE_EXECUTE)
        new_prot = PAGE_READWRITE;
      else
        g_assert_not_reached ();
      break;
    case PAGE_EXECUTE_WRITECOPY:
      if (self->access_mask == GUM_PAGE_WRITE)
        new_prot = PAGE_EXECUTE_READ;
      else if (self->access_mask == (GUM_PAGE_EXECUTE | GUM_PAGE_WRITE))
        new_prot = PAGE_READONLY;
      else if (self->access_mask == GUM_PAGE_EXECUTE)
        new_prot = PAGE_WRITECOPY;
      else
        g_assert_not_reached ();
      break;
    case PAGE_NOACCESS:
      return TRUE;
    case PAGE_READONLY:
      return TRUE;
    case PAGE_READWRITE:
      if ((self->access_mask & GUM_PAGE_WRITE) != 0)
        new_prot = PAGE_READONLY;
      else
        return TRUE;
      break;
    case PAGE_WRITECOPY:
      if ((self->access_mask & GUM_PAGE_WRITE) != 0)
        new_prot = PAGE_READONLY;
      else
        return TRUE;
      break;
    default:
      g_assert_not_reached ();
    }
  }

  num_pages = self->num_pages;

  self->pages_details = g_realloc (self->pages_details,
      (num_pages + 1) * sizeof (self->pages_details[0]));

  self->pages_details[num_pages].range_index = details->range_index;
  self->pages_details[num_pages].original_protection = details->protection;
  self->pages_details[num_pages].address =
      GSIZE_TO_POINTER (details->range->base_address);
  self->pages_details[num_pages].is_guarded = is_guarded;
  self->pages_details[num_pages].completed = 0;

  self->num_pages++;

  success = VirtualProtect (GSIZE_TO_POINTER (details->range->base_address),
      details->range->size, new_prot, &old_prot);
  if (!success)
    g_atomic_int_add (&self->pages_remaining, -1);

  return TRUE;
}

static gboolean
gum_clear_guard_flag (const GumLiveRangeDetails * details,
                      gpointer user_data)
{
  DWORD old_prot;
  GumMemoryAccessMonitor * self = GUM_MEMORY_ACCESS_MONITOR (user_data);
  guint i;

  for (i = 0; i != self->num_pages; i++)
  {
    const GumPageDetails * page = &self->pages_details[i];
    const GumMemoryRange * r = &self->ranges[page->range_index];

    if (GUM_MEMORY_RANGE_INCLUDES (r, details->range->base_address))
    {
      return VirtualProtect (GSIZE_TO_POINTER (details->range->base_address),
          details->range->size, page->original_protection, &old_prot);
    }
  }
  return FALSE;
}

static void
gum_memory_access_monitor_enumerate_live_ranges (GumMemoryAccessMonitor * self,
                                                 GumFoundLiveRangeFunc func,
                                                 gpointer user_data)
{
  guint i;
  gboolean carry_on = TRUE;

  for (i = 0; i != self->num_ranges && carry_on; i++)
  {
    GumMemoryRange * r = &self->ranges[i];
    gpointer cur = GSIZE_TO_POINTER (r->base_address);
    gpointer end = GSIZE_TO_POINTER (r->base_address + r->size);

    do
    {
      MEMORY_BASIC_INFORMATION mbi;
      SIZE_T size;
      GumLiveRangeDetails details;
      GumMemoryRange range;

      size = VirtualQuery (cur, &mbi, sizeof (mbi));
      if (size == 0)
        break;

      /* force the iteration one page at a time */
      size = MIN (mbi.RegionSize, self->page_size);

      details.range = &range;
      details.protection = mbi.Protect;
      details.range_index = i;

      range.base_address = GUM_ADDRESS (cur);
      range.size = MIN ((gsize) ((guint8 *) end - (guint8 *) cur),
          size - ((guint8 *) cur - (guint8 *) mbi.BaseAddress));

      carry_on = func (&details, user_data);

      cur = (guint8 *) mbi.BaseAddress + size;
    }
    while (cur < end && carry_on);
  }
}

static gboolean
gum_memory_access_monitor_on_exception (GumExceptionDetails * details,
                                        gpointer user_data)
{
  GumMemoryAccessMonitor * self;
  GumMemoryAccessDetails d;
  guint i;

  self = GUM_MEMORY_ACCESS_MONITOR (user_data);

  d.operation = details->memory.operation;
  d.from = details->address;
  d.address = details->memory.address;

  for (i = 0; i != self->num_pages; i++)
  {
    GumPageDetails * page = &self->pages_details[i];
    const GumMemoryRange * r = &self->ranges[page->range_index];
    guint operation_mask;
    guint operations_reported;
    guint pages_remaining;

    if ((page->address <= d.address) &&
        ((guint8 *) page->address + self->page_size > (guint8 *) d.address))
    {
      /* make sure that we don't misinterpret access violation / page guard */
      if (page->is_guarded)
      {
        if (details->type != GUM_EXCEPTION_GUARD_PAGE)
          return FALSE;
      }
      else if (details->type == GUM_EXCEPTION_ACCESS_VIOLATION)
      {
        GumPageProtection gum_original_protection =
            gum_page_protection_from_windows (page->original_protection);
        switch (d.operation)
        {
        case GUM_MEMOP_READ:
          if ((gum_original_protection & GUM_PAGE_READ) == 0)
            return FALSE;
          break;
        case GUM_MEMOP_WRITE:
          if ((gum_original_protection & GUM_PAGE_WRITE) == 0)
            return FALSE;
          break;
        case GUM_MEMOP_EXECUTE:
          if ((gum_original_protection & GUM_PAGE_EXECUTE) == 0)
            return FALSE;
          break;
        default:
          g_assert_not_reached ();
        }
      }
      else
        return FALSE;

      /* restore the original protection if needed */
      if (self->auto_reset && !page->is_guarded)
      {
        DWORD old_prot;
        /* may be called multiple times in case of simultaneous access
         * but it should not be a problem */
        VirtualProtect (
            (guint8 *) d.address - (((guintptr) d.address) % self->page_size),
            self->page_size, page->original_protection, &old_prot);
      }

      /* if an operation was already reported, don't report it. */
      operation_mask = 1 << d.operation;
      operations_reported = g_atomic_int_or (&page->completed, operation_mask);
      if ((operations_reported != 0) && self->auto_reset)
        return FALSE;

      if (!operations_reported)
        pages_remaining = g_atomic_int_add (&self->pages_remaining, -1) - 1;
      else
        pages_remaining = g_atomic_int_get (&self->pages_remaining);
      d.pages_completed = self->pages_total - pages_remaining;

      d.range_index = page->range_index;
      d.page_index = ((guint8 *) d.address -
            (guint8 *) GSIZE_TO_POINTER (r->base_address)) /
          self->page_size;
      d.pages_total = self->pages_total;

      self->notify_func (self, &d, self->notify_data);

      return TRUE;
    }
  }

  return FALSE;
}

#endif
```