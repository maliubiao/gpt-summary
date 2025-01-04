Response:
Let's break down the thought process to analyze this C code for Frida's dynamic instrumentation tool.

**1. Understanding the Goal:**

The core request is to analyze the functionality of `gummemoryaccessmonitor-posix.c`, particularly in the context of reverse engineering, low-level details, and common usage scenarios. The request also asks for tracing how a user might reach this code and potential errors.

**2. Initial Code Scan and High-Level Understanding:**

First, I'd quickly scan the code, noting key data structures and function names. This gives a general idea of the code's purpose. I see:

* **Data Structures:** `GumMemoryAccessMonitor`, `GumPageState`, `GumRangeStats`, `GumLivePageDetails`, `GumEnumerateLivePagesContext`. These suggest managing memory regions and tracking access.
* **Function Names:**  `gum_memory_access_monitor_new`, `enable`, `disable`, `on_exception`, `enumerate_live_pages`, `monitor_range`, `demonitor_range`. These clearly indicate the lifecycle and core actions of a memory access monitor.
* **Includes:** `<sys/mman.h>`, "gummemoryaccessmonitor.h", "gumexceptor.h". This points towards direct memory manipulation (mmap) and exception handling, confirming the low-level nature.
* **`#ifndef GUM_DIET`:** This conditional compilation suggests this code is part of a larger build system and likely includes features not present in a "diet" (presumably smaller or more limited) build.

**3. Focusing on Core Functionality (Mental Model Building):**

I would then try to build a mental model of how the memory access monitor works. Key questions to ask:

* **What does it monitor?** Memory ranges specified by the user.
* **How does it monitor?** By changing memory protections (using `mprotect`) and catching access violation exceptions.
* **What happens on access?** A notification function is called.
* **What are the key states?** Enabled/disabled.
* **What are the key phases?** Initialization, enabling, access monitoring, disabling.

**4. Connecting to Reverse Engineering:**

With the mental model, I can now start connecting it to reverse engineering techniques:

* **Memory Breakpoints:** The core concept is similar to setting hardware memory breakpoints in debuggers. The code is *software-based* memory breakpointing.
* **Dynamic Analysis:** This is explicitly for dynamic instrumentation, fitting squarely within dynamic analysis.
* **Hooking:** While this specific code doesn't directly *hook* functions, it *intercepts* memory accesses at a lower level (via exceptions), which can be used in conjunction with hooking.

**5. Delving into Low-Level Details:**

Now, I'd look for code segments dealing with low-level aspects:

* **`sys/mman.h` and `gum_try_mprotect`:** These clearly indicate interaction with the operating system's memory management. The use of `mprotect` to change page permissions is crucial.
* **Page Alignment:** The code explicitly aligns memory ranges to page boundaries. This shows an understanding of how memory protection works at the page level.
* **Exception Handling (`gumexceptor.h`, `gum_memory_access_monitor_on_exception`):**  This highlights the mechanism used to detect access violations. The code registers a handler with the exception manager.
* **`GUM_MEMOP_*`:** The enumeration of memory operations (read, write, execute) and how they relate to page protections (`GUM_PAGE_*`).

**6. Analyzing Logic and Potential Inputs/Outputs:**

I'd examine functions with more complex logic, like `gum_memory_access_monitor_on_exception`:

* **Input:** An exception detail structure (`GumExceptionDetails`).
* **Logic:**  Checks if the exception is an access violation, determines the type of access, checks if it's within a monitored page, calls the notification function.
* **Output:**  Potentially calls the user-provided notification function.

I'd consider a hypothetical scenario: "The user wants to monitor writes to a specific memory region."  This leads to thinking about how the `access_mask` is used and how the `on_exception` handler reacts to write violations.

**7. Identifying Potential User Errors:**

Thinking about common programming mistakes and how users might interact with this API is key:

* **Incorrect Range Specification:** Providing invalid or overlapping memory ranges.
* **Enabling Without Proper Setup:**  Not ensuring the target process has the memory allocated before enabling the monitor.
* **Conflicting Monitors:**  Having multiple monitors trying to protect the same memory regions with different permissions.
* **Forgetting to Disable:**  Leaving the monitor enabled, potentially impacting performance.
* **Incorrect Notification Callback:**  Providing a callback function that crashes or has side effects.

**8. Tracing User Interaction (Debugging Clues):**

I'd imagine the steps a user might take to reach this code:

1. **Frida Script:** The user writes a Frida script.
2. **`MemoryAccessMonitor` API:** The script uses Frida's JavaScript API, likely involving `Process.enumerateRanges()` to find memory regions and then creating a `MemoryAccessMonitor` object.
3. **Frida Core:** The JavaScript API call translates into a call to the native Frida core.
4. **Gum Library:** The Frida core uses the Gum library, and eventually, `gum_memory_access_monitor_new` in this file gets called.
5. **Enabling the Monitor:** The script calls `enable()` on the `MemoryAccessMonitor` object, leading to `gum_memory_access_monitor_enable`.
6. **Memory Access:** The target process performs a memory access that violates the configured permissions.
7. **Exception Handling:** The OS signals an access violation, which is caught by Frida's exception handler, eventually calling `gum_memory_access_monitor_on_exception`.

**9. Structuring the Answer:**

Finally, I would organize the information into the requested categories: functionality, relationship to reverse engineering, low-level details, logic and I/O, user errors, and tracing user interaction. Using concrete examples makes the explanation clearer. I'd also use the file and function names mentioned in the prompt to ground the explanation.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "This is just about memory breakpoints."  **Correction:** While related, it's more about *monitoring* access and triggering notifications, not necessarily halting execution.
* **Initial thought:** "The user directly calls these C functions." **Correction:**  Users primarily interact through Frida's higher-level APIs (JavaScript, Python, etc.). The C code is the implementation detail.
* **Ensuring clarity:** Reviewing the explanation to make sure the connections between concepts (e.g., `mprotect` and access violations) are clearly stated.

This detailed thinking process, involving code scanning, mental model building, connecting to concepts, analyzing logic, considering errors, and tracing user flow, helps to generate a comprehensive and accurate answer to the request.
This is the source code for `gummemoryaccessmonitor-posix.c`, a component of Frida's dynamic instrumentation toolkit. Its primary function is to **monitor memory accesses (read, write, execute) within specified memory ranges in a target process on POSIX-based systems (like Linux and Android).**

Let's break down its functionality and address the specific points raised:

**功能 (Functionality):**

1. **Memory Range Monitoring:** It allows users to define specific memory ranges (base address and size) they want to monitor for access.
2. **Access Type Filtering:**  Users can specify which types of memory access they are interested in (read, write, execute) using the `access_mask`.
3. **Notification on Access:** When a monitored memory location is accessed in a way that matches the `access_mask`, a user-defined callback function (`notify_func`) is triggered. This callback receives details about the access, such as the type of operation, the address being accessed, and the address from which the access originated.
4. **Page-Level Granularity:** The monitoring operates at the memory page level. This means that if any byte within a monitored page is accessed, the notification is triggered.
5. **Automatic Reset (Optional):** The `auto_reset` flag controls whether the memory protection is automatically restored to its original state after an access is detected. If `auto_reset` is true, the access violation is essentially a "soft break," allowing the execution to continue. If false, the access violation will likely result in a signal (like SIGSEGV).
6. **Integration with Frida's Exception Handling:** It uses Frida's exception handling mechanism (`GumExceptor`) to intercept memory access violations.
7. **Enabling and Disabling:** The monitor can be enabled and disabled dynamically.
8. **Handles Unallocated/Inaccessible Pages:** It checks if the specified memory ranges are valid (allocated and accessible) before enabling the monitor.

**与逆向的方法的关系 (Relationship with Reverse Engineering Methods):**

This component is a powerful tool for dynamic analysis, a core technique in reverse engineering. Here's how it relates:

* **Memory Breakpoints:** It acts as a software-based memory breakpoint. Instead of halting execution like a debugger's hardware breakpoint, it allows you to be notified when specific memory locations are accessed. This is useful for:
    * **Tracking Data Access:**  Understanding how a program reads or writes to particular variables, data structures, or buffers. For example, you could monitor the memory region of a specific object to see when its fields are being modified.
    * **Identifying Sensitive Data Usage:**  Monitoring access to memory regions containing cryptographic keys, passwords, or other sensitive information.
    * **Understanding Algorithm Behavior:** Observing how data is processed and transformed within a particular function or code block by monitoring the memory it operates on.
    * **Finding Code that Accesses Specific Data:** By setting a watchpoint on a data location, you can pinpoint the exact instructions that read or write to it.

    **Example:** Let's say you are reverse-engineering a game and want to find out how the player's health is updated. You could:
    1. Use Frida to find the memory address where the player's health is stored.
    2. Use `gum_memory_access_monitor_new` to create a monitor for that memory address, specifically looking for write accesses (`GUM_PAGE_WRITE`).
    3. Enable the monitor using `gum_memory_access_monitor_enable`.
    4. When the player's health changes in the game, your `notify_func` will be called, providing you with information about the write operation, including the address of the instruction that performed the write.

* **Dynamic Analysis:**  It's a fundamental building block for dynamic analysis scripts in Frida. It allows you to observe the runtime behavior of a program without necessarily needing to step through every instruction.

**涉及二进制底层，linux, android内核及框架的知识 (Involvement of Binary, Linux/Android Kernel, and Framework Knowledge):**

This code directly interacts with low-level operating system features:

* **Binary Level:** It deals with memory addresses and sizes, which are core concepts in understanding how programs are laid out in memory.
* **Linux/Android Kernel:**
    * **`sys/mman.h` and `mprotect()`:** The code uses the `mprotect()` system call (or a wrapper `gum_try_mprotect`) to change the memory protection attributes of pages. This is a fundamental kernel function for memory management and security. Understanding how memory permissions (read, write, execute) work at the kernel level is crucial.
    * **Page Size:** It queries the system's page size (`gum_query_page_size()`). Memory protection is applied at the granularity of memory pages.
    * **Memory Mapping:**  The concept of memory ranges relates to how processes map memory regions.
    * **Exception Handling:** It relies on the operating system's exception handling mechanism (signals like SIGSEGV on Linux/Android) to detect access violations. Frida's `GumExceptor` hooks into this system.
* **Android Framework (Less Direct, but Applicable):** While the code itself is low-level, it can be used to analyze interactions with the Android framework. For example, you could monitor memory regions used by specific Android system services or framework components to understand their behavior.

**逻辑推理 (Logical Reasoning):**

Let's consider a hypothetical scenario:

**假设输入 (Hypothetical Input):**

* `ranges`: An array containing a single `GumMemoryRange` struct defining a memory region from address `0x1000` to `0x10FF` (size 256 bytes).
* `num_ranges`: 1
* `access_mask`: `GUM_PAGE_WRITE` (monitor write accesses).
* `auto_reset`: `TRUE`.
* `notify_func`: A custom function that prints "Write access detected at address: [address]".

**输出 (Output):**

1. **When a write operation occurs at address `0x1050` within the monitored range:**
   - The `gum_memory_access_monitor_on_exception` function will be triggered because a write access violation will occur due to the temporary modification of page permissions.
   - The `notify_func` will be called with `d.operation` set to `GUM_MEMOP_WRITE` and `d.address` set to `0x1050`.
   - The `notify_func` will print: "Write access detected at address: 0x1050".
   - Because `auto_reset` is `TRUE`, the memory protection of the page containing `0x1050` will be restored to its original state, allowing the program to continue execution (unless there are other issues).

2. **When a read operation occurs at address `0x10A0` within the monitored range:**
   - The `gum_memory_access_monitor_on_exception` function will *not* be triggered because the `access_mask` is set to `GUM_PAGE_WRITE`, and we are performing a read.

**用户或编程常见的使用错误 (Common User or Programming Errors):**

1. **Incorrect Range Specification:**
   ```c
   GumMemoryRange range = { .base_address = 0x1000, .size = 100 };
   GumMemoryAccessMonitor *monitor = gum_memory_access_monitor_new(&range, 1, GUM_PAGE_WRITE, TRUE, my_notify_func, NULL, NULL);
   ```
   If the actual memory region you intend to monitor is larger or starts at a different address, the monitor will not cover the intended area, leading to missed notifications.

2. **Monitoring Unallocated or Inaccessible Memory:**
   ```c
   GumMemoryRange range = { .base_address = 0xFFFFFFFFFFFFFFFF, .size = 100 }; // Likely invalid address
   GumMemoryAccessMonitor *monitor = gum_memory_access_monitor_new(&range, 1, GUM_PAGE_WRITE, TRUE, my_notify_func, NULL, NULL);
   if (!gum_memory_access_monitor_enable(monitor, &error)) {
       g_printerr("Error enabling monitor: %s\n", error->message); // This is likely to happen
       g_error_free(error);
   }
   ```
   The `gum_memory_access_monitor_enable` function will likely fail if the specified memory range is invalid, resulting in an error.

3. **Conflicting Access Masks:**  Setting an `access_mask` that doesn't align with the actual permissions of the memory region. For instance, monitoring for write access on a read-only memory region might not behave as expected.

4. **Forgetting to Disable the Monitor:**  If the monitor is left enabled unnecessarily, it can introduce performance overhead due to the exception handling mechanism.

5. **Errors in the `notify_func`:** If the user-provided `notify_func` has bugs or performs time-consuming operations, it can negatively impact the performance of the target process.

**用户操作是如何一步步的到达这里，作为调试线索 (How User Operations Reach This Code as Debugging Clues):**

1. **User Writes a Frida Script (JavaScript/Python/etc.):** The user starts by writing a Frida script to interact with a target process.
2. **Script Uses Frida's `MemoryAccessMonitor` API:** The script utilizes Frida's high-level API (e.g., in JavaScript: `MemoryAccessMonitor`) to create and configure a memory access monitor. This involves specifying the memory ranges and the access types to monitor.
3. **Frida's Core Translates API Calls:** The JavaScript API calls are translated by Frida's core into calls to the underlying C/C++ implementation. This is where functions like `gum_memory_access_monitor_new` get invoked.
4. **`gum_memory_access_monitor_new` is Called:** This function allocates and initializes the `GumMemoryAccessMonitor` structure based on the user's specifications.
5. **User Enables the Monitor (`monitor.enable()` in JavaScript):** The user's script then calls the `enable` method on the `MemoryAccessMonitor` object. This triggers the `gum_memory_access_monitor_enable` function in the C code.
6. **`gum_memory_access_monitor_enable` Sets Up Monitoring:** This function registers an exception handler (`gum_memory_access_monitor_on_exception`) and uses `mprotect` to modify the permissions of the monitored memory pages, causing access violations when the specified types of access occur.
7. **Target Process Accesses Monitored Memory:** When the target process attempts to access a memory location within the monitored range in a way that violates the modified permissions, the operating system generates an exception (e.g., SIGSEGV).
8. **Frida's Exception Handler Intercepts:** Frida's `GumExceptor` catches this exception.
9. **`gum_memory_access_monitor_on_exception` is Executed:**  Frida's exception handler calls the registered `gum_memory_access_monitor_on_exception` function.
10. **Notification Callback is Triggered:** Inside `gum_memory_access_monitor_on_exception`, if the access matches the configured `access_mask`, the user-provided `notify_func` is called, providing details about the memory access.

**Debugging Clues:**

Understanding this call flow is crucial for debugging:

* **If the monitor isn't triggering:** Check if the correct memory ranges and access masks are specified in the Frida script. Verify that `gum_memory_access_monitor_enable` was called successfully (check for errors).
* **If the `notify_func` isn't being called:** Ensure that the target process is actually accessing the monitored memory in the way you expect. Use other Frida tools (like `Interceptor` or `Stalker`) to confirm the access patterns.
* **If there are crashes or unexpected behavior:** Look for potential issues in the `notify_func`. Check if the `auto_reset` setting is appropriate for your use case. Incorrect memory range specifications can also lead to unexpected behavior.

In summary, `gummemoryaccessmonitor-posix.c` is a vital component for dynamic memory access monitoring in Frida on POSIX systems. It leverages low-level OS features to provide a powerful mechanism for reverse engineers and security researchers to understand how programs interact with memory at runtime.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-posix/gummemoryaccessmonitor-posix.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2019 Álvaro Felipe Melchor <alvaro.felipe91@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gummemoryaccessmonitor.h"

#include "gumexceptor.h"

#include <sys/mman.h>

typedef struct _GumPageState GumPageState;
typedef struct _GumRangeStats GumRangeStats;
typedef struct _GumLivePageDetails GumLivePageDetails;
typedef struct _GumEnumerateLivePagesContext GumEnumerateLivePagesContext;

typedef gboolean (* GumFoundLivePageFunc) (const GumLivePageDetails * details,
    gpointer user_data);

struct _GumMemoryAccessMonitor
{
  GObject parent;

  guint page_size;

  gboolean enabled;
  GumExceptor * exceptor;

  GumMemoryRange * ranges;
  guint num_ranges;
  volatile gint pages_remaining;
  gint pages_total;

  GumPageProtection access_mask;
  GArray * pages;
  gboolean auto_reset;

  GumMemoryAccessNotify notify_func;
  gpointer notify_data;
  GDestroyNotify notify_data_destroy;
};

struct _GumPageState
{
  gpointer base;
  GumPageProtection protection;
  guint range_index;
  volatile guint completed;
};

struct _GumRangeStats
{
  guint live_count;
  guint guarded_count;
};

struct _GumLivePageDetails
{
  gpointer base;
  GumPageProtection protection;
  guint range_index;
};

struct _GumEnumerateLivePagesContext
{
  GumFoundLivePageFunc func;
  gpointer user_data;

  GumMemoryAccessMonitor * monitor;
};

static void gum_memory_access_monitor_dispose (GObject * object);
static void gum_memory_access_monitor_finalize (GObject * object);

static gboolean gum_collect_range_stats (const GumLivePageDetails * details,
    gpointer user_data);
static gboolean gum_monitor_range (const GumLivePageDetails * details,
    gpointer user_data);
static gboolean gum_demonitor_range (const GumLivePageDetails * details,
    gpointer user_data);

static void gum_memory_access_monitor_enumerate_live_pages (
    GumMemoryAccessMonitor * self, GumFoundLivePageFunc func,
    gpointer user_data);
static gboolean gum_emit_live_range_if_monitored (
    const GumRangeDetails * details, gpointer user_data);

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
    g_clear_pointer (&self->notify_data, self->notify_data_destroy);

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
  monitor->ranges = g_memdup (ranges, num_ranges * sizeof (GumMemoryRange));
  monitor->num_ranges = num_ranges;
  monitor->access_mask = access_mask;
  monitor->auto_reset = auto_reset;
  monitor->pages_total = 0;

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

  stats.live_count = 0;
  stats.guarded_count = 0;
  gum_memory_access_monitor_enumerate_live_pages (self,
      gum_collect_range_stats, &stats);

  if (stats.live_count != self->pages_total)
    goto error_invalid_pages;
  else if (stats.guarded_count != 0)
    goto error_inaccessible_pages;

  self->exceptor = gum_exceptor_obtain ();
  gum_exceptor_add (self->exceptor, gum_memory_access_monitor_on_exception,
      self);

  self->pages = g_array_new (FALSE, FALSE, sizeof (GumPageState));
  gum_memory_access_monitor_enumerate_live_pages (self, gum_monitor_range,
      self);

  self->enabled = TRUE;

  return TRUE;

error_invalid_pages:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "One or more pages are unallocated");
    return FALSE;
  }
error_inaccessible_pages:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "One or more pages are already fully inaccessible");
    return FALSE;
  }
}

void
gum_memory_access_monitor_disable (GumMemoryAccessMonitor * self)
{
  if (!self->enabled)
    return;

  gum_memory_access_monitor_enumerate_live_pages (self, gum_demonitor_range,
      self);

  gum_exceptor_remove (self->exceptor, gum_memory_access_monitor_on_exception,
      self);
  g_object_unref (self->exceptor);
  self->exceptor = NULL;

  g_array_free (self->pages, TRUE);

  self->pages = NULL;
  self->enabled = FALSE;
}

static gboolean
gum_collect_range_stats (const GumLivePageDetails * details,
                         gpointer user_data)
{
  GumRangeStats * stats = user_data;

  stats->live_count++;
  if (details->protection == GUM_PAGE_NO_ACCESS)
    stats->guarded_count++;

  return TRUE;
}

static gboolean
gum_monitor_range (const GumLivePageDetails * details,
                   gpointer user_data)
{
  GumMemoryAccessMonitor * self = user_data;
  GumPageProtection old_prot, new_prot;
  GumPageState page;

  old_prot = details->protection;
  new_prot = (old_prot ^ self->access_mask) & old_prot;

  page.base = details->base;
  page.protection = old_prot;
  page.range_index = details->range_index;
  page.completed = 0;

  g_array_append_val (self->pages, page);

  gum_try_mprotect (page.base, self->page_size, new_prot);

  return TRUE;
}

static gboolean
gum_demonitor_range (const GumLivePageDetails * details,
                     gpointer user_data)
{
  GumMemoryAccessMonitor * self = user_data;
  guint i;

  for (i = 0; i != self->pages->len; i++)
  {
    const GumPageState * page = &g_array_index (self->pages, GumPageState, i);

    if (page->base == details->base)
    {
      gum_try_mprotect (page->base, self->page_size, page->protection);
      return TRUE;
    }
  }

  return TRUE;
}

static void
gum_memory_access_monitor_enumerate_live_pages (GumMemoryAccessMonitor * self,
                                                GumFoundLivePageFunc func,
                                                gpointer user_data)
{
  GumEnumerateLivePagesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  ctx.monitor = self;

  gum_process_enumerate_ranges (GUM_PAGE_NO_ACCESS,
      gum_emit_live_range_if_monitored, &ctx);
}

static gboolean
gum_emit_live_range_if_monitored (const GumRangeDetails * details,
                                  gpointer user_data)
{
  gboolean carry_on;
  GumEnumerateLivePagesContext * ctx = user_data;
  GumMemoryAccessMonitor * self = ctx->monitor;
  const guint page_size = self->page_size;
  const GumMemoryRange * range = details->range;
  gpointer range_start, range_end;
  guint i;

  range_start = GSIZE_TO_POINTER (range->base_address);
  range_end = range_start + range->size;

  carry_on = TRUE;

  for (i = 0; i != self->num_ranges && carry_on; i++)
  {
    const GumMemoryRange * r = &self->ranges[i];
    gpointer candidate_start, candidate_end;
    gpointer intersect_start, intersect_end;
    gpointer cur;

    candidate_start = GSIZE_TO_POINTER (r->base_address);
    candidate_end = candidate_start + r->size;

    intersect_start = MAX (range_start, candidate_start);
    intersect_end = MIN (range_end, candidate_end);
    if (intersect_end <= intersect_start)
      continue;

    for (cur = intersect_start;
        cur != intersect_end && carry_on;
        cur += page_size)
    {
      GumLivePageDetails d;

      d.base = cur;
      d.protection = details->protection;
      d.range_index = i;

      carry_on = ctx->func (&d, ctx->user_data);
    }
  }

  return carry_on;
}

static gboolean
gum_memory_access_monitor_on_exception (GumExceptionDetails * details,
                                        gpointer user_data)
{
  GumMemoryAccessMonitor * self = user_data;
  const guint page_size = self->page_size;
  GumMemoryAccessDetails d;
  guint i;

  if (details->type != GUM_EXCEPTION_ACCESS_VIOLATION)
    return FALSE;

  d.operation = details->memory.operation;
  d.from = details->address;
  d.address = details->memory.address;

  for (i = 0; i != self->pages->len; i++)
  {
    GumPageState * page;
    const GumMemoryRange * r;
    guint operation_mask;
    guint operations_reported;
    guint pages_remaining;

    page = &g_array_index (self->pages, GumPageState, i);
    r = &self->ranges[page->range_index];

    if (d.address >= page->base && d.address < page->base + page_size)
    {
      GumPageProtection original_prot = page->protection;

      switch (d.operation)
      {
        case GUM_MEMOP_READ:
          if ((original_prot & GUM_PAGE_READ) == 0)
            return FALSE;
          break;
        case GUM_MEMOP_WRITE:
          if ((original_prot & GUM_PAGE_WRITE) == 0)
            return FALSE;
          break;
        case GUM_MEMOP_EXECUTE:
          if ((original_prot & GUM_PAGE_EXECUTE) == 0)
            return FALSE;
          break;
        default:
          g_assert_not_reached ();
      }

      if (self->auto_reset)
        gum_try_mprotect (page->base, page_size, page->protection);

      operation_mask = 1 << d.operation;
      operations_reported = g_atomic_int_or (&page->completed, operation_mask);
      if (operations_reported != 0 && self->auto_reset)
        return FALSE;
      if (operations_reported == 0)
        pages_remaining = g_atomic_int_add (&self->pages_remaining, -1) - 1;
      else
        pages_remaining = g_atomic_int_get (&self->pages_remaining);
      d.pages_completed = self->pages_total - pages_remaining;

      d.range_index = page->range_index;
      d.page_index =
          (d.address - GSIZE_TO_POINTER (r->base_address)) / page_size;
      d.pages_total = self->pages_total;

      self->notify_func (self, &d, self->notify_data);

      return TRUE;
    }
  }

  return FALSE;
}

#endif

"""

```