Response:
Let's break down the thought process for analyzing this C code. The goal is to understand its functionality, its relation to reverse engineering, its interaction with low-level concepts, and potential usage scenarios and errors.

**1. Initial Skim and High-Level Understanding:**

* **Keywords:**  `frida`, `gum`, `darwin`, `memory`, `mach`, `mmap`, `mprotect`, `task`, `page`. These immediately suggest the code is related to memory management on macOS/iOS (Darwin kernel) within the Frida framework.
* **Includes:**  Standard C libraries (`errno.h`, `unistd.h`), Darwin-specific headers (`libkern/OSCacheControl.h`, `mach/mach.h`), and internal Frida headers (`gummemory.h`, `gum/gumdarwin.h`, `gummemory-priv.h`). This confirms the low-level, Darwin-specific nature.
* **Function Names:**  Functions like `gum_memory_allocate`, `gum_memory_free`, `gum_memory_read`, `gum_memory_write`, `gum_try_mprotect`, `gum_clear_cache` are strong indicators of memory manipulation. The `darwin` prefix suggests platform-specific implementations.

**2. Deeper Dive - Categorizing Functionality:**

Now, I'll go through the code function by function, grouping them by purpose:

* **Initialization/Deinitialization:** `_gum_memory_backend_init`, `_gum_memory_backend_deinit`. Likely sets up and tears down resources.
* **Page Size Querying:** `_gum_memory_backend_query_page_size`, `gum_darwin_query_page_size`. Retrieving the system's memory page size, crucial for memory management. The `darwin_query_page_size` with `task` suggests it can query page size for other processes.
* **PtrAuth Support:** `gum_darwin_query_ptrauth_support`. Dealing with pointer authentication, a security feature on ARM64.
* **Free Memory Range Enumeration:** `gum_enumerate_free_ranges`. Finding available memory regions. This is a core function for dynamic memory allocation.
* **Memory Read/Write:** `gum_memory_is_readable`, `gum_memory_query_protection`, `gum_memory_read`, `gum_memory_write`, `gum_darwin_read`, `gum_darwin_write`. Basic memory access operations, potentially across process boundaries (`task` argument).
* **Memory Protection:** `gum_try_mprotect`, `gum_mach_vm_protect`, `gum_page_protection_from_mach`, `gum_page_protection_to_mach`, `gum_page_protection_to_bsd`. Changing memory permissions (read, write, execute).
* **Cache Management:** `gum_clear_cache`. Ensuring data consistency between CPU caches and main memory, especially important when modifying code.
* **Page-Based Allocation:** `gum_try_alloc_n_pages`, `gum_try_alloc_n_pages_near`, `gum_query_page_allocation_range`, `gum_free_pages`. Allocating and freeing memory in page-sized chunks.
* **General Allocation:** `gum_memory_allocate`, `gum_allocate_page_aligned`, `gum_memory_allocate_near`, `gum_try_alloc_in_range_if_near_enough`, `gum_try_suggest_allocation_base`. More flexible allocation with size and alignment. The "near" versions attempt to allocate memory close to a specified address.
* **Deallocation:** `gum_memory_free`, `gum_memory_release`. Releasing allocated memory.
* **Memory Recommit/Discard/Decommit:** `gum_memory_recommit`, `gum_memory_discard`, `gum_memory_decommit`. More advanced memory management techniques to potentially free up resources or mark memory as unused.

**3. Connecting to Reverse Engineering:**

* **Observation:** Functions like `gum_memory_read`, `gum_memory_write`, `gum_try_mprotect` are fundamental to dynamic instrumentation. Reverse engineers use these to inspect process memory, modify code, and bypass security measures.
* **Example:**  Modifying the return value of a function, patching out a conditional jump, or injecting code into a running process.

**4. Identifying Low-Level Concepts:**

* **Kernel Interaction:** The use of `mach` APIs (`mach_vm_region_recurse`, `mach_vm_read`, `mach_vm_write`, `mach_vm_protect`, `mach_task_self`) clearly indicates direct interaction with the Darwin kernel.
* **Memory Pages:**  The frequent mention of `page_size` and functions operating on "n_pages" highlights the importance of page-level memory management.
* **Memory Protection Bits:** `VM_PROT_READ`, `VM_PROT_WRITE`, `VM_PROT_EXECUTE` are kernel-level flags controlling access permissions.
* **Address Spaces:**  The `task` argument in several functions signifies operations potentially spanning across different process address spaces.
* **CPU Architecture:** The conditional compilation with `HAVE_ARM`, `HAVE_ARM64`, `HAVE_I386` shows awareness of different CPU architectures and their specific system call conventions.
* **Caching:** `sys_icache_invalidate`, `sys_dcache_flush` are direct calls to manage CPU caches.

**5. Logical Reasoning and Assumptions:**

* **Allocation Near Hints:** The `gum_memory_allocate_near` functions and related logic (`gum_try_alloc_in_range_if_near_enough`, `gum_try_suggest_allocation_base`) involve searching for suitable memory regions based on proximity to a requested address. The assumption is that allocating memory nearby might be beneficial for performance or code locality.
* **Page Alignment:** Many functions ensure page alignment, which is a common requirement for memory protection and efficient memory management.
* **Error Handling:** The code frequently checks return values of system calls (`kern_return_t`) for success (`KERN_SUCCESS`).

**6. User/Programming Errors:**

* **Incorrect Size/Alignment:**  Providing incorrect sizes or alignment values to allocation functions can lead to crashes or unexpected behavior.
* **Accessing Freed Memory:**  Using pointers to memory that has been freed is a classic error.
* **Mismatched Protection Levels:**  Trying to write to read-only memory or execute non-executable memory will result in errors.
* **Cross-Process Issues:** When operating on a remote `task`, the target process might not be in a state where the memory operation is valid.

**7. Tracing User Actions (Debugging Clues):**

This part requires understanding how Frida is used:

* **Frida Script:** A user would typically write a JavaScript or Python script using the Frida API.
* **Frida API Calls:**  The script would eventually translate into calls to Frida's core library (`frida-core`).
* **Gum Integration:**  Frida Core uses Gum, its code manipulation engine. Functions in `gummemory-darwin.c` are part of Gum's backend for Darwin.
* **Example Trace:**
    1. User's Frida script calls `Memory.alloc(1024)` to allocate memory.
    2. This call in the JavaScript/Python bridge translates to a call within Frida Core.
    3. Frida Core invokes `gum_memory_allocate` (or a related allocation function) in `gummemory-darwin.c`.

**Self-Correction/Refinement during Analysis:**

* **Initially, I might just list function names.**  Then I'd group them by functionality.
* **When seeing `task` arguments,** I'd realize the cross-process capabilities are important.
* **Spotting the ARM-specific code** prompts me to consider architecture-specific details.
* **If unsure about a specific system call,** I'd quickly look up its documentation (e.g., `man mach_vm_protect`).

By following these steps, systematically examining the code, and leveraging prior knowledge of operating systems and reverse engineering concepts, a comprehensive understanding of the file's purpose and implications can be achieved.
This C source code file, `gummemory-darwin.c`, is a backend implementation for memory management within the Frida dynamic instrumentation toolkit, specifically for the Darwin operating system (macOS, iOS, etc.). It provides low-level primitives for allocating, freeing, reading, writing, and modifying the protection of memory regions within a process.

Here's a breakdown of its functionalities, relating them to reverse engineering, binary details, and potential usage:

**Core Functionalities:**

1. **Memory Allocation and Deallocation:**
   - `gum_memory_allocate()`: Allocates a block of memory with specified size and alignment.
   - `gum_allocate_page_aligned()`: A helper function to allocate page-aligned memory using `mmap`.
   - `gum_memory_allocate_near()`: Attempts to allocate memory near a specified address. This is crucial for code injection and hooking where proximity to existing code is sometimes necessary.
   - `gum_memory_free()` and `gum_memory_release()`: Deallocates previously allocated memory using `munmap`.
   - `gum_try_alloc_n_pages()` and `gum_try_alloc_n_pages_near()`: Allocate memory in page-sized chunks, often used for injecting executable code.
   - `gum_free_pages()`: Frees memory allocated using the page-based allocation functions.

2. **Memory Access (Read and Write):**
   - `gum_memory_read()` and `gum_darwin_read()`: Reads data from a specified memory address. This is fundamental for reverse engineering to inspect data structures, function arguments, and code.
   - `gum_memory_write()` and `gum_darwin_write()`: Writes data to a specified memory address. This is essential for patching code, modifying data, and injecting payloads.

3. **Memory Protection Modification:**
   - `gum_try_mprotect()` and `gum_mach_vm_protect()`: Changes the memory protection attributes (read, write, execute permissions) of a memory region using the `mach_vm_protect` system call. This is vital for making allocated memory executable for injected code or for temporarily making read-only memory writable for patching.
   - `gum_page_protection_from_mach()` and `gum_page_protection_to_mach()`: Convert between Frida's `GumPageProtection` enum and the Mach kernel's memory protection flags.
   - `gum_page_protection_to_bsd()`: Converts Frida's protection flags to BSD-style protection flags (used by `mmap`).

4. **Memory Querying:**
   - `gum_memory_is_readable()`: Checks if a memory region is readable.
   - `gum_memory_query_protection()`: Retrieves the current memory protection attributes of a memory region.
   - `gum_darwin_query_page_size()`: Queries the system's page size, which is fundamental for page-aligned operations.
   - `gum_darwin_query_ptrauth_support()`: Checks if pointer authentication is supported for a given task (process). This is a security feature on ARM64 architectures.
   - `gum_enumerate_free_ranges()`: Iterates through the free memory regions of a process. This can be useful for finding suitable locations for memory allocation.
   - `gum_query_page_allocation_range()`: Determines the full range of a page allocation (including the guard page).

5. **Cache Management:**
   - `gum_clear_cache()`: Invalidates the instruction cache and flushes the data cache for a given memory region. This is crucial after writing executable code to memory to ensure the CPU fetches the updated instructions.

6. **Memory Recommit, Discard, and Decommit:**
   - `gum_memory_recommit()`: Makes previously discarded memory available again (using `madvise` with `MADV_FREE_REUSE`).
   - `gum_memory_discard()`: Marks memory as eligible to be freed by the system (using `madvise` with `MADV_FREE_REUSABLE` or `MADV_DONTNEED`).
   - `gum_memory_decommit()`: Decommits memory, making it inaccessible and potentially freeing up physical memory (using `mmap` with `PROT_NONE`).

**Relationship with Reverse Engineering:**

This file is deeply intertwined with reverse engineering techniques using dynamic instrumentation:

* **Code Injection:** Functions like `gum_memory_allocate_near`, `gum_try_alloc_n_pages_near`, and `gum_try_mprotect` are used to allocate executable memory and change its protection, enabling the injection of custom code into a running process.
    * **Example:** A reverse engineer might want to inject a custom function into a target application to log its behavior or intercept API calls. They would allocate memory using `gum_memory_allocate_near`, copy the code into it using `gum_memory_write`, and then make the memory executable using `gum_try_mprotect`.
* **Hooking:** To intercept function calls, reverse engineers often overwrite the beginning of a function with a jump to their own code. This requires writing to the function's memory using `gum_memory_write`. Before writing, they might need to temporarily change the memory protection to make it writable using `gum_try_mprotect`.
    * **Example:**  A reverse engineer might hook the `malloc` function to track memory allocations or the `open` system call to monitor file access.
* **Data Inspection and Modification:**  `gum_memory_read` allows reading the contents of memory to understand data structures and variable values. `gum_memory_write` enables modifying data to change program behavior.
    * **Example:** A reverse engineer could read the value of a flag variable to understand a program's decision-making process or modify a return value to bypass a security check.

**Binary 底层 (Binary Low-Level), Linux, Android Kernel & Framework Knowledge:**

* **Binary 底层 (Binary Low-Level):**
    * **Memory Layout:** The code operates directly on memory addresses and interacts with the operating system's memory management mechanisms. Understanding how processes are laid out in memory (stack, heap, code sections) is crucial for using these functions effectively.
    * **System Calls:**  The code directly uses Darwin-specific system calls like `mmap`, `munmap`, `sys_icache_invalidate`, `sys_dcache_flush`, and `mach_vm_protect`. Knowledge of these system calls and their arguments is essential.
    * **Page Alignment:** Many operations are page-aligned because memory protection is managed at the page level. The code frequently uses `getpagesize()` to determine the page size.
    * **CPU Caches:** `gum_clear_cache` directly interacts with the CPU's caching mechanisms, demonstrating an understanding of how instructions are fetched and executed.
* **Linux/Android Kernel & Framework (While Darwin-Specific):**
    * **Memory Management Concepts:** The fundamental concepts of memory allocation, deallocation, and protection are similar across operating systems. Understanding concepts like virtual memory, paging, and memory regions is transferable.
    * **System Call Parallels:** While the specific system calls differ (e.g., `mmap` exists on Linux too, but `mach_vm_protect` is Darwin-specific, with `mprotect` being its Linux equivalent), the underlying principles are the same. Understanding Linux's `mprotect` would help in grasping the purpose of `gum_try_mprotect`.
    * **Code Injection Techniques:** The principles behind code injection and hooking are similar across platforms, even though the implementation details vary.

**Logical Reasoning, Assumptions, Input & Output:**

Let's take the `gum_memory_allocate_near` function as an example:

* **Assumption:** The assumption is that allocating memory close to a specific address might be beneficial for performance (better cache locality) or for code injection scenarios where relative addressing is used.
* **Input:**
    * `spec`: A `GumAddressSpec` structure containing the desired `near_address` and potentially other constraints.
    * `size`: The size of the memory block to allocate.
    * `alignment`: The required alignment of the memory block.
    * `prot`: The desired memory protection (`GumPageProtection`).
* **Logical Reasoning:**
    1. It first tries a direct allocation near the suggested address using `gum_memory_allocate`.
    2. If that fails or doesn't meet the specification, it iterates through free memory ranges using `gum_enumerate_free_ranges`.
    3. For each free range, `gum_try_alloc_in_range_if_near_enough` is called to see if the range is suitable.
    4. `gum_try_suggest_allocation_base` attempts to calculate a suitable base address within the free range that is close to the desired address and meets the alignment requirements.
    5. If a suitable location is found, `gum_memory_allocate` is called again to allocate memory in that range.
* **Output:**
    * A pointer to the allocated memory block if successful.
    * `NULL` if allocation fails.

**User/Programming Common Usage Errors:**

1. **Incorrect Size or Alignment:** Passing incorrect size or alignment values to allocation functions can lead to memory corruption or crashes.
    * **Example:** Allocating less memory than needed to store data, or requesting an alignment that is not a power of 2.
2. **Memory Leaks:** Forgetting to call `gum_memory_free` or `gum_free_pages` after allocating memory results in memory leaks, potentially leading to performance degradation and eventually crashes.
    * **Example:** Allocating memory for a temporary buffer and not freeing it after use.
3. **Accessing Freed Memory (Use-After-Free):** Dereferencing a pointer to memory that has already been freed is a common and dangerous error, leading to unpredictable behavior and security vulnerabilities.
    * **Example:** Freeing a buffer and then later trying to read or write to it.
4. **Incorrect Memory Protection:** Setting incorrect memory protection flags can lead to crashes (e.g., trying to write to read-only memory, or executing code in a non-executable region).
    * **Example:**  Allocating memory for code but forgetting to set the execute permission before jumping to it.
5. **Cross-Process Issues (if Frida is used to target another process):**  Attempting to read or write memory in another process without proper permissions or if the target process's memory layout has changed can lead to errors.
6. **Cache Incoherence:** Modifying code in memory without calling `gum_clear_cache` might result in the CPU executing stale instructions from its cache, leading to unexpected behavior.

**User Operation Steps to Reach This Code (Debugging Clues):**

1. **User writes a Frida script (JavaScript or Python).**
2. **The script uses Frida's API for memory manipulation.** This could involve:
   - `Memory.alloc(size)` to allocate memory.
   - `Memory.protect(address, size, protection)` to change memory protection.
   - `Memory.readByteArray(address, length)` or `Memory.writeByteArray(address, data)` to read or write memory.
   - `Interceptor.replace(address, nativeCallback)` or similar hooking mechanisms.
3. **The Frida script interacts with a target process.**
4. **Frida's core library (`frida-core`) receives the API calls from the script.**
5. **For memory-related operations on Darwin, `frida-core` dispatches these calls to the Gum library.** Gum is Frida's code manipulation engine.
6. **Within Gum, the platform-specific backend for Darwin is invoked, which includes `gummemory-darwin.c`.**
7. **The specific functions in `gummemory-darwin.c` are called based on the Frida API functions used in the script.** For example, `Memory.alloc()` in the script might eventually lead to a call to `gum_memory_allocate()` in this file.

**Example Debugging Scenario:**

Let's say a user's Frida script attempts to inject code into a running process and gets a crash. Debugging could involve:

1. **Examining the crash logs or debugger output.**  This might show an error related to memory access (e.g., segmentation fault).
2. **Reviewing the Frida script.**  Is the allocation size correct? Is the memory protection set to execute? Are there any use-after-free errors?
3. **Using Frida's debugging features or a debugger attached to the Frida agent.** This could involve setting breakpoints within the Frida agent or even within the `gummemory-darwin.c` code itself.
4. **Tracing the execution flow.**  Stepping through the code can help pinpoint where the memory allocation or protection change is failing. For example, if `gum_try_mprotect` returns an error, it indicates an issue with changing memory permissions.
5. **Verifying assumptions about the target process's memory layout.**  Is there enough free memory at the desired location? Are there any memory regions that might interfere with the allocation?

In summary, `gummemory-darwin.c` is a crucial component of Frida on Darwin, providing the foundational memory management capabilities necessary for dynamic instrumentation and reverse engineering tasks. Understanding its functions and their relationship to low-level OS concepts is key to effectively using Frida for these purposes.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gummemory-darwin.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gummemory.h"

#include "gum/gumdarwin.h"
#include "gummemory-priv.h"

#include <errno.h>
#include <unistd.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <sys/sysctl.h>

typedef gboolean (* GumFoundFreeRangeFunc) (const GumMemoryRange * range,
    gpointer user_data);

typedef struct _GumAllocNearContext GumAllocNearContext;

struct _GumAllocNearContext
{
  const GumAddressSpec * spec;
  gsize size;
  gsize alignment;
  gsize page_size;
  GumPageProtection prot;

  gpointer result;
};

static gpointer gum_allocate_page_aligned (gpointer address, gsize size,
    gint prot);
static gboolean gum_try_alloc_in_range_if_near_enough (
    const GumMemoryRange * range, gpointer user_data);
static gboolean gum_try_suggest_allocation_base (const GumMemoryRange * range,
    const GumAllocNearContext * ctx, gpointer * allocation_base);
static gint gum_page_protection_to_bsd (GumPageProtection prot);

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
  return getpagesize ();
}

gboolean
gum_darwin_query_ptrauth_support (mach_port_t task,
                                  GumPtrauthSupport * ptrauth_support)
{
#ifdef HAVE_ARM64
  GumDarwinAllImageInfos infos;
  GumAddress actual_ptr, stripped_ptr;

  if (task == mach_task_self ())
  {
    *ptrauth_support = gum_query_ptrauth_support ();
    return TRUE;
  }

  if (!gum_darwin_query_all_image_infos (task, &infos))
    return FALSE;

  actual_ptr = infos.notification_address;
  stripped_ptr = actual_ptr & G_GUINT64_CONSTANT (0x7fffffffff);

  *ptrauth_support = (stripped_ptr != actual_ptr)
      ? GUM_PTRAUTH_SUPPORTED
      : GUM_PTRAUTH_UNSUPPORTED;
#else
  *ptrauth_support = GUM_PTRAUTH_UNSUPPORTED;
#endif

  return TRUE;
}

gboolean
gum_darwin_query_page_size (mach_port_t task,
                            guint * page_size)
{
  int pid;
  kern_return_t kr;
  GumCpuType cpu_type;

  if (task == mach_task_self ())
  {
    *page_size = gum_query_page_size ();
    return TRUE;
  }

  /* FIXME: any way we can probe it without access to the task's host port? */
  kr = pid_for_task (task, &pid);
  if (kr != KERN_SUCCESS)
    return FALSE;

  if (!gum_darwin_cpu_type_from_pid (pid, &cpu_type))
    return FALSE;

  switch (cpu_type)
  {
    case GUM_CPU_IA32:
    case GUM_CPU_AMD64:
      *page_size = 4096;
      break;
    case GUM_CPU_ARM:
    {
      if (gum_darwin_check_xnu_version (3216, 0, 0))
      {
        char buf[256];
        size_t size;
        G_GNUC_UNUSED int res;
        guint64 hw_page_size = 0;

        size = sizeof (buf);
        res = sysctlbyname ("hw.pagesize", buf, &size, NULL, 0);
        g_assert (res == 0);

        if (size == 8)
          hw_page_size = *((guint64 *) buf);
        else if (size == 4)
          hw_page_size = *((guint32 *) buf);
        else
          g_assert_not_reached ();

        *page_size = hw_page_size;
      }
      else
      {
        *page_size = 4096;
      }

      break;
    }
    case GUM_CPU_ARM64:
      *page_size = 16384;
      break;
    default:
      g_assert_not_reached ();
  }

  return TRUE;
}

static void
gum_enumerate_free_ranges (GumFoundFreeRangeFunc func,
                           gpointer user_data)
{
  mach_port_t self;
  guint page_size, index;
  mach_vm_address_t address = MACH_VM_MIN_ADDRESS;
  GumAddress prev_end = 0;

  self = mach_task_self ();

  page_size = gum_query_page_size ();

  for (index = 0; TRUE; index++)
  {
    mach_vm_size_t size = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info;
    mach_msg_type_number_t info_count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t kr;

    kr = mach_vm_region_recurse (self, &address, &size, &depth,
        (vm_region_recurse_info_t) &info, &info_count);
    if (kr != KERN_SUCCESS)
    {
      if (prev_end != 0)
      {
        GumAddress max_address;
        GumMemoryRange r;

#if GLIB_SIZEOF_VOID_P == 4
        max_address = 0xffffffff;
#elif defined (HAVE_I386)
        max_address = G_GUINT64_CONSTANT (0x0001000000000000);
#elif defined (HAVE_ARM64)
        max_address = G_GUINT64_CONSTANT (0x0000000200000000);
#endif

        if (max_address > prev_end)
        {
          r.base_address = prev_end;
          r.size = max_address - prev_end;

          func (&r, user_data);
        }
      }

      break;
    }

    if (index == 0 && address > page_size)
    {
      GumMemoryRange r;

      r.base_address = page_size;
      r.size = address - page_size;

      if (!func (&r, user_data))
        break;
    }

    if (prev_end != 0)
    {
      gint64 gap_size;

      gap_size = address - prev_end;

      if (gap_size > 0)
      {
        GumMemoryRange r;

        r.base_address = prev_end;
        r.size = gap_size;

        if (!func (&r, user_data))
          break;
      }
    }

    prev_end = address + size;

    address += size;
  }
}

gboolean
gum_memory_is_readable (gconstpointer address,
                        gsize len)
{
  gboolean is_readable;
  guint8 * bytes;
  gsize n_bytes_read;

  bytes = gum_memory_read (address, len, &n_bytes_read);
  is_readable = bytes != NULL && n_bytes_read == len;
  g_free (bytes);

  return is_readable;
}

gboolean
gum_memory_query_protection (gconstpointer address,
                             GumPageProtection * prot)
{
  return gum_darwin_query_protection (mach_task_self (), GUM_ADDRESS (address),
      prot);
}

guint8 *
gum_memory_read (gconstpointer address,
                 gsize len,
                 gsize * n_bytes_read)
{
  return gum_darwin_read (mach_task_self (), GUM_ADDRESS (address), len,
      n_bytes_read);
}

gboolean
gum_memory_write (gpointer address,
                  const guint8 * bytes,
                  gsize len)
{
  return gum_darwin_write (mach_task_self (), GUM_ADDRESS (address), bytes,
      len);
}

guint8 *
gum_darwin_read (mach_port_t task,
                 GumAddress address,
                 gsize len,
                 gsize * n_bytes_read)
{
  guint page_size;
  guint8 * result;
  gsize offset;
  kern_return_t kr;

  if (!gum_darwin_query_page_size (task, &page_size))
    return NULL;

  result = g_malloc (len);
  offset = 0;

  while (offset != len)
  {
    GumAddress chunk_address, page_address;
    gsize chunk_size, page_offset;

    chunk_address = address + offset;
    page_address = chunk_address & ~(GumAddress) (page_size - 1);
    page_offset = chunk_address - page_address;
    chunk_size = MIN (len - offset, page_size - page_offset);

#if defined (HAVE_IOS) || defined (HAVE_TVOS)
    mach_vm_size_t n_bytes_read;

    /* mach_vm_read corrupts memory on iOS */
    kr = mach_vm_read_overwrite (task, chunk_address, chunk_size,
        (vm_address_t) (result + offset), &n_bytes_read);
    if (kr != KERN_SUCCESS)
      break;
    g_assert (n_bytes_read == chunk_size);
#else
    vm_offset_t result_data;
    mach_msg_type_number_t result_size;

    /* mach_vm_read_overwrite leaks memory on macOS */
    kr = mach_vm_read (task, page_address, page_size,
        &result_data, &result_size);
    if (kr != KERN_SUCCESS)
      break;
    g_assert (result_size == page_size);
    memcpy (result + offset, (gpointer) (result_data + page_offset),
        chunk_size);
    mach_vm_deallocate (mach_task_self (), result_data, result_size);
#endif

    offset += chunk_size;
  }

  if (offset == 0)
  {
    g_free (result);
    result = NULL;
  }

  if (n_bytes_read != NULL)
    *n_bytes_read = offset;

  return result;
}

gboolean
gum_darwin_write (mach_port_t task,
                  GumAddress address,
                  const guint8 * bytes,
                  gsize len)
{
  kern_return_t kr;

  kr = mach_vm_write (task, address, (vm_offset_t) bytes, len);

  return (kr == KERN_SUCCESS);
}

static kern_return_t
gum_mach_vm_protect (vm_map_t target_task,
                     mach_vm_address_t address,
                     mach_vm_size_t size,
                     boolean_t set_maximum,
                     vm_prot_t new_protection)
{
#if defined (HAVE_ARM)
  kern_return_t result;
  guint32 args[] = {
    target_task,
    address & 0xffffffff,
    (address >> 32) & 0xffffffff,
    size & 0xffffffff,
    (size >> 32) & 0xffffffff,
    set_maximum,
    new_protection,
    0
  };

  /* FIXME: Should avoid clobbering R7, which is reserved. */
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winline-asm"

  asm volatile (
      "push {r0, r1, r2, r3, r4, r5, r6, r7, r12}\n\t"
      "ldmdb %1!, {r0, r1, r2, r3, r4, r5, r6, r7}\n\t"
      "mvn r12, 0xd\n\t"
      "svc 0x80\n\t"
      "mov %0, r0\n\t"
      "pop {r0, r1, r2, r3, r4, r5, r6, r7, r12}\n\t"
      : "=r" (result)
      : "r" (args + G_N_ELEMENTS (args))
      : "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r12"
  );

#pragma clang diagnostic pop

  return result;
#elif defined (HAVE_ARM64)
  kern_return_t result;

  asm volatile (
      "sub sp, sp, #16 * 3\n\t"
      "stp x0, x1, [sp, #16 * 0]\n\t"
      "stp x2, x3, [sp, #16 * 1]\n\t"
      "stp x4, x16, [sp, #16 * 2]\n\t"
      "mov x0, %1\n\t"
      "mov x1, %2\n\t"
      "mov x2, %3\n\t"
      "mov x3, %4\n\t"
      "mov x4, %5\n\t"
      "movn x16, 0xd\n\t"
      "svc 0x80\n\t"
      "mov %w0, w0\n\t"
      "ldp x0, x1, [sp, #16 * 0]\n\t"
      "ldp x2, x3, [sp, #16 * 1]\n\t"
      "ldp x4, x16, [sp, #16 * 2]\n\t"
      "add sp, sp, #16 * 3\n\t"
      : "=r" (result)
      : "r" ((gsize) target_task),
        "r" (address),
        "r" (size),
        "r" ((gsize) set_maximum),
        "r" ((gsize) new_protection)
      : "x0", "x1", "x2", "x3", "x4", "x16"
  );

  return result;
#else
  return mach_vm_protect (target_task, address, size, set_maximum,
      new_protection);
#endif
}

gboolean
gum_try_mprotect (gpointer address,
                  gsize size,
                  GumPageProtection prot)
{
  gsize page_size;
  gpointer aligned_address;
  gsize aligned_size;
  vm_prot_t mach_prot;
  kern_return_t kr;

  g_assert (size != 0);

  page_size = gum_query_page_size ();
  aligned_address = GSIZE_TO_POINTER (
      GPOINTER_TO_SIZE (address) & ~(page_size - 1));
  aligned_size =
      (1 + ((address + size - 1 - aligned_address) / page_size)) * page_size;
  mach_prot = gum_page_protection_to_mach (prot);

  kr = gum_mach_vm_protect (mach_task_self (),
      GPOINTER_TO_SIZE (aligned_address), aligned_size, FALSE, mach_prot);

  return kr == KERN_SUCCESS;
}

void
gum_clear_cache (gpointer address,
                 gsize size)
{
  sys_icache_invalidate (address, size);
  sys_dcache_flush (address, size);
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
  gsize page_size;
  mach_vm_address_t address;
  mach_vm_size_t size;
  G_GNUC_UNUSED kern_return_t kr;

  page_size = gum_query_page_size ();

  address = GPOINTER_TO_SIZE (mem) - page_size;
  size = *((gsize *) address);

  kr = mach_vm_deallocate (mach_task_self (), address, size);
  g_assert (kr == KERN_SUCCESS);
}

gpointer
gum_memory_allocate (gpointer address,
                     gsize size,
                     gsize alignment,
                     GumPageProtection prot)
{
  gsize page_size, allocation_size;
  guint8 * base, * aligned_base;

  address = GUM_ALIGN_POINTER (gpointer, address, alignment);

  page_size = gum_query_page_size ();
  allocation_size = size + (alignment - page_size);
  allocation_size = GUM_ALIGN_SIZE (allocation_size, page_size);

  base = gum_allocate_page_aligned (address, allocation_size,
      gum_page_protection_to_bsd (prot));
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

static gpointer
gum_allocate_page_aligned (gpointer address,
                           gsize size,
                           gint prot)
{
  gpointer result;

  result = mmap (address, size, prot, MAP_PRIVATE | MAP_ANONYMOUS,
      VM_MAKE_TAG (255), 0);
  if (result == MAP_FAILED)
    return NULL;

#if (defined (HAVE_IOS) || defined (HAVE_TVOS)) && !defined (HAVE_I386)
  {
    gboolean need_checkra1n_quirk;

    need_checkra1n_quirk = prot == (PROT_READ | PROT_WRITE | PROT_EXEC) &&
        gum_query_rwx_support () == GUM_RWX_ALLOCATIONS_ONLY;
    if (need_checkra1n_quirk)
    {
      gum_mach_vm_protect (mach_task_self (), GPOINTER_TO_SIZE (result), size,
          FALSE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
    }
  }
#endif

  return result;
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
gum_try_alloc_in_range_if_near_enough (const GumMemoryRange * range,
                                       gpointer user_data)
{
  GumAllocNearContext * ctx = user_data;
  gpointer suggested_base, received_base;

  if (!gum_try_suggest_allocation_base (range, ctx, &suggested_base))
    goto keep_looking;

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
  int res;

  do
    res = madvise (address, size, MADV_FREE_REUSE);
  while (res == -1 && errno == EAGAIN);

  return TRUE;
}

gboolean
gum_memory_discard (gpointer address,
                    gsize size)
{
  int res;

  do
    res = madvise (address, size, MADV_FREE_REUSABLE);
  while (res == -1 && errno == EAGAIN);

  if (res == -1)
    res = madvise (address, size, MADV_DONTNEED);

  return res == 0;
}

gboolean
gum_memory_decommit (gpointer address,
                     gsize size)
{
  return mmap (address, size, PROT_NONE,
      MAP_FIXED | MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) == address;
}

GumPageProtection
gum_page_protection_from_mach (vm_prot_t native_prot)
{
  GumPageProtection prot = 0;

  if ((native_prot & VM_PROT_READ) == VM_PROT_READ)
    prot |= GUM_PAGE_READ;
  if ((native_prot & VM_PROT_WRITE) == VM_PROT_WRITE)
    prot |= GUM_PAGE_WRITE;
  if ((native_prot & VM_PROT_EXECUTE) == VM_PROT_EXECUTE)
    prot |= GUM_PAGE_EXECUTE;

  return prot;
}

vm_prot_t
gum_page_protection_to_mach (GumPageProtection prot)
{
  vm_prot_t mach_prot = VM_PROT_NONE;

  if ((prot & GUM_PAGE_READ) != 0)
    mach_prot |= VM_PROT_READ;
  if ((prot & GUM_PAGE_WRITE) != 0)
    mach_prot |= VM_PROT_WRITE | VM_PROT_COPY;
  if ((prot & GUM_PAGE_EXECUTE) != 0)
    mach_prot |= VM_PROT_EXECUTE;

  return mach_prot;
}

static gint
gum_page_protection_to_bsd (GumPageProtection prot)
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