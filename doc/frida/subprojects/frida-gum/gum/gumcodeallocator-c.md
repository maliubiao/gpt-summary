Response:
Let's break down the thought process for analyzing the C code and fulfilling the request.

**1. Initial Understanding of the Goal:**

The core request is to understand the functionality of `gumcodeallocator.c` within the Frida dynamic instrumentation framework. The request specifically asks to identify its purpose, relate it to reverse engineering, explain its low-level aspects, explore logical reasoning, point out common usage errors, and describe how a user might trigger this code.

**2. High-Level Reading and Identifying Key Structures and Functions:**

My first pass involves quickly skimming the code, looking for major types, function names, and overall code structure. I notice the following:

* **Includes:**  Headers like `gumcodeallocator.h`, `gumcloak.h`, `gumcodesegment.h`, `gummemory.h`, and architecture-specific headers (ARM, ARM64) indicate the file deals with code management, memory operations, and potentially hooking/instrumentation.
* **Structures:**  `GumCodeSlice`, `GumCodePages`, `GumCodeDeflectorDispatcher`, and `GumCodeDeflectorImpl` are central. Their members suggest the code manages blocks of executable memory, tracks their usage, and deals with redirecting execution.
* **Functions:**  Names like `alloc_slice`, `commit`, `alloc_deflector`, `insert_deflector`, and `write_thunk` strongly hint at allocation, memory management, and code modification (likely for hooking).
* **Conditional Compilation:**  `#ifdef HAVE_ARM`, `#ifdef HAVE_ARM64`, `#if defined (HAVE_DARWIN) || ...` show platform-specific logic, particularly around code injection.

**3. Focusing on Core Functionality - Code Allocation:**

The name `gumcodeallocator` and functions like `gum_code_allocator_alloc_slice` and `gum_code_allocator_try_alloc_batch_near` immediately suggest its primary purpose is to allocate executable memory. I then examine how this allocation works:

* **Slices and Pages:** The code allocates memory in `slices` within larger `pages`. This is a common optimization to reduce allocation overhead.
* **Near Allocation:** The `try_alloc_slice_near` function and the `GumAddressSpec` structure indicate an attempt to allocate memory close to a specified address. This is crucial for code patching and hooking, where relative jumps are often used.
* **Commitment:** The `gum_code_allocator_commit` function hints at a two-stage allocation process, where memory is initially reserved (perhaps read-write) and then made executable. The handling of `uncommitted_pages` and `dirty_pages` confirms this.
* **Code Segments:** The use of `GumCodeSegment` suggests leveraging OS-level code segments for better security and management, if supported. The code handles cases where this isn't supported.

**4. Focusing on Code Deflection (Hooking/Redirection):**

The presence of `GumCodeDeflector` and related functions points to the core instrumentation capability.

* **Deflectors:** `gum_code_allocator_alloc_deflector` allocates a "deflector," which is a mechanism to intercept and redirect execution.
* **Dispatchers:** `GumCodeDeflectorDispatcher` appears to manage multiple deflectors targeting the same code location. This is an optimization to reduce overhead when multiple hooks are placed near each other.
* **Trampolines and Thunks:** These are key concepts in hooking. The "trampoline" is the jump inserted at the target location, redirecting execution. The "thunk" is a small piece of code that saves context, calls a handler, and restores context before returning to the original execution flow.
* **`gum_insert_deflector` and `gum_write_thunk`:** These functions contain architecture-specific assembly code to implement the redirection logic. The use of `ldr pc, ...` or `br x0` is a telltale sign of code injection.
* **Code Caves:** The `gum_probe_module_for_code_cave` function searches for small, unused regions in the target process's memory where the trampoline can be placed. This is a common technique in hooking.

**5. Connecting to Reverse Engineering Concepts:**

With an understanding of the core functionality, I can now explicitly link it to reverse engineering:

* **Dynamic Instrumentation:** The whole purpose of Frida is dynamic instrumentation, and this code is a foundational component.
* **Hooking:** The code deflection mechanism is a direct implementation of hooking, allowing modification of program behavior at runtime.
* **Code Injection:** The process of writing the trampoline and thunk involves injecting new code into the target process.
* **Bypassing Protections:** The handling of RWX memory and code segments suggests an attempt to work around memory protection mechanisms.

**6. Identifying Low-Level Details:**

This involves looking closer at the code:

* **Memory Management:** Functions like `gum_alloc_n_pages`, `gum_free_pages`, and `gum_mprotect` are direct interactions with the operating system's memory management.
* **Architecture-Specific Code:** The `#ifdef` blocks show how the code adapts to different CPU architectures, generating appropriate assembly instructions.
* **Cache Coherency:** `gum_clear_cache` is essential to ensure that the modified code is seen by the CPU.
* **Page Alignment:** The `gum_query_page_size()` function and the allocation in multiples of page size highlight the importance of page-level memory management.

**7. Inferring Logical Reasoning, Assumptions, and Error Conditions:**

* **Near Allocation Assumption:** The code assumes that allocating memory close to the target is beneficial for performance or correctness of hooks (likely due to relative addressing).
* **Code Cave Assumption:** The code assumes that finding a small, empty code cave is a reliable way to insert trampolines.
* **Error Handling:**  While there's some checking for `NULL` returns (e.g., in allocation), there's not extensive error handling. This is typical for low-level instrumentation code, where the focus is on performance and the expectation is that higher-level code will handle errors.
* **User Errors:** Common mistakes would involve incorrect `GumAddressSpec` values, failing to `commit` allocated memory, or memory corruption if slices are misused.

**8. Tracing User Actions:**

I consider how a user would interact with Frida and eventually trigger this code. The user would:

* **Write a Frida Script:**  This script would use Frida's API to specify where to hook and what function to call.
* **Target a Process:** The script would target a specific running process.
* **Set Hooks:**  The Frida engine would translate the script into actions that involve allocating code, creating deflectors, and patching the target process's memory. This allocation and patching process is where `gumcodeallocator.c` comes into play.

**9. Structuring the Output:**

Finally, I organize the gathered information according to the prompt's requirements, providing clear explanations and concrete examples. I use the structure provided in the initial prompt as a guide to ensure all aspects are addressed. This involves categorizing the information into functionalities, relationship with reverse engineering, low-level details, logical reasoning, user errors, and debugging clues.
This C source code file, `gumcodeallocator.c`, is a core component of Frida responsible for **dynamically allocating and managing executable code within a target process**. It provides the infrastructure for Frida to inject and execute its own code, which is essential for runtime instrumentation.

Here's a breakdown of its functionalities:

**1. Allocation of Executable Code Slices:**

* **Purpose:**  Provides small, contiguous blocks of memory that can be used to store generated code (e.g., instrumentation logic, trampolines for hooking).
* **Mechanism:**
    * It manages larger chunks of memory called "pages".
    * Within these pages, it divides the memory into smaller "slices" of a configurable size (`allocator->slice_size`).
    * It keeps track of free slices (`allocator->free_slices`).
    * It attempts to allocate slices near a specified address if requested (`gum_code_allocator_try_alloc_slice_near`), which can be important for code patching where relative jumps are involved.
    * It handles cases where Read-Write-Execute (RWX) memory is supported by the OS and where it isn't, potentially using code segments for the latter.
* **Data Structures:**
    * `GumCodeSlice`: Represents a single allocatable block of executable memory.
    * `GumCodePages`: Represents a larger page containing multiple `GumCodeSlice`s. It manages the underlying memory allocation and its properties.

**2. Code Deflection (Hooking Infrastructure):**

* **Purpose:**  Provides a mechanism to intercept the execution flow of the target process and redirect it to Frida's injected code. This is the fundamental basis for hooking.
* **Mechanism:**
    * It allocates "deflectors" (`GumCodeDeflector`) which represent a hook at a specific location.
    * It uses "dispatchers" (`GumCodeDeflectorDispatcher`) to manage multiple deflectors at or near the same code location, optimizing the hooking process.
    * When a deflector is created, it reserves a small "code cave" in the target process's memory (often within the module's header).
    * It writes a short jump instruction (a "trampoline") at the original target location, redirecting execution to the code cave or a dynamically generated "thunk".
    * The "thunk" is a small piece of injected code that saves the necessary registers, calls a Frida-controlled function (the instrumentation logic), and then restores the registers and returns to the original execution flow.
    * It manages the lifecycle of these deflectors and dispatchers, ensuring resources are properly allocated and freed.
* **Data Structures:**
    * `GumCodeDeflector`: Represents a single hook.
    * `GumCodeDeflectorDispatcher`: Manages a group of deflectors sharing a common redirection point.

**3. Memory Management and Protection:**

* **Purpose:**  Ensures the allocated code is executable and manages the underlying memory.
* **Mechanism:**
    * It uses system calls (via `gummemory.h`) to allocate memory pages with appropriate permissions (read, write, execute).
    * It handles cases where the operating system supports RWX memory directly and cases where it doesn't (requiring the use of code segments).
    * It uses `gum_mprotect` to change memory permissions (e.g., making allocated pages executable after code is written).
    * It uses `gum_clear_cache` to ensure that the CPU's instruction cache is synchronized with the newly written code.
    * It employs `gumcloak.h` to potentially hide allocated memory regions from introspection.
* **Functions:**
    * `gum_code_allocator_commit`: Makes allocated pages executable and clears the instruction cache.

**Relationship with Reverse Engineering:**

This file is deeply intertwined with reverse engineering techniques, specifically **dynamic analysis and code injection**.

* **Example:** When a reverse engineer uses Frida to hook a function, say `malloc`, the `gumcodeallocator.c` plays a crucial role.
    1. Frida needs to insert code at the beginning of the `malloc` function to intercept its execution.
    2. `gum_code_allocator_alloc_slice` (or `try_alloc_slice_near`) is used to allocate a small block of memory within the target process where the hook's trampoline will be placed.
    3. `gum_code_allocator_alloc_deflector` is used to create a deflector for the `malloc` function.
    4. Inside `gum_insert_deflector`, architecture-specific assembly code (e.g., using `GumArmWriter` or `GumArm64Writer`) is generated to:
        * Save the current instruction pointer.
        * Load the address of Frida's handler function into a register.
        * Jump to Frida's handler function.
    5. This injected code effectively redirects the execution flow whenever `malloc` is called, allowing the reverse engineer to examine its arguments, return values, or modify its behavior.

**Involvement of Binary Underlying, Linux, Android Kernel & Framework:**

* **Binary Underlying:** The code directly manipulates memory at the binary level. Functions like `memcpy` are used to write the trampoline instructions. The code needs to be aware of the target architecture's instruction set (ARM, ARM64) and generate correct machine code.
* **Linux/Android Kernel:**
    * **Memory Management:** The code relies on kernel services for memory allocation (`gum_alloc_n_pages`, `gum_free_pages`) and setting memory protection flags (`gum_mprotect`).
    * **Code Segments:** On systems without direct RWX support, it interacts with the kernel's code segment management (if available) through `gumcodesegment.h`.
    * **Instruction Cache:** The `gum_clear_cache` function likely uses kernel-specific system calls (e.g., `cacheflush` on Linux) to ensure cache coherency.
* **Framework (Android):** While the core of this file is OS-agnostic to some extent (abstracted through `gummemory.h`), on Android, the specific implementations within `gummemory.c` would interact with Android's Bionic libc and the underlying Linux kernel. The need to allocate executable memory on Android, which often has stricter security policies, makes this component critical.

**Logical Reasoning (Hypothetical Input & Output):**

Let's consider the scenario of hooking a function on ARM:

**Hypothetical Input:**

* `gum_code_allocator_alloc_deflector` is called with:
    * `caller->near_address`: The address of the function to be hooked (e.g., `0x70001000`).
    * `return_address`: The return address after the hook (not directly used in the deflector logic, but associated with the call).
    * `target`: The address of Frida's handler function (e.g., `0x7fff9000`).
    * `dedicated`: `FALSE` (assuming a shared dispatcher).

**Logical Reasoning & Steps:**

1. **Dispatcher Lookup:** The code checks if an existing dispatcher is close enough to the `caller->near_address`. If not, a new dispatcher is created.
2. **Code Cave Allocation (in `gum_code_deflector_dispatcher_new`):**
   * `gum_probe_module_for_code_cave` searches for a small, unused region (a "cave") in the module containing the target function. Let's say it finds a cave at `0x70000008` with a size of `GUM_CODE_DEFLECTOR_CAVE_SIZE` (e.g., 8 or 24 bytes).
3. **Trampoline Insertion (in `gum_insert_deflector` for ARM Thumb):**
   * Assuming the target function is Thumb code (address has the least significant bit set), `gum_thumb_writer_init` is used.
   * Assembly instructions are written into the code cave to:
     * Load the address of the dispatcher's thunk into the PC register (effectively jumping to the thunk). For example: `ldr pc, [pc, #-4]` followed by the address of the thunk.
4. **Thunk Creation (if dedicated is false):**
   * `gum_memory_allocate` allocates a page of RW memory for the thunk.
   * `gum_write_thunk` generates Thumb assembly code within the thunk to:
     * Push registers onto the stack to preserve their values.
     * Call the `gum_code_deflector_dispatcher_lookup` function, passing the dispatcher and the return address.
     * `gum_code_deflector_dispatcher_lookup` will look up the `target` (Frida's handler) associated with this return address within this dispatcher.
     * The return value of `gum_code_deflector_dispatcher_lookup` (the address of Frida's handler) is placed in a register (e.g., R0).
     * Pop the saved registers from the stack.
     * Branch to the address in R0 (Frida's handler).
5. **Deflector Linking:** The new deflector is added to the dispatcher's list of callers.

**Hypothetical Output:**

* The original instruction at `0x70001000` is overwritten (or part of it) with a jump instruction that transfers control to the code cave at `0x70000008`.
* The code cave at `0x70000008` contains assembly code that jumps to the dispatcher's thunk.
* The dispatcher's thunk contains code that calls `gum_code_deflector_dispatcher_lookup` to determine the correct handler and then jumps to it.

**Common User or Programming Mistakes:**

* **Incorrect `GumAddressSpec`:** Providing an incorrect `near_address` or `max_distance` might lead to allocation failures or unexpected behavior if the code tries to allocate memory too far away.
* **Forgetting to Call `gum_code_allocator_commit`:** If `gum_code_allocator_commit` is not called after allocating slices and writing code, the memory might not be marked as executable, leading to crashes or unexpected errors.
* **Memory Corruption:**  Writing beyond the bounds of an allocated slice can lead to memory corruption and unpredictable behavior.
* **Incorrectly Calculating Relative Addresses:** When manually writing code into allocated slices, errors in calculating relative jumps or branches can lead to incorrect execution flow.
* **Trying to Allocate Too Many Slices:**  While the allocator manages batches, excessively allocating slices without freeing them could eventually exhaust available memory.
* **Not Handling Architecture Differences:**  Assuming code generated for one architecture will work on another is a common mistake. This file explicitly handles architecture variations.

**User Operation Leading to This Code (Debugging Clues):**

A user typically interacts with this code indirectly through Frida's scripting interface. Here's a step-by-step scenario that would lead to the execution of functions in `gumcodeallocator.c`:

1. **User Writes a Frida Script:** The user writes a JavaScript (or Python) script using Frida's API. This script might include actions like:
   ```javascript
   Interceptor.attach(Module.findExportByName(null, "malloc"), {
     onEnter: function (args) {
       console.log("malloc called with size:", args[0]);
     }
   });
   ```
2. **User Executes the Frida Script:** The user runs the Frida script, targeting a specific process.
3. **Frida Engine Initialization:** Frida's core engine is initialized and connects to the target process.
4. **`Interceptor.attach` Calls:** When `Interceptor.attach` is called, the Frida engine needs to set up a hook at the `malloc` function.
5. **Resolution of Target Address:** Frida resolves the address of the `malloc` function in the target process's memory.
6. **Deflector Allocation (`gum_code_allocator_alloc_deflector`):**  Frida's internal logic calls `gum_code_allocator_alloc_deflector` to create a hook at the `malloc` function's address.
7. **Code Slice Allocation (`gum_code_allocator_alloc_slice` or `try_alloc_slice_near`):** To place the trampoline for the hook, Frida needs executable memory. `gum_code_allocator_alloc_slice` (or a near variant) is called to obtain a code slice.
8. **Trampoline Insertion (`gum_insert_deflector`):** Architecture-specific code within `gum_insert_deflector` is executed to write the trampoline (a jump instruction) at the beginning of the `malloc` function. This involves potentially finding a code cave.
9. **Thunk Creation and Writing (`gum_write_thunk`):** If it's a non-dedicated hook, a thunk is created and code is written to it to handle context saving, calling the JavaScript handler, and context restoration.
10. **Memory Commitment (`gum_code_allocator_commit`):** Frida calls `gum_code_allocator_commit` to ensure the allocated memory is marked as executable and the instruction cache is flushed.
11. **Target Function Execution:** When the target process calls `malloc`, the trampoline inserted by Frida redirects execution to the thunk (or directly to the handler if it's a dedicated hook).
12. **JavaScript Handler Execution:** The thunk executes, which eventually calls the user's JavaScript `onEnter` function.

By stepping through the Frida engine's execution with a debugger, one could see these functions in `gumcodeallocator.c` being called and observe the memory being allocated and modified in the target process. This makes `gumcodeallocator.c` a crucial entry point for understanding how Frida's dynamic instrumentation works at a low level.

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/gumcodeallocator.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumcodeallocator.h"

#include "gumcloak.h"
#include "gumcodesegment.h"
#include "gummemory.h"
#include "gumprocess-priv.h"
#ifdef HAVE_ARM
# include "gumarmwriter.h"
# include "gumthumbwriter.h"
#endif
#ifdef HAVE_ARM64
# include "gumarm64writer.h"
#endif

#include <string.h>

#define GUM_CODE_SLICE_ELEMENT_FROM_SLICE(s) \
    ((GumCodeSliceElement *) (((guint8 *) (s)) - \
        G_STRUCT_OFFSET (GumCodeSliceElement, slice)))

#if GLIB_SIZEOF_VOID_P == 8
# define GUM_CODE_DEFLECTOR_CAVE_SIZE 24
# define GUM_MAX_CODE_DEFLECTOR_THUNK_SIZE 128
#else
# define GUM_CODE_DEFLECTOR_CAVE_SIZE 8
# define GUM_MAX_CODE_DEFLECTOR_THUNK_SIZE 64
#endif

typedef struct _GumCodePages GumCodePages;
typedef struct _GumCodeSliceElement GumCodeSliceElement;
typedef struct _GumCodeDeflectorDispatcher GumCodeDeflectorDispatcher;
typedef struct _GumCodeDeflectorImpl GumCodeDeflectorImpl;
typedef struct _GumProbeRangeForCodeCaveContext GumProbeRangeForCodeCaveContext;
typedef struct _GumInsertDeflectorContext GumInsertDeflectorContext;

struct _GumCodeSliceElement
{
  GList parent;
  GumCodeSlice slice;
};

struct _GumCodePages
{
  gint ref_count;

  GumCodeSegment * segment;
  gpointer data;
  gsize size;

  GumCodeAllocator * allocator;

  GumCodeSliceElement elements[1];
};

struct _GumCodeDeflectorDispatcher
{
  GSList * callers;

  gpointer address;

  gpointer original_data;
  gsize original_size;

  gpointer trampoline;
  gpointer thunk;
  gsize thunk_size;
};

struct _GumCodeDeflectorImpl
{
  GumCodeDeflector parent;

  GumCodeAllocator * allocator;
};

struct _GumProbeRangeForCodeCaveContext
{
  const GumAddressSpec * caller;

  GumMemoryRange cave;
};

struct _GumInsertDeflectorContext
{
  GumAddress pc;
  gsize max_size;
  gpointer return_address;
  gpointer dedicated_target;

  GumCodeDeflectorDispatcher * dispatcher;
};

static GumCodeSlice * gum_code_allocator_try_alloc_batch_near (
    GumCodeAllocator * self, const GumAddressSpec * spec);

static void gum_code_pages_unref (GumCodePages * self);

static gboolean gum_code_slice_is_near (const GumCodeSlice * self,
    const GumAddressSpec * spec);
static gboolean gum_code_slice_is_aligned (const GumCodeSlice * slice,
    gsize alignment);

static GumCodeDeflectorDispatcher * gum_code_deflector_dispatcher_new (
    const GumAddressSpec * caller, gpointer return_address,
    gpointer dedicated_target);
static void gum_code_deflector_dispatcher_free (
    GumCodeDeflectorDispatcher * dispatcher);
static void gum_insert_deflector (gpointer cave,
    GumInsertDeflectorContext * ctx);
static void gum_write_thunk (gpointer thunk,
    GumCodeDeflectorDispatcher * dispatcher);
static void gum_remove_deflector (gpointer cave,
    GumCodeDeflectorDispatcher * dispatcher);
static gpointer gum_code_deflector_dispatcher_lookup (
    GumCodeDeflectorDispatcher * self, gpointer return_address);

static gboolean gum_probe_module_for_code_cave (
    const GumModuleDetails * details, gpointer user_data);

GUM_DEFINE_BOXED_TYPE (GumCodeSlice, gum_code_slice, gum_code_slice_ref,
                       gum_code_slice_unref)
GUM_DEFINE_BOXED_TYPE (GumCodeDeflector, gum_code_deflector,
                       gum_code_deflector_ref, gum_code_deflector_unref)

void
gum_code_allocator_init (GumCodeAllocator * allocator,
                         gsize slice_size)
{
  allocator->slice_size = slice_size;
  allocator->pages_per_batch = 7;
  allocator->slices_per_batch =
      (allocator->pages_per_batch * gum_query_page_size ()) / slice_size;
  allocator->pages_metadata_size = sizeof (GumCodePages) +
      ((allocator->slices_per_batch - 1) * sizeof (GumCodeSliceElement));

  allocator->uncommitted_pages = NULL;
  allocator->dirty_pages = g_hash_table_new (NULL, NULL);
  allocator->free_slices = NULL;

  allocator->dispatchers = NULL;
}

void
gum_code_allocator_free (GumCodeAllocator * allocator)
{
  g_slist_foreach (allocator->dispatchers,
      (GFunc) gum_code_deflector_dispatcher_free, NULL);
  g_slist_free (allocator->dispatchers);
  allocator->dispatchers = NULL;

  g_list_foreach (allocator->free_slices, (GFunc) gum_code_pages_unref, NULL);
  g_hash_table_unref (allocator->dirty_pages);
  g_slist_free (allocator->uncommitted_pages);
  allocator->uncommitted_pages = NULL;
  allocator->dirty_pages = NULL;
  allocator->free_slices = NULL;
}

GumCodeSlice *
gum_code_allocator_alloc_slice (GumCodeAllocator * self)
{
  return gum_code_allocator_try_alloc_slice_near (self, NULL, 0);
}

GumCodeSlice *
gum_code_allocator_try_alloc_slice_near (GumCodeAllocator * self,
                                         const GumAddressSpec * spec,
                                         gsize alignment)
{
  GList * cur;

  for (cur = self->free_slices; cur != NULL; cur = cur->next)
  {
    GumCodeSliceElement * element = (GumCodeSliceElement *) cur;
    GumCodeSlice * slice = &element->slice;

    if (gum_code_slice_is_near (slice, spec) &&
        gum_code_slice_is_aligned (slice, alignment))
    {
      GumCodePages * pages = element->parent.data;

      self->free_slices = g_list_remove_link (self->free_slices, cur);

      g_hash_table_add (self->dirty_pages, pages);

      return slice;
    }
  }

  return gum_code_allocator_try_alloc_batch_near (self, spec);
}

void
gum_code_allocator_commit (GumCodeAllocator * self)
{
  gboolean rwx_supported;
  GSList * cur;
  GHashTableIter iter;
  gpointer key;

  rwx_supported = gum_query_is_rwx_supported ();

  for (cur = self->uncommitted_pages; cur != NULL; cur = cur->next)
  {
    GumCodePages * pages = cur->data;
    GumCodeSegment * segment = pages->segment;

    if (segment != NULL)
    {
      gum_code_segment_realize (segment);
      gum_code_segment_map (segment, 0,
          gum_code_segment_get_virtual_size (segment),
          gum_code_segment_get_address (segment));
    }
    else
    {
      gum_mprotect (pages->data, pages->size, GUM_PAGE_RX);
    }
  }
  g_slist_free (self->uncommitted_pages);
  self->uncommitted_pages = NULL;

  g_hash_table_iter_init (&iter, self->dirty_pages);
  while (g_hash_table_iter_next (&iter, &key, NULL))
  {
    GumCodePages * pages = key;

    gum_clear_cache (pages->data, pages->size);
  }
  g_hash_table_remove_all (self->dirty_pages);

  if (!rwx_supported)
  {
    g_list_foreach (self->free_slices, (GFunc) gum_code_pages_unref, NULL);
    self->free_slices = NULL;
  }
}

static GumCodeSlice *
gum_code_allocator_try_alloc_batch_near (GumCodeAllocator * self,
                                         const GumAddressSpec * spec)
{
  GumCodeSlice * result = NULL;
  gboolean rwx_supported, code_segment_supported;
  gsize page_size, size_in_pages, size_in_bytes;
  GumCodeSegment * segment;
  gpointer data;
  GumCodePages * pages;
  guint i;

  rwx_supported = gum_query_is_rwx_supported ();
  code_segment_supported = gum_code_segment_is_supported ();

  page_size = gum_query_page_size ();
  size_in_pages = self->pages_per_batch;
  size_in_bytes = size_in_pages * page_size;

  if (rwx_supported || !code_segment_supported)
  {
    GumPageProtection protection;
    GumMemoryRange range;

    protection = rwx_supported ? GUM_PAGE_RWX : GUM_PAGE_RW;

    segment = NULL;
    if (spec != NULL)
    {
      data = gum_try_alloc_n_pages_near (size_in_pages, protection, spec);
      if (data == NULL)
        return NULL;
    }
    else
    {
      data = gum_alloc_n_pages (size_in_pages, protection);
    }

    gum_query_page_allocation_range (data, size_in_bytes, &range);
    gum_cloak_add_range (&range);
  }
  else
  {
    segment = gum_code_segment_new (size_in_bytes, spec);
    if (segment == NULL)
      return NULL;
    data = gum_code_segment_get_address (segment);
  }

  pages = g_slice_alloc (self->pages_metadata_size);
  pages->ref_count = self->slices_per_batch;

  pages->segment = segment;
  pages->data = data;
  pages->size = size_in_bytes;

  pages->allocator = self;

  for (i = self->slices_per_batch; i != 0; i--)
  {
    guint slice_index = i - 1;
    GumCodeSliceElement * element = &pages->elements[slice_index];
    GList * link;
    GumCodeSlice * slice;

    slice = &element->slice;
    slice->data = (guint8 *) data + (slice_index * self->slice_size);
    slice->size = self->slice_size;
    slice->ref_count = 1;

    link = &element->parent;
    link->data = pages;
    link->prev = NULL;
    if (slice_index == 0)
    {
      link->next = NULL;
      result = slice;
    }
    else
    {
      if (self->free_slices != NULL)
        self->free_slices->prev = link;
      link->next = self->free_slices;
      self->free_slices = link;
    }
  }

  if (!rwx_supported)
    self->uncommitted_pages = g_slist_prepend (self->uncommitted_pages, pages);

  g_hash_table_add (self->dirty_pages, pages);

  return result;
}

static void
gum_code_pages_unref (GumCodePages * self)
{
  self->ref_count--;
  if (self->ref_count == 0)
  {
    if (self->segment != NULL)
    {
      gum_code_segment_free (self->segment);
    }
    else
    {
      GumMemoryRange range;

      gum_free_pages (self->data);

      gum_query_page_allocation_range (self->data, self->size, &range);
      gum_cloak_remove_range (&range);
    }

    g_slice_free1 (self->allocator->pages_metadata_size, self);
  }
}

GumCodeSlice *
gum_code_slice_ref (GumCodeSlice * slice)
{
  g_atomic_int_inc (&slice->ref_count);

  return slice;
}

void
gum_code_slice_unref (GumCodeSlice * slice)
{
  GumCodeSliceElement * element;
  GumCodePages * pages;

  if (slice == NULL)
    return;

  if (!g_atomic_int_dec_and_test (&slice->ref_count))
    return;

  element = GUM_CODE_SLICE_ELEMENT_FROM_SLICE (slice);
  pages = element->parent.data;

  if (gum_query_is_rwx_supported ())
  {
    GumCodeAllocator * allocator = pages->allocator;
    GList * link = &element->parent;

    if (allocator->free_slices != NULL)
      allocator->free_slices->prev = link;
    link->next = allocator->free_slices;
    allocator->free_slices = link;
  }
  else
  {
    gum_code_pages_unref (pages);
  }
}

static gboolean
gum_code_slice_is_near (const GumCodeSlice * self,
                        const GumAddressSpec * spec)
{
  gssize near_address;
  gssize slice_start, slice_end;
  gsize distance_start, distance_end;

  if (spec == NULL)
    return TRUE;

  near_address = (gssize) spec->near_address;

  slice_start = (gssize) self->data;
  slice_end = slice_start + self->size - 1;

  distance_start = ABS (near_address - slice_start);
  distance_end = ABS (near_address - slice_end);

  return distance_start <= spec->max_distance &&
      distance_end <= spec->max_distance;
}

static gboolean
gum_code_slice_is_aligned (const GumCodeSlice * slice,
                           gsize alignment)
{
  if (alignment == 0)
    return TRUE;

  return GPOINTER_TO_SIZE (slice->data) % alignment == 0;
}

GumCodeDeflector *
gum_code_allocator_alloc_deflector (GumCodeAllocator * self,
                                    const GumAddressSpec * caller,
                                    gpointer return_address,
                                    gpointer target,
                                    gboolean dedicated)
{
  GumCodeDeflectorDispatcher * dispatcher = NULL;
  GSList * cur;
  GumCodeDeflectorImpl * impl;
  GumCodeDeflector * deflector;

  if (!dedicated)
  {
    for (cur = self->dispatchers; cur != NULL; cur = cur->next)
    {
      GumCodeDeflectorDispatcher * d = cur->data;
      gsize distance;

      distance = ABS ((gssize) GPOINTER_TO_SIZE (d->address) -
          (gssize) caller->near_address);
      if (distance <= caller->max_distance)
      {
        dispatcher = d;
        break;
      }
    }
  }

  if (dispatcher == NULL)
  {
    dispatcher = gum_code_deflector_dispatcher_new (caller, return_address,
        dedicated ? target : NULL);
    if (dispatcher == NULL)
      return NULL;
    self->dispatchers = g_slist_prepend (self->dispatchers, dispatcher);
  }

  impl = g_slice_new (GumCodeDeflectorImpl);

  deflector = &impl->parent;
  deflector->return_address = return_address;
  deflector->target = target;
  deflector->trampoline = dispatcher->trampoline;
  deflector->ref_count = 1;

  impl->allocator = self;

  dispatcher->callers = g_slist_prepend (dispatcher->callers, deflector);

  return deflector;
}

GumCodeDeflector *
gum_code_deflector_ref (GumCodeDeflector * deflector)
{
  g_atomic_int_inc (&deflector->ref_count);

  return deflector;
}

void
gum_code_deflector_unref (GumCodeDeflector * deflector)
{
  GumCodeDeflectorImpl * impl = (GumCodeDeflectorImpl *) deflector;
  GumCodeAllocator * allocator;
  GSList * cur;

  if (deflector == NULL)
    return;

  if (!g_atomic_int_dec_and_test (&deflector->ref_count))
    return;

  allocator = impl->allocator;

  for (cur = allocator->dispatchers; cur != NULL; cur = cur->next)
  {
    GumCodeDeflectorDispatcher * dispatcher = cur->data;
    GSList * entry;

    entry = g_slist_find (dispatcher->callers, deflector);
    if (entry != NULL)
    {
      g_slice_free (GumCodeDeflectorImpl, impl);

      dispatcher->callers = g_slist_delete_link (dispatcher->callers, entry);
      if (dispatcher->callers == NULL)
      {
        gum_code_deflector_dispatcher_free (dispatcher);
        allocator->dispatchers = g_slist_remove (allocator->dispatchers,
            dispatcher);
      }

      return;
    }
  }

  g_assert_not_reached ();
}

static GumCodeDeflectorDispatcher *
gum_code_deflector_dispatcher_new (const GumAddressSpec * caller,
                                   gpointer return_address,
                                   gpointer dedicated_target)
{
#if defined (HAVE_DARWIN) || (defined (HAVE_ELF) && GLIB_SIZEOF_VOID_P == 4)
  GumCodeDeflectorDispatcher * dispatcher;
  GumProbeRangeForCodeCaveContext probe_ctx;
  GumInsertDeflectorContext insert_ctx;

  probe_ctx.caller = caller;

  probe_ctx.cave.base_address = 0;
  probe_ctx.cave.size = 0;

  gum_process_enumerate_modules (gum_probe_module_for_code_cave, &probe_ctx);

  if (probe_ctx.cave.base_address == 0)
    return NULL;

  dispatcher = g_slice_new0 (GumCodeDeflectorDispatcher);

  dispatcher->address = GSIZE_TO_POINTER (probe_ctx.cave.base_address);

  dispatcher->original_data = g_memdup (dispatcher->address,
      probe_ctx.cave.size);
  dispatcher->original_size = probe_ctx.cave.size;

  if (dedicated_target == NULL)
  {
    gsize thunk_size;
    GumMemoryRange range;

    thunk_size = gum_query_page_size ();

    dispatcher->thunk =
        gum_memory_allocate (NULL, thunk_size, thunk_size, GUM_PAGE_RW);
    dispatcher->thunk_size = thunk_size;

    gum_memory_patch_code (dispatcher->thunk, GUM_MAX_CODE_DEFLECTOR_THUNK_SIZE,
        (GumMemoryPatchApplyFunc) gum_write_thunk, dispatcher);

    range.base_address = GUM_ADDRESS (dispatcher->thunk);
    range.size = thunk_size;
    gum_cloak_add_range (&range);
  }

  insert_ctx.pc = GUM_ADDRESS (dispatcher->address);
  insert_ctx.max_size = dispatcher->original_size;
  insert_ctx.return_address = return_address;
  insert_ctx.dedicated_target = dedicated_target;

  insert_ctx.dispatcher = dispatcher;

  gum_memory_patch_code (dispatcher->address, dispatcher->original_size,
      (GumMemoryPatchApplyFunc) gum_insert_deflector, &insert_ctx);

  return dispatcher;
#else
  (void) gum_insert_deflector;
  (void) gum_write_thunk;
  (void) gum_probe_module_for_code_cave;

  return NULL;
#endif
}

static void
gum_code_deflector_dispatcher_free (GumCodeDeflectorDispatcher * dispatcher)
{
  gum_memory_patch_code (dispatcher->address, dispatcher->original_size,
      (GumMemoryPatchApplyFunc) gum_remove_deflector, dispatcher);

  if (dispatcher->thunk != NULL)
  {
    GumMemoryRange range;

    gum_memory_release (dispatcher->thunk, dispatcher->thunk_size);

    range.base_address = GUM_ADDRESS (dispatcher->thunk);
    range.size = dispatcher->thunk_size;
    gum_cloak_remove_range (&range);
  }

  g_free (dispatcher->original_data);

  g_slist_foreach (dispatcher->callers, (GFunc) gum_code_deflector_unref, NULL);
  g_slist_free (dispatcher->callers);

  g_slice_free (GumCodeDeflectorDispatcher, dispatcher);
}

static void
gum_insert_deflector (gpointer cave,
                      GumInsertDeflectorContext * ctx)
{
# if defined (HAVE_ARM)
  GumCodeDeflectorDispatcher * dispatcher = ctx->dispatcher;
  GumThumbWriter tw;

  if (ctx->dedicated_target != NULL)
  {
    gboolean owner_is_arm;

    owner_is_arm = (GPOINTER_TO_SIZE (ctx->return_address) & 1) == 0;
    if (owner_is_arm)
    {
      GumArmWriter aw;

      gum_arm_writer_init (&aw, cave);
      aw.cpu_features = gum_query_cpu_features ();
      aw.pc = ctx->pc;
      gum_arm_writer_put_ldr_reg_address (&aw, ARM_REG_PC,
          GUM_ADDRESS (ctx->dedicated_target));
      gum_arm_writer_flush (&aw);
      g_assert (gum_arm_writer_offset (&aw) <= ctx->max_size);
      gum_arm_writer_clear (&aw);

      dispatcher->trampoline = GSIZE_TO_POINTER (ctx->pc);

      return;
    }

    gum_thumb_writer_init (&tw, cave);
    tw.pc = ctx->pc;
    gum_thumb_writer_put_ldr_reg_address (&tw, ARM_REG_PC,
        GUM_ADDRESS (ctx->dedicated_target));
  }
  else
  {
    gum_thumb_writer_init (&tw, cave);
    tw.pc = ctx->pc;
    gum_thumb_writer_put_ldr_reg_address (&tw, ARM_REG_PC,
        GUM_ADDRESS (dispatcher->thunk) + 1);
  }

  gum_thumb_writer_flush (&tw);
  g_assert (gum_thumb_writer_offset (&tw) <= ctx->max_size);
  gum_thumb_writer_clear (&tw);

  dispatcher->trampoline = GSIZE_TO_POINTER (ctx->pc + 1);
# elif defined (HAVE_ARM64)
  GumCodeDeflectorDispatcher * dispatcher = ctx->dispatcher;
  GumArm64Writer aw;

  gum_arm64_writer_init (&aw, cave);
  aw.pc = ctx->pc;

  if (ctx->dedicated_target != NULL)
  {
    gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X0, ARM64_REG_LR);
    gum_arm64_writer_put_ldr_reg_address (&aw, ARM64_REG_X0,
        GUM_ADDRESS (ctx->dedicated_target));
    gum_arm64_writer_put_br_reg (&aw, ARM64_REG_X0);
  }
  else
  {
    gum_arm64_writer_put_ldr_reg_address (&aw, ARM64_REG_X0,
        GUM_ADDRESS (dispatcher->thunk));
    gum_arm64_writer_put_br_reg (&aw, ARM64_REG_X0);
  }

  gum_arm64_writer_flush (&aw);
  g_assert (gum_arm64_writer_offset (&aw) <= ctx->max_size);
  gum_arm64_writer_clear (&aw);

  dispatcher->trampoline = GSIZE_TO_POINTER (ctx->pc);
# else
  (void) gum_code_deflector_dispatcher_lookup;
# endif
}

static void
gum_write_thunk (gpointer thunk,
                 GumCodeDeflectorDispatcher * dispatcher)
{
# if defined (HAVE_ARM)
  GumThumbWriter tw;

  gum_thumb_writer_init (&tw, thunk);
  tw.pc = GUM_ADDRESS (dispatcher->thunk);

  gum_thumb_writer_put_push_regs (&tw, 2, ARM_REG_R9, ARM_REG_R12);

  gum_thumb_writer_put_call_address_with_arguments (&tw,
      GUM_ADDRESS (gum_code_deflector_dispatcher_lookup), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (dispatcher),
      GUM_ARG_REGISTER, ARM_REG_LR);

  gum_thumb_writer_put_pop_regs (&tw, 2, ARM_REG_R9, ARM_REG_R12);

  gum_thumb_writer_put_bx_reg (&tw, ARM_REG_R0);
  gum_thumb_writer_clear (&tw);
# elif defined (HAVE_ARM64)
  GumArm64Writer aw;

  gum_arm64_writer_init (&aw, thunk);
  aw.pc = GUM_ADDRESS (dispatcher->thunk);

  /* push {q0-q7} */
  gum_arm64_writer_put_instruction (&aw, 0xadbf1fe6);
  gum_arm64_writer_put_instruction (&aw, 0xadbf17e4);
  gum_arm64_writer_put_instruction (&aw, 0xadbf0fe2);
  gum_arm64_writer_put_instruction (&aw, 0xadbf07e0);

  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X17, ARM64_REG_X18);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X15, ARM64_REG_X16);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X13, ARM64_REG_X14);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X11, ARM64_REG_X12);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X9, ARM64_REG_X10);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X7, ARM64_REG_X8);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X5, ARM64_REG_X6);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X3, ARM64_REG_X4);
  gum_arm64_writer_put_push_reg_reg (&aw, ARM64_REG_X1, ARM64_REG_X2);

  gum_arm64_writer_put_call_address_with_arguments (&aw,
      GUM_ADDRESS (gum_code_deflector_dispatcher_lookup), 2,
      GUM_ARG_ADDRESS, GUM_ADDRESS (dispatcher),
      GUM_ARG_REGISTER, ARM64_REG_LR);

  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X1, ARM64_REG_X2);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X3, ARM64_REG_X4);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X5, ARM64_REG_X6);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X7, ARM64_REG_X8);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X9, ARM64_REG_X10);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X11, ARM64_REG_X12);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X13, ARM64_REG_X14);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X15, ARM64_REG_X16);
  gum_arm64_writer_put_pop_reg_reg (&aw, ARM64_REG_X17, ARM64_REG_X18);

  /* pop {q0-q7} */
  gum_arm64_writer_put_instruction (&aw, 0xacc107e0);
  gum_arm64_writer_put_instruction (&aw, 0xacc10fe2);
  gum_arm64_writer_put_instruction (&aw, 0xacc117e4);
  gum_arm64_writer_put_instruction (&aw, 0xacc11fe6);

  gum_arm64_writer_put_br_reg (&aw, ARM64_REG_X0);
  gum_arm64_writer_clear (&aw);
# else
  (void) gum_code_deflector_dispatcher_lookup;
# endif
}

static void
gum_remove_deflector (gpointer cave,
                      GumCodeDeflectorDispatcher * dispatcher)
{
  memcpy (cave, dispatcher->original_data, dispatcher->original_size);
}

static gpointer
gum_code_deflector_dispatcher_lookup (GumCodeDeflectorDispatcher * self,
                                      gpointer return_address)
{
  GSList * cur;

  for (cur = self->callers; cur != NULL; cur = cur->next)
  {
    GumCodeDeflector * caller = cur->data;

    if (caller->return_address == return_address)
      return caller->target;
  }

  return NULL;
}

static gboolean
gum_probe_module_for_code_cave (const GumModuleDetails * details,
                                gpointer user_data)
{
  const GumMemoryRange * range = details->range;
  GumProbeRangeForCodeCaveContext * ctx = user_data;
  const GumAddressSpec * caller = ctx->caller;
  GumAddress header_address, cave_address;
  gsize distance;
  const guint8 empty_cave[GUM_CODE_DEFLECTOR_CAVE_SIZE] = { 0, };

  header_address = range->base_address;

#ifdef HAVE_DARWIN
  cave_address = header_address + 4096 - sizeof (empty_cave);
#else
  cave_address = header_address + 8;
#endif

  distance = ABS ((gssize) cave_address - (gssize) caller->near_address);
  if (distance > caller->max_distance)
    return TRUE;

  if (memcmp (GSIZE_TO_POINTER (cave_address), empty_cave,
      sizeof (empty_cave)) != 0)
  {
#ifdef HAVE_DARWIN
    gboolean found_empty_cave, nothing_in_front_of_cave;

    found_empty_cave = FALSE;
    nothing_in_front_of_cave = TRUE;

    do
    {
      cave_address -= sizeof (empty_cave);

      found_empty_cave = memcmp (GSIZE_TO_POINTER (cave_address), empty_cave,
          sizeof (empty_cave)) == 0;
    }
    while (!found_empty_cave && cave_address > header_address + 0x500);

    if (found_empty_cave)
    {
      gsize offset;

      for (offset = sizeof (empty_cave);
          offset <= 2 * sizeof (empty_cave);
          offset += sizeof (empty_cave))
      {
        nothing_in_front_of_cave = memcmp (
            GSIZE_TO_POINTER (cave_address - offset), empty_cave,
            sizeof (empty_cave)) == 0;
      }
    }

    if (!(found_empty_cave && nothing_in_front_of_cave))
      return TRUE;
#else
    return TRUE;
#endif
  }

  ctx->cave.base_address = cave_address;
  ctx->cave.size = sizeof (empty_cave);
  return FALSE;
}

"""

```