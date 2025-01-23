Response:
Let's break down the thought process for analyzing this C code for Frida's `gumkernel-darwin.c`.

1. **Understand the Purpose:** The filename and the initial comments clearly indicate this file deals with interacting with the Darwin kernel (macOS/iOS) within the Frida framework. The "gum" prefix suggests it's part of Frida's core dynamic instrumentation engine. The copyright notices and license confirm it's production code.

2. **Identify Key Data Structures:**  The code defines several structs. These are crucial for understanding the data being manipulated. I'll list them out and briefly note their purpose:
    * `GumKernelScanContext`:  For managing kernel memory scanning.
    * `GumKernelEnumerateModuleRangesContext`:  For iterating through kernel module memory ranges.
    * `GumKernelSearchKextContext`:  Specifically for finding kernel extensions (kexts).
    * `GumKernelKextInfo`:  Stores information about a kext (name and address).
    * ...and others relating to finding ranges and emitting module information.

3. **Identify Key Functions:**  A quick scan reveals functions with prefixes like `gum_kernel_`, `gum_darwin_`, and standard C library functions. I'll categorize them:
    * **Core Kernel Interaction (`gum_kernel_*`):**  These are the heart of the file – allocating/freeing memory, reading/writing memory, enumerating modules/ranges, scanning memory.
    * **Darwin Abstraction (`gum_darwin_*`):** These likely interface with Darwin-specific APIs (like Mach).
    * **Utility/Helper:** Functions like `gum_match_pattern_*`, `g_malloc`, `g_free`, `strncmp`, etc.

4. **Analyze Functionality by Grouping:** Instead of going line by line, I'll group functions based on their apparent roles:
    * **Initialization/Cleanup:** `gum_kernel_get_task`, `gum_kernel_do_init`, `gum_kernel_do_deinit`. These manage the connection to the kernel task.
    * **Memory Management:** `gum_kernel_alloc_n_pages`, `gum_kernel_free_pages`, `gum_kernel_try_mprotect`. Basic operations on kernel memory.
    * **Memory Access:** `gum_kernel_read`, `gum_kernel_write`. Fundamental for instrumentation.
    * **Memory Scanning:** `gum_kernel_scan`, `gum_kernel_emit_match`, `gum_kernel_scan_section`. Used to find patterns in kernel memory.
    * **Module Enumeration:** `gum_kernel_enumerate_modules`, `gum_kernel_enumerate_kexts`, `gum_kernel_emit_module`. Essential for understanding the kernel's structure.
    * **Module Range Enumeration:** `gum_kernel_enumerate_module_ranges`, `gum_kernel_emit_module_range`. More granular view of module memory.
    * **Base Address Finding:** `gum_kernel_find_base_address`, `gum_kernel_do_find_base_address`, and platform-specific helpers like `gum_kernel_get_base_from_all_image_info`, `gum_kernel_bruteforce_base`. This is critical for working with ASLR.
    * **Helper Functions:** Functions like `gum_kernel_range_by_name`, `gum_kernel_find_module_by_name`, etc., simplify common tasks.

5. **Connect to Reverse Engineering:**  Now, relate the functionality to reverse engineering techniques:
    * **Hooking/Interception:** The ability to read and write kernel memory is foundational for hooking kernel functions.
    * **Code Analysis:**  Scanning memory for patterns (like Mach-O headers or specific strings) helps identify code and data structures. Enumerating modules and their ranges provides the map of the kernel.
    * **Understanding Kernel Structure:** Enumerating modules and sections gives insights into the kernel's organization and how different components interact.
    * **Bypassing Security Measures (KASLR):** The base address finding functions are directly related to bypassing Kernel Address Space Layout Randomization.

6. **Identify Binary/Low-Level Aspects:**  Look for code dealing with:
    * **Memory Addresses and Sizes:** The extensive use of `GumAddress` and `gsize`.
    * **Mach-O Headers:** The checks for `MH_MAGIC_64`, `CPU_TYPE_ARM64`, `MH_EXECUTE`.
    * **Kernel Data Structures:**  References to `kmod.h` and the search for "com.apple" suggest interaction with kernel extension structures.
    * **System Calls (Indirectly):**  The `gum_darwin_*` functions likely wrap system calls related to task management and memory.

7. **Consider Linux/Android Parallels:** While this code is Darwin-specific, think about the analogous concepts on other kernels:
    * **Modules/Kexts:** Linux has kernel modules (`.ko` files), and Android has kernel modules.
    * **Memory Regions:** Both Linux and Android kernels have different memory regions with varying permissions.
    * **System Calls:**  While the specific calls differ, the need to interact with the kernel via system calls is universal.
    * **Address Space Layout Randomization (ASLR):** Both Linux and Android implement ASLR for security.

8. **Logical Reasoning/Assumptions:**  For functions like `gum_kernel_bruteforce_base`, the comments reveal the underlying assumptions and techniques (iterating through potential ASLR slides). Consider how the input (`unslid_base`) and the output (the likely slid base address) relate.

9. **User/Programming Errors:** Think about common mistakes when using such low-level APIs:
    * **Incorrect Memory Addresses:** Providing invalid addresses to read/write functions.
    * **Incorrect Sizes:** Reading or writing beyond allocated buffers.
    * **Permission Issues:** Trying to modify read-only memory.
    * **Race Conditions (less evident in this static code, but relevant in a dynamic instrumentation context):** If multiple threads try to modify kernel state simultaneously.

10. **Tracing User Actions:**  Imagine how a Frida user would reach this code:
    * **Attaching to a Process:** Frida needs to get a handle to the target process's kernel task.
    * **Instrumenting Kernel Code:** The user would likely write a Frida script that uses `Interceptor.attach()` or similar to hook kernel functions. This would trigger Frida to use the functions in this file to read/write memory and find the target functions.
    * **Enumerating Modules:** A user might want to list loaded kernel extensions.
    * **Searching for Patterns:** A user might want to find specific data structures or code sequences in the kernel.

11. **Review and Refine:** After the initial analysis, go back and refine the descriptions. Ensure the explanations are clear, concise, and accurate. Double-check the connections to reverse engineering, low-level concepts, and potential errors. Make sure the example scenarios are realistic.

By following these steps, we can systematically analyze the C code and address all the requirements of the prompt, even without having prior deep knowledge of the specific codebase. The key is to break down the problem into smaller, manageable parts and use the available information (function names, data structures, comments) to infer the purpose and functionality.
This C source code file, `gumkernel-darwin.c`, is a crucial component of Frida that deals with **interacting with the Darwin kernel** (the core of macOS and iOS) for dynamic instrumentation. It provides low-level functionalities to read, write, and analyze kernel memory and structures.

Here's a breakdown of its functions, categorized by your requests:

**1. Core Functionality:**

* **Kernel Task Management:**
    * `gum_kernel_get_task()`:  Obtains a Mach port representing the kernel task. This is the essential handle for interacting with the kernel's address space.
    * `gum_kernel_do_init()`: Initializes the kernel task connection.
    * `gum_kernel_do_deinit()`: Deallocates the kernel task port.
    * `gum_kernel_api_is_available()`: Checks if the kernel API is accessible (i.e., if a valid kernel task port exists).

* **Kernel Memory Management:**
    * `gum_kernel_query_page_size()`: Retrieves the kernel's page size.
    * `gum_kernel_alloc_n_pages()`: Allocates contiguous kernel memory pages.
    * `gum_kernel_free_pages()`: Frees allocated kernel memory pages.
    * `gum_kernel_try_mprotect()`: Attempts to change the memory protection attributes (read, write, execute) of kernel memory.

* **Kernel Memory Access:**
    * `gum_kernel_read()`: Reads data from the kernel's memory at a given address. It handles potential page boundaries and uses `mach_vm_read_overwrite`.
    * `gum_kernel_write()`: Writes data to the kernel's memory at a given address, using `gum_darwin_write` (likely a wrapper around a Mach system call).

* **Kernel Memory Analysis and Scanning:**
    * `gum_kernel_enumerate_ranges()`: Iterates through all memory ranges in the kernel with specific protection attributes.
    * `gum_kernel_scan()`: Scans a given kernel memory range for a specific byte pattern.
    * `gum_kernel_emit_match()`: A helper function used during scanning to report a match.
    * `gum_kernel_scan_section()`: Scans a specific named section within the kernel.

* **Kernel Module Enumeration:**
    * `gum_kernel_enumerate_modules()`: Enumerates all loaded kernel modules (including the main kernel and kernel extensions - kexts).
    * `gum_kernel_enumerate_kexts()`: Specifically enumerates kernel extensions by searching for Mach-O header signatures and kext name strings in specific sections.
    * `gum_kernel_emit_module()`: A helper function to report information about a found kernel module.
    * `gum_kernel_find_module_by_name()`: Finds a specific kernel module by its name.
    * `gum_kernel_kext_by_name()`: Helper function used during kext enumeration to match by name.

* **Kernel Module Range Enumeration:**
    * `gum_kernel_enumerate_module_ranges()`: Enumerates memory ranges within a specific kernel module.
    * `gum_kernel_emit_module_range()`: A helper function to report information about a memory range within a kernel module.
    * `gum_kernel_range_by_name()`: Finds a specific named memory range within the kernel.
    * `gum_kernel_find_range_by_name()`: Helper function to find a memory range during enumeration.

* **Kernel Base Address Discovery (Primarily ARM64):**
    * `gum_kernel_find_base_address()`:  Determines the base address where the kernel is loaded in memory. This is crucial due to Address Space Layout Randomization (ASLR).
    * `gum_kernel_do_find_base_address()`: The core logic for finding the base address, potentially using different strategies based on the OS version.
    * `gum_kernel_get_base_from_all_image_info()`: Attempts to get the kernel base address from the `all_image_info` structure (a more reliable method if available).
    * `gum_kernel_bruteforce_base()`:  A fallback mechanism to brute-force the kernel base address by checking for valid Mach-O headers at potential slide offsets.
    * `gum_kernel_is_header()`: Checks if a given memory address contains a valid Mach-O header for the kernel.
    * `gum_kernel_has_kld()`: Checks for the presence of the "__KLD" section, often used to identify kernel code.
    * `gum_kernel_get_version()`: Retrieves the Darwin kernel version.

* **Helper Functions:**
    * `gum_darwin_module_estimate_size()`: Estimates the size of a kernel module.
    * `gum_kernel_store_kext_addr()`: Stores the address of a potential kernel extension during scanning.
    * `gum_kernel_store_kext_name()`: Stores the name of a kernel extension found during scanning.

**2. Relationship with Reverse Engineering:**

This file is **deeply intertwined with reverse engineering methodologies**:

* **Memory Inspection:** The ability to `gum_kernel_read` allows reverse engineers to directly examine kernel data structures, code, and variables at runtime. This is fundamental for understanding how the kernel works.
    * **Example:** A reverse engineer could use `gum_kernel_read` to examine the contents of a process's task structure to understand its state or to inspect the arguments passed to a specific kernel function.

* **Code Analysis:** `gum_kernel_scan` and `gum_kernel_scan_section` are used to locate specific code patterns or signatures within the kernel. This can help identify specific functions or code blocks without prior knowledge of their exact addresses (especially useful with ASLR).
    * **Example:** Reverse engineers might scan for the prologue of a known system call handler function to find its runtime address, even if ASLR is enabled.

* **Kernel Structure Discovery:**  `gum_kernel_enumerate_modules` and `gum_kernel_enumerate_module_ranges` provide a way to map out the loaded kernel modules and their memory layouts. This is crucial for understanding the organization of the kernel and identifying components of interest.
    * **Example:** A reverse engineer could use these functions to find the address range of a specific kext, like a filesystem driver, to then focus further analysis on its code.

* **Dynamic Analysis:** The core purpose of Frida and this file is **dynamic instrumentation**. By providing read/write access and the ability to find code, it enables the hooking and modification of kernel behavior at runtime. This is a powerful reverse engineering technique for understanding how the kernel behaves under specific conditions.
    * **Example:**  A reverse engineer could use Frida to hook a system call related to file access to log all file operations performed by a specific process.

* **Bypassing Security Mechanisms:** The logic in `gum_kernel_find_base_address` is directly aimed at bypassing Kernel Address Space Layout Randomization (KASLR). By finding the base address, reverse engineers can then calculate the absolute addresses of other kernel components and functions.

**3. Binary Bottom, Linux/Android Kernel, and Framework Knowledge:**

This code demonstrates deep understanding of:

* **Binary Bottom:**
    * **Memory Addresses and Sizes:** The code extensively uses `GumAddress` and `gsize` to represent memory locations and sizes, highlighting the low-level nature of kernel interaction.
    * **Mach-O Executable Format:** The code searches for Mach-O header magic numbers (`MH_MAGIC_64`) and checks CPU type (`CPU_TYPE_ARM64`) and file type (`MH_EXECUTE`), demonstrating knowledge of the kernel executable format on Darwin.
    * **Kernel Data Structures:** The code implicitly interacts with kernel data structures through memory reads and writes, even if the specific structure definitions aren't directly included in this file (they would be in other parts of Frida).

* **Darwin Kernel Specifics:**
    * **Mach Ports:** The reliance on Mach ports for inter-process communication (specifically, getting the kernel task port) is a core concept of the Darwin kernel.
    * **Kernel Extensions (Kexts):** The specific logic for enumerating kexts, searching for "com.apple" strings and Mach-O headers in prelink sections, is specific to how kexts are loaded and structured in Darwin.
    * **Memory Management System Calls:**  Functions like `mach_vm_allocate`, `mach_vm_deallocate`, `mach_vm_protect`, and `mach_vm_read_overwrite` are direct interfaces to the Darwin kernel's virtual memory management.
    * **System Control (sysctl):** The use of `sysctlbyname` to get kernel version and boot arguments is a standard way to query kernel parameters on macOS/iOS.

* **Linux/Android Kernel Analogies:** While this code is Darwin-specific, there are parallels to Linux and Android kernels:
    * **Kernel Modules:** Linux and Android have similar concepts of loadable kernel modules (`.ko` files).
    * **Virtual Memory Management:**  Linux and Android kernels also have system calls for memory allocation, deallocation, and protection (e.g., `mmap`, `munmap`, `mprotect`).
    * **Address Space Layout Randomization (ASLR):**  Both Linux and Android implement ASLR, and techniques similar to the brute-force approach here might be used (though specific implementation details would differ).
    * **Kernel Symbols:** On Linux, `/proc/kallsyms` provides a way to enumerate kernel symbols, serving a similar purpose to the module enumeration here.
    * **Device Tree (Android):** On Android, the device tree provides information about hardware and loaded modules, which could be inspected as an alternative to kext enumeration.

**4. Logical Reasoning and Assumptions:**

* **Kernel Base Address Brute-Force:** The `gum_kernel_bruteforce_base` function makes the assumption that the kernel base address is located at specific slide offsets from the unslid base. It iterates through these potential offsets and checks for a valid Mach-O header.
    * **Assumption Input:** `unslid_base` (the kernel base address without ASLR).
    * **Assumption Output:** The actual kernel base address in memory if found, otherwise 0.

* **Kext Enumeration:** The kext enumeration logic assumes that kext information (Mach-O headers and "com.apple" strings) will be present in the `__PRELINK_TEXT.__text` and `__PRELINK_DATA.__data` sections.
    * **Assumption Input:**  Kernel memory regions.
    * **Assumption Output:** A list of `GumDarwinModule` structures representing found kexts.

**5. User or Programming Common Usage Errors:**

* **Incorrect Memory Addresses:**  Providing incorrect or out-of-bounds memory addresses to `gum_kernel_read` or `gum_kernel_write` will lead to crashes or unexpected behavior. This is a classic error in low-level programming.
    * **Example:** Trying to read from an address that hasn't been mapped or belongs to a different process.

* **Incorrect Sizes:**  Specifying incorrect sizes for memory reads or writes can lead to buffer overflows or incomplete data transfers.
    * **Example:** Reading less data than expected from a kernel structure.

* **Permission Issues:** Attempting to write to read-only kernel memory using `gum_kernel_write` or `gum_kernel_try_mprotect` without proper privileges will fail.
    * **Example:** Trying to modify code in a read-only code segment.

* **Race Conditions (in a dynamic context):** While not directly evident in this static code, if multiple Frida scripts or threads try to access or modify kernel memory concurrently without proper synchronization, it can lead to race conditions and unpredictable behavior.

* **Incorrectly Handling Kernel Pointers:**  Kernel pointers are only valid within the kernel's address space. Trying to dereference a kernel pointer in user space will cause a crash.

**6. User Operations Leading Here (Debugging Clues):**

A user's interaction with Frida that ends up executing code in `gumkernel-darwin.c` typically involves:

1. **Attaching to a Process:** The user would first attach Frida to a running process on macOS or iOS. This involves Frida establishing a connection to the target process and potentially obtaining the kernel task port.
2. **Kernel Instrumentation:** The user would then use Frida's API to interact with the kernel. Common scenarios include:
    * **Hooking Kernel Functions:** Using `Interceptor.attach()` with an address within the kernel (requiring the kernel base address to be known, hence the `gum_kernel_find_base_address` calls).
    * **Reading Kernel Memory:** Using `Process.readMemory()` with a kernel address.
    * **Writing Kernel Memory:** Using `Process.writeMemory()` with a kernel address.
    * **Enumerating Kernel Modules:**  Using Frida's module enumeration functions, which internally call `gum_kernel_enumerate_modules`.
    * **Scanning Kernel Memory:** Using Frida's memory scanning capabilities, which utilize `gum_kernel_scan`.
3. **Frida Script Execution:** The user's actions are typically encapsulated in a JavaScript or Python Frida script. When this script is executed by the Frida agent, it will call the underlying C functions in `gumkernel-darwin.c` to perform the requested operations.
4. **Error Scenarios:** If the user's script attempts an invalid operation (e.g., reading from an invalid kernel address), the functions in this file might return error codes or cause exceptions, providing debugging clues.

**In summary, `gumkernel-darwin.c` is a foundational piece of Frida that enables powerful dynamic instrumentation capabilities on macOS and iOS by providing low-level access and analysis tools for the Darwin kernel.** It's crucial for reverse engineering, security analysis, and debugging tasks at the kernel level.

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gumkernel-darwin.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2015-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Alex Soler <asoler@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumkernel.h"

#include "gum-init.h"
#include "gum/gumdarwin.h"
#include "gummemory-priv.h"
#include "gumprocess-darwin-priv.h"

#include <mach/mach.h>
#include <mach-o/loader.h>
#include <sys/sysctl.h>

#define GUM_KERNEL_SLIDE_OFFSET 0x1000000
#define GUM_KERNEL_SLIDE_SIZE 0x200000

typedef struct _GumKernelScanContext GumKernelScanContext;
typedef struct _GumKernelEnumerateModuleRangesContext
    GumKernelEnumerateModuleRangesContext;
typedef struct _GumKernelSearchKextContext GumKernelSearchKextContext;
typedef struct _GumKernelKextInfo GumKernelKextInfo;
typedef struct _GumKernelFindRangeByNameContext GumKernelFindRangeByNameContext;
typedef struct _GumEmitModuleContext GumEmitModuleContext;
typedef struct _GumKernelKextByNameContext GumKernelKextByNameContext;

struct _GumKernelScanContext
{
  GumMemoryScanMatchFunc func;
  gpointer user_data;

  GumAddress cursor_userland;
  GumAddress cursor_kernel;

  gboolean carry_on;
};

struct _GumKernelEnumerateModuleRangesContext
{
  GumPageProtection protection;
  GumFoundKernelModuleRangeFunc func;
  gpointer user_data;
};

struct _GumKernelSearchKextContext
{
  GHashTable * kexts;
};

struct _GumKernelKextInfo
{
  gchar name[0x41];
  GumAddress address;
};

struct _GumKernelFindRangeByNameContext
{
  const gchar * name;
  gboolean found;
  GumMemoryRange range;
};

struct _GumEmitModuleContext
{
  GumFoundModuleFunc func;
  gpointer user_data;
};

struct _GumKernelKextByNameContext
{
  const gchar * module_name;
  gboolean found;
  GumDarwinModule * module;
};

typedef gboolean (* GumFoundKextFunc) (GumDarwinModule * module,
    gpointer user_data);

static gboolean gum_kernel_emit_match (GumAddress address, gsize size,
    GumKernelScanContext * ctx);
static void gum_kernel_enumerate_kexts (GumFoundKextFunc func,
    gpointer user_data);
static gboolean gum_kernel_scan_section (const gchar * section_name,
    const gchar * pattern_string, GumMemoryScanMatchFunc func,
    gpointer user_data);
static gboolean gum_kernel_emit_module_range (
    const GumDarwinSectionDetails * section, gpointer user_data);
static gboolean gum_kernel_emit_module (GumDarwinModule * module,
    gpointer user_data);
static gsize gum_darwin_module_estimate_size (
    GumDarwinModule * module);
static gboolean gum_kernel_range_by_name (GumMemoryRange * out_range,
    const gchar * name);
static gboolean gum_kernel_find_range_by_name (
    GumKernelModuleRangeDetails * details,
    GumKernelFindRangeByNameContext * ctx);
static gboolean gum_kernel_store_kext_addr (GumAddress address,
    gsize size, GumKernelSearchKextContext * ctx);
static gboolean gum_kernel_store_kext_name (GumAddress address,
    gsize size, GumKernelSearchKextContext * ctx);
static GumDarwinModule * gum_kernel_find_module_by_name (
    const gchar * module_name);
static gboolean gum_kernel_kext_by_name (GumDarwinModule * module,
    GumKernelKextByNameContext * ctx);
static GumDarwinModule * gum_kernel_get_module (void);
static GumAddress * gum_kernel_do_find_base_address (void);

#ifdef HAVE_ARM64

static float gum_kernel_get_version (void);
static GumAddress gum_kernel_get_base_from_all_image_info (void);
static GumAddress gum_kernel_bruteforce_base (GumAddress unslid_base);
static gboolean gum_kernel_is_header (GumAddress address);
static gboolean gum_kernel_has_kld (GumAddress address);
static gboolean gum_kernel_find_first_hit (GumAddress address, gsize size,
    gboolean * found);

#endif

mach_port_t gum_kernel_get_task (void);
static mach_port_t gum_kernel_do_init (void);
static void gum_kernel_do_deinit (void);

static GumDarwinModule * gum_kernel_cached_module = NULL;
static GumAddress gum_kernel_external_base = 0;

gboolean
gum_kernel_api_is_available (void)
{
  return gum_kernel_get_task () != MACH_PORT_NULL;
}

guint
gum_kernel_query_page_size (void)
{
  return vm_kernel_page_size;
}

GumAddress
gum_kernel_alloc_n_pages (guint n_pages)
{
  mach_vm_address_t result;
  mach_port_t task;
  gsize page_size, size;
  G_GNUC_UNUSED kern_return_t kr;
  G_GNUC_UNUSED gboolean written;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return 0;

  page_size = vm_kernel_page_size;
  size = (n_pages + 1) * page_size;

  result = 0;
  kr = mach_vm_allocate (task, &result, size, VM_FLAGS_ANYWHERE);
  g_assert (kr == KERN_SUCCESS);

  written = gum_darwin_write (task, result, (guint8 *) &size, sizeof (gsize));
  g_assert (written);

  kr = vm_protect (task, result + page_size, size - page_size,
      TRUE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE);
  g_assert (kr == KERN_SUCCESS);

  return result + page_size;
}

void
gum_kernel_free_pages (GumAddress mem)
{
  mach_port_t task;
  gsize page_size;
  mach_vm_address_t address;
  mach_vm_size_t * size;
  gsize bytes_read;
  G_GNUC_UNUSED kern_return_t kr;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return;

  page_size = vm_kernel_page_size;

  address = mem - page_size;
  size = (mach_vm_size_t *) gum_kernel_read (address, sizeof (mach_vm_size_t),
      &bytes_read);
  if (size == NULL)
    return;
  if (bytes_read < sizeof (mach_vm_size_t))
  {
    g_free (size);
    return;
  }

  kr = mach_vm_deallocate (task, address, *size);
  g_free (size);
  g_assert (kr == KERN_SUCCESS);
}

gboolean
gum_kernel_try_mprotect (GumAddress address,
                         gsize size,
                         GumPageProtection prot)
{
  mach_port_t task;
  gsize page_size;
  GumAddress aligned_address;
  gsize aligned_size;
  vm_prot_t mach_prot;
  kern_return_t kr;

  g_assert (size != 0);

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return FALSE;

  page_size = vm_kernel_page_size;
  aligned_address = address & ~(page_size - 1);
  aligned_size =
      (1 + ((address + size - 1 - aligned_address) / page_size)) * page_size;
  mach_prot = gum_page_protection_to_mach (prot);

  kr = mach_vm_protect (task, aligned_address, aligned_size, FALSE, mach_prot);

  return kr == KERN_SUCCESS;
}

guint8 *
gum_kernel_read (GumAddress address,
                 gsize len,
                 gsize * n_bytes_read)
{
  mach_port_t task;
  guint page_size;
  guint8 * result;
  gsize offset;
  kern_return_t kr;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return NULL;

  /* Failsafe size, smaller than the kernel page size. */
  page_size = 2048;
  result = g_malloc (len);
  offset = 0;

  while (offset != len)
  {
    GumAddress chunk_address, page_address;
    gsize chunk_size, page_offset;

    chunk_address = address + offset;
    page_address = chunk_address & ~GUM_ADDRESS (page_size - 1);
    page_offset = chunk_address - page_address;
    chunk_size = MIN (len - offset, page_size - page_offset);

    mach_vm_size_t n_bytes_read;

    /* mach_vm_read corrupts memory on iOS */
    kr = mach_vm_read_overwrite (task, chunk_address, chunk_size,
        (vm_address_t) (result + offset), &n_bytes_read);
    if (kr != KERN_SUCCESS)
      break;
    g_assert (n_bytes_read == chunk_size);

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
gum_kernel_write (GumAddress address,
                  const guint8 * bytes,
                  gsize len)
{
  mach_port_t task;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return FALSE;

  return gum_darwin_write (task, address, bytes, len);
}

void
gum_kernel_enumerate_ranges (GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  mach_port_t task;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return;

  gum_darwin_enumerate_ranges (task, prot, func, user_data);
}

void
gum_kernel_scan (const GumMemoryRange * range,
                 const GumMatchPattern * pattern,
                 GumMemoryScanMatchFunc func,
                 gpointer user_data)
{
  GumKernelScanContext ctx;
  GumAddress cursor, end;
  guint pattern_size;
  gsize size, max_chunk_size;

  ctx.func = func;
  ctx.user_data = user_data;

  cursor = range->base_address;
  pattern_size = gum_match_pattern_get_size (pattern);
  size = range->size;
  max_chunk_size = MAX (pattern_size * 2, 2048 * 512);
  end = cursor + size - pattern_size;

  while (cursor <= end)
  {
    gsize chunk_size;
    guint8 * haystack;
    GumMemoryRange subrange;

    chunk_size = MIN (size, max_chunk_size);
    haystack = gum_kernel_read (cursor, chunk_size, NULL);
    if (haystack == NULL)
      return;

    subrange.base_address = GUM_ADDRESS (haystack);
    subrange.size = chunk_size;

    ctx.cursor_userland = GUM_ADDRESS (haystack);
    ctx.cursor_kernel = GUM_ADDRESS (cursor);

    gum_memory_scan (&subrange, pattern,
        (GumMemoryScanMatchFunc) gum_kernel_emit_match, &ctx);

    g_free (haystack);

    if (!ctx.carry_on)
      return;

    cursor += chunk_size - pattern_size + 1;
    size -= chunk_size - pattern_size + 1;
  }
}

static gboolean
gum_kernel_emit_match (GumAddress address,
                       gsize size,
                       GumKernelScanContext * ctx)
{
  GumAddress address_kernel = address - ctx->cursor_userland +
      ctx->cursor_kernel;

  ctx->carry_on = ctx->func (address_kernel, size, ctx->user_data);

  return ctx->carry_on;
}

void
gum_kernel_enumerate_modules (GumFoundModuleFunc func,
                              gpointer user_data)
{
  GumEmitModuleContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  if (!gum_kernel_emit_module (gum_kernel_get_module (), &ctx))
    return;

  gum_kernel_enumerate_kexts (gum_kernel_emit_module, &ctx);
}

static gboolean
gum_kernel_emit_module (GumDarwinModule * module,
                        gpointer user_data)
{
  GumEmitModuleContext * ctx = user_data;
  GumModuleDetails details;
  GumMemoryRange range;

  range.base_address = module->base_address;
  range.size = gum_darwin_module_estimate_size (module);

  details.name = module->name;
  details.range = &range;
  details.path = NULL;

  return ctx->func (&details, ctx->user_data);
}

static void
gum_kernel_enumerate_kexts (GumFoundKextFunc func,
                            gpointer user_data)
{
  mach_port_t task;
  GHashTable * kexts;
  GumKernelSearchKextContext kext_ctx;
  GHashTableIter iter;
  gpointer item;
  gpointer header_addr;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return;

  kexts = g_hash_table_new (NULL, NULL);
  kext_ctx.kexts = kexts;

  /* Search the first 8 bytes of mach0 header. */
  if (!gum_kernel_scan_section ("__PRELINK_TEXT.__text", "cffaedfe0c00000100",
        (GumMemoryScanMatchFunc) gum_kernel_store_kext_addr, &kext_ctx))
  {
    return;
  }

  /* Search for "com.apple" string. */
  if (!gum_kernel_scan_section ("__PRELINK_DATA.__data", "636f6d2e6170706c65",
        (GumMemoryScanMatchFunc) gum_kernel_store_kext_name, &kext_ctx))
  {
    if (!gum_kernel_scan_section ("__PRELINK_TEXT.__text", "636f6d2e6170706c65",
          (GumMemoryScanMatchFunc) gum_kernel_store_kext_name, &kext_ctx))
    {
      return;
    }
  }

  g_hash_table_iter_init (&iter, kexts);
  while (g_hash_table_iter_next (&iter, &header_addr, &item))
  {
    GumKernelKextInfo * kext = item;
    GumDarwinModule * module;

    if (*kext->name == '\0')
      continue;

    module = gum_darwin_module_new_from_memory (kext->name, task, kext->address,
        GUM_DARWIN_MODULE_FLAGS_NONE, NULL);

    if (module == NULL)
      continue;

    if (!func (module, user_data))
      break;
  }

  g_hash_table_unref (kexts);
}

static gboolean
gum_kernel_scan_section (const gchar * section_name,
                         const gchar * pattern_string,
                         GumMemoryScanMatchFunc func,
                         gpointer user_data)
{
  GumMemoryRange range;
  GumMatchPattern * pattern;

  if (!gum_kernel_range_by_name (&range, section_name))
    return FALSE;

  pattern = gum_match_pattern_new_from_string (pattern_string);
  if (pattern == NULL)
    return FALSE;

  gum_kernel_scan (&range, pattern, func, user_data);

  gum_match_pattern_unref (pattern);

  return TRUE;
}

static gsize
gum_darwin_module_estimate_size (GumDarwinModule * module)
{
  gsize index = 0, size = 0;

  do
  {
    const GumDarwinSegment * segment;

    segment = gum_darwin_module_get_nth_segment (module, index++);
    size += segment->vm_size;
  }
  while (index < module->segments->len);

  return size;
}

static gboolean
gum_kernel_range_by_name (GumMemoryRange * out_range,
                          const gchar * name)
{
  GumKernelFindRangeByNameContext ctx;

  ctx.name = name;
  ctx.found = FALSE;

  gum_kernel_enumerate_module_ranges ("Kernel", GUM_PAGE_NO_ACCESS,
      (GumFoundKernelModuleRangeFunc) gum_kernel_find_range_by_name, &ctx);

  if (ctx.found)
  {
    out_range->base_address = ctx.range.base_address;
    out_range->size = ctx.range.size;
    return TRUE;
  }

  return FALSE;
}

static gboolean
gum_kernel_find_range_by_name (GumKernelModuleRangeDetails * details,
                               GumKernelFindRangeByNameContext * ctx)
{
  if (strncmp (details->name, ctx->name, sizeof (details->name)) == 0)
  {
    ctx->range.base_address = details->address;
    ctx->range.size = details->size;
    ctx->found = TRUE;
    return FALSE;
  }

  return TRUE;
}

static gboolean
gum_kernel_store_kext_addr (GumAddress address,
                            gsize size,
                            GumKernelSearchKextContext * ctx)
{
  GumKernelKextInfo * kext;

  kext = g_slice_new0 (GumKernelKextInfo);
  kext->address = address;

  g_hash_table_insert (ctx->kexts, GSIZE_TO_POINTER (address), kext);

  return TRUE;
}

static gboolean
gum_kernel_store_kext_name (GumAddress address,
                            gsize size,
                            GumKernelSearchKextContext * ctx)
{
  GumKernelKextInfo * kext;
  guint8 * buf;

  /* Reference: osfmk/mach/kmod.h */
  buf = gum_kernel_read (address + 0x8c, 8, NULL);
  kext = g_hash_table_lookup (ctx->kexts, *((GumAddress **) buf));
  g_free (buf);

  if (kext == NULL)
    return TRUE;

  buf = gum_kernel_read (address, 0x40, NULL);
  strncpy (kext->name, (gchar*) buf, 0x40);
  kext->name[0x40] = 0;
  g_free (buf);

  return TRUE;
}

void
gum_kernel_enumerate_module_ranges (const gchar * module_name,
                                    GumPageProtection prot,
                                    GumFoundKernelModuleRangeFunc func,
                                    gpointer user_data)
{
  GumDarwinModule * module;
  GumKernelEnumerateModuleRangesContext ctx;

  module = gum_kernel_find_module_by_name (module_name);
  if (module == NULL)
    return;

  ctx.protection = prot;
  ctx.func = func;
  ctx.user_data = user_data;

  gum_darwin_module_enumerate_sections (module, gum_kernel_emit_module_range,
      &ctx);
}

static GumDarwinModule *
gum_kernel_find_module_by_name (const gchar * module_name)
{
  GumKernelKextByNameContext ctx;

  if (strcmp (module_name, "Kernel") == 0)
    return gum_kernel_get_module ();

  ctx.module_name = module_name;
  ctx.found = FALSE;

  gum_kernel_enumerate_kexts ((GumFoundKextFunc) gum_kernel_kext_by_name, &ctx);

  if (!ctx.found)
    return NULL;

  return ctx.module;
}

static gboolean
gum_kernel_kext_by_name (GumDarwinModule * module,
                         GumKernelKextByNameContext * ctx)
{
  ctx->found = strcmp (module->name, ctx->module_name) == 0;

  if (ctx->found)
    ctx->module = module;

  return !ctx->found;
}

static gboolean
gum_kernel_emit_module_range (const GumDarwinSectionDetails * section,
                              gpointer user_data)
{
  GumKernelEnumerateModuleRangesContext * ctx = user_data;
  GumPageProtection prot;
  GumKernelModuleRangeDetails details;

  prot = gum_page_protection_from_mach (section->protection);
  if ((prot & ctx->protection) != ctx->protection)
    return TRUE;

  g_snprintf (details.name, sizeof (details.name), "%s.%s",
      section->segment_name, section->section_name);
  details.address = section->vm_address;
  details.size = section->size;
  details.protection = prot;

  return ctx->func (&details, ctx->user_data);
}

static GumDarwinModule *
gum_kernel_get_module (void)
{
  mach_port_t task;
  GumAddress base;

  if (gum_kernel_cached_module != NULL)
    return gum_kernel_cached_module;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return NULL;

  base = gum_kernel_find_base_address ();

  gum_kernel_cached_module = gum_darwin_module_new_from_memory ("Kernel", task,
      base, GUM_DARWIN_MODULE_FLAGS_NONE, NULL);

  return gum_kernel_cached_module;
}

GumAddress
gum_kernel_find_base_address (void)
{
  static GOnce get_base_once = G_ONCE_INIT;

  if (gum_kernel_external_base != 0)
    return gum_kernel_external_base;

  g_once (&get_base_once, (GThreadFunc) gum_kernel_do_find_base_address, NULL);

  return *((GumAddress *) get_base_once.retval);
}

void
gum_kernel_set_base_address (GumAddress base)
{
  gum_kernel_external_base = base;
}

static GumAddress *
gum_kernel_do_find_base_address (void)
{
  GumAddress base = 0;

#ifdef HAVE_ARM64
  float version;

  base = gum_kernel_get_base_from_all_image_info ();
  if (base == 0)
  {
    version = gum_kernel_get_version ();
    if (version >= 16.0) /* iOS 10.0+ */
    {
      base = gum_kernel_bruteforce_base (
          G_GUINT64_CONSTANT (0xfffffff007004000));
    }
    else if (version >= 15.0) /* iOS 9.0+ */
    {
      base = gum_kernel_bruteforce_base (
          G_GUINT64_CONSTANT (0xffffff8004004000));
    }
  }
#endif

  return g_slice_dup (GumAddress, &base);
}

#ifdef HAVE_ARM64

static float
gum_kernel_get_version (void)
{
  char buf[256];
  size_t size;
  G_GNUC_UNUSED int res;
  float version;

  size = sizeof (buf);
  res = sysctlbyname ("kern.osrelease", buf, &size, NULL, 0);
  g_assert (res == 0);

  version = atof (buf);

  return version;
}

static GumAddress
gum_kernel_get_base_from_all_image_info (void)
{
  mach_port_t task;
  kern_return_t kr;
  DyldInfo info_raw;
  mach_msg_type_number_t info_count = DYLD_INFO_COUNT;

  task = gum_kernel_get_task ();
  if (task == MACH_PORT_NULL)
    return 0;

  kr = task_info (task, TASK_DYLD_INFO, (task_info_t) &info_raw, &info_count);
  if (kr != KERN_SUCCESS)
    return 0;

  if (info_raw.info_64.all_image_info_addr == 0 &&
      info_raw.info_64.all_image_info_size == 0)
  {
    return 0;
  }

  return info_raw.info_64.all_image_info_size +
      G_GUINT64_CONSTANT (0xfffffff007004000);
}

static gboolean
gum_kernel_is_debug (void)
{
  char buf[256];
  size_t size;
  G_GNUC_UNUSED int res;

  size = sizeof (buf);
  res = sysctlbyname ("kern.bootargs", buf, &size, NULL, 0);
  g_assert (res == 0);

  return strstr (buf, "debug") != NULL;
}

static GumAddress
gum_kernel_bruteforce_base (GumAddress unslid_base)
{
  /*
   * References & credits:
   * http://conference.hackinthebox.org/hitbsecconf2012kul/materials
   *    /D1T2%20-%20Mark%20Dowd%20&%20Tarjei%20Mandt%20-%20iOS6%20Security.pdf
   * https://www.theiphonewiki.com/wiki/Kernel_ASLR
   * https://www.wikiwand.com/en/Address_space_layout_randomization
   * https://www.slideshare.net/i0n1c
   *    /csw2013-stefan-esserios6exploitation280dayslater
   *    /19-KASLR_iOS_6_introduces_KASLR
   * http://people.oregonstate.edu/~jangye/assets/papers/2016/jang:drk-bh.pdf
   */

  gint slide_byte;
  gboolean is_debug;

  is_debug = gum_kernel_is_debug ();

  if (is_debug && gum_kernel_is_header (unslid_base))
    return unslid_base;

  if (gum_kernel_is_header (unslid_base + 0x21000000))
    return unslid_base + 0x21000000;

  for (slide_byte = 255; slide_byte > 0; slide_byte--)
  {
    GumAddress base = unslid_base;

    base += GUM_KERNEL_SLIDE_OFFSET +
        ((1 + slide_byte) * GUM_KERNEL_SLIDE_SIZE);

    if (gum_kernel_is_header (base))
      return base;
  }

  return 0;
}

static gboolean
gum_kernel_is_header (GumAddress address)
{
  gboolean result = FALSE;
  guint8 * header = NULL;
  gsize n_bytes_read;

  header = gum_kernel_read (address, 28, &n_bytes_read);
  if (n_bytes_read != 28 || header == NULL)
    goto bail_out;

  /* Magic */
  if (*((guint32*) (header + 0)) != MH_MAGIC_64)
    goto bail_out;

  /* Cpu type */
  if (*((guint32*) (header + 4)) != CPU_TYPE_ARM64)
    goto bail_out;

  /* File type */
  if (*((guint32*) (header + 12)) != MH_EXECUTE)
    goto bail_out;

  if (!gum_kernel_has_kld (address))
    goto bail_out;

  result = TRUE;

bail_out:
  if (header != NULL)
    g_free (header);

  return result;
}

static gboolean
gum_kernel_has_kld (GumAddress address)
{
  gboolean found = FALSE;
  GumMemoryRange range;
  GumMatchPattern * pattern;

  range.base_address = address;
  range.size = 2048;

  /* __KLD */
  pattern = gum_match_pattern_new_from_string ("5f 5f 4b 4c 44");
  if (pattern == NULL)
    return FALSE;

  gum_kernel_scan (&range, pattern,
      (GumMemoryScanMatchFunc) gum_kernel_find_first_hit, &found);

  gum_match_pattern_unref (pattern);

  return found;
}

static gboolean
gum_kernel_find_first_hit (GumAddress address,
                           gsize size,
                           gboolean * found)
{
  *found = TRUE;

  return FALSE;
}

#endif

mach_port_t
gum_kernel_get_task (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, (GThreadFunc) gum_kernel_do_init, NULL);

  return (mach_port_t) GPOINTER_TO_SIZE (init_once.retval);
}

static mach_port_t
gum_kernel_do_init (void)
{
#if defined (HAVE_IOS) || defined (HAVE_TVOS)
  mach_port_t task;

  if (gum_darwin_query_hardened ())
    return MACH_PORT_NULL;

  task = MACH_PORT_NULL;
  task_for_pid (mach_task_self (), 0, &task);
  if (task == MACH_PORT_NULL)
  {
    /* Untested, but should work on iOS 9.1 with Pangu jailbreak */
    host_get_special_port (mach_host_self (), HOST_LOCAL_NODE, 4, &task);
  }

  if (task != MACH_PORT_NULL)
    _gum_register_destructor (gum_kernel_do_deinit);

  return task;
#else
  (void) gum_kernel_do_deinit;

  return MACH_PORT_NULL;
#endif
}

static void
gum_kernel_do_deinit (void)
{
  mach_port_deallocate (mach_task_self (), gum_kernel_get_task ());
}
```