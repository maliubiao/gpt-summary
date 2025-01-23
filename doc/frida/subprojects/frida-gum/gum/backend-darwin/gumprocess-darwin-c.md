Response:
The user wants to understand the functionality of the `gumprocess-darwin.c` file, which is part of Frida. I need to analyze the provided C code and identify its core responsibilities.

Here's a breakdown of the thinking process:

1. **High-Level Understanding:** The file name suggests it's related to process-level operations on Darwin (macOS/iOS). The `gum` prefix indicates it's part of Frida's Gum engine.

2. **Include Directives:** The `#include` directives point to key areas:
    * `gumprocess-priv.h`: Likely contains private declarations for this module.
    * `gum-init.h`:  Initialization routines for Gum.
    * `gum/gumdarwin.h`: Darwin-specific Gum API.
    * `gumdarwinmodule.h`:  Handling of modules on Darwin.
    * `gumleb.h`: Likely Little-Endian Base library (common in cross-platform tools).
    * `gumprocess-darwin-priv.h`: More private Darwin process info.
    * Standard system headers (`dlfcn.h`, `errno.h`, etc.): Standard OS functionality.
    * `mach-o/*`:  Working with Mach-O executable format (core of macOS/iOS).

3. **Constants and Macros:**
    * `MAX_MACH_HEADER_SIZE`:  Indicates interaction with Mach-O headers.
    * `DYLD_IMAGE_INFO_*_SIZE`:  Working with dynamic linker information.
    * `GUM_THREAD_POLL_*`:  Potentially related to monitoring threads.
    * `GUM_PTHREAD_FIELD_*`:  Accessing internal fields of `pthread_t` structures, a strong indicator of low-level manipulation.
    * `GUM_PTHREAD_GET_FIELD`:  A macro for accessing those internal `pthread_t` fields.
    * Architecture-specific macros (`HAVE_ARM64`, `__darwin_arm_thread_state64_*`):  Handling platform differences in thread state.

4. **Type Definitions:**  Various `typedef struct` declarations define contexts for different operations. This helps organize the code and pass data around. Key examples:
    * `GumSetHardwareBreakpointContext`, `GumSetHardwareWatchpointContext`: Managing hardware breakpoints and watchpoints.
    * `GumEnumerateImportsContext`, `GumEnumerateExportsContext`, `GumEnumerateSymbolsContext`, `GumEnumerateSectionsContext`: Inspecting module contents.
    * `GumFindEntrypointContext`: Locating the entry point of a process/module.
    * `GumEnumerateModulesSlowContext`:  A context for enumerating modules.
    * `GumEnumerateMallocRangesContext`:  Inspecting dynamically allocated memory.
    * `DyldAllImageInfos*`, `DyldImageInfo*`: Structures mirroring the dynamic linker's data structures.

5. **Function Declarations:**  The function prototypes (especially the `static` ones) provide clues about the file's internal workings:
    * `gum_do_set_hardware_breakpoint`, `gum_do_unset_hardware_breakpoint`, etc.:  Low-level functions for manipulating debug registers.
    * `gum_emit_malloc_ranges`: Callback for reporting malloc'd memory regions.
    * `gum_read_malloc_memory`: Reading memory from another process (essential for dynamic instrumentation).
    * `gum_probe_range_for_entrypoint`, `gum_store_range_of_potential_modules`, `gum_emit_modules_in_range`: Logic for discovering modules in memory.
    * `gum_emit_import`, `gum_resolve_export`, `gum_emit_export`, `gum_emit_symbol`, `gum_emit_section`: Callbacks for reporting module contents.
    * `find_image_address_and_slide`:  Locating modules in memory and their ASLR slide.
    * `gum_canonicalize_module_name`:  Standardizing module names.
    * `gum_thread_state_from_darwin`:  Converting Darwin's thread state to a generic Gum representation.
    * `gum_darwin_fill_file_mapping`, `gum_darwin_clamp_range_size`:  Relating memory ranges to files on disk.

6. **Global Functions:** The non-`static` functions define the public API of this module within Frida:
    * `gum_process_query_libc_name`:  Getting the name of the C standard library.
    * `gum_process_is_debugger_attached`: Detecting if a debugger is present.
    * `gum_process_get_id`, `gum_process_get_current_thread_id`:  Getting process and thread IDs.
    * `gum_process_has_thread`: Checking if a thread exists in the process.
    * `gum_process_modify_thread`: Applying changes to a thread's state.
    * `_gum_process_enumerate_threads`, `_gum_process_enumerate_modules`, `_gum_process_enumerate_ranges`:  Internal functions for enumerating threads, modules, and memory ranges.
    * `gum_process_enumerate_malloc_ranges`: Enumerating dynamically allocated memory.
    * `gum_thread_try_get_ranges`:  Getting stack and other thread-related memory ranges.
    * `gum_thread_get_system_error`, `gum_thread_set_system_error`: Accessing and setting thread-local error numbers.
    * `gum_thread_suspend`, `gum_thread_resume`:  Controlling thread execution.
    * `gum_thread_set_hardware_breakpoint`, `gum_thread_unset_hardware_breakpoint`, `gum_thread_set_hardware_watchpoint`, `gum_thread_unset_hardware_watchpoint`:  Managing hardware debugging features.
    * `gum_module_load`, `gum_module_ensure_initialized`: Loading and ensuring modules are initialized.
    * `gum_module_enumerate_imports`, `gum_module_enumerate_exports`, `gum_module_enumerate_symbols`, `gum_module_enumerate_ranges`, `gum_module_enumerate_sections`, `gum_module_enumerate_dependencies`:  Inspecting module contents.
    * `gum_module_find_base_address`, `gum_module_find_export_by_name`:  Locating module base addresses and exported symbols.
    * `gum_darwin_check_xnu_version`:  Checking the macOS/iOS kernel version.
    * `gum_darwin_cpu_type_from_pid`: Determining the CPU architecture of a process.
    * `gum_darwin_query_sysroot`, `gum_darwin_query_hardened`, `gum_darwin_query_all_image_infos`:  Getting system-level information.

7. **Putting It Together:** Based on the includes, constants, types, and function declarations, the primary functionalities are:
    * **Process Introspection:** Getting information about the current process (ID, threads, modules, memory ranges).
    * **Thread Manipulation:** Suspending, resuming, and modifying thread states (including debug registers).
    * **Module Inspection:** Enumerating imports, exports, symbols, sections, and dependencies of loaded modules.
    * **Memory Management Inspection:**  Enumerating malloc'd memory regions.
    * **Hardware Debugging:** Setting and unsetting hardware breakpoints and watchpoints.
    * **Module Loading:** Dynamically loading libraries.
    * **System Information:**  Querying OS version and other system details.

8. **Relating to Reverse Engineering:** The ability to inspect memory, threads, and modules, and to set breakpoints/watchpoints are core reverse engineering techniques. Frida uses these to enable dynamic analysis and instrumentation.

9. **Low-Level Details:** The code interacts directly with Mach system calls (like `task_threads`, `thread_get_state`), internal `pthread_t` structure fields, and Mach-O file format structures, demonstrating its low-level nature.

10. **Hypothetical Inputs/Outputs:** While full tracing isn't feasible here, considering specific functions:
    * `gum_process_get_id()`: Input: None. Output: The process ID (an integer).
    * `gum_module_find_export_by_name("libSystem.B.dylib", "printf")`: Input: Module name ("libSystem.B.dylib"), symbol name ("printf"). Output: The memory address of the `printf` function in that library, or 0 if not found.
    * `gum_thread_suspend(some_thread_id, &error)`: Input: A thread ID, a pointer to a `GError` struct. Output: `TRUE` on success, `FALSE` on failure (with `error` potentially filled).

11. **Common Usage Errors:**
    * Providing an incorrect module name to functions like `gum_module_enumerate_exports`.
    * Using an invalid thread ID for thread manipulation functions.
    * Incorrectly setting hardware breakpoint/watchpoint addresses or conditions.
    * Forgetting to check the `GError` pointer for errors after function calls.

12. **User Steps to Reach This Code:** A user interacting with Frida might trigger this code through:
    * Using Frida's API to list modules in a process.
    * Setting breakpoints or watchpoints using Frida.
    * Calling Frida functions to enumerate exports of a library.
    * Inspecting memory allocated by a process using Frida.

13. **Final Summarization:**  Focus on the main categories of functionality identified in step 7.
This is the first part of the source code for `gumprocess-darwin.c`, a file within the Frida dynamic instrumentation toolkit. Based on the includes, structure definitions, and function declarations, here's a summary of its functionalities:

**Core Functionalities:**

This file provides Darwin (macOS/iOS) specific implementations for core process-related operations within Frida's Gum engine. It deals with:

1. **Process Information and Manipulation:**
   - **Getting Process ID:**  Retrieves the current process ID.
   - **Checking Debugger Attachment:** Determines if a debugger is currently attached to the process.
   - **Thread Enumeration:**  Provides a mechanism to iterate through all threads within the process.
   - **Thread Existence Check:** Verifies if a specific thread ID belongs to the current process.
   - **Thread State Modification:** Allows for applying custom functions to modify the state of a given thread.
   - **Thread Suspension and Resumption:** Provides the ability to pause and restart the execution of individual threads.

2. **Module Inspection and Manipulation:**
   - **Module Enumeration:**  Discovers and lists all loaded modules (libraries, executables) within the process.
   - **Main Module Identification:** Identifies the main executable module of the process.
   - **Module Loading:**  Provides a way to dynamically load additional libraries into the process.
   - **Ensuring Module Initialization:** Attempts to fully initialize a loaded module.
   - **Import Enumeration:** Lists the symbols imported by a specific module from other libraries.
   - **Export Enumeration:** Lists the symbols exported (made available) by a specific module.
   - **Symbol Enumeration:**  Lists all symbols (functions, variables) within a module.
   - **Section Enumeration:** Iterates through the different sections within a module's binary file.
   - **Dependency Enumeration:** Lists the other modules that a given module depends on.
   - **Finding Module Base Address:**  Locates the starting address in memory where a module is loaded.
   - **Finding Exported Symbols:**  Retrieves the memory address of a specific exported symbol within a module.

3. **Memory Region Management:**
   - **Range Enumeration:**  Iterates through different memory regions within the process's address space, categorized by their page protection (e.g., read, write, execute).
   - **Malloc Range Enumeration:** Specifically enumerates memory regions allocated using `malloc`.
   - **Retrieving Thread Stack Ranges:**  Attempts to get the memory ranges associated with a thread's stack.

4. **Hardware Debugging Support:**
   - **Setting and Unsetting Hardware Breakpoints:** Allows setting and removing hardware breakpoints at specific memory addresses.
   - **Setting and Unsetting Hardware Watchpoints:** Enables setting and removing hardware watchpoints to monitor memory access.

5. **System Information Retrieval:**
   - **Getting LibC Name:**  Retrieves the standard name for the C library.
   - **Checking XNU Version:**  Compares the running kernel version against a specified version.
   - **Determining CPU Type:**  Identifies the CPU architecture of a given process.
   - **Querying Sysroot:**  Attempts to determine the system root directory (more relevant for simulators).
   - **Querying Hardened Runtime Status:** Checks if the process is running with the hardened runtime enabled.
   - **Querying Dyld All Image Infos:** Retrieves information about all loaded images from the dynamic linker.

**Relationship to Reverse Engineering:**

This file is fundamentally linked to reverse engineering techniques. It provides the building blocks for:

* **Dynamic Analysis:** By allowing inspection of a running process's memory, threads, and loaded modules, reverse engineers can understand the program's behavior in real-time.
* **Hooking and Instrumentation:** Frida, leveraging this code, allows injecting custom code into a running process to intercept function calls, modify data, and alter program flow. The hardware breakpoint and watchpoint functionalities are directly used for this.
* **Understanding Program Structure:**  Enumerating modules, imports, exports, and sections helps in understanding the organization and dependencies of the target application.

**Examples related to Reverse Engineering:**

* **Hooking a Function:** A reverse engineer could use `gum_module_find_export_by_name` to get the address of a function like `-[NSString stringWithUTF8String:]` in `Foundation` and then use Frida's API (built upon lower-level functions here) to replace its implementation with a custom one.
* **Tracing API Calls:** By setting a breakpoint at the entry point of a system call (e.g., using `gum_thread_set_hardware_breakpoint`), a reverse engineer can monitor when and how the application interacts with the operating system.
* **Analyzing Memory Allocation:** Using `gum_process_enumerate_malloc_ranges`, one can examine dynamically allocated memory blocks to understand data structures and memory management within the application.

**Explanation of Potential Further Parts:**

Given that this is "Part 1 of 3," the subsequent parts likely cover:

* **Part 2:** Could focus on more complex interactions with the target process, potentially including code injection, advanced memory manipulation, or more sophisticated debugging techniques.
* **Part 3:** Might cover the interaction with the Frida agent and the communication mechanism between the injected code and the Frida host process. It could also delve into error handling, logging, and other auxiliary functionalities.

In summary, `gumprocess-darwin.c` forms a crucial foundation for Frida on Darwin-based systems, providing the essential low-level mechanisms for dynamic instrumentation and reverse engineering.

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gumprocess-darwin.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共3部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2015 Asger Hautop Drewsen <asgerdrewsen@gmail.com>
 * Copyright (C) 2022-2023 Francesco Tamagni <mrmacete@protonmail.ch>
 * Copyright (C) 2022-2024 Håvard Sørbø <havard@hsorbo.no>
 * Copyright (C) 2023 Alex Soler <asoler@nowsecure.com>
 * Copyright (C) 2023 Grant Douglas <me@hexplo.it>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumprocess-priv.h"

#include "gum-init.h"
#include "gum/gumdarwin.h"
#include "gumdarwinmodule.h"
#include "gumleb.h"
#include "gumprocess-darwin-priv.h"

#include <dlfcn.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <mach-o/dyld.h>
#include <mach-o/nlist.h>
#include <malloc/malloc.h>
#include <pthread.h>
#include <sys/sysctl.h>
#include <unistd.h>

#define MAX_MACH_HEADER_SIZE (64 * 1024)
#define DYLD_IMAGE_INFO_32_SIZE 12
#define DYLD_IMAGE_INFO_64_SIZE 24
#define GUM_THREAD_POLL_STEP 1000
#define GUM_MAX_THREAD_POLL (20000000 / GUM_THREAD_POLL_STEP)
#define GUM_PTHREAD_FIELD_STACKADDR ((GLIB_SIZEOF_VOID_P == 8) ? 0xb0 : 0x88)
#define GUM_PTHREAD_FIELD_FREEADDR ((GLIB_SIZEOF_VOID_P == 8) ? 0xc0 : 0x90)
#define GUM_PTHREAD_FIELD_FREESIZE ((GLIB_SIZEOF_VOID_P == 8) ? 0xc8 : 0x94)
#define GUM_PTHREAD_FIELD_GUARDSIZE ((GLIB_SIZEOF_VOID_P == 8) ? 0xd0 : 0x98)
#define GUM_PTHREAD_FIELD_THREADID ((GLIB_SIZEOF_VOID_P == 8) ? 0xd8 : 0xa0)
#define GUM_PTHREAD_GET_FIELD(thread, field, type) \
    (*((type *) ((guint8 *) thread + field)))

#if defined (HAVE_ARM64) && !defined (__DARWIN_OPAQUE_ARM_THREAD_STATE64)
# define __darwin_arm_thread_state64_get_pc_fptr(ts) \
    ((void *) (uintptr_t) ((ts).__pc))
# define __darwin_arm_thread_state64_set_pc_fptr(ts, fptr) \
    ((ts).__pc = (uintptr_t) (fptr))
# define __darwin_arm_thread_state64_get_lr_fptr(ts) \
    ((void *) (uintptr_t) ((ts).__lr))
# define __darwin_arm_thread_state64_set_lr_fptr(ts, fptr) \
    ((ts).__lr = (uintptr_t) (fptr))
# define __darwin_arm_thread_state64_get_sp(ts) \
    ((ts).__sp)
# define __darwin_arm_thread_state64_set_sp(ts, ptr) \
    ((ts).__sp = (uintptr_t) (ptr))
# define __darwin_arm_thread_state64_get_fp(ts) \
    ((ts).__fp)
# define __darwin_arm_thread_state64_set_fp(ts, ptr) \
    ((ts).__fp = (uintptr_t) (ptr))
#endif

typedef struct _GumSetHardwareBreakpointContext GumSetHardwareBreakpointContext;
typedef struct _GumSetHardwareWatchpointContext GumSetHardwareWatchpointContext;
typedef void (* GumModifyDebugRegistersFunc) (GumDarwinNativeDebugState * ds,
    gpointer user_data);
typedef struct _GumEnumerateImportsContext GumEnumerateImportsContext;
typedef struct _GumEnumerateExportsContext GumEnumerateExportsContext;
typedef struct _GumEnumerateSymbolsContext GumEnumerateSymbolsContext;
typedef struct _GumEnumerateSectionsContext GumEnumerateSectionsContext;
typedef struct _GumFindEntrypointContext GumFindEntrypointContext;
typedef struct _GumEnumerateModulesSlowContext GumEnumerateModulesSlowContext;
typedef struct _GumEnumerateMallocRangesContext GumEnumerateMallocRangesContext;
typedef struct _GumCanonicalizeNameContext GumCanonicalizeNameContext;

typedef struct _DyldAllImageInfos32 DyldAllImageInfos32;
typedef struct _DyldAllImageInfos64 DyldAllImageInfos64;
typedef struct _DyldImageInfo32 DyldImageInfo32;
typedef struct _DyldImageInfo64 DyldImageInfo64;

struct _GumSetHardwareBreakpointContext
{
  guint breakpoint_id;
  GumAddress address;
};

struct _GumSetHardwareWatchpointContext
{
  guint watchpoint_id;
  GumAddress address;
  gsize size;
  GumWatchConditions conditions;
};

struct _GumEnumerateImportsContext
{
  GumFoundImportFunc func;
  gpointer user_data;

  GumDarwinModuleResolver * resolver;
  GumModuleMap * module_map;
};

struct _GumEnumerateExportsContext
{
  GumFoundExportFunc func;
  gpointer user_data;

  GumDarwinModuleResolver * resolver;
  GumDarwinModule * module;
  gboolean carry_on;
};

struct _GumEnumerateSymbolsContext
{
  GumFoundSymbolFunc func;
  gpointer user_data;

  GArray * sections;
};

struct _GumEnumerateSectionsContext
{
  GumFoundSectionFunc func;
  gpointer user_data;

  guint next_section_id;
};

struct _GumFindEntrypointContext
{
  GumAddress result;
  mach_port_t task;
  guint alignment;
};

struct _GumEnumerateModulesSlowContext
{
  mach_port_t task;
  GumFoundModuleFunc func;
  gpointer user_data;

  GArray * ranges;
  guint alignment;
};

struct _GumEnumerateMallocRangesContext
{
  GumFoundMallocRangeFunc func;
  gpointer user_data;
  gboolean carry_on;
};

struct _GumCanonicalizeNameContext
{
  const gchar * module_name;
  gchar * module_path;
};

struct _DyldAllImageInfos32
{
  guint32 version;
  guint32 info_array_count;
  guint32 info_array;
  guint32 notification;
  guint8 process_detached_from_shared_region;
  guint8 libsystem_initialized;
  guint32 dyld_image_load_address;
  guint32 jit_info;
  guint32 dyld_version;
  guint32 error_message;
  guint32 termination_flags;
  guint32 core_symbolication_shm_page;
  guint32 system_order_flag;
  guint32 uuid_array_count;
  guint32 uuid_array;
  guint32 dyld_all_image_infos_address;
  guint32 initial_image_count;
  guint32 error_kind;
  guint32 error_client_of_dylib_path;
  guint32 error_target_dylib_path;
  guint32 error_symbol;
  guint32 shared_cache_slide;
  guint8 shared_cache_uuid[16];
  guint32 shared_cache_base_address;
  volatile guint64 info_array_change_timestamp;
  guint32 dyld_path;
  guint32 notify_mach_ports[8];
  guint32 reserved[5];
  guint32 compact_dyld_image_info_addr;
  guint32 compact_dyld_image_info_size;
  guint32 platform;
};

struct _DyldAllImageInfos64
{
  guint32 version;
  guint32 info_array_count;
  guint64 info_array;
  guint64 notification;
  guint8 process_detached_from_shared_region;
  guint8 libsystem_initialized;
  guint32 padding;
  guint64 dyld_image_load_address;
  guint64 jit_info;
  guint64 dyld_version;
  guint64 error_message;
  guint64 termination_flags;
  guint64 core_symbolication_shm_page;
  guint64 system_order_flag;
  guint64 uuid_array_count;
  guint64 uuid_array;
  guint64 dyld_all_image_infos_address;
  guint64 initial_image_count;
  guint64 error_kind;
  guint64 error_client_of_dylib_path;
  guint64 error_target_dylib_path;
  guint64 error_symbol;
  guint64 shared_cache_slide;
  guint8 shared_cache_uuid[16];
  guint64 shared_cache_base_address;
  volatile guint64 info_array_change_timestamp;
  guint64 dyld_path;
  guint32 notify_mach_ports[8];
  guint64 reserved[9];
  guint64 compact_dyld_image_info_addr;
  guint64 compact_dyld_image_info_size;
  guint32 platform;
};

struct _DyldImageInfo32
{
  guint32 image_load_address;
  guint32 image_file_path;
  guint32 image_file_mod_date;
};

struct _DyldImageInfo64
{
  guint64 image_load_address;
  guint64 image_file_path;
  guint64 image_file_mod_date;
};

#ifndef PROC_PIDREGIONPATHINFO2
# define PROC_PIDREGIONPATHINFO2 22
#endif

#ifndef PROC_INFO_CALL_PIDINFO

# define PROC_INFO_CALL_PIDINFO 0x2
# define PROC_PIDREGIONINFO     7
# define PROC_PIDREGIONPATHINFO 8

struct vinfo_stat
{
  uint32_t vst_dev;
  uint16_t vst_mode;
  uint16_t vst_nlink;
  uint64_t vst_ino;
  uid_t vst_uid;
  gid_t vst_gid;
  int64_t vst_atime;
  int64_t vst_atimensec;
  int64_t vst_mtime;
  int64_t vst_mtimensec;
  int64_t vst_ctime;
  int64_t vst_ctimensec;
  int64_t vst_birthtime;
  int64_t vst_birthtimensec;
  off_t vst_size;
  int64_t vst_blocks;
  int32_t vst_blksize;
  uint32_t vst_flags;
  uint32_t vst_gen;
  uint32_t vst_rdev;
  int64_t vst_qspare[2];
};

struct vnode_info
{
  struct vinfo_stat vi_stat;
  int vi_type;
  int vi_pad;
  fsid_t vi_fsid;
};

struct vnode_info_path
{
  struct vnode_info vip_vi;
  char vip_path[MAXPATHLEN];
};

struct proc_regioninfo
{
  uint32_t pri_protection;
  uint32_t pri_max_protection;
  uint32_t pri_inheritance;
  uint32_t pri_flags;
  uint64_t pri_offset;
  uint32_t pri_behavior;
  uint32_t pri_user_wired_count;
  uint32_t pri_user_tag;
  uint32_t pri_pages_resident;
  uint32_t pri_pages_shared_now_private;
  uint32_t pri_pages_swapped_out;
  uint32_t pri_pages_dirtied;
  uint32_t pri_ref_count;
  uint32_t pri_shadow_depth;
  uint32_t pri_share_mode;
  uint32_t pri_private_pages_resident;
  uint32_t pri_shared_pages_resident;
  uint32_t pri_obj_id;
  uint32_t pri_depth;
  uint64_t pri_address;
  uint64_t pri_size;
};

struct proc_regionwithpathinfo
{
  struct proc_regioninfo prp_prinfo;
  struct vnode_info_path prp_vip;
};

#endif

extern int __proc_info (int callnum, int pid, int flavor, uint64_t arg,
    void * buffer, int buffersize);

static void gum_do_set_hardware_breakpoint (GumDarwinNativeDebugState * ds,
    gpointer user_data);
static void gum_do_unset_hardware_breakpoint (GumDarwinNativeDebugState * ds,
    gpointer user_data);
static void gum_do_set_hardware_watchpoint (GumDarwinNativeDebugState * ds,
    gpointer user_data);
static void gum_do_unset_hardware_watchpoint (GumDarwinNativeDebugState * ds,
    gpointer user_data);
static gboolean gum_modify_debug_registers (GumThreadId thread_id,
    GumModifyDebugRegistersFunc func, gpointer user_data, GError ** error);
static void gum_emit_malloc_ranges (task_t task,
    void * user_data, unsigned type, vm_range_t * ranges, unsigned count);
static kern_return_t gum_read_malloc_memory (task_t remote_task,
    vm_address_t remote_address, vm_size_t size, void ** local_memory);
#ifdef HAVE_I386
static void gum_deinit_sysroot (void);
#endif
static gboolean gum_probe_range_for_entrypoint (const GumRangeDetails * details,
    gpointer user_data);
static gboolean gum_store_range_of_potential_modules (
    const GumRangeDetails * details, gpointer user_data);
static gboolean gum_emit_modules_in_range (const GumMemoryRange * range,
    GumEnumerateModulesSlowContext * ctx);
static gboolean gum_emit_import (const GumImportDetails * details,
    gpointer user_data);
static GumAddress gum_resolve_export (const char * module_name,
    const char * symbol_name, gpointer user_data);
static gboolean gum_emit_export (const GumDarwinExportDetails * details,
    gpointer user_data);
static gboolean gum_emit_symbol (const GumDarwinSymbolDetails * details,
    gpointer user_data);
static gboolean gum_append_symbol_section (
    const GumDarwinSectionDetails * details, gpointer user_data);
static void gum_symbol_section_destroy (GumSymbolSection * self);
static gboolean gum_emit_section (const GumDarwinSectionDetails * details,
    gpointer user_data);

static gboolean find_image_address_and_slide (const gchar * image_name,
    gpointer * address, gpointer * slide);

static gchar * gum_canonicalize_module_name (const gchar * name);
static gboolean gum_store_module_path_if_module_name_matches (
    const GumModuleDetails * details, gpointer user_data);
static gboolean gum_module_path_equals (const gchar * path,
    const gchar * name_or_path);

static GumThreadState gum_thread_state_from_darwin (integer_t run_state);

static gboolean gum_darwin_fill_file_mapping (gint pid,
    mach_vm_address_t address, GumFileMapping * file,
    struct proc_regionwithpathinfo * region);
static void gum_darwin_clamp_range_size (GumMemoryRange * range,
    const GumFileMapping * file);

const gchar *
gum_process_query_libc_name (void)
{
  return "/usr/lib/libSystem.B.dylib";
}

gboolean
gum_process_is_debugger_attached (void)
{
  int mib[4];
  struct kinfo_proc info;
  size_t size;
  G_GNUC_UNUSED int result;

  mib[0] = CTL_KERN;
  mib[1] = KERN_PROC;
  mib[2] = KERN_PROC_PID;
  mib[3] = getpid ();

  size = sizeof (info);
  result = sysctl (mib, G_N_ELEMENTS (mib), &info, &size, NULL, 0);
  g_assert (result == 0);

  return (info.kp_proc.p_flag & P_TRACED) != 0;
}

GumProcessId
gum_process_get_id (void)
{
  return getpid ();
}

GumThreadId
gum_process_get_current_thread_id (void)
{
  return pthread_mach_thread_np (pthread_self ());
}

gboolean
gum_process_has_thread (GumThreadId thread_id)
{
  gboolean found = FALSE;
  mach_port_t task;
  thread_act_array_t threads;
  mach_msg_type_number_t count;
  kern_return_t kr;
  guint i;

  /*
   * We won't see the same Mach port name as the one that libpthread has,
   * so we need to special-case it. This also doubles as an optimization.
   */
  if (thread_id == gum_process_get_current_thread_id ())
    return TRUE;

  task = mach_task_self ();

  kr = task_threads (task, &threads, &count);
  if (kr != KERN_SUCCESS)
    goto beach;

  for (i = 0; i != count; i++)
  {
    if (threads[i] == thread_id)
    {
      found = TRUE;
      break;
    }
  }

  for (i = 0; i != count; i++)
    mach_port_deallocate (task, threads[i]);
  vm_deallocate (task, (vm_address_t) threads, count * sizeof (thread_t));

beach:
  return found;
}

gboolean
gum_process_modify_thread (GumThreadId thread_id,
                           GumModifyThreadFunc func,
                           gpointer user_data,
                           GumModifyThreadFlags flags)
{
  return gum_darwin_modify_thread (thread_id, func, user_data, flags);
}

void
_gum_process_enumerate_threads (GumFoundThreadFunc func,
                                gpointer user_data)
{
  gum_darwin_enumerate_threads (mach_task_self (), func, user_data);
}

gboolean
_gum_process_collect_main_module (const GumModuleDetails * details,
                                  gpointer user_data)
{
  GumModuleDetails ** out = user_data;
  gum_mach_header_t * header;

  header = GSIZE_TO_POINTER (details->range->base_address);
  if (header->filetype == MH_EXECUTE)
  {
    *out = gum_module_details_copy (details);

    return FALSE;
  }

  return TRUE;
}

void
_gum_process_enumerate_modules (GumFoundModuleFunc func,
                                gpointer user_data)
{
  gum_darwin_enumerate_modules (mach_task_self (), func, user_data);
}

void
_gum_process_enumerate_ranges (GumPageProtection prot,
                               GumFoundRangeFunc func,
                               gpointer user_data)
{
  gum_darwin_enumerate_ranges (mach_task_self (), prot, func, user_data);
}

void
gum_process_enumerate_malloc_ranges (GumFoundMallocRangeFunc func,
                                     gpointer user_data)
{
  task_t task;
  kern_return_t ret;
  unsigned i;
  vm_address_t * malloc_zone_addresses;
  unsigned malloc_zone_count;

  task = mach_task_self ();

  ret = malloc_get_all_zones (task,
      gum_read_malloc_memory, &malloc_zone_addresses,
      &malloc_zone_count);
  if (ret != KERN_SUCCESS)
    return;

  for (i = 0; i != malloc_zone_count; i++)
  {
    vm_address_t zone_address = malloc_zone_addresses[i];
    malloc_zone_t * zone = (malloc_zone_t *) zone_address;

    if (zone != NULL && zone->introspect != NULL &&
        zone->introspect->enumerator != NULL)
    {
      GumEnumerateMallocRangesContext ctx = { func, user_data, TRUE };

      zone->introspect->enumerator (task, &ctx,
          MALLOC_PTR_IN_USE_RANGE_TYPE, zone_address,
          gum_read_malloc_memory,
          gum_emit_malloc_ranges);

      if (!ctx.carry_on)
        return;
    }
  }
}

static void
gum_emit_malloc_ranges (task_t task,
                        void * user_data,
                        unsigned type,
                        vm_range_t * ranges,
                        unsigned count)
{
  GumEnumerateMallocRangesContext * ctx =
      (GumEnumerateMallocRangesContext *) user_data;
  GumMemoryRange gum_range;
  GumMallocRangeDetails details;
  unsigned i;

  if (!ctx->carry_on)
    return;

  details.range = &gum_range;

  for (i = 0; i != count; i++)
  {
    vm_range_t range = ranges[i];

    gum_range.base_address = range.address;
    gum_range.size = range.size;

    ctx->carry_on = ctx->func (&details, ctx->user_data);
    if (!ctx->carry_on)
      return;
  }
}

static kern_return_t
gum_read_malloc_memory (task_t remote_task,
                        vm_address_t remote_address,
                        vm_size_t size,
                        void ** local_memory)
{
  *local_memory = (void *) remote_address;

  return KERN_SUCCESS;
}

guint
gum_thread_try_get_ranges (GumMemoryRange * ranges,
                           guint max_length)
{
  pthread_t thread;
  uint64_t thread_id, real_thread_id;
  guint skew;
  GumMemoryRange * range;
  GumAddress stack_addr;
  size_t guard_size, stack_size;
  GumAddress stack_base;

  range = &ranges[0];

  thread = pthread_self ();

  thread_id = GUM_PTHREAD_GET_FIELD (thread,
      GUM_PTHREAD_FIELD_THREADID, uint64_t);
  pthread_threadid_np (thread, &real_thread_id);

  skew = (thread_id == real_thread_id) ? 0 : 8;

  range->base_address = GUM_ADDRESS (GUM_PTHREAD_GET_FIELD (thread,
      GUM_PTHREAD_FIELD_FREEADDR + skew, void *));
  range->size = GUM_PTHREAD_GET_FIELD (thread,
      GUM_PTHREAD_FIELD_FREESIZE + skew, size_t);

  if (max_length == 1)
    return 1;

  stack_addr = GUM_ADDRESS (GUM_PTHREAD_GET_FIELD (thread,
      GUM_PTHREAD_FIELD_STACKADDR + skew, void *));
  stack_size = pthread_get_stacksize_np (thread);
  guard_size = GUM_PTHREAD_GET_FIELD (thread,
      GUM_PTHREAD_FIELD_GUARDSIZE + skew, size_t);

  stack_base = stack_addr - stack_size - guard_size;

  if (stack_base == range->base_address)
    return 1;

  range = &ranges[1];

  range->base_address = stack_base;
  range->size = stack_addr - stack_base;

  return 2;
}

gint
gum_thread_get_system_error (void)
{
  return errno;
}

void
gum_thread_set_system_error (gint value)
{
  errno = value;
}

gboolean
gum_thread_suspend (GumThreadId thread_id,
                    GError ** error)
{
#ifdef HAVE_WATCHOS
  g_set_error (error,
      GUM_ERROR,
      GUM_ERROR_NOT_SUPPORTED,
      "Not supported");
  return FALSE;
#else
  kern_return_t kr;

  kr = thread_suspend (thread_id);
  if (kr != KERN_SUCCESS)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error,
        GUM_ERROR,
        GUM_ERROR_NOT_FOUND,
        "%s",
        mach_error_string (kr));
    return FALSE;
  }
#endif
}

gboolean
gum_thread_resume (GumThreadId thread_id,
                   GError ** error)
{
#ifdef HAVE_WATCHOS
  g_set_error (error,
      GUM_ERROR,
      GUM_ERROR_NOT_SUPPORTED,
      "Not supported");
  return FALSE;
#else
  kern_return_t kr;

  kr = thread_resume (thread_id);
  if (kr != KERN_SUCCESS)
    goto failure;

  return TRUE;

failure:
  {
    g_set_error (error,
        GUM_ERROR,
        GUM_ERROR_NOT_FOUND,
        "%s",
        mach_error_string (kr));
    return FALSE;
  }
#endif
}

gboolean
gum_thread_set_hardware_breakpoint (GumThreadId thread_id,
                                    guint breakpoint_id,
                                    GumAddress address,
                                    GError ** error)
{
  GumSetHardwareBreakpointContext bpc;

  bpc.breakpoint_id = breakpoint_id;
  bpc.address = address;

  return gum_modify_debug_registers (thread_id, gum_do_set_hardware_breakpoint,
      &bpc, error);
}

static void
gum_do_set_hardware_breakpoint (GumDarwinNativeDebugState * ds,
                                gpointer user_data)
{
  GumSetHardwareBreakpointContext * bpc = user_data;

#ifdef HAVE_ARM64
  _gum_arm64_set_breakpoint (ds->__bcr, ds->__bvr, bpc->breakpoint_id,
      bpc->address);
#else
  _gum_x86_set_breakpoint ((gsize *) &ds->__dr7, (gsize *) &ds->__dr0,
      bpc->breakpoint_id, bpc->address);
#endif
}

gboolean
gum_thread_unset_hardware_breakpoint (GumThreadId thread_id,
                                      guint breakpoint_id,
                                      GError ** error)
{
  return gum_modify_debug_registers (thread_id,
      gum_do_unset_hardware_breakpoint, GUINT_TO_POINTER (breakpoint_id),
      error);
}

static void
gum_do_unset_hardware_breakpoint (GumDarwinNativeDebugState * ds,
                                  gpointer user_data)
{
  guint breakpoint_id = GPOINTER_TO_UINT (user_data);

#ifdef HAVE_ARM64
  _gum_arm64_unset_breakpoint (ds->__bcr, ds->__bvr, breakpoint_id);
#else
  _gum_x86_unset_breakpoint ((gsize *) &ds->__dr7, (gsize *) &ds->__dr0,
      breakpoint_id);
#endif
}

gboolean
gum_thread_set_hardware_watchpoint (GumThreadId thread_id,
                                    guint watchpoint_id,
                                    GumAddress address,
                                    gsize size,
                                    GumWatchConditions wc,
                                    GError ** error)
{
  GumSetHardwareWatchpointContext wpc;

  wpc.watchpoint_id = watchpoint_id;
  wpc.address = address;
  wpc.size = size;
  wpc.conditions = wc;

  return gum_modify_debug_registers (thread_id, gum_do_set_hardware_watchpoint,
      &wpc, error);
}

static void
gum_do_set_hardware_watchpoint (GumDarwinNativeDebugState * ds,
                                gpointer user_data)
{
  GumSetHardwareWatchpointContext * wpc = user_data;

#if defined (HAVE_ARM64)
  _gum_arm64_set_watchpoint (ds->__wcr, ds->__wvr, wpc->watchpoint_id,
      wpc->address, wpc->size, wpc->conditions);
#else
  _gum_x86_set_watchpoint ((gsize *) &ds->__dr7, (gsize *) &ds->__dr0,
      wpc->watchpoint_id, wpc->address, wpc->size, wpc->conditions);
#endif
}

gboolean
gum_thread_unset_hardware_watchpoint (GumThreadId thread_id,
                                      guint watchpoint_id,
                                      GError ** error)
{
  return gum_modify_debug_registers (thread_id,
      gum_do_unset_hardware_watchpoint, GUINT_TO_POINTER (watchpoint_id),
      error);
}

static void
gum_do_unset_hardware_watchpoint (GumDarwinNativeDebugState * ds,
                                  gpointer user_data)
{
  guint watchpoint_id = GPOINTER_TO_UINT (user_data);

#if defined (HAVE_ARM64)
  _gum_arm64_unset_watchpoint (ds->__wcr, ds->__wvr, watchpoint_id);
#else
  _gum_x86_unset_watchpoint ((gsize *) &ds->__dr7, (gsize *) &ds->__dr0,
      watchpoint_id);
#endif
}

static gboolean
gum_modify_debug_registers (GumThreadId thread_id,
                            GumModifyDebugRegistersFunc func,
                            gpointer user_data,
                            GError ** error)
{
#ifdef HAVE_WATCHOS
  g_set_error (error,
      GUM_ERROR,
      GUM_ERROR_NOT_SUPPORTED,
      "Not supported");
  return FALSE;
#else
  gboolean success = FALSE;
  kern_return_t kr;
  GumDarwinNativeDebugState state;
  mach_msg_type_number_t state_count = GUM_DARWIN_DEBUG_STATE_COUNT;
  thread_state_flavor_t state_flavor = GUM_DARWIN_DEBUG_STATE_FLAVOR;

  kr = thread_get_state (thread_id, state_flavor, (thread_state_t) &state,
      &state_count);
  if (kr != KERN_SUCCESS)
    goto failure;

  func (&state, user_data);

  kr = thread_set_state (thread_id, state_flavor, (thread_state_t) &state,
      state_count);
  if (kr != KERN_SUCCESS)
    goto failure;

  success = TRUE;
  goto beach;

failure:
  {
    g_set_error (error,
        GUM_ERROR,
        GUM_ERROR_FAILED,
        "Unable to modify debug registers: %s", mach_error_string (kr));
    goto beach;
  }
beach:
  {
    return success;
  }
#endif
}

gboolean
gum_module_load (const gchar * module_name,
                 GError ** error)
{
  if (dlopen (module_name, RTLD_LAZY) == NULL)
    goto not_found;

  return TRUE;

not_found:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_FOUND, "%s", dlerror ());
    return FALSE;
  }
}

gboolean
gum_module_ensure_initialized (const gchar * module_name)
{
  gboolean success;
  gchar * name;
  void * module;

  success = FALSE;

  name = gum_canonicalize_module_name (module_name);
  if (name == NULL)
    goto beach;

  module = dlopen (name, RTLD_LAZY | RTLD_NOLOAD);
  if (module == NULL)
    goto beach;
  dlclose (module);

  module = dlopen (name, RTLD_LAZY);
  if (module == NULL)
    goto beach;
  dlclose (module);

  success = TRUE;

beach:
  g_free (name);

  return success;
}

void
gum_module_enumerate_imports (const gchar * module_name,
                              GumFoundImportFunc func,
                              gpointer user_data)
{
  return gum_darwin_enumerate_imports (mach_task_self (), module_name, func,
      user_data);
}

void
gum_module_enumerate_exports (const gchar * module_name,
                              GumFoundExportFunc func,
                              gpointer user_data)
{
  return gum_darwin_enumerate_exports (mach_task_self (), module_name, func,
      user_data);
}

void
gum_module_enumerate_symbols (const gchar * module_name,
                              GumFoundSymbolFunc func,
                              gpointer user_data)
{
  return gum_darwin_enumerate_symbols (mach_task_self (), module_name, func,
      user_data);
}

void
gum_module_enumerate_ranges (const gchar * module_name,
                             GumPageProtection prot,
                             GumFoundRangeFunc func,
                             gpointer user_data)
{
  gpointer address, slide;
  gint pid;
  gum_mach_header_t * header;
  guint8 * p;
  guint cmd_index;

  if (!find_image_address_and_slide (module_name, &address, &slide))
    return;

  pid = getpid ();

  header = address;
  p = (guint8 *) (header + 1);
  for (cmd_index = 0; cmd_index != header->ncmds; cmd_index++)
  {
    struct load_command * lc = (struct load_command *) p;

    if (lc->cmd == GUM_LC_SEGMENT)
    {
      gum_segment_command_t * segcmd = (gum_segment_command_t *) lc;
      gboolean is_page_zero;
      GumPageProtection cur_prot;

      is_page_zero = segcmd->vmaddr == 0 &&
          segcmd->filesize == 0 &&
          segcmd->vmsize != 0 &&
          (segcmd->initprot & VM_PROT_ALL) == VM_PROT_NONE &&
          (segcmd->maxprot & VM_PROT_ALL) == VM_PROT_NONE;
      if (is_page_zero)
      {
        p += lc->cmdsize;
        continue;
      }

      cur_prot = gum_page_protection_from_mach (segcmd->initprot);

      if ((cur_prot & prot) == prot)
      {
        GumMemoryRange range;
        GumRangeDetails details;
        GumFileMapping file;
        struct proc_regionwithpathinfo region;

        range.base_address = GUM_ADDRESS (
            GSIZE_TO_POINTER (segcmd->vmaddr) + GPOINTER_TO_SIZE (slide));
        range.size = segcmd->vmsize;

        details.range = &range;
        details.protection = cur_prot;
        details.file = NULL;

        if (pid != 0 && gum_darwin_fill_file_mapping (pid, range.base_address,
            &file, &region))
        {
          details.file = &file;
          gum_darwin_clamp_range_size (&range, &file);
        }

        if (!func (&details, user_data))
          return;
      }
    }

    p += lc->cmdsize;
  }
}

void
gum_module_enumerate_sections (const gchar * module_name,
                               GumFoundSectionFunc func,
                               gpointer user_data)
{
  gum_darwin_enumerate_sections (mach_task_self (), module_name, func,
      user_data);
}

void
gum_module_enumerate_dependencies (const gchar * module_name,
                                   GumFoundDependencyFunc func,
                                   gpointer user_data)
{
  gum_darwin_enumerate_dependencies (mach_task_self (), module_name, func,
      user_data);
}

GumAddress
gum_module_find_base_address (const gchar * module_name)
{
  gpointer address, slide;

  if (!find_image_address_and_slide (module_name, &address, &slide))
    return 0;

  return GUM_ADDRESS (address);
}

GumAddress
gum_module_find_export_by_name (const gchar * module_name,
                                const gchar * symbol_name)
{
  GumAddress result;
  void * module;

  if (module_name != NULL)
  {
    gchar * name;

    name = gum_canonicalize_module_name (module_name);
    if (name == NULL)
      return 0;

#ifndef GUM_DIET
    if (g_str_has_prefix (name, "/usr/lib/dyld"))
    {
      GumDarwinModuleResolver * resolver;
      GumDarwinModule * dm;

      resolver = gum_darwin_module_resolver_new (mach_task_self (), NULL);
      g_assert (resolver != NULL);

      dm = gum_darwin_module_resolver_find_module (resolver, name);
      if (dm != NULL)
      {
        result = gum_darwin_module_resolver_find_export_address (resolver, dm,
            symbol_name);
      }
      else
      {
        result = 0;
      }

      g_object_unref (resolver);

      g_free (name);

      return result;
    }
#endif

    module = dlopen (name, RTLD_LAZY | RTLD_NOLOAD);

    g_free (name);
  }
  else
  {
    module = RTLD_DEFAULT;
  }

  result = GUM_ADDRESS (dlsym (module, symbol_name));

  if (module != RTLD_DEFAULT)
    dlclose (module);

  return result;
}

gboolean
gum_darwin_check_xnu_version (guint major,
                              guint minor,
                              guint micro)
{
  static gboolean initialized = FALSE;
  static guint xnu_major = G_MAXUINT;
  static guint xnu_minor = G_MAXUINT;
  static guint xnu_micro = G_MAXUINT;

  if (!initialized)
  {
    char buf[256] = { 0, };
    size_t size;
    G_GNUC_UNUSED int res;
    const char * version_str;

    size = sizeof (buf);
    res = sysctlbyname ("kern.version", buf, &size, NULL, 0);
    g_assert (res == 0);

    version_str = strstr (buf, "xnu-");
    if (version_str != NULL)
    {
      version_str += 4;
      sscanf (version_str, "%u.%u.%u", &xnu_major, &xnu_minor, &xnu_micro);
    }

    initialized = TRUE;
  }

  if (xnu_major > major)
    return TRUE;

  if (xnu_major == major && xnu_minor > minor)
    return TRUE;

  return xnu_major == major && xnu_minor == minor && xnu_micro >= micro;
}

gboolean
gum_darwin_cpu_type_from_pid (pid_t pid,
                              GumCpuType * cpu_type)
{
  int mib[4] = { CTL_KERN, KERN_PROC, KERN_PROC_PID, pid };
  struct kinfo_proc kp;
  size_t bufsize = sizeof (kp);
  int err;

  memset (&kp, 0, sizeof (kp));
  err = sysctl (mib, G_N_ELEMENTS (mib), &kp, &bufsize, NULL, 0);
  if (err != 0)
    return FALSE;

#ifdef HAVE_I386
  *cpu_type = (kp.kp_proc.p_flag & P_LP64) ? GUM_CPU_AMD64 : GUM_CPU_IA32;
#else
  *cpu_type = (kp.kp_proc.p_flag & P_LP64) ? GUM_CPU_ARM64 : GUM_CPU_ARM;
#endif
  return TRUE;
}

#ifdef HAVE_I386

const gchar *
gum_darwin_query_sysroot (void)
{
  static gsize cached_result = 0;

  if (g_once_init_enter (&cached_result))
  {
    gchar * result = NULL;
    const gchar * program_path;

    program_path = _dyld_get_image_name (0);

    if (g_str_has_suffix (program_path, "/usr/lib/dyld_sim"))
    {
      result = g_strndup (program_path, strlen (program_path) - 17);
      _gum_register_destructor (gum_deinit_sysroot);
    }

    g_once_init_leave (&cached_result, GPOINTER_TO_SIZE (result) + 1);
  }

  return GSIZE_TO_POINTER (cached_result - 1);
}

static void
gum_deinit_sysroot (void)
{
  g_free ((gchar *) gum_darwin_query_sysroot ());
}

#else

const gchar *
gum_darwin_query_sysroot (void)
{
  return NULL;
}

#endif

gboolean
gum_darwin_query_hardened (void)
{
  static gsize cached_result = 0;

  if (g_once_init_enter (&cached_result))
  {
    const gchar * program_path;
    guint i;
    gboolean is_hardened;

    for (program_path = NULL, i = 0; program_path == NULL; i++)
    {
      if (_dyld_get_image_header (i)->filetype == MH_EXECUTE)
        program_path = _dyld_get_image_name (i);
    }

    is_hardened = strcmp (program_path, "/sbin/launchd") == 0 ||
        g_str_has_prefix (program_path, "/usr/libexec/") ||
        g_str_has_prefix (program_path, "/System/") ||
        g_str_has_prefix (program_path, "/Developer/");

    g_once_init_leave (&cached_result, is_hardened + 1);
  }

  return cached_result - 1;
}

gboolean
gum_darwin_query_all_image_infos (mach_port_t task,
                                  GumDarwinAllImageInfos * infos)
{
  struct task_dyld_info info;
  mach_msg_type_number_t count;
  kern_return_t kr;
  gboolean inprocess;

  bzero (infos, sizeof (GumDarwinAllImageInfos));

#if defined (HAVE_ARM) || defined (HAVE_ARM64)
  DyldInfo info_raw;
  count = DYLD_INFO_COUNT;
  kr = task_info (task, TASK_DYLD_INFO, (task_info_t) &info_raw, &count);
  if (kr != KERN_SUCCESS)
    return FALSE;
  switch (count)
  {
    case DYLD_INFO_LEGACY_COUNT:
      info.all_image_info_addr = info_raw.info_legacy.all_image_info_addr;
      info.all_image_info_size = 0;
      info.all_image_info_format = TASK_DYLD_ALL_IMAGE_INFO_32;
      break;
    case DYLD_INFO_32_COUNT:
      info.all_image_info_addr = info_raw.info_32.all_image_info_addr;
      info.all_image_info_size = info_raw.info_32.all_image_info_size;
      info.all_image_info_format = info_raw.info_32.all_image_info_format;
      break;
    case DYLD_INFO_64_COUNT:
      info.all_image_info_addr = info_raw.info_64.all_image_info_addr;
      info.all_image_info_size = info_raw.info_64.all_image_info_size;
      info.all_image_info_format = info_raw.info_64.all_image_info_format;
      break;
    default:
      g_assert_not_reached ();
  }
#else
  count = TASK_DYLD_INFO_COUNT;
  kr = task_info (task, TASK_DYLD_INFO, (task_info_t) &info, &count);
  if (kr != KERN_SUCCESS)
```