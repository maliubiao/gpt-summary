Response:
The user is asking for a functional overview of the provided C source code file, `gumdarwinmapper.c`. The request specifically asks for:

1. **Functionality Listing:** A summary of what the code does.
2. **Relevance to Reverse Engineering:**  Examples of how the code relates to reverse engineering techniques.
3. **Low-Level Details:**  Explanation of its interaction with binary, Linux/Android kernels/frameworks.
4. **Logical Inference:**  Hypothetical input/output examples if the code performs logical reasoning.
5. **Common Usage Errors:**  Examples of mistakes users or programmers might make when interacting with this code.
6. **User Operation to Reach This Code:**  A step-by-step explanation of how a user might end up executing this code during debugging.
7. **Overall Functional Summary (Part 1):**  A concise summary of the code's function, as this is the first of a three-part request.

**Mental Model:**

This code seems to be part of Frida's core functionality for instrumenting Darwin-based systems (macOS, iOS, etc.). The filename "mapper" suggests it's responsible for mapping dynamic libraries (dylibs) into a process's memory space. This mapping likely involves replicating the dylib's structure, resolving dependencies, and handling relocations.

**Plan:**

1. **High-Level Functionality:** Identify the primary goal of the file (mapping dylibs).
2. **Key Data Structures:**  Note the important structs like `GumDarwinMapper`, `GumDarwinMapping`, and their roles.
3. **Key Functions:**  Focus on functions like `gum_darwin_mapper_map`, `gum_darwin_mapper_load`, and functions related to resolving symbols and dependencies.
4. **Reverse Engineering Relevance:**  Connect the functionality to common reverse engineering tasks like analyzing library dependencies, understanding memory layout, and examining symbol resolution.
5. **Low-Level Details:**  Highlight the interaction with `mach_vm_*` functions, indicating direct system calls related to memory management on Darwin.
6. **Logical Inference:**  Consider if any functions perform conditional logic based on data within the dylib (e.g., handling different load commands). If so, create a simple hypothetical example.
7. **Usage Errors:** Think about potential misconfigurations or incorrect inputs when using the Frida API that might lead to issues within this code.
8. **User Journey:** Trace back how a Frida user might initiate a script that eventually triggers the dylib mapping process.
9. **Concise Summary:**  Synthesize the key functionalities into a short summary for Part 1.
This C source code file, `gumdarwinmapper.c`, is a crucial component of Frida responsible for **dynamically mapping Darwin (macOS, iOS, etc.) Mach-O executable files (like dynamic libraries - dylibs) into a target process's memory**. It handles the complex process of loading a dylib, resolving its dependencies, and preparing it for execution within the context of the instrumented process.

Here's a breakdown of its functionalities:

**Core Functionalities:**

1. **Loading and Parsing Mach-O Files:**
   - It takes a path to a Mach-O file or a memory blob representing one.
   - It uses `GumDarwinModule` (likely another Frida component) to parse the Mach-O structure, extracting information like segments, sections, dependencies, symbols, and relocation information.

2. **Managing Dependencies:**
   - It tracks the dependencies of a loaded dylib.
   - It recursively loads and maps these dependencies.
   - It ensures that dependencies are loaded in the correct order.

3. **Memory Allocation and Mapping:**
   - It calculates the total memory footprint required for the dylib and its runtime support structures.
   - It uses Mach kernel API calls (like `mach_vm_allocate`, `mach_vm_remap`, `mach_vm_protect`, `mach_vm_write`) to allocate and map memory regions in the target process.
   - It handles the mapping of code and data segments with appropriate memory protection attributes (read, write, execute).

4. **Relocation and Binding:**
   - It processes relocation entries within the Mach-O file to adjust addresses based on the actual load address in memory.
   - It handles both regular and "chained" fixups (a more modern form of relocation).
   - It resolves external symbols by looking them up in already loaded libraries or using a resolver component (`GumDarwinModuleResolver`).
   - It supports both direct binding and lazy binding of symbols.

5. **Thread-Local Storage (TLS) Management:**
   - It handles the initialization of thread-local variables.
   - It interacts with the `libsystem_pthread` library to manage thread keys.

6. **Runtime Code Generation:**
   - It dynamically generates a small runtime code block that handles tasks like:
     - Calling constructors and destructors of the dylib.
     - Processing chained fixups and threaded binds.

7. **Caching and Budgeting:**
   - It keeps track of the memory footprint of mapped dylibs.
   - It might implement some form of budgeting or caching to optimize the mapping process.

**Relationship to Reverse Engineering:**

This code is fundamental to many dynamic reverse engineering techniques employed by tools like Frida. Here are some examples:

* **Dynamic Library Analysis:** Reverse engineers often want to understand how a specific dynamic library works. Frida uses this code to load the library into memory, allowing for inspection of its code, data, and interactions with other libraries in real-time.
    * **Example:** A reverse engineer might use Frida to load a custom dylib into a running application to inject malicious code or intercept function calls. `gumdarwinmapper.c` is responsible for making this loading possible.
* **Function Hooking/Interception:**  To hook a function in a dylib, Frida needs to know the function's address in the target process's memory. This code establishes the memory layout of the dylib, making it possible to calculate and locate function addresses for hooking.
    * **Example:** A security researcher might use Frida to hook a sensitive API call within a system library to monitor its arguments and return values. `gumdarwinmapper.c` ensures that the system library is loaded and its functions are addressable.
* **Understanding Memory Layout:** By observing how Frida maps libraries, reverse engineers can gain insights into the target process's memory organization, including the base addresses of libraries and the layout of their segments.
    * **Example:** When analyzing a crash dump, knowing the loading addresses of libraries (as managed by `gumdarwinmapper.c`) is crucial for understanding the context of the crash.
* **Analyzing Relocations and Bindings:**  The relocation and binding processes handled by this code are core concepts in understanding how dynamic linking works. Reverse engineers analyzing a compiled binary will often need to understand these processes.
    * **Example:** If a reverse engineer encounters an indirect function call, understanding how the symbol is resolved (a process managed by this code) is key to determining the actual target of the call.

**Involvement of Binary 底层, Linux, Android 内核及框架的知识:**

While this code is specifically for Darwin (macOS, iOS), it touches upon general concepts relevant to binary manipulation and operating system kernels:

* **Binary 底层 (Binary Low-Level):**
    - **Mach-O Format:** The code directly interacts with the Mach-O binary format, parsing headers, load commands, segments, sections, and relocation tables. This requires a deep understanding of the binary's structure.
    - **Relocations:** The code implements logic to process relocation entries, which are instructions within the binary that tell the loader how to adjust addresses at runtime. Understanding different relocation types is crucial.
    - **Code and Data Segments:** The code differentiates between code and data segments and applies appropriate memory protections, demonstrating an understanding of how executables are structured in memory.
* **Darwin Kernel:**
    - **Mach Virtual Memory API:** The code heavily relies on the Mach kernel's virtual memory management API (`mach_vm_*`). This includes allocating memory (`mach_vm_allocate`), mapping files into memory (`mach_vm_remap`), changing memory protections (`mach_vm_protect`), and writing data to memory (`mach_vm_write`).
    - **Task Management:** The `resolver->task` likely refers to the Mach task port of the target process, allowing Frida to perform memory operations within that process's address space.
* **Linux/Android (Conceptual Overlap):** While not directly using Linux/Android APIs, the concepts are similar:
    - **Dynamic Linking:** The general principles of dynamic linking (resolving dependencies, relocating code) are shared across operating systems. On Linux, this would involve ELF files and calls like `mmap`. On Android, it involves the ELF format and the Android linker (`linker`).
    - **Virtual Memory Management:**  All modern operating systems have a virtual memory system, and the core tasks of allocating, mapping, and protecting memory are universal, though the specific API calls differ.

**Logical Inference (Hypothetical Input & Output):**

Let's consider the `gum_darwin_mapper_resolve_import` function (even though the full implementation isn't shown, we can infer its purpose).

**Hypothetical Input:**

* `self`: A `GumDarwinMapper` object representing a dylib being loaded (e.g., `MyLib.dylib`).
* `library_ordinal`: An integer representing the index of a dependency (e.g., `0` for the first dependency).
* `symbol_name`: The name of a symbol to resolve (e.g., `_some_function`).
* `is_weak`: A boolean indicating if the import is weak (e.g., `FALSE`).

**Logical Inference:**

The function would likely perform the following logic:

1. **Find the Dependency:** Look up the dependency based on the `library_ordinal`.
2. **Search for Symbol:** Search for the `symbol_name` within the exports of the dependency.
3. **Handle Weak Imports:** If `is_weak` is `TRUE` and the symbol is not found, the function might return success but with an address of `0`.
4. **Return Address:** If the symbol is found, return the address of the symbol within the dependency's mapped memory.

**Hypothetical Output:**

* **Success Case:** If `_some_function` exists in the dependency, the function might return `TRUE` and set the `value->address` to the resolved address of `_some_function`.
* **Failure Case:** If the dependency isn't found or `_some_function` doesn't exist (and it's not a weak import), the function might return `FALSE` and set an error.

**User or Programming Common Usage Errors:**

While users don't directly interact with this low-level code, incorrect usage of the Frida API can lead to issues that manifest within this component:

* **Incorrect Dependency Handling:** If a Frida script attempts to manually load a library without respecting its dependencies, it might bypass the proper loading sequence managed by `gumdarwinmapper.c`, leading to unresolved symbols or crashes.
    * **Example:** A user might try to `dlopen` a dylib from within a Frida script without ensuring its dependencies are also loaded. This might cause issues when `gumdarwinmapper.c` later tries to resolve symbols from those missing dependencies.
* **Memory Conflicts:** If a Frida script allocates memory at addresses that conflict with the memory regions allocated by `gumdarwinmapper.c`, it can lead to unpredictable behavior or crashes.
* **Manipulating Memory Directly Without Frida's Mechanisms:**  Trying to manually map or unmap memory regions that Frida is managing can create inconsistencies and lead to errors within this mapping logic.

**User Operation Steps to Reach This Code (Debugging Context):**

1. **User Writes a Frida Script:** A user starts by writing a Frida script to instrument an application on macOS or iOS. This script might involve:
   - Attaching to a running process or spawning a new process.
   - Using `Module.load()` to load a specific dynamic library.
   - Using `Interceptor.attach()` to hook functions within a dynamic library.
2. **Frida Processes the Script:** Frida's core runtime interprets the user's script.
3. **`Module.load()` is Called:** When the script calls `Module.load()`, Frida needs to load the specified dylib into the target process.
4. **`GumDarwinModuleResolver` is Involved:** Frida's module resolver component (`GumDarwinModuleResolver`) is used to locate the dylib on the file system or in memory.
5. **`gum_darwin_mapper_new_from_file` is Called:**  The `GumDarwinMapper` object is created, likely using `gum_darwin_mapper_new_from_file`, to manage the loading of the dylib.
6. **`gum_darwin_mapper_load` is Called:** This function is invoked to process the dylib's dependencies.
7. **`gum_darwin_mapper_map` is Called:**  The core mapping logic is initiated with `gum_darwin_mapper_map`, which allocates memory, maps segments, and performs relocations. This is where the majority of the code in this file is executed.
8. **Relocation and Binding within `gum_darwin_mapper_map`:** During the `gum_darwin_mapper_map` execution, functions like `gum_darwin_mapper_resolve_import`, and the processing of chained fixups and binds are performed, potentially executing the logical inference steps described earlier.
9. **Hooking with `Interceptor.attach()`:** Once the dylib is mapped, when `Interceptor.attach()` is called, Frida can now calculate the address of the function to be hooked within the mapped memory region.

**Summary of Functionality (Part 1):**

In summary, the `gumdarwinmapper.c` file in Frida is responsible for the essential task of **dynamically loading and mapping Mach-O dynamic libraries into the memory space of a target process on Darwin-based systems**. It handles dependency resolution, memory allocation using Mach kernel APIs, and the complex processes of relocation and binding, preparing the dylib for execution and enabling Frida's dynamic instrumentation capabilities. It's a low-level component deeply involved with the binary format and operating system kernel.

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gumdarwinmapper.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
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
 * Copyright (C) 2015-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Fabian Freyer <fabian.freyer@physik.tu-berlin.de>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gum/gumdarwinmapper.h"

#include "gum/gumdarwin.h"
#include "gumdarwinmodule.h"
#include "helpers/fixupchainprocessor.h"

#include <dlfcn.h>
#include <string.h>
#ifdef HAVE_I386
# include <gum/arch-x86/gumx86writer.h>
#else
# include <gum/arch-arm/gumthumbwriter.h>
# include <gum/arch-arm64/gumarm64writer.h>
#endif

#define GUM_MAPPER_HEADER_BASE_SIZE         64
#define GUM_MAPPER_CODE_BASE_SIZE           80
#define GUM_MAPPER_DEPENDENCY_SIZE          32
#define GUM_MAPPER_CHAINED_FIXUP_CALL_SIZE  64
#define GUM_MAPPER_THREADED_BINDS_CALL_SIZE 64
#define GUM_MAPPER_RESOLVER_SIZE            40
#define GUM_MAPPER_INIT_SIZE               128
#define GUM_MAPPER_TERM_SIZE                64
#define GUM_MAPPER_INIT_TLV_SIZE           196

#define GUM_CHECK_MACH_RESULT(n1, cmp, n2, op) \
    if (!(n1 cmp n2)) \
    { \
      failed_operation = op; \
      goto mach_failure; \
    }

typedef struct _GumDarwinMapping GumDarwinMapping;
typedef struct _GumDarwinSymbolValue GumDarwinSymbolValue;

typedef struct _GumAccumulateFootprintContext GumAccumulateFootprintContext;

typedef struct _GumMapContext GumMapContext;

typedef struct _GumLibdyldDyld4Section32 GumLibdyldDyld4Section32;
typedef struct _GumLibdyldDyld4Section64 GumLibdyldDyld4Section64;

struct _GumDarwinMapper
{
  GObject object;

  gchar * name;
  GumDarwinModule * module;
  GumDarwinModuleImage * image;
  GumDarwinModuleResolver * resolver;
  GumDarwinMapper * parent;

  gboolean mapped;
  GPtrArray * dependencies;
  GPtrArray * apple_parameters;

  gsize vm_size;
  gpointer runtime;
  GumAddress runtime_address;
  GumAddress empty_strv;
  GumAddress apple_strv;
  GumAddress process_chained_fixups;
  GumAddress chained_symbols_vector;
  GumAddress tlv_get_addr_addr;
  GumAddress tlv_area;
  GumAddress pthread_key;
  GumAddress pthread_key_create;
  GumAddress pthread_key_delete;
  gsize runtime_vm_size;
  gsize runtime_file_size;
  gsize runtime_header_size;
  gsize constructor_offset;
  gsize destructor_offset;
  guint chained_fixups_count;
  GumMemoryRange shared_cache_range;
  GumDarwinTlvParameters tlv;

  GArray * chained_symbols;
  GArray * threaded_symbols;
  GArray * threaded_regions;

  GSList * children;
  GHashTable * mappings;
};

enum
{
  PROP_0,
  PROP_NAME,
  PROP_MODULE,
  PROP_RESOLVER,
  PROP_PARENT
};

struct _GumDarwinMapping
{
  gint ref_count;
  GumDarwinModule * module;
  GumDarwinMapper * mapper;
};

struct _GumDarwinSymbolValue
{
  GumAddress address;
  GumAddress resolver;
};

struct _GumAccumulateFootprintContext
{
  GumDarwinMapper * mapper;
  gsize total;
  guint chained_fixups_count;
  guint chained_imports_count;
  guint threaded_regions_count;
};

struct _GumMapContext
{
  GumDarwinMapper * mapper;
  gboolean success;
  GError ** error;
};

struct _GumLibdyldDyld4Section32
{
  guint32 apis;
  guint32 all_image_infos;
  guint32 default_vars[5];
  guint32 dyld_lookup_func_addr;
  guint32 tlv_get_addr_addr;
};

struct _GumLibdyldDyld4Section64
{
  guint64 apis;
  guint64 all_image_infos;
  guint64 default_vars[5];
  guint64 dyld_lookup_func_addr;
  guint64 tlv_get_addr_addr;
};

static void gum_darwin_mapper_constructed (GObject * object);
static void gum_darwin_mapper_finalize (GObject * object);
static void gum_darwin_mapper_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_darwin_mapper_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);

static GumDarwinMapper * gum_darwin_mapper_new_from_file_with_parent (
    GumDarwinMapper * parent, const gchar * path,
    GumDarwinModuleResolver * resolver, GError ** error);
static gsize gum_darwin_mapper_get_footprint_budget (GumDarwinMapper * self);
static void gum_darwin_mapper_discard_footprint_budget (GumDarwinMapper * self);
static void gum_darwin_mapper_init_footprint_budget (GumDarwinMapper * self);
static GumAddress gum_darwin_mapper_make_code_address (GumDarwinMapper * self,
    GumAddress value);

static void gum_darwin_mapper_alloc_and_emit_runtime (GumDarwinMapper * self,
    GumAddress base_address, gsize size);
static void gum_emit_runtime (GumDarwinMapper * self, gpointer output_buffer,
    GumAddress pc, gsize * size);
static gboolean gum_accumulate_chained_fixups_size (
    const GumDarwinChainedFixupsDetails * details, gpointer user_data);
static gboolean gum_accumulate_bind_footprint_size (
    const GumDarwinBindDetails * details, gpointer user_data);
static void gum_accumulate_bind_pointer_footprint_size (
    GumAccumulateFootprintContext * ctx, const GumDarwinBindDetails * details);
static void gum_accumulate_bind_threaded_table_footprint_size (
    GumAccumulateFootprintContext * ctx, const GumDarwinBindDetails * details);
static void gum_accumulate_bind_threaded_items_footprint_size (
    GumAccumulateFootprintContext * ctx, const GumDarwinBindDetails * details);
static gboolean gum_accumulate_init_pointers_footprint_size (
    const GumDarwinInitPointersDetails * details, gpointer user_data);
static gboolean gum_accumulate_init_offsets_footprint_size (
    const GumDarwinInitOffsetsDetails * details, gpointer user_data);
static gboolean gum_accumulate_term_footprint_size (
    const GumDarwinTermPointersDetails * details, gpointer user_data);

static gpointer gum_darwin_mapper_data_from_offset (GumDarwinMapper * self,
    guint64 offset, guint size);
static GumDarwinMapping * gum_darwin_mapper_get_dependency_by_ordinal (
    GumDarwinMapper * self, gint ordinal, GError ** error);
static GumDarwinMapping * gum_darwin_mapper_get_dependency_by_name (
    GumDarwinMapper * self, const gchar * name, GError ** error);
static gboolean gum_darwin_mapper_resolve_import (GumDarwinMapper * self,
    gint library_ordinal, const gchar * symbol_name, gboolean is_weak,
    GumDarwinSymbolValue * value, GError ** error);
static gboolean gum_darwin_mapper_resolve_symbol (GumDarwinMapper * self,
    GumDarwinModule * module, const gchar * symbol,
    GumDarwinSymbolValue * value);
static GumDarwinMapping * gum_darwin_mapper_add_existing_mapping (
    GumDarwinMapper * self, GumDarwinModule * module);
static GumDarwinMapping * gum_darwin_mapper_add_pending_mapping (
    GumDarwinMapper * self, const gchar * name, GumDarwinMapper * mapper);
static GumDarwinMapping * gum_darwin_mapper_add_alias_mapping (
    GumDarwinMapper * self, const gchar * name, const GumDarwinMapping * to);
static gboolean gum_darwin_mapper_resolve_chained_imports (
    const GumDarwinChainedFixupsDetails * details, gpointer user_data);
static gboolean gum_darwin_mapper_append_chained_symbol (GumDarwinMapper * self,
    gint library_ordinal, const gchar * symbol_name, gboolean is_weak,
    gint64 addend, GError ** error);
static gboolean gum_darwin_mapper_rebase (
    const GumDarwinRebaseDetails * details, gpointer user_data);
static gboolean gum_darwin_mapper_bind (const GumDarwinBindDetails * details,
    gpointer user_data);
static gboolean gum_darwin_mapper_bind_pointer (GumDarwinMapper * self,
    const GumDarwinBindDetails * bind, GError ** error);
static gboolean gum_darwin_mapper_bind_table (GumDarwinMapper * self,
    const GumDarwinBindDetails * bind, GError ** error);
static gboolean gum_darwin_mapper_bind_items (GumDarwinMapper * self,
    const GumDarwinBindDetails * bind, GError ** error);

static void gum_darwin_mapping_free (GumDarwinMapping * self);

static gboolean gum_find_tlv_get_addr (const GumDarwinSectionDetails * details,
    gpointer user_data);

G_DEFINE_TYPE (GumDarwinMapper, gum_darwin_mapper, G_TYPE_OBJECT)

#if defined (HAVE_ARM) || defined (HAVE_ARM64)
/* Compiled from helpers/threadedbindprocessor.c */
const guint32 gum_threaded_bind_processor_code[] = {
  0xd2800008U, 0x2a0403e9U, 0xeb09011fU, 0x54000620U, 0xf86878aaU, 0xf940014bU,
  0xb7f001ebU, 0xd36bfd6cU, 0x9240a96dU, 0x936aa96eU, 0x925531ceU, 0xb3481d8dU,
  0xaa0e01acU, 0x92407d6dU, 0xf241017fU, 0x9a8003eeU, 0x9a8d018cU, 0x8b0101cdU,
  0x8b0c01acU, 0xb6f8036bU, 0x14000004U, 0x92403d6cU, 0xf86c786cU, 0xb6f802ebU,
  0xd371fd6eU, 0xd360bd6dU, 0xaa0a03efU, 0xb3503dafU, 0xf250017fU, 0x9a8f01adU,
  0x924005d0U, 0xf1000e1fU, 0x9a9f9210U, 0x10000291U, 0xd503201fU, 0xb8b07a30U,
  0x10000011U, 0x8b100230U, 0xd61f0200U, 0xdac101acU, 0x14000006U, 0xdac109acU,
  0x14000004U, 0xdac105acU, 0x14000002U, 0xdac10dacU, 0xd373f56bU, 0xf900014cU,
  0x8b2b4d4aU, 0x35fffa8bU, 0x91000508U, 0x17ffffcfU, 0xd65f03c0U, 0x0000000cU,
  0x0000001cU, 0x00000014U, 0x00000024U
};
#endif

/* Compiled from helpers/fixupchainprocessor.c */
#if defined (HAVE_ARM) || defined (HAVE_ARM64)
const guint32 gum_fixup_chain_processor_code[] = {
  0xd10283ffU, 0xa9046ffcU, 0xa90567faU, 0xa9065ff8U, 0xa90757f6U, 0xa9084ff4U,
  0xa9097bfdU, 0x910243fdU, 0xaa0303f3U, 0xaa0103f5U, 0xd2800009U, 0xb9400408U,
  0x8b080008U, 0xa9000be8U, 0xb840450aU, 0xa9012be8U, 0xb26db3fcU, 0xf9400fe8U,
  0xeb08013fU, 0x54000c80U, 0xf90013e9U, 0xf9400be8U, 0xb8697908U, 0x34000ba8U,
  0xd2800018U, 0xf94003e9U, 0x8b08013aU, 0x79400f48U, 0x79402b4aU, 0x91005b49U,
  0xa9032be9U, 0x121d7909U, 0xb9002fe9U, 0x7100311fU, 0x529fffe9U, 0x12bfe00aU,
  0x9a89015bU, 0x7100051fU, 0xf94007eaU, 0x9a9f0149U, 0xcb0902b7U, 0x7100191fU,
  0x9a8a03e8U, 0xcb0802b4U, 0xf9401fe8U, 0xeb08031fU, 0x540008c0U, 0xf9401be8U,
  0x78787908U, 0x529fffe9U, 0xeb09011fU, 0x540007e0U, 0xf9400749U, 0x8b0902a9U,
  0x79400b4aU, 0x9b0a2709U, 0x8b080136U, 0xb9402fe8U, 0x7100091fU, 0x54000241U,
  0xf94002c8U, 0xb7f800e8U, 0xd36cad09U, 0x92481d29U, 0x92408d0aU, 0x8b0a028aU,
  0x8b090149U, 0x14000005U, 0x92405d09U, 0xf8697a69U, 0xd358fd0aU, 0x8b2a0129U,
  0xf90002c9U, 0xd373f908U, 0x8b080ad6U, 0xb5fffe28U, 0x14000026U, 0xf94002d9U,
  0xd37eff30U, 0xd360bf22U, 0xd370c323U, 0xd371cb21U, 0xf1000e1fU, 0x9a9f9210U,
  0x10000571U, 0xd503201fU, 0xb8b07a30U, 0x10000011U, 0x8b100230U, 0xd61f0200U,
  0xd373cb28U, 0x92481d08U, 0x9240ab29U, 0x8b0902e9U, 0x8b080120U, 0x1400000fU,
  0x8a1b0328U, 0xf8687a68U, 0xd360cb29U, 0xf141013fU, 0x9a9c33e9U, 0xb360cb29U,
  0x8b090100U, 0x14000007U, 0x8b3942a0U, 0x14000003U, 0x8a1b0328U, 0xf8687a60U,
  0xaa1603e4U, 0x94000016U, 0xf90002c0U, 0xd373f728U, 0x8b080ed6U, 0xb5fffb88U,
  0x91000718U, 0x17ffffb9U, 0xf94013e9U, 0x91000529U, 0x17ffff9bU, 0xa9497bfdU,
  0xa9484ff4U, 0xa94757f6U, 0xa9465ff8U, 0xa94567faU, 0xa9446ffcU, 0x910283ffU,
  0xd65f03c0U, 0x0000000cU, 0x00000024U, 0x00000044U, 0x0000004cU, 0xb3503c44U,
  0x7100007fU, 0x9a840048U, 0x71000c3fU, 0x54000228U, 0x2a0103f0U, 0xf1000e1fU,
  0x9a9f9210U, 0x100001d1U, 0xd503201fU, 0xb8b07a30U, 0x10000011U, 0x8b100230U,
  0xd61f0200U, 0xdac10100U, 0xd65f03c0U, 0xdac10500U, 0xd65f03c0U, 0xdac10900U,
  0xd65f03c0U, 0xdac10d00U, 0xd65f03c0U, 0x0000000cU, 0x00000014U, 0x0000001cU,
  0x00000024U
};
#else
const guint8 gum_fixup_chain_processor_code[] = {
  0x55, 0x48, 0x89, 0xe5, 0x41, 0x57, 0x41, 0x56, 0x41, 0x55, 0x41, 0x54, 0x53,
  0x48, 0x89, 0x55, 0xd0, 0x8b, 0x47, 0x04, 0x4c, 0x8d, 0x14, 0x07, 0x8b, 0x04,
  0x07, 0x48, 0x89, 0x45, 0xc8, 0x49, 0xbd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0xff, 0x48, 0xb8, 0xff, 0xff, 0xff, 0xff, 0x0f, 0x00, 0x00, 0x00, 0x45,
  0x31, 0xdb, 0x4c, 0x3b, 0x5d, 0xc8, 0x0f, 0x84, 0xb4, 0x00, 0x00, 0x00, 0x43,
  0x8b, 0x7c, 0x9a, 0x04, 0x48, 0x85, 0xff, 0x0f, 0x84, 0x9e, 0x00, 0x00, 0x00,
  0x4d, 0x8d, 0x3c, 0x3a, 0x45, 0x0f, 0xb7, 0x74, 0x3a, 0x14, 0x66, 0x41, 0x83,
  0x7c, 0x3a, 0x06, 0x06, 0x48, 0x8b, 0x7d, 0xd0, 0xba, 0x00, 0x00, 0x00, 0x00,
  0x48, 0x0f, 0x44, 0xfa, 0x48, 0x89, 0xf3, 0x48, 0x29, 0xfb, 0x45, 0x31, 0xe4,
  0x4d, 0x39, 0xf4, 0x74, 0x72, 0x43, 0x0f, 0xb7, 0x7c, 0x67, 0x16, 0x48, 0x81,
  0xff, 0xff, 0xff, 0x00, 0x00, 0x74, 0x5e, 0x41, 0x0f, 0xb7, 0x57, 0x04, 0x49,
  0x0f, 0xaf, 0xd4, 0x49, 0x03, 0x7f, 0x08, 0x48, 0x01, 0xd7, 0x48, 0x01, 0xf7,
  0x4c, 0x8b, 0x0f, 0x4d, 0x85, 0xc9, 0x78, 0x18, 0x4c, 0x89, 0xca, 0x48, 0xc1,
  0xe2, 0x14, 0x4c, 0x21, 0xea, 0x4d, 0x89, 0xc8, 0x49, 0x21, 0xc0, 0x49, 0x01,
  0xd8, 0x49, 0x01, 0xd0, 0xeb, 0x14, 0x44, 0x89, 0xca, 0x81, 0xe2, 0xff, 0xff,
  0xff, 0x00, 0x45, 0x89, 0xc8, 0x41, 0xc1, 0xe8, 0x18, 0x4c, 0x03, 0x04, 0xd1,
  0x4c, 0x89, 0x07, 0x49, 0xc1, 0xe9, 0x33, 0x41, 0x81, 0xe1, 0xff, 0x0f, 0x00,
  0x00, 0x4a, 0x8d, 0x3c, 0x8f, 0x4d, 0x85, 0xc9, 0x75, 0xb5, 0x49, 0xff, 0xc4,
  0xeb, 0x89, 0x49, 0xff, 0xc3, 0xe9, 0x42, 0xff, 0xff, 0xff, 0x5b, 0x41, 0x5c,
  0x41, 0x5d, 0x41, 0x5e, 0x41, 0x5f, 0x5d, 0xc3
};
#endif

static void
gum_darwin_mapper_class_init (GumDarwinMapperClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_darwin_mapper_constructed;
  object_class->finalize = gum_darwin_mapper_finalize;
  object_class->get_property = gum_darwin_mapper_get_property;
  object_class->set_property = gum_darwin_mapper_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_MODULE,
      g_param_spec_object ("module", "Module", "Module",
      GUM_TYPE_DARWIN_MODULE, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_RESOLVER,
      g_param_spec_object ("resolver", "Resolver", "Module resolver",
      GUM_DARWIN_TYPE_MODULE_RESOLVER, G_PARAM_READWRITE |
      G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PARENT,
      g_param_spec_object ("parent", "Parent", "Parent mapper",
      GUM_DARWIN_TYPE_MAPPER, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_mapper_init (GumDarwinMapper * self)
{
  self->mapped = FALSE;
  self->apple_parameters = g_ptr_array_new_with_free_func (g_free);
}

static void
gum_darwin_mapper_constructed (GObject * object)
{
  GumDarwinMapper * self = GUM_DARWIN_MAPPER (object);
  GumDarwinMapper * parent = self->parent;

  g_assert (self->name != NULL);
  g_assert (self->module != NULL);
  g_assert (self->resolver != NULL);

  gum_darwin_query_shared_cache_range (self->resolver->task,
      &self->shared_cache_range);

  gum_darwin_module_query_tlv_parameters (self->module, &self->tlv);

  if (self->tlv.num_descriptors != 0)
  {
    GumDarwinModule * pthread = gum_darwin_module_resolver_find_module (
        self->resolver, "/usr/lib/system/libsystem_pthread.dylib");
    if (pthread != NULL)
    {
      self->pthread_key_create =
          gum_darwin_module_resolver_find_export_address (self->resolver,
              pthread, "pthread_key_create");
      self->pthread_key_delete =
          gum_darwin_module_resolver_find_export_address (self->resolver,
              pthread, "pthread_key_delete");
    }
  }

  if (parent != NULL)
  {
    parent->children = g_slist_prepend (parent->children, self);

    gum_darwin_mapper_add_pending_mapping (parent, self->name, self);
  }
}

static void
gum_darwin_mapper_finalize (GObject * object)
{
  GumDarwinMapper * self = GUM_DARWIN_MAPPER (object);

  g_clear_pointer (&self->mappings, g_hash_table_unref);
  g_slist_free_full (self->children, g_object_unref);

  g_clear_pointer (&self->threaded_regions, g_array_unref);
  g_clear_pointer (&self->threaded_symbols, g_array_unref);
  g_clear_pointer (&self->chained_symbols, g_array_unref);

  g_free (self->runtime);

  g_ptr_array_unref (self->apple_parameters);
  g_ptr_array_unref (self->dependencies);

  g_object_unref (self->resolver);
  g_object_unref (self->module);
  g_free (self->name);

  G_OBJECT_CLASS (gum_darwin_mapper_parent_class)->finalize (object);
}

static void
gum_darwin_mapper_get_property (GObject * object,
                                guint property_id,
                                GValue * value,
                                GParamSpec * pspec)
{
  GumDarwinMapper * self = GUM_DARWIN_MAPPER (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_MODULE:
      g_value_set_object (value, self->module);
      break;
    case PROP_RESOLVER:
      g_value_set_object (value, self->resolver);
      break;
    case PROP_PARENT:
      g_value_set_object (value, self->parent);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_darwin_mapper_set_property (GObject * object,
                                guint property_id,
                                const GValue * value,
                                GParamSpec * pspec)
{
  GumDarwinMapper * self = GUM_DARWIN_MAPPER (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_free (self->name);
      self->name = g_value_dup_string (value);
      break;
    case PROP_MODULE:
      g_clear_object (&self->module);
      self->module = g_value_dup_object (value);
      self->image = (self->module != NULL) ? self->module->image : NULL;
      break;
    case PROP_RESOLVER:
      g_clear_object (&self->resolver);
      self->resolver = g_value_dup_object (value);
      break;
    case PROP_PARENT:
      self->parent = g_value_get_object (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinMapper *
gum_darwin_mapper_new_from_file (const gchar * path,
                                 GumDarwinModuleResolver * resolver,
                                 GError ** error)
{
  return gum_darwin_mapper_new_from_file_with_parent (NULL, path, resolver,
      error);
}

GumDarwinMapper *
gum_darwin_mapper_new_take_blob (const gchar * name,
                                 GBytes * blob,
                                 GumDarwinModuleResolver * resolver,
                                 GError ** error)
{
  GumDarwinModule * module;
  GumDarwinMapper * mapper;

  module = gum_darwin_module_new_from_blob (blob, resolver->cpu_type,
      resolver->ptrauth_support, GUM_DARWIN_MODULE_FLAGS_NONE, error);
  if (module == NULL)
    goto malformed_blob;

  if (module->name == NULL)
    g_object_set (module, "name", name, NULL);

  mapper = g_object_new (GUM_DARWIN_TYPE_MAPPER,
      "name", name,
      "module", module,
      "resolver", resolver,
      NULL);
  if (!gum_darwin_mapper_load (mapper, error))
  {
    g_object_unref (mapper);
    mapper = NULL;
  }

  g_object_unref (module);
  g_bytes_unref (blob);

  return mapper;

malformed_blob:
  {
    g_bytes_unref (blob);

    return NULL;
  }
}

static GumDarwinMapper *
gum_darwin_mapper_new_from_file_with_parent (GumDarwinMapper * parent,
                                             const gchar * path,
                                             GumDarwinModuleResolver * resolver,
                                             GError ** error)
{
  GumDarwinMapper * mapper = NULL;
  GumDarwinModule * module;

  module = gum_darwin_module_new_from_file (path, resolver->cpu_type,
      resolver->ptrauth_support, GUM_DARWIN_MODULE_FLAGS_NONE,
      error);
  if (module == NULL)
    goto beach;

  if (module->name == NULL)
    g_object_set (module, "name", path, NULL);

  mapper = g_object_new (GUM_DARWIN_TYPE_MAPPER,
      "name", path,
      "module", module,
      "resolver", resolver,
      "parent", parent,
      NULL);
  if (!gum_darwin_mapper_load (mapper, error))
  {
    g_object_unref (mapper);
    mapper = NULL;
  }

beach:
  g_clear_object (&module);

  return mapper;
}

gboolean
gum_darwin_mapper_load (GumDarwinMapper * self,
                        GError ** error)
{
  GumDarwinModule * module = self->module;
  GArray * dependencies;
  guint i;

  if (self->dependencies != NULL)
    return TRUE;

  self->dependencies = g_ptr_array_sized_new (5);

  if (self->parent == NULL)
  {
    self->mappings = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
        (GDestroyNotify) gum_darwin_mapping_free);
    gum_darwin_mapper_add_pending_mapping (self, module->name, self);
  }

  dependencies = module->dependencies;
  for (i = 0; i != dependencies->len; i++)
  {
    GumDarwinMapping * dependency;

    dependency = gum_darwin_mapper_get_dependency_by_name (self,
        g_array_index (dependencies, GumDependencyDetails, i).name,
        error);
    if (dependency == NULL)
      return FALSE;
    g_ptr_array_add (self->dependencies, dependency);
  }

  return TRUE;
}

void
gum_darwin_mapper_add_apple_parameter (GumDarwinMapper * self,
                                       const gchar * key,
                                       const gchar * value)
{
  g_ptr_array_add (self->apple_parameters, g_strconcat (key, "=", value, NULL));

  gum_darwin_mapper_discard_footprint_budget (self);
}

gsize
gum_darwin_mapper_size (GumDarwinMapper * self)
{
  gsize total;
  GSList * cur;

  total = 0;

  for (cur = self->children; cur != NULL; cur = cur->next)
  {
    GumDarwinMapper * child = cur->data;

    total += gum_darwin_mapper_get_footprint_budget (child);
  }

  total += gum_darwin_mapper_get_footprint_budget (self);

  return total;
}

static gsize
gum_darwin_mapper_get_footprint_budget (GumDarwinMapper * self)
{
  if (self->vm_size == 0)
    gum_darwin_mapper_init_footprint_budget (self);

  return self->vm_size;
}

static void
gum_darwin_mapper_discard_footprint_budget (GumDarwinMapper * self)
{
  self->vm_size = 0;
}

static void
gum_darwin_mapper_init_footprint_budget (GumDarwinMapper * self)
{
  GumDarwinModule * module = self->module;
  GumDarwinModuleImage * image = self->image;
  gsize pointer_size = self->module->pointer_size;
  guint page_size = self->resolver->page_size;
  gsize segments_size;
  guint i;
  GumAccumulateFootprintContext runtime;
  gsize header_size;
  GPtrArray * params;
  const gsize rounded_alignment_padding_for_code = 4;
  const gsize rounded_alignment_padding_for_pointers = pointer_size;

  if (image->shared_segments->len == 0)
  {
    segments_size = 0;
    for (i = 0; i != module->segments->len; i++)
    {
      GumDarwinSegment * segment =
          &g_array_index (module->segments, GumDarwinSegment, i);

      segments_size += segment->vm_size;
      if (segment->vm_size % page_size != 0)
        segments_size += page_size - (segment->vm_size % page_size);
    }
  }
  else
  {
    segments_size = image->size;
  }

  runtime.mapper = self;
  runtime.total = 0;
  runtime.chained_fixups_count = 0;
  runtime.chained_imports_count = 0;
  runtime.threaded_regions_count = 0;

  header_size = GUM_MAPPER_HEADER_BASE_SIZE;
  params = self->apple_parameters;
  header_size += params->len * pointer_size;
  for (i = 0; i != params->len; i++)
  {
    const gchar * param = g_ptr_array_index (params, i);
    header_size += strlen (param) + 1;
  }
  header_size = GUM_ALIGN_SIZE (header_size, 16);

  gum_darwin_module_enumerate_chained_fixups (module,
      gum_accumulate_chained_fixups_size, &runtime);
  gum_darwin_module_enumerate_binds (module,
      gum_accumulate_bind_footprint_size, &runtime);
  gum_darwin_module_enumerate_lazy_binds (module,
      gum_accumulate_bind_footprint_size, &runtime);
  gum_darwin_module_enumerate_init_pointers (module,
      gum_accumulate_init_pointers_footprint_size, &runtime);
  gum_darwin_module_enumerate_init_offsets (module,
      gum_accumulate_init_offsets_footprint_size, &runtime);
  gum_darwin_module_enumerate_term_pointers (module,
      gum_accumulate_term_footprint_size, &runtime);

  if (self->tlv.num_descriptors != 0)
    runtime.total += GUM_MAPPER_INIT_TLV_SIZE;

  if (runtime.chained_fixups_count != 0)
  {
    header_size += rounded_alignment_padding_for_code;
    header_size += sizeof (gum_fixup_chain_processor_code);
  }

  if (runtime.chained_imports_count != 0)
  {
    header_size += rounded_alignment_padding_for_pointers;
    header_size += runtime.chained_imports_count * pointer_size;
  }

  runtime.total += header_size;
  runtime.total += g_slist_length (self->children) * GUM_MAPPER_DEPENDENCY_SIZE;
  runtime.total += GUM_MAPPER_CODE_BASE_SIZE;
  if (runtime.threaded_regions_count != 0)
    runtime.total += GUM_MAPPER_THREADED_BINDS_CALL_SIZE;

  self->runtime_vm_size = runtime.total;
  if (runtime.total % page_size != 0)
    self->runtime_vm_size += page_size - (runtime.total % page_size);
  self->runtime_file_size = runtime.total;
  self->runtime_header_size = header_size;

  self->vm_size = segments_size + self->runtime_vm_size;

  self->chained_fixups_count = runtime.chained_fixups_count;
}

gboolean
gum_darwin_mapper_map (GumDarwinMapper * self,
                       GumAddress base_address,
                       GError ** error)
{
  GumMapContext ctx;
  gsize total_vm_size;
  GumAddress macho_base_address;
  GSList * cur;
  GumDarwinModule * module = self->module;
  mach_port_t task = self->resolver->task;
  const GumDarwinTlvParameters * tlv = &self->tlv;
  guint i;
  mach_vm_address_t mapped_address;
  vm_prot_t cur_protection, max_protection;
  GArray * shared_segments;
  const gchar * failed_operation;
  kern_return_t kr;
  static gboolean use_memory_mapping = TRUE;

  g_assert (!self->mapped);

  ctx.mapper = self;
  ctx.success = TRUE;
  ctx.error = error;

  total_vm_size = gum_darwin_mapper_size (self);

  self->runtime_address = base_address;
  macho_base_address = base_address + self->runtime_vm_size;

  for (cur = self->children; cur != NULL; cur = cur->next)
  {
    GumDarwinMapper * child = cur->data;

    ctx.success = gum_darwin_mapper_map (child, macho_base_address, error);
    if (!ctx.success)
      goto beach;
    macho_base_address += child->vm_size;
  }

  g_object_set (module, "base-address", macho_base_address, NULL);

  gum_darwin_module_enumerate_chained_fixups (module,
      gum_darwin_mapper_resolve_chained_imports, &ctx);
  if (!ctx.success)
    goto beach;

  gum_darwin_module_enumerate_rebases (module, gum_darwin_mapper_rebase, &ctx);
  if (!ctx.success)
    goto beach;

  gum_darwin_module_enumerate_binds (module, gum_darwin_mapper_bind, &ctx);
  if (!ctx.success)
    goto beach;

  gum_darwin_module_enumerate_lazy_binds (module, gum_darwin_mapper_bind, &ctx);
  if (!ctx.success)
    goto beach;

  self->tlv_area = 0;
  if (tlv->num_descriptors != 0)
  {
    GumDarwinModule * libdyld;

    libdyld = gum_darwin_module_resolver_find_module (self->resolver,
        "libdyld.dylib");
    ctx.success = FALSE;
    gum_darwin_module_enumerate_sections (libdyld, gum_find_tlv_get_addr, &ctx);
    if (!ctx.success)
      goto unsupported_dyld_version;

    kr = mach_vm_allocate (task, &self->tlv_area,
        tlv->data_size + tlv->bss_size, VM_FLAGS_ANYWHERE);
    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_allocate(tlv)");

    kr = mach_vm_protect (task, self->tlv_area,
        tlv->data_size + tlv->bss_size, FALSE, VM_PROT_READ | VM_PROT_WRITE);
    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_protect(tlv)");

    kr = mach_vm_write (task, self->tlv_area,
        GPOINTER_TO_SIZE (self->image->data) + tlv->data_offset,
        tlv->data_size);
    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_write(tlv)");
  }

  gum_darwin_mapper_alloc_and_emit_runtime (self, base_address, total_vm_size);

  for (i = 0; i != module->segments->len; i++)
  {
    GumDarwinSegment * s =
        &g_array_index (module->segments, GumDarwinSegment, i);
    GumAddress segment_address;
    guint64 file_offset;

    if (s->file_size == 0)
      continue;

    segment_address =
        macho_base_address + s->vm_address - module->preferred_address;
    file_offset =
        (s->file_offset != 0) ? s->file_offset - self->image->source_offset : 0;

    mapped_address = segment_address;
    if (use_memory_mapping)
    {
      kr = mach_vm_remap (task, &mapped_address, s->file_size, 0,
          VM_FLAGS_OVERWRITE, mach_task_self (),
          (vm_offset_t) (self->image->data + file_offset), TRUE,
          &cur_protection, &max_protection, VM_INHERIT_COPY);
      GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_remap(segment)");

      kr = mach_vm_protect (task, segment_address, s->vm_size, FALSE,
          s->protection);
      if (kr == KERN_PROTECTION_FAILURE)
      {
        use_memory_mapping = FALSE;

        kr = mach_vm_allocate (task, &mapped_address, s->vm_size,
            VM_FLAGS_FIXED | VM_FLAGS_OVERWRITE);
        GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_allocate(oops)");

        goto fallback;
      }
      else
      {
        GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS,
            "mach_vm_protect(segment)");
      }
    }
    else
    {
fallback:
      kr = mach_vm_write (task, segment_address,
          (vm_offset_t) (self->image->data + file_offset), s->file_size);
      GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_write(segment)");

      kr = mach_vm_protect (task, segment_address, s->vm_size, FALSE,
          s->protection);
      GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_protect(segment)");
    }
  }

  shared_segments = self->image->shared_segments;
  for (i = 0; i != shared_segments->len; i++)
  {
    GumDarwinModuleImageSegment * s =
        &g_array_index (shared_segments, GumDarwinModuleImageSegment, i);

    mapped_address = macho_base_address + s->offset;
    kr = mach_vm_remap (task, &mapped_address, s->size, 0, VM_FLAGS_OVERWRITE,
        mach_task_self (), (vm_offset_t) (self->image->data + s->offset), TRUE,
        &cur_protection, &max_protection, VM_INHERIT_COPY);
    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS,
        "mach_vm_remap(shared_segment)");

    kr = mach_vm_protect (task, macho_base_address + s->offset, s->size, FALSE,
        s->protection);
    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS,
        "mach_vm_protect(shared_segment)");
  }

  if (gum_query_is_rwx_supported () || !gum_code_segment_is_supported ())
  {
    kr = mach_vm_write (task, self->runtime_address,
        (vm_offset_t) self->runtime, self->runtime_file_size);
    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_write(runtime)");

    kr = mach_vm_protect (task, self->runtime_address, self->runtime_vm_size,
        FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_protect(runtime)");
  }
  else
  {
    GumCodeSegment * segment;
    guint8 * scratch_page;

    segment = gum_code_segment_new (self->runtime_vm_size, NULL);

    scratch_page = gum_code_segment_get_address (segment);
    memcpy (scratch_page, self->runtime, self->runtime_file_size);

    gum_code_segment_realize (segment);
    gum_code_segment_map (segment, 0, self->runtime_vm_size, scratch_page);

    mapped_address = self->runtime_address;
    kr = mach_vm_remap (task, &mapped_address, self->runtime_vm_size, 0,
        VM_FLAGS_OVERWRITE, mach_task_self (), (mach_vm_address_t) scratch_page,
        FALSE, &cur_protection, &max_protection, VM_INHERIT_COPY);

    gum_code_segment_free (segment);

    GUM_CHECK_MACH_RESULT (kr, ==, KERN_SUCCESS, "mach_vm_remap(runtime)");
  }

  self->mapped = TRUE;

beach:
  return ctx.success;

unsupported_dyld_version:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED,
        "Unsupported dyld version; please file a bug");
    return FALSE;
  }
mach_failure:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED,
        "Unexpected error while mapping dylib (%s returned '%s')",
        failed_operation, mach_error_string (kr));
    return FALSE;
  }
}

GumAddress
gum_darwin_mapper_constructor (GumDarwinMapper * self)
{
  g_assert (self->mapped);

  return gum_darwin_mapper_make_code_address (self, self->runtime_address +
      self->runtime_header_size + self->constructor_offset);
}

GumAddress
gum_darwin_mapper_destructor (GumDarwinMapper * self)
{
  g_assert (self->mapped);

  return gum_darwin_mapper_make_code_address (self, self->runtime_address +
      self->runtime_header_size + self->destructor_offset);
}

GumAddress
gum_darwin_mapper_resolve (GumDarwinMapper * self,
                           const gchar * symbol)
{
  GumDarwinModule * module = self->module;
  gchar * mangled_symbol;
  GumDarwinSymbolValue v;
  gboolean success;

  g_assert (self->mapped);

  mangled_symbol = g_strconcat ("_", symbol, NULL);
  success = gum_darwin_mapper_resolve_symbol (self, module, mangled_symbol, &v);
  g_free (mangled_symbol);

  if (!success)
    return 0;

  if (v.resolver != 0)
    return 0;

  if (gum_darwin_module_is_address_in_text_section (module, v.address))
    v.address = gum_darwin_mapper_make_code_address (self, v.address);

  return v.address;
}

static GumAddress
gum_d
```