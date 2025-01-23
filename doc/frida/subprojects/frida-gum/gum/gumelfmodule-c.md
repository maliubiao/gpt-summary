Response:
My thinking process to analyze the C code for `gumelfmodule.c` and generate the requested summary involved several steps:

1. **Understand the Goal:** The primary goal is to understand the functionality of the `gumelfmodule.c` file within the Frida dynamic instrumentation framework. This requires identifying its purpose, its relationship to reverse engineering, its use of low-level concepts, and potential user errors. The request also asks for a summary of its functions.

2. **Initial Code Scan (High-Level Overview):** I first scanned the code for keywords and structures that provide clues about its purpose. I noticed:
    * **Includes:** `gumelfmodule.h`, standard library headers (`string.h`), and conditional includes based on `HAVE_ANDROID` and `HAVE_MINIZIP`. This immediately suggests the file deals with ELF (Executable and Linkable Format) files and might have Android-specific features and potentially handle compressed archives.
    * **Data Structures:**  Structures like `GumElfModule`, `GumElfEhdr`, `GumElfPhdr`, `GumElfShdr`, `GumElfDyn`, `GumElfSectionDetails`, and context structures for enumerating imports/exports/dependencies. These clearly indicate the code parses and represents the components of an ELF file.
    * **Function Prefixes:**  Functions prefixed with `gum_elf_module_` strongly suggest operations related to processing and managing ELF modules.
    * **GObject:** The use of `GObject` indicates this code is likely part of a larger GObject-based framework, providing object-oriented features and property management.
    * **Macros:** Macros like `GUM_CHECK_BOUNDS` and `GUM_READ` suggest safety checks and streamlined data reading from the ELF file.
    * **Properties:** The `G_DEFINE_TYPE` and `g_object_class_install_property` calls define properties like `etype`, `pointer-size`, `base-address`, etc., reflecting the attributes of an ELF module.

3. **Identify Core Functionality (ELF Parsing and Representation):** Based on the data structures and function prefixes, it became clear that the primary function of this file is to load, parse, and represent the structure of ELF files. This involves reading the ELF header, program headers, section headers, and dynamic entries.

4. **Relate to Reverse Engineering:**  The ability to parse ELF files is fundamental to reverse engineering. I considered specific reverse engineering tasks that this code would enable:
    * **Examining Headers:** Inspecting ELF metadata like entry point, architecture, and segment/section information.
    * **Analyzing Symbols:**  Extracting import and export symbols to understand dependencies and available functionalities.
    * **Understanding Memory Layout:**  Using program headers to determine how the ELF file is loaded into memory.
    * **Relocation Analysis:**  While not explicitly detailed in *this snippet*, the presence of `GumElfRelocationGroup` hints at handling relocations, a crucial aspect of dynamic linking.

5. **Identify Low-Level and Kernel/Framework Concepts:** I looked for elements related to operating system internals:
    * **Binary Format:** ELF is the standard binary format on Linux and Android, directly linking this code to low-level binary understanding.
    * **Memory Management:** Concepts like base address, preferred address, mapped size, and page protection are directly related to how operating systems load and manage processes in memory.
    * **Dynamic Linking:** The mention of dynamic entries, imports, exports, and dependencies points to the handling of shared libraries and the dynamic linking process.
    * **Android-Specifics:** The `HAVE_ANDROID` conditional compilation and the inclusion of `gum/gumandroid.h` (not shown, but implied) indicate Android kernel and framework awareness. The potential use of `minizip` suggests handling of APK files, which are essentially ZIP archives.

6. **Infer Logical Reasoning and Data Flow:** I analyzed the flow of operations:
    * **Loading:** The `gum_elf_module_new_from_file`, `gum_elf_module_new_from_blob`, and `gum_elf_module_new_from_memory` functions indicate different ways to load an ELF module (from a file path, raw bytes, or memory).
    * **Parsing:** Functions like `gum_elf_module_load_elf_header`, `gum_elf_module_load_program_headers`, and `gum_elf_module_load_section_headers` sequentially parse the ELF structure.
    * **Data Storage:** The `GumElfModule` structure acts as a container to store the parsed ELF information.

7. **Consider Potential User Errors:** I thought about common mistakes a programmer might make when using this code:
    * **Invalid File Path/Blob:** Providing incorrect paths or corrupted binary data.
    * **Incorrect Base Address:** When loading from memory, specifying the wrong base address could lead to incorrect interpretation of addresses.
    * **Assumptions about ELF Structure:** Users might make assumptions about the presence or format of certain ELF sections, leading to errors if those assumptions are wrong.

8. **Trace User Operations (Debugging Context):** I considered how a user might end up interacting with this code during debugging:
    * **Frida Scripting:** A user writing a Frida script might use functions that internally call into `gumelfmodule.c` to analyze loaded modules.
    * **Frida CLI Tools:** Frida command-line tools might also leverage this code for module inspection.
    * **Internal Frida Operations:** Frida itself uses this code as part of its core functionality for instrumenting processes.

9. **Structure the Output:** Finally, I organized my findings into the requested categories: functionality, relationship to reverse engineering, low-level/kernel/framework knowledge, logical reasoning, user errors, and user operation tracing. I tried to provide specific examples within each category.

10. **Summarize Functionality:** Based on the analysis, I wrote a concise summary of the file's purpose.

This iterative process of code scanning, identifying key concepts, relating them to the broader context of reverse engineering and operating systems, and considering potential use cases allowed me to generate a comprehensive analysis of the provided C code snippet. The focus was on understanding *what* the code does and *why* it's important in the context of Frida.
```c
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2019 Jon Wilson <jonwilson@zepler.net>
 * Copyright (C)      2021 Paul Schmidt <p.schmidt@tu-bs.de>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumelfmodule.h"

// ... (rest of the includes and code)
```

这是 Frida 动态 instrumentation 工具中 `frida/subprojects/frida-gum/gum/gumelfmodule.c` 文件的第一部分源代码。根据这段代码，我们可以归纳一下它的功能：

**主要功能：**

该文件的主要功能是**解析和表示 ELF (Executable and Linkable Format) 文件**。ELF 是一种用于可执行文件、目标代码、共享库和核心转储的标准文件格式，广泛应用于 Linux 和其他类 Unix 系统，包括 Android。

**详细功能点：**

1. **ELF 文件加载和解析：**
   - 提供了从文件路径 (`gum_elf_module_new_from_file`)、内存中的数据块 (`gum_elf_module_new_from_blob`) 和已加载到内存中的模块 (`gum_elf_module_new_from_memory`) 创建 `GumElfModule` 对象的功能。
   - `gum_elf_module_load` 函数负责实际的 ELF 文件加载过程，根据不同的加载模式（在线或离线）处理文件或内存数据。
   - 解析 ELF 文件的各个部分，包括 ELF 头部 (`gum_elf_module_load_elf_header`)、程序头部 (`gum_elf_module_load_program_headers`)、节区头部 (`gum_elf_module_load_section_headers`) 和动态链接条目 (`gum_elf_module_load_dynamic_entries`)。

2. **ELF 文件信息的存储和访问：**
   - 使用 `GumElfModule` 结构体来存储解析后的 ELF 文件信息，例如：
     - 文件来源 (`source_path`, `source_blob`, `source_mode`)
     - 原始文件数据 (`file_bytes`, `file_data`, `file_size`)
     - ELF 头部信息 (`ehdr`)
     - 程序头部和节区头部数组 (`phdrs`, `shdrs`)
     - 动态链接条目数组 (`dyns`)
     - 节区详细信息数组 (`sections`)
     - 基址、首选地址、映射大小等内存相关信息 (`base_address`, `preferred_address`, `mapped_size`)
   - 提供了访问这些信息的属性 (properties)，例如 `etype`, `pointer-size`, `base-address` 等，通过 `g_object_class_install_property` 定义，并提供 `gum_elf_module_get_property` 和 `gum_elf_module_set_property` 进行访问和设置。

3. **处理不同的 ELF 文件来源：**
   - 支持从磁盘文件加载 (`GUM_ELF_SOURCE_MODE_OFFLINE`)。
   - 支持从内存中的已加载模块加载 (`GUM_ELF_SOURCE_MODE_ONLINE`)。
   - 针对 Android 平台，可能支持从 APK 文件中提取 ELF 文件 (`gum_maybe_extract_from_apk`)。

4. **错误处理：**
   - 使用 `GError` 机制来报告加载和解析过程中遇到的错误。

5. **内存管理：**
   - 使用 `GBytes` 来管理文件或内存数据，提供引用计数。
   - 使用 `GArray` 来存储动态数组，例如程序头部和节区头部。
   - 提供了 `gum_elf_module_unload` 函数来释放分配的资源。

**与逆向方法的联系：**

这段代码是 Frida 动态 instrumentation 工具的核心组成部分，它使得 Frida 能够**理解目标进程的内存布局和代码结构**，这对于逆向工程至关重要。

* **分析可执行文件结构：** 逆向工程师可以使用 Frida 加载目标进程的模块，并利用 `GumElfModule` 提供的接口来检查 ELF 头部、程序头部和节区头部，从而了解程序的入口点、内存段分布、代码段、数据段等信息。
* **查找符号表：** 虽然这段代码本身没有显式地处理符号表，但它是后续处理符号表的基础。通过解析节区头部，可以找到符号表所在的节区，并进一步分析导出和导入的符号，从而理解模块的函数和依赖关系。
* **理解动态链接：**  解析动态链接条目可以帮助逆向工程师理解模块依赖哪些共享库，以及动态链接器是如何加载和解析这些依赖的。

**二进制底层，Linux, Android 内核及框架的知识：**

这段代码深入涉及到以下方面的知识：

* **ELF 文件格式：** 代码中大量使用了 ELF 文件格式的术语和结构，例如 `Ehdr` (ELF header), `Phdr` (Program header), `Shdr` (Section header), `Dyn` (Dynamic entry)。理解这些结构是理解代码的基础。
* **二进制数据处理：** 代码需要读取和解析二进制的 ELF 文件数据，需要考虑字节序 (endianness) 等问题。
* **Linux 进程内存布局：** `base_address`, `preferred_address`, `mapped_size` 等属性直接关联到 Linux 进程的内存布局。程序头部描述了如何将 ELF 文件映射到内存中。
* **Linux 动态链接器：** `PT_INTERP` 类型的程序头部指向动态链接器的路径，解析动态链接条目可以理解动态链接的过程。
* **Android 平台特性：**
    * `HAVE_ANDROID` 宏和 `gum/gumandroid.h` 的包含表明代码有针对 Android 平台的特殊处理。
    * `gum_maybe_extract_from_apk` 函数暗示了对 APK 文件（Android 应用程序包）的处理，因为 Android 的共享库通常打包在 APK 文件中。
    *  涉及到 Android 内核加载器如何加载和链接共享库的知识。
* **内存保护机制：**  `gum_elf_module_find_address_protection` 函数以及 `GumPageProtection` 类型表明代码关注内存页的保护属性。

**逻辑推理：**

假设输入一个有效的 ELF 文件路径给 `gum_elf_module_new_from_file` 函数：

* **假设输入：** `path = "/system/lib64/libc.so"`
* **预期输出：**
    * 如果加载成功，将创建一个 `GumElfModule` 对象，其 `source_path` 属性设置为 `/system/lib64/libc.so`，并且内部的 ELF 头部、程序头部、节区头部等信息会被成功解析并存储在 `GumElfModule` 结构体中。
    * 如果加载失败（例如，文件不存在或不是有效的 ELF 文件），则返回 `NULL`，并且 `error` 参数会包含相应的错误信息。

**用户或编程常见的使用错误：**

1. **提供无效的文件路径或内存地址：**
   - 用户可能向 `gum_elf_module_new_from_file` 传递一个不存在的文件路径，或者向 `gum_elf_module_new_from_memory` 传递一个错误的基址，导致加载失败。
   - **示例：** `gum_elf_module_new_from_file("/nonexistent/file.so", &error);`
2. **在 `source_mode` 不匹配的情况下使用函数：**
   - 例如，在 `GUM_ELF_SOURCE_MODE_ONLINE` 模式下，如果提供的路径与实际加载的模块不符，可能会导致解析错误。
3. **假设特定的 ELF 结构存在：**
   - 用户编写的代码可能假设目标模块包含特定的节区或程序头部，如果目标模块不符合这个假设，代码可能会出错。
4. **忘记处理错误：**
   - 用户可能调用加载函数后没有检查 `error` 参数，导致在加载失败的情况下继续操作，引发未定义的行为。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本：**  用户可能正在编写一个 Frida 脚本来 hook 某个 Android 应用的 Native 函数。
2. **获取目标模块信息：**  脚本可能需要获取目标模块（例如 `libc.so`）的基址、导出函数地址等信息。
3. **调用 Frida 的 API：**  Frida 提供了 `Process.getModuleByName()` 或 `Module.getBaseAddress()` 等 API 来获取模块信息。
4. **内部调用 `gumelfmodule.c` 的函数：**  Frida 的内部实现会调用 `gumelfmodule.c` 中的函数，例如 `gum_elf_module_new_from_memory`，来加载和解析目标模块的 ELF 文件头，以便获取基址、节区信息等。
5. **调试线索：** 如果用户在获取模块信息时遇到错误，例如无法找到模块或解析 ELF 头失败，那么调试线索就会指向 `gumelfmodule.c` 中的加载和解析逻辑。用户可以通过查看 Frida 的日志或使用调试器来跟踪执行流程，最终定位到 `gumelfmodule.c` 中的具体代码。

**归纳一下它的功能（第一部分）：**

这段 `gumelfmodule.c` 文件的第一部分主要负责 **ELF 文件的加载、初步解析和基本信息的提取**。它定义了 `GumElfModule` 对象，提供了创建和加载 ELF 模块的方法，并解析了 ELF 文件的头部和程序头部，为后续更深入的分析（例如节区、符号表、重定位等）奠定了基础。它处理了从不同来源加载 ELF 文件的情况，并初步管理了相关的内存资源。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/gumelfmodule.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2019 Jon Wilson <jonwilson@zepler.net>
 * Copyright (C)      2021 Paul Schmidt <p.schmidt@tu-bs.de>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumelfmodule.h"

#include "gumelfmodule-priv.h"
#ifdef HAVE_ANDROID
# include "gum/gumandroid.h"
# ifdef HAVE_MINIZIP
#  include <minizip/mz.h>
#  include <minizip/mz_strm.h>
#  include <minizip/mz_strm_os.h>
#  include <minizip/mz_zip.h>
#  include <minizip/mz_zip_rw.h>
# endif
#endif

#include <string.h>

#define GUM_ELF_DEFAULT_MAPPED_SIZE (64 * 1024)
#define GUM_ELF_PAGE_START(value, page_size) \
    (GUM_ADDRESS (value) & ~GUM_ADDRESS (page_size - 1))

#define GUM_CHECK_BOUNDS(l, r, name) \
    G_STMT_START \
    { \
      if (!gum_elf_module_check_bounds (self, l, r, data, size, name, error)) \
        goto propagate_error; \
    } \
    G_STMT_END
#define GUM_CHECK_STR_BOUNDS(s, name) \
    G_STMT_START \
    { \
      if (!gum_elf_module_check_str_bounds (self, s, data, size, name, error)) \
        goto propagate_error; \
    } \
    G_STMT_END
#define GUM_READ(dst, src, type) \
    dst = G_PASTE (gum_elf_module_read_, type) (self, &src);

typedef guint GumElfDynamicAddressState;
typedef struct _GumElfRelocationGroup GumElfRelocationGroup;
typedef struct _GumElfEnumerateImportsContext GumElfEnumerateImportsContext;
typedef struct _GumElfEnumerateExportsContext GumElfEnumerateExportsContext;
typedef struct _GumElfStoreSymtabParamsContext GumElfStoreSymtabParamsContext;
typedef struct _GumElfEnumerateDepsContext GumElfEnumerateDepsContext;

enum
{
  PROP_0,
  PROP_ETYPE,
  PROP_POINTER_SIZE,
  PROP_BYTE_ORDER,
  PROP_OS_ABI,
  PROP_OS_ABI_VERSION,
  PROP_MACHINE,
  PROP_BASE_ADDRESS,
  PROP_PREFERRED_ADDRESS,
  PROP_MAPPED_SIZE,
  PROP_ENTRYPOINT,
  PROP_INTERPRETER,
  PROP_SOURCE_PATH,
  PROP_SOURCE_BLOB,
  PROP_SOURCE_MODE,
};

struct _GumElfModule
{
  GObject parent;

  gchar * source_path;
  GBytes * source_blob;
  GumElfSourceMode source_mode;

  GBytes * file_bytes;
  gconstpointer file_data;
  gsize file_size;

  GumElfEhdr ehdr;
  GArray * phdrs;
  GArray * shdrs;
  GArray * dyns;

  GArray * sections;

  GumAddress base_address;
  GumAddress preferred_address;
  guint64 mapped_size;
  GumElfDynamicAddressState dynamic_address_state;
  const gchar * dynamic_strings;
};

enum _GumElfDynamicAddressState
{
  GUM_ELF_DYNAMIC_ADDRESS_PRISTINE,
  GUM_ELF_DYNAMIC_ADDRESS_ADJUSTED,
};

struct _GumElfRelocationGroup
{
  guint64 offset;
  guint64 size;
  guint64 entsize;
  gboolean relocs_have_addend;

  guint64 symtab_offset;
  guint64 symtab_entsize;

  const gchar * strings;
  const gchar * strings_base;
  gsize strings_size;

  const GumElfSectionDetails * parent;
};

struct _GumElfEnumerateImportsContext
{
  GumFoundImportFunc func;
  gpointer user_data;

  GHashTable * slots;
  guint32 jump_slot_type;
};

struct _GumElfEnumerateExportsContext
{
  GumFoundExportFunc func;
  gpointer user_data;
};

struct _GumElfStoreSymtabParamsContext
{
  guint pending;
  gboolean found_hash;

  gpointer entries;
  gsize entry_size;
  gsize entry_count;

  GumElfModule * module;
};

struct _GumElfEnumerateDepsContext
{
  GumFoundDependencyFunc func;
  gpointer user_data;

  GumElfModule * module;
};

static void gum_elf_module_finalize (GObject * object);
static void gum_elf_module_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_elf_module_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);

static gboolean gum_elf_module_load_elf_header (GumElfModule * self,
    GError ** error);
static gboolean gum_elf_module_load_program_headers (GumElfModule * self,
    GError ** error);
static gboolean gum_elf_module_load_section_headers (GumElfModule * self,
    GError ** error);
static gboolean gum_elf_module_load_section_details (GumElfModule * self,
    GError ** error);
static void gum_elf_section_details_clear (GumElfSectionDetails * d);
static gboolean gum_elf_module_load_dynamic_entries (GumElfModule * self,
    GError ** error);
static gconstpointer gum_elf_module_get_live_data (GumElfModule * self,
    gsize * size);
static void gum_elf_module_unload (GumElfModule * self);
static gboolean gum_elf_module_emit_relocations (GumElfModule * self,
    const GumElfRelocationGroup * g, GumFoundElfRelocationFunc func,
    gpointer user_data);
static gboolean gum_emit_elf_import (const GumElfSymbolDetails * details,
    gpointer user_data);
static gboolean gum_try_get_jump_slot_relocation_type_for_machine (
    GumElfMachine machine, guint32 * type);
static gboolean gum_maybe_collect_import_slot_from_relocation (
    const GumElfRelocationDetails * details, gpointer user_data);
static gboolean gum_emit_elf_export (const GumElfSymbolDetails * details,
    gpointer user_data);
static void gum_elf_module_parse_symbol (GumElfModule * self,
    const GumElfSym * sym, const gchar * strings, GumElfSymbolDetails * d);
static void gum_elf_module_read_symbol (GumElfModule * self,
    gconstpointer raw_sym, GumElfSym * sym);
static gboolean gum_store_symtab_params (
    const GumElfDynamicEntryDetails * details, gpointer user_data);
static gboolean gum_adjust_symtab_params (const GumElfSectionDetails * details,
    gpointer user_data);
static void gum_elf_module_enumerate_symbols_in_section (GumElfModule * self,
    GumElfSectionType section, GumFoundElfSymbolFunc func, gpointer user_data);
static gboolean gum_emit_each_needed (const GumElfDynamicEntryDetails * details,
    gpointer user_data);
static gboolean gum_elf_module_find_address_protection (GumElfModule * self,
    GumAddress address, GumPageProtection * prot);
static GumPageProtection gum_parse_phdr_protection (const GumElfPhdr * phdr);
static const GumElfPhdr * gum_elf_module_find_phdr_by_type (GumElfModule * self,
    guint32 type);
static const GumElfPhdr * gum_elf_module_find_load_phdr_by_address (
    GumElfModule * self, GumAddress address);
static const GumElfShdr * gum_elf_module_find_section_header_by_index (
    GumElfModule * self, guint i);
static const GumElfShdr * gum_elf_module_find_section_header_by_type (
    GumElfModule * self, GumElfSectionType type);
static const GumElfSectionDetails *
    gum_elf_module_find_section_details_by_index (GumElfModule * self, guint i);
static GumAddress gum_elf_module_compute_preferred_address (
    GumElfModule * self);
static guint64 gum_elf_module_compute_mapped_size (GumElfModule * self);
static GumElfDynamicAddressState gum_elf_module_detect_dynamic_address_state (
    GumElfModule * self);
static gpointer gum_elf_module_resolve_dynamic_virtual_location (
    GumElfModule * self, GumAddress address);
static gboolean gum_store_dynamic_string_table (
    const GumElfDynamicEntryDetails * details, gpointer user_data);

static gboolean gum_elf_module_check_bounds (GumElfModule * self,
    gconstpointer left, gconstpointer right, gconstpointer base, gsize size,
    const gchar * name, GError ** error);
static gboolean gum_elf_module_check_str_bounds (GumElfModule * self,
    const gchar * str, gconstpointer base, gsize size, const gchar * name,
    GError ** error);

static guint8 gum_elf_module_read_uint8 (GumElfModule * self, const guint8 * v);
static guint16 gum_elf_module_read_uint16 (GumElfModule * self,
    const guint16 * v);
static gint32 gum_elf_module_read_int32 (GumElfModule * self, const gint32 * v);
static guint32 gum_elf_module_read_uint32 (GumElfModule * self,
    const guint32 * v);
static gint64 gum_elf_module_read_int64 (GumElfModule * self, const gint64 * v);
static guint64 gum_elf_module_read_uint64 (GumElfModule * self,
    const guint64 * v);

static gboolean gum_maybe_extract_from_apk (const gchar * path,
    GBytes ** file_bytes);

G_DEFINE_TYPE (GumElfModule, gum_elf_module, G_TYPE_OBJECT)

static void
gum_elf_module_class_init (GumElfModuleClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_elf_module_finalize;
  object_class->get_property = gum_elf_module_get_property;
  object_class->set_property = gum_elf_module_set_property;

  g_object_class_install_property (object_class, PROP_ETYPE,
      g_param_spec_enum ("etype", "Type", "ELF Type",
      GUM_TYPE_ELF_TYPE, GUM_ELF_NONE,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_POINTER_SIZE,
      g_param_spec_uint ("pointer-size", "Pointer Size",
      "Pointer size in bytes", 4, 8, 8,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BYTE_ORDER,
      g_param_spec_int ("byte-order", "Byte Order",
      "Byte order/endian", G_LITTLE_ENDIAN, G_BIG_ENDIAN, G_BYTE_ORDER,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_OS_ABI,
      g_param_spec_enum ("os-abi", "OS ABI", "Operating system ABI",
      GUM_TYPE_ELF_OSABI, GUM_ELF_OS_SYSV,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_OS_ABI_VERSION,
      g_param_spec_uint ("os-abi-version", "OS ABI Version",
      "Operating system ABI version", 0, G_MAXUINT8, 0,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_MACHINE,
      g_param_spec_enum ("machine", "Machine", "Machine",
      GUM_TYPE_ELF_MACHINE, GUM_ELF_MACHINE_NONE,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BASE_ADDRESS,
      g_param_spec_uint64 ("base-address", "Base Address",
      "Base virtual address, or zero when operating offline", 0,
      G_MAXUINT64, 0,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_PREFERRED_ADDRESS,
      g_param_spec_uint64 ("preferred-address", "Preferred Address",
      "Preferred virtual address", 0, G_MAXUINT64, 0,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_MAPPED_SIZE,
      g_param_spec_uint64 ("mapped-size", "Mapped Size",
      "Mapped size", 0, G_MAXUINT64, GUM_ELF_DEFAULT_MAPPED_SIZE,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_ENTRYPOINT,
      g_param_spec_uint64 ("entrypoint", "Entrypoint",
      "Entrypoint virtual address", 0, G_MAXUINT64, 0,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_INTERPRETER,
      g_param_spec_string ("interpreter", "Interpreter", "Interpreter", NULL,
      G_PARAM_READABLE | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_PATH,
      g_param_spec_string ("source-path", "SourcePath", "Source path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_BLOB,
      g_param_spec_boxed ("source-blob", "SourceBlob", "Source blob",
      G_TYPE_BYTES,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE_MODE,
      g_param_spec_enum ("source-mode", "SourceMode", "Source mode",
      GUM_TYPE_ELF_SOURCE_MODE, GUM_ELF_SOURCE_MODE_OFFLINE,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

static void
gum_elf_module_init (GumElfModule * self)
{
  self->phdrs = g_array_new (FALSE, FALSE, sizeof (GumElfPhdr));
  self->shdrs = g_array_new (FALSE, FALSE, sizeof (GumElfShdr));
  self->dyns = g_array_new (FALSE, FALSE, sizeof (GumElfDyn));

  self->sections = g_array_new (FALSE, TRUE, sizeof (GumElfSectionDetails));
  g_array_set_clear_func (self->sections,
      (GDestroyNotify) gum_elf_section_details_clear);

  self->mapped_size = GUM_ELF_DEFAULT_MAPPED_SIZE;
}

static void
gum_elf_module_finalize (GObject * object)
{
  GumElfModule * self = GUM_ELF_MODULE (object);

  gum_elf_module_unload (self);

  g_array_unref (self->sections);

  g_array_unref (self->dyns);
  g_array_unref (self->shdrs);
  g_array_unref (self->phdrs);

  g_bytes_unref (self->source_blob);
  g_free (self->source_path);

  G_OBJECT_CLASS (gum_elf_module_parent_class)->finalize (object);
}

static void
gum_elf_module_get_property (GObject * object,
                             guint property_id,
                             GValue * value,
                             GParamSpec * pspec)
{
  GumElfModule * self = GUM_ELF_MODULE (object);

  switch (property_id)
  {
    case PROP_ETYPE:
      g_value_set_enum (value, gum_elf_module_get_etype (self));
      break;
    case PROP_POINTER_SIZE:
      g_value_set_uint (value, gum_elf_module_get_pointer_size (self));
      break;
    case PROP_BYTE_ORDER:
      g_value_set_int (value, gum_elf_module_get_byte_order (self));
      break;
    case PROP_OS_ABI:
      g_value_set_enum (value, gum_elf_module_get_os_abi (self));
      break;
    case PROP_OS_ABI_VERSION:
      g_value_set_uint (value, gum_elf_module_get_os_abi_version (self));
      break;
    case PROP_MACHINE:
      g_value_set_enum (value, gum_elf_module_get_machine (self));
      break;
    case PROP_BASE_ADDRESS:
      g_value_set_uint64 (value, gum_elf_module_get_base_address (self));
      break;
    case PROP_PREFERRED_ADDRESS:
      g_value_set_uint64 (value, gum_elf_module_get_preferred_address (self));
      break;
    case PROP_MAPPED_SIZE:
      g_value_set_uint64 (value, gum_elf_module_get_mapped_size (self));
      break;
    case PROP_ENTRYPOINT:
      g_value_set_uint64 (value, gum_elf_module_get_entrypoint (self));
      break;
    case PROP_INTERPRETER:
      g_value_set_string (value, gum_elf_module_get_interpreter (self));
      break;
    case PROP_SOURCE_PATH:
      g_value_set_string (value, gum_elf_module_get_source_path (self));
      break;
    case PROP_SOURCE_BLOB:
      g_value_set_boxed (value, gum_elf_module_get_source_blob (self));
      break;
    case PROP_SOURCE_MODE:
      g_value_set_enum (value, gum_elf_module_get_source_mode (self));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_elf_module_set_property (GObject * object,
                             guint property_id,
                             const GValue * value,
                             GParamSpec * pspec)
{
  GumElfModule * self = GUM_ELF_MODULE (object);

  switch (property_id)
  {
    case PROP_BASE_ADDRESS:
      self->base_address = g_value_get_uint64 (value);
      break;
    case PROP_SOURCE_PATH:
      g_free (self->source_path);
      self->source_path = g_value_dup_string (value);
      break;
    case PROP_SOURCE_BLOB:
      g_bytes_unref (self->source_blob);
      self->source_blob = g_value_dup_boxed (value);
      break;
    case PROP_SOURCE_MODE:
      self->source_mode = g_value_get_enum (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumElfModule *
gum_elf_module_new_from_file (const gchar * path,
                              GError ** error)
{
  GumElfModule * module;

  module = g_object_new (GUM_ELF_TYPE_MODULE,
      "source-path", path,
      "source-mode", GUM_ELF_SOURCE_MODE_OFFLINE,
      NULL);
  if (!gum_elf_module_load (module, error))
  {
    g_object_unref (module);
    return NULL;
  }

  return module;
}

GumElfModule *
gum_elf_module_new_from_blob (GBytes * blob,
                              GError ** error)
{
  GumElfModule * module;

  module = g_object_new (GUM_ELF_TYPE_MODULE,
      "source-blob", blob,
      "source-mode", GUM_ELF_SOURCE_MODE_OFFLINE,
      NULL);
  if (!gum_elf_module_load (module, error))
  {
    g_object_unref (module);
    return NULL;
  }

  return module;
}

GumElfModule *
gum_elf_module_new_from_memory (const gchar * path,
                                GumAddress base_address,
                                GError ** error)
{
  GumElfModule * module;

  module = g_object_new (GUM_ELF_TYPE_MODULE,
      "base-address", base_address,
      "source-path", path,
      "source-mode", GUM_ELF_SOURCE_MODE_ONLINE,
      NULL);
  if (!gum_elf_module_load (module, error))
  {
    g_object_unref (module);
    return NULL;
  }

  return module;
}

gboolean
gum_elf_module_load (GumElfModule * self,
                     GError ** error)
{
  GError * local_error = NULL;

  if (self->file_bytes != NULL)
    return TRUE;

  if (self->source_blob != NULL)
  {
    self->file_bytes = g_bytes_ref (self->source_blob);
  }
  else
  {
#ifdef HAVE_LINUX
    if (self->source_mode == GUM_ELF_SOURCE_MODE_ONLINE &&
        strcmp (self->source_path, "linux-vdso.so.1") == 0)
    {
      self->file_bytes = g_bytes_new_static (
          GSIZE_TO_POINTER (self->base_address), gum_query_page_size ());
    }
    else
#endif
    if (!gum_maybe_extract_from_apk (self->source_path, &self->file_bytes))
    {
      GMappedFile * file =
          g_mapped_file_new (self->source_path, FALSE, &local_error);
      if (file == NULL)
        goto unable_to_open;
      self->file_bytes = g_mapped_file_get_bytes (file);
      g_mapped_file_unref (file);
    }
  }

  self->file_data = g_bytes_get_data (self->file_bytes, &self->file_size);

  if (!gum_elf_module_load_elf_header (self, error))
    goto propagate_error;

  if (!gum_elf_module_load_program_headers (self, error))
    goto propagate_error;

  self->mapped_size = gum_elf_module_compute_mapped_size (self);
  self->preferred_address = gum_elf_module_compute_preferred_address (self);

  if (!gum_elf_module_load_section_headers (self, error))
    goto propagate_error;

  if (!gum_elf_module_load_dynamic_entries (self, error))
    goto propagate_error;

  self->dynamic_address_state =
      gum_elf_module_detect_dynamic_address_state (self);

  gum_elf_module_enumerate_dynamic_entries (self,
      gum_store_dynamic_string_table, self);

  if (!gum_elf_module_load_section_details (self, error))
    goto propagate_error;

  return TRUE;

unable_to_open:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "%s", local_error->message);
    goto propagate_error;
  }
propagate_error:
  {
    g_clear_error (&local_error);

    gum_elf_module_unload (self);

    return FALSE;
  }
}

static gboolean
gum_elf_module_load_elf_header (GumElfModule * self,
                                GError ** error)
{
  gconstpointer data;
  gsize size;
  const GumElfIdentity * identity;

  data = gum_elf_module_get_live_data (self, &size);

  identity = data;
  GUM_CHECK_BOUNDS (identity, identity + 1, "ELF header");
  self->ehdr.identity = *identity;

#define GUM_READ_EHDR_FIELD(name, type) \
    GUM_READ (self->ehdr.name, src->name, type)
#define GUM_READ_EHDR() \
    G_STMT_START \
    { \
      GUM_READ_EHDR_FIELD (type,      uint16); \
      GUM_READ_EHDR_FIELD (machine,   uint16); \
      GUM_READ_EHDR_FIELD (version,   uint32); \
      GUM_READ_EHDR_FIELD (entry,     uint64); \
      GUM_READ_EHDR_FIELD (phoff,     uint64); \
      GUM_READ_EHDR_FIELD (shoff,     uint64); \
      GUM_READ_EHDR_FIELD (flags,     uint32); \
      GUM_READ_EHDR_FIELD (ehsize,    uint16); \
      GUM_READ_EHDR_FIELD (phentsize, uint16); \
      GUM_READ_EHDR_FIELD (phnum,     uint16); \
      GUM_READ_EHDR_FIELD (shentsize, uint16); \
      GUM_READ_EHDR_FIELD (shnum,     uint16); \
      GUM_READ_EHDR_FIELD (shstrndx,  uint16); \
    } \
    G_STMT_END
#define GUM_READ_EHDR32() \
    G_STMT_START \
    { \
      GUM_READ_EHDR_FIELD (type,      uint16); \
      GUM_READ_EHDR_FIELD (machine,   uint16); \
      GUM_READ_EHDR_FIELD (version,   uint32); \
      GUM_READ_EHDR_FIELD (entry,     uint32); \
      GUM_READ_EHDR_FIELD (phoff,     uint32); \
      GUM_READ_EHDR_FIELD (shoff,     uint32); \
      GUM_READ_EHDR_FIELD (flags,     uint32); \
      GUM_READ_EHDR_FIELD (ehsize,    uint16); \
      GUM_READ_EHDR_FIELD (phentsize, uint16); \
      GUM_READ_EHDR_FIELD (phnum,     uint16); \
      GUM_READ_EHDR_FIELD (shentsize, uint16); \
      GUM_READ_EHDR_FIELD (shnum,     uint16); \
      GUM_READ_EHDR_FIELD (shstrndx,  uint16); \
    } \
    G_STMT_END

  switch (identity->klass)
  {
    case GUM_ELF_CLASS_64:
    {
      const GumElfEhdr * src = data;

      GUM_CHECK_BOUNDS (src, src + 1, "ELF header");
      GUM_READ_EHDR ();

      break;
    }
    case GUM_ELF_CLASS_32:
    {
      const GumElfEhdr32 * src = data;

      GUM_CHECK_BOUNDS (src, src + 1, "ELF header");
      GUM_READ_EHDR32 ();

      break;
    }
    default:
      goto invalid_value;
  }

#undef GUM_READ_EHDR_FIELD
#undef GUM_READ_EHDR
#undef GUM_READ_EHDR32

  return TRUE;

invalid_value:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Invalid ELF header");
    goto propagate_error;
  }
propagate_error:
  {
    return FALSE;
  }
}

static gboolean
gum_elf_module_load_program_headers (GumElfModule * self,
                                     GError ** error)
{
  gconstpointer data;
  gsize size;
  guint16 n;
  gconstpointer start, end, cursor;
  guint16 i;

  data = gum_elf_module_get_live_data (self, &size);

  n = self->ehdr.phnum;

  start = (const guint8 *) data + self->ehdr.phoff;
  end = (const guint8 *) start + (n * self->ehdr.phentsize);
  GUM_CHECK_BOUNDS (start, end, "program headers");

  g_array_set_size (self->phdrs, n);

  cursor = start;
  for (i = 0; i != n; i++)
  {
    GumElfPhdr * dst = &g_array_index (self->phdrs, GumElfPhdr, i);

#define GUM_READ_PHDR_FIELD(name, type) \
    GUM_READ (dst->name, src->name, type)
#define GUM_READ_PHDR() \
    G_STMT_START \
    { \
      GUM_READ_PHDR_FIELD (type,   uint32); \
      GUM_READ_PHDR_FIELD (flags,  uint32); \
      GUM_READ_PHDR_FIELD (offset, uint64); \
      GUM_READ_PHDR_FIELD (vaddr,  uint64); \
      GUM_READ_PHDR_FIELD (paddr,  uint64); \
      GUM_READ_PHDR_FIELD (filesz, uint64); \
      GUM_READ_PHDR_FIELD (memsz,  uint64); \
      GUM_READ_PHDR_FIELD (align,  uint64); \
    } \
    G_STMT_END
#define GUM_READ_PHDR32() \
    G_STMT_START \
    { \
      GUM_READ_PHDR_FIELD (type,   uint32); \
      GUM_READ_PHDR_FIELD (offset, uint32); \
      GUM_READ_PHDR_FIELD (vaddr,  uint32); \
      GUM_READ_PHDR_FIELD (paddr,  uint32); \
      GUM_READ_PHDR_FIELD (filesz, uint32); \
      GUM_READ_PHDR_FIELD (memsz,  uint32); \
      GUM_READ_PHDR_FIELD (flags,  uint32); \
      GUM_READ_PHDR_FIELD (align,  uint32); \
    } \
    G_STMT_END

    switch (self->ehdr.identity.klass)
    {
      case GUM_ELF_CLASS_64:
      {
        const GumElfPhdr * src = cursor;
        GUM_READ_PHDR ();
        break;
      }
      case GUM_ELF_CLASS_32:
      {
        const GumElfPhdr32 * src = cursor;
        GUM_READ_PHDR32 ();
        break;
      }
      default:
        g_assert_not_reached ();
    }

#undef GUM_READ_PHDR_FIELD
#undef GUM_READ_PHDR
#undef GUM_READ_PHDR32

    cursor = (const guint8 *) cursor + self->ehdr.phentsize;
  }

  return TRUE;

propagate_error:
  {
    return FALSE;
  }
}

static gboolean
gum_elf_module_load_section_headers (GumElfModule * self,
                                     GError ** error)
{
  gconstpointer data;
  gsize size;
  guint16 n;
  gconstpointer start, end, cursor;
  guint16 i;

  data = gum_elf_module_get_file_data (self, &size);

  n = self->ehdr.shnum;

  start = (const guint8 *) data + self->ehdr.shoff;
  end = (const guint8 *) start + (n * self->ehdr.shentsize);
  if (end == start)
    return TRUE;
  GUM_CHECK_BOUNDS (start, end, "section headers");

  g_array_set_size (self->shdrs, n);

  cursor = start;
  for (i = 0; i != n; i++)
  {
    GumElfShdr * dst = &g_array_index (self->shdrs, GumElfShdr, i);

#define GUM_READ_SHDR_FIELD(name, type) \
    GUM_READ (dst->name, src->name, type)
#define GUM_READ_SHDR() \
    G_STMT_START \
    { \
      GUM_READ_SHDR_FIELD (name,      uint32); \
      GUM_READ_SHDR_FIELD (type,      uint32); \
      GUM_READ_SHDR_FIELD (flags,     uint64); \
      GUM_READ_SHDR_FIELD (addr,      uint64); \
      GUM_READ_SHDR_FIELD (offset,    uint64); \
      GUM_READ_SHDR_FIELD (size,      uint64); \
      GUM_READ_SHDR_FIELD (link,      uint32); \
      GUM_READ_SHDR_FIELD (info,      uint32); \
      GUM_READ_SHDR_FIELD (addralign, uint64); \
      GUM_READ_SHDR_FIELD (entsize,   uint64); \
    } \
    G_STMT_END
#define GUM_READ_SHDR32() \
    G_STMT_START \
    { \
      GUM_READ_SHDR_FIELD (name,      uint32); \
      GUM_READ_SHDR_FIELD (type,      uint32); \
      GUM_READ_SHDR_FIELD (flags,     uint32); \
      GUM_READ_SHDR_FIELD (addr,      uint32); \
      GUM_READ_SHDR_FIELD (offset,    uint32); \
      GUM_READ_SHDR_FIELD (size,      uint32); \
      GUM_READ_SHDR_FIELD (link,      uint32); \
      GUM_READ_SHDR_FIELD (info,      uint32); \
      GUM_READ_SHDR_FIELD (addralign, uint32); \
      GUM_READ_SHDR_FIELD (entsize,   uint32); \
    } \
    G_STMT_END

    switch (self->ehdr.identity.klass)
    {
      case GUM_ELF_CLASS_64:
      {
        const GumElfShdr * src = cursor;
        GUM_READ_SHDR ();
        break;
      }
      case GUM_ELF_CLASS_32:
      {
        const GumElfShdr32 * src = cursor;
        GUM_READ_SHDR32 ();
        break;
      }
      default:
        g_assert_not_reached ();
    }

#undef GUM_READ_SHDR_FIELD
#undef GUM_READ_SHDR
#undef GUM_READ_SHDR32

    cursor = (const guint8 *) cursor + self->ehdr.shentsize;
  }

  return TRUE;

propagate_error:
  {
    return FALSE;
  }
}

static gboolean
gum_elf_module_load_section_details (GumElfModule * self,
                                     GError ** error)
{
  const GumElfShdr * strings_shdr;
  gconstpointer data;
  gsize size;
  const gchar * strings;
  guint n, i;

  strings_shdr =
      gum_elf_module_find_section_header_by_index (self, self->ehdr.shstrndx);
  if (strings_shdr == NULL)
    return TRUE;

  data = gum_elf_module_get_file_data (self, &size);

  strings = (const gchar *) data + strings_shdr->offset;

  n = self->shdrs->len;
  g_array_set_size (self->sections, n);

  for (i = 0; i != n; i++)
  {
    const GumElfShdr * shdr =
        &g_array_index (self->shdrs, GumElfShdr, i);
    GumElfSectionDetails * d =
        &g_array_index (self->sections, GumElfSectionDetails, i);
    const gchar * name = strings + shdr->name;

    GUM_CHECK_STR_BOUNDS (name, "section name");

    if (name[0] != '\0')
    {
      d->id = g_strdup_printf ("%u%s%s",
          i,
          (name[0] != '.') ? "." : "",
          name);
    }
    else
    {
      d->id = g_strdup_printf ("%u", i);
    }
    d->name = name;
    d->type = shdr->type;
    d->flags = shdr->flags;
    d->address = gum_elf_module_translate_to_online (self, shdr->addr);
    d->offset = shdr->offset;
    d->size = shdr->size;
    d->link = shdr->link;
    d->info = shdr->info;
    d->alignment = shdr->addralign;
    d->entry_size = shdr->entsize;
    if (!gum_elf_module_find_address_protection (self, shdr->addr,
        &d->protection))
    {
      d->protection = GUM_PAGE_NO_ACCESS;
    }
  }

  return TRUE;

propagate_error:
  {
    g_array_set_size (self->sections, 0);

    return FALSE;
  }
}

static void
gum_elf_section_details_clear (GumElfSectionDetails * d)
{
  g_clear_pointer ((gchar **) &d->id, g_free);
}

static gboolean
gum_elf_module_load_dynamic_entries (GumElfModule * self,
                                     GError ** error)
{
  const GumElfPhdr * phdr;
  gconstpointer data;
  gsize size, entry_size, n;
  gconstpointer start, end, cursor;
  gsize i;

  phdr = gum_elf_module_find_phdr_by_type (self, GUM_ELF_PHDR_DYNAMIC);
  if (phdr == NULL)
    return TRUE;

  data = gum_elf_module_get_live_data (self, &size);

  entry_size = (self->ehdr.identity.klass == GUM_ELF_CLASS_64)
      ? sizeof (GumElfDyn)
      : sizeof (GumElfDyn32);
  n = phdr->filesz / entry_size;

  start = (self->source_mode == GUM_ELF_SOURCE_MODE_ONLINE)
      ? GSIZE_TO_POINTER (
          gum_elf_module_translate_to_online (self, phdr->vaddr))
      : (const guint8 *) data + phdr->offset;
  end = (const guint8 *) start + (n * entry_size);
  GUM_CHECK_BOUNDS (start, end, "dynamic entries");

  g_array_set_size (self->dyns, n);

  cursor = start;
  for (i = 0; i != n; i++)
  {
    GumElfDyn * dst = &g_array_index (self->dyns, GumElfDyn, i);

#define GUM_READ_DYN_FIELD(name, type) \
    GUM_READ (dst->name, src->name, type)
#define GUM_READ_DYN() \
    G_STMT_START \
    { \
      GUM_READ_DYN_FIELD (tag, int64); \
      GUM_READ_DYN_FIELD (val, uint64); \
    } \
    G_STMT_END
#define GUM_READ_DYN32() \
    G_STMT_START \
    { \
      GUM_READ_DYN_FIELD (tag, int32); \
      GUM_READ_DYN_FIELD (val, uint32); \
    } \
    G_STMT_END

    switch (self->ehdr.identity.klass)
    {
      case GUM_ELF_CLASS_64:
      {
        const GumElfDyn * src = cursor;
        GUM_READ_DYN ();
        break;
      }
      case GUM_ELF_CLASS_32:
      {
        const GumElfDyn32 * src = cursor;
        GUM_READ_DYN32 ();
        break;
      }
      default:
        g_assert_not_reached ();
    }

#undef GUM_READ_DYN_FIELD
#undef GUM_READ_DYN
#undef GUM_READ_DYN32

    cursor = (const guint8 *) cursor + entry_size;
  }

  return TRUE;

propagate_error:
  {
    return FALSE;
  }
}

static gconstpointer
gum_elf_module_get_live_data (GumElfModule * self,
                              gsize * size)
{
  if (self->source_mode == GUM_ELF_SOURCE_MODE_ONLINE)
  {
    *size = self->mapped_size;
    return GSIZE_TO_POINTER (self->base_address);
  }
  else
  {
    *size = self->file_size;
    return self->file_data;
  }
}

static void
gum_elf_module_unload (GumElfModule * self)
{
  self->dynamic_strings = NULL;
  self->dynamic_address_state = GUM_ELF_DYNAMIC_ADDRESS_PRISTINE;
  self->mapped_size = GUM_ELF_DEFAULT_MAPPED_SIZE;
  self->preferred_address = 0;

  g_array_set_size (self->sections, 0);

  g_array_set_size (self->dyns, 0);
  g_array_set_size (self->shdrs, 0);
  g_array_set_size (self->phdrs, 0);
  memset (&self->ehdr, 0, sizeof (self->ehdr));

  g_bytes_unref (self->file_bytes);
  self->file_bytes = NULL;
  self->file_data = NULL;
  self->file_size = 0;
}

GumElfType
gum_elf_module_get_etype (GumElfModule * self)
{
  return self->ehdr.type;
}

guint
gum_elf_module_get_pointer_size (GumElfModule * self)
{
  return (self->ehdr.identity.klass == GUM_ELF_CLASS_64) ? 8 : 4;
}

gint
gum_elf_module_get_byte_order (GumElfModule * self)
{
  return (self->ehdr.identity.data_encoding == GUM_ELF_DATA_ENCODING_LSB)
      ? G_LITTLE_ENDIAN
      : G_BIG_ENDIAN;
}

GumElfOSABI
gum_elf_module_get_os_abi (GumElfModule * self)
{
  return self->ehdr.identity.os_abi;
}

guint8
gum_elf_module_get_os_abi_version (GumElfModule * self)
{
  return self->ehdr.identity.os_abi_version;
}

GumElfMachine
gum_elf_module_get_machine (GumElfModule * self)
{
  return self->ehdr.machine;
}

GumAddress
gum_elf_module_get_base_address (GumElfModule * self)
{
  return self->base_address;
}

GumAddress
gum_elf_module_get_preferred_address (GumElfModule * self)
{
  return self->preferred_address;
}

guint64
gum_elf_module_get_mapped_size (GumElfModule * self)
{
  return self->mapped_size;
}

GumAddress
gum_elf_module_get_entrypoint (GumElfModule * self)
{
  GumAddress entrypoint = self->ehdr.entry;

  if (self->ehdr.type == GUM_ELF_DYN)
    entrypoint += self->base_address;

  return gum_elf_module_translate_to_online (self, entrypoint);
}

const gchar *
gum_elf_module_get_interpreter (GumElfModule * self)
{
  guint i;

  for (i = 0; i != self->phdrs->len; i++)
  {
    const GumElfPhdr * phdr = &g_array_index (self->phdrs, GumElfPhdr, i);

    if (phdr->type == GUM_ELF_PHDR_INTERP)
    {
      gconstpointer data;
      gsize size;
      const gchar * interp;

      data = gum_elf_module_get_file_data (self, &size);

      interp = (const gchar *) data + phdr->offset;
      if (!gum_elf_module_check_str_bounds (self, interp, data, size, "interp",
            NULL))
      {
        return NULL;
      }

      return interp;
    }
  }

  return NULL;
}

const gchar *
gum_elf_module_get_source_path (GumElfModule * self)
{
  return self->source_path;
}

GBytes *
gum_elf_module_get_source_blob (GumElfModule * self)
{
  return self->source_blob;
}

GumElfSourceMode
gum_elf_module_get_source_mode (GumElfModule * self)
{
  return self->source_mode;
}

gconstpointer
gum_elf_module_get_file_data (GumElfModule * self,
                              gsize * size)
{
  if (size != NULL)
    *size = self->file_size;

  return self->file_data;
}

void
gum_elf_module_enumerate_segments (GumElfModule * self,
                                   GumFoundElfSegmentFunc func,
```