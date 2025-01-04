Response:
The user wants a summary of the functionality of the `gumswiftapiresolver.c` file, which is part of the Frida dynamic instrumentation tool. The summary should include explanations related to reverse engineering, binary/kernel/framework aspects, logical reasoning, common usage errors, and debugging.

Here's a plan to address the request:

1. **Identify the core purpose:** The file is named `gumswiftapiresolver.c` and has a descriptive comment about resolving APIs in Swift modules. This is the central function.

2. **Break down functionalities by looking at key data structures and function names:**
    - `GumSwiftApiResolver`: The main class, holding modules and query patterns.
    - `GumModuleMetadata`:  Stores information about loaded Swift modules (name, path, base address, functions, vtables).
    - `GumFunctionMetadata`:  Represents a Swift function with its name and address.
    - `gum_swift_api_resolver_enumerate_matches`: The main function for finding matching APIs based on a query.
    - Functions related to module registration (`gum_swift_api_resolver_register_module`).
    - Functions for collecting exports and sections (`gum_module_metadata_collect_export`, `gum_module_metadata_collect_section`).
    - Functions for handling classes, methods, and overrides (`gum_module_metadata_collect_class`, `gum_class_parse`).
    - Demangling functionality (`gum_demangle`).
    - Thunk ingestion (potentially for vtable resolution) on ARM64.

3. **Relate functionalities to the requested categories:**
    - **Reverse Engineering:**  API resolution is a fundamental reverse engineering technique. The tool helps find and hook specific Swift functions.
    - **Binary/Kernel/Framework:** The code interacts with loaded modules, which are binary files. It reads section information (`__swift5_types`), indicating interaction with the Swift runtime's internal structure. The Darwin/non-Darwin conditional compilation shows platform-specific handling of module loading.
    - **Logical Reasoning:** The process of matching queries to function names involves pattern matching and string comparisons. The thunk ingestion involves analyzing assembly code to deduce vtable information.
    - **User/Programming Errors:** Incorrect query syntax is a possible user error. The "unsupported Swift runtime" error indicates a dependency on the presence of the `swift_demangle_getDemangledName` symbol.
    - **Debugging:** The file is part of the API resolution process, which is crucial for Frida's hooking capabilities. Understanding its functions helps in tracing how Frida finds targets.

4. **Construct the summary, providing examples and explanations for each category.**

5. **Since this is Part 1, focus on the overall functionality and avoid delving too deep into the implementation details of individual functions (that might be for Part 2).**
这是 Frida 动态instrumentation 工具中负责解析 Swift API 的源代码文件。以下是其功能归纳：

**核心功能：Swift API 解析与查找**

`gumswiftapiresolver.c` 的主要功能是 **在运行时动态地查找已加载的 Swift 模块中的函数和方法**，以便 Frida 可以对这些目标进行 hook 或拦截。它实现了 Frida 的 `Gum.ApiResolver` 接口，提供了一种专门针对 Swift 代码的 API 解析机制。

**具体功能点：**

1. **模块管理：**
   - **加载和注册 Swift 模块：** 它负责跟踪当前进程中已加载的 Swift 模块。通过操作系统提供的接口（在 macOS 上使用 `GumDarwinModuleResolver`，其他平台使用 `GumModuleMap`），获取模块的名称、路径和基地址等信息。
   - **存储模块元数据：**  为每个 Swift 模块创建一个 `GumModuleMetadata` 结构体来存储其信息，包括模块名称、路径、基地址以及解析到的函数和虚函数表（vtables）。

2. **API 查询与匹配：**
   - **接收查询字符串：**  接收用户提供的查询字符串，用于指定要查找的 Swift API。查询字符串的格式是 `functions:<模块名>!<函数名>`，并支持大小写不敏感匹配。
   - **模式匹配：** 使用正则表达式 (`GRegex`) 对用户提供的模块名和函数名进行模式匹配。
   - **遍历模块和函数：**  遍历已加载的 Swift 模块，并检查每个模块中解析到的函数是否与查询字符串匹配。

3. **Swift 元数据解析：**
   - **解析 Swift 元数据段：**  读取 Swift 模块的特定段（`__swift5_types`），该段包含了 Swift 类型（包括类、结构体、枚举等）的元数据信息。
   - **解析类型描述符：**  解析 `__swift5_types` 段中的类型描述符 (`GumTypeContextDescriptor` 及其子结构)，从中提取类名、方法信息、虚函数表信息等。
   - **解析方法描述符：** 解析方法描述符 (`GumMethodDescriptor`)，获取方法的实现地址。
   - **处理继承和方法重写：**  识别 Swift 中的继承关系和方法重写，并解析重写方法的实现地址。

4. **虚函数表（VTable）处理：**
   - **识别虚函数表：**  在解析类元数据时，识别类是否包含虚函数表。
   - **提取虚函数表条目：**  提取虚函数表中的方法名称和地址。对于 ARM64 架构，它甚至尝试通过反汇编 "dispatch thunk" 代码来推断虚函数表的信息。

5. **Swift 符号反混淆（Demangling）：**
   - **调用 Swift 反混淆函数：**  依赖于 Swift 运行时提供的 `swift_demangle_getDemangledName` 函数，将 Swift 编译器生成的 mangled 符号名还原成可读的名称。

**与逆向方法的关系及举例：**

`gumswiftapiresolver.c` 显著地与逆向方法相关，因为它使得在运行时定位和分析 Swift 代码成为可能。

**举例：**

假设你想 hook Swift 标准库中的 `String` 类的 `append(_:)` 方法。

1. **逆向分析：** 你可能首先需要通过静态分析工具（如 Hopper 或 IDA Pro）或在线 Swift API 文档来确定该方法的签名，例如 `String.append(_:)`.
2. **Frida 查询：** 使用 Frida 的 `ApiResolver` 功能，结合 `gumswiftapiresolver.c`，你可以构造如下查询：`frida> Swift.String!append` （或 `functions:Swift.String!append`，具体取决于 Frida 的 API）。
3. **动态定位：**  `gumswiftapiresolver.c` 会解析 `Swift` 模块的元数据，找到 `String` 类的描述符，然后在其方法列表中查找以 "append" 开头的方法，并结合参数信息进行匹配。
4. **Hook 操作：**  一旦定位到 `append(_:)` 方法的地址，Frida 就可以在该地址设置 hook，拦截对该方法的调用，从而实现监控参数、修改返回值等逆向分析操作。

**涉及的二进制底层、Linux、Android 内核及框架的知识及举例：**

1. **二进制底层：**
   - **模块加载机制：**  理解操作系统如何加载动态链接库（如 Mach-O 文件在 macOS 上，ELF 文件在 Linux/Android 上）。`GumDarwinModuleResolver` 和 `GumModuleMap` 封装了这些平台的模块枚举和信息获取的细节。
   - **内存布局：**  知道模块在内存中的布局，以及如何通过基地址和偏移量访问模块的数据段和代码段。
   - **符号表：**  了解动态链接库中的符号表结构，以及如何从中获取导出函数的地址和名称。（虽然 `gumswiftapiresolver.c` 主要依赖 Swift 元数据，但在早期阶段或某些情况下可能也会利用符号表信息）。
   - **指令集架构 (ARM64)：**  对于 ARM64 架构，它会进行简单的反汇编来推断虚函数表信息，这需要对 ARM64 指令有一定的了解。

2. **Linux/Android 内核及框架：**
   - **动态链接器：**  理解 Linux 和 Android 中动态链接器（如 `ld-linux.so`）的工作原理，以及它们如何加载和解析共享库。
   - **`/proc` 文件系统：** 在 Linux/Android 上，`GumModuleMap` 可能会使用 `/proc/[pid]/maps` 文件来获取进程加载的模块信息。
   - **Android 框架 (ART)：**  虽然代码没有直接提到 ART，但对于 Android 上的 Swift 应用，最终的二进制可能运行在 ART 虚拟机之上。`gumswiftapiresolver.c` 需要能够解析在 ART 环境中加载的 Swift 模块。

**逻辑推理与假设输入输出：**

**假设输入：**

- **已加载的 Swift 模块：**  假设进程中加载了名为 "MyApp" 和 "SwiftUI" 的 Swift 模块。
- **查询字符串：**  用户输入查询字符串 `"functions:MyApp!MyClass.myMethod"`.

**逻辑推理过程：**

1. **解析查询：** `gumswiftapiresolver.c` 解析查询字符串，提取模块名 "MyApp" 和函数名模式 "MyClass.myMethod"。
2. **遍历模块：**  它会遍历已加载的模块，找到名为 "MyApp" 的模块。
3. **解析元数据：**  解析 "MyApp" 模块的 `__swift5_types` 段，查找名为 "MyClass" 的类的描述符。
4. **查找方法：**  在 "MyClass" 的方法列表中查找名称与 "myMethod" 匹配的方法。
5. **反混淆：**  如果方法名是 mangled 的，则调用 `swift_demangle_getDemangledName` 进行反混淆。
6. **匹配：**  比较反混淆后的方法名是否与查询字符串中的函数名模式匹配。

**假设输出：**

- 如果找到匹配的方法，则返回包含方法名（例如："MyApp.MyClass.myMethod"）和地址的 `GumApiDetails` 结构体。
- 如果未找到匹配的方法，则不会有任何输出（或者在 Frida 的上下文中，`ApiResolver` 的回调函数不会被调用）。

**涉及用户或编程常见的使用错误及举例：**

1. **错误的查询语法：** 用户可能输入错误的查询字符串格式，例如 `"MyApp.myMethod"` 而不是 `"functions:MyApp!MyClass.myMethod"`. 这会导致 `g_regex_match` 失败，从而无法进行后续的查找。
2. **模块名或函数名拼写错误：**  用户提供的模块名或函数名与实际的名称不符。例如，将 "MyClass" 拼写成 "MyClas"。
3. **大小写敏感问题（如果未指定 `/i`）：**  如果查询时未指定大小写不敏感 (`/i`)，但实际的函数名大小写与查询不一致，则可能找不到目标。
4. **尝试在非 Swift 模块中查找 Swift API：** 用户可能错误地尝试在 Objective-C 或 C 模块中查找 Swift API。

**用户操作是如何一步步到达这里的作为调试线索：**

1. **启动 Frida：** 用户首先需要启动 Frida 服务或通过命令行工具 `frida` 连接到目标进程。
2. **编写 Frida 脚本：**  用户编写 JavaScript 代码，使用 Frida 的 `ApiResolver` API 来查找 Swift 函数，例如：
   ```javascript
   const resolver = new ApiResolver('swift');
   resolver.enumerateMatches('functions:MyApp!MyClass.myMethod', {
     onMatch: function(details) {
       console.log('Found:', details.name, 'at', details.address);
     },
     onComplete: function() {
       console.log('Done');
     }
   });
   ```
3. **加载和执行脚本：**  用户将该脚本加载到目标进程中执行。
4. **`ApiResolver` 调用：**  在 JavaScript 代码中创建 `ApiResolver('swift')` 时，Frida 内部会创建 `GumSwiftApiResolver` 的实例。
5. **`enumerateMatches` 调用：** 当 `enumerateMatches` 方法被调用时，最终会调用到 `gum_swift_api_resolver_enumerate_matches` 函数，开始执行 Swift API 的查找过程。

**调试线索：**

如果 Frida 无法找到预期的 Swift 函数，调试时可以关注以下几点：

- **检查查询字符串是否正确。**
- **确认目标 Swift 模块是否已加载到进程中。**
- **验证 Swift 函数名是否拼写正确，包括大小写。**
- **查看 Frida 的日志输出，是否有关于模块加载或 API 解析的错误信息。**
- **使用其他工具（如 `dladdr` 或平台特定的模块枚举 API）来确认目标函数是否真的存在于目标模块中。**
- **检查 Swift 运行时反混淆函数 (`swift_demangle_getDemangledName`) 是否可用。**

**第 1 部分功能归纳：**

`gumswiftapiresolver.c` 的主要功能是 **提供一种机制，用于在 Frida 动态instrumentation 工具中查找和解析已加载的 Swift 模块中的函数和方法**。它通过解析 Swift 模块的元数据段，结合用户提供的查询字符串，实现对 Swift API 的动态定位，为 Frida 对 Swift 代码进行 hook 和分析奠定了基础。 它涉及到操作系统模块加载机制、二进制文件结构、Swift 语言的元数据结构以及符号反混淆等技术。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/gumswiftapiresolver.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2023 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

/**
 * GumSwiftApiResolver:
 *
 * Resolves APIs by searching currently loaded Swift modules.
 *
 * See [iface@Gum.ApiResolver] for more information.
 */

#ifndef GUM_DIET

#include "gumswiftapiresolver.h"

#ifdef HAVE_DARWIN
# include "gum/gumdarwin.h"
#else
# include "gummodulemap.h"
#endif
#include "gumprocess.h"

#include <capstone.h>
#include <string.h>

#define GUM_DESCRIPTOR_FLAGS_KIND(flags) \
    (flags & 0x1f)
#define GUM_DESCRIPTOR_FLAGS_KIND_FLAGS(flags) \
    (flags >> 16)
#define GUM_DESCRIPTOR_FLAGS_IS_GENERIC(flags) \
    ((flags & GUM_DESCRIPTOR_IS_GENERIC) != 0)
#define GUM_DESCRIPTOR_FLAGS_IS_UNIQUE(flags) \
    ((flags & GUM_DESCRIPTOR_IS_UNIQUE) != 0)

#define GUM_ANONYMOUS_DESCRIPTOR_FLAGS_HAS_MANGLED_NAME(flags) \
    ((flags & GUM_ANONYMOUS_DESCRIPTOR_HAS_MANGLED_NAME) != 0)

#define GUM_TYPE_FLAGS_METADATA_INITIALIZATION_MASK(flags) \
    (flags & 3)
#define GUM_TYPE_FLAGS_CLASS_HAS_VTABLE(flags) \
    ((flags & GUM_CLASS_HAS_VTABLE) != 0)
#define GUM_TYPE_FLAGS_CLASS_HAS_OVERRIDE_TABLE(flags) \
    ((flags & GUM_CLASS_HAS_OVERRIDE_TABLE) != 0)
#define GUM_TYPE_FLAGS_CLASS_HAS_RESILIENT_SUPERCLASS(flags) \
    ((flags & GUM_CLASS_HAS_RESILIENT_SUPERCLASS) != 0)

#define GUM_GENERIC_DESCRIPTOR_FLAGS_HAS_TYPE_PACKS(flags) \
    ((flags & GUM_GENERIC_DESCRIPTOR_HAS_TYPE_PACKS) != 0)

#define GUM_METHOD_DESCRIPTOR_IS_ASYNC(desc) \
    (((desc)->flags & GUM_METHOD_ASYNC) != 0)

#define GUM_ALIGN(ptr, type) \
    GUM_ALIGN_POINTER (type *, ptr, G_ALIGNOF (type))

typedef struct _GumModuleMetadata GumModuleMetadata;
typedef struct _GumFunctionMetadata GumFunctionMetadata;
typedef gsize (* GumSwiftDemangle) (const gchar * name, gchar * output,
    gsize length);

typedef struct _GumClass GumClass;

typedef guint GumContextDescriptorKind;
typedef struct _GumContextDescriptor GumContextDescriptor;
typedef struct _GumModuleContextDescriptor GumModuleContextDescriptor;
typedef struct _GumExtensionContextDescriptor GumExtensionContextDescriptor;
typedef struct _GumTypeContextDescriptor GumTypeContextDescriptor;
typedef struct _GumClassDescriptor GumClassDescriptor;
typedef struct _GumGenericContextDescriptorHeader
    GumGenericContextDescriptorHeader;
typedef struct _GumGenericParamDescriptor GumGenericParamDescriptor;
typedef struct _GumGenericRequirementDescriptor GumGenericRequirementDescriptor;
typedef struct _GumTypeGenericContextDescriptorHeader
    GumTypeGenericContextDescriptorHeader;
typedef struct _GumGenericPackShapeHeader GumGenericPackShapeHeader;
typedef struct _GumGenericPackShapeDescriptor GumGenericPackShapeDescriptor;
typedef guint16 GumGenericPackKind;
typedef struct _GumResilientSuperclass GumResilientSuperclass;
typedef struct _GumSingletonMetadataInitialization
    GumSingletonMetadataInitialization;
typedef struct _GumForeignMetadataInitialization
    GumForeignMetadataInitialization;
typedef struct _GumVTableDescriptorHeader GumVTableDescriptorHeader;
typedef struct _GumMethodDescriptor GumMethodDescriptor;
typedef struct _GumOverrideTableHeader GumOverrideTableHeader;
typedef struct _GumMethodOverrideDescriptor GumMethodOverrideDescriptor;

typedef gint32 GumRelativeDirectPtr;
typedef gint32 GumRelativeIndirectPtr;
typedef gint32 GumRelativeIndirectablePtr;

struct _GumSwiftApiResolver
{
  GObject parent;

  GRegex * query_pattern;

  GHashTable * modules;
#ifdef HAVE_DARWIN
  GumDarwinModuleResolver * module_resolver;
#else
  GumModuleMap * all_modules;
#endif
};

struct _GumModuleMetadata
{
  gint ref_count;

  const gchar * name;
  const gchar * path;

  GumAddress base_address;
  GArray * functions;
  GHashTable * vtables;
  GumSwiftApiResolver * resolver;

#ifdef HAVE_DARWIN
  GumDarwinModule * darwin_module;
#endif
};

struct _GumFunctionMetadata
{
  gchar * name;
  GumAddress address;
};

struct _GumClass
{
  gchar * name;

  const GumMethodDescriptor * methods;
  guint num_methods;

  const GumMethodOverrideDescriptor * overrides;
  guint num_overrides;
};

enum _GumContextDescriptorKind
{
  GUM_CONTEXT_DESCRIPTOR_MODULE,
  GUM_CONTEXT_DESCRIPTOR_EXTENSION,
  GUM_CONTEXT_DESCRIPTOR_ANONYMOUS,
  GUM_CONTEXT_DESCRIPTOR_PROTOCOL,
  GUM_CONTEXT_DESCRIPTOR_OPAQUE_TYPE,

  GUM_CONTEXT_DESCRIPTOR_TYPE_FIRST = 16,

  GUM_CONTEXT_DESCRIPTOR_CLASS = GUM_CONTEXT_DESCRIPTOR_TYPE_FIRST,
  GUM_CONTEXT_DESCRIPTOR_STRUCT = GUM_CONTEXT_DESCRIPTOR_TYPE_FIRST + 1,
  GUM_CONTEXT_DESCRIPTOR_ENUM = GUM_CONTEXT_DESCRIPTOR_TYPE_FIRST + 2,

  GUM_CONTEXT_DESCRIPTOR_TYPE_LAST = 31,
};

enum _GumContextDescriptorFlags
{
  GUM_DESCRIPTOR_IS_GENERIC = (1 << 7),
  GUM_DESCRIPTOR_IS_UNIQUE  = (1 << 6),
};

enum _GumAnonymousContextDescriptorFlags
{
  GUM_ANONYMOUS_DESCRIPTOR_HAS_MANGLED_NAME = (1 << 0),
};

enum _GumTypeContextDescriptorFlags
{
  GUM_CLASS_HAS_VTABLE               = (1 << 15),
  GUM_CLASS_HAS_OVERRIDE_TABLE       = (1 << 14),
  GUM_CLASS_HAS_RESILIENT_SUPERCLASS = (1 << 13),
};

enum _GumTypeMetadataInitializationKind
{
  GUM_METADATA_INITIALIZATION_NONE,
  GUM_METADATA_INITIALIZATION_SINGLETON,
  GUM_METADATA_INITIALIZATION_FOREIGN,
};

struct _GumContextDescriptor
{
  guint32 flags;
  GumRelativeIndirectablePtr parent;
};

struct _GumModuleContextDescriptor
{
  GumContextDescriptor context;
  GumRelativeDirectPtr name;
};

struct _GumExtensionContextDescriptor
{
  GumContextDescriptor context;
  GumRelativeDirectPtr extended_context;
};

struct _GumTypeContextDescriptor
{
  GumContextDescriptor context;
  GumRelativeDirectPtr name;
  GumRelativeDirectPtr access_function_ptr;
  GumRelativeDirectPtr fields;
};

struct _GumClassDescriptor
{
  GumTypeContextDescriptor type_context;
  GumRelativeDirectPtr superclass_type;
  guint32 metadata_negative_size_in_words_or_resilient_metadata_bounds;
  guint32 metadata_positive_size_in_words_or_extra_class_flags;
  guint32 num_immediate_members;
  guint32 num_fields;
  guint32 field_offset_vector_offset;
};

struct _GumGenericContextDescriptorHeader
{
  guint16 num_params;
  guint16 num_requirements;
  guint16 num_key_arguments;
  guint16 flags;
};

enum _GumGenericContextDescriptorFlags
{
  GUM_GENERIC_DESCRIPTOR_HAS_TYPE_PACKS = (1 << 0),
};

struct _GumGenericParamDescriptor
{
  guint8 value;
};

struct _GumGenericRequirementDescriptor
{
  guint32 flags;
  GumRelativeDirectPtr param;
  GumRelativeDirectPtr type_or_protocol_or_conformance_or_layout;
};

struct _GumTypeGenericContextDescriptorHeader
{
  GumRelativeDirectPtr instantiation_cache;
  GumRelativeDirectPtr default_instantiation_pattern;
  GumGenericContextDescriptorHeader base;
};

struct _GumGenericPackShapeHeader
{
  guint16 num_packs;
  guint16 num_shape_classes;
};

struct _GumGenericPackShapeDescriptor
{
  GumGenericPackKind kind;
  guint16 index;
  guint16 shape_class;
  guint16 unused;
};

enum _GumGenericPackKind
{
  GUM_GENERIC_PACK_METADATA,
  GUM_GENERIC_PACK_WITNESS_TABLE,
};

struct _GumResilientSuperclass
{
  GumRelativeDirectPtr superclass;
};

struct _GumSingletonMetadataInitialization
{
  GumRelativeDirectPtr initialization_cache;
  GumRelativeDirectPtr incomplete_metadata_or_resilient_pattern;
  GumRelativeDirectPtr completion_function;
};

struct _GumForeignMetadataInitialization
{
  GumRelativeDirectPtr completion_function;
};

struct _GumVTableDescriptorHeader
{
  guint32 vtable_offset;
  guint32 vtable_size;
};

struct _GumMethodDescriptor
{
  guint32 flags;
  GumRelativeDirectPtr impl;
};

enum _GumMethodDescriptorFlags
{
  GUM_METHOD_ASYNC = (1 << 6),
};

struct _GumOverrideTableHeader
{
  guint32 num_entries;
};

struct _GumMethodOverrideDescriptor
{
  GumRelativeIndirectablePtr class;
  GumRelativeIndirectablePtr method;
  GumRelativeDirectPtr impl;
};

static void gum_swift_api_resolver_iface_init (gpointer g_iface,
    gpointer iface_data);
static GumModuleMetadata * gum_swift_api_resolver_register_module (
    GumSwiftApiResolver * self, const gchar * name, const gchar * path,
    GumAddress base_address);
static void gum_swift_api_resolver_finalize (GObject * object);
static void gum_swift_api_resolver_enumerate_matches (
    GumApiResolver * resolver, const gchar * query, GumFoundApiFunc func,
    gpointer user_data, GError ** error);

static void gum_module_metadata_unref (GumModuleMetadata * module);
static GArray * gum_module_metadata_get_functions (GumModuleMetadata * self);
#ifdef HAVE_DARWIN
static gboolean gum_module_metadata_collect_darwin_export (
    const GumDarwinExportDetails * details, gpointer user_data);
static gboolean gum_module_metadata_collect_darwin_section (
    const GumDarwinSectionDetails * details, gpointer user_data);
#endif
static gboolean gum_module_metadata_collect_export (
    const GumExportDetails * details, gpointer user_data);
static gboolean gum_module_metadata_collect_section (
    const GumSectionDetails * details, gpointer user_data);
static void gum_module_metadata_collect_class (GumModuleMetadata * self,
    const GumTypeContextDescriptor * type);
static void gum_module_metadata_maybe_ingest_thunk (GumModuleMetadata * self,
    const gchar * name, GumAddress address);
#ifdef HAVE_ARM64
static gchar * gum_extract_class_name (const gchar * full_name);
static const gchar * gum_find_character_backwards (const gchar * starting_point,
    char needle, const gchar * start);
#endif

static void gum_function_metadata_free (GumFunctionMetadata * function);

static void gum_class_parse (GumClass * klass, const GumClassDescriptor * cd);
static void gum_class_clear (GumClass * klass);

static gconstpointer gum_resolve_method_implementation (
    const GumRelativeDirectPtr * impl, const GumMethodDescriptor * method);

static gchar * gum_compute_context_descriptor_name (
    const GumContextDescriptor * cd);
static void gum_append_demangled_context_name (GString * result,
    const gchar * mangled_name);

static void gum_skip_generic_type_trailers (gconstpointer * trailer_ptr,
    const GumTypeContextDescriptor * t);
static void gum_skip_generic_parts (gconstpointer * trailer_ptr,
    const GumGenericContextDescriptorHeader * h);
static void gum_skip_resilient_superclass_trailer (gconstpointer * trailer_ptr,
    const GumTypeContextDescriptor * t);
static void gum_skip_metadata_initialization_trailers (
    gconstpointer * trailer_ptr, const GumTypeContextDescriptor * t);

static gconstpointer gum_resolve_relative_direct_ptr (
    const GumRelativeDirectPtr * delta);
static gconstpointer gum_resolve_relative_indirect_ptr (
    const GumRelativeIndirectPtr * delta);
static gconstpointer gum_resolve_relative_indirectable_ptr (
    const GumRelativeIndirectablePtr * delta);

static gchar * gum_demangle (const gchar * name);

G_DEFINE_TYPE_EXTENDED (GumSwiftApiResolver,
                        gum_swift_api_resolver,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_API_RESOLVER,
                            gum_swift_api_resolver_iface_init))

static GumSwiftDemangle gum_demangle_impl;

static void
gum_swift_api_resolver_class_init (GumSwiftApiResolverClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_swift_api_resolver_finalize;

  gum_demangle_impl = GUM_POINTER_TO_FUNCPTR (GumSwiftDemangle,
      gum_module_find_export_by_name (NULL, "swift_demangle_getDemangledName"));
}

static void
gum_swift_api_resolver_iface_init (gpointer g_iface,
                                   gpointer iface_data)
{
  GumApiResolverInterface * iface = g_iface;

  iface->enumerate_matches = gum_swift_api_resolver_enumerate_matches;
}

static void
gum_swift_api_resolver_init (GumSwiftApiResolver * self)
{
  self->query_pattern = g_regex_new ("functions:(.+)!([^\\n\\r\\/]+)(\\/i)?",
      0, 0, NULL);

  self->modules = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      (GDestroyNotify) gum_module_metadata_unref);

  {
#ifdef HAVE_DARWIN
    GHashTableIter iter;
    const gchar * name_or_path;
    GumDarwinModule * dm;

    self->module_resolver =
        gum_darwin_module_resolver_new (mach_task_self (), NULL);

    g_hash_table_iter_init (&iter, self->module_resolver->modules);

    while (g_hash_table_iter_next (&iter, (gpointer *) &name_or_path,
          (gpointer *) &dm))
    {
      GumModuleMetadata * module;

      if (name_or_path[0] == '/')
        continue;

      module = gum_swift_api_resolver_register_module (self, name_or_path,
          dm->name, dm->base_address);
      module->darwin_module = dm;
    }
#else
    GArray * entries;
    guint i;

    self->all_modules = gum_module_map_new ();

    entries = gum_module_map_get_values (self->all_modules);
    for (i = 0; i != entries->len; i++)
    {
      GumModuleDetails * d = &g_array_index (entries, GumModuleDetails, i);

      gum_swift_api_resolver_register_module (self, d->name, d->path,
          d->range->base_address);
    }
#endif
  }
}

static GumModuleMetadata *
gum_swift_api_resolver_register_module (GumSwiftApiResolver * self,
                                        const gchar * name,
                                        const gchar * path,
                                        GumAddress base_address)
{
  GumModuleMetadata * module;

  module = g_slice_new0 (GumModuleMetadata);
  module->ref_count = 2;
  module->name = name;
  module->path = path;
  module->base_address = base_address;
  module->functions = NULL;
  module->vtables = g_hash_table_new_full (g_str_hash, g_str_equal,
      g_free, (GDestroyNotify) g_ptr_array_unref);
  module->resolver = self;

  g_hash_table_insert (self->modules, g_strdup (name), module);
  g_hash_table_insert (self->modules, g_strdup (path), module);

  return module;
}

static void
gum_swift_api_resolver_finalize (GObject * object)
{
  GumSwiftApiResolver * self = GUM_SWIFT_API_RESOLVER (object);

#ifdef HAVE_DARWIN
  g_object_unref (self->module_resolver);
#else
  g_object_unref (self->all_modules);
#endif

  g_hash_table_unref (self->modules);

  g_regex_unref (self->query_pattern);

  G_OBJECT_CLASS (gum_swift_api_resolver_parent_class)->finalize (object);
}

/**
 * gum_swift_api_resolver_new:
 *
 * Creates a new resolver that searches exports and imports of currently loaded
 * modules.
 *
 * Returns: (transfer full): the newly created resolver instance
 */
GumApiResolver *
gum_swift_api_resolver_new (void)
{
  return g_object_new (GUM_TYPE_SWIFT_API_RESOLVER, NULL);
}

static void
gum_swift_api_resolver_enumerate_matches (GumApiResolver * resolver,
                                          const gchar * query,
                                          GumFoundApiFunc func,
                                          gpointer user_data,
                                          GError ** error)
{
  GumSwiftApiResolver * self = GUM_SWIFT_API_RESOLVER (resolver);
  GMatchInfo * query_info;
  gboolean ignore_case;
  gchar * module_query, * func_query;
  GPatternSpec * module_spec, * func_spec;
  GHashTableIter module_iter;
  GHashTable * seen_modules;
  gboolean carry_on;
  GumModuleMetadata * module;

  if (gum_demangle_impl == NULL)
    goto unsupported_runtime;

  g_regex_match (self->query_pattern, query, 0, &query_info);
  if (!g_match_info_matches (query_info))
    goto invalid_query;

  ignore_case = g_match_info_get_match_count (query_info) >= 5;

  module_query = g_match_info_fetch (query_info, 1);
  func_query = g_match_info_fetch (query_info, 2);

  g_match_info_free (query_info);

  if (ignore_case)
  {
    gchar * str;

    str = g_utf8_strdown (module_query, -1);
    g_free (module_query);
    module_query = str;

    str = g_utf8_strdown (func_query, -1);
    g_free (func_query);
    func_query = str;
  }

  module_spec = g_pattern_spec_new (module_query);
  func_spec = g_pattern_spec_new (func_query);

  g_hash_table_iter_init (&module_iter, self->modules);
  seen_modules = g_hash_table_new (NULL, NULL);
  carry_on = TRUE;

  while (carry_on &&
      g_hash_table_iter_next (&module_iter, NULL, (gpointer *) &module))
  {
    const gchar * module_name = module->name;
    const gchar * module_path = module->path;
    gchar * module_name_copy = NULL;
    gchar * module_path_copy = NULL;

    if (g_hash_table_contains (seen_modules, module))
      continue;
    g_hash_table_add (seen_modules, module);

    if (ignore_case)
    {
      module_name_copy = g_utf8_strdown (module_name, -1);
      module_name = module_name_copy;

      module_path_copy = g_utf8_strdown (module_path, -1);
      module_path = module_path_copy;
    }

    if (g_pattern_spec_match_string (module_spec, module_name) ||
        g_pattern_spec_match_string (module_spec, module_path))
    {
      GArray * functions;
      guint i;

      functions = gum_module_metadata_get_functions (module);

      for (i = 0; carry_on && i != functions->len; i++)
      {
        const GumFunctionMetadata * f =
            &g_array_index (functions, GumFunctionMetadata, i);

        if (g_pattern_spec_match_string (func_spec, f->name))
        {
          GumApiDetails details;

          details.name = g_strconcat (
              module->path,
              "!",
              f->name,
              NULL);
          details.address = f->address;
          details.size = GUM_API_SIZE_NONE;

          carry_on = func (&details, user_data);

          g_free ((gpointer) details.name);
        }
      }
    }

    g_free (module_path_copy);
    g_free (module_name_copy);
  }

  g_hash_table_unref (seen_modules);

  g_pattern_spec_free (func_spec);
  g_pattern_spec_free (module_spec);

  g_free (func_query);
  g_free (module_query);

  return;

unsupported_runtime:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "unsupported Swift runtime; please file a bug");
  }
invalid_query:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "invalid query; format is: *someModule*!SomeClassPrefix*.*secret*()");
  }
}

static void
gum_module_metadata_unref (GumModuleMetadata * module)
{
  module->ref_count--;
  if (module->ref_count == 0)
  {
    if (module->vtables != NULL)
      g_hash_table_unref (module->vtables);

    if (module->functions != NULL)
      g_array_unref (module->functions);

    g_slice_free (GumModuleMetadata, module);
  }
}

static GArray *
gum_module_metadata_get_functions (GumModuleMetadata * self)
{
  if (self->functions == NULL)
  {
    self->functions = g_array_new (FALSE, FALSE, sizeof (GumFunctionMetadata));
    g_array_set_clear_func (self->functions,
        (GDestroyNotify) gum_function_metadata_free);

    {
#ifdef HAVE_DARWIN
      gum_darwin_module_enumerate_exports (self->darwin_module,
          gum_module_metadata_collect_darwin_export, self);
      gum_darwin_module_enumerate_sections (self->darwin_module,
          gum_module_metadata_collect_darwin_section, self);
#else
      gum_module_enumerate_exports (self->path,
          gum_module_metadata_collect_export, self);
      gum_module_enumerate_sections (self->path,
          gum_module_metadata_collect_section, self);
#endif
    }
  }

  return self->functions;
}

#ifdef HAVE_DARWIN

static gboolean
gum_module_metadata_collect_darwin_export (
    const GumDarwinExportDetails * details,
    gpointer user_data)
{
  GumModuleMetadata * self = user_data;
  GumExportDetails export;

  if (!gum_darwin_module_resolver_resolve_export (
        self->resolver->module_resolver, self->darwin_module,
        details, &export))
  {
    return TRUE;
  }

  return gum_module_metadata_collect_export (&export, user_data);
}

static gboolean
gum_module_metadata_collect_darwin_section (
    const GumDarwinSectionDetails * details,
    gpointer user_data)
{
  GumSectionDetails section;

  section.id = "<unused>";
  section.name = details->section_name;
  section.address = details->vm_address;
  section.size = details->size;

  return gum_module_metadata_collect_section (&section, user_data);
}

#endif

static gboolean
gum_module_metadata_collect_export (const GumExportDetails * details,
                                    gpointer user_data)
{
  GumModuleMetadata * self = user_data;
  gchar * name;
  GumFunctionMetadata func;

  if (details->type != GUM_EXPORT_FUNCTION)
    goto skip;

  name = gum_demangle (details->name);
  if (name == NULL)
    goto skip;

  func.name = name;
  func.address = details->address;
  g_array_append_val (self->functions, func);

  gum_module_metadata_maybe_ingest_thunk (self, name,
      gum_strip_code_address (func.address));

skip:
  return TRUE;
}

static gboolean
gum_module_metadata_collect_section (const GumSectionDetails * details,
                                     gpointer user_data)
{
  GumModuleMetadata * module = user_data;
  gsize n, i;
  GumRelativeDirectPtr * types;

  if (strcmp (details->name, "__swift5_types") != 0)
    return TRUE;

  n = details->size / sizeof (gint32);

  types = GSIZE_TO_POINTER (details->address);

  for (i = 0; i != n; i++)
  {
    const GumTypeContextDescriptor * type;
    guint32 descriptor_flags;

    type = gum_resolve_relative_indirectable_ptr (&types[i]);
    descriptor_flags = type->context.flags;

    switch (GUM_DESCRIPTOR_FLAGS_KIND (descriptor_flags))
    {
      case GUM_CONTEXT_DESCRIPTOR_CLASS:
        gum_module_metadata_collect_class (module, type);
        break;
      default:
        break;
    }
  }

  return TRUE;
}

static void
gum_module_metadata_collect_class (GumModuleMetadata * self,
                                   const GumTypeContextDescriptor * type)
{
  GumClass klass;
  guint i;

  gum_class_parse (&klass, (const GumClassDescriptor *) type);

  if (klass.num_methods != 0)
  {
    GPtrArray * vtable;

    vtable = g_hash_table_lookup (self->vtables, klass.name);

    for (i = 0; i != klass.num_methods; i++)
    {
      const GumMethodDescriptor * method = &klass.methods[i];
      gconstpointer impl;
      GumFunctionMetadata func;

      impl = gum_resolve_method_implementation (&method->impl, method);
      if (impl == NULL)
        continue;

      func.name = NULL;
      if (vtable != NULL && i < vtable->len)
        func.name = g_strdup (g_ptr_array_index (vtable, i));
      if (func.name == NULL)
        func.name = g_strdup_printf ("%s.vtable[%u]", klass.name, i);

      func.address = GUM_ADDRESS (impl);

      g_array_append_val (self->functions, func);
    }
  }

  for (i = 0; i != klass.num_overrides; i++)
  {
    const GumMethodOverrideDescriptor * od = &klass.overrides[i];
    GumClass parent_class;
    const GumMethodDescriptor * parent_method;
    guint vtable_index;
    gconstpointer impl;
    GPtrArray * parent_vtable;
    GumFunctionMetadata func;

    gum_class_parse (&parent_class,
        gum_resolve_relative_indirectable_ptr (&od->class));
    parent_method = gum_resolve_relative_indirectable_ptr (&od->method);
    vtable_index = parent_method - parent_class.methods;

    impl = gum_resolve_method_implementation (&od->impl, parent_method);
    if (impl == NULL)
      continue;

    parent_vtable = g_hash_table_lookup (self->vtables, parent_class.name);

    func.name = NULL;
    if (parent_vtable != NULL && vtable_index < parent_vtable->len)
    {
      const gchar * name = g_ptr_array_index (parent_vtable, vtable_index);
      if (name != NULL)
      {
        func.name = g_strconcat (
            klass.name,
            name + strlen (parent_class.name),
            NULL);
      }
    }
    if (func.name == NULL)
      func.name = g_strdup_printf ("%s.overrides[%u]", klass.name, i);

    func.address = GUM_ADDRESS (impl);

    g_array_append_val (self->functions, func);

    gum_class_clear (&parent_class);
  }

  gum_class_clear (&klass);
}

#ifdef HAVE_ARM64

static void
gum_module_metadata_maybe_ingest_thunk (GumModuleMetadata * self,
                                        const gchar * name,
                                        GumAddress address)
{
  csh capstone;
  const uint8_t * code;
  size_t size;
  cs_insn * insn;
  gint vtable_index, vtable_offsets[18];
  gboolean end_of_thunk;
  guint i;

  if (!g_str_has_prefix (name, "dispatch thunk of "))
    return;

  gum_cs_arch_register_native ();
  cs_open (GUM_DEFAULT_CS_ARCH, GUM_DEFAULT_CS_MODE, &capstone);
  cs_option (capstone, CS_OPT_DETAIL, CS_OPT_ON);

  code = GSIZE_TO_POINTER (address);
  size = 1024;

  insn = cs_malloc (capstone);

  vtable_index = -1;
  for (i = 0; i != G_N_ELEMENTS (vtable_offsets); i++)
    vtable_offsets[i] = -1;
  end_of_thunk = FALSE;

  while (vtable_index == -1 && !end_of_thunk &&
      cs_disasm_iter (capstone, &code, &size, &address, insn))
  {
    const cs_arm64_op * ops = insn->detail->arm64.operands;

#define GUM_REG_IS_TRACKED(reg) (reg >= ARM64_REG_X0 && reg <= ARM64_REG_X17)
#define GUM_REG_INDEX(reg) (reg - ARM64_REG_X0)

    switch (insn->id)
    {
      case ARM64_INS_LDR:
      {
        arm64_reg dst = ops[0].reg;
        const arm64_op_mem * src = &ops[1].mem;

        if (GUM_REG_IS_TRACKED (dst))
        {
          if (!(src->base == ARM64_REG_X20 && src->disp == 0))
          {
            /*
             * ldr x3, [x16, #0xd0]!
             * ...
             * braa x3, x16
             */
            vtable_offsets[GUM_REG_INDEX (dst)] = src->disp;
          }
        }

        break;
      }
      case ARM64_INS_MOV:
      {
        arm64_reg dst = ops[0].reg;
        const cs_arm64_op * src = &ops[1];

        /*
         * mov x17, #0x3b0
         * add x16, x16, x17
         * ldr x7, [x16]
         * ...
         * braa x7, x16
         */
        if (src->type == ARM64_OP_IMM && GUM_REG_IS_TRACKED (dst))
          vtable_offsets[GUM_REG_INDEX (dst)] = src->imm;

        break;
      }
      case ARM64_INS_ADD:
      {
        arm64_reg dst = ops[0].reg;
        arm64_reg left = ops[1].reg;
        const cs_arm64_op * right = &ops[2];
        gint offset;

        if (left == dst)
        {
          if (right->type == ARM64_OP_REG &&
              GUM_REG_IS_TRACKED (right->reg) &&
              (offset = vtable_offsets[GUM_REG_INDEX (right->reg)]) != -1)
          {
            vtable_index = offset / sizeof (gpointer);
          }

          if (right->type == ARM64_OP_IMM)
          {
            vtable_index = right->imm / sizeof (gpointer);
          }
        }

        break;
      }
      case ARM64_INS_BR:
      case ARM64_INS_BRAA:
      case ARM64_INS_BRAAZ:
      case ARM64_INS_BRAB:
      case ARM64_INS_BRABZ:
      case ARM64_INS_BLR:
      case ARM64_INS_BLRAA:
      case ARM64_INS_BLRAAZ:
      case ARM64_INS_BLRAB:
      case ARM64_INS_BLRABZ:
      {
        arm64_reg target = ops[0].reg;
        gint offset;

        switch (insn->id)
        {
          case ARM64_INS_BR:
          case ARM64_INS_BRAA:
          case ARM64_INS_BRAAZ:
          case ARM64_INS_BRAB:
          case ARM64_INS_BRABZ:
            end_of_thunk = TRUE;
            break;
          default:
            break;
        }

        if (GUM_REG_IS_TRACKED (target) &&
            (offset = vtable_offsets[GUM_REG_INDEX (target)]) != -1)
        {
          vtable_index = offset / sizeof (gpointer);
        }

        break;
      }
      case ARM64_INS_RET:
      case ARM64_INS_RETAA:
      case ARM64_INS_RETAB:
        end_of_thunk = TRUE;
        break;
    }

#undef GUM_REG_IS_TRACKED
#undef GUM_REG_INDEX
  }

  cs_free (insn, 1);

  cs_close (&capstone);

  if (vtable_index != -1)
  {
    const gchar * full_name;
    gchar * class_name;
    GPtrArray * vtable;

    full_name = name + strlen ("dispatch thunk of ");
    class_name = gum_extract_class_name (full_name);
    if (class_name == NULL)
      return;

    vtable = g_hash_table_lookup (self->vtables, class_name);
    if (vtable == NULL)
    {
      vtable = g_ptr_array_new_full (64, g_free);
      g_hash_table_insert (self->vtables, g_steal_pointer (&class_name),
          vtable);
    }

    if (vtable_index >= vtable->len)
      g_ptr_array_set_size (vtable, vtable_index + 1);
    g_free (g_ptr_array_index (vtable, vtable_index));
    g_ptr_array_index (vtable, vtable_index) = g_strdup (full_name);

    g_free (class_name);
  }
}

static gchar *
gum_extract_class_name (const gchar * full_name)
{
  const gchar * ch;

  ch = strstr (full_name, " : ");
  if (ch != NULL)
  {
    ch = gum_find_character_backwards (ch, '.', full_name);
    if (ch == NULL)
      return NULL;
  }
  else
  {
    const gchar * start;

    start = g_str_has_prefix (full_name, "(extension in ")
        ? full_name + strlen ("(extension in ")
        : full_name;

    ch = strchr (start, '(');
    if (ch == NULL)
      return NULL;
  }

  ch = gum_find_character_backwards (ch, '.', full_name);
  if (ch == NULL)
    return NULL;

  return g_strndup (full_name, ch - full_name);
}

static const gchar *
gum_find_character_backwards (const gchar * starting_point,
                              char needle,
                              const gchar * start)
{
  const gchar * ch = starting_point;

  while (ch != start)
  {
    ch--;
    if (*ch == needle)
      return ch;
  }

  return NULL;
}

#else

static void
gum_module_metadata_maybe_ingest_thunk (GumModuleMetadata * self,
                                        const gchar * name,
                                        GumAddress address)
{
}

#endif

static void
gum_function_metadata_free (GumFunctionMetadata * function)
{
  g_free (function->name);
}

static void
gum_class_parse (GumClass * klass,
                 const GumClassDescriptor * cd)
{
  const GumTypeContextDescriptor * type;
  gconstpointer trailer;
  guint16 type_flags;

  memset (klass, 0, sizeof (GumClass));

  type = &cd->type_context;

  klass->name = gum_compute_context_descriptor_name (&type->context);

  trailer = cd + 1;

  gum_skip_generic_type_trailers (&trailer, type);

  gum_skip_resilient_superclass_trailer (&trailer, type);

  gum_skip_metadata_initialization_trailers (&trailer, type);

  type_flags = GUM_DESCRIPTOR_FLAGS_KIND_FLAGS (type->context.flags);

  if (GUM_TYPE_FLAGS_CLASS_HAS_VTABLE (type_flags))
  {
    const GumVTableDescriptorHeader * vth;
    const GumMethodDescriptor * methods;

    vth = GUM_ALIGN (trailer, GumVTableDescriptorHeader);
    methods = GUM_ALIGN ((const GumMethodDescriptor *) (vth + 1),
        GumMethodDescriptor);

    klass->methods = methods;
    klass->num_methods = vth->vtable_size;

    trailer = methods + vth->vtable_size;
  }

  if (GUM_TYPE_FLAGS_CLASS_HAS_OVERRIDE_TABLE (type_flags))
  {
    const GumOverrideTableHeader * oth;
    const GumMethodOverrideDescriptor * overrides;

    oth = GUM_ALIGN (trailer, GumOverrideTableHeader);
    overrides = GUM_ALIGN ((const GumMethodOverrideDescriptor *) (oth + 1),
        GumMethodOverrideDescriptor);

    klass->overrides = overrides;
    klass->num_overrides = oth->num_entries;

    trailer = overrides + oth->num_entries;
  }
}

static void
gum_class_clear (GumClass * klass)
{
  g_free (klass->name);
}

static gconstpointer
gum_resolve_method_implementation (const GumRelativeDirectPtr * impl,
                                   const GumMethodDescriptor * method)
{
  gconstpointer address;

  address = gum_resolve_relative_direct_ptr (impl);
  if (address == NULL)
    return NULL;

  if (GUM_METHOD_DESCRIPTOR_IS_ASYNC (method))
    address = gum_resolve_relative_direct_ptr (address);

  return address;
}

static gchar *
gum_compute_context_descriptor_name (const GumContextDescriptor * cd)
{
  GString * name;
  const GumContextDescriptor * cur;
  gboolean reached_toplevel;

  name = g_string_sized_new (16);

  for (cur = cd, reached_toplevel = FALSE;
      cur != NULL && !reached_toplevel;
      cur = gum_resolve_relative_indirectable_ptr (&cur->parent))
  {
    GumContextDescriptorKind kind = GUM_DESCRIPTOR_FLAGS_KIND (cur->flags);

    switch (kind)
    {
      case GUM_CONTEXT_DESCRIPTOR_MODULE:
      {
        const GumModuleContextDescriptor * m =
            (const GumModuleContextDescriptor *) cur;
        if (name->len != 0)
          g_string_prepend_c (name, '.');
        g_string_prepend (name, gum_resolve_relative_direct_ptr (&m->name));
        break;
      }
      case GUM_CONTEXT_DESCRIPTOR_EXTENSION:
      {
        const GumExtensionContextDescriptor * e =
            (const GumExtensionContextDescriptor *) cur;
        GString * part;
        gchar * parent;

        part = g_string_sized_new (64);
        g_string_append (part, "(extension in ");

        parent = gum_compute_context_descriptor_name (
            gum_resolve_relative_indirectable_ptr (&cur->parent));
        g_string_append (part, parent);
        g_free (parent);

        g_string_append (part, "):");

     
"""


```