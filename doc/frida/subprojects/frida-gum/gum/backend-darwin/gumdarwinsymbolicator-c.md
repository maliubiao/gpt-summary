Response:
Let's break down the thought process for analyzing this C code and fulfilling the request.

**1. Understanding the Core Request:**

The fundamental task is to understand the functionality of the `gumdarwinsymbolicator.c` file within the context of Frida, a dynamic instrumentation toolkit. This means identifying its purpose, how it interacts with the operating system (Darwin/macOS), and its relevance to reverse engineering. The request also includes specific prompts about its relationship to reverse engineering, binary internals, kernel/framework knowledge, logical reasoning, common errors, and the user journey to this code.

**2. Initial Code Scan and High-Level Purpose:**

A quick scan reveals several key elements:

* **Includes:**  `gum/...`, `<CoreFoundation/CoreFoundation.h>`, `dlfcn.h`. This suggests it's part of the Frida-Gum library and interacts with macOS system libraries, particularly for symbolication.
* **Data Structures:** `_GumDarwinSymbolicator`, `CSRange`, `CSSymbolicatorRef`, `CSSymbolRef`, etc. These point to the core functionality: working with symbols, addresses, and ranges.
* **Function Prefixes:** `gum_darwin_symbolicator_...`, `gum_cs_...`. This indicates functions specific to the Darwin symbolicator and those related to the CoreSymbolication framework.
* **GObject:** The `G_DEFINE_TYPE` macro signifies that this is a GObject, a fundamental building block in GLib/GTK, implying an object-oriented approach within Frida-Gum.
* **`CSSymbolicator...` function calls:** These are direct calls to the CoreSymbolication framework, which is macOS's API for accessing debugging symbols.

From this initial scan, the core purpose becomes clear: **This file implements a symbolicator for Darwin (macOS) using Apple's CoreSymbolication framework.** It helps to translate memory addresses into human-readable symbol names, file names, and line numbers.

**3. Detailed Analysis - Function by Function (Logical Grouping):**

Now, let's delve deeper into the code, grouping functions by their purpose:

* **Object Lifecycle (Creation, Destruction):** `gum_darwin_symbolicator_new_with_path`, `gum_darwin_symbolicator_new_with_task`, `gum_darwin_symbolicator_load`, `gum_darwin_symbolicator_dispose`, `gum_darwin_symbolicator_finalize`. These manage the creation and destruction of the `GumDarwinSymbolicator` object, including loading the CoreSymbolication framework.
* **Property Management:** `gum_darwin_symbolicator_get_property`, `gum_darwin_symbolicator_set_property`. These handle the object's properties like `path`, `cpu_type`, and `task`.
* **Symbol Resolution (Core Functionality):** `gum_darwin_symbolicator_details_from_address`, `gum_darwin_symbolicator_name_from_address`, `gum_darwin_symbolicator_find_function`, `gum_darwin_symbolicator_find_functions_named`, `gum_darwin_symbolicator_find_functions_matching`. These are the core functions that take an address and try to find corresponding symbol information.
* **Synthesizing Details (Fallback):** `gum_darwin_symbolicator_synthesize_details_from_address`. This function handles cases where CoreSymbolication might not provide full information, likely for dynamically generated code or cases where debug symbols are missing. It uses the Objective-C runtime API to try and resolve method names.
* **Helper Functions (CoreSymbolication Interaction):** `gum_cs_symbol_address`, `gum_cpu_type_to_darwin`, `gum_cs_ensure_library_loaded`, `gum_cs_load_library`, `gum_cs_unload_library`. These functions abstract the interaction with the CoreSymbolication framework.
* **Enumeration Callbacks:** `gum_collect_functions`, `gum_get_section_from_address`. These are callbacks used with CoreSymbolication's enumeration functions to gather function start addresses and section information.
* **Comparison Function:** `gum_compare_collected_functions`. This is used for binary searching the collected function addresses.

**4. Addressing the Specific Prompts:**

Now, with a good understanding of the code, we can address each prompt systematically:

* **Functionality Listing:**  This involves summarizing the purpose of the major function groups identified above.
* **Relationship to Reverse Engineering:**  Think about how symbolication helps reverse engineers. It provides context to raw addresses, making disassembled code much easier to understand. Give concrete examples, like identifying function names and understanding code flow.
* **Binary/Kernel/Framework Knowledge:**  Identify the specific areas where such knowledge is evident. This includes:
    * **Binary 底层:** Understanding of memory addresses, code vs. data sections, function boundaries, CPU architectures (ARM, x86), and the concept of debugging symbols.
    * **Linux:** While the code is Darwin-specific, the *concept* of symbolication is present in Linux. Briefly mentioning similarities or differences (like using `libbfd` instead of CoreSymbolication) adds depth.
    * **Android Kernel/Framework:** Acknowledge that Android has its own symbolication mechanisms (like `unwind` and using symbols from `/system/lib/debug/`). Highlighting the platform-specific nature is important.
* **Logical Reasoning (Input/Output):** Choose a simple function like `gum_darwin_symbolicator_name_from_address`. Provide a hypothetical input address and explain how the code would try to find the corresponding symbol name. Explain the fallback mechanism if no symbol is found.
* **Common Usage Errors:** Consider how a user of the Frida API might misuse the symbolicator. Examples include providing an incorrect path to a binary or trying to symbolize an address from a process without the necessary permissions.
* **User Operation and Debugging:**  Trace a typical Frida workflow that would lead to this code being executed. This usually involves attaching to a process, setting breakpoints, and then using Frida's API to inspect the call stack or get symbol information for a specific address.

**5. Structuring the Response:**

Organize the information logically, using headings and bullet points to make it easy to read and understand. Start with a general overview of the file's purpose and then delve into the specifics. Address each prompt clearly and provide concrete examples.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe focus heavily on the GObject aspects.
* **Correction:** While GObject is present, the *core* functionality revolves around symbolication. Emphasize the interaction with CoreSymbolication.
* **Initial thought:**  Just list the functions.
* **Correction:** Group functions by their logical purpose for better understanding.
* **Initial thought:**  Only talk about macOS.
* **Correction:** Briefly mention Linux and Android to provide broader context and highlight platform differences.
* **Initial thought:**  Provide very technical code-level explanations for each prompt.
* **Correction:** Balance technical details with higher-level explanations and examples that are easier for a wider audience to grasp.

By following this structured analysis, we can effectively understand the code and provide a comprehensive and accurate response to the request.
这是一个Frida动态instrumentation工具的源代码文件，名为 `gumdarwinsymbolicator.c`，其位于Frida项目中的 `frida/subprojects/frida-gum/gum/backend-darwin/` 目录下。从文件名和目录结构可以推断，这个文件专门负责在Darwin（macOS和iOS等操作系统）平台上进行符号化（Symbolication）操作。

**功能列举:**

`gumdarwinsymbolicator.c` 文件的主要功能是：

1. **加载和管理 CoreSymbolication 框架:**  这个文件会动态加载 macOS 的私有框架 `CoreSymbolication.framework`，并使用其中的 API 来获取符号信息。这通过 `dlopen` 和 `dlsym` 等动态链接机制实现。

2. **创建符号化器对象:**  它定义了一个 `GumDarwinSymbolicator` 对象，用于封装符号化的上下文和状态。可以通过文件路径或目标进程的 task 句柄来创建此对象。

3. **根据地址查找符号信息:**  提供了核心功能，即给定一个内存地址，能够查找出该地址对应的符号名、所属模块、源文件名、行号和列号。这通过调用 CoreSymbolication 的 `CSSymbolicatorGetSymbolWithAddressAtTime` 和 `CSSymbolicatorGetSourceInfoWithAddressAtTime` 等函数实现。

4. **根据符号名查找地址:**  支持根据符号名称查找其对应的内存地址。可以使用精确匹配或模式匹配来查找多个符合条件的符号。这通过调用 CoreSymbolication 的 `CSSymbolicatorForeachSymbolWithNameAtTime` 和 `CSSymbolicatorForeachSymbolAtTime` 等函数实现。

5. **处理 Thumb 指令:**  能识别 ARM 架构下的 Thumb 指令，并在返回地址时设置相应的标志位。

6. **合成符号信息:**  在 CoreSymbolication 无法提供完整符号信息的情况下，例如对于动态生成的代码或者 stripped 的二进制文件，它会尝试通过其他方式（如 Objective-C runtime API）来合成符号信息，例如查找 Objective-C 的方法名。

7. **缓存模块信息:**  使用 `GumModuleMap` 来缓存已加载的模块信息，提高效率。

8. **处理 Objective-C 方法:**  与 `gumobjcapiresolver.c` 协同工作，解析 Objective-C 的方法名。

**与逆向方法的关系及举例说明:**

`gumdarwinsymbolicator.c` 文件是逆向工程中非常重要的工具，因为它能够将机器码地址转换为人类可读的符号信息，极大地提高了分析效率。

**举例说明:**

假设在 Frida hook 了一个运行在 iOS 上的应用程序，并且在一个函数调用时命中断点。此时，我们可能得到一个类似于 `0x1b8a340fc` 的内存地址。

使用 `gumdarwinsymbolicator.c` 提供的功能，我们可以将这个地址转换为：

* **符号名:**  可能是 `- [ViewController viewDidLoad]`
* **模块名:**  可能是 `MyApp`
* **源文件名:**  可能是 `ViewController.m`
* **行号:**  可能是 `25`

如果没有符号化，我们只能看到一堆十六进制的机器码，很难理解代码的含义。有了符号信息，我们就能快速定位到具体的函数和代码位置，从而进行更深入的分析，例如了解函数的用途、参数和返回值等。

**涉及到二进制底层、Linux、Android内核及框架的知识的举例说明:**

* **二进制底层:**
    * **内存地址:** 文件处理的核心是内存地址的转换和查找。需要理解程序在内存中的布局，例如代码段、数据段、堆栈等。
    * **CPU 架构:** 代码中区分了不同的 CPU 类型 (`GumCpuType`)，并针对 ARM 架构的 Thumb 指令做了特殊处理。这需要了解不同架构的指令集和调用约定。
    * **符号表:** 符号化本质上是解析二进制文件中的符号表信息。虽然这里使用了 CoreSymbolication 框架，但理解符号表的结构（如 `.symtab`, `.strtab` 等）有助于理解符号化的原理。
    * **动态链接:** 代码中使用了 `dlopen` 和 `dlsym` 来加载和使用 `CoreSymbolication.framework`，这涉及到动态链接的知识。

* **Linux 内核及框架:**
    * 尽管此文件是 Darwin 特有的，但符号化的概念在 Linux 中同样存在。Linux 中可以使用 `libbfd` 库或者直接解析 ELF 文件来获取符号信息。理解 Linux 下的符号化机制有助于对比和理解 Darwin 的实现。
    * Linux 内核也有符号表，用于调试内核模块。虽然这个文件不直接处理 Linux 内核符号，但理解内核符号表的概念是有益的。

* **Android 内核及框架:**
    * Android 也有其符号化机制，虽然不使用 CoreSymbolication。Android 的调试符号通常位于 `/system/lib/debug/` 目录下。Frida 在 Android 上的实现会使用不同的机制来获取符号信息，可能涉及到解析 ELF 文件或者使用 Android 提供的调试接口。
    * Android 框架层也有 Java 和 native 代码的符号化需求，例如在分析 ART 虚拟机或者 native 代码时。

**逻辑推理及假设输入与输出:**

**假设输入:**

* `GumDarwinSymbolicator` 对象已通过 `gum_darwin_symbolicator_new_with_path` 创建，并指定了应用程序的路径，例如 `/Applications/MyApp.app/Contents/MacOS/MyApp`。
* 调用 `gum_darwin_symbolicator_details_from_address` 函数，并传入一个内存地址 `address = 0x100008000`。

**逻辑推理:**

1. 函数首先调用 `CSSymbolicatorGetSymbolWithAddressAtTime` 尝试从 CoreSymbolication 获取符号信息。
2. 如果 CoreSymbolication 找到了对应的符号，例如函数名 `-[AppDelegate application:didFinishLaunchingWithOptions:]`，所属模块 `MyApp`，源文件 `AppDelegate.m`，行号 `30`，则这些信息会被填充到 `GumDebugSymbolDetails` 结构体中。
3. 如果 CoreSymbolication 没有找到精确的符号信息（例如，地址位于一个函数的中间），则会调用 `gum_darwin_symbolicator_synthesize_details_from_address` 尝试合成符号信息。
4. 在合成符号信息时，会查找包含该地址的模块，并尝试使用 Objective-C runtime API (`_gum_objc_api_resolver_find_method_by_address`) 查找最接近的方法名。
5. 最终，`GumDebugSymbolDetails` 结构体包含尽可能多的符号信息。

**输出:**

`GumDebugSymbolDetails` 结构体可能包含以下信息：

```c
details->address = 0x100008000;
strcpy(details->module_name, "MyApp");
strcpy(details->symbol_name, "-[AppDelegate application:didFinishLaunchingWithOptions:]");
strcpy(details->file_name, "/path/to/MyApp/AppDelegate.m"); // 实际路径
details->line_number = 30;
details->column = 5; // 可能的列号
```

**涉及用户或编程常见的使用错误及举例说明:**

1. **未正确加载 CoreSymbolication 框架:** 如果 Frida 运行的环境不允许加载私有框架，或者 CoreSymbolication 框架损坏，会导致符号化失败。Frida 会尝试加载，但如果失败，相关功能将不可用。

2. **传入错误的路径:**  如果使用 `gum_darwin_symbolicator_new_with_path` 创建对象时，提供的路径不是一个有效的 Mach-O 可执行文件，`CSSymbolicatorCreateWithPathAndArchitecture` 会返回 NULL，导致后续操作失败。

   **例如:** 用户可能错误地提供了 `.dylib` 库的路径，而不是主可执行文件的路径。

3. **尝试符号化已卸载模块的地址:**  如果尝试符号化一个已经从进程内存中卸载的模块的地址，CoreSymbolication 可能找不到对应的符号信息。

4. **权限问题:**  如果 Frida 没有足够的权限访问目标进程或其依赖的库，可能无法正确加载符号信息。

5. **CPU 类型不匹配:**  如果在创建 `GumDarwinSymbolicator` 对象时指定了错误的 CPU 类型，可能会导致符号化失败，尤其是在跨架构调试时。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

一个典型的用户操作流程，最终会用到 `gumdarwinsymbolicator.c` 中的功能，可能是这样的：

1. **用户编写 Frida 脚本，用于 hook 一个在 Darwin 系统上运行的应用程序。** 例如，使用 `Frida.attach()` 连接到目标进程。
2. **用户在脚本中设置一个 Interceptor，用于拦截某个函数的调用。** 例如：
   ```javascript
   Interceptor.attach(Module.findExportByName("MyApp", "someFunction"), {
     onEnter: function(args) {
       console.log("Entered someFunction");
       // 获取当前指令的地址
       var address = this.context.pc;
       // 使用 Frida 的 API 获取符号信息
       var symbols = DebugSymbol.fromAddress(address);
       console.log("Symbol:", symbols.name, "Module:", symbols.moduleName, "Offset:", symbols.address.sub(Module.getBaseAddress("MyApp")));
     }
   });
   ```
3. **当目标应用程序执行到被 hook 的函数时，`onEnter` 回调函数被触发。**
4. **在 `onEnter` 函数中，`this.context.pc` 获取了当前指令的地址。**
5. **`DebugSymbol.fromAddress(address)` 函数被调用。**  这个 Frida 的 JavaScript API 最终会调用到 Frida-Gum 的 C 代码。
6. **在 Frida-Gum 的 C 代码中，会根据目标进程的信息，选择合适的符号化器，对于 Darwin 系统，会使用 `gumdarwinsymbolicator.c` 中实现的 `GumDarwinSymbolicator` 对象。**
7. **`gum_darwin_symbolicator_details_from_address` 或 `gum_darwin_symbolicator_name_from_address` 等函数会被调用，传入获取到的内存地址。**
8. **`GumDarwinSymbolicator` 对象内部会调用 CoreSymbolication 的 API，根据地址查找符号信息。**
9. **查找到的符号信息会被封装成 `DebugSymbol` 对象，返回给 JavaScript 脚本。**
10. **用户在控制台上看到输出的符号信息，例如 "Symbol: someFunction, Module: MyApp, Offset: 0x1234"。**

**作为调试线索:**

当用户在使用 Frida 时遇到符号化相关的问题时，例如：

* **没有符号信息输出:**  这可能意味着 CoreSymbolication 无法找到符号，或者 `gumdarwinsymbolicator.c` 加载失败，或者用户提供的地址不正确。
* **输出的符号信息不准确:**  这可能是由于二进制文件被 stripped，或者符号信息过时。
* **Frida 报告 CoreSymbolication 相关错误:**  这通常意味着 `gumdarwinsymbolicator.c` 在加载或使用 CoreSymbolication 框架时遇到了问题。

通过检查 Frida 的错误日志，或者在 Frida 脚本中添加更详细的日志，可以追踪到 `gumdarwinsymbolicator.c` 的执行过程，并判断问题是否出在符号化环节。例如，可以检查 `gum_cs_ensure_library_loaded` 的返回值，或者查看 `CSSymbolicatorGetSymbolWithAddressAtTime` 是否返回了 NULL。理解 `gumdarwinsymbolicator.c` 的工作原理有助于诊断和解决这些符号化问题。

### 提示词
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gumdarwinsymbolicator.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2018-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2021 Abdelrahman Eid <hot3eed@gmail.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gum/gumdarwinsymbolicator.h"

#include "gum-init.h"
#include "gumapiresolver.h"
#include "gumdarwinmodule.h"
#include "gumleb.h"
#include "gummodulemap.h"
#include "gumobjcapiresolver-priv.h"

#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>

#define kCSNull ((CSTypeRef) { NULL, NULL })
#define kCSNow  G_GUINT64_CONSTANT (0x8000000000000000)

typedef struct _CSTypeRef CSTypeRef;
typedef struct _CSRange CSRange;
typedef uint64_t CSTime;

typedef CSTypeRef CSSymbolicatorRef;
typedef CSTypeRef CSSymbolRef;
typedef CSTypeRef CSSymbolOwnerRef;
typedef CSTypeRef CSSourceInfoRef;

typedef int (^ CSEachSymbolBlock) (CSSymbolRef symbol);

typedef struct _GumCollectFunctionsOperation GumCollectFunctionsOperation;
typedef struct _GumCollectedFunction GumCollectedFunction;
typedef struct _GumSectionFromAddressOperation GumSectionFromAddressOperation;

struct _CSTypeRef
{
  void * data;
  void * obj;
};

struct _GumDarwinSymbolicator
{
  GObject object;

  gchar * path;
  GumCpuType cpu_type;

  mach_port_t task;

  CSSymbolicatorRef handle;

  GumApiResolver * objc_resolver;
  GumModuleMap * modules;
};

enum
{
  PROP_0,
  PROP_PATH,
  PROP_CPU_TYPE,
  PROP_TASK,
};

struct _CSRange
{
  uint64_t location;
  uint64_t length;
};

struct _GumCollectFunctionsOperation
{
  GArray * functions;
  gconstpointer linkedit;
  GumDarwinModule * module;
};

struct _GumCollectedFunction
{
  GumAddress address;
  guint64 size;
};

struct _GumSectionFromAddressOperation
{
  GumAddress address;
  GumDarwinSectionDetails sect_details;
};

static void gum_darwin_symbolicator_dispose (GObject * object);
static void gum_darwin_symbolicator_finalize (GObject * object);
static void gum_darwin_symbolicator_get_property (GObject * object,
    guint property_id, GValue * value, GParamSpec * pspec);
static void gum_darwin_symbolicator_set_property (GObject * object,
    guint property_id, const GValue * value, GParamSpec * pspec);
static gboolean gum_darwin_symbolicator_synthesize_details_from_address (
    GumDarwinSymbolicator * self, GumAddress address,
    GumDebugSymbolDetails * details);
static gboolean gum_collect_functions (
    const GumDarwinFunctionStartsDetails * details, gpointer user_data);
static gint gum_compare_collected_functions (const GumCollectedFunction * a,
    const GumCollectedFunction * b);
static gboolean gum_get_section_from_address (
    const GumDarwinSectionDetails * details, gpointer user_data);

static cpu_type_t gum_cpu_type_to_darwin (GumCpuType cpu_type);
static GumAddress gum_cs_symbol_address (CSSymbolRef symbol);

static gboolean gum_cs_ensure_library_loaded (void);
static gpointer gum_cs_load_library (gpointer data);
static void gum_cs_unload_library (void);

G_DEFINE_TYPE (GumDarwinSymbolicator, gum_darwin_symbolicator, G_TYPE_OBJECT)

static void * gum_cs;

#define GUM_DECLARE_CS_FUNC(N, R, A) \
    typedef R (* G_PASTE (G_PASTE (CS, N), Func)) A; \
    static G_PASTE (G_PASTE (CS, N), Func) G_PASTE (CS, N)

GUM_DECLARE_CS_FUNC (IsNull, Boolean, (CSTypeRef cs));
GUM_DECLARE_CS_FUNC (Release, void, (CSTypeRef cs));

GUM_DECLARE_CS_FUNC (SymbolicatorCreateWithPathAndArchitecture,
    CSSymbolicatorRef, (const char * path, cpu_type_t cpu_type));
GUM_DECLARE_CS_FUNC (SymbolicatorCreateWithTask, CSSymbolicatorRef,
    (task_t task));
GUM_DECLARE_CS_FUNC (SymbolicatorGetSymbolWithAddressAtTime, CSSymbolRef,
    (CSSymbolicatorRef symbolicator, mach_vm_address_t address, CSTime time));
GUM_DECLARE_CS_FUNC (SymbolicatorGetSourceInfoWithAddressAtTime,
    CSSourceInfoRef, (CSSymbolicatorRef symbolicator, mach_vm_address_t address,
    CSTime time));
GUM_DECLARE_CS_FUNC (SymbolicatorForeachSymbolAtTime, int,
    (CSSymbolicatorRef symbolicator, CSTime time, CSEachSymbolBlock block));
GUM_DECLARE_CS_FUNC (SymbolicatorForeachSymbolWithNameAtTime, int,
    (CSSymbolicatorRef symbolicator, const char * name, CSTime time,
    CSEachSymbolBlock block));

GUM_DECLARE_CS_FUNC (SymbolGetName, const char *, (CSSymbolRef symbol));
GUM_DECLARE_CS_FUNC (SymbolGetRange, CSRange, (CSSymbolRef symbol));
GUM_DECLARE_CS_FUNC (SymbolGetSymbolOwner, CSSymbolOwnerRef,
    (CSSymbolRef symbol));
GUM_DECLARE_CS_FUNC (SymbolIsFunction, Boolean, (CSSymbolRef symbol));
GUM_DECLARE_CS_FUNC (SymbolIsThumb, Boolean, (CSSymbolRef symbol));

GUM_DECLARE_CS_FUNC (SymbolOwnerGetName, const char *,
    (CSSymbolOwnerRef owner));
GUM_DECLARE_CS_FUNC (SymbolOwnerGetBaseAddress, unsigned long long,
    (CSSymbolOwnerRef owner));

GUM_DECLARE_CS_FUNC (SourceInfoGetPath, const char *,
    (CSSourceInfoRef info));
GUM_DECLARE_CS_FUNC (SourceInfoGetLineNumber, int,
    (CSSourceInfoRef info));
GUM_DECLARE_CS_FUNC (SourceInfoGetColumn, int,
    (CSSourceInfoRef info));

#undef GUM_DECLARE_CS_FUNC

static void
gum_darwin_symbolicator_class_init (GumDarwinSymbolicatorClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_darwin_symbolicator_dispose;
  object_class->finalize = gum_darwin_symbolicator_finalize;
  object_class->get_property = gum_darwin_symbolicator_get_property;
  object_class->set_property = gum_darwin_symbolicator_set_property;

  g_object_class_install_property (object_class, PROP_PATH,
      g_param_spec_string ("path", "Path", "Path", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_CPU_TYPE,
      g_param_spec_uint ("cpu-type", "CpuType", "CPU type", 0, G_MAXUINT,
      GUM_CPU_INVALID, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_TASK,
      g_param_spec_uint ("task", "Task", "Mach task", 0, G_MAXUINT,
      MACH_PORT_NULL, G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS));
}

static void
gum_darwin_symbolicator_init (GumDarwinSymbolicator * self)
{
}

static void
gum_darwin_symbolicator_dispose (GObject * object)
{
  GumDarwinSymbolicator * self = GUM_DARWIN_SYMBOLICATOR (object);

  if (gum_cs_ensure_library_loaded () && !CSIsNull (self->handle))
  {
    CSRelease (self->handle);
    self->handle = kCSNull;
  }

  g_clear_object (&self->modules);
  g_clear_object (&self->objc_resolver);

  G_OBJECT_CLASS (gum_darwin_symbolicator_parent_class)->dispose (object);
}

static void
gum_darwin_symbolicator_finalize (GObject * object)
{
  GumDarwinSymbolicator * self = GUM_DARWIN_SYMBOLICATOR (object);

  g_free (self->path);

  G_OBJECT_CLASS (gum_darwin_symbolicator_parent_class)->finalize (object);
}

static void
gum_darwin_symbolicator_get_property (GObject * object,
                                      guint property_id,
                                      GValue * value,
                                      GParamSpec * pspec)
{
  GumDarwinSymbolicator * self = GUM_DARWIN_SYMBOLICATOR (object);

  switch (property_id)
  {
    case PROP_PATH:
      g_value_set_string (value, self->path);
      break;
    case PROP_CPU_TYPE:
      g_value_set_uint (value, self->cpu_type);
      break;
    case PROP_TASK:
      g_value_set_uint (value, self->task);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_darwin_symbolicator_set_property (GObject * object,
                                      guint property_id,
                                      const GValue * value,
                                      GParamSpec * pspec)
{
  GumDarwinSymbolicator * self = GUM_DARWIN_SYMBOLICATOR (object);

  switch (property_id)
  {
    case PROP_PATH:
      g_free (self->path);
      self->path = g_value_dup_string (value);
      break;
    case PROP_CPU_TYPE:
      self->cpu_type = g_value_get_uint (value);
      break;
    case PROP_TASK:
      self->task = g_value_get_uint (value);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

GumDarwinSymbolicator *
gum_darwin_symbolicator_new_with_path (const gchar * path,
                                       GumCpuType cpu_type,
                                       GError ** error)
{
  GumDarwinSymbolicator * symbolicator;

  symbolicator = g_object_new (GUM_DARWIN_TYPE_SYMBOLICATOR,
      "path", path,
      NULL);
  if (!gum_darwin_symbolicator_load (symbolicator, error))
  {
    g_object_unref (symbolicator);
    symbolicator = NULL;
  }

  return symbolicator;
}

GumDarwinSymbolicator *
gum_darwin_symbolicator_new_with_task (mach_port_t task,
                                       GError ** error)
{
  GumDarwinSymbolicator * symbolicator;

  symbolicator = g_object_new (GUM_DARWIN_TYPE_SYMBOLICATOR,
      "task", task,
      NULL);
  if (!gum_darwin_symbolicator_load (symbolicator, error))
  {
    g_object_unref (symbolicator);
    symbolicator = NULL;
  }

  return symbolicator;
}

gboolean
gum_darwin_symbolicator_load (GumDarwinSymbolicator * self,
                              GError ** error)
{
  if (!gum_cs_ensure_library_loaded ())
    goto not_available;

  if (!CSIsNull (self->handle))
    return TRUE;

  if (self->path != NULL)
  {
    self->handle = CSSymbolicatorCreateWithPathAndArchitecture (self->path,
        gum_cpu_type_to_darwin (self->cpu_type));
    if (CSIsNull (self->handle))
      goto invalid_path;
  }
  else
  {
    self->handle = CSSymbolicatorCreateWithTask (self->task);
    if (CSIsNull (self->handle))
      goto invalid_task;
  }

  return TRUE;

not_available:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "CoreSymbolication not available");
    return FALSE;
  }
invalid_path:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "File not found");
    return FALSE;
  }
invalid_task:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "Target process is gone");
    return FALSE;
  }
}

gboolean
gum_darwin_symbolicator_details_from_address (GumDarwinSymbolicator * self,
                                              GumAddress address,
                                              GumDebugSymbolDetails * details)
{
  CSSymbolRef symbol;
  CSSymbolOwnerRef owner;
  const char * name;
  CSSourceInfoRef info;

  symbol = CSSymbolicatorGetSymbolWithAddressAtTime (self->handle, address,
      kCSNow);
  if (CSIsNull (symbol))
  {
    return gum_darwin_symbolicator_synthesize_details_from_address (self,
        address, details);
  }

  owner = CSSymbolGetSymbolOwner (symbol);

  details->address = address;
  g_strlcpy (details->module_name, CSSymbolOwnerGetName (owner),
      sizeof (details->module_name));
  name = CSSymbolGetName (symbol);
  if (name != NULL)
  {
    g_strlcpy (details->symbol_name, name, sizeof (details->symbol_name));
  }
  else if (!gum_darwin_symbolicator_synthesize_details_from_address (self,
      address, details))
  {
    sprintf (details->symbol_name, "0x%zx",
        (size_t) ((unsigned long long) details->address -
            CSSymbolOwnerGetBaseAddress (owner)));
  }

  info = CSSymbolicatorGetSourceInfoWithAddressAtTime (self->handle,
      GPOINTER_TO_SIZE (address), kCSNow);
  if (!CSIsNull (info))
  {
    gchar * canonicalized;

    canonicalized = g_canonicalize_filename (CSSourceInfoGetPath (info), "/");
    g_strlcpy (details->file_name, canonicalized, sizeof (details->file_name));
    g_free (canonicalized);
    details->line_number = CSSourceInfoGetLineNumber (info);
    details->column = CSSourceInfoGetColumn (info);
  }
  else
  {
    details->file_name[0] = '\0';
    details->line_number = 0;
    details->column = 0;
  }

  return TRUE;
}

gchar *
gum_darwin_symbolicator_name_from_address (GumDarwinSymbolicator * self,
                                           GumAddress address)
{
  gchar * result;
  CSSymbolRef symbol;
  const char * name;

  symbol = CSSymbolicatorGetSymbolWithAddressAtTime (self->handle, address,
      kCSNow);
  if (CSIsNull (symbol))
    return NULL;

  name = CSSymbolGetName (symbol);
  if (name != NULL)
  {
    result = g_strdup (name);
  }
  else
  {
    CSSymbolOwnerRef owner;

    owner = CSSymbolGetSymbolOwner (symbol);

    result = g_strdup_printf ("0x%lx", (long) ((unsigned long long) address -
        CSSymbolOwnerGetBaseAddress (owner)));
  }

  return result;
}

GumAddress
gum_darwin_symbolicator_find_function (GumDarwinSymbolicator * self,
                                       const gchar * name)
{
  __block GumAddress result = 0;

  CSSymbolicatorForeachSymbolWithNameAtTime (self->handle, name, kCSNow,
      ^(CSSymbolRef symbol)
  {
    if (result == 0 && CSSymbolIsFunction (symbol))
      result = gum_cs_symbol_address (symbol);
    return 0;
  });

  return result;
}

GumAddress *
gum_darwin_symbolicator_find_functions_named (GumDarwinSymbolicator * self,
                                              const gchar * name,
                                              gsize * len)
{
  GArray * result;

  result = g_array_new (FALSE, FALSE, sizeof (GumAddress));

  CSSymbolicatorForeachSymbolWithNameAtTime (self->handle, name, kCSNow,
      ^(CSSymbolRef symbol)
  {
    if (CSSymbolIsFunction (symbol))
    {
      GumAddress address = gum_cs_symbol_address (symbol);
      g_array_append_val (result, address);
    }
    return 0;
  });

  *len = result->len;

  return (GumAddress *) g_array_free (result, FALSE);
}

GumAddress *
gum_darwin_symbolicator_find_functions_matching (GumDarwinSymbolicator * self,
                                                 const gchar * str,
                                                 gsize * len)
{
  GArray * result;
  GPatternSpec * pspec;

  result = g_array_new (FALSE, FALSE, sizeof (GumAddress));

  pspec = g_pattern_spec_new (str);

  CSSymbolicatorForeachSymbolAtTime (self->handle, kCSNow,
      ^(CSSymbolRef symbol)
  {
    if (CSSymbolIsFunction (symbol))
    {
      const char * name = CSSymbolGetName (symbol);
      if (name != NULL && g_pattern_match_string (pspec, name))
      {
        GumAddress address = gum_cs_symbol_address (symbol);
        g_array_append_val (result, address);
      }
    }
    return 0;
  });

  g_pattern_spec_free (pspec);

  *len = result->len;

  return (GumAddress *) g_array_free (result, FALSE);
}

static gboolean
gum_darwin_symbolicator_synthesize_details_from_address (
    GumDarwinSymbolicator * self,
    GumAddress address,
    GumDebugSymbolDetails * details)
{
  gboolean success = FALSE;
  const GumModuleDetails * module_details;
  GumDarwinModule * module = NULL;
  GumCollectFunctionsOperation op = { NULL, NULL, NULL };
  GumCollectedFunction key, * match;
  gchar * symbol_name = NULL;

  if (self->objc_resolver == NULL)
  {
    GumApiResolver * resolver = gum_api_resolver_make ("objc");
    if (resolver == NULL)
      goto beach;
    self->objc_resolver = resolver;
  }

  if (self->modules == NULL)
    self->modules = gum_module_map_new ();

  module_details = gum_module_map_find (self->modules, address);
  if (module_details == NULL)
    goto beach;

  module = gum_darwin_module_new_from_memory (module_details->path, self->task,
      module_details->range->base_address, GUM_DARWIN_MODULE_FLAGS_NONE, NULL);
  if (!gum_darwin_module_ensure_image_loaded (module, NULL))
    goto beach;

  op.functions = g_array_new (FALSE, FALSE, sizeof (GumCollectedFunction));
  op.linkedit = module->image->data;
  op.module = module;

  gum_darwin_module_enumerate_function_starts (module, gum_collect_functions,
      &op);

  key.address = gum_strip_code_address (address);
  key.size = 0;

  match = bsearch (&key, op.functions->data, op.functions->len,
      sizeof (GumCollectedFunction),
      (GCompareFunc) gum_compare_collected_functions);
  if (match == NULL)
    goto beach;

  symbol_name = _gum_objc_api_resolver_find_method_by_address (
      self->objc_resolver, match->address);
  if (symbol_name == NULL)
    goto beach;

  success = TRUE;

  details->address = address;
  g_strlcpy (details->symbol_name, symbol_name, sizeof (details->symbol_name));
  g_strlcpy (details->module_name, module->name, sizeof (details->module_name));

beach:
  if (!success && module != NULL)
  {
    sprintf (details->symbol_name, "0x%zx (0x%zx)",
        (size_t) (address - module->base_address),
        (size_t) (module->preferred_address +
          (address - module->base_address)));
    success = TRUE;
  }

  g_free (symbol_name);
  g_clear_pointer (&op.functions, g_array_unref);
  g_clear_object (&module);

  return success;
}

static gboolean
gum_collect_functions (const GumDarwinFunctionStartsDetails * details,
                       gpointer user_data)
{
  GumCollectFunctionsOperation * op = user_data;
  GArray * functions = op->functions;
  const guint8 * p, * end;
  guint i, offset;

  p = GSIZE_TO_POINTER (details->vm_address);
  end = p + details->size;

  for (i = 0, offset = 0; p != end; i++)
  {
    guint64 delta;
    GumCollectedFunction function;

    delta = gum_read_uleb128 (&p, end);
    if (delta == 0)
      break;

    if (i != 0)
    {
      GumCollectedFunction * prev_function =
          &g_array_index (functions, GumCollectedFunction, i - 1);
      prev_function->size = delta;
    }

    offset += delta;

    function.address = GUM_ADDRESS (op->linkedit + offset);
    function.size = 0;
    g_array_append_val (functions, function);
  }

  if (functions->len != 0)
  {
    GumCollectedFunction * last_function;
    GumSectionFromAddressOperation sfa_op = { 0, };
    const GumDarwinSectionDetails * sect;

    last_function =
        &g_array_index (functions, GumCollectedFunction, functions->len - 1);

    sfa_op.address = last_function->address;
    gum_darwin_module_enumerate_sections (op->module,
        gum_get_section_from_address, &sfa_op);

    sect = &sfa_op.sect_details;
    last_function->size =
        (sect->vm_address + sect->size) - last_function->address;
  }

  return TRUE;
}

static gint
gum_compare_collected_functions (const GumCollectedFunction * key,
                                 const GumCollectedFunction * f)
{
  GumAddress p = key->address;

  if (p >= f->address && p < f->address + f->size)
    return 0;

  return p < f->address ? -1 : 1;
}

static gboolean
gum_get_section_from_address (const GumDarwinSectionDetails * details,
                              gpointer user_data)
{
  GumSectionFromAddressOperation * op = user_data;
  GumAddress address = op->address;

  if (address >= details->vm_address &&
      address < details->vm_address + details->size)
  {
    op->sect_details = *details;
    return FALSE;
  }

  return TRUE;
}

static cpu_type_t
gum_cpu_type_to_darwin (GumCpuType cpu_type)
{
  switch (cpu_type)
  {
    case GUM_CPU_IA32:  return CPU_TYPE_I386;
    case GUM_CPU_AMD64: return CPU_TYPE_X86_64;
    case GUM_CPU_ARM:   return CPU_TYPE_ARM;
    case GUM_CPU_ARM64: return CPU_TYPE_ARM64;
    default:
      break;
  }

  return CPU_TYPE_ANY;
}

static GumAddress
gum_cs_symbol_address (CSSymbolRef symbol)
{
  uint64_t address;

  address = CSSymbolGetRange (symbol).location;

  if (CSSymbolIsThumb (symbol))
    address |= 1;

  if (CSSymbolIsFunction (symbol))
    address = gum_sign_code_address (address);

  return address;
}

static gboolean
gum_cs_ensure_library_loaded (void)
{
  static GOnce init_once = G_ONCE_INIT;

  g_once (&init_once, gum_cs_load_library, NULL);

  return GPOINTER_TO_SIZE (init_once.retval);
}

static gpointer
gum_cs_load_library (gpointer data)
{
  void * cf;

  /*
   * CoreFoundation must be loaded by the main thread, so we should avoid
   * loading it. This must be done by the user of frida-gum explicitly.
   */
  cf = dlopen ("/System/Library/Frameworks/"
      "CoreFoundation.framework/CoreFoundation",
      RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD);
  if (cf == NULL)
    return NULL;
  dlclose (cf);

  gum_cs = dlopen ("/System/Library/PrivateFrameworks/"
      "CoreSymbolication.framework/CoreSymbolication",
      RTLD_LAZY | RTLD_GLOBAL);
  if (gum_cs == NULL)
    goto api_error;

#define GUM_TRY_ASSIGN(name) \
    G_PASTE (CS, name) = dlsym (gum_cs, G_STRINGIFY (G_PASTE (CS, name))); \
    if (G_PASTE (CS, name) == NULL) \
      goto api_error

  GUM_TRY_ASSIGN (IsNull);
  GUM_TRY_ASSIGN (Release);

  GUM_TRY_ASSIGN (SymbolicatorCreateWithPathAndArchitecture);
  GUM_TRY_ASSIGN (SymbolicatorCreateWithTask);
  GUM_TRY_ASSIGN (SymbolicatorGetSymbolWithAddressAtTime);
  GUM_TRY_ASSIGN (SymbolicatorGetSourceInfoWithAddressAtTime);
  GUM_TRY_ASSIGN (SymbolicatorForeachSymbolAtTime);
  GUM_TRY_ASSIGN (SymbolicatorForeachSymbolWithNameAtTime);

  GUM_TRY_ASSIGN (SymbolGetName);
  GUM_TRY_ASSIGN (SymbolGetRange);
  GUM_TRY_ASSIGN (SymbolGetSymbolOwner);
  GUM_TRY_ASSIGN (SymbolIsFunction);
  GUM_TRY_ASSIGN (SymbolIsThumb);

  GUM_TRY_ASSIGN (SymbolOwnerGetName);
  GUM_TRY_ASSIGN (SymbolOwnerGetBaseAddress);

  GUM_TRY_ASSIGN (SourceInfoGetPath);
  GUM_TRY_ASSIGN (SourceInfoGetLineNumber);
  GUM_TRY_ASSIGN (SourceInfoGetColumn);

#undef GUM_TRY_ASSIGN

  _gum_register_destructor (gum_cs_unload_library);

  return GSIZE_TO_POINTER (TRUE);

api_error:
  {
    if (gum_cs != NULL)
    {
      dlclose (gum_cs);
      gum_cs = NULL;
    }

    return GSIZE_TO_POINTER (FALSE);
  }
}

static void
gum_cs_unload_library (void)
{
  dlclose (gum_cs);
  gum_cs = NULL;
}

#endif
```