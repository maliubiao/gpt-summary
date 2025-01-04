Response:
My thinking process to analyze the provided C code snippet and generate the detailed response involved several steps:

1. **Understanding the Goal:** The primary goal is to understand the functionality of `gumandroid.c` within the context of Frida, focusing on its relation to reverse engineering, low-level systems (Linux, Android kernel/framework), logical reasoning, potential user errors, and debugging. The request explicitly asks for a summary of the functionality in the first part.

2. **Initial Scan and Keyword Identification:** I started by scanning the code for prominent keywords and data structures. I looked for things like:
    * Includes: `gumandroid.h`, `gumlinux.h`, `dlfcn.h`, `elf.h`, `link.h`, `pthread.h`, etc. These immediately suggest interaction with dynamic linking, ELF files, threading, and system properties.
    * Data Structures:  Structures like `GumSoinfo`, `GumLinkerApi`, `GumModuleDetails`, `GumMemoryRange`, etc., point to the core concerns of the file: managing loaded modules (shared objects) and interacting with the Android linker.
    * Function Names: Functions like `gum_android_get_module_handle`, `gum_android_enumerate_modules`, `gum_linker_api_get`, `gum_try_init_linker_details`, and those involving `dlopen` and `dlsym` clearly indicate the file's role in module management and dynamic linking.
    * Constants and Macros:  Definitions like `GUM_ANDROID_LEGACY_SOINFO`, `GUM_ANDROID_VDSO_MODULE_NAME`, and signatures for `dlopen` and `dlsym` provide clues about different Android versions and their linker implementations.

3. **Identifying Core Functionality:** Based on the initial scan, I identified the following key functionalities:
    * **Module Management:**  The code is heavily involved in tracking and managing loaded shared libraries (`.so` files). This includes getting handles to modules, enumerating them, and retrieving their details (name, path, address range).
    * **Linker Interaction:** A significant portion of the code focuses on interacting with the Android dynamic linker (`linker`, `linker64`). This involves finding the linker's path, parsing its memory maps, and extracting information about its internal data structures and functions.
    * **Dynamic Linking Hooking (Implicit):** While the code doesn't directly implement hooking, its focus on `dlopen` and `dlsym`, and the extraction of linker API functions, suggests that this is a foundational piece for Frida's dynamic instrumentation capabilities. Frida likely uses this information to intercept or modify calls to these functions.
    * **Android Version and Flavor Handling:** The code explicitly handles different Android API levels and linker flavors (native vs. emulated), indicating a need to adapt to varying system implementations.

4. **Connecting to Reverse Engineering:** I then considered how these functionalities relate to reverse engineering:
    * **Dynamic Analysis:**  The ability to enumerate loaded modules and get their handles is crucial for dynamic analysis, allowing tools like Frida to inspect and manipulate running code.
    * **Understanding Program Structure:**  Knowing the loaded libraries and their addresses helps reverse engineers understand the structure and dependencies of an application.
    * **Function Hooking:** The focus on `dlopen` and `dlsym` is directly related to function hooking, a core technique in dynamic analysis and instrumentation. By intercepting calls to these functions, Frida can control the loading of libraries and the resolution of symbols.

5. **Identifying Low-Level System Aspects:** I looked for code sections dealing with:
    * **ELF Format:** The inclusion of `elf.h` and the use of structures like `ElfW(Phdr)` and `ElfW(Sym)` indicate direct interaction with the ELF file format, the standard binary format on Linux and Android.
    * **Linux System Calls/APIs:**  Functions like `dlopen`, `dlsym`, `pthread_mutex_lock`, `g_file_get_contents` (which likely reads `/proc/self/maps`), and interaction with system properties via `__system_property_get` show interaction with the underlying operating system.
    * **Android Internals:** The code directly deals with Android-specific concepts like the linker (`linker`, `linker64`), `vdso`, and system properties related to API level and codename. The handling of different `GumSoinfo` structures based on Android versions highlights the need to understand Android's internal changes.
    * **Memory Management:** The parsing of `/proc/self/maps` and the tracking of memory ranges are fundamental to understanding the memory layout of processes.

6. **Logical Reasoning and Assumptions:** I identified areas where the code makes logical inferences or assumptions:
    * **Linker Location:** The code assumes the linker is located at specific paths based on the Android API level and architecture.
    * **Linker Memory Map Structure:**  The parsing of `/proc/self/maps` relies on the expected format of this file.
    * **Linker Internal Structures:** The forensic approaches to finding `dlopen`, `dlsym`, and the mutex rely on assumptions about the linker's internal structure and how these elements are likely to be located in memory. The function signature matching is a clear example of logical deduction based on known instruction sequences.

7. **Potential User/Programming Errors:**  I considered how users or developers might misuse this code or encounter errors:
    * **Incorrect Module Names:** Providing an incorrect or misspelled module name to functions like `gum_android_get_module_handle` will result in failure.
    * **Assumptions about Linker Internals:** Directly manipulating linker structures based on assumptions could break with different Android versions or custom ROMs.
    * **Race Conditions (Potentially):** While the code uses mutexes to protect linker data, improper use in a larger context could still lead to race conditions. This is more relevant to how Frida uses this code rather than direct errors *within* this code.

8. **Debugging and User Steps:** I traced how a user might end up interacting with this code during debugging:
    * **Frida Scripting:** A user writing a Frida script might use functions like `Module.getHandle()` or `Process.enumerateModules()` which internally rely on the functionalities provided by `gumandroid.c`.
    * **Debugging Frida Itself:** A developer debugging Frida might step through this code to understand how module enumeration or linker interaction is implemented.
    * **Investigating Instrumentation Failures:** If Frida fails to hook a function or load a module, this code might be a starting point for investigating the issue.

9. **Summarizing Functionality (Part 1):** Finally, I synthesized the information gathered to create a concise summary of the file's core functions, as requested for the first part of the response.

Throughout this process, I iteratively refined my understanding by cross-referencing different parts of the code and focusing on the relationships between data structures and functions. The comments within the code itself were also valuable for understanding the purpose of certain sections. The explicit mention of different Android API levels and specific device examples in the comments provided important context.
这是名为 `gumandroid.c` 的 Frida 代码文件的第一部分，该文件位于 Frida 的一个子项目中，专门处理 Linux 平台上的 Android 环境。其主要功能是为 Frida 动态插桩工具提供在 Android 系统上运行所需的基础设施，特别是与 Android 的动态链接器进行交互。

**它的主要功能可以归纳为：**

1. **定位和识别 Android 动态链接器 (`linker` / `linker64`)：**
   - 通过读取 `/proc/self/maps` 文件来查找当前进程中映射的模块。
   - 使用正则表达式匹配已知的链接器路径（`/system/bin/linker` 或 `/apex/com.android.runtime/bin/linker` 等）。
   - 考虑了不同 Android API 版本和架构（32位/64位）下链接器的位置。
   - 能够区分模拟器环境和原生环境。

2. **获取 Android 系统 API Level：**
   - 通过读取系统属性 `ro.build.version.sdk` 来获取当前 Android 系统的 API 级别。
   - 辅助判断 Android 版本，以便采取不同的处理逻辑。

3. **与 Android 动态链接器进行交互，获取其内部数据和函数：**
   - 打开链接器模块，以便检查其符号表。
   - 尝试查找链接器导出的关键函数，如 `dlopen`, `dlsym`（不同 API 版本可能具有不同的符号名，例如 `__dl___loader_dlopen` 或 `__dl__Z8__dlopenPKciPKv`）。
   - 尝试查找链接器内部的关键数据结构，例如用于管理已加载共享库的链表头 (`solist_get_head` 或 `solist`) 以及用于同步的互斥锁 (`dl_mutex`)。
   - 针对不同的 Android API 版本，可能采用不同的方法来查找这些符号和数据，包括直接符号查找和基于代码特征的“forensic”查找（例如，通过扫描代码段查找特定的指令序列）。

4. **提供访问已加载模块信息的能力：**
   - 提供了 `gum_android_get_module_handle` 函数，允许通过模块名称获取模块的句柄。这个函数会遍历链接器维护的已加载共享库列表。
   - 提供了 `gum_android_enumerate_modules` 函数，允许遍历所有已加载的模块，并对每个模块执行用户指定的回调函数。

5. **辅助实现 `dlopen` 和 `dlsym` 的功能：**
   - 通过获取链接器内部的 `dlopen` 和 `dlsym` 函数的地址，Frida 可以利用这些函数来加载新的共享库或解析符号，这在动态插桩中至关重要。

**与逆向的方法的关系及举例说明：**

- **动态分析和代码注入：** `gumandroid.c` 提供的模块枚举和句柄获取功能是 Frida 进行动态分析和代码注入的基础。例如，一个逆向工程师可以使用 Frida 脚本调用 `Module.getHandle("libnative.so")` 来获取目标 native 库的加载地址，然后使用这个地址来 hook 库中的特定函数。
- **理解程序结构和依赖：** 通过 `gum_android_enumerate_modules`，逆向工程师可以了解目标进程加载了哪些动态链接库，从而分析程序的依赖关系和模块组成。例如，一个恶意软件可能加载了某些加密库或网络库，通过枚举模块可以快速定位这些可疑模块。
- **绕过反动态分析技术：** 一些反动态分析技术会检测是否有调试器或插桩工具附加。Frida 通过与链接器交互，可以更底层地控制模块加载，从而可能绕过一些基于高层 API 的检测。例如，某些检测可能会检查 `/proc/pid/status` 中的 TracerPid，而 Frida 的底层操作可能不直接触发这种检测。
- **理解和利用动态链接过程：** `gumandroid.c` 深入研究了 Android 的动态链接过程，这使得 Frida 能够在这个过程中进行干预。逆向工程师可以利用 Frida hook `dlopen` 来阻止某些库的加载，或者 hook `dlsym` 来替换函数的实现。

**涉及到的二进制底层、Linux、Android 内核及框架的知识及举例说明：**

- **ELF 文件格式：** 代码中使用了 `<elf.h>` 头文件，并涉及到 `ElfW(Phdr)` (程序头) 和 `ElfW(Sym)` (符号表)。这表明代码需要解析 ELF 文件结构来获取模块的加载信息和符号信息。
- **Linux 进程内存管理：**  读取 `/proc/self/maps` 文件是 Linux 操作系统提供的查看进程内存映射的方式。`gumandroid.c` 利用这一点来定位链接器模块。
- **Android 动态链接器 (`linker`)：** 代码的核心功能是与 Android 的动态链接器交互。理解链接器的工作原理（例如，如何加载共享库，如何解析符号）对于编写 Frida 插件至关重要。
- **Android 系统属性：** 通过 `__system_property_get` 函数读取 `ro.build.version.sdk`，这是 Android 系统提供的获取系统配置信息的方式。
- **`dlfcn.h` 相关的函数：** 代码中尝试获取 `dlopen` 和 `dlsym` 等函数的地址，这些函数是 POSIX 标准中用于动态加载和符号解析的关键函数。
- **`pthread` 库：** 代码中使用了 `pthread_mutex_lock` 和 `pthread_mutex_unlock`，表明需要处理多线程环境下的同步问题，确保在访问链接器内部数据结构时不会出现竞争条件。
- **`link.h` 结构体：** 代码中包含 `<link.h>`，其中定义了 `link_map` 结构体，这是链接器用于管理已加载共享库的关键数据结构。代码尝试访问 `GumSoinfo` 结构体中的 `link_map_head` 成员。

**逻辑推理的假设输入与输出：**

假设输入：
- 函数 `gum_android_get_module_handle` 的输入是模块名字符串，例如 `"libc.so"`.
- 函数 `gum_enumerate_soinfo` 被调用。

逻辑推理过程：
1. `gum_android_get_module_handle` 会调用 `gum_enumerate_soinfo` 来遍历已加载的共享库。
2. `gum_enumerate_soinfo` 首先获取链接器的 API 结构体 `GumLinkerApi`。
3. 它会尝试锁定链接器的互斥锁 `api->dl_mutex`，以确保线程安全。
4. 它会获取已加载模块链表的头部 `api->solist_get_head()` 或 `api->solist`。
5. 它会遍历链表中的每个 `GumSoinfo` 结构体，这些结构体包含了关于每个加载的共享库的信息。
6. 对于每个 `GumSoinfo` 结构体，它会获取模块的路径 `details->path`。
7. `gum_store_module_handle_if_name_matches` 函数会被调用，比较 `details->path` 和输入的模块名 `"libc.so"`。
8. 如果路径匹配，它会尝试使用链接器的 `dlopen` 或 `do_dlopen` 函数（取决于 Android 版本和可用的 API）以 `RTLD_NOLOAD` 标志打开该模块，并返回其句柄。

假设输出：
- 如果找到名为 `"libc.so"` 的模块，`gum_android_get_module_handle` 将返回该模块的加载地址作为句柄（`void *`）。
- 如果未找到，则返回 `NULL`。
- `gum_enumerate_soinfo` 将会遍历所有已加载的共享库，并对每个库调用用户提供的回调函数。

**涉及用户或者编程常见的使用错误及举例说明：**

- **传递错误的模块名给 `gum_android_get_module_handle`：** 如果用户传递了一个不存在的或拼写错误的模块名，例如 `"libnativ.so"`（少了一个 "e"），则该函数将无法找到匹配的模块并返回 `NULL`。这会导致后续依赖于该句柄的操作失败。
- **假设链接器 API 在所有 Android 版本上都是相同的：** 代码中可以看到针对不同 API 版本的特殊处理逻辑。如果用户直接使用硬编码的链接器内部结构偏移或函数地址，而不考虑 Android 版本的差异，他们的 Frida 脚本很可能会在新版本的 Android 上失效。
- **在多线程环境下不正确地使用模块信息：** 虽然 `gumandroid.c` 内部使用了互斥锁来保护链接器的数据，但在 Frida 脚本中，如果多个线程同时调用依赖于 `gumandroid.c` 功能的 API，而没有进行适当的同步，可能会导致数据竞争或不可预测的行为。

**说明用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本，尝试获取特定 Android 模块的句柄或枚举所有模块。** 例如，用户可能编写了以下 Frida 脚本：
   ```javascript
   // 获取 libc.so 的句柄
   const libcModule = Process.getModuleByName("libc.so");
   if (libcModule) {
       console.log("libc.so base address:", libcModule.base);
   } else {
       console.log("libc.so not found!");
   }

   // 枚举所有模块
   Process.enumerateModules({
       onMatch: function(module) {
           console.log("Module:", module.name, module.base);
       },
       onComplete: function() {
           console.log("Module enumeration complete.");
       }
   });
   ```

2. **Frida 脚本引擎执行 `Process.getModuleByName()` 或 `Process.enumerateModules()`。** 这些 Frida JavaScript API 会映射到 Frida 的 C/C++ 代码实现。

3. **在 Frida 的 C/C++ 代码中，`Process.getModuleByName()` 最终会调用 `gum_android_get_module_handle()`，并将模块名 `"libc.so"` 传递给它。** 同样，`Process.enumerateModules()` 会调用 `gum_android_enumerate_modules()`。

4. **`gum_android_get_module_handle()` 或 `gum_android_enumerate_modules()` 内部会调用 `gum_enumerate_soinfo()`。**

5. **在 `gum_enumerate_soinfo()` 中，会调用 `gum_linker_api_get()` 来获取链接器的 API 结构体。** 这可能涉及到查找和解析链接器模块的过程，正如代码所示。

6. **接下来，会尝试锁定链接器的互斥锁，然后遍历链接器维护的已加载模块列表。**

7. **对于 `Process.getModuleByName()`，`gum_store_module_handle_if_name_matches()` 会被用于检查当前遍历到的模块是否与目标模块名匹配。**

8. **对于 `Process.enumerateModules()`，`gum_emit_module_from_soinfo()` 会被调用，将模块信息传递给用户提供的回调函数。**

**作为调试线索：**

如果在 Frida 脚本中 `Process.getModuleByName("libc.so")` 返回 `null`，开发者可能会怀疑 `gum_android_get_module_handle()` 没有正确找到 `libc.so`。调试时，他们可能会：

- 在 `gum_android_get_module_handle()` 中设置断点，检查传递的模块名是否正确。
- 在 `gum_enumerate_soinfo()` 中设置断点，查看是否成功获取了链接器的 API 结构体，以及是否能够正确遍历已加载的模块列表。
- 检查 `details->path` 的值，看是否与预期的模块路径一致。
- 检查 `gum_linker_api_get()` 的返回值，确保成功获取了链接器的 API，如果获取失败，可能需要进一步调查链接器定位和符号查找的过程。

**总结其功能:**

`gumandroid.c` 的主要功能是作为 Frida 在 Android 平台上运行的桥梁，它负责与 Android 系统的动态链接器进行交互，获取关键的模块信息和链接器 API，从而为 Frida 提供动态插桩所需的基础能力，包括模块枚举、获取模块句柄以及辅助实现动态加载和符号解析。它需要深入理解 Android 的底层机制，包括 ELF 文件格式、进程内存管理、动态链接过程以及不同 Android 版本之间的差异。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-linux/gumandroid.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gum/gumandroid.h"

#include "gum-init.h"
#include "gum/gumlinux.h"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <pthread.h>
#include <string.h>
#include <sys/system_properties.h>

#if (defined (HAVE_I386) && GLIB_SIZEOF_VOID_P == 4) || defined (HAVE_ARM)
# define GUM_ANDROID_LEGACY_SOINFO 1
#endif

#define GUM_ANDROID_VDSO_MODULE_NAME "linux-vdso.so.1"

#if GLIB_SIZEOF_VOID_P == 4
# define GUM_LIBCXX_TINY_STRING_CAPACITY 11
#else
# define GUM_LIBCXX_TINY_STRING_CAPACITY 23
#endif

typedef struct _GumGetModuleHandleContext GumGetModuleHandleContext;
typedef struct _GumEnsureModuleInitializedContext
    GumEnsureModuleInitializedContext;
typedef struct _GumEnumerateModulesContext GumEnumerateModulesContext;

typedef struct _GumSoinfoDetails GumSoinfoDetails;
typedef gboolean (* GumFoundSoinfoFunc) (const GumSoinfoDetails * details,
    gpointer user_data);

typedef struct _GumLinkerApi GumLinkerApi;

typedef struct _GumSoinfo GumSoinfo;
typedef struct _GumSoinfoHead GumSoinfoHead;
typedef struct _GumSoinfoBody GumSoinfoBody;
typedef struct _GumSoinfoExtrasPre33 GumSoinfoExtrasPre33;
typedef struct _GumSoinfoExtrasPost33 GumSoinfoExtrasPost33;
typedef struct _GumSoinfoModern GumSoinfoModern;
typedef struct _GumSoinfoLegacy23 GumSoinfoLegacy23;
typedef struct _GumSoinfoLegacy GumSoinfoLegacy;
typedef guint32 GumSoinfoFlags;
typedef struct _GumSoinfoListModern GumSoinfoListModern;
typedef struct _GumSoinfoListLegacy GumSoinfoListLegacy;
typedef struct _GumSoinfoListHeader GumSoinfoListHeader;
typedef struct _GumSoinfoListEntry GumSoinfoListEntry;

typedef struct _GumFindDlopenApiContext GumFindDlopenApiContext;
typedef struct _GumFindDlMutexContext GumFindDlMutexContext;
typedef struct _GumFindFunctionSignatureContext GumFindFunctionSignatureContext;
typedef struct _GumFunctionSignature GumFunctionSignature;

typedef union _GumLibcxxString GumLibcxxString;
typedef struct _GumLibcxxTinyString GumLibcxxTinyString;
typedef struct _GumLibcxxHugeString GumLibcxxHugeString;

struct _GumGetModuleHandleContext
{
  const gchar * name;
  void * module;
};

struct _GumEnsureModuleInitializedContext
{
  const gchar * name;
  gboolean success;
};

struct _GumEnumerateModulesContext
{
  GumFoundModuleFunc func;
  gpointer user_data;
};

struct _GumSoinfoDetails
{
  const gchar * path;
  GumSoinfo * si;
  GumSoinfoBody * body;
  GumLinkerApi * api;
};

struct _GumLinkerApi
{
  GumAndroidDlopenImpl dlopen;
  GumAndroidDlsymImpl dlsym;
  gpointer trusted_caller;

  void * (* do_dlopen) (const char * filename, int flags, const void * extinfo,
      void * caller_addr);
  guint8 (* do_dlsym) (void * handle, const char * sym_name,
      const char * sym_ver, void * caller_addr, void ** symbol);

  pthread_mutex_t * dl_mutex;

  GumSoinfo * (* solist_get_head) (void);
  GumSoinfo ** solist;
  GumSoinfo * libdl_info;
  GumSoinfo * (* solist_get_somain) (void);
  GumSoinfo ** somain;
  GumSoinfo * somain_node;

  const char * (* soinfo_get_path) (GumSoinfo * si);
};

struct _GumSoinfoListModern
{
  GumSoinfoListHeader * header;
};

struct _GumSoinfoListLegacy
{
  GumSoinfoListEntry * head;
  GumSoinfoListEntry * tail;
};

struct _GumSoinfoListHeader
{
  GumSoinfoListEntry * head;
  GumSoinfoListEntry * tail;
};

struct _GumSoinfoListEntry
{
  GumSoinfoListEntry * next;
  GumSoinfo * element;
};

struct _GumLibcxxTinyString
{
  guint8 size;
  gchar data[GUM_LIBCXX_TINY_STRING_CAPACITY];
};

struct _GumLibcxxHugeString
{
  gsize capacity;
  gsize size;
  gchar * data;
};

union _GumLibcxxString
{
  GumLibcxxTinyString tiny;
  GumLibcxxHugeString huge;
};

struct _GumSoinfoHead
{
#ifdef GUM_ANDROID_LEGACY_SOINFO
  gchar old_name[128];
#endif

  const ElfW(Phdr) * phdr;
  gsize phnum;
};

struct _GumSoinfoExtrasPre33
{
  GumSoinfoListLegacy children;
  GumSoinfoListLegacy parents;

  /* version >= 1 */
  off64_t file_offset;
  guint32 rtld_flags;
  guint32 dt_flags_1;
  gsize strtab_size;

  /* version >= 2 */
  gsize gnu_nbucket;
  guint32 * gnu_bucket;
  guint32 * gnu_chain;
  guint32 gnu_maskwords;
  guint32 gnu_shift2;
  ElfW(Addr) * gnu_bloom_filter;

  GumSoinfo * local_group_root;

  guint8 * android_relocs;
  gsize android_relocs_size;

  const gchar * soname;
  GumLibcxxString realpath;

  const ElfW(Versym) * versym;

  ElfW(Addr) verdef_ptr;
  gsize verdef_cnt;

  ElfW(Addr) verneed_ptr;
  gsize verneed_cnt;

  gint target_sdk_version;

  /* For now we don't need anything from version >= 3. */
};

struct _GumSoinfoExtrasPost33
{
  GumSoinfoListModern children;
  GumSoinfoListModern parents;

  off64_t file_offset;
  guint32 rtld_flags;
  guint32 dt_flags_1;
  gsize strtab_size;

  gsize gnu_nbucket;
  guint32 * gnu_bucket;
  guint32 * gnu_chain;
  guint32 gnu_maskwords;
  guint32 gnu_shift2;
  ElfW(Addr) * gnu_bloom_filter;

  GumSoinfo * local_group_root;

  guint8 * android_relocs;
  gsize android_relocs_size;

  GumLibcxxString soname;
  GumLibcxxString realpath;

  const ElfW(Versym) * versym;

  ElfW(Addr) verdef_ptr;
  gsize verdef_cnt;

  ElfW(Addr) verneed_ptr;
  gsize verneed_cnt;

  gint target_sdk_version;
};

struct _GumSoinfoBody
{
#ifdef GUM_ANDROID_LEGACY_SOINFO
  ElfW(Addr) unused0;
#endif
  ElfW(Addr) base;
  gsize size;

#ifdef GUM_ANDROID_LEGACY_SOINFO
  guint32 unused1;
#endif

  ElfW(Dyn) * dynamic;

#ifdef GUM_ANDROID_LEGACY_SOINFO
  guint32 unused2;
  guint32 unused3;
#endif

  GumSoinfo * next;

  GumSoinfoFlags flags;

  const gchar * strtab;
  ElfW(Sym) * symtab;

  gsize nbucket;
  gsize nchain;
  guint32 * bucket;
  guint32 * chain;

#if GLIB_SIZEOF_VOID_P == 4
  ElfW(Addr) ** plt_got;
#endif

  gpointer plt_relx;
  gsize plt_relx_count;

  gpointer relx;
  gsize relx_count;

  gpointer * preinit_array;
  gsize preinit_array_count;

  gpointer * init_array;
  gsize init_array_count;
  gpointer * fini_array;
  gsize fini_array_count;

  gpointer init_func;
  gpointer fini_func;

#if defined (HAVE_ARM)
  guint32 * arm_exidx;
  gsize arm_exidx_count;
#elif defined (HAVE_MIPS)
  guint32 mips_symtabno;
  guint32 mips_local_gotno;
  guint32 mips_gotsym;
#endif

  gsize ref_count;

  struct link_map link_map_head;

  guint8 constructors_called;

  ElfW(Addr) load_bias;

#if GLIB_SIZEOF_VOID_P == 4
  guint8 has_text_relocations;
#endif
  guint8 has_dt_symbolic;

  /* Next part of structure only present when NEW_FORMAT is in flags. */
  guint32 version;

  /* version >= 0 */
  dev_t st_dev;
  ino_t st_ino;

  union
  {
    GumSoinfoExtrasPre33 pre33;
    GumSoinfoExtrasPost33 post33;
  }
  extras;
};

struct _GumSoinfoModern
{
  GumSoinfoHead head;
  GumSoinfoBody body;
};

struct _GumSoinfoLegacy23
{
  GumSoinfoHead head;

#ifndef GUM_ANDROID_LEGACY_SOINFO
  ElfW(Addr) entry;
#endif
  GumSoinfoBody body;
};

struct _GumSoinfoLegacy
{
#ifndef GUM_ANDROID_LEGACY_SOINFO
  gchar name[128];
#endif

  GumSoinfoLegacy23 legacy23;
};

struct _GumSoinfo
{
  union
  {
    GumSoinfoModern modern;
    GumSoinfoLegacy23 legacy23;
    GumSoinfoLegacy legacy;
  };
};

enum _GumSoinfoFlags
{
  GUM_SOINFO_LINKED     = 0x00000001,
  GUM_SOINFO_EXE        = 0x00000004,
  GUM_SOINFO_GNU_HASH   = 0x00000040,
  GUM_SOINFO_NEW_FORMAT = 0x40000000,
};

struct _GumFindDlopenApiContext
{
  GumElfModule * linker;

  const GumFunctionSignature * dlopen_signatures;
  gpointer dlopen;

  const GumFunctionSignature * dlsym_signatures;
  gpointer dlsym;
};

struct _GumFindDlMutexContext
{
  GumElfModule * linker;
  pthread_mutex_t * dl_mutex;
};

struct _GumFindFunctionSignatureContext
{
  GumAddress match;
  guint num_matches;
};

struct _GumFunctionSignature
{
  const gchar * signature;
  gint displacement;
};

static const GumModuleDetails * gum_try_init_linker_details (void);
static void gum_deinit_linker_details (void);
static gchar * gum_find_linker_path (void);
static GRegex * gum_find_linker_path_pattern (void);
static gboolean gum_try_parse_linker_proc_maps_line (const gchar * line,
    const gchar * linker_path, const GRegex * linker_path_pattern,
    GumModuleDetails * module, GumMemoryRange * range);

static gboolean gum_store_module_handle_if_name_matches (
    const GumSoinfoDetails * details, GumGetModuleHandleContext * ctx);
static gboolean gum_emit_module_from_soinfo (const GumSoinfoDetails * details,
    GumEnumerateModulesContext * ctx);

static void gum_enumerate_soinfo (GumFoundSoinfoFunc func, gpointer user_data);
static void gum_init_soinfo_details (GumSoinfoDetails * details, GumSoinfo * si,
    GumLinkerApi * api, GHashTable ** ranges);
static const gchar * gum_resolve_soinfo_path (GumSoinfo * si,
    GumLinkerApi * api, GHashTable ** ranges);

static GumLinkerApi * gum_linker_api_get (void);
static GumLinkerApi * gum_linker_api_try_init (void);
static gboolean gum_store_linker_symbol_if_needed (
    const GumElfSymbolDetails * details, guint * pending);
static gboolean gum_try_find_dlopen_api245_forensically (GumElfModule * linker,
    GumLinkerApi * api);
static gboolean gum_try_find_dlopen_api26p_forensically (GumElfModule * linker,
    GumLinkerApi * api);
static gboolean gum_store_dlopen_api_if_found_in_section (
    const GumElfSectionDetails * details, GumFindDlopenApiContext * ctx);
static gboolean gum_try_find_dl_mutex_forensically (GumElfModule * linker,
    pthread_mutex_t ** dl_mutex);
static gboolean gum_store_dl_mutex_pointer_if_found_in_section (
    const GumElfSectionDetails * details, GumFindDlMutexContext * ctx);
static gboolean gum_try_find_libdl_info_forensically (GumElfModule * linker,
    GumSoinfo ** libdl_info);
static gboolean gum_store_libdl_info_pointer_if_found_in_section (
    const GumElfSectionDetails * details, GumSoinfo ** libdl_info);
static gboolean gum_try_find_somain_forensically (GumLinkerApi * api);
static gpointer gum_find_function_by_signature (GumAddress address, gsize size,
    const GumFunctionSignature * signatures);
static gboolean gum_store_function_signature_match (GumAddress address,
    gsize size, GumFindFunctionSignatureContext * ctx);
static gboolean gum_store_first_scan_match (GumAddress address, gsize size,
    gpointer user_data);
static GumSoinfo * gum_solist_get_head_fallback (void);
static GumSoinfo * gum_solist_get_somain_fallback (void);
#ifdef GUM_ANDROID_LEGACY_SOINFO
static GumSoinfoHead * gum_soinfo_get_head (GumSoinfo * self);
#endif
static GumSoinfoBody * gum_soinfo_get_body (GumSoinfo * self);
static gboolean gum_soinfo_is_linker (GumSoinfo * self);
static GumSoinfo * gum_soinfo_get_parent (GumSoinfo * self);
static guint32 gum_soinfo_get_rtld_flags (GumSoinfo * self);
static const gchar * gum_soinfo_get_realpath (GumSoinfo * self);
static const char * gum_soinfo_get_path_fallback (GumSoinfo * self);

static void * gum_call_inner_dlopen (const char * filename, int flags);
static void * gum_call_inner_dlsym (void * handle, const char * symbol);

static const char * gum_libcxx_string_get_data (const GumLibcxxString * self);

static gboolean gum_android_is_vdso_module_name (const gchar * name);

static gchar * gum_dl_path;
static GumModuleDetails gum_dl_module;
static GumMemoryRange gum_dl_range;
static GumLinkerApi gum_dl_api;

static const gchar * gum_magic_linker_export_names_pre_api_level_26[] =
{
  "dlopen",
  "dlsym",
  "dlclose",
  "dlerror",
  NULL
};

static const gchar * gum_magic_linker_export_names_post_api_level_26[] =
{
  NULL
};

/*
 * The following signatures have been tested on:
 *
 * - Xiaomi iRedmi Note 3 running LineageOS 14.1 (Android 7.1.2)
 */

static const GumFunctionSignature gum_dlopen_signatures_api245[] =
{
#ifdef HAVE_ARM
  {
    "93 46 "        /* mov r11, r2                             */
    "0c 46 "        /* mov r4, r1                              */
    "78 44 "        /* add r0, pc                              */
    "05 68",        /* ldr r5, [r0]                            */
    -12 + 1
  },
#endif
#ifdef HAVE_ARM64
  {
    "f4 4f 04 a9 "  /* stp x20, x19, [sp, #0x40]               */
    "fd 7b 05 a9 "  /* stp x29, x30, [sp, #0x50]               */
    "fd 43 01 91 "  /* add x29, sp, #0x50                      */
    "ff c3 04 d1 "  /* sub sp, sp, #0x130                      */
    "?? ?? ?? ?? "  /* adrp x8, #0xb1000                       */
    "?? ?? ?? ?? "  /* ldr x21, [x8, #0x688]                   */
    "f4 03 02 aa",  /* mov x20, x2                             */
    -16
  },
#endif
  { NULL, 0 }
};

static const GumFunctionSignature gum_dlsym_signatures_api245[] =
{
#ifdef HAVE_ARM
  {
    "14 46 "        /* mov r4, r2                              */
    "88 46 "        /* mov r8, r1                              */
    "?? ?? "        /* cbz r6, loc_52a6                        */
    "b8 f1 00 0f",  /* cmp.w r8, #0                            */
    -8 + 1
  },
#endif
#ifdef HAVE_ARM64
  {
    "ff c3 01 d1 "  /* sub sp, sp, #0x70                       */
    "f3 03 04 aa "  /* mov x19, x4                             */
    "f4 03 02 aa "  /* mov x20, x2                             */
    "f5 03 01 aa "  /* mov x21, x1                             */
    "e8 03 00 aa",  /* mov x8, x0                              */
    -16
  },
#endif
  { NULL, 0 }
};

/*
 * The following signatures have been tested on:
 *
 * - Pixel 3 running Android 9.0
 */

static const GumFunctionSignature gum_dlopen_signatures_api26p[] =
{
#ifdef HAVE_ARM
  {
    "0d 46 "        /* mov r5, r1                              */
    "78 44 "        /* add r0, pc                              */
    "?? ?? ?? ?? "  /* bl __dl_pthread_mutex_lock              */
    "?? ?? "        /* ldr r0, =0xbd62a                        */
    "78 44",        /* add r0, pc                              */
    -8 + 1
  },
#endif
#ifdef HAVE_ARM64
  {
    "f3 03 02 aa "  /* mov x19, x2                             */
    "f4 03 01 2a "  /* mov w20, w1                             */
    "f5 03 00 aa "  /* mov x21, x0                             */
    "?? ?? ?? ?? "  /* adrp x0, #0x150000                      */
    "?? ?? ?? ?? "  /* add x0, x0, #0                          */
    "?? ?? ?? ?4 "  /* bl __dl_pthread_mutex_lock              */
    "?? ?? ?? ?? "  /* adrp x0, #0x14f000                      */
    "?? ?? ?? ?? "  /* ldr x0, [x0, #0x840]                    */
    "?? ?? ?? ?4 "  /* bl __dl__ZN12LinkerLogger10ResetStateEv */
    "e0 03 15 aa ", /* mov x0, x21                             */
    -16
  },
#endif
  { NULL, 0 }
};

static const GumFunctionSignature gum_dlsym_signatures_api26p[] =
{
#ifdef HAVE_ARM
  {
    "1c 46 "        /* mov r4, r3                              */
    "15 46 "        /* mov r5, r2                              */
    "0e 46 "        /* mov r6, r1                              */
    "78 44 "        /* add r0, pc                              */
    "?? ?? ?? ?? "  /* bl __dl_pthread_mutex_lock              */
    "?? ?? "        /* ldr r0, =0xbd5ce                        */
    "78 44 "        /* add r0, pc                              */
    "00 68 "        /* ldr r0, [r0]                            */
    "?? ?? ?? ?? "  /* bl __dl__ZN12LinkerLogger10ResetStateEv */
    "02 a8",        /* add r0, sp, #8                          */
    -8 + 1
  },
#endif
#ifdef HAVE_ARM64
  {
    "fd c3 00 91 "  /* add x29, sp, #0x30                      */
    "f3 03 03 aa "  /* mov x19, x3                             */
    "f4 03 02 aa "  /* mov x20, x2                             */
    "f5 03 01 aa "  /* mov x21, x1                             */
    "f6 03 00 aa "  /* mov x22, x0                             */
    "?? ?? ?? ?? "  /* adrp x0, #0x150000                      */
    "?? ?? ?? ?? "  /* add x0, x0, #0                          */
    "?? ?? ?? ?4 "  /* bl __dl_pthread_mutex_lock              */
    "?? ?? ?? ?? "  /* adrp x0, #0x14f000                      */
    "?? ?? ?? ?? "  /* ldr x0, [x0, #0x840]                    */
    "?? ?? ?? ?4 "  /* bl __dl__ZN12LinkerLogger10ResetStateEv */
    "e4 23 00 91",  /* add x4, sp, #8                          */
    -16
  },
#endif
  { NULL, 0 }
};

GumAndroidLinkerFlavor
gum_android_get_linker_flavor (void)
{
#if defined (HAVE_ARM) || defined (HAVE_ARM64)
  static GumAndroidLinkerFlavor cached_flavor = -1;

  if (cached_flavor == -1)
  {
    gchar * info = NULL;

    g_file_get_contents ("/sys/devices/system/cpu/modalias", &info, NULL, NULL);

    cached_flavor = (info != NULL && strstr (info, "x86") != NULL)
        ? GUM_ANDROID_LINKER_EMULATED
        : GUM_ANDROID_LINKER_NATIVE;

    g_free (info);
  }

  return cached_flavor;
#else
  return GUM_ANDROID_LINKER_NATIVE;
#endif
}

guint
gum_android_get_api_level (void)
{
  static guint cached_api_level = G_MAXUINT;

  if (cached_api_level == G_MAXUINT)
  {
    gchar sdk_version[PROP_VALUE_MAX];

    __system_property_get ("ro.build.version.sdk", sdk_version);

    cached_api_level = atoi (sdk_version);
  }

  return cached_api_level;
}

static gboolean
gum_android_is_api33_or_newer (void)
{
  static gboolean is_api33_or_newer;
  static gboolean initialized = FALSE;

  if (!initialized)
  {
    if (gum_android_get_api_level () >= 33)
    {
      is_api33_or_newer = TRUE;
    }
    else
    {
      gchar codename[PROP_VALUE_MAX];

      __system_property_get ("ro.build.version.codename", codename);

      is_api33_or_newer = strcmp (codename, "Tiramisu") == 0;
    }

    initialized = TRUE;
  }

  return is_api33_or_newer;
}

gboolean
gum_android_is_linker_module_name (const gchar * name)
{
  const GumModuleDetails * linker;

  linker = gum_android_get_linker_module_details ();

  if (name[0] != '/')
    return strcmp (name, linker->name) == 0;

  return strcmp (name, linker->path) == 0;
}

const GumModuleDetails *
gum_android_get_linker_module_details (void)
{
  static GOnce once = G_ONCE_INIT;

  g_once (&once, (GThreadFunc) gum_try_init_linker_details, NULL);

  if (once.retval == NULL)
    gum_panic ("Unable to locate the Android linker; please file a bug");

  return once.retval;
}

static const GumModuleDetails *
gum_try_init_linker_details (void)
{
  const GumModuleDetails * result = NULL;
  gchar * linker_path;
  GRegex * linker_path_pattern;
  gchar * maps, ** lines;
  gint num_lines, vdso_index, i;

  linker_path = gum_find_linker_path ();
  linker_path_pattern = gum_find_linker_path_pattern ();

  /*
   * Using /proc/self/maps means there might be false positives, as the
   * application – or even Frida itself – may have mmap()ed the module.
   *
   * Knowing that the linker is mapped right around the vdso, with no
   * empty space between, we just have to find the vdso, and we can
   * count on the the next or previous linker mapping being the actual
   * linker.
   */
  g_file_get_contents ("/proc/self/maps", &maps, NULL, NULL);
  lines = g_strsplit (maps, "\n", 0);
  num_lines = g_strv_length (lines);

  vdso_index = -1;
  for (i = 0; i != num_lines; i++)
  {
    const gchar * line = lines[i];

    if (g_str_has_suffix (line, " [vdso]"))
    {
      vdso_index = i;
      break;
    }
  }
  if (vdso_index == -1)
    goto no_vdso;

  for (i = vdso_index + 1; i != num_lines; i++)
  {
    if (gum_try_parse_linker_proc_maps_line (lines[i], linker_path,
        linker_path_pattern, &gum_dl_module, &gum_dl_range))
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

  for (i = vdso_index - 1; i >= 0; i--)
  {
    if (gum_try_parse_linker_proc_maps_line (lines[i], linker_path,
        linker_path_pattern, &gum_dl_module, &gum_dl_range))
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

  goto beach;

no_vdso:
  for (i = num_lines - 1; i >= 0; i--)
  {
    if (gum_try_parse_linker_proc_maps_line (lines[i], linker_path,
        linker_path_pattern, &gum_dl_module, &gum_dl_range))
    {
      result = &gum_dl_module;
      goto beach;
    }
  }

beach:
  if (result != NULL)
  {
    gum_dl_path = linker_path;
    _gum_register_destructor (gum_deinit_linker_details);
  }
  else
  {
    g_free (linker_path);
  }

  g_strfreev (lines);
  g_free (maps);
  g_regex_unref (linker_path_pattern);

  return result;
}

static void
gum_deinit_linker_details (void)
{
  g_free (gum_dl_path);
}

static gchar *
gum_find_linker_path (void)
{
  const gchar * traditional_path, * modern_path, * path;

  traditional_path = (sizeof (gpointer) == 4)
      ? "/system/bin/linker"
      : "/system/bin/linker64";

  modern_path = (sizeof (gpointer) == 4)
      ? "/apex/com.android.runtime/bin/linker"
      : "/apex/com.android.runtime/bin/linker64";

  path = (gum_android_get_api_level () >= 29)
      ? modern_path
      : traditional_path;

  return g_strdup (path);
}

static GRegex *
gum_find_linker_path_pattern (void)
{
  const gchar * pattern;

  if (gum_android_get_api_level () >= 29)
  {
    pattern = (sizeof (gpointer) == 4)
        ? "/apex/com.android.runtime[^/]*/bin/linker$"
        : "/apex/com.android.runtime[^/]*/bin/linker64$";
  }
  else
  {
    pattern = (sizeof (gpointer) == 4)
        ? "/system/bin/linker$"
        : "/system/bin/linker64$";
  }

  return g_regex_new (pattern, 0, 0, NULL);
}

static gboolean
gum_try_parse_linker_proc_maps_line (const gchar * line,
                                     const gchar * linker_path,
                                     const GRegex * linker_path_pattern,
                                     GumModuleDetails * module,
                                     GumMemoryRange * range)
{
  GumAddress start, end;
  gchar perms[5] = { 0, };
  gchar path[PATH_MAX];
  gint n;
  const guint8 elf_magic[] = { 0x7f, 'E', 'L', 'F' };

  n = sscanf (line,
      "%" G_GINT64_MODIFIER "x-%" G_GINT64_MODIFIER "x "
      "%4c "
      "%*x %*s %*d "
      "%s",
      &start, &end,
      perms,
      path);
  if (n != 4)
    return FALSE;

  if (!g_regex_match (linker_path_pattern, path, 0, NULL))
    return FALSE;

  if (perms[0] != 'r')
    return FALSE;

  if (memcmp (GSIZE_TO_POINTER (start), elf_magic, sizeof (elf_magic)) != 0)
    return FALSE;

  module->name = strrchr (linker_path, '/') + 1;
  module->range = range;
  module->path = linker_path;

  range->base_address = start;
  range->size = end - start;

  return TRUE;
}

const gchar **
gum_android_get_magic_linker_export_names (void)
{
  return (gum_android_get_api_level () < 26)
      ? gum_magic_linker_export_names_pre_api_level_26
      : gum_magic_linker_export_names_post_api_level_26;
}

gboolean
gum_android_try_resolve_magic_export (const gchar * module_name,
                                      const gchar * symbol_name,
                                      GumAddress * result)
{
  const gchar ** magic_exports;
  guint i;

  magic_exports = gum_android_get_magic_linker_export_names ();
  if (magic_exports[0] == NULL)
    return FALSE;

  if (module_name == NULL || !gum_android_is_linker_module_name (module_name))
    return FALSE;

  for (i = 0; magic_exports[i] != NULL; i++)
  {
    if (strcmp (symbol_name, magic_exports[i]) == 0)
    {
      *result = GUM_ADDRESS (dlsym (RTLD_DEFAULT, symbol_name));
      return TRUE;
    }
  }

  return FALSE;
}

GumElfModule *
gum_android_open_linker_module (void)
{
  const GumModuleDetails * linker;

  linker = gum_android_get_linker_module_details ();

  return gum_elf_module_new_from_memory (linker->path,
      linker->range->base_address, NULL);
}

void *
gum_android_get_module_handle (const gchar * name)
{
  GumGetModuleHandleContext ctx;

  ctx.name = name;
  ctx.module = NULL;

  gum_enumerate_soinfo (
      (GumFoundSoinfoFunc) gum_store_module_handle_if_name_matches, &ctx);

  return ctx.module;
}

static gboolean
gum_store_module_handle_if_name_matches (const GumSoinfoDetails * details,
                                         GumGetModuleHandleContext * ctx)
{
  GumLinkerApi * api = details->api;

  if (gum_linux_module_path_matches (details->path, ctx->name))
  {
    GumSoinfoBody * sb = details->body;
    int flags = RTLD_LAZY;
    void * caller_addr = GSIZE_TO_POINTER (sb->base);

    if (gum_android_is_vdso_module_name (details->path))
      return FALSE;

    if ((sb->flags & GUM_SOINFO_NEW_FORMAT) != 0)
    {
      GumSoinfo * parent;

      parent = gum_soinfo_get_parent (details->si);
      if (parent != NULL)
      {
        caller_addr = GSIZE_TO_POINTER (gum_soinfo_get_body (parent)->base);
      }

      if (sb->version >= 1)
      {
        flags = gum_soinfo_get_rtld_flags (details->si);
      }
    }

    if (gum_android_get_api_level () >= 21)
    {
      flags |= RTLD_NOLOAD;
    }

    if (api->dlopen != NULL)
    {
      /* API level >= 26 (Android >= 8.0) */
      ctx->module = api->dlopen (details->path, flags, caller_addr);
    }
    else if (api->do_dlopen != NULL)
    {
      /* API level >= 24 (Android >= 7.0) */
      ctx->module = api->do_dlopen (details->path, flags, NULL, caller_addr);
    }
    else
    {
      ctx->module = dlopen (details->path, flags);
    }

    return FALSE;
  }

  return TRUE;
}

gboolean
gum_android_ensure_module_initialized (const gchar * name)
{
  void * module;

  module = gum_android_get_module_handle (name);
  if (module == NULL)
    return FALSE;
  dlclose (module);
  return TRUE;
}

void
gum_android_enumerate_modules (GumFoundModuleFunc func,
                               gpointer user_data)
{
  GumEnumerateModulesContext ctx;

  ctx.func = func;
  ctx.user_data = user_data;

  gum_enumerate_soinfo ((GumFoundSoinfoFunc) gum_emit_module_from_soinfo, &ctx);
}

static gboolean
gum_emit_module_from_soinfo (const GumSoinfoDetails * details,
                             GumEnumerateModulesContext * ctx)
{
  gchar * name;
  GumModuleDetails module;
  GumMemoryRange range;
  gboolean carry_on;

  name = g_path_get_basename (details->path);

  module.name = name;
  module.range = &range;
  module.path = details->path;

  if (gum_soinfo_is_linker (details->si))
  {
    range = *gum_android_get_linker_module_details ()->range;
  }
  else
  {
    GumSoinfoBody * sb = details->body;

    range.base_address = sb->base;
    range.size = sb->size;
  }

  carry_on = ctx->func (&module, ctx->user_data);

  g_free (name);

  return carry_on;
}

static void
gum_enumerate_soinfo (GumFoundSoinfoFunc func,
                      gpointer user_data)
{
  GumLinkerApi * api;
  GumSoinfo * somain, * sovdso, * solinker, * si, * next;
  GHashTable * ranges;
  GumSoinfoDetails details;
  gboolean carry_on;

  api = gum_linker_api_get ();

  pthread_mutex_lock (api->dl_mutex);

  somain = api->solist_get_somain ();
  sovdso = NULL;
  solinker = NULL;

  ranges = NULL;

  gum_init_soinfo_details (&details, somain, api, &ranges);
  carry_on = func (&details, user_data);

  next = NULL;
  for (si = api->solist_get_head (); carry_on && si != NULL; si = next)
  {
    gum_init_soinfo_details (&details, si, api, &ranges);

    if (si == somain)
      goto skip;

    if (gum_android_is_vdso_module_name (details.path))
    {
      sovdso = si;
      goto skip;
    }

    if (gum_android_is_linker_module_name (details.path))
    {
      solinker = si;
      goto skip;
    }

    carry_on = func (&details, user_data);

skip:
    next = details.body->next;
  }

  if (carry_on && sovdso != NULL)
  {
    gum_init_soinfo_details (&details, sovdso, api, &ranges);
    carry_on = func (&details, user_data);
  }

  if (carry_on && solinker != NULL)
  {
    gum_init_soinfo_details (&details, solinker, api, &ranges);
    carry_on = func (&details, user_data);
  }

  pthread_mutex_unlock (api->dl_mutex);

  if (ranges != NULL)
    g_hash_table_unref (ranges);
}

static void
gum_init_soinfo_details (GumSoinfoDetails * details,
                         GumSoinfo * si,
                         GumLinkerApi * api,
                         GHashTable ** ranges)
{
  details->path = gum_resolve_soinfo_path (si, api, ranges);
  details->si = si;
  details->body = gum_soinfo_get_body (si);
  details->api = api;
}

static const gchar *
gum_resolve_soinfo_path (GumSoinfo * si,
                         GumLinkerApi * api,
                         GHashTable ** ranges)
{
  const gchar * result = NULL;

  if (api->soinfo_get_path != NULL)
  {
    result = api->soinfo_get_path (si);

    if (strcmp (result, "[vdso]") == 0)
      result = GUM_ANDROID_VDSO_MODULE_NAME;
    else if (strcmp (result, "libdl.so") == 0)
      result = gum_android_get_linker_module_details ()->path;
    else if (result[0] != '/')
      result = NULL;
  }
  else if (gum_soinfo_is_linker (si))
  {
    result = gum_android_get_linker_module_details ()->path;
  }

  if (result == NULL)
  {
    GumLinuxNamedRange * range;

    if (*ranges == NULL)
    {
      *ranges = gum_linux_collect_named_ranges ();
    }

    range = g_hash_table_lookup (*ranges,
        GSIZE_TO_POINTER (gum_soinfo_get_body (si)->base));

    result = (range != NULL) ? range->name : "<unknown>";
  }

  return result;
}

static GumLinkerApi *
gum_linker_api_get (void)
{
  static GOnce once = G_ONCE_INIT;

  g_once (&once, (GThreadFunc) gum_linker_api_try_init, NULL);

  if (once.retval == NULL)
    gum_panic ("Unsupported Android linker; please file a bug");

  return once.retval;
}

static GumLinkerApi *
gum_linker_api_try_init (void)
{
  GumElfModule * linker;
  guint api_level, pending;
  gboolean got_dlopen_api245, got_dlopen_api26p;

  linker = gum_android_open_linker_module ();

  api_level = gum_android_get_api_level ();

  pending = 6;
  gum_elf_module_enumerate_symbols (linker,
      (GumFoundElfSymbolFunc) gum_store_linker_symbol_if_needed, &pending);

  got_dlopen_api245 =
      (gum_dl_api.do_dlopen != NULL) && (gum_dl_api.do_dlsym != NULL);
  got_dlopen_api26p =
      (gum_dl_api.dlopen != NULL) && (gum_dl_api.dlsym != NULL);

  if (api_level >= 24)
  {
    if (api_level < 26 && (got_dlopen_api245 ||
        gum_try_find_dlopen_api245_forensically (linker, &gum_dl_api)))
    {
      pending -= 2;
    }
    else if (api_level >= 26 && !got_dlopen_api26p &&
        gum_try_find_dlopen_api26p_forensically (linker, &gum_dl_api))
    {
      pending -= 2;
    }
  }
  else if (!got_dlopen_api245 && !got_dlopen_api26p)
  {
    pending -= 2;
  }

  if (gum_dl_api.dl_mutex == NULL &&
      gum_try_find_dl_mutex_forensically (linker, &gum_dl_api.dl_mutex))
  {
    pending--;
  }

  if (gum_dl_api.solist_get_head == NULL &&
      (gum_dl_api.solist != NULL || gum_dl_api.libdl_info != NULL ||
       gum_try_find_libdl_info_forensically (linker, &gum_dl_api.libdl_info)))
  {
    gum_dl_api.solist_get_head = gum_solist_get_head_fallback;
    pending--;
  }

  if (gum_dl_api.solist_get_somain == NULL &&
      (gum_dl_api.somain != NULL ||
       gum_try_find_somain_forensically (&gum_dl_api)))
  {
    gum_dl_api.solist_get_somain = gum_solist_get_somain_fallback;
    pending--;
  }

  if (gum_dl_api.soinfo_get_path == NULL)
  {
    if (api_level >= 24)
    {
      gum_dl_api.soinfo_get_path = gum_soinfo_get_path_fallback;
    }

    pending--;
  }

  gum_dl_api.trusted_caller = dlsym (RTLD_DEFAULT, "open");

  gum_object_unref (linker);

  return (pending == 0) ? &gum_dl_api : NULL;
}

#define GUM_TRY_ASSIGN(field_name, symbol_name) \
    _GUM_TRY_ASSIGN (field_name, symbol_name, 1)
#define GUM_TRY_ASSIGN_OPTIONAL(field_name, symbol_name) \
    _GUM_TRY_ASSIGN (field_name, symbol_name, 0)
#define _GUM_TRY_ASSIGN(field_name, symbol_name, pending_delta) \
    G_STMT_START \
    { \
      if (gum_dl_api.field_name == NULL && \
          strcmp (details->name, symbol_name) == 0) \
      { \
        gum_dl_api.field_name = GSIZE_TO_POINTER (details->address); \
        *pending -= pending_delta; \
        goto beach; \
      } \
    } \
    G_STMT_END

static gboolean
gum_store_linker_symbol_if_needed (const GumElfSymbolDetails * details,
                                   guint * pending)
{
  /* Restricted dlopen() implemented in API level >= 26 (Android >= 8.0). */
  GUM_TRY_ASSIGN (dlopen, "__dl___loader_dlopen");       /* >= 28 */
  GUM_TRY_ASSIGN (dlsym, "__dl___loader_dlvsym");        /* >= 28 */
  GUM_TRY_ASSIGN (dlopen, "__dl__Z8__dlopenPKciPKv");    /* >= 26 */
  GUM_TRY_ASSIGN (dlsym, "__dl__Z8__dlvsymPvPKcS1_PKv"); /* >= 26 */
  /* Namespaces implemented in API level >= 24 (Android >= 7.0). */
  GUM_TRY_ASSIGN_OPTIONAL (do_dlopen,
      "__dl__Z9do_dlopenPKciPK17android_dlextinfoPv");
  GUM_TRY_ASSIGN_OPTIONAL (do_dlsym, "__dl__Z8do_dlsymPvPKcS1_S_PS_");

  GUM_TRY_ASSIGN (dl_mutex, "__dl__ZL10g_dl_mutex"); /* >= 21 */
  GUM_TRY_ASSIGN (dl_mutex, "__dl__ZL8gDlMutex");    /*  < 21 */

  GUM_TRY_ASSIGN (solist_get_head, "__dl__Z15solist_get_headv"); /* >= 26 */
  GUM_TRY_ASSIGN_OPTIONAL (solist, "__dl__ZL6solist");           /* >= 21 */
  GUM_TRY_ASSIGN_OPTIONAL (libdl_info, "__dl_libdl_info");
"""


```