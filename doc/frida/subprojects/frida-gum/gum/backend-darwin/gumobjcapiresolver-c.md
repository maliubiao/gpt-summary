Response:
Let's break down the thought process for analyzing this C code and answering the prompt.

**1. Understanding the Goal:**

The primary goal is to analyze the provided C source code for `gumobjcapiresolver.c` and explain its functionality in the context of Frida, reverse engineering, and potentially lower-level concepts. The prompt also specifically asks for examples, assumptions, user errors, and debugging steps.

**2. Initial Code Scan and Keyword Recognition:**

The first step is a quick scan of the code, looking for recognizable patterns and keywords. This helps to form an initial understanding of the code's purpose. Key things to notice:

* **Copyright and License:**  Indicates the origin and licensing of the code. Not directly functional, but good context.
* **`#ifndef GUM_DIET`:**  Suggests conditional compilation, likely related to different build configurations (e.g., a "diet" or lightweight version). We'll assume the full version for this analysis.
* **Includes:** `<dlfcn.h>`, `<objc/runtime.h>`, `<stdlib.h>`, and the internal Frida headers (`guminterceptor.h`, etc.) immediately signal that this code interacts with the Objective-C runtime.
* **`GumObjcApiResolver` struct:** This is the central data structure. The members (`query_pattern`, `available`, `class_by_handle`, etc.) provide clues about the class's responsibilities.
* **Function names:**  Functions like `gum_objc_api_resolver_enumerate_matches`, `gum_objc_api_resolver_create_snapshot`, `_gum_objc_api_resolver_find_method_by_address` clearly suggest functionalities related to finding Objective-C methods.
* **`GObject` and `G_DEFINE_TYPE_EXTENDED`:** Indicates the use of the GLib object system, a common framework in projects like Frida.
* **Use of `dlsym` and `dlopen`:** Confirms interaction with dynamic libraries, specifically `libobjc.A.dylib`.
* **Regular expressions (`GRegex`) and pattern matching (`GPatternSpec`):** Hints at the ability to search for methods using patterns.
* **Hash tables (`GHashTable`) and linked lists (`GSList`):** Common data structures for efficient data storage and retrieval.

**3. Identifying Core Functionality:**

Based on the initial scan, it becomes clear that this code is about resolving (finding) Objective-C APIs (classes and methods). The core functions seem to be:

* **Initialization (`gum_objc_api_resolver_init`):** Loads the Objective-C runtime library and gets pointers to relevant functions.
* **Enumeration (`gum_objc_api_resolver_enumerate_matches`):** Takes a query string (likely a pattern for class and method names) and iterates through the available Objective-C classes and methods, calling a callback function for each match.
* **Snapshotting (`gum_objc_api_resolver_create_snapshot`):** Creates a representation of the currently loaded Objective-C classes and their methods. This is likely for performance and consistency.
* **Address Lookup (`_gum_objc_api_resolver_find_method_by_address`):**  The reverse of enumeration – given an address, find the corresponding Objective-C method.

**4. Connecting to Reverse Engineering:**

The "enumerate matches" and "find method by address" functionalities are fundamental to dynamic analysis and reverse engineering. This allows a user to:

* **Discover available methods:** See what methods a specific class or set of classes implements.
* **Find the implementation of a method:**  Given the address where a method is executed, determine the method's name and class. This is crucial for setting breakpoints and understanding code flow.

**5. Identifying Low-Level Concepts:**

The code directly interacts with the Objective-C runtime, which is a low-level concept. Specifically:

* **Objective-C Runtime:**  The functions like `objc_getClassList`, `objc_lookUpClass`, `class_getName`, `method_getImplementation`, etc., are all part of the Objective-C runtime API.
* **Dynamic Linking:** The use of `dlopen` and `dlsym` demonstrates interaction with the dynamic linker.
* **Memory Management:**  The code uses `g_new`, `g_malloc`, `g_slice_new`, and `g_free` (or `gum_libc_free`), indicating memory management responsibilities. The `GumObjcDisposeClassPairMonitor` suggests handling events related to class unloading.

**6. Inferring Logical Reasoning and Assumptions:**

The code makes several assumptions and uses logical steps:

* **Query Pattern Parsing:** The regular expression in `gum_objc_api_resolver_init` defines the expected format for queries. The code assumes the input query adheres to this format.
* **Class Hierarchy Traversal:**  The `gum_objc_api_resolver_enumerate_matches_for_class` function recursively traverses the class hierarchy (subclasses) to find matching methods. This assumes a standard Objective-C inheritance model.
* **Caching:**  The `class_by_handle` hash table acts as a cache to improve performance by avoiding repeated lookups of class information.

**7. Considering User Errors:**

Potential user errors include:

* **Incorrect Query Format:** Providing a query string that doesn't match the expected regular expression will lead to an error.
* **Typos in Class or Method Names:**  Case sensitivity (unless explicitly ignored) and spelling are crucial.

**8. Tracing User Actions (Debugging Clues):**

To understand how a user reaches this code, consider the typical Frida workflow for interacting with Objective-C:

1. **Frida Script:** A user writes a JavaScript (or Python) Frida script.
2. **API Resolution Request:** The script likely uses Frida's API to find Objective-C methods. For example: `ObjC.classes.NSString["stringWithUTF8String:"].implementation`.
3. **Frida Core:** The Frida core receives this request.
4. **API Resolver Dispatch:**  The core determines that this is an Objective-C API request and dispatches it to the appropriate resolver, which is `gumobjcapiresolver.c`.
5. **Query Matching:** The resolver parses the request (e.g., "NSString" and "stringWithUTF8String:") and uses its internal logic to find the matching method implementation.
6. **Result Return:** The resolver returns the address (and potentially other details) of the method to the Frida core, which then passes it back to the user's script.

**9. Structuring the Answer:**

Finally, organize the gathered information into a clear and structured answer, addressing each point of the prompt with relevant code snippets and explanations. Use clear headings and bullet points to improve readability. Provide concrete examples for each point where applicable.

This systematic approach allows for a comprehensive analysis of the provided C code and the generation of a detailed and informative answer to the prompt. It involves understanding the code's purpose, its interaction with external libraries and systems, and its role within the larger Frida ecosystem.
好的，让我们来详细分析一下 `gumobjcapiresolver.c` 这个文件。

**文件功能概述**

`gumobjcapiresolver.c` 文件是 Frida 工具中负责解析和查找 Objective-C API（主要是类和方法）的组件。它的主要功能是：

1. **提供 Objective-C API 的动态查找能力:**  允许 Frida 在运行时查找目标进程中加载的 Objective-C 类及其方法。
2. **支持通过模式匹配进行查找:**  允许用户使用类似正则表达式的模式来查找特定的类或方法。
3. **缓存已查找到的 API 信息:**  通过缓存机制提高查找效率。
4. **处理 Objective-C 运行时的动态变化:**  监听类加载和卸载事件，保持 API 信息的准确性。
5. **将查找到的 API 信息返回给 Frida 核心:**  为 Frida 的其他组件提供可用的 Objective-C API 信息，用于 hook、调用等操作。

**与逆向方法的关系及举例**

`gumobjcapiresolver.c` 是 Frida 实现动态 Instrumentation 的核心组成部分，与逆向工程的方法紧密相关。它使得逆向工程师能够在运行时探索和操作目标应用的 Objective-C 代码。

**举例说明:**

假设你想知道 `NSString` 类中所有以 `initWith` 开头的方法的实现地址，你可以使用 Frida 的 JavaScript API：

```javascript
ObjC.schedule(function() {
  const NSString = ObjC.classes.NSString;
  for (const methodName in NSString) {
    if (methodName.startsWith('initWith')) {
      const method = NSString[methodName];
      console.log(`Method: -[NSString ${methodName}], Implementation: ${method.implementation}`);
    }
  }
});
```

在这个过程中，Frida 内部会调用 `gumobjcapiresolver.c` 提供的功能，使用类似 `-[NSString initWith*]` 的模式去查找匹配的方法，并将找到的方法名和实现地址返回给 JavaScript。

**二进制底层、Linux、Android 内核及框架的知识**

虽然 `gumobjcapiresolver.c` 主要关注 Objective-C 运行时，但它仍然涉及到一些底层概念：

1. **二进制底层:**
   - **动态链接:**  代码使用了 `dlopen` 和 `dlsym` 来加载和获取 Objective-C 运行时库 (`libobjc.A.dylib`) 中的函数。这是动态链接的基础知识。
   - **函数指针:**  代码中定义了函数指针类型，例如 `GumLibcFreeFunc`，并使用 `dlsym` 获取这些函数的地址。
   - **内存管理:**  使用了 `malloc` (通过 `gum_module_find_export_by_name` 获取 `free`) 和 GLib 提供的内存管理函数（如 `g_new`, `g_free`, `g_slice_new`, `g_hash_table_new_full` 等）。

2. **Linux:**
   - **动态链接库:**  `libobjc.A.dylib` 是 macOS 上的 Objective-C 运行时库，但在 Linux 上，对应的可能是 `libobjc.so` 或其他名称。Frida 的设计是跨平台的，虽然这个文件针对 Darwin (macOS)，但在其他平台上会有类似的实现。
   - **文件路径:**  代码中硬编码了 `/usr/lib/system/libsystem_malloc.dylib` 和 `/usr/lib/libobjc.A.dylib` 的路径，这是 macOS 上的标准路径。在 Linux 或 Android 上，这些路径会不同。

3. **Android 内核及框架:**
   - **Objective-C 在 iOS 和 macOS 上使用:**  Android 系统主要使用 Java 和 Kotlin。因此，`gumobjcapiresolver.c` 这个特定的文件不会直接涉及到 Android 内核。
   - **Frida 在 Android 上的对应实现:**  在 Android 上，Frida 会有类似的组件来解析和查找 Dalvik/ART 虚拟机中的类和方法，但实现方式和涉及的技术栈会完全不同 (例如，涉及到 `libart.so` 和 JNI)。

**逻辑推理及假设输入与输出**

`gumobjcapiresolver.c` 中存在一些逻辑推理，例如：

**假设输入:** 用户在 Frida 脚本中请求查找 `NSString` 类中所有以 `length` 开头的方法（不区分大小写）。查询字符串可能是 `-[NSString length*]/i`.

**逻辑推理步骤:**

1. **解析查询字符串:** `gum_objc_api_resolver_enumerate_matches` 函数会使用正则表达式解析查询字符串，提取方法类型 (`-`), 类名模式 (`NSString`), 方法名模式 (`length*`)，以及是否忽略大小写 (`/i`)。
2. **获取类列表快照:** 如果 `class_by_handle` 为空，则调用 `gum_objc_api_resolver_create_snapshot` 获取当前加载的所有 Objective-C 类的信息。
3. **遍历类:** 遍历已加载的类，并使用 `g_pattern_match_string` 检查类名是否匹配 `NSString` 模式。
4. **遍历方法:** 对于匹配的类 (`NSString`)，获取其所有实例方法（因为查询字符串指定了 `-`）。
5. **匹配方法名:** 使用 `g_pattern_match_string` 检查每个方法名是否匹配 `length*` 模式（忽略大小写）。
6. **调用回调函数:** 对于匹配的方法，调用用户提供的回调函数 (`GumFoundApiFunc`)，传递包含方法详细信息（名称、地址等）的 `GumApiDetails` 结构。

**可能的输出 (传递给回调函数的信息):**

```
details.name = "-[NSString length]"
details.address = 0x7ff807c1d920  // 示例地址
details.size = GUM_API_SIZE_NONE
```

**用户或编程常见的使用错误**

1. **查询字符串格式错误:**  如果用户提供的查询字符串不符合 `gum_objc_api_resolver_init` 中定义的正则表达式，`g_regex_match` 会失败，导致查找无法进行。
   ```
   // 错误示例：缺少方法类型
   // Resolver.enumerateMatches("NSString length", ...);
   ```
   Frida 会返回一个错误，提示查询格式不正确。

2. **类名或方法名拼写错误:**  如果用户输入的类名或方法名拼写错误，`g_pattern_match_string` 将无法找到匹配项。
   ```javascript
   // 错误示例：类名拼写错误
   ObjC.classes.NSSting; // 应该为 NSString
   ```
   在这种情况下，不会找到任何匹配的方法。

3. **大小写敏感性问题:**  如果用户没有在查询字符串中指定 `/i` 来忽略大小写，那么大小写不匹配的方法将不会被找到。
   ```javascript
   // 查询区分大小写
   // Resolver.enumerateMatches("-[NSString Length]", ...); // 假设实际方法名为 length
   ```

**用户操作如何一步步到达这里 (作为调试线索)**

以下是一个典型的用户操作流程，最终会涉及到 `gumobjcapiresolver.c`：

1. **用户编写 Frida 脚本:** 用户编写一个 JavaScript 或 Python 脚本，使用 Frida 的 API 来与目标应用交互。例如，用户想 hook `NSString` 的 `stringWithUTF8String:` 方法。
   ```javascript
   if (ObjC.available) {
     ObjC.schedule(function() {
       const NSString = ObjC.classes.NSString;
       const stringWithUTF8String = NSString["stringWithUTF8String:"];
       if (stringWithUTF8String) {
         Interceptor.attach(stringWithUTF8String.implementation, {
           onEnter: function(args) {
             console.log("stringWithUTF8String called with:", ObjC.Object(args[2]).toString());
           }
         });
       } else {
         console.log("stringWithUTF8String: method not found");
       }
     });
   } else {
     console.log("Objective-C runtime is not available.");
   }
   ```

2. **Frida 执行脚本:** 用户使用 Frida CLI 或其他工具将脚本注入到目标进程中。
   ```bash
   frida -p <process_id> -l your_script.js
   ```

3. **`ObjC.classes.NSString` 的解析:** 当 JavaScript 代码执行到 `ObjC.classes.NSString` 时，Frida 的 JavaScript 桥接层会尝试获取 `NSString` 类的相关信息。

4. **调用 `gumobjcapiresolver`:** Frida 内部会调用 `gumobjcapiresolver.c` 中的相关函数（例如，通过 `objc_lookUpClass` 或遍历类列表）来查找 `NSString` 类。

5. **`NSString["stringWithUTF8String:"]` 的解析:** 接着，当访问 `NSString["stringWithUTF8String:"]` 时，Frida 会再次调用 `gumobjcapiresolver.c`，这次使用 `-[NSString stringWithUTF8String:]` 或类似的模式来查找 `NSString` 类的 `stringWithUTF8String:` 方法。

6. **查找方法实现:** `gumobjcapiresolver.c` 会使用 Objective-C 运行时提供的 API (例如 `class_getMethodImplementation`) 获取该方法的实现地址。

7. **`Interceptor.attach`:**  如果找到方法，`Interceptor.attach` 函数会将 hook 逻辑与该方法的实现地址关联起来。这个过程本身不直接在 `gumobjcapiresolver.c` 中，但依赖于它提供的地址信息。

**调试线索:**

- **检查 Frida 是否成功连接到目标进程:**  确保 Frida 能够正常注入。
- **查看 Frida 控制台输出:**  Frida 会输出错误信息，例如无法找到类或方法。
- **使用 Frida 的调试功能:**  可以在 Frida 脚本中添加 `console.log` 来跟踪变量的值和执行流程。
- **检查目标进程中是否加载了 Objective-C 运行时:**  如果目标进程不是一个使用 Objective-C 的应用，`ObjC.available` 将为 `false`。
- **使用更精确的查询字符串:**  如果查找不到方法，可以尝试更精确的查询字符串，或者检查类名和方法名的拼写是否正确。

总而言之，`gumobjcapiresolver.c` 是 Frida 连接到 Objective-C 世界的桥梁，它使得 Frida 能够理解和操作 Objective-C 的对象和方法，为动态逆向分析提供了强大的能力。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/gum/backend-darwin/gumobjcapiresolver.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。

"""
/*
 * Copyright (C) 2016-2023 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C)      2020 Grant Douglas <grant@reconditorium.uk>
 * Copyright (C)      2021 Abdelrahman Eid <hot3eed@gmail.com>
 * Copyright (C)      2021 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#ifndef GUM_DIET

#include "gumobjcapiresolver.h"

#include "guminterceptor.h"
#include "gumobjcapiresolver-priv.h"
#include "gumobjcdisposeclasspairmonitor.h"
#include "gumprocess.h"

#include <dlfcn.h>
#include <objc/runtime.h>
#include <stdlib.h>

typedef struct _GumObjcClassMetadata GumObjcClassMetadata;
typedef void (* GumLibcFreeFunc) (gpointer mem);

struct _GumObjcApiResolver
{
  GObject parent;

  GRegex * query_pattern;

  gboolean available;
  GHashTable * class_by_handle;
  GumObjcDisposeClassPairMonitor * monitor;

  gint (* objc_getClassList) (Class * buffer, gint class_count);
  Class (* objc_lookUpClass) (const gchar * name);
  Class (* class_getSuperclass) (Class klass);
  const gchar * (* class_getName) (Class klass);
  Method * (* class_copyMethodList) (Class klass, guint * method_count);
  Class (* object_getClass) (gpointer object);
  SEL (* method_getName) (Method method);
  IMP (* method_getImplementation) (Method method);
  const gchar * (* sel_getName) (SEL selector);
};

struct _GumObjcClassMetadata
{
  Class handle;
  const gchar * name;

  Method * class_methods;
  guint class_method_count;

  Method * instance_methods;
  guint instance_method_count;

  GSList * subclasses;

  GumObjcApiResolver * resolver;
};

static void gum_objc_api_resolver_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_objc_api_resolver_dispose (GObject * object);
static void gum_objc_api_resolver_finalize (GObject * object);
static void gum_objc_api_resolver_enumerate_matches (GumApiResolver * resolver,
    const gchar * query, GumFoundApiFunc func, gpointer user_data,
    GError ** error);
static gboolean gum_objc_api_resolver_enumerate_matches_for_class (
    GumObjcApiResolver * self, GumObjcClassMetadata * klass, gchar method_type,
    GPatternSpec * method_spec, GHashTable * visited_classes,
    gboolean ignore_case, GumFoundApiFunc func, gpointer user_data);

static gchar gum_method_type_from_match_info (GMatchInfo * match_info,
    gint match_num);
static GPatternSpec * gum_pattern_spec_from_match_info (GMatchInfo * match_info,
    gint match_num, gboolean ignore_case);

static GHashTable * gum_objc_api_resolver_create_snapshot (
    GumObjcApiResolver * resolver);

static void gum_objc_class_metadata_free (GumObjcClassMetadata * klass);
static const Method * gum_objc_class_metadata_get_methods (
    GumObjcClassMetadata * self, gchar type, guint * count);
static gboolean gum_objc_class_metadata_is_disposed (
    GumObjcClassMetadata * self);

G_DEFINE_TYPE_EXTENDED (GumObjcApiResolver,
                        gum_objc_api_resolver,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_API_RESOLVER,
                            gum_objc_api_resolver_iface_init))

static GumLibcFreeFunc gum_libc_free;

static void
gum_objc_api_resolver_class_init (GumObjcApiResolverClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  gum_libc_free = (GumLibcFreeFunc) gum_module_find_export_by_name (
      "/usr/lib/system/libsystem_malloc.dylib", "free");

  object_class->dispose = gum_objc_api_resolver_dispose;
  object_class->finalize = gum_objc_api_resolver_finalize;
}

static void
gum_objc_api_resolver_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  GumApiResolverInterface * iface = g_iface;

  iface->enumerate_matches = gum_objc_api_resolver_enumerate_matches;
}

static void
gum_objc_api_resolver_init (GumObjcApiResolver * self)
{
  gpointer objc;

  self->query_pattern = g_regex_new ("([+*-])\\[(\\S+)\\s+(\\S+)\\](\\/i)?", 0,
      0, NULL);

  objc = dlopen ("/usr/lib/libobjc.A.dylib",
      RTLD_LAZY | RTLD_GLOBAL | RTLD_NOLOAD);
  if (objc == NULL)
    goto beach;

#define GUM_TRY_ASSIGN_OBJC_FUNC(N) \
    self->N = dlsym (objc, G_STRINGIFY (N)); \
    if (self->N == NULL) \
      goto beach

  GUM_TRY_ASSIGN_OBJC_FUNC (objc_getClassList);
  GUM_TRY_ASSIGN_OBJC_FUNC (objc_lookUpClass);
  GUM_TRY_ASSIGN_OBJC_FUNC (class_getSuperclass);
  GUM_TRY_ASSIGN_OBJC_FUNC (class_getName);
  GUM_TRY_ASSIGN_OBJC_FUNC (class_copyMethodList);
  GUM_TRY_ASSIGN_OBJC_FUNC (object_getClass);
  GUM_TRY_ASSIGN_OBJC_FUNC (method_getName);
  GUM_TRY_ASSIGN_OBJC_FUNC (method_getImplementation);
  GUM_TRY_ASSIGN_OBJC_FUNC (sel_getName);

  self->available = TRUE;
  self->monitor = gum_objc_dispose_class_pair_monitor_obtain ();

beach:
  if (objc != NULL)
    dlclose (objc);
}

static void
gum_objc_api_resolver_dispose (GObject * object)
{
  GumObjcApiResolver * self = GUM_OBJC_API_RESOLVER (object);

  g_clear_object (&self->monitor);

  G_OBJECT_CLASS (gum_objc_api_resolver_parent_class)->dispose (object);
}

static void
gum_objc_api_resolver_finalize (GObject * object)
{
  GumObjcApiResolver * self = GUM_OBJC_API_RESOLVER (object);

  g_clear_pointer (&self->class_by_handle, g_hash_table_unref);

  g_regex_unref (self->query_pattern);

  G_OBJECT_CLASS (gum_objc_api_resolver_parent_class)->finalize (object);
}

GumApiResolver *
gum_objc_api_resolver_new (void)
{
  GumObjcApiResolver * resolver;

  resolver = g_object_new (GUM_TYPE_OBJC_API_RESOLVER, NULL);
  if (!resolver->available)
  {
    g_object_unref (resolver);
    return NULL;
  }

  return GUM_API_RESOLVER (resolver);
}

static void
gum_objc_api_resolver_ensure_class_by_handle (GumObjcApiResolver * self)
{
  g_rec_mutex_lock (&self->monitor->mutex);

  if (self->class_by_handle == NULL)
    self->class_by_handle = gum_objc_api_resolver_create_snapshot (self);

  g_rec_mutex_unlock (&self->monitor->mutex);
}

static void
gum_objc_api_resolver_enumerate_matches (GumApiResolver * resolver,
                                         const gchar * query,
                                         GumFoundApiFunc func,
                                         gpointer user_data,
                                         GError ** error)
{
  GumObjcApiResolver * self = GUM_OBJC_API_RESOLVER (resolver);
  GMatchInfo * query_info;
  gboolean ignore_case;
  gchar method_type;
  GPatternSpec * class_spec, * method_spec;
  GHashTableIter iter;
  gboolean carry_on;
  GHashTable * visited_classes;
  GumObjcClassMetadata * klass;

  if (self->monitor == NULL)
    return;

  g_regex_match (self->query_pattern, query, 0, &query_info);
  if (!g_match_info_matches (query_info))
    goto invalid_query;

  ignore_case = g_match_info_get_match_count (query_info) >= 5;

  method_type = gum_method_type_from_match_info (query_info, 1);
  class_spec = gum_pattern_spec_from_match_info (query_info, 2, ignore_case);
  method_spec = gum_pattern_spec_from_match_info (query_info, 3, ignore_case);

  g_match_info_free (query_info);

  gum_objc_api_resolver_ensure_class_by_handle (self);

  g_hash_table_iter_init (&iter, self->class_by_handle);
  carry_on = TRUE;
  visited_classes = g_hash_table_new (NULL, NULL);
  while (carry_on && g_hash_table_iter_next (&iter, NULL, (gpointer *) &klass))
  {
    const gchar * class_name = klass->name;
    gchar * class_name_copy = NULL;

    if (gum_objc_class_metadata_is_disposed (klass))
    {
      g_hash_table_iter_remove (&iter);
      continue;
    }

    if (ignore_case)
    {
      class_name_copy = g_utf8_strdown (class_name, -1);
      class_name = class_name_copy;
    }

    if (g_pattern_match_string (class_spec, class_name))
    {
      carry_on = gum_objc_api_resolver_enumerate_matches_for_class (self, klass,
          method_type, method_spec, visited_classes, ignore_case, func,
          user_data);
    }

    g_free (class_name_copy);
  }
  g_hash_table_unref (visited_classes);

  g_pattern_spec_free (method_spec);
  g_pattern_spec_free (class_spec);

  return;

invalid_query:
  {
    g_set_error (error, GUM_ERROR, GUM_ERROR_INVALID_ARGUMENT,
        "invalid query; format is: "
        "-[NS*Number foo:bar:], +[Foo foo*] or *[Bar baz]");
  }
}

static gboolean
gum_objc_api_resolver_enumerate_matches_for_class (GumObjcApiResolver * self,
                                                   GumObjcClassMetadata * klass,
                                                   gchar method_type,
                                                   GPatternSpec * method_spec,
                                                   GHashTable * visited_classes,
                                                   gboolean ignore_case,
                                                   GumFoundApiFunc func,
                                                   gpointer user_data)
{
  const gchar all_method_types[3] = { '+', '-', '\0' };
  const gchar one_method_type[2] = { method_type, '\0' };
  const gchar * method_types, * t;
  gboolean carry_on;
  GSList * cur;

  if (g_hash_table_lookup (visited_classes, klass) != NULL)
    return TRUE;
  g_hash_table_add (visited_classes, klass);

  method_types = (method_type == '*') ? all_method_types : one_method_type;

  for (t = method_types; *t != '\0'; t++)
  {
    const Method * method_handles;
    guint method_count, method_index;
    const gchar prefix[3] = { *t, '[', '\0' };
    const gchar suffix[2] = { ']', '\0' };

    method_handles =
        gum_objc_class_metadata_get_methods (klass, *t, &method_count);
    for (method_index = 0; method_index != method_count; method_index++)
    {
      Method method_handle = method_handles[method_index];
      const gchar * method_name, * canonical_method_name;
      gchar * method_name_copy = NULL;

      method_name = self->sel_getName (self->method_getName (method_handle));
      canonical_method_name = method_name;

      if (ignore_case)
      {
        method_name_copy = g_utf8_strdown (method_name, -1);
        method_name = method_name_copy;
      }

      if (g_pattern_match_string (method_spec, method_name))
      {
        GumApiDetails details;

        details.name = g_strconcat (prefix, klass->name, " ",
            canonical_method_name, suffix, NULL);
        details.address = GUM_ADDRESS (
            self->method_getImplementation (method_handle));
        details.size = GUM_API_SIZE_NONE;

        carry_on = func (&details, user_data);

        g_free ((gpointer) details.name);

        if (!carry_on)
        {
          g_free (method_name_copy);
          return FALSE;
        }
      }

      g_free (method_name_copy);
    }
  }

  for (cur = klass->subclasses; cur != NULL; cur = cur->next)
  {
    Class subclass_handle = cur->data;
    GumObjcClassMetadata * subclass;

    subclass = g_hash_table_lookup (self->class_by_handle, subclass_handle);
    if (subclass == NULL)
      continue;

    if (gum_objc_class_metadata_is_disposed (subclass))
      continue;

    carry_on = gum_objc_api_resolver_enumerate_matches_for_class (self,
        subclass, method_type, method_spec, visited_classes, ignore_case, func,
        user_data);
    if (!carry_on)
      return FALSE;
  }

  return TRUE;
}

gchar *
_gum_objc_api_resolver_find_method_by_address (GumApiResolver * resolver,
                                               GumAddress address)
{
  GumObjcApiResolver * self = GUM_OBJC_API_RESOLVER (resolver);
  gchar * result = NULL;
  GumAddress bare_address;
  gint class_count, class_index;
  Class * classes;

  if (self->monitor == NULL)
    return NULL;

  bare_address = gum_strip_code_address (address);

  g_rec_mutex_lock (&self->monitor->mutex);

  class_count = self->objc_getClassList (NULL, 0);
  classes = g_new (Class, class_count);
  self->objc_getClassList (classes, class_count);

  for (class_index = 0;
      class_index != class_count && result == NULL;
      class_index++)
  {
    Class handle = classes[class_index];
    GumObjcClassMetadata * klass;
    const gchar * t;
    const gchar all_method_types[] = { '+', '-', '\0' };

    klass = g_slice_new (GumObjcClassMetadata);
    klass->handle = handle;
    klass->name = self->class_getName (handle);
    klass->class_methods = NULL;
    klass->instance_methods = NULL;
    klass->subclasses = NULL;

    klass->resolver = self;

    for (t = all_method_types; *t != '\0' && result == NULL; t++)
    {
      const Method * method_handles;
      guint count, i;

      method_handles = gum_objc_class_metadata_get_methods (klass, *t, &count);

      for (i = 0; i != count; i++)
      {
        Method handle = method_handles[i];
        GumAddress imp;

        imp = GUM_ADDRESS (self->method_getImplementation (handle));

        if (gum_strip_code_address (imp) == bare_address)
        {
          const gchar * name;
          const gchar prefix[3] = { *t, '[', '\0' };
          const gchar suffix[2] = { ']', '\0' };

          name = self->sel_getName (self->method_getName (handle));

          result = g_strconcat (prefix, klass->name, " ", name, suffix, NULL);
          break;
        }
      }
    }

    gum_objc_class_metadata_free (klass);
  }

  g_rec_mutex_unlock (&self->monitor->mutex);

  g_free (classes);

  return result;
}

static gchar
gum_method_type_from_match_info (GMatchInfo * match_info,
                                 gint match_num)
{
  gchar * type_str, type;

  type_str = g_match_info_fetch (match_info, match_num);
  type = type_str[0];
  g_free (type_str);

  return type;
}

static GPatternSpec *
gum_pattern_spec_from_match_info (GMatchInfo * match_info,
                                  gint match_num,
                                  gboolean ignore_case)
{
  GPatternSpec * spec;
  gchar * pattern;

  pattern = g_match_info_fetch (match_info, match_num);
  if (ignore_case)
  {
    gchar * str = g_utf8_strdown (pattern, -1);
    g_free (pattern);
    pattern = str;
  }

  spec = g_pattern_spec_new (pattern);

  g_free (pattern);

  return spec;
}

static GHashTable *
gum_objc_api_resolver_create_snapshot (GumObjcApiResolver * self)
{
  GHashTable * class_by_handle;
  gint class_count, class_index;
  Class * classes;

  class_by_handle = g_hash_table_new_full (NULL, NULL, NULL,
      (GDestroyNotify) gum_objc_class_metadata_free);

  class_count = self->objc_getClassList (NULL, 0);
  classes = g_malloc (class_count * sizeof (Class));
  self->objc_getClassList (classes, class_count);

  for (class_index = 0; class_index != class_count; class_index++)
  {
    Class handle = classes[class_index];
    GumObjcClassMetadata * klass;

    klass = g_slice_new (GumObjcClassMetadata);
    klass->handle = handle;
    klass->name = self->class_getName (handle);
    klass->class_methods = NULL;
    klass->instance_methods = NULL;
    klass->subclasses = NULL;

    klass->resolver = self;

    g_hash_table_insert (class_by_handle, handle, klass);
  }

  for (class_index = 0; class_index != class_count; class_index++)
  {
    Class handle = classes[class_index];
    Class super_handle;

    super_handle = self->class_getSuperclass (handle);
    if (super_handle != NULL)
    {
      GumObjcClassMetadata * klass;

      klass = g_hash_table_lookup (class_by_handle, super_handle);
      if (klass != NULL)
        klass->subclasses = g_slist_prepend (klass->subclasses, handle);
    }
  }

  g_free (classes);

  return class_by_handle;
}

static void
gum_objc_class_metadata_free (GumObjcClassMetadata * klass)
{
  g_slist_free (klass->subclasses);

  if (klass->instance_methods != NULL)
    gum_libc_free (klass->instance_methods);

  if (klass->class_methods != NULL)
    gum_libc_free (klass->class_methods);

  g_slice_free (GumObjcClassMetadata, klass);
}

static const Method *
gum_objc_class_metadata_get_methods (GumObjcClassMetadata * self,
                                     gchar type,
                                     guint * count)
{
  Method ** cached_methods;
  guint * cached_method_count;

  if (type == '+')
  {
    cached_methods = &self->class_methods;
    cached_method_count = &self->class_method_count;
  }
  else
  {
    cached_methods = &self->instance_methods;
    cached_method_count = &self->instance_method_count;
  }

  if (*cached_methods == NULL)
  {
    GumObjcApiResolver * resolver = self->resolver;

    *cached_methods = resolver->class_copyMethodList (
        (type == '+') ? resolver->object_getClass (self->handle) : self->handle,
        cached_method_count);
  }

  *count = *cached_method_count;

  return *cached_methods;
}

static gboolean
gum_objc_class_metadata_is_disposed (GumObjcClassMetadata * self)
{
  GumObjcApiResolver * resolver = self->resolver;

  return resolver->objc_lookUpClass (self->name) != self->handle;
}

#endif

"""

```