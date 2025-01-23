Response:
Let's break down the thought process for analyzing this C code file.

1. **Understand the Goal:** The request asks for a breakdown of the functionality of `gumscriptbackend.c`, its relationship to reverse engineering, its use of low-level concepts, any logical deductions, potential user errors, and how a user might reach this code.

2. **Initial Code Scan - High-Level Overview:**  Start by reading through the code to get a general understanding of its purpose and the main components involved. Look for keywords, data structures, function names, and include files.

    * Includes: `gumscriptbackend.h`, `gumquickscriptbackend.h`, `gumv8scriptbackend.h`, `<gum/gum-init.h>`, `<sqlite3.h>`. This immediately suggests it deals with script execution within the Gum framework, potentially supporting multiple JavaScript engines (QuickJS and V8), and possibly integrates with SQLite.
    * `GumScriptBackend`: This seems to be the central entity. It's defined as an interface (`G_DEFINE_INTERFACE_WITH_CODE`). This implies there will be concrete implementations.
    * `gum_script_backend_obtain`:  Looks like a factory function to get an instance of `GumScriptBackend`. It tries QuickJS first, then V8.
    * `gum_script_backend_create`, `compile`, `snapshot`: These function names strongly suggest functionalities for creating, compiling, and taking snapshots of scripts.
    * `gum_script_backend_get_scheduler`:  Points to some kind of task scheduling mechanism.
    * `gum_script_backend_extract_inline_source_map`:  Deals with extracting source maps from script code.
    * `#ifdef HAVE_SQLITE`: Conditional compilation, indicating optional SQLite support.
    * `gum_sqlite_allocator_*`: Functions related to a custom memory allocator for SQLite.

3. **Functionality Decomposition:** Go through the code section by section, detailing the purpose of each function and the overall flow.

    * **Interface Definition:** `G_DEFINE_INTERFACE_WITH_CODE` is crucial. Explain what an interface is in the context of GObject and how it enables polymorphism.
    * **Backend Selection:**  Describe `gum_script_backend_obtain` and its logic for choosing between QuickJS and V8.
    * **Script Lifecycle:** Explain the `create`, `compile`, and `snapshot` functions and their asynchronous/synchronous variations. Note the use of `GBytes` for handling script data.
    * **Locking:** Explain `gum_script_backend_with_lock_held` and `gum_script_backend_is_locked` in the context of thread safety.
    * **Scheduling:** Describe `gum_script_backend_get_scheduler` and its role in managing script execution.
    * **Source Maps:**  Explain `gum_script_backend_extract_inline_source_map` and its purpose in debugging.
    * **SQLite Integration:** Detail the custom allocator and its potential benefits (though the code doesn't explicitly state them, one can infer reasons like memory control or debugging).
    * **Initialization and Deinitialization:** Describe `gum_script_backend_init_internals`, `gum_script_backend_deinit_internals`, and the scheduler/QJS/V8 deinitialization functions.

4. **Connecting to Reverse Engineering:**  Think about how the functionalities provided by this code are relevant to reverse engineering.

    * **Dynamic Instrumentation:** Emphasize that Frida is a dynamic instrumentation tool.
    * **Script Injection:**  Explain how `create`, `compile`, and `snapshot` enable injecting and running custom JavaScript code into a target process.
    * **Hooking and Interception:**  Infer that the scripts executed by this backend are likely used for hooking and intercepting function calls.
    * **Source Map Importance:** Explain how source maps aid in debugging injected scripts within the context of the original source code.
    * **Conditional Behavior Analysis:**  Mention how scripts can be used to observe and modify the behavior of the target application.

5. **Identifying Low-Level Concepts:** Pinpoint aspects of the code that interact with the operating system or hardware at a lower level.

    * **Process Injection:** Although not explicitly in *this* file, the core purpose relates to injecting code into other processes.
    * **JavaScript Engines (QuickJS/V8):** These are complex pieces of software that interact directly with memory management and CPU instructions.
    * **Memory Management:** The custom SQLite allocator is a clear example of low-level memory manipulation.
    * **Threading and Synchronization:** The locking mechanisms hint at multi-threading considerations.
    * **Operating System APIs:**  The underlying implementations of QuickJS and V8 will rely on OS APIs.

6. **Logical Deductions (Input/Output):**  Consider the behavior of functions given certain inputs.

    * **`gum_script_backend_obtain`:** If QuickJS support is enabled (`HAVE_QUICKJS` is defined), it will return a QuickJS backend; otherwise, it will try V8. If neither is available, it will return NULL (though the current code structure prevents this).
    * **`gum_script_backend_extract_inline_source_map`:**  If the `source` string contains a valid inline source map, it will be extracted and returned; otherwise, NULL will be returned.

7. **Common User Errors:**  Think about mistakes a developer might make when using this API.

    * **Incorrect Script Syntax:** Providing invalid JavaScript code.
    * **Security Issues:** Injecting malicious scripts.
    * **Resource Leaks:**  Though the code has deinitialization, users of the `GumScript` objects (not shown here) might introduce leaks if not managed correctly.
    * **Concurrency Issues:** Incorrectly using the API without proper locking.
    * **Missing Dependencies:** Not having the necessary JavaScript engine libraries available.

8. **User Operations Leading to This Code:**  Trace the potential steps a user would take to end up using this specific file.

    * **Frida Scripting:**  The user would write a JavaScript script intended for dynamic instrumentation.
    * **Script Loading:** The Frida client would send this script to the Frida agent running in the target process.
    * **Backend Selection:** The agent would use `gum_script_backend_obtain` to select an appropriate JavaScript engine.
    * **Script Compilation/Creation:**  Functions like `gum_script_backend_create_sync` or `gum_script_backend_compile_sync` would be called to process the script.

9. **Refine and Organize:**  Structure the analysis logically with clear headings and concise explanations. Use bullet points and code snippets to illustrate key points.

10. **Review and Iterate:**  Read through the analysis to ensure accuracy, clarity, and completeness. Check if all aspects of the request have been addressed. For example, ensure that each "if" statement in the prompt has a corresponding explanation in the answer. (Self-correction: Initially, I might have missed explicitly stating that this file *doesn't* directly handle hooking, but sets up the environment for scripts that *do* the hooking.)

This systematic approach helps ensure all aspects of the code and the prompt are considered, resulting in a comprehensive and informative analysis.
好的，让我们来详细分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumscriptbackend.c` 这个文件。

**文件功能概述**

`gumscriptbackend.c` 文件是 Frida 动态插桩工具中，负责管理和抽象 JavaScript 脚本执行后端的关键组件。它的主要功能可以概括为：

1. **抽象 JavaScript 引擎:**  它提供了一个统一的接口 (`GumScriptBackend`)，使得 Frida 可以支持不同的 JavaScript 引擎，目前主要支持 QuickJS 和 V8。这个文件本身并不直接实现任何一个引擎，而是通过接口的方式，将具体的引擎实现委托给 `gumquickscriptbackend.c` 和 `gumv8scriptbackend.c`。
2. **脚本生命周期管理:**  它定义了创建、编译和快照（snapshot）JavaScript 脚本的接口。这些操作可以异步或同步执行。
3. **线程安全管理:** 提供了 `gum_script_backend_with_lock_held` 和 `gum_script_backend_is_locked` 函数，用于在多线程环境下安全地访问脚本后端。
4. **调度器管理:** 维护一个全局的脚本调度器 (`GumScriptScheduler`)，用于管理脚本的执行。
5. **内联 Source Map 处理:**  提供了 `gum_script_backend_extract_inline_source_map` 函数，用于从 JavaScript 代码中提取内联的 Source Map，方便调试。
6. **可选的 SQLite 集成:**  如果定义了 `HAVE_SQLITE` 宏，则会集成 SQLite 的支持，并使用自定义的内存分配器。

**与逆向方法的关联及举例**

`gumscriptbackend.c` 是 Frida 实现动态插桩的核心部分，与逆向方法紧密相关。

* **动态代码注入和执行:** 逆向工程师可以使用 Frida 将自定义的 JavaScript 代码注入到目标进程中，并利用 `gumscriptbackend.c` 提供的接口来创建和执行这些脚本。例如，可以使用 `gum_script_backend_create_sync` 创建一个脚本，该脚本使用 Frida 的 API（例如 `Interceptor.attach`）来 hook 目标进程中的函数。

   ```c
   // 假设已经获取了 GumScriptBackend *backend
   GError *error = NULL;
   GumScript *script = gum_script_backend_create_sync(
       backend,
       "MyScript",
       "Interceptor.attach(Module.findExportByName(null, 'my_target_function'), { onEnter: function(args) { console.log('my_target_function called!'); } });",
       NULL, // snapshot
       NULL, // cancellable
       &error
   );
   if (script == NULL) {
       g_printerr("Failed to create script: %s\n", error->message);
       g_error_free(error);
   }
   ```

* **运行时行为分析:**  通过注入 JavaScript 脚本，逆向工程师可以在程序运行时监控函数调用、修改参数、返回值，从而深入理解程序的内部逻辑和行为。`gumscriptbackend.c` 提供了执行这些分析脚本的基础设施。

* **代码覆盖率分析:** 可以编写脚本，利用 Frida API 记录代码的执行路径，分析代码覆盖率。

* **漏洞挖掘:** 通过动态修改程序行为，例如修改函数返回值或跳过某些检查，来探测潜在的安全漏洞。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例**

虽然 `gumscriptbackend.c` 本身是用 C 语言编写的，并且提供了一些抽象，但其背后的功能和依赖涉及到不少底层知识：

* **二进制底层:**
    * **JavaScript 引擎:**  无论是 QuickJS 还是 V8，都是复杂的软件，它们需要解析和执行 JavaScript 字节码或机器码。`gumscriptbackend.c` 需要与这些引擎的 API 进行交互。
    * **内存管理:**  代码中自定义了 SQLite 的内存分配器（如果启用了 SQLite），这涉及到对内存的分配、释放和重新分配的底层操作。
    * **动态链接:** Frida 需要将 JavaScript 引擎的库加载到目标进程中，这涉及到操作系统底层的动态链接机制。

* **Linux/Android:**
    * **进程间通信 (IPC):** Frida agent 运行在目标进程中，需要与 Frida client 进行通信。虽然 `gumscriptbackend.c` 本身不直接处理 IPC，但它执行的脚本通常会涉及到与 Frida agent 的交互，而 agent 使用 IPC 与 client 通信。
    * **内存操作:**  Frida 的 hook 机制需要在目标进程的内存中修改指令。`gumscriptbackend.c` 执行的脚本会使用 Frida 的 API 来进行这些内存操作。
    * **系统调用:**  JavaScript 引擎在执行过程中可能会调用底层的系统调用，例如内存分配、线程创建等。
    * **Android 框架:**  在 Android 平台上，Frida 经常用于 hook Android framework 的 API，例如 ActivityManager、PackageManager 等。`gumscriptbackend.c` 执行的脚本可以调用 Frida 提供的 Android 相关的 API 来实现这些 hook。

* **内核知识 (间接涉及):**
    * **进程和线程:**  动态插桩操作涉及到对目标进程和线程的控制和监控。
    * **内存管理:**  理解目标进程的内存布局对于编写有效的 hook 脚本至关重要。
    * **安全机制:**  Frida 的某些功能可能需要绕过操作系统的安全机制，例如地址空间布局随机化 (ASLR)。

**逻辑推理及假设输入与输出**

* **假设输入 (gum_script_backend_obtain):**
    * 场景 1: 系统已安装 QuickJS 库，并且 `HAVE_QUICKJS` 宏被定义。
    * 场景 2: 系统未安装 QuickJS 库，但已安装 V8 库，并且 `HAVE_V8` 宏被定义。
    * 场景 3: 系统既未安装 QuickJS 也未安装 V8，或者相应的宏未定义。

* **逻辑推理与输出:**
    * 场景 1: `gum_script_backend_obtain` 会首先调用 `gum_script_backend_obtain_qjs()`。由于 `HAVE_QUICKJS` 被定义，该函数会创建一个 `GumQuickScriptBackend` 实例并返回。
    * 场景 2: `gum_script_backend_obtain_qjs()` 返回 `NULL`。然后 `gum_script_backend_obtain` 会调用 `gum_script_backend_obtain_v8()`。由于 `HAVE_V8` 被定义，该函数会创建一个 `GumV8ScriptBackend` 实例并返回。
    * 场景 3: `gum_script_backend_obtain_qjs()` 返回 `NULL`，`gum_script_backend_obtain_v8()` 也返回 `NULL`。最终 `gum_script_backend_obtain` 返回 `NULL`。

* **假设输入 (gum_script_backend_extract_inline_source_map):**
    * 输入 1: `source` 字符串包含有效的内联 Source Map，例如：`"// # sourceMappingURL=data:application/json;charset=utf-8;base64,eyJ2ZXJzaW9uIjozLCJzb3VyY2VzIjpbInNjcmlwdC5qcyJdLCJuYW1lcyI6W10sIm1hcHBpbmdzIjoiIn0=\""`
    * 输入 2: `source` 字符串不包含内联 Source Map，或者包含格式错误的 Source Map。

* **逻辑推理与输出:**
    * 输入 1: `gum_script_backend_extract_inline_source_map` 会成功匹配正则表达式，解码 Base64 数据，验证 UTF-8 编码，并返回 Source Map 的字符串。
    * 输入 2: `gum_script_backend_extract_inline_source_map` 无法匹配正则表达式，或者解码或验证失败，最终返回 `NULL`。

**用户或编程常见的使用错误及举例**

* **尝试在没有初始化的情况下使用脚本后端:** 用户可能错误地尝试直接调用 `gum_script_backend_*` 系列函数，而没有先通过 `gum_script_backend_obtain()` 获取一个有效的后端实例。

   ```c
   // 错误示例
   GumScriptBackend *backend = NULL; // 没有初始化
   GError *error = NULL;
   GumScript *script = gum_script_backend_create_sync(
       backend, // backend 为 NULL，会导致程序崩溃或未定义行为
       "MyScript",
       "console.log('Hello');",
       NULL, NULL, &error
   );
   ```

* **在多线程环境下不加锁地访问脚本后端:**  如果多个线程同时调用 `gum_script_backend_*` 系列函数，可能会导致数据竞争和未定义的行为。应该使用 `gum_script_backend_with_lock_held` 来确保线程安全。

   ```c
   // 错误示例 (假设多个线程同时执行)
   // ... 获取 backend ...
   GumScript *script = gum_script_backend_create_sync(backend, ...); // 可能会发生竞争
   ```

* **传递无效的脚本源代码:**  如果传递给 `gum_script_backend_create_sync` 或 `gum_script_backend_compile_sync` 的 `source` 参数不是合法的 JavaScript 代码，会导致脚本创建或编译失败。用户需要检查 `error` 参数以获取错误信息。

* **忘记释放资源:**  尽管代码中看到了 `g_object_unref` 用于释放 `GumScriptBackend` 和 `GumScriptScheduler`，但用户如果直接操作 `GumScript` 对象，也需要注意释放这些对象的资源，避免内存泄漏。

**用户操作是如何一步步的到达这里，作为调试线索**

一个典型的用户操作流程，最终会涉及到 `gumscriptbackend.c` 中的代码：

1. **编写 Frida 脚本:** 用户编写 JavaScript 代码，用于 hook 目标进程或执行其他动态分析任务。例如，`Interceptor.attach(Module.findExportByName(null, 'open'), { onEnter: ... });`。
2. **使用 Frida 客户端连接目标进程:** 用户在终端或通过编程方式（例如 Python）使用 Frida 客户端连接到目标进程。例如，`frida -p <pid> -l my_script.js` 或使用 Python API。
3. **Frida 客户端发送脚本给 Frida agent:**  Frida 客户端将用户编写的 JavaScript 脚本发送给目标进程中运行的 Frida agent。
4. **Frida agent 接收脚本并选择脚本后端:** Frida agent 接收到脚本后，会调用 `gum_script_backend_obtain()` 来获取一个合适的 JavaScript 引擎后端实例（QuickJS 或 V8）。
5. **创建或编译脚本:** 根据用户的操作，Frida agent 会调用 `gum_script_backend_create` 或 `gum_script_backend_compile`（或其同步版本）来创建或编译接收到的 JavaScript 脚本。这部分代码在 `gumscriptbackend.c` 中定义了接口，具体的实现则在 `gumquickscriptbackend.c` 或 `gumv8scriptbackend.c` 中。
6. **执行脚本:**  创建或编译成功后，脚本会被加载到选定的 JavaScript 引擎中执行。脚本中调用的 Frida API (如 `Interceptor.attach`) 会与 Frida agent 的其他组件交互，实现 hook 等功能。

**作为调试线索:**

当用户在使用 Frida 过程中遇到问题时，理解 `gumscriptbackend.c` 的作用可以提供一些调试线索：

* **脚本加载或编译错误:** 如果用户编写的脚本存在语法错误或 Frida API 使用不当，`gum_script_backend_create_finish` 或 `gum_script_backend_compile_finish` 可能会返回错误。查看错误信息可以帮助定位问题。
* **性能问题:**  如果脚本执行缓慢，可能需要考虑选择更高效的 JavaScript 引擎，或者优化脚本代码。理解 `gumscriptbackend.c` 中涉及的引擎选择机制可以帮助用户做出更明智的选择。
* **线程安全问题:** 如果在多线程环境下使用 Frida，并且出现意外的崩溃或行为，可能是由于没有正确使用锁机制。检查是否正确调用了 `gum_script_backend_with_lock_held` 可以帮助排查问题。
* **SQLite 相关问题:** 如果启用了 SQLite 支持，并且在使用过程中遇到与数据库相关的错误，可以查看 `gum_sqlite_allocator_*` 系列函数，了解 Frida 如何管理 SQLite 的内存。

总而言之，`gumscriptbackend.c` 是 Frida 架构中一个至关重要的组件，它抽象了 JavaScript 引擎的细节，为 Frida 提供了灵活且可扩展的脚本执行能力，是理解 Frida 工作原理和进行问题排查的关键入口点之一。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumscriptbackend.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2015-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptbackend.h"

#include "gumquickscriptbackend.h"
#include "gumv8scriptbackend.h"

#include <gum/gum-init.h>
#ifdef HAVE_SQLITE
# include <sqlite3.h>
#endif

#define GUM_SQLITE_BLOCK_ALLOC_SIZE(s) (sizeof (GumSqliteBlock) + (s))
#define GUM_SQLITE_BLOCK_TO_CLIENT(b) (((GumSqliteBlock *) (b)) + 1)
#define GUM_SQLITE_BLOCK_FROM_CLIENT(b) (((GumSqliteBlock *) (b)) - 1)

typedef struct _GumSqliteBlock GumSqliteBlock;

struct _GumSqliteBlock
{
  int size;
  int padding;
};

static void gum_script_backend_deinit_scheduler (void);

static void gum_script_backend_init_internals (void);
static void gum_script_backend_deinit_internals (void);

#ifdef HAVE_SQLITE
static int gum_sqlite_allocator_init (void * data);
static void gum_sqlite_allocator_shutdown (void * data);
static void * gum_sqlite_allocator_malloc (int size);
static void gum_sqlite_allocator_free (void * mem);
static void * gum_sqlite_allocator_realloc (void * mem, int n_bytes);
static int gum_sqlite_allocator_size (void * mem);
static int gum_sqlite_allocator_roundup (int size);
#endif

G_DEFINE_INTERFACE_WITH_CODE (GumScriptBackend, gum_script_backend,
    G_TYPE_OBJECT, gum_script_backend_init_internals ())

static GRegex * gum_inline_source_map_pattern;

static void
gum_script_backend_default_init (GumScriptBackendInterface * iface)
{
}

GumScriptBackend *
gum_script_backend_obtain (void)
{
  GumScriptBackend * backend = NULL;

  backend = gum_script_backend_obtain_qjs ();
  if (backend == NULL)
    backend = gum_script_backend_obtain_v8 ();

  return backend;
}

#ifdef HAVE_QUICKJS

static void gum_script_backend_deinit_qjs (void);

GumScriptBackend *
gum_script_backend_obtain_qjs (void)
{
  static gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GumScriptBackend * backend;

    backend = g_object_new (GUM_QUICK_TYPE_SCRIPT_BACKEND, NULL);

    _gum_register_early_destructor (gum_script_backend_deinit_qjs);

    g_once_init_leave (&gonce_value, GPOINTER_TO_SIZE (backend) + 1);
  }

  return GSIZE_TO_POINTER (gonce_value - 1);
}

static void
gum_script_backend_deinit_qjs (void)
{
  g_object_unref (gum_script_backend_obtain_qjs ());
}

#else

GumScriptBackend *
gum_script_backend_obtain_qjs (void)
{
  return NULL;
}

#endif

#ifdef HAVE_V8

static void gum_script_backend_deinit_v8 (void);

GumScriptBackend *
gum_script_backend_obtain_v8 (void)
{
  static gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GumScriptBackend * backend;

    backend = g_object_new (GUM_V8_TYPE_SCRIPT_BACKEND, NULL);

    _gum_register_early_destructor (gum_script_backend_deinit_v8);

    g_once_init_leave (&gonce_value, GPOINTER_TO_SIZE (backend) + 1);
  }

  return GSIZE_TO_POINTER (gonce_value - 1);
}

static void
gum_script_backend_deinit_v8 (void)
{
  g_object_unref (gum_script_backend_obtain_v8 ());
}

#else

GumScriptBackend *
gum_script_backend_obtain_v8 (void)
{
  return NULL;
}

#endif

void
gum_script_backend_create (GumScriptBackend * self,
                           const gchar * name,
                           const gchar * source,
                           GBytes * snapshot,
                           GCancellable * cancellable,
                           GAsyncReadyCallback callback,
                           gpointer user_data)
{
  GUM_SCRIPT_BACKEND_GET_IFACE (self)->create (self, name, source, snapshot,
      cancellable, callback, user_data);
}

GumScript *
gum_script_backend_create_finish (GumScriptBackend * self,
                                  GAsyncResult * result,
                                  GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_IFACE (self)->create_finish (self, result,
      error);
}

GumScript *
gum_script_backend_create_sync (GumScriptBackend * self,
                                const gchar * name,
                                const gchar * source,
                                GBytes * snapshot,
                                GCancellable * cancellable,
                                GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_IFACE (self)->create_sync (self, name, source,
      snapshot, cancellable, error);
}

void
gum_script_backend_create_from_bytes (GumScriptBackend * self,
                                      GBytes * bytes,
                                      GBytes * snapshot,
                                      GCancellable * cancellable,
                                      GAsyncReadyCallback callback,
                                      gpointer user_data)
{
  GUM_SCRIPT_BACKEND_GET_IFACE (self)->create_from_bytes (self, bytes, snapshot,
      cancellable, callback, user_data);
}

GumScript *
gum_script_backend_create_from_bytes_finish (GumScriptBackend * self,
                                             GAsyncResult * result,
                                             GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_IFACE (self)->create_from_bytes_finish (self,
      result, error);
}

GumScript *
gum_script_backend_create_from_bytes_sync (GumScriptBackend * self,
                                           GBytes * bytes,
                                           GBytes * snapshot,
                                           GCancellable * cancellable,
                                           GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_IFACE (self)->create_from_bytes_sync (self,
      bytes, snapshot, cancellable, error);
}

void
gum_script_backend_compile (GumScriptBackend * self,
                            const gchar * name,
                            const gchar * source,
                            GCancellable * cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
  GUM_SCRIPT_BACKEND_GET_IFACE (self)->compile (self, name, source, cancellable,
      callback, user_data);
}

GBytes *
gum_script_backend_compile_finish (GumScriptBackend * self,
                                   GAsyncResult * result,
                                   GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_IFACE (self)->compile_finish (self, result,
      error);
}

GBytes *
gum_script_backend_compile_sync (GumScriptBackend * self,
                                 const gchar * name,
                                 const gchar * source,
                                 GCancellable * cancellable,
                                 GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_IFACE (self)->compile_sync (self, name, source,
      cancellable, error);
}

void
gum_script_backend_snapshot (GumScriptBackend * self,
                             const gchar * embed_script,
                             const gchar * warmup_script,
                             GCancellable * cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
  GUM_SCRIPT_BACKEND_GET_IFACE (self)->snapshot (self, embed_script,
      warmup_script, cancellable, callback, user_data);
}

GBytes *
gum_script_backend_snapshot_finish (GumScriptBackend * self,
                                    GAsyncResult * result,
                                    GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_IFACE (self)->snapshot_finish (self, result,
      error);
}

GBytes *
gum_script_backend_snapshot_sync (GumScriptBackend * self,
                                  const gchar * embed_script,
                                  const gchar * warmup_script,
                                  GCancellable * cancellable,
                                  GError ** error)
{
  return GUM_SCRIPT_BACKEND_GET_IFACE (self)->snapshot_sync (self, embed_script,
      warmup_script, cancellable, error);
}

void
gum_script_backend_with_lock_held (GumScriptBackend * self,
                                   GumScriptBackendLockedFunc func,
                                   gpointer user_data)
{
  GUM_SCRIPT_BACKEND_GET_IFACE (self)->with_lock_held (self, func, user_data);
}

gboolean
gum_script_backend_is_locked (GumScriptBackend * self)
{
  return GUM_SCRIPT_BACKEND_GET_IFACE (self)->is_locked (self);
}

GumScriptScheduler *
gum_script_backend_get_scheduler (void)
{
  static gsize gonce_value;

  if (g_once_init_enter (&gonce_value))
  {
    GumScriptScheduler * scheduler;

    scheduler = gum_script_scheduler_new ();

    _gum_register_early_destructor (gum_script_backend_deinit_scheduler);

    g_once_init_leave (&gonce_value, GPOINTER_TO_SIZE (scheduler) + 1);
  }

  return GSIZE_TO_POINTER (gonce_value - 1);
}

static void
gum_script_backend_deinit_scheduler (void)
{
  g_object_unref (gum_script_backend_get_scheduler ());
}

gchar *
gum_script_backend_extract_inline_source_map (const gchar * source)
{
  gchar * result = NULL;
  GMatchInfo * match_info;

  g_regex_match (gum_inline_source_map_pattern, source, 0, &match_info);
  if (g_match_info_matches (match_info))
  {
    gchar * data_encoded, * data;
    gsize size;

    data_encoded = g_match_info_fetch (match_info, 1);

    data = (gchar *) g_base64_decode (data_encoded, &size);
    if (data != NULL && g_utf8_validate (data, size, NULL))
    {
      result = g_strndup (data, size);
    }
    g_free (data);

    g_free (data_encoded);
  }

  g_match_info_free (match_info);

  return result;
}

static void
gum_script_backend_init_internals (void)
{
#ifdef HAVE_SQLITE
  sqlite3_mem_methods gum_mem_methods = {
    gum_sqlite_allocator_malloc,
    gum_sqlite_allocator_free,
    gum_sqlite_allocator_realloc,
    gum_sqlite_allocator_size,
    gum_sqlite_allocator_roundup,
    gum_sqlite_allocator_init,
    gum_sqlite_allocator_shutdown,
    NULL,
  };

  sqlite3_config (SQLITE_CONFIG_MALLOC, &gum_mem_methods);
  sqlite3_config (SQLITE_CONFIG_MULTITHREAD);

  sqlite3_initialize ();
#endif

  gum_inline_source_map_pattern = g_regex_new ("//[#@][ \\t]sourceMappingURL="
      "[ \\t]*data:application/json;.*?base64,([^\\s'\"]*)[ \\t]*$",
      G_REGEX_MULTILINE, 0, NULL);

  _gum_register_early_destructor (gum_script_backend_deinit_internals);
}

static void
gum_script_backend_deinit_internals (void)
{
  g_regex_unref (gum_inline_source_map_pattern);

#ifdef HAVE_SQLITE
  sqlite3_shutdown ();
#endif
}

#ifdef HAVE_SQLITE

static int
gum_sqlite_allocator_init (void * data)
{
  return SQLITE_OK;
}

static void
gum_sqlite_allocator_shutdown (void * data)
{
}

static void *
gum_sqlite_allocator_malloc (int size)
{
  GumSqliteBlock * block;

  block = g_malloc (GUM_SQLITE_BLOCK_ALLOC_SIZE (size));
  block->size = size;

  return GUM_SQLITE_BLOCK_TO_CLIENT (block);
}

static void
gum_sqlite_allocator_free (void * mem)
{
  GumSqliteBlock * block = GUM_SQLITE_BLOCK_FROM_CLIENT (mem);

  g_free (block);
}

static void *
gum_sqlite_allocator_realloc (void * mem,
                              int n_bytes)
{
  GumSqliteBlock * block = GUM_SQLITE_BLOCK_FROM_CLIENT (mem);

  block = g_realloc (block, GUM_SQLITE_BLOCK_ALLOC_SIZE (n_bytes));
  block->size = n_bytes;

  return GUM_SQLITE_BLOCK_TO_CLIENT (block);
}

static int
gum_sqlite_allocator_size (void * mem)
{
  GumSqliteBlock * block = GUM_SQLITE_BLOCK_FROM_CLIENT (mem);

  return block->size;
}

static int
gum_sqlite_allocator_roundup (int size)
{
  return size;
}

#endif
```