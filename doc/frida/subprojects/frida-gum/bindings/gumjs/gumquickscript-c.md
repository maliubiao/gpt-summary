Response:
Let's break down the thought process to analyze the C code for `gumquickscript.c`.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of this specific C file within the larger Frida project. We need to identify its core purpose, its interactions with other parts of Frida, and its relevance to dynamic instrumentation and reverse engineering.

**2. Initial Scan and Keyword Spotting:**

The first step is to quickly scan the code and identify key terms, data structures, and function names. This gives us a high-level overview. Some immediately noticeable elements are:

* **Includes:**  `gumquickscript.h`, and a bunch of other `gumquick*` headers. This suggests that this file is central to the "quick script" functionality.
* **Data Structures:** `GumQuickScript`, `GumUnloadNotifyCallback`, `GumEmitData`, `GumPostData`, `GumQuickWorker`, etc. These structures hint at the various aspects of script management, communication, and execution.
* **Function Prefixes:**  `gum_quick_script_*`, `gum_quick_worker_*`. This naming convention strongly indicates the modules these functions belong to.
* **`GObject` and GTK-related types:** `GObject`, `GMainContext`, `GBytes`, `GSList`, `GMutex`, `GCond`, `GError`, `GSource`, etc. This confirms that Frida's core is built on the GObject system, a common C framework.
* **`JSContext`, `JSRuntime`, `JSValue`:**  These are clearly related to a JavaScript engine, which is expected for Frida's scripting capabilities.
* **Keywords related to instrumentation:**  `interceptor`, `stalker`, `cloak`, `memory`, `module`, `process`, `thread`. These strongly suggest the file's involvement in manipulating the target process.
* **Keywords related to scripting:** `source`, `bytecode`, `load`, `unload`, `message`, `emit`, `post`.
* **Conditional Compilation:** `#ifdef HAVE_SQLITE`. This indicates optional features.

**3. Focusing on the `GumQuickScript` Structure:**

The `struct _GumQuickScript` is likely the most important structure in this file. Examining its members reveals its core responsibilities:

* **Metadata:** `name`, `source`, `bytecode`. Stores information about the script itself.
* **Context Management:** `main_context`, `backend`, `state`, `on_unload`, `rt`, `ctx`, `program`. Deals with the lifecycle and execution environment of the script.
* **Sub-modules (Composition):**  `core`, `kernel`, `memory`, `module`, `thread`, `process`, `file`, `checksum`, `stream`, `socket`, `database`, `interceptor`, `api_resolver`, `symbol`, `cmodule`, `instruction`, `code_writer`, `code_relocator`, `stalker`, `cloak`. This is a crucial observation: `GumQuickScript` *aggregates* various functionalities, acting as a central coordinator.
* **Communication:** `message_handler`, `message_handler_data`. Handles communication between the script and the Frida core.

**4. Analyzing Key Function Groups:**

Based on the function prefixes, we can group functions and deduce their purposes:

* **Lifecycle (`gum_quick_script_load*`, `gum_quick_script_unload*`):** These functions manage the loading and unloading of the script, including asynchronous and synchronous operations.
* **Context Management (`gum_quick_script_create_context`, `gum_quick_script_destroy_context`):** Handles the creation and destruction of the JavaScript execution environment.
* **Message Handling (`gum_quick_script_set_message_handler`, `gum_quick_script_post`, `gum_quick_script_emit`):** Deals with sending messages to and from the script.
* **Worker Management (`gum_quick_worker_*`):** Manages the creation and execution of JavaScript workers.
* **Property Handling (`gum_quick_script_get_property`, `gum_quick_script_set_property`):**  Provides access to the script's properties.

**5. Connecting to Reverse Engineering Concepts:**

Now, we explicitly connect the discovered functionalities to reverse engineering methods:

* **Interception (`GumQuickInterceptor`):**  This directly relates to hooking and intercepting function calls, a fundamental technique in dynamic analysis.
* **Code Tracing (`GumQuickStalker`):**  Allows for tracing the execution flow of the target application.
* **Memory Manipulation (`GumQuickMemory`):** Enables reading and writing to the target process's memory.
* **Module and Symbol Resolution (`GumQuickModule`, `GumQuickSymbol`, `GumQuickApiResolver`):**  Provides information about loaded libraries and their functions.
* **Code Injection (`GumQuickCodeWriter`, `GumQuickCodeRelocator`):**  Facilitates injecting custom code into the target process.
* **Cloaking (`GumQuickCloak`):**  Likely related to techniques for hiding Frida's presence from anti-instrumentation measures.

**6. Inferring Interactions and Dependencies:**

By examining the included headers and the function parameters, we can infer how `gumquickscript.c` interacts with other parts of Frida:

* **`gumquickscriptbackend.h`:**  The backend seems to handle the actual execution of the JavaScript code and provides an abstraction layer.
* **`gumscripttask.h`:**  Asynchronous operations are managed using `GumScriptTask`.
* **Other `gumquick*.h` headers:**  Indicate the components managed by `GumQuickScript`.
* **The JavaScript engine:** The code extensively uses the JavaScript C API.

**7. Reasoning and Examples:**

Based on the identified functionalities, we can start reasoning about use cases and providing examples:

* **Reverse Engineering:** Hooking `open()` to monitor file access, tracing calls to a specific API, modifying return values of functions.
* **Binary/OS/Kernel:** Accessing memory addresses, interacting with kernel objects (though the level of direct kernel interaction might be abstracted), understanding process and thread concepts.
* **User Errors:**  Incorrectly formatted scripts, trying to load a script in an invalid state, misuse of the API.

**8. Debugging Hints:**

Understanding the lifecycle and state transitions (`GUM_SCRIPT_STATE_*`) provides valuable debugging clues if something goes wrong during script loading or unloading.

**9. Structuring the Answer:**

Finally, the information needs to be organized logically. Starting with a general overview of the file's purpose and then diving into specific functionalities, providing examples, and addressing the prompt's specific questions about reverse engineering, low-level details, and potential errors. The "User Operations" section reconstructs the likely steps a user would take to interact with this code indirectly.

**Self-Correction/Refinement:**

During the analysis, we might need to revisit earlier assumptions or refine our understanding. For instance, initially, one might not be entirely sure what the "backend" is. However, by seeing functions like `gum_quick_script_backend_make_runtime`, it becomes clearer that the backend handles the underlying JavaScript engine. Similarly, the purpose of `GumQuickCloak` might not be immediately obvious but can be inferred from the context of anti-instrumentation.这是 frida 动态Instrumentation 工具中 `frida/subprojects/frida-gum/bindings/gumjs/gumquickscript.c` 文件的第一部分源代码。 这个文件是实现 Frida 中“快速脚本”功能的核心组件。  它负责加载、卸载和管理 JavaScript 脚本，并提供与目标进程交互的各种能力。

**功能归纳:**

总的来说，`gumquickscript.c` 文件的主要功能是：

1. **脚本生命周期管理:**  负责 JavaScript 脚本的创建、加载、运行、卸载和清理。
2. **JavaScript 运行时环境管理:**  创建和管理用于执行 JavaScript 代码的运行时环境（JSRuntime 和 JSContext）。
3. **Frida 核心 API 暴露:**  初始化并管理一系列用于与目标进程交互的核心 Frida API 对象，例如内存操作、模块操作、进程操作、线程操作、文件操作、网络操作、拦截器、代码追踪器 (stalker) 等。
4. **脚本通信机制:**  提供脚本与 Frida 核心之间的消息传递机制 (post 和 emit)。
5. **多线程支持 (Worker):**  支持创建和管理 JavaScript Worker，允许在独立的线程中执行脚本代码。
6. **错误处理:**  处理脚本加载和执行过程中可能出现的错误。
7. **与其他 Frida 组件的集成:**  与脚本后端 (backend)、任务调度器 (scheduler) 等其他 Frida 组件进行交互。

**与逆向方法的关系及举例说明:**

这个文件是 Frida 实现动态逆向的核心部分，因为它提供了在目标进程中执行 JavaScript 代码的能力，从而可以实现各种动态分析和修改行为。

* **代码 Hook (拦截):**  `GumQuickInterceptor` 组件允许在目标进程的函数执行前后插入 JavaScript 代码。
    * **举例:**  可以 Hook `open()` 系统调用，在每次打开文件时记录文件名和参数，从而监控应用程序的文件访问行为。
* **代码追踪 (Stalker):** `GumQuickStalker` 组件允许跟踪目标进程的代码执行流程。
    * **举例:**  可以追踪特定函数的调用路径，了解其执行逻辑，或者监控关键代码段的执行频率。
* **内存操作:** `GumQuickMemory` 组件允许读取和修改目标进程的内存。
    * **举例:**  可以读取敏感数据（例如加密密钥），或者修改函数返回值来改变程序行为。
* **模块和符号解析:** `GumQuickModule` 和 `GumQuickSymbol` 组件允许访问目标进程加载的模块和符号信息。
    * **举例:**  可以列出所有加载的动态链接库，或者查找特定函数的地址以便进行 Hook。
* **代码注入:** 虽然这个文件本身不直接负责代码注入，但它管理的 `GumQuickCodeWriter` 和 `GumQuickCodeRelocator` 组件是实现代码注入的基础，用于在运行时生成和重定位机器码。
    * **举例:**  配合拦截器，可以在函数入口处注入一段新的代码，执行自定义逻辑后再跳转回原始代码。

**涉及二进制底层、Linux、Android 内核及框架的知识及举例说明:**

这个文件虽然主要处理的是 JavaScript 脚本的执行环境，但其底层的 Frida 功能必然涉及到对操作系统和硬件的理解。

* **二进制底层:**
    * **代码重定位 (`GumQuickCodeRelocator`):**  在动态修改代码时，需要理解目标架构的指令格式和寻址方式，以便正确地生成和重定位机器码。
    * **函数调用约定:**  Hook 函数时，需要理解目标平台的函数调用约定 (例如参数传递方式、寄存器使用等)。
* **Linux/Android 内核:**
    * **系统调用拦截:**  Frida 的拦截机制通常基于对系统调用的监控或修改，这需要理解 Linux 或 Android 内核的系统调用接口。
    * **进程和线程管理:**  `GumQuickProcess` 和 `GumQuickThread` 组件涉及到对操作系统进程和线程模型的理解，例如进程的内存空间、线程的上下文切换等。
    * **内存管理:**  `GumQuickMemory` 组件的操作直接与操作系统底层的内存管理机制相关，例如虚拟内存、内存保护等。
* **Android 框架:**
    * **Art/Dalvik 虚拟机:** 在 Android 环境下，Frida 需要与 Art 或 Dalvik 虚拟机进行交互，理解其内部结构和运行机制，例如方法调用、对象模型等。

**逻辑推理及假设输入与输出:**

由于这是 C 代码，且主要负责框架的搭建和管理，其逻辑推理更多体现在对不同状态的判断和流程的控制。

* **假设输入:** 一个包含 JavaScript 代码的字符串 (作为 `source` 属性传入) 或编译后的字节码 (`bytecode` 属性)。
* **逻辑推理:** 当调用 `gum_quick_script_load` 时，会检查脚本的状态 (`self->state`)，如果状态为 `GUM_SCRIPT_STATE_CREATED`，则会创建 JavaScript 运行时环境，编译或读取脚本代码，并执行脚本的入口点。
* **假设输出:**  如果加载成功，脚本的状态会变为 `GUM_SCRIPT_STATE_LOADED`，并且脚本中定义的全局对象和函数可以在 Frida 中被调用和交互。如果加载失败，会返回错误信息。

**涉及用户或编程常见的使用错误及举例说明:**

用户在使用 Frida 和编写脚本时的一些错误可能会导致程序执行到这个文件中的某些逻辑，例如：

* **尝试在脚本加载前或卸载后进行操作:**  如果用户尝试在脚本还未加载完成或者已经卸载后调用 Frida 的 API（例如 Hook 函数），会导致状态检查失败，可能会触发错误处理逻辑。
    * **举例:**  在脚本的 `load` 事件触发前就尝试调用 `Interceptor.attach()`.
* **脚本语法错误:**  如果提供的 JavaScript 代码存在语法错误，会导致 `gum_quick_script_create_context` 中的编译或读取程序失败。
    * **举例:**  JavaScript 代码中缺少分号或括号不匹配。
* **尝试卸载一个未加载的脚本:**  调用 `gum_quick_script_unload` 时，如果脚本状态不是 `GUM_SCRIPT_STATE_LOADED`，将会报错。
* **资源泄漏:**  虽然代码中使用了 `g_object_unref` 等进行资源管理，但如果用户在 JavaScript 脚本中创建了大量的对象且未进行适当的清理，可能导致内存泄漏，最终影响 Frida 的性能。

**用户操作如何一步步的到达这里，作为调试线索:**

用户操作通常通过 Frida 的 Python API 或命令行工具与 Frida Agent 交互，最终触发 `gumquickscript.c` 中的代码执行。 步骤可能如下：

1. **用户编写 JavaScript 脚本:**  用户编写用于动态分析或修改目标进程的 JavaScript 代码。
2. **用户使用 Frida API 加载脚本:**  用户在 Python 中使用 `frida.attach()` 连接到目标进程，然后调用 `session.create_script(script_source)` 或 `session.create_script_from_file(script_path)` 来加载脚本。
3. **Frida Python API 调用 C 代码:**  Python API 内部会将加载脚本的请求传递给 Frida 的 C 代码层。
4. **`gum_script_backend_create_script` (或其他后端创建函数):**  在 Frida 的后端实现中，会创建 `GumQuickScript` 对象，并将脚本的源代码或字节码传递给它。
5. **`gum_quick_script_set_property`:**  设置 `GumQuickScript` 对象的属性，例如 `name`、`source` 或 `bytecode`。
6. **`script.load()` 调用:** 用户在 Python 中调用 `script.load()` 方法，触发 `gum_quick_script_load` 函数。
7. **脚本加载流程:** `gum_quick_script_load` 函数会创建 JavaScript 运行时环境，编译或加载脚本，并执行脚本的入口点。  在这个过程中，会调用 `gum_quick_script_create_context` 等函数。
8. **脚本中的 Frida API 调用:**  在 JavaScript 脚本中，用户会使用 `Interceptor.attach()`, `Memory.read*()`, `Module.findExportByName()` 等 Frida 提供的 API。  这些 API 的调用会映射到 `gumquickscript.c` 中管理的各个组件 (例如 `GumQuickInterceptor`, `GumQuickMemory`, `GumQuickModule`) 的相应功能。

**总结 (针对第一部分):**

`gumquickscript.c` 的第一部分定义了 `GumQuickScript` 对象及其相关的结构体和枚举类型，并实现了脚本对象的基本生命周期管理和属性操作。 核心功能包括创建和管理 JavaScript 运行时环境，以及初始化一系列用于与目标进程交互的 Frida 核心 API 组件。  它为后续的脚本执行和与目标进程的交互奠定了基础。  理解这部分代码有助于深入理解 Frida 的架构和脚本加载机制。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickscript.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2020-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumquickscript.h"

#include "gumquickapiresolver.h"
#include "gumquickchecksum.h"
#include "gumquickcloak.h"
#include "gumquickcmodule.h"
#include "gumquickcoderelocator.h"
#include "gumquickcodewriter.h"
#include "gumquickcore.h"
#include "gumquickfile.h"
#include "gumquickinstruction.h"
#include "gumquickinterceptor.h"
#include "gumquickkernel.h"
#include "gumquickmemory.h"
#include "gumquickmodule.h"
#include "gumquickprocess.h"
#include "gumquickscript-priv.h"
#include "gumquickscript-runtime.h"
#include "gumquickscriptbackend-priv.h"
#include "gumquickscriptbackend.h"
#include "gumquicksocket.h"
#include "gumquickstalker.h"
#include "gumquickstream.h"
#include "gumquicksymbol.h"
#include "gumquickthread.h"
#include "gumscripttask.h"
#ifdef HAVE_SQLITE
# include "gumquickdatabase.h"
#endif

typedef guint GumScriptState;
typedef struct _GumUnloadNotifyCallback GumUnloadNotifyCallback;
typedef void (* GumUnloadNotifyFunc) (GumQuickScript * self,
    gpointer user_data);
typedef struct _GumEmitData GumEmitData;
typedef struct _GumPostData GumPostData;
typedef guint GumWorkerState;
typedef struct _GumWorkerMessageDelivery GumWorkerMessageDelivery;

struct _GumQuickScript
{
  GObject parent;

  gchar * name;
  gchar * source;
  GBytes * bytecode;
  GMainContext * main_context;
  GumQuickScriptBackend * backend;

  GumScriptState state;
  GSList * on_unload;
  JSRuntime * rt;
  JSContext * ctx;
  GumESProgram * program;
  GumQuickCore core;
  GumQuickKernel kernel;
  GumQuickMemory memory;
  GumQuickModule module;
  GumQuickThread thread;
  GumQuickProcess process;
  GumQuickFile file;
  GumQuickChecksum checksum;
  GumQuickStream stream;
  GumQuickSocket socket;
#ifdef HAVE_SQLITE
  GumQuickDatabase database;
#endif
  GumQuickInterceptor interceptor;
  GumQuickApiResolver api_resolver;
  GumQuickSymbol symbol;
  GumQuickCModule cmodule;
  GumQuickInstruction instruction;
  GumQuickCodeWriter code_writer;
  GumQuickCodeRelocator code_relocator;
  GumQuickStalker stalker;
  GumQuickCloak cloak;

  GumScriptMessageHandler message_handler;
  gpointer message_handler_data;
  GDestroyNotify message_handler_data_destroy;
};

enum
{
  PROP_0,
  PROP_NAME,
  PROP_SOURCE,
  PROP_BYTECODE,
  PROP_MAIN_CONTEXT,
  PROP_BACKEND
};

enum _GumScriptState
{
  GUM_SCRIPT_STATE_CREATED,
  GUM_SCRIPT_STATE_LOADING,
  GUM_SCRIPT_STATE_LOADED,
  GUM_SCRIPT_STATE_UNLOADING,
  GUM_SCRIPT_STATE_UNLOADED
};

struct _GumUnloadNotifyCallback
{
  GumUnloadNotifyFunc func;
  gpointer data;
  GDestroyNotify data_destroy;
};

struct _GumEmitData
{
  GumQuickScript * script;
  gchar * message;
  GBytes * data;
};

struct _GumPostData
{
  GumQuickScript * script;
  gchar * message;
  GBytes * data;
};

struct _GumQuickWorker
{
  gint ref_count;

  GumWorkerState state;

  gboolean flushed;
  GMutex flush_mutex;
  GCond flush_cond;

  GumQuickScript * script;
  GumESAsset * asset;
  JSValue on_message;

  GumScriptScheduler * scheduler;

  GRecMutex scope_mutex;

  JSRuntime * rt;
  JSContext * ctx;

  JSValue entrypoint;

  GumQuickCore core;
  GumQuickKernel kernel;
  GumQuickMemory memory;
  GumQuickModule module;
  GumQuickProcess process;
  GumQuickThread thread;
  GumQuickFile file;
  GumQuickChecksum checksum;
  GumQuickStream stream;
  GumQuickSocket socket;
#ifdef HAVE_SQLITE
  GumQuickDatabase database;
#endif
  GumQuickApiResolver api_resolver;
  GumQuickSymbol symbol;
  GumQuickCModule cmodule;
  GumQuickInstruction instruction;
  GumQuickCodeWriter code_writer;
  GumQuickCodeRelocator code_relocator;
  GumQuickCloak cloak;
};

enum _GumWorkerState
{
  GUM_WORKER_CREATED,
  GUM_WORKER_INITIALIZED,
  GUM_WORKER_LOADED,
  GUM_WORKER_RUNNING,
  GUM_WORKER_TERMINATED,
};

struct _GumWorkerMessageDelivery
{
  GumQuickWorker * worker;
  gchar * message;
  GBytes * data;
};

static void gum_quick_script_iface_init (gpointer g_iface, gpointer iface_data);

static void gum_quick_script_dispose (GObject * object);
static void gum_quick_script_finalize (GObject * object);
static void gum_quick_script_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_quick_script_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);
static void gum_quick_script_destroy_context (GumQuickScript * self);

static void gum_quick_script_load (GumScript * script,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_quick_script_load_finish (GumScript * script,
    GAsyncResult * result);
static void gum_quick_script_load_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_quick_script_do_load (GumScriptTask * task,
    GumQuickScript * self, gpointer task_data, GCancellable * cancellable);
static void gum_quick_script_execute_entrypoints (GumQuickScript * self,
    GumScriptTask * task);
static JSValue gum_quick_script_on_entrypoints_executed (JSContext * ctx,
    JSValueConst this_val, int argc, JSValueConst * argv, int magic,
    JSValue * func_data);
static gboolean gum_quick_script_complete_load_task (GumScriptTask * task);
static void gum_quick_script_unload (GumScript * script,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_quick_script_unload_finish (GumScript * script,
    GAsyncResult * result);
static void gum_quick_script_unload_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_quick_script_do_unload (GumScriptTask * task,
    GumQuickScript * self, gpointer task_data, GCancellable * cancellable);
static void gum_quick_script_complete_unload_task (GumQuickScript * self,
    GumScriptTask * task);
static void gum_quick_script_try_unload (GumQuickScript * self);
static void gum_quick_script_once_unloaded (GumQuickScript * self,
    GumUnloadNotifyFunc func, gpointer data, GDestroyNotify data_destroy);

static void gum_quick_script_set_message_handler (GumScript * script,
    GumScriptMessageHandler handler, gpointer data,
    GDestroyNotify data_destroy);
static void gum_quick_script_post (GumScript * script, const gchar * message,
    GBytes * data);
static void gum_quick_script_do_post (GumPostData * d);
static void gum_quick_post_data_free (GumPostData * d);

static void gum_quick_script_set_debug_message_handler (GumScript * backend,
    GumScriptDebugMessageHandler handler, gpointer data,
    GDestroyNotify data_destroy);
static void gum_quick_script_post_debug_message (GumScript * backend,
    const gchar * message);

static GumStalker * gum_quick_script_get_stalker (GumScript * script);

static void gum_quick_script_emit (const gchar * message, GBytes * data,
    GumQuickScript * self);
static gboolean gum_quick_script_do_emit (GumEmitData * d);
static void gum_quick_emit_data_free (GumEmitData * d);

static GumQuickWorker * gum_quick_worker_new (GumQuickScript * script,
    GumESAsset * asset, JSValue on_message);
static void gum_quick_worker_run (GumQuickWorker * self);
static void gum_quick_worker_flush (GumQuickWorker * self);
static void gum_quick_worker_do_post (GumWorkerMessageDelivery * d);
static void gum_quick_worker_emit (const gchar * message, GBytes * data,
    GumQuickWorker * self);
static void gum_quick_worker_do_emit (GumWorkerMessageDelivery * d);

static GumWorkerMessageDelivery * gum_worker_message_delivery_new (
    GumQuickWorker * worker, const gchar * message, GBytes * data);
static void gum_worker_message_delivery_free (GumWorkerMessageDelivery * d);

G_DEFINE_TYPE_EXTENDED (GumQuickScript,
                        gum_quick_script,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT,
                            gum_quick_script_iface_init))

static void
gum_quick_script_class_init (GumQuickScriptClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_quick_script_dispose;
  object_class->finalize = gum_quick_script_finalize;
  object_class->get_property = gum_quick_script_get_property;
  object_class->set_property = gum_quick_script_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_SOURCE,
      g_param_spec_string ("source", "Source", "Source code", NULL,
      G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BYTECODE,
      g_param_spec_boxed ("bytecode", "Bytecode", "Bytecode", G_TYPE_BYTES,
      G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_MAIN_CONTEXT,
      g_param_spec_boxed ("main-context", "MainContext",
      "MainContext being used", G_TYPE_MAIN_CONTEXT,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
  g_object_class_install_property (object_class, PROP_BACKEND,
      g_param_spec_object ("backend", "Backend", "Backend being used",
      GUM_QUICK_TYPE_SCRIPT_BACKEND,
      G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY | G_PARAM_STATIC_STRINGS));
}

static void
gum_quick_script_iface_init (gpointer g_iface,
                             gpointer iface_data)
{
  GumScriptInterface * iface = g_iface;

  iface->load = gum_quick_script_load;
  iface->load_finish = gum_quick_script_load_finish;
  iface->load_sync = gum_quick_script_load_sync;
  iface->unload = gum_quick_script_unload;
  iface->unload_finish = gum_quick_script_unload_finish;
  iface->unload_sync = gum_quick_script_unload_sync;

  iface->set_message_handler = gum_quick_script_set_message_handler;
  iface->post = gum_quick_script_post;

  iface->set_debug_message_handler = gum_quick_script_set_debug_message_handler;
  iface->post_debug_message = gum_quick_script_post_debug_message;

  iface->get_stalker = gum_quick_script_get_stalker;
}

static void
gum_quick_script_init (GumQuickScript * self)
{
  self->name = g_strdup ("agent");

  self->state = GUM_SCRIPT_STATE_CREATED;
  self->on_unload = NULL;
}

static void
gum_quick_script_dispose (GObject * object)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (object);
  GumScript * script = GUM_SCRIPT (self);

  gum_quick_script_set_message_handler (script, NULL, NULL, NULL);

  if (self->state == GUM_SCRIPT_STATE_LOADED)
  {
    /* dispose() will be triggered again at the end of unload() */
    gum_quick_script_unload (script, NULL, NULL, NULL);
  }
  else
  {
    if (self->state == GUM_SCRIPT_STATE_CREATED && self->ctx != NULL)
      gum_quick_script_destroy_context (self);

    g_clear_pointer (&self->main_context, g_main_context_unref);
    g_clear_pointer (&self->backend, g_object_unref);
  }

  G_OBJECT_CLASS (gum_quick_script_parent_class)->dispose (object);
}

static void
gum_quick_script_finalize (GObject * object)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (object);

  g_free (self->name);
  g_free (self->source);
  g_bytes_unref (self->bytecode);

  G_OBJECT_CLASS (gum_quick_script_parent_class)->finalize (object);
}

static void
gum_quick_script_get_property (GObject * object,
                               guint property_id,
                               GValue * value,
                               GParamSpec * pspec)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_value_set_string (value, self->name);
      break;
    case PROP_MAIN_CONTEXT:
      g_value_set_boxed (value, self->main_context);
      break;
    case PROP_BACKEND:
      g_value_set_object (value, self->backend);
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

static void
gum_quick_script_set_property (GObject * object,
                               guint property_id,
                               const GValue * value,
                               GParamSpec * pspec)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (object);

  switch (property_id)
  {
    case PROP_NAME:
      g_free (self->name);
      self->name = g_value_dup_string (value);
      break;
    case PROP_SOURCE:
      g_free (self->source);
      self->source = g_value_dup_string (value);
      break;
    case PROP_BYTECODE:
      g_bytes_unref (self->bytecode);
      self->bytecode = g_value_dup_boxed (value);
      break;
    case PROP_MAIN_CONTEXT:
      if (self->main_context != NULL)
        g_main_context_unref (self->main_context);
      self->main_context = g_value_dup_boxed (value);
      break;
    case PROP_BACKEND:
      if (self->backend != NULL)
        g_object_unref (self->backend);
      self->backend = GUM_QUICK_SCRIPT_BACKEND (g_value_dup_object (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

gboolean
gum_quick_script_create_context (GumQuickScript * self,
                                 GError ** error)
{
  GumQuickCore * core = &self->core;
  JSRuntime * rt;
  JSContext * ctx;
  GumESProgram * program;
  JSValue global_obj;
  GumQuickScope scope = { core, NULL, };

  g_assert (self->ctx == NULL);

  rt = gum_quick_script_backend_make_runtime (self->backend);
  JS_SetRuntimeOpaque (rt, core);

  ctx = JS_NewContext (rt);
  JS_SetContextOpaque (ctx, core);

  if (self->bytecode != NULL)
  {
    program = gum_quick_script_backend_read_program (self->backend, ctx,
        self->bytecode, error);
  }
  else
  {
    program = gum_quick_script_backend_compile_program (self->backend, ctx,
        self->name, self->source, error);
  }
  if (program == NULL)
    goto malformed_program;

  self->rt = rt;
  self->ctx = ctx;
  self->program = program;

  global_obj = JS_GetGlobalObject (ctx);

  JS_DefinePropertyValueStr (ctx, global_obj, "global",
      JS_DupValue (ctx, global_obj), JS_PROP_C_W_E);

  _gum_quick_core_init (core, self, ctx, global_obj,
      gum_quick_script_backend_get_scope_mutex (self->backend),
      program, gumjs_frida_source_map, &self->interceptor, &self->stalker,
      (GumQuickMessageEmitter) gum_quick_script_emit, self,
      gum_quick_script_backend_get_scheduler (self->backend));

  core->current_scope = &scope;

  _gum_quick_kernel_init (&self->kernel, global_obj, core);
  _gum_quick_memory_init (&self->memory, global_obj, core);
  _gum_quick_module_init (&self->module, global_obj, core);
  _gum_quick_thread_init (&self->thread, global_obj, core);
  _gum_quick_process_init (&self->process, global_obj, &self->module,
      &self->thread, core);
  _gum_quick_file_init (&self->file, global_obj, core);
  _gum_quick_checksum_init (&self->checksum, global_obj, core);
  _gum_quick_stream_init (&self->stream, global_obj, core);
  _gum_quick_socket_init (&self->socket, global_obj, &self->stream, core);
#ifdef HAVE_SQLITE
  _gum_quick_database_init (&self->database, global_obj, core);
#endif
  _gum_quick_interceptor_init (&self->interceptor, global_obj, core);
  _gum_quick_api_resolver_init (&self->api_resolver, global_obj, core);
  _gum_quick_symbol_init (&self->symbol, global_obj, core);
  _gum_quick_cmodule_init (&self->cmodule, global_obj, core);
  _gum_quick_instruction_init (&self->instruction, global_obj, core);
  _gum_quick_code_writer_init (&self->code_writer, global_obj, core);
  _gum_quick_code_relocator_init (&self->code_relocator, global_obj,
      &self->code_writer, &self->instruction, core);
  _gum_quick_stalker_init (&self->stalker, global_obj, &self->code_writer,
      &self->instruction, core);
  _gum_quick_cloak_init (&self->cloak, global_obj, core);

  JS_FreeValue (ctx, global_obj);

  core->current_scope = NULL;

  g_free (self->source);
  self->source = NULL;

  g_bytes_unref (self->bytecode);
  self->bytecode = NULL;

  return TRUE;

malformed_program:
  {
    JS_FreeContext (ctx);
    JS_FreeRuntime (rt);

    return FALSE;
  }
}

static void
gum_quick_script_destroy_context (GumQuickScript * self)
{
  GumQuickCore * core = &self->core;

  g_assert (self->ctx != NULL);

  {
    GumQuickScope scope;

    _gum_quick_scope_enter (&scope, core);

    _gum_quick_cloak_dispose (&self->cloak);
    _gum_quick_stalker_dispose (&self->stalker);
    _gum_quick_code_relocator_dispose (&self->code_relocator);
    _gum_quick_code_writer_dispose (&self->code_writer);
    _gum_quick_instruction_dispose (&self->instruction);
    _gum_quick_cmodule_dispose (&self->cmodule);
    _gum_quick_symbol_dispose (&self->symbol);
    _gum_quick_api_resolver_dispose (&self->api_resolver);
    _gum_quick_interceptor_dispose (&self->interceptor);
#ifdef HAVE_SQLITE
    _gum_quick_database_dispose (&self->database);
#endif
    _gum_quick_socket_dispose (&self->socket);
    _gum_quick_stream_dispose (&self->stream);
    _gum_quick_checksum_dispose (&self->checksum);
    _gum_quick_file_dispose (&self->file);
    _gum_quick_process_dispose (&self->process);
    _gum_quick_thread_dispose (&self->thread);
    _gum_quick_module_dispose (&self->module);
    _gum_quick_memory_dispose (&self->memory);
    _gum_quick_kernel_dispose (&self->kernel);
    _gum_quick_core_dispose (core);

    _gum_quick_scope_leave (&scope);
  }

  {
    GumQuickScope scope = { core, NULL, };

    core->current_scope = &scope;

    gum_es_program_free (self->program, self->ctx);
    self->program = NULL;

    JS_FreeContext (self->ctx);
    self->ctx = NULL;

    JS_FreeRuntime (self->rt);
    self->rt = NULL;

    core->current_scope = NULL;
  }

  _gum_quick_cloak_finalize (&self->cloak);
  _gum_quick_stalker_finalize (&self->stalker);
  _gum_quick_code_relocator_finalize (&self->code_relocator);
  _gum_quick_code_writer_finalize (&self->code_writer);
  _gum_quick_instruction_finalize (&self->instruction);
  _gum_quick_cmodule_finalize (&self->cmodule);
  _gum_quick_symbol_finalize (&self->symbol);
  _gum_quick_api_resolver_finalize (&self->api_resolver);
  _gum_quick_interceptor_finalize (&self->interceptor);
#ifdef HAVE_SQLITE
  _gum_quick_database_finalize (&self->database);
#endif
  _gum_quick_socket_finalize (&self->socket);
  _gum_quick_stream_finalize (&self->stream);
  _gum_quick_checksum_finalize (&self->checksum);
  _gum_quick_file_finalize (&self->file);
  _gum_quick_process_finalize (&self->process);
  _gum_quick_thread_finalize (&self->thread);
  _gum_quick_module_finalize (&self->module);
  _gum_quick_memory_finalize (&self->memory);
  _gum_quick_kernel_finalize (&self->kernel);
  _gum_quick_core_finalize (core);
}

static void
gum_quick_script_load (GumScript * script,
                       GCancellable * cancellable,
                       GAsyncReadyCallback callback,
                       gpointer user_data)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new ((GumScriptTaskFunc) gum_quick_script_do_load,
      self, cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_quick_script_backend_get_scheduler (self->backend));
  g_object_unref (task);
}

static void
gum_quick_script_load_finish (GumScript * script,
                              GAsyncResult * result)
{
  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_quick_script_load_sync (GumScript * script,
                            GCancellable * cancellable)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new ((GumScriptTaskFunc) gum_quick_script_do_load,
      self, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_quick_script_backend_get_scheduler (self->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_quick_script_do_load (GumScriptTask * task,
                          GumQuickScript * self,
                          gpointer task_data,
                          GCancellable * cancellable)
{
  if (self->state != GUM_SCRIPT_STATE_CREATED)
    goto invalid_operation;

  self->state = GUM_SCRIPT_STATE_LOADING;

  gum_quick_script_execute_entrypoints (self, task);

  return;

invalid_operation:
  {
    gum_script_task_return_error (task,
        g_error_new_literal (
          GUM_ERROR,
          GUM_ERROR_NOT_SUPPORTED,
          "Invalid operation"));
  }
}

static void
gum_quick_script_execute_entrypoints (GumQuickScript * self,
                                      GumScriptTask * task)
{
  GumQuickScope scope;
  JSContext * ctx = self->ctx;
  GArray * entrypoints;
  guint i;
  gboolean done;

  _gum_quick_scope_enter (&scope, &self->core);

  gum_quick_bundle_load (gumjs_runtime_modules, ctx);

  entrypoints = self->program->entrypoints;

  if (gum_es_program_is_esm (self->program))
  {
    JSValue pending;
    guint num_results;
    JSValue global_obj, promise_class, all_settled_func, loaded_promise;
    JSValue then_func, task_obj, on_loaded_func, result_val;

    pending = JS_NewArray (ctx);
    num_results = 0;
    for (i = 0; i != entrypoints->len; i++)
    {
      JSValue result;

      result = JS_EvalFunction (ctx, g_array_index (entrypoints, JSValue, i));
      if (JS_IsException (result))
      {
        _gum_quick_scope_catch_and_emit (&scope);
      }
      else
      {
        JS_DefinePropertyValueUint32 (ctx, pending, num_results++, result,
            JS_PROP_C_W_E);
      }
    }

    global_obj = JS_GetGlobalObject (ctx);
    promise_class = JS_GetPropertyStr (ctx, global_obj, "Promise");
    all_settled_func = JS_GetPropertyStr (ctx, promise_class, "allSettled");

    loaded_promise =
        JS_Call (ctx, all_settled_func, promise_class, 1, &pending);

    then_func = JS_GetPropertyStr (ctx, loaded_promise, "then");

    task_obj = JS_NewObject (ctx);
    JS_SetOpaque (task_obj, g_object_ref (task));

    on_loaded_func = JS_NewCFunctionData (ctx,
        gum_quick_script_on_entrypoints_executed, 1, 0, 1, &task_obj);

    result_val = JS_Call (ctx, then_func, loaded_promise, 1, &on_loaded_func);

    JS_FreeValue (ctx, result_val);
    JS_FreeValue (ctx, on_loaded_func);
    JS_FreeValue (ctx, task_obj);
    JS_FreeValue (ctx, then_func);
    JS_FreeValue (ctx, loaded_promise);
    JS_FreeValue (ctx, all_settled_func);
    JS_FreeValue (ctx, promise_class);
    JS_FreeValue (ctx, global_obj);
    JS_FreeValue (ctx, pending);

    done = FALSE;
  }
  else
  {
    for (i = 0; i != entrypoints->len; i++)
    {
      JSValue result;

      result = JS_EvalFunction (ctx, g_array_index (entrypoints, JSValue, i));
      if (JS_IsException (result))
        _gum_quick_scope_catch_and_emit (&scope);

      JS_FreeValue (ctx, result);
    }

    done = TRUE;
  }

  g_array_set_size (entrypoints, 0);

  _gum_quick_scope_leave (&scope);

  if (done)
  {
    self->state = GUM_SCRIPT_STATE_LOADED;

    gum_script_task_return_pointer (task, NULL, NULL);
  }
}

static JSValue
gum_quick_script_on_entrypoints_executed (JSContext * ctx,
                                          JSValueConst this_val,
                                          int argc,
                                          JSValueConst * argv,
                                          int magic,
                                          JSValue * func_data)
{
  JSValueConst results = argv[0];
  GumScriptTask * task;
  JSClassID class_id;
  GumQuickScript * self;
  GumQuickCore * core;
  guint n, i;
  GSource * source;

  task = JS_GetAnyOpaque (func_data[0], &class_id);
  self = GUM_QUICK_SCRIPT (
      g_async_result_get_source_object (G_ASYNC_RESULT (task)));

  core = JS_GetContextOpaque (ctx);

  _gum_quick_array_get_length (ctx, results, core, &n);
  for (i = 0; i != n; i++)
  {
    JSValue result, reason;

    result = JS_GetPropertyUint32 (ctx, results, i);

    reason = JS_GetPropertyStr (ctx, result, "reason");
    if (!JS_IsUndefined (reason))
      _gum_quick_core_on_unhandled_exception (core, reason);

    JS_FreeValue (ctx, reason);
    JS_FreeValue (ctx, result);
  }

  source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_quick_script_complete_load_task,
      task, g_object_unref);
  g_source_attach (source,
      gum_script_scheduler_get_js_context (core->scheduler));
  g_source_unref (source);

  _gum_quick_core_pin (core);

  g_object_unref (self);

  return JS_UNDEFINED;
}

static gboolean
gum_quick_script_complete_load_task (GumScriptTask * task)
{
  GumQuickScript * self;
  GumQuickCore * core;
  GumQuickScope scope;

  self = GUM_QUICK_SCRIPT (
      g_async_result_get_source_object (G_ASYNC_RESULT (task)));
  core = &self->core;

  _gum_quick_scope_enter (&scope, core);
  _gum_quick_core_unpin (core);
  _gum_quick_scope_leave (&scope);

  self->state = GUM_SCRIPT_STATE_LOADED;

  gum_script_task_return_pointer (task, NULL, NULL);

  g_object_unref (self);

  return G_SOURCE_REMOVE;
}

static void
gum_quick_script_unload (GumScript * script,
                         GCancellable * cancellable,
                         GAsyncReadyCallback callback,
                         gpointer user_data)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new ((GumScriptTaskFunc) gum_quick_script_do_unload,
      self, cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_quick_script_backend_get_scheduler (self->backend));
  g_object_unref (task);
}

static void
gum_quick_script_unload_finish (GumScript * script,
                                GAsyncResult * result)
{
  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_quick_script_unload_sync (GumScript * script,
                              GCancellable * cancellable)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);
  GumScriptTask * task;

  task = gum_script_task_new ((GumScriptTaskFunc) gum_quick_script_do_unload,
      self, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_quick_script_backend_get_scheduler (self->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_quick_script_do_unload (GumScriptTask * task,
                            GumQuickScript * self,
                            gpointer task_data,
                            GCancellable * cancellable)
{
  if (self->state != GUM_SCRIPT_STATE_LOADED)
    goto invalid_operation;

  self->state = GUM_SCRIPT_STATE_UNLOADING;
  gum_quick_script_once_unloaded (self,
      (GumUnloadNotifyFunc) gum_quick_script_complete_unload_task,
      g_object_ref (task), g_object_unref);

  gum_quick_script_try_unload (self);

  return;

invalid_operation:
  {
    gum_script_task_return_error (task,
        g_error_new_literal (
          GUM_ERROR,
          GUM_ERROR_NOT_SUPPORTED,
          "Invalid operation"));
  }
}

static void
gum_quick_script_complete_unload_task (GumQuickScript * self,
                                       GumScriptTask * task)
{
  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_quick_script_try_unload (GumQuickScript * self)
{
  GumQuickScope scope;
  gboolean success;

  g_assert (self->state == GUM_SCRIPT_STATE_UNLOADING);

  _gum_quick_scope_enter (&scope, &self->core);

  _gum_quick_stalker_flush (&self->stalker);
  _gum_quick_interceptor_flush (&self->interceptor);
  _gum_quick_socket_flush (&self->socket);
  _gum_quick_stream_flush (&self->stream);
  _gum_quick_process_flush (&self->process);
  success = _gum_quick_core_flush (&self->core,
      (GumQuickFlushNotify) gum_quick_script_try_unload,
      g_object_ref (self), g_object_unref);

  _gum_quick_scope_leave (&scope);

  if (success)
  {
    gum_quick_script_destroy_context (self);

    self->state = GUM_SCRIPT_STATE_UNLOADED;

    while (self->on_unload != NULL)
    {
      GSList * link = self->on_unload;
      GumUnloadNotifyCallback * callback = link->data;

      callback->func (self, callback->data);
      if (callback->data_destroy != NULL)
        callback->data_destroy (callback->data);
      g_slice_free (GumUnloadNotifyCallback, callback);

      self->on_unload = g_slist_delete_link (self->on_unload, link);
    }
  }
}

static void
gum_quick_script_once_unloaded (GumQuickScript * self,
                                GumUnloadNotifyFunc func,
                                gpointer data,
                                GDestroyNotify data_destroy)
{
  GumUnloadNotifyCallback * callback;

  callback = g_slice_new (GumUnloadNotifyCallback);
  callback->func = func;
  callback->data = data;
  callback->data_destroy = data_destroy;

  self->on_unload = g_slist_append (self->on_unload, callback);
}

static void
gum_quick_script_set_message_handler (GumScript * script,
                                      GumScriptMessageHandler handler,
                                      gpointer data,
                                      GDestroyNotify data_destroy)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);

  if (self->message_handler_data_destroy != NULL)
    self->message_handler_data_destroy (self->message_handler_data);
  self->message_handler = handler;
  self->message_handler_data = data;
  self->message_handler_data_destroy = data_destroy;
}

static void
gum_quick_script_post (GumScript * script,
                       const gchar * message,
                       GBytes * data)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);
  GumPostData * d;

  d = g_slice_new (GumPostData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  gum_script_scheduler_push_job_on_js_thread (
      gum_quick_script_backend_get_scheduler (self->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_quick_script_do_post, d,
      (GDestroyNotify) gum_quick_post_data_free);
}

static void
gum_quick_script_do_post (GumPostData * d)
{
  GBytes * data;

  data = d->data;
  d->data = NULL;

  _gum_quick_core_post (&d->script->core, d->message, data);
}

static void
gum_quick_post_data_free (GumPostData * d)
{
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumPostData, d);
}

static void
gum_quick_script_set_debug_message_handler (
    GumScript * backend,
    GumScriptDebugMessageHandler handler,
    gpointer data,
    GDestroyNotify data_destroy)
{
  if (data_destroy != NULL)
    data_destroy (data);
}

static void
gum_quick_script_post_debug_message (GumScript * backend,
                                     const gchar * message)
{
}

static GumStalker *
gum_quick_script_get_stalker (GumScript * script)
{
  GumQuickScript * self = GUM_QUICK_SCRIPT (script);

  return _gum_quick_stalker_get (&self->stalker);
}

static void
gum_quick_script_emit (const gchar * message,
                       GBytes * data,
                       GumQuickScript * self)
{
  GumEmitData * d;
  GSource * source;

  d = g_slice_new (GumEmitData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_quick_script_do_emit,
      d,
      (GDestroyNotify) gum_quick_emit_data_free);
  g_source_attach (source, self->main_context);
  g_source_unref (source);
}

static gboolean
gum_quick_script_do_emit (GumEmitData * d)
{
  GumQuickScript * self = d->script;

  if (self->message_handler != NULL)
    self->message_handler (d->message, d->data, self->message_handler_data);

  return FALSE;
}

static void
gum_quick_emit_data_free (GumEmitData * d)
{
  g_bytes_unref (d->data);
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumEmitData, d);
}

GumQuickWorker *
_gum_quick_script_make_worker (GumQuickScript * self,
                               const gchar * url,
                               JSValue on_message)
{
  GumQuickWorker * worker;
  GumESAsset * asset;
  JSContext * ctx;
  JSValue mod;
  JSValue global_obj;
  GumQuickCore * core;

  if (!g_str_has_prefix (url, "file://"))
    goto invalid_url;

  asset = g_hash_table_lookup (self->program->es_assets,
      url + strlen ("file://"));
  if (asset == NULL)
    goto invalid_url;

  worker = gum_quick_worker_new (self, asset, on_message);
  ctx = worker->ctx;

  mod = gum_es_program_compile_worker (self->program, ctx, asset);
  if (JS_IsException (mod))
    goto malformed_module;
  worker->entrypoint = mod;

  global_obj = JS_GetGlobalObject (ctx);

  JS_DefinePropertyValueStr (ctx, global_obj, "global",
"""


```