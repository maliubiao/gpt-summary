Response:
The user wants to understand the functionality of the `gumv8script.cpp` file in the Frida dynamic instrumentation tool. They are particularly interested in how it relates to reverse engineering, low-level concepts, and potential user errors.

Here's a breakdown of how to approach this:

1. **Identify Core Functionality:** Scan the code for key classes, functions, and data structures. Look for names that suggest core responsibilities.
2. **Reverse Engineering Relevance:** Consider how the identified functionality enables or interacts with common reverse engineering tasks like code injection, hooking, and inspection.
3. **Low-Level Interactions:** Search for mentions of OS primitives (like threads, memory management), kernel interfaces (even indirectly), and architecture-specific concepts.
4. **Logical Inference:**  Analyze code blocks that involve decision-making or data manipulation. Try to trace how inputs lead to outputs.
5. **User Errors:** Think about common mistakes developers make when working with scripting environments or dynamic instrumentation. Look for error handling or areas where improper usage could lead to issues.
6. **User Journey:**  Imagine the steps a user would take to end up triggering the code within this file. This helps contextualize the functionality.
7. **Summarize:** Condense the findings into a concise summary of the file's purpose.

**Mental Walkthrough of the Code:**

* **Includes:**  The included headers (`gumv8script.h`, `gumscripttask.h`, etc.) point to the file's integration within the larger Frida framework. V8-related headers (`v8.h`, `v8-inspector.h`) indicate the use of the V8 JavaScript engine.
* **Macros:** `GUM_V8_INSPECTOR_LOCK/UNLOCK` suggest thread safety concerns around inspector functionality.
* **Namespaces:** `v8` and `v8_inspector` confirm the V8 integration.
* **Typedefs/Enums:**  `GumUnloadNotifyFunc`, enums for signals and properties define the structure and communication mechanisms of `GumV8Script`.
* **Structs:** `GumImportOperation`, `GumUnloadNotifyCallback`, `GumPostData`, `GumEmitData`, `GumEmitDebugMessageData` represent data passed between different parts of the system, hinting at asynchronous operations and event handling.
* **Classes:** `GumInspectorClient` and `GumInspectorChannel` are clearly related to the V8 Inspector, which is a debugging tool.
* **Static Functions:**  A large number of static functions indicate internal implementation details and callbacks for V8 events (module loading, script execution, etc.). The naming conventions (`gum_v8_script_*`) clearly associate them with the `GumV8Script` class.
* **GObject Integration:** The use of `G_DEFINE_TYPE_EXTENDED` and the presence of `_class_init`, `_iface_init`, `_init`, `_constructed`, `_dispose`, `_finalize`, `_get_property`, `_set_property` functions strongly suggest this class is part of the GLib/GObject type system. This framework is common in projects using GTK and related technologies, often used for building cross-platform applications.
* **Script Loading/Unloading:** Functions like `gum_v8_script_load`, `gum_v8_script_unload`, and their associated `_sync`, `_finish`, `_do_load`, `_do_unload` variations indicate the lifecycle management of JavaScript scripts within Frida.
* **Message Handling:** Functions related to `gum_v8_script_set_message_handler`, `gum_v8_script_post`, and `gum_v8_script_emit` point to communication mechanisms between the injected JavaScript and the Frida host.
* **Debugging:** Functions involving `debug_message_handler` and inspector interactions (`gum_v8_script_connect_inspector_channel`, `gum_v8_script_dispatch_inspector_stanza`) highlight the debugging capabilities.
* **Module System:** The `gum_import_module`, `gum_resolve_module`, and related functions deal with JavaScript module loading, which is a core part of modern JavaScript development.
* **Compilation:** The `gum_v8_script_compile` function handles the compilation of JavaScript source code.
* **Fatal Error Handling:** `gum_v8_script_on_fatal_error` suggests a mechanism for dealing with critical errors within the V8 engine.

**Connecting to User Request:**

* **Reverse Engineering:**  The ability to load and execute scripts, intercept function calls (implied by `_gum_v8_interceptor_init`), and inspect memory (`_gum_v8_memory_init`) are core to Frida's reverse engineering capabilities.
* **Low-Level Concepts:** The interaction with V8, the management of isolates (V8's execution environments), and the handling of binary data (snapshots) involve low-level concepts.
* **Logical Inference:** Analyzing the module loading logic (`gum_import_module`, `gum_resolve_module`) requires tracing how module specifiers are resolved to actual files or resources.
* **User Errors:**  Incorrect module paths, invalid JavaScript syntax, or attempting to access undefined variables are common user errors.
* **User Journey:** Users interact with Frida through its command-line interface, Python bindings, or other client libraries. These interactions lead to Frida injecting and executing JavaScript code, which is managed by `gumv8script.cpp`.

By combining these steps, we can generate a comprehensive and accurate description of the file's functionality.
好的，让我们来分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumv8script.cpp` 文件的功能。

**文件功能归纳:**

`gumv8script.cpp` 文件是 Frida 中负责管理和执行 V8 JavaScript 脚本的核心组件。它的主要功能包括：

1. **V8 引擎集成:** 负责创建、初始化、管理和销毁 V8 JavaScript 引擎的实例 (Isolate)。这包括设置 V8 的参数，例如快照 (snapshot) 和数组缓冲区分配器。
2. **脚本生命周期管理:** 管理 JavaScript 脚本的加载、卸载、编译和执行。它处理脚本的源代码、快照数据，并将其转化为 V8 可以执行的格式。
3. **JavaScript 上下文管理:** 为每个脚本创建独立的 V8 上下文 (Context)，提供隔离的执行环境。它负责上下文的创建、销毁以及与脚本的关联。
4. **Frida API 暴露:**  将 Frida 提供的各种功能（例如，内存操作、函数拦截、模块加载、线程管理、进程信息、文件操作、网络通信等）以 JavaScript API 的形式暴露给脚本。这通过初始化和关联各种 GumV8 相关的类（例如 `GumV8Core`, `GumV8Interceptor`, `GumV8Stalker` 等）来实现。
5. **模块化支持:**  支持 JavaScript 模块的导入和解析，允许脚本组织成模块化的结构。它实现了 `import` 语句的功能，并处理模块的加载、解析和实例化。
6. **消息传递机制:**  提供 JavaScript 脚本与 Frida Host (通常是 Python 脚本) 之间的双向通信机制。这包括从 JavaScript 发送消息到 Host，以及 Host 发送消息到 JavaScript。
7. **调试支持 (Inspector):** 集成了 V8 Inspector 协议，允许开发者使用 Chrome DevTools 等工具对 Frida 注入的 JavaScript 代码进行远程调试。这包括创建 Inspector 客户端和通道，处理 Inspector 的命令和事件。
8. **错误处理:**  处理 JavaScript 脚本执行过程中可能发生的错误，并提供相应的错误信息。
9. **资源管理:**  管理与脚本相关的资源，例如分配的内存、打开的文件句柄等，并在脚本卸载时进行清理。
10. **异步操作处理:** 通过 `GumScriptTask` 等机制处理脚本的异步加载和卸载操作。

**与逆向方法的关联及举例说明:**

`gumv8script.cpp` 是 Frida 动态插桩的核心，它直接支撑了 Frida 的各种逆向分析能力。以下是一些例子：

* **代码注入与执行:** Frida 用户可以将 JavaScript 代码通过 `frida.attach()` 或 `session.create_script()` 等方法注入到目标进程中。`gumv8script.cpp` 负责加载和执行这些注入的 JavaScript 代码。例如，用户可以注入以下 JavaScript 代码来打印目标进程的模块列表：

   ```javascript
   Process.enumerateModules().forEach(function(module) {
     console.log(module.name + " @ " + module.base);
   });
   ```

   `gumv8script.cpp` 会编译并执行这段代码。

* **函数 Hooking (拦截):** Frida 的 `Interceptor` API 允许用户拦截目标进程中的函数调用。`gumv8script.cpp` 中的 `_gum_v8_interceptor_init` 和相关函数负责将 `Interceptor` 对象暴露给 JavaScript，并处理 JavaScript 中定义的 Hook 逻辑。例如，用户可以使用以下 JavaScript 代码 Hook `open` 函数：

   ```javascript
   Interceptor.attach(Module.findExportByName(null, 'open'), {
     onEnter: function (args) {
       console.log('Opening file:', args[0].readUtf8String());
     },
     onLeave: function (retval) {
       console.log('open returned:', retval);
     }
   });
   ```

   `gumv8script.cpp` 会接收来自 JavaScript 的 Hook 请求，并在目标进程中设置相应的 Hook 点。

* **内存操作:** Frida 允许 JavaScript 脚本直接读写目标进程的内存。`gumv8script.cpp` 中的 `_gum_v8_memory_init` 负责将内存操作相关的 API（例如 `Memory.read*`, `Memory.write*`）暴露给 JavaScript。例如，用户可以使用以下 JavaScript 代码读取目标进程中某个地址的值：

   ```javascript
   var address = ptr("0x12345678");
   var value = Memory.readInt(address);
   console.log("Value at " + address + ": " + value);
   ```

   `gumv8script.cpp` 会调用底层的内存读取函数来获取指定地址的值。

* **代码追踪 (Stalker):** Frida 的 `Stalker` API 允许用户跟踪目标进程的执行流程。`gumv8script.cpp` 中的 `_gum_v8_stalker_init` 负责将 `Stalker` 对象暴露给 JavaScript，并处理 JavaScript 中定义的追踪配置。

**涉及二进制底层，Linux, Android 内核及框架的知识及举例说明:**

`gumv8script.cpp` 本身主要关注 V8 引擎的集成和 JavaScript 脚本的管理，但它所支持的 Frida 功能深入地涉及到二进制底层、操作系统内核和框架知识：

* **二进制底层:**
    * **内存布局:** 函数 Hooking 和内存操作都需要理解目标进程的内存布局，包括代码段、数据段、堆栈等。Frida 的 JavaScript API (例如 `Module.findExportByName`, `ptr()`) 依赖于对二进制文件的解析和地址计算。
    * **指令集架构:** 代码追踪和动态代码修改 (虽然此文件本身不直接涉及动态代码修改，但 Frida 具备此能力) 需要理解目标进程的指令集架构 (例如 x86, ARM)。
    * **调用约定:** 函数 Hooking 需要理解目标平台的调用约定，以便正确地获取函数参数和返回值。

* **Linux 内核:**
    * **进程和线程管理:** Frida 需要与目标进程进行交互，包括附加到进程、创建线程等，这些操作依赖于 Linux 内核提供的系统调用 (例如 `ptrace`)。
    * **内存管理:** Frida 的内存操作功能直接与 Linux 内核的内存管理机制交互，例如读取 `/proc/pid/mem` 或使用 `ptrace` 进行内存读写。
    * **动态链接器:** `Module.findExportByName` 等功能需要理解 Linux 的动态链接机制，例如如何解析 ELF 文件和查找符号。

* **Android 内核及框架:**
    * **Android Runtime (ART):** 在 Android 上，Frida 需要与 ART 虚拟机交互，例如 Hook Java 方法、访问 Java 对象等。这需要理解 ART 的内部结构和机制。
    * **Binder IPC:**  Android 系统广泛使用 Binder 进行进程间通信。Frida 可以 Hook Binder 调用，这需要理解 Binder 协议和内核驱动。
    * **System Server:** Android 的核心服务运行在 System Server 进程中。Frida 可以 Hook System Server 的函数，需要理解 Android 框架的架构。

**举例说明:**

当用户在 Android 上使用 Frida Hook 一个 Java 方法时，例如：

```javascript
Java.perform(function () {
  var String = Java.use('java.lang.String');
  String.getBytes.implementation = function () {
    console.log('getBytes called on:', this.toString());
    return this.getBytes();
  };
});
```

虽然 `gumv8script.cpp` 本身处理的是 V8 引擎和 JavaScript 脚本，但它背后的 Frida Gum 框架会：

1. **与 Android 内核交互:**  Frida Agent (由 `gumv8script.cpp` 管理的 JavaScript 运行时) 通过 Gum 框架调用底层的 C++ 代码，这些 C++ 代码可能使用 `ptrace` 或其他内核机制来注入到目标进程。
2. **与 ART 交互:**  Gum 框架会使用 ART 提供的 API (例如 JNI) 来查找 `java.lang.String` 类和 `getBytes` 方法。
3. **修改 ART 内部结构:**  为了实现 Hook，Frida 可能会修改 ART 虚拟机内部的函数表或方法结构，将 `getBytes` 方法的入口点替换为 Frida 提供的代理函数。

**逻辑推理及假设输入与输出:**

在 `gumv8script.cpp` 中，逻辑推理的例子主要体现在模块加载和依赖解析部分：

**假设输入:**

* JavaScript 代码中包含 `import` 语句，例如 `import { something } from './my-module.js';`
* 当前脚本的文件路径或模块名作为基础路径。
* Frida 配置中可能包含模块搜索路径。

**逻辑推理过程 (以 `gum_resolve_module` 函数为例):**

1. **获取引用模块的信息:**  `gum_resolve_module` 函数接收 `referrer` 参数，表示发起 `import` 的模块。通过 `referrer->ScriptId()` 可以获取引用模块的 ID。
2. **查找引用模块的元数据:**  根据模块 ID 在 `program->es_modules` 中查找引用模块的 `GumESAsset` 结构，其中包含模块的名称等信息。
3. **解析模块说明符:**  获取 `import` 语句中的模块说明符 (`specifier`)，例如 `'./my-module.js'`。
4. **规范化模块名称:**  调用 `gum_normalize_module_name` 函数，根据基础路径和模块说明符解析出完整的模块名称或路径。
    * 如果模块说明符以 `.` 开头，则表示相对路径，需要根据引用模块的路径进行拼接。
    * 如果模块说明符不以 `.` 开头，则可能是绝对路径或模块名，需要在预定义的模块搜索路径中查找。
5. **查找目标模块:**  根据规范化后的模块名称在 `program->es_assets` 中查找对应的 `GumESAsset` 结构。
6. **加载和实例化模块:** 如果找到目标模块，则调用 `gum_ensure_module_defined` 加载模块代码并创建 V8 模块对象。

**输出:**

* 如果模块加载成功，`gum_resolve_module` 返回一个 `MaybeLocal<Module>`，其中包含加载的 V8 模块对象。
* 如果模块加载失败 (例如，找不到模块)，则返回一个空的 `MaybeLocal<Module>`，并可能抛出一个 JavaScript 异常。

**涉及用户或者编程常见的使用错误及举例说明:**

`gumv8script.cpp` 的功能涉及到脚本的加载和执行，因此常见的用户错误包括：

1. **JavaScript 语法错误:** 如果用户提供的 JavaScript 代码包含语法错误，V8 引擎在编译阶段会报错。`gumv8_script_compile` 函数中的 `TryCatch` 块会捕获这些错误，并将错误信息传递给 Frida Host。

   **例子:**  在 JavaScript 代码中遗漏分号或括号不匹配。

2. **引用未定义的变量或函数:** 如果 JavaScript 代码尝试访问未声明或未定义的变量或函数，V8 引擎在执行阶段会抛出 `ReferenceError`。

   **例子:**  `console.log(undefinedVariable);`

3. **模块加载错误:**
    * **模块路径错误:** 在 `import` 语句中指定了错误的模块路径，导致 Frida 无法找到对应的模块文件。
    * **循环依赖:** 模块之间存在循环依赖关系，导致模块加载过程陷入死循环。
    * **模块未导出:** 尝试导入模块中未导出的变量或函数。

   **例子:**  `import { something } from './non-existent-module.js';`

4. **类型错误:** 在 JavaScript 中进行了不兼容的类型操作。

   **例子:**  尝试对一个字符串调用 `parseInt()` 方法时传入的参数不是字符串。

5. **异步操作处理不当:** 如果 JavaScript 代码中使用了异步操作 (例如 `setTimeout`, `Promise`)，用户可能没有正确处理异步操作的结果或回调。

6. **Frida API 使用错误:** 用户可能错误地使用了 Frida 提供的 API，例如传递了错误的参数类型或值。

   **例子:**  `Interceptor.attach(0, ...)`  // 尝试 Hook 一个非法的地址。

**用户操作是如何一步步的到达这里，作为调试线索:**

一个典型的用户操作流程如下，最终会触发 `gumv8script.cpp` 中的代码执行：

1. **编写 Frida 脚本:** 用户编写一个 JavaScript 文件 (例如 `my-script.js`)，其中使用了 Frida 提供的 API 来进行逆向操作 (例如 Hook 函数、读取内存等)。
2. **使用 Frida 客户端 (例如 Python):** 用户使用 Frida 的 Python 绑定或其他客户端连接到目标进程。
   ```python
   import frida
   process = frida.attach("target_process")
   ```
3. **创建 Frida 脚本对象:** 用户使用 `process.create_script()` 方法创建一个 Frida 脚本对象，并将 JavaScript 代码传递给它。
   ```python
   script = process.create_script(open("my-script.js").read())
   ```
   在这一步，Frida 会将 JavaScript 源代码传递给 `gumv8script.cpp` 中的相关逻辑进行处理。
4. **加载脚本:** 用户调用 `script.load()` 方法加载脚本。
   ```python
   script.load()
   ```
   这将触发 `gum_v8_script_load` 函数，负责创建 V8 Isolate 和 Context，并编译 JavaScript 代码。
5. **脚本执行:** Frida 会执行加载的 JavaScript 代码。如果脚本中包含 `import` 语句，会触发 `gum_import_module` 和 `gum_resolve_module` 等函数。如果脚本使用了 Frida 的 API (例如 `Interceptor.attach`), 会调用 `_gum_v8_interceptor_init` 中注册的 JavaScript 函数，并最终调用到 Gum 框架的 C++ 代码。
6. **消息传递 (可选):** 如果 JavaScript 脚本中使用了 `send()` 函数发送消息，会触发 `gum_v8_script_post` 函数。
7. **调试 (可选):** 如果用户启用了 Inspector 调试，Frida 会创建 Inspector 通道，并通过 `gum_v8_script_connect_inspector_channel` 和 `gum_v8_script_dispatch_inspector_stanza` 等函数处理调试命令。
8. **卸载脚本:** 用户可以调用 `script.unload()` 方法卸载脚本。
   ```python
   script.unload()
   ```
   这将触发 `gum_v8_script_unload` 函数，负责清理 V8 Context 和 Isolate。

**作为调试线索:**

如果用户在使用 Frida 时遇到问题，例如脚本加载失败、Hook 不生效、消息传递错误等，可以通过以下方式使用 `gumv8script.cpp` 的相关知识进行调试：

* **查看 Frida 的日志输出:** Frida 通常会输出详细的日志信息，包括 V8 引擎的错误信息、模块加载的日志等。这些信息可以帮助定位问题。
* **使用 Inspector 调试:** 如果问题与 JavaScript 代码的执行逻辑有关，可以使用 Chrome DevTools 连接到 Frida 的 Inspector 进行断点调试、单步执行等。
* **阅读 `gumv8script.cpp` 源码:** 理解 `gumv8script.cpp` 中脚本加载、模块解析、API 暴露等关键流程的实现细节，可以帮助理解 Frida 的行为，并找到潜在的错误原因。例如，如果模块加载失败，可以查看 `gum_resolve_module` 函数的实现，了解 Frida 是如何查找和加载模块的。
* **分析崩溃堆栈:** 如果 Frida 或目标进程崩溃，分析崩溃堆栈可以帮助确定崩溃发生的位置。如果崩溃发生在 `gumv8script.cpp` 相关的函数中，则表明问题可能与 V8 引擎的集成或脚本执行有关。

总而言之，`gumv8script.cpp` 是 Frida 中一个至关重要的组件，它将 V8 JavaScript 引擎集成到 Frida 框架中，并负责管理和执行用户提供的 JavaScript 代码，从而实现 Frida 的各种动态插桩功能。理解其功能对于深入理解 Frida 的工作原理和进行高级调试至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8script.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第1部分，共2部分，请归纳一下它的功能

"""
/*
 * Copyright (C) 2010-2024 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 * Copyright (C) 2024 Håvard Sørbø <havard@hsorbo.no>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8script.h"

#include "gumscripttask.h"
#include "gumv8script-priv.h"
#include "gumv8script-runtime.h"
#include "gumv8value.h"

#include <cstring>

#define GUM_V8_INSPECTOR_LOCK(o) g_mutex_lock (&(o)->inspector_mutex)
#define GUM_V8_INSPECTOR_UNLOCK(o) g_mutex_unlock (&(o)->inspector_mutex)

using namespace v8;
using namespace v8_inspector;

typedef void (* GumUnloadNotifyFunc) (GumV8Script * self, gpointer user_data);

enum
{
  CONTEXT_CREATED,
  CONTEXT_DESTROYED,
  LAST_SIGNAL
};

enum
{
  PROP_0,
  PROP_NAME,
  PROP_SOURCE,
  PROP_SNAPSHOT,
  PROP_MAIN_CONTEXT,
  PROP_BACKEND
};

struct GumImportOperation
{
  GumV8Script * self;
  Global<Promise::Resolver> * resolver;
  Global<Module> * module;
};

struct GumUnloadNotifyCallback
{
  GumUnloadNotifyFunc func;
  gpointer data;
  GDestroyNotify data_destroy;
};

struct GumPostData
{
  GumV8Script * script;
  gchar * message;
  GBytes * data;
};

struct GumEmitData
{
  GumV8Script * script;
  gchar * message;
  GBytes * data;
};

struct GumEmitDebugMessageData
{
  GumV8Script * script;
  gchar * message;
};

class GumInspectorClient : public V8InspectorClient
{
public:
  GumInspectorClient (GumV8Script * script);

  void runMessageLoopOnPause (int context_group_id) override;
  void quitMessageLoopOnPause () override;

  Local<Context> ensureDefaultContextInGroup (int contextGroupId) override;

  double currentTimeMS () override;

private:
  void startSkippingAllPauses ();

  GumV8Script * script;
};

class GumInspectorChannel : public V8Inspector::Channel
{
public:
  GumInspectorChannel (GumV8Script * script, guint id);

  void takeSession (std::unique_ptr<V8InspectorSession> session);
  void dispatchStanza (const char * stanza);
  void startSkippingAllPauses ();

  void sendResponse (int call_id,
      std::unique_ptr<StringBuffer> message) override;
  void sendNotification (std::unique_ptr<StringBuffer> message) override;
  void flushProtocolNotifications () override;

private:
  void emitStanza (std::unique_ptr<StringBuffer> stanza);

  GumV8Script * script;
  guint id;
  std::unique_ptr<V8InspectorSession> inspector_session;
};

static void gum_v8_script_iface_init (gpointer g_iface, gpointer iface_data);

static void gum_v8_script_constructed (GObject * object);
static void gum_v8_script_dispose (GObject * object);
static void gum_v8_script_finalize (GObject * object);
static void gum_v8_script_get_property (GObject * object, guint property_id,
    GValue * value, GParamSpec * pspec);
static void gum_v8_script_set_property (GObject * object, guint property_id,
    const GValue * value, GParamSpec * pspec);
static GumESProgram * gum_v8_script_compile (GumV8Script * self,
    Isolate * isolate, Local<Context> context, GError ** error);
static MaybeLocal<Promise> gum_import_module (Local<Context> context,
    Local<Data> host_defined_options, Local<Value> resource_name,
    Local<String> specifier, Local<FixedArray> import_assertions);
static void gum_on_import_success (const FunctionCallbackInfo<Value> & info);
static void gum_on_import_failure (const FunctionCallbackInfo<Value> & info);
static void gum_import_operation_free (GumImportOperation * op);
static MaybeLocal<Module> gum_resolve_module (Local<Context> context,
    Local<String> specifier, Local<FixedArray> import_assertions,
    Local<Module> referrer);
static gchar * gum_normalize_module_name (const gchar * base_name,
    const gchar * name, GumESProgram * program);
static MaybeLocal<Module> gum_ensure_module_defined (Isolate * isolate,
    Local<Context> context, GumESAsset * asset, GumESProgram * program);
static void gum_v8_script_destroy_context (GumV8Script * self);

static void gum_v8_script_load (GumScript * script, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static void gum_v8_script_load_finish (GumScript * script,
    GAsyncResult * result);
static void gum_v8_script_load_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_v8_script_do_load (GumScriptTask * task, GumV8Script * self,
    gpointer task_data, GCancellable * cancellable);
static void gum_v8_script_execute_entrypoints (GumV8Script * self,
    GumScriptTask * task);
static void gum_v8_script_on_entrypoints_executed (
    const FunctionCallbackInfo<Value> & info);
static gboolean gum_v8_script_complete_load_task (GumScriptTask * task);
static void gum_v8_script_unload (GumScript * script,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_v8_script_unload_finish (GumScript * script,
    GAsyncResult * result);
static void gum_v8_script_unload_sync (GumScript * script,
    GCancellable * cancellable);
static void gum_v8_script_do_unload (GumScriptTask * task, GumV8Script * self,
    gpointer task_data, GCancellable * cancellable);
static void gum_v8_script_complete_unload_task (GumV8Script * self,
    GumScriptTask * task);
static void gum_v8_script_try_unload (GumV8Script * self);
static void gum_v8_script_once_unloaded (GumV8Script * self,
    GumUnloadNotifyFunc func, gpointer data, GDestroyNotify data_destroy);

static void gum_v8_script_set_message_handler (GumScript * script,
    GumScriptMessageHandler handler, gpointer data,
    GDestroyNotify data_destroy);
static void gum_v8_script_post (GumScript * script, const gchar * message,
    GBytes * data);
static void gum_v8_script_do_post (GumPostData * d);
static void gum_v8_post_data_free (GumPostData * d);

static void gum_v8_script_emit (GumV8Script * self, const gchar * message,
    GBytes * data);
static gboolean gum_v8_script_do_emit (GumEmitData * d);
static void gum_v8_emit_data_free (GumEmitData * d);

static void gum_v8_script_set_debug_message_handler (GumScript * backend,
    GumScriptDebugMessageHandler handler, gpointer data,
    GDestroyNotify data_destroy);
static void gum_v8_script_post_debug_message (GumScript * backend,
    const gchar * message);
static void gum_v8_script_process_queued_debug_messages (GumV8Script * self);
static void gum_v8_script_process_queued_debug_messages_unlocked (
    GumV8Script * self);
static void gum_v8_script_drop_queued_debug_messages_unlocked (
    GumV8Script * self);
static void gum_v8_script_process_debug_message (GumV8Script * self,
    const gchar * message);
static gboolean gum_v8_script_do_emit_debug_message (
    GumEmitDebugMessageData * d);
static void gum_emit_debug_message_data_free (GumEmitDebugMessageData * d);
static void gum_v8_script_clear_inspector_channels (GumV8Script * self);
static void gum_v8_script_connect_inspector_channel (GumV8Script * self,
    guint id);
static void gum_v8_script_disconnect_inspector_channel (GumV8Script * self,
    guint id);
static void gum_v8_script_dispatch_inspector_stanza (GumV8Script * self,
    guint channel_id, const gchar * stanza);

static GumStalker * gum_v8_script_get_stalker (GumScript * script);

static void gum_v8_script_on_fatal_error (const char * location,
    const char * message);

static GumESProgram * gum_es_program_new (void);
static void gum_es_program_free (GumESProgram * program);

static GumESAsset * gum_es_asset_new_take (const gchar * name, gpointer data,
    gsize data_size);
static GumESAsset * gum_es_asset_ref (GumESAsset * asset);
static void gum_es_asset_unref (GumESAsset * asset);

static std::unique_ptr<StringBuffer> gum_string_buffer_from_utf8 (
    const gchar * str);
static gchar * gum_string_view_to_utf8 (const StringView & view);

G_DEFINE_TYPE_EXTENDED (GumV8Script,
                        gum_v8_script,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT,
                            gum_v8_script_iface_init))

static guint gum_v8_script_signals[LAST_SIGNAL] = { 0, };

static void
gum_v8_script_class_init (GumV8ScriptClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->constructed = gum_v8_script_constructed;
  object_class->dispose = gum_v8_script_dispose;
  object_class->finalize = gum_v8_script_finalize;
  object_class->get_property = gum_v8_script_get_property;
  object_class->set_property = gum_v8_script_set_property;

  g_object_class_install_property (object_class, PROP_NAME,
      g_param_spec_string ("name", "Name", "Name", NULL,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_SOURCE,
      g_param_spec_string ("source", "Source", "Source code", NULL,
      (GParamFlags) (G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_SNAPSHOT,
      g_param_spec_boxed ("snapshot", "Snapshot", "Snapshot", G_TYPE_BYTES,
      (GParamFlags) (G_PARAM_WRITABLE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_MAIN_CONTEXT,
      g_param_spec_boxed ("main-context", "MainContext",
      "MainContext being used", G_TYPE_MAIN_CONTEXT,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));
  g_object_class_install_property (object_class, PROP_BACKEND,
      g_param_spec_object ("backend", "Backend", "Backend being used",
      GUM_V8_TYPE_SCRIPT_BACKEND,
      (GParamFlags) (G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY |
      G_PARAM_STATIC_STRINGS)));

  gum_v8_script_signals[CONTEXT_CREATED] = g_signal_new ("context-created",
      G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST, 0, NULL, NULL,
      g_cclosure_marshal_VOID__POINTER, G_TYPE_NONE, 1, G_TYPE_POINTER);
  gum_v8_script_signals[CONTEXT_DESTROYED] = g_signal_new ("context-destroyed",
      G_TYPE_FROM_CLASS (klass), G_SIGNAL_RUN_LAST, 0, NULL, NULL,
      g_cclosure_marshal_VOID__POINTER, G_TYPE_NONE, 1, G_TYPE_POINTER);
}

static void
gum_v8_script_iface_init (gpointer g_iface,
                          gpointer iface_data)
{
  auto iface = (GumScriptInterface *) g_iface;

  iface->load = gum_v8_script_load;
  iface->load_finish = gum_v8_script_load_finish;
  iface->load_sync = gum_v8_script_load_sync;
  iface->unload = gum_v8_script_unload;
  iface->unload_finish = gum_v8_script_unload_finish;
  iface->unload_sync = gum_v8_script_unload_sync;

  iface->set_message_handler = gum_v8_script_set_message_handler;
  iface->post = gum_v8_script_post;

  iface->set_debug_message_handler = gum_v8_script_set_debug_message_handler;
  iface->post_debug_message = gum_v8_script_post_debug_message;

  iface->get_stalker = gum_v8_script_get_stalker;
}

static void
gum_v8_script_init (GumV8Script * self)
{
  self->state = GUM_SCRIPT_STATE_CREATED;
  self->on_unload = NULL;

  g_mutex_init (&self->inspector_mutex);
  g_cond_init (&self->inspector_cond);
  self->inspector_state = GUM_V8_RUNNING;
  self->context_group_id = 1;

  g_queue_init (&self->debug_messages);
  self->flush_scheduled = false;

  self->channels = new GumInspectorChannelMap ();
}

static void
gum_v8_script_constructed (GObject * object)
{
  auto self = GUM_V8_SCRIPT (object);

  G_OBJECT_CLASS (gum_v8_script_parent_class)->constructed (object);

  Isolate::CreateParams params;
  params.snapshot_blob = self->snapshot_blob;
  params.array_buffer_allocator =
      ((GumV8Platform *) gum_v8_script_backend_get_platform (self->backend))
      ->GetArrayBufferAllocator ();

  Isolate * isolate = Isolate::New (params);
  isolate->SetData (0, self);
  isolate->SetFatalErrorHandler (gum_v8_script_on_fatal_error);
  isolate->SetMicrotasksPolicy (MicrotasksPolicy::kExplicit);
  isolate->SetHostImportModuleDynamicallyCallback (gum_import_module);
  self->isolate = isolate;

  {
    Locker locker (isolate);
    Isolate::Scope isolate_scope (isolate);
    HandleScope handle_scope (isolate);

    auto client = new GumInspectorClient (self);
    self->inspector_client = client;

    auto inspector = V8Inspector::create (isolate, client);
    self->inspector = inspector.release ();
  }
}

static void
gum_v8_script_dispose (GObject * object)
{
  auto self = GUM_V8_SCRIPT (object);
  auto script = GUM_SCRIPT (self);

  gum_v8_script_set_message_handler (script, NULL, NULL, NULL);

  if (self->state == GUM_SCRIPT_STATE_LOADED)
  {
    /* dispose() will be triggered again at the end of unload() */
    gum_v8_script_unload (script, NULL, NULL, NULL);
  }
  else
  {
    if (self->state == GUM_SCRIPT_STATE_CREATED && self->context != nullptr)
      gum_v8_script_destroy_context (self);

    g_clear_pointer (&self->debug_handler_context, g_main_context_unref);
    if (self->debug_handler_data_destroy != NULL)
      self->debug_handler_data_destroy (self->debug_handler_data);
    self->debug_handler = NULL;
    self->debug_handler_data = NULL;
    self->debug_handler_data_destroy = NULL;

    GUM_V8_INSPECTOR_LOCK (self);
    self->inspector_state = GUM_V8_RUNNING;
    g_cond_signal (&self->inspector_cond);
    GUM_V8_INSPECTOR_UNLOCK (self);

    gum_v8_script_clear_inspector_channels (self);

    GUM_V8_INSPECTOR_LOCK (self);
    gum_v8_script_drop_queued_debug_messages_unlocked (self);
    GUM_V8_INSPECTOR_UNLOCK (self);

    delete self->channels;
    self->channels = nullptr;

    {
      auto isolate = self->isolate;
      Locker locker (isolate);
      Isolate::Scope isolate_scope (isolate);
      HandleScope handle_scope (isolate);

      delete self->inspector;
      self->inspector = nullptr;

      delete self->inspector_client;
      self->inspector_client = nullptr;
    }

    auto platform =
        (GumV8Platform *) gum_v8_script_backend_get_platform (self->backend);
    platform->DisposeIsolate (&self->isolate);

    g_clear_pointer (&self->main_context, g_main_context_unref);
    g_clear_pointer (&self->backend, g_object_unref);
  }

  G_OBJECT_CLASS (gum_v8_script_parent_class)->dispose (object);
}

static void
gum_v8_script_finalize (GObject * object)
{
  auto self = GUM_V8_SCRIPT (object);

  g_cond_clear (&self->inspector_cond);
  g_mutex_clear (&self->inspector_mutex);

  g_free (self->name);
  g_free (self->source);
  g_bytes_unref (self->snapshot);

  G_OBJECT_CLASS (gum_v8_script_parent_class)->finalize (object);
}

static void
gum_v8_script_get_property (GObject * object,
                            guint property_id,
                            GValue * value,
                            GParamSpec * pspec)
{
  auto self = GUM_V8_SCRIPT (object);

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
gum_v8_script_set_property (GObject * object,
                            guint property_id,
                            const GValue * value,
                            GParamSpec * pspec)
{
  auto self = GUM_V8_SCRIPT (object);

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
    case PROP_SNAPSHOT:
      g_bytes_unref (self->snapshot);
      self->snapshot = (GBytes *) g_value_dup_boxed (value);

      if (self->snapshot != NULL)
      {
        gsize size;
        gconstpointer data = g_bytes_get_data (self->snapshot, &size);

        self->snapshot_blob_storage = { (const char *) data, (int) size };
        self->snapshot_blob = &self->snapshot_blob_storage;
      }
      else
      {
        self->snapshot_blob = NULL;
      }

      break;
    case PROP_MAIN_CONTEXT:
      if (self->main_context != NULL)
        g_main_context_unref (self->main_context);
      self->main_context = (GMainContext *) g_value_dup_boxed (value);
      break;
    case PROP_BACKEND:
      if (self->backend != NULL)
        g_object_unref (self->backend);
      self->backend = GUM_V8_SCRIPT_BACKEND (g_value_dup_object (value));
      break;
    default:
      G_OBJECT_WARN_INVALID_PROPERTY_ID (object, property_id, pspec);
  }
}

gboolean
gum_v8_script_create_context (GumV8Script * self,
                              GError ** error)
{
  g_assert (self->context == NULL);

  {
    Isolate * isolate = self->isolate;
    Locker locker (isolate);
    Isolate::Scope isolate_scope (isolate);
    HandleScope handle_scope (isolate);

    self->inspector->idleStarted ();

    auto global_templ = ObjectTemplate::New (isolate);
    _gum_v8_core_init (&self->core, self, gumjs_frida_source_map,
        gum_v8_script_emit, gum_v8_script_backend_get_scheduler (self->backend),
        isolate, global_templ);
    _gum_v8_kernel_init (&self->kernel, &self->core, global_templ);
    _gum_v8_memory_init (&self->memory, &self->core, global_templ);
    _gum_v8_module_init (&self->module, &self->core, global_templ);
    _gum_v8_thread_init (&self->thread, &self->core, global_templ);
    _gum_v8_process_init (&self->process, &self->module, &self->thread,
        &self->core, global_templ);
    _gum_v8_file_init (&self->file, &self->core, global_templ);
    _gum_v8_checksum_init (&self->checksum, &self->core, global_templ);
    _gum_v8_stream_init (&self->stream, &self->core, global_templ);
    _gum_v8_socket_init (&self->socket, &self->core, global_templ);
#ifdef HAVE_SQLITE
    _gum_v8_database_init (&self->database, &self->core, global_templ);
#endif
    _gum_v8_interceptor_init (&self->interceptor, &self->core,
        global_templ);
    _gum_v8_api_resolver_init (&self->api_resolver, &self->core, global_templ);
    _gum_v8_symbol_init (&self->symbol, &self->core, global_templ);
    _gum_v8_cmodule_init (&self->cmodule, &self->core, global_templ);
    _gum_v8_instruction_init (&self->instruction, &self->core, global_templ);
    _gum_v8_code_writer_init (&self->code_writer, &self->core, global_templ);
    _gum_v8_code_relocator_init (&self->code_relocator, &self->code_writer,
        &self->instruction, &self->core, global_templ);
    _gum_v8_stalker_init (&self->stalker, &self->code_writer,
        &self->instruction, &self->core, global_templ);
    _gum_v8_cloak_init (&self->cloak, &self->core, global_templ);

    Local<Context> context (Context::New (isolate, NULL, global_templ));
    {
      auto name_buffer = gum_string_buffer_from_utf8 (self->name);
      V8ContextInfo info (context, self->context_group_id,
          name_buffer->string ());
      self->inspector->contextCreated (info);
    }
    g_signal_emit (self, gum_v8_script_signals[CONTEXT_CREATED], 0, &context);
    self->context = new Global<Context> (isolate, context);
    Context::Scope context_scope (context);
    _gum_v8_core_realize (&self->core);
    _gum_v8_kernel_realize (&self->kernel);
    _gum_v8_memory_realize (&self->memory);
    _gum_v8_module_realize (&self->module);
    _gum_v8_thread_realize (&self->thread);
    _gum_v8_process_realize (&self->process);
    _gum_v8_file_realize (&self->file);
    _gum_v8_checksum_realize (&self->checksum);
    _gum_v8_stream_realize (&self->stream);
    _gum_v8_socket_realize (&self->socket);
#ifdef HAVE_SQLITE
    _gum_v8_database_realize (&self->database);
#endif
    _gum_v8_interceptor_realize (&self->interceptor);
    _gum_v8_api_resolver_realize (&self->api_resolver);
    _gum_v8_symbol_realize (&self->symbol);
    _gum_v8_cmodule_realize (&self->cmodule);
    _gum_v8_instruction_realize (&self->instruction);
    _gum_v8_code_writer_realize (&self->code_writer);
    _gum_v8_code_relocator_realize (&self->code_relocator);
    _gum_v8_stalker_realize (&self->stalker);
    _gum_v8_cloak_realize (&self->cloak);

    self->program = gum_v8_script_compile (self, isolate, context, error);
  }

  if (self->program == NULL)
  {
    gum_v8_script_destroy_context (self);
    return FALSE;
  }

  g_free (self->source);
  self->source = NULL;

  return TRUE;
}

static GumESProgram *
gum_v8_script_compile (GumV8Script * self,
                       Isolate * isolate,
                       Local<Context> context,
                       GError ** error)
{
  GumESProgram * program = gum_es_program_new ();
  context->SetAlignedPointerInEmbedderData (0, program);

  const gchar * source = self->source;
  const gchar * package_marker = "📦\n";
  const gchar * delimiter_marker = "\n✄\n";
  const gchar * alias_marker = "\n↻ ";

  if (g_str_has_prefix (source, package_marker))
  {
    program->entrypoints = g_ptr_array_new ();

    const gchar * source_end = source + std::strlen (source);
    const gchar * header_cursor = source + std::strlen (package_marker);

    do
    {
      GumESAsset * entrypoint = NULL;

      const gchar * asset_cursor = strstr (header_cursor, delimiter_marker);
      if (asset_cursor == NULL)
        goto malformed_package;

      const gchar * header_end = asset_cursor;

      for (guint i = 0; header_cursor != header_end; i++)
      {
        if (i != 0 && !g_str_has_prefix (asset_cursor, delimiter_marker))
          goto malformed_package;
        asset_cursor += std::strlen (delimiter_marker);

        const gchar * size_end;
        guint64 asset_size =
            g_ascii_strtoull (header_cursor, (gchar **) &size_end, 10);
        if (asset_size == 0 || asset_size > GUM_MAX_ASSET_SIZE)
          goto malformed_package;
        if (asset_cursor + asset_size > source_end)
          goto malformed_package;

        const gchar * rest_start = size_end + 1;
        const gchar * rest_end = std::strchr (rest_start, '\n');

        gchar * asset_name = g_strndup (rest_start, rest_end - rest_start);
        if (g_hash_table_contains (program->es_assets, asset_name))
        {
          g_free (asset_name);
          goto malformed_package;
        }

        gchar * asset_data = g_strndup (asset_cursor, asset_size);

        auto asset = gum_es_asset_new_take (asset_name, asset_data, asset_size);
        g_hash_table_insert (program->es_assets, asset_name, asset);

        while (g_str_has_prefix (rest_end, alias_marker))
        {
          const gchar * alias_start = rest_end + std::strlen (alias_marker);
          const gchar * alias_end = std::strchr (alias_start, '\n');

          gchar * asset_alias =
              g_strndup (alias_start, alias_end - alias_start);
          if (g_hash_table_contains (program->es_assets, asset_alias))
          {
            g_free (asset_alias);
            goto malformed_package;
          }
          g_hash_table_insert (program->es_assets, asset_alias,
              gum_es_asset_ref (asset));

          rest_end = alias_end;
        }

        if (entrypoint == NULL && g_str_has_suffix (asset_name, ".js"))
          entrypoint = asset;

        header_cursor = rest_end;
        asset_cursor += asset_size;
      }

      if (entrypoint == NULL)
        goto malformed_package;

      Local<Module> module;
      TryCatch trycatch (isolate);
      auto result =
          gum_ensure_module_defined (isolate, context, entrypoint, program);
      bool success = result.ToLocal (&module);
      if (success)
      {
        auto instantiate_result =
            module->InstantiateModule (context, gum_resolve_module);
        if (!instantiate_result.To (&success))
          success = false;
      }

      if (!success)
      {
        gchar * message =
            _gum_v8_error_get_message (isolate, trycatch.Exception ());
        g_set_error_literal (error, GUM_ERROR, GUM_ERROR_FAILED, message);
        g_free (message);
        goto propagate_error;
      }

      g_ptr_array_add (program->entrypoints, entrypoint);

      if (g_str_has_prefix (asset_cursor, delimiter_marker))
        header_cursor = asset_cursor + std::strlen (delimiter_marker);
      else
        header_cursor = NULL;
    }
    while (header_cursor != NULL);
  }
  else
  {
    program->global_filename = g_strconcat ("/", self->name, ".js", NULL);

    auto resource_name = String::NewFromUtf8 (isolate, program->global_filename)
        .ToLocalChecked ();
    ScriptOrigin origin (isolate, resource_name);

    auto source_str = String::NewFromUtf8 (isolate, source).ToLocalChecked ();

    Local<Script> code;
    TryCatch trycatch (isolate);
    auto maybe_code = Script::Compile (context, source_str, &origin);
    if (maybe_code.ToLocal (&code))
    {
      program->global_code = new Global<Script> (isolate, code);
    }
    else
    {
      Local<Message> message = trycatch.Message ();
      Local<Value> exception = trycatch.Exception ();
      String::Utf8Value exception_str (isolate, exception);
      g_set_error (error, GUM_ERROR, GUM_ERROR_FAILED, "Script(line %d): %s",
          message->GetLineNumber (context).FromMaybe (-1), *exception_str);
      goto propagate_error;
    }
  }

  goto beach;

malformed_package:
  {
    g_set_error (error,
        GUM_ERROR,
        GUM_ERROR_INVALID_DATA,
        "Malformed package");

    goto propagate_error;
  }
propagate_error:
  {
    context->SetAlignedPointerInEmbedderData (0, nullptr);
    gum_es_program_free (program);
    program = NULL;

    goto beach;
  }
beach:
  {
    return program;
  }
}

MaybeLocal<Module>
_gum_v8_script_load_module (GumV8Script * self,
                            const gchar * name,
                            const gchar * source)
{
  auto isolate = self->isolate;

  GumESProgram * program = self->program;
  if (g_hash_table_contains (program->es_assets, name))
  {
    _gum_v8_throw (isolate, "module '%s' already exists", name);
    return MaybeLocal<Module> ();
  }

  gchar * name_copy = g_strdup (name);
  GumESAsset * asset =
      gum_es_asset_new_take (name_copy, g_strdup (source), strlen (source));

  auto context = Local<Context>::New (isolate, *self->context);

  MaybeLocal<Module> maybe_module =
      gum_ensure_module_defined (isolate, context, asset, program);

  bool success = false;
  Local<Module> m;
  if (maybe_module.ToLocal (&m))
  {
    success = m->InstantiateModule (context, gum_resolve_module).IsJust ();
  }

  if (success)
  {
    g_hash_table_insert (program->es_assets, name_copy, asset);

    gchar * source_map = gum_script_backend_extract_inline_source_map (source);
    if (source_map != NULL)
    {
      gchar * map_name = g_strconcat (name, ".map", NULL);
      g_hash_table_insert (program->es_assets, map_name,
          gum_es_asset_new_take (map_name, source_map, strlen (source_map)));
    }
  }
  else
  {
    gum_es_asset_unref (asset);
    g_free (name_copy);
  }

  return maybe_module;
}

void
_gum_v8_script_register_source_map (GumV8Script * self,
                                    const gchar * name,
                                    gchar * source_map)
{
  gchar * map_name = g_strconcat (name, ".map", NULL);
  g_hash_table_insert (self->program->es_assets, map_name,
      gum_es_asset_new_take (map_name, source_map, strlen (source_map)));
}

static MaybeLocal<Promise>
gum_import_module (Local<Context> context,
                   Local<Data> host_defined_options,
                   Local<Value> resource_name,
                   Local<String> specifier,
                   Local<FixedArray> import_assertions)
{
  Local<Promise::Resolver> resolver =
      Promise::Resolver::New (context).ToLocalChecked ();

  auto isolate = context->GetIsolate ();
  auto self = (GumV8Script *) isolate->GetData (0);
  auto program =
      (GumESProgram *) context->GetAlignedPointerFromEmbedderData (0);

  String::Utf8Value specifier_str (isolate, specifier);
  String::Utf8Value resource_name_str (isolate, resource_name);

  gchar * name =
      gum_normalize_module_name (*resource_name_str, *specifier_str, program);

  GumESAsset * target_module = (GumESAsset *) g_hash_table_lookup (
      program->es_assets, name);

  g_free (name);

  if (target_module == NULL)
  {
    resolver->Reject (context,
        Exception::Error (_gum_v8_string_new_ascii (isolate, "not found")))
          .ToChecked ();
    return MaybeLocal<Promise> (resolver->GetPromise ());
  }

  Local<Module> module;
  {
    TryCatch trycatch (isolate);
    if (!gum_ensure_module_defined (isolate, context, target_module, program)
        .ToLocal (&module))
    {
      resolver->Reject (context, trycatch.Exception ()).ToChecked ();
      return MaybeLocal<Promise> (resolver->GetPromise ());
    }
  }

  auto operation = g_slice_new (GumImportOperation);
  operation->self = self;
  operation->resolver = new Global<Promise::Resolver> (isolate, resolver);
  operation->module = new Global<Module> (isolate, module);
  _gum_v8_core_pin (&self->core);

  auto evaluate_request = module->Evaluate (context)
      .ToLocalChecked ().As<Promise> ();
  auto data = External::New (isolate, operation);
  evaluate_request->Then (context,
      Function::New (context, gum_on_import_success,
        data, 1, ConstructorBehavior::kThrow).ToLocalChecked (),
      Function::New (context, gum_on_import_failure,
        data, 1, ConstructorBehavior::kThrow).ToLocalChecked ())
      .ToLocalChecked ();

  return MaybeLocal<Promise> (resolver->GetPromise ());
}

static void
gum_on_import_success (const FunctionCallbackInfo<Value> & info)
{
  auto op = (GumImportOperation *) info.Data ().As<External> ()->Value ();
  auto isolate = info.GetIsolate ();
  auto context = isolate->GetCurrentContext ();

  auto resolver = Local<Promise::Resolver>::New (isolate, *op->resolver);
  auto module = Local<Module>::New (isolate, *op->module);
  resolver->Resolve (context, module->GetModuleNamespace ()).ToChecked ();

  gum_import_operation_free (op);
}

static void
gum_on_import_failure (const FunctionCallbackInfo<Value> & info)
{
  auto op = (GumImportOperation *) info.Data ().As<External> ()->Value ();
  auto isolate = info.GetIsolate ();
  auto context = isolate->GetCurrentContext ();

  auto resolver = Local<Promise::Resolver>::New (isolate, *op->resolver);
  resolver->Reject (context, info[0]).ToChecked ();

  gum_import_operation_free (op);
}

static void
gum_import_operation_free (GumImportOperation * op)
{
  delete op->module;
  delete op->resolver;
  _gum_v8_core_unpin (&op->self->core);
  g_slice_free (GumImportOperation, op);
}

static MaybeLocal<Module>
gum_resolve_module (Local<Context> context,
                    Local<String> specifier,
                    Local<FixedArray> import_assertions,
                    Local<Module> referrer)
{
  auto isolate = context->GetIsolate ();
  auto program =
      (GumESProgram *) context->GetAlignedPointerFromEmbedderData (0);

  auto referrer_module = (GumESAsset *) g_hash_table_lookup (
      program->es_modules, GINT_TO_POINTER (referrer->ScriptId ()));

  String::Utf8Value specifier_str (isolate, specifier);
  gchar * name = gum_normalize_module_name (referrer_module->name,
      *specifier_str, program);

  GumESAsset * target_module = (GumESAsset *) g_hash_table_lookup (
      program->es_assets, name);

  if (target_module == NULL)
    goto not_found;

  g_free (name);

  return gum_ensure_module_defined (isolate, context, target_module, program);

not_found:
  {
    _gum_v8_throw (isolate, "could not load module '%s'", name);
    g_free (name);
    return MaybeLocal<Module> ();
  }
}

static gchar *
gum_normalize_module_name (const gchar * base_name,
                           const gchar * name,
                           GumESProgram * program)
{
  if (name[0] != '.')
  {
    auto asset = (GumESAsset *) g_hash_table_lookup (program->es_assets, name);
    if (asset != NULL)
      return g_strdup (asset->name);

    return g_strdup (name);
  }

  /* The following is exactly like QuickJS' default implementation: */

  guint base_dir_length;
  auto base_dir_end = strrchr (base_name, '/');
  if (base_dir_end != NULL)
    base_dir_length = base_dir_end - base_name;
  else
    base_dir_length = 0;

  auto result = (gchar *) g_malloc (base_dir_length + 1 + strlen (name) + 1);
  memcpy (result, base_name, base_dir_length);
  result[base_dir_length] = '\0';

  auto cursor = name;
  while (TRUE)
  {
    if (g_str_has_prefix (cursor, "./"))
    {
      cursor += 2;
    }
    else if (g_str_has_prefix (cursor, "../"))
    {
      if (result[0] == '\0')
        break;

      gchar * new_end = strrchr (result, '/');
      if (new_end != NULL)
        new_end++;
      else
        new_end = result;

      if (strcmp (new_end, ".") == 0 || strcmp (new_end, "..") == 0)
        break;

      if (new_end > result)
        new_end--;


"""


```