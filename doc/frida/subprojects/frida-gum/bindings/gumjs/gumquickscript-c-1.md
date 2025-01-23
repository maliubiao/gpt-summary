Response:
My thinking process to analyze the code and answer the prompt follows these steps:

1. **Understand the Goal:** The request asks for a functional summary of `gumquickscript.c`, relating it to reverse engineering, low-level details, logic, common errors, and debugging. It also specifies this is the *second* part of the analysis, requiring a summary.

2. **Identify Key Data Structures and Functions:**  I first scan the code for prominent structures and functions. The names give strong hints about their purpose. I note:
    * `GumQuickScript`: Likely the main script object.
    * `GumQuickWorker`: Represents a sandboxed execution environment for the script.
    * `GumQuickCore`:  Provides core functionality within the worker.
    * `GumQuickScope`:  Manages the JavaScript context.
    * Functions like `gum_quick_worker_new`, `gum_quick_worker_init`, `gum_quick_worker_run`, `gum_quick_worker_terminate`, `gum_quick_worker_post`, `gum_quick_worker_emit`. These clearly relate to the lifecycle and communication of the worker.
    * Initialization functions for various subsystems: `_gum_quick_kernel_init`, `_gum_quick_memory_init`, etc. These suggest the scope of the worker's capabilities.

3. **Trace the Worker Lifecycle:** I follow the creation and execution flow of a `GumQuickWorker`:
    * `gum_quick_worker_new`: Allocates and initializes basic worker data (state, mutexes, script association, scheduler, JS runtime/context).
    * `gum_quick_worker_init`:  Sets up the core, initializes various sub-modules (kernel, memory, module, thread, process, etc.), and pushes a job to the JS thread to start execution. This is where a lot of the core Frida functionality within the script gets initialized.
    * `gum_quick_worker_run`:  Loads runtime modules, evaluates the script's entry point, and then executes the main part of the script within an asynchronous context. This involves `import` and `await`, suggesting modern JavaScript features.
    * `gum_quick_worker_terminate`: Initiates the shutdown process, flushing buffers and stopping the scheduler.
    * `gum_quick_worker_flush`:  Handles the actual flushing of resources, ensuring data is written out.

4. **Analyze Subsystem Initialization:** The `_gum_quick_*_init` calls are crucial. They indicate what capabilities are being provided to the JavaScript script:
    * **Low-level:** `kernel`, `memory`, `instruction`, `code_writer`, `code_relocator`. These directly relate to interacting with the target process's memory and code.
    * **OS Interaction:** `module`, `thread`, `process`, `file`, `socket`. These allow the script to interact with the operating system environment of the target process.
    * **Utilities:** `checksum`, `stream`, `database` (if SQLite is enabled), `api_resolver`, `symbol`, `cmodule`, `cloak`. These offer additional tools and functionalities.

5. **Examine Communication Mechanisms:** The `gum_quick_worker_post` and `gum_quick_worker_emit` functions reveal how the script communicates:
    * `gum_quick_worker_post`:  Sends messages *to* the Frida core (likely the main Frida process).
    * `gum_quick_worker_emit`: Sends messages *from* the Frida core to the script's message handler. This suggests an event-driven communication model.

6. **Identify Potential Errors and User Actions:**  I look for error handling and scenarios where things might go wrong:
    * `invalid_url` and `malformed_module` labels in `gum_quick_worker_init` suggest issues with loading the script.
    * `_gum_quick_script_rethrow_parse_error_with_decorations` indicates how script parsing errors are handled and presented.
    * The use of `JS_Eval` opens up possibilities for runtime errors in the JavaScript code.

7. **Relate to Reverse Engineering Concepts:** With the understanding of the functionalities, I connect them to reverse engineering techniques:
    * **Instrumentation:** The core purpose of Frida, enabled by the ability to inject and execute code.
    * **Code manipulation:** `code_writer`, `code_relocator` directly support this.
    * **Memory inspection:** `memory` module allows reading and writing process memory.
    * **API hooking:** `api_resolver` is used to intercept function calls.
    * **Understanding program structure:** `module`, `symbol` help analyze loaded libraries and their symbols.

8. **Consider Low-Level Details:** I highlight aspects that touch the operating system and architecture:
    * Kernel interaction.
    * Memory management.
    * Thread management.
    * File and socket operations.
    * The use of `GBytes` suggests handling of raw binary data.

9. **Analyze Logic and Assumptions:** I look for any conditional logic or assumptions made in the code. The asynchronous nature of script execution and the message passing mechanisms are key logical components.

10. **Construct Examples:**  Based on the identified functionalities and potential errors, I create illustrative examples for reverse engineering use cases and common programming mistakes.

11. **Address Debugging:** I consider how a developer might reach this code during debugging – likely by stepping through Frida's initialization process or investigating script loading/execution errors.

12. **Synthesize the Summary:** Finally, based on all the above analysis, I write a concise summary that captures the main functions of `gumquickscript.c`, emphasizing its role in setting up and managing the JavaScript execution environment within Frida. I highlight its connection to dynamic instrumentation and the capabilities it provides to the injected scripts.

Essentially, I'm reading the code with a focus on "what does this do?", "why does it do it?", and "how can it fail?". The function names and data structures provide a high-level understanding, and then examining the implementation details fills in the gaps. The context of Frida being a dynamic instrumentation tool is crucial for interpreting the purpose of various components.
好的，让我们来归纳一下 `frida/subprojects/frida-gum/bindings/gumjs/gumquickscript.c` 文件中展示的功能，并结合之前部分的内容进行总结。

**文件功能归纳 (结合第一部分):**

`gumquickscript.c` 的主要职责是**管理和执行 Frida Gum JavaScript 脚本**。它创建了一个隔离的 JavaScript 运行环境（称为 `GumQuickWorker`），并负责脚本的加载、初始化、运行、消息传递和最终的清理工作。  该文件是 Frida 中将 JavaScript 代码注入到目标进程并进行动态分析的核心组成部分。

具体来说，它的功能包括：

1. **创建和管理 JavaScript 运行时环境 (`GumQuickWorker`)：**
   - 初始化独立的 JavaScript 引擎实例 (`JS_NewRuntime`, `JS_NewContext`)。
   - 管理 worker 的生命周期，包括创建、初始化、运行、终止等状态。
   - 使用 `GumScriptScheduler` 管理在 JavaScript 线程上执行的任务。

2. **加载和执行 JavaScript 脚本：**
   - 接收要执行的 JavaScript 代码 (`GumESAsset`)。
   - 在独立的 JavaScript 上下文中评估和执行脚本代码 (`JS_EvalFunction`, `JS_Eval`)。
   - 处理脚本执行过程中的异常 (`_gum_quick_scope_catch_and_emit`).
   - 支持异步模块加载 (`import`) 和执行 (`w.run()`).

3. **提供 Frida Gum 的核心功能给 JavaScript 脚本：**
   - 初始化并暴露 Frida Gum 提供的各种 API 和模块到 JavaScript 环境中，例如：
     - **底层操作:** `kernel`, `memory`, `instruction`, `code_writer`, `code_relocator`.
     - **进程和线程:** `process`, `thread`.
     - **模块和符号:** `module`, `symbol`, `api_resolver`.
     - **文件和网络:** `file`, `stream`, `socket`.
     - **其他实用工具:** `checksum`, `database` (如果启用 SQLite), `cloak`.

4. **处理 JavaScript 脚本与 Frida Core 之间的消息传递：**
   - 提供 `post` 方法 (`gum_quick_worker_post`)，允许 JavaScript 脚本向 Frida Core 发送消息。
   - 提供 `emit` 机制 (`gum_quick_worker_emit`)，允许 Frida Core 向 JavaScript 脚本发送消息。
   - 使用 `GumWorkerMessageDelivery` 结构体来封装传递的消息和数据。

5. **资源管理和清理：**
   - 使用引用计数 (`g_atomic_int_inc`, `g_atomic_int_dec_and_test`) 管理 `GumQuickWorker` 的生命周期。
   - 在 worker 终止时，释放所有相关的资源，包括 JavaScript 运行时、上下文、模块、以及分配的内存。

**与逆向方法的关联及举例说明：**

`gumquickscript.c` 是 Frida 进行动态 instrumentation 的核心，与各种逆向方法紧密相关。以下是一些例子：

* **代码注入和执行：**  Frida 通过此文件将 JavaScript 代码注入到目标进程中，实现自定义逻辑的执行。例如，逆向工程师可以使用 JavaScript 代码 Hook 目标函数的入口点，记录参数、修改返回值或者执行额外的操作。
   ```javascript
   // 假设要 Hook 的函数是 Module.findExportByName("libc.so", "open")
   Interceptor.attach(Module.findExportByName("libc.so", "open"), {
     onEnter: function (args) {
       console.log("Opening file:", args[0].readUtf8String());
     },
     onLeave: function (retval) {
       console.log("File descriptor:", retval);
     }
   });
   ```
* **内存读取和修改：**  通过 `Memory` 模块提供的 API，JavaScript 脚本可以读取和修改目标进程的内存，用于分析数据结构、破解保护机制等。
   ```javascript
   // 读取地址 0x12345678 的 4 个字节
   var value = Memory.readU32(ptr("0x12345678"));
   console.log("Value at 0x12345678:", value);

   // 将地址 0x98765432 的 4 个字节修改为 0
   Memory.writeU32(ptr("0x98765432"), 0);
   ```
* **API Hooking：**  `Interceptor` API 允许在函数调用前后插入自定义代码，用于监控 API 调用、分析参数、修改行为等。这是逆向工程中常用的技术。
* **动态代码生成和修改：**  `Instruction`、`CodeWriter` 和 `CodeRelocator` 模块允许在运行时分析、生成和修改目标进程的代码，实现更复杂的动态分析和操控。

**涉及的二进制底层、Linux/Android 内核及框架知识及举例说明：**

该文件以及它所支持的功能深入涉及到二进制底层和操作系统相关的知识：

* **进程内存管理：**  `Memory` 模块的操作直接涉及目标进程的内存地址空间，需要理解内存布局、地址计算等概念。在 Linux/Android 中，这涉及到对进程虚拟地址空间的理解。
* **动态链接和加载：**  `Module` 和 `Symbol` 模块需要理解动态链接库的加载过程、符号表的结构等。在 Linux 中，这涉及到 ELF 文件的格式；在 Android 中，则涉及到 ELF 和 ART/Dalvik 虚拟机的相关知识。
* **系统调用：**  许多 Frida Gum 的功能最终会转化为系统调用。例如，`File` 模块的操作会调用 `open`、`read`、`write` 等系统调用。理解系统调用的原理对于深入分析 Frida 的行为至关重要。
* **指令集架构：**  `Instruction` 模块需要理解目标平台的指令集架构（例如 ARM、x86）。
* **线程管理：**  `Thread` 模块涉及对线程的枚举和操作，需要了解操作系统提供的线程管理机制。
* **Socket 编程：** `Socket` 模块涉及网络编程的基础知识，例如 TCP/IP 协议栈。
* **Android Framework：** 在 Android 平台上，Frida 还可以与 Android Framework 进行交互，例如 Hook Java 层的方法。这需要了解 Android Runtime (ART) 的内部机制。

**逻辑推理、假设输入与输出：**

以下是一个关于消息传递的逻辑推理示例：

* **假设输入：** JavaScript 脚本调用 `send("hello", [1, 2, 3])`，其中 `[1, 2, 3]` 将被转换为 `ArrayBuffer`。
* **逻辑推理：**
    1. `gum_quick_worker_post` 函数被调用，将消息 "hello" 和 `ArrayBuffer` 数据传递给 Frida Core。
    2. Frida Core 接收到消息，并可能将其转发到连接的客户端。
    3. 如果客户端也通过 Frida 发送了消息处理函数，那么该函数将接收到 "hello" 字符串和一个包含 `[1, 2, 3]` 数据的 `ArrayBuffer` 对象。
* **输出：** 客户端的 JavaScript 代码接收到消息 "hello" 和一个包含 `[1, 2, 3]` 数据的 `ArrayBuffer`。

**用户或编程常见的使用错误及举例说明：**

* **在错误的线程上调用 Frida API：** 许多 Frida Gum 的 API 必须在特定的线程上调用（通常是 Gum 的 worker 线程）。如果在其他线程上调用，可能会导致崩溃或未定义的行为。
   ```javascript
   // 错误示例：在 setTimeout 的回调函数中调用 Interceptor.attach
   setTimeout(function() {
     Interceptor.attach(Module.findExportByName("libc.so", "malloc"), {
       // ...
     });
   }, 1000);
   ```
* **内存操作错误：** 错误地计算内存地址、读取越界或写入非法地址可能导致目标进程崩溃。
   ```javascript
   // 错误示例：读取一个可能未映射的地址
   var invalidAddress = ptr("0xdeadbeef");
   try {
     Memory.readU32(invalidAddress);
   } catch (e) {
     console.error("Error reading memory:", e);
   }
   ```
* **Hooking 不存在的函数或地址：** 尝试 Hook 不存在的函数或地址会导致错误。
   ```javascript
   // 错误示例：Hook 一个不存在的函数名
   Interceptor.attach(Module.findExportByName("libc.so", "nonExistentFunction"), {
     // ...
   }); // 这将会抛出异常
   ```
* **资源泄漏：**  如果脚本分配了资源（例如通过 `Memory.alloc`），但没有正确释放，可能导致内存泄漏。

**用户操作如何一步步到达这里，作为调试线索：**

1. **用户编写 Frida 脚本 (JavaScript)。**
2. **用户使用 Frida 命令行工具 (`frida`) 或 API 将脚本注入到目标进程。**  例如：`frida -p <pid> -l your_script.js`。
3. **Frida Core 接收到注入请求，并创建一个 `GumQuickScript` 实例。**
4. **`gum_quick_worker_new` 被调用，创建一个 `GumQuickWorker` 实例。**
5. **`gum_quick_worker_init` 被调用，初始化 worker 的各种模块和环境。**  这是当前代码片段的核心功能。如果在此处发生错误，例如加载脚本失败，那么调试器可能会停在这里。
6. **`gum_quick_worker_run` 被调用，开始执行 JavaScript 脚本。**
7. **在脚本执行过程中，可能会调用各种 Frida Gum 的 API，这些 API 的实现最终会与 `GumQuickWorker` 中的各种模块进行交互。**
8. **如果脚本调用 `send()`，则会触发 `gum_quick_worker_post`。如果 Frida Core 需要向脚本发送消息，则会调用 `gum_quick_worker_emit`。**
9. **当脚本执行完成或被终止时，`_gum_quick_worker_unref` 会被调用，进行资源的清理。**

作为调试线索，如果用户在使用 Frida 时遇到问题，例如脚本加载失败或运行时崩溃，那么查看 `gumquickscript.c` 中的代码（特别是 `gum_quick_worker_init` 和 `gum_quick_worker_run`）可以帮助理解脚本初始化的过程，并找到可能的错误原因，例如无效的脚本 URL、脚本解析错误等。此外，检查 worker 的状态转换也有助于理解脚本的生命周期。

总而言之，`gumquickscript.c` 是 Frida Gum 中至关重要的组成部分，它负责构建和管理 JavaScript 脚本的执行环境，并将 Frida 的强大功能暴露给脚本，从而支持各种动态 instrumentation 和逆向分析任务。理解这个文件的功能有助于深入了解 Frida 的工作原理，并能更有效地使用和调试 Frida 脚本。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickscript.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
JS_DupValue (ctx, global_obj), JS_PROP_C_W_E);

  core = &worker->core;

  {
    GumQuickScope scope = { core, NULL, };

    _gum_quick_core_init (core, self, ctx, global_obj, &worker->scope_mutex,
        self->program, gumjs_frida_source_map, NULL, NULL,
        (GumQuickMessageEmitter) gum_quick_worker_emit, worker,
        worker->scheduler);

    core->current_scope = &scope;

    _gum_quick_kernel_init (&worker->kernel, global_obj, core);
    _gum_quick_memory_init (&worker->memory, global_obj, core);
    _gum_quick_module_init (&worker->module, global_obj, core);
    _gum_quick_thread_init (&worker->thread, global_obj, core);
    _gum_quick_process_init (&worker->process, global_obj, &worker->module,
        &worker->thread, core);
    _gum_quick_file_init (&worker->file, global_obj, core);
    _gum_quick_checksum_init (&worker->checksum, global_obj, core);
    _gum_quick_stream_init (&worker->stream, global_obj, core);
    _gum_quick_socket_init (&worker->socket, global_obj, &worker->stream, core);
#ifdef HAVE_SQLITE
    _gum_quick_database_init (&worker->database, global_obj, core);
#endif
    _gum_quick_api_resolver_init (&worker->api_resolver, global_obj, core);
    _gum_quick_symbol_init (&worker->symbol, global_obj, core);
    _gum_quick_cmodule_init (&worker->cmodule, global_obj, core);
    _gum_quick_instruction_init (&worker->instruction, global_obj, core);
    _gum_quick_code_writer_init (&worker->code_writer, global_obj, core);
    _gum_quick_code_relocator_init (&worker->code_relocator, global_obj,
        &worker->code_writer, &worker->instruction, core);
    _gum_quick_cloak_init (&worker->cloak, global_obj, core);

    core->current_scope = NULL;
  }

  JS_FreeValue (ctx, global_obj);

  worker->state = GUM_WORKER_INITIALIZED;

  gum_script_scheduler_push_job_on_js_thread (worker->scheduler,
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_quick_worker_run,
      _gum_quick_worker_ref (worker),
      (GDestroyNotify) _gum_quick_worker_unref);

  return worker;

invalid_url:
  {
    _gum_quick_throw_literal (self->ctx, "invalid URL");

    return NULL;
  }
malformed_module:
  {
    _gum_quick_script_rethrow_parse_error_with_decorations (self, ctx,
        asset->name);

    _gum_quick_worker_unref (worker);

    return NULL;
  }
}

static GumQuickWorker *
gum_quick_worker_new (GumQuickScript * script,
                      GumESAsset * asset,
                      JSValue on_message)
{
  GumQuickWorker * worker;

  worker = g_slice_new0 (GumQuickWorker);
  worker->ref_count = 1;

  worker->state = GUM_WORKER_CREATED;

  worker->flushed = FALSE;
  g_mutex_init (&worker->flush_mutex);
  g_cond_init (&worker->flush_cond);

  worker->script = script;
  worker->asset = gum_es_asset_ref (asset);
  worker->on_message = JS_DupValue (script->ctx, on_message);

  worker->scheduler = gum_script_scheduler_new ();

  g_rec_mutex_init (&worker->scope_mutex);

  worker->rt = gum_quick_script_backend_make_runtime (script->backend);
  JS_SetRuntimeOpaque (worker->rt, &worker->core);

  worker->ctx = JS_NewContext (worker->rt);
  JS_SetContextOpaque (worker->ctx, &worker->core);

  worker->entrypoint = JS_NULL;

  return worker;
}

GumQuickWorker *
_gum_quick_worker_ref (GumQuickWorker * worker)
{
  g_atomic_int_inc (&worker->ref_count);

  return worker;
}

void
_gum_quick_worker_unref (GumQuickWorker * worker)
{
  GumQuickCore * core;

  if (worker == NULL)
    return;

  if (!g_atomic_int_dec_and_test (&worker->ref_count))
    return;

  g_assert (worker->state == GUM_WORKER_CREATED ||
      worker->state == GUM_WORKER_TERMINATED);

  g_object_unref (worker->scheduler);

  core = &worker->core;

  if (worker->state != GUM_WORKER_CREATED)
  {
    GumQuickScope scope;

    _gum_quick_scope_enter (&scope, core);

    _gum_quick_code_relocator_dispose (&worker->code_relocator);
    _gum_quick_code_writer_dispose (&worker->code_writer);
    _gum_quick_instruction_dispose (&worker->instruction);
    _gum_quick_cmodule_dispose (&worker->cmodule);
    _gum_quick_symbol_dispose (&worker->symbol);
    _gum_quick_api_resolver_dispose (&worker->api_resolver);
#ifdef HAVE_SQLITE
    _gum_quick_database_dispose (&worker->database);
#endif
    _gum_quick_socket_dispose (&worker->socket);
    _gum_quick_stream_dispose (&worker->stream);
    _gum_quick_checksum_dispose (&worker->checksum);
    _gum_quick_file_dispose (&worker->file);
    _gum_quick_thread_dispose (&worker->thread);
    _gum_quick_process_dispose (&worker->process);
    _gum_quick_module_dispose (&worker->module);
    _gum_quick_memory_dispose (&worker->memory);
    _gum_quick_kernel_dispose (&worker->kernel);
    _gum_quick_core_dispose (core);

    _gum_quick_scope_leave (&scope);
  }

  {
    GumQuickScope scope = { core, NULL, };

    core->current_scope = &scope;

    JS_FreeContext (worker->ctx);
    JS_FreeRuntime (worker->rt);

    core->current_scope = NULL;
  }

  if (worker->state != GUM_WORKER_CREATED)
  {
    _gum_quick_code_relocator_finalize (&worker->code_relocator);
    _gum_quick_code_writer_finalize (&worker->code_writer);
    _gum_quick_instruction_finalize (&worker->instruction);
    _gum_quick_cmodule_finalize (&worker->cmodule);
    _gum_quick_symbol_finalize (&worker->symbol);
    _gum_quick_api_resolver_finalize (&worker->api_resolver);
#ifdef HAVE_SQLITE
    _gum_quick_database_finalize (&worker->database);
#endif
    _gum_quick_socket_finalize (&worker->socket);
    _gum_quick_stream_finalize (&worker->stream);
    _gum_quick_checksum_finalize (&worker->checksum);
    _gum_quick_file_finalize (&worker->file);
    _gum_quick_thread_finalize (&worker->thread);
    _gum_quick_process_finalize (&worker->process);
    _gum_quick_module_finalize (&worker->module);
    _gum_quick_memory_finalize (&worker->memory);
    _gum_quick_kernel_finalize (&worker->kernel);
    _gum_quick_core_finalize (core);
  }

  g_rec_mutex_clear (&worker->scope_mutex);

  JS_FreeValue (worker->script->ctx, worker->on_message);

  gum_es_asset_unref (worker->asset);

  g_cond_clear (&worker->flush_cond);
  g_mutex_clear (&worker->flush_mutex);

  g_slice_free (GumQuickWorker, worker);
}

static void
gum_quick_worker_run (GumQuickWorker * self)
{
  JSContext * ctx = self->ctx;
  GumQuickScope scope;
  JSValue val;

  _gum_quick_scope_enter (&scope, &self->core);

  gum_quick_bundle_load (gumjs_runtime_modules, ctx);

  val = JS_EvalFunction (ctx, self->entrypoint);
  if (!JS_IsException (val))
    self->state = GUM_WORKER_LOADED;
  else
    _gum_quick_scope_catch_and_emit (&scope);

  JS_FreeValue (ctx, val);

  if (self->state == GUM_WORKER_LOADED)
  {
    gchar * init_code;

    init_code = g_strdup_printf (
        "(async () => {\n"
        "  try {\n"
        "    const w = await import('%s');\n"
        "    await w.run();\n"
        "  } catch (e) {\n"
        "    Script.nextTick(() => { throw e; });\n"
        "  }\n"
        "})();\n",
        self->asset->name);

    val = JS_Eval (ctx, init_code, strlen (init_code),
        "/_frida_worker_runtime.js",
        JS_EVAL_TYPE_GLOBAL | JS_EVAL_FLAG_STRICT);
    if (!JS_IsException (val))
      self->state = GUM_WORKER_RUNNING;
    else
      _gum_quick_scope_catch_and_emit (&scope);

    JS_FreeValue (ctx, val);
    g_free (init_code);
  }

  _gum_quick_scope_leave (&scope);
}

void
_gum_quick_worker_terminate (GumQuickWorker * self)
{
  if (self->state == GUM_WORKER_TERMINATED)
    return;

  gum_script_scheduler_push_job_on_js_thread (self->scheduler,
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_quick_worker_flush,
      self, NULL);

  g_mutex_lock (&self->flush_mutex);
  while (!self->flushed)
    g_cond_wait (&self->flush_cond, &self->flush_mutex);
  g_mutex_unlock (&self->flush_mutex);

  gum_script_scheduler_stop (self->scheduler);

  self->state = GUM_WORKER_TERMINATED;
}

static void
gum_quick_worker_flush (GumQuickWorker * self)
{
  GumQuickScope scope;
  gboolean success;

  _gum_quick_scope_enter (&scope, &self->core);

  _gum_quick_socket_flush (&self->socket);
  _gum_quick_stream_flush (&self->stream);
  _gum_quick_process_flush (&self->process);
  success = _gum_quick_core_flush (&self->core,
      (GumQuickFlushNotify) gum_quick_worker_flush,
      _gum_quick_worker_ref (self),
      (GDestroyNotify) _gum_quick_worker_unref);

  _gum_quick_scope_leave (&scope);

  if (success)
  {
    g_mutex_lock (&self->flush_mutex);
    self->flushed = TRUE;
    g_cond_signal (&self->flush_cond);
    g_mutex_unlock (&self->flush_mutex);
  }
}

void
_gum_quick_worker_post (GumQuickWorker * self,
                        const gchar * message,
                        GBytes * data)
{
  gum_script_scheduler_push_job_on_js_thread (self->scheduler,
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_quick_worker_do_post,
      gum_worker_message_delivery_new (self, message, data),
      (GDestroyNotify) gum_worker_message_delivery_free);
}

static void
gum_quick_worker_do_post (GumWorkerMessageDelivery * d)
{
  _gum_quick_core_post (&d->worker->core, d->message,
      g_steal_pointer (&d->data));
}

static void
gum_quick_worker_emit (const gchar * message,
                       GBytes * data,
                       GumQuickWorker * self)
{
  gum_script_scheduler_push_job_on_js_thread (
      gum_quick_script_backend_get_scheduler (self->core.backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_quick_worker_do_emit,
      gum_worker_message_delivery_new (self, message, data),
      (GDestroyNotify) gum_worker_message_delivery_free);
}

static void
gum_quick_worker_do_emit (GumWorkerMessageDelivery * d)
{
  GumQuickWorker * self = d->worker;
  GumQuickScript * script = self->script;
  JSContext * ctx = script->ctx;
  GumQuickScope scope;
  JSValue argv[2];

  _gum_quick_scope_enter (&scope, &script->core);

  argv[0] = JS_NewString (ctx, d->message);

  if (d->data != NULL)
  {
    gpointer data_buffer;
    gsize data_size;

    data_buffer =
        g_bytes_unref_to_data (g_steal_pointer (&d->data), &data_size);

    argv[1] = JS_NewArrayBuffer (ctx, data_buffer, data_size,
        _gum_quick_array_buffer_free, data_buffer, FALSE);
  }
  else
  {
    argv[1] = JS_NULL;
  }

  _gum_quick_scope_call_void (&scope, self->on_message, JS_UNDEFINED,
      G_N_ELEMENTS (argv), argv);

  JS_FreeValue (ctx, argv[1]);
  JS_FreeValue (ctx, argv[0]);

  _gum_quick_scope_leave (&scope);
}

static GumWorkerMessageDelivery *
gum_worker_message_delivery_new (GumQuickWorker * worker,
                                 const gchar * message,
                                 GBytes * data)
{
  GumWorkerMessageDelivery * d;

  d = g_slice_new (GumWorkerMessageDelivery);
  d->worker = _gum_quick_worker_ref (worker);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  return d;
}

static void
gum_worker_message_delivery_free (GumWorkerMessageDelivery * d)
{
  g_bytes_unref (d->data);
  g_free (d->message);
  _gum_quick_worker_unref (d->worker);

  g_slice_free (GumWorkerMessageDelivery, d);
}

JSValue
_gum_quick_script_rethrow_parse_error_with_decorations (GumQuickScript * self,
                                                        JSContext * ctx,
                                                        const gchar * name)
{
  JSValue exception_val, message_val, line_val;
  const char * message;
  uint32_t line;

  exception_val = JS_GetException (ctx);
  message_val = JS_GetPropertyStr (ctx, exception_val, "message");
  line_val = JS_GetPropertyStr (ctx, exception_val, "lineNumber");

  message = JS_ToCString (ctx, message_val);
  JS_ToUint32 (ctx, &line, line_val);

  _gum_quick_throw (self->ctx, "could not parse '%s' line %u: %s",
      name, line, message);

  JS_FreeCString (ctx, message);
  JS_FreeValue (ctx, line_val);
  JS_FreeValue (ctx, message_val);
  JS_FreeValue (ctx, exception_val);

  return JS_EXCEPTION;
}

void
_gum_quick_panic (JSContext * ctx,
                  const gchar * prefix)
{
  JSValue exception_val, stack_val;
  const char * message, * stack;

  exception_val = JS_GetException (ctx);

  message = JS_ToCString (ctx, exception_val);

  stack_val = JS_GetPropertyStr (ctx, exception_val, "stack");
  stack = JS_ToCString (ctx, stack_val);

  if (stack[0] != '\0')
    gum_panic ("%s: %s [stack: %s]", prefix, message, stack);
  else
    gum_panic ("%s: %s", prefix, message);
}
```