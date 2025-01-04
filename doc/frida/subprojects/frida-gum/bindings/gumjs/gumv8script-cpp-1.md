Response:
The user is asking for a summary of the functionalities present in the provided C++ code snippet, which is part of Frida, a dynamic instrumentation toolkit. The user also wants to know how these functionalities relate to reverse engineering, low-level concepts (like the kernel), and common user errors.

Here's a breakdown of the thought process to answer the request:

1. **Identify the Core Purpose:** The file is named `gumv8script.cpp` and resides within Frida's source tree, specifically under `frida-gum/bindings/gumjs`. This immediately suggests it's responsible for bridging Frida's "Gum" (the core instrumentation engine) with the V8 JavaScript engine. The "script" part indicates it manages the execution of JavaScript code within Frida's environment.

2. **Analyze Function Declarations:**  Skim through the code and identify the main functions. Look for patterns and prefixes. Functions starting with `gum_v8_script_` are likely the primary interface for managing JavaScript scripts.

3. **Categorize Functionalities:** Group the functions based on their apparent purpose. Some obvious categories emerge:
    * **Script Lifecycle:** Loading (`gum_v8_script_load`, `gum_v8_script_do_load`, `gum_v8_script_execute_entrypoints`), unloading (`gum_v8_script_unload`, `gum_v8_script_do_unload`, `gum_v8_script_try_unload`), creation and destruction (`gum_v8_script_destroy_context`).
    * **Context Management:**  The `gum_v8_script_destroy_context` function explicitly deals with cleaning up the V8 context and associated Frida components.
    * **Message Handling:**  Functions like `gum_v8_script_post`, `gum_v8_script_do_post`, `gum_v8_script_emit`, and `gum_v8_script_do_emit` clearly manage communication between the Frida agent (JavaScript) and the Frida core.
    * **Debugging:** The presence of `gum_v8_script_set_debug_message_handler`, `gum_v8_script_post_debug_message`, and related functions indicates support for debugging the JavaScript code. The "inspector" mentions point to the V8 Inspector protocol.
    * **Module Handling:** `gum_ensure_module_defined` suggests support for JavaScript modules.
    * **Internal Frida Components:**  Functions related to `stalker`, `interceptor`, `code_relocator`, etc., point to Frida's internal instrumentation capabilities being exposed to JavaScript.
    * **Error Handling:** The code uses `TryCatch` blocks in V8 and functions like `_gum_v8_throw`, indicating error management.

4. **Connect to Reverse Engineering Concepts:**  Think about how each category of functionality can be used in reverse engineering:
    * **Instrumentation:** The core of Frida. The ability to run JavaScript allows dynamic analysis, hooking functions, intercepting calls, and modifying behavior. The mentions of `stalker` (code tracing) and `interceptor` (function hooking) are direct connections.
    * **Debugging:**  Essential for understanding program flow and identifying issues in reverse-engineered targets. The V8 Inspector integration allows using standard debugging tools.
    * **Module Handling:** Important for modern JavaScript applications and for injecting code into specific parts of the target process.
    * **Low-Level Access:**  The presence of modules like `_gum_v8_memory_dispose`, `_gum_v8_process_dispose`, etc., indicates the ability to interact with the target process's memory, processes, and threads.

5. **Relate to Low-Level Concepts:** Look for keywords and function names that suggest interaction with the operating system or underlying architecture:
    * **Kernel:** `_gum_v8_kernel_dispose` explicitly mentions the kernel.
    * **Linux/Android:** While not explicitly stated in *this* snippet, the context of Frida as a cross-platform tool, particularly its use in Android reverse engineering, makes this a likely underlying platform.
    * **Binary/Memory:** Functions related to memory (`_gum_v8_memory_dispose`) and code relocation (`_gum_v8_code_relocator_dispose`) point to direct manipulation of the target process's binary code in memory.

6. **Consider Logical Reasoning (Input/Output):**  While the code is primarily about setting up and managing the V8 environment, some logical flows can be inferred:
    * **Module Loading:** Input: a path to a JavaScript module. Output: A loaded V8 Module object.
    * **Message Passing:** Input: a string message and optional binary data from either the native side or the JavaScript side. Output: The message is delivered to the other side.
    * **Debugging:** Input: Debug commands over the V8 Inspector protocol. Output: Changes in the execution state of the JavaScript code (breakpoints hit, stepping, etc.).

7. **Identify Potential User Errors:** Think about how a developer using Frida might misuse these features:
    * **Incorrect Script Loading:** Providing a script with syntax errors would cause the compilation to fail.
    * **Unloading Issues:** Trying to unload a script that is still actively running or has resources allocated could lead to errors.
    * **Incorrect Message Handling:**  Mismatched message formats between the agent and the Frida core.
    * **Debugger Issues:**  Trying to debug without a debugger attached or sending invalid debugger commands.

8. **Trace User Operations:**  Imagine the steps a user takes when using Frida:
    1. **Target Selection:** The user selects a process to instrument.
    2. **Script Creation:** The user writes a JavaScript script to perform the desired instrumentation.
    3. **Script Injection/Loading:** Frida loads the script into the target process. This is where the `gum_v8_script_load` functions are used.
    4. **Script Execution:** The JavaScript code executes within the V8 context managed by this file.
    5. **Interaction (Optional):** The JavaScript code might send messages back to the user or interact with Frida's native components.
    6. **Unloading (Optional):** The user might choose to detach Frida and unload the script.

9. **Address Part 2:**  The final instruction is to summarize the functionality. This involves concisely stating the main responsibilities of the `gumv8script.cpp` file.

By following these steps, we can systematically analyze the code snippet and generate a comprehensive and informative answer that addresses all aspects of the user's request.
这是 `frida/subprojects/frida-gum/bindings/gumjs/gumv8script.cpp` 文件的第二部分代码，延续了第一部分的功能，主要负责 Frida 中 JavaScript 脚本的生命周期管理、执行、通信以及调试功能。

**归纳一下它的功能：**

总体来说，这部分代码主要负责以下几个核心功能：

1. **脚本加载和执行的完成:**  实现了 JavaScript 模块入口点（entrypoints）的执行，并处理执行结果，包括可能的异常。
2. **脚本卸载:** 提供了异步和同步的脚本卸载机制，确保在卸载前清理所有相关资源。
3. **脚本和 Frida 核心之间的消息传递:**  实现了从 JavaScript 脚本向 Frida 核心发送消息 (`gum_v8_script_post`) 以及从 Frida 核心向 JavaScript 脚本发送消息 (`gum_v8_script_emit`) 的机制。
4. **JavaScript 脚本的调试支持:**  集成了 V8 的 Inspector 协议，允许外部调试器连接并调试 Frida 注入的 JavaScript 代码。
5. **内部 Frida 组件的访问:**  提供了访问 Frida 内部组件（如 Stalker）的接口，以便 JavaScript 脚本可以利用 Frida 的强大功能。
6. **资源管理和清理:**  在脚本加载、卸载以及生命周期的其他阶段，负责管理和清理 V8 上下文、模块、以及其他相关资源。

**与逆向方法的关系及举例说明:**

* **动态代码注入和执行:**  这段代码是 Frida 动态代码注入和执行的核心部分。逆向工程师可以使用 Frida 编写 JavaScript 脚本，并通过这段代码加载和执行到目标进程中，从而动态地修改目标程序的行为。
    * **举例:**  逆向工程师可以编写一个 JavaScript 脚本，使用 `Interceptor.attach` 监听目标程序特定函数的调用，并记录函数的参数和返回值。当 Frida 加载并执行这个脚本时，这段代码中的逻辑会使得 `Interceptor.attach` 生效，从而实现对目标函数的 hook。
* **运行时分析和修改:**  通过执行 JavaScript 脚本，逆向工程师可以在运行时检查和修改目标程序的内存、调用栈、函数行为等。
    * **举例:**  可以使用 `Memory.readByteArray` 读取目标进程内存中的数据，或者使用 `Memory.writeByteArray` 修改内存中的指令，从而在运行时改变程序的逻辑。
* **调试和跟踪:**  V8 Inspector 集成允许逆向工程师使用 Chrome DevTools 等工具连接到 Frida 并调试注入的 JavaScript 代码，方便理解脚本的执行流程和排查问题。
    * **举例:**  在 JavaScript 脚本中设置断点，当脚本执行到断点时，调试器会暂停，允许逆向工程师查看当前的变量值、调用栈等信息。

**涉及到的二进制底层、Linux、Android 内核及框架的知识及举例说明:**

* **V8 JavaScript 引擎:**  代码大量使用了 V8 引擎的 API，例如 `Isolate`, `Context`, `ScriptCompiler`, `Module` 等。理解 V8 引擎的原理和 API 是理解这段代码的关键。
* **内存管理:**  代码中涉及到内存的分配和释放，例如 `g_slice_new`, `g_free` 等，以及 V8 对象的生命周期管理。
* **线程和同步:**  代码中使用了 Glib 库的线程和同步机制，例如 `g_main_context_ref_thread_default`, `g_idle_source_new`, `g_cond_signal`, `g_mutex_lock` 等，用于管理 JavaScript 代码的执行线程以及同步访问共享资源。
* **进程间通信 (IPC):**  虽然这段代码本身没有直接涉及进程间通信，但 Frida 作为动态插桩工具，其核心功能就是跨进程工作。这段代码负责在目标进程中运行 JavaScript 代码，而 Frida 的其他部分则负责与 Frida 客户端进行通信。
* **动态链接和加载:**  Frida 需要将 Gum 引擎和 JavaScript 脚本注入到目标进程中，这涉及到动态链接和加载的知识。
* **操作系统 API:**  Frida 的底层操作会涉及到操作系统 API 的调用，例如内存读写、进程管理等。虽然这段代码没有直接展示这些 API 调用，但其背后的 Frida Gum 引擎会使用到这些 API。

**逻辑推理、假设输入与输出:**

* **假设输入:**  一个包含 ES 模块入口点的 JavaScript 脚本的 GumESProgram 对象。
* **逻辑推理:** `gum_v8_script_execute_entrypoints` 函数会遍历 `program->entrypoints` 中的每个模块，使用 V8 的 `Module::Evaluate` 方法执行这些模块。它会创建一个 Promise 数组来追踪每个模块的执行结果，并使用 `Promise.allSettled` 来等待所有模块执行完成。
* **输出:** 如果所有模块都成功执行，`gum_v8_script_on_entrypoints_executed` 会被调用，并最终调用 `gum_v8_script_complete_load_task`，将脚本状态设置为 `GUM_SCRIPT_STATE_LOADED`。如果任何模块执行失败，`gum_v8_script_on_entrypoints_executed` 中会处理异常。

* **假设输入:**  调用 `gum_v8_script_unload` 函数请求卸载一个已加载的脚本。
* **逻辑推理:** `gum_v8_script_do_unload` 会将脚本状态设置为 `GUM_SCRIPT_STATE_UNLOADING`，并调用 `gum_v8_script_try_unload` 尝试卸载。`gum_v8_script_try_unload` 会清理 Frida 内部组件和 V8 上下文。
* **输出:** 如果卸载成功，脚本状态最终会变为 `GUM_SCRIPT_STATE_UNLOADED`，并且之前注册的卸载回调函数会被执行。

**涉及用户或者编程常见的使用错误及举例说明:**

* **尝试卸载未加载的脚本:**  用户可能会尝试调用 `frida.unload()` 卸载一个尚未成功加载的脚本，这会导致 `gum_v8_script_do_unload` 中的状态检查失败，并抛出错误 "Invalid operation"。
* **在脚本卸载后尝试访问脚本对象:**  用户可能会在调用 `frida.unload()` 后，仍然尝试访问之前获取的脚本对象，这会导致访问已经释放的内存，从而引发崩溃或不可预测的行为。
* **在消息处理函数中抛出未捕获的异常:**  如果用户在传递给 `script.on('message', ...)` 的消息处理函数中抛出异常，可能会导致 Frida 崩溃或脚本执行中断。Frida 会尝试捕获这些异常，但这仍然是一个潜在的错误点。
* **调试器端口冲突:**  如果用户尝试连接调试器，但指定的端口已被其他程序占用，连接会失败。

**说明用户操作是如何一步步的到达这里，作为调试线索:**

1. **用户编写 Frida JavaScript 脚本:**  用户使用 Frida API 编写 JavaScript 代码，例如使用 `Interceptor.attach` 进行 hook，或者使用 `send()` 发送消息。
2. **用户使用 Frida 客户端加载脚本:**  用户通过 Frida 客户端（例如 Python 脚本中使用 `session.create_script(js_code).load()`）将 JavaScript 代码发送给 Frida 服务。
3. **Frida 服务接收脚本并创建 GumV8Script 对象:**  Frida 服务会创建一个 `GumV8Script` 对象来管理这个脚本的生命周期。
4. **调用 `gum_v8_script_load` 或其同步版本:**  Frida 服务会调用 `gum_v8_script_load` 或 `gum_v8_script_load_sync` 来启动脚本加载过程.
5. **执行入口点 (`gum_v8_script_execute_entrypoints`):**  该函数会被调用来执行脚本中定义的模块入口点。这部分代码负责执行这些模块并处理可能的错误。
6. **消息传递 (`gum_v8_script_post`, `gum_v8_script_emit`):**  如果 JavaScript 脚本中使用了 `send()` 函数，最终会调用到 `gum_v8_script_post` 函数，将消息发送到 Frida 客户端。反之，Frida 客户端使用 `script.post()` 发送的消息会通过 `gum_v8_script_emit` 传递到 JavaScript 脚本。
7. **调试器连接 (`gum_v8_script_set_debug_message_handler`, etc.):** 当用户尝试使用调试器连接到 Frida 时，会触发与 V8 Inspector 相关的函数，例如 `gum_v8_script_set_debug_message_handler`，用于建立调试通道。
8. **卸载脚本 (`gum_v8_script_unload`):** 当用户在 Frida 客户端调用 `script.unload()` 时，会触发 `gum_v8_script_unload` 函数，开始脚本卸载流程。

作为调试线索，理解这些步骤可以帮助开发者追踪脚本加载、执行、消息传递以及调试过程中出现的问题，例如：

* **脚本加载失败:**  检查 `gum_v8_script_do_load` 和 `gum_v8_script_execute_entrypoints` 中是否有错误抛出。
* **消息无法传递:**  检查 `gum_v8_script_post` 和 `gum_v8_script_emit` 是否正确调用，以及消息处理函数是否正确注册。
* **调试器连接问题:**  检查 `gum_v8_script_connect_inspector_channel` 和相关的 Inspector 函数是否正常工作。
* **脚本卸载问题:**  检查 `gum_v8_script_try_unload` 中是否有资源清理失败的情况。

总而言之，这部分代码是 Frida 中 JavaScript 脚本运行的核心基础设施，负责脚本的生命周期管理、执行环境搭建、以及与 Frida 核心的通信和调试支持。理解这段代码的功能对于深入理解 Frida 的工作原理和进行高级的 Frida 开发至关重要。

Prompt: 
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8script.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能

"""
      *new_end = '\0';

      cursor += 3;
    }
    else
    {
      break;
    }
  }

  strcat (result, "/");
  strcat (result, cursor);

  return result;
}

static MaybeLocal<Module>
gum_ensure_module_defined (Isolate * isolate,
                           Local<Context> context,
                           GumESAsset * asset,
                           GumESProgram * program)
{
  if (asset->module != nullptr)
    return Local<Module>::New (isolate, *asset->module);

  auto source_str = String::NewFromUtf8 (isolate, (const char *) asset->data)
      .ToLocalChecked ();

  auto resource_name = String::NewFromUtf8 (isolate, asset->name)
      .ToLocalChecked ();
  int resource_line_offset = 0;
  int resource_column_offset = 0;
  bool resource_is_shared_cross_origin = false;
  int script_id = -1;
  auto source_map_url = Local<Value> ();
  bool resource_is_opaque = false;
  bool is_wasm = false;
  bool is_module = true;
  ScriptOrigin origin (
      isolate,
      resource_name,
      resource_line_offset,
      resource_column_offset,
      resource_is_shared_cross_origin,
      script_id,
      source_map_url,
      resource_is_opaque,
      is_wasm,
      is_module);

  ScriptCompiler::Source source (source_str, origin);

  Local<Module> module;
  gchar * error_description = NULL;
  int line = -1;
  {
    TryCatch trycatch (isolate);
    auto compile_result = ScriptCompiler::CompileModule (isolate, &source);
    if (!compile_result.ToLocal (&module))
    {
      error_description =
          _gum_v8_error_get_message (isolate, trycatch.Exception ());
      line = trycatch.Message ()->GetLineNumber (context).FromMaybe (-1);
    }
  }
  if (error_description != NULL)
  {
    _gum_v8_throw (isolate,
        "could not parse '%s' line %d: %s",
        asset->name,
        line,
        error_description);
    g_free (error_description);
    return MaybeLocal<Module> ();
  }

  asset->module = new Global<Module> (isolate, module);

  g_hash_table_insert (program->es_modules,
      GINT_TO_POINTER (module->ScriptId ()), asset);

  g_free (asset->data);
  asset->data = NULL;

  return module;
}

static void
gum_v8_script_destroy_context (GumV8Script * self)
{
  g_assert (self->context != NULL);

  {
    ScriptScope scope (self);

    _gum_v8_cloak_dispose (&self->cloak);
    _gum_v8_stalker_dispose (&self->stalker);
    _gum_v8_code_relocator_dispose (&self->code_relocator);
    _gum_v8_code_writer_dispose (&self->code_writer);
    _gum_v8_instruction_dispose (&self->instruction);
    _gum_v8_cmodule_dispose (&self->cmodule);
    _gum_v8_symbol_dispose (&self->symbol);
    _gum_v8_api_resolver_dispose (&self->api_resolver);
    _gum_v8_interceptor_dispose (&self->interceptor);
#ifdef HAVE_SQLITE
    _gum_v8_database_dispose (&self->database);
#endif
    _gum_v8_socket_dispose (&self->socket);
    _gum_v8_stream_dispose (&self->stream);
    _gum_v8_checksum_dispose (&self->checksum);
    _gum_v8_file_dispose (&self->file);
    _gum_v8_process_dispose (&self->process);
    _gum_v8_thread_dispose (&self->thread);
    _gum_v8_module_dispose (&self->module);
    _gum_v8_memory_dispose (&self->memory);
    _gum_v8_kernel_dispose (&self->kernel);
    _gum_v8_core_dispose (&self->core);

    auto context = Local<Context>::New (self->isolate, *self->context);
    self->inspector->contextDestroyed (context);
    g_signal_emit (self, gum_v8_script_signals[CONTEXT_DESTROYED], 0, &context);
  }

  gum_es_program_free (self->program);
  self->program = NULL;
  delete self->context;
  self->context = nullptr;

  _gum_v8_cloak_finalize (&self->cloak);
  _gum_v8_stalker_finalize (&self->stalker);
  _gum_v8_code_relocator_finalize (&self->code_relocator);
  _gum_v8_code_writer_finalize (&self->code_writer);
  _gum_v8_instruction_finalize (&self->instruction);
  _gum_v8_cmodule_finalize (&self->cmodule);
  _gum_v8_symbol_finalize (&self->symbol);
  _gum_v8_api_resolver_finalize (&self->api_resolver);
  _gum_v8_interceptor_finalize (&self->interceptor);
#ifdef HAVE_SQLITE
  _gum_v8_database_finalize (&self->database);
#endif
  _gum_v8_socket_finalize (&self->socket);
  _gum_v8_stream_finalize (&self->stream);
  _gum_v8_checksum_finalize (&self->checksum);
  _gum_v8_file_finalize (&self->file);
  _gum_v8_process_finalize (&self->process);
  _gum_v8_thread_finalize (&self->thread);
  _gum_v8_module_finalize (&self->module);
  _gum_v8_memory_finalize (&self->memory);
  _gum_v8_kernel_finalize (&self->kernel);
  _gum_v8_core_finalize (&self->core);
}

static void
gum_v8_script_load (GumScript * script,
                    GCancellable * cancellable,
                    GAsyncReadyCallback callback,
                    gpointer user_data)
{
  auto self = GUM_V8_SCRIPT (script);

  auto task = gum_script_task_new ((GumScriptTaskFunc) gum_v8_script_do_load,
      self, cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self->backend));
  g_object_unref (task);
}

static void
gum_v8_script_load_finish (GumScript * script,
                           GAsyncResult * result)
{
  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_v8_script_load_sync (GumScript * script,
                         GCancellable * cancellable)
{
  auto self = GUM_V8_SCRIPT (script);

  auto task = gum_script_task_new ((GumScriptTaskFunc) gum_v8_script_do_load,
      self, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_v8_script_do_load (GumScriptTask * task,
                       GumV8Script * self,
                       gpointer task_data,
                       GCancellable * cancellable)
{
  if (self->state != GUM_SCRIPT_STATE_CREATED)
    goto invalid_operation;

  self->state = GUM_SCRIPT_STATE_LOADING;

  gum_v8_script_execute_entrypoints (self, task);

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
gum_v8_script_execute_entrypoints (GumV8Script * self,
                                   GumScriptTask * task)
{
  bool done;
  {
    ScriptScope scope (self);
    auto isolate = self->isolate;
    auto context = isolate->GetCurrentContext ();

    auto runtime = gum_v8_bundle_new (isolate, gumjs_runtime_modules);
    gum_v8_bundle_run (runtime);
    gum_v8_bundle_free (runtime);

    auto program = self->program;
    if (program->entrypoints != NULL)
    {
      auto entrypoints = program->entrypoints;

      auto pending = Array::New (isolate, entrypoints->len);
      for (guint i = 0; i != entrypoints->len; i++)
      {
        auto entrypoint = (GumESAsset *) g_ptr_array_index (entrypoints, i);
        auto module = Local<Module>::New (isolate, *entrypoint->module);
        auto promise = module->Evaluate (context);
        pending->Set (context, i, promise.ToLocalChecked ()).Check ();
      }

      auto promise_class = context->Global ()
          ->Get (context, _gum_v8_string_new_ascii (isolate, "Promise"))
          .ToLocalChecked ().As<Object> ();
      auto all_settled = promise_class
          ->Get (context, _gum_v8_string_new_ascii (isolate, "allSettled"))
          .ToLocalChecked ().As<Function> ();

      Local<Value> argv[] = { pending };
      auto load_request = all_settled
          ->Call (context, promise_class, G_N_ELEMENTS (argv), argv)
          .ToLocalChecked ().As<Promise> ();

      load_request->Then (context,
          Function::New (context, gum_v8_script_on_entrypoints_executed,
            External::New (isolate, g_object_ref (task)), 1,
            ConstructorBehavior::kThrow)
          .ToLocalChecked ())
          .ToLocalChecked ();

      done = false;
    }
    else
    {
      auto code = Local<Script>::New (isolate, *program->global_code);
      auto result = code->Run (context);
      _gum_v8_ignore_result (result);

      done = true;
    }
  }

  if (done)
  {
    self->state = GUM_SCRIPT_STATE_LOADED;

    gum_script_task_return_pointer (task, NULL, NULL);
  }
}

static void
gum_v8_script_on_entrypoints_executed (const FunctionCallbackInfo<Value> & info)
{
  auto task = (GumScriptTask *) info.Data ().As<External> ()->Value ();
  auto self = (GumV8Script *)
      g_async_result_get_source_object (G_ASYNC_RESULT (task));
  auto core = &self->core;
  auto isolate = info.GetIsolate ();
  auto context = isolate->GetCurrentContext ();

  auto values = info[0].As<Array> ();
  uint32_t n = values->Length ();
  auto reason_str = _gum_v8_string_new_ascii (isolate, "reason");
  for (uint32_t i = 0; i != n; i++)
  {
    auto value = values->Get (context, i).ToLocalChecked ().As<Object> ();
    auto reason = value->Get (context, reason_str).ToLocalChecked ();
    if (!reason->IsUndefined ())
      _gum_v8_core_on_unhandled_exception (core, reason);
  }

  auto source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) gum_v8_script_complete_load_task,
      task, g_object_unref);
  g_source_attach (source,
      gum_script_scheduler_get_js_context (core->scheduler));
  g_source_unref (source);

  _gum_v8_core_pin (core);

  g_object_unref (self);
}

static gboolean
gum_v8_script_complete_load_task (GumScriptTask * task)
{
  auto self = GUM_V8_SCRIPT (
      g_async_result_get_source_object (G_ASYNC_RESULT (task)));

  {
    ScriptScope scope (self);

    _gum_v8_core_unpin (&self->core);
  }

  self->state = GUM_SCRIPT_STATE_LOADED;

  gum_script_task_return_pointer (task, NULL, NULL);

  g_object_unref (self);

  return G_SOURCE_REMOVE;
}

static void
gum_v8_script_unload (GumScript * script,
                      GCancellable * cancellable,
                      GAsyncReadyCallback callback,
                      gpointer user_data)
{
  auto self = GUM_V8_SCRIPT (script);

  auto task = gum_script_task_new ((GumScriptTaskFunc) gum_v8_script_do_unload,
      self, cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self->backend));
  g_object_unref (task);
}

static void
gum_v8_script_unload_finish (GumScript * script,
                             GAsyncResult * result)
{
  gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result), NULL);
}

static void
gum_v8_script_unload_sync (GumScript * script,
                           GCancellable * cancellable)
{
  auto self = GUM_V8_SCRIPT (script);

  auto task = gum_script_task_new ((GumScriptTaskFunc) gum_v8_script_do_unload,
      self, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self->backend));
  gum_script_task_propagate_pointer (task, NULL);
  g_object_unref (task);
}

static void
gum_v8_script_do_unload (GumScriptTask * task,
                         GumV8Script * self,
                         gpointer task_data,
                         GCancellable * cancellable)
{
  if (self->state != GUM_SCRIPT_STATE_LOADED)
    goto invalid_operation;

  self->state = GUM_SCRIPT_STATE_UNLOADING;
  gum_v8_script_once_unloaded (self,
      (GumUnloadNotifyFunc) gum_v8_script_complete_unload_task,
      g_object_ref (task), g_object_unref);

  gum_v8_script_try_unload (self);

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
gum_v8_script_complete_unload_task (GumV8Script * self,
                                    GumScriptTask * task)
{
  gum_script_task_return_pointer (task, NULL, NULL);
}

static void
gum_v8_script_try_unload (GumV8Script * self)
{
  g_assert (self->state == GUM_SCRIPT_STATE_UNLOADING);

  gboolean success;

  {
    ScriptScope scope (self);

    _gum_v8_stalker_flush (&self->stalker);
    _gum_v8_interceptor_flush (&self->interceptor);
    _gum_v8_socket_flush (&self->socket);
    _gum_v8_stream_flush (&self->stream);
    _gum_v8_process_flush (&self->process);
    success = _gum_v8_core_flush (&self->core, gum_v8_script_try_unload);
  }

  if (success)
  {
    gum_v8_script_destroy_context (self);

    self->state = GUM_SCRIPT_STATE_UNLOADED;

    while (self->on_unload != NULL)
    {
      auto link = self->on_unload;
      auto callback = (GumUnloadNotifyCallback *) link->data;

      callback->func (self, callback->data);
      if (callback->data_destroy != NULL)
        callback->data_destroy (callback->data);
      g_slice_free (GumUnloadNotifyCallback, callback);

      self->on_unload = g_slist_delete_link (self->on_unload, link);
    }
  }
}

static void
gum_v8_script_once_unloaded (GumV8Script * self,
                             GumUnloadNotifyFunc func,
                             gpointer data,
                             GDestroyNotify data_destroy)
{
  auto callback = g_slice_new (GumUnloadNotifyCallback);
  callback->func = func;
  callback->data = data;
  callback->data_destroy = data_destroy;

  self->on_unload = g_slist_append (self->on_unload, callback);
}

static void
gum_v8_script_set_message_handler (GumScript * script,
                                   GumScriptMessageHandler handler,
                                   gpointer data,
                                   GDestroyNotify data_destroy)
{
  auto self = GUM_V8_SCRIPT (script);

  if (self->message_handler_data_destroy != NULL)
    self->message_handler_data_destroy (self->message_handler_data);
  self->message_handler = handler;
  self->message_handler_data = data;
  self->message_handler_data_destroy = data_destroy;
}

static void
gum_v8_script_post (GumScript * script,
                    const gchar * message,
                    GBytes * data)
{
  auto self = GUM_V8_SCRIPT (script);

  auto d = g_slice_new (GumPostData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  gum_script_scheduler_push_job_on_js_thread (
      gum_v8_script_backend_get_scheduler (self->backend),
      G_PRIORITY_DEFAULT, (GumScriptJobFunc) gum_v8_script_do_post, d,
      (GDestroyNotify) gum_v8_post_data_free);
}

static void
gum_v8_script_do_post (GumPostData * d)
{
  GBytes * data = d->data;
  d->data = NULL;

  _gum_v8_core_post (&d->script->core, d->message, data);
}

static void
gum_v8_post_data_free (GumPostData * d)
{
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumPostData, d);
}

static void
gum_v8_script_emit (GumV8Script * self,
                    const gchar * message,
                    GBytes * data)
{
  auto d = g_slice_new (GumEmitData);
  d->script = self;
  g_object_ref (self);
  d->message = g_strdup (message);
  d->data = (data != NULL) ? g_bytes_ref (data) : NULL;

  auto source = g_idle_source_new ();
  g_source_set_callback (source, (GSourceFunc) gum_v8_script_do_emit, d,
      (GDestroyNotify) gum_v8_emit_data_free);
  g_source_attach (source, self->main_context);
  g_source_unref (source);
}

static gboolean
gum_v8_script_do_emit (GumEmitData * d)
{
  auto self = d->script;

  if (self->message_handler != NULL)
    self->message_handler (d->message, d->data, self->message_handler_data);

  return FALSE;
}

static void
gum_v8_emit_data_free (GumEmitData * d)
{
  g_bytes_unref (d->data);
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumEmitData, d);
}

static void
gum_v8_script_set_debug_message_handler (GumScript * backend,
                                         GumScriptDebugMessageHandler handler,
                                         gpointer data,
                                         GDestroyNotify data_destroy)
{
  auto self = GUM_V8_SCRIPT (backend);

  if (self->debug_handler_data_destroy != NULL)
    self->debug_handler_data_destroy (self->debug_handler_data);

  self->debug_handler = handler;
  self->debug_handler_data = data;
  self->debug_handler_data_destroy = data_destroy;

  auto new_context = (handler != NULL)
      ? g_main_context_ref_thread_default ()
      : NULL;

  GUM_V8_INSPECTOR_LOCK (self);

  auto old_context = self->debug_handler_context;
  self->debug_handler_context = new_context;

  if (handler != NULL)
  {
    if (self->inspector_state == GUM_V8_RUNNING)
      self->inspector_state = GUM_V8_DEBUGGING;
  }
  else
  {
    gum_v8_script_drop_queued_debug_messages_unlocked (self);

    self->inspector_state = GUM_V8_RUNNING;
    g_cond_signal (&self->inspector_cond);
  }

  GUM_V8_INSPECTOR_UNLOCK (self);

  if (old_context != NULL)
    g_main_context_unref (old_context);

  if (handler == NULL)
  {
    gum_script_scheduler_push_job_on_js_thread (
        gum_v8_script_backend_get_scheduler (self->backend), G_PRIORITY_DEFAULT,
        (GumScriptJobFunc) gum_v8_script_clear_inspector_channels,
        g_object_ref (self), g_object_unref);
  }
}

static void
gum_v8_script_post_debug_message (GumScript * backend,
                                  const gchar * message)
{
  auto self = GUM_V8_SCRIPT (backend);

  if (self->debug_handler == NULL)
    return;

  gchar * message_copy = g_strdup (message);

  GUM_V8_INSPECTOR_LOCK (self);

  g_queue_push_tail (&self->debug_messages, message_copy);
  g_cond_signal (&self->inspector_cond);

  bool flush_not_already_scheduled = !self->flush_scheduled;
  self->flush_scheduled = true;

  GUM_V8_INSPECTOR_UNLOCK (self);

  if (flush_not_already_scheduled)
  {
    gum_script_scheduler_push_job_on_js_thread (
        gum_v8_script_backend_get_scheduler (self->backend), G_PRIORITY_DEFAULT,
        (GumScriptJobFunc) gum_v8_script_process_queued_debug_messages,
        self, NULL);
  }
}

static void
gum_v8_script_process_queued_debug_messages (GumV8Script * self)
{
  auto isolate = self->isolate;
  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  GUM_V8_INSPECTOR_LOCK (self);
  gum_v8_script_process_queued_debug_messages_unlocked (self);
  GUM_V8_INSPECTOR_UNLOCK (self);

  isolate->PerformMicrotaskCheckpoint ();
}

static void
gum_v8_script_process_queued_debug_messages_unlocked (GumV8Script * self)
{
  gchar * message;
  while ((message = (gchar *) g_queue_pop_head (&self->debug_messages)) != NULL)
  {
    GUM_V8_INSPECTOR_UNLOCK (self);
    gum_v8_script_process_debug_message (self, message);
    GUM_V8_INSPECTOR_LOCK (self);

    g_free (message);
  }

  self->flush_scheduled = false;
}

static void
gum_v8_script_drop_queued_debug_messages_unlocked (GumV8Script * self)
{
  gchar * message;
  while ((message = (gchar *) g_queue_pop_head (&self->debug_messages)) != NULL)
    g_free (message);
}

static void
gum_v8_script_process_debug_message (GumV8Script * self,
                                     const gchar * message)
{
  guint id;
  const char * id_start, * id_end;
  id_start = strchr (message, ' ');
  if (id_start == NULL)
    return;
  id_start++;
  id = (guint) g_ascii_strtoull (id_start, (gchar **) &id_end, 10);
  if (id_end == id_start)
    return;

  if (g_str_has_prefix (message, "CONNECT "))
  {
    gum_v8_script_connect_inspector_channel (self, id);
  }
  else if (g_str_has_prefix (message, "DISCONNECT "))
  {
    gum_v8_script_disconnect_inspector_channel (self, id);
  }
  else if (g_str_has_prefix (message, "DISPATCH "))
  {
    if (*id_end != ' ')
      return;
    const char * stanza = id_end + 1;
    gum_v8_script_dispatch_inspector_stanza (self, id, stanza);
  }
}

static void
gum_v8_script_emit_debug_message (GumV8Script * self,
                                  const gchar * format,
                                  ...)
{
  GUM_V8_INSPECTOR_LOCK (self);
  auto context = (self->debug_handler_context != NULL)
      ? g_main_context_ref (self->debug_handler_context)
      : NULL;
  GUM_V8_INSPECTOR_UNLOCK (self);

  if (context == NULL)
    return;

  auto d = g_slice_new (GumEmitDebugMessageData);

  d->script = self;
  g_object_ref (self);

  va_list args;
  va_start (args, format);
  d->message = g_strdup_vprintf (format, args);
  va_end (args);

  auto source = g_idle_source_new ();
  g_source_set_callback (source,
      (GSourceFunc) gum_v8_script_do_emit_debug_message, d,
      (GDestroyNotify) gum_emit_debug_message_data_free);
  g_source_attach (source, context);
  g_source_unref (source);

  g_main_context_unref (context);
}

static gboolean
gum_v8_script_do_emit_debug_message (GumEmitDebugMessageData * d)
{
  auto self = d->script;

  if (self->debug_handler != NULL)
    self->debug_handler (d->message, self->debug_handler_data);

  return FALSE;
}

static void
gum_emit_debug_message_data_free (GumEmitDebugMessageData * d)
{
  g_free (d->message);
  g_object_unref (d->script);

  g_slice_free (GumEmitDebugMessageData, d);
}

static void
gum_v8_script_clear_inspector_channels (GumV8Script * self)
{
  auto isolate = self->isolate;
  Locker locker (isolate);
  Isolate::Scope isolate_scope (isolate);
  HandleScope handle_scope (isolate);

  GUM_V8_INSPECTOR_LOCK (self);
  bool debugger_still_disabled = (self->inspector_state == GUM_V8_RUNNING);
  GUM_V8_INSPECTOR_UNLOCK (self);

  if (debugger_still_disabled)
    self->channels->clear ();
}

static void
gum_v8_script_connect_inspector_channel (GumV8Script * self,
                                         guint id)
{
  auto channel = new GumInspectorChannel (self, id);
  (*self->channels)[id] = std::unique_ptr<GumInspectorChannel> (channel);

  auto session = self->inspector->connect (self->context_group_id, channel,
      StringView (), V8Inspector::ClientTrustLevel::kFullyTrusted);
  channel->takeSession (std::move (session));
}

static void
gum_v8_script_disconnect_inspector_channel (GumV8Script * self,
                                            guint id)
{
  self->channels->erase (id);
}

static void
gum_v8_script_dispatch_inspector_stanza (GumV8Script * self,
                                         guint channel_id,
                                         const gchar * stanza)
{
  auto channel = (*self->channels)[channel_id].get ();
  if (channel == nullptr)
    return;

  channel->dispatchStanza (stanza);
}

static void
gum_v8_script_emit_inspector_stanza (GumV8Script * self,
                                     guint channel_id,
                                     const gchar * stanza)
{
  gum_v8_script_emit_debug_message (self, "DISPATCH %u %s",
      channel_id, stanza);
}

GumInspectorClient::GumInspectorClient (GumV8Script * script)
  : script (script)
{
}

void
GumInspectorClient::runMessageLoopOnPause (int context_group_id)
{
  GUM_V8_INSPECTOR_LOCK (script);

  if (script->inspector_state == GUM_V8_RUNNING)
  {
    startSkippingAllPauses ();
    GUM_V8_INSPECTOR_UNLOCK (script);
    return;
  }

  script->inspector_state = GUM_V8_PAUSED;
  while (script->inspector_state == GUM_V8_PAUSED)
  {
    gum_v8_script_process_queued_debug_messages_unlocked (script);

    if (script->inspector_state == GUM_V8_PAUSED)
      g_cond_wait (&script->inspector_cond, &script->inspector_mutex);
  }

  gum_v8_script_process_queued_debug_messages_unlocked (script);

  if (script->inspector_state == GUM_V8_RUNNING)
  {
    startSkippingAllPauses ();
  }

  GUM_V8_INSPECTOR_UNLOCK (script);
}

void
GumInspectorClient::quitMessageLoopOnPause ()
{
  GUM_V8_INSPECTOR_LOCK (script);

  if (script->inspector_state == GUM_V8_PAUSED)
  {
    script->inspector_state = GUM_V8_DEBUGGING;
    g_cond_signal (&script->inspector_cond);
  }

  GUM_V8_INSPECTOR_UNLOCK (script);
}

Local<Context>
GumInspectorClient::ensureDefaultContextInGroup (int contextGroupId)
{
  return Local<Context>::New (script->isolate, *script->context);
}

double
GumInspectorClient::currentTimeMS ()
{
  auto platform =
      (GumV8Platform *) gum_v8_script_backend_get_platform (script->backend);

  return platform->CurrentClockTimeMillis ();
}

void
GumInspectorClient::startSkippingAllPauses ()
{
  for (const auto & pair : *script->channels)
  {
    pair.second->startSkippingAllPauses ();
  }
}

GumInspectorChannel::GumInspectorChannel (GumV8Script * script,
                                          guint id)
  : script (script),
    id (id)
{
}

void
GumInspectorChannel::takeSession (std::unique_ptr<V8InspectorSession> session)
{
  inspector_session = std::move (session);
}

void
GumInspectorChannel::dispatchStanza (const char * stanza)
{
  auto buffer = gum_string_buffer_from_utf8 (stanza);

  inspector_session->dispatchProtocolMessage (buffer->string ());
}

void
GumInspectorChannel::startSkippingAllPauses ()
{
  inspector_session->setSkipAllPauses (true);
}

void
GumInspectorChannel::emitStanza (std::unique_ptr<StringBuffer> stanza)
{
  gchar * stanza_utf8 = gum_string_view_to_utf8 (stanza->string ());

  gum_v8_script_emit_inspector_stanza (script, id, stanza_utf8);

  g_free (stanza_utf8);
}

void
GumInspectorChannel::sendResponse (int call_id,
                                   std::unique_ptr<StringBuffer> message)
{
  emitStanza (std::move (message));
}

void
GumInspectorChannel::sendNotification (std::unique_ptr<StringBuffer> message)
{
  emitStanza (std::move (message));
}

void
GumInspectorChannel::flushProtocolNotifications ()
{
}

static GumStalker *
gum_v8_script_get_stalker (GumScript * script)
{
  auto self = GUM_V8_SCRIPT (script);

  return _gum_v8_stalker_get (&self->stalker);
}

static void
gum_v8_script_on_fatal_error (const char * location,
                              const char * message)
{
  g_log ("V8", G_LOG_LEVEL_ERROR, "%s: %s", location, message);
}

static GumESProgram *
gum_es_program_new (void)
{
  auto program = g_slice_new0 (GumESProgram);

  program->es_assets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      (GDestroyNotify) gum_es_asset_unref);
  program->es_modules = g_hash_table_new (NULL, NULL);

  return program;
}

static void
gum_es_program_free (GumESProgram * program)
{
  if (program == NULL)
    return;

  delete program->global_code;
  g_free (program->global_filename);

  g_clear_pointer (&program->es_modules, g_hash_table_unref);
  g_clear_pointer (&program->es_assets, g_hash_table_unref);
  g_clear_pointer (&program->entrypoints, g_ptr_array_unref);

  g_slice_free (GumESProgram, program);
}

static GumESAsset *
gum_es_asset_new_take (const gchar * name,
                       gpointer data,
                       gsize data_size)
{
  auto asset = g_slice_new (GumESAsset);

  asset->ref_count = 1;

  asset->name = name;

  asset->data = data;
  asset->data_size = data_size;

  asset->module = nullptr;

  return asset;
}

static GumESAsset *
gum_es_asset_ref (GumESAsset * asset)
{
  g_atomic_int_inc (&asset->ref_count);

  return asset;
}

static void
gum_es_asset_unref (GumESAsset * asset)
{
  if (asset == NULL)
    return;

  if (!g_atomic_int_dec_and_test (&asset->ref_count))
    return;

  delete asset->module;
  g_free (asset->data);

  g_slice_free (GumESAsset, asset);
}

static std::unique_ptr<StringBuffer>
gum_string_buffer_from_utf8 (const gchar * str)
{
  glong length;
  auto str_utf16 = g_utf8_to_utf16 (str, -1, NULL, &length, NULL);
  g_assert (str_utf16 != NULL);

  auto buffer = StringBuffer::create (StringView (str_utf16, length));

  g_free (str_utf16);

  return buffer;
}

static gchar *
gum_string_view_to_utf8 (const StringView & view)
{
  if (view.is8Bit ())
    return g_strndup ((const gchar *) view.characters8 (), view.length ());

  return g_utf16_to_utf8 (view.characters16 (), (glong) view.length (), NULL,
      NULL, NULL);
}

"""


```