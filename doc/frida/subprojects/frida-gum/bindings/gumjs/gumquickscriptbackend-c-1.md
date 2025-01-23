Response:
Let's break down the thought process for analyzing this C code snippet.

1. **Understand the Goal:** The primary goal is to understand the functionality of `gumquickscriptbackend.c` within the Frida framework, specifically as the second part of a larger file. The request asks for various aspects: core functionality, relation to reverse engineering, interaction with OS/kernel elements, logic, potential user errors, and how users might reach this code.

2. **Identify the Core Component:** The file name itself, `gumquickscriptbackend.c`, strongly suggests this code implements a backend for executing JavaScript (or a similar scripting language) within Frida, likely using the QuickJS engine. The "gum" prefix is common in Frida and hints at its internal nature.

3. **Analyze Data Structures:**  Start by looking at the `typedef` and `struct` definitions. This provides a high-level understanding of the data the code manipulates:
    * `GumQuickScriptBackend`:  Likely the main structure for this backend, containing a mutex (`scope_mutex`) for thread safety, a flag for tracking mutex status (`scope_mutex_trapped`), and a reference to the QuickJS runtime (`rt`).
    * `GumScriptTask`: Represents an asynchronous task for script execution.
    * `GumCompileScriptData`, `GumRunScriptData`, `GumSnapshotScriptData`: Structures holding data specific to different types of script operations (compilation, execution, snapshotting). Note that `GumSnapshotScriptData`'s functionality is explicitly marked as unsupported.
    * `GumESProgram`:  Seems to represent a compiled ECMAScript (JavaScript) program, holding entry points and assets.
    * `GumESAsset`: Represents a script file or module, containing its name and content.

4. **Analyze Function Signatures and Implementations:**  Go through the functions, grouping them by their purpose:
    * **Backend Creation and Destruction:** `gum_quick_script_backend_new`, `gum_quick_script_backend_finalize`, `gum_quick_script_backend_dispose`. These are standard object lifecycle functions. The use of `g_object_new` and `GObjectClass` indicates integration with GLib's object system.
    * **Script Execution:** `gum_compile_script_task_new`, `gum_compile_script_task_run`, `gum_run_script_task_new`, `gum_run_script_task_run`. These functions likely handle the asynchronous compilation and execution of scripts. Notice the use of `GumScriptTask` which suggests a standardized way of managing script operations.
    * **Snapshotting (Unsupported):** `gum_snapshot_script_task_new`, `gum_snapshot_script_task_run`. The code explicitly states "not supported by the QuickJS runtime," which is crucial information.
    * **Locking:** `gum_quick_script_backend_with_lock_held`, `gum_quick_script_backend_is_locked`, `gum_quick_script_backend_is_scope_mutex_trapped`, `gum_quick_script_backend_mark_scope_mutex_trapped`. These functions manage a mutex to ensure thread-safe access to the QuickJS runtime. The "trapped" concept might relate to specific error handling or debugging scenarios.
    * **Module Management:** `gum_es_program_new`, `gum_es_program_free`, `gum_es_program_is_esm`, `gum_es_program_compile_worker`, `gum_es_program_normalize_module_name`. These functions deal with compiling and managing JavaScript modules. The module loading functions (`gum_normalize_module_name_during_runtime`, `gum_load_module_during_runtime`) are important for understanding how Frida handles script imports.
    * **Asset Management:** `gum_es_asset_new_take`, `gum_es_asset_ref`, `gum_es_asset_unref`. These are standard reference counting functions for managing script content.
    * **Error Handling:** `gum_capture_parse_error`. This function handles errors that occur during the parsing of JavaScript code.
    * **Memory Allocation (Conditional):** `gum_quick_malloc`, `gum_quick_free`, `gum_quick_realloc`, `gum_quick_malloc_usable_size`. These functions appear to be custom memory allocation wrappers, possibly used when ASan (AddressSanitizer) is not enabled.

5. **Connect to Request Requirements:** Now, explicitly address each point in the request:
    * **Functionality:** Summarize the identified function groups (script execution, module management, locking, etc.).
    * **Reverse Engineering:** Think about how Frida is used in reverse engineering. The ability to execute arbitrary JavaScript code within a target process is key. Highlight how this backend enables that. Give concrete examples of hooking functions, inspecting memory, etc.
    * **Binary/OS/Kernel/Framework:**  Consider the underlying technologies involved. QuickJS is a C engine. Frida interacts with the target process's memory and execution flow. Mention concepts like address spaces, system calls, and how Frida injects its agent. Android's framework (like ART for the runtime) is relevant if the target is an Android application.
    * **Logic/Input/Output:** Focus on specific functions with clear logic. `gum_es_program_normalize_module_name` is a good example of string manipulation based on module paths. Create a simple example to illustrate its behavior.
    * **User Errors:** Think about common mistakes developers make when using Frida. Incorrect script syntax, attempting unsupported operations (like snapshotting with QuickJS), or issues with module paths are all potential errors.
    * **User Operation to Reach Code:** Describe the typical Frida workflow: attaching to a process, loading a script, and the script then being processed by this backend. Debugging scenarios where a user might step into this code are also relevant.
    * **Summary of Functionality (Part 2):**  Specifically focus on the functionality present *within this specific code snippet*. It's about the QuickJS integration, not the entire Frida ecosystem.

6. **Refine and Organize:** Structure the answer logically with clear headings and bullet points. Use precise language and avoid jargon where possible, or explain it when necessary. Ensure the examples are easy to understand.

7. **Self-Correction/Review:**  Read through the answer. Does it accurately reflect the code? Are the explanations clear and concise? Have all parts of the request been addressed?  For instance, initially, I might have overlooked the conditional memory allocation based on `HAVE_ASAN`. Reviewing the code would catch this. Also, ensuring the examples are practical and directly related to the code is important.

By following these steps, one can systematically analyze the code and generate a comprehensive and accurate response to the given prompt. The key is to break down the problem, analyze the code in manageable chunks, and then synthesize the findings in a structured and informative way.
这是提供的 `frida/subprojects/frida-gum/bindings/gumjs/gumquickscriptbackend.c` 文件的第二部分源代码。结合第一部分，我们可以归纳一下这个文件的整体功能，以及这部分代码的具体作用：

**整体功能归纳（结合第一部分）：**

`gumquickscriptbackend.c` 文件实现了 Frida 中一个使用 QuickJS JavaScript 引擎作为后端的脚本执行环境。它的主要职责是：

1. **初始化和管理 QuickJS 运行时环境:**  创建、配置和销毁 QuickJS 的运行时 (Runtime) 和上下文 (Context)。
2. **加载和编译 JavaScript 代码:**  接收用户提供的 JavaScript 代码（包括模块化的 ES 模块），并使用 QuickJS 引擎进行编译。
3. **执行 JavaScript 代码:** 在目标进程中执行已编译的 JavaScript 代码，并提供与 Frida Gum 框架交互的能力。
4. **处理 JavaScript 异常:** 捕获和报告在 JavaScript 执行过程中发生的错误。
5. **提供异步脚本执行机制:**  通过 `GumScriptTask` 管理异步的脚本编译和执行任务。
6. **处理模块化 JavaScript (ES Modules):**  支持 ES 模块的加载、解析和执行，包括路径解析和模块缓存。
7. **内存管理:**  使用 Frida 的内存管理机制（在没有 ASan 的情况下）或系统默认的内存管理。
8. **线程安全:** 使用互斥锁 (`scope_mutex`) 保护对 QuickJS 上下文的并发访问。
9. **快照功能（但目前不支持）：** 定义了快照相关的结构和任务，但明确指出 QuickJS 运行时不支持此功能。

**第二部分的功能归纳：**

这部分代码主要负责以下功能：

1. **定义和管理快照脚本任务:** 
   - 定义了 `GumSnapshotScriptData` 结构体来存储快照脚本的相关数据（嵌入脚本和预热脚本）。
   - 提供了创建快照脚本任务的函数 `gum_snapshot_script_task_new`。
   - 实现了快照脚本任务的执行函数 `gum_snapshot_script_task_run`，但此函数中直接返回一个 "不支持" 的错误，说明 QuickJS 后端目前不实现快照功能。
   - 提供了释放快照脚本数据的函数 `gum_snapshot_script_data_free`。

2. **管理 QuickJS 上下文的互斥锁:**
   - 提供了 `gum_quick_script_backend_with_lock_held` 函数，用于在持有互斥锁的情况下执行一个函数，确保对 QuickJS 上下文的线程安全访问。
   - 提供了 `gum_quick_script_backend_is_locked` 函数，用于检查互斥锁是否被持有。
   - 提供了 `gum_quick_script_backend_is_scope_mutex_trapped` 和 `gum_quick_script_backend_mark_scope_mutex_trapped` 函数，用于处理特定情况下互斥锁被“捕获”的状态，这可能与错误处理或调试有关。

3. **管理 ECMAScript 程序 (GumESProgram):**
   - 提供了 `gum_es_program_new` 函数，用于创建 `GumESProgram` 结构体，其中包含入口点数组和模块资产哈希表。
   - 提供了 `gum_es_program_free` 函数，用于释放 `GumESProgram` 结构体及其包含的资源。
   - 提供了 `gum_es_program_is_esm` 函数，用于判断程序是否为 ES 模块。
   - 提供了 `gum_es_program_compile_worker` 函数，用于在工作线程中编译 ES 模块。
   - 提供了 `gum_es_program_normalize_module_name` 函数，用于在运行时规范化模块名称，模拟 QuickJS 的模块解析行为。

4. **管理 ES 模块资产 (GumESAsset):**
   - 提供了 `gum_es_asset_new_take` 函数，用于创建并拥有一个模块资产。
   - 提供了 `gum_es_asset_ref` 和 `gum_es_asset_unref` 函数，用于管理模块资产的引用计数。

5. **捕获 JavaScript 解析错误:**
   - 提供了 `gum_capture_parse_error` 函数，用于从 QuickJS 上下文中获取异常信息（消息和行号），并创建一个 `GError` 对象来表示解析错误。

6. **自定义内存管理 (非 ASan 构建):**
   - 在没有 AddressSanitizer (ASan) 的构建中，提供了包装 Frida 内存分配函数的接口：`gum_quick_malloc`, `gum_quick_free`, `gum_quick_realloc`, `gum_quick_malloc_usable_size`。这允许 Frida 控制 QuickJS 的内存分配行为。

**与逆向方法的关联及举例说明：**

这部分代码直接支持了 Frida 的核心逆向功能，即在目标进程中执行用户自定义的 JavaScript 代码。

* **动态代码注入和执行:**  通过编译和执行 JavaScript 代码，逆向工程师可以动态地修改目标进程的行为，例如：
    * **Hook 函数:** 使用 Frida 的 `Interceptor` API 在 JavaScript 中拦截目标进程的函数调用，并修改参数、返回值或执行额外的逻辑。例如，可以 hook `open` 系统调用来监控文件访问，或者 hook 特定应用的 API 来分析其行为。
    * **内存读写:** 使用 Frida 的 `Memory` API 在 JavaScript 中读写目标进程的内存，从而检查变量的值、修改数据结构等。例如，可以读取游戏中的金币数量，或者修改网络请求的参数。
    * **调用目标进程函数:** 使用 Frida 的 `NativeFunction` API 在 JavaScript 中调用目标进程中的原生函数。例如，可以调用加密算法的实现来获取密钥。

* **模块化脚本支持:**  对 ES 模块的支持使得逆向脚本可以更好地组织和复用，方便编写复杂的逆向分析工具。可以将不同的 hook 或分析逻辑放在不同的模块中进行管理。

**涉及到的二进制底层、Linux、Android 内核及框架的知识及举例说明：**

* **二进制底层:**
    * **内存地址:**  Frida 需要知道目标进程中函数的内存地址才能进行 hook。这部分代码处理的 JavaScript 最终会通过 Frida Gum 框架与这些内存地址进行交互。
    * **函数调用约定:**  在进行函数 hook 和调用时，需要理解目标平台的函数调用约定（例如，参数如何传递，返回值如何获取）。虽然这部分代码本身不直接处理调用约定，但其执行的 JavaScript 代码会依赖 Frida Gum 框架来处理这些细节。

* **Linux/Android:**
    * **进程和内存管理:** Frida 需要与目标进程进行交互，涉及到进程创建、内存映射等操作系统概念。这部分代码执行的 JavaScript 运行在目标进程的上下文中。
    * **系统调用:**  逆向分析经常涉及到监控系统调用，例如 `open`, `read`, `write`, `connect` 等。通过 Frida 执行的 JavaScript 可以 hook 这些系统调用。
    * **动态链接:**  目标进程通常会加载动态链接库。Frida 需要解析这些库的符号表来找到要 hook 的函数。

* **Android 内核及框架:**
    * **ART (Android Runtime):**  对于 Android 应用，Frida 需要与 ART 虚拟机进行交互来 hook Java 方法或 Native 代码。
    * **Binder 机制:** Android 应用的组件之间经常通过 Binder IPC 机制进行通信。Frida 可以 hook Binder 调用来分析应用的行为。

**逻辑推理、假设输入与输出的举例说明：**

`gum_es_program_normalize_module_name` 函数进行模块路径的规范化，它模拟了 QuickJS 的模块解析逻辑。

**假设输入:**

* `base_name`: "/path/to/module/main.js"
* `name`: "./utils.js"

**输出:**

* "/path/to/module/utils.js"

**假设输入:**

* `base_name`: "/path/to/module/main.js"
* `name`: "../common/shared.js"

**输出:**

* "/path/common/shared.js"

**假设输入 (模块名非相对路径):**

* `base_name`: "/path/to/module/main.js"
* `name`: "some-library"

**输出:**

* "some-library" (假设 "some-library" 在 `es_assets` 中存在，否则会返回相同的字符串)

**涉及用户或编程常见的使用错误及举例说明：**

* **在 QuickJS 后端中使用不支持的快照功能:** 用户可能会尝试调用 Frida 的快照相关 API，但由于 `gum_snapshot_script_task_run` 明确返回错误，会导致脚本执行失败。
    ```javascript
    // 假设 Frida 提供了一个 global.snapshot() 函数
    // 在使用 QuickJS 后端的 Frida 环境中执行以下代码会报错
    snapshot();
    ```
* **模块路径解析错误:**  如果用户在 JavaScript 代码中使用了错误的模块路径，`gum_es_program_normalize_module_name` 可能会解析出错误的路径，导致模块加载失败。
    ```javascript
    // main.js
    import Utils from './wrong_path/utils.js'; // 路径不正确

    // 或者

    import Utils from '../common/missing.js'; // 模块不存在
    ```
* **尝试在未持有锁的情况下访问 QuickJS 上下文:**  虽然用户通常不会直接操作锁，但在编写异步 Frida 脚本时，如果错误地使用了并发操作，可能会导致访问冲突。Frida 内部会使用 `gum_quick_script_backend_with_lock_held` 等函数来避免这种情况，但错误的脚本逻辑仍然可能引发问题。

**用户操作是如何一步步的到达这里，作为调试线索：**

1. **用户编写 Frida 脚本:** 用户创建一个 JavaScript 文件，使用 Frida 的 API (例如 `Interceptor.attach`, `Memory.read*`) 来实现逆向分析逻辑。
2. **用户运行 Frida 命令或使用 Frida 客户端:**  用户使用 `frida` 命令行工具或 Frida 的 Python/Node.js 客户端连接到目标进程，并加载他们编写的 JavaScript 脚本。
3. **Frida 加载脚本并选择 QuickJS 后端:**  Frida 核心会根据配置或默认设置选择 `gumquickscriptbackend` 作为 JavaScript 的执行后端。
4. **脚本编译和执行:**
   - 当 Frida 需要编译 JavaScript 代码时，会调用 `gum_compile_script_task_new` 和 `gum_compile_script_task_run` (在第一部分中)。
   - 如果脚本包含 ES 模块，会涉及到 `gum_es_program_compile_worker` 和 `gum_es_program_normalize_module_name` 来加载和解析模块。
   - 最终，JavaScript 代码会在 QuickJS 上下文中执行。
5. **遇到错误或需要调试:**
   - 如果 JavaScript 代码中存在语法错误或运行时错误，`gum_capture_parse_error` 会被调用来捕获错误信息。
   - 如果用户尝试使用不支持的快照功能，`gum_snapshot_script_task_run` 会返回错误。
   - 在多线程环境下，Frida 内部会使用 `gum_quick_script_backend_with_lock_held` 来确保对 QuickJS 上下文的线程安全访问。

**调试线索:**  当用户报告 Frida 脚本执行错误，尤其是与模块加载、快照功能或并发访问相关的问题时，开发人员可能会查看 `gumquickscriptbackend.c` 的代码来分析问题原因。例如：

* 如果出现 "not supported by the QuickJS runtime" 的错误，可以追溯到 `gum_snapshot_script_task_run` 函数。
* 如果模块加载失败，可以检查 `gum_es_program_normalize_module_name` 的逻辑是否正确处理了模块路径。
* 如果在多线程环境下出现崩溃或数据竞争，可能需要检查互斥锁的使用情况，例如 `gum_quick_script_backend_with_lock_held` 是否被正确调用。

总而言之，`gumquickscriptbackend.c` (的第二部分) 深入负责 Frida 中使用 QuickJS 执行 JavaScript 脚本的细节，包括模块管理、线程安全、以及对特定功能（如快照）的支持（或不支持）。理解这部分代码对于调试 Frida 脚本执行过程中的问题至关重要。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumquickscriptbackend.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```c
task, error);
  g_object_unref (task);

  return bytes;
}

static GumScriptTask *
gum_snapshot_script_task_new (GumQuickScriptBackend * backend,
                              const gchar * embed_script,
                              const gchar * warmup_script,
                              GCancellable * cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
  GumScriptTask * task;
  GumSnapshotScriptData * d;

  d = g_slice_new (GumSnapshotScriptData);
  d->embed_script = g_strdup (embed_script);
  d->warmup_script = g_strdup (warmup_script);

  task = gum_script_task_new ((GumScriptTaskFunc) gum_snapshot_script_task_run,
      backend, cancellable, callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_snapshot_script_data_free);

  return task;
}

static void
gum_snapshot_script_task_run (GumScriptTask * task,
                              GumQuickScriptBackend * self,
                              GumSnapshotScriptData * d,
                              GCancellable * cancellable)
{
  gum_script_task_return_error (task,
      g_error_new (GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
        "not supported by the QuickJS runtime"));
}

static void
gum_snapshot_script_data_free (GumSnapshotScriptData * d)
{
  g_free (d->embed_script);
  g_free (d->warmup_script);

  g_slice_free (GumSnapshotScriptData, d);
}

static void
gum_quick_script_backend_with_lock_held (GumScriptBackend * backend,
                                         GumScriptBackendLockedFunc func,
                                         gpointer user_data)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (backend);

  if (self->scope_mutex_trapped)
  {
    func (user_data);
    return;
  }

  g_rec_mutex_lock (&self->scope_mutex);
  func (user_data);
  g_rec_mutex_unlock (&self->scope_mutex);
}

static gboolean
gum_quick_script_backend_is_locked (GumScriptBackend * backend)
{
  GumQuickScriptBackend * self = GUM_QUICK_SCRIPT_BACKEND (backend);

  if (self->scope_mutex_trapped)
    return FALSE;

  if (!g_rec_mutex_trylock (&self->scope_mutex))
    return TRUE;

  g_rec_mutex_unlock (&self->scope_mutex);

  return FALSE;
}

gboolean
gum_quick_script_backend_is_scope_mutex_trapped (GumQuickScriptBackend * self)
{
  return self->scope_mutex_trapped;
}

void
gum_quick_script_backend_mark_scope_mutex_trapped (GumQuickScriptBackend * self)
{
  self->scope_mutex_trapped = TRUE;
}

static GumESProgram *
gum_es_program_new (void)
{
  GumESProgram * program;

  program = g_slice_new0 (GumESProgram);
  program->entrypoints = g_array_new (FALSE, FALSE, sizeof (JSValue));
  program->es_assets = g_hash_table_new_full (g_str_hash, g_str_equal, g_free,
      (GDestroyNotify) gum_es_asset_unref);

  return program;
}

void
gum_es_program_free (GumESProgram * program,
                     JSContext * ctx)
{
  GArray * entrypoints;
  guint i;

  if (program == NULL)
    return;

  g_free (program->global_source_map);
  g_free (program->global_filename);

  g_clear_pointer (&program->es_assets, g_hash_table_unref);

  entrypoints = program->entrypoints;
  for (i = 0; i != entrypoints->len; i++)
    JS_FreeValue (ctx, g_array_index (entrypoints, JSValue, i));
  g_array_free (entrypoints, TRUE);

  g_slice_free (GumESProgram, program);
}

gboolean
gum_es_program_is_esm (GumESProgram * self)
{
  return self->global_filename == NULL;
}

JSValue
gum_es_program_compile_worker (GumESProgram * self,
                               JSContext * ctx,
                               const GumESAsset * asset)
{
  JS_SetModuleLoaderFunc (JS_GetRuntime (ctx),
      gum_normalize_module_name_during_runtime,
      gum_load_module_during_runtime,
      self);

  return gum_compile_module (ctx, asset);
}

static char *
gum_es_program_normalize_module_name (GumESProgram * self,
                                      JSContext * ctx,
                                      const char * base_name,
                                      const char * name)
{
  char * result;
  const char * base_dir_end;
  guint base_dir_length;
  const char * cursor;

  if (name[0] != '.')
  {
    GumESAsset * asset;

    asset = g_hash_table_lookup (self->es_assets, name);
    if (asset != NULL)
      return js_strdup (ctx, asset->name);

    return js_strdup (ctx, name);
  }

  /* The following mimics QuickJS' default implementation: */

  base_dir_end = strrchr (base_name, '/');
  if (base_dir_end != NULL)
    base_dir_length = base_dir_end - base_name;
  else
    base_dir_length = 0;

  result = js_malloc (ctx, base_dir_length + 1 + strlen (name) + 1);
  memcpy (result, base_name, base_dir_length);
  result[base_dir_length] = '\0';

  cursor = name;
  while (TRUE)
  {
    if (g_str_has_prefix (cursor, "./"))
    {
      cursor += 2;
    }
    else if (g_str_has_prefix (cursor, "../"))
    {
      char * new_end;

      if (result[0] == '\0')
        break;

      new_end = strrchr (result, '/');
      if (new_end != NULL)
        new_end++;
      else
        new_end = result;

      if (strcmp (new_end, ".") == 0 || strcmp (new_end, "..") == 0)
        break;

      if (new_end > result)
        new_end--;

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

GumESAsset *
gum_es_asset_new_take (const gchar * name,
                       gpointer data,
                       gsize data_size)
{
  GumESAsset * asset;

  asset = g_slice_new (GumESAsset);

  asset->ref_count = 1;

  asset->name = name;

  asset->data = data;
  asset->data_size = data_size;

  return asset;
}

GumESAsset *
gum_es_asset_ref (GumESAsset * asset)
{
  g_atomic_int_inc (&asset->ref_count);

  return asset;
}

void
gum_es_asset_unref (GumESAsset * asset)
{
  if (asset == NULL)
    return;

  if (!g_atomic_int_dec_and_test (&asset->ref_count))
    return;

  g_free (asset->data);

  g_slice_free (GumESAsset, asset);
}

static GError *
gum_capture_parse_error (JSContext * ctx,
                         const gchar * filename)
{
  GError * error;
  JSValue exception_val, message_val, line_val;
  const char * message;
  uint32_t line;

  exception_val = JS_GetException (ctx);
  message_val = JS_GetPropertyStr (ctx, exception_val, "message");
  line_val = JS_GetPropertyStr (ctx, exception_val, "lineNumber");

  message = JS_ToCString (ctx, message_val);
  JS_ToUint32 (ctx, &line, line_val);

  error = g_error_new (
      GUM_ERROR,
      GUM_ERROR_FAILED,
      "Could not parse '%s' line %u: %s",
      filename,
      line,
      message);

  JS_FreeCString (ctx, message);
  JS_FreeValue (ctx, line_val);
  JS_FreeValue (ctx, message_val);

  JS_Throw (ctx, exception_val);

  return error;
}

#ifndef HAVE_ASAN

static void *
gum_quick_malloc (JSMallocState * state,
                  size_t size)
{
  return gum_malloc (size);
}

static void
gum_quick_free (JSMallocState * state,
                void * ptr)
{
  gum_free (ptr);
}

static void *
gum_quick_realloc (JSMallocState * state,
                   void * ptr,
                   size_t size)
{
  return gum_realloc (ptr, size);
}

static size_t
gum_quick_malloc_usable_size (const void * ptr)
{
  return gum_malloc_usable_size (ptr);
}

#endif
```