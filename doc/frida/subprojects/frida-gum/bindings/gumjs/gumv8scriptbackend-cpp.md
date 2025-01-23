Response:
Let's break down the thought process to analyze the C++ code and answer the user's request.

**1. Understanding the Goal:**

The user wants to understand the functionality of the `gumv8scriptbackend.cpp` file within the Frida dynamic instrumentation tool. They're specifically interested in its relationship to reverse engineering, low-level concepts, logical reasoning, common usage errors, and how a user might reach this code.

**2. Initial Code Scan and Keyword Identification:**

My first step is to quickly scan the code for keywords and patterns that indicate the file's purpose. I see:

* **`GumV8ScriptBackend`**: This immediately tells me it's related to running JavaScript (V8) within Frida. "Backend" suggests it handles the underlying implementation.
* **`GumScriptBackend`**:  The inheritance relationship (`G_IMPLEMENT_INTERFACE`) indicates this is an implementation of a more general script backend interface.
* **`v8::Isolate`, `v8::Context`, `v8::Script`, `v8::SnapshotCreator`**: These are core V8 JavaScript engine classes, confirming the V8 integration.
* **`gum/guminterceptor.h`**: This header relates to Frida's core functionality of intercepting function calls.
* **`GMutex`, `GHashTable`**: These are GLib primitives for thread safety and managing collections, indicating the backend needs to be thread-safe.
* **`create`, `compile`, `snapshot`**: These function names suggest the backend can create, compile, and generate snapshots of JavaScript code.
* **`async`, `sync` function pairs**:  This suggests asynchronous and synchronous ways of interacting with the backend.
* **`GBytes`**: This GLib type is used for managing byte arrays, suggesting interaction with compiled code or snapshots.
* **Platform-specific flags (`HAVE_DARWIN`, `HAVE_ARM`, etc.)**: This indicates platform-aware behavior, likely for security or performance reasons.
* **`FRIDA_V8_EXTRA_FLAGS`**:  Environment variable usage hints at configurability.

**3. Deconstructing Functionality:**

Now, I go through the major functions and data structures, trying to understand their purpose:

* **`GumV8ScriptBackend` struct**:  Holds the core state: a mutex for thread safety, a hash table of active scripts, and a pointer to the V8 platform.
* **`GumCreateScriptData`, `GumCreateScriptFromBytesData`, `GumCompileScriptData`, `GumSnapshotScriptData`**: These structs seem to hold the parameters for different operations. The names are self-explanatory.
* **`gum_v8_script_backend_create` family**: Handles creating JavaScript scripts from source code, potentially using a snapshot for faster startup. The asynchronous and synchronous versions are present.
* **`gum_v8_script_backend_create_from_bytes` family**:  Handles creating scripts from pre-compiled bytecode. However, the implementation notes that it's *not supported* by V8. This is a crucial detail.
* **`gum_v8_script_backend_compile` family**: Intended for compiling JavaScript to bytecode, but again, notes that it's *not supported* by V8.
* **`gum_v8_script_backend_snapshot` family**:  Handles creating V8 snapshots. This involves running embedded and warmup scripts to pre-initialize the JavaScript environment.
* **`gum_create_snapshot` and `gum_warm_up_snapshot`**:  These functions implement the core snapshot creation logic using V8's `SnapshotCreator`.
* **`gum_run_code`**:  A helper function to run JavaScript code within a V8 context and handle potential errors.
* **`gum_v8_script_backend_with_lock_held`**:  A function to execute a callback while holding a lock, ensuring thread safety when interacting with V8. This is important because V8 has thread affinity.
* **`gum_v8_script_backend_is_locked`**: Checks if any V8 isolates are currently locked.
* **`gum_v8_script_backend_on_context_created` and `gum_v8_script_backend_on_context_destroyed`**:  Manage the `live_scripts` hash table, tracking active JavaScript contexts.

**4. Connecting to Reverse Engineering:**

With the functionality understood, I consider how it relates to reverse engineering:

* **Dynamic Instrumentation:** The entire purpose of Frida is dynamic instrumentation. This backend provides the ability to inject and execute JavaScript code within a running process, which is a core reverse engineering technique.
* **Code Injection:**  The `create` functions are used to inject JavaScript code.
* **Hooking/Interception:** While not directly implemented in this file, the comment mentioning `guminterceptor.h` and the ability to run arbitrary JavaScript suggests that this backend is a building block for hooking. You'd use this to execute your hooking logic written in JavaScript.
* **Understanding Program Behavior:** By injecting and running scripts, reverse engineers can inspect variables, call functions, and modify program behavior at runtime.

**5. Identifying Low-Level Concepts:**

I look for code that interacts with operating system features or low-level details:

* **Memory Protection (`--write-protect-code-memory`)**: The V8 flags indicate awareness of memory protection mechanisms.
* **JIT Compilation (`--turbo-instruction-scheduling`)**:  Indicates interaction with the JIT compiler, a low-level performance optimization.
* **WebAssembly (`--wasm-*`)**: Support for WebAssembly execution points to dealing with a different kind of binary format.
* **Snapshots:**  Understanding how snapshots work involves knowledge of memory layout and serialization.
* **Threads and Locking (`GMutex`, `Locker`)**:  Dealing with concurrency is a low-level concern.
* **Platform-specific code (`#if defined(...)`)**:  Shows awareness of OS and architecture differences.
* **Code Signing Policy (`gum_process_get_code_signing_policy`)**:  Interacting with OS security features.

**6. Logical Reasoning and Assumptions:**

I consider the "why" behind the code:

* **Asynchronous Operations:**  The async functions suggest that script creation/compilation might be time-consuming and should not block the main Frida thread.
* **Snapshots for Performance:** The snapshot functionality is clearly an optimization to speed up script startup by avoiding repeated parsing and compilation.
* **Thread Safety:** The mutex and locking mechanisms are essential for correctness in a multi-threaded environment like Frida.
* **Error Handling:** The consistent use of `GError` demonstrates a need to report issues to the user.

**7. Common Usage Errors:**

I think about how a programmer might misuse this API:

* **Incorrectly handling asynchronous results:** Not using the `_finish` functions correctly.
* **Trying to use unsupported features (bytecode creation/compilation):**  The code explicitly states these are not supported by V8.
* **Concurrency issues without proper locking:** Although the backend provides some locking, users might still introduce race conditions in their injected scripts.
* **Providing invalid JavaScript code:** This would lead to errors during script creation or execution.

**8. Tracing User Actions:**

Finally, I consider how a user might end up interacting with this specific code:

* **Basic Script Injection:** A user using Frida's Python API to load and run a JavaScript script would trigger the `create` functions in this backend.
* **Snapshot Creation (Advanced):**  A more advanced user might use Frida's tooling or internal APIs to create custom snapshots.
* **Debugging/Troubleshooting:**  If something goes wrong during script loading or execution, a developer might dig into Frida's source code, potentially ending up in this file.

**Self-Correction/Refinement During the Process:**

* **Initial assumption about bytecode:**  I initially thought the `compile` functions would work. However, noticing the "not supported" comments corrected my understanding.
* **Focusing on the "why"**:  Instead of just listing the functions, I tried to explain *why* they exist and how they contribute to Frida's overall functionality.
* **Connecting the dots**:  I made sure to link the low-level concepts to how they manifest in the code (e.g., V8 flags for memory protection).

By following this structured approach, combining code analysis with knowledge of Frida's architecture and common reverse engineering practices, I could generate a comprehensive and accurate answer to the user's request.
好的，让我们来分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumv8scriptbackend.cpp` 这个文件的功能。

**文件功能概览**

这个文件 `gumv8scriptbackend.cpp` 是 Frida 工具中 `frida-gum` 库的一部分，专门负责 **使用 V8 JavaScript 引擎来执行和管理 JavaScript 代码**。它实现了 `GumScriptBackend` 接口，为 Frida 提供了在目标进程中运行 JavaScript 代码的能力。

**核心功能点：**

1. **JavaScript 脚本的创建和管理：**
   - 提供了创建新的 JavaScript 脚本的功能 (`gum_v8_script_backend_create`, `gum_v8_script_backend_create_sync`, `gum_v8_script_backend_create_from_bytes`, `gum_v8_script_backend_create_from_bytes_sync`)。
   - 使用 `GumV8Script` 对象来表示和管理这些脚本。
   - 维护一个 `live_scripts` 哈希表来跟踪当前活动的脚本。

2. **JavaScript 代码的编译（理论上）：**
   - 提供了编译 JavaScript 代码到字节码的功能 (`gum_v8_script_backend_compile`, `gum_v8_script_backend_compile_sync`)。
   - **然而，代码中明确指出 V8 运行时不支持编译到字节码，所以这个功能实际上是未实现的，会返回一个错误。**

3. **V8 快照（Snapshots）的支持：**
   - 提供了创建和使用 V8 快照的功能 (`gum_v8_script_backend_snapshot`, `gum_v8_script_backend_snapshot_sync`)。
   - 快照允许预先编译和初始化 JavaScript 代码，从而加快脚本的启动速度。这对于需要快速注入和执行代码的场景非常有用。

4. **V8 引擎的初始化和配置：**
   - 负责初始化和配置 V8 JavaScript 引擎 (`gum_v8_script_backend_get_platform`)，包括设置 V8 的启动标志（flags）。
   - 允许通过环境变量 `FRIDA_V8_EXTRA_FLAGS` 来添加额外的 V8 启动标志。
   - 根据代码签名策略 (`gum_process_get_code_signing_policy`) 动态设置 `--jitless` 标志。

5. **线程安全管理：**
   - 使用互斥锁 (`GMutex`) 来保护对共享数据的访问，确保线程安全 (`gum_v8_script_backend_with_lock_held`, `gum_v8_script_backend_is_locked`)。
   - 特别注意 V8 的线程模型，V8 的 Isolate 必须在创建它的线程上访问。

6. **异步操作支持：**
   - 使用 GLib 的异步操作机制 (`GCancellable`, `GAsyncReadyCallback`) 来执行一些可能耗时的操作，如脚本创建和快照生成，避免阻塞主线程。

**与逆向方法的关联及举例说明**

这个文件直接关系到 Frida 进行动态 instrumentation 的核心方法。通过这个 backend，逆向工程师可以将 JavaScript 代码注入到目标进程中，并利用 JavaScript 的灵活性和 Frida 提供的 API 来实现各种逆向分析和修改操作。

**举例说明：**

假设逆向工程师想要 hook 目标进程中的 `open` 函数，以监控哪些文件被打开。他们可以编写如下的 JavaScript 代码：

```javascript
Interceptor.attach(Module.findExportByName
### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumv8scriptbackend.cpp的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```cpp
/*
 * Copyright (C) 2010-2022 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 * Copyright (C) 2013 Karl Trygve Kalleberg <karltk@boblycat.org>
 * Copyright (C) 2020 Francesco Tamagni <mrmacete@protonmail.ch>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumv8scriptbackend.h"

#include "gumscripttask.h"
#include "gumv8platform.h"
#include "gumv8script-priv.h"

#include <gum/guminterceptor.h>
#include <string.h>

#if defined (HAVE_DARWIN) && (defined (HAVE_ARM) || defined (HAVE_ARM64))
# define GUM_V8_PLATFORM_FLAGS \
    "--write-protect-code-memory " \
    "--wasm-write-protect-code-memory "
#else
# define GUM_V8_PLATFORM_FLAGS
#endif

#define GUM_V8_FLAGS \
    GUM_V8_PLATFORM_FLAGS \
    "--no-freeze-flags-after-init " \
    "--turbo-instruction-scheduling " \
    "--use-strict " \
    "--expose-gc " \
    "--wasm-staging " \
    "--experimental-wasm-eh " \
    "--experimental-wasm-simd " \
    "--experimental-wasm-return-call"

#define GUM_V8_SCRIPT_BACKEND_LOCK(o) g_mutex_lock (&(o)->mutex)
#define GUM_V8_SCRIPT_BACKEND_UNLOCK(o) g_mutex_unlock (&(o)->mutex)

using namespace v8;
using namespace v8_inspector;

struct _GumV8ScriptBackend
{
  GObject parent;

  gboolean scope_mutex_trapped;

  GMutex mutex;
  GHashTable * live_scripts;
  GumV8Platform * platform;
};

struct GumCreateScriptData
{
  gchar * name;
  gchar * source;
  GBytes * snapshot;
};

struct GumCreateScriptFromBytesData
{
  GBytes * bytes;
  GBytes * snapshot;
};

struct GumCompileScriptData
{
  gchar * name;
  gchar * source;
};

struct GumSnapshotScriptData
{
  gchar * embed_script;
  gchar * warmup_script;
};

static void gum_v8_script_backend_iface_init (gpointer g_iface,
    gpointer iface_data);
static void gum_v8_script_backend_finalize (GObject * object);

static void gum_v8_script_backend_create (GumScriptBackend * backend,
    const gchar * name, const gchar * source, GBytes * snapshot,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static GumScript * gum_v8_script_backend_create_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GumScript * gum_v8_script_backend_create_sync (
    GumScriptBackend * backend, const gchar * name, const gchar * source,
    GBytes * snapshot, GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_create_script_task_new (GumV8ScriptBackend * backend,
    const gchar * name, const gchar * source, GBytes * snapshot,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_create_script_task_run (GumScriptTask * task,
    GumV8ScriptBackend * self, GumCreateScriptData * d,
    GCancellable * cancellable);
static void gum_create_script_data_free (GumCreateScriptData * d);
static void gum_v8_script_backend_create_from_bytes (GumScriptBackend * backend,
    GBytes * bytes, GBytes * snapshot, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GumScript * gum_v8_script_backend_create_from_bytes_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GumScript * gum_v8_script_backend_create_from_bytes_sync (
    GumScriptBackend * backend, GBytes * bytes, GBytes * snapshot,
    GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_create_script_from_bytes_task_new (
    GumV8ScriptBackend * backend, GBytes * bytes, GBytes * snapshot,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_create_script_from_bytes_task_run (GumScriptTask * task,
    GumV8ScriptBackend * self, GumCreateScriptFromBytesData * d,
    GCancellable * cancellable);
static void gum_create_script_from_bytes_data_free (
    GumCreateScriptFromBytesData * d);

static void gum_v8_script_backend_compile (GumScriptBackend * backend,
    const gchar * name, const gchar * source, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static GBytes * gum_v8_script_backend_compile_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GBytes * gum_v8_script_backend_compile_sync (GumScriptBackend * backend,
    const gchar * name, const gchar * source, GCancellable * cancellable,
    GError ** error);
static GumScriptTask * gum_compile_script_task_new (
    GumV8ScriptBackend * backend, const gchar * name, const gchar * source,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static void gum_compile_script_task_run (GumScriptTask * task,
    GumV8ScriptBackend * self, GumCompileScriptData * d,
    GCancellable * cancellable);
static void gum_compile_script_data_free (GumCompileScriptData * d);
static void gum_v8_script_backend_snapshot (GumScriptBackend * backend,
    const gchar * embed_script, const gchar * warmup_script,
    GCancellable * cancellable, GAsyncReadyCallback callback,
    gpointer user_data);
static GBytes * gum_v8_script_backend_snapshot_finish (
    GumScriptBackend * backend, GAsyncResult * result, GError ** error);
static GBytes * gum_v8_script_backend_snapshot_sync (GumScriptBackend * backend,
    const gchar * embed_script, const gchar * warmup_script,
    GCancellable * cancellable, GError ** error);
static GumScriptTask * gum_snapshot_script_task_new (
    GumV8ScriptBackend * backend, const gchar * embed_script,
    const gchar * warmup_script, GCancellable * cancellable,
    GAsyncReadyCallback callback, gpointer user_data);
static void gum_snapshot_script_task_run (GumScriptTask * task,
    GumV8ScriptBackend * self, GumSnapshotScriptData * d,
    GCancellable * cancellable);
static StartupData gum_create_snapshot (const gchar * embed_script,
    GumV8Platform * platform, GError ** error);
static StartupData gum_warm_up_snapshot (StartupData cold,
    const gchar * warmup_script, GumV8Platform * platform, GError ** error);
static bool gum_run_code (Isolate * isolate, Local<Context> context,
    const gchar * source, const gchar * name, GError ** error);
static void gum_snapshot_script_data_free (GumSnapshotScriptData * d);
static void gum_snapshot_script_blob_free (char * blob);

static void gum_v8_script_backend_with_lock_held (GumScriptBackend * backend,
    GumScriptBackendLockedFunc func, gpointer user_data);
static gboolean gum_v8_script_backend_is_locked (GumScriptBackend * backend);

static void gum_v8_script_backend_on_context_created (GumV8ScriptBackend * self,
    Local<Context> * context, GumV8Script * script);
static void gum_v8_script_backend_on_context_destroyed (
    GumV8ScriptBackend * self, Local<Context> * context, GumV8Script * script);

G_DEFINE_TYPE_EXTENDED (GumV8ScriptBackend,
                        gum_v8_script_backend,
                        G_TYPE_OBJECT,
                        0,
                        G_IMPLEMENT_INTERFACE (GUM_TYPE_SCRIPT_BACKEND,
                            gum_v8_script_backend_iface_init))

static void
gum_v8_script_backend_class_init (GumV8ScriptBackendClass * klass)
{
  auto object_class = G_OBJECT_CLASS (klass);

  object_class->finalize = gum_v8_script_backend_finalize;
}

static void
gum_v8_script_backend_iface_init (gpointer g_iface,
                                  gpointer iface_data)
{
  auto iface = (GumScriptBackendInterface *) g_iface;

  iface->create = gum_v8_script_backend_create;
  iface->create_finish = gum_v8_script_backend_create_finish;
  iface->create_sync = gum_v8_script_backend_create_sync;
  iface->create_from_bytes = gum_v8_script_backend_create_from_bytes;
  iface->create_from_bytes_finish =
      gum_v8_script_backend_create_from_bytes_finish;
  iface->create_from_bytes_sync = gum_v8_script_backend_create_from_bytes_sync;

  iface->compile = gum_v8_script_backend_compile;
  iface->compile_finish = gum_v8_script_backend_compile_finish;
  iface->compile_sync = gum_v8_script_backend_compile_sync;
  iface->snapshot = gum_v8_script_backend_snapshot;
  iface->snapshot_finish = gum_v8_script_backend_snapshot_finish;
  iface->snapshot_sync = gum_v8_script_backend_snapshot_sync;

  iface->with_lock_held = gum_v8_script_backend_with_lock_held;
  iface->is_locked = gum_v8_script_backend_is_locked;
}

static void
gum_v8_script_backend_init (GumV8ScriptBackend * self)
{
  self->scope_mutex_trapped = FALSE;

  g_mutex_init (&self->mutex);
  self->live_scripts = g_hash_table_new (NULL, NULL);
  self->platform = NULL;
}

static void
gum_v8_script_backend_finalize (GObject * object)
{
  auto self = GUM_V8_SCRIPT_BACKEND (object);

  delete self->platform;
  g_hash_table_unref (self->live_scripts);
  g_mutex_clear (&self->mutex);

  G_OBJECT_CLASS (gum_v8_script_backend_parent_class)->finalize (object);
}

gpointer
gum_v8_script_backend_get_platform (GumV8ScriptBackend * self)
{
  if (self->platform == NULL)
  {
    GString * flags;

    flags = g_string_new (GUM_V8_FLAGS);

    if (gum_process_get_code_signing_policy () == GUM_CODE_SIGNING_REQUIRED)
    {
      g_string_append (flags, " --jitless");
    }

    const gchar * extra_flags = g_getenv ("FRIDA_V8_EXTRA_FLAGS");
    if (extra_flags != NULL)
    {
      g_string_append_c (flags, ' ');
      g_string_append (flags, extra_flags);
    }

    V8::SetFlagsFromString (flags->str, (size_t) flags->len);

    g_string_free (flags, TRUE);

    self->platform = new GumV8Platform ();
  }

  return self->platform;
}

GumScriptScheduler *
gum_v8_script_backend_get_scheduler (GumV8ScriptBackend * self)
{
  auto platform = (GumV8Platform *) gum_v8_script_backend_get_platform (self);

  return platform->GetScheduler ();
}

static void
gum_v8_script_backend_create (GumScriptBackend * backend,
                              const gchar * name,
                              const gchar * source,
                              GBytes * snapshot,
                              GCancellable * cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_create_script_task_new (self, name, source, snapshot,
      cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GumScript *
gum_v8_script_backend_create_finish (GumScriptBackend * backend,
                                     GAsyncResult * result,
                                     GError ** error)
{
  return GUM_SCRIPT (gum_script_task_propagate_pointer (
      GUM_SCRIPT_TASK (result), error));
}

static GumScript *
gum_v8_script_backend_create_sync (GumScriptBackend * backend,
                                   const gchar * name,
                                   const gchar * source,
                                   GBytes * snapshot,
                                   GCancellable * cancellable,
                                   GError ** error)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_create_script_task_new (self, name, source, snapshot,
      cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self));
  auto script = GUM_SCRIPT (gum_script_task_propagate_pointer (task, error));
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_create_script_task_new (GumV8ScriptBackend * backend,
                            const gchar * name,
                            const gchar * source,
                            GBytes * snapshot,
                            GCancellable * cancellable,
                            GAsyncReadyCallback callback,
                            gpointer user_data)
{
  auto d = g_slice_new (GumCreateScriptData);
  d->name = g_strdup (name);
  d->source = g_strdup (source);
  d->snapshot = (snapshot != NULL) ? g_bytes_ref (snapshot) : NULL;

  auto task = gum_script_task_new (
      (GumScriptTaskFunc) gum_create_script_task_run, backend, cancellable,
      callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_create_script_data_free);
  return task;
}

static void
gum_create_script_task_run (GumScriptTask * task,
                            GumV8ScriptBackend * self,
                            GumCreateScriptData * d,
                            GCancellable * cancellable)
{
  auto script = GUM_V8_SCRIPT (g_object_new (GUM_V8_TYPE_SCRIPT,
      "name", d->name,
      "source", d->source,
      "snapshot", d->snapshot,
      "main-context", gum_script_task_get_context (task),
      "backend", self,
      NULL));
  g_signal_connect_swapped (script, "context-created",
      G_CALLBACK (gum_v8_script_backend_on_context_created), self);
  g_signal_connect_swapped (script, "context-destroyed",
      G_CALLBACK (gum_v8_script_backend_on_context_destroyed), self);

  GError * error = NULL;
  gum_v8_script_create_context (script, &error);

  if (error == NULL)
  {
    gum_script_task_return_pointer (task, script, g_object_unref);
  }
  else
  {
    gum_script_task_return_error (task, error);
    g_object_unref (script);
  }
}

static void
gum_create_script_data_free (GumCreateScriptData * d)
{
  g_free (d->name);
  g_free (d->source);
  g_bytes_unref (d->snapshot);

  g_slice_free (GumCreateScriptData, d);
}

static void
gum_v8_script_backend_create_from_bytes (GumScriptBackend * backend,
                                         GBytes * bytes,
                                         GBytes * snapshot,
                                         GCancellable * cancellable,
                                         GAsyncReadyCallback callback,
                                         gpointer user_data)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_create_script_from_bytes_task_new (self, bytes, snapshot,
      cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GumScript *
gum_v8_script_backend_create_from_bytes_finish (GumScriptBackend * backend,
                                                GAsyncResult * result,
                                                GError ** error)
{
  return GUM_SCRIPT (gum_script_task_propagate_pointer (
      GUM_SCRIPT_TASK (result), error));
}

static GumScript *
gum_v8_script_backend_create_from_bytes_sync (GumScriptBackend * backend,
                                              GBytes * bytes,
                                              GBytes * snapshot,
                                              GCancellable * cancellable,
                                              GError ** error)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_create_script_from_bytes_task_new (self, bytes, snapshot,
      cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self));
  auto script = GUM_SCRIPT (gum_script_task_propagate_pointer (task, error));
  g_object_unref (task);

  return script;
}

static GumScriptTask *
gum_create_script_from_bytes_task_new (GumV8ScriptBackend * backend,
                                       GBytes * bytes,
                                       GBytes * snapshot,
                                       GCancellable * cancellable,
                                       GAsyncReadyCallback callback,
                                       gpointer user_data)
{
  auto d = g_slice_new (GumCreateScriptFromBytesData);
  d->bytes = g_bytes_ref (bytes);
  d->snapshot = (snapshot != NULL) ? g_bytes_ref (snapshot) : NULL;

  auto task = gum_script_task_new (
      (GumScriptTaskFunc) gum_create_script_from_bytes_task_run, backend,
      cancellable, callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_create_script_from_bytes_data_free);
  return task;
}

static void
gum_create_script_from_bytes_task_run (GumScriptTask * task,
                                       GumV8ScriptBackend * self,
                                       GumCreateScriptFromBytesData * d,
                                       GCancellable * cancellable)
{
  auto error = g_error_new (GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
      "script creation from bytecode is not supported by the V8 runtime");
  gum_script_task_return_error (task, error);
}

static void
gum_create_script_from_bytes_data_free (GumCreateScriptFromBytesData * d)
{
  g_bytes_unref (d->bytes);
  g_bytes_unref (d->snapshot);

  g_slice_free (GumCreateScriptFromBytesData, d);
}

static void
gum_v8_script_backend_compile (GumScriptBackend * backend,
                               const gchar * name,
                               const gchar * source,
                               GCancellable * cancellable,
                               GAsyncReadyCallback callback,
                               gpointer user_data)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_compile_script_task_new (self, name, source, cancellable,
      callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GBytes *
gum_v8_script_backend_compile_finish (GumScriptBackend * backend,
                                      GAsyncResult * result,
                                      GError ** error)
{
  return (GBytes *) gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result),
      error);
}

static GBytes *
gum_v8_script_backend_compile_sync (GumScriptBackend * backend,
                                    const gchar * name,
                                    const gchar * source,
                                    GCancellable * cancellable,
                                    GError ** error)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task =
      gum_compile_script_task_new (self, name, source, cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self));
  auto bytes = (GBytes *) gum_script_task_propagate_pointer (task, error);
  g_object_unref (task);

  return bytes;
}

static GumScriptTask *
gum_compile_script_task_new (GumV8ScriptBackend * backend,
                             const gchar * name,
                             const gchar * source,
                             GCancellable * cancellable,
                             GAsyncReadyCallback callback,
                             gpointer user_data)
{
  auto d = g_slice_new (GumCompileScriptData);
  d->name = g_strdup (name);
  d->source = g_strdup (source);

  auto task = gum_script_task_new (
      (GumScriptTaskFunc) gum_compile_script_task_run, backend, cancellable,
      callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_compile_script_data_free);
  return task;
}

static void
gum_compile_script_task_run (GumScriptTask * task,
                             GumV8ScriptBackend * self,
                             GumCompileScriptData * d,
                             GCancellable * cancellable)
{
  auto error = g_error_new (GUM_ERROR, GUM_ERROR_NOT_SUPPORTED,
      "compilation to bytecode is not supported by the V8 runtime");
  gum_script_task_return_error (task, error);
}

static void
gum_compile_script_data_free (GumCompileScriptData * d)
{
  g_free (d->name);
  g_free (d->source);

  g_slice_free (GumCompileScriptData, d);
}

static void
gum_v8_script_backend_snapshot (GumScriptBackend * backend,
                                const gchar * embed_script,
                                const gchar * warmup_script,
                                GCancellable * cancellable,
                                GAsyncReadyCallback callback,
                                gpointer user_data)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_snapshot_script_task_new (self, embed_script, warmup_script,
      cancellable, callback, user_data);
  gum_script_task_run_in_js_thread (task,
      gum_v8_script_backend_get_scheduler (self));
  g_object_unref (task);
}

static GBytes *
gum_v8_script_backend_snapshot_finish (GumScriptBackend * backend,
                                       GAsyncResult * result,
                                       GError ** error)
{
  return (GBytes *) gum_script_task_propagate_pointer (GUM_SCRIPT_TASK (result),
      error);
}

static GBytes *
gum_v8_script_backend_snapshot_sync (GumScriptBackend * backend,
                                     const gchar * embed_script,
                                     const gchar * warmup_script,
                                     GCancellable * cancellable,
                                     GError ** error)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  auto task = gum_snapshot_script_task_new (self, embed_script, warmup_script,
      cancellable, NULL, NULL);
  gum_script_task_run_in_js_thread_sync (task,
      gum_v8_script_backend_get_scheduler (self));
  auto bytes = (GBytes *) gum_script_task_propagate_pointer (task, error);
  g_object_unref (task);

  return bytes;
}

static GumScriptTask *
gum_snapshot_script_task_new (GumV8ScriptBackend * backend,
                              const gchar * embed_script,
                              const gchar * warmup_script,
                              GCancellable * cancellable,
                              GAsyncReadyCallback callback,
                              gpointer user_data)
{
  auto d = g_slice_new (GumSnapshotScriptData);
  d->embed_script = g_strdup (embed_script);
  d->warmup_script = g_strdup (warmup_script);

  auto task = gum_script_task_new (
      (GumScriptTaskFunc) gum_snapshot_script_task_run, backend, cancellable,
      callback, user_data);
  gum_script_task_set_task_data (task, d,
      (GDestroyNotify) gum_snapshot_script_data_free);
  return task;
}

static void
gum_snapshot_script_task_run (GumScriptTask * task,
                              GumV8ScriptBackend * self,
                              GumSnapshotScriptData * d,
                              GCancellable * cancellable)
{
  auto platform = (GumV8Platform *) gum_v8_script_backend_get_platform (self);

  GError * error = NULL;
  StartupData blob = gum_create_snapshot (d->embed_script, platform, &error);

  if (error == NULL && d->warmup_script != NULL)
  {
    StartupData cold = blob;
    blob = gum_warm_up_snapshot (cold, d->warmup_script, platform, &error);
    delete[] cold.data;
  }

  if (error == NULL)
  {
    gum_script_task_return_pointer (task,
        g_bytes_new_with_free_func (blob.data, blob.raw_size,
          (GDestroyNotify) gum_snapshot_script_blob_free,
          (gpointer) blob.data),
        (GDestroyNotify) g_bytes_unref);
  }
  else
  {
    gum_script_task_return_error (task, error);
  }
}

static StartupData
gum_create_snapshot (const gchar * embed_script,
                     GumV8Platform * platform,
                     GError ** error)
{
  SnapshotCreator creator;

  StartupData blob = {};
  auto isolate = creator.GetIsolate ();
  {
    Isolate::Scope isolate_scope (isolate);
    Locker locker (isolate);

    bool success = false;
    {
      HandleScope handle_scope (isolate);
      auto context = Context::New (isolate);

      if (gum_run_code (isolate, context, embed_script, "embedded", error))
      {
        creator.SetDefaultContext (context);
        success = true;
      }
    }

    if (success)
      blob = creator.CreateBlob (SnapshotCreator::FunctionCodeHandling::kKeep);
  }

  platform->ForgetIsolate (isolate);

  return blob;
}

static StartupData
gum_warm_up_snapshot (StartupData cold,
                      const gchar * warmup_script,
                      GumV8Platform * platform,
                      GError ** error)
{
  SnapshotCreator creator (nullptr, &cold);

  StartupData blob = {};
  auto isolate = creator.GetIsolate ();
  {
    Isolate::Scope isolate_scope (isolate);
    Locker locker (isolate);

    bool success = false;
    {
      HandleScope handle_scope (isolate);
      auto context = Context::New (isolate);

      success = gum_run_code (isolate, context, warmup_script, "warmup", error);
    }

    if (success)
    {
      {
        HandleScope handle_scope (isolate);
        isolate->ContextDisposedNotification (false);
        auto context = Context::New (isolate);
        creator.SetDefaultContext (context);
      }

      blob = creator.CreateBlob (SnapshotCreator::FunctionCodeHandling::kKeep);
    }
  }

  platform->ForgetIsolate (isolate);

  return blob;
}

static bool
gum_run_code (Isolate * isolate,
              Local<Context> context,
              const gchar * source,
              const gchar * name,
              GError ** error)
{
  Context::Scope context_scope (context);

  bool success = false;
  Local<Script> code;
  TryCatch trycatch (isolate);
  if (Script::Compile (context, String::NewFromUtf8 (isolate, source)
        .ToLocalChecked ()).ToLocal (&code))
  {
    success = !code->Run (context).IsEmpty ();
  }

  if (!success)
  {
    Local<Message> message = trycatch.Message ();
    Local<Value> exception = trycatch.Exception ();
    String::Utf8Value exception_str (isolate, exception);
    *error = g_error_new (
        GUM_ERROR,
        GUM_ERROR_FAILED,
        "%s script line %d: %s",
        name,
        message->GetLineNumber (context).FromMaybe (-1),
        *exception_str);
  }

  return success;
}

static void
gum_snapshot_script_data_free (GumSnapshotScriptData * d)
{
  g_free (d->embed_script);
  g_free (d->warmup_script);

  g_slice_free (GumSnapshotScriptData, d);
}

static void
gum_snapshot_script_blob_free (char * blob)
{
  delete[] blob;
}

static void
gum_v8_script_backend_with_lock_held (GumScriptBackend * backend,
                                      GumScriptBackendLockedFunc func,
                                      gpointer user_data)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  if (self->scope_mutex_trapped)
  {
    func (user_data);
    return;
  }

  GUM_V8_SCRIPT_BACKEND_LOCK (self);

  gint n = g_hash_table_size (self->live_scripts);
  auto lockers = g_newa (Locker, n);

  GHashTableIter iter;
  g_hash_table_iter_init (&iter, self->live_scripts);

  GumV8Script * script;
  for (gint i = 0;
      g_hash_table_iter_next (&iter, (gpointer *) &script, NULL);
      i++)
  {
    new (&lockers[i]) Locker (script->isolate);
  }

  GUM_V8_SCRIPT_BACKEND_UNLOCK (self);

  func (user_data);

  for (gint i = n - 1; i != -1; i--)
    lockers[i].~Locker ();
}

static gboolean
gum_v8_script_backend_is_locked (GumScriptBackend * backend)
{
  auto self = GUM_V8_SCRIPT_BACKEND (backend);

  if (self->scope_mutex_trapped)
    return FALSE;

  GUM_V8_SCRIPT_BACKEND_LOCK (self);

  GHashTableIter iter;
  g_hash_table_iter_init (&iter, self->live_scripts);

  gboolean is_locked = FALSE;
  GumV8Script * script;
  while (g_hash_table_iter_next (&iter, (gpointer *) &script, NULL))
  {
    auto isolate = script->isolate;

    if (Locker::IsLocked (isolate))
      continue;

    if (Locker::IsLockedByAnyThread (isolate))
    {
      is_locked = TRUE;
      break;
    }
  }

  GUM_V8_SCRIPT_BACKEND_UNLOCK (self);

  return is_locked;
}

gboolean
gum_v8_script_backend_is_scope_mutex_trapped (GumV8ScriptBackend * self)
{
  return self->scope_mutex_trapped;
}

void
gum_v8_script_backend_mark_scope_mutex_trapped (GumV8ScriptBackend * self)
{
  self->scope_mutex_trapped = TRUE;
}

static void
gum_v8_script_backend_on_context_created (GumV8ScriptBackend * self,
                                          Local<Context> * context,
                                          GumV8Script * script)
{
  GUM_V8_SCRIPT_BACKEND_LOCK (self);
  g_hash_table_add (self->live_scripts, script);
  GUM_V8_SCRIPT_BACKEND_UNLOCK (self);
}

static void
gum_v8_script_backend_on_context_destroyed (GumV8ScriptBackend * self,
                                            Local<Context> * context,
                                            GumV8Script * script)
{
  GUM_V8_SCRIPT_BACKEND_LOCK (self);
  g_hash_table_remove (self->live_scripts, script);
  GUM_V8_SCRIPT_BACKEND_UNLOCK (self);
}
```