Response:
Let's break down the thought process for analyzing this C code snippet for Frida.

**1. Understanding the Goal:**

The primary goal is to understand the functionality of `gumscriptscheduler.c` within the context of Frida and its relevance to reverse engineering. This involves identifying core functionalities, connections to lower-level systems, potential usage scenarios, and common pitfalls.

**2. Initial Code Scan and Keyword Identification:**

A quick skim reveals several key terms and structures:

* **`GumScriptScheduler`**:  This is clearly the central data structure.
* **`GThread`, `GMainLoop`, `GMainContext`, `GThreadPool`**:  These are GLib primitives related to threading, event loops, and thread pools. This immediately suggests the code manages asynchronous tasks.
* **`GumScriptJob`**: This structure likely represents a unit of work to be scheduled.
* **`gum_script_scheduler_push_job_on_js_thread`, `gum_script_scheduler_push_job_on_thread_pool`**:  These function names strongly indicate task scheduling to different execution environments.
* **`js_thread`, `js_loop`, `js_context`**:  The "js" prefix hints at a connection to JavaScript execution, which is a core part of Frida's scripting capabilities.
* **`dispose`**: This is a standard GObject method for cleanup, indicating resource management.
* **`start`, `stop`**: These methods control the lifecycle of the scheduler.

**3. Deeper Dive into Functionality:**

Based on the keywords, the next step is to understand what each part does:

* **`GumScriptScheduler` structure:**  It holds the state of the scheduler, including flags, threads, loops, and a thread pool. The `start_request_seqno` and `disposed` fields suggest mechanisms for managing the scheduler's lifecycle and preventing double initialization or use after disposal.
* **`GumScriptJob` structure:**  It encapsulates a function to execute (`func`), associated data (`data`), and a way to free the data (`data_destroy`). This is a common pattern for asynchronous tasks.
* **`gum_script_scheduler_new`**:  Creates a new scheduler instance.
* **`gum_script_scheduler_enable_background_thread`, `gum_script_scheduler_disable_background_thread`**: These control whether the JavaScript execution happens on a dedicated background thread.
* **`gum_script_scheduler_start`**: Initializes the JavaScript thread and event loop if the background thread is enabled. The atomic operation on `start_request_seqno` likely acts as a simple locking mechanism to prevent race conditions during startup.
* **`gum_script_scheduler_stop`**:  Terminates the JavaScript thread and event loop. It pushes a quit job onto the JS thread to ensure a clean shutdown.
* **`gum_script_scheduler_get_js_context`**: Provides access to the main loop context for JavaScript execution.
* **`gum_script_scheduler_push_job_on_js_thread`**:  Schedules a `GumScriptJob` to be executed on the JavaScript thread. It uses `g_idle_source_new` to integrate the job into the GLib main loop. The priority parameter allows for ordering of tasks.
* **`gum_script_scheduler_push_job_on_thread_pool`**:  Schedules a `GumScriptJob` to be executed on a general-purpose thread pool. This is for tasks that don't need to interact directly with the JavaScript environment or need to run concurrently.
* **`gum_script_scheduler_perform_js_job`**:  The callback executed on the JavaScript thread. It simply calls the job's function.
* **`gum_script_scheduler_perform_pool_job`**: The callback executed by a thread pool worker. It calls the job's function and then frees the job.
* **`gum_script_scheduler_run_js_loop`**:  The entry point for the JavaScript thread. It runs the GLib main loop, which processes events and scheduled jobs.
* **`gum_script_job_new`, `gum_script_job_free`**: Functions for creating and destroying `GumScriptJob` instances.
* **`gum_script_job_start_on_js_thread`**:  Provides a way to start a job on the JS thread, even if called from a different thread. It checks if the current thread is the JS thread and executes directly or schedules it otherwise.

**4. Connecting to Reverse Engineering:**

The key connection is how this scheduler enables Frida's dynamic instrumentation:

* **JavaScript Interaction:** Frida uses JavaScript to define instrumentation logic. This scheduler ensures that the JavaScript runtime has a dedicated thread and event loop to execute these scripts. The `gum_script_scheduler_push_job_on_js_thread` function is crucial for delivering commands and receiving results between the core Frida engine (written in C) and the JavaScript environment.
* **Asynchronous Operations:**  Instrumentation often involves actions that shouldn't block the main application's execution. The thread pool allows Frida to perform tasks like memory allocation, code patching, and data processing in the background.
* **Inter-Thread Communication:**  Frida needs to coordinate between its C core and the JavaScript environment. The scheduler provides the mechanisms for safely passing data and control between these different contexts.

**5. Considering Lower-Level Aspects:**

* **Operating System Primitives:**  The use of `GThread` directly maps to OS-level threading mechanisms (pthreads on Linux, Windows threads). `GMainLoop` and `GMainContext` are built upon OS event notification mechanisms (epoll, kqueue, etc.).
* **Memory Management:**  The code uses `g_slice_new` and `g_slice_free` for allocating `GumScriptJob` structures, suggesting an attempt at efficient memory management. The `data_destroy` callback is vital for preventing memory leaks.
* **Concurrency and Synchronization:** The use of atomic operations (`g_atomic_int_add`, `g_atomic_int_set`) highlights the need for careful synchronization when dealing with shared resources across multiple threads.

**6. Logical Reasoning and Examples:**

At this point, it's possible to formulate examples of input and output. For instance, if a JavaScript script calls a Frida API to hook a function, this will likely result in a job being pushed onto the JS thread to execute the JavaScript hook handler. If a script requests to read memory, a job might be pushed onto the thread pool to perform the read operation.

**7. Identifying User Errors:**

Understanding how the scheduler works helps identify potential errors:

* **Incorrect Threading Assumptions:** Users might try to directly access JavaScript objects from a non-JS thread without using the provided scheduling mechanisms, leading to crashes or undefined behavior.
* **Resource Leaks:**  If the `data_destroy` callback is not correctly set or implemented, data associated with scheduled jobs might not be freed, leading to memory leaks.
* **Deadlocks:**  While not immediately apparent in this code, if jobs pushed to different threads have dependencies and are not handled carefully, deadlocks could occur.

**8. Tracing User Actions:**

To understand how a user reaches this code, consider the typical Frida workflow:

1. **User writes a Frida script (JavaScript).**
2. **User attaches Frida to a process.**
3. **The Frida engine loads the script.**
4. **The script uses Frida APIs (e.g., `Interceptor.attach`).**
5. **Internally, these API calls often result in jobs being scheduled using `gum_script_scheduler_push_job_on_js_thread` to execute the JavaScript callbacks defined by the user.**

**Self-Correction/Refinement:**

During the process, I might have initially focused too much on just the threading aspect. Realizing the "js" prefix is significant would lead to exploring the connection to JavaScript execution, which is central to Frida. Similarly, recognizing the GObject patterns would highlight the importance of the `dispose` method and resource management.

By following these steps, moving from a broad overview to specific details and considering the context of Frida, a comprehensive understanding of the `gumscriptscheduler.c` file can be achieved.
好的，让我们来分析一下 `frida/subprojects/frida-gum/bindings/gumjs/gumscriptscheduler.c` 这个文件，它是 Frida Dynamic Instrumentation 工具的一部分。

**功能列表：**

这个文件的主要功能是实现了一个脚本调度器，用于在 Frida 的 GumJS 绑定中管理和执行 JavaScript 相关的任务。具体来说，它负责：

1. **JavaScript 线程管理:**
   - 创建和管理一个独立的线程 (`js_thread`) 来运行 JavaScript 代码。
   - 在该线程上创建一个 GLib 的主循环 (`js_loop`) 和上下文 (`js_context`)，用于处理事件和异步任务。
   - 提供启动和停止 JavaScript 线程和主循环的功能。

2. **任务调度:**
   - 允许将需要在 JavaScript 线程上执行的任务（`GumScriptJob`）推送到调度器。
   - 使用 GLib 的 `g_idle_source` 将这些任务添加到 JavaScript 线程的主循环中，以便在主循环空闲时执行。
   - 支持为推送到 JavaScript 线程的任务设置优先级。

3. **线程池管理:**
   - 创建和管理一个线程池 (`thread_pool`)，用于执行不需要在 JavaScript 线程上运行的任务。
   - 允许将任务推送到线程池中异步执行。

4. **任务抽象:**
   - 定义了一个 `GumScriptJob` 结构，用于封装需要执行的函数 (`func`) 和相关数据 (`data`)。
   - 提供了创建和释放 `GumScriptJob` 实例的函数。

5. **资源管理:**
   - 使用 GLib 的对象模型进行管理，包括对象的创建、初始化和销毁 (`dispose`)。
   - 确保在调度器销毁时释放相关的资源，如线程池、主循环和上下文。

**与逆向方法的关系及举例说明：**

这个脚本调度器是 Frida 动态插桩功能的核心组件，直接关系到逆向分析人员如何与目标进程进行交互。

**举例说明：**

假设逆向工程师想要 Hook 目标进程中的一个函数 `evil_function`，并在函数执行前后打印一些信息。他们会编写一个 Frida JavaScript 脚本，如下所示：

```javascript
Interceptor.attach(Module.findExportByName(null, 'evil_function'), {
  onEnter: function(args) {
    console.log("evil_function is called with arguments: " + args);
  },
  onLeave: function(retval) {
    console.log("evil_function returned: " + retval);
  }
});
```

当 Frida 加载并执行这个脚本时，以下步骤会涉及到 `gumscriptscheduler.c`：

1. **`Interceptor.attach` 调用:**  JavaScript 引擎执行 `Interceptor.attach` 函数。
2. **C++ 层处理:**  Frida 的 C++ 层接收到这个调用，并需要在 JavaScript 线程上执行一些操作，例如注册 Hook 回调函数。
3. **任务推送:**  Frida C++ 层会创建一个 `GumScriptJob`，其中包含了需要在 JavaScript 线程上执行的回调函数（可能与内部的 JavaScript 对象关联），然后通过 `gum_script_scheduler_push_job_on_js_thread` 将这个任务推送到脚本调度器。
4. **JavaScript 线程执行:**  `gumscriptscheduler.c` 管理的 JavaScript 线程上的主循环会接收到这个任务，并在合适的时机执行它。这可能涉及到在 JavaScript 虚拟机中创建或更新一些对象，以便在目标进程执行 `evil_function` 时触发 JavaScript 的 `onEnter` 和 `onLeave` 回调。
5. **目标函数执行和回调:** 当目标进程执行到 `evil_function` 时，Frida 的插桩代码会暂停执行，并通知 JavaScript 线程。这通常也会通过脚本调度器来完成，将执行回调的任务推送到 JavaScript 线程。
6. **JavaScript 代码执行:** JavaScript 线程执行 `onEnter` 和 `onLeave` 中的代码，例如打印日志。

**涉及到二进制底层、Linux/Android 内核及框架的知识及举例说明：**

虽然 `gumscriptscheduler.c` 本身主要关注线程和任务调度，但它服务的对象—— Frida 的动态插桩功能，深深地依赖于底层的知识。

**举例说明：**

1. **二进制底层：**
   - **代码注入:** Frida 需要将自己的代码注入到目标进程中才能进行插桩。这涉及到对目标进程内存布局的理解，以及如何修改进程的内存空间。
   - **指令级别的操作:**  Hook 函数通常需要在目标函数的入口或出口处插入跳转指令，以便 Frida 的代码能够获得控制权。这需要了解目标架构（例如 ARM, x86）的指令集。
   - **调用约定 (Calling Convention):**  当 JavaScript 回调函数被触发时，Frida 需要正确地传递参数和处理返回值。这需要了解目标平台的调用约定，例如参数如何传递（寄存器、栈），返回值如何存储。

2. **Linux/Android 内核:**
   - **进程和线程管理:**  Frida 需要使用操作系统提供的 API（例如 `ptrace` 在 Linux 上，或者 Android 提供的调试接口）来attach到目标进程，并控制其执行。
   - **内存管理:**  Frida 需要读取和修改目标进程的内存。这涉及到对操作系统内存管理机制的理解，例如虚拟内存、页表等。
   - **信号处理:**  Frida 可能会使用信号机制来中断目标进程的执行，以便执行插桩代码。
   - **Android 框架:** 在 Android 环境下，Frida 需要与 Android Runtime (ART) 或 Dalvik 虚拟机进行交互，才能 Hook Java 方法。这需要理解 ART/Dalvik 的内部结构，例如如何查找类、方法，以及如何修改其执行流程。

**逻辑推理、假设输入与输出：**

假设我们调用 `gum_script_scheduler_push_job_on_js_thread` 来推送一个简单的任务，该任务只是打印一条消息。

**假设输入：**

- `self`: 一个有效的 `GumScriptScheduler` 实例。
- `priority`: `G_PRIORITY_DEFAULT`。
- `func`: 一个函数指针，指向以下函数：
  ```c
  void print_message(gpointer data) {
    const char* message = (const char*)data;
    g_print("%s\n", message);
  }
  ```
- `data`: 一个指向字符串 "Hello from JS thread!" 的指针。
- `data_destroy`: `NULL` (因为字符串是静态的)。

**逻辑推理：**

1. `gum_script_job_new` 会创建一个新的 `GumScriptJob` 实例，并将 `print_message` 和 "Hello from JS thread!" 作为参数存储起来。
2. `g_idle_source_new` 会创建一个新的空闲源。
3. `g_source_set_priority` 设置优先级。
4. `g_source_set_callback` 设置回调函数为 `gum_script_scheduler_perform_js_job`，并将 `GumScriptJob` 实例作为数据传递。
5. `g_source_attach` 将空闲源附加到 JavaScript 线程的 `js_context` 上。
6. 当 JavaScript 线程的主循环空闲时，`gum_script_scheduler_perform_js_job` 会被调用，它会执行 `job->func(job->data)`，即调用 `print_message("Hello from JS thread!")`。

**预期输出：**

在 Frida 的控制台或者目标进程的输出中，将会看到：

```
Hello from JS thread!
```

**用户或编程常见的使用错误及举例说明：**

1. **在错误的线程上访问 JavaScript 对象:** 用户可能会尝试在一个非 JavaScript 线程上直接调用 Frida 提供的 JavaScript API，或者访问 JavaScript 创建的对象。由于 JavaScript 代码只能在其自己的线程上安全执行，这会导致崩溃或未定义的行为。

   **错误示例 (在 C 代码中):**
   ```c
   // 假设 'global_js_object' 是在 JavaScript 中创建的全局对象
   extern JSObject *global_js_object; // 错误的做法！

   void some_thread_function() {
     // 尝试在非 JavaScript 线程上访问 JavaScript 对象
     JSValue value = JS_GetPropertyStr(js_context, global_js_object, "someProperty");
     // ... 可能会崩溃
   }
   ```
   **正确做法:**  应该使用 `gum_script_scheduler_push_job_on_js_thread` 将访问 JavaScript 对象的操作放到 JavaScript 线程上执行。

2. **忘记释放 `GumScriptJob` 的数据:** 如果在创建 `GumScriptJob` 时指定了 `data_destroy` 回调，但用户忘记提供或正确实现该回调，可能会导致内存泄漏。

   **错误示例:**
   ```c
   char* dynamic_data = g_strdup("Temporary Data");
   gum_script_scheduler_push_job_on_js_thread(scheduler, G_PRIORITY_DEFAULT, some_func, dynamic_data, NULL); // 忘记设置 data_destroy
   // ... dynamic_data 将会泄漏
   ```
   **正确做法:** 提供 `g_free` 作为 `data_destroy` 回调：
   ```c
   char* dynamic_data = g_strdup("Temporary Data");
   gum_script_scheduler_push_job_on_js_thread(scheduler, G_PRIORITY_DEFAULT, some_func, dynamic_data, g_free);
   ```

3. **在 `dispose` 之后使用调度器:** 用户可能会错误地尝试在 `GumScriptScheduler` 对象被销毁 (`dispose` 方法被调用) 后继续使用它，这会导致访问已释放的内存。

   **错误示例:**
   ```c
   GumScriptScheduler* scheduler = gum_script_scheduler_new();
   // ... 使用 scheduler ...
   g_object_unref(scheduler); // 触发 dispose

   // 稍后尝试继续使用 scheduler
   gum_script_scheduler_push_job_on_js_thread(scheduler, G_PRIORITY_DEFAULT, some_func, NULL, NULL); // 错误！scheduler 已经失效
   ```

**用户操作是如何一步步到达这里的，作为调试线索：**

当逆向工程师在使用 Frida 进行动态插桩时，`gumscriptscheduler.c` 的代码会在后台默默地工作。以下是一些可能导致执行到这个文件中的代码的步骤：

1. **编写 Frida JavaScript 脚本:**  用户首先会编写 JavaScript 代码来定义他们想要执行的插桩操作，例如 Hook 函数、修改内存等。

2. **使用 Frida 命令行工具或 API 连接到目标进程:**  用户会使用 `frida` 命令行工具或者通过编程方式（例如 Python 的 `frida` 模块）连接到他们想要分析的目标进程。

3. **加载和执行脚本:**  Frida 会将用户的 JavaScript 脚本加载到目标进程的 Frida Agent 中执行。

4. **JavaScript 代码调用 Frida API:**  用户的 JavaScript 代码会调用 Frida 提供的 API，例如 `Interceptor.attach()`, `Memory.read*()`, `Memory.write*()` 等。

5. **Frida 内部操作触发任务调度:**  当这些 JavaScript API 被调用时，Frida 的内部实现会创建需要在特定线程上执行的任务。例如：
   - 当调用 `Interceptor.attach()` 时，需要在 JavaScript 线程上创建和管理 Hook 的状态。
   - 当需要读取或写入目标进程的内存时，这些操作可以在线程池中执行。
   - 当 JavaScript 代码需要与 Frida 的 C++ 核心进行通信时，通常需要在 JavaScript 线程上执行相应的处理。

6. **调用 `gum_script_scheduler_*` 函数:**  在 Frida 的 C++ 代码中，会调用 `gum_script_scheduler_push_job_on_js_thread` 或 `gum_script_scheduler_push_job_on_thread_pool` 等函数来将这些任务添加到调度器中。

7. **任务执行:**  `gumscriptscheduler.c` 中实现的逻辑会确保这些任务在相应的线程上被执行。

**作为调试线索：**

当进行 Frida 相关的调试时，如果遇到以下情况，可能需要关注 `gumscriptscheduler.c`：

- **JavaScript 代码执行异常或崩溃:**  如果 JavaScript 代码抛出异常或者导致 Frida Agent 崩溃，可能是因为在 JavaScript 线程上执行了错误的操作，或者有任务调度方面的问题。
- **性能问题:**  如果 Frida 脚本执行缓慢，可能是因为有大量的任务被推送到 JavaScript 线程或者线程池，导致资源竞争或调度延迟。可以使用 Frida 提供的性能分析工具来查看任务调度的状况。
- **死锁或竞争条件:**  虽然 `gumscriptscheduler.c` 本身有简单的同步机制，但在复杂的 Frida 脚本中，如果涉及到多个异步操作和回调，可能会出现死锁或竞争条件。理解任务是如何被调度和执行的有助于分析这些问题。
- **内存泄漏:**  如果怀疑有内存泄漏，可以检查 `GumScriptJob` 的创建和销毁，以及 `data_destroy` 回调是否正确使用。

通过理解 `gumscriptscheduler.c` 的功能，以及用户操作如何触发其执行，逆向工程师可以更好地理解 Frida 的内部工作原理，并更有效地进行调试和问题排查。

### 提示词
```
这是目录为frida/subprojects/frida-gum/bindings/gumjs/gumscriptscheduler.c的fridaDynamic instrumentation tool的源代码文件， 请列举一下它的功能, 
如果它与逆向的方法有关系，请做出对应的举例说明，
如果涉及到二进制底层，linux, android内核及框架的知识，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明,
说明用户操作是如何一步步的到达这里，作为调试线索。
```

### 源代码
```c
/*
 * Copyright (C) 2015-2021 Ole André Vadla Ravnås <oleavr@nowsecure.com>
 *
 * Licence: wxWindows Library Licence, Version 3.1
 */

#include "gumscriptscheduler.h"

struct _GumScriptScheduler
{
  GObject parent;

  gboolean disposed;

  gboolean enable_background_thread;
  GThread * js_thread;
  GMainLoop * js_loop;
  GMainContext * js_context;
  volatile gint start_request_seqno;

  GThreadPool * thread_pool;
};

struct _GumScriptJob
{
  GumScriptJobFunc func;
  gpointer data;
  GDestroyNotify data_destroy;

  GumScriptScheduler * scheduler;
};

static void gum_script_scheduler_dispose (GObject * obj);

static gboolean gum_script_scheduler_perform_js_job (
    GumScriptJob * job);
static void gum_script_scheduler_perform_pool_job (GumScriptJob * job,
    GumScriptScheduler * self);

static gpointer gum_script_scheduler_run_js_loop (GumScriptScheduler * self);

G_DEFINE_TYPE (GumScriptScheduler, gum_script_scheduler, G_TYPE_OBJECT)

static void
gum_script_scheduler_class_init (GumScriptSchedulerClass * klass)
{
  GObjectClass * object_class = G_OBJECT_CLASS (klass);

  object_class->dispose = gum_script_scheduler_dispose;
}

static void
gum_script_scheduler_init (GumScriptScheduler * self)
{
  self->enable_background_thread = TRUE;

  self->js_context = g_main_context_new ();
}

static void
gum_script_scheduler_dispose (GObject * obj)
{
  GumScriptScheduler * self = GUM_SCRIPT_SCHEDULER (obj);

  if (!self->disposed)
  {
    self->disposed = TRUE;

    if (self->thread_pool != NULL)
    {
      g_thread_pool_free (self->thread_pool, FALSE, TRUE);
      self->thread_pool = NULL;
    }

    gum_script_scheduler_stop (self);

    g_main_context_unref (self->js_context);
    self->js_context = NULL;
  }

  G_OBJECT_CLASS (gum_script_scheduler_parent_class)->dispose (obj);
}

GumScriptScheduler *
gum_script_scheduler_new (void)
{
  return g_object_new (GUM_TYPE_SCRIPT_SCHEDULER, NULL);
}

void
gum_script_scheduler_enable_background_thread (GumScriptScheduler * self)
{
  self->enable_background_thread = TRUE;

  gum_script_scheduler_start (self);
}

void
gum_script_scheduler_disable_background_thread (GumScriptScheduler * self)
{
  gum_script_scheduler_stop (self);

  self->enable_background_thread = FALSE;
}

void
gum_script_scheduler_start (GumScriptScheduler * self)
{
  if (self->disposed)
    return;

  if (self->enable_background_thread && self->js_thread == NULL &&
      g_atomic_int_add (&self->start_request_seqno, 1) == 0)
  {
    self->js_loop = g_main_loop_new (self->js_context, TRUE);

    self->js_thread = g_thread_new ("gum-js-loop",
        (GThreadFunc) gum_script_scheduler_run_js_loop, self);
  }
}

void
gum_script_scheduler_stop (GumScriptScheduler * self)
{
  if (self->js_thread != NULL)
  {
    gum_script_scheduler_push_job_on_js_thread (self, G_PRIORITY_LOW,
        (GumScriptJobFunc) g_main_loop_quit, self->js_loop, NULL);
    g_thread_join (self->js_thread);
    self->js_thread = NULL;

    g_main_loop_unref (self->js_loop);
    self->js_loop = NULL;

    g_atomic_int_set (&self->start_request_seqno, 0);
  }
}

GMainContext *
gum_script_scheduler_get_js_context (GumScriptScheduler * self)
{
  return self->js_context;
}

void
gum_script_scheduler_push_job_on_js_thread (GumScriptScheduler * self,
                                            gint priority,
                                            GumScriptJobFunc func,
                                            gpointer data,
                                            GDestroyNotify data_destroy)
{
  GumScriptJob * job;
  GSource * source;

  job = gum_script_job_new (self, func, data, data_destroy);

  source = g_idle_source_new ();
  g_source_set_priority (source, priority);
  g_source_set_callback (source,
      (GSourceFunc) gum_script_scheduler_perform_js_job,
      job,
      (GDestroyNotify) gum_script_job_free);
  g_source_attach (source, self->js_context);
  g_source_unref (source);

  gum_script_scheduler_start (self);
}

void
gum_script_scheduler_push_job_on_thread_pool (GumScriptScheduler * self,
                                              GumScriptJobFunc func,
                                              gpointer data,
                                              GDestroyNotify data_destroy)
{
  if (self->thread_pool == NULL)
  {
    self->thread_pool = g_thread_pool_new (
        (GFunc) gum_script_scheduler_perform_pool_job,
        self,
        4,
        FALSE,
        NULL);
  }

  g_thread_pool_push (self->thread_pool,
      gum_script_job_new (self, func, data, data_destroy),
      NULL);
}

static gboolean
gum_script_scheduler_perform_js_job (GumScriptJob * job)
{
  job->func (job->data);

  return FALSE;
}

static void
gum_script_scheduler_perform_pool_job (GumScriptJob * job,
                                       GumScriptScheduler * self)
{
  job->func (job->data);

  gum_script_job_free (job);
}

static gpointer
gum_script_scheduler_run_js_loop (GumScriptScheduler * self)
{
  g_main_context_push_thread_default (self->js_context);
  g_main_loop_run (self->js_loop);
  g_main_context_pop_thread_default (self->js_context);

  return NULL;
}

GumScriptJob *
gum_script_job_new (GumScriptScheduler * scheduler,
                    GumScriptJobFunc func,
                    gpointer data,
                    GDestroyNotify data_destroy)
{
  GumScriptJob * job;

  job = g_slice_new (GumScriptJob);
  job->func = func;
  job->data = data;
  job->data_destroy = data_destroy;

  job->scheduler = scheduler;

  return job;
}

void
gum_script_job_free (GumScriptJob * job)
{
  if (job->data_destroy != NULL)
    job->data_destroy (job->data);

  g_slice_free (GumScriptJob, job);
}

void
gum_script_job_start_on_js_thread (GumScriptJob * job)
{
  GMainContext * js_context = job->scheduler->js_context;

  if (g_main_context_is_owner (js_context))
  {
    job->func (job->data);
  }
  else
  {
    GSource * source;

    source = g_idle_source_new ();
    g_source_set_callback (source,
        (GSourceFunc) gum_script_scheduler_perform_js_job,
        job,
        NULL);
    g_source_attach (source, js_context);
    g_source_unref (source);

    gum_script_scheduler_start (job->scheduler);
  }
}
```