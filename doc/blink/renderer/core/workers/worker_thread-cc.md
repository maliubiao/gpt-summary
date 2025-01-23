Response:
My thinking process to analyze the `WorkerThread.cc` file and generate the summary goes like this:

1. **Understand the Goal:** The request asks for a summary of the `WorkerThread.cc` file's functionality, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning (input/output), common user/programming errors, and a general conclusion for this first part of the file.

2. **Initial Scan for Key Concepts:** I quickly scanned the code for prominent keywords, class names, and included headers. This gave me a high-level overview:
    * `WorkerThread`: The central class.
    * Includes related to threading (`base/threading`, `base/synchronization`), task scheduling (`base/task`, `third_party/blink/renderer/platform/scheduler`), and V8 (`third_party/blink/renderer/bindings/core/v8`).
    * Mentions of inspector (`third_party/blink/renderer/core/inspector`), loading (`third_party/blink/public/common/loader`), and global scope (`third_party/blink/renderer/core/workers/global_scope`).
    * References to JavaScript execution (`EvaluateClassicScript`, `FetchAndRunClassicScript`, `FetchAndRunModuleScript`).
    * Keywords like `Terminate`, `Pause`, `Resume`, `Shutdown`.

3. **Focus on the `WorkerThread` Class:** I recognized this as the core component and started analyzing its methods and member variables. I looked for:
    * **Lifecycle Methods:** `Start`, `Terminate`, the destructor `~WorkerThread`, `Pause`, `Freeze`, `Resume`. These indicate control over the worker's lifespan.
    * **Script Execution Methods:** `EvaluateClassicScript`, `FetchAndRunClassicScript`, `FetchAndRunModuleScript`. These are clearly related to JavaScript.
    * **State Management:**  Variables like `thread_state_`, `exit_code_`, `requested_to_terminate_`, `pause_or_freeze_count_`. These help track the worker's current state.
    * **Threading Primitives:**  `base::Lock`, `base::WaitableEvent`. These manage concurrency.
    * **Communication with Parent:**  Methods using `PostCrossThreadTask` suggest interaction with the main browser thread.
    * **Inspector Integration:**  Members like `worker_inspector_controller_`, methods related to debugging.

4. **Identify Core Functionalities:** Based on the method analysis, I started grouping related actions:
    * **Thread Management:** Creating, starting, stopping, pausing, resuming the worker thread.
    * **JavaScript Execution:** Loading and running JavaScript code (classic and modules).
    * **Communication:** Interacting with the main thread and potentially child workers.
    * **Debugging:** Supporting debugging through the Inspector.
    * **Resource Management:**  Handling the worker's global scope and associated resources.
    * **Lifecycle Management:** Managing the different phases of the worker's existence (initialization, running, termination).

5. **Relate to Web Technologies:** I specifically looked for connections to JavaScript, HTML, and CSS.
    * **JavaScript:** The `Evaluate...` and `FetchAndRun...` methods directly deal with running JavaScript. The file mentions `WorkerGlobalScope`, which is the JavaScript global object for workers.
    * **HTML:** While this specific file doesn't directly manipulate the DOM (which is primarily on the main thread), it's responsible for executing the JavaScript that *might* eventually interact with the DOM (through message passing or shared workers). The loading of scripts via URLs also links to HTML `<script>` tags or similar mechanisms.
    * **CSS:**  Similar to HTML, this file doesn't directly handle CSS rendering. However, the loaded JavaScript could fetch or manipulate CSS through APIs (though less common within workers compared to the main thread).

6. **Consider Logical Reasoning (Input/Output):** I thought about the flow of data:
    * **Input:** URLs of scripts, source code, parameters for script loading, commands to pause/terminate.
    * **Output:**  While the code doesn't directly *return* values in many cases, its actions *result* in: JavaScript code being executed, messages being sent, the worker's state changing, and potentially errors or debugging information.

7. **Identify Potential User/Programming Errors:**  I looked for areas where incorrect usage could lead to problems:
    * **Premature Termination:** Calling `Terminate` unexpectedly.
    * **Concurrency Issues:**  Although the file uses locks, incorrect use of shared resources from within the worker's JavaScript could still lead to problems.
    * **Not Handling Termination Signals:** The worker needs to gracefully handle termination requests.

8. **Synthesize the Summary for Part 1:** I focused on the major functionalities evident in the first part of the code. I prioritized the creation, initialization, script loading, and the basic lifecycle management (start, pause, terminate). I made sure to include the relationship to JavaScript and the role in offloading tasks from the main thread.

9. **Review and Refine:** I reread my summary and compared it back to the code snippet to ensure accuracy and completeness within the scope of the provided text. I looked for clearer wording and better organization. I ensured that the language was accessible and explained the technical concepts without being overly simplistic.

This iterative process of scanning, focusing, analyzing, grouping, relating, and synthesizing allowed me to break down the complex code into a comprehensive and understandable summary. The emphasis on linking the code to web technologies and considering potential errors helped make the explanation more practical.
好的，这是对 `blink/renderer/core/workers/worker_thread.cc` 文件第一部分功能的总结：

**功能概述:**

`WorkerThread.cc` 文件的核心功能是**管理和控制独立的 worker 线程的生命周期和执行环境**。它负责创建、启动、暂停、恢复和终止 worker 线程，并在这些线程上执行 JavaScript 代码。  该文件是 Blink 渲染引擎中处理 Web Workers 的关键组件。

**具体功能点:**

1. **Worker 线程的创建和启动:**
   - `WorkerThread` 类代表一个独立的 worker 线程。
   - `Start()` 方法负责初始化 worker 线程，包括创建 worker 线程的调度器、初始化 worker 线程上的环境（如 `WorkerGlobalScope`），并准备执行 JavaScript 代码。
   - 它涉及到 `WorkerBackingThread` 的使用，后者是实际执行 worker 线程的底层线程。

2. **JavaScript 代码的执行:**
   - 提供了多个方法来在 worker 线程上执行 JavaScript 代码：
     - `EvaluateClassicScript()`:  执行内联的或者通过 URL 加载的经典 JavaScript 代码。
     - `FetchAndRunClassicScript()`: 从指定 URL 获取并执行经典 JavaScript 代码。
     - `FetchAndRunModuleScript()`: 从指定 URL 获取并执行 JavaScript 模块代码。

3. **Worker 线程的生命周期管理:**
   - `Pause()` 和 `Freeze()`: 暂停 worker 线程的执行。`Freeze()`  通常用于将 worker 线程放入后退/前进缓存中。
   - `Resume()`: 恢复已暂停的 worker 线程的执行。
   - `Terminate()`:  请求终止 worker 线程的执行。这会触发 worker 线程上的清理和关闭过程。
   - `PerformShutdownOnWorkerThread()`: 在 worker 线程上执行实际的关闭操作。

4. **与主线程的通信:**
   - 使用 `PostCrossThreadTask()` 将任务投递到 worker 线程上执行，实现主线程与 worker 线程之间的通信。

5. **集成开发者工具 (Inspector):**
   - 包含了与 Chrome 开发者工具集成的功能，例如：
     - `WorkerDevToolsParams`:  传递开发者工具相关的参数。
     - `WorkerInspectorController`:  控制 worker 线程的调试。
     - `WorkerThreadDebugger`:  提供 worker 线程的调试能力。

6. **资源管理:**
   - 管理 worker 线程的调度器 (`scheduler::WorkerScheduler`) 和任务队列。
   - 管理 worker 线程的全局作用域 (`WorkerGlobalScope`)。

7. **错误处理和终止:**
   - 提供了强制终止 worker 线程执行的能力 (`EnsureScriptExecutionTerminates()`)，以应对 worker 线程无响应的情况。

**与 JavaScript, HTML, CSS 的关系及举例:**

- **JavaScript:**
    - **例子:** `EvaluateClassicScript()` 方法用于执行 JavaScript 代码。假设用户在 HTML 中创建了一个 Worker 并向其发送了一段 JavaScript 代码字符串：
      ```javascript
      const worker = new Worker('worker.js');
      worker.postMessage('console.log("Hello from worker!");');
      ```
      Blink 引擎会调用 `EvaluateClassicScript()` (或者类似的方法) 在 worker 线程上执行 `console.log("Hello from worker!");` 这段 JavaScript 代码。
    - **关系:**  `WorkerThread` 的主要职责之一就是执行 JavaScript 代码，这是 Web Workers 的核心功能。

- **HTML:**
    - **例子:**  当 HTML 页面创建一个新的 Worker 时，例如 `<script> const worker = new Worker('my-worker.js'); </script>`, Blink 引擎会创建并启动一个新的 `WorkerThread` 来加载和执行 `my-worker.js` 中的代码。
    - **关系:** `WorkerThread` 的创建通常由主线程上的 JavaScript 代码（通过 `new Worker()` 构造函数）触发，而这些 JavaScript 代码通常嵌入在 HTML 页面中。

- **CSS:**
    - **关系比较间接:**  `WorkerThread` 本身不直接处理 CSS 渲染。然而，在 worker 线程中运行的 JavaScript 代码 *可能* 会影响到主线程上的 CSS，例如通过 `postMessage` 将数据传递回主线程，主线程上的脚本再根据这些数据动态修改样式。
    - **例子:**  一个 worker 线程可以执行计算密集型的任务，例如解析大型 CSS 文件的一部分数据，并将结果发送回主线程，主线程根据这些结果应用特定的样式规则。

**逻辑推理的假设输入与输出:**

假设输入：主线程调用 `workerThread->Terminate()`。

逻辑推理过程：

1. `Terminate()` 方法被调用，设置 `requested_to_terminate_` 标记为 true。
2. 启动一个定时任务 (`ScheduleToTerminateScriptExecution()`)，以在一定延迟后强制终止脚本执行，作为安全措施。
3. `PrepareForShutdownOnWorkerThread()` 任务被投递到 worker 线程，开始清理 worker 线程的环境。
4. `PerformShutdownOnWorkerThread()` 任务被投递到 worker 线程，执行最终的关闭操作。

假设输出：worker 线程停止执行 JavaScript 代码，相关的资源被释放，该 `WorkerThread` 对象最终被销毁。

**用户或编程常见的使用错误举例:**

1. **忘记终止 Worker:**  如果用户创建了一个 Worker 但忘记在不再需要时调用 `worker.terminate()`，可能导致 worker 线程持续运行，消耗资源。
2. **在 Worker 线程中访问 DOM:**  Worker 线程无法直接访问主线程的 DOM。尝试这样做会导致错误。例如，在 worker 线程中执行 `document.getElementById('myElement')` 会返回 `null` 或抛出异常。
3. **在主线程和 Worker 线程之间传递不可序列化的数据:**  `postMessage` API 用于在主线程和 worker 线程之间通信，但传递的数据需要是可序列化的。尝试传递不可序列化的对象（例如包含闭包的函数）会导致错误。
4. **过度依赖 Worker 线程进行 DOM 操作:** 虽然 Worker 可以执行一些计算并将结果传递回主线程进行 DOM 更新，但过度依赖 Worker 进行密集的 DOM 操作通常不是最佳实践，因为 DOM 操作主要应在主线程上进行。

**本部分功能归纳:**

这部分代码主要关注 `WorkerThread` 类的定义和与 worker 线程生命周期管理、JavaScript 执行以及与主线程通信相关的核心功能。它搭建了 worker 线程的基础架构，使其能够独立于主线程执行 JavaScript 代码，从而提高 Web 应用的性能和响应速度。  同时，它也初步涉及了与开发者工具的集成，为调试 worker 线程提供了支持。

### 提示词
```
这是目录为blink/renderer/core/workers/worker_thread.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
/*
 * Copyright (C) 2008 Apple Inc. All Rights Reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE COMPUTER, INC. ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL APPLE COMPUTER, INC. OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY
 * OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include "third_party/blink/renderer/core/workers/worker_thread.h"

#include <limits>
#include <memory>
#include <utility>

#include "base/metrics/histogram_functions.h"
#include "base/synchronization/lock.h"
#include "base/synchronization/waitable_event.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/thread_restrictions.h"
#include "third_party/blink/public/common/loader/worker_main_script_load_parameters.h"
#include "third_party/blink/public/mojom/frame/lifecycle.mojom-shared.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/public/platform/task_type.h"
#include "third_party/blink/renderer/bindings/core/v8/worker_or_worklet_script_controller.h"
#include "third_party/blink/renderer/core/execution_context/agent.h"
#include "third_party/blink/renderer/core/frame/policy_container.h"
#include "third_party/blink/renderer/core/inspector/console_message_storage.h"
#include "third_party/blink/renderer/core/inspector/inspector_issue_storage.h"
#include "third_party/blink/renderer/core/inspector/inspector_task_runner.h"
#include "third_party/blink/renderer/core/inspector/worker_devtools_params.h"
#include "third_party/blink/renderer/core/inspector/worker_inspector_controller.h"
#include "third_party/blink/renderer/core/inspector/worker_thread_debugger.h"
#include "third_party/blink/renderer/core/loader/worker_resource_timing_notifier_impl.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/core/workers/cross_thread_global_scope_creation_params_copier.h"
#include "third_party/blink/renderer/core/workers/global_scope_creation_params.h"
#include "third_party/blink/renderer/core/workers/worker_backing_thread.h"
#include "third_party/blink/renderer/core/workers/worker_clients.h"
#include "third_party/blink/renderer/core/workers/worker_global_scope.h"
#include "third_party/blink/renderer/core/workers/worker_reporting_proxy.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/loader/fetch/fetch_client_settings_object_snapshot.h"
#include "third_party/blink/renderer/platform/loader/fetch/worker_resource_timing_notifier.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/worker_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/worker/non_main_thread_impl.h"
#include "third_party/blink/renderer/platform/scheduler/worker/worker_thread_scheduler.h"
#include "third_party/blink/renderer/platform/weborigin/kurl.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_copier_std.h"
#include "third_party/blink/renderer/platform/wtf/cross_thread_functional.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/blink/renderer/platform/wtf/text/wtf_string.h"
#include "third_party/blink/renderer/platform/wtf/threading.h"

namespace blink {

using ExitCode = WorkerThread::ExitCode;

namespace {

constexpr base::TimeDelta kForcibleTerminationDelay = base::Seconds(2);

}  // namespace

base::Lock& WorkerThread::ThreadSetLock() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(base::Lock, lock, ());
  return lock;
}

static std::atomic_int g_unique_worker_thread_id(1);

static int GetNextWorkerThreadId() {
  int next_worker_thread_id =
      g_unique_worker_thread_id.fetch_add(1, std::memory_order_relaxed);
  CHECK_LT(next_worker_thread_id, std::numeric_limits<int>::max());
  return next_worker_thread_id;
}

// RefCountedWaitableEvent makes WaitableEvent thread-safe refcounted.
// WorkerThread retains references to the event from both the parent context
// thread and the worker thread with this wrapper. See
// WorkerThread::PerformShutdownOnWorkerThread() for details.
class WorkerThread::RefCountedWaitableEvent
    : public WTF::ThreadSafeRefCounted<RefCountedWaitableEvent> {
 public:
  static scoped_refptr<RefCountedWaitableEvent> Create() {
    return base::AdoptRef<RefCountedWaitableEvent>(new RefCountedWaitableEvent);
  }

  RefCountedWaitableEvent(const RefCountedWaitableEvent&) = delete;
  RefCountedWaitableEvent& operator=(const RefCountedWaitableEvent&) = delete;

  void Wait() { event_.Wait(); }
  void Signal() { event_.Signal(); }

 private:
  RefCountedWaitableEvent() = default;

  base::WaitableEvent event_;
};

// A class that is passed into V8 Interrupt and via a PostTask. Once both have
// run this object will be destroyed in
// PauseOrFreezeWithInterruptDataOnWorkerThread. The V8 API only takes a raw ptr
// otherwise this could have been done with WTF::Bind and ref counted objects.
class WorkerThread::InterruptData {
 public:
  InterruptData(WorkerThread* worker_thread,
                mojom::blink::FrameLifecycleState state,
                bool is_in_back_forward_cache)
      : worker_thread_(worker_thread),
        state_(state),
        is_in_back_forward_cache_(is_in_back_forward_cache) {
    DCHECK(!is_in_back_forward_cache ||
           state == mojom::blink::FrameLifecycleState::kFrozen);
  }

  InterruptData(const InterruptData&) = delete;
  InterruptData& operator=(const InterruptData&) = delete;

  bool ShouldRemoveFromList() { return seen_interrupt_ && seen_post_task_; }
  void MarkPostTaskCalled() { seen_post_task_ = true; }
  void MarkInterruptCalled() { seen_interrupt_ = true; }

  mojom::blink::FrameLifecycleState state() { return state_; }
  WorkerThread* worker_thread() { return worker_thread_; }
  bool is_in_back_forward_cache() const { return is_in_back_forward_cache_; }

 private:
  WorkerThread* worker_thread_;
  mojom::blink::FrameLifecycleState state_;
  bool is_in_back_forward_cache_;
  bool seen_interrupt_ = false;
  bool seen_post_task_ = false;
};

WorkerThread::~WorkerThread() {
  DCHECK_CALLED_ON_VALID_THREAD(parent_thread_checker_);
  base::AutoLock locker(ThreadSetLock());
  DCHECK(InitializingWorkerThreads().Contains(this) ||
         WorkerThreads().Contains(this));
  InitializingWorkerThreads().erase(this);
  WorkerThreads().erase(this);

  DCHECK(child_threads_.empty());
  DCHECK_NE(ExitCode::kNotTerminated, exit_code_);
}

void WorkerThread::Start(
    std::unique_ptr<GlobalScopeCreationParams> global_scope_creation_params,
    const std::optional<WorkerBackingThreadStartupData>& thread_startup_data,
    std::unique_ptr<WorkerDevToolsParams> devtools_params) {
  DCHECK_CALLED_ON_VALID_THREAD(parent_thread_checker_);
  devtools_worker_token_ = devtools_params->devtools_worker_token;

  // Synchronously initialize the per-global-scope scheduler to prevent someone
  // from posting a task to the thread before the scheduler is ready.
  base::WaitableEvent waitable_event;
  PostCrossThreadTask(
      *GetWorkerBackingThread().BackingThread().GetTaskRunner(), FROM_HERE,
      CrossThreadBindOnce(&WorkerThread::InitializeSchedulerOnWorkerThread,
                          CrossThreadUnretained(this),
                          CrossThreadUnretained(&waitable_event)));
  {
    base::ScopedAllowBaseSyncPrimitives allow_wait;
    waitable_event.Wait();
  }

  inspector_task_runner_ =
      InspectorTaskRunner::Create(GetTaskRunner(TaskType::kInternalInspector));

  PostCrossThreadTask(
      *GetWorkerBackingThread().BackingThread().GetTaskRunner(), FROM_HERE,
      CrossThreadBindOnce(&WorkerThread::InitializeOnWorkerThread,
                          CrossThreadUnretained(this),
                          std::move(global_scope_creation_params),
                          IsOwningBackingThread() ?
                              thread_startup_data : std::nullopt,
                          std::move(devtools_params)));
}

void WorkerThread::EvaluateClassicScript(
    const KURL& script_url,
    const String& source_code,
    std::unique_ptr<Vector<uint8_t>> cached_meta_data,
    const v8_inspector::V8StackTraceId& stack_id) {
  DCHECK_CALLED_ON_VALID_THREAD(parent_thread_checker_);
  PostCrossThreadTask(
      *GetTaskRunner(TaskType::kDOMManipulation), FROM_HERE,
      CrossThreadBindOnce(&WorkerThread::EvaluateClassicScriptOnWorkerThread,
                          CrossThreadUnretained(this), script_url, source_code,
                          std::move(cached_meta_data), stack_id));
}

void WorkerThread::FetchAndRunClassicScript(
    const KURL& script_url,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    std::unique_ptr<WebPolicyContainer> policy_container,
    std::unique_ptr<CrossThreadFetchClientSettingsObjectData>
        outside_settings_object_data,
    WorkerResourceTimingNotifier* outside_resource_timing_notifier,
    const v8_inspector::V8StackTraceId& stack_id) {
  DCHECK_CALLED_ON_VALID_THREAD(parent_thread_checker_);
  PostCrossThreadTask(
      *GetTaskRunner(TaskType::kDOMManipulation), FROM_HERE,
      CrossThreadBindOnce(
          &WorkerThread::FetchAndRunClassicScriptOnWorkerThread,
          CrossThreadUnretained(this), script_url,
          std::move(worker_main_script_load_params),
          std::move(policy_container), std::move(outside_settings_object_data),
          WrapCrossThreadPersistent(outside_resource_timing_notifier),
          stack_id));
}

void WorkerThread::FetchAndRunModuleScript(
    const KURL& script_url,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    std::unique_ptr<WebPolicyContainer> policy_container,
    std::unique_ptr<CrossThreadFetchClientSettingsObjectData>
        outside_settings_object_data,
    WorkerResourceTimingNotifier* outside_resource_timing_notifier,
    network::mojom::CredentialsMode credentials_mode,
    RejectCoepUnsafeNone reject_coep_unsafe_none) {
  DCHECK_CALLED_ON_VALID_THREAD(parent_thread_checker_);
  PostCrossThreadTask(
      *GetTaskRunner(TaskType::kDOMManipulation), FROM_HERE,
      CrossThreadBindOnce(
          &WorkerThread::FetchAndRunModuleScriptOnWorkerThread,
          CrossThreadUnretained(this), script_url,
          std::move(worker_main_script_load_params),
          std::move(policy_container), std::move(outside_settings_object_data),
          WrapCrossThreadPersistent(outside_resource_timing_notifier),
          credentials_mode, reject_coep_unsafe_none.value()));
}

void WorkerThread::Pause() {
  PauseOrFreeze(mojom::blink::FrameLifecycleState::kPaused, false);
}

void WorkerThread::Freeze(bool is_in_back_forward_cache) {
  PauseOrFreeze(mojom::blink::FrameLifecycleState::kFrozen,
                is_in_back_forward_cache);
}

void WorkerThread::Resume() {
  // Might be called from any thread.
  if (IsCurrentThread()) {
    ResumeOnWorkerThread();
  } else {
    PostCrossThreadTask(
        *GetWorkerBackingThread().BackingThread().GetTaskRunner(), FROM_HERE,
        CrossThreadBindOnce(&WorkerThread::ResumeOnWorkerThread,
                            CrossThreadUnretained(this)));
  }
}

void WorkerThread::Terminate() {
  DCHECK_CALLED_ON_VALID_THREAD(parent_thread_checker_);
  {
    base::AutoLock locker(lock_);
    if (requested_to_terminate_)
      return;
    requested_to_terminate_ = true;
  }

  // Schedule a task to forcibly terminate the script execution in case that the
  // shutdown sequence does not start on the worker thread in a certain time
  // period.
  ScheduleToTerminateScriptExecution();

  inspector_task_runner_->Dispose();

  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetWorkerBackingThread().BackingThread().GetTaskRunner();
  PostCrossThreadTask(
      *task_runner, FROM_HERE,
      CrossThreadBindOnce(&WorkerThread::PrepareForShutdownOnWorkerThread,
                          CrossThreadUnretained(this)));
  PostCrossThreadTask(
      *task_runner, FROM_HERE,
      CrossThreadBindOnce(&WorkerThread::PerformShutdownOnWorkerThread,
                          CrossThreadUnretained(this)));
}

void WorkerThread::TerminateForTesting() {
  // Schedule a regular async worker thread termination task, and forcibly
  // terminate the V8 script execution to ensure the task runs.
  Terminate();
  EnsureScriptExecutionTerminates(ExitCode::kSyncForciblyTerminated);
}

void WorkerThread::WillProcessTask(const base::PendingTask& pending_task,
                                   bool was_blocked_or_low_priority) {
  DCHECK(IsCurrentThread());

  // No tasks should get executed after we have closed.
  DCHECK(!GlobalScope()->IsClosing());
}

void WorkerThread::DidProcessTask(const base::PendingTask& pending_task) {
  DCHECK(IsCurrentThread());

  // TODO(tzik): Move this to WorkerThreadScheduler::OnTaskCompleted(), so that
  // metrics for microtasks are counted as a part of the preceding task.
  GlobalScope()->GetAgent()->event_loop()->PerformMicrotaskCheckpoint();

  // EventLoop::PerformIsolateGlobalMicrotasksCheckpoint() runs microtasks and
  // its completion hooks for the default microtask queue. The default queue may
  // contain the microtasks queued by V8 itself, and legacy
  // blink::MicrotaskQueue::EnqueueMicrotask. The completion hook contains
  // IndexedDB clean-up task, as described at
  // https://html.spec.whatwg.org/C#perform-a-microtask-checkpoint
  // TODO(tzik): Move rejected promise handling to EventLoop.

  GlobalScope()->ScriptController()->GetRejectedPromises()->ProcessQueue();
  if (GlobalScope()->IsClosing()) {
    // This WorkerThread will eventually be requested to terminate.
    GetWorkerReportingProxy().DidCloseWorkerGlobalScope();

    // Stop further worker tasks to run after this point based on the spec:
    // https://html.spec.whatwg.org/C/#close-a-worker
    //
    // "To close a worker, given a workerGlobal, run these steps:"
    // Step 1: "Discard any tasks that have been added to workerGlobal's event
    // loop's task queues."
    // Step 2: "Set workerGlobal's closing flag to true. (This prevents any
    // further tasks from being queued.)"
    PrepareForShutdownOnWorkerThread();
  } else if (IsForciblyTerminated()) {
    // The script has been terminated forcibly, which means we need to
    // ask objects in the thread to stop working as soon as possible.
    PrepareForShutdownOnWorkerThread();
  }
}

v8::Isolate* WorkerThread::GetIsolate() {
  return GetWorkerBackingThread().GetIsolate();
}

bool WorkerThread::IsCurrentThread() {
  return GetWorkerBackingThread().BackingThread().IsCurrentThread();
}

void WorkerThread::DebuggerTaskStarted() {
  base::AutoLock locker(lock_);
  DCHECK(IsCurrentThread());
  debugger_task_counter_++;
}

void WorkerThread::DebuggerTaskFinished() {
  base::AutoLock locker(lock_);
  DCHECK(IsCurrentThread());
  debugger_task_counter_--;
}

WorkerOrWorkletGlobalScope* WorkerThread::GlobalScope() {
  DCHECK(IsCurrentThread());
  return global_scope_.Get();
}

WorkerInspectorController* WorkerThread::GetWorkerInspectorController() {
  DCHECK(IsCurrentThread());
  return worker_inspector_controller_.Get();
}

unsigned WorkerThread::WorkerThreadCount() {
  base::AutoLock locker(ThreadSetLock());
  return InitializingWorkerThreads().size() + WorkerThreads().size();
}

HashSet<WorkerThread*>& WorkerThread::InitializingWorkerThreads() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(HashSet<WorkerThread*>, threads, ());
  return threads;
}

HashSet<WorkerThread*>& WorkerThread::WorkerThreads() {
  DEFINE_THREAD_SAFE_STATIC_LOCAL(HashSet<WorkerThread*>, threads, ());
  return threads;
}

bool WorkerThread::IsForciblyTerminated() {
  base::AutoLock locker(lock_);
  switch (exit_code_) {
    case ExitCode::kNotTerminated:
    case ExitCode::kGracefullyTerminated:
      return false;
    case ExitCode::kSyncForciblyTerminated:
    case ExitCode::kAsyncForciblyTerminated:
      return true;
  }
  NOTREACHED() << static_cast<int>(exit_code_);
}

void WorkerThread::WaitForShutdownForTesting() {
  DCHECK_CALLED_ON_VALID_THREAD(parent_thread_checker_);
  base::ScopedAllowBaseSyncPrimitives allow_wait;
  shutdown_event_->Wait();
}

ExitCode WorkerThread::GetExitCodeForTesting() {
  base::AutoLock locker(lock_);
  return exit_code_;
}

scheduler::WorkerScheduler* WorkerThread::GetScheduler() {
  DCHECK(IsCurrentThread());
  return worker_scheduler_.get();
}

scoped_refptr<base::SingleThreadTaskRunner> WorkerThread::GetTaskRunner(
    TaskType type) {
  // Task runners must be captured when the worker scheduler is initialized. See
  // comments in InitializeSchedulerOnWorkerThread().
  CHECK(worker_task_runners_.Contains(type)) << static_cast<int>(type);
  return worker_task_runners_.at(type);
}

void WorkerThread::ChildThreadStartedOnWorkerThread(WorkerThread* child) {
  DCHECK(IsCurrentThread());
#if DCHECK_IS_ON()
  {
    base::AutoLock locker(lock_);
    DCHECK_EQ(ThreadState::kRunning, thread_state_);
  }
#endif
  child_threads_.insert(child);
}

void WorkerThread::ChildThreadTerminatedOnWorkerThread(WorkerThread* child) {
  DCHECK(IsCurrentThread());
  child_threads_.erase(child);
  if (child_threads_.empty() && CheckRequestedToTerminate())
    PerformShutdownOnWorkerThread();
}

WorkerThread::WorkerThread(WorkerReportingProxy& worker_reporting_proxy)
    : WorkerThread(worker_reporting_proxy,
                   ThreadScheduler::Current()->CleanupTaskRunner()) {}

WorkerThread::WorkerThread(WorkerReportingProxy& worker_reporting_proxy,
                           scoped_refptr<base::SingleThreadTaskRunner>
                               parent_thread_default_task_runner)
    : time_origin_(base::TimeTicks::Now()),
      worker_thread_id_(GetNextWorkerThreadId()),
      forcible_termination_delay_(kForcibleTerminationDelay),
      worker_reporting_proxy_(worker_reporting_proxy),
      parent_thread_default_task_runner_(
          std::move(parent_thread_default_task_runner)),
      shutdown_event_(RefCountedWaitableEvent::Create()) {
  DCHECK_CALLED_ON_VALID_THREAD(parent_thread_checker_);
  base::AutoLock locker(ThreadSetLock());
  InitializingWorkerThreads().insert(this);
}

void WorkerThread::ScheduleToTerminateScriptExecution() {
  DCHECK_CALLED_ON_VALID_THREAD(parent_thread_checker_);
  DCHECK(!forcible_termination_task_handle_.IsActive());
  // It's safe to post a task bound with |this| to the parent thread default
  // task runner because this task is canceled on the destructor of this
  // class on the parent thread.
  forcible_termination_task_handle_ = PostDelayedCancellableTask(
      *parent_thread_default_task_runner_, FROM_HERE,
      WTF::BindOnce(&WorkerThread::EnsureScriptExecutionTerminates,
                    WTF::Unretained(this), ExitCode::kAsyncForciblyTerminated),
      forcible_termination_delay_);
}

WorkerThread::TerminationState WorkerThread::ShouldTerminateScriptExecution() {
  DCHECK_CALLED_ON_VALID_THREAD(parent_thread_checker_);
  switch (thread_state_) {
    case ThreadState::kNotStarted:
      // Shutdown sequence will surely start during initialization sequence
      // on the worker thread. Don't have to schedule a termination task.
      return TerminationState::kTerminationUnnecessary;
    case ThreadState::kRunning:
      // Terminating during debugger task may lead to crash due to heavy use
      // of v8 api in debugger. Any debugger task is guaranteed to finish, so
      // we can wait for the completion.
      return debugger_task_counter_ > 0 ? TerminationState::kPostponeTerminate
                                        : TerminationState::kTerminate;
    case ThreadState::kReadyToShutdown:
      // Shutdown sequence might have started in a nested event loop but
      // JS might continue running after it exits the nested loop.
      return exit_code_ == ExitCode::kNotTerminated
                 ? TerminationState::kTerminate
                 : TerminationState::kTerminationUnnecessary;
  }
  NOTREACHED();
}

void WorkerThread::EnsureScriptExecutionTerminates(ExitCode exit_code) {
  DCHECK_CALLED_ON_VALID_THREAD(parent_thread_checker_);
  base::AutoLock locker(lock_);
  switch (ShouldTerminateScriptExecution()) {
    case TerminationState::kTerminationUnnecessary:
      return;
    case TerminationState::kTerminate:
      break;
    case TerminationState::kPostponeTerminate:
      ScheduleToTerminateScriptExecution();
      return;
  }

  DCHECK(exit_code == ExitCode::kSyncForciblyTerminated ||
         exit_code == ExitCode::kAsyncForciblyTerminated);
  SetExitCode(exit_code);

  GetIsolate()->TerminateExecution();
  forcible_termination_task_handle_.Cancel();
}

void WorkerThread::InitializeSchedulerOnWorkerThread(
    base::WaitableEvent* waitable_event) {
  DCHECK(IsCurrentThread());
  DCHECK(!worker_scheduler_);

  // TODO(hajimehoshi, nhiroki): scheduler::NonMainThreadImpl and scheduler::
  // WorkerThreadScheduler are not in scheduler/public, then using them is a
  // layer violation. Fix this.
  auto& worker_thread = static_cast<scheduler::NonMainThreadImpl&>(
      GetWorkerBackingThread().BackingThread());
  worker_scheduler_ = scheduler::WorkerScheduler::CreateWorkerScheduler(
      static_cast<scheduler::WorkerThreadScheduler*>(
          worker_thread.GetNonMainThreadScheduler()),
      worker_thread.worker_scheduler_proxy());

  // Capture the worker task runners so that it's safe to access GetTaskRunner()
  // from any threads even after the worker scheduler is disposed of on the
  // worker thread. See also comments on GetTaskRunner().
  // We only capture task types that are actually used. When you want to use a
  // new task type, add it here.
  static constexpr TaskType kAvailableTaskTypes[] = {
      TaskType::kBackgroundFetch,
      TaskType::kCanvasBlobSerialization,
      TaskType::kDatabaseAccess,
      TaskType::kDOMManipulation,
      TaskType::kFileReading,
      TaskType::kFontLoading,
      TaskType::kInternalDefault,
      TaskType::kInternalInspector,
      TaskType::kInternalLoading,
      TaskType::kInternalMedia,
      TaskType::kInternalMediaRealTime,
      TaskType::kInternalTest,
      TaskType::kInternalWebCrypto,
      TaskType::kJavascriptTimerImmediate,
      TaskType::kJavascriptTimerDelayedLowNesting,
      TaskType::kJavascriptTimerDelayedHighNesting,
      TaskType::kMediaElementEvent,
      TaskType::kMachineLearning,
      TaskType::kMicrotask,
      TaskType::kMiscPlatformAPI,
      TaskType::kNetworking,
      TaskType::kNetworkingUnfreezable,
      TaskType::kPerformanceTimeline,
      TaskType::kPermission,
      TaskType::kPostedMessage,
      TaskType::kRemoteEvent,
      TaskType::kStorage,
      TaskType::kUserInteraction,
      TaskType::kWakeLock,
      TaskType::kWebGL,
      TaskType::kWebGPU,
      TaskType::kWebLocks,
      TaskType::kWebSocket,
      TaskType::kWorkerAnimation};
  worker_task_runners_.ReserveCapacityForSize(std::size(kAvailableTaskTypes));
  for (auto type : kAvailableTaskTypes) {
    auto task_runner = worker_scheduler_->GetTaskRunner(type);
    auto result = worker_task_runners_.insert(type, std::move(task_runner));
    DCHECK(result.is_new_entry);
  }

  waitable_event->Signal();
}

void WorkerThread::InitializeOnWorkerThread(
    std::unique_ptr<GlobalScopeCreationParams> global_scope_creation_params,
    const std::optional<WorkerBackingThreadStartupData>& thread_startup_data,
    std::unique_ptr<WorkerDevToolsParams> devtools_params) {
  base::ElapsedTimer timer;
  DCHECK(IsCurrentThread());
  backing_thread_weak_factory_.emplace(this);
  worker_reporting_proxy_.WillInitializeWorkerContext();
  {
    TRACE_EVENT0("blink.worker", "WorkerThread::InitializeWorkerContext");
    base::AutoLock locker(lock_);
    DCHECK_EQ(ThreadState::kNotStarted, thread_state_);

    if (IsOwningBackingThread()) {
      global_scope_creation_params->is_default_world_of_isolate = true;
      DCHECK(thread_startup_data.has_value());
      GetWorkerBackingThread().InitializeOnBackingThread(*thread_startup_data);
    } else {
      DCHECK(!thread_startup_data.has_value());
    }
    GetWorkerBackingThread().BackingThread().AddTaskObserver(this);

    // TODO(crbug.com/866666): Ideally this URL should be the response URL of
    // the worker top-level script, while currently can be the request URL
    // for off-the-main-thread top-level script fetch cases.
    const KURL url_for_debugger = global_scope_creation_params->script_url;

    console_message_storage_ = MakeGarbageCollected<ConsoleMessageStorage>();
    // Record this only for the DedicatedWorker.
    if (global_scope_creation_params->dedicated_worker_start_time.has_value()) {
      base::UmaHistogramTimes(
          "Worker.TopLevelScript.Initialization2GlobalScopeCreation",
          timer.Elapsed());
    }
    global_scope_ =
        CreateWorkerGlobalScope(std::move(global_scope_creation_params));
    worker_scheduler_->InitializeOnWorkerThread(global_scope_);
    worker_reporting_proxy_.DidCreateWorkerGlobalScope(GlobalScope());

    worker_inspector_controller_ = WorkerInspectorController::Create(
        this, url_for_debugger, inspector_task_runner_,
        std::move(devtools_params));

    // Since context initialization below may fail, we should notify debugger
    // about the new worker thread separately, so that it can resolve it by id
    // at any moment.
    if (WorkerThreadDebugger* debugger =
            WorkerThreadDebugger::From(GetIsolate()))
      debugger->WorkerThreadCreated(this);

    GlobalScope()->ScriptController()->Initialize(url_for_debugger);
    GlobalScope()->WillBeginLoading();
    v8::HandleScope handle_scope(GetIsolate());
    Platform::Current()->WorkerContextCreated(
        GlobalScope()->ScriptController()->GetContext());

    inspector_task_runner_->InitIsolate(GetIsolate());
    SetThreadState(ThreadState::kRunning);
  }

  if (CheckRequestedToTerminate()) {
    // Stop further worker tasks from running after this point. WorkerThread
    // was requested to terminate before initialization.
    // PerformShutdownOnWorkerThread() will be called soon.
    PrepareForShutdownOnWorkerThread();
    return;
  }

  {
    base::AutoLock locker(ThreadSetLock());
    DCHECK(InitializingWorkerThreads().Contains(this));
    DCHECK(!WorkerThreads().Contains(this));
    InitializingWorkerThreads().erase(this);
    WorkerThreads().insert(this);
  }

  // It is important that no code is run on the Isolate between
  // initializing InspectorTaskRunner and pausing on start.
  // Otherwise, InspectorTaskRunner might interrupt isolate execution
  // from another thread and try to resume "pause on start" before
  // we even paused.
  worker_inspector_controller_->WaitForDebuggerIfNeeded();
  // Note the above call runs nested message loop which may result in
  // worker thread being torn down by request from the parent thread,
  // while waiting for debugger.
}

void WorkerThread::EvaluateClassicScriptOnWorkerThread(
    const KURL& script_url,
    String source_code,
    std::unique_ptr<Vector<uint8_t>> cached_meta_data,
    const v8_inspector::V8StackTraceId& stack_id) {
  WorkerGlobalScope* global_scope = To<WorkerGlobalScope>(GlobalScope());
  CHECK(global_scope);
  global_scope->EvaluateClassicScript(script_url, std::move(source_code),
                                      std::move(cached_meta_data), stack_id);
}

void WorkerThread::FetchAndRunClassicScriptOnWorkerThread(
    const KURL& script_url,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    std::unique_ptr<WebPolicyContainer> policy_container,
    std::unique_ptr<CrossThreadFetchClientSettingsObjectData>
        outside_settings_object,
    WorkerResourceTimingNotifier* outside_resource_timing_notifier,
    const v8_inspector::V8StackTraceId& stack_id) {
  if (!outside_resource_timing_notifier) {
    outside_resource_timing_notifier =
        MakeGarbageCollected<NullWorkerResourceTimingNotifier>();
  }

  To<WorkerGlobalScope>(GlobalScope())
      ->FetchAndRunClassicScript(
          script_url, std::move(worker_main_script_load_params),
          PolicyContainer::CreateFromWebPolicyContainer(
              std::move(policy_container)),
          *MakeGarbageCollected<FetchClientSettingsObjectSnapshot>(
              std::move(outside_settings_object)),
          *outside_resource_timing_notifier, stack_id);
}

void WorkerThread::FetchAndRunModuleScriptOnWorkerThread(
    const KURL& script_url,
    std::unique_ptr<WorkerMainScriptLoadParameters>
        worker_main_script_load_params,
    std::unique_ptr<WebPolicyContainer> policy_container,
    std::unique_ptr<CrossThreadFetchClientSettingsObjectData>
        outside_settings_object,
    WorkerResourceTimingNotifier* outside_resource_timing_notifier,
    network::mojom::CredentialsMode credentials_mode,
    bool reject_coep_unsafe_none) {
  if (!outside_resource_timing_notifier) {
    outside_resource_timing_notifier =
        MakeGarbageCollected<NullWorkerResourceTimingNotifier>();
  }
  // Worklets have a different code path to import module scripts.
  // TODO(nhiroki): Consider excluding this code path from WorkerThread like
  // Worklets.
  To<WorkerGlobalScope>(GlobalScope())
      ->FetchAndRunModuleScript(
          script_url, std::move(worker_main_script_load_params),
          PolicyContainer::CreateFromWebPolicyContainer(
              std::move(policy_container)),
          *MakeGarbageCollected<FetchClientSettingsObjectSnapshot>(
              std::move(outside_settings_object)),
          *outside_resource_timing_notifier, credentials_mode,
          RejectCoepUnsafeNone(reject_coep_unsafe_none));
}

void WorkerThread::PrepareForShutdownOnWorkerThread() {
  DCHECK(IsCurrentThread());
  {
    base::AutoLock locker(lock_);
    if (thread_state_ == ThreadState::kReadyToShutdown)
      return;
    SetThreadState(ThreadState::kReadyToShutdown);
  }

  backing_thread_weak_factory_ = std::nullopt;
  if (pause_or_freeze_count_ > 0) {
    DCHECK(nested_runner_);
    pause_or_freeze_count_ = 0;
    nested_runner_->QuitNow();
  }
  pause_handle_.reset();

  if (WorkerThreadDebugger* debugger = WorkerThreadDebugger::From(GetIsolate()))
    debugger->WorkerThreadDestroyed(this);

  GetWorkerReportingProxy().WillDestroyWorkerGlobalScope();

  probe::AllAsyncTasksCanceled(GlobalScope());

  // This will eventually call the |child_threads_|'s Terminate() through
  // ContextLifecycleObserver::ContextDestroyed(), because the nested workers
  // are observer of the |GlobalScope()| (see the DedicatedWorker class) and
  // they initiate thread termination on destruction of the parent context.
  GlobalScope()->NotifyContextDestroyed();

  worker_scheduler_->Dispose();

  // No V8 microtasks should get executed after shutdown is requested.
  GetWorkerBackingThread().BackingThread().RemoveTaskObserver(this);
}

void WorkerThread::PerformShutdownOnWorkerThread() {
  DCHECK(IsCurrentThread());
  {
    base::AutoLock locker(lock_);
    DCHECK(requested_to_terminate_);
    DCHECK_EQ(ThreadState::kReadyToShutdown, thread_state_);
    if (exit_code_ == ExitCode::kNotTerminated)
      SetExitCode(ExitCode::kGracefullyTerminated);
  }

  // When child workers are present, wait for them to shutdown before shutting
  // down this thread. ChildThreadTerminatedOnWorkerThread() is responsible
  // for completing shutdown on the worker thread after the last child shuts
  // down.
  if (!child_threads_.empty())
    return;

  inspector_task_runner_->Dispose();
  if (worker_inspector_controller_) {
    worker_insp
```