Response:
Let's break down the thought process for analyzing this C++ code and answering the prompt.

1. **Understand the Goal:** The request asks for the functionalities of `scripted_idle_task_controller.cc`, its relationship with web technologies (JavaScript, HTML, CSS), logical reasoning with examples, and common usage errors.

2. **Initial Code Scan - Identify Key Elements:**  Read through the code, noting important classes, methods, and data structures. Look for keywords and patterns that suggest the file's purpose. In this case, "IdleTask", "Scheduler", "Callback", "Timeout", and "ExecutionContext" stand out.

3. **Identify the Core Functionality:** The name `ScriptedIdleTaskController` strongly suggests it manages tasks that are related to scripting and execute when the browser is idle. The methods `RegisterCallback`, `CancelCallback`, `SchedulerIdleTask`, and `SchedulerTimeoutTask` confirm this. It's about scheduling and executing JavaScript callbacks when the main thread is not busy.

4. **Establish the Connection to Web Technologies:**
    * **JavaScript:** The code manages tasks triggered by JavaScript's `requestIdleCallback` API. This is the most direct connection. The `IdleRequestOptions` parameter in `RegisterCallback` further reinforces this link.
    * **HTML:** While not directly manipulating HTML, the idle tasks often perform actions that *affect* the DOM (rendering, layout, etc.). Idle time is used for non-critical updates, which are often related to what's displayed in the HTML.
    * **CSS:** Similar to HTML, idle tasks can be used for optimizations or deferred updates related to styling, although the connection is less direct than with JavaScript.

5. **Detail the Functionalities:** Go through the code method by method, explaining what each function does:
    * **Constructor/Destructor:**  Initialization and cleanup.
    * **`From()`:**  Accessing the controller.
    * **`RegisterCallback()`:**  The core - registering idle callbacks, assigning IDs, scheduling.
    * **`PostSchedulerIdleAndTimeoutTasks()`:**  Setting up the idle task and the timeout. The "OOMFix" feature is an important detail.
    * **`CancelCallback()`:** Removing scheduled tasks.
    * **`PostSchedulerIdleTask()`:**  Delegating the idle task to the scheduler.
    * **`SchedulerIdleTask()`:** The actual execution of the idle callback when idle time is available. Handles pausing/rescheduling.
    * **`SchedulerTimeoutTask()`:** Executing the callback when the timeout expires.
    * **`RunIdleTask()`:**  The core execution logic, invoking the JavaScript callback.
    * **`RemoveIdleTask()`/`RemoveAllIdleTasks()`:** Cleanup.
    * **Context Lifecycle Methods (`ContextDestroyed`, `ContextPaused`, `ContextUnpaused`):** Handling the impact of page lifecycle events on idle tasks.
    * **Helper Functions (`NextCallbackId`, `UpdateMaxIdleTasksCrashKey`, `UpdateMaxSchedulerIdleTasksCrashKey`):** Utility functions.

6. **Provide Concrete Examples (JavaScript Interaction):**  Create simple JavaScript snippets that demonstrate how `requestIdleCallback` interacts with the C++ code. Show registration, cancellation, and the behavior of the callback.

7. **Logical Reasoning and Examples:**
    * **Assumption:**  Focus on how the controller manages the timing of callbacks.
    * **Input:** Registration with/without timeout, state of the main thread (idle or busy).
    * **Output:** When the callback is executed.
    * **Illustrate different scenarios:**  Callback firing immediately, after a delay, due to timeout.

8. **Identify Potential Usage Errors:** Think about common mistakes developers might make when using `requestIdleCallback`:
    * **Long-running tasks:** Blocking the main thread.
    * **Relying on immediate execution:** Idle callbacks are not guaranteed to run instantly.
    * **Incorrect timeout values:**  Too short or too long.
    * **Forgetting to cancel:**  Resource leaks.
    * **DOM manipulation without checks:**  The DOM might be in an unexpected state.

9. **Review and Refine:**  Read through the generated explanation, ensuring clarity, accuracy, and completeness. Check that all aspects of the prompt are addressed. Make sure the examples are easy to understand and the reasoning is sound. For instance, initially, I might have missed the detail about the crash keys, but rereading the code would highlight their presence and purpose. Also, ensure the connection between the C++ code and the JavaScript API is clear and explicitly stated.

**Self-Correction Example During the Process:**

Initially, I might have focused too much on the internal workings of the scheduler without explicitly connecting it back to the JavaScript API. Realizing the prompt specifically asks for the relationship with JavaScript, I would then add more detailed examples of `requestIdleCallback` usage and explain how the C++ code facilitates that API. Similarly, if I only listed the functionalities without providing illustrative examples or reasoning, I'd go back and add those to better address the prompt's requirements. The "OOMFix" feature is also something I might initially overlook and need to add upon closer inspection.
这个文件 `scripted_idle_task_controller.cc` 是 Chromium Blink 渲染引擎的一部分，主要负责管理和调度通过 JavaScript 的 `requestIdleCallback` API 注册的空闲任务。  它确保这些任务在浏览器主线程空闲时执行，从而避免阻塞用户交互和关键渲染工作。

以下是该文件的主要功能：

**1. 管理 `requestIdleCallback` 的注册和取消:**

* **注册 (RegisterCallback):**  当 JavaScript 代码调用 `requestIdleCallback` 时，这个函数会被调用。它会创建一个 `IdleTask` 对象，为其分配一个唯一的 ID，并将该任务存储起来。同时，它还会根据 `IdleRequestOptions` 中的 `timeout` 参数，设置一个超时任务。
    * **JavaScript 关系:**  直接响应 JavaScript 的 `requestIdleCallback` API 调用。
    * **HTML/CSS 关系:**  虽然不直接操作 HTML 或 CSS，但 `requestIdleCallback` 常用于执行一些非关键的、延迟执行的任务，这些任务可能会间接影响页面的 HTML 结构或 CSS 样式，例如数据预处理、资源预加载、或一些不影响首次渲染的 DOM 更新。
    * **假设输入与输出:**
        * **假设输入:** JavaScript 调用 `window.requestIdleCallback(callback)` 或 `window.requestIdleCallback(callback, { timeout: 1000 })`。
        * **输出:**  在 C++ 层，会创建一个 `IdleTask` 对象，并将其添加到 `idle_tasks_` 列表中。如果指定了超时时间，还会设置一个定时器。返回一个唯一的 callback ID 给 JavaScript。

* **取消 (CancelCallback):** 当 JavaScript 代码调用 `cancelIdleCallback` 时，这个函数会被调用。它根据提供的 ID 移除对应的 `IdleTask`。
    * **JavaScript 关系:** 直接响应 JavaScript 的 `cancelIdleCallback` API 调用。
    * **假设输入与输出:**
        * **假设输入:**  JavaScript 调用 `window.cancelIdleCallback(callbackId)`，其中 `callbackId` 是之前 `requestIdleCallback` 返回的 ID。
        * **输出:**  在 C++ 层，会从 `idle_tasks_` 列表中移除对应的 `IdleTask`，并取消可能存在的超时定时器。

**2. 调度空闲任务:**

* **PostSchedulerIdleTask:**  将 `IdleTask` 提交给 Blink 的调度器，以便在主线程空闲时执行。
* **SchedulerIdleTask:** 当调度器指示主线程空闲时，此函数会被调用。它会检查任务是否仍然有效，并且当前是否处于暂停状态。如果条件满足，它会调用 `RunIdleTask` 来执行实际的回调。  如果主线程即将因为有更高优先级的工作而让出，则会重新调度该空闲任务。
    * **JavaScript 关系:** 间接影响 JavaScript 回调的执行时机。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** 主线程进入空闲状态。`idle_tasks_` 列表中存在已注册的空闲任务。
        * **输出:**  `SchedulerIdleTask` 被调用，并最终调用 JavaScript 注册的回调函数。
        * **假设输入:** 主线程即将因为高优先级任务而变得繁忙。
        * **输出:** `SchedulerIdleTask` 会重新调度该空闲任务，等待下一次空闲机会。

**3. 处理超时:**

* **PostSchedulerIdleAndTimeoutTasks:**  在注册 `IdleTask` 时，如果指定了超时时间，会设置一个定时器。
* **SchedulerTimeoutTask:**  当 `IdleTask` 的超时时间到达时，此函数会被调用。它会检查任务是否仍然有效，并调用 `RunIdleTask` 来执行回调，即使主线程不完全空闲。
    * **JavaScript 关系:** 确保在一定时间内，即使没有完全空闲的时间，`requestIdleCallback` 的回调也会被执行。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:** 注册了一个带有超时时间的 `requestIdleCallback`，且在超时时间内主线程一直很忙。
        * **输出:** 超时时间到达后，`SchedulerTimeoutTask` 被调用，并最终调用 JavaScript 注册的回调函数。

**4. 执行空闲任务:**

* **RunIdleTask:**  实际执行与 `requestIdleCallback` 关联的 JavaScript 回调函数。它会创建一个 `IdleDeadline` 对象，该对象包含可用的剩余时间以及一个布尔值，指示回调是否由于超时而执行。
    * **JavaScript 关系:**  这是连接 C++ 层和 JavaScript 层的关键点，实际调用了用户定义的 JavaScript 回调函数。
    * **假设输入与输出:**
        * **假设输入:**  `SchedulerIdleTask` 或 `SchedulerTimeoutTask` 决定执行某个 `IdleTask`。
        * **输出:**  在 JavaScript 环境中，之前通过 `requestIdleCallback` 注册的函数被调用，并传入一个 `IdleDeadline` 对象作为参数。

**5. 处理生命周期事件:**

* **ContextDestroyed:**  当关联的执行上下文（例如一个文档或 Worker）被销毁时，会移除所有待处理的空闲任务。
* **ContextPaused/ContextUnpaused:**  当执行上下文进入或退出暂停状态时，会暂停或恢复空闲任务的调度。

**6. 性能监控和调试:**

* 使用宏 `UMA_HISTOGRAM_MACROS` 记录一些性能指标。
* 使用 `TRACE_EVENT` 进行性能追踪。
* 使用 crash key (`UpdateMaxIdleTasksCrashKey`, `UpdateMaxSchedulerIdleTasksCrashKey`) 在崩溃报告中包含有用的信息，帮助诊断问题。

**与用户或编程常见的使用错误相关的例子:**

* **长时间运行的空闲回调:**  如果 `requestIdleCallback` 的回调函数执行时间过长，它可能会占用后续帧的时间，导致卡顿。浏览器会尽力提供足够的空闲时间，但开发者不应该在空闲回调中执行大量耗时的同步操作。
    * **例子:**  一个 `requestIdleCallback` 回调函数中执行了复杂的 DOM 操作或大量计算，导致后续的动画或用户交互变得卡顿。
* **过度依赖立即执行:**  开发者不应该假设 `requestIdleCallback` 的回调会立即执行。它只会在主线程空闲时运行，所以不适用于需要立即执行的任务。
    * **例子:**  开发者期望通过 `requestIdleCallback` 立刻更新 UI，但由于主线程繁忙，更新被延迟，导致用户体验不佳。
* **不取消不再需要的空闲回调:** 如果注册了 `requestIdleCallback` 但之后不再需要执行，应该使用 `cancelIdleCallback` 取消，否则可能会导致不必要的资源消耗。
    * **例子:**  在一个单页应用中，用户导航到另一个页面后，之前页面注册的 `requestIdleCallback` 回调仍然会尝试执行，但可能已经不再有效或需要。
* **在空闲回调中进行高优先级的操作:** `requestIdleCallback` 旨在处理低优先级的任务。如果在回调中执行了应该立即执行的高优先级操作，可能会导致性能问题。
    * **例子:**  在 `requestIdleCallback` 的回调中尝试处理关键的用户输入事件，导致响应延迟。
* **超时时间设置不当:**  如果超时时间设置得太短，可能导致回调在主线程仍然繁忙时被强制执行，反而影响性能。如果设置得太长，可能会延迟任务的执行。
    * **例子:**  将 `timeout` 设置为 0，实际上会让回调在很短的时间后就执行，可能并非真正的主线程空闲时。

总而言之，`scripted_idle_task_controller.cc` 在 Blink 渲染引擎中扮演着至关重要的角色，它使得开发者能够利用浏览器空闲时间执行非关键任务，从而优化页面性能，提升用户体验。它与 JavaScript 的 `requestIdleCallback` API 紧密相连，并通过调度器和超时机制来管理这些任务的执行。 理解其功能有助于开发者更好地利用 `requestIdleCallback` API，并避免一些常见的性能陷阱。

Prompt: 
```
这是目录为blink/renderer/core/scheduler/scripted_idle_task_controller.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/scheduler/scripted_idle_task_controller.h"

#include "base/debug/crash_logging.h"
#include "base/location.h"
#include "base/metrics/histogram_macros.h"
#include "base/not_fatal_until.h"
#include "third_party/blink/public/mojom/frame/lifecycle.mojom-shared.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_idle_request_options.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/inspector/inspector_trace_events.h"
#include "third_party/blink/renderer/core/probe/core_probes.h"
#include "third_party/blink/renderer/platform/instrumentation/tracing/trace_event.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

namespace blink {

namespace {

void UpdateMaxIdleTasksCrashKey(size_t num_pending_idle_tasks) {
  // A crash key with the highest number of pending `IdleTasks` in a single
  // `ScriptedIdleTaskController` instance, rounded down to the nearest hundred
  // to minimize the frequency of updates and reduce overhead.
  static auto* crash_key = base::debug::AllocateCrashKeyString(
      "max_idle_tasks", base::debug::CrashKeySize::Size32);
  static std::optional<size_t> crash_key_value;

  const size_t num_pending_idle_tasks_rounded_down =
      (num_pending_idle_tasks / 100) * 100;
  if (!crash_key_value.has_value() ||
      crash_key_value.value() < num_pending_idle_tasks_rounded_down) {
    base::debug::SetCrashKeyString(
        crash_key, base::NumberToString(num_pending_idle_tasks_rounded_down));
    crash_key_value = num_pending_idle_tasks_rounded_down;
  }
}

void UpdateMaxSchedulerIdleTasksCrashKey(
    size_t num_pending_scheduler_idle_tasks) {
  // A crash key with the highest number of scheduler idle tasks outstanding for
  // a single `ScriptedIdleTaskController` instance, rounded down to the nearest
  // hundred to minimize the frequency of updates and reduce overhead.
  static auto* crash_key = base::debug::AllocateCrashKeyString(
      "max_scheduler_idle_tasks", base::debug::CrashKeySize::Size32);
  static std::optional<size_t> crash_key_value;

  const size_t num_pending_scheduler_idle_tasks_rounded_down =
      (num_pending_scheduler_idle_tasks / 100) * 100;
  if (!crash_key_value.has_value() ||
      crash_key_value.value() < num_pending_scheduler_idle_tasks_rounded_down) {
    base::debug::SetCrashKeyString(
        crash_key,
        base::NumberToString(num_pending_scheduler_idle_tasks_rounded_down));
    crash_key_value = num_pending_scheduler_idle_tasks_rounded_down;
  }
}

}  // namespace

BASE_FEATURE(kScriptedIdleTaskControllerOOMFix,
             "ScriptedIdleTaskControllerOOMFix",
             base::FEATURE_DISABLED_BY_DEFAULT);

IdleTask::~IdleTask() {
  CHECK(!delayed_task_handle_.IsValid());
}

ScriptedIdleTaskController::DelayedTaskCanceler::DelayedTaskCanceler() =
    default;
ScriptedIdleTaskController::DelayedTaskCanceler::DelayedTaskCanceler(
    base::DelayedTaskHandle delayed_task_handle)
    : delayed_task_handle_(std::move(delayed_task_handle)) {}
ScriptedIdleTaskController::DelayedTaskCanceler::DelayedTaskCanceler(
    DelayedTaskCanceler&&) = default;
ScriptedIdleTaskController::DelayedTaskCanceler&
ScriptedIdleTaskController::DelayedTaskCanceler::operator=(
    ScriptedIdleTaskController::DelayedTaskCanceler&&) = default;

ScriptedIdleTaskController::DelayedTaskCanceler::~DelayedTaskCanceler() {
  delayed_task_handle_.CancelTask();
}

const char ScriptedIdleTaskController::kSupplementName[] =
    "ScriptedIdleTaskController";

// static
ScriptedIdleTaskController& ScriptedIdleTaskController::From(
    ExecutionContext& context) {
  ScriptedIdleTaskController* controller =
      Supplement<ExecutionContext>::From<ScriptedIdleTaskController>(&context);
  if (!controller) {
    controller = MakeGarbageCollected<ScriptedIdleTaskController>(&context);
    Supplement<ExecutionContext>::ProvideTo(context, controller);
  }
  return *controller;
}

ScriptedIdleTaskController::ScriptedIdleTaskController(
    ExecutionContext* context)
    : ExecutionContextLifecycleStateObserver(context),
      Supplement<ExecutionContext>(*context),
      scheduler_(ThreadScheduler::Current()) {
  UpdateStateIfNeeded();
}

ScriptedIdleTaskController::~ScriptedIdleTaskController() {
  CHECK(idle_tasks_.empty(), base::NotFatalUntil::M135);
}

void ScriptedIdleTaskController::Trace(Visitor* visitor) const {
  visitor->Trace(idle_tasks_);
  ExecutionContextLifecycleStateObserver::Trace(visitor);
  Supplement<ExecutionContext>::Trace(visitor);
}

int ScriptedIdleTaskController::NextCallbackId() {
  while (true) {
    ++next_callback_id_;

    if (!IsValidCallbackId(next_callback_id_))
      next_callback_id_ = 1;

    if (!idle_tasks_.Contains(next_callback_id_))
      return next_callback_id_;
  }
}

void ScriptedIdleTaskController::Dispose() {
  RemoveAllIdleTasks();
}

ScriptedIdleTaskController::CallbackId
ScriptedIdleTaskController::RegisterCallback(
    IdleTask* idle_task,
    const IdleRequestOptions* options) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    return 0;
  }

  DCHECK(idle_task);
  CallbackId id = NextCallbackId();
  idle_tasks_.Set(id, idle_task);
  UpdateMaxIdleTasksCrashKey(idle_tasks_.size());
  uint32_t timeout_millis = options->timeout();

  idle_task->async_task_context()->Schedule(GetExecutionContext(),
                                            "requestIdleCallback");

  PostSchedulerIdleAndTimeoutTasks(id, timeout_millis);
  DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT(
      "RequestIdleCallback", inspector_idle_callback_request_event::Data,
      GetExecutionContext(), id, timeout_millis);
  return id;
}

void ScriptedIdleTaskController::PostSchedulerIdleAndTimeoutTasks(
    CallbackId id,
    uint32_t timeout_millis) {
  // Note: be careful about memory usage of this method.
  // 1. In certain corner case scenarios, millions of callbacks per minute could
  //    be processed. The memory usage per callback should be minimized as much
  //    as possible.
  // 2. `timeout_millis` is page-originated and doesn't have any reasonable
  //    limit. When a callback is processed, it's critical to remove the timeout
  //    task from the queue. Failure to do so is likely to result in OOM.
  base::DelayedTaskHandle delayed_task_handle;
  if (timeout_millis > 0) {
    auto callback =
        WTF::BindOnce(&ScriptedIdleTaskController::SchedulerTimeoutTask,
                      WrapWeakPersistent(this), id);
    delayed_task_handle =
        GetExecutionContext()
            ->GetTaskRunner(TaskType::kIdleTask)
            ->PostCancelableDelayedTask(base::subtle::PostDelayedTaskPassKey(),
                                        FROM_HERE, std::move(callback),
                                        base::Milliseconds(timeout_millis));

    if (base::FeatureList::IsEnabled(kScriptedIdleTaskControllerOOMFix)) {
      auto it = idle_tasks_.find(id);
      CHECK_NE(it, idle_tasks_.end());
      CHECK(!it->value->delayed_task_handle_.IsValid());
      it->value->delayed_task_handle_ = std::move(delayed_task_handle);
    }
  }

  PostSchedulerIdleTask(id,
                        DelayedTaskCanceler(std::move(delayed_task_handle)));
}

void ScriptedIdleTaskController::CancelCallback(CallbackId id) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    return;
  }

  DEVTOOLS_TIMELINE_TRACE_EVENT_INSTANT(
      "CancelIdleCallback", inspector_idle_callback_cancel_event::Data,
      GetExecutionContext(), id);
  if (!IsValidCallbackId(id)) {
    return;
  }

  RemoveIdleTask(id);
}

void ScriptedIdleTaskController::PostSchedulerIdleTask(
    CallbackId id,
    DelayedTaskCanceler canceler) {
  ++num_pending_scheduler_idle_tasks_;
  UpdateMaxSchedulerIdleTasksCrashKey(num_pending_scheduler_idle_tasks_);

  scheduler_->PostIdleTask(
      FROM_HERE,
      WTF::BindOnce(&ScriptedIdleTaskController::SchedulerIdleTask,
                    WrapWeakPersistent(this), id, std::move(canceler)));
}

void ScriptedIdleTaskController::SchedulerIdleTask(
    CallbackId id,
    ScriptedIdleTaskController::DelayedTaskCanceler /* canceler */,
    base::TimeTicks deadline) {
  CHECK_GT(num_pending_scheduler_idle_tasks_, 0u, base::NotFatalUntil::M135);
  --num_pending_scheduler_idle_tasks_;

  if (!idle_tasks_.Contains(id)) {
    return;
  }

  if (paused_) {
    if (base::FeatureList::IsEnabled(kScriptedIdleTaskControllerOOMFix)) {
      // Reschedule when unpaused.
      idle_tasks_to_reschedule_.emplace_back(id);
    } else {
      // All `IdleTask`s are rescheduled when unpaused.
    }
    return;
  }

  // If we are going to yield immediately, reschedule the callback for later.
  if (ThreadScheduler::Current()->ShouldYieldForHighPriorityWork()) {
    // Note: `canceler` is implicitly deleted in this code path, which means
    // that the timeout will not be honored when the
    // "ScriptedIdleTaskControllerOOMFix" feature is disabled (when the feature
    // is enabled, the `DelayedTaskHandle` is stored on the `IdleTask`).
    PostSchedulerIdleTask(id, DelayedTaskCanceler());
    return;
  }

  RunIdleTask(id, deadline, IdleDeadline::CallbackType::kCalledWhenIdle);
}

void ScriptedIdleTaskController::SchedulerTimeoutTask(CallbackId id) {
  if (!idle_tasks_.Contains(id)) {
    return;
  }

  // This task uses `blink::TaskType::kIdleTask` which has freezable and
  // pauseable `blink::scheduler::MainThreadTaskQueue::QueueTraits`, so it
  // shouldn't be scheduled while paused.
  CHECK(!paused_, base::NotFatalUntil::M133);

  // TODO(crbug.com/365114039): Remove this in M133 if the above CHECK holds.
  if (paused_) {
    // Reschedule when unpaused.
    idle_tasks_with_expired_timeout_.push_back(id);
    return;
  }

  RunIdleTask(id, /*deadline=*/base::TimeTicks::Now(),
              IdleDeadline::CallbackType::kCalledByTimeout);
}

void ScriptedIdleTaskController::RunIdleTask(
    CallbackId id,
    base::TimeTicks deadline,
    IdleDeadline::CallbackType callback_type) {
  DCHECK(!paused_);

  // Keep the idle task in |idle_tasks_| so that it's still wrapper-traced.
  // TODO(https://crbug.com/796145): Remove this hack once on-stack objects
  // get supported by either of wrapper-tracing or unified GC.
  auto idle_task_iter = idle_tasks_.find(id);
  CHECK_NE(idle_task_iter, idle_tasks_.end(), base::NotFatalUntil::M133);
  if (idle_task_iter == idle_tasks_.end())
    return;
  IdleTask* idle_task = idle_task_iter->value;
  DCHECK(idle_task);

  base::TimeDelta allotted_time =
      std::max(deadline - base::TimeTicks::Now(), base::TimeDelta());

  probe::AsyncTask async_task(GetExecutionContext(),
                              idle_task->async_task_context());
  probe::UserCallback probe(GetExecutionContext(), "requestIdleCallback",
                            AtomicString(), true);

  bool cross_origin_isolated_capability =
      GetExecutionContext()
          ? GetExecutionContext()->CrossOriginIsolatedCapability()
          : false;
  DEVTOOLS_TIMELINE_TRACE_EVENT(
      "FireIdleCallback", inspector_idle_callback_fire_event::Data,
      GetExecutionContext(), id, allotted_time.InMillisecondsF(),
      callback_type == IdleDeadline::CallbackType::kCalledByTimeout);
  idle_task->invoke(MakeGarbageCollected<IdleDeadline>(
      deadline, cross_origin_isolated_capability, callback_type));

  // Finally there is no need to keep the idle task alive.
  //
  // Do not use the iterator because the idle task might update |idle_tasks_|.
  RemoveIdleTask(id);
}

void ScriptedIdleTaskController::RemoveIdleTask(CallbackId id) {
  auto it = idle_tasks_.find(id);
  if (it == idle_tasks_.end()) {
    return;
  }
  // A `base::DelayedTaskHandle` must be explicitly canceled before deletion.
  it->value->delayed_task_handle_.CancelTask();
  idle_tasks_.erase(it);
}

void ScriptedIdleTaskController::RemoveAllIdleTasks() {
  for (auto& idle_task : idle_tasks_) {
    // A `base::DelayedTaskHandle` must be explicitly canceled before deletion.
    idle_task.value->delayed_task_handle_.CancelTask();
  }
  idle_tasks_.clear();
}

void ScriptedIdleTaskController::ContextDestroyed() {
  RemoveAllIdleTasks();
}

void ScriptedIdleTaskController::ContextLifecycleStateChanged(
    mojom::FrameLifecycleState state) {
  if (state != mojom::FrameLifecycleState::kRunning)
    ContextPaused();
  else
    ContextUnpaused();
}

void ScriptedIdleTaskController::ContextPaused() {
  paused_ = true;
}

void ScriptedIdleTaskController::ContextUnpaused() {
  DCHECK(paused_);
  paused_ = false;

  // Reschedule `IdleTask`s for which `SchedulerTimeoutTask` ran while paused.
  for (auto& id : idle_tasks_with_expired_timeout_) {
    GetExecutionContext()
        ->GetTaskRunner(TaskType::kIdleTask)
        ->PostTask(
            FROM_HERE,
            WTF::BindOnce(&ScriptedIdleTaskController::SchedulerTimeoutTask,
                          WrapWeakPersistent(this), id));
  }
  idle_tasks_with_expired_timeout_.clear();

  if (base::FeatureList::IsEnabled(kScriptedIdleTaskControllerOOMFix)) {
    // Reschedule `IdleTask`s for which `SchedulerIdleTask` ran while paused.
    for (auto& idle_task : idle_tasks_to_reschedule_) {
      PostSchedulerIdleTask(idle_task, DelayedTaskCanceler());
    }
    idle_tasks_to_reschedule_.clear();
  } else {
    // Reschedule all `IdleTask`s.
    for (auto& idle_task : idle_tasks_) {
      PostSchedulerIdleTask(idle_task.key, DelayedTaskCanceler());
    }
  }
}

}  // namespace blink

"""

```