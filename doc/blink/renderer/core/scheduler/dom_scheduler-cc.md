Response:
Let's break down the thought process for analyzing the `DOMScheduler.cc` file.

1. **Understanding the Request:** The request asks for the functionalities of `DOMScheduler.cc`, its relation to web technologies (JavaScript, HTML, CSS), logical reasoning examples, and common usage errors.

2. **Initial Code Scan - Identifying Key Components:**  The first step is a quick skim of the code to identify major classes, methods, and data structures. Keywords like `postTask`, `yield`, `DOMTaskSignal`, `DOMTaskQueue`, `ScriptPromise`, and the inclusion of scheduler-related headers (`FrameOrWorkerScheduler`, `MainThreadScheduler`) immediately stand out. The `Supplement` pattern used also hints at its role in extending `ExecutionContext`.

3. **Inferring Core Functionality from Names and Types:**  Based on the names, I can start forming hypotheses:

    * `postTask`:  Likely for scheduling tasks to be executed later. The `V8SchedulerPostTaskCallback` suggests it involves JavaScript functions. The `SchedulerPostTaskOptions` and `AbortSignal` indicate configurable behavior and cancellation.
    * `yield`:  Seems related to pausing and resuming execution, perhaps for cooperative multitasking within the browser's event loop. The return type `ScriptPromise<IDLUndefined>` suggests it interacts with promises.
    * `DOMTaskSignal`:  This likely represents a way to signal or control the execution of tasks, potentially related to priority or cancellation. The presence of "fixed priority" and "dynamic priority" further supports this.
    * `DOMTaskQueue`: Clearly a container for tasks, likely organized by priority.
    * `ScriptPromise`: Confirms interaction with asynchronous JavaScript.
    * The various `WebScheduling...` types point towards an underlying scheduling mechanism within the Chromium engine.

4. **Analyzing Key Methods in Detail:**  Next, I'd delve into the implementation of the core methods:

    * **`postTask`:**  The checks for `ExecutionContext` destruction and `AbortSignal` immediately reveal error handling. The logic for determining the `priority_source` (either from options or a signal) is crucial for understanding how task prioritization works. The creation of `DOMTask` and `ScriptPromiseResolver` links this to asynchronous JavaScript execution. The `delay()` option confirms its role in time-delayed task scheduling.

    * **`yield`:** The creation of `fixed_priority_continuation_queues_` if they don't exist is a detail to note. The inheritance of `abort_source` and `priority_source` from `ScriptWrappableTaskState` suggests context propagation. The creation of `DOMTaskContinuation` indicates a slightly different type of scheduled work compared to `postTask`.

    * **`taskId` and `setTaskId`:** These clearly relate to task attribution, a debugging or monitoring feature. The interaction with `TaskAttributionTracker` confirms this.

    * **`CreateFixedPriorityTaskQueues` and `CreateDynamicPriorityTaskQueue`:** These methods handle the creation of different types of task queues, based on whether the priority is fixed or dynamic (controlled by a `DOMTaskSignal`).

    * **`GetFixedPriorityTaskSignal` and `GetTaskQueue`:** These methods manage the retrieval or creation of task signals and queues, implementing the logic for associating tasks with their execution environment.

5. **Connecting to Web Technologies:** Based on the method analysis, the connections become clear:

    * **JavaScript:** `postTask` and `yield` directly expose functionality to JavaScript through the `Scheduler` API. They use `ScriptPromise` and callbacks, making them integral to asynchronous JavaScript programming.
    * **HTML:** While not directly manipulating HTML elements, the scheduling of JavaScript tasks heavily influences the responsiveness and interactivity of web pages, which are built with HTML. For instance, `postTask` can be used to schedule updates to the DOM.
    * **CSS:**  Similar to HTML, CSS is indirectly affected. JavaScript often manipulates CSS styles, and `DOMScheduler` plays a role in when those style changes are applied.

6. **Developing Examples:**  Once the connections are established, creating examples becomes straightforward:

    * **`postTask`:** Demonstrating scheduling a function, setting priority, using a delay, and using an `AbortSignal`.
    * **`yield`:** Showing how it can be used to break up long-running tasks and how an `AbortSignal` can interrupt it.
    * **`taskId` and `setTaskId`:** Illustrating how to get and set task IDs for debugging or tracking.

7. **Identifying Usage Errors:**  Looking at the error handling in the code and considering common developer mistakes helps identify potential usage errors:

    * Calling `postTask` or `yield` after the window is detached.
    * Not handling promise rejections when using `AbortSignal`.
    * Misunderstanding the priority levels.
    * Potential misuse of `setTaskId` if Task Attribution is disabled.

8. **Structuring the Output:** Finally, organize the information logically, using headings and bullet points to make it easy to read and understand. Group related functionalities together and provide clear explanations and examples. Ensure that the examples demonstrate the interaction with JavaScript APIs.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe `DOMScheduler` directly manipulates the DOM.
* **Correction:**  The code focuses on *scheduling* tasks. While the *tasks themselves* might manipulate the DOM, `DOMScheduler`'s core responsibility is the timing and prioritization of these tasks. This is evident from the lack of direct DOM manipulation methods.

* **Initial thought:**  The priority mechanism is simple.
* **Refinement:**  The presence of fixed and dynamic priorities, along with the `DOMTaskSignal`, suggests a more sophisticated system for managing task importance.

* **Ensuring Accuracy:**  Double-checking the types and parameters of the methods against the provided code snippet is crucial to avoid misinterpretations. For example, confirming that `postTask` returns a `ScriptPromise`.

By following these steps, combining code analysis with an understanding of web technologies and potential developer errors, we can arrive at a comprehensive and accurate description of the `DOMScheduler.cc` file's functionality.
好的，让我们来分析一下 `blink/renderer/core/scheduler/dom_scheduler.cc` 文件的功能。

**核心功能:**

`DOMScheduler` 的核心功能是**管理和调度 DOM 相关的任务**。它提供了一种机制，允许 JavaScript 代码或其他 Blink 内部组件提交需要在主线程上执行的任务，并可以控制这些任务的优先级、延迟和取消。 它的主要目标是优化浏览器的性能和响应性，避免长时间运行的任务阻塞用户交互。

**具体功能分解:**

1. **任务提交 (`postTask`)**:
   - 允许 JavaScript 通过 `scheduler.postTask()` API 提交任务。
   - 接受一个回调函数作为要执行的任务。
   - 允许指定任务的优先级 (`priority` 选项)。
   - 允许指定任务的延迟执行时间 (`delay` 选项)。
   - 允许关联一个 `AbortSignal`，用于取消任务。
   - 返回一个 `Promise`，该 Promise 将在任务完成时 resolve 或在任务被取消时 reject。
   - 内部会将 JavaScript 回调封装成 `DOMTask` 对象。

2. **任务暂停/让步 (`yield`)**:
   - 允许 JavaScript 通过 `scheduler.yield()` API 暂停当前任务的执行，允许浏览器处理其他更高优先级的任务或进行渲染更新。
   - 返回一个 `Promise`，该 Promise 将在当前任务可以继续执行时 resolve。
   - 可以继承当前任务的 `AbortSignal`，允许在 yield 期间取消。
   - 内部会将 yield 操作封装成 `DOMTaskContinuation` 对象。

3. **任务优先级管理**:
   - 支持不同的任务优先级级别 (`UserBlocking`, `UserVisible`, `Background`)，对应于 `V8TaskPriority` 枚举。
   - 允许通过 `postTask` 的 `priority` 选项显式设置任务优先级。
   - 允许通过 `DOMTaskSignal` 对象动态调整任务优先级。
   - 根据优先级将任务放入不同的任务队列中执行。

4. **任务取消**:
   - 通过 `AbortSignal` 机制取消已提交但尚未执行的任务。
   - 当与任务关联的 `AbortSignal` 被触发时，任务将被移除出队列，并且其相关的 Promise 将被 reject。

5. **任务队列管理**:
   - 维护多个任务队列，每个队列对应一个优先级。
   -  `fixed_priority_task_queues_`: 存储固定优先级的任务队列。
   -  `fixed_priority_continuation_queues_`: 存储用于 `yield` 操作的固定优先级延续队列。
   -  `signal_to_task_queue_map_` 和 `signal_to_continuation_queue_map_`: 用于存储与 `DOMTaskSignal` 关联的动态优先级任务队列。

6. **任务上下文传递**:
   - 通过 `ScriptWrappableTaskState` 机制，在 `yield` 操作中传递任务的上下文信息，例如 `AbortSignal` 和优先级。

7. **任务追踪 (`taskId`, `setTaskId`)**:
   - 提供 `taskId` 方法获取当前正在执行的 JavaScript 任务的 ID (如果启用了任务追踪功能)。
   - 提供 `setTaskId` 方法设置当前 JavaScript 任务的 ID (主要用于测试目的)。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`DOMScheduler` 是 Blink 引擎中管理 JavaScript 任务执行的核心组件之一，它直接影响到 JavaScript 代码的执行时机和优先级，进而影响到页面的渲染和用户交互。

**JavaScript:**

- **`scheduler.postTask()` API**: 这是 JavaScript 直接使用 `DOMScheduler` 的入口。
  ```javascript
  // 提交一个低优先级的任务，延迟 100 毫秒执行
  scheduler.postTask(() => {
    console.log("这个任务将在稍后执行");
    // 可能进行一些 DOM 操作或数据处理
    document.getElementById('myElement').textContent = '任务已完成';
  }, { priority: 'background', delay: 100 });

  const controller = new AbortController();
  const signal = controller.signal;
  // 提交一个可取消的任务
  scheduler.postTask(() => {
    console.log("这个任务可以被取消");
  }, { signal });
  controller.abort(); // 取消任务
  ```

- **`scheduler.yield()` API**: 允许 JavaScript 主动让出控制权。
  ```javascript
  async function processLargeData() {
    const data = await fetchData();
    for (let i = 0; i < data.length; i++) {
      // 处理数据项
      processDataItem(data[i]);
      if (i % 100 === 0) {
        await scheduler.yield(); // 每处理 100 项让步一次
      }
    }
    console.log("数据处理完成");
  }
  ```

**HTML:**

- JavaScript 代码通常会操作 DOM 结构，而 `DOMScheduler` 决定了这些 DOM 操作何时执行。如果高优先级的任务阻塞了主线程，DOM 的更新可能会延迟，导致页面响应缓慢。
- 例如，一个复杂的 JavaScript 计算如果没有使用 `scheduler.yield()` 进行适当的分割，可能会阻塞浏览器处理用户输入或渲染更新，让用户感觉页面卡顿。

**CSS:**

- JavaScript 经常会修改元素的 CSS 样式。`DOMScheduler` 影响着这些样式修改何时生效。
- 例如，一个动画效果是通过 JavaScript 定时修改 CSS 属性实现的，`DOMScheduler` 的调度策略会影响动画的流畅度。如果动画相关的 JavaScript 任务优先级较低，可能会出现掉帧的情况。

**逻辑推理及假设输入与输出:**

**假设输入:**

1. JavaScript 代码调用 `scheduler.postTask()` 提交一个回调函数 `() => console.log("Task 1")`，没有指定优先级或延迟。
2. JavaScript 代码紧接着调用 `scheduler.postTask()` 提交另一个回调函数 `() => console.log("Task 2")`，优先级设置为 `user-blocking`。

**逻辑推理:**

- 默认情况下，`postTask` 使用默认优先级（通常是 `user-visible`）。
- `user-blocking` 优先级高于 `user-visible`。
- 因此，即使 "Task 1" 先提交，"Task 2" 会因为更高的优先级而被优先执行。

**输出:**

控制台输出的顺序将是：

```
Task 2
Task 1
```

**假设输入:**

1. JavaScript 代码调用 `scheduler.postTask()` 提交一个回调函数，并关联一个已经 aborted 的 `AbortSignal`。

**逻辑推理:**

- `DOMScheduler` 在 `postTask` 中会检查 `AbortSignal` 的状态。
- 如果 `AbortSignal` 已经 aborted，任务将不会被加入队列，并且 `postTask` 返回的 Promise 会立即被 reject。

**输出:**

- 提交任务的 `postTask` 调用返回的 Promise 将会进入 rejected 状态。
- 关联的回调函数不会被执行。

**用户或编程常见的使用错误:**

1. **过度使用高优先级**: 开发者可能会错误地将所有任务都设置为高优先级，这会削弱优先级机制的优势，可能导致某些低优先级的任务永远无法执行。

   ```javascript
   // 错误的做法：所有任务都设置为 user-blocking
   scheduler.postTask(() => { /* ... */ }, { priority: 'user-blocking' });
   scheduler.postTask(() => { /* ... */ }, { priority: 'user-blocking' });
   scheduler.postTask(() => { /* ... */ }, { priority: 'user-blocking' });
   ```

2. **不恰当的 `yield` 使用**:  过度使用 `yield` 可能会增加任务调度的开销，而使用不足则可能导致长时间运行的任务阻塞主线程。需要根据实际场景进行权衡。

3. **忘记处理 Promise rejection**: 当使用 `AbortSignal` 取消任务时，`postTask` 返回的 Promise 会被 reject。开发者需要正确处理这些 rejection，避免出现未处理的 Promise 错误。

   ```javascript
   const controller = new AbortController();
   const signal = controller.signal;
   scheduler.postTask(() => {
     // ...
   }, { signal }).catch(error => {
     console.error("任务被取消:", error);
   });
   controller.abort();
   ```

4. **在不应该的时候调用 `setTaskId`**:  `setTaskId` 主要用于测试和调试，在生产代码中滥用可能会导致意外的行为或性能问题。

5. **在 window detached 后调用 `postTask` 或 `yield`**:  当 window 已经 detached (例如，页面被关闭) 后，相关的 `ExecutionContext` 会被销毁。此时调用 `postTask` 或 `yield` 会抛出 `NotSupportedError` 异常。开发者应该在操作 `scheduler` 前检查 `ExecutionContext` 的状态。

总而言之，`DOMScheduler` 是 Blink 引擎中至关重要的组件，它通过管理和调度 DOM 相关的任务，直接影响着 Web 页面的性能和用户体验。理解其功能和使用方式对于编写高性能的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/core/scheduler/dom_scheduler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/scheduler/dom_scheduler.h"

#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/public/common/scheduler/task_attribution_id.h"
#include "third_party/blink/renderer/bindings/core/v8/idl_types.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise.h"
#include "third_party/blink/renderer/bindings/core/v8/script_promise_resolver.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scheduler_post_task_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_scheduler_post_task_options.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_task_priority.h"
#include "third_party/blink/renderer/core/dom/abort_signal.h"
#include "third_party/blink/renderer/core/execution_context/execution_context.h"
#include "third_party/blink/renderer/core/scheduler/dom_task.h"
#include "third_party/blink/renderer/core/scheduler/dom_task_continuation.h"
#include "third_party/blink/renderer/core/scheduler/dom_task_signal.h"
#include "third_party/blink/renderer/core/scheduler/script_wrappable_task_state.h"
#include "third_party/blink/renderer/core/scheduler/task_attribution_info_impl.h"
#include "third_party/blink/renderer/platform/bindings/enumeration_base.h"
#include "third_party/blink/renderer/platform/bindings/exception_code.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_or_worker_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/task_attribution_tracker.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_priority.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_queue_type.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_task_queue.h"
#include "third_party/blink/renderer/platform/wtf/text/atomic_string.h"

namespace blink {

namespace {
WebSchedulingPriority WebSchedulingPriorityFromEnum(
    V8TaskPriority::Enum priority) {
  switch (priority) {
    case V8TaskPriority::Enum::kUserBlocking:
      return WebSchedulingPriority::kUserBlockingPriority;
    case V8TaskPriority::Enum::kUserVisible:
      return WebSchedulingPriority::kUserVisiblePriority;
    case V8TaskPriority::Enum::kBackground:
      return WebSchedulingPriority::kBackgroundPriority;
  }
  NOTREACHED();
}
V8TaskPriority::Enum V8TaskEnumFromWebSchedulingPriority(
    WebSchedulingPriority priority) {
  switch (priority) {
    case WebSchedulingPriority::kUserBlockingPriority:
      return V8TaskPriority::Enum::kUserBlocking;
    case WebSchedulingPriority::kUserVisiblePriority:
      return V8TaskPriority::Enum::kUserVisible;
    case WebSchedulingPriority::kBackgroundPriority:
      return V8TaskPriority::Enum::kBackground;
  }
  NOTREACHED();
}
}  // namespace

const char DOMScheduler::kSupplementName[] = "DOMScheduler";

DOMScheduler* DOMScheduler::scheduler(ExecutionContext& context) {
  DOMScheduler* scheduler =
      Supplement<ExecutionContext>::From<DOMScheduler>(context);
  if (!scheduler) {
    scheduler = MakeGarbageCollected<DOMScheduler>(&context);
    Supplement<ExecutionContext>::ProvideTo(context, scheduler);
  }
  return scheduler;
}

DOMScheduler::DOMScheduler(ExecutionContext* context)
    : ExecutionContextLifecycleObserver(context),
      Supplement<ExecutionContext>(*context),
      fixed_priority_task_signals_(kWebSchedulingPriorityCount) {
  if (context->IsContextDestroyed()) {
    return;
  }
  CHECK(context->GetScheduler());
  CreateFixedPriorityTaskQueues(context, WebSchedulingQueueType::kTaskQueue,
                                fixed_priority_task_queues_);
}

void DOMScheduler::ContextDestroyed() {
  fixed_priority_task_queues_.clear();
  signal_to_task_queue_map_.clear();
}

void DOMScheduler::Trace(Visitor* visitor) const {
  visitor->Trace(fixed_priority_task_queues_);
  visitor->Trace(fixed_priority_continuation_queues_);
  visitor->Trace(fixed_priority_task_signals_);
  visitor->Trace(signal_to_task_queue_map_);
  visitor->Trace(signal_to_continuation_queue_map_);
  ScriptWrappable::Trace(visitor);
  ExecutionContextLifecycleObserver::Trace(visitor);
  Supplement<ExecutionContext>::Trace(visitor);
}

ScriptPromise<IDLAny> DOMScheduler::postTask(
    ScriptState* script_state,
    V8SchedulerPostTaskCallback* callback_function,
    SchedulerPostTaskOptions* options,
    ExceptionState& exception_state) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    // The bindings layer implicitly converts thrown exceptions in
    // promise-returning functions to promise rejections.
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Current window is detached");
    return EmptyPromise();
  }

  AbortSignal* signal_option = options->getSignalOr(nullptr);
  if (signal_option && signal_option->aborted()) {
    return ScriptPromise<IDLAny>::Reject(script_state,
                                         signal_option->reason(script_state));
  }

  DOMTaskSignal* priority_source = nullptr;
  if (options->hasPriority()) {
    // The priority option overrides the signal for priority.
    priority_source = GetFixedPriorityTaskSignal(
        script_state,
        WebSchedulingPriorityFromEnum(options->priority().AsEnum()));
  } else if (IsA<DOMTaskSignal>(signal_option)) {
    priority_source = To<DOMTaskSignal>(signal_option);
  }
  // `priority_source` will be null if no signal and no priority were provided,
  // or only a plain `AbortSignal` was provided.
  if (!priority_source) {
    priority_source =
        GetFixedPriorityTaskSignal(script_state, kDefaultPriority);
  }

  auto* task_queue =
      GetTaskQueue(priority_source, WebSchedulingQueueType::kTaskQueue);
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLAny>>(
      script_state, exception_state.GetContext());
  MakeGarbageCollected<DOMTask>(
      resolver, callback_function, signal_option, priority_source, task_queue,
      base::Milliseconds(options->delay()), NextIdForTracing());
  return resolver->Promise();
}

ScriptPromise<IDLUndefined> DOMScheduler::yield(
    ScriptState* script_state,
    ExceptionState& exception_state) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    exception_state.ThrowDOMException(DOMExceptionCode::kNotSupportedError,
                                      "Current window is detached");
    return EmptyPromise();
  }

  if (fixed_priority_continuation_queues_.empty()) {
    CreateFixedPriorityTaskQueues(GetExecutionContext(),
                                  WebSchedulingQueueType::kContinuationQueue,
                                  fixed_priority_continuation_queues_);
  }

  AbortSignal* abort_source = nullptr;
  DOMTaskSignal* priority_source = nullptr;
  if (auto* inherited_state =
          ScriptWrappableTaskState::GetCurrent(script_state->GetIsolate())) {
    abort_source = inherited_state->WrappedState()->AbortSource();
    priority_source = inherited_state->WrappedState()->PrioritySource();
  }

  if (abort_source && abort_source->aborted()) {
    return ScriptPromise<IDLUndefined>::Reject(
        script_state, abort_source->reason(script_state));
  }

  // `priority_source` will be null if there's nothing to inherit, i.e. yielding
  // from a non-postTask task.
  if (!priority_source) {
    priority_source =
        GetFixedPriorityTaskSignal(script_state, kDefaultPriority);
  }
  auto* task_queue =
      GetTaskQueue(priority_source, WebSchedulingQueueType::kContinuationQueue);
  auto* resolver = MakeGarbageCollected<ScriptPromiseResolver<IDLUndefined>>(
      script_state, exception_state.GetContext());
  MakeGarbageCollected<DOMTaskContinuation>(resolver, abort_source, task_queue,
                                            NextIdForTracing());
  return resolver->Promise();
}

scheduler::TaskAttributionIdType DOMScheduler::taskId(
    ScriptState* script_state) {
  // `tracker` will be null if TaskAttributionInfrastructureDisabledForTesting
  // is enabled.
  if (auto* tracker =
          scheduler::TaskAttributionTracker::From(script_state->GetIsolate())) {
    // `task_state` is null if there's nothing to propagate.
    if (scheduler::TaskAttributionInfo* task_state = tracker->RunningTask()) {
      return task_state->Id().value();
    }
  }
  return 0;
}

void DOMScheduler::setTaskId(ScriptState* script_state,
                             scheduler::TaskAttributionIdType task_id) {
  if (!scheduler::TaskAttributionTracker::From(script_state->GetIsolate())) {
    // This will be null if TaskAttributionInfrastructureDisabledForTesting is
    // enabled.
    return;
  }
  auto* task_state = MakeGarbageCollected<TaskAttributionInfoImpl>(
      scheduler::TaskAttributionId(task_id),
      /*soft_navigation_context=*/nullptr);
  ScriptWrappableTaskState::SetCurrent(
      script_state, MakeGarbageCollected<ScriptWrappableTaskState>(task_state));
  auto* scheduler = ThreadScheduler::Current()->ToMainThreadScheduler();
  // This test API is only available on the main thread.
  CHECK(scheduler);
  // Clear `task_state` at the end of the current task since there might not be
  // a task scope on the stack to clear it.
  scheduler->ExecuteAfterCurrentTaskForTesting(
      WTF::BindOnce(
          [](ScriptState* script_state) {
            ScriptWrappableTaskState::SetCurrent(script_state, nullptr);
          },
          WrapPersistent(script_state)),
      ExecuteAfterCurrentTaskRestricted{});
}

void DOMScheduler::CreateFixedPriorityTaskQueues(
    ExecutionContext* context,
    WebSchedulingQueueType queue_type,
    FixedPriorityTaskQueueVector& task_queues) {
  FrameOrWorkerScheduler* scheduler = context->GetScheduler();
  for (size_t i = 0; i < kWebSchedulingPriorityCount; i++) {
    auto priority = static_cast<WebSchedulingPriority>(i);
    std::unique_ptr<WebSchedulingTaskQueue> task_queue =
        scheduler->CreateWebSchedulingTaskQueue(queue_type, priority);
    task_queues.push_back(
        MakeGarbageCollected<DOMTaskQueue>(std::move(task_queue), priority));
  }
}

DOMScheduler::DOMTaskQueue* DOMScheduler::CreateDynamicPriorityTaskQueue(
    DOMTaskSignal* signal,
    WebSchedulingQueueType queue_type) {
  FrameOrWorkerScheduler* scheduler = GetExecutionContext()->GetScheduler();
  CHECK(scheduler);
  WebSchedulingPriority priority =
      WebSchedulingPriorityFromEnum(signal->priority().AsEnum());
  std::unique_ptr<WebSchedulingTaskQueue> task_queue =
      scheduler->CreateWebSchedulingTaskQueue(queue_type, priority);
  CHECK(task_queue);
  auto* dom_task_queue =
      MakeGarbageCollected<DOMTaskQueue>(std::move(task_queue), priority);
  auto* handle = signal->AddPriorityChangeAlgorithm(WTF::BindRepeating(
      &DOMScheduler::OnPriorityChange, WrapWeakPersistent(this),
      WrapWeakPersistent(signal), WrapWeakPersistent(dom_task_queue)));
  dom_task_queue->SetPriorityChangeHandle(handle);
  return dom_task_queue;
}

DOMTaskSignal* DOMScheduler::GetFixedPriorityTaskSignal(
    ScriptState* script_state,
    WebSchedulingPriority priority) {
  wtf_size_t index = static_cast<wtf_size_t>(priority);
  if (!fixed_priority_task_signals_[index]) {
    auto* signal = DOMTaskSignal::CreateFixedPriorityTaskSignal(
        script_state, V8TaskEnumFromWebSchedulingPriority(priority));
    CHECK(signal->HasFixedPriority());
    fixed_priority_task_signals_[index] = signal;
  }
  return fixed_priority_task_signals_[index].Get();
}

DOMScheduler::DOMTaskQueue* DOMScheduler::GetTaskQueue(
    DOMTaskSignal* task_signal,
    WebSchedulingQueueType queue_type) {
  if (task_signal->HasFixedPriority()) {
    auto priority =
        WebSchedulingPriorityFromEnum(task_signal->priority().AsEnum());
    return queue_type == WebSchedulingQueueType::kTaskQueue
               ? fixed_priority_task_queues_[static_cast<wtf_size_t>(priority)]
               : fixed_priority_continuation_queues_[static_cast<wtf_size_t>(
                     priority)];
  } else {
    SignalToTaskQueueMap& queue_map =
        queue_type == WebSchedulingQueueType::kTaskQueue
            ? signal_to_task_queue_map_
            : signal_to_continuation_queue_map_;
    if (queue_map.Contains(task_signal)) {
      return queue_map.at(task_signal);
    }
    // We haven't seen this task signal before, so create a task queue for it.
    auto* dom_task_queue =
        CreateDynamicPriorityTaskQueue(task_signal, queue_type);
    queue_map.insert(task_signal, dom_task_queue);
    return dom_task_queue;
  }
}

void DOMScheduler::OnPriorityChange(DOMTaskSignal* signal,
                                    DOMTaskQueue* task_queue) {
  if (!GetExecutionContext() || GetExecutionContext()->IsContextDestroyed()) {
    return;
  }
  DCHECK(signal);
  task_queue->SetPriority(
      WebSchedulingPriorityFromEnum(signal->priority().AsEnum()));
}

DOMScheduler::DOMTaskQueue::DOMTaskQueue(
    std::unique_ptr<WebSchedulingTaskQueue> task_queue,
    WebSchedulingPriority priority)
    : web_scheduling_task_queue_(std::move(task_queue)),
      task_runner_(web_scheduling_task_queue_->GetTaskRunner()),
      priority_(priority) {
  DCHECK(task_runner_);
}

void DOMScheduler::DOMTaskQueue::Trace(Visitor* visitor) const {
  visitor->Trace(priority_change_handle_);
}

void DOMScheduler::DOMTaskQueue::SetPriority(WebSchedulingPriority priority) {
  if (priority_ == priority)
    return;
  web_scheduling_task_queue_->SetPriority(priority);
  priority_ = priority;
}

DOMScheduler::DOMTaskQueue::~DOMTaskQueue() = default;

}  // namespace blink

"""

```