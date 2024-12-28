Response:
The user is asking for a summary of the functionality of the provided C++ code snippet from Chromium's Blink rendering engine. The request specifically asks to:

1. **List the functionalities** of the code.
2. **Explain its relationship to Javascript, HTML, and CSS** with examples.
3. **Provide examples of logical reasoning** with assumed inputs and outputs.
4. **Illustrate common user or programming errors**.
5. **Provide a summary of its function** (this is the specific request for part 3).

Let's break down the code and identify the key functionalities:

**Code Analysis and Functionalities:**

* **UseCase Management:**  The code determines the current "use case" (e.g., loading, touch interaction) to optimize scheduling. The `ComputeCurrentUseCase()` function and the logic around `UseCase::kTouchstart` demonstrate this.
* **Idle Time Management:**  The `CanEnterLongIdlePeriod()` function checks if the main thread can enter a long idle period to perform less critical tasks. This is related to performance optimization.
* **Virtual Time Control:**  Functions like `OnVirtualTimeEnabled()`, `OnVirtualTimeDisabled()`, `OnVirtualTimePaused()`, and `OnVirtualTimeResumed()` suggest support for simulating time, likely for testing purposes.
* **Tracing and Debugging:**  `CreateTraceEventObjectSnapshot()` and `WriteIntoTraceLocked()` are used for logging and debugging the scheduler's state.
* **Policy Management:**  The `Policy` struct and functions like `UpdatePolicyLocked()` and `ForceUpdatePolicy()` manage scheduling policies based on the current state. This includes features like pausing task queues under certain conditions.
* **Task Queue Management:** The code interacts with task queues (`MainThreadTaskQueue`) to schedule and manage tasks. Functions like `Policy::IsQueueEnabled()` determine if a task queue should be running based on the current policy.
* **RAIL Mode Observation:**  The `AddRAILModeObserver()` and `RemoveRAILModeObserver()` functions allow observing changes in the RAIL (Response, Animation, Idle, Load) mode, a performance model.
* **Agent Group Scheduling:** Functions related to `AgentGroupScheduler` suggest a mechanism for grouping and scheduling tasks from different origins or contexts.
* **Page Scheduling:** The code interacts with `PageSchedulerImpl`, managing scheduling at a per-page level.
* **Task Completion Handling:**  `OnTaskCompleted()` is crucial for handling tasks after they are executed, recording metrics, and potentially updating the scheduling policy.
* **UKM (User Key Metrics) Recording:** The `RecordTaskUkm()` functions handle recording performance data for analysis.
* **Task Priority Computation:**  `ComputePriority()` determines the priority of tasks based on various factors.
* **Idle Task Posting:** Functions like `PostIdleTask()` and `PostDelayedIdleTask()` allow scheduling tasks to run during idle periods.
* **Virtual Task Runners:**  The code manages virtual task runners for time-sensitive operations during virtual time.

**Relationship to Javascript, HTML, and CSS:**

* **Javascript:** The scheduler directly impacts how Javascript code is executed. When Javascript interacts with the DOM (HTML structure) or CSS styles, the resulting tasks are scheduled and managed by this code.
    * **Example:** A Javascript event handler triggered by a user click will result in tasks being queued and prioritized by the scheduler. If the scheduler is in a "touch start" use case, it might prioritize tasks related to the touch event.
* **HTML:** The loading and rendering of HTML are managed by the scheduler. Parsing HTML, building the DOM tree, and triggering layout are all tasks handled by the scheduler.
    * **Example:** When a new HTML page is loaded, the scheduler will prioritize tasks related to fetching resources (images, scripts, stylesheets) and rendering the initial content. The `UseCase::kLoading` and the logic around main frame paints are relevant here.
* **CSS:** Applying CSS styles and calculating the visual layout of the page are also tasks managed by the scheduler.
    * **Example:** When CSS rules change (e.g., due to a Javascript animation), the scheduler will manage the tasks involved in recalculating styles and repainting the affected parts of the page.

**Logical Reasoning Examples:**

* **Hypothesis:** If the user performs a touch gesture (touchstart event), the scheduler should prioritize tasks related to handling this input to provide a responsive experience.
    * **Input:**  `main_thread_only().current_use_case` is set to `UseCase::kTouchstart`.
    * **Output:** `CanEnterLongIdlePeriod()` will return `false`, preventing less critical idle tasks from running and potentially delaying the touch response. The `Policy::IsQueueEnabled()` function will likely defer non-essential tasks.
* **Hypothesis:**  When the renderer is backgrounded, the scheduler should reduce the priority of tasks to save resources.
    * **Input:** `main_thread_only().renderer_backgrounded` is true.
    * **Output:**  The `UpdatePolicyLocked()` function will likely set a policy that reduces the priority of certain task queues. The `RecordTaskUkmImpl()` function records the `RendererBackgrounded` state.

**Common User or Programming Errors:**

* **Overly Long Running Javascript Tasks:** If Javascript code takes a very long time to execute, it can block the main thread, leading to unresponsiveness. The scheduler tries to mitigate this, but poorly written Javascript can still cause issues.
    * **Example:** A complex synchronous computation in Javascript will prevent the scheduler from processing other important tasks, leading to jank or a frozen UI.
* **Excessive DOM Manipulation:**  Performing many small DOM manipulations in Javascript can lead to a large number of layout and paint tasks, overloading the scheduler.
    * **Example:**  Adding hundreds of elements to the DOM one by one in a loop will generate many individual tasks that the scheduler needs to process.
* **Incorrectly Prioritized Tasks:**  While the scheduler automatically prioritizes tasks, developers can sometimes influence task priorities. Incorrectly prioritizing low-priority tasks for critical operations can lead to performance problems.
    * **Example:**  If a developer uses a low-priority task queue for a time-sensitive animation, the animation might appear jerky.

**Summary of Functionality (Part 3):**

This section of the `MainThreadSchedulerImpl.cc` file primarily focuses on **advanced scheduling features, debugging, and lifecycle management**. It details how the scheduler handles:

* **Determining and managing the current operational context (UseCase) to optimize task prioritization.**
* **Entering and exiting idle periods for performing less critical background tasks.**
* **Simulating time for testing and debugging through virtual time control.**
* **Collecting detailed performance information and logging scheduler state for analysis.**
* **Dynamically adjusting scheduling policies based on the current context and system state.**
* **Integrating with tracing mechanisms to provide insights into scheduler behavior.**

In essence, this part of the code moves beyond basic task queuing and delves into the more nuanced aspects of ensuring smooth and efficient rendering by adapting its behavior to different situations and providing tools for understanding its operation.

这是 `MainThreadSchedulerImpl.cc` 文件的第三部分，主要涵盖了以下功能：

**1. 用例 (UseCase) 管理:**

*   **确定当前用例:** `ComputeCurrentUseCase()` 函数根据当前渲染器的状态（例如，是否可见、是否有输入、是否正在加载）来判断当前最合适的用例。这有助于优化任务调度策略。
*   **影响调度策略:**  判断出的用例会影响后续的任务调度，例如，在 `UseCase::kTouchstart` 期间，会避免进入长时间的空闲状态，以确保触摸事件的及时响应。

**与 Javascript, HTML, CSS 的关系举例:**

*   **Javascript:** 当用户触发 `touchstart` 事件时，Javascript 代码可能会执行一些逻辑。`ComputeCurrentUseCase()` 可能会将用例设置为 `UseCase::kTouchstart`，这会指示调度器优先处理与此事件相关的任务，从而提高交互的响应速度。
*   **HTML:** 在页面加载过程中，`ComputeCurrentUseCase()` 可能会判断为 `UseCase::kLoading`，调度器会优先处理与页面渲染相关的任务，例如解析 HTML、加载资源等。

**逻辑推理举例:**

*   **假设输入:**
    *   `main_thread_only().renderer_hidden` 为 `false` (渲染器可见)
    *   `any_thread().have_seen_input_since_navigation` 为 `true` (自导航以来有用户输入)
    *   没有正在加载的主框架 (`!IsAnyOrdinaryMainFrameLoading()`)
    *   没有等待主框架绘制 (`!IsAnyPendingMainFrameUpdate()`)
*   **输出:** `ComputeCurrentUseCase()`  返回 `UseCase::kUserInitiated`，表示当前处于用户交互后的状态，调度器会采取相应的策略来优化用户体验。

**2. 长时间空闲期管理:**

*   **判断是否可以进入:** `CanEnterLongIdlePeriod()` 函数判断当前是否可以进入长时间的空闲期，以便执行优先级较低的任务。
*   **避免在关键时期进入:**  例如，在 `UseCase::kTouchstart` 期间，会阻止进入长时间空闲期，避免影响触摸事件的响应。

**3. 虚拟时间控制:**

*   **支持虚拟时间:**  提供 `OnVirtualTimeEnabled()`, `OnVirtualTimeDisabled()`, `OnVirtualTimePaused()`, `OnVirtualTimeResumed()` 等函数，用于在测试或调试环境下控制时间的流逝。
*   **影响任务队列:** 在虚拟时间暂停时，会向非 `CanRunWhenVirtualTimePaused()` 的任务队列插入栅栏，阻止任务执行。

**与 Javascript, HTML, CSS 的关系举例:**

*   **Javascript:** 在测试 Javascript 动画时，可以使用虚拟时间来加速测试过程或模拟特定的时间场景。
*   **HTML/CSS:** 虚拟时间可以用于测试依赖于时间的 CSS 动画或 HTML 中使用 Javascript 操作时间的行为。

**逻辑推理举例:**

*   **假设输入:** 调用 `OnVirtualTimePaused()`
*   **输出:** 所有非 `CanRunWhenVirtualTimePaused()` 的任务队列会被插入栅栏，这些队列上的任务将暂停执行，直到调用 `OnVirtualTimeResumed()`。

**4. 跟踪事件快照:**

*   **生成快照:** `CreateTraceEventObjectSnapshot()` 和 `CreateTraceEventObjectSnapshotLocked()` 函数用于生成调度器状态的跟踪事件快照，方便调试和性能分析。
*   **记录关键信息:** 快照中包含当前用例、渲染器状态、策略信息、任务队列状态等。

**5. 策略 (Policy) 管理:**

*   **判断队列是否启用:** `Policy::IsQueueEnabled()` 函数根据当前策略判断给定的任务队列是否应该被启用。
*   **根据用例和特性调整:**  策略会根据当前的用例和一些特性（如 `kDeferRendererTasksAfterInput`）来动态调整，例如在 `UseCase::kTouchstart` 期间，可能会延迟某些可以延迟的任务队列。

**与 Javascript, HTML, CSS 的关系举例:**

*   **Javascript:**  如果启用了 `kDeferRendererTasksAfterInput` 并且当前处于 `UseCase::kDiscreteInputResponse` 状态，某些非用户阻塞的 Javascript 任务可能会被延迟执行，以优先处理与用户输入响应相关的任务。

**逻辑推理举例:**

*   **假设输入:**
    *   当前 `use_case` 为 `UseCase::kTouchstart`
    *   任务队列 `task_queue` 的 `CanBeDeferred()` 返回 `true`
*   **输出:** `Policy::IsQueueEnabled(task_queue, settings)` 返回 `false`，表示该任务队列在触摸开始期间应该被延迟。

**6. 空闲期事件处理:**

*   **通知空闲期开始和结束:** `OnIdlePeriodStarted()` 和 `OnIdlePeriodEnded()` 函数用于通知调度器空闲期的开始和结束。
*   **更新策略:** 在空闲期开始和结束时，会更新调度策略。

**7. 待处理任务变化处理:**

*   **异步通知:** `OnPendingTasksChanged()` 函数在待处理任务数量变化时被调用，并异步分发 `RequestBeginMainFrameNotExpectedSoon` 通知。

**8. 导航事件处理:**

*   **重置状态:** `DidStartProvisionalLoad()` 和 `DidCommitProvisionalLoad()` 函数在页面导航开始和提交时被调用，用于重置调度器的相关状态，例如用例和用户模型。

**9. 主帧绘制处理:**

*   **更新状态:** `OnMainFramePaint()` 函数在主帧绘制完成后被调用，用于更新与绘制相关的状态，例如是否正在等待首次内容绘制或首次有意义绘制。

**10. 重置导航状态:**

*   **清除用户模型等:** `ResetForNavigationLocked()` 函数用于在导航发生时重置用户模型、输入状态等。

**11. RAIL 模式观察者:**

*   **添加和移除观察者:** `AddRAILModeObserver()` 和 `RemoveRAILModeObserver()` 函数用于添加和移除 RAIL 模式的观察者，以便在 RAIL 模式改变时得到通知。

**12. 遍历主线程 Isolate:**

*   **执行回调:** `ForEachMainThreadIsolate()` 函数用于遍历所有主线程的 V8 Isolate，并对每个 Isolate 执行指定的回调函数。

**13. 设置渲染器进程类型:**

*   **记录进程类型:** `SetRendererProcessType()` 函数用于设置渲染器进程的类型。

**14. 获取待处理用户输入信息:**

*   **获取输入事件属性:** `GetPendingUserInputInfo()` 函数用于获取待处理的用户输入事件的属性信息。

**15. 运行和提交空闲任务:**

*   **提供多种方式:** 提供 `RunIdleTask()`, `PostIdleTask()`, `PostDelayedIdleTask()`, `PostNonNestableIdleTask()` 等函数来运行或提交在空闲期间执行的任务。

**用户或编程常见的使用错误举例:**

*   **在 `UseCase::kTouchstart` 期间提交长时间运行的非必要任务:**  这可能会导致触摸事件响应延迟，用户可能会感受到卡顿。
*   **在虚拟时间环境下忘记恢复真实时间:** 如果在测试后忘记调用 `OnVirtualTimeDisabled()`，可能会导致渲染器的行为异常。

**功能归纳:**

这部分代码主要负责 **更精细化的主线程任务调度管理和优化**。它通过以下方式来实现：

*   **根据渲染器的当前状态和用户行为动态调整调度策略 (UseCase)。**
*   **利用空闲时间执行低优先级任务，提高资源利用率。**
*   **提供虚拟时间控制能力，方便进行性能测试和调试。**
*   **通过跟踪事件和策略管理，增强了代码的可观察性和可控性。**
*   **处理页面导航和渲染的关键生命周期事件，维护调度器状态的一致性。**

总而言之，这部分代码是 `MainThreadSchedulerImpl` 中负责实现高级调度特性、提升渲染性能和提供调试能力的关键组成部分。

Prompt: 
```
这是目录为blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共4部分，请归纳一下它的功能

"""
 UseCase::kLoading;
      }
    }
  }
  return UseCase::kNone;
}

bool MainThreadSchedulerImpl::CanEnterLongIdlePeriod(
    base::TimeTicks now,
    base::TimeDelta* next_long_idle_period_delay_out) {
  helper_.CheckOnValidThread();

  MaybeUpdatePolicy();
  if (main_thread_only().current_use_case == UseCase::kTouchstart) {
    // Don't start a long idle task in touch start priority, try again when
    // the policy is scheduled to end.
    *next_long_idle_period_delay_out =
        std::max(base::TimeDelta(),
                 main_thread_only().current_policy_expiration_time - now);
    return false;
  }
  return true;
}

MainThreadSchedulerHelper*
MainThreadSchedulerImpl::GetSchedulerHelperForTesting() {
  return &helper_;
}

IdleTimeEstimator* MainThreadSchedulerImpl::GetIdleTimeEstimatorForTesting() {
  return &main_thread_only().idle_time_estimator;
}

base::SequencedTaskRunner* MainThreadSchedulerImpl::GetVirtualTimeTaskRunner() {
  return virtual_time_control_task_queue_->GetTaskRunnerWithDefaultTaskType()
      .get();
}

void MainThreadSchedulerImpl::OnVirtualTimeEnabled() {
  DCHECK(!virtual_time_control_task_queue_);
  virtual_time_control_task_queue_ =
      helper_.NewTaskQueue(MainThreadTaskQueue::QueueCreationParams(
          MainThreadTaskQueue::QueueType::kControl));
  virtual_time_control_task_queue_->SetQueuePriority(
      TaskPriority::kControlPriority);

  ForceUpdatePolicy();

  for (auto* page_scheduler : main_thread_only().page_schedulers) {
    page_scheduler->OnVirtualTimeEnabled();
  }
}

void MainThreadSchedulerImpl::OnVirtualTimeDisabled() {
  virtual_time_control_task_queue_->ShutdownTaskQueue();
  virtual_time_control_task_queue_ = nullptr;

  ForceUpdatePolicy();

  // Reset the MetricsHelper because it gets confused by time going backwards.
  base::TimeTicks now = NowTicks();
  main_thread_only().metrics_helper.ResetForTest(now);
}

void MainThreadSchedulerImpl::OnVirtualTimePaused() {
  for (const auto& pair : task_runners_) {
    if (pair.first->CanRunWhenVirtualTimePaused())
      continue;
    DCHECK(!pair.first->IsThrottled());
    pair.first->GetTaskQueue()->InsertFence(
        TaskQueue::InsertFencePosition::kNow);
  }
}

void MainThreadSchedulerImpl::OnVirtualTimeResumed() {
  for (const auto& pair : task_runners_) {
    if (pair.first->CanRunWhenVirtualTimePaused())
      continue;
    DCHECK(!pair.first->IsThrottled());
    DCHECK(pair.first->GetTaskQueue()->HasActiveFence());
    pair.first->GetTaskQueue()->RemoveFence();
  }
}

void MainThreadSchedulerImpl::CreateTraceEventObjectSnapshot() const {
  TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(
      TRACE_DISABLED_BY_DEFAULT("renderer.scheduler.debug"),
      "MainThreadScheduler", this, [&](perfetto::TracedValue context) {
        base::AutoLock lock(any_thread_lock_);
        WriteIntoTraceLocked(std::move(context), helper_.NowTicks());
      });
}

void MainThreadSchedulerImpl::CreateTraceEventObjectSnapshotLocked() const {
  TRACE_EVENT_OBJECT_SNAPSHOT_WITH_ID(
      TRACE_DISABLED_BY_DEFAULT("renderer.scheduler.debug"),
      "MainThreadScheduler", this, [&](perfetto::TracedValue context) {
        WriteIntoTraceLocked(std::move(context), helper_.NowTicks());
      });
}

void MainThreadSchedulerImpl::WriteIntoTraceLocked(
    perfetto::TracedValue context,
    base::TimeTicks optional_now) const {
  helper_.CheckOnValidThread();
  any_thread_lock_.AssertAcquired();

  auto dict = std::move(context).WriteDictionary();

  if (optional_now.is_null())
    optional_now = helper_.NowTicks();
  dict.Add("current_use_case",
           UseCaseToString(main_thread_only().current_use_case));
  dict.Add("compositor_will_send_main_frame_not_expected",
           main_thread_only().compositor_will_send_main_frame_not_expected);
  dict.Add("blocking_input_expected_soon",
           main_thread_only().blocking_input_expected_soon);
  dict.Add("idle_period_state", IdleHelper::IdlePeriodStateToString(
                                    idle_helper_.SchedulerIdlePeriodState()));
  dict.Add("renderer_hidden", main_thread_only().renderer_hidden.get());
  dict.Add("waiting_for_any_main_frame_contentful_paint",
           any_thread().waiting_for_any_main_frame_contentful_paint);
  dict.Add("waiting_for_any_main_frame_meaningful_paint",
           any_thread().waiting_for_any_main_frame_meaningful_paint);
  dict.Add("is_any_main_frame_loading", any_thread().is_any_main_frame_loading);
  dict.Add("have_seen_input_since_navigation",
           any_thread().have_seen_input_since_navigation);
  dict.Add("renderer_backgrounded",
           main_thread_only().renderer_backgrounded.get());
  dict.Add("now", (optional_now - base::TimeTicks()).InMillisecondsF());
  dict.Add("last_idle_period_end_time",
           (any_thread().last_idle_period_end_time - base::TimeTicks())
               .InMillisecondsF());
  dict.Add("awaiting_touch_start_response",
           any_thread().awaiting_touch_start_response);
  dict.Add("begin_main_frame_on_critical_path",
           any_thread().begin_main_frame_on_critical_path);
  dict.Add("last_gesture_was_compositor_driven",
           any_thread().last_gesture_was_compositor_driven);
  dict.Add("default_gesture_prevented", any_thread().default_gesture_prevented);
  dict.Add("is_audio_playing", main_thread_only().is_audio_playing);
  dict.Add("page_schedulers", [&](perfetto::TracedValue context) {
    auto array = std::move(context).WriteArray();
    for (const auto* page_scheduler : main_thread_only().page_schedulers) {
      page_scheduler->WriteIntoTrace(array.AppendItem(), optional_now);
    }
  });

  dict.Add("policy", main_thread_only().current_policy);

  // TODO(skyostil): Can we somehow trace how accurate these estimates were?
  dict.Add("compositor_frame_interval",
           main_thread_only().compositor_frame_interval.InMillisecondsF());
  dict.Add("estimated_next_frame_begin",
           (main_thread_only().estimated_next_frame_begin - base::TimeTicks())
               .InMillisecondsF());
  dict.Add("in_idle_period", any_thread().in_idle_period);

  dict.Add("user_model", any_thread().user_model);
  dict.Add("render_widget_scheduler_signals", render_widget_scheduler_signals_);
  WriteVirtualTimeInfoIntoTrace(dict);
}

bool MainThreadSchedulerImpl::Policy::IsQueueEnabled(
    MainThreadTaskQueue* task_queue,
    const SchedulingSettings& settings) const {
  if (should_pause_task_queues && task_queue->CanBePaused()) {
    return false;
  }

  if (should_pause_task_queues_for_android_webview &&
      task_queue->CanBePausedForAndroidWebview()) {
    return false;
  }

  if (use_case == UseCase::kTouchstart && task_queue->CanBeDeferred()) {
    return false;
  }

  if (base::FeatureList::IsEnabled(features::kDeferRendererTasksAfterInput)) {
    if (use_case == UseCase::kDiscreteInputResponse &&
        task_queue->CanBeDeferredForRendering()) {
      std::optional<WebSchedulingPriority> priority =
          task_queue->GetWebSchedulingPriority();
      if (!priority) {
        return false;
      }
      // Web scheduling task priority is dynamic, and the deferrability of
      // background and user-blocking scheduler tasks depends on the specific
      // policy.
      CHECK(settings.discrete_input_task_deferral_policy);
      switch (*settings.discrete_input_task_deferral_policy) {
        case features::TaskDeferralPolicy::kMinimalTypes:
          if (*priority == WebSchedulingPriority::kBackgroundPriority) {
            return false;
          }
          break;
        case features::TaskDeferralPolicy::kNonUserBlockingDeferrableTypes:
        case features::TaskDeferralPolicy::kNonUserBlockingTypes:
          if (*priority != WebSchedulingPriority::kUserBlockingPriority) {
            return false;
          }
          break;
        case features::TaskDeferralPolicy::kAllDeferrableTypes:
        case features::TaskDeferralPolicy::kAllTypes:
          return false;
      }
    }
  }

  return true;
}

void MainThreadSchedulerImpl::Policy::WriteIntoTrace(
    perfetto::TracedValue context) const {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("rail_mode", RAILModeToString(rail_mode));
  dict.Add("use_case", UseCaseToString(use_case));
  dict.Add("should_pause_task_queues", should_pause_task_queues);
  dict.Add("should_pause_task_queues_for_android_webview",
           should_pause_task_queues_for_android_webview);
  dict.Add("should_freeze_compositor_task_queue",
           should_freeze_compositor_task_queue);
  dict.Add("should_prioritize_ipc_tasks", should_prioritize_ipc_tasks);
}

void MainThreadSchedulerImpl::OnIdlePeriodStarted() {
  base::AutoLock lock(any_thread_lock_);
  any_thread().in_idle_period = true;
  UpdatePolicyLocked(UpdateType::kMayEarlyOutIfPolicyUnchanged);
}

void MainThreadSchedulerImpl::OnIdlePeriodEnded() {
  base::AutoLock lock(any_thread_lock_);
  any_thread().last_idle_period_end_time = helper_.NowTicks();
  any_thread().in_idle_period = false;
  UpdatePolicyLocked(UpdateType::kMayEarlyOutIfPolicyUnchanged);
}

void MainThreadSchedulerImpl::OnPendingTasksChanged(bool has_tasks) {
  if (has_tasks ==
      main_thread_only().compositor_will_send_main_frame_not_expected.get())
    return;

  // Dispatch RequestBeginMainFrameNotExpectedSoon notifications asynchronously.
  // This is needed because idle task can be posted (and OnPendingTasksChanged
  // called) at any moment, including in the middle of allocating an object,
  // when state is not consistent. Posting a task to dispatch notifications
  // minimizes the amount of code that runs and sees an inconsistent state .
  control_task_queue_->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE,
      base::BindOnce(
          &MainThreadSchedulerImpl::DispatchRequestBeginMainFrameNotExpected,
          weak_factory_.GetWeakPtr(), has_tasks));
}

void MainThreadSchedulerImpl::DispatchRequestBeginMainFrameNotExpected(
    bool has_tasks) {
  if (has_tasks ==
      main_thread_only().compositor_will_send_main_frame_not_expected.get())
    return;

  TRACE_EVENT1(
      TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
      "MainThreadSchedulerImpl::DispatchRequestBeginMainFrameNotExpected",
      "has_tasks", has_tasks);
  bool success = false;
  for (PageSchedulerImpl* page_scheduler : main_thread_only().page_schedulers) {
    success |= page_scheduler->RequestBeginMainFrameNotExpected(has_tasks);
  }
  main_thread_only().compositor_will_send_main_frame_not_expected =
      success && has_tasks;
}

void MainThreadSchedulerImpl::DidStartProvisionalLoad(
    bool is_outermost_main_frame) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "MainThreadSchedulerImpl::DidStartProvisionalLoad");
  if (is_outermost_main_frame) {
    base::AutoLock lock(any_thread_lock_);
    ResetForNavigationLocked();
  }
}

void MainThreadSchedulerImpl::DidCommitProvisionalLoad(
    bool is_web_history_inert_commit,
    bool is_reload,
    bool is_outermost_main_frame) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "MainThreadSchedulerImpl::DidCommitProvisionalLoad");
  main_thread_only().has_navigated = true;

  // If this either isn't a history inert commit or it's a reload then we must
  // reset the task cost estimators.
  if (is_outermost_main_frame && (!is_web_history_inert_commit || is_reload)) {
    RAILMode old_rail_mode;
    RAILMode new_rail_mode;
    {
      base::AutoLock lock(any_thread_lock_);
      old_rail_mode = main_thread_only().current_policy.rail_mode;
      ResetForNavigationLocked();
      new_rail_mode = main_thread_only().current_policy.rail_mode;
    }
    if (old_rail_mode == RAILMode::kLoad && new_rail_mode == RAILMode::kLoad &&
        isolate()) {
      // V8 was already informed that the load started, but now that the load is
      // committed, update the start timestamp.
      isolate()->SetIsLoading(true);
    }
  }
}

void MainThreadSchedulerImpl::OnMainFramePaint() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "MainThreadSchedulerImpl::OnMainFramePaint");
  base::AutoLock lock(any_thread_lock_);

  // The state of a non-ordinary page (e.g. SVG image) shouldn't affect the
  // scheduler's global UseCase.
  any_thread().waiting_for_any_main_frame_contentful_paint =
      IsAnyOrdinaryMainFrameWaitingForFirstContentfulPaint();
  any_thread().waiting_for_any_main_frame_meaningful_paint =
      IsAnyOrdinaryMainFrameWaitingForFirstMeaningfulPaint();
  any_thread().is_any_main_frame_loading = IsAnyOrdinaryMainFrameLoading();

  UpdatePolicyLocked(UpdateType::kMayEarlyOutIfPolicyUnchanged);
}

void MainThreadSchedulerImpl::ResetForNavigationLocked() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "MainThreadSchedulerImpl::ResetForNavigationLocked");
  helper_.CheckOnValidThread();
  any_thread_lock_.AssertAcquired();
  any_thread().user_model.Reset(helper_.NowTicks());
  any_thread().have_seen_a_blocking_gesture = false;
  any_thread().waiting_for_any_main_frame_contentful_paint =
      IsAnyOrdinaryMainFrameWaitingForFirstContentfulPaint();
  any_thread().waiting_for_any_main_frame_meaningful_paint =
      IsAnyOrdinaryMainFrameWaitingForFirstMeaningfulPaint();
  any_thread().is_any_main_frame_loading = IsAnyOrdinaryMainFrameLoading();
  any_thread().have_seen_input_since_navigation = false;
  main_thread_only().idle_time_estimator.Clear();
  UpdatePolicyLocked(UpdateType::kMayEarlyOutIfPolicyUnchanged);
}

void MainThreadSchedulerImpl::AddRAILModeObserver(RAILModeObserver* observer) {
  main_thread_only().rail_mode_observers.AddObserver(observer);
  observer->OnRAILModeChanged(main_thread_only().current_policy.rail_mode);
}

void MainThreadSchedulerImpl::RemoveRAILModeObserver(
    RAILModeObserver const* observer) {
  main_thread_only().rail_mode_observers.RemoveObserver(observer);
}

void MainThreadSchedulerImpl::ForEachMainThreadIsolate(
    base::RepeatingCallback<void(v8::Isolate* isolate)> callback) {
  // TODO(dtapuska): For each AgentGroupScheduler's isolate invoke the callback.
  if (v8::Isolate* isolate = Isolate()) {
    callback.Run(isolate);
  }
}

void MainThreadSchedulerImpl::SetRendererProcessType(
    WebRendererProcessType type) {
  main_thread_only().process_type = type;
}

Vector<WebInputEventAttribution>
MainThreadSchedulerImpl::GetPendingUserInputInfo(
    bool include_continuous) const {
  base::AutoLock lock(any_thread_lock_);
  return any_thread().pending_input_monitor.Info(include_continuous);
}

blink::MainThreadScheduler* MainThreadSchedulerImpl::ToMainThreadScheduler() {
  return this;
}

void MainThreadSchedulerImpl::RunIdleTask(Thread::IdleTask task,
                                          base::TimeTicks deadline) {
  std::move(task).Run(deadline);
}

void MainThreadSchedulerImpl::PostIdleTask(const base::Location& location,
                                           Thread::IdleTask task) {
  IdleTaskRunner()->PostIdleTask(
      location,
      base::BindOnce(&MainThreadSchedulerImpl::RunIdleTask, std::move(task)));
}

void MainThreadSchedulerImpl::PostDelayedIdleTask(
    const base::Location& location,
    base::TimeDelta delay,
    Thread::IdleTask task) {
  IdleTaskRunner()->PostDelayedIdleTask(
      location, delay,
      base::BindOnce(&MainThreadSchedulerImpl::RunIdleTask, std::move(task)));
}

void MainThreadSchedulerImpl::PostNonNestableIdleTask(
    const base::Location& location,
    Thread::IdleTask task) {
  IdleTaskRunner()->PostNonNestableIdleTask(
      location,
      base::BindOnce(&MainThreadSchedulerImpl::RunIdleTask, std::move(task)));
}

scoped_refptr<base::SingleThreadTaskRunner>
MainThreadSchedulerImpl::V8TaskRunner() {
  return v8_task_runner_;
}

scoped_refptr<base::SingleThreadTaskRunner>
MainThreadSchedulerImpl::V8UserVisibleTaskRunner() {
  return v8_user_visible_task_runner_;
}

scoped_refptr<base::SingleThreadTaskRunner>
MainThreadSchedulerImpl::V8BestEffortTaskRunner() {
  return v8_best_effort_task_runner_;
}

scoped_refptr<base::SingleThreadTaskRunner>
MainThreadSchedulerImpl::NonWakingTaskRunner() {
  return non_waking_task_runner_;
}

AgentGroupScheduler* MainThreadSchedulerImpl::CreateAgentGroupScheduler() {
  auto* agent_group_scheduler =
      MakeGarbageCollected<AgentGroupSchedulerImpl>(*this);
  AddAgentGroupScheduler(agent_group_scheduler);
  return agent_group_scheduler;
}

std::unique_ptr<WebAgentGroupScheduler>
MainThreadSchedulerImpl::CreateWebAgentGroupScheduler() {
  return std::make_unique<WebAgentGroupScheduler>(CreateAgentGroupScheduler());
}

void MainThreadSchedulerImpl::RemoveAgentGroupScheduler(
    AgentGroupSchedulerImpl* agent_group_scheduler) {
  DCHECK(main_thread_only().agent_group_schedulers);
  DCHECK(main_thread_only().agent_group_schedulers->Contains(
      agent_group_scheduler));
  main_thread_only().agent_group_schedulers->erase(agent_group_scheduler);
}

AgentGroupScheduler* MainThreadSchedulerImpl::GetCurrentAgentGroupScheduler() {
  helper_.CheckOnValidThread();
  return current_agent_group_scheduler_;
}

void MainThreadSchedulerImpl::SetV8Isolate(v8::Isolate* isolate) {
  ThreadSchedulerBase::SetV8Isolate(isolate);
}

v8::Isolate* MainThreadSchedulerImpl::Isolate() {
  return isolate();
}

base::TimeTicks MainThreadSchedulerImpl::MonotonicallyIncreasingVirtualTime() {
  return GetTickClock()->NowTicks();
}

void MainThreadSchedulerImpl::BeginAgentGroupSchedulerScope(
    AgentGroupScheduler* next_agent_group_scheduler) {
  scoped_refptr<base::SingleThreadTaskRunner> next_task_runner;
  const char* trace_event_scope_name;
  void* trace_event_scope_id;

  if (next_agent_group_scheduler) {
    // If the |next_agent_group_scheduler| is not null, it means that a
    // per-AgentSchedulingGroup task is about to start. In this case, a
    // per-AgentGroupScheduler scope starts.
    next_task_runner = next_agent_group_scheduler->DefaultTaskRunner(),
    trace_event_scope_name = "scheduler.agent_scope";
    trace_event_scope_id = next_agent_group_scheduler;
  } else {
    // If the |next_agent_group_scheduler| is null, it means that a
    // per-thread task is about to start. In this case, a per-thread scope
    // starts.
    next_task_runner = helper_.DefaultTaskRunner();
    trace_event_scope_name = "scheduler.thread_scope";
    trace_event_scope_id = this;
  }

  TRACE_EVENT_NESTABLE_ASYNC_BEGIN1(
      TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"), trace_event_scope_name,
      trace_event_scope_id, "agent_group_scheduler",
      static_cast<void*>(next_agent_group_scheduler));

  AgentGroupScheduler* previous_agent_group_scheduler =
      current_agent_group_scheduler_;
  current_agent_group_scheduler_ = next_agent_group_scheduler;

  scoped_refptr<base::SingleThreadTaskRunner> previous_task_runner =
      base::SingleThreadTaskRunner::GetCurrentDefault();
  std::unique_ptr<base::SingleThreadTaskRunner::CurrentDefaultHandle>
      single_thread_task_runner_current_handle_override;
  if (scheduling_settings().mbi_override_task_runner_handle &&
      next_task_runner != previous_task_runner) {
    // per-thread and per-AgentSchedulingGroup task runner allows nested
    // runloop. `MainThreadSchedulerImpl` guarantees that
    // `SingleThreadTaskRunner::GetCurrentDefault()` and
    // `SequencedTaskRunner::GetCurrentDefault()` return a proper task runner
    // even when a nested runloop is used. Because
    // `MainThreadSchedulerImpl::OnTaskStarted()` always overrides
    // STTR/STR::GetCurrentDefault() properly. So there is no concern about
    // returning an unexpected task runner from STTR/STR::GetCurrentDefault() in
    // this specific case.
    single_thread_task_runner_current_handle_override =
        std::unique_ptr<base::SingleThreadTaskRunner::CurrentDefaultHandle>(
            new base::SingleThreadTaskRunner::CurrentDefaultHandle(
                next_task_runner, base::SingleThreadTaskRunner::
                                      CurrentDefaultHandle::MayAlreadyExist{}));
  }

  main_thread_only().agent_group_scheduler_scope_stack.emplace_back(
      AgentGroupSchedulerScope{
          std::move(single_thread_task_runner_current_handle_override),
          previous_agent_group_scheduler, next_agent_group_scheduler,
          std::move(previous_task_runner), std::move(next_task_runner),
          trace_event_scope_name, trace_event_scope_id});
}

void MainThreadSchedulerImpl::EndAgentGroupSchedulerScope() {
  AgentGroupSchedulerScope& agent_group_scheduler_scope =
      main_thread_only().agent_group_scheduler_scope_stack.back();

  if (scheduling_settings().mbi_override_task_runner_handle) {
    DCHECK_EQ(base::SingleThreadTaskRunner::GetCurrentDefault(),
              agent_group_scheduler_scope.current_task_runner);
    DCHECK_EQ(base::SequencedTaskRunner::GetCurrentDefault(),
              agent_group_scheduler_scope.current_task_runner);
  }
  agent_group_scheduler_scope
      .single_thread_task_runner_current_handle_override = nullptr;
  DCHECK_EQ(base::SingleThreadTaskRunner::GetCurrentDefault(),
            agent_group_scheduler_scope.previous_task_runner);
  DCHECK_EQ(base::SequencedTaskRunner::GetCurrentDefault(),
            agent_group_scheduler_scope.previous_task_runner);

  current_agent_group_scheduler_ =
      agent_group_scheduler_scope.previous_agent_group_scheduler;

  TRACE_EVENT_NESTABLE_ASYNC_END1(
      TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
      agent_group_scheduler_scope.trace_event_scope_name,
      agent_group_scheduler_scope.trace_event_scope_id.get(),
      "agent_group_scheduler",
      static_cast<void*>(
          agent_group_scheduler_scope.current_agent_group_scheduler));

  main_thread_only().agent_group_scheduler_scope_stack.pop_back();
}

WebThreadScheduler* MainThreadSchedulerImpl::ToWebMainThreadScheduler() {
  return this;
}

const base::TickClock* MainThreadSchedulerImpl::GetTickClock() const {
  return helper_.GetClock();
}

base::TimeTicks MainThreadSchedulerImpl::NowTicks() const {
  return GetTickClock()->NowTicks();
}

void MainThreadSchedulerImpl::AddAgentGroupScheduler(
    AgentGroupSchedulerImpl* agent_group_scheduler) {
  bool is_new_entry = main_thread_only()
                          .agent_group_schedulers->insert(agent_group_scheduler)
                          .is_new_entry;
  DCHECK(is_new_entry);
}

void MainThreadSchedulerImpl::AddPageScheduler(
    PageSchedulerImpl* page_scheduler) {
  main_thread_only().page_schedulers.insert(page_scheduler);
  DetachOnIPCTaskPostedWhileInBackForwardCacheHandler();
  if (page_scheduler->IsOrdinary()) {
    // MemoryPurgeManager::OnPageCreated() assumes that the page isn't frozen.
    // Its logic must be modified if this assumption is broken in the future.
    CHECK(!page_scheduler->IsFrozen());
    memory_purge_manager_.OnPageCreated();
  }

  base::AutoLock lock(any_thread_lock_);
  any_thread().waiting_for_any_main_frame_contentful_paint =
      IsAnyOrdinaryMainFrameWaitingForFirstContentfulPaint();
  any_thread().waiting_for_any_main_frame_meaningful_paint =
      IsAnyOrdinaryMainFrameWaitingForFirstMeaningfulPaint();
  any_thread().is_any_main_frame_loading = IsAnyOrdinaryMainFrameLoading();
  UpdatePolicyLocked(UpdateType::kMayEarlyOutIfPolicyUnchanged);
}

void MainThreadSchedulerImpl::RemovePageScheduler(
    PageSchedulerImpl* page_scheduler) {
  DCHECK(base::Contains(main_thread_only().page_schedulers, page_scheduler));
  main_thread_only().page_schedulers.erase(page_scheduler);
  if (page_scheduler->IsOrdinary()) {
    memory_purge_manager_.OnPageDestroyed(
        /* frozen=*/page_scheduler->IsFrozen());
  }

  if (IsIpcTrackingEnabledForAllPages()) {
    SetOnIPCTaskPostedWhileInBackForwardCacheIfNeeded();
  }

  if (main_thread_only().is_audio_playing && page_scheduler->IsAudioPlaying()) {
    // This page may have been the only one playing audio.
    OnAudioStateChanged();
  }

  base::AutoLock lock(any_thread_lock_);
  any_thread().waiting_for_any_main_frame_contentful_paint =
      IsAnyOrdinaryMainFrameWaitingForFirstContentfulPaint();
  any_thread().waiting_for_any_main_frame_meaningful_paint =
      IsAnyOrdinaryMainFrameWaitingForFirstMeaningfulPaint();
  any_thread().is_any_main_frame_loading = IsAnyOrdinaryMainFrameLoading();
  UpdatePolicyLocked(UpdateType::kMayEarlyOutIfPolicyUnchanged);
}

void MainThreadSchedulerImpl::OnPageFrozen(
    base::MemoryReductionTaskContext called_from) {
  memory_purge_manager_.OnPageFrozen(called_from);
  UpdatePolicy();
}

void MainThreadSchedulerImpl::OnPageResumed() {
  memory_purge_manager_.OnPageResumed();
  UpdatePolicy();
}

void MainThreadSchedulerImpl::OnTaskStarted(
    MainThreadTaskQueue* queue,
    const base::sequence_manager::Task& task,
    const TaskQueue::TaskTiming& task_timing) {
  if (scheduling_settings().mbi_override_task_runner_handle) {
    BeginAgentGroupSchedulerScope(queue ? queue->GetAgentGroupScheduler()
                                        : nullptr);
  }

  main_thread_only().running_queues.push(queue);
  if (helper_.IsInNestedRunloop())
    return;

  main_thread_only().current_task_start_time = task_timing.start_time();
  main_thread_only().task_description_for_tracing = TaskDescriptionForTracing{
      static_cast<TaskType>(task.task_type),
      queue ? std::optional<MainThreadTaskQueue::QueueType>(queue->queue_type())
            : std::nullopt};

  main_thread_only().task_priority_for_tracing =
      queue ? std::optional<TaskPriority>(queue->GetQueuePriority())
            : std::nullopt;
}

void MainThreadSchedulerImpl::OnTaskCompleted(
    base::WeakPtr<MainThreadTaskQueue> queue,
    const base::sequence_manager::Task& task,
    TaskQueue::TaskTiming* task_timing,
    base::LazyNow* lazy_now) {
  TRACE_EVENT("renderer.scheduler", "BlinkScheduler_OnTaskCompleted");

  // Microtasks may detach the task queue and invalidate |queue|.
  PerformMicrotaskCheckpoint();

  task_timing->RecordTaskEnd(lazy_now);

  DCHECK_LE(task_timing->start_time(), task_timing->end_time());
  DCHECK(!main_thread_only().running_queues.empty());
  DCHECK(!queue ||
         main_thread_only().running_queues.top().get() == queue.get());
  if (task_timing->has_wall_time() && queue && queue->GetFrameScheduler())
    queue->GetFrameScheduler()->AddTaskTime(task_timing->wall_duration());
  main_thread_only().running_queues.pop();

  // The overriding TaskRunnerHandle scope ends here.
  if (scheduling_settings().mbi_override_task_runner_handle)
    EndAgentGroupSchedulerScope();

  if (helper_.IsInNestedRunloop())
    return;

  DispatchOnTaskCompletionCallbacks();

  if (queue) {
    queue->OnTaskRunTimeReported(task_timing);

    if (FrameSchedulerImpl* frame_scheduler = queue->GetFrameScheduler()) {
      frame_scheduler->OnTaskCompleted(task_timing);
    }
  }

  // TODO(altimin): Per-page metrics should also be considered.
  main_thread_only().metrics_helper.RecordTaskMetrics(queue.get(), task,
                                                      *task_timing);
  main_thread_only().task_description_for_tracing = std::nullopt;

  // Unset the state of |task_priority_for_tracing|.
  main_thread_only().task_priority_for_tracing = std::nullopt;

  RecordTaskUkm(queue.get(), task, *task_timing);

  MaybeUpdatePolicyOnTaskCompleted(queue.get(), *task_timing);

  find_in_page_budget_pool_controller_->OnTaskCompleted(queue.get(),
                                                        task_timing);
  ShutdownEmptyDetachedTaskQueues();
}

void MainThreadSchedulerImpl::RecordTaskUkm(
    MainThreadTaskQueue* queue,
    const base::sequence_manager::Task& task,
    const TaskQueue::TaskTiming& task_timing) {
  if (!helper_.ShouldRecordTaskUkm(task_timing.has_thread_time()))
    return;

  for (PageSchedulerImpl* page_scheduler : main_thread_only().page_schedulers) {
    auto status = RecordTaskUkmImpl(
        queue, task, task_timing,
        page_scheduler->SelectFrameForUkmAttribution(), false);
    UMA_HISTOGRAM_ENUMERATION(
        "Scheduler.Experimental.Renderer.UkmRecordingStatus", status,
        UkmRecordingStatus::kCount);
  }
}

UkmRecordingStatus MainThreadSchedulerImpl::RecordTaskUkmImpl(
    MainThreadTaskQueue* queue,
    const base::sequence_manager::Task& task,
    const TaskQueue::TaskTiming& task_timing,
    FrameSchedulerImpl* frame_scheduler,
    bool precise_attribution) {
  // Skip tasks which have deleted the frame or the page scheduler.
  if (!frame_scheduler)
    return UkmRecordingStatus::kErrorMissingFrame;
  if (!frame_scheduler->GetPageScheduler())
    return UkmRecordingStatus::kErrorDetachedFrame;

  ukm::UkmRecorder* ukm_recorder = frame_scheduler->GetUkmRecorder();
  // OOPIFs are not supported.
  if (!ukm_recorder)
    return UkmRecordingStatus::kErrorMissingUkmRecorder;

  ukm::builders::RendererSchedulerTask builder(
      frame_scheduler->GetUkmSourceId());

  builder.SetVersion(kUkmMetricVersion);
  builder.SetPageSchedulers(main_thread_only().page_schedulers.size());

  builder.SetRendererBackgrounded(
      main_thread_only().renderer_backgrounded.get());
  builder.SetRendererHidden(main_thread_only().renderer_hidden.get());
  builder.SetRendererAudible(main_thread_only().is_audio_playing);
  builder.SetUseCase(
      static_cast<int>(main_thread_only().current_use_case.get()));
  builder.SetTaskType(task.task_type);
  builder.SetQueueType(static_cast<int>(
      queue ? queue->queue_type() : MainThreadTaskQueue::QueueType::kDetached));
  builder.SetFrameStatus(static_cast<int>(
      GetFrameStatus(queue ? queue->GetFrameScheduler() : nullptr)));
  builder.SetTaskDuration(task_timing.wall_duration().InMicroseconds());
  builder.SetIsOOPIF(!frame_scheduler->GetPageScheduler()->IsMainFrameLocal());

  if (main_thread_only().renderer_backgrounded.get()) {
    base::TimeDelta time_since_backgrounded =
        (task_timing.end_time() -
         main_thread_only().background_status_changed_at);

    // Trade off for privacy: Round to seconds for times below 10 minutes and
    // minutes afterwards.
    int64_t seconds_since_backgrounded = 0;
    if (time_since_backgrounded < base::Minutes(10)) {
      seconds_since_backgrounded = time_since_backgrounded.InSeconds();
    } else {
      seconds_since_backgrounded =
          time_since_backgrounded.InMinutes() * kSecondsPerMinute;
    }

    builder.SetSecondsSinceBackgrounded(seconds_since_backgrounded);
  }

  if (task_timing.has_thread_time()) {
    builder.SetTaskCPUDuration(task_timing.thread_duration().InMicroseconds());
  }

  builder.Record(ukm_recorder);

  return UkmRecordingStatus::kSuccess;
}

TaskPriority MainThreadSchedulerImpl::ComputePriority(
    MainThreadTaskQueue* task_queue) const {
  DCHECK(task_queue);

  // If |task_queue| is associated to a frame, then the frame scheduler computes
  // the priority.
  FrameSchedulerImpl* frame_scheduler = task_queue->GetFrameScheduler();

  if (frame_scheduler) {
    return frame_scheduler->ComputePriority(task_queue);
  }

  if (task_queue->queue_type() == MainThreadTaskQueue::QueueType::kDefault) {
    return main_thread_only().current_policy.should_prioritize_ipc_tasks
               ? TaskPriority::kVeryHighPriority
               : TaskPriority::kNormalPriority;
  }

  switch (task_queue->GetPrioritisationType()) {
    case MainThreadTaskQueue::QueueTraits::PrioritisationType::kCompositor:
      return main_thread_only().compositor_priority;
    case MainThreadTaskQueue::QueueTraits::PrioritisationType::kInput:
      return TaskPriority::kHighestPriority;
    case MainThreadTaskQueue::QueueTraits::PrioritisationType::kBestEffort:
      return TaskPriority::kBestEffortPriority;
    case MainThreadTaskQueue::QueueTraits::PrioritisationType::kRegular:
      return TaskPriority::kNormalPriority;
    case MainThreadTaskQueue::QueueTraits::PrioritisationType::kLow:
      return TaskPriority::kLowPriority;
    default:
      NOTREACHED();
  }
}

void MainThreadSchedulerImpl::AddTaskTimeObserver(
    TaskTimeObserver* task_time_observer) {
  helper_.AddTaskTimeObserver(task_time_observer);
}

void MainThreadSchedulerImpl::RemoveTaskTimeObserver(
    TaskTimeObserver* task_time_observer) {
  helper_.RemoveTaskTimeObserver(task_time_observer);
}

std::unique_ptr<CPUTimeBudgetPool>
MainThreadSchedulerImpl::CreateCPUTimeBudgetPoolForTesting(const char* name) {
  return std::make_unique<CPUTimeBudgetPool>(name, &tracing_controller_,
                                             NowTicks());
}

void MainThreadSchedulerImpl::OnTraceLogEnabled() {
  CreateTraceEventObjectSnapshot();
  tracing_controller_.OnTraceLogEnabled();
  for (PageSchedulerImpl* page_scheduler : main_thread_only().page_schedulers) {
    page_scheduler->OnTraceLogEnabled();
  }
"""


```