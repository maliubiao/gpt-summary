Response: The user wants a summary of the functionality of the provided C++ code snippet. This code is part of the Chromium Blink rendering engine and specifically deals with main thread scheduling.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The code manages the scheduling of tasks on the main thread in the Blink rendering engine.

2. **Analyze key methods and data structures:**  Look for functions that perform actions related to scheduling, prioritization, idle time, and interaction with other components. Pay attention to member variables that hold state information.

3. **Categorize functionalities:** Group related methods and variables into logical categories like policy management, idle time handling, task execution, virtual time control, and interaction with other parts of the engine (like JavaScript, HTML, CSS via the rendering pipeline).

4. **Explain relationships with web technologies:** If a function or mechanism influences how JavaScript, HTML, or CSS are processed, provide concrete examples.

5. **Infer logical relationships (hypothetical inputs/outputs):**  For functions that make decisions based on state, consider a simple scenario and trace how the function would behave.

6. **Identify potential usage errors:**  Think about common mistakes developers might make when interacting with scheduling mechanisms.

7. **Synthesize a concise summary:** Combine the identified functionalities into a clear and understandable overview.
好的，这个代码片段是 `MainThreadSchedulerImpl` 类的另一个部分，继续定义了主线程调度器的具体功能。以下是这个部分的功能归纳：

**核心功能延续与扩展:**

* **判断是否能进入长空闲期 (`CanEnterLongIdlePeriod`)**:  根据当前状态（例如，是否正在处理 `touchstart` 事件）来决定是否可以开始执行长空闲任务。
    * **与 JavaScript, HTML, CSS 的关系**:  长空闲期通常用于执行不紧急的任务，例如某些 JavaScript 动画的优化，或者在用户没有交互时进行的资源清理，不直接影响关键渲染路径上的 HTML 和 CSS 处理。
    * **逻辑推理 (假设输入与输出)**:
        * **假设输入**:  `now` 为当前时间，`current_use_case` 为 `UseCase::kNone`。
        * **输出**: 返回 `true`，可以进入长空闲期。
        * **假设输入**: `now` 为当前时间，`current_use_case` 为 `UseCase::kTouchstart`，且 `current_policy_expiration_time` 大于 `now`。
        * **输出**: 返回 `false`，并将 `next_long_idle_period_delay_out` 设置为剩余时间。
* **提供测试接口 (`GetSchedulerHelperForTesting`, `GetIdleTimeEstimatorForTesting`)**:  暴露内部组件 `MainThreadSchedulerHelper` 和 `IdleTimeEstimator` 用于单元测试。
* **虚拟时间控制 (`GetVirtualTimeTaskRunner`, `OnVirtualTimeEnabled`, `OnVirtualTimeDisabled`, `OnVirtualTimePaused`, `OnVirtualTimeResumed`)**:  支持虚拟时间，这在测试和性能分析中很有用，可以控制时间的流逝。
    * **与 JavaScript, HTML, CSS 的关系**: 虚拟时间可以用于测试依赖于时间的 JavaScript 代码 (如 `setTimeout`, `requestAnimationFrame`)，以及模拟不同时间条件下的渲染行为。
    * **逻辑推理 (假设输入与输出)**:
        * **假设输入**: 调用 `OnVirtualTimeEnabled`。
        * **输出**: 创建并启动一个虚拟时间控制的任务队列。
        * **假设输入**: 调用 `OnVirtualTimePaused`。
        * **输出**: 在所有可以被暂停的任务队列中插入栅栏，阻止其继续执行。
* **创建和记录跟踪事件快照 (`CreateTraceEventObjectSnapshot`, `CreateTraceEventObjectSnapshotLocked`, `WriteIntoTraceLocked`)**:  用于性能分析和调试，记录调度器的状态信息。
    * **与 JavaScript, HTML, CSS 的关系**: 跟踪事件可以帮助开发者理解在特定时间点，调度器是如何处理与 JavaScript 执行、HTML 解析、CSS 样式计算相关的任务的。例如，可以观察到在页面加载期间，哪些任务占据了主线程。
* **策略控制 (`Policy::IsQueueEnabled`, `Policy::WriteIntoTrace`)**:  定义了调度策略，决定哪些任务队列应该被启用。
    * **与 JavaScript, HTML, CSS 的关系**:  调度策略会影响不同类型的任务的执行顺序，例如，在用户交互时，与用户输入响应相关的 JavaScript 任务可能会被优先执行，而某些非关键的 CSS 动画可能会被延迟。
    * **逻辑推理 (假设输入与输出)**:
        * **假设输入**: `use_case` 为 `UseCase::kTouchstart`，`task_queue` 可以被延迟。
        * **输出**: `IsQueueEnabled` 返回 `false`。
        * **假设输入**: `use_case` 为 `UseCase::kNone`，`task_queue` 可以被延迟。
        * **输出**: `IsQueueEnabled` 返回 `true`。
* **空闲期管理 (`OnIdlePeriodStarted`, `OnIdlePeriodEnded`)**:  处理空闲期的开始和结束事件，并更新调度策略。
    * **与 JavaScript, HTML, CSS 的关系**:  空闲期可以用于执行一些延迟任务，例如预渲染下一个页面，或执行不紧急的 JavaScript 代码。
* **待处理任务变化通知 (`OnPendingTasksChanged`, `DispatchRequestBeginMainFrameNotExpected`)**:  当待处理任务队列发生变化时，通知相关的组件（如 `PageSchedulerImpl`）。
    * **与 JavaScript, HTML, CSS 的关系**: 这与浏览器的渲染优化有关。当没有待处理的任务时，可以通知合成器可以开始合成帧，或者进入低功耗模式。
* **页面加载事件处理 (`DidStartProvisionalLoad`, `DidCommitProvisionalLoad`)**:  响应页面加载开始和提交事件，并重置调度器状态。
    * **与 JavaScript, HTML, CSS 的关系**:  页面加载是 Web 技术的核心过程。调度器需要根据加载阶段调整策略，例如在加载初期优先下载资源和解析 HTML。
* **主帧绘制处理 (`OnMainFramePaint`)**:  在主帧绘制完成后更新调度器状态和策略。
    * **与 JavaScript, HTML, CSS 的关系**:  主帧绘制是用户看到网页内容的关键时刻。调度器需要跟踪绘制状态，以便在绘制完成后调整策略。
* **导航重置 (`ResetForNavigationLocked`)**:  在页面导航发生时重置相关的状态。
    * **与 JavaScript, HTML, CSS 的关系**: 每次页面导航都意味着新的上下文，调度器需要清除之前的状态。
* **RAIL 模式观察者 (`AddRAILModeObserver`, `RemoveRAILModeObserver`)**:  允许其他组件监听 RAIL (Response, Animation, Idle, Load) 模式的变化。
    * **与 JavaScript, HTML, CSS 的关系**: RAIL 是一种性能模型，用于指导 Web 应用的性能优化。不同的 RAIL 模式下，调度器会采用不同的策略来处理任务，例如在 Load 阶段，会优先处理页面加载相关的任务。
* **遍历主线程 Isolate (`ForEachMainThreadIsolate`)**:  允许对所有与主线程相关的 JavaScript V8 Isolate 执行回调。
    * **与 JavaScript, HTML, CSS 的关系**:  JavaScript 的执行环境是 V8 Isolate。这个功能允许调度器与 JavaScript 引擎进行更底层的交互。
* **设置渲染器进程类型 (`SetRendererProcessType`)**:  记录渲染器进程的类型。
* **获取待处理用户输入信息 (`GetPendingUserInputInfo`)**:  获取当前待处理的用户输入事件的信息。
    * **与 JavaScript, HTML, CSS 的关系**:  调度器需要跟踪用户输入，以便优先处理与用户交互相关的任务，保证页面的响应性。
* **提供 `MainThreadScheduler` 接口 (`ToMainThreadScheduler`)**:  返回当前对象的 `MainThreadScheduler` 接口指针。
* **运行和提交空闲任务 (`RunIdleTask`, `PostIdleTask`, `PostDelayedIdleTask`, `PostNonNestableIdleTask`)**:  提供提交和执行空闲任务的接口。
    * **与 JavaScript, HTML, CSS 的关系**:  空闲任务可以用于执行一些非关键的 JavaScript 代码，或者在浏览器空闲时进行一些优化操作。
* **获取 V8 任务运行器 (`V8TaskRunner`, `V8UserVisibleTaskRunner`, `V8BestEffortTaskRunner`)**:  提供用于执行 JavaScript 任务的任务运行器。
    * **与 JavaScript, HTML, CSS 的关系**:  JavaScript 代码最终在 V8 引擎中执行，这些任务运行器负责将 JavaScript 任务调度到 V8 引擎。
* **创建和管理 AgentGroupScheduler (`CreateAgentGroupScheduler`, `CreateWebAgentGroupScheduler`, `RemoveAgentGroupScheduler`, `GetCurrentAgentGroupScheduler`)**:  支持基于 AgentGroup 的调度，用于隔离不同域的 JavaScript 执行。
    * **与 JavaScript, HTML, CSS 的关系**:  AgentGroupScheduler 用于处理不同域的 JavaScript 代码，这与浏览器的安全模型有关。
* **设置和获取 V8 Isolate (`SetV8Isolate`, `Isolate`)**:  允许设置和获取与调度器关联的 V8 Isolate。
* **单调递增的虚拟时间 (`MonotonicallyIncreasingVirtualTime`)**:  提供单调递增的虚拟时间，用于测试。
* **AgentGroupScheduler 作用域管理 (`BeginAgentGroupSchedulerScope`, `EndAgentGroupSchedulerScope`)**:  在执行特定 AgentGroup 的任务前后设置和清理上下文。
* **提供 `WebThreadScheduler` 接口 (`ToWebMainThreadScheduler`)**:  返回当前对象的 `WebThreadScheduler` 接口指针。
* **获取时钟 (`GetTickClock`, `NowTicks`)**:  提供获取当前时间的接口。
* **添加和移除 PageScheduler (`AddPageScheduler`, `RemovePageScheduler`)**:  管理与每个页面相关的调度器。
    * **与 JavaScript, HTML, CSS 的关系**:  每个页面都有自己的生命周期和需要处理的任务，PageScheduler 负责管理这些任务的调度。
* **页面冻结和恢复通知 (`OnPageFrozen`, `OnPageResumed`)**:  响应页面冻结和恢复事件，并更新调度策略。
* **任务开始和完成处理 (`OnTaskStarted`, `OnTaskCompleted`)**:  在任务开始和完成时执行相应的操作，例如记录任务执行时间，更新调度策略。
    * **与 JavaScript, HTML, CSS 的关系**:  这是调度器的核心功能，跟踪任务的执行情况，并根据执行情况调整后续的调度策略。例如，如果一个 JavaScript 任务执行时间过长，可能会影响到后续的渲染帧率。
* **记录任务 UKM 指标 (`RecordTaskUkm`, `RecordTaskUkmImpl`)**:  记录任务相关的 UKM (User Key Metrics) 指标用于性能分析。
    * **与 JavaScript, HTML, CSS 的关系**:  这些指标可以帮助开发者了解不同类型任务的性能表现，例如 JavaScript 执行耗时，渲染耗时等。
* **计算任务优先级 (`ComputePriority`)**:  根据任务队列的类型和当前状态计算任务的优先级。
* **添加和移除任务时间观察者 (`AddTaskTimeObserver`, `RemoveTaskTimeObserver`)**:  允许其他组件监听任务执行时间。
* **创建 CPU 时间预算池 (用于测试) (`CreateCPUTimeBudgetPoolForTesting`)**:  提供创建 CPU 时间预算池的接口，用于测试。
* **跟踪日志开关处理 (`OnTraceLogEnabled`, `OnTraceLogDisabled`)**:  在跟踪日志开启和关闭时执行相应的操作。
* **获取弱指针 (`GetWeakPtr`)**:  提供获取对象弱指针的接口。
* **音频播放状态查询 (`IsAudioPlaying`)**:  查询是否有音频正在播放。
    * **与 JavaScript, HTML, CSS 的关系**:  音频播放状态会影响浏览器的优先级策略，例如，正在播放音频的页面可能需要更高的优先级。
* **判断是否需要更新任务队列优先级 (`ShouldUpdateTaskQueuePriorities`)**:  根据策略变化判断是否需要更新任务队列的优先级。
* **获取当前 UseCase (`current_use_case`)**:  返回当前的使用场景。
* **获取调度设置 (`scheduling_settings`)**:  返回调度器的配置参数。
* **计算合成器任务队列优先级 (`ComputeCompositorPriority`, `UpdateCompositorTaskQueuePriority`, `ComputeCompositorPriorityFromUseCase`, `ComputeCompositorPriorityForMainFrame`)**:  根据不同的因素计算和更新合成器任务队列的优先级。
    * **与 JavaScript, HTML, CSS 的关系**:  合成器任务负责将渲染层组合成最终的图像。合理的优先级设置可以保证动画的流畅性，避免卡顿。例如，在用户进行手势操作时，合成器任务的优先级应该更高。
* **根据任务完成情况更新策略 (`MaybeUpdatePolicyOnTaskCompleted`, `UpdateRenderingPrioritizationStateOnTaskCompleted`)**:  在任务完成后，根据任务的执行情况和当前状态更新调度策略。
* **判断所有页面是否都冻结 (`AllPagesFrozen`)**:  检查是否所有页面都被冻结。
* **枚举类型转字符串 (`RAILModeToString`, `TimeDomainTypeToString`)**:  提供将枚举类型转换为字符串的辅助函数，用于调试和日志记录。
* **获取任务完成回调队列 (`GetOnTaskCompletionCallbacks`)**:  提供访问任务完成回调队列的接口。
* **在当前任务完成后执行 (`ExecuteAfterCurrentTaskForTesting`)**: 提供在当前任务完成后执行指定闭包的接口，用于测试。
* **处理紧急消息 (`OnUrgentMessageReceived`, `OnUrgentMessageProcessed`)**:  处理来自其他进程的紧急消息，并可能调整调度策略。
* **处理 WebSchedulingTaskQueue 优先级变化 (`OnWebSchedulingTaskQueuePriorityChanged`)**:  响应 Web 调度任务队列的优先级变化，并根据当前策略调整队列的启用状态。

**与 JavaScript, HTML, CSS 的关系举例:**

* **JavaScript 动画:** 当 JavaScript 代码执行动画时，调度器可能会将其任务优先级提高，以确保动画的流畅性。
* **HTML 解析:** 在页面加载初期，HTML 解析任务可能会被优先执行，以便更快地构建 DOM 树。
* **CSS 样式计算:**  CSS 样式的计算会影响渲染树的构建，调度器会根据当前的状态（例如，是否在滚动）来调整相关任务的优先级。
* **用户交互:** 当用户点击或滚动页面时，与这些交互相关的 JavaScript 事件处理任务会被优先调度，以保证页面的响应速度。

**逻辑推理 (假设输入与输出) 举例:**

* **假设输入:** 用户开始触摸屏幕 (touchstart 事件)。
* **输出:** `GetCurrentUseCase()` 可能会返回 `UseCase::kTouchstart`，并且调度器会优先处理与 `touchstart` 事件相关的任务，例如阻止长空闲期的执行。

**用户或编程常见的使用错误举例:**

* **过度使用高优先级任务:**  如果开发者将所有任务都设置为高优先级，可能会导致某些低优先级但重要的任务被饿死，例如 Service Worker 的后台同步任务。
* **在不适合的时机执行耗时任务:**  如果在用户交互的关键路径上执行长时间运行的 JavaScript 代码，会导致页面卡顿，影响用户体验。调度器的存在就是为了尽量避免这种情况。

**总结:**

这个代码片段继续完善了 `MainThreadSchedulerImpl` 类的功能，涵盖了虚拟时间控制、更细粒度的调度策略管理、与外部组件的交互（如 PageScheduler 和 V8 引擎）、性能分析和调试支持、以及对页面生命周期事件的响应。它深入到了 Blink 渲染引擎主线程调度的核心逻辑，负责协调各种任务的执行顺序和优先级，以保证页面的流畅性和响应性，并优化资源利用率。 这些功能共同确保了浏览器能够高效地处理 JavaScript、HTML 和 CSS，为用户提供良好的浏览体验。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
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
}

void MainThreadSchedulerImpl::OnTraceLogDisabled() {}

base::WeakPtr<MainThreadSchedulerImpl> MainThreadSchedulerImpl::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

bool MainThreadSchedulerImpl::IsAudioPlaying() const {
  return main_thread_only().is_audio_playing;
}

bool MainThreadSchedulerImpl::ShouldUpdateTaskQueuePriorities(
    Policy old_policy) const {
  return old_policy.use_case != main_thread_only().current_policy.use_case ||
         old_policy.find_in_page_priority !=
             main_thread_only().current_policy.find_in_page_priority ||
         old_policy.should_prioritize_ipc_tasks !=
             main_thread_only().current_policy.should_prioritize_ipc_tasks;
}

UseCase MainThreadSchedulerImpl::current_use_case() const {
  return main_thread_only().current_use_case;
}

const MainThreadSchedulerImpl::SchedulingSettings&
MainThreadSchedulerImpl::scheduling_settings() const {
  return scheduling_settings_;
}

TaskPriority MainThreadSchedulerImpl::ComputeCompositorPriority() const {
  std::optional<TaskPriority> targeted_main_frame_priority =
      ComputeCompositorPriorityForMainFrame();
  std::optional<TaskPriority> use_case_priority =
      ComputeCompositorPriorityFromUseCase();
  if (!targeted_main_frame_priority && !use_case_priority) {
    return TaskPriority::kNormalPriority;
  } else if (!use_case_priority) {
    return *targeted_main_frame_priority;
  } else if (!targeted_main_frame_priority) {
    return *use_case_priority;
  }

  // Both are set, so some reconciliation is needed.
  CHECK(targeted_main_frame_priority && use_case_priority);
  // If either votes for the highest priority, use that to simplify the
  // remaining case.
  if (*targeted_main_frame_priority == TaskPriority::kHighestPriority ||
      *use_case_priority == TaskPriority::kHighestPriority) {
    return TaskPriority::kHighestPriority;
  }
  // Otherwise, this must be a combination of UseCase::kCompositorGesture and
  // rendering starvation since all other states set the priority to highest.
  CHECK(current_use_case() == UseCase::kCompositorGesture &&
        (main_thread_only().main_frame_prioritization_state ==
             RenderingPrioritizationState::kRenderingStarved ||
         main_thread_only().main_frame_prioritization_state ==
             RenderingPrioritizationState::kRenderingStarvedByRenderBlocking));

  // The default behavior for compositor gestures like compositor-driven
  // scrolling is to deprioritize compositor TQ tasks (low priority) and not
  // apply delay-based anti-starvation. This can lead to degraded user
  // experience due to increased checkerboarding or scrolling blank content.
  // When `features::kThreadedScrollPreventRenderingStarvation` is enabled, we
  // use a configurable value to control the delay-based anti-starvation to
  // mitigate these issues.
  //
  // Note: for other use cases, the computed priority is higher, so they are
  // not prone to rendering starvation in the same way.
  if (!base::FeatureList::IsEnabled(
          features::kThreadedScrollPreventRenderingStarvation)) {
    return *use_case_priority;
  } else {
    CHECK_LE(*targeted_main_frame_priority, *use_case_priority);
    return *targeted_main_frame_priority;
  }
}

void MainThreadSchedulerImpl::UpdateCompositorTaskQueuePriority() {
  TaskPriority old_compositor_priority = main_thread_only().compositor_priority;
  main_thread_only().compositor_priority = ComputeCompositorPriority();

  if (old_compositor_priority == main_thread_only().compositor_priority)
    return;

  for (const auto& pair : task_runners_) {
    if (pair.first->GetPrioritisationType() !=
        MainThreadTaskQueue::QueueTraits::PrioritisationType::kCompositor)
      continue;
    pair.first->SetQueuePriority(ComputePriority(pair.first.get()));
  }
}

void MainThreadSchedulerImpl::MaybeUpdatePolicyOnTaskCompleted(
    MainThreadTaskQueue* queue,
    const base::sequence_manager::TaskQueue::TaskTiming& task_timing) {
  bool needs_policy_update = false;

  bool should_prioritize_ipc_tasks =
      num_pending_urgent_ipc_messages_.load(std::memory_order_relaxed) > 0;
  if (should_prioritize_ipc_tasks !=
      main_thread_only().current_policy.should_prioritize_ipc_tasks) {
    needs_policy_update = true;
  }

  if (base::FeatureList::IsEnabled(features::kDeferRendererTasksAfterInput) &&
      queue) {
    base::AutoLock lock(any_thread_lock_);
    // In web tests using non-threaded compositing, BeginMainFrame is scheduled
    // (eagarly) via a per-frame kInternalTest task runner, which is ignored
    // here.
    // TODO(crbug.com/350540984): Consider using the appropriate compositor task
    // queue for tests that use non-threaded compositing.
    if (main_thread_only().is_current_task_main_frame &&
        queue->queue_type() == MainThreadTaskQueue::QueueType::kCompositor) {
      if (any_thread().awaiting_discrete_input_response) {
        any_thread().awaiting_discrete_input_response = false;
        any_thread().user_model.DidProcessDiscreteInputResponse();
        needs_policy_update = true;
      }
    } else if (queue->queue_type() == MainThreadTaskQueue::QueueType::kInput &&
               main_thread_only().is_frame_requested_after_discrete_input) {
      CHECK(main_thread_only().is_current_task_discrete_input);
      any_thread().awaiting_discrete_input_response = true;
      any_thread().user_model.DidProcessDiscreteInputEvent(
          task_timing.end_time());
      needs_policy_update = true;
    }
  }

  RenderingPrioritizationState old_state =
      main_thread_only().main_frame_prioritization_state;
  UpdateRenderingPrioritizationStateOnTaskCompleted(queue, task_timing);

  main_thread_only().is_current_task_discrete_input = false;
  main_thread_only().is_frame_requested_after_discrete_input = false;
  main_thread_only().is_current_task_main_frame = false;

  if (needs_policy_update) {
    UpdatePolicy();
  } else if (old_state != main_thread_only().main_frame_prioritization_state) {
    UpdateCompositorTaskQueuePriority();
  }
}

void MainThreadSchedulerImpl::UpdateRenderingPrioritizationStateOnTaskCompleted(
    MainThreadTaskQueue* queue,
    const base::sequence_manager::TaskQueue::TaskTiming& task_timing) {
  if (queue &&
      queue->GetQueuePriority() == TaskPriority::kExtremelyHighPriority) {
    main_thread_only().rendering_blocking_duration_since_last_frame +=
        task_timing.wall_duration();
  }

  // With `features::kThreadedScrollPreventRenderingStarvation` enabled, no
  // rendering anti-starvation policy should kick in until the configurable
  // threshold is reached when in `UseCase::kCompositorGesture`.
  base::TimeDelta render_blocking_starvation_threshold =
      base::FeatureList::IsEnabled(
          features::kThreadedScrollPreventRenderingStarvation) &&
              current_use_case() == UseCase::kCompositorGesture &&
              kRenderBlockingStarvationThreshold <
                  scheduling_settings_
                      .compositor_gesture_rendering_starvation_threshold
          ? scheduling_settings_
                .compositor_gesture_rendering_starvation_threshold
          : kRenderBlockingStarvationThreshold;

  // A main frame task resets the rendering prioritization state. Otherwise if
  // the scheduler is waiting for a frame because of discrete input, the state
  // will only change once a main frame happens. Otherwise, compute the state in
  // descending priority order.
  if (queue &&
      queue->queue_type() == MainThreadTaskQueue::QueueType::kCompositor &&
      main_thread_only().is_current_task_main_frame) {
    main_thread_only().last_frame_time = task_timing.end_time();
    main_thread_only().rendering_blocking_duration_since_last_frame =
        base::TimeDelta();
    main_thread_only().main_frame_prioritization_state =
        RenderingPrioritizationState::kNone;
  } else if (main_thread_only().main_frame_prioritization_state !=
             RenderingPrioritizationState::kWaitingForInputResponse) {
    if (queue &&
        queue->queue_type() == MainThreadTaskQueue::QueueType::kInput &&
        main_thread_only().is_current_task_discrete_input) {
      // Assume this input will result in a frame, which we want to show ASAP.
      main_thread_only().main_frame_prioritization_state =
          RenderingPrioritizationState::kWaitingForInputResponse;
    } else if (main_thread_only()
                   .rendering_blocking_duration_since_last_frame >=
               render_blocking_starvation_threshold) {
      main_thread_only().main_frame_prioritization_state =
          RenderingPrioritizationState::kRenderingStarvedByRenderBlocking;
    } else {
      base::TimeDelta threshold;
      switch (current_use_case()) {
        case UseCase::kCompositorGesture:
          threshold = scheduling_settings_
                          .compositor_gesture_rendering_starvation_threshold;
          break;
        case UseCase::kEarlyLoading:
          threshold =
              scheduling_settings_.prioritize_compositing_after_delay_pre_fcp;
          break;
        default:
          threshold =
              scheduling_settings_.prioritize_compositing_after_delay_post_fcp;
          break;
      }
      if (task_timing.end_time() - main_thread_only().last_frame_time >=
          threshold) {
        main_thread_only().main_frame_prioritization_state =
            RenderingPrioritizationState::kRenderingStarved;
      }
    }
  }
}

std::optional<TaskPriority>
MainThreadSchedulerImpl::ComputeCompositorPriorityFromUseCase() const {
  switch (current_use_case()) {
    case UseCase::kCompositorGesture:
      if (main_thread_only().blocking_input_expected_soon)
        return TaskPriority::kHighestPriority;
      // What we really want to do is priorize loading tasks, but that doesn't
      // seem to be safe. Instead we do that by proxy by deprioritizing
      // compositor tasks. This should be safe since we've already gone to the
      // pain of fixing ordering issues with them.
      //
      // During periods of main-thread contention, e.g. scrolling while loading
      // new content, rendering can be indefinitely starved, leading user
      // experience issues like scrolling blank/stale content and
      // checkerboarding. We adjust the compositor TQ priority and enable
      // delay-based rendering anti-starvation when the
      // `kThreadedScrollPreventRenderingStarvation` experiment is enabled to
      // mitigate these issues.
      return TaskPriority::kLowPriority;

    case UseCase::kSynchronizedGesture:
    case UseCase::kMainThreadCustomInputHandling:
      // In main thread input handling use case we don't have perfect knowledge
      // about which things we should be prioritizing, so we don't attempt to
      // block expensive tasks because we don't know whether they were integral
      // to the page's functionality or not.
      if (main_thread_only().main_thread_compositing_is_fast)
        return TaskPriority::kHighestPriority;
      return std::nullopt;

    case UseCase::kMainThreadGesture:
    case UseCase::kTouchstart:
    case UseCase::kDiscreteInputResponse:
      // A main thread gesture is for example a scroll gesture which is handled
      // by the main thread. Since we know the established gesture type, we can
      // be a little more aggressive about prioritizing compositing and input
      // handling over other tasks.
      return TaskPriority::kHighestPriority;

    case UseCase::kNone:
    case UseCase::kEarlyLoading:
    case UseCase::kLoading:
      return std::nullopt;
  }
}

std::optional<TaskPriority>
MainThreadSchedulerImpl::ComputeCompositorPriorityForMainFrame() const {
  switch (main_thread_only().main_frame_prioritization_state) {
    case RenderingPrioritizationState::kNone:
      return std::nullopt;
    case RenderingPrioritizationState::kRenderingStarved:
      // Set higher than most tasks, but lower than render blocking tasks and
      // input.
      return TaskPriority::kVeryHighPriority;
    case RenderingPrioritizationState::kRenderingStarvedByRenderBlocking:
      // Set to rendering blocking to prevent starvation by render blocking
      // tasks, but don't block input.
      return TaskPriority::kExtremelyHighPriority;
    case RenderingPrioritizationState::kWaitingForInputResponse:
      // Return the highest priority here otherwise consecutive heavy inputs
      // (e.g. typing) will starve rendering.
      return TaskPriority::kHighestPriority;
  }
  NOTREACHED();
}

bool MainThreadSchedulerImpl::AllPagesFrozen() const {
  if (main_thread_only().page_schedulers.empty())
    return false;
  for (const auto* scheduler : main_thread_only().page_schedulers) {
    if (!scheduler->IsFrozen())
      return false;
  }
  return true;
}

// static
const char* MainThreadSchedulerImpl::RAILModeToString(RAILMode rail_mode) {
  switch (rail_mode) {
    case RAILMode::kDefault:
      return "idle";
    case RAILMode::kLoad:
      return "load";
  }
  NOTREACHED();
}

// static
const char* MainThreadSchedulerImpl::TimeDomainTypeToString(
    TimeDomainType domain_type) {
  switch (domain_type) {
    case TimeDomainType::kReal:
      return "real";
    case TimeDomainType::kVirtual:
      return "virtual";
    default:
      NOTREACHED();
  }
}

WTF::Vector<base::OnceClosure>&
MainThreadSchedulerImpl::GetOnTaskCompletionCallbacks() {
  return main_thread_only().on_task_completion_callbacks;
}

void MainThreadSchedulerImpl::ExecuteAfterCurrentTaskForTesting(
    base::OnceClosure on_completion_task,
    ExecuteAfterCurrentTaskRestricted) {
  ThreadSchedulerBase::ExecuteAfterCurrentTask(std::move(on_completion_task));
}

void MainThreadSchedulerImpl::OnUrgentMessageReceived() {
  std::atomic_fetch_add_explicit(&num_pending_urgent_ipc_messages_, 1u,
                                 std::memory_order_relaxed);
}

void MainThreadSchedulerImpl::OnUrgentMessageProcessed() {
  uint64_t prev_urgent_message_count = std::atomic_fetch_sub_explicit(
      &num_pending_urgent_ipc_messages_, 1u, std::memory_order_relaxed);
  CHECK_GT(prev_urgent_message_count, 0u);
}

void MainThreadSchedulerImpl::OnWebSchedulingTaskQueuePriorityChanged(
    MainThreadTaskQueue* queue) {
  if (!base::FeatureList::IsEnabled(features::kDeferRendererTasksAfterInput)) {
    return;
  }
  CHECK(scheduling_settings().discrete_input_task_deferral_policy);
  features::TaskDeferralPolicy policy =
      *scheduling_settings().discrete_input_task_deferral_policy;
  if (policy == features::TaskDeferralPolicy::kNonUserBlockingDeferrableTypes ||
      policy == features::TaskDeferralPolicy::kNonUserBlockingTypes ||
      policy == features::TaskDeferralPolicy::kMinimalTypes) {
    CHECK(queue);
    auto iter = task_runners_.find(queue);
    CHECK(iter != task_runners_.end());
    TaskQueue::QueueEnabledVoter* voter = iter->second.get();
    CHECK(voter);
    voter->SetVoteToEnable(main_thread_only().current_policy.IsQueueEnabled(
        queue, scheduling_settings()));
  }
}

}  // namespace scheduler
}  // namespace blink
```