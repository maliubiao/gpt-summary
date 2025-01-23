Response:
The user is asking for a summary of the functionality of the `FrameSchedulerImpl` class in the Chromium Blink engine, specifically focusing on its relationship with JavaScript, HTML, CSS, logical reasoning, and common user/programming errors. This is the second part of a two-part request.

My plan is to:
1. **Review the provided code snippet** and identify the key functionalities of the `FrameSchedulerImpl` class.
2. **Relate these functionalities to the core web technologies:** JavaScript, HTML, and CSS.
3. **Analyze any logical reasoning** present in the code, identifying assumptions, inputs, and outputs.
4. **Identify potential user or programming errors** that could arise from improper use of this class or related components.
5. **Synthesize a concise summary** of the class's purpose based on the identified functionalities.

Here's a breakdown of the code snippet's functionalities:

- **Frame Lifecycle Management:**  Handles the visibility, pausing, freezing, and throttling of frames.
- **Task Scheduling:** Manages task queues associated with the frame, including prioritization and throttling.
- **Integration with Page Scheduler:** Interacts with the `PageScheduler` to coordinate scheduling across the entire page.
- **Performance Monitoring:**  Provides hooks for tracing and UKM (User Metrics) recording.
- **Back/Forward Cache Interaction:** Handles tasks related to caching and restoring frames from the back/forward cache.
- **Web Scheduling API Implementation:**  Supports the `scheduler.postTask()` API.

Now, I'll elaborate on each point and its relevance to the user's requirements.
好的，根据您提供的代码片段（第2部分），让我们继续归纳 `FrameSchedulerImpl` 的功能，并补充之前未涉及的部分。

**归纳 `FrameSchedulerImpl` 的功能（结合第1部分和第2部分）：**

`FrameSchedulerImpl` 是 Chromium Blink 引擎中负责管理单个渲染帧内任务调度的核心组件。它的主要职责是确保帧内的任务（例如 JavaScript 执行、布局计算、渲染绘制等）以高效且符合用户体验的方式执行。  它与 `PageScheduler` 协同工作，共同管理整个页面的渲染调度。

更具体地说，`FrameSchedulerImpl` 负责以下功能：

1. **帧生命周期管理:**
    *   **跟踪帧的可见性 (`frame_visible_`, `IsPageVisible()`)**:  确定帧是否在屏幕上可见，这会影响任务的优先级和是否需要进行节流。
    *   **暂停和恢复帧 (`SetPaused()`)**:  允许暂停帧内的任务执行，常用于调试或在特定状态下阻止帧的活动。
    *   **冻结和解冻帧 (`UpdateQueuePolicy()` 结合 `parent_page_scheduler_->IsFrozen()`)**:  在后台或特定情况下冻结帧以节省资源，并在帧重新可见时解冻。
    *   **子资源加载控制 (`GetPauseSubresourceLoadingHandle()`, `AddPauseSubresourceLoadingHandle()`, `RemovePauseSubresourceLoadingHandle()`)**: 允许暂停和恢复帧内子资源的加载，例如图片、脚本等。

2. **任务队列管理和调度策略:**
    *   **管理帧相关的任务队列 (`frame_task_queue_controller_`)**:  维护与此帧相关联的各种任务队列，每个队列可能具有不同的优先级和特性。
    *   **计算和应用任务优先级 (`ComputePriority()`, `UpdatePriority()`)**:  根据多种因素（例如任务类型、用户交互、帧的可见性等）确定任务的执行优先级。
    *   **应用节流策略 (`ComputeThrottlingType()`, `UpdatePolicy()`)**:  根据帧的可见性、是否播放音频等因素，决定是否以及如何节流帧内的任务执行，以优化性能和功耗。 包括前台非重要帧的定时器节流 (`ThrottlingType::kForegroundUnimportant`) 和后台帧的节流 (`ThrottlingType::kBackground`, `ThrottlingType::kBackgroundIntensive`)。
    *   **管理任务队列的启用和禁用 (`UpdateQueuePolicy()`, `TaskQueue::QueueEnabledVoter`)**:  根据帧的状态（例如是否暂停、是否冻结、是否可见）启用或禁用任务队列。
    *   **支持 `scheduler.postTask()` API (`CreateWebSchedulingTaskQueue()`, `OnWebSchedulingTaskQueuePriorityChanged()`, `OnWebSchedulingTaskQueueDestroyed()`)**:  实现了 Web 标准的 `scheduler.postTask()` API，允许 JavaScript 代码更精细地控制任务的调度。

3. **与页面调度器的交互 (`parent_page_scheduler_`)**:
    *   **获取页面级别的状态信息**:  例如，页面是否可见、是否正在播放音频、是否被冻结等，这些信息会影响帧内任务的调度。
    *   **参与 CPU 时间预算和唤醒预算管理 (`GetWakeUpBudgetPool()`, `AddQueueToWakeUpBudgetPool()`, `RemoveQueueFromWakeUpBudgetPool()`)**:  与页面调度器协同工作，根据预算限制帧内任务的执行频率，特别是在后台时。

4. **性能监控和追踪:**
    *   **写入追踪信息 (`WriteIntoTrace()`)**:  将帧的状态信息写入性能追踪系统，用于分析性能瓶颈。
    *   **集成 UKM (User Metrics) (`GetUkmRecorder()`, `GetUkmSourceId()`)**:  允许记录与帧相关的用户指标，用于分析用户体验。

5. **Back/Forward 缓存支持 (`SetOnIPCTaskPostedWhileInBackForwardCacheHandler()`, `DetachOnIPCTaskPostedWhileInBackForwardCacheHandler()`, `OnIPCTaskPostedWhileInBackForwardCache()`, `GetActiveFeaturesTrackedForBackForwardCacheMetrics()`)**:
    *   处理当页面进入 Back/Forward 缓存后可能发生的 IPC 消息，并记录这些意外的消息。
    *   跟踪影响 Back/Forward 缓存的特性。

6. **渲染流水线集成:**
    *   **通知主线程调度器关键渲染事件 (`OnFirstContentfulPaintInMainFrame()`, `OnMainFrameInteractive()`, `OnFirstMeaningfulPaint()`, `OnDispatchLoadEvent()`)**:  将帧内的关键渲染事件通知给主线程调度器，以便进行全局的调度优化。
    *   **确定加载状态 (`IsWaitingForContentfulPaint()`, `IsWaitingForMeaningfulPaint()`, `IsLoading()`)**:  跟踪帧的加载状态，影响某些任务的优先级。

7. **合作式调度的支持 (`SetPreemptedForCooperativeScheduling()`)**: 允许更高优先级的任务在当前任务执行到某个点时主动让出 CPU，实现更精细的任务调度。

**与 JavaScript, HTML, CSS 的关系举例:**

*   **JavaScript**:
    *   当 JavaScript 代码调用 `setTimeout` 或 `setInterval` 时，`FrameSchedulerImpl` 会参与管理这些定时器任务的执行时机，并可能在后台进行节流。例如，如果一个标签页被切换到后台，`ComputeThrottlingType()` 可能会返回 `ThrottlingType::kBackground`，从而延迟定时器的触发。
    *   `scheduler.postTask()` API 直接由 `FrameSchedulerImpl` 实现，允许 JavaScript 代码指定任务的优先级和延迟执行。例如，`scheduler.postTask({priority: 'user-blocking'}, () => { ... })` 将创建一个高优先级的任务队列。
    *   JavaScript 可以触发 DOM 操作，这些操作会在 `FrameSchedulerImpl` 管理的任务队列中排队执行。例如，通过 JavaScript 修改 `innerHTML` 可能会创建一个 `DOMManipulation` 类型的任务。
*   **HTML**:
    *   HTML 结构决定了帧的类型（主帧或子帧），这会影响 `FrameSchedulerImpl` 的调度策略。例如，跨域子帧的定时器可能会受到更严格的节流。
    *   HTML 中 `<script>` 标签的属性（如 `async`, `defer`) 会影响脚本的加载和执行时机，`FrameSchedulerImpl` 会参与管理这些脚本的执行顺序。
*   **CSS**:
    *   CSS 样式的改变可能触发布局和重绘，这些操作会作为任务添加到 `FrameSchedulerImpl` 管理的任务队列中。 例如，通过 JavaScript 修改元素的 `className` 可能会触发样式计算和布局。

**逻辑推理的假设输入与输出:**

假设输入：

1. `frame_visible_` 为 `false` (帧不可见)。
2. `parent_page_scheduler_->IsPageVisible()` 为 `false` (页面不可见)。
3. `parent_page_scheduler_->IsAudioPlaying()` 为 `false` (页面没有播放音频)。
4. `RuntimeEnabledFeatures::TimerThrottlingForBackgroundTabsEnabled()` 为 `true` (后台标签页定时器节流已启用)。

逻辑推理（在 `ComputeThrottlingType()` 中）：

*   由于 `frame_visible_` 和 `parent_page_scheduler_->IsPageVisible()` 均为 `false`，`frame_can_be_throttled_background` 为 `true`。
*   由于 `parent_page_scheduler_->IsAudioPlaying()` 为 `false`，且页面不可见，`page_can_be_throttled_intensively` 也为 `true`。
*   由于 `RuntimeEnabledFeatures::TimerThrottlingForBackgroundTabsEnabled()` 为 `true`，并且 `page_can_be_throttled_intensively` 为 `true`。

输出：

*   `ComputeThrottlingType()` 将返回 `ThrottlingType::kBackgroundIntensive`。这意味着帧内的定时器任务将以更严格的方式进行节流。

**用户或编程常见的使用错误举例:**

1. **过度依赖高优先级任务**:  如果开发者将所有任务都设置为高优先级，可能会导致真正的用户交互任务被延迟，反而降低用户体验。例如，不必要地将数据预fetch 任务设置为 `user-blocking` 优先级。
2. **在后台标签页执行不必要的密集计算**:  即使 Blink 引擎会进行节流，在后台标签页执行大量的 JavaScript 计算仍然会消耗用户的 CPU 和电量。开发者应该避免在后台执行非必要的任务。
3. **错误地假设定时器在后台会立即触发**:  开发者需要意识到，当标签页进入后台时，定时器可能会被延迟触发。依赖精确的定时器触发时间在后台可能导致逻辑错误。
4. **不理解 `scheduler.postTask()` 的优先级和延迟选项**:  错误地使用 `scheduler.postTask()` 的优先级或延迟选项可能导致任务执行顺序混乱或性能问题。例如，将用户交互必须立即响应的任务设置为低优先级。
5. **在 `BackForwardCache` 生效期间进行不正确的状态假设**:  开发者可能会错误地认为从缓存恢复的页面状态与离开时完全一致，而忽略了在缓存期间可能发生的 IPC 消息或状态变化。

希望这个更全面的归纳能够帮助您理解 `FrameSchedulerImpl` 的功能。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
: "Subframe");
  dict.Add("is_visible_area_large", is_visible_area_large_);
  dict.Add("had_user_activation", had_user_activation_);
  dict.Add("disable_background_timer_throttling",
           !RuntimeEnabledFeatures::TimerThrottlingForBackgroundTabsEnabled());

  dict.Add("frame_task_queue_controller", frame_task_queue_controller_);
}

void FrameSchedulerImpl::WriteIntoTrace(
    perfetto::TracedProto<
        perfetto::protos::pbzero::RendererMainThreadTaskExecution> proto)
    const {
  proto->set_frame_visible(frame_visible_);
  proto->set_page_visible(parent_page_scheduler_->IsPageVisible());
  proto->set_frame_type(
      frame_type_ == FrameScheduler::FrameType::kMainFrame
          ? RendererMainThreadTaskExecution::FRAME_TYPE_MAIN_FRAME
      : IsCrossOriginToNearestMainFrame()
          ? RendererMainThreadTaskExecution::FRAME_TYPE_CROSS_ORIGIN_SUBFRAME
          : RendererMainThreadTaskExecution::FRAME_TYPE_SAME_ORIGIN_SUBFRAME);
  proto->set_is_ad_frame(is_ad_frame_);
}

bool FrameSchedulerImpl::IsPageVisible() const {
  return parent_page_scheduler_ ? parent_page_scheduler_->IsPageVisible()
                                : true;
}

void FrameSchedulerImpl::SetPaused(bool frame_paused) {
  DCHECK(parent_page_scheduler_);
  if (frame_paused_ == frame_paused)
    return;

  frame_paused_ = frame_paused;
  UpdatePolicy();
}

void FrameSchedulerImpl::SetShouldReportPostedTasksWhenDisabled(
    bool should_report) {
  // Forward this to all the task queues associated with this frame.
  for (const auto& task_queue_and_voter :
       frame_task_queue_controller_->GetAllTaskQueuesAndVoters()) {
    auto* task_queue = task_queue_and_voter.first;
    if (task_queue->CanBeFrozen()) {
      task_queue->SetShouldReportPostedTasksWhenDisabled(should_report);
    }
  }
}

void FrameSchedulerImpl::SetPageFrozenForTracing(bool frozen) {
  page_frozen_for_tracing_ = frozen;
}


void FrameSchedulerImpl::UpdatePolicy() {
  base::LazyNow lazy_now(main_thread_scheduler_->GetTickClock());

  ThrottlingType previous_throttling_type = throttling_type_;
  throttling_type_ = ComputeThrottlingType();

  if (throttling_type_ == ThrottlingType::kNone) {
    throttled_task_queue_handles_.clear();
  }

  for (const auto& task_queue_and_voter :
       frame_task_queue_controller_->GetAllTaskQueuesAndVoters()) {
    auto* task_queue = task_queue_and_voter.first;
    UpdateQueuePolicy(task_queue, task_queue_and_voter.second);

    if (!task_queue->CanBeThrottled()) {
      continue;
    }

    auto* new_wake_up_budget_pool = parent_page_scheduler_->GetWakeUpBudgetPool(
        task_queue, frame_origin_type_, throttling_type_);
    if (task_queue->GetWakeUpBudgetPool() != new_wake_up_budget_pool) {
      parent_page_scheduler_->RemoveQueueFromWakeUpBudgetPool(task_queue,
                                                              &lazy_now);
      parent_page_scheduler_->AddQueueToWakeUpBudgetPool(
          task_queue, new_wake_up_budget_pool, &lazy_now);
    }

    if (throttling_type_ != ThrottlingType::kNone &&
        previous_throttling_type == ThrottlingType::kNone) {
      MainThreadTaskQueue::ThrottleHandle handle =
          task_queue_and_voter.first->Throttle();
      throttled_task_queue_handles_.push_back(std::move(handle));
    }
  }

  NotifyLifecycleObservers();
}

void FrameSchedulerImpl::UpdateQueuePolicy(
    MainThreadTaskQueue* queue,
    TaskQueue::QueueEnabledVoter* voter) {
  DCHECK(queue);
  UpdatePriority(queue);

  DCHECK(voter);
  DCHECK(parent_page_scheduler_);
  bool queue_disabled = false;
  queue_disabled |= frame_paused_ && queue->CanBePaused();
  queue_disabled |= preempted_for_cooperative_scheduling_;
  // Per-frame freezable task queues will be frozen after 5 mins in background
  // on Android, and if the browser freezes the page in the background. They
  // will be resumed when the page is visible.
  bool queue_frozen =
      parent_page_scheduler_->IsFrozen() && queue->CanBeFrozen();
  queue_disabled |= queue_frozen;
  // Per-frame freezable queues of tasks which are specified as getting frozen
  // immediately when their frame becomes invisible get frozen. They will be
  // resumed when the frame becomes visible again.
  queue_disabled |= !frame_visible_ && !queue->CanRunInBackground();
  if (queue_disabled) {
    TRACE_EVENT_INSTANT("renderer.scheduler",
                        "FrameSchedulerImpl::UpdateQueuePolicy_QueueDisabled");
  } else {
    TRACE_EVENT_INSTANT("renderer.scheduler",
                        "FrameSchedulerImpl::UpdateQueuePolicy_QueueEnabled");
  }
  voter->SetVoteToEnable(!queue_disabled);
}

SchedulingLifecycleState FrameSchedulerImpl::CalculateLifecycleState(
    ObserverType type) const {
  // Detached frames are not throttled.
  if (!parent_page_scheduler_)
    return SchedulingLifecycleState::kNotThrottled;
  if (parent_page_scheduler_->IsFrozen()) {
    DCHECK(!parent_page_scheduler_->IsPageVisible());
    return SchedulingLifecycleState::kStopped;
  }
  if (subresource_loading_paused_ && type == ObserverType::kLoader)
    return SchedulingLifecycleState::kStopped;
  if (type == ObserverType::kLoader &&
      parent_page_scheduler_->OptedOutFromAggressiveThrottling()) {
    return SchedulingLifecycleState::kNotThrottled;
  }
  // Note: The scheduling lifecycle state ignores wake up rate throttling.
  if (parent_page_scheduler_->IsCPUTimeThrottled())
    return SchedulingLifecycleState::kThrottled;
  if (!parent_page_scheduler_->IsPageVisible())
    return SchedulingLifecycleState::kHidden;
  return SchedulingLifecycleState::kNotThrottled;
}

void FrameSchedulerImpl::OnFirstContentfulPaintInMainFrame() {
  waiting_for_contentful_paint_ = false;
  DCHECK_EQ(GetFrameType(), FrameScheduler::FrameType::kMainFrame);
  main_thread_scheduler_->OnMainFramePaint();
}

void FrameSchedulerImpl::OnMainFrameInteractive() {
  if (delegate_) {
    return delegate_->MainFrameInteractive();
  }
}

void FrameSchedulerImpl::OnFirstMeaningfulPaint(base::TimeTicks timestamp) {
  waiting_for_meaningful_paint_ = false;
  first_meaningful_paint_timestamp_ = timestamp;

  if (GetFrameType() != FrameScheduler::FrameType::kMainFrame ||
      is_in_embedded_frame_tree_) {
    return;
  }

  main_thread_scheduler_->OnMainFramePaint();
  if (delegate_) {
    return delegate_->MainFrameFirstMeaningfulPaint();
  }
}

void FrameSchedulerImpl::OnDispatchLoadEvent() {
  is_load_event_dispatched_ = true;
}

bool FrameSchedulerImpl::IsWaitingForContentfulPaint() const {
  return waiting_for_contentful_paint_;
}

bool FrameSchedulerImpl::IsWaitingForMeaningfulPaint() const {
  return waiting_for_meaningful_paint_;
}

bool FrameSchedulerImpl::IsLoading() const {
  if (waiting_for_meaningful_paint_) {
    return true;
  }

  if (is_load_event_dispatched_) {
    return false;
  }

  return base::TimeTicks::Now() - first_meaningful_paint_timestamp_ <=
         GetLoadingPhaseBufferTimeAfterFirstMeaningfulPaint();
}

bool FrameSchedulerImpl::IsOrdinary() const {
  if (!parent_page_scheduler_)
    return true;
  return parent_page_scheduler_->IsOrdinary();
}

ThrottlingType FrameSchedulerImpl::ComputeThrottlingType() {
  DCHECK(parent_page_scheduler_);

  const bool page_can_be_throttled_intensively =
      !parent_page_scheduler_->IsAudioPlaying() &&
      !parent_page_scheduler_->IsPageVisible();

  const bool frame_can_be_throttled_background =
      !AreFrameAndPageVisible() && !parent_page_scheduler_->IsAudioPlaying() &&
      !(parent_page_scheduler_->IsPageVisible() &&
        !IsCrossOriginToNearestMainFrame()) &&
      !(base::FeatureList::IsEnabled(features::kNoThrottlingVisibleAgent) &&
        GetAgentGroupSchedulerImpl().IsAgentVisible(agent_cluster_id_));

  const bool frame_can_be_throttled_foreground =
      IsCrossOriginToNearestMainFrame() && !IsImportant() &&
      base::FeatureList::IsEnabled(features::kThrottleUnimportantFrameTimers);

  if (RuntimeEnabledFeatures::TimerThrottlingForBackgroundTabsEnabled()) {
    if (frame_can_be_throttled_background) {
      if (page_can_be_throttled_intensively) {
        return ThrottlingType::kBackgroundIntensive;
      }
      return ThrottlingType::kBackground;
    }
  }

  if (frame_can_be_throttled_foreground) {
    return ThrottlingType::kForegroundUnimportant;
  }

  return ThrottlingType::kNone;
}

bool FrameSchedulerImpl::IsExemptFromBudgetBasedThrottling() const {
  return opted_out_from_aggressive_throttling();
}

TaskPriority FrameSchedulerImpl::ComputePriority(
    MainThreadTaskQueue* task_queue) const {
  DCHECK(task_queue);

  FrameScheduler* frame_scheduler = task_queue->GetFrameScheduler();

  // Checks the task queue is associated with this frame scheduler.
  DCHECK_EQ(frame_scheduler, this);

  // TODO(crbug.com/986569): Ordering here is relative to the experiments below.
  // Cleanup unused experiment logic so that this switch can be merged with the
  // prioritisation type decisions below.
  switch (task_queue->GetPrioritisationType()) {
    case MainThreadTaskQueue::QueueTraits::PrioritisationType::
        kInternalScriptContinuation:
      return TaskPriority::kVeryHighPriority;
    case MainThreadTaskQueue::QueueTraits::PrioritisationType::kBestEffort:
      return TaskPriority::kBestEffortPriority;
    case MainThreadTaskQueue::QueueTraits::PrioritisationType::
        kPostMessageForwarding:
      return TaskPriority::kVeryHighPriority;
    case MainThreadTaskQueue::QueueTraits::PrioritisationType::
        kInternalNavigationCancellation:
      return TaskPriority::kVeryHighPriority;
    default:
      break;
  }

  // TODO(shaseley): This should use lower priorities if the frame is
  // deprioritized. Change this once we refactor and add frame policy/priorities
  // and add a range of new priorities less than low.
  if (std::optional<WebSchedulingQueueType> queue_type =
          task_queue->GetWebSchedulingQueueType()) {
    bool is_continuation =
        *queue_type == WebSchedulingQueueType::kContinuationQueue;
    switch (*task_queue->GetWebSchedulingPriority()) {
      case WebSchedulingPriority::kUserBlockingPriority:
        return is_continuation ? TaskPriority::kHighPriorityContinuation
                               : TaskPriority::kHighPriority;
      case WebSchedulingPriority::kUserVisiblePriority:
        return is_continuation ? TaskPriority::kNormalPriorityContinuation
                               : TaskPriority::kNormalPriority;
      case WebSchedulingPriority::kBackgroundPriority:
        return is_continuation ? TaskPriority::kLowPriorityContinuation
                               : TaskPriority::kLowPriority;
    }
  }

  if (!parent_page_scheduler_) {
    // Frame might be detached during its shutdown. Return a default priority
    // in that case.
    return TaskPriority::kNormalPriority;
  }

  if (task_queue->GetPrioritisationType() ==
      MainThreadTaskQueue::QueueTraits::PrioritisationType::kLoadingControl) {
    return TaskPriority::kHighPriority;
  }

  if (task_queue->GetPrioritisationType() ==
      MainThreadTaskQueue::QueueTraits::PrioritisationType::kFindInPage) {
    return main_thread_scheduler_->find_in_page_priority();
  }

  if (task_queue->GetPrioritisationType() ==
      MainThreadTaskQueue::QueueTraits::PrioritisationType::
          kHighPriorityLocalFrame) {
    return TaskPriority::kHighestPriority;
  }

  if (task_queue->GetPrioritisationType() ==
      MainThreadTaskQueue::QueueTraits::PrioritisationType::kInput) {
    return TaskPriority::kHighestPriority;
  }

  if (task_queue->GetPrioritisationType() ==
      MainThreadTaskQueue::QueueTraits::PrioritisationType::
          kExperimentalDatabase) {
    // TODO(shaseley): This decision should probably be based on Agent
    // visibility. Consider changing this before shipping anything.
    return parent_page_scheduler_->IsPageVisible()
               ? TaskPriority::kHighPriority
               : TaskPriority::kNormalPriority;
  }

  if (task_queue->GetPrioritisationType() ==
      MainThreadTaskQueue::QueueTraits::PrioritisationType::kRenderBlocking) {
    return parent_page_scheduler_->IsPageVisible()
               ? TaskPriority::kExtremelyHighPriority
               : TaskPriority::kNormalPriority;
  }

  if (task_queue->GetPrioritisationType() ==
      MainThreadTaskQueue::QueueTraits::PrioritisationType::kAsyncScript) {
    return low_priority_async_script_task_priority_;
  }

  return TaskPriority::kNormalPriority;
}

std::unique_ptr<blink::mojom::blink::PauseSubresourceLoadingHandle>
FrameSchedulerImpl::GetPauseSubresourceLoadingHandle() {
  return std::make_unique<PauseSubresourceLoadingHandleImpl>(
      weak_factory_.GetWeakPtr());
}

void FrameSchedulerImpl::AddPauseSubresourceLoadingHandle() {
  ++subresource_loading_pause_count_;
  if (subresource_loading_pause_count_ != 1) {
    DCHECK(subresource_loading_paused_);
    return;
  }

  DCHECK(!subresource_loading_paused_);
  subresource_loading_paused_ = true;
  UpdatePolicy();
}

void FrameSchedulerImpl::RemovePauseSubresourceLoadingHandle() {
  DCHECK_LT(0u, subresource_loading_pause_count_);
  --subresource_loading_pause_count_;
  DCHECK(subresource_loading_paused_);
  if (subresource_loading_pause_count_ == 0) {
    subresource_loading_paused_ = false;
    UpdatePolicy();
  }
}

ukm::UkmRecorder* FrameSchedulerImpl::GetUkmRecorder() {
  if (!delegate_)
    return nullptr;
  return delegate_->GetUkmRecorder();
}

ukm::SourceId FrameSchedulerImpl::GetUkmSourceId() {
  if (!delegate_)
    return ukm::kInvalidSourceId;
  return delegate_->GetUkmSourceId();
}

void FrameSchedulerImpl::OnTaskQueueCreated(
    MainThreadTaskQueue* task_queue,
    base::sequence_manager::TaskQueue::QueueEnabledVoter* voter) {
  DCHECK(parent_page_scheduler_);

  UpdateQueuePolicy(task_queue, voter);

  if (task_queue->CanBeThrottled()) {
    base::LazyNow lazy_now(main_thread_scheduler_->GetTickClock());

    CPUTimeBudgetPool* cpu_time_budget_pool =
        parent_page_scheduler_->background_cpu_time_budget_pool();
    if (cpu_time_budget_pool) {
      task_queue->AddToBudgetPool(lazy_now.Now(), cpu_time_budget_pool);
    }

    if (throttling_type_ != ThrottlingType::kNone) {
      parent_page_scheduler_->AddQueueToWakeUpBudgetPool(
          task_queue,
          parent_page_scheduler_->GetWakeUpBudgetPool(
              task_queue, frame_origin_type_, throttling_type_),
          &lazy_now);

      MainThreadTaskQueue::ThrottleHandle handle = task_queue->Throttle();
      throttled_task_queue_handles_.push_back(std::move(handle));
    }
  }
}

void FrameSchedulerImpl::SetOnIPCTaskPostedWhileInBackForwardCacheHandler() {
  DCHECK(parent_page_scheduler_->IsInBackForwardCache());
  for (const auto& task_queue_and_voter :
       frame_task_queue_controller_->GetAllTaskQueuesAndVoters()) {
    task_queue_and_voter.first->SetOnIPCTaskPosted(base::BindRepeating(
        [](scoped_refptr<base::SingleThreadTaskRunner> task_runner,
           base::WeakPtr<FrameSchedulerImpl> frame_scheduler,
           const base::sequence_manager::Task& task) {
          // Only log IPC tasks. IPC tasks are only logged currently as IPC
          // hash can be mapped back to a function name, and IPC tasks may
          // potentially post sensitive information.
          if (!task.ipc_hash && !task.ipc_interface_name) {
            return;
          }
          base::ScopedDeferTaskPosting::PostOrDefer(
              task_runner, FROM_HERE,
              base::BindOnce(
                  &FrameSchedulerImpl::OnIPCTaskPostedWhileInBackForwardCache,
                  frame_scheduler, task.ipc_hash, task.ipc_interface_name),
              base::Seconds(1));
        },
        main_thread_scheduler_->BackForwardCacheIpcTrackingTaskRunner(),
        GetInvalidatingOnBFCacheRestoreWeakPtr()));
  }
}

void FrameSchedulerImpl::DetachOnIPCTaskPostedWhileInBackForwardCacheHandler() {
  for (const auto& task_queue_and_voter :
       frame_task_queue_controller_->GetAllTaskQueuesAndVoters()) {
    task_queue_and_voter.first->DetachOnIPCTaskPostedWhileInBackForwardCache();
  }

  invalidating_on_bfcache_restore_weak_factory_.InvalidateWeakPtrs();
}

void FrameSchedulerImpl::OnIPCTaskPostedWhileInBackForwardCache(
    uint32_t ipc_hash,
    const char* ipc_interface_name) {
  // IPC tasks may have an IPC interface name in addition to, or instead of an
  // IPC hash. IPC hash is known from the mojo Accept method. When IPC hash is
  // 0, then the IPC hash must be calculated from the IPC interface name
  // instead.
  if (!ipc_hash) {
    // base::HashMetricName produces a uint64; however, the MD5 hash calculation
    // for an IPC interface name is always calculated as uint32; the IPC hash on
    // a task is also a uint32. The calculation here is meant to mimic the
    // calculation used in base::MD5Hash32Constexpr.
    ipc_hash = base::TaskAnnotator::ScopedSetIpcHash::MD5HashMetricName(
        ipc_interface_name);
  }

  DCHECK(parent_page_scheduler_->IsInBackForwardCache());
  base::UmaHistogramSparse(
      "BackForwardCache.Experimental.UnexpectedIPCMessagePostedToCachedFrame."
      "MethodHash",
      static_cast<int32_t>(ipc_hash));

  base::TimeDelta duration =
      main_thread_scheduler_->NowTicks() -
      parent_page_scheduler_->GetStoredInBackForwardCacheTimestamp();
  base::UmaHistogramCustomTimes(
      "BackForwardCache.Experimental.UnexpectedIPCMessagePostedToCachedFrame."
      "TimeUntilIPCReceived",
      duration, base::TimeDelta(), base::Minutes(5), 100);
}

WTF::HashSet<SchedulingPolicy::Feature>
FrameSchedulerImpl::GetActiveFeaturesTrackedForBackForwardCacheMetrics() {
  return back_forward_cache_disabling_feature_tracker_
      .GetActiveFeaturesTrackedForBackForwardCacheMetrics();
}

base::WeakPtr<FrameOrWorkerScheduler>
FrameSchedulerImpl::GetFrameOrWorkerSchedulerWeakPtr() {
  // We reset feature sets upon frame navigation, so having a document-bound
  // weak pointer ensures that the feature handle associated with previous
  // document can't influence the new one.
  return document_bound_weak_factory_.GetWeakPtr();
}

std::unique_ptr<WebSchedulingTaskQueue>
FrameSchedulerImpl::CreateWebSchedulingTaskQueue(
    WebSchedulingQueueType queue_type,
    WebSchedulingPriority priority) {
  bool can_be_deferred_for_rendering = ComputeCanBeDeferredForRendering(
      /*is_deferrable_for_touchstart=*/true,
      TaskType::kWebSchedulingPostedTask);

  // The QueueTraits for scheduler.postTask() are similar to those of
  // setTimeout() (deferrable queue traits + throttling for delayed tasks), with
  // the following differences:
  //  1. All delayed tasks are intensively throttled (no nesting-level exception
  //     or policy/flag opt-out)
  //  2. There is no separate PrioritisationType (prioritization is based on the
  //     WebSchedulingPriority, which is only set for these task queues)
  scoped_refptr<MainThreadTaskQueue> immediate_task_queue =
      frame_task_queue_controller_->NewWebSchedulingTaskQueue(
          DeferrableTaskQueueTraits().SetCanBeDeferredForRendering(
              can_be_deferred_for_rendering),
          queue_type, priority);
  // Continuation task queues can only be used for immediate tasks since there
  // the yield API doesn't support delayed continuations.
  if (queue_type == WebSchedulingQueueType::kContinuationQueue) {
    return std::make_unique<MainThreadWebSchedulingTaskQueueImpl>(
        immediate_task_queue->AsWeakPtr(), nullptr);
  }
  scoped_refptr<MainThreadTaskQueue> delayed_task_queue =
      frame_task_queue_controller_->NewWebSchedulingTaskQueue(
          DeferrableTaskQueueTraits()
              .SetCanBeThrottled(true)
              .SetCanBeIntensivelyThrottled(true)
              .SetCanBeDeferredForRendering(can_be_deferred_for_rendering),
          queue_type, priority);
  return std::make_unique<MainThreadWebSchedulingTaskQueueImpl>(
      immediate_task_queue->AsWeakPtr(), delayed_task_queue->AsWeakPtr());
}

void FrameSchedulerImpl::OnWebSchedulingTaskQueuePriorityChanged(
    MainThreadTaskQueue* queue) {
  UpdateQueuePolicy(queue,
                    frame_task_queue_controller_->GetQueueEnabledVoter(queue));
  main_thread_scheduler_->OnWebSchedulingTaskQueuePriorityChanged(queue);
}

void FrameSchedulerImpl::OnWebSchedulingTaskQueueDestroyed(
    MainThreadTaskQueue* queue) {
  if (queue->CanBeThrottled()) {
    RemoveThrottleableQueueFromBudgetPools(queue);
  }

  // Don't run web scheduling tasks after detach.
  queue->ShutdownTaskQueue();

  // After this is called, the queue will be destroyed. Do not attempt
  // to use it further.
  frame_task_queue_controller_->RemoveWebSchedulingTaskQueue(queue);
}

const base::UnguessableToken& FrameSchedulerImpl::GetAgentClusterId() const {
  if (!delegate_)
    return base::UnguessableToken::Null();
  return delegate_->GetAgentClusterId();
}

base::TimeDelta FrameSchedulerImpl::UnreportedTaskTime() const {
  return unreported_task_time_;
}

bool FrameSchedulerImpl::ComputeCanBeDeferredForRendering(
    bool is_deferrable_for_touchstart,
    TaskType task_type) const {
  if (!base::FeatureList::IsEnabled(features::kDeferRendererTasksAfterInput)) {
    return false;
  }
  std::optional<features::TaskDeferralPolicy> policy =
      main_thread_scheduler_->scheduling_settings()
          .discrete_input_task_deferral_policy;
  CHECK(policy);
  switch (*policy) {
    case features::TaskDeferralPolicy::kMinimalTypes:
      return task_type == TaskType::kDOMManipulation ||
             task_type == TaskType::kIdleTask ||
             task_type == TaskType::kWebSchedulingPostedTask;
    case features::TaskDeferralPolicy::kNonUserBlockingDeferrableTypes:
    case features::TaskDeferralPolicy::kAllDeferrableTypes:
      // kPosteMessaged is used for scheduling, so unlike touchstart deferral,
      // consider this a deferrable type.
      return is_deferrable_for_touchstart ||
             task_type == TaskType::kPostedMessage;
    case features::TaskDeferralPolicy::kNonUserBlockingTypes:
    case features::TaskDeferralPolicy::kAllTypes:
      return true;
  }
}

// static
MainThreadTaskQueue::QueueTraits
FrameSchedulerImpl::ThrottleableTaskQueueTraits() {
  return QueueTraits()
      .SetCanBeThrottled(true)
      .SetCanBeFrozen(true)
      .SetCanBeDeferred(true)
      .SetCanBePaused(true)
      .SetCanRunWhenVirtualTimePaused(false)
      .SetCanBePausedForAndroidWebview(true);
}

// static
MainThreadTaskQueue::QueueTraits
FrameSchedulerImpl::DeferrableTaskQueueTraits() {
  return QueueTraits()
      .SetCanBeDeferred(true)
      .SetCanBeFrozen(true)
      .SetCanBePaused(true)
      .SetCanRunWhenVirtualTimePaused(false)
      .SetCanBePausedForAndroidWebview(true);
}

// static
MainThreadTaskQueue::QueueTraits FrameSchedulerImpl::PausableTaskQueueTraits() {
  return QueueTraits()
      .SetCanBeFrozen(true)
      .SetCanBePaused(true)
      .SetCanRunWhenVirtualTimePaused(false)
      .SetCanBePausedForAndroidWebview(true);
}

// static
MainThreadTaskQueue::QueueTraits
FrameSchedulerImpl::FreezableTaskQueueTraits() {
  // Should not use VirtualTime because using VirtualTime would make the task
  // execution non-deterministic and produce timeouts failures.
  return QueueTraits().SetCanBeFrozen(true);
}

// static
MainThreadTaskQueue::QueueTraits
FrameSchedulerImpl::UnpausableTaskQueueTraits() {
  return QueueTraits().SetCanRunWhenVirtualTimePaused(false);
}

MainThreadTaskQueue::QueueTraits
FrameSchedulerImpl::ForegroundOnlyTaskQueueTraits() {
  return ThrottleableTaskQueueTraits()
      .SetCanRunInBackground(false)
      .SetCanRunWhenVirtualTimePaused(false);
}

MainThreadTaskQueue::QueueTraits
FrameSchedulerImpl::CanRunWhenVirtualTimePausedTaskQueueTraits() {
  return QueueTraits().SetCanRunWhenVirtualTimePaused(true);
}

void FrameSchedulerImpl::SetPreemptedForCooperativeScheduling(
    Preempted preempted) {
  DCHECK_NE(preempted.value(), preempted_for_cooperative_scheduling_);
  preempted_for_cooperative_scheduling_ = preempted.value();
  UpdatePolicy();
}

MainThreadTaskQueue::QueueTraits FrameSchedulerImpl::LoadingTaskQueueTraits() {
  return QueueTraits()
      .SetCanBePaused(true)
      .SetCanBeFrozen(true)
      .SetCanBeDeferred(true)
      .SetPrioritisationType(QueueTraits::PrioritisationType::kLoading);
}

MainThreadTaskQueue::QueueTraits
FrameSchedulerImpl::UnfreezableLoadingTaskQueueTraits() {
  return LoadingTaskQueueTraits().SetCanBeFrozen(false);
}

MainThreadTaskQueue::QueueTraits
FrameSchedulerImpl::LoadingControlTaskQueueTraits() {
  return QueueTraits()
      .SetCanBePaused(true)
      .SetCanBeFrozen(true)
      .SetCanBeDeferred(true)
      .SetPrioritisationType(QueueTraits::PrioritisationType::kLoadingControl);
}

MainThreadTaskQueue::QueueTraits
FrameSchedulerImpl::FindInPageTaskQueueTraits() {
  return PausableTaskQueueTraits().SetPrioritisationType(
      QueueTraits::PrioritisationType::kFindInPage);
}

MainThreadTaskQueue::QueueTraits
FrameSchedulerImpl::InputBlockingQueueTraits() {
  return QueueTraits().SetPrioritisationType(
      QueueTraits::PrioritisationType::kInput);
}
}  // namespace scheduler
}  // namespace blink
```