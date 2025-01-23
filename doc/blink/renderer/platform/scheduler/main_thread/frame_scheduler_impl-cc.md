Response: Let's break down the request and the provided code to generate the response.

**1. Understanding the Core Request:**

The request is to analyze the `FrameSchedulerImpl.cc` file from Chromium's Blink rendering engine and describe its functionality. Specifically, it asks for:

* **Core Functionality:** What does this class *do*?
* **Relationship to Web Technologies (JS, HTML, CSS):** How does it influence or interact with these?
* **Logical Reasoning (Input/Output):**  Are there clear input scenarios that lead to predictable outputs within this class?
* **Common Usage Errors:** What mistakes could a developer make (even within the Blink codebase itself) related to this class?

**2. Initial Code Scan and Keyword Spotting:**

I'll quickly scan the code for key terms and patterns:

* **`FrameSchedulerImpl`:** The central class, clearly responsible for scheduling tasks related to a frame.
* **`TaskQueue`:**  This appears frequently, suggesting the class manages queues of tasks.
* **`Priority`:**  The code mentions and computes task priorities.
* **`Visibility` (Page, Frame):**  Visibility states seem important for scheduling.
* **`Throttling`:**  The code deals with throttling tasks under certain conditions.
* **`UserActivation`:** User interaction appears to influence scheduling.
* **`JavaScriptTimer`:**  Specific handling of JavaScript timers.
* **`Loading` (Networking):**  Integration with network loading.
* **`Paint` (Contentful, Meaningful):**  Interaction with rendering milestones.
* **`WebSchedulingTaskQueue`:**  Support for a more general web scheduling API.
* **`BackForwardCache`:**  Interaction with the back/forward cache mechanism.
* **`PolicyUpdater`:**  A separate component for updating scheduling policies.
* **`Delegate`:**  The class interacts with other components through a delegate.

**3. Deduction and Grouping of Functionalities:**

Based on the keywords, I can start grouping functionalities:

* **Task Management:** Creating, prioritizing, and executing tasks. This is core.
* **Visibility-Based Scheduling:**  Adjusting scheduling based on whether the frame and page are visible.
* **Throttling:**  Reducing resource usage for less important frames or background tabs.
* **JavaScript Timer Handling:** Special attention to timer execution.
* **Loading Integration:**  Managing tasks related to fetching resources.
* **Rendering Synchronization:** Aligning tasks with paint events.
* **Web Scheduling API Support:** Providing an interface for web developers to schedule tasks.
* **Back/Forward Cache Considerations:**  Ensuring proper behavior when pages are cached.

**4. Connecting to Web Technologies:**

Now, I link the functionalities to JS, HTML, and CSS:

* **JavaScript:**  The class handles JavaScript timers and the more general `scheduler.postTask()`. It impacts how quickly JS code executes, especially during loading, in the background, or for less important frames.
* **HTML:** Visibility changes (due to HTML structure or user interaction) trigger scheduling adjustments. Loading resources (images, scripts, stylesheets referenced in HTML) is managed through this class.
* **CSS:** While less direct, CSS can influence visibility (e.g., `display: none`) and trigger repaints, which are scheduling events.

**5. Constructing Input/Output Examples:**

I need simple scenarios to illustrate logical reasoning:

* **Visibility:** A frame becomes visible; the scheduler should prioritize its tasks.
* **User Activation:** A user clicks something; tasks related to that frame should get a boost.
* **Throttling:** A background tab's timers should fire less frequently.

**6. Identifying Potential Usage Errors:**

Thinking about how developers (even within Blink) might misuse this class:

* **Incorrect Task Type:**  Assigning the wrong `TaskType` could lead to unexpected prioritization or throttling.
* **Forgetting Visibility:** Not considering visibility when scheduling could lead to wasted resources.
* **Over-reliance on High Priority:**  Using high priority unnecessarily could starve other important tasks.
* **Ignoring Back/Forward Cache:**  Not handling tasks correctly when a page is cached could cause issues when the user navigates back.

**7. Structuring the Output:**

Finally, I organize the information into the requested categories:

* **功能 (Functions):** List the core responsibilities clearly and concisely.
* **与 JavaScript, HTML, CSS 的关系 (Relationship with JS, HTML, CSS):** Provide concrete examples of how the scheduler interacts with these technologies.
* **逻辑推理 (Logical Reasoning):**  Present the input/output examples with clear assumptions and outcomes.
* **用户或者编程常见的使用错误 (Common Usage Errors):**  List potential pitfalls with brief explanations.

This structured approach ensures that all aspects of the request are addressed comprehensively and that the explanation is clear and easy to understand.
好的，让我们来详细分析一下 `blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl.cc` 文件的功能。

**主要功能:**

`FrameSchedulerImpl` 类是 Blink 渲染引擎中负责**管理和调度单个渲染帧（Frame）内任务执行**的核心组件。 它的主要职责包括：

1. **任务队列管理:**
   - 为不同类型的任务维护多个优先级不同的任务队列 (例如，用于 JavaScript 执行、网络请求、DOM 操作等)。
   -  根据任务的类型和属性（如是否可被节流、是否可被暂停等）选择合适的任务队列。
   - 提供 API 用于向这些队列添加任务。

2. **任务优先级管理:**
   -  根据帧的状态（例如，是否可见、是否有用户交互、是否正在加载等）动态计算任务队列的优先级。
   -  允许外部因素（例如，Web 调度 API）影响任务优先级。

3. **任务节流 (Throttling):**
   -  根据帧的状态（例如，是否在后台、是否是不重要的跨域 iframe）对某些类型的任务进行节流，以减少资源消耗并提高性能。
   -  提供机制让某些任务或功能可以“选择退出”激进的节流策略。

4. **帧生命周期管理集成:**
   -  与页面的可见性状态、冻结状态等生命周期事件集成，调整任务调度策略。
   -  响应帧的显示和隐藏，暂停或恢复某些任务队列的执行。

5. **与 Web 技术交互:**
   -  处理 JavaScript 定时器 (setTimeout, setInterval) 的调度。
   -  管理与网络请求相关的任务。
   -  影响 DOM 操作任务的执行时机。
   -  支持 `scheduler.postTask()` 等 Web 调度 API。

6. **Back/Forward Cache (BFCache) 集成:**
   -  跟踪阻止页面进入 BFCache 的功能使用情况。
   -  在页面从 BFCache 恢复时，处理可能需要延迟或取消的任务。

7. **性能监控和追踪:**
   -  记录任务执行时间，用于性能分析。
   -  提供 tracing 事件，方便开发者进行性能调试。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

`FrameSchedulerImpl` 的核心功能直接影响着 JavaScript, HTML, 和 CSS 的执行和渲染：

* **JavaScript:**
    - **JavaScript 定时器:** `FrameSchedulerImpl` 管理 `setTimeout` 和 `setInterval` 的执行。例如，当一个隐藏的标签页中的 iframe 调用了 `setTimeout`，`FrameSchedulerImpl` 可能会对该定时器进行节流，使其延迟触发，从而节省 CPU 资源。
    - **`scheduler.postTask()`:** 该文件实现了对 Web 标准 `scheduler.postTask()` API 的支持，允许 JavaScript 代码更精细地控制任务的调度优先级和延迟。 例如，一个交互动画可以使用 `scheduler.postTask({priority: 'user-blocking'}, ...)` 来确保动画的流畅性。
    - **异步脚本执行:**  `FrameSchedulerImpl` 管理异步脚本的执行优先级。例如，使用 `<script async>` 加载的脚本，在页面加载的早期阶段，可能会被赋予更高的优先级以加速页面渲染。
    - **微任务 (Microtask):** 虽然没有直接提到，但微任务的执行通常紧跟在每个宏任务之后，`FrameSchedulerImpl` 间接地影响着微任务的执行时机。

* **HTML:**
    - **页面可见性:** 当 HTML 文档所属的标签页被切换到后台时，`FrameSchedulerImpl` 会收到通知，并可能降低该帧内任务的优先级或进行节流。这影响了后台标签页中 JavaScript 定时器的触发频率和资源消耗。
    - **用户交互:**  用户在 HTML 页面上的点击、滚动等操作会触发用户激活状态的改变，`FrameSchedulerImpl` 会根据此调整任务优先级，确保与用户交互相关的任务能够及时响应。
    - **资源加载:** HTML 中引用的图片、CSS 文件、JavaScript 文件等的加载由网络模块负责，但与加载完成后的处理相关的任务（例如，JavaScript 中处理图片加载完成的事件）由 `FrameSchedulerImpl` 进行调度。

* **CSS:**
    - **渲染阻塞:**  虽然 `FrameSchedulerImpl` 不直接解析 CSS，但 CSS 的加载和解析会影响渲染过程。与渲染相关的任务，例如布局计算、绘制等，由 `FrameSchedulerImpl` 进行调度。
    - **动画:**  CSS 动画和 JavaScript 驱动的动画都依赖于任务调度。`FrameSchedulerImpl` 的策略会影响动画的流畅程度。

**逻辑推理 (假设输入与输出):**

假设一个场景：一个包含 JavaScript 代码的 iframe 嵌入在一个主页面中。

**假设输入:**

1. **帧状态:**
   - iframe 当前是可见的。
   - 用户刚刚与主页面进行了交互（iframe 继承了部分用户激活状态）。
   - iframe 正在加载一些图片资源。

2. **JavaScript 代码:**
   - iframe 中有一个使用 `setTimeout` 设置的定时器，延迟 100ms 执行一个 DOM 操作。
   - iframe 中有代码监听图片加载完成事件。

**逻辑推理:**

* **定时器优先级:** 由于 iframe 可见且具有部分用户激活状态，`FrameSchedulerImpl` 会给予该定时器任务较高的优先级，使其能够相对及时地执行。
* **DOM 操作:** 当定时器触发时，执行的 DOM 操作任务也会被赋予较高的优先级，以便尽快更新页面显示。
* **图片加载事件:** 当图片加载完成后，触发的 JavaScript 事件处理函数会被添加到任务队列中，由于 iframe 正在加载资源，这个任务的优先级也会被适当提高。

**可能的输出:**

* 定时器会在接近 100ms 的时间内触发，执行 DOM 操作。
* 图片加载完成后，相应的事件处理函数会相对较快地执行，更新页面内容。

**假设输入改变:**

如果 iframe 变得不可见（例如，用户切换到其他标签页）：

* **定时器节流:** `FrameSchedulerImpl` 可能会对 `setTimeout` 设置的定时器进行节流，使其触发时间间隔变长，以减少资源消耗。
* **任务优先级降低:**  与 iframe 相关的任务的优先级会被降低。

**用户或编程常见的使用错误举例:**

1. **不恰当的任务类型选择:**  开发者在 Blink 内部提交任务时，如果选择了不恰当的 `TaskType`，可能会导致任务被错误地优先级处理或节流。例如，将一个对用户交互至关重要的任务标记为 `kIdleTask`，可能导致响应延迟。

2. **忽略帧的可见性状态:**  在开发涉及帧间通信的功能时，如果开发者没有考虑到目标帧的可见性状态，可能会导致在目标帧不可见时仍然进行大量的计算或 DOM 操作，造成资源浪费。 `FrameSchedulerImpl` 的节流机制在一定程度上可以缓解这个问题，但更好的做法是在应用层进行优化。

3. **过度依赖高优先级任务:**  如果一个帧内有大量的任务都被赋予过高的优先级，可能会导致其他低优先级的任务被饿死，无法得到执行。这可能导致页面功能异常。

4. **在 BFCache 中执行不安全的操作:**  开发者如果没有考虑到页面可能被缓存到 BFCache，并在页面恢复时执行某些不应该执行的操作（例如，发送网络请求），可能会导致意外的行为。`FrameSchedulerImpl` 提供了机制来跟踪和处理这些情况，但开发者也需要注意避免这类错误。例如，应该使用 `Document::WasRestored()` 来检查页面是否从 BFCache 恢复，并据此调整行为。

**总结:**

`FrameSchedulerImpl` 是 Blink 渲染引擎中一个至关重要的组件，它负责精细地管理和调度帧内的任务执行，直接影响着网页的性能和用户体验。理解其工作原理对于开发高性能的 Web 应用以及进行 Blink 引擎的开发和调试都至关重要。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl.h"

#include <memory>

#include "base/feature_list.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_functions.h"
#include "base/task/common/lazy_now.h"
#include "base/task/common/scoped_defer_task_posting.h"
#include "base/task/common/task_annotator.h"
#include "base/task/single_thread_task_runner.h"
#include "base/threading/platform_thread.h"
#include "base/time/time.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/scheduler/web_scheduler_tracked_feature.h"
#include "third_party/blink/public/platform/web_string.h"
#include "third_party/blink/renderer/platform/back_forward_cache_utils.h"
#include "third_party/blink/renderer/platform/runtime_enabled_features.h"
#include "third_party/blink/renderer/platform/scheduler/common/features.h"
#include "third_party/blink/renderer/platform/scheduler/common/task_priority.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/budget_pool.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/type.h"
#include "third_party/blink/renderer/platform/scheduler/common/tracing_helper.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/find_in_page_budget_pool_controller.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_task_queue.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_web_scheduling_task_queue_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/page_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/page_visibility_state.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/policy_updater.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/task_type_names.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_queue_type.h"
#include "third_party/blink/renderer/platform/scheduler/worker/worker_scheduler_proxy.h"
#include "third_party/perfetto/include/perfetto/tracing/traced_value.h"

namespace blink {

namespace scheduler {

using base::sequence_manager::TaskQueue;
using QueueTraits = MainThreadTaskQueue::QueueTraits;
using perfetto::protos::pbzero::RendererMainThreadTaskExecution;

namespace {

// When enabled, the main thread's type is reduced from `kDisplayCritical` to
// `kDefault` when WebRTC is in use within the renderer. This is a simple
// workaround meant to be merged to higher channels while we're working on a
// more refined solution. See crbug.com/1513904.
BASE_FEATURE(kRendererMainIsDefaultThreadTypeForWebRTC,
             "RendererMainIsNormalThreadTypeForWebRTC",
             base::FEATURE_ENABLED_BY_DEFAULT);

const char* VisibilityStateToString(bool is_visible) {
  if (is_visible) {
    return "visible";
  } else {
    return "hidden";
  }
}

const char* IsVisibleAreaLargeStateToString(bool is_large) {
  if (is_large) {
    return "large";
  } else {
    return "small";
  }
}

const char* UserActivationStateToString(bool had_user_activation) {
  if (had_user_activation) {
    return "had user activation";
  } else {
    return "no user activation";
  }
}

const char* PausedStateToString(bool is_paused) {
  if (is_paused) {
    return "paused";
  } else {
    return "running";
  }
}

const char* FrozenStateToString(bool is_frozen) {
  if (is_frozen) {
    return "frozen";
  } else {
    return "running";
  }
}

// Used to update the priority of task_queue. Note that this function is
// used for queues associated with a frame.
void UpdatePriority(MainThreadTaskQueue* task_queue) {
  if (!task_queue)
    return;

  FrameSchedulerImpl* frame_scheduler = task_queue->GetFrameScheduler();
  DCHECK(frame_scheduler);
  task_queue->SetQueuePriority(frame_scheduler->ComputePriority(task_queue));
}

TaskPriority GetLowPriorityAsyncScriptTaskPriority() {
  switch (
      features::kLowPriorityAsyncScriptExecutionLowerTaskPriorityParam.Get()) {
    case features::AsyncScriptPrioritisationType::kHigh:
      return TaskPriority::kHighPriority;
    case features::AsyncScriptPrioritisationType::kLow:
      return TaskPriority::kLowPriority;
    case features::AsyncScriptPrioritisationType::kBestEffort:
      return TaskPriority::kBestEffortPriority;
  }
  NOTREACHED();
}

}  // namespace

FrameSchedulerImpl::PauseSubresourceLoadingHandleImpl::
    PauseSubresourceLoadingHandleImpl(
        base::WeakPtr<FrameSchedulerImpl> frame_scheduler)
    : frame_scheduler_(std::move(frame_scheduler)) {
  DCHECK(frame_scheduler_);
  frame_scheduler_->AddPauseSubresourceLoadingHandle();
}

FrameSchedulerImpl::PauseSubresourceLoadingHandleImpl::
    ~PauseSubresourceLoadingHandleImpl() {
  if (frame_scheduler_)
    frame_scheduler_->RemovePauseSubresourceLoadingHandle();
}

FrameSchedulerImpl::FrameSchedulerImpl(PageSchedulerImpl* parent_page_scheduler,
                                       FrameScheduler::Delegate* delegate,
                                       bool is_in_embedded_frame_tree,
                                       FrameScheduler::FrameType frame_type)
    : FrameSchedulerImpl(parent_page_scheduler->GetMainThreadScheduler(),
                         parent_page_scheduler,
                         delegate,
                         is_in_embedded_frame_tree,
                         frame_type) {}

FrameSchedulerImpl::FrameSchedulerImpl(
    MainThreadSchedulerImpl* main_thread_scheduler,
    PageSchedulerImpl* parent_page_scheduler,
    FrameScheduler::Delegate* delegate,
    bool is_in_embedded_frame_tree,
    FrameScheduler::FrameType frame_type)
    : frame_type_(frame_type),
      is_in_embedded_frame_tree_(is_in_embedded_frame_tree),
      main_thread_scheduler_(main_thread_scheduler),
      parent_page_scheduler_(parent_page_scheduler),
      delegate_(delegate),
      page_visibility_(
          parent_page_scheduler_ && parent_page_scheduler_->IsPageVisible()
              ? PageVisibilityState::kVisible
              : PageVisibilityState::kHidden,
          "FrameScheduler.PageVisibility",
          &tracing_controller_,
          PageVisibilityStateToString),
      frame_visible_(true,
                     "FrameScheduler.FrameVisible",
                     &tracing_controller_,
                     VisibilityStateToString),
      is_visible_area_large_(true,
                             "FrameScheduler.IsVisibleAreaLarge",
                             &tracing_controller_,
                             IsVisibleAreaLargeStateToString),
      had_user_activation_(false,
                           "FrameScheduler.HadUserActivation",
                           &tracing_controller_,
                           UserActivationStateToString),
      frame_paused_(false,
                    "FrameScheduler.FramePaused",
                    &tracing_controller_,
                    PausedStateToString),
      frame_origin_type_(frame_type == FrameType::kMainFrame
                             ? FrameOriginType::kMainFrame
                             : FrameOriginType::kSameOriginToMainFrame,
                         "FrameScheduler.Origin",
                         &tracing_controller_,
                         FrameOriginTypeToString),
      subresource_loading_paused_(false,
                                  "FrameScheduler.SubResourceLoadingPaused",
                                  &tracing_controller_,
                                  PausedStateToString),
      url_tracer_("FrameScheduler.URL"),
      throttling_type_(ThrottlingType::kNone,
                       "FrameScheduler.ThrottlingType",
                       &tracing_controller_,
                       ThrottlingTypeToString),
      preempted_for_cooperative_scheduling_(
          false,
          "FrameScheduler.PreemptedForCooperativeScheduling",
          &tracing_controller_,
          YesNoStateToString),
      aggressive_throttling_opt_out_count_(0),
      opted_out_from_aggressive_throttling_(
          false,
          "FrameScheduler.AggressiveThrottlingDisabled",
          &tracing_controller_,
          YesNoStateToString),
      subresource_loading_pause_count_(0u),
      back_forward_cache_disabling_feature_tracker_(&tracing_controller_,
                                                    main_thread_scheduler_),
      low_priority_async_script_task_priority_(
          GetLowPriorityAsyncScriptTaskPriority()),
      page_frozen_for_tracing_(
          parent_page_scheduler_ ? parent_page_scheduler_->IsFrozen() : true,
          "FrameScheduler.PageFrozen",
          &tracing_controller_,
          FrozenStateToString),
      waiting_for_contentful_paint_(true,
                                    "FrameScheduler.WaitingForContentfulPaint",
                                    &tracing_controller_,
                                    YesNoStateToString),
      waiting_for_meaningful_paint_(true,
                                    "FrameScheduler.WaitingForMeaningfulPaint",
                                    &tracing_controller_,
                                    YesNoStateToString),
      is_load_event_dispatched_(false,
                                "FrameScheduler.IsLoadEventDispatched",
                                &tracing_controller_,
                                YesNoStateToString) {
  frame_task_queue_controller_ = base::WrapUnique(
      new FrameTaskQueueController(main_thread_scheduler_, this, this));
  back_forward_cache_disabling_feature_tracker_.SetDelegate(delegate_);
}

FrameSchedulerImpl::FrameSchedulerImpl()
    : FrameSchedulerImpl(/*main_thread_scheduler=*/nullptr,
                         /*parent_page_scheduler=*/nullptr,
                         /*delegate=*/nullptr,
                         /*is_in_embedded_frame_tree=*/false,
                         FrameType::kSubframe) {}

FrameSchedulerImpl::~FrameSchedulerImpl() {
  weak_factory_.InvalidateWeakPtrs();

  for (const auto& task_queue_and_voter :
       frame_task_queue_controller_->GetAllTaskQueuesAndVoters()) {
    if (task_queue_and_voter.first->CanBeThrottled()) {
      RemoveThrottleableQueueFromBudgetPools(task_queue_and_voter.first);
    }
    auto* queue = task_queue_and_voter.first;
    CHECK(queue);
    queue->DetachTaskQueue();
    CHECK(!queue->GetFrameScheduler());
  }

  if (parent_page_scheduler_) {
    parent_page_scheduler_->Unregister(this);

    if (AreFrameAndPageVisible()) {
      PolicyUpdater policy_updater;
      GetAgentGroupSchedulerImpl().DecrementVisibleFramesForAgent(
          agent_cluster_id_, policy_updater);
    }

    if (opted_out_from_aggressive_throttling())
      parent_page_scheduler_->OnThrottlingStatusUpdated();
  }
}

AgentGroupSchedulerImpl& FrameSchedulerImpl::GetAgentGroupSchedulerImpl() {
  CHECK(parent_page_scheduler_);
  return parent_page_scheduler_->GetAgentGroupScheduler();
}

void FrameSchedulerImpl::OnPageVisibilityChange(
    PageVisibilityState page_visibility,
    PolicyUpdater& policy_updater) {
  CHECK_NE(page_visibility, page_visibility_.get());

  const bool were_frame_and_page_visible = AreFrameAndPageVisible();
  page_visibility_ = page_visibility;
  CHECK_EQ(page_visibility_ == PageVisibilityState::kVisible,
           parent_page_scheduler_->IsPageVisible());
  const bool are_frame_and_page_visible = AreFrameAndPageVisible();

  if (were_frame_and_page_visible != are_frame_and_page_visible) {
    OnFrameAndPageVisibleChanged(policy_updater);
  }
}

void FrameSchedulerImpl::OnPageSchedulerDeletion(
    PolicyUpdater& policy_updater) {
  for (const auto& task_queue_and_voter :
       frame_task_queue_controller_->GetAllTaskQueuesAndVoters()) {
    if (task_queue_and_voter.first->CanBeThrottled()) {
      RemoveThrottleableQueueFromBudgetPools(task_queue_and_voter.first);
    }
  }

  if (AreFrameAndPageVisible()) {
    GetAgentGroupSchedulerImpl().DecrementVisibleFramesForAgent(
        agent_cluster_id_, policy_updater);
  }

  parent_page_scheduler_ = nullptr;
}

void FrameSchedulerImpl::OnFrameAndPageVisibleChanged(
    PolicyUpdater& policy_updater) {
  if (AreFrameAndPageVisible()) {
    return GetAgentGroupSchedulerImpl().IncrementVisibleFramesForAgent(
        agent_cluster_id_, policy_updater);
  } else {
    return GetAgentGroupSchedulerImpl().DecrementVisibleFramesForAgent(
        agent_cluster_id_, policy_updater);
  }
}

void FrameSchedulerImpl::RemoveThrottleableQueueFromBudgetPools(
    MainThreadTaskQueue* task_queue) {
  DCHECK(task_queue);
  DCHECK(task_queue->CanBeThrottled());

  if (!parent_page_scheduler_)
    return;

  CPUTimeBudgetPool* cpu_time_budget_pool =
      parent_page_scheduler_->background_cpu_time_budget_pool();

  // On tests, the scheduler helper might already be shut down and tick is not
  // available.
  base::LazyNow lazy_now =
      main_thread_scheduler_->GetTickClock()
          ? base::LazyNow(main_thread_scheduler_->GetTickClock())
          : base::LazyNow(base::TimeTicks::Now());

  if (cpu_time_budget_pool) {
    task_queue->RemoveFromBudgetPool(lazy_now.Now(), cpu_time_budget_pool);
  }

  parent_page_scheduler_->RemoveQueueFromWakeUpBudgetPool(task_queue,
                                                          &lazy_now);
}

void FrameSchedulerImpl::SetFrameVisible(bool frame_visible) {
  if (frame_visible_ == frame_visible) {
    return;
  }

  const bool were_frame_and_page_visible = AreFrameAndPageVisible();
  frame_visible_ = frame_visible;
  const bool are_frame_and_page_visible = AreFrameAndPageVisible();

  PolicyUpdater policy_updater;
  policy_updater.UpdateFramePolicy(this);
  if (were_frame_and_page_visible != are_frame_and_page_visible) {
    OnFrameAndPageVisibleChanged(policy_updater);
  }
}

bool FrameSchedulerImpl::IsFrameVisible() const {
  return frame_visible_;
}

void FrameSchedulerImpl::SetVisibleAreaLarge(bool is_large) {
  DCHECK(parent_page_scheduler_);
  if (is_visible_area_large_ == is_large) {
    return;
  }
  is_visible_area_large_ = is_large;

  if (!IsCrossOriginToNearestMainFrame()) {
    return;
  }

  UpdatePolicy();
}

void FrameSchedulerImpl::SetHadUserActivation(bool had_user_activation) {
  DCHECK(parent_page_scheduler_);
  if (had_user_activation_ == had_user_activation) {
    return;
  }
  had_user_activation_ = had_user_activation;

  if (!IsCrossOriginToNearestMainFrame()) {
    return;
  }

  UpdatePolicy();
}

void FrameSchedulerImpl::SetCrossOriginToNearestMainFrame(bool cross_origin) {
  DCHECK(parent_page_scheduler_);
  if (frame_origin_type_ == FrameOriginType::kMainFrame) {
    DCHECK(!cross_origin);
    return;
  }

  if (cross_origin) {
    frame_origin_type_ = FrameOriginType::kCrossOriginToMainFrame;
  } else {
    frame_origin_type_ = FrameOriginType::kSameOriginToMainFrame;
  }

  UpdatePolicy();
}

void FrameSchedulerImpl::SetIsAdFrame(bool is_ad_frame) {
  is_ad_frame_ = is_ad_frame;
  UpdatePolicy();
}

bool FrameSchedulerImpl::IsAdFrame() const {
  return is_ad_frame_;
}

bool FrameSchedulerImpl::IsInEmbeddedFrameTree() const {
  return is_in_embedded_frame_tree_;
}

bool FrameSchedulerImpl::IsCrossOriginToNearestMainFrame() const {
  return frame_origin_type_ == FrameOriginType::kCrossOriginToMainFrame;
}

void FrameSchedulerImpl::SetAgentClusterId(
    const base::UnguessableToken& agent_cluster_id) {
  PolicyUpdater policy_updater;

  if (AreFrameAndPageVisible()) {
    GetAgentGroupSchedulerImpl().IncrementVisibleFramesForAgent(
        agent_cluster_id, policy_updater);
    GetAgentGroupSchedulerImpl().DecrementVisibleFramesForAgent(
        agent_cluster_id_, policy_updater);
  }

  agent_cluster_id_ = agent_cluster_id;
  policy_updater.UpdateFramePolicy(this);
}

void FrameSchedulerImpl::TraceUrlChange(const String& url) {
  url_tracer_.TraceString(url);
}

void FrameSchedulerImpl::AddTaskTime(base::TimeDelta time) {
  // The duration of task time under which AddTaskTime buffers rather than
  // sending the task time update to the delegate.
  constexpr base::TimeDelta kTaskDurationSendThreshold =
      base::Milliseconds(100);
  if (!delegate_)
    return;
  unreported_task_time_ += time;
  if (unreported_task_time_ >= kTaskDurationSendThreshold) {
    delegate_->UpdateTaskTime(unreported_task_time_);
    unreported_task_time_ = base::TimeDelta();
  }
}

FrameScheduler::FrameType FrameSchedulerImpl::GetFrameType() const {
  return frame_type_;
}

// static
QueueTraits FrameSchedulerImpl::CreateQueueTraitsForTaskType(TaskType type) {
  // TODO(sreejakshetty): Clean up the PrioritisationType QueueTrait and
  // QueueType for kInternalContinueScriptLoading and kInternalContentCapture.
  switch (type) {
    case TaskType::kInternalContentCapture:
      return ThrottleableTaskQueueTraits().SetPrioritisationType(
          QueueTraits::PrioritisationType::kBestEffort);
    case TaskType::kJavascriptTimerDelayedLowNesting:
      return ThrottleableTaskQueueTraits().SetPrioritisationType(
          QueueTraits::PrioritisationType::kJavaScriptTimer);
    case TaskType::kJavascriptTimerDelayedHighNesting:
      return ThrottleableTaskQueueTraits()
          .SetPrioritisationType(
              QueueTraits::PrioritisationType::kJavaScriptTimer)
          .SetCanBeIntensivelyThrottled(IsIntensiveWakeUpThrottlingEnabled());
    case TaskType::kJavascriptTimerImmediate: {
      // Immediate timers are not throttled.
      return DeferrableTaskQueueTraits().SetPrioritisationType(
          QueueTraits::PrioritisationType::kJavaScriptTimer);
    }
    case TaskType::kInternalLoading:
    case TaskType::kNetworking:
      return LoadingTaskQueueTraits();
    case TaskType::kNetworkingUnfreezable:
      return IsInflightNetworkRequestBackForwardCacheSupportEnabled()
                 ? UnfreezableLoadingTaskQueueTraits()
                 : LoadingTaskQueueTraits();
    case TaskType::kNetworkingUnfreezableRenderBlockingLoading: {
      QueueTraits queue_traits =
          IsInflightNetworkRequestBackForwardCacheSupportEnabled()
              ? UnfreezableLoadingTaskQueueTraits()
              : LoadingTaskQueueTraits();
      queue_traits.SetPrioritisationType(
          QueueTraits::PrioritisationType::kRenderBlocking);
      return queue_traits;
    }
    case TaskType::kNetworkingControl:
      return LoadingControlTaskQueueTraits();
    case TaskType::kLowPriorityScriptExecution:
      return LoadingTaskQueueTraits().SetPrioritisationType(
          QueueTraits::PrioritisationType::kAsyncScript);
    // Throttling following tasks may break existing web pages, so tentatively
    // these are unthrottled.
    // TODO(nhiroki): Throttle them again after we're convinced that it's safe
    // or provide a mechanism that web pages can opt-out it if throttling is not
    // desirable.
    case TaskType::kDOMManipulation:
    case TaskType::kHistoryTraversal:
    case TaskType::kEmbed:
    case TaskType::kCanvasBlobSerialization:
    case TaskType::kRemoteEvent:
    case TaskType::kWebSocket:
    case TaskType::kMicrotask:
    case TaskType::kUnshippedPortMessage:
    case TaskType::kPresentation:
    case TaskType::kSensor:
    case TaskType::kPerformanceTimeline:
    case TaskType::kWebGL:
    case TaskType::kWebGPU:
    case TaskType::kIdleTask:
    case TaskType::kInternalDefault:
    case TaskType::kMiscPlatformAPI:
    case TaskType::kFontLoading:
    case TaskType::kApplicationLifeCycle:
    case TaskType::kBackgroundFetch:
    case TaskType::kPermission:
    case TaskType::kWakeLock:
    case TaskType::kStorage:
    case TaskType::kClipboard:
    case TaskType::kMachineLearning:
      // TODO(altimin): Move appropriate tasks to throttleable task queue.
      return DeferrableTaskQueueTraits();
    case TaskType::kFileReading:
      // This is used by Blob operations (BlobURLStore in particular, which is
      // associated to BlobRegistry) and should run with VT paused to prevent
      // deadlocks when reading network requests as Blobs. See crbug.com/1455267
      // for more details.
      return DeferrableTaskQueueTraits().SetCanRunWhenVirtualTimePaused(true);
    // PostedMessage can be used for navigation, so we shouldn't defer it
    // when expecting a user gesture.
    case TaskType::kPostedMessage:
    case TaskType::kServiceWorkerClientMessage:
    case TaskType::kWorkerAnimation:
    // UserInteraction tasks should be run even when expecting a user gesture.
    case TaskType::kUserInteraction:
    // Media events should not be deferred to ensure that media playback is
    // smooth.
    case TaskType::kMediaElementEvent:
    case TaskType::kInternalWebCrypto:
    case TaskType::kInternalMedia:
    case TaskType::kInternalMediaRealTime:
    case TaskType::kInternalUserInteraction:
    case TaskType::kInternalIntersectionObserver:
      return PausableTaskQueueTraits();
    case TaskType::kInternalFindInPage:
      return FindInPageTaskQueueTraits();
    case TaskType::kInternalHighPriorityLocalFrame:
      return QueueTraits().SetPrioritisationType(
          QueueTraits::PrioritisationType::kHighPriorityLocalFrame);
    case TaskType::kInternalContinueScriptLoading:
      return PausableTaskQueueTraits().SetPrioritisationType(
          QueueTraits::PrioritisationType::kInternalScriptContinuation);
    case TaskType::kDatabaseAccess:
      if (base::FeatureList::IsEnabled(kHighPriorityDatabaseTaskType)) {
        return PausableTaskQueueTraits().SetPrioritisationType(
            QueueTraits::PrioritisationType::kExperimentalDatabase);
      } else {
        return PausableTaskQueueTraits();
      }
    case TaskType::kInternalNavigationAssociated:
      return FreezableTaskQueueTraits();
    case TaskType::kInternalNavigationCancellation:
      return FreezableTaskQueueTraits().SetPrioritisationType(
          QueueTraits::PrioritisationType::kInternalNavigationCancellation);
    case TaskType::kInternalInputBlocking:
      return InputBlockingQueueTraits();
    // Some tasks in the tests need to run when objects are paused e.g. to hook
    // when recovering from debugger JavaScript statetment.
    case TaskType::kInternalTest:
    // kWebLocks can be frozen if for entire page, but not for individual
    // frames. See https://crrev.com/c/1687716
    case TaskType::kWebLocks:
    case TaskType::kInternalFrameLifecycleControl:
      return UnpausableTaskQueueTraits();
    case TaskType::kInternalTranslation:
      return ForegroundOnlyTaskQueueTraits();
    // The TaskType of Inspector tasks need to be unpausable and should not use
    // virtual time because they need to run on a paused page or when virtual
    // time is paused.
    case TaskType::kInternalInspector:
    // Navigation IPCs do not run using virtual time to avoid hanging.
    case TaskType::kInternalNavigationAssociatedUnfreezable:
      return CanRunWhenVirtualTimePausedTaskQueueTraits();
    case TaskType::kInternalPostMessageForwarding:
      // postMessages to remote frames hop through the scheduler so that any
      // IPCs generated in the same task arrive first. These tasks must be
      // pausable in order to maintain this invariant, otherwise they might run
      // in a nested event loop before the task completes, e.g. debugger
      // breakpoints or javascript dialogs.
      //
      // Freezing this task type would prevent transmission of postMessages to
      // remote frames that occurred in unfreezable tasks or from tasks that ran
      // prior to being frozen (e.g. freeze event handler), which is not
      // desirable. The messages are still queued on the receiving side, which
      // is where frozenness should be assessed.
      return PausableTaskQueueTraits()
          .SetCanBeFrozen(false)
          .SetPrioritisationType(
              QueueTraits::PrioritisationType::kPostMessageForwarding);
    case TaskType::kDeprecatedNone:
    case TaskType::kMainThreadTaskQueueV8:
    case TaskType::kMainThreadTaskQueueV8UserVisible:
    case TaskType::kMainThreadTaskQueueV8BestEffort:
    case TaskType::kMainThreadTaskQueueCompositor:
    case TaskType::kMainThreadTaskQueueDefault:
    case TaskType::kMainThreadTaskQueueInput:
    case TaskType::kMainThreadTaskQueueIdle:
    case TaskType::kMainThreadTaskQueueControl:
    case TaskType::kMainThreadTaskQueueMemoryPurge:
    case TaskType::kMainThreadTaskQueueIPCTracking:
    case TaskType::kCompositorThreadTaskQueueDefault:
    case TaskType::kCompositorThreadTaskQueueInput:
    case TaskType::kWorkerThreadTaskQueueDefault:
    case TaskType::kWorkerThreadTaskQueueV8:
    case TaskType::kWorkerThreadTaskQueueCompositor:
    case TaskType::kMainThreadTaskQueueNonWaking:
    // The web scheduling API task types are used by WebSchedulingTaskQueues.
    // The associated TaskRunner should be obtained by creating a
    // WebSchedulingTaskQueue with CreateWebSchedulingTaskQueue().
    case TaskType::kWebSchedulingPostedTask:
      // Not a valid frame-level TaskType.
      NOTREACHED();
  }
  // This method is called for all values between 0 and kCount. TaskType,
  // however, has numbering gaps, so even though all enumerated TaskTypes are
  // handled in the switch and return a value, we fall through for some values
  // of |type|.
  NOTREACHED();
}

scoped_refptr<base::SingleThreadTaskRunner> FrameSchedulerImpl::GetTaskRunner(
    TaskType type) {
  auto it = task_runners_.find(type);
  if (it == task_runners_.end()) {
    scoped_refptr<MainThreadTaskQueue> task_queue = GetTaskQueue(type);
    DCHECK(task_queue);
    auto res = task_queue->CreateTaskRunner(type);
    task_runners_.insert(type, res);
    return res;
  }
  return it->value;
}

scoped_refptr<MainThreadTaskQueue> FrameSchedulerImpl::GetTaskQueue(
    TaskType type) {
  QueueTraits queue_traits = CreateQueueTraitsForTaskType(type);
  queue_traits = queue_traits.SetCanBeDeferredForRendering(
      ComputeCanBeDeferredForRendering(queue_traits.can_be_deferred, type));
  return frame_task_queue_controller_->GetTaskQueue(queue_traits);
}

scoped_refptr<base::SingleThreadTaskRunner>
FrameSchedulerImpl::ControlTaskRunner() {
  DCHECK(parent_page_scheduler_);
  return main_thread_scheduler_->ControlTaskRunner();
}

AgentGroupScheduler* FrameSchedulerImpl::GetAgentGroupScheduler() {
  return parent_page_scheduler_
             ? &parent_page_scheduler_->GetAgentGroupScheduler()
             : nullptr;
}

blink::PageScheduler* FrameSchedulerImpl::GetPageScheduler() const {
  return parent_page_scheduler_;
}

void FrameSchedulerImpl::DidStartProvisionalLoad() {
  main_thread_scheduler_->DidStartProvisionalLoad(
      frame_type_ == FrameScheduler::FrameType::kMainFrame &&
      !is_in_embedded_frame_tree_);
}

void FrameSchedulerImpl::DidCommitProvisionalLoad(
    bool is_web_history_inert_commit,
    NavigationType navigation_type,
    DidCommitProvisionalLoadParams params) {
  bool is_outermost_main_frame =
      GetFrameType() == FrameType::kMainFrame && !is_in_embedded_frame_tree_;
  bool is_same_document = navigation_type == NavigationType::kSameDocument;

  if (!is_same_document) {
    waiting_for_contentful_paint_ = true;
    waiting_for_meaningful_paint_ = true;
    is_load_event_dispatched_ = false;
  }

  if (is_outermost_main_frame && !is_same_document) {
    unreported_task_time_ = base::TimeDelta();
  } else {
    unreported_task_time_ = params.previous_document_unreported_task_time;
  }

  main_thread_scheduler_->DidCommitProvisionalLoad(
      is_web_history_inert_commit, navigation_type == NavigationType::kReload,
      is_outermost_main_frame);
  if (!is_same_document)
    ResetForNavigation();
}

WebScopedVirtualTimePauser FrameSchedulerImpl::CreateWebScopedVirtualTimePauser(
    const WTF::String& name,
    WebScopedVirtualTimePauser::VirtualTaskDuration duration) {
  return WebScopedVirtualTimePauser(main_thread_scheduler_, duration, name);
}

scoped_refptr<base::SingleThreadTaskRunner>
FrameSchedulerImpl::CompositorTaskRunner() {
  return parent_page_scheduler_->GetAgentGroupScheduler()
      .CompositorTaskRunner();
}

void FrameSchedulerImpl::ResetForNavigation() {
  document_bound_weak_factory_.InvalidateWeakPtrs();
  back_forward_cache_disabling_feature_tracker_.Reset();
}

bool FrameSchedulerImpl::IsImportant() const {
  // Hidden frame is never important.
  if (!AreFrameAndPageVisible()) {
    return false;
  }

  return is_visible_area_large_ || had_user_activation_;
}

bool FrameSchedulerImpl::AreFrameAndPageVisible() const {
  return frame_visible_ && page_visibility_ == PageVisibilityState::kVisible;
}

void FrameSchedulerImpl::OnStartedUsingNonStickyFeature(
    SchedulingPolicy::Feature feature,
    const SchedulingPolicy& policy,
    std::unique_ptr<SourceLocation> source_location,
    SchedulingAffectingFeatureHandle* handle) {
  if (policy.disable_aggressive_throttling)
    OnAddedAggressiveThrottlingOptOut();
  if (policy.disable_back_forward_cache) {
    back_forward_cache_disabling_feature_tracker_.AddNonStickyFeature(
        feature, std::move(source_location), handle);
  }
  if (policy.disable_align_wake_ups) {
    DisableAlignWakeUpsForProcess();
  }

  if (feature == SchedulingPolicy::Feature::kWebRTC) {
    if (base::FeatureList::IsEnabled(
            kRendererMainIsDefaultThreadTypeForWebRTC) &&
        base::PlatformThread::GetCurrentThreadType() ==
            base::ThreadType::kDisplayCritical) {
      base::PlatformThread::SetCurrentThreadType(base::ThreadType::kDefault);
    }

    if (auto* rc = delegate_->GetDocumentResourceCoordinator()) {
      rc->OnStartedUsingWebRTC();
    }
  }
}

void FrameSchedulerImpl::OnStartedUsingStickyFeature(
    SchedulingPolicy::Feature feature,
    const SchedulingPolicy& policy,
    std::unique_ptr<SourceLocation> source_location) {
  if (policy.disable_aggressive_throttling)
    OnAddedAggressiveThrottlingOptOut();
  if (policy.disable_back_forward_cache) {
    back_forward_cache_disabling_feature_tracker_.AddStickyFeature(
        feature, std::move(source_location));
  }
  if (policy.disable_align_wake_ups) {
    DisableAlignWakeUpsForProcess();
  }
}

void FrameSchedulerImpl::OnStoppedUsingNonStickyFeature(
    SchedulingAffectingFeatureHandle* handle) {
  if (handle->GetPolicy().disable_aggressive_throttling)
    OnRemovedAggressiveThrottlingOptOut();
  if (handle->GetPolicy().disable_back_forward_cache) {
    back_forward_cache_disabling_feature_tracker_.Remove(
        handle->GetFeatureAndJSLocationBlockingBFCache());
  }

  if (handle->GetFeature() == SchedulingPolicy::Feature::kWebRTC) {
    if (auto* rc = delegate_->GetDocumentResourceCoordinator()) {
      rc->OnStoppedUsingWebRTC();
    }
  }
}

base::WeakPtr<FrameScheduler> FrameSchedulerImpl::GetWeakPtr() {
  return weak_factory_.GetWeakPtr();
}

base::WeakPtr<const FrameSchedulerImpl> FrameSchedulerImpl::GetWeakPtr() const {
  return weak_factory_.GetWeakPtr();
}

void FrameSchedulerImpl::ReportActiveSchedulerTrackedFeatures() {
  back_forward_cache_disabling_feature_tracker_.ReportFeaturesToDelegate();
}

base::WeakPtr<FrameSchedulerImpl>
FrameSchedulerImpl::GetInvalidatingOnBFCacheRestoreWeakPtr() {
  return invalidating_on_bfcache_restore_weak_factory_.GetWeakPtr();
}

void FrameSchedulerImpl::OnAddedAggressiveThrottlingOptOut() {
  ++aggressive_throttling_opt_out_count_;
  opted_out_from_aggressive_throttling_ =
      static_cast<bool>(aggressive_throttling_opt_out_count_);
  if (parent_page_scheduler_)
    parent_page_scheduler_->OnThrottlingStatusUpdated();
}

void FrameSchedulerImpl::OnRemovedAggressiveThrottlingOptOut() {
  DCHECK_GT(aggressive_throttling_opt_out_count_, 0);
  --aggressive_throttling_opt_out_count_;
  opted_out_from_aggressive_throttling_ =
      static_cast<bool>(aggressive_throttling_opt_out_count_);
  if (parent_page_scheduler_)
    parent_page_scheduler_->OnThrottlingStatusUpdated();
}

void FrameSchedulerImpl::OnTaskCompleted(TaskQueue::TaskTiming* timing) {
  if (delegate_) {
    delegate_->OnTaskCompleted(timing->start_time(), timing->end_time());
  }
}

void FrameSchedulerImpl::WriteIntoTrace(perfetto::TracedValue context) const {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("frame_visible", frame_visible_);
  dict.Add("page_visible", parent_page_scheduler_->IsPageVisible());
  dict.Add("cross_origin_to_main_frame", IsCrossOriginToNearestMainFrame());
  dict.Add("frame_type", frame_type_ == FrameScheduler::FrameType::kMainFrame
                             ? "MainFrame"
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