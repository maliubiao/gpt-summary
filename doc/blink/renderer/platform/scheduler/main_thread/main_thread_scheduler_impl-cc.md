Response: The user wants me to analyze the provided C++ source code file `main_thread_scheduler_impl.cc` from the Chromium Blink engine. I need to:

1. **List its functionalities:**  Understand what this class is responsible for.
2. **Explain its relation to web technologies (JavaScript, HTML, CSS):** How does this code interact with the execution of these technologies in a web browser?
3. **Provide examples of logical reasoning:** If the code makes decisions based on certain conditions, illustrate these with hypothetical inputs and outputs.
4. **Highlight common user/programming errors:**  Are there any typical mistakes related to how this component might be used or misused?
5. **Summarize its overall function:**  Provide a concise overview based on the analysis so far.

**Let's break down the code to address each point:**

* **Headers:** The included headers give clues about the class's responsibilities. We see things like `base/task`, `base/metrics`, `third_party/blink/public/common/input`, `third_party/blink/renderer/platform/scheduler`, suggesting it deals with task scheduling, performance monitoring, and handling input events.
* **Class definition `MainThreadSchedulerImpl`:** This is the core class we need to analyze.
* **Member variables:** These variables represent the internal state and dependencies of the scheduler. They offer insights into its functionalities (e.g., `idle_helper_`, `task_runners_`, `main_thread_only_`).
* **Methods:** The methods define the behavior of the scheduler. Looking at method names like `PostTask`, `ScheduleDelayedTask`, `WillBeginFrame`, `DidHandleInputEventOnMainThread`, `UpdatePolicy`, etc., reveals its primary role in managing tasks and responding to events on the main thread.
* **Inner classes/structs:**  `MainThreadOnly`, `AnyThread`, `CompositorThreadOnly`, and `SchedulingSettings` group related data and further clarify the scope of the scheduler's operations across different threads and contexts.
* **Focus on input event handling:** The code has sections specifically dealing with `WebInputEvent`, indicating a significant role in processing user interactions.
* **Emphasis on scheduling and priorities:**  The code manages different task queues with varying priorities, which is crucial for performance.
* **Interaction with the compositor:** There are mentions of compositor tasks and synchronization, suggesting it plays a part in the rendering pipeline.

**Potential relations to web technologies:**

* **JavaScript:** The scheduler manages the execution of JavaScript code on the main thread.
* **HTML/CSS:**  The scheduler is involved in processing layout, rendering, and user interactions related to HTML and CSS.

**Logical reasoning examples:** I can create hypothetical scenarios based on the conditions and actions within the methods, particularly around input event handling and priority updates.

**Common errors:** Misusing the API for posting tasks, not understanding the priority implications, or creating deadlocks by incorrect synchronization could be potential errors.

**Summarization:**  Based on the initial analysis, `MainThreadSchedulerImpl` appears to be a central component responsible for managing the execution of tasks and events on the main thread of the Blink rendering engine, with a focus on maintaining responsiveness and handling user input efficiently.
```
功能归纳：

`MainThreadSchedulerImpl` 是 Chromium Blink 引擎中负责主线程任务调度的核心组件。它的主要功能可以概括为：

1. **任务队列管理:**
   - 创建和管理不同类型的任务队列（例如，用于 V8 任务、用户可见 V8 任务、最佳努力 V8 任务、非唤醒任务、IPC 跟踪任务等）。
   - 为每个任务队列分配优先级，并根据当前系统状态和策略动态调整优先级。
   - 提供接口用于向不同队列提交任务和延迟任务。
   - 支持任务队列的暂停、冻结和唤醒。
   - 管理不再依附于任何 Frame 的独立任务队列。

2. **主线程生命周期管理:**
   - 监听并响应渲染器进程的隐藏和后台状态变化，并据此调整调度策略。
   - 管理渲染器暂停状态。
   - 在渲染器关闭时进行清理工作。

3. **输入事件处理:**
   - 接收来自合成器线程的输入事件通知。
   - 判断输入事件是否需要优先处理。
   - 根据输入事件类型和处理结果调整调度策略，例如，在触摸开始事件后优先处理合成器任务，以确保流畅的滚动体验。
   - 追踪待处理的输入事件，并根据处理结果更新状态。

4. **帧调度同步:**
   - 接收来自合成器线程的 `WillBeginFrame` 和 `DidCommitFrameToCompositor` 事件，用于同步主线程的任务调度和渲染流程。
   - 根据帧开始和提交的时间信息，估计下一帧的开始时间，并据此安排空闲时间的利用。
   - 管理 `BeginFrameNotExpectedSoon` 和 `BeginMainFrameNotExpectedUntil` 状态，并据此调整调度策略，例如，在没有预期帧时进入长空闲时间。

5. **调度策略管理:**
   - 维护和更新主线程的调度策略（`Policy`），该策略决定了不同任务队列的优先级和是否启用。
   - 调度策略的更新会考虑多种因素，包括用户交互状态、渲染器可见性、后台状态、音频播放状态等。
   - 提供机制强制更新调度策略。
   - 使用 `UseCase` 枚举来表示当前主线程正在执行的任务类型，并据此应用不同的调度策略。

6. **空闲时间管理:**
   - 使用 `IdleHelper` 来管理主线程的空闲时间，并在空闲期间执行低优先级的任务。
   - 可以根据渲染器是否隐藏来调整空闲时间的策略。

7. **性能监控和追踪:**
   - 使用 `TRACE_EVENT` 进行性能追踪，记录关键事件和状态变化。
   - 收集和记录主线程的性能指标，例如，空闲时间、任务执行时长等。
   - 通过 `TracingController` 将调度状态信息添加到跟踪事件中。

8. **内存管理辅助:**
   - 提供用于内存清理任务的独立任务队列和管理器。

9. **与其他组件的交互:**
   - 与 `FrameSchedulerImpl`、`WidgetSchedulerImpl`、`PageSchedulerImpl` 等其他调度器组件协同工作。
   - 与 V8 引擎交互，管理 JavaScript 任务的执行。
   - 与合成器线程通信，同步渲染流程。
   - 与 `ParkableStringManager` 交互，管理可停靠字符串的生命周期。
   - 与 `FindInPageBudgetPoolController` 交互，管理查找功能的优先级。

与 Javascript, HTML, CSS 的功能关系举例说明：

1. **Javascript 执行:** 当 JavaScript 代码需要执行时（例如，通过 `setTimeout`, `requestAnimationFrame`, 或事件处理），Blink 会将相应的任务提交给 `MainThreadSchedulerImpl` 管理的 V8 任务队列。`MainThreadSchedulerImpl` 会根据当前策略和优先级决定何时执行这些 JavaScript 任务。例如，在高优先级的用户交互期间，V8 任务队列的优先级可能会提升，以确保 JavaScript 响应的及时性。

   * **假设输入:** 用户点击了一个按钮，触发了一个 JavaScript 事件处理函数。
   * **输出:** `MainThreadSchedulerImpl` 会将该事件处理函数对应的任务加入到 V8 任务队列，并根据当前策略（例如，如果正处于用户交互期间）尽快执行该任务。

2. **HTML 解析和渲染:**  当浏览器解析 HTML 并构建 DOM 树时，或者当 CSS 样式发生变化需要重新布局和绘制时，`MainThreadSchedulerImpl` 会管理与这些操作相关的任务。例如，布局计算、样式计算和绘制操作会被放入相应的任务队列中执行。在某些情况下，例如页面加载初期，与渲染相关的任务可能会被赋予更高的优先级，以尽快显示页面内容。

   * **假设输入:** 浏览器开始加载一个新的网页，需要解析 HTML 并构建 DOM 树。
   * **输出:** `MainThreadSchedulerImpl` 会调度与 HTML 解析相关的任务，例如 Tokenizer、Tree Construction 等。这些任务可能会被赋予较高的优先级，以便尽快完成 DOM 树的构建。

3. **CSS 动画和过渡:**  CSS 动画和过渡通常由 Blink 的渲染引擎驱动，但 `MainThreadSchedulerImpl` 仍然参与其中。例如，`requestAnimationFrame` 回调函数会被提交给 `MainThreadSchedulerImpl` 管理，用于在每一帧更新动画状态。

   * **假设输入:** 一个使用了 CSS 动画的元素需要在下一帧更新其动画状态。
   * **输出:**  `MainThreadSchedulerImpl` 会调度与 `requestAnimationFrame` 回调相关的任务，确保在合适的时机执行，以驱动动画的流畅播放。

逻辑推理的假设输入与输出:

1. **假设输入:** 用户刚刚开始触摸屏幕并滑动 (TouchStart 事件)，并且该事件是阻塞型的。
   * **推理:** `IsBlockingEvent` 函数会返回 `true`。`UpdateForInputEventOnCompositorThread` 会设置 `any_thread().awaiting_touch_start_response` 为 `true`，并且 `any_thread().have_seen_a_blocking_gesture` 为 `true`。`UpdatePolicyLocked` 会被调用，并可能将 `UseCase` 设置为 `kTouchstart`，从而提升合成器任务队列的优先级。
   * **输出:** 合成器任务队列的优先级提升，以便优先处理与滚动相关的任务，保证滚动的流畅性。

2. **假设输入:** 渲染器进程从前台切换到后台。
   * **推理:** `SetRendererBackgrounded` 函数会被调用，`main_thread_only().renderer_backgrounded` 的值会被更新。`UpdatePolicy` 会被调用，并且可能会降低某些任务队列的优先级，并暂停不必要的后台任务。
   * **输出:** 主线程上某些任务的优先级降低，资源消耗减少，例如减少 JavaScript 定时器的执行频率。

涉及用户或者编程常见的使用错误举例说明：

1. **错误地假设任务会立即执行:**  开发者可能会错误地认为调用 `PostTask` 后任务会立即执行。然而，`MainThreadSchedulerImpl` 会根据当前策略和任务队列的优先级来安排任务的执行顺序。如果主线程正忙于处理高优先级的任务，新提交的任务可能会被延迟执行。

   * **错误示例:**  一段 JavaScript 代码提交了一个任务来更新 DOM，并紧接着读取该 DOM 元素的属性，期望立即获得更新后的值。如果该任务被延迟执行，读取操作可能会得到旧的值。

2. **在高优先级任务中执行耗时操作:** 开发者可能会在用户交互相关的任务中执行大量的同步计算或 I/O 操作，阻塞主线程，导致页面卡顿。

   * **错误示例:** 在一个触摸事件处理函数中，同步读取一个大文件或执行复杂的图像处理操作。这将导致用户在滑动或点击时感受到明显的延迟。

3. **不理解任务队列的优先级和类型:** 开发者可能会将不重要的后台任务提交到高优先级的任务队列中，或者将需要立即执行的任务提交到低优先级的任务队列中，导致性能问题。

   * **错误示例:** 将用于记录用户行为的后台统计任务提交到 V8 任务队列，可能会影响 JavaScript 代码的执行效率。

功能总结：

`MainThreadSchedulerImpl` 是 Blink 渲染引擎中主线程的核心调度器，负责管理各种类型的任务队列，并根据系统状态、用户交互和渲染流程等因素动态调整任务的优先级和执行顺序。它确保了主线程的响应性，特别是在处理用户输入和渲染更新方面，并负责主线程的生命周期管理和性能监控。它与 JavaScript, HTML, CSS 的执行息息相关，通过调度不同类型的任务来驱动网页的渲染和交互行为。
```
### 提示词
```
这是目录为blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <type_traits>
#include <utility>

#include "base/check_op.h"
#include "base/containers/contains.h"
#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram.h"
#include "base/metrics/histogram_functions.h"
#include "base/metrics/histogram_macros.h"
#include "base/notreached.h"
#include "base/numerics/safe_conversions.h"
#include "base/observer_list.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/common/scoped_defer_task_posting.h"
#include "base/task/common/task_annotator.h"
#include "base/task/sequenced_task_runner.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/common/trace_event_common.h"
#include "base/trace_event/trace_event.h"
#include "base/trace_event/traced_value.h"
#include "build/build_config.h"
#include "components/viz/common/frame_sinks/begin_frame_args.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_input_event_attribution.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/common/input/web_touch_event.h"
#include "third_party/blink/public/common/page/launching_process_state.h"
#include "third_party/blink/public/platform/scheduler/web_agent_group_scheduler.h"
#include "third_party/blink/public/platform/scheduler/web_renderer_process_type.h"
#include "third_party/blink/public/platform/web_input_event_result.h"
#include "third_party/blink/renderer/platform/bindings/parkable_string_manager.h"
#include "third_party/blink/renderer/platform/bindings/v8_per_isolate_data.h"
#include "third_party/blink/renderer/platform/heap/collection_support/heap_vector.h"
#include "third_party/blink/renderer/platform/instrumentation/resource_coordinator/renderer_resource_coordinator.h"
#include "third_party/blink/renderer/platform/scheduler/common/auto_advancing_virtual_time_domain.h"
#include "third_party/blink/renderer/platform/scheduler/common/features.h"
#include "third_party/blink/renderer/platform/scheduler/common/process_state.h"
#include "third_party/blink/renderer/platform/scheduler/common/task_priority.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/task_queue_throttler.h"
#include "third_party/blink/renderer/platform/scheduler/common/tracing_helper.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/agent_group_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_metrics_helper.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/page_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/pending_user_input.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/task_type_names.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/widget_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"
#include "third_party/perfetto/protos/perfetto/trace/track_event/chrome_renderer_scheduler_state.pbzero.h"
#include "third_party/perfetto/protos/perfetto/trace/track_event/track_event.pbzero.h"
#include "v8/include/v8.h"

namespace base {
class LazyNow;
}

namespace blink {
namespace scheduler {

using base::sequence_manager::TaskQueue;
using base::sequence_manager::TaskTimeObserver;
using base::sequence_manager::TimeDomain;

namespace {
const int kShortIdlePeriodDurationSampleCount = 10;
const double kShortIdlePeriodDurationPercentile = 50;
// Amount of idle time left in a frame (as a ratio of the vsync interval) above
// which main thread compositing can be considered fast.
const double kFastCompositingIdleTimeThreshold = .2;
const int64_t kSecondsPerMinute = 60;

constexpr int kDefaultPrioritizeCompositingAfterDelayMs = 100;

void AddRAILModeToProto(perfetto::protos::pbzero::TrackEvent* event,
                        RAILMode mode) {
  using perfetto::protos::pbzero::ChromeRAILMode;
  auto* scheduler_state = event->set_chrome_renderer_scheduler_state();
  switch (mode) {
    case RAILMode::kDefault:
      scheduler_state->set_rail_mode(ChromeRAILMode::RAIL_MODE_IDLE);
      return;
    case RAILMode::kLoad:
      scheduler_state->set_rail_mode(ChromeRAILMode::RAIL_MODE_LOAD);
      return;
  }
  NOTREACHED();
}

void AddBackgroundedToProto(perfetto::protos::pbzero::TrackEvent* event,
                            bool is_backgrounded) {
  event->set_chrome_renderer_scheduler_state()->set_is_backgrounded(
      is_backgrounded);
}

void AddHiddenToProto(perfetto::protos::pbzero::TrackEvent* event,
                      bool is_hidden) {
  event->set_chrome_renderer_scheduler_state()->set_is_hidden(is_hidden);
}

const char* AudioPlayingStateToString(bool is_audio_playing) {
  if (is_audio_playing) {
    return "playing";
  } else {
    return "silent";
  }
}

const char* RendererProcessTypeToString(WebRendererProcessType process_type) {
  switch (process_type) {
    case WebRendererProcessType::kRenderer:
      return "normal";
    case WebRendererProcessType::kExtensionRenderer:
      return "extension";
  }
  NOTREACHED();
}

const char* OptionalTaskDescriptionToString(
    std::optional<MainThreadSchedulerImpl::TaskDescriptionForTracing> desc) {
  if (!desc)
    return nullptr;
  if (desc->task_type != TaskType::kDeprecatedNone)
    return TaskTypeNames::TaskTypeToString(desc->task_type);
  if (!desc->queue_type)
    return "detached_tq";
  return perfetto::protos::pbzero::SequenceManagerTask::QueueName_Name(
      MainThreadTaskQueue::NameForQueueType(desc->queue_type.value()));
}

const char* OptionalTaskPriorityToString(std::optional<TaskPriority> priority) {
  if (!priority)
    return nullptr;
  return TaskPriorityToString(*priority);
}

bool IsBlockingEvent(const blink::WebInputEvent& web_input_event) {
  blink::WebInputEvent::Type type = web_input_event.GetType();
  DCHECK(type == blink::WebInputEvent::Type::kTouchStart ||
         type == blink::WebInputEvent::Type::kMouseWheel);

  if (type == blink::WebInputEvent::Type::kTouchStart) {
    const WebTouchEvent& touch_event =
        static_cast<const WebTouchEvent&>(web_input_event);
    return touch_event.dispatch_type ==
           blink::WebInputEvent::DispatchType::kBlocking;
  }

  const WebMouseWheelEvent& mouse_event =
      static_cast<const WebMouseWheelEvent&>(web_input_event);
  return mouse_event.dispatch_type ==
         blink::WebInputEvent::DispatchType::kBlocking;
}

const char* InputEventStateToString(
    WidgetScheduler::InputEventState input_event_state) {
  switch (input_event_state) {
    case WidgetScheduler::InputEventState::EVENT_CONSUMED_BY_COMPOSITOR:
      return "event_consumed_by_compositor";
    case WidgetScheduler::InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD:
      return "event_forwarded_to_main_thread";
    default:
      NOTREACHED();
  }
}

const char* RenderingPrioritizationStateToString(
    MainThreadSchedulerImpl::RenderingPrioritizationState state) {
  using RenderingPrioritizationState =
      MainThreadSchedulerImpl::RenderingPrioritizationState;
  switch (state) {
    case RenderingPrioritizationState::kNone:
      return "none";
    case RenderingPrioritizationState::kRenderingStarved:
      return "rendering_starved";
    case RenderingPrioritizationState::kRenderingStarvedByRenderBlocking:
      return "rendering_starved_by_render_blocking";
    case RenderingPrioritizationState::kWaitingForInputResponse:
      return "waiting_for_input_response";
  }
}

}  // namespace

MainThreadSchedulerImpl::MainThreadSchedulerImpl(
    std::unique_ptr<base::sequence_manager::SequenceManager> sequence_manager)
    : MainThreadSchedulerImpl(sequence_manager.get()) {
  owned_sequence_manager_ = std::move(sequence_manager);
}

MainThreadSchedulerImpl::MainThreadSchedulerImpl(
    base::sequence_manager::SequenceManager* sequence_manager)
    : sequence_manager_(sequence_manager),
      helper_(sequence_manager_, this),
      idle_helper_queue_(helper_.NewTaskQueue(
          MainThreadTaskQueue::QueueCreationParams(
              MainThreadTaskQueue::QueueType::kIdle)
              .SetPrioritisationType(MainThreadTaskQueue::QueueTraits::
                                         PrioritisationType::kBestEffort)
              .SetCanBeDeferredForRendering(base::FeatureList::IsEnabled(
                  features::kDeferRendererTasksAfterInput)))),
      idle_queue_voter_(
          base::FeatureList::IsEnabled(features::kDeferRendererTasksAfterInput)
              ? idle_helper_queue_->CreateQueueEnabledVoter()
              : nullptr),
      idle_helper_(&helper_,
                   this,
                   "MainThreadSchedulerIdlePeriod",
                   base::TimeDelta(),
                   idle_helper_queue_->GetTaskQueue()),
      render_widget_scheduler_signals_(this),
      find_in_page_budget_pool_controller_(
          new FindInPageBudgetPoolController(this)),
      control_task_queue_(helper_.ControlMainThreadTaskQueue()),
      back_forward_cache_ipc_tracking_task_queue_(helper_.NewTaskQueue(
          MainThreadTaskQueue::QueueCreationParams(
              MainThreadTaskQueue::QueueType::kIPCTrackingForCachedPages)
              .SetShouldNotifyObservers(false))),
      memory_purge_task_queue_(helper_.NewTaskQueue(
          MainThreadTaskQueue::QueueCreationParams(
              MainThreadTaskQueue::QueueType::kIdle)
              .SetPrioritisationType(MainThreadTaskQueue::QueueTraits::
                                         PrioritisationType::kBestEffort))),
      memory_purge_manager_(memory_purge_task_queue_->CreateTaskRunner(
          TaskType::kMainThreadTaskQueueMemoryPurge)),
      delayed_update_policy_runner_(
          base::BindRepeating(&MainThreadSchedulerImpl::UpdatePolicy,
                              base::Unretained(this)),
          helper_.ControlMainThreadTaskQueue()->CreateTaskRunner(
              TaskType::kMainThreadTaskQueueControl)),
      main_thread_only_(this, helper_.GetClock(), helper_.NowTicks()),
      any_thread_(this),
      policy_may_need_update_(&any_thread_lock_) {
  helper_.AttachToCurrentThread();

  // Compositor task queue and default task queue should be managed by
  // WebThreadScheduler. Control task queue should not.
  task_runners_.emplace(helper_.DefaultMainThreadTaskQueue(), nullptr);

  back_forward_cache_ipc_tracking_task_runner_ =
      back_forward_cache_ipc_tracking_task_queue_->CreateTaskRunner(
          TaskType::kMainThreadTaskQueueIPCTracking);

  v8_task_queue_ = NewTaskQueue(MainThreadTaskQueue::QueueCreationParams(
      MainThreadTaskQueue::QueueType::kV8));
  v8_user_visible_task_queue_ = NewTaskQueue(
      MainThreadTaskQueue::QueueCreationParams(
          MainThreadTaskQueue::QueueType::kV8UserVisible)
          .SetPrioritisationType(
              MainThreadTaskQueue::QueueTraits::PrioritisationType::kLow)
          .SetCanBeDeferredForRendering(base::FeatureList::IsEnabled(
              features::kDeferRendererTasksAfterInput)));
  v8_best_effort_task_queue_ = NewTaskQueue(
      MainThreadTaskQueue::QueueCreationParams(
          MainThreadTaskQueue::QueueType::kV8BestEffort)
          .SetPrioritisationType(
              MainThreadTaskQueue::QueueTraits::PrioritisationType::kBestEffort)
          .SetCanBeDeferredForRendering(base::FeatureList::IsEnabled(
              features::kDeferRendererTasksAfterInput)));
  non_waking_task_queue_ =
      NewTaskQueue(MainThreadTaskQueue::QueueCreationParams(
                       MainThreadTaskQueue::QueueType::kNonWaking)
                       .SetNonWaking(true));

  v8_task_runner_ =
      v8_task_queue_->CreateTaskRunner(TaskType::kMainThreadTaskQueueV8);
  v8_user_visible_task_runner_ = v8_user_visible_task_queue_->CreateTaskRunner(
      TaskType::kMainThreadTaskQueueV8UserVisible);
  v8_best_effort_task_runner_ = v8_best_effort_task_queue_->CreateTaskRunner(
      TaskType::kMainThreadTaskQueueV8BestEffort);
  control_task_runner_ = helper_.ControlMainThreadTaskQueue()->CreateTaskRunner(
      TaskType::kMainThreadTaskQueueControl);
  non_waking_task_runner_ = non_waking_task_queue_->CreateTaskRunner(
      TaskType::kMainThreadTaskQueueNonWaking);

  // TaskQueueThrottler requires some task runners, then initialize
  // TaskQueueThrottler after task queues/runners are initialized.
  update_policy_closure_ = base::BindRepeating(
      &MainThreadSchedulerImpl::UpdatePolicy, weak_factory_.GetWeakPtr());
  end_renderer_hidden_idle_period_closure_.Reset(base::BindRepeating(
      &MainThreadSchedulerImpl::EndIdlePeriod, weak_factory_.GetWeakPtr()));

  TRACE_EVENT_OBJECT_CREATED_WITH_ID(
      TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"), "MainThreadScheduler",
      this);

  helper_.SetObserver(this);

  // Register a tracing state observer unless we're running in a test without a
  // task runner. Note that it's safe to remove a non-existent observer.
  if (base::SingleThreadTaskRunner::HasCurrentDefault()) {
    base::trace_event::TraceLog::GetInstance()->AddAsyncEnabledStateObserver(
        weak_factory_.GetWeakPtr());
  }

  internal::ProcessState::Get()->is_process_backgrounded =
      main_thread_only().renderer_backgrounded.get();

  main_thread_only().current_policy.find_in_page_priority =
      find_in_page_budget_pool_controller_->CurrentTaskPriority();

  // Explicitly set the priority of this queue since it is not managed by
  // the main thread scheduler.
  memory_purge_task_queue_->SetQueuePriority(
      ComputePriority(memory_purge_task_queue_.get()));
}

MainThreadSchedulerImpl::~MainThreadSchedulerImpl() {
  TRACE_EVENT_OBJECT_DELETED_WITH_ID(
      TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"), "MainThreadScheduler",
      this);
  // Ensure the renderer scheduler was shut down explicitly, because otherwise
  // we could end up having stale pointers to the Blink heap which has been
  // terminated by this point.
  CHECK(was_shutdown_);

  // These should be cleared during shutdown.
  CHECK(task_runners_.empty());
  CHECK(main_thread_only().detached_task_queues.empty());
  CHECK(!virtual_time_control_task_queue_);

  base::trace_event::TraceLog::GetInstance()->RemoveAsyncEnabledStateObserver(
      this);
}

// static
WebThreadScheduler& WebThreadScheduler::MainThreadScheduler() {
  auto* main_thread = Thread::MainThread();
  // Enforce that this is not called before the main thread is initialized.
  CHECK(main_thread && main_thread->Scheduler() &&
        main_thread->Scheduler()->ToMainThreadScheduler());
  auto* scheduler = main_thread->Scheduler()
                        ->ToMainThreadScheduler()
                        ->ToWebMainThreadScheduler();
  // `scheduler` can be null if it isn't a MainThreadSchedulerImpl, which can
  // happen in tests. Tests should use a real main thread scheduler if a
  // `WebThreadScheduler` is needed.
  CHECK(scheduler);
  return *scheduler;
}

MainThreadSchedulerImpl::MainThreadOnly::MainThreadOnly(
    MainThreadSchedulerImpl* main_thread_scheduler_impl,
    const base::TickClock* time_source,
    base::TimeTicks now)
    : idle_time_estimator(time_source,
                          kShortIdlePeriodDurationSampleCount,
                          kShortIdlePeriodDurationPercentile),
      current_use_case(UseCase::kNone,
                       "Scheduler.UseCase",
                       &main_thread_scheduler_impl->tracing_controller_,
                       UseCaseToString),
      renderer_pause_count(0,
                           "Scheduler.PauseCount",
                           &main_thread_scheduler_impl->tracing_controller_),
      rail_mode_for_tracing(current_policy.rail_mode,
                            "Scheduler.RAILMode",
                            &main_thread_scheduler_impl->tracing_controller_,
                            &AddRAILModeToProto),
      renderer_hidden(false,
                      "RendererVisibility",
                      &main_thread_scheduler_impl->tracing_controller_,
                      &AddHiddenToProto),
      renderer_backgrounded(kLaunchingProcessIsBackgrounded,
                            "RendererPriority",
                            &main_thread_scheduler_impl->tracing_controller_,
                            &AddBackgroundedToProto),
      blocking_input_expected_soon(
          false,
          "Scheduler.BlockingInputExpectedSoon",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString),
      in_idle_period_for_testing(
          false,
          "Scheduler.InIdlePeriod",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString),
      is_audio_playing(false,
                       "RendererAudioState",
                       &main_thread_scheduler_impl->tracing_controller_,
                       AudioPlayingStateToString),
      compositor_will_send_main_frame_not_expected(
          false,
          "Scheduler.CompositorWillSendMainFrameNotExpected",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString),
      has_navigated(false,
                    "Scheduler.HasNavigated",
                    &main_thread_scheduler_impl->tracing_controller_,
                    YesNoStateToString),
      pause_timers_for_webview(false,
                               "Scheduler.PauseTimersForWebview",
                               &main_thread_scheduler_impl->tracing_controller_,
                               YesNoStateToString),
      background_status_changed_at(now),
      metrics_helper(
          main_thread_scheduler_impl,
          main_thread_scheduler_impl->helper_.HasCPUTimingForEachTask(),
          now,
          renderer_backgrounded.get()),
      process_type(WebRendererProcessType::kRenderer,
                   "RendererProcessType",
                   &main_thread_scheduler_impl->tracing_controller_,
                   RendererProcessTypeToString),
      task_description_for_tracing(
          std::nullopt,
          "Scheduler.MainThreadTask",
          &main_thread_scheduler_impl->tracing_controller_,
          OptionalTaskDescriptionToString),
      task_priority_for_tracing(
          std::nullopt,
          "Scheduler.TaskPriority",
          &main_thread_scheduler_impl->tracing_controller_,
          OptionalTaskPriorityToString),
      main_thread_compositing_is_fast(false),
      compositor_priority(TaskPriority::kNormalPriority,
                          "Scheduler.CompositorPriority",
                          &main_thread_scheduler_impl->tracing_controller_,
                          TaskPriorityToString),
      main_frame_prioritization_state(
          RenderingPrioritizationState::kNone,
          "RenderingPrioritizationState",
          &main_thread_scheduler_impl->tracing_controller_,
          RenderingPrioritizationStateToString),
      last_frame_time(now),
      agent_group_schedulers(
          MakeGarbageCollected<
              HeapHashSet<WeakMember<AgentGroupSchedulerImpl>>>()) {}

MainThreadSchedulerImpl::MainThreadOnly::~MainThreadOnly() = default;

MainThreadSchedulerImpl::AnyThread::AnyThread(
    MainThreadSchedulerImpl* main_thread_scheduler_impl)
    : awaiting_touch_start_response(
          false,
          "Scheduler.AwaitingTouchstartResponse",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString),
      awaiting_discrete_input_response(
          false,
          "Scheduler.AwaitingDiscreteInputResponse",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString),
      in_idle_period(false,
                     "Scheduler.InIdlePeriod",
                     &main_thread_scheduler_impl->tracing_controller_,
                     YesNoStateToString),
      begin_main_frame_on_critical_path(
          false,
          "Scheduler.BeginMainFrameOnCriticalPath",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString),
      last_gesture_was_compositor_driven(
          false,
          "Scheduler.LastGestureWasCompositorDriven",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString),
      default_gesture_prevented(
          true,
          "Scheduler.DefaultGesturePrevented",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString),
      have_seen_a_blocking_gesture(
          false,
          "Scheduler.HaveSeenBlockingGesture",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString),
      waiting_for_any_main_frame_contentful_paint(
          false,
          "Scheduler.WaitingForMainFrameContentfulPaint",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString),
      waiting_for_any_main_frame_meaningful_paint(
          false,
          "Scheduler.WaitingForMeaningfulPaint",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString),
      is_any_main_frame_loading(
          false,
          "Scheduler.IsAnyMainFrameLoading",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString),
      have_seen_input_since_navigation(
          false,
          "Scheduler.HaveSeenInputSinceNavigation",
          &main_thread_scheduler_impl->tracing_controller_,
          YesNoStateToString) {}

MainThreadSchedulerImpl::SchedulingSettings::SchedulingSettings() {
  mbi_override_task_runner_handle =
      base::FeatureList::IsEnabled(kMbiOverrideTaskRunnerHandle);

  compositor_gesture_rendering_starvation_threshold =
      GetThreadedScrollRenderingStarvationThreshold();

  if (base::FeatureList::IsEnabled(features::kDeferRendererTasksAfterInput)) {
    discrete_input_task_deferral_policy =
        features::kTaskDeferralPolicyParam.Get();
  }

  prioritize_compositing_after_delay_pre_fcp =
      base::Milliseconds(base::GetFieldTrialParamByFeatureAsInt(
          kPrioritizeCompositingAfterDelayTrials, "PreFCP",
          kDefaultPrioritizeCompositingAfterDelayMs));
  prioritize_compositing_after_delay_post_fcp =
      base::Milliseconds(base::GetFieldTrialParamByFeatureAsInt(
          kPrioritizeCompositingAfterDelayTrials, "PostFCP",
          kDefaultPrioritizeCompositingAfterDelayMs));
}

MainThreadSchedulerImpl::AnyThread::~AnyThread() = default;

MainThreadSchedulerImpl::CompositorThreadOnly::CompositorThreadOnly()
    : last_input_type(blink::WebInputEvent::Type::kUndefined) {}

MainThreadSchedulerImpl::CompositorThreadOnly::~CompositorThreadOnly() =
    default;

MainThreadSchedulerImpl::RendererPauseHandleImpl::RendererPauseHandleImpl(
    MainThreadSchedulerImpl* scheduler)
    : scheduler_(scheduler) {
  scheduler_->PauseRendererImpl();
}

MainThreadSchedulerImpl::RendererPauseHandleImpl::~RendererPauseHandleImpl() {
  scheduler_->ResumeRendererImpl();
}

void MainThreadSchedulerImpl::ShutdownAllQueues() {
  while (!task_runners_.empty()) {
    scoped_refptr<MainThreadTaskQueue> queue = task_runners_.begin()->first;
    queue->ShutdownTaskQueue();
  }
  while (!main_thread_only().detached_task_queues.empty()) {
    scoped_refptr<MainThreadTaskQueue> queue =
        *main_thread_only().detached_task_queues.begin();
    queue->ShutdownTaskQueue();
  }
  if (virtual_time_control_task_queue_) {
    virtual_time_control_task_queue_->ShutdownTaskQueue();
    virtual_time_control_task_queue_ = nullptr;
  }
}

bool MainThreadSchedulerImpl::
    IsAnyOrdinaryMainFrameWaitingForFirstMeaningfulPaint() const {
  for (const PageSchedulerImpl* ps : main_thread_only().page_schedulers) {
    if (ps->IsOrdinary() && ps->IsWaitingForMainFrameMeaningfulPaint())
      return true;
  }
  return false;
}

bool MainThreadSchedulerImpl::IsAnyOrdinaryMainFrameLoading() const {
  for (const PageSchedulerImpl* ps : main_thread_only().page_schedulers) {
    if (ps->IsOrdinary() && ps->IsMainFrameLoading()) {
      return true;
    }
  }
  return false;
}

bool MainThreadSchedulerImpl::
    IsAnyOrdinaryMainFrameWaitingForFirstContentfulPaint() const {
  for (const PageSchedulerImpl* ps : main_thread_only().page_schedulers) {
    if (ps->IsOrdinary() && ps->IsWaitingForMainFrameContentfulPaint())
      return true;
  }
  return false;
}

void MainThreadSchedulerImpl::Shutdown() {
  if (was_shutdown_)
    return;
  base::TimeTicks now = NowTicks();
  main_thread_only().metrics_helper.OnRendererShutdown(now);
  // This needs to be after metrics helper, to prevent it being confused by
  // potential virtual time domain shutdown!
  ThreadSchedulerBase::Shutdown();

  ShutdownAllQueues();

  // Shut down |helper_| first, so that the ForceUpdatePolicy() call
  // from |idle_helper_| early-outs and doesn't do anything.
  helper_.Shutdown();
  idle_helper_.Shutdown();
  sequence_manager_ = nullptr;
  owned_sequence_manager_.reset();
  main_thread_only().rail_mode_observers.Clear();
  was_shutdown_ = true;
}

std::unique_ptr<MainThread> MainThreadSchedulerImpl::CreateMainThread() {
  return std::make_unique<MainThreadImpl>(this);
}

scoped_refptr<WidgetScheduler>
MainThreadSchedulerImpl::CreateWidgetScheduler() {
  return base::MakeRefCounted<WidgetSchedulerImpl>(
      this, &render_widget_scheduler_signals_);
}

scoped_refptr<base::SingleThreadTaskRunner>
MainThreadSchedulerImpl::ControlTaskRunner() {
  return control_task_runner_;
}

scoped_refptr<base::SingleThreadTaskRunner>
MainThreadSchedulerImpl::DefaultTaskRunner() {
  return helper_.DefaultTaskRunner();
}

scoped_refptr<SingleThreadIdleTaskRunner>
MainThreadSchedulerImpl::IdleTaskRunner() {
  return idle_helper_.IdleTaskRunner();
}

scoped_refptr<base::SingleThreadTaskRunner>
MainThreadSchedulerImpl::DeprecatedDefaultTaskRunner() {
  return helper_.DeprecatedDefaultTaskRunner();
}

scoped_refptr<MainThreadTaskQueue> MainThreadSchedulerImpl::V8TaskQueue() {
  helper_.CheckOnValidThread();
  return v8_task_queue_;
}

scoped_refptr<base::SingleThreadTaskRunner>
MainThreadSchedulerImpl::CleanupTaskRunner() {
  return DefaultTaskRunner();
}

scoped_refptr<MainThreadTaskQueue> MainThreadSchedulerImpl::ControlTaskQueue() {
  return helper_.ControlMainThreadTaskQueue();
}

scoped_refptr<MainThreadTaskQueue> MainThreadSchedulerImpl::DefaultTaskQueue() {
  return helper_.DefaultMainThreadTaskQueue();
}

scoped_refptr<MainThreadTaskQueue> MainThreadSchedulerImpl::NewTaskQueue(
    const MainThreadTaskQueue::QueueCreationParams& params) {
  helper_.CheckOnValidThread();
  scoped_refptr<MainThreadTaskQueue> task_queue(helper_.NewTaskQueue(params));

  std::unique_ptr<TaskQueue::QueueEnabledVoter> voter;
  if (params.queue_traits.can_be_deferred ||
      params.queue_traits.can_be_deferred_for_rendering ||
      params.queue_traits.can_be_paused || params.queue_traits.can_be_frozen) {
    voter = task_queue->CreateQueueEnabledVoter();
  }

  if (task_queue->GetPrioritisationType() ==
      MainThreadTaskQueue::QueueTraits::PrioritisationType::kCompositor) {
    DCHECK(!voter);
    voter = task_queue->CreateQueueEnabledVoter();
    main_thread_only().idle_time_estimator.AddCompositorTaskQueue(task_queue);
  }

  auto insert_result = task_runners_.emplace(task_queue, std::move(voter));

  UpdateTaskQueueState(task_queue.get(), insert_result.first->second.get(),
                       Policy(), main_thread_only().current_policy,
                       /*should_update_priority=*/true);

  // If this is a timer queue, and virtual time is enabled and paused, it should
  // be suspended by adding a fence to prevent immediate tasks from running when
  // they're not supposed to.
  if (!VirtualTimeAllowedToAdvance() &&
      !task_queue->CanRunWhenVirtualTimePaused()) {
    task_queue->GetTaskQueue()->InsertFence(
        TaskQueue::InsertFencePosition::kNow);
  }

  return task_queue;
}

bool MainThreadSchedulerImpl::IsIpcTrackingEnabledForAllPages() {
  for (auto* scheduler : main_thread_only().page_schedulers) {
    if (!(scheduler->IsInBackForwardCache() &&
          scheduler->has_ipc_detection_enabled())) {
      return false;
    }
  }
  return true;
}

void MainThreadSchedulerImpl::UpdateIpcTracking() {
  bool should_track = IsIpcTrackingEnabledForAllPages();
  if (should_track == has_ipc_callback_set_)
    return;

  has_ipc_callback_set_ = should_track;
  if (has_ipc_callback_set_) {
    SetOnIPCTaskPostedWhileInBackForwardCacheIfNeeded();
  } else {
    DetachOnIPCTaskPostedWhileInBackForwardCacheHandler();
  }
}

void MainThreadSchedulerImpl::
    SetOnIPCTaskPostedWhileInBackForwardCacheIfNeeded() {
  has_ipc_callback_set_ = true;
  helper_.DefaultMainThreadTaskQueue()->SetOnIPCTaskPosted(base::BindRepeating(
      [](scoped_refptr<base::SingleThreadTaskRunner> task_runner,
         base::WeakPtr<MainThreadSchedulerImpl> main_thread_scheduler,
         const base::sequence_manager::Task& task) {
        // Only log IPC tasks. IPC tasks are only logged currently as IPC
        // hash can be mapped back to a function name, and IPC tasks may
        // potentially post sensitive information.
        if (!task.ipc_hash && !task.ipc_interface_name) {
          return;
        }
        base::ScopedDeferTaskPosting::PostOrDefer(
            task_runner, FROM_HERE,
            base::BindOnce(&MainThreadSchedulerImpl::
                               OnIPCTaskPostedWhileInAllPagesBackForwardCache,
                           main_thread_scheduler, task.ipc_hash,
                           task.ipc_interface_name),
            base::TimeDelta());
      },
      back_forward_cache_ipc_tracking_task_runner_, GetWeakPtr()));
}

void MainThreadSchedulerImpl::OnIPCTaskPostedWhileInAllPagesBackForwardCache(
    uint32_t ipc_hash,
    const char* ipc_interface_name) {
  // As this is a multi-threaded environment, we need to check that all page
  // schedulers are in the cache before logging. There may be instances where
  // the scheduler has been unfrozen prior to the IPC tracking handler being
  // reset.
  if (!IsIpcTrackingEnabledForAllPages()) {
    return;
  }

  // IPC tasks may have an IPC interface name in addition to, or instead of an
  // IPC hash. IPC hash is known from the mojo Accept method. When IPC hash is
  // 0, then the IPC hash must be calculated form the IPC interface name
  // instead.
  if (!ipc_hash) {
    // base::HashMetricName produces a uint64; however, the MD5 hash calculation
    // for an IPC interface name is always calculated as uint32; the IPC hash on
    // a task is also a uint32. The calculation here is meant to mimic the
    // calculation used in base::MD5Hash32Constexpr.
    ipc_hash = static_cast<uint32_t>(
        base::TaskAnnotator::ScopedSetIpcHash::MD5HashMetricName(
            ipc_interface_name));
  }

  base::UmaHistogramSparse(
      "BackForwardCache.Experimental.UnexpectedIPCMessagePostedToCachedFrame."
      "MethodHash",
      static_cast<int32_t>(ipc_hash));
}

void MainThreadSchedulerImpl::
    DetachOnIPCTaskPostedWhileInBackForwardCacheHandler() {
  has_ipc_callback_set_ = false;
  helper_.DefaultMainThreadTaskQueue()
      ->DetachOnIPCTaskPostedWhileInBackForwardCache();
}

void MainThreadSchedulerImpl::ShutdownEmptyDetachedTaskQueues() {
  if (main_thread_only().detached_task_queues.empty()) {
    return;
  }
  WTF::Vector<scoped_refptr<MainThreadTaskQueue>> queues_to_delete;
  for (auto& queue : main_thread_only().detached_task_queues) {
    if (queue->IsEmpty()) {
      queues_to_delete.push_back(queue);
    }
  }
  for (auto& queue : queues_to_delete) {
    queue->ShutdownTaskQueue();
    // The task queue is removed in `OnShutdownTaskQueue()`.
    CHECK(!main_thread_only().detached_task_queues.Contains(queue));
  }
}

scoped_refptr<MainThreadTaskQueue>
MainThreadSchedulerImpl::NewThrottleableTaskQueueForTest(
    FrameSchedulerImpl* frame_scheduler) {
  return NewTaskQueue(MainThreadTaskQueue::QueueCreationParams(
                          MainThreadTaskQueue::QueueType::kFrameThrottleable)
                          .SetCanBePaused(true)
                          .SetCanBeFrozen(true)
                          .SetCanBeDeferred(true)
                          .SetCanBeThrottled(true)
                          .SetFrameScheduler(frame_scheduler)
                          .SetCanRunWhenVirtualTimePaused(false));
}

void MainThreadSchedulerImpl::OnShutdownTaskQueue(
    const scoped_refptr<MainThreadTaskQueue>& task_queue) {
  if (was_shutdown_) {
    return;
  }
  task_queue.get()->DetachOnIPCTaskPostedWhileInBackForwardCache();
  task_runners_.erase(task_queue.get());
  main_thread_only().detached_task_queues.erase(task_queue.get());
}

void MainThreadSchedulerImpl::OnDetachTaskQueue(
    MainThreadTaskQueue& task_queue) {
  if (was_shutdown_) {
    return;
  }
  // `UpdatePolicy()` is not set up to handle detached frame scheduler queues.
  // TODO(crbug.com/1143007): consider keeping FrameScheduler alive until all
  // tasks have finished running.
  task_runners_.erase(&task_queue);

  // Don't immediately shut down the task queue even if it's empty. Tasks can
  // still be queued before this task ends, which some parts of blink depend on.
  main_thread_only().detached_task_queues.insert(
      base::WrapRefCounted(&task_queue));
}

void MainThreadSchedulerImpl::AddTaskObserver(
    base::TaskObserver* task_observer) {
  helper_.AddTaskObserver(task_observer);
}

void MainThreadSchedulerImpl::RemoveTaskObserver(
    base::TaskObserver* task_observer) {
  helper_.RemoveTaskObserver(task_observer);
}

void MainThreadSchedulerImpl::WillBeginFrame(const viz::BeginFrameArgs& args) {
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "MainThreadSchedulerImpl::WillBeginFrame", "args",
               args.AsValue());
  helper_.CheckOnValidThread();
  if (helper_.IsShutdown())
    return;

  EndIdlePeriod();
  main_thread_only().estimated_next_frame_begin =
      args.frame_time + args.interval;
  main_thread_only().compositor_frame_interval = args.interval;
  {
    base::AutoLock lock(any_thread_lock_);
    any_thread().begin_main_frame_on_critical_path = args.on_critical_path;
  }
  main_thread_only().is_current_task_main_frame = true;
}

void MainThreadSchedulerImpl::DidCommitFrameToCompositor() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "MainThreadSchedulerImpl::DidCommitFrameToCompositor");
  helper_.CheckOnValidThread();
  if (helper_.IsShutdown())
    return;

  base::TimeTicks now(helper_.NowTicks());
  if (now < main_thread_only().estimated_next_frame_begin) {
    // TODO(rmcilroy): Consider reducing the idle period based on the runtime of
    // the next pending delayed tasks (as currently done in for long idle times)
    idle_helper_.StartIdlePeriod(
        IdleHelper::IdlePeriodState::kInShortIdlePeriod, now,
        main_thread_only().estimated_next_frame_begin);
  }

  main_thread_only().idle_time_estimator.DidCommitFrameToCompositor();
}

void MainThreadSchedulerImpl::BeginFrameNotExpectedSoon() {
  // TODO(crbug/1068426): Should this call |UpdatePolicy|?
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "MainThreadSchedulerImpl::BeginFrameNotExpectedSoon");
  helper_.CheckOnValidThread();
  if (helper_.IsShutdown())
    return;

  idle_helper_.EnableLongIdlePeriod();
  {
    base::AutoLock lock(any_thread_lock_);
    any_thread().begin_main_frame_on_critical_path = false;
  }
}

void MainThreadSchedulerImpl::BeginMainFrameNotExpectedUntil(
    base::TimeTicks time) {
  helper_.CheckOnValidThread();
  if (helper_.IsShutdown())
    return;

  base::TimeTicks now(helper_.NowTicks());
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "MainThreadSchedulerImpl::BeginMainFrameNotExpectedUntil",
               "time_remaining", (time - now).InMillisecondsF());

  if (now < time) {
    // End any previous idle period.
    EndIdlePeriod();

    // TODO(rmcilroy): Consider reducing the idle period based on the runtime of
    // the next pending delayed tasks (as currently done in for long idle times)
    idle_helper_.StartIdlePeriod(
        IdleHelper::IdlePeriodState::kInShortIdlePeriod, now, time);
  }
}

void MainThreadSchedulerImpl::SetAllRenderWidgetsHidden(bool hidden) {
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "MainThreadSchedulerImpl::SetAllRenderWidgetsHidden", "hidden",
               hidden);

  helper_.CheckOnValidThread();

  if (helper_.IsShutdown() ||
      main_thread_only().renderer_hidden.get() == hidden) {
    return;
  }

  end_renderer_hidden_idle_period_closure_.Cancel();

  if (hidden) {
    idle_helper_.EnableLongIdlePeriod();

    // Ensure that we stop running idle tasks after a few seconds of being
    // hidden.
    base::TimeDelta end_idle_when_hidden_delay =
        base::Milliseconds(kEndIdleWhenHiddenDelayMillis);
    control_task_queue_->GetTaskRunnerWithDefaultTaskType()->PostDelayedTask(
        FROM_HERE, end_renderer_hidden_idle_period_closure_.GetCallback(),
        end_idle_when_hidden_delay);
    main_thread_only().renderer_hidden = true;
  } else {
    main_thread_only().renderer_hidden = false;
    EndIdlePeriod();
  }

  // TODO(alexclarke): Should we update policy here?
  CreateTraceEventObjectSnapshot();
}

void MainThreadSchedulerImpl::SetRendererHidden(bool hidden) {
  if (hidden) {
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
                 "MainThreadSchedulerImpl::OnRendererHidden");
    main_thread_only().renderer_hidden_metadata.emplace(
        "MainThreadSchedulerImpl.RendererHidden", /* is_hidden */ 1,
        base::SampleMetadataScope::kProcess);
  } else {
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
                 "MainThreadSchedulerImpl::OnRendererVisible");
    main_thread_only().renderer_hidden_metadata.reset();
  }
  helper_.CheckOnValidThread();
  main_thread_only().renderer_hidden = hidden;
}

void MainThreadSchedulerImpl::SetRendererBackgrounded(bool backgrounded) {
  helper_.CheckOnValidThread();

  if (helper_.IsShutdown() ||
      main_thread_only().renderer_backgrounded.get() == backgrounded)
    return;
  if (backgrounded) {
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
                 "MainThreadSchedulerImpl::OnRendererBackgrounded");
  } else {
    TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
                 "MainThreadSchedulerImpl::OnRendererForegrounded");
  }

  main_thread_only().renderer_backgrounded = backgrounded;
  internal::ProcessState::Get()->is_process_backgrounded = backgrounded;

  main_thread_only().background_status_changed_at = NowTicks();

  UpdatePolicy();

  base::TimeTicks now = NowTicks();
  if (backgrounded) {
    main_thread_only().metrics_helper.OnRendererBackgrounded(now);
  } else {
    main_thread_only().metrics_helper.OnRendererForegrounded(now);
  }

  ParkableStringManager::Instance().SetRendererBackgrounded(backgrounded);
  memory_purge_manager_.SetRendererBackgrounded(backgrounded);
}

void MainThreadSchedulerImpl::SetRendererBackgroundedForTesting(
    bool backgrounded) {
  SetRendererBackgrounded(backgrounded);
}

#if BUILDFLAG(IS_ANDROID)
void MainThreadSchedulerImpl::PauseTimersForAndroidWebView() {
  main_thread_only().pause_timers_for_webview = true;
  UpdatePolicy();
}

void MainThreadSchedulerImpl::ResumeTimersForAndroidWebView() {
  main_thread_only().pause_timers_for_webview = false;
  UpdatePolicy();
}
#endif

void MainThreadSchedulerImpl::OnAudioStateChanged() {
  bool is_audio_playing = false;
  for (PageSchedulerImpl* page_scheduler : main_thread_only().page_schedulers) {
    is_audio_playing = is_audio_playing || page_scheduler->IsAudioPlaying();
  }

  if (is_audio_playing == main_thread_only().is_audio_playing)
    return;

  main_thread_only().is_audio_playing = is_audio_playing;
}

std::unique_ptr<MainThreadScheduler::RendererPauseHandle>
MainThreadSchedulerImpl::PauseScheduler() {
  return std::make_unique<RendererPauseHandleImpl>(this);
}

void MainThreadSchedulerImpl::PauseRendererImpl() {
  helper_.CheckOnValidThread();
  if (helper_.IsShutdown())
    return;

  ++main_thread_only().renderer_pause_count;
  UpdatePolicy();
}

void MainThreadSchedulerImpl::ResumeRendererImpl() {
  helper_.CheckOnValidThread();
  if (helper_.IsShutdown())
    return;
  --main_thread_only().renderer_pause_count;
  DCHECK_GE(main_thread_only().renderer_pause_count.value(), 0);
  UpdatePolicy();
}

void MainThreadSchedulerImpl::EndIdlePeriod() {
  if (main_thread_only().in_idle_period_for_testing)
    return;
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "MainThreadSchedulerImpl::EndIdlePeriod");
  helper_.CheckOnValidThread();
  idle_helper_.EndIdlePeriod();
}

void MainThreadSchedulerImpl::EndIdlePeriodForTesting(
    base::TimeTicks time_remaining) {
  main_thread_only().in_idle_period_for_testing = false;
  EndIdlePeriod();
}

bool MainThreadSchedulerImpl::PolicyNeedsUpdateForTesting() {
  return policy_may_need_update_.IsSet();
}

void MainThreadSchedulerImpl::PerformMicrotaskCheckpoint() {
  TRACE_EVENT("toplevel", "BlinkScheduler_PerformMicrotaskCheckpoint");

  // This will fallback to execute the microtask checkpoint for the
  // default EventLoop for the isolate.
  if (isolate())
    EventLoop::PerformIsolateGlobalMicrotasksCheckpoint(isolate());

  // Perform a microtask checkpoint for each AgentSchedulingGroup. This
  // really should only be the ones that are not frozen but AgentSchedulingGroup
  // does not have that concept yet.
  // TODO(dtapuska): Move this to EndAgentGroupSchedulerScope so that we only
  // run the microtask checkpoint for a given AgentGroupScheduler.
  //
  // This code is performance sensitive so we do not wish to allocate
  // memory, use an inline vector of 10. 10 is an appropriate size as typically
  // we only see a few AgentGroupSchedulers (this will change in the future).
  // We use an inline HeapVector here because cloning to a HeapHashSet was
  // causing floating garbage even with ClearCollectionScope. See
  // crbug.com/1376394.
  HeapVector<Member<AgentGroupSchedulerImpl>, 10> schedulers;
  for (AgentGroupSchedulerImpl* scheduler :
       *main_thread_only().agent_group_schedulers) {
    schedulers.push_back(scheduler);
  }
  for (AgentGroupSchedulerImpl* agent_group_scheduler : schedulers) {
    DCHECK(main_thread_only().agent_group_schedulers->Contains(
        agent_group_scheduler));
    agent_group_scheduler->PerformMicrotaskCheckpoint();
  }
}

// static
bool MainThreadSchedulerImpl::ShouldPrioritizeInputEvent(
    const blink::WebInputEvent& web_input_event) {
  // We regard MouseMove events with the left mouse button down as a signal
  // that the user is doing something requiring a smooth frame rate.
  if ((web_input_event.GetType() == blink::WebInputEvent::Type::kMouseDown ||
       web_input_event.GetType() == blink::WebInputEvent::Type::kMouseMove) &&
      (web_input_event.GetModifiers() &
       blink::WebInputEvent::kLeftButtonDown)) {
    return true;
  }
  // Ignore all other mouse events because they probably don't signal user
  // interaction needing a smooth framerate. NOTE isMouseEventType returns false
  // for mouse wheel events, hence we regard them as user input.
  // Ignore keyboard events because it doesn't really make sense to enter
  // compositor priority for them.
  if (blink::WebInputEvent::IsMouseEventType(web_input_event.GetType()) ||
      blink::WebInputEvent::IsKeyboardEventType(web_input_event.GetType())) {
    return false;
  }
  return true;
}

void MainThreadSchedulerImpl::DidHandleInputEventOnCompositorThread(
    const blink::WebInputEvent& web_input_event,
    WidgetScheduler::InputEventState event_state) {
  TRACE_EVENT0(
      TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
      "MainThreadSchedulerImpl::DidHandleInputEventOnCompositorThread");
  if (!ShouldPrioritizeInputEvent(web_input_event))
    return;

  UpdateForInputEventOnCompositorThread(web_input_event, event_state);
}

void MainThreadSchedulerImpl::UpdateForInputEventOnCompositorThread(
    const blink::WebInputEvent& web_input_event,
    WidgetScheduler::InputEventState input_event_state) {
  base::AutoLock lock(any_thread_lock_);
  base::TimeTicks now = helper_.NowTicks();

  blink::WebInputEvent::Type type = web_input_event.GetType();

  // TODO(alexclarke): Move WebInputEventTraits where we can access it from here
  // and record the name rather than the integer representation.
  TRACE_EVENT2(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "MainThreadSchedulerImpl::UpdateForInputEventOnCompositorThread",
               "type", static_cast<int>(type), "input_event_state",
               InputEventStateToString(input_event_state));

  base::TimeDelta unused_policy_duration;
  UseCase previous_use_case =
      ComputeCurrentUseCase(now, &unused_policy_duration);
  bool was_awaiting_touch_start_response =
      any_thread().awaiting_touch_start_response;

  any_thread().user_model.DidStartProcessingInputEvent(type, now);
  any_thread().have_seen_input_since_navigation = true;

  if (input_event_state ==
      WidgetScheduler::InputEventState::EVENT_CONSUMED_BY_COMPOSITOR)
    any_thread().user_model.DidFinishProcessingInputEvent(now);

  switch (type) {
    case blink::WebInputEvent::Type::kTouchStart:
      any_thread().awaiting_touch_start_response = true;
      // This is just a fail-safe to reset the state of
      // |last_gesture_was_compositor_driven| to the default. We don't know
      // yet where the gesture will run.
      any_thread().last_gesture_was_compositor_driven = false;
      // Assume the default gesture is prevented until we see evidence
      // otherwise.
      any_thread().default_gesture_prevented = true;

      if (IsBlockingEvent(web_input_event))
        any_thread().have_seen_a_blocking_gesture = true;
      break;
    case blink::WebInputEvent::Type::kTouchMove:
      // Observation of consecutive touchmoves is a strong signal that the
      // page is consuming the touch sequence, in which case touchstart
      // response prioritization is no longer necessary. Otherwise, the
      // initial touchmove should preserve the touchstart response pending
      // state.
      if (any_thread().awaiting_touch_start_response &&
          GetCompositorThreadOnly().last_input_type ==
              blink::WebInputEvent::Type::kTouchMove) {
        any_thread().awaiting_touch_start_response = false;
      }
      break;

    case blink::WebInputEvent::Type::kGesturePinchUpdate:
    case blink::WebInputEvent::Type::kGestureScrollUpdate:
      // If we see events for an established gesture, we can lock it to the
      // appropriate thread as the gesture can no longer be cancelled.
      any_thread().last_gesture_was_compositor_driven =
          input_event_state ==
          WidgetScheduler::InputEventState::EVENT_CONSUMED_BY_COMPOSITOR;
      any_thread().awaiting_touch_start_response = false;
      any_thread().default_gesture_prevented = false;
      break;

    case blink::WebInputEvent::Type::kGestureFlingCancel:
    case blink::WebInputEvent::Type::kGestureTapDown:
    case blink::WebInputEvent::Type::kGestureShowPress:
    case blink::WebInputEvent::Type::kGestureScrollEnd:
      // With no observable effect, these meta events do not indicate a
      // meaningful touchstart response and should not impact task priority.
      break;

    case blink::WebInputEvent::Type::kMouseDown:
      // Reset tracking state at the start of a new mouse drag gesture.
      any_thread().last_gesture_was_compositor_driven = false;
      any_thread().default_gesture_prevented = true;
      break;

    case blink::WebInputEvent::Type::kMouseMove:
      // Consider mouse movement with the left button held down (see
      // ShouldPrioritizeInputEvent) similarly to a touch gesture.
      any_thread().last_gesture_was_compositor_driven =
          input_event_state ==
          WidgetScheduler::InputEventState::EVENT_CONSUMED_BY_COMPOSITOR;
      any_thread().awaiting_touch_start_response = false;
      break;

    case blink::WebInputEvent::Type::kMouseWheel:
      any_thread().last_gesture_was_compositor_driven =
          input_event_state ==
          WidgetScheduler::InputEventState::EVENT_CONSUMED_BY_COMPOSITOR;
      any_thread().awaiting_touch_start_response = false;
      // If the event was sent to the main thread, assume the default gesture is
      // prevented until we see evidence otherwise.
      any_thread().default_gesture_prevented =
          !any_thread().last_gesture_was_compositor_driven;
      if (IsBlockingEvent(web_input_event))
        any_thread().have_seen_a_blocking_gesture = true;
      break;
    case blink::WebInputEvent::Type::kUndefined:
      break;

    default:
      any_thread().awaiting_touch_start_response = false;
      break;
  }

  // Avoid unnecessary policy updates if the use case did not change.
  UseCase use_case = ComputeCurrentUseCase(now, &unused_policy_duration);

  if (use_case != previous_use_case ||
      was_awaiting_touch_start_response !=
          any_thread().awaiting_touch_start_response) {
    EnsureUrgentPolicyUpdatePostedOnMainThread(FROM_HERE);
  }
  GetCompositorThreadOnly().last_input_type = type;
}

void MainThreadSchedulerImpl::WillPostInputEventToMainThread(
    WebInputEvent::Type web_input_event_type,
    const WebInputEventAttribution& web_input_event_attribution) {
  base::AutoLock lock(any_thread_lock_);
  any_thread().pending_input_monitor.OnEnqueue(web_input_event_type,
                                               web_input_event_attribution);
}

void MainThreadSchedulerImpl::WillHandleInputEventOnMainThread(
    WebInputEvent::Type web_input_event_type,
    const WebInputEventAttribution& web_input_event_attribution) {
  helper_.CheckOnValidThread();

  base::AutoLock lock(any_thread_lock_);
  any_thread().pending_input_monitor.OnDequeue(web_input_event_type,
                                               web_input_event_attribution);
}

void MainThreadSchedulerImpl::DidHandleInputEventOnMainThread(
    const WebInputEvent& web_input_event,
    WebInputEventResult result,
    bool frame_requested) {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "MainThreadSchedulerImpl::DidHandleInputEventOnMainThread");
  helper_.CheckOnValidThread();
  if (ShouldPrioritizeInputEvent(web_input_event)) {
    base::AutoLock lock(any_thread_lock_);
    any_thread().user_model.DidFinishProcessingInputEvent(helper_.NowTicks());

    // If we were waiting for a touchstart response and the main thread has
    // prevented the default gesture, consider the gesture established. This
    // ensures single-event gestures such as button presses are promptly
    // detected.
    if (any_thread().awaiting_touch_start_response &&
        result == WebInputEventResult::kHandledApplication) {
      any_thread().awaiting_touch_start_response = false;
      any_thread().default_gesture_prevented = true;
      UpdatePolicyLocked(UpdateType::kMayEarlyOutIfPolicyUnchanged);
    }
  }

  bool is_discrete =
      base::FeatureList::IsEnabled(
          features::kBlinkSchedulerDiscreteInputMatchesResponsivenessMetrics)
          ? WebInputEvent::IsWebInteractionEvent(web_input_event.GetType())
          : !PendingUserInput::IsContinuousEventType(web_input_event.GetType());
  if (is_discrete) {
    main_thread_only().is_current_task_discrete_input = true;
    main_thread_only().is_frame_requested_after_discrete_input =
        frame_requested;
  }
}

bool MainThreadSchedulerImpl::ShouldYieldForHighPriorityWork() {
  helper_.CheckOnValidThread();
  if (helper_.IsShutdown())
    return false;

  MaybeUpdatePolicy();
  // We only yield if there's a urgent task to be run now, or we are expecting
  // one soon (touch start).
  // Note: even though the control queue has the highest priority we don't yield
  // for it since these tasks are not user-provided work and they are only
  // intended to run before the next task, not interrupt the tasks.
  switch (main_thread_only().current_use_case) {
    case UseCase::kCompositorGesture:
    case UseCase::kNone:
      return main_thread_only().blocking_input_expected_soon;

    case UseCase::kMainThreadGesture:
    case UseCase::kMainThreadCustomInputHandling:
    case UseCase::kSynchronizedGesture:
      for (const auto& pair : task_runners_) {
        if (pair.first->GetPrioritisationType() ==
                MainThreadTaskQueue::QueueTraits::PrioritisationType::
                    kCompositor &&
            pair.first->HasTaskToRunImmediatelyOrReadyDelayedTask())
          return true;
      }
      return main_thread_only().blocking_input_expected_soon;

    case UseCase::kTouchstart:
      return true;

    case UseCase::kEarlyLoading:
    case UseCase::kLoading:
    case UseCase::kDiscreteInputResponse:
      return false;
  }
}

base::TimeTicks MainThreadSchedulerImpl::CurrentIdleTaskDeadlineForTesting()
    const {
  return idle_helper_.CurrentIdleTaskDeadline();
}

void MainThreadSchedulerImpl::StartIdlePeriodForTesting() {
  main_thread_only().in_idle_period_for_testing = true;
  IdleTaskRunner()->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&MainThreadSchedulerImpl::EndIdlePeriodForTesting,
                     weak_factory_.GetWeakPtr()));
  idle_helper_.EnableLongIdlePeriod();
}

void MainThreadSchedulerImpl::MaybeUpdatePolicy() {
  helper_.CheckOnValidThread();
  if (policy_may_need_update_.IsSet()) {
    UpdatePolicy();
  }
}

void MainThreadSchedulerImpl::EnsureUrgentPolicyUpdatePostedOnMainThread(
    const base::Location& from_here) {
  // TODO(scheduler-dev): Check that this method isn't called from the main
  // thread.
  any_thread_lock_.AssertAcquired();
  if (!policy_may_need_update_.IsSet()) {
    policy_may_need_update_.SetWhileLocked(true);
    control_task_queue_->GetTaskRunnerWithDefaultTaskType()->PostTask(
        from_here, update_policy_closure_);
  }
}

void MainThreadSchedulerImpl::UpdatePolicy() {
  base::AutoLock lock(any_thread_lock_);
  UpdatePolicyLocked(UpdateType::kMayEarlyOutIfPolicyUnchanged);
}

void MainThreadSchedulerImpl::ForceUpdatePolicy() {
  base::AutoLock lock(any_thread_lock_);
  UpdatePolicyLocked(UpdateType::kForceUpdate);
}

void MainThreadSchedulerImpl::UpdatePolicyLocked(UpdateType update_type) {
  helper_.CheckOnValidThread();
  any_thread_lock_.AssertAcquired();
  if (helper_.IsShutdown())
    return;

  base::TimeTicks now = helper_.NowTicks();
  policy_may_need_update_.SetWhileLocked(false);

  base::TimeDelta expected_use_case_duration;
  main_thread_only().current_use_case =
      ComputeCurrentUseCase(now, &expected_use_case_duration);

  base::TimeDelta gesture_expected_flag_valid_for_duration;

  main_thread_only().blocking_input_expected_soon = false;
  if (any_thread().have_seen_a_blocking_gesture) {
    main_thread_only().blocking_input_expected_soon =
        any_thread().user_model.IsGestureExpectedSoon(
            now, &gesture_expected_flag_valid_for_duration);
  }

  // The |new_policy_duration| is the minimum of |expected_use_case_duration|
  // and |gesture_expected_flag_valid_for_duration| unless one is zero in
  // which case we choose the other.
  base::TimeDelta new_policy_duration = expected_use_case_duration;
  if (new_policy_duration.is_zero() ||
      (gesture_expected_flag_valid_for_duration.is_positive() &&
       new_policy_duration > gesture_expected_flag_valid_for_duration)) {
    new_policy_duration = gesture_expected_flag_valid_for_duration;
  }

  if (new_policy_duration.is_positive()) {
    main_thread_only().current_policy_expiration_time =
        now + new_policy_duration;
    delayed_update_policy_runner_.SetDeadline(FROM_HERE, new_policy_duration,
                                              now);
  } else {
    main_thread_only().current_policy_expiration_time = base::TimeTicks();
  }

  // Avoid prioritizing main thread compositing (e.g., rAF) if it is extremely
  // slow, because that can cause starvation in other task sources.
  main_thread_only().main_thread_compositing_is_fast =
      main_thread_only().idle_time_estimator.GetExpectedIdleDuration(
          main_thread_only().compositor_frame_interval) >
      main_thread_only().compositor_frame_interval *
          kFastCompositingIdleTimeThreshold;

  Policy new_policy;
  new_policy.use_case = main_thread_only().current_use_case;
  new_policy.rail_mode = ComputeCurrentRAILMode(new_policy.use_case);

  if (main_thread_only().renderer_pause_count != 0) {
    new_policy.should_pause_task_queues = true;
  }

  if (main_thread_only().pause_timers_for_webview) {
    new_policy.should_pause_task_queues_for_android_webview = true;
  }

  new_policy.find_in_page_priority =
      find_in_page_budget_pool_controller_->CurrentTaskPriority();

  new_policy.should_prioritize_ipc_tasks =
      num_pending_urgent_ipc_messages_.load(std::memory_order_relaxed) > 0;

  new_policy.should_freeze_compositor_task_queue = AllPagesFrozen();

  // Tracing is done before the early out check, because it's quite possible we
  // will otherwise miss this information in traces.
  CreateTraceEventObjectSnapshotLocked();

  // Update the compositor priority before the early out check because the
  // priority computation relies on state outside of the policy
  // (main_thread_compositing_is_fast) that may have been updated here.
  UpdateCompositorTaskQueuePriority();

  // TODO(alexclarke): Can we get rid of force update now?
  // talp: Can't get rid of this, as per-agent scheduling happens on top of the
  //  policy, based on agent states.
  if (update_type == UpdateType::kMayEarlyOutIfPolicyUnchanged &&
      new_policy == main_thread_only().current_policy) {
    return;
  }

  main_thread_only().rail_mode_for_tracing = new_policy.rail_mode;
  if (new_policy.rail_mode != main_thread_only().current_policy.rail_mode) {
    if (isolate()) {
      isolate()->SetIsLoading(new_policy.rail_mode == RAILMode::kLoad);
    }
    for (auto& observer : main_thread_only().rail_mode_observers) {
      observer.OnRAILModeChanged(new_policy.rail_mode);
    }
  }

  Policy old_policy = main_thread_only().current_policy;
  main_thread_only().current_policy = new_policy;

  UpdateStateForAllTaskQueues(old_policy);
}

RAILMode MainThreadSchedulerImpl::ComputeCurrentRAILMode(
    UseCase use_case) const {
  switch (use_case) {
    case UseCase::kDiscreteInputResponse:
      // TODO(crbug.com/350540984): This really should be `RAILMode::kDefault`,
      // but switching out of the loading mode affects GC and causes some
      // benchmark regressions. For now, don't change the `RAILMode` for this
      // experimental `UseCase`.
      return main_thread_only().current_policy.rail_mode;

    case UseCase::kTouchstart:
    case UseCase::kCompositorGesture:
    case UseCase::kSynchronizedGesture:
    case UseCase::kMainThreadGesture:
    case UseCase::kNone:
    case UseCase::kMainThreadCustomInputHandling:
      return RAILMode::kDefault;

    case UseCase::kEarlyLoading:
    case UseCase::kLoading:
      return main_thread_only().renderer_hidden.get() ? RAILMode::kDefault
                                                      : RAILMode::kLoad;
  }
  NOTREACHED();
}

void MainThreadSchedulerImpl::UpdateStateForAllTaskQueues(
    std::optional<Policy> previous_policy) {
  helper_.CheckOnValidThread();

  const Policy& current_policy = main_thread_only().current_policy;
  const Policy& old_policy =
      previous_policy.value_or(main_thread_only().current_policy);

  bool should_update_priorities =
      !previous_policy.has_value() ||
      ShouldUpdateTaskQueuePriorities(previous_policy.value());
  for (const auto& pair : task_runners_) {
    UpdateTaskQueueState(pair.first.get(), pair.second.get(), old_policy,
                         current_policy, should_update_priorities);
  }

  if (base::FeatureList::IsEnabled(features::kDeferRendererTasksAfterInput)) {
    // TODO(crbug.com/350540984): The `idle_helper_queue_` is not tracked in
    // `task_runners_`, but should be added if this feature ships.
    UpdateTaskQueueState(idle_helper_queue_.get(), idle_queue_voter_.get(),
                         old_policy, current_policy,
                         /*should_update_priority=*/false);
  }
}

void MainThreadSchedulerImpl::UpdateTaskQueueState(
    MainThreadTaskQueue* task_queue,
    TaskQueue::QueueEnabledVoter* task_queue_enabled_voter,
    const Policy& old_policy,
    const Policy& new_policy,
    bool should_update_priority) const {
  if (should_update_priority)
    task_queue->SetQueuePriority(ComputePriority(task_queue));

  if (task_queue_enabled_voter) {
    task_queue_enabled_voter->SetVoteToEnable(
        new_policy.IsQueueEnabled(task_queue, scheduling_settings()));
  }

  // Make sure if there's no voter that the task queue is enabled.
  DCHECK(task_queue_enabled_voter ||
         old_policy.IsQueueEnabled(task_queue, scheduling_settings()));

  if (task_queue->GetPrioritisationType() ==
      MainThreadTaskQueue::QueueTraits::PrioritisationType::kCompositor) {
    task_queue_enabled_voter->SetVoteToEnable(
        !new_policy.should_freeze_compositor_task_queue);
  }
}

UseCase MainThreadSchedulerImpl::ComputeCurrentUseCase(
    base::TimeTicks now,
    base::TimeDelta* expected_use_case_duration) const {
  any_thread_lock_.AssertAcquired();

  // Above all else we want to be responsive to user input.
  *expected_use_case_duration = base::TimeDelta();
  base::TimeDelta time_left_in_continuous_gesture =
      any_thread().user_model.TimeLeftInContinuousUserGesture(now);
  base::TimeDelta time_left_in_discrete_gesture =
      any_thread().user_model.TimeLeftUntilDiscreteInputResponseDeadline(now);

  // A touchstart event can turn into either an actual gesture (scroll) or a
  // discrete input event (click/tap). The policies for these are similar in
  // that both prioritize the compositor task queue and both defer tasks, but
  // the deferral details are a bit different. For now, the existing behavior
  // takes precedent.
  //
  // TODO(crbug.com/350540984): Try to align the different deferral policies
  // after experimenting with discrete input-based deferral.
  if (time_left_in_continuous_gesture.is_positive() &&
      any_thread().awaiting_touch_start_response) {
    // The gesture hasn't been fully established; arrange for compositor tasks
    // to be run at the highest priority, and for tasks to be deferred as to not
    // block gesture establishment.
    *expected_use_case_duration = time_left_in_continuous_gesture;
    return UseCase::kTouchstart;
  }

  if (time_left_in_discrete_gesture.is_positive() &&
      any_thread().awaiting_discrete_input_response) {
    CHECK(
        base::FeatureList::IsEnabled(features::kDeferRendererTasksAfterInput));
    *expected_use_case_duration = time_left_in_discrete_gesture;
    return UseCase::kDiscreteInputResponse;
  }

  if (time_left_in_continuous_gesture.is_positive()) {
    *expected_use_case_duration = time_left_in_continuous_gesture;
    // A gesture has been established. Based on how the gesture is handled we
    // need to choose between one of four use cases:
    // 1. kCompositorGesture where the gesture is processed only on the
    //    compositor thread.
    // 2. MAIN_THREAD_GESTURE where the gesture is processed only on the main
    //    thread.
    // 3. MAIN_THREAD_CUSTOM_INPUT_HANDLING where the main thread processes a
    //    stream of input events and has prevented a default gesture from being
    //    started.
    // 4. SYNCHRONIZED_GESTURE where the gesture is processed on both threads.
    if (any_thread().last_gesture_was_compositor_driven) {
      if (any_thread().begin_main_frame_on_critical_path) {
        return UseCase::kSynchronizedGesture;
      } else {
        return UseCase::kCompositorGesture;
      }
    }
    if (any_thread().default_gesture_prevented) {
      return UseCase::kMainThreadCustomInputHandling;
    } else {
      return UseCase::kMainThreadGesture;
    }
  }

  // Occasionally the meaningful paint fails to be detected, so as a fallback we
  // treat the presence of input as an indirect signal that there is meaningful
  // content on the page.
  if (!any_thread().have_seen_input_since_navigation) {
    if (any_thread().waiting_for_any_main_frame_contentful_paint)
      return UseCase::kEarlyLoading;

    if (base::FeatureList::IsEnabled(
            features::kLoadingPhaseBufferTimeAfterFirstMeaningfulPaint)) {
      if (any_thread().waiting_for_any_main_frame_meaningful_paint) {
        return UseCase::kLoading;
      }
    } else {
      if (any_thread().is_any_main_frame_loading) {
        return
```