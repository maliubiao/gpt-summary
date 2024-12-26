Response: My thought process for analyzing the `MainThreadTaskQueue.cc` file and generating the response involved several steps:

1. **Understanding the Core Purpose:** I first read through the code to grasp the fundamental role of `MainThreadTaskQueue`. The name itself is a strong hint. I identified keywords like "task queue," "main thread," and "scheduler." This immediately told me it's responsible for managing tasks that execute on the main thread of the Blink rendering engine.

2. **Identifying Key Data Structures and Members:**  I looked for prominent data structures and member variables. `task_queue_` stood out as the core task queue implementation (likely from Chromium's `sequence_manager`). I noted other important members like `queue_type_`, `queue_traits_`, `throttler_`, `frame_scheduler_`, and `main_thread_scheduler_`. These suggested different aspects of task queue management (prioritization, throttling, integration with frame and main thread scheduling).

3. **Analyzing Public Methods:** I examined the public methods to understand the primary actions the `MainThreadTaskQueue` can perform. Methods like `PostTask`, `ShutdownTaskQueue`, `Throttle`, `SetWebSchedulingPriority`, and `CreateTaskRunner` revealed its capabilities for adding tasks, managing lifecycle, controlling execution speed, and creating task runners with specific types.

4. **Tracing Interactions with External Components:** I looked for interactions with other Blink/Chromium components. The inclusion of headers like `FrameSchedulerImpl.h` and `MainThreadSchedulerImpl.h`, along with the member variables, indicated close collaboration with frame scheduling and overall main thread scheduling. The use of `base::task::SingleThreadTaskRunner` pointed to integration with Chromium's task scheduling infrastructure.

5. **Connecting to Web Concepts (JavaScript, HTML, CSS):**  This was a crucial step. I reasoned that because this is the *main thread* task queue, it *must* be involved in executing JavaScript, processing HTML, and applying CSS styles. I looked for clues in the queue types (e.g., `kV8`, `kInput`, `kFrameLoading`) and reasoned how these would relate to web page rendering and interaction. For example, JavaScript execution heavily relies on the main thread, hence the `kV8` queues. Input events from the user (mouse clicks, keyboard presses) also need to be processed on the main thread. Frame loading involves fetching and parsing HTML and related resources.

6. **Considering Logic and Data Flow:**  I thought about how tasks would be added to the queue, how they would be prioritized and executed, and how the throttling mechanism might work. The `OnTaskStarted` and `OnTaskCompleted` methods, along with the `throttler_`, suggested a mechanism for tracking task execution time and potentially delaying less critical tasks.

7. **Identifying Potential User Errors:** I considered common mistakes developers might make when interacting with a system like this (even indirectly). For example, long-running tasks on the main thread can cause jank, and misunderstanding task prioritization could lead to unexpected execution order.

8. **Structuring the Response:** Finally, I organized my findings into a clear and structured response. I started with a high-level summary of the file's functionality. Then, I addressed the specific requests about connections to web technologies, providing concrete examples. I also included a section on logical reasoning with hypothetical input/output (although the code doesn't lend itself to simple input/output in the traditional sense, I focused on demonstrating the effect of prioritization). Lastly, I added a section on common usage errors.

**Internal Trial-and-Error/Refinement:**

* **Initial Focus on Direct Web API Mapping (Less fruitful):**  Initially, I might have tried to find direct mappings between `MainThreadTaskQueue` concepts and specific JavaScript APIs (like `setTimeout`). While there's a connection, it's not a direct 1:1 mapping. I realized I needed to think at a higher level about the *types* of work the main thread performs.
* **Emphasis on the "Why":**  Simply listing the queue types isn't enough. I needed to explain *why* those different queue types exist and how they contribute to the overall performance and responsiveness of the browser.
* **Balancing Technical Detail and Clarity:**  I had to strike a balance between providing sufficient technical detail and keeping the explanation understandable for a wider audience. Avoiding overly specific implementation details of the underlying `sequence_manager` was important.
* **Refining the Examples:**  I aimed for examples that were concrete and easy to grasp, illustrating the impact of the `MainThreadTaskQueue` on user experience.

By following these steps, I could effectively analyze the provided source code and generate a comprehensive and informative response.
`blink/renderer/platform/scheduler/main_thread/main_thread_task_queue.cc` 文件是 Chromium Blink 渲染引擎中负责管理主线程上执行任务的关键组件。它定义了 `MainThreadTaskQueue` 类，这个类是实际存储和调度主线程任务的容器。

以下是该文件的主要功能：

**1. 任务队列管理:**

* **存储任务:**  `MainThreadTaskQueue` 维护着一个任务队列，用于存储待执行的任务。这些任务通常是需要在浏览器主线程上执行的操作。
* **任务分类:**  该文件定义了多种类型的任务队列 (`QueueType` 枚举)，例如：
    * `kControl`:  控制任务，优先级最高。
    * `kDefault`:  默认任务队列。
    * `kFrameLoading`:  与页面加载相关的任务。
    * `kFrameThrottleable`: 可以被节流的帧相关任务。
    * `kV8`:  与 JavaScript 引擎 V8 相关的任务。
    * `kInput`:  用户输入事件处理任务。
    * 其他类型用于处理特定场景的任务。
    通过区分任务类型，可以实现不同优先级和处理方式的任务调度。
* **任务执行:**  `MainThreadTaskQueue` 与底层的 `base::sequence_manager::SequenceManager` 交互，后者负责实际从队列中取出任务并在主线程上执行。
* **任务生命周期管理:**  它跟踪任务的开始和完成，并提供回调 (`OnTaskStarted`, `OnTaskCompleted`) 以便其他组件了解任务执行状态。

**2. 任务调度策略:**

* **优先级控制:** 不同类型的任务队列具有不同的优先级，从而影响任务的执行顺序。例如，用户输入事件通常比后台加载任务具有更高的优先级。
* **节流 (Throttling):** 某些任务队列（如 `kFrameThrottleable`）可以被节流，以控制帧率，避免主线程过载，保证用户交互的流畅性。 `throttler_` 成员负责实现节流逻辑。
* **延迟 (Deferring):** 某些任务可以被延迟执行，例如在页面空闲时执行。
* **暂停 (Pausing):** 某些类型的任务队列可以被暂停和恢复。

**3. 与其他组件的交互:**

* **`MainThreadSchedulerImpl`:**  `MainThreadTaskQueue` 由 `MainThreadSchedulerImpl` 创建和管理，并与其紧密协作，例如在任务开始和结束时通知 `MainThreadSchedulerImpl`。
* **`FrameSchedulerImpl`:**  对于与渲染帧相关的任务队列，`MainThreadTaskQueue` 与 `FrameSchedulerImpl` 交互，后者负责协调帧的生成和渲染过程。
* **`AgentGroupScheduler`:**  在某些情况下，任务队列可能与 `AgentGroupScheduler` 关联，用于管理一组相关的渲染进程或 worker。
* **Tracing:**  通过 Perfetto 集成，可以记录任务的执行信息，用于性能分析和调试。

**4. Web 特性关联举例:**

* **JavaScript:** 当 JavaScript 代码执行时，例如通过 `setTimeout` 或事件处理程序，V8 引擎会将相应的任务添加到 `kV8` 或 `kV8UserVisible` 等任务队列中。这些任务会在主线程上被调度执行，从而驱动 JavaScript 代码的运行。
    * **假设输入:** JavaScript 代码 `setTimeout(() => { console.log('Hello'); }, 100);` 被执行。
    * **输出:** 一个在 100 毫秒后执行 `console.log('Hello')` 的任务会被添加到 `MainThreadTaskQueue` 的某个 V8 相关的队列中。
* **HTML:**  当浏览器解析 HTML 时，会产生需要在主线程上执行的任务，例如构建 DOM 树、处理资源加载等。这些任务可能被添加到 `kFrameLoading` 或 `kDefault` 等任务队列。
    * **假设输入:**  浏览器开始加载包含大量图片的 HTML 页面。
    * **输出:**  与图片解码、渲染相关的任务会被添加到 `MainThreadTaskQueue` 中。
* **CSS:**  CSS 样式的计算、布局和应用也需要在主线程上执行。当 CSSOM 构建完成后，会生成相应的任务来更新渲染树。
    * **假设输入:**  CSS 样式发生变化，例如通过 JavaScript 修改元素的 `style` 属性。
    * **输出:**  一个重新计算样式和布局的任务会被添加到 `MainThreadTaskQueue` 中。
* **用户交互:**  当用户与网页交互时，例如点击按钮、滚动页面，浏览器会生成相应的事件，这些事件的处理任务会被添加到 `kInput` 任务队列中。
    * **假设输入:** 用户点击了一个按钮。
    * **输出:**  一个处理该点击事件的任务（可能触发 JavaScript 事件处理函数）会被添加到 `MainThreadTaskQueue` 的 `kInput` 队列中。

**5. 逻辑推理示例:**

* **假设输入:** 两个任务被添加到 `MainThreadTaskQueue`，一个类型为 `kInput`，另一个类型为 `kFrameThrottleable`。
* **输出:**  `kInput` 类型的任务由于优先级更高，通常会先于 `kFrameThrottleable` 类型的任务被执行。这保证了用户交互的及时响应。

**6. 常见使用错误示例:**

* **在主线程上执行耗时同步操作:**  如果在主线程的任务中执行了耗时的同步操作（例如大量的计算或同步 I/O），会导致主线程阻塞，影响页面响应性和用户体验。
    * **示例:**  JavaScript 代码中执行了一个复杂的循环计算，没有使用 Web Workers 或异步操作。这会导致其他任务（包括渲染更新和用户输入处理）被延迟执行，造成页面卡顿。
* **过度使用 `setTimeout` 或 `requestAnimationFrame`:**  虽然这些 API 用于异步执行代码，但过度或不当使用可能会导致大量的任务被添加到主线程队列，增加主线程的负担，尤其是在高频率的情况下。
    * **示例:**  在一个动画效果中使用过低的 `setTimeout` 延迟值，或者在 `requestAnimationFrame` 回调中执行了大量不必要的计算。
* **不理解任务优先级:**  开发者可能错误地认为所有添加到主线程的任务都会以相同的优先级执行。如果关键任务被低优先级任务阻塞，可能会导致性能问题。
    * **示例:**  在一个优先级较低的任务队列中执行了页面渲染的关键逻辑，导致页面更新延迟。
* **忘记处理异步操作的完成回调:**  如果异步操作（例如网络请求）的完成回调没有被正确处理并添加到主线程任务队列，可能会导致数据更新或 UI 更新失败。
    * **示例:**  发起一个网络请求后，没有在 `then` 或 `catch` 中处理响应并更新页面内容，导致页面状态与实际数据不符。

总而言之，`MainThreadTaskQueue` 是 Blink 渲染引擎中管理主线程任务的核心组件，它负责任务的存储、调度和执行，并与 JavaScript、HTML、CSS 等 Web 技术的功能紧密相关，直接影响着网页的渲染性能和用户体验。理解其工作原理对于开发高性能的 Web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/scheduler/main_thread/main_thread_task_queue.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_task_queue.h"

#include <memory>
#include <utility>

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/task/common/scoped_defer_task_posting.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/base_tracing.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/scheduler/common/blink_scheduler_single_thread_task_runner.h"
#include "third_party/blink/renderer/platform/scheduler/common/tracing_helper.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"
#include "third_party/perfetto/include/perfetto/tracing/traced_value.h"

namespace blink {
namespace scheduler {

namespace internal {
using base::sequence_manager::internal::TaskQueueImpl;
}

using perfetto::protos::pbzero::ChromeTrackEvent;
using perfetto::protos::pbzero::RendererMainThreadTaskExecution;
using QueueName = ::perfetto::protos::pbzero::SequenceManagerTask::QueueName;
// static
QueueName MainThreadTaskQueue::NameForQueueType(
    MainThreadTaskQueue::QueueType queue_type) {
  switch (queue_type) {
    case MainThreadTaskQueue::QueueType::kControl:
      return QueueName::CONTROL_TQ;
    case MainThreadTaskQueue::QueueType::kDefault:
      return QueueName::DEFAULT_TQ;
    case MainThreadTaskQueue::QueueType::kFrameLoading:
      return QueueName::FRAME_LOADING_TQ;
    case MainThreadTaskQueue::QueueType::kFrameThrottleable:
      return QueueName::FRAME_THROTTLEABLE_TQ;
    case MainThreadTaskQueue::QueueType::kFrameDeferrable:
      return QueueName::FRAME_DEFERRABLE_TQ;
    case MainThreadTaskQueue::QueueType::kFramePausable:
      return QueueName::FRAME_PAUSABLE_TQ;
    case MainThreadTaskQueue::QueueType::kFrameUnpausable:
      return QueueName::FRAME_UNPAUSABLE_TQ;
    case MainThreadTaskQueue::QueueType::kCompositor:
      return QueueName::COMPOSITOR_TQ;
    case MainThreadTaskQueue::QueueType::kIdle:
      return QueueName::IDLE_TQ;
    case MainThreadTaskQueue::QueueType::kTest:
      return QueueName::TEST_TQ;
    case MainThreadTaskQueue::QueueType::kFrameLoadingControl:
      return QueueName::FRAME_LOADING_CONTROL_TQ;
    case MainThreadTaskQueue::QueueType::kV8:
      return QueueName::V8_TQ;
    case MainThreadTaskQueue::QueueType::kV8UserVisible:
      return QueueName::V8_USER_VISIBLE_TQ;
    case MainThreadTaskQueue::QueueType::kV8BestEffort:
      return QueueName::V8_BEST_EFFORT_TQ;
    case MainThreadTaskQueue::QueueType::kInput:
      return QueueName::INPUT_TQ;
    case MainThreadTaskQueue::QueueType::kDetached:
      return QueueName::DETACHED_TQ;
    case MainThreadTaskQueue::QueueType::kOther:
      return QueueName::OTHER_TQ;
    case MainThreadTaskQueue::QueueType::kWebScheduling:
      return QueueName::WEB_SCHEDULING_TQ;
    case MainThreadTaskQueue::QueueType::kNonWaking:
      return QueueName::NON_WAKING_TQ;
    case MainThreadTaskQueue::QueueType::kIPCTrackingForCachedPages:
      return QueueName::IPC_TRACKING_FOR_CACHED_PAGES_TQ;
    case MainThreadTaskQueue::QueueType::kCount:
      NOTREACHED();
  }
  NOTREACHED();
}

MainThreadTaskQueue::MainThreadTaskQueue(
    base::sequence_manager::SequenceManager& sequence_manager,
    const TaskQueue::Spec& spec,
    const QueueCreationParams& params,
    MainThreadSchedulerImpl* main_thread_scheduler)
    : task_queue_(sequence_manager.CreateTaskQueue(spec)),
      queue_type_(params.queue_type),
      queue_traits_(params.queue_traits),
      web_scheduling_queue_type_(params.web_scheduling_queue_type),
      web_scheduling_priority_(params.web_scheduling_priority),
      main_thread_scheduler_(main_thread_scheduler),
      agent_group_scheduler_(params.agent_group_scheduler),
      frame_scheduler_(params.frame_scheduler) {
  task_runner_with_default_task_type_ =
      WrapTaskRunner(task_queue_->task_runner());
  // Throttling needs |should_notify_observers| to get task timing.
  DCHECK(!params.queue_traits.can_be_throttled || spec.should_notify_observers)
      << "Throttled queue is not supported with |!should_notify_observers|";
  DCHECK_EQ(web_scheduling_priority_.has_value(),
            web_scheduling_queue_type_.has_value());
  DCHECK_EQ(web_scheduling_priority_.has_value(),
            queue_type_ == QueueType::kWebScheduling);
  if (spec.should_notify_observers) {
    if (params.queue_traits.can_be_throttled) {
      throttler_.emplace(task_queue_.get(),
                         main_thread_scheduler_->GetTickClock());
    }
    // TODO(scheduler-dev): Consider mapping directly to
    // MainThreadSchedulerImpl::OnTaskStarted/Completed. At the moment this
    // is not possible due to task queue being created inside
    // MainThreadScheduler's constructor.
    task_queue_->SetOnTaskStartedHandler(base::BindRepeating(
        &MainThreadTaskQueue::OnTaskStarted, base::Unretained(this)));
    task_queue_->SetOnTaskCompletedHandler(base::BindRepeating(
        &MainThreadTaskQueue::OnTaskCompleted, base::Unretained(this)));
    task_queue_->SetTaskExecutionTraceLogger(base::BindRepeating(
        &MainThreadTaskQueue::LogTaskExecution, base::Unretained(this)));
  }
}

MainThreadTaskQueue::~MainThreadTaskQueue() {
  DCHECK(!wake_up_budget_pool_);
}

void MainThreadTaskQueue::OnTaskStarted(
    const base::sequence_manager::Task& task,
    const base::sequence_manager::TaskQueue::TaskTiming& task_timing) {
  if (main_thread_scheduler_) {
    main_thread_scheduler_->OnTaskStarted(this, task, task_timing);
  }
}

void MainThreadTaskQueue::OnTaskCompleted(
    const base::sequence_manager::Task& task,
    TaskQueue::TaskTiming* task_timing,
    base::LazyNow* lazy_now) {
  if (main_thread_scheduler_) {
    main_thread_scheduler_->OnTaskCompleted(weak_ptr_factory_.GetWeakPtr(),
                                            task, task_timing, lazy_now);
  }
}

void MainThreadTaskQueue::LogTaskExecution(
    perfetto::EventContext& ctx,
    const base::sequence_manager::Task& task) {
  static const uint8_t* enabled =
      TRACE_EVENT_API_GET_CATEGORY_GROUP_ENABLED("scheduler");
  if (!*enabled)
    return;
  RendererMainThreadTaskExecution* execution =
      ctx.event<ChromeTrackEvent>()->set_renderer_main_thread_task_execution();
  execution->set_task_type(
      TaskTypeToProto(static_cast<blink::TaskType>(task.task_type)));
  if (frame_scheduler_) {
    frame_scheduler_->WriteIntoTrace(ctx.Wrap(execution));
  }
}

void MainThreadTaskQueue::OnTaskRunTimeReported(
    TaskQueue::TaskTiming* task_timing) {
  if (throttler_) {
    throttler_->OnTaskRunTimeReported(task_timing->start_time(),
                                      task_timing->end_time());
  }
}

void MainThreadTaskQueue::DetachTaskQueue() {
  // The task queue was already shut down, which happens in tests if the
  // `agent_group_scheduler_` is GCed after the task queue impl is unregistered.
  //
  // TODO(crbug.com/1143007): AgentGroupSchedulerImpl should probably not be
  // detaching shut down task queues.
  if (!task_queue_) {
    return;
  }
  // `main_thread_scheduler_` can be null in tests.
  if (!main_thread_scheduler_) {
    return;
  }

  task_queue_->ResetThrottler();
  throttler_.reset();

  // Detach from the underlying scheduler and transfer control to the main
  // thread scheduler.
  agent_group_scheduler_ = nullptr;
  frame_scheduler_ = nullptr;
  on_ipc_task_posted_callback_handle_.reset();
  main_thread_scheduler_->OnDetachTaskQueue(*this);
}

void MainThreadTaskQueue::SetOnIPCTaskPosted(
    base::RepeatingCallback<void(const base::sequence_manager::Task&)>
        on_ipc_task_posted_callback) {
  // We use the frame_scheduler_ to track metrics so as to ensure that metrics
  // are not tied to individual task queues.
  on_ipc_task_posted_callback_handle_ = task_queue_->AddOnTaskPostedHandler(
      std::move(on_ipc_task_posted_callback));
}

void MainThreadTaskQueue::DetachOnIPCTaskPostedWhileInBackForwardCache() {
  on_ipc_task_posted_callback_handle_.reset();
}

void MainThreadTaskQueue::ShutdownTaskQueue() {
  if (main_thread_scheduler_) {
    main_thread_scheduler_->OnShutdownTaskQueue(this);
  }
  main_thread_scheduler_ = nullptr;
  agent_group_scheduler_ = nullptr;
  frame_scheduler_ = nullptr;
  throttler_.reset();
  task_queue_.reset();
}

AgentGroupScheduler* MainThreadTaskQueue::GetAgentGroupScheduler() {
  DCHECK(task_queue_->task_runner()->BelongsToCurrentThread());

  if (agent_group_scheduler_) {
    DCHECK(!frame_scheduler_);
    return agent_group_scheduler_;
  }
  if (frame_scheduler_) {
    return frame_scheduler_->GetAgentGroupScheduler();
  }
  // If this MainThreadTaskQueue was created for MainThreadSchedulerImpl, this
  // queue will not be associated with AgentGroupScheduler or FrameScheduler.
  return nullptr;
}

FrameSchedulerImpl* MainThreadTaskQueue::GetFrameScheduler() const {
  if (!task_queue_) {
    return frame_scheduler_;
  }
  DCHECK(task_queue_->task_runner()->BelongsToCurrentThread());
  return frame_scheduler_;
}

void MainThreadTaskQueue::SetFrameSchedulerForTest(
    FrameSchedulerImpl* frame_scheduler) {
  frame_scheduler_ = frame_scheduler;
}

void MainThreadTaskQueue::SetWebSchedulingPriority(
    WebSchedulingPriority priority) {
  if (web_scheduling_priority_ == priority) {
    return;
  }
  web_scheduling_priority_ = priority;
  if (frame_scheduler_) {
    frame_scheduler_->OnWebSchedulingTaskQueuePriorityChanged(this);
  }
}

void MainThreadTaskQueue::OnWebSchedulingTaskQueueDestroyed() {
  if (frame_scheduler_) {
    frame_scheduler_->OnWebSchedulingTaskQueueDestroyed(this);
  }
}

bool MainThreadTaskQueue::IsThrottled() const {
  if (main_thread_scheduler_) {
    return throttler_.has_value() && throttler_->IsThrottled();
  } else {
    // When the frame detaches the task queue is removed from the throttler.
    return false;
  }
}

MainThreadTaskQueue::ThrottleHandle MainThreadTaskQueue::Throttle() {
  DCHECK(CanBeThrottled());
  return ThrottleHandle(*this);
}

void MainThreadTaskQueue::AddToBudgetPool(base::TimeTicks now,
                                          BudgetPool* pool) {
  pool->AddThrottler(now, &throttler_.value());
}

void MainThreadTaskQueue::RemoveFromBudgetPool(base::TimeTicks now,
                                               BudgetPool* pool) {
  pool->RemoveThrottler(now, &throttler_.value());
}

void MainThreadTaskQueue::SetWakeUpBudgetPool(
    WakeUpBudgetPool* wake_up_budget_pool) {
  wake_up_budget_pool_ = wake_up_budget_pool;
}

void MainThreadTaskQueue::WriteIntoTrace(perfetto::TracedValue context) const {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("type", queue_type_);
  dict.Add("traits", queue_traits_);
  dict.Add("throttler", throttler_);
}

void MainThreadTaskQueue::QueueTraits::WriteIntoTrace(
    perfetto::TracedValue context) const {
  auto dict = std::move(context).WriteDictionary();
  dict.Add("can_be_deferred", can_be_deferred);
  dict.Add("can_be_throttled", can_be_throttled);
  dict.Add("can_be_intensively_throttled", can_be_intensively_throttled);
  dict.Add("can_be_paused", can_be_paused);
  dict.Add("can_be_frozen", can_be_frozen);
  dict.Add("can_run_in_background", can_run_in_background);
  dict.Add("can_run_when_virtual_time_paused",
           can_run_when_virtual_time_paused);
  dict.Add("can_be_paused_for_android_webview",
           can_be_paused_for_android_webview);
  dict.Add("prioritisation_type", prioritisation_type);
}

scoped_refptr<base::SingleThreadTaskRunner>
MainThreadTaskQueue::CreateTaskRunner(TaskType task_type) {
  CHECK(task_queue_);
  return WrapTaskRunner(
      task_queue_->CreateTaskRunner(static_cast<int>(task_type)));
}

scoped_refptr<BlinkSchedulerSingleThreadTaskRunner>
MainThreadTaskQueue::WrapTaskRunner(
    scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
  // We need to pass the cleanup task runner to task task queues that may stop
  // running tasks before the main thread shuts down as a backup for object
  // deleter tasks.
  scoped_refptr<base::SingleThreadTaskRunner> cleanup_runner =
      main_thread_scheduler_ && (frame_scheduler_ || agent_group_scheduler_)
          ? main_thread_scheduler_->CleanupTaskRunner()
          : nullptr;
  return base::MakeRefCounted<BlinkSchedulerSingleThreadTaskRunner>(
      std::move(task_runner), std::move(cleanup_runner));
}

}  // namespace scheduler
}  // namespace blink

"""

```