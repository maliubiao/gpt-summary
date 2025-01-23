Response: Let's break down the thought process for analyzing the `WorkerThreadScheduler.cc` file.

1. **Understand the Goal:** The core task is to understand the functionality of this specific source code file within the Chromium/Blink project. This means identifying its purpose, how it interacts with other components, and what kinds of tasks it manages.

2. **High-Level Overview (Reading the Header and Copyright):**  The initial lines provide crucial context. We see it's part of the Blink rendering engine, specifically the `platform/scheduler/worker` directory. The name `WorkerThreadScheduler` immediately suggests its responsibility is managing the scheduling of tasks on a worker thread. The copyright and license information are important but don't directly contribute to understanding the functionality.

3. **Include Analysis:**  The `#include` statements are vital clues to the dependencies and capabilities of this class. We can categorize them:

    * **General C++:** `<memory>`, which suggests dynamic memory management.
    * **Base Library:** `base/containers/contains.h`, `base/functional/bind.h`, `base/metrics/...`, `base/strings/...`, `base/task/...`, `base/trace_event/...`. These signal core functionalities like data structures, function binding, metrics collection, string manipulation, task management, and tracing.
    * **Mojo:** `mojo/public/cpp/bindings/...`. This indicates interaction with the Mojo IPC system, likely for communication with other processes.
    * **Services:** `services/metrics/public/cpp/...`. Specifically, the UKM (User Keyed Metrics) recorder, showing its role in collecting performance data.
    * **Blink Public API:** `third_party/blink/public/common/...`, `third_party/blink/public/platform/...`. These point to interactions with the broader Blink environment and platform specifics.
    * **Blink Internal (Scheduler):** `third_party/blink/renderer/platform/scheduler/...`. This is the most important category. It reveals the relationships with other scheduler components like `AutoAdvancingVirtualTimeDomain`, `features`, `metrics_helper`, `process_state`, `throttling` mechanisms, `EventLoop`, `NonMainThreadSchedulerHelper`, `WorkerSchedulerImpl`, and `WorkerSchedulerProxy`. This is where the core scheduling logic lies.

4. **Namespace and Class Definition:** The code is within the `blink::scheduler` namespace, confirming its role in the Blink scheduler. The `class WorkerThreadScheduler` declaration is the central focus.

5. **Constructor and Destructor:** The constructor (`WorkerThreadScheduler(...)`) takes `ThreadType`, `SequenceManager`, and `WorkerSchedulerProxy` as arguments. This tells us it's instantiated with information about the type of worker thread and has a connection to a `SequenceManager` (the core of task scheduling in Chromium) and a `WorkerSchedulerProxy` (likely representing the interface to the main thread or other entities). The constructor also initializes things like the idle helper and potentially budget pools for throttling. The destructor (`~WorkerThreadScheduler()`) checks that all associated worker schedulers have been unregistered, indicating a cleanup responsibility.

6. **Key Methods and their Functionality (Iterative Analysis):** Go through the public methods and try to understand their purpose based on their names, parameters, and internal operations. This is where the bulk of the analysis happens:

    * **Task Runners (`IdleTaskRunner`, `V8TaskRunner`, `CleanupTaskRunner`, `CompositorTaskRunner`):**  These methods expose different task runners for specific types of tasks, indicating a separation of concerns within the worker thread. The names suggest their purposes: idle tasks, JavaScript (V8) tasks, cleanup tasks, and compositor-related tasks.
    * **`ShouldYieldForHighPriorityWork()`:** Indicates whether the scheduler prioritizes certain types of work. The comment clarifies that workers don't have this concept.
    * **Task Observers (`AddTaskObserver`, `RemoveTaskObserver`):**  Allows external components to monitor task execution.
    * **`Shutdown()`:**  Cleans up resources.
    * **`DefaultTaskQueue()`:** Returns the primary queue for worker tasks.
    * **`Init()`:**  Performs initialization steps.
    * **`OnTaskCompleted()`:** Handles actions after a task finishes, including microtask checkpoints, completion callbacks, and UKM recording.
    * **Lifecycle Management (`OnLifecycleStateChanged`, `RegisterWorkerScheduler`, `UnregisterWorkerScheduler`):**  These methods are crucial for managing the state of the worker thread and its associated worker schedulers, particularly related to throttling or backgrounding.
    * **Throttling (`CreateBudgetPools`):**  Sets up mechanisms for limiting the resources consumed by the worker thread, especially when backgrounded.
    * **UKM Recording (`RecordTaskUkm`, `CreateMojoUkmRecorder`, `SetUkmRecorderForTest`, `SetUkmTaskSamplingRateForTest`):**  Collects performance data about task execution.
    * **Virtual Time (`GetVirtualTimeTaskRunner`, `OnVirtualTimeDisabled`, `OnVirtualTimePaused`, `OnVirtualTimeResumed`):**  Supports simulating time progression, often used for testing.
    * **Idle Tasks (`PostIdleTask`, `PostNonNestableIdleTask`, `PostDelayedIdleTask`):**  Provides ways to schedule tasks that should run when the thread is idle.
    * **V8 Isolate (`SetV8Isolate`):** Connects the scheduler to the V8 JavaScript engine instance.

7. **Relationship to JavaScript, HTML, and CSS:**  Once the core functionalities are understood, connect them to web technologies:

    * **JavaScript:**  The presence of `V8TaskRunner` and `SetV8Isolate` directly links to JavaScript execution within the worker. Worker threads are commonly used for background JavaScript processing.
    * **HTML:** While not directly manipulating the DOM, worker threads are often initiated from HTML (e.g., using `<script type="module" worker>`). They might process data fetched from the network or perform computations that affect the rendering of HTML.
    * **CSS:** Indirectly related. While workers don't directly manipulate CSSOM, they might be used to perform layout calculations or pre-processing of style information in complex applications.

8. **Logic Inference and Examples:**  Based on the identified functionalities, create hypothetical scenarios to illustrate how the code might behave. This involves imagining inputs (e.g., lifecycle state changes) and predicting outputs (e.g., throttling behavior).

9. **Common Usage Errors:** Think about how a developer might misuse the APIs provided by this class. Examples include forgetting to register/unregister worker schedulers, not understanding the implications of different task runners, or misconfiguring throttling parameters.

10. **Review and Refine:** Go back through the analysis, ensuring that the explanations are clear, concise, and accurate. Check for any missing functionalities or misinterpretations. Pay attention to comments in the code, as they often provide valuable insights. For instance, the comments about worker throttling trial parameters are very helpful.

By following these steps, we can systematically dissect the source code and arrive at a comprehensive understanding of its purpose and functionality. The key is to start with the big picture and gradually zoom in on the details, using the code itself as the primary source of information.
这个文件 `worker_thread_scheduler.cc` 是 Chromium Blink 渲染引擎中负责管理 Worker 线程上任务调度的核心组件。它定义了 `WorkerThreadScheduler` 类，该类负责管理和调度在 Dedicated Worker 或 Shared Worker 等非主线程上运行的任务。

以下是它的主要功能，并解释了与 JavaScript, HTML, CSS 的关系，以及可能的错误使用场景：

**主要功能:**

1. **任务队列管理:**
   - 管理多个任务队列（TaskQueue），例如默认任务队列、V8 任务队列、Compositor 任务队列和 Idle 任务队列。
   - 根据任务类型将任务添加到相应的队列中。

2. **任务调度:**
   - 负责从任务队列中取出任务并执行。
   - 实现基于优先级的调度策略，尽管在 Worker 线程上目前没有高优先级任务的概念。
   - 允许注册任务观察者（TaskObserver）来监控任务的执行。

3. **Worker 生命周期管理:**
   - 跟踪 Worker 的生命周期状态（例如，是否被节流）。
   - 当 Worker 的生命周期状态发生变化时，通知关联的 `WorkerScheduler` 实例。

4. **空闲任务处理:**
   - 提供机制来执行在 Worker 线程空闲时运行的任务（Idle Tasks）。
   - 利用 `IdleHelper` 类来管理空闲任务的调度。

5. **性能监控 (UKM):**
   - 记录 Worker 线程上执行的任务的性能指标（例如，任务持续时间、CPU 持续时间）。
   - 使用 UKM (User Keyed Metrics) 将这些指标报告给 Chrome 的遥测系统。

6. **节流 (Throttling):**
   - 实现了针对 Dedicated Worker 的节流机制（如果 `kDedicatedWorkerThrottling` FeatureFlag 被启用）。
   - 使用 `WakeUpBudgetPool` 和 `CPUTimeBudgetPool` 来限制 Worker 线程的唤醒频率和 CPU 使用时间，特别是在 Worker 处于后台状态时。
   - 通过 Field Trial 参数控制节流的具体行为，例如最大预算、恢复速率和最大延迟。

7. **虚拟时间支持:**
   - 支持虚拟时间的推进和暂停，主要用于测试目的。

8. **与 V8 引擎集成:**
   - 提供一个专门的 V8 任务队列 (`kWorkerThreadTaskQueueV8`) 用于执行 JavaScript 代码。
   - 通过 `SetV8Isolate` 方法与 V8 Isolate 关联。

**与 JavaScript, HTML, CSS 的关系:**

* **JavaScript:** `WorkerThreadScheduler` 直接负责调度和执行 Worker 线程上的 JavaScript 代码。当一个 Web Worker 被创建时，其内部的 JavaScript 代码将在这个调度器管理的线程上运行。`V8TaskRunner()` 返回的 TaskRunner 用于执行 JavaScript 任务。
    * **示例:** 当 `postMessage()` 方法被调用向 Worker 发送消息时，Worker 线程上的 `WorkerThreadScheduler` 会调度相应的 JavaScript 代码来处理这个消息。

* **HTML:** Worker 通常由 HTML 中的 JavaScript 代码创建。`WorkerThreadScheduler` 负责管理这些 Worker 的执行环境。
    * **示例:** `<script>` 标签中的 JavaScript 代码可以创建 `new Worker('my-worker.js')`，这个操作最终会导致一个 `WorkerThreadScheduler` 的实例被创建来管理 `my-worker.js` 的执行。

* **CSS:** `WorkerThreadScheduler` 与 CSS 的关系相对间接。Worker 线程本身不能直接访问或修改 DOM 或 CSSOM。然而，Worker 可以执行与 CSS 相关的计算密集型任务，例如样式预处理、布局计算的某些部分（虽然通常在主线程进行），或者处理从网络加载的 CSS 数据。
    * **示例:** 一个 Worker 线程可以下载一个大型 CSS 文件，对其进行解析和预处理，然后将处理后的数据发送回主线程。`WorkerThreadScheduler` 负责调度这些处理 CSS 数据的任务。

**逻辑推理的假设输入与输出:**

假设我们启用了 Dedicated Worker 的节流功能 (`kDedicatedWorkerThrottling` FeatureFlag 为 true)。

**假设输入:**

* Worker 线程处于活动状态，并不断提交需要执行的任务。
* `kWorkerThrottlingMaxBudgetParam` 被设置为 "100" (毫秒)。
* `kWorkerThrottlingRecoveryRateParam` 被设置为 "0.02"。

**逻辑推理:**

1. **初始状态:** Worker 线程开始执行任务。`CPUTimeBudgetPool` 会跟踪 Worker 的 CPU 时间预算。
2. **预算消耗:**  随着任务的执行，Worker 的 CPU 时间预算会减少。
3. **达到预算上限:** 当 Worker 线程执行任务消耗的 CPU 时间达到 `kWorkerThrottlingMaxBudgetParam` 设置的 100 毫秒时，`CPUTimeBudgetPool` 会限制该 Worker 进一步执行 CPU 密集型任务。
4. **节流延迟:**  后续提交的任务可能会被延迟执行，直到 CPU 时间预算恢复。
5. **预算恢复:** `CPUTimeBudgetPool` 会以 `kWorkerThrottlingRecoveryRateParam` 设置的 0.02 的速率恢复预算。这意味着每经过一定时间，预算会增加一部分。
6. **解除节流:** 当预算恢复到一定程度后，被延迟的任务可以被调度执行。

**输出:**

* Worker 线程的 CPU 使用率会被限制在一个合理的范围内，即使它有大量的任务需要处理。
* 在预算耗尽期间，任务的执行可能会出现延迟。
* 通过调整 Field Trial 参数，可以控制节流的强度和响应速度。

**用户或编程常见的使用错误:**

1. **忘记注册/取消注册 WorkerScheduler:** 如果在创建或销毁 `WorkerSchedulerImpl` 实例时，没有正确调用 `RegisterWorkerScheduler` 和 `UnregisterWorkerScheduler`，可能会导致生命周期状态变化通知无法正确传递，或者在 `WorkerThreadScheduler` 析构时发生断言失败。

   ```c++
   // 错误示例: 创建了 WorkerSchedulerImpl 但没有注册
   auto worker_scheduler = base::MakeRefCounted<WorkerSchedulerImpl>(...);
   // ... 没有调用 GetWorkerThreadScheduler()->RegisterWorkerScheduler(worker_scheduler.get());

   // 正确示例:
   auto worker_scheduler = base::MakeRefCounted<WorkerSchedulerImpl>(...);
   GetWorkerThreadScheduler()->RegisterWorkerScheduler(worker_scheduler.get());
   // ... 在适当的时候
   GetWorkerThreadScheduler()->UnregisterWorkerScheduler(worker_scheduler.get());
   ```

2. **在错误的 TaskRunner 上执行任务:**  如果在需要访问 V8 Isolate 的任务中使用了默认的 TaskRunner，可能会导致错误，因为 V8 Isolate 不是线程安全的。应该使用 `V8TaskRunner()` 返回的 TaskRunner 执行 JavaScript 相关的任务。

   ```c++
   // 错误示例: 在默认队列上执行 V8 相关任务
   GetWorkerThreadScheduler()->DefaultTaskQueue()->PostTask(FROM_HERE, base::BindOnce([]() {
     v8::Isolate::GetCurrent()->... // 可能会崩溃或产生未定义行为
   }));

   // 正确示例: 使用 V8 队列
   GetWorkerThreadScheduler()->V8TaskRunner()->PostTask(FROM_HERE, base::BindOnce([]() {
     v8::Isolate::GetCurrent()->...
   }));
   ```

3. **不理解节流的影响:**  开发者可能没有意识到 Dedicated Worker 的节流机制，导致在某些情况下 Worker 的任务执行速度变慢。这通常发生在 Worker 处于后台并且有大量 CPU 密集型任务需要处理时。理解节流参数的含义并根据应用的需求进行配置是很重要的。

4. **过度依赖同步操作:** 虽然 Worker 线程可以执行长时间运行的任务而不会阻塞主线程，但过度使用同步操作仍然可能导致 Worker 线程自身的阻塞，影响其响应能力。应该尽量使用异步操作和任务调度来提高 Worker 的效率。

总而言之，`WorkerThreadScheduler` 是 Blink 引擎中管理 Worker 线程任务执行的关键组件，它负责任务的排队、调度、性能监控以及资源管理（通过节流）。理解它的功能对于开发高性能的 Web 应用，特别是涉及到 Web Workers 的应用至关重要。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/worker/worker_thread_scheduler.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/worker/worker_thread_scheduler.h"

#include <memory>

#include "base/containers/contains.h"
#include "base/functional/bind.h"
#include "base/metrics/field_trial_params.h"
#include "base/metrics/histogram_macros.h"
#include "base/strings/string_number_conversions.h"
#include "base/task/sequence_manager/sequence_manager.h"
#include "base/task/sequence_manager/task_queue.h"
#include "base/task/single_thread_task_runner.h"
#include "base/trace_event/trace_event.h"
#include "base/trace_event/traced_value.h"
#include "mojo/public/cpp/bindings/pending_remote.h"
#include "services/metrics/public/cpp/mojo_ukm_recorder.h"
#include "services/metrics/public/cpp/ukm_builders.h"
#include "third_party/blink/public/common/thread_safe_browser_interface_broker_proxy.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/scheduler/common/auto_advancing_virtual_time_domain.h"
#include "third_party/blink/renderer/platform/scheduler/common/features.h"
#include "third_party/blink/renderer/platform/scheduler/common/metrics_helper.h"
#include "third_party/blink/renderer/platform/scheduler/common/process_state.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/cpu_time_budget_pool.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/task_queue_throttler.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/wake_up_budget_pool.h"
#include "third_party/blink/renderer/platform/scheduler/public/event_loop.h"
#include "third_party/blink/renderer/platform/scheduler/worker/non_main_thread_scheduler_helper.h"
#include "third_party/blink/renderer/platform/scheduler/worker/worker_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/worker/worker_scheduler_proxy.h"

namespace blink {
namespace scheduler {

using base::sequence_manager::TaskQueue;

namespace {

// Worker throttling trial
const char kWorkerThrottlingTrial[] = "BlinkSchedulerDedicatedWorkerThrottling";
const char kWorkerThrottlingMaxBudgetParam[] = "max_budget_ms";
const char kWorkerThrottlingRecoveryRateParam[] = "recovery_rate";
const char kWorkerThrottlingMaxDelayParam[] = "max_delay_ms";

constexpr base::TimeDelta kDefaultMaxBudget = base::Seconds(1);
constexpr double kDefaultRecoveryRate = 0.01;
constexpr base::TimeDelta kDefaultMaxThrottlingDelay = base::Seconds(60);

std::optional<base::TimeDelta> GetMaxBudgetLevel() {
  int max_budget_level_ms;
  if (!base::StringToInt(
          base::GetFieldTrialParamValue(kWorkerThrottlingTrial,
                                        kWorkerThrottlingMaxBudgetParam),
          &max_budget_level_ms)) {
    return kDefaultMaxBudget;
  }
  if (max_budget_level_ms < 0)
    return std::nullopt;
  return base::Milliseconds(max_budget_level_ms);
}

double GetBudgetRecoveryRate() {
  double recovery_rate;
  if (!base::StringToDouble(
          base::GetFieldTrialParamValue(kWorkerThrottlingTrial,
                                        kWorkerThrottlingRecoveryRateParam),
          &recovery_rate)) {
    return kDefaultRecoveryRate;
  }
  return recovery_rate;
}

std::optional<base::TimeDelta> GetMaxThrottlingDelay() {
  int max_throttling_delay_ms;
  if (!base::StringToInt(
          base::GetFieldTrialParamValue(kWorkerThrottlingTrial,
                                        kWorkerThrottlingMaxDelayParam),
          &max_throttling_delay_ms)) {
    return kDefaultMaxThrottlingDelay;
  }
  if (max_throttling_delay_ms < 0)
    return std::nullopt;
  return base::Milliseconds(max_throttling_delay_ms);
}

std::unique_ptr<ukm::MojoUkmRecorder> CreateMojoUkmRecorder() {
  mojo::Remote<ukm::mojom::UkmRecorderFactory> factory;
  Platform::Current()->GetBrowserInterfaceBroker()->GetInterface(
      factory.BindNewPipeAndPassReceiver());
  return ukm::MojoUkmRecorder::Create(*factory);
}

}  // namespace

WorkerThreadScheduler::WorkerThreadScheduler(
    ThreadType thread_type,
    base::sequence_manager::SequenceManager* sequence_manager,
    WorkerSchedulerProxy* proxy)
    : NonMainThreadSchedulerBase(sequence_manager,
                                 TaskType::kWorkerThreadTaskQueueDefault),
      thread_type_(thread_type),
      idle_helper_queue_(GetHelper().NewTaskQueue(
          TaskQueue::Spec(base::sequence_manager::QueueName::WORKER_IDLE_TQ))),
      idle_helper_(&GetHelper(),
                   this,
                   "WorkerSchedulerIdlePeriod",
                   base::Milliseconds(300),
                   idle_helper_queue_->GetTaskQueue()),
      lifecycle_state_(proxy ? proxy->lifecycle_state()
                             : SchedulingLifecycleState::kNotThrottled),
      initial_frame_status_(proxy ? proxy->initial_frame_status()
                                  : FrameStatus::kNone),
      ukm_source_id_(proxy ? proxy->ukm_source_id() : ukm::kInvalidSourceId) {
  if (thread_type == ThreadType::kDedicatedWorkerThread &&
      base::FeatureList::IsEnabled(kDedicatedWorkerThrottling)) {
    CreateBudgetPools();
  }

  GetHelper().SetObserver(this);

  TRACE_EVENT_OBJECT_CREATED_WITH_ID(
      TRACE_DISABLED_BY_DEFAULT("worker.scheduler"), "WorkerScheduler", this);
}

WorkerThreadScheduler::~WorkerThreadScheduler() {
  TRACE_EVENT_OBJECT_DELETED_WITH_ID(
      TRACE_DISABLED_BY_DEFAULT("worker.scheduler"), "WorkerScheduler", this);

  DCHECK(worker_schedulers_.empty());
}

scoped_refptr<SingleThreadIdleTaskRunner>
WorkerThreadScheduler::IdleTaskRunner() {
  DCHECK(initialized_);
  return idle_helper_.IdleTaskRunner();
}

scoped_refptr<base::SingleThreadTaskRunner>
WorkerThreadScheduler::V8TaskRunner() {
  DCHECK(initialized_);
  return v8_task_runner_;
}

scoped_refptr<base::SingleThreadTaskRunner>
WorkerThreadScheduler::CleanupTaskRunner() {
  return DefaultTaskQueue()->GetTaskRunnerWithDefaultTaskType();
}

scoped_refptr<base::SingleThreadTaskRunner>
WorkerThreadScheduler::CompositorTaskRunner() {
  DCHECK(initialized_);
  return compositor_task_runner_;
}

bool WorkerThreadScheduler::ShouldYieldForHighPriorityWork() {
  // We don't consider any work as being high priority on workers.
  return false;
}

void WorkerThreadScheduler::AddTaskObserver(base::TaskObserver* task_observer) {
  DCHECK(initialized_);
  GetHelper().AddTaskObserver(task_observer);
}

void WorkerThreadScheduler::RemoveTaskObserver(
    base::TaskObserver* task_observer) {
  DCHECK(initialized_);
  GetHelper().RemoveTaskObserver(task_observer);
}

void WorkerThreadScheduler::Shutdown() {
  DCHECK(initialized_);
  ThreadSchedulerBase::Shutdown();
  idle_helper_.Shutdown();
  idle_helper_queue_->ShutdownTaskQueue();
  GetHelper().Shutdown();
}

scoped_refptr<NonMainThreadTaskQueue>
WorkerThreadScheduler::DefaultTaskQueue() {
  DCHECK(initialized_);
  return GetHelper().DefaultNonMainThreadTaskQueue();
}

void WorkerThreadScheduler::Init() {
  initialized_ = true;
  idle_helper_.EnableLongIdlePeriod();

  v8_task_runner_ =
      DefaultTaskQueue()->CreateTaskRunner(TaskType::kWorkerThreadTaskQueueV8);
  compositor_task_runner_ = DefaultTaskQueue()->CreateTaskRunner(
      TaskType::kWorkerThreadTaskQueueCompositor);
}

void WorkerThreadScheduler::OnTaskCompleted(
    NonMainThreadTaskQueue* task_queue,
    const base::sequence_manager::Task& task,
    TaskQueue::TaskTiming* task_timing,
    base::LazyNow* lazy_now) {
  PerformMicrotaskCheckpoint();

  task_timing->RecordTaskEnd(lazy_now);
  DispatchOnTaskCompletionCallbacks();

  if (task_queue != nullptr)
    task_queue->OnTaskRunTimeReported(task_timing);

  RecordTaskUkm(task_queue, task, *task_timing);
}

SchedulerHelper* WorkerThreadScheduler::GetSchedulerHelperForTesting() {
  return &GetHelper();
}

bool WorkerThreadScheduler::CanEnterLongIdlePeriod(base::TimeTicks,
                                                   base::TimeDelta*) {
  return true;
}

base::TimeTicks WorkerThreadScheduler::CurrentIdleTaskDeadlineForTesting()
    const {
  return idle_helper_.CurrentIdleTaskDeadline();
}

void WorkerThreadScheduler::OnLifecycleStateChanged(
    SchedulingLifecycleState lifecycle_state) {
  if (lifecycle_state_ == lifecycle_state)
    return;
  lifecycle_state_ = lifecycle_state;

  for (WorkerScheduler* worker_scheduler : worker_schedulers_)
    worker_scheduler->OnLifecycleStateChanged(lifecycle_state);
}

void WorkerThreadScheduler::RegisterWorkerScheduler(
    WorkerSchedulerImpl* worker_scheduler) {
  worker_schedulers_.insert(worker_scheduler);
  worker_scheduler->OnLifecycleStateChanged(lifecycle_state_);
}

void WorkerThreadScheduler::UnregisterWorkerScheduler(
    WorkerSchedulerImpl* worker_scheduler) {
  DCHECK(base::Contains(worker_schedulers_, worker_scheduler));
  worker_schedulers_.erase(worker_scheduler);
}

scoped_refptr<NonMainThreadTaskQueue>
WorkerThreadScheduler::ControlTaskQueue() {
  return GetHelper().ControlNonMainThreadTaskQueue();
}

void WorkerThreadScheduler::CreateBudgetPools() {
  if (wake_up_budget_pool_ && cpu_time_budget_pool_)
    return;
  base::TimeTicks now = GetTickClock()->NowTicks();
  wake_up_budget_pool_ =
      std::make_unique<WakeUpBudgetPool>("worker_wake_up_pool");
  cpu_time_budget_pool_ = std::make_unique<CPUTimeBudgetPool>(
      "worker_cpu_time_pool", &traceable_variable_controller_, now);

  cpu_time_budget_pool_->SetMaxBudgetLevel(now, GetMaxBudgetLevel());
  cpu_time_budget_pool_->SetTimeBudgetRecoveryRate(now,
                                                   GetBudgetRecoveryRate());
  cpu_time_budget_pool_->SetMaxThrottlingDelay(now, GetMaxThrottlingDelay());
}

void WorkerThreadScheduler::RecordTaskUkm(
    NonMainThreadTaskQueue* worker_task_queue,
    const base::sequence_manager::Task& task,
    const base::sequence_manager::TaskQueue::TaskTiming& task_timing) {
  if (!GetHelper().ShouldRecordTaskUkm(task_timing.has_thread_time()))
    return;

  if (!ukm_recorder_)
    ukm_recorder_ = CreateMojoUkmRecorder();

  ukm::builders::RendererSchedulerTask builder(ukm_source_id_);

  builder.SetVersion(kUkmMetricVersion);
  builder.SetThreadType(static_cast<int>(thread_type_));

  builder.SetRendererBackgrounded(
      internal::ProcessState::Get()->is_process_backgrounded);
  builder.SetTaskType(task.task_type);
  builder.SetFrameStatus(static_cast<int>(initial_frame_status_));
  builder.SetTaskDuration(task_timing.wall_duration().InMicroseconds());

  if (task_timing.has_thread_time())
    builder.SetTaskCPUDuration(task_timing.thread_duration().InMicroseconds());

  builder.Record(ukm_recorder_.get());
}

void WorkerThreadScheduler::SetUkmRecorderForTest(
    std::unique_ptr<ukm::UkmRecorder> ukm_recorder) {
  ukm_recorder_ = std::move(ukm_recorder);
}

void WorkerThreadScheduler::SetUkmTaskSamplingRateForTest(double rate) {
  GetHelper().SetUkmTaskSamplingRateForTest(rate);
}

void WorkerThreadScheduler::SetCPUTimeBudgetPoolForTesting(
    std::unique_ptr<CPUTimeBudgetPool> cpu_time_budget_pool) {
  cpu_time_budget_pool_ = std::move(cpu_time_budget_pool);
}

HashSet<WorkerSchedulerImpl*>&
WorkerThreadScheduler::GetWorkerSchedulersForTesting() {
  return worker_schedulers_;
}

void WorkerThreadScheduler::PerformMicrotaskCheckpoint() {
  if (isolate())
    EventLoop::PerformIsolateGlobalMicrotasksCheckpoint(isolate());
}

base::SequencedTaskRunner* WorkerThreadScheduler::GetVirtualTimeTaskRunner() {
  // Note this is not Control task runner because it has task notifications
  // disabled.
  return DefaultTaskQueue()->GetTaskRunnerWithDefaultTaskType().get();
}

void WorkerThreadScheduler::OnVirtualTimeDisabled() {}

void WorkerThreadScheduler::OnVirtualTimePaused() {
  for (auto* worker_scheduler : worker_schedulers_) {
    worker_scheduler->PauseVirtualTime();
  }
}

void WorkerThreadScheduler::OnVirtualTimeResumed() {
  for (WorkerScheduler* worker_scheduler : worker_schedulers_) {
    auto* scheduler = static_cast<WorkerSchedulerImpl*>(worker_scheduler);
    scheduler->UnpauseVirtualTime();
  }
}

void WorkerThreadScheduler::PostIdleTask(const base::Location& location,
                                         Thread::IdleTask task) {
  IdleTaskRunner()->PostIdleTask(location, std::move(task));
}

void WorkerThreadScheduler::PostNonNestableIdleTask(
    const base::Location& location,
    Thread::IdleTask task) {
  IdleTaskRunner()->PostNonNestableIdleTask(location, std::move(task));
}

void WorkerThreadScheduler::PostDelayedIdleTask(const base::Location& location,
                                                base::TimeDelta delay,
                                                Thread::IdleTask task) {
  IdleTaskRunner()->PostDelayedIdleTask(location, delay, std::move(task));
}

base::TimeTicks WorkerThreadScheduler::MonotonicallyIncreasingVirtualTime() {
  return base::TimeTicks::Now();
}

void WorkerThreadScheduler::SetV8Isolate(v8::Isolate* isolate) {
  NonMainThreadSchedulerBase::SetV8Isolate(isolate);
}

}  // namespace scheduler
}  // namespace blink
```