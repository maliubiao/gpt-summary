Response: Let's break down the thought process for analyzing the `idle_helper.cc` file and generating the comprehensive explanation.

**1. Understanding the Core Purpose:**

The first step is to read the initial comments and the class name `IdleHelper`. The name immediately suggests its function: helping manage idle periods. The copyright notice and include statements indicate it's part of the Chromium Blink rendering engine and interacts with scheduling mechanisms.

**2. Identifying Key Components and Their Roles:**

Next, I'd scan the class members and their types. This gives a high-level overview of the helper's dependencies and internal state:

* `SchedulerHelper* helper_`: Likely a central class for scheduling tasks.
* `Delegate* delegate_`:  Indicates a pattern where `IdleHelper` informs another object about idle periods.
* `TaskQueue* idle_queue_`: A specific queue for idle-priority tasks.
* `State state_`: An internal object to manage the current idle period state.
* Various `base::TimeDelta` and boolean members: Related to timing and status.
* `scoped_refptr<SingleThreadIdleTaskRunner> idle_task_runner_`:  Responsible for running idle tasks.
* Closures (`base::RepeatingClosure`): Used for delayed task execution.

From this, I can infer that `IdleHelper` isn't just passively waiting; it actively manages when and how idle tasks are executed, based on input from `SchedulerHelper` and interactions with a `Delegate`.

**3. Analyzing Key Methods and Their Logic:**

Now, I'd go through the important methods, focusing on their functionality and interactions:

* **Constructor:**  Initializes members, sets up the idle task runner, and importantly, inserts a fence in the `idle_queue_` to initially block idle tasks. This suggests a controlled activation of idle work.
* **`EnableLongIdlePeriod()`:** This seems central to initiating longer idle periods. It checks for quiescence, calculates the duration, and potentially posts delayed tasks to retry. The logic involving `ShouldWaitForQuiescence()` is crucial for understanding its behavior.
* **`StartIdlePeriod()` and `EndIdlePeriod()`:** These methods manage the transitions into and out of idle states. The use of fences to control idle task execution within these methods is key.
* **`ComputeNewLongIdlePeriodState()`:**  Calculates the duration of a long idle period, taking into account pending tasks and a maximum duration.
* **`WillProcessTask()` and `DidProcessTask()`:**  These methods, part of a task observer pattern, react to the processing of non-idle tasks. `DidProcessTask` checks if an idle period deadline has been reached.
* **`OnIdleTaskPosted()` and `OnIdleTaskPostedOnMainThread()`:** Handle the posting of idle tasks and potentially restart long idle periods.
* **`WillProcessIdleTask()` and `DidProcessIdleTask()`:**  Manage the execution of individual idle tasks.
* **`State` Inner Class:** This encapsulates the idle period state, simplifying the main `IdleHelper` class. Its `UpdateState` and tracing methods are important for understanding how state changes are managed and debugged.

**4. Connecting to Web Technologies (JavaScript, HTML, CSS):**

With an understanding of the core functionality, I'd think about how this relates to web development:

* **JavaScript:** Idle tasks are prime candidates for executing less critical JavaScript code that shouldn't block user interaction (e.g., analytics, pre-rendering, background updates).
* **HTML/CSS:**  While `IdleHelper` doesn't directly manipulate HTML or CSS, its management of idle time can indirectly impact related processes like layout, rendering, and style recalculation. If these tasks are deferred to idle time, `IdleHelper` is involved.

**5. Deriving Examples and Use Cases:**

Based on the understanding of the methods and their purpose, I'd construct illustrative examples:

* **JavaScript:**  Demonstrate how `requestIdleCallback` in JavaScript maps to the idle periods managed by `IdleHelper`.
* **HTML/CSS:** Explain how delaying non-critical rendering tasks to idle time can improve initial page load performance.

**6. Identifying Potential Errors and Edge Cases:**

Consider how things could go wrong or be misused:

* **Overly Long Idle Tasks:** If an idle task takes too long, it can negate the benefits of idle scheduling and potentially interfere with more critical tasks.
* **Incorrect Quiescence Detection:** If the system isn't truly quiescent when an idle period starts, it might lead to unexpected behavior.
* **Shutdown Issues:** The `Shutdown()` method is important; not calling it properly could lead to resource leaks or undefined behavior.

**7. Formulating Assumptions, Inputs, and Outputs for Logic:**

For key logical sections, especially `ComputeNewLongIdlePeriodState()`, I would consider:

* **Inputs:** Current time, next wake-up time (if any), whether the delegate allows entering a long idle period.
* **Outputs:** The calculated idle period state and the delay until the next attempt to enter a long idle period.
* **Assumptions:**  That `helper_->GetNextWakeUp()` provides accurate information about pending tasks.

**8. Structuring the Explanation:**

Finally, I'd organize the information logically, starting with a high-level overview and then delving into specific aspects like functionality, relationships to web technologies, examples, errors, and logical deductions. Using clear headings and bullet points improves readability.

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Maybe `IdleHelper` just passively waits for the system to be idle.
* **Correction:**  The code shows it actively *manages* idle periods, setting deadlines and controlling when idle tasks can run using fences.
* **Initial thought:** The delegate is just a passive observer.
* **Correction:** The delegate provides important input via `CanEnterLongIdlePeriod` and is informed of state changes.

By iteratively analyzing the code, identifying key components, understanding their interactions, and relating them to the broader context of web technologies, a comprehensive and accurate explanation can be generated.
这个文件 `idle_helper.cc` 是 Chromium Blink 渲染引擎中 `scheduler` 组件的一部分，它主要负责管理和协调浏览器的空闲时间（idle time），以便在用户没有交互或者浏览器不忙的时候执行一些低优先级的任务。这有助于提高浏览器的响应性和性能，避免在关键操作期间执行耗时任务。

以下是 `idle_helper.cc` 的主要功能：

**1. 管理空闲期（Idle Period）:**

* **启动和结束空闲期:** `IdleHelper` 负责决定何时进入和退出空闲期。它可以根据一段时间内的系统空闲状态、是否有待执行的任务以及其他条件来判断。
* **区分长短空闲期:** 代码中提到了 "Long Idle Period" 和暗示的 "Short Idle Period"。长空闲期通常用于执行更长时间的、优先级更低的任务，而短空闲期可能用于更快速的清理或维护工作。
* **设置空闲期截止时间:**  `IdleHelper` 会为每个空闲期设置一个截止时间，确保即使在空闲期执行任务也不会无限期地占用资源，从而影响后续更重要的任务。

**2. 调度空闲任务（Idle Tasks）:**

* **维护一个空闲任务队列:**  虽然这个文件本身不直接管理队列，但它与 `idle_queue_` 关联，这个 `TaskQueue` 专门用于存放优先级较低的空闲任务。
* **控制空闲任务的执行:**  通过 `idle_task_runner_`，`IdleHelper` 可以在空闲期内执行排队的空闲任务。它使用 fences 机制来控制何时允许空闲任务运行。
* **延迟执行空闲任务:**  空闲任务通常不会立即执行，而是等到系统进入空闲状态后才开始执行。

**3. 与调度器（Scheduler）的其他部分交互:**

* **依赖 `SchedulerHelper`:** `IdleHelper` 依赖 `SchedulerHelper` 来获取当前时间、检查系统是否空闲、以及提交任务等。
* **使用 `Delegate` 模式:** `IdleHelper` 使用 `Delegate` 接口与外部组件通信，例如通知它们空闲期的开始和结束，以及是否有待处理的空闲任务。

**4. 跟踪和调试:**

* **使用 Trace Event:** 代码中大量使用了 `TRACE_EVENT` 宏，这允许开发者在 Chromium 的 tracing 系统中记录 `IdleHelper` 的状态和事件，方便调试和性能分析。

**与 JavaScript, HTML, CSS 的关系:**

`IdleHelper` 虽然不直接处理 JavaScript, HTML, CSS 的解析或渲染，但它影响着与这些技术相关的任务的执行时机，从而间接地影响用户体验。

**举例说明:**

* **JavaScript:**
    * **场景:** 网页加载完成后，需要执行一些非关键的 JavaScript 代码，例如发送分析数据、预加载下一个页面的资源或者进行一些后台更新。
    * **`IdleHelper` 的作用:**  这些任务可以作为空闲任务提交。`IdleHelper` 会在浏览器空闲时调度执行这些 JavaScript 代码，避免在用户正在交互时占用主线程资源，从而保持页面的流畅性。
    * **假设输入与输出:**
        * **假设输入:**  JavaScript 代码通过 `requestIdleCallback` API 请求在空闲时执行某个函数。Blink 内部会将这个请求转化为一个空闲任务提交到 `idle_queue_`。
        * **输出:** 当 `IdleHelper` 检测到浏览器进入空闲期，并且空闲期截止时间未到时，它会指示 `idle_task_runner_` 执行该 JavaScript 函数。

* **HTML/CSS:**
    * **场景:**  浏览器可能在空闲时进行一些与 HTML 或 CSS 相关的优化工作，例如清理不再使用的样式规则、预解析下一个可能加载的资源、或者进行一些布局优化。
    * **`IdleHelper` 的作用:** 这些优化任务可以作为空闲任务执行，避免在页面渲染的关键路径上增加负担。
    * **假设输入与输出:**
        * **假设输入:** 渲染引擎内部的某个模块决定在空闲时执行 CSS 规则的清理操作。
        * **输出:**  这个清理操作会被封装成一个空闲任务提交，并在 `IdleHelper` 管理的空闲期内被执行。

**逻辑推理的假设输入与输出:**

* **场景:** `EnableLongIdlePeriod()` 方法决定是否进入长空闲期。
    * **假设输入:**
        * `now`: 当前时间。
        * `delegate_->CanEnterLongIdlePeriod(now, &next_long_idle_period_delay)` 返回 `true`，表示可以进入长空闲期。
        * `helper_->GetNextWakeUp()` 返回一个未来的时间 `wake_up_time`，表示有即将到来的任务需要执行。
        * `wake_up_time - now > kMaximumIdlePeriod`。
        * `!idle_queue_->HasTaskToRunImmediatelyOrReadyDelayedTask()`，表示没有立即需要运行的空闲任务。
    * **输出:**
        * `ComputeNewLongIdlePeriodState` 将计算出 `long_idle_period_duration` 为 `kMaximumIdlePeriod`。
        * 返回 `IdlePeriodState::kInLongIdlePeriodPaused`，因为虽然可以进入长空闲期，但当前没有需要立即执行的空闲任务，所以进入暂停状态。

* **场景:** `DidProcessTask()` 方法在处理完一个非空闲任务后被调用。
    * **假设输入:**
        * `state_.idle_period_state()` 为 `IdlePeriodState::kInLongIdlePeriod`。
        * `helper_->NowTicks()` 大于等于 `state_.idle_period_deadline()`。
    * **输出:**
        * `EnableLongIdlePeriod()` 将被调用，尝试开始一个新的长空闲期。

**用户或编程常见的使用错误:**

* **错误地提交高优先级任务到空闲队列:** 开发者可能会错误地将对性能有关键影响的任务提交到空闲队列。这些任务只有在浏览器空闲时才会被执行，导致不必要的延迟。
    * **例子:** 将处理用户输入的关键逻辑错误地提交为空闲任务，导致用户交互无响应。
* **空闲任务执行时间过长:**  如果提交的空闲任务执行时间过长，可能会导致浏览器即使在用户无交互时也无法真正进入空闲状态，影响后续空闲任务的执行或系统资源的回收。
    * **例子:**  一个分析任务需要处理大量数据，导致空闲期持续很长时间，阻止了其他潜在的优化操作。
* **对 `Delegate` 接口的错误实现:**  如果 `Delegate` 的实现不正确，可能会导致 `IdleHelper` 无法正确判断是否可以进入空闲期，或者无法及时收到空闲期开始和结束的通知。
    * **例子:** `CanEnterLongIdlePeriod` 方法的实现总是返回 `false`，导致永远无法进入长空闲期。
* **在不应该的时候调用 `Shutdown()`:**  过早或在不正确的时机调用 `Shutdown()` 方法可能会导致 `IdleHelper` 提前停止工作，影响依赖空闲期执行的任务。

总的来说，`idle_helper.cc` 负责精细化地管理浏览器的空闲时间，允许开发者利用这些空闲时间执行低优先级的任务，从而在不影响用户体验的前提下提高浏览器的效率和性能。正确理解和使用 `IdleHelper` 的机制对于构建高性能的 web 应用至关重要。

Prompt: 
```
这是目录为blink/renderer/platform/scheduler/common/idle_helper.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/common/idle_helper.h"

#include "base/feature_list.h"
#include "base/functional/bind.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/sequence_manager/sequence_manager.h"
#include "base/task/sequence_manager/task_queue.h"
#include "base/task/sequence_manager/time_domain.h"
#include "base/task/single_thread_task_runner.h"
#include "base/time/time.h"
#include "base/trace_event/trace_event.h"
#include "base/trace_event/traced_value.h"
#include "third_party/blink/renderer/platform/scheduler/common/blink_scheduler_single_thread_task_runner.h"
#include "third_party/blink/renderer/platform/scheduler/common/scheduler_helper.h"
#include "third_party/blink/renderer/platform/scheduler/common/task_priority.h"

namespace blink {
namespace scheduler {

using base::sequence_manager::TaskQueue;

// static
constexpr base::TimeDelta IdleHelper::kMaximumIdlePeriod;

IdleHelper::IdleHelper(
    SchedulerHelper* helper,
    Delegate* delegate,
    const char* idle_period_tracing_name,
    base::TimeDelta required_quiescence_duration_before_long_idle_period,
    TaskQueue* idle_queue)
    : helper_(helper),
      delegate_(delegate),
      idle_queue_(idle_queue),
      state_(helper, delegate, idle_period_tracing_name),
      required_quiescence_duration_before_long_idle_period_(
          required_quiescence_duration_before_long_idle_period),
      is_shutdown_(false) {
  weak_idle_helper_ptr_ = weak_factory_.GetWeakPtr();
  enable_next_long_idle_period_closure_.Reset(base::BindRepeating(
      &IdleHelper::EnableLongIdlePeriod, weak_idle_helper_ptr_));
  on_idle_task_posted_closure_.Reset(base::BindRepeating(
      &IdleHelper::OnIdleTaskPostedOnMainThread, weak_idle_helper_ptr_));
  idle_task_runner_ = base::MakeRefCounted<SingleThreadIdleTaskRunner>(
      base::MakeRefCounted<BlinkSchedulerSingleThreadTaskRunner>(
          idle_queue_->CreateTaskRunner(
              static_cast<int>(TaskType::kMainThreadTaskQueueIdle)),
          nullptr),
      helper_->ControlTaskRunner(), this);
  // This fence will block any idle tasks from running.
  idle_queue_->InsertFence(TaskQueue::InsertFencePosition::kBeginningOfTime);
  idle_queue_->SetQueuePriority(TaskPriority::kBestEffortPriority);
}

IdleHelper::~IdleHelper() {
  Shutdown();
}

void IdleHelper::Shutdown() {
  if (is_shutdown_)
    return;

  EndIdlePeriod();
  is_shutdown_ = true;
  weak_factory_.InvalidateWeakPtrs();
}

IdleHelper::Delegate::Delegate() = default;

IdleHelper::Delegate::~Delegate() = default;

scoped_refptr<SingleThreadIdleTaskRunner> IdleHelper::IdleTaskRunner() {
  return idle_task_runner_;
}

IdleHelper::IdlePeriodState IdleHelper::ComputeNewLongIdlePeriodState(
    const base::TimeTicks now,
    base::TimeDelta* next_long_idle_period_delay_out) {
  helper_->CheckOnValidThread();

  if (!delegate_->CanEnterLongIdlePeriod(now,
                                         next_long_idle_period_delay_out)) {
    return IdlePeriodState::kNotInIdlePeriod;
  }

  auto wake_up = helper_->GetNextWakeUp();

  base::TimeDelta long_idle_period_duration;

  if (wake_up) {
    // Limit the idle period duration to be before the next pending task.
    long_idle_period_duration =
        std::min(wake_up->time - now, kMaximumIdlePeriod);
  } else {
    long_idle_period_duration = kMaximumIdlePeriod;
  }

  if (long_idle_period_duration >=
      base::Milliseconds(kMinimumIdlePeriodDurationMillis)) {
    *next_long_idle_period_delay_out = long_idle_period_duration;
    if (!idle_queue_->HasTaskToRunImmediatelyOrReadyDelayedTask())
      return IdlePeriodState::kInLongIdlePeriodPaused;
    if (long_idle_period_duration == kMaximumIdlePeriod)
      return IdlePeriodState::kInLongIdlePeriodWithMaxDeadline;
    return IdlePeriodState::kInLongIdlePeriod;
  } else {
    // If we can't start the idle period yet then try again after wake-up.
    *next_long_idle_period_delay_out =
        base::Milliseconds(kRetryEnableLongIdlePeriodDelayMillis);
    return IdlePeriodState::kNotInIdlePeriod;
  }
}

bool IdleHelper::ShouldWaitForQuiescence() {
  helper_->CheckOnValidThread();

  if (required_quiescence_duration_before_long_idle_period_ ==
      base::TimeDelta()) {
    return false;
  }

  bool system_is_quiescent = helper_->GetAndClearSystemIsQuiescentBit();
  TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "ShouldWaitForQuiescence", "system_is_quiescent",
               system_is_quiescent);
  return !system_is_quiescent;
}

void IdleHelper::EnableLongIdlePeriod() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "EnableLongIdlePeriod");
  helper_->CheckOnValidThread();
  if (is_shutdown_)
    return;

  // End any previous idle period.
  EndIdlePeriod();

  if (ShouldWaitForQuiescence()) {
    helper_->ControlTaskRunner()->PostDelayedTask(
        FROM_HERE, enable_next_long_idle_period_closure_.GetCallback(),
        required_quiescence_duration_before_long_idle_period_);
    delegate_->IsNotQuiescent();
    return;
  }

  base::TimeTicks now(helper_->NowTicks());
  base::TimeDelta next_long_idle_period_delay;
  IdlePeriodState new_idle_period_state =
      ComputeNewLongIdlePeriodState(now, &next_long_idle_period_delay);
  if (IsInIdlePeriod(new_idle_period_state)) {
    StartIdlePeriod(new_idle_period_state, now,
                    now + next_long_idle_period_delay);
  } else {
    // Otherwise wait for the next long idle period delay before trying again.
    helper_->ControlTaskRunner()->PostDelayedTask(
        FROM_HERE, enable_next_long_idle_period_closure_.GetCallback(),
        next_long_idle_period_delay);
  }
}

void IdleHelper::StartIdlePeriod(IdlePeriodState new_state,
                                 base::TimeTicks now,
                                 base::TimeTicks idle_period_deadline) {
  DCHECK(!is_shutdown_);
  DCHECK_GT(idle_period_deadline, now);
  helper_->CheckOnValidThread();
  DCHECK(IsInIdlePeriod(new_state));

  // Allow any ready delayed idle tasks to run.
  idle_task_runner_->EnqueueReadyDelayedIdleTasks();

  base::TimeDelta idle_period_duration(idle_period_deadline - now);
  if (idle_period_duration <
      base::Milliseconds(kMinimumIdlePeriodDurationMillis)) {
    TRACE_EVENT1(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
                 "NotStartingIdlePeriodBecauseDeadlineIsTooClose",
                 "idle_period_duration_ms",
                 idle_period_duration.InMillisecondsF());
    return;
  }

  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "StartIdlePeriod");
  if (!IsInIdlePeriod(state_.idle_period_state()))
    helper_->AddTaskObserver(this);

  // Use a fence to make sure any idle tasks posted after this point do not run
  // until the next idle period and unblock existing tasks.
  idle_queue_->InsertFence(TaskQueue::InsertFencePosition::kNow);

  state_.UpdateState(new_state, idle_period_deadline, now);
}

void IdleHelper::EndIdlePeriod() {
  if (is_shutdown_)
    return;

  helper_->CheckOnValidThread();
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "EndIdlePeriod");

  enable_next_long_idle_period_closure_.Cancel();
  on_idle_task_posted_closure_.Cancel();

  // If we weren't already within an idle period then early-out.
  if (!IsInIdlePeriod(state_.idle_period_state()))
    return;

  helper_->RemoveTaskObserver(this);

  // This fence will block any idle tasks from running.
  idle_queue_->InsertFence(TaskQueue::InsertFencePosition::kBeginningOfTime);
  state_.UpdateState(IdlePeriodState::kNotInIdlePeriod, base::TimeTicks(),
                     base::TimeTicks());
}

void IdleHelper::WillProcessTask(const base::PendingTask& pending_task,
                                 bool was_blocked_or_low_priority) {
  DCHECK(!is_shutdown_);
}

void IdleHelper::DidProcessTask(const base::PendingTask& pending_task) {
  helper_->CheckOnValidThread();
  DCHECK(!is_shutdown_);
  DCHECK(IsInIdlePeriod(state_.idle_period_state()));
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "DidProcessTask");
  if (state_.idle_period_state() != IdlePeriodState::kInLongIdlePeriodPaused &&
      helper_->NowTicks() >= state_.idle_period_deadline()) {
    // If the idle period deadline has now been reached, either end the idle
    // period or trigger a new long-idle period.
    if (IsInLongIdlePeriod(state_.idle_period_state())) {
      EnableLongIdlePeriod();
    } else {
      DCHECK(IdlePeriodState::kInShortIdlePeriod == state_.idle_period_state());
      EndIdlePeriod();
    }
  }
}

void IdleHelper::UpdateLongIdlePeriodStateAfterIdleTask() {
  helper_->CheckOnValidThread();
  DCHECK(!is_shutdown_);
  DCHECK(IsInLongIdlePeriod(state_.idle_period_state()));
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "UpdateLongIdlePeriodStateAfterIdleTask");

  if (!idle_queue_->HasTaskToRunImmediatelyOrReadyDelayedTask()) {
    // If there are no more idle tasks then pause long idle period ticks until a
    // new idle task is posted.
    state_.UpdateState(IdlePeriodState::kInLongIdlePeriodPaused,
                       state_.idle_period_deadline(), base::TimeTicks());
  } else if (idle_queue_->BlockedByFence()) {
    // If there is still idle work to do then just start the next idle period.
    base::TimeDelta next_long_idle_period_delay;
    // Ensure that we kick the scheduler at the right time to
    // initiate the next idle period.
    next_long_idle_period_delay = std::max(
        base::TimeDelta(), state_.idle_period_deadline() - helper_->NowTicks());
    if (next_long_idle_period_delay.is_zero()) {
      EnableLongIdlePeriod();
    } else {
      helper_->ControlTaskRunner()->PostDelayedTask(
          FROM_HERE, enable_next_long_idle_period_closure_.GetCallback(),
          next_long_idle_period_delay);
    }
  }
}

base::TimeTicks IdleHelper::CurrentIdleTaskDeadline() const {
  helper_->CheckOnValidThread();
  return state_.idle_period_deadline();
}

void IdleHelper::OnIdleTaskPosted() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "OnIdleTaskPosted");
  if (is_shutdown_)
    return;
  if (idle_task_runner_->RunsTasksInCurrentSequence()) {
    OnIdleTaskPostedOnMainThread();
  } else {
    helper_->ControlTaskRunner()->PostTask(
        FROM_HERE, on_idle_task_posted_closure_.GetCallback());
  }
}

void IdleHelper::OnIdleTaskPostedOnMainThread() {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "OnIdleTaskPostedOnMainThread");
  if (is_shutdown_)
    return;
  delegate_->OnPendingTasksChanged(true);
  if (state_.idle_period_state() == IdlePeriodState::kInLongIdlePeriodPaused) {
    // Restart long idle period ticks.
    helper_->ControlTaskRunner()->PostTask(
        FROM_HERE, enable_next_long_idle_period_closure_.GetCallback());
  }
}

base::TimeTicks IdleHelper::WillProcessIdleTask() {
  helper_->CheckOnValidThread();
  DCHECK(!is_shutdown_);
  state_.TraceIdleIdleTaskStart();
  return CurrentIdleTaskDeadline();
}

void IdleHelper::DidProcessIdleTask() {
  helper_->CheckOnValidThread();
  if (is_shutdown_)
    return;
  state_.TraceIdleIdleTaskEnd();
  if (IsInLongIdlePeriod(state_.idle_period_state())) {
    UpdateLongIdlePeriodStateAfterIdleTask();
  }
  delegate_->OnPendingTasksChanged(idle_queue_->GetNumberOfPendingTasks() > 0);
}

base::TimeTicks IdleHelper::NowTicks() {
  return helper_->NowTicks();
}

// static
bool IdleHelper::IsInIdlePeriod(IdlePeriodState state) {
  return state != IdlePeriodState::kNotInIdlePeriod;
}

// static
bool IdleHelper::IsInLongIdlePeriod(IdlePeriodState state) {
  return state == IdlePeriodState::kInLongIdlePeriod ||
         state == IdlePeriodState::kInLongIdlePeriodWithMaxDeadline ||
         state == IdlePeriodState::kInLongIdlePeriodPaused;
}

bool IdleHelper::CanExceedIdleDeadlineIfRequired() const {
  TRACE_EVENT0(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "CanExceedIdleDeadlineIfRequired");
  helper_->CheckOnValidThread();
  return state_.idle_period_state() ==
         IdlePeriodState::kInLongIdlePeriodWithMaxDeadline;
}

IdleHelper::IdlePeriodState IdleHelper::SchedulerIdlePeriodState() const {
  return state_.idle_period_state();
}

IdleHelper::State::State(SchedulerHelper* helper,
                         Delegate* delegate,
                         const char* idle_period_tracing_name)
    : helper_(helper),
      delegate_(delegate),
      idle_period_state_(IdlePeriodState::kNotInIdlePeriod),
      idle_period_trace_event_started_(false),
      running_idle_task_for_tracing_(false),
      idle_period_tracing_name_(idle_period_tracing_name) {}

IdleHelper::State::~State() = default;

IdleHelper::IdlePeriodState IdleHelper::State::idle_period_state() const {
  helper_->CheckOnValidThread();
  return idle_period_state_;
}

base::TimeTicks IdleHelper::State::idle_period_deadline() const {
  helper_->CheckOnValidThread();
  return idle_period_deadline_;
}

void IdleHelper::State::UpdateState(IdlePeriodState new_state,
                                    base::TimeTicks new_deadline,
                                    base::TimeTicks optional_now) {
  IdlePeriodState old_idle_period_state = idle_period_state_;

  helper_->CheckOnValidThread();
  if (new_state == idle_period_state_) {
    DCHECK_EQ(new_deadline, idle_period_deadline_);
    return;
  }

  bool is_tracing;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED("renderer.scheduler", &is_tracing);
  if (is_tracing) {
    base::TimeTicks now(optional_now.is_null() ? helper_->NowTicks()
                                               : optional_now);
    TraceEventIdlePeriodStateChange(new_state, running_idle_task_for_tracing_,
                                    new_deadline, now);
  }

  idle_period_state_ = new_state;
  idle_period_deadline_ = new_deadline;

  // Inform the delegate if we are starting or ending an idle period.
  if (IsInIdlePeriod(new_state) && !IsInIdlePeriod(old_idle_period_state)) {
    delegate_->OnIdlePeriodStarted();
  } else if (!IsInIdlePeriod(new_state) &&
             IsInIdlePeriod(old_idle_period_state)) {
    delegate_->OnIdlePeriodEnded();
  }
}

void IdleHelper::State::TraceIdleIdleTaskStart() {
  helper_->CheckOnValidThread();

  bool is_tracing;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED("renderer.scheduler", &is_tracing);
  if (is_tracing) {
    TraceEventIdlePeriodStateChange(idle_period_state_, true,
                                    idle_period_deadline_,
                                    base::TimeTicks::Now());
  }
}

void IdleHelper::State::TraceIdleIdleTaskEnd() {
  helper_->CheckOnValidThread();

  bool is_tracing;
  TRACE_EVENT_CATEGORY_GROUP_ENABLED("renderer.scheduler", &is_tracing);
  if (is_tracing) {
    TraceEventIdlePeriodStateChange(idle_period_state_, false,
                                    idle_period_deadline_,
                                    base::TimeTicks::Now());
  }
}

void IdleHelper::State::TraceEventIdlePeriodStateChange(
    IdlePeriodState new_state,
    bool new_running_idle_task,
    base::TimeTicks new_deadline,
    base::TimeTicks now) {
  TRACE_EVENT2(TRACE_DISABLED_BY_DEFAULT("renderer.scheduler"),
               "SetIdlePeriodState", "old_state",
               IdleHelper::IdlePeriodStateToString(idle_period_state_),
               "new_state", IdleHelper::IdlePeriodStateToString(new_state));

  if (idle_period_trace_event_started_ && running_idle_task_for_tracing_ &&
      !new_running_idle_task) {
    running_idle_task_for_tracing_ = false;
    if (!idle_period_deadline_.is_null() && now > idle_period_deadline_) {
      if (last_sub_trace_event_name_) {
        TRACE_EVENT_NESTABLE_ASYNC_END0("renderer.scheduler",
                                        last_sub_trace_event_name_,
                                        TRACE_ID_LOCAL(this));
      }
      last_sub_trace_event_name_ = "DeadlineOverrun";
      TRACE_EVENT_NESTABLE_ASYNC_BEGIN_WITH_TIMESTAMP0(
          "renderer.scheduler", last_sub_trace_event_name_,
          TRACE_ID_LOCAL(this),
          std::max(idle_period_deadline_, last_idle_task_trace_time_));
    }
  }

  if (IsInIdlePeriod(new_state)) {
    if (!idle_period_trace_event_started_) {
      idle_period_trace_event_started_ = true;
      TRACE_EVENT_NESTABLE_ASYNC_BEGIN1(
          "renderer.scheduler", idle_period_tracing_name_, TRACE_ID_LOCAL(this),
          "idle_period_length_ms", (new_deadline - now).InMillisecondsF());
    }

    const char* new_sub_trace_event_name = nullptr;

    if (new_running_idle_task) {
      last_idle_task_trace_time_ = now;
      running_idle_task_for_tracing_ = true;
      new_sub_trace_event_name = "RunningIdleTask";
    } else if (new_state == IdlePeriodState::kInShortIdlePeriod) {
      new_sub_trace_event_name = "ShortIdlePeriod";
    } else if (IsInLongIdlePeriod(new_state) &&
               new_state != IdlePeriodState::kInLongIdlePeriodPaused) {
      new_sub_trace_event_name = "LongIdlePeriod";
    } else if (new_state == IdlePeriodState::kInLongIdlePeriodPaused) {
      new_sub_trace_event_name = "LongIdlePeriodPaused";
    }

    if (new_sub_trace_event_name) {
      if (last_sub_trace_event_name_) {
        TRACE_EVENT_NESTABLE_ASYNC_END0("renderer.scheduler",
                                        last_sub_trace_event_name_,
                                        TRACE_ID_LOCAL(this));
      }
      TRACE_EVENT_NESTABLE_ASYNC_BEGIN0(
          "renderer.scheduler", new_sub_trace_event_name, TRACE_ID_LOCAL(this));
      last_sub_trace_event_name_ = new_sub_trace_event_name;
    }
  } else if (idle_period_trace_event_started_) {
    if (last_sub_trace_event_name_) {
      TRACE_EVENT_NESTABLE_ASYNC_END0("renderer.scheduler",
                                      last_sub_trace_event_name_,
                                      TRACE_ID_LOCAL(this));
      last_sub_trace_event_name_ = nullptr;
    }
    TRACE_EVENT_NESTABLE_ASYNC_END0(
        "renderer.scheduler", idle_period_tracing_name_, TRACE_ID_LOCAL(this));
    idle_period_trace_event_started_ = false;
  }
}

// static
const char* IdleHelper::IdlePeriodStateToString(
    IdlePeriodState idle_period_state) {
  switch (idle_period_state) {
    case IdlePeriodState::kNotInIdlePeriod:
      return "not_in_idle_period";
    case IdlePeriodState::kInShortIdlePeriod:
      return "in_short_idle_period";
    case IdlePeriodState::kInLongIdlePeriod:
      return "in_long_idle_period";
    case IdlePeriodState::kInLongIdlePeriodWithMaxDeadline:
      return "in_long_idle_period_with_max_deadline";
    case IdlePeriodState::kInLongIdlePeriodPaused:
      return "in_long_idle_period_paused";
    default:
      NOTREACHED();
  }
}

}  // namespace scheduler
}  // namespace blink

"""

```