Response: Let's break down the thought process for analyzing this C++ code snippet.

1. **Understand the Context:** The file path `blink/renderer/platform/scheduler/test/fuzzer/thread_manager.cc` immediately tells us this code is part of the Blink rendering engine (Chrome's rendering engine), specifically within the scheduler component, for testing purposes (fuzzer). This suggests it's not core rendering logic but infrastructure to *simulate* and test scheduling behavior.

2. **Identify the Core Class:** The prominent class is `ThreadManager`. This will likely be the central focus of the analysis.

3. **High-Level Functionality Scan:** Read through the class definition and the methods. Look for keywords and class names that suggest the purpose of different parts of the code. We see:
    * `TestMockTimeTaskRunner`:  Indicates control over simulated time.
    * `SequenceManagerForTest`:  Suggests this is a testing-specific version of a real sequence manager.
    * `TaskQueue`:  Deals with managing queues of tasks.
    * `PostDelayedTask`, `ExecuteTask`: Task scheduling and execution.
    * `SetQueuePriority`, `SetQueueEnabled`: Manipulating task queue properties.
    * `CreateThread`, `CrossThreadPost`: Handling multiple threads.
    * `InsertFence`, `RemoveFence`:  Mechanisms for controlling task execution order.
    * `Action` (from `SequenceManagerTestDescription`):  Driven by external input, suggesting a fuzzer.

4. **Connect to Web Technologies (if applicable):** Consider how the concepts in the code relate to JavaScript, HTML, and CSS.
    * **JavaScript:**  JavaScript execution heavily relies on an event loop and task queue. This `ThreadManager` seems to be a low-level simulation of that kind of system. Things like `setTimeout` and promises are ultimately scheduled as tasks.
    * **HTML/CSS:**  Rendering and layout are also task-based. When the browser parses HTML or calculates CSS styles, it schedules tasks to perform these operations. While this code doesn't directly *perform* rendering, it simulates the scheduling of those kinds of tasks.

5. **Fuzzer Aspect:** Recognize that the "fuzzer" context means the `ThreadManager` is designed to be driven by random or semi-random inputs. The `SequenceManagerTestDescription` likely defines the possible actions the fuzzer can take. This implies the code needs to be robust against unexpected sequences of operations.

6. **Detailed Method Analysis (Focus on key methods):**  Go through the methods identified in the high-level scan, understanding their specific purpose. Pay attention to:
    * **Constructor:** How is the `ThreadManager` initialized?  What dependencies does it have?
    * **`ExecuteThread`:**  This seems like the main entry point for running a sequence of actions.
    * **`RunAction`:**  A dispatcher for different types of actions.
    * **Task-related methods:** `PostDelayedTask`, `ExecuteTask`, `CancelTask`.
    * **Queue manipulation methods:** `CreateTaskQueue`, `SetQueuePriority`, `SetQueueEnabled`.
    * **Cross-thread methods:** `CreateThread`, `ExecuteCrossThreadPostDelayedTask`.

7. **Logical Inference and Assumptions:** Think about how different actions interact. For example, creating a task queue doesn't automatically mean tasks are added to it. Setting a queue's priority will affect the order in which tasks are executed. Cross-thread posting involves sending tasks between different `ThreadManager` instances. Consider potential race conditions or unexpected behavior if actions are performed in certain sequences.

8. **User/Programming Errors:**  Think about how a *user* of this `ThreadManager` (likely another testing component) might make mistakes. For instance, trying to post a task to a non-existent queue, or manipulating queues in a way that leads to deadlocks (though this simple example might not have complex deadlock scenarios).

9. **Structure the Output:** Organize the findings into logical categories:
    * Core functionality.
    * Relationship to web technologies.
    * Logical inferences (with assumptions and inputs/outputs).
    * Common errors.

10. **Review and Refine:** Read through the analysis to ensure it's clear, accurate, and covers the key aspects of the code. Check for any missed details or areas that could be explained more effectively. For example, initially, I might not have explicitly mentioned the role of `SequenceManagerFuzzerProcessor`, but a second pass would highlight its importance in coordinating multiple `ThreadManager` instances and logging actions.

This systematic approach, starting with high-level understanding and gradually drilling down into specifics, helps in effectively analyzing and explaining the functionality of even moderately complex code like this. The context of "fuzzer" and "scheduler" is crucial for guiding the analysis.
这个文件 `blink/renderer/platform/scheduler/test/fuzzer/thread_manager.cc` 是 Chromium Blink 引擎中用于模糊测试（fuzzing）调度器组件的 `ThreadManager` 类的实现。它的主要功能是模拟和管理单个线程上的任务队列和任务执行，以便在各种操作序列下测试调度器的行为。

以下是它的详细功能列表：

**核心功能：**

1. **模拟线程环境:**  `ThreadManager` 模拟了一个单线程的执行环境，它拥有自己的任务队列和时间控制。

2. **管理任务队列:**
   - **创建任务队列 (`ExecuteCreateTaskQueueAction`):** 可以动态创建新的任务队列，并可以设置初始优先级。
   - **设置任务队列优先级 (`ExecuteSetQueuePriorityAction`):**  允许更改现有任务队列的优先级。
   - **启用/禁用任务队列 (`ExecuteSetQueueEnabledAction`):** 可以通过投票器（voter）机制控制任务队列是否可以执行任务。
   - **关闭任务队列 (`ExecuteShutdownTaskQueueAction`):**  可以移除任务队列，防止其继续执行任务。

3. **管理任务:**
   - **发布延迟任务 (`ExecutePostDelayedTaskAction`, `ExecuteCrossThreadPostDelayedTaskAction`, `PostDelayedTask`):**  允许向当前线程或其他线程的任务队列发布需要延迟执行的任务。
   - **执行任务 (`ExecuteTask`):**  模拟任务的执行过程，可以指定任务的执行时长，并递归地执行任务中定义的子操作。
   - **取消任务 (`ExecuteCancelTaskAction`):**  可以取消尚未执行的任务。

4. **时间控制:**
   - **推进模拟时钟 (`AdvanceMockTickClock`):**  允许手动推进模拟的时间，以便测试在不同时间点发生的事件。
   - **获取当前模拟时间 (`NowTicks`):**  获取当前的模拟时间。
   - **获取下一个待处理任务的延迟 (`NextPendingTaskDelay`):**  查询下一个即将执行的任务的延迟时间。

5. **跨线程交互:**
   - **创建新线程 (`ExecuteCreateThreadAction`):**  允许创建新的 `ThreadManager` 实例来模拟多线程环境。
   - **跨线程发布任务 (`ExecuteCrossThreadPostDelayedTaskAction`):**  允许将任务发布到其他线程的队列中。

6. **栅栏（Fence）机制:**
   - **插入栅栏 (`ExecuteInsertFenceAction`):**  可以在任务队列中插入栅栏，阻止后续任务的执行，直到栅栏被移除。
   - **移除栅栏 (`ExecuteRemoveFenceAction`):**  移除任务队列中的栅栏，允许后续任务继续执行。

7. **记录操作和任务:**
   - `ordered_actions_` 和 `ordered_tasks_` 成员变量用于记录执行的操作和任务，用于后续的测试验证和分析。

**与 JavaScript, HTML, CSS 的关系及举例说明：**

`ThreadManager` 模拟的是浏览器渲染引擎中任务调度的底层机制。虽然它本身不直接处理 JavaScript、HTML 或 CSS 的解析和执行，但它模拟了这些操作背后的任务调度过程。

* **JavaScript:**
    * **`setTimeout` 和 `setInterval`:**  `ExecutePostDelayedTaskAction` 可以模拟 `setTimeout` 和 `setInterval` 的行为。假设输入一个描述 `setTimeout` 的 action，指定延迟时间和要执行的 JavaScript 代码（在模糊测试中以占位符或其他方式表示），`ThreadManager` 会在模拟的延迟时间后执行相应的任务。
        * **假设输入:**  一个 `PostDelayedTaskAction`，`delay_ms` 为 100，`task` 描述一个简单的 JavaScript 函数调用。
        * **输出:** 在模拟时间推进 100ms 后，会执行与该 `task` 相关的操作，例如记录该任务的执行。
    * **Promise 和异步操作:**  Promise 的 `then` 和异步函数的 `await` 也会在事件循环中调度任务。`ThreadManager` 可以模拟这些任务的调度和执行顺序。
        * **假设输入:**  一系列 actions，先执行一个 Promise 的 resolve，然后执行其 `then` 方法对应的 `PostDelayedTaskAction`。
        * **输出:**  会先执行 resolve 相关的操作，然后将 `then` 方法的回调函数作为一个延迟任务添加到队列，并在合适的时机执行。
* **HTML 和 CSS:**
    * **页面渲染和布局:** 浏览器解析 HTML 和 CSS 后，会创建一系列的任务来构建渲染树、计算布局等。`ThreadManager` 可以模拟这些渲染任务的调度。
        * **假设输入:** 一系列 actions，模拟解析 HTML 结构后创建渲染树节点的任务。
        * **输出:** `ThreadManager` 会按照一定的顺序执行这些任务，例如先创建父节点，再创建子节点。
    * **CSS 动画和过渡:**  CSS 动画和过渡效果的执行也是基于浏览器的任务调度机制。
        * **假设输入:** 一个 `PostDelayedTaskAction`，模拟在特定时间点更新元素的 CSS 属性以实现动画效果。
        * **输出:** 在模拟的动画时间点，会执行更新 CSS 属性的任务。

**逻辑推理的假设输入与输出：**

假设存在以下 actions 序列：

1. **`CreateTaskQueueAction`:** 创建一个任务队列，ID 为 0，初始优先级为 `NORMAL`。
2. **`PostDelayedTaskAction`:** 向任务队列 0 发布一个延迟 50ms 的任务，任务 ID 为 0。
3. **`AdvanceMockTickClockAction` (隐式):** 模拟时间推进 30ms。
4. **`PostDelayedTaskAction`:** 向任务队列 0 发布一个延迟 20ms 的任务，任务 ID 为 1。

**推理:**

- 执行 Action 1 后，创建一个优先级为 `NORMAL` 的任务队列。
- 执行 Action 2 后，任务 0 会在模拟时间 50ms 后执行。
- 执行 Action 3 后，当前模拟时间为 30ms。
- 执行 Action 4 时，由于当前时间是 30ms，任务 1 会在模拟时间 30ms + 20ms = 50ms 后执行。

**输出:**

在模拟时间推进到 50ms 时，任务 0 和任务 1 都有可能被执行（取决于具体的调度策略，但在这个简单的模拟中，它们会按发布顺序执行）。 `ordered_tasks_` 可能会记录任务 0 和任务 1 的执行时间戳。

**用户或编程常见的使用错误举例说明：**

1. **尝试操作不存在的任务队列:** 如果一个 action 试图设置一个不存在的任务队列的优先级（例如，使用了错误的 `task_queue_id`），`GetTaskQueueFor` 方法会触发 `DCHECK`，表明程序存在错误。

2. **在多线程环境下未正确同步:** 虽然 `ThreadManager` 模拟了线程，但在实际使用中，如果多个线程同时访问和修改共享的 `ThreadManager` 实例（尽管在这个模糊测试框架中不太可能直接发生这种情况，因为每个 `ThreadManager` 通常管理一个模拟线程），可能会导致数据竞争和未定义的行为。例如，在 `ExecuteShutdownTaskQueueAction` 中，获取锁是为了防止跨线程发布任务时访问已经释放的内存。

3. **过度依赖模拟时间:**  开发者可能会错误地认为模拟时间与真实时间完全一致，这在进行性能分析时可能会产生误导。模糊测试的目的是测试逻辑正确性，而不是精确的性能指标。

4. **不正确的任务依赖:**  如果在模糊测试中定义了复杂的任务依赖关系，但由于 action 的随机性导致依赖关系被打破，可能会导致某些任务无法执行或执行顺序错误。`InsertFenceAction` 和 `RemoveFenceAction` 可以用来显式地控制任务的执行顺序，如果使用不当也可能导致死锁或其他问题。

总而言之，`thread_manager.cc` 中的 `ThreadManager` 类是模糊测试框架的核心组件，它提供了一种可控的方式来模拟和操作线程、任务队列和任务，从而有效地测试 Blink 渲染引擎调度器的健壮性和正确性。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/test/fuzzer/thread_manager.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
#ifdef UNSAFE_BUFFERS_BUILD
// TODO(crbug.com/351564777): Remove this and convert code to safer constructs.
#pragma allow_unsafe_buffers
#endif

#include "third_party/blink/renderer/platform/scheduler/test/fuzzer/thread_manager.h"

#include <algorithm>

#include "base/task/sequence_manager/task_queue.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/renderer/platform/scheduler/common/task_priority.h"
#include "third_party/blink/renderer/platform/scheduler/test/fuzzer/thread_pool_manager.h"

namespace base {
namespace sequence_manager {

namespace {

blink::scheduler::TaskPriority ToTaskQueuePriority(
    SequenceManagerTestDescription::QueuePriority priority) {
  using blink::scheduler::TaskPriority;

  static_assert(static_cast<int>(TaskPriority::kPriorityCount) == 11,
                "Number of task priorities has changed in "
                "blink::scheduler::TaskPriority.");

  switch (priority) {
    case SequenceManagerTestDescription::BEST_EFFORT:
      return TaskPriority::kBestEffortPriority;
    case SequenceManagerTestDescription::LOW:
      return TaskPriority::kLowPriority;
    case SequenceManagerTestDescription::LOW_CONTINUATION:
      return TaskPriority::kLowPriorityContinuation;
    case SequenceManagerTestDescription::UNDEFINED:
    case SequenceManagerTestDescription::NORMAL:
      return TaskPriority::kNormalPriority;
    case SequenceManagerTestDescription::NORMAL_CONTINUATION:
      return TaskPriority::kNormalPriorityContinuation;
    case SequenceManagerTestDescription::HIGH:
      return TaskPriority::kHighPriority;
    case SequenceManagerTestDescription::HIGH_CONTINUATION:
      return TaskPriority::kHighPriorityContinuation;
    case SequenceManagerTestDescription::VERY_HIGH:
      return TaskPriority::kVeryHighPriority;
    case SequenceManagerTestDescription::EXTREMELY_HIGH:
      return TaskPriority::kExtremelyHighPriority;
    case SequenceManagerTestDescription::HIGHEST:
      return TaskPriority::kHighestPriority;
    case SequenceManagerTestDescription::CONTROL:
      return TaskPriority::kControlPriority;
  }
}

}  // namespace

ThreadManager::ThreadManager(base::TimeTicks initial_time,
                             SequenceManagerFuzzerProcessor* processor)
    : processor_(processor) {
  DCHECK(processor_);

  test_task_runner_ = WrapRefCounted(
      new TestMockTimeTaskRunner(TestMockTimeTaskRunner::Type::kBoundToThread));

  DCHECK(!(initial_time - base::TimeTicks()).is_zero())
      << "A zero clock is not allowed as empty base::TimeTicks have a special "
         "value "
         "(i.e. base::TimeTicks::is_null())";

  test_task_runner_->AdvanceMockTickClock(initial_time - base::TimeTicks());

  manager_ = SequenceManagerForTest::Create(
      nullptr, SingleThreadTaskRunner::GetCurrentDefault(),
      test_task_runner_->GetMockTickClock(),
      SequenceManager::Settings::Builder()
          .SetPrioritySettings(::blink::scheduler::CreatePrioritySettings())
          .Build());

  TaskQueue::Spec spec = TaskQueue::Spec(QueueName::DEFAULT_TQ);
  task_queues_.emplace_back(
      MakeRefCounted<TaskQueueWithVoters>(manager_->CreateTaskQueue(spec)));
}

ThreadManager::~ThreadManager() = default;

base::TimeTicks ThreadManager::NowTicks() {
  return test_task_runner_->GetMockTickClock()->NowTicks();
}

base::TimeDelta ThreadManager::NextPendingTaskDelay() {
  return std::max(base::Milliseconds(0),
                  test_task_runner_->NextPendingTaskDelay());
}

void ThreadManager::AdvanceMockTickClock(base::TimeDelta delta) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  return test_task_runner_->AdvanceMockTickClock(delta);
}

void ThreadManager::ExecuteThread(
    const google::protobuf::RepeatedPtrField<
        SequenceManagerTestDescription::Action>& initial_thread_actions) {
  for (const auto& initial_thread_action : initial_thread_actions) {
    RunAction(initial_thread_action);
  }

  while (NowTicks() < base::TimeTicks::Max()) {
    RunLoop().RunUntilIdle();
    processor_->thread_pool_manager()
        ->AdvanceClockSynchronouslyByPendingTaskDelay(this);
  }

  RunLoop().RunUntilIdle();
  processor_->thread_pool_manager()->ThreadDone();
}

void ThreadManager::RunAction(
    const SequenceManagerTestDescription::Action& action) {
  if (action.has_create_task_queue()) {
    ExecuteCreateTaskQueueAction(action.action_id(),
                                 action.create_task_queue());
  } else if (action.has_set_queue_priority()) {
    ExecuteSetQueuePriorityAction(action.action_id(),
                                  action.set_queue_priority());
  } else if (action.has_set_queue_enabled()) {
    ExecuteSetQueueEnabledAction(action.action_id(),
                                 action.set_queue_enabled());
  } else if (action.has_create_queue_voter()) {
    ExecuteCreateQueueVoterAction(action.action_id(),
                                  action.create_queue_voter());
  } else if (action.has_shutdown_task_queue()) {
    ExecuteShutdownTaskQueueAction(action.action_id(),
                                   action.shutdown_task_queue());
  } else if (action.has_cancel_task()) {
    ExecuteCancelTaskAction(action.action_id(), action.cancel_task());
  } else if (action.has_insert_fence()) {
    ExecuteInsertFenceAction(action.action_id(), action.insert_fence());
  } else if (action.has_remove_fence()) {
    ExecuteRemoveFenceAction(action.action_id(), action.remove_fence());
  } else if (action.has_create_thread()) {
    ExecuteCreateThreadAction(action.action_id(), action.create_thread());
  } else if (action.has_cross_thread_post()) {
    ExecuteCrossThreadPostDelayedTaskAction(action.action_id(),
                                            action.cross_thread_post());
  } else {
    ExecutePostDelayedTaskAction(action.action_id(),
                                 action.post_delayed_task());
  }
}

void ThreadManager::ExecuteCreateThreadAction(
    uint64_t action_id,
    const SequenceManagerTestDescription::CreateThreadAction& action) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  processor_->LogActionForTesting(&ordered_actions_, action_id,
                                  ActionForTest::ActionType::kCreateThread,
                                  NowTicks());

  processor_->thread_pool_manager()->CreateThread(
      action.initial_thread_actions(), NowTicks());
}

void ThreadManager::ExecuteCreateTaskQueueAction(
    uint64_t action_id,
    const SequenceManagerTestDescription::CreateTaskQueueAction& action) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  processor_->LogActionForTesting(&ordered_actions_, action_id,
                                  ActionForTest::ActionType::kCreateTaskQueue,
                                  NowTicks());

  TaskQueue::Spec spec = TaskQueue::Spec(QueueName::TEST_TQ);

  TaskQueue* chosen_task_queue;
  {
    AutoLock lock(lock_);
    task_queues_.emplace_back(
        MakeRefCounted<TaskQueueWithVoters>(manager_->CreateTaskQueue(spec)));
    chosen_task_queue = task_queues_.back()->queue.get();
  }
  chosen_task_queue->SetQueuePriority(
      ToTaskQueuePriority(action.initial_priority()));
}

void ThreadManager::ExecutePostDelayedTaskAction(
    uint64_t action_id,
    const SequenceManagerTestDescription::PostDelayedTaskAction& action) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  processor_->LogActionForTesting(&ordered_actions_, action_id,
                                  ActionForTest::ActionType::kPostDelayedTask,
                                  NowTicks());

  PostDelayedTask(action.task_queue_id(), action.delay_ms(), action.task());
}

void ThreadManager::ExecuteCrossThreadPostDelayedTaskAction(
    uint64_t action_id,
    const SequenceManagerTestDescription::CrossThreadPostDelayedTaskAction&
        action) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  processor_->LogActionForTesting(
      &ordered_actions_, action_id,
      ActionForTest::ActionType::kCrossThreadPostDelayedTask, NowTicks());

  processor_->thread_pool_manager()
      ->GetThreadManagerFor(action.thread_id())
      ->PostDelayedTask(action.task_queue_id(), action.delay_ms(),
                        action.task());
}

void ThreadManager::PostDelayedTask(
    uint64_t task_queue_id,
    uint32_t delay_ms,
    const SequenceManagerTestDescription::Task& task) {
  // PostDelayedTask can be called cross-thread, which can race with destroying
  // the task queue on the thread on which ThreadManager lives. Instead of
  // accessing the queue, get the task runner, which is synchronized with task
  // queue destruction.
  scoped_refptr<SingleThreadTaskRunner> chosen_task_runner =
      GetTaskRunnerFor(task_queue_id);

  std::unique_ptr<Task> pending_task = std::make_unique<Task>(this);

  // TODO(farahcharab) After adding non-nestable/nestable tasks, fix this to
  // PostNonNestableDelayedTask for the former and PostDelayedTask for the
  // latter.
  chosen_task_runner->PostDelayedTask(
      FROM_HERE,
      BindOnce(&Task::Execute, pending_task->weak_ptr_factory_.GetWeakPtr(),
               task),
      base::Milliseconds(delay_ms));

  {
    AutoLock lock(lock_);
    pending_tasks_.push_back(std::move(pending_task));
  }
}

void ThreadManager::ExecuteSetQueuePriorityAction(
    uint64_t action_id,
    const SequenceManagerTestDescription::SetQueuePriorityAction& action) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  processor_->LogActionForTesting(&ordered_actions_, action_id,
                                  ActionForTest::ActionType::kSetQueuePriority,
                                  NowTicks());

  scoped_refptr<TaskQueueWithVoters> chosen_task_queue =
      GetTaskQueueFor(action.task_queue_id());
  chosen_task_queue->queue->SetQueuePriority(
      ToTaskQueuePriority(action.priority()));
}

void ThreadManager::ExecuteSetQueueEnabledAction(
    uint64_t action_id,
    const SequenceManagerTestDescription::SetQueueEnabledAction& action) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  processor_->LogActionForTesting(&ordered_actions_, action_id,
                                  ActionForTest::ActionType::kSetQueueEnabled,
                                  NowTicks());

  scoped_refptr<TaskQueueWithVoters> chosen_task_queue =
      GetTaskQueueFor(action.task_queue_id());

  if (chosen_task_queue->voters.empty()) {
    chosen_task_queue->voters.push_back(
        chosen_task_queue->queue.get()->CreateQueueEnabledVoter());
  }

  wtf_size_t voter_index = action.voter_id() % chosen_task_queue->voters.size();
  chosen_task_queue->voters[voter_index]->SetVoteToEnable(action.enabled());
}

void ThreadManager::ExecuteCreateQueueVoterAction(
    uint64_t action_id,
    const SequenceManagerTestDescription::CreateQueueVoterAction& action) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  processor_->LogActionForTesting(&ordered_actions_, action_id,
                                  ActionForTest::ActionType::kCreateQueueVoter,
                                  NowTicks());

  scoped_refptr<TaskQueueWithVoters> chosen_task_queue =
      GetTaskQueueFor(action.task_queue_id());
  chosen_task_queue->voters.push_back(
      chosen_task_queue->queue.get()->CreateQueueEnabledVoter());
}

void ThreadManager::ExecuteShutdownTaskQueueAction(
    uint64_t action_id,
    const SequenceManagerTestDescription::ShutdownTaskQueueAction& action) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  processor_->LogActionForTesting(&ordered_actions_, action_id,
                                  ActionForTest::ActionType::kShutdownTaskQueue,
                                  NowTicks());

  // The shutdown needs to happen with the lock held to prevent cross-thread
  // task posting from grabbing a dangling pointer.
  AutoLock lock(lock_);
  // We always want to have a default task queue.
  if (task_queues_.size() > 1) {
    wtf_size_t queue_index = action.task_queue_id() % task_queues_.size();
    task_queues_[queue_index].reset();
    task_queues_.erase(task_queues_.begin() + queue_index);
  }
}

void ThreadManager::ExecuteCancelTaskAction(
    uint64_t action_id,
    const SequenceManagerTestDescription::CancelTaskAction& action) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  processor_->LogActionForTesting(&ordered_actions_, action_id,
                                  ActionForTest::ActionType::kCancelTask,
                                  NowTicks());

  AutoLock lock(lock_);
  if (!pending_tasks_.empty()) {
    wtf_size_t task_index = action.task_id() % pending_tasks_.size();
    pending_tasks_[task_index]->weak_ptr_factory_.InvalidateWeakPtrs();

    // If it is already running, it is a parent task and will be deleted when
    // it is done.
    if (!pending_tasks_[task_index]->is_running_) {
      pending_tasks_.erase(pending_tasks_.begin() + task_index);
    }
  }
}

void ThreadManager::ExecuteInsertFenceAction(
    uint64_t action_id,
    const SequenceManagerTestDescription::InsertFenceAction& action) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  processor_->LogActionForTesting(&ordered_actions_, action_id,
                                  ActionForTest::ActionType::kInsertFence,
                                  NowTicks());

  scoped_refptr<TaskQueueWithVoters> chosen_task_queue =
      GetTaskQueueFor(action.task_queue_id());

  if (action.position() ==
      SequenceManagerTestDescription::InsertFenceAction::NOW) {
    chosen_task_queue->queue->InsertFence(TaskQueue::InsertFencePosition::kNow);
  } else {
    chosen_task_queue->queue->InsertFence(
        TaskQueue::InsertFencePosition::kBeginningOfTime);
  }
}

void ThreadManager::ExecuteRemoveFenceAction(
    uint64_t action_id,
    const SequenceManagerTestDescription::RemoveFenceAction& action) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);

  processor_->LogActionForTesting(&ordered_actions_, action_id,
                                  ActionForTest::ActionType::kRemoveFence,
                                  NowTicks());

  scoped_refptr<TaskQueueWithVoters> chosen_task_queue =
      GetTaskQueueFor(action.task_queue_id());
  chosen_task_queue->queue->RemoveFence();
}

void ThreadManager::ExecuteTask(
    const SequenceManagerTestDescription::Task& task) {
  base::TimeTicks start_time = NowTicks();

  // We can limit the depth of the nested post delayed action when processing
  // the proto.
  for (const auto& task_action : task.actions()) {
    // TODO(farahcharab) Add run loop to deal with nested tasks later. So far,
    // we are assuming tasks are non-nestable.
    RunAction(task_action);
  }

  base::TimeTicks end_time = NowTicks();

  base::TimeTicks next_time =
      start_time +
      std::max(base::TimeDelta(), base::Milliseconds(task.duration_ms()) -
                                      (end_time - start_time));

  while (NowTicks() != next_time) {
    processor_->thread_pool_manager()->AdvanceClockSynchronouslyToTime(
        this, next_time);
  }

  processor_->LogTaskForTesting(&ordered_tasks_, task.task_id(), start_time,
                                NowTicks());
}

void ThreadManager::DeleteTask(Task* task) {
  AutoLock lock(lock_);
  wtf_size_t i = 0;
  while (i < pending_tasks_.size() && task != pending_tasks_[i].get()) {
    i++;
  }
  if (i < pending_tasks_.size())
    pending_tasks_.erase(pending_tasks_.begin() + i);
}

scoped_refptr<TaskQueueWithVoters> ThreadManager::GetTaskQueueFor(
    uint64_t task_queue_id) {
  AutoLock lock(lock_);
  DCHECK(!task_queues_.empty());
  return task_queues_[task_queue_id % task_queues_.size()].get();
}

scoped_refptr<SingleThreadTaskRunner> ThreadManager::GetTaskRunnerFor(
    uint64_t task_queue_id) {
  AutoLock lock(lock_);
  DCHECK(!task_queues_.empty());
  return task_queues_[task_queue_id % task_queues_.size()]
      ->queue->task_runner();
}

const Vector<SequenceManagerFuzzerProcessor::TaskForTest>&
ThreadManager::ordered_tasks() const {
  return ordered_tasks_;
}

const Vector<SequenceManagerFuzzerProcessor::ActionForTest>&
ThreadManager::ordered_actions() const {
  return ordered_actions_;
}

ThreadManager::Task::Task(ThreadManager* thread_manager)
    : is_running_(false), thread_manager_(thread_manager) {
  DCHECK(thread_manager_);
}

void ThreadManager::Task::Execute(
    const SequenceManagerTestDescription::Task& task) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_manager_->thread_checker_);
  is_running_ = true;
  thread_manager_->ExecuteTask(task);
  thread_manager_->DeleteTask(this);
}

}  // namespace sequence_manager
}  // namespace base
```