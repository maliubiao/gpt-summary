Response: Let's break down the thought process for analyzing this C++ unittest file.

1. **Understand the Goal:** The core request is to understand the *functionality* of `worker_scheduler_impl_unittest.cc`. This means identifying what aspects of the `WorkerSchedulerImpl` are being tested.

2. **Identify the Subject Under Test:** The filename itself is a huge clue: `worker_scheduler_impl_unittest.cc`. This tells us the central class being tested is likely `WorkerSchedulerImpl`. Looking at the includes confirms this: `#include "third_party/blink/renderer/platform/scheduler/worker/worker_scheduler_impl.h"`.

3. **Recognize the Testing Framework:** The presence of `#include "testing/gmock/include/gmock/gmock.h"` and `#include "testing/gtest/include/gtest/gtest.h"` immediately indicates this is a Google Test (gtest) based unit test. This means we should look for `TEST_F` macros.

4. **High-Level Structure Analysis:** Scan the code for `TEST_F`. Each `TEST_F` function represents a specific test case. List these out to get a sense of the overall test coverage:

    * `TestPostTasks`
    * `RegisterWorkerSchedulers`
    * `ThrottleWorkerScheduler`
    * `ThrottleWorkerScheduler_CreateThrottled`
    * `ThrottleWorkerScheduler_RunThrottledTasks`
    * `ThrottleWorkerScheduler_RunThrottledTasks_CPUBudget`
    * `PausableTasks`
    * `NestedPauseHandlesTasks`
    * `FeatureUpload`
    * `TasksRunInPriorityOrder`
    * `DynamicTaskPriorityOrder`
    * `TasksAndContinuations`
    * `DynamicPriorityContinuations`
    * `WebScheduingAndNonWebScheduingTasks`
    * `DeleteSoonAfterDispose`

5. **Analyze Individual Test Cases:** Go through each `TEST_F` and decipher its purpose. Look at:

    * **Setup:** What is being initialized before the test runs?  (e.g., `WorkerSchedulerImpl`, `WorkerThreadScheduler`).
    * **Actions:** What methods of the `WorkerSchedulerImpl` are being called? What are the inputs?
    * **Assertions:** What are the expected outcomes?  What is being checked using `EXPECT_THAT`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, etc.?

    *Example Breakdown of `TestPostTasks`:*
        * **Setup:**  A `WorkerSchedulerImpl` is created.
        * **Actions:** `PostTestTask` is called multiple times with different task descriptors. `RunUntilIdle()` is used to execute tasks. `Dispose()` is called. `PostTestTask` is called *after* disposal.
        * **Assertions:** `EXPECT_THAT` verifies the order of tasks executed before disposal. `EXPECT_TRUE` checks that no tasks run after disposal.

6. **Identify Key Functionality Being Tested:** Based on the analysis of the test cases, group them by the features they are exercising. This leads to categories like:

    * **Task Posting and Execution:** How tasks are added and run.
    * **Worker Scheduler Registration:** How multiple worker schedulers interact.
    * **Throttling:** How the scheduler behaves when throttled (due to background tabs, etc.). Pay attention to CPU budget.
    * **Pausing:** How task execution can be temporarily stopped.
    * **Feature Upload:**  Mechanism for reporting feature usage.
    * **Web Scheduling Priorities:** Testing the priority-based task execution using `WebSchedulingQueueType` and `WebSchedulingPriority`. Look for "BG", "UV", "UB" prefixes in task descriptors.
    * **Continuations:** Testing tasks that are dependent on the completion of other tasks.
    * **Task Deletion:** How `DeleteSoon` works, especially after disposal.

7. **Relate to Web Concepts (JavaScript, HTML, CSS):**  Consider how the tested functionality relates to web development.

    * **JavaScript:**  The scheduling of JavaScript timers (`kJavascriptTimerImmediate`, `kJavascriptTimerDelayedLowNesting`), `postMessage` (`kPostedMessage`), and the general execution of JavaScript code in workers are directly related. Throttling directly impacts how quickly JavaScript timers fire in background tabs.
    * **HTML:**  The Back/Forward Cache disabling features being tested (`kMainResourceHasCacheControlNoStore`, `kMainResourceHasCacheControlNoCache`) are triggered by HTML headers. The concept of a "worker" itself is an HTML concept.
    * **CSS:** While not as direct, the overall responsiveness of the UI, which can be affected by background worker tasks, indirectly relates to CSS rendering performance.

8. **Logical Inference and Examples:** For scenarios involving conditional behavior or ordering, create hypothetical inputs and outputs to illustrate the logic. For example, the priority testing clearly demonstrates that User Blocking tasks run before User Visible tasks, which run before Background tasks.

9. **Identify Potential Usage Errors:** Think about common mistakes developers might make when using or interacting with the scheduler:

    * Posting tasks after the scheduler is disposed.
    * Assuming tasks will run immediately when the scheduler is paused.
    * Not understanding the implications of throttling on background tasks.
    * Incorrectly setting task priorities.

10. **Structure the Output:** Organize the findings in a clear and logical way, addressing each part of the original request. Use headings, bullet points, and code snippets where appropriate.

11. **Review and Refine:** Read through the analysis to ensure accuracy, clarity, and completeness. Check for any missed points or areas that could be explained better. For example, initially, I might not have explicitly connected the feature upload to browser-side functionality. A review would prompt me to add that detail.

By following these steps, we can systematically analyze the unittest file and generate a comprehensive explanation of its functionality and its relevance to web technologies.
这个文件 `worker_scheduler_impl_unittest.cc` 是 Chromium Blink 引擎中用于测试 `WorkerSchedulerImpl` 类的单元测试代码。 `WorkerSchedulerImpl` 负责管理 worker 线程上的任务调度。

**主要功能：**

该文件通过一系列的测试用例，验证了 `WorkerSchedulerImpl` 的以下核心功能：

1. **任务的发布和执行 (Task Posting and Execution):**
   - 测试了在 `WorkerSchedulerImpl` 上发布不同类型的任务，并验证它们能否按照预期执行。
   - 验证了在 `WorkerSchedulerImpl` 被销毁后，新发布的任务不会被执行。
   - **例子：** `TEST_F(WorkerSchedulerImplTest, TestPostTasks)`  测试了发布 `TaskType::kInternalTest` 类型的任务，并验证了它们的执行顺序。

2. **Worker 调度器的注册和管理 (Worker Scheduler Registration and Management):**
   - 测试了多个 `WorkerSchedulerImpl` 实例在同一个 `WorkerThreadScheduler` 下的注册和管理。
   - 验证了当 `WorkerSchedulerImpl` 被销毁时，它能从 `WorkerThreadScheduler` 中正确移除。
   - **例子：** `TEST_F(WorkerSchedulerImplTest, RegisterWorkerSchedulers)` 测试了注册和注销多个 `WorkerSchedulerImpl` 实例。

3. **Worker 调度器的节流 (Throttling Worker Scheduler):**
   - 测试了 `WorkerSchedulerImpl` 在生命周期状态改变时的节流行为。
   - 验证了当父线程（例如主渲染线程）进入节流状态（例如标签页被隐藏）时，worker 线程的 `WorkerSchedulerImpl` 也会被节流，从而降低资源消耗。
   - 测试了在节流状态下创建的 `WorkerSchedulerImpl` 是否也会被立即节流。
   - 测试了节流状态下任务的执行，包括考虑 CPU 时间预算的情况。
   - **与 JavaScript 的关系：**  JavaScript 任务在 worker 线程上执行，如果 worker 线程被节流，JavaScript 代码的执行速度会受到限制，例如 `setTimeout` 和 `setInterval` 的回调执行会被延迟。这有助于降低后台标签页的 CPU 占用。
   - **假设输入与输出：**
     - **假设输入：** 主线程进入节流状态。
     - **预期输出：** `worker_scheduler_->ThrottleableTaskQueue()->IsThrottled()` 返回 `true`。
     - **假设输入：** 在节流状态下发布一个延时执行的 JavaScript 定时器任务。
     - **预期输出：** 该定时器任务的执行会被延迟，直到节流状态解除或获得足够的 CPU 时间预算。

4. **可暂停任务队列 (Pausable Task Queues):**
   - 测试了 `WorkerSchedulerImpl` 的暂停和恢复功能。
   - 验证了当 `WorkerSchedulerImpl` 被暂停时，可暂停的任务不会被执行，直到恢复。
   - 验证了嵌套的暂停句柄 (pause handles) 的行为。
   - **与 JavaScript 的关系：**  一些 JavaScript API 可能会使用可暂停的任务队列，例如涉及网络请求或特定资源加载的任务。暂停 worker 可以阻止这些操作的进行。
   - **假设输入与输出：**
     - **假设输入：** 调用 `worker_scheduler_->Pause()`。
     - **预期输出：** 发布到可暂停队列的任务不会立即执行。
     - **假设输入：** 之前调用了 `worker_scheduler_->Pause()`，然后释放了暂停句柄。
     - **预期输出：**  之前发布到可暂停队列的任务开始执行。

5. **特性上传 (Feature Upload):**
   - 测试了 worker 调度器是否会将某些特性（例如禁用 Back/Forward Cache 的特性）的使用情况上传到浏览器进程。
   - **与 HTML 的关系：**  Back/Forward Cache 是浏览器的一项优化，可以加速页面的前进和后退。某些 HTML 结构或 JavaScript 代码可能会阻止 Back/Forward Cache 的使用。此测试验证了 worker 调度器能够报告这些阻止行为。
   - **假设输入与输出：**
     - **假设输入：** 在 worker 中注册了禁用 Back/Forward Cache 的特性。
     - **预期输出：** 调度器会调用委托对象的方法，通知浏览器进程该特性被使用。

6. **Web 调度任务队列 (Web Scheduling Task Queues):**
   - 测试了使用 `WebSchedulingPriority` 和 `WebSchedulingQueueType` 进行任务调度，包括任务队列和延续队列。
   - 验证了不同优先级的任务的执行顺序。
   - 验证了可以动态修改任务队列的优先级。
   - 验证了任务和延续任务的执行顺序。
   - **与 JavaScript, HTML, CSS 的关系：**  这部分涉及到更精细的任务优先级管理，可以用于优化与用户交互相关的任务（例如响应用户点击）的优先级，确保用户体验流畅。例如，用户可见的任务（`kUserVisiblePriority`) 会比后台任务 (`kBackgroundPriority`) 更早执行。 这可以影响 JavaScript 事件处理程序的执行顺序，以及与页面渲染相关的任务。
   - **假设输入与输出：**
     - **假设输入：** 发布了多个不同优先级的任务（例如，用户阻塞、用户可见、后台）。
     - **预期输出：** 任务按照优先级顺序执行：用户阻塞 > 用户可见 > 后台。
     - **假设输入：** 将一个用户阻塞优先级的任务队列的优先级动态设置为后台优先级。
     - **预期输出：** 该队列中的任务的执行顺序会降低到后台优先级。

7. **资源释放 (Resource Release):**
   - 测试了 `DeleteSoon` 方法在 `WorkerSchedulerImpl` 销毁后的行为，确保资源能够被正确释放。
   - **编程常见的使用错误：**  如果在 `WorkerSchedulerImpl` 已经销毁后，仍然尝试使用其任务队列发布或删除任务，可能会导致崩溃或未定义行为。此测试验证了 `DeleteSoon` 在销毁后的安全性。
   - **假设输入与输出：**
     - **假设输入：** 在 `WorkerSchedulerImpl` 销毁后，调用 `task_runner->DeleteSoon`。
     - **预期输出：**  待删除的对象最终会被安全地删除，即使调度器已经不再运行。

**与 JavaScript, HTML, CSS 的关系总结：**

- **JavaScript：**  `WorkerSchedulerImpl` 直接管理着 worker 线程上 JavaScript 任务的执行。节流和优先级调度会影响 JavaScript 代码的运行速度和响应性。
- **HTML：**  测试中涉及的 Back/Forward Cache 是 HTML 相关的浏览器特性。worker 调度器能够报告影响此特性的行为。
- **CSS：**  虽然没有直接的关系，但 worker 线程可以执行一些与页面渲染相关的任务。合理的任务调度可以避免 worker 线程的任务阻塞主线程，从而提高页面渲染的流畅度。

**逻辑推理的假设输入与输出示例：**

```
// 假设测试用例验证了优先级调度
TEST_F(NonMainThreadWebSchedulingTaskQueueTest, TasksRunInPriorityOrder) {
  // ... (发布不同优先级的任务) ...

  // 假设输入： 发布了以下任务
  // - 任务 A: 优先级为 UserBlocking
  // - 任务 B: 优先级为 UserVisible
  // - 任务 C: 优先级为 Background

  RunUntilIdle();

  // 预期输出： 任务执行顺序为 A -> B -> C
  EXPECT_THAT(run_order, testing::ElementsAre("A", "B", "C"));
}
```

**用户或编程常见的使用错误示例：**

- **错误使用场景：**  在 worker 线程的 `WorkerSchedulerImpl` 已经被 `Dispose()` 销毁后，仍然尝试获取其 `TaskRunner` 并发布任务。
- **后果：**  这会导致程序崩溃或产生不可预测的行为，因为 `TaskRunner` 所关联的底层机制可能已经被释放。
- **测试用例的验证：** `TEST_F(WorkerSchedulerImplTest, TestPostTasks)` 中就测试了这种情况，验证了在 `Dispose()` 之后发布的任务不会被执行，但这主要是为了保证内部逻辑的正确性，避免出现更严重的问题。开发者应该避免在调度器销毁后继续使用。
- **另一个错误使用场景：**  过度依赖高优先级任务，导致低优先级任务长时间得不到执行，可能会影响后台任务的处理。 理解不同优先级的含义和适用场景非常重要。

总而言之，`worker_scheduler_impl_unittest.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎中 worker 线程任务调度的正确性和可靠性，这对于 Web Workers 的正常运行和性能优化至关重要。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/worker/worker_scheduler_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/worker/worker_scheduler_impl.h"

#include <memory>

#include "base/functional/bind.h"
#include "base/memory/raw_ptr.h"
#include "base/memory/scoped_refptr.h"
#include "base/task/sequence_manager/test/sequence_manager_for_test.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/time/time.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/abseil-cpp/absl/types/variant.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/renderer/platform/scheduler/common/task_priority.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/cpu_time_budget_pool.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/task_queue_throttler.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_or_worker_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_priority.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_queue_type.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_task_queue.h"
#include "third_party/blink/renderer/platform/scheduler/test/web_scheduling_test_helper.h"
#include "third_party/blink/renderer/platform/scheduler/worker/worker_thread_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/functional.h"

using testing::ElementsAre;
using testing::ElementsAreArray;

namespace blink {
namespace scheduler {
// To avoid symbol collisions in jumbo builds.
namespace worker_scheduler_unittest {

namespace {

void AppendToVectorTestTask(Vector<String>* vector, String value) {
  vector->push_back(value);
}

void RunChainedTask(scoped_refptr<NonMainThreadTaskQueue> task_queue,
                    int count,
                    base::TimeDelta duration,
                    scoped_refptr<base::TestMockTimeTaskRunner> environment,
                    Vector<base::TimeTicks>* tasks) {
  tasks->push_back(environment->GetMockTickClock()->NowTicks());

  environment->AdvanceMockTickClock(duration);

  if (count == 1)
    return;

  // Add a delay of 50ms to ensure that wake-up based throttling does not affect
  // us.
  task_queue->GetTaskRunnerWithDefaultTaskType()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RunChainedTask, task_queue, count - 1, duration,
                     environment, base::Unretained(tasks)),
      base::Milliseconds(50));
}

void IncrementCounter(int* counter) {
  ++*counter;
}

class TestObject {
 public:
  explicit TestObject(int* counter) : counter_(counter) {}

  ~TestObject() { ++(*counter_); }

 private:
  raw_ptr<int> counter_;
};

}  // namespace

class WorkerThreadSchedulerForTest : public WorkerThreadScheduler {
 public:
  // |manager| and |proxy| must remain valid for the entire lifetime of this
  // object.
  WorkerThreadSchedulerForTest(ThreadType thread_type,
                               base::sequence_manager::SequenceManager* manager,
                               WorkerSchedulerProxy* proxy)
      : WorkerThreadScheduler(thread_type, manager, proxy) {}

  const HashSet<WorkerSchedulerImpl*>& worker_schedulers() {
    return GetWorkerSchedulersForTesting();
  }

  using WorkerThreadScheduler::CreateBudgetPools;
  using WorkerThreadScheduler::SetCPUTimeBudgetPoolForTesting;
};

class WorkerSchedulerForTest : public WorkerSchedulerImpl {
 public:
  explicit WorkerSchedulerForTest(
      WorkerThreadSchedulerForTest* thread_scheduler)
      : WorkerSchedulerImpl(thread_scheduler, nullptr) {}

  using WorkerSchedulerImpl::ThrottleableTaskQueue;
  using WorkerSchedulerImpl::UnpausableTaskQueue;
};

class WorkerSchedulerImplTest : public testing::Test {
 public:
  WorkerSchedulerImplTest()
      : mock_task_runner_(new base::TestMockTimeTaskRunner()),
        sequence_manager_(
            base::sequence_manager::SequenceManagerForTest::Create(
                nullptr,
                mock_task_runner_,
                mock_task_runner_->GetMockTickClock(),
                base::sequence_manager::SequenceManager::Settings::Builder()
                    .SetPrioritySettings(CreatePrioritySettings())
                    .Build())),
        scheduler_(new WorkerThreadSchedulerForTest(ThreadType::kTestThread,
                                                    sequence_manager_.get(),
                                                    nullptr /* proxy */)) {
    mock_task_runner_->AdvanceMockTickClock(base::Microseconds(5000));
    start_time_ = mock_task_runner_->NowTicks();
  }

  WorkerSchedulerImplTest(const WorkerSchedulerImplTest&) = delete;
  WorkerSchedulerImplTest& operator=(const WorkerSchedulerImplTest&) = delete;
  ~WorkerSchedulerImplTest() override = default;

  void SetUp() override {
    scheduler_->Init();
    scheduler_->AttachToCurrentThread();
    worker_scheduler_ =
        std::make_unique<WorkerSchedulerForTest>(scheduler_.get());
  }

  void TearDown() override {
    if (worker_scheduler_) {
      worker_scheduler_->Dispose();
      worker_scheduler_.reset();
    }
  }

  const base::TickClock* GetClock() {
    return mock_task_runner_->GetMockTickClock();
  }

  void RunUntilIdle() { mock_task_runner_->FastForwardUntilNoTasksRemain(); }

  // Helper for posting a task.
  void PostTestTask(Vector<String>* run_order,
                    const String& task_descriptor,
                    TaskType task_type) {
    PostTestTask(run_order, task_descriptor,
                 *worker_scheduler_->GetTaskRunner(task_type).get());
  }

  void PostTestTask(Vector<String>* run_order,
                    const String& task_descriptor,
                    base::SingleThreadTaskRunner& task_runner) {
    task_runner.PostTask(
        FROM_HERE, WTF::BindOnce(&AppendToVectorTestTask,
                                 WTF::Unretained(run_order), task_descriptor));
  }

 protected:
  scoped_refptr<base::TestMockTimeTaskRunner> mock_task_runner_;
  std::unique_ptr<base::sequence_manager::SequenceManagerForTest>
      sequence_manager_;
  std::unique_ptr<WorkerThreadSchedulerForTest> scheduler_;
  std::unique_ptr<WorkerSchedulerForTest> worker_scheduler_;
  base::TimeTicks start_time_;
  base::test::ScopedFeatureList feature_list_;
};

TEST_F(WorkerSchedulerImplTest, TestPostTasks) {
  Vector<String> run_order;
  PostTestTask(&run_order, "T1", TaskType::kInternalTest);
  PostTestTask(&run_order, "T2", TaskType::kInternalTest);
  RunUntilIdle();
  PostTestTask(&run_order, "T3", TaskType::kInternalTest);
  RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("T1", "T2", "T3"));

  // GetTaskRunner() is only supposed to be called by the WorkerThread, and only
  // during initialization. Simulate this by using a cached task runner after
  // disposal.
  scoped_refptr<base::SingleThreadTaskRunner> test_task_runner =
      worker_scheduler_->GetTaskRunner(TaskType::kInternalTest);
  // Tasks should not run after the scheduler is disposed of.
  worker_scheduler_->Dispose();
  run_order.clear();
  PostTestTask(&run_order, "T4", *test_task_runner.get());
  PostTestTask(&run_order, "T5", *test_task_runner.get());
  RunUntilIdle();
  EXPECT_TRUE(run_order.empty());

  worker_scheduler_.reset();
}

TEST_F(WorkerSchedulerImplTest, RegisterWorkerSchedulers) {
  EXPECT_THAT(scheduler_->worker_schedulers(),
              testing::ElementsAre(worker_scheduler_.get()));

  std::unique_ptr<WorkerSchedulerForTest> worker_scheduler2 =
      std::make_unique<WorkerSchedulerForTest>(scheduler_.get());

  EXPECT_THAT(scheduler_->worker_schedulers(),
              testing::UnorderedElementsAre(worker_scheduler_.get(),
                                            worker_scheduler2.get()));

  worker_scheduler_->Dispose();
  worker_scheduler_.reset();

  EXPECT_THAT(scheduler_->worker_schedulers(),
              testing::ElementsAre(worker_scheduler2.get()));

  worker_scheduler2->Dispose();

  EXPECT_THAT(scheduler_->worker_schedulers(), testing::ElementsAre());
}

TEST_F(WorkerSchedulerImplTest, ThrottleWorkerScheduler) {
  scheduler_->CreateBudgetPools();

  EXPECT_FALSE(worker_scheduler_->ThrottleableTaskQueue()->IsThrottled());

  scheduler_->OnLifecycleStateChanged(SchedulingLifecycleState::kThrottled);
  EXPECT_TRUE(worker_scheduler_->ThrottleableTaskQueue()->IsThrottled());

  scheduler_->OnLifecycleStateChanged(SchedulingLifecycleState::kThrottled);
  EXPECT_TRUE(worker_scheduler_->ThrottleableTaskQueue()->IsThrottled());

  // Ensure that two calls with kThrottled do not mess with throttling
  // refcount.
  scheduler_->OnLifecycleStateChanged(SchedulingLifecycleState::kNotThrottled);
  EXPECT_FALSE(worker_scheduler_->ThrottleableTaskQueue()->IsThrottled());
}

TEST_F(WorkerSchedulerImplTest, ThrottleWorkerScheduler_CreateThrottled) {
  scheduler_->CreateBudgetPools();

  scheduler_->OnLifecycleStateChanged(SchedulingLifecycleState::kThrottled);

  std::unique_ptr<WorkerSchedulerForTest> worker_scheduler2 =
      std::make_unique<WorkerSchedulerForTest>(scheduler_.get());

  // Ensure that newly created scheduler is throttled.
  EXPECT_TRUE(worker_scheduler2->ThrottleableTaskQueue()->IsThrottled());

  worker_scheduler2->Dispose();
}

TEST_F(WorkerSchedulerImplTest, ThrottleWorkerScheduler_RunThrottledTasks) {
  scheduler_->CreateBudgetPools();
  scheduler_->SetCPUTimeBudgetPoolForTesting(nullptr);

  // Create a new |worker_scheduler| to ensure that it's properly initialised.
  worker_scheduler_->Dispose();
  worker_scheduler_ =
      std::make_unique<WorkerSchedulerForTest>(scheduler_.get());

  scheduler_->OnLifecycleStateChanged(SchedulingLifecycleState::kThrottled);

  Vector<base::TimeTicks> tasks;

  worker_scheduler_->ThrottleableTaskQueue()
      ->GetTaskRunnerWithDefaultTaskType()
      ->PostTask(FROM_HERE,
                 base::BindOnce(&RunChainedTask,
                                worker_scheduler_->ThrottleableTaskQueue(), 5,
                                base::TimeDelta(), mock_task_runner_,
                                base::Unretained(&tasks)));

  RunUntilIdle();

  EXPECT_THAT(tasks, ElementsAre(base::TimeTicks() + base::Seconds(1),
                                 base::TimeTicks() + base::Seconds(2),
                                 base::TimeTicks() + base::Seconds(3),
                                 base::TimeTicks() + base::Seconds(4),
                                 base::TimeTicks() + base::Seconds(5)));
}

TEST_F(WorkerSchedulerImplTest,
       ThrottleWorkerScheduler_RunThrottledTasks_CPUBudget) {
  scheduler_->CreateBudgetPools();

  scheduler_->cpu_time_budget_pool()->SetTimeBudgetRecoveryRate(
      GetClock()->NowTicks(), 0.01);

  // Create a new |worker_scheduler| to ensure that it's properly initialised.
  worker_scheduler_->Dispose();
  worker_scheduler_ =
      std::make_unique<WorkerSchedulerForTest>(scheduler_.get());

  scheduler_->OnLifecycleStateChanged(SchedulingLifecycleState::kThrottled);

  Vector<base::TimeTicks> tasks;

  worker_scheduler_->ThrottleableTaskQueue()
      ->GetTaskRunnerWithDefaultTaskType()
      ->PostTask(FROM_HERE,
                 base::BindOnce(&RunChainedTask,
                                worker_scheduler_->ThrottleableTaskQueue(), 5,
                                base::Milliseconds(100), mock_task_runner_,
                                base::Unretained(&tasks)));

  RunUntilIdle();

  EXPECT_THAT(tasks, ElementsAre(base::TimeTicks() + base::Seconds(1),
                                 start_time_ + base::Seconds(10),
                                 start_time_ + base::Seconds(20),
                                 start_time_ + base::Seconds(30),
                                 start_time_ + base::Seconds(40)));
}

TEST_F(WorkerSchedulerImplTest, PausableTasks) {
  Vector<String> run_order;
  auto pause_handle = worker_scheduler_->Pause();
  // Tests interlacing pausable, throttable and unpausable tasks and
  // ensures that the pausable & throttable tasks don't run when paused.
  // Throttable
  PostTestTask(&run_order, "T1", TaskType::kJavascriptTimerDelayedLowNesting);
  // Pausable
  PostTestTask(&run_order, "T2", TaskType::kNetworking);
  // Unpausable
  PostTestTask(&run_order, "T3", TaskType::kInternalTest);
  RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("T3"));
  pause_handle.reset();
  RunUntilIdle();

  EXPECT_THAT(run_order, testing::ElementsAre("T3", "T1", "T2"));
}

TEST_F(WorkerSchedulerImplTest, NestedPauseHandlesTasks) {
  Vector<String> run_order;
  auto pause_handle = worker_scheduler_->Pause();
  {
    auto pause_handle2 = worker_scheduler_->Pause();
    PostTestTask(&run_order, "T1", TaskType::kJavascriptTimerDelayedLowNesting);
    PostTestTask(&run_order, "T2", TaskType::kNetworking);
  }
  RunUntilIdle();
  EXPECT_EQ(0u, run_order.size());
  pause_handle.reset();
  RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("T1", "T2"));
}

class WorkerSchedulerDelegateForTesting : public WorkerScheduler::Delegate {
 public:
  MOCK_METHOD(void, UpdateBackForwardCacheDisablingFeatures, (BlockingDetails));
};

MATCHER(BlockingDetailsHasCCNS, "Compares two blocking details.") {
  bool vector_empty =
      arg.non_sticky_features_and_js_locations->details_list.empty();
  bool vector_has_ccns =
      arg.sticky_features_and_js_locations->details_list.Contains(
          FeatureAndJSLocationBlockingBFCache(
              SchedulingPolicy::Feature::kMainResourceHasCacheControlNoStore,
              nullptr)) &&
      arg.sticky_features_and_js_locations->details_list.Contains(
          FeatureAndJSLocationBlockingBFCache(
              SchedulingPolicy::Feature::kMainResourceHasCacheControlNoCache,
              nullptr));
  return vector_empty && vector_has_ccns;
}

// Confirms that the feature usage in a dedicated worker is uploaded to
// somewhere (the browser side in the actual implementation) via a delegate.
TEST_F(WorkerSchedulerImplTest, FeatureUpload) {
  auto delegate = std::make_unique<
      testing::StrictMock<WorkerSchedulerDelegateForTesting>>();
  worker_scheduler_->InitializeOnWorkerThread(delegate.get());

  // As the tracked features are uplodaed after the current task is done by
  // ExecuteAfterCurrentTask, register features in a different task, and wait
  // for the task execution.
  worker_scheduler_->GetTaskRunner(TaskType::kJavascriptTimerImmediate)
      ->PostTask(FROM_HERE,
                 base::BindOnce(
                     [](WorkerSchedulerImpl* worker_scheduler,
                        testing::StrictMock<WorkerSchedulerDelegateForTesting>*
                            delegate) {
                       worker_scheduler->RegisterStickyFeature(
                           SchedulingPolicy::Feature::
                               kMainResourceHasCacheControlNoStore,
                           {SchedulingPolicy::DisableBackForwardCache()});
                       worker_scheduler->RegisterStickyFeature(
                           SchedulingPolicy::Feature::
                               kMainResourceHasCacheControlNoCache,
                           {SchedulingPolicy::DisableBackForwardCache()});
                       testing::Mock::VerifyAndClearExpectations(delegate);
                       EXPECT_CALL(*delegate,
                                   UpdateBackForwardCacheDisablingFeatures(
                                       BlockingDetailsHasCCNS()));
                     },
                     worker_scheduler_.get(), delegate.get()));

  RunUntilIdle();

  testing::Mock::VerifyAndClearExpectations(delegate.get());
}

class NonMainThreadWebSchedulingTaskQueueTest
    : public WorkerSchedulerImplTest,
      public WebSchedulingTestHelper::Delegate {
 public:
  void SetUp() override {
    WorkerSchedulerImplTest::SetUp();
    web_scheduling_test_helper_ =
        std::make_unique<WebSchedulingTestHelper>(*this);
  }

  void TearDown() override {
    WorkerSchedulerImplTest::TearDown();
    web_scheduling_test_helper_.reset();
  }

  FrameOrWorkerScheduler& GetFrameOrWorkerScheduler() override {
    return *worker_scheduler_.get();
  }

  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunner(
      TaskType task_type) override {
    return worker_scheduler_->GetTaskRunner(task_type);
  }

 protected:
  using TestTaskSpecEntry = WebSchedulingTestHelper::TestTaskSpecEntry;
  using WebSchedulingParams = WebSchedulingTestHelper::WebSchedulingParams;

  std::unique_ptr<WebSchedulingTestHelper> web_scheduling_test_helper_;
};

TEST_F(NonMainThreadWebSchedulingTaskQueueTest, TasksRunInPriorityOrder) {
  Vector<String> run_order;

  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "BG1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "BG2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "UV1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UV2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UB1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})},
      {.descriptor = "UB2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("UB1", "UB2", "UV1", "UV2", "BG1", "BG2"));
}

TEST_F(NonMainThreadWebSchedulingTaskQueueTest, DynamicTaskPriorityOrder) {
  Vector<String> run_order;
  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "BG1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "BG2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "UV1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UV2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UB1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})},
      {.descriptor = "UB2",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  web_scheduling_test_helper_
      ->GetWebSchedulingTaskQueue(WebSchedulingQueueType::kTaskQueue,
                                  WebSchedulingPriority::kUserBlockingPriority)
      ->SetPriority(WebSchedulingPriority::kBackgroundPriority);

  RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("UV1", "UV2", "BG1", "BG2", "UB1", "UB2"));
}

TEST_F(NonMainThreadWebSchedulingTaskQueueTest, TasksAndContinuations) {
  Vector<String> run_order;
  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "BG",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "BG-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "UV",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UV-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UB",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})},
      {.descriptor = "UB-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("UB-C", "UB", "UV-C", "UV", "BG-C", "BG"));
}

TEST_F(NonMainThreadWebSchedulingTaskQueueTest, DynamicPriorityContinuations) {
  Vector<String> run_order;
  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "BG-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "UV-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UB-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  web_scheduling_test_helper_
      ->GetWebSchedulingTaskQueue(WebSchedulingQueueType::kContinuationQueue,
                                  WebSchedulingPriority::kUserBlockingPriority)
      ->SetPriority(WebSchedulingPriority::kBackgroundPriority);

  RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("UV-C", "BG-C", "UB-C"));
}

TEST_F(NonMainThreadWebSchedulingTaskQueueTest,
       WebScheduingAndNonWebScheduingTasks) {
  Vector<String> run_order;
  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "PostMessage", .type_info = TaskType::kPostedMessage},
      {.descriptor = "BG",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "BG-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "UV",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UV-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UB",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})},
      {.descriptor = "UB-C",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kContinuationQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})},
      {.descriptor = "Timer",
       .type_info = TaskType::kJavascriptTimerImmediate}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("UB-C", "UB", "UV-C", "PostMessage", "UV",
                                   "Timer", "BG-C", "BG"));
}

enum class DeleterTaskRunnerEnabled { kEnabled, kDisabled };

TEST_F(WorkerSchedulerImplTest, DeleteSoonAfterDispose) {
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      worker_scheduler_->GetTaskRunner(TaskType::kInternalTest);
  int counter = 0;

  // Deleting before shutdown should always work.
  std::unique_ptr<TestObject> test_object1 =
      std::make_unique<TestObject>(&counter);
  task_runner->DeleteSoon(FROM_HERE, std::move(test_object1));
  EXPECT_EQ(counter, 0);
  RunUntilIdle();
  EXPECT_EQ(counter, 1);

  task_runner->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  worker_scheduler_->Dispose();
  worker_scheduler_.reset();

  // No more tasks should run after worker scheduler disposal.
  EXPECT_EQ(counter, 1);
  RunUntilIdle();
  EXPECT_EQ(counter, 1);

  std::unique_ptr<TestObject> test_object2 =
      std::make_unique<TestObject>(&counter);
  task_runner->DeleteSoon(FROM_HERE, std::move(test_object2));
  EXPECT_EQ(counter, 1);
  RunUntilIdle();
  EXPECT_EQ(counter, 2);
}

}  // namespace worker_scheduler_unittest
}  // namespace scheduler
}  // namespace blink
```