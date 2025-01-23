Response: Let's break down the thought process for analyzing this C++ unittest file for Chromium's Blink engine.

1. **Identify the Core Subject:** The filename `worker_thread_scheduler_unittest.cc` immediately tells us this file contains unit tests for the `WorkerThreadScheduler` class. The `unittest.cc` suffix is a common convention.

2. **Understand the Purpose of Unit Tests:** Unit tests are designed to verify the behavior of individual units of code in isolation. They typically set up specific conditions, execute a function or method, and then assert that the result matches the expected outcome.

3. **Scan for Key Components and Concepts:**  Quickly skim the code for important classes, functions, and data structures. Look for keywords related to testing (`TEST_F`, `EXPECT_THAT`, `ASSERT_EQ`), scheduling (`PostTask`, `PostDelayedTask`, `PostIdleTask`, `RunUntilIdle`), time (`base::TimeTicks`, `base::TimeDelta`), and any Blink-specific terms (`FrameScheduler`, `WorkerSchedulerProxy`).

4. **Group Functionality by Test Cases:**  Notice the `TEST_F` macros, which define individual test cases. Each test case focuses on a specific aspect of the `WorkerThreadScheduler`'s functionality. Mentally (or physically) group related test cases together. For example, tests involving posting and executing tasks form one group. Tests related to idle tasks form another.

5. **Analyze Individual Test Cases:** For each test case, ask:
    * **What is being tested?** (Look at the test name and the actions performed within the test).
    * **What is the setup?** (How is the `WorkerThreadScheduler` initialized? What tasks are posted?)
    * **What is the expected outcome?** (What are the assertions checking?)
    * **How does this relate to the `WorkerThreadScheduler`'s responsibilities?**

6. **Identify Relationships to Web Technologies (JavaScript, HTML, CSS):** Consider how the functionality being tested might relate to web development concepts. Think about:
    * **JavaScript execution:**  Workers execute JavaScript in a separate thread. The scheduler is responsible for managing these tasks.
    * **Event handling:**  JavaScript events can trigger tasks.
    * **Timers:** `setTimeout` and `setInterval` rely on scheduling mechanisms.
    * **Idle detection:**  Browsers often perform tasks during idle periods.
    * **Rendering pipeline:** Although this specific class is for worker threads, scheduling is a fundamental aspect of the entire rendering process.

7. **Look for Logic and Assumptions:**  Examine the code for any explicit logic or implicit assumptions. For instance, the idle task scheduling logic depends on the system being "quiescent." The tests demonstrate how posting regular tasks affects the timing of idle tasks.

8. **Identify Potential Usage Errors:**  Think about how a developer might misuse the `WorkerThreadScheduler` or related APIs. Are there scenarios where tasks might not execute as expected?  Are there timing-related issues to consider?

9. **Consider the UKM Integration:**  Notice the tests involving `ukm::TestUkmRecorder`. This indicates the scheduler collects metrics for User Keyed Metrics, which are used for performance analysis and understanding user behavior.

10. **Synthesize and Structure the Output:** Organize the findings into clear categories:

    * **Core Functionality:** Start with the primary responsibilities of the class.
    * **Relationships to Web Tech:** Connect the tested functionality to JavaScript, HTML, and CSS concepts. Provide concrete examples.
    * **Logical Reasoning:** Explain the assumptions, inputs, and outputs of specific test scenarios.
    * **Potential Usage Errors:**  Highlight common mistakes developers might make.

**Self-Correction/Refinement during the Process:**

* **Initial thought:** "This just tests basic task posting."
* **Correction:**  "Wait, there are also tests for delayed tasks, idle tasks, and how they interact. The scheduler prioritizes different types of tasks."
* **Initial thought:** "The UKM integration is just for internal metrics."
* **Correction:** "While internal, these metrics are used to understand performance characteristics, which indirectly affects the user experience of web pages."
* **Initial thought:** "The examples with JavaScript/HTML/CSS are a bit abstract."
* **Refinement:** "Let's provide concrete examples of how `setTimeout`, `requestIdleCallback`, and worker threads rely on this type of scheduling."

By following this structured approach, breaking down the code into smaller pieces, and continuously connecting the details back to the overall purpose of the `WorkerThreadScheduler`, we can effectively understand and explain its functionality and its role in the Blink rendering engine.
这个C++源代码文件 `worker_thread_scheduler_unittest.cc` 是 Chromium Blink 引擎中 `WorkerThreadScheduler` 类的单元测试文件。它的主要功能是验证 `WorkerThreadScheduler` 的各种行为和功能是否符合预期。

以下是该文件的详细功能列表，并结合 JavaScript、HTML、CSS 的关系进行说明：

**核心功能及测试点:**

1. **任务调度 (Task Scheduling):**
   - **功能:** 测试 `WorkerThreadScheduler` 是否能够正确地调度和执行不同类型的任务，包括普通任务 (Default Task) 和空闲任务 (Idle Task)。
   - **与 JavaScript 的关系:**  JavaScript 在 Worker 线程中执行时，其代码会被封装成任务由 `WorkerThreadScheduler` 调度。例如，`postMessage` 发送的消息、`setTimeout` 或 `setInterval` 设置的定时器回调，都可能作为任务被调度。
   - **假设输入与输出:**
     - **假设输入:**  向 `WorkerThreadScheduler` 提交多个普通任务和一个空闲任务。
     - **预期输出:** 普通任务会优先执行，然后在线程空闲时执行空闲任务。测试会验证任务的执行顺序是否符合预期。
   - **代码示例:** `TEST_F(WorkerThreadSchedulerTest, TestPostDefaultTask)` 和 `TEST_F(WorkerThreadSchedulerTest, TestPostIdleTask)` 测试了普通任务和空闲任务的基本调度。

2. **延迟任务 (Delayed Tasks):**
   - **功能:** 测试 `WorkerThreadScheduler` 是否能够正确处理延迟执行的任务。
   - **与 JavaScript 的关系:** `setTimeout` 和 `setInterval` 在 Worker 线程中的实现依赖于 `WorkerThreadScheduler` 的延迟任务机制。
   - **假设输入与输出:**
     - **假设输入:**  提交一个延迟 1 秒执行的普通任务。
     - **预期输出:**  在快进时间 1 秒后，该任务会被执行。
   - **代码示例:** `TEST_F(WorkerThreadSchedulerTest, TestPostDefaultDelayedAndIdleTasks)` 测试了延迟任务的执行。

3. **空闲任务调度 (Idle Task Scheduling):**
   - **功能:** 测试 `WorkerThreadScheduler` 如何调度空闲任务，包括在系统繁忙和空闲时的行为，以及空闲任务的截止时间 (deadline)。
   - **与 JavaScript 的关系:** `requestIdleCallback` API 允许 JavaScript 代码在浏览器空闲时执行。在 Worker 线程中，`WorkerThreadScheduler` 负责管理这些空闲任务。
   - **假设输入与输出:**
     - **假设输入:**  提交一个空闲任务，并在其执行前提交一个普通任务。
     - **预期输出:** 空闲任务会在普通任务执行完毕且线程进入空闲状态后执行。测试会验证空闲任务的执行时机和截止时间是否正确。
   - **代码示例:** `TEST_F(WorkerThreadSchedulerTest, TestIdleTaskWhenIsNotQuiescent)` 和 `TEST_F(WorkerThreadSchedulerTest, TestIdleDeadlineWithPendingDelayedTask)` 测试了空闲任务在不同场景下的行为。

4. **长空闲期 (Long Idle Period):**
   - **功能:** 测试 `WorkerThreadScheduler` 如何管理长空闲期，以及在长空闲期内调度空闲任务的行为。
   - **与 JavaScript 的关系:**  长空闲期是浏览器优化性能的一种机制，允许在用户无交互时执行一些低优先级的任务，例如垃圾回收。Worker 线程也会有类似的机制。
   - **假设输入与输出:**
     - **假设输入:**  在线程空闲一段时间后提交一个空闲任务。
     - **预期输出:** 空闲任务会在进入长空闲期后被执行。测试会验证长空闲期的触发和空闲任务的执行。
   - **代码示例:** `TEST_F(WorkerThreadSchedulerTest, TestLongIdlePeriodTimeline)` 测试了长空闲期的相关行为。

5. **微任务检查点 (Microtask Checkpoint):**
   - **功能:** 测试 `WorkerThreadScheduler` 在微任务检查点时的行为，并测量微任务的执行时间。
   - **与 JavaScript 的关系:**  JavaScript 的 Promise 和 `queueMicrotask` API 会产生微任务。`WorkerThreadScheduler` 需要在适当的时机执行这些微任务。
   - **假设输入与输出:**
     - **假设输入:**  提交一个任务，并在该任务执行过程中触发一个微任务检查点。
     - **预期输出:** 微任务检查点会被执行，并且微任务的执行时间会被计入前一个任务的执行时间。
   - **代码示例:** `TEST_F(WorkerThreadSchedulerTest, TestMicrotaskCheckpointTiming)` 测试了微任务检查点的时序。

6. **UKM (User Keyed Metrics) 记录:**
   - **功能:** 测试 `WorkerThreadScheduler` 是否能够正确记录任务执行相关的 UKM 指标。
   - **与 JavaScript、HTML、CSS 的关系:** UKM 用于收集用户体验相关的性能指标，例如任务的执行时长、CPU 占用等。这些指标可以帮助 Chromium 团队优化浏览器性能，从而提升网页加载速度和交互体验。
   - **假设输入与输出:**
     - **假设输入:**  完成一个特定类型的任务。
     - **预期输出:**  会生成一条包含该任务相关信息的 UKM 记录，例如线程类型、任务类型、执行时长等。
   - **代码示例:** `TEST_F(WorkerThreadSchedulerWithProxyTest, UkmTaskRecording)` 测试了 UKM 记录功能。

**与 JavaScript, HTML, CSS 的功能关系举例:**

* **JavaScript `setTimeout` in Workers:**  当在 Worker 线程中使用 `setTimeout` 时，`WorkerThreadScheduler` 会创建一个延迟任务，并在指定的时间后执行回调函数。测试中的 `PostDelayedTask` 就模拟了这种场景。
* **JavaScript `requestIdleCallback` in Workers:**  `requestIdleCallback` 允许在 Worker 线程空闲时执行代码。`WorkerThreadScheduler` 的空闲任务调度机制正是为了支持这种 API。测试中的 `PostIdleTask` 相关测试验证了这一点。
* **JavaScript Promise in Workers:**  当 Worker 线程中执行 Promise 的 `then` 或 `catch` 回调时，这些回调会被作为微任务添加到队列中。`WorkerThreadScheduler` 会在合适的时机（微任务检查点）执行这些微任务。`TestMicrotaskCheckpointTiming` 模拟了这种行为。
* **HTML 和 CSS 的资源加载和解析:**  虽然这个测试文件主要关注 Worker 线程的调度，但 Worker 线程也可能参与到 HTML 和 CSS 资源的加载和解析过程中。例如，Service Worker 可以拦截网络请求并缓存资源。`WorkerThreadScheduler` 负责调度这些 Service Worker 的任务。
* **性能监控和优化:**  `WorkerThreadScheduler` 收集的 UKM 指标可以帮助开发者和 Chromium 团队了解 Worker 线程的性能瓶颈，例如哪些类型的任务执行时间过长，从而进行优化，最终提升网页的渲染性能和用户体验。

**逻辑推理的假设输入与输出:**

很多测试用例都包含了逻辑推理。以下举例说明：

* **假设输入:** 先提交一个延迟 1 秒的普通任务，然后提交一个空闲任务。
* **预期输出:**  空闲任务不会在延迟任务执行前执行，因为它需要等待线程进入空闲状态。只有在延迟任务执行完毕后，线程才有可能进入空闲状态并执行空闲任务。

**用户或编程常见的使用错误举例:**

虽然这个文件是测试代码，但它也间接揭示了一些用户或编程可能犯的错误：

* **过度依赖高优先级任务:** 如果在 Worker 线程中提交了大量的普通任务，可能会导致空闲任务一直无法执行，从而影响到依赖空闲任务执行的功能，例如性能优化或资源清理。
* **不合理的延迟设置:**  `setTimeout` 的延迟时间设置不合理可能会导致任务执行不及时或过于频繁，影响性能。
* **对微任务执行时机的误解:**  开发者可能不清楚微任务会在当前任务执行完毕后立即执行，这可能会导致一些时序上的错误。
* **没有考虑 Worker 线程的生命周期:**  如果在 Worker 线程销毁后仍然尝试提交任务，可能会导致程序崩溃或出现未定义行为。虽然这个文件没有直接测试这种情况，但 `WorkerThreadScheduler` 的设计需要考虑 Worker 线程的生命周期管理。

总而言之，`worker_thread_scheduler_unittest.cc` 通过各种测试用例，全面地验证了 `WorkerThreadScheduler` 的任务调度、延迟执行、空闲处理以及性能监控等核心功能，确保了 Worker 线程能够高效可靠地执行各种任务，从而支持 Web Worker 和 Service Worker 等重要特性在 Blink 引擎中的正确运行。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/worker/worker_thread_scheduler_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/worker/worker_thread_scheduler.h"

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/memory/raw_ptr.h"
#include "base/task/sequence_manager/test/fake_task.h"
#include "base/task/sequence_manager/test/sequence_manager_for_test.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "components/ukm/test_ukm_recorder.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/scheduler/common/process_state.h"
#include "third_party/blink/renderer/platform/scheduler/common/task_priority.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_frame_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/test/recording_task_time_observer.h"

using testing::ElementsAreArray;

namespace blink {
namespace scheduler {
// To avoid symbol collisions in jumbo builds.
namespace worker_thread_scheduler_unittest {

namespace {

void NopTask() {}

// Instantiated at the beginning of each test. |timeline_start_ticks_| can be
// used to offset the original Now() against future timings to helper
// readability of the test cases.
class ScopedSaveStartTicks {
 public:
  ScopedSaveStartTicks(base::TimeTicks now) {
    DCHECK(timeline_start_ticks_.is_null());
    timeline_start_ticks_ = now;
  }

  ~ScopedSaveStartTicks() { timeline_start_ticks_ = base::TimeTicks(); }

  static base::TimeTicks timeline_start_ticks_;
};

// static
base::TimeTicks ScopedSaveStartTicks::timeline_start_ticks_;

int TimeTicksToIntMs(const base::TimeTicks& time) {
  return static_cast<int>(
      (time - ScopedSaveStartTicks::timeline_start_ticks_).InMilliseconds());
}

void RecordTimelineTask(Vector<String>* timeline,
                        const base::TickClock* clock) {
  timeline->push_back(String::Format("run RecordTimelineTask @ %d",
                                     TimeTicksToIntMs(clock->NowTicks())));
}

void AppendToVectorTestTask(Vector<String>* vector, String value) {
  vector->push_back(value);
}

void AppendToVectorIdleTestTask(Vector<String>* vector,
                                String value,
                                base::TimeTicks deadline) {
  AppendToVectorTestTask(vector, value);
}

void TimelineIdleTestTask(Vector<String>* timeline, base::TimeTicks deadline) {
  timeline->push_back(String::Format("run TimelineIdleTestTask deadline %d",
                                     TimeTicksToIntMs(deadline)));
}

class WorkerThreadSchedulerForTest : public WorkerThreadScheduler {
 public:
  WorkerThreadSchedulerForTest(base::sequence_manager::SequenceManager* manager,
                               const base::TickClock* clock_,
                               Vector<String>* timeline)
      : WorkerThreadScheduler(ThreadType::kTestThread, manager, nullptr),
        clock_(clock_),
        timeline_(timeline) {}

  WorkerThreadSchedulerForTest(base::sequence_manager::SequenceManager* manager,
                               const base::TickClock* clock_,
                               Vector<String>* timeline,
                               WorkerSchedulerProxy* proxy)
      : WorkerThreadScheduler(ThreadType::kTestThread, manager, proxy),
        clock_(clock_),
        timeline_(timeline) {}

  using WorkerThreadScheduler::SetUkmRecorderForTest;
  using WorkerThreadScheduler::SetUkmTaskSamplingRateForTest;

  void AddTaskTimeObserver(base::sequence_manager::TaskTimeObserver* observer) {
    GetHelper().AddTaskTimeObserver(observer);
  }

  void RemoveTaskTimeObserver(
      base::sequence_manager::TaskTimeObserver* observer) {
    GetHelper().RemoveTaskTimeObserver(observer);
  }

  void set_on_microtask_checkpoint(base::OnceClosure cb) {
    on_microtask_checkpoint_ = std::move(cb);
  }

 private:
  bool CanEnterLongIdlePeriod(
      base::TimeTicks now,
      base::TimeDelta* next_long_idle_period_delay_out) override {
    if (timeline_) {
      timeline_->push_back(
          String::Format("CanEnterLongIdlePeriod @ %d", TimeTicksToIntMs(now)));
    }
    return WorkerThreadScheduler::CanEnterLongIdlePeriod(
        now, next_long_idle_period_delay_out);
  }

  void IsNotQuiescent() override {
    if (timeline_) {
      timeline_->push_back(String::Format(
          "IsNotQuiescent @ %d", TimeTicksToIntMs(clock_->NowTicks())));
    }
    WorkerThreadScheduler::IsNotQuiescent();
  }

  void PerformMicrotaskCheckpoint() override {
    if (on_microtask_checkpoint_)
      std::move(on_microtask_checkpoint_).Run();
  }

  raw_ptr<const base::TickClock> clock_;  // Not owned.
  raw_ptr<Vector<String>> timeline_;      // Not owned.
  base::OnceClosure on_microtask_checkpoint_;
};

class WorkerThreadSchedulerTest : public testing::Test {
 public:
  WorkerThreadSchedulerTest()
      : task_environment_(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME,
            base::test::TaskEnvironment::ThreadPoolExecutionMode::QUEUED),
        sequence_manager_(
            base::sequence_manager::SequenceManagerForTest::Create(
                nullptr,
                task_environment_.GetMainThreadTaskRunner(),
                task_environment_.GetMockTickClock(),
                base::sequence_manager::SequenceManager::Settings::Builder()
                    .SetPrioritySettings(CreatePrioritySettings())
                    .Build())),
        scheduler_(new WorkerThreadSchedulerForTest(
            sequence_manager_.get(),
            task_environment_.GetMockTickClock(),
            &timeline_)) {
    scheduler_->Init();
    scheduler_->AttachToCurrentThread();
    default_task_queue_ =
        scheduler_->CreateTaskQueue(base::sequence_manager::QueueName::TEST_TQ);
    default_task_runner_ =
        default_task_queue_->GetTaskRunnerWithDefaultTaskType();
    idle_task_runner_ = scheduler_->IdleTaskRunner();
  }

  WorkerThreadSchedulerTest(const WorkerThreadSchedulerTest&) = delete;
  WorkerThreadSchedulerTest& operator=(const WorkerThreadSchedulerTest&) =
      delete;
  ~WorkerThreadSchedulerTest() override = default;

  void TearDown() override {
    task_environment_.FastForwardUntilNoTasksRemain();
  }

  void RunUntilIdle() {
    timeline_.push_back(String::Format(
        "RunUntilIdle begin @ %d",
        TimeTicksToIntMs(task_environment_.GetMockTickClock()->NowTicks())));
    // RunUntilIdle with auto-advancing for the mock clock.
    task_environment_.FastForwardUntilNoTasksRemain();
    timeline_.push_back(String::Format(
        "RunUntilIdle end @ %d",
        TimeTicksToIntMs(task_environment_.GetMockTickClock()->NowTicks())));
  }

  // Helper for posting several tasks of specific types. |task_descriptor| is a
  // string with space delimited task identifiers. The first letter of each
  // task identifier specifies the task type:
  // - 'D': Default task
  // - 'I': Idle task
  void PostTestTasks(Vector<String>* run_order, const String& task_descriptor) {
    std::istringstream stream(task_descriptor.Utf8());
    while (!stream.eof()) {
      std::string task;
      stream >> task;
      switch (task[0]) {
        case 'D':
          default_task_runner_->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        case 'I':
          idle_task_runner_->PostIdleTask(
              FROM_HERE, base::BindOnce(&AppendToVectorIdleTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        default:
          NOTREACHED();
      }
    }
  }

  static base::TimeDelta maximum_idle_period_duration() {
    return IdleHelper::kMaximumIdlePeriod;
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  // Needs to be initialized immediately after |task_environment_|, specifically
  // before |scheduler_|.
  ScopedSaveStartTicks save_start_ticks_{task_environment_.NowTicks()};
  std::unique_ptr<base::sequence_manager::SequenceManagerForTest>
      sequence_manager_;
  Vector<String> timeline_;
  std::unique_ptr<WorkerThreadSchedulerForTest> scheduler_;
  scoped_refptr<NonMainThreadTaskQueue> default_task_queue_;
  scoped_refptr<base::SingleThreadTaskRunner> default_task_runner_;
  scoped_refptr<SingleThreadIdleTaskRunner> idle_task_runner_;
};

}  // namespace

TEST_F(WorkerThreadSchedulerTest, TestPostDefaultTask) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 D2 D3 D4");

  RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "D2", "D3", "D4"));
}

TEST_F(WorkerThreadSchedulerTest, TestPostIdleTask) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "I1");

  RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("I1"));
}

TEST_F(WorkerThreadSchedulerTest, TestPostDefaultAndIdleTasks) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D2 D3 D4");

  RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("D2", "D3", "D4", "I1"));
}

TEST_F(WorkerThreadSchedulerTest, TestPostDefaultDelayedAndIdleTasks) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D2 D3 D4");

  default_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&AppendToVectorTestTask, &run_order, "DELAYED"),
      base::Milliseconds(1000));

  RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("D2", "D3", "D4", "I1", "DELAYED"));
}

TEST_F(WorkerThreadSchedulerTest, TestIdleTaskWhenIsNotQuiescent) {
  timeline_.push_back("Post default task");
  // Post a delayed task timed to occur mid way during the long idle period.
  default_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&RecordTimelineTask, base::Unretained(&timeline_),
                     base::Unretained(task_environment_.GetMockTickClock())));
  RunUntilIdle();

  timeline_.push_back("Post idle task");
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&TimelineIdleTestTask, base::Unretained(&timeline_)));

  RunUntilIdle();

  String expected_timeline[] = {
      "CanEnterLongIdlePeriod @ 0",   "Post default task",
      "RunUntilIdle begin @ 0",       "run RecordTimelineTask @ 0",
      "RunUntilIdle end @ 0",         "Post idle task",
      "RunUntilIdle begin @ 0",       "IsNotQuiescent @ 0",
      "CanEnterLongIdlePeriod @ 300", "run TimelineIdleTestTask deadline 350",
      "RunUntilIdle end @ 300"};

  EXPECT_THAT(timeline_, ElementsAreArray(expected_timeline));
}

TEST_F(WorkerThreadSchedulerTest, TestIdleDeadlineWithPendingDelayedTask) {
  timeline_.push_back("Post delayed and idle tasks");
  // Post a delayed task timed to occur mid way during the long idle period.
  default_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RecordTimelineTask, base::Unretained(&timeline_),
                     base::Unretained(task_environment_.GetMockTickClock())),
      base::Milliseconds(20));
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&TimelineIdleTestTask, base::Unretained(&timeline_)));

  RunUntilIdle();

  String expected_timeline[] = {
      "CanEnterLongIdlePeriod @ 0",
      "Post delayed and idle tasks",
      "RunUntilIdle begin @ 0",
      "CanEnterLongIdlePeriod @ 0",
      "run TimelineIdleTestTask deadline 20",  // Note the short 20ms deadline.
      "run RecordTimelineTask @ 20",
      "RunUntilIdle end @ 20"};

  EXPECT_THAT(timeline_, ElementsAreArray(expected_timeline));
}

TEST_F(WorkerThreadSchedulerTest,
       TestIdleDeadlineWithPendingDelayedTaskFarInTheFuture) {
  timeline_.push_back("Post delayed and idle tasks");
  // Post a delayed task timed to occur well after the long idle period.
  default_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RecordTimelineTask, base::Unretained(&timeline_),
                     base::Unretained(task_environment_.GetMockTickClock())),
      base::Milliseconds(500));
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&TimelineIdleTestTask, base::Unretained(&timeline_)));

  RunUntilIdle();

  String expected_timeline[] = {
      "CanEnterLongIdlePeriod @ 0",
      "Post delayed and idle tasks",
      "RunUntilIdle begin @ 0",
      "CanEnterLongIdlePeriod @ 0",
      "run TimelineIdleTestTask deadline 50",  // Note the full 50ms deadline.
      "run RecordTimelineTask @ 500",
      "RunUntilIdle end @ 500"};

  EXPECT_THAT(timeline_, ElementsAreArray(expected_timeline));
}

TEST_F(WorkerThreadSchedulerTest, TestPostIdleTaskAfterRunningUntilIdle) {
  default_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NopTask),
                                        base::Milliseconds(1000));
  RunUntilIdle();

  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 I2 D3");

  RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("D3", "I1", "I2"));
}

void PostIdleTask(Vector<String>* timeline,
                  const base::TickClock* clock,
                  SingleThreadIdleTaskRunner* idle_task_runner) {
  timeline->push_back(String::Format("run PostIdleTask @ %d",
                                     TimeTicksToIntMs(clock->NowTicks())));

  idle_task_runner->PostIdleTask(
      FROM_HERE, base::BindOnce(&TimelineIdleTestTask, timeline));
}

TEST_F(WorkerThreadSchedulerTest, TestLongIdlePeriodTimeline) {
  // The scheduler should not run the initiate_next_long_idle_period task if
  // there are no idle tasks and no other task woke up the scheduler, thus
  // the idle period deadline shouldn't update at the end of the current long
  // idle period.
  base::TimeTicks idle_period_deadline =
      scheduler_->CurrentIdleTaskDeadlineForTesting();
  // Not printed in the timeline.
  task_environment_.FastForwardBy(maximum_idle_period_duration());

  base::TimeTicks new_idle_period_deadline =
      scheduler_->CurrentIdleTaskDeadlineForTesting();
  EXPECT_EQ(idle_period_deadline, new_idle_period_deadline);

  // Post a task to post an idle task. Because the system is non-quiescent a
  // 300ms pause will occur before the next long idle period is initiated and
  // the idle task run.
  default_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&PostIdleTask, base::Unretained(&timeline_),
                     base::Unretained(task_environment_.GetMockTickClock()),
                     base::Unretained(idle_task_runner_.get())),
      base::Milliseconds(30));

  timeline_.push_back("PostFirstIdleTask");
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&TimelineIdleTestTask, base::Unretained(&timeline_)));
  RunUntilIdle();
  new_idle_period_deadline = scheduler_->CurrentIdleTaskDeadlineForTesting();

  // Running a normal task will mark the system as non-quiescent.
  timeline_.push_back("Post RecordTimelineTask");
  default_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&RecordTimelineTask, base::Unretained(&timeline_),
                     base::Unretained(task_environment_.GetMockTickClock())));
  RunUntilIdle();

  String expected_timeline[] = {"CanEnterLongIdlePeriod @ 0",
                                "PostFirstIdleTask",
                                "RunUntilIdle begin @ 50",
                                "CanEnterLongIdlePeriod @ 50",
                                "run TimelineIdleTestTask deadline 80",
                                "run PostIdleTask @ 80",
                                "IsNotQuiescent @ 80",
                                "CanEnterLongIdlePeriod @ 380",
                                "run TimelineIdleTestTask deadline 430",
                                "RunUntilIdle end @ 380",
                                "Post RecordTimelineTask",
                                "RunUntilIdle begin @ 380",
                                "run RecordTimelineTask @ 380",
                                "RunUntilIdle end @ 380"};

  EXPECT_THAT(timeline_, ElementsAreArray(expected_timeline));
}

TEST_F(WorkerThreadSchedulerTest, TestMicrotaskCheckpointTiming) {
  const base::TimeDelta kTaskTime = base::Milliseconds(100);
  const base::TimeDelta kMicrotaskTime = base::Milliseconds(200);

  base::TimeTicks start_time = task_environment_.NowTicks();
  default_task_runner_->PostTask(
      FROM_HERE,
      WTF::BindOnce(&base::test::TaskEnvironment::FastForwardBy,
                    base::Unretained(&task_environment_), kTaskTime));
  scheduler_->set_on_microtask_checkpoint(
      WTF::BindOnce(&base::test::TaskEnvironment::FastForwardBy,
                    base::Unretained(&task_environment_), kMicrotaskTime));

  RecordingTaskTimeObserver observer;

  scheduler_->AddTaskTimeObserver(&observer);
  RunUntilIdle();
  scheduler_->RemoveTaskTimeObserver(&observer);

  // Expect that the duration of microtask is counted as a part of the preceding
  // task.
  ASSERT_EQ(1u, observer.result().size());
  EXPECT_EQ(start_time, observer.result().back().first);
  EXPECT_EQ(start_time + kTaskTime + kMicrotaskTime,
            observer.result().back().second);
}

namespace {

class FrameSchedulerDelegateWithUkmSourceId : public FrameScheduler::Delegate {
 public:
  FrameSchedulerDelegateWithUkmSourceId(ukm::SourceId source_id)
      : source_id_(source_id) {}

  ~FrameSchedulerDelegateWithUkmSourceId() override {}

  ukm::UkmRecorder* GetUkmRecorder() override { return nullptr; }

  ukm::SourceId GetUkmSourceId() override { return source_id_; }
  void OnTaskCompleted(base::TimeTicks,
                       base::TimeTicks) override {}

  void UpdateTaskTime(base::TimeDelta time) override {}

  void UpdateBackForwardCacheDisablingFeatures(BlockingDetails) override {}

  const base::UnguessableToken& GetAgentClusterId() const override {
    return base::UnguessableToken::Null();
  }

  DocumentResourceCoordinator* GetDocumentResourceCoordinator() override {
    return nullptr;
  }

 private:
  ukm::SourceId source_id_;
};

}  // namespace

class WorkerThreadSchedulerWithProxyTest : public testing::Test {
 public:
  WorkerThreadSchedulerWithProxyTest()
      : task_environment_(
            base::test::TaskEnvironment::TimeSource::MOCK_TIME,
            base::test::TaskEnvironment::ThreadPoolExecutionMode::QUEUED),
        sequence_manager_(
            base::sequence_manager::SequenceManagerForTest::Create(
                nullptr,
                task_environment_.GetMainThreadTaskRunner(),
                task_environment_.GetMockTickClock(),
                base::sequence_manager::SequenceManager::Settings::Builder()
                    .SetPrioritySettings(CreatePrioritySettings())
                    .Build())) {
    frame_scheduler_delegate_ =
        std::make_unique<FrameSchedulerDelegateWithUkmSourceId>(42);
    frame_scheduler_ = FakeFrameScheduler::Builder()
                           .SetIsPageVisible(false)
                           .SetFrameType(FrameScheduler::FrameType::kSubframe)
                           .SetIsCrossOriginToNearestMainFrame(true)
                           .SetDelegate(frame_scheduler_delegate_.get())
                           .Build();
    frame_scheduler_->SetCrossOriginToNearestMainFrame(true);

    worker_scheduler_proxy_ =
        std::make_unique<WorkerSchedulerProxy>(frame_scheduler_.get());

    scheduler_ = std::make_unique<WorkerThreadSchedulerForTest>(
        sequence_manager_.get(), task_environment_.GetMockTickClock(),
        &timeline_, worker_scheduler_proxy_.get());

    task_environment_.FastForwardBy(base::Milliseconds(5));

    scheduler_->Init();
    scheduler_->AttachToCurrentThread();
  }

  WorkerThreadSchedulerWithProxyTest(
      const WorkerThreadSchedulerWithProxyTest&) = delete;
  WorkerThreadSchedulerWithProxyTest& operator=(
      const WorkerThreadSchedulerWithProxyTest&) = delete;
  ~WorkerThreadSchedulerWithProxyTest() override = default;

  void TearDown() override {
    task_environment_.FastForwardUntilNoTasksRemain();
  }

 protected:
  base::test::TaskEnvironment task_environment_;
  std::unique_ptr<base::sequence_manager::SequenceManagerForTest>
      sequence_manager_;
  Vector<String> timeline_;
  std::unique_ptr<FrameScheduler::Delegate> frame_scheduler_delegate_;
  std::unique_ptr<FrameScheduler> frame_scheduler_;
  std::unique_ptr<WorkerSchedulerProxy> worker_scheduler_proxy_;
  std::unique_ptr<WorkerThreadSchedulerForTest> scheduler_;
  scoped_refptr<base::SingleThreadTaskRunner> default_task_runner_;
  scoped_refptr<SingleThreadIdleTaskRunner> idle_task_runner_;
};

TEST_F(WorkerThreadSchedulerWithProxyTest, UkmTaskRecording) {
  internal::ProcessState::Get()->is_process_backgrounded = true;

  std::unique_ptr<ukm::TestUkmRecorder> owned_ukm_recorder =
      std::make_unique<ukm::TestUkmRecorder>();
  ukm::TestUkmRecorder* ukm_recorder = owned_ukm_recorder.get();

  scheduler_->SetUkmTaskSamplingRateForTest(1);
  scheduler_->SetUkmRecorderForTest(std::move(owned_ukm_recorder));

  base::sequence_manager::FakeTask task(
      static_cast<int>(TaskType::kJavascriptTimerDelayedLowNesting));
  base::sequence_manager::FakeTaskTiming task_timing(
      base::TimeTicks() + base::Milliseconds(200),
      base::TimeTicks() + base::Milliseconds(700),
      base::ThreadTicks() + base::Milliseconds(250),
      base::ThreadTicks() + base::Milliseconds(500));

  scheduler_->OnTaskCompleted(nullptr, task, &task_timing, nullptr);

  auto entries = ukm_recorder->GetEntriesByName("RendererSchedulerTask");

  EXPECT_EQ(entries.size(), static_cast<size_t>(1));

  ukm::TestUkmRecorder::ExpectEntryMetric(
      entries[0], "ThreadType", static_cast<int>(ThreadType::kTestThread));
  ukm::TestUkmRecorder::ExpectEntryMetric(entries[0], "RendererBackgrounded",
                                          true);
  ukm::TestUkmRecorder::ExpectEntryMetric(
      entries[0], "TaskType",
      static_cast<int>(TaskType::kJavascriptTimerDelayedLowNesting));
  ukm::TestUkmRecorder::ExpectEntryMetric(
      entries[0], "FrameStatus",
      static_cast<int>(FrameStatus::kCrossOriginBackground));
  ukm::TestUkmRecorder::ExpectEntryMetric(entries[0], "TaskDuration", 500000);
  ukm::TestUkmRecorder::ExpectEntryMetric(entries[0], "TaskCPUDuration",
                                          250000);
}

}  // namespace worker_thread_scheduler_unittest
}  // namespace scheduler
}  // namespace blink
```