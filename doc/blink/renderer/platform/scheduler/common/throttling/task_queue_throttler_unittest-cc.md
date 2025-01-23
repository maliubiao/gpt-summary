Response: The user wants a summary of the functionality of the provided C++ unittest file for `TaskQueueThrottler` in the Chromium Blink engine. I need to identify the main purpose of this file, which is to test the `TaskQueueThrottler` class. I should look for patterns in the tests, like how tasks are scheduled and how throttling is applied. Keywords like "throttle", "alignment", "wake up", and "budget" are important.

Specifically, I need to:
1. **Identify the core functionality being tested**: This seems to be about controlling the execution of tasks in a task queue based on different throttling mechanisms.
2. **Look for relationships with web technologies**:  While this is low-level code, I should consider how task scheduling and throttling might relate to the responsiveness of JavaScript, HTML rendering, and CSS animations.
3. **Extract logical reasoning**:  The tests likely involve setting up scenarios (inputs) and verifying the expected behavior (outputs) of the throttler.
4. **Identify potential usage errors**:  Unittests often implicitly reveal how a class should *not* be used.
5. **Summarize the overall functionality based on the first part of the file.**
```
这是目录为blink/renderer/platform/scheduler/common/throttling/task_queue_throttler_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能,
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

这个 C++ 单元测试文件 `task_queue_throttler_unittest.cc` 的主要功能是**测试 `TaskQueueThrottler` 类的各种功能和行为**。`TaskQueueThrottler` 类的作用是控制任务队列中任务的执行速度，以避免过度消耗资源或影响性能。

**与 JavaScript、HTML、CSS 的功能关系：**

虽然这个文件本身是 C++ 代码，但 `TaskQueueThrottler` 的行为直接影响 Blink 引擎处理 JavaScript、HTML 和 CSS 的方式。

* **JavaScript：**  JavaScript 代码的执行通常通过任务调度进行。`TaskQueueThrottler` 可以限制 JavaScript 任务的执行频率。例如，一个高频率触发的 `requestAnimationFrame` 回调可能被 `TaskQueueThrottler` 限制，以避免帧率过高导致不必要的资源消耗。
    * **举例：** 假设一个网页有复杂的 JavaScript 动画，并且动画代码使用了 `setInterval` 或 `requestAnimationFrame` 来更新 UI。如果 `TaskQueueThrottler` 被激活，它可能会延迟这些回调的执行，从而降低动画的帧率，减少 CPU 使用率。
* **HTML 和 CSS：**  HTML 的解析、CSS 的计算和布局也依赖于任务调度。`TaskQueueThrottler` 可以影响这些过程的执行速度。例如，在页面滚动时触发的大量重绘和重排操作，可能会受到 `TaskQueueThrottler` 的限制，以防止页面卡顿。
    * **举例：**  假设用户快速滚动一个包含大量元素的网页。`TaskQueueThrottler` 可能会延迟处理与滚动事件相关的布局和绘制任务，从而避免在滚动过程中出现明显的卡顿。

**逻辑推理 (基于部分代码)：**

* **假设输入：**  一个任务队列 `timer_queue_`，并且 `TaskQueueThrottler` 被设置为启用状态（通过 `IncreaseThrottleRefCount()`）。
* **输出：**  当向 `timer_queue_` 提交延迟任务时，这些任务的实际执行时间可能会被延迟到下一个对齐的时间点（例如，1 秒的倍数），除非 `TaskQueueThrottler` 被禁用。
    * **代码体现：** `TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest, TimerAlignment)` 和 `TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest, WakeUpForDelayedTask)` 等测试用例展示了这种行为。
* **假设输入：**  `TaskQueueThrottler` 的引用计数大于 0。
* **输出：**  与该 `TaskQueueThrottler` 关联的任务队列会被认为是“被节流”的状态，其任务的执行可能会受到限制。
    * **代码体现：** `TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest, Refcount)` 测试用例验证了引用计数对节流状态的影响。

**涉及用户或编程常见的使用错误（基于部分代码推测）：**

虽然这里是测试代码，但可以推测一些可能的使用错误：

* **不匹配的 `IncreaseThrottleRefCount()` 和 `DecreaseThrottleRefCount()` 调用：** 如果只调用 `IncreaseThrottleRefCount()` 而不调用相应的 `DecreaseThrottleRefCount()`，节流状态可能一直保持，导致任务队列一直处于受限状态，从而影响应用的响应性。
* **过度依赖时间对齐：**  虽然 `TaskQueueThrottler` 提供了时间对齐的功能，但过度依赖这种机制可能会导致任务执行出现意外的延迟。开发者应该理解时间对齐的原理和适用场景。

**第一部分的功能归纳：**

这部分代码主要关注 `TaskQueueThrottler` 的基本节流功能和基于时间的任务对齐机制的测试。它测试了以下方面：

1. **基本的节流/取消节流功能：** 通过 `IncreaseThrottleRefCount()` 和 `DecreaseThrottleRefCount()` 控制任务队列的执行。
2. **基于时间的任务对齐：**  当启用节流时，延迟任务会被推迟到下一个时间对齐的边界执行。
3. **唤醒机制：**  即使在节流状态下，某些类型的任务（例如，非延迟任务或即将到期的延迟任务）也能触发任务队列的“唤醒”，从而得到执行。
4. **与 `WakeUpBudgetPool` 和 `CPUTimeBudgetPool` 的集成：** 测试 `TaskQueueThrottler` 如何与不同的预算池协同工作，进行更精细的资源控制。
5. **启用/禁用节流：**  测试在运行时动态启用和禁用节流机制的效果。
6. **报告节流信息：**  测试 `TaskQueueThrottler` 报告任务被节流的时间的功能。
7. **授予额外预算：** 测试 `CPUTimeBudgetPool` 允许为任务队列授予额外执行预算的功能。
8. **多个任务队列和预算池的协同工作：** 测试多个受不同预算池控制的任务队列之间的交互。

总而言之，这部分测试代码旨在全面验证 `TaskQueueThrottler` 作为一个核心的调度节流机制，其基本功能和与不同预算管理策略的集成是否正确工作。
```
### 提示词
```
这是目录为blink/renderer/platform/scheduler/common/throttling/task_queue_throttler_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/common/throttling/task_queue_throttler.h"

#include <stddef.h>

#include <memory>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/task/common/lazy_now.h"
#include "base/task/sequence_manager/sequence_manager.h"
#include "base/task/sequence_manager/task_queue.h"
#include "base/task/sequence_manager/test/sequence_manager_for_test.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/time/time.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/renderer/platform/scheduler/common/auto_advancing_virtual_time_domain.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/budget_pool.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/cpu_time_budget_pool.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/wake_up_budget_pool.h"
#include "third_party/blink/renderer/platform/wtf/deque.h"

namespace blink {
namespace scheduler {
// To avoid symbol collisions in jumbo builds.
namespace task_queue_throttler_unittest {

using base::LazyNow;
using base::TestMockTimeTaskRunner;
using base::TimeTicks;
using base::sequence_manager::TaskQueue;
using testing::ElementsAre;

void NopTask() {}

void AddOneTask(size_t* count) {
  (*count)++;
}

void RunTenTimesTask(size_t* count, TaskQueue* timer_queue) {
  if (++(*count) < 10) {
    timer_queue->task_runner()->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&RunTenTimesTask, count, base::Unretained(timer_queue)),
        base::Milliseconds(1));
  }
}

Deque<base::TimeDelta> MakeTaskDurations(wtf_size_t size,
                                         base::TimeDelta duration) {
  Deque<base::TimeDelta> task_durations;
  for (wtf_size_t i = 0; i < size; ++i)
    task_durations.push_back(duration);
  return task_durations;
}

class TaskQueueThrottlerTest : public testing::Test {
 public:
  TaskQueueThrottlerTest()
      : test_task_runner_(base::MakeRefCounted<TestMockTimeTaskRunner>()) {}
  TaskQueueThrottlerTest(const TaskQueueThrottlerTest&) = delete;
  TaskQueueThrottlerTest& operator=(const TaskQueueThrottlerTest&) = delete;
  ~TaskQueueThrottlerTest() override = default;

  void SetUp() override {
    // A null clock triggers some assertions.
    test_task_runner_->AdvanceMockTickClock(base::Milliseconds(5));
    start_time_ = test_task_runner_->NowTicks();

    sequence_manager_ = base::sequence_manager::SequenceManagerForTest::Create(
        nullptr, test_task_runner_, GetTickClock());
    wake_up_budget_pool_ =
        std::make_unique<WakeUpBudgetPool>("Wake Up Budget Pool");
    wake_up_budget_pool_->SetWakeUpDuration(base::TimeDelta());
    wake_up_budget_pool_->SetWakeUpInterval(base::TimeTicks(),
                                            base::Seconds(1));

    timer_queue_ = CreateTaskQueue(base::sequence_manager::QueueName::TEST_TQ);
    task_queue_throttler_ = CreateThrottlerForTaskQueue(timer_queue_.get());

    wake_up_budget_pool_->AddThrottler(test_task_runner_->NowTicks(),
                                       task_queue_throttler_.get());
    timer_task_runner_ = timer_queue_->task_runner();
  }

  void TearDown() override {
    wake_up_budget_pool_->RemoveThrottler(test_task_runner_->NowTicks(),
                                          task_queue_throttler_.get());
    task_queue_throttler_.reset();
    timer_queue_.reset();
  }

  base::sequence_manager::TaskQueue::Handle CreateTaskQueue(
      base::sequence_manager::QueueName name) {
    return sequence_manager_->CreateTaskQueue(
        base::sequence_manager::TaskQueue::Spec(name).SetDelayedFencesAllowed(
            true));
  }

  std::unique_ptr<TaskQueueThrottler> CreateThrottlerForTaskQueue(
      base::sequence_manager::TaskQueue* queue) {
    auto throttler = std::make_unique<TaskQueueThrottler>(
        queue, test_task_runner_->GetMockTickClock());
    queue->SetOnTaskCompletedHandler(base::BindRepeating(
        [](TaskQueueThrottler* throttler,
           const base::sequence_manager::Task& task,
           TaskQueue::TaskTiming* task_timing, base::LazyNow* lazy_now) {
          task_timing->RecordTaskEnd(lazy_now);
          throttler->OnTaskRunTimeReported(task_timing->start_time(),
                                           task_timing->end_time());
        },
        base::Unretained(throttler.get())));
    return throttler;
  }

  void ExpectThrottled(TaskQueue* timer_queue) {
    size_t count = 0;
    timer_task_runner_->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&RunTenTimesTask, &count, base::Unretained(timer_queue)),
        base::Milliseconds(1));

    test_task_runner_->FastForwardBy(base::Milliseconds(11));
    EXPECT_EQ(count, 0u);

    // Make sure the rest of the tasks run or we risk a UAF on |count|.
    test_task_runner_->FastForwardUntilNoTasksRemain();
    EXPECT_EQ(count, 10u);
  }

  void ExpectUnthrottled(TaskQueue* timer_queue) {
    size_t count = 0;
    timer_task_runner_->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&RunTenTimesTask, &count, base::Unretained(timer_queue)),
        base::Milliseconds(1));

    test_task_runner_->FastForwardBy(base::Milliseconds(11));
    EXPECT_EQ(count, 10u);
  }

  bool IsQueueBlocked(TaskQueue* task_queue) {
    if (!task_queue->IsQueueEnabled())
      return true;
    return task_queue->BlockedByFence();
  }

  void ForwardTimeToNextMinute() {
    test_task_runner_->FastForwardBy(
        test_task_runner_->NowTicks().SnappedToNextTick(base::TimeTicks(),
                                                        base::Minutes(1)) -
        test_task_runner_->NowTicks());
  }

 protected:
  virtual const base::TickClock* GetTickClock() const {
    return test_task_runner_->GetMockTickClock();
  }

  base::TimeTicks start_time_;

  scoped_refptr<TestMockTimeTaskRunner> test_task_runner_;
  std::unique_ptr<base::sequence_manager::SequenceManager> sequence_manager_;

  // A queue that is subject to |wake_up_budget_pool_|.
  base::sequence_manager::TaskQueue::Handle timer_queue_;
  std::unique_ptr<TaskQueueThrottler> task_queue_throttler_;

  scoped_refptr<base::SingleThreadTaskRunner> timer_task_runner_;
  std::unique_ptr<WakeUpBudgetPool> wake_up_budget_pool_;

  TraceableVariableController tracing_controller_;
};

// Advances mock clock every time we call NowTicks() from the scheduler.
class AutoAdvancingProxyClock : public base::TickClock {
 public:
  AutoAdvancingProxyClock(scoped_refptr<TestMockTimeTaskRunner> task_runner)
      : task_runner_(task_runner) {}
  ~AutoAdvancingProxyClock() override = default;

  void SetAutoAdvanceInterval(base::TimeDelta interval) {
    advance_interval_ = interval;
  }

  base::TimeTicks NowTicks() const override {
    if (!advance_interval_.is_zero())
      task_runner_->AdvanceMockTickClock(advance_interval_);
    return task_runner_->NowTicks();
  }

 private:
  scoped_refptr<TestMockTimeTaskRunner> task_runner_;
  base::TimeDelta advance_interval_;
};

class TaskQueueThrottlerWithAutoAdvancingTimeTest
    : public TaskQueueThrottlerTest,
      public testing::WithParamInterface<bool> {
 public:
  TaskQueueThrottlerWithAutoAdvancingTimeTest()
      : proxy_clock_(test_task_runner_) {}
  TaskQueueThrottlerWithAutoAdvancingTimeTest(
      const TaskQueueThrottlerWithAutoAdvancingTimeTest&) = delete;
  TaskQueueThrottlerWithAutoAdvancingTimeTest& operator=(
      const TaskQueueThrottlerWithAutoAdvancingTimeTest&) = delete;
  ~TaskQueueThrottlerWithAutoAdvancingTimeTest() override = default;

  void SetUp() override {
    TaskQueueThrottlerTest::SetUp();
    if (GetParam()) {
      // Will advance the time by this value after running each task.
      proxy_clock_.SetAutoAdvanceInterval(base::Microseconds(10));
    }
  }

 protected:
  const base::TickClock* GetTickClock() const override { return &proxy_clock_; }

 private:
  AutoAdvancingProxyClock proxy_clock_;
};

INSTANTIATE_TEST_SUITE_P(All,
                         TaskQueueThrottlerWithAutoAdvancingTimeTest,
                         testing::Bool());

namespace {

// Round up time to milliseconds to deal with autoadvancing time.
// TODO(altimin): round time only when autoadvancing time is enabled.
base::TimeDelta RoundTimeToMilliseconds(base::TimeDelta time) {
  return time - time % base::Milliseconds(1);
}

base::TimeTicks RoundTimeToMilliseconds(base::TimeTicks time) {
  return base::TimeTicks() + RoundTimeToMilliseconds(time - base::TimeTicks());
}

void TestTask(Vector<base::TimeTicks>* run_times,
              scoped_refptr<TestMockTimeTaskRunner> task_runner) {
  run_times->push_back(RoundTimeToMilliseconds(task_runner->NowTicks()));
  // FIXME No auto-advancing
}

void ExpensiveTestTask(Vector<base::TimeTicks>* run_times,
                       scoped_refptr<TestMockTimeTaskRunner> task_runner) {
  run_times->push_back(RoundTimeToMilliseconds(task_runner->NowTicks()));
  task_runner->AdvanceMockTickClock(base::Milliseconds(250));
  // FIXME No auto-advancing
}

void RecordThrottling(Vector<base::TimeDelta>* reported_throttling_times,
                      base::TimeDelta throttling_duration) {
  reported_throttling_times->push_back(
      RoundTimeToMilliseconds(throttling_duration));
}
}  // namespace

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest, TimerAlignment) {
  Vector<base::TimeTicks> run_times;
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(200.0));

  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(800.0));

  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(1200.0));

  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(8300.0));

  task_queue_throttler_->IncreaseThrottleRefCount();

  test_task_runner_->FastForwardUntilNoTasksRemain();

  // Times are aligned to a multiple of 1000 milliseconds.
  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Seconds(1),
                                     base::TimeTicks() + base::Seconds(1),
                                     base::TimeTicks() + base::Seconds(2),
                                     base::TimeTicks() + base::Seconds(9)));
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       TimerAlignment_Unthrottled) {
  Vector<base::TimeTicks> run_times;
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(200.0));

  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(800.0));

  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(1200.0));

  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(8300.0));

  task_queue_throttler_->IncreaseThrottleRefCount();
  task_queue_throttler_->DecreaseThrottleRefCount();

  test_task_runner_->FastForwardUntilNoTasksRemain();

  // Times are not aligned.
  EXPECT_THAT(
      run_times,
      ElementsAre(
          RoundTimeToMilliseconds(start_time_ + base::Milliseconds(200.0)),
          RoundTimeToMilliseconds(start_time_ + base::Milliseconds(800.0)),
          RoundTimeToMilliseconds(start_time_ + base::Milliseconds(1200.0)),
          RoundTimeToMilliseconds(start_time_ + base::Milliseconds(8300.0))));
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest, Refcount) {
  ExpectUnthrottled(timer_queue_.get());

  task_queue_throttler_->IncreaseThrottleRefCount();
  ExpectThrottled(timer_queue_.get());

  task_queue_throttler_->IncreaseThrottleRefCount();
  ExpectThrottled(timer_queue_.get());

  task_queue_throttler_->DecreaseThrottleRefCount();
  ExpectThrottled(timer_queue_.get());

  task_queue_throttler_->DecreaseThrottleRefCount();
  ExpectUnthrottled(timer_queue_.get());

  task_queue_throttler_->IncreaseThrottleRefCount();
  ExpectThrottled(timer_queue_.get());
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest, WakeUpForNonDelayedTask) {
  Vector<base::TimeTicks> run_times;

  // Nothing is posted on timer_queue_ so PumpThrottledTasks will not tick.
  task_queue_throttler_->IncreaseThrottleRefCount();

  // Posting a task should trigger the pump.
  timer_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_));

  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(1000.0)));
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest, WakeUpForDelayedTask) {
  Vector<base::TimeTicks> run_times;

  // Nothing is posted on timer_queue_ so PumpThrottledTasks will not tick.
  task_queue_throttler_->IncreaseThrottleRefCount();

  // Posting a task should trigger the pump.
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(1200.0));

  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(2000.0)));
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       SingleThrottledTaskPumpedAndRunWithNoExtraneousMessageLoopTasks) {
  task_queue_throttler_->IncreaseThrottleRefCount();

  base::TimeDelta delay(base::Milliseconds(10));
  timer_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NopTask),
                                      delay);
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       SingleFutureThrottledTaskPumpedAndRunWithNoExtraneousMessageLoopTasks) {
  task_queue_throttler_->IncreaseThrottleRefCount();

  base::TimeDelta delay(base::Seconds(15.5));
  timer_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NopTask),
                                      delay);
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       TwoFutureThrottledTaskPumpedAndRunWithNoExtraneousMessageLoopTasks) {
  task_queue_throttler_->IncreaseThrottleRefCount();
  Vector<base::TimeTicks> run_times;

  base::TimeDelta delay(base::Seconds(15.5));
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      delay);

  base::TimeDelta delay2(base::Seconds(5.5));
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      delay2);

  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
  test_task_runner_->FastForwardBy(test_task_runner_->NextPendingTaskDelay());
  EXPECT_EQ(1u, test_task_runner_->GetPendingTaskCount());
  test_task_runner_->FastForwardBy(test_task_runner_->NextPendingTaskDelay());
  EXPECT_EQ(0u, test_task_runner_->GetPendingTaskCount());

  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Seconds(6),
                                     base::TimeTicks() + base::Seconds(16)));
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       TaskDelayIsBasedOnRealTime) {
  Vector<base::TimeTicks> run_times;

  task_queue_throttler_->IncreaseThrottleRefCount();

  // Post an initial task that should run at the first aligned time period.
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(900.0));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  // Advance realtime.
  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(250));

  // Post a task that due to real time + delay must run in the third aligned
  // time period.
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(900.0));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Seconds(1),
                                     base::TimeTicks() + base::Seconds(3)));
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       DoubleIncrementDoubleDecrement) {
  EXPECT_FALSE(IsQueueBlocked(timer_queue_.get()));
  task_queue_throttler_->IncreaseThrottleRefCount();
  task_queue_throttler_->IncreaseThrottleRefCount();
  EXPECT_TRUE(IsQueueBlocked(timer_queue_.get()));
  task_queue_throttler_->DecreaseThrottleRefCount();
  task_queue_throttler_->DecreaseThrottleRefCount();
  EXPECT_FALSE(IsQueueBlocked(timer_queue_.get()));
}

TEST_F(TaskQueueThrottlerTest, TimeBasedThrottling) {
  Vector<base::TimeTicks> run_times;

  std::unique_ptr<CPUTimeBudgetPool> pool = std::make_unique<CPUTimeBudgetPool>(
      "test", &tracing_controller_, test_task_runner_->NowTicks());

  pool->SetTimeBudgetRecoveryRate(base::TimeTicks(), 0.1);
  pool->AddThrottler(base::TimeTicks(), task_queue_throttler_.get());

  task_queue_throttler_->IncreaseThrottleRefCount();

  // Submit two tasks. They should be aligned, and second one should be
  // throttled.
  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));
  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  // The 1st task runs when allowed by the WakeUpBudgetPool. The 2nd task
  // runs when the CPU budget used by the 2nd task has recovered.
  EXPECT_THAT(run_times, ElementsAre(TimeTicks() + base::Seconds(1),
                                     start_time_ + base::Milliseconds(2500)));

  pool->RemoveThrottler(test_task_runner_->NowTicks(),
                        task_queue_throttler_.get());
  run_times.clear();

  // Queue was removed from CPUTimeBudgetPool, only timer alignment should be
  // active now.
  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));
  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times, ElementsAre(TimeTicks() + base::Milliseconds(3000),
                                     TimeTicks() + base::Milliseconds(3250)));

  task_queue_throttler_->DecreaseThrottleRefCount();
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       EnableAndDisableCPUTimeBudgetPool) {
  Vector<base::TimeTicks> run_times;

  std::unique_ptr<CPUTimeBudgetPool> pool = std::make_unique<CPUTimeBudgetPool>(
      "test", &tracing_controller_, test_task_runner_->NowTicks());
  EXPECT_TRUE(pool->IsThrottlingEnabled());

  pool->SetTimeBudgetRecoveryRate(base::TimeTicks(), 0.1);
  pool->AddThrottler(base::TimeTicks(), task_queue_throttler_.get());

  task_queue_throttler_->IncreaseThrottleRefCount();

  // Post an expensive task. Pool is now throttled.
  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(1000)));
  run_times.clear();

  LazyNow lazy_now_1(test_task_runner_->GetMockTickClock());
  pool->DisableThrottling(&lazy_now_1);
  EXPECT_FALSE(pool->IsThrottlingEnabled());

  // Pool should not be throttled now.
  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(2000)));
  run_times.clear();

  LazyNow lazy_now_2(test_task_runner_->GetMockTickClock());
  pool->EnableThrottling(&lazy_now_2);
  EXPECT_TRUE(pool->IsThrottlingEnabled());

  // Because time pool was disabled, time budget level did not replenish
  // and queue is throttled.
  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times, ElementsAre(start_time_ + base::Milliseconds(3500)));
  run_times.clear();

  task_queue_throttler_->DecreaseThrottleRefCount();

  pool->RemoveThrottler(test_task_runner_->NowTicks(),
                        task_queue_throttler_.get());
}

TEST_F(TaskQueueThrottlerTest, ImmediateTasksTimeBudgetThrottling) {
  Vector<base::TimeTicks> run_times;

  std::unique_ptr<CPUTimeBudgetPool> pool = std::make_unique<CPUTimeBudgetPool>(
      "test", &tracing_controller_, test_task_runner_->NowTicks());

  pool->SetTimeBudgetRecoveryRate(base::TimeTicks(), 0.1);
  pool->AddThrottler(base::TimeTicks(), task_queue_throttler_.get());

  task_queue_throttler_->IncreaseThrottleRefCount();

  // Submit two tasks. They should be aligned, and second one should be
  // throttled.
  timer_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_));
  timer_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(1000),
                          start_time_ + base::Milliseconds(2500)));

  pool->RemoveThrottler(test_task_runner_->NowTicks(),
                        task_queue_throttler_.get());
  run_times.clear();

  // Queue was removed from CPUTimeBudgetPool, only timer alignment should be
  // active now.
  timer_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_));
  timer_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(3000),
                          base::TimeTicks() + base::Milliseconds(3250)));

  task_queue_throttler_->DecreaseThrottleRefCount();
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       TwoQueuesTimeBudgetThrottling) {
  Vector<base::TimeTicks> run_times;

  base::sequence_manager::TaskQueue::Handle second_queue =
      sequence_manager_->CreateTaskQueue(
          base::sequence_manager::TaskQueue::Spec(
              base::sequence_manager::QueueName::TEST2_TQ)
              .SetDelayedFencesAllowed(true));
  auto second_queue_throttler = CreateThrottlerForTaskQueue(second_queue.get());

  std::unique_ptr<CPUTimeBudgetPool> pool = std::make_unique<CPUTimeBudgetPool>(
      "test", &tracing_controller_, test_task_runner_->NowTicks());

  pool->SetTimeBudgetRecoveryRate(base::TimeTicks(), 0.1);
  pool->AddThrottler(base::TimeTicks(), task_queue_throttler_.get());
  pool->AddThrottler(base::TimeTicks(), second_queue_throttler.get());
  wake_up_budget_pool_->AddThrottler(base::TimeTicks(),
                                     second_queue_throttler.get());

  task_queue_throttler_->IncreaseThrottleRefCount();
  second_queue_throttler->IncreaseThrottleRefCount();

  timer_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_));
  second_queue->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(1000),
                          start_time_ + base::Milliseconds(2500)));

  task_queue_throttler_->DecreaseThrottleRefCount();
  second_queue_throttler->DecreaseThrottleRefCount();

  pool->RemoveThrottler(test_task_runner_->NowTicks(),
                        task_queue_throttler_.get());
  pool->RemoveThrottler(test_task_runner_->NowTicks(),
                        second_queue_throttler.get());
  wake_up_budget_pool_->RemoveThrottler(test_task_runner_->NowTicks(),
                                        second_queue_throttler.get());
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       DisabledTimeBudgetDoesNotAffectThrottledQueues) {
  Vector<base::TimeTicks> run_times;
  LazyNow lazy_now(test_task_runner_->GetMockTickClock());

  std::unique_ptr<CPUTimeBudgetPool> pool = std::make_unique<CPUTimeBudgetPool>(
      "test", &tracing_controller_, test_task_runner_->NowTicks());
  pool->SetTimeBudgetRecoveryRate(lazy_now.Now(), 0.1);
  pool->DisableThrottling(&lazy_now);

  pool->AddThrottler(lazy_now.Now(), task_queue_throttler_.get());

  task_queue_throttler_->IncreaseThrottleRefCount();

  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(100));
  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(100));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(1000),
                          base::TimeTicks() + base::Milliseconds(1250)));
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       TimeBudgetThrottlingDoesNotAffectUnthrottledQueues) {
  Vector<base::TimeTicks> run_times;

  std::unique_ptr<CPUTimeBudgetPool> pool = std::make_unique<CPUTimeBudgetPool>(
      "test", &tracing_controller_, test_task_runner_->NowTicks());
  pool->SetTimeBudgetRecoveryRate(base::TimeTicks(), 0.1);

  LazyNow lazy_now(test_task_runner_->GetMockTickClock());
  pool->DisableThrottling(&lazy_now);

  pool->AddThrottler(test_task_runner_->NowTicks(),
                     task_queue_throttler_.get());

  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(100));
  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(100));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times, ElementsAre(start_time_ + base::Milliseconds(100),
                                     start_time_ + base::Milliseconds(350)));
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest, MaxThrottlingDelay) {
  Vector<base::TimeTicks> run_times;

  std::unique_ptr<CPUTimeBudgetPool> pool = std::make_unique<CPUTimeBudgetPool>(
      "test", &tracing_controller_, test_task_runner_->NowTicks());

  pool->SetMaxThrottlingDelay(base::TimeTicks(), base::Minutes(1));

  pool->SetTimeBudgetRecoveryRate(base::TimeTicks(), 0.001);
  pool->AddThrottler(base::TimeTicks(), task_queue_throttler_.get());

  task_queue_throttler_->IncreaseThrottleRefCount();

  for (int i = 0; i < 5; ++i) {
    timer_task_runner_->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
        base::Milliseconds(200));
  }

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(1000),
                          base::TimeTicks() + base::Milliseconds(61250),
                          base::TimeTicks() + base::Milliseconds(121500),
                          base::TimeTicks() + base::Milliseconds(181750),
                          base::TimeTicks() + base::Milliseconds(242000)));
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       EnableAndDisableThrottling) {
  Vector<base::TimeTicks> run_times;

  task_queue_throttler_->IncreaseThrottleRefCount();

  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));

  test_task_runner_->FastForwardBy(base::Milliseconds(300));

  // Disable throttling - task should run immediately.
  LazyNow lazy_now_1(test_task_runner_->GetMockTickClock());
  wake_up_budget_pool_->DisableThrottling(&lazy_now_1);

  test_task_runner_->FastForwardBy(base::Milliseconds(200));

  EXPECT_THAT(run_times, ElementsAre(start_time_ + base::Milliseconds(300)));
  run_times.clear();

  // Schedule a task at 900ms. It should proceed as normal.
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(400));

  // Schedule a task at 1200ms. It should proceed as normal.
  // PumpThrottledTasks was scheduled at 1000ms, so it needs to be checked
  // that it was cancelled and it does not interfere with tasks posted before
  // 1s mark and scheduled to run after 1s mark.
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(700));

  test_task_runner_->FastForwardBy(base::Milliseconds(800));

  EXPECT_THAT(run_times, ElementsAre(start_time_ + base::Milliseconds(900),
                                     start_time_ + base::Milliseconds(1200)));
  run_times.clear();

  // Schedule a task at 1500ms. It should be throttled because of enabled
  // throttling.
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));

  test_task_runner_->FastForwardBy(base::Milliseconds(100));

  // Throttling is enabled and new task should be aligned.
  LazyNow lazy_now_2(test_task_runner_->GetMockTickClock());
  wake_up_budget_pool_->EnableThrottling(&lazy_now_2);

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(2000)));
}

TEST_F(TaskQueueThrottlerTest, ReportThrottling) {
  Vector<base::TimeTicks> run_times;
  Vector<base::TimeDelta> reported_throttling_times;

  std::unique_ptr<CPUTimeBudgetPool> pool = std::make_unique<CPUTimeBudgetPool>(
      "test", &tracing_controller_, test_task_runner_->NowTicks());

  pool->SetTimeBudgetRecoveryRate(base::TimeTicks(), 0.1);
  pool->AddThrottler(base::TimeTicks(), task_queue_throttler_.get());

  pool->SetReportingCallback(
      base::BindRepeating(&RecordThrottling, &reported_throttling_times));

  task_queue_throttler_->IncreaseThrottleRefCount();

  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));
  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));
  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times, ElementsAre(TimeTicks() + base::Seconds(1),
                                     TimeTicks() + base::Seconds(1),
                                     start_time_ + base::Milliseconds(2500)));

  EXPECT_THAT(
      reported_throttling_times,
      ElementsAre((start_time_ - TimeTicks()) + base::Milliseconds(1250),
                  base::Milliseconds(2250)));

  pool->RemoveThrottler(test_task_runner_->NowTicks(),
                        task_queue_throttler_.get());
  task_queue_throttler_->DecreaseThrottleRefCount();
}

TEST_F(TaskQueueThrottlerTest, GrantAdditionalBudget) {
  Vector<base::TimeTicks> run_times;

  std::unique_ptr<CPUTimeBudgetPool> pool = std::make_unique<CPUTimeBudgetPool>(
      "test", &tracing_controller_, test_task_runner_->NowTicks());

  pool->SetTimeBudgetRecoveryRate(base::TimeTicks(), 0.1);
  pool->AddThrottler(base::TimeTicks(), task_queue_throttler_.get());
  pool->GrantAdditionalBudget(base::TimeTicks(), base::Milliseconds(500));

  task_queue_throttler_->IncreaseThrottleRefCount();

  // Submit five tasks. First three will not be throttled because they have
  // budget to run.
  for (int i = 0; i < 5; ++i) {
    timer_task_runner_->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_),
        base::Milliseconds(200));
  }

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times, ElementsAre(TimeTicks() + base::Milliseconds(1000),
                                     TimeTicks() + base::Milliseconds(1250),
                                     TimeTicks() + base::Milliseconds(1500),
                                     start_time_ + base::Milliseconds(2500),
                                     start_time_ + base::Milliseconds(5000)));

  pool->RemoveThrottler(test_task_runner_->NowTicks(),
                        task_queue_throttler_.get());
  task_queue_throttler_->DecreaseThrottleRefCount();
  pool->Close();
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       AddQueueThrottlerToBudgetPoolWhenThrottlingDisabled) {
  // This test checks that a task queue is added to time budget pool
  // when throttling is disabled, is does not throttle queue.
  Vector<base::TimeTicks> run_times;

  std::unique_ptr<CPUTimeBudgetPool> pool = std::make_unique<CPUTimeBudgetPool>(
      "test", &tracing_controller_, test_task_runner_->NowTicks());

  LazyNow lazy_now_1(test_task_runner_->GetMockTickClock());
  wake_up_budget_pool_->DisableThrottling(&lazy_now_1);
  pool->DisableThrottling(&lazy_now_1);
  task_queue_throttler_->IncreaseThrottleRefCount();

  test_task_runner_->FastForwardBy(base::Milliseconds(100));

  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));

  pool->AddThrottler(base::TimeTicks(), task_queue_throttler_.get());

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times, ElementsAre(start_time_ + base::Milliseconds(300)));
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       DisabledQueueThenEnabledQueue) {
  Vector<base::TimeTicks> run_times;

  base::sequence_manager::TaskQueue::Handle second_queue =
      sequence_manager_->CreateTaskQueue(
          base::sequence_manager::TaskQueue::Spec(
              base::sequence_manager::QueueName::TEST2_TQ)
              .SetDelayedFencesAllowed(true));
  auto second_queue_throttler = CreateThrottlerForTaskQueue(second_queue.get());
  wake_up_budget_pool_->AddThrottler(base::TimeTicks(),
                                     second_queue_throttler.get());

  task_queue_throttler_->IncreaseThrottleRefCount();
  second_queue_throttler->IncreaseThrottleRefCount();

  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(100));
  second_queue->task_runner()->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Milliseconds(200));

  std::unique_ptr<TaskQueue::QueueEnabledVoter> voter =
      timer_queue_->CreateQueueEnabledVoter();
  voter->SetVoteToEnable(false);

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(250));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(1000)));

  // Advance time passed the 1-second aligned wake up. The next task will run on
  // the next 1-second aligned wake up.
  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(10));

  voter->SetVoteToEnable(true);
  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(1000),
                          base::TimeTicks() + base::Milliseconds(2000)));

  wake_up_budget_pool_->RemoveThrottler(base::TimeTicks(),
                                        second_queue_throttler.get());
}

TEST_F(TaskQueueThrottlerTest, TwoBudgetPools) {
  Vector<base::TimeTicks> run_times;

  std::unique_ptr<CPUTimeBudgetPool> pool1 =
      std::make_unique<CPUTimeBudgetPool>("test", &tracing_controller_,
                                          test_task_runner_->NowTicks());
  std::unique_ptr<CPUTimeBudgetPool> pool2 =
      std::make_unique<CPUTimeBudgetPool>("test", &tracing_controller_,
                                          test_task_runner_->NowTicks());

  base::sequence_manager::TaskQueue::Handle second_queue =
      sequence_manager_->CreateTaskQueue(
          base::sequence_manager::TaskQueue::Spec(
              base::sequence_manager::QueueName::TEST2_TQ)
              .SetDelayedFencesAllowed(true));
  auto second_queue_throttler = CreateThrottlerForTaskQueue(second_queue.get());

  wake_up_budget_pool_->AddThrottler(base::TimeTicks(),
                                     second_queue_throttler.get());

  pool1->SetTimeBudgetRecoveryRate(base::TimeTicks(), 0.1);
  pool1->AddThrottler(base::TimeTicks(), task_queue_throttler_.get());
  pool1->AddThrottler(base::TimeTicks(), second_queue_throttler.get());

  pool2->SetTimeBudgetRecoveryRate(base::TimeTicks(), 0.01);
  pool2->AddThrottler(base::TimeTicks(), task_queue_throttler_.get());

  task_queue_throttler_->IncreaseThrottleRefCount();
  second_queue_throttler->IncreaseThrottleRefCount();

  timer_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_));
  second_queue->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_));
  timer_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_));
  second_queue->task_runner()->PostTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, &run_times, test_task_runner_));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(1000),
                          start_time_ + base::Milliseconds(2500),
                          start_time_ + base::Milliseconds(5000),
                          start_time_ + base::Milliseconds(25000)));

  wake_up_budget_pool_->RemoveThrottler(test_task_runner_->NowTicks(),
                                        second_queue_throttler.get());
}

namespace {

void RunChainedTask(Deque<base::TimeDelta> task_durations,
                    TaskQueue* queue,
                    scoped_refptr<TestMockTimeTaskRunner> task_runner,
                    Vector<base::TimeTicks>* run_times,
                    base::TimeDelta delay) {
  if (task_durations.empty())
    return;

  // FIXME No auto-advancing.

  run_times->push_back(RoundTimeToMilliseconds(task_runner->NowTicks()));
  task_runner->AdvanceMockTickClock(task_durations.front());
  task_durations.pop_front();

  queue->task_runner()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RunChainedTask, std::move(task_durations),
                     base::Unretained(queue), task_runner, run_times, delay),
      delay);
}
}  // namespace

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       WakeUpBasedThrottling_ChainedTasks_Instantaneous) {
  wake_up_budget_pool_->SetWakeUpDuration(base::Milliseconds(10));
  Vector<base::TimeTicks> run_times;

  task_queue_throttler_->IncreaseThrottleRefCount();

  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RunChainedTask, MakeTaskDurations(10, base::TimeDelta()),
                     base::Unretained(timer_queue_.get()), test_task_runner_,
                     &run_times, base::TimeDelta()),
      base::Milliseconds(100));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Seconds(1),
                                     base::TimeTicks() + base::Seconds(1),
                                     base::TimeTicks() + base::Seconds(1),
                                     base::TimeTicks() + base::Seconds(1),
                                     base::TimeTicks() + base::Seconds(1),
                                     base::TimeTicks() + base::Seconds(1),
                                     base::TimeTicks() + base::Seconds(1),
                                     base::TimeTicks() + base::Seconds(1),
                                     base::TimeTicks() + base::Seconds(1),
                                     base::TimeTicks() + base::Seconds(1)));
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       WakeUpBasedThrottling_ImmediateTasks_Fast) {
  wake_up_budget_pool_->SetWakeUpDuration(base::Milliseconds(10));
  Vector<base::TimeTicks> run_times;

  task_queue_throttler_->IncreaseThrottleRefCount();

  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RunChainedTask,
                     MakeTaskDurations(10, base::Milliseconds(3)),
                     base::Unretained(timer_queue_.get()), test_task_runner_,
                     &run_times, base::TimeDelta()),
      base::Milliseconds(100));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  // TODO(altimin): Add fence mechanism to block immediate tasks.
  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(1000),
                          base::TimeTicks() + base::Milliseconds(1003),
                          base::TimeTicks() + base::Milliseconds(1006),
                          base::TimeTicks() + base::Milliseconds(1009),
                          base::TimeTicks() + base::Milliseconds(2000),
                          base::TimeTicks() + base::Milliseconds(2003),
                          base::TimeTicks() + base::Milliseconds(2006),
                          base::TimeTicks() + base::Milliseconds(2009),
                          base::TimeTicks() + base::Milliseconds(3000),
                          base::TimeTicks() + base::Milliseconds(3003)));
}

TEST_P(TaskQueueThrottlerWithAutoAdvancingTimeTest,
       WakeUpBasedThrottling_DelayedTasks) {
  wake_up_budget_pool_->SetWakeUpDuration(base::Milliseconds(10));
  Vector<base::TimeTicks> run_times;

  task_queue_throttler_->IncreaseThrottleRefCount();

  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RunChainedTask, MakeTaskDurations(10, base::TimeDelta()),
                     base::Unretained(timer_queue_.get()), test_task_runner_,
                     &run_times, base::Milliseconds(3)),
      base::Milliseconds(100));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(1000),
                          base::TimeTicks() + base::Milliseconds(1003),
                          base::TimeTicks() + base::Milliseconds(1006),
                          base::TimeTicks() + base::Milliseconds(1009),
                          base::TimeTicks() + base::Milliseconds(2000),
                          base::TimeTicks() + base::Milliseconds(2003),
                          base::TimeTicks() + base::Milliseconds(2006),
                          base::TimeTicks() + base::Milliseconds(2009),
                          base::TimeTicks() + base::Milliseconds(3000),
                          base::TimeTicks() + base::Milliseconds(3003)));
}

TEST_F(TaskQueueThrottlerTest,
       WakeUpBasedThrottling_MultiplePoolsWithDifferentIntervalsOneEmpty) {
  // Have |wake_up_budget_pool_| control |task_queue| with a wake-up inteval
  // of one-minute.
  wake_up_budget_pool_->SetWakeUpInterval(test_task_runner_->NowTicks(),
                                          base::Minutes(1));
  task_queue_throttler_->IncreaseThrottleRefCount();
  WakeUpBudgetPool* one_minute_pool = wake_up_budget_pool_.get();
  scoped_refptr<base::SingleThreadTaskRunner> one_minute_task_runner =
      timer_task_runner_;

  // Create another TaskQueue, throttled by another WakeUpBudgetPool with
  // a wake-up interval of two minutes.
  std::unique_ptr<WakeUpBudgetPool> two_minutes_pool =
      std::make_unique<WakeUpBudgetPool>("Two Minutes Interval Pool");
  two_minutes_pool->SetWakeUpDuration(base::TimeDelta());
  two_minutes_pool->SetWakeUpInterval(test_task_runner_->NowTicks(),
                                      base::Minutes(2));
  base::sequence_manager::TaskQueue::Handle two_minutes_queue =
      sequence_manager_->CreateTaskQueue(
          base::sequence_manager::TaskQueue::Spec(
              base::sequence_manager::QueueName::TEST2_TQ)
              .SetDelayedFencesAllowed(true));
  auto two_minutes_queue_throttler =
      CreateThrottlerForTaskQueue(two_minutes_queue.get());
  two_minutes_pool->AddThrottler(base::TimeTicks(),
                                 two_minutes_queue_throttler.get());
  scoped_refptr<base::SingleThreadTaskRunner> two_minutes_task_runner =
      two_minutes_queue->task_runner();
  two_minutes_queue_throttler->IncreaseThrottleRefCount();

  // Post a task with a short delay to the first queue.
  constexpr base::TimeDelta kShortDelay = base::Seconds(1);
  Vector<base::TimeTicks> run_times;
  one_minute_task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      kShortDelay);

  // Pools did not observe wake ups yet whether they had pending tasks or not.
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(), std::nullopt);
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(), std::nullopt);

  // The first task should run after 1 minute, which is the wake up interval of
  // |one_minute_pool|.
  test_task_runner_->FastForwardBy(base::Minutes(1));
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(),
            base::TimeTicks() + base::Minutes(1));
  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Minutes(1)));

  // The second pool should not have woken up since it had no tasks.
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(), std::nullopt);

  // No new task execution or wake-ups for the first queue since it did not
  // get new tasks executed.
  test_task_runner_->FastForwardBy(base::Minutes(1));
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(),
            base::TimeTicks() + base::Minutes(1));
  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Minutes(1)));

  // The second pool should not have woken up since it had no tasks.
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(), std::nullopt);

  // Still no new executions so no update on the wake-up for the queues.
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(),
            base::TimeTicks() + base::Minutes(1));
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(), std::nullopt);

  // Clean up.
  two_minutes_pool->RemoveThrottler(test_task_runner_->NowTicks(),
                                    two_minutes_queue_throttler.get());
}

TEST_F(TaskQueueThrottlerTest,
       WakeUpBasedThrottling_MultiplePoolsWithDifferentIntervals) {
  wake_up_budget_pool_->SetWakeUpInterval(test_task_runner_->NowTicks(),
                                          base::Minutes(1));
  task_queue_throttler_->IncreaseThrottleRefCount();
  WakeUpBudgetPool* one_minute_pool = wake_up_budget_pool_.get();
  scoped_refptr<base::SingleThreadTaskRunner> one_minute_task_runner =
      timer_task_runner_;

  // Create another TaskQueue, throttled by another WakeUpBudgetPool.
  std::unique_ptr<WakeUpBudgetPool> two_minutes_pool =
      std::make_unique<WakeUpBudgetPool>("Two Minutes Interval Pool");
  two_minutes_pool->SetWakeUpDuration(base::TimeDelta());
  two_minutes_pool->SetWakeUpInterval(test_task_runner_->NowTicks(),
                                      base::Minutes(2));
  base::sequence_manager::TaskQueue::Handle two_minutes_queue =
      sequence_manager_->CreateTaskQueue(
          base::sequence_manager::TaskQueue::Spec(
              base::sequence_manager::QueueName::TEST2_TQ)
              .SetDelayedFencesAllowed(true));
  auto two_minutes_queue_throttler =
      CreateThrottlerForTaskQueue(two_minutes_queue.get());
  two_minutes_pool->AddThrottler(base::TimeTicks(),
                                 two_minutes_queue_throttler.get());
  scoped_refptr<base::SingleThreadTaskRunner> two_minutes_task_runner =
      two_minutes_queue->task_runner();
  two_minutes_queue_throttler->IncreaseThrottleRefCount();

  // Post tasks with a short delay to both queues.
  constexpr base::TimeDelta kShortDelay = base::Seconds(1);

  Vector<base::TimeTicks> run_times;
  one_minute_task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      kShortDelay);
  two_minutes_task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      kShortDelay);

  // Pools do not observe wake ups yet.
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(), std::nullopt);
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(), std::nullopt);

  // The first task should run after 1 minute, which is the wake up interval of
  // |one_minute_pool|. The second task should run after 2 minutes, which is the
  // wake up interval of |two_minutes_pool|.
  test_task_runner_->FastForwardBy(base::Minutes(1));
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(),
            base::TimeTicks() + base::Minutes(1));
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(), std::nullopt);
  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Minutes(1)));

  test_task_runner_->FastForwardBy(base::Minutes(1));
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(),
            base::TimeTicks() + base::Minutes(1));
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(),
            base::TimeTicks() + base::Minutes(2));
  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Minutes(1),
                                     base::TimeTicks() + base::Minutes(2)));

  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(),
            base::TimeTicks() + base::Minutes(1));
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(),
            base::TimeTicks() + base::Minutes(2));

  // Clean up.
  two_minutes_pool->RemoveThrottler(test_task_runner_->NowTicks(),
                                    two_minutes_queue_throttler.get());
}

TEST_F(TaskQueueThrottlerTest,
       WakeUpBasedThrottling_MultiplePoolsWithUnalignedWakeUps) {
  // Snap the time to the next minute to simplify expectations.
  ForwardTimeToNextMinute();
  const base::TimeTicks start_time = test_task_runner_->NowTicks();

  wake_up_budget_pool_->SetWakeUpInterval(test_task_runner_->NowTicks(),
                                          base::Minutes(1));
  wake_up_budget_pool_->AllowLowerAlignmentIfNoRecentWakeUp(base::Seconds(1));
  task_queue_throttler_->IncreaseThrottleRefCount();
  WakeUpBudgetPool* one_minute_pool = wake_up_budget_pool_.get();
  scoped_refptr<base::SingleThreadTaskRunner> one_minute_task_runner =
      timer_task_runner_;

  // Create another TaskQueue, throttled by another WakeUpBudgetPool.
  std::unique_ptr<WakeUpBudgetPool> two_minutes_pool =
      std::make_unique<WakeUpBudgetPool>("Two Minutes Interval Pool");
  two_minutes_pool->SetWakeUpDuration(base::TimeDelta());
  two_minutes_pool->SetWakeUpInterval(test_task_runner_->NowTicks(),
                                      base::Minutes(1));
  two_minutes_pool->AllowLowerAlignmentIfNoRecentWakeUp(base::Seconds(1));
  base::sequence_manager::TaskQueue::Handle two_minutes_queue =
      sequence_manager_->CreateTaskQueue(
          base::sequence_manager::TaskQueue::Spec(
              base::sequence_manager::QueueName::TEST2_TQ)
              .SetDelayedFencesAllowed(true));
  auto two_minutes_queue_throttler =
      CreateThrottlerForTaskQueue(two_minutes_queue.get());

  two_minutes_pool->AddThrottler(base::TimeTicks(),
                                 two_minutes_queue_throttler.get());
  scoped_refptr<base::SingleThreadTaskRunner> two_minutes_task_runner =
      two_minutes_queue->task_runner();
  two_minutes_queue_throttler->IncreaseThrottleRefCount();

  // Post tasks with short delays to both queues. They should run unaligned. The
  // wake up in |one_minute_pool| should not be taken into account when
  // evaluating whether there was a recent wake up in
  // |two_minutes_pool_|.
  Vector<base::TimeTicks> run_times;
  one_minute_task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Seconds(2));
  two_minutes_task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Seconds(3));

  test_task_runner_->FastForwardBy(base::Seconds(2));
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(2));
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(), std::nullopt);
  EXPECT_THAT(run_times, ElementsAre(start_time + base::Seconds(2)));

  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(2));
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(3));
  EXPECT_THAT(run_times, ElementsAre(start_time + base::Seconds(2),
                                     start_time + base::Seconds(3)));

  // Post extra tasks with long unaligned wake ups. They should run unaligned,
  // since their desired run time is more than 1 minute after the last wake up
  // in their respective pools.
  run_times.clear();
  one_minute_task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Seconds(602));
  two_minutes_task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Seconds(603));

  test_task_runner_->FastForwardBy(base::Seconds(601));
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(2));
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(3));
  EXPECT_THAT(run_times, ElementsAre());

  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(605));
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(3));
  EXPECT_THAT(run_times, ElementsAre(start_time + base::Seconds(605)));

  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(605));
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(606));
  EXPECT_THAT(run_times, ElementsAre(start_time + base::Seconds(605),
                                     start_time + base::Seconds(606)));

  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(one_minute_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(605));
  EXPECT_EQ(two_minutes_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(606));

  // Clean up.
  two_minutes_pool->RemoveThrottler(test_task_runner_->NowTicks(),
                                    two_minutes_queue_throttler.get());
}

TEST_F(TaskQueueThrottlerTest,
       WakeUpBasedThrottling_MultiplePoolsWithAllignedAndUnalignedWakeUps) {
  // Snap the time to the next minute to simplify expectations.
  ForwardTimeToNextMinute();
  const base::TimeTicks start_time = test_task_runner_->NowTicks();

  // The 1st WakeUpBudgetPool doesn't allow unaligned wake ups.
  wake_up_budget_pool_->SetWakeUpInterval(test_task_runner_->NowTicks(),
                                          base::Minutes(1));
  task_queue_throttler_->IncreaseThrottleRefCount();
  WakeUpBudgetPool* aligned_pool = wake_up_budget_pool_.get();
  scoped_refptr<base::SingleThreadTaskRunner> aligned_task_runner =
      timer_task_runner_;

  // Create another TaskQueue, throttled by another WakeUpBudgetPool. This 2nd
  // WakeUpBudgetPool allows unaligned wake ups.
  std::unique_ptr<WakeUpBudgetPool> unaligned_pool =
      std::make_unique<WakeUpBudgetPool>("Other Wake Up Budget Pool");
  unaligned_pool->SetWakeUpDuration(base::TimeDelta());
  unaligned_pool->SetWakeUpInterval(test_task_runner_->NowTicks(),
                                    base::Minutes(1));
  unaligned_pool->AllowLowerAlignmentIfNoRecentWakeUp(base::Seconds(1));
  base::sequence_manager::TaskQueue::Handle unaligned_queue =
      sequence_manager_->CreateTaskQueue(
          base::sequence_manager::TaskQueue::Spec(
              base::sequence_manager::QueueName::TEST2_TQ)
              .SetDelayedFencesAllowed(true));
  auto unaligned_queue_throttler =
      CreateThrottlerForTaskQueue(unaligned_queue.get());

  unaligned_pool->AddThrottler(base::TimeTicks(),
                               unaligned_queue_throttler.get());
  scoped_refptr<base::SingleThreadTaskRunner> unaligned_task_runner =
      unaligned_queue->task_runner();
  unaligned_queue_throttler->IncreaseThrottleRefCount();

  // Post tasks with short delays to both queues. The 1st task should run
  // aligned, while the 2nd task should run unaligned.
  Vector<base::TimeTicks> run_times;
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Seconds(2));
  unaligned_task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Seconds(3));

  test_task_runner_->FastForwardBy(base::Seconds(2));
  EXPECT_EQ(aligned_pool->last_wake_up_for_testing(), std::nullopt);
  EXPECT_EQ(unaligned_pool->last_wake_up_for_testing(), std::nullopt);
  EXPECT_THAT(run_times, ElementsAre());

  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_EQ(aligned_pool->last_wake_up_for_testing(), std::nullopt);
  EXPECT_EQ(unaligned_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(3));
  EXPECT_THAT(run_times, ElementsAre(start_time + base::Seconds(3)));

  test_task_runner_->FastForwardBy(base::Seconds(57));
  EXPECT_EQ(aligned_pool->last_wake_up_for_testing(),
            start_time + base::Minutes(1));
  EXPECT_EQ(unaligned_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(3));
  EXPECT_THAT(run_times, ElementsAre(start_time + base::Seconds(3),
                                     start_time + base::Minutes(1)));

  // Post extra tasks with long unaligned wake ups. The 1st task should run
  // aligned, while the 2nd task should run unaligned.
  run_times.clear();
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Seconds(602));
  unaligned_task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Seconds(603));

  test_task_runner_->FastForwardBy(base::Seconds(601));
  EXPECT_EQ(aligned_pool->last_wake_up_for_testing(),
            start_time + base::Minutes(1));
  EXPECT_EQ(unaligned_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(3));
  EXPECT_THAT(run_times, ElementsAre());

  test_task_runner_->FastForwardBy(base::Seconds(2));
  EXPECT_EQ(aligned_pool->last_wake_up_for_testing(),
            start_time + base::Minutes(1));
  EXPECT_EQ(unaligned_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(663));
  EXPECT_THAT(run_times, ElementsAre(start_time + base::Seconds(663)));

  test_task_runner_->FastForwardBy(base::Seconds(117));
  EXPECT_EQ(aligned_pool->last_wake_up_for_testing(),
            start_time + base::Minutes(12));
  EXPECT_EQ(unaligned_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(663));
  EXPECT_THAT(run_times, ElementsAre(start_time + base::Seconds(663),
                                     start_time + base::Minutes(12)));

  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(aligned_pool->last_wake_up_for_testing(),
            start_time + base::Minutes(12));
  EXPECT_EQ(unaligned_pool->last_wake_up_for_testing(),
            start_time + base::Seconds(663));

  // Clean up.
  unaligned_pool->RemoveThrottler(test_task_runner_->NowTicks(),
                                  unaligned_queue_throttler.get());
}

TEST_F(TaskQueueThrottlerTest, WakeUpBasedThrottling_EnableDisableThrottling) {
  constexpr base::TimeDelta kDelay = base::Seconds(10);
  constexpr base::TimeDelta kTimeBetweenWakeUps = base::Minutes(1);
  wake_up_budget_pool_->SetWakeUpInterval(base::TimeTicks(),
                                          kTimeBetweenWakeUps);
  wake_up_budget_pool_->SetWakeUpDuration(base::Milliseconds(1));
  Vector<base::TimeTicks> run_times;

  task_queue_throttler_->IncreaseThrottleRefCount();

  timer_task_runner_->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RunChainedTask, MakeTaskDurations(10, base::TimeDelta()),
                     base::Unretained(timer_queue_.get()), test_task_runner_,
                     &run_times, kDelay),
      kDelay);

  // Throttling is enabled. Only 1 task runs per |kTimeBetweenWakeUps|.
  test_task_runner_->FastForwardBy(kTimeBetweenWakeUps);

  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Seconds(60)));
  run_times.clear();

  // Disable throttling. All tasks can run.
  LazyNow lazy_now_1(test_task_runner_->GetMockTickClock());
  wake_up_budget_pool_->DisableThrottling(&lazy_now_1);
  test_task_runner_->FastForwardBy(5 * kDelay);

  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Seconds(70),
                                     base::TimeTicks() + base::Seconds(80),
                                     base::TimeTicks() + base::Seconds(90),
                                     base::TimeTicks() + base::Seconds(100),
                                     base::TimeTicks() + base::Seconds(110)));
  run_times.clear();

  // Throttling is enabled. Only 1 task runs per |kTimeBetweenWakeUps|.
  LazyNow lazy_now_2(test_task_runner_->GetMockTickClock());
  wake_up_budget_pool_->EnableThrottling(&lazy_now_2);
  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Seconds(120),
                                     base::TimeTicks() + base::Seconds(180),
                                     base::TimeTicks() + base::Seconds(240),
                                     base::TimeTicks() + base::Seconds(300)));
}

TEST_F(TaskQueueThrottlerTest, WakeUpBasedThrottling_LowAlignedWakeUps) {
  // All throttled wake ups are aligned on 1-second intervals by
  // TaskQueueThrottler, irrespective of BudgetPools. Start the test at a time
  // aligned on a 1-minute interval, to simplify expectations.
  ForwardTimeToNextMinute();
  const base::TimeTicks start_time = test_task_runner_->NowTicks();

  Vector<base::TimeTicks> run_times;
  task_queue_throttler_->IncreaseThrottleRefCount();

  wake_up_budget_pool_->SetWakeUpInterval(test_task_runner_->NowTicks(),
                                          base::Minutes(1));
  wake_up_budget_pool_->AllowLowerAlignmentIfNoRecentWakeUp(base::Seconds(10));

  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Seconds(88));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_times, ElementsAre(start_time + base::Seconds(90)));
}

TEST_F(TaskQueueThrottlerTest,
       WakeUpBasedThrottling_UnalignedWakeUps_MultipleTasks) {
  // Start at a 1-minute aligned time to simplify expectations.
  ForwardTimeToNextMinute();
  const base::TimeTicks initial_time = test_task_runner_->NowTicks();
  wake_up_budget_pool_->SetWakeUpInterval(test_task_runner_->NowTicks(),
                                          base::Minutes(1));
  wake_up_budget_pool_->AllowLowerAlignmentIfNoRecentWakeUp(base::Seconds(1));
  Vector<base::TimeTicks> run_times;
  task_queue_throttler_->IncreaseThrottleRefCount();
  // Task delay:        Expected run time:    Reason:
  // 30 seconds         30 seconds            >= 60 seconds after last wake up
  // 80 seconds         90 seconds            >= 60 seconds after last wake up
  // 95 seconds         120 seconds           Aligned
  // 100 seconds        120 seconds           Aligned
  // 130 seconds        180 seconds           Aligned
  // 251 seconds        251 seconds           >= 60 seconds after last wake up
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOnce(&TestTask, &run_times, test_task_runner_),
      base::Seconds(30));
  timer_task_runner_->PostDelayedTask(
      FROM_HERE, base::BindOn
```