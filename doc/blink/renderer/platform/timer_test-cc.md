Response: My thinking process to analyze the `timer_test.cc` file and answer the user's request goes like this:

1. **Understand the Goal:** The user wants to know the functionality of `timer_test.cc`, its relation to web technologies (JavaScript, HTML, CSS), examples of logical reasoning, and common usage errors.

2. **Identify the Core Functionality:** The file name `timer_test.cc` strongly suggests it's a test file for timer-related functionality. Scanning the `#include` directives confirms this, especially the inclusion of `third_party/blink/renderer/platform/timer.h`. The presence of `testing/gtest/include/gtest/gtest.h` further solidifies its role as a unit test file.

3. **Analyze the Test Structure:**  The code uses the Google Test framework (`TEST_F`). This means the file contains multiple independent test cases. Each `TEST_F` function focuses on testing a specific aspect of the `Timer` class.

4. **Break Down Individual Tests:** I need to go through each `TEST_F` and understand what it's testing. I'll look for:
    * **What action is being tested?** (e.g., `StartOneShot`, `StartRepeating`, `Stop`, `MoveToNewTaskRunner`).
    * **What are the different scenarios?** (e.g., zero delay, non-zero delay, cancelling, reposting, testing `IsActive`, `NextFireInterval`, `RepeatInterval`).
    * **What are the assertions?** (`EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_EQ`, `EXPECT_THAT`). These tell me what the expected behavior is.
    * **What helper functions are used?** (`CountingTask`, `RecordNextFireTimeTask`, `RunUntilDeadline`, `TimeTillNextDelayedTask`). Understanding these helps clarify the test setup and verification.

5. **Connect to Web Technologies:** This is the trickiest part. Timers are fundamental to JavaScript's asynchronous nature (`setTimeout`, `setInterval`). I need to bridge the gap between the C++ implementation in Blink and the JavaScript API.
    * **JavaScript Connection:** Focus on how the tested functionalities map to JavaScript timer functions. `StartOneShot` is like `setTimeout`, `StartRepeating` is like `setInterval`, and `Stop` corresponds to `clearTimeout`/`clearInterval`.
    * **HTML/CSS Connection (Indirect):**  While timers don't directly manipulate HTML or CSS syntax, they are crucial for dynamic behavior driven by JavaScript. Animations, delayed actions, and periodic updates to the DOM or styles all rely on timers. I need to illustrate this indirect relationship.

6. **Identify Logical Reasoning and Assumptions:** The tests themselves embody logical reasoning. Each test sets up a specific condition (input) and then asserts the expected outcome (output). I need to extract these implicit "if-then" statements. For example: "If I start a one-shot timer with a 10-second delay, then after running the event loop, the callback should have executed at approximately 10 seconds after the start time."

7. **Spot Potential Usage Errors:** By examining the tests, I can infer common mistakes developers might make when using timers:
    * **Forgetting to cancel repeating timers:** The tests demonstrate the importance of `Stop()`.
    * **Assuming immediate execution for zero-delay timers:** While they run "soon," they are still asynchronous.
    * **Not understanding timer drift:** The `RepeatingTimerDoesNotDrift` test highlights this nuance.
    * **Issues with on-heap timers and garbage collection:** The tests involving `OnHeapTimerOwner` touch on memory management concerns.

8. **Structure the Answer:** Organize the findings into the categories requested by the user:
    * **Functionality:** Provide a high-level summary and then list specific functionalities tested.
    * **Relationship to Web Technologies:** Explain the connection to JavaScript and how it indirectly relates to HTML and CSS, providing concrete examples.
    * **Logical Reasoning:**  Present examples of the test logic as "if-then" statements with assumed inputs and expected outputs.
    * **Common Usage Errors:** List potential pitfalls with illustrative examples based on the test scenarios.

9. **Refine and Elaborate:** Review the answer for clarity, accuracy, and completeness. Add details and explanations where necessary. For instance, clarify the role of the mock scheduler in the tests. Ensure the examples are easy to understand. Explain the significance of testing various edge cases (zero delay, cancellation, etc.).

By following this process, I can systematically analyze the code and generate a comprehensive and informative answer to the user's request. The key is to understand the purpose of the code (testing), dissect the individual tests, and then connect those tests to real-world web development concepts and potential issues.
This C++ source code file, `timer_test.cc`, located within the Chromium Blink rendering engine, is a **unit test file** specifically designed to verify the functionality of the `Timer` class (likely `blink::Timer` or a related class like `blink::TaskRunnerTimer`).

Here's a breakdown of its functionalities:

**Core Functionality: Testing the `Timer` Class**

The primary goal is to rigorously test various aspects of how timers work within the Blink rendering engine. This includes:

* **One-Shot Timers:**
    * **Starting:** Tests starting a timer that executes once after a specified delay (zero or non-zero).
    * **Execution:** Verifies that the timer's associated task (callback function) is executed at the correct time.
    * **Cancellation:** Checks that stopping a timer before it fires prevents its execution.
    * **Reposting:** Tests starting a new one-shot timer after a previous one has either fired or been cancelled.
    * **Zero Delay:** Specifically tests timers with a zero delay, ensuring they execute promptly.
    * **Multiple Posts:** Examines the behavior when the same one-shot timer is started multiple times with the same or different delays.
* **Repeating Timers:**
    * **Starting:** Tests initiating timers that execute repeatedly at a given interval.
    * **Execution:** Confirms that the timer's task is executed multiple times at the expected intervals.
    * **Cancellation:** Verifies that stopping a repeating timer prevents further executions.
    * **Interaction with One-Shot Timers:** Checks how starting a one-shot timer interacts with an already running repeating timer.
* **Timer Properties:**
    * **`IsActive()`:** Tests whether the timer correctly reports its active state (whether it's scheduled to fire).
    * **`NextFireInterval()`:** Checks if the timer accurately reports the time remaining until its next execution.
    * **`RepeatInterval()`:** Verifies the reported repeat interval of a repeating timer.
    * **`AugmentRepeatInterval()`:** Tests the ability to dynamically change the repeat interval of a repeating timer.
* **Timer Drift:**
    * **Non-Drifting Behavior:**  Specifically tests that repeating timers maintain their intended interval and don't accumulate timing errors over time.
* **Task Runner Association:**
    * **Custom Task Runners:** Tests the ability to associate timers with specific task runners, allowing for execution on different threads or queues.
    * **Moving to New Task Runner:**  Verifies the functionality of moving a timer to a different task runner while it's active or inactive.
* **On-Heap Timers and Garbage Collection:**
    * **Garbage Collection Safety:** Tests timers that are owned by garbage-collected objects, ensuring they behave correctly when the owner is collected. This includes scenarios where the timer might still be active.
* **Task Observation:**
    * Tests the execution order of timers when moved between different task runners, using `base::TaskObserver`.

**Relationship to JavaScript, HTML, and CSS**

The `Timer` class tested here is a fundamental building block for implementing JavaScript's timer functions (`setTimeout` and `setInterval`). While this C++ code doesn't directly manipulate HTML or CSS, it's essential for the underlying mechanism that enables JavaScript to create asynchronous behavior and interact with the web page:

* **JavaScript `setTimeout`:** The `StartOneShot` functionality in the C++ `Timer` class directly corresponds to the behavior of `setTimeout` in JavaScript. When you call `setTimeout(callback, delay)` in JavaScript, the browser's rendering engine (which includes Blink) uses a mechanism like the tested `Timer` to schedule the execution of the `callback` function after the specified `delay`.

    * **Example:**
        ```javascript
        // JavaScript:
        setTimeout(function() {
          console.log("This message appears after 1000ms");
          document.getElementById("myElement").style.color = "red"; // Example of DOM manipulation
        }, 1000);
        ```
        Internally, Blink's `Timer` class (tested here) would be used to schedule the execution of the JavaScript code within the anonymous function after 1000 milliseconds.

* **JavaScript `setInterval`:** The `StartRepeating` functionality in the C++ `Timer` class mirrors the behavior of `setInterval` in JavaScript. `setInterval(callback, interval)` in JavaScript instructs the browser to repeatedly execute the `callback` function at the given `interval`.

    * **Example:**
        ```javascript
        // JavaScript:
        setInterval(function() {
          console.log("This message appears every 500ms");
        }, 500);
        ```
        Blink's `Timer` class would be responsible for scheduling the repeated execution of the provided JavaScript function.

* **Indirect Relation to HTML and CSS:** JavaScript timers are frequently used to:
    * **Animate elements:** By repeatedly updating CSS properties over time using `setInterval` or carefully timed `setTimeout` calls.
    * **Implement dynamic behavior:**  Such as updating content on a page at regular intervals (e.g., a stock ticker), delaying the loading of resources, or responding to user interactions after a delay.
    * **Control the flow of interactions:** For example, showing a modal after a certain time or implementing debouncing/throttling of events.

**Logical Reasoning (Hypothesized Input and Output)**

Let's take one test case as an example of logical reasoning:

**Test Case:** `TEST_F(TimerTest, StartOneShot_NonZero)`

**Hypothesized Input:**
1. A `TimerTest` object is created.
2. A `TaskRunnerTimer` is created, associated with the `TimerTest` object and its `CountingTask` method.
3. `timer.StartOneShot(base::Seconds(10), FROM_HERE)` is called.

**Logical Reasoning:**
* **Assumption:** The `StartOneShot` method should schedule the `CountingTask` to be executed after a delay of 10 seconds.
* **Assertion:** `TimeTillNextDelayedTask(&run_time)` should return `true` because there's a pending delayed task.
* **Assertion:** `run_time` should be approximately equal to `base::Seconds(10)`.
* **Action:** `platform_->RunUntilIdle()` simulates running the event loop until all pending tasks are executed.
* **Assertion:** `run_times_` should contain exactly one element, which is the `start_time_` plus 10 seconds (the time when `CountingTask` was executed).

**Hypothesized Output:**
* `TimeTillNextDelayedTask` returns `true`.
* `run_time` is approximately 10 seconds.
* `run_times_` contains a single value representing the execution time, roughly 10 seconds after the start.

**Common Usage Errors (Based on Test Scenarios)**

The test suite implicitly highlights potential errors developers might make when working with timers:

1. **Forgetting to Cancel Repeating Timers:** The `StartRepeatingTask_ThenCancel` test demonstrates the importance of calling `timer.Stop()` on repeating timers when they are no longer needed. Failing to do so can lead to unintended continuous execution of the associated task, potentially causing performance issues or unexpected behavior.

    * **Example Error:**
        ```javascript
        // JavaScript - potential memory leak if clearInterval is missed
        setInterval(function() {
          // Do something repeatedly
        }, 100);
        // ... if the interval is not cleared, this function keeps running
        ```

2. **Assuming Immediate Execution of Zero-Delay Timers:**  Tests like `StartOneShot_Zero` clarify that even with a zero delay, the timer's task is not executed *immediately*. It's placed on the event loop queue and will be executed as soon as the current execution context finishes.

    * **Example Error:**
        ```javascript
        // JavaScript - might not execute *before* the next line
        setTimeout(function() {
          console.log("This might not be the first message");
        }, 0);
        console.log("This message might appear first");
        ```

3. **Not Understanding Timer Drift in Repeating Timers:** While the tests verify that the implementation *prevents* drift, developers might incorrectly assume perfect precision with repeating timers. Factors like system load and browser behavior can introduce minor variations in execution times.

4. **Issues with Object Lifetime and Timers:** The `RunOnHeapTimer` and `DestructOnHeapTimer` tests highlight the importance of managing the lifetime of objects that own timers. If an object with an active timer is garbage collected prematurely, it can lead to crashes or unexpected behavior. This is especially relevant in C++ where manual memory management or smart pointers are used. In JavaScript, while garbage collection is automatic, understanding the relationship between timer callbacks and object references is crucial to avoid memory leaks.

    * **Example Error (Conceptual C++ analogy):**
        ```c++
        // C++ - potential issue if owner is deleted before timer fires
        class MyClass {
         public:
          void startTimer() { timer_.StartOneShot(base::Seconds(1), FROM_HERE); }
         private:
          void onTimerFired(TimerBase*) { /* ... access member variables ... */ }
          TaskRunnerTimer<MyClass> timer_{/* ... */, this, &MyClass::onTimerFired};
        };

        {
          MyClass obj;
          obj.startTimer();
        } // obj is destroyed, but the timer might still be pending, leading to a crash
        ```

In summary, `timer_test.cc` is a critical piece of the Blink rendering engine, ensuring the reliability and correctness of the timer mechanisms that underpin much of the dynamic behavior we see on the web. By testing various scenarios and edge cases, it helps prevent bugs and ensures that JavaScript timer functions behave as expected.

### 提示词
```
这是目录为blink/renderer/platform/timer_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2015 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/timer.h"

#include <memory>
#include <queue>

#include "base/memory/raw_ptr.h"
#include "base/task/common/lazy_now.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/task_environment.h"
#include "base/time/time.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/platform/platform.h"
#include "third_party/blink/renderer/platform/heap/garbage_collected.h"
#include "third_party/blink/renderer/platform/heap/thread_state.h"
#include "third_party/blink/renderer/platform/heap/thread_state_scopes.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_task_queue.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/testing/testing_platform_support_with_mock_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/ref_counted.h"

using base::sequence_manager::TaskQueue;
using blink::scheduler::MainThreadTaskQueue;
using testing::ElementsAre;

namespace blink {
namespace {

class TimerTest : public testing::Test {
 public:
  TimerTest() {
    scoped_refptr<MainThreadTaskQueue> task_queue =
        platform_->GetMainThreadScheduler()->NewTaskQueue(
            MainThreadTaskQueue::QueueCreationParams(
                MainThreadTaskQueue::QueueType::kTest));
    task_runner_ = task_queue->CreateTaskRunner(TaskType::kInternalTest);
  }

  void SetUp() override {
    run_times_.clear();
    platform_->AdvanceClock(base::Seconds(10));
    start_time_ = Now();
  }

  base::TimeTicks Now() { return platform_->test_task_runner()->NowTicks(); }

  void CountingTask(TimerBase*) { run_times_.push_back(Now()); }

  void RecordNextFireTimeTask(TimerBase* timer) {
    next_fire_times_.push_back(Now() + timer->NextFireInterval());
  }

  void RunUntilDeadline(base::TimeTicks deadline) {
    base::TimeDelta period = deadline - Now();
    EXPECT_GE(period, base::TimeDelta());
    platform_->RunForPeriod(period);
  }

  // Returns false if there are no pending delayed tasks, otherwise sets |time|
  // to the delay in seconds till the next pending delayed task is scheduled to
  // fire.
  bool TimeTillNextDelayedTask(base::TimeDelta* time) const {
    base::LazyNow lazy_now(platform_->NowTicks());
    auto* scheduler_helper =
        platform_->GetMainThreadScheduler()->GetSchedulerHelperForTesting();
    scheduler_helper->ReclaimMemory();
    auto wake_up = scheduler_helper->GetNextWakeUp();
    if (!wake_up)
      return false;
    *time = wake_up->time - lazy_now.Now();
    return true;
  }

  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunner() {
    return task_runner_;
  }

 protected:
  base::TimeTicks start_time_;
  WTF::Vector<base::TimeTicks> run_times_;
  WTF::Vector<base::TimeTicks> next_fire_times_;
  ScopedTestingPlatformSupport<TestingPlatformSupportWithMockScheduler>
      platform_;
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;

  base::test::TaskEnvironment task_environment_;
};

class OnHeapTimerOwner final : public GarbageCollected<OnHeapTimerOwner> {
 public:
  class Record final : public RefCounted<Record> {
   public:
    static scoped_refptr<Record> Create() { return base::AdoptRef(new Record); }

    bool TimerHasFired() const { return timer_has_fired_; }
    bool IsDisposed() const { return is_disposed_; }
    bool OwnerIsDestructed() const { return owner_is_destructed_; }
    void SetTimerHasFired() { timer_has_fired_ = true; }
    void Dispose() { is_disposed_ = true; }
    void SetOwnerIsDestructed() { owner_is_destructed_ = true; }

   private:
    Record() = default;

    bool timer_has_fired_ = false;
    bool is_disposed_ = false;
    bool owner_is_destructed_ = false;
  };

  explicit OnHeapTimerOwner(
      scoped_refptr<Record> record,
      scoped_refptr<base::SingleThreadTaskRunner> task_runner)
      : timer_(std::move(task_runner), this, &OnHeapTimerOwner::Fired),
        record_(std::move(record)) {}
  ~OnHeapTimerOwner() { record_->SetOwnerIsDestructed(); }

  void StartOneShot(base::TimeDelta interval, const base::Location& caller) {
    timer_.StartOneShot(interval, caller);
  }

  void Trace(Visitor* visitor) const { visitor->Trace(timer_); }

 private:
  void Fired(TimerBase*) {
    EXPECT_FALSE(record_->IsDisposed());
    record_->SetTimerHasFired();
  }

  HeapTaskRunnerTimer<OnHeapTimerOwner> timer_;
  scoped_refptr<Record> record_;
};

TEST_F(TimerTest, StartOneShot_Zero) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::TimeDelta(), FROM_HERE);

  base::TimeDelta run_time;
  EXPECT_FALSE(TimeTillNextDelayedTask(&run_time));

  platform_->RunUntilIdle();
  EXPECT_THAT(run_times_, ElementsAre(start_time_));
}

TEST_F(TimerTest, StartOneShot_ZeroAndCancel) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::TimeDelta(), FROM_HERE);

  base::TimeDelta run_time;
  EXPECT_FALSE(TimeTillNextDelayedTask(&run_time));

  timer.Stop();

  platform_->RunUntilIdle();
  EXPECT_FALSE(run_times_.size());
}

TEST_F(TimerTest, StartOneShot_ZeroAndCancelThenRepost) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::TimeDelta(), FROM_HERE);

  base::TimeDelta run_time;
  EXPECT_FALSE(TimeTillNextDelayedTask(&run_time));

  timer.Stop();

  platform_->RunUntilIdle();
  EXPECT_FALSE(run_times_.size());

  timer.StartOneShot(base::TimeDelta(), FROM_HERE);

  EXPECT_FALSE(TimeTillNextDelayedTask(&run_time));

  platform_->RunUntilIdle();
  EXPECT_THAT(run_times_, ElementsAre(start_time_));
}

TEST_F(TimerTest, StartOneShot_Zero_RepostingAfterRunning) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::TimeDelta(), FROM_HERE);

  base::TimeDelta run_time;
  EXPECT_FALSE(TimeTillNextDelayedTask(&run_time));

  platform_->RunUntilIdle();
  EXPECT_THAT(run_times_, ElementsAre(start_time_));

  timer.StartOneShot(base::TimeDelta(), FROM_HERE);

  EXPECT_FALSE(TimeTillNextDelayedTask(&run_time));

  platform_->RunUntilIdle();
  EXPECT_THAT(run_times_, ElementsAre(start_time_, start_time_));
}

TEST_F(TimerTest, StartOneShot_NonZero) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);

  base::TimeDelta run_time;
  EXPECT_TRUE(TimeTillNextDelayedTask(&run_time));
  EXPECT_EQ(base::Seconds(10), run_time);

  platform_->RunUntilIdle();
  EXPECT_THAT(run_times_, ElementsAre(start_time_ + base::Seconds(10)));
}

TEST_F(TimerTest, StartOneShot_NonZeroAndCancel) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);

  base::TimeDelta run_time;
  EXPECT_TRUE(TimeTillNextDelayedTask(&run_time));
  EXPECT_EQ(base::Seconds(10), run_time);

  timer.Stop();
  EXPECT_FALSE(TimeTillNextDelayedTask(&run_time));

  platform_->RunUntilIdle();
  EXPECT_FALSE(run_times_.size());
}

TEST_F(TimerTest, StartOneShot_NonZeroAndCancelThenRepost) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);

  base::TimeDelta run_time;
  EXPECT_TRUE(TimeTillNextDelayedTask(&run_time));
  EXPECT_EQ(base::Seconds(10), run_time);

  timer.Stop();
  EXPECT_FALSE(TimeTillNextDelayedTask(&run_time));

  platform_->RunUntilIdle();
  EXPECT_FALSE(run_times_.size());

  base::TimeTicks second_post_time = Now();
  timer.StartOneShot(base::Seconds(10), FROM_HERE);

  EXPECT_TRUE(TimeTillNextDelayedTask(&run_time));
  EXPECT_EQ(base::Seconds(10), run_time);

  platform_->RunUntilIdle();
  EXPECT_THAT(run_times_, ElementsAre(second_post_time + base::Seconds(10)));
}

TEST_F(TimerTest, StartOneShot_NonZero_RepostingAfterRunning) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);

  base::TimeDelta run_time;
  EXPECT_TRUE(TimeTillNextDelayedTask(&run_time));
  EXPECT_EQ(base::Seconds(10), run_time);

  platform_->RunUntilIdle();
  EXPECT_THAT(run_times_, ElementsAre(start_time_ + base::Seconds(10)));

  timer.StartOneShot(base::Seconds(20), FROM_HERE);

  EXPECT_TRUE(TimeTillNextDelayedTask(&run_time));
  EXPECT_EQ(base::Seconds(20), run_time);

  platform_->RunUntilIdle();
  EXPECT_THAT(run_times_, ElementsAre(start_time_ + base::Seconds(10),
                                      start_time_ + base::Seconds(30)));
}

TEST_F(TimerTest, PostingTimerTwiceWithSameRunTimeDoesNothing) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);

  base::TimeDelta run_time;
  EXPECT_TRUE(TimeTillNextDelayedTask(&run_time));
  EXPECT_EQ(base::Seconds(10), run_time);

  platform_->RunUntilIdle();
  EXPECT_THAT(run_times_, ElementsAre(start_time_ + base::Seconds(10)));
}

TEST_F(TimerTest, PostingTimerTwiceWithNewerRunTimeCancelsOriginalTask) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);
  timer.StartOneShot(base::TimeDelta(), FROM_HERE);

  platform_->RunUntilIdle();
  EXPECT_THAT(run_times_, ElementsAre(start_time_ + base::Seconds(0)));
}

TEST_F(TimerTest, PostingTimerTwiceWithLaterRunTimeCancelsOriginalTask) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::TimeDelta(), FROM_HERE);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);

  platform_->RunUntilIdle();
  EXPECT_THAT(run_times_, ElementsAre(start_time_ + base::Seconds(10)));
}

TEST_F(TimerTest, StartRepeatingTask) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartRepeating(base::Seconds(1), FROM_HERE);

  base::TimeDelta run_time;
  EXPECT_TRUE(TimeTillNextDelayedTask(&run_time));
  EXPECT_EQ(base::Seconds(1), run_time);

  RunUntilDeadline(start_time_ + base::Milliseconds(5500));
  EXPECT_THAT(run_times_, ElementsAre(start_time_ + base::Seconds(1),
                                      start_time_ + base::Seconds(2),
                                      start_time_ + base::Seconds(3),
                                      start_time_ + base::Seconds(4),
                                      start_time_ + base::Seconds(5)));
}

TEST_F(TimerTest, StartRepeatingTask_ThenCancel) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartRepeating(base::Seconds(1), FROM_HERE);

  base::TimeDelta run_time;
  EXPECT_TRUE(TimeTillNextDelayedTask(&run_time));
  EXPECT_EQ(base::Seconds(1), run_time);

  RunUntilDeadline(start_time_ + base::Milliseconds(2500));
  EXPECT_THAT(run_times_, ElementsAre(start_time_ + base::Seconds(1),
                                      start_time_ + base::Seconds(2)));

  timer.Stop();
  platform_->RunUntilIdle();

  EXPECT_THAT(run_times_, ElementsAre(start_time_ + base::Seconds(1),
                                      start_time_ + base::Seconds(2)));
}

TEST_F(TimerTest, StartRepeatingTask_ThenPostOneShot) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartRepeating(base::Seconds(1), FROM_HERE);

  base::TimeDelta run_time;
  EXPECT_TRUE(TimeTillNextDelayedTask(&run_time));
  EXPECT_EQ(base::Seconds(1), run_time);

  RunUntilDeadline(start_time_ + base::Milliseconds(2500));
  EXPECT_THAT(run_times_, ElementsAre(start_time_ + base::Seconds(1),
                                      start_time_ + base::Seconds(2)));

  timer.StartOneShot(base::TimeDelta(), FROM_HERE);
  platform_->RunUntilIdle();

  EXPECT_THAT(run_times_, ElementsAre(start_time_ + base::Seconds(1),
                                      start_time_ + base::Seconds(2),
                                      start_time_ + base::Milliseconds(2500)));
}

TEST_F(TimerTest, IsActive_NeverPosted) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);

  EXPECT_FALSE(timer.IsActive());
}

TEST_F(TimerTest, IsActive_AfterPosting_OneShotZero) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::TimeDelta(), FROM_HERE);

  EXPECT_TRUE(timer.IsActive());
}

TEST_F(TimerTest, IsActive_AfterPosting_OneShotNonZero) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);

  EXPECT_TRUE(timer.IsActive());
}

TEST_F(TimerTest, IsActive_AfterPosting_Repeating) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartRepeating(base::Seconds(1), FROM_HERE);

  EXPECT_TRUE(timer.IsActive());
}

TEST_F(TimerTest, IsActive_AfterRunning_OneShotZero) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::TimeDelta(), FROM_HERE);

  platform_->RunUntilIdle();
  EXPECT_FALSE(timer.IsActive());
}

TEST_F(TimerTest, IsActive_AfterRunning_OneShotNonZero) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);

  platform_->RunUntilIdle();
  EXPECT_FALSE(timer.IsActive());
}

TEST_F(TimerTest, IsActive_AfterRunning_Repeating) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartRepeating(base::Seconds(1), FROM_HERE);

  RunUntilDeadline(start_time_ + base::Seconds(10));
  EXPECT_TRUE(timer.IsActive());  // It should run until cancelled.
}

TEST_F(TimerTest, NextFireInterval_OneShotZero) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::TimeDelta(), FROM_HERE);

  EXPECT_TRUE(timer.NextFireInterval().is_zero());
}

TEST_F(TimerTest, NextFireInterval_OneShotNonZero) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);

  EXPECT_EQ(base::Seconds(10), timer.NextFireInterval());
}

TEST_F(TimerTest, NextFireInterval_OneShotNonZero_AfterAFewSeconds) {
  platform_->SetAutoAdvanceNowToPendingTasks(false);

  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);

  platform_->AdvanceClock(base::Seconds(2));
  EXPECT_EQ(base::Seconds(8), timer.NextFireInterval());
}

TEST_F(TimerTest, NextFireInterval_Repeating) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartRepeating(base::Seconds(20), FROM_HERE);

  EXPECT_EQ(base::Seconds(20), timer.NextFireInterval());
}

TEST_F(TimerTest, RepeatInterval_NeverStarted) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);

  EXPECT_TRUE(timer.RepeatInterval().is_zero());
}

TEST_F(TimerTest, RepeatInterval_OneShotZero) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::TimeDelta(), FROM_HERE);

  EXPECT_TRUE(timer.RepeatInterval().is_zero());
}

TEST_F(TimerTest, RepeatInterval_OneShotNonZero) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartOneShot(base::Seconds(10), FROM_HERE);

  EXPECT_TRUE(timer.RepeatInterval().is_zero());
}

TEST_F(TimerTest, RepeatInterval_Repeating) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartRepeating(base::Seconds(20), FROM_HERE);

  EXPECT_EQ(base::Seconds(20), timer.RepeatInterval());
}

TEST_F(TimerTest, AugmentRepeatInterval) {
  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartRepeating(base::Seconds(10), FROM_HERE);
  EXPECT_EQ(base::Seconds(10), timer.RepeatInterval());
  EXPECT_EQ(base::Seconds(10), timer.NextFireInterval());

  platform_->AdvanceClock(base::Seconds(2));
  timer.AugmentRepeatInterval(base::Seconds(10));

  EXPECT_EQ(base::Seconds(20), timer.RepeatInterval());
  EXPECT_EQ(base::Seconds(18), timer.NextFireInterval());

  RunUntilDeadline(start_time_ + base::Seconds(50));
  EXPECT_THAT(run_times_, ElementsAre(start_time_ + base::Seconds(20),
                                      start_time_ + base::Seconds(40)));
}

TEST_F(TimerTest, AugmentRepeatInterval_TimerFireDelayed) {
  platform_->SetAutoAdvanceNowToPendingTasks(false);

  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::CountingTask);
  timer.StartRepeating(base::Seconds(10), FROM_HERE);
  EXPECT_EQ(base::Seconds(10), timer.RepeatInterval());
  EXPECT_EQ(base::Seconds(10), timer.NextFireInterval());

  platform_->AdvanceClock(base::Seconds(123));  // Make the timer long overdue.
  timer.AugmentRepeatInterval(base::Seconds(10));

  EXPECT_EQ(base::Seconds(20), timer.RepeatInterval());
  // The timer is overdue so it should be scheduled to fire immediatly.
  EXPECT_TRUE(timer.NextFireInterval().is_zero());
}

TEST_F(TimerTest, RepeatingTimerDoesNotDrift) {
  platform_->SetAutoAdvanceNowToPendingTasks(false);

  TaskRunnerTimer<TimerTest> timer(GetTaskRunner(), this,
                                   &TimerTest::RecordNextFireTimeTask);
  timer.StartRepeating(base::Seconds(2), FROM_HERE);

  RecordNextFireTimeTask(
      &timer);  // Next scheduled task to run at |start_time_| + 2s

  // Simulate timer firing early. Next scheduled task to run at
  // |start_time_| + 4s
  platform_->AdvanceClock(base::Milliseconds(1900));
  RunUntilDeadline(Now() + base::Milliseconds(200));

  // Next scheduled task to run at |start_time_| + 6s
  platform_->RunForPeriod(base::Seconds(2));
  // Next scheduled task to run at |start_time_| + 8s
  platform_->RunForPeriod(base::Milliseconds(2100));
  // Next scheduled task to run at |start_time_| + 10s
  platform_->RunForPeriod(base::Milliseconds(2900));
  // Next scheduled task to run at |start_time_| + 12s
  platform_->AdvanceClock(base::Milliseconds(1800));
  platform_->RunUntilIdle();
  // Next scheduled task to run at |start_time_| + 14s
  platform_->AdvanceClock(base::Milliseconds(1900));
  platform_->RunUntilIdle();
  // Next scheduled task to run at |start_time_| + 18s (skips a beat)
  platform_->AdvanceClock(base::Milliseconds(50));
  platform_->RunUntilIdle();
  // Next scheduled task to run at |start_time_| + 28s (skips 5 beats)
  platform_->AdvanceClock(base::Seconds(10));
  platform_->RunUntilIdle();

  EXPECT_THAT(
      next_fire_times_,
      ElementsAre(
          start_time_ + base::Seconds(2), start_time_ + base::Seconds(4),
          start_time_ + base::Seconds(6), start_time_ + base::Seconds(8),
          start_time_ + base::Seconds(10), start_time_ + base::Seconds(12),
          start_time_ + base::Seconds(14), start_time_ + base::Seconds(24)));
}

template <typename TimerFiredClass>
class TimerForTest : public TaskRunnerTimer<TimerFiredClass> {
 public:
  using TimerFiredFunction =
      typename TaskRunnerTimer<TimerFiredClass>::TimerFiredFunction;

  ~TimerForTest() override = default;

  TimerForTest(scoped_refptr<base::SingleThreadTaskRunner> task_runner,
               TimerFiredClass* timer_fired_class,
               TimerFiredFunction timer_fired_function)
      : TaskRunnerTimer<TimerFiredClass>(std::move(task_runner),
                                         timer_fired_class,
                                         timer_fired_function) {}
};

TEST_F(TimerTest, UserSuppliedTaskRunner) {
  scoped_refptr<MainThreadTaskQueue> task_queue(
      platform_->GetMainThreadScheduler()->NewThrottleableTaskQueueForTest(
          nullptr));
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      task_queue->CreateTaskRunner(TaskType::kInternalTest);
  TimerForTest<TimerTest> timer(task_runner, this, &TimerTest::CountingTask);
  timer.StartOneShot(base::TimeDelta(), FROM_HERE);

  // Make sure the task was posted on taskRunner.
  EXPECT_FALSE(task_queue->IsEmpty());
}

TEST_F(TimerTest, RunOnHeapTimer) {
  scoped_refptr<OnHeapTimerOwner::Record> record =
      OnHeapTimerOwner::Record::Create();
  Persistent<OnHeapTimerOwner> owner =
      MakeGarbageCollected<OnHeapTimerOwner>(record, GetTaskRunner());

  owner->StartOneShot(base::TimeDelta(), FROM_HERE);

  EXPECT_FALSE(record->TimerHasFired());
  platform_->RunUntilIdle();
  EXPECT_TRUE(record->TimerHasFired());
}

TEST_F(TimerTest, DestructOnHeapTimer) {
  scoped_refptr<OnHeapTimerOwner::Record> record =
      OnHeapTimerOwner::Record::Create();
  Persistent<OnHeapTimerOwner> owner =
      MakeGarbageCollected<OnHeapTimerOwner>(record, GetTaskRunner());

  record->Dispose();
  owner->StartOneShot(base::TimeDelta(), FROM_HERE);

  owner = nullptr;
  ThreadState::Current()->CollectAllGarbageForTesting(
      ThreadState::StackState::kNoHeapPointers);
  EXPECT_TRUE(record->OwnerIsDestructed());

  EXPECT_FALSE(record->TimerHasFired());
  platform_->RunUntilIdle();
  EXPECT_FALSE(record->TimerHasFired());
}

// TODO(1056170): Re-enable test.
TEST_F(TimerTest, DISABLED_MarkOnHeapTimerAsUnreachable) {
  scoped_refptr<OnHeapTimerOwner::Record> record =
      OnHeapTimerOwner::Record::Create();
  Persistent<OnHeapTimerOwner> owner =
      MakeGarbageCollected<OnHeapTimerOwner>(record, GetTaskRunner());

  record->Dispose();
  owner->StartOneShot(base::TimeDelta(), FROM_HERE);

  owner = nullptr;
  // Explicit regular GC call to allow lazy sweeping.
  // TODO(1056170): Needs a specific forced GC call to be able to test the
  // scenario below.
  // ThreadState::Current()->CollectGarbageForTesting(
  //     BlinkGC::CollectionType::kMajor, BlinkGC::kNoHeapPointersOnStack,
  //     BlinkGC::kAtomicMarking, BlinkGC::kConcurrentAndLazySweeping,
  //     BlinkGC::GCReason::kForcedGCForTesting);
  // Since the heap is laziy swept, owner is not yet destructed.
  EXPECT_FALSE(record->OwnerIsDestructed());

  {
    ThreadState::GCForbiddenScope gc_forbidden(ThreadState::Current());
    EXPECT_FALSE(record->TimerHasFired());
    platform_->RunUntilIdle();
    EXPECT_FALSE(record->TimerHasFired());
    EXPECT_FALSE(record->OwnerIsDestructed());
    // ThreadState::Current()->CompleteSweep();
  }
}

namespace {

class TaskObserver : public base::TaskObserver {
 public:
  TaskObserver(scoped_refptr<base::SingleThreadTaskRunner> task_runner,
               Vector<scoped_refptr<base::SingleThreadTaskRunner>>* run_order)
      : task_runner_(std::move(task_runner)), run_order_(run_order) {}

  void WillProcessTask(const base::PendingTask&, bool) override {}

  void DidProcessTask(const base::PendingTask&) override {
    run_order_->push_back(task_runner_);
  }

 private:
  scoped_refptr<base::SingleThreadTaskRunner> task_runner_;
  raw_ptr<Vector<scoped_refptr<base::SingleThreadTaskRunner>>> run_order_;
};

}  // namespace

TEST_F(TimerTest, MoveToNewTaskRunnerOneShot) {
  Vector<scoped_refptr<base::SingleThreadTaskRunner>> run_order;

  scoped_refptr<MainThreadTaskQueue> task_queue1(
      platform_->GetMainThreadScheduler()->NewThrottleableTaskQueueForTest(
          nullptr));
  scoped_refptr<base::SingleThreadTaskRunner> task_runner1 =
      task_queue1->CreateTaskRunner(TaskType::kInternalTest);
  TaskObserver task_observer1(task_runner1, &run_order);
  task_queue1->AddTaskObserver(&task_observer1);

  scoped_refptr<MainThreadTaskQueue> task_queue2(
      platform_->GetMainThreadScheduler()->NewThrottleableTaskQueueForTest(
          nullptr));
  scoped_refptr<base::SingleThreadTaskRunner> task_runner2 =
      task_queue2->CreateTaskRunner(TaskType::kInternalTest);
  TaskObserver task_observer2(task_runner2, &run_order);
  task_queue2->AddTaskObserver(&task_observer2);

  TimerForTest<TimerTest> timer(task_runner1, this, &TimerTest::CountingTask);

  base::TimeTicks start_time = Now();

  timer.StartOneShot(base::Seconds(1), FROM_HERE);

  platform_->RunForPeriod(base::Milliseconds(500));

  timer.MoveToNewTaskRunner(task_runner2);

  platform_->RunUntilIdle();

  EXPECT_THAT(run_times_, ElementsAre(start_time + base::Seconds(1)));

  EXPECT_THAT(run_order, ElementsAre(task_runner2));

  EXPECT_TRUE(task_queue1->IsEmpty());
  EXPECT_TRUE(task_queue2->IsEmpty());
}

TEST_F(TimerTest, MoveToNewTaskRunnerRepeating) {
  Vector<scoped_refptr<base::SingleThreadTaskRunner>> run_order;

  scoped_refptr<MainThreadTaskQueue> task_queue1(
      platform_->GetMainThreadScheduler()->NewThrottleableTaskQueueForTest(
          nullptr));
  scoped_refptr<base::SingleThreadTaskRunner> task_runner1 =
      task_queue1->CreateTaskRunner(TaskType::kInternalTest);
  TaskObserver task_observer1(task_runner1, &run_order);
  task_queue1->AddTaskObserver(&task_observer1);

  scoped_refptr<MainThreadTaskQueue> task_queue2(
      platform_->GetMainThreadScheduler()->NewThrottleableTaskQueueForTest(
          nullptr));
  scoped_refptr<base::SingleThreadTaskRunner> task_runner2 =
      task_queue2->CreateTaskRunner(TaskType::kInternalTest);
  TaskObserver task_observer2(task_runner2, &run_order);
  task_queue2->AddTaskObserver(&task_observer2);

  TimerForTest<TimerTest> timer(task_runner1, this, &TimerTest::CountingTask);

  base::TimeTicks start_time = Now();

  timer.StartRepeating(base::Seconds(1), FROM_HERE);

  platform_->RunForPeriod(base::Milliseconds(2500));

  timer.MoveToNewTaskRunner(task_runner2);

  platform_->RunForPeriod(base::Seconds(2));

  EXPECT_THAT(run_times_, ElementsAre(start_time + base::Seconds(1),
                                      start_time + base::Seconds(2),
                                      start_time + base::Seconds(3),
                                      start_time + base::Seconds(4)));

  EXPECT_THAT(run_order, ElementsAre(task_runner1, task_runner1, task_runner2,
                                     task_runner2));

  EXPECT_TRUE(task_queue1->IsEmpty());
  EXPECT_FALSE(task_queue2->IsEmpty());
}

// This test checks that when inactive timer is moved to a different task
// runner it isn't activated.
TEST_F(TimerTest, MoveToNewTaskRunnerWithoutTasks) {
  scoped_refptr<MainThreadTaskQueue> task_queue1(
      platform_->GetMainThreadScheduler()->NewThrottleableTaskQueueForTest(
          nullptr));
  scoped_refptr<base::SingleThreadTaskRunner> task_runner1 =
      task_queue1->CreateTaskRunner(TaskType::kInternalTest);

  scoped_refptr<MainThreadTaskQueue> task_queue2(
      platform_->GetMainThreadScheduler()->NewThrottleableTaskQueueForTest(
          nullptr));
  scoped_refptr<base::SingleThreadTaskRunner> task_runner2 =
      task_queue2->CreateTaskRunner(TaskType::kInternalTest);

  TimerForTest<TimerTest> timer(task_runner1, this, &TimerTest::CountingTask);

  platform_->RunUntilIdle();
  EXPECT_TRUE(!run_times_.size());
  EXPECT_TRUE(task_queue1->IsEmpty());
  EXPECT_TRUE(task_queue2->IsEmpty());
}

}  // namespace
}  // namespace blink
```