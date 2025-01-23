Response:
The user wants to understand the functionality of the provided C++ code snippet, which is a part of a unit test for `IdleHelper` in the Chromium Blink engine. I need to analyze the test cases to infer the behavior of `IdleHelper`.

Here's a breakdown of the tests and their implications:

*   **`LongIdlePeriodStartsAfterQuiescence`**:  This test checks if the long idle period starts only after a period of quiescence (no tasks being processed). It involves a repeating task that keeps the scheduler busy, and verifies that the idle task runs after the quiescence delay plus the long idle period.
*   **`QuescienceCheckedForAfterLongIdlePeriodEnds`**: This test confirms that after a long idle period, the system checks for quiescence before running new idle tasks. A normal task is posted to make the scheduler non-quiescent, and an idle task posted afterwards only runs after the quiescence delay.
*   **`NoShortIdlePeriodWhenDeadlineTooClose`**: This test ensures that a short idle period doesn't start if the deadline is too close. It checks the behavior when the available time is less than and more than the minimum idle period duration.
*   **`NoLongIdlePeriodWhenDeadlineTooClose`**: Similar to the previous test, but for long idle periods. It checks if a long idle period is initiated when the deadline is too close, considering the minimum idle period duration.
*   **`PendingEnableLongIdlePeriodNotRunAfterShutdown`**: This test verifies that if `EnableLongIdlePeriod` is called but the `IdleHelper` is shut down before the idle period starts, the idle tasks are not executed.
*   **`TestPostDelayedIdleTask`**: This test examines the behavior of posting delayed idle tasks. It verifies that the tasks are not added to the queue immediately and are executed only after the delay and during an idle period.
*   **`OnPendingTasksChanged`**: This test checks the `OnPendingTasksChanged` callback, ensuring it's called when the idle queue becomes non-empty and empty.
*   **`OnPendingTasksChanged_TwoTasksAtTheSameTime`**: Similar to the previous one, but with two idle tasks posted at the same time, confirming the callback behavior.
*   **`MultiThreadedIdleHelperTest`**: This section contains tests that involve posting idle tasks from non-main threads, including both immediate and delayed tasks. It checks that `IdleHelper` correctly handles idle tasks coming from different threads.

Based on these observations, I can summarize the functionality of `IdleHelper`.

**Relating to JavaScript, HTML, CSS:**

The `IdleHelper` plays a role in optimizing browser performance, which indirectly affects the execution of JavaScript, rendering of HTML, and application of CSS. Idle tasks can be used for non-critical operations that can be deferred until the browser is less busy, preventing jank and improving responsiveness.

**Logical Reasoning (Hypothetical Input and Output):**

Let's take the `LongIdlePeriodStartsAfterQuiescence` test as an example:

*   **Input:**
    *   A repeating task posted to the default task runner.
    *   An idle task posted to the idle task runner.
    *   `EnableLongIdlePeriod` called on the `IdleHelper`.
*   **Assumptions:**
    *   `kQuiescenceDelayMs` and `kLongIdlePeriodMs` have defined values.
    *   The `test_task_runner_` allows for advancing time and running tasks.
*   **Output:**
    *   The idle task's `run_count` will be 1.
    *   The `deadline_in_task` will be approximately `NowTicks() + 5 * kQuiescenceDelayMs + kLongIdlePeriodMs`.

**User/Programming Errors:**

*   A common mistake could be assuming idle tasks will run immediately after posting them, without considering the quiescence period or the start of an idle period. For example, a developer might post an idle task to perform a DOM manipulation expecting it to happen instantly, which could lead to unexpected behavior if the task is delayed.
*   Another error could be not handling the possibility that idle tasks might not run at all if the browser remains busy or if the idle helper is shut down.

Now, I can synthesize the answer based on this analysis.
这是对 `blink/renderer/platform/scheduler/common/idle_helper_unittest.cc` 文件第二部分的分析归纳，延续了第一部分的测试用例，继续揭示了 `IdleHelper` 的功能。

**功能归纳:**

这部分测试用例主要关注以下 `IdleHelper` 的功能和特性：

1. **长空闲期启动的条件 (Quiescence):**
    *   验证了长空闲期只有在系统进入静默期（quiescence）之后才会启动。即使调用了 `EnableLongIdlePeriod`，如果系统持续有任务运行（被认为繁忙），长空闲期也不会立即开始。
    *   测试了在长空闲期结束后，系统会再次检查静默期，只有当系统再次进入静默期后，新的空闲任务才会被执行。

2. **截止时间对空闲期的影响:**
    *   测试了当剩余时间不足以完成一个最短空闲期时，无论是短空闲期还是长空闲期都不会启动。这确保了空闲任务不会因为时间不足而被匆忙执行。

3. **关闭时的行为:**
    *   验证了在调用 `EnableLongIdlePeriod` 后，如果 `IdleHelper` 被关闭（Shutdown），则等待执行的长空闲期相关的空闲任务将不会被执行。

4. **延迟空闲任务:**
    *   测试了 `PostDelayedIdleTask` 的功能。延迟的空闲任务不会立即加入待执行队列，而是在指定的延迟时间到达后，并且在下一个空闲期开始时才会被执行。

5. **`OnPendingTasksChanged` 回调:**
    *   测试了 `OnPendingTasksChanged` 回调函数的行为。该回调会在空闲任务队列从空变为非空时被调用（传入 `true`），在队列中的所有任务执行完毕变为空时被调用（传入 `false`）。即使同时添加多个空闲任务，也只会在最后一个任务执行完毕后调用一次 `false` 的回调。

6. **多线程下的空闲任务:**
    *   测试了在非主线程中发布空闲任务的情况。验证了 `IdleHelper` 能够正确处理来自不同线程的空闲任务。
    *   测试了在多线程下发布延迟空闲任务的情况，确保延迟机制在多线程环境下仍然有效。
    *   测试了混合使用立即执行和延迟执行的空闲任务，并从多个线程发布的情况，验证了 `IdleHelper` 的调度和管理能力。

**与 Javascript, HTML, CSS 的关系举例:**

*   **延迟空闲任务用于优化 JavaScript 执行:** 当网页加载或用户交互后，可能有一些非关键的 JavaScript 任务需要执行，例如数据分析、缓存更新等。可以使用 `PostDelayedIdleTask` 将这些任务推迟到浏览器空闲时执行，避免阻塞主线程，提高页面响应速度，改善用户体验。
    *   **假设输入:** 用户在页面上完成一个操作后 200 毫秒，有一个 JavaScript 函数需要更新本地存储。
    *   **代码示例 (伪代码):**
        ```javascript
        function updateLocalStorage() {
          // ... 执行本地存储更新操作 ...
        }
        // 在 Blink 渲染进程中，对应的 C++ 代码会使用 PostDelayedIdleTask
        // idle_task_runner_->PostDelayedIdleTask(FROM_HERE, base::Milliseconds(200),
        //                                      base::BindOnce(updateLocalStorage));
        ```
    *   **预期输出:**  `updateLocalStorage` 函数会在用户操作完成 200 毫秒后，并且浏览器处于空闲状态时执行。

*   **空闲期用于 CSS 动画优化:**  一些复杂的 CSS 动画或者过渡效果可能在浏览器繁忙时出现卡顿。可以将一些相关的计算或者资源加载放在空闲任务中执行，例如预加载动画所需的图片资源。
    *   **假设输入:** 页面上有一个复杂的 CSS 动画，依赖于几张高清图片。
    *   **代码示例 (伪代码):**
        ```c++
        // 在 IdleHelper 的空闲任务中预加载图片
        void PreloadAnimationImages() {
          // ... 加载动画图片 ...
        }
        // idle_task_runner_->PostIdleTask(FROM_HERE, base::BindOnce(&PreloadAnimationImages));
        ```
    *   **预期输出:**  `PreloadAnimationImages` 函数会在浏览器空闲时执行，提前加载动画所需的图片，减少动画播放时的卡顿。

*   **空闲期用于 HTML 结构优化:**  在某些场景下，可能需要在页面加载完成后对 DOM 结构进行一些优化，例如懒加载不可见区域的 HTML 内容。可以将这些操作放在空闲任务中执行，避免影响页面的初始渲染速度。
    *   **假设输入:** 页面底部有一些不重要的内容，可以延迟加载。
    *   **代码示例 (伪代码):**
        ```c++
        // 在 IdleHelper 的空闲任务中加载底部内容
        void LoadBottomContent() {
          // ... 加载并插入底部 HTML 内容 ...
        }
        // idle_task_runner_->PostIdleTask(FROM_HERE, base::BindOnce(&LoadBottomContent));
        ```
    *   **预期输出:**  `LoadBottomContent` 函数会在浏览器空闲时执行，加载并插入底部内容，提升首屏渲染速度。

**逻辑推理 (假设输入与输出):**

以 `LongIdlePeriodStartsAfterQuiescence` 测试为例：

*   **假设输入:**
    *   在 `default_task_runner_` 上循环 Post 一个任务，模拟繁忙状态。
    *   在 `idle_task_runner_` 上 Post 一个空闲任务。
    *   调用 `idle_helper_->EnableLongIdlePeriod()`。
*   **逻辑推理:** 由于 `default_task_runner_` 一直有任务执行，系统不会进入静默期。`EnableLongIdlePeriod` 会尝试启动长空闲期，但因为不满足静默条件，实际的长空闲期启动会被延迟。只有当循环任务结束后，系统进入静默期，长空闲期才会真正开始，空闲任务才会被执行。
*   **预期输出:** 空闲任务的 `run_count` 为 1，并且其执行的 `actual_deadline` 时间会是在等待静默期结束后加上长空闲期的时间。

**涉及用户或者编程常见的使用错误举例:**

*   **错误地假设空闲任务会立即执行:** 开发者可能会认为调用 `PostIdleTask` 后，任务会立即执行，而没有考虑到静默期和空闲期的概念。这可能导致依赖于立即执行的任务出现问题。
    *   **错误代码示例:**
        ```javascript
        // 错误地认为这个操作会立即完成
        someCriticalOperation();
        requestIdleCallback(() => {
          // 假设这里的代码依赖于 someCriticalOperation 的立即完成
          doSomethingDependentOnCriticalOperation();
        });
        ```
    *   **正确做法:** 应该理解空闲任务的执行时机是不确定的，并相应地设计代码逻辑。对于有依赖关系的任务，应该使用普通任务或者 Promise 等机制来保证执行顺序。

*   **过度依赖空闲任务导致重要任务延迟:**  开发者可能会为了追求性能优化，将过多的任务都放到空闲队列中，包括一些实际上比较重要的任务。如果浏览器一直处于繁忙状态，这些重要的空闲任务可能会被延迟很久才执行，影响用户体验。
    *   **错误代码示例:** 将所有网络请求或者关键数据处理都放在 `requestIdleCallback` 中。
    *   **正确做法:** 应该仔细评估任务的优先级，只将真正可以延迟执行的非关键任务放在空闲队列中。

总而言之，这部分测试用例进一步强调了 `IdleHelper` 在 Blink 引擎中用于优化任务调度，利用浏览器空闲时间执行非关键任务，从而提升整体性能和用户体验的关键作用。理解其工作原理，特别是静默期、空闲期和延迟任务的概念，对于正确使用 `IdleHelper` 至关重要。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/common/idle_helper_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
HERE, base::BindOnce(&RepostingIdleTestTask,
                                base::RetainedRef(idle_task_runner_),
                                &run_count, &actual_deadline));

  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();

  EXPECT_EQ(0, run_count);
}

TEST_F(IdleHelperWithQuiescencePeriodTest,
       LongIdlePeriodStartsAfterQuiescence) {
  MakeNonQuiescent();

  // Run a repeating task so we're deemed to be busy for the next 400ms.
  default_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&RepeatingTask,
                                base::Unretained(default_task_runner_.get()),
                                10, base::Milliseconds(40)));

  int run_count = 0;
  // In this scenario EnableLongIdlePeriod deems us not to be quiescent 5x in
  // a row.
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() +
      base::Milliseconds(5 * kQuiescenceDelayMs + kLongIdlePeriodMs);
  base::TimeTicks deadline_in_task;
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(1, run_count);
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

TEST_F(IdleHelperWithQuiescencePeriodTest,
       QuescienceCheckedForAfterLongIdlePeriodEnds) {
  idle_task_runner_->PostIdleTask(FROM_HERE, base::BindOnce(&NullIdleTask));
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();

  // Post a normal task to make the scheduler non-quiescent.
  default_task_runner_->PostTask(FROM_HERE, base::BindOnce(&NullTask));
  test_task_runner_->RunUntilIdle();

  // Post an idle task. The idle task won't run initially because the system is
  // not judged to be quiescent, but should be run after the quiescence delay.
  int run_count = 0;
  base::TimeTicks deadline_in_task;
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() +
      base::Milliseconds(kQuiescenceDelayMs + kLongIdlePeriodMs);
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_EQ(1, run_count);
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

TEST_F(IdleHelperTest, NoShortIdlePeriodWhenDeadlineTooClose) {
  int run_count = 0;
  base::TimeTicks deadline_in_task;

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  base::TimeDelta half_a_ms(base::Microseconds(50));
  base::TimeTicks less_than_min_deadline(test_task_runner_->NowTicks() +
                                         minimum_idle_period_duration() -
                                         half_a_ms);
  base::TimeTicks more_than_min_deadline(test_task_runner_->NowTicks() +
                                         minimum_idle_period_duration() +
                                         half_a_ms);

  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                less_than_min_deadline);
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                more_than_min_deadline);
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);
}

TEST_F(IdleHelperTest, NoLongIdlePeriodWhenDeadlineTooClose) {
  int run_count = 0;
  base::TimeTicks deadline_in_task;

  base::TimeDelta half_a_ms(base::Microseconds(50));
  base::TimeDelta less_than_min_deadline_duration(
      minimum_idle_period_duration() - half_a_ms);
  base::TimeDelta more_than_min_deadline_duration(
      minimum_idle_period_duration() + half_a_ms);

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  default_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NullTask),
                                        less_than_min_deadline_duration);

  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->EndIdlePeriod();
  test_task_runner_->AdvanceMockTickClock(maximum_idle_period_duration());
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  default_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NullTask),
                                        more_than_min_deadline_duration);
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);
}

TEST_F(IdleHelperWithQuiescencePeriodTest,
       PendingEnableLongIdlePeriodNotRunAfterShutdown) {
  MakeNonQuiescent();

  bool shutdown_task_run = false;
  int run_count = 0;
  base::TimeTicks deadline_in_task;
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&ShutdownIdleTask, base::Unretained(idle_helper_.get()),
                     &shutdown_task_run));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  // Delayed call to IdleHelper::EnableLongIdlePeriod enables idle tasks.
  idle_helper_->EnableLongIdlePeriod();
  test_task_runner_->AdvanceMockTickClock(maximum_idle_period_duration() * 2.0);
  test_task_runner_->RunUntilIdle();
  EXPECT_TRUE(shutdown_task_run);
  EXPECT_EQ(0, run_count);

  // Shutdown immediately after idle period started should prevent the idle
  // task from running.
  idle_helper_->Shutdown();
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);
}

TEST_F(IdleHelperTest, TestPostDelayedIdleTask) {
  int run_count = 0;
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() + base::Milliseconds(2300);
  base::TimeTicks deadline_in_task;

  // Posting a delayed idle task should not post anything on the underlying
  // task queue until the delay is up.
  idle_task_runner_->PostDelayedIdleTask(
      FROM_HERE, base::Milliseconds(200),
      base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  EXPECT_EQ(0u, idle_queue()->GetNumberOfPendingTasks());

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));

  // It shouldn't run until the delay is over even though we went idle.
  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                expected_deadline);
  EXPECT_EQ(0u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));
  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                expected_deadline);
  EXPECT_EQ(1u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();

  EXPECT_EQ(1, run_count);
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

// Tests that the OnPendingTasksChanged callback is called once when the idle
// queue becomes non-empty and again when it becomes empty.
TEST_F(IdleHelperTest, OnPendingTasksChanged) {
  int run_count = 0;
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() + base::Milliseconds(2300);
  base::TimeTicks deadline_in_task;

  {
    testing::InSequence dummy;
    // This will be called once. I.e when the one and only task is posted.
    EXPECT_CALL(*idle_helper_, OnPendingTasksChanged(true)).Times(1);
    // This will be called once. I.e when the one and only task completes.
    EXPECT_CALL(*idle_helper_, OnPendingTasksChanged(false)).Times(1);
  }

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                expected_deadline);
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(1, run_count);
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

// Tests that the OnPendingTasksChanged callback is still only called once
// with false despite there being two idle tasks posted.
TEST_F(IdleHelperTest, OnPendingTasksChanged_TwoTasksAtTheSameTime) {
  int run_count = 0;
  base::TimeTicks expected_deadline =
      test_task_runner_->NowTicks() + base::Milliseconds(2300);
  base::TimeTicks deadline_in_task;

  {
    testing::InSequence dummy;
    // This will be called 3 times. I.e when T1 and T2 are posted and when T1
    // completes.
    EXPECT_CALL(*idle_helper_, OnPendingTasksChanged(true)).Times(3);
    // This will be called once. I.e when T2 completes.
    EXPECT_CALL(*idle_helper_, OnPendingTasksChanged(false)).Times(1);
  }

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->StartIdlePeriod(IdleHelper::IdlePeriodState::kInShortIdlePeriod,
                                test_task_runner_->NowTicks(),
                                expected_deadline);
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(2, run_count);
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

class MultiThreadedIdleHelperTest : public IdleHelperTest {
 public:
  void PostIdleTaskFromNewThread(int* run_count) {
    PostDelayedIdleTaskFromNewThread(base::TimeDelta(), run_count);
  }

  void PostDelayedIdleTaskFromNewThread(base::TimeDelta delay, int* run_count) {
    std::unique_ptr<NonMainThread> thread = NonMainThread::CreateThread(
        ThreadCreationParams(ThreadType::kTestThread)
            .SetThreadNameForTest("TestBackgroundThread"));
    PostCrossThreadTask(
        *thread->GetTaskRunner(), FROM_HERE,
        CrossThreadBindOnce(&PostIdleTaskFromBackgroundThread,
                            idle_task_runner_, delay,
                            WTF::CrossThreadUnretained(run_count)));
    thread.reset();
  }

 protected:
  static void PostIdleTaskFromBackgroundThread(
      scoped_refptr<SingleThreadIdleTaskRunner> idle_task_runner,
      base::TimeDelta delay,
      int* run_count) {
    auto callback = ConvertToBaseOnceCallback(CrossThreadBindOnce(
        &IdleTestTask, WTF::CrossThreadUnretained(run_count), nullptr));
    if (delay.is_zero()) {
      idle_task_runner->PostIdleTask(FROM_HERE, std::move(callback));
    } else {
      idle_task_runner->PostDelayedIdleTask(FROM_HERE, delay,
                                            std::move(callback));
    }
  }
};

TEST_F(MultiThreadedIdleHelperTest, IdleTasksFromNonMainThreads) {
  int run_count = 0;

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));

  PostIdleTaskFromNewThread(&run_count);
  PostIdleTaskFromNewThread(&run_count);
  PostIdleTaskFromNewThread(&run_count);

  EXPECT_EQ(3u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(3, run_count);
}

TEST_F(MultiThreadedIdleHelperTest, DelayedIdleTasksFromNonMainThreads) {
  int run_count = 0;

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));

  PostDelayedIdleTaskFromNewThread(base::Milliseconds(200), &run_count);
  PostDelayedIdleTaskFromNewThread(base::Milliseconds(250), &run_count);
  PostDelayedIdleTaskFromNewThread(base::Milliseconds(300), &run_count);

  // Delayed idle tasks are not queued until a new idle period starts.
  EXPECT_EQ(0u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(300));
  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  EXPECT_EQ(3u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();

  EXPECT_EQ(3, run_count);
}

TEST_F(MultiThreadedIdleHelperTest,
       DelayedAndNonDelayedIdleTasksFromMultipleThreads) {
  int run_count = 0;

  PostIdleTaskFromNewThread(&run_count);

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, nullptr));

  PostDelayedIdleTaskFromNewThread(base::Milliseconds(200), &run_count);

  idle_task_runner_->PostDelayedIdleTask(
      FROM_HERE, base::Milliseconds(250),
      base::BindOnce(&IdleTestTask, &run_count, nullptr));

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(250));

  EXPECT_EQ(2u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();
  EXPECT_EQ(0, run_count);

  idle_helper_->StartIdlePeriod(
      IdleHelper::IdlePeriodState::kInShortIdlePeriod,
      test_task_runner_->NowTicks(),
      test_task_runner_->NowTicks() + base::Milliseconds(10));
  EXPECT_EQ(4u, idle_queue()->GetNumberOfPendingTasks());
  test_task_runner_->RunUntilIdle();

  EXPECT_EQ(4, run_count);
}

}  // namespace idle_helper_unittest
}  // namespace scheduler
}  // namespace blink
```