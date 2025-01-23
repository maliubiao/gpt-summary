Response:
The user wants a summary of the functionality of the C++ code file `frame_scheduler_impl_unittest.cc`. This file appears to be a unit test suite for the `FrameSchedulerImpl` class in the Chromium Blink rendering engine.

Here's a breakdown of the thought process to generate the summary:

1. **Identify the core purpose:** The file name itself, "...unittest.cc", strongly suggests that this file contains unit tests. The tests are for `FrameSchedulerImpl`, indicating the focus is on testing the frame scheduling logic.

2. **Scan for keywords related to functionality:** Look for patterns and keywords that reveal the tested features. Keywords like `TEST_P`, `TEST_F`, `EXPECT_THAT`, `PostDelayedTask`, `SetPageVisible`, `SetCrossOriginToNearestMainFrame`, `RegisterFeature`, etc., are good indicators.

3. **Group tests by feature:** Notice how the tests are named. Many tests are prefixed with `TaskExecution`, `ManySameOriginFrames`, `AggressiveThrottlingOptOut`, etc. This suggests that the tests are organized around specific aspects of frame scheduling. Group these related tests together.

4. **Infer the tested features:** Based on the test names and the operations performed within the tests, deduce the underlying functionalities being tested. For example:
    * `TaskExecution...`: Tests how tasks are scheduled and executed under different conditions (same-origin, cross-origin, visible, hidden).
    * `...WithIntensiveWakeUpThrottling`: Focuses on the intensive wake-up throttling mechanism.
    * `AggressiveThrottlingOptOut`: Tests the ability to disable aggressive throttling for specific features.
    * `FrameChangesOriginType`: Examines how the scheduler behaves when a frame's origin changes.
    * `ThrottleUnimportantFrameTimersEnabledTest`: Deals with throttling timers in less important frames.

5. **Look for connections to web technologies:** Analyze if the tested features have any relevance to JavaScript, HTML, or CSS. Keywords like `JavascriptTimerDelayed`, `PostMessageForwarding`, and discussions around frame visibility and origin point to these connections.

6. **Identify logic and assumptions:** Notice the use of `FastForwardBy` and `FastForwardUntilNoTasksRemain`. This shows the tests manipulate time to simulate different scenarios and check task execution order and timing. The tests often set up specific conditions (e.g., page visibility, frame origin) as input and verify the task execution times as output.

7. **Identify potential user/programming errors:** While primarily focused on testing internal logic, some tests touch on scenarios that could relate to developer behavior, like the implications of cross-origin iframes or the impact of hidden pages on timer execution.

8. **Focus on the current section:** Remember that the prompt specifies this is part 4 of 5. Look for the main themes covered in this specific section of the code. This section heavily emphasizes intensive wake-up throttling under various cross-origin and visibility scenarios.

9. **Synthesize the summary:** Combine the observations into a concise summary, addressing the user's request for functionality, relationships to web technologies, logical reasoning, and potential errors.

**Self-Correction/Refinement during the process:**

* **Initial thought:**  Maybe the file just tests basic task posting.
* **Correction:**  The test names and the presence of throttling-related functions indicate more advanced features are being tested.
* **Initial thought:**  Focus only on the positive tests.
* **Correction:**  Consider negative scenarios or edge cases implicitly tested, like how throttling behaves under different conditions.
* **Initial thought:** List every single test case.
* **Correction:** Group similar tests by the functionality they are verifying to provide a more structured and understandable summary.

By following this structured approach, we can accurately and comprehensively summarize the functionality of the given code snippet.
这是 `blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl_unittest.cc` 文件的第四部分，主要关注 **在不同场景下任务的调度和执行，特别是针对跨域 frame 和后台页面时的 `IntensiveWakeUpThrottling` (密集唤醒节流) 机制的测试。**

以下是更详细的功能归纳：

**核心功能：密集唤醒节流 (IntensiveWakeUpThrottling) 测试**

这部分代码主要用于测试 `FrameSchedulerImpl` 中实现的密集唤醒节流功能，该功能旨在限制后台或不可见 frame 中 JavaScript 定时器等任务的唤醒频率，以节省资源和提升性能。

**测试场景和功能点：**

* **跨域 Frame 的任务执行：**
    * 测试在跨域 frame 中，即使页面处于后台，任务的执行时间是否符合密集唤醒节流的预期。
    * 验证在密集节流生效后，任务的唤醒时间是否会按照分钟级别对齐（如果 `TaskType` 支持密集节流），否则按秒级别对齐。
    * 验证当跨域 frame 的页面与用户进行通信后（例如，更新了标题或 Favicon），密集节流是否仍然生效。
* **多个同源 Frame 的任务执行：**
    * 测试当有多个同源的 frame 时，任务的执行时间是否符合预期。
    * 验证在密集节流生效后，不同同源 frame 的任务是否会按照秒或分钟级别对齐。
* **页面加载时隐藏的场景：**
    * 测试当页面在加载过程中被隐藏时，密集唤醒节流的启动延迟是否会延长（从 1 分钟延长到 5 分钟）。
* **禁用密集节流的机制 (Opt-Out)：**
    * 测试通过 `RegisterFeature` 注册 `SchedulingPolicy::DisableAggressiveThrottling()` 后，是否能禁用密集唤醒节流。
    * 验证禁用后，任务的执行仍然会受到默认的唤醒节流影响，但不会受到分钟级别的密集节流限制。
* **Frame 的 Origin 类型变化：**
    * 测试当一个 frame 在同源和跨域之间切换时，任务的执行时间是否会相应地发生变化，以符合密集唤醒节流的规则。
* **策略强制启用/禁用：**
    * 测试通过策略强制启用或禁用密集唤醒节流的功能。
* **快速密集唤醒节流 (QuickIntensiveWakeUpThrottling)：**
    * 测试在启用 `kQuickIntensiveWakeUpThrottlingAfterLoading` feature 后，加载中和加载完成的页面的密集节流 Grace Period 是否符合预期。
* **非延迟的 WebScheduling 任务：**
    * 验证非延迟的 `kWebSchedulingPostedTask` 任务不会受到节流机制的影响，会立即执行。
* **PostMessage 转发任务的优先级：**
    * 验证 `kInternalPostMessageForwarding` 类型的任务具有非常高的优先级。
* **不可见但重要的 Frame 的节流 (ThrottleUnimportantFrameTimers)：**
    * 测试在启用 `kThrottleUnimportantFrameTimers` feature 后，对于跨域且不可见的 frame，会根据其可见区域大小和用户激活状态来节流定时器任务。
    * 验证在不同条件下（隐藏、小面积可见、无用户激活等），定时器任务会被对齐到 32ms 或 1s。
* **没有节流的可见代理 (NoThrottlingVisibleAgent)：**
    * 测试在启用 `kNoThrottlingVisibleAgent` feature 后，对于可见的 agent (可能是 iframe 或 worker)，即使是跨域的，也不会应用节流。

**与 JavaScript, HTML, CSS 的关系：**

这部分测试直接关系到 JavaScript 的定时器功能，例如 `setTimeout` 和 `setInterval`。密集唤醒节流的主要目标就是限制这些定时器在后台或不可见 frame 中的执行频率，从而影响 JavaScript 代码的执行时机。

**举例说明：**

* **假设输入 (跨域 Frame，页面后台)：** 一个跨域的 iframe 页面被隐藏，其中设置了一个 `setTimeout` 定时器，延迟 1 秒执行一个函数。
* **预期输出 (密集节流生效)：** 如果密集节流生效，这个定时器不会在 1 秒后立即执行，而是会被延迟到下一个分钟级别的对齐时间点执行（如果 `TaskType` 支持密集节流）。

* **假设输入 (禁用密集节流)：** 通过 `RegisterFeature` 为某个 frame 禁用了密集节流，并且该 frame 页面处于后台。其中设置了一个 `setTimeout` 定时器，延迟 1 秒执行一个函数。
* **预期输出 (默认节流生效)：** 定时器不会立即执行，而是会被延迟到下一个秒级别的对齐时间点执行，因为默认的唤醒节流仍然生效。

**用户或编程常见的使用错误：**

* **过度依赖后台定时器：** 开发者可能会在后台页面或跨域 iframe 中过度使用 `setTimeout` 或 `setInterval` 来执行任务，而没有考虑到密集唤醒节流的影响，导致任务执行时机延迟，影响应用的功能。
* **没有考虑 Frame 的 Origin 类型：** 开发者可能没有意识到跨域 frame 和同源 frame 在后台任务调度上存在差异，导致在跨域 iframe 中设置的定时器行为与预期不符。
* **错误地认为禁用某些功能会影响节流：**  开发者可能认为禁用某个 JavaScript API 会阻止节流机制生效，但实际上节流机制是针对任务类型的，而不是特定的 API。

**总结:**

这部分单元测试主要验证了 `FrameSchedulerImpl` 中密集唤醒节流机制在各种跨域和页面可见性场景下的行为是否符合预期。它确保了 Blink 引擎能够有效地限制后台任务的唤醒频率，从而提高性能和节省资源，同时也测试了开发者可以通过特定方式禁用该机制的能力。测试覆盖了 JavaScript 定时器在这种机制下的行为，并暗示了开发者在使用后台定时器时需要注意的潜在问题。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共5部分，请归纳一下它的功能
```

### 源代码
```cpp
tensiveThrottlingExpected()) {
      EXPECT_THAT(
          run_times,
          testing::ElementsAre(
              scope_start + base::Seconds(1), scope_start + base::Seconds(2),
              scope_start + base::Seconds(3),
              scope_start - kDefaultThrottledWakeUpInterval + base::Minutes(1),
              scope_start - kDefaultThrottledWakeUpInterval + base::Minutes(1),
              scope_start - kDefaultThrottledWakeUpInterval +
                  base::Minutes(1)));
    } else {
      EXPECT_THAT(
          run_times,
          testing::ElementsAre(
              scope_start + base::Seconds(1), scope_start + base::Seconds(2),
              scope_start + base::Seconds(3), scope_start + base::Seconds(4),
              scope_start + base::Seconds(5), scope_start + base::Seconds(6)));
    }
  }
}

// Verify that tasks run at the expected time in a frame that is cross-origin
// with the main frame with intensive wake up throttling.
TEST_P(FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
       TaskExecutionCrossOriginFrame) {
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);

  // Throttled TaskRunner to which tasks are posted in this test.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetTaskRunner();

  // Snap the time to a multiple of
  // |kIntensiveThrottledWakeUpInterval|. Otherwise, the time at which
  // tasks can run after throttling is enabled will vary.
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);
  const base::TimeTicks test_start = base::TimeTicks::Now();

  // Hide the page. This starts the delay to throttle background wake ups.
  EXPECT_TRUE(page_scheduler_->IsPageVisible());
  page_scheduler_->SetPageVisible(false);

  // Initially, wake ups are not intensively throttled.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start);
    std::vector<base::TimeTicks> run_times;

    for (int i = 0; i < kNumTasks; ++i) {
      task_runner->PostDelayedTask(
          FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
          kShortDelay + i * kDefaultThrottledWakeUpInterval);
    }

    task_environment_.FastForwardBy(kGracePeriod);
    EXPECT_THAT(run_times,
                testing::ElementsAre(scope_start + base::Seconds(1),
                                     scope_start + base::Seconds(2),
                                     scope_start + base::Seconds(3),
                                     scope_start + base::Seconds(4),
                                     scope_start + base::Seconds(5)));
  }

  // After the grace period:

  // Test posting a task when there is no recent wake up. The wake up should be
  // 1-minute aligned if the TaskType supports intensive throttling (in a main
  // frame, it would have been 1-second aligned since there was no wake up in
  // the last minute). Otherwise, it should be 1-second aligned.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(1));
    std::vector<base::TimeTicks> run_times;

    task_runner->PostDelayedTask(FROM_HERE,
                                 base::BindOnce(&RecordRunTime, &run_times),
                                 kDefaultThrottledWakeUpInterval);

    task_environment_.FastForwardBy(kIntensiveThrottledWakeUpInterval);
    EXPECT_THAT(run_times, testing::ElementsAre(scope_start +
                                                GetExpectedWakeUpInterval()));
  }

  // Test posting many tasks with short delays. Wake ups should be 1-minute
  // aligned if the TaskType supports intensive throttling, or 1-second aligned
  // otherwise.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(2));
    std::vector<base::TimeTicks> run_times;

    for (int i = 0; i < kNumTasks; ++i) {
      task_runner->PostDelayedTask(
          FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
          kShortDelay + i * kDefaultThrottledWakeUpInterval);
    }

    task_environment_.FastForwardBy(kIntensiveThrottledWakeUpInterval);

    if (IsIntensiveThrottlingExpected()) {
      const base::TimeTicks aligned_time =
          scope_start + kIntensiveThrottledWakeUpInterval;
      EXPECT_THAT(run_times,
                  testing::ElementsAre(aligned_time, aligned_time, aligned_time,
                                       aligned_time, aligned_time));
    } else {
      EXPECT_THAT(run_times,
                  testing::ElementsAre(scope_start + base::Seconds(1),
                                       scope_start + base::Seconds(2),
                                       scope_start + base::Seconds(3),
                                       scope_start + base::Seconds(4),
                                       scope_start + base::Seconds(5)));
    }
  }

  // Post an extra task with a short delay. Wake ups should be 1-minute aligned
  // if the TaskType supports intensive throttling, or 1-second aligned
  // otherwise.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(3));
    std::vector<base::TimeTicks> run_times;

    task_runner->PostDelayedTask(FROM_HERE,
                                 base::BindOnce(&RecordRunTime, &run_times),
                                 kDefaultThrottledWakeUpInterval);

    task_environment_.FastForwardBy(kIntensiveThrottledWakeUpInterval);
    EXPECT_THAT(run_times, testing::ElementsAre(scope_start +
                                                GetExpectedWakeUpInterval()));
  }

  // Post an extra task with a delay longer than the intensive throttling wake
  // up interval. The wake up should be 1-minute aligned if the TaskType
  // supports intensive throttling (in a main frame, it would have been 1-second
  // aligned because there was no wake up in the last minute). Otherwise, it
  // should be 1-second aligned.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(4));
    std::vector<base::TimeTicks> run_times;

    const base::TimeDelta kLongDelay = kIntensiveThrottledWakeUpInterval * 6;
    task_runner->PostDelayedTask(FROM_HERE,
                                 base::BindOnce(&RecordRunTime, &run_times),
                                 kLongDelay - kShortDelay);

    task_environment_.FastForwardBy(kLongDelay);
    EXPECT_THAT(run_times, testing::ElementsAre(scope_start + kLongDelay));
  }

  // Post tasks with short delays after the page communicated with the user in
  // background. Wake ups should be 1-minute aligned if the TaskType supports
  // intensive throttling, since cross-origin frames are not affected by title
  // or favicon update. Otherwise, they should be 1-second aligned.
  {
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    EXPECT_EQ(scope_start, test_start + base::Minutes(10));
    std::vector<base::TimeTicks> run_times;

    page_scheduler_->OnTitleOrFaviconUpdated();
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindLambdaForTesting([&]() {
          RecordRunTime(&run_times);
          for (int i = 0; i < kNumTasks; ++i) {
            task_runner->PostDelayedTask(
                FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
                kDefaultThrottledWakeUpInterval * (i + 1));
          }
          page_scheduler_->OnTitleOrFaviconUpdated();
        }),
        kDefaultThrottledWakeUpInterval);

    task_environment_.FastForwardUntilNoTasksRemain();

    if (IsIntensiveThrottlingExpected()) {
      EXPECT_THAT(
          run_times,
          testing::ElementsAre(
              scope_start + base::Minutes(1), scope_start + base::Minutes(2),
              scope_start + base::Minutes(2), scope_start + base::Minutes(2),
              scope_start + base::Minutes(2), scope_start + base::Minutes(2)));
    } else {
      EXPECT_THAT(
          run_times,
          testing::ElementsAre(
              scope_start + base::Seconds(1), scope_start + base::Seconds(2),
              scope_start + base::Seconds(3), scope_start + base::Seconds(4),
              scope_start + base::Seconds(5), scope_start + base::Seconds(6)));
    }
  }
}

// Verify that tasks from different frames that are same-origin with the main
// frame run at the expected time.
TEST_P(FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
       ManySameOriginFrames) {
  ASSERT_FALSE(frame_scheduler_->IsCrossOriginToNearestMainFrame());
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetTaskRunner();

  // Create a FrameScheduler that is same-origin with the main frame, and an
  // associated throttled TaskRunner.
  std::unique_ptr<FrameSchedulerImpl> other_frame_scheduler =
      CreateFrameScheduler(page_scheduler_.get(),
                           frame_scheduler_delegate_.get(),
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kSubframe);
  ASSERT_FALSE(other_frame_scheduler->IsCrossOriginToNearestMainFrame());
  const scoped_refptr<base::SingleThreadTaskRunner> other_task_runner =
      GetTaskRunner(other_frame_scheduler.get());

  // Snap the time to a multiple of
  // |kIntensiveThrottledWakeUpInterval|. Otherwise, the time at which
  // tasks can run after throttling is enabled will vary.
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);

  // Hide the page and wait until the intensive throttling grace period has
  // elapsed.
  EXPECT_TRUE(page_scheduler_->IsPageVisible());
  page_scheduler_->SetPageVisible(false);
  task_environment_.FastForwardBy(kGracePeriod);

  // Post tasks in both frames, with delays shorter than the intensive wake up
  // interval.
  const base::TimeTicks post_time = base::TimeTicks::Now();
  std::vector<base::TimeTicks> run_times;
  task_runner->PostDelayedTask(FROM_HERE,
                               base::BindOnce(&RecordRunTime, &run_times),
                               kDefaultThrottledWakeUpInterval + kShortDelay);
  other_task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
      2 * kDefaultThrottledWakeUpInterval + kShortDelay);
  task_environment_.FastForwardUntilNoTasksRemain();

  // The first task is 1-second aligned, because there was no wake up in the
  // last minute. The second task is 1-minute aligned if the TaskType supports
  // intensive throttling, or 1-second aligned otherwise.
  if (IsIntensiveThrottlingExpected()) {
    EXPECT_THAT(run_times, testing::ElementsAre(
                               post_time + 2 * kDefaultThrottledWakeUpInterval,
                               post_time + kIntensiveThrottledWakeUpInterval));
  } else {
    EXPECT_THAT(
        run_times,
        testing::ElementsAre(post_time + 2 * kDefaultThrottledWakeUpInterval,
                             post_time + 3 * kDefaultThrottledWakeUpInterval));
  }
}

// Verify that intensive wake up throttling starts after 5 minutes instead of 1
// minute if the page is loading when hidden.
TEST_P(FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
       TaskExecutionPageLoadingWhenHidden) {
  ASSERT_FALSE(frame_scheduler_->IsCrossOriginToNearestMainFrame());

  // Throttled TaskRunner to which tasks are posted in this test.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetTaskRunner();

  // Snap the time to a multiple of
  // |kIntensiveThrottledWakeUpInterval|. Otherwise, the time at which
  // tasks can run after throttling is enabled will vary.
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);
  const base::TimeTicks test_start = base::TimeTicks::Now();

  // Create a main frame and simulate a load in it.
  std::unique_ptr<FrameSchedulerImpl> main_frame_scheduler =
      CreateFrameScheduler(page_scheduler_.get(),
                           frame_scheduler_delegate_.get(),
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kMainFrame);
  main_frame_scheduler->DidCommitProvisionalLoad(
      /*is_web_history_inert_commit=*/false,
      /*navigation_type=*/FrameScheduler::NavigationType::kOther);
  EXPECT_TRUE(page_scheduler_->IsLoading());

  // Hide the page. This starts the delay to throttle background wake ups.
  EXPECT_TRUE(page_scheduler_->IsPageVisible());
  page_scheduler_->SetPageVisible(false);

  // Wake ups are only "intensively" throttled after 5 minutes.
  std::vector<base::TimeTicks> run_times;
  task_runner->PostDelayedTask(
      FROM_HERE, base::BindOnce(&RecordRunTime, &run_times), base::Seconds(59));
  task_runner->PostDelayedTask(FROM_HERE,
                               base::BindOnce(&RecordRunTime, &run_times),
                               base::Seconds(297));
  task_runner->PostDelayedTask(FROM_HERE,
                               base::BindOnce(&RecordRunTime, &run_times),
                               base::Seconds(298));
  task_runner->PostDelayedTask(FROM_HERE,
                               base::BindOnce(&RecordRunTime, &run_times),
                               base::Seconds(300));
  task_runner->PostDelayedTask(FROM_HERE,
                               base::BindOnce(&RecordRunTime, &run_times),
                               base::Seconds(301));

  task_environment_.FastForwardBy(base::Minutes(7));

  if (IsIntensiveThrottlingExpected()) {
    EXPECT_THAT(run_times, testing::ElementsAre(test_start + base::Seconds(59),
                                                test_start + base::Seconds(297),
                                                test_start + base::Seconds(298),
                                                test_start + base::Seconds(300),
                                                test_start + base::Minutes(6)));
  } else {
    EXPECT_THAT(run_times,
                testing::ElementsAre(test_start + base::Seconds(59),
                                     test_start + base::Seconds(297),
                                     test_start + base::Seconds(298),
                                     test_start + base::Seconds(300),
                                     test_start + base::Seconds(301)));
  }
}

// Verify that intensive throttling is disabled when there is an opt-out.
TEST_P(FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
       AggressiveThrottlingOptOut) {
  constexpr int kNumTasks = 3;
  // |task_runner| is throttled.
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetTaskRunner();
  // |other_task_runner| is throttled. It belongs to a different frame on the
  // same page.
  const auto other_frame_scheduler = CreateFrameScheduler(
      page_scheduler_.get(), frame_scheduler_delegate_.get(),
      /*is_in_embedded_frame_tree=*/false,
      FrameScheduler::FrameType::kSubframe);
  const scoped_refptr<base::SingleThreadTaskRunner> other_task_runner =
      GetTaskRunner(other_frame_scheduler.get());

  // Fast-forward the time to a multiple of
  // |kIntensiveThrottledWakeUpInterval|. Otherwise,
  // the time at which tasks can run after throttling is enabled will vary.
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);

  // Hide the page and wait until the intensive throttling grace period has
  // elapsed.
  EXPECT_TRUE(page_scheduler_->IsPageVisible());
  page_scheduler_->SetPageVisible(false);
  task_environment_.FastForwardBy(kGracePeriod);

  {
    // Wake ups are intensively throttled, since there is no throttling opt-out.
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    std::vector<base::TimeTicks> run_times;
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindOnce(&RecordRunTime, &run_times), kShortDelay);
    task_runner->PostDelayedTask(FROM_HERE,
                                 base::BindOnce(&RecordRunTime, &run_times),
                                 kDefaultThrottledWakeUpInterval + kShortDelay);
    task_environment_.FastForwardUntilNoTasksRemain();
    if (IsIntensiveThrottlingExpected()) {
      // Note: Intensive throttling is not applied on the 1st task since there
      // is no recent wake up.
      EXPECT_THAT(run_times,
                  testing::ElementsAre(
                      scope_start + kDefaultThrottledWakeUpInterval,
                      scope_start + kIntensiveThrottledWakeUpInterval));
    } else {
      EXPECT_THAT(run_times,
                  testing::ElementsAre(
                      scope_start + kDefaultThrottledWakeUpInterval,
                      scope_start + 2 * kDefaultThrottledWakeUpInterval));
    }
  }

  {
    // Create an opt-out.
    auto handle = frame_scheduler_->RegisterFeature(
        SchedulingPolicy::Feature::kWebRTC,
        {SchedulingPolicy::DisableAggressiveThrottling()});

    {
      // Tasks should run after |kDefaultThrottledWakeUpInterval|, since
      // aggressive throttling is disabled, but default wake up throttling
      // remains enabled.
      const base::TimeTicks scope_start = base::TimeTicks::Now();
      std::vector<base::TimeTicks> run_times;
      for (int i = 1; i < kNumTasks + 1; ++i) {
        task_runner->PostDelayedTask(FROM_HERE,
                                     base::BindOnce(&RecordRunTime, &run_times),
                                     i * kShortDelay);
      }
      task_environment_.FastForwardUntilNoTasksRemain();
      EXPECT_THAT(
          run_times,
          testing::ElementsAre(scope_start + kDefaultThrottledWakeUpInterval,
                               scope_start + kDefaultThrottledWakeUpInterval,
                               scope_start + kDefaultThrottledWakeUpInterval));
    }

    {
      // Same thing for another frame on the same page.
      const base::TimeTicks scope_start = base::TimeTicks::Now();
      std::vector<base::TimeTicks> run_times;
      for (int i = 1; i < kNumTasks + 1; ++i) {
        other_task_runner->PostDelayedTask(
            FROM_HERE, base::BindOnce(&RecordRunTime, &run_times),
            i * kShortDelay);
      }
      task_environment_.FastForwardUntilNoTasksRemain();
      EXPECT_THAT(
          run_times,
          testing::ElementsAre(scope_start + kDefaultThrottledWakeUpInterval,
                               scope_start + kDefaultThrottledWakeUpInterval,
                               scope_start + kDefaultThrottledWakeUpInterval));
    }
  }

  // Fast-forward so that there is no recent wake up. Then, align the time on
  // |kIntensiveThrottledWakeUpInterval| to simplify expectations.
  task_environment_.FastForwardBy(kIntensiveThrottledWakeUpInterval);
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);

  {
    // Wake ups are intensively throttled, since there is no throttling opt-out.
    const base::TimeTicks scope_start = base::TimeTicks::Now();
    std::vector<base::TimeTicks> run_times;
    task_runner->PostDelayedTask(
        FROM_HERE, base::BindOnce(&RecordRunTime, &run_times), kShortDelay);
    task_runner->PostDelayedTask(FROM_HERE,
                                 base::BindOnce(&RecordRunTime, &run_times),
                                 kDefaultThrottledWakeUpInterval + kShortDelay);
    task_environment_.FastForwardUntilNoTasksRemain();
    if (IsIntensiveThrottlingExpected()) {
      // Note: Intensive throttling is not applied on the 1st task since there
      // is no recent wake up.
      EXPECT_THAT(run_times,
                  testing::ElementsAre(
                      scope_start + kDefaultThrottledWakeUpInterval,
                      scope_start + kIntensiveThrottledWakeUpInterval));
    } else {
      EXPECT_THAT(run_times,
                  testing::ElementsAre(
                      scope_start + kDefaultThrottledWakeUpInterval,
                      scope_start + 2 * kDefaultThrottledWakeUpInterval));
    }
  }
}

// Verify that tasks run at the same time when a frame switches between being
// same-origin and cross-origin with the main frame.
TEST_P(FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
       FrameChangesOriginType) {
  EXPECT_FALSE(frame_scheduler_->IsCrossOriginToNearestMainFrame());
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      GetTaskRunner();

  // Create a new FrameScheduler that remains cross-origin with the main frame
  // throughout the test.
  std::unique_ptr<FrameSchedulerImpl> cross_origin_frame_scheduler =
      CreateFrameScheduler(page_scheduler_.get(),
                           frame_scheduler_delegate_.get(),
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kSubframe);
  cross_origin_frame_scheduler->SetCrossOriginToNearestMainFrame(true);
  const scoped_refptr<base::SingleThreadTaskRunner> cross_origin_task_runner =
      GetTaskRunner(cross_origin_frame_scheduler.get());

  // Snap the time to a multiple of
  // |kIntensiveThrottledWakeUpInterval|. Otherwise, the time at which
  // tasks can run after throttling is enabled will vary.
  FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);

  // Hide the page and wait until the intensive throttling grace period has
  // elapsed.
  EXPECT_TRUE(page_scheduler_->IsPageVisible());
  page_scheduler_->SetPageVisible(false);
  task_environment_.FastForwardBy(kGracePeriod);

  {
    // Post delayed tasks with short delays to both frames. The
    // main-frame-origin task can run at the desired time, because there is no
    // recent wake up. The cross-origin task must run at an aligned time.
    int counter = 0;
    task_runner->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&IncrementCounter, base::Unretained(&counter)),
        kDefaultThrottledWakeUpInterval);
    int cross_origin_counter = 0;
    cross_origin_task_runner->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&IncrementCounter,
                       base::Unretained(&cross_origin_counter)),
        kDefaultThrottledWakeUpInterval);

    // Make the |frame_scheduler_| cross-origin. Its task must now run at an
    // aligned time.
    frame_scheduler_->SetCrossOriginToNearestMainFrame(true);

    task_environment_.FastForwardBy(kDefaultThrottledWakeUpInterval);
    if (IsIntensiveThrottlingExpected()) {
      EXPECT_EQ(0, counter);
      EXPECT_EQ(0, cross_origin_counter);
    } else {
      EXPECT_EQ(1, counter);
      EXPECT_EQ(1, cross_origin_counter);
    }

    FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);
    EXPECT_EQ(1, counter);
    EXPECT_EQ(1, cross_origin_counter);
  }

  {
    // Post delayed tasks with long delays that aren't aligned with the wake up
    // interval. They should run at aligned times, since they are cross-origin.
    const base::TimeDelta kLongUnalignedDelay =
        5 * kIntensiveThrottledWakeUpInterval + kDefaultThrottledWakeUpInterval;
    int counter = 0;
    task_runner->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&IncrementCounter, base::Unretained(&counter)),
        kLongUnalignedDelay);
    int cross_origin_counter = 0;
    cross_origin_task_runner->PostDelayedTask(
        FROM_HERE,
        base::BindOnce(&IncrementCounter,
                       base::Unretained(&cross_origin_counter)),
        kLongUnalignedDelay);

    // Make the |frame_scheduler_| same-origin. Its task can now run at a
    // 1-second aligned time, since there was no wake up in the last minute.
    frame_scheduler_->SetCrossOriginToNearestMainFrame(false);

    task_environment_.FastForwardBy(kLongUnalignedDelay);
    if (IsIntensiveThrottlingExpected()) {
      EXPECT_EQ(1, counter);
      EXPECT_EQ(0, cross_origin_counter);
    } else {
      EXPECT_EQ(1, counter);
      EXPECT_EQ(1, cross_origin_counter);
    }

    FastForwardToAlignedTime(kIntensiveThrottledWakeUpInterval);
    EXPECT_EQ(1, counter);
    EXPECT_EQ(1, cross_origin_counter);
  }
}

INSTANTIATE_TEST_SUITE_P(
    AllTimerTaskTypes,
    FrameSchedulerImplTestWithIntensiveWakeUpThrottling,
    testing::Values(
        IntensiveWakeUpThrottlingTestParam{
            /* task_type=*/TaskType::kJavascriptTimerDelayedLowNesting,
            /* is_intensive_throttling_expected=*/false},
        IntensiveWakeUpThrottlingTestParam{
            /* task_type=*/TaskType::kJavascriptTimerDelayedHighNesting,
            /* is_intensive_throttling_expected=*/true},
        IntensiveWakeUpThrottlingTestParam{
            /* task_type=*/TaskType::kWebSchedulingPostedTask,
            /* is_intensive_throttling_expected=*/true}),
    [](const testing::TestParamInfo<IntensiveWakeUpThrottlingTestParam>& info) {
      return TaskTypeNames::TaskTypeToString(info.param.task_type);
    });

TEST_F(FrameSchedulerImplTestWithIntensiveWakeUpThrottlingPolicyOverride,
       PolicyForceEnable) {
  SetPolicyOverride(/* enabled = */ true);
  EXPECT_TRUE(IsIntensiveWakeUpThrottlingEnabled());

  // The parameters should be the defaults.
  EXPECT_EQ(
      base::Seconds(kIntensiveWakeUpThrottling_GracePeriodSeconds_Default),
      GetIntensiveWakeUpThrottlingGracePeriod(false));
}

TEST_F(FrameSchedulerImplTestWithIntensiveWakeUpThrottlingPolicyOverride,
       PolicyForceDisable) {
  SetPolicyOverride(/* enabled = */ false);
  EXPECT_FALSE(IsIntensiveWakeUpThrottlingEnabled());
}

class FrameSchedulerImplTestQuickIntensiveWakeUpThrottlingEnabled
    : public FrameSchedulerImplTest {
 public:
  FrameSchedulerImplTestQuickIntensiveWakeUpThrottlingEnabled()
      : FrameSchedulerImplTest(
            {features::kQuickIntensiveWakeUpThrottlingAfterLoading},
            {}) {}
};

TEST_F(FrameSchedulerImplTestQuickIntensiveWakeUpThrottlingEnabled,
       LoadingPageGracePeriod) {
  EXPECT_EQ(
      base::Seconds(kIntensiveWakeUpThrottling_GracePeriodSeconds_Default),
      GetIntensiveWakeUpThrottlingGracePeriod(true));
}

TEST_F(FrameSchedulerImplTestQuickIntensiveWakeUpThrottlingEnabled,
       LoadedPageGracePeriod) {
  EXPECT_EQ(base::Seconds(
                kIntensiveWakeUpThrottling_GracePeriodSecondsLoaded_Default),
            GetIntensiveWakeUpThrottlingGracePeriod(false));
}

// Verify that non-delayed kWebSchedulingPostedTask tasks are not throttled.
TEST_F(FrameSchedulerImplTest, ImmediateWebSchedulingTasksAreNotThrottled) {
  std::vector<base::TimeTicks> run_times;

  // Make sure we are *not* aligned to a 1 second boundary by aligning to a 1
  // second boundary and moving past it a bit. If we were throttled, even
  // non-delayed tasks will need to wait until the next aligned interval to run.
  FastForwardToAlignedTime(base::Seconds(1));
  task_environment_.FastForwardBy(base::Milliseconds(1));

  const base::TimeTicks start = base::TimeTicks::Now();

  // Hide the page to start throttling timers.
  page_scheduler_->SetPageVisible(false);

  std::unique_ptr<WebSchedulingTaskQueue> queue =
      frame_scheduler_->CreateWebSchedulingTaskQueue(
          WebSchedulingQueueType::kTaskQueue,
          WebSchedulingPriority::kUserVisiblePriority);
  // Post a non-delayed task to a web scheduling task queue.
  queue->GetTaskRunner()->PostTask(FROM_HERE,
                                   base::BindOnce(&RecordRunTime, &run_times));

  // Run any ready tasks, which includes our non-delayed non-throttled web
  // scheduling task. If we are throttled, our task will not run.
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(run_times, testing::ElementsAre(start));
}

TEST_F(FrameSchedulerImplTest, PostMessageForwardingHasVeryHighPriority) {
  auto task_queue = GetTaskQueue(TaskType::kInternalPostMessageForwarding);

  EXPECT_EQ(TaskPriority::kVeryHighPriority, task_queue->GetQueuePriority());
}

class FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest
    : public FrameSchedulerImplTest {
 public:
  FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest()
      : FrameSchedulerImplTest({features::kThrottleUnimportantFrameTimers},
                               {}) {}
};

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       VisibleSizeChange_CrossOrigin_ExplicitInit) {
  LazyInitThrottleableTaskQueue();
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetVisibleAreaLarge(true);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetVisibleAreaLarge(false);
  EXPECT_TRUE(IsThrottled());
  frame_scheduler_->SetVisibleAreaLarge(true);
  EXPECT_FALSE(IsThrottled());
}

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       UserActivationChange_CrossOrigin_ExplicitInit) {
  LazyInitThrottleableTaskQueue();
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetVisibleAreaLarge(false);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  frame_scheduler_->SetHadUserActivation(false);
  EXPECT_TRUE(IsThrottled());
  frame_scheduler_->SetHadUserActivation(true);
  EXPECT_FALSE(IsThrottled());
  frame_scheduler_->SetHadUserActivation(false);
  EXPECT_TRUE(IsThrottled());
}

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       UnimportantFrameThrottling) {
  page_scheduler_->SetPageVisible(true);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(
          TaskType::kJavascriptTimerDelayedLowNesting);
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetVisibleAreaLarge(false);
  frame_scheduler_->SetHadUserActivation(false);

  PostTasks_Expect32msAlignment(task_runner);
}

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       HiddenCrossOriginFrameThrottling) {
  page_scheduler_->SetPageVisible(true);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(
          TaskType::kJavascriptTimerDelayedLowNesting);
  frame_scheduler_->SetFrameVisible(false);
  frame_scheduler_->SetVisibleAreaLarge(false);
  frame_scheduler_->SetHadUserActivation(false);

  PostTasks_Expect1sAlignment(task_runner);
}

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       BackgroundPageTimerThrottling) {
  page_scheduler_->SetPageVisible(false);

  frame_scheduler_->SetCrossOriginToNearestMainFrame(false);
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(
          TaskType::kJavascriptTimerDelayedLowNesting);
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetVisibleAreaLarge(true);
  frame_scheduler_->SetHadUserActivation(false);

  PostTasks_Expect1sAlignment(task_runner);
}

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       LargeCrossOriginFrameNoThrottling) {
  page_scheduler_->SetPageVisible(true);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(
          TaskType::kJavascriptTimerDelayedLowNesting);
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetVisibleAreaLarge(true);
  frame_scheduler_->SetHadUserActivation(false);

  PostTasks_ExpectNoAlignment(task_runner);
}

TEST_F(FrameSchedulerImplThrottleUnimportantFrameTimersEnabledTest,
       UserActivatedCrossOriginFrameNoThrottling) {
  page_scheduler_->SetPageVisible(true);
  frame_scheduler_->SetCrossOriginToNearestMainFrame(true);
  const scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      frame_scheduler_->GetTaskRunner(
          TaskType::kJavascriptTimerDelayedLowNesting);
  frame_scheduler_->SetFrameVisible(true);
  frame_scheduler_->SetVisibleAreaLarge(false);
  frame_scheduler_->SetHadUserActivation(true);

  PostTasks_ExpectNoAlignment(task_runner);
}

class FrameSchedulerImplNoThrottlingVisibleAgentTest
    : public FrameSchedulerImplTest,
      // True iff the other frame belongs to a different page.
      public testing::WithParamInterface<bool> {
 public:
  FrameSchedulerImplNoThrottlingVisibleAgentTest()
      : FrameSchedulerImplTest({features::kNoThrottlingVisibleAgent}, {}) {}

  void SetUp() override {
    FrameSchedulerImplTest::SetUp();

    if (IsOtherFrameOnDifferentPage()) {
      other_page_scheduler_ = CreatePageScheduler(nullptr, scheduler_.get(),
                                                  *agent_group_scheduler_);
      EXPECT_TRUE(other_page_scheduler_->IsPageVisible());
    }

    task_runner_ = frame_scheduler_->GetTaskRunner(
        TaskType::kJavascriptTimerDelayedLowNesting);

    // Initial state: `frame_scheduler_` is a visible frame cross-origin to its
    // main frame. Its parent page scheduler is visible. It is not throttled.
    LazyInitThrottleableTaskQueue
```