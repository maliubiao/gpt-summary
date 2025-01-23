Response:
The user wants me to summarize the functionality of the provided C++ code snippet, which is part of a unit test file for the Chromium Blink engine's main thread scheduler. I need to identify the key features being tested in this section and relate them to web technologies (JavaScript, HTML, CSS) where applicable. I also need to provide examples of how these features work, including hypothetical input and output, and potential usage errors.

Here's a breakdown of the code's functionality:

1. **Non-Waking Task Queue:** Tests that tasks posted to the non-waking task runner do not cause unnecessary wake-ups of the scheduler.
2. **Find-in-Page Priority:**  Tests the priority of find-in-page tasks, including how an experiment can lower their priority and how a long-running find-in-page task can temporarily reduce their priority.
3. **Compositor Task Priority:** Tests how compositor task priorities are managed, including boosting the priority of the first compositor task after a delay and how a short delay doesn't trigger this boost.
4. **Task Queue Throttling:** Tests the `ThrottleHandle` mechanism for pausing and resuming task execution in a task queue.
5. **Prioritizing Compositing After Delay:** Tests an experimental feature that boosts compositor task priority after a configurable delay, distinguishing between pre-FCP (First Contentful Paint) and post-FCP scenarios, as well as during compositor gestures.
6. **Threaded Scroll Prevent Rendering Starvation:** Tests a feature that dynamically boosts compositor task priority during threaded scrolling to prevent rendering starvation, considering both a configurable timeout and interaction with render-blocking tasks.
7. **Render-Blocking Task Priority:** Tests the high priority assigned to render-blocking tasks.
8. **Interaction of Render-Blocking and Discrete Input Tasks:** Tests the prioritization of discrete input tasks over render-blocking tasks.
9. **Render-Blocking Starvation Prevention:** Tests a mechanism to prioritize non-render-blocking tasks if render-blocking tasks have been running for too long, but excluding this behavior during compositor gestures.
10. **Detaching a Running Task Queue:** Tests the ability to detach a task queue while a task from that queue is running.
11. **Prioritizing Urgent Message IPC Tasks:** Tests a mechanism to prioritize tasks related to urgent IPC messages.
12. **Interaction of Urgent Messages and Compositor Priority:** Tests how urgent messages affect the priority of compositor tasks.
13. **Deferring Renderer Tasks After Input:** Tests a feature that delays certain types of renderer tasks after user input to improve responsiveness, considering different deferral policies and a timeout mechanism.
14. **Discrete Input Use Case Logic:** Tests the conditions under which the "discrete input response" use case is activated and its interaction with continuous input and frame requests.
15. **Discrete Input Use Case Timeout:** Tests the timeout mechanism for the "discrete input response" use case.
16. **Touchstart Use Case Priority:** Tests the higher priority of the "touchstart" use case over discrete input.
17. **Discrete Input During Continuous Gesture:** Tests the interaction between discrete input and continuous gesture use cases and their timeouts.
18. **Discrete Input and RAIL Mode:** Tests that discrete input does not change the current RAIL mode.
这是对 `blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl_unittest.cc` 文件功能的第 5 部分的总结。这部分主要关注以下几个方面的 **主线程调度器** 功能测试：

**1. 非唤醒任务队列 (NonWakingTaskQueue):**

*   **功能:** 测试 `NonWakingTaskRunner` 的行为。这个任务运行器用于执行延迟任务，但它不应该主动唤醒主线程来执行这些任务，只有当主线程因为其他原因被唤醒时，它才会检查并执行到期的非唤醒任务。
*   **与 Web 功能的关系:**  与那些不需要立即执行，可以稍后执行的后台任务相关，例如预加载资源，或者某些不重要的分析任务。
*   **假设输入与输出:**
    *   **假设输入:**
        1. 向默认任务队列提交一个立即执行的任务 "regular (immediate)"。
        2. 向非唤醒任务队列提交一个延迟 3 秒的任务 "non-waking"。
        3. 向默认任务队列提交一个延迟 5 秒的任务 "regular (delayed)"。
    *   **预期输出:** 所有任务最终都会执行。`non-waking` 任务的执行时间应该晚于初始时间至少 3 秒，并且与 `regular (delayed)` 任务大致同时执行，因为主线程会在 5 秒后被 `regular (delayed)` 任务唤醒，届时也会检查非唤醒队列。关键在于 `non-waking` 任务不会导致额外的提前唤醒。
*   **常见使用错误:**  开发者可能会错误地认为非唤醒任务会像普通延迟任务一样保证在指定时间点被执行，而忽略了主线程是否已经被唤醒。这可能导致某些后台任务的执行时机与预期不符。

**2. Find-in-Page 任务优先级:**

*   **功能:** 测试 Find-in-Page 功能相关任务的优先级管理。测试用例涵盖了 Find-in-Page 任务的默认高优先级，以及通过实验将其优先级降低到 "尽力而为 (BestEffortPriority)" 的情况。同时，还测试了当 Find-in-Page 任务占用过多 CPU 时间后，其优先级会临时降低到普通优先级。
*   **与 Web 功能的关系:**  Find-in-Page 功能是浏览器内置的页面内搜索功能。其性能直接影响用户体验，因此需要合理的优先级策略。
*   **假设输入与输出:**
    *   **假设输入 (默认高优先级):**  交替提交 Find-in-Page 任务 (标记为 "F") 和默认优先级任务 (标记为 "D")。
    *   **预期输出:** Find-in-Page 任务会优先于默认优先级任务执行，例如 "F1 F2 F3 D1 D2 D3"。
    *   **假设输入 (实验性低优先级):** 在实验性配置下，交替提交 Find-in-Page 任务和默认优先级任务。
    *   **预期输出:** 默认优先级任务会优先于 Find-in-Page 任务执行，例如 "D1 D2 D3 F1 F2 F3"。
    *   **假设输入 (长时间运行的 Find-in-Page 任务):**  模拟一个长时间运行的 Find-in-Page 任务，然后提交一些 Find-in-Page 任务和默认优先级任务。
    *   **预期输出:** 在长时间运行的 Find-in-Page 任务之后，其优先级会暂时降低，与默认优先级任务交错执行，例如 "D1 D2 F1 F2 D3 F3"。
*   **常见使用错误:**  如果没有合理的优先级管理，大量的 Find-in-Page 任务可能会阻塞其他重要的渲染或 JavaScript 执行任务，导致页面卡顿。反之，如果 Find-in-Page 任务优先级过低，可能会导致搜索响应缓慢，影响用户体验。

**3. 合成器 (Compositor) 策略:**

*   **功能:** 测试与合成器相关的任务的优先级策略。测试用例涵盖了：
    *   通常情况下，合成器任务保持普通优先级。
    *   在一定延迟后，第一个合成器任务会被提升到非常高的优先级，以加速渲染更新。
    *   短时间的任务不会触发合成器任务的优先级提升。
    *   BeginMainFrame 任务 (CM) 会重置优先级提升状态。
*   **与 Web 功能的关系:** 合成器负责页面的绘制和动画，其性能至关重要。合理的优先级策略可以确保流畅的动画和滚动体验。
*   **假设输入与输出:**
    *   **假设输入 (无延迟):** 提交一些默认优先级任务 (D)、合成器任务 (C) 和一个呈现前任务 (P)。
    *   **预期输出:** 呈现前任务最先执行，然后是默认优先级任务，最后是合成器任务 (P1 D1 C1 D2 C2)。
    *   **假设输入 (有延迟):** 在一段时间延迟后提交一些默认优先级任务和合成器任务。
    *   **预期输出:** 第一个合成器任务会被提升到高优先级，优先执行 (C1 C2 D1 D2)。随后的 BeginMainFrame 任务会重置状态。
*   **常见使用错误:**  不合理的合成器任务优先级可能导致页面渲染延迟或掉帧，影响动画和滚动的流畅性。

**4. 任务队列节流 (Throttle):**

*   **功能:** 测试 `ThrottleHandle` 的功能，用于暂停和恢复任务队列的执行。
*   **与 Web 功能的关系:**  在某些情况下，可能需要临时暂停某些任务队列的执行，例如在执行更高优先级的任务时，或者在进行资源受限的操作时。
*   **假设输入与输出:**
    *   **假设输入:**  获取一个可节流任务队列的 `ThrottleHandle`，然后检查队列是否被节流，释放 `ThrottleHandle`，再次检查队列是否被节流。
    *   **预期输出:**  在获取 `ThrottleHandle` 后，队列应该被节流，释放后应该恢复未节流状态。可以嵌套多个 `ThrottleHandle`，只有当所有 `ThrottleHandle` 都被释放后，队列才会恢复。
*   **常见使用错误:**  忘记释放 `ThrottleHandle` 会导致任务队列永久暂停，造成功能异常。

**总结第 5 部分的功能:**

第 5 部分的测试用例主要关注 `MainThreadSchedulerImpl` 中关于 **任务优先级管理** 和 **任务队列控制** 的功能。它涵盖了非唤醒任务、Find-in-Page 任务、合成器任务的优先级策略，以及任务队列的节流机制。这些测试旨在确保主线程调度器能够合理地分配资源，优先执行关键任务，保证页面的响应性和流畅性。 这些功能都与 Web 浏览器的核心性能息息相关，直接影响用户与网页的交互体验。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第5部分，共6部分，请归纳一下它的功能
```

### 源代码
```cpp
kMicrotaskTime,
            observer.result().front().second);
}

TEST_F(MainThreadSchedulerImplTest, NonWakingTaskQueue) {
  std::vector<std::pair<std::string, base::TimeTicks>> log;
  base::TimeTicks start = scheduler_->NowTicks();

  scheduler_->DefaultTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE,
      base::BindOnce(
          [](std::vector<std::pair<std::string, base::TimeTicks>>* log,
             const base::TickClock* clock) {
            log->emplace_back("regular (immediate)", clock->NowTicks());
          },
          &log, scheduler_->GetTickClock()));
  scheduler_->NonWakingTaskRunner()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(
          [](std::vector<std::pair<std::string, base::TimeTicks>>* log,
             const base::TickClock* clock) {
            log->emplace_back("non-waking", clock->NowTicks());
          },
          &log, scheduler_->GetTickClock()),
      base::Seconds(3));
  scheduler_->DefaultTaskQueue()
      ->GetTaskRunnerWithDefaultTaskType()
      ->PostDelayedTask(
          FROM_HERE,
          base::BindOnce(
              [](std::vector<std::pair<std::string, base::TimeTicks>>* log,
                 const base::TickClock* clock) {
                log->emplace_back("regular (delayed)", clock->NowTicks());
              },
              &log, scheduler_->GetTickClock()),
          base::Seconds(5));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  // Check that the non-waking task runner didn't generate an unnecessary
  // wake-up.
  // Note: the exact order of these tasks is not fixed and depends on the time
  // domain iteration order.
  EXPECT_THAT(
      log, testing::UnorderedElementsAre(
               std::make_pair("regular (immediate)", start),
               std::make_pair("non-waking", start + base::Seconds(5)),
               std::make_pair("regular (delayed)", start + base::Seconds(5))));
}

class BestEffortPriorityForFindInPageExperimentTest
    : public MainThreadSchedulerImplTest {
 public:
  BestEffortPriorityForFindInPageExperimentTest()
      : MainThreadSchedulerImplTest({kBestEffortPriorityForFindInPage}, {}) {}
};

TEST_F(BestEffortPriorityForFindInPageExperimentTest,
       FindInPageTasksAreBestEffortPriorityUnderExperiment) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "F1 D1 F2 D2 F3 D3");
  EnableIdleTasks();
  EXPECT_EQ(scheduler_->find_in_page_priority(),
            TaskPriority::kBestEffortPriority);
  base::RunLoop().RunUntilIdle();
  // Find-in-page tasks have "best-effort" priority, so they will be done after
  // the default tasks (which have normal priority).
  EXPECT_THAT(run_order,
              testing::ElementsAre("D1", "D2", "D3", "F1", "F2", "F3"));
}

TEST_F(MainThreadSchedulerImplTest, FindInPageTasksAreVeryHighPriority) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 D2 D3 F1 F2 F3");
  EnableIdleTasks();
  EXPECT_EQ(
      scheduler_->find_in_page_priority(),
      FindInPageBudgetPoolController::kFindInPageBudgetNotExhaustedPriority);
  base::RunLoop().RunUntilIdle();
  // Find-in-page tasks have very high task priority, so we will do them before
  // the default tasks.
  EXPECT_THAT(run_order,
              testing::ElementsAre("F1", "F2", "F3", "D1", "D2", "D3"));
}

TEST_F(MainThreadSchedulerImplTest, FindInPageTasksChangeToNormalPriority) {
  EXPECT_EQ(
      scheduler_->find_in_page_priority(),
      FindInPageBudgetPoolController::kFindInPageBudgetNotExhaustedPriority);
  EnableIdleTasks();
  // Simulate a really long find-in-page task that takes 30% of CPU time
  // (300ms out of 1000 ms).
  base::TimeTicks task_start_time = Now();
  base::TimeTicks task_end_time = task_start_time + base::Milliseconds(300);
  FakeTask fake_task;
  fake_task.set_enqueue_order(
      base::sequence_manager::EnqueueOrder::FromIntForTesting(42));
  FakeTaskTiming task_timing(task_start_time, task_end_time);
  scheduler_->OnTaskStarted(find_in_page_task_queue(), fake_task, task_timing);
  AdvanceMockTickClockTo(task_start_time + base::Milliseconds(1000));
  scheduler_->OnTaskCompleted(find_in_page_task_queue()->AsWeakPtr(), fake_task,
                              &task_timing, nullptr);

  // Now the find-in-page tasks have normal priority (same priority as default
  // tasks, so we will do them in order).
  EXPECT_EQ(scheduler_->find_in_page_priority(),
            FindInPageBudgetPoolController::kFindInPageBudgetExhaustedPriority);
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 D2 F1 F2 D3 F3");

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("D1", "D2", "F1", "F2", "D3", "F3"));
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicy_CompositorStaysAtNormalPriority) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2 P1");

  DoMainFrame();
  EnableIdleTasks();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("P1", "D1", "C1", "D2", "C2", "I1"));
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicy_FirstCompositorTaskSetToVeryHighPriority) {
  AdvanceTimeWithTask(kDelayForHighPriorityRendering);

  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 C1 D2 C2 P1");

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("P1", "C1", "C2", "D1", "D2"));
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());

  // The next compositor task is the BeginMainFrame, after which the priority is
  // returned to normal.
  PostTestTasks(&run_order, "CM");
  base::RunLoop().RunUntilIdle();

  run_order.clear();
  PostTestTasks(&run_order, "C1 D1 D2 C2 P1");

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("P1", "C1", "D1", "D2", "C2"));
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicy_FirstCompositorTaskStaysAtNormalPriority) {
  // A short task should not cause compositor tasks to be prioritized.
  AdvanceTimeWithTask(base::Milliseconds(5));

  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2 P1");

  EnableIdleTasks();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("P1", "D1", "C1", "D2", "C2", "I1"));
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest, ThrottleHandleThrottlesQueue) {
  EXPECT_FALSE(throttleable_task_queue()->IsThrottled());
  {
    MainThreadTaskQueue::ThrottleHandle handle =
        throttleable_task_queue()->Throttle();
    EXPECT_TRUE(throttleable_task_queue()->IsThrottled());
    {
      MainThreadTaskQueue::ThrottleHandle handle_2 =
          throttleable_task_queue()->Throttle();
      EXPECT_TRUE(throttleable_task_queue()->IsThrottled());
    }
    EXPECT_TRUE(throttleable_task_queue()->IsThrottled());
  }
  EXPECT_FALSE(throttleable_task_queue()->IsThrottled());
}

class PrioritizeCompositingAfterDelayTest : public MainThreadSchedulerImplTest {
 public:
  PrioritizeCompositingAfterDelayTest()
      : MainThreadSchedulerImplTest({::base::test::FeatureRefAndParams(
            kPrioritizeCompositingAfterDelayTrials,
            {{"PreFCP", "120"}, {"PostFCP", "80"}})}) {}
};

TEST_F(PrioritizeCompositingAfterDelayTest, PreFCP) {
  scheduler_->SetCurrentUseCase(UseCase::kEarlyLoading);
  AdvanceTimeWithTask(base::Milliseconds(119));
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 CM1 P1");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("P1", "D1", "CM1"));

  AdvanceTimeWithTask(base::Milliseconds(121));
  run_order.clear();
  PostTestTasks(&run_order, "D1 CM1 P1");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("P1", "CM1", "D1"));
}

TEST_F(PrioritizeCompositingAfterDelayTest, PostFCP) {
  scheduler_->SetCurrentUseCase(UseCase::kNone);
  AdvanceTimeWithTask(base::Milliseconds(79));
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 CM1 P1");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("P1", "D1", "CM1"));

  AdvanceTimeWithTask(base::Milliseconds(81));
  run_order.clear();
  PostTestTasks(&run_order, "D1 CM1 P1");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("P1", "CM1", "D1"));
}

TEST_F(PrioritizeCompositingAfterDelayTest, DuringCompositorGesture) {
  scheduler_->SetCurrentUseCase(UseCase::kCompositorGesture);
  AdvanceTimeWithTask(base::Milliseconds(99));
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 CM1 P1");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("P1", "D1", "CM1"));

  AdvanceTimeWithTask(base::Milliseconds(101));
  run_order.clear();
  PostTestTasks(&run_order, "P1 D1 CM1");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("P1", "CM1", "D1"));
}

class ThreadedScrollPreventRenderingStarvationTest
    : public MainThreadSchedulerImplTest,
      public ::testing::WithParamInterface<int> {
 public:
  ThreadedScrollPreventRenderingStarvationTest() {
    feature_list_.Reset();
    feature_list_.InitWithFeaturesAndParameters(
        {{features::kThreadedScrollPreventRenderingStarvation,
          base::FieldTrialParams(
              {{"threshold_ms", base::NumberToString(GetParam())}})}},
        {});
  }
};

TEST_P(ThreadedScrollPreventRenderingStarvationTest, CompositorPriority) {
  SimulateEnteringCompositorGestureUseCase();

  // Compositor task queues should initially have low priority.
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 C1 D2 C2");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "D2", "C1", "C2"));
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());

  // The priority should remain low up to the timeout.
  AdvanceTimeWithTask(base::Milliseconds(GetParam() - 1));
  // The policy has a max duration, so simulate a longer scroll (multiple
  // updates) with another scroll start.
  SimulateEnteringCompositorGestureUseCase();

  run_order.clear();
  PostTestTasks(&run_order, "D1 D2 C1 C2");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "D2", "C1", "C2"));
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());

  // Reaching the configurable delay should boost the compositor TQ priority
  // until the next frame.
  run_order.clear();
  AdvanceTimeWithTask(base::Milliseconds(1));
  PostTestTasks(&run_order, "D1 C1 D2 C2");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "D1", "D2"));
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());

  // The next BeginMainFrame (CM1) should reset the frame delay counter so that
  // the compositor task queues drop back down to low priority.
  PostTestTasks(&run_order, "CM1");
  base::RunLoop().RunUntilIdle();

  run_order.clear();
  PostTestTasks(&run_order, "D1 C1 D2 C2");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "D2", "C1", "C2"));
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());
}

TEST_P(ThreadedScrollPreventRenderingStarvationTest,
       CompositorPriorityWithRenderBlockingTaskStarvation) {
  // The starved-by-render-blocking-tasks bit isn't cleared when we change use
  // cases, so start out in scrolling use case.
  SimulateEnteringCompositorGestureUseCase();
  SimulateRenderBlockingTask(
      MainThreadSchedulerImpl::kRenderBlockingStarvationThreshold);

  // The use case will have been cleared because the policy timeout will have
  // been reached.
  SimulateEnteringCompositorGestureUseCase();

  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 C1 D2 R1 C2");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());

  if (base::Milliseconds(GetParam()) >
      MainThreadSchedulerImpl::kRenderBlockingStarvationThreshold) {
    // No anti-starvation should kick in.
    EXPECT_THAT(run_order, testing::ElementsAre("R1", "D1", "D2", "C1", "C2"));

    // Advance far enough to trigger the render-blocking anti-starvation.
    run_order.clear();
    SimulateRenderBlockingTask(
        base::Milliseconds(GetParam()) -
        MainThreadSchedulerImpl::kRenderBlockingStarvationThreshold);
    SimulateEnteringCompositorGestureUseCase();

    PostTestTasks(&run_order, "D1 C1 D2 R1 C2");
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());
  }

  EXPECT_THAT(run_order, testing::ElementsAre("C1", "R1", "C2", "D1", "D2"));
}

INSTANTIATE_TEST_SUITE_P(,
                         ThreadedScrollPreventRenderingStarvationTest,
                         testing::Values(100, 250, 500, 600));

TEST_F(MainThreadSchedulerImplTest, RenderBlockingTaskPriority) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 CM1 R1 R2 R3");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("R1", "R2", "R3", "D1", "CM1"));
}

TEST_F(MainThreadSchedulerImplTest, RenderBlockingAndDiscreteInput) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 CM1 R1 PD1 R2 R3");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("PD1", "CM1", "R1", "R2", "R3", "D1"));
}

TEST_F(MainThreadSchedulerImplTest, RenderBlockingStarvationPrevention) {
  SimulateRenderBlockingTask(
      MainThreadSchedulerImpl::kRenderBlockingStarvationThreshold);
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 R1 CM1 R2 R3");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("R1", "CM1", "R2", "R3", "D1"));
}

TEST_F(MainThreadSchedulerImplTest,
       RenderBlockingStarvationPreventionDoesNotAffectCompositorGestures) {
  SimulateEnteringCompositorGestureUseCase();
  SimulateRenderBlockingTask(
      MainThreadSchedulerImpl::kRenderBlockingStarvationThreshold);

  // The use case will have been cleared because the policy timeout will have
  // been reached.
  SimulateEnteringCompositorGestureUseCase();

  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 R1 CM1 R2 R3");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());
  EXPECT_THAT(run_order, testing::ElementsAre("R1", "R2", "R3", "D1", "CM1"));
}

TEST_F(MainThreadSchedulerImplTest, DetachRunningTaskQueue) {
  scoped_refptr<MainThreadTaskQueue> queue =
      scheduler_->NewThrottleableTaskQueueForTest(nullptr);
  base::WeakPtr<MainThreadTaskQueue> weak_queue = queue->AsWeakPtr();
  scoped_refptr<base::SingleThreadTaskRunner> task_runner =
      queue->GetTaskRunnerWithDefaultTaskType();
  queue = nullptr;

  task_runner->PostTask(FROM_HERE, base::BindLambdaForTesting([&]() {
                          weak_queue->DetachTaskQueue();
                        }));

  EXPECT_TRUE(weak_queue);
  // `queue` is deleted while running its last task, but sequence manager should
  // keep the underlying queue alive while its needed, so this shouldn't crash.
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(weak_queue);
}

TEST_F(MainThreadSchedulerImplTest, PrioritizeUrgentMessageIPCTasks) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "T1 D1 T2");
  // Default TQ tasks after this are prioritized until the there are no more
  // pending urgent messages, which happens in the "D5" task.
  default_task_runner_->PostTask(FROM_HERE, base::BindLambdaForTesting([&]() {
                                   run_order.push_back("D2a");
                                   scheduler_->OnUrgentMessageReceived();
                                 }));
  default_task_runner_->PostTask(FROM_HERE, base::BindLambdaForTesting([&]() {
                                   run_order.push_back("D2b");
                                   scheduler_->OnUrgentMessageReceived();
                                 }));
  default_task_runner_->PostTask(FROM_HERE, base::BindLambdaForTesting([&]() {
                                   run_order.push_back("D2c");
                                   scheduler_->OnUrgentMessageProcessed();
                                 }));
  PostTestTasks(&run_order, "T3 T4 T5 D3 D4");
  default_task_runner_->PostTask(FROM_HERE, base::BindLambdaForTesting([&]() {
                                   run_order.push_back("D5");
                                   scheduler_->OnUrgentMessageProcessed();
                                 }));
  PostTestTasks(&run_order, "T6 D6");

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("T1", "D1", "T2", "D2a", "D2b", "D2c", "D3",
                                   "D4", "D5", "T3", "T4", "T5", "T6", "D6"));
}

TEST_F(MainThreadSchedulerImplTest, UrgentMessageAndCompositorPriority) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "T1 T2 D1 PD1 C1");
  // Simulate receiving an urgent message while running a BeginMainFrame to make
  // sure the policy reflects both.
  compositor_task_runner_->PostTask(FROM_HERE,
                                    base::BindLambdaForTesting([&]() {
                                      scheduler_->OnUrgentMessageReceived();
                                      DoMainFrame();
                                      run_order.push_back("CM");
                                    }));
  PostTestTasks(&run_order, "C2 C3 D2");

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("PD1", "C1", "CM", "D1", "D2",
                                              "T1", "T2", "C2", "C3"));
}

class DeferRendererTasksAfterInputTest
    : public MainThreadSchedulerImplTest,
      public ::testing::WithParamInterface<features::TaskDeferralPolicy>,
      public WebSchedulingTestHelper::Delegate {
 public:
  static std::string GetFieldTrialParamName(
      features::TaskDeferralPolicy policy) {
    switch (policy) {
      case features::TaskDeferralPolicy::kMinimalTypes:
        return "minimal-types";
      case features::TaskDeferralPolicy::kNonUserBlockingDeferrableTypes:
        return "non-user-blocking-deferrable-types";
      case features::TaskDeferralPolicy::kNonUserBlockingTypes:
        return "non-user-blocking-types";
      case features::TaskDeferralPolicy::kAllDeferrableTypes:
        return "all-deferrable-types";
      case features::TaskDeferralPolicy::kAllTypes:
        return "all-types";
    }
  }

  DeferRendererTasksAfterInputTest() {
    feature_list_.Reset();
    feature_list_.InitWithFeaturesAndParameters(
        {{features::kDeferRendererTasksAfterInput,
          base::FieldTrialParams(
              {{"policy", GetFieldTrialParamName(GetParam())}})}},
        {});
  }

  void SetUp() override {
    MainThreadSchedulerImplTest::SetUp();
    web_scheduling_test_helper_ =
        std::make_unique<WebSchedulingTestHelper>(*this);
  }

  void TearDown() override {
    MainThreadSchedulerImplTest::TearDown();
    web_scheduling_test_helper_.reset();
  }

  FrameOrWorkerScheduler& GetFrameOrWorkerScheduler() override {
    return *main_frame_scheduler_.get();
  }

  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunner(
      TaskType task_type) override {
    return main_frame_scheduler_->GetTaskRunner(task_type);
  }

 protected:
  using TestTaskSpecEntry = WebSchedulingTestHelper::TestTaskSpecEntry;
  using WebSchedulingParams = WebSchedulingTestHelper::WebSchedulingParams;

  std::unique_ptr<WebSchedulingTestHelper> web_scheduling_test_helper_;
};

TEST_P(DeferRendererTasksAfterInputTest, TaskDeferral) {
  Vector<String> run_order;

  // Simulate a long idle period starting.
  scheduler_->BeginFrameNotExpectedSoon();

  // Post potentially deferrable tasks.
  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "F1", .type_info = TaskType::kDOMManipulation},
      {.descriptor = "F2", .type_info = TaskType::kPostedMessage},
      {.descriptor = "F3", .type_info = TaskType::kInternalMediaRealTime},
      {.descriptor = "F4", .type_info = TaskType::kJavascriptTimerImmediate},
      {.descriptor = "BG1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kBackgroundPriority})},
      {.descriptor = "UV1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UB1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  // The input task will run first and change the UseCase.
  PostTestTasks(&run_order, "PD1 D1 I1");

  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kDiscreteInputResponse);

  // The main frame task will reset the UseCase and unblock the deferred queues.
  PostTestTasks(&run_order, "CM1");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);

  switch (GetParam()) {
    case features::TaskDeferralPolicy::kMinimalTypes:
      EXPECT_THAT(run_order,
                  testing::ElementsAre("PD1", "UB1", "F2", "F3", "F4", "UV1",
                                       "D1", "CM1", "F1", "BG1", "I1"));
      break;
    case features::TaskDeferralPolicy::kNonUserBlockingDeferrableTypes:
      EXPECT_THAT(run_order,
                  testing::ElementsAre("PD1", "UB1", "F3", "D1", "CM1", "F1",
                                       "F2", "F4", "UV1", "BG1", "I1"));
      break;
    case features::TaskDeferralPolicy::kAllDeferrableTypes:
      EXPECT_THAT(run_order,
                  testing::ElementsAre("PD1", "F3", "D1", "CM1", "UB1", "F1",
                                       "F2", "F4", "UV1", "BG1", "I1"));
      break;
    case features::TaskDeferralPolicy::kNonUserBlockingTypes:
      EXPECT_THAT(run_order,
                  testing::ElementsAre("PD1", "UB1", "D1", "CM1", "F1", "F2",
                                       "F3", "F4", "UV1", "BG1", "I1"));
      break;
    case features::TaskDeferralPolicy::kAllTypes:
      EXPECT_THAT(run_order,
                  testing::ElementsAre("PD1", "D1", "CM1", "UB1", "F1", "F2",
                                       "F3", "F4", "UV1", "BG1", "I1"));
      break;
  }
}

TEST_P(DeferRendererTasksAfterInputTest, DynamicPriorityTaskDeferral) {
  Vector<String> run_order;

  PostTestTasks(&run_order, "PD1");
  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kDiscreteInputResponse);
  EXPECT_THAT(run_order, testing::ElementsAre("PD1"));

  // Post potentially deferrable tasks.
  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "UV1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserVisiblePriority})},
      {.descriptor = "UB1",
       .type_info = WebSchedulingParams(
           {.queue_type = WebSchedulingQueueType::kTaskQueue,
            .priority = WebSchedulingPriority::kUserBlockingPriority})}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  web_scheduling_test_helper_
      ->GetWebSchedulingTaskQueue(WebSchedulingQueueType::kTaskQueue,
                                  WebSchedulingPriority::kUserBlockingPriority)
      ->SetPriority(WebSchedulingPriority::kBackgroundPriority);
  web_scheduling_test_helper_
      ->GetWebSchedulingTaskQueue(WebSchedulingQueueType::kTaskQueue,
                                  WebSchedulingPriority::kUserVisiblePriority)
      ->SetPriority(WebSchedulingPriority::kUserBlockingPriority);

  // Run whatever isn't deferrable.
  base::RunLoop().RunUntilIdle();

  // The main frame task will reset the UseCase and unblock the deferred queues.
  PostTestTasks(&run_order, "CM1");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);

  // UB1, which is now background priority, should be deferred by every policy.
  // UV1, which is now user-blocking priority, will should only be deferred for
  // the all-types and all-deferrable policies.
  switch (GetParam()) {
    case features::TaskDeferralPolicy::kMinimalTypes:
    case features::TaskDeferralPolicy::kNonUserBlockingDeferrableTypes:
    case features::TaskDeferralPolicy::kNonUserBlockingTypes:
      EXPECT_THAT(run_order, testing::ElementsAre("PD1", "UV1", "CM1", "UB1"));
      break;
    case features::TaskDeferralPolicy::kAllDeferrableTypes:
    case features::TaskDeferralPolicy::kAllTypes:
      EXPECT_THAT(run_order, testing::ElementsAre("PD1", "CM1", "UV1", "UB1"));
      break;
  }
}

TEST_P(DeferRendererTasksAfterInputTest, TaskDeferralTimeout) {
  Vector<String> run_order;

  Vector<TestTaskSpecEntry> test_spec = {
      {.descriptor = "F1", .type_info = TaskType::kDOMManipulation}};
  web_scheduling_test_helper_->PostTestTasks(&run_order, test_spec);

  PostTestTasks(&run_order, "PD1 D1");
  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kDiscreteInputResponse);
  EXPECT_THAT(run_order, testing::ElementsAre("PD1", "D1"));

  // Simulate reaching the discrete input deferral timeout.
  run_order.clear();
  test_task_runner_->FastForwardBy(base::Milliseconds(50));
  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);
  EXPECT_THAT(run_order, testing::ElementsAre("F1"));
}

TEST_P(DeferRendererTasksAfterInputTest,
       DiscreteInputUseCaseDependsOnFrameRequested) {
  input_task_runner_->PostTask(
      FROM_HERE, base::BindLambdaForTesting([&]() {
        scheduler_->DidHandleInputEventOnMainThread(
            FakeInputEvent(WebInputEvent::Type::kMouseUp),
            WebInputEventResult::kHandledApplication,
            /*frame_requested=*/false);
      }));
  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);

  input_task_runner_->PostTask(
      FROM_HERE, base::BindLambdaForTesting([&]() {
        scheduler_->DidHandleInputEventOnMainThread(
            FakeInputEvent(WebInputEvent::Type::kMouseUp),
            WebInputEventResult::kHandledApplication,
            /*frame_requested=*/true);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kDiscreteInputResponse);
}

TEST_P(DeferRendererTasksAfterInputTest,
       DiscreteInputUseCaseIgnoresContinuous) {
  input_task_runner_->PostTask(
      FROM_HERE, base::BindLambdaForTesting([&]() {
        scheduler_->DidHandleInputEventOnMainThread(
            FakeInputEvent(WebInputEvent::Type::kMouseMove),
            WebInputEventResult::kHandledApplication,
            /*frame_requested=*/false);
      }));
  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);
}

TEST_P(DeferRendererTasksAfterInputTest, UseCaseTimeout) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "PD1");
  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kDiscreteInputResponse);

  test_task_runner_->AdvanceMockTickClock(
      UserModel::kDiscreteInputResponseDeadline);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);
}

TEST_P(DeferRendererTasksAfterInputTest, TouchStartAndDiscreteInput) {
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  EXPECT_EQ(ForceUpdatePolicyAndGetCurrentUseCase(), UseCase::kTouchstart);

  Vector<String> run_order;
  PostTestTasks(&run_order, "PD1");
  base::RunLoop().RunUntilIdle();
  // The touchstart use case should take precedent.
  EXPECT_EQ(CurrentUseCase(), UseCase::kTouchstart);
  EXPECT_THAT(run_order, testing::ElementsAre("PD1"));
}

TEST_P(DeferRendererTasksAfterInputTest, DiscreteInputDuringContinuousGesture) {
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kMouseDown,
                     blink::WebInputEvent::kLeftButtonDown),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kMouseMove,
                     blink::WebInputEvent::kLeftButtonDown),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kMainThreadCustomInputHandling);

  // Actually handling the mousedown event should transition to discrete input.
  input_task_runner_->PostTask(
      FROM_HERE, base::BindLambdaForTesting([&]() {
        scheduler_->DidHandleInputEventOnMainThread(
            FakeInputEvent(WebInputEvent::Type::kMouseDown,
                           blink::WebInputEvent::kLeftButtonDown),
            WebInputEventResult::kHandledApplication,
            /*frame_requested=*/true);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kDiscreteInputResponse);

  // Handling the mousemove shouldn't change anything. Note: This is necessary
  // to bring the pending event count to 0 so that the use case gets cleared
  // after the second timeout.
  input_task_runner_->PostTask(
      FROM_HERE, base::BindLambdaForTesting([&]() {
        scheduler_->DidHandleInputEventOnMainThread(
            FakeInputEvent(WebInputEvent::Type::kMouseMove,
                           blink::WebInputEvent::kLeftButtonDown),
            WebInputEventResult::kHandledApplication,
            /*frame_requested=*/true);
      }));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kDiscreteInputResponse);

  // Fast forwarding past the discrete input policy timeout should then fall
  // back to the previous policy, since that has a longer timeout.
  EXPECT_LT(UserModel::kDiscreteInputResponseDeadline,
            UserModel::kGestureEstimationLimit);
  test_task_runner_->AdvanceMockTickClock(
      UserModel::kDiscreteInputResponseDeadline);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kMainThreadCustomInputHandling);

  // Fast forwarding past the continuous gesture timeout should then reset the
  // use case.
  test_task_runner_->AdvanceMockTickClock(
      UserModel::kGestureEstimationLimit -
      UserModel::kDiscreteInputResponseDeadline);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kNone);
}

TEST_P(DeferRendererTasksAfterInputTest, DiscreteInputDoesNotChangeRAILMode) {
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameContentfulPaint)
      .WillByDefault(Return(true));
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameMeaningfulPaint)
      .WillByDefault(Return(true));
  ON_CALL(*page_scheduler_, IsMainFrameLoading).WillByDefault(Return(true));
  scheduler_->DidStartProvisionalLoad(true);
  EXPECT_EQ(ForceUpdatePolicyAndGetCurrentUseCase(), UseCase::kEarlyLoading);
  EXPECT_EQ(GetRAILMode(), RAILMode::kLoad);

  Vector<String> run_order;
  PostTestTasks(&run_order, "PD1");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kDiscreteInputResponse);
  EXPECT_EQ(GetRAILMode(), RAILMode::kLoad);

  PostTestTasks(&run_order, "CM1");
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(CurrentUseCase(), UseCase::kEarlyLoading);
  EXPECT_EQ(GetRAILMode(), RAILMode::kLoad);
}

INSTANTIATE_TEST_SUITE_P(
    ,
    DeferRendererTasksAfterInputTest,
    testing::Values(
        features::TaskDeferralPolicy::kMinimalTypes,
        features::TaskDeferralPolicy::kNonUserBlockingDeferrableTypes,
        features::TaskDeferralPolicy::kNonUserBlockingTypes,
        features::TaskDeferralPolicy::kAllDeferrableTypes,
        features::TaskDeferralPolicy::kAllTypes),
    [](const testing::TestParamInfo<features::TaskDeferralPolicy>& info) {
      switch (info.param) {
        case features::TaskDeferralPolicy::kMinimalTypes:
          return "MinimalTypes";
        case features::TaskDeferralPolicy::kNonUserBlockingDeferrableTypes:
          return "NonUserBlockingDeferrableTypes";
        case features::TaskDeferralPolicy::kNonUserBlockingTypes:
          return "NonUserBlockingTypes";
        case features::TaskDeferralPolicy::kAllDeferrableTypes:
          return "AllDeferrableTypes";
        case features::TaskDeferralPolicy::kAllTypes:
          return "AllTypes";
      }
    });

class DiscreteInputMatchesResponsivenessMetricsTest
    : public MainThreadSchedulerImplTest,
      public ::testing::WithParamInterface<bool> {
```