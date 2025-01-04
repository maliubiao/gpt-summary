Response: The user wants a summary of the functionality of the provided C++ unittest file for the Chromium Blink engine.
I need to analyze the test cases and understand what aspects of the `MainThreadSchedulerImpl` class are being tested. Specifically, I need to identify:

1. **Core functionalities tested:** What scheduling features are being verified?
2. **Relationship to web technologies:**  Are there tests related to how JavaScript, HTML, or CSS are handled by the scheduler?
3. **Logic and assumptions:** Can I infer any logic or rules about the scheduler's behavior from the test cases?
4. **Potential user/programmer errors:** Do any tests highlight common mistakes in using the scheduler?
5. **Overall purpose:** What is the overarching goal of this set of tests?

Based on the test names and the code within them, I can see tests for:

*   Task prioritization (default, find-in-page, compositor, render-blocking, urgent messages)
*   Task queue management (non-waking, throttleable)
*   Compositor task scheduling policies (prioritization delays)
*   Input event handling and use case management (discrete input, continuous gestures, touchstart)
*   Task deferral after input
*   Render blocking starvation prevention

I should organize the summary around these key areas.
这是对 `blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl_unittest.cc` 文件功能的总结，延续了前两个部分的讨论。本部分主要集中在以下功能测试：

**核心功能测试:**

*   **非唤醒任务队列 (NonWakingTaskQueue):** 测试了可以延迟执行，且不会主动唤醒主线程的任务队列。这种队列用于执行一些非关键性的后台任务，避免不必要的唤醒导致性能损耗。
    *   **假设输入:**  向默认任务队列和非唤醒任务队列分别投递任务，其中非唤醒任务设置了 3 秒的延迟，默认延迟任务设置了 5 秒的延迟。
    *   **预期输出:** 默认立即执行的任务会立即执行，非唤醒任务和默认延迟任务会在 5 秒后一起执行，但非唤醒任务的执行不会提前唤醒线程。
*   **查找页面任务优先级 (Find-In-Page Tasks Priority):** 测试了查找页面功能相关任务的优先级管理。在实验特性开启时，查找页面任务的优先级为最低优先级 (BestEffortPriority)，而在实验特性未开启时，优先级非常高 (VeryHighPriority)。当查找页面任务占用过多预算时，其优先级会降为普通优先级。
    *   **与 HTML 相关性:** 查找页面功能直接作用于渲染后的 HTML 内容。这些测试确保了查找功能相关的任务能够按照预期优先级执行，不会阻塞用户交互或其他重要任务。
    *   **假设输入 (BestEffortPriority 实验开启):** 同时提交默认优先级任务（D1, D2, D3）和查找页面任务（F1, F2, F3）。
    *   **预期输出 (BestEffortPriority 实验开启):** 默认优先级任务先执行完毕，然后执行查找页面任务 (D1, D2, D3, F1, F2, F3)。
    *   **假设输入 (BestEffortPriority 实验未开启):** 同时提交默认优先级任务（D1, D2, D3）和查找页面任务（F1, F2, F3）。
    *   **预期输出 (BestEffortPriority 实验未开启):** 查找页面任务优先执行完毕，然后执行默认优先级任务 (F1, F2, F3, D1, D2, D3)。
    *   **假设输入 (查找页面任务占用过多预算):** 模拟一个长时间运行的查找页面任务消耗了大量 CPU 时间。之后提交默认优先级任务和查找页面任务。
    *   **预期输出 (查找页面任务占用过多预算):** 查找页面任务的优先级降为普通，与默认优先级任务交替执行。
*   **合成器策略 (Compositor Policy):** 测试了合成器相关任务的优先级策略。首次合成器任务会被提升到很高优先级以保证渲染的及时性。
    *   **与 CSS 相关性:** 合成器负责将 HTML 和 CSS 渲染成最终的像素。这些测试确保了合成器任务能够及时执行，避免页面卡顿。
    *   **假设输入 (首次合成器任务):**  在一段时间延迟后提交合成器任务 (C1, C2) 和默认优先级任务 (D1, D2)。
    *   **预期输出 (首次合成器任务):** 合成器任务优先执行 (C1, C2, D1, D2)。
    *   **假设输入 (后续合成器任务):**  在执行过一次 BeginMainFrame 后，再次提交合成器任务和默认优先级任务。
    *   **预期输出 (后续合成器任务):** 合成器任务的优先级恢复正常，与默认优先级任务交替执行。
*   **节流句柄 (ThrottleHandle):** 测试了如何使用节流句柄来暂停和恢复任务队列的执行。
    *   **编程常见的使用错误:**  不正确地管理 `ThrottleHandle` 的生命周期可能导致任务队列意外地被暂停或无法恢复。例如，如果 `ThrottleHandle` 在其作用域结束前就被销毁，任务队列可能无法恢复执行。
*   **延迟后提升合成优先级 (PrioritizeCompositingAfterDelay):** 测试了在特定延迟后，合成器任务的优先级会被提升的机制，用于优化页面加载和用户交互体验。
*   **线程滚动防止渲染饥饿 (ThreadedScrollPreventRenderingStarvation):** 测试了在用户进行线程滚动操作时，为了防止渲染任务被阻塞，会提升合成器任务优先级的机制。
*   **渲染阻塞任务优先级 (RenderBlockingTaskPriority):** 测试了渲染阻塞任务的优先级高于普通任务，确保关键渲染流程的执行。
    *   **与 HTML, CSS 相关性:** 渲染阻塞任务通常与解析 HTML 和 CSS，构建渲染树等关键渲染流程相关。
*   **渲染阻塞和离散输入 (RenderBlockingAndDiscreteInput):** 测试了渲染阻塞任务和离散输入事件处理任务的优先级关系。离散输入事件处理任务通常具有更高的优先级。
    *   **与 JavaScript, HTML 相关性:** 离散输入事件 (例如点击) 触发的 JavaScript 代码执行可能会修改 DOM 结构，需要及时渲染。
*   **渲染阻塞饥饿预防 (RenderBlockingStarvationPrevention):** 测试了当渲染阻塞任务运行时间过长时，为了避免其他任务被饿死，会暂时提升其他任务的优先级。
*   **分离运行中的任务队列 (DetachRunningTaskQueue):** 测试了在任务队列正在执行最后一个任务时，将其分离的功能，防止程序崩溃。
*   **优先处理紧急消息 IPC 任务 (PrioritizeUrgentMessageIPCTasks):** 测试了当接收到紧急消息时，会优先执行与该消息相关的任务。
*   **紧急消息和合成器优先级 (UrgentMessageAndCompositorPriority):** 测试了当同时存在紧急消息和合成器任务时，优先级的处理策略。
*   **输入后延迟渲染器任务 (DeferRendererTasksAfterInput):** 测试了在用户输入事件发生后，可以延迟执行某些类型的渲染器任务，以优化用户响应速度。
    *   **与 JavaScript, HTML, CSS 相关性:**  涉及 DOM 操作、样式计算、布局等任务可能会被延迟。
    *   **假设输入:** 提交不同类型的渲染器任务，然后模拟用户输入事件。
    *   **预期输出:** 某些类型的任务会被延迟执行，直到下一个主帧开始。
    *   **用户或编程常见的使用错误:**  过度依赖于输入事件后立即执行的渲染操作，可能会因为任务被延迟而导致 UI 上的不一致性或延迟更新。
*   **动态优先级任务延迟 (DynamicPriorityTaskDeferral):**  测试了当任务的优先级在运行时发生变化时，任务延迟策略如何应用。
*   **任务延迟超时 (TaskDeferralTimeout):** 测试了任务延迟机制的超时处理，即使没有新的主帧开始，被延迟的任务也会在超时后执行。
*   **离散输入 UseCase 取决于是否请求帧 (DiscreteInputUseCaseDependsOnFrameRequested):** 测试了离散输入事件是否会触发 `DiscreteInputResponse` UseCase 取决于事件处理是否请求了新的渲染帧。
*   **离散输入 UseCase 忽略连续输入 (DiscreteInputUseCaseIgnoresContinuous):** 测试了连续输入事件不会触发 `DiscreteInputResponse` UseCase。
*   **UseCase 超时 (UseCaseTimeout):** 测试了各种 UseCase 的超时机制，当超过一定时间没有新的相关事件发生时，UseCase 会被重置。
*   **TouchStart 和离散输入 (TouchStartAndDiscreteInput):** 测试了 `touchstart` 事件的 UseCase 优先级高于离散输入事件。
*   **连续手势期间的离散输入 (DiscreteInputDuringContinuousGesture):** 测试了在连续手势操作期间，如果发生离散输入事件，UseCase 的切换和超时处理。
*   **离散输入不会改变 RAIL 模式 (DiscreteInputDoesNotChangeRAILMode):** 测试了离散输入事件不会影响当前的 RAIL (响应、动画、空闲、加载) 模式。
*   **离散输入匹配响应指标 (DiscreteInputMatchesResponsivenessMetrics):**  测试了一个实验特性，该特性决定某些类型的输入事件是否应该被视为“离散输入”以用于响应性指标的计算。

**总结:**

这部分测试主要关注 `MainThreadSchedulerImpl` 中更细粒度的任务优先级管理、特定场景下的调度策略（例如查找页面、合成、用户输入），以及一些防止主线程被阻塞的机制。它涵盖了各种复杂的调度场景，旨在确保 Blink 引擎在各种情况下都能高效、流畅地运行，并提供良好的用户体验。尤其关注了在用户交互时的响应速度和渲染效率的平衡。

Prompt: 
```
这是目录为blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第3部分，共3部分，请归纳一下它的功能

"""
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
 public:
  DiscreteInputMatchesResponsivenessMetricsTest() {
    feature_list_.Reset();
    if (GetParam()) {
      feature_list_.InitWithFeatures(
          {{features::
                kBlinkSchedulerDiscreteInputMatchesResponsivenessMetrics}},
          {});
    } else {
      feature_list_.InitWithFeatures(
          {}, {{features::
                    kBlinkSchedulerDiscreteInputMatchesResponsivenessMetrics}});
    }
  }
};

TEST_P(DiscreteInputMatchesResponsivenessMetricsTest, TestPolicy) {
  Vector<String> run_order;

  // This will not be considered discrete iff the feature is enabled.
  input_task_runner_->PostTask(
      FROM_HERE, base::BindLambdaForTesting([&]() {
        scheduler_->DidHandleInputEventOnMainThread(
            FakeInputEvent(WebInputEvent::Type::kMouseLeave),
            WebInputEventResult::kHandledApplication,
            /*frame_requested=*/true);
        run_order.push_back("I1");
      }));
  PostTestTasks(&run_order, "D1 D2 CM1");
  base::RunLoop().RunUntilIdle();

  if (GetParam()) {
    EXPECT_THAT(run_order, testing::ElementsAre("I1", "D1", "D2", "CM1"));
  } else {
    EXPECT_THAT(run_order, testing::ElementsAre("I1", "CM1", "D1", "D2"));
  }

  run_order.clear();
  // This shouldn't be considered discrete in either case.
  input_task_runner_->PostTask(
      FROM_HERE, base::BindLambdaForTesting([&]() {
        scheduler_->DidHandleInputEventOnMainThread(
            FakeInputEvent(WebInputEvent::Type::kTouchMove),
            WebInputEventResult::kHandledApplication,
            /*frame_requested=*/true);
        run_order.push_back("I1");
      }));
  PostTestTasks(&run_order, "D1 D2 CM1");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("I1", "D1", "D2", "CM1"));
}

INSTANTIATE_TEST_SUITE_P(,
                         DiscreteInputMatchesResponsivenessMetricsTest,
                         testing::Values(true, false),
                         [](const testing::TestParamInfo<bool>& info) {
                           return info.param ? "Enabled" : "Disabled";
                         });

}  // namespace main_thread_scheduler_impl_unittest
}  // namespace scheduler
}  // namespace blink

"""


```