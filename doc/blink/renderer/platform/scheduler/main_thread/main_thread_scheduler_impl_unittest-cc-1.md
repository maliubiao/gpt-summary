Response: The user wants a summary of the functionalities of the provided C++ code snippet. This code is a unit test for `MainThreadSchedulerImpl` in the Chromium Blink engine.

Here's a breakdown of how to approach this:

1. **Identify the core purpose:** The file is a unit test. This means it tests the behavior of the `MainThreadSchedulerImpl` class.

2. **Analyze the test names:** The names of the `TEST_F` macros are descriptive and reveal the specific functionalities being tested.

3. **Look for patterns and keywords:**  Terms like "EventConsumedOnCompositorThread", "EventForwardedToMainThread", "MouseWheel", "KeyboardEvents", "Gesture", "TouchStart", "IdleTasks", "ShouldYield", "UpdatePolicy", "RAILMode", "VirtualTime", "ThrottleableQueue", "PauseScheduler", "Shutdown", "LoadingTasks", "Compositing", etc., are key indicators of the features being tested.

4. **Consider the test logic:**  Even without fully understanding the Chromium codebase, the structure of the tests (setting up expectations with `EXPECT_EQ`, `EXPECT_THAT`, calling methods on `scheduler_`, running the event loop with `base::RunLoop().RunUntilIdle()`) gives clues about what the scheduler is responsible for.

5. **Relate to web technologies (JavaScript, HTML, CSS):** Think about how the tested functionalities connect to user interactions and browser behavior. Input events, scrolling, rendering, loading, idle time are all relevant to how web pages function.

6. **Infer assumptions and outputs:** When a test involves specific input events and checks the order of execution (`run_order`), it's possible to infer assumptions about how the scheduler prioritizes and handles different types of tasks.

7. **Identify potential user/programming errors:** Tests that check scenarios where events are consumed or forwarded can hint at situations where developers might make mistakes in event handling.

8. **Organize the findings:**  Group the functionalities based on related concepts (e.g., input event handling, task prioritization, idle time management, etc.).
这是对 `blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl_unittest.cc` 文件第2部分代码的功能归纳：

**核心功能：测试 `MainThreadSchedulerImpl` 类在处理不同类型的输入事件以及由此引发的策略更新和任务调度行为。**

具体来说，这部分代码主要测试了以下功能：

1. **输入事件处理和任务优先级：**
   - 测试当输入事件（鼠标事件、滚轮事件）在合成器线程被消费或转发到主线程时，不同类型任务（例如：合成器任务、默认任务、空闲任务）的执行顺序和优先级。
   - 验证了合成器任务在某些情况下会被优先执行，尤其是在处理快速路径的合成器手势时。
   - 针对键盘事件做了特殊处理，即使在合成器线程被消费或转发到主线程，也不会触发特定的 use case 或改变任务优先级。

2. **use case 的管理和切换：**
   - 测试了在不同输入事件场景下，`MainThreadSchedulerImpl` 如何设置和切换当前的 `UseCase`，例如 `kCompositorGesture`、`kMainThreadCustomInputHandling`、`kMainThreadGesture`。
   - `UseCase` 代表了当前主线程调度器正在处理的高优先级任务类型。

3. **主线程滚动手势的优化：**
   - 测试了主线程滚动手势 (`kMainThreadScrolling`) 不会饿死默认任务，保证了其他类型的任务也能得到执行。

4. **策略更新机制：**
   - 测试了 `ForceUpdatePolicyAndGetCurrentUseCase()` 方法，用于强制更新调度策略并获取当前的 `UseCase`。
   - 验证了在合成器处理输入事件和主线程处理输入事件的不同情况下，策略更新的触发和 `UseCase` 的变化。

5. **touchstart 策略：**
   - 测试了 `touchstart` 事件发生时，调度器会进入特殊的策略模式，该模式会延迟空闲任务和加载任务的执行。
   - 验证了 `touchstart` 策略会在超时或者接收到连续的 `touchmove` 事件后结束。

6. **`ShouldYieldForHighPriorityWork()` 方法：**
   - 测试了 `ShouldYieldForHighPriorityWork()` 方法，用于判断当前是否应该暂停低优先级任务来执行高优先级任务。
   - 验证了接收到 `touchstart` 事件会立即触发 yielding。

7. **慢速主线程输入事件的处理：**
   - 测试了当主线程处理输入事件耗时过长时，`UseCase` 的变化以及超时后的恢复。

8. **策略更新的优化：**
   - 测试了避免过于频繁地触发策略更新，确保在短时间内多次请求更新时只执行一次。
   - 验证了 `DidHandleInputEventOnCompositorThread` 和 `DidHandleInputEventOnMainThread` 如何触发策略更新。

9. **阻塞输入事件预期：**
   - 测试了 `BlockingInputExpectedSoon()` 方法，用于判断是否预期即将有阻塞输入事件发生。

10. **长空闲周期 (Long Idle Period)：**
    - 测试了 `BeginMainFrameNotExpectedUntil()` 和 `BeginFrameNotExpectedSoon()` 方法，用于指示在一段时间内不期望有新的帧开始，从而允许执行低优先级的空闲任务。
    - 验证了长空闲周期在有延迟任务存在的情况下如何被处理，以及在 `touchstart` 策略期间是否会被延迟。
    - 测试了重复执行的空闲任务和在渲染器隐藏时的空闲周期行为。

**与 JavaScript, HTML, CSS 的关系举例说明：**

* **`EventConsumedOnCompositorThread_MouseWheel` 和 `EventForwardedToMainThread_MouseWheel_PreventDefault`:** 当用户滚动鼠标滚轮时，浏览器会生成 `wheel` 事件。如果 JavaScript 代码中调用了 `event.preventDefault()` 阻止了默认行为（例如，平滑滚动），事件可能会被转发到主线程处理，这会影响任务的优先级，如测试所示，合成器任务会被优先执行。
* **`EventForwardedToMainThread_NoPreventDefault`:** 如果 JavaScript 没有阻止滚轮事件的默认行为，浏览器的合成器线程可以处理滚动，主线程也会收到相应的 `GestureScrollBegin` 和 `GestureScrollUpdate` 事件，这会触发 `kMainThreadGesture` 的 `UseCase`。
* **`TestTouchstartPolicyEndsAfterTimeout` 和 `TestTouchstartPolicyEndsAfterConsecutiveTouchmoves`:** 当用户触摸屏幕时，会触发 `touchstart` 事件。浏览器会进入 `touchstart` 策略，等待 JavaScript 代码的响应。如果 JavaScript 处理时间过长或者用户连续移动手指（触发 `touchmove`），策略会结束，这影响了空闲任务的执行时机。
* **`TestShouldYield_TouchStart`:** 当接收到 `touchstart` 事件时，即使没有其他高优先级任务，调度器也会标记为应该 yield，这意味着可能会暂停正在执行的低优先级任务，以便优先处理与触摸相关的操作，保证用户交互的响应性。

**逻辑推理 (假设输入与输出):**

* **假设输入:**  接收到一个 `blink::WebInputEvent::Type::kMouseUp` 事件，且 `InputEventState` 为 `EVENT_FORWARDED_TO_MAIN_THREAD`。
* **输出:**  `CurrentUseCase()` 返回 `UseCase::kMainThreadCustomInputHandling`，且任务执行顺序 `run_order` 中合成器任务 (`C1`, `C2`) 会在默认任务 (`D1`, `D2`) 之前执行。

* **假设输入:**  在 `touchstart` 策略期间，调用 `BeginFrameNotExpectedSoon()`。
* **输出:**  空闲任务不会立即执行，而是会等待 `touchstart` 策略结束后再执行。

**用户或编程常见的使用错误举例说明：**

* **在合成器线程处理输入事件时，错误地认为所有任务的优先级都会降低：** 测试 `EventConsumedOnCompositorThread_MouseWheel` 表明，即使事件在合成器线程被消费，合成器任务的优先级仍然可能很高。
* **过度依赖 `preventDefault()` 可能会导致性能问题：**  如果 JavaScript 代码频繁地对输入事件调用 `preventDefault()`，可能会导致事件被转发到主线程处理，增加主线程的负担，影响页面的流畅性。
* **不理解 `touchstart` 策略对任务调度的影响：**  开发者可能会在 `touchstart` 事件处理函数中执行耗时操作，导致空闲任务和加载任务被延迟，影响页面的加载速度和用户体验。

**总结：** 这部分测试代码主要关注 `MainThreadSchedulerImpl` 如何根据不同类型的用户输入事件，动态地调整任务的优先级和调度策略，以确保用户交互的响应性和页面的流畅性。它涵盖了合成器线程和主线程之间如何协调处理输入事件，以及各种策略模式（例如 `touchstart` 策略）对任务执行的影响。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共3部分，请归纳一下它的功能
```

### 源代码
```cpp
::WebInputEvent::Type::kMouseUp,
                     blink::WebInputEvent::kLeftButtonDown),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(UseCase::kMainThreadCustomInputHandling, CurrentUseCase());

  // Note compositor tasks are prioritized.
  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "D1", "D2", "I1"));
}

TEST_F(MainThreadSchedulerImplTest,
       EventConsumedOnCompositorThread_MouseWheel) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2");

  EnableIdleTasks();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeMouseWheelEvent(blink::WebInputEvent::Type::kMouseWheel),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  base::RunLoop().RunUntilIdle();
  // Note compositor tasks are not prioritized.
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "D2", "C1", "C2", "I1"));
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       EventForwardedToMainThread_MouseWheel_PreventDefault) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2");

  EnableIdleTasks();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeMouseWheelEvent(blink::WebInputEvent::Type::kMouseWheel),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  base::RunLoop().RunUntilIdle();
  // Note compositor tasks are prioritized (since they are fast).
  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "D1", "D2", "I1"));
  EXPECT_EQ(UseCase::kMainThreadCustomInputHandling, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       EventForwardedToMainThread_NoPreventDefault) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2");

  EnableIdleTasks();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeMouseWheelEvent(blink::WebInputEvent::Type::kMouseWheel),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollBegin),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  base::RunLoop().RunUntilIdle();
  // Note compositor tasks are prioritized.
  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "D1", "D2", "I1"));
  EXPECT_EQ(UseCase::kMainThreadGesture, CurrentUseCase());
}

TEST_F(
    MainThreadSchedulerImplTest,
    EventForwardedToMainThreadAndBackToCompositor_MouseWheel_NoPreventDefault) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2");

  EnableIdleTasks();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeMouseWheelEvent(blink::WebInputEvent::Type::kMouseWheel),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollBegin),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  base::RunLoop().RunUntilIdle();
  // Note compositor tasks are not prioritized.
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "D2", "C1", "C2", "I1"));
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       EventConsumedOnCompositorThread_IgnoresKeyboardEvents) {
  DoMainFrame();
  RunSlowCompositorTask();

  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2");

  EnableIdleTasks();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kKeyDown),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  base::RunLoop().RunUntilIdle();
  // Note compositor tasks are not prioritized.
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "C1", "D2", "C2", "I1"));
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       EventForwardedToMainThread_IgnoresKeyboardEvents) {
  DoMainFrame();
  RunSlowCompositorTask();

  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2");

  EnableIdleTasks();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kKeyDown),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  base::RunLoop().RunUntilIdle();
  // Note compositor tasks are not prioritized.
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "C1", "D2", "C2", "I1"));
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());
  // Note compositor tasks are not prioritized.
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kKeyDown),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
}

TEST_F(MainThreadSchedulerImplTest,
       TestMainthreadScrollingUseCaseDoesNotStarveDefaultTasks) {
  SimulateMainThreadGestureStart(
      TouchEventPolicy::kDontSendTouchStart,
      blink::WebInputEvent::Type::kGestureScrollBegin);
  EnableIdleTasks();

  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 C1");

  for (int i = 0; i < 20; i++) {
    compositor_task_runner_->PostTask(FROM_HERE, base::BindOnce(&NullTask));
  }
  PostTestTasks(&run_order, "C2");

  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureFlingStart),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "D1"));
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicyEnds_CompositorHandlesInput) {
  SimulateCompositorGestureStart(TouchEventPolicy::kDontSendTouchStart);
  EXPECT_EQ(UseCase::kCompositorGesture,
            ForceUpdatePolicyAndGetCurrentUseCase());

  test_task_runner_->AdvanceMockTickClock(base::Seconds(1));
  EXPECT_EQ(UseCase::kNone, ForceUpdatePolicyAndGetCurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicyEnds_MainThreadHandlesInput) {
  SimulateMainThreadGestureStart(
      TouchEventPolicy::kDontSendTouchStart,
      blink::WebInputEvent::Type::kGestureScrollBegin);
  EXPECT_EQ(UseCase::kMainThreadCustomInputHandling,
            ForceUpdatePolicyAndGetCurrentUseCase());

  test_task_runner_->AdvanceMockTickClock(base::Seconds(1));
  EXPECT_EQ(UseCase::kNone, ForceUpdatePolicyAndGetCurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest, TestTouchstartPolicyEndsAfterTimeout) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 D1 C1 D2 C2");

  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "D1", "D2"));

  run_order.clear();
  test_task_runner_->AdvanceMockTickClock(base::Seconds(1));

  // Don't post any compositor tasks to simulate a very long running event
  // handler.
  PostTestTasks(&run_order, "D1 D2");

  // Touchstart policy mode should have ended now that the clock has advanced.
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("L1", "D1", "D2"));
}

TEST_F(MainThreadSchedulerImplTest,
       TestTouchstartPolicyEndsAfterConsecutiveTouchmoves) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 D1 C1 D2 C2");

  // Observation of touchstart should defer execution of idle and loading tasks.
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "D1", "D2"));

  // Receiving the first touchmove will not affect scheduler priority.
  run_order.clear();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre());

  // Receiving the second touchmove will kick us back into compositor priority.
  run_order.clear();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("L1"));
}

TEST_F(MainThreadSchedulerImplTest, TestShouldYield) {
  bool should_yield_before = false;
  bool should_yield_after = false;

  default_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(&PostingYieldingTestTask, scheduler_.get(),
                                base::RetainedRef(default_task_runner_), false,
                                &should_yield_before, &should_yield_after));
  base::RunLoop().RunUntilIdle();
  // Posting to default runner shouldn't cause yielding.
  EXPECT_FALSE(should_yield_before);
  EXPECT_FALSE(should_yield_after);

  default_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&PostingYieldingTestTask, scheduler_.get(),
                     base::RetainedRef(compositor_task_runner_), false,
                     &should_yield_before, &should_yield_after));
  base::RunLoop().RunUntilIdle();
  // Posting while not mainthread scrolling shouldn't cause yielding.
  EXPECT_FALSE(should_yield_before);
  EXPECT_FALSE(should_yield_after);

  default_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(&PostingYieldingTestTask, scheduler_.get(),
                     base::RetainedRef(compositor_task_runner_), true,
                     &should_yield_before, &should_yield_after));
  base::RunLoop().RunUntilIdle();
  // We should be able to switch to compositor priority mid-task.
  EXPECT_FALSE(should_yield_before);
  EXPECT_TRUE(should_yield_after);
}

TEST_F(MainThreadSchedulerImplTest, TestShouldYield_TouchStart) {
  // Receiving a touchstart should immediately trigger yielding, even if
  // there's no immediately pending work in the compositor queue.
  EXPECT_FALSE(scheduler_->ShouldYieldForHighPriorityWork());
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  EXPECT_TRUE(scheduler_->ShouldYieldForHighPriorityWork());
  base::RunLoop().RunUntilIdle();
}

TEST_F(MainThreadSchedulerImplTest, SlowMainThreadInputEvent) {
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());

  // An input event should bump us into input priority.
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureFlingStart),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(UseCase::kMainThreadCustomInputHandling, CurrentUseCase());

  // Simulate the input event being queued for a very long time. The compositor
  // task we post here represents the enqueued input task.
  test_task_runner_->AdvanceMockTickClock(UserModel::kGestureEstimationLimit *
                                          2);
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureFlingStart),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  base::RunLoop().RunUntilIdle();

  // Even though we exceeded the input priority escalation period, we should
  // still be in main thread gesture since the input remains queued.
  EXPECT_EQ(UseCase::kMainThreadCustomInputHandling, CurrentUseCase());

  // After the escalation period ends we should go back into normal mode.
  test_task_runner_->FastForwardBy(UserModel::kGestureEstimationLimit * 2);
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest, OnlyOnePendingUrgentPolicyUpdate) {
  for (int i = 0; i < 4; i++) {
    scheduler_->EnsureUrgentPolicyUpdatePostedOnMainThread();
  }
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, scheduler_->update_policy_count_);
}

TEST_F(MainThreadSchedulerImplTest, OnePendingDelayedAndOneUrgentUpdatePolicy) {
  scheduler_->ScheduleDelayedPolicyUpdate(Now(), base::Milliseconds(1));
  scheduler_->EnsureUrgentPolicyUpdatePostedOnMainThread();

  test_task_runner_->FastForwardUntilNoTasksRemain();
  // We expect both the urgent and the delayed updates to run.
  EXPECT_EQ(2, scheduler_->update_policy_count_);
}

TEST_F(MainThreadSchedulerImplTest, OneUrgentAndOnePendingDelayedUpdatePolicy) {
  scheduler_->EnsureUrgentPolicyUpdatePostedOnMainThread();
  scheduler_->ScheduleDelayedPolicyUpdate(Now(), base::Milliseconds(1));

  test_task_runner_->FastForwardUntilNoTasksRemain();
  // We expect both the urgent and the delayed updates to run.
  EXPECT_EQ(2, scheduler_->update_policy_count_);
}

TEST_F(MainThreadSchedulerImplTest, UpdatePolicyCountTriggeredByOneInputEvent) {
  // We expect DidHandleInputEventOnCompositorThread to post an urgent policy
  // update.
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  EXPECT_EQ(0, scheduler_->update_policy_count_);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, scheduler_->update_policy_count_);

  scheduler_->DidHandleInputEventOnMainThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  EXPECT_EQ(1, scheduler_->update_policy_count_);

  test_task_runner_->AdvanceMockTickClock(base::Seconds(1));
  base::RunLoop().RunUntilIdle();
  // We finally expect a delayed policy update 100ms later.
  EXPECT_EQ(2, scheduler_->update_policy_count_);
}

TEST_F(MainThreadSchedulerImplTest,
       UpdatePolicyCountTriggeredByThreeInputEvents) {
  // We expect DidHandleInputEventOnCompositorThread to post
  // an urgent policy update.
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart,
                     blink::WebInputEvent::DispatchType::kEventNonBlocking),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  EXPECT_EQ(0, scheduler_->update_policy_count_);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, scheduler_->update_policy_count_);

  scheduler_->DidHandleInputEventOnMainThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  EXPECT_EQ(1, scheduler_->update_policy_count_);

  // The second call to DidHandleInputEventOnCompositorThread should not post
  // a policy update because we are already in compositor priority.
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, scheduler_->update_policy_count_);

  // We expect DidHandleInputEvent to trigger a policy update.
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  EXPECT_EQ(1, scheduler_->update_policy_count_);

  // The third call to DidHandleInputEventOnCompositorThread should post a
  // policy update because the awaiting_touch_start_response_ flag changed.
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  EXPECT_EQ(1, scheduler_->update_policy_count_);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2, scheduler_->update_policy_count_);

  // We expect DidHandleInputEvent to trigger a policy update.
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  EXPECT_EQ(2, scheduler_->update_policy_count_);
  test_task_runner_->FastForwardBy(base::Seconds(1));
  // We finally expect a delayed policy update.
  EXPECT_EQ(3, scheduler_->update_policy_count_);
}

TEST_F(MainThreadSchedulerImplTest,
       UpdatePolicyCountTriggeredByTwoInputEventsWithALongSeparatingDelay) {
  // We expect DidHandleInputEventOnCompositorThread to post an urgent policy
  // update.
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart,
                     blink::WebInputEvent::DispatchType::kEventNonBlocking),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  EXPECT_EQ(0, scheduler_->update_policy_count_);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, scheduler_->update_policy_count_);

  scheduler_->DidHandleInputEventOnMainThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  EXPECT_EQ(1, scheduler_->update_policy_count_);
  test_task_runner_->FastForwardBy(base::Seconds(1));
  // We expect a delayed policy update.
  EXPECT_EQ(2, scheduler_->update_policy_count_);

  // We expect the second call to DidHandleInputEventOnCompositorThread to post
  // an urgent policy update because we are no longer in compositor priority.
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  EXPECT_EQ(2, scheduler_->update_policy_count_);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(3, scheduler_->update_policy_count_);

  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  EXPECT_EQ(3, scheduler_->update_policy_count_);
  test_task_runner_->FastForwardBy(base::Seconds(1));
  // We finally expect a delayed policy update.
  EXPECT_EQ(4, scheduler_->update_policy_count_);
}

TEST_F(MainThreadSchedulerImplTest, EnsureUpdatePolicyNotTriggeredTooOften) {
  EXPECT_EQ(0, scheduler_->update_policy_count_);
  ForceUpdatePolicyAndGetCurrentUseCase();
  EXPECT_EQ(1, scheduler_->update_policy_count_);

  SimulateCompositorGestureStart(TouchEventPolicy::kSendTouchStart);

  // We expect the first call to ShouldYieldForHighPriorityWork to be called
  // after receiving an input event (but before the UpdateTask was processed) to
  // call UpdatePolicy.
  EXPECT_EQ(1, scheduler_->update_policy_count_);
  scheduler_->ShouldYieldForHighPriorityWork();
  EXPECT_EQ(2, scheduler_->update_policy_count_);
  // Subsequent calls should not call UpdatePolicy.
  scheduler_->ShouldYieldForHighPriorityWork();
  scheduler_->ShouldYieldForHighPriorityWork();
  scheduler_->ShouldYieldForHighPriorityWork();

  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollEnd),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kTouchEnd),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);

  scheduler_->DidHandleInputEventOnMainThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kTouchEnd),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);

  EXPECT_EQ(2, scheduler_->update_policy_count_);

  // We expect both the urgent and the delayed updates to run in addition to the
  // earlier updated cause by ShouldYieldForHighPriorityWork, a final update
  // transitions from 'not_scrolling touchstart expected' to 'not_scrolling'.
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_THAT(scheduler_->use_cases_,
              testing::ElementsAre("none", "compositor_gesture",
                                   "compositor_gesture blocking input expected",
                                   "none blocking input expected", "none"));
}

TEST_F(MainThreadSchedulerImplTest,
       BlockingInputExpectedSoonWhenBlockInputEventSeen) {
  SimulateCompositorGestureStart(TouchEventPolicy::kSendTouchStart);
  EXPECT_TRUE(HaveSeenABlockingGesture());
  ForceBlockingInputToBeExpectedSoon();
  EXPECT_TRUE(BlockingInputExpectedSoon());
}

TEST_F(MainThreadSchedulerImplTest,
       BlockingInputNotExpectedSoonWhenNoBlockInputEventSeen) {
  SimulateCompositorGestureStart(TouchEventPolicy::kDontSendTouchStart);
  EXPECT_FALSE(HaveSeenABlockingGesture());
  ForceBlockingInputToBeExpectedSoon();
  EXPECT_FALSE(BlockingInputExpectedSoon());
}

TEST_F(MainThreadSchedulerImplTest, TestBeginMainFrameNotExpectedUntil) {
  base::TimeDelta ten_millis(base::Milliseconds(10));
  base::TimeTicks expected_deadline = Now() + ten_millis;
  base::TimeTicks deadline_in_task;
  int run_count = 0;

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, run_count);  // Shouldn't run yet as no idle period.

  base::TimeTicks now = Now();
  base::TimeTicks frame_time = now + ten_millis;
  // No main frame is expected until frame_time, so short idle work can be
  // scheduled in the mean time.
  scheduler_->BeginMainFrameNotExpectedUntil(frame_time);
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, run_count);  // Should have run in a long idle time.
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

TEST_F(MainThreadSchedulerImplTest, TestLongIdlePeriod) {
  base::TimeTicks expected_deadline = Now() + maximum_idle_period_duration();
  base::TimeTicks deadline_in_task;
  int run_count = 0;

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, run_count);  // Shouldn't run yet as no idle period.

  scheduler_->BeginFrameNotExpectedSoon();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, run_count);  // Should have run in a long idle time.
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

TEST_F(MainThreadSchedulerImplTest, TestLongIdlePeriodWithPendingDelayedTask) {
  base::TimeDelta pending_task_delay = base::Milliseconds(30);
  base::TimeTicks expected_deadline = Now() + pending_task_delay;
  base::TimeTicks deadline_in_task;
  int run_count = 0;

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  default_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NullTask),
                                        pending_task_delay);

  scheduler_->BeginFrameNotExpectedSoon();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, run_count);  // Should have run in a long idle time.
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

TEST_F(MainThreadSchedulerImplTest,
       TestLongIdlePeriodWithLatePendingDelayedTask) {
  base::TimeDelta pending_task_delay = base::Milliseconds(10);
  base::TimeTicks deadline_in_task;
  int run_count = 0;

  default_task_runner_->PostDelayedTask(FROM_HERE, base::BindOnce(&NullTask),
                                        pending_task_delay);

  // Advance clock until after delayed task was meant to be run.
  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(20));

  // Post an idle task and BeginFrameNotExpectedSoon to initiate a long idle
  // period. Since there is a late pending delayed task this shouldn't actually
  // start an idle period.
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));
  scheduler_->BeginFrameNotExpectedSoon();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, run_count);

  // After the delayed task has been run we should trigger an idle period.
  test_task_runner_->FastForwardBy(maximum_idle_period_duration());
  EXPECT_EQ(1, run_count);
}

TEST_F(MainThreadSchedulerImplTest, TestLongIdlePeriodRepeating) {
  Vector<base::TimeTicks> actual_deadlines;
  int run_count = 0;

  g_max_idle_task_reposts = 3;
  base::TimeTicks clock_before = Now();
  base::TimeDelta idle_task_runtime(base::Milliseconds(10));
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&RepostingUpdateClockIdleTestTask,
                     base::RetainedRef(idle_task_runner_), &run_count,
                     test_task_runner_, idle_task_runtime, &actual_deadlines));
  scheduler_->BeginFrameNotExpectedSoon();
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(3, run_count);
  EXPECT_THAT(
      actual_deadlines,
      testing::ElementsAre(clock_before + maximum_idle_period_duration(),
                           clock_before + 2 * maximum_idle_period_duration(),
                           clock_before + 3 * maximum_idle_period_duration()));

  // Check that idle tasks don't run after the idle period ends with a
  // new BeginMainFrame.
  g_max_idle_task_reposts = 5;
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&RepostingUpdateClockIdleTestTask,
                     base::RetainedRef(idle_task_runner_), &run_count,
                     test_task_runner_, idle_task_runtime, &actual_deadlines));
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&WillBeginFrameIdleTask,
                     base::Unretained(scheduler_.get()),
                     next_begin_frame_number_++,
                     base::Unretained(test_task_runner_->GetMockTickClock())));
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(4, run_count);
}

TEST_F(MainThreadSchedulerImplTest, TestLongIdlePeriodInTouchStartPolicy) {
  base::TimeTicks deadline_in_task;
  int run_count = 0;

  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  // Observation of touchstart should defer the start of the long idle period.
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  scheduler_->BeginFrameNotExpectedSoon();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, run_count);

  // The long idle period should start after the touchstart policy has finished.
  test_task_runner_->FastForwardBy(UserModel::kGestureEstimationLimit);
  EXPECT_EQ(1, run_count);
}

TEST_F(MainThreadSchedulerImplTest, TestRendererHiddenIdlePeriod) {
  int run_count = 0;

  g_max_idle_task_reposts = 2;
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&RepostingIdleTestTask,
                     base::RetainedRef(idle_task_runner_), &run_count));

  // Renderer should start in visible state.
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(0, run_count);

  // When we hide the renderer it should start a max deadline idle period, which
  // will run an idle task and then immediately start a new idle period, which
  // runs the second idle task.
  scheduler_->SetAllRenderWidgetsHidden(true);
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_EQ(2, run_count);

  // Advance time by amount of time by the maximum amount of time we execute
  // idle tasks when hidden (plus some slack) - idle period should have ended.
  g_max_idle_task_reposts = 3;
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&RepostingIdleTestTask,
                     base::RetainedRef(idle_task_runner_), &run_count));
  test_task_runner_->FastForwardBy(end_idle_when_hidden_delay() +
                                   base::Milliseconds(10));
  EXPECT_EQ(2, run_count);
}

TEST_F(MainThreadSchedulerImplTest, ThrottleableQueueEnabledByDefault) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "T1 T2");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("T1", "T2"));
}

TEST_F(MainThreadSchedulerImplTest, StopAndResumeRenderer) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "T1 T2");

  auto pause_handle = scheduler_->PauseScheduler();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre());

  pause_handle.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("T1", "T2"));
}

TEST_F(MainThreadSchedulerImplTest, StopAndThrottleThrottleableQueue) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "T1 T2");

  auto pause_handle = scheduler_->PauseScheduler();
  base::RunLoop().RunUntilIdle();
  MainThreadTaskQueue::ThrottleHandle handle =
      throttleable_task_queue()->Throttle();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre());
}

TEST_F(MainThreadSchedulerImplTest, MultipleStopsNeedMultipleResumes) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "T1 T2");

  auto pause_handle1 = scheduler_->PauseScheduler();
  auto pause_handle2 = scheduler_->PauseScheduler();
  auto pause_handle3 = scheduler_->PauseScheduler();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre());

  pause_handle1.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre());

  pause_handle2.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre());

  pause_handle3.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("T1", "T2"));
}

TEST_F(MainThreadSchedulerImplTest, PauseRenderer) {
  // Tasks in some queues don't fire when the renderer is paused.
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 C1 L1 I1 T1");
  auto pause_handle = scheduler_->PauseScheduler();
  EnableIdleTasks();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "C1", "I1"));

  // Tasks are executed when renderer is resumed.
  run_order.clear();
  pause_handle.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("L1", "T1"));
}

TEST_F(MainThreadSchedulerImplTest, UseCaseToString) {
  for (unsigned i = 0; i <= static_cast<unsigned>(UseCase::kMaxValue); i++) {
    UseCaseToString(static_cast<UseCase>(i));
  }
}

TEST_F(MainThreadSchedulerImplTest, MismatchedDidHandleInputEventOnMainThread) {
  // This should not DCHECK because there was no corresponding compositor side
  // call to DidHandleInputEventOnCompositorThread with
  // blink::mojom::InputEventResultState::kNotConsumed. There are legitimate
  // reasons for the compositor to not be there and we don't want to make
  // debugging impossible.
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureFlingStart),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
}

TEST_F(MainThreadSchedulerImplTest, BeginMainFrameOnCriticalPath) {
  ASSERT_FALSE(scheduler_->BeginMainFrameOnCriticalPath());
  viz::BeginFrameArgs begin_frame_args = viz::BeginFrameArgs::Create(
      BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
      base::TimeTicks(), base::Milliseconds(1000), viz::BeginFrameArgs::NORMAL);
  scheduler_->WillBeginFrame(begin_frame_args);
  ASSERT_TRUE(scheduler_->BeginMainFrameOnCriticalPath());

  begin_frame_args.on_critical_path = false;
  scheduler_->WillBeginFrame(begin_frame_args);
  ASSERT_FALSE(scheduler_->BeginMainFrameOnCriticalPath());
}

TEST_F(MainThreadSchedulerImplTest, ShutdownPreventsPostingOfNewTasks) {
  main_frame_scheduler_.reset();
  page_scheduler_.reset();
  scheduler_->Shutdown();
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 C1");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre());
}

namespace {
void SlowCountingTask(
    size_t* count,
    scoped_refptr<base::TestMockTimeTaskRunner> task_runner,
    int task_duration,
    scoped_refptr<base::SingleThreadTaskRunner> throttleable_queue) {
  task_runner->AdvanceMockTickClock(base::Milliseconds(task_duration));
  if (++(*count) < 500) {
    throttleable_queue->PostTask(
        FROM_HERE, base::BindOnce(SlowCountingTask, count, task_runner,
                                  task_duration, throttleable_queue));
  }
}
}  // namespace

TEST_F(
    MainThreadSchedulerImplTest,
    SYNCHRONIZED_GESTURE_ThrottleableTaskThrottling_ThrottleableQueuesStopped) {
  SimulateCompositorGestureStart(TouchEventPolicy::kSendTouchStart);

  base::TimeTicks first_run_time = Now();

  size_t count = 0;
  // With the compositor task taking 10ms, there is not enough time to run this
  // 7ms throttleable task in the 16ms frame.
  throttleable_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(SlowCountingTask, &count, test_task_runner_, 7,
                                throttleable_task_runner_));

  std::unique_ptr<MainThreadScheduler::RendererPauseHandle> paused;
  for (int i = 0; i < 1000; i++) {
    viz::BeginFrameArgs begin_frame_args = viz::BeginFrameArgs::Create(
        BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
        base::TimeTicks(), base::Milliseconds(16), viz::BeginFrameArgs::NORMAL);
    begin_frame_args.on_critical_path = true;
    scheduler_->WillBeginFrame(begin_frame_args);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);

    compositor_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&MainThreadSchedulerImplTest::
                           SimulateMainThreadCompositorAndQuitRunLoopTask,
                       base::Unretained(this), base::Milliseconds(10)));

    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(UseCase::kSynchronizedGesture, CurrentUseCase()) << "i = " << i;

    // Before the policy is updated the queue will be enabled. Subsequently it
    // will be disabled until the throttled queue is pumped.
    bool expect_queue_enabled = (i == 0) || (Now() > first_run_time);
    if (paused)
      expect_queue_enabled = false;
    EXPECT_EQ(expect_queue_enabled, throttleable_task_queue()->IsQueueEnabled())
        << "i = " << i;

    // After we've run any expensive tasks suspend the queue.  The throttling
    // helper should /not/ re-enable this queue under any circumstances while
    // throttleable queues are paused.
    if (count > 0 && !paused) {
      EXPECT_EQ(2u, count) << "i = " << i;
      paused = scheduler_->PauseScheduler();
    }
  }

  // Make sure the throttleable queue stayed paused!
  EXPECT_EQ(2u, count);
}

TEST_F(MainThreadSchedulerImplTest,
       SYNCHRONIZED_GESTURE_ThrottleableTaskThrottling_task_not_expensive) {
  SimulateCompositorGestureStart(TouchEventPolicy::kSendTouchStart);

  size_t count = 0;
  // With the compositor task taking 10ms, there is enough time to run this 6ms
  // throttleable task in the 16ms frame.
  throttleable_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(SlowCountingTask, &count, test_task_runner_, 6,
                                throttleable_task_runner_));

  for (int i = 0; i < 1000; i++) {
    viz::BeginFrameArgs begin_frame_args = viz::BeginFrameArgs::Create(
        BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
        base::TimeTicks(), base::Milliseconds(16), viz::BeginFrameArgs::NORMAL);
    begin_frame_args.on_critical_path = true;
    scheduler_->WillBeginFrame(begin_frame_args);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);

    compositor_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&MainThreadSchedulerImplTest::
                           SimulateMainThreadCompositorAndQuitRunLoopTask,
                       base::Unretained(this), base::Milliseconds(10)));

    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(UseCase::kSynchronizedGesture, CurrentUseCase()) << "i = " << i;
    EXPECT_TRUE(throttleable_task_queue()->IsQueueEnabled()) << "i = " << i;
  }

  // Task is not throttled.
  EXPECT_EQ(500u, count);
}

TEST_F(MainThreadSchedulerImplTest, DenyLongIdleDuringTouchStart) {
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  EXPECT_EQ(UseCase::kTouchstart, ForceUpdatePolicyAndGetCurrentUseCase());

  // First check that long idle is denied during the TOUCHSTART use case.
  IdleHelper::Delegate* idle_delegate = scheduler_.get();
  base::TimeTicks now;
  base::TimeDelta next_time_to_check;
  EXPECT_FALSE(idle_delegate->CanEnterLongIdlePeriod(now, &next_time_to_check));
  EXPECT_GE(next_time_to_check, base::TimeDelta());

  // Check again at a time past the TOUCHSTART expiration. We should still get a
  // non-negative delay to when to check again.
  now += base::Milliseconds(500);
  EXPECT_FALSE(idle_delegate->CanEnterLongIdlePeriod(now, &next_time_to_check));
  EXPECT_GE(next_time_to_check, base::TimeDelta());
}

TEST_F(MainThreadSchedulerImplTest, SYNCHRONIZED_GESTURE_CompositingExpensive) {
  SimulateCompositorGestureStart(TouchEventPolicy::kSendTouchStart);

  // With the compositor task taking 20ms, there is not enough time to run
  // other tasks in the same 16ms frame. To avoid starvation, compositing tasks
  // should therefore not get prioritized.
  Vector<String> run_order;
  for (int i = 0; i < 1000; i++)
    PostTestTasks(&run_order, "T1");

  for (int i = 0; i < 100; i++) {
    viz::BeginFrameArgs begin_frame_args = viz::BeginFrameArgs::Create(
        BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
        base::TimeTicks(), base::Milliseconds(16), viz::BeginFrameArgs::NORMAL);
    begin_frame_args.on_critical_path = true;
    scheduler_->WillBeginFrame(begin_frame_args);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);

    compositor_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&MainThreadSchedulerImplTest::
                           SimulateMainThreadCompositorAndQuitRunLoopTask,
                       base::Unretained(this), base::Milliseconds(20)));

    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(UseCase::kSynchronizedGesture, CurrentUseCase()) << "i = " << i;
  }

  // Throttleable tasks should not have been starved by the expensive compositor
  // tasks.
  EXPECT_EQ(TaskPriority::kNormalPriority,
            compositor_task_queue()->GetQueuePriority());
  EXPECT_EQ(1000u, run_order.size());
}

TEST_F(MainThreadSchedulerImplTest, MAIN_THREAD_CUSTOM_INPUT_HANDLING) {
  SimulateMainThreadGestureStart(
      TouchEventPolicy::kSendTouchStart,
      blink::WebInputEvent::Type::kGestureScrollBegin);

  // With the compositor task taking 20ms, there is not enough time to run
  // other tasks in the same 16ms frame. To avoid starvation, compositing tasks
  // should therefore not get prioritized.
  Vector<String> run_order;
  for (int i = 0; i < 1000; i++)
    PostTestTasks(&run_order, "T1");

  for (int i = 0; i < 100; i++) {
    viz::BeginFrameArgs begin_frame_args = viz::BeginFrameArgs::Create(
        BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
        base::TimeTicks(), base::Milliseconds(16), viz::BeginFrameArgs::NORMAL);
    begin_frame_args.on_critical_path = true;
    scheduler_->WillBeginFrame(begin_frame_args);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
        InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);

    compositor_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&MainThreadSchedulerImplTest::
                           SimulateMainThreadCompositorAndQuitRunLoopTask,
                       base::Unretained(this), base::Milliseconds(20)));

    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(UseCase::kMainThreadCustomInputHandling, CurrentUseCase())
        << "i = " << i;
  }

  // Throttleable tasks should not have been starved by the expensive compositor
  // tasks.
  EXPECT_EQ(TaskPriority::kNormalPriority,
            compositor_task_queue()->GetQueuePriority());
  EXPECT_EQ(1000u, run_order.size());
}

TEST_F(MainThreadSchedulerImplTest, MAIN_THREAD_GESTURE) {
  SimulateMainThreadGestureStart(
      TouchEventPolicy::kDontSendTouchStart,
      blink::WebInputEvent::Type::kGestureScrollBegin);

  // With the compositor task taking 20ms, there is not enough time to run
  // other tasks in the same 16ms frame. However because this is a main thread
  // gesture instead of custom main thread input handling, we allow the
  // throttleable tasks to be starved.
  Vector<String> run_order;
  for (int i = 0; i < 1000; i++)
    PostTestTasks(&run_order, "T1");

  for (int i = 0; i < 100; i++) {
    viz::BeginFrameArgs begin_frame_args = viz::BeginFrameArgs::Create(
        BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
        base::TimeTicks(), base::Milliseconds(16), viz::BeginFrameArgs::NORMAL);
    begin_frame_args.on_critical_path = true;
    scheduler_->WillBeginFrame(begin_frame_args);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
        InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);

    compositor_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&MainThreadSchedulerImplTest::
                           SimulateMainThreadCompositorAndQuitRunLoopTask,
                       base::Unretained(this), base::Milliseconds(20)));

    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(UseCase::kMainThreadGesture, CurrentUseCase()) << "i = " << i;
  }

  EXPECT_EQ(TaskPriority::kHighestPriority,
            compositor_task_queue()->GetQueuePriority());
  EXPECT_EQ(279u, run_order.size());
}

class MockRAILModeObserver : public RAILModeObserver {
 public:
  MOCK_METHOD(void, OnRAILModeChanged, (RAILMode rail_mode));
};

TEST_F(MainThreadSchedulerImplTest, TestDefaultRAILMode) {
  MockRAILModeObserver observer;
  EXPECT_CALL(observer, OnRAILModeChanged(RAILMode::kDefault));
  scheduler_->AddRAILModeObserver(&observer);

  EXPECT_EQ(UseCase::kNone, ForceUpdatePolicyAndGetCurrentUseCase());
  EXPECT_EQ(RAILMode::kDefault, GetRAILMode());
  scheduler_->RemoveRAILModeObserver(&observer);
}

TEST_P(
    MainThreadSchedulerImplWithLoadingPhaseBufferTimeAfterFirstMeaningfulPaintTest,
    TestLoadRAILMode) {
  InSequence s;
  MockRAILModeObserver observer;
  EXPECT_CALL(observer, OnRAILModeChanged(RAILMode::kDefault));
  EXPECT_CALL(observer, OnRAILModeChanged(RAILMode::kLoad));
  EXPECT_CALL(observer, OnRAILModeChanged(RAILMode::kDefault));
  scheduler_->AddRAILModeObserver(&observer);

  ON_CALL(*page_scheduler_, IsWaitingForMainFrameContentfulPaint)
      .WillByDefault(Return(true));
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameMeaningfulPaint)
      .WillByDefault(Return(true));
  ON_CALL(*page_scheduler_, IsMainFrameLoading).WillByDefault(Return(true));
  scheduler_->DidStartProvisionalLoad(true);
  EXPECT_EQ(RAILMode::kLoad, GetRAILMode());
  EXPECT_EQ(UseCase::kEarlyLoading, ForceUpdatePolicyAndGetCurrentUseCase());
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameContentfulPaint)
      .WillByDefault(Return(false));
  scheduler_->OnMainFramePaint();
  EXPECT_EQ(UseCase::kLoading, ForceUpdatePolicyAndGetCurrentUseCase());
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameMeaningfulPaint)
      .WillByDefault(Return(false));
  ON_CALL(*page_scheduler_, IsMainFrameLoading).WillByDefault(Return(false));
  scheduler_->OnMainFramePaint();
  EXPECT_EQ(UseCase::kNone, ForceUpdatePolicyAndGetCurrentUseCase());
  EXPECT_EQ(RAILMode::kDefault, GetRAILMode());
  scheduler_->RemoveRAILModeObserver(&observer);
}

TEST_P(
    MainThreadSchedulerImplWithLoadingPhaseBufferTimeAfterFirstMeaningfulPaintTest,
    TestLoadRAILModeWhileHidden) {
  InSequence s;
  MockRAILModeObserver observer;
  EXPECT_CALL(observer, OnRAILModeChanged(RAILMode::kDefault));
  scheduler_->AddRAILModeObserver(&observer);
  scheduler_->SetAllRenderWidgetsHidden(true);

  ON_CALL(*page_scheduler_, IsWaitingForMainFrameContentfulPaint)
      .WillByDefault(Return(true));
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameMeaningfulPaint)
      .WillByDefault(Return(true));
  ON_CALL(*page_scheduler_, IsMainFrameLoading).WillByDefault(Return(true));

  // Because the widget is hidden, the mode should still be kDefault while
  // loading.
  scheduler_->DidStartProvisionalLoad(true);
  EXPECT_EQ(RAILMode::kDefault, GetRAILMode());
  EXPECT_EQ(UseCase::kEarlyLoading, ForceUpdatePolicyAndGetCurrentUseCase());
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameContentfulPaint)
      .WillByDefault(Return(false));
  scheduler_->OnMainFramePaint();
  EXPECT_EQ(UseCase::kLoading, ForceUpdatePolicyAndGetCurrentUseCase());
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameMeaningfulPaint)
      .WillByDefault(Return(false));
  ON_CALL(*page_scheduler_, IsMainFrameLoading).WillByDefault(Return(false));
  scheduler_->OnMainFramePaint();
  EXPECT_EQ(UseCase::kNone, ForceUpdatePolicyAndGetCurrentUseCase());
  EXPECT_EQ(RAILMode::kDefault, GetRAILMode());
  scheduler_->RemoveRAILModeObserver(&observer);
}

TEST_P(
    MainThreadSchedulerImplWithLoadingPhaseBufferTimeAfterFirstMeaningfulPaintTest,
    InputTerminatesLoadRAILMode) {
  InSequence s;
  MockRAILModeObserver observer;
  EXPECT_CALL(observer, OnRAILModeChanged(RAILMode::kDefault));
  EXPECT_CALL(observer, OnRAILModeChanged(RAILMode::kLoad));
  EXPECT_CALL(observer, OnRAILModeChanged(RAILMode::kDefault));
  scheduler_->AddRAILModeObserver(&observer);

  ON_CALL(*page_scheduler_, IsWaitingForMainFrameContentfulPaint)
      .WillByDefault(Return(true));
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameMeaningfulPaint)
      .WillByDefault(Return(true));
  ON_CALL(*page_scheduler_, IsMainFrameLoading).WillByDefault(Return(true));
  scheduler_->DidStartProvisionalLoad(true);
  EXPECT_EQ(RAILMode::kLoad, GetRAILMode());
  EXPECT_EQ(UseCase::kEarlyLoading, ForceUpdatePolicyAndGetCurrentUseCase());
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollBegin),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  EXPECT_EQ(UseCase::kCompositorGesture,
            ForceUpdatePolicyAndGetCurrentUseCase());
  EXPECT_EQ(RAILMode::kDefault, GetRAILMode());
  scheduler_->RemoveRAILModeObserver(&observer);
}

TEST_F(MainThreadSchedulerImplTest, UnthrottledTaskRunner) {
  // Ensure neither suspension nor throttleable task throttling affects an
  // unthrottled task runner.
  SimulateCompositorGestureStart(TouchEventPolicy::kSendTouchStart);
  scoped_refptr<MainThreadTaskQueue> unthrottled_task_queue =
      NewUnpausableTaskQueue();

  size_t throttleable_count = 0;
  size_t unthrottled_count = 0;
  throttleable_task_runner_->PostTask(
      FROM_HERE,
      base::BindOnce(SlowCountingTask, &throttleable_count, test_task_runner_,
                     7, throttleable_task_runner_));
  unthrottled_task_queue->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE,
      base::BindOnce(
          SlowCountingTask, &unthrottled_count, test_task_runner_, 7,
          unthrottled_task_queue->GetTaskRunnerWithDefaultTaskType()));
  auto handle = scheduler_->PauseScheduler();

  for (int i = 0; i < 1000; i++) {
    viz::BeginFrameArgs begin_frame_args = viz::BeginFrameArgs::Create(
        BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
        base::TimeTicks(), base::Milliseconds(16), viz::BeginFrameArgs::NORMAL);
    begin_frame_args.on_critical_path = true;
    scheduler_->WillBeginFrame(begin_frame_args);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);

    compositor_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&MainThreadSchedulerImplTest::
                           SimulateMainThreadCompositorAndQuitRunLoopTask,
                       base::Unretained(this), base::Milliseconds(10)));

    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(UseCase::kSynchronizedGesture, CurrentUseCase()) << "i = " << i;
  }

  EXPECT_EQ(0u, throttleable_count);
  EXPECT_EQ(500u, unthrottled_count);
}

TEST_F(MainThreadSchedulerImplTest, EnableVirtualTime) {
  EXPECT_FALSE(scheduler_->IsVirtualTimeEnabled());
  scheduler_->EnableVirtualTime(base::Time());
  EXPECT_TRUE(scheduler_->IsVirtualTimeEnabled());
  EXPECT_TRUE(scheduler_->GetVirtualTimeDomain());
}

TEST_F(MainThreadSchedulerImplTest, DisableVirtualTimeForTesting) {
  scheduler_->EnableVirtualTime(base::Time());
  scheduler_->DisableVirtualTimeForTesting();
  EXPECT_FALSE(scheduler_->IsVirtualTimeEnabled());
}

TEST_F(MainThreadSchedulerImplTest, VirtualTimePauser) {
  scheduler_->EnableVirtualTime(base::Time());
  scheduler_->SetVirtualTimePolicy(
      VirtualTimeController::VirtualTimePolicy::kDeterministicLoading);

  WebScopedVirtualTimePauser pauser(
      scheduler_.get(),
      WebScopedVirtualTimePauser::VirtualTaskDuration::kInstant, "test");

  base::TimeTicks before = scheduler_->NowTicks();
  EXPECT_TRUE(scheduler_->VirtualTimeAllowedToAdvance());
  pauser.PauseVirtualTime();
  EXPECT_FALSE(scheduler_->VirtualTimeAllowedToAdvance());

  pauser.UnpauseVirtualTime();
  EXPECT_TRUE(scheduler_->VirtualTimeAllowedToAdvance());
  base::TimeTicks after = scheduler_->NowTicks();
  EXPECT_EQ(after, before);
}

TEST_F(MainThreadSchedulerImplTest, VirtualTimePauserNonInstantTask) {
  scheduler_->EnableVirtualTime(base::Time());
  scheduler_->SetVirtualTimePolicy(
      VirtualTimeController::VirtualTimePolicy::kDeterministicLoading);

  WebScopedVirtualTimePauser pauser(
      scheduler_.get(),
      WebScopedVirtualTimePauser::VirtualTaskDuration::kNonInstant, "test");

  base::TimeTicks before = scheduler_->NowTicks();
  pauser.PauseVirtualTime();
  pauser.UnpauseVirtualTime();
  base::TimeTicks after = scheduler_->NowTicks();
  EXPECT_GT(after, before);
}

TEST_F(MainThreadSchedulerImplTest, VirtualTimeWithOneQueueWithoutVirtualTime) {
  // This test ensures that we do not do anything strange like stopping
  // processing task queues after we encountered one task queue with
  // DoNotUseVirtualTime trait.
  scheduler_->EnableVirtualTime(base::Time());
  scheduler_->SetVirtualTimePolicy(
      VirtualTimeController::VirtualTimePolicy::kDeterministicLoading);

  WebScopedVirtualTimePauser pauser(
      scheduler_.get(),
      WebScopedVirtualTimePauser::VirtualTaskDuration::kNonInstant, "test");

  // Test will pass if the queue without virtual is the last one in the
  // iteration order. Create 100 of them and ensure that it is created in the
  // middle.
  std::vector<scoped_refptr<MainThreadTaskQueue>> task_queues;
  constexpr int kTaskQueueCount = 100;

  for (size_t i = 0; i < kTaskQueueCount; ++i) {
    task_queues.push_back(scheduler_->NewTaskQueue(
        MainThreadTaskQueue::QueueCreationParams(
            MainThreadTaskQueue::QueueType::kFrameThrottleable)
            .SetCanRunWhenVirtualTimePaused(i == 42)));
  }

  // This should install a fence on all queues with virtual time.
  pauser.PauseVirtualTime();

  int counter = 0;

  for (const auto& task_queue : task_queues) {
    task_queue->GetTaskRunnerWithDefaultTaskType()->PostTask(
        FROM_HERE, base::BindOnce([](int* counter) { ++*counter; }, &counter));
  }

  // Only the queue without virtual time should run, all others should be
  // blocked by their fences.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(counter, 1);

  pauser.UnpauseVirtualTime();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(counter, kTaskQueueCount);
}

TEST_F(MainThreadSchedulerImplTest, Tracing) {
  // This test sets renderer scheduler to some non-trivial state
  // (by posting tasks, creating child schedulers, etc) and converts it into a
  // traced value. This test checks that no internal checks fire during this.

  std::unique_ptr<PageSchedulerImpl> page_scheduler1 =
      CreatePageScheduler(nullptr, scheduler_.get(), *agent_group_scheduler_);
  scheduler_->AddPageScheduler(page_scheduler1.get());

  std::unique_ptr<FrameSchedulerImpl> frame_scheduler =
      CreateFrameScheduler(page_scheduler1.get(), nullptr,
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kSubframe);

  std::unique_ptr<PageSchedulerImpl> page_scheduler2 =
      CreatePageScheduler(nullptr, scheduler_.get(), *agent_group_scheduler_);
  scheduler_->AddPageScheduler(page_scheduler2.get());

  std::unique_ptr<CPUTimeBudgetPool> time_budget_pool =
      scheduler_->CreateCPUTimeBudgetPoolForTesting("test");

  throttleable_task_queue()->AddToBudgetPool(base::TimeTicks(),
                                             time_budget_pool.get());

  throttleable_task_runner_->PostTask(FROM_HERE, base::BindOnce(NullTask));

  loading_task_queue()->GetTaskRunnerWithDefaultTaskType()->PostDelayedTask(
      FROM_HERE, base::BindOnce(NullTask), base::Milliseconds(10));

  scheduler_->CreateTraceEventObjectSnapshot();
}

TEST_F(MainThreadSchedulerImplTest,
       LogIpcsPostedToDocumentsInBackForwardCache) {
  base::HistogramTester histogram_tester;

  // Start recording IPCs immediately.
  base::FieldTrialParams params;
  params["delay_before_tracking_ms"] = "0";
  base::test::ScopedFeatureList scoped_feature_list;
  scoped_feature_list.InitAndEnableFeatureWithParameters(
      blink::features::kLogUnexpectedIPCPostedToBackForwardCachedDocuments,
      params);

  // Store documents inside the back-forward cache. IPCs are only tracked IFF
  // all pages are in the back-forward cache.
  PageSchedulerImpl* page_scheduler = page_scheduler_.get();
  page_scheduler->SetPageBackForwardCached(true);
  base::RunLoop().RunUntilIdle();
  {
    base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash(1);
    default_task_runner_->PostTask(FROM_HERE, base::DoNothing());
  }
  base::RunLoop().RunUntilIdle();

  // Adding a new page scheduler results in IPCs not being logged, as this
  // page scheduler is not in the cache.
  std::unique_ptr<PageSchedulerImpl> page_scheduler1 =
      CreatePageScheduler(nullptr, scheduler_.get(), *agent_group_scheduler_);
  scheduler_->AddPageScheduler(page_scheduler1.get());
  base::RunLoop().RunUntilIdle();
  {
    base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash(2);
    default_task_runner_->PostTask(FROM_HERE, base::DoNothing());
  }
  base::RunLoop().RunUntilIdle();

  // Removing an un-cached page scheduler results in IPCs being logged, as all
  // page schedulers are now in the cache.
  page_scheduler1.reset();
  base::RunLoop().RunUntilIdle();
  {
    base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash(3);
    default_task_runner_->PostTask(FROM_HERE, base::DoNothing());
  }
  base::RunLoop().RunUntilIdle();

  // When a page is restored from the back-forward cache, IPCs should not be
  // recorded anymore, as not all pages are in the cache.
  page_scheduler->SetPageBackForwardCached(false);
  base::RunLoop().RunUntilIdle();
  {
    base::TaskAnnotator::ScopedSetIpcHash scoped_set_ipc_hash(4);
    default_task_runner_->PostTask(FROM_HERE, base::DoNothing());
  }
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(
      histogram_tester.GetAllSamples(
          "BackForwardCache.Experimental."
          "UnexpectedIPCMessagePostedToCachedFrame.MethodHash"),
      testing::UnorderedElementsAre(base::Bucket(1, 1), base::Bucket(3, 1)));
}

void RecordingTimeTestTask(
    Vector<base::TimeTicks>* run_times,
    scoped_refptr<base::TestMockTimeTaskRunner> task_runner) {
  run_times->push_back(task_runner->GetMockTickClock()->NowTicks());
}

TEST_F(MainThreadSchedulerImplTest, LoadingControlTasks) {
  // Expect control loading tasks (M) to jump ahead of any regular loading
  // tasks (L).
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 L2 M1 L3 L4 M2 L5 L6");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("M1", "M2", "L1", "L2", "L3",
                                              "L4", "L5", "L6"));
}

TEST_F(MainThreadSchedulerImplTest, RequestBeginMainFrameNotExpected) {
  scheduler_->OnPendingTasksChanged(true);
  EXPECT_CALL(*page_scheduler_, RequestBeginMainFrameNotExpected(true))
      .Times(1)
      .WillRepeatedly(testing::Return(true));
  base::RunLoop().RunUntilIdle();

  Mock::VerifyAndClearExpectations(page_scheduler_.get());

  scheduler_->OnPendingTasksChanged(false);
  EXPECT_CALL(*page_scheduler_, RequestBeginMainFrameNotExpected(false))
      .Times(1)
      .WillRepeatedly(testing::Return(true));
  base::RunLoop().RunUntilIdle();

  Mock::VerifyAndClearExpectations(page_scheduler_.get());
}

TEST_F(MainThreadSchedulerImplTest,
       RequestBeginMainFrameNotExpected_MultipleCalls) {
  scheduler_->OnPendingTasksChanged(true);
  scheduler_->OnPendingTasksChanged(true);
  // Multiple calls should result in only one call.
  EXPECT_CALL(*page_scheduler_, RequestBeginMainFrameNotExpected(true))
      .Times(1)
      .WillRepeatedly(testing::Return(true));
  base::RunLoop().RunUntilIdle();

  Mock::VerifyAndClearExpectations(page_scheduler_.get());
}

#if BUILDFLAG(IS_ANDROID)
TEST_F(MainThreadSchedulerImplTest, PauseTimersForAndroidWebView) {
  // Tasks in some queues don't fire when the throttleable queues are paused.
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 C1 L1 I1 T1");
  scheduler_->PauseTimersForAndroidWebView();
  EnableIdleTasks();
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "C1", "L1", "I1"));
  // The rest queued tasks fire when the throttleable queues are resumed.
  run_order.clear();
  scheduler_->ResumeTimersForAndroidWebView();
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_THAT(run_order, testing::ElementsAre("T1"));
}
#endif  // BUILDFLAG(IS_ANDROID)

TEST_F(MainThreadSchedulerImplTest, FreezesCompositorQueueWhenAllPagesFrozen) {
  main_frame_scheduler_.reset();
  page_scheduler_.reset();

  std::unique_ptr<PageScheduler> sched_1 =
      agent_group_scheduler_->CreatePageScheduler(nullptr);
  sched_1->SetPageVisible(false);
  std::unique_ptr<PageScheduler> sched_2 =
      agent_group_scheduler_->CreatePageScheduler(nullptr);
  sched_2->SetPageVisible(false);

  Vector<String> run_order;

  sched_1->SetPageVisible(false);
  sched_1->SetPageFrozen(true);
  PostTestTasks(&run_order, "D1 C1");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "C1"));

  run_order.clear();
  sched_2->SetPageFrozen(true);
  PostTestTasks(&run_order, "D2 C2");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("D2"));

  run_order.clear();
  std::unique_ptr<PageScheduler> sched_3 =
      agent_group_scheduler_->CreatePageScheduler(nullptr);
  sched_3->SetPageVisible(false);
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("C2"));

  run_order.clear();
  PostTestTasks(&run_order, "D3 C3");
  sched_3.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("D3"));

  run_order.clear();
  sched_1.reset();
  sched_2.reset();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("C3"));
}

class MainThreadSchedulerImplWithInitalVirtualTimeTest
    : public MainThreadSchedulerImplTest {
 public:
  void SetUp() override {
    CreateTestTaskRunner();
    auto main_thread_scheduler =
        std::make_unique<MainThreadSchedulerImplForTest>(
            base::sequence_manager::SequenceManagerForTest::Create(
                nullptr, test_task_runner_,
                test_task_runner_->GetMockTickClock(),
                base::sequence_manager::SequenceManager::Settings::Builder()
                    .SetRandomisedSamplingEnabled(true)
                    .SetPrioritySettings(CreatePrioritySettings())
                    .Build()));
    main_thread_scheduler->EnableVirtualTime(
        /* initial_time= */ base::Time::FromMillisecondsSinceUnixEpoch(
            1000000.0));
    main_thread_scheduler->SetVirtualTimePolicy(
        VirtualTimeController::VirtualTimePolicy::kPause);
    Initialize(std::move(main_thread_scheduler));
  }
};

TEST_F(MainThreadSchedulerImplWithInitalVirtualTimeTest, VirtualTimeOverride) {
  EXPECT_TRUE(scheduler_->IsVirtualTimeEnabled());
  EXPECT_EQ(VirtualTimeController::VirtualTimePolicy::kPause,
            scheduler_->GetVirtualTimePolicyForTest());
  EXPECT_EQ(base::Time::Now(),
            base::Time::FromMillisecondsSinceUnixEpoch(1000000.0));
}

TEST_F(MainThreadSchedulerImplTest, CompositingAfterInput) {
  Vector<String> run_order;

  // Input tasks don't cause compositor tasks to be prioritized unless an input
  // event was handled.
  PostTestTasks(&run_order, "P1 T1 C1 C2");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("P1", "T1", "C1", "C2"));
  run_order.clear();

  // Tasks with input events cause compositor tasks to be prioritized until a
  // BeginMainFrame runs.
  PostTestTasks(&run_order, "T1 P1 PD1 C1 C2 CM1 C2 T2 CM2");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("P1", "PD1", "C1", "C2", "CM1",
                                              "T1", "C2", "T2", "CM2"));
  run_order.clear();

  // Input tasks and compositor tasks will be interleaved because they have the
  // same priority.
  PostTestTasks(&run_order, "T1 PD1 C1 PD2 C2 CM1");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("PD1", "C1", "PD2", "C2", "CM1", "T1"));
  run_order.clear();
}

TEST_F(MainThreadSchedulerImplTest,
       CompositorNotPrioritizedAfterContinuousInput) {
  Vector<String> run_order;

  // rAF-aligned input should not cause the next frame to be prioritized.
  PostTestTasks(&run_order, "P1 T1 CI1 T2 CI2 T3 CM1");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("P1", "T1", "CI1", "T2", "CI2",
                                              "T3", "CM1"));
  run_order.clear();

  // Continuous input that runs outside of rAF should not cause the next frame
  // to be prioritized.
  PostTestTasks(&run_order, "PC1 T1 CM1 T2 CM2");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("PC1", "T1", "CM1", "T2", "CM2"));
  run_order.clear();
}

TEST_F(MainThreadSchedulerImplTest, TaskQueueReferenceClearedOnShutdown) {
  // Ensure that the scheduler clears its references to a task queue after
  // |shutdown| and doesn't try to update its policies.
  scoped_refptr<MainThreadTaskQueue> queue1 =
      scheduler_->NewThrottleableTaskQueueForTest(nullptr);
  scoped_refptr<MainThreadTaskQueue> queue2 =
      scheduler_->NewThrottleableTaskQueueForTest(nullptr);

  EXPECT_TRUE(queue1->IsQueueEnabled());
  EXPECT_TRUE(queue2->IsQueueEnabled());

  scheduler_->OnShutdownTaskQueue(queue1);

  auto pause_handle = scheduler_->PauseScheduler();

  // queue2 should be disabled, as it is a regular queue and nothing should
  // change for queue1 because it was shut down.
  EXPECT_TRUE(queue1->IsQueueEnabled());
  EXPECT_FALSE(queue2->IsQueueEnabled());
}

TEST_F(MainThreadSchedulerImplTest, MicrotaskCheckpointTiming) {
  base::RunLoop().RunUntilIdle();

  base::TimeTicks start_time = Now();
  RecordingTaskTimeObserver observer;

  const base::TimeDelta kTaskTime = base::Milliseconds(100);
  const base::TimeDelta kMicrotaskTime = base::Milliseconds(200);
  default_task_runner_->PostTask(
      FROM_HERE,
      WTF::BindOnce(&MainThreadSchedulerImplTest::AdvanceMockTickClockBy,
                    base::Unretained(this), kTaskTime));
  scheduler_->on_microtask_checkpoint_ =
      WTF::BindOnce(&MainThreadSchedulerImplTest::AdvanceMockTickClockBy,
                    base::Unretained(this), kMicrotaskTime);

  scheduler_->AddTaskTimeObserver(&observer);
  base::RunLoop().RunUntilIdle();
  scheduler_->RemoveTaskTimeObserver(&observer);

  // Expect that the duration of microtask is counted as a part of the preceding
  // task.
  ASSERT_EQ(1u, observer.result().size());
  EXPECT_EQ(start_time, observer.result().front().first);
  EXPECT_EQ(start_time + kTaskTime +
```