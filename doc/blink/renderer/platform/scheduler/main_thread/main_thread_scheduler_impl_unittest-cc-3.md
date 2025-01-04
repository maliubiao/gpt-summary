Response:
The user wants a summary of the functionality of the provided C++ code. This code is a unit test file for `MainThreadSchedulerImpl` in the Chromium Blink rendering engine.

Here's a breakdown of the code's purpose and how it relates to web technologies:

1. **Core Functionality:** The code tests the scheduling of tasks on the main thread in the Blink engine. It verifies how different types of tasks (e.g., compositing, throttleable, loading) are prioritized and executed under various conditions.

2. **Relationship to JavaScript, HTML, CSS:** The main thread scheduler is crucial for the execution of JavaScript, the rendering of HTML and CSS, and handling user interactions. The tests simulate scenarios that directly impact how these web technologies perform.

3. **Logical Reasoning and Examples:** The tests often involve setting up specific conditions (e.g., a long-running compositor task, a gesture event) and then asserting the state of the scheduler or the order in which tasks are executed.

4. **User/Programming Errors:** While the code itself doesn't directly demonstrate user errors, the scenarios it tests are designed to prevent jank and unresponsiveness, which are common user-facing issues caused by improper task scheduling.

5. **Functionality Summary (Part 4):** This specific snippet focuses on testing various aspects of task scheduling, including:
    * Throttling of tasks during synchronized gestures.
    * Behavior during `touchstart` events.
    * Prioritization of compositing tasks.
    * Handling of main thread gestures and custom input handling.
    * RAIL mode transitions based on loading state and user interaction.
    * Behavior of unthrottled task runners.
    * Virtual time control and its interaction with different task queues.
    * Tracing of scheduler events.
    * Logging of IPCs posted to back-forward cached documents.
    * Prioritization of loading control tasks.
    * Requesting BeginMainFrame based on pending tasks.
    * Pausing timers for Android WebView.
    * Freezing the compositor queue when all pages are frozen.
    * Initial virtual time setup.
    * Compositing task prioritization after input events.
    * Handling of continuous input.
    * Clearing task queue references on shutdown.
    * Timing of microtasks.
这个C++代码文件是 `blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl_unittest.cc` 的一部分，它专门用于测试 `MainThreadSchedulerImpl` 类的功能。 `MainThreadSchedulerImpl` 负责管理Chromium Blink引擎中主线程上的任务调度。

**归纳一下这部分代码的功能：**

这部分代码主要测试了 `MainThreadSchedulerImpl` 在以下场景下的行为和功能：

1. **同步手势期间的节流任务处理 (SYNCHRONIZED_GESTURE_ThrottleableTaskThrottling_...)**:
   - 测试在用户进行同步手势（如滚动）时，可节流任务队列的节流机制。
   - 验证在合成器任务占用大量时间的情况下，可节流任务是否会被正确地暂停或执行。
   - **与JavaScript, HTML, CSS的关系**:  流畅的滚动体验依赖于高效的任务调度。JavaScript中的事件监听器可能会触发一些需要在主线程上执行的任务。如果这些任务没有被正确节流，可能会导致滚动卡顿。
   - **假设输入与输出**:
     - **假设输入**: 模拟一个同步手势开始，并向可节流队列中添加一个耗时较长的任务。同时模拟合成器线程执行耗时任务。
     - **预期输出**: 验证在合成器任务繁忙时，可节流任务队列会被暂停，以保证合成器任务的优先级，从而保证滚动的流畅性。反之，如果可节流任务耗时较短，则能及时执行。

2. **`touchstart` 期间禁止长时间空闲 (DenyLongIdleDuringTouchStart)**:
   - 测试在 `touchstart` 事件发生后的一段时间内，系统是否会拒绝进入长时间空闲状态。
   - **与JavaScript, HTML, CSS的关系**:  `touchstart` 事件通常标志着用户与页面进行交互的开始。为了保证交互的响应速度，系统会避免进入长时间空闲状态，以便及时处理后续的交互事件。
   - **假设输入与输出**:
     - **假设输入**: 模拟在合成器线程上接收到一个 `touchstart` 事件。
     - **预期输出**: 调用 `CanEnterLongIdlePeriod` 方法应返回 `false`，且 `next_time_to_check` 会返回一个非负的时间差，表示需要过一段时间才能再次检查是否可以进入空闲。

3. **同步手势期间合成器任务耗时较长时的处理 (SYNCHRONIZED_GESTURE_CompositingExpensive)**:
   - 测试当合成器任务耗时较长时，调度器是否会避免过度优先处理合成器任务，以防止其他类型的任务（如可节流任务）被饿死。
   - **与JavaScript, HTML, CSS的关系**:  合成器负责页面的绘制。如果合成器任务耗时过长，可能会导致页面渲染延迟。但同时，主线程上的其他任务（如JavaScript执行）也需要得到执行。
   - **假设输入与输出**:
     - **假设输入**: 模拟一个同步手势开始，并设置合成器任务的执行时间较长。同时向可节流队列添加一些任务。
     - **预期输出**: 验证即使合成器任务耗时较长，可节流任务也应该能够得到执行，并且合成器任务的优先级不会被提升到最高，避免饿死其他任务。

4. **主线程自定义输入处理 (MAIN_THREAD_CUSTOM_INPUT_HANDLING)**:
   - 测试当输入事件被转发到主线程进行自定义处理时，调度器的行为。
   - **与JavaScript, HTML, CSS的关系**:  开发者可以通过JavaScript来监听和处理特定的输入事件，实现自定义的交互逻辑。
   - **假设输入与输出**:
     - **假设输入**: 模拟一个手势开始，并将后续的 `touchmove` 事件转发到主线程处理。同时模拟合成器线程执行耗时任务，并向可节流队列添加任务。
     - **预期输出**: 验证调度器处于 `kMainThreadCustomInputHandling` 用例，并且即使合成器任务耗时，可节流任务也应该能够得到执行，避免被饿死。

5. **主线程手势 (MAIN_THREAD_GESTURE)**:
   - 测试当整个手势处理都在主线程上进行时，调度器的行为。
   - **与JavaScript, HTML, CSS的关系**:  某些手势可能不需要合成器线程的参与，而完全在主线程上处理。
   - **假设输入与输出**:
     - **假设输入**: 模拟一个手势开始，后续的 `gestureScrollUpdate` 事件被转发到主线程处理。同时模拟合成器线程执行耗时任务，并向可节流队列添加任务。
     - **预期输出**: 验证调度器处于 `kMainThreadGesture` 用例，并且合成器任务的优先级会被提升到最高，可能会导致可节流任务被饿死，因为主线程手势的响应需要优先保证。

6. **RAIL模式观察者 (TestDefaultRAILMode, TestLoadRAILMode 等)**:
   - 测试 `RAILModeObserver` 接口以及在不同场景下（如页面加载）RAIL模式的切换。
   - **与JavaScript, HTML, CSS的关系**: RAIL (Response, Animation, Idle, Load) 是一种性能模型，用于指导Web应用程序的性能优化。调度器需要根据当前的RAIL模式来调整任务的优先级。
   - **假设输入与输出**:
     - **假设输入**: 模拟页面加载开始、First Contentful Paint (FCP)、Meaningful Paint (MP) 事件，以及用户输入事件。
     - **预期输出**: 验证在不同的加载阶段和用户交互阶段，RAIL模式会正确切换（例如，从 `kDefault` 到 `kLoad`，再到 `kDefault`），并且当前的UseCase也会相应变化。

7. **非节流任务运行器 (UnthrottledTaskRunner)**:
   - 测试非节流任务运行器在调度器暂停和节流机制下的行为，确保非节流任务不受影响。
   - **与JavaScript, HTML, CSS的关系**:  某些关键任务可能需要立即执行，不应该受到节流的限制。
   - **假设输入与输出**:
     - **假设输入**: 模拟一个同步手势开始，并同时向可节流和非节流队列添加任务，然后暂停调度器。
     - **预期输出**: 验证在调度器暂停期间，可节流任务不会执行，但非节流任务会正常执行。

8. **虚拟时间控制 (EnableVirtualTime, DisableVirtualTimeForTesting, VirtualTimePauser 等)**:
   - 测试虚拟时间功能，允许在测试中控制时间的流逝，以便更方便地测试时间相关的逻辑。
   - **与JavaScript, HTML, CSS的关系**:  许多Web API和功能依赖于时间，例如 `setTimeout`, `requestAnimationFrame` 等。虚拟时间可以帮助测试这些功能的行为。
   - **假设输入与输出**:
     - **假设输入**: 启用虚拟时间，设置不同的虚拟时间策略，并使用 `WebScopedVirtualTimePauser` 来暂停和恢复虚拟时间的流逝。
     - **预期输出**: 验证 `IsVirtualTimeEnabled` 的状态是否正确，虚拟时间是否按预期暂停和恢复，以及在不同虚拟时间策略下任务的执行情况。

9. **追踪 (Tracing)**:
   - 测试调度器的追踪功能，确保在记录调度器状态时不会发生内部错误。
   - **与JavaScript, HTML, CSS的关系**:  追踪信息可以帮助开发者分析性能瓶颈，了解任务的执行顺序和耗时。

10. **记录发送到后退/前进缓存文档的IPC (LogIpcsPostedToDocumentsInBackForwardCache)**:
    - 测试是否能正确记录发送到后退/前进缓存中的文档的进程间通信 (IPC) 消息。
    - **与JavaScript, HTML, CSS的关系**:  后退/前进缓存是为了提升页面导航性能而设计的。记录发送到缓存页面的IPC有助于诊断潜在的问题。
    - **假设输入与输出**:
        - **假设输入**:  将页面放入后退/前进缓存，然后尝试向该页面发送IPC消息。
        - **预期输出**: 验证相应的直方图记录了这些IPC消息的方法哈希。

11. **加载控制任务 (LoadingControlTasks)**:
    - 测试加载控制任务的优先级高于普通加载任务。
    - **与JavaScript, HTML, CSS的关系**: 加载控制任务通常与关键资源的加载有关，需要优先执行以尽快呈现页面内容。
    - **假设输入与输出**:
        - **假设输入**:  向加载队列中添加普通加载任务和加载控制任务。
        - **预期输出**: 验证加载控制任务会在普通加载任务之前执行。

12. **请求不期望的BeginMainFrame (RequestBeginMainFrameNotExpected)**:
    - 测试在任务队列状态变化时，是否会正确请求或取消 BeginMainFrame。
    - **与JavaScript, HTML, CSS的关系**: BeginMainFrame 信号触发渲染流程，调度器需要根据是否有待处理的任务来决定是否需要触发。

13. **为Android WebView暂停定时器 (PauseTimersForAndroidWebView)**:
    - 测试在 Android WebView 环境下暂停和恢复定时器的功能。
    - **与JavaScript, HTML, CSS的关系**:  `setTimeout` 和 `setInterval` 等 JavaScript 定时器在 WebView 中可能需要特殊的处理。

14. **当所有页面都冻结时冻结合成器队列 (FreezesCompositorQueueWhenAllPagesFrozen)**:
    - 测试当所有页面都处于冻结状态时，合成器任务队列是否会被冻结。
    - **与JavaScript, HTML, CSS的关系**:  页面冻结是一种优化手段，用于减少后台页面的资源消耗。

15. **具有初始虚拟时间的MainThreadScheduler (MainThreadSchedulerImplWithInitalVirtualTimeTest)**:
    - 测试在启用虚拟时间时，是否可以设置初始时间。

16. **输入后的合成 (CompositingAfterInput)**:
    - 测试在处理输入事件后，合成器任务的优先级是否会提升。
    - **与JavaScript, HTML, CSS的关系**:  为了保证用户交互的流畅性，在处理输入事件后，需要优先执行合成器任务来更新页面渲染。

17. **连续输入后不优先处理合成器 (CompositorNotPrioritizedAfterContinuousInput)**:
    - 测试在连续输入事件之后，是否不会持续优先处理合成器任务，以避免饿死其他任务。

18. **在关闭时清除任务队列引用 (TaskQueueReferenceClearedOnShutdown)**:
    - 测试在任务队列关闭后，调度器是否会清除对该队列的引用。

19. **微任务检查点计时 (MicrotaskCheckpointTiming)**:
    - 测试微任务执行的时间是否被正确计入到前一个任务的执行时间中。
    - **与JavaScript, HTML, CSS的关系**: 微任务是 JavaScript 执行模型的一部分，它们会在当前任务执行完成后立即执行。

**用户或编程常见的使用错误举例说明：**

* **错误地假设可节流任务总能及时执行**: 开发者可能会错误地认为提交到可节流队列的任务会立即执行，而没有考虑到在繁忙的渲染或合成期间，这些任务可能会被延迟。这可能导致UI更新不及时。
* **在 `touchstart` 事件处理中执行耗时操作**: 如果开发者在 `touchstart` 事件处理程序中执行了大量同步的JavaScript代码，可能会阻塞主线程，导致后续的触摸事件响应延迟，影响用户体验。
* **过度依赖主线程进行手势处理**: 将所有手势处理逻辑都放在主线程上执行，可能会导致在手势操作期间主线程过于繁忙，影响性能。应该尽可能利用合成器线程来处理手势。
* **不理解RAIL模型对任务调度的影响**: 开发者可能没有意识到当前所处的RAIL模式会影响任务的优先级，导致在页面加载或交互阶段出现性能问题。

总而言之，这部分代码通过大量的单元测试，细致地验证了 `MainThreadSchedulerImpl` 在各种复杂场景下的任务调度行为，确保了Blink引擎在处理用户交互、页面渲染和JavaScript执行时的性能和稳定性。这些测试覆盖了与Web前端技术（JavaScript, HTML, CSS）密切相关的各种场景，旨在预防潜在的性能问题和错误行为。

Prompt: 
```
这是目录为blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第4部分，共6部分，请归纳一下它的功能

"""
refptr<base::SingleThreadTaskRunner> throttleable_queue) {
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
"""


```