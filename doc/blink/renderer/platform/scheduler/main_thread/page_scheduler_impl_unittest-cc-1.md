Response:
The user wants to understand the functionality of the provided C++ code snippet, which is part of a unit test file for `PageSchedulerImpl` in the Chromium Blink engine.

Here's a breakdown of the thought process to analyze the code and fulfill the user's request:

1. **Identify the Core Class Under Test:** The file name `page_scheduler_impl_unittest.cc` and the test fixture name `PageSchedulerImplTest` clearly indicate that the code is testing the `PageSchedulerImpl` class.

2. **Recognize the Test Structure:** The code uses the Google Test framework (`TEST_F`). Each `TEST_F` function represents a distinct test case for a specific aspect of `PageSchedulerImpl`'s behavior.

3. **Analyze Individual Test Cases:**  Go through each `TEST_F` function and determine its purpose. Look for:
    * **Setup:** What objects are being created and initialized? (e.g., `PageSchedulerImpl`, `FrameSchedulerImpl`, `VirtualTimeController`, `TestMockTimeTaskRunner`).
    * **Actions:** What methods of `PageSchedulerImpl` or related classes are being called? (e.g., `PostDelayedTask`, `SetVirtualTimePolicy`, `PauseVirtualTime`, `UnpauseVirtualTime`, `OnTaskStarted`, `OnTaskCompleted`, `SetPageVisible`, `AudioStateChanged`, `SetPageFrozen`, `GrantVirtualTimeBudget`, `RegisterFeature`).
    * **Assertions:** What are the expected outcomes, checked using `EXPECT_EQ`, `EXPECT_TRUE`, `EXPECT_FALSE`, `EXPECT_THAT`?

4. **Identify Key Concepts:** As you analyze the test cases, note the recurring themes and concepts being tested. In this snippet, the prominent concepts are:
    * **Virtual Time:**  The use of `VirtualTimeController` and `WebScopedVirtualTimePauser` suggests testing the behavior of the scheduler under controlled, simulated time. Different `VirtualTimePolicy` values (e.g., `kDeterministicLoading`, `kPause`, `kAdvance`) indicate different modes of virtual time progression.
    * **Task Scheduling:** The use of `PostDelayedTask`, `ThrottleableTaskRunner`, and the manipulation of work batch sizes hint at testing how tasks are scheduled and executed.
    * **Page Visibility and Freezing:** Tests involving `SetPageVisible` and `SetPageFrozen` are checking the scheduler's behavior when the page becomes backgrounded or explicitly frozen.
    * **Audio State:** Tests related to `AudioStateChanged` explore how the scheduler reacts to audio playback status.
    * **Background Throttling:** Tests involving `IsCPUTimeThrottled` and the `ExpensiveTestTask` are likely related to how the scheduler manages resource usage for background tabs.
    * **WebSocket Exemption:** A test specifically checks if having an open WebSocket connection affects background throttling.
    * **Nested Message Loops:**  A test case examines the interaction of virtual time with nested message loops.

5. **Relate to Web Technologies (JavaScript, HTML, CSS):** Consider how the tested functionalities might relate to web development:
    * **JavaScript Timers (setTimeout, setInterval):** The virtual time tests directly relate to how JavaScript timers behave, especially in scenarios with background tabs or controlled execution.
    * **RequestAnimationFrame:** While not explicitly mentioned, the frame scheduler and the concept of synchronizing with rendering frames are related to `requestAnimationFrame`.
    * **Page Lifecycle Events (visibilitychange, freeze, resume):** The tests for page visibility and freezing directly correspond to these browser events and how the browser manages resources for inactive tabs.
    * **WebSockets:** The test about WebSocket exemption from throttling demonstrates how certain important background activities can bypass resource restrictions.
    * **Audio and Media Playback:** The audio state tests are relevant to how browsers handle tabs playing audio and the implications for background processing.

6. **Infer Logical Reasoning and Assumptions:**  For tests involving virtual time, identify the assumptions about how virtual time advances and how different policies affect task execution order and timing. For example, in the `PauseAndUnpauseVirtualTime` test, the assumption is that pausing and unpausing virtual time with a `WebScopedVirtualTimePauser` will introduce a specific delay.

7. **Identify Potential User/Programming Errors:** Think about common mistakes developers might make that these tests aim to prevent. Examples include:
    * **Incorrectly assuming timers will fire precisely when set in background tabs.** The throttling and freezing tests highlight this.
    * **Not understanding how virtual time affects the execution of asynchronous operations.** The virtual time tests help ensure developers understand these nuances in testing environments.
    * **Failing to account for the browser's resource management strategies for background tabs.** The throttling and freezing tests demonstrate these mechanisms.

8. **Synthesize the Information:**  Organize the findings into a coherent summary, grouping related functionalities together. Use clear and concise language, and provide specific examples to illustrate the points.

9. **Address the "Part 2" Request:**  Since this is "part 2," focus on summarizing the overall functionality of the *provided code snippet* rather than the entire test file (assuming a "part 1" existed previously).

**Self-Correction/Refinement During the Process:**

* **Initial thought:**  Focus only on the C++ aspects.
* **Correction:** Realize the prompt specifically asks for connections to JavaScript, HTML, and CSS, requiring a higher-level understanding of how these scheduler features relate to web development.
* **Initial thought:** Summarize each test case individually.
* **Refinement:** Group related test cases by the functionality they are testing (e.g., virtual time, page visibility, audio state) for a more organized and insightful summary.
* **Initial thought:**  Only describe *what* the tests do.
* **Refinement:** Explain *why* these tests are important and what potential issues they are designed to catch. This adds more value to the user's understanding.
好的，这是对提供的代码片段的功能归纳：

**功能归纳:**

这部分单元测试主要集中在 `PageSchedulerImpl` 中与**虚拟时间控制**、**后台节流和冻结**以及**音频状态**相关的行为测试。具体来说，它测试了以下几个方面：

1. **虚拟时间控制 (Virtual Time Control):**
   - 测试在不同的虚拟时间策略 (`kDeterministicLoading`, `kPause`, `kAdvance`) 下，任务的执行顺序和时间推进是否符合预期。
   - 测试 `WebScopedVirtualTimePauser` 如何暂停和恢复虚拟时间，以及多个 pauser 协同工作的情况。
   - 测试虚拟时间预算 (budget) 的机制，当预算耗尽时，任务是否会暂停执行，并触发相应的回调。
   - 测试在嵌套消息循环中虚拟时间的推进是否正确。
   - 测试最大虚拟时间任务饥饿计数 (MaxVirtualTimeTaskStarvationCount) 的作用，即在虚拟时间推进时，为了避免某些任务被无限期延迟，允许真实时间推进。

2. **后台节流和冻结 (Background Throttling and Freezing):**
   - 测试在页面不可见时，定时器任务是否会被节流（延迟执行）。
   - 测试实验性功能 `ExpensiveBackgroundTimerThrottling` 的行为，验证后台定时器任务会受到 CPU 时间预算的限制。
   - 测试当页面有活动的 WebSocket 连接时，是否会豁免于后台节流策略。
   - 测试页面冻结机制，验证在页面不可见且静音一段时间后，任务队列中的任务会被暂停执行。
   - 测试页面从冻结状态恢复（变为可见）后，任务队列中的任务是否能正常执行。

3. **音频状态 (Audio State):**
   - 测试 `AudioStateChanged` 方法如何更新页面的音频播放状态。
   - 测试在音频播放状态变化后，页面是否会在一段时间内保持“可听见”状态，即使音频信号已经消失。
   - 测试可听见的页面是否不会被节流。
   - 测试页面冻结状态与音频播放状态的交互，例如，即使页面不可见，但正在播放音频，也不会立即被冻结。

**与 JavaScript, HTML, CSS 的关系及举例说明:**

这些测试覆盖的功能直接影响到网页中的 JavaScript 代码的行为，特别是在页面不可见或处于后台时：

* **JavaScript 定时器 (setTimeout, setInterval):**
    - **例 1 (后台节流):** 当一个页面不可见时，JavaScript 中通过 `setTimeout` 或 `setInterval` 设置的定时器回调的执行可能会被延迟。`BackgroundTimerThrottling` 测试验证了这种行为。
    - **例 2 (页面冻结):** 当页面被冻结后，定时器回调将不会被执行，直到页面被解冻。`PageFreezeAndSetVisible` 和 `PageFreezeAndUnfreeze` 测试了这种场景。

* **requestAnimationFrame:** 虽然代码中没有直接提到 `requestAnimationFrame`，但页面调度器负责管理帧的调度，`requestAnimationFrame` 的回调执行也受到页面可见性状态的影响。

* **WebSockets:**
    - **例 3:**  如果一个网页打开了一个 WebSocket 连接，即使该页面处于后台，为了保持连接的活跃，该页面的一些节流策略可能会被禁用。`OpenWebSocketExemptsFromBudgetThrottling` 测试了这种例外情况。

* **Page Lifecycle API (Visibility API, Page Lifecycle API):**
    - **例 4:**  `SetPageVisible(false)` 模拟了用户切换标签页，导致页面进入后台不可见的状态。这与 Visibility API 的 `visibilitychange` 事件相关。浏览器会根据页面的可见性状态来调整资源分配和任务调度。
    - **例 5:**  `SetPageFrozen(true)` 模拟了浏览器冻结后台标签页，这对应于 Page Lifecycle API 中的 "Frozen" 状态。

* **HTML5 Audio API:**
    - **例 6:** `AudioStateChanged(true)` 模拟了页面开始播放音频。即使页面不可见，正在播放音频的页面通常不会被立即冻结。`AudiblePagesAreNotThrottled` 和 `PageFrozenOnlyWhileAudioSilent` 测试了这种与音频状态相关的调度行为。

**逻辑推理、假设输入与输出:**

**示例 1: `PauseAndUnpauseVirtualTime_DETERMINISTIC_LOADING`**

* **假设输入:**
    - 初始虚拟时间: T0
    - 在虚拟时间 T0 + 3ms 时，执行一个任务，该任务会创建一个 `WebScopedVirtualTimePauser` 并暂停虚拟时间。
    - `WebScopedVirtualTimePauser` 的默认延迟为 10ms。
    - 紧接着，该任务会立即恢复虚拟时间。
    - 在虚拟时间 T0 + 5ms 时，执行另一个任务记录当前的虚拟时间。
* **逻辑推理:**
    1. 第一个任务在 T0 + 3ms 执行，暂停虚拟时间。
    2. 由于 `WebScopedVirtualTimePauser` 的延迟，虚拟时间会额外推进 10ms。
    3. 恢复虚拟时间后，虚拟时间到达 T0 + 3ms + 10ms = T0 + 13ms。
    4. 第二个任务计划在 T0 + 5ms 执行，但由于虚拟时间被暂停，它会在虚拟时间恢复后立即执行。此时虚拟时间已经到达 T0 + 13ms。
* **预期输出:**
    - `time_paused` (暂停时的时间) 应该等于 T0 + 3ms。
    - `time_unpaused` (恢复时的时间) 应该等于 T0 + 13ms。
    - `time_second_task` (第二个任务执行时的时间) 应该等于 T0 + 13ms。

**示例 2: `VirtualTimeBudgetExhaustedCallback`**

* **假设输入:**
    - 初始虚拟时间: T0
    - 提交多个延迟任务，分别在虚拟时间 T0 + 1ms, T0 + 2ms, T0 + 5ms, T0 + 7ms 执行。
    - 设置虚拟时间预算为 5ms。当虚拟时间推进到 T0 + 5ms 时，将虚拟时间策略设置为暂停。
* **逻辑推理:**
    1. 前三个任务（计划在 T0 + 1ms, T0 + 2ms, T0 + 5ms 执行）会在预算耗尽前执行。
    2. 第四个任务（计划在 T0 + 7ms 执行）在预算耗尽后，虚拟时间被暂停，因此不会立即执行。
* **预期输出:**
    - `real_times` (任务实际执行的时间) 应该包含前三个任务的执行时间。
    - `virtual_times` (任务执行时的虚拟时间) 应该分别为 T0 + 1ms, T0 + 2ms, T0 + 5ms。

**用户或编程常见的使用错误举例:**

1. **假设后台标签页的定时器会精确执行:** 开发者可能会错误地认为，即使标签页在后台，通过 `setTimeout(..., 1000)` 设置的定时器也会在 1 秒后精确执行。然而，浏览器的后台节流机制会延迟这些定时器的执行，导致意外的行为。这些测试强调了这种差异。

2. **不理解虚拟时间对异步操作的影响:** 在测试环境中使用虚拟时间时，开发者可能会错误地假设异步操作会像在真实环境中一样自然推进时间。例如，如果一个 Promise 在虚拟时间下 resolve，开发者需要确保虚拟时间已经推进到足以让 Promise 的回调执行。

3. **在页面冻结后仍然依赖定时器执行某些关键逻辑:** 开发者可能会依赖 `setInterval` 来定期更新 UI 或执行其他重要任务，但当页面被冻结时，这些定时器将停止工作。开发者需要使用 Page Lifecycle API 提供的事件来处理页面状态的变化，而不是仅仅依赖定时器。

4. **没有考虑到音频播放对后台节流的影响:**  开发者可能没有意识到，即使页面在后台，如果正在播放音频，其被节流或冻结的优先级会降低。如果某些后台逻辑需要即使在后台也及时执行，并且与音频播放相关，则需要注意这种行为。

**总结 (针对提供的代码片段):**

这段代码主要通过单元测试来验证 `PageSchedulerImpl` 类在处理虚拟时间、后台节流/冻结以及音频状态时的正确性和预期行为。它确保了 Blink 引擎能够按照 Chromium 的策略有效地管理页面资源的调度，尤其是在页面不可见或处于后台时，从而提高整体的浏览器性能和用户体验。这些测试对于理解和调试与 JavaScript 定时器、页面生命周期以及后台任务管理相关的行为至关重要。

### 提示词
```
这是目录为blink/renderer/platform/scheduler/main_thread/page_scheduler_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第2部分，共2部分，请归纳一下它的功能
```

### 源代码
```cpp
the next task delay
  // after each task.
  scheduler_->GetSchedulerHelperForTesting()->SetWorkBatchSizeForTesting(1);

  VirtualTimeController* vtc = page_scheduler_->GetVirtualTimeController();
  vtc->EnableVirtualTime(base::Time());
  vtc->SetVirtualTimePolicy(VirtualTimePolicy::kDeterministicLoading);

  base::TimeTicks initial_virtual_time = scheduler_->NowTicks();

  base::TimeTicks time_paused;
  base::TimeTicks time_unpaused;
  base::TimeTicks time_second_task;

  std::unique_ptr<FrameSchedulerImpl> frame_scheduler =
      CreateFrameScheduler(page_scheduler_.get(), nullptr,
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kSubframe);

  // Pauses and unpauses virtual time, thereby advancing virtual time by an
  // additional 10ms due to WebScopedVirtualTimePauser's delay.
  ThrottleableTaskRunner()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(
          &PauseAndUnpauseVirtualTime, base::Unretained(scheduler_.get()),
          base::Unretained(frame_scheduler.get()),
          base::Unretained(&time_paused), base::Unretained(&time_unpaused)),
      base::Milliseconds(3));

  // Will run after the first task has advanced virtual time past 5ms.
  ThrottleableTaskRunner()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&RecordVirtualTime, base::Unretained(scheduler_.get()),
                     base::Unretained(&time_second_task)),
      base::Milliseconds(5));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_EQ(time_paused, initial_virtual_time + base::Milliseconds(3));
  EXPECT_EQ(time_unpaused, initial_virtual_time + base::Milliseconds(13));
  EXPECT_EQ(time_second_task, initial_virtual_time + base::Milliseconds(13));
}

TEST_F(PageSchedulerImplTest,
       MultipleWebScopedVirtualTimePausers_DETERMINISTIC_LOADING) {
  VirtualTimeController* vtc = page_scheduler_->GetVirtualTimeController();
  vtc->EnableVirtualTime(base::Time());
  vtc->SetVirtualTimePolicy(VirtualTimePolicy::kDeterministicLoading);

  std::unique_ptr<FrameSchedulerImpl> frame_scheduler =
      CreateFrameScheduler(page_scheduler_.get(), nullptr,
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kSubframe);

  WebScopedVirtualTimePauser virtual_time_pauser1 =
      frame_scheduler->CreateWebScopedVirtualTimePauser(
          "test", WebScopedVirtualTimePauser::VirtualTaskDuration::kNonInstant);
  WebScopedVirtualTimePauser virtual_time_pauser2 =
      frame_scheduler->CreateWebScopedVirtualTimePauser(
          "test", WebScopedVirtualTimePauser::VirtualTaskDuration::kNonInstant);

  EXPECT_TRUE(scheduler_->VirtualTimeAllowedToAdvance());

  virtual_time_pauser1.PauseVirtualTime();
  virtual_time_pauser2.PauseVirtualTime();
  EXPECT_FALSE(scheduler_->VirtualTimeAllowedToAdvance());

  virtual_time_pauser2.UnpauseVirtualTime();
  EXPECT_FALSE(scheduler_->VirtualTimeAllowedToAdvance());

  virtual_time_pauser1.UnpauseVirtualTime();
  EXPECT_TRUE(scheduler_->VirtualTimeAllowedToAdvance());
}

TEST_F(PageSchedulerImplTest, NestedMessageLoop_DETERMINISTIC_LOADING) {
  VirtualTimeController* vtc = page_scheduler_->GetVirtualTimeController();
  vtc->EnableVirtualTime(base::Time());
  vtc->SetVirtualTimePolicy(VirtualTimePolicy::kDeterministicLoading);
  EXPECT_TRUE(scheduler_->VirtualTimeAllowedToAdvance());

  FakeTask fake_task;
  fake_task.set_enqueue_order(
      base::sequence_manager::EnqueueOrder::FromIntForTesting(42));
  const base::TimeTicks start = scheduler_->NowTicks();
  scheduler_->OnTaskStarted(nullptr, fake_task,
                            FakeTaskTiming(start, base::TimeTicks()));
  scheduler_->GetSchedulerHelperForTesting()->OnBeginNestedRunLoop();
  EXPECT_FALSE(scheduler_->VirtualTimeAllowedToAdvance());

  scheduler_->GetSchedulerHelperForTesting()->OnExitNestedRunLoop();
  EXPECT_TRUE(scheduler_->VirtualTimeAllowedToAdvance());
  FakeTaskTiming task_timing(start, scheduler_->NowTicks());
  scheduler_->OnTaskCompleted(nullptr, fake_task, &task_timing, nullptr);
}

TEST_F(PageSchedulerImplTest, PauseTimersWhileVirtualTimeIsPaused) {
  Vector<int> run_order;

  std::unique_ptr<FrameSchedulerImpl> frame_scheduler =
      CreateFrameScheduler(page_scheduler_.get(), nullptr,
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kSubframe);
  VirtualTimeController* vtc = page_scheduler_->GetVirtualTimeController();
  vtc->EnableVirtualTime(base::Time());
  vtc->SetVirtualTimePolicy(VirtualTimePolicy::kPause);

  ThrottleableTaskQueueForScheduler(frame_scheduler.get())
      ->GetTaskRunnerWithDefaultTaskType()
      ->PostTask(FROM_HERE, base::BindOnce(&RunOrderTask, 1,
                                           base::Unretained(&run_order)));

  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(run_order.empty());

  vtc->SetVirtualTimePolicy(VirtualTimePolicy::kAdvance);
  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_THAT(run_order, ElementsAre(1));
}

TEST_F(PageSchedulerImplTest, VirtualTimeBudgetExhaustedCallback) {
  Vector<base::TimeTicks> real_times;
  Vector<base::TimeTicks> virtual_times;

  VirtualTimeController* vtc = page_scheduler_->GetVirtualTimeController();
  vtc->EnableVirtualTime(base::Time());

  base::TimeTicks initial_real_time = scheduler_->NowTicks();
  base::TimeTicks initial_virtual_time = scheduler_->NowTicks();

  ThrottleableTaskRunner()->PostDelayedTask(
      FROM_HERE,
      MakeVirtualTimeRecorderTask(test_task_runner_->GetMockTickClock(),
                                  scheduler_.get(), &real_times,
                                  &virtual_times),
      base::Milliseconds(1));

  ThrottleableTaskRunner()->PostDelayedTask(
      FROM_HERE,
      MakeVirtualTimeRecorderTask(test_task_runner_->GetMockTickClock(),
                                  scheduler_.get(), &real_times,
                                  &virtual_times),
      base::Milliseconds(2));

  ThrottleableTaskRunner()->PostDelayedTask(
      FROM_HERE,
      MakeVirtualTimeRecorderTask(test_task_runner_->GetMockTickClock(),
                                  scheduler_.get(), &real_times,
                                  &virtual_times),
      base::Milliseconds(5));

  ThrottleableTaskRunner()->PostDelayedTask(
      FROM_HERE,
      MakeVirtualTimeRecorderTask(test_task_runner_->GetMockTickClock(),
                                  scheduler_.get(), &real_times,
                                  &virtual_times),
      base::Milliseconds(7));

  vtc->GrantVirtualTimeBudget(
      base::Milliseconds(5),
      base::BindOnce(&VirtualTimeController::SetVirtualTimePolicy,
                     base::Unretained(vtc), VirtualTimePolicy::kPause));
  test_task_runner_->FastForwardUntilNoTasksRemain();

  // The timer that is scheduled for the exact point in time when virtual time
  // expires will not run.
  EXPECT_THAT(real_times, ElementsAre(initial_real_time, initial_real_time,
                                      initial_real_time));
  EXPECT_THAT(virtual_times,
              ElementsAre(initial_virtual_time + base::Milliseconds(1),
                          initial_virtual_time + base::Milliseconds(2),
                          initial_virtual_time + base::Milliseconds(5)));
}

namespace {
void RepostingTask(scoped_refptr<base::SingleThreadTaskRunner> task_runner,
                   int max_count,
                   int* count) {
  if (++(*count) >= max_count)
    return;

  task_runner->PostTask(FROM_HERE,
                        base::BindOnce(&RepostingTask, task_runner, max_count,
                                       base::Unretained(count)));
}

void DelayedTask(int* count_in, int* count_out) {
  *count_out = *count_in;
}

}  // namespace

TEST_F(PageSchedulerImplTest, MaxVirtualTimeTaskStarvationCountOneHundred) {
  VirtualTimeController* vtc = page_scheduler_->GetVirtualTimeController();

  vtc->EnableVirtualTime(base::Time());
  vtc->SetMaxVirtualTimeTaskStarvationCount(100);
  vtc->SetVirtualTimePolicy(VirtualTimePolicy::kAdvance);

  int count = 0;
  int delayed_task_run_at_count = 0;
  RepostingTask(ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType(),
                1000, &count);
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(DelayedTask, base::Unretained(&count),
                     base::Unretained(&delayed_task_run_at_count)),
      base::Milliseconds(10));

  vtc->GrantVirtualTimeBudget(
      base::Milliseconds(1000),
      base::BindOnce(&VirtualTimeController::SetVirtualTimePolicy,
                     base::Unretained(vtc), VirtualTimePolicy::kPause));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  // Two delayed tasks with a run of 100 tasks, plus initial call.
  EXPECT_EQ(201, count);
  EXPECT_EQ(102, delayed_task_run_at_count);
}

TEST_F(PageSchedulerImplTest,
       MaxVirtualTimeTaskStarvationCountOneHundredNestedMessageLoop) {
  VirtualTimeController* vtc = page_scheduler_->GetVirtualTimeController();
  vtc->EnableVirtualTime(base::Time());
  vtc->SetMaxVirtualTimeTaskStarvationCount(100);
  vtc->SetVirtualTimePolicy(VirtualTimePolicy::kAdvance);

  FakeTask fake_task;
  fake_task.set_enqueue_order(
      base::sequence_manager::EnqueueOrder::FromIntForTesting(42));
  const base::TimeTicks start = scheduler_->NowTicks();
  scheduler_->OnTaskStarted(nullptr, fake_task,
                            FakeTaskTiming(start, base::TimeTicks()));
  scheduler_->GetSchedulerHelperForTesting()->OnBeginNestedRunLoop();

  int count = 0;
  int delayed_task_run_at_count = 0;
  RepostingTask(ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType(),
                1000, &count);
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(DelayedTask, base::Unretained(&count),
                     base::Unretained(&delayed_task_run_at_count)),
      base::Milliseconds(10));

  vtc->GrantVirtualTimeBudget(
      base::Milliseconds(1000),
      base::BindOnce(&VirtualTimeController::SetVirtualTimePolicy,
                     base::Unretained(vtc), VirtualTimePolicy::kPause));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_EQ(1000, count);
  EXPECT_EQ(1000, delayed_task_run_at_count);
}

TEST_F(PageSchedulerImplTest, MaxVirtualTimeTaskStarvationCountZero) {
  VirtualTimeController* vtc = page_scheduler_->GetVirtualTimeController();
  vtc->EnableVirtualTime(base::Time());
  vtc->SetMaxVirtualTimeTaskStarvationCount(0);
  vtc->SetVirtualTimePolicy(VirtualTimePolicy::kAdvance);

  int count = 0;
  int delayed_task_run_at_count = 0;
  RepostingTask(ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType(),
                1000, &count);
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(DelayedTask, base::Unretained(&count),
                     base::Unretained(&delayed_task_run_at_count)),
      base::Milliseconds(10));

  vtc->GrantVirtualTimeBudget(
      base::Milliseconds(1000),
      base::BindOnce(&VirtualTimeController::SetVirtualTimePolicy,
                     base::Unretained(vtc), VirtualTimePolicy::kPause));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  EXPECT_EQ(1000, count);
  // If the initial count had been higher, the delayed task could have been
  // arbitrarily delayed.
  EXPECT_EQ(1000, delayed_task_run_at_count);
}

namespace {

void ExpensiveTestTask(scoped_refptr<base::TestMockTimeTaskRunner> task_runner,
                       Vector<base::TimeTicks>* run_times) {
  run_times->push_back(task_runner->GetMockTickClock()->NowTicks());
  task_runner->AdvanceMockTickClock(base::Milliseconds(250));
}

void InitializeTrialParams() {
  base::FieldTrialParams params = {{"cpu_budget", "0.01"},
                                   {"max_budget", "0.0"},
                                   {"initial_budget", "0.0"},
                                   {"max_delay", "0.0"}};
  const char kParamName[] = "ExpensiveBackgroundTimerThrottling";
  const char kGroupName[] = "Enabled";
  EXPECT_TRUE(base::AssociateFieldTrialParams(kParamName, kGroupName, params));
  EXPECT_TRUE(base::FieldTrialList::CreateFieldTrial(kParamName, kGroupName));

  base::FieldTrialParams actual_params;
  base::GetFieldTrialParams(kParamName, &actual_params);
  EXPECT_EQ(actual_params, params);
}

}  // namespace

TEST_F(PageSchedulerImplTest, BackgroundTimerThrottling) {
  InitializeTrialParams();
  page_scheduler_ =
      CreatePageScheduler(nullptr, scheduler_.get(), *agent_group_scheduler_);
  EXPECT_FALSE(page_scheduler_->IsCPUTimeThrottled());
  base::TimeTicks start_time = test_task_runner_->NowTicks();

  Vector<base::TimeTicks> run_times;
  frame_scheduler_ = CreateFrameScheduler(page_scheduler_.get(), nullptr,
                                          /*is_in_embedded_frame_tree=*/false,
                                          FrameScheduler::FrameType::kSubframe);
  page_scheduler_->SetPageVisible(true);
  EXPECT_FALSE(page_scheduler_->IsCPUTimeThrottled());

  FastForwardTo(base::TimeTicks() + base::Milliseconds(2500));

  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, test_task_runner_, &run_times),
      base::Milliseconds(1));
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, test_task_runner_, &run_times),
      base::Milliseconds(1));

  FastForwardTo(base::TimeTicks() + base::Milliseconds(3500));

  // Check that these tasks are aligned, but are not subject to budget-based
  // throttling.
  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(2501),
                          base::TimeTicks() + base::Milliseconds(2751)));
  run_times.clear();

  page_scheduler_->SetPageVisible(false);
  EXPECT_FALSE(page_scheduler_->IsCPUTimeThrottled());

  // Ensure that the page is fully throttled.
  FastForwardTo(base::TimeTicks() + base::Seconds(15));
  EXPECT_TRUE(page_scheduler_->IsCPUTimeThrottled());

  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, test_task_runner_, &run_times),
      base::Microseconds(1));
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostDelayedTask(
      FROM_HERE,
      base::BindOnce(&ExpensiveTestTask, test_task_runner_, &run_times),
      base::Microseconds(1));

  test_task_runner_->FastForwardUntilNoTasksRemain();

  // Check that tasks are aligned and throttled.
  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Seconds(16),
                                     start_time + base::Seconds(25)));

  base::FieldTrialParamAssociator::GetInstance()->ClearAllParamsForTesting();
}

TEST_F(PageSchedulerImplTest, OpenWebSocketExemptsFromBudgetThrottling) {
  InitializeTrialParams();
  std::unique_ptr<PageSchedulerImpl> page_scheduler =
      CreatePageScheduler(nullptr, scheduler_.get(), *agent_group_scheduler_);
  base::TimeTicks start_time = test_task_runner_->NowTicks();

  Vector<base::TimeTicks> run_times;

  std::unique_ptr<FrameSchedulerImpl> frame_scheduler1 =
      CreateFrameScheduler(page_scheduler.get(), nullptr,
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kSubframe);
  std::unique_ptr<FrameSchedulerImpl> frame_scheduler2 =
      CreateFrameScheduler(page_scheduler.get(), nullptr,
                           /*is_in_embedded_frame_tree=*/false,
                           FrameScheduler::FrameType::kSubframe);

  page_scheduler->SetPageVisible(false);

  // Wait for 20s to avoid initial throttling delay.
  FastForwardTo(base::TimeTicks() + base::Milliseconds(20500));

  for (size_t i = 0; i < 3; ++i) {
    ThrottleableTaskQueueForScheduler(frame_scheduler1.get())
        ->GetTaskRunnerWithDefaultTaskType()
        ->PostDelayedTask(
            FROM_HERE,
            base::BindOnce(&ExpensiveTestTask, test_task_runner_, &run_times),
            base::Milliseconds(1));
  }

  FastForwardTo(base::TimeTicks() + base::Milliseconds(55500));

  // Check that tasks are throttled.
  EXPECT_THAT(run_times, ElementsAre(base::TimeTicks() + base::Seconds(21),
                                     start_time + base::Seconds(25),
                                     start_time + base::Seconds(50)));
  run_times.clear();

  FrameScheduler::SchedulingAffectingFeatureHandle websocket_feature =
      frame_scheduler1->RegisterFeature(
          SchedulingPolicy::Feature::kWebSocket,
          {SchedulingPolicy::DisableAggressiveThrottling()});

  for (size_t i = 0; i < 3; ++i) {
    ThrottleableTaskQueueForScheduler(frame_scheduler1.get())
        ->GetTaskRunnerWithDefaultTaskType()
        ->PostDelayedTask(
            FROM_HERE,
            base::BindOnce(&ExpensiveTestTask, test_task_runner_, &run_times),
            base::Milliseconds(1));
  }

  FastForwardTo(base::TimeTicks() + base::Milliseconds(58500));

  // Check that the timer task queue from the first frame is aligned,
  // but not throttled.
  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(56000),
                          base::TimeTicks() + base::Milliseconds(56250),
                          base::TimeTicks() + base::Milliseconds(56500)));
  run_times.clear();

  for (size_t i = 0; i < 3; ++i) {
    ThrottleableTaskQueueForScheduler(frame_scheduler2.get())
        ->GetTaskRunnerWithDefaultTaskType()
        ->PostDelayedTask(
            FROM_HERE,
            base::BindOnce(&ExpensiveTestTask, test_task_runner_, &run_times),
            base::Milliseconds(1));
  }

  FastForwardTo(base::TimeTicks() + base::Milliseconds(59500));

  // Check that the second frame scheduler becomes unthrottled.
  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(59000),
                          base::TimeTicks() + base::Milliseconds(59250),
                          base::TimeTicks() + base::Milliseconds(59500)));
  run_times.clear();

  websocket_feature.reset();

  // Wait for 10s to enable throttling back.
  FastForwardTo(base::TimeTicks() + base::Milliseconds(70500));

  for (size_t i = 0; i < 3; ++i) {
    ThrottleableTaskQueueForScheduler(frame_scheduler1.get())
        ->GetTaskRunnerWithDefaultTaskType()
        ->PostDelayedTask(
            FROM_HERE,
            base::BindOnce(&ExpensiveTestTask, test_task_runner_, &run_times),
            base::Milliseconds(1));
  }

  test_task_runner_->FastForwardUntilNoTasksRemain();

  // WebSocket is closed, budget-based throttling now applies.
  EXPECT_THAT(run_times,
              ElementsAre(base::TimeTicks() + base::Milliseconds(84500),
                          base::TimeTicks() + base::Milliseconds(109500),
                          base::TimeTicks() + base::Milliseconds(134500)));

  base::FieldTrialParamAssociator::GetInstance()->ClearAllParamsForTesting();
}

// Verify that freezing a page prevents tasks in its task queues from running.
// Then, verify that making the page visible unfreezes it and allows tasks in
// its task queues to run.
TEST_F(PageSchedulerImplTest, PageFreezeAndSetVisible) {
  TestFreeze(true);
}

// Same as before, but unfreeze the page explicitly instead of making it
// visible.
TEST_F(PageSchedulerImplTest, PageFreezeAndUnfreeze) {
  TestFreeze(false);
}

TEST_F(PageSchedulerImplTest, AudioState) {
  page_scheduler_->AudioStateChanged(true);
  EXPECT_TRUE(page_scheduler_->IsAudioPlaying());

  page_scheduler_->AudioStateChanged(false);
  // We are audible for a certain period after raw signal disappearing.
  EXPECT_TRUE(page_scheduler_->IsAudioPlaying());

  test_task_runner_->FastForwardBy(recent_audio_delay() / 2);

  page_scheduler_->AudioStateChanged(false);
  // We are still audible. A new call to AudioStateChanged shouldn't change
  // anything.
  EXPECT_TRUE(page_scheduler_->IsAudioPlaying());

  test_task_runner_->FastForwardBy(recent_audio_delay() / 2);

  // Audio is finally silent.
  EXPECT_FALSE(page_scheduler_->IsAudioPlaying());
}

TEST_F(PageSchedulerImplTest, PageSchedulerDestroyedWhileAudioChangePending) {
  page_scheduler_->AudioStateChanged(true);
  EXPECT_TRUE(page_scheduler_->IsAudioPlaying());
  page_scheduler_->AudioStateChanged(false);

  page_scheduler_.reset();

  test_task_runner_->FastForwardUntilNoTasksRemain();
}

TEST_F(PageSchedulerImplTest, AudiblePagesAreNotThrottled) {
  page_scheduler_->SetPageVisible(false);
  EXPECT_TRUE(ThrottleableTaskQueue()->IsThrottled());

  // No throttling when the page is audible.
  page_scheduler_->AudioStateChanged(true);
  EXPECT_FALSE(ThrottleableTaskQueue()->IsThrottled());

  // No throttling for some time after audio signal disappears.
  page_scheduler_->AudioStateChanged(false);
  EXPECT_FALSE(ThrottleableTaskQueue()->IsThrottled());

  // Eventually throttling is reenabled again.
  test_task_runner_->FastForwardUntilNoTasksRemain();
  EXPECT_TRUE(ThrottleableTaskQueue()->IsThrottled());
}

// Regression test for crbug.com/1431695. Test freezing and state changes work
// correctly if the OnAudioSilent timer fires after the page is frozen.
TEST_F(PageSchedulerImplTest, FreezingRecentlyAudiblePage) {
  page_scheduler_->AudioStateChanged(true);
  EXPECT_TRUE(page_scheduler_->IsAudioPlaying());

  page_scheduler_->AudioStateChanged(false);
  // The page is audible for a certain period after raw signal disappearing.
  EXPECT_TRUE(page_scheduler_->IsAudioPlaying());

  page_scheduler_->SetPageVisible(false);
  // Freeze the page from the external entrypoint. This should transition the
  // page to silent and frozen.
  page_scheduler_->SetPageFrozen(true);
  EXPECT_FALSE(page_scheduler_->IsAudioPlaying());
  EXPECT_TRUE(page_scheduler_->IsFrozen());

  // Fast-forwarding past the recent audio delay should not affect the state.
  test_task_runner_->FastForwardBy(recent_audio_delay() +
                                   base::Milliseconds(10));
  EXPECT_FALSE(page_scheduler_->IsAudioPlaying());
  EXPECT_TRUE(page_scheduler_->IsFrozen());
}

// Regression test for crbug.com/1431695. Test freezing and state changes work
// correctly if the AudioStateChanged notification occurs after the page is
// frozen.
TEST_F(PageSchedulerImplTest, FreezingAudiblePage) {
  page_scheduler_->AudioStateChanged(true);
  EXPECT_TRUE(page_scheduler_->IsAudioPlaying());

  page_scheduler_->SetPageVisible(false);
  page_scheduler_->SetPageFrozen(true);
  EXPECT_TRUE(page_scheduler_->IsFrozen());

  EXPECT_TRUE(page_scheduler_->IsAudioPlaying());
  page_scheduler_->AudioStateChanged(false);
  // The page should become silent immediately.
  EXPECT_FALSE(page_scheduler_->IsAudioPlaying());
  // And the page should still be frozen.
  EXPECT_TRUE(page_scheduler_->IsFrozen());

  // Fast-forwarding past the recent audio delay should not affect the state.
  test_task_runner_->FastForwardBy(recent_audio_delay() +
                                   base::Milliseconds(10));
  EXPECT_FALSE(page_scheduler_->IsAudioPlaying());
  EXPECT_TRUE(page_scheduler_->IsFrozen());
}

TEST_F(PageSchedulerImplTest, BudgetBasedThrottlingForPageScheduler) {
  page_scheduler_->SetPageVisible(false);
}

TEST_F(PageSchedulerImplTest, TestPageBackgroundedTimerSuspension) {
  int counter = 0;
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));

  // The background signal will not immediately suspend the timer queue.
  page_scheduler_->SetPageVisible(false);
  test_task_runner_->FastForwardBy(base::Milliseconds(1100));
  EXPECT_FALSE(page_scheduler_->IsFrozen());
  EXPECT_EQ(2, counter);

  counter = 0;
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_FALSE(page_scheduler_->IsFrozen());
  EXPECT_EQ(1, counter);

  // Advance the time until after the scheduled timer queue suspension.
  counter = 0;
  test_task_runner_->FastForwardBy(delay_for_background_tab_freezing() +
                                   base::Milliseconds(10));
  EXPECT_TRUE(page_scheduler_->IsFrozen());
  EXPECT_EQ(0, counter);

  // Timer tasks should be paused until the page becomes visible.
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  UnpausableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  test_task_runner_->FastForwardBy(base::Seconds(10));
  EXPECT_EQ(1, counter);

  counter = 0;
  page_scheduler_->SetPageVisible(true);
  EXPECT_FALSE(page_scheduler_->IsFrozen());
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_EQ(2, counter);

  // Subsequent timer tasks should fire as usual.
  counter = 0;
  ThrottleableTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(&IncrementCounter, base::Unretained(&counter)));
  test_task_runner_->FastForwardBy(base::Seconds(1));
  EXPECT_EQ(1, counter);
}

TEST_F(PageSchedulerImplTest, PageFrozenOnlyWhileAudioSilent) {
  page_scheduler_->AudioStateChanged(true);
  page_scheduler_->SetPageVisible(false);
  EXPECT_TRUE(page_scheduler_->IsAudioPlaying());
  EXPECT_FALSE(page_scheduler_->IsFrozen());

  page_scheduler_->AudioStateChanged(false);
  // We are audible for a certain period after raw signal disappearing. The page
  // should not be eligible to freeze until after this delay.
  EXPECT_TRUE(page_scheduler_->IsAudioPlaying());
  EXPECT_FALSE(page_scheduler_->IsFrozen());

  test_task_runner_->FastForwardBy(recent_audio_delay());
  // Audio is finally silent. The page should be eligible for freezing.
  EXPECT_FALSE(page_scheduler_->IsAudioPlaying());
  EXPECT_FALSE(page_scheduler_->IsFrozen());
  test_task_runner_->FastForwardBy(delay_for_background_tab_freezing() -
                                   kEpsilon);
  EXPECT_FALSE(page_scheduler_->IsFrozen());
  test_task_runner_->FastForwardBy(kEpsilon);
  EXPECT_TRUE(page_scheduler_->IsFrozen());

  // Page should unfreeze if audio starts playing.
  page_scheduler_->AudioStateChanged(true);
  EXPECT_FALSE(page_scheduler_->IsFrozen());
}

TEST_F(PageSchedulerImplTest, PageFrozenOnlyWhileNotVisible) {
  page_scheduler_->SetPageVisible(true);
  EXPECT_FALSE(page_scheduler_->IsFrozen());

  // Page should freeze after delay.
  page_scheduler_->SetPageVisible(false);
  test_task_runner_->FastForwardBy(delay_for_background_tab_freezing() -
                                   kEpsilon);
  EXPECT_FALSE(page_scheduler_->IsFrozen());
  test_task_runner_->FastForwardBy(kEpsilon);
  EXPECT_TRUE(page_scheduler_->IsFrozen());

  // Page should unfreeze when it becomes visible.
  page_scheduler_->SetPageVisible(true);
  EXPECT_FALSE(page_scheduler_->IsFrozen());

  // If the page becomes visible before the freezing delay expires, it should
  // not freeze after the delay elapses.
  page_scheduler_->SetPageVisible(false);
  test_task_runner_->FastForwardBy(delay_for_background_tab_freezing() -
                                   kEpsilon);
  EXPECT_FALSE(page_scheduler_->IsFrozen());
  page_scheduler_->SetPageVisible(true);
  test_task_runner_->FastForwardBy(delay_for_background_tab_freezing() +
                                   kEpsilon);
  EXPECT_FALSE(page_scheduler_->IsFrozen());
}

}  // namespace page_scheduler_impl_unittest
}  // namespace scheduler
}  // namespace blink
```