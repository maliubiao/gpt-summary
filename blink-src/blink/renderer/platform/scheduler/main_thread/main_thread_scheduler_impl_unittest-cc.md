Response: The user is asking for an analysis of a C++ unittest file for the Chromium Blink rendering engine. I need to identify the purpose of this file and relate it to web technologies like JavaScript, HTML, and CSS if applicable. I should also consider logical deductions, potential user/programming errors, and finally provide a summary of the file's functionality based on the provided first part of the code.

Here's a breakdown of the thought process:

1. **Identify the core subject:** The file name `main_thread_scheduler_impl_unittest.cc` clearly indicates that it's testing the `MainThreadSchedulerImpl` class.

2. **Infer the purpose of `MainThreadSchedulerImpl`:**  The location of the file (`blink/renderer/platform/scheduler/main_thread/`) suggests that this class is responsible for managing tasks on the main thread of the rendering engine. The "scheduler" part implies control over the order and timing of these tasks.

3. **Analyze includes:** The included headers provide valuable clues:
    * `<memory>`, `<string>`, etc.: Basic C++ utilities.
    * `"base/functional/bind.h"`, `"base/run_loop.h"`, `"base/task/...`:  Indicates use of Chromium's base library for task management, asynchronous operations, and testing utilities.
    * `"components/viz/common/frame_sinks/begin_frame_args.h"`: Points to interaction with the Viz component, specifically related to frame synchronization.
    * `"testing/gmock/include/gmock/gmock.h"`, `"testing/gtest/include/gtest/gtest.h"`: Confirms this is a unit test file using Google Test and Google Mock frameworks.
    * `"third_party/blink/public/common/features.h"`, `"third_party/blink/public/common/input/web_input_event.h"`: Shows involvement with Blink-specific features and handling of input events.
    * `"third_party/blink/renderer/platform/scheduler/...`: Includes files within the scheduler module, suggesting tests for different aspects of scheduling.
    * `"v8/include/v8.h"`: Implies interaction with the V8 JavaScript engine.

4. **Examine the code structure:** The file defines a namespace `main_thread_scheduler_impl_unittest`. It contains helper functions like `CreatePageScheduler` and `CreateFrameScheduler`, and mock classes like `MockFrameDelegate` and `MockPageSchedulerImpl`. There are also various `Fake...Event` classes for simulating input. Crucially, there's a test fixture class `MainThreadSchedulerImplTest`.

5. **Focus on the tests:**  The methods within `MainThreadSchedulerImplTest` (e.g., `TestPostDefaultTask`, `TestPostIdleTask`, `TestCompositorPolicy...`) reveal the kinds of scenarios being tested. These tests seem to cover:
    * Posting and executing tasks of different types (default, compositor, idle, input, loading, etc.).
    * The impact of different input events (mouse, touch, wheel) on task prioritization.
    * Different "use cases" or states of the scheduler (e.g., compositor gesture, main thread input handling, loading).
    * Interactions with the frame lifecycle (BeginFrame, DidCommitFrameToCompositor).
    * Handling of idle tasks and deadlines.

6. **Relate to web technologies:**
    * **JavaScript:** The inclusion of `v8.h` and the mention of "microtask checkpoint" strongly link the scheduler to the execution of JavaScript code. The scheduler likely manages the execution of JavaScript tasks on the main thread.
    * **HTML:** The rendering engine is responsible for parsing and interpreting HTML. The scheduler influences when tasks related to HTML processing (e.g., layout, painting) are executed.
    * **CSS:** Similarly, the scheduler determines the timing of tasks associated with CSS parsing, style calculation, and visual updates. The "BeginFrame" concept is directly tied to the rendering pipeline, including CSS-driven animations.

7. **Identify potential logical deductions, input/output:** The tests themselves demonstrate logical deductions. For example, the `TestCompositorPolicy` tests show how different input events lead to specific task prioritization outcomes. The "input" to these tests is often a sequence of posted tasks and simulated input events, and the "output" is the order in which the tasks are executed (verified by the `run_order` vector).

8. **Consider common errors:**  The tests implicitly highlight potential errors. For example, if tasks are not prioritized correctly, the `run_order` will be wrong. A common programming error might be posting tasks to the wrong queue, leading to unexpected execution order or delays. Incorrectly handling input events or failing to update the scheduler's state based on input could also lead to problems.

9. **Summarize the functionality:** Based on the analysis, the file primarily tests the `MainThreadSchedulerImpl`'s ability to manage and prioritize tasks on the main thread. This includes handling different types of tasks, responding to input events, and managing the rendering pipeline through interactions with the compositor.

10. **Structure the response:** Organize the findings into clear sections addressing the user's specific questions about functionality, relationships to web technologies, logical deductions, and common errors.
这是文件 `blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl_unittest.cc` 的第一部分，它是一个单元测试文件，专门用于测试 `MainThreadSchedulerImpl` 类的功能。`MainThreadSchedulerImpl` 是 Blink 渲染引擎中负责管理主线程上任务调度的核心组件。

**主要功能归纳:**

1. **测试主线程上各种类型任务的调度和执行顺序:** 文件中定义了各种测试用例，用于验证不同类型的任务（例如：默认任务、合成器任务、输入任务、加载任务、空闲任务等）在主线程上的调度顺序是否符合预期。它模拟了不同场景，例如有输入事件发生、正在进行合成器动画、页面加载等，来测试调度器的行为。

2. **测试输入事件对任务调度的影响:**  该文件模拟了各种类型的输入事件（例如：鼠标事件、触摸事件、滚轮事件），并测试这些事件如何影响主线程上任务的优先级和执行顺序。这对于保证用户交互的流畅性至关重要。

3. **测试不同的调度策略 (Use Cases):**  Blink 的主线程调度器会根据当前的状态和发生的事件切换不同的调度策略（称为 Use Cases），例如：空闲状态、合成器手势、主线程输入处理、页面加载等。该文件测试了在不同 Use Cases 下，任务的优先级和执行顺序是否正确。

4. **测试空闲任务的调度:**  文件中包含测试空闲任务（Idle Tasks）的用例，验证空闲任务是否在主线程空闲时执行，并且能够正确处理空闲任务的截止时间。

5. **测试与合成器 (Compositor) 的交互:**  通过模拟 `WillBeginFrame` 和 `DidCommitFrameToCompositor` 等事件，该文件测试了主线程调度器与合成器之间的协作，例如在合成器需要新帧时，主线程如何安排任务来生成新的渲染内容。

**与 JavaScript, HTML, CSS 的功能关系及举例:**

`MainThreadSchedulerImpl` 直接影响 JavaScript, HTML, CSS 的处理，因为它负责安排执行与这些技术相关的任务。

* **JavaScript:**
    * **举例:** 当 JavaScript 代码调用 `setTimeout` 或 `requestAnimationFrame` 时，`MainThreadSchedulerImpl` 负责将对应的回调函数作为任务添加到主线程的任务队列中，并在合适的时机执行。测试用例中模拟了各种类型的任务，其中就包含了可以被认为是 JavaScript 任务的场景。例如，一个“默认任务”可能就代表一个普通的 JavaScript 回调。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:**  JavaScript 代码执行 `setTimeout(myFunction, 100)`.
        * **预期输出:** `MainThreadSchedulerImpl` 在大约 100ms 后将 `myFunction` 添加到任务队列并最终执行。测试用例会验证在其他任务存在的情况下，这个延时任务是否按照优先级正确执行。

* **HTML:**
    * **举例:** 当浏览器解析 HTML 并构建 DOM 树时，相关的工作（例如：解析器任务、样式计算任务、布局任务）会由 `MainThreadSchedulerImpl` 安排执行。测试用例中，"加载任务" (Loading Task) 可能就代表与 HTML 加载和解析相关的任务。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:**  浏览器接收到一个新的 HTML 文档。
        * **预期输出:** `MainThreadSchedulerImpl` 安排执行 HTML 解析器任务，构建 DOM 树。测试用例可能模拟这种情况，验证解析任务是否在其他类型任务（例如输入事件处理）之后或之前执行，取决于当前的调度策略。

* **CSS:**
    * **举例:** 当浏览器解析 CSS 并计算样式时，相关的工作（例如：CSS 解析器任务、样式计算任务）也会由 `MainThreadSchedulerImpl` 调度。测试用例中，与渲染相关的任务，例如在 `WillBeginFrame` 之后执行的任务，可能就涉及到 CSS 样式的应用。
    * **逻辑推理 (假设输入与输出):**
        * **假设输入:**  网页加载了一个新的 CSS 文件。
        * **预期输出:** `MainThreadSchedulerImpl` 安排执行 CSS 解析器任务，并将解析后的样式应用到 DOM 树上。测试用例可能会验证样式计算任务是否在布局任务之前执行。

**涉及用户或者编程常见的使用错误 (举例说明):**

虽然这是单元测试，但它间接反映了如果 `MainThreadSchedulerImpl` 工作不正常，用户或开发者可能遇到的问题：

* **用户使用错误 (通过编程错误体现):**  如果 JavaScript 代码中存在大量的同步阻塞操作，会导致主线程被长时间占用，使得 `MainThreadSchedulerImpl` 无法及时处理其他重要的任务（例如：渲染更新、用户输入响应）。这在测试中可能会表现为某些任务被延迟执行或者根本无法执行。
    * **测试用例可能模拟:**  在主线程上插入一个耗时很长的“默认任务”，然后观察其他类型的任务（例如：合成器任务、输入任务）是否会被延迟。

* **编程错误:**
    * **任务优先级设置错误:** 开发者可能错误地设置了某些任务的优先级，导致重要的任务被低优先级任务阻塞。测试用例会验证不同优先级任务的执行顺序。
    * **死锁或无限循环:**  某些编程错误可能导致主线程上的任务进入死锁或无限循环，使得 `MainThreadSchedulerImpl` 无法继续调度后续任务。虽然单元测试不太可能直接测试死锁，但它可以测试任务是否按照预期完成，如果出现问题，可能需要进一步排查死锁原因。

**总结其功能 (基于第 1 部分):**

该单元测试文件的主要功能是全面测试 `MainThreadSchedulerImpl` 类的核心调度逻辑，包括不同类型任务的优先级管理、输入事件的处理、不同调度策略的切换以及与合成器的协同工作。通过模拟各种场景和事件，确保主线程上的任务能够按照预期顺序执行，从而保证渲染引擎的性能和用户交互的流畅性。 它是验证 Blink 引擎主线程调度器正确性的关键组成部分。

Prompt: 
```
这是目录为blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl_unittest.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
这是第1部分，共3部分，请归纳一下它的功能

"""
// Copyright 2014 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.h"

#include <memory>
#include <string>
#include <utility>

#include "base/functional/bind.h"
#include "base/functional/callback.h"
#include "base/functional/callback_helpers.h"
#include "base/memory/ptr_util.h"
#include "base/metrics/field_trial_params.h"
#include "base/run_loop.h"
#include "base/strings/string_number_conversions.h"
#include "base/strings/string_util.h"
#include "base/task/common/task_annotator.h"
#include "base/task/sequence_manager/test/fake_task.h"
#include "base/task/sequence_manager/test/sequence_manager_for_test.h"
#include "base/task/single_thread_task_runner.h"
#include "base/test/bind.h"
#include "base/test/metrics/histogram_tester.h"
#include "base/test/scoped_feature_list.h"
#include "base/test/simple_test_tick_clock.h"
#include "base/test/test_mock_time_task_runner.h"
#include "base/time/time.h"
#include "build/build_config.h"
#include "components/viz/common/frame_sinks/begin_frame_args.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/common/features.h"
#include "third_party/blink/public/common/input/web_input_event.h"
#include "third_party/blink/public/common/input/web_mouse_wheel_event.h"
#include "third_party/blink/public/common/input/web_touch_event.h"
#include "third_party/blink/public/common/page/launching_process_state.h"
#include "third_party/blink/public/platform/web_input_event_result.h"
#include "third_party/blink/renderer/platform/scheduler/common/auto_advancing_virtual_time_domain.h"
#include "third_party/blink/renderer/platform/scheduler/common/features.h"
#include "third_party/blink/renderer/platform/scheduler/common/task_priority.h"
#include "third_party/blink/renderer/platform/scheduler/common/throttling/budget_pool.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/find_in_page_budget_pool_controller.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/frame_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/frame_task_queue_controller.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_priority.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_queue_type.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_task_queue.h"
#include "third_party/blink/renderer/platform/scheduler/test/recording_task_time_observer.h"
#include "third_party/blink/renderer/platform/scheduler/test/web_scheduling_test_helper.h"
#include "v8/include/v8.h"

using base::sequence_manager::TaskQueue;

namespace blink {
namespace scheduler {
// To avoid symbol collisions in jumbo builds.
namespace main_thread_scheduler_impl_unittest {

namespace {
using ::base::Feature;
using ::base::sequence_manager::FakeTask;
using ::base::sequence_manager::FakeTaskTiming;
using blink::WebInputEvent;
using ::testing::InSequence;
using ::testing::Mock;
using ::testing::NiceMock;
using ::testing::NotNull;
using ::testing::Return;
using ::testing::ReturnRef;
using InputEventState = WidgetScheduler::InputEventState;

constexpr base::TimeDelta kDelayForHighPriorityRendering =
    base::Milliseconds(150);

// This is a wrapper around MainThreadSchedulerImpl::CreatePageScheduler, that
// returns the PageScheduler as a PageSchedulerImpl.
std::unique_ptr<PageSchedulerImpl> CreatePageScheduler(
    PageScheduler::Delegate* page_scheduler_delegate,
    ThreadSchedulerBase* scheduler,
    AgentGroupScheduler& agent_group_scheduler) {
  std::unique_ptr<PageScheduler> page_scheduler =
      agent_group_scheduler.CreatePageScheduler(page_scheduler_delegate);
  std::unique_ptr<PageSchedulerImpl> page_scheduler_impl(
      static_cast<PageSchedulerImpl*>(page_scheduler.release()));
  return page_scheduler_impl;
}

// This is a wrapper around PageSchedulerImpl::CreateFrameScheduler, that
// returns the FrameScheduler as a FrameSchedulerImpl.
std::unique_ptr<FrameSchedulerImpl> CreateFrameScheduler(
    PageSchedulerImpl* page_scheduler,
    FrameScheduler::Delegate* delegate,
    bool is_in_embedded_frame_tree,
    FrameScheduler::FrameType frame_type) {
  auto frame_scheduler = page_scheduler->CreateFrameScheduler(
      delegate, is_in_embedded_frame_tree, frame_type);
  std::unique_ptr<FrameSchedulerImpl> frame_scheduler_impl(
      static_cast<FrameSchedulerImpl*>(frame_scheduler.release()));
  return frame_scheduler_impl;
}

class MockFrameDelegate : public FrameScheduler::Delegate {
 public:
  MockFrameDelegate() {
    ON_CALL(*this, GetAgentClusterId)
        .WillByDefault(ReturnRef(agent_cluster_id_));
  }

  MOCK_METHOD(const base::UnguessableToken&,
              GetAgentClusterId,
              (),
              (const, override));
  MOCK_METHOD(ukm::UkmRecorder*, GetUkmRecorder, ());
  MOCK_METHOD(ukm::SourceId, GetUkmSourceId, ());
  MOCK_METHOD(void, UpdateTaskTime, (base::TimeDelta));
  MOCK_METHOD(void, UpdateActiveSchedulerTrackedFeatures, (uint64_t));

 private:
  base::UnguessableToken agent_cluster_id_ = base::UnguessableToken::Create();
};

}  // namespace

class FakeInputEvent : public blink::WebInputEvent {
 public:
  explicit FakeInputEvent(blink::WebInputEvent::Type event_type,
                          int modifiers = WebInputEvent::kNoModifiers)
      : WebInputEvent(event_type,
                      modifiers,
                      WebInputEvent::GetStaticTimeStampForTests()) {}

  std::unique_ptr<WebInputEvent> Clone() const override {
    return std::make_unique<FakeInputEvent>(*this);
  }

  bool CanCoalesce(const blink::WebInputEvent& event) const override {
    return false;
  }

  void Coalesce(const WebInputEvent& event) override { NOTREACHED(); }
};

class FakeTouchEvent : public blink::WebTouchEvent {
 public:
  explicit FakeTouchEvent(blink::WebInputEvent::Type event_type,
                          DispatchType dispatch_type =
                              blink::WebInputEvent::DispatchType::kBlocking)
      : WebTouchEvent(event_type,
                      WebInputEvent::kNoModifiers,
                      WebInputEvent::GetStaticTimeStampForTests()) {
    this->dispatch_type = dispatch_type;
  }
};

class FakeMouseWheelEvent : public blink::WebMouseWheelEvent {
 public:
  explicit FakeMouseWheelEvent(
      blink::WebInputEvent::Type event_type,
      DispatchType dispatch_type =
          blink::WebInputEvent::DispatchType::kBlocking)
      : WebMouseWheelEvent(event_type,
                           WebInputEvent::kNoModifiers,
                           WebInputEvent::GetStaticTimeStampForTests()) {
    this->dispatch_type = dispatch_type;
  }
};

void AppendToVectorTestTask(Vector<String>* vector, String value) {
  vector->push_back(value);
}

void AppendToVectorIdleTestTask(Vector<String>* vector,
                                String value,
                                base::TimeTicks deadline) {
  AppendToVectorTestTask(vector, value);
}

void NullTask() {}

void AppendToVectorReentrantTask(base::SingleThreadTaskRunner* task_runner,
                                 Vector<int>* vector,
                                 int* reentrant_count,
                                 int max_reentrant_count) {
  vector->push_back((*reentrant_count)++);
  if (*reentrant_count < max_reentrant_count) {
    task_runner->PostTask(FROM_HERE,
                          base::BindOnce(AppendToVectorReentrantTask,
                                         base::Unretained(task_runner), vector,
                                         reentrant_count, max_reentrant_count));
  }
}

void IdleTestTask(int* run_count,
                  base::TimeTicks* deadline_out,
                  base::TimeTicks deadline) {
  (*run_count)++;
  *deadline_out = deadline;
}

int g_max_idle_task_reposts = 2;

void RepostingIdleTestTask(SingleThreadIdleTaskRunner* idle_task_runner,
                           int* run_count,
                           base::TimeTicks deadline) {
  if ((*run_count + 1) < g_max_idle_task_reposts) {
    idle_task_runner->PostIdleTask(
        FROM_HERE,
        base::BindOnce(&RepostingIdleTestTask,
                       base::Unretained(idle_task_runner), run_count));
  }
  (*run_count)++;
}

void RepostingUpdateClockIdleTestTask(
    SingleThreadIdleTaskRunner* idle_task_runner,
    int* run_count,
    scoped_refptr<base::TestMockTimeTaskRunner> test_task_runner,
    base::TimeDelta advance_time,
    Vector<base::TimeTicks>* deadlines,
    base::TimeTicks deadline) {
  if ((*run_count + 1) < g_max_idle_task_reposts) {
    idle_task_runner->PostIdleTask(
        FROM_HERE, base::BindOnce(&RepostingUpdateClockIdleTestTask,
                                  base::Unretained(idle_task_runner), run_count,
                                  test_task_runner, advance_time, deadlines));
  }
  deadlines->push_back(deadline);
  (*run_count)++;
  test_task_runner->AdvanceMockTickClock(advance_time);
}

void WillBeginFrameIdleTask(MainThreadSchedulerImpl* scheduler,
                            uint64_t sequence_number,
                            const base::TickClock* clock,
                            base::TimeTicks deadline) {
  scheduler->WillBeginFrame(viz::BeginFrameArgs::Create(
      BEGINFRAME_FROM_HERE, 0, sequence_number, clock->NowTicks(),
      base::TimeTicks(), base::Milliseconds(1000),
      viz::BeginFrameArgs::NORMAL));
}

void UpdateClockToDeadlineIdleTestTask(
    scoped_refptr<base::TestMockTimeTaskRunner> task_runner,
    int* run_count,
    base::TimeTicks deadline) {
  task_runner->AdvanceMockTickClock(
      deadline - task_runner->GetMockTickClock()->NowTicks());
  (*run_count)++;
}

void PostingYieldingTestTask(MainThreadSchedulerImpl* scheduler,
                             base::SingleThreadTaskRunner* task_runner,
                             bool simulate_input,
                             bool* should_yield_before,
                             bool* should_yield_after) {
  *should_yield_before = scheduler->ShouldYieldForHighPriorityWork();
  task_runner->PostTask(FROM_HERE, base::BindOnce(NullTask));
  if (simulate_input) {
    scheduler->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  }
  *should_yield_after = scheduler->ShouldYieldForHighPriorityWork();
}

enum class SimulateInputType {
  kNone,
  kTouchStart,
  kTouchEnd,
  kGestureScrollBegin,
  kGestureScrollEnd
};

class MockPageSchedulerImpl : public PageSchedulerImpl {
 public:
  explicit MockPageSchedulerImpl(MainThreadSchedulerImpl* main_thread_scheduler,
                                 AgentGroupSchedulerImpl& agent_group_scheduler)
      : PageSchedulerImpl(nullptr, agent_group_scheduler) {
    ON_CALL(*this, IsWaitingForMainFrameContentfulPaint)
        .WillByDefault(Return(false));
    ON_CALL(*this, IsWaitingForMainFrameMeaningfulPaint)
        .WillByDefault(Return(false));
    ON_CALL(*this, IsMainFrameLoading).WillByDefault(Return(false));
    ON_CALL(*this, IsMainFrameLocal).WillByDefault(Return(true));
    ON_CALL(*this, IsOrdinary).WillByDefault(Return(true));

    // This would normally be called by
    // MainThreadSchedulerImpl::CreatePageScheduler.
    main_thread_scheduler->AddPageScheduler(this);
  }
  MockPageSchedulerImpl(const MockPageSchedulerImpl&) = delete;
  MockPageSchedulerImpl& operator=(const MockPageSchedulerImpl&) = delete;
  ~MockPageSchedulerImpl() override = default;

  MOCK_METHOD(bool, RequestBeginMainFrameNotExpected, (bool));
  MOCK_METHOD(bool, IsWaitingForMainFrameContentfulPaint, (), (const));
  MOCK_METHOD(bool, IsWaitingForMainFrameMeaningfulPaint, (), (const));
  MOCK_METHOD(bool, IsMainFrameLoading, (), (const));
  MOCK_METHOD(bool, IsMainFrameLocal, (), (const));
  MOCK_METHOD(bool, IsOrdinary, (), (const));
};

class MainThreadSchedulerImplForTest : public MainThreadSchedulerImpl {
 public:
  using MainThreadSchedulerImpl::CompositorTaskQueue;
  using MainThreadSchedulerImpl::ControlTaskQueue;
  using MainThreadSchedulerImpl::DefaultTaskQueue;
  using MainThreadSchedulerImpl::OnIdlePeriodEnded;
  using MainThreadSchedulerImpl::OnIdlePeriodStarted;
  using MainThreadSchedulerImpl::OnPendingTasksChanged;
  using MainThreadSchedulerImpl::V8TaskQueue;

  explicit MainThreadSchedulerImplForTest(
      std::unique_ptr<base::sequence_manager::SequenceManager> manager)
      : MainThreadSchedulerImpl(std::move(manager)), update_policy_count_(0) {}

  void UpdatePolicyLocked(UpdateType update_type) override {
    update_policy_count_++;
    MainThreadSchedulerImpl::UpdatePolicyLocked(update_type);

    String use_case = UseCaseToString(main_thread_only().current_use_case);
    if (main_thread_only().blocking_input_expected_soon) {
      use_cases_.push_back(use_case + " blocking input expected");
    } else {
      use_cases_.push_back(use_case);
    }
  }

  void EnsureUrgentPolicyUpdatePostedOnMainThread() {
    base::AutoLock lock(any_thread_lock_);
    MainThreadSchedulerImpl::EnsureUrgentPolicyUpdatePostedOnMainThread(
        FROM_HERE);
  }

  void ScheduleDelayedPolicyUpdate(base::TimeTicks now, base::TimeDelta delay) {
    delayed_update_policy_runner_.SetDeadline(FROM_HERE, delay, now);
  }

  bool BeginMainFrameOnCriticalPath() {
    base::AutoLock lock(any_thread_lock_);
    return any_thread().begin_main_frame_on_critical_path;
  }

  void PerformMicrotaskCheckpoint() override {
    if (on_microtask_checkpoint_)
      std::move(on_microtask_checkpoint_).Run();
  }

  void SetCurrentUseCase(UseCase use_case) {
    SetCurrentUseCaseForTest(use_case);
  }

  int update_policy_count_;
  Vector<String> use_cases_;
  base::OnceClosure on_microtask_checkpoint_;
};

// Lets gtest print human readable Policy values.
::std::ostream& operator<<(::std::ostream& os, const UseCase& use_case) {
  return os << UseCaseToString(use_case);
}

class MainThreadSchedulerImplTest : public testing::Test {
 public:
  MainThreadSchedulerImplTest(
      const std::vector<base::test::FeatureRef>& features_to_enable,
      const std::vector<base::test::FeatureRef>& features_to_disable) {
    feature_list_.InitWithFeatures(features_to_enable, features_to_disable);
  }

  explicit MainThreadSchedulerImplTest(
      std::vector<::base::test::FeatureRefAndParams> features_to_enable) {
    feature_list_.InitWithFeaturesAndParameters(features_to_enable, {});
  }

  MainThreadSchedulerImplTest() : MainThreadSchedulerImplTest({}, {}) {}

  MainThreadSchedulerImplTest(const MainThreadSchedulerImplTest&) = delete;
  MainThreadSchedulerImplTest& operator=(const MainThreadSchedulerImplTest&) =
      delete;

  ~MainThreadSchedulerImplTest() override = default;

  void SetUp() override {
    CreateTestTaskRunner();
    Initialize(std::make_unique<MainThreadSchedulerImplForTest>(
        base::sequence_manager::SequenceManagerForTest::Create(
            nullptr, test_task_runner_, test_task_runner_->GetMockTickClock(),
            base::sequence_manager::SequenceManager::Settings::Builder()
                .SetRandomisedSamplingEnabled(true)
                .SetPrioritySettings(CreatePrioritySettings())
                .Build())));

    EXPECT_EQ(ForceUpdatePolicyAndGetCurrentUseCase(), UseCase::kNone);
    // Don't count the above policy change.
    scheduler_->update_policy_count_ = 0;
    scheduler_->use_cases_.clear();
  }

  void CreateTestTaskRunner() {
    test_task_runner_ = base::WrapRefCounted(new base::TestMockTimeTaskRunner(
        base::TestMockTimeTaskRunner::Type::kBoundToThread));
    // A null clock triggers some assertions.
    test_task_runner_->AdvanceMockTickClock(base::Milliseconds(5));
  }

  void Initialize(std::unique_ptr<MainThreadSchedulerImplForTest> scheduler) {
    scheduler_ = std::move(scheduler);

    if (kLaunchingProcessIsBackgrounded) {
      scheduler_->SetRendererBackgrounded(false);
      // Reset the policy count as foregrounding would force an initial update.
      scheduler_->update_policy_count_ = 0;
      scheduler_->use_cases_.clear();
    }

    default_task_runner_ =
        scheduler_->DefaultTaskQueue()->GetTaskRunnerWithDefaultTaskType();
    idle_task_runner_ = scheduler_->IdleTaskRunner();
    v8_task_runner_ =
        scheduler_->V8TaskQueue()->GetTaskRunnerWithDefaultTaskType();

    agent_group_scheduler_ = static_cast<AgentGroupSchedulerImpl*>(
        scheduler_->CreateAgentGroupScheduler());
    compositor_task_runner_ = agent_group_scheduler_->CompositorTaskQueue()
                                  ->GetTaskRunnerWithDefaultTaskType();
    page_scheduler_ = std::make_unique<NiceMock<MockPageSchedulerImpl>>(
        scheduler_.get(), *agent_group_scheduler_);
    agent_group_scheduler_->AddPageSchedulerForTesting(page_scheduler_.get());
    main_frame_scheduler_ =
        CreateFrameScheduler(page_scheduler_.get(), nullptr,
                             /*is_in_embedded_frame_tree=*/false,
                             FrameScheduler::FrameType::kMainFrame);

    widget_scheduler_ = scheduler_->CreateWidgetScheduler();
    input_task_runner_ = widget_scheduler_->InputTaskRunner();

    loading_control_task_runner_ =
        main_frame_scheduler_->FrameTaskQueueControllerForTest()
            ->GetTaskQueue(
                main_frame_scheduler_->LoadingControlTaskQueueTraits())
            ->GetTaskRunnerWithDefaultTaskType();
    throttleable_task_runner_ =
        throttleable_task_queue()->GetTaskRunnerWithDefaultTaskType();
    find_in_page_task_runner_ = main_frame_scheduler_->GetTaskRunner(
        blink::TaskType::kInternalFindInPage);
    prioritised_local_frame_task_runner_ = main_frame_scheduler_->GetTaskRunner(
        blink::TaskType::kInternalHighPriorityLocalFrame);
    render_blocking_task_runner_ = main_frame_scheduler_->GetTaskRunner(
        blink::TaskType::kNetworkingUnfreezableRenderBlockingLoading);
  }

  MainThreadTaskQueue* compositor_task_queue() {
    return agent_group_scheduler_->CompositorTaskQueue().get();
  }

  MainThreadTaskQueue* loading_task_queue() {
    auto queue_traits = FrameSchedulerImpl::LoadingTaskQueueTraits();
    return main_frame_scheduler_->FrameTaskQueueControllerForTest()
        ->GetTaskQueue(queue_traits)
        .get();
  }

  MainThreadTaskQueue* throttleable_task_queue() {
    auto* frame_task_queue_controller =
        main_frame_scheduler_->FrameTaskQueueControllerForTest();
    return frame_task_queue_controller
        ->GetTaskQueue(main_frame_scheduler_->ThrottleableTaskQueueTraits())
        .get();
  }

  MainThreadTaskQueue* find_in_page_task_queue() {
    auto* frame_task_queue_controller =
        main_frame_scheduler_->FrameTaskQueueControllerForTest();

    return frame_task_queue_controller
        ->GetTaskQueue(main_frame_scheduler_->FindInPageTaskQueueTraits())
        .get();
  }

  scoped_refptr<MainThreadTaskQueue> NewUnpausableTaskQueue() {
    return scheduler_->NewTaskQueue(
        MainThreadTaskQueue::QueueCreationParams(
            MainThreadTaskQueue::QueueType::kFrameUnpausable)
            .SetQueueTraits(
                main_frame_scheduler_->UnpausableTaskQueueTraits()));
  }

  void TearDown() override {
    widget_scheduler_.reset();
    main_frame_scheduler_.reset();
    page_scheduler_.reset();
    agent_group_scheduler_ = nullptr;
    scheduler_->Shutdown();
    base::RunLoop().RunUntilIdle();
    scheduler_.reset();
  }

  virtual base::TimeTicks Now() {
    CHECK(test_task_runner_);
    return test_task_runner_->GetMockTickClock()->NowTicks();
  }

  void AdvanceMockTickClockTo(base::TimeTicks time) {
    CHECK(test_task_runner_);
    CHECK_LE(Now(), time);
    test_task_runner_->AdvanceMockTickClock(time - Now());
  }

  void AdvanceMockTickClockBy(base::TimeDelta delta) {
    CHECK(test_task_runner_);
    CHECK_LE(base::TimeDelta(), delta);
    test_task_runner_->AdvanceMockTickClock(delta);
  }

  void DoMainFrame() {
    viz::BeginFrameArgs begin_frame_args = viz::BeginFrameArgs::Create(
        BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
        base::TimeTicks(), base::Milliseconds(16), viz::BeginFrameArgs::NORMAL);
    begin_frame_args.on_critical_path = false;
    scheduler_->WillBeginFrame(begin_frame_args);
    scheduler_->DidCommitFrameToCompositor();
  }

  void DoMainFrameOnCriticalPath() {
    viz::BeginFrameArgs begin_frame_args = viz::BeginFrameArgs::Create(
        BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
        base::TimeTicks(), base::Milliseconds(16), viz::BeginFrameArgs::NORMAL);
    begin_frame_args.on_critical_path = true;
    scheduler_->WillBeginFrame(begin_frame_args);
  }

  void ForceBlockingInputToBeExpectedSoon() {
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollEnd),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
    test_task_runner_->AdvanceMockTickClock(UserModel::kGestureEstimationLimit *
                                            2);
    scheduler_->ForceUpdatePolicy();
  }

  void SimulateExpensiveTasks(
      const scoped_refptr<base::SingleThreadTaskRunner>& task_runner) {
    // Simulate a bunch of expensive tasks.
    for (int i = 0; i < 10; i++) {
      task_runner->PostTask(
          FROM_HERE,
          base::BindOnce(&base::TestMockTimeTaskRunner::AdvanceMockTickClock,
                         test_task_runner_, base::Milliseconds(500)));
    }
    test_task_runner_->FastForwardUntilNoTasksRemain();
  }

  void SimulateEnteringCompositorGestureUseCase() {
    SimulateCompositorGestureStart(TouchEventPolicy::kDontSendTouchStart);
    base::RunLoop().RunUntilIdle();
    EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());
  }

  void SimulateRenderBlockingTask(base::TimeDelta duration) {
    render_blocking_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(&base::TestMockTimeTaskRunner::AdvanceMockTickClock,
                       test_task_runner_, duration));
    test_task_runner_->FastForwardUntilNoTasksRemain();
  }

  enum class TouchEventPolicy {
    kSendTouchStart,
    kDontSendTouchStart,
  };

  void SimulateCompositorGestureStart(TouchEventPolicy touch_event_policy) {
    if (touch_event_policy == TouchEventPolicy::kSendTouchStart) {
      scheduler_->DidHandleInputEventOnCompositorThread(
          FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
          InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
      scheduler_->DidHandleInputEventOnCompositorThread(
          FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
          InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
      scheduler_->DidHandleInputEventOnCompositorThread(
          FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
          InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
    }
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollBegin),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  }

  // Simulate a gesture where there is an active compositor scroll, but no
  // scroll updates are generated. Instead, the main thread handles
  // non-canceleable touch events, making this an effectively main thread
  // driven gesture.
  void SimulateMainThreadGestureWithoutScrollUpdates() {
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
        InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
        InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollBegin),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
        InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  }

  // Simulate a gesture where the main thread handles touch events but does not
  // preventDefault(), allowing the gesture to turn into a compositor driven
  // gesture. This function also verifies the necessary policy updates are
  // scheduled.
  void SimulateMainThreadGestureWithoutPreventDefault() {
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
        InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);

    // Touchstart policy update.
    EXPECT_TRUE(scheduler_->PolicyNeedsUpdateForTesting());
    EXPECT_EQ(UseCase::kTouchstart, ForceUpdatePolicyAndGetCurrentUseCase());
    EXPECT_FALSE(scheduler_->PolicyNeedsUpdateForTesting());

    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
        InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureTapCancel),
        InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollBegin),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);

    // Main thread gesture policy update.
    EXPECT_TRUE(scheduler_->PolicyNeedsUpdateForTesting());
    EXPECT_EQ(UseCase::kMainThreadCustomInputHandling,
              ForceUpdatePolicyAndGetCurrentUseCase());
    EXPECT_FALSE(scheduler_->PolicyNeedsUpdateForTesting());

    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollUpdate),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kTouchScrollStarted),
        InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
        InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);

    // Compositor thread gesture policy update.
    EXPECT_TRUE(scheduler_->PolicyNeedsUpdateForTesting());
    EXPECT_EQ(UseCase::kCompositorGesture,
              ForceUpdatePolicyAndGetCurrentUseCase());
    EXPECT_FALSE(scheduler_->PolicyNeedsUpdateForTesting());
  }

  void SimulateMainThreadGestureStart(TouchEventPolicy touch_event_policy,
                                      blink::WebInputEvent::Type gesture_type) {
    if (touch_event_policy == TouchEventPolicy::kSendTouchStart) {
      scheduler_->DidHandleInputEventOnCompositorThread(
          FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
          InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
      scheduler_->DidHandleInputEventOnMainThread(
          FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
          WebInputEventResult::kHandledSystem,
          /*frame_requested=*/true);

      scheduler_->DidHandleInputEventOnCompositorThread(
          FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
          InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
      scheduler_->DidHandleInputEventOnMainThread(
          FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
          WebInputEventResult::kHandledSystem,
          /*frame_requested=*/true);

      scheduler_->DidHandleInputEventOnCompositorThread(
          FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
          InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
      scheduler_->DidHandleInputEventOnMainThread(
          FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
          WebInputEventResult::kHandledSystem,
          /*frame_requested=*/true);
    }
    if (gesture_type != blink::WebInputEvent::Type::kUndefined) {
      scheduler_->DidHandleInputEventOnCompositorThread(
          FakeInputEvent(gesture_type),
          InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
      scheduler_->DidHandleInputEventOnMainThread(
          FakeInputEvent(gesture_type), WebInputEventResult::kHandledSystem,
          /*frame_requested=*/true);
    }
  }

  void SimulateMainThreadInputHandlingCompositorTask(
      base::TimeDelta begin_main_frame_duration) {
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
        InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
    test_task_runner_->AdvanceMockTickClock(begin_main_frame_duration);
    scheduler_->DidHandleInputEventOnMainThread(
        FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
        WebInputEventResult::kHandledApplication,
        /*frame_requested=*/true);
    scheduler_->DidCommitFrameToCompositor();
  }

  void SimulateMainThreadCompositorTask(
      base::TimeDelta begin_main_frame_duration) {
    test_task_runner_->AdvanceMockTickClock(begin_main_frame_duration);
    scheduler_->DidCommitFrameToCompositor();
  }

  void SimulateMainThreadCompositorAndQuitRunLoopTask(
      base::TimeDelta begin_main_frame_duration) {
    SimulateMainThreadCompositorTask(begin_main_frame_duration);
    base::RunLoop().Quit();
  }

  void SimulateThrottleableTask(base::TimeDelta duration) {
    test_task_runner_->AdvanceMockTickClock(duration);
    simulate_throttleable_task_ran_ = true;
  }

  void EnableIdleTasks() { DoMainFrame(); }

  UseCase CurrentUseCase() {
    return scheduler_->main_thread_only().current_use_case;
  }

  UseCase ForceUpdatePolicyAndGetCurrentUseCase() {
    scheduler_->ForceUpdatePolicy();
    return scheduler_->main_thread_only().current_use_case;
  }

  RAILMode GetRAILMode() {
    return scheduler_->main_thread_only().current_policy.rail_mode;
  }

  bool BlockingInputExpectedSoon() {
    return scheduler_->main_thread_only().blocking_input_expected_soon;
  }

  base::TimeTicks EstimatedNextFrameBegin() {
    return scheduler_->main_thread_only().estimated_next_frame_begin;
  }

  bool HaveSeenABlockingGesture() {
    base::AutoLock lock(scheduler_->any_thread_lock_);
    return scheduler_->any_thread().have_seen_a_blocking_gesture;
  }

  void AdvanceTimeWithTask(base::TimeDelta duration) {
    RunTask(base::BindOnce(
        [](scoped_refptr<base::TestMockTimeTaskRunner> test_task_runner,
           base::TimeDelta duration) {
          test_task_runner->AdvanceMockTickClock(duration);
        },
        test_task_runner_, duration));
  }

  void RunTask(base::OnceClosure task) {
    scoped_refptr<MainThreadTaskQueue> fake_queue =
        scheduler_->NewTaskQueue(MainThreadTaskQueue::QueueCreationParams(
            MainThreadTaskQueue::QueueType::kTest));

    base::TimeTicks start = Now();
    FakeTask fake_task;
    fake_task.set_enqueue_order(
        base::sequence_manager::EnqueueOrder::FromIntForTesting(42));
    scheduler_->OnTaskStarted(fake_queue.get(), fake_task,
                              FakeTaskTiming(start, base::TimeTicks()));
    std::move(task).Run();
    base::TimeTicks end = Now();
    FakeTaskTiming task_timing(start, end);
    scheduler_->OnTaskCompleted(fake_queue->weak_ptr_factory_.GetWeakPtr(),
                                fake_task, &task_timing, nullptr);
  }

  void RunSlowCompositorTask() {
    // Run a long compositor task so that compositor tasks appear to be running
    // slow and thus compositor tasks will not be prioritized.
    compositor_task_runner_->PostTask(
        FROM_HERE,
        base::BindOnce(
            &MainThreadSchedulerImplTest::SimulateMainThreadCompositorTask,
            base::Unretained(this), base::Milliseconds(1000)));
    base::RunLoop().RunUntilIdle();
  }

  void AppendToVectorBeginMainFrameTask(Vector<String>* vector, String value) {
    DoMainFrame();
    AppendToVectorTestTask(vector, value);
  }

  void AppendToVectorBeginMainFrameTaskWithInput(Vector<String>* vector,
                                                 String value) {
    scheduler_->DidHandleInputEventOnMainThread(
        FakeInputEvent(WebInputEvent::Type::kMouseMove),
        WebInputEventResult::kHandledApplication,
        /*frame_requested=*/true);
    AppendToVectorBeginMainFrameTask(vector, value);
  }

  void AppendToVectorInputEventTask(WebInputEvent::Type event_type,
                                    Vector<String>* vector,
                                    String value) {
    scheduler_->DidHandleInputEventOnMainThread(
        FakeInputEvent(event_type), WebInputEventResult::kHandledApplication,
        /*frame_requested=*/true);
    AppendToVectorTestTask(vector, value);
  }

  // Helper for posting several tasks of specific types. |task_descriptor| is a
  // string with space delimited task identifiers. The first letter of each
  // task identifier specifies the task type. For 'C' and 'P' types, the second
  // letter specifies that type of task to simulate.
  // - 'D': Default task
  // - 'C': Compositor task
  //   - "CM": Compositor task that simulates running a main frame
  //   - "CI": Compositor task that simulates running a main frame with
  //            rAF-algined input
  // - 'P': Input task
  //   - "PC": Input task that simulates dispatching a continuous input event
  //   - "PD": Input task that simulates dispatching a discrete input event
  // - 'E': Input task that dispatches input events
  // - 'L': Loading task
  // - 'M': Loading Control task
  // - 'I': Idle task
  // - 'R': Render-blocking task
  // - 'T': Throttleable task
  // - 'V': kV8 task
  // - 'F': FindInPage task
  // - 'U': Prioritised local frame task
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
        case 'C':
          if (task.starts_with("CM")) {
            compositor_task_runner_->PostTask(
                FROM_HERE, base::BindOnce(&MainThreadSchedulerImplTest::
                                              AppendToVectorBeginMainFrameTask,
                                          base::Unretained(this), run_order,
                                          String::FromUTF8(task)));
          } else if (task.starts_with("CI")) {
            compositor_task_runner_->PostTask(
                FROM_HERE,
                base::BindOnce(&MainThreadSchedulerImplTest::
                                   AppendToVectorBeginMainFrameTaskWithInput,
                               base::Unretained(this), run_order,
                               String::FromUTF8(task)));
          } else {
            compositor_task_runner_->PostTask(
                FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                          String::FromUTF8(task)));
          }
          break;
        case 'P':
          if (task.starts_with("PC")) {
            input_task_runner_->PostTask(
                FROM_HERE,
                base::BindOnce(
                    &MainThreadSchedulerImplTest::AppendToVectorInputEventTask,
                    base::Unretained(this), WebInputEvent::Type::kMouseMove,
                    run_order, String::FromUTF8(task)));

          } else if (task.starts_with("PD")) {
            input_task_runner_->PostTask(
                FROM_HERE,
                base::BindOnce(
                    &MainThreadSchedulerImplTest::AppendToVectorInputEventTask,
                    base::Unretained(this), WebInputEvent::Type::kMouseUp,
                    run_order, String::FromUTF8(task)));
          } else {
            input_task_runner_->PostTask(
                FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                          String::FromUTF8(task)));
          }
          break;
        case 'L':
          loading_task_queue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        case 'M':
          loading_control_task_runner_->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        case 'I':
          idle_task_runner_->PostIdleTask(
              FROM_HERE, base::BindOnce(&AppendToVectorIdleTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        case 'R':
          render_blocking_task_runner_->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        case 'T':
          throttleable_task_runner_->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        case 'V':
          v8_task_runner_->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        case 'F':
          find_in_page_task_runner_->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        case 'U':
          prioritised_local_frame_task_runner_->PostTask(
              FROM_HERE, base::BindOnce(&AppendToVectorTestTask, run_order,
                                        String::FromUTF8(task)));
          break;
        default:
          NOTREACHED();
      }
    }
  }

 protected:
  static base::TimeDelta maximum_idle_period_duration() {
    return IdleHelper::kMaximumIdlePeriod;
  }

  static base::TimeDelta end_idle_when_hidden_delay() {
    return base::Milliseconds(
        MainThreadSchedulerImpl::kEndIdleWhenHiddenDelayMillis);
  }

  static scoped_refptr<MainThreadTaskQueue> ThrottleableTaskQueue(
      FrameSchedulerImpl* scheduler) {
    auto* frame_task_queue_controller =
        scheduler->FrameTaskQueueControllerForTest();
    auto queue_traits = FrameSchedulerImpl::ThrottleableTaskQueueTraits();
    return frame_task_queue_controller->GetTaskQueue(queue_traits);
  }

  static scoped_refptr<MainThreadTaskQueue> QueueForTaskType(
      FrameSchedulerImpl* scheduler,
      TaskType task_type) {
    return scheduler->GetTaskQueue(task_type);
  }

  base::test::ScopedFeatureList feature_list_;

  scoped_refptr<base::TestMockTimeTaskRunner> test_task_runner_;

  std::unique_ptr<MainThreadSchedulerImplForTest> scheduler_;
  Persistent<AgentGroupSchedulerImpl> agent_group_scheduler_;
  std::unique_ptr<MockPageSchedulerImpl> page_scheduler_;
  std::unique_ptr<FrameSchedulerImpl> main_frame_scheduler_;
  scoped_refptr<WidgetScheduler> widget_scheduler_;

  scoped_refptr<base::SingleThreadTaskRunner> default_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> compositor_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> input_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> loading_control_task_runner_;
  scoped_refptr<SingleThreadIdleTaskRunner> idle_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> throttleable_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> v8_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> find_in_page_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner>
      prioritised_local_frame_task_runner_;
  scoped_refptr<base::SingleThreadTaskRunner> render_blocking_task_runner_;
  bool simulate_throttleable_task_ran_;
  uint64_t next_begin_frame_number_ = viz::BeginFrameArgs::kStartingFrameNumber;
};

class
    MainThreadSchedulerImplWithLoadingPhaseBufferTimeAfterFirstMeaningfulPaintTest
    : public MainThreadSchedulerImplTest,
      public ::testing::WithParamInterface<bool> {
 public:
  MainThreadSchedulerImplWithLoadingPhaseBufferTimeAfterFirstMeaningfulPaintTest() {
    if (GetParam()) {
      feature_list_.Reset();
      feature_list_.InitWithFeaturesAndParameters(
          {base::test::FeatureRefAndParams(
              features::kLoadingPhaseBufferTimeAfterFirstMeaningfulPaint,
              {{"LoadingPhaseBufferTimeAfterFirstMeaningfulPaintMillis",
                "5000"}})},
          {});
    }
  }
};

INSTANTIATE_TEST_SUITE_P(
    All,
    MainThreadSchedulerImplWithLoadingPhaseBufferTimeAfterFirstMeaningfulPaintTest,
    testing::Bool());

TEST_F(MainThreadSchedulerImplTest, TestPostDefaultTask) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 D2 D3 D4");

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "D2", "D3", "D4"));
}

TEST_F(MainThreadSchedulerImplTest, TestPostDefaultAndCompositor) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "D1 C1 P1");
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::Contains("D1"));
  EXPECT_THAT(run_order, testing::Contains("C1"));
  EXPECT_THAT(run_order, testing::Contains("P1"));
}

TEST_F(MainThreadSchedulerImplTest, TestRentrantTask) {
  int count = 0;
  Vector<int> run_order;
  default_task_runner_->PostTask(
      FROM_HERE, base::BindOnce(AppendToVectorReentrantTask,
                                base::RetainedRef(default_task_runner_),
                                &run_order, &count, 5));
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(run_order, testing::ElementsAre(0, 1, 2, 3, 4));
}

TEST_F(MainThreadSchedulerImplTest, TestPostIdleTask) {
  int run_count = 0;
  base::TimeTicks expected_deadline = Now() + base::Milliseconds(2300);
  base::TimeTicks deadline_in_task;

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(100));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, run_count);  // Shouldn't run yet as no WillBeginFrame.

  scheduler_->WillBeginFrame(viz::BeginFrameArgs::Create(
      BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
      base::TimeTicks(), base::Milliseconds(1000),
      viz::BeginFrameArgs::NORMAL));
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, run_count);  // Shouldn't run as no DidCommitFrameToCompositor.

  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(1200));
  scheduler_->DidCommitFrameToCompositor();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, run_count);  // We missed the deadline.

  scheduler_->WillBeginFrame(viz::BeginFrameArgs::Create(
      BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
      base::TimeTicks(), base::Milliseconds(1000),
      viz::BeginFrameArgs::NORMAL));
  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(800));
  scheduler_->DidCommitFrameToCompositor();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, run_count);
  EXPECT_EQ(expected_deadline, deadline_in_task);
}

TEST_F(MainThreadSchedulerImplTest, TestRepostingIdleTask) {
  int run_count = 0;

  g_max_idle_task_reposts = 2;
  idle_task_runner_->PostIdleTask(
      FROM_HERE,
      base::BindOnce(&RepostingIdleTestTask,
                     base::RetainedRef(idle_task_runner_), &run_count));
  EnableIdleTasks();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, run_count);

  // Reposted tasks shouldn't run until next idle period.
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(1, run_count);

  EnableIdleTasks();
  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(2, run_count);
}

TEST_F(MainThreadSchedulerImplTest, TestIdleTaskExceedsDeadline) {
  int run_count = 0;

  // Post two UpdateClockToDeadlineIdleTestTask tasks.
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&UpdateClockToDeadlineIdleTestTask,
                                test_task_runner_, &run_count));
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&UpdateClockToDeadlineIdleTestTask,
                                test_task_runner_, &run_count));

  EnableIdleTasks();
  base::RunLoop().RunUntilIdle();
  // Only the first idle task should execute since it's used up the deadline.
  EXPECT_EQ(1, run_count);

  EnableIdleTasks();
  base::RunLoop().RunUntilIdle();
  // Second task should be run on the next idle period.
  EXPECT_EQ(2, run_count);
}

TEST_F(MainThreadSchedulerImplTest, TestDelayedEndIdlePeriodCanceled) {
  int run_count = 0;

  base::TimeTicks deadline_in_task;
  idle_task_runner_->PostIdleTask(
      FROM_HERE, base::BindOnce(&IdleTestTask, &run_count, &deadline_in_task));

  // Trigger the beginning of an idle period for 1000ms.
  scheduler_->WillBeginFrame(viz::BeginFrameArgs::Create(
      BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
      base::TimeTicks(), base::Milliseconds(1000),
      viz::BeginFrameArgs::NORMAL));
  DoMainFrame();

  // End the idle period early (after 500ms), and send a WillBeginFrame which
  // specifies that the next idle period should end 1000ms from now.
  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(500));
  scheduler_->WillBeginFrame(viz::BeginFrameArgs::Create(
      BEGINFRAME_FROM_HERE, 0, next_begin_frame_number_++, Now(),
      base::TimeTicks(), base::Milliseconds(1000),
      viz::BeginFrameArgs::NORMAL));

  base::RunLoop().RunUntilIdle();
  EXPECT_EQ(0, run_count);  // Not currently in an idle period.

  // Trigger the start of the idle period before the task to end the previous
  // idle period has been triggered.
  test_task_runner_->AdvanceMockTickClock(base::Milliseconds(400));
  scheduler_->DidCommitFrameToCompositor();

  // Post a task which simulates running until after the previous end idle
  // period delayed task was scheduled for
  scheduler_->DefaultTaskQueue()->GetTaskRunnerWithDefaultTaskType()->PostTask(
      FROM_HERE, base::BindOnce(NullTask));
  test_task_runner_->FastForwardBy(base::Milliseconds(300));
  EXPECT_EQ(1, run_count);  // We should still be in the new idle period.
}

TEST_F(MainThreadSchedulerImplTest, TestDefaultPolicy) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 I1 D1 P1 C1 D2 P2 C2 U1");

  EnableIdleTasks();
  base::RunLoop().RunUntilIdle();
  // High-priority input is enabled and input tasks are processed first.
  // One compositing event is prioritized after an input event but still
  // has lower priority than input event.
  EXPECT_THAT(run_order, testing::ElementsAre("P1", "P2", "U1", "L1", "D1",
                                              "C1", "D2", "C2", "I1"));
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest, TestDefaultPolicyWithSlowCompositor) {
  DoMainFrame();
  RunSlowCompositorTask();

  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 I1 D1 C1 P1 D2 C2");

  EnableIdleTasks();
  base::RunLoop().RunUntilIdle();
  // Even with slow compositor input tasks are handled first.
  EXPECT_THAT(run_order,
              testing::ElementsAre("P1", "L1", "D1", "C1", "D2", "C2", "I1"));
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicy_CompositorHandlesInput_WithTouchHandler) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 I1 D1 C1 D2 C2");

  EnableIdleTasks();
  SimulateCompositorGestureStart(TouchEventPolicy::kSendTouchStart);
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("L1", "D1", "D2", "C1", "C2", "I1"));
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicy_MainThreadHandlesInput_WithoutScrollUpdates) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 I1 D1 C1 D2 C2");

  EnableIdleTasks();
  SimulateMainThreadGestureWithoutScrollUpdates();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("C1", "C2", "L1", "D1", "D2", "I1"));
  EXPECT_EQ(UseCase::kMainThreadCustomInputHandling, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicy_MainThreadHandlesInput_WithoutPreventDefault) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 I1 D1 C1 D2 C2");

  EnableIdleTasks();
  SimulateMainThreadGestureWithoutPreventDefault();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("L1", "D1", "D2", "C1", "C2", "I1"));
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicy_CompositorHandlesInput_LongGestureDuration) {
  EnableIdleTasks();
  SimulateCompositorGestureStart(TouchEventPolicy::kSendTouchStart);

  base::TimeTicks loop_end_time = Now() + UserModel::kMedianGestureDuration * 2;

  // The UseCase::kCompositorGesture usecase initially deprioritizes
  // compositor tasks (see
  // TestCompositorPolicy_CompositorHandlesInput_WithTouchHandler) but if the
  // gesture is long enough, compositor tasks get prioritized again.
  while (Now() < loop_end_time) {
    scheduler_->DidHandleInputEventOnCompositorThread(
        FakeInputEvent(blink::WebInputEvent::Type::kTouchMove),
        InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
    test_task_runner_->AdvanceMockTickClock(base::Milliseconds(16));
    base::RunLoop().RunUntilIdle();
  }

  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 I1 D1 C1 D2 C2");

  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "L1", "D1", "D2"));
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicy_CompositorHandlesInput_WithoutTouchHandler) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 I1 D1 C1 D2 C2");

  EnableIdleTasks();
  SimulateCompositorGestureStart(TouchEventPolicy::kDontSendTouchStart);
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("L1", "D1", "D2", "C1", "C2", "I1"));
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicy_MainThreadHandlesInput_WithTouchHandler) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 I1 D1 C1 D2 C2");

  EnableIdleTasks();
  SimulateMainThreadGestureStart(
      TouchEventPolicy::kSendTouchStart,
      blink::WebInputEvent::Type::kGestureScrollBegin);
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("C1", "C2", "L1", "D1", "D2", "I1"));
  EXPECT_EQ(UseCase::kMainThreadCustomInputHandling, CurrentUseCase());
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureFlingStart),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicy_MainThreadHandlesInput_WithoutTouchHandler) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 I1 D1 C1 D2 C2");

  EnableIdleTasks();
  SimulateMainThreadGestureStart(
      TouchEventPolicy::kDontSendTouchStart,
      blink::WebInputEvent::Type::kGestureScrollBegin);
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order,
              testing::ElementsAre("C1", "C2", "L1", "D1", "D2", "I1"));
  EXPECT_EQ(UseCase::kMainThreadCustomInputHandling, CurrentUseCase());
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureFlingStart),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
}

TEST_F(MainThreadSchedulerImplTest,
       TestCompositorPolicy_MainThreadHandlesInput_SingleEvent_PreventDefault) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 I1 D1 C1 D2 C2");

  EnableIdleTasks();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnMainThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      WebInputEventResult::kHandledApplication,
      /*frame_requested=*/true);
  base::RunLoop().RunUntilIdle();
  // Because the main thread is performing custom input handling, we let all
  // tasks run. However compositing tasks are still given priority.
  EXPECT_THAT(run_order,
              testing::ElementsAre("C1", "C2", "L1", "D1", "D2", "I1"));
  EXPECT_EQ(UseCase::kMainThreadCustomInputHandling, CurrentUseCase());
}

TEST_F(
    MainThreadSchedulerImplTest,
    TestCompositorPolicy_MainThreadHandlesInput_SingleEvent_NoPreventDefault) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 I1 D1 C1 D2 C2");

  EnableIdleTasks();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnMainThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  base::RunLoop().RunUntilIdle();
  // Because we are still waiting for the touchstart to be processed,
  // non-essential tasks like loading tasks are blocked.
  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "D1", "D2", "I1"));
  EXPECT_EQ(UseCase::kTouchstart, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest, Navigation_ResetsTaskCostEstimations) {
  Vector<String> run_order;

  SimulateExpensiveTasks(throttleable_task_runner_);
  DoMainFrame();
  // A navigation occurs which creates a new Document thus resetting the task
  // cost estimations.
  scheduler_->DidStartProvisionalLoad(true);
  SimulateMainThreadGestureStart(
      TouchEventPolicy::kSendTouchStart,
      blink::WebInputEvent::Type::kGestureScrollUpdate);

  PostTestTasks(&run_order, "C1 T1");

  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(run_order, testing::ElementsAre("C1", "T1"));
}

TEST_F(MainThreadSchedulerImplTest, TestTouchstartPolicy_Compositor) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 D1 C1 D2 C2 T1 T2");

  // Observation of touchstart should defer execution of throttleable, idle and
  // loading tasks.
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  EnableIdleTasks();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "D1", "D2"));

  // Animation or meta events like TapDown/FlingCancel shouldn't affect the
  // priority.
  run_order.clear();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureFlingCancel),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureTapDown),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre());

  // Action events like ScrollBegin will kick us back into compositor priority,
  // allowing service of the throttleable, loading and idle queues.
  run_order.clear();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollBegin),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(run_order, testing::ElementsAre("L1", "T1", "T2"));
}

TEST_F(MainThreadSchedulerImplTest, TestTouchstartPolicy_MainThread) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "L1 D1 C1 D2 C2 T1 T2");

  // Observation of touchstart should defer execution of throttleable, idle and
  // loading tasks.
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnMainThread(
      FakeTouchEvent(blink::WebInputEvent::Type::kTouchStart),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  EnableIdleTasks();
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "D1", "D2"));

  // Meta events like TapDown/FlingCancel shouldn't affect the priority.
  run_order.clear();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureFlingCancel),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureFlingCancel),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureTapDown),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureTapDown),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  base::RunLoop().RunUntilIdle();
  EXPECT_THAT(run_order, testing::ElementsAre());

  // Action events like ScrollBegin will kick us back into compositor priority,
  // allowing service of the throttleable, loading and idle queues.
  run_order.clear();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollBegin),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kGestureScrollBegin),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
  base::RunLoop().RunUntilIdle();

  EXPECT_THAT(run_order, testing::ElementsAre("L1", "T1", "T2"));
}

TEST_P(
    MainThreadSchedulerImplWithLoadingPhaseBufferTimeAfterFirstMeaningfulPaintTest,
    InitiallyInEarlyLoadingUseCase) {
  // `IsWaitingForMainFrame(Contentful|Meaningful)Paint return true for a new
  // page scheduler in production.
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameContentfulPaint)
      .WillByDefault(Return(true));
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameMeaningfulPaint)
      .WillByDefault(Return(true));
  ON_CALL(*page_scheduler_, IsMainFrameLoading).WillByDefault(Return(true));

  scheduler_->OnMainFramePaint();

  // Should be early loading by default.
  EXPECT_EQ(UseCase::kEarlyLoading, ForceUpdatePolicyAndGetCurrentUseCase());

  ON_CALL(*page_scheduler_, IsWaitingForMainFrameContentfulPaint)
      .WillByDefault(Return(false));
  scheduler_->OnMainFramePaint();
  EXPECT_EQ(UseCase::kLoading, CurrentUseCase());

  ON_CALL(*page_scheduler_, IsWaitingForMainFrameMeaningfulPaint)
      .WillByDefault(Return(false));
  ON_CALL(*page_scheduler_, IsMainFrameLoading).WillByDefault(Return(false));
  scheduler_->OnMainFramePaint();
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());
}

TEST_P(
    MainThreadSchedulerImplWithLoadingPhaseBufferTimeAfterFirstMeaningfulPaintTest,
    NonOrdinaryPageDoesNotTriggerLoadingUseCase) {
  // `IsWaitingForMainFrame(Contentful|Meaningful)Paint return true for a new
  // page scheduler in production.
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameContentfulPaint)
      .WillByDefault(Return(true));
  ON_CALL(*page_scheduler_, IsWaitingForMainFrameMeaningfulPaint)
      .WillByDefault(Return(true));
  ON_CALL(*page_scheduler_, IsMainFrameLoading).WillByDefault(Return(true));

  // Make the page non-ordinary.
  ON_CALL(*page_scheduler_, IsOrdinary).WillByDefault(Return(false));

  // The UseCase should be `kNone` event if the page is waiting for a first
  // contentful/meaningful paint.
  scheduler_->OnMainFramePaint();
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());
}

TEST_F(MainThreadSchedulerImplTest,
       EventConsumedOnCompositorThread_IgnoresMouseMove_WhenMouseUp) {
  DoMainFrame();
  RunSlowCompositorTask();

  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2");

  EnableIdleTasks();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kMouseMove),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  base::RunLoop().RunUntilIdle();
  // Note compositor tasks are not prioritized.
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "C1", "D2", "C2", "I1"));
}

TEST_F(MainThreadSchedulerImplTest,
       EventForwardedToMainThread_IgnoresMouseMove_WhenMouseUp) {
  DoMainFrame();
  RunSlowCompositorTask();

  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2");

  EnableIdleTasks();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kMouseMove),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  base::RunLoop().RunUntilIdle();
  // Note compositor tasks are not prioritized.
  EXPECT_EQ(UseCase::kNone, CurrentUseCase());
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "C1", "D2", "C2", "I1"));
}

TEST_F(MainThreadSchedulerImplTest,
       EventConsumedOnCompositorThread_MouseMove_WhenMouseDown) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2");

  // Note that currently the compositor will never consume mouse move events,
  // but this test reflects what should happen if that was the case.
  EnableIdleTasks();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kMouseMove,
                     blink::WebInputEvent::kLeftButtonDown),
      InputEventState::EVENT_CONSUMED_BY_COMPOSITOR);
  base::RunLoop().RunUntilIdle();
  // Note compositor tasks deprioritized.
  EXPECT_EQ(UseCase::kCompositorGesture, CurrentUseCase());
  EXPECT_THAT(run_order, testing::ElementsAre("D1", "D2", "C1", "C2", "I1"));
}

TEST_F(MainThreadSchedulerImplTest,
       EventForwardedToMainThread_MouseMove_WhenMouseDown) {
  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2");

  EnableIdleTasks();
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kMouseMove,
                     blink::WebInputEvent::kLeftButtonDown),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  base::RunLoop().RunUntilIdle();
  // Note compositor tasks are prioritized.
  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "D1", "D2", "I1"));
  scheduler_->DidHandleInputEventOnMainThread(
      FakeInputEvent(blink::WebInputEvent::Type::kMouseMove,
                     blink::WebInputEvent::kLeftButtonDown),
      WebInputEventResult::kHandledSystem,
      /*frame_requested=*/true);
}

TEST_F(MainThreadSchedulerImplTest,
       EventForwardedToMainThread_MouseMove_WhenMouseDown_AfterMouseWheel) {
  // Simulate a main thread driven mouse wheel scroll gesture.
  SimulateMainThreadGestureStart(
      TouchEventPolicy::kSendTouchStart,
      blink::WebInputEvent::Type::kGestureScrollUpdate);
  base::RunLoop().RunUntilIdle();
  EXPECT_FALSE(BlockingInputExpectedSoon());
  EXPECT_EQ(UseCase::kMainThreadGesture, CurrentUseCase());

  // Now start a main thread mouse touch gesture. It should be detected as main
  // thread custom input handling.
  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2");
  EnableIdleTasks();

  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kMouseDown,
                     blink::WebInputEvent::kLeftButtonDown),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kMouseMove,
                     blink::WebInputEvent::kLeftButtonDown),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  base::RunLoop().RunUntilIdle();

  EXPECT_EQ(UseCase::kMainThreadCustomInputHandling, CurrentUseCase());

  // Note compositor tasks are prioritized.
  EXPECT_THAT(run_order, testing::ElementsAre("C1", "C2", "D1", "D2", "I1"));
}

TEST_F(MainThreadSchedulerImplTest, EventForwardedToMainThread_MouseClick) {
  // A mouse click should be detected as main thread input handling, which means
  // we won't try to defer expensive tasks because of one. We can, however,
  // prioritize compositing/input handling.
  Vector<String> run_order;
  PostTestTasks(&run_order, "I1 D1 C1 D2 C2");
  EnableIdleTasks();

  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink::WebInputEvent::Type::kMouseDown,
                     blink::WebInputEvent::kLeftButtonDown),
      InputEventState::EVENT_FORWARDED_TO_MAIN_THREAD);
  scheduler_->DidHandleInputEventOnCompositorThread(
      FakeInputEvent(blink
"""


```