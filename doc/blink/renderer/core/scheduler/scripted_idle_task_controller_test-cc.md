Response:
Let's break down the thought process for analyzing the C++ test file.

1. **Understand the Goal:** The primary goal is to figure out what the code *does* and how it relates to web technologies (JavaScript, HTML, CSS). Since it's a test file (`*_test.cc`), it's specifically designed to verify the functionality of another piece of code. The filename `scripted_idle_task_controller_test.cc` gives a strong clue that it's testing something called `ScriptedIdleTaskController`.

2. **Initial Code Scan (High-Level):**  Start by glancing through the code to get a general feel. Look for keywords and structures that stand out:
    * Includes:  `#include` statements tell us what other components this code relies on. We see includes related to:
        * Standard C++ (`<deque>`)
        * Chromium base library (`"base/..."`) - this hints at platform-level features.
        * Testing frameworks (`"testing/gmock/..."`, `"testing/gtest/..."`) - confirms it's a test file.
        * Blink specific headers (`"third_party/blink/..."`) - This is the core area of interest. Pay attention to the specific Blink modules: `mojom/frame/lifecycle.mojom-blink.h`, `platform/scheduler/...`, `bindings/core/v8/...`, `core/testing/...`. These give clues about the functionality being tested. "scheduler" and "bindings/core/v8" are key terms related to JavaScript execution and browser scheduling.
    * Namespaces: `blink` confirms it's Blink-specific code. The anonymous namespace `namespace {` often contains helper classes and functions used only within this test file.
    * Classes:  Identify the main classes. We see `DelayedTaskHandleDelegateFacade`, `TestTaskRunner`, `MockScriptedIdleTaskControllerScheduler`, `IdleTaskControllerFrameScheduler`, `MockIdleTask`, and the main test fixture `ScriptedIdleTaskControllerTest`.
    * Test Macros:  `TEST_P`, `EXPECT_EQ`, `EXPECT_NE`, `EXPECT_CALL` are signs of Google Test being used.

3. **Focus on Key Components:** Now, dig deeper into the more relevant parts:

    * **`ScriptedIdleTaskController` (from the filename):**  While the test file *doesn't define* this class, its presence in the filename and the `GetController()` method strongly suggest it's the subject under test. The name itself implies it manages "idle tasks" triggered by scripts. This likely relates to the `requestIdleCallback` API in JavaScript.

    * **`MockScriptedIdleTaskControllerScheduler`:** The "Mock" prefix usually means this is a test double. It simulates the behavior of a real scheduler. Look at its methods: `ShouldYieldForHighPriorityWork()`, `PostIdleTask()`, `RunIdleTask()`. This reinforces the idea of managing and executing idle tasks. The `should_yield_` member suggests it controls whether the scheduler should pause execution for more important tasks.

    * **`IdleTaskControllerFrameScheduler`:**  This seems to be a mock for a `FrameScheduler`, which manages scheduling within a browser frame. It likely interacts with the `ScriptedIdleTaskController`. The connection to `PageScheduler` and `AgentGroupScheduler` indicates its place in the broader Blink scheduling hierarchy.

    * **`MockIdleTask`:** Another mock, this one represents the actual idle task being executed. The `invoke()` method is likely what gets called when the idle task runs.

    * **`TestTaskRunner`:** This custom task runner likely intercepts task posting and cancellation events to allow the tests to verify those actions. The `GetTaskCanceledCount()` is a key indicator of its purpose.

    * **Test Cases (`TEST_P(...)`):**  Read through the individual test cases. Each test aims to verify a specific aspect of the `ScriptedIdleTaskController`'s behavior. Look for the actions being performed: `RegisterCallback`, `CancelCallback`, simulating pauses and unpauses. Pay attention to the assertions (`EXPECT_EQ`, `EXPECT_NE`, `EXPECT_CALL`).

4. **Connect to Web Technologies (JavaScript, HTML, CSS):**  Now, think about how the observed behavior relates to web development:

    * **`requestIdleCallback`:** The core functionality being tested strongly aligns with the JavaScript `requestIdleCallback` API. This API allows developers to schedule non-critical tasks to run when the browser is idle, avoiding interference with more important operations like rendering or user interactions.

    * **`RegisterCallback`:**  This likely corresponds to calling `requestIdleCallback` in JavaScript. The `IdleRequestOptions` with `timeout` would map directly to the options passed to `requestIdleCallback`.

    * **"Yielding":** The `ShouldYieldForHighPriorityWork()` mechanism is crucial for ensuring responsiveness. If the browser becomes busy, idle tasks should be paused. This directly relates to the benefits of using `requestIdleCallback`.

    * **Timeouts:** The tests with timeouts demonstrate how the controller handles cases where an idle task isn't executed before its specified timeout.

    * **Pausing/Unpausing:**  The tests involving `ContextLifecycleStateChanged` highlight how the idle task controller interacts with the browser's lifecycle. When a page is in the background or paused, idle tasks might be suspended.

    * **Memory Management (OOM Fix):**  The `kScriptedIdleTaskControllerOOMFix` feature flag and the tests checking `GetTaskCanceledCount()` point to efforts to optimize memory usage by canceling unnecessary idle tasks or their timers.

5. **Logical Inference (Input/Output):** Consider the input to the `ScriptedIdleTaskController` (registration of callbacks with options) and the expected output (execution of callbacks, potential cancellation, interaction with the scheduler). For example:

    * **Input:** JavaScript calls `requestIdleCallback(myFunction, { timeout: 1000 })`.
    * **Inference:** The `RegisterCallback` method in the `ScriptedIdleTaskController` is called. A timer is set. The idle task is queued.
    * **Output (Scenario 1 - Idle time available):** `myFunction` is eventually executed with an `IdleDeadline` object.
    * **Output (Scenario 2 - Timeout occurs):** `myFunction` is not executed. The timer is canceled.

6. **Common Usage Errors:** Think about how developers might misuse `requestIdleCallback` and how the controller might handle those situations:

    * **Registering too many idle callbacks:** While not directly tested here, the memory management aspects hint at the importance of not overwhelming the system with idle tasks.
    * **Relying on immediate execution:** Developers need to understand that idle callbacks are not guaranteed to run immediately. The "yielding" mechanism ensures higher-priority tasks are prioritized.
    * **Not handling the `IdleDeadline` correctly:** Although not a direct focus of these tests, the `IdleDeadline` provides information about remaining idle time, which developers should use to avoid blocking the main thread.

7. **Refine and Organize:** Finally, structure the findings into a clear and concise explanation, grouping related functionalities and providing specific examples. Use the information gathered from the code analysis to support the explanations.

By following this process of initial scanning, focused analysis, connecting to web concepts, inferring logic, considering errors, and refining the output, we can effectively understand the purpose and functionality of the given C++ test file.
这个文件 `blink/renderer/core/scheduler/scripted_idle_task_controller_test.cc` 是 Chromium Blink 引擎的源代码文件，它主要用于**测试 `ScriptedIdleTaskController` 类的功能**。 `ScriptedIdleTaskController` 的职责是管理和执行由 JavaScript `requestIdleCallback` API 注册的空闲任务。

让我们详细列举一下它的功能，并解释它与 JavaScript、HTML、CSS 的关系，以及潜在的逻辑推理和常见错误：

**功能列表:**

1. **测试空闲任务的注册和执行:**
   - 模拟 JavaScript 代码调用 `window.requestIdleCallback(callback)` 注册一个空闲任务。
   - 验证当浏览器处于空闲状态时，注册的回调函数（`MockIdleTask`）是否被正确调用。
   - 测试在空闲任务执行时，`IdleDeadline` 对象是否被传递给回调函数。

2. **测试空闲任务的取消:**
   - 模拟 JavaScript 代码调用 `window.cancelIdleCallback(id)` 取消一个已注册的空闲任务。
   - 验证取消操作是否阻止了回调函数的执行。
   - 测试取消操作是否会清理相关的定时器和资源。

3. **测试空闲任务的超时机制:**
   - 模拟 JavaScript 代码调用 `window.requestIdleCallback(callback, { timeout: ... })` 注册一个带有超时的空闲任务。
   - 验证如果浏览器在超时时间到期前没有进入空闲状态，回调函数是否会被强制执行。
   - 测试超时机制是否按预期工作，包括超时时间的计算和任务的执行。

4. **测试在不同调度器状态下的行为:**
   - 使用 `MockScriptedIdleTaskControllerScheduler` 模拟不同的调度器状态，例如是否应该让步给更高优先级的任务。
   - 验证当调度器指示需要让步时，空闲任务是否不会立即执行，而是被重新调度。

5. **测试在页面生命周期变化时的行为:**
   - 模拟页面生命周期状态的变化，例如从运行状态到暂停状态（`mojom::FrameLifecycleState::kPaused`）。
   - 验证在页面暂停时，空闲任务的执行是否受到影响，以及在页面恢复运行时，任务是否能够继续执行。

6. **测试内存管理和资源清理:**
   - 特别关注带有超时的空闲任务的定时器是否在任务执行或取消后被正确清理，防止内存泄漏（OOM 错误）。 文件中提到了 `kScriptedIdleTaskControllerOOMFix` 特性标志，表明存在对内存管理的优化。

**与 JavaScript, HTML, CSS 的关系举例说明:**

* **JavaScript:** `ScriptedIdleTaskController` 直接对应于 JavaScript 的 `requestIdleCallback` 和 `cancelIdleCallback` API。
    * **假设输入:** JavaScript 代码 `requestIdleCallback(() => { console.log('Idle task executed!'); }, { timeout: 500 });`
    * **对应测试:** `TEST_P(ScriptedIdleTaskControllerTest, RunCallback)` 和 `TEST_P(ScriptedIdleTaskControllerTest, LongTimeoutShouldBeRemoveFromQueue)` 等测试用例模拟了这种注册行为，并验证了回调函数的执行和超时机制。
* **HTML:**  HTML 页面加载和渲染过程中可能会触发 `requestIdleCallback`。 例如，一个网站可能在空闲时加载延迟加载的图片或执行不影响首屏渲染的任务。
    * **假设场景:** 一个网页在加载完成后，使用 `requestIdleCallback` 来分析用户行为数据并发送到服务器。
    * **`ScriptedIdleTaskController` 的作用:**  确保这个分析任务在用户交互不繁忙的时候执行，避免影响页面流畅度。
* **CSS:**  CSS 动画或复杂的样式计算可能会影响浏览器的繁忙程度，从而间接地影响 `requestIdleCallback` 的执行时机。 如果浏览器忙于处理 CSS 相关的任务，空闲回调将需要等待更长时间才能执行。
    * **假设场景:** 一个网页有复杂的 CSS 动画正在运行。
    * **`ScriptedIdleTaskController` 的作用:**  `ShouldYieldForHighPriorityWork()` 方法模拟了这种场景，测试在浏览器繁忙时，空闲任务是否会延迟执行，以保证动画的流畅性。

**逻辑推理的假设输入与输出:**

* **假设输入:**  调用 `GetController()->RegisterCallback(idle_task, options)` 注册一个空闲任务，并且调度器 (`MockScriptedIdleTaskControllerScheduler`) 的 `should_yield_` 值为 `false` (表示可以执行低优先级任务)。
* **输出:** 预期 `scheduler_->RunIdleTask()` 会调用 `idle_task` 的 `invoke` 方法，执行注册的回调函数。  测试用例 `TEST_P(ScriptedIdleTaskControllerTest, RunCallback)` 验证了这一点。

* **假设输入:** 调用 `GetController()->RegisterCallback(idle_task, options)` 注册一个空闲任务，并且调度器的 `should_yield_` 值为 `true` (表示应该让步给更高优先级任务)。
* **输出:** 预期 `scheduler_->RunIdleTask()` 不会立即调用 `idle_task` 的 `invoke` 方法，而是会将该空闲任务重新调度，等待后续的空闲时间。 测试用例 `TEST_P(ScriptedIdleTaskControllerTest, DontRunCallbackWhenAskedToYield)` 验证了这一点。

**涉及用户或编程常见的使用错误举例说明:**

* **未正确取消空闲任务:**  如果 JavaScript 代码注册了一个带有超时时间的空闲任务，但在任务执行前页面发生了导航或关闭，而没有调用 `cancelIdleCallback`，那么相关的定时器可能会继续存在，造成资源浪费，甚至可能在页面卸载后仍然尝试执行回调函数，导致错误。  测试用例 `TEST_P(ScriptedIdleTaskControllerTest, RunAfterSchedulerWasDeleted)` 模拟了这种场景，并验证了即使在 `ScriptedIdleTaskController` 已经被销毁的情况下，超时任务也能被正确取消，防止潜在的崩溃或错误。
* **过度依赖空闲回调的及时性:**  开发者可能会错误地认为 `requestIdleCallback` 注册的任务会立即或在很短的时间内执行。 然而，浏览器的空闲时间是不确定的，受到其他任务的影响。 如果关键逻辑放在空闲回调中，可能会导致延迟或不执行。  虽然测试文件本身不直接测试这种用户错误，但它验证了 `ScriptedIdleTaskController` 在各种调度状态下的行为，帮助开发者理解空闲回调的执行时机。
* **内存泄漏风险:**  在注册带有超时的空闲任务时，如果没有妥善处理取消逻辑，或者 `ScriptedIdleTaskController` 没有正确管理定时器，可能会导致内存泄漏。 测试用例 `TEST_P(ScriptedIdleTaskControllerTest, LongTimeoutShouldBeRemoveFromQueue)` 和 `TEST_P(ScriptedIdleTaskControllerTest, SchedulerTimeoutTaskCanceledOnIdleTaskCanceled)` 关注了这方面的测试，验证了超时定时器在任务执行或取消后是否被正确清理。

总而言之，`blink/renderer/core/scheduler/scripted_idle_task_controller_test.cc` 是一个至关重要的测试文件，它确保了 Blink 引擎中 `requestIdleCallback` API 的核心逻辑的正确性和健壮性，涵盖了任务注册、执行、取消、超时、调度以及生命周期管理等多个方面，并特别关注了潜在的内存管理问题。

### 提示词
```
这是目录为blink/renderer/core/scheduler/scripted_idle_task_controller_test.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明
```

### 源代码
```cpp
// Copyright 2017 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/core/scheduler/scripted_idle_task_controller.h"

#include <deque>

#include "base/task/single_thread_task_runner.h"
#include "base/test/scoped_feature_list.h"
#include "testing/gmock/include/gmock/gmock.h"
#include "testing/gtest/include/gtest/gtest.h"
#include "third_party/blink/public/mojom/frame/lifecycle.mojom-blink.h"
#include "third_party/blink/public/platform/scheduler/web_agent_group_scheduler.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_idle_request_callback.h"
#include "third_party/blink/renderer/bindings/core/v8/v8_idle_request_options.h"
#include "third_party/blink/renderer/core/testing/null_execution_context.h"
#include "third_party/blink/renderer/platform/scheduler/public/dummy_schedulers.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/page_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_task_queue.h"
#include "third_party/blink/renderer/platform/scheduler/test/fake_task_runner.h"
#include "third_party/blink/renderer/platform/testing/scoped_scheduler_overrider.h"
#include "third_party/blink/renderer/platform/testing/task_environment.h"

namespace blink {
namespace {

using ShouldYield = base::StrongAlias<class ShouldYieldTag, bool>;

// A facade to a real DelayedTaskHandle instance that hooks CancelTask() call.
class DelayedTaskHandleDelegateFacade
    : public base::DelayedTaskHandle::Delegate {
 public:
  explicit DelayedTaskHandleDelegateFacade(base::DelayedTaskHandle handle,
                                           base::OnceClosure on_canceled)
      : handle_(std::move(handle)), on_canceled_(std::move(on_canceled)) {}
  ~DelayedTaskHandleDelegateFacade() override = default;

  bool IsValid() const override { return handle_.IsValid(); }

  void CancelTask() override {
    if (IsValid()) {
      std::move(on_canceled_).Run();
    }
    handle_.CancelTask();
  }

 private:
  base::DelayedTaskHandle handle_;
  base::OnceClosure on_canceled_;
};

// A variant of `FakeTaskRunner` that counts the number of cancelled tasks.
class TestTaskRunner : public scheduler::FakeTaskRunner {
 public:
  int GetTaskCanceledCount() const { return task_canceled_count_; }

 private:
  base::DelayedTaskHandle PostCancelableDelayedTask(
      base::subtle::PostDelayedTaskPassKey pass_key,
      const base::Location& from_here,
      base::OnceClosure task,
      base::TimeDelta delay) override {
    auto handle = scheduler::FakeTaskRunner::PostCancelableDelayedTask(
        pass_key, from_here, std::move(task), delay);
    return base::DelayedTaskHandle(
        std::make_unique<DelayedTaskHandleDelegateFacade>(
            std::move(handle),
            base::BindOnce(&TestTaskRunner::OnTaskCanceled, this)));
  }

  void OnTaskCanceled() { ++task_canceled_count_; }

  int task_canceled_count_ = 0;
};
class MockScriptedIdleTaskControllerScheduler final : public ThreadScheduler {
 public:
  explicit MockScriptedIdleTaskControllerScheduler(ShouldYield should_yield)
      : should_yield_(should_yield) {}
  MockScriptedIdleTaskControllerScheduler(
      const MockScriptedIdleTaskControllerScheduler&) = delete;
  MockScriptedIdleTaskControllerScheduler& operator=(
      const MockScriptedIdleTaskControllerScheduler&) = delete;
  ~MockScriptedIdleTaskControllerScheduler() override = default;

  // ThreadScheduler implementation:
  scoped_refptr<base::SingleThreadTaskRunner> V8TaskRunner() override {
    return nullptr;
  }
  scoped_refptr<base::SingleThreadTaskRunner> CleanupTaskRunner() override {
    return nullptr;
  }
  void Shutdown() override {}
  bool ShouldYieldForHighPriorityWork() override { return should_yield_; }
  void PostIdleTask(const base::Location&,
                    Thread::IdleTask idle_task) override {
    idle_tasks_.push_back(std::move(idle_task));
  }
  void PostDelayedIdleTask(const base::Location&,
                           base::TimeDelta,
                           Thread::IdleTask) override {
    NOTIMPLEMENTED();
  }
  void PostNonNestableIdleTask(const base::Location&,
                               Thread::IdleTask) override {}
  base::TimeTicks MonotonicallyIncreasingVirtualTime() override {
    return base::TimeTicks();
  }

  void AddTaskObserver(Thread::TaskObserver* task_observer) override {}

  void RemoveTaskObserver(Thread::TaskObserver* task_observer) override {}

  void SetV8Isolate(v8::Isolate* isolate) override { isolate_ = isolate; }

  void RunIdleTask() { TakeIdleTask().Run(base::TimeTicks()); }
  size_t GetNumIdleTasks() const { return idle_tasks_.size(); }
  Thread::IdleTask TakeIdleTask() {
    CHECK(!idle_tasks_.empty());
    auto idle_task = std::move(idle_tasks_.front());
    idle_tasks_.pop_front();
    return idle_task;
  }

  scoped_refptr<TestTaskRunner> TaskRunner() { return task_runner_; }

  void AdvanceTimeAndRun(base::TimeDelta delta) {
    task_runner_->AdvanceTimeAndRun(delta);
  }

  v8::Isolate* GetIsolate() { return isolate_; }

 private:
  v8::Isolate* isolate_;
  bool should_yield_;
  std::deque<Thread::IdleTask> idle_tasks_;
  scoped_refptr<TestTaskRunner> task_runner_ =
      base::MakeRefCounted<TestTaskRunner>();
};

class IdleTaskControllerFrameScheduler : public FrameScheduler {
 public:
  explicit IdleTaskControllerFrameScheduler(
      MockScriptedIdleTaskControllerScheduler* scripted_idle_scheduler)
      : scripted_idle_scheduler_(scripted_idle_scheduler),
        page_scheduler_(scheduler::CreateDummyPageScheduler(
            scripted_idle_scheduler->GetIsolate())) {}
  ~IdleTaskControllerFrameScheduler() override = default;

  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunner(TaskType) override {
    DCHECK(WTF::IsMainThread());
    return scripted_idle_scheduler_->TaskRunner();
  }

  PageScheduler* GetPageScheduler() const override {
    return page_scheduler_.get();
  }
  AgentGroupScheduler* GetAgentGroupScheduler() override {
    return &page_scheduler_->GetAgentGroupScheduler();
  }

  void SetPreemptedForCooperativeScheduling(Preempted) override {}
  void SetFrameVisible(bool) override {}
  bool IsFrameVisible() const override { return true; }
  void SetVisibleAreaLarge(bool) override {}
  void SetHadUserActivation(bool) override {}
  bool IsPageVisible() const override { return true; }
  void SetPaused(bool) override {}
  void SetShouldReportPostedTasksWhenDisabled(bool) override {}
  void SetCrossOriginToNearestMainFrame(bool) override {}
  bool IsCrossOriginToNearestMainFrame() const override { return false; }
  void SetAgentClusterId(const base::UnguessableToken&) override {}
  void SetIsAdFrame(bool is_ad_frame) override {}
  bool IsAdFrame() const override { return false; }
  bool IsInEmbeddedFrameTree() const override { return false; }
  void TraceUrlChange(const String&) override {}
  void AddTaskTime(base::TimeDelta) override {}
  FrameType GetFrameType() const override { return FrameType::kMainFrame; }
  WebScopedVirtualTimePauser CreateWebScopedVirtualTimePauser(
      const String& name,
      WebScopedVirtualTimePauser::VirtualTaskDuration) override {
    return WebScopedVirtualTimePauser();
  }
  void DidStartProvisionalLoad() override {}
  void DidCommitProvisionalLoad(bool,
                                FrameScheduler::NavigationType,
                                DidCommitProvisionalLoadParams) override {}
  void OnFirstContentfulPaintInMainFrame() override {}
  void OnMainFrameInteractive() override {}
  void OnFirstMeaningfulPaint(base::TimeTicks timestamp) override {}
  void OnDispatchLoadEvent() override {}
  bool IsExemptFromBudgetBasedThrottling() const override { return false; }
  std::unique_ptr<blink::mojom::blink::PauseSubresourceLoadingHandle>
  GetPauseSubresourceLoadingHandle() override {
    return nullptr;
  }
  std::unique_ptr<WebSchedulingTaskQueue> CreateWebSchedulingTaskQueue(
      WebSchedulingQueueType,
      WebSchedulingPriority) override {
    return nullptr;
  }
  ukm::SourceId GetUkmSourceId() override { return ukm::kInvalidSourceId; }
  void OnStartedUsingNonStickyFeature(
      SchedulingPolicy::Feature feature,
      const SchedulingPolicy& policy,
      std::unique_ptr<SourceLocation> source_location,
      SchedulingAffectingFeatureHandle* handle) override {}
  void OnStartedUsingStickyFeature(
      SchedulingPolicy::Feature feature,
      const SchedulingPolicy& policy,
      std::unique_ptr<SourceLocation> source_location) override {}
  void OnStoppedUsingNonStickyFeature(
      SchedulingAffectingFeatureHandle* handle) override {}
  base::WeakPtr<FrameOrWorkerScheduler> GetFrameOrWorkerSchedulerWeakPtr()
      override {
    return weak_ptr_factory_.GetWeakPtr();
  }
  WTF::HashSet<SchedulingPolicy::Feature>
  GetActiveFeaturesTrackedForBackForwardCacheMetrics() override {
    return WTF::HashSet<SchedulingPolicy::Feature>();
  }
  base::WeakPtr<FrameScheduler> GetWeakPtr() override {
    return weak_ptr_factory_.GetWeakPtr();
  }
  void ReportActiveSchedulerTrackedFeatures() override {}
  scoped_refptr<base::SingleThreadTaskRunner> CompositorTaskRunner() override {
    return scripted_idle_scheduler_->TaskRunner();
  }
  base::TimeDelta UnreportedTaskTime() const override {
    return base::TimeDelta();
  }

 private:
  MockScriptedIdleTaskControllerScheduler* scripted_idle_scheduler_;
  std::unique_ptr<PageScheduler> page_scheduler_;
  base::WeakPtrFactory<FrameScheduler> weak_ptr_factory_{this};
};

class MockIdleTask : public IdleTask {
 public:
  MOCK_METHOD1(invoke, void(IdleDeadline*));
};
}  // namespace

class ScriptedIdleTaskControllerTest
    : public testing::Test,
      public testing::WithParamInterface<bool> {
 public:
  ScriptedIdleTaskControllerTest() {
    if (IsOOMFixEnabled()) {
      scoped_feature_list_.InitAndEnableFeature(
          kScriptedIdleTaskControllerOOMFix);
    } else {
      scoped_feature_list_.InitAndDisableFeature(
          kScriptedIdleTaskControllerOOMFix);
    }
  }

  void InitializeScheduler(ShouldYield should_yield) {
    scheduler_.emplace(should_yield);
    scheduler_overrider_.emplace(&scheduler_.value(), scheduler_->TaskRunner());
    execution_context_.emplace(
        std::make_unique<IdleTaskControllerFrameScheduler>(
            &scheduler_.value()));
  }

  void DeleteScheduler() {
    execution_context_.reset();
    scheduler_overrider_.reset();
    scheduler_.reset();
  }

  ScriptedIdleTaskController* GetController() {
    return &ScriptedIdleTaskController::From(
        execution_context_->GetExecutionContext());
  }

  bool IsOOMFixEnabled() { return GetParam(); }

 protected:
  test::TaskEnvironment task_environment_;
  std::optional<MockScriptedIdleTaskControllerScheduler> scheduler_;

 private:
  base::test::ScopedFeatureList scoped_feature_list_;
  std::optional<ScopedSchedulerOverrider> scheduler_overrider_;
  std::optional<ScopedNullExecutionContext> execution_context_;
};

TEST_P(ScriptedIdleTaskControllerTest, RunCallback) {
  InitializeScheduler(ShouldYield(false));

  Persistent<MockIdleTask> idle_task(MakeGarbageCollected<MockIdleTask>());
  IdleRequestOptions* options = IdleRequestOptions::Create();
  EXPECT_EQ(0u, scheduler_->GetNumIdleTasks());
  int id = GetController()->RegisterCallback(idle_task, options);
  EXPECT_NE(id, 0);
  EXPECT_EQ(1u, scheduler_->GetNumIdleTasks());

  EXPECT_CALL(*idle_task, invoke(testing::_));
  scheduler_->RunIdleTask();
  testing::Mock::VerifyAndClearExpectations(idle_task);
  EXPECT_EQ(0u, scheduler_->GetNumIdleTasks());
}

TEST_P(ScriptedIdleTaskControllerTest, DontRunCallbackWhenAskedToYield) {
  InitializeScheduler(ShouldYield(true));

  Persistent<MockIdleTask> idle_task(MakeGarbageCollected<MockIdleTask>());
  IdleRequestOptions* options = IdleRequestOptions::Create();
  int id = GetController()->RegisterCallback(idle_task, options);
  EXPECT_NE(0, id);

  EXPECT_CALL(*idle_task, invoke(testing::_)).Times(0);
  scheduler_->RunIdleTask();
  testing::Mock::VerifyAndClearExpectations(idle_task);

  // The idle task should have been reposted.
  EXPECT_EQ(1u, scheduler_->GetNumIdleTasks());
}

TEST_P(ScriptedIdleTaskControllerTest, LongTimeoutShouldBeRemoveFromQueue) {
  InitializeScheduler(ShouldYield(false));

  // Register an idle task with a deadline.
  Persistent<MockIdleTask> idle_task(MakeGarbageCollected<MockIdleTask>());
  IdleRequestOptions* options = IdleRequestOptions::Create();
  options->setTimeout(1000000);
  int id = GetController()->RegisterCallback(idle_task, options);
  EXPECT_NE(id, 0);
  EXPECT_EQ(scheduler_->TaskRunner()->GetTaskCanceledCount(), 0);

  // Run the task.
  EXPECT_CALL(*idle_task, invoke(testing::_));
  scheduler_->RunIdleTask();
  testing::Mock::VerifyAndClearExpectations(idle_task);

  // The timeout task should be removed from the task queue.
  // Failure to do so is likely to result in OOM.
  EXPECT_EQ(scheduler_->TaskRunner()->GetTaskCanceledCount(), 1);
}

TEST_P(ScriptedIdleTaskControllerTest, RunAfterSchedulerWasDeleted) {
  InitializeScheduler(ShouldYield(false));

  scoped_refptr<TestTaskRunner> task_runner = scheduler_->TaskRunner();

  Persistent<MockIdleTask> idle_task(MakeGarbageCollected<MockIdleTask>());
  IdleRequestOptions* options = IdleRequestOptions::Create();
  options->setTimeout(1);

    // Register an idle task with a deadline.
  int id = GetController()->RegisterCallback(idle_task, options);
  EXPECT_NE(id, 0);

  Thread::IdleTask thread_idle_task = scheduler_->TakeIdleTask();

  DeleteScheduler();

  EXPECT_CALL(*idle_task, invoke(testing::_)).Times(0);
  std::move(thread_idle_task).Run(base::TimeTicks());
  testing::Mock::VerifyAndClearExpectations(idle_task);

  EXPECT_EQ(task_runner->GetTaskCanceledCount(), 1);
}

TEST_P(ScriptedIdleTaskControllerTest, NoUnnecessaryRepostOnUnpause) {
  InitializeScheduler(ShouldYield(false));

  // Register an idle task.
  Persistent<MockIdleTask> idle_task(MakeGarbageCollected<MockIdleTask>());
  GetController()->RegisterCallback(idle_task, IdleRequestOptions::Create());

  // Pause/unpause the context a few times.
  for (int i = 0; i < 3; ++i) {
    GetController()->ContextLifecycleStateChanged(
        mojom::FrameLifecycleState::kPaused);
    GetController()->ContextLifecycleStateChanged(
        mojom::FrameLifecycleState::kRunning);
  }

  // Pausing/unpausing the context should not cause more scheduler idle tasks to
  // be posted. That would unnecessarily use memory.
  if (IsOOMFixEnabled()) {
    EXPECT_EQ(scheduler_->GetNumIdleTasks(), 1u);
  } else {
    EXPECT_GT(scheduler_->GetNumIdleTasks(), 1u);
  }
}

TEST_P(ScriptedIdleTaskControllerTest,
       SchedulerTimeoutTaskCanceledOnIdleTaskCanceled) {
  InitializeScheduler(ShouldYield(false));

  // Register and cancel an idle task with a timeout.
  Persistent<MockIdleTask> idle_task(MakeGarbageCollected<MockIdleTask>());
  IdleRequestOptions* options = IdleRequestOptions::Create();
  options->setTimeout(1);
  const int id = GetController()->RegisterCallback(idle_task, options);
  GetController()->CancelCallback(id);

  // The scheduler timeout task should be canceled. Otherwise, it stays in the
  // queue until the timeout expires which unnecessarily uses memory.
  if (IsOOMFixEnabled()) {
    EXPECT_EQ(scheduler_->TaskRunner()->GetTaskCanceledCount(), 1);
  } else {
    EXPECT_EQ(scheduler_->TaskRunner()->GetTaskCanceledCount(), 0);
  }
}

INSTANTIATE_TEST_SUITE_P(, ScriptedIdleTaskControllerTest, ::testing::Bool());

}  // namespace blink
```