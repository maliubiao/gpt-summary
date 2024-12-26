Response: Let's break down the thought process for analyzing the `dummy_schedulers.cc` file.

1. **Understand the Purpose:** The file name itself, "dummy_schedulers.cc," strongly suggests that it's providing placeholder or simplified implementations of scheduler components. The comment at the top reinforces this by mentioning it's for cases where a full scheduler isn't needed.

2. **Identify Key Classes:** Scan the file for class definitions. The prominent ones are:
    * `DummyWidgetScheduler`
    * `DummyFrameScheduler`
    * `DummyPageScheduler`
    * `SimpleMainThread`
    * `SimpleMainThreadWithScheduler`
    * `DummyWebMainThreadScheduler`
    * `DummyAgentGroupScheduler`

3. **Analyze Each Class Individually:** For each class, examine its methods and what they *do* (or, in this case, *don't do*).

    * **`DummyWidgetScheduler`:**  Most methods are empty or return a default task runner. This indicates it's a no-op or minimally functional placeholder for the real `WidgetScheduler`. Key methods related to input events and frame lifecycle are present but do nothing.

    * **`DummyFrameScheduler`:**  Similarly, methods related to frame visibility, lifecycle events (loads, paints), and task queue creation are present but have basic or no implementations. It holds a `DummyPageScheduler`.

    * **`DummyPageScheduler`:**  Again, lifecycle methods and the creation of `FrameScheduler` and `WidgetScheduler` instances are present, but the logic is minimal. It holds a `DummyAgentGroupScheduler`.

    * **`SimpleMainThread`:** This class focuses on providing access to the main thread's task runner. It has logic for testing purposes (`SetMainThreadTaskRunnerForTesting`). It relies on `base::SingleThreadTaskRunner::GetCurrentDefault()`.

    * **`SimpleMainThreadWithScheduler`:**  A variation of `SimpleMainThread` that includes an actual `SimpleMainThreadScheduler`. This suggests a slightly less "dummy" scenario.

    * **`DummyWebMainThreadScheduler`:**  Implements the `WebThreadScheduler` and `MainThreadScheduler` interfaces. Most methods are empty or return defaults. It handles the creation of `AgentGroupScheduler`.

    * **`DummyAgentGroupScheduler`:** Holds a `DummyWebMainThreadScheduler` and is responsible for creating `PageScheduler` instances. Its methods have minimal logic.

4. **Infer Relationships:** Observe how these classes are instantiated and connected. `DummyFrameScheduler` has a `DummyPageScheduler`, which has a `DummyAgentGroupScheduler`, which has a `DummyWebMainThreadScheduler`. This hierarchy reflects the real scheduler structure, but with simplified implementations.

5. **Connect to Web Technologies (JavaScript, HTML, CSS):** Consider how the *real* scheduler interacts with these technologies. Since these are dummy implementations, the *connection* is mostly through the *presence* of relevant methods.

    * **JavaScript:**  The presence of `v8::Isolate*` in the constructors hints at the scheduler's role in managing JavaScript execution. The task queue methods are also relevant. Since these are dummies, they don't *actually* schedule JS, but they provide the interface.

    * **HTML:**  Methods related to frame lifecycle (load, commit), visibility, and input events are crucial for rendering and interactivity. The dummy schedulers don't perform these actions, but their presence indicates where the real scheduler would.

    * **CSS:**  While not as direct, the frame lifecycle and rendering processes managed by the scheduler are essential for applying CSS styles and layout.

6. **Identify Logical Reasoning (and Lack Thereof):**  The dummy schedulers primarily *stub out* functionality. There isn't much complex logical reasoning. The "reasoning" is more about providing default values or doing nothing. If asked for input/output, the input would be calls to these methods, and the output would be the default return values or no action.

7. **Consider User/Programming Errors:**  The main risk is using these *dummy* schedulers in a production environment or a scenario where actual scheduling is needed. This would lead to:
    * No proper task prioritization.
    * Input events not being handled correctly.
    * Incorrect frame rendering and lifecycle management.
    * JavaScript not executing as expected.

8. **Structure the Answer:** Organize the findings into clear sections: Functionality, Relationship to Web Tech, Logical Reasoning, and Common Errors. Use bullet points and examples for clarity.

**Self-Correction/Refinement during the process:**

* **Initial thought:** "These are just empty classes."
* **Correction:** "While many methods are empty, the *presence* of these methods and the class hierarchy is significant. They define the interfaces and relationships within the scheduler system."
* **Initial thought:** "No direct connection to JS/HTML/CSS in the *code*."
* **Correction:** "The *interfaces* these dummy schedulers implement are directly related to the execution of JS, rendering of HTML, and application of CSS. They represent the points where the scheduler interacts with these technologies."
* **Initial thought:** "Hard to give input/output examples because they do nothing."
* **Correction:** "The input is the method call, and the output is the default return value or lack of action. The *lack* of complex logic is the key characteristic."

By following these steps, we can systematically analyze the provided code and generate a comprehensive and accurate explanation.
这个文件 `blink/renderer/platform/scheduler/common/dummy_schedulers.cc` 的主要功能是 **提供一组“虚拟”或“空操作”的调度器实现**。 这些虚拟调度器在功能上是最小化的，通常不执行任何实际的调度或资源管理操作。 它们主要用于以下几种场景：

* **测试环境:** 在单元测试或集成测试中，有时不需要完整的调度器功能。 使用虚拟调度器可以简化测试设置，避免与复杂的调度逻辑产生耦合，专注于测试被测代码的核心功能。
* **占位符或默认值:** 在某些情况下，可能需要一个调度器对象，但实际的调度逻辑尚未实现或当前不需要。虚拟调度器可以作为占位符，避免空指针或构建错误。
* **禁用某些功能:**  在特定的配置或场景下，可能需要禁用某些调度器功能。使用虚拟调度器可以有效地关闭这些功能。

**它与 JavaScript, HTML, CSS 的功能关系：**

尽管这些是“虚拟”调度器，但它们所实现的接口 (例如 `WidgetScheduler`, `FrameScheduler`, `PageScheduler`) 与渲染引擎处理 JavaScript, HTML, 和 CSS 的过程息息相关。 真实的调度器负责管理和协调与这些技术相关的各种任务的执行。

以下是一些虚拟调度器与 Web 技术相关的接口以及它们在真实场景中的作用，以及虚拟调度器如何“忽略”这些作用的例子：

1. **`WidgetScheduler`:**  与渲染 Widget (例如，浏览器的渲染区域) 相关的调度。
    * **真实场景:**  负责安排处理输入事件 (鼠标点击、键盘输入等)、触发合成器线程进行渲染、管理帧的开始等。
    * **虚拟调度器 (`DummyWidgetScheduler`) 的例子:**
        * `WillBeginFrame(const viz::BeginFrameArgs& args)`: 在真实调度器中，这会触发主线程的布局、绘制等操作。在虚拟调度器中，这个方法是空的，什么也不做。
        * `DidHandleInputEventOnMainThread(...)`:  在真实调度器中，处理输入事件后可能需要调度 JavaScript 回调或触发重绘。在虚拟调度器中，这些操作被忽略。

2. **`FrameScheduler`:**  与单个帧 (Frame) 的生命周期和任务调度相关。
    * **真实场景:**  负责管理 JavaScript 任务的执行、处理页面加载事件、控制帧的可见性、进行性能优化等。
    * **虚拟调度器 (`DummyFrameScheduler`) 的例子:**
        * `CreateWebSchedulingTaskQueue(WebSchedulingQueueType, WebSchedulingPriority)`: 在真实调度器中，会创建用于执行特定类型和优先级的任务队列。在虚拟调度器中，返回 `nullptr`，表示没有实际的任务队列。
        * `OnFirstContentfulPaintInMainFrame()`:  在真实调度器中，会记录关键的性能指标。在虚拟调度器中，这个方法是空的。

3. **`PageScheduler`:**  与整个页面 (Page) 相关的调度。
    * **真实场景:**  负责管理页面级别的资源、控制页面的可见性和冻结状态、处理导航等。
    * **虚拟调度器 (`DummyPageScheduler`) 的例子:**
        * `SetPageVisible(bool)`: 在真实调度器中，会触发渲染流程的启动或停止。在虚拟调度器中，这个方法是空的。
        * `CreateFrameScheduler(...)`:  在真实调度器中，会创建具有实际调度能力的 `FrameScheduler`。在虚拟调度器中，创建的仍然是 `DummyFrameScheduler`。

4. **`WebMainThreadScheduler` (及其虚拟实现 `DummyWebMainThreadScheduler`):**  与主线程相关的调度。
    * **真实场景:**  负责执行 JavaScript 代码、处理 DOM 操作、运行 CSS 计算等。
    * **虚拟调度器 (`DummyWebMainThreadScheduler`) 的例子:**
        * `PostIdleTask(...)`: 在真实调度器中，会在主线程空闲时执行任务。在虚拟调度器中，这个任务会被忽略。

**逻辑推理示例：**

假设输入：在一个使用虚拟调度器的环境中，尝试执行一段 JavaScript 代码来修改 DOM。

输出：这段 JavaScript 代码可能会被执行（因为 `DummyWebMainThreadScheduler` 仍然持有一个 V8 Isolate），但是由于相关的调度器是虚拟的，可能不会触发预期的渲染更新。例如，如果 JavaScript 代码修改了元素的样式，这个更改可能不会立即反映在屏幕上，因为虚拟的 `WidgetScheduler` 和 `FrameScheduler` 没有执行实际的渲染流程。

**假设输入与输出的具体例子：**

* **假设输入:** 调用 `DummyWidgetScheduler` 的 `WillBeginFrame` 方法。
* **输出:**  该方法内部没有任何操作，不会触发任何实际的帧开始流程。

* **假设输入:**  调用 `DummyFrameScheduler` 的 `CreateWebSchedulingTaskQueue` 方法。
* **输出:** 返回 `nullptr`，表示没有创建任何可用的任务队列。这意味着如果尝试向这个队列 post 任务，实际不会有任何任务被调度执行。

**用户或编程常见的使用错误：**

1. **在需要真实调度功能的生产环境中使用虚拟调度器:**  这是最严重的错误。如果应用程序依赖于调度器来处理用户交互、渲染更新或执行 JavaScript，使用虚拟调度器会导致功能缺失和不可预测的行为。
    * **例子:**  一个动画效果依赖于 `WidgetScheduler` 的帧调度，但在使用了虚拟调度器的环境中，动画将无法运行。

2. **在测试中过度依赖虚拟调度器而忽略了实际的调度逻辑:**  虽然虚拟调度器简化了测试，但过度使用可能会导致测试覆盖率不足，无法发现与调度相关的 bug。
    * **例子:**  测试某个功能是否正确处理了高优先级任务，如果只使用虚拟调度器，就无法验证优先级机制是否正常工作。

3. **不理解虚拟调度器的局限性:**  开发者可能错误地认为虚拟调度器只是一个轻量级的调度器，而忽略了它实际上是一个“空操作”的实现。
    * **例子:**  开发者可能会尝试在虚拟调度器上 post 任务并期望它们被执行，但实际上这些任务会被静默地忽略。

**总结:**

`dummy_schedulers.cc` 提供的虚拟调度器是为了在特定场景下简化开发和测试而存在的。它们通过实现调度器接口但不执行实际的调度逻辑来达到目的。理解它们的局限性以及它们与真实调度器的区别对于避免错误和正确使用 Blink 引擎至关重要。在生产环境中，必须使用功能完备的调度器实现。

Prompt: 
```
这是目录为blink/renderer/platform/scheduler/common/dummy_schedulers.cc的chromium blink引擎源代码文件， 请列举一下它的功能, 
如果它与javascript, html, css的功能有关系，请做出对应的举例说明，
如果做了逻辑推理，请给出假设输入与输出,
如果涉及用户或者编程常见的使用错误，请举例说明

"""
// Copyright 2019 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "third_party/blink/renderer/platform/scheduler/public/dummy_schedulers.h"

#include <memory>

#include "base/memory/raw_ptr.h"
#include "base/task/single_thread_task_runner.h"
#include "third_party/blink/public/platform/browser_interface_broker_proxy.h"
#include "third_party/blink/renderer/platform/scheduler/common/simple_main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/main_thread/main_thread_scheduler_impl.h"
#include "third_party/blink/renderer/platform/scheduler/public/agent_group_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/frame_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread.h"
#include "third_party/blink/renderer/platform/scheduler/public/main_thread_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/page_scheduler.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_priority.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_queue_type.h"
#include "third_party/blink/renderer/platform/scheduler/public/web_scheduling_task_queue.h"
#include "third_party/blink/renderer/platform/scheduler/public/widget_scheduler.h"
#include "third_party/blink/renderer/platform/wtf/wtf.h"

namespace blink {

class VirtualTimeController;

namespace scheduler {
namespace {

class DummyWidgetScheduler final : public WidgetScheduler {
 public:
  DummyWidgetScheduler() = default;
  DummyWidgetScheduler(const DummyWidgetScheduler&) = delete;
  DummyWidgetScheduler& operator=(const DummyWidgetScheduler&) = delete;
  ~DummyWidgetScheduler() override = default;

  void Shutdown() override {}
  // Returns the input task runner.
  scoped_refptr<base::SingleThreadTaskRunner> InputTaskRunner() override {
    return base::SingleThreadTaskRunner::GetCurrentDefault();
  }
  void WillBeginFrame(const viz::BeginFrameArgs& args) override {}
  void BeginFrameNotExpectedSoon() override {}
  void BeginMainFrameNotExpectedUntil(base::TimeTicks time) override {}
  void DidCommitFrameToCompositor() override {}
  void DidHandleInputEventOnCompositorThread(
      const WebInputEvent& web_input_event,
      InputEventState event_state) override {}
  void WillPostInputEventToMainThread(
      WebInputEvent::Type web_input_event_type,
      const WebInputEventAttribution& web_input_event_attribution) override {}
  void WillHandleInputEventOnMainThread(
      WebInputEvent::Type web_input_event_type,
      const WebInputEventAttribution& web_input_event_attribution) override {}
  void DidHandleInputEventOnMainThread(const WebInputEvent& web_input_event,
                                       WebInputEventResult result,
                                       bool frame_requested) override {}
  void DidRunBeginMainFrame() override {}
  void SetHidden(bool hidden) override {}
};

class DummyFrameScheduler : public FrameScheduler {
 public:
  explicit DummyFrameScheduler(v8::Isolate* isolate)
      : page_scheduler_(CreateDummyPageScheduler(isolate)) {}
  ~DummyFrameScheduler() override = default;

  DummyFrameScheduler(const DummyFrameScheduler&) = delete;
  DummyFrameScheduler& operator=(const DummyFrameScheduler&) = delete;

  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunner(TaskType) override {
    DCHECK(WTF::IsMainThread());
    return base::SingleThreadTaskRunner::GetCurrentDefault();
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
  void SetAgentClusterId(const base::UnguessableToken&) override {}
  bool IsCrossOriginToNearestMainFrame() const override { return false; }
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
  void OnFirstMeaningfulPaint(base::TimeTicks timestamp) override {}
  void OnDispatchLoadEvent() override {}
  void OnMainFrameInteractive() override {}
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
    return base::SingleThreadTaskRunner::GetCurrentDefault();
  }
  base::TimeDelta UnreportedTaskTime() const override {
    return base::TimeDelta();
  }

 private:
  std::unique_ptr<PageScheduler> page_scheduler_;
  base::WeakPtrFactory<FrameScheduler> weak_ptr_factory_{this};
};

class DummyPageScheduler : public PageScheduler {
 public:
  explicit DummyPageScheduler(v8::Isolate* isolate)
      : agent_group_scheduler_(CreateDummyAgentGroupScheduler(isolate)) {}
  ~DummyPageScheduler() override = default;

  DummyPageScheduler(const DummyPageScheduler&) = delete;
  DummyPageScheduler& operator=(const DummyPageScheduler&) = delete;

  std::unique_ptr<FrameScheduler> CreateFrameScheduler(
      FrameScheduler::Delegate* delegate,
      bool is_in_embedded_frame_tree,
      FrameScheduler::FrameType) override {
    return CreateDummyFrameScheduler(agent_group_scheduler_->Isolate());
  }

  void OnTitleOrFaviconUpdated() override {}
  void SetPageVisible(bool) override {}
  bool IsPageVisible() const override { return true; }
  void SetPageFrozen(bool) override {}
  void SetPageBackForwardCached(bool) override {}
  bool IsMainFrameLocal() const override { return true; }
  void SetIsMainFrameLocal(bool) override {}
  void AudioStateChanged(bool is_audio_playing) override {}
  bool IsAudioPlaying() const override { return false; }
  bool IsExemptFromBudgetBasedThrottling() const override { return false; }
  bool OptedOutFromAggressiveThrottlingForTest() const override {
    return false;
  }
  bool IsInBackForwardCache() const override { return false; }
  bool RequestBeginMainFrameNotExpected(bool) override { return false; }
  AgentGroupScheduler& GetAgentGroupScheduler() override {
    return *agent_group_scheduler_;
  }
  VirtualTimeController* GetVirtualTimeController() override { return nullptr; }
  scoped_refptr<WidgetScheduler> CreateWidgetScheduler() override {
    return base::MakeRefCounted<DummyWidgetScheduler>();
  }

 private:
  Persistent<AgentGroupScheduler> agent_group_scheduler_;
};

class SimpleMainThread : public MainThread {
 public:
  // We rely on base::SingleThreadTaskRunner::CurrentDefaultHandle for tasks
  // posted on the main thread. The task runner handle may not be available on
  // Blink's startup (== on SimpleMainThread's construction), because some tests
  // like blink_platform_unittests do not set up a global task environment. In
  // those cases, a task environment is set up on a test fixture's creation, and
  // GetTaskRunner() returns the right task runner during a test.
  //
  // If GetTaskRunner() can be called from a non-main thread (including a worker
  // thread running Mojo callbacks), we need to somehow get a task runner for
  // the main thread. This is not possible with
  // SingleThreadTaskRunner::CurrentDefaultHandle. We currently deal with this
  // issue by setting the main thread task runner on the test startup and
  // clearing it on the test tear-down. This is what
  // SetMainThreadTaskRunnerForTesting() for. This function is called from
  // Platform::SetMainThreadTaskRunnerForTesting() and
  // Platform::UnsetMainThreadTaskRunnerForTesting().

  explicit SimpleMainThread(ThreadScheduler* scheduler)
      : scheduler_ptr_(scheduler) {}
  ~SimpleMainThread() override = default;

  SimpleMainThread(const SimpleMainThread&) = delete;
  SimpleMainThread& operator=(const SimpleMainThread&) = delete;

  scoped_refptr<base::SingleThreadTaskRunner> GetTaskRunner(
      MainThreadTaskRunnerRestricted) const override {
    if (main_thread_task_runner_for_testing_) {
      return main_thread_task_runner_for_testing_;
    }
    DCHECK(WTF::IsMainThread());
    return base::SingleThreadTaskRunner::GetCurrentDefault();
  }

  ThreadScheduler* Scheduler() override { return scheduler_ptr_; }

  bool IsCurrentThread() const { return WTF::IsMainThread(); }

  void SetMainThreadTaskRunnerForTesting(
      scoped_refptr<base::SingleThreadTaskRunner> task_runner) {
    main_thread_task_runner_for_testing_ = std::move(task_runner);
  }

 private:
  bool IsSimpleMainThread() const override { return true; }

  raw_ptr<ThreadScheduler> scheduler_ptr_;
  scoped_refptr<base::SingleThreadTaskRunner>
      main_thread_task_runner_for_testing_;
};

class SimpleMainThreadWithScheduler : public SimpleMainThread {
 public:
  SimpleMainThreadWithScheduler() : SimpleMainThread(nullptr) {}

  ThreadScheduler* Scheduler() override { return &scheduler_; }

 private:
  scheduler::SimpleMainThreadScheduler scheduler_;
};

class DummyWebMainThreadScheduler : public WebThreadScheduler,
                                    public MainThreadScheduler {
 public:
  DummyWebMainThreadScheduler() = default;
  ~DummyWebMainThreadScheduler() override = default;

  // WebThreadScheduler implementation:
  void Shutdown() override {}
  WebThreadScheduler* ToWebMainThreadScheduler() override { return this; }

  // ThreadScheduler implementation:
  bool ShouldYieldForHighPriorityWork() override { return false; }
  void PostIdleTask(const base::Location&, Thread::IdleTask) override {}
  void PostDelayedIdleTask(const base::Location&,
                           base::TimeDelta delay,
                           Thread::IdleTask) override {}
  void PostNonNestableIdleTask(const base::Location&,
                               Thread::IdleTask) override {}
  void AddRAILModeObserver(RAILModeObserver*) override {}
  void RemoveRAILModeObserver(RAILModeObserver const*) override {}
  base::TimeTicks MonotonicallyIncreasingVirtualTime() override {
    return base::TimeTicks::Now();
  }
  void AddTaskObserver(base::TaskObserver*) override {}
  void RemoveTaskObserver(base::TaskObserver*) override {}
  blink::MainThreadScheduler* ToMainThreadScheduler() override { return this; }
  void SetV8Isolate(v8::Isolate* isolate) override { isolate_ = isolate; }

  scoped_refptr<base::SingleThreadTaskRunner> DeprecatedDefaultTaskRunner()
      override {
    DCHECK(WTF::IsMainThread());
    return base::SingleThreadTaskRunner::GetCurrentDefault();
  }

  scoped_refptr<base::SingleThreadTaskRunner> V8TaskRunner() override {
    DCHECK(WTF::IsMainThread());
    return base::SingleThreadTaskRunner::GetCurrentDefault();
  }

  scoped_refptr<base::SingleThreadTaskRunner> CleanupTaskRunner() override {
    DCHECK(WTF::IsMainThread());
    return base::SingleThreadTaskRunner::GetCurrentDefault();
  }

  std::unique_ptr<MainThread> CreateMainThread() override {
    return std::make_unique<SimpleMainThread>(this);
  }

  AgentGroupScheduler* CreateAgentGroupScheduler() override {
    return CreateDummyAgentGroupScheduler(isolate_);
  }

  std::unique_ptr<WebAgentGroupScheduler> CreateWebAgentGroupScheduler()
      override {
    return std::make_unique<WebAgentGroupScheduler>(
        CreateAgentGroupScheduler());
  }

  scoped_refptr<base::SingleThreadTaskRunner> NonWakingTaskRunner() override {
    DCHECK(WTF::IsMainThread());
    return base::SingleThreadTaskRunner::GetCurrentDefault();
  }

  AgentGroupScheduler* GetCurrentAgentGroupScheduler() override {
    return nullptr;
  }

  std::unique_ptr<RendererPauseHandle> PauseScheduler() override {
    return nullptr;
  }

  void ExecuteAfterCurrentTaskForTesting(
      base::OnceClosure on_completion_task,
      ExecuteAfterCurrentTaskRestricted) override {}

  v8::Isolate* Isolate() override {
    return isolate_;
  }

  void StartIdlePeriodForTesting() override {}

  void ForEachMainThreadIsolate(
      base::RepeatingCallback<void(v8::Isolate* isolate)> callback) override {
    if (isolate_) {
      callback.Run(isolate_.get());
    }
  }

  void SetRendererBackgroundedForTesting(bool) override {}

 private:
  raw_ptr<v8::Isolate> isolate_ = nullptr;
};

class DummyAgentGroupScheduler : public AgentGroupScheduler {
 public:
  explicit DummyAgentGroupScheduler(v8::Isolate* isolate)
      : main_thread_scheduler_(new DummyWebMainThreadScheduler()) {
    main_thread_scheduler_->SetV8Isolate(isolate);
  }
  ~DummyAgentGroupScheduler() override = default;

  DummyAgentGroupScheduler(const DummyAgentGroupScheduler&) = delete;
  DummyAgentGroupScheduler& operator=(const DummyAgentGroupScheduler&) = delete;

  std::unique_ptr<PageScheduler> CreatePageScheduler(
      PageScheduler::Delegate*) override {
    return CreateDummyPageScheduler(Isolate());
  }
  scoped_refptr<base::SingleThreadTaskRunner> DefaultTaskRunner() override {
    DCHECK(WTF::IsMainThread());
    return base::SingleThreadTaskRunner::GetCurrentDefault();
  }
  scoped_refptr<base::SingleThreadTaskRunner> CompositorTaskRunner() override {
    DCHECK(WTF::IsMainThread());
    return base::SingleThreadTaskRunner::GetCurrentDefault();
  }
  WebThreadScheduler& GetMainThreadScheduler() override {
    return *main_thread_scheduler_;
  }
  v8::Isolate* Isolate() override { return main_thread_scheduler_->Isolate(); }
  void AddAgent(Agent* agent) override {}
  void OnUrgentMessageReceived() override {}
  void OnUrgentMessageProcessed() override {}

 private:
  std::unique_ptr<DummyWebMainThreadScheduler> main_thread_scheduler_;
};

}  // namespace

std::unique_ptr<FrameScheduler> CreateDummyFrameScheduler(
    v8::Isolate* isolate) {
  DCHECK(isolate);
  return std::make_unique<DummyFrameScheduler>(isolate);
}

std::unique_ptr<PageScheduler> CreateDummyPageScheduler(v8::Isolate* isolate) {
  // TODO(crbug.com/1315595): Assert isolate is non-null.
  return std::make_unique<DummyPageScheduler>(isolate);
}

AgentGroupScheduler* CreateDummyAgentGroupScheduler(v8::Isolate* isolate) {
  // TODO(crbug.com/1315595): Assert isolate is non-null.
  return MakeGarbageCollected<DummyAgentGroupScheduler>(isolate);
}

std::unique_ptr<WebThreadScheduler> CreateDummyWebMainThreadScheduler() {
  return std::make_unique<DummyWebMainThreadScheduler>();
}

std::unique_ptr<MainThread> CreateSimpleMainThread() {
  return std::make_unique<SimpleMainThreadWithScheduler>();
}

void SetMainThreadTaskRunnerForTesting() {
  static_cast<SimpleMainThread*>(Thread::MainThread())
      ->SetMainThreadTaskRunnerForTesting(
          base::SingleThreadTaskRunner::GetCurrentDefault());
}

void UnsetMainThreadTaskRunnerForTesting() {
  static_cast<SimpleMainThread*>(Thread::MainThread())
      ->SetMainThreadTaskRunnerForTesting(nullptr);
}

}  // namespace scheduler
}  // namespace blink

"""

```